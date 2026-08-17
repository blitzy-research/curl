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

use core::fmt;
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::conn::filters::{
    discard_chain_from, link, CallCtx, CfType, ConnFilter, ConnId, FilterBase,
    FilterChain, FilterChains, FilterLink, ShutdownTimer, CURL_LOG_LVL_NONE,
};
use crate::conn::happy_eyeballs::ExpireScheduler;
use crate::conn::pool::{ConnectionId, ConnectionPool, PoolKey};
use crate::conn::select::Socket;
use crate::conn::shutdown::ConnShutdownTimer;
use crate::conn::socket::Deadline;
use crate::dns::{AlpnId, DnsEntryRef};
use crate::error::{CURLcode, CodeResult, CurlResult, Error};
use crate::trace::{failf, trc_cf, TimerId};
use crate::util::timediff::TimeDiff;
use crate::util::timeval::{timediff_ms, Clock, CurlTime};

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

/// Dual-stack connection racing -- supersedes `lib/cf-ip-happy.c` and
/// `lib/cf-ip-happy.h`.
///
/// The fifth module of this directory, and it consumes three of the four before
/// it: its candidate filters come from [`socket`]'s factories, each candidate is
/// an independent [`filters::FilterChain`] it drives itself, and the readiness it
/// waits on is a [`select::EasyPollset`]. Nothing in `cf-socket.h`,
/// `cfilters.h` or `select.h` names anything from `cf-ip-happy.h`, so the
/// direction is one-way -- and `lib/cf-socket.h:84-89` says why the dependency
/// runs this way round: a socket filter *"will not touch any connection/data
/// flags and can be used in happy eyeballing"*, which is a property the socket
/// module provides and this one consumes.
///
/// It owns the IPv6-first alternating race of `struct cf_ip_ballers`: two
/// address streams, one candidate per address tried, a delay between families,
/// and a winner that is TRANSFERRED into the main chain. C links the candidates
/// with an intrusive `next` pointer and reaches each one's filter through a raw
/// pointer it also stores on the connection; here each candidate owns its whole
/// subchain by value, so a losing socket cannot leak, be closed twice, or become
/// reachable from the main chain before it has won.
///
/// # The deadline contract this module shares with this file
///
/// `Curl_timeleft_ms` (`lib/connect.c:105-141`) is the transfer's own deadline
/// and it belongs to THIS file, which supersedes `lib/connect.c`. The racing
/// module consumes it through the injected
/// [`socket::Deadline`] interface and duplicates no timeout policy: it neither
/// stores a budget nor computes one. The convention that travels across the seam
/// is the C's exactly -- **zero means no limit and a NEGATIVE value means the
/// deadline has already passed** -- and the implementor owes the rest:
/// `Curl_timeleft_now_ms` computes the CONNECT limit and the OPERATION limit
/// separately and applies the fake-zero-to-`-1` correction to EACH of them
/// (`lib/connect.c:117-118`, `:127-128`) before folding them with `CURLMIN`,
/// because a computed exact zero must not be misread as "unlimited". Applying it
/// once, to the folded answer, would report no limit for a transfer whose
/// deadline expired at that instant.
///
/// No `#[allow(dead_code)]` on this declaration, for the same reason as
/// [`select`], [`filters`] and [`shutdown`]: the allowances belong on the items.
pub(crate) mod happy_eyeballs;

/// The connection pool -- supersedes `lib/conncache.c` and
/// `lib/conncache.h`.
///
/// The sixth module of this directory, and it consumes the first three of
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

// The two default budgets -- `lib/connect.h:43-45`

/// `DEFAULT_CONNECT_TIMEOUT` (`lib/connect.h:43`): **300000** milliseconds,
/// which the header's own comment glosses as "five minutes".
///
/// The budget a single connect attempt gets when `CURLOPT_CONNECTTIMEOUT` is
/// unset. Written as the C's literal rather than as `5 * 60 * 1000` because
/// the number is the contract: `--connect-timeout` reports against it, and a
/// factorisation invites somebody to "correct" one of the factors.
#[allow(dead_code)] // consumers: crate::protocols and crate::transfer
pub(crate) const DEFAULT_CONNECT_TIMEOUT: TimeDiff = 300000;

/// `DEFAULT_SHUTDOWN_TIMEOUT_MS` (`lib/connect.h:45`): `2 * 1000`, so **2000**
/// milliseconds.
///
/// Declared by [`filters`] rather than here, because
/// [`filters::ShutdownTimer::start`] documents it as the meaning of its own
/// zero argument and a trait cannot depend on its consumer. It is re-exported
/// at this name because `lib/connect.h` is the header this file supersedes, so
/// a reader looking for the C's home for the constant finds it -- and because
/// a second definition would be a second number to keep in step.
#[allow(unused_imports)]
pub(crate) use crate::conn::filters::DEFAULT_SHUTDOWN_TIMEOUT_MS;

// The checked domains this file speaks in, re-exported from their owners

/// `FIRSTSOCKET` = 0 (`lib/urldata.h:421`), for the callers that speak in raw
/// indices.
#[allow(unused_imports)]
pub(crate) use crate::conn::filters::FIRSTSOCKET;

/// `SECONDARYSOCKET` = 1 (`lib/urldata.h:422`).
#[allow(unused_imports)]
pub(crate) use crate::conn::filters::SECONDARYSOCKET;

/// Which of a connection's two chains a helper is asking about --
/// `conn->cfilter[2]` and `conn->shutdown.start[2]`.
///
/// Owned by [`filters`], which needs it in every method of
/// [`filters::ConnFilter`]. Re-exported rather than redefined: two enumerations
/// over `{0, 1}` would be two conversions to keep honest, and
/// [`filters::SocketIndex::from_i32`] is already the checked one.
pub(crate) use crate::conn::filters::SocketIndex;

/// What the bottom of a chain is carrying -- the `TRNSPRT_*` set
/// (`lib/urldata.h:567-571`), with its retired values 1 and 2 still absent.
pub(crate) use crate::conn::filters::Transport;

/// Whether a chain being built should carry TLS -- C's `int ssl_mode`, whose
/// three values are `CURL_CF_SSL_DEFAULT` = -1, `CURL_CF_SSL_DISABLE` = 0 and
/// `CURL_CF_SSL_ENABLE` = 1 (`lib/cfilters.h:351-353`).
///
/// Spelled `TlsMode` here because that is the name this file's contract uses
/// and because "SSL" names a protocol nothing in this crate speaks; it is the
/// SAME TYPE as [`filters::CfSslMode`], not a copy of it, so a value crosses
/// between the two modules without a conversion and the tri-state cannot
/// acquire a second numbering.
pub(crate) use crate::conn::filters::CfSslMode as TlsMode;

/// `MAX_IPADR_LEN` = **46** -- `sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")`
/// (`lib/urldata.h:124`), the buffer `Curl_addr2string` writes into.
///
/// Owned by [`crate::dns`], which sizes every printable address against it.
/// [`addr2string`] returns a [`String`] and so has no buffer to overrun, but
/// the bound is still observable: `crate::conn::socket`'s `ip_text_fits`
/// refuses to publish an address the C could not have stored.
#[allow(unused_imports)]
pub(crate) use crate::dns::MAX_IPADR_LEN;

// `PROTOPT_*` -- the scheme capability bitmap of `lib/urldata.h:526-558`

/// The `flags` member of `struct Curl_scheme` (`lib/urldata.h:522`): what is
/// unusual about a protocol.
///
/// # Why a newtype and not the `bitflags` crate
///
/// Because the set is closed and sixteen bits wide, and because AAP 0.5.1 pins
/// every dependency exactly: a crate earns its place by doing something the
/// twenty lines below cannot. This is the same shape [`filters::CfType`] uses
/// for `CF_TYPE_*` and [`crate::conn::pool`]'s `ConnCheck` uses for
/// `CONNCHECK_*`, so the crate has one idiom for a C bitmap rather than two.
///
/// # The bit that must stay empty
///
/// `1 << 9` was `PROTOPT_STREAM` and the C tree says so in a comment where the
/// definition used to be: *"(1 << 9) was PROTOPT_STREAM, now free"*
/// (`lib/urldata.h:545`). It is published here as
/// [`Self::RESERVED_BIT_9`] rather than omitted, because omitting it is what
/// makes somebody adding the seventeenth capability reach for the hole. A
/// scheme table must never set it.
#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct ProtocolOptions(u32);

impl ProtocolOptions {
    /// `PROTOPT_NONE` = 0 (`lib/urldata.h:526`): nothing extra.
    pub(crate) const NONE: Self = Self(0);

    /// `PROTOPT_SSL` = `1 << 0` (`lib/urldata.h:527`): the scheme uses TLS.
    ///
    /// Read by the SETUP filter's TLS stage, which is the one place in this
    /// file that consults a scheme's flags -- see [`SetupFilter::connect`].
    pub(crate) const SSL: Self = Self(1 << 0);

    /// `PROTOPT_DUAL` = `1 << 1` (`lib/urldata.h:528`): two connections, which
    /// is what makes `SECONDARYSOCKET` exist at all.
    pub(crate) const DUAL: Self = Self(1 << 1);

    /// `PROTOPT_CLOSEACTION` = `1 << 2` (`lib/urldata.h:529`): something must
    /// happen before the socket closes.
    pub(crate) const CLOSEACTION: Self = Self(1 << 2);

    /// `PROTOPT_DIRLOCK` = `1 << 3` (`lib/urldata.h:534`).
    pub(crate) const DIRLOCK: Self = Self(1 << 3);

    /// `PROTOPT_NONETWORK` = `1 << 4` (`lib/urldata.h:535`): the scheme uses no
    /// network, which is `file://` and nothing else.
    ///
    /// This is the flag [`filters::FilterChain::is_connected`] takes as its
    /// `no_network` argument: such a scheme is connected without a chain.
    pub(crate) const NONETWORK: Self = Self(1 << 4);

    /// `PROTOPT_NEEDSPWD` = `1 << 5` (`lib/urldata.h:536`): a default password
    /// is supplied when none is set.
    pub(crate) const NEEDSPWD: Self = Self(1 << 5);

    /// `PROTOPT_NOURLQUERY` = `1 << 6` (`lib/urldata.h:538`): a `?foo=bar` tail
    /// is not a query for this scheme.
    pub(crate) const NOURLQUERY: Self = Self(1 << 6);

    /// `PROTOPT_CREDSPERREQUEST` = `1 << 7` (`lib/urldata.h:540`): credentials
    /// are per request rather than per connection.
    pub(crate) const CREDSPERREQUEST: Self = Self(1 << 7);

    /// `PROTOPT_ALPN` = `1 << 8` (`lib/urldata.h:543`): advertise ALPN.
    pub(crate) const ALPN: Self = Self(1 << 8);

    /// `1 << 9`, which the C reserves and no scheme sets.
    ///
    /// See the type's documentation: this was `PROTOPT_STREAM` and
    /// `lib/urldata.h:544` records that it is now free. It is a named hole so
    /// that the next capability takes `1 << 17`.
    pub(crate) const RESERVED_BIT_9: Self = Self(1 << 9);

    /// `PROTOPT_URLOPTIONS` = `1 << 10` (`lib/urldata.h:545`): the userinfo
    /// field may carry options.
    pub(crate) const URLOPTIONS: Self = Self(1 << 10);

    /// `PROTOPT_PROXY_AS_HTTP` = `1 << 11` (`lib/urldata.h:547`): a non-HTTP
    /// scheme an HTTP proxy may gateway.
    pub(crate) const PROXY_AS_HTTP: Self = Self(1 << 11);

    /// `PROTOPT_WILDCARD` = `1 << 12` (`lib/urldata.h:551`): wildcard matching.
    pub(crate) const WILDCARD: Self = Self(1 << 12);

    /// `PROTOPT_USERPWDCTRL` = `1 << 13` (`lib/urldata.h:552`): control bytes
    /// below ASCII 32 are allowed in the credentials.
    pub(crate) const USERPWDCTRL: Self = Self(1 << 13);

    /// `PROTOPT_NOTCPPROXY` = `1 << 14` (`lib/urldata.h:554`): this scheme
    /// cannot be proxied over TCP.
    pub(crate) const NOTCPPROXY: Self = Self(1 << 14);

    /// `PROTOPT_SSL_REUSE` = `1 << 15` (`lib/urldata.h:555`): an existing TLS
    /// connection in the same family may be reused without [`Self::SSL`].
    pub(crate) const SSL_REUSE: Self = Self(1 << 15);

    /// `PROTOPT_CONN_REUSE` = `1 << 16` (`lib/urldata.h:558`): connections may
    /// be reused at all.
    pub(crate) const CONN_REUSE: Self = Self(1 << 16);

    /// Every bit the C defines, INCLUDING the reserved one, in bit order.
    ///
    /// Seventeen entries for sixteen capabilities: the reserved hole is a
    /// member so that an exhaustiveness test walks over it and would notice it
    /// being handed a meaning.
    #[allow(dead_code)] // consumers: crate::protocols and crate::transfer
    pub(crate) const ALL: [Self; 17] = [
        Self::SSL,
        Self::DUAL,
        Self::CLOSEACTION,
        Self::DIRLOCK,
        Self::NONETWORK,
        Self::NEEDSPWD,
        Self::NOURLQUERY,
        Self::CREDSPERREQUEST,
        Self::ALPN,
        Self::RESERVED_BIT_9,
        Self::URLOPTIONS,
        Self::PROXY_AS_HTTP,
        Self::WILDCARD,
        Self::USERPWDCTRL,
        Self::NOTCPPROXY,
        Self::SSL_REUSE,
        Self::CONN_REUSE,
    ];

    /// The raw bitmap, as the C's `uint32_t flags` holds it.
    pub(crate) const fn bits(self) -> u32 {
        self.0
    }

    /// A set from a raw bitmap.
    ///
    /// Total, exactly as [`filters::CfType::from_bits`] is: the C stores
    /// whatever a scheme declared, and this is a SET rather than an
    /// enumeration, so an unrecognised bit is preserved instead of rejected.
    #[allow(dead_code)] // consumers: crate::protocols and crate::transfer
    pub(crate) const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// The union, for the `|`-composed declarations a scheme table writes.
    pub(crate) const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// True when ANY bit of `other` is present -- the C's `flags & mask`.
    pub(crate) const fn intersects(self, other: Self) -> bool {
        (self.0 & other.0) != 0
    }

    /// True when EVERY bit of `other` is present.
    #[allow(dead_code)] // consumers: crate::protocols and crate::transfer
    pub(crate) const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// True when the scheme declared `PROTOPT_NONE`.
    pub(crate) const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl core::ops::BitOr for ProtocolOptions {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

/// Names the bits rather than printing a number, so an assertion failure reads
/// as the scheme table wrote it.
impl fmt::Debug for ProtocolOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return f.write_str("ProtocolOptions(NONE)");
        }
        f.write_str("ProtocolOptions(")?;
        let mut first = true;
        let mut accounted = Self::NONE;
        for (bit, name) in PROTOCOL_OPTION_NAMES {
            accounted = accounted.union(bit);
            if self.intersects(bit) {
                if !first {
                    f.write_str("|")?;
                }
                f.write_str(name)?;
                first = false;
            }
        }
        // Whatever survives the seventeen known bits, so a stray bit shows up
        // instead of vanishing from the rendering.
        let unknown = self.0 & !accounted.bits();
        if unknown != 0 {
            if !first {
                f.write_str("|")?;
            }
            write!(f, "{unknown:#x}")?;
        }
        f.write_str(")")
    }
}

/// The rendering table [`ProtocolOptions`]'s [`fmt::Debug`] walks, in bit
/// order, spelled as the C macro tails.
const PROTOCOL_OPTION_NAMES: [(ProtocolOptions, &str); 17] = [
    (ProtocolOptions::SSL, "SSL"),
    (ProtocolOptions::DUAL, "DUAL"),
    (ProtocolOptions::CLOSEACTION, "CLOSEACTION"),
    (ProtocolOptions::DIRLOCK, "DIRLOCK"),
    (ProtocolOptions::NONETWORK, "NONETWORK"),
    (ProtocolOptions::NEEDSPWD, "NEEDSPWD"),
    (ProtocolOptions::NOURLQUERY, "NOURLQUERY"),
    (ProtocolOptions::CREDSPERREQUEST, "CREDSPERREQUEST"),
    (ProtocolOptions::ALPN, "ALPN"),
    (ProtocolOptions::RESERVED_BIT_9, "RESERVED(1<<9)"),
    (ProtocolOptions::URLOPTIONS, "URLOPTIONS"),
    (ProtocolOptions::PROXY_AS_HTTP, "PROXY_AS_HTTP"),
    (ProtocolOptions::WILDCARD, "WILDCARD"),
    (ProtocolOptions::USERPWDCTRL, "USERPWDCTRL"),
    (ProtocolOptions::NOTCPPROXY, "NOTCPPROXY"),
    (ProtocolOptions::SSL_REUSE, "SSL_REUSE"),
    (ProtocolOptions::CONN_REUSE, "CONN_REUSE"),
];

// `CONNCTRL_*` -- what a caller is declaring the end of

/// `CONNCTRL_KEEP` = 0 (`lib/connect.h:90`): undo a marked closure.
#[allow(dead_code)] // consumers: crate::protocols and crate::transfer
pub(crate) const CONNCTRL_KEEP: i32 = 0;

/// `CONNCTRL_CONNECTION` = 1 (`lib/connect.h:91`).
#[allow(dead_code)] // consumers: crate::protocols and crate::transfer
pub(crate) const CONNCTRL_CONNECTION: i32 = 1;

/// `CONNCTRL_STREAM` = 2 (`lib/connect.h:92`).
#[allow(dead_code)] // consumers: crate::protocols and crate::transfer
pub(crate) const CONNCTRL_STREAM: i32 = 2;

/// What [`conncontrol`] is being told has ended.
///
/// The three `CONNCTRL_*` values (`lib/connect.h:90-92`), which the C reaches
/// through the `connkeep`, `connclose` and `streamclose` macros
/// (`lib/connect.h:101-109`) and never as a bare integer.
///
/// # Why the conversion refuses an unknown integer
///
/// The C's `int ctrl` is compared against two of the three values and falls
/// through for anything else, so `7` behaves as `CONNCTRL_KEEP` -- it clears a
/// marked closure. Nothing in the C tree can reach that arm, because every call
/// site is one of the three macros, so making it unrepresentable changes no
/// reachable behaviour and removes an arm nobody intended. A boundary handed an
/// integer therefore gets [`CURLcode::BadFunctionArgument`], exactly as
/// [`filters::SocketIndex::from_i32`] does for a socket index.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)] // consumers: crate::protocols and crate::transfer
pub(crate) enum ConnControl {
    /// `CONNCTRL_KEEP`: the connection is to be kept, undoing a mark.
    ///
    /// The default because the C's zeroed value is, and because "keep" is the
    /// state a fresh connection is in.
    #[default]
    Keep = CONNCTRL_KEEP as isize,
    /// `CONNCTRL_CONNECTION`: the whole connection has ended.
    Connection = CONNCTRL_CONNECTION as isize,
    /// `CONNCTRL_STREAM`: one stream has ended, which closes the connection
    /// only when it is not multiplexed.
    Stream = CONNCTRL_STREAM as isize,
}

impl ConnControl {
    /// Every control, in `lib/connect.h` declaration order.
    #[allow(dead_code)] // consumers: crate::protocols and crate::transfer
    pub(crate) const ALL: [Self; 3] =
        [Self::Keep, Self::Connection, Self::Stream];

    /// The control as the C integer.
    #[allow(dead_code)] // consumers: crate::protocols and crate::transfer
    pub(crate) const fn as_i32(self) -> i32 {
        self as i32
    }

    /// The checked conversion a boundary performs.
    ///
    /// # Errors
    ///
    /// [`CURLcode::BadFunctionArgument`] for anything that is not one of the
    /// three defined values. See the type's documentation for why this is a
    /// refusal rather than the C's fall-through.
    #[allow(dead_code)] // consumers: crate::protocols and crate::transfer
    pub(crate) fn from_i32(raw: i32) -> CodeResult<Self> {
        match raw {
            CONNCTRL_KEEP => Ok(Self::Keep),
            CONNCTRL_CONNECTION => Ok(Self::Connection),
            CONNCTRL_STREAM => Ok(Self::Stream),
            _ => Err(CURLcode::BadFunctionArgument),
        }
    }
}

// `CURLPROXY_*` -- only as far as `IS_HTTPS_PROXY` needs it

/// `conn->http_proxy.proxytype`, so far as chain construction reads it.
///
/// The `CURLPROXY_*` set (`include/curl/curl.h:790-802`) with its integers
/// pinned, because they are public ABI: `CURLOPT_PROXYTYPE` takes them from an
/// application. The whole set is present rather than only the two HTTPS
/// members, so that a `match` over a proxy type is exhaustive and
/// [`Self::is_https`] is the only place the two-member test lives.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)] // consumers: crate::protocols and crate::transfer
pub(crate) enum ProxyType {
    /// `CURLPROXY_HTTP` = 0. The C's default, and the default here.
    #[default]
    Http = 0,
    /// `CURLPROXY_HTTP_1_0` = 1: force `CONNECT` over HTTP/1.0.
    Http10 = 1,
    /// `CURLPROXY_HTTPS` = 2: TLS to the proxy, HTTP/1 only.
    Https = 2,
    /// `CURLPROXY_HTTPS2` = 3: TLS to the proxy, HTTP/2 attempted.
    Https2 = 3,
    /// `CURLPROXY_SOCKS4` = 4.
    Socks4 = 4,
    /// `CURLPROXY_SOCKS5` = 5.
    Socks5 = 5,
    /// `CURLPROXY_SOCKS4A` = 6.
    Socks4a = 6,
    /// `CURLPROXY_SOCKS5_HOSTNAME` = 7.
    Socks5Hostname = 7,
}

impl ProxyType {
    /// Every proxy type, in `include/curl/curl.h` declaration order.
    #[allow(dead_code)] // consumers: crate::protocols and crate::transfer
    pub(crate) const ALL: [Self; 8] = [
        Self::Http,
        Self::Http10,
        Self::Https,
        Self::Https2,
        Self::Socks4,
        Self::Socks5,
        Self::Socks4a,
        Self::Socks5Hostname,
    ];

    /// The type as the public ABI integer.
    #[allow(dead_code)] // consumers: crate::protocols and crate::transfer
    pub(crate) const fn as_i32(self) -> i32 {
        self as i32
    }

    /// `IS_HTTPS_PROXY(t)` (`lib/http_proxy.h:61-62`): TLS is spoken to the
    /// proxy itself.
    ///
    /// Exactly two members, and `CURLPROXY_HTTP_1_0` is deliberately not one of
    /// them: it forces the `CONNECT` request's HTTP version and says nothing
    /// about transport security.
    pub(crate) const fn is_https(self) -> bool {
        matches!(self, Self::Https | Self::Https2)
    }

    /// The checked conversion.
    ///
    /// # Errors
    ///
    /// [`CURLcode::BadFunctionArgument`] for anything outside `0..8`, which is
    /// what `setopt` rejects for `CURLOPT_PROXYTYPE`.
    #[allow(dead_code)] // consumers: crate::protocols and crate::transfer
    pub(crate) fn from_i32(raw: i32) -> CodeResult<Self> {
        Self::ALL
            .into_iter()
            .find(|kind| kind.as_i32() == raw)
            .ok_or(CURLcode::BadFunctionArgument)
    }
}

// The connection state these helpers own -- NOT a second `struct connectdata`

/// The two connection bits `lib/connect.c` is responsible for.
///
/// # Why this is two fields and not a god struct
///
/// `struct connectdata` has upwards of ninety members and
/// `lib/urldata.h` is included by nearly every translation unit in the C tree;
/// reproducing it would reproduce the coupling this rewrite exists to remove.
/// What `lib/connect.c` actually writes is exactly two bits -- `bits.close`,
/// which `Curl_conncontrol` assigns, and `bits.multiplex`, which
/// `Curl_conn_set_multiplex` sets -- so those two are what this type holds. The
/// filter chains live in [`filters::FilterChains`], the shutdown deadline in
/// [`ShutdownTimers`], the resolved addresses in [`ResolvedEntries`], and the
/// connection's identity in [`crate::conn::pool`]. Every one of them is passed
/// to the helper that needs it and to no other.
///
/// # The invariant this type exists to protect
///
/// `lib/connect.c:319-320` carries the comment *"the only place in the source
/// code that should assign this bit"* about `conn->bits.close`. Here that is
/// not a comment but a consequence: the field is private, the module exposes
/// [`Self::wants_close`] and no setter, and [`conncontrol`] is the one function
/// that assigns it. A test asserts the assignment appears exactly once in this
/// file's own source.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)] // consumers: crate::protocols and crate::transfer
pub(crate) struct ConnectionState {
    /// `conn->bits.close` (`lib/urldata.h:349`): close after this request.
    ///
    /// Written by [`conncontrol`] and by nothing else.
    close: bool,
    /// `conn->bits.multiplex` (`lib/urldata.h:381`): this connection is
    /// multiplexed.
    ///
    /// Written by [`conn_set_multiplex`], which is a one-way latch.
    multiplex: bool,
    /// Why the close bit was last written, for a trace.
    ///
    /// C's `reason` parameter exists only
    /// `#if defined(DEBUGBUILD) && defined(CURLVERBOSE)` and its body is
    /// `(void)reason; /* useful for debugging */` -- it is passed, named and
    /// then deliberately discarded. Retaining it under `debug_assertions` and
    /// nowhere else reproduces both halves: a debug build can see why a
    /// connection was marked, and a release build carries no [`String`] per
    /// connection for a value nothing reads.
    #[cfg(debug_assertions)]
    close_reason: Option<String>,
}

impl ConnectionState {
    /// A fresh connection: kept, not multiplexed.
    #[allow(dead_code)] // consumers: crate::protocols and crate::transfer
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// `conn->bits.close`.
    #[allow(dead_code)] // consumers: crate::protocols and crate::transfer
    pub(crate) const fn wants_close(&self) -> bool {
        self.close
    }

    /// `conn->bits.multiplex`.
    #[allow(dead_code)] // consumers: crate::protocols and crate::transfer
    pub(crate) const fn is_multiplex(&self) -> bool {
        self.multiplex
    }

    /// Why the close bit was last written, in a debug build.
    ///
    /// Always [`None`] in a release build, where the reason is not retained --
    /// see the field's documentation. Declared unconditionally, and answering
    /// [`None`] rather than not existing, so that a caller does not have to
    /// carry the `cfg` too.
    #[allow(dead_code)] // consumers: crate::protocols and crate::transfer
    pub(crate) fn close_reason(&self) -> Option<&str> {
        #[cfg(debug_assertions)]
        {
            self.close_reason.as_deref()
        }
        #[cfg(not(debug_assertions))]
        {
            None
        }
    }
}

// ALPN identifiers -- `lib/connect.c:73-94`

/// `Curl_alpn2alpnid` (`lib/connect.c:73-88`): the ALPN identifier an
/// advertised protocol name denotes.
///
/// # Why this delegates rather than deciding
///
/// The lookup belongs to [`crate::dns::AlpnId`], because
/// [`AlpnId::from_wire`] is what the Alt-Svc parser and the HTTPS resource
/// record parser already call and because the enumerant integers -- 8, 16 and
/// 32, from `CURLALTSVC_H1`, `_H2` and `_H3` -- are that type's contract. Two
/// copies of a five-line table is how one of them comes to accept `h2c` and the
/// other not; there is one, and this is the name `lib/connect.c` gave it.
///
/// # The matching rule, which is stricter than it looks
///
/// Length first, then exact BYTES:
///
/// * two bytes accept `h1`, `h2` and `h3`, and nothing else;
/// * eight bytes accept `http/1.1`, which maps to [`AlpnId::H1`];
/// * everything else is [`AlpnId::None`], *"unknown, probably rubbish input"*.
///
/// So `H2` is not `h2`, `h2c` is not `h2`, `http/1.0` is not `http/1.1`, and a
/// name with trailing whitespace is nothing at all. No case folding happens at
/// any point -- ALPN protocol identifiers are octet sequences, not strings.
#[allow(dead_code)] // consumers: crate::cookies::altsvc and crate::dns::httpsrr
pub(crate) fn alpn2alpnid(name: &[u8]) -> AlpnId {
    AlpnId::from_wire(name)
}

/// `Curl_str2alpnid` (`lib/connect.c:90-94`): [`alpn2alpnid`] over a parsed
/// token.
///
/// The C takes a `struct Curl_str *` and immediately unpacks it into the
/// pointer-and-length pair the other function wants:
///
/// ```c
/// return Curl_alpn2alpnid((const unsigned char *)curlx_str(cstr),
///                         curlx_strlen(cstr));
/// ```
///
/// A Rust slice already carries its length, and
/// [`crate::util::strparse`] models `struct Curl_str` as a plain borrowed span
/// rather than as a struct, so the unpacking has nothing left to do. What
/// remains is the convenience the C function actually provides: accepting the
/// token as text. It adds no rule of its own -- in particular it does not trim,
/// because the C does not.
#[allow(dead_code)] // consumers: crate::cookies::altsvc and crate::dns::httpsrr
pub(crate) fn str2alpnid(text: &str) -> AlpnId {
    alpn2alpnid(text.as_bytes())
}

// The transfer's deadline -- `lib/connect.c:98-142`

/// Everything `Curl_timeleft_now_ms` reads off the transfer.
///
/// Six values, which is the whole of that function's input besides the clock
/// and the shutdown timers: `data->set.connecttimeout`, `data->set.timeout`,
/// `data->set.connect_only`, `Curl_is_connecting(data)`,
/// `data->progress.t_startsingle` and `data->progress.t_startop`. Gathering
/// them into one owned value is what lets the arithmetic be tested without a
/// transfer, a multi handle or a socket -- which is the whole reason AAP 0.3.3
/// asks for injection here.
///
/// # On `connecting`
///
/// `Curl_is_connecting(data)` is `data->mstate < MSTATE_DO`
/// (`lib/multi.c:358-361`), and `mstate` belongs to `crate::multi`, which this
/// directory does not name -- see the module documentation. The predicate
/// therefore arrives as a `bool` that the owner of the state sets, and
/// `crate::multi::state::CurlMstate::is_connecting` is the function that
/// computes it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)] // consumers: crate::transfer and crate::multi
pub(crate) struct DeadlineState {
    /// `data->set.connecttimeout` -- `CURLOPT_CONNECTTIMEOUT_MS`. Zero means
    /// unset, in which case [`DEFAULT_CONNECT_TIMEOUT`] applies.
    connect_timeout_ms: TimeDiff,
    /// `data->set.timeout` -- `CURLOPT_TIMEOUT_MS`. Zero means no overall
    /// limit.
    operation_timeout_ms: TimeDiff,
    /// `data->set.connect_only` -- `CURLOPT_CONNECT_ONLY`.
    connect_only: bool,
    /// `Curl_is_connecting(data)`.
    connecting: bool,
    /// `data->progress.t_startsingle`: when the current single connect began.
    started_single_at: CurlTime,
    /// `data->progress.t_startop`: when the operation began.
    started_op_at: CurlTime,
}

impl DeadlineState {
    /// A transfer with no configured limit that is not connecting.
    ///
    /// The state a freshly initialised easy handle is in, where
    /// [`timeleft_now_ms`] answers zero -- "no limit".
    #[allow(dead_code)] // consumers: crate::transfer and crate::multi
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Sets `CURLOPT_CONNECTTIMEOUT_MS`. Zero restores the default budget.
    #[allow(dead_code)] // consumers: crate::transfer and crate::multi
    pub(crate) fn set_connect_timeout_ms(&mut self, ms: TimeDiff) {
        self.connect_timeout_ms = ms;
    }

    /// `data->set.connecttimeout`.
    #[allow(dead_code)] // consumers: crate::transfer and crate::multi
    pub(crate) const fn connect_timeout_ms(&self) -> TimeDiff {
        self.connect_timeout_ms
    }

    /// Sets `CURLOPT_TIMEOUT_MS`. Zero removes the overall limit.
    #[allow(dead_code)] // consumers: crate::transfer and crate::multi
    pub(crate) fn set_operation_timeout_ms(&mut self, ms: TimeDiff) {
        self.operation_timeout_ms = ms;
    }

    /// `data->set.timeout`.
    #[allow(dead_code)] // consumers: crate::transfer and crate::multi
    pub(crate) const fn operation_timeout_ms(&self) -> TimeDiff {
        self.operation_timeout_ms
    }

    /// Sets `CURLOPT_CONNECT_ONLY`.
    #[allow(dead_code)] // consumers: crate::transfer and crate::multi
    pub(crate) fn set_connect_only(&mut self, connect_only: bool) {
        self.connect_only = connect_only;
    }

    /// `data->set.connect_only`.
    #[allow(dead_code)] // consumers: crate::transfer and crate::multi
    pub(crate) const fn connect_only(&self) -> bool {
        self.connect_only
    }

    /// Records `Curl_is_connecting(data)`.
    #[allow(dead_code)] // consumers: crate::transfer and crate::multi
    pub(crate) fn set_connecting(&mut self, connecting: bool) {
        self.connecting = connecting;
    }

    /// `Curl_is_connecting(data)`.
    #[allow(dead_code)] // consumers: crate::transfer and crate::multi
    pub(crate) const fn connecting(&self) -> bool {
        self.connecting
    }

    /// `Curl_pgrsTime(data, TIMER_STARTSINGLE)`.
    #[allow(dead_code)] // consumers: crate::transfer and crate::multi
    pub(crate) fn set_started_single_at(&mut self, at: CurlTime) {
        self.started_single_at = at;
    }

    /// `data->progress.t_startsingle`.
    #[allow(dead_code)] // consumers: crate::transfer and crate::multi
    pub(crate) const fn started_single_at(&self) -> CurlTime {
        self.started_single_at
    }

    /// `Curl_pgrsTime(data, TIMER_STARTOP)`.
    #[allow(dead_code)] // consumers: crate::transfer and crate::multi
    pub(crate) fn set_started_op_at(&mut self, at: CurlTime) {
        self.started_op_at = at;
    }

    /// `data->progress.t_startop`.
    #[allow(dead_code)] // consumers: crate::transfer and crate::multi
    pub(crate) const fn started_op_at(&self) -> CurlTime {
        self.started_op_at
    }
}

/// `Curl_timeleft_now_ms` (`lib/connect.c:105-137`): how long the transfer has
/// left, measured against `now`.
///
/// # The three answers, and why zero is not "expired"
///
/// * **Zero** -- there is NO timeout; infinite time remains.
/// * **Negative** -- the deadline has already passed.
/// * **Positive** -- that many milliseconds remain.
///
/// Zero meaning "unlimited" is the whole difficulty of this function, because a
/// deadline that expires at exactly `now` computes to zero and must not be
/// reported as unlimited. The C's remedy is a comment repeated twice --
/// *"0 is 'no limit', fake 1 ms expiry"* -- and it applies the correction to
/// each of the two budgets SEPARATELY (`lib/connect.c:118-119` for the connect
/// budget, `:128-129` for the operation budget) before folding them with
/// `CURLMIN`. Applying it once to the folded answer would report no limit for a
/// transfer whose deadline expired at this instant, so the doubling is
/// load-bearing rather than redundant.
///
/// # The order of the tests
///
/// 1. A shutdown in progress on [`SocketIndex::First`] wins outright: its own
///    deadline is returned and neither budget below is consulted
///    (`:111-112`).
/// 2. Otherwise, while connecting, the connect budget is
///    `CURLOPT_CONNECTTIMEOUT_MS` when positive and
///    [`DEFAULT_CONNECT_TIMEOUT`] when not, less the time since
///    `t_startsingle`.
/// 3. Otherwise -- NOT connecting -- an absent overall timeout or an active
///    `CURLOPT_CONNECT_ONLY` returns zero immediately (`:121-123`). Note that
///    this arm is skipped entirely while connecting, so `connect_only` does not
///    lift the connect budget.
/// 4. The overall budget is then `CURLOPT_TIMEOUT_MS` less the time since
///    `t_startop`, when one is set. This runs even in the connecting case,
///    which is how a transfer with both options set gets the smaller of the
///    two.
/// 5. Zero on either side means that side has no limit, so the other is
///    returned; otherwise the minimum.
#[allow(dead_code)] // consumers: crate::transfer and crate::multi
pub(crate) fn timeleft_now_ms(
    deadline: &DeadlineState,
    timers: &ShutdownTimers,
    now: CurlTime,
) -> TimeDiff {
    let mut timeleft_ms: TimeDiff = 0;
    let mut ctimeleft_ms: TimeDiff = 0;

    if shutdown_started(timers, SocketIndex::First) {
        return shutdown_timeleft(timers, SocketIndex::First);
    } else if deadline.connecting {
        // `(data->set.connecttimeout > 0) ? ... : DEFAULT_CONNECT_TIMEOUT`
        let ctimeout_ms = if deadline.connect_timeout_ms > 0 {
            deadline.connect_timeout_ms
        } else {
            DEFAULT_CONNECT_TIMEOUT
        };
        ctimeleft_ms =
            ctimeout_ms - timediff_ms(now, deadline.started_single_at);
        if ctimeleft_ms == 0 {
            // `0 is "no limit", fake 1 ms expiry`
            ctimeleft_ms = -1;
        }
    } else if deadline.operation_timeout_ms == 0 || deadline.connect_only {
        // `no timeout in place or checked, return "no limit"`
        return 0;
    }

    if deadline.operation_timeout_ms != 0 {
        timeleft_ms = deadline.operation_timeout_ms
            - timediff_ms(now, deadline.started_op_at);
        if timeleft_ms == 0 {
            // The same correction again, on the OTHER budget.
            timeleft_ms = -1;
        }
    }

    if ctimeleft_ms == 0 {
        timeleft_ms
    } else if timeleft_ms == 0 {
        ctimeleft_ms
    } else {
        // `CURLMIN(ctimeleft_ms, timeleft_ms)`
        ctimeleft_ms.min(timeleft_ms)
    }
}

/// `Curl_timeleft_ms` (`lib/connect.c:139-142`): [`timeleft_now_ms`] against
/// the clock's current reading.
///
/// The C reads `Curl_pgrs_now(data)`, a cached reading the progress meter
/// refreshes once per pass rather than a fresh syscall. Here the reading comes
/// from the INJECTED clock, which is what makes every deadline test in this
/// crate deterministic: nothing in this module calls a global clock, so no test
/// depends on how long it took to run.
#[allow(dead_code)] // consumers: crate::transfer and crate::multi
pub(crate) fn timeleft_ms(
    deadline: &DeadlineState,
    timers: &ShutdownTimers,
    clock: &dyn Clock,
) -> TimeDiff {
    timeleft_now_ms(deadline, timers, clock.now())
}

// The shutdown timer family -- `lib/connect.c:144-207`

/// Whose handle a shutdown is charged to, as far as arming a timer goes.
///
/// `Curl_shutdown_start` arms `EXPIRE_SHUTDOWN` under one condition,
/// `if(data->mid)` (`lib/connect.c:156`), whose comment is *"Set a timer, unless
/// we operate on the admin handle"*. `data->mid` is the transfer's index in the
/// multi handle's transfer table, so a handle that has one is a REGISTERED
/// transfer with timers of its own, and a handle that does not is the multi
/// handle's internal admin handle, whose expiry list nothing reads.
///
/// Modelled as a two-variant enumeration rather than a `bool` because the two
/// readings of a bare `true` here -- "is the admin handle" and "is a registered
/// transfer" -- are opposites, and a caller getting it backwards would arm no
/// timer at all and stall a graceful shutdown until the next unrelated wakeup.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)] // consumers: crate::transfer and crate::multi
pub(crate) enum TransferRole {
    /// `data->mid` is set: a transfer the multi handle knows about, whose
    /// timers are honoured. The default, because the overwhelmingly common
    /// caller is an ordinary transfer.
    #[default]
    Registered,
    /// `data->mid` is unset: the multi handle's own admin handle, which gets no
    /// timer.
    Admin,
}

impl TransferRole {
    /// Whether a timer armed on this handle would be honoured -- C's
    /// `if(data->mid)`.
    #[allow(dead_code)] // consumers: crate::transfer and crate::multi
    pub(crate) const fn arms_timers(self) -> bool {
        matches!(self, Self::Registered)
    }
}

/// `conn->shutdown` (`lib/urldata.h:650-653`): when each chain's graceful
/// shutdown began, and how long it is allowed.
///
/// # Why the storage lives here
///
/// Because `lib/connect.h:47-64` declares all five accessors and
/// `lib/connect.c:144-207` defines them, and this file supersedes that pair.
/// Both consumers say so from their own side:
/// [`filters::ShutdownTimer`]'s documentation records that *"the storage
/// belongs to `conn/mod.rs`"*, and `crate::conn::shutdown` carries a section
/// headed "THE SHUTDOWN-TIMER CONTRACT WITH `conn/mod.rs`" stating the budget
/// rule this type implements. One implementation behind one trait is what stops
/// the deadline from existing twice and disagreeing.
///
/// # The clock is owned, not passed
///
/// [`filters::ShutdownTimer::time_left_ms`] takes `&self` and no clock, because
/// its callers -- [`filters::FilterChain::shutdown`] among them -- hold the
/// timer through a shared reference from inside a filter walk. So the timer
/// holds the clock. It is spelled `Arc<dyn Clock + Send + Sync>` because
/// [`Clock`] itself requires only [`fmt::Debug`], while the trait this type
/// implements requires [`Send`] and [`Sync`] -- one `CURLSH` is usable from two
/// threads, so the pool that holds these must be.
#[derive(Clone, Debug)]
pub(crate) struct ShutdownTimers {
    /// The injected clock. Nothing here reads a global one.
    clock: Arc<dyn Clock + Send + Sync>,
    /// `conn->shutdown.start[2]`, as an absence rather than a zero reading.
    ///
    /// C tests `start[i].tv_sec` for "not started" and
    /// `(tv_sec > 0) || (tv_usec > 0)` for "started", which are two spellings
    /// of the same intent and are NOT quite the same predicate -- a reading of
    /// `{0, 500}` is "started" by the second and "not started" by the first.
    /// [`Option`] collapses that to one fact, which is the intent both were
    /// reaching for; the divergence is unreachable in the C because
    /// `Curl_pgrs_now` never returns a zero second on a running transfer.
    start: [Option<CurlTime>; SocketIndex::COUNT],
    /// `conn->shutdown.timeout_ms`: the budget, resolved once per connection by
    /// the first [`Self::start`] and shared by both chains. Zero means no
    /// limit.
    timeout_ms: TimeDiff,
    /// `data->set.shutdowntimeout` -- `CURLOPT_SHUTDOWN_TIMEOUT` (`lib/urldata.h:1423`).
    ///
    /// Held here rather than passed to every `start` because it is
    /// configuration, not an argument: C reaches it off `data` at the moment it
    /// resolves the budget, and the middle term of the three-way rule below has
    /// nowhere else to come from.
    configured_ms: TimeDiff,
}

impl ShutdownTimers {
    /// Timers over `clock`, with neither chain started and no configured
    /// budget.
    #[allow(dead_code)] // consumers: crate::transfer and crate::multi
    pub(crate) fn new(clock: Arc<dyn Clock + Send + Sync>) -> Self {
        Self {
            clock,
            start: [None; SocketIndex::COUNT],
            timeout_ms: 0,
            configured_ms: 0,
        }
    }

    /// Records `CURLOPT_SHUTDOWN_TIMEOUT`, in the builder form.
    #[must_use]
    #[allow(dead_code)] // consumers: crate::transfer and crate::multi
    pub(crate) fn with_configured_timeout_ms(mut self, ms: TimeDiff) -> Self {
        self.configured_ms = ms;
        self
    }

    /// Records `CURLOPT_SHUTDOWN_TIMEOUT`.
    #[allow(dead_code)] // consumers: crate::transfer and crate::multi
    pub(crate) fn set_configured_timeout_ms(&mut self, ms: TimeDiff) {
        self.configured_ms = ms;
    }

    /// `data->set.shutdowntimeout`.
    #[allow(dead_code)] // consumers: crate::transfer and crate::multi
    pub(crate) const fn configured_timeout_ms(&self) -> TimeDiff {
        self.configured_ms
    }

    /// `conn->shutdown.timeout_ms`: the budget in force, or zero before either
    /// chain has started.
    #[allow(dead_code)] // consumers: crate::transfer and crate::multi
    pub(crate) const fn timeout_ms(&self) -> TimeDiff {
        self.timeout_ms
    }

    /// When `sockindex`'s shutdown began, if it has.
    #[allow(dead_code)] // consumers: crate::transfer and crate::multi
    pub(crate) fn started_at(
        &self,
        sockindex: SocketIndex,
    ) -> Option<CurlTime> {
        self.start[sockindex.as_usize()]
    }

    /// The three-way budget rule of `lib/connect.c:151-154`, in its order:
    ///
    /// ```text
    /// explicit > 0     ? explicit
    /// : configured > 0 ? configured    (CURLOPT_SHUTDOWN_TIMEOUT)
    /// : DEFAULT_SHUTDOWN_TIMEOUT_MS                        (2000)
    /// ```
    ///
    /// Strictly greater than zero at both steps, so a NEGATIVE explicit or
    /// configured value falls through rather than becoming an already-expired
    /// budget.
    const fn resolve_timeout_ms(&self, explicit_ms: TimeDiff) -> TimeDiff {
        if explicit_ms > 0 {
            explicit_ms
        } else if self.configured_ms > 0 {
            self.configured_ms
        } else {
            DEFAULT_SHUTDOWN_TIMEOUT_MS
        }
    }
}

impl ShutdownTimer for ShutdownTimers {
    /// `Curl_shutdown_started` (`lib/connect.c:200-207`).
    fn started(&self, sockindex: SocketIndex) -> bool {
        self.start[sockindex.as_usize()].is_some()
    }

    /// `Curl_shutdown_start` (`lib/connect.c:144-160`), minus the timer and the
    /// trace line.
    ///
    /// Those two need the transfer, which a filter walk holding this through a
    /// trait object does not have; [`shutdown_start`] is the full entry point
    /// and this is what it delegates the state change to. Splitting them is
    /// also what lets [`filters::FilterChain::shutdown`] start a timer on its
    /// own, which is exactly what `Curl_conn_shutdown` does at
    /// `lib/cfilters.c:180`.
    fn start(&mut self, sockindex: SocketIndex, timeout_ms: TimeDiff) {
        self.start[sockindex.as_usize()] = Some(self.clock.now());
        self.timeout_ms = self.resolve_timeout_ms(timeout_ms);
    }

    /// `Curl_shutdown_timeleft` (`lib/connect.c:162-176`).
    fn time_left_ms(&self, sockindex: SocketIndex) -> TimeDiff {
        // `if(!conn->shutdown.start[sockindex].tv_sec ||
        //    (conn->shutdown.timeout_ms <= 0)) return 0;`
        let Some(started_at) = self.start[sockindex.as_usize()] else {
            return 0;
        };
        if self.timeout_ms <= 0 {
            return 0;
        }
        let left_ms =
            self.timeout_ms - timediff_ms(self.clock.now(), started_at);
        // `return left_ms ? left_ms : -1;`
        if left_ms == 0 {
            -1
        } else {
            left_ms
        }
    }

    /// `Curl_shutdown_clear` (`lib/connect.c:194-198`): the requested chain's
    /// marker only.
    ///
    /// C `memset`s one element of `start[2]`; the budget and the other chain's
    /// marker are untouched, which is why clearing the primary does not release
    /// a shutdown still running on the secondary.
    fn clear(&mut self, sockindex: SocketIndex) {
        self.start[sockindex.as_usize()] = None;
    }
}

/// `Curl_shutdown_start` (`lib/connect.c:144-160`) in full.
///
/// Three effects, in the C's order:
///
/// 1. The chain's start marker is recorded and the connection's budget resolved
///    by [`ShutdownTimers::resolve_timeout_ms`]. Note that the budget is
///    resolved on EVERY call, not only the first, so starting the secondary
///    chain with an explicit timeout re-resolves the shared budget -- which is
///    the C's behaviour and is why [`ShutdownTimers::timeout_ms`] is documented
///    as shared.
/// 2. `EXPIRE_SHUTDOWN` -- timer **14** -- is armed for the resolved budget, and
///    only for a [`TransferRole::Registered`] handle.
/// 3. One trace line is emitted: `shutdown start on connection` for the primary
///    chain and `shutdown start on secondary connection` for the secondary. The
///    C writes one format string, `"shutdown start on%s connection"` with
///    `sockindex ? " secondary" : ""`, and the two rendered results are what a
///    `--trace` log contains.
///
/// The line goes through [`ConnDiagnostics`] rather than through the tracer
/// directly because `CURL_TRC_M` labels its output with the transfer's multi
/// state, which lives in `crate::multi` -- a module this directory does not
/// name. See [`ConnDiagnostics`].
#[allow(dead_code)] // consumers: crate::transfer and crate::multi
pub(crate) fn shutdown_start(
    timers: &mut ShutdownTimers,
    sockindex: SocketIndex,
    timeout_ms: TimeDiff,
    role: TransferRole,
    expiry: &dyn ExpireScheduler,
    diagnostics: &mut dyn ConnDiagnostics,
) {
    timers.start(sockindex, timeout_ms);

    // `if(data->mid) Curl_expire_ex(data, conn->shutdown.timeout_ms,
    //                               EXPIRE_SHUTDOWN);`
    if role.arms_timers() {
        expiry.expire(timers.timeout_ms(), TimerId::Shutdown);
    }

    diagnostics.multi_note(match sockindex {
        SocketIndex::First => SHUTDOWN_START_PRIMARY,
        SocketIndex::Secondary => SHUTDOWN_START_SECONDARY,
    });
}

/// The rendering of `"shutdown start on%s connection"` for the primary chain.
#[allow(dead_code)] // consumers: crate::transfer and crate::multi
pub(crate) const SHUTDOWN_START_PRIMARY: &str = "shutdown start on connection";

/// The rendering of `"shutdown start on%s connection"` for the secondary chain,
/// where the `%s` is `" secondary"`.
#[allow(dead_code)] // consumers: crate::transfer and crate::multi
pub(crate) const SHUTDOWN_START_SECONDARY: &str =
    "shutdown start on secondary connection";

/// `Curl_shutdown_started` (`lib/connect.c:200-207`).
///
/// The C answers `FALSE` when the transfer has no connection at all
/// (`if(data->conn)` guards the whole body); here the absence of a connection is
/// the absence of a [`ShutdownTimers`] to ask, so the caller cannot reach this
/// function without one and the guard has nothing to guard.
#[allow(dead_code)] // consumers: crate::transfer and crate::multi
pub(crate) fn shutdown_started(
    timers: &ShutdownTimers,
    sockindex: SocketIndex,
) -> bool {
    timers.started(sockindex)
}

/// `Curl_shutdown_timeleft` (`lib/connect.c:162-176`): one chain's remaining
/// time.
///
/// Zero when the chain has not started or the budget is not positive, negative
/// once the deadline has passed -- including the exact-zero case, which becomes
/// `-1` for the reason [`timeleft_now_ms`] sets out.
#[allow(dead_code)] // consumers: crate::transfer and crate::multi
pub(crate) fn shutdown_timeleft(
    timers: &ShutdownTimers,
    sockindex: SocketIndex,
) -> TimeDiff {
    timers.time_left_ms(sockindex)
}

/// `Curl_conn_shutdown_timeleft` (`lib/connect.c:178-192`): the deadline across
/// BOTH chains.
///
/// The smallest NON-ZERO remaining time, or zero when neither chain has one.
/// That is not `min` over the two values: a chain with no deadline reports zero,
/// and a plain minimum would let that zero win and report the whole connection
/// unlimited.
///
/// The walk itself is [`ConnShutdownTimer::conn_time_left_ms`], defined once as
/// a blanket method over [`filters::ShutdownTimer`] in `crate::conn::shutdown`
/// so that the queue there and this entry point cannot disagree. This function
/// is the name `lib/connect.h:58-59` gave it.
#[allow(dead_code)] // consumers: crate::transfer and crate::multi
pub(crate) fn conn_shutdown_timeleft(timers: &ShutdownTimers) -> TimeDiff {
    timers.conn_time_left_ms()
}

/// `Curl_shutdown_clear` (`lib/connect.c:194-198`).
#[allow(dead_code)] // consumers: crate::transfer and crate::multi
pub(crate) fn shutdown_clear(
    timers: &mut ShutdownTimers,
    sockindex: SocketIndex,
) {
    timers.clear(sockindex);
}

/// The transfer's deadline, shareable as [`socket::Deadline`].
///
/// # Why this exists
///
/// `crate::conn::socket`, `crate::conn::happy_eyeballs` and
/// `crate::conn::pool` all hold `Arc<dyn Deadline>` and each records that the
/// storage behind it belongs to this file. `Deadline::time_left_ms` takes
/// `&self` and is called from a filter that holds the seam through an [`Arc`],
/// while [`timeleft_now_ms`] needs a mutable-in-practice
/// [`DeadlineState`] and [`ShutdownTimers`] -- so the two live behind one lock,
/// and this is that lock.
///
/// The lock is POISON-TOLERANT, through [`read_lock`] and [`write_lock`]: a
/// panic on another thread must not turn every subsequent deadline query into a
/// panic of its own, because a deadline is consulted from inside the connect
/// path of every unrelated transfer.
#[derive(Debug)]
#[allow(dead_code)] // consumers: crate::transfer and crate::multi
pub(crate) struct TransferDeadline {
    /// Both halves of the arithmetic's input, under one lock.
    inner: RwLock<DeadlineInner>,
}

/// What [`TransferDeadline`] guards.
#[derive(Debug)]
#[allow(dead_code)] // consumers: crate::transfer and crate::multi
struct DeadlineInner {
    /// The transfer's configuration and timing.
    deadline: DeadlineState,
    /// The connection's shutdown timers, which take precedence.
    timers: ShutdownTimers,
}

impl TransferDeadline {
    /// A deadline over `deadline` and `timers`.
    #[allow(dead_code)] // consumers: crate::transfer and crate::multi
    pub(crate) fn new(deadline: DeadlineState, timers: ShutdownTimers) -> Self {
        Self {
            inner: RwLock::new(DeadlineInner { deadline, timers }),
        }
    }

    /// Mutates the transfer's configuration and timing.
    ///
    /// A closure rather than a returned guard so that the lock cannot be held
    /// across an await point by accident, which for a `!Send` guard would be a
    /// compile error in one caller and a deadlock hazard in the next.
    #[allow(dead_code)] // consumers: crate::transfer and crate::multi
    pub(crate) fn with_state<T>(
        &self,
        body: impl FnOnce(&mut DeadlineState) -> T,
    ) -> T {
        body(&mut write_lock(&self.inner).deadline)
    }

    /// Mutates the connection's shutdown timers -- how [`shutdown_start`] and
    /// [`shutdown_clear`] are reached through a shared handle.
    #[allow(dead_code)] // consumers: crate::transfer and crate::multi
    pub(crate) fn with_timers<T>(
        &self,
        body: impl FnOnce(&mut ShutdownTimers) -> T,
    ) -> T {
        body(&mut write_lock(&self.inner).timers)
    }

    /// The reading [`Deadline::time_left_ms`] answers, against `now`.
    ///
    /// Separate from the trait method so that a test can pin the instant
    /// without owning the clock.
    #[allow(dead_code)] // consumers: crate::transfer and crate::multi
    pub(crate) fn time_left_at(&self, now: CurlTime) -> TimeDiff {
        let inner = read_lock(&self.inner);
        timeleft_now_ms(&inner.deadline, &inner.timers, now)
    }
}

impl Deadline for TransferDeadline {
    /// `Curl_timeleft_ms(data)`, through the clock the timers hold.
    ///
    /// Reads the clock once and then does the arithmetic against that reading,
    /// which is what [`timeleft_ms`] does with a clock passed separately -- and
    /// is the only shape available here, because the clock is reached THROUGH
    /// the guard and cannot be borrowed alongside it.
    fn time_left_ms(&self) -> TimeDiff {
        let inner = read_lock(&self.inner);
        let now = inner.timers.clock.now();
        timeleft_now_ms(&inner.deadline, &inner.timers, now)
    }
}

/// A shared read guard that survives a poisoned lock.
///
/// A [`RwLock`] is poisoned by a panic while it was held, and every subsequent
/// `read()` then answers [`Err`]. Propagating that would turn one unrelated
/// panic into a panic in every transfer that later asks for a deadline or a
/// resolved address, which is a strictly worse outcome than reading state that a
/// panic may have left half-written -- and the state under these two locks is
/// plain integers, booleans and an [`Arc`], none of which has an invariant a
/// partial write could break.
#[allow(dead_code)] // consumers: crate::transfer and crate::multi
fn read_lock<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(PoisonError::into_inner)
}

/// An exclusive write guard that survives a poisoned lock -- see [`read_lock`].
#[allow(dead_code)] // consumers: crate::transfer and crate::multi
fn write_lock<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    lock.write().unwrap_or_else(PoisonError::into_inner)
}

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

// The most recent connection -- `lib/connect.c:262-293`

/// What [`getconnectinfo`] found.
///
/// C writes the connection through an out-parameter and RETURNS the socket,
/// with `CURL_SOCKET_BAD` standing for both "no connection" and "no socket".
/// Pairing them in an [`Option`] separates the two: absence means there is no
/// most-recent connection, and a present value carries both facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)] // consumer: crate::easy, behind CURLINFO_ACTIVESOCKET
pub(crate) struct LastConnectInfo {
    /// Where the connection sits in the pool.
    ///
    /// This is INTERNAL and must not be published: it carries a slab slot and a
    /// generation, and AAP 0.6.1's integer-exactness discipline applies to what
    /// crosses the ABI. The identifier an application may hold is
    /// [`ConnectionId`], which the caller already has -- it is what it asked
    /// with.
    pub(crate) key: PoolKey,
    /// `conn->sock[FIRSTSOCKET]`.
    ///
    /// [`crate::conn::select::CURL_SOCKET_BAD`] when the chain has no
    /// descriptor to offer, which is what `CURLINFO_ACTIVESOCKET` then reports.
    pub(crate) socket: Socket,
}

/// `Curl_getconnectinfo` (`lib/connect.c:268-293`): the socket and connection of
/// the most recent transfer on a handle.
///
/// The C's own comment lists the two situations in which a handle has one:
///
/// ```text
/// - that has been used for curl_easy_perform()
/// - that is associated with a multi handle, and whose connection
///   was detached with CURLOPT_CONNECT_ONLY
/// ```
///
/// # The stale identifier, and why it is written back
///
/// `data->state.lastconnect_id` outlives the connection it names: a pooled
/// connection may be evicted, shut down, or terminated while a handle still
/// holds its identifier. C detects that by `Curl_cpool_get_conn` returning
/// `NULL` and then RESETS the field to `-1` before answering
/// `CURL_SOCKET_BAD`, so a second query does not repeat the search. That
/// write-back is why `lastconnect_id` arrives here by mutable reference rather
/// than by value.
///
/// The detection itself is stronger than the C's. C walks the pool comparing
/// `conn->connection_id`, so an identifier can only be stale by being absent;
/// [`ConnectionPool::key_of`] additionally validates the GENERATION of the slab
/// slot, so an identifier whose slot has been reused for a different connection
/// is stale too rather than resolving to the wrong connection.
///
/// # The socket
///
/// C reads `conn->sock[FIRSTSOCKET]`, an array the connection caches. There is
/// no such cache here -- a socket belongs to the socket filter that owns it --
/// so the answer comes from [`filters::FilterChain::socket`], which is
/// `Curl_conn_cf_get_socket` and asks the chain. That is the same descriptor:
/// `conn->sock[]` is written from the filter's own answer when it connects.
///
/// No reference into the pool outlives this call, so a caller cannot hold a
/// connection across the mutation that would invalidate it.
#[allow(dead_code)] // consumer: crate::easy, behind CURLINFO_ACTIVESOCKET
pub(crate) fn getconnectinfo(
    cx: &mut CallCtx<'_, '_>,
    lastconnect_id: &mut ConnectionId,
    pool: &mut ConnectionPool,
) -> Option<LastConnectInfo> {
    // `if(data->state.lastconnect_id != -1) {`
    if lastconnect_id.is_none() {
        return None;
    }

    // `conn = Curl_cpool_get_conn(data, data->state.lastconnect_id);`
    let Some(key) = pool.key_of(*lastconnect_id) else {
        // `if(!conn) { data->state.lastconnect_id = -1;
        //              return CURL_SOCKET_BAD; }`
        *lastconnect_id = ConnectionId::NONE;
        return None;
    };

    let socket = pool.get_mut(key).map(|conn| {
        conn.chains_mut().chain_mut(SocketIndex::First).socket(cx)
    })?;
    Some(LastConnectInfo { key, socket })
}

// Marking a connection or a stream closed -- `lib/connect.c:295-322`

/// `Curl_conncontrol` (`lib/connect.c:298-322`): the end of a connection, or of
/// one stream on it.
///
/// # The truth table, including the case that is not in it
///
/// | `ctrl` | multiplexed | effect |
/// |---|---|---|
/// | [`ConnControl::Connection`] | either | mark closed |
/// | [`ConnControl::Stream`] | no | mark closed |
/// | [`ConnControl::Stream`] | yes | **nothing at all** |
/// | [`ConnControl::Keep`] | either | clear a mark |
///
/// The third row is the one worth stating separately, and the C states it with
/// an empty branch and a comment: *"stream signal on multiplex conn never
/// affects close state"* (`lib/connect.c:316-317`). It is not "mark open" and it
/// is not "leave closed" -- it is a no-op, so a connection already marked for
/// closure stays marked and one that is not stays unmarked. Folding it into the
/// `closeit` computation would clear a mark that a previous
/// [`ConnControl::Connection`] had set, which is a live HTTP/2 connection being
/// reused after something decided it must not be.
///
/// # Where multiplexing is read from
///
/// [`SocketIndex::First`]'s chain, always -- `Curl_conn_is_multiplex(conn,
/// FIRSTSOCKET)` -- even when the caller is a secondary-socket protocol. The
/// search is [`filters::FilterChain::is_multiplex`], which stops at either a
/// `CF_TYPE_IP_CONNECT` or a `CF_TYPE_SSL` filter, so multiplexing INSIDE a
/// tunnel does not count as multiplexing of this connection.
///
/// Note that this reads the FILTER CHAIN and not
/// [`ConnectionState::is_multiplex`]. The two are different questions: the chain
/// says whether a multiplexing filter is installed, and the bit says whether the
/// connection is willing to be shared. `Curl_conn_set_multiplex` sets the bit;
/// this function never reads it.
///
/// # `reason`
///
/// C takes it only in a verbose debug build and its body is
/// `(void)reason; /* useful for debugging */`. It is accepted unconditionally
/// here so that call sites do not carry a `cfg`, and retained only under
/// `debug_assertions` -- see [`ConnectionState::close_reason`].
///
/// This function is the ONLY writer of [`ConnectionState::wants_close`]. The C
/// asks for that with a comment; here the field is private and this is the only
/// assignment in the file, which a test asserts against this file's own source.
#[allow(dead_code)] // consumers: crate::protocols and crate::transfer
pub(crate) fn conncontrol(
    state: &mut ConnectionState,
    chains: &FilterChains,
    ctrl: ConnControl,
    reason: &str,
) {
    // `is_multiplex = Curl_conn_is_multiplex(conn, FIRSTSOCKET);`
    let is_multiplex = chains.chain(SocketIndex::First).is_multiplex();

    // `closeit = (ctrl == CONNCTRL_CONNECTION) ||
    //           ((ctrl == CONNCTRL_STREAM) && !is_multiplex);`
    let closeit = matches!(ctrl, ConnControl::Connection)
        || (matches!(ctrl, ConnControl::Stream) && !is_multiplex);

    if matches!(ctrl, ConnControl::Stream) && is_multiplex {
        // `; /* stream signal on multiplex conn never affects close state */`
        let _ = reason;
    } else if closeit != state.close {
        // `conn->bits.close = closeit;` -- the one assignment.
        state.close = closeit;
        #[cfg(debug_assertions)]
        {
            state.close_reason = Some(reason.to_owned());
        }
    }
}

// Allowing a connection to be multiplexed -- `lib/connect.c:595-603`

/// The multi handle a connection is attached to, so far as this file reaches it.
///
/// `conn->attached_multi` (`lib/urldata.h:675`) is a back pointer to
/// `struct Curl_multi`, and `crate::multi` is a module this directory does not
/// name -- see the module documentation. The single call made through that
/// pointer from `lib/connect.c` is `Curl_multi_connchanged`, so that one call is
/// the whole of the interface, and the pointer's absence -- a connection not yet
/// attached -- is the [`Option`] the caller passes.
#[allow(dead_code)] // consumers: crate::protocols and crate::transfer
pub(crate) trait MultiOwnerNotify: fmt::Debug {
    /// `Curl_multi_connchanged(multi)` (`lib/multiif.h:45`): *"there is a
    /// connection in the connection pool that is now available"*, which wakes
    /// transfers parked for want of one.
    fn connchanged(&mut self);
}

/// `Curl_conn_set_multiplex` (`lib/connect.c:595-603`): let this connection be
/// shared.
///
/// A one-way latch, and the guard is what makes it one: `if(!conn->bits.multiplex)`
/// means a second call on an already-multiplexed connection does nothing and, in
/// particular, does not notify again. That matters because
/// `Curl_multi_connchanged` sets `multi->recheckstate`, which makes the next
/// `curl_multi_perform` re-examine every parked transfer -- an HTTP/2 connection
/// serving many streams would otherwise force that scan on every stream.
///
/// Returns whether the transition happened, which the C's `void` cannot. The
/// answer is derivable by the caller -- read the bit first -- so this adds no
/// capability, only a way for a test to observe the latch directly.
#[allow(dead_code)] // consumers: crate::protocols and crate::transfer
pub(crate) fn conn_set_multiplex(
    state: &mut ConnectionState,
    attached_multi: Option<&mut dyn MultiOwnerNotify>,
) -> bool {
    if state.multiplex {
        return false;
    }
    state.multiplex = true;
    if let Some(multi) = attached_multi {
        multi.connchanged();
    }
    true
}

// The injected seams -- AAP 0.3.3 P12

/// Where this module's diagnostics go.
///
/// # Why the tracer is not enough
///
/// `lib/connect.c` writes two kinds of diagnostic and they need different
/// things. `failf(data, ...)` needs only the tracer and the error buffer, both of
/// which [`filters::CallCtx`] already carries, so the HAProxy refusal in
/// [`SetupFilter::connect`] goes straight through [`crate::trace::failf`] with no
/// seam at all. `CURL_TRC_M(data, ...)` is different: it labels its line with the
/// transfer's multi STATE, which is `crate::multi::state::CurlMstate` -- and this
/// directory does not name `crate::multi`, deliberately, because the multi handle
/// owns connections and a dependency the other way would close the cycle.
///
/// So the one `CURL_TRC_M` line this file emits travels out through this trait to
/// whoever does hold the state. That is the same arrangement
/// `crate::conn::shutdown` uses for `ShutdownHost` and
/// `crate::conn::happy_eyeballs` uses for `ConnMeta`, for the same reason.
#[allow(dead_code)] // consumers: the protocols, TLS and proxy modules
pub(crate) trait ConnDiagnostics: fmt::Debug {
    /// `CURL_TRC_M(data, "...")` (`lib/curl_trc.h:129-131`): a multi-handle line
    /// carrying the transfer's state.
    ///
    /// The message arrives already rendered, because the two renderings this
    /// file produces are fixed strings -- [`SHUTDOWN_START_PRIMARY`] and
    /// [`SHUTDOWN_START_SECONDARY`] -- and a format-argument seam would buy
    /// nothing but a lifetime.
    fn multi_note(&mut self, message: &str);
}

/// A [`ConnDiagnostics`] that discards everything.
///
/// What a caller with no transfer to attribute a line to uses -- a test, or the
/// admin handle, whose trace output nothing reads. Discarding is honest here
/// rather than lossy: `CURL_TRC_M` is itself gated on `--trace-config multi`, so
/// the overwhelmingly common production behaviour is also to discard.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)] // consumers: the protocols, TLS and proxy modules
pub(crate) struct SilentDiagnostics;

impl ConnDiagnostics for SilentDiagnostics {
    fn multi_note(&mut self, message: &str) {
        let _ = message;
    }
}

/// `data->state.dns[2]` (`lib/urldata.h`): the resolved address list each chain
/// was set up with.
///
/// # Ownership replaces the bookkeeping
///
/// C holds a `struct Curl_dns_entry *` per socket index and releases it with
/// `Curl_resolv_unlink(data, &data->state.dns[sockindex])`, which decrements the
/// entry's reference count, clears the pointer, and frees the entry when the
/// count reaches zero. [`crate::dns::DnsEntryRef`] is an
/// [`Arc`](std::sync::Arc), so all three of those are what dropping the value
/// does. `Curl_resolv_unlink` therefore has no successor function: it is
/// [`Self::release`], whose whole body is a `take`.
///
/// That is also why [`conn_setup`]'s failure path is a `release` and not a
/// "remember to unlink" comment -- an early return from anywhere between the
/// store and the failure releases the entry on the way out.
#[derive(Clone, Debug, Default)]
#[allow(dead_code)] // consumers: the protocols, TLS and proxy modules
pub(crate) struct ResolvedEntries {
    /// One entry per chain, absent until a `conn_setup` stores one.
    entries: [Option<DnsEntryRef>; SocketIndex::COUNT],
}

impl ResolvedEntries {
    /// Neither chain resolved.
    #[allow(dead_code)] // consumers: the protocols, TLS and proxy modules
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// `data->state.dns[sockindex]`.
    #[allow(dead_code)] // consumers: the protocols, TLS and proxy modules
    pub(crate) fn get(&self, sockindex: SocketIndex) -> Option<&DnsEntryRef> {
        self.entries[sockindex.as_usize()].as_ref()
    }

    /// The `Curl_resolv_unlink` then assignment pair of `lib/connect.c:567-568`,
    /// as one operation.
    ///
    /// Returns whatever was displaced so that a caller may inspect it; dropping
    /// the return value is the release, which is why the two C statements
    /// collapse into one here without losing the unlink.
    #[allow(dead_code)] // consumers: the protocols, TLS and proxy modules
    pub(crate) fn replace(
        &mut self,
        sockindex: SocketIndex,
        entry: DnsEntryRef,
    ) -> Option<DnsEntryRef> {
        self.entries[sockindex.as_usize()].replace(entry)
    }

    /// `Curl_resolv_unlink(data, &data->state.dns[sockindex])`
    /// (`lib/hostip.h:117`).
    #[allow(dead_code)] // consumers: the protocols, TLS and proxy modules
    pub(crate) fn release(
        &mut self,
        sockindex: SocketIndex,
    ) -> Option<DnsEntryRef> {
        self.entries[sockindex.as_usize()].take()
    }
}

/// Whether a chain has an address to connect to -- the
/// `if(!dns) return CURLE_FAILED_INIT;` of `cf_setup_connect`
/// (`lib/connect.c:355-356`).
///
/// # Why the SETUP filter asks rather than holds
///
/// C reads `data->state.dns[cf->sockindex]` FRESH at the top of every connect
/// pass, and it must: the entry is stored by `Curl_conn_setup` before the chain
/// is ever driven, and it is released again on a failure path that can run
/// between two passes. A copy taken when the filter was built would answer for a
/// state that no longer holds, which is the difference between reporting
/// [`CURLcode::FailedInit`] and dereferencing nothing.
///
/// So the filter holds a shared handle to the storage and asks it.
/// [`SharedResolvedEntries`] implements this, and is the ordinary production
/// wiring; a caller with no storage to share can inject anything else.
pub(crate) trait ResolvedPresence: fmt::Debug + Send + Sync {
    /// Whether `data->state.dns[sockindex]` is non-`NULL`.
    fn has_resolved(&self, sockindex: SocketIndex) -> bool;
}

/// [`ResolvedEntries`] behind a lock, so that [`conn_setup`] can write it while
/// a [`SetupFilter`] reads it.
///
/// The two are separated in time rather than running concurrently -- a chain is
/// set up and only then driven -- but they are separated by an [`Arc`], and a
/// filter is `Send` because a connection may move between tokio worker threads.
/// A lock is what makes that shape expressible within the crate's safety
/// policy, with no interior-mutability escape hatch; the contention is nil.
#[derive(Debug, Default)]
#[allow(dead_code)] // consumers: the protocols, TLS and proxy modules
pub(crate) struct SharedResolvedEntries {
    /// The storage. Poison-tolerant, through [`read_lock`] and [`write_lock`].
    entries: RwLock<ResolvedEntries>,
}

impl SharedResolvedEntries {
    /// Neither chain resolved.
    #[allow(dead_code)] // consumers: the protocols, TLS and proxy modules
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Reads the entries.
    #[allow(dead_code)] // consumers: the protocols, TLS and proxy modules
    pub(crate) fn with<T>(
        &self,
        body: impl FnOnce(&ResolvedEntries) -> T,
    ) -> T {
        body(&read_lock(&self.entries))
    }

    /// Mutates the entries -- how [`conn_setup`] stores and releases one.
    #[allow(dead_code)] // consumers: the protocols, TLS and proxy modules
    pub(crate) fn with_mut<T>(
        &self,
        body: impl FnOnce(&mut ResolvedEntries) -> T,
    ) -> T {
        body(&mut write_lock(&self.entries))
    }
}

impl ResolvedPresence for SharedResolvedEntries {
    fn has_resolved(&self, sockindex: SocketIndex) -> bool {
        self.with(|entries| entries.get(sockindex).is_some())
    }
}

/// Builds the filters a chain needs, without this file naming any of them.
///
/// # The five stage inserters, and the one specialiser
///
/// `cf_setup_connect` reaches six functions that live in six other translation
/// units (`lib/cf-ip-happy.c`, `lib/socks.c`, `lib/vtls/vtls.c`,
/// `lib/http_proxy.c`, `lib/cf-haproxy.c` and `lib/cf-https-connect.c`). None of
/// their Rust counterparts exists yet, and AAP 0.3.3 P12 requires that the
/// protocol and TLS modules be INJECTED here rather than imported: importing a
/// concrete TLS module here would make the protocol layer name TLS
/// transitively, which is the coupling the filter chain exists to remove. AAP
/// 0.8.4's acceptance gate greps this file for that import path, so the path is
/// not spelled anywhere in it -- not even in prose.
///
/// # Why five of them return a filter and one installs a chain
///
/// The asymmetry is the C's. The five stage functions are
/// `..._insert_after(cf_at, data, ...)` -- they are handed a filter and splice
/// one BELOW it. The specialiser is `Curl_cf_https_setup(data, conn, sockindex)`
/// -- it is handed the connection and installs a whole chain of its own, and it
/// runs only when no chain exists at all.
///
/// A filter cannot reach the chain it is installed in -- it does not own it --
/// so the five return a [`filters::FilterLink`] and [`SetupFilter`] splices it
/// below itself. The specialiser runs before any filter exists, so it takes the
/// chain directly.
///
/// # What an implementation owes
///
/// Each returned filter must have NO SUCCESSOR: it is about to be spliced above
/// one, and a link it already held would be stranded. It MAY, however, already
/// carry its connection's identity and socket index --
/// [`crate::conn::happy_eyeballs::HappyEyeballs::new`] stamps both from the
/// arguments below -- because [`SetupFilter`]'s splice restamps every node it
/// installs, making a correct stamp idempotent and a stale one corrected.
pub(crate) trait ConnectionFilterFactories:
    fmt::Debug + Send + Sync
{
    /// `cf_ip_happy_insert_after(cf_at, data, transport)`
    /// (`lib/cf-ip-happy.h:45-47`): dual-stack connection racing for
    /// `transport`.
    ///
    /// # Errors
    ///
    /// [`CURLcode::UnsupportedProtocol`] for a transport with no registered
    /// provider, which is `get_cf_create` returning `NULL`
    /// (`lib/cf-ip-happy.c:968-972`).
    fn happy_eyeballs(
        &self,
        cx: &mut CallCtx<'_, '_>,
        sockindex: SocketIndex,
        conn: Option<ConnId>,
        transport: Transport,
    ) -> CurlResult<FilterLink>;

    /// `Curl_cf_socks_proxy_insert_after(cf_at, data)` (`lib/socks.h:49-50`).
    ///
    /// # Errors
    ///
    /// Whatever the SOCKS layer reports.
    fn socks_proxy(
        &self,
        cx: &mut CallCtx<'_, '_>,
        sockindex: SocketIndex,
        conn: Option<ConnId>,
    ) -> CurlResult<FilterLink>;

    /// `Curl_cf_ssl_proxy_insert_after(cf_at, data)`
    /// (`lib/vtls/vtls.h:222-223`): TLS to the PROXY, not to the origin.
    ///
    /// # Errors
    ///
    /// Whatever the TLS layer reports.
    fn proxy_tls(
        &self,
        cx: &mut CallCtx<'_, '_>,
        sockindex: SocketIndex,
        conn: Option<ConnId>,
    ) -> CurlResult<FilterLink>;

    /// `Curl_cf_http_proxy_insert_after(cf_at, data)`
    /// (`lib/http_proxy.h:54-55`): the `CONNECT` tunnel, which itself chooses
    /// between HTTP/1 and HTTP/2.
    ///
    /// # Errors
    ///
    /// Whatever the proxy layer reports.
    fn http_proxy_tunnel(
        &self,
        cx: &mut CallCtx<'_, '_>,
        sockindex: SocketIndex,
        conn: Option<ConnId>,
    ) -> CurlResult<FilterLink>;

    /// `Curl_cf_haproxy_insert_after(cf_at, data)`
    /// (`lib/cf-haproxy.h:32-33`): the PROXY protocol header.
    ///
    /// # Errors
    ///
    /// Whatever the HAProxy layer reports. The refusal when TLS is already in
    /// place is decided by [`SetupFilter::connect`] BEFORE this is called, so an
    /// implementation never has to check for it.
    fn haproxy(
        &self,
        cx: &mut CallCtx<'_, '_>,
        sockindex: SocketIndex,
        conn: Option<ConnId>,
    ) -> CurlResult<FilterLink>;

    /// `Curl_cf_ssl_insert_after(cf_at, data)` (`lib/vtls/vtls.h:215-216`): TLS
    /// to the ORIGIN.
    ///
    /// # Errors
    ///
    /// Whatever the TLS layer reports.
    fn origin_tls(
        &self,
        cx: &mut CallCtx<'_, '_>,
        sockindex: SocketIndex,
        conn: Option<ConnId>,
    ) -> CurlResult<FilterLink>;

    /// `Curl_cf_https_setup(data, conn, sockindex)`
    /// (`lib/cf-https-connect.h:43-45`): the HTTPS version race, which installs
    /// its own chain.
    ///
    /// Called by [`conn_setup`] only when the chain is EMPTY and the scheme is
    /// `https`, and it may legitimately install nothing -- a build with no
    /// HTTP/3 and no HTTP/2 has no versions to race, and the generic
    /// [`SetupFilter`] then applies. The chain being non-empty afterwards is how
    /// [`conn_setup`] tells the two apart, exactly as
    /// `if(!conn->cfilter[sockindex])` does at `lib/connect.c:581`.
    ///
    /// # Errors
    ///
    /// Whatever the HTTPS-connect layer reports.
    #[allow(dead_code)] // consumers: the protocols, TLS and proxy modules
    fn https_setup(
        &self,
        cx: &mut CallCtx<'_, '_>,
        chain: &mut FilterChain,
    ) -> CurlResult<()>;
}

/// Everything a connection is built with that this file does not own.
///
/// AAP 0.3.3 P12 requires the resolver, the clock, the timer scheduler and the
/// filter factories to be injected rather than reached for globally, and this is
/// the one value that carries them. Bundling has a concrete purpose beyond
/// tidiness: a connection is built in several steps -- [`conn_setup`], then a
/// connect pass per stage -- and a bundle is what lets each step be handed the
/// same seams without a five-argument signature at every call.
///
/// # On the resolver
///
/// This module never resolves anything. `lib/connect.c` does not either: it
/// receives a `struct Curl_dns_entry *` that somebody else looked up and stores
/// it (`lib/connect.c:567-568`). The seam is here because a connection's owner
/// needs one place to state it -- [`crate::dns::Resolver`] is what
/// `crate::transfer` will call before it calls [`conn_setup`] -- and because
/// stating it anywhere else would invite this file to grow a lookup of its own.
#[derive(Clone, Debug)]
#[allow(dead_code)] // consumers: the protocols, TLS and proxy modules
pub(crate) struct ConnSeams {
    /// `Curl_resolv` (`lib/hostip.c:860-1012`), as a contract. Read by the
    /// caller that resolves; never called from this module.
    resolver: Arc<dyn crate::dns::Resolver>,
    /// `curlx_now()`. The clock every deadline in this file measures against.
    clock: Arc<dyn Clock + Send + Sync>,
    /// `Curl_expire_ex` and `Curl_expire_done` (`lib/multiif.h:31-32`).
    expiry: Arc<dyn ExpireScheduler>,
    /// The six filter builders of [`ConnectionFilterFactories`].
    factories: Arc<dyn ConnectionFilterFactories>,
}

impl ConnSeams {
    /// A bundle over the four seams.
    #[allow(dead_code)] // consumers: the protocols, TLS and proxy modules
    pub(crate) fn new(
        resolver: Arc<dyn crate::dns::Resolver>,
        clock: Arc<dyn Clock + Send + Sync>,
        expiry: Arc<dyn ExpireScheduler>,
        factories: Arc<dyn ConnectionFilterFactories>,
    ) -> Self {
        Self {
            resolver,
            clock,
            expiry,
            factories,
        }
    }

    /// The injected resolver, for the caller that performs the lookup.
    #[allow(dead_code)] // consumers: the protocols, TLS and proxy modules
    pub(crate) fn resolver(&self) -> &Arc<dyn crate::dns::Resolver> {
        &self.resolver
    }

    /// The injected clock.
    #[allow(dead_code)] // consumers: the protocols, TLS and proxy modules
    pub(crate) fn clock(&self) -> &Arc<dyn Clock + Send + Sync> {
        &self.clock
    }

    /// The injected timer scheduler, which [`shutdown_start`] arms.
    #[allow(dead_code)] // consumers: the protocols, TLS and proxy modules
    pub(crate) fn expiry(&self) -> &Arc<dyn ExpireScheduler> {
        &self.expiry
    }

    /// The injected filter factories, which [`SetupFilter`] builds through.
    #[allow(dead_code)] // consumers: the protocols, TLS and proxy modules
    pub(crate) fn factories(&self) -> &Arc<dyn ConnectionFilterFactories> {
        &self.factories
    }

    /// Timers over this bundle's clock -- the pairing every connection needs.
    #[allow(dead_code)] // consumers: the protocols, TLS and proxy modules
    pub(crate) fn shutdown_timers(&self) -> ShutdownTimers {
        ShutdownTimers::new(Arc::clone(&self.clock))
    }
}

// The SETUP filter -- `lib/connect.c:324-553`

/// The `name` member of `struct Curl_cft_setup` (`lib/connect.c:471`).
///
/// `--trace-config` matches it and every trace line this filter emits is
/// labelled with it. [`crate::trace::TraceFilter::Setup`] carries the same
/// spelling, and [`crate::trace::TraceFilter::from_name`] is what resolves one
/// to the other.
pub(crate) const CF_SETUP_FILTER_NAME: &str = "SETUP";

/// The `flags` member (`lib/connect.c:472`): `0`.
///
/// The SETUP filter declares no capability, which is exactly right -- it neither
/// provides an IP connection, nor TLS, nor multiplexing, nor proxying. It only
/// arranges for the filters that do. That zero is also why it is invisible to
/// every capability search in `crate::conn::filters`: `is_ssl`,
/// `is_multiplex` and `is_ip_connected` walk past it without a decision.
pub(crate) const CF_SETUP_FLAGS: CfType = CfType::NONE;

/// The `log_level` member (`lib/connect.c:473`): `CURL_LOG_LVL_NONE`.
#[allow(dead_code)] // consumers: the protocols, TLS and proxy modules
pub(crate) const CF_SETUP_LOG_LEVEL: i32 = CURL_LOG_LVL_NONE;

/// `failf(data, "haproxy protocol not support with SSL encryption in place (QUIC?)")`
/// (`lib/connect.c:411-412`).
///
/// Reproduced byte for byte, including *"not support"* where English wants "not
/// supported": AAP 0.8.1 freezes the observable surface, and this string reaches
/// `CURLOPT_ERRORBUFFER` and `curl`'s stderr. The C writes it as two adjacent
/// literals that the preprocessor joins; the join is what is quoted here.
pub(crate) const HAPROXY_AFTER_SSL: &str =
    "haproxy protocol not support with SSL encryption in place (QUIC?)";

/// How far the SETUP filter has got in building the chain beneath it.
///
/// `cf_setup_state` (`lib/connect.c:324-332`), whose seven values are visited in
/// declaration order and COMPARED with `<`: every stage guard is
/// `ctx->state < CF_SETUP_CNNCT_...`, so the ordering is part of the contract and
/// [`Ord`] is derived rather than hand-written.
///
/// # Which states a plain connection actually passes through
///
/// Not all of them, and the pattern is worth knowing before reading
/// [`SetupFilter::connect`]. Two of the five stages -- SOCKS and the HTTP proxy
/// -- carry their configuration test in the OUTER guard, so an unconfigured
/// stage advances nothing:
///
/// ```text
/// if(ctx->state < CF_SETUP_CNNCT_SOCKS && cf->conn->bits.socksproxy) {
///   ...
///   ctx->state = CF_SETUP_CNNCT_SOCKS;      /* inside the guard */
/// ```
///
/// The other three advance unconditionally, because their configuration test is
/// nested INSIDE a guard that only looks at the state. So a direct, unproxied,
/// plaintext connection goes [`Self::Init`] -> [`Self::CnnctEyeballs`] ->
/// [`Self::CnnctHaproxy`] -> [`Self::CnnctSsl`] -> [`Self::Done`] and never
/// takes the value [`Self::CnnctSocks`] or [`Self::CnnctHttpProxy`] at all. That
/// is not a defect to tidy: the states are progress markers for a `<` test, not
/// a path every connection walks.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum SetupState {
    /// `CF_SETUP_INIT`: nothing built yet. The state a fresh filter is in and
    /// the state [`SetupFilter::close`] returns it to.
    #[default]
    Init = 0,
    /// `CF_SETUP_CNNCT_EYEBALLS`: dual-stack racing is installed.
    CnnctEyeballs = 1,
    /// `CF_SETUP_CNNCT_SOCKS`: a SOCKS proxy is installed.
    CnnctSocks = 2,
    /// `CF_SETUP_CNNCT_HTTP_PROXY`: proxy TLS and/or the `CONNECT` tunnel are
    /// installed.
    CnnctHttpProxy = 3,
    /// `CF_SETUP_CNNCT_HAPROXY`: the PROXY protocol header is installed, or was
    /// not asked for.
    CnnctHaproxy = 4,
    /// `CF_SETUP_CNNCT_SSL`: origin TLS is installed, or was not wanted.
    CnnctSsl = 5,
    /// `CF_SETUP_DONE`: the chain is complete and connected.
    Done = 6,
}

impl SetupState {
    /// Every state, in `lib/connect.c:324-332` declaration order.
    #[allow(dead_code)] // consumers: the protocols, TLS and proxy modules
    pub(crate) const ALL: [Self; 7] = [
        Self::Init,
        Self::CnnctEyeballs,
        Self::CnnctSocks,
        Self::CnnctHttpProxy,
        Self::CnnctHaproxy,
        Self::CnnctSsl,
        Self::Done,
    ];

    /// The state as the C's enumerator ordinal.
    #[allow(dead_code)] // consumers: the protocols, TLS and proxy modules
    pub(crate) const fn as_i32(self) -> i32 {
        self as i32
    }
}

/// What the SETUP filter reads about its connection while it builds.
///
/// # Why these five bits and not `struct connectdata`
///
/// Because they are exactly what `cf_setup_connect` consults:
/// `conn->bits.socksproxy`, `conn->bits.httpproxy`, `conn->bits.tunnel_proxy`,
/// `IS_HTTPS_PROXY(conn->http_proxy.proxytype)`, `data->set.haproxyprotocol` and
/// `conn->scheme->flags & PROTOPT_SSL`. Nothing else about the connection reaches
/// this file, so nothing else is carried.
///
/// # Why it is cloned rather than borrowed
///
/// A filter outlives the call that built it and is reached later through a
/// [`filters::FilterLink`], so it cannot hold a borrow of the connection. The
/// two costly members are [`Arc`]s and the rest are bits, so a clone is two
/// refcount bumps.
///
/// The values are read once, when the filter is built, which matches the C:
/// `conn->bits` and `data->set` are settled before a chain is driven. The one
/// thing that genuinely changes between passes is the resolved address, and that
/// is why [`Self::resolved`] is a live handle rather than a copied `bool` -- see
/// [`ResolvedPresence`].
#[derive(Clone, Debug)]
pub(crate) struct SetupContext {
    /// The six filter builders.
    factories: Arc<dyn ConnectionFilterFactories>,
    /// `data->state.dns[]`, asked afresh on every connect pass.
    resolved: Arc<dyn ResolvedPresence>,
    /// `conn->bits.socksproxy` (`lib/urldata.h:340`).
    socks_proxy: bool,
    /// `conn->bits.httpproxy` (`lib/urldata.h:339`).
    http_proxy: bool,
    /// `conn->bits.tunnel_proxy` (`lib/urldata.h:342`).
    tunnel_proxy: bool,
    /// `conn->http_proxy.proxytype`, tested by [`ProxyType::is_https`].
    proxy_type: ProxyType,
    /// `data->set.haproxyprotocol` -- `CURLOPT_HAPROXYPROTOCOL`.
    haproxy_protocol: bool,
    /// `conn->scheme->flags`; only [`ProtocolOptions::SSL`] is read.
    protocol_flags: ProtocolOptions,
}

impl SetupContext {
    /// A context over the two injected seams, with no proxy and no scheme
    /// flags.
    ///
    /// The state a direct, plaintext, unproxied connection is in, which is the
    /// shape most callers want; the builders below add whatever is configured.
    ///
    /// `resolved` and the storage [`conn_setup`] writes to must be the SAME
    /// cell: the filter's `!dns` test is only meaningful if it observes the entry
    /// that `conn_setup` stored. In production both are `Arc::clone`s of one
    /// `SyncCell<ResolvedEntries>`, which implements [`ResolvedPresence`]
    /// directly for exactly this purpose.
    #[allow(dead_code)] // consumers: the protocols, TLS and proxy modules
    pub(crate) fn new(
        factories: Arc<dyn ConnectionFilterFactories>,
        resolved: Arc<dyn ResolvedPresence>,
    ) -> Self {
        Self {
            factories,
            resolved,
            socks_proxy: false,
            http_proxy: false,
            tunnel_proxy: false,
            proxy_type: ProxyType::Http,
            haproxy_protocol: false,
            protocol_flags: ProtocolOptions::NONE,
        }
    }

    /// Records `conn->bits.socksproxy`.
    #[must_use]
    #[allow(dead_code)] // consumers: the protocols, TLS and proxy modules
    pub(crate) fn with_socks_proxy(mut self, socks_proxy: bool) -> Self {
        self.socks_proxy = socks_proxy;
        self
    }

    /// Records `conn->bits.httpproxy`, `conn->bits.tunnel_proxy` and
    /// `conn->http_proxy.proxytype` together.
    ///
    /// One builder for the three because they are one decision: an HTTP proxy
    /// has a type and may or may not tunnel, and setting the tunnel bit without
    /// the proxy bit describes nothing the C can represent.
    #[must_use]
    #[allow(dead_code)] // consumers: the protocols, TLS and proxy modules
    pub(crate) fn with_http_proxy(
        mut self,
        proxy_type: ProxyType,
        tunnel_proxy: bool,
    ) -> Self {
        self.http_proxy = true;
        self.proxy_type = proxy_type;
        self.tunnel_proxy = tunnel_proxy;
        self
    }

    /// Records `data->set.haproxyprotocol`.
    #[must_use]
    #[allow(dead_code)] // consumers: the protocols, TLS and proxy modules
    pub(crate) fn with_haproxy_protocol(mut self, haproxy: bool) -> Self {
        self.haproxy_protocol = haproxy;
        self
    }

    /// Records `conn->scheme->flags`.
    #[must_use]
    #[allow(dead_code)] // consumers: the protocols, TLS and proxy modules
    pub(crate) fn with_protocol_flags(
        mut self,
        flags: ProtocolOptions,
    ) -> Self {
        self.protocol_flags = flags;
        self
    }

    /// `conn->scheme->flags`.
    #[allow(dead_code)] // consumers: the protocols, TLS and proxy modules
    pub(crate) const fn protocol_flags(&self) -> ProtocolOptions {
        self.protocol_flags
    }
}

/// `conn->scheme` and `conn->transport_wanted`, so far as [`conn_setup`] reads
/// them.
///
/// Two members, because `Curl_conn_setup` consults exactly two things about the
/// scheme: whether it is `CURLPROTO_HTTPS`, which decides whether the HTTPS
/// version race is offered the chain, and `conn->transport_wanted`, which the
/// generic filter is built with. The scheme's `flags` reach the filter through
/// [`SetupContext::with_protocol_flags`] instead, because it is the FILTER that
/// reads them, on every pass, rather than this function once.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[allow(dead_code)] // consumers: the protocols, TLS and proxy modules
pub(crate) struct SchemeSetup {
    /// `conn->scheme->protocol == CURLPROTO_HTTPS` (`lib/connect.c:572`).
    pub(crate) is_https: bool,
    /// `conn->transport_wanted` (`lib/urldata.h:719`), which
    /// `lib/connect.c:583` passes to the generic filter.
    pub(crate) transport_wanted: Transport,
}

/// The outermost connection filter: the one that builds all the others.
///
/// `Curl_cft_setup` (`lib/connect.c:470-486`) together with its context
/// `struct cf_setup_ctx` (`lib/connect.c:334-338`). The C keeps the three state
/// members behind a `void *ctx` and casts it back at the top of every method;
/// here they are ordinary typed fields, which is the translation rule AAP 0.1.2
/// sets for the whole filter layer.
#[derive(Debug)]
pub(crate) struct SetupFilter {
    /// The chain link, socket index and two state flags.
    base: FilterBase,
    /// `ctx->state`.
    state: SetupState,
    /// `ctx->ssl_mode`.
    tls_mode: TlsMode,
    /// `ctx->transport`.
    transport: Transport,
    /// The injected seams and the connection's configuration.
    context: SetupContext,
}

impl SetupFilter {
    /// `cf_setup_create` (`lib/connect.c:488-518`).
    ///
    /// The C's `CURLcode` return has no successor, for the reason
    /// [`filters::link`] records: its only failure was `curlx_calloc` answering
    /// `NULL`, and a [`Box`] of a fixed-size value has no stable fallible
    /// spelling at the declared minimum Rust version. Nothing else in
    /// `cf_setup_create` can fail.
    ///
    /// # The connection is deliberately NOT stamped here
    ///
    /// Faithfully so: `Curl_cf_create` leaves `cf->conn` as `NULL`, and
    /// `Curl_conn_cf_add` (`lib/cfilters.c:339`) and
    /// `Curl_conn_cf_insert_after` (`:357`) are what assign it. The Rust
    /// primitives raise that from a convention to a PRECONDITION -- both
    /// [`filters::FilterChain::add`] and [`filters::FilterChain::insert_after`]
    /// assert `!is_attached()` before installing -- so a constructor that
    /// stamped the identity would render its own product uninstallable. The one
    /// caller that keeps a `SetupFilter` outside a chain stamps it through
    /// [`filters::ConnFilter::base_mut`].
    #[allow(dead_code)] // consumers: the protocols, TLS and proxy modules
    pub(crate) fn new(
        sockindex: SocketIndex,
        context: SetupContext,
        transport: Transport,
        tls_mode: TlsMode,
    ) -> Self {
        Self {
            base: FilterBase::new(sockindex),
            state: SetupState::Init,
            tls_mode,
            transport,
            context,
        }
    }

    /// How far the chain below has been built.
    #[allow(dead_code)] // consumers: the protocols, TLS and proxy modules
    pub(crate) const fn state(&self) -> SetupState {
        self.state
    }

    /// `ctx->ssl_mode`.
    #[allow(dead_code)] // consumers: the protocols, TLS and proxy modules
    pub(crate) const fn tls_mode(&self) -> TlsMode {
        self.tls_mode
    }

    /// `ctx->transport`.
    #[allow(dead_code)] // consumers: the protocols, TLS and proxy modules
    pub(crate) const fn transport(&self) -> Transport {
        self.transport
    }

    /// One trace line attributed to this filter -- `CURL_TRC_CF(data, cf, ...)`.
    fn trace(&self, cx: &mut CallCtx<'_, '_>, message: &str) {
        let sockindex = self.base.sockindex().as_i32();
        if let Some(identity) = self.trace_filter() {
            if let Some(tracer) = cx.tracer_mut() {
                trc_cf!(tracer, identity, sockindex, "{}", message);
            }
        }
    }

    /// `!cf->next || !cf->next->connected`, inverted: the successor exists AND
    /// reports itself connected.
    fn next_connected(&self) -> bool {
        self.base
            .next_ref()
            .is_some_and(|next| next.base().is_connected())
    }

    /// Lends the subchain to a [`filters::FilterChain`] for the duration of one
    /// question, then takes it back.
    ///
    /// # Why the subchain is lent rather than walked here
    ///
    /// The question this is used for is `Curl_conn_is_ssl`, whose search is not
    /// a simple scan: it answers true at the first `CF_TYPE_SSL` filter but
    /// STOPS at the first `CF_TYPE_IP_CONNECT` one, which is how TLS towards a
    /// proxy is excluded from "is this connection TLS-protected". That search is
    /// [`filters::FilterChain::is_ssl`] and it belongs there. Copying ten lines
    /// of it into this file is how the two come to disagree about the boundary,
    /// so the subchain is handed to the code that owns the search instead.
    ///
    /// The C reaches the search differently -- `Curl_conn_is_ssl(cf->conn,
    /// cf->sockindex)` walks `conn->cfilter[sockindex]` from the CHAIN HEAD via
    /// the back pointer a filter keeps. A filter here does not own its chain and
    /// has no such pointer (see [`filters::ConnId`]), so it can only see from
    /// itself downwards. The two agree wherever the SETUP filter is the head,
    /// which `cf_setup_add` makes it; and at the one mid-chain insertion point
    /// in the C tree -- `lib/cf-https-connect.c:161-165`, which detaches
    /// `cf->next`, inserts SETUP, harvests the result and restores the link --
    /// the enclosing filter is `Curl_cft_http_connect`, whose flags are
    /// `CF_TYPE_HTTP` and not `CF_TYPE_SSL`, so it contributes no decision to
    /// the search either.
    ///
    /// Borrowing is `&mut self` because the link is moved out and back; the chain
    /// is whole again before the function returns, on every path.
    fn with_subchain<T>(&mut self, body: impl FnOnce(&FilterChain) -> T) -> T {
        let mut lent =
            FilterChain::new(self.base.conn(), self.base.sockindex());
        let displaced = lent.set_chain(self.base.take_next());
        debug_assert!(displaced.is_none(), "a fresh chain has no head");
        let answer = body(&lent);
        self.base.set_next(lent.take_chain());
        answer
    }

    /// `Curl_conn_is_ssl(cf->conn, cf->sockindex)` (`lib/cfilters.c:632-648`),
    /// asked of the chain from this filter downwards.
    fn subchain_is_ssl(&mut self) -> bool {
        self.with_subchain(FilterChain::is_ssl)
    }

    /// `Curl_conn_cf_insert_after(cf, cf_new)` (`lib/cfilters.c:345-363`)
    /// applied to this filter: `filter` becomes the successor and the old
    /// successor is hung off the end of it.
    ///
    /// Emits no trace line, which is what the C does -- `Curl_conn_cf_insert_after`
    /// has no `CURL_TRC_CF` call, unlike `Curl_conn_cf_add` which logs
    /// `"added"`. The stamping walk the C spells as a `do {} while(cf_new)` loop
    /// is [`filters::FilterChain::set_chain`], which restamps every node it is
    /// handed; the old tail is attached AFTER that walk, exactly as the C's
    /// `*pnext = tail` is, so nodes that were already correctly stamped are not
    /// revisited.
    /// A filter arriving here MAY already carry its connection's identity,
    /// which is where this differs from [`filters::FilterChain::add`] and
    /// [`filters::FilterChain::insert_after`]: both of those require an
    /// unattached filter, while
    /// [`crate::conn::happy_eyeballs::HappyEyeballs::new`] stamps the identity
    /// it is handed. Since `set_chain` restamps every node below, an
    /// already-correct stamp is idempotent and a stale one is corrected, so
    /// there is nothing an attachment precondition would protect. The successor
    /// link is asserted instead, because a filter that already had one would
    /// silently strand the tail hanging below it.
    fn insert_below(&mut self, filter: FilterLink) {
        debug_assert!(
            !filter.base().has_next(),
            "a filter being spliced in must not already have a successor"
        );
        let tail = self.base.take_next();
        let mut inserted =
            FilterChain::new(self.base.conn(), self.base.sockindex());
        let displaced = inserted.set_chain(Some(filter));
        debug_assert!(displaced.is_none(), "a fresh chain has no head");
        let last = inserted.len().saturating_sub(1);
        if let Some(node) = inserted.nth_mut(last) {
            node.base_mut().set_next(tail);
        }
        self.base.set_next(inserted.take_chain());
    }
}

impl ConnFilter for SetupFilter {
    fn trace_name(&self) -> &'static str {
        CF_SETUP_FILTER_NAME
    }

    /// [`CF_SETUP_FLAGS`], which is `0`.
    ///
    /// Stated explicitly rather than left to the trait default, because the
    /// zero is a decision the C makes and a reader comparing
    /// `lib/connect.c:472` against this file should find it.
    fn cf_type(&self) -> CfType {
        CF_SETUP_FLAGS
    }

    fn base(&self) -> &FilterBase {
        &self.base
    }

    fn base_mut(&mut self) -> &mut FilterBase {
        &mut self.base
    }

    /// `cf_setup_destroy` (`lib/connect.c:462-468`): the trace line, and
    /// nothing else.
    ///
    /// C's body is `CURL_TRC_CF(data, cf, "destroy")` then
    /// `Curl_safefree(ctx)`. The free has no successor: the state is an ordinary
    /// field of this struct, so it is released when the struct is dropped, which
    /// the caller does immediately after calling this. Reaching `next` from here
    /// would be a double destruction -- the caller has already severed the link
    /// -- and the trait forbids it.
    fn destroy(&mut self, cx: &mut CallCtx<'_, '_>) {
        self.trace(cx, "destroy");
    }

    /// `cf_setup_connect` (`lib/connect.c:340-445`): build the chain beneath
    /// this filter, one stage per re-entry, and drive it.
    ///
    /// # The shape, and why it is a loop rather than five calls
    ///
    /// The C is a `goto connect_sub_chain` back to a label above the first
    /// stage. Every stage that installs something jumps back, so the newly
    /// installed subchain is DRIVEN before the next stage is considered -- a
    /// SOCKS proxy must be reachable before a `CONNECT` tunnel is stacked on it,
    /// and the tunnel must be established before TLS is negotiated through it.
    /// The state field is what stops the re-entry from repeating a stage.
    ///
    /// # The order the chain ends up in
    ///
    /// Every stage inserts immediately BELOW this filter, so the chain reads in
    /// the REVERSE of the order the stages ran:
    ///
    /// ```text
    /// SETUP -> SSL -> HAPROXY -> HTTP-PROXY -> SSL-PROXY -> SOCKS
    ///       -> HAPPY-EYEBALLS -> the winning transport
    /// ```
    ///
    /// which is what the bytes require: the topmost filter is the last
    /// transformation applied on the way out and the first on the way in, so
    /// origin TLS must sit above the tunnel that carries it, and the tunnel above
    /// the SOCKS hop that reaches the proxy. Reading the stage order as the chain
    /// order is the single easiest mistake to make in this file.
    ///
    /// Within the HTTP-proxy stage the two inserts are ordered too, and by the
    /// same rule: proxy TLS is inserted FIRST so that it ends up BELOW the
    /// tunnel, because the `CONNECT` request is what travels inside the proxy's
    /// TLS session.
    ///
    /// # Errors
    ///
    /// * [`CURLcode::FailedInit`] when no address has been resolved for this
    ///   chain -- the C's `if(!dns)`, tested afresh on every re-entry.
    /// * [`CURLcode::UnsupportedProtocol`] when the PROXY protocol is requested
    ///   on a chain that is already TLS-protected, with [`HAPROXY_AFTER_SSL`]
    ///   reported through `failf`.
    /// * Whatever a factory or a filter below reports.
    fn connect(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<bool> {
        // `if(cf->connected) { *done = TRUE; return CURLE_OK; }`
        if self.base.is_connected() {
            return Ok(true);
        }

        let sockindex = self.base.sockindex();
        let conn = self.base.conn();

        loop {
            // `connect_sub_chain:` -- `if(!dns) return CURLE_FAILED_INIT;`
            if !self.context.resolved.has_resolved(sockindex) {
                return Err(Error::with_context(
                    CURLcode::FailedInit,
                    "connect: no address resolved for this connection",
                ));
            }

            // `if(cf->next && !cf->next->connected) { ... }`
            if self.base.has_next() && !self.next_connected() {
                let done = match self.base.next_mut() {
                    Some(next) => next.connect(cx)?,
                    None => true,
                };
                if !done {
                    return Ok(false);
                }
            }

            // 1. Happy Eyeballs, always (`lib/connect.c:364-371`).
            if self.state < SetupState::CnnctEyeballs {
                let filter = self.context.factories.happy_eyeballs(
                    cx,
                    sockindex,
                    conn,
                    self.transport,
                )?;
                self.insert_below(filter);
                self.state = SetupState::CnnctEyeballs;
                if !self.next_connected() {
                    continue;
                }
            }

            // 2. SOCKS, when configured (`:375-382`). The configuration test is
            //    in the guard, so an unconfigured stage advances no state.
            if self.state < SetupState::CnnctSocks && self.context.socks_proxy {
                let filter =
                    self.context.factories.socks_proxy(cx, sockindex, conn)?;
                self.insert_below(filter);
                self.state = SetupState::CnnctSocks;
                if !self.next_connected() {
                    continue;
                }
            }

            // 3. The HTTP proxy, when configured (`:384-404`): proxy TLS first,
            //    so that it ends up beneath the tunnel.
            if self.state < SetupState::CnnctHttpProxy
                && self.context.http_proxy
            {
                if self.context.proxy_type.is_https() && !self.subchain_is_ssl()
                {
                    let filter = self
                        .context
                        .factories
                        .proxy_tls(cx, sockindex, conn)?;
                    self.insert_below(filter);
                }
                if self.context.tunnel_proxy {
                    let filter = self
                        .context
                        .factories
                        .http_proxy_tunnel(cx, sockindex, conn)?;
                    self.insert_below(filter);
                }
                self.state = SetupState::CnnctHttpProxy;
                if !self.next_connected() {
                    continue;
                }
            }

            // 4. The PROXY protocol header (`:407-423`). The state advances
            //    whether or not it was asked for.
            if self.state < SetupState::CnnctHaproxy {
                if self.context.haproxy_protocol {
                    if self.subchain_is_ssl() {
                        if let Some(tracer) = cx.tracer_mut() {
                            failf!(tracer, "{}", HAPROXY_AFTER_SSL);
                        }
                        return Err(Error::with_context(
                            CURLcode::UnsupportedProtocol,
                            HAPROXY_AFTER_SSL,
                        ));
                    }
                    let filter =
                        self.context.factories.haproxy(cx, sockindex, conn)?;
                    self.insert_below(filter);
                }
                self.state = SetupState::CnnctHaproxy;
                if !self.next_connected() {
                    continue;
                }
            }

            // 5. Origin TLS (`:425-439`). `CURL_CF_SSL_ENABLE` forces it;
            //    otherwise the scheme decides, unless `CURL_CF_SSL_DISABLE`
            //    forbids it. Already-present TLS is never doubled.
            if self.state < SetupState::CnnctSsl {
                let wanted = matches!(self.tls_mode, TlsMode::Enable)
                    || (!matches!(self.tls_mode, TlsMode::Disable)
                        && self
                            .context
                            .protocol_flags
                            .intersects(ProtocolOptions::SSL));
                if wanted && !self.subchain_is_ssl() {
                    let filter = self
                        .context
                        .factories
                        .origin_tls(cx, sockindex, conn)?;
                    self.insert_below(filter);
                }
                self.state = SetupState::CnnctSsl;
                if !self.next_connected() {
                    continue;
                }
            }

            // `ctx->state = CF_SETUP_DONE; cf->connected = TRUE; *done = TRUE;`
            self.state = SetupState::Done;
            self.base.set_connected(true);
            return Ok(true);
        }
    }

    /// `cf_setup_close` (`lib/connect.c:447-460`): DESTRUCTIVE, unlike the
    /// generic close.
    ///
    /// [`filters::ConnFilter::close`]'s contract is that filters remain
    /// installed and may be connected again, and almost every implementation
    /// honours it. This one does not, and the C is explicit about it: after
    /// closing the successor it calls `Curl_conn_cf_discard_chain(&cf->next,
    /// data)` and throws the whole subchain away.
    ///
    /// That is sound precisely because the subchain is PRIVATE to this filter --
    /// nothing else can reach it, since a chain is owned from its head -- and it
    /// is necessary because reconnecting must rebuild rather than reuse: the
    /// stages that would be skipped are chosen by the state field, which is
    /// reset to [`SetupState::Init`] here, so a retained subchain and a reset
    /// state would build a second Happy Eyeballs filter above the first.
    ///
    /// The sequence is the C's, in order: trace, clear connected, reset the
    /// state, close the successor, then discard.
    fn close(&mut self, cx: &mut CallCtx<'_, '_>) {
        self.trace(cx, "close");
        self.base.set_connected(false);
        self.state = SetupState::Init;
        if let Some(mut next) = self.base.take_next() {
            next.as_mut().get_mut().close(cx);
            discard_chain_from(cx, Some(next));
        }
    }
}

/// `cf_setup_add` (`lib/connect.c:520-536`): build a SETUP filter and install
/// it at the TOP of `chain`.
///
/// Returns nothing, where the C returns `CURLcode`: its only failure was the
/// allocation, which [`SetupFilter::new`] records as having no successor.
/// [`filters::FilterChain::add`] cannot fail either -- it takes an owned filter
/// and a chain that is by construction the right one.
#[allow(dead_code)] // consumers: the protocols, TLS and proxy modules
pub(crate) fn cf_setup_add(
    cx: &mut CallCtx<'_, '_>,
    chain: &mut FilterChain,
    context: SetupContext,
    transport: Transport,
    tls_mode: TlsMode,
) {
    let filter =
        SetupFilter::new(chain.sockindex(), context, transport, tls_mode);
    chain.add(cx, link(filter));
}

/// `Curl_cf_setup_insert_after` (`lib/connect.c:538-553`, declared at
/// `lib/connect.h:111-114`): build a SETUP filter and install it immediately
/// BELOW the filter at `index`.
///
/// # The four semantic parameters, and where they went
///
/// The C takes `(cf_at, data, transport, ssl_mode)` and all four survive:
///
/// * `cf_at`, a filter pointer naming a POSITION, becomes `at` plus `index` --
///   which is how `crate::conn::filters` spells a position, because a safe
///   chain is owned from its head and a filter cannot be named by a borrow that
///   outlives the call.
/// * `data`, the connection context, becomes `context` for the parts this file
///   reads and `cx` for the tracer and clock. The split is deliberate: `data` in
///   the C is three unrelated things behind one pointer, and only two of them
///   are needed here.
/// * `transport` and `ssl_mode` pass through unchanged as `transport` and
///   `tls_mode`.
///
/// # Its one caller in the C tree
///
/// `lib/cf-https-connect.c:161-163`, which builds a detached SETUP subchain per
/// HTTPS version being raced, with `CURL_CF_SSL_ENABLE` and a transport chosen
/// from the ALPN identifier. That is why [`TlsMode`] is a parameter rather than
/// being derived from the scheme.
///
/// # Errors
///
/// [`CURLcode::BadFunctionArgument`] when no filter is installed at `index`,
/// which is [`filters::FilterChain::insert_after`]'s answer for a position that
/// does not resolve -- the C asserts `cf_at` is non-`NULL` instead, which a
/// position cannot express.
#[allow(dead_code)] // consumers: the protocols, TLS and proxy modules
pub(crate) fn cf_setup_insert_after(
    cx: &mut CallCtx<'_, '_>,
    at: &mut FilterChain,
    index: usize,
    context: SetupContext,
    transport: Transport,
    tls_mode: TlsMode,
) -> CurlResult<()> {
    let filter = SetupFilter::new(at.sockindex(), context, transport, tls_mode);
    at.insert_after(cx, index, link(filter))
}

/// `Curl_conn_setup` (`lib/connect.c:555-593`): install a filter chain for one
/// socket index, if there is not one already.
///
/// # The two installs, and why the order matters
///
/// 1. An `https://` scheme with an EMPTY chain is offered to the HTTPS version
///    race first, through [`ConnectionFilterFactories::https_setup`]. That
///    specialiser is what installs `HTTPS-CONNECT` and races HTTP/3 against
///    HTTP/2 and HTTP/1, and it must run before the generic filter because the
///    generic filter would commit the connection to one transport.
/// 2. Whatever the specialiser did or did not install, an empty chain then gets
///    the generic [`SetupFilter`] with `conn->transport_wanted`. The C's comment
///    is *"Still no cfilter set, apply default."*, and the emptiness re-test is
///    the whole mechanism: a build with neither HTTP/3 nor HTTP/2 has no
///    versions to race, so the specialiser legitimately installs nothing.
///
/// # The resolved entry, and the failure path
///
/// The entry is stored BEFORE either install, because the SETUP filter's own
/// `if(!dns)` test reads it on the first connect pass. C releases it again on
/// every failure path with a shared `goto out`; here the release is a `take` on
/// the way out of a failed call, which is [`ResolvedEntries::release`]. The
/// displaced previous entry is released by being dropped, which is the whole of
/// `Curl_resolv_unlink`'s successor -- see [`ResolvedEntries`].
///
/// `resolved` must be the same storage the [`SetupContext`] was built to observe;
/// see [`SetupContext::new`].
///
/// # Errors
///
/// Whatever the HTTPS specialiser reports. The generic install cannot fail.
#[allow(dead_code)] // consumers: the protocols, TLS and proxy modules
pub(crate) fn conn_setup(
    cx: &mut CallCtx<'_, '_>,
    chain: &mut FilterChain,
    resolved: &SharedResolvedEntries,
    dns: DnsEntryRef,
    scheme: SchemeSetup,
    context: SetupContext,
    tls_mode: TlsMode,
) -> CurlResult<()> {
    let sockindex = chain.sockindex();

    // `Curl_resolv_unlink(data, &data->state.dns[sockindex]);`
    // `data->state.dns[sockindex] = dns;`
    resolved.with_mut(|entries| drop(entries.replace(sockindex, dns)));

    let outcome = conn_setup_chain(cx, chain, scheme, context, tls_mode);
    if outcome.is_err() {
        // `out: if(result) Curl_resolv_unlink(data,
        //                                    &data->state.dns[sockindex]);`
        resolved.with_mut(|entries| drop(entries.release(sockindex)));
    }
    outcome
}

/// The two installs of [`conn_setup`], separated so that the resolved entry is
/// released on exactly one path and the reader can see which.
#[allow(dead_code)] // consumers: the protocols, TLS and proxy modules
fn conn_setup_chain(
    cx: &mut CallCtx<'_, '_>,
    chain: &mut FilterChain,
    scheme: SchemeSetup,
    context: SetupContext,
    tls_mode: TlsMode,
) -> CurlResult<()> {
    // `if(!conn->cfilter[sockindex] &&
    //     conn->scheme->protocol == CURLPROTO_HTTPS) {`
    if chain.is_empty() && scheme.is_https {
        // `DEBUGASSERT(ssl_mode != CURL_CF_SSL_DISABLE);`
        debug_assert!(
            !matches!(tls_mode, TlsMode::Disable),
            "an https:// scheme cannot be set up with TLS disabled"
        );
        context.factories.https_setup(cx, chain)?;
    }

    // `/* Still no cfilter set, apply default. */`
    if chain.is_empty() {
        cf_setup_add(cx, chain, context, scheme.transport_wanted, tls_mode);
    }

    // `DEBUGASSERT(conn->cfilter[sockindex]);`
    debug_assert!(chain.is_setup(), "a chain is installed by now");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::filters::{
        chain_close, CfQuery, CfQueryValue, CF_TYPE_HTTP, CF_TYPE_IP_CONNECT,
        CF_TYPE_MULTIPLEX, CF_TYPE_PROXY, CF_TYPE_SSL, CURL_CF_SSL_DEFAULT,
        CURL_CF_SSL_DISABLE, CURL_CF_SSL_ENABLE,
    };
    use crate::conn::pool::ConnectionSpec;
    use crate::conn::select::CURL_SOCKET_BAD;
    use crate::conn::shutdown::EXPIRE_SHUTDOWN;
    use crate::dns::{
        DnsEntry, IpVersion, ResolveFuture, ResolvedAddr, Resolver,
    };
    use crate::trace::{
        TraceConfig, TraceFilter, TraceLevel, Tracer, WriterSink,
    };
    use crate::util::sync_cell::SyncCell;
    use crate::util::timeval::TestClock;
    use socket2::SockAddr;
    use std::net::SocketAddr;
    use std::time::Duration;

    // -- shared plumbing ---------------------------------------------------

    /// An ordered record of what happened, shared by every double in a test.
    ///
    /// A filter installed below another is owned as
    /// `Pin<Box<dyn ConnFilter>>` and there is no way back to its concrete
    /// type -- deliberately, because recovering one is what the filter
    /// translation exists to abolish. A shared log is therefore the only way a
    /// test can observe what a linked filter did.
    type EventLog = Arc<SyncCell<Vec<String>>>;

    fn new_log() -> EventLog {
        Arc::new(SyncCell::new(Vec::new()))
    }

    fn events(log: &EventLog) -> Vec<String> {
        log.borrow().clone()
    }

    /// A clock at a round, non-zero reading.
    ///
    /// Non-zero on purpose: a zero monotonic reading is what C's "shutdown not
    /// started" test keys off, and a test whose clock reads zero would agree
    /// with a broken implementation by accident.
    fn clock() -> TestClock {
        TestClock::new(CurlTime::new(1_000, 0))
    }

    /// A shared clock handle, for the types that own one.
    fn shared_clock(at: CurlTime) -> Arc<TestClock> {
        Arc::new(TestClock::new(at))
    }

    fn timers_at(clock: &Arc<TestClock>) -> ShutdownTimers {
        ShutdownTimers::new(Arc::clone(clock) as Arc<dyn Clock + Send + Sync>)
    }

    /// A resolved entry, which these tests only ever test the PRESENCE of.
    fn dns_entry() -> DnsEntryRef {
        Arc::new(DnsEntry {
            addrs: Vec::new(),
            timestamp: CurlTime::ZERO,
            hostport: 443,
            hostname: "example.com".to_owned(),
            hinfo: None,
        })
    }

    /// A [`Resolver`] that is never called, for the seams bundle.
    #[derive(Debug)]
    struct UnusedResolver;

    impl Resolver for UnusedResolver {
        fn resolve<'a>(
            &'a self,
            host: &'a str,
            port: u16,
            ip_version: IpVersion,
        ) -> ResolveFuture<'a, Vec<ResolvedAddr>> {
            let _ = (host, port, ip_version);
            Box::pin(async { Err(CURLcode::CouldntResolveHost) })
        }
    }

    /// Records every `Curl_expire_ex` and `Curl_expire_done`.
    #[derive(Debug, Default)]
    struct TestExpiry {
        armed: SyncCell<Vec<(TimeDiff, TimerId)>>,
        cleared: SyncCell<Vec<TimerId>>,
    }

    impl ExpireScheduler for TestExpiry {
        fn expire(&self, timeout_ms: TimeDiff, timer: TimerId) {
            self.armed.borrow_mut().push((timeout_ms, timer));
        }

        fn expire_done(&self, timer: TimerId) {
            self.cleared.borrow_mut().push(timer);
        }
    }

    /// Records every `CURL_TRC_M` line.
    #[derive(Debug, Default)]
    struct Recorder {
        notes: Vec<String>,
    }

    impl ConnDiagnostics for Recorder {
        fn multi_note(&mut self, message: &str) {
            self.notes.push(message.to_owned());
        }
    }

    /// Counts `Curl_multi_connchanged`.
    #[derive(Debug, Default)]
    struct TestMulti {
        changed: usize,
    }

    impl MultiOwnerNotify for TestMulti {
        fn connchanged(&mut self) {
            self.changed += 1;
        }
    }

    /// A [`ResolvedPresence`] with a fixed answer per chain.
    #[derive(Debug)]
    struct FixedPresence([bool; SocketIndex::COUNT]);

    impl FixedPresence {
        fn all(present: bool) -> Arc<Self> {
            Arc::new(Self([present; SocketIndex::COUNT]))
        }
    }

    impl ResolvedPresence for FixedPresence {
        fn has_resolved(&self, sockindex: SocketIndex) -> bool {
            self.0[sockindex.as_usize()]
        }
    }

    // -- the marker filter -------------------------------------------------

    /// A filter that only records that it was reached.
    ///
    /// It carries the NAME and FLAGS of the real filter it stands in for, taken
    /// from that filter's own `struct Curl_cftype`, because the capability
    /// searches the setup machine performs read the flags and nothing else.
    #[derive(Debug)]
    struct Marker {
        base: FilterBase,
        name: &'static str,
        flags: CfType,
        /// Connect passes still to be refused before reporting connected.
        steps: usize,
        /// What `CF_QUERY_SOCKET` answers, when anything.
        socket: Option<Socket>,
        log: EventLog,
    }

    impl Marker {
        fn new(
            name: &'static str,
            flags: CfType,
            steps: usize,
            log: &EventLog,
        ) -> Self {
            Self {
                base: FilterBase::new(SocketIndex::First),
                name,
                flags,
                steps,
                socket: None,
                log: Arc::clone(log),
            }
        }

        fn with_socket(mut self, socket: Socket) -> Self {
            self.socket = Some(socket);
            self
        }

        fn note(&self, what: &str) {
            self.log.borrow_mut().push(format!("{}:{what}", self.name));
        }
    }

    impl ConnFilter for Marker {
        fn trace_name(&self) -> &'static str {
            self.name
        }

        fn cf_type(&self) -> CfType {
            self.flags
        }

        fn base(&self) -> &FilterBase {
            &self.base
        }

        fn base_mut(&mut self) -> &mut FilterBase {
            &mut self.base
        }

        fn connect(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<bool> {
            self.note("connect");
            if let Some(next) = self.base.next_mut() {
                if !next.base().is_connected() && !next.connect(cx)? {
                    return Ok(false);
                }
            }
            if self.steps > 0 {
                self.steps -= 1;
                return Ok(false);
            }
            self.base.set_connected(true);
            Ok(true)
        }

        fn close(&mut self, cx: &mut CallCtx<'_, '_>) {
            self.note("close");
            chain_close(self, cx);
        }

        fn destroy(&mut self, cx: &mut CallCtx<'_, '_>) {
            let _ = cx;
            self.note("destroy");
        }

        fn query(
            &mut self,
            cx: &mut CallCtx<'_, '_>,
            query: CfQuery,
        ) -> CurlResult<CfQueryValue> {
            if matches!(query, CfQuery::Socket) {
                if let Some(socket) = self.socket {
                    return Ok(CfQueryValue::Socket(socket));
                }
            }
            match self.base_mut().next_mut() {
                Some(next) => next.query(cx, query),
                None => Err(Error::new(CURLcode::UnknownOption)),
            }
        }
    }

    // -- the factory double ------------------------------------------------

    /// The name and flags each stage's real filter declares, so that a test
    /// double behaves like it in every search the setup machine performs.
    fn flags_of(name: &str) -> CfType {
        match name {
            // `lib/cf-ip-happy.c:903-905` -- zero, notably.
            "HAPPY-EYEBALLS" => CfType::NONE,
            // `lib/socks.c:1384-1386`
            "SOCKS" => CF_TYPE_IP_CONNECT.union(CF_TYPE_PROXY),
            // `lib/vtls/vtls.c:1687-1689`
            "SSL-PROXY" => CF_TYPE_SSL.union(CF_TYPE_PROXY),
            // `lib/http_proxy.c:395-397`
            "HTTP-PROXY" => CF_TYPE_IP_CONNECT.union(CF_TYPE_PROXY),
            // `lib/cf-haproxy.c:186-188`
            "HAPROXY" => CF_TYPE_PROXY,
            // `lib/vtls/vtls.c:1667-1669`
            "SSL" => CF_TYPE_SSL,
            // `lib/cf-socket.c:1682-1684`
            _ => CF_TYPE_IP_CONNECT,
        }
    }

    /// Builds a [`Marker`] per stage, and can be told to fail one of them.
    #[derive(Debug)]
    struct TestFactories {
        log: EventLog,
        /// Connect passes each produced filter refuses before connecting.
        steps: usize,
        /// A stage name that must fail, and the code it fails with.
        fail: Option<(&'static str, CURLcode)>,
        /// What `https_setup` installs, top first. Empty installs nothing.
        https_chain: Vec<&'static str>,
    }

    impl TestFactories {
        fn new(log: &EventLog) -> Self {
            Self {
                log: Arc::clone(log),
                steps: 0,
                fail: None,
                https_chain: Vec::new(),
            }
        }

        fn with_steps(mut self, steps: usize) -> Self {
            self.steps = steps;
            self
        }

        fn failing(mut self, stage: &'static str, code: CURLcode) -> Self {
            self.fail = Some((stage, code));
            self
        }

        fn with_https_chain(mut self, names: &[&'static str]) -> Self {
            self.https_chain = names.to_vec();
            self
        }

        fn build(
            &self,
            name: &'static str,
            sockindex: SocketIndex,
            conn: Option<ConnId>,
        ) -> CurlResult<FilterLink> {
            self.log.borrow_mut().push(format!("build:{name}"));
            if let Some((stage, code)) = self.fail {
                if stage == name {
                    return Err(Error::new(code));
                }
            }
            let mut marker =
                Marker::new(name, flags_of(name), self.steps, &self.log);
            marker.base.set_sockindex(sockindex);
            marker.base.set_conn(conn);
            Ok(link(marker))
        }
    }

    impl ConnectionFilterFactories for TestFactories {
        fn happy_eyeballs(
            &self,
            cx: &mut CallCtx<'_, '_>,
            sockindex: SocketIndex,
            conn: Option<ConnId>,
            transport: Transport,
        ) -> CurlResult<FilterLink> {
            let _ = cx;
            self.log
                .borrow_mut()
                .push(format!("transport:{}", transport.as_u8()));
            self.build("HAPPY-EYEBALLS", sockindex, conn)
        }

        fn socks_proxy(
            &self,
            cx: &mut CallCtx<'_, '_>,
            sockindex: SocketIndex,
            conn: Option<ConnId>,
        ) -> CurlResult<FilterLink> {
            let _ = cx;
            self.build("SOCKS", sockindex, conn)
        }

        fn proxy_tls(
            &self,
            cx: &mut CallCtx<'_, '_>,
            sockindex: SocketIndex,
            conn: Option<ConnId>,
        ) -> CurlResult<FilterLink> {
            let _ = cx;
            self.build("SSL-PROXY", sockindex, conn)
        }

        fn http_proxy_tunnel(
            &self,
            cx: &mut CallCtx<'_, '_>,
            sockindex: SocketIndex,
            conn: Option<ConnId>,
        ) -> CurlResult<FilterLink> {
            let _ = cx;
            self.build("HTTP-PROXY", sockindex, conn)
        }

        fn haproxy(
            &self,
            cx: &mut CallCtx<'_, '_>,
            sockindex: SocketIndex,
            conn: Option<ConnId>,
        ) -> CurlResult<FilterLink> {
            let _ = cx;
            self.build("HAPROXY", sockindex, conn)
        }

        fn origin_tls(
            &self,
            cx: &mut CallCtx<'_, '_>,
            sockindex: SocketIndex,
            conn: Option<ConnId>,
        ) -> CurlResult<FilterLink> {
            let _ = cx;
            self.build("SSL", sockindex, conn)
        }

        fn https_setup(
            &self,
            cx: &mut CallCtx<'_, '_>,
            chain: &mut FilterChain,
        ) -> CurlResult<()> {
            self.log.borrow_mut().push("build:HTTPS-SETUP".to_owned());
            if let Some((stage, code)) = self.fail {
                if stage == "HTTPS-SETUP" {
                    return Err(Error::new(code));
                }
            }
            for name in self.https_chain.iter().rev() {
                let marker =
                    Marker::new(name, flags_of(name), self.steps, &self.log);
                chain.add(cx, link(marker));
            }
            Ok(())
        }
    }

    /// A [`SetupContext`] over `factories`, with every address resolved.
    fn context(factories: &Arc<TestFactories>) -> SetupContext {
        SetupContext::new(
            Arc::clone(factories) as Arc<dyn ConnectionFilterFactories>,
            FixedPresence::all(true) as Arc<dyn ResolvedPresence>,
        )
    }

    /// The chain from `filter` downwards, top first, SETUP included.
    fn chain_names(filter: &SetupFilter) -> Vec<&'static str> {
        let mut names = vec![filter.trace_name()];
        let mut cursor = filter.base().next_ref();
        while let Some(node) = cursor {
            names.push(node.trace_name());
            cursor = node.base().next_ref();
        }
        names
    }

    /// The names installed in `chain`, top first.
    fn installed(chain: &FilterChain) -> Vec<&'static str> {
        chain.iter().map(ConnFilter::trace_name).collect()
    }

    /// Collects a verbose trace of `body` with every filter level raised.
    fn traced(body: impl FnOnce(&mut CallCtx<'_, '_>)) -> String {
        let clock = clock();
        let mut config = TraceConfig::new();
        for filter in TraceFilter::ALL {
            config.set_filter_level(*filter, TraceLevel::Info);
        }
        let mut sink = WriterSink::new(Vec::new());
        {
            let mut tracer = Tracer::new(&config, &mut sink);
            tracer.set_verbose(true);
            let mut cx = CallCtx::new(&clock).with_tracer(&mut tracer);
            body(&mut cx);
        }
        String::from_utf8(sink.into_inner()).expect("trace output is text")
    }

    // -- 1. the module's exports ------------------------------------------

    /// Required test 1 -- every export this file owes its dependents is
    /// nameable, constructible and of the documented type.
    ///
    /// Its value is not the assertions but the SIGNATURES: the test would stop
    /// compiling if an item were renamed, if a re-export were dropped, or if a
    /// parameter list changed, which is the whole of what a dependent relies on.
    #[test]
    fn every_export_of_this_module_is_reachable_and_typed() {
        let log = new_log();
        let factories = Arc::new(TestFactories::new(&log));
        let handle = shared_clock(CurlTime::new(5, 0));

        // The two budgets.
        let _: TimeDiff = DEFAULT_CONNECT_TIMEOUT;
        let _: TimeDiff = DEFAULT_SHUTDOWN_TIMEOUT_MS;
        let _: usize = MAX_IPADR_LEN;
        let _: i32 = FIRSTSOCKET;
        let _: i32 = SECONDARYSOCKET;

        // The checked domains.
        let _: SocketIndex = SocketIndex::First;
        let _: Transport = Transport::Tcp;
        let _: TlsMode = TlsMode::Default;
        let _: ProtocolOptions = ProtocolOptions::SSL;
        let _: ConnControl = ConnControl::Keep;
        let _: ProxyType = ProxyType::Https;
        let _: SetupState = SetupState::Init;
        let _: TransferRole = TransferRole::Registered;

        // The owned state.
        let mut state = ConnectionState::new();
        assert!(!state.wants_close());
        assert!(!state.is_multiplex());
        assert!(state.close_reason().is_none());
        let mut deadline = DeadlineState::new();
        deadline.set_connect_only(false);
        let mut timers = timers_at(&handle);
        let entries = ResolvedEntries::new();
        assert!(entries.get(SocketIndex::First).is_none());
        let shared = SharedResolvedEntries::new();
        assert!(!shared.has_resolved(SocketIndex::First));

        // The free functions.
        assert_eq!(alpn2alpnid(b"h2"), AlpnId::H2);
        assert_eq!(str2alpnid("h3"), AlpnId::H3);
        assert_eq!(timeleft_now_ms(&deadline, &timers, handle.now()), 0);
        assert_eq!(timeleft_ms(&deadline, &timers, handle.as_ref()), 0);
        assert!(!shutdown_started(&timers, SocketIndex::First));
        assert_eq!(shutdown_timeleft(&timers, SocketIndex::First), 0);
        assert_eq!(conn_shutdown_timeleft(&timers), 0);
        shutdown_clear(&mut timers, SocketIndex::First);
        assert!(conn_set_multiplex(&mut state, None), "the first transition");
        assert!(state.is_multiplex());
        let chains = FilterChains::new(Some(ConnId::new(1)));
        conncontrol(&mut state, &chains, ConnControl::Connection, "test");
        assert!(state.wants_close());

        // The injected seams and the value that bundles them.
        let seams = ConnSeams::new(
            Arc::new(UnusedResolver),
            Arc::clone(&handle) as Arc<dyn Clock + Send + Sync>,
            Arc::new(TestExpiry::default()),
            Arc::clone(&factories) as Arc<dyn ConnectionFilterFactories>,
        );
        assert_eq!(seams.clock().now(), handle.now());
        assert!(!seams.shutdown_timers().started(SocketIndex::First));
        seams.expiry().expire(7, TimerId::Shutdown);
        let _ = seams.factories();
        let _ = seams.resolver();

        // The deadline adapter, through the trait its consumers hold it by.
        let shared_deadline: Arc<dyn Deadline> = Arc::new(
            TransferDeadline::new(DeadlineState::new(), timers_at(&handle)),
        );
        assert_eq!(shared_deadline.time_left_ms(), 0);

        // The filter, its context and the three entry points.
        let scheme = SchemeSetup {
            is_https: false,
            transport_wanted: Transport::Tcp,
        };
        assert_eq!(scheme.transport_wanted, Transport::Tcp);
        let filter = SetupFilter::new(
            SocketIndex::First,
            context(&factories),
            Transport::Tcp,
            TlsMode::Default,
        );
        assert_eq!(filter.state(), SetupState::Init);
        assert_eq!(filter.tls_mode(), TlsMode::Default);
        assert_eq!(filter.transport(), Transport::Tcp);
        assert_eq!(filter.trace_name(), CF_SETUP_FILTER_NAME);
        assert_eq!(filter.cf_type(), CF_SETUP_FLAGS);
        assert_eq!(CF_SETUP_LOG_LEVEL, CURL_LOG_LVL_NONE);
        assert!(HAPROXY_AFTER_SSL.starts_with("haproxy protocol"));
        assert_eq!(SHUTDOWN_START_PRIMARY, "shutdown start on connection");
        assert_eq!(
            SHUTDOWN_START_SECONDARY,
            "shutdown start on secondary connection"
        );
    }

    // -- 2. the `PROTOPT_*` bitmap ----------------------------------------

    /// Required test 2 -- every `PROTOPT_*` bit holds the C's value, the
    /// reserved hole included.
    ///
    /// Transcribed from `lib/urldata.h:526-558` as SHIFTS rather than as decimal
    /// numbers, because that is how the C writes them and a transcription error
    /// in a shift is visible where one in `65536` is not.
    #[test]
    fn every_protocol_option_holds_the_c_bit_value() {
        assert_eq!(ProtocolOptions::NONE.bits(), 0);
        assert!(ProtocolOptions::NONE.is_empty());

        let expected: [(ProtocolOptions, u32, &str); 17] = [
            (ProtocolOptions::SSL, 1 << 0, "PROTOPT_SSL"),
            (ProtocolOptions::DUAL, 1 << 1, "PROTOPT_DUAL"),
            (ProtocolOptions::CLOSEACTION, 1 << 2, "PROTOPT_CLOSEACTION"),
            (ProtocolOptions::DIRLOCK, 1 << 3, "PROTOPT_DIRLOCK"),
            (ProtocolOptions::NONETWORK, 1 << 4, "PROTOPT_NONETWORK"),
            (ProtocolOptions::NEEDSPWD, 1 << 5, "PROTOPT_NEEDSPWD"),
            (ProtocolOptions::NOURLQUERY, 1 << 6, "PROTOPT_NOURLQUERY"),
            (
                ProtocolOptions::CREDSPERREQUEST,
                1 << 7,
                "PROTOPT_CREDSPERREQUEST",
            ),
            (ProtocolOptions::ALPN, 1 << 8, "PROTOPT_ALPN"),
            (ProtocolOptions::RESERVED_BIT_9, 1 << 9, "was STREAM"),
            (ProtocolOptions::URLOPTIONS, 1 << 10, "PROTOPT_URLOPTIONS"),
            (
                ProtocolOptions::PROXY_AS_HTTP,
                1 << 11,
                "PROTOPT_PROXY_AS_HTTP",
            ),
            (ProtocolOptions::WILDCARD, 1 << 12, "PROTOPT_WILDCARD"),
            (ProtocolOptions::USERPWDCTRL, 1 << 13, "PROTOPT_USERPWDCTRL"),
            (ProtocolOptions::NOTCPPROXY, 1 << 14, "PROTOPT_NOTCPPROXY"),
            (ProtocolOptions::SSL_REUSE, 1 << 15, "PROTOPT_SSL_REUSE"),
            (ProtocolOptions::CONN_REUSE, 1 << 16, "PROTOPT_CONN_REUSE"),
        ];

        for (option, bits, name) in expected {
            assert_eq!(option.bits(), bits, "{name} moved");
        }
        assert_eq!(
            ProtocolOptions::ALL.len(),
            expected.len(),
            "ALL must carry every bit, the reserved one included"
        );
        for (index, (option, _, name)) in expected.iter().enumerate() {
            assert_eq!(
                ProtocolOptions::ALL[index],
                *option,
                "ALL is out of bit order at {name}"
            );
        }

        // The reserved bit is a hole, not a capability: nothing may be built
        // that sets it, and the next capability must take `1 << 17`.
        assert_eq!(ProtocolOptions::RESERVED_BIT_9.bits(), 512);
        assert_eq!(
            ProtocolOptions::CONN_REUSE.bits() << 1,
            1 << 17,
            "the next bit is 1 << 17"
        );

        // Set algebra.
        let both = ProtocolOptions::SSL | ProtocolOptions::ALPN;
        assert!(both.intersects(ProtocolOptions::SSL));
        assert!(both.contains(ProtocolOptions::ALPN));
        assert!(!both.contains(ProtocolOptions::DUAL));
        assert!(!both.is_empty());
        assert_eq!(both, ProtocolOptions::SSL.union(ProtocolOptions::ALPN));
        assert_eq!(ProtocolOptions::from_bits(both.bits()), both);
        // Total, as the C's storage is: an unknown bit survives a round trip.
        assert_eq!(ProtocolOptions::from_bits(1 << 20).bits(), 1 << 20);

        // Readable rendering, stray bits included.
        assert_eq!(
            format!("{:?}", ProtocolOptions::NONE),
            "ProtocolOptions(NONE)"
        );
        assert_eq!(format!("{both:?}"), "ProtocolOptions(SSL|ALPN)");
        assert_eq!(
            format!("{:?}", ProtocolOptions::from_bits(1 << 20)),
            "ProtocolOptions(0x100000)"
        );
    }

    /// Required test 2, second half -- there is ONE numeric domain, not three.
    ///
    /// `crate::conn::socket` and `crate::conn::pool` each declare the handful of
    /// `PROTOPT_*` bits they read as bare `u32` constants. This asserts they
    /// agree with the typed set here, so that the three cannot drift apart --
    /// which is what "do not create conflicting duplicate numeric domains"
    /// requires, without editing either module.
    #[test]
    fn the_protocol_option_bits_agree_across_the_directory() {
        use crate::conn::pool;
        use crate::conn::socket;

        assert_eq!(ProtocolOptions::SSL.bits(), socket::PROTOPT_SSL);
        assert_eq!(ProtocolOptions::DUAL.bits(), socket::PROTOPT_DUAL);
        assert_eq!(ProtocolOptions::ALPN.bits(), socket::PROTOPT_ALPN);
        assert_eq!(
            ProtocolOptions::RESERVED_BIT_9.bits(),
            socket::PROTOPT_FREE_BIT_9
        );
        assert_eq!(
            ProtocolOptions::NOTCPPROXY.bits(),
            socket::PROTOPT_NOTCPPROXY
        );
        assert_eq!(
            ProtocolOptions::SSL_REUSE.bits(),
            socket::PROTOPT_SSL_REUSE
        );
        assert_eq!(
            ProtocolOptions::CONN_REUSE.bits(),
            socket::PROTOPT_CONN_REUSE
        );
        assert_eq!(ProtocolOptions::SSL_REUSE.bits(), pool::PROTOPT_SSL_REUSE);
        assert_eq!(
            ProtocolOptions::CONN_REUSE.bits(),
            pool::PROTOPT_CONN_REUSE
        );
    }

    // -- 3. the re-exported domains ---------------------------------------

    /// Required test 3 -- the re-exports carry the C's integers unchanged.
    #[test]
    fn the_re_exported_domains_keep_their_c_values() {
        assert_eq!(FIRSTSOCKET, 0);
        assert_eq!(SECONDARYSOCKET, 1);
        assert_eq!(SocketIndex::First.as_i32(), 0);
        assert_eq!(SocketIndex::Secondary.as_i32(), 1);
        assert_eq!(SocketIndex::COUNT, 2);
        assert_eq!(SocketIndex::ALL.len(), 2);
        assert_eq!(
            SocketIndex::from_i32(2),
            Err(CURLcode::BadFunctionArgument)
        );

        assert_eq!(Transport::None.as_u8(), 0);
        assert_eq!(Transport::Tcp.as_u8(), 3);
        assert_eq!(Transport::Udp.as_u8(), 4);
        assert_eq!(Transport::Quic.as_u8(), 5);
        assert_eq!(Transport::Unix.as_u8(), 6);
        // 1 and 2 were retired and must stay unrepresentable.
        assert_eq!(Transport::from_u8(1), None);
        assert_eq!(Transport::from_u8(2), None);

        assert_eq!(TlsMode::Default.as_i32(), CURL_CF_SSL_DEFAULT);
        assert_eq!(TlsMode::Default.as_i32(), -1);
        assert_eq!(TlsMode::Disable.as_i32(), CURL_CF_SSL_DISABLE);
        assert_eq!(TlsMode::Disable.as_i32(), 0);
        assert_eq!(TlsMode::Enable.as_i32(), CURL_CF_SSL_ENABLE);
        assert_eq!(TlsMode::Enable.as_i32(), 1);

        assert_eq!(MAX_IPADR_LEN, 46);
        assert_eq!(
            MAX_IPADR_LEN,
            "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255".len() + 1,
            "the C's sizeof() counts the terminator"
        );

        assert_eq!(DEFAULT_CONNECT_TIMEOUT, 300000);
        assert_eq!(DEFAULT_SHUTDOWN_TIMEOUT_MS, 2000);

        // The connection controls, and the refusal of anything else.
        assert_eq!(CONNCTRL_KEEP, 0);
        assert_eq!(CONNCTRL_CONNECTION, 1);
        assert_eq!(CONNCTRL_STREAM, 2);
        assert_eq!(ConnControl::Keep.as_i32(), 0);
        assert_eq!(ConnControl::Connection.as_i32(), 1);
        assert_eq!(ConnControl::Stream.as_i32(), 2);
        for control in ConnControl::ALL {
            assert_eq!(ConnControl::from_i32(control.as_i32()), Ok(control));
        }
        for stray in [-1, 3, 7, i32::MAX] {
            assert_eq!(
                ConnControl::from_i32(stray),
                Err(CURLcode::BadFunctionArgument),
                "{stray} must not fall through to KEEP"
            );
        }

        // The proxy types, and `IS_HTTPS_PROXY`'s exactly two members.
        for (index, kind) in ProxyType::ALL.iter().enumerate() {
            assert_eq!(kind.as_i32(), index as i32);
            assert_eq!(ProxyType::from_i32(kind.as_i32()), Ok(*kind));
        }
        assert_eq!(ProxyType::from_i32(8), Err(CURLcode::BadFunctionArgument));
        for kind in ProxyType::ALL {
            let expected = matches!(kind, ProxyType::Https | ProxyType::Https2);
            assert_eq!(kind.is_https(), expected, "{kind:?}");
        }
        assert!(!ProxyType::Http10.is_https(), "1.0 is a version, not TLS");

        // The seven setup states, in order and by ordinal.
        for (index, state) in SetupState::ALL.iter().enumerate() {
            assert_eq!(state.as_i32(), index as i32);
        }
        assert!(SetupState::Init < SetupState::CnnctEyeballs);
        assert!(SetupState::CnnctEyeballs < SetupState::CnnctSocks);
        assert!(SetupState::CnnctSocks < SetupState::CnnctHttpProxy);
        assert!(SetupState::CnnctHttpProxy < SetupState::CnnctHaproxy);
        assert!(SetupState::CnnctHaproxy < SetupState::CnnctSsl);
        assert!(SetupState::CnnctSsl < SetupState::Done);
        assert_eq!(SetupState::default(), SetupState::Init);
    }

    // -- 4, 5, 6. ALPN identifiers ----------------------------------------

    /// Required tests 4 and 5 -- the four names the C accepts, and nothing else
    /// of those lengths.
    #[test]
    fn the_alpn_names_the_c_accepts_map_to_its_identifiers() {
        assert_eq!(alpn2alpnid(b"h1"), AlpnId::H1);
        assert_eq!(alpn2alpnid(b"h2"), AlpnId::H2);
        assert_eq!(alpn2alpnid(b"h3"), AlpnId::H3);
        assert_eq!(alpn2alpnid(b"http/1.1"), AlpnId::H1);

        // The pinned integers, which are `CURLALTSVC_H1/_H2/_H3` and not
        // ordinals -- the delegation is what keeps them so.
        assert_eq!(AlpnId::H1.as_u8(), 8);
        assert_eq!(AlpnId::H2.as_u8(), 16);
        assert_eq!(AlpnId::H3.as_u8(), 32);
        assert_eq!(AlpnId::None.as_u8(), 0);

        // `str2` is the same decision reached through text.
        assert_eq!(str2alpnid("h1"), AlpnId::H1);
        assert_eq!(str2alpnid("h2"), AlpnId::H2);
        assert_eq!(str2alpnid("h3"), AlpnId::H3);
        assert_eq!(str2alpnid("http/1.1"), AlpnId::H1);
    }

    /// Required test 6 -- length, case and near-misses are all refused.
    #[test]
    fn every_alpn_near_miss_is_unknown() {
        let refused: [&[u8]; 18] = [
            b"",
            b"h",
            b"h4",
            b"h0",
            b"h2c", // the HTTP/2-over-cleartext token: three bytes
            b"H1",  // no case folding
            b"H2",
            b"H3",
            b"HTTP/1.1",
            b"Http/1.1",
            b"http/1.0", // eight bytes, wrong content
            b"http/2.0",
            b"http/1.1 ", // nine bytes: not trimmed
            b" http/1.1",
            b"h2 ",
            b"\0h2",
            b"h1h2",
            b"spdy/3.1", // eight bytes, a real ALPN name curl does not map
        ];
        for name in refused {
            assert_eq!(
                alpn2alpnid(name),
                AlpnId::None,
                "{:?} must be unknown",
                String::from_utf8_lossy(name)
            );
        }
        for text in ["", "H2", "h2c", "http/1.0", "http/1.1 "] {
            assert_eq!(str2alpnid(text), AlpnId::None, "{text:?}");
        }
    }

    /// Required test 4, structural half -- the lookup table is NOT duplicated
    /// here.
    ///
    /// The needles are assembled at run time so that this test's own source
    /// does not satisfy the search it performs.
    #[test]
    fn the_alpn_lookup_is_delegated_rather_than_copied() {
        let here = include_str!("mod.rs");
        assert!(
            here.contains(&format!("AlpnId::{}(name)", "from_wire")),
            "alpn2alpnid must delegate to the canonical constructor"
        );
        for token in ["h1\"", "h2\"", "h3\"", "http/1.1\""] {
            let needle = format!("b\"{token}");
            assert!(
                !here
                    .split("#[cfg(test)]")
                    .next()
                    .unwrap_or("")
                    .contains(&needle),
                "the production half must not carry a literal {needle}"
            );
        }
    }

    // -- 7 to 12. the transfer deadline -----------------------------------

    /// A deadline that is connecting, with the single connect having started at
    /// the clock's own zero point.
    fn connecting_at(started: CurlTime) -> DeadlineState {
        let mut deadline = DeadlineState::new();
        deadline.set_connecting(true);
        deadline.set_started_single_at(started);
        deadline
    }

    /// Required test 7 -- while connecting with no `CURLOPT_CONNECTTIMEOUT`,
    /// the budget is [`DEFAULT_CONNECT_TIMEOUT`].
    #[test]
    fn a_connecting_transfer_gets_the_default_five_minute_budget() {
        let handle = shared_clock(CurlTime::new(1_000, 0));
        let timers = timers_at(&handle);
        let deadline = connecting_at(CurlTime::new(1_000, 0));

        assert_eq!(
            timeleft_now_ms(&deadline, &timers, handle.now()),
            300000,
            "nothing has elapsed, so the whole default remains"
        );

        handle.advance(Duration::from_millis(1_500));
        assert_eq!(
            timeleft_ms(&deadline, &timers, handle.as_ref()),
            300000 - 1_500
        );

        // And it expires, rather than wrapping or saturating.
        handle.advance(Duration::from_millis(400_000));
        assert!(timeleft_ms(&deadline, &timers, handle.as_ref()) < 0);
    }

    /// Required test 8 -- a configured `CURLOPT_CONNECTTIMEOUT` replaces the
    /// default, and only a POSITIVE one does.
    #[test]
    fn a_configured_connect_timeout_replaces_the_default() {
        let handle = shared_clock(CurlTime::new(2_000, 0));
        let timers = timers_at(&handle);
        let mut deadline = connecting_at(CurlTime::new(2_000, 0));
        deadline.set_connect_timeout_ms(5_000);
        assert_eq!(deadline.connect_timeout_ms(), 5_000);

        assert_eq!(timeleft_now_ms(&deadline, &timers, handle.now()), 5_000);
        handle.advance(Duration::from_millis(4_000));
        assert_eq!(timeleft_now_ms(&deadline, &timers, handle.now()), 1_000);

        // `(data->set.connecttimeout > 0)` is strict, so zero and a negative
        // value both fall back to the default rather than expiring at once.
        for configured in [0, -1, -5_000] {
            let mut fallback = connecting_at(handle.now());
            fallback.set_connect_timeout_ms(configured);
            assert_eq!(
                timeleft_now_ms(&fallback, &timers, handle.now()),
                300000,
                "{configured} must fall back to the default"
            );
        }
    }

    /// Required test 9 -- the overall `CURLOPT_TIMEOUT` when not connecting.
    #[test]
    fn the_overall_timeout_applies_once_connecting_is_over() {
        let handle = shared_clock(CurlTime::new(10, 0));
        let timers = timers_at(&handle);
        let mut deadline = DeadlineState::new();
        deadline.set_operation_timeout_ms(30_000);
        deadline.set_started_op_at(CurlTime::new(10, 0));
        assert_eq!(deadline.operation_timeout_ms(), 30_000);
        assert!(!deadline.connecting());

        assert_eq!(timeleft_now_ms(&deadline, &timers, handle.now()), 30_000);
        handle.advance(Duration::from_millis(29_999));
        assert_eq!(timeleft_now_ms(&deadline, &timers, handle.now()), 1);
        handle.advance(Duration::from_millis(2));
        assert_eq!(timeleft_now_ms(&deadline, &timers, handle.now()), -1);
    }

    /// Required test 10 -- with both budgets live, the SMALLER is reported.
    #[test]
    fn the_two_budgets_fold_to_their_minimum() {
        let handle = shared_clock(CurlTime::new(0, 0));
        let timers = timers_at(&handle);

        // The connect budget is the tighter one.
        let mut deadline = connecting_at(CurlTime::new(0, 0));
        deadline.set_connect_timeout_ms(1_000);
        deadline.set_operation_timeout_ms(9_000);
        deadline.set_started_op_at(CurlTime::new(0, 0));
        assert_eq!(timeleft_now_ms(&deadline, &timers, handle.now()), 1_000);

        // The overall budget is the tighter one.
        let mut other = connecting_at(CurlTime::new(0, 0));
        other.set_connect_timeout_ms(9_000);
        other.set_operation_timeout_ms(1_500);
        other.set_started_op_at(CurlTime::new(0, 0));
        assert_eq!(timeleft_now_ms(&other, &timers, handle.now()), 1_500);

        // The operation started earlier than this connect attempt, which is the
        // ordinary case on a redirect: the overall budget has been running
        // longer and wins.
        let mut later = connecting_at(CurlTime::new(4, 0));
        later.set_connect_timeout_ms(10_000);
        later.set_operation_timeout_ms(6_000);
        later.set_started_op_at(CurlTime::new(0, 0));
        handle.set(CurlTime::new(4, 0));
        assert_eq!(
            timeleft_now_ms(&later, &timers, handle.now()),
            2_000,
            "6000 less the 4000 already spent on the operation"
        );
    }

    /// Required test 11 -- zero means "no limit", and the two ways of asking
    /// for it.
    #[test]
    fn no_timeout_and_connect_only_both_report_no_limit() {
        let handle = shared_clock(CurlTime::new(50, 0));
        let timers = timers_at(&handle);

        // Not connecting and no overall timeout.
        let bare = DeadlineState::new();
        assert_eq!(timeleft_now_ms(&bare, &timers, handle.now()), 0);

        // Not connecting, an overall timeout set, but `CURLOPT_CONNECT_ONLY`.
        let mut connect_only = DeadlineState::new();
        connect_only.set_operation_timeout_ms(1_000);
        connect_only.set_started_op_at(CurlTime::new(0, 0));
        connect_only.set_connect_only(true);
        assert!(connect_only.connect_only());
        assert_eq!(timeleft_now_ms(&connect_only, &timers, handle.now()), 0);

        // While CONNECTING, `connect_only` does NOT lift the connect budget:
        // the C reaches that arm only in the `else` of `Curl_is_connecting`.
        let mut still_connecting = connecting_at(CurlTime::new(50, 0));
        still_connecting.set_connect_only(true);
        assert_eq!(
            timeleft_now_ms(&still_connecting, &timers, handle.now()),
            300000
        );
    }

    /// Required test 12 -- an exactly-expired budget reports `-1`, and the
    /// correction is applied to EACH budget independently.
    ///
    /// This is the test that would fail if the correction were applied once to
    /// the folded answer instead of twice to the operands.
    #[test]
    fn an_exactly_expired_budget_reports_minus_one_on_each_side() {
        let handle = shared_clock(CurlTime::new(0, 0));
        let timers = timers_at(&handle);

        // The CONNECT budget lands exactly on zero, with no overall timeout.
        let mut connect = connecting_at(CurlTime::new(0, 0));
        connect.set_connect_timeout_ms(1_000);
        handle.set(CurlTime::new(1, 0));
        assert_eq!(
            timeleft_now_ms(&connect, &timers, handle.now()),
            -1,
            "an exact zero must not be reported as unlimited"
        );

        // The OPERATION budget lands exactly on zero, while not connecting.
        let mut operation = DeadlineState::new();
        operation.set_operation_timeout_ms(1_000);
        operation.set_started_op_at(CurlTime::new(0, 0));
        assert_eq!(timeleft_now_ms(&operation, &timers, handle.now()), -1);

        // BOTH land exactly on zero at once. Each becomes -1 and the minimum of
        // -1 and -1 is -1; a single correction applied to the fold would have
        // seen 0 - 0 = 0 and answered "unlimited".
        let mut both = connecting_at(CurlTime::new(0, 0));
        both.set_connect_timeout_ms(1_000);
        both.set_operation_timeout_ms(1_000);
        both.set_started_op_at(CurlTime::new(0, 0));
        assert_eq!(timeleft_now_ms(&both, &timers, handle.now()), -1);

        // One exact zero beside one live budget: the -1 wins the fold, because
        // an expired deadline is smaller than any remaining time.
        let mut mixed = connecting_at(CurlTime::new(0, 0));
        mixed.set_connect_timeout_ms(1_000);
        mixed.set_operation_timeout_ms(60_000);
        mixed.set_started_op_at(CurlTime::new(0, 0));
        assert_eq!(timeleft_now_ms(&mixed, &timers, handle.now()), -1);
    }

    // -- 13 to 18. the shutdown timers ------------------------------------

    /// Required test 13 -- a shutdown in progress on the primary chain wins
    /// outright over both generic budgets.
    #[test]
    fn a_started_shutdown_overrides_the_generic_deadline() {
        let handle = shared_clock(CurlTime::new(0, 0));
        let mut timers = timers_at(&handle);
        let expiry = TestExpiry::default();
        let mut diagnostics = Recorder::default();

        // A transfer whose generic answer would be 1000 ms.
        let mut deadline = connecting_at(CurlTime::new(0, 0));
        deadline.set_connect_timeout_ms(1_000);
        assert_eq!(timeleft_now_ms(&deadline, &timers, handle.now()), 1_000);

        shutdown_start(
            &mut timers,
            SocketIndex::First,
            250,
            TransferRole::Registered,
            &expiry,
            &mut diagnostics,
        );

        assert_eq!(
            timeleft_now_ms(&deadline, &timers, handle.now()),
            250,
            "the shutdown budget replaces the connect budget entirely"
        );

        // A shutdown on the SECONDARY chain does not: the C tests FIRSTSOCKET.
        let mut secondary = timers_at(&handle);
        shutdown_start(
            &mut secondary,
            SocketIndex::Secondary,
            250,
            TransferRole::Registered,
            &expiry,
            &mut diagnostics,
        );
        assert_eq!(
            timeleft_now_ms(&deadline, &secondary, handle.now()),
            1_000,
            "only the primary chain's shutdown short-circuits"
        );
    }

    /// Required test 14 -- the three-way budget rule, in its order.
    #[test]
    fn the_shutdown_budget_resolves_explicit_then_configured_then_default() {
        let handle = shared_clock(CurlTime::new(0, 0));
        let expiry = TestExpiry::default();
        let mut diagnostics = Recorder::default();

        // Nothing set anywhere: the 2000 ms default.
        let mut plain = timers_at(&handle);
        assert_eq!(plain.configured_timeout_ms(), 0);
        shutdown_start(
            &mut plain,
            SocketIndex::First,
            0,
            TransferRole::Registered,
            &expiry,
            &mut diagnostics,
        );
        assert_eq!(plain.timeout_ms(), 2000);

        // `CURLOPT_SHUTDOWN_TIMEOUT` set, no explicit argument.
        let mut configured = timers_at(&handle).with_configured_timeout_ms(750);
        assert_eq!(configured.configured_timeout_ms(), 750);
        shutdown_start(
            &mut configured,
            SocketIndex::First,
            0,
            TransferRole::Registered,
            &expiry,
            &mut diagnostics,
        );
        assert_eq!(configured.timeout_ms(), 750);

        // An explicit argument outranks the configured value.
        let mut explicit = timers_at(&handle).with_configured_timeout_ms(750);
        shutdown_start(
            &mut explicit,
            SocketIndex::First,
            120,
            TransferRole::Registered,
            &expiry,
            &mut diagnostics,
        );
        assert_eq!(explicit.timeout_ms(), 120);

        // Both tests are strictly positive, so a non-positive value at either
        // step falls through instead of becoming an expired budget.
        for (explicit_ms, configured_ms, expected) in
            [(0, 0, 2000), (-1, 0, 2000), (0, -1, 2000), (-1, 900, 900)]
        {
            let mut timers =
                timers_at(&handle).with_configured_timeout_ms(configured_ms);
            timers.set_configured_timeout_ms(configured_ms);
            shutdown_start(
                &mut timers,
                SocketIndex::First,
                explicit_ms,
                TransferRole::Registered,
                &expiry,
                &mut diagnostics,
            );
            assert_eq!(
                timers.timeout_ms(),
                expected,
                "explicit {explicit_ms}, configured {configured_ms}"
            );
        }
    }

    /// Required test 15 -- starting and clearing are per chain.
    #[test]
    fn each_chain_starts_and_clears_independently() {
        let handle = shared_clock(CurlTime::new(7, 0));
        let mut timers = timers_at(&handle);
        let expiry = TestExpiry::default();
        let mut diagnostics = Recorder::default();

        assert!(!shutdown_started(&timers, SocketIndex::First));
        assert!(!shutdown_started(&timers, SocketIndex::Secondary));
        assert!(timers.started_at(SocketIndex::First).is_none());

        shutdown_start(
            &mut timers,
            SocketIndex::First,
            500,
            TransferRole::Registered,
            &expiry,
            &mut diagnostics,
        );
        assert!(shutdown_started(&timers, SocketIndex::First));
        assert!(!shutdown_started(&timers, SocketIndex::Secondary));
        assert_eq!(
            timers.started_at(SocketIndex::First),
            Some(CurlTime::new(7, 0))
        );

        handle.advance(Duration::from_millis(100));
        shutdown_start(
            &mut timers,
            SocketIndex::Secondary,
            500,
            TransferRole::Registered,
            &expiry,
            &mut diagnostics,
        );
        assert_eq!(
            timers.started_at(SocketIndex::Secondary),
            Some(CurlTime::new(7, 100_000)),
            "each chain records its OWN instant"
        );

        // Clearing one leaves the other running, which is why the C `memset`s
        // a single element of `start[2]`.
        shutdown_clear(&mut timers, SocketIndex::First);
        assert!(!shutdown_started(&timers, SocketIndex::First));
        assert!(shutdown_started(&timers, SocketIndex::Secondary));
        assert_eq!(
            timers.timeout_ms(),
            500,
            "clearing a marker does not clear the shared budget"
        );

        shutdown_clear(&mut timers, SocketIndex::Secondary);
        assert!(!shutdown_started(&timers, SocketIndex::Secondary));
        assert_eq!(shutdown_timeleft(&timers, SocketIndex::Secondary), 0);
    }

    /// Required test 16 -- an exactly-expired shutdown reports `-1`, and an
    /// unstarted or unlimited one reports `0`.
    #[test]
    fn an_exactly_expired_shutdown_reports_minus_one() {
        let handle = shared_clock(CurlTime::new(0, 0));
        let mut timers = timers_at(&handle);
        let expiry = TestExpiry::default();
        let mut diagnostics = Recorder::default();

        // Not started: zero, meaning no limit rather than no time.
        assert_eq!(shutdown_timeleft(&timers, SocketIndex::First), 0);

        shutdown_start(
            &mut timers,
            SocketIndex::First,
            1_000,
            TransferRole::Registered,
            &expiry,
            &mut diagnostics,
        );
        assert_eq!(shutdown_timeleft(&timers, SocketIndex::First), 1_000);

        handle.advance(Duration::from_millis(999));
        assert_eq!(shutdown_timeleft(&timers, SocketIndex::First), 1);

        handle.advance(Duration::from_millis(1));
        assert_eq!(
            shutdown_timeleft(&timers, SocketIndex::First),
            -1,
            "landing exactly on the deadline is expiry, not unlimited"
        );

        handle.advance(Duration::from_millis(500));
        assert_eq!(shutdown_timeleft(&timers, SocketIndex::First), -500);
    }

    /// Required test 17 -- the connection-wide answer is the smallest NON-ZERO
    /// remaining time, not a plain minimum.
    #[test]
    fn the_connection_wide_shutdown_deadline_ignores_zeroes() {
        let handle = shared_clock(CurlTime::new(0, 0));
        let expiry = TestExpiry::default();
        let mut diagnostics = Recorder::default();

        // Neither chain started: zero.
        let mut none = timers_at(&handle);
        assert_eq!(conn_shutdown_timeleft(&none), 0);

        // Only the secondary started: its own answer, not zero -- a plain `min`
        // over the two would have taken the primary's zero and reported the
        // whole connection unlimited.
        shutdown_start(
            &mut none,
            SocketIndex::Secondary,
            800,
            TransferRole::Registered,
            &expiry,
            &mut diagnostics,
        );
        assert_eq!(shutdown_timeleft(&none, SocketIndex::First), 0);
        assert_eq!(conn_shutdown_timeleft(&none), 800);

        // Both started, at different instants: the tighter one.
        handle.advance(Duration::from_millis(300));
        shutdown_start(
            &mut none,
            SocketIndex::First,
            800,
            TransferRole::Registered,
            &expiry,
            &mut diagnostics,
        );
        assert_eq!(shutdown_timeleft(&none, SocketIndex::Secondary), 500);
        assert_eq!(shutdown_timeleft(&none, SocketIndex::First), 800);
        assert_eq!(conn_shutdown_timeleft(&none), 500);

        // An expired chain beside a live one: the negative wins, because it is
        // non-zero and smaller.
        handle.advance(Duration::from_millis(600));
        assert_eq!(conn_shutdown_timeleft(&none), -100);
    }

    /// Required test 18 -- timer 14 is armed for a registered transfer only,
    /// and the two trace renderings are the C's.
    #[test]
    fn the_shutdown_timer_is_fourteen_and_the_trace_names_the_chain() {
        assert_eq!(TimerId::Shutdown.as_i32(), 14);
        assert_eq!(EXPIRE_SHUTDOWN, 14);

        let handle = shared_clock(CurlTime::new(0, 0));
        let expiry = TestExpiry::default();
        let mut diagnostics = Recorder::default();
        let mut timers = timers_at(&handle).with_configured_timeout_ms(1_250);

        shutdown_start(
            &mut timers,
            SocketIndex::First,
            0,
            TransferRole::Registered,
            &expiry,
            &mut diagnostics,
        );
        assert_eq!(
            expiry.armed.borrow().as_slice(),
            &[(1_250, TimerId::Shutdown)],
            "the RESOLVED budget is what is armed, not the argument"
        );
        assert_eq!(diagnostics.notes, vec![SHUTDOWN_START_PRIMARY.to_owned()]);
        assert_eq!(diagnostics.notes[0], "shutdown start on connection");

        shutdown_start(
            &mut timers,
            SocketIndex::Secondary,
            0,
            TransferRole::Registered,
            &expiry,
            &mut diagnostics,
        );
        assert_eq!(expiry.armed.borrow().len(), 2);
        assert_eq!(
            diagnostics.notes[1], "shutdown start on secondary connection",
            "the C's `sockindex ? \" secondary\" : \"\"`"
        );

        // The admin handle gets the state change and the trace, but NO timer:
        // `if(data->mid)` is what gates the arming.
        let mut admin = timers_at(&handle);
        shutdown_start(
            &mut admin,
            SocketIndex::First,
            300,
            TransferRole::Admin,
            &expiry,
            &mut diagnostics,
        );
        assert!(admin.started(SocketIndex::First));
        assert_eq!(admin.timeout_ms(), 300);
        assert_eq!(
            expiry.armed.borrow().len(),
            2,
            "the admin handle arms nothing"
        );
        assert_eq!(diagnostics.notes.len(), 3, "but it still traces");
        assert!(TransferRole::Registered.arms_timers());
        assert!(!TransferRole::Admin.arms_timers());
        assert_eq!(TransferRole::default(), TransferRole::Registered);
    }

    /// The [`Deadline`] adapter really is this module's arithmetic, reached
    /// through the trait object every sibling injects.
    #[test]
    fn the_shared_deadline_reports_this_modules_arithmetic() {
        let handle = shared_clock(CurlTime::new(0, 0));
        let shared =
            TransferDeadline::new(DeadlineState::new(), timers_at(&handle));

        assert_eq!(shared.time_left_ms(), 0, "no limit to begin with");

        shared.with_state(|state| {
            state.set_connecting(true);
            state.set_started_single_at(CurlTime::new(0, 0));
            state.set_connect_timeout_ms(4_000);
        });
        assert_eq!(shared.time_left_ms(), 4_000);
        assert_eq!(shared.time_left_at(CurlTime::new(1, 0)), 3_000);

        handle.advance(Duration::from_millis(1_500));
        assert_eq!(shared.time_left_ms(), 2_500);

        // A shutdown started through the same handle takes precedence, which is
        // the whole reason the two live behind one lock.
        let expiry = TestExpiry::default();
        let mut diagnostics = Recorder::default();
        shared.with_timers(|timers| {
            shutdown_start(
                timers,
                SocketIndex::First,
                200,
                TransferRole::Registered,
                &expiry,
                &mut diagnostics,
            );
        });
        assert_eq!(shared.time_left_ms(), 200);

        // And it is usable as the trait object the siblings hold.
        let injected: Arc<dyn Deadline> = Arc::new(TransferDeadline::new(
            DeadlineState::new(),
            timers_at(&handle),
        ));
        assert_eq!(injected.time_left_ms(), 0);
    }

    // -- 19 to 23. `addr2string` -------------------------------------------

    /// Required test 19 -- an `AF_INET` address and its host-order port.
    #[test]
    fn addr2string_renders_an_ipv4_address_and_port() {
        for (text, expected_addr, expected_port) in [
            ("127.0.0.1:80", "127.0.0.1", 80_u16),
            ("0.0.0.0:0", "0.0.0.0", 0),
            ("255.255.255.255:65535", "255.255.255.255", 65535),
            ("192.168.1.10:8080", "192.168.1.10", 8080),
        ] {
            let parsed = text.parse::<SocketAddr>().expect("a literal");
            let rendered = addr2string(&SockAddr::from(parsed))
                .expect("AF_INET is supported");
            assert_eq!(rendered.addr, expected_addr);
            assert_eq!(
                rendered.port, expected_port,
                "the port is HOST order: `ntohs(si->sin_port)`"
            );
            assert!(rendered.addr.len() < MAX_IPADR_LEN);
        }
    }

    /// Required test 20 -- an `AF_INET6` address, including the two renderings
    /// where curl and the standard library disagree.
    #[test]
    fn addr2string_renders_an_ipv6_address_and_port() {
        for (text, expected_addr) in [
            ("[::]:443", "::"),
            ("[::1]:443", "::1"),
            ("[fe80::1]:9", "fe80::1"),
            ("[2001:db8::5]:443", "2001:db8::5"),
            // curl declines to compress a SINGLE zero group where the standard
            // library compresses it, so this must not render as `2001:db8::1:1`.
            ("[2001:db8:0:1:1:1:1:1]:1", "2001:db8:0:1:1:1:1:1"),
            // An IPv4-compatible address, which curl renders with a dotted tail.
            ("[::1.2.3.4]:7", "::1.2.3.4"),
        ] {
            let parsed = text.parse::<SocketAddr>().expect("a literal");
            let rendered = addr2string(&SockAddr::from(parsed))
                .expect("AF_INET6 is supported");
            assert_eq!(rendered.addr, expected_addr, "for {text}");
            assert!(
                rendered.addr.len() < MAX_IPADR_LEN,
                "every rendering fits the C's buffer"
            );
        }

        // The widest rendering a real address REACHES is 39 bytes: eight
        // four-digit groups and the seven colons between them. `MAX_IPADR_LEN`
        // is 46 because the C sizes its buffer from the widest SPELLING a human
        // might write, `ffff:...:255.255.255.255` -- and that spelling denotes
        // the all-ones address, which renders in pure hexadecimal because
        // curl's dotted-tail rule requires a leading run of zero groups.
        let widest = "[ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255]:1"
            .parse::<SocketAddr>()
            .expect("a literal");
        let rendered = addr2string(&SockAddr::from(widest)).expect("supported");
        assert_eq!(rendered.addr, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
        assert_eq!(rendered.addr.len(), 39);
        assert!(rendered.addr.len() < MAX_IPADR_LEN);
        assert_eq!(rendered.port, 1);

        // The widest DOTTED rendering, which is what curl's rule produces for
        // an IPv4-mapped address -- the form the 46-byte buffer was sized for.
        let mapped = "[::ffff:255.255.255.255]:1"
            .parse::<SocketAddr>()
            .expect("a literal");
        let rendered = addr2string(&SockAddr::from(mapped)).expect("supported");
        assert_eq!(rendered.addr, "::ffff:255.255.255.255");
        assert_eq!(rendered.port, 1);
    }

    /// Required test 21 -- a NAMED `AF_UNIX` socket: its path, port zero,
    /// success.
    #[test]
    #[cfg(unix)]
    fn addr2string_renders_a_named_unix_path() {
        for path in ["/tmp/curl-rs-conn-test.sock", "relative.sock", "/x"] {
            let named = SockAddr::unix(path).expect("a short path");
            let rendered = addr2string(&named).expect("AF_UNIX is supported");
            assert_eq!(rendered.addr, path);
            assert_eq!(rendered.port, 0, "AF_UNIX has no port");
        }
    }

    /// Required test 22 -- an UNNAMED `AF_UNIX` socket is a SUCCESS with an
    /// empty name.
    ///
    /// The C's `else addr[0] = 0;` arm, whose comment is *"socket with no
    /// name"*, reached when `salen` is no larger than the family field. An
    /// unnamed Unix socket is an ordinary thing -- a `socketpair` produces two
    /// of them -- so this is not a failure and must not be reported as one.
    #[test]
    #[cfg(unix)]
    fn addr2string_renders_an_unnamed_unix_socket_as_empty() {
        let unnamed = SockAddr::unix("").expect("the empty path");
        assert!(unnamed.is_unix());
        assert!(
            unnamed.as_pathname().is_none(),
            "the length is exactly the family field, so there is no name"
        );

        let rendered =
            addr2string(&unnamed).expect("an unnamed socket is not an error");
        assert_eq!(rendered.addr, "");
        assert_eq!(rendered.port, 0);
    }

    /// Required test 23 -- an unsupported family empties both outputs and
    /// reports `SOCKEAFNOSUPPORT`.
    ///
    /// The errno mapping is asserted unconditionally. The family itself is
    /// exercised through `AF_VSOCK`, which `socket2` can build SAFELY -- and
    /// only on Linux and Android, so the second half is gated. That is the only
    /// safe route to a fourth family: every other constructor in `socket2`
    /// produces `AF_INET`, `AF_INET6` or `AF_UNIX`, and the general one carries
    /// the safety obligation this crate does not accept outside `src/ffi`.
    #[test]
    fn addr2string_refuses_an_unsupported_family() {
        assert_eq!(
            Addr2StringError::AfNotSupported.errno(),
            crate::ffi::sys::SOCKEAFNOSUPPORT
        );

        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let vsock = SockAddr::vsock(1, 2);
            assert!(vsock.as_socket().is_none(), "not AF_INET or AF_INET6");
            assert!(!vsock.is_unix());

            let outcome = addr2string(&vsock);
            assert_eq!(outcome, Err(Addr2StringError::AfNotSupported));

            // `addr[0] = '\0'; *port = 0;` -- the C writes both before failing,
            // and here the pair simply cannot be read from an `Err`, which is
            // the stronger guarantee.
            assert!(outcome.is_err());
        }
    }

    // -- 24 to 26. the most recent connection ------------------------------

    /// A pooled connection whose primary chain answers `CF_QUERY_SOCKET` with
    /// `socket`, and its identity.
    fn pool_with_connection(
        cx: &mut CallCtx<'_, '_>,
        pool: &mut ConnectionPool,
        handle: &Arc<TestClock>,
        log: &EventLog,
        socket: Option<Socket>,
    ) -> (ConnectionId, PoolKey) {
        let mut chains = FilterChains::new(None);
        if let Some(socket) = socket {
            let marker =
                Marker::new("TCP", flags_of("TCP"), 0, log).with_socket(socket);
            chains.chain_mut(SocketIndex::First).add(cx, link(marker));
        }
        let spec = ConnectionSpec::new(
            "example.com:443",
            chains,
            Box::new(timers_at(handle)),
            handle.now(),
        );
        let key = pool.add(cx, spec);
        let id = pool
            .get(key)
            .expect("the connection was just added")
            .connection_id();
        (id, key)
    }

    /// Required test 24 -- a handle that has never connected answers nothing.
    #[test]
    fn getconnectinfo_answers_nothing_without_a_last_connection() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let mut pool = ConnectionPool::new();
        let mut lastconnect_id = ConnectionId::NONE;

        assert!(
            getconnectinfo(&mut cx, &mut lastconnect_id, &mut pool).is_none()
        );
        assert_eq!(
            lastconnect_id,
            ConnectionId::NONE,
            "the field is left as it was"
        );

        // `Curl_cpool_xfer_init` is what puts it in this state.
        assert_eq!(pool.xfer_init().lastconnect_id, ConnectionId::NONE);
    }

    /// Required test 25 -- a stale identifier is reset to `-1` and answers
    /// nothing, so a second query does not repeat the search.
    #[test]
    fn getconnectinfo_resets_a_stale_identifier() {
        let clock = clock();
        let handle = shared_clock(CurlTime::new(3, 0));
        let log = new_log();
        let mut cx = CallCtx::new(&clock);
        let mut pool = ConnectionPool::new();

        let (id, key) =
            pool_with_connection(&mut cx, &mut pool, &handle, &log, Some(11));
        let mut lastconnect_id = id;

        // Live: it resolves.
        assert!(
            getconnectinfo(&mut cx, &mut lastconnect_id, &mut pool).is_some()
        );
        assert_eq!(lastconnect_id, id, "a live identifier is left alone");

        // Now the connection goes away, as an eviction or a shutdown does.
        assert!(pool.remove(key).is_some());
        assert!(
            getconnectinfo(&mut cx, &mut lastconnect_id, &mut pool).is_none()
        );
        assert_eq!(
            lastconnect_id,
            ConnectionId::NONE,
            "the stale identifier must be written back as -1"
        );

        // A second query short-circuits on the reset field.
        assert!(
            getconnectinfo(&mut cx, &mut lastconnect_id, &mut pool).is_none()
        );
    }

    /// Required test 26 -- a live identifier answers with the pool key and the
    /// PRIMARY chain's socket.
    #[test]
    fn getconnectinfo_answers_the_primary_socket() {
        let clock = clock();
        let handle = shared_clock(CurlTime::new(3, 0));
        let log = new_log();
        let mut cx = CallCtx::new(&clock);
        let mut pool = ConnectionPool::new();

        let (id, key) =
            pool_with_connection(&mut cx, &mut pool, &handle, &log, Some(42));
        let mut lastconnect_id = id;

        let found = getconnectinfo(&mut cx, &mut lastconnect_id, &mut pool)
            .expect("the connection is live");
        assert_eq!(found.key, key, "the key is the pool's, not the ABI's");
        assert_eq!(found.socket, 42);

        // A connection with no chain has no descriptor to offer, which is the
        // `CURL_SOCKET_BAD` the FFI reports for `CURLINFO_ACTIVESOCKET`.
        let (bare_id, _) =
            pool_with_connection(&mut cx, &mut pool, &handle, &log, None);
        let mut bare = bare_id;
        let found = getconnectinfo(&mut cx, &mut bare, &mut pool)
            .expect("the connection is live even with no chain");
        assert_eq!(found.socket, CURL_SOCKET_BAD);
        assert_eq!(bare, bare_id, "and the identifier is not disturbed");
    }

    // -- 27, 28. marking a connection closed -------------------------------

    /// A [`FilterChains`] whose primary chain carries one filter with `flags`.
    fn chains_with(
        cx: &mut CallCtx<'_, '_>,
        log: &EventLog,
        name: &'static str,
        flags: CfType,
    ) -> FilterChains {
        let mut chains = FilterChains::new(Some(ConnId::new(5)));
        chains
            .chain_mut(SocketIndex::First)
            .add(cx, link(Marker::new(name, flags, 0, log)));
        chains
    }

    /// Required test 27 -- the four rows of `Curl_conncontrol`'s truth table.
    #[test]
    fn conncontrol_marks_a_connection_a_stream_and_nothing_else() {
        let clock = clock();
        let log = new_log();
        let mut cx = CallCtx::new(&clock);

        let plain = chains_with(&mut cx, &log, "TCP", flags_of("TCP"));
        let multiplexed =
            chains_with(&mut cx, &log, "HTTP/2", CF_TYPE_MULTIPLEX);
        assert!(!plain.chain(SocketIndex::First).is_multiplex());
        assert!(multiplexed.chain(SocketIndex::First).is_multiplex());

        // CONNECTION marks, whether multiplexed or not.
        for chains in [&plain, &multiplexed] {
            let mut state = ConnectionState::new();
            conncontrol(&mut state, chains, ConnControl::Connection, "done");
            assert!(state.wants_close());
        }

        // STREAM marks only when NOT multiplexed.
        let mut state = ConnectionState::new();
        conncontrol(&mut state, &plain, ConnControl::Stream, "stream over");
        assert!(state.wants_close(), "a stream IS the connection here");

        let mut shared = ConnectionState::new();
        conncontrol(&mut shared, &multiplexed, ConnControl::Stream, "one of n");
        assert!(!shared.wants_close());

        // KEEP clears a mark.
        let mut marked = ConnectionState::new();
        conncontrol(&mut marked, &plain, ConnControl::Connection, "mark");
        assert!(marked.wants_close());
        conncontrol(&mut marked, &plain, ConnControl::Keep, "never mind");
        assert!(!marked.wants_close());

        // The row that is a NO-OP rather than a clear: a stream signal on a
        // multiplexed connection must leave an existing mark standing.
        let mut already = ConnectionState::new();
        conncontrol(
            &mut already,
            &multiplexed,
            ConnControl::Connection,
            "fatal",
        );
        assert!(already.wants_close());
        conncontrol(&mut already, &multiplexed, ConnControl::Stream, "stream");
        assert!(
            already.wants_close(),
            "a stream signal on a multiplexed connection must change nothing"
        );

        // And it does not mark an unmarked one either.
        let mut unmarked = ConnectionState::new();
        conncontrol(&mut unmarked, &multiplexed, ConnControl::Stream, "s");
        assert!(!unmarked.wants_close());

        // The debug reason is retained in a debug build and reaches a trace.
        let mut reasoned = ConnectionState::new();
        conncontrol(&mut reasoned, &plain, ConnControl::Connection, "no keep");
        #[cfg(debug_assertions)]
        assert_eq!(reasoned.close_reason(), Some("no keep"));
    }

    /// Required test 28 -- nothing else in this module writes the close bit.
    ///
    /// Two halves. Behaviourally, every other entry point is driven against a
    /// state that is already marked and the mark must survive. Structurally, the
    /// assignment appears exactly once in this file's source -- which is what
    /// `lib/connect.c:319-320` asks for with a comment: *"the only place in the
    /// source code that should assign this bit"*. The needle is assembled at run
    /// time so that this test's own source does not satisfy it.
    #[test]
    fn only_conncontrol_writes_the_close_bit() {
        let here = include_str!("mod.rs");
        let needle = format!("state.{} = closeit", "close");
        assert_eq!(
            here.matches(&needle).count(),
            1,
            "the close bit must be assigned in exactly one place"
        );
        assert!(
            !here.contains(&format!("fn set_{}(", "close")),
            "no setter may exist for it"
        );

        let clock = clock();
        let handle = shared_clock(CurlTime::new(0, 0));
        let log = new_log();
        let mut cx = CallCtx::new(&clock);
        let plain = chains_with(&mut cx, &log, "TCP", flags_of("TCP"));

        let mut state = ConnectionState::new();
        conncontrol(&mut state, &plain, ConnControl::Connection, "mark");
        assert!(state.wants_close());

        // Everything else this module exposes, against the marked state.
        let mut multi = TestMulti::default();
        assert!(conn_set_multiplex(&mut state, Some(&mut multi)));
        let mut timers = timers_at(&handle);
        let expiry = TestExpiry::default();
        let mut diagnostics = Recorder::default();
        shutdown_start(
            &mut timers,
            SocketIndex::First,
            10,
            TransferRole::Registered,
            &expiry,
            &mut diagnostics,
        );
        shutdown_clear(&mut timers, SocketIndex::First);
        let _ = conn_shutdown_timeleft(&timers);
        let _ = timeleft_ms(&DeadlineState::new(), &timers, handle.as_ref());
        let _ = alpn2alpnid(b"h2");

        assert!(
            state.wants_close(),
            "no other entry point may disturb the close bit"
        );
    }

    // -- 29 to 37. the setup machine ---------------------------------------

    /// A standalone SETUP filter over `context`, outside any chain.
    ///
    /// Outside a chain deliberately: the filter splices below ITSELF, so it
    /// needs no chain to build one, and keeping it out of a chain is what lets a
    /// test read [`SetupFilter::state`] between passes -- a filter installed in
    /// a chain is a `dyn ConnFilter` with no way back to its concrete type.
    fn setup(context: SetupContext, tls_mode: TlsMode) -> SetupFilter {
        let mut filter = SetupFilter::new(
            SocketIndex::First,
            context,
            Transport::Tcp,
            tls_mode,
        );
        // A chain would stamp this; standing outside one, the filter stamps
        // itself, because `insert_below` propagates the identity downwards.
        filter.base_mut().set_conn(Some(ConnId::new(9)));
        filter
    }

    /// Required test 29 -- the seven states, and the ones a plain connection
    /// actually visits.
    #[test]
    fn the_setup_machine_visits_the_states_the_c_visits() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let log = new_log();
        let factories = Arc::new(TestFactories::new(&log).with_steps(1));

        let mut filter = setup(context(&factories), TlsMode::Default);
        assert_eq!(filter.state(), SetupState::Init);

        // The first pass installs Happy Eyeballs and then finds it unconnected,
        // so it stops there.
        assert!(!filter.connect(&mut cx).expect("no failure"));
        assert_eq!(filter.state(), SetupState::CnnctEyeballs);

        // The second pass connects it and walks the remaining stages. Neither
        // SOCKS nor the HTTP proxy is configured, and their state assignment is
        // inside their guard, so neither value is ever taken.
        assert!(filter.connect(&mut cx).expect("no failure"));
        assert_eq!(filter.state(), SetupState::Done);
        assert!(filter.base().is_connected());

        // An already-connected filter answers at once and installs nothing.
        let before = events(&log);
        assert!(filter.connect(&mut cx).expect("no failure"));
        assert_eq!(
            events(&log),
            before,
            "the early-out must be side-effect free"
        );

        // Every state is constructible and ordered; a proxied, secured
        // connection is what takes the two the plain one skipped. Every stage
        // is requested, so every stage installs.
        //
        // The HAProxy stage survives an HTTPS proxy because `is_ssl` stops at
        // the first `CF_TYPE_IP_CONNECT` filter, exactly as C's
        // `Curl_conn_is_ssl` does: the tunnel sits ABOVE the proxy TLS, so the
        // walk answers "not encrypted" and stage 4 is not refused. Test 32
        // covers the arrangement where it IS refused.
        let full = Arc::new(TestFactories::new(&log));
        let mut proxied = setup(
            context(&full)
                .with_socks_proxy(true)
                .with_http_proxy(ProxyType::Https, true)
                .with_haproxy_protocol(true)
                .with_protocol_flags(ProtocolOptions::SSL),
            TlsMode::Default,
        );
        assert!(proxied.connect(&mut cx).expect("no failure"));
        assert_eq!(proxied.state(), SetupState::Done);
        assert_eq!(
            chain_names(&proxied),
            vec![
                "SETUP",
                "SSL",
                "HAPROXY",
                "HTTP-PROXY",
                "SSL-PROXY",
                "SOCKS",
                "HAPPY-EYEBALLS",
            ],
            "a HAPROXY appears only because it was asked for below"
        );
    }

    /// Required test 30 -- the whole stack, in the exact order the bytes
    /// require.
    ///
    /// This is the single most important assertion in this file. Every stage
    /// inserts immediately below SETUP, so the chain reads in the REVERSE of the
    /// order the stages ran.
    #[test]
    fn the_full_stack_is_built_top_down_in_reverse_stage_order() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let log = new_log();
        let factories = Arc::new(TestFactories::new(&log));

        let mut filter = setup(
            context(&factories)
                .with_socks_proxy(true)
                .with_http_proxy(ProxyType::Https2, true)
                .with_haproxy_protocol(true)
                .with_protocol_flags(ProtocolOptions::SSL),
            TlsMode::Default,
        );

        assert!(filter.connect(&mut cx).expect("every stage succeeds"));
        assert_eq!(
            chain_names(&filter),
            vec![
                "SETUP",
                "SSL",
                "HAPROXY",
                "HTTP-PROXY",
                "SSL-PROXY",
                "SOCKS",
                "HAPPY-EYEBALLS",
            ]
        );

        // The order the stages RAN, which is the reverse of the above.
        let built: Vec<String> = events(&log)
            .into_iter()
            .filter(|line| line.starts_with("build:"))
            .collect();
        assert_eq!(
            built,
            vec![
                "build:HAPPY-EYEBALLS",
                "build:SOCKS",
                "build:SSL-PROXY",
                "build:HTTP-PROXY",
                "build:HAPROXY",
                "build:SSL",
            ],
            "proxy TLS is built BEFORE the tunnel so it ends up BELOW it"
        );

        // The transport reached the factory unchanged.
        assert!(events(&log).contains(&"transport:3".to_owned()));

        // Every inserted filter was stamped with the chain's identity.
        let mut cursor = filter.base().next_ref();
        while let Some(node) = cursor {
            assert_eq!(node.base().conn(), Some(ConnId::new(9)));
            assert_eq!(node.base().sockindex(), SocketIndex::First);
            cursor = node.base().next_ref();
        }
    }

    /// The independent model of the algorithm this file implements.
    ///
    /// Re-derived from `lib/connect.c:364-439` rather than from the
    /// implementation, which is what makes the exhaustive comparison below
    /// meaningful: agreeing with itself would prove nothing.
    fn model(
        socks: bool,
        proxy: Option<(ProxyType, bool)>,
        haproxy: bool,
        tls_mode: TlsMode,
        scheme_ssl: bool,
    ) -> Result<Vec<&'static str>, CURLcode> {
        /// `cf_is_ssl` over a chain given top first.
        fn is_ssl(chain: &[&'static str]) -> bool {
            for name in chain {
                let flags = flags_of(name);
                if flags.intersects(CF_TYPE_SSL) {
                    return true;
                }
                if flags.intersects(CF_TYPE_IP_CONNECT) {
                    return false;
                }
            }
            false
        }

        // Built bottom-up, because each insert goes at the TOP of the subchain.
        let mut chain: Vec<&'static str> = vec!["HAPPY-EYEBALLS"];
        if socks {
            chain.insert(0, "SOCKS");
        }
        if let Some((proxy_type, tunnel)) = proxy {
            if proxy_type.is_https() && !is_ssl(&chain) {
                chain.insert(0, "SSL-PROXY");
            }
            if tunnel {
                chain.insert(0, "HTTP-PROXY");
            }
        }
        if haproxy {
            if is_ssl(&chain) {
                return Err(CURLcode::UnsupportedProtocol);
            }
            chain.insert(0, "HAPROXY");
        }
        let wanted = matches!(tls_mode, TlsMode::Enable)
            || (!matches!(tls_mode, TlsMode::Disable) && scheme_ssl);
        if wanted && !is_ssl(&chain) {
            chain.insert(0, "SSL");
        }
        chain.insert(0, "SETUP");
        Ok(chain)
    }

    /// Required test 31 -- every combination of the four configurable stages,
    /// compared against an independently derived model.
    #[test]
    fn every_stage_combination_builds_the_chain_the_c_would() {
        let clock = clock();
        let log = new_log();
        let proxies = [
            None,
            Some((ProxyType::Http, false)),
            Some((ProxyType::Http, true)),
            Some((ProxyType::Http10, true)),
            Some((ProxyType::Https, false)),
            Some((ProxyType::Https, true)),
            Some((ProxyType::Https2, false)),
            Some((ProxyType::Https2, true)),
        ];
        let modes = [TlsMode::Default, TlsMode::Disable, TlsMode::Enable];

        let mut checked = 0_usize;
        let mut refusals = 0_usize;
        for socks in [false, true] {
            for proxy in proxies {
                for haproxy in [false, true] {
                    for tls_mode in modes {
                        for scheme_ssl in [false, true] {
                            let mut cx = CallCtx::new(&clock);
                            let factories = Arc::new(TestFactories::new(&log));
                            let mut built = context(&factories)
                                .with_socks_proxy(socks)
                                .with_haproxy_protocol(haproxy);
                            if let Some((kind, tunnel)) = proxy {
                                built = built.with_http_proxy(kind, tunnel);
                            }
                            if scheme_ssl {
                                built = built
                                    .with_protocol_flags(ProtocolOptions::SSL);
                            }
                            let mut filter = setup(built, tls_mode);
                            let outcome = filter.connect(&mut cx);
                            let expected = model(
                                socks, proxy, haproxy, tls_mode, scheme_ssl,
                            );
                            let label = format!(
                                "socks {socks}, proxy {proxy:?}, \
                                 haproxy {haproxy}, mode {tls_mode:?}, \
                                 scheme_ssl {scheme_ssl}"
                            );
                            match expected {
                                Ok(names) => {
                                    assert!(
                                        outcome.expect("{label}"),
                                        "{label}"
                                    );
                                    assert_eq!(
                                        chain_names(&filter),
                                        names,
                                        "{label}"
                                    );
                                }
                                Err(code) => {
                                    refusals += 1;
                                    let error =
                                        outcome.expect_err(&label.clone());
                                    assert_eq!(error.code(), code, "{label}");
                                }
                            }
                            checked += 1;
                        }
                    }
                }
            }
        }
        assert_eq!(checked, 2 * 8 * 2 * 3 * 2);
        assert!(
            refusals > 0,
            "the refusal arm must be reached, or the model is not testing it"
        );
    }

    /// Required test 32 -- the HAProxy refusal, with the C's exact bytes.
    ///
    /// Reached by making the transport filter itself TLS-protected, which is
    /// what happens under QUIC -- and is why the C's message ends `(QUIC?)`.
    #[test]
    fn haproxy_over_an_encrypted_chain_is_refused_with_the_c_message() {
        assert_eq!(
            HAPROXY_AFTER_SSL,
            "haproxy protocol not support with SSL encryption in place \
             (QUIC?)"
        );

        let log = new_log();
        let factories = Arc::new(TestFactories::new(&log));

        // `with_http_proxy(Https, false)` installs SSL-PROXY with no tunnel
        // above it, so the chain is already TLS-protected when HAProxy is
        // considered.
        let rendered = traced(|cx| {
            let mut filter = setup(
                context(&factories)
                    .with_http_proxy(ProxyType::Https, false)
                    .with_haproxy_protocol(true),
                TlsMode::Default,
            );
            let error = filter
                .connect(cx)
                .expect_err("HAProxy over TLS must be refused");
            assert_eq!(error.code(), CURLcode::UnsupportedProtocol);
            assert_eq!(error.to_string(), HAPROXY_AFTER_SSL);
            // The refusal happens BEFORE the factory is asked for a filter.
            assert!(!events(&log).contains(&"build:HAPROXY".to_owned()));
            // And the state stops short of the HAProxy marker.
            assert_eq!(filter.state(), SetupState::CnnctHttpProxy);
        });
        assert!(
            rendered.contains(HAPROXY_AFTER_SSL),
            "the message must reach the error report: {rendered}"
        );
    }

    /// Required test 33 -- the TLS tri-state against `PROTOPT_SSL`.
    #[test]
    fn the_tls_stage_obeys_the_tri_state_and_the_scheme() {
        let clock = clock();
        let log = new_log();

        for (tls_mode, scheme_ssl, expected) in [
            (TlsMode::Default, false, false),
            (TlsMode::Default, true, true),
            (TlsMode::Disable, false, false),
            // The one row worth pointing at: DISABLE beats the scheme.
            (TlsMode::Disable, true, false),
            (TlsMode::Enable, false, true),
            (TlsMode::Enable, true, true),
        ] {
            let mut cx = CallCtx::new(&clock);
            let factories = Arc::new(TestFactories::new(&log));
            let mut built = context(&factories);
            if scheme_ssl {
                built = built.with_protocol_flags(ProtocolOptions::SSL);
            }
            let mut filter = setup(built, tls_mode);
            assert!(filter.connect(&mut cx).expect("no failure"));
            let has_ssl = chain_names(&filter).contains(&"SSL");
            assert_eq!(
                has_ssl, expected,
                "mode {tls_mode:?} with PROTOPT_SSL {scheme_ssl}"
            );
        }

        // TLS is never doubled: an already-encrypted chain gets no second
        // filter even when the mode demands one.
        let mut cx = CallCtx::new(&clock);
        let factories = Arc::new(TestFactories::new(&log));
        let mut filter = setup(
            context(&factories)
                .with_http_proxy(ProxyType::Https, false)
                .with_protocol_flags(ProtocolOptions::SSL),
            TlsMode::Enable,
        );
        assert!(filter.connect(&mut cx).expect("no failure"));
        assert_eq!(
            chain_names(&filter),
            vec!["SETUP", "SSL-PROXY", "HAPPY-EYEBALLS"],
            "the SSL-PROXY already satisfies `Curl_conn_is_ssl`"
        );
    }

    /// Required test 34 -- each inserted subchain is DRIVEN before the next
    /// stage is considered.
    #[test]
    fn each_inserted_subchain_is_driven_before_the_next_stage() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let log = new_log();
        let factories = Arc::new(TestFactories::new(&log).with_steps(1));

        let mut filter = setup(
            context(&factories)
                .with_socks_proxy(true)
                .with_protocol_flags(ProtocolOptions::SSL),
            TlsMode::Default,
        );

        // Each stage costs one pass, because each new filter refuses once.
        let mut passes = 0_usize;
        loop {
            passes += 1;
            assert!(passes < 12, "the machine must terminate");
            if filter.connect(&mut cx).expect("no failure") {
                break;
            }
        }
        assert_eq!(filter.state(), SetupState::Done);
        assert_eq!(
            chain_names(&filter),
            vec!["SETUP", "SSL", "SOCKS", "HAPPY-EYEBALLS"]
        );

        // A stage's filter is always built AFTER the previous stage's filter has
        // been connected at least once -- which is what the `goto` buys.
        let lines = events(&log);
        let position = |needle: &str| {
            lines
                .iter()
                .position(|line| line == needle)
                .unwrap_or_else(|| panic!("missing {needle}: {lines:?}"))
        };
        assert!(
            position("HAPPY-EYEBALLS:connect") < position("build:SOCKS"),
            "{lines:?}"
        );
        assert!(
            position("SOCKS:connect") < position("build:SSL"),
            "{lines:?}"
        );
    }

    /// Required test 35 -- SETUP's close is destructive and resets the state.
    #[test]
    fn setup_close_destroys_the_subchain_and_resets_the_state() {
        let log = new_log();
        let factories = Arc::new(TestFactories::new(&log));

        let rendered = traced(|cx| {
            let mut filter = setup(
                context(&factories).with_socks_proxy(true),
                TlsMode::Enable,
            );
            assert!(filter.connect(cx).expect("no failure"));
            assert_eq!(
                chain_names(&filter),
                vec!["SETUP", "SSL", "SOCKS", "HAPPY-EYEBALLS"]
            );

            log.borrow_mut().clear();
            filter.close(cx);

            assert_eq!(
                chain_names(&filter),
                vec!["SETUP"],
                "the whole subchain is discarded, not merely disconnected"
            );
            assert_eq!(filter.state(), SetupState::Init);
            assert!(!filter.base().is_connected());
            assert!(!filter.base().has_next());

            // Closed top-down, then destroyed front to back.
            assert_eq!(
                events(&log),
                vec![
                    "SSL:close",
                    "SOCKS:close",
                    "HAPPY-EYEBALLS:close",
                    "SSL:destroy",
                    "SOCKS:destroy",
                    "HAPPY-EYEBALLS:destroy",
                ]
            );

            // And it rebuilds from scratch, which is what the reset is for.
            assert!(filter.connect(cx).expect("no failure"));
            assert_eq!(
                chain_names(&filter),
                vec!["SETUP", "SSL", "SOCKS", "HAPPY-EYEBALLS"],
                "exactly one of each: a retained subchain would double them"
            );
            filter.destroy(cx);
        });
        // `[SETUP]`, not `[SETUP-0]`: `Tracer::assemble` appends the index
        // only when it is greater than zero, which is C's `CURL_TRC_CF`
        // rendering FIRSTSOCKET without a suffix.
        assert!(rendered.contains("[SETUP]"), "{rendered}");
        assert!(!rendered.contains("[SETUP-"), "{rendered}");
        assert!(rendered.contains("close"), "{rendered}");
        assert!(rendered.contains("destroy"), "{rendered}");
    }

    /// Required test 36 -- the four-parameter insert-after, and the position
    /// failure a chain index can express and a C pointer cannot.
    #[test]
    fn setup_can_be_inserted_below_a_named_position() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let log = new_log();
        let factories = Arc::new(TestFactories::new(&log));

        let mut chain =
            FilterChain::new(Some(ConnId::new(4)), SocketIndex::Secondary);
        chain.add(
            &mut cx,
            link(Marker::new("HTTPS-CONNECT", CF_TYPE_HTTP, 0, &log)),
        );

        cf_setup_insert_after(
            &mut cx,
            &mut chain,
            0,
            context(&factories),
            Transport::Quic,
            TlsMode::Enable,
        )
        .expect("position 0 resolves");

        assert_eq!(installed(&chain), vec!["HTTPS-CONNECT", "SETUP"]);
        let inserted = chain.nth_ref(1).expect("the SETUP filter");
        assert_eq!(
            inserted.base().sockindex(),
            SocketIndex::Secondary,
            "the whole-chain primitive stamps the socket index"
        );
        assert_eq!(inserted.base().conn(), Some(ConnId::new(4)));
        assert_eq!(inserted.cf_type(), CF_SETUP_FLAGS);

        // A position that does not resolve is reported, not asserted away.
        assert_eq!(
            cf_setup_insert_after(
                &mut cx,
                &mut chain,
                7,
                context(&factories),
                Transport::Tcp,
                TlsMode::Default,
            )
            .expect_err("position 7 is empty")
            .code(),
            CURLcode::BadFunctionArgument
        );

        // `cf_setup_add` puts it at the TOP instead.
        let mut top = FilterChain::new(None, SocketIndex::First);
        cf_setup_add(
            &mut cx,
            &mut top,
            context(&factories),
            Transport::Unix,
            TlsMode::Disable,
        );
        assert_eq!(installed(&top), vec!["SETUP"]);
        assert!(top.is_setup());
    }

    /// Required test 37 -- the HTTPS specialiser runs first, and the generic
    /// filter fills in only when it installed nothing.
    #[test]
    fn conn_setup_offers_https_first_and_falls_back_to_the_generic_filter() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let log = new_log();
        let https = SchemeSetup {
            is_https: true,
            transport_wanted: Transport::Tcp,
        };
        let plain = SchemeSetup {
            is_https: false,
            transport_wanted: Transport::Tcp,
        };

        // An https:// scheme whose specialiser installs a chain: the generic
        // filter must NOT be added on top of it.
        let specialising = Arc::new(
            TestFactories::new(&log).with_https_chain(&["HTTPS-CONNECT"]),
        );
        let resolved = SharedResolvedEntries::new();
        let mut chain = FilterChain::new(None, SocketIndex::First);
        conn_setup(
            &mut cx,
            &mut chain,
            &resolved,
            dns_entry(),
            https,
            context(&specialising),
            TlsMode::Enable,
        )
        .expect("the specialiser succeeds");
        assert_eq!(installed(&chain), vec!["HTTPS-CONNECT"]);
        assert!(events(&log).contains(&"build:HTTPS-SETUP".to_owned()));

        // An https:// scheme whose specialiser installs nothing -- a build with
        // no versions to race -- falls back to the generic filter.
        let inert = Arc::new(TestFactories::new(&log));
        let mut empty = FilterChain::new(None, SocketIndex::First);
        conn_setup(
            &mut cx,
            &mut empty,
            &resolved,
            dns_entry(),
            https,
            context(&inert),
            TlsMode::Enable,
        )
        .expect("the fallback succeeds");
        assert_eq!(installed(&empty), vec!["SETUP"]);

        // A non-https scheme is never offered to the specialiser at all.
        log.borrow_mut().clear();
        let mut direct = FilterChain::new(None, SocketIndex::First);
        conn_setup(
            &mut cx,
            &mut direct,
            &resolved,
            dns_entry(),
            plain,
            context(&inert),
            TlsMode::Default,
        )
        .expect("the generic install succeeds");
        assert_eq!(installed(&direct), vec!["SETUP"]);
        assert!(!events(&log).contains(&"build:HTTPS-SETUP".to_owned()));

        // Nor is a chain that already has filters, whatever its scheme.
        let mut occupied = FilterChain::new(None, SocketIndex::First);
        occupied
            .add(&mut cx, link(Marker::new("TCP", flags_of("TCP"), 0, &log)));
        log.borrow_mut().clear();
        conn_setup(
            &mut cx,
            &mut occupied,
            &resolved,
            dns_entry(),
            https,
            context(&inert),
            TlsMode::Enable,
        )
        .expect("nothing to do");
        assert_eq!(installed(&occupied), vec!["TCP"]);
        assert!(events(&log).is_empty(), "neither install may run");
    }

    // -- 38, 39, 40. resolver ownership, multiplexing, injection ------------

    /// Required test 38 -- the resolved entry is replaced on the way in and
    /// released on a failure, by ownership rather than by bookkeeping.
    #[test]
    fn conn_setup_replaces_the_resolved_entry_and_releases_it_on_failure() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let log = new_log();
        let https = SchemeSetup {
            is_https: true,
            transport_wanted: Transport::Tcp,
        };

        let resolved = SharedResolvedEntries::new();
        assert!(!resolved.has_resolved(SocketIndex::First));

        // A first, successful setup stores the entry.
        let inert = Arc::new(TestFactories::new(&log));
        let first = dns_entry();
        let mut chain = FilterChain::new(None, SocketIndex::First);
        conn_setup(
            &mut cx,
            &mut chain,
            &resolved,
            Arc::clone(&first),
            https,
            context(&inert),
            TlsMode::Enable,
        )
        .expect("the generic install succeeds");
        assert!(resolved.has_resolved(SocketIndex::First));
        resolved.with(|entries| {
            let held = entries.get(SocketIndex::First).expect("stored");
            assert!(Arc::ptr_eq(held, &first), "the entry itself, not a copy");
        });
        assert!(
            !resolved.has_resolved(SocketIndex::Secondary),
            "only the chain's own index is written"
        );

        // A second setup DISPLACES the first, and the displaced entry is
        // released -- the successor of `Curl_resolv_unlink` -- so the only
        // remaining owner is this test's own handle.
        let second = dns_entry();
        let mut again = FilterChain::new(None, SocketIndex::First);
        conn_setup(
            &mut cx,
            &mut again,
            &resolved,
            Arc::clone(&second),
            https,
            context(&inert),
            TlsMode::Enable,
        )
        .expect("the generic install succeeds");
        resolved.with(|entries| {
            let held = entries.get(SocketIndex::First).expect("stored");
            assert!(Arc::ptr_eq(held, &second));
        });
        assert_eq!(
            Arc::strong_count(&first),
            1,
            "the displaced entry was released"
        );

        // A FAILING setup releases the entry it had just stored, which is the
        // C's `out: if(result) Curl_resolv_unlink(...)`.
        let failing = Arc::new(
            TestFactories::new(&log)
                .failing("HTTPS-SETUP", CURLcode::OutOfMemory),
        );
        let third = dns_entry();
        let mut broken = FilterChain::new(None, SocketIndex::First);
        let error = conn_setup(
            &mut cx,
            &mut broken,
            &resolved,
            Arc::clone(&third),
            https,
            context(&failing),
            TlsMode::Enable,
        )
        .expect_err("the specialiser refuses");
        assert_eq!(error.code(), CURLcode::OutOfMemory);
        assert!(
            !resolved.has_resolved(SocketIndex::First),
            "the entry must not survive a failed setup"
        );
        assert_eq!(Arc::strong_count(&third), 1, "and it is released");
        assert!(broken.is_empty(), "and no chain is left half-built");

        // The storage itself: replace hands back what it displaced, release
        // hands back what it removed, and neither reaches the other index.
        let mut entries = ResolvedEntries::new();
        assert!(entries.replace(SocketIndex::First, dns_entry()).is_none());
        assert!(entries.replace(SocketIndex::First, dns_entry()).is_some());
        assert!(entries.get(SocketIndex::Secondary).is_none());
        assert!(entries.release(SocketIndex::Secondary).is_none());
        assert!(entries.release(SocketIndex::First).is_some());
        assert!(entries.release(SocketIndex::First).is_none());
    }

    /// The SETUP filter refuses to connect while nothing has been resolved, and
    /// it re-reads that fact on every pass rather than caching it.
    #[test]
    fn the_setup_machine_refuses_an_unresolved_chain_on_every_pass() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let log = new_log();
        let factories = Arc::new(TestFactories::new(&log));

        let context = SetupContext::new(
            Arc::clone(&factories) as Arc<dyn ConnectionFilterFactories>,
            FixedPresence::all(false) as Arc<dyn ResolvedPresence>,
        );
        let mut filter = setup(context, TlsMode::Default);

        for _ in 0..3 {
            let error = filter.connect(&mut cx).expect_err("no address");
            assert_eq!(error.code(), CURLcode::FailedInit);
        }
        assert_eq!(filter.state(), SetupState::Init, "nothing was built");
        assert!(events(&log).is_empty(), "no factory was reached");

        // The live handle is what makes the re-read meaningful: an entry stored
        // between passes is observed by the next one.
        let shared = Arc::new(SharedResolvedEntries::new());
        let live = SetupContext::new(
            Arc::clone(&factories) as Arc<dyn ConnectionFilterFactories>,
            Arc::clone(&shared) as Arc<dyn ResolvedPresence>,
        );
        let mut waiting = setup(live, TlsMode::Default);
        assert_eq!(
            waiting
                .connect(&mut cx)
                .expect_err("still unresolved")
                .code(),
            CURLcode::FailedInit
        );
        shared.with_mut(|entries| {
            drop(entries.replace(SocketIndex::First, dns_entry()));
        });
        assert!(
            waiting.connect(&mut cx).expect("now resolved"),
            "the filter re-reads the storage rather than a cached copy"
        );
    }

    /// Required test 39 -- multiplexing is a one-way latch that notifies once.
    #[test]
    fn conn_set_multiplex_is_a_latch_that_notifies_once() {
        let mut state = ConnectionState::new();
        let mut multi = TestMulti::default();

        assert!(!state.is_multiplex());
        assert!(conn_set_multiplex(&mut state, Some(&mut multi)));
        assert!(state.is_multiplex());
        assert_eq!(multi.changed, 1);

        // Repeated calls are no-ops, and in particular do NOT notify again --
        // an HTTP/2 connection serving many streams would otherwise force a scan
        // of every parked transfer per stream.
        for _ in 0..5 {
            assert!(!conn_set_multiplex(&mut state, Some(&mut multi)));
        }
        assert_eq!(multi.changed, 1);
        assert!(state.is_multiplex());

        // A connection not yet attached to a multi handle latches with no
        // notification at all, which is the C's `if(conn->attached_multi)`.
        let mut detached = ConnectionState::new();
        assert!(conn_set_multiplex(&mut detached, None));
        assert!(detached.is_multiplex());

        // The preference bit and the chain's capability are DIFFERENT questions:
        // `conncontrol` reads the chain and never this bit.
        let clock = clock();
        let log = new_log();
        let mut cx = CallCtx::new(&clock);
        let plain = chains_with(&mut cx, &log, "TCP", flags_of("TCP"));
        let mut latched = ConnectionState::new();
        assert!(conn_set_multiplex(&mut latched, None));
        conncontrol(&mut latched, &plain, ConnControl::Stream, "stream");
        assert!(
            latched.wants_close(),
            "the bit is set but the chain does not multiplex, so a stream \
             close closes the connection"
        );
    }

    /// Required test 40 -- no concrete TLS, proxy or protocol module is named
    /// here; every one of them arrives as an injected factory.
    ///
    /// The needles are assembled at run time so that this test's own source does
    /// not satisfy the searches it performs.
    #[test]
    fn no_concrete_tls_proxy_or_protocol_module_is_imported() {
        let here = include_str!("mod.rs");

        for module in ["tls", "proxy", "protocols", "multi", "transfer"] {
            let needle = format!("crate::{module}::");
            let offenders: Vec<&str> = here
                .lines()
                .filter(|line| line.contains(&needle))
                .filter(|line| {
                    let code = line.trim_start();
                    !code.starts_with("//") && !code.starts_with("///")
                })
                .collect();
            assert!(
                offenders.is_empty(),
                "crate::{module} must not be named in code: {offenders:?}"
            );
        }

        // The seams that replace them are all present and all injected.
        for seam in [
            "ConnectionFilterFactories",
            "ResolvedPresence",
            "ConnDiagnostics",
            "MultiOwnerNotify",
        ] {
            assert!(
                here.contains(&format!("{} {seam}", "trait")),
                "the {seam} seam must be declared here"
            );
        }
        for injected in [
            "happy_eyeballs",
            "socks_proxy",
            "proxy_tls",
            "http_proxy_tunnel",
            "haproxy",
            "origin_tls",
            "https_setup",
        ] {
            assert!(
                here.contains(&format!("{} {injected}(", "fn")),
                "the {injected} factory must be a trait method"
            );
        }

        // And the AAP's own negative gates, asserted from inside the file.
        // Each needle is assembled at run time, so this test's own source
        // cannot satisfy the search it is performing.
        for forbidden in [
            format!("li{}::", "bc"),
            format!("extern \"{}\"", "C"),
            format!("no_{}", "mangle"),
            format!("re{}(C)", "pr"),
            format!("Instant::{}", "now"),
            format!("SystemTime::{}", "now"),
        ] {
            assert!(
                !here.contains(&forbidden),
                "{forbidden} must not appear anywhere in this file"
            );
        }
        assert!(
            !here.contains(&format!("{} = \"tls\"", "feature")),
            "there is no Cargo feature named tls"
        );
        // The keyword AND the failure message are assembled at run time, so
        // neither the search nor its diagnostic can be what the search finds.
        //
        // Scanned over the WHOLE text rather than over code lines only, because
        // AAP 0.8.4's acceptance gate is a plain `grep` that cannot tell a
        // comment from a statement. Prose that merely NAMES the keyword would
        // fail that gate, so this file does not name it at all.
        let keyword = format!("un{}", "safe");
        assert!(
            !here.contains(&keyword),
            "no {keyword} may appear in this file, prose included"
        );
        let import = format!("crate::{}", "tls");
        assert!(
            !here.contains(&import),
            "{import} must not be named here, prose included: TLS is injected"
        );

        // The one seam the resolver occupies: injected, and never called.
        let handle = shared_clock(CurlTime::new(0, 0));
        let log = new_log();
        let factories = Arc::new(TestFactories::new(&log));
        let seams = ConnSeams::new(
            Arc::new(UnusedResolver),
            Arc::clone(&handle) as Arc<dyn Clock + Send + Sync>,
            Arc::new(TestExpiry::default()),
            Arc::clone(&factories) as Arc<dyn ConnectionFilterFactories>,
        );
        let _ = seams.resolver();
        // Assembled at run time, for the same reason as the gates above.
        let call = format!(".{}(", "resolve");
        assert!(
            !here.lines().any(|line| line.contains(&call)),
            "this module consumes resolved entries and never resolves them"
        );
    }

    /// The silent diagnostics sink discards without failing, which is what an
    /// admin handle and a test both need.
    #[test]
    fn the_silent_diagnostics_sink_discards_every_line() {
        let handle = shared_clock(CurlTime::new(0, 0));
        let mut timers = timers_at(&handle);
        let expiry = TestExpiry::default();
        let mut silent = SilentDiagnostics;

        shutdown_start(
            &mut timers,
            SocketIndex::First,
            100,
            TransferRole::Registered,
            &expiry,
            &mut silent,
        );
        assert!(timers.started(SocketIndex::First));
        assert_eq!(timers.timeout_ms(), 100);
        // The sink is defaultable, which is what lets an admin handle hold one
        // without naming it. Asserted through the BOUND rather than through
        // `SilentDiagnostics::default()`, because a unit struct's inherent
        // `default()` is a clippy lint and the bound is the real claim.
        fn defaulted<T: Default>() -> T {
            T::default()
        }
        assert_eq!(SilentDiagnostics, defaulted::<SilentDiagnostics>());
    }
}
