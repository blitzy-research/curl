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

//! Dual-stack connection racing -- "Happy Eyeballs".
//!
//! Supersedes `lib/cf-ip-happy.c` (982 lines) and `lib/cf-ip-happy.h`
//! (56 lines), with context from `lib/cf-socket.h`, `lib/vquic/vquic.h`,
//! `lib/urldata.h`, `lib/curl_trc.c`, `lib/connect.c`, `lib/cfilters.h` and
//! the public `CURL_IPRESOLVE_*` constants of `include/curl/curl.h`.
//!
//! The five regions of the C file map onto the five sections below:
//!
//! * `lib/cf-ip-happy.c:61-106` -- the `transport_providers[]` table,
//!   `get_cf_create()` and the `UNITTESTS`-only
//!   `Curl_debug_set_transport_provider()`, which become
//!   [`TransportProvider`] and [`TransportRegistry`].
//! * `:108-224` -- `struct cf_ai_iter` and `struct cf_ip_attempt`, which
//!   become [`AddrIter`] and [`IpAttempt`].
//! * `:227-532` -- `struct cf_ip_ballers` and `cf_ip_ballers_run()`, the race
//!   itself, which become [`Ballers`].
//! * `:535-683` -- shutdown, pollset, pending, the two query aggregations and
//!   `is_connected()`'s failure composition.
//! * `:694-982` -- `start_connect()`, the eleven `cf_ip_happy_*` callbacks and
//!   `struct Curl_cftype Curl_cft_ip_happy`, which become [`HappyEyeballs`]
//!   and its [`ConnFilter`] implementation.
//!
//! # What this filter owns, and what it hands over
//!
//! The contract of `cf_ip_connect_create` (`lib/cf-ip-happy.h:28-43`) is the
//! whole design in three sentences: a filter is created for ONE address, it
//! *"MUST use only the supplied `ai` for its connection attempt"*, its
//! `connect` *"needs to support non-blocking"*, and *"once connected, it MAY
//! be installed in the connection filter chain to serve transfers"*.
//!
//! So this filter owns a set of INDEPENDENT candidate subchains, one per
//! address it has decided to try. None of them is reachable from the main
//! chain: each lives in its own [`FilterChain`] inside its own [`IpAttempt`],
//! and a loser is destroyed there. The first candidate that reports connected
//! is UNLINKED from the race and its subchain is transferred into this
//! filter's own `next`, at which point the race is over and every remaining
//! candidate is torn down (`lib/cf-ip-happy.c:788-818`). That transfer is why
//! `Curl_cft_ip_happy` declares flags of exactly `0` (`:903-919`) and not
//! `CF_TYPE_IP_CONNECT`: this filter never provides an IP connection itself,
//! the winner it installs does.
//!
//! Two consequences follow, and both look like violations of the ordinary
//! filter contract until the subchains are accounted for:
//!
//! * [`ConnFilter::adjust_pollset`] drives EACH candidate subchain rather than
//!   passing the pollset to `next` (`:557-568`, `:748-759`). That does not
//!   contradict [`crate::conn::filters`]'s pure-no-op default; the outer walk
//!   simply cannot see filters it does not own.
//! * [`ConnFilter::close`] is DESTRUCTIVE (`:828-842`). A generic filter close
//!   clears state and leaves the chain installed; this one discards the
//!   installed winner outright, because the winner was chosen by a race that
//!   would have to be run again.
//!
//! # Everything time-dependent or platform-dependent is injected
//!
//! The clock arrives through [`CallCtx`], the transfer deadline through
//! [`Deadline`] -- which is already `Curl_timeleft_ms`'s seam and is reused
//! rather than duplicated -- the two `Curl_expire` calls through
//! [`ExpireScheduler`], the connection's own facts through [`ConnMeta`], and
//! the candidate filters through [`TransportProvider`]. Nothing here reads a
//! host clock, opens a socket, or resolves a name, which is what puts every
//! branch of the race within reach of a deterministic test.

use core::fmt;
use std::collections::VecDeque;
use std::rc::Rc;
use std::time::Duration;

use tokio::sync::Notify;

use crate::conn::filters::{
    discard_chain_from, link, CallCtx, CfQuery, CfQueryValue, CfType,
    ConnFilter, ConnId, FilterBase, FilterChain, FilterLink, SocketIndex,
    Transport, CURL_LOG_LVL_NONE,
};
use crate::conn::select::{EasyPollset, PollFds};
use crate::conn::socket::{
    cf_tcp_create, cf_unix_create, Deadline, SocketHooks, SocketSettings,
};
use crate::dns::{split_families, AddressFamily, IpVersion, ResolvedAddr};
use crate::error::{CURLcode, CurlResult, Error};
use crate::trace::{trc_cf, TimerId, TraceFilter};
use crate::util::timediff::{mstotv, TimeDiff};
use crate::util::timeval::{timediff_ms, timediff_us, CurlTime};

// =========================================================================
// Constants -- the ones that cross a boundary and must not drift
// =========================================================================

/// `CURL_IPRESOLVE_WHATEVER 0L` (`include/curl/curl.h:2299-2300`): every
/// address family the system allows.
///
/// The three `CURL_IPRESOLVE_*` integers are public ABI, and this file is the
/// one that consumes them as behaviour: `WHATEVER` keeps both address streams,
/// `V4` empties the IPv6 stream and `V6` empties the IPv4 one
/// (`lib/cf-ip-happy.c:307-342`). They are restated here as integers, next to
/// the code that races on them, and [`iprresolve_integers_match_ip_version`]
/// pins them against the checked enumeration [`IpVersion`] that carries them
/// through the engine -- so the two cannot disagree.
#[allow(dead_code)] // Consumed by curl-rs-ffi and easy/setopt.rs through IpVersion.
pub(crate) const CURL_IPRESOLVE_WHATEVER: i32 = 0;

/// `CURL_IPRESOLVE_V4 1L` (`include/curl/curl.h:2301`): IPv4 only.
#[allow(dead_code)] // See CURL_IPRESOLVE_WHATEVER.
pub(crate) const CURL_IPRESOLVE_V4: i32 = 1;

/// `CURL_IPRESOLVE_V6 2L` (`include/curl/curl.h:2302`): IPv6 only.
#[allow(dead_code)] // See CURL_IPRESOLVE_WHATEVER.
pub(crate) const CURL_IPRESOLVE_V6: i32 = 2;

/// `CURL_HET_DEFAULT 200L` (`include/curl/curl.h:967`): the default delay, in
/// milliseconds, before a second address family is tried.
///
/// **Zero is a valid configured value and does not mean "unset".** It means
/// the next attempt is eligible immediately, which
/// `curlx_ptimediff_ms(...) >= bs->attempt_delay_ms` accepts on its first
/// evaluation (`lib/cf-ip-happy.c:405-407`). Nothing in this module treats
/// zero as absent, and [`a_zero_delay_starts_the_next_attempt_at_once`]
/// proves it.
#[allow(dead_code)] // Consumed by easy/setopt.rs as the option default.
pub(crate) const CURL_HET_DEFAULT: TimeDiff = 200;

/// `EXPIRE_HAPPY_EYEBALLS_DNS`, index 5 of `expire_id`
/// (`lib/urldata.h:886-905`), named `"HAPPY_EYEBALLS_DNS"` at index 5 of
/// `Curl_trc_timer_names[]` (`lib/curl_trc.c:281-296`).
///
/// The resolver half of dual-stack racing. It is NOT armed here -- the C arms
/// it from the asynchronous resolver, as its own comment *"See asyn-ares.c"*
/// records -- and it is declared anyway because the two indices are adjacent
/// and index-aligned with their names. Pinning both is what stops a later
/// insertion into `expire_id` from silently renaming this module's timer;
/// [`timer_identities_are_index_aligned_with_their_names`] asserts the
/// alignment against [`TimerId`].
#[allow(dead_code)] // Declared to pin the index; armed by dns/resolver.rs.
pub(crate) const EXPIRE_HAPPY_EYEBALLS_DNS: u8 = 5;

/// `EXPIRE_HAPPY_EYEBALLS`, index 6 of `expire_id` (`lib/urldata.h:887-903`),
/// named `"HAPPY_EYEBALLS"` at index 6 of `Curl_trc_timer_names[]`.
///
/// The connect half, and the one timer this module arms. Note the spelling:
/// the timer has UNDERSCORES while the filter of nearly the same name is
/// hyphenated (`"HAPPY-EYEBALLS"`, [`HAPPY_EYEBALLS_FILTER_NAME`]). Both
/// strings reach trace output, so neither may be regularised.
pub(crate) const EXPIRE_HAPPY_EYEBALLS: u8 = 6;

// The two indices, proven against the enumeration that carries them, AT COMPILE
// TIME rather than in a test. `crate::trace::TimerId` is `#[repr(u8)]` with every
// discriminant written out, and it is what this module actually passes to
// `Curl_expire`; these two assertions are what make the integers above and the
// identities below the same fact. A renumbering of `expire_id` fails the build
// here instead of silently arming the wrong timer.
const _: () =
    assert!(EXPIRE_HAPPY_EYEBALLS_DNS == TimerId::HappyEyeballsDns as u8);
const _: () = assert!(EXPIRE_HAPPY_EYEBALLS == TimerId::HappyEyeballs as u8);

/// The one timer this filter arms, selected BY ITS `expire_id` INDEX.
///
/// Every `Curl_expire`/`Curl_expire_done` call in this module goes through
/// this constant rather than naming [`TimerId::HappyEyeballs`] directly, which
/// makes the index from `lib/urldata.h:887-903` the thing that CHOOSES the
/// identity instead of merely being checked against it. That is strictly
/// stronger than the assertion above: the two cannot disagree by construction,
/// so a renumbering of `expire_id` cannot leave this module arming a timer the
/// C does not. The assertion is retained because it is what proves
/// [`TimerId::ALL`] is index-aligned with the discriminants, which is the
/// premise this derivation rests on, and
/// [`timer_identities_are_index_aligned_with_their_names`] pins the names to
/// the same indices.
const HAPPY_EYEBALLS_TIMER: TimerId =
    TimerId::ALL[EXPIRE_HAPPY_EYEBALLS as usize];

/// The `name` member of `Curl_cft_ip_happy` (`lib/cf-ip-happy.c:904`).
///
/// The label `--trace-config` matches and every trace line from this filter
/// prints. Hyphenated; see [`EXPIRE_HAPPY_EYEBALLS`].
pub(crate) const HAPPY_EYEBALLS_FILTER_NAME: &str = "HAPPY-EYEBALLS";

/// The `log_level` member of `Curl_cft_ip_happy` (`lib/cf-ip-happy.c:906`).
///
/// `CURL_LOG_LVL_NONE`. The level lives in [`crate::trace::TraceConfig`] here
/// rather than on the filter type, so this constant exists to record what the
/// C declares and to let [`the_filter_identity_matches_the_c_table`] assert
/// it.
#[allow(dead_code)] // Asserted by the identity test; the level lives in TraceConfig.
pub(crate) const HAPPY_EYEBALLS_LOG_LEVEL: i32 = CURL_LOG_LVL_NONE;

/// One filter-attributed trace line -- `CURL_TRC_CF`.
///
/// [`crate::conn::filters`] has an identical private wrapper, and it is
/// private, so this module carries its own rather than reaching for it. The
/// three conditions [`trc_cf`] needs are the same as there: a tracer on the
/// transfer, a registered identity for the filter, and a verbose level for
/// that identity.
macro_rules! trc {
    (
        $cx:expr, $filter:expr, $sockindex:expr,
        $fmt:literal $(, $arg:expr)* $(,)?
    ) => {{
        let identity: Option<TraceFilter> = $filter;
        let sockindex: i32 = $sockindex;
        if let Some(identity) = identity {
            if let Some(tracer) = $cx.tracer_mut() {
                trc_cf!(tracer, identity, sockindex, $fmt $(, $arg)*);
            }
        }
    }};
}

// =========================================================================
// The transport providers -- `transport_providers[]` and `get_cf_create()`
// =========================================================================

/// Creates the filter that makes one "ip" connection.
///
/// The successor of the `cf_ip_connect_create` function type
/// (`lib/cf-ip-happy.h:28-43`), whose documented contract this trait inherits
/// in full:
///
/// * The connection *"can be a TCP socket, a UDP socket or even a QUIC
///   connection"*, so the returned value is an ordinary [`FilterLink`] and may
///   be a MULTI-NODE subchain -- which is what a QUIC provider returns.
/// * *"It MUST use only the supplied `ai` for its connection attempt."* One
///   address, not a list: the race owns the choice of address, and a provider
///   that fell back to a second one would run a second, invisible race.
/// * *"Its `connect` implementation needs to support non-blocking"*, which is
///   [`ConnFilter::connect`]'s `Ok(false)` and is how the whole race works.
/// * *"Once connected, it MAY be installed in the connection filter chain to
///   serve transfers"*, which is [`HappyEyeballs`]'s winner transfer.
///
/// The returned link is UNATTACHED: it carries no connection identity and no
/// socket index yet. [`IpAttempt::new`] stamps both onto every node of it,
/// which is the `for(wcf = a->cf; wcf; wcf = wcf->next)` walk of
/// `lib/cf-ip-happy.c:213-217`.
pub(crate) trait TransportProvider: fmt::Debug {
    /// Builds an unattached candidate for `addr`.
    ///
    /// # Errors
    ///
    /// Whatever the transport's own creation reports. The C's
    /// `CURLE_OUT_OF_MEMORY` has no successor, because a failure to allocate
    /// aborts rather than returning a code.
    fn create(
        &self,
        addr: &ResolvedAddr,
        sockindex: SocketIndex,
    ) -> CurlResult<FilterLink>;
}

/// One row of `transport_providers[]` (`lib/cf-ip-happy.c:60-63`).
///
/// The provider is an [`Option`] so that a row can EXIST while being unfilled,
/// which is the shape the QUIC row needs -- see [`TransportRegistry::sockets`].
#[derive(Debug)]
struct TransportSlot {
    /// The `transport` member.
    transport: Transport,
    /// The `cf_create` member, absent while no provider has been installed.
    provider: Option<Rc<dyn TransportProvider>>,
}

/// The `transport_providers[]` table, injected rather than global.
///
/// C keeps the table as a file-scope array that is `const` in a release build
/// and MUTABLE under `UNITTESTS`, so that `unit2600.c` can substitute a fake
/// transport through `Curl_debug_set_transport_provider()`
/// (`lib/cf-ip-happy.c:89-103`). That seam is load-bearing -- it is the only
/// way the race can be tested without a network -- and process-global mutable
/// state is the wrong way to have it. Here the table is an ordinary value that
/// the filter is CONSTRUCTED with, so a test substitutes a provider by building
/// its own registry and nothing global changes.
///
/// # Which rows exist, and why UDP is not one of them
///
/// The C's table is gated by three preprocessor conditions:
///
/// ```c
/// { TRNSPRT_TCP, Curl_cf_tcp_create },
/// #if !defined(CURL_DISABLE_HTTP) && defined(USE_HTTP3)
///   { TRNSPRT_QUIC, Curl_cf_quic_create },
/// #endif
/// #ifndef CURL_DISABLE_TFTP
///   { TRNSPRT_UDP, Curl_cf_udp_create },
/// #endif
/// #ifdef USE_UNIX_SOCKETS
///   { TRNSPRT_UNIX, Curl_cf_unix_create },
/// #endif
/// ```
///
/// * TCP is unconditional here as it is there.
/// * QUIC's row exists exactly when the `http3` feature is on, which is this
///   build's `USE_HTTP3`. It is UNFILLED, because `Curl_cf_quic_create` builds
///   one filter carrying the whole QUIC and HTTP/3 stack
///   (`lib/vquic/vquic.h:48`) and that stack is not this module's to build.
///   `crate::protocols::http3` installs it by implementing
///   [`TransportProvider`], which is why the row must exist to be filled.
/// * UNIX's row exists on a Unix target, which is this build's
///   `USE_UNIX_SOCKETS`. All four mandated targets are Unix.
/// * **UDP has no row at all.** The C gates it on `!CURL_DISABLE_TFTP` and TFTP
///   is out of implementation scope, so advertising a generic UDP transport
///   here would offer a transport with no protocol above it to use it. QUIC is
///   a separate row and does not depend on this one.
///   [`no_udp_provider_is_advertised`] pins the absence.
#[derive(Debug, Default)]
pub(crate) struct TransportRegistry {
    /// The rows, in the C's declaration order.
    slots: Vec<TransportSlot>,
}

impl TransportRegistry {
    /// An empty table, for a caller that installs every provider itself.
    #[allow(dead_code)] // No consumer yet; used by tests and by protocols/.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Appends a row, or replaces one that already exists.
    ///
    /// The C's table is a `static` initialiser with no run-time equivalent, so
    /// this is the builder for writing one. It is distinct from
    /// [`Self::set_provider`], which is `Curl_debug_set_transport_provider` and
    /// deliberately CANNOT add a row -- a substitution that silently invented a
    /// transport would defeat the purpose of the gate in
    /// [`no_udp_provider_is_advertised`].
    #[allow(dead_code)] // No consumer yet; used by tests and by bespoke tables.
    #[must_use]
    pub(crate) fn with_row(
        mut self,
        transport: Transport,
        provider: Rc<dyn TransportProvider>,
    ) -> Self {
        if !self.set_provider(transport, Rc::clone(&provider)) {
            self.slots.push(TransportSlot {
                transport,
                provider: Some(provider),
            });
        }
        self
    }

    /// The table `transport_providers[]` declares, over the real transports of
    /// [`crate::conn::socket`].
    ///
    /// `hooks` and `settings` are the two bundles every socket filter is built
    /// with; they are cloned per candidate, which is correct and not merely
    /// convenient -- each attempt gets its own socket and must not share the
    /// mutable state of another's.
    #[allow(dead_code)] // No consumer yet; conn/mod.rs builds the chain with it.
    pub(crate) fn sockets(
        hooks: SocketHooks,
        settings: SocketSettings,
    ) -> Self {
        // `{ TRNSPRT_TCP, Curl_cf_tcp_create }` -- unconditional.
        let tcp = TransportSlot {
            transport: Transport::Tcp,
            provider: Some(Rc::new(SocketProvider {
                transport: Transport::Tcp,
                hooks: hooks.clone(),
                settings: settings.clone(),
            })),
        };

        // The two conditional rows are built by functions with two bodies each,
        // rather than by `#[cfg]`-gated pushes, so that the row set is one
        // expression on every target and no local is conditionally mutable.
        let rows = [Some(tcp), quic_row(), unix_row(hooks, settings)];
        Self {
            slots: rows.into_iter().flatten().collect(),
        }
    }

    /// `Curl_debug_set_transport_provider` (`lib/cf-ip-happy.c:89-103`):
    /// replaces the provider of an EXISTING row.
    ///
    /// Reports whether a row was found. The C returns `void` and silently does
    /// nothing for a transport that is not in the table -- its loop simply
    /// finds no match -- so this reports the same outcome without changing it,
    /// and a test can then assert that a UDP substitution really is refused.
    #[allow(dead_code)] // No consumer yet; protocols/http3.rs installs QUIC with it.
    pub(crate) fn set_provider(
        &mut self,
        transport: Transport,
        provider: Rc<dyn TransportProvider>,
    ) -> bool {
        for slot in &mut self.slots {
            if slot.transport == transport {
                slot.provider = Some(provider);
                return true;
            }
        }
        false
    }

    /// `get_cf_create` (`lib/cf-ip-happy.c:80-88`): the provider for
    /// `transport`, or [`None`].
    ///
    /// [`None`] covers both of the C's ways of having no provider: a transport
    /// with no row, and -- new here -- a row whose provider has not been
    /// installed. Both mean the same thing to the caller, which turns them into
    /// [`CURLcode::UnsupportedProtocol`].
    pub(crate) fn provider(
        &self,
        transport: Transport,
    ) -> Option<Rc<dyn TransportProvider>> {
        self.slots
            .iter()
            .find(|slot| slot.transport == transport)
            .and_then(|slot| slot.provider.clone())
    }

    /// True when a row for `transport` exists, filled or not.
    ///
    /// Distinct from [`Self::provider`] on purpose: an unfilled QUIC row is a
    /// transport this build KNOWS about and cannot yet serve, which is a
    /// different fact from UDP, which it does not know about at all.
    #[allow(dead_code)] // No consumer yet; read by tests and by protocols/http3.rs.
    pub(crate) fn has_row(&self, transport: Transport) -> bool {
        self.slots.iter().any(|slot| slot.transport == transport)
    }
}

/// A provider over one of [`crate::conn::socket`]'s factories.
///
/// The three C functions the table names -- `Curl_cf_tcp_create`,
/// `Curl_cf_udp_create` and `Curl_cf_unix_create` -- differ only in which
/// factory they call, so one type carries the transport and dispatches. Each
/// candidate is built with its OWN clone of the hooks and settings.
#[derive(Debug)]
struct SocketProvider {
    /// Which factory to call. Set at construction and never changed, so a
    /// provider cannot answer for a transport it was not registered under.
    transport: Transport,
    /// The seams a socket filter holds.
    hooks: SocketHooks,
    /// The `data->set` members a socket filter reads.
    settings: SocketSettings,
}

/// `#if !defined(CURL_DISABLE_HTTP) && defined(USE_HTTP3) { TRNSPRT_QUIC,
/// Curl_cf_quic_create }` (`lib/cf-ip-happy.c:69-71`).
///
/// The row exists and is UNFILLED; see [`TransportRegistry`] for why the QUIC
/// provider cannot be built here and who installs it.
#[cfg(feature = "http3")]
fn quic_row() -> Option<TransportSlot> {
    Some(TransportSlot {
        transport: Transport::Quic,
        provider: None,
    })
}

/// No QUIC row at all when the `http3` feature is off, which is the C's
/// `#endif` -- a `quic://`-carrying scheme then fails with
/// [`CURLcode::UnsupportedProtocol`] exactly as it does in a build without
/// `USE_HTTP3`.
#[cfg(not(feature = "http3"))]
fn quic_row() -> Option<TransportSlot> {
    None
}

/// `#ifdef USE_UNIX_SOCKETS { TRNSPRT_UNIX, Curl_cf_unix_create }`
/// (`lib/cf-ip-happy.c:75-77`).
#[cfg(unix)]
fn unix_row(
    hooks: SocketHooks,
    settings: SocketSettings,
) -> Option<TransportSlot> {
    Some(TransportSlot {
        transport: Transport::Unix,
        provider: Some(Rc::new(SocketProvider {
            transport: Transport::Unix,
            hooks,
            settings,
        })),
    })
}

/// No Unix row on a target without Unix domain sockets. Unreachable on all four
/// mandated targets, which are Unix.
#[cfg(not(unix))]
fn unix_row(
    _hooks: SocketHooks,
    _settings: SocketSettings,
) -> Option<TransportSlot> {
    None
}

impl TransportProvider for SocketProvider {
    fn create(
        &self,
        addr: &ResolvedAddr,
        sockindex: SocketIndex,
    ) -> CurlResult<FilterLink> {
        match self.transport {
            Transport::Tcp => {
                let filter = cf_tcp_create(
                    addr,
                    self.hooks.clone(),
                    self.settings.clone(),
                    sockindex,
                )
                .map_err(Error::from)?;
                Ok(link(filter))
            }
            #[cfg(unix)]
            Transport::Unix => {
                let filter = cf_unix_create(
                    addr,
                    self.hooks.clone(),
                    self.settings.clone(),
                    sockindex,
                )
                .map_err(Error::from)?;
                Ok(link(filter))
            }
            // Unreachable through [`TransportRegistry::sockets`], which builds
            // a provider only for the transports above. Reported rather than
            // asserted, because a panic here would take a live transfer down
            // and the code is exactly the one the registry would have produced
            // for a transport it has no row for.
            _ => Err(Error::with_context(
                CURLcode::UnsupportedProtocol,
                "no socket factory for this transport",
            )),
        }
    }
}

// =========================================================================
// The two remaining injected seams
// =========================================================================

/// The two `Curl_expire` calls this module makes.
///
/// C reaches the multi handle's timer set through
/// `Curl_expire(data, ms, EXPIRE_HAPPY_EYEBALLS)` (`lib/cf-ip-happy.c:479`,
/// `:529`) and clears it with
/// `Curl_expire_done(data, EXPIRE_HAPPY_EYEBALLS)` (`:795`). Both are
/// multi-handle operations, and `crate::multi` must not be named from
/// `conn/`, so they arrive as a seam -- the same arrangement
/// [`crate::conn::shutdown`] uses for `EXPIRE_SHUTDOWN`.
///
/// Both methods take `&self`: the filter holds this behind an [`Rc`] alongside
/// the connection, so shared access with interior mutability is the shape the
/// ownership graph permits.
pub(crate) trait ExpireScheduler: fmt::Debug {
    /// `Curl_expire(data, timeout_ms, timer)`: arm `timer` to fire in
    /// `timeout_ms` milliseconds.
    fn expire(&self, timeout_ms: TimeDiff, timer: TimerId);

    /// `Curl_expire_done(data, timer)`: disarm `timer`.
    fn expire_done(&self, timer: TimerId);
}

/// The connection and transfer facts this module reads.
///
/// The successor of every `cf->conn->...` and `data->...` read in
/// `lib/cf-ip-happy.c`, enumerated rather than summarised so that a reviewer
/// can check the list against the C. A back pointer is the one thing a safe
/// ownership graph cannot reproduce -- the connection owns the chain, so the
/// chain cannot own the connection -- so the facts travel as a seam, exactly as
/// [`crate::conn::socket::ConnState`] does for the socket filter.
///
/// The readings are DELIBERATELY RAW. `is_connected()` composes its failure
/// message from three separate decisions -- which hostname, which port, which
/// proxy -- and those decisions belong to this module, because the message they
/// build is frozen output. An implementor that pre-decided them could not be
/// checked against `lib/cf-ip-happy.c:637-676`.
pub(crate) trait ConnMeta: fmt::Debug {
    /// `cf->conn->ip_version` (`lib/cf-ip-happy.c:721`), one of the three
    /// `CURL_IPRESOLVE_*` values.
    fn ip_version(&self) -> IpVersion;

    /// `data->set.happy_eyeballs_timeout` (`:723`), in milliseconds.
    ///
    /// Zero is valid and means "immediately eligible"; see
    /// [`CURL_HET_DEFAULT`].
    fn happy_eyeballs_timeout_ms(&self) -> TimeDiff;

    /// `data->state.dns[cf->sockindex]->addr` (`:702-705`), in the order the
    /// resolver produced it.
    ///
    /// [`None`] is C's `if(!dns)`, which is [`CURLcode::FailedInit`].
    ///
    /// **The order is behaviour.** Nothing in this module sorts, deduplicates
    /// or normalises the list: a resolver's ordering within a family encodes
    /// the host's address-selection policy, and a race that reordered it would
    /// connect to a different address than curl does.
    fn resolved(&self, sockindex: SocketIndex) -> Option<Vec<ResolvedAddr>>;

    /// `conn->host.name` (`:653-654`).
    fn host_name(&self) -> String;

    /// `conn->conn_to_host.name`, present exactly when
    /// `conn->bits.conn_to_host` is set (`:653-654`).
    fn connect_to_host(&self) -> Option<String>;

    /// `conn->unix_domain_socket` (`:657-661`), absent when this is not a Unix
    /// domain connection.
    fn unix_socket_path(&self) -> Option<String>;

    /// `conn->secondary_port` (`:666-667`), the port of the SECOND socket.
    fn secondary_port(&self) -> u16;

    /// `conn->conn_to_port`, present exactly when `conn->bits.conn_to_port` is
    /// set (`:668-669`).
    fn connect_to_port(&self) -> Option<u16>;

    /// `conn->remote_port` (`:670-671`).
    fn remote_port(&self) -> u16;

    /// `conn->socks_proxy.host.name`, present exactly when
    /// `conn->bits.socksproxy` is set (`:645-646`).
    fn socks_proxy_name(&self) -> Option<String>;

    /// `conn->http_proxy.host.name`, present exactly when
    /// `conn->bits.httpproxy` is set (`:647-648`).
    fn http_proxy_name(&self) -> Option<String>;

    /// `cf->conn->scheme->protocol & PROTO_FAMILY_SSH` (`:801`).
    ///
    /// True for SFTP and SCP, which are connected at application level the
    /// moment the transport is.
    fn is_ssh_family(&self) -> bool;

    /// `SOCKETIMEDOUT == data->state.os_errno` (`:686-688`).
    ///
    /// A PREDICATE rather than the integer, because `SOCKETIMEDOUT` is
    /// `WSAETIMEDOUT` on Windows and `ETIMEDOUT` elsewhere
    /// (`lib/curl_setup.h:1111`, `:1128`) and this file may not name a
    /// platform errno -- the engine speaks in fixed-width Rust integers and
    /// leaves the C widths and the platform constants to
    /// `curl-rs-lib/src/ffi/`. The comparison itself is one line in the
    /// implementor and the DECISION it feeds stays here.
    fn os_error_is_timeout(&self) -> bool;

    /// `data->progress.t_startsingle` (`:678`, `:502`): when the current single
    /// request began, which both elapsed-time messages measure from.
    fn transfer_started_at(&self) -> CurlTime;

    /// `data->info.numconnects++` (`:818`): *"to track the # of connections
    /// made"*.
    fn note_connection(&self);

    /// `Curl_pgrsTime(data, TIMER_APPCONNECT)` (`:802`), for the SSH family
    /// only -- *"we are connected already"*.
    fn mark_app_connect_time(&self);
}

// =========================================================================
// Address iteration -- `struct cf_ai_iter`
// =========================================================================

/// One family's addresses, walked once.
///
/// The successor of `struct cf_ai_iter` (`lib/cf-ip-happy.c:105-157`). C walks
/// the single `ai_next` list twice with a different `ai_family` test each time,
/// keeping `head`, `last` and a counter `n` whose `-1` means "not started"; the
/// list is shared, so neither iterator owns anything.
///
/// Here the two families are separated ONCE, by
/// [`crate::dns::split_families`], and each iterator owns its own vector with a
/// plain index. That is not merely tidier: the C's `last` pointer is into a
/// list owned by the DNS cache entry, so its validity depends on that entry
/// outliving the race.
///
/// The three operations the race needs are exactly the C's three:
///
/// * [`Self::started`] -- the `n < 0` test.
/// * [`Self::next_addr`] -- advance and yield, or yield nothing for ever after.
/// * [`Self::has_more`] -- whether a further address exists, **without moving
///   the cursor**. That is load-bearing: the race consults it to decide whether
///   to alternate families and whether to arm a timer, both of which must not
///   consume an address.
///
/// The vector is never sorted and never deduplicated; see
/// [`ConnMeta::resolved`].
#[derive(Clone, Debug)]
struct AddrIter {
    /// The addresses of this family, in resolver order.
    addrs: Vec<ResolvedAddr>,
    /// The `ai_family` member. Retained even when [`Self::addrs`] is empty,
    /// because the race reads it to label the attempt it is about to start:
    /// `ai_family = bs->ipv6_iter.ai_family` (`lib/cf-ip-happy.c:423`) runs
    /// whether or not the iterator produced anything.
    family: AddressFamily,
    /// How many addresses have been yielded, which doubles as the C's `n`: zero
    /// is "not started" and [`Self::addrs`]'s length is "exhausted".
    yielded: usize,
}

impl AddrIter {
    /// `cf_ai_iter_init` over a family's own list.
    fn new(addrs: Vec<ResolvedAddr>, family: AddressFamily) -> Self {
        Self {
            addrs,
            family,
            yielded: 0,
        }
    }

    /// `cf_ai_iter_init(iter, NULL, family)`: an iterator that yields nothing
    /// but still names its family.
    ///
    /// This is how the C suppresses a family: `CURL_IPRESOLVE_V6` initialises
    /// the IPv4 iterator over `NULL` rather than skipping it
    /// (`lib/cf-ip-happy.c:325-328`), so every later `has_more` and `next` on
    /// it is well defined and answers "nothing".
    fn empty(family: AddressFamily) -> Self {
        Self::new(Vec::new(), family)
    }

    /// The `iter->n < 0` test: has anything been yielded yet?
    ///
    /// C needs the distinction because its `has_more` has to know whether to
    /// look from `head` or from `last->ai_next`; over an owned vector with an
    /// index both collapse into one comparison, so nothing in the race consults
    /// this. It is part of the iterator's contract all the same, and
    /// [`the_address_iterator_reproduces_the_c_cursor`] asserts it.
    #[allow(dead_code)] // Read by tests; folded into the index comparison here.
    fn started(&self) -> bool {
        self.yielded > 0
    }

    /// `cf_ai_iter_next`: the next address of this family.
    ///
    /// NOT named `next`, deliberately: this type is not an [`Iterator`] --
    /// [`Self::has_more`] and [`Self::started`] have no counterpart there, and
    /// a borrowing `Iterator::next` would conflict with the race's need to
    /// mutate the attempt list in the same statement.
    ///
    /// Cloned rather than borrowed for that same reason. The clone is what the
    /// attempt then owns, which removes the C's dependency on the DNS entry
    /// outliving the race.
    fn next_addr(&mut self) -> Option<ResolvedAddr> {
        let addr = self.addrs.get(self.yielded)?;
        let addr = addr.clone();
        self.yielded += 1;
        Some(addr)
    }

    /// `cf_ai_iter_has_more`: is there a further address, without advancing?
    ///
    /// The C's three cases collapse to one comparison over a pre-filtered
    /// vector: "not started" looks from the head, "in progress" looks past
    /// `last`, and "exhausted" answers `FALSE` because `last` is `NULL` and `n`
    /// is no longer negative.
    fn has_more(&self) -> bool {
        self.yielded < self.addrs.len()
    }
}

// =========================================================================
// What the C reaches through `cf` -- bundled once
// =========================================================================

/// The facts and seams the race needs, gathered off the filter.
///
/// C passes `struct Curl_cfilter *cf` into every baller function and reads
/// `cf->conn`, `cf->sockindex` and `cf->cft` out of it. Here the race is a
/// separate value ([`Ballers`]) owned BY the filter, so it cannot borrow the
/// filter while the filter borrows it mutably. Handing it this bundle -- with
/// the three seams as [`Rc`] clones rather than references -- resolves the
/// borrow without copying anything that matters.
#[derive(Debug)]
struct RaceCtx {
    /// `cf->sockindex`, stamped onto every candidate node.
    sockindex: SocketIndex,
    /// `cf->conn`, likewise.
    conn: Option<ConnId>,
    /// `cf->cft`'s trace identity, for `CURL_TRC_CF`.
    identity: Option<TraceFilter>,
    /// The connection's own facts.
    meta: Rc<dyn ConnMeta>,
    /// `Curl_timeleft_ms(data)`.
    deadline: Rc<dyn Deadline>,
    /// `Curl_expire` and `Curl_expire_done`.
    expiry: Rc<dyn ExpireScheduler>,
}

impl RaceCtx {
    /// `cf->sockindex` as the integer a trace line prints.
    fn sockidx(&self) -> i32 {
        self.sockindex.as_i32()
    }
}

// =========================================================================
// One candidate -- `struct cf_ip_attempt`
// =========================================================================

/// One address being tried, with the subchain trying it.
///
/// The successor of `struct cf_ip_attempt` (`lib/cf-ip-happy.c:159-173`). Two
/// members change shape and the rest are transcribed:
///
/// * `struct cf_ip_attempt *next` disappears. The attempts live in a
///   [`VecDeque`] on [`Ballers`], so the list is owned rather than intrusive
///   and an attempt cannot be reachable from two places at once.
/// * `struct Curl_cfilter *cf` becomes an owned [`FilterChain`]. That is what
///   makes the subchain PRIVATE: the chain is created with this connection's
///   identity and socket index, it stamps them onto every node it installs, and
///   dropping the attempt tears the whole subchain down front to back through
///   [`FilterChain::discard_chain`]. No candidate socket can leak, be closed
///   twice, or become reachable from the main chain before it wins.
/// * `const struct Curl_addrinfo *addr` -- *"List of addresses to try, not
///   owned"* -- becomes an owned clone. The comment's plural is a leftover: the
///   contract of `cf_ip_connect_create` is one address, and the C only ever
///   passes the single entry the iterator produced.
#[derive(Debug)]
struct IpAttempt {
    /// The one address this candidate may use.
    addr: ResolvedAddr,
    /// The candidate's private subchain, possibly several filters deep.
    chain: FilterChain,
    /// `cf_create`, retained because a restart builds a REPLACEMENT filter.
    provider: Rc<dyn TransportProvider>,
    /// `struct curltime started; /* start of current attempt */`.
    ///
    /// C declares this member and never assigns it -- nothing in
    /// `lib/cf-ip-happy.c` reads or writes `a->started`, the race timing all
    /// hanging off `bs->last_attempt_started` instead. It is kept, and here it
    /// is actually set, so the field is truthful rather than misleading; no
    /// decision depends on it, so setting it changes nothing observable.
    #[allow(dead_code)]
    // Read by tests; C declares the member and never assigns it.
    started: CurlTime,
    /// `CURLcode result`, with [`CURLcode::Ok`] meaning "still running".
    ///
    /// A code rather than an [`Error`], because that is exactly what the C
    /// keeps and what the final message needs: the failure line renders
    /// `curl_easy_strerror(result)` (`:682`), the GENERIC string for the code,
    /// and any specific line a candidate wrote was already cleared by
    /// `Curl_reset_fail` before the next attempt started.
    result: CURLcode,
    /// `int ai_family`.
    ///
    /// Written and never read, in the C as here: the alternation reads
    /// `bs->last_attempt_ai_family`, which the race records separately, and no
    /// decision consults the family of an individual candidate. Kept because the
    /// C keeps it and because a test can then check that a candidate was started
    /// for the family the race intended.
    #[allow(dead_code)]
    // Read by tests; C declares the member and only writes it.
    family: AddressFamily,
    /// `uint8_t transport`.
    #[allow(dead_code)]
    // Read by tests; the C keeps it for the restart path.
    transport: Transport,
    /// `int error`, the operating-system error of this candidate.
    ///
    /// C declares this member and never assigns it either -- the OS error a
    /// failure reports travels on `data->state.os_errno`, which is
    /// [`ConnMeta::os_error_is_timeout`]. Kept for the same reason as
    /// [`Self::started`].
    #[allow(dead_code)]
    // Read by tests; C declares the member and never assigns it.
    os_error: i32,
    /// `BIT(connected)` -- *"cf has connected"*.
    connected: bool,
    /// `BIT(shutdown)` -- *"cf has shutdown"*.
    shut_down: bool,
    /// `BIT(inconclusive)` -- *"connect was not a hard failure, we might talk to
    /// a restarting server"*.
    inconclusive: bool,
}

impl IpAttempt {
    /// `cf_ip_attempt_new` (`lib/cf-ip-happy.c:185-224`).
    ///
    /// The provider builds an unattached candidate and it is then installed
    /// into this attempt's own chain, which stamps the connection identity and
    /// socket index onto EVERY node -- the C's *"the new filter might have
    /// sub-filters"* walk at `:213-217`. A node left holding a stale identity
    /// would report the wrong socket index in every trace line it emits, and a
    /// multi-node QUIC candidate is the ordinary case rather than a corner one.
    ///
    /// # Errors
    ///
    /// Whatever the provider reports. The C frees the half-built attempt on
    /// that path (`:220-223`); here there is nothing to free, because the
    /// attempt is not constructed until the candidate exists.
    fn new(
        cx: &mut CallCtx<'_, '_>,
        rc: &RaceCtx,
        addr: ResolvedAddr,
        family: AddressFamily,
        transport: Transport,
        provider: Rc<dyn TransportProvider>,
    ) -> CurlResult<Self> {
        let head = provider.create(&addr, rc.sockindex)?;
        let mut chain = FilterChain::new(rc.conn, rc.sockindex);
        // `for(wcf = a->cf; wcf; wcf = wcf->next) { wcf->conn = cf->conn;
        //  wcf->sockindex = cf->sockindex; }` -- `set_chain` restamps the whole
        // subchain, which is why the walk needs no counterpart here.
        chain.set_chain(Some(head));
        Ok(Self {
            addr,
            chain,
            provider,
            started: cx.now(),
            result: CURLcode::Ok,
            family,
            transport,
            os_error: 0,
            connected: false,
            shut_down: false,
            inconclusive: false,
        })
    }

    /// `cf_ip_attempt_connect` (`lib/cf-ip-happy.c:227-244`): one non-blocking
    /// step, reporting whether this candidate is now connected.
    ///
    /// Three properties are transcribed exactly:
    ///
    /// * A candidate that has already failed or already connected is NOT
    ///   stepped again -- `if(!a->result && !*connected)`.
    /// * [`CURLcode::WeirdServerReply`] sets [`Self::inconclusive`] *"failed,
    ///   but inconclusive"*. It is not a hard terminal failure: the comment on
    ///   the flag is *"we might talk to a restarting server"*, and
    ///   [`Ballers`] gives such a candidate another go once every address has
    ///   been tried. The result is still recorded, because the C's `else if` is
    ///   on `a->result` and leaves it set.
    /// * The C reports `a->result` and writes `*connected`; here the connected
    ///   flag is returned and the result stays on the attempt, which the caller
    ///   reads directly.
    fn connect_step(&mut self, cx: &mut CallCtx<'_, '_>) -> bool {
        let mut connected = self.connected;
        if self.result.is_ok() && !connected {
            match self.chain.connect_head(cx) {
                Ok(done) => {
                    connected = done;
                    if done {
                        self.connected = true;
                    }
                }
                Err(error) => {
                    self.result = error.code();
                    if self.result == CURLcode::WeirdServerReply {
                        self.inconclusive = true;
                    }
                }
            }
        }
        connected
    }

    /// `cf_ip_attempt_restart` (`lib/cf-ip-happy.c:262-290`): try this address
    /// again with a NEW filter.
    ///
    /// The ordering is the whole point and the C says why: *"When restarting, we
    /// tear down and existing filter \*after\* we started up the new one. This
    /// gives us a new socket number and probably a new local port. Which may
    /// prevent confusion."* So the previous subchain is detached but held, the
    /// replacement is created and stepped, and only then is the previous one
    /// destroyed. Holding it in a local is what makes that safe: every exit
    /// path below destroys it exactly once.
    ///
    /// The three flags are cleared first, so a restarted candidate is neither
    /// connected nor inconclusive nor failed until its replacement says so.
    ///
    /// # Errors
    ///
    /// Only what the PROVIDER reports, which the C treats as a *"serious
    /// failure"* that aborts the race. The replacement's own connect result is
    /// recorded on the attempt instead, so a replacement that is inconclusive
    /// again remains eligible for another delayed restart.
    fn restart(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        rc: &RaceCtx,
    ) -> CurlResult<()> {
        // `a->result = CURLE_OK; a->connected = FALSE; a->inconclusive = FALSE;
        //  a->cf = NULL;`
        self.result = CURLcode::Ok;
        self.connected = false;
        self.inconclusive = false;
        self.shut_down = false;
        let previous = self.chain.take_chain();

        let created = self.provider.create(&self.addr, rc.sockindex);
        let outcome = match created {
            Ok(head) => {
                self.chain.set_chain(Some(head));
                self.started = cx.now();
                // `bool dummy; a->result = cf_ip_attempt_connect(a, data,
                //  &dummy);` -- the readiness is discarded here because the
                // caller re-evaluates every attempt immediately afterwards.
                let _connected = self.connect_step(cx);
                Ok(())
            }
            Err(error) => Err(error),
        };

        // `if(cf_prev) Curl_conn_cf_discard_chain(&cf_prev, data);` -- reached
        // on both paths, exactly as the C's single call after the `if` is.
        discard_chain_from(cx, previous);
        outcome
    }

    /// `cf_ip_attempt_free` (`lib/cf-ip-happy.c:175-183`): destroy this
    /// candidate and its whole subchain.
    ///
    /// Consumes the attempt, so it cannot be freed twice -- which is the C's
    /// one hazard here, since `cf_ip_attempt_free` takes a pointer it does not
    /// clear.
    fn discard(mut self, cx: &mut CallCtx<'_, '_>) {
        self.chain.discard_chain(cx);
    }
}

// =========================================================================
// The race -- `struct cf_ip_ballers` and `cf_ip_ballers_run()`
// =========================================================================

/// What one pass over the running list found.
///
/// The three locals `cf_ip_ballers_run` keeps across its walk -- the winner it
/// may have found, `ongoing` and `inconclusive` (`lib/cf-ip-happy.c:340-388`).
/// Gathered into a value so that the walk and the decisions that follow it are
/// separate functions without either losing what the other measured.
#[derive(Clone, Copy, Debug)]
struct RunPass {
    /// The position in the running list of the first candidate that reported
    /// connected, if any.
    winner_at: Option<usize>,
    /// How many candidates are still trying.
    ongoing: usize,
    /// How many failed with an INCONCLUSIVE result and may be restarted.
    inconclusive: usize,
}

/// Where `cf_ip_ballers_run`'s control flow goes next.
///
/// The C uses two labels, `evaluate` and `out`, and jumps between them. Naming
/// the two destinations makes the same flow expressible as a loop without a
/// reader having to reconstruct which `goto` went where.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Step {
    /// `goto evaluate` -- something changed, so walk the candidates again.
    Evaluate,
    /// `goto out` -- nothing more to start right now; fall through to the
    /// timer arithmetic.
    Out,
}

/// The two address streams, the candidates racing on them, and the winner.
///
/// The successor of `struct cf_ip_ballers` (`lib/cf-ip-happy.c:246-259`). The
/// name is the C's: the two address families are the two "balls" of Happy
/// Eyeballs, and a candidate is a "baller" throughout the C's own trace output,
/// which is why the wording survives into the messages here.
#[derive(Debug)]
struct Ballers {
    /// `struct cf_ip_attempt *running` -- the candidates still in the race, in
    /// the order they were started. **The order is behaviour**: it decides
    /// which candidate wins when two report connected in the same pass, and it
    /// decides which failure is the one reported when they all fail.
    running: VecDeque<IpAttempt>,
    /// `struct cf_ip_attempt *winner`, once one exists.
    winner: Option<IpAttempt>,
    /// `struct cf_ai_iter addr_iter` -- the `AF_INET` stream.
    addr_iter: AddrIter,
    /// `struct cf_ai_iter ipv6_iter` -- the `AF_INET6` stream. Unconditional
    /// here where the C wraps it in `#ifdef USE_IPV6`; every mandated target
    /// has IPv6.
    ipv6_iter: AddrIter,
    /// `cf_ip_connect_create *cf_create` -- *"for creating cf"*.
    provider: Rc<dyn TransportProvider>,
    /// `struct curltime started` -- when the first candidate was started, set
    /// once and only when nothing is ongoing (`:395-397`).
    started: CurlTime,
    /// `struct curltime last_attempt_started`, which the inter-attempt delay is
    /// measured from.
    last_attempt_started: CurlTime,
    /// `timediff_t attempt_delay_ms` -- `CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS`.
    attempt_delay_ms: TimeDiff,
    /// `int last_attempt_ai_family`.
    ///
    /// **Initialised to `AF_INET` so that `AF_INET6` is next**, which the C
    /// states in as many words: `bs->last_attempt_ai_family = AF_INET; /* so
    /// AF_INET6 is next */` (`:307`). That single line is why curl's first
    /// actual attempt is IPv6, and it is the whole of the "IPv6 first" policy.
    last_attempt_family: AddressFamily,
    /// `uint8_t transport`.
    transport: Transport,
}

impl Ballers {
    /// The all-zero state C's `calloc` leaves behind, before `start_connect`.
    ///
    /// `cf_ip_ballers_clear` is safe on this state and so is every accessor,
    /// which is what lets [`HappyEyeballs::close`] reset the race by replacing
    /// it (`lib/cf-ip-happy.c:828-842`).
    fn empty(
        provider: Rc<dyn TransportProvider>,
        transport: Transport,
    ) -> Self {
        Self {
            running: VecDeque::new(),
            winner: None,
            addr_iter: AddrIter::empty(AddressFamily::Inet),
            ipv6_iter: AddrIter::empty(AddressFamily::Inet6),
            provider,
            started: CurlTime::ZERO,
            last_attempt_started: CurlTime::ZERO,
            attempt_delay_ms: 0,
            last_attempt_family: AddressFamily::Inet,
            transport,
        }
    }

    /// `cf_ip_ballers_init` (`lib/cf-ip-happy.c:301-342`).
    ///
    /// Two shapes, chosen by the transport:
    ///
    /// * `TRNSPRT_UNIX` gets ONE stream of `AF_UNIX` addresses, or
    ///   [`CURLcode::UnsupportedProtocol`] on a target without Unix sockets.
    ///   There is no second family to alternate with, so the IPv6 stream is
    ///   empty and the alternation below degenerates correctly.
    /// * Everything else gets both streams, each suppressed by
    ///   `CURLOPT_IPRESOLVE`: `V6` initialises the IPv4 stream over `NULL` and
    ///   `V4` initialises the IPv6 stream over `NULL`. Note that the C
    ///   suppresses a family by giving its iterator an EMPTY list rather than by
    ///   skipping the iterator, so every later `has_more` on it is well defined.
    ///
    /// Neither stream is sorted or deduplicated; see [`ConnMeta::resolved`].
    ///
    /// # Errors
    ///
    /// [`CURLcode::UnsupportedProtocol`] for `TRNSPRT_UNIX` where the target
    /// has no Unix domain sockets -- the C's `#else return
    /// CURLE_UNSUPPORTED_PROTOCOL;` at `:315-317`.
    fn init(
        ip_version: IpVersion,
        addrs: &[ResolvedAddr],
        provider: Rc<dyn TransportProvider>,
        transport: Transport,
        attempt_delay_ms: TimeDiff,
    ) -> CurlResult<Self> {
        let mut ballers = Self::empty(provider, transport);
        ballers.attempt_delay_ms = attempt_delay_ms;

        if transport == Transport::Unix {
            ballers.addr_iter = unix_iter(addrs)?;
            ballers.ipv6_iter = AddrIter::empty(AddressFamily::Inet6);
            return Ok(ballers);
        }

        // `cf_ai_iter_init(&bs->addr_iter, (ip_version == V6) ? NULL :
        //  addr_list, AF_INET)` and the mirror image for IPv6.
        let families = split_families(addrs);
        let v4 = if ip_version == IpVersion::V6 {
            Vec::new()
        } else {
            families.v4
        };
        let v6 = if ip_version == IpVersion::V4 {
            Vec::new()
        } else {
            families.v6
        };
        ballers.addr_iter = AddrIter::new(v4, AddressFamily::Inet);
        ballers.ipv6_iter = AddrIter::new(v6, AddressFamily::Inet6);
        Ok(ballers)
    }

    /// `cf_ip_ballers_clear` (`lib/cf-ip-happy.c:290-300`): destroy every
    /// candidate and the winner.
    fn clear(&mut self, cx: &mut CallCtx<'_, '_>) {
        self.clear_running(cx);
        if let Some(winner) = self.winner.take() {
            winner.discard(cx);
        }
    }

    /// The `while(bs->running)` half of [`Self::clear`], which the winner walk
    /// also uses (`:369-373`).
    ///
    /// Front to back, as the C's list splice is.
    fn clear_running(&mut self, cx: &mut CallCtx<'_, '_>) {
        while let Some(attempt) = self.running.pop_front() {
            attempt.discard(cx);
        }
    }

    /// `cf_ai_iter_has_more(&bs->addr_iter) || cf_ai_iter_has_more(
    /// &bs->ipv6_iter)`, which the C computes at three separate points.
    fn more_possible(&self) -> bool {
        self.addr_iter.has_more() || self.ipv6_iter.has_more()
    }

    /// How long until the next attempt becomes eligible, in milliseconds.
    ///
    /// `CURLMAX(bs->attempt_delay_ms - elapsed_ms, 0)` (`:521`), and [`None`]
    /// when there is no further address to start, which is the `if(more_possible)`
    /// guard around it.
    fn remaining_delay_ms(&self, now: CurlTime) -> Option<TimeDiff> {
        if !self.more_possible() {
            return None;
        }
        let elapsed = timediff_ms(now, self.last_attempt_started);
        Some((self.attempt_delay_ms - elapsed).max(0))
    }

    /// One pass over the running list -- the `for(panchor = &bs->running; ...)`
    /// walk of `lib/cf-ip-happy.c:340-388`.
    ///
    /// Stops at the FIRST candidate that reports connected, which is what makes
    /// the winner deterministic when two become ready in the same reactor turn:
    /// the earlier position in the running list wins, and the running list is in
    /// start order.
    fn poll_running(&mut self, cx: &mut CallCtx<'_, '_>) -> RunPass {
        let mut pass = RunPass {
            winner_at: None,
            ongoing: 0,
            inconclusive: 0,
        };
        for (index, attempt) in self.running.iter_mut().enumerate() {
            let connected = attempt.connect_step(cx);
            if attempt.result.is_ok() {
                if connected {
                    pass.winner_at = Some(index);
                    break;
                }
                // `/* still running */ ++ongoing;`
                pass.ongoing += 1;
            } else if attempt.inconclusive {
                // `/* failed, but inconclusive */ ++inconclusive;`
                pass.inconclusive += 1;
            }
        }
        pass
    }

    /// Declares the candidate at `index` the winner and frees every loser
    /// (`lib/cf-ip-happy.c:363-374`).
    ///
    /// The winner is removed from the running list FIRST, so the sweep that
    /// follows cannot reach it. The C achieves that by splicing it out and
    /// clearing its `next`; removing it from an owned collection has the same
    /// effect and cannot be got wrong by omission.
    fn take_winner(&mut self, cx: &mut CallCtx<'_, '_>, index: usize) {
        let winner = self.running.remove(index);
        self.clear_running(cx);
        self.winner = winner;
    }

    /// The alternation -- `lib/cf-ip-happy.c:414-427`.
    ///
    /// ```c
    /// if((bs->last_attempt_ai_family == AF_INET) ||
    ///    !cf_ai_iter_has_more(&bs->addr_iter)) {
    ///   addr = cf_ai_iter_next(&bs->ipv6_iter);
    ///   ai_family = bs->ipv6_iter.ai_family;
    /// }
    /// if(!addr) {
    ///   addr = cf_ai_iter_next(&bs->addr_iter);
    ///   ai_family = bs->addr_iter.ai_family;
    /// }
    /// ```
    ///
    /// Read closely, because the two conditions are not symmetric. IPv6 is tried
    /// when the LAST attempt was IPv4 **or** when no IPv4 address remains -- the
    /// second disjunct is what drains a family that outlives the other. IPv4 is
    /// then tried only if that produced nothing, which covers both "IPv6 was
    /// never even consulted" and "IPv6 is exhausted".
    ///
    /// The family reported is the ITERATOR's family and not the address's, which
    /// matters for the suppressed-family case: an iterator initialised over an
    /// empty list still names its family, and the C reads it unconditionally.
    fn pick_next(&mut self) -> Option<(ResolvedAddr, AddressFamily)> {
        let v6_family = self.ipv6_iter.family;
        let v4_family = self.addr_iter.family;

        if self.last_attempt_family == AddressFamily::Inet
            || !self.addr_iter.has_more()
        {
            if let Some(addr) = self.ipv6_iter.next_addr() {
                return Some((addr, v6_family));
            }
        }
        self.addr_iter.next_addr().map(|addr| (addr, v4_family))
    }
}

// -- the race proper -------------------------------------------------------

impl Ballers {
    /// `cf_ip_ballers_run` (`lib/cf-ip-happy.c:344-532`): make progress, and
    /// report whether a candidate has won.
    ///
    /// The C is one function with two labels; this is the same control flow with
    /// the two labels named. `loop` is the `evaluate` label, the tail of the body
    /// is `out`, and [`Step`] says which of the two a decision reached.
    ///
    /// # Termination
    ///
    /// Every `continue` follows an event that moved the race forward: a candidate
    /// was started (so `last_attempt_started` advanced and one address was
    /// consumed), a candidate was restarted (likewise), or the attempt delay was
    /// found to be due with an address still to try (so the next pass starts
    /// one). The address streams are finite and each pass consumes at most one
    /// address, so the loop cannot spin.
    ///
    /// # Errors
    ///
    /// [`CURLcode::CouldntConnect`] or the LAST candidate's own failure when
    /// every address has been tried and none connected;
    /// [`CURLcode::OperationTimedout`] when the transfer's deadline has passed;
    /// and whatever a provider reported while building or rebuilding a
    /// candidate.
    fn run(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        rc: &RaceCtx,
    ) -> CurlResult<bool> {
        // `if(bs->winner) return CURLE_OK;`
        if self.winner.is_some() {
            return Ok(true);
        }

        loop {
            // `evaluate:`
            let pass = self.poll_running(cx);
            if let Some(index) = pass.winner_at {
                trc!(
                    cx,
                    rc.identity,
                    rc.sockidx(),
                    "connect attempt #{} successful",
                    index
                );
                self.take_winner(cx, index);
                return Ok(true);
            }
            if !self.running.is_empty() {
                trc!(
                    cx,
                    rc.identity,
                    rc.sockidx(),
                    "checked connect attempts: {} ongoing, {} inconclusive",
                    pass.ongoing,
                    pass.inconclusive
                );
            }

            // `if(!ongoing) { ... do_more = TRUE; } else { ... }`
            let do_more = if pass.ongoing == 0 {
                if self.started.is_zero() {
                    self.started = cx.now();
                }
                true
            } else if self.more_possible()
                && timediff_ms(cx.now(), self.last_attempt_started)
                    >= self.attempt_delay_ms
            {
                trc!(
                    cx,
                    rc.identity,
                    rc.sockidx(),
                    "happy eyeballs timeout expired, start next attempt"
                );
                true
            } else {
                false
            };

            if do_more && self.start_or_restart(cx, rc, pass)? == Step::Evaluate
            {
                continue;
            }

            // `out:` reached with `result == CURLE_OK`, which is the only way
            // here: every failing branch above returned its error already, and
            // the C's own `goto out` with a result set falls straight past the
            // `if(!result)` block below.
            if self.schedule(cx, rc)? {
                continue;
            }
            return Ok(false);
        }
    }

    /// The `if(do_more)` block of `cf_ip_ballers_run` (`:413-495`).
    ///
    /// Three outcomes, in the C's own order: start the next address, restart an
    /// inconclusive candidate, or conclude that the race has failed.
    ///
    /// # Errors
    ///
    /// The failures [`Self::run`] documents. Each corresponds to a `goto out`
    /// with `result` set, which in the C skips the timer arithmetic entirely.
    fn start_or_restart(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        rc: &RaceCtx,
        pass: RunPass,
    ) -> CurlResult<Step> {
        let picked = self.pick_next();

        // `Curl_reset_fail(data);` -- *"We are (re-)starting attempts. We are not
        // interested in keeping old failure information. The new attempt will
        // either succeed or persist new failure."* Note the placement: BEFORE
        // the address is known to exist, so it also runs on the paths that go on
        // to restart an inconclusive candidate.
        if let Some(tracer) = cx.tracer_mut() {
            tracer.reset_fail();
        }

        if let Some((addr, family)) = picked {
            // `bs->running ? "next" : "first"`, evaluated BEFORE the append.
            let ordinal = if self.running.is_empty() {
                "first"
            } else {
                "next"
            };
            let outcome = IpAttempt::new(
                cx,
                rc,
                addr,
                family,
                self.transport,
                Rc::clone(&self.provider),
            );
            // The C traces the CURLcode it is about to act on, whether or not it
            // is a failure, so the code is taken before the `?`.
            let code = match &outcome {
                Ok(_) => CURLcode::Ok,
                Err(error) => error.code(),
            };
            trc!(
                cx,
                rc.identity,
                rc.sockidx(),
                "starting {} attempt for ipv{} -> {}",
                ordinal,
                if family == AddressFamily::Inet {
                    "4"
                } else {
                    "6"
                },
                code.as_i32()
            );
            let attempt = outcome?;

            // `panchor = &bs->running; while(*panchor) panchor = ...; *panchor =
            //  a;` -- appended at the TAIL, which is what keeps the running list
            // in start order and therefore keeps the winner and the reported
            // failure deterministic.
            self.running.push_back(attempt);
            self.last_attempt_started = cx.now();
            self.last_attempt_family = family;
            return Ok(Step::Evaluate);
        }

        if pass.inconclusive > 0 {
            return self.retry_inconclusive(cx, rc);
        }

        if pass.ongoing == 0 {
            // `/* no more addresses, no inconclusive attempts */`
            trc!(cx, rc.identity, rc.sockidx(), "no more attempts to try");
            let mut code = CURLcode::CouldntConnect;
            for attempt in &self.running {
                // The index is LITERALLY ZERO on every line, and that is the C:
                // `VERBOSE(i = 0);` before the loop with no `++i` inside it
                // (`:489-495`), unlike the two other numbered walks in this file
                // which do increment. Reproduced rather than corrected, because a
                // trace line is observable output and correcting it would be a
                // behaviour change justified only by improvement.
                trc!(
                    cx,
                    rc.identity,
                    rc.sockidx(),
                    "baller {}: result={}",
                    0,
                    attempt.result.as_i32()
                );
                if !attempt.result.is_ok() {
                    // Overwritten every time, so THE LAST FAILING CANDIDATE'S
                    // RESULT IS THE ONE REPORTED -- not the first, not the most
                    // specific, and not an aggregate.
                    code = attempt.result;
                }
            }
            return Err(Error::new(code));
        }

        // Unreachable: `do_more` is true only when nothing is ongoing -- in
        // which case the branch above applies -- or when an address remains, in
        // which case `pick_next` produced one. Written as a fall-through rather
        // than an assertion because the C falls through here too.
        Ok(Step::Out)
    }

    /// The `else if(inconclusive)` block (`lib/cf-ip-happy.c:455-484`).
    ///
    /// Every address has been tried and some candidate failed inconclusively, so
    /// the race waits out the remainder of the inter-attempt delay and then
    /// restarts ONE candidate -- the FIRST inconclusive one in running order.
    ///
    /// # Errors
    ///
    /// A provider failure while rebuilding, which the C calls a *"serious
    /// failure"* and which aborts the race.
    fn retry_inconclusive(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        rc: &RaceCtx,
    ) -> CurlResult<Step> {
        let since = timediff_ms(cx.now(), self.last_attempt_started);
        let delay = self.attempt_delay_ms - since;

        if delay > 0 {
            // `/* let's wait some more before restarting */`
            if let Some(tracer) = cx.tracer_mut() {
                tracer.infof(format_args!(
                    "connect attempts inconclusive, retrying in {delay}ms"
                ));
            }
            rc.expiry.expire(delay, HAPPY_EYEBALLS_TIMER);
            return Ok(Step::Out);
        }

        trc!(
            cx,
            rc.identity,
            rc.sockidx(),
            "all attempts inconclusive, restarting one"
        );
        let Some(index) = self.running.iter().position(|a| a.inconclusive)
        else {
            // `DEBUGASSERT(0); /* should not come here */` -- an inconclusive
            // count with no inconclusive candidate. Asserted in a debug build
            // and treated as "nothing to restart" in a release one, which is
            // what the C's assertion falls through to.
            debug_assert!(
                false,
                "an inconclusive count with no inconclusive candidate"
            );
            return Ok(Step::Out);
        };

        let outcome = match self.running.get_mut(index) {
            Some(attempt) => attempt.restart(cx, rc),
            // Unreachable: `position` resolved the index a statement ago and
            // nothing has touched the list since.
            None => Ok(()),
        };
        let code = match &outcome {
            Ok(()) => CURLcode::Ok,
            Err(error) => error.code(),
        };
        trc!(
            cx,
            rc.identity,
            rc.sockidx(),
            "restarted baller {} -> {}",
            index,
            code.as_i32()
        );
        outcome?;
        self.last_attempt_started = cx.now();
        Ok(Step::Evaluate)
    }

    /// The `out:` block's `if(!result)` half (`lib/cf-ip-happy.c:497-530`):
    /// decide when this filter needs to be called again.
    ///
    /// Reports `true` for the C's `goto evaluate`, meaning the delay is already
    /// due and another pass should run at once.
    ///
    /// # The one place a deadline of zero is folded rather than compared
    ///
    /// `Curl_timeleft_ms` returns ZERO for "no limit" and a NEGATIVE value for
    /// "already elapsed" (`lib/connect.c:98-101`). The C then computes
    /// `CURLMIN(next_expire_ms, expire_ms)`, which for a no-limit transfer is
    /// `CURLMIN(0, expire_ms) == 0`, takes the `<= 0` branch and re-evaluates
    /// immediately -- spinning until the delay elapses. That is unreachable
    /// through curl's own deadline, because `Curl_timeleft_now_ms` applies
    /// `DEFAULT_CONNECT_TIMEOUT` while a transfer is connecting and fakes an
    /// exact zero to `-1` so that it can never report "no limit" here. An
    /// INJECTED deadline can report zero, so the fold honours the convention and
    /// waits out the attempt delay instead: identical semantics, without the
    /// busy loop. [`crate::conn::filters::FilterChain::connect`] resolves the
    /// same C expression the same way, and for the same reason.
    ///
    /// # Errors
    ///
    /// [`CURLcode::OperationTimedout`] once the transfer's deadline has passed,
    /// reported with the elapsed time since the single transfer started.
    fn schedule(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        rc: &RaceCtx,
    ) -> CurlResult<bool> {
        // `next_expire_ms = Curl_timeleft_ms(data);`
        let overall = rc.deadline.time_left_ms();
        if overall < 0 {
            let elapsed = timediff_ms(cx.now(), rc.meta.transfer_started_at());
            let message = format!("Connection timeout after {elapsed} ms");
            if let Some(tracer) = cx.tracer_mut() {
                tracer.failf(format_args!("{message}"));
            }
            return Err(Error::with_context(
                CURLcode::OperationTimedout,
                message,
            ));
        }

        let Some(expire) = self.remaining_delay_ms(cx.now()) else {
            // `if(more_possible)` was false: nothing further to start, so no
            // timer is armed and the race waits on its candidates alone.
            return Ok(false);
        };

        let next = if overall == 0 {
            expire
        } else {
            overall.min(expire)
        };
        if next <= 0 {
            trc!(
                cx,
                rc.identity,
                rc.sockidx(),
                "HAPPY_EYEBALLS timeout due, re-evaluate"
            );
            return Ok(true);
        }
        trc!(
            cx,
            rc.identity,
            rc.sockidx(),
            "next HAPPY_EYEBALLS timeout in {}ms",
            next
        );
        rc.expiry.expire(next, HAPPY_EYEBALLS_TIMER);
        Ok(false)
    }
}

// -- the four collective operations over the candidates --------------------

impl Ballers {
    /// `cf_ip_ballers_shutdown` (`lib/cf-ip-happy.c:535-555`): shut every
    /// candidate down, non-blocking.
    ///
    /// Three properties, all deliberate:
    ///
    /// * A candidate whose shutdown FAILED is marked done -- *"treat a failed
    ///   shutdown as done"* -- so one broken candidate cannot stall the others.
    /// * The walk visits EVERY candidate on every call rather than stopping at
    ///   the first unfinished one, which is the opposite of
    ///   [`crate::conn::filters::FilterChain::shutdown`]'s one-filter-per-pass
    ///   rule. These are independent subchains, so there is no ordering between
    ///   them to preserve.
    /// * The return is ALWAYS success. Only `done` carries information, and it is
    ///   false exactly while at least one candidate is still saying goodbye.
    ///
    /// The C calls `a->cf->cft->do_shutdown(a->cf, ...)` -- the head filter's own
    /// method -- and not `Curl_conn_shutdown`, so no driver is involved and the
    /// subchain below the head is not walked.
    fn shutdown(&mut self, cx: &mut CallCtx<'_, '_>) -> bool {
        let mut done = true;
        for attempt in &mut self.running {
            if attempt.shut_down {
                continue;
            }
            let outcome = match attempt.chain.head_mut() {
                Some(head) => head.shutdown(cx),
                // A candidate with no chain has nothing to say goodbye with,
                // which is the C's `a->cf` being NULL after a failed restart.
                None => Ok(true),
            };
            match outcome {
                Err(error) => {
                    attempt.result = error.code();
                    attempt.shut_down = true;
                }
                Ok(true) => attempt.shut_down = true,
                Ok(false) => done = false,
            }
        }
        done
    }

    /// `cf_ip_ballers_pollset` (`lib/cf-ip-happy.c:557-568`): collect what every
    /// live candidate is waiting for.
    ///
    /// Each candidate is driven through its OWN subchain driver, because the
    /// outer walk cannot see a filter it does not own. A candidate that has
    /// already failed contributes nothing, and the walk stops at the first
    /// error.
    ///
    /// # Errors
    ///
    /// Whatever a candidate's chain reports while adjusting.
    fn pollset(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        ps: &mut EasyPollset,
    ) -> CurlResult<()> {
        for attempt in &mut self.running {
            if !attempt.result.is_ok() {
                continue;
            }
            attempt.chain.adjust_pollset(cx, ps)?;
        }
        Ok(())
    }

    /// `cf_ip_ballers_pending` (`lib/cf-ip-happy.c:570-583`): has any live
    /// candidate buffered bytes?
    ///
    /// The head filter's own `has_data_pending` is called, not
    /// [`crate::conn::filters::FilterChain::data_pending`]: the latter skips to
    /// the first CONNECTED filter, and a racing candidate has none.
    fn pending(&mut self, cx: &CallCtx<'_, '_>) -> bool {
        for attempt in &mut self.running {
            if !attempt.result.is_ok() {
                continue;
            }
            if let Some(head) = attempt.chain.head_mut() {
                if head.data_pending(cx) {
                    return true;
                }
            }
        }
        false
    }

    /// `cf_ip_ballers_max_time` (`lib/cf-ip-happy.c:585-601`): the LATEST of one
    /// timer across every candidate.
    ///
    /// Zero readings are skipped, because zero is the C's "not set"
    /// (`if((t.tv_sec || t.tv_usec) && ...)`), and the comparison is
    /// `curlx_ptimediff_us(&t, &tmax) > 0` -- strictly later, so the first
    /// candidate to report a given instant keeps it. A candidate that does not
    /// answer contributes nothing. Unlike [`Self::pollset`] and
    /// [`Self::pending`], a FAILED candidate is still asked: the C does not skip
    /// one here, and its timers are legitimate history.
    fn max_time(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        which: CfQuery,
    ) -> CurlTime {
        let mut latest = CurlTime::ZERO;
        for attempt in &mut self.running {
            let answer = attempt.chain.query_typed(cx, which);
            if let Ok(CfQueryValue::Timer(at)) = answer {
                if !at.is_zero() && timediff_us(at, latest) > 0 {
                    latest = at;
                }
            }
        }
        latest
    }

    /// `cf_ip_ballers_min_reply_ms` (`lib/cf-ip-happy.c:603-617`): the EARLIEST
    /// first-response time across every candidate.
    ///
    /// `-1` when nobody answered, which is `CF_QUERY_CONNECT_REPLY_MS`'s own
    /// "not determined yet" (`lib/cfilters.h:147`) rather than an error. A
    /// negative answer from a candidate is ignored for the same reason.
    fn min_reply_ms(&mut self, cx: &mut CallCtx<'_, '_>) -> TimeDiff {
        let mut earliest: TimeDiff = -1;
        for attempt in &mut self.running {
            let answer = attempt.chain.query_typed(cx, CfQuery::ConnectReplyMs);
            if let Ok(CfQueryValue::ConnectReplyMs(reply)) = answer {
                if reply >= 0 && (earliest < 0 || reply < earliest) {
                    earliest = reply;
                }
            }
        }
        earliest
    }
}

/// The `AF_UNIX` stream, on a target that has Unix domain sockets.
///
/// `cf_ai_iter_init(&bs->addr_iter, addr_list, AF_UNIX)`
/// (`lib/cf-ip-happy.c:313-314`). [`crate::dns::split_families`] deliberately
/// DROPS `AF_UNIX` -- a Unix socket has no family to race -- so the filtering is
/// done here instead, preserving the resolver's order and keeping duplicates.
#[cfg(unix)]
fn unix_iter(addrs: &[ResolvedAddr]) -> CurlResult<AddrIter> {
    let paths: Vec<ResolvedAddr> = addrs
        .iter()
        .filter(|addr| addr.family() == AddressFamily::Unix)
        .cloned()
        .collect();
    Ok(AddrIter::new(paths, AddressFamily::Unix))
}

/// `#else return CURLE_UNSUPPORTED_PROTOCOL;` (`lib/cf-ip-happy.c:315-317`).
///
/// Unreachable on all four mandated targets, which are Unix. Compiled rather
/// than dropped because the transport is chosen by the URL and a build without
/// Unix sockets must refuse it with a code rather than a panic.
#[cfg(not(unix))]
fn unix_iter(_addrs: &[ResolvedAddr]) -> CurlResult<AddrIter> {
    Err(Error::with_context(
        CURLcode::UnsupportedProtocol,
        "this build has no Unix domain sockets",
    ))
}

// =========================================================================
// The filter -- `struct Curl_cftype Curl_cft_ip_happy`
// =========================================================================

/// `cf_connect_state` (`lib/cf-ip-happy.c:619-623`).
///
/// Three states and no more. The C drives them with a `switch` that
/// deliberately FALLS THROUGH from `SCFST_INIT` into `SCFST_WAITING`, so that
/// starting the race and taking its first step happen in one call; the
/// [`HappyEyeballs::connect`] arm below reproduces that by calling the same
/// helper the `Waiting` arm does.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum ConnectState {
    /// `SCFST_INIT`: nothing started. The state a fresh filter is in, and the
    /// state [`HappyEyeballs::close`] returns to.
    #[default]
    Init,
    /// `SCFST_WAITING`: the race is running.
    Waiting,
    /// `SCFST_DONE`: a winner is installed.
    Done,
}

/// Everything the filter is injected with.
///
/// One value rather than four constructor arguments, so that a caller states
/// its seams once and a test substitutes one of them by building the bundle.
#[derive(Clone, Debug)]
pub(crate) struct HappyEyeballsSeams {
    /// The connection's own facts.
    pub(crate) meta: Rc<dyn ConnMeta>,
    /// `Curl_timeleft_ms(data)`, owned by `conn/mod.rs`.
    pub(crate) deadline: Rc<dyn Deadline>,
    /// `Curl_expire` and `Curl_expire_done`.
    pub(crate) expiry: Rc<dyn ExpireScheduler>,
    /// `transport_providers[]`.
    pub(crate) registry: Rc<TransportRegistry>,
}

/// The dual-stack racing filter -- `Curl_cft_ip_happy`.
///
/// The successor of `struct cf_ip_happy_ctx` (`lib/cf-ip-happy.c:625-631`)
/// together with the eleven `cf_ip_happy_*` callbacks and the filter-type table
/// they are registered in (`:903-919`).
///
/// The state that C keeps behind `void *ctx` is TYPED here and sits beside
/// [`FilterBase`], which is the whole of the translation: there is no cast at
/// any boundary and no way to reach this state through the wrong type.
#[derive(Debug)]
pub(crate) struct HappyEyeballs {
    /// The chain link, socket index and two state flags.
    base: FilterBase,
    /// `uint8_t transport`.
    transport: Transport,
    /// `cf_ip_connect_create *cf_create`, resolved from the registry once, at
    /// construction, exactly as `cf_ip_happy_insert_after` resolves it.
    provider: Rc<dyn TransportProvider>,
    /// `cf_connect_state state`.
    state: ConnectState,
    /// `struct cf_ip_ballers ballers`.
    ballers: Ballers,
    /// `struct curltime started`, set when the race begins.
    #[allow(dead_code)]
    // Read by tests; C declares the member and only writes it.
    started: CurlTime,
    /// The injected seams.
    seams: HappyEyeballsSeams,
    /// The explicit re-evaluation signal for [`Self::race`].
    ///
    /// C has no counterpart because it has no reactor: the multi handle simply
    /// calls `cf_ip_happy_connect` again when `EXPIRE_HAPPY_EYEBALLS` fires or a
    /// socket becomes ready. The asynchronous driver here waits, so it needs a
    /// way for an owner to say "conditions changed, look again" -- a
    /// `CURLOPT_TIMEOUT` lowered mid-connect, or `curl_multi_wakeup`.
    wake: Rc<Notify>,
}

impl HappyEyeballs {
    /// `cf_ip_happy_create` (`lib/cf-ip-happy.c:921-959`) plus the provider
    /// lookup that `cf_ip_happy_insert_after` performs before calling it.
    ///
    /// The two are merged because the lookup is the only failure either has that
    /// survives translation -- the C's `CURLE_OUT_OF_MEMORY` does not, a failure
    /// to allocate aborting instead -- and merging them means a constructed
    /// filter always has a provider, which removes an [`Option`] that could
    /// otherwise be `None` at connect time.
    ///
    /// # Errors
    ///
    /// [`CURLcode::UnsupportedProtocol`] for a transport the registry has no
    /// provider for, which is `get_cf_create` returning `NULL`
    /// (`lib/cf-ip-happy.c:968-972`).
    #[allow(dead_code)] // No consumer yet; conn/mod.rs builds the chain with it.
    pub(crate) fn new(
        cx: &mut CallCtx<'_, '_>,
        transport: Transport,
        sockindex: SocketIndex,
        conn: Option<ConnId>,
        seams: HappyEyeballsSeams,
    ) -> CurlResult<Self> {
        let identity =
            TraceFilter::from_name(HAPPY_EYEBALLS_FILTER_NAME.as_bytes());
        let Some(provider) = seams.registry.provider(transport) else {
            // C attributes this line to `cf_at`, the filter being inserted
            // after, because the new filter does not exist yet. Here it is
            // attributed to this filter's own identity, which is the closest
            // available and carries the identical text.
            trc!(
                cx,
                identity,
                sockindex.as_i32(),
                "unsupported transport type {}",
                transport.as_u8()
            );
            return Err(Error::with_context(
                CURLcode::UnsupportedProtocol,
                "unsupported transport type",
            ));
        };

        let mut base = FilterBase::new(sockindex);
        base.set_conn(conn);
        Ok(Self {
            base,
            transport,
            provider: Rc::clone(&provider),
            state: ConnectState::Init,
            ballers: Ballers::empty(provider, transport),
            started: CurlTime::ZERO,
            seams,
            wake: Rc::new(Notify::new()),
        })
    }

    /// `cf_ip_happy_insert_after` (`lib/cf-ip-happy.c:961-982`): build the
    /// filter and install it immediately below the filter at `index`.
    ///
    /// The C asserts `cf_at` is non-`NULL` -- *"Need to be first"* -- which a
    /// position cannot express; [`FilterChain::insert_after`] reports
    /// [`CURLcode::BadFunctionArgument`] for a position with no filter instead.
    ///
    /// # Errors
    ///
    /// As [`Self::new`], plus whatever [`FilterChain::insert_after`] reports.
    #[allow(dead_code)] // No consumer yet; conn/mod.rs installs the chain with it.
    pub(crate) fn insert_after(
        cx: &mut CallCtx<'_, '_>,
        chain: &mut FilterChain,
        index: usize,
        transport: Transport,
        seams: HappyEyeballsSeams,
    ) -> CurlResult<()> {
        let filter =
            Self::new(cx, transport, chain.sockindex(), chain.conn(), seams)?;
        chain.insert_after(cx, index, link(filter))
    }

    /// The signal [`Self::race`] waits on, for an owner that needs to interrupt
    /// it.
    ///
    /// Handing out the [`Rc`] rather than a `wake()` method is deliberate: the
    /// waker outlives any single borrow of the filter, and an owner that has to
    /// borrow the filter in order to wake it could not wake it from the task
    /// that is currently racing.
    #[allow(dead_code)] // No consumer yet; conn/mod.rs and multi/ wake the race.
    pub(crate) fn waker(&self) -> Rc<Notify> {
        Rc::clone(&self.wake)
    }

    /// The bundle the race is driven with, gathered off this filter.
    fn race_ctx(&self) -> RaceCtx {
        RaceCtx {
            sockindex: self.base.sockindex(),
            conn: self.base.conn(),
            identity: self.trace_filter(),
            meta: Rc::clone(&self.seams.meta),
            deadline: Rc::clone(&self.seams.deadline),
            expiry: Rc::clone(&self.seams.expiry),
        }
    }

    /// `start_connect` (`lib/cf-ip-happy.c:694-724`).
    ///
    /// # Errors
    ///
    /// [`CURLcode::FailedInit`] when the connection has no resolved addresses,
    /// which is the C's `if(!dns)`; [`CURLcode::OperationTimedout`] when the
    /// deadline has ALREADY passed, which the C calls *"a precaution, no need to
    /// continue if time already is up"*; and
    /// [`CURLcode::UnsupportedProtocol`] from [`Ballers::init`].
    fn start_connect(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<()> {
        let sockindex = self.base.sockindex();
        let Some(addrs) = self.seams.meta.resolved(sockindex) else {
            return Err(Error::with_context(
                CURLcode::FailedInit,
                "no resolved addresses for this connection",
            ));
        };

        if self.seams.deadline.time_left_ms() < 0 {
            if let Some(tracer) = cx.tracer_mut() {
                tracer.failf(format_args!("Connection time-out"));
            }
            return Err(Error::with_context(
                CURLcode::OperationTimedout,
                "Connection time-out",
            ));
        }

        trc!(
            cx,
            self.trace_filter(),
            sockindex.as_i32(),
            "init ip ballers for transport {}",
            self.transport.as_u8()
        );
        self.started = cx.now();
        self.ballers = Ballers::init(
            self.seams.meta.ip_version(),
            &addrs,
            Rc::clone(&self.provider),
            self.transport,
            self.seams.meta.happy_eyeballs_timeout_ms(),
        )?;
        Ok(())
    }

    /// `is_connected` (`lib/cf-ip-happy.c:633-691`): run the race, and on
    /// failure compose the line the application reads.
    ///
    /// # Errors
    ///
    /// Whatever [`Ballers::run`] reported, with the message attached and with
    /// the operating-system timeout translation applied.
    fn is_connected(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<bool> {
        let rc = self.race_ctx();
        match self.ballers.run(cx, &rc) {
            Ok(done) => Ok(done),
            Err(error) => Err(self.report_failure(cx, error)),
        }
    }

    /// The port the failure message names (`lib/cf-ip-happy.c:663-673`).
    ///
    /// Three cases in a fixed order, and the order is what makes them
    /// unambiguous: the SECOND socket reports the connection's secondary port
    /// whatever else is configured, an explicit `--connect-to` port wins over
    /// the URL's, and the URL's port is the fallback.
    fn destination_port(&self) -> u16 {
        let meta = &*self.seams.meta;
        if self.base.sockindex() == SocketIndex::Secondary {
            meta.secondary_port()
        } else if let Some(port) = meta.connect_to_port() {
            port
        } else {
            meta.remote_port()
        }
    }

    /// The `failf` of `is_connected` (`lib/cf-ip-happy.c:637-689`), and the one
    /// place the reported code may change.
    ///
    /// The C's format string is
    /// `"Failed to connect to %s %s %s%s%safter %" FMT_TIMEDIFF_T " ms: %s"`,
    /// whose middle three conversions are the proxy clause and are all empty
    /// when there is no proxy -- so the text reads `"... port 80 after 12 ms:
    /// ..."` without one and `"... port 80 via proxy.example after 12 ms: ..."`
    /// with one. The trailing message is `curl_easy_strerror(result)`, the
    /// GENERIC string for the code, which is [`CURLcode::message`].
    ///
    /// The translation at the end is the C's, verbatim in effect: an
    /// operating-system error of `SOCKETIMEDOUT` makes the reported code
    /// [`CURLcode::OperationTimedout`] whatever the race concluded. It happens
    /// AFTER the message is composed, so the message still names the original
    /// failure -- which is deliberate in the C and preserved here.
    fn report_failure(&self, cx: &mut CallCtx<'_, '_>, error: Error) -> Error {
        let meta = &*self.seams.meta;
        let hostname =
            meta.connect_to_host().unwrap_or_else(|| meta.host_name());
        let via = match meta.unix_socket_path() {
            Some(path) => format!("over {path}"),
            None => format!("port {}", self.destination_port()),
        };
        let proxy = meta.socks_proxy_name().or_else(|| meta.http_proxy_name());
        let elapsed = timediff_ms(cx.now(), meta.transfer_started_at());
        let reason = error.code().message();
        let message = match proxy {
            Some(name) => format!(
                "Failed to connect to {hostname} {via} via {name} after \
                 {elapsed} ms: {reason}"
            ),
            None => format!(
                "Failed to connect to {hostname} {via} after {elapsed} ms: \
                 {reason}"
            ),
        };
        if let Some(tracer) = cx.tracer_mut() {
            tracer.failf(format_args!("{message}"));
        }

        let code = if meta.os_error_is_timeout() {
            CURLcode::OperationTimedout
        } else {
            error.code()
        };
        Error::with_context(code, message)
    }

    /// One step of the `SCFST_WAITING` arm (`lib/cf-ip-happy.c:784-820`).
    ///
    /// # Errors
    ///
    /// As [`Self::is_connected`] and [`Self::install_winner`].
    fn wait_for_winner(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
    ) -> CurlResult<bool> {
        if !self.is_connected(cx)? {
            return Ok(false);
        }
        self.install_winner(cx)?;
        Ok(true)
    }

    /// Promotes the winner into this filter's own `next` (`:788-818`).
    ///
    /// The sequence is the C's, in the C's order: mark done, mark connected,
    /// TRANSFER the winner's subchain, destroy every remaining candidate,
    /// disarm the timer, clear the accumulated failure, mark the application
    /// connect time for the SSH family, trace, and count the connection.
    ///
    /// The transfer is what leaves the attempt empty, so the `ctx_clear` that
    /// follows cannot destroy the chain it just handed over -- the C achieves
    /// the same by assigning `ctx->ballers.winner->cf = NULL` and relies on the
    /// reader noticing; here the chain is MOVED and the emptiness is a
    /// consequence rather than a convention.
    ///
    /// # Errors
    ///
    /// [`CURLcode::FailedInit`] if the winner has no chain. The C asserts this
    /// invariant three times over (`:786-788`) and would then dereference
    /// `NULL` in a release build; reporting it keeps a broken invariant
    /// diagnosable without a panic in a live transfer, and the race is reset so
    /// the failure cannot repeat in a loop.
    fn install_winner(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<()> {
        let winner = self
            .ballers
            .winner
            .as_mut()
            .and_then(|winner| winner.chain.take_chain());
        let Some(head) = winner else {
            debug_assert!(
                false,
                "a completed race must have a winner holding a chain"
            );
            self.ballers.clear(cx);
            self.state = ConnectState::Init;
            return Err(Error::with_context(
                CURLcode::FailedInit,
                "the winning candidate had no filter chain",
            ));
        };

        self.state = ConnectState::Done;
        self.base.set_connected(true);
        self.base.set_next(Some(head));
        self.ballers.clear(cx);
        self.seams.expiry.expire_done(HAPPY_EYEBALLS_TIMER);
        // `/* whatever errors where reported by ballers, clear our errorbuf */`
        if let Some(tracer) = cx.tracer_mut() {
            tracer.reset_fail();
        }
        if self.seams.meta.is_ssh_family() {
            // `/* we are connected already */`
            self.seams.meta.mark_app_connect_time();
        }

        // `if(!Curl_conn_cf_get_ip_info(cf->next, data, &is_ipv6, &ipquad))`.
        // The host is `Curl_conn_get_current_host`'s FALLBACK, `conn->host.name`
        // (`lib/cfilters.c:849-851`), and not the `--connect-to` host: that
        // function's interim answer comes from a tunnelling proxy filter that has
        // NOT connected, and at this instant this filter and everything below it
        // have. It also cannot be reached from here in any case, since the walk
        // starts at the chain head, which is above this filter.
        let quad = match self.base.next_mut() {
            Some(next) => match next.query(cx, CfQuery::IpInfo) {
                Ok(CfQueryValue::IpInfo { quad, .. }) => Some(quad),
                _ => None,
            },
            None => None,
        };
        if let Some(quad) = quad {
            let host = self.seams.meta.host_name();
            trc!(
                cx,
                self.trace_filter(),
                self.base.sockindex().as_i32(),
                "Connected to {} ({}) port {}",
                host,
                quad.remote_ip,
                quad.remote_port
            );
        }

        // `data->info.numconnects++; /* to track the # of connections made */`
        self.seams.meta.note_connection();
        Ok(())
    }

    /// Drives the race to completion, asynchronously.
    ///
    /// [`ConnFilter::connect`] is non-blocking and synchronous, exactly as its C
    /// original is: it reports `Ok(false)` and expects to be called again. In the
    /// C that call comes from the multi handle's own loop, which polls sockets
    /// and fires `EXPIRE_HAPPY_EYEBALLS`. Here `conn/` owns the asynchronous
    /// boundary, so this is where the waiting happens -- and it is
    /// [`tokio::select!`] that waits, on the four things that can end a wait:
    ///
    /// 1. **Readiness** of any candidate's sockets, collected by
    ///    [`Self::adjust_pollset`] from every live subchain and awaited through
    ///    [`crate::conn::select`]. Nothing here touches `poll` or `select`.
    /// 2. **The inter-attempt delay**, so that the second address family is tried
    ///    the moment `CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS` allows. A configured
    ///    delay of zero makes this arm ready immediately, which is what makes a
    ///    zero delay mean "at once" rather than "never".
    /// 3. **The transfer deadline**, so that the wait cannot outlast it. The
    ///    deadline POLICY is not duplicated here: this only bounds the wait, and
    ///    the next `connect` is what turns an elapsed deadline into
    ///    [`CURLcode::OperationTimedout`] -- through [`Ballers::schedule`], the
    ///    one place that decision lives.
    /// 4. **An explicit wake** on [`Self::waker`].
    ///
    /// The wait is additionally bounded by a ceiling, 10 milliseconds when no
    /// candidate has a socket to wait on and 1000 when one does. Those are the
    /// C's own two numbers from the equivalent bound in `Curl_conn_connect`
    /// (`lib/cfilters.c:577`), and the small one matters: a candidate making
    /// progress on buffered data alone still gets stepped promptly.
    ///
    /// `biased` orders the arms so that an explicit wake is observed before a
    /// timer that came due in the same turn, which makes the loop's behaviour
    /// reproducible rather than dependent on a random poll order.
    ///
    /// # Errors
    ///
    /// Whatever [`ConnFilter::connect`] reports, plus a failure of the wait
    /// itself.
    ///
    /// # Panics
    ///
    /// Requires a `tokio` runtime with the time driver, as every wait in
    /// [`crate::conn::select`] does.
    #[allow(dead_code)] // No consumer yet; conn/mod.rs drives the connect with it.
    pub(crate) async fn race(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
    ) -> CurlResult<()> {
        loop {
            if self.connect(cx)? {
                return Ok(());
            }

            let mut ps = EasyPollset::new();
            self.adjust_pollset(cx, &mut ps)?;
            let mut pfds = PollFds::new();
            pfds.add_ps(&ps);
            let ready = !pfds.is_empty();

            let ceiling: TimeDiff = if ready { 1000 } else { 10 };
            let mut wait = ceiling;
            if let Some(delay) = self.ballers.remaining_delay_ms(cx.now()) {
                wait = wait.min(delay);
            }
            // Zero is "no limit" and a negative value is already handled by the
            // connect above, so only a positive deadline bounds the wait.
            let overall = self.seams.deadline.time_left_ms();
            if overall > 0 {
                wait = wait.min(overall);
            }
            let wait = wait.max(0);
            let span = mstotv(wait).unwrap_or(Duration::ZERO);
            let wake = Rc::clone(&self.wake);

            tokio::select! {
                biased;
                () = wake.notified() => {}
                outcome = pfds.poll(wait), if ready => {
                    outcome.map_err(Error::from)?;
                }
                () = tokio::time::sleep(span) => {}
            }
        }
    }
}

impl ConnFilter for HappyEyeballs {
    /// The `name` member: `"HAPPY-EYEBALLS"` (`lib/cf-ip-happy.c:904`).
    fn trace_name(&self) -> &'static str {
        HAPPY_EYEBALLS_FILTER_NAME
    }

    /// The `flags` member: **exactly `0`** (`lib/cf-ip-happy.c:905`).
    ///
    /// Written out rather than left to the trait default, because the zero is
    /// load-bearing and surprising. This filter does NOT declare
    /// [`crate::conn::filters::CF_TYPE_IP_CONNECT`] even though its whole
    /// purpose is to obtain an IP connection: the capability belongs to the
    /// winner it installs, and declaring it here would stop
    /// `Curl_conn_is_ip_connected`'s upward walk at this filter, which reports
    /// "not connected" for a filter that provides the connection and is not
    /// itself connected.
    fn cf_type(&self) -> CfType {
        CfType::NONE
    }

    fn base(&self) -> &FilterBase {
        &self.base
    }

    fn base_mut(&mut self) -> &mut FilterBase {
        &mut self.base
    }

    /// `cf_ip_happy_destroy` (`lib/cf-ip-happy.c:890-901`).
    ///
    /// Does not chain, as the contract requires: the caller has already severed
    /// the link. The candidates are this filter's own and are destroyed here.
    fn destroy(&mut self, cx: &mut CallCtx<'_, '_>) {
        trc!(
            cx,
            self.trace_filter(),
            self.base.sockindex().as_i32(),
            "destroy"
        );
        self.ballers.clear(cx);
    }

    /// `cf_ip_happy_connect` (`lib/cf-ip-happy.c:762-825`).
    ///
    /// The `SCFST_INIT` arm ends in a `FALLTHROUGH()` into `SCFST_WAITING`, so
    /// starting the race and taking its first step happen in ONE call. That is
    /// not cosmetic: a race whose first attempt would connect immediately -- a
    /// Unix socket, an in-memory transport -- completes without ever needing a
    /// second call.
    ///
    /// # Errors
    ///
    /// As [`Self::start_connect`] and [`Self::wait_for_winner`].
    fn connect(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<bool> {
        if self.base.is_connected() {
            return Ok(true);
        }
        match self.state {
            ConnectState::Init => {
                // `DEBUGASSERT(CURL_SOCKET_BAD == Curl_conn_cf_get_socket(cf,
                //  data)); DEBUGASSERT(!cf->connected);` -- the socket comes from
                // the winner's chain, and in `Init` there is no winner to have
                // installed one.
                debug_assert!(
                    !self.base.has_next(),
                    "a filter in Init must have no installed winner"
                );
                self.start_connect(cx)?;
                self.state = ConnectState::Waiting;
                // `FALLTHROUGH();`
                self.wait_for_winner(cx)
            }
            ConnectState::Waiting => self.wait_for_winner(cx),
            ConnectState::Done => Ok(true),
        }
    }

    /// `cf_ip_happy_close` (`lib/cf-ip-happy.c:828-842`).
    ///
    /// **Deliberately destructive, and this differs from every other filter's
    /// close.** The generic contract is that a close clears state and leaves the
    /// chain installed so it may be connected again
    /// (`lib/cfilters.h:424-425`); here the installed winner is closed AND
    /// discarded, and the state machine returns to [`ConnectState::Init`]. That
    /// is correct precisely because the winner was chosen by a race: connecting
    /// again means racing again, and the addresses may by then be different.
    fn close(&mut self, cx: &mut CallCtx<'_, '_>) {
        trc!(
            cx,
            self.trace_filter(),
            self.base.sockindex().as_i32(),
            "close"
        );
        self.ballers.clear(cx);
        self.base.set_connected(false);
        self.state = ConnectState::Init;

        // `if(cf->next) { cf->next->cft->do_close(cf->next, data);
        //  Curl_conn_cf_discard_chain(&cf->next, data); }` -- closed first so
        // the winner can say goodbye, then destroyed.
        if let Some(next) = self.base.next_mut() {
            next.close(cx);
        }
        let installed = self.base.take_next();
        discard_chain_from(cx, installed);
    }

    /// `cf_ip_happy_shutdown` (`lib/cf-ip-happy.c:730-746`).
    ///
    /// A CONNECTED filter is done at once: there is nothing racing, and the
    /// installed winner is shut down by the chain driver in its own turn. While
    /// racing, every candidate is shut down; see [`Ballers::shutdown`] for why a
    /// failure counts as done and why the overall result is always success.
    fn shutdown(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<bool> {
        if self.base.is_connected() {
            return Ok(true);
        }
        let done = self.ballers.shutdown(cx);
        // `CURL_TRC_CF(data, cf, "shutdown -> %d, done=%d", result, *done)` --
        // `result` is unconditionally `CURLE_OK` here, so the zero is the C's.
        trc!(
            cx,
            self.trace_filter(),
            self.base.sockindex().as_i32(),
            "shutdown -> {}, done={}",
            CURLcode::Ok.as_i32(),
            u8::from(done)
        );
        Ok(done)
    }

    /// `cf_ip_happy_adjust_pollset` (`lib/cf-ip-happy.c:748-759`).
    ///
    /// Drives EACH candidate's own subchain rather than passing the pollset to
    /// `next`. That is not a violation of
    /// [`ConnFilter::adjust_pollset`]'s pure-no-op default: a filter owning a
    /// private subchain is the one sanctioned case, because the outer walk
    /// cannot see filters it does not own. Once connected there is nothing to
    /// add -- the installed winner is part of the main chain and the driver
    /// reaches it directly.
    ///
    /// # Errors
    ///
    /// As [`Ballers::pollset`].
    fn adjust_pollset(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        ps: &mut EasyPollset,
    ) -> CurlResult<()> {
        if self.base.is_connected() {
            return Ok(());
        }
        let outcome = self.ballers.pollset(cx, ps);
        let code = match &outcome {
            Ok(()) => CURLcode::Ok,
            Err(error) => error.code(),
        };
        let socks = ps.len();
        trc!(
            cx,
            self.trace_filter(),
            self.base.sockindex().as_i32(),
            "adjust_pollset -> {}, {} socks",
            code.as_i32(),
            socks
        );
        outcome
    }

    /// `cf_ip_happy_data_pending` (`lib/cf-ip-happy.c:844-853`).
    ///
    /// Before a winner exists the question is asked of every live candidate;
    /// afterwards it is delegated to the winner. The C dereferences `cf->next`
    /// unchecked on the second path, relying on "connected implies an installed
    /// winner" -- an invariant [`Self::install_winner`] is the only writer of.
    /// It is asserted here and answered `false` in a release build rather than
    /// panicking.
    fn data_pending(&mut self, cx: &CallCtx<'_, '_>) -> bool {
        if !self.base.is_connected() {
            return self.ballers.pending(cx);
        }
        debug_assert!(
            self.base.has_next(),
            "a connected HAPPY-EYEBALLS filter must have an installed winner"
        );
        match self.base.next_mut() {
            Some(next) => next.data_pending(cx),
            None => false,
        }
    }

    /// `cf_ip_happy_query` (`lib/cf-ip-happy.c:855-888`).
    ///
    /// While racing, three questions are answered by AGGREGATING the candidates
    /// -- the earliest first response and the latest of each connect timer --
    /// because no single candidate is yet the connection. Everything else, and
    /// everything once connected, is delegated to the installed winner.
    ///
    /// # Errors
    ///
    /// [`CURLcode::UnknownOption`] when there is no winner to delegate to, which
    /// is the C's `CURLE_UNKNOWN_OPTION` for a `NULL` `cf->next` -- a SENTINEL
    /// meaning "nobody understood the question" rather than a failure.
    fn query(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        query: CfQuery,
    ) -> CurlResult<CfQueryValue> {
        if !self.base.is_connected() {
            match query {
                CfQuery::ConnectReplyMs => {
                    let reply = self.ballers.min_reply_ms(cx);
                    trc!(
                        cx,
                        self.trace_filter(),
                        self.base.sockindex().as_i32(),
                        "query connect reply: {}ms",
                        reply
                    );
                    return Ok(CfQueryValue::ConnectReplyMs(reply));
                }
                CfQuery::TimerConnect | CfQuery::TimerAppConnect => {
                    let when = self.ballers.max_time(cx, query);
                    return Ok(CfQueryValue::Timer(when));
                }
                // `default: break;` -- every other question falls through to the
                // delegation below even while racing.
                _ => {}
            }
        }
        match self.base.next_mut() {
            Some(next) => next.query(cx, query),
            None => Err(Error::new(CURLcode::UnknownOption)),
        }
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::select::{is_valid_sock, Socket};
    use crate::conn::socket::{
        TRNSPRT_NONE, TRNSPRT_QUIC, TRNSPRT_TCP, TRNSPRT_UDP, TRNSPRT_UNIX,
    };
    use crate::dns::{unix2addr, IpProto, ResolvedSockAddr, SockType};
    use crate::trace::{TraceConfig, TraceLevel, Tracer, WriterSink};
    use crate::util::timeval::TestClock;
    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;
    use std::path::Path;

    // -- the shared event log ---------------------------------------------

    /// An ordered record of what every candidate did.
    ///
    /// A candidate installed in an attempt is owned as
    /// `Pin<Box<dyn ConnFilter>>` and there is no way back to its concrete
    /// type -- deliberately, since abolishing that recovery is the point of the
    /// translation. A shared log is therefore the only way a test can observe
    /// the ORDER of events across two different candidates, which is exactly
    /// what the restart ordering requires.
    type EventLog = Rc<RefCell<Vec<String>>>;

    fn new_log() -> EventLog {
        Rc::new(RefCell::new(Vec::new()))
    }

    fn events(log: &EventLog) -> Vec<String> {
        log.borrow().clone()
    }

    fn clock() -> TestClock {
        TestClock::new(CurlTime::new(1_000, 0))
    }

    // -- addresses ---------------------------------------------------------

    fn v4(text: &str) -> ResolvedAddr {
        ResolvedAddr::tcp(
            text.parse().expect("a valid IPv4 socket address"),
            Some(String::from("example.com")),
        )
    }

    fn v6(text: &str) -> ResolvedAddr {
        ResolvedAddr::tcp(
            text.parse().expect("a valid IPv6 socket address"),
            Some(String::from("example.com")),
        )
    }

    fn unix(path: &str) -> ResolvedAddr {
        unix2addr(Path::new(path), false).expect("a short enough path")
    }

    /// A `SOCK_DGRAM` address, for the transports that would want one.
    fn dgram(text: &str) -> ResolvedAddr {
        ResolvedAddr {
            addr: ResolvedSockAddr::Ip(
                text.parse().expect("a valid socket address"),
            ),
            socktype: SockType::Dgram,
            protocol: IpProto::Udp,
            canonname: None,
            flags: 0,
        }
    }

    /// The key a script is filed under: the address as a candidate sees it.
    fn addr_key(addr: &ResolvedAddr) -> String {
        match &addr.addr {
            ResolvedSockAddr::Ip(ip) => ip.to_string(),
            ResolvedSockAddr::Unix { path, .. } => {
                path.to_string_lossy().into_owned()
            }
        }
    }

    // -- the scripted in-memory candidate ---------------------------------

    /// What one candidate is told to do.
    ///
    /// Every field defaults to the simplest behaviour -- connect on the first
    /// step, one node, no timers, no socket -- so a test states only the part
    /// it is about.
    #[derive(Clone, Debug, Default)]
    struct Script {
        /// How many `Ok(false)` steps before the outcome below.
        connect_steps: usize,
        /// The failure after those steps, or a connection.
        fail_with: Option<CURLcode>,
        /// A provider failure, so no candidate is built at all.
        create_fails: Option<CURLcode>,
        /// How deep the subchain is. Zero and one both mean a single node.
        nodes: usize,
        /// `CF_QUERY_CONNECT_REPLY_MS`, unanswered when absent.
        reply_ms: Option<TimeDiff>,
        /// `CF_QUERY_TIMER_CONNECT`, unanswered when absent.
        timer_connect: Option<CurlTime>,
        /// `CF_QUERY_TIMER_APPCONNECT`, unanswered when absent.
        timer_appconnect: Option<CurlTime>,
        /// `has_data_pending`.
        pending: bool,
        /// How many `Ok(false)` shutdown steps before it reports done.
        shutdown_steps: usize,
        /// Whether the shutdown fails outright.
        shutdown_fails: bool,
        /// A descriptor to register readiness on, if any.
        socket: Option<Socket>,
        /// What `CF_QUERY_IP_INFO` reports.
        remote_ip: String,
        /// Likewise.
        remote_port: u16,
    }

    /// What a candidate has actually done, and what it will do next.
    #[derive(Debug)]
    struct CandidateState {
        script: Script,
        label: String,
        log: EventLog,
        connects: usize,
        closes: usize,
        destroys: usize,
        shutdowns: usize,
        pollsets: usize,
    }

    type Candidate = Rc<RefCell<CandidateState>>;

    impl CandidateState {
        fn note(&self, what: &str) {
            self.log.borrow_mut().push(format!("{what}:{}", self.label));
        }
    }

    /// One node of a candidate's subchain.
    #[derive(Debug)]
    struct MemFilter {
        base: FilterBase,
        state: Candidate,
    }

    impl MemFilter {
        fn new(sockindex: SocketIndex, state: Candidate) -> Self {
            Self {
                base: FilterBase::new(sockindex),
                state,
            }
        }
    }

    impl ConnFilter for MemFilter {
        /// Not a registered trace name, so a candidate traces nothing -- which
        /// keeps the trace assertions below about this module alone.
        fn trace_name(&self) -> &'static str {
            "MEM"
        }

        /// A real candidate declares `CF_TYPE_IP_CONNECT`, and this one does
        /// too, because the winner it becomes is what supplies that capability
        /// to the chain.
        fn cf_type(&self) -> CfType {
            crate::conn::filters::CF_TYPE_IP_CONNECT
        }

        fn base(&self) -> &FilterBase {
            &self.base
        }

        fn base_mut(&mut self) -> &mut FilterBase {
            &mut self.base
        }

        fn destroy(&mut self, _cx: &mut CallCtx<'_, '_>) {
            let mut state = self.state.borrow_mut();
            state.destroys += 1;
            state.note("destroy");
        }

        fn connect(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<bool> {
            // A stacked node drives what is beneath it first, as every real
            // multi-node candidate does.
            if let Some(next) = self.base.next_mut() {
                if !next.connect(cx)? {
                    return Ok(false);
                }
            }
            let outcome = {
                let mut state = self.state.borrow_mut();
                state.connects += 1;
                state.note("connect");
                if state.script.connect_steps > 0 {
                    state.script.connect_steps -= 1;
                    Ok(false)
                } else if let Some(code) = state.script.fail_with {
                    Err(Error::new(code))
                } else {
                    Ok(true)
                }
            };
            if matches!(outcome, Ok(true)) {
                self.base.set_connected(true);
            }
            outcome
        }

        fn close(&mut self, cx: &mut CallCtx<'_, '_>) {
            {
                let mut state = self.state.borrow_mut();
                state.closes += 1;
                state.note("close");
            }
            self.base.set_connected(false);
            if let Some(next) = self.base.next_mut() {
                next.close(cx);
            }
        }

        fn shutdown(&mut self, _cx: &mut CallCtx<'_, '_>) -> CurlResult<bool> {
            let mut state = self.state.borrow_mut();
            state.shutdowns += 1;
            state.note("shutdown");
            if state.script.shutdown_fails {
                return Err(Error::new(CURLcode::SendError));
            }
            if state.script.shutdown_steps > 0 {
                state.script.shutdown_steps -= 1;
                return Ok(false);
            }
            Ok(true)
        }

        fn adjust_pollset(
            &mut self,
            cx: &mut CallCtx<'_, '_>,
            ps: &mut EasyPollset,
        ) -> CurlResult<()> {
            let socket = {
                let mut state = self.state.borrow_mut();
                state.pollsets += 1;
                state.note("pollset");
                state.script.socket
            };
            match socket {
                Some(sock) if is_valid_sock(sock) => ps
                    .set(sock, true, true, cx.tracer_mut())
                    .map_err(Error::from),
                _ => Ok(()),
            }
        }

        fn data_pending(&mut self, _cx: &CallCtx<'_, '_>) -> bool {
            self.state.borrow().script.pending
        }

        fn query(
            &mut self,
            cx: &mut CallCtx<'_, '_>,
            query: CfQuery,
        ) -> CurlResult<CfQueryValue> {
            let script = self.state.borrow().script.clone();
            match query {
                CfQuery::ConnectReplyMs => match script.reply_ms {
                    Some(ms) => Ok(CfQueryValue::ConnectReplyMs(ms)),
                    None => Err(Error::new(CURLcode::UnknownOption)),
                },
                CfQuery::TimerConnect => match script.timer_connect {
                    Some(at) => Ok(CfQueryValue::Timer(at)),
                    None => Err(Error::new(CURLcode::UnknownOption)),
                },
                CfQuery::TimerAppConnect => match script.timer_appconnect {
                    Some(at) => Ok(CfQueryValue::Timer(at)),
                    None => Err(Error::new(CURLcode::UnknownOption)),
                },
                CfQuery::IpInfo => Ok(CfQueryValue::IpInfo {
                    is_ipv6: script.remote_ip.contains(':'),
                    quad: crate::conn::filters::IpQuadruple {
                        remote_ip: script.remote_ip,
                        local_ip: String::from("127.0.0.1"),
                        remote_port: script.remote_port,
                        local_port: 51_000,
                        transport: Transport::Tcp,
                    },
                }),
                _ => match self.base.next_mut() {
                    Some(next) => next.query(cx, query),
                    None => Err(Error::new(CURLcode::UnknownOption)),
                },
            }
        }
    }

    // -- the injected factory ---------------------------------------------

    /// A [`TransportProvider`] over scripted in-memory candidates.
    ///
    /// The Rust successor of the `UNITTESTS`-only
    /// `Curl_debug_set_transport_provider` seam, and the reason no test here
    /// opens a socket, resolves a name, or waits on a real clock.
    #[derive(Debug)]
    struct Factory {
        scripts: RefCell<HashMap<String, VecDeque<Script>>>,
        created: RefCell<Vec<(String, Candidate)>>,
        creations: Cell<usize>,
        log: EventLog,
    }

    impl Factory {
        fn new(log: &EventLog) -> Self {
            Self {
                scripts: RefCell::new(HashMap::new()),
                created: RefCell::new(Vec::new()),
                creations: Cell::new(0),
                log: Rc::clone(log),
            }
        }

        /// Files `script` under `addr`. Several scripts for one address are
        /// consumed in order, so a RESTART can behave differently from the
        /// first attempt; the last one is reused once the queue is down to it.
        fn script(&self, addr: &ResolvedAddr, script: Script) {
            self.scripts
                .borrow_mut()
                .entry(addr_key(addr))
                .or_default()
                .push_back(script);
        }

        fn next_script(&self, key: &str) -> Script {
            let mut scripts = self.scripts.borrow_mut();
            match scripts.get_mut(key) {
                Some(queue) if queue.len() > 1 => {
                    queue.pop_front().unwrap_or_default()
                }
                Some(queue) => queue.front().cloned().unwrap_or_default(),
                None => Script::default(),
            }
        }

        /// Every candidate ever built, in creation order.
        fn created(&self) -> Vec<(String, Candidate)> {
            self.created.borrow().clone()
        }

        /// The candidate built for `addr` at `nth` creation of it, if any.
        fn candidate(&self, addr: &ResolvedAddr, nth: usize) -> Candidate {
            let key = addr_key(addr);
            let created = self.created.borrow();
            let mut seen = 0_usize;
            for (built, state) in created.iter() {
                if *built == key {
                    if seen == nth {
                        return Rc::clone(state);
                    }
                    seen += 1;
                }
            }
            panic!("no candidate {nth} was built for {key}");
        }
    }

    impl TransportProvider for Factory {
        fn create(
            &self,
            addr: &ResolvedAddr,
            sockindex: SocketIndex,
        ) -> CurlResult<FilterLink> {
            let key = addr_key(addr);
            let script = self.next_script(&key);
            let ordinal = self.creations.get() + 1;
            self.creations.set(ordinal);
            let label = format!("{key}#{ordinal}");

            if let Some(code) = script.create_fails {
                self.log.borrow_mut().push(format!("create-failed:{label}"));
                return Err(Error::new(code));
            }
            self.log.borrow_mut().push(format!("create:{label}"));

            let nodes = script.nodes.max(1);
            let state: Candidate = Rc::new(RefCell::new(CandidateState {
                script,
                label: label.clone(),
                log: Rc::clone(&self.log),
                connects: 0,
                closes: 0,
                destroys: 0,
                shutdowns: 0,
                pollsets: 0,
            }));
            self.created.borrow_mut().push((key, Rc::clone(&state)));

            // Built from the bottom up, so the head is the node the race drives
            // and every lower node is reached through it. The head carries the
            // script; the lower nodes connect immediately, which is what a real
            // stacked candidate's socket does before its upper layers negotiate.
            let mut lower_chain: Option<FilterLink> = None;
            for depth in (1..nodes).rev() {
                let lower: Candidate = Rc::new(RefCell::new(CandidateState {
                    script: Script::default(),
                    label: format!("{label}/{depth}"),
                    log: Rc::clone(&self.log),
                    connects: 0,
                    closes: 0,
                    destroys: 0,
                    shutdowns: 0,
                    pollsets: 0,
                }));
                let mut node = MemFilter::new(sockindex, lower);
                node.base.set_next(lower_chain.take());
                lower_chain = Some(link(node));
            }
            let mut head = MemFilter::new(sockindex, Rc::clone(&state));
            head.base.set_next(lower_chain);
            Ok(link(head))
        }
    }

    // -- the injected connection metadata ---------------------------------

    /// Every fact [`ConnMeta`] names, settable and observable.
    #[derive(Debug)]
    struct TestMeta {
        ip_version: Cell<IpVersion>,
        delay_ms: Cell<TimeDiff>,
        addrs: RefCell<Option<Vec<ResolvedAddr>>>,
        host: RefCell<String>,
        connect_to_host: RefCell<Option<String>>,
        unix_path: RefCell<Option<String>>,
        secondary_port: Cell<u16>,
        connect_to_port: Cell<Option<u16>>,
        remote_port: Cell<u16>,
        socks_proxy: RefCell<Option<String>>,
        http_proxy: RefCell<Option<String>>,
        ssh: Cell<bool>,
        os_timeout: Cell<bool>,
        started_at: Cell<CurlTime>,
        connections: Cell<usize>,
        app_connect_marks: Cell<usize>,
    }

    impl Default for TestMeta {
        fn default() -> Self {
            Self {
                ip_version: Cell::new(IpVersion::Whatever),
                delay_ms: Cell::new(CURL_HET_DEFAULT),
                addrs: RefCell::new(Some(Vec::new())),
                host: RefCell::new(String::from("example.com")),
                connect_to_host: RefCell::new(None),
                unix_path: RefCell::new(None),
                secondary_port: Cell::new(2_121),
                connect_to_port: Cell::new(None),
                remote_port: Cell::new(80),
                socks_proxy: RefCell::new(None),
                http_proxy: RefCell::new(None),
                ssh: Cell::new(false),
                os_timeout: Cell::new(false),
                started_at: Cell::new(CurlTime::new(1_000, 0)),
                connections: Cell::new(0),
                app_connect_marks: Cell::new(0),
            }
        }
    }

    impl ConnMeta for TestMeta {
        fn ip_version(&self) -> IpVersion {
            self.ip_version.get()
        }

        fn happy_eyeballs_timeout_ms(&self) -> TimeDiff {
            self.delay_ms.get()
        }

        fn resolved(
            &self,
            _sockindex: SocketIndex,
        ) -> Option<Vec<ResolvedAddr>> {
            self.addrs.borrow().clone()
        }

        fn host_name(&self) -> String {
            self.host.borrow().clone()
        }

        fn connect_to_host(&self) -> Option<String> {
            self.connect_to_host.borrow().clone()
        }

        fn unix_socket_path(&self) -> Option<String> {
            self.unix_path.borrow().clone()
        }

        fn secondary_port(&self) -> u16 {
            self.secondary_port.get()
        }

        fn connect_to_port(&self) -> Option<u16> {
            self.connect_to_port.get()
        }

        fn remote_port(&self) -> u16 {
            self.remote_port.get()
        }

        fn socks_proxy_name(&self) -> Option<String> {
            self.socks_proxy.borrow().clone()
        }

        fn http_proxy_name(&self) -> Option<String> {
            self.http_proxy.borrow().clone()
        }

        fn is_ssh_family(&self) -> bool {
            self.ssh.get()
        }

        fn os_error_is_timeout(&self) -> bool {
            self.os_timeout.get()
        }

        fn transfer_started_at(&self) -> CurlTime {
            self.started_at.get()
        }

        fn note_connection(&self) {
            self.connections.set(self.connections.get() + 1);
        }

        fn mark_app_connect_time(&self) {
            self.app_connect_marks.set(self.app_connect_marks.get() + 1);
        }
    }

    /// Every `Curl_expire` and `Curl_expire_done` this module made.
    #[derive(Debug, Default)]
    struct TestExpiry {
        armed: RefCell<Vec<(TimeDiff, TimerId)>>,
        disarmed: RefCell<Vec<TimerId>>,
    }

    impl ExpireScheduler for TestExpiry {
        fn expire(&self, timeout_ms: TimeDiff, timer: TimerId) {
            self.armed.borrow_mut().push((timeout_ms, timer));
        }

        fn expire_done(&self, timer: TimerId) {
            self.disarmed.borrow_mut().push(timer);
        }
    }

    /// `Curl_timeleft_ms`, under the test's control.
    #[derive(Debug, Default)]
    struct TestDeadline {
        left: Cell<TimeDiff>,
    }

    impl Deadline for TestDeadline {
        fn time_left_ms(&self) -> TimeDiff {
            self.left.get()
        }
    }

    // -- the rig -----------------------------------------------------------

    /// Everything a test injects except the clock, which a test owns so that
    /// [`CallCtx`] can borrow it.
    #[derive(Debug)]
    struct Rig {
        meta: Rc<TestMeta>,
        expiry: Rc<TestExpiry>,
        deadline: Rc<TestDeadline>,
        factory: Rc<Factory>,
        log: EventLog,
    }

    impl Rig {
        fn new() -> Self {
            let log = new_log();
            let deadline = TestDeadline::default();
            // A generous but FINITE budget, so that the fold in
            // `Ballers::schedule` is exercised on its ordinary path.
            deadline.left.set(30_000);
            Self {
                meta: Rc::new(TestMeta::default()),
                expiry: Rc::new(TestExpiry::default()),
                deadline: Rc::new(deadline),
                factory: Rc::new(Factory::new(&log)),
                log,
            }
        }

        fn addrs(&self, addrs: &[ResolvedAddr]) {
            *self.meta.addrs.borrow_mut() = Some(addrs.to_vec());
        }

        /// A registry whose only row is `transport`, served by the scripted
        /// factory. Built with the row builder rather than by mutating a global,
        /// which is the whole point of the injected table.
        fn seams(&self, transport: Transport) -> HappyEyeballsSeams {
            let registry = TransportRegistry::new()
                .with_row(transport, Rc::clone(&self.factory) as _);
            HappyEyeballsSeams {
                meta: Rc::clone(&self.meta) as _,
                deadline: Rc::clone(&self.deadline) as _,
                expiry: Rc::clone(&self.expiry) as _,
                registry: Rc::new(registry),
            }
        }

        fn filter(
            &self,
            cx: &mut CallCtx<'_, '_>,
            transport: Transport,
        ) -> HappyEyeballs {
            HappyEyeballs::new(
                cx,
                transport,
                SocketIndex::First,
                Some(ConnId::new(7)),
                self.seams(transport),
            )
            .expect("the rig registers a provider for this transport")
        }
    }

    /// A tracer that captures everything, with this filter verbose.
    fn tracing_config() -> TraceConfig {
        let mut config = TraceConfig::new();
        config.set_filter_level(TraceFilter::IpHappy, TraceLevel::Info);
        config
    }

    /// A dual-stack answer: two addresses of each family, interleaved, in an
    /// order that is deliberately NOT sorted.
    fn dual_stack() -> Vec<ResolvedAddr> {
        vec![
            v4("192.0.2.9:80"),
            v6("[2001:db8::9]:80"),
            v4("192.0.2.1:80"),
            v6("[2001:db8::1]:80"),
        ]
    }

    // -- 1. the constants that cross a boundary ---------------------------

    /// The three `CURL_IPRESOLVE_*` integers are the public ABI's and are the
    /// same fact as [`IpVersion`] (`include/curl/curl.h:2297-2303`).
    #[test]
    fn iprresolve_integers_match_ip_version() {
        assert_eq!(CURL_IPRESOLVE_WHATEVER, 0);
        assert_eq!(CURL_IPRESOLVE_V4, 1);
        assert_eq!(CURL_IPRESOLVE_V6, 2);
        assert_eq!(IpVersion::Whatever.as_i32(), CURL_IPRESOLVE_WHATEVER);
        assert_eq!(IpVersion::V4.as_i32(), CURL_IPRESOLVE_V4);
        assert_eq!(IpVersion::V6.as_i32(), CURL_IPRESOLVE_V6);
        assert_eq!(IpVersion::from_i32(CURL_IPRESOLVE_V6), Some(IpVersion::V6));
        // `CURL_HET_DEFAULT 200L` (`include/curl/curl.h:967`).
        assert_eq!(CURL_HET_DEFAULT, 200);
    }

    /// The transport integers are `TRNSPRT_*` (`lib/urldata.h:567-571`), with 1
    /// and 2 retired and left unassigned.
    #[test]
    fn the_transport_integers_match_the_c() {
        assert_eq!(Transport::None.as_u8(), TRNSPRT_NONE);
        assert_eq!(Transport::Tcp.as_u8(), TRNSPRT_TCP);
        assert_eq!(Transport::Udp.as_u8(), TRNSPRT_UDP);
        assert_eq!(Transport::Quic.as_u8(), TRNSPRT_QUIC);
        assert_eq!(Transport::Unix.as_u8(), TRNSPRT_UNIX);
        assert_eq!(Transport::from_u8(1), None);
        assert_eq!(Transport::from_u8(2), None);
    }

    /// Timer 5 and timer 6 are index-aligned with their names
    /// (`lib/urldata.h:886-905`, `lib/curl_trc.c:281-296`), and the two
    /// spellings differ in exactly one character class.
    #[test]
    fn timer_identities_are_index_aligned_with_their_names() {
        assert_eq!(EXPIRE_HAPPY_EYEBALLS_DNS, 5);
        assert_eq!(EXPIRE_HAPPY_EYEBALLS, 6);
        assert_eq!(
            TimerId::ALL[usize::from(EXPIRE_HAPPY_EYEBALLS_DNS)].name(),
            "HAPPY_EYEBALLS_DNS"
        );
        assert_eq!(
            TimerId::ALL[usize::from(EXPIRE_HAPPY_EYEBALLS)].name(),
            "HAPPY_EYEBALLS"
        );
        // Underscores in the timer, a hyphen in the filter. Both are frozen
        // output and neither may be regularised into the other.
        assert_eq!(HAPPY_EYEBALLS_FILTER_NAME, "HAPPY-EYEBALLS");
        assert_ne!(HAPPY_EYEBALLS_FILTER_NAME, TimerId::HappyEyeballs.name());
    }

    /// `struct Curl_cftype Curl_cft_ip_happy` (`lib/cf-ip-happy.c:903-919`):
    /// the name, **flags of exactly zero**, and `CURL_LOG_LVL_NONE`.
    #[test]
    fn the_filter_identity_matches_the_c_table() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let rig = Rig::new();
        let filter = rig.filter(&mut cx, Transport::Tcp);

        assert_eq!(filter.trace_name(), "HAPPY-EYEBALLS");
        assert_eq!(filter.cf_type(), CfType::NONE);
        assert_eq!(filter.cf_type().bits(), 0);
        assert!(filter.cf_type().is_empty());
        assert!(
            !filter
                .cf_type()
                .intersects(crate::conn::filters::CF_TYPE_IP_CONNECT),
            "the winner supplies IP_CONNECT, never this filter"
        );
        assert_eq!(HAPPY_EYEBALLS_LOG_LEVEL, CURL_LOG_LVL_NONE);
        assert_eq!(
            filter.trace_filter(),
            Some(TraceFilter::IpHappy),
            "the name must resolve to a registered trace identity"
        );
    }

    // -- 2. the provider table --------------------------------------------

    /// The C gates its UDP row on `!CURL_DISABLE_TFTP`, and TFTP is out of
    /// implementation scope, so no generic UDP transport is advertised -- and a
    /// substitution cannot invent the row either.
    #[test]
    fn no_udp_provider_is_advertised() {
        let registry = TransportRegistry::sockets(
            SocketHooks::default(),
            SocketSettings::default(),
        );
        assert!(
            registry.has_row(Transport::Tcp),
            "TCP is unconditional in the C table"
        );
        assert!(registry.provider(Transport::Tcp).is_some());
        assert!(
            !registry.has_row(Transport::Udp),
            "a UDP row would offer a transport with no protocol to use it"
        );
        assert!(registry.provider(Transport::Udp).is_none());

        // `Curl_debug_set_transport_provider` finds no matching row and does
        // nothing, which is what its loop does in the C.
        let log = new_log();
        let mut registry = registry;
        let installed =
            registry.set_provider(Transport::Udp, Rc::new(Factory::new(&log)));
        assert!(!installed);
        assert!(registry.provider(Transport::Udp).is_none());

        // And a datagram address in hand changes nothing: the absence is a
        // property of the TABLE, not of the address that would have been raced.
        let tftp = dgram("192.0.2.1:69");
        assert_eq!(tftp.socktype, SockType::Dgram);
        assert_eq!(tftp.protocol, IpProto::Udp);
        assert!(registry.provider(Transport::Udp).is_none());
    }

    /// `#ifdef USE_UNIX_SOCKETS` and the `USE_HTTP3` gate, as this build
    /// resolves them.
    #[test]
    fn the_socket_table_gates_unix_and_quic_the_way_the_c_does() {
        let registry = TransportRegistry::sockets(
            SocketHooks::default(),
            SocketSettings::default(),
        );
        assert_eq!(registry.has_row(Transport::Unix), cfg!(unix));
        assert_eq!(
            registry.provider(Transport::Unix).is_some(),
            cfg!(unix),
            "the Unix row is filled wherever it exists"
        );
        assert_eq!(
            registry.has_row(Transport::Quic),
            cfg!(feature = "http3"),
            "the QUIC row exists exactly when HTTP/3 does"
        );
        assert!(
            registry.provider(Transport::Quic).is_none(),
            "the QUIC provider is HTTP/3's to install, not this module's"
        );

        // And it IS installable where the row exists, which is the seam
        // `crate::protocols::http3` uses.
        let log = new_log();
        let mut registry = registry;
        assert_eq!(
            registry.set_provider(Transport::Quic, Rc::new(Factory::new(&log))),
            cfg!(feature = "http3")
        );
        assert_eq!(
            registry.provider(Transport::Quic).is_some(),
            cfg!(feature = "http3")
        );
    }

    /// `get_cf_create` returning `NULL` is
    /// [`CURLcode::UnsupportedProtocol`], with the C's own trace line
    /// (`lib/cf-ip-happy.c:968-972`).
    #[test]
    fn an_unregistered_transport_is_unsupported_protocol() {
        let clock = clock();
        let config = tracing_config();
        let mut sink = WriterSink::new(Vec::new());
        let mut tracer = Tracer::new(&config, &mut sink);
        tracer.set_verbose(true);
        let mut cx = CallCtx::new(&clock).with_tracer(&mut tracer);

        let rig = Rig::new();
        // A registry that serves TCP only, asked for UDP.
        let seams = rig.seams(Transport::Tcp);
        let outcome = HappyEyeballs::new(
            &mut cx,
            Transport::Udp,
            SocketIndex::First,
            Some(ConnId::new(7)),
            seams,
        );
        let error = outcome.expect_err("UDP has no provider in this registry");
        assert_eq!(error.code(), CURLcode::UnsupportedProtocol);

        // `cx` and `tracer` are not used again, so the borrow of `sink`
        // ends here and the buffer can be taken back.
        let rendered = String::from_utf8(sink.into_inner())
            .expect("the trace output is text");
        assert!(
            rendered.contains("unsupported transport type 4"),
            "the C's own wording, with the TRNSPRT_UDP integer: {rendered}"
        );
    }

    // -- 3. address iteration ---------------------------------------------

    /// `struct cf_ai_iter`'s three operations (`lib/cf-ip-happy.c:105-157`),
    /// including that `has_more` does NOT move the cursor and that an exhausted
    /// iterator stays exhausted.
    #[test]
    fn the_address_iterator_reproduces_the_c_cursor() {
        let mut iter = AddrIter::new(
            vec![v4("192.0.2.1:80"), v4("192.0.2.2:80")],
            AddressFamily::Inet,
        );
        assert!(!iter.started(), "n < 0 before anything is yielded");
        assert!(iter.has_more());
        assert!(iter.has_more(), "asking twice must not consume anything");

        let first = iter.next_addr().expect("the first address");
        assert_eq!(first.printable_address(), "192.0.2.1");
        assert!(iter.started());
        assert!(iter.has_more());

        let second = iter.next_addr().expect("the second address");
        assert_eq!(second.printable_address(), "192.0.2.2");
        assert!(!iter.has_more(), "exhausted");
        assert!(iter.next_addr().is_none());
        assert!(
            iter.next_addr().is_none(),
            "an exhausted iterator yields nothing for ever after"
        );
        assert!(!iter.has_more());

        // A suppressed family still names itself, which the alternation reads
        // unconditionally.
        let empty = AddrIter::empty(AddressFamily::Inet6);
        assert_eq!(empty.family, AddressFamily::Inet6);
        assert!(!empty.started());
        assert!(!empty.has_more());
    }

    /// The resolver's order is behaviour: within each family the addresses are
    /// tried in the order they arrived, never sorted and never deduplicated.
    #[test]
    fn resolver_order_is_preserved_within_each_family() {
        // Deliberately unsorted, and with a duplicate.
        let addrs = vec![
            v4("192.0.2.9:80"),
            v4("192.0.2.1:80"),
            v4("192.0.2.9:80"),
            v6("[2001:db8::9]:80"),
            v6("[2001:db8::1]:80"),
        ];
        let ballers = Ballers::init(
            IpVersion::Whatever,
            &addrs,
            Rc::new(Factory::new(&new_log())),
            Transport::Tcp,
            CURL_HET_DEFAULT,
        )
        .expect("a dual-stack list initialises");

        let v4_order: Vec<String> = ballers
            .addr_iter
            .addrs
            .iter()
            .map(ResolvedAddr::printable_address)
            .collect();
        assert_eq!(v4_order, ["192.0.2.9", "192.0.2.1", "192.0.2.9"]);
        let v6_order: Vec<String> = ballers
            .ipv6_iter
            .addrs
            .iter()
            .map(ResolvedAddr::printable_address)
            .collect();
        assert_eq!(v6_order, ["2001:db8::9", "2001:db8::1"]);
    }

    /// `bs->last_attempt_ai_family = AF_INET; /* so AF_INET6 is next */`
    /// (`lib/cf-ip-happy.c:307`) -- the whole of the IPv6-first policy.
    #[test]
    fn whatever_starts_with_ipv6_because_the_sentinel_is_ipv4() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let rig = Rig::new();
        let addrs = dual_stack();
        rig.addrs(&addrs);
        // Nothing connects, so the race keeps starting attempts.
        for addr in &addrs {
            rig.factory.script(
                addr,
                Script {
                    connect_steps: 99,
                    ..Script::default()
                },
            );
        }
        let mut filter = rig.filter(&mut cx, Transport::Tcp);
        assert!(!filter.connect(&mut cx).expect("the race starts"));

        assert_eq!(
            rig.factory.created().len(),
            1,
            "exactly one attempt is started per pass"
        );
        assert_eq!(
            rig.factory.created()[0].0,
            "[2001:db8::9]:80",
            "the FIRST attempt is IPv6, and it is the first IPv6 address"
        );
    }

    /// `CURL_IPRESOLVE_V4` initialises the IPv6 iterator over `NULL`
    /// (`lib/cf-ip-happy.c:330-333`), so no IPv6 attempt can ever start.
    #[test]
    fn v4_only_never_starts_an_ipv6_attempt() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let rig = Rig::new();
        rig.meta.ip_version.set(IpVersion::V4);
        rig.meta.delay_ms.set(0);
        let addrs = dual_stack();
        rig.addrs(&addrs);
        for addr in &addrs {
            rig.factory.script(
                addr,
                Script {
                    connect_steps: 99,
                    ..Script::default()
                },
            );
        }
        let mut filter = rig.filter(&mut cx, Transport::Tcp);
        // A zero delay makes every remaining address eligible at once, so one
        // call drains the family.
        let _ = filter.connect(&mut cx).expect("the race starts");

        let started: Vec<String> = rig
            .factory
            .created()
            .into_iter()
            .map(|(key, _)| key)
            .collect();
        assert_eq!(started, ["192.0.2.9:80", "192.0.2.1:80"]);
    }

    /// The mirror image: `CURL_IPRESOLVE_V6` empties the IPv4 stream
    /// (`lib/cf-ip-happy.c:325-328`).
    #[test]
    fn v6_only_never_starts_an_ipv4_attempt() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let rig = Rig::new();
        rig.meta.ip_version.set(IpVersion::V6);
        rig.meta.delay_ms.set(0);
        let addrs = dual_stack();
        rig.addrs(&addrs);
        for addr in &addrs {
            rig.factory.script(
                addr,
                Script {
                    connect_steps: 99,
                    ..Script::default()
                },
            );
        }
        let mut filter = rig.filter(&mut cx, Transport::Tcp);
        let _ = filter.connect(&mut cx).expect("the race starts");

        let started: Vec<String> = rig
            .factory
            .created()
            .into_iter()
            .map(|(key, _)| key)
            .collect();
        assert_eq!(started, ["[2001:db8::9]:80", "[2001:db8::1]:80"]);
    }

    /// `TRNSPRT_UNIX` races ONE stream of `AF_UNIX` addresses
    /// (`lib/cf-ip-happy.c:312-318`), which
    /// [`crate::dns::split_families`] deliberately drops.
    #[cfg(unix)]
    #[test]
    fn a_unix_transport_races_one_af_unix_stream() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let rig = Rig::new();
        let socket = unix("/tmp/curl-rs-happy.sock");
        let addrs = vec![v4("192.0.2.1:80"), socket.clone()];
        rig.addrs(&addrs);
        rig.factory.script(&socket, Script::default());
        rig.meta
            .unix_path
            .replace(Some(String::from("/tmp/curl-rs-happy.sock")));

        let mut filter = rig.filter(&mut cx, Transport::Unix);
        assert!(
            filter
                .connect(&mut cx)
                .expect("the Unix candidate connects"),
            "one immediate candidate wins in the first call"
        );
        let started: Vec<String> = rig
            .factory
            .created()
            .into_iter()
            .map(|(key, _)| key)
            .collect();
        assert_eq!(
            started,
            ["/tmp/curl-rs-happy.sock"],
            "the IPv4 address in the list is not a Unix socket and is ignored"
        );
    }

    // -- 4. the race ------------------------------------------------------

    /// An IPv6 candidate that connects on its first step wins before any delay
    /// has elapsed, which is the whole point of trying it first.
    #[test]
    fn an_ipv6_candidate_that_connects_at_once_wins_before_any_delay() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let rig = Rig::new();
        let addrs = dual_stack();
        rig.addrs(&addrs);
        rig.factory.script(
            &addrs[1],
            Script {
                remote_ip: String::from("2001:db8::9"),
                remote_port: 80,
                ..Script::default()
            },
        );

        let mut filter = rig.filter(&mut cx, Transport::Tcp);
        assert!(filter.connect(&mut cx).expect("the race completes"));
        assert!(filter.base().is_connected());
        assert_eq!(filter.state, ConnectState::Done);
        assert_eq!(
            rig.factory.created().len(),
            1,
            "no IPv4 attempt was ever needed"
        );
        assert_eq!(rig.meta.connections.get(), 1, "numconnects++");
    }

    /// The second family is tried once `CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS` has
    /// elapsed, and the IPv4 candidate then wins
    /// (`lib/cf-ip-happy.c:400-411`).
    #[test]
    fn an_ipv4_candidate_wins_after_the_delay_starts_the_second_attempt() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let rig = Rig::new();
        let addrs = vec![v6("[2001:db8::9]:80"), v4("192.0.2.9:80")];
        rig.addrs(&addrs);
        // The IPv6 candidate never finishes; the IPv4 one connects at once.
        rig.factory.script(
            &addrs[0],
            Script {
                connect_steps: 99,
                ..Script::default()
            },
        );
        rig.factory.script(&addrs[1], Script::default());

        let mut filter = rig.filter(&mut cx, Transport::Tcp);
        assert!(!filter.connect(&mut cx).expect("the race starts"));
        assert_eq!(rig.factory.created().len(), 1, "IPv6 only, so far");

        // Not yet due: 199 ms of a 200 ms delay.
        clock.advance(Duration::from_millis(199));
        assert!(!filter.connect(&mut cx).expect("still racing"));
        assert_eq!(rig.factory.created().len(), 1, "the delay had not elapsed");

        // Due.
        clock.advance(Duration::from_millis(1));
        assert!(filter.connect(&mut cx).expect("the IPv4 candidate wins"));
        let started: Vec<String> = rig
            .factory
            .created()
            .into_iter()
            .map(|(key, _)| key)
            .collect();
        assert_eq!(started, ["[2001:db8::9]:80", "192.0.2.9:80"]);
    }

    /// A configured delay of ZERO means "eligible at once", not "unset"
    /// (`include/curl/curl.h:967` and the `>=` at `lib/cf-ip-happy.c:405-407`).
    #[test]
    fn a_zero_delay_starts_the_next_attempt_at_once() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let rig = Rig::new();
        rig.meta.delay_ms.set(0);
        let addrs = vec![v6("[2001:db8::9]:80"), v4("192.0.2.9:80")];
        rig.addrs(&addrs);
        for addr in &addrs {
            rig.factory.script(
                addr,
                Script {
                    connect_steps: 99,
                    ..Script::default()
                },
            );
        }

        let mut filter = rig.filter(&mut cx, Transport::Tcp);
        // ONE call, no clock movement at all: both attempts start.
        assert!(!filter.connect(&mut cx).expect("the race starts"));
        assert_eq!(
            rig.factory.created().len(),
            2,
            "a zero delay makes the second address eligible immediately"
        );
    }

    /// The second disjunct of the alternation: IPv6 is tried when NO IPv4
    /// address remains, whatever the last family was
    /// (`lib/cf-ip-happy.c:419-424`).
    #[test]
    fn an_exhausted_family_falls_back_to_the_other() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let rig = Rig::new();
        rig.meta.delay_ms.set(0);
        // One IPv4 address and two IPv6 ones, so IPv4 runs out first.
        let addrs = vec![
            v4("192.0.2.9:80"),
            v6("[2001:db8::9]:80"),
            v6("[2001:db8::1]:80"),
        ];
        rig.addrs(&addrs);
        for addr in &addrs {
            rig.factory.script(
                addr,
                Script {
                    connect_steps: 99,
                    ..Script::default()
                },
            );
        }

        let mut filter = rig.filter(&mut cx, Transport::Tcp);
        assert!(!filter.connect(&mut cx).expect("the race starts"));
        let started: Vec<String> = rig
            .factory
            .created()
            .into_iter()
            .map(|(key, _)| key)
            .collect();
        assert_eq!(
            started,
            ["[2001:db8::9]:80", "192.0.2.9:80", "[2001:db8::1]:80"],
            "IPv6, then IPv4, then IPv6 again once IPv4 has run out"
        );
    }

    /// When two candidates report connected in the same pass, the EARLIER
    /// position in the running list wins -- the walk stops at the first one
    /// (`lib/cf-ip-happy.c:346-374`).
    #[test]
    fn the_first_candidate_in_running_order_wins_a_tie() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let rig = Rig::new();
        rig.meta.delay_ms.set(0);
        let addrs = vec![v6("[2001:db8::9]:80"), v4("192.0.2.9:80")];
        rig.addrs(&addrs);
        // The IPv6 candidate needs one step and the IPv4 one would connect on
        // its FIRST step, so by the pass in which IPv6 reports connected the
        // IPv4 candidate is equally ready. The tie is therefore real.
        rig.factory.script(
            &addrs[0],
            Script {
                connect_steps: 1,
                ..Script::default()
            },
        );
        rig.factory.script(&addrs[1], Script::default());

        let mut filter = rig.filter(&mut cx, Transport::Tcp);
        assert!(filter.connect(&mut cx).expect("a candidate wins"));
        assert_eq!(rig.factory.created().len(), 2, "both were started");

        let v6_state = rig.factory.candidate(&addrs[0], 0);
        let v4_state = rig.factory.candidate(&addrs[1], 0);
        assert_eq!(
            v6_state.borrow().destroys,
            0,
            "the EARLIER candidate in running order wins and is installed"
        );
        assert_eq!(
            v4_state.borrow().destroys,
            1,
            "the loser is destroyed once the winner is declared"
        );
        assert_eq!(
            v4_state.borrow().connects,
            0,
            "and it was never even stepped: the walk stops at the first \
             candidate that reports connected"
        );
    }

    /// Every loser is destroyed exactly once, and its subchain with it
    /// (`lib/cf-ip-happy.c:369-373`).
    #[test]
    fn every_loser_is_closed_and_destroyed_exactly_once() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let rig = Rig::new();
        rig.meta.delay_ms.set(0);
        let addrs = vec![
            v6("[2001:db8::9]:80"),
            v4("192.0.2.9:80"),
            v6("[2001:db8::1]:80"),
        ];
        rig.addrs(&addrs);
        // The first two never finish; the third connects at once.
        rig.factory.script(
            &addrs[0],
            Script {
                connect_steps: 99,
                ..Script::default()
            },
        );
        rig.factory.script(
            &addrs[1],
            Script {
                connect_steps: 99,
                ..Script::default()
            },
        );
        rig.factory.script(&addrs[2], Script::default());

        let mut filter = rig.filter(&mut cx, Transport::Tcp);
        assert!(filter.connect(&mut cx).expect("the third candidate wins"));

        let losers = [
            rig.factory.candidate(&addrs[0], 0),
            rig.factory.candidate(&addrs[1], 0),
        ];
        for loser in &losers {
            assert_eq!(
                loser.borrow().destroys,
                1,
                "each loser is destroyed exactly once"
            );
        }
        let winner = rig.factory.candidate(&addrs[2], 0);
        assert_eq!(winner.borrow().destroys, 0);
    }

    /// The whole of a multi-node candidate is installed, and EVERY node carries
    /// the connection identity and socket index
    /// (`lib/cf-ip-happy.c:213-217`, `:790-791`).
    #[test]
    fn a_multi_node_winner_installs_whole_with_its_metadata() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let rig = Rig::new();
        let addrs = vec![v6("[2001:db8::9]:80")];
        rig.addrs(&addrs);
        rig.factory.script(
            &addrs[0],
            Script {
                nodes: 3,
                ..Script::default()
            },
        );

        let mut filter = rig.filter(&mut cx, Transport::Tcp);
        assert!(filter.connect(&mut cx).expect("the candidate connects"));

        // Walk the installed subchain and check every node.
        let mut node = filter.base().next_ref();
        let mut depth = 0_usize;
        while let Some(current) = node {
            assert_eq!(
                current.base().conn(),
                Some(ConnId::new(7)),
                "node {depth} carries the connection identity"
            );
            assert_eq!(
                current.sockindex(),
                SocketIndex::First,
                "node {depth} carries the socket index"
            );
            depth += 1;
            node = current.base().next_ref();
        }
        assert_eq!(depth, 3, "all three nodes were transferred");
    }

    /// Every address tried and none connected: the reported code is the LAST
    /// failing candidate's, not the first (`lib/cf-ip-happy.c:486-495`).
    #[test]
    fn the_last_failing_candidate_supplies_the_reported_code() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let rig = Rig::new();
        rig.meta.delay_ms.set(0);
        let addrs = vec![v6("[2001:db8::9]:80"), v4("192.0.2.9:80")];
        rig.addrs(&addrs);
        // Started IPv6 first, so IPv6 is first in the running list; its failure
        // must be OVERWRITTEN by the IPv4 one.
        rig.factory.script(
            &addrs[0],
            Script {
                fail_with: Some(CURLcode::SslConnectError),
                ..Script::default()
            },
        );
        rig.factory.script(
            &addrs[1],
            Script {
                fail_with: Some(CURLcode::InterfaceFailed),
                ..Script::default()
            },
        );

        let mut filter = rig.filter(&mut cx, Transport::Tcp);
        let error = filter.connect(&mut cx).expect_err("every address failed");
        assert_eq!(
            error.code(),
            CURLcode::InterfaceFailed,
            "the LAST failure in running order wins"
        );
    }

    /// With no addresses at all the race concludes
    /// [`CURLcode::CouldntConnect`], which is the seed the C starts from
    /// (`lib/cf-ip-happy.c:488`).
    #[test]
    fn an_empty_address_list_is_couldnt_connect() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let rig = Rig::new();
        rig.addrs(&[]);

        let mut filter = rig.filter(&mut cx, Transport::Tcp);
        let error = filter
            .connect(&mut cx)
            .expect_err("there is nothing to connect to");
        assert_eq!(error.code(), CURLcode::CouldntConnect);
        assert!(rig.factory.created().is_empty());
    }

    // -- 5. inconclusive restarts ------------------------------------------

    /// [`CURLcode::WeirdServerReply`] marks a candidate INCONCLUSIVE rather than
    /// terminally failed -- *"we might talk to a restarting server"*
    /// (`lib/cf-ip-happy.c:227-244`).
    #[test]
    fn a_weird_server_reply_is_inconclusive_rather_than_fatal() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let rig = Rig::new();
        let addrs = vec![v6("[2001:db8::9]:80")];
        rig.addrs(&addrs);
        rig.factory.script(
            &addrs[0],
            Script {
                fail_with: Some(CURLcode::WeirdServerReply),
                ..Script::default()
            },
        );

        let mut filter = rig.filter(&mut cx, Transport::Tcp);
        // The only address failed, but inconclusively, so the race is still
        // running rather than concluded.
        assert!(
            !filter
                .connect(&mut cx)
                .expect("an inconclusive failure is not the end"),
            "the race waits to restart rather than reporting a failure"
        );
        let attempt = filter
            .ballers
            .running
            .front()
            .expect("the candidate is still in the running list");
        assert!(attempt.inconclusive);
        assert_eq!(attempt.result, CURLcode::WeirdServerReply);
        // A hard failure by contrast concludes the race at once.
        assert_eq!(
            rig.expiry.armed.borrow().len(),
            1,
            "a retry timer was armed instead"
        );
        assert_eq!(rig.expiry.armed.borrow()[0].1, TimerId::HappyEyeballs);
    }

    /// The remainder of the delay is waited out first, and the retry is
    /// announced with `infof` (`lib/cf-ip-happy.c:475-480`).
    #[test]
    fn an_inconclusive_race_waits_out_the_remaining_delay() {
        let clock = clock();
        let config = tracing_config();
        let mut sink = WriterSink::new(Vec::new());
        let mut tracer = Tracer::new(&config, &mut sink);
        tracer.set_verbose(true);
        let mut cx = CallCtx::new(&clock).with_tracer(&mut tracer);

        let rig = Rig::new();
        let addrs = vec![v6("[2001:db8::9]:80")];
        rig.addrs(&addrs);
        rig.factory.script(
            &addrs[0],
            Script {
                fail_with: Some(CURLcode::WeirdServerReply),
                ..Script::default()
            },
        );

        let mut filter = rig.filter(&mut cx, Transport::Tcp);
        assert!(!filter.connect(&mut cx).expect("still racing"));
        assert_eq!(
            rig.factory.created().len(),
            1,
            "no restart while the delay has time left"
        );
        assert_eq!(
            rig.expiry.armed.borrow()[0].0,
            200,
            "the whole delay remains, because no time has passed"
        );

        // `cx` and `tracer` are not used again, so the borrow of `sink`
        // ends here and the buffer can be taken back.
        let rendered = String::from_utf8(sink.into_inner())
            .expect("the trace output is text");
        assert!(
            rendered
                .contains("connect attempts inconclusive, retrying in 200ms"),
            "the C's own wording: {rendered}"
        );
    }

    /// Once the delay has elapsed the FIRST inconclusive candidate is restarted
    /// (`lib/cf-ip-happy.c:460-472`).
    #[test]
    fn the_first_inconclusive_candidate_is_the_one_restarted() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let rig = Rig::new();
        rig.meta.delay_ms.set(0);
        let addrs = vec![v6("[2001:db8::9]:80"), v4("192.0.2.9:80")];
        rig.addrs(&addrs);
        // Both are inconclusive on their first attempt; the rebuild of the FIRST
        // one connects.
        for addr in &addrs {
            rig.factory.script(
                addr,
                Script {
                    fail_with: Some(CURLcode::WeirdServerReply),
                    ..Script::default()
                },
            );
            rig.factory.script(addr, Script::default());
        }

        let mut filter = rig.filter(&mut cx, Transport::Tcp);
        assert!(
            filter
                .connect(&mut cx)
                .expect("the restarted candidate connects"),
            "a zero delay restarts immediately and the rebuild wins"
        );

        let created: Vec<String> = rig
            .factory
            .created()
            .into_iter()
            .map(|(key, _)| key)
            .collect();
        assert_eq!(
            created,
            ["[2001:db8::9]:80", "192.0.2.9:80", "[2001:db8::9]:80"],
            "the third creation rebuilds the FIRST inconclusive candidate"
        );
    }

    /// *"When restarting, we tear down and existing filter \*after\* we started
    /// up the new one"* (`lib/cf-ip-happy.c:264-266`) -- which is what obtains a
    /// new socket number and probably a new local port.
    #[test]
    fn a_restart_creates_the_replacement_before_destroying_the_previous() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let rig = Rig::new();
        rig.meta.delay_ms.set(0);
        let addrs = vec![v6("[2001:db8::9]:80")];
        rig.addrs(&addrs);
        rig.factory.script(
            &addrs[0],
            Script {
                fail_with: Some(CURLcode::WeirdServerReply),
                ..Script::default()
            },
        );
        rig.factory.script(&addrs[0], Script::default());

        let mut filter = rig.filter(&mut cx, Transport::Tcp);
        assert!(filter.connect(&mut cx).expect("the rebuild connects"));

        let log = events(&rig.log);
        let created_second = log
            .iter()
            .position(|line| line == "create:[2001:db8::9]:80#2")
            .expect("the replacement was created");
        let destroyed_first = log
            .iter()
            .position(|line| line == "destroy:[2001:db8::9]:80#1")
            .expect("the previous candidate was destroyed");
        assert!(
            created_second < destroyed_first,
            "the replacement must exist before the previous one is torn down: \
             {log:?}"
        );
    }

    /// A provider failure during a restart is the C's *"serious failure"* and
    /// aborts the race (`lib/cf-ip-happy.c:469-470`).
    #[test]
    fn a_provider_failure_during_a_restart_aborts() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let rig = Rig::new();
        rig.meta.delay_ms.set(0);
        let addrs = vec![v6("[2001:db8::9]:80")];
        rig.addrs(&addrs);
        rig.factory.script(
            &addrs[0],
            Script {
                fail_with: Some(CURLcode::WeirdServerReply),
                ..Script::default()
            },
        );
        rig.factory.script(
            &addrs[0],
            Script {
                create_fails: Some(CURLcode::OutOfMemory),
                ..Script::default()
            },
        );

        let mut filter = rig.filter(&mut cx, Transport::Tcp);
        let error = filter
            .connect(&mut cx)
            .expect_err("the rebuild could not be created");
        assert_eq!(error.code(), CURLcode::OutOfMemory);
        // The previous subchain was still torn down, exactly once.
        let first = rig.factory.candidate(&addrs[0], 0);
        assert_eq!(first.borrow().destroys, 1);
    }

    // -- 6. the deadline and the timer -------------------------------------

    /// *"a precaution, no need to continue if time already is up"*
    /// (`lib/cf-ip-happy.c:707-711`): a deadline already passed refuses BEFORE
    /// the race is initialised.
    #[test]
    fn a_deadline_already_passed_refuses_before_the_race_starts() {
        let clock = clock();
        let config = tracing_config();
        let mut sink = WriterSink::new(Vec::new());
        let mut tracer = Tracer::new(&config, &mut sink);
        tracer.set_verbose(true);
        let mut cx = CallCtx::new(&clock).with_tracer(&mut tracer);

        let rig = Rig::new();
        rig.deadline.left.set(-1);
        let addrs = dual_stack();
        rig.addrs(&addrs);

        let mut filter = rig.filter(&mut cx, Transport::Tcp);
        let error = filter
            .connect(&mut cx)
            .expect_err("the deadline has passed");
        assert_eq!(error.code(), CURLcode::OperationTimedout);
        assert_eq!(error.message(), "Connection time-out");
        assert!(
            rig.factory.created().is_empty(),
            "no candidate is built at all"
        );
        assert_eq!(
            filter.state,
            ConnectState::Init,
            "the state machine does not advance past a refusal"
        );

        // `cx` and `tracer` are not used again, so the borrow of `sink`
        // ends here and the buffer can be taken back.
        let rendered = String::from_utf8(sink.into_inner())
            .expect("the trace output is text");
        assert!(rendered.contains("Connection time-out"), "{rendered}");
    }

    /// A deadline that passes DURING the race is reported with the elapsed time
    /// since the single transfer started (`lib/cf-ip-happy.c:499-510`).
    #[test]
    fn a_deadline_passing_during_the_race_is_a_timeout() {
        let clock = clock();
        let config = tracing_config();
        let mut sink = WriterSink::new(Vec::new());
        let mut tracer = Tracer::new(&config, &mut sink);
        tracer.set_verbose(true);
        let mut cx = CallCtx::new(&clock).with_tracer(&mut tracer);

        let rig = Rig::new();
        rig.meta.started_at.set(CurlTime::new(999, 950_000));
        let addrs = vec![v6("[2001:db8::9]:80")];
        rig.addrs(&addrs);
        rig.factory.script(
            &addrs[0],
            Script {
                connect_steps: 99,
                ..Script::default()
            },
        );

        let mut filter = rig.filter(&mut cx, Transport::Tcp);
        assert!(!filter.connect(&mut cx).expect("the race starts"));

        rig.deadline.left.set(-1);
        let error = filter
            .connect(&mut cx)
            .expect_err("the deadline passed mid-race");
        assert_eq!(error.code(), CURLcode::OperationTimedout);

        // `cx` and `tracer` are not used again, so the borrow of `sink`
        // ends here and the buffer can be taken back.
        let rendered = String::from_utf8(sink.into_inner())
            .expect("the trace output is text");
        assert!(
            rendered.contains("Connection timeout after 50 ms"),
            "the elapsed time is measured from t_startsingle: {rendered}"
        );
        assert!(
            rendered.contains(
                "Failed to connect to example.com port 80 \
                               after 50 ms"
            ),
            "and the composed failure follows it: {rendered}"
        );
    }

    /// `EXPIRE_HAPPY_EYEBALLS` is armed at the MINIMUM of the deadline and the
    /// remaining attempt delay (`lib/cf-ip-happy.c:512-530`).
    #[test]
    fn the_timer_is_armed_at_the_minimum_of_the_two_budgets() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let rig = Rig::new();
        let addrs = vec![v6("[2001:db8::9]:80"), v4("192.0.2.9:80")];
        rig.addrs(&addrs);
        rig.factory.script(
            &addrs[0],
            Script {
                connect_steps: 99,
                ..Script::default()
            },
        );
        rig.factory.script(
            &addrs[1],
            Script {
                connect_steps: 99,
                ..Script::default()
            },
        );

        let mut filter = rig.filter(&mut cx, Transport::Tcp);
        // A deadline of 30 s against a 200 ms delay: the delay wins.
        assert!(!filter.connect(&mut cx).expect("the race starts"));
        assert_eq!(
            rig.expiry.armed.borrow().last().copied(),
            Some((200, TimerId::HappyEyeballs))
        );

        // A deadline of 50 ms against 150 ms of delay left: the deadline wins.
        clock.advance(Duration::from_millis(50));
        rig.deadline.left.set(50);
        assert!(!filter.connect(&mut cx).expect("still racing"));
        assert_eq!(
            rig.expiry.armed.borrow().last().copied(),
            Some((50, TimerId::HappyEyeballs))
        );
    }

    /// `Curl_timeleft_ms`'s ZERO means "no limit" and must not collapse the fold
    /// to an immediate re-evaluation; the attempt delay is what is waited on.
    #[test]
    fn a_transfer_without_a_deadline_waits_on_the_attempt_delay() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let rig = Rig::new();
        rig.deadline.left.set(0);
        let addrs = vec![v6("[2001:db8::9]:80"), v4("192.0.2.9:80")];
        rig.addrs(&addrs);
        rig.factory.script(
            &addrs[0],
            Script {
                connect_steps: 99,
                ..Script::default()
            },
        );
        rig.factory.script(
            &addrs[1],
            Script {
                connect_steps: 99,
                ..Script::default()
            },
        );

        let mut filter = rig.filter(&mut cx, Transport::Tcp);
        assert!(!filter.connect(&mut cx).expect("the race starts"));
        assert_eq!(
            rig.expiry.armed.borrow().last().copied(),
            Some((200, TimerId::HappyEyeballs)),
            "no limit means the delay alone bounds the next call"
        );
        assert_eq!(
            rig.factory.created().len(),
            1,
            "and it must NOT spin into starting the second attempt early"
        );
    }

    // -- 7. the winner, and the chain behaviour ----------------------------

    /// Installing the winner disarms timer 6 and clears the accumulated failure
    /// (`lib/cf-ip-happy.c:795-797`).
    #[test]
    fn installing_the_winner_disarms_the_timer_and_clears_the_failure() {
        let clock = clock();
        let config = tracing_config();
        let mut sink = WriterSink::new(Vec::new());
        let mut tracer = Tracer::new(&config, &mut sink);
        tracer.set_verbose(true);
        let mut cx = CallCtx::new(&clock).with_tracer(&mut tracer);

        let rig = Rig::new();
        rig.meta.delay_ms.set(0);
        rig.meta.ssh.set(true);
        let addrs = vec![v6("[2001:db8::9]:80"), v4("192.0.2.9:80")];
        rig.addrs(&addrs);
        // The IPv6 candidate fails hard; the IPv4 one then wins, so there IS an
        // accumulated failure to clear.
        rig.factory.script(
            &addrs[0],
            Script {
                fail_with: Some(CURLcode::CouldntConnect),
                ..Script::default()
            },
        );
        rig.factory.script(
            &addrs[1],
            Script {
                remote_ip: String::from("192.0.2.9"),
                remote_port: 80,
                ..Script::default()
            },
        );

        let mut filter = rig.filter(&mut cx, Transport::Tcp);
        assert!(filter.connect(&mut cx).expect("the IPv4 candidate wins"));

        assert_eq!(
            rig.expiry.disarmed.borrow().as_slice(),
            [TimerId::HappyEyeballs],
            "Curl_expire_done(data, EXPIRE_HAPPY_EYEBALLS)"
        );
        assert_eq!(
            rig.meta.app_connect_marks.get(),
            1,
            "an SSH-family scheme is application-connected already"
        );
        assert_eq!(rig.meta.connections.get(), 1);
        assert!(filter.ballers.running.is_empty());
        assert!(filter.ballers.winner.is_none(), "the race state is cleared");

        // `cx` and `tracer` are not used again, so the borrow of `sink`
        // ends here and the buffer can be taken back.
        let rendered = String::from_utf8(sink.into_inner())
            .expect("the trace output is text");
        assert!(
            rendered.contains("Connected to example.com (192.0.2.9) port 80"),
            "the C's own wording, from the winner's own IP info: {rendered}"
        );
    }

    /// A scheme that is not SSH does NOT get an application-connect time
    /// (`lib/cf-ip-happy.c:801-802`).
    #[test]
    fn a_non_ssh_scheme_gets_no_application_connect_time() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let rig = Rig::new();
        let addrs = vec![v6("[2001:db8::9]:80")];
        rig.addrs(&addrs);
        rig.factory.script(&addrs[0], Script::default());

        let mut filter = rig.filter(&mut cx, Transport::Tcp);
        assert!(filter.connect(&mut cx).expect("the candidate connects"));
        assert_eq!(rig.meta.app_connect_marks.get(), 0);
    }

    /// `cf_ip_happy_close` is DESTRUCTIVE: the installed winner is closed AND
    /// discarded, and the state machine returns to `SCFST_INIT`
    /// (`lib/cf-ip-happy.c:828-842`).
    #[test]
    fn close_destroys_the_installed_winner() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let rig = Rig::new();
        let addrs = vec![v6("[2001:db8::9]:80")];
        rig.addrs(&addrs);
        rig.factory.script(&addrs[0], Script::default());

        let mut filter = rig.filter(&mut cx, Transport::Tcp);
        assert!(filter.connect(&mut cx).expect("the candidate connects"));
        let winner = rig.factory.candidate(&addrs[0], 0);
        assert_eq!(winner.borrow().closes, 0);

        filter.close(&mut cx);
        assert!(!filter.base().is_connected());
        assert_eq!(filter.state, ConnectState::Init);
        assert!(
            !filter.base().has_next(),
            "the winner is discarded, not merely closed"
        );
        let state = winner.borrow();
        assert_eq!(state.closes, 1, "closed exactly once");
        assert_eq!(state.destroys, 1, "and destroyed exactly once");
    }

    /// `cf_ip_happy_shutdown` (`:535-555`): a failed shutdown counts as done,
    /// the walk continues to the other candidates, and the overall result is
    /// always success.
    #[test]
    fn a_failed_shutdown_counts_as_done_and_the_others_continue() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let rig = Rig::new();
        rig.meta.delay_ms.set(0);
        let addrs = vec![v6("[2001:db8::9]:80"), v4("192.0.2.9:80")];
        rig.addrs(&addrs);
        rig.factory.script(
            &addrs[0],
            Script {
                connect_steps: 99,
                shutdown_fails: true,
                ..Script::default()
            },
        );
        rig.factory.script(
            &addrs[1],
            Script {
                connect_steps: 99,
                shutdown_steps: 1,
                ..Script::default()
            },
        );

        let mut filter = rig.filter(&mut cx, Transport::Tcp);
        assert!(!filter.connect(&mut cx).expect("the race starts"));
        assert_eq!(rig.factory.created().len(), 2);

        // The first fails, the second needs one more step, so the whole is not
        // done -- but the result is success and BOTH were visited.
        let done = filter.shutdown(&mut cx).expect("shutdown never fails");
        assert!(!done, "the second candidate has not finished");
        assert_eq!(rig.factory.candidate(&addrs[0], 0).borrow().shutdowns, 1);
        assert_eq!(
            rig.factory.candidate(&addrs[1], 0).borrow().shutdowns,
            1,
            "a failure in the first must not stop the walk"
        );

        // The failed one is not asked again; the other finishes.
        let done = filter.shutdown(&mut cx).expect("shutdown never fails");
        assert!(done);
        assert_eq!(
            rig.factory.candidate(&addrs[0], 0).borrow().shutdowns,
            1,
            "a candidate marked done is not shut down twice"
        );
        assert_eq!(rig.factory.candidate(&addrs[1], 0).borrow().shutdowns, 2);

        // A CONNECTED filter is done at once, with nothing racing.
        filter.base_mut().set_connected(true);
        assert!(filter.shutdown(&mut cx).expect("nothing to shut down"));
    }

    /// `CF_QUERY_CONNECT_REPLY_MS` aggregates to the EARLIEST non-negative
    /// answer, and `-1` when nobody answers (`lib/cf-ip-happy.c:603-617`).
    #[test]
    fn the_connect_reply_aggregate_is_the_earliest_non_negative() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let rig = Rig::new();
        rig.meta.delay_ms.set(0);
        let addrs = vec![
            v6("[2001:db8::9]:80"),
            v4("192.0.2.9:80"),
            v6("[2001:db8::1]:80"),
        ];
        rig.addrs(&addrs);
        // 40 ms, an unanswered one, and 25 ms.
        rig.factory.script(
            &addrs[0],
            Script {
                connect_steps: 99,
                reply_ms: Some(40),
                ..Script::default()
            },
        );
        rig.factory.script(
            &addrs[1],
            Script {
                connect_steps: 99,
                ..Script::default()
            },
        );
        rig.factory.script(
            &addrs[2],
            Script {
                connect_steps: 99,
                reply_ms: Some(25),
                ..Script::default()
            },
        );

        let mut filter = rig.filter(&mut cx, Transport::Tcp);
        assert!(!filter.connect(&mut cx).expect("the race starts"));
        assert_eq!(rig.factory.created().len(), 3);

        let answer = filter
            .query(&mut cx, CfQuery::ConnectReplyMs)
            .expect("the aggregate always answers while racing");
        assert_eq!(answer, CfQueryValue::ConnectReplyMs(25));
    }

    /// The same aggregate answers `-1` when no candidate has determined one.
    #[test]
    fn an_undetermined_connect_reply_aggregates_to_minus_one() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let rig = Rig::new();
        let addrs = vec![v6("[2001:db8::9]:80")];
        rig.addrs(&addrs);
        rig.factory.script(
            &addrs[0],
            Script {
                connect_steps: 99,
                ..Script::default()
            },
        );

        let mut filter = rig.filter(&mut cx, Transport::Tcp);
        assert!(!filter.connect(&mut cx).expect("the race starts"));
        assert_eq!(
            filter
                .query(&mut cx, CfQuery::ConnectReplyMs)
                .expect("answered"),
            CfQueryValue::ConnectReplyMs(-1)
        );
    }

    /// The two timers aggregate to the LATEST non-zero reading
    /// (`lib/cf-ip-happy.c:585-601`), and a zero reading is "not set".
    #[test]
    fn the_timer_aggregates_are_the_latest_non_zero() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let rig = Rig::new();
        rig.meta.delay_ms.set(0);
        let addrs = vec![v6("[2001:db8::9]:80"), v4("192.0.2.9:80")];
        rig.addrs(&addrs);
        rig.factory.script(
            &addrs[0],
            Script {
                connect_steps: 99,
                timer_connect: Some(CurlTime::new(1_000, 500_000)),
                timer_appconnect: Some(CurlTime::ZERO),
                ..Script::default()
            },
        );
        rig.factory.script(
            &addrs[1],
            Script {
                connect_steps: 99,
                timer_connect: Some(CurlTime::new(1_000, 250_000)),
                timer_appconnect: Some(CurlTime::new(1_001, 0)),
                ..Script::default()
            },
        );

        let mut filter = rig.filter(&mut cx, Transport::Tcp);
        assert!(!filter.connect(&mut cx).expect("the race starts"));

        assert_eq!(
            filter
                .query(&mut cx, CfQuery::TimerConnect)
                .expect("answered"),
            CfQueryValue::Timer(CurlTime::new(1_000, 500_000)),
            "the later of the two readings"
        );
        assert_eq!(
            filter
                .query(&mut cx, CfQuery::TimerAppConnect)
                .expect("answered"),
            CfQueryValue::Timer(CurlTime::new(1_001, 0)),
            "a zero reading is not set and cannot win"
        );
    }

    /// Every other query, and every query once connected, is DELEGATED to the
    /// installed winner -- and there is no winner to delegate to while racing
    /// (`lib/cf-ip-happy.c:882-887`).
    #[test]
    fn an_unsupported_query_falls_through_to_the_winner() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let rig = Rig::new();
        let addrs = vec![v6("[2001:db8::9]:80")];
        rig.addrs(&addrs);
        rig.factory.script(
            &addrs[0],
            Script {
                connect_steps: 1,
                remote_ip: String::from("2001:db8::9"),
                remote_port: 443,
                ..Script::default()
            },
        );

        let mut filter = rig.filter(&mut cx, Transport::Tcp);
        assert!(!filter.connect(&mut cx).expect("the race starts"));
        // Racing, and `IpInfo` is not one of the three aggregated questions, so
        // it falls through to a `next` that does not exist yet.
        let error = filter
            .query(&mut cx, CfQuery::IpInfo)
            .expect_err("nothing to delegate to");
        assert_eq!(error.code(), CURLcode::UnknownOption);

        assert!(filter.connect(&mut cx).expect("the candidate connects"));
        let answer = filter
            .query(&mut cx, CfQuery::IpInfo)
            .expect("the winner answers now");
        match answer {
            CfQueryValue::IpInfo { is_ipv6, quad } => {
                assert!(is_ipv6);
                assert_eq!(quad.remote_port, 443);
            }
            other => panic!("the winner answered {other:?}"),
        }
        // And once connected even the aggregated questions are delegated.
        assert_eq!(
            filter
                .query(&mut cx, CfQuery::ConnectReplyMs)
                .map(|_| ())
                .expect_err("the winner does not answer this one")
                .code(),
            CURLcode::UnknownOption
        );
    }

    /// `cf_ip_happy_data_pending` (`:844-853`): the candidates before a winner
    /// exists, the winner afterwards.
    #[test]
    fn data_pending_scans_the_candidates_and_then_the_winner() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let rig = Rig::new();
        rig.meta.delay_ms.set(0);
        let addrs = vec![v6("[2001:db8::9]:80"), v4("192.0.2.9:80")];
        rig.addrs(&addrs);
        // The first candidate never finishes, so it can neither win nor supply
        // the pending bytes.
        rig.factory.script(
            &addrs[0],
            Script {
                connect_steps: 99,
                ..Script::default()
            },
        );
        // The second has bytes waiting and connects on its second step, so it is
        // both the source of "pending" and the eventual winner.
        rig.factory.script(
            &addrs[1],
            Script {
                connect_steps: 1,
                pending: true,
                ..Script::default()
            },
        );

        let mut filter = rig.filter(&mut cx, Transport::Tcp);
        assert!(!filter.connect(&mut cx).expect("the race starts"));
        assert!(
            filter.data_pending(&cx),
            "a candidate with buffered bytes is found by the scan"
        );

        assert!(filter.connect(&mut cx).expect("the second candidate wins"));
        assert!(
            filter.data_pending(&cx),
            "and afterwards the question is the winner's to answer"
        );
    }

    /// `cf_ip_happy_adjust_pollset` (`:748-759`) drives EACH candidate's own
    /// subchain, and adds nothing once connected.
    #[test]
    fn the_pollset_reaches_every_candidate_subchain() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let rig = Rig::new();
        rig.meta.delay_ms.set(0);
        let addrs = vec![v6("[2001:db8::9]:80"), v4("192.0.2.9:80")];
        rig.addrs(&addrs);
        rig.factory.script(
            &addrs[0],
            Script {
                connect_steps: 99,
                socket: Some(7),
                ..Script::default()
            },
        );
        rig.factory.script(
            &addrs[1],
            Script {
                connect_steps: 99,
                socket: Some(9),
                ..Script::default()
            },
        );

        let mut filter = rig.filter(&mut cx, Transport::Tcp);
        assert!(!filter.connect(&mut cx).expect("the race starts"));

        let mut ps = EasyPollset::new();
        filter
            .adjust_pollset(&mut cx, &mut ps)
            .expect("both candidates register");
        assert_eq!(ps.len(), 2, "one descriptor per candidate");
        assert!(ps.want_recv(7) && ps.want_send(7));
        assert!(ps.want_recv(9) && ps.want_send(9));
        assert_eq!(rig.factory.candidate(&addrs[0], 0).borrow().pollsets, 1);
        assert_eq!(rig.factory.candidate(&addrs[1], 0).borrow().pollsets, 1);

        // Connected: the installed winner is part of the main chain and the
        // outer driver reaches it directly, so this adds nothing.
        filter.base_mut().set_connected(true);
        let mut ps = EasyPollset::new();
        filter
            .adjust_pollset(&mut cx, &mut ps)
            .expect("nothing to add");
        assert!(ps.is_empty());
    }

    // -- 8. the failure message --------------------------------------------

    /// Drives a race in which the single address fails hard, and hands back the
    /// composed message.
    fn failure_message(rig: &Rig, clock: &TestClock) -> String {
        let mut cx = CallCtx::new(clock);
        let addrs = vec![v6("[2001:db8::9]:80")];
        rig.addrs(&addrs);
        rig.factory.script(
            &addrs[0],
            Script {
                fail_with: Some(CURLcode::CouldntConnect),
                ..Script::default()
            },
        );
        let mut filter = rig.filter(&mut cx, Transport::Tcp);
        let error = filter
            .connect(&mut cx)
            .expect_err("the only address failed");
        error.message().to_owned()
    }

    /// The four shapes of `is_connected`'s `failf`
    /// (`lib/cf-ip-happy.c:637-684`): the primary socket's port, the secondary
    /// socket's port, a Unix path, and a proxy clause.
    #[test]
    fn the_failure_message_is_assembled_exactly_as_the_c_does() {
        // 1. The ordinary case: the URL's host and port.
        let plain_clock = clock();
        let plain = Rig::new();
        plain.meta.started_at.set(CurlTime::new(999, 950_000));
        assert_eq!(
            failure_message(&plain, &plain_clock),
            "Failed to connect to example.com port 80 after 50 ms: \
             Could not connect to server"
        );

        // 2. `--connect-to` replaces BOTH the host and the port.
        let connect_to_clock = clock();
        let connect_to = Rig::new();
        connect_to.meta.started_at.set(CurlTime::new(1_000, 0));
        connect_to
            .meta
            .connect_to_host
            .replace(Some(String::from("interim.example")));
        connect_to.meta.connect_to_port.set(Some(8_080));
        assert_eq!(
            failure_message(&connect_to, &connect_to_clock),
            "Failed to connect to interim.example port 8080 after 0 ms: \
             Could not connect to server"
        );

        // 3. A Unix domain socket replaces the port clause entirely.
        let unix_clock = clock();
        let over_unix = Rig::new();
        over_unix
            .meta
            .unix_path
            .replace(Some(String::from("/var/run/curl.sock")));
        assert_eq!(
            failure_message(&over_unix, &unix_clock),
            "Failed to connect to example.com over /var/run/curl.sock \
             after 0 ms: Could not connect to server"
        );

        // 4. A SOCKS proxy wins over an HTTP one, and the clause carries its own
        //    spacing.
        let socks_clock = clock();
        let via_socks = Rig::new();
        via_socks
            .meta
            .socks_proxy
            .replace(Some(String::from("socks.example")));
        via_socks
            .meta
            .http_proxy
            .replace(Some(String::from("http.example")));
        assert_eq!(
            failure_message(&via_socks, &socks_clock),
            "Failed to connect to example.com port 80 via socks.example \
             after 0 ms: Could not connect to server"
        );

        // 5. An HTTP proxy alone.
        let http_clock = clock();
        let via_http = Rig::new();
        via_http
            .meta
            .http_proxy
            .replace(Some(String::from("http.example")));
        assert_eq!(
            failure_message(&via_http, &http_clock),
            "Failed to connect to example.com port 80 via http.example \
             after 0 ms: Could not connect to server"
        );
    }

    /// The SECOND socket reports the connection's secondary port, whatever else
    /// is configured (`lib/cf-ip-happy.c:666-667`).
    #[test]
    fn the_secondary_socket_names_the_secondary_port() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let rig = Rig::new();
        rig.meta.connect_to_port.set(Some(8_080));
        let addrs = vec![v6("[2001:db8::9]:80")];
        rig.addrs(&addrs);
        rig.factory.script(
            &addrs[0],
            Script {
                fail_with: Some(CURLcode::CouldntConnect),
                ..Script::default()
            },
        );

        let mut filter = HappyEyeballs::new(
            &mut cx,
            Transport::Tcp,
            SocketIndex::Secondary,
            Some(ConnId::new(7)),
            rig.seams(Transport::Tcp),
        )
        .expect("the rig registers TCP");
        let error = filter.connect(&mut cx).expect_err("the address failed");
        assert_eq!(
            error.message(),
            "Failed to connect to example.com port 2121 after 0 ms: \
             Could not connect to server",
            "the secondary port outranks even an explicit --connect-to port"
        );
    }

    /// An operating-system error of `SOCKETIMEDOUT` overrides the reported code,
    /// AFTER the message has been composed (`lib/cf-ip-happy.c:686-688`).
    #[test]
    fn an_os_timeout_overrides_the_reported_code_but_not_the_message() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let rig = Rig::new();
        rig.meta.os_timeout.set(true);
        let addrs = vec![v6("[2001:db8::9]:80")];
        rig.addrs(&addrs);
        rig.factory.script(
            &addrs[0],
            Script {
                fail_with: Some(CURLcode::CouldntConnect),
                ..Script::default()
            },
        );

        let mut filter = rig.filter(&mut cx, Transport::Tcp);
        let error = filter.connect(&mut cx).expect_err("the address failed");
        assert_eq!(error.code(), CURLcode::OperationTimedout);
        assert!(
            error.message().contains("Could not connect to server"),
            "the message still names the original failure: {}",
            error.message()
        );
    }

    /// A connection with no resolved addresses at all is
    /// [`CURLcode::FailedInit`] -- the C's `if(!dns)`
    /// (`lib/cf-ip-happy.c:702-705`).
    #[test]
    fn an_unresolved_connection_is_failed_init() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let rig = Rig::new();
        *rig.meta.addrs.borrow_mut() = None;

        let mut filter = rig.filter(&mut cx, Transport::Tcp);
        let error = filter.connect(&mut cx).expect_err("there is no DNS entry");
        assert_eq!(error.code(), CURLcode::FailedInit);
    }

    /// The trace vocabulary of the race, as the C spells it.
    #[test]
    fn the_race_emits_the_c_trace_wording() {
        let clock = clock();
        let config = tracing_config();
        let mut sink = WriterSink::new(Vec::new());
        let mut tracer = Tracer::new(&config, &mut sink);
        tracer.set_verbose(true);
        let mut cx = CallCtx::new(&clock).with_tracer(&mut tracer);

        let rig = Rig::new();
        let addrs = vec![v6("[2001:db8::9]:80"), v4("192.0.2.9:80")];
        rig.addrs(&addrs);
        rig.factory.script(
            &addrs[0],
            Script {
                connect_steps: 99,
                ..Script::default()
            },
        );
        rig.factory.script(
            &addrs[1],
            Script {
                connect_steps: 99,
                ..Script::default()
            },
        );

        let mut filter = rig.filter(&mut cx, Transport::Tcp);
        assert!(!filter.connect(&mut cx).expect("the race starts"));
        clock.advance(Duration::from_millis(200));
        assert!(!filter.connect(&mut cx).expect("still racing"));

        // `cx` and `tracer` are not used again, so the borrow of `sink`
        // ends here and the buffer can be taken back.
        let rendered = String::from_utf8(sink.into_inner())
            .expect("the trace output is text");
        for expected in [
            "init ip ballers for transport 3",
            "starting first attempt for ipv6 -> 0",
            "checked connect attempts: 1 ongoing, 0 inconclusive",
            "next HAPPY_EYEBALLS timeout in 200ms",
            "happy eyeballs timeout expired, start next attempt",
            "starting next attempt for ipv4 -> 0",
        ] {
            assert!(
                rendered.contains(expected),
                "missing {expected:?} from:\n{rendered}"
            );
        }
        assert!(
            rendered.contains("[HAPPY-EYEBALLS]"),
            "every line is attributed to the filter: {rendered}"
        );
    }

    /// The failure walk's trace line, whose index the C never increments
    /// (`lib/cf-ip-happy.c:489-495`). Reproduced rather than corrected, because
    /// a trace line is observable output.
    #[test]
    fn the_failure_walk_prints_the_index_the_c_prints() {
        let clock = clock();
        let config = tracing_config();
        let mut sink = WriterSink::new(Vec::new());
        let mut tracer = Tracer::new(&config, &mut sink);
        tracer.set_verbose(true);
        let mut cx = CallCtx::new(&clock).with_tracer(&mut tracer);

        let rig = Rig::new();
        rig.meta.delay_ms.set(0);
        let addrs = vec![v6("[2001:db8::9]:80"), v4("192.0.2.9:80")];
        rig.addrs(&addrs);
        for addr in &addrs {
            rig.factory.script(
                addr,
                Script {
                    fail_with: Some(CURLcode::CouldntConnect),
                    ..Script::default()
                },
            );
        }

        let mut filter = rig.filter(&mut cx, Transport::Tcp);
        let _ = filter.connect(&mut cx).expect_err("everything failed");

        // `cx` and `tracer` are not used again, so the borrow of `sink`
        // ends here and the buffer can be taken back.
        let rendered = String::from_utf8(sink.into_inner())
            .expect("the trace output is text");
        assert!(rendered.contains("no more attempts to try"), "{rendered}");
        let zeroes = rendered.matches("baller 0: result=7").count();
        assert_eq!(
            zeroes, 2,
            "both lines say `baller 0`, because the C's `VERBOSE(i = 0)` has \
             no increment: {rendered}"
        );
    }

    // -- 9. the asynchronous driver ----------------------------------------

    /// The whole race, driven by [`HappyEyeballs::race`] and therefore by
    /// [`tokio::select!`], with NO network of any kind: no socket is opened, no
    /// name is resolved, and the only clock is the injected one.
    ///
    /// The runtime's timer is PAUSED, so the inter-attempt delay and the wait
    /// ceiling cost no real time; the injected clock is advanced by hand, which
    /// is what makes the delay elapse.
    #[tokio::test(start_paused = true)]
    async fn the_whole_race_needs_no_network() {
        let clock = clock();
        let rig = Rig::new();
        let addrs = vec![v6("[2001:db8::9]:80"), v4("192.0.2.9:80")];
        rig.addrs(&addrs);
        // The IPv6 candidate never finishes and registers no descriptor, so the
        // wait is a pure timer wait; the IPv4 one connects at once.
        rig.factory.script(
            &addrs[0],
            Script {
                connect_steps: usize::MAX,
                ..Script::default()
            },
        );
        rig.factory.script(&addrs[1], Script::default());

        // The delay is what the driver must wait out, so the injected clock has
        // to move with the runtime's. A background task advances it once.
        let mut filter = {
            let mut cx = CallCtx::new(&clock);
            rig.filter(&mut cx, Transport::Tcp)
        };

        let raced = {
            let mut cx = CallCtx::new(&clock);
            // One pass starts the IPv6 attempt and arms the wait; advancing the
            // injected clock past the delay is what the next pass sees.
            let first = filter.connect(&mut cx);
            assert!(!first.expect("the race starts"));
            clock.advance(Duration::from_millis(200));
            filter.race(&mut cx).await
        };
        raced.expect("the IPv4 candidate wins without a network");

        assert!(filter.base().is_connected());
        assert_eq!(filter.state, ConnectState::Done);
        assert_eq!(rig.meta.connections.get(), 1);
        let started: Vec<String> = rig
            .factory
            .created()
            .into_iter()
            .map(|(key, _)| key)
            .collect();
        assert_eq!(started, ["[2001:db8::9]:80", "192.0.2.9:80"]);
    }

    /// An explicit wake ends a wait that no timer and no socket would have
    /// ended, which is what [`HappyEyeballs::waker`] is for.
    #[tokio::test(start_paused = true)]
    async fn an_explicit_wake_re_evaluates_the_race() {
        let clock = clock();
        let rig = Rig::new();
        let addrs = vec![v6("[2001:db8::9]:80")];
        rig.addrs(&addrs);
        rig.factory.script(
            &addrs[0],
            Script {
                connect_steps: 1,
                ..Script::default()
            },
        );

        let mut cx = CallCtx::new(&clock);
        let mut filter = rig.filter(&mut cx, Transport::Tcp);
        let waker = filter.waker();
        // Woken before the race is even entered, so the permit is stored and the
        // first wait ends immediately -- the candidate then connects on its
        // second step.
        waker.notify_one();
        filter
            .race(&mut cx)
            .await
            .expect("the candidate connects on its second step");
        assert!(filter.base().is_connected());
    }

    /// The race is reusable after a destructive close: it starts over, races
    /// again, and installs a NEW winner.
    #[test]
    fn a_closed_filter_races_again_from_the_start() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let rig = Rig::new();
        let addrs = vec![v6("[2001:db8::9]:80")];
        rig.addrs(&addrs);
        rig.factory.script(&addrs[0], Script::default());

        let mut filter = rig.filter(&mut cx, Transport::Tcp);
        assert!(filter.connect(&mut cx).expect("the first race wins"));
        filter.close(&mut cx);
        assert_eq!(filter.state, ConnectState::Init);

        assert!(filter.connect(&mut cx).expect("the second race wins"));
        assert_eq!(
            rig.factory.created().len(),
            2,
            "a new candidate is built, because the old one was discarded"
        );
        assert_eq!(rig.meta.connections.get(), 2);
    }
}
