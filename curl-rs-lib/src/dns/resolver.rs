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

//! The resolution engine: the decision tree, the system resolver and the
//! timeout.
//!
//! Supersedes the resolve-path and timeout portions of `lib/hostip.c` -
//! `Curl_resolv` (`:860-1012`), `Curl_resolv_blocking` (`:1016-1042`),
//! `Curl_resolv_timeout` (`:1077-1233`), `alarmfunc` (`:1042-1052`),
//! `store_negative_resolve` (`:811-841`), `can_resolve_ip_version`
//! (`:806-820`), `tailmatch` (`:798-805`), `Curl_probeipv6` with
//! `Curl_ipv6works` (`:752-776`) and `Curl_resolver_error` (`:1570-1589`) -
//! together with `lib/hostip4.c`, `lib/hostip6.c` and the whole threaded and
//! asynchronous apparatus of `lib/asyn.h`, `lib/asyn-base.c`,
//! `lib/asyn-thrdd.c` and `lib/curl_threads.c`.
//!
//! ## `Curl_resolv_timeout`, step by step, with each disposition
//!
//! | Step | C behaviour | Disposition here |
//! |---|---|---|
//! | 1 | `if(timeoutms < 0) return CURLE_OPERATION_TIMEDOUT;` - *"got an already expired timeout"* (`:1100-1102`) | **PRESERVED.** Not alarm-specific. |
//! | 2 | `data->set.no_signal` sets `timeout = 0` (`:1105-1107`) | **DROPPED** - Change 2 below. |
//! | 3 | `if(!timeout \|\| data->set.doh) return Curl_resolv(...)` (`:1111-1117`) | **COLLAPSED.** A zero timeout still means "apply none"; the DoH half had nothing to bypass once the alarm path is gone. |
//! | 4 | `if(timeout < 1000) { failf(...); return CURLE_OPERATION_TIMEDOUT; }` (`:1119-1126`) | **NOT REPRODUCED** - Change 1 below. |
//! | 5 | `if(sigsetjmp(curl_jmpenv, 1)) { failf(data, "name lookup timed out"); ... }` (`:1136-1141`) | The **string is preserved verbatim**; the mechanism is gone. |
//! | 6 | install a `SIGALRM` `sigaction` with `SA_RESTART` cleared, then `prev_alarm = alarm(timeout / 1000)` (`:1143-1167`) | **DELETED** entirely. |
//! | 7 | non-alarm, non-async build: `infof(data, "timeout on name lookup is not supported")` (`:1173`) | **NOT EMITTED.** Moot: `tokio::time::timeout` is always available, so the state the line described cannot arise. |
//! | 8 | `clean_up`: `alarm(0)`, restore the handler, unlock, re-arm `prev_alarm`, and on a residual that already expired `alarm(1)` plus `failf(data, "Previous alarm fired off")` (`:1180-1225`) | **THE ENTIRE TEARDOWN DISAPPEARS.** With no signal there is no handler to restore and no foreign alarm to preserve. |
//!
//! # The two deliberate behavioural changes
//!
//! Both remove a limitation that existed only because of the mechanism, and
//! both are written down here so that a later reader restoring "fidelity"
//! reintroduces a defect knowingly rather than by accident.
//!
//! **Change 1 - the `timeout < 1000` early bail is REMOVED.** C emits
//! `"remaining timeout of %ld too small to resolve via SIGALRM method"` and
//! fails. The reason is arithmetic, not policy: `alarm()` takes an integer
//! number of *seconds*, so `alarm(timeout / 1000)` with `timeout` under a
//! second computes `alarm(0)`, and `alarm(0)` *cancels* an alarm rather than
//! setting one. Faced with silently disabling the timeout, C chose to fail
//! instead. [`tokio::time::timeout`] has far finer resolution, so a
//! sub-second budget is **honoured**, and a caller that asks for 200 ms gets
//! 200 ms rather than [`CURLcode::OperationTimedout`]. This is the one place
//! in this module where dropping the C mechanism removes a C-only limitation
//! instead of changing behaviour, and
//! `a_sub_second_timeout_is_honoured_not_refused` is its executable proof.
//!
//! # Why `tokio` appears here when the utility layer forbids it
//!
//! `lib/curl_threads.c` is consequently **not ported**. It is a bare pthread
//! wrapper - `Curl_thread_create` around a heap-allocated `Curl_actual_call`
//! thunk, `Curl_thread_destroy` as `pthread_detach` plus a free,
//! `Curl_thread_join` as `pthread_join` - and `lib/asyn-thrdd.c` is the
//! resolver built on top of it. `spawn_blocking` replaces both files
//! together, so this module creates no thread of its own and owns no pool.
//!
//! # Truthful advertisement: the `AsynchDNS` decision
//!
//! Truthful advertisement is therefore the optimal strategy, not merely the
//! honest one."* `crate::version` owns the banner text; this module owns the
//! runtime truth behind one of its names and the justification for it, which
//! is written here.
//!
//! **The trap, and why no string here contains that substring.**
//! `tests/runtests.pl:611-613` is
//! `if($libcurl =~ /ares/i) { $feature{"c-ares"} = 1; $resolver = "c-ares"; }`
//! - a **case-insensitive substring match anywhere in the banner**. Any
//! token containing those four letters switches the harness into a mode
//! written for a resolver this build does not contain, which is the fatal
//! direction of the asymmetry above. Nothing in this module emits banner
//! text, and no literal in it carries that substring; the paragraph above
//! about the dropped library is the sole occurrence in the whole file and it
//! is a comment.
//!
//! **The measured cost, stated rather than buried.** Across all 1,914
//! fixtures exactly two gate on resolver identity: `tests/data/test3026`
//! (*"curl_global_init thread-safety"*) requires `threadsafe` with
//! `threaded-resolver` and becomes eligible when the name is advertised,
//! while `tests/data/test506` (*"HTTP with shared cookie list (and dns
//! cache)"*) requires `!threaded-resolver` with `!c-ares` and skips. Zero
//! fixtures gate on `AsynchDNS` or `asyn-rr` directly. The choice trades one
//! fixture either way, so truthfulness decides it, and the `test506` skip is
//! a deliberate consequence rather than a regression.
//!
//! # Which trace lines survive, and which do not
//!
//! `lib/asyn-thrdd.c`'s diagnostics describe a thread lifecycle the runtime
//! subsumes, so most of them describe states that cannot occur here and are
//! **not emitted**: a line for an impossible state is worse than no line.
//! Retained, because the situation still exists:
//!
//! * `failf(data, "getaddrinfo() thread failed")` (`:724`) - the lookup task
//!   itself failed. Reproduced by [`msg::GETADDRINFO_TASK_FAILED`], which is
//!   what a panicked or cancelled `spawn_blocking` join reports.
//! * `infof(data, "getaddrinfo(3) failed for %s:%d")` (`lib/hostip6.c:110`) -
//!   the resolver returned no answer. [`msg::getaddrinfo_failed`].
//! * `CURL_TRC_DNS(data, "init threaded resolve of %s:%d")` (`:739`) - a
//!   lookup is starting. [`msg::init_resolve`].
//!
//! Dropped, with the reason:
//!
//! * `"getaddrinfo() thread failed to start"` (`:762`) - C reports
//!   `pthread_create` failing. `spawn_blocking` does not fail to enqueue; a
//!   task that cannot run surfaces as a join error, which the retained line
//!   above already covers.
//! * `"resolve thread started for of %s:%d"` (`:451`, the *"for of"* typo is
//!   in the source) - a second line for the same event as `init_resolve`,
//!   emitted from the thread rather than from its creator. There is no
//!   second vantage point here.
//! * `"resolve thread failed init: %d"` (`:455`) - the thread context could
//!   not be built. There is no thread context.
//! * `"starting new resolve, with previous not cleaned up"` (`:407`) - only
//!   reachable because C's per-handle resolve state outlives its lookup.
//!   Dropping the future is the cleanup, so the overlap cannot arise.
//! * `"resolve, wait for thread to finish"` (`:505`) - the join that
//!   `Curl_async_await` performed. `await` is the join.
//! * `"is_resolved() result=%d, dns=%sfound"` and `"threaded: is_resolved(),
//!   already done, dns=%sfound"` (`:635`, `:579`) - both report a poll of a
//!   completion flag. There is no poll and no flag.
//! * `"async_thrdd_destroy, thread joined"`, `"async_thrdd_destroy, thread
//!   detached"` and `"async_thrdd_shutdown, thread joined"` (`:317`, `:322`,
//!   `:486`) - the shutdown-and-destroy pair, subsumed by `Drop`.
//! * `infof(data, "Failed HTTPS RR operation")` (`:449`) - belongs to
//!   `dns/httpsrr.rs`, not here, and emitting it from two files would break
//!   the byte-exact comparison the fixture corpus performs.

use core::fmt;
use std::net::ToSocketAddrs;

use crate::error::{CURLcode, CodeResult};
use crate::trace::{failf, infof, trc_feat, TraceFeature, Tracer};
use crate::util::strcase::{casecompare, ncasecompare};
use crate::util::timediff::{mstotv, TimeDiff};
use crate::util::timeval::Clock;

use super::msg::{found_in_cache, store_negative, NEGATIVE_ENTRY, NO_ONION};
use super::{
    can_resolve_ip_version, is_ipaddr, localhost_addrs, resolver_error_message,
    show_resolve_info, str2addr, AddressFamily, DnsCache, DnsEntryRef,
    IpVersion, Ipv6Probe, Ipv6Support, ResolveFuture, ResolveTarget,
    ResolvedAddr, Resolver, CURL_TIMEOUT_RESOLVE,
};

// Constants

/// The ceiling an asynchronous resolve is given: 300 seconds, in
/// milliseconds.
#[allow(dead_code)]
pub(crate) const RESOLVE_TIMEOUT_CEILING_MS: TimeDiff =
    CURL_TIMEOUT_RESOLVE * 1000;

/// Whether a numeric address literal is handed to the system resolver
/// anyway.
///
/// Handing a literal to the resolver anyway has two consequences, and both
/// are reproduced:
///
/// * `Curl_resolv`'s literal shortcut is compiled out
///   (`lib/hostip.c:928-936`), so on Apple platforms a literal falls through
///   to the resolver instead of being converted locally.
/// * `Curl_sync_getaddrinfo`'s `AI_NUMERICHOST` hint is compiled out
///   (`lib/hostip6.c:88-98`), whose own comment is *"The AI_NUMERICHOST must
///   not be set to get synthesized IPv6 address from an IPv4 address on iOS
///   and macOS."*
#[cfg(any(target_os = "macos", target_os = "ios"))]
#[allow(dead_code)]
pub(crate) const RESOLVE_ON_IPS: bool = true;

/// Whether a numeric address literal is handed to the system resolver
/// anyway - false everywhere except Apple platforms.
///
/// See the Apple-side definition for the reasoning and the C locators.
#[cfg(not(any(target_os = "macos", target_os = "ios")))]
#[allow(dead_code)]
pub(crate) const RESOLVE_ON_IPS: bool = false;

/// The suffix `.onion` names end with, and the length of its dotted form.
///
/// `lib/hostip.c:889-891` matches two suffixes, `".onion"` at six bytes and
/// `".onion."` at seven, and gates both behind the **same** `>= 7` length
/// test. [`is_onion`] records why that is not a typo to fix.
#[allow(dead_code)]
const ONION_SUFFIX: &[u8] = b".onion";

/// The dotted form of the suffix above: `".onion."`, seven bytes.
#[allow(dead_code)]
const ONION_SUFFIX_DOTTED: &[u8] = b".onion.";

/// The two loopback names C matches exactly, and the two it tail-matches.
///
/// `lib/hostip.c:938-943`:
///
/// ```c
/// if(curl_strequal(hostname, "localhost") ||
///    curl_strequal(hostname, "localhost.") ||
///    tailmatch(hostname, hostname_len, STRCONST(".localhost")) ||
///    tailmatch(hostname, hostname_len, STRCONST(".localhost.")))
/// ```
#[rustfmt::skip]
#[allow(dead_code)]
const LOCALHOST_EXACT: [&[u8]; 2] = [
    b"localhost",
    b"localhost.",
];

/// The two suffixes that make any name a loopback name.
///
/// The tail-matched half of `lib/hostip.c:938-943`. A leading dot is part of
/// each suffix, which is what stops `"notlocalhost"` from matching.
#[rustfmt::skip]
#[allow(dead_code)]
const LOCALHOST_SUFFIXES: [&[u8]; 2] = [
    b".localhost",
    b".localhost.",
];

// The message strings this module owns

/// The diagnostics this file emits that `dns/mod.rs` does not already hold.
///
/// `dns/mod.rs` owns the frozen text of every message shared with the cache
/// and with `CURLOPT_RESOLVE`; the four this module emits from that set are
/// imported rather than respelled. What remains here is the text that has no
/// counterpart there: the deadline line and the resolver-task diagnostics.
#[rustfmt::skip]
pub(crate) mod msg {
    /// `"name lookup timed out"` - `lib/hostip.c:1139`.
    #[allow(dead_code)]
    pub(crate) const NAME_LOOKUP_TIMED_OUT: &str = "name lookup timed out";

    /// `"getaddrinfo(3) failed for %s:%d"` - `lib/hostip6.c:110`.
    #[allow(dead_code)]
    pub(crate) fn getaddrinfo_failed(host: &str, port: u16) -> String {
        format!("getaddrinfo(3) failed for {host}:{port}")
    }

    /// `"getaddrinfo() thread failed"` - `lib/asyn-thrdd.c:724`.
    ///
    /// The lookup task itself failed rather than merely finding nothing:
    /// here, a blocking task that panicked or was cancelled before it could
    /// report. C's sibling `"getaddrinfo() thread failed to start"`
    /// (`:762`) has no counterpart, because a blocking task does not fail to
    /// enqueue and a task that cannot run surfaces as this same join
    /// failure.
    #[allow(dead_code)]
    pub(crate) const GETADDRINFO_TASK_FAILED: &str =
        "getaddrinfo() thread failed";

    /// `"init threaded resolve of %s:%d"` - `lib/asyn-thrdd.c:739`.
    ///
    /// A `CURL_TRC_DNS` line, so it is emitted under the `dns` trace feature
    /// rather than through `infof`. It survives because the situation
    /// survives: a lookup is about to be issued. The companion line C emits
    /// from inside the thread does not, since there is no second vantage
    /// point - the module documentation lists every dropped line with its
    /// reason.
    #[allow(dead_code)]
    pub(crate) fn init_resolve(host: &str, port: u16) -> String {
        format!("init threaded resolve of {host}:{port}")
    }
}

// Name classification

/// True when `hostname` must be refused as a Tor onion name.
///
/// Supersedes the `.onion` guard of `Curl_resolv` (`lib/hostip.c:887-895`),
/// whose comment is *"We should intentionally error and not resolve .onion
/// TLDs"* - RFC 7686:
///
/// ```c
/// hostname_len = strlen(hostname);
/// if(hostname_len >= 7 &&
///    (curl_strequal(&hostname[hostname_len - 6], ".onion") ||
///     curl_strequal(&hostname[hostname_len - 7], ".onion.")))
/// ```
///
/// # The measured quirk, which is NOT to be fixed
///
/// The comparison is `curl_strequal`, so it is case-insensitive and
/// ASCII-only: [`casecompare`] is the successor, and Unicode-aware folding
/// must not be substituted for it.
#[allow(dead_code)]
pub(crate) fn is_onion(hostname: &[u8]) -> bool {
    // `if(hostname_len >= 7 && ...)` -- the single gate, for both suffixes.
    if hostname.len() < ONION_SUFFIX_DOTTED.len() {
        return false;
    }

    // `&hostname[hostname_len - 6]` against `".onion"`, and
    // `&hostname[hostname_len - 7]` against `".onion."`. Both offsets are in
    // range because the length is at least seven.
    let undotted = &hostname[hostname.len() - ONION_SUFFIX.len()..];
    let dotted = &hostname[hostname.len() - ONION_SUFFIX_DOTTED.len()..];

    casecompare(undotted, ONION_SUFFIX)
        || casecompare(dotted, ONION_SUFFIX_DOTTED)
}

/// True when `part` is a case-insensitive tail of `full`.
///
/// Supersedes `tailmatch` (`lib/hostip.c:798-805`), whose whole body is:
///
/// ```c
/// if(plen > flen)
///   return FALSE;
/// return curl_strnequal(part, &full[flen - plen], plen);
/// ```
#[allow(dead_code)]
pub(crate) fn tailmatch(full: &[u8], part: &[u8]) -> bool {
    // `if(plen > flen) return FALSE;`
    if part.len() > full.len() {
        return false;
    }
    let tail = &full[full.len() - part.len()..];
    ncasecompare(part, tail, part.len())
}

/// True when `hostname` is one of the loopback names curl synthesises for.
#[allow(dead_code)]
pub(crate) fn is_localhost(hostname: &[u8]) -> bool {
    LOCALHOST_EXACT
        .iter()
        .any(|name| casecompare(hostname, name))
        || LOCALHOST_SUFFIXES
            .iter()
            .any(|suffix| tailmatch(hostname, suffix))
}

/// Whether an alternative in-process resolver is available to this build.
///
/// The predicate behind the default-off `hickory-dns` feature, and the
/// second factor `crate::version`'s alternative-resolver banner slot needs
/// once `ENGINE_DNS` becomes present. It follows the rule
/// `crate::version` states for the internationalised-domain-name token: the
/// authority is *the implementing module's own predicate*, not a second
/// opinion written beside the banner.
///
/// It reports `false` at **every** feature setting, `--all-features`
/// included, and the reason is measured rather than chosen.
/// `curl-rs-lib/Cargo.toml` records it in full: every `hickory-resolver`
/// release that clears the workspace minimum Rust version requires a
/// `hickory-proto` carrying an open advisory, and every `hickory-proto` that
/// carries the fix states a minimum above the floor. No admissible version
/// exists, no new dependency may be added, and inventing one would fail the
/// advisory gate.
///
/// # This is a blocked requirement, not an unfinished one
///
/// The distinction is worth drawing here rather than left to the manifest,
/// because this function is where a reader arrives when they ask why the
/// feature does nothing. AAP 0.5.2 asks for a working optional backend; this
/// workspace does not have one and cannot obtain one without failing AAP 0.8.3
/// or AAP 0.8.4's ninth gate. That is recorded as a machine-readable blocked
/// gate under `[workspace.metadata.curl-rs.blocked-aap-gates.hickory-dns]` in
/// the root manifest, together with the exact `cargo deny` result that
/// establishes it, and `curl-rs-ffi/build.rs` checks on every build that the
/// declaration has not gone stale. So the answer to "is this finished?" is
/// neither yes nor not-yet: it is blocked on a decision recorded in one place,
/// with an owner named beside it.
///
/// So the feature is a declared name whose arm is a documented placeholder.
/// The alternative here is deliberately not "omit the predicate": a build
/// with the feature on must still compile, and the banner must still be
/// stopped from naming a resolver the binary does not contain. Reporting
/// `false` does both. When an admissible version appears, this function, the
/// backend-selection point in [`SystemResolver::lookup`] - which has a
/// single arm today for exactly this reason - and that blocked-gate row are
/// the three places that change; there is no `hickory.rs` and none may be
/// created.
// No consumer yet; crate::version conjoins it once ENGINE_DNS
// flips to present.
#[allow(dead_code)]
pub(crate) fn alternative_resolver_available() -> bool {
    // Written as a conjunction rather than a bare `false` so that the
    // feature's role stays visible: the flag is necessary and, today, not
    // sufficient. `cfg!` rather than `#[cfg]` because both arms must always
    // type-check.
    cfg!(feature = "hickory-dns") && ALTERNATIVE_RESOLVER_IS_LINKED
}

/// Whether an alternative resolver crate is actually in the dependency
/// graph.
#[allow(dead_code)]
const ALTERNATIVE_RESOLVER_IS_LINKED: bool = false;

// The system resolver

/// Which address families a lookup is permitted to return.
///
/// C expresses this as the `int pf` it puts into `hints.ai_family`
/// (`lib/hostip6.c:79-82`):
///
/// ```c
/// int pf = PF_INET;
/// if((ip_version != CURL_IPRESOLVE_V4) && Curl_ipv6works(data))
///   /* The stack seems to be IPv6-enabled */
///   pf = PF_UNSPEC;
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AllowedFamilies {
    /// Whether an `AF_INET` answer is kept.
    pub(crate) inet: bool,
    /// Whether an `AF_INET6` answer is kept.
    pub(crate) inet6: bool,
}

impl AllowedFamilies {
    /// The families a request for `ip_version` may return.
    ///
    /// Reconciles two authorities that do not quite agree, and the
    /// disagreement is worth recording rather than smoothing over:
    ///
    /// * **C narrows the hint.** `lib/hostip6.c:79-82` uses `PF_INET` for a
    ///   [`IpVersion::V4`] request and for any request on a host without
    ///   IPv6, and `PF_UNSPEC` otherwise. Note that a
    ///   [`IpVersion::V6`] request therefore gets `PF_UNSPEC` in C - **both**
    ///   families - and the narrowing to IPv6 happens later, in the
    ///   connection layer.
    /// * **[`Resolver`]'s contract narrows the answer.** `dns/mod.rs`
    ///   states it directly: *"Pass [`IpVersion::V4`] or [`IpVersion::V6`]
    ///   and the result contains only that family"*, because
    ///   `conn/happy_eyeballs.rs` races two family-scoped calls against each
    ///   other and must not receive the other family in either.
    pub(crate) const fn for_request(
        ip_version: IpVersion,
        ipv6_works: bool,
    ) -> Self {
        match ip_version {
            // `pf = PF_INET` -- IPv4 only.
            IpVersion::V4 => Self {
                inet: true,
                inet6: false,
            },
            // The trait's narrowing; C reaches the same set through the
            // connection layer.
            IpVersion::V6 => Self {
                inet: false,
                inet6: true,
            },
            // `PF_UNSPEC` when the stack has IPv6, and `PF_INET` when it
            // does not -- the outcome that is easy to miss.
            IpVersion::Whatever => Self {
                inet: true,
                inet6: ipv6_works,
            },
        }
    }

    /// Whether an address of `family` survives this filter.
    pub(crate) const fn accepts(self, family: AddressFamily) -> bool {
        match family {
            AddressFamily::Inet => self.inet,
            AddressFamily::Inet6 => self.inet6,
            // Neither arm of C's family test.
            AddressFamily::Unix => false,
        }
    }
}

/// The default [`Resolver`]: the operating system's own, off the calling
/// task.
///
/// Supersedes `Curl_sync_getaddrinfo` in both of its builds -
/// `lib/hostip6.c:65-118` for the `getaddrinfo` form and `lib/hostip4.c:70-84`
/// for the `gethostbyname_r` form - and, together with them, the entire
/// threaded apparatus of `lib/asyn-thrdd.c` and `lib/curl_threads.c`.
#[derive(Debug)]
pub(crate) struct SystemResolver {
    /// The memoised IPv6 answer, an [`OnceLock`](std::sync::OnceLock) owned
    /// by this value rather than by the process.
    ipv6: Ipv6Support,
    /// How that answer is obtained the first time.
    probe: Box<dyn Ipv6Probe + Send + Sync>,
}

impl Default for SystemResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemResolver {
    /// A resolver that probes IPv6 with a real socket, at most once.
    pub(crate) fn new() -> Self {
        Self {
            ipv6: Ipv6Support::new(),
            probe: Box::new(super::SocketIpv6Probe),
        }
    }

    /// A resolver whose IPv6 answer is already known, probing never.
    ///
    /// Not test-only. A caller that has established the answer elsewhere -
    /// from another handle's [`Ipv6Support::cached`], or from a
    /// configuration that settles it - should be able to say so without a
    /// syscall, and Miri needs that route because it cannot make one.
    #[allow(dead_code)]
    pub(crate) fn with_known_ipv6(works: bool) -> Self {
        Self {
            ipv6: Ipv6Support::known(works),
            probe: Box::new(super::FixedIpv6Probe(Ok(works))),
        }
    }

    /// A resolver over a caller-supplied probe.
    #[allow(dead_code)]
    pub(crate) fn with_probe(probe: Box<dyn Ipv6Probe + Send + Sync>) -> Self {
        Self {
            ipv6: Ipv6Support::new(),
            probe,
        }
    }

    /// The memoised IPv6 answer this resolver uses.
    ///
    /// Hand this to [`ResolveContext`] so that the decision tree's
    /// `can_resolve_ip_version` gate and this resolver's family hint consult
    /// one memoised answer rather than probing twice.
    #[allow(dead_code)]
    pub(crate) fn ipv6(&self) -> &Ipv6Support {
        &self.ipv6
    }

    /// The probe behind that answer.
    #[allow(dead_code)]
    pub(crate) fn ipv6_probe(&self) -> &(dyn Ipv6Probe + Send + Sync) {
        self.probe.as_ref()
    }

    /// The families this resolver will keep for `ip_version`.
    ///
    /// # Errors
    ///
    /// Whatever [`Ipv6Support::works`] reports, which is
    /// [`CURLcode::OutOfMemory`] and only that.
    fn allowed(&self, ip_version: IpVersion) -> CodeResult<AllowedFamilies> {
        // C reads `Curl_ipv6works(data)` unconditionally at this point, so
        // the probe may be taken even for a request that does not need it.
        // Reproduced, because the probe is memoised either way and because
        // the error it can report would otherwise be observable only for
        // some requests.
        let works = self.ipv6.works(self.probe.as_ref())?;
        Ok(AllowedFamilies::for_request(ip_version, works))
    }

    /// Selects the resolution backend and performs one blocking lookup.
    ///
    /// # Errors
    ///
    /// [`CURLcode::CouldntResolveHost`] when the resolver reported a
    /// failure. An empty-but-successful answer is *not* an error at this
    /// level - the caller distinguishes it, because the diagnostic differs.
    fn lookup(host: &str, port: u16) -> CodeResult<Vec<ResolvedAddr>> {
        Self::system_lookup(host, port)
    }

    /// One blocking `getaddrinfo(3)`, converted to owned addresses.
    ///
    /// `std::net::ToSocketAddrs` for a `(&str, u16)` pair is the standard
    /// library's `getaddrinfo`, and it is the faithful successor to
    /// `Curl_getaddrinfo_ex` (`lib/curl_addrinfo.c:558+`) for four measured
    /// reasons:
    ///
    /// * **The socket type matches.** The standard library hints
    ///   `SOCK_STREAM`, which is what C hints for a TCP transport
    ///   (`lib/hostip6.c:86-88`). Every address therefore carries
    ///   [`SockType::Stream`](super::SockType) with
    ///   [`IpProto::Tcp`](super::IpProto), which is what
    ///   [`ResolvedAddr::tcp`] builds.
    /// * **The port is applied to every answer**, which is C's
    ///   `Curl_addrinfo_set_port(res, port)` (`lib/hostip6.c:113-115`)
    ///   following the service string it passed. A zero port yields zero
    ///   ports, matching C's `if(port)` guard on that string.
    /// * **The canonical name is absent, and that is correct.** C copies
    ///   `ai_canonname` only when the system supplied one
    ///   (`lib/curl_addrinfo.c:23`, `:58-66`), and curl's hints never set
    ///   `AI_CANONNAME`, so the field is NULL in practice. The standard
    ///   library likewise reports none, so [`None`] is faithful rather than
    ///   a loss.
    /// * **A literal is parsed locally.** The standard library tries
    ///   `IpAddr`'s parser before calling the resolver, which is the effect
    ///   C obtains with its `AI_NUMERICHOST` hint (`lib/hostip6.c:88-98`) on
    ///   the platforms where that hint is set. On Apple platforms C omits the
    ///   hint deliberately so that NAT64 synthesis can happen; that
    ///   divergence is recorded on [`RESOLVE_ON_IPS`] and is not reachable
    ///   through this interface, which is a documented limitation of using
    ///   the standard library rather than raw hints.
    ///
    /// # Errors
    ///
    /// [`CURLcode::CouldntResolveHost`] for any resolver failure. The
    /// underlying `io::Error` is deliberately not propagated: `CURLcode` is
    /// this crate's sole error type and C reports exactly this code here.
    fn system_lookup(host: &str, port: u16) -> CodeResult<Vec<ResolvedAddr>> {
        let addrs = (host, port)
            .to_socket_addrs()
            .map_err(|_| CURLcode::CouldntResolveHost)?;

        // The ORDER the resolver produced is preserved. It encodes the
        // host's own address-selection policy, and `dns/mod.rs` records that
        // reordering it would make a Happy Eyeballs race connect to a
        // different address than curl does.
        Ok(addrs.map(|addr| ResolvedAddr::tcp(addr, None)).collect())
    }

    /// Runs [`Self::lookup`] off the calling task when a runtime is present.
    ///
    /// # Why the absence of a runtime is handled rather than asserted
    ///
    /// `tokio::task::spawn_blocking` panics when called outside a runtime.
    /// A panic here could unwind across the C boundary through
    /// `curl-rs-ffi`, which is undefined behaviour on the C side, so the
    /// condition is detected with `Handle::try_current` and answered by
    /// performing the lookup on the calling thread instead. That fall-back is
    /// not a degradation: it is exactly `CURLRES_SYNCH`, the synchronous
    /// build C ships, and it is also what makes this function usable from a
    /// bare `block_on` with no reactor.
    ///
    /// # Errors
    ///
    /// [`CURLcode::CouldntResolveHost`], either from the lookup itself or
    /// from a join failure - a task that panicked or was cancelled. The two
    /// are distinguished in the diagnostic, not in the code, exactly as C
    /// distinguishes `"getaddrinfo(3) failed for %s:%d"` from
    /// `"getaddrinfo() thread failed"` while returning one code for both.
    async fn lookup_off_task(
        host: String,
        port: u16,
    ) -> Result<CodeResult<Vec<ResolvedAddr>>, JoinFailed> {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => handle
                .spawn_blocking(move || Self::lookup(&host, port))
                .await
                .map_err(|_| JoinFailed),
            // `CURLRES_SYNCH`: no runtime, so resolve here and now.
            Err(_) => Ok(Self::lookup(&host, port)),
        }
    }
}

/// The blocking lookup task did not produce an answer at all.
///
/// A panicked or cancelled task, which is the situation
/// `failf(data, "getaddrinfo() thread failed")` reports
/// (`lib/asyn-thrdd.c:724`). It is a distinct type rather than a
/// [`CURLcode`] so that the caller cannot confuse "the resolver said no"
/// with "the resolver never answered": the two produce the same code and
/// different diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct JoinFailed;

impl Resolver for SystemResolver {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        port: u16,
        ip_version: IpVersion,
    ) -> ResolveFuture<'a, Vec<ResolvedAddr>> {
        // The host is copied because `spawn_blocking` requires a `'static`
        // closure: a blocking task outlives the borrow that produced it, and
        // that is the whole reason C had to duplicate the hostname into
        // `struct async_thrdd_addr_ctx` too (`lib/asyn.h`, the `hostname`
        // member commented "Curl_async.hostname duplicate").
        let owned = host.to_owned();

        Box::pin(async move {
            // C's `can_resolve_ip_version` companion inside the resolver:
            // the family hint needs the same memoised answer, and taking it
            // here is what `lib/hostip6.c:79-82` does.
            let allowed = self.allowed(ip_version)?;

            let answered = Self::lookup_off_task(owned, port).await;
            let addrs = match answered {
                Ok(result) => result?,
                Err(JoinFailed) => return Err(CURLcode::CouldntResolveHost),
            };

            // The family narrowing. C narrows the hint instead; the surviving
            // set is the same, and `AllowedFamilies::for_request` records the
            // one case where the trait's contract is narrower than the hint.
            Ok(addrs
                .into_iter()
                .filter(|addr| allowed.accepts(addr.family()))
                .collect())
        })
    }
}

// The request and the injected context

/// What one resolution asks for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct ResolveRequest<'a> {
    /// The name to resolve, as the caller spelled it.
    pub(crate) hostname: &'a str,
    /// The port, which every resolved address carries.
    ///
    /// C's `int port`, narrowed to the range a port occupies. Zero is
    /// meaningful and means "no service", which is C's `if(port)` guard on
    /// the service string (`lib/hostip6.c:101-104`).
    pub(crate) port: u16,
    /// Which address families are acceptable - `CURLOPT_IPRESOLVE`.
    pub(crate) ip_version: IpVersion,
    /// Whether DNS-over-HTTPS may be used for this lookup.
    ///
    /// C's `allowDOH`, which is `TRUE` from `Curl_resolv_timeout`
    /// (`lib/hostip.c:1117`) and `FALSE` from `Curl_resolv_blocking`
    /// (`:1024`). The second is not a preference: resolving the DoH server's
    /// own name over DoH would not terminate.
    pub(crate) allow_doh: bool,
}

impl<'a> ResolveRequest<'a> {
    /// A request for `hostname` and `port`, any family, DoH permitted.
    ///
    /// The defaults are C's from `Curl_resolv_timeout`:
    /// `CURL_IPRESOLVE_WHATEVER` is the option's own default and `allowDOH`
    /// is `TRUE` there.
    #[allow(dead_code)]
    pub(crate) fn new(hostname: &'a str, port: u16) -> Self {
        Self {
            hostname,
            port,
            ip_version: IpVersion::Whatever,
            allow_doh: true,
        }
    }

    /// The same request restricted to one address family.
    #[allow(dead_code)]
    pub(crate) fn with_ip_version(mut self, ip_version: IpVersion) -> Self {
        self.ip_version = ip_version;
        self
    }

    /// The same request with DoH permitted or refused.
    #[allow(dead_code)]
    pub(crate) fn with_allow_doh(mut self, allow_doh: bool) -> Self {
        self.allow_doh = allow_doh;
        self
    }
}

/// Everything a resolution may use, all of it injected.
///
/// The trace sink is **not** a member: it travels as its own argument,
/// because [`Tracer`] borrows both a configuration and a sink and nesting
/// those borrows inside another borrowed structure buys nothing and costs
/// clarity.
#[allow(dead_code)]
pub(crate) struct ResolveContext<'a> {
    /// The cache to consult and to populate.
    cache: Option<&'a mut DnsCache>,

    /// The injected clock. Every entry timestamp comes from here.
    ///
    /// Never [`std::time::Instant::now`] and never tokio's timer, for the
    /// reason the module preamble records: a cache-expiry test must be able
    /// to advance time without sleeping.
    clock: &'a dyn Clock,

    /// The resolver to use when no shortcut applies.
    resolver: &'a dyn Resolver,

    /// The DNS-over-HTTPS resolver, when `CURLOPT_DOH_URL` selected one.
    #[cfg(feature = "doh")]
    doh: Option<&'a dyn Resolver>,

    /// The memoised IPv6 answer, owned by the caller's handle.
    ipv6: &'a Ipv6Support,

    /// How that answer is taken, the first time only.
    ipv6_probe: &'a (dyn Ipv6Probe + Send + Sync),

    /// `CURLOPT_DNS_CACHE_TIMEOUT` in milliseconds.
    ///
    /// [`DNS_CACHE_TIMEOUT_FOREVER`](super::DNS_CACHE_TIMEOUT_FOREVER)
    /// means never expire. It has no default here on purpose: the option
    /// belongs to the handle, and inventing a default would put the policy in
    /// the wrong module.
    max_age_ms: TimeDiff,

    /// `CURLOPT_RESOLVER_START_FUNCTION`, if the application set one.
    resolver_start: Option<&'a mut dyn FnMut() -> i32>,

    /// The entropy source for `CURLOPT_DNS_SHUFFLE_ADDRESSES`.
    ///
    /// C's `Curl_rand(data, (unsigned char *)rnd, rnd_size)`
    /// (`lib/hostip.c:531`) with the handle replaced by whatever the closure
    /// captured. Present means shuffle; absent means do not.
    shuffle: Option<&'a mut dyn FnMut(&mut [u8]) -> CodeResult<()>>,

    /// Whether the last resolution went over DoH - C's `conn->bits.doh`.
    ///
    /// `Curl_resolv` clears it on entry (`lib/hostip.c:874-876`) and the DoH
    /// branch sets it. Retained because `CURLINFO` and the trace output
    /// distinguish a DoH lookup from a system one, and because clearing it on
    /// entry is observable: a handle that used DoH for one transfer must not
    /// still claim so for the next.
    doh_used: bool,
}

/// Written by hand rather than derived, because two members are closures and
/// `dyn FnMut` carries no [`fmt::Debug`].
impl fmt::Debug for ResolveContext<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = formatter.debug_struct("ResolveContext");
        out.field("cache", &self.cache.is_some())
            .field("clock", &self.clock)
            .field("resolver", &self.resolver);
        #[cfg(feature = "doh")]
        out.field("doh", &self.doh.is_some());
        out.field("ipv6", &self.ipv6)
            .field("ipv6_probe", &self.ipv6_probe)
            .field("max_age_ms", &self.max_age_ms)
            .field("resolver_start", &self.resolver_start.is_some())
            .field("shuffle", &self.shuffle.is_some())
            .field("doh_used", &self.doh_used)
            .finish()
    }
}

impl<'a> ResolveContext<'a> {
    /// A context over the seams a resolution cannot do without.
    ///
    /// Six arguments, every one of them an injected dependency: there is no
    /// default for any of them that would not amount to reaching for global
    /// state. The optional four - the DoH resolver, the start callback, the
    /// entropy source and the DoH flag - have builders below.
    #[allow(dead_code)]
    pub(crate) fn new(
        cache: &'a mut DnsCache,
        clock: &'a dyn Clock,
        resolver: &'a dyn Resolver,
        ipv6: &'a Ipv6Support,
        ipv6_probe: &'a (dyn Ipv6Probe + Send + Sync),
        max_age_ms: TimeDiff,
    ) -> Self {
        Self {
            cache: Some(cache),
            clock,
            resolver,
            #[cfg(feature = "doh")]
            doh: None,
            ipv6,
            ipv6_probe,
            max_age_ms,
            resolver_start: None,
            shuffle: None,
            doh_used: false,
        }
    }

    /// A context whose cache is absent, reproducing C's NULL `dnscache`.
    ///
    /// Not a curiosity: it is the only way to reach
    /// [`CURLcode::BadFunctionArgument`] from `Curl_resolv`
    /// (`lib/hostip.c:882-885`), and a path that cannot be reached cannot be
    /// tested.
    #[allow(dead_code)]
    pub(crate) fn without_cache(
        clock: &'a dyn Clock,
        resolver: &'a dyn Resolver,
        ipv6: &'a Ipv6Support,
        ipv6_probe: &'a (dyn Ipv6Probe + Send + Sync),
        max_age_ms: TimeDiff,
    ) -> Self {
        Self {
            cache: None,
            clock,
            resolver,
            #[cfg(feature = "doh")]
            doh: None,
            ipv6,
            ipv6_probe,
            max_age_ms,
            resolver_start: None,
            shuffle: None,
            doh_used: false,
        }
    }

    /// Selects DNS-over-HTTPS by handing over the resolver that performs it.
    #[cfg(feature = "doh")]
    #[allow(dead_code)]
    pub(crate) fn with_doh(mut self, doh: &'a dyn Resolver) -> Self {
        self.doh = Some(doh);
        self
    }

    /// Installs `CURLOPT_RESOLVER_START_FUNCTION`.
    #[allow(dead_code)]
    pub(crate) fn with_resolver_start(
        mut self,
        callback: &'a mut dyn FnMut() -> i32,
    ) -> Self {
        self.resolver_start = Some(callback);
        self
    }

    /// Enables `CURLOPT_DNS_SHUFFLE_ADDRESSES` by supplying its entropy.
    #[allow(dead_code)]
    pub(crate) fn with_shuffle(
        mut self,
        entropy: &'a mut dyn FnMut(&mut [u8]) -> CodeResult<()>,
    ) -> Self {
        self.shuffle = Some(entropy);
        self
    }

    /// Whether the last resolution used DoH - C's `conn->bits.doh`.
    #[allow(dead_code)]
    pub(crate) fn doh_used(&self) -> bool {
        self.doh_used
    }
}

/// Which of `Curl_resolv`'s two failure exits a failure took.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
enum Exit {
    /// C's `goto error`: the centralised path, which may store a negative
    /// resolve.
    Error(CURLcode),
    /// C's bare `return` from the `out:` block, bypassing `error:` entirely.
    Direct(CURLcode),
}

impl Exit {
    /// The code this exit carries.
    #[allow(dead_code)]
    const fn code(self) -> CURLcode {
        match self {
            Self::Error(code) | Self::Direct(code) => code,
        }
    }
}

// The resolution decision tree

/// Resolves a name, consulting and populating the cache.
///
/// # The twelve steps, in C's order
///
/// The order is behaviour, not taste. Each numbered comment in the body
/// carries its C locator, and three of the steps have a test of their own
/// because their position - not merely their effect - is observable:
/// the `.onion` refusal happens **before** the cache is consulted, the
/// cache-hit line is emitted **before** a negative entry is reported, and
/// the `CURLOPT_RESOLVER_START_FUNCTION` callback fires **only** on a cache
/// miss.
///
/// # Errors
///
/// [`CURLcode::BadFunctionArgument`] with no cache,
/// [`CURLcode::AbortedByCallback`] when the start callback refuses,
/// [`CURLcode::OutOfMemory`] when the entry cannot be built,
/// [`CURLcode::CouldntResolveHost`] for a refused or failed lookup, and
/// whatever an injected resolver reported.
#[allow(dead_code)]
pub(crate) async fn resolve(
    request: &ResolveRequest<'_>,
    ctx: &mut ResolveContext<'_>,
    tracer: &mut Tracer<'_>,
) -> CodeResult<DnsEntryRef> {
    // Step 1. `*entry = NULL;` needs no counterpart - there is no
    // out-parameter - but `data->conn->bits.doh = FALSE;`
    // (`lib/hostip.c:874-876`) does, and clearing it on entry is observable:
    // a handle that resolved over DoH once must not still say so.
    ctx.doh_used = false;

    match resolve_tree(request, ctx, tracer).await {
        Ok(entry) => Ok(entry),
        Err(exit) => {
            let code = exit.code();

            // C's `error:` label (`lib/hostip.c:1004-1011`). Its first two
            // statements have no counterpart: `Curl_resolv_unlink(data,
            // &dns)` is `Arc`'s `Drop`, which has already happened, and
            // `Curl_async_shutdown(data)` is the dropped future, which
            // cancelled itself. What remains is the negative store, and it
            // is conditional on the code:
            //
            //   if(result == CURLE_COULDNT_RESOLVE_HOST)
            //     store_negative_resolve(data, hostname, port);
            if matches!(exit, Exit::Error(_))
                && code == CURLcode::CouldntResolveHost
            {
                // C discards the return value at the call site; a failure to
                // record a failure must not replace the failure being
                // reported.
                let _ = store_negative_resolve(
                    ctx,
                    request.hostname,
                    request.port,
                    tracer,
                );
            }
            Err(code)
        }
    }
}

/// The body of [`resolve`], with C's two failure exits kept distinct.
///
/// Split out so that the `error:` label exists once, in the caller, rather
/// than at each of the six places C reaches it with a `goto`.
#[allow(clippy::too_many_lines)] // One C function, kept as one function.
#[allow(dead_code)]
async fn resolve_tree(
    request: &ResolveRequest<'_>,
    ctx: &mut ResolveContext<'_>,
    tracer: &mut Tracer<'_>,
) -> Result<DnsEntryRef, Exit> {
    let hostname = request.hostname;
    let port = request.port;

    // The injected seams that are shared references are copied out here.
    // They are `Copy`, so this ends the borrow of `*ctx` immediately and
    // leaves the mutable members - the cache, the two callbacks and the DoH
    // flag - free to be borrowed independently later.
    let clock = ctx.clock;
    let resolver = ctx.resolver;
    let ipv6 = ctx.ipv6;
    let ipv6_probe = ctx.ipv6_probe;
    let max_age_ms = ctx.max_age_ms;

    // Step 2. `DEBUGASSERT(dnscache); if(!dnscache) { result =
    // CURLE_BAD_FUNCTION_ARGUMENT; goto error; }` (`lib/hostip.c:881-885`).
    if ctx.cache.is_none() {
        return Err(Exit::Error(CURLcode::BadFunctionArgument));
    }

    // Step 3. The `.onion` refusal (`lib/hostip.c:887-895`), commented
    // *"We should intentionally error and not resolve .onion TLDs"*. It is
    // BEFORE the cache lookup, so an onion name is refused even if some
    // earlier path had cached it.
    if is_onion(hostname.as_bytes()) {
        failf!(tracer, "{}", NO_ONION);
        return Err(Exit::Error(CURLcode::CouldntResolveHost));
    }

    // Step 4. `dnscache_lock; dns = fetch_addr(...); dns->refcount++;
    // dnscache_unlock;` (`lib/hostip.c:897-907`). The lock has no
    // counterpart - `dns/mod.rs` records that the sharing policy belongs to
    // `crate::share` - and the reference count is `Arc`'s.
    let now = clock.now();
    let hit = match ctx.cache.as_deref_mut() {
        Some(cache) => cache.get(
            hostname.as_bytes(),
            port,
            request.ip_version,
            max_age_ms,
            now,
            tracer,
        ),
        // Unreachable: step 2 established the cache is present. Answered
        // rather than asserted, because no path here may panic.
        None => return Err(Exit::Error(CURLcode::BadFunctionArgument)),
    };

    if let Some(entry) = hit {
        // `infof(data, "Hostname %s was found in DNS cache", hostname)`
        // (`:904`) -- UNQUOTED, unlike its sibling at `:1491`. It is emitted
        // BEFORE the negative-entry test below, which is C's order because
        // the hit reaches `out:` by `goto` and the test lives there.
        infof!(tracer, "{}", found_in_cache(hostname));

        // Step 10. `else if(dns) { if(!dns->addr) { infof(data, "Negative
        // DNS entry"); dns->refcount--; return CURLE_COULDNT_RESOLVE_HOST; }
        // ... }` (`lib/hostip.c:974-979`). A bare `return`, NOT a
        // `goto error`, so no negative resolve is stored -- the entry it
        // would store is the one just read.
        if entry.is_negative() {
            infof!(tracer, "{}", NEGATIVE_ENTRY);
            return Err(Exit::Direct(CURLcode::CouldntResolveHost));
        }
        return Ok(entry);
    }

    // Step 5. `if(data->set.resolver_start) { ... }`
    // (`lib/hostip.c:909-926`). On a cache HIT this never runs, which is why
    // the callback's position matters and has a test.
    //
    // `Curl_async_get_impl(data, &resolver)` precedes the call and can fail,
    // but the non-c-ares build defines it as `(*(y) = NULL, CURLE_OK)`, so
    // its error arm was already unreachable there and is absent here. The
    // `Curl_set_in_callback` bracketing likewise has no counterpart: it
    // guards C against re-entrant `curl_easy_*` calls from inside a
    // callback, and a Rust closure holding no handle cannot make one.
    if let Some(start) = ctx.resolver_start.as_deref_mut() {
        if start() != 0 {
            return Err(Exit::Error(CURLcode::AbortedByCallback));
        }
    }

    let literal = is_ipaddr(hostname.as_bytes());

    // Step 6. The literal shortcut (`lib/hostip.c:928-936`), commented
    // *"shortcut literal IP addresses, if we are not told to resolve them"*.
    // The whole body sits inside `#ifndef USE_RESOLVE_ON_IPS`, so on Apple
    // platforms a literal is handed to the resolver instead -- see
    // [`RESOLVE_ON_IPS`].
    if literal && !RESOLVE_ON_IPS {
        // `result = Curl_str2addr(hostname, port, &addr); if(result) goto
        // error; goto out;`
        let addr = str2addr(hostname.as_bytes(), port).map_err(Exit::Error)?;
        return install(ctx, hostname, port, vec![addr], tracer);
    }

    // C's `else if(!Curl_is_ipaddr(hostname) && allowDOH && data->set.doh)`
    // (`lib/hostip.c:946-949`), reduced to the presence of the resolver that
    // would perform it. With the `doh` feature off there is nothing to
    // select, which is C's `#ifndef CURL_DISABLE_DOH` compiling the branch
    // out.
    #[cfg(feature = "doh")]
    let doh_target = if literal || !request.allow_doh {
        None
    } else {
        ctx.doh
    };
    #[cfg(not(feature = "doh"))]
    let doh_target: Option<&dyn Resolver> = None;

    let addrs = if is_localhost(hostname.as_bytes()) {
        // Step 7. `addr = get_localhost(port, hostname); result = addr ?
        // CURLE_OK : CURLE_OUT_OF_MEMORY;` (`lib/hostip.c:938-945`). The
        // out-of-memory arm has no counterpart: the synthesis is two pushes
        // onto a `Vec` and cannot report failure. The ORDER it produces --
        // `::1` first, `127.0.0.1` second -- is observable and is fixed by
        // [`localhost_addrs`].
        localhost_addrs(port, hostname)
    } else if let Some(doh) = doh_target {
        // Step 8. `result = Curl_doh(data, hostname, port, ip_version);
        // respwait = TRUE;`. `respwait` was how C said "the answer is not
        // here yet"; awaiting the future is that, so the flag disappears
        // along with the `CURLE_AGAIN` it eventually produced.
        ctx.doh_used = true;
        doh.resolve(hostname, port, request.ip_version)
            .await
            .map_err(Exit::Error)?
    } else {
        // Step 9. `if(!can_resolve_ip_version(data, ip_version)) { result =
        // CURLE_COULDNT_RESOLVE_HOST; goto error; }`
        // (`lib/hostip.c:951-955`). The gate is `dns/mod.rs`'s; the
        // diagnostic and the code are this file's, which is why it lives
        // here.
        let resolvable =
            can_resolve_ip_version(request.ip_version, ipv6, ipv6_probe)
                .map_err(Exit::Error)?;
        if !resolvable {
            return Err(Exit::Error(CURLcode::CouldntResolveHost));
        }

        // `CURL_TRC_DNS(data, "init threaded resolve of %s:%d", hostname,
        // port)` (`lib/asyn-thrdd.c:739`) -- one of the three trace lines
        // whose situation survives the runtime taking over the thread.
        trc_feat!(
            tracer,
            TraceFeature::Dns,
            "{}",
            msg::init_resolve(hostname, port)
        );

        // `Curl_async_getaddrinfo` and `Curl_sync_getaddrinfo` are one call
        // here. The two diagnostics C keeps apart are kept apart too, and
        // the empty-versus-error distinction is what carries them: an empty
        // answer is `Curl_sync_getaddrinfo` returning NULL, whereas an error
        // is the lookup never having been performed.
        match resolver.resolve(hostname, port, request.ip_version).await {
            Ok(addrs) => addrs,
            Err(CURLcode::CouldntResolveHost) => {
                // `failf(data, "getaddrinfo() thread failed")`
                // (`lib/asyn-thrdd.c:724`).
                failf!(tracer, "{}", msg::GETADDRINFO_TASK_FAILED);
                return Err(Exit::Error(CURLcode::CouldntResolveHost));
            }
            Err(code) => return Err(Exit::Error(code)),
        }
    };

    if addrs.is_empty() {
        // C's `addr` stayed NULL, so `result` keeps the
        // CURLE_COULDNT_RESOLVE_HOST it was initialised with and
        // `Curl_sync_getaddrinfo` has already said why
        // (`lib/hostip6.c:109-112`). The message is emitted here because the
        // [`Resolver`] seam carries no tracer -- deliberately, so that an
        // implementation cannot write to the caller's trace log behind its
        // back.
        infof!(tracer, "{}", msg::getaddrinfo_failed(hostname, port));
        return Err(Exit::Error(CURLcode::CouldntResolveHost));
    }

    install(ctx, hostname, port, addrs, tracer)
}

/// C's `out:` block for a freshly resolved address list.
///
/// Supersedes `lib/hostip.c:983-993`:
///
/// ```c
/// dns = Curl_dnscache_mk_entry(data, &addr, hostname, 0, port, FALSE);
/// if(!dns || Curl_dnscache_add(data, dns)) {
///   /* this is OOM or similar, do not store such negative resolves */
///   result = CURLE_OUT_OF_MEMORY;
///   goto error;
/// }
/// show_resolve_info(data, dns);
/// *entry = dns;
/// return CURLE_OK;
/// ```
///
/// Three details are reproduced deliberately:
///
/// * **The entry is NON-PERMANENT.** C passes `FALSE`, so the entry carries a
///   real timestamp and expires under `CURLOPT_DNS_CACHE_TIMEOUT`. Only a
///   `CURLOPT_RESOLVE` entry is permanent.
/// * **Any failure becomes [`CURLcode::OutOfMemory`]**, never the underlying
///   code. C reaches this through `!dns`, which is what a failed address
///   shuffle also produces (`lib/hostip.c:570-574`), so the mapping is
///   faithful rather than lossy.
/// * **That code is not `CURLE_COULDNT_RESOLVE_HOST`, so no negative resolve
///   is stored** - which is precisely what C's comment insists on. The
///   condition lives in [`resolve`], so this happens by construction.
#[allow(dead_code)]
fn install(
    ctx: &mut ResolveContext<'_>,
    hostname: &str,
    port: u16,
    addrs: Vec<ResolvedAddr>,
    tracer: &mut Tracer<'_>,
) -> Result<DnsEntryRef, Exit> {
    let clock = ctx.clock;

    // Two disjoint field borrows through one `&mut`, which is why the cache
    // is taken before the entropy source is inspected.
    let entropy = &mut ctx.shuffle;
    let cache = match ctx.cache.as_deref_mut() {
        Some(cache) => cache,
        // Unreachable from [`resolve_tree`], which established the cache in
        // its second step; answered rather than asserted.
        None => return Err(Exit::Error(CURLcode::BadFunctionArgument)),
    };

    // The entropy source is re-wrapped in a LOCAL closure rather than handed
    // straight through, and the reason is the borrow checker rather than
    // taste: the stored `&mut dyn FnMut` carries the context's own lifetime
    // as its trait-object bound, `&mut` is invariant in the type it points
    // at, and `add_addrs` elides a single shorter lifetime for both halves of
    // its parameter. A fresh closure gives a bound this call can satisfy.
    // The call is written twice because the two arms differ in exactly the
    // way that matters -- present means shuffle, absent means do not - and
    // collapsing them would need an always-present source.
    let built = match entropy.as_mut() {
        Some(source) => {
            let mut local = |buffer: &mut [u8]| source(buffer);
            cache.add_addrs(
                hostname,
                port,
                addrs,
                false,
                clock,
                Some(&mut local),
                tracer,
            )
        }
        None => {
            cache.add_addrs(hostname, port, addrs, false, clock, None, tracer)
        }
    };

    let entry = built.map_err(|_| Exit::Error(CURLcode::OutOfMemory))?;

    show_resolve_info(&entry, tracer);
    Ok(entry)
}

/// Records that a name could not be resolved, so the failure is cached too.
///
/// Supersedes `store_negative_resolve` (`lib/hostip.c:811-841`):
///
/// ```c
/// dns = dnscache_add_addr(data, dnscache, NULL, host, 0, port, FALSE);
/// if(dns) {
///   /* release the returned reference; the cache itself will keep the
///    * entry alive: */
///   dns->refcount--;
///   infof(data, "Store negative name resolve for %s:%d", host, port);
///   return CURLE_OK;
/// }
/// return CURLE_OUT_OF_MEMORY;
/// ```
///
/// # Errors
///
/// [`CURLcode::FailedInit`] with no cache, which is C's own answer to its
/// `DEBUGASSERT(dnscache)` - note that it differs from the
/// [`CURLcode::BadFunctionArgument`] `Curl_resolv` gives for the same
/// absence, and both are reproduced as measured.
/// [`CURLcode::OutOfMemory`] if the entry cannot be built.
#[allow(dead_code)]
pub(crate) fn store_negative_resolve(
    ctx: &mut ResolveContext<'_>,
    hostname: &str,
    port: u16,
    tracer: &mut Tracer<'_>,
) -> CodeResult<()> {
    let clock = ctx.clock;
    let cache = match ctx.cache.as_deref_mut() {
        Some(cache) => cache,
        None => return Err(CURLcode::FailedInit),
    };

    // `dnscache_add_addr(data, dnscache, NULL, host, 0, port, FALSE)` -- a
    // NULL address list is an empty one, and `FALSE` is non-permanent. No
    // entropy source is passed: shuffling nothing is nothing, and C's
    // `Curl_dnscache_mk_entry` skips the shuffle for a NULL list too.
    let entry = cache
        .add_addrs(hostname, port, Vec::new(), false, clock, None, tracer)
        .map_err(|_| CURLcode::OutOfMemory)?;

    // `dns->refcount--` with the comment *"release the returned reference;
    // the cache itself will keep the entry alive"*. Releasing an `Arc` is
    // that decrement, and the cache holds the other one.
    drop(entry);

    infof!(tracer, "{}", store_negative(hostname, port));
    Ok(())
}

/// Resolves a name and waits for the answer, refusing DoH.
///
/// Supersedes `Curl_resolv_blocking` (`lib/hostip.c:1016-1042`), which is
/// `Curl_resolv` with `allowDOH = FALSE` followed by, on `CURLE_AGAIN`, a
/// `Curl_async_await`. Two things happen to that shape here:
///
/// * **`allowDOH` is forced false**, whatever the request said. That is not a
///   preference: this entry point exists for lookups that must not recurse
///   through DoH, and resolving the DoH server's own name over DoH would not
///   terminate.
/// * **The unbounded join becomes a bounded await.** `Curl_async_await`
///   reaches `asyn_thrdd_await` (`lib/asyn-thrdd.c:495-520`), whose wait is a
///   plain `Curl_thread_join` with **no deadline at all** - a hang, if the
///   system resolver never returns. The bound applied instead is curl's own
///   [`RESOLVE_TIMEOUT_CEILING_MS`], from the constant
///   `lib/hostip.h:38-39` sets aside for this exact purpose: *"when using
///   asynch methods, we allow this many seconds for a name resolve"*.
///
/// # Errors
///
/// Whatever [`resolve`] reports, plus [`CURLcode::OperationTimedout`] if the
/// ceiling is reached.
#[allow(dead_code)]
pub(crate) async fn resolve_blocking(
    request: &ResolveRequest<'_>,
    ctx: &mut ResolveContext<'_>,
    tracer: &mut Tracer<'_>,
) -> CodeResult<DnsEntryRef> {
    // `Curl_resolv(data, hostname, port, ip_version, FALSE, entry)`.
    let no_doh = request.with_allow_doh(false);
    resolve_timeout(&no_doh, ctx, RESOLVE_TIMEOUT_CEILING_MS, tracer).await
}

/// Resolves a name under a deadline.
///
/// # The three readings of `timeout_ms`, which are not two
///
/// * **Negative means already expired** and returns
///   [`CURLcode::OperationTimedout`] without invoking the resolver at all -
///   C's first act, `if(timeoutms < 0) return CURLE_OPERATION_TIMEDOUT;`
///   (`:1100-1102`).
/// * **Zero means no deadline**, which is C's step 3:
///   `if(!timeout ...) return Curl_resolv(...)` (`:1111-1117`). The lookup
///   is then bounded only by the resolver's own limits, exactly as it is in
///   C.
/// * **Positive is honoured exactly**, to whatever resolution the runtime's
///   timer offers. C refused anything under a second because `alarm()`
///   counts in whole seconds; that refusal is **not reproduced**, and the
///   module preamble records it as Change 1.
///
/// # Errors
///
/// [`CURLcode::OperationTimedout`] for an expired or elapsed deadline, and
/// otherwise whatever [`resolve`] reports.
#[allow(dead_code)]
pub(crate) async fn resolve_timeout(
    request: &ResolveRequest<'_>,
    ctx: &mut ResolveContext<'_>,
    timeout_ms: TimeDiff,
    tracer: &mut Tracer<'_>,
) -> CodeResult<DnsEntryRef> {
    // Step 1, and it must come FIRST: `mstotv` reads a negative count as
    // "block forever", which is the opposite of what this means.
    if timeout_ms < 0 {
        return Err(CURLcode::OperationTimedout);
    }

    // Steps 2, 3 and 4 at once. `mstotv` cannot answer `None` here - the
    // sign test above ruled that out - so the only fold needed is the zero
    // one: `Some(Duration::ZERO)` is `mstotv`'s "poll", and C's step 3 reads
    // a zero timeout as "apply no deadline" instead. Handing a zero duration
    // to the timer would elapse immediately and turn every such call into a
    // spurious timeout.
    let budget = mstotv(timeout_ms).filter(|span| !span.is_zero());

    let Some(budget) = budget else {
        return resolve(request, ctx, tracer).await;
    };

    // The whole of C's alarm apparatus, in one line. The result is bound to
    // a local so that the borrows of `ctx` and `tracer` inside the future
    // end at the semicolon, leaving the tracer usable for the message below.
    let outcome =
        tokio::time::timeout(budget, resolve(request, ctx, tracer)).await;

    match outcome {
        Ok(result) => result,
        Err(_elapsed) => {
            // `failf(data, "name lookup timed out")` (`lib/hostip.c:1139`),
            // which C reached by `siglongjmp` out of a `SIGALRM` handler.
            // The text is character for character; the mechanism is gone.
            failf!(tracer, "{}", msg::NAME_LOOKUP_TIMED_OUT);
            Err(CURLcode::OperationTimedout)
        }
    }
}

/// States why a resolution failed and returns the code that accompanies it.
///
/// Supersedes `Curl_resolver_error` (`lib/hostip.c:1570-1589`):
///
/// ```c
/// failf(data, "Could not resolve %s: %s%s%s%s", host_or_proxy, name,
///       detail ? " (" : "", detail ? detail : "", detail ? ")" : "");
/// ```
///
/// Five conversions for two pieces of information, because C has no way to
/// make a parenthesised clause optional other than by emitting its three
/// parts conditionally. With a detail the line is
/// `Could not resolve host: example.com (some detail)`; without one it is
/// `Could not resolve host: example.com`, with no trailing space and no
/// empty parentheses. [`resolver_error_message`] in `dns/mod.rs` is the
/// shared formatter, so that conditional parenthesisation exists exactly
/// once; the emission is here, with the failure paths.
#[allow(dead_code)]
pub(crate) fn resolver_error(
    target: ResolveTarget,
    name: &str,
    detail: Option<&str>,
    tracer: &mut Tracer<'_>,
) -> CURLcode {
    failf!(tracer, "{}", resolver_error_message(target, name, detail));
    target.code()
}

// TESTS

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{FixedIpv6Probe, IpProto, SockType};
    use crate::trace::{TraceConfig, TraceLevel, TraceState, WriterSink};
    use crate::util::timeval::{CurlTime, TestClock};
    use std::cell::Cell;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
    use std::time::Duration;

    // -- scaffolding --------------------------------------------------------

    /// A trace configuration, a capture buffer and the tracer over them.
    ///
    /// The shape `crate::trace`'s and `dns/mod.rs`'s tests use: nothing
    /// global, nothing one test can observe from another. The `dns` feature
    /// level is raised so that the one `CURL_TRC_DNS` line this module emits
    /// is captured rather than suppressed.
    struct Log {
        config: TraceConfig,
        sink: WriterSink<Vec<u8>>,
    }

    impl Log {
        fn new() -> Self {
            let mut config = TraceConfig::new();
            config.set_feature_level(TraceFeature::Dns, TraceLevel::Info);
            Self {
                config,
                sink: WriterSink::new(Vec::new()),
            }
        }

        /// A verbose tracer over this buffer.
        ///
        /// The fields are destructured so that the shared borrow of the
        /// configuration and the exclusive borrow of the sink are of two
        /// different places rather than of `self` twice.
        fn tracer(&mut self) -> Tracer<'_> {
            let Self { config, sink } = self;
            Tracer::new(config, sink).with_state(TraceState::verbose())
        }

        /// Everything written, as text.
        fn text(self) -> String {
            String::from_utf8(self.sink.into_inner())
                .unwrap_or_else(|_| String::from("<non-utf8>"))
        }
    }

    /// A `127.0.0.x` endpoint.
    fn v4(last: u8, port: u16) -> ResolvedAddr {
        ResolvedAddr::tcp(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, last)), port),
            None,
        )
    }

    /// A `::x` endpoint.
    fn v6(last: u16, port: u16) -> ResolvedAddr {
        ResolvedAddr::tcp(
            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, last)),
                port,
            ),
            None,
        )
    }

    /// The injected [`Resolver`] every test above the syscall line uses.
    ///
    /// Programmable in the three ways the decision tree distinguishes: the
    /// answer it gives, how long it takes, and how many times it was asked.
    /// The empty-versus-error distinction matters and is reachable through
    /// both [`Self::empty`] and [`Self::failing`], because the tree emits a
    /// different diagnostic for each - C's
    /// `"getaddrinfo(3) failed for %s:%d"` against
    /// `"getaddrinfo() thread failed"`.
    #[derive(Debug)]
    struct MockResolver {
        answer: CodeResult<Vec<ResolvedAddr>>,
        delay: Duration,
        calls: AtomicUsize,
        last_ip_version: AtomicI32,
    }

    impl MockResolver {
        /// One that answers with `addrs`, immediately.
        fn answering(addrs: Vec<ResolvedAddr>) -> Self {
            Self {
                answer: Ok(addrs),
                delay: Duration::ZERO,
                calls: AtomicUsize::new(0),
                last_ip_version: AtomicI32::new(-1),
            }
        }

        /// One that answers with nothing - C's `Curl_sync_getaddrinfo`
        /// returning NULL after `getaddrinfo(3)` reported a failure.
        fn empty() -> Self {
            Self::answering(Vec::new())
        }

        /// One that could not perform the lookup at all.
        fn failing(code: CURLcode) -> Self {
            Self {
                answer: Err(code),
                delay: Duration::ZERO,
                calls: AtomicUsize::new(0),
                last_ip_version: AtomicI32::new(-1),
            }
        }

        /// The same, taking `delay` to answer.
        fn after(mut self, delay: Duration) -> Self {
            self.delay = delay;
            self
        }

        /// How many lookups reached it.
        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }

        /// The family restriction of the last lookup, if there was one.
        fn last_ip_version(&self) -> Option<IpVersion> {
            IpVersion::from_i32(self.last_ip_version.load(Ordering::SeqCst))
        }
    }

    impl Resolver for MockResolver {
        fn resolve<'a>(
            &'a self,
            _host: &'a str,
            _port: u16,
            ip_version: IpVersion,
        ) -> ResolveFuture<'a, Vec<ResolvedAddr>> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                self.last_ip_version
                    .store(ip_version.as_i32(), Ordering::SeqCst);
                if !self.delay.is_zero() {
                    tokio::time::sleep(self.delay).await;
                }
                self.answer.clone()
            })
        }
    }

    /// The clock every test injects, at a fixed and arbitrary instant.
    fn clock() -> TestClock {
        TestClock::new(CurlTime::new(1_000, 0))
    }

    /// One second of cache lifetime, so that the doubled ageing of a negative
    /// entry is reachable by a single [`TestClock::advance`].
    const ONE_SECOND_MS: TimeDiff = 1_000;

    // -- name classification ------------------------------------------------

    /// `lib/hostip.c:887-895`, case-insensitively and in both spellings.
    #[test]
    fn onion_names_are_refused_in_both_spellings_and_any_case() {
        for name in [
            "foo.onion",
            "foo.onion.",
            "FOO.ONION",
            "Foo.Onion.",
            "a.very.long.name.onion",
        ] {
            assert!(is_onion(name.as_bytes()), "{name} must be refused");
        }

        for name in ["example.com", "onion", ".onions", "onion.example"] {
            assert!(!is_onion(name.as_bytes()), "{name} must not be refused");
        }
    }

    /// The measured quirk: ONE `>= 7` gate for a six-byte suffix.
    #[test]
    fn a_bare_six_byte_onion_slips_through_the_guard() {
        assert_eq!(".onion".len(), 6);
        assert!(!is_onion(b".onion"));
        // Seven bytes is the shortest refused form, either way round.
        assert!(is_onion(b"x.onion"));
        assert!(is_onion(b".onion."));
    }

    /// `lib/hostip.c:798-805`: the length test comes first.
    #[test]
    fn tailmatch_refuses_a_suffix_longer_than_its_subject() {
        assert!(!tailmatch(b"ab", b".localhost"));
        assert!(tailmatch(b"x.localhost", b".localhost"));
        assert!(tailmatch(b"X.LOCALHOST", b".localhost"));
        // An empty suffix is a tail of everything, which is what
        // `curl_strnequal(part, ..., 0)` returns.
        assert!(tailmatch(b"anything", b""));
    }

    /// `lib/hostip.c:938-943`: two exact names and two tail matches.
    #[test]
    fn the_four_loopback_forms_match_and_notlocalhost_does_not() {
        for name in [
            "localhost",
            "localhost.",
            "LOCALHOST",
            "LocalHost.",
            "foo.localhost",
            "foo.localhost.",
            "FOO.LOCALHOST",
        ] {
            assert!(is_localhost(name.as_bytes()), "{name} is a loopback name");
        }

        // The leading dot of each suffix is what rules these out.
        for name in ["notlocalhost", "localhosts", "localhost.com", "host"] {
            assert!(
                !is_localhost(name.as_bytes()),
                "{name} is not a loopback name"
            );
        }
    }

    /// `lib/hostip6.c:79-82` is three outcomes, not two.
    #[test]
    fn allowed_families_reproduce_the_three_outcomes_of_the_c_hint() {
        // `pf = PF_INET` -- a V4 request never sees IPv6, whatever the stack.
        for works in [true, false] {
            let only_v4 = AllowedFamilies::for_request(IpVersion::V4, works);
            assert!(only_v4.accepts(AddressFamily::Inet));
            assert!(!only_v4.accepts(AddressFamily::Inet6));
        }

        // The trait's narrowing for a V6 request.
        let only_v6 = AllowedFamilies::for_request(IpVersion::V6, true);
        assert!(!only_v6.accepts(AddressFamily::Inet));
        assert!(only_v6.accepts(AddressFamily::Inet6));

        // `PF_UNSPEC` with IPv6, and the outcome that is easy to miss:
        // `PF_INET` without it.
        let both = AllowedFamilies::for_request(IpVersion::Whatever, true);
        assert!(both.accepts(AddressFamily::Inet));
        assert!(both.accepts(AddressFamily::Inet6));

        let no_stack = AllowedFamilies::for_request(IpVersion::Whatever, false);
        assert!(no_stack.accepts(AddressFamily::Inet));
        assert!(!no_stack.accepts(AddressFamily::Inet6));

        // A Unix address belongs to neither: a name resolver never makes one.
        for allowed in [only_v6, both, no_stack] {
            assert!(!allowed.accepts(AddressFamily::Unix));
        }
    }

    /// The optional resolver is unavailable at every feature setting.
    #[test]
    fn the_alternative_resolver_is_unavailable_at_every_feature_setting() {
        assert!(!alternative_resolver_available());
        // And the SECOND factor is what makes it false: the feature alone is
        // necessary and not sufficient, which is the whole point of keeping
        // the two facts apart. Written as a comparison against the
        // conjunction so that enabling the feature cannot quietly flip the
        // answer without a crate behind it.
        assert_eq!(
            alternative_resolver_available(),
            cfg!(feature = "hickory-dns") && ALTERNATIVE_RESOLVER_IS_LINKED
        );
    }

    /// The ceiling is C's constant, converted once.
    #[test]
    fn the_ceiling_is_the_c_constant_in_milliseconds() {
        assert_eq!(CURL_TIMEOUT_RESOLVE, 300);
        assert_eq!(RESOLVE_TIMEOUT_CEILING_MS, 300_000);
        // And it converts to a duration rather than being a bare number.
        assert_eq!(
            mstotv(RESOLVE_TIMEOUT_CEILING_MS),
            Some(Duration::from_secs(300))
        );
    }

    /// The literal shortcut follows the platform, not a build choice.
    ///
    /// `lib/curl_setup.h:407-409` defines `USE_RESOLVE_ON_IPS` for
    /// `__APPLE__` only, so the constant must be true on exactly those
    /// targets. Asserted against `cfg!` rather than against a literal, so the
    /// test states the RULE and passes on every mandated target.
    #[test]
    fn resolve_on_ips_matches_the_platform_c_compiles_for() {
        assert_eq!(
            RESOLVE_ON_IPS,
            cfg!(any(target_os = "macos", target_os = "ios"))
        );
    }

    // -- Curl_resolver_error ------------------------------------------------

    /// `lib/hostip.c:1586-1587`, both arms of the conditional
    /// parenthesisation.
    #[test]
    fn resolver_error_parenthesises_a_detail_and_omits_it_otherwise() {
        let mut log = Log::new();
        let code = {
            let mut tracer = log.tracer();
            resolver_error(
                ResolveTarget::Host,
                "example.com",
                Some("some detail"),
                &mut tracer,
            )
        };
        assert_eq!(code, CURLcode::CouldntResolveHost);
        assert!(
            log.text()
                .contains("Could not resolve host: example.com (some detail)"),
            "the detail is parenthesised"
        );

        let mut log = Log::new();
        let code = {
            let mut tracer = log.tracer();
            resolver_error(
                ResolveTarget::Host,
                "example.com",
                None,
                &mut tracer,
            )
        };
        assert_eq!(code, CURLcode::CouldntResolveHost);
        let text = log.text();
        assert!(text.contains("Could not resolve host: example.com"));
        // No trailing space and no empty parentheses.
        assert!(!text.contains("example.com ("));
        assert!(!text.contains("example.com ()"));
    }

    /// The proxy variant says `proxy` and carries its own code.
    #[test]
    fn the_proxy_variant_says_proxy_and_yields_its_own_code() {
        let mut log = Log::new();
        let code = {
            let mut tracer = log.tracer();
            resolver_error(
                ResolveTarget::Proxy,
                "proxy.example",
                Some("refused"),
                &mut tracer,
            )
        };
        assert_eq!(code, CURLcode::CouldntResolveProxy);
        assert!(log
            .text()
            .contains("Could not resolve proxy: proxy.example (refused)"));
    }

    // -- the decision tree, step by step ------------------------------------

    /// Step 2: `lib/hostip.c:882-885`.
    ///
    /// Reachable only because the cache is modelled as an [`Option`], which
    /// is what `dnscache_get(data)` returning NULL becomes.
    #[tokio::test(start_paused = true)]
    async fn a_missing_cache_is_a_bad_function_argument() {
        let resolver = MockResolver::answering(vec![v4(1, 80)]);
        let time = clock();
        let probe = FixedIpv6Probe(Ok(true));
        let support = Ipv6Support::known(true);
        let mut log = Log::new();
        let request = ResolveRequest::new("example.com", 80);

        let mut ctx = ResolveContext::without_cache(
            &time,
            &resolver,
            &support,
            &probe,
            ONE_SECOND_MS,
        );
        let mut tracer = log.tracer();
        let outcome = resolve(&request, &mut ctx, &mut tracer).await;

        assert_eq!(outcome.err(), Some(CURLcode::BadFunctionArgument));
        assert_eq!(resolver.calls(), 0, "the resolver is never reached");
    }

    /// Step 3, and its position: BEFORE the cache is consulted.
    ///
    /// C reaches `goto error` with `result` still at the
    /// `CURLE_COULDNT_RESOLVE_HOST` it was initialised with
    /// (`lib/hostip.c:868`), so the error path stores a negative resolve for
    /// an onion name too. Both halves are asserted.
    #[tokio::test(start_paused = true)]
    async fn an_onion_name_is_refused_and_its_failure_is_remembered() {
        let resolver = MockResolver::answering(vec![v4(1, 80)]);
        let time = clock();
        let probe = FixedIpv6Probe(Ok(true));
        let support = Ipv6Support::known(true);
        let mut cache = DnsCache::new();
        let mut log = Log::new();
        let request = ResolveRequest::new("secret.onion", 80);

        let outcome = {
            let mut ctx = ResolveContext::new(
                &mut cache,
                &time,
                &resolver,
                &support,
                &probe,
                ONE_SECOND_MS,
            );
            let mut tracer = log.tracer();
            resolve(&request, &mut ctx, &mut tracer).await
        };

        assert_eq!(outcome.err(), Some(CURLcode::CouldntResolveHost));
        assert_eq!(resolver.calls(), 0, "an onion name never reaches a lookup");
        assert_eq!(cache.len(), 1, "the refusal is cached as a negative entry");

        let text = log.text();
        assert!(text.contains("Not resolving .onion address (RFC 7686)"));
        assert!(
            text.contains("Store negative name resolve for secret.onion:80")
        );
    }

    /// Step 4: the cache answers and the resolver is never asked.
    #[tokio::test(start_paused = true)]
    async fn a_cache_hit_reports_the_cache_and_never_calls_the_resolver() {
        let resolver = MockResolver::answering(vec![v4(1, 80)]);
        let time = clock();
        let probe = FixedIpv6Probe(Ok(true));
        let support = Ipv6Support::known(true);
        let mut cache = DnsCache::new();
        let mut log = Log::new();

        {
            let mut tracer = log.tracer();
            cache
                .add_addrs(
                    "example.com",
                    80,
                    vec![v4(9, 80)],
                    false,
                    &time,
                    None,
                    &mut tracer,
                )
                .expect("the seeded entry is built");
        }

        let request = ResolveRequest::new("example.com", 80);
        let entry = {
            let mut ctx = ResolveContext::new(
                &mut cache,
                &time,
                &resolver,
                &support,
                &probe,
                ONE_SECOND_MS,
            );
            let mut tracer = log.tracer();
            resolve(&request, &mut ctx, &mut tracer)
                .await
                .expect("the cache answers")
        };

        assert_eq!(resolver.calls(), 0);
        assert_eq!(entry.addrs, vec![v4(9, 80)]);
        // `lib/hostip.c:904` -- UNQUOTED, unlike its sibling at `:1491`.
        assert!(log
            .text()
            .contains("Hostname example.com was found in DNS cache"));
    }

    /// Step 10: a hit with no addresses, and the exit it takes.
    ///
    /// The cache-hit line comes FIRST, then the negative report - C's order,
    /// because the hit reaches `out:` by `goto` and the test lives there. And
    /// the exit is a bare `return`, so NO further negative resolve is stored:
    /// the cache still holds exactly the one entry that was seeded.
    #[tokio::test(start_paused = true)]
    async fn a_negative_cache_hit_reports_it_and_stores_nothing_further() {
        let resolver = MockResolver::answering(vec![v4(1, 80)]);
        let time = clock();
        let probe = FixedIpv6Probe(Ok(true));
        let support = Ipv6Support::known(true);
        let mut cache = DnsCache::new();
        let mut log = Log::new();

        {
            let mut tracer = log.tracer();
            cache
                .add_addrs(
                    "nowhere.example",
                    80,
                    Vec::new(),
                    false,
                    &time,
                    None,
                    &mut tracer,
                )
                .expect("a negative entry is still an entry");
        }
        assert_eq!(cache.len(), 1);

        let request = ResolveRequest::new("nowhere.example", 80);
        let outcome = {
            let mut ctx = ResolveContext::new(
                &mut cache,
                &time,
                &resolver,
                &support,
                &probe,
                ONE_SECOND_MS,
            );
            let mut tracer = log.tracer();
            resolve(&request, &mut ctx, &mut tracer).await
        };

        assert_eq!(outcome.err(), Some(CURLcode::CouldntResolveHost));
        assert_eq!(resolver.calls(), 0);
        assert_eq!(cache.len(), 1, "no second negative entry was stored");

        let text = log.text();
        let cached_at = text
            .find("Hostname nowhere.example was found in DNS cache")
            .expect("the cache-hit line is emitted");
        let negative_at = text
            .find("Negative DNS entry")
            .expect("and then the report");
        assert!(cached_at < negative_at, "the cache line comes first");
        assert!(
            !text.contains("Store negative name resolve"),
            "the direct exit bypasses the error path"
        );
    }

    /// Step 5's position: the callback fires on a MISS and not on a hit.
    #[tokio::test(start_paused = true)]
    async fn the_start_callback_fires_only_on_a_cache_miss() {
        let resolver = MockResolver::answering(vec![v4(1, 80)]);
        let time = clock();
        let probe = FixedIpv6Probe(Ok(true));
        let support = Ipv6Support::known(true);
        let mut cache = DnsCache::new();
        let mut log = Log::new();
        let starts = Cell::new(0_usize);
        let request = ResolveRequest::new("example.com", 80);

        {
            let mut start = || {
                starts.set(starts.get() + 1);
                0
            };
            let mut ctx = ResolveContext::new(
                &mut cache,
                &time,
                &resolver,
                &support,
                &probe,
                ONE_SECOND_MS,
            )
            .with_resolver_start(&mut start);
            let mut tracer = log.tracer();
            resolve(&request, &mut ctx, &mut tracer)
                .await
                .expect("the miss is resolved");
        }
        assert_eq!(starts.get(), 1, "the miss consulted the callback");
        assert_eq!(resolver.calls(), 1);

        // The same name again, now cached: no second callback.
        {
            let mut start = || {
                starts.set(starts.get() + 1);
                0
            };
            let mut ctx = ResolveContext::new(
                &mut cache,
                &time,
                &resolver,
                &support,
                &probe,
                ONE_SECOND_MS,
            )
            .with_resolver_start(&mut start);
            let mut tracer = log.tracer();
            resolve(&request, &mut ctx, &mut tracer)
                .await
                .expect("the cache answers");
        }
        assert_eq!(starts.get(), 1, "a cache hit never consults the callback");
        assert_eq!(resolver.calls(), 1);
    }

    /// Step 5: a non-zero return aborts.
    #[tokio::test(start_paused = true)]
    async fn a_refusing_start_callback_aborts_by_callback() {
        let resolver = MockResolver::answering(vec![v4(1, 80)]);
        let time = clock();
        let probe = FixedIpv6Probe(Ok(true));
        let support = Ipv6Support::known(true);
        let mut cache = DnsCache::new();
        let mut log = Log::new();
        let request = ResolveRequest::new("example.com", 80);

        let outcome = {
            let mut refuse = || 1;
            let mut ctx = ResolveContext::new(
                &mut cache,
                &time,
                &resolver,
                &support,
                &probe,
                ONE_SECOND_MS,
            )
            .with_resolver_start(&mut refuse);
            let mut tracer = log.tracer();
            resolve(&request, &mut ctx, &mut tracer).await
        };

        assert_eq!(outcome.err(), Some(CURLcode::AbortedByCallback));
        assert_eq!(resolver.calls(), 0);
        // Not a resolve failure, so nothing is cached.
        assert!(cache.is_empty());
        assert!(!log.text().contains("Store negative name resolve"));
    }

    /// Step 6: a numeric literal is converted locally, off Apple platforms.
    ///
    /// Asserted against [`RESOLVE_ON_IPS`] rather than against one answer, so
    /// the test states the rule on all four mandated targets: on Linux the
    /// resolver is bypassed, and on Apple platforms C deliberately hands the
    /// literal to `getaddrinfo` for NAT64 synthesis.
    #[tokio::test(start_paused = true)]
    async fn a_literal_address_short_circuits_the_resolver() {
        for literal in ["127.0.0.1", "::1"] {
            let resolver = MockResolver::answering(vec![v4(1, 443)]);
            let time = clock();
            let probe = FixedIpv6Probe(Ok(true));
            let support = Ipv6Support::known(true);
            let mut cache = DnsCache::new();
            let mut log = Log::new();
            let request = ResolveRequest::new(literal, 443);

            let entry = {
                let mut ctx = ResolveContext::new(
                    &mut cache,
                    &time,
                    &resolver,
                    &support,
                    &probe,
                    ONE_SECOND_MS,
                );
                let mut tracer = log.tracer();
                resolve(&request, &mut ctx, &mut tracer)
                    .await
                    .expect("a literal always resolves")
            };

            if RESOLVE_ON_IPS {
                assert_eq!(
                    resolver.calls(),
                    1,
                    "{literal} goes to the resolver"
                );
            } else {
                assert_eq!(resolver.calls(), 0, "{literal} is converted here");
                // `ip2addr` sets SOCK_STREAM and copies the dotted text into
                // `ai_canonname` (`lib/curl_addrinfo.c:373-375`), leaving the
                // protocol at the zero its `calloc` produced.
                let addr = &entry.addrs[0];
                assert_eq!(addr.socktype, SockType::Stream);
                assert_eq!(addr.protocol, IpProto::Unspecified);
                assert_eq!(addr.canonname.as_deref(), Some(literal));
                assert_eq!(
                    addr.socket_addr().map(|socket| socket.port()),
                    Some(443)
                );
            }
        }
    }

    /// Step 7: every loopback form synthesises, `::1` before `127.0.0.1`.
    ///
    /// The order is observable: `crate::conn`'s Happy Eyeballs race reads the
    /// list in the order it was produced.
    #[tokio::test(start_paused = true)]
    async fn a_loopback_name_synthesises_ipv6_before_ipv4() {
        for name in [
            "localhost",
            "localhost.",
            "LOCALHOST",
            "foo.localhost",
            "foo.localhost.",
        ] {
            let resolver = MockResolver::answering(vec![v4(1, 8080)]);
            let time = clock();
            let probe = FixedIpv6Probe(Ok(true));
            let support = Ipv6Support::known(true);
            let mut cache = DnsCache::new();
            let mut log = Log::new();
            let request = ResolveRequest::new(name, 8080);

            let entry = {
                let mut ctx = ResolveContext::new(
                    &mut cache,
                    &time,
                    &resolver,
                    &support,
                    &probe,
                    ONE_SECOND_MS,
                );
                let mut tracer = log.tracer();
                resolve(&request, &mut ctx, &mut tracer)
                    .await
                    .expect("a loopback name always resolves")
            };

            assert_eq!(resolver.calls(), 0, "{name} is synthesised");
            assert_eq!(entry.addrs.len(), 2, "{name} yields both families");
            assert_eq!(entry.addrs[0].family(), AddressFamily::Inet6);
            assert_eq!(entry.addrs[1].family(), AddressFamily::Inet);
            assert_eq!(
                entry.addrs[0].socket_addr(),
                Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080))
            );
            assert_eq!(
                entry.addrs[1].socket_addr(),
                Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080))
            );
        }

        // And a name that merely ends in the label is NOT a loopback name, so
        // it does reach the resolver.
        let resolver = MockResolver::answering(vec![v4(1, 80)]);
        let time = clock();
        let probe = FixedIpv6Probe(Ok(true));
        let support = Ipv6Support::known(true);
        let mut cache = DnsCache::new();
        let mut log = Log::new();
        let request = ResolveRequest::new("notlocalhost", 80);
        {
            let mut ctx = ResolveContext::new(
                &mut cache,
                &time,
                &resolver,
                &support,
                &probe,
                ONE_SECOND_MS,
            );
            let mut tracer = log.tracer();
            resolve(&request, &mut ctx, &mut tracer)
                .await
                .expect("it resolves through the resolver");
        }
        assert_eq!(resolver.calls(), 1);
        drop(log);
    }

    /// Step 9: `can_resolve_ip_version` (`lib/hostip.c:951-955`).
    #[tokio::test(start_paused = true)]
    async fn a_v6_request_without_ipv6_cannot_resolve() {
        let resolver = MockResolver::answering(vec![v6(1, 80)]);
        let time = clock();
        let probe = FixedIpv6Probe(Ok(false));
        let support = Ipv6Support::known(false);
        let mut cache = DnsCache::new();
        let mut log = Log::new();
        let request = ResolveRequest::new("example.com", 80)
            .with_ip_version(IpVersion::V6);

        let outcome = {
            let mut ctx = ResolveContext::new(
                &mut cache,
                &time,
                &resolver,
                &support,
                &probe,
                ONE_SECOND_MS,
            );
            let mut tracer = log.tracer();
            resolve(&request, &mut ctx, &mut tracer).await
        };

        assert_eq!(outcome.err(), Some(CURLcode::CouldntResolveHost));
        assert_eq!(resolver.calls(), 0, "the gate is before the lookup");
        // A resolve failure, so the refusal is remembered.
        assert!(log.text().contains("Store negative name resolve"));
    }

    /// Step 9: a V4 request proceeds whatever the IPv6 answer, and the
    /// restriction reaches the resolver.
    #[tokio::test(start_paused = true)]
    async fn a_v4_request_proceeds_whatever_the_ipv6_answer() {
        for works in [true, false] {
            let resolver = MockResolver::answering(vec![v4(4, 80)]);
            let time = clock();
            let probe = FixedIpv6Probe(Ok(works));
            let support = Ipv6Support::known(works);
            let mut cache = DnsCache::new();
            let mut log = Log::new();
            let request = ResolveRequest::new("example.com", 80)
                .with_ip_version(IpVersion::V4);

            {
                let mut ctx = ResolveContext::new(
                    &mut cache,
                    &time,
                    &resolver,
                    &support,
                    &probe,
                    ONE_SECOND_MS,
                );
                let mut tracer = log.tracer();
                resolve(&request, &mut ctx, &mut tracer)
                    .await
                    .expect("a V4 request always proceeds");
            }
            assert_eq!(resolver.calls(), 1);
            assert_eq!(resolver.last_ip_version(), Some(IpVersion::V4));
            drop(log);
        }
    }

    /// An empty answer is C's `Curl_sync_getaddrinfo` returning NULL.
    #[tokio::test(start_paused = true)]
    async fn an_empty_answer_reports_getaddrinfo_and_is_remembered() {
        let resolver = MockResolver::empty();
        let time = clock();
        let probe = FixedIpv6Probe(Ok(true));
        let support = Ipv6Support::known(true);
        let mut cache = DnsCache::new();
        let mut log = Log::new();
        let request = ResolveRequest::new("nowhere.example", 8080);

        let outcome = {
            let mut ctx = ResolveContext::new(
                &mut cache,
                &time,
                &resolver,
                &support,
                &probe,
                ONE_SECOND_MS,
            );
            let mut tracer = log.tracer();
            resolve(&request, &mut ctx, &mut tracer).await
        };

        assert_eq!(outcome.err(), Some(CURLcode::CouldntResolveHost));
        assert_eq!(resolver.calls(), 1);
        assert_eq!(cache.len(), 1);

        let text = log.text();
        assert!(text.contains("init threaded resolve of nowhere.example:8080"));
        assert!(text.contains("getaddrinfo(3) failed for nowhere.example:8080"));
        assert!(text
            .contains("Store negative name resolve for nowhere.example:8080"));
        // The task-failure line belongs to the OTHER situation.
        assert!(!text.contains("getaddrinfo() thread failed"));
    }

    /// A lookup that could not be performed is the OTHER diagnostic.
    #[tokio::test(start_paused = true)]
    async fn a_lookup_that_never_answered_reports_the_task_and_is_remembered() {
        let resolver = MockResolver::failing(CURLcode::CouldntResolveHost);
        let time = clock();
        let probe = FixedIpv6Probe(Ok(true));
        let support = Ipv6Support::known(true);
        let mut cache = DnsCache::new();
        let mut log = Log::new();
        let request = ResolveRequest::new("example.com", 80);

        let outcome = {
            let mut ctx = ResolveContext::new(
                &mut cache,
                &time,
                &resolver,
                &support,
                &probe,
                ONE_SECOND_MS,
            );
            let mut tracer = log.tracer();
            resolve(&request, &mut ctx, &mut tracer).await
        };

        assert_eq!(outcome.err(), Some(CURLcode::CouldntResolveHost));
        assert_eq!(cache.len(), 1);
        let text = log.text();
        assert!(text.contains("getaddrinfo() thread failed"));
        assert!(!text.contains("getaddrinfo(3) failed for"));
    }

    /// A resolver error that is not a resolve failure is reported unchanged
    /// and remembers nothing.
    #[tokio::test(start_paused = true)]
    async fn an_error_that_is_not_a_resolve_failure_stores_nothing() {
        for code in [
            CURLcode::AbortedByCallback,
            CURLcode::OutOfMemory,
            CURLcode::OperationTimedout,
            CURLcode::CouldntResolveProxy,
        ] {
            let resolver = MockResolver::failing(code);
            let time = clock();
            let probe = FixedIpv6Probe(Ok(true));
            let support = Ipv6Support::known(true);
            let mut cache = DnsCache::new();
            let mut log = Log::new();
            let request = ResolveRequest::new("example.com", 80);

            let outcome = {
                let mut ctx = ResolveContext::new(
                    &mut cache,
                    &time,
                    &resolver,
                    &support,
                    &probe,
                    ONE_SECOND_MS,
                );
                let mut tracer = log.tracer();
                resolve(&request, &mut ctx, &mut tracer).await
            };

            assert_eq!(outcome.err(), Some(code), "{code:?} is propagated");
            assert!(cache.is_empty(), "{code:?} caches nothing");
            assert!(!log.text().contains("Store negative name resolve"));
        }
    }

    /// Step 11: a fresh answer is cached NON-PERMANENTLY, and reported.
    #[tokio::test(start_paused = true)]
    async fn a_fresh_answer_is_cached_non_permanently_and_reported() {
        let resolver = MockResolver::answering(vec![v6(1, 80), v4(1, 80)]);
        let time = clock();
        let probe = FixedIpv6Probe(Ok(true));
        let support = Ipv6Support::known(true);
        let mut cache = DnsCache::new();
        let mut log = Log::new();
        let request = ResolveRequest::new("example.com", 80);

        let entry = {
            let mut ctx = ResolveContext::new(
                &mut cache,
                &time,
                &resolver,
                &support,
                &probe,
                ONE_SECOND_MS,
            );
            let mut tracer = log.tracer();
            resolve(&request, &mut ctx, &mut tracer)
                .await
                .expect("the lookup succeeds")
        };

        assert!(!entry.is_permanent(), "only CURLOPT_RESOLVE is permanent");
        assert!(!entry.is_negative());
        assert_eq!(entry.hostname, "example.com");
        assert_eq!(entry.hostport, 80);
        assert_eq!(cache.len(), 1);

        // `show_resolve_info` runs before the entry is handed back, and its
        // IPv6 line precedes its IPv4 line.
        let text = log.text();
        let resolved_at = text
            .find("Host example.com:80 was resolved.")
            .expect("the resolve is reported");
        let v6_at = text.find("IPv6: ::1").expect("the IPv6 line");
        let v4_at = text.find("IPv4: 127.0.0.1").expect("the IPv4 line");
        assert!(resolved_at < v6_at && v6_at < v4_at);
    }

    /// A failure to BUILD the entry is out of memory, and caches nothing.
    #[tokio::test(start_paused = true)]
    async fn a_failure_to_build_the_entry_is_out_of_memory_and_caches_nothing()
    {
        let resolver = MockResolver::answering(vec![v4(1, 80), v4(2, 80)]);
        let time = clock();
        let probe = FixedIpv6Probe(Ok(true));
        let support = Ipv6Support::known(true);
        let mut cache = DnsCache::new();
        let mut log = Log::new();
        let request = ResolveRequest::new("example.com", 80);

        let outcome = {
            let mut broken =
                |_: &mut [u8]| -> CodeResult<()> { Err(CURLcode::OutOfMemory) };
            let mut ctx = ResolveContext::new(
                &mut cache,
                &time,
                &resolver,
                &support,
                &probe,
                ONE_SECOND_MS,
            )
            .with_shuffle(&mut broken);
            let mut tracer = log.tracer();
            resolve(&request, &mut ctx, &mut tracer).await
        };

        assert_eq!(outcome.err(), Some(CURLcode::OutOfMemory));
        assert!(cache.is_empty(), "no entry, and no negative resolve either");
        assert!(!log.text().contains("Store negative name resolve"));
    }

    /// Negative entries age at DOUBLE rate, which gates the retry.
    #[tokio::test(start_paused = true)]
    async fn a_negative_entry_ages_twice_as_fast_and_gates_the_retry() {
        let resolver = MockResolver::empty();
        let time = clock();
        let probe = FixedIpv6Probe(Ok(true));
        let support = Ipv6Support::known(true);
        let mut cache = DnsCache::new();
        let request = ResolveRequest::new("nowhere.example", 80);

        // First attempt: the lookup fails and the failure is remembered.
        let mut log = Log::new();
        {
            let mut ctx = ResolveContext::new(
                &mut cache,
                &time,
                &resolver,
                &support,
                &probe,
                ONE_SECOND_MS,
            );
            let mut tracer = log.tracer();
            let outcome = resolve(&request, &mut ctx, &mut tracer).await;
            assert_eq!(outcome.err(), Some(CURLcode::CouldntResolveHost));
        }
        assert_eq!(resolver.calls(), 1);
        assert!(log.text().contains("Store negative name resolve"));

        // 400 ms later: doubled that is 800, still inside the second, so the
        // negative entry answers and the resolver is NOT asked again.
        time.advance(Duration::from_millis(400));
        let mut log = Log::new();
        {
            let mut ctx = ResolveContext::new(
                &mut cache,
                &time,
                &resolver,
                &support,
                &probe,
                ONE_SECOND_MS,
            );
            let mut tracer = log.tracer();
            let outcome = resolve(&request, &mut ctx, &mut tracer).await;
            assert_eq!(outcome.err(), Some(CURLcode::CouldntResolveHost));
        }
        assert_eq!(resolver.calls(), 1, "the cached failure answered");
        assert!(log.text().contains("Negative DNS entry"));

        // 200 ms further on - 600 ms in all, doubled to 1,200 - the entry is
        // stale and the lookup is retried.
        time.advance(Duration::from_millis(200));
        let mut log = Log::new();
        {
            let mut ctx = ResolveContext::new(
                &mut cache,
                &time,
                &resolver,
                &support,
                &probe,
                ONE_SECOND_MS,
            );
            let mut tracer = log.tracer();
            let outcome = resolve(&request, &mut ctx, &mut tracer).await;
            assert_eq!(outcome.err(), Some(CURLcode::CouldntResolveHost));
        }
        assert_eq!(resolver.calls(), 2, "the stale failure was retried");
        assert!(log
            .text()
            .contains("Hostname in DNS cache was stale, zapped"));
    }

    /// Step 8: DoH is used when a DoH resolver is injected, and the flag is
    /// set.
    #[cfg(feature = "doh")]
    #[tokio::test(start_paused = true)]
    async fn doh_answers_when_one_is_injected_and_sets_the_flag() {
        let system = MockResolver::answering(vec![v4(1, 443)]);
        let over_doh = MockResolver::answering(vec![v4(2, 443)]);
        let time = clock();
        let probe = FixedIpv6Probe(Ok(true));
        let support = Ipv6Support::known(true);
        let mut cache = DnsCache::new();
        let mut log = Log::new();
        let request = ResolveRequest::new("example.com", 443);

        let (entry, used) = {
            let mut ctx = ResolveContext::new(
                &mut cache,
                &time,
                &system,
                &support,
                &probe,
                ONE_SECOND_MS,
            )
            .with_doh(&over_doh);
            let mut tracer = log.tracer();
            let entry = resolve(&request, &mut ctx, &mut tracer)
                .await
                .expect("DoH answers");
            (entry, ctx.doh_used())
        };

        assert!(used, "conn->bits.doh is set for a DoH lookup");
        assert_eq!(over_doh.calls(), 1);
        assert_eq!(system.calls(), 0, "the system resolver is bypassed");
        assert_eq!(entry.addrs, vec![v4(2, 443)]);
        drop(log);
    }

    /// Step 8's two refusals: a literal and a request that forbids DoH.
    ///
    /// The second is what `Curl_resolv_blocking` relies on to keep the DoH
    /// server's own name from being resolved over DoH.
    #[cfg(feature = "doh")]
    #[tokio::test(start_paused = true)]
    async fn doh_is_refused_for_a_literal_and_when_the_request_forbids_it() {
        let system = MockResolver::answering(vec![v4(1, 443)]);
        let over_doh = MockResolver::answering(vec![v4(2, 443)]);
        let time = clock();
        let probe = FixedIpv6Probe(Ok(true));
        let support = Ipv6Support::known(true);
        let mut cache = DnsCache::new();
        let mut log = Log::new();

        let request =
            ResolveRequest::new("example.com", 443).with_allow_doh(false);
        let used = {
            let mut ctx = ResolveContext::new(
                &mut cache,
                &time,
                &system,
                &support,
                &probe,
                ONE_SECOND_MS,
            )
            .with_doh(&over_doh);
            let mut tracer = log.tracer();
            resolve(&request, &mut ctx, &mut tracer)
                .await
                .expect("the system resolver answers");
            ctx.doh_used()
        };
        assert!(!used);
        assert_eq!(over_doh.calls(), 0, "allow_doh = false refuses DoH");
        assert_eq!(system.calls(), 1);
        drop(log);

        // A literal never goes to DoH either, whatever the request says.
        let mut cache = DnsCache::new();
        let mut log = Log::new();
        let literal = ResolveRequest::new("127.0.0.1", 443);
        let used = {
            let mut ctx = ResolveContext::new(
                &mut cache,
                &time,
                &system,
                &support,
                &probe,
                ONE_SECOND_MS,
            )
            .with_doh(&over_doh);
            let mut tracer = log.tracer();
            resolve(&literal, &mut ctx, &mut tracer)
                .await
                .expect("a literal always resolves");
            ctx.doh_used()
        };
        assert!(!used, "a numeric address is never resolved over DoH");
        assert_eq!(over_doh.calls(), 0);
        drop(log);
    }

    /// The DoH flag is CLEARED on entry, so one lookup cannot speak for the
    /// next - C's `data->conn->bits.doh = FALSE;` (`lib/hostip.c:874-876`).
    #[cfg(feature = "doh")]
    #[tokio::test(start_paused = true)]
    async fn the_doh_flag_is_cleared_on_every_entry() {
        let system = MockResolver::answering(vec![v4(1, 443)]);
        let over_doh = MockResolver::answering(vec![v4(2, 443)]);
        let time = clock();
        let probe = FixedIpv6Probe(Ok(true));
        let support = Ipv6Support::known(true);
        let mut cache = DnsCache::new();
        let mut log = Log::new();

        let mut ctx = ResolveContext::new(
            &mut cache,
            &time,
            &system,
            &support,
            &probe,
            ONE_SECOND_MS,
        )
        .with_doh(&over_doh);

        {
            let over = ResolveRequest::new("example.com", 443);
            let mut tracer = log.tracer();
            resolve(&over, &mut ctx, &mut tracer)
                .await
                .expect("DoH answers");
        }
        assert!(ctx.doh_used());

        {
            // A literal, which never uses DoH: the flag must go back down.
            let direct = ResolveRequest::new("127.0.0.1", 443);
            let mut tracer = log.tracer();
            resolve(&direct, &mut ctx, &mut tracer)
                .await
                .expect("a literal always resolves");
        }
        assert!(!ctx.doh_used(), "the flag is cleared on entry");
        drop(log);
    }

    // -- the deadline -------------------------------------------------------

    /// THE HEADLINE TEST. A sub-second deadline is HONOURED, not refused.
    ///
    /// C bails at `lib/hostip.c:1119-1126` with
    /// `"remaining timeout of %ld too small to resolve via SIGALRM method"`
    /// and `CURLE_OPERATION_TIMEDOUT`, because `alarm()` counts whole seconds
    /// and `alarm(200 / 1000)` is `alarm(0)`, which CANCELS an alarm. With
    /// `tokio::time::timeout` there is no such floor, so a lookup that
    /// answers in 10 milliseconds under a 200-millisecond budget must
    /// SUCCEED. This is the executable proof of Change 1, and the message C
    /// emitted must appear nowhere.
    #[tokio::test(start_paused = true)]
    async fn a_sub_second_timeout_is_honoured_not_refused() {
        let resolver = MockResolver::answering(vec![v4(1, 80)])
            .after(Duration::from_millis(10));
        let time = clock();
        let probe = FixedIpv6Probe(Ok(true));
        let support = Ipv6Support::known(true);
        let mut cache = DnsCache::new();
        let mut log = Log::new();
        let request = ResolveRequest::new("example.com", 80);

        let outcome = {
            let mut ctx = ResolveContext::new(
                &mut cache,
                &time,
                &resolver,
                &support,
                &probe,
                ONE_SECOND_MS,
            );
            let mut tracer = log.tracer();
            // 200 ms: under C's one-second floor, and comfortably over the
            // 10 ms the lookup needs.
            resolve_timeout(&request, &mut ctx, 200, &mut tracer).await
        };

        let entry = outcome.expect("a sub-second deadline must be honoured");
        assert_eq!(entry.addrs, vec![v4(1, 80)]);
        assert_eq!(resolver.calls(), 1);

        let text = log.text();
        assert!(
            !text.contains("too small to resolve"),
            "C's SIGALRM floor must not be reproduced"
        );
        assert!(!text.contains("name lookup timed out"));
    }

    /// An elapsed deadline reports C's exact text.
    #[tokio::test(start_paused = true)]
    async fn an_elapsed_deadline_reports_name_lookup_timed_out() {
        let resolver = MockResolver::answering(vec![v4(1, 80)])
            .after(Duration::from_secs(10));
        let time = clock();
        let probe = FixedIpv6Probe(Ok(true));
        let support = Ipv6Support::known(true);
        let mut cache = DnsCache::new();
        let mut log = Log::new();
        let request = ResolveRequest::new("example.com", 80);

        let outcome = {
            let mut ctx = ResolveContext::new(
                &mut cache,
                &time,
                &resolver,
                &support,
                &probe,
                ONE_SECOND_MS,
            );
            let mut tracer = log.tracer();
            resolve_timeout(&request, &mut ctx, 200, &mut tracer).await
        };

        assert_eq!(outcome.err(), Some(CURLcode::OperationTimedout));
        // `lib/hostip.c:1139`, character for character.
        assert!(log.text().contains("name lookup timed out"));
        assert!(cache.is_empty(), "a cancelled lookup installs nothing");
    }

    /// An already-expired deadline never reaches the resolver.
    ///
    /// C's first act (`lib/hostip.c:1100-1102`). This is the reading that is
    /// the OPPOSITE of [`mstotv`]'s, whose `None` means "block forever", and
    /// the reason the sign test comes first.
    #[tokio::test(start_paused = true)]
    async fn an_already_expired_deadline_never_calls_the_resolver() {
        for expired in [-1, -1_000, TimeDiff::MIN] {
            let resolver = MockResolver::answering(vec![v4(1, 80)]);
            let time = clock();
            let probe = FixedIpv6Probe(Ok(true));
            let support = Ipv6Support::known(true);
            let mut cache = DnsCache::new();
            let mut log = Log::new();
            let request = ResolveRequest::new("example.com", 80);

            let outcome = {
                let mut ctx = ResolveContext::new(
                    &mut cache,
                    &time,
                    &resolver,
                    &support,
                    &probe,
                    ONE_SECOND_MS,
                );
                let mut tracer = log.tracer();
                resolve_timeout(&request, &mut ctx, expired, &mut tracer).await
            };

            assert_eq!(outcome.err(), Some(CURLcode::OperationTimedout));
            assert_eq!(resolver.calls(), 0, "{expired} is already expired");
            assert!(cache.is_empty());
            // No message: C returns before any `failf`.
            assert!(!log.text().contains("name lookup timed out"));
            // And `mstotv` really does read the same value the other way.
            assert_eq!(mstotv(expired), None);
        }
    }

    /// A zero deadline applies NONE, and a slow answer is not cut short.
    ///
    /// C's step 3 (`lib/hostip.c:1111-1117`). Handing `mstotv`'s
    /// `Some(Duration::ZERO)` to the timer instead would elapse immediately
    /// and turn every such call into a spurious timeout.
    #[tokio::test(start_paused = true)]
    async fn a_zero_deadline_applies_none() {
        let resolver = MockResolver::answering(vec![v4(1, 80)])
            .after(Duration::from_secs(600));
        let time = clock();
        let probe = FixedIpv6Probe(Ok(true));
        let support = Ipv6Support::known(true);
        let mut cache = DnsCache::new();
        let mut log = Log::new();
        let request = ResolveRequest::new("example.com", 80);

        // `mstotv` reads zero as a zero-length wait; this reads it as no wait
        // at all, and the two must not be merged.
        assert_eq!(mstotv(0), Some(Duration::ZERO));

        let outcome = {
            let mut ctx = ResolveContext::new(
                &mut cache,
                &time,
                &resolver,
                &support,
                &probe,
                ONE_SECOND_MS,
            );
            let mut tracer = log.tracer();
            resolve_timeout(&request, &mut ctx, 0, &mut tracer).await
        };

        assert!(outcome.is_ok(), "a ten-minute answer is not cut short");
        assert_eq!(resolver.calls(), 1);
        assert!(!log.text().contains("name lookup timed out"));
    }

    /// `CURLOPT_NOSIGNAL` cannot disable this deadline, because there is no
    /// signal to suppress.
    #[tokio::test(start_paused = true)]
    async fn no_signal_does_not_disable_the_deadline() {
        let resolver = MockResolver::answering(vec![v4(1, 80)])
            .after(Duration::from_secs(30));
        let time = clock();
        let probe = FixedIpv6Probe(Ok(true));
        let support = Ipv6Support::known(true);
        let mut cache = DnsCache::new();
        let mut log = Log::new();

        // Every knob this module offers, all of them set: none of them is
        // `no_signal`, and none of them changes the outcome.
        let request = ResolveRequest::new("example.com", 80)
            .with_ip_version(IpVersion::Whatever)
            .with_allow_doh(true);

        let outcome = {
            let mut ctx = ResolveContext::new(
                &mut cache,
                &time,
                &resolver,
                &support,
                &probe,
                ONE_SECOND_MS,
            );
            let mut tracer = log.tracer();
            resolve_timeout(&request, &mut ctx, 500, &mut tracer).await
        };

        assert_eq!(
            outcome.err(),
            Some(CURLcode::OperationTimedout),
            "the deadline is honoured unconditionally"
        );
        assert!(log.text().contains("name lookup timed out"));
    }

    /// `resolve_blocking` refuses DoH and bounds its wait by curl's constant.
    #[cfg(feature = "doh")]
    #[tokio::test(start_paused = true)]
    async fn resolve_blocking_refuses_doh() {
        let system = MockResolver::answering(vec![v4(1, 80)]);
        let over_doh = MockResolver::answering(vec![v4(2, 80)]);
        let time = clock();
        let probe = FixedIpv6Probe(Ok(true));
        let support = Ipv6Support::known(true);
        let mut cache = DnsCache::new();
        let mut log = Log::new();
        // The request ASKS for DoH; `resolve_blocking` must override it.
        let request =
            ResolveRequest::new("example.com", 80).with_allow_doh(true);

        let entry = {
            let mut ctx = ResolveContext::new(
                &mut cache,
                &time,
                &system,
                &support,
                &probe,
                ONE_SECOND_MS,
            )
            .with_doh(&over_doh);
            let mut tracer = log.tracer();
            resolve_blocking(&request, &mut ctx, &mut tracer)
                .await
                .expect("the system resolver answers")
        };

        assert_eq!(over_doh.calls(), 0, "a blocking resolve never uses DoH");
        assert_eq!(system.calls(), 1);
        assert_eq!(entry.addrs, vec![v4(1, 80)]);
        drop(log);
    }

    /// `resolve_blocking` replaces an unbounded join with curl's own ceiling.
    #[tokio::test(start_paused = true)]
    async fn resolve_blocking_bounds_its_wait_by_the_curl_ceiling() {
        let resolver = MockResolver::answering(vec![v4(1, 80)])
            .after(Duration::from_secs(400));
        let time = clock();
        let probe = FixedIpv6Probe(Ok(true));
        let support = Ipv6Support::known(true);
        let mut cache = DnsCache::new();
        let mut log = Log::new();
        let request = ResolveRequest::new("example.com", 80);

        let outcome = {
            let mut ctx = ResolveContext::new(
                &mut cache,
                &time,
                &resolver,
                &support,
                &probe,
                ONE_SECOND_MS,
            );
            let mut tracer = log.tracer();
            resolve_blocking(&request, &mut ctx, &mut tracer).await
        };

        assert_eq!(outcome.err(), Some(CURLcode::OperationTimedout));
        assert!(log.text().contains("name lookup timed out"));
    }

    /// Dropping the resolve future cancels the lookup and leaves nothing.
    #[tokio::test(start_paused = true)]
    async fn dropping_the_resolve_future_leaves_nothing_behind() {
        let resolver = MockResolver::answering(vec![v4(1, 80)])
            .after(Duration::from_secs(30));
        let time = clock();
        let probe = FixedIpv6Probe(Ok(true));
        let support = Ipv6Support::known(true);
        let mut cache = DnsCache::new();
        let mut log = Log::new();
        let request = ResolveRequest::new("example.com", 80);

        {
            let mut ctx = ResolveContext::new(
                &mut cache,
                &time,
                &resolver,
                &support,
                &probe,
                ONE_SECOND_MS,
            );
            let mut tracer = log.tracer();
            let outcome =
                resolve_timeout(&request, &mut ctx, 1, &mut tracer).await;
            assert_eq!(outcome.err(), Some(CURLcode::OperationTimedout));
        }

        assert_eq!(resolver.calls(), 1, "the lookup was entered");
        assert!(cache.is_empty(), "and left nothing behind");
        drop(log);
    }

    // -- the system resolver ------------------------------------------------

    /// A numeric literal is answered without any network.
    ///
    /// `std::net::ToSocketAddrs` parses a literal before consulting the
    /// resolver, which is the effect C obtains with its `AI_NUMERICHOST`
    /// hint, so this exercises the real code path with no packets.
    #[tokio::test]
    #[cfg_attr(
        miri,
        ignore = "spawn_blocking needs a real thread pool, which Miri has \
                  no isolation model for; every seam above this line is \
                  covered by the injected resolver instead"
    )]
    async fn the_system_resolver_answers_a_literal_without_a_network() {
        let resolver = SystemResolver::with_known_ipv6(true);
        let addrs = resolver
            .resolve("127.0.0.1", 8080, IpVersion::V4)
            .await
            .expect("a literal always resolves");

        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].family(), AddressFamily::Inet);
        assert_eq!(
            addrs[0].socket_addr(),
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080))
        );
        // `Curl_getaddrinfo_ex` copies `ai_canonname` only when the system
        // supplied one, and curl's hints never ask for it.
        assert_eq!(addrs[0].canonname, None);
        assert_eq!(addrs[0].socktype, SockType::Stream);
        assert_eq!(addrs[0].protocol, IpProto::Tcp);
    }

    /// The family filter narrows the answer, so a V6 request drops a V4
    /// literal.
    #[tokio::test]
    #[cfg_attr(
        miri,
        ignore = "spawn_blocking needs a real thread pool; the filter itself \
                  is covered by allowed_families_reproduce_the_three_outcomes\
                  _of_the_c_hint"
    )]
    async fn the_system_resolver_filters_to_the_requested_family() {
        let resolver = SystemResolver::with_known_ipv6(true);

        let none = resolver
            .resolve("127.0.0.1", 80, IpVersion::V6)
            .await
            .expect("the lookup itself succeeds");
        assert!(none.is_empty(), "a V6 request keeps no V4 address");

        let some = resolver
            .resolve("::1", 80, IpVersion::V6)
            .await
            .expect("the lookup succeeds");
        assert_eq!(some.len(), 1);
        assert_eq!(some[0].family(), AddressFamily::Inet6);
    }

    /// A failing IPv6 probe propagates, and it does so before any lookup.
    #[tokio::test]
    async fn a_failing_ipv6_probe_propagates_from_the_system_resolver() {
        let resolver = SystemResolver::with_probe(Box::new(FixedIpv6Probe(
            Err(CURLcode::OutOfMemory),
        )));

        let outcome = resolver
            .resolve("example.invalid", 80, IpVersion::Whatever)
            .await;
        assert_eq!(outcome.err(), Some(CURLcode::OutOfMemory));

        // The memoised answer is now `false`, exactly as C leaves it.
        assert_eq!(resolver.ipv6().cached(), Some(false));
    }

    /// The probe is taken at most once, and the accessors expose the same
    /// pair a caller hands to [`ResolveContext`].
    #[test]
    fn the_ipv6_answer_is_memoised_and_shareable() {
        #[derive(Debug, Default)]
        struct Counting {
            probes: AtomicUsize,
        }
        impl Ipv6Probe for Counting {
            fn probe(&self) -> CodeResult<bool> {
                self.probes.fetch_add(1, Ordering::SeqCst);
                Ok(true)
            }
        }

        let resolver =
            SystemResolver::with_probe(Box::new(Counting::default()));
        assert_eq!(resolver.ipv6().cached(), None, "unprobed to begin with");

        // Two family decisions, one probe.
        assert!(
            resolver
                .allowed(IpVersion::Whatever)
                .expect("the probe succeeds")
                .inet6
        );
        assert!(
            resolver
                .allowed(IpVersion::Whatever)
                .expect("the probe succeeds")
                .inet6
        );
        assert_eq!(resolver.ipv6().cached(), Some(true));

        // The accessor pair is what a caller passes with the context, so
        // the decision tree's gate consults the SAME memoised answer.
        let support = resolver.ipv6();
        let probe = resolver.ipv6_probe();
        assert!(can_resolve_ip_version(IpVersion::V6, support, probe)
            .expect("the memoised answer needs no probe"));
    }

    /// `SystemResolver::default` is `SystemResolver::new`, and the real probe
    /// is what it installs.
    #[test]
    fn the_default_system_resolver_probes_for_real() {
        // Constructed but not probed: `Ipv6Support::new` is lazy, so this
        // performs no syscall and is Miri-clean.
        let resolver = SystemResolver::default();
        assert_eq!(resolver.ipv6().cached(), None);
        let named = SystemResolver::new();
        assert_eq!(named.ipv6().cached(), None);
    }

    // -- cross-cutting ------------------------------------------------------

    /// No message this module can emit carries the dropped resolver's name.
    #[test]
    fn no_message_this_module_emits_carries_the_dropped_resolver_token() {
        // Assembled from its own letters so that this test does not itself
        // put the token in the binary.
        let token: String = ['a', 'r', 'e', 's'].iter().collect();

        let emitted = [
            msg::NAME_LOOKUP_TIMED_OUT.to_owned(),
            msg::GETADDRINFO_TASK_FAILED.to_owned(),
            msg::getaddrinfo_failed("example.com", 80),
            msg::init_resolve("example.com", 80),
            NO_ONION.to_owned(),
            NEGATIVE_ENTRY.to_owned(),
            found_in_cache("example.com"),
            store_negative("example.com", 80),
            resolver_error_message(ResolveTarget::Host, "example.com", None),
            resolver_error_message(
                ResolveTarget::Proxy,
                "proxy.example",
                Some("detail"),
            ),
        ];

        for line in emitted {
            assert!(
                !line.to_ascii_lowercase().contains(&token),
                "{line:?} would switch the harness to the dropped resolver"
            );
        }
    }

    /// The frozen text of every message this file emits, transcribed from the
    /// C.
    #[test]
    fn the_frozen_message_table_matches_the_c_text() {
        // `lib/hostip.c:1139`.
        assert_eq!(msg::NAME_LOOKUP_TIMED_OUT, "name lookup timed out");
        // `lib/asyn-thrdd.c:724`.
        assert_eq!(msg::GETADDRINFO_TASK_FAILED, "getaddrinfo() thread failed");
        // `lib/hostip6.c:110`.
        assert_eq!(
            msg::getaddrinfo_failed("example.com", 8080),
            "getaddrinfo(3) failed for example.com:8080"
        );
        // `lib/asyn-thrdd.c:739`.
        assert_eq!(
            msg::init_resolve("example.com", 8080),
            "init threaded resolve of example.com:8080"
        );
        // The four this file emits from `dns/mod.rs`'s table, checked here too
        // so that a change there is caught by the file that emits them.
        assert_eq!(NO_ONION, "Not resolving .onion address (RFC 7686)");
        assert_eq!(NEGATIVE_ENTRY, "Negative DNS entry");
        assert_eq!(
            found_in_cache("example.com"),
            "Hostname example.com was found in DNS cache"
        );
        assert_eq!(
            store_negative("example.com", 8080),
            "Store negative name resolve for example.com:8080"
        );
    }

    /// `Exit` keeps C's two failure exits apart, and reports the same code
    /// from either.
    #[test]
    fn the_two_failure_exits_carry_their_code_and_stay_distinct() {
        let through_error = Exit::Error(CURLcode::CouldntResolveHost);
        let direct = Exit::Direct(CURLcode::CouldntResolveHost);
        assert_eq!(through_error.code(), CURLcode::CouldntResolveHost);
        assert_eq!(direct.code(), CURLcode::CouldntResolveHost);
        assert_ne!(
            through_error, direct,
            "one may store a negative resolve and the other may not"
        );
    }

    /// The context's diagnostic form reports the closures without pretending
    /// to print them.
    #[test]
    fn the_context_is_debuggable_without_printing_its_closures() {
        let resolver = MockResolver::answering(Vec::new());
        let time = clock();
        let probe = FixedIpv6Probe(Ok(true));
        let support = Ipv6Support::known(true);
        let mut cache = DnsCache::new();

        let rendered = {
            let mut refuse = || 0;
            let ctx = ResolveContext::new(
                &mut cache,
                &time,
                &resolver,
                &support,
                &probe,
                ONE_SECOND_MS,
            )
            .with_resolver_start(&mut refuse);
            format!("{ctx:?}")
        };

        assert!(rendered.contains("ResolveContext"));
        assert!(rendered.contains("cache: true"));
        assert!(rendered.contains("resolver_start: true"));
        assert!(rendered.contains("shuffle: false"));
        assert!(rendered.contains("doh_used: false"));
    }
}
