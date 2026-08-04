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

//! Name resolution: the DNS cache, the address types and the [`Resolver`]
//! seam.
//!
//! This is the module root of the resolution subsystem. It supersedes the
//! cache, key-formation, entry-lifecycle, address-list, address-formatting
//! and `CURLOPT_RESOLVE` portions of `lib/hostip.c` and `lib/hostip.h`,
//! together with the address-list shape of `lib/curl_addrinfo.{c,h}`. The
//! resolution decision tree and its timeout live in `resolver.rs`; the
//! division is recorded under *Who owns which message string* below,
//! because a string emitted twice would break the byte-exact fixture
//! comparison AAP 0.6.7 measures.
//!
//! Every claim here is cited, per AAP 0.7 (*"Claims are evidenced, not
//! asserted"*). The lines cited are `lib/hostip.h:36`, `:38-39`, `:49-54`,
//! `:56-73` and `:146-158`; `lib/hostip.c:76`, `:78`, `:118-179`,
//! `:203-227`, `:233-244`, `:246-275`, `:298-363`, `:374-476`, `:492-557`,
//! `:560-667`, `:671-746`, `:752-796`, `:860-1012`, `:1242-1272`,
//! `:1279-1470` and `:1570-1589`; `lib/curl_addrinfo.h` for the
//! `Curl_addrinfo` shape and `lib/curl_addrinfo.c:407-440` for the literal
//! probes; `lib/urldata.h:124` for `MAX_IPADR_LEN`;
//! `include/curl/curl.h:1033-1035` for the ALPN integers; and
//! `lib/fake_addrinfo.c:170` with `lib/fake_addrinfo.h:33-35` for the
//! `CURL_DNS_SERVER` note.
//!
//! # Five conclusions recorded here so nobody re-derives them
//!
//! **(a) Pruning is ORDER-INDEPENDENT, and must never become an LRU.**
//! `crate::util::hash` asks this module for that answer directly, because
//! `HashMap` iteration order is randomised per process in Rust while C
//! walked buckets in index order. [`DnsCache::prune`] performs a FULL scan,
//! removes every entry whose (possibly doubled) age meets the limit, and
//! folds `oldest` as a maximum - there is no positional selection and no
//! "first N", so a randomised visit order cannot change the surviving set.
//! The size cap of `MAX_DNS_CACHE_SIZE` is enforced by repeatedly HALVING
//! the age limit (`lib/hostip.c:325-353`), not by evicting the least
//! recently used. An LRU would be order-dependent, which is the second and
//! independent reason not to introduce one.
//!
//! **(b) `CURL_HOSTENT_SIZE` is deliberately not ported.**
//! `lib/hostip.h:36` defines it as 9000 to size the scratch buffer
//! `gethostbyname_r` writes its `struct hostent` into, with a comment
//! citing Stevens for the 8192-byte alias area. Nothing in this
//! implementation calls a `_r` resolver variant with a caller-supplied
//! buffer, so the constant has no Rust analogue. It is absent on purpose;
//! do not go looking for it.
//!
//! **(c) `lib/fake_addrinfo.c` is c-ares-only, and `CURL_DNS_SERVER` has no
//! effect.** That file is wrapped in `USE_FAKE_GETADDRINFO`, which
//! `lib/fake_addrinfo.h:33-35` defines only when `CURL_MEMDEBUG` *and*
//! `HAVE_GETADDRINFO` *and* `USE_ARES` *and* `ARES_VERSION >= 0x011a00`
//! all hold; it includes `<ares.h>` and exports only `r_getaddrinfo()` and
//! `r_freeaddrinfo()`. c-ares is dropped by AAP 0.5.2, so the one portable
//! idea in it - the `CURL_DNS_SERVER` environment override at
//! `lib/fake_addrinfo.c:170`, which the harness sets for c-ares builds - has
//! nothing to configure. This implementation reads that variable nowhere and
//! ignoring it is correct rather than an oversight.
//!
//! **(d) The ALPN wire parser lives HERE, and `conn/mod.rs` must delegate.**
//! `enum alpnid` is declared at `lib/hostip.h:49-54`, a source of this file,
//! so [`AlpnId`] and its [`AlpnId::from_wire`] constructor belong together.
//! C's parser `Curl_alpn2alpnid` sits in `lib/connect.c:73-87`, whose
//! successor is `crate::conn`; that successor MUST call
//! [`AlpnId::from_wire`] rather than reimplement the table. A second copy
//! would drift, and the integers are load-bearing (see [`AlpnId`]).
//!
//! **(e) [`DnsCache`] carries NO internal lock, by design.**
//! `lib/hostip.c:298-319` shows `dnscache_lock`/`dnscache_unlock` taking
//! `Curl_share_lock(data, CURL_LOCK_DATA_DNS, CURL_LOCK_ACCESS_SINGLE)`
//! **only** when the selected cache is the share's - a multi handle's own
//! cache is never locked, because a multi handle is single-threaded. The
//! sharing policy therefore belongs to `crate::share`, which will wrap this
//! type in interior mutability and own the `CURLSHOPT_SHARE` mechanics.
//! Adding a `Mutex` here would double-lock the shared case and put the
//! policy in the wrong module. That contract is stated for the benefit of
//! whoever authors `share/`.
//!
//! # What the C's ownership machinery becomes
//!
//! `struct Curl_dns_entry` carries `size_t refcount` with the comment
//! *"reference counter, entry is freed on reaching 0"* (`lib/hostip.h:63`),
//! and two functions decrement it - `Curl_resolv_unlink` (`:1242-1254`) and
//! `dnscache_entry_dtor` (`:1256-1263`). Both become [`Arc`]: the counter is
//! not hand-rolled, `dnscache_entry_free` (`:184-194`) becomes `Drop`, and
//! there is consequently nothing to free by hand. **Do not add a manual
//! release path.** The header comment of `Curl_dnscache_mk_entry`
//! (`lib/hostip.h:146-158`) promises that the call *"takes ownership of
//! `addr`, even in case of failure, and always clears `*paddr`"*; in Rust
//! ownership transfer is what passing a value by value already means, so the
//! out-parameter and its clearing clause simply do not exist here.
//!
//! The intrusive singly-linked `Curl_addrinfo` list becomes a
//! [`Vec<ResolvedAddr>`], as AAP 0.6.9 requires. **Its order is
//! behaviourally significant** and is preserved everywhere in this module:
//! `conn/happy_eyeballs.rs`, superseding `lib/cf-ip-happy.c`, races the two
//! families, so the sequence a resolver produces is observable. The
//! synthesised localhost list is the clearest case - see
//! [`localhost_addrs`].
//!
//! # Who owns which message string
//!
//! This module owns the cache-hit line at `lib/hostip.c:904`, the two
//! "zapped" lines, everything `show_resolve_info` prints, the shuffle line
//! and every `CURLOPT_RESOLVE` line. `resolver.rs` owns the `.onion`
//! rejection, the negative-resolve store, the timeout line and the
//! `Curl_resolver_error` text - for which [`resolver_error_message`] here is
//! the shared formatter, so that the conditional parenthesisation exists
//! once. Note that C has **two** different "found in DNS cache" strings and
//! they differ in quoting: `lib/hostip.c:904` is unquoted and `:1491` is
//! quoted. Both are reproduced, at their own call sites, and they are
//! deliberately not unified.
//!
//! # Injection, not global state
//!
//! `lib/hostip.c:365-370` keeps `static sigjmp_buf curl_jmpenv;` beside
//! `static curl_simple_lock curl_jmpenv_lock;` under a comment that admits
//! *"Beware this is a global and unique instance ... This is not thread-safe
//! stuff."* Nothing of that shape survives. Per AAP 0.3.3 P12 the clock, the
//! resolver, the entropy source, the IPv6 probe, the DoH transport and the
//! trace sink are all **injected**: this module declares no `static mut`, no
//! singleton and no lazily initialised mutable global. The one `OnceLock` it
//! uses ([`Ipv6Support`]) is write-once immutable shared state owned by the
//! caller's handle, which is the distinction `crate::util::timeval` draws
//! for the same reason.
//!
//! Time comes from `crate::util::timeval`, which owns the clock seam and
//! enforces it with a repository-wide grep gate; this module never reads a
//! wall or monotonic clock directly. Case folding comes from
//! `crate::util::strcase` and is ASCII-only: using Unicode-aware
//! lowercasing would change *which hostnames collide in the cache*, so it is
//! a correctness requirement rather than a preference. Address text comes
//! from `crate::util::inet`, never from `std::net`'s `Display`, because curl
//! diverges from it twice - IPv4-compatible addresses render as
//! `::a.b.c.d`, and a single zero word is not compressed.
//!
//! # Visibility
//!
//! Everything here is `pub(crate)`. AAP 0.4.2 replaces C's
//! `extern CURLcode Curl_xyz(...)` - private by convention, visible to the
//! linker - with private by enforcement. Nothing is re-exported to make
//! `tests/libtest` or `tests/unit` link; AAP 0.8.7 records their inability
//! to link as a deliberate deviation, and re-exporting internals to satisfy
//! them *"would defeat the encapsulation that makes the zero-`unsafe`
//! guarantee possible."* The coverage those C programs provided is
//! relocated into the `#[cfg(test)]` module at the foot of this file.

use core::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};

use crate::error::{CURLcode, CodeResult};
use crate::trace::{failf, infof, Tracer};
use crate::util::dynbuf::DynBuf;
use crate::util::hash::StrHash;
use crate::util::inet::{ntop4, ntop6, pton4, pton6};
use crate::util::strcase::strntolower;
use crate::util::strparse::{
    str_casecompare, str_number, str_single, str_until,
};
use crate::util::timediff::TimeDiff;
use crate::util::timeval::{timediff_ms, Clock, CurlTime};

// THE FOUR SUBMODULES OF THIS DIRECTORY -- SPECIFIED, NOT YET DECLARED.
//
// AAP 0.3.1's layout line for this directory is
// `curl-rs-lib/src/dns/{mod,resolver,doh,httpsrr,if2ip}.rs`, so the target
// design is exactly four children and no more. None of the four has a file
// at this commit, and a `mod` line without its file is E0583 -- a hard error
// that no `#[allow]` can reach, because module resolution never gets far
// enough to produce a lint. They are therefore DESCRIBED here with the
// declaration each one takes, and each declaration arrives WITH its file in
// the unit of work that creates it. This is the same discipline
// `curl-rs-lib/src/lib.rs` states for its own not-yet-written subsystems,
// and it was verified by compiling: declaring a child that does not exist
// breaks the whole crate, so describing it is the only way this module root
// can be delivered at all.
//
// The declarations, verbatim, for whoever lands each file:
//
//     pub(crate) mod resolver;
//     pub(crate) mod httpsrr;
//     pub(crate) mod if2ip;
//
//     #[cfg(feature = "doh")]
//     pub(crate) mod doh;
//
// --- resolver (pub(crate)) -----------------------------------------------
// The resolution engine: `Curl_resolv` and its decision tree
// (`lib/hostip.c:860-1012`), `lib/hostip4.c`, `lib/hostip6.c`, and the
// entire threaded apparatus of `lib/asyn.h`, `lib/asyn-base.c`,
// `lib/asyn-thrdd.c` and `lib/curl_threads.c`. It implements the
// [`Resolver`] trait declared below and must not declare a second one. This
// is where AAP 0.6.9 deletes the `alarm()` plus `sigsetjmp`/`siglongjmp`
// timeout outright in favour of `tokio::time::timeout`. `hickory-dns`
// support, if any, is `#[cfg(feature = "hickory-dns")]` INSIDE that file --
// there is no `hickory.rs` and none may be created.
//
// --- httpsrr (pub(crate)) ------------------------------------------------
// `lib/httpsrr.c` and `lib/httpsrr.h`: the HTTPS resource record, whose
// `Curl_https_rrinfo` successor is the type [`DnsEntry`] will carry in the
// slot described on that struct. Compiled UNCONDITIONALLY -- `httpsrr` is
// not one of the fifteen features; only its advertisement in the version
// banner is conditional, and that belongs to `crate::version`. It stores
// [`AlpnId`] values as raw bytes in a four-element array and dedupes them
// with `memchr` (`lib/httpsrr.c:57-61`), which is why the integers below are
// not free to change.
//
// --- if2ip (pub(crate)) --------------------------------------------------
// `lib/if2ip.c`: resolving `--interface` to a local address.
//
// --- doh (pub(crate), behind the default-ON `doh` feature) ---------------
// `lib/doh.c`: DNS-over-HTTPS. Feature-gated because `doh` is one of the
// fifteen and gates a whole capability. It performs its transfers through
// the injected [`DohTransport`] below and must never write
// `use crate::protocols`: a `dns -> protocols -> dns` import cycle is
// exactly what that seam exists to avoid.

/// The size of C's cache-key buffer, and therefore the truncation rule.
///
/// `lib/hostip.c:76`: `#define MAX_HOSTCACHE_LEN (255 + 7)`, commented
/// *"max FQDN + colon + port number + zero"* - so 262. In C this sizes a
/// stack array; here it survives as a **truncation rule**, because the
/// truncation is observable: two hosts sharing their first
/// [`MAX_HOSTCACHE_HOST_LEN`] bytes collide in the cache. Keeping the C
/// spelling of the constant is what makes the derivation below readable.
// No consumer yet; named for the derivation below and by resolver.rs.
#[allow(dead_code)]
pub(crate) const MAX_HOSTCACHE_LEN: usize = 255 + 7;

/// The longest host stored in a cache key: 255 bytes.
///
/// C's `if(len > (buflen - 7)) len = buflen - 7;` (`lib/hostip.c:239-240`)
/// with `buflen == MAX_HOSTCACHE_LEN`. The seven reserved bytes are the
/// colon, up to five decimal digits of port, and the terminator that C needs
/// and Rust does not.
// No consumer yet; read by the key builder's tests and by conn/.
#[allow(dead_code)]
pub(crate) const MAX_HOSTCACHE_HOST_LEN: usize = MAX_HOSTCACHE_LEN - 7;

/// The entry count above which [`DnsCache::prune`] halves its age limit.
///
/// `lib/hostip.c:78`: `#define MAX_DNS_CACHE_SIZE 29999`.
#[allow(dead_code)] // No consumer yet; Read by DnsCache::prune and by share/.
pub(crate) const MAX_DNS_CACHE_SIZE: usize = 29999;

/// Seconds allowed for one name resolution: 300.
///
/// `lib/hostip.h:38-39`, commented *"when using asynch methods, we allow
/// this many seconds for a name resolve"*. It reaches the C's async core as
/// `struct timeval maxtime = { CURL_TIMEOUT_RESOLVE, 0 }` in
/// `lib/asyn-base.c`. `resolver.rs` consumes this as its ceiling and must
/// not redefine it.
#[allow(dead_code)] // No consumer yet; resolver.rs consumes it as its ceiling.
pub(crate) const CURL_TIMEOUT_RESOLVE: i64 = 300;

/// The longest printable address plus its terminator: 46.
///
/// `lib/urldata.h:124` defines `MAX_IPADR_LEN` as
/// `sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")` -
/// 45 characters and a NUL. Retained because it is also the length bound
/// C's `CURLOPT_RESOLVE` parser passes to `curlx_str_until` for a bracketed
/// host (`lib/hostip.c:1300`, `:1339`), where it is a genuine input limit
/// rather than a buffer size.
// No consumer yet; also conn/'s bound when it formats an address.
#[allow(dead_code)]
pub(crate) const MAX_IPADR_LEN: usize = 46;

/// The per-family accumulator budget of `show_resolve_info`: 1024 bytes.
///
/// `lib/hostip.c:143-146` initialises each `dynbuf` with `curlx_dyn_init(d,
/// 1024)`, and exceeding it is what produces the
/// [`msg::TOO_MANY_IP`] line rather than a longer one.
#[allow(dead_code)] // No consumer yet; Read by show_resolve_info.
const SHOW_RESOLVE_BUDGET: usize = 1024;

/// The longest address literal a `CURLOPT_RESOLVE` entry may carry: 64.
///
/// C's buffer is `char address[64]` (`lib/hostip.c:1327`) and the guard is
/// `if(curlx_strlen(&target) >= sizeof(address)) goto err;` (`:1382-1383`),
/// so 64 bytes or more is an error and 63 is the longest accepted. The bound
/// is part of the frozen `CURLOPT_RESOLVE` syntax (AAP 0.8.1) and must not
/// be relaxed.
#[allow(dead_code)] // No consumer yet; Read by parse_resolve_addresses.
const RESOLVE_ADDRESS_MAX: usize = 64;

/// The non-bracketed host bound C's `CURLOPT_RESOLVE` parser passes: 4096.
///
/// `lib/hostip.c:1306`, `:1345`. Bracketed hosts get [`MAX_IPADR_LEN`]
/// instead, which is a much tighter limit and is measured, not assumed.
#[allow(dead_code)] // No consumer yet; Read by both CURLOPT_RESOLVE branches.
const RESOLVE_HOST_MAX: usize = 4096;

/// The largest port a `CURLOPT_RESOLVE` entry may name: `0xffff`.
///
/// The `max` argument of every `curlx_str_number` call in
/// `Curl_loadhostpairs` (`lib/hostip.c:1315`, `:1348`).
#[allow(dead_code)] // No consumer yet; Read by both CURLOPT_RESOLVE branches.
const RESOLVE_PORT_MAX: i64 = 0xffff;

/// The longest `sun_path` an `AF_UNIX` address can hold.
///
/// `sizeof(struct sockaddr_un::sun_path)`, which
/// `Curl_unix2addr` (`lib/curl_addrinfo.c:466-471`) compares
/// `strlen(path) + 1` against. It is 104 on Apple platforms and 108 on
/// Linux, and both of the mandated operating systems appear here explicitly
/// rather than through a `libc` constant, because `libc` is confined to
/// `crate::ffi` (AAP 0.8.5 conflict C3). No other platform is in the
/// four-target matrix of AAP 0.1.1 G8.
#[cfg(any(target_os = "macos", target_os = "ios"))]
#[allow(dead_code)] // No consumer yet; conn/socket.rs consumes it.
pub(crate) const UNIX_PATH_MAX: usize = 104;

/// The longest `sun_path` an `AF_UNIX` address can hold - see the Apple arm.
#[cfg(not(any(target_os = "macos", target_os = "ios")))]
#[allow(dead_code)] // No consumer yet; conn/socket.rs consumes it.
pub(crate) const UNIX_PATH_MAX: usize = 108;

/// The observable text this module emits, frozen.
///
/// AAP 0.8.1 freezes `--verbose` and `--trace` output, and AAP 0.6.7
/// measures the comparison that enforces it: `compareparts` joins both
/// sides into one string, so casing, spacing and punctuation are all
/// significant. `#[rustfmt::skip]` therefore covers the whole module: these
/// are wire bytes wearing the costume of source code, and a formatter that
/// rewrapped one of them would change program output.
///
/// Each item is transcribed from the C source and carries its locator. The
/// parameterised ones are functions rather than format strings because
/// `crate::trace::infof` requires a literal format string, and one
/// definition per message beats a template duplicated at its call site.
#[rustfmt::skip]
pub(crate) mod msg {
    /// `"Hostname %s was found in DNS cache"` - `lib/hostip.c:904`.
    ///
    /// **Unquoted.** The sibling at `:1491` quotes its `%s`; see
    /// [`found_in_cache_quoted`]. The two are deliberately not unified.
    #[allow(dead_code)] // No consumer yet; resolver.rs emits it on a cache hit.
    pub(crate) fn found_in_cache(host: &str) -> String {
        format!("Hostname {host} was found in DNS cache")
    }

    /// `"Hostname '%s' was found in DNS cache"` - `lib/hostip.c:1491`.
    ///
    /// **Quoted**, and emitted from the async re-check path, which is
    /// `resolver.rs`. It lives here so that both spellings sit side by side
    /// and neither can be "corrected" into the other by accident.
    // No consumer yet; resolver.rs emits it from the async re-check.
    #[allow(dead_code)]
    pub(crate) fn found_in_cache_quoted(host: &str) -> String {
        format!("Hostname '{host}' was found in DNS cache")
    }

    /// `"Hostname in DNS cache was stale, zapped"` - `lib/hostip.c:411`.
    #[allow(dead_code)] // No consumer yet; Emitted by DnsCache::fetch_addr.
    pub(crate) const STALE_ZAPPED: &str =
        "Hostname in DNS cache was stale, zapped";

    /// `"Hostname in DNS cache does not have needed family, zapped"` -
    /// `lib/hostip.c:437`.
    #[allow(dead_code)] // No consumer yet; Emitted by DnsCache::fetch_addr.
    pub(crate) const FAMILY_ZAPPED: &str =
        "Hostname in DNS cache does not have needed family, zapped";

    /// `"Host %s:%d was resolved."` - `lib/hostip.c:138-139`.
    ///
    /// The trailing period is C's and is preserved.
    #[allow(dead_code)] // No consumer yet; Emitted by show_resolve_info.
    pub(crate) fn host_was_resolved(host: &str, port: u16) -> String {
        format!("Host {host}:{port} was resolved.")
    }

    /// The `"(none)"` an absent name or an empty accumulator renders as -
    /// `lib/hostip.c:139`, `:168`, `:172`.
    #[allow(dead_code)] // No consumer yet; Emitted by show_resolve_info.
    pub(crate) const NONE: &str = "(none)";

    /// `"too many IP, cannot show"` - `lib/hostip.c:157`.
    #[allow(dead_code)] // No consumer yet; Emitted by show_resolve_info.
    pub(crate) const TOO_MANY_IP: &str = "too many IP, cannot show";

    /// `"IPv6: %s"` - `lib/hostip.c:167-168`. Emitted BEFORE the IPv4 line.
    #[allow(dead_code)] // No consumer yet; Emitted by show_resolve_info.
    pub(crate) fn ipv6_line(list: &str) -> String {
        format!("IPv6: {list}")
    }

    /// `"IPv4: %s"` - `lib/hostip.c:171-172`. Emitted AFTER the IPv6 line.
    #[allow(dead_code)] // No consumer yet; Emitted by show_resolve_info.
    pub(crate) fn ipv4_line(list: &str) -> String {
        format!("IPv4: {list}")
    }

    /// The `", "` between addresses on one line - `lib/hostip.c:151`.
    ///
    /// A comma AND a space; `curlx_dyn_addn(d, ", ", 2)` names the length.
    #[allow(dead_code)] // No consumer yet; Read by show_resolve_info.
    pub(crate) const ADDR_SEPARATOR: &str = ", ";

    /// `"Shuffling %i addresses"` - `lib/hostip.c:515`.
    ///
    /// `%i` renders as a plain decimal, which is what `{}` does for an
    /// `usize`, so the rendered bytes are identical.
    #[allow(dead_code)] // No consumer yet; Emitted by shuffle_addrs.
    pub(crate) fn shuffling(count: usize) -> String {
        format!("Shuffling {count} addresses")
    }

    /// `"Resolve address '%s' found illegal"` - `lib/hostip.c:1394`.
    // No consumer yet; emitted by the CURLOPT_RESOLVE loader.
    #[allow(dead_code)]
    pub(crate) fn address_illegal(address: &str) -> String {
        format!("Resolve address '{address}' found illegal")
    }

    /// `"Could not parse CURLOPT_RESOLVE entry '%s'"` -
    /// `lib/hostip.c:1412`. A `failf`, paired with
    /// [`crate::error::CURLcode::SetoptOptionSyntax`].
    #[allow(dead_code)] // No consumer yet; Emitted by unparsable_entry.
    pub(crate) fn resolve_unparsable(entry: &str) -> String {
        format!("Could not parse CURLOPT_RESOLVE entry '{entry}'")
    }

    /// `"RESOLVE %.*s:%<off_t> - old addresses discarded"` -
    /// `lib/hostip.c:1428-1430`.
    // No consumer yet; emitted by the CURLOPT_RESOLVE loader.
    #[allow(dead_code)]
    pub(crate) fn resolve_replaced(host: &str, port: u16) -> String {
        format!("RESOLVE {host}:{port} - old addresses discarded")
    }

    /// `"Added %.*s:%<off_t>:%s to DNS cache%s"` -
    /// `lib/hostip.c:1458-1460`.
    ///
    /// The final `%s` is `permanent ? "" : " (non-permanent)"`, so both
    /// forms are reachable and both are reproduced.
    // No consumer yet; emitted by the CURLOPT_RESOLVE loader.
    #[allow(dead_code)]
    pub(crate) fn resolve_added(
        host: &str,
        port: u16,
        addresses: &str,
        permanent: bool,
    ) -> String {
        let suffix = if permanent { "" } else { " (non-permanent)" };
        format!("Added {host}:{port}:{addresses} to DNS cache{suffix}")
    }

    /// `"RESOLVE *:%<off_t> using wildcard"` - `lib/hostip.c:1464-1465`.
    // No consumer yet; emitted by the CURLOPT_RESOLVE loader.
    #[allow(dead_code)]
    pub(crate) fn resolve_wildcard(port: u16) -> String {
        format!("RESOLVE *:{port} using wildcard")
    }

    /// `"Store negative name resolve for %s:%d"` - `lib/hostip.c:837`.
    ///
    /// Emitted by `resolver.rs`, whose `store_negative_resolve` successor
    /// inserts the no-address entry that [`super::DnsEntry`] ages at double
    /// rate. The text lives here with its siblings.
    #[allow(dead_code)] // No consumer yet; resolver.rs emits it.
    pub(crate) fn store_negative(host: &str, port: u16) -> String {
        format!("Store negative name resolve for {host}:{port}")
    }

    /// `"Negative DNS entry"` - `lib/hostip.c:976`.
    ///
    /// Emitted by `resolver.rs` when a cache hit carries no addresses.
    #[allow(dead_code)] // No consumer yet; resolver.rs emits it.
    pub(crate) const NEGATIVE_ENTRY: &str = "Negative DNS entry";

    /// `"Not resolving .onion address (RFC 7686)"` - `lib/hostip.c:892`.
    ///
    /// A `failf`, emitted by `resolver.rs`, which also owns the measured
    /// `hostname_len >= 7` guard that lets a bare six-byte `".onion"`
    /// through.
    #[allow(dead_code)] // No consumer yet; resolver.rs emits it.
    pub(crate) const NO_ONION: &str =
        "Not resolving .onion address (RFC 7686)";
}

/// An application protocol identifier, with curl's integers pinned.
///
/// Supersedes `enum alpnid` (`lib/hostip.h:49-54`):
///
/// ```c
/// enum alpnid {
///   ALPN_none = 0,
///   ALPN_h1 = CURLALTSVC_H1,
///   ALPN_h2 = CURLALTSVC_H2,
///   ALPN_h3 = CURLALTSVC_H3
/// };
/// ```
///
/// # The integers are load-bearing
///
/// `include/curl/curl.h:1033-1035` fixes them: `CURLALTSVC_H1 (1L << 3)`,
/// `CURLALTSVC_H2 (1L << 4)`, `CURLALTSVC_H3 (1L << 5)` - that is 8, 16 and
/// 32. They are NOT arbitrary and NOT ordinals. `lib/httpsrr.c:57-61` stores
/// these values into an `unsigned char alpns[4]` and deduplicates the array
/// with `memchr` over those bytes, so renumbering them would change which
/// advertised protocols survive deduplication. They are also the bits the
/// public `CURLOPT_ALTSVC_CTRL` mask uses, which is why they are powers of
/// two with a gap below them.
///
/// `#[repr(u8)]` is sound for every value here because the largest is 32.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
#[allow(dead_code)] // No consumer yet; httpsrr.rs and conn/ consume it.
pub(crate) enum AlpnId {
    /// `ALPN_none = 0` - nothing negotiated, or unrecognised input.
    None = 0,
    /// `ALPN_h1 = CURLALTSVC_H1` - HTTP/1.1, `1 << 3`.
    H1 = 8,
    /// `ALPN_h2 = CURLALTSVC_H2` - HTTP/2, `1 << 4`.
    H2 = 16,
    /// `ALPN_h3 = CURLALTSVC_H3` - HTTP/3, `1 << 5`.
    H3 = 32,
}

impl AlpnId {
    /// The pinned integer, as the byte `lib/httpsrr.c` stores.
    #[allow(dead_code)] // No consumer yet; httpsrr.rs stores this byte.
    pub(crate) const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parses an ALPN protocol name off the wire.
    ///
    /// Supersedes `Curl_alpn2alpnid` (`lib/connect.c:73-87`). The C is a
    /// length-then-content decision and is reproduced exactly:
    ///
    /// ```c
    /// if(len == 2) {
    ///   if(!memcmp("h1", name, 2)) return ALPN_h1;
    ///   if(!memcmp("h2", name, 2)) return ALPN_h2;
    ///   if(!memcmp("h3", name, 2)) return ALPN_h3;
    /// }
    /// else if(len == 8) {
    ///   if(!memcmp("http/1.1", name, 8)) return ALPN_h1;
    /// }
    /// return ALPN_none; /* unknown, probably rubbish input */
    /// ```
    ///
    /// Three consequences are measured rather than assumed, and each has a
    /// test below. The comparison is `memcmp`, so it is **case-sensitive**
    /// and `"HTTP/1.1"` yields [`AlpnId::None`]. Only lengths two and eight
    /// are examined at all, so a three-byte input is rejected without its
    /// content being looked at. And an unknown two-byte token such as
    /// `"h4"` is [`AlpnId::None`] rather than an error, which is what lets a
    /// server advertise a protocol this client has never heard of without
    /// failing the connection.
    ///
    /// **`crate::conn` must call this rather than reimplement the table.**
    /// The type is declared in `lib/hostip.h`, a source of this file, so its
    /// constructor belongs beside it; a second copy in the module that
    /// supersedes `lib/connect.c` would drift from this one.
    #[allow(dead_code)] // No consumer yet; conn/ must delegate to it.
    pub(crate) fn from_wire(name: &[u8]) -> Self {
        match name.len() {
            2 => match name {
                b"h1" => Self::H1,
                b"h2" => Self::H2,
                b"h3" => Self::H3,
                _ => Self::None,
            },
            8 if name == b"http/1.1" => Self::H1,
            _ => Self::None,
        }
    }
}

/// Which address families a resolution may return.
///
/// Supersedes the `CURL_IPRESOLVE_*` triple that `CURLOPT_IPRESOLVE` sets
/// and that `Curl_resolv` threads through as a bare `int ip_version`
/// (`include/curl/curl.h:2300-2303`). The integers are the public ABI's and
/// are pinned, so `curl-rs-ffi` can convert without a lookup table.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
#[allow(dead_code)] // No consumer yet; resolver.rs and conn/ consume it.
pub(crate) enum IpVersion {
    /// `CURL_IPRESOLVE_WHATEVER 0L` - the default; every family is
    /// acceptable. C's comment reads *"uses addresses to all IP versions
    /// that your system allows"*.
    #[default]
    Whatever = 0,
    /// `CURL_IPRESOLVE_V4 1L` - IPv4 only.
    V4 = 1,
    /// `CURL_IPRESOLVE_V6 2L` - IPv6 only.
    V6 = 2,
}

impl IpVersion {
    /// The public ABI integer.
    #[allow(dead_code)] // No consumer yet; curl-rs-ffi converts through it.
    pub(crate) const fn as_i32(self) -> i32 {
        self as i32
    }

    /// The variant for a public ABI integer, or `None` for anything else.
    ///
    /// A `Result` would be the wrong shape: `lib/setopt.c` rejects an
    /// out-of-range `CURLOPT_IPRESOLVE` with its own code, so the decision
    /// belongs to the option setter rather than here.
    #[allow(dead_code)] // No consumer yet; easy/setopt.rs converts through it.
    pub(crate) const fn from_i32(raw: i32) -> Option<Self> {
        match raw {
            0 => Some(Self::Whatever),
            1 => Some(Self::V4),
            2 => Some(Self::V6),
            _ => None,
        }
    }

    /// The family a cached entry must contain, or `None` when any will do.
    ///
    /// This is the `int pf` of `fetch_addr`'s fourth step
    /// (`lib/hostip.c:419-426`): `PF_INET` by default, and `PF_INET6` when
    /// the request is [`IpVersion::V6`]. C's `#ifdef PF_INET6` guard around
    /// the assignment has no counterpart - every mandated target has IPv6.
    #[allow(dead_code)] // No consumer yet; Read by DnsCache::fetch_addr.
    pub(crate) const fn required_family(self) -> Option<AddressFamily> {
        match self {
            Self::Whatever => None,
            Self::V4 => Some(AddressFamily::Inet),
            Self::V6 => Some(AddressFamily::Inet6),
        }
    }
}

/// The address family of one resolved address.
///
/// C reads `ai_family` and compares it against `AF_INET`, `AF_INET6` or
/// `AF_UNIX`, whose numeric values differ across the mandated operating
/// systems - `AF_INET6` is 10 on Linux and 30 on Apple platforms. Naming
/// them as an enumeration keeps those platform integers out of the engine
/// entirely; they belong to `crate::ffi` and to the socket crate, and the
/// gate in `crate::lib`'s `source_policy` exists to keep them there.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[allow(dead_code)] // No consumer yet; conn/happy_eyeballs.rs consumes it.
pub(crate) enum AddressFamily {
    /// `AF_INET`.
    Inet,
    /// `AF_INET6`.
    Inet6,
    /// `AF_UNIX`, which `Curl_unix2addr` produces
    /// (`lib/curl_addrinfo.c:447-485`) and which
    /// [`ResolvedAddr::printable_address`] renders as the empty string.
    Unix,
}

/// The socket type of one resolved address.
///
/// Every address this module constructs is `SOCK_STREAM`, which is not an
/// accident worth eliding: `ip2addr` (`lib/curl_addrinfo.c:375`),
/// `get_localhost` (`lib/hostip.c:733`), `get_localhost6` (`:695`) and
/// `Curl_unix2addr` (`lib/curl_addrinfo.c:475`, commented *"assume reliable
/// transport for HTTP"*) all set it. [`SockType::Dgram`] exists because a
/// system resolver may report it for a service and because the QUIC filter
/// will need it.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[allow(dead_code)] // No consumer yet; conn/socket.rs consumes it.
pub(crate) enum SockType {
    /// `SOCK_STREAM`.
    #[default]
    Stream,
    /// `SOCK_DGRAM`.
    Dgram,
}

/// The transport protocol of one resolved address.
///
/// `get_localhost` and `get_localhost6` set `ai_protocol = IPPROTO_TCP`
/// explicitly (`lib/hostip.c:734`, `:696`), whereas `ip2addr` leaves the
/// field at the zero its `calloc` produced (`lib/curl_addrinfo.c:366-377`) -
/// that is `IPPROTO_IP`, meaning "unspecified, let the socket type
/// decide". The distinction is preserved because it is a real difference
/// between two C functions this module supersedes, and eliding it would
/// silently change what a filter chain sees.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[allow(dead_code)] // No consumer yet; conn/socket.rs consumes it.
pub(crate) enum IpProto {
    /// `IPPROTO_IP`, the zero a `calloc`ed `Curl_addrinfo` carries.
    #[default]
    Unspecified,
    /// `IPPROTO_TCP`.
    Tcp,
    /// `IPPROTO_UDP`.
    Udp,
}

/// Where one resolved address points.
///
/// `struct Curl_addrinfo` stores a `struct sockaddr *ai_addr` with an
/// `ai_addrlen`, and every consumer casts it to `sockaddr_in`,
/// `sockaddr_in6` or `sockaddr_un` after reading `ai_family`. That cast is
/// the pattern AAP 0.6.9 removes: the discriminant and the payload travel
/// together here, so no consumer can read the wrong one.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[allow(dead_code)] // No consumer yet; conn/socket.rs consumes it.
pub(crate) enum ResolvedSockAddr {
    /// An IPv4 or IPv6 endpoint with its port.
    Ip(SocketAddr),
    /// A filesystem or abstract Unix domain socket path.
    ///
    /// The `bool` is C's `abstract` argument to `Curl_unix2addr`
    /// (`lib/curl_addrinfo.c:447`): an abstract socket's name occupies
    /// `sun_path` from offset one, leaving the leading byte zero, which is
    /// the Linux convention for a name outside the filesystem.
    Unix { path: PathBuf, abstract_ns: bool },
}

/// One resolved address, owning everything it needs.
///
/// Supersedes `struct Curl_addrinfo` (`lib/curl_addrinfo.h`):
///
/// ```c
/// struct Curl_addrinfo {
///   int                   ai_flags;
///   int                   ai_family;
///   int                   ai_socktype;
///   int                   ai_protocol;
///   curl_socklen_t        ai_addrlen;
///   char                 *ai_canonname;
///   struct sockaddr      *ai_addr;
///   struct Curl_addrinfo *ai_next;
/// };
/// ```
///
/// Four of those eight members disappear rather than being translated, and
/// each disappearance is a deliberate simplification of an unsafe pattern:
///
/// * `ai_next` is gone - the intrusive list becomes a
///   [`Vec<ResolvedAddr>`], as AAP 0.6.9 requires. **The order of that
///   vector is behaviour, not an implementation detail.**
/// * `ai_addrlen` is gone - it existed only to tell a `connect(2)` how many
///   bytes of the `sockaddr` union are meaningful, which the discriminant of
///   [`ResolvedSockAddr`] now answers.
/// * `ai_family` is gone as a stored field and becomes
///   [`ResolvedAddr::family`], computed from the address so that the two can
///   never disagree. In C they could, and a mismatch was undefined
///   behaviour.
/// * `ai_addr` is gone as a raw pointer - the address is stored inline.
///
/// `ai_flags` is retained because a system resolver reports it and because
/// C carries it through `Curl_addrinfo_copy`; nothing in this module reads
/// it, which is why it has an explicit allowance rather than being dropped.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)] // No consumer yet; conn/ and resolver.rs consume it.
pub(crate) struct ResolvedAddr {
    /// Where it points, family and payload together.
    pub(crate) addr: ResolvedSockAddr,
    /// `ai_socktype`.
    pub(crate) socktype: SockType,
    /// `ai_protocol`.
    pub(crate) protocol: IpProto,
    /// `ai_canonname`, which is optional in C because the field is a
    /// pointer that may be NULL. `get_localhost` sets it to the requested
    /// name (`lib/hostip.c:738`) and `ip2addr` to the dotted text
    /// (`lib/curl_addrinfo.c:373`), so it is usually present.
    pub(crate) canonname: Option<String>,
    /// `ai_flags`, carried for fidelity with a system resolver's answer.
    #[allow(dead_code)] // Carried for fidelity; conn/ will read it.
    pub(crate) flags: i32,
}

impl ResolvedAddr {
    /// A TCP stream endpoint, the shape every synthesised address takes.
    ///
    /// `SockType::Stream` with `IpProto::Tcp` is what `get_localhost` and
    /// `get_localhost6` set (`lib/hostip.c:733-734`, `:695-696`).
    pub(crate) fn tcp(addr: SocketAddr, canonname: Option<String>) -> Self {
        Self {
            addr: ResolvedSockAddr::Ip(addr),
            socktype: SockType::Stream,
            protocol: IpProto::Tcp,
            canonname,
            flags: 0,
        }
    }

    /// The family of this address, derived rather than stored.
    pub(crate) fn family(&self) -> AddressFamily {
        match &self.addr {
            ResolvedSockAddr::Ip(SocketAddr::V4(_)) => AddressFamily::Inet,
            ResolvedSockAddr::Ip(SocketAddr::V6(_)) => AddressFamily::Inet6,
            ResolvedSockAddr::Unix { .. } => AddressFamily::Unix,
        }
    }

    /// The IP endpoint, when this is one.
    #[allow(dead_code)] // No consumer yet; conn/socket.rs consumes it.
    pub(crate) fn socket_addr(&self) -> Option<SocketAddr> {
        match &self.addr {
            ResolvedSockAddr::Ip(addr) => Some(*addr),
            ResolvedSockAddr::Unix { .. } => None,
        }
    }

    /// A printable form of this address, or the empty string.
    ///
    /// Supersedes `Curl_printable_address` (`lib/hostip.c:203-227`), whose
    /// documented contract is *"If the conversion fails, the target buffer is
    /// empty."* Three details are reproduced exactly:
    ///
    /// * The buffer is emptied FIRST - `buf[0] = 0;` at `:207`, before the
    ///   `switch`. Returning [`String::new`] from the fall-through arm is
    ///   that same guarantee.
    /// * Only `AF_INET` and `AF_INET6` are converted. **Any other family
    ///   leaves the result empty**, which is what an `AF_UNIX` entry
    ///   produces, and `show_resolve_info` relies on it by skipping such
    ///   addresses entirely.
    /// * The conversion is `curlx_inet_ntop`, so
    ///   [`crate::util::inet::ntop4`] and [`crate::util::inet::ntop6`] are
    ///   used and never [`Ipv6Addr`]'s [`fmt::Display`]. That is not
    ///   pedantry: curl renders IPv4-compatible addresses as `::a.b.c.d`
    ///   where the standard library does not, and curl declines to compress
    ///   a single zero word where the standard library compresses it. Both
    ///   divergences reach `--verbose` output.
    ///
    /// C writes into a caller-supplied `char buf[MAX_IPADR_LEN]`; the
    /// returned [`String`] can never exceed [`MAX_IPADR_LEN`] minus its
    /// terminator, which [`Self::printable_address_fits_the_c_buffer`]
    /// asserts.
    pub(crate) fn printable_address(&self) -> String {
        match &self.addr {
            ResolvedSockAddr::Ip(SocketAddr::V4(v4)) => {
                ntop4(&v4.ip().octets())
            }
            ResolvedSockAddr::Ip(SocketAddr::V6(v6)) => {
                ntop6(&v6.ip().octets())
            }
            // `default: break;` with the buffer still empty.
            ResolvedSockAddr::Unix { .. } => String::new(),
        }
    }

    /// True when [`Self::printable_address`] fits C's `MAX_IPADR_LEN` array.
    ///
    /// Kept as an ordinary method rather than a test-only helper because it
    /// states an invariant `crate::conn` will want to rely on when it writes
    /// an address into a fixed-size field, and because a `debug_assert` in a
    /// caller reads better than a re-derivation of the bound.
    #[allow(dead_code)] // No consumer yet; conn/ asserts with it.
    pub(crate) fn printable_address_fits_the_c_buffer(&self) -> bool {
        self.printable_address().len() < MAX_IPADR_LEN
    }
}

/// True when `hostname` is a numeric IPv4 or IPv6 address.
///
/// Supersedes `Curl_host_is_ipnum` (`lib/hostip.c:783-796`), which is two
/// `curlx_inet_pton` probes joined by `||`, and - byte for byte the same
/// logic - `Curl_is_ipaddr` (`lib/curl_addrinfo.c:426-440`). The C tree
/// carries both because they live in different translation units; there is
/// no reason to carry two here, so [`is_ipaddr`] delegates.
///
/// The probes are curl's own parsers, not the standard library's. That
/// matters for acceptance as well as for rendering: `crate::util::inet`
/// reproduces curl's `inet_pton`, which is stricter than a permissive
/// parser about leading zeroes and about trailing junk, and the strictness
/// decides whether a host is treated as a literal or handed to a resolver.
// No consumer yet; resolver.rs and show_resolve_info consume it.
#[allow(dead_code)]
pub(crate) fn host_is_ipnum(hostname: &[u8]) -> bool {
    pton4(hostname).is_some() || pton6(hostname).is_some()
}

/// True when `address` is a numeric IPv4 or IPv6 address.
///
/// Supersedes `Curl_is_ipaddr` (`lib/curl_addrinfo.c:426-440`). Delegates to
/// [`host_is_ipnum`] because the two C functions are the same two probes; a
/// second implementation could only drift.
#[allow(dead_code)] // No consumer yet; resolver.rs consumes it.
pub(crate) fn is_ipaddr(address: &[u8]) -> bool {
    host_is_ipnum(address)
}

/// Builds one address from a numeric literal and a port.
///
/// Supersedes `Curl_str2addr` (`lib/curl_addrinfo.c:407-423`) together with
/// the `ip2addr` helper it calls (`:341-401`). IPv4 is tried first, then
/// IPv6, and neither matching yields the C's own choice of code:
/// `CURLE_BAD_FUNCTION_ARGUMENT`, commented *"bad input format"*. This is
/// what the `CURLOPT_RESOLVE` loader calls for each address literal, and a
/// failure there produces [`msg::address_illegal`].
///
/// `ip2addr` sets `ai_socktype = SOCK_STREAM` and copies the dotted text
/// into `ai_canonname`, leaving `ai_protocol` and `ai_flags` at the zero its
/// `calloc` produced. All four are reproduced, including the protocol being
/// [`IpProto::Unspecified`] rather than [`IpProto::Tcp`] - that is a real
/// difference from `get_localhost`, which sets `IPPROTO_TCP` explicitly, and
/// eliding it would change what a filter chain observes.
///
/// # Errors
///
/// [`CURLcode::BadFunctionArgument`] when `dotted` is neither an IPv4 nor an
/// IPv6 literal.
// No consumer yet; the CURLOPT_RESOLVE loader and resolver.rs.
#[allow(dead_code)]
pub(crate) fn str2addr(dotted: &[u8], port: u16) -> CodeResult<ResolvedAddr> {
    // The canonical name is the literal itself. It is only nameable when the
    // bytes are UTF-8, which every accepted literal is: `pton4` and `pton6`
    // admit nothing outside ASCII, so a successful parse guarantees it.
    let ip = if let Some(octets) = pton4(dotted) {
        IpAddr::V4(Ipv4Addr::from(octets))
    } else if let Some(octets) = pton6(dotted) {
        IpAddr::V6(Ipv6Addr::from(octets))
    } else {
        return Err(CURLcode::BadFunctionArgument);
    };

    let canonname = core::str::from_utf8(dotted).ok().map(str::to_owned);

    Ok(ResolvedAddr {
        addr: ResolvedSockAddr::Ip(SocketAddr::new(ip, port)),
        socktype: SockType::Stream,
        // `ip2addr` leaves this at the zero of its `calloc`.
        protocol: IpProto::Unspecified,
        canonname,
        flags: 0,
    })
}

/// Builds one `AF_UNIX` address from a socket path.
///
/// Supersedes `Curl_unix2addr` (`lib/curl_addrinfo.c:447-485`). C signals an
/// over-long path through a `bool *longpath` out-parameter beside a NULL
/// return, so that the caller can distinguish it from an allocation failure
/// and report a different message. Rust needs neither: an over-long path is
/// the only failure mode left, so it is the only error this returns, and the
/// out-parameter disappears.
///
/// The bound is C's: `strlen(path) + 1 > sizeof(sun_path)`, so the path plus
/// its terminator must fit in [`UNIX_PATH_MAX`]. An abstract socket's name
/// starts at offset one of `sun_path`, which C arranges by copying
/// `path_len - 1` bytes to `sun_path + 1`; the leading zero is the name, not
/// padding, so the length available is unchanged and `abstract_ns` is
/// recorded rather than folded into the path.
///
/// This is the reason a [`DnsEntry`]'s hostname may be empty: C's comment at
/// `lib/hostip.h:67` says the name *"may be NULL (Unix domain sockets)"*.
///
/// # Errors
///
/// [`CURLcode::BadFunctionArgument`] when the path does not fit. C's caller
/// turns `longpath` into its own diagnostic, which is why no message is
/// emitted here.
#[allow(dead_code)] // No consumer yet; conn/socket.rs consumes it.
pub(crate) fn unix2addr(
    path: &Path,
    abstract_ns: bool,
) -> CodeResult<ResolvedAddr> {
    // `path_len = strlen(path) + 1;` then
    // `if(path_len > sizeof(sa_un->sun_path)) { *longpath = TRUE; ... }`.
    // `as_os_str().as_encoded_bytes()` is not available at MSRV 1.75, and
    // `to_string_lossy` would change the length of a non-UTF-8 path, so the
    // byte length is taken from the lossless UTF-8 form when there is one
    // and refused otherwise -- a path this crate cannot render is a path it
    // cannot put in a message either.
    let text = path.to_str().ok_or(CURLcode::BadFunctionArgument)?;
    if text.len() + 1 > UNIX_PATH_MAX {
        return Err(CURLcode::BadFunctionArgument);
    }

    Ok(ResolvedAddr {
        addr: ResolvedSockAddr::Unix {
            path: path.to_path_buf(),
            abstract_ns,
        },
        // `ai->ai_socktype = SOCK_STREAM; /* assume reliable transport for
        // HTTP */` -- `lib/curl_addrinfo.c:475`.
        socktype: SockType::Stream,
        protocol: IpProto::Unspecified,
        canonname: None,
        flags: 0,
    })
}

/// Builds the DNS cache key for one host and port.
///
/// Supersedes `create_dnscache_id` (`lib/hostip.c:233-244`), reproduced step
/// for step:
///
/// ```c
/// size_t len = nlen ? nlen : strlen(name);
/// DEBUGASSERT(buflen >= MAX_HOSTCACHE_LEN);
/// if(len > (buflen - 7))
///   len = buflen - 7;
/// /* store and lower case the name */
/// Curl_strntolower(ptr, name, len);
/// return curl_msnprintf(&ptr[len], 7, ":%u", port) + len;
/// ```
///
/// so the key is `<ascii-lowercased-truncated-host>:<port>`.
///
/// # The lowercasing is required, not cosmetic
///
/// `Curl_dnscache_init` builds the table with `Curl_hash_str` and
/// `curlx_str_key_compare` (`lib/hostip.c:1270-1271`), and that comparator
/// is **case-sensitive** - it is an exact-length byte comparison.
/// Case-insensitive lookup is therefore achieved by normalising at the call
/// site, which is exactly what this function is. The folding is ASCII-only,
/// through [`crate::util::strcase::strntolower`], whose `raw_tolower` is the
/// identity for every byte in `0x80..=0xFF`. Using Rust's Unicode-aware
/// lowercasing instead would change *which hostnames collide in the cache*:
/// it would fold `U+0130` and other non-ASCII letters, and it can change a
/// string's length. That is a correctness requirement.
///
/// # The truncation is observable
///
/// A host longer than [`MAX_HOSTCACHE_HOST_LEN`] is cut to exactly 255
/// bytes, so two hosts differing only after byte 255 share a cache entry.
/// That is C's behaviour and it is reproduced rather than repaired: a
/// hostname that long is invalid under RFC 1035 anyway, and "repairing" it
/// would make this cache disagree with curl's.
///
/// # The trailing NUL: a decision, not an accident
///
/// Every lookup, insert and delete in C passes `entry_len + 1`, deliberately
/// **including the terminator** (`lib/hostip.c:392`, `:399`, `:413`, `:439`,
/// `:633`, `:660`). The key returned here omits it. That is safe and is
/// chosen on three grounds. A [`Vec<u8>`] carries its own length, so the
/// separator the NUL provided in C is structural here. The comparator is an
/// exact-length byte comparison, so a byte appended to every key uniformly
/// cannot change which keys collide. And there is no persisted, on-disk or
/// cross-process DNS-cache format anywhere in curl - the cache lives and
/// dies with a multi or share handle - so no external consumer can observe
/// the difference. Were a serialised format ever added, appending `0u8` here
/// would restore byte-for-byte parity with C in one line.
///
/// # Panics
///
/// Never. `nlen` is expressed as the caller passing the exact byte slice it
/// means, which removes C's `nlen ? nlen : strlen(name)` branch along with
/// the class of defect where the two disagree.
#[allow(dead_code)] // No consumer yet; The cache and the loader consume it.
pub(crate) fn create_dnscache_id(host: &[u8], port: u16) -> Vec<u8> {
    // `if(len > (buflen - 7)) len = buflen - 7;`
    let len = host.len().min(MAX_HOSTCACHE_HOST_LEN);
    let source = &host[..len];

    // `:%u` is at most six bytes for a `u16`, so the exact capacity is
    // known. Reserving it is not an optimisation; it documents the same
    // arithmetic C's `MAX_HOSTCACHE_LEN` performs.
    let mut key = vec![0u8; len];

    // `Curl_strntolower(ptr, name, len)` -- ASCII-only, locale-independent.
    let written = strntolower(&mut key, source);
    debug_assert_eq!(
        written, len,
        "strntolower copies min(dest, src), and dest was sized to src"
    );

    // `curl_msnprintf(&ptr[len], 7, ":%u", port)` -- a colon, then the
    // UNSIGNED port. C's parameter is an `int` and the conversion is `%u`,
    // so a negative port would have printed as a large unsigned value; the
    // port is a `u16` here, which is the range every caller in the C tree
    // can actually produce (`curlx_str_number(..., 0xffff)` bounds the
    // `CURLOPT_RESOLVE` path, and a URL port is bounded the same way).
    key.push(b':');
    key.extend_from_slice(itoa_u16(port).as_ref().as_bytes());
    key
}

/// The cache key for the wildcard entry `CURLOPT_RESOLVE`'s `*` creates.
///
/// C forms it with `create_dnscache_id("*", 1, port, ...)`
/// (`lib/hostip.c:396`), passing an explicit length of one. Named here so
/// that the two call sites - the wildcard lookup in [`DnsCache::fetch_addr`]
/// and the wildcard insert in [`load_host_pairs`] - cannot disagree about
/// what the wildcard host is.
#[allow(dead_code)] // No consumer yet; fetch_addr and the loader consume it.
pub(crate) fn wildcard_dnscache_id(port: u16) -> Vec<u8> {
    create_dnscache_id(WILDCARD_HOST, port)
}

/// The host `CURLOPT_RESOLVE` treats as "any host on this port".
///
/// `lib/hostip.c:1463` tests the parsed host with
/// `curlx_str_casecompare(&source, "*")`, and `:396` looks the entry up
/// under the one-byte name `"*"`.
// No consumer yet; read by the wildcard key and its test.
#[allow(dead_code)]
const WILDCARD_HOST: &[u8] = b"*";

/// Renders a `u16` as decimal without allocating.
///
/// `curl_msnprintf(&ptr[len], 7, ":%u", port)` writes into the caller's
/// buffer, so the C allocates nothing here. A five-byte array plus a length
/// is the same trade, and it keeps [`create_dnscache_id`] free of a
/// temporary [`String`] on a path that runs once per lookup.
#[allow(dead_code)] // No consumer yet; Read by create_dnscache_id.
fn itoa_u16(value: u16) -> impl AsRef<str> {
    /// Five digits is the widest a `u16` can be: 65535.
    struct Decimal {
        digits: [u8; 5],
        len: usize,
    }

    impl AsRef<str> for Decimal {
        fn as_ref(&self) -> &str {
            // Every byte written is an ASCII digit, so the slice is UTF-8 by
            // construction. `from_utf8` is used rather than an unchecked
            // conversion because this crate contains no `unsafe`, and the
            // fall-back can never be taken.
            core::str::from_utf8(&self.digits[..self.len]).unwrap_or("")
        }
    }

    let mut digits = [0u8; 5];
    let mut len = 0usize;
    let mut rest = value;
    // Write least-significant first, then reverse: the same shape
    // `curl_msnprintf`'s integer conversion uses. `get_mut` rather than an
    // index expression so that staying inside the array is structural --
    // 65535 is five digits, so the loop can never ask for a sixth, and the
    // condition failing is unreachable rather than a real early exit.
    while let Some(slot) = digits.get_mut(len) {
        *slot = b'0' + (rest % 10) as u8;
        len += 1;
        rest /= 10;
        if rest == 0 {
            break;
        }
    }
    if let Some(written) = digits.get_mut(..len) {
        written.reverse();
    }
    Decimal { digits, len }
}

/// One cache entry: the addresses a host and port resolved to.
///
/// Supersedes `struct Curl_dns_entry` (`lib/hostip.h:56-69`):
///
/// ```c
/// struct Curl_dns_entry {
///   struct Curl_addrinfo *addr;
/// #ifdef USE_HTTPSRR
///   struct Curl_https_rrinfo *hinfo;
/// #endif
///   /* timestamp == 0 -- permanent CURLOPT_RESOLVE entry (does not time
///      out) */
///   struct curltime timestamp;
///   /* reference counter, entry is freed on reaching 0 */
///   size_t refcount;
///   /* hostname port number that resolved to addr. */
///   int hostport;
///   /* hostname that resolved to addr. may be NULL (Unix domain sockets). */
///   char hostname[1];
/// };
/// ```
///
/// # `refcount` is [`Arc`], not a field
///
/// The counter is gone. `Curl_resolv_unlink` (`lib/hostip.c:1242-1254`) and
/// `dnscache_entry_dtor` (`:1256-1263`) both decrement and free at zero, and
/// `dnscache_entry_free` (`:184-194`) releases the address list, then the
/// HTTPS-RR record, then the entry itself. Every one of those becomes
/// [`Arc`] plus `Drop`. **Nothing here needs a manual free and none may be
/// added**: an entry the cache still holds and a caller still holds is one
/// `Arc` with two owners, and it disappears when the second of them does.
/// Handles are [`DnsEntryRef`].
///
/// # `hostname` is a `String` that may be empty
///
/// C's flexible array is always present, and the code tests `dns->hostname[0]`
/// rather than the pointer - at `lib/hostip.c:131-134` to decide whether to
/// print anything, and at `:138-139` to substitute `"(none)"`. The empty
/// string is therefore the faithful representation of the comment's *"may be
/// NULL (Unix domain sockets)"* case, and an [`Option`] would force every
/// consumer to re-decide which of `None` and `Some("")` C meant.
///
/// # The HTTPS-RR slot is specified and not yet present
///
/// C carries `struct Curl_https_rrinfo *hinfo` under `USE_HTTPSRR`; in Rust
/// the handling is unconditional, so the field takes no `cfg`. Its type is
/// owned by `dns/httpsrr.rs`, which does not exist at this commit, and
/// defining a placeholder here would create a second definition that file
/// would then have to displace - the drift AAP 0.1.2 forbids. The field this
/// struct gains with that file is therefore recorded rather than invented:
///
/// ```text
///     /// C's `hinfo`, unconditional here. Released by `Drop`.
///     pub(crate) hinfo: Option<Box<httpsrr::HttpsRrInfo>>,
/// ```
///
/// Its arrival is additive: nothing in this module reads `hinfo`, because
/// nothing in `lib/hostip.c` does either beyond freeing it.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)] // No consumer yet; resolver.rs and conn/ consume it.
pub(crate) struct DnsEntry {
    /// C's `addr`. **Empty means a negative entry**, which is what
    /// `store_negative_resolve` (`lib/hostip.c:822-845`) inserts after a
    /// failed lookup and what makes [`Self::is_stale`] age this entry twice
    /// as fast.
    pub(crate) addrs: Vec<ResolvedAddr>,
    /// C's `timestamp`. **The all-zero reading means permanent** - a
    /// `CURLOPT_RESOLVE` entry that never times out. That is C's own
    /// encoding, kept rather than replaced with an `Option`, because the
    /// staleness predicate tests the two fields directly
    /// (`lib/hostip.c:264`) and because `Curl_dnscache_mk_entry` writes the
    /// zeroes explicitly (`:591-592`) to say so.
    pub(crate) timestamp: CurlTime,
    /// C's `hostport`, narrowed from `int` to the range a port occupies.
    pub(crate) hostport: u16,
    /// C's `hostname`, ASCII-cased as the caller supplied it. The cache key
    /// is lowercased; this is not, because `show_resolve_info` prints it.
    pub(crate) hostname: String,
}

impl DnsEntry {
    /// True when this entry never times out.
    ///
    /// `lib/hostip.h:61`: *"timestamp == 0 -- permanent CURLOPT_RESOLVE
    /// entry (does not time out)"*, tested in the C as
    /// `if(dns->timestamp.tv_sec || dns->timestamp.tv_usec)`.
    #[allow(dead_code)] // No consumer yet; Read by DnsEntry::staleness.
    pub(crate) fn is_permanent(&self) -> bool {
        self.timestamp.is_zero()
    }

    /// True when this entry holds no addresses.
    ///
    /// C's `if(!dns->addr)`. Named because it appears in two places with two
    /// different meanings: it doubles the ageing rate here, and it is what
    /// makes `resolver.rs` report [`msg::NEGATIVE_ENTRY`] on a cache hit.
    // No consumer yet; read by staleness and by resolver.rs.
    #[allow(dead_code)]
    pub(crate) fn is_negative(&self) -> bool {
        self.addrs.is_empty()
    }

    /// True when this entry holds an address of `family`.
    ///
    /// The linear scan of `fetch_addr`'s fourth step
    /// (`lib/hostip.c:428-435`), which walks `ai_next` looking for a single
    /// match and stops at the first.
    #[allow(dead_code)] // No consumer yet; Read by DnsCache::fetch_addr.
    pub(crate) fn has_family(&self, family: AddressFamily) -> bool {
        self.addrs.iter().any(|addr| addr.family() == family)
    }

    /// The staleness decision, and the age that fed it.
    ///
    /// Supersedes `dnscache_entry_is_stale` (`lib/hostip.c:258-275`), whose
    /// contract is stated in its own comment at `:255-257`: *"Returning
    /// non-zero means remove the entry, return 0 to keep it in the cache."*
    /// The returned [`Staleness`] carries both halves of what C's callback
    /// communicated - its `int` return and the `oldest_ms` it wrote back
    /// through the shared `struct dnscache_prune_data` (`:246-250`) - so the
    /// scratch struct disappears without losing anything.
    ///
    /// The four steps, in C's order:
    ///
    /// 1. `if(dns->timestamp.tv_sec || dns->timestamp.tv_usec)` - a
    ///    **permanent entry falls straight through to `return FALSE`** and is
    ///    never stale, whatever `max_age_ms` says.
    /// 2. `age = curlx_ptimediff_ms(&prune->now, &dns->timestamp);`
    /// 3. **`if(!dns->addr) age *= 2;`** - `:267-268`, whose comment is
    ///    *"negative entries age twice as fast"*. A cached failure therefore
    ///    expires at half the configured lifetime, which is what governs how
    ///    soon a failed lookup is retried. This is easy to miss and has its
    ///    own test.
    /// 4. `if(age >= prune->max_age_ms) return TRUE;` - **`>=`, not `>`**, so
    ///    an entry exactly `max_age_ms` old is removed.
    /// 5. Otherwise `if(age > prune->oldest_ms) prune->oldest_ms = age;` -
    ///    note that this runs only for a SURVIVING entry, because step 4
    ///    returned first. `oldest` is consequently the age of the oldest
    ///    entry still in the cache, which is exactly what
    ///    [`DnsCache::prune`] needs to halve.
    ///
    /// The multiplication in step 3 saturates. C's `timediff_t` is a signed
    /// 64-bit integer and doubling it can overflow only for an age of more
    /// than 146 million years, where C would wrap into a negative value and
    /// wrongly keep the entry; saturating keeps it stale instead, which is
    /// the answer the code plainly intends. The divergence is unreachable
    /// from any clock this crate can read and is recorded rather than left
    /// implicit.
    #[allow(dead_code)] // No consumer yet; Read by DnsCache::prune_once.
    pub(crate) fn staleness(
        &self,
        now: CurlTime,
        max_age_ms: TimeDiff,
    ) -> Staleness {
        // Step 1: the permanent short-circuit.
        if self.is_permanent() {
            return Staleness::Keep { age_ms: 0 };
        }

        // Step 2: the age in milliseconds.
        let mut age_ms = timediff_ms(now, self.timestamp);

        // Step 3: negative entries age twice as fast.
        if self.is_negative() {
            age_ms = age_ms.saturating_mul(2);
        }

        // Step 4: `>=`, not `>`.
        if age_ms >= max_age_ms {
            Staleness::Remove { age_ms }
        } else {
            Staleness::Keep { age_ms }
        }
    }

    /// True when this entry should be removed at `max_age_ms`.
    ///
    /// The `int` half of C's callback return, for the callers that do not
    /// need the age.
    #[allow(dead_code)] // No consumer yet; Read by DnsCache::fetch_addr.
    pub(crate) fn is_stale(&self, now: CurlTime, max_age_ms: TimeDiff) -> bool {
        self.staleness(now, max_age_ms).is_remove()
    }
}

/// What the staleness predicate decided, and the age it measured.
///
/// C fused these into an `int` return plus a write through a shared mutable
/// struct. Splitting them makes the "only surviving entries update `oldest`"
/// rule of [`DnsEntry::staleness`] a property of the type rather than of the
/// order two statements happen to appear in.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)] // No consumer yet; Returned by DnsEntry::staleness.
pub(crate) enum Staleness {
    /// C's `return FALSE` - keep the entry. `age_ms` is the age that
    /// [`DnsCache::prune`] folds into `oldest`, and is zero for a permanent
    /// entry, matching C's skipping of the fold entirely.
    Keep { age_ms: TimeDiff },
    /// C's `return TRUE` - remove the entry.
    Remove { age_ms: TimeDiff },
}

impl Staleness {
    /// True for [`Staleness::Remove`], which is C's non-zero return.
    #[allow(dead_code)] // No consumer yet; Read by DnsEntry::is_stale.
    pub(crate) const fn is_remove(self) -> bool {
        matches!(self, Self::Remove { .. })
    }

    /// The age this decision measured, in milliseconds.
    // No consumer yet; share/ reports the oldest age through it.
    #[allow(dead_code)]
    pub(crate) const fn age_ms(self) -> TimeDiff {
        match self {
            Self::Keep { age_ms } | Self::Remove { age_ms } => age_ms,
        }
    }
}

/// A shared handle on a cache entry.
///
/// C's `struct Curl_dns_entry *` with its manual `refcount`. Every C
/// function that hands one out increments the counter and documents that
/// *"The returned data *MUST* be 'released' with Curl_resolv_unlink() after
/// use, or we will leak memory!"* (`lib/hostip.h:81-82`, `:172-173`). Here
/// the release is [`Drop`], so the warning has nothing to warn about.
#[allow(dead_code)] // No consumer yet; resolver.rs and conn/ consume it.
pub(crate) type DnsEntryRef = Arc<DnsEntry>;

/// The value `CURLOPT_DNS_CACHE_TIMEOUT` takes to mean "never expire".
///
/// `lib/hostip.c:326-327` comments it *"the timeout may be set -1
/// (forever)"* and both `Curl_dnscache_prune` (`:330`) and `fetch_addr`
/// (`:408`) test for exactly `-1` rather than for any negative value. The
/// literal is named so that neither test can be written as `< 0` by mistake.
// No consumer yet; read by prune, fetch_addr and easy/setopt.
#[allow(dead_code)]
pub(crate) const DNS_CACHE_TIMEOUT_FOREVER: TimeDiff = -1;

/// The DNS cache: hostname and port to addresses.
///
/// Supersedes `struct Curl_dnscache` (`lib/hostip.h:71-73`), which is one
/// `struct Curl_hash entries` built by `Curl_dnscache_init`
/// (`lib/hostip.c:1268-1272`) with `Curl_hash_str` as its hash,
/// `curlx_str_key_compare` as its comparator and `dnscache_entry_dtor` as its
/// destructor. All three become properties of the Rust types:
/// [`crate::util::hash::StrHash`] carries the first two, and the third is
/// [`Arc`]'s `Drop`.
///
/// # No interior locking - read this before adding a `Mutex`
///
/// `lib/hostip.c:298-319` selects and locks the cache in three separate
/// functions:
///
/// ```c
/// static struct Curl_dnscache *dnscache_get(struct Curl_easy *data)
/// {
///   if(data->share && data->share->specifier & (1 << CURL_LOCK_DATA_DNS))
///     return &data->share->dnscache;
///   if(data->multi)
///     return &data->multi->dnscache;
///   return NULL;
/// }
/// ```
///
/// and `dnscache_lock` takes `Curl_share_lock(data, CURL_LOCK_DATA_DNS,
/// CURL_LOCK_ACCESS_SINGLE)` **only** `if(data->share && dnscache ==
/// &data->share->dnscache)`. A multi handle's own cache is never locked at
/// all. The lock therefore belongs to the *sharing decision*, not to the
/// cache, and `crate::share` owns that decision: it will wrap this type in
/// interior mutability and implement the caller's `CURLSHOPT_LOCKFUNC`
/// contract. A lock inside this type would double-lock the shared case and
/// would put the policy in the module that cannot see the `specifier` bit.
///
/// The selection itself - share, else multi, else none - also belongs
/// outside. `crate::easy` and `crate::multi` own the handles; a missing cache
/// is what makes C return `CURLE_FAILED_INIT` from `Curl_dnscache_add`
/// (`:651`) and `Curl_loadhostpairs` (`:1286`), and those codes are produced
/// by the caller that discovers the absence, not by this type.
///
/// # Ordering
///
/// [`Self::prune`] is order-independent; the module documentation records the
/// full argument and the reason an LRU must not replace it.
#[derive(Debug, Default)]
#[allow(dead_code)] // No consumer yet; multi/ and share/ own an instance.
pub(crate) struct DnsCache {
    /// C's `struct Curl_hash entries`, keyed by [`create_dnscache_id`].
    entries: StrHash<DnsEntryRef>,
    /// C's `data->state.wildcard_resolve` (`lib/hostip.c:1287`, `:395`).
    ///
    /// It lives here rather than on a transfer's state because it describes
    /// the cache's contents: it is set by [`load_host_pairs`] when a
    /// `CURLOPT_RESOLVE` entry named `*`, and read by [`Self::fetch_addr`] to
    /// decide whether a miss is worth a second lookup. Keeping the flag with
    /// the entries it describes is what stops the two from disagreeing after
    /// a [`Self::clear`].
    wildcard_resolve: bool,
}

impl DnsCache {
    /// An empty cache.
    ///
    /// C's `Curl_dnscache_init(dns, size)` takes a slot-count hint, which
    /// `Curl_hash_init` uses to size its bucket array. Use
    /// [`Self::with_size`] when a hint is meaningful.
    #[allow(dead_code)] // No consumer yet; The owning handle constructs it.
    pub(crate) fn new() -> Self {
        Self {
            entries: StrHash::new(),
            wildcard_resolve: false,
        }
    }

    /// An empty cache with room for `size` entries.
    ///
    /// Supersedes `Curl_dnscache_init` (`lib/hostip.c:1268-1272`). C's `size`
    /// is a bucket count; here it is a capacity hint, which is the closest
    /// faithful reading - both exist to avoid rehashing a cache whose
    /// expected population is known.
    // No consumer yet; multi/ sizes the cache at handle init.
    #[allow(dead_code)]
    pub(crate) fn with_size(size: usize) -> Self {
        Self {
            entries: StrHash::with_slots(size),
            wildcard_resolve: false,
        }
    }

    /// How many entries the cache holds.
    ///
    /// C's `Curl_hash_count(&dnscache->entries)`, which
    /// `Curl_dnscache_prune` compares against [`MAX_DNS_CACHE_SIZE`].
    #[allow(dead_code)] // No consumer yet; Read by DnsCache::prune.
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when the cache holds nothing.
    #[allow(dead_code)] // No consumer yet; share/ reports emptiness through it.
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether a `CURLOPT_RESOLVE` wildcard entry is in force.
    #[allow(dead_code)] // No consumer yet; resolver.rs reads the flag.
    pub(crate) fn wildcard_resolve(&self) -> bool {
        self.wildcard_resolve
    }

    /// Empties the cache.
    ///
    /// Supersedes `Curl_dnscache_clear` (`lib/hostip.c:355-363`), which calls
    /// `Curl_hash_clean` under the lock. The wildcard flag is cleared with
    /// the entries, because the entry it described is one of the entries
    /// being removed - leaving it set would make [`Self::fetch_addr`] perform
    /// a second lookup that can no longer succeed.
    // No consumer yet; share/ backs CURLSHOPT_UNSHARE with it.
    #[allow(dead_code)]
    pub(crate) fn clear(&mut self) {
        self.entries.clear();
        self.wildcard_resolve = false;
    }

    /// Removes one entry by key, returning it when it was present.
    ///
    /// C's `Curl_hash_delete(&dnscache->entries, entry_id, entry_len + 1)`,
    /// whose return is `void` and whose callers all ignore whether anything
    /// was there - `Curl_loadhostpairs` comments *"delete entry, ignore if it
    /// did not exist"* (`lib/hostip.c:1319`). The value is returned here
    /// anyway, because a caller that wants to know can now ask and the tests
    /// below do.
    #[allow(dead_code)] // No consumer yet; Read by fetch_addr and the loader.
    pub(crate) fn remove(&mut self, key: &[u8]) -> Option<DnsEntryRef> {
        self.entries.remove(key)
    }

    /// Inserts a prepared entry under the key its own host and port give.
    ///
    /// Supersedes `Curl_dnscache_add` (`lib/hostip.c:645-667`). Two of that
    /// function's three outcomes cannot occur here and their absence is
    /// deliberate:
    ///
    /// * `if(!dnscache) return CURLE_FAILED_INIT;` - a missing cache is not
    ///   expressible when the cache is the receiver. The caller that selects
    ///   between the share's cache and the multi's is the one that discovers
    ///   the absence, and it is the one that returns that code.
    /// * `if(!Curl_hash_add(...)) return CURLE_OUT_OF_MEMORY;` - insertion
    ///   into a Rust map does not report allocation failure; the process
    ///   aborts instead. Nothing is lost, because there is no recovery path
    ///   in C either beyond propagating the code.
    ///
    /// `entry->refcount++` becomes cloning the [`Arc`], which is what
    /// returning the handle while the map keeps its own does.
    ///
    /// The key is built from the entry's own `hostname` and `hostport`, as
    /// C's `create_dnscache_id(entry->hostname, 0, entry->hostport, ...)`
    /// does with an explicit zero length so that `strlen` supplies it.
    ///
    /// Returns the previous entry for this key when one was replaced, which
    /// C's `Curl_hash_add` also does implicitly by destroying it.
    #[allow(dead_code)] // No consumer yet; Read by DnsCache::add_addrs.
    pub(crate) fn add(&mut self, entry: DnsEntry) -> DnsEntryRef {
        let key = create_dnscache_id(entry.hostname.as_bytes(), entry.hostport);
        let shared: DnsEntryRef = Arc::new(entry);
        self.entries.insert(&key, Arc::clone(&shared));
        shared
    }

    /// Builds an entry and inserts it, returning a handle on it.
    ///
    /// Supersedes the pair `Curl_dnscache_mk_entry` (`lib/hostip.c:560-608`)
    /// and `dnscache_add_addr` (`:611-642`), which C keeps apart so that a
    /// caller can modify the entry - attaching an HTTPS-RR record - between
    /// building and inserting. The header comment
    /// (`lib/hostip.h:146-158`) is the contract:
    ///
    /// > Creates a dnscache entry *without* adding it to a dnscache. This
    /// > allows further modifications of the entry *before* then adding it to
    /// > a cache. The entry is created with a reference count of 1 ... The call
    /// > takes ownership of `addr`, even in case of failure, and always
    /// > clears `*paddr`. It makes a copy of `hostname`.
    ///
    /// Two clauses of that contract vanish in Rust rather than being
    /// emulated. "Takes ownership ... and always clears `*paddr`" is what
    /// passing `addrs` by value already means, so there is no out-parameter
    /// to clear and no way for a caller to keep a stale alias to a freed
    /// list. "Makes a copy of `hostname`" is likewise the meaning of taking a
    /// [`String`]. A caller that wants to build without inserting uses
    /// [`Self::mk_entry`] and then [`Self::add`], which is C's split
    /// preserved.
    ///
    /// # Errors
    ///
    /// Whatever the entropy source reports when shuffling is requested. C
    /// returns `CURLE_OUT_OF_MEMORY` there and leaves the list unshuffled;
    /// see [`shuffle_addrs`] for what replaces that.
    // Seven parameters: C's own five plus the clock and entropy seams that
    // replace its `struct Curl_easy *data`. The threshold is nine.
    #[allow(dead_code)] // No consumer yet; resolver.rs and the loader.
    pub(crate) fn add_addrs(
        &mut self,
        hostname: &str,
        port: u16,
        addrs: Vec<ResolvedAddr>,
        permanent: bool,
        clock: &dyn Clock,
        shuffle: Option<&mut dyn FnMut(&mut [u8]) -> CodeResult<()>>,
        tracer: &mut Tracer<'_>,
    ) -> CodeResult<DnsEntryRef> {
        let entry = Self::mk_entry(
            hostname, port, addrs, permanent, clock, shuffle, tracer,
        )?;
        Ok(self.add(entry))
    }

    /// Builds an entry without inserting it.
    ///
    /// Supersedes `Curl_dnscache_mk_entry` (`lib/hostip.c:560-608`). The
    /// order of the two steps is C's and matters: **the shuffle happens
    /// first**, before the entry exists, because C shuffles through the
    /// `paddr` out-parameter and bails out of entry creation entirely if it
    /// fails (`:571-576`).
    ///
    /// `permanent` selects the timestamp, exactly as `:590-596` does: the
    /// all-zero reading for a permanent entry - C writes both fields
    /// explicitly and comments each *"an entry that never goes stale"* - and
    /// otherwise the current instant from the **injected** clock, which is
    /// C's `*Curl_pgrs_now(data)`.
    ///
    /// # Errors
    ///
    /// Whatever the entropy source reports when shuffling is requested.
    // Seven parameters, as [`Self::add_addrs`] explains.
    #[allow(dead_code)] // No consumer yet; resolver.rs builds then inserts.
    pub(crate) fn mk_entry(
        hostname: &str,
        port: u16,
        mut addrs: Vec<ResolvedAddr>,
        permanent: bool,
        clock: &dyn Clock,
        shuffle: Option<&mut dyn FnMut(&mut [u8]) -> CodeResult<()>>,
        tracer: &mut Tracer<'_>,
    ) -> CodeResult<DnsEntry> {
        // `if(data->set.dns_shuffle_addresses && paddr)` -- the shuffle is
        // requested by passing an entropy source, which is the same
        // condition expressed as the presence of what it needs.
        if let Some(entropy) = shuffle {
            shuffle_addrs(&mut addrs, entropy, tracer)?;
        }

        let timestamp = if permanent {
            // `dns->timestamp.tv_sec = 0; dns->timestamp.tv_usec = 0;`
            CurlTime::ZERO
        } else {
            // `dns->timestamp = *Curl_pgrs_now(data);`
            clock.now()
        };

        Ok(DnsEntry {
            addrs,
            timestamp,
            hostport: port,
            hostname: hostname.to_owned(),
        })
    }

    /// Looks a host and port up, taking a reference to what it finds.
    ///
    /// Supersedes `Curl_dnscache_get` (`lib/hostip.c:459-476`), which is
    /// `dnscache_lock` then [`Self::fetch_addr`] then `dns->refcount++` then
    /// `dnscache_unlock`. The locking is `crate::share`'s, and the reference
    /// count is the [`Arc`] clone this returns.
    ///
    /// C's documentation of why this exists is worth keeping: *"Curl_resolv()
    /// checks initially and multi_runsingle() checks each time it discovers
    /// the handle in the state WAITRESOLVE whether the hostname has already
    /// been resolved ... This short circuits waiting for a lot of pending
    /// lookups for the same hostname requested by different handles."*
    // No consumer yet; resolver.rs performs the cache lookup.
    #[allow(dead_code)]
    pub(crate) fn get(
        &mut self,
        hostname: &[u8],
        port: u16,
        ip_version: IpVersion,
        max_age_ms: TimeDiff,
        now: CurlTime,
        tracer: &mut Tracer<'_>,
    ) -> Option<DnsEntryRef> {
        self.fetch_addr(hostname, port, ip_version, max_age_ms, now, tracer)
    }

    /// The four-step cache lookup.
    ///
    /// Supersedes `fetch_addr` (`lib/hostip.c:374-443`) step for step. The
    /// steps are ordered and the order is behaviour:
    ///
    /// 1. Build the key from `(hostname, port)` and look it up.
    /// 2. **On a miss, and only when a wildcard entry is in force**, rebuild
    ///    the key as `create_dnscache_id("*", 1, port, ...)` and look up
    ///    again (`:395-400`). This is how `--resolve '*:443:1.2.3.4'`
    ///    answers for a host nobody named.
    /// 3. **On a hit, and only when the timeout is not
    ///    [`DNS_CACHE_TIMEOUT_FOREVER`]**, apply
    ///    [`DnsEntry::staleness`]. A stale entry produces
    ///    [`msg::STALE_ZAPPED`] and is deleted (`:407-415`).
    /// 4. **On a hit, and only when a specific family was requested**, scan
    ///    for it. Its absence produces [`msg::FAMILY_ZAPPED`] and a delete
    ///    (`:417-441`).
    ///
    /// # The subtlety in steps 3 and 4
    ///
    /// Both delete using `entry_id`, which is **the last key computed** -
    /// C reuses one stack buffer and step 2 overwrote it. So when the
    /// wildcard path supplied the hit, it is the **wildcard entry** that gets
    /// zapped, not the exact-host entry that was never there. That is
    /// measured, not inferred, and it is reproduced here by tracking which
    /// key produced the hit. It also happens to be the only sensible
    /// behaviour: deleting the exact key would remove nothing and leave the
    /// stale wildcard entry to be found again on the next lookup.
    #[allow(dead_code)] // No consumer yet; Read by DnsCache::get.
    pub(crate) fn fetch_addr(
        &mut self,
        hostname: &[u8],
        port: u16,
        ip_version: IpVersion,
        max_age_ms: TimeDiff,
        now: CurlTime,
        tracer: &mut Tracer<'_>,
    ) -> Option<DnsEntryRef> {
        // Step 1. C's `entry_len + 1` includes the terminator; this key
        // omits it, for the reasons `create_dnscache_id` records.
        let mut key = create_dnscache_id(hostname, port);
        let mut found = self.entries.get(&key).map(Arc::clone);

        // Step 2. `if(!dns && data->state.wildcard_resolve)`.
        if found.is_none() && self.wildcard_resolve {
            key = wildcard_dnscache_id(port);
            found = self.entries.get(&key).map(Arc::clone);
        }

        // Step 3. `if(dns && (data->set.dns_cache_timeout_ms != -1))`.
        if let Some(entry) = found.as_ref() {
            if max_age_ms != DNS_CACHE_TIMEOUT_FOREVER
                && entry.is_stale(now, max_age_ms)
            {
                infof!(tracer, "{}", msg::STALE_ZAPPED);
                // C sets `dns = NULL` and lets the hash's destructor free
                // the entry; here dropping the handle and removing the map's
                // is the same thing, and the deletion uses the LAST key.
                found = None;
                self.entries.remove(&key);
            }
        }

        // Step 4. `if(dns && ip_version != CURL_IPRESOLVE_WHATEVER)`.
        if let Some(entry) = found.as_ref() {
            if let Some(required) = ip_version.required_family() {
                if !entry.has_family(required) {
                    infof!(tracer, "{}", msg::FAMILY_ZAPPED);
                    found = None;
                    self.entries.remove(&key);
                }
            }
        }

        found
    }

    /// Prunes stale entries, halving the age limit until the cache fits.
    ///
    /// Supersedes `Curl_dnscache_prune` (`lib/hostip.c:325-353`) together
    /// with the `dnscache_prune` helper it calls (`:280-296`):
    ///
    /// ```c
    /// if(!dnscache || (timeout_ms == -1))
    ///   return;
    /// do {
    ///   timediff_t oldest_ms = dnscache_prune(&dnscache->entries, timeout_ms,
    ///                                         *Curl_pgrs_now(data));
    ///   if(Curl_hash_count(&dnscache->entries) > MAX_DNS_CACHE_SIZE)
    ///     /* prune the ones over half this age */
    ///     timeout_ms = oldest_ms / 2;
    ///   else
    ///     break;
    ///   /* if the cache size is still too big, use the oldest age as new
    ///      prune limit */
    /// } while(timeout_ms);
    /// ```
    ///
    /// Three properties of that loop are load-bearing:
    ///
    /// * **[`DNS_CACHE_TIMEOUT_FOREVER`] skips pruning entirely.** The test
    ///   is for exactly `-1`, so it is written that way here too.
    /// * **The size cap is enforced by age-halving, never by LRU eviction.**
    ///   Do not "modernise" this. An LRU would need a recency order this
    ///   cache does not keep, and it would make the result depend on
    ///   iteration order - see the module documentation.
    /// * **The loop terminates.** `while(timeout_ms)` exits once the halved
    ///   age reaches zero, and it reaches zero because integer division by
    ///   two of a non-negative value strictly decreases until it does. A
    ///   `max_age_ms` of zero on entry removes every non-permanent entry on
    ///   the first pass, after which `oldest` is zero and the loop stops.
    ///   Permanent entries survive any limit, so a cache holding more than
    ///   [`MAX_DNS_CACHE_SIZE`] permanent entries stays over the cap rather
    ///   than looping forever - which is also exactly what C does.
    ///
    /// Returns the age in milliseconds of the oldest surviving entry, which
    /// is `dnscache_prune`'s own return value.
    #[allow(dead_code)] // No consumer yet; multi/ prunes between transfers.
    pub(crate) fn prune(
        &mut self,
        max_age_ms: TimeDiff,
        now: CurlTime,
    ) -> TimeDiff {
        // `if(!dnscache || (timeout_ms == -1)) return;`
        if max_age_ms == DNS_CACHE_TIMEOUT_FOREVER {
            return 0;
        }

        let mut limit_ms = max_age_ms;
        let mut oldest_ms;
        loop {
            oldest_ms = self.prune_once(limit_ms, now);

            if self.entries.len() > MAX_DNS_CACHE_SIZE {
                // "prune the ones over half this age"
                limit_ms = oldest_ms / 2;
            } else {
                break;
            }

            // The C's `while(timeout_ms)` condition, written where the loop
            // shape puts it rather than where C's `do`/`while` does.
            if limit_ms == 0 {
                break;
            }
        }
        oldest_ms
    }

    /// One full scan, removing every stale entry.
    ///
    /// Supersedes `dnscache_prune` (`lib/hostip.c:280-296`), which fills a
    /// `struct dnscache_prune_data` and hands it to
    /// `Curl_hash_clean_with_criterium`. That struct is not reproduced: its
    /// `now` and `max_age_ms` are parameters, and its `oldest_ms` is the
    /// return value, so a mutable scratch record shared with a callback
    /// becomes a captured local.
    ///
    /// [`crate::util::hash::StrHash::clean_with_criterium`] keeps **curl's
    /// polarity**, where the predicate returning `true` means REMOVE. That is
    /// the opposite of [`std::collections::HashMap::retain`], and the single
    /// inversion lives inside that method so a transliterated consumer such
    /// as this one is correct without having to notice.
    #[allow(dead_code)] // No consumer yet; Read by DnsCache::prune.
    fn prune_once(&mut self, max_age_ms: TimeDiff, now: CurlTime) -> TimeDiff {
        let mut oldest_ms: TimeDiff = 0;
        self.entries.clean_with_criterium(|entry| {
            match entry.staleness(now, max_age_ms) {
                Staleness::Remove { .. } => true,
                Staleness::Keep { age_ms } => {
                    // `if(age > prune->oldest_ms) prune->oldest_ms = age;`,
                    // reached only for a surviving entry.
                    if age_ms > oldest_ms {
                        oldest_ms = age_ms;
                    }
                    false
                }
            }
        });
        oldest_ms
    }
}

/// The synthesised address list for a loopback name.
///
/// Supersedes the pair `get_localhost` (`lib/hostip.c:708-745`) and
/// `get_localhost6` (`:671-702`), which C keeps apart only because the second
/// is compiled out without IPv6. Both build a `SOCK_STREAM` /`IPPROTO_TCP`
/// entry carrying the requested port and setting `ai_canonname` to the
/// requested name. IPv6 zeroes `sin6_flowinfo` and `sin6_scope_id`
/// explicitly (`:685-688`) and IPv4 `memset`s the whole `sockaddr_in` to
/// clear `sin_zero` (`:719-720`) - all of which
/// [`std::net::SocketAddr`] already guarantees, since it has no
/// uninitialised padding to leak.
///
/// # The order is IPv6 first, and it is behaviour
///
/// `lib/hostip.c:741-745` is the whole of it:
///
/// ```c
/// ca6 = get_localhost6(port, name);
/// if(!ca6)
///   return ca;
/// ca6->ai_next = ca;
/// return ca6;
/// ```
///
/// The IPv6 entry is prepended, so **`::1` is first and `127.0.0.1` is
/// second**, and if IPv6 synthesis fails only the IPv4 entry is returned.
/// This is not cosmetic: `conn/happy_eyeballs.rs`, superseding
/// `lib/cf-ip-happy.c`, races the families in list order, so reversing these
/// two would change which family a `localhost` connection prefers. Preserved
/// exactly.
///
/// Synthesis cannot fail here - C's only failure mode was `calloc` returning
/// NULL - so the IPv4-only outcome is unreachable and the return is a plain
/// [`Vec`] rather than a [`Result`]. That is recorded rather than silently
/// simplified, because a reader comparing against the C will look for the
/// missing branch.
///
/// Which names trigger this is `Curl_resolv`'s decision and therefore
/// `resolver.rs`'s: C matches `"localhost"`, `"localhost."`, any
/// `*.localhost` and any `*.localhost.`, all case-insensitively
/// (`lib/hostip.c:938-944`). The synthesis lives here because the addresses
/// do.
// No consumer yet; resolver.rs decides which names trigger it.
#[allow(dead_code)]
pub(crate) fn localhost_addrs(port: u16, name: &str) -> Vec<ResolvedAddr> {
    let canonname = Some(name.to_owned());
    vec![
        // `get_localhost6`: `::1`, FIRST.
        ResolvedAddr::tcp(
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port),
            canonname.clone(),
        ),
        // `get_localhost`: `127.0.0.1`, SECOND.
        ResolvedAddr::tcp(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            canonname,
        ),
    ]
}

/// Whether this host has a usable IPv6 stack.
///
/// The seam behind `Curl_probeipv6` (`lib/hostip.c:752-766`), which opens a
/// `PF_INET6` / `SOCK_DGRAM` socket and closes it again:
///
/// ```c
/// curl_socket_t s = CURL_SOCKET(PF_INET6, SOCK_DGRAM, 0);
/// multi->ipv6_works = FALSE;
/// if(s == CURL_SOCKET_BAD) {
///   if(SOCKERRNO == SOCKENOMEM)
///     return CURLE_OUT_OF_MEMORY;
/// }
/// else {
///   multi->ipv6_works = TRUE;
///   sclose(s);
/// }
/// return CURLE_OK;
/// ```
///
/// It is a trait rather than a free function for two reasons that AAP 0.3.3
/// P12 makes non-negotiable. A unit test must be able to state that IPv6 does
/// not work without disabling it on the host, which is what
/// [`DnsCache::fetch_addr`]'s family filtering and
/// [`can_resolve_ip_version`] need in order to be tested at all. And Miri
/// cannot perform a real syscall, so a test of anything above this line would
/// otherwise have to be excluded from the Miri gate - the seam is what keeps
/// it in.
#[allow(dead_code)] // No consumer yet; resolver.rs consumes it.
pub(crate) trait Ipv6Probe: fmt::Debug {
    /// True when a `PF_INET6` datagram socket could be created.
    ///
    /// # Errors
    ///
    /// [`CURLcode::OutOfMemory`], and only that, mirroring the one error C
    /// distinguishes: every other `socket(2)` failure means IPv6 is
    /// unavailable rather than that something went wrong.
    fn probe(&self) -> CodeResult<bool>;
}

/// The production [`Ipv6Probe`]: it really opens a socket.
///
/// Uses `socket2`, which is what AAP 0.8.5 conflict C3 prescribes so that no
/// `unsafe` block and no `libc` name is needed for a socket option or a
/// socket creation. `Domain::IPV6` and `Type::DGRAM` are the crate's spellings
/// of `PF_INET6` and `SOCK_DGRAM`, and the socket closes when the value is
/// dropped, which is `sclose(s)`.
///
/// C passes `0` as the protocol, meaning "the default for this type"; that is
/// `socket2`'s `None`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)] // No consumer yet; multi/ wires it in at handle init.
pub(crate) struct SocketIpv6Probe;

impl Ipv6Probe for SocketIpv6Probe {
    fn probe(&self) -> CodeResult<bool> {
        use socket2::{Domain, Socket, Type};

        match Socket::new(Domain::IPV6, Type::DGRAM, None) {
            // `multi->ipv6_works = TRUE; sclose(s);` -- the drop closes it.
            Ok(_socket) => Ok(true),
            Err(error) => {
                // `if(SOCKERRNO == SOCKENOMEM) return CURLE_OUT_OF_MEMORY;`
                // ENOMEM is 12 on both Linux and Apple platforms; the raw
                // value is compared rather than a `libc` constant named,
                // because `libc` is confined to `crate::ffi`. ENOBUFS is
                // treated the same way: C's `SOCKENOMEM` expands to ENOMEM,
                // and ENOBUFS is the allocation failure the BSD-derived
                // stacks report instead, so neither is evidence that IPv6 is
                // absent.
                const ENOMEM: i32 = 12;
                const ENOBUFS_LINUX: i32 = 105;
                const ENOBUFS_APPLE: i32 = 55;
                let errno = error.raw_os_error().unwrap_or(0);
                if errno == ENOMEM
                    || (cfg!(target_os = "linux") && errno == ENOBUFS_LINUX)
                    || (cfg!(any(target_os = "macos", target_os = "ios"))
                        && errno == ENOBUFS_APPLE)
                {
                    return Err(CURLcode::OutOfMemory);
                }
                // Every other failure means the stack is not there.
                Ok(false)
            }
        }
    }
}

/// An [`Ipv6Probe`] with a fixed answer.
///
/// Not test-only: `resolver.rs` needs a way to honour a build or a
/// configuration that has already established the answer, and a caller that
/// knows IPv6 is absent should be able to say so without a syscall. It is
/// also what makes every test above this line runnable under Miri.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
// No consumer yet; resolver.rs and the tests below wire it in.
#[allow(dead_code)]
pub(crate) struct FixedIpv6Probe(pub(crate) CodeResult<bool>);

impl Ipv6Probe for FixedIpv6Probe {
    fn probe(&self) -> CodeResult<bool> {
        self.0
    }
}

/// The memoised result of the IPv6 probe.
///
/// C keeps it in `multi->ipv6_works` and probes once, for the reason its own
/// comment gives at `lib/hostip.c:749-751`: *"the nature of most systems is
/// that IPv6 status does not come and go during a program's lifetime so we
/// only probe the first time and then we have the info kept for fast
/// reuse."* `Curl_ipv6works` (`:771-776`) is then a plain field read.
///
/// The memoisation is an [`OnceLock`] **owned by the handle that owns this
/// value**, never a process-global. That distinction is the one
/// `crate::util::timeval` draws for its own baseline: written once and never
/// again is immutable shared state, which is not what AAP 0.3.3 P12
/// prohibits. A `static mut`, a `lazy_static`-style singleton or anything a
/// second handle could observe would be.
#[derive(Debug, Default)]
#[allow(dead_code)] // No consumer yet; multi/ owns one per handle.
pub(crate) struct Ipv6Support {
    works: OnceLock<bool>,
}

impl Ipv6Support {
    /// An unprobed instance.
    #[allow(dead_code)] // No consumer yet; The owning handle constructs it.
    pub(crate) fn new() -> Self {
        Self {
            works: OnceLock::new(),
        }
    }

    /// One with the answer already known, probing never.
    // No consumer yet; resolver.rs and the tests construct it.
    #[allow(dead_code)]
    pub(crate) fn known(works: bool) -> Self {
        let cell = OnceLock::new();
        // The cell is fresh, so this cannot fail; the result is discarded
        // rather than unwrapped because a panic here would be unreachable
        // and `unwrap` is not permitted on any path.
        let _ = cell.set(works);
        Self { works: cell }
    }

    /// The answer, probing at most once.
    ///
    /// Supersedes `Curl_ipv6works` (`lib/hostip.c:771-776`) over
    /// `Curl_probeipv6` (`:752-766`).
    ///
    /// # Errors
    ///
    /// Whatever the probe reports. Note that C sets `multi->ipv6_works =
    /// FALSE` *before* testing the socket and returns the error without
    /// clearing that assignment, so a failed probe leaves the handle
    /// believing IPv6 is unavailable. That is reproduced: the memoised value
    /// becomes `false` and the error still propagates, so a caller that
    /// ignores the code sees the same state C would have left behind.
    #[allow(dead_code)] // No consumer yet; Read by can_resolve_ip_version.
    pub(crate) fn works(&self, probe: &dyn Ipv6Probe) -> CodeResult<bool> {
        if let Some(known) = self.works.get() {
            return Ok(*known);
        }
        match probe.probe() {
            Ok(works) => {
                let _ = self.works.set(works);
                Ok(works)
            }
            Err(code) => {
                // C's `multi->ipv6_works = FALSE;` precedes the early return.
                let _ = self.works.set(false);
                Err(code)
            }
        }
    }

    /// The memoised answer without probing, when one has been taken.
    // No consumer yet; resolver.rs reads it without probing.
    #[allow(dead_code)]
    pub(crate) fn cached(&self) -> Option<bool> {
        self.works.get().copied()
    }
}

/// Whether `ip_version` can be satisfied on this host.
///
/// Supersedes `can_resolve_ip_version` (`lib/hostip.c:807-820`), which under
/// `CURLRES_IPV6` is one test:
///
/// ```c
/// if(ip_version == CURL_IPRESOLVE_V6 && !Curl_ipv6works(data))
///   return FALSE;
/// ```
///
/// C's `#elif defined(CURLRES_IPV4)` arm - where any `CURL_IPRESOLVE_V6`
/// request fails outright - has no counterpart, because every mandated target
/// has IPv6 and the build is never IPv4-only. Requesting
/// [`IpVersion::V4`] or [`IpVersion::Whatever`] always proceeds.
///
/// The caller turns `false` into [`CURLcode::CouldntResolveHost`], which is
/// what `Curl_resolv` does at `lib/hostip.c:951-955`; that lives in
/// `resolver.rs` so that the diagnostic accompanies it.
///
/// # Errors
///
/// Whatever [`Ipv6Support::works`] reports.
#[allow(dead_code)] // No consumer yet; resolver.rs gates its lookup on it.
pub(crate) fn can_resolve_ip_version(
    ip_version: IpVersion,
    support: &Ipv6Support,
    probe: &dyn Ipv6Probe,
) -> CodeResult<bool> {
    if ip_version == IpVersion::V6 {
        return support.works(probe);
    }
    Ok(true)
}

/// Shuffles an address list in place, Fisher-Yates.
///
/// Supersedes `Curl_shuffle_addr` (`lib/hostip.c:492-557`), which
/// `CURLOPT_DNS_SHUFFLE_ADDRESSES` enables and which C annotates
/// `@unittest: 1608` - so AAP 0.8.7 relocates that unit test into this file.
///
/// The algorithm is reproduced exactly, including its direction and its
/// modulus (`:533-537`):
///
/// ```c
/// for(i = num_addrs - 1; i > 0; i--) {
///   swap_tmp = nodes[rnd[i] % (unsigned int)(i + 1)];
///   nodes[rnd[i] % (unsigned int)(i + 1)] = nodes[i];
///   nodes[i] = swap_tmp;
/// }
/// ```
///
/// Four details are measured rather than assumed, and each is asserted by a
/// test below:
///
/// * **It runs only for more than one address** - `if(num_addrs > 1)` at
///   `:503`. A single-element list is untouched and, critically, emits no
///   message.
/// * **The entropy is exactly one `unsigned int` per address**, from
///   `rnd_size = num_addrs * sizeof(*rnd)` at `:522`, and the loop indexes
///   `rnd[i]` - so element zero of the array is drawn and never read. The
///   draw size is part of the behaviour: a shorter draw would consume a
///   different prefix of the stream.
/// * **The words are little-endian.** C reads them as `unsigned int` through
///   a buffer the RNG filled with bytes, so the interpretation is the host's.
///   All four mandated targets are little-endian
///   (`x86_64`/`aarch64` on Linux and Apple), so [`u32::from_le_bytes`] is
///   the faithful reading and the one that reproduces C's permutation.
/// * **A failed draw leaves the list untouched.** C returns
///   `CURLE_OUT_OF_MEMORY` when either allocation fails, having relinked
///   nothing, and skips the shuffle entirely when `Curl_rand` fails
///   (`:531`). Here the draw happens before any swap, so an error propagates
///   with the order intact. The allocation failures themselves have no
///   counterpart.
///
/// The entropy source is **injected**, per AAP 0.3.3 P12: a closure filling a
/// caller-supplied buffer, which is C's `Curl_rand(data, buf, len)` with the
/// handle replaced by whatever the closure captured. It is deliberately not a
/// new trait - `crate::crypto::rand` already owns the crate's random-number
/// seam, and a second abstraction here would fragment it - and deliberately
/// not an import of that module, so that this file names no subsystem it does
/// not depend on.
///
/// # Errors
///
/// Whatever the entropy source reports.
#[allow(dead_code)] // No consumer yet; DnsCache::mk_entry consumes it.
pub(crate) fn shuffle_addrs(
    addrs: &mut [ResolvedAddr],
    entropy: &mut dyn FnMut(&mut [u8]) -> CodeResult<()>,
    tracer: &mut Tracer<'_>,
) -> CodeResult<()> {
    // `const int num_addrs = num_addresses(*addr);` then `if(num_addrs > 1)`.
    let num_addrs = addrs.len();
    if num_addrs <= 1 {
        return Ok(());
    }

    infof!(tracer, "{}", msg::shuffling(num_addrs));

    // `rnd_size = num_addrs * sizeof(*rnd)` -- four bytes per address. The
    // multiplication is checked rather than assumed: an overflow is where C's
    // `curlx_malloc(rnd_size)` would have returned NULL, and its answer to
    // that is `CURLE_OUT_OF_MEMORY` with the list left unshuffled. It is
    // unreachable in practice -- a `ResolvedAddr` is far larger than four
    // bytes, so a list long enough to overflow could not have been allocated
    // -- but no path in this crate may panic on data, so it is a `Result`
    // rather than an argument.
    let word_size = core::mem::size_of::<u32>();
    let Some(rnd_size) = num_addrs.checked_mul(word_size) else {
        return Err(CURLcode::OutOfMemory);
    };
    let mut bytes = vec![0u8; rnd_size];
    entropy(&mut bytes)?;

    // `for(i = num_addrs - 1; i > 0; i--)`, descending, with
    // `j = rnd[i] % (i + 1)`.
    for i in (1..num_addrs).rev() {
        // Read `rnd[i]` without an index expression, so that being in bounds
        // is a property of the code rather than of a comment. Both `get` and
        // the array conversion succeed for every `i < num_addrs`, because the
        // buffer is exactly `num_addrs * 4` bytes long.
        let Some(slice) = bytes.get(i * word_size..(i + 1) * word_size) else {
            break;
        };
        let Ok(word_bytes) = <[u8; 4]>::try_from(slice) else {
            break;
        };
        let word = u32::from_le_bytes(word_bytes);

        // `i + 1` is at most `num_addrs`, which fits a `u32` for any list a
        // resolver can return, and the modulus is taken in C's width so the
        // permutation matches bit for bit. Were the count somehow to exceed
        // `u32::MAX`, the saturated modulus still yields a `j` below `i`, so
        // the swap stays in bounds.
        let modulus = u32::try_from(i + 1).unwrap_or(u32::MAX);
        let j = (word % modulus) as usize;
        addrs.swap(i, j);
    }

    Ok(())
}

/// Reports a resolved host and its addresses under `--verbose`.
///
/// Supersedes `show_resolve_info` (`lib/hostip.c:118-179`). Five properties
/// are measured and reproduced:
///
/// * **The gate is three conditions** (`:130-134`): verbose must be on, the
///   hostname must be non-empty, and the hostname must not itself be a
///   numeric address. C's comment is *"ignore no name or numerical IP
///   addresses"* - printing `Host 1.2.3.4:80 was resolved. IPv4: 1.2.3.4`
///   would be noise. The verbose test is [`Tracer::is_verbose`], which
///   `infof` would apply anyway; it is tested here as well so the
///   accumulators are not built for nothing, exactly as C returns early.
/// * **The accumulator index is `(a->ai_family != PF_INET)`** (`:150`), so
///   **slot 0 is IPv4 and slot 1 is IPv6**, and any other family is skipped
///   by the enclosing `if` (`:146-149`) rather than mis-filed. An `AF_UNIX`
///   entry therefore contributes to neither line.
/// * **The separator is `", "`** - a comma AND a space,
///   `curlx_dyn_addn(d, ", ", 2)` at `:151-152`.
/// * **Each accumulator has a 1024-byte budget** (`:143-146`), and exceeding
///   it produces [`msg::TOO_MANY_IP`] and **abandons both lines** - C's
///   `goto fail` skips the two `infof` calls entirely.
/// * **The IPv6 line is emitted FIRST** (`:166-172`), then the IPv4 line,
///   each rendering [`msg::NONE`] when its accumulator is empty. The order is
///   the reverse of the slot order, which is exactly the sort of detail a
///   reimplementation gets wrong.
///
/// The `"was resolved."` line carries a trailing period and substitutes
/// [`msg::NONE`] for an empty name (`:138-139`) - unreachable behind the
/// gate above, and reproduced anyway because the gate and the substitution
/// are two separate statements in the C and a future edit to one should not
/// silently change the other.
// No consumer yet; resolver.rs calls it once a lookup lands.
#[allow(dead_code)]
pub(crate) fn show_resolve_info(entry: &DnsEntry, tracer: &mut Tracer<'_>) {
    // `if(!data->set.verbose || !dns->hostname[0] ||
    //     Curl_host_is_ipnum(dns->hostname)) return;`
    if !tracer.is_verbose()
        || entry.hostname.is_empty()
        || host_is_ipnum(entry.hostname.as_bytes())
    {
        return;
    }

    let name = if entry.hostname.is_empty() {
        msg::NONE
    } else {
        entry.hostname.as_str()
    };
    infof!(tracer, "{}", msg::host_was_resolved(name, entry.hostport));

    // `struct dynbuf out[2]`, each `curlx_dyn_init(&out[i], 1024)`. Index 0
    // is IPv4 and index 1 is IPv6, from `(a->ai_family != PF_INET)`.
    //
    // The 1024 is a CEILING, not a capacity: `curlx_dyn_init`'s second
    // parameter is `toobig`, and crossing it is what produces the message
    // below. Building these with the crate's own `DynBuf` rather than a bare
    // `String` is what keeps the accounting identical, terminator byte
    // included -- C's ceiling test is `fit > s->toobig` (`dynbuf.c:82`)
    // where `fit = len + idx + 1`, glossed in the source itself as
    // "new string + old string + zero byte" (`lib/curlx/dynbuf.c:72`).
    let mut lists = [
        DynBuf::new(SHOW_RESOLVE_BUDGET),
        DynBuf::new(SHOW_RESOLVE_BUDGET),
    ];

    for addr in &entry.addrs {
        let slot = match addr.family() {
            AddressFamily::Inet => 0usize,
            AddressFamily::Inet6 => 1usize,
            // Neither arm of C's `if`, so it contributes to no line.
            AddressFamily::Unix => continue,
        };
        let text = addr.printable_address();
        let list = &mut lists[slot];

        // `if(curlx_dyn_len(d)) result = curlx_dyn_addn(d, ", ", 2);`
        // `if(!result) result = curlx_dyn_add(d, buf);`
        let mut result = Ok(());
        if !list.is_empty() {
            result = list.addn(msg::ADDR_SEPARATOR.as_bytes());
        }
        if result.is_ok() {
            result = list.add(&text);
        }
        if result.is_err() {
            // C's `dynbuf` refuses the write, and `show_resolve_info` reports
            // this and jumps past BOTH lines.
            infof!(tracer, "{}", msg::TOO_MANY_IP);
            return;
        }
    }

    // The IPv6 line FIRST, then the IPv4 line.
    infof!(tracer, "{}", msg::ipv6_line(&rendered_list(&lists[1])));
    infof!(tracer, "{}", msg::ipv4_line(&rendered_list(&lists[0])));
}

/// One accumulated address list as text, or `"(none)"` when it is empty.
///
/// C's `(curlx_dyn_len(&out[i]) ? curlx_dyn_ptr(&out[i]) : "(none)")`
/// (`lib/hostip.c:168`, `:172`). The bytes are always ASCII - they came from
/// [`crate::util::inet`]'s converters and from `", "` - so the UTF-8 check
/// cannot fail; it is written as a fallible conversion with a fall-back rather
/// than an assertion because no path in this crate may panic on data.
#[allow(dead_code)] // No consumer yet; read by show_resolve_info.
fn rendered_list(list: &DynBuf) -> String {
    if list.is_empty() {
        return msg::NONE.to_owned();
    }
    core::str::from_utf8(list.as_slice())
        .unwrap_or(msg::NONE)
        .to_owned()
}

/// Which endpoint a resolution failure names.
///
/// C's `const char *host_or_proxy` and the `CURLcode` beside it
/// (`lib/hostip.c:1572-1584`). The two always travel together - the literal
/// `"host"` accompanies `CURLE_COULDNT_RESOLVE_HOST` and `"proxy"`
/// accompanies `CURLE_COULDNT_RESOLVE_PROXY` - so pairing them in one type
/// removes the possibility of reporting one with the other's code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)] // No consumer yet; resolver.rs consumes it.
pub(crate) enum ResolveTarget {
    /// C's `"host"` with `CURLE_COULDNT_RESOLVE_HOST`.
    Host,
    /// C's `"proxy"` with `CURLE_COULDNT_RESOLVE_PROXY`, selected by
    /// `if(conn->bits.proxy)`.
    Proxy,
}

impl ResolveTarget {
    /// The literal C interpolates as the first `%s`.
    #[allow(dead_code)] // No consumer yet; Read by resolver_error_message.
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Proxy => "proxy",
        }
    }

    /// The code C returns alongside it.
    #[allow(dead_code)] // No consumer yet; resolver.rs returns it.
    pub(crate) const fn code(self) -> CURLcode {
        match self {
            Self::Host => CURLcode::CouldntResolveHost,
            Self::Proxy => CURLcode::CouldntResolveProxy,
        }
    }
}

/// Formats the failure text of `Curl_resolver_error`.
///
/// Supersedes the `failf` of `Curl_resolver_error`
/// (`lib/hostip.c:1586-1587`):
///
/// ```c
/// failf(data, "Could not resolve %s: %s%s%s%s", host_or_proxy, name,
///       detail ? " (" : "", detail ? detail : "", detail ? ")" : "");
/// ```
///
/// Five conversions for two pieces of information, because C has no way to
/// make a parenthesised clause optional other than by emitting its three
/// parts conditionally. With a detail the result is
/// `Could not resolve host: example.com (some detail)`; without one it is
/// `Could not resolve host: example.com`, with no trailing space and no empty
/// parentheses.
///
/// The emission belongs to `resolver.rs`, which owns the failure paths and
/// the `CURLOPT_ERRORBUFFER` interaction; the formatting lives here so that
/// the conditional parenthesisation exists once. [`ResolveTarget::code`]
/// supplies the code that accompanies it.
#[allow(dead_code)] // No consumer yet; resolver.rs emits it.
pub(crate) fn resolver_error_message(
    target: ResolveTarget,
    name: &str,
    detail: Option<&str>,
) -> String {
    let label = target.label();
    match detail {
        Some(detail) => {
            format!("Could not resolve {label}: {name} ({detail})")
        }
        None => format!("Could not resolve {label}: {name}"),
    }
}

/// Pre-seeds the cache from `CURLOPT_RESOLVE`.
///
/// Supersedes `Curl_loadhostpairs` (`lib/hostip.c:1279-1470`). **This syntax
/// is frozen.** AAP 0.8.1 places CLI flag semantics outside this migration's
/// authority, and `--resolve` maps straight onto this option, so no prefix may
/// be added, no bound relaxed and no silent skip turned into an error.
///
/// # The grammar, as measured
///
/// ```text
///     entry := delete | add
///    delete := '-' host ':' port
///       add := [ '+' ] host ':' port ':' address { ',' address }
///      host := '[' <up to 46 bytes> ']' | <up to 4096 bytes>
///   address := '[' <up to 46 bytes> ']' | <up to 4096 bytes>
/// ```
///
/// with a port bounded by [`RESOLVE_PORT_MAX`] and each address literal
/// bounded by [`RESOLVE_ADDRESS_MAX`] - 64 bytes, C's `char address[64]`,
/// where **64 or more is an error and 63 is the longest accepted**.
///
/// # The four behaviours a reimplementation gets wrong
///
/// * **A malformed DELETE entry is skipped in complete silence.** Every
///   failure in that branch is a bare `continue` (`lib/hostip.c:1303`,
///   `:1308`, and the implicit skip when `curlx_str_number` fails at
///   `:1315`) - no message, no error, no diagnostic of any kind. A malformed
///   ADD entry, by contrast, is fatal. Reproduced exactly.
/// * **The default is PERMANENT.** `bool permanent = TRUE;` at `:1331`, and
///   only a leading `'+'` clears it (`:1335-1338`). A permanent entry carries
///   the all-zero timestamp and never goes stale, so `--resolve` without `+`
///   outlives any `CURLOPT_DNS_CACHE_TIMEOUT`.
/// * **An existing entry is deleted before the new one is added**, with
///   [`msg::resolve_replaced`] first (`:1427-1442`). C documents four reasons,
///   which are carried in the code below because they explain why replacing
///   rather than updating is correct.
/// * **The error code is [`CURLcode::SetoptOptionSyntax`]**, not
///   `CURLE_BAD_FUNCTION_ARGUMENT` (`:1414`).
///
/// # Two branches of the C that are deliberately absent
///
/// C guards an IPv6 literal with `#ifndef USE_IPV6` and, in an IPv4-only
/// build, reports `"Ignoring resolve address '%.*s', missing IPv6 support."`
/// and skips it (`:1370-1378`). Every target in AAP 0.1.1 G8 has IPv6, so
/// that branch is unreachable and is not implemented; the omission is
/// recorded here rather than left for a reader to wonder about. Likewise
/// C's `if(!dnscache) return CURLE_FAILED_INIT;` (`:1285-1286`) has no
/// counterpart, because the cache is the receiver - the caller that selects
/// between the share's cache and the multi's is the one that discovers the
/// absence and returns that code.
///
/// # Reference counting
///
/// C creates each entry with a reference and then immediately drops it,
/// commenting *"release the returned reference; the cache itself will keep the
/// entry alive"* (`:1447-1450`). Here the handle [`DnsCache::add`] returns is
/// simply not bound, which is the same thing.
///
/// # Errors
///
/// [`CURLcode::SetoptOptionSyntax`] for a malformed ADD entry, after
/// [`msg::resolve_unparsable`] has been reported through
/// [`crate::trace::failf`] - which is where C reports it too
/// (`lib/hostip.c:1412`), and which is what also places the text in the
/// caller's `CURLOPT_ERRORBUFFER`. [`CURLcode::OutOfMemory`] cannot arise
/// here in practice: it is C's response to a failed allocation, and the only
/// fallible step this path has is the address shuffle, which pre-seeding does
/// not perform.
#[allow(dead_code)] // No consumer yet; easy/ calls it before a transfer starts.
pub(crate) fn load_host_pairs<'a, I>(
    cache: &mut DnsCache,
    entries: I,
    clock: &dyn Clock,
    tracer: &mut Tracer<'_>,
) -> CodeResult<()>
where
    I: IntoIterator<Item = &'a str>,
{
    // `data->state.wildcard_resolve = FALSE;` -- "Default is no wildcard
    // found", reset on every load rather than accumulated.
    cache.wildcard_resolve = false;

    for entry in entries {
        let bytes = entry.as_bytes();
        // `if(!host) continue;` -- C's guard against a NULL slist item. An
        // empty string is the closest Rust equivalent and is skipped for the
        // same reason: there is nothing to parse.
        if bytes.is_empty() {
            continue;
        }

        if bytes[0] == b'-' {
            delete_host_pair(cache, &bytes[1..]);
        } else {
            add_host_pair(cache, entry, clock, tracer)?;
        }
    }

    Ok(())
}

/// Handles a `-host:port` entry: remove it, silently on any failure.
///
/// `lib/hostip.c:1296-1323`. The bracketed form exists so that an IPv6
/// literal, which contains colons, can be named unambiguously.
#[allow(dead_code)] // No consumer yet; Read by load_host_pairs.
fn delete_host_pair(cache: &mut DnsCache, rest: &[u8]) {
    let mut cursor = rest;

    // `if(!curlx_str_single(&host, '['))` -- str_single returns zero on a
    // MATCH, so the negation selects the BRACKETED branch.
    let host = if str_single(&mut cursor, b'[').is_ok() {
        // `str_until(&host, &source, MAX_IPADR_LEN, ']') ||
        //  str_single(&host, ']') || str_single(&host, ':')` -> continue
        let Ok(host) = str_until(&mut cursor, MAX_IPADR_LEN, b']') else {
            return;
        };
        if str_single(&mut cursor, b']').is_err()
            || str_single(&mut cursor, b':').is_err()
        {
            return;
        }
        host
    } else {
        // `str_until(&host, &source, 4096, ':') || str_single(&host, ':')`
        let Ok(host) = str_until(&mut cursor, RESOLVE_HOST_MAX, b':') else {
            return;
        };
        if str_single(&mut cursor, b':').is_err() {
            return;
        }
        host
    };

    // `if(!curlx_str_number(&host, &num, 0xffff))` -- zero means success, so
    // a port that will not parse means the entry is skipped in silence.
    let Ok(port) = str_number(&mut cursor, RESOLVE_PORT_MAX) else {
        return;
    };
    let Ok(port) = u16::try_from(port) else {
        return;
    };

    // "delete entry, ignore if it did not exist"
    cache.remove(&create_dnscache_id(host, port));
}

/// Handles a `[+]host:port:addr[,addr...]` entry.
///
/// `lib/hostip.c:1324-1467`. Every parse failure past the host reaches C's
/// `err:` label, which reports [`msg::resolve_unparsable`] and returns
/// [`CURLcode::SetoptOptionSyntax`]; the two failures *at* the host are bare
/// `continue`s, like the delete branch, and are reproduced as such.
#[allow(dead_code)] // No consumer yet; Read by load_host_pairs.
fn add_host_pair(
    cache: &mut DnsCache,
    entry: &str,
    clock: &dyn Clock,
    tracer: &mut Tracer<'_>,
) -> CodeResult<()> {
    let mut cursor = entry.as_bytes();

    // `if(*host == '+') { host++; permanent = FALSE; }` -- the default is
    // TRUE, so an entry with no prefix never goes stale.
    let permanent = str_single(&mut cursor, b'+').is_err();

    // The host, bracketed or not. Both failures here are `continue`, not
    // `goto err` -- measured at `:1350` and `:1355`.
    let host = if str_single(&mut cursor, b'[').is_ok() {
        let Ok(host) = str_until(&mut cursor, MAX_IPADR_LEN, b']') else {
            return Ok(());
        };
        if str_single(&mut cursor, b']').is_err() {
            return Ok(());
        }
        host
    } else {
        let Ok(host) = str_until(&mut cursor, RESOLVE_HOST_MAX, b':') else {
            return Ok(());
        };
        host
    };

    // `if(curlx_str_single(&host, ':') ||
    //     curlx_str_number(&host, &port, 0xffff) ||
    //     curlx_str_single(&host, ':')) goto err;`
    if str_single(&mut cursor, b':').is_err() {
        return unparsable_entry(entry, tracer);
    }
    let Some(port) = str_number(&mut cursor, RESOLVE_PORT_MAX)
        .ok()
        .and_then(|value| u16::try_from(value).ok())
    else {
        return unparsable_entry(entry, tracer);
    };
    if str_single(&mut cursor, b':').is_err() {
        return unparsable_entry(entry, tracer);
    }

    // `VERBOSE(addresses = host);` -- the whole remaining text, captured
    // BEFORE the address loop consumes it, because the success message
    // echoes it verbatim.
    let addresses = core::str::from_utf8(cursor).unwrap_or("");

    let Ok(addrs) = parse_resolve_addresses(&mut cursor, port, tracer) else {
        return unparsable_entry(entry, tracer);
    };

    // `if(!head) goto err;` -- an entry naming a port but no address is
    // malformed even though every individual address parsed.
    if addrs.is_empty() {
        return unparsable_entry(entry, tracer);
    }

    let host_text = core::str::from_utf8(host).unwrap_or("");
    let key = create_dnscache_id(host, port);

    // `if(dns) { infof(...); Curl_hash_delete(...); }` -- C documents four
    // reasons for replacing rather than reusing:
    //   1. the old entry may have different addresses;
    //   2. even a correct entry may be close to expiring, and would then be
    //      pruned before the next request;
    //   3. a non-permanent entry must be able to displace a permanent one;
    //   4. a non-permanent entry must get a timeout that starts NOW.
    if cache.entries.get(&key).is_some() {
        infof!(tracer, "{}", msg::resolve_replaced(host_text, port));
        cache.remove(&key);
    }

    // `dnscache_add_addr(...)` then `dns->refcount--` -- the returned
    // reference is released because the cache keeps the entry alive, which is
    // what not binding the handle does. No shuffle here: C's
    // `dnscache_add_addr` passes through `Curl_dnscache_mk_entry`, which
    // shuffles only when `data->set.dns_shuffle_addresses` is set, and a
    // pre-seeded entry is one the user listed in the order they meant.
    let _ = cache
        .add_addrs(host_text, port, addrs, permanent, clock, None, tracer)?;

    infof!(
        tracer,
        "{}",
        msg::resolve_added(host_text, port, addresses, permanent)
    );

    // `if(curlx_str_casecompare(&source, "*"))` -- case-insensitive, which
    // costs nothing for a one-byte token and is what the C does.
    if str_casecompare(host, WILDCARD_HOST) {
        infof!(tracer, "{}", msg::resolve_wildcard(port));
        cache.wildcard_resolve = true;
    }

    Ok(())
}

/// C's `err:` label: report the entry and fail with the frozen code.
///
/// `lib/hostip.c:1410-1416`:
///
/// ```c
/// if(error) {
///   failf(data, "Could not parse CURLOPT_RESOLVE entry '%s'", hostp->data);
///   Curl_freeaddrinfo(head);
///   return CURLE_SETOPT_OPTION_SYNTAX;
/// }
/// ```
///
/// `Curl_freeaddrinfo(head)` has no counterpart: the partially built list is
/// an owned [`Vec`] that is dropped on the way out, so the leak this line
/// exists to prevent cannot occur.
///
/// The return type is the caller's so that every failure site reads
/// `return unparsable_entry(entry, tracer);` - one statement, with the
/// message and the code inseparable. **The code is
/// [`CURLcode::SetoptOptionSyntax`] and not
/// [`CURLcode::BadFunctionArgument`]**; the two are easy to confuse and the C
/// is unambiguous.
///
/// # Errors
///
/// Always [`CURLcode::SetoptOptionSyntax`].
#[allow(dead_code)] // No consumer yet; Read by add_host_pair.
fn unparsable_entry(entry: &str, tracer: &mut Tracer<'_>) -> CodeResult<()> {
    failf!(tracer, "{}", msg::resolve_unparsable(entry));
    Err(CURLcode::SetoptOptionSyntax)
}

/// Parses the comma-separated address list of an ADD entry.
///
/// `lib/hostip.c:1358-1404`. Three measured details:
///
/// * An address may be bracketed, in which case it is bounded by
///   [`MAX_IPADR_LEN`] and a missing `']'` is fatal.
/// * An unbracketed address that yields nothing before a comma is **skipped
///   rather than rejected**, but only when a comma really follows - C's
///   comment is *"survive nothing but just a comma"* (`:1365-1368`). So
///   `1.2.3.4,,5.6.7.8` is accepted and the empty element vanishes.
/// * The loop ends at the first byte that is not a comma
///   (`if(curlx_str_single(&host, ',')) break;`), so trailing junk after the
///   last address is silently ignored rather than reported. Preserved.
///
/// # Errors
///
/// `Err(())` for anything C reaches `goto err` from; the caller turns that
/// into [`CURLcode::SetoptOptionSyntax`] with its message. The unit error is
/// deliberate: there is exactly one failure outcome and inventing a richer
/// one here would imply a distinction the frozen syntax does not make.
#[allow(dead_code)] // No consumer yet; Read by add_host_pair.
fn parse_resolve_addresses(
    cursor: &mut &[u8],
    port: u16,
    tracer: &mut Tracer<'_>,
) -> Result<Vec<ResolvedAddr>, ()> {
    let mut addrs: Vec<ResolvedAddr> = Vec::new();

    // `while(*host)`
    while !cursor.is_empty() {
        let target = if str_single(cursor, b'[').is_ok() {
            // `str_until(&host, &target, MAX_IPADR_LEN, ']') ||
            //  str_single(&host, ']')` -> goto err
            let target =
                str_until(cursor, MAX_IPADR_LEN, b']').map_err(|_| ())?;
            str_single(cursor, b']').map_err(|_| ())?;
            target
        } else {
            match str_until(cursor, RESOLVE_HOST_MAX, b',') {
                Ok(target) => target,
                Err(_) => {
                    // "survive nothing but just a comma"
                    str_single(cursor, b',').map_err(|_| ())?;
                    continue;
                }
            }
        };

        // `if(curlx_strlen(&target) >= sizeof(address)) goto err;` -- the
        // `char address[64]` bound, frozen.
        if target.len() >= RESOLVE_ADDRESS_MAX {
            return Err(());
        }

        match str2addr(target, port) {
            Ok(addr) => addrs.push(addr),
            Err(_) => {
                let text = core::str::from_utf8(target).unwrap_or("");
                infof!(tracer, "{}", msg::address_illegal(text));
                return Err(());
            }
        }

        // `if(curlx_str_single(&host, ',')) break;`
        if str_single(cursor, b',').is_err() {
            break;
        }
    }

    Ok(addrs)
}

/// The future a [`Resolver`] returns.
///
/// A boxed, pinned, `Send` future rather than `impl Future`, and the choice
/// is forced rather than stylistic. `&dyn Resolver` is required - every
/// consumer holds an injected resolver whose concrete type it must not know,
/// which is the whole point of the seam - and a trait with a
/// return-position `impl Trait` method is **not object-safe at any Rust
/// version**, so `dyn Resolver` would not exist. Return-position `impl
/// Trait` in traits did stabilise in exactly 1.75, the MSRV floor, so it was
/// available; it was rejected on object safety, and the choice was confirmed
/// by compiling this file with `cargo +1.75.0`.
///
/// `Send` is required because `resolver.rs` runs the blocking system resolver
/// through `tokio::task::spawn_blocking`, and because the multi handle drives
/// transfers on a multi-thread runtime (AAP 0.8.3).
#[allow(dead_code)] // No consumer yet; Named by both seams below.
pub(crate) type ResolveFuture<'a, T> =
    Pin<Box<dyn core::future::Future<Output = CodeResult<T>> + Send + 'a>>;

/// The name-resolution seam: one of the three injection points AAP 0.3.3 P12
/// names at the crate root.
///
/// Supersedes `Curl_resolv` (`lib/hostip.c:860-1012`) as a *contract*, and
/// with it all six entry points of `lib/asyn.h` -
/// `Curl_async_global_cleanup`, `Curl_async_get_impl`, `Curl_async_pollset`,
/// `Curl_async_is_resolved`, `Curl_async_await` and
/// `Curl_async_getaddrinfo`. Those six collapse into this one call because
/// `pollset`, `is_resolved` and `await` exist only so that C can surrender
/// file descriptors to an external poll loop and be re-entered; awaiting a
/// future subsumes all three, and dropping one subsumes
/// `Curl_async_shutdown`.
///
/// # Why this exists at all
///
/// AAP 0.8.4 requires at least 80% line coverage on
/// `curl-rs-lib/src/protocols/` and `curl-rs-lib/src/transfer/`. Neither is
/// reachable if a protocol test needs a live DNS server, so the resolver has
/// to be substitutable. That is the gate this trait serves, and it is why the
/// trait is the **only** path by which `crate::conn` may obtain an address:
/// a module that calls a system resolver directly makes itself untestable and
/// takes the coverage gate down with it.
///
/// # How `conn` is expected to consume it
///
/// `conn/happy_eyeballs.rs`, superseding `lib/cf-ip-happy.c`, races the two
/// address families against each other with `tokio::select!`, so it needs
/// them **separately and each in the resolver's own order**. Two shapes are
/// provided and both preserve intra-family order:
///
/// * **A family-scoped call.** Pass [`IpVersion::V4`] or [`IpVersion::V6`]
///   and the result contains only that family. This is the shape a race
///   wants: two calls, two futures, one `select!`.
/// * **A split of a combined answer.** Call with [`IpVersion::Whatever`] and
///   hand the result to [`split_families`], which partitions without
///   reordering within either family. This is the shape the cache wants,
///   because a cache entry holds one list for all families and
///   [`DnsEntry::has_family`] scans it.
///
/// The combined order itself is significant and must not be sorted: for a
/// loopback name it is the `::1`-then-`127.0.0.1` sequence
/// [`localhost_addrs`] fixes, and for a system answer it is whatever the
/// resolver returned, which encodes the host's own address-selection policy.
///
/// # What must NOT appear in an implementation
///
/// `lib/hostip.c:365-370`'s process-global `sigjmp_buf` behind a spinlock,
/// and the `SIGALRM` handler at `:1042-1052` that jumps into it - by curl's
/// own admission causing *"the remainder of the application to run within a
/// signal handler which is nonportable and could lead to problems."* None of
/// it survives. An implementation bounds the wait with
/// `tokio::time::timeout` and holds no global mutable state whatsoever.
// No consumer yet; resolver.rs implements it; conn/ consumes it.
#[allow(dead_code)]
pub(crate) trait Resolver: fmt::Debug + Send + Sync {
    /// Resolves `host` and `port` to addresses.
    ///
    /// `ip_version` restricts the families returned, and an implementation
    /// must check [`can_resolve_ip_version`] before attempting a
    /// [`IpVersion::V6`]-only lookup on a host without IPv6 - C's
    /// `can_resolve_ip_version` gate at `lib/hostip.c:807-820`, whose failure
    /// is [`CURLcode::CouldntResolveHost`].
    ///
    /// # Errors
    ///
    /// [`CURLcode::CouldntResolveHost`] or
    /// [`CURLcode::CouldntResolveProxy`] for a lookup that failed,
    /// [`CURLcode::OperationTimedout`] for one that ran out of time, and
    /// [`CURLcode::AbortedByCallback`] when a
    /// `CURLOPT_RESOLVER_START_FUNCTION` callback refused it
    /// (`lib/hostip.c:910-926`).
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        port: u16,
        ip_version: IpVersion,
    ) -> ResolveFuture<'a, Vec<ResolvedAddr>>;
}

/// One address list split by family, each half in its original order.
///
/// What `conn/happy_eyeballs.rs` races. C reaches the same information by
/// walking `ai_next` twice with a different `ai_family` test each time
/// (`lib/cf-ip-happy.c`), which is where the two "balls" of Happy Eyeballs
/// come from.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)] // No consumer yet; conn/happy_eyeballs.rs consumes it.
pub(crate) struct AddrFamilies {
    /// The `AF_INET6` addresses, in the order the resolver produced them.
    pub(crate) v6: Vec<ResolvedAddr>,
    /// The `AF_INET` addresses, in the order the resolver produced them.
    pub(crate) v4: Vec<ResolvedAddr>,
}

/// Splits an address list by family without reordering either half.
///
/// The field order of [`AddrFamilies`] deliberately puts `v6` first, matching
/// the order [`localhost_addrs`] fixes and the order `show_resolve_info`
/// prints; that is documentation, not behaviour, since the two lists are
/// named rather than positional. What *is* behaviour is that neither list is
/// sorted: a resolver's ordering within a family encodes the host's
/// address-selection policy, and a race that reordered it would connect to a
/// different address than curl does.
///
/// `AF_UNIX` addresses belong to neither list and are dropped, exactly as
/// `show_resolve_info` skips them: a Unix socket has no family to race.
#[allow(dead_code)] // No consumer yet; conn/happy_eyeballs.rs consumes it.
pub(crate) fn split_families(addrs: &[ResolvedAddr]) -> AddrFamilies {
    let mut split = AddrFamilies::default();
    for addr in addrs {
        match addr.family() {
            AddressFamily::Inet6 => split.v6.push(addr.clone()),
            AddressFamily::Inet => split.v4.push(addr.clone()),
            AddressFamily::Unix => {}
        }
    }
    split
}

/// The DNS-over-HTTPS transport seam.
///
/// `dns/doh.rs` must implement DoH *"via the crate's own HTTP client"*
/// (AAP 0.4.1) while never writing `use crate::protocols`: a
/// `dns -> protocols -> dns` import cycle is precisely what AAP 0.3.3 P12's
/// injection avoids, and the cycle is real rather than hypothetical, since a
/// DoH request is an HTTPS transfer whose own hostname has to be resolved.
///
/// The seam is deliberately narrow. `lib/doh.c` builds a DNS wire query,
/// POSTs it with `Content-Type: application/dns-message`, and parses the wire
/// response; only the middle step needs a protocol stack. So this trait
/// carries bytes and nothing else - no header map, no status code, no
/// redirect policy - which keeps every decision that is DNS's in `doh.rs` and
/// every decision that is HTTP's in the implementation the caller injects.
#[allow(dead_code)] // No consumer yet; doh.rs consumes it.
pub(crate) trait DohTransport: fmt::Debug + Send + Sync {
    /// POSTs a DNS wire query to a DoH endpoint and returns the response.
    ///
    /// `url` is `CURLOPT_DOH_URL`. `query` is a complete DNS message, and the
    /// return is a complete DNS response; neither is interpreted here.
    ///
    /// # Errors
    ///
    /// Whatever the transfer produced. `lib/doh.c` maps a failed DoH transfer
    /// to [`CURLcode::CouldntResolveHost`] rather than propagating the
    /// transfer's own code, because a caller asked to resolve a name and not
    /// to perform an HTTPS request; that mapping belongs to `doh.rs`, so
    /// implementations report the real code and let it decide.
    fn post<'a>(
        &'a self,
        url: &'a str,
        query: &'a [u8],
    ) -> ResolveFuture<'a, Vec<u8>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::{TraceConfig, TraceState, WriterSink};
    use crate::util::timeval::TestClock;
    use std::time::Duration;

    // AAP 0.8.7 relocates the coverage of `tests/unit` and `tests/libtest`
    // into the crate, because a Rust static library does not export
    // `pub(crate)` items and no quality of implementation makes those C
    // programs link. `Curl_shuffle_addr` carries `@unittest: 1608` in the C
    // (`lib/hostip.c:505`), so its unit test in particular is a relocation
    // rather than an addition.
    //
    // Every test here runs without a network and without a syscall, because
    // the resolver, the clock, the entropy source, the IPv6 probe and the
    // trace sink are all injected. That is what makes the suite runnable
    // under Miri, which cannot perform a real syscall. The three exceptions
    // are marked `#[cfg_attr(miri, ignore = ...)]` with their reason at the
    // point of use, and in each case the reason is cost or a deliberate real
    // syscall rather than a seam that should have existed.

    /// A tracer over a capture buffer, verbose, running `body`.
    ///
    /// The shape `crate::trace`'s own tests use: nothing global, nothing
    /// observed by another test.
    fn traced<F>(body: F) -> String
    where
        F: FnOnce(&mut Tracer<'_>),
    {
        let config = TraceConfig::new();
        let mut sink = WriterSink::new(Vec::<u8>::new());
        {
            let mut tracer = Tracer::new(&config, &mut sink)
                .with_state(TraceState::verbose());
            body(&mut tracer);
        }
        String::from_utf8(sink.into_inner())
            .unwrap_or_else(|_| String::from("<non-utf8>"))
    }

    /// A tracer that captures nothing, for the paths under test that emit.
    fn silent<F, T>(body: F) -> T
    where
        F: FnOnce(&mut Tracer<'_>) -> T,
    {
        let config = TraceConfig::new();
        let mut sink = WriterSink::new(Vec::<u8>::new());
        let mut tracer = Tracer::new(&config, &mut sink);
        body(&mut tracer)
    }

    /// A `127.0.0.x` TCP address, for populating entries cheaply.
    fn v4(last: u8, port: u16) -> ResolvedAddr {
        ResolvedAddr::tcp(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, last)), port),
            None,
        )
    }

    /// A `::1`-family TCP address.
    fn v6(last: u16, port: u16) -> ResolvedAddr {
        ResolvedAddr::tcp(
            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, last)),
                port,
            ),
            None,
        )
    }

    /// An entry stamped at `at`, holding `addrs`.
    fn entry_at(
        host: &str,
        port: u16,
        addrs: Vec<ResolvedAddr>,
        at: CurlTime,
    ) -> DnsEntry {
        DnsEntry {
            addrs,
            timestamp: at,
            hostport: port,
            hostname: host.to_owned(),
        }
    }

    // ---------------------------------------------------------------------
    // Key formation -- `create_dnscache_id`, lib/hostip.c:233-244.
    // ---------------------------------------------------------------------

    #[test]
    fn a_key_is_the_lowercased_host_then_a_colon_then_the_port() {
        assert_eq!(create_dnscache_id(b"Example.COM", 443), b"example.com:443");
        assert_eq!(create_dnscache_id(b"example.com", 80), b"example.com:80");
    }

    #[test]
    fn two_hosts_differing_only_in_case_share_one_key() {
        // The comparator `curlx_str_key_compare` is case-SENSITIVE, so
        // case-insensitive lookup exists only because the key is folded here.
        assert_eq!(
            create_dnscache_id(b"WWW.Example.Com", 8080),
            create_dnscache_id(b"www.example.com", 8080)
        );
    }

    #[test]
    fn a_host_longer_than_255_bytes_truncates_to_exactly_255() {
        let host = vec![b'a'; 300];
        let key = create_dnscache_id(&host, 65535);
        // `if(len > (buflen - 7)) len = buflen - 7;` with buflen 262.
        assert_eq!(&key[..MAX_HOSTCACHE_HOST_LEN], &vec![b'a'; 255][..]);
        assert_eq!(&key[MAX_HOSTCACHE_HOST_LEN..], b":65535");
        assert_eq!(key.len(), 255 + 6);
    }

    #[test]
    fn two_hosts_differing_only_after_byte_255_collide() {
        // The truncation is observable, and reproducing it faithfully means
        // reproducing the collision. A name this long is invalid under
        // RFC 1035 anyway, and "repairing" it would make this cache disagree
        // with curl's.
        let mut first = vec![b'a'; 255];
        first.push(b'b');
        let mut second = vec![b'a'; 255];
        second.push(b'c');
        assert_eq!(
            create_dnscache_id(&first, 80),
            create_dnscache_id(&second, 80)
        );
    }

    #[test]
    fn a_high_byte_is_left_unchanged_by_the_folding() {
        // `raw_tolower` is the identity for every byte in 0x80..=0xFF, so a
        // UTF-8 or percent-decoded host is not silently rewritten. Rust's own
        // `to_lowercase` would fold some of these and could change the
        // length, which would change which hostnames collide.
        for byte in 0x80u8..=0xFF {
            let host = [b'x', byte, b'y'];
            let key = create_dnscache_id(&host, 1);
            assert_eq!(&key[..3], &host, "byte {byte:#04x} was rewritten");
        }
    }

    #[test]
    fn a_key_never_panics_on_an_edge_case_host_or_port() {
        // The whole input space that reaches this function: an empty name,
        // the truncation boundary from either side, and both port extremes.
        for host in [
            vec![],
            vec![b'a'; 1],
            vec![b'a'; MAX_HOSTCACHE_HOST_LEN],
            vec![b'a'; MAX_HOSTCACHE_HOST_LEN + 1],
        ] {
            for port in [0u16, 1, 65534, 65535] {
                let key = create_dnscache_id(&host, port);
                // C's buffer is MAX_HOSTCACHE_LEN bytes INCLUDING the
                // terminator, so the content never reaches that length.
                assert!(key.len() < MAX_HOSTCACHE_LEN);
                assert!(key.contains(&b':'));
            }
        }
        assert_eq!(create_dnscache_id(b"", 0), b":0");
        assert_eq!(create_dnscache_id(b"h", 65535), b"h:65535");
    }

    #[test]
    fn the_wildcard_key_is_the_one_byte_host_and_the_port() {
        assert_eq!(wildcard_dnscache_id(443), b"*:443");
        assert_eq!(wildcard_dnscache_id(443), create_dnscache_id(b"*", 443));
    }

    #[test]
    fn the_port_renders_as_unsigned_decimal_with_no_padding() {
        for (port, text) in [
            (0u16, ":0"),
            (7, ":7"),
            (80, ":80"),
            (443, ":443"),
            (8080, ":8080"),
            (65535, ":65535"),
        ] {
            assert_eq!(create_dnscache_id(b"", port), text.as_bytes());
        }
    }

    // ---------------------------------------------------------------------
    // Staleness -- lib/hostip.c:258-275.
    // ---------------------------------------------------------------------

    #[test]
    fn an_entry_is_fresh_one_millisecond_before_the_limit() {
        let clock = TestClock::new(CurlTime::new(1_000, 0));
        let entry = entry_at("example.com", 80, vec![v4(1, 80)], clock.now());
        clock.advance(Duration::from_millis(59_999));
        assert!(!entry.is_stale(clock.now(), 60_000));
    }

    #[test]
    fn an_entry_is_stale_at_exactly_the_limit() {
        // `if(age >= prune->max_age_ms) return TRUE;` -- the boundary is `>=`
        // and not `>`, which is a one-millisecond difference in when a
        // hostname is looked up again.
        let clock = TestClock::new(CurlTime::new(1_000, 0));
        let entry = entry_at("example.com", 80, vec![v4(1, 80)], clock.now());
        clock.advance(Duration::from_millis(60_000));
        assert!(entry.is_stale(clock.now(), 60_000));
    }

    #[test]
    fn a_negative_entry_ages_twice_as_fast() {
        // `if(!dns->addr) age *= 2; /* negative entries age twice as fast */`
        // -- lib/hostip.c:267-268. This is the rule that governs how soon a
        // failed lookup is retried, and it is the easiest line in the
        // function to overlook.
        let clock = TestClock::new(CurlTime::new(1_000, 0));
        let positive =
            entry_at("example.com", 80, vec![v4(1, 80)], clock.now());
        let negative = entry_at("example.com", 80, Vec::new(), clock.now());

        // Half the limit: the negative entry is already gone, the positive
        // one is still fresh.
        clock.advance(Duration::from_millis(30_000));
        assert!(negative.is_stale(clock.now(), 60_000));
        assert!(!positive.is_stale(clock.now(), 60_000));

        // And the doubling is visible in the reported age, not only in the
        // verdict.
        assert_eq!(negative.staleness(clock.now(), 60_000).age_ms(), 60_000);
        assert_eq!(positive.staleness(clock.now(), 60_000).age_ms(), 30_000);
    }

    #[test]
    fn a_negative_entry_one_millisecond_short_of_half_is_still_fresh() {
        let clock = TestClock::new(CurlTime::new(1_000, 0));
        let negative = entry_at("example.com", 80, Vec::new(), clock.now());
        clock.advance(Duration::from_millis(29_999));
        // 29,999 doubled is 59,998, which is below the limit.
        assert!(!negative.is_stale(clock.now(), 60_000));
        clock.advance(Duration::from_millis(1));
        assert!(negative.is_stale(clock.now(), 60_000));
    }

    #[test]
    fn a_permanent_entry_never_expires() {
        // `timestamp == 0 -- permanent CURLOPT_RESOLVE entry (does not time
        // out)`. The outer guard of the C predicate is
        // `if(timestamp.tv_sec || timestamp.tv_usec)`, so a zero reading falls
        // through to `return FALSE` whatever the limit is.
        let clock = TestClock::new(CurlTime::new(1_000, 0));
        let entry =
            entry_at("example.com", 80, vec![v4(1, 80)], CurlTime::ZERO);
        assert!(entry.is_permanent());
        clock.advance(Duration::from_secs(60 * 60 * 24 * 365 * 30));
        assert!(!entry.is_stale(clock.now(), 1));
        assert!(!entry.is_stale(clock.now(), 0));
        // A permanent entry contributes a zero age, so it can never become
        // the `oldest` that the prune loop halves.
        assert_eq!(entry.staleness(clock.now(), 1).age_ms(), 0);
    }

    #[test]
    fn a_permanent_negative_entry_also_never_expires() {
        // The two rules interact: the doubling is reached only past the
        // permanent short-circuit, so a permanent no-address entry -- which
        // `--resolve host:port:` cannot produce but a future caller could --
        // is still immortal.
        let entry = entry_at("example.com", 80, Vec::new(), CurlTime::ZERO);
        assert!(!entry.is_stale(CurlTime::new(1_000_000, 0), 1));
    }

    #[test]
    fn staleness_reports_the_age_it_measured_in_both_arms() {
        let base = CurlTime::new(100, 0);
        let entry = entry_at("h", 1, vec![v4(1, 1)], base);
        let later = CurlTime::new(105, 0);
        assert_eq!(
            entry.staleness(later, 10_000),
            Staleness::Keep { age_ms: 5_000 }
        );
        assert_eq!(
            entry.staleness(later, 5_000),
            Staleness::Remove { age_ms: 5_000 }
        );
        assert!(entry.staleness(later, 5_000).is_remove());
        assert!(!entry.staleness(later, 10_000).is_remove());
    }

    // ---------------------------------------------------------------------
    // Cache hit, miss and pruning.
    // ---------------------------------------------------------------------

    #[test]
    fn a_cache_hit_returns_the_entry_and_a_miss_returns_nothing() {
        let clock = TestClock::new(CurlTime::new(500, 0));
        let mut cache = DnsCache::new();
        cache.add(entry_at("example.com", 80, vec![v4(1, 80)], clock.now()));

        let hit = silent(|tracer| {
            cache.get(
                b"EXAMPLE.com",
                80,
                IpVersion::Whatever,
                60_000,
                clock.now(),
                tracer,
            )
        });
        assert!(hit.is_some(), "the key is case-folded, so this must hit");

        let wrong_port = silent(|tracer| {
            cache.get(
                b"example.com",
                443,
                IpVersion::Whatever,
                60_000,
                clock.now(),
                tracer,
            )
        });
        assert!(wrong_port.is_none(), "the port is part of the key");

        let wrong_host = silent(|tracer| {
            cache.get(
                b"other.example",
                80,
                IpVersion::Whatever,
                60_000,
                clock.now(),
                tracer,
            )
        });
        assert!(wrong_host.is_none());
    }

    #[test]
    fn a_stale_hit_is_zapped_and_reported() {
        let clock = TestClock::new(CurlTime::new(500, 0));
        let mut cache = DnsCache::new();
        cache.add(entry_at("example.com", 80, vec![v4(1, 80)], clock.now()));
        clock.advance(Duration::from_millis(60_000));

        let out = traced(|tracer| {
            let hit = cache.fetch_addr(
                b"example.com",
                80,
                IpVersion::Whatever,
                60_000,
                clock.now(),
                tracer,
            );
            assert!(hit.is_none());
        });
        assert_eq!(out, "* Hostname in DNS cache was stale, zapped\n");
        assert!(cache.is_empty(), "the zapped entry is gone from the cache");
    }

    #[test]
    fn a_forever_timeout_never_zaps_a_stale_hit() {
        // `if(dns && (data->set.dns_cache_timeout_ms != -1))` -- the staleness
        // test is skipped entirely, so an ancient entry keeps answering.
        let clock = TestClock::new(CurlTime::new(500, 0));
        let mut cache = DnsCache::new();
        cache.add(entry_at("example.com", 80, vec![v4(1, 80)], clock.now()));
        clock.advance(Duration::from_secs(60 * 60 * 24));

        let out = traced(|tracer| {
            let hit = cache.fetch_addr(
                b"example.com",
                80,
                IpVersion::Whatever,
                DNS_CACHE_TIMEOUT_FOREVER,
                clock.now(),
                tracer,
            );
            assert!(hit.is_some());
        });
        assert_eq!(out, "", "nothing is reported when nothing is zapped");
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn an_entry_without_the_needed_family_is_zapped_and_reported() {
        let clock = TestClock::new(CurlTime::new(500, 0));
        let mut cache = DnsCache::new();
        cache.add(entry_at("example.com", 80, vec![v4(1, 80)], clock.now()));

        // `Whatever` accepts it.
        let any = silent(|tracer| {
            cache.fetch_addr(
                b"example.com",
                80,
                IpVersion::Whatever,
                60_000,
                clock.now(),
                tracer,
            )
        });
        assert!(any.is_some());
        assert_eq!(cache.len(), 1);

        // `V4` accepts it too.
        let four = silent(|tracer| {
            cache.fetch_addr(
                b"example.com",
                80,
                IpVersion::V4,
                60_000,
                clock.now(),
                tracer,
            )
        });
        assert!(four.is_some());

        // `V6` does not, and the entry is removed rather than merely refused.
        let out = traced(|tracer| {
            let six = cache.fetch_addr(
                b"example.com",
                80,
                IpVersion::V6,
                60_000,
                clock.now(),
                tracer,
            );
            assert!(six.is_none());
        });
        assert_eq!(
            out,
            "* Hostname in DNS cache does not have needed family, zapped\n"
        );
        assert!(cache.is_empty());
    }

    #[test]
    fn a_mixed_family_entry_satisfies_every_ip_version() {
        let clock = TestClock::new(CurlTime::new(500, 0));
        let mut cache = DnsCache::new();
        cache.add(entry_at(
            "example.com",
            80,
            vec![v6(1, 80), v4(1, 80)],
            clock.now(),
        ));
        for version in [IpVersion::Whatever, IpVersion::V4, IpVersion::V6] {
            let hit = silent(|tracer| {
                cache.fetch_addr(
                    b"example.com",
                    80,
                    version,
                    60_000,
                    clock.now(),
                    tracer,
                )
            });
            assert!(hit.is_some(), "{version:?} should have been satisfied");
            assert_eq!(cache.len(), 1);
        }
    }

    #[test]
    fn a_forever_timeout_skips_pruning_entirely() {
        let clock = TestClock::new(CurlTime::new(500, 0));
        let mut cache = DnsCache::new();
        for i in 0..5u8 {
            cache.add(entry_at(
                &format!("h{i}.example"),
                80,
                vec![v4(i, 80)],
                clock.now(),
            ));
        }
        clock.advance(Duration::from_secs(60 * 60 * 24 * 365));
        assert_eq!(cache.prune(DNS_CACHE_TIMEOUT_FOREVER, clock.now()), 0);
        assert_eq!(cache.len(), 5, "-1 means forever, so nothing is pruned");
    }

    #[test]
    fn pruning_removes_the_stale_and_reports_the_oldest_survivor() {
        let base = CurlTime::new(1_000, 0);
        let mut cache = DnsCache::new();
        // Ages, at `now` = 1,100s: 100s, 60s, 30s, 10s.
        for (i, secs) in [1_000i64, 1_040, 1_070, 1_090].iter().enumerate() {
            cache.add(entry_at(
                &format!("h{i}.example"),
                80,
                vec![v4(i as u8, 80)],
                CurlTime::new(*secs, 0),
            ));
        }
        let now = base.add(Duration::from_secs(100));

        // A 45-second limit removes the 100-second and 60-second entries and
        // reports the oldest survivor, which is the 30-second one.
        let oldest = cache.prune(45_000, now);
        assert_eq!(cache.len(), 2);
        assert_eq!(oldest, 30_000);
    }

    #[test]
    fn pruning_is_independent_of_insertion_order() {
        // The executable form of the answer `crate::util::hash` asks this
        // module for. `HashMap` iteration order is randomised per process,
        // while C walked buckets in index order; pruning survives that
        // because it is a full scan with no positional selection. An LRU
        // would NOT survive it, which is the second reason not to introduce
        // one.
        let base = CurlTime::new(1_000, 0);
        let now = base.add(Duration::from_secs(100));
        let population: Vec<(String, i64)> = (0..40u32)
            .map(|i| (format!("h{i}.example"), 1_000 + i64::from(i) * 2))
            .collect();

        let survivors = |order: &mut dyn Iterator<Item = usize>| {
            let mut cache = DnsCache::new();
            for index in order {
                let (host, secs) = &population[index];
                cache.add(entry_at(
                    host,
                    80,
                    vec![v4(0, 80)],
                    CurlTime::new(*secs, 0),
                ));
            }
            let oldest = cache.prune(50_000, now);
            let mut keys: Vec<Vec<u8>> =
                cache.entries.keys().map(<[u8]>::to_vec).collect();
            keys.sort();
            (keys, oldest)
        };

        let forwards = survivors(&mut (0..population.len()));
        let backwards = survivors(&mut (0..population.len()).rev());
        assert_eq!(forwards, backwards);
        assert!(!forwards.0.is_empty(), "the comparison must not be vacuous");
        assert!(
            forwards.0.len() < population.len(),
            "and something must actually have been pruned"
        );
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "30,001 inserts is correct but impractically slow under \
                  Miri; the algorithm it exercises is entirely safe Rust, so \
                  there is nothing here for Miri to find"
    )]
    fn exceeding_the_size_cap_halves_the_age_limit_until_the_cache_fits() {
        // `if(Curl_hash_count(&dnscache->entries) > MAX_DNS_CACHE_SIZE)
        //    timeout_ms = oldest_ms / 2;` -- the cap is enforced by repeated
        // age-halving and never by LRU eviction.
        let mut cache = DnsCache::new();
        let count = MAX_DNS_CACHE_SIZE + 2;
        for i in 0..count {
            // Ages at `now` = 60,002s run from 30,002s down to 2s.
            cache.add(entry_at(
                &format!("h{i}.example"),
                80,
                vec![v4(0, 80)],
                CurlTime::new(30_000 + i as i64, 0),
            ));
        }
        assert_eq!(cache.len(), count);

        // A limit nothing can reach, so the first pass removes nothing and
        // only the halving can bring the population down.
        let oldest = cache.prune(TimeDiff::MAX, CurlTime::new(60_002, 0));
        assert!(
            cache.len() <= MAX_DNS_CACHE_SIZE,
            "the loop must bring the cache within the cap, got {}",
            cache.len()
        );
        assert!(cache.len() < count, "and it must actually remove entries");
        assert!(oldest > 0, "surviving entries still have an age");
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "30,001 inserts is correct but impractically slow under \
                  Miri; see the sibling cap test"
    )]
    fn the_halving_loop_terminates_when_the_cap_cannot_be_met() {
        // The pathological case, and the one that proves `while(timeout_ms)`
        // is load-bearing: every entry is permanent, so no limit can remove
        // any of them. Permanent entries report a zero age, so `oldest / 2` is
        // zero on the first iteration and the loop stops rather than spinning.
        let mut cache = DnsCache::new();
        let count = MAX_DNS_CACHE_SIZE + 2;
        for i in 0..count {
            cache.add(entry_at(
                &format!("h{i}.example"),
                80,
                vec![v4(0, 80)],
                CurlTime::ZERO,
            ));
        }
        let oldest = cache.prune(1, CurlTime::new(1_000_000, 0));
        assert_eq!(oldest, 0);
        assert_eq!(
            cache.len(),
            count,
            "permanent entries survive every limit, exactly as in C"
        );
    }

    #[test]
    fn clearing_empties_the_cache_and_forgets_the_wildcard() {
        let clock = TestClock::new(CurlTime::new(1, 0));
        let mut cache = DnsCache::new();
        silent(|tracer| {
            load_host_pairs(&mut cache, ["*:443:10.0.0.1"], &clock, tracer)
        })
        .expect("a well-formed wildcard entry");
        assert!(cache.wildcard_resolve());
        assert_eq!(cache.len(), 1);

        cache.clear();
        assert!(cache.is_empty());
        assert!(
            !cache.wildcard_resolve(),
            "the flag described an entry that is now gone"
        );
    }

    #[test]
    fn a_sized_cache_behaves_like_a_default_one() {
        let clock = TestClock::new(CurlTime::new(1, 0));
        let mut cache = DnsCache::with_size(DEFAULT_TEST_SLOTS);
        cache.add(entry_at("example.com", 80, vec![v4(1, 80)], clock.now()));
        let hit = silent(|tracer| {
            cache.get(
                b"example.com",
                80,
                IpVersion::Whatever,
                60_000,
                clock.now(),
                tracer,
            )
        });
        assert!(hit.is_some());
    }

    /// C's `Curl_dnscache_init(dns, 7)` for an easy handle's own cache.
    const DEFAULT_TEST_SLOTS: usize = 7;

    #[test]
    fn an_entry_handle_shares_with_the_cache_rather_than_copying() {
        let clock = TestClock::new(CurlTime::new(1, 0));
        let mut cache = DnsCache::new();
        let held = cache.add(entry_at(
            "example.com",
            80,
            vec![v4(9, 80)],
            clock.now(),
        ));
        // Two owners: the cache and this handle. C would have `refcount == 2`.
        assert_eq!(Arc::strong_count(&held), 2);

        // Removing the cache's own reference leaves the handle usable, which
        // is what `Curl_resolv_unlink`'s decrement-and-free-at-zero achieves
        // and what makes a zapped entry safe to keep reading.
        cache.clear();
        assert_eq!(Arc::strong_count(&held), 1);
        assert_eq!(held.addrs.len(), 1);
    }

    // ---------------------------------------------------------------------
    // CURLOPT_RESOLVE -- lib/hostip.c:1279-1470. The syntax is frozen.
    // ---------------------------------------------------------------------

    /// Loads `entries` into a fresh cache, discarding the trace.
    fn load(entries: &[&str], clock: &TestClock) -> (DnsCache, CodeResult<()>) {
        let mut cache = DnsCache::new();
        let result = silent(|tracer| {
            load_host_pairs(&mut cache, entries.iter().copied(), clock, tracer)
        });
        (cache, result)
    }

    #[test]
    fn a_plain_resolve_entry_lands_as_a_permanent_entry() {
        let clock = TestClock::new(CurlTime::new(1_000, 0));
        let (mut cache, result) = load(&["example.com:443:10.0.0.1"], &clock);
        assert_eq!(result, Ok(()));
        assert_eq!(cache.len(), 1);

        let hit = silent(|tracer| {
            cache.fetch_addr(
                b"example.com",
                443,
                IpVersion::Whatever,
                60_000,
                clock.now(),
                tracer,
            )
        })
        .expect("the entry was just added");
        assert!(hit.is_permanent(), "no prefix means permanent");
        assert_eq!(hit.hostname, "example.com");
        assert_eq!(hit.hostport, 443);
        assert_eq!(
            hit.addrs[0].socket_addr(),
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443))
        );
    }

    #[test]
    fn a_plus_prefixed_entry_is_non_permanent_and_a_plain_one_is_not() {
        let clock = TestClock::new(CurlTime::new(1_000, 0));
        let (mut cache, result) = load(
            &[
                "+temporary.example:80:10.0.0.1",
                "forever.example:80:10.0.0.2",
            ],
            &clock,
        );
        assert_eq!(result, Ok(()));
        assert_eq!(cache.len(), 2);

        // A day later the non-permanent entry is stale and the plain one is
        // not, which is the whole difference the `+` makes.
        clock.advance(Duration::from_secs(60 * 60 * 24));
        let temporary = silent(|tracer| {
            cache.fetch_addr(
                b"temporary.example",
                80,
                IpVersion::Whatever,
                60_000,
                clock.now(),
                tracer,
            )
        });
        assert!(temporary.is_none(), "+ entries expire");

        let forever = silent(|tracer| {
            cache.fetch_addr(
                b"forever.example",
                80,
                IpVersion::Whatever,
                60_000,
                clock.now(),
                tracer,
            )
        });
        assert!(forever.is_some(), "plain entries do not");
    }

    #[test]
    fn a_minus_prefixed_entry_deletes_and_accepts_the_bracketed_form() {
        let clock = TestClock::new(CurlTime::new(1_000, 0));
        let mut cache = DnsCache::new();
        silent(|tracer| {
            load_host_pairs(
                &mut cache,
                ["example.com:443:10.0.0.1", "[::1]:8080:[::2]"],
                &clock,
                tracer,
            )
        })
        .expect("both entries are well formed");
        assert_eq!(cache.len(), 2);

        // The unbracketed delete form.
        silent(|tracer| {
            load_host_pairs(&mut cache, ["-example.com:443"], &clock, tracer)
        })
        .expect("a delete never fails");
        assert!(cache
            .remove(&create_dnscache_id(b"example.com", 443))
            .is_none());

        // The bracketed delete form, which exists so that an IPv6 literal --
        // full of colons -- can be named unambiguously.
        silent(|tracer| {
            load_host_pairs(&mut cache, ["-[::1]:8080"], &clock, tracer)
        })
        .expect("a delete never fails");
        assert!(cache.is_empty());
    }

    #[test]
    fn a_malformed_delete_entry_is_ignored_in_complete_silence() {
        // Every failure in C's delete branch is a bare `continue`: no message,
        // no error, no diagnostic. A malformed ADD entry is fatal; a malformed
        // DELETE entry is not, and the asymmetry is preserved.
        let clock = TestClock::new(CurlTime::new(1_000, 0));
        let mut cache = DnsCache::new();
        let malformed = [
            "-",                  // nothing at all
            "-example.com",       // no colon and no port
            "-example.com:",      // a colon but no port
            "-example.com:abc",   // a port that is not a number
            "-example.com:99999", // a port above 0xffff
            "-[::1",              // an unterminated bracket
            "-[::1]",             // brackets but no port separator
            "-:80",               // a port but no host
        ];
        let out = traced(|tracer| {
            let result = load_host_pairs(&mut cache, malformed, &clock, tracer);
            assert_eq!(result, Ok(()), "a malformed delete is not an error");
        });
        assert_eq!(out, "", "and it says nothing at all");
        assert!(cache.is_empty());
    }

    #[test]
    fn a_malformed_add_entry_is_a_setopt_syntax_error() {
        let clock = TestClock::new(CurlTime::new(1_000, 0));
        for entry in [
            "example.com:443",            // no address section
            "example.com:443:",           // an empty address section
            "example.com:abc:10.0.0.1",   // a port that is not a number
            "example.com:99999:10.0.0.1", // a port above 0xffff
            "example.com:443:not-an-ip",  // an address that will not parse
            "example.com:443:10.0.0.1,x", // a second address that will not
        ] {
            let (cache, result) = load(&[entry], &clock);
            assert_eq!(
                result,
                Err(CURLcode::SetoptOptionSyntax),
                "entry {entry:?} must be a syntax error, not \
                 BadFunctionArgument and not silence"
            );
            assert!(cache.is_empty(), "entry {entry:?} must leave no trace");
        }
    }

    #[test]
    fn a_malformed_add_entry_reports_the_frozen_message() {
        let clock = TestClock::new(CurlTime::new(1_000, 0));
        let mut cache = DnsCache::new();
        let out = traced(|tracer| {
            let result = load_host_pairs(
                &mut cache,
                ["example.com:443:not-an-ip"],
                &clock,
                tracer,
            );
            assert_eq!(result, Err(CURLcode::SetoptOptionSyntax));
        });
        assert_eq!(
            out,
            "* Resolve address 'not-an-ip' found illegal\n\
             * Could not parse CURLOPT_RESOLVE entry \
             'example.com:443:not-an-ip'\n"
        );
    }

    #[test]
    fn an_address_literal_of_64_bytes_is_rejected_and_63_is_accepted() {
        // C's buffer is `char address[64]` and the guard is
        // `if(curlx_strlen(&target) >= sizeof(address)) goto err;`.
        let clock = TestClock::new(CurlTime::new(1_000, 0));

        // A 64-byte literal: rejected on length before it is even parsed, so
        // the "found illegal" line does not appear.
        let long = "1".repeat(RESOLVE_ADDRESS_MAX);
        assert_eq!(long.len(), 64);
        let mut cache = DnsCache::new();
        let out = traced(|tracer| {
            let result = load_host_pairs(
                &mut cache,
                [format!("h.example:80:{long}").as_str()],
                &clock,
                tracer,
            );
            assert_eq!(result, Err(CURLcode::SetoptOptionSyntax));
        });
        assert!(
            !out.contains("found illegal"),
            "the length bound is tested before the parse: {out}"
        );

        // 63 bytes gets as far as the parser, which then rejects it on its
        // own terms -- proving the bound, not the parser, refused the 64.
        let short = "1".repeat(RESOLVE_ADDRESS_MAX - 1);
        let mut cache = DnsCache::new();
        let out = traced(|tracer| {
            let _ = load_host_pairs(
                &mut cache,
                [format!("h.example:80:{short}").as_str()],
                &clock,
                tracer,
            );
        });
        assert!(out.contains("found illegal"), "{out}");
    }

    #[test]
    fn several_comma_separated_addresses_all_land_in_order() {
        let clock = TestClock::new(CurlTime::new(1_000, 0));
        let (mut cache, result) =
            load(&["h.example:80:10.0.0.1,10.0.0.2,[::5],10.0.0.3"], &clock);
        assert_eq!(result, Ok(()));

        let hit = silent(|tracer| {
            cache.fetch_addr(
                b"h.example",
                80,
                IpVersion::Whatever,
                60_000,
                clock.now(),
                tracer,
            )
        })
        .expect("the entry was just added");
        let rendered: Vec<String> = hit
            .addrs
            .iter()
            .map(ResolvedAddr::printable_address)
            .collect();
        assert_eq!(rendered, ["10.0.0.1", "10.0.0.2", "::5", "10.0.0.3"]);
    }

    #[test]
    fn an_empty_element_between_two_commas_is_survived() {
        // C's comment is "survive nothing but just a comma"
        // (lib/hostip.c:1365-1368): an unbracketed element that yields nothing
        // is skipped when a comma really follows.
        let clock = TestClock::new(CurlTime::new(1_000, 0));
        let (mut cache, result) =
            load(&["h.example:80:10.0.0.1,,10.0.0.2"], &clock);
        assert_eq!(result, Ok(()));
        let hit = silent(|tracer| {
            cache.fetch_addr(
                b"h.example",
                80,
                IpVersion::Whatever,
                60_000,
                clock.now(),
                tracer,
            )
        })
        .expect("the entry was just added");
        assert_eq!(hit.addrs.len(), 2);
    }

    #[test]
    fn replacing_an_entry_reports_the_discard_first() {
        let clock = TestClock::new(CurlTime::new(1_000, 0));
        let mut cache = DnsCache::new();
        silent(|tracer| {
            load_host_pairs(
                &mut cache,
                ["h.example:80:10.0.0.1"],
                &clock,
                tracer,
            )
        })
        .expect("well formed");

        let out = traced(|tracer| {
            load_host_pairs(
                &mut cache,
                ["h.example:80:10.0.0.9"],
                &clock,
                tracer,
            )
            .expect("well formed");
        });
        assert_eq!(
            out,
            "* RESOLVE h.example:80 - old addresses discarded\n\
             * Added h.example:80:10.0.0.9 to DNS cache\n"
        );
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn the_added_line_carries_the_non_permanent_suffix_only_when_it_applies() {
        let clock = TestClock::new(CurlTime::new(1_000, 0));
        let mut cache = DnsCache::new();

        let plain = traced(|tracer| {
            load_host_pairs(
                &mut cache,
                ["a.example:80:10.0.0.1"],
                &clock,
                tracer,
            )
            .expect("well formed");
        });
        assert_eq!(plain, "* Added a.example:80:10.0.0.1 to DNS cache\n");

        let plus = traced(|tracer| {
            load_host_pairs(
                &mut cache,
                ["+b.example:80:10.0.0.2"],
                &clock,
                tracer,
            )
            .expect("well formed");
        });
        assert_eq!(
            plus,
            "* Added b.example:80:10.0.0.2 to DNS cache (non-permanent)\n"
        );
    }

    #[test]
    fn a_wildcard_entry_answers_for_any_host_on_that_port() {
        let clock = TestClock::new(CurlTime::new(1_000, 0));
        let mut cache = DnsCache::new();
        let out = traced(|tracer| {
            load_host_pairs(&mut cache, ["*:443:10.0.0.7"], &clock, tracer)
                .expect("well formed");
        });
        assert_eq!(
            out,
            "* Added *:443:10.0.0.7 to DNS cache\n\
             * RESOLVE *:443 using wildcard\n"
        );
        assert!(cache.wildcard_resolve());

        // A host nobody named, on the wildcard's port: it hits.
        let hit = silent(|tracer| {
            cache.fetch_addr(
                b"never.mentioned.example",
                443,
                IpVersion::Whatever,
                60_000,
                clock.now(),
                tracer,
            )
        });
        assert!(hit.is_some(), "the wildcard answers for an unrelated host");

        // A different port: it does not.
        let miss = silent(|tracer| {
            cache.fetch_addr(
                b"never.mentioned.example",
                80,
                IpVersion::Whatever,
                60_000,
                clock.now(),
                tracer,
            )
        });
        assert!(miss.is_none(), "the wildcard is per port");
    }

    #[test]
    fn the_wildcard_flag_resets_on_every_load() {
        // "Default is no wildcard found" -- `data->state.wildcard_resolve =
        // FALSE;` at the top of `Curl_loadhostpairs`, so a later load without
        // a `*` turns the behaviour off again.
        let clock = TestClock::new(CurlTime::new(1_000, 0));
        let mut cache = DnsCache::new();
        silent(|tracer| {
            load_host_pairs(&mut cache, ["*:443:10.0.0.7"], &clock, tracer)
        })
        .expect("well formed");
        assert!(cache.wildcard_resolve());

        silent(|tracer| {
            load_host_pairs(
                &mut cache,
                ["h.example:80:10.0.0.1"],
                &clock,
                tracer,
            )
        })
        .expect("well formed");
        assert!(!cache.wildcard_resolve());
    }

    #[test]
    fn a_stale_wildcard_hit_zaps_the_wildcard_key_not_the_exact_one() {
        // The measured subtlety: C reuses one stack buffer for the key, so the
        // delete in steps 3 and 4 uses the LAST key computed. When the
        // wildcard path supplied the hit, the WILDCARD entry is what gets
        // zapped -- which is also the only useful behaviour, since deleting
        // the exact key would remove nothing and leave the stale wildcard to
        // be found again.
        let clock = TestClock::new(CurlTime::new(1_000, 0));
        let mut cache = DnsCache::new();
        silent(|tracer| {
            load_host_pairs(&mut cache, ["+*:443:10.0.0.7"], &clock, tracer)
        })
        .expect("well formed");
        assert!(cache.wildcard_resolve());
        assert_eq!(cache.len(), 1);

        clock.advance(Duration::from_millis(60_000));
        let out = traced(|tracer| {
            let hit = cache.fetch_addr(
                b"unrelated.example",
                443,
                IpVersion::Whatever,
                60_000,
                clock.now(),
                tracer,
            );
            assert!(hit.is_none());
        });
        assert_eq!(out, "* Hostname in DNS cache was stale, zapped\n");
        assert!(
            cache.is_empty(),
            "the wildcard entry is what was removed, so the cache is empty"
        );
    }

    #[test]
    fn an_empty_resolve_entry_is_skipped() {
        // C's `if(!host) continue;` guards a NULL slist item; an empty string
        // is the closest Rust equivalent and is skipped for the same reason.
        let clock = TestClock::new(CurlTime::new(1_000, 0));
        let (cache, result) = load(&["", ""], &clock);
        assert_eq!(result, Ok(()));
        assert!(cache.is_empty());
    }

    #[test]
    fn one_malformed_entry_abandons_the_whole_load() {
        // C returns from `Curl_loadhostpairs` at the first bad ADD entry, so a
        // later well-formed entry in the same list never lands.
        let clock = TestClock::new(CurlTime::new(1_000, 0));
        let (cache, result) = load(
            &["bad.example:443:nope", "good.example:80:10.0.0.1"],
            &clock,
        );
        assert_eq!(result, Err(CURLcode::SetoptOptionSyntax));
        assert!(cache.is_empty());
    }

    // ---------------------------------------------------------------------
    // AlpnId -- lib/hostip.h:49-54 and include/curl/curl.h:1033-1035.
    // ---------------------------------------------------------------------

    #[test]
    fn the_alpn_integers_are_the_public_altsvc_bits() {
        // CURLALTSVC_H1 (1L << 3), H2 (1L << 4), H3 (1L << 5). These are NOT
        // ordinals: lib/httpsrr.c:57-61 stores them as bytes and dedupes the
        // array with `memchr`, so renumbering changes which advertised
        // protocols survive deduplication.
        assert_eq!(AlpnId::None.as_u8(), 0);
        assert_eq!(AlpnId::H1.as_u8(), 8);
        assert_eq!(AlpnId::H2.as_u8(), 16);
        assert_eq!(AlpnId::H3.as_u8(), 32);
        assert_eq!(1u8 << 3, AlpnId::H1.as_u8());
        assert_eq!(1u8 << 4, AlpnId::H2.as_u8());
        assert_eq!(1u8 << 5, AlpnId::H3.as_u8());
    }

    #[test]
    fn the_alpn_parser_accepts_exactly_what_the_c_accepts() {
        assert_eq!(AlpnId::from_wire(b"h1"), AlpnId::H1);
        assert_eq!(AlpnId::from_wire(b"h2"), AlpnId::H2);
        assert_eq!(AlpnId::from_wire(b"h3"), AlpnId::H3);
        assert_eq!(AlpnId::from_wire(b"http/1.1"), AlpnId::H1);
    }

    #[test]
    fn the_alpn_parser_rejects_everything_else_without_erring() {
        // C's comment: "unknown, probably rubbish input" -- an unrecognised
        // token is ALPN_none rather than a failure, which is what lets a
        // server advertise a protocol this client has never heard of.
        for input in [
            &b""[..],
            b"h",
            b"h4",
            b"h0",
            b"xy",
            b"h22",      // three bytes: only lengths 2 and 8 are examined
            b"HTTP/1.1", // the comparison is memcmp, so case matters
            b"Http/1.1",
            b"http/1.0",
            b"http/2.0",
            b"http/1.11",
        ] {
            assert_eq!(
                AlpnId::from_wire(input),
                AlpnId::None,
                "{:?} must not parse",
                core::str::from_utf8(input).unwrap_or("<bytes>")
            );
        }
    }

    // ---------------------------------------------------------------------
    // IpVersion -- include/curl/curl.h:2300-2303.
    // ---------------------------------------------------------------------

    #[test]
    fn the_ip_version_integers_are_the_public_abi_values() {
        assert_eq!(IpVersion::Whatever.as_i32(), 0);
        assert_eq!(IpVersion::V4.as_i32(), 1);
        assert_eq!(IpVersion::V6.as_i32(), 2);
        assert_eq!(IpVersion::from_i32(0), Some(IpVersion::Whatever));
        assert_eq!(IpVersion::from_i32(1), Some(IpVersion::V4));
        assert_eq!(IpVersion::from_i32(2), Some(IpVersion::V6));
        assert_eq!(IpVersion::from_i32(3), None);
        assert_eq!(IpVersion::from_i32(-1), None);
        assert_eq!(IpVersion::default(), IpVersion::Whatever);
    }

    #[test]
    fn only_a_specific_ip_version_demands_a_family() {
        assert_eq!(IpVersion::Whatever.required_family(), None);
        assert_eq!(IpVersion::V4.required_family(), Some(AddressFamily::Inet));
        assert_eq!(IpVersion::V6.required_family(), Some(AddressFamily::Inet6));
    }

    // ---------------------------------------------------------------------
    // Localhost synthesis -- lib/hostip.c:671-746.
    // ---------------------------------------------------------------------

    #[test]
    fn localhost_synthesis_puts_the_ipv6_entry_first() {
        // `ca6->ai_next = ca; return ca6;` -- lib/hostip.c:743-744. The order
        // is observable through Happy Eyeballs racing, so it is behaviour.
        let addrs = localhost_addrs(8080, "localhost");
        assert_eq!(addrs.len(), 2);

        assert_eq!(addrs[0].family(), AddressFamily::Inet6);
        assert_eq!(addrs[0].printable_address(), "::1");
        assert_eq!(addrs[1].family(), AddressFamily::Inet);
        assert_eq!(addrs[1].printable_address(), "127.0.0.1");

        for addr in &addrs {
            assert_eq!(addr.socktype, SockType::Stream);
            assert_eq!(addr.protocol, IpProto::Tcp);
            assert_eq!(addr.canonname.as_deref(), Some("localhost"));
            assert_eq!(addr.socket_addr().map(|a| a.port()), Some(8080));
        }
    }

    #[test]
    fn localhost_synthesis_carries_the_name_the_caller_asked_for() {
        // `curlx_strcopy(ca->ai_canonname, hostlen + 1, name, hostlen)` -- the
        // canonical name is the REQUESTED name, so `foo.localhost` resolves to
        // loopback under its own name rather than under "localhost".
        for name in ["localhost", "localhost.", "foo.localhost", "LOCALHOST"] {
            let addrs = localhost_addrs(443, name);
            assert!(addrs.iter().all(|a| a.canonname.as_deref() == Some(name)));
        }
    }

    // ---------------------------------------------------------------------
    // The shuffle -- lib/hostip.c:492-557, C's @unittest: 1608.
    // ---------------------------------------------------------------------

    #[test]
    fn the_shuffle_reproduces_a_hand_computed_fisher_yates() {
        // Entropy words, little-endian: rnd = [7, 0, 1, 2]. Element zero is
        // drawn and never read, because the loop runs from num_addrs-1 down to
        // 1 and indexes rnd[i].
        //
        //   start        [A, B, C, D]
        //   i = 3: j = 2 % 4 = 2  swap(3,2)  [A, B, D, C]
        //   i = 2: j = 1 % 3 = 1  swap(2,1)  [A, D, B, C]
        //   i = 1: j = 0 % 2 = 0  swap(1,0)  [D, A, B, C]
        let words: [u32; 4] = [7, 0, 1, 2];
        let mut stream: Vec<u8> = Vec::new();
        for word in words {
            stream.extend_from_slice(&word.to_le_bytes());
        }

        let mut addrs = vec![v4(1, 80), v4(2, 80), v4(3, 80), v4(4, 80)];
        let mut fill = |out: &mut [u8]| -> CodeResult<()> {
            out.copy_from_slice(&stream[..out.len()]);
            Ok(())
        };
        let out = traced(|tracer| {
            shuffle_addrs(&mut addrs, &mut fill, tracer)
                .expect("the entropy source cannot fail here");
        });
        assert_eq!(out, "* Shuffling 4 addresses\n");

        let rendered: Vec<String> =
            addrs.iter().map(ResolvedAddr::printable_address).collect();
        assert_eq!(
            rendered,
            ["127.0.0.4", "127.0.0.1", "127.0.0.2", "127.0.0.3"]
        );
    }

    #[test]
    fn the_shuffle_draws_exactly_four_bytes_per_address() {
        // `rnd_size = num_addrs * sizeof(*rnd)` -- the draw size is part of the
        // behaviour, because a shorter draw would consume a different prefix of
        // the random stream and produce a different permutation.
        for count in 2usize..=8 {
            let mut addrs: Vec<ResolvedAddr> =
                (0..count).map(|i| v4(i as u8, 80)).collect();
            let mut requested = 0usize;
            let mut fill = |out: &mut [u8]| -> CodeResult<()> {
                requested += out.len();
                out.fill(0);
                Ok(())
            };
            silent(|tracer| shuffle_addrs(&mut addrs, &mut fill, tracer))
                .expect("filling with zeroes cannot fail");
            assert_eq!(requested, count * 4);
        }
    }

    #[test]
    fn a_one_element_list_is_left_alone_and_says_nothing() {
        // `if(num_addrs > 1)` -- and the message lives inside that guard, so a
        // single address produces no output at all.
        for count in [0usize, 1] {
            let mut addrs: Vec<ResolvedAddr> =
                (0..count).map(|i| v4(i as u8, 80)).collect();
            let before = addrs.clone();
            let mut fill = |_: &mut [u8]| -> CodeResult<()> {
                panic!("the entropy source must not be consulted");
            };
            let out = traced(|tracer| {
                shuffle_addrs(&mut addrs, &mut fill, tracer)
                    .expect("nothing to shuffle");
            });
            assert_eq!(out, "");
            assert_eq!(addrs, before);
        }
    }

    #[test]
    fn a_failed_draw_leaves_the_order_untouched() {
        // C returns CURLE_OUT_OF_MEMORY having relinked nothing, and skips the
        // shuffle entirely when `Curl_rand` fails. The draw happens before any
        // swap here, so the error propagates with the order intact.
        let mut addrs = vec![v4(1, 80), v4(2, 80), v4(3, 80)];
        let before = addrs.clone();
        let mut fill =
            |_: &mut [u8]| -> CodeResult<()> { Err(CURLcode::OutOfMemory) };
        let result =
            silent(|tracer| shuffle_addrs(&mut addrs, &mut fill, tracer));
        assert_eq!(result, Err(CURLcode::OutOfMemory));
        assert_eq!(addrs, before);
    }

    #[test]
    fn a_shuffle_is_a_permutation_for_every_entropy_pattern() {
        // Whatever the draw, every address is still present exactly once: the
        // algorithm relinks rather than replaces, and C's modulus keeps every
        // index in range.
        for pattern in [0u8, 1, 0x7f, 0x80, 0xfe, 0xff] {
            let mut addrs: Vec<ResolvedAddr> =
                (0..6u8).map(|i| v4(i, 80)).collect();
            let mut fill = |out: &mut [u8]| -> CodeResult<()> {
                out.fill(pattern);
                Ok(())
            };
            silent(|tracer| shuffle_addrs(&mut addrs, &mut fill, tracer))
                .expect("a constant fill cannot fail");
            let mut seen: Vec<String> =
                addrs.iter().map(ResolvedAddr::printable_address).collect();
            seen.sort();
            let expected: Vec<String> =
                (0..6u8).map(|i| format!("127.0.0.{i}")).collect();
            assert_eq!(seen, expected, "pattern {pattern:#04x} lost an entry");
        }
    }

    #[test]
    fn mk_entry_shuffles_before_it_builds_and_stamps_from_the_clock() {
        let clock = TestClock::new(CurlTime::new(4_242, 500_000));
        let mut fill = |out: &mut [u8]| -> CodeResult<()> {
            out.fill(0);
            Ok(())
        };
        let entry = silent(|tracer| {
            DnsCache::mk_entry(
                "h.example",
                80,
                vec![v4(1, 80), v4(2, 80)],
                false,
                &clock,
                Some(&mut fill),
                tracer,
            )
        })
        .expect("a zero fill cannot fail");
        assert_eq!(entry.timestamp, CurlTime::new(4_242, 500_000));
        assert_eq!(entry.addrs.len(), 2);

        // And a permanent entry gets the all-zero reading instead.
        let permanent = silent(|tracer| {
            DnsCache::mk_entry(
                "h.example",
                80,
                vec![v4(1, 80)],
                true,
                &clock,
                None,
                tracer,
            )
        })
        .expect("no shuffle requested");
        assert_eq!(permanent.timestamp, CurlTime::ZERO);
        assert!(permanent.is_permanent());
    }

    #[test]
    fn a_failed_shuffle_prevents_the_entry_from_being_built() {
        // `if(result) goto out;` -- C bails out of entry creation entirely when
        // the shuffle fails, freeing the address list on the way.
        let clock = TestClock::new(CurlTime::new(1, 0));
        let mut fill =
            |_: &mut [u8]| -> CodeResult<()> { Err(CURLcode::OutOfMemory) };
        let mut cache = DnsCache::new();
        let result = silent(|tracer| {
            cache.add_addrs(
                "h.example",
                80,
                vec![v4(1, 80), v4(2, 80)],
                false,
                &clock,
                Some(&mut fill),
                tracer,
            )
        });
        assert!(result.is_err());
        assert!(cache.is_empty(), "nothing was inserted");
    }

    // ---------------------------------------------------------------------
    // Address text -- lib/hostip.c:203-227, through crate::util::inet.
    // ---------------------------------------------------------------------

    #[test]
    fn an_unknown_family_renders_as_the_empty_string() {
        // `buf[0] = 0;` happens FIRST and the `default:` arm leaves it there.
        // C's own comment: "If the conversion fails, the target buffer is
        // empty." An AF_UNIX entry is exactly that case.
        let unix = unix2addr(Path::new("/tmp/curl.sock"), false)
            .expect("a short path");
        assert_eq!(unix.family(), AddressFamily::Unix);
        assert_eq!(unix.printable_address(), "");
        assert_eq!(unix.socket_addr(), None);
    }

    #[test]
    fn ipv4_and_ipv6_render_through_the_crates_own_converter() {
        assert_eq!(v4(1, 80).printable_address(), "127.0.0.1");
        assert_eq!(
            ResolvedAddr::tcp(
                SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                    443
                ),
                None
            )
            .printable_address(),
            "2001:db8::1"
        );
    }

    #[test]
    fn a_single_zero_word_is_not_compressed() {
        // curl's `inet_ntop` diverges from `std::net`'s Display here: a run of
        // exactly one zero word is left uncompressed. Rendering through
        // `Ipv6Addr::to_string` would produce `1:0:2:3:4:5:6:7` as
        // `1::2:3:4:5:6:7` and change --verbose output.
        let addr = ResolvedAddr::tcp(
            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(1, 0, 2, 3, 4, 5, 6, 7)),
                80,
            ),
            None,
        );
        assert_eq!(addr.printable_address(), "1:0:2:3:4:5:6:7");
    }

    #[test]
    fn an_ipv4_compatible_address_renders_in_dotted_form() {
        // The second divergence: curl renders an IPv4-COMPATIBLE address (not
        // only a mapped one) with a dotted tail.
        let addr = ResolvedAddr::tcp(
            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0x0102, 0x0304)),
                80,
            ),
            None,
        );
        assert_eq!(addr.printable_address(), "::1.2.3.4");
    }

    #[test]
    fn every_rendered_address_fits_the_c_buffer() {
        // MAX_IPADR_LEN sizes a `char buf[]` in C, so nothing this renders may
        // reach it. The widest possible IPv6 text plus a terminator is exactly
        // the bound.
        let widest = ResolvedAddr::tcp(
            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(
                    0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
                    0xffff,
                )),
                80,
            ),
            None,
        );
        assert!(widest.printable_address_fits_the_c_buffer());
        assert!(v4(255, 80).printable_address_fits_the_c_buffer());
    }

    // ---------------------------------------------------------------------
    // Literal probes -- lib/hostip.c:783-796, lib/curl_addrinfo.c:407-440.
    // ---------------------------------------------------------------------

    #[test]
    fn a_numeric_address_is_recognised_and_a_name_is_not() {
        for literal in [
            &b"127.0.0.1"[..],
            b"0.0.0.0",
            b"255.255.255.255",
            b"::1",
            b"::",
            b"2001:db8::1",
            b"::ffff:1.2.3.4",
        ] {
            assert!(
                host_is_ipnum(literal),
                "{:?} is a literal",
                core::str::from_utf8(literal).unwrap_or("<bytes>")
            );
            assert!(is_ipaddr(literal), "the two probes must agree");
        }
        for name in [
            &b"example.com"[..],
            b"localhost",
            b"",
            b"1.2.3",
            b"1.2.3.4.5",
            b"[::1]",
            b"not-an-ip",
        ] {
            assert!(
                !host_is_ipnum(name),
                "{:?} is not a literal",
                core::str::from_utf8(name).unwrap_or("<bytes>")
            );
            assert!(!is_ipaddr(name), "the two probes must agree");
        }
    }

    #[test]
    fn str2addr_builds_a_stream_address_with_the_literal_as_its_name() {
        // `ip2addr` sets SOCK_STREAM, leaves ai_protocol at the zero of its
        // calloc, and copies the dotted text into ai_canonname.
        let four = str2addr(b"10.0.0.1", 8080).expect("a valid literal");
        assert_eq!(four.family(), AddressFamily::Inet);
        assert_eq!(four.socktype, SockType::Stream);
        assert_eq!(
            four.protocol,
            IpProto::Unspecified,
            "ip2addr never sets IPPROTO_TCP, unlike get_localhost"
        );
        assert_eq!(four.canonname.as_deref(), Some("10.0.0.1"));
        assert_eq!(
            four.socket_addr(),
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                8080
            ))
        );

        let six = str2addr(b"::2", 443).expect("a valid literal");
        assert_eq!(six.family(), AddressFamily::Inet6);
        assert_eq!(six.canonname.as_deref(), Some("::2"));
    }

    #[test]
    fn str2addr_rejects_a_non_literal_with_bad_function_argument() {
        // C's own choice of code, commented "bad input format".
        for input in [&b"example.com"[..], b"", b"1.2.3", b"[::1]", b"::g"] {
            assert_eq!(str2addr(input, 80), Err(CURLcode::BadFunctionArgument));
        }
    }

    #[test]
    fn unix2addr_bounds_the_path_by_the_platform_sun_path() {
        // `if(path_len > sizeof(sa_un->sun_path))`, where C's `path_len` is
        // `strlen(path) + 1`.
        let longest = "x".repeat(UNIX_PATH_MAX - 1);
        let ok = unix2addr(Path::new(&longest), false)
            .expect("exactly the longest path that fits");
        assert_eq!(ok.socktype, SockType::Stream);
        assert_eq!(ok.canonname, None);

        let too_long = "x".repeat(UNIX_PATH_MAX);
        assert_eq!(
            unix2addr(Path::new(&too_long), false),
            Err(CURLcode::BadFunctionArgument),
            "C signals this through *longpath; here it is the only error"
        );
    }

    #[test]
    fn unix2addr_records_whether_the_name_is_abstract() {
        // An abstract socket's name starts at offset one of sun_path, so the
        // flag is recorded rather than folded into the path.
        let plain =
            unix2addr(Path::new("/run/curl.sock"), false).expect("short");
        let abstract_ns = unix2addr(Path::new("curl"), true).expect("short");
        assert_eq!(
            plain.addr,
            ResolvedSockAddr::Unix {
                path: PathBuf::from("/run/curl.sock"),
                abstract_ns: false,
            }
        );
        assert_eq!(
            abstract_ns.addr,
            ResolvedSockAddr::Unix {
                path: PathBuf::from("curl"),
                abstract_ns: true,
            }
        );
    }

    // ---------------------------------------------------------------------
    // show_resolve_info -- lib/hostip.c:118-179.
    // ---------------------------------------------------------------------

    #[test]
    fn resolve_info_prints_the_ipv6_line_before_the_ipv4_line() {
        let entry = entry_at(
            "example.com",
            443,
            vec![v4(1, 443), v6(1, 443), v4(2, 443), v6(2, 443)],
            CurlTime::new(1, 0),
        );
        let out = traced(|tracer| show_resolve_info(&entry, tracer));
        assert_eq!(
            out,
            "* Host example.com:443 was resolved.\n\
             * IPv6: ::1, ::2\n\
             * IPv4: 127.0.0.1, 127.0.0.2\n",
            "the IPv6 line comes first, the separator is a comma AND a space, \
             and the first line ends with a period"
        );
    }

    #[test]
    fn resolve_info_renders_none_for_an_absent_family() {
        let four_only =
            entry_at("example.com", 80, vec![v4(1, 80)], CurlTime::new(1, 0));
        let out = traced(|tracer| show_resolve_info(&four_only, tracer));
        assert_eq!(
            out,
            "* Host example.com:80 was resolved.\n\
             * IPv6: (none)\n\
             * IPv4: 127.0.0.1\n"
        );

        let six_only =
            entry_at("example.com", 80, vec![v6(1, 80)], CurlTime::new(1, 0));
        let out = traced(|tracer| show_resolve_info(&six_only, tracer));
        assert_eq!(
            out,
            "* Host example.com:80 was resolved.\n\
             * IPv6: ::1\n\
             * IPv4: (none)\n"
        );
    }

    #[test]
    fn resolve_info_says_nothing_for_a_numeric_host_or_an_empty_name() {
        // "ignore no name or numerical IP addresses" -- printing
        // `Host 1.2.3.4:80 was resolved. IPv4: 1.2.3.4` would be noise.
        for host in ["1.2.3.4", "::1", ""] {
            let entry =
                entry_at(host, 80, vec![v4(1, 80)], CurlTime::new(1, 0));
            let out = traced(|tracer| show_resolve_info(&entry, tracer));
            assert_eq!(out, "", "host {host:?} must be silent");
        }
    }

    #[test]
    fn resolve_info_says_nothing_when_tracing_is_off() {
        let entry =
            entry_at("example.com", 80, vec![v4(1, 80)], CurlTime::new(1, 0));
        let config = TraceConfig::new();
        let mut sink = WriterSink::new(Vec::<u8>::new());
        {
            let mut tracer = Tracer::new(&config, &mut sink);
            show_resolve_info(&entry, &mut tracer);
        }
        assert!(sink.into_inner().is_empty());
    }

    #[test]
    fn resolve_info_abandons_both_lines_when_a_list_overflows() {
        // Each dynbuf is initialised with a 1024-byte cap, and exceeding it
        // produces "too many IP, cannot show" and C's `goto fail`, which skips
        // BOTH the IPv6 and the IPv4 line.
        let mut addrs = Vec::new();
        for i in 0..200u16 {
            addrs.push(v6(i + 1, 80));
        }
        let entry = entry_at("example.com", 80, addrs, CurlTime::new(1, 0));
        let out = traced(|tracer| show_resolve_info(&entry, tracer));
        assert_eq!(
            out,
            "* Host example.com:80 was resolved.\n\
             * too many IP, cannot show\n"
        );
    }

    #[test]
    fn resolve_info_skips_a_unix_address_entirely() {
        // C's enclosing `if(family == PF_INET6 || family == PF_INET)` means an
        // AF_UNIX entry contributes to neither line rather than being
        // mis-filed into one of them.
        let unix = unix2addr(Path::new("/run/curl.sock"), false)
            .expect("a short path");
        let entry = entry_at(
            "example.com",
            80,
            vec![unix, v4(1, 80)],
            CurlTime::new(1, 0),
        );
        let out = traced(|tracer| show_resolve_info(&entry, tracer));
        assert_eq!(
            out,
            "* Host example.com:80 was resolved.\n\
             * IPv6: (none)\n\
             * IPv4: 127.0.0.1\n"
        );
    }

    // ---------------------------------------------------------------------
    // Curl_resolver_error -- lib/hostip.c:1570-1589.
    // ---------------------------------------------------------------------

    #[test]
    fn the_resolver_error_parenthesises_a_detail_and_omits_it_otherwise() {
        assert_eq!(
            resolver_error_message(
                ResolveTarget::Host,
                "example.com",
                Some("Name or service not known")
            ),
            "Could not resolve host: example.com (Name or service not known)"
        );
        assert_eq!(
            resolver_error_message(ResolveTarget::Host, "example.com", None),
            "Could not resolve host: example.com",
            "no trailing space and no empty parentheses"
        );
        assert_eq!(
            resolver_error_message(ResolveTarget::Proxy, "proxy.example", None),
            "Could not resolve proxy: proxy.example"
        );
    }

    #[test]
    fn each_resolve_target_carries_its_own_code() {
        assert_eq!(ResolveTarget::Host.label(), "host");
        assert_eq!(ResolveTarget::Proxy.label(), "proxy");
        assert_eq!(ResolveTarget::Host.code(), CURLcode::CouldntResolveHost);
        assert_eq!(ResolveTarget::Proxy.code(), CURLcode::CouldntResolveProxy);
    }

    #[test]
    fn the_frozen_message_table_matches_the_c_text() {
        // Transcribed from lib/hostip.c and compared here so that a formatter,
        // an editor or a well-meaning rewording cannot change program output
        // without a test failing.
        assert_eq!(
            msg::found_in_cache("example.com"),
            "Hostname example.com was found in DNS cache"
        );
        assert_eq!(
            msg::found_in_cache_quoted("example.com"),
            "Hostname 'example.com' was found in DNS cache",
            "the two spellings differ in quoting and must not be unified"
        );
        assert_ne!(
            msg::found_in_cache("example.com"),
            msg::found_in_cache_quoted("example.com")
        );
        assert_eq!(
            msg::STALE_ZAPPED,
            "Hostname in DNS cache was stale, zapped"
        );
        assert_eq!(
            msg::FAMILY_ZAPPED,
            "Hostname in DNS cache does not have needed family, zapped"
        );
        assert_eq!(
            msg::host_was_resolved("example.com", 80),
            "Host example.com:80 was resolved."
        );
        assert_eq!(msg::NONE, "(none)");
        assert_eq!(msg::TOO_MANY_IP, "too many IP, cannot show");
        assert_eq!(msg::ipv6_line("::1"), "IPv6: ::1");
        assert_eq!(msg::ipv4_line("127.0.0.1"), "IPv4: 127.0.0.1");
        assert_eq!(msg::ADDR_SEPARATOR, ", ");
        assert_eq!(msg::shuffling(3), "Shuffling 3 addresses");
        assert_eq!(
            msg::address_illegal("nope"),
            "Resolve address 'nope' found illegal"
        );
        assert_eq!(
            msg::resolve_unparsable("h:80"),
            "Could not parse CURLOPT_RESOLVE entry 'h:80'"
        );
        assert_eq!(
            msg::resolve_replaced("h.example", 80),
            "RESOLVE h.example:80 - old addresses discarded"
        );
        assert_eq!(
            msg::resolve_added("h.example", 80, "10.0.0.1", true),
            "Added h.example:80:10.0.0.1 to DNS cache"
        );
        assert_eq!(
            msg::resolve_added("h.example", 80, "10.0.0.1", false),
            "Added h.example:80:10.0.0.1 to DNS cache (non-permanent)"
        );
        assert_eq!(msg::resolve_wildcard(443), "RESOLVE *:443 using wildcard");
        assert_eq!(
            msg::store_negative("example.com", 80),
            "Store negative name resolve for example.com:80"
        );
        assert_eq!(msg::NEGATIVE_ENTRY, "Negative DNS entry");
        assert_eq!(msg::NO_ONION, "Not resolving .onion address (RFC 7686)");
    }

    // ---------------------------------------------------------------------
    // The IPv6 probe and can_resolve_ip_version -- lib/hostip.c:752-820.
    // ---------------------------------------------------------------------

    #[test]
    fn the_ipv6_answer_is_memoised_after_one_probe() {
        // "the nature of most systems is that IPv6 status does not come and go
        // during a program's lifetime so we only probe the first time"
        // -- lib/hostip.c:749-751.
        #[derive(Debug)]
        struct Counting {
            calls: std::cell::Cell<usize>,
            answer: bool,
        }
        impl Ipv6Probe for Counting {
            fn probe(&self) -> CodeResult<bool> {
                self.calls.set(self.calls.get() + 1);
                Ok(self.answer)
            }
        }

        let probe = Counting {
            calls: std::cell::Cell::new(0),
            answer: true,
        };
        let support = Ipv6Support::new();
        assert_eq!(support.cached(), None);
        assert_eq!(support.works(&probe), Ok(true));
        assert_eq!(support.works(&probe), Ok(true));
        assert_eq!(support.works(&probe), Ok(true));
        assert_eq!(probe.calls.get(), 1, "probed once, then remembered");
        assert_eq!(support.cached(), Some(true));
    }

    #[test]
    fn a_known_answer_never_probes() {
        #[derive(Debug)]
        struct Forbidden;
        impl Ipv6Probe for Forbidden {
            fn probe(&self) -> CodeResult<bool> {
                panic!("a known answer must not consult the probe");
            }
        }
        assert_eq!(Ipv6Support::known(false).works(&Forbidden), Ok(false));
        assert_eq!(Ipv6Support::known(true).works(&Forbidden), Ok(true));
    }

    #[test]
    fn a_failing_probe_propagates_and_records_that_ipv6_is_absent() {
        // C assigns `multi->ipv6_works = FALSE` BEFORE testing the socket and
        // returns the error without clearing it, so a caller that ignores the
        // code still sees the pessimistic answer.
        let support = Ipv6Support::new();
        let probe = FixedIpv6Probe(Err(CURLcode::OutOfMemory));
        assert_eq!(support.works(&probe), Err(CURLcode::OutOfMemory));
        assert_eq!(support.cached(), Some(false));
        // And the memoised false answers the next call without erring again.
        assert_eq!(support.works(&probe), Ok(false));
    }

    #[test]
    fn only_a_v6_request_consults_the_ipv6_probe() {
        let absent = Ipv6Support::known(false);
        let present = Ipv6Support::known(true);
        let probe = FixedIpv6Probe(Ok(true));

        assert_eq!(
            can_resolve_ip_version(IpVersion::V6, &absent, &probe),
            Ok(false),
            "asking for IPv6 without IPv6 cannot be satisfied"
        );
        assert_eq!(
            can_resolve_ip_version(IpVersion::V6, &present, &probe),
            Ok(true)
        );
        for version in [IpVersion::Whatever, IpVersion::V4] {
            assert_eq!(
                can_resolve_ip_version(version, &absent, &probe),
                Ok(true),
                "{version:?} never depends on IPv6"
            );
        }
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "this deliberately performs a real socket(2), which Miri \
                  cannot execute; every caller above it takes its answer \
                  through the Ipv6Probe seam precisely so that only this one \
                  test needs the exclusion"
    )]
    fn the_socket_probe_reaches_the_operating_system() {
        // The one test that is allowed to touch the host. It asserts only that
        // the probe answers rather than which answer it gives: a container
        // without IPv6 must not fail the suite, and the answer is exactly what
        // the seam exists to make substitutable everywhere else.
        let answer = SocketIpv6Probe.probe();
        assert!(
            answer == Ok(true) || answer == Ok(false),
            "a probe reports availability, or OutOfMemory: {answer:?}"
        );
    }

    // ---------------------------------------------------------------------
    // split_families -- the contract conn/happy_eyeballs.rs inherits.
    // ---------------------------------------------------------------------

    #[test]
    fn splitting_preserves_the_order_within_each_family() {
        let addrs = vec![v4(1, 80), v6(1, 80), v4(2, 80), v6(2, 80), v4(3, 80)];
        let split = split_families(&addrs);
        let render = |list: &[ResolvedAddr]| -> Vec<String> {
            list.iter().map(ResolvedAddr::printable_address).collect()
        };
        assert_eq!(render(&split.v6), ["::1", "::2"]);
        assert_eq!(render(&split.v4), ["127.0.0.1", "127.0.0.2", "127.0.0.3"]);
    }

    #[test]
    fn splitting_drops_a_unix_address_and_survives_an_empty_list() {
        let unix = unix2addr(Path::new("/run/curl.sock"), false)
            .expect("a short path");
        let split = split_families(&[unix]);
        assert!(split.v4.is_empty() && split.v6.is_empty());
        assert_eq!(split_families(&[]), AddrFamilies::default());
    }

    #[test]
    fn splitting_a_localhost_list_yields_the_c_race_order() {
        // The two "balls" of Happy Eyeballs, and the reason the synthesis
        // order matters: `::1` is the IPv6 candidate and `127.0.0.1` the IPv4
        // one, each alone in its list.
        let split = split_families(&localhost_addrs(80, "localhost"));
        assert_eq!(split.v6.len(), 1);
        assert_eq!(split.v6[0].printable_address(), "::1");
        assert_eq!(split.v4.len(), 1);
        assert_eq!(split.v4[0].printable_address(), "127.0.0.1");
    }

    // ---------------------------------------------------------------------
    // Constants, measured against the C.
    // ---------------------------------------------------------------------

    #[test]
    fn the_constants_are_the_measured_c_values() {
        assert_eq!(MAX_HOSTCACHE_LEN, 262, "lib/hostip.c:76, (255 + 7)");
        assert_eq!(MAX_HOSTCACHE_HOST_LEN, 255);
        assert_eq!(MAX_DNS_CACHE_SIZE, 29_999, "lib/hostip.c:78");
        assert_eq!(CURL_TIMEOUT_RESOLVE, 300, "lib/hostip.h:38-39");
        assert_eq!(
            MAX_IPADR_LEN,
            "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255".len() + 1,
            "lib/urldata.h:124 is a sizeof, so it includes the terminator"
        );
        assert_eq!(SHOW_RESOLVE_BUDGET, 1_024, "lib/hostip.c:143-146");
        assert_eq!(RESOLVE_ADDRESS_MAX, 64, "lib/hostip.c:1327, char[64]");
        assert_eq!(RESOLVE_HOST_MAX, 4_096);
        assert_eq!(RESOLVE_PORT_MAX, 0xffff);
        assert_eq!(DNS_CACHE_TIMEOUT_FOREVER, -1);
        // `sizeof(struct sockaddr_un::sun_path)`, asserted per target
        // rather than tautologically: the value is a compile-time constant, so
        // it is compared against the platform that selected it.
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        assert_eq!(UNIX_PATH_MAX, 104, "Apple platforms");
        #[cfg(not(any(target_os = "macos", target_os = "ios")))]
        assert_eq!(UNIX_PATH_MAX, 108, "Linux");
        assert_eq!(WILDCARD_HOST, b"*");
    }

    #[test]
    fn the_resolver_seam_is_object_safe_and_usable_behind_a_reference() {
        // The reason `resolve` returns a boxed future rather than
        // return-position `impl Trait`: `&dyn Resolver` must exist, and a trait
        // with an RPITIT method is not object-safe at any Rust version. This
        // test is that requirement, executable -- it would not compile if the
        // seam were declared the other way.
        #[derive(Debug)]
        struct Fixed(Vec<ResolvedAddr>);

        impl Resolver for Fixed {
            fn resolve<'a>(
                &'a self,
                _host: &'a str,
                _port: u16,
                ip_version: IpVersion,
            ) -> ResolveFuture<'a, Vec<ResolvedAddr>> {
                let wanted = ip_version.required_family();
                let answer: Vec<ResolvedAddr> = self
                    .0
                    .iter()
                    .filter(|addr| wanted.accepts(addr.family()))
                    .cloned()
                    .collect();
                Box::pin(async move {
                    if answer.is_empty() {
                        Err(CURLcode::CouldntResolveHost)
                    } else {
                        Ok(answer)
                    }
                })
            }
        }

        /// `Option<AddressFamily>` as a filter: `None` takes every family.
        trait FamilyFilter {
            fn accepts(self, family: AddressFamily) -> bool;
        }
        impl FamilyFilter for Option<AddressFamily> {
            fn accepts(self, family: AddressFamily) -> bool {
                match self {
                    None => true,
                    Some(required) => required == family,
                }
            }
        }

        let concrete = Fixed(vec![v6(1, 80), v4(1, 80)]);
        let injected: &dyn Resolver = &concrete;

        let both =
            block_on(injected.resolve("h.example", 80, IpVersion::Whatever))
                .expect("both families are present");
        assert_eq!(both.len(), 2);
        // The combined order is preserved, which is what a race observes.
        assert_eq!(both[0].family(), AddressFamily::Inet6);

        let four = block_on(injected.resolve("h.example", 80, IpVersion::V4))
            .expect("IPv4 is present");
        assert_eq!(four.len(), 1);
        assert_eq!(four[0].family(), AddressFamily::Inet);

        let empty = Fixed(Vec::new());
        let injected: &dyn Resolver = &empty;
        assert_eq!(
            block_on(injected.resolve("h.example", 80, IpVersion::Whatever)),
            Err(CURLcode::CouldntResolveHost)
        );
    }

    #[test]
    fn the_doh_seam_is_object_safe_and_carries_only_bytes() {
        // The seam that lets doh.rs perform an HTTPS transfer without naming
        // `crate::protocols`, and so without a dns -> protocols -> dns cycle.
        #[derive(Debug)]
        struct Echo;
        impl DohTransport for Echo {
            fn post<'a>(
                &'a self,
                url: &'a str,
                query: &'a [u8],
            ) -> ResolveFuture<'a, Vec<u8>> {
                Box::pin(async move {
                    if url.starts_with("https://") {
                        Ok(query.to_vec())
                    } else {
                        Err(CURLcode::CouldntResolveHost)
                    }
                })
            }
        }

        let injected: &dyn DohTransport = &Echo;
        assert_eq!(
            block_on(injected.post("https://doh.example/dns-query", b"wire")),
            Ok(b"wire".to_vec())
        );
        assert_eq!(
            block_on(injected.post("http://doh.example/dns-query", b"wire")),
            Err(CURLcode::CouldntResolveHost)
        );
    }

    /// Drives a future to completion on a current-thread runtime.
    ///
    /// The seams above are `async` because resolution is, and a unit test needs
    /// an executor to observe one. `tokio`'s current-thread runtime is the same
    /// one `curl-rs/src/main.rs` builds, so nothing here depends on a shape the
    /// production code does not have.
    fn block_on<F: core::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .map(|runtime| runtime.block_on(future))
            .unwrap_or_else(|error| {
                panic!("a current-thread runtime must build: {error}")
            })
    }
}
