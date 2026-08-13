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

//! Public Suffix List integration -- supersedes `lib/psl.c` and `lib/psl.h`,
//! replacing the `libpsl` binding with the `publicsuffix` crate.
//!
//! Two consumers, and no others:
//!
//! * `is_public_suffix` in [`super`] -- the port of `lib/cookie.c:774-819`.
//!   It calls [`PslCache::use_list`] to obtain a list and
//!   [`is_cookie_domain_acceptable`] to reach a verdict, and it owns the
//!   log text and the length cut-off described below.
//! * `crate::version` -- which must report the `PSL` capability truthfully,
//!   and therefore asks [`available`] rather than assuming.
//!
//! # What the C does, line by line
//!
//! `Curl_psl_use` (`lib/psl.c:42-95`) is a cache with a 72-hour
//! time-to-live. Stripped of its locking, which is not this module's job
//! (see below), it is:
//!
//! 1. `lib/psl.c:48-49` -- no cache at all yields no list.
//! 2. `lib/psl.c:52` -- read the clock. `Curl_pgrs_now(easy)->tv_sec`, which
//!    is the **monotonic** reading; see the section on the clock.
//! 3. `lib/psl.c:53` -- refresh when `!psl || expires <= now_sec`. Note
//!    `<=`, so a list whose deadline equals the current second is stale.
//! 4. `lib/psl.c:61-63` -- after taking exclusive access, a recheck that is
//!    deliberately **narrower** than step 3: it tests only `expires`, and
//!    its only effect is to re-read the clock.
//! 5. `lib/psl.c:64` -- then the full condition again.
//! 6. `lib/psl.c:69-79` -- load, in two tiers. `psl_latest()` first, which
//!    marks the cache *dynamic*; `psl_builtin()` only if that failed **and**
//!    the cached list is not already dynamic.
//! 7. `lib/psl.c:72-73` -- the new deadline, with an explicit overflow
//!    guard. The assignment sits unconditionally inside the
//!    modern-`libpsl` arm, so the built-in fallback receives the same
//!    72-hour deadline as a freshly downloaded list. It is *not* true that
//!    the deadline applies only to the dynamic list.
//! 8. `lib/psl.c:81-86` -- install only on success. A failed refresh leaves
//!    both the previous list **and** its already-expired deadline in place,
//!    so every subsequent call retries. That is intentional and is
//!    preserved.
//!
//! # The clock is injected, and it is the monotonic one
//!
//! `lib/psl.c:52` and `lib/psl.c:62` read `Curl_pgrs_now(easy)->tv_sec`,
//! which is `curlx_pnow` (`lib/progress.c:171-177`), which is
//! `CLOCK_MONOTONIC_RAW` or `CLOCK_MONOTONIC` (`lib/curlx/timeval.c:50-99`,
//! whose own comment notes that the "time starting point is unspecified").
//! **This module therefore uses `Clock::now().secs`, never
//! `Clock::epoch_secs()`.** Its three siblings in this directory -- the
//! cookie engine itself, `hsts` and `altsvc` -- all use `time(NULL)`, which
//! is the wall reading. Getting it backwards would make a 72-hour deadline
//! depend on wall-clock jumps.
//!
//! Injection is faithful to the C rather than a Rust affectation: the C tree
//! already substitutes its own clock for testability, at `lib/hsts.c:50-64`
//! and `lib/altsvc.c:431-447`, where a
//! `#if defined(DEBUGBUILD) || defined(UNITTESTS)` shim reads the
//! `CURL_TIME` environment variable and then redefines `time`. That
//! mechanism is deliberately **not** reproduced; the injected trait replaces
//! it.
//!
//! # Locking belongs to `share/`, not here
//!
//! One hazard for that layer, recorded so it is not discovered the hard way:
//! `crate::share` is `pub` while `super` is `pub(crate)`, so naming
//! [`PslCache`] in a `pub` signature there is
//! `error[E0446]: private type in public interface`. The resolution is for
//! `crate::share` to keep it behind its own opaque `pub` wrapper -- which
//! mirrors the C, where `CURLSH` is literally `typedef void CURLSH` -- or
//! for the crate root to add a curated re-export. The types here stay
//! `pub(crate)` deliberately and are not widened to paper over it.

use core::fmt;

use publicsuffix::{List, Psl};

use crate::util::timeval::Clock;

/// How long a loaded list is used before it is reloaded, in seconds.
#[allow(dead_code)]
pub(crate) const PSL_TTL: i64 = 72 * 3600;

/// The size of the C's fixed lowering buffers, and therefore the length at
/// which the public-suffix check is skipped.
#[allow(dead_code)]
pub(crate) const MAX_PSL_DOMAIN_LEN: usize = 256;

/// Where the Public Suffix List text comes from.
#[allow(dead_code)]
pub(crate) trait PslSource: fmt::Debug {
    /// The refreshable list -- the `psl_latest()` analogue
    /// (`lib/psl.c:69`).
    ///
    /// Returning `Some` marks the cache *dynamic* (`lib/psl.c:70`), which
    /// suppresses the built-in fallback on subsequent refreshes.
    fn latest(&self) -> Option<Vec<u8>>;

    /// The fixed list -- the `psl_builtin()` analogue (`lib/psl.c:79`).
    ///
    /// Consulted only when [`Self::latest`] yielded nothing **and** the cache
    /// is not already holding a dynamic list (`lib/psl.c:76`).
    fn builtin(&self) -> Option<Vec<u8>>;
}

/// A [`PslSource`] serving both tiers from bytes held in memory.
///
/// Deliberately not `#[cfg(test)]`-gated, exactly as
/// `crate::util::timeval::TestClock` is not: the configuration layer that
/// owns the list bytes injects them through this type, and the tests in this
/// file use the same type, so the tests exercise the production path rather
/// than a parallel one.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct MemoryPslSource {
    /// Served by [`PslSource::latest`]; `None` means that tier is absent.
    latest: Option<Vec<u8>>,
    /// Served by [`PslSource::builtin`]; `None` means that tier is absent.
    builtin: Option<Vec<u8>>,
}

#[allow(dead_code)]
impl MemoryPslSource {
    /// A source with both tiers absent -- a configured source that always
    /// fails to load.
    pub(crate) fn empty() -> Self {
        Self::default()
    }

    /// A source offering `text` as the refreshable tier only.
    ///
    /// A cache loading from it becomes dynamic, so it will never fall back to
    /// the built-in tier afterwards.
    pub(crate) fn latest(text: impl Into<Vec<u8>>) -> Self {
        Self {
            latest: Some(text.into()),
            builtin: None,
        }
    }

    /// A source offering `text` as the fixed tier only.
    pub(crate) fn builtin(text: impl Into<Vec<u8>>) -> Self {
        Self {
            latest: None,
            builtin: Some(text.into()),
        }
    }

    /// A source offering both tiers.
    pub(crate) fn new(
        latest: Option<Vec<u8>>,
        builtin: Option<Vec<u8>>,
    ) -> Self {
        Self { latest, builtin }
    }
}

impl PslSource for MemoryPslSource {
    fn latest(&self) -> Option<Vec<u8>> {
        self.latest.clone()
    }

    fn builtin(&self) -> Option<Vec<u8>> {
        self.builtin.clone()
    }
}

/// The cached Public Suffix List and its deadline.
#[derive(Debug, Default)]
#[allow(dead_code)]
pub(crate) struct PslCache {
    /// `lib/psl.h:35` -- `const psl_ctx_t *psl`, the list itself.
    ///
    /// Owned rather than borrowed, which is what makes
    /// [`Self::destroy`]'s C counterpart -- a conditional `psl_free` -- fall
    /// out of `Drop` instead of needing the `dynamic` flag to decide.
    psl: Option<List>,
    /// `lib/psl.h:36` -- `time_t expires`, the instant the list goes stale,
    /// on the **monotonic** clock. Compared with `<=`, so equality is stale.
    expires: i64,
    /// `lib/psl.h:37` -- `BIT(dynamic)`.
    ///
    /// In C this decides whether `psl_free` is called. Here it survives for
    /// the other reason it exists: `lib/psl.c:76` consults it to decide
    /// whether the built-in tier may be tried.
    dynamic: bool,
}

#[allow(dead_code)]
impl PslCache {
    /// A cache holding no list.
    ///
    /// Equivalent to the zeroed C structure, and therefore stale.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Releases the cached list -- `Curl_psl_destroy`, `lib/psl.c:32-40`.
    pub(crate) fn destroy(&mut self) {
        // C: lib/psl.c:34 -- the whole reset sits behind `if(pslcache->psl)`,
        // so destroying an already-empty cache changes nothing, `dynamic`
        // included. Kept verbatim rather than simplified to an
        // unconditional reset.
        if self.psl.is_some() {
            self.psl = None;
            self.dynamic = false;
        }
    }

    /// Returns the cached list, refreshing it first when it is stale --
    /// `Curl_psl_use`, `lib/psl.c:42-95`, minus the locking.
    pub(crate) fn use_list(
        &mut self,
        clock: &dyn Clock,
        source: &dyn PslSource,
    ) -> Option<&List> {
        // C: lib/psl.c:52 -- `Curl_pgrs_now(easy)->tv_sec`, which is
        // `curlx_pnow` (lib/progress.c:171-177) and therefore
        // CLOCK_MONOTONIC_RAW/CLOCK_MONOTONIC (lib/curlx/timeval.c:50-99).
        // The wall clock is deliberately not used here; see the module
        // documentation.
        let mut now_sec = clock.now().secs;

        // C: lib/psl.c:53 -- `<=`, so a deadline equal to the current second
        // is already stale.
        if self.psl.is_none() || self.expires <= now_sec {
            // C: lib/psl.c:61-64 -- the recheck tests only `expires` and
            // merely refreshes `now_sec`; the full re-test follows. Kept
            // verbatim.
            if self.expires <= now_sec {
                now_sec = clock.now().secs;
            }
            if self.psl.is_none() || self.expires <= now_sec {
                // C: lib/psl.c:65-66 declares `dynamic = FALSE` and
                // `expires = TIME_T_MAX` and then overwrites both, at
                // lib/psl.c:70 and lib/psl.c:72-73, because this port takes
                // the modern-libpsl arm unconditionally. Writing the dead
                // initialisers literally would trip `unused_assignments`
                // under the crate's zero-warning gate, so the final values
                // are bound directly and the C's initialisers are recorded
                // here instead.

                // C: lib/psl.c:69-70.
                let mut psl = source.latest().and_then(parse_list);
                let dynamic = psl.is_some();

                // C: lib/psl.c:72-73 -- `(now_sec < TIME_T_MAX - PSL_TTL) ?
                // (now_sec + PSL_TTL) : TIME_T_MAX`, which for
                // TIME_T_MAX == i64::MAX is exactly a saturating add. The
                // assignment is unconditional inside that arm, so the
                // built-in fallback below receives the same deadline.
                let expires = now_sec.saturating_add(PSL_TTL);

                // C: lib/psl.c:76 -- the built-in list is tried only when
                // the refreshable one failed AND the cached list is not
                // already dynamic, so a working download is never replaced
                // by the fixed list.
                if psl.is_none() && !self.dynamic {
                    psl = source.builtin().and_then(parse_list);
                }

                // C: lib/psl.c:81-86 -- install only on success.
                if let Some(list) = psl {
                    self.destroy();
                    self.psl = Some(list);
                    self.dynamic = dynamic;
                    self.expires = expires;
                }
            }
        }

        // C: lib/psl.c:91-94.
        self.psl.as_ref()
    }

    /// Whether a list is currently cached, without touching the clock.
    ///
    /// For `crate::share`'s bookkeeping and for tests; the C reads
    /// `pslcache->psl` directly for the same purpose.
    pub(crate) fn has_list(&self) -> bool {
        self.psl.is_some()
    }

    /// The cached list as it stands, refreshing nothing --
    /// `pslcache->psl` read directly, as `lib/psl.c:91` reads it.
    ///
    /// The companion to [`Self::use_list`], and the one the *shared* phase
    /// needs. `Curl_psl_use` performs its refresh only inside the exclusive
    /// phase (`lib/psl.c:58-88`) and then re-takes the shared lock before
    /// reading `pslcache->psl` at `:91` and returning it at `:94`; that final
    /// read mutates nothing, which is exactly why holding it shared is sound
    /// in the C. `&self` says the same thing to the compiler, so a caller
    /// holding no more than a reader can still hand the list out.
    ///
    /// [`None`] carries `lib/psl.c:92`'s meaning -- `if(!psl)`, no usable
    /// list -- and a caller must fail closed, as [`Self::use_list`] records.
    pub(crate) fn list(&self) -> Option<&List> {
        // C: lib/psl.c:91 -- `psl = pslcache->psl;`.
        self.psl.as_ref()
    }

    /// `lib/psl.h:37`'s `dynamic` bit.
    pub(crate) fn is_dynamic(&self) -> bool {
        self.dynamic
    }

    /// `lib/psl.h:36`'s `expires`, on the monotonic clock.
    pub(crate) fn expires(&self) -> i64 {
        self.expires
    }
}

/// Parses list text, discarding the reason it failed.
#[allow(dead_code)]
fn parse_list(text: Vec<u8>) -> Option<List> {
    List::from_bytes(&text).ok()
}

/// Whether public-suffix checking is genuinely available.
///
/// `None` -- no source configured -- is the `#ifndef USE_LIBPSL` state: the
/// caller uses `bad_domain` (`lib/cookie.c:327-342`) and `PSL` must not be
/// advertised. `Some` with a source that cannot produce a list is the
/// *configured but broken* state, which is the `#ifdef` arm with a `NULL`
/// list and must fail closed. Reporting `PSL` optimistically converts a
/// clean fixture skip into a hard failure, so the load is actually attempted
/// rather than assumed.
#[allow(dead_code)]
pub(crate) fn available(source: Option<&dyn PslSource>) -> bool {
    match source {
        // The `#ifndef USE_LIBPSL` build: there is no list and there never
        // was going to be one.
        None => false,
        Some(source) => source
            .latest()
            .and_then(parse_list)
            .or_else(|| source.builtin().and_then(parse_list))
            .is_some(),
    }
}

/// The part of `name` that nobody can register -- its public suffix, and the
/// analogue of `psl_unregistrable_domain`.
///
/// 1. **A lone label is its own public suffix.** The algorithm's implicit `*`
///    rule covers every unlisted label, so an unlisted top-level domain is
///    one. The crate agrees for a label that is valid UTF-8 and reports
///    nothing at all for one that is not, where `libpsl` still answers -- so
///    the rule is stated rather than left to the lookup.
/// 2. **A wildcard rule makes its own parent a public suffix.** The list
///    carries `*.compute-1.amazonaws.com` and no bare
///    `compute-1.amazonaws.com`, and `libpsl` treats the bare name as a public
///    suffix anyway. The crate does not, so the parent case is asked
///    separately by looking up `*.` followed by the name: a literal `*` label
///    occurs in no other rule, so that lookup succeeds exactly when a wildcard
///    rule for this parent exists. Only the immediate parent is affected, so
///    `amazonaws.com` is unaffected by that rule.
/// 3. Otherwise the crate's own answer.
#[allow(dead_code)]
pub(crate) fn unregistrable_domain<'a>(
    list: &List,
    name: &'a [u8],
) -> Option<&'a [u8]> {
    if name.is_empty() {
        return None;
    }
    // Step 1.
    if !name.contains(&b'.') {
        return Some(name);
    }
    // Step 2.
    let mut wildcard = Vec::with_capacity(name.len().saturating_add(2));
    wildcard.extend_from_slice(b"*.");
    wildcard.extend_from_slice(name);
    if spans_whole_name(list, &wildcard) {
        return Some(name);
    }
    // Step 3.
    list.suffix(name).map(|suffix| {
        let length = suffix.as_bytes().len();
        // The suffix the crate reports is a byte range at the end of `name`,
        // so it is reborrowed from `name` rather than from the temporary, and
        // a length that somehow exceeded the name yields the whole name.
        name.get(name.len().saturating_sub(length)..)
            .unwrap_or(name)
    })
}

/// Whether the public suffix the list reports for `name` is `name` itself.
///
/// The comparison is on the byte span rather than through `Suffix`'s own
/// equality, which is trailing-dot-insensitive and would report
/// `example.com.` as equal to its own suffix `com.`.
fn spans_whole_name(list: &List, name: &[u8]) -> bool {
    list.suffix(name)
        .is_some_and(|suffix| suffix.as_bytes() == name)
}

/// Whether `cookie_domain` may set cookies for `host` --
/// `psl_is_cookie_domain_acceptable(psl, hostname, cookie_domain)`.
#[allow(dead_code)]
pub(crate) fn is_cookie_domain_acceptable(
    list: &List,
    host: &[u8],
    cookie_domain: &[u8],
) -> bool {
    // libpsl: `while (*cookie_domain == '.') cookie_domain++;` -- every
    // leading dot, not just one.
    let cookie_domain = strip_leading_dots(cookie_domain);

    // libpsl: an exact match is always acceptable, and it is tested before
    // anything else -- which is why a cookie whose domain equals a
    // registry-level host name is stored. tests/data/test1136 depends on
    // this for z-1.compute-1.amazonaws.com.
    if host == cookie_domain {
        return true;
    }

    // libpsl: `if (hostname_length <= cookie_domain_length) return 0;`. The
    // equal-length case has already been handled above, so a zero offset
    // here means equal lengths with different bytes.
    let Some(at) = host.len().checked_sub(cookie_domain.len()) else {
        return false;
    };
    if at == 0 {
        return false;
    }

    // libpsl: `if (*(p - 1) != '.' || strcmp(p, cookie_domain)) return 0;`.
    // The label boundary is what stops `o.example.com` passing for
    // `foo.example.com`, and the comparison is byte-exact.
    if host.get(..at).and_then(|head| head.last()) != Some(&b'.') {
        return false;
    }
    if host.get(at..) != Some(cookie_domain) {
        return false;
    }

    // libpsl: an IP literal host accepts nothing but the exact match above.
    // Measured, because the rule is invisible in the C: `1.2.3.4` may not
    // set a cookie for `2.3.4`, while `01.2.3.4` and `1.2.3.256` may,
    // because inet_pton rejects those.
    if host_is_ip_literal(host) {
        return false;
    }

    // libpsl: and finally, the cookie domain must reach at least one label
    // below the part of the host nobody can register. Both it and that part
    // are label-boundary suffixes of the same host, so "strictly longer" is
    // "at least one more label", which is the registrable domain or deeper.
    let Some(unregistrable) = unregistrable_domain(list, host) else {
        // A host that cannot be classified is refused rather than trusted.
        return false;
    };
    cookie_domain.len() > unregistrable.len()
}

// Fully qualified hosts: where the corpus and the locally installed libpsl
// disagree, and why the corpus wins. Recorded beside the code it concerns
// rather than left for someone to rediscover.

/// `name` with every leading `.` removed.
///
/// libpsl's `while (*cookie_domain == '.') cookie_domain++;`. All of them, so
/// `..example.com` reduces to `example.com` and `...` reduces to nothing.
fn strip_leading_dots(name: &[u8]) -> &[u8] {
    let mut rest = name;
    while let Some((&b'.', tail)) = rest.split_first() {
        rest = tail;
    }
    rest
}

/// Whether `host` is an IP address literal rather than a name.
///
/// libpsl reaches this conclusion with `inet_pton`, for both families, and
/// the two recognisers below reproduce that exactly. They are deliberately
/// local: the rule being expressed is **libpsl's**, applied to the request
/// host, and it is a different rule from curl's own `Curl_host_is_ipnum`,
/// which the cookie engine applies to the cookie *domain* before calling
/// here at all. Sharing one implementation between the two would merge two
/// contracts that happen to agree today.
fn host_is_ip_literal(host: &[u8]) -> bool {
    pton4(host) || pton6(host)
}

/// Whether `text` is a dotted-quad IPv4 literal, by `inet_pton`'s rules.
fn pton4(text: &[u8]) -> bool {
    let mut octets = 0_usize;
    for field in text.split(|byte| *byte == b'.') {
        octets += 1;
        if octets > 4 {
            return false;
        }
        // An empty field covers both a doubled dot and a leading or
        // trailing one, so `1..2.3.4` and `1.2.3.4.` are both rejected here.
        if field.is_empty() || field.len() > 3 {
            return false;
        }
        if !field.iter().all(u8::is_ascii_digit) {
            return false;
        }
        // glibc's inet_pton refuses a leading zero, so `1.2.3.04` is not an
        // address even though its value would be in range.
        if field.len() > 1 && field.first() == Some(&b'0') {
            return false;
        }
        let mut value = 0_u32;
        for byte in field {
            // Three digits at most, so `value` stays below 1000 and neither
            // operation can overflow; and every byte is an ASCII digit, so
            // the subtraction cannot wrap.
            value = value * 10 + u32::from(*byte - b'0');
        }
        if value > 255 {
            return false;
        }
    }
    octets == 4
}

/// Whether `text` is an IPv6 literal, by `inet_pton`'s rules.
fn pton6(text: &[u8]) -> bool {
    let fields: Vec<&[u8]> = text.split(|byte| *byte == b':').collect();
    // Splitting always yields at least one field, so fewer than two means
    // there is no colon at all and this cannot be an IPv6 literal. A bare
    // IPv4 address lands here, which is why [`pton4`] is tried separately.
    if fields.len() < 2 {
        return false;
    }
    let Some(last) = fields.len().checked_sub(1) else {
        return false;
    };

    // An empty field marks a run of colons. `::` shows up as one empty field
    // in the interior, or as two at the front or the back; anything else is
    // a stray colon or a second `::`, both of which are invalid.
    let empty: Vec<usize> = fields
        .iter()
        .enumerate()
        .filter(|(_, field)| field.is_empty())
        .map(|(index, _)| index)
        .collect();
    let (gap, groups): (bool, Vec<&[u8]>) = match empty.as_slice() {
        // No `::`: every field is a group.
        [] => (false, fields.clone()),
        // `::` on its own, the unspecified address. Three empty fields can
        // only come from a text of exactly two colons and nothing else.
        [0, 1, 2] if last == 2 => (true, Vec::new()),
        // A leading `::`, which also covers `::` on its own.
        [0, 1] => (true, fields.iter().skip(2).copied().collect()),
        // A trailing `::`.
        [first, second] if first + 1 == *second && *second == last => {
            (true, fields.iter().take(*first).copied().collect())
        }
        // An interior `::`.
        [only] if *only > 0 && *only < last => (
            true,
            fields
                .iter()
                .enumerate()
                .filter(|(index, _)| index != only)
                .map(|(_, field)| *field)
                .collect(),
        ),
        _ => return false,
    };

    let count = groups.len();
    let mut words = 0_usize;
    for (index, group) in groups.iter().enumerate() {
        if group.is_empty() {
            return false;
        }
        // The embedded IPv4 form is allowed only as the final group, and it
        // occupies two of the eight words.
        if index + 1 == count && pton4(group) {
            words += 2;
            continue;
        }
        if group.len() > 4 || !group.iter().all(u8::is_ascii_hexdigit) {
            return false;
        }
        words += 1;
    }

    if gap {
        // `::` stands for one or more omitted words, so a full complement
        // leaves it nothing to stand for.
        words <= 7
    } else {
        words == 8
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::time::Duration;

    use super::*;
    use crate::util::strcase;
    use crate::util::timeval::{CurlTime, TestClock};

    /// A Public Suffix List small enough to read and large enough to be
    /// interesting.
    const LIST: &str = concat!(
        "// ===BEGIN ICANN DOMAINS===\n",
        "com\n",
        "uk\n",
        "co.uk\n",
        "*.ck\n",
        "!www.ck\n",
        "jp\n",
        "*.kobe.jp\n",
        "!city.kobe.jp\n",
        "us\n",
        "ma.us\n",
        "k12.ma.us\n",
        "pvt.k12.ma.us\n",
        "// ===END ICANN DOMAINS===\n",
        "// ===BEGIN PRIVATE DOMAINS===\n",
        "blogspot.com\n",
        "*.compute-1.amazonaws.com\n",
        "// ===END PRIVATE DOMAINS===\n",
    );

    /// Host, cookie domain and the verdict, measured against `libpsl` 0.21.2
    /// loaded with [`LIST`].
    const VECTORS: &[(&str, &str, bool)] = &[
        // Ordinary registrable domains.
        ("www.example.com", "example.com", true),
        ("www.example.com", "com", false),
        ("www.example.com", "www.example.com", true),
        ("example.com", "example.com", true),
        ("com", "com", true),
        ("sub.www.example.com", "www.example.com", true),
        ("sub.www.example.com", "example.com", true),
        ("a.b.c.example.com", "c.example.com", true),
        // Leading dots are stripped, all of them; an empty remainder is not
        // acceptable.
        ("www.example.com", ".example.com", true),
        ("www.example.com", "..example.com", true),
        ("www.example.com", "", false),
        ("www.example.com", ".", false),
        ("foo.example.com", "o.example.com", false),
        // Wildcard rules, and the exception that undoes one.
        ("www.example.ck", "example.ck", false),
        ("www.example.ck", "www.example.ck", true),
        ("www.ck", "ck", false),
        ("www.ck", "www.ck", true),
        ("x.www.ck", "www.ck", true),
        ("www.city.kobe.jp", "city.kobe.jp", true),
        ("www.city.kobe.jp", "kobe.jp", false),
        ("x.y.kobe.jp", "y.kobe.jp", false),
        ("x.y.kobe.jp", "kobe.jp", false),
        // Multi-label ICANN suffixes.
        ("curl.co.uk", "co.uk", false),
        ("curl.co.uk", "curl.co.uk", true),
        ("www.curl.co.uk", "curl.co.uk", true),
        ("www.curl.co.uk", "co.uk", false),
        ("www.curl.co.uk", "uk", false),
        ("www.example.pvt.k12.ma.us", "example.pvt.k12.ma.us", true),
        ("www.example.pvt.k12.ma.us", "pvt.k12.ma.us", false),
        // The private section counts too.
        ("my.own.blogspot.com", "own.blogspot.com", true),
        ("my.own.blogspot.com", "blogspot.com", false),
        (
            "z-1.compute-1.amazonaws.com",
            "z-1.compute-1.amazonaws.com",
            true,
        ),
        (
            "a.z-1.compute-1.amazonaws.com",
            "z-1.compute-1.amazonaws.com",
            false,
        ),
        (
            "a.z-1.compute-1.amazonaws.com",
            "compute-1.amazonaws.com",
            false,
        ),
        // Names the list says nothing about: the implicit `*` rule makes the
        // bare label registry-level and the label below it registrable.
        ("www.example.invalidtld", "example.invalidtld", true),
        ("www.example.invalidtld", "invalidtld", false),
        ("invalidtld", "invalidtld", true),
        ("localhost", "localhost", true),
        ("foo.localhost", "localhost", false),
        // An IP-literal host accepts nothing but itself.
        ("1.2.3.4", "1.2.3.4", true),
        ("1.2.3.4", "2.3.4", false),
        ("1.2.3.4", "3.4", false),
        ("127.0.0.1", "0.0.1", false),
        ("01.2.3.4", "3.4", true),
        ("1.2.3.256", "3.256", true),
        ("1.2.3.4.5", "4.5", true),
        ("x.1.2.3.4", "2.3.4", true),
        ("a.b.4", "b.4", true),
        ("::ffff:1.2.3.4", "3.4", false),
        ("::1.2.3.4", "3.4", false),
        (":::1.2.3.4", "3.4", true),
        ("1:2:3:4:5:6:1.2.3.4", "3.4", false),
        ("1:2:3:4:5:1.2.3.4", "3.4", true),
        ("1:2:3:4:5::1.2.3.4", "3.4", false),
        ("1:2:3:4:5:6::1.2.3.4", "3.4", true),
        ("ABCD::1.2.3.4", "3.4", false),
        ("abcde::1.2.3.4", "3.4", true),
        ("::ffff:1.2.3.4%eth0", "3.4%eth0", true),
        ("[::ffff:1.2.3.4]", "3.4]", true),
        ("::ffff:1.2.3.256", "3.256", true),
        ("fe80::1.2.3.4", "3.4", false),
        // A trailing dot is part of the byte comparison, on both sides.
        ("www.example.com.", "example.com.", true),
        ("www.example.com", "example.com.", false),
        ("www.example.com.", "example.com", false),
    ];

    /// Names and whether `libpsl` 0.21.2 calls each one a public suffix, over
    /// [`LIST`]. Also measured rather than reasoned.
    const SUFFIXES: &[(&str, bool)] = &[
        ("com", true),
        ("uk", true),
        ("co.uk", true),
        ("example.com", false),
        ("www.example.com", false),
        // No bare `ck` rule exists, yet a lone label is always a suffix.
        ("ck", true),
        ("example.ck", true),
        // Undone by `!www.ck`.
        ("www.ck", false),
        ("jp", true),
        // No bare rule; a suffix only because `*.kobe.jp` exists.
        ("kobe.jp", true),
        ("y.kobe.jp", true),
        // Undone by `!city.kobe.jp`.
        ("city.kobe.jp", false),
        ("pvt.k12.ma.us", true),
        ("k12.ma.us", true),
        ("blogspot.com", true),
        ("own.blogspot.com", false),
        // The wildcard parent, and the label above it which is not one.
        ("compute-1.amazonaws.com", true),
        ("z-1.compute-1.amazonaws.com", true),
        ("amazonaws.com", false),
        // Unlisted entirely.
        ("invalidtld", true),
        ("localhost", true),
        ("example.invalidtld", false),
    ];

    /// Names and their `psl_unregistrable_domain`, measured against `libpsl`
    /// 0.21.2 over [`LIST`].
    const UNREGISTRABLE: &[(&str, &str)] = &[
        ("com", "com"),
        ("example.com", "com"),
        ("www.example.com", "com"),
        ("sub.www.example.com", "com"),
        ("a.b.c.example.com", "com"),
        ("foo.example.com", "com"),
        ("ck", "ck"),
        ("example.ck", "example.ck"),
        ("www.ck", "ck"),
        ("x.www.ck", "ck"),
        ("jp", "jp"),
        ("kobe.jp", "kobe.jp"),
        ("y.kobe.jp", "y.kobe.jp"),
        ("city.kobe.jp", "kobe.jp"),
        ("www.city.kobe.jp", "kobe.jp"),
        ("x.y.kobe.jp", "y.kobe.jp"),
        ("uk", "uk"),
        ("co.uk", "co.uk"),
        ("curl.co.uk", "co.uk"),
        ("www.curl.co.uk", "co.uk"),
        ("blogspot.com", "blogspot.com"),
        ("own.blogspot.com", "blogspot.com"),
        ("my.own.blogspot.com", "blogspot.com"),
        ("compute-1.amazonaws.com", "compute-1.amazonaws.com"),
        ("z-1.compute-1.amazonaws.com", "z-1.compute-1.amazonaws.com"),
        (
            "a.z-1.compute-1.amazonaws.com",
            "z-1.compute-1.amazonaws.com",
        ),
        ("amazonaws.com", "com"),
        ("invalidtld", "invalidtld"),
        ("example.invalidtld", "invalidtld"),
        ("www.example.invalidtld", "invalidtld"),
        ("localhost", "localhost"),
        ("foo.localhost", "localhost"),
        ("pvt.k12.ma.us", "pvt.k12.ma.us"),
        ("www.example.pvt.k12.ma.us", "pvt.k12.ma.us"),
        ("1.2.3.4", "4"),
        ("x.1.2.3.4", "4"),
    ];

    /// A [`PslSource`] that counts how often each tier is consulted.
    ///
    /// Wraps [`MemoryPslSource`] rather than reimplementing it, so the tests
    /// drive the production type and only observe the call pattern that
    /// `lib/psl.c:69-79` prescribes.
    #[derive(Debug)]
    struct CountingSource {
        inner: MemoryPslSource,
        latest_calls: Cell<usize>,
        builtin_calls: Cell<usize>,
        /// When set, [`PslSource::latest`] reports nothing regardless of what
        /// `inner` holds, which is how a download failure is simulated.
        latest_fails: Cell<bool>,
    }

    impl CountingSource {
        fn new(inner: MemoryPslSource) -> Self {
            Self {
                inner,
                latest_calls: Cell::new(0),
                builtin_calls: Cell::new(0),
                latest_fails: Cell::new(false),
            }
        }

        fn both() -> Self {
            Self::new(MemoryPslSource::new(
                Some(LIST.as_bytes().to_vec()),
                Some(LIST.as_bytes().to_vec()),
            ))
        }
    }

    impl PslSource for CountingSource {
        fn latest(&self) -> Option<Vec<u8>> {
            self.latest_calls.set(self.latest_calls.get() + 1);
            if self.latest_fails.get() {
                return None;
            }
            self.inner.latest()
        }

        fn builtin(&self) -> Option<Vec<u8>> {
            self.builtin_calls.set(self.builtin_calls.get() + 1);
            self.inner.builtin()
        }
    }

    /// Parses [`LIST`] the way [`PslCache`] does, for the tests that need a
    /// list without needing a cache.
    fn list() -> List {
        let parsed = parse_list(LIST.as_bytes().to_vec());
        assert!(parsed.is_some(), "the embedded list parses");
        parsed.unwrap_or_default()
    }

    /// `psl_is_public_suffix`, expressed through the primitive this module
    /// publishes.
    fn is_public_suffix(list: &List, name: &[u8]) -> bool {
        unregistrable_domain(list, name) == Some(name)
    }

    /// Lowers `text` the way `lib/cookie.c:796-797` lowers a name: raw ASCII
    /// folding into a buffer of exactly the C's size.
    fn lower(text: &[u8]) -> Vec<u8> {
        let mut buffer = [0_u8; MAX_PSL_DOMAIN_LEN];
        let written = strcase::strntolower(&mut buffer, text);
        // `written` is what the function reports it wrote, so the range is in
        // bounds; the fallback keeps this free of a panicking accessor.
        buffer.get(..written).unwrap_or(&[]).to_vec()
    }

    /// `lib/psl.h:32`.
    #[test]
    fn the_time_to_live_is_seventy_two_hours() {
        assert_eq!(PSL_TTL, 72 * 3600);
        assert_eq!(PSL_TTL, 259_200);
    }

    /// `lib/cookie.c:790-792`, expressed as the caller has to express it.
    ///
    /// The gate is `(dlen < sizeof(lcase)) && (clen < sizeof(lcookie))`, a
    /// **strict** comparison against the buffer size, so 255 is the longest
    /// name ever checked and a name of 256 or more skips the check with
    /// `acceptable` still `FALSE` -- the cookie is dropped with no log line.
    fn c_length_gate(host: &[u8], cookie_domain: &[u8]) -> bool {
        host.len() < MAX_PSL_DOMAIN_LEN
            && cookie_domain.len() < MAX_PSL_DOMAIN_LEN
    }

    /// The cut-off, driven through [`c_length_gate`] over real byte strings so
    /// that the lengths are run-time values rather than folded constants.
    #[test]
    fn the_length_cut_off_is_the_c_buffer_size() {
        assert_eq!(MAX_PSL_DOMAIN_LEN, 256);

        let short = vec![b'a'; MAX_PSL_DOMAIN_LEN - 1];
        let exact = vec![b'a'; MAX_PSL_DOMAIN_LEN];
        let over = vec![b'a'; MAX_PSL_DOMAIN_LEN + 1];
        assert_eq!(short.len(), 255);

        // Both within the buffers: the check runs.
        assert!(c_length_gate(&short, &short));
        // Either one at the buffer size or beyond: it does not, and the
        // caller's `acceptable` stays FALSE, so the cookie is dropped
        // silently.
        assert!(!c_length_gate(&exact, &short));
        assert!(!c_length_gate(&short, &exact));
        assert!(!c_length_gate(&over, &short));
        assert!(!c_length_gate(&short, &over));
        assert!(!c_length_gate(&exact, &exact));

        // A realistic pair that the gate admits, to show it is not simply
        // refusing everything.
        assert!(c_length_gate(b"www.example.com", b"example.com"));
    }

    /// `lib/psl.c:72-73` guards the addition explicitly. With
    /// `TIME_T_MAX == i64::MAX` that guard and a saturating add agree for
    /// every input, which this asserts instead of assuming.
    #[test]
    fn the_saturating_add_reproduces_the_c_overflow_guard() {
        fn c_expression(now_sec: i64) -> i64 {
            if now_sec < i64::MAX - PSL_TTL {
                now_sec + PSL_TTL
            } else {
                i64::MAX
            }
        }

        let probes = [
            i64::MIN,
            i64::MIN + 1,
            -PSL_TTL,
            -1,
            0,
            1,
            PSL_TTL,
            i64::MAX - PSL_TTL - 1,
            i64::MAX - PSL_TTL,
            i64::MAX - PSL_TTL + 1,
            i64::MAX - 1,
            i64::MAX,
        ];
        for now_sec in probes {
            assert_eq!(now_sec.saturating_add(PSL_TTL), c_expression(now_sec));
        }
        assert_eq!(i64::MAX.saturating_add(PSL_TTL), i64::MAX);
    }

    /// `lib/psl.c:53` and `lib/psl.c:64` both test `expires <= now_sec`, so
    /// the deadline second itself is stale.
    #[test]
    fn a_list_is_reused_until_its_deadline_and_reloaded_at_it() {
        let clock = TestClock::new(CurlTime::new(1_000, 0));
        let source = CountingSource::both();
        let mut cache = PslCache::new();

        assert!(cache.use_list(&clock, &source).is_some());
        assert_eq!(cache.expires(), 1_000 + PSL_TTL);
        assert_eq!(source.latest_calls.get(), 1);

        // One second before the deadline: still fresh, no reload.
        clock.set(CurlTime::new(1_000 + PSL_TTL - 1, 0));
        assert!(cache.use_list(&clock, &source).is_some());
        assert_eq!(source.latest_calls.get(), 1);
        assert_eq!(cache.expires(), 1_000 + PSL_TTL);

        // On the deadline: stale, because the test is `<=`.
        clock.set(CurlTime::new(1_000 + PSL_TTL, 0));
        assert!(cache.use_list(&clock, &source).is_some());
        assert_eq!(source.latest_calls.get(), 2);
        assert_eq!(cache.expires(), 1_000 + 2 * PSL_TTL);
    }

    /// The sub-second part of the reading is discarded, exactly as
    /// `Curl_pgrs_now(easy)->tv_sec` discards it.
    #[test]
    fn only_whole_seconds_of_the_monotonic_reading_are_used() {
        let clock = TestClock::new(CurlTime::new(500, 999_999));
        let source = CountingSource::both();
        let mut cache = PslCache::new();

        assert!(cache.use_list(&clock, &source).is_some());
        assert_eq!(cache.expires(), 500 + PSL_TTL);

        // Advancing by a microsecond crosses a second boundary but not the
        // deadline, so nothing reloads.
        clock.advance(Duration::from_micros(1));
        assert!(cache.use_list(&clock, &source).is_some());
        assert_eq!(source.latest_calls.get(), 1);
    }

    /// `lib/psl.c:72-73` clamps rather than wrapping.
    #[test]
    fn the_deadline_clamps_instead_of_wrapping() {
        let clock = TestClock::new(CurlTime::new(i64::MAX - 1, 0));
        let source = CountingSource::both();
        let mut cache = PslCache::new();

        assert!(cache.use_list(&clock, &source).is_some());
        assert_eq!(cache.expires(), i64::MAX);
        assert!(cache.expires() > 0);

        // A clamped deadline is in the future for every reachable reading, so
        // the list is never reloaded again.
        clock.set(CurlTime::new(i64::MAX - 1, 0));
        assert!(cache.use_list(&clock, &source).is_some());
        assert_eq!(source.latest_calls.get(), 1);
    }

    /// `lib/psl.c:70`.
    #[test]
    fn the_refreshable_tier_marks_the_cache_dynamic() {
        let clock = TestClock::new(CurlTime::new(0, 0));
        let source = CountingSource::new(MemoryPslSource::latest(LIST));
        let mut cache = PslCache::new();

        assert!(cache.use_list(&clock, &source).is_some());
        assert!(cache.is_dynamic());
        assert!(cache.has_list());
        // The refreshable tier answered, so the fixed one was never asked.
        assert_eq!(source.latest_calls.get(), 1);
        assert_eq!(source.builtin_calls.get(), 0);
    }

    /// `lib/psl.c:76` -- the fixed tier is reached only when the refreshable
    /// one failed and the cache is not already dynamic.
    #[test]
    fn the_fixed_tier_is_the_fallback_and_leaves_the_cache_static() {
        let clock = TestClock::new(CurlTime::new(0, 0));
        let source = CountingSource::new(MemoryPslSource::builtin(LIST));
        let mut cache = PslCache::new();

        assert!(cache.use_list(&clock, &source).is_some());
        assert!(!cache.is_dynamic());
        assert_eq!(source.latest_calls.get(), 1);
        assert_eq!(source.builtin_calls.get(), 1);
    }

    /// `lib/psl.c:76` again, from the other side: once the cache holds a
    /// dynamic list, a failing refresh must **not** reach for the fixed one.
    #[test]
    fn a_dynamic_cache_suppresses_the_fixed_tier() {
        let clock = TestClock::new(CurlTime::new(0, 0));
        let source = CountingSource::both();
        let mut cache = PslCache::new();

        assert!(cache.use_list(&clock, &source).is_some());
        assert!(cache.is_dynamic());
        assert_eq!(source.builtin_calls.get(), 0);

        // Now let the refreshable tier fail and force a reload.
        source.latest_fails.set(true);
        clock.set(CurlTime::new(PSL_TTL, 0));
        assert!(cache.use_list(&clock, &source).is_some());
        assert_eq!(source.latest_calls.get(), 2);
        assert_eq!(source.builtin_calls.get(), 0);
    }

    /// `lib/psl.c:81` -- a failed refresh installs nothing, so the previous
    /// list **and** its expired deadline both survive and every later call
    /// retries. Faithfully preserved, retry included.
    #[test]
    fn a_failed_refresh_keeps_the_previous_list_and_retries() {
        let clock = TestClock::new(CurlTime::new(10, 0));
        // No fixed tier at all, so once the refreshable one starts failing
        // there is nothing left to load from.
        let source = CountingSource::new(MemoryPslSource::latest(LIST));
        let mut cache = PslCache::new();

        assert!(cache.use_list(&clock, &source).is_some());
        let deadline = cache.expires();
        assert_eq!(deadline, 10 + PSL_TTL);

        source.latest_fails.set(true);

        clock.set(CurlTime::new(deadline, 0));
        assert!(cache.use_list(&clock, &source).is_some());
        assert_eq!(cache.expires(), deadline);
        assert_eq!(source.latest_calls.get(), 2);

        // Still expired, so the next call tries again rather than backing
        // off.
        assert!(cache.use_list(&clock, &source).is_some());
        assert_eq!(cache.expires(), deadline);
        assert_eq!(source.latest_calls.get(), 3);
        // And the fixed tier was never reached, because the cache is holding
        // a dynamic list (`lib/psl.c:76`).
        assert_eq!(source.builtin_calls.get(), 0);
    }

    /// A cache that never managed to load reports no list, which is the
    /// caller's fail-closed trigger.
    #[test]
    fn a_source_that_cannot_load_yields_no_list() {
        let clock = TestClock::new(CurlTime::new(0, 0));
        let source = CountingSource::new(MemoryPslSource::empty());
        let mut cache = PslCache::new();

        assert!(cache.use_list(&clock, &source).is_none());
        assert!(!cache.has_list());
        assert!(!cache.is_dynamic());
        // Both tiers were tried, and the deadline stayed at its initial zero
        // because nothing was installed.
        assert_eq!(source.latest_calls.get(), 1);
        assert_eq!(source.builtin_calls.get(), 1);
        assert_eq!(cache.expires(), 0);
    }

    /// Unparsable text is a load failure, not a panic and not a partial
    /// list.
    #[test]
    fn unparseable_list_text_is_a_load_failure() {
        // No section marker, so the parser stores no rule and rejects the
        // list as empty.
        assert!(parse_list(b"com\nco.uk\n".to_vec()).is_none());
        // Not UTF-8.
        assert!(parse_list(vec![0x80, 0xff]).is_none());
        // Nothing at all.
        assert!(parse_list(Vec::new()).is_none());
        // And the real thing does parse into a list with rules in it, so the
        // assertions above are not vacuous.
        assert!(parse_list(LIST.as_bytes().to_vec()).is_some());
        assert!(!list().is_empty());
    }

    /// `lib/psl.c:34-39` -- and note that `expires` is deliberately left
    /// alone.
    #[test]
    fn destroy_clears_the_list_and_the_dynamic_flag() {
        let clock = TestClock::new(CurlTime::new(7, 0));
        let source = CountingSource::both();
        let mut cache = PslCache::new();

        assert!(cache.use_list(&clock, &source).is_some());
        assert!(cache.is_dynamic());
        let deadline = cache.expires();

        cache.destroy();
        assert!(!cache.has_list());
        assert!(!cache.is_dynamic());
        assert_eq!(cache.expires(), deadline);

        // Destroying an empty cache is a no-op, which is what the C's
        // `if(pslcache->psl)` guard buys.
        cache.destroy();
        assert!(!cache.has_list());
        assert_eq!(cache.expires(), deadline);
    }

    /// `lib/psl.c:48-49` -- an absent cache yields no list. Expressed by the
    /// caller holding an `Option`, and distinct from a present cache that has
    /// never loaded.
    #[test]
    fn an_absent_cache_yields_no_list() {
        let clock = TestClock::new(CurlTime::new(0, 0));
        let source = CountingSource::both();

        let mut absent: Option<PslCache> = None;
        let got = absent
            .as_mut()
            .and_then(|cache| cache.use_list(&clock, &source));
        assert!(got.is_none());
        assert_eq!(source.latest_calls.get(), 0);

        let mut present = Some(PslCache::new());
        let loaded = present
            .as_mut()
            .and_then(|cache| cache.use_list(&clock, &source))
            .is_some();
        assert!(loaded);
        assert_eq!(source.latest_calls.get(), 1);
    }

    /// The headline behaviour: a cookie for a registry-level name is refused
    /// while the host's own registrable domain is allowed.
    #[test]
    fn a_registry_level_cookie_domain_is_rejected() {
        let list = list();

        // `tests/data/test1476`, lowered as `lib/cookie.c:796-797` lowers
        // it.
        assert!(!is_cookie_domain_acceptable(&list, b"curl.co.uk", b"co.uk"));
        assert!(is_cookie_domain_acceptable(
            &list,
            b"curl.co.uk",
            b"curl.co.uk"
        ));

        // `tests/data/test1136`, all five cookies.
        assert!(!is_cookie_domain_acceptable(
            &list,
            b"www.example.ck",
            b"example.ck"
        ));
        assert!(is_cookie_domain_acceptable(
            &list,
            b"www.example.ck",
            b"www.example.ck"
        ));
        assert!(!is_cookie_domain_acceptable(&list, b"www.ck", b"ck"));
        assert!(is_cookie_domain_acceptable(&list, b"www.ck", b"www.ck"));
        assert!(is_cookie_domain_acceptable(
            &list,
            b"z-1.compute-1.amazonaws.com",
            b"z-1.compute-1.amazonaws.com"
        ));

        // A bare top-level domain is the plainest super cookie of all.
        assert!(!is_cookie_domain_acceptable(
            &list,
            b"www.example.com",
            b"com"
        ));
        // And the ordinary case still works.
        assert!(is_cookie_domain_acceptable(
            &list,
            b"www.example.com",
            b"example.com"
        ));
    }

    /// Every row of [`VECTORS`], which is `libpsl`'s own output.
    #[test]
    fn the_verdict_matches_libpsl_on_every_measured_pair() {
        let list = list();
        for (host, cookie_domain, expected) in VECTORS {
            let got = is_cookie_domain_acceptable(
                &list,
                host.as_bytes(),
                cookie_domain.as_bytes(),
            );
            assert_eq!(
                got, *expected,
                "host {host:?}, cookie domain {cookie_domain:?}"
            );
        }
    }

    /// Every row of [`UNREGISTRABLE`], which is `psl_unregistrable_domain`'s
    /// own output.
    #[test]
    fn the_unregistrable_domain_matches_libpsl() {
        let list = list();
        for (name, expected) in UNREGISTRABLE {
            assert_eq!(
                unregistrable_domain(&list, name.as_bytes()),
                Some(expected.as_bytes()),
                "name {name:?}"
            );
        }
        // Un-classifiable input yields nothing rather than a guess.
        assert_eq!(unregistrable_domain(&list, b""), None);
        assert_eq!(unregistrable_domain(&list, &[b'a', b'.', 0xff]), None);
        // And a lone unreadable label is still its own suffix, as libpsl has
        // it.
        assert_eq!(unregistrable_domain(&list, &[0xfe]), Some(&[0xfe][..]));
    }

    /// Every row of [`SUFFIXES`], likewise measured.
    #[test]
    fn the_public_suffix_verdict_matches_libpsl() {
        let list = list();
        for (name, expected) in SUFFIXES {
            assert_eq!(
                is_public_suffix(&list, name.as_bytes()),
                *expected,
                "name {name:?}"
            );
        }
    }

    /// The distinction the module documentation calls out: `Suffix::is_known`
    /// is a different question and answers it wrongly.
    #[test]
    fn the_predicate_is_not_whether_the_suffix_is_known() {
        let list = list();
        for name in [&b"ck"[..], b"invalidtld", b"localhost"] {
            // Not explicitly listed...
            assert!(
                list.suffix(name).is_some_and(|suffix| !suffix.is_known()),
                "name {name:?} should have no listed type"
            );
            // ...and a public suffix regardless.
            assert!(is_public_suffix(&list, name), "name {name:?}");
        }
    }

    /// The wildcard-parent case, which the crate's own lookup alone misses.
    #[test]
    fn a_wildcard_rules_parent_is_itself_a_public_suffix() {
        let list = list();
        let parent = &b"compute-1.amazonaws.com"[..];
        assert!(!spans_whole_name(&list, parent));
        assert!(is_public_suffix(&list, parent));
        // And the consequence for the verdict: the parent may not receive a
        // cookie from a host below it.
        assert!(!is_cookie_domain_acceptable(
            &list,
            b"x.compute-1.amazonaws.com",
            b"compute-1.amazonaws.com"
        ));
        // Only the immediate parent, so the label above it is unaffected.
        assert!(!is_public_suffix(&list, b"amazonaws.com"));
        // Same shape for `kobe.jp`, which also has no bare rule.
        assert!(!spans_whole_name(&list, b"kobe.jp"));
        assert!(is_public_suffix(&list, b"kobe.jp"));
        // And an exception is still an exception.
        assert!(!is_public_suffix(&list, b"www.ck"));
        assert!(!is_public_suffix(&list, b"city.kobe.jp"));
    }

    /// libpsl strips every leading dot before doing anything else.
    #[test]
    fn leading_dots_are_stripped_from_the_cookie_domain() {
        assert_eq!(strip_leading_dots(b"example.com"), b"example.com");
        assert_eq!(strip_leading_dots(b".example.com"), b"example.com");
        assert_eq!(strip_leading_dots(b"...example.com"), b"example.com");
        assert_eq!(strip_leading_dots(b"..."), b"");
        assert_eq!(strip_leading_dots(b"."), b"");
        assert_eq!(strip_leading_dots(b""), b"");
        // Interior and trailing dots are untouched.
        assert_eq!(strip_leading_dots(b"a..b."), b"a..b.");
    }

    /// `inet_pton(AF_INET, ...)`, every clause measured against `libpsl`.
    #[test]
    fn strict_dotted_quads_are_recognised_and_nothing_else_is() {
        for text in [
            &b"1.2.3.4"[..],
            b"0.0.0.0",
            b"255.255.255.255",
            b"127.0.0.1",
            b"1.2.3.44",
            b"9.8.7.6",
        ] {
            assert!(pton4(text), "expected an address: {text:?}");
        }
        for text in [
            &b""[..],
            b"1",
            b"1.2",
            b"1.2.3",
            b"1.2.3.4.5",
            b"1.2.3.4.",
            b".1.2.3.4",
            b"1..2.3.4",
            b"01.2.3.4",
            b"1.02.3.4",
            b"1.2.3.04",
            b"1.2.3.256",
            b"256.1.1.1",
            b"999.999.999.999",
            b"1.2.3.0x4",
            b"1.2.3.4a",
            b"a.2.3.4",
            b"1.2.3.-4",
            b"1.2.3.+4",
            b"1.2.3.4 ",
            b"1.2.3.1234",
        ] {
            assert!(!pton4(text), "expected no address: {text:?}");
        }
    }

    /// `inet_pton(AF_INET6, ...)`, likewise. The word-count arithmetic is
    /// where an implementation usually goes wrong, so both sides of each
    /// boundary appear.
    #[test]
    fn ipv6_literals_are_recognised_and_nothing_else_is() {
        for text in [
            &b"::"[..],
            b"::1",
            b"1::",
            b"1:2:3:4:5:6:7:8",
            b"1::8",
            b"fe80::1",
            b"::ffff:1.2.3.4",
            b"::1.2.3.4",
            b"0:0:0:0:0:0:1.2.3.4",
            b"0:0:0:0:0:ffff:1.2.3.4",
            b"1:2:3:4:5:6:1.2.3.4",
            b"1:2:3:4:5::1.2.3.4",
            b"64:ff9b::1.2.3.4",
            b"2001:db8::1.2.3.4",
            b"ABCD::1.2.3.4",
            b"AbCd::1",
            b"::ffff:0102:0304",
        ] {
            assert!(pton6(text), "expected an address: {text:?}");
        }
        for text in [
            &b""[..],
            b"1.2.3.4",
            b"example.com",
            b":::1.2.3.4",
            b":::",
            b":1.2.3.4",
            b":1",
            b"1:",
            b"1::2::3.4.5.6",
            b"1::2::3",
            b"x::1.2.3.4",
            b"abcde::1.2.3.4",
            b"::ffff:1.2.3.256",
            b"::ffff:1.2.3.4%eth0",
            b"[::ffff:1.2.3.4]",
            b"::ffff:1.2.3.4:5",
            b"1.2.3.4::5.6.7.8",
            b"::1.2.3.4.5",
            // Seven words and no gap to fill the eighth.
            b"1:2:3:4:5:1.2.3.4",
            b"1:2:3:4:5:6:7",
            // Eight words and a gap with nothing left to stand for.
            b"1:2:3:4:5:6::1.2.3.4",
            b"1:2:3:4:5:6:7::1.2.3.4",
            b"1:2:3:4:5:6:7:8::",
            // Nine words.
            b"1:2:3:4:5:6:7:1.2.3.4",
            b"1:2:3:4:5:6:7:8:9",
            b"1:2:3:4:5:6:7:8:1.2.3.4",
        ] {
            assert!(!pton6(text), "expected no address: {text:?}");
        }
    }

    /// Only the host is examined, never the cookie domain: `x.1.2.3.4` may
    /// set a cookie for the IP-shaped name below it.
    #[test]
    fn the_ip_rule_looks_at_the_host_and_not_the_cookie_domain() {
        let list = list();
        assert!(host_is_ip_literal(b"1.2.3.4"));
        assert!(!host_is_ip_literal(b"x.1.2.3.4"));
        assert!(is_cookie_domain_acceptable(&list, b"x.1.2.3.4", b"1.2.3.4"));
        assert!(!is_cookie_domain_acceptable(&list, b"1.2.3.4", b"2.3.4"));
    }

    /// The caller lowers both names first (`lib/cookie.c:796-797`) with raw
    /// ASCII folding, and this module then compares bytes. Driven through
    /// [`crate::util::strcase`] so the pipeline, not a paraphrase of it, is
    /// what is asserted.
    #[test]
    fn the_caller_lowers_both_names_with_raw_ascii_folding() {
        let list = list();

        // `tests/data/test1476` sends `domain=co.UK` for host `curl.co.UK`.
        let host = lower(b"curl.co.UK");
        let cookie_domain = lower(b"co.UK");
        assert_eq!(host, b"curl.co.uk");
        assert_eq!(cookie_domain, b"co.uk");
        assert!(!is_cookie_domain_acceptable(&list, &host, &cookie_domain));

        // The one measured divergence from `libpsl`, recorded rather than
        // hidden. `libpsl` requires lowercase input and compares bytes
        // throughout, so it does **not** recognise `co.UK` as a public suffix
        // and calls this pair acceptable. The workspace pins `publicsuffix`
        // with its `anycase` feature, so the lookup here folds case and the
        // pair is refused instead. Unreachable from curl, which lowers both
        // names before calling, and fail-safe where it could be reached: the
        // divergence only ever rejects a cookie that `libpsl` would have
        // allowed.
        assert!(!is_cookie_domain_acceptable(&list, b"curl.co.UK", b"co.UK"));
        assert!(is_public_suffix(&list, b"co.UK"));

        // Raw folding leaves bytes at or above 0x80 alone, which is the
        // property `char`'s own Unicode-aware case mapping would not have.
        assert_eq!(strcase::raw_tolower(0xC0), 0xC0);
        assert_eq!(strcase::raw_tolower(b'A'), b'a');
    }

    /// Untrusted bytes must not panic, and must not be accepted either.
    #[test]
    fn adversarial_input_is_refused_without_panicking() {
        let list = list();

        // Bytes that are not UTF-8 stop the list lookup dead: it reports no
        // suffix at all, for the name and for every name containing such a
        // label.
        //
        // A lone label is its own public suffix whether or not it is text, so
        // an unreadable single label may not receive a cookie. libpsl agrees.
        assert!(is_public_suffix(&list, &[0xfe]));
        assert!(!is_cookie_domain_acceptable(
            &list,
            &[0xff, b'.', 0xfe],
            &[0xfe]
        ));

        // A host with an unreadable label cannot be classified, so it is
        // refused rather than trusted. libpsl 0.21.2 lowercases through its
        // IDN library first and reports `com`, and so accepts this pair;
        // refusing is the fail-safe direction and no fixture reaches it,
        // because a host name that is not text cannot be resolved.
        assert!(unregistrable_domain(&list, b"x.\xff.com").is_none());
        assert!(!is_cookie_domain_acceptable(
            &list,
            b"x.\xff.com",
            b"\xff.com"
        ));
        // And never for the registry-level name above it, on which both
        // agree.
        assert!(!is_cookie_domain_acceptable(&list, b"x.\xff.com", b"com"));

        // Empty on either side. Two empty names are equal, and libpsl accepts
        // an exact match before it looks at anything else -- measured, so the
        // surprising row is the faithful one.
        assert!(is_cookie_domain_acceptable(&list, b"", b""));
        assert!(is_cookie_domain_acceptable(&list, b"", b"..."));
        assert!(!is_cookie_domain_acceptable(&list, b"", b"example.com"));
        assert!(!is_cookie_domain_acceptable(&list, b"example.com", b""));
        assert!(!is_cookie_domain_acceptable(&list, b"example.com.", b""));

        // An interior NUL is just another byte here, as it is in C only
        // because the C never gets this far with one.
        assert!(!is_cookie_domain_acceptable(
            &list,
            b"a\0b.example.com",
            b"\0b.example.com"
        ));

        // A cookie domain longer than the host.
        assert!(!is_cookie_domain_acceptable(
            &list,
            b"example.com",
            b"www.example.com"
        ));

        // Pathological lengths, well past the C's buffers, which the caller
        // would have refused first.
        let long_host = vec![b'a'; 4096];
        let long_domain = vec![b'a'; 8192];
        assert!(!is_cookie_domain_acceptable(
            &list,
            &long_host,
            &long_domain
        ));
        assert!(!host_is_ip_literal(&long_host));
        // One enormous label is still one label, and therefore still a public
        // suffix -- the same answer libpsl gives for any lone label.
        assert!(is_public_suffix(&list, &long_domain));

        // Two enormous labels are not, and a host under them may set a cookie
        // for them, which exercises the deep path with adversarial lengths.
        let mut deep = vec![b'a'; 4096];
        deep.push(b'.');
        deep.extend_from_slice(&vec![b'b'; 4096]);
        assert!(!is_public_suffix(&list, &deep));
        let mut deeper = b"host.".to_vec();
        deeper.extend_from_slice(&deep);
        assert!(is_cookie_domain_acceptable(&list, &deeper, &deep));

        // A name made of nothing but label separators.
        let many_labels = vec![b'.'; 512];
        assert!(!is_public_suffix(&list, &many_labels));
        assert!(!is_cookie_domain_acceptable(
            &list,
            &many_labels,
            &many_labels
        ));

        // Long runs of the delimiters both recognisers key on.
        let dots = vec![b'.'; 1024];
        let colons = vec![b':'; 1024];
        assert!(!pton4(&dots));
        assert!(!pton6(&dots));
        assert!(!pton4(&colons));
        assert!(!pton6(&colons));
        assert_eq!(strip_leading_dots(&dots), b"");
    }

    /// `tests/data/test977`, and the fully qualified host it turns on.
    #[test]
    fn a_fully_qualified_host_still_may_not_set_a_registry_level_cookie() {
        let list = list();

        // The fixture itself. `me` is not in the embedded list, so the lone
        // label `me.` reaches the same verdict here as it does against the
        // real list: the host's unregistrable part is `me.` too.
        assert_eq!(
            unregistrable_domain(&list, b"firsthost.me."),
            Some(&b"me."[..])
        );
        assert!(!is_cookie_domain_acceptable(
            &list,
            b"firsthost.me.",
            b"me."
        ));
        // And with the leading dot still attached, which strip removes.
        assert!(!is_cookie_domain_acceptable(
            &list,
            b"firsthost.me.",
            b".me."
        ));

        // The same shape over a listed suffix, and over an IP-shaped name.
        assert!(!is_cookie_domain_acceptable(
            &list,
            b"www.example.com.",
            b"com."
        ));
        assert!(!is_cookie_domain_acceptable(&list, b"1.2.3.4.", b"4."));
        assert_eq!(
            unregistrable_domain(&list, b"www.example.com."),
            Some(&b"com."[..])
        );

        // Everything a caller would actually do with a trailing dot still
        // behaves, and agrees with libpsl.
        assert!(is_cookie_domain_acceptable(
            &list,
            b"www.example.com.",
            b"example.com."
        ));
        assert!(is_cookie_domain_acceptable(
            &list,
            b"www.example.com.",
            b"www.example.com."
        ));
    }

    /// `available` answers the "was public-suffix checking configured at all"
    /// question, and answers it by trying.
    #[test]
    fn availability_is_reported_only_for_a_working_source() {
        // No source: the `#ifndef USE_LIBPSL` state. `PSL` must not be
        // advertised.
        assert!(!available(None));

        // A configured source that cannot load: the fail-closed state, and
        // still not something to advertise.
        let empty = MemoryPslSource::empty();
        assert!(!available(Some(&empty)));

        // Unparsable text is no better than no text.
        let broken = MemoryPslSource::latest("not a list at all");
        assert!(!available(Some(&broken)));

        // Either tier on its own is enough.
        let latest = MemoryPslSource::latest(LIST);
        assert!(available(Some(&latest)));
        let builtin = MemoryPslSource::builtin(LIST);
        assert!(available(Some(&builtin)));

        // And the fallback is reached without any `dynamic` condition, since
        // no cache is involved.
        let source = CountingSource::new(MemoryPslSource::builtin(LIST));
        assert!(available(Some(&source)));
        assert_eq!(source.latest_calls.get(), 1);
        assert_eq!(source.builtin_calls.get(), 1);
    }

    /// The four `libpsl` configurations [`MemoryPslSource`] can express.
    #[test]
    fn the_memory_source_serves_both_tiers_independently() {
        let neither = MemoryPslSource::empty();
        assert!(neither.latest().is_none());
        assert!(neither.builtin().is_none());

        let only_latest = MemoryPslSource::latest(LIST);
        assert!(only_latest.latest().is_some());
        assert!(only_latest.builtin().is_none());

        let only_builtin = MemoryPslSource::builtin(LIST);
        assert!(only_builtin.latest().is_none());
        assert!(only_builtin.builtin().is_some());

        let both = MemoryPslSource::new(
            Some(b"first".to_vec()),
            Some(b"second".to_vec()),
        );
        assert_eq!(both.latest(), Some(b"first".to_vec()));
        assert_eq!(both.builtin(), Some(b"second".to_vec()));
    }
}
