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
//! Trace and diagnostic output.
//!
//! Rust counterpart of `lib/curl_trc.c` (750 lines) and `lib/curl_trc.h`
//! (337 lines). This module owns the whole of curl's diagnostic surface: the
//! two-level log scheme, the trace-feature and connection-filter registries,
//! the `--trace-config` grammar behind the exported `curl_global_trace()`
//! (`lib/libcurl.def:34`, `include/curl/curl.h:2791`), the line assembly that
//! produces every `--trace` and `-v` record, and the hex/ASCII dump geometry.
//!
//! # The formats are the contract
//!
//! Every literal in this file is consumer-visible output. AAP section 0.8.1
//! freezes protocol and terminal presentation, and AAP section 0.3.4 states
//! that these surfaces are "reproduced byte-for-byte". Prefixes, bracket
//! forms, separators, column alignment and dump geometry are therefore
//! transcribed, never redesigned, and no formatting or readability pass may
//! rewrite them. Where a literal is unusual, a comment records the C origin
//! so that the oddity is visibly deliberate rather than apparently accidental.
//!
//! The `tracing` and `log` crates are available to this crate but do not
//! appear here on purpose. Both are facades that would decide a layout, and
//! curl's layout is the specification; a `tracing_subscriber` default line is
//! not. Anything wanting to bridge these records into `tracing` does so in
//! the [`TraceSink`] implementation, downstream of the bytes this module has
//! already fixed.
//!
//! # Verified against the running C library, not only read
//!
//! The layouts below were confirmed by linking a probe against the C
//! `libcurl.so.4` built from this tree (`curl 8.19.0-DEV`, the version AAP
//! section 0.8.5/C6 binds every parity claim to) and calling
//! `curl_global_trace()` with `CURLOPT_VERBOSE` and no debug callback, so the
//! library's own writer was exercised:
//!
//! ```text
//! * [0-x] [MULTI] [INIT] added to multi, mid=1, running=1, total=2
//! * [0-0] [TCP] adjust_pollset, !connected, POLLOUT fd=4
//! * [0-0] [TIMER] [HAPPY_EYEBALLS] cleared
//! * [0-0] [MULTI] [CONNECTING] -> [PROTOCONNECT]
//! [0-0] > GET /data.txt HTTP/1.1
//! ```
//!
//! Two things in that capture are easy to get wrong and are reproduced
//! exactly. First, the identifier block sits *after* the `"* "` prefix on an
//! informational line but *before* the `"> "` prefix on a raw-data line,
//! because `trc_infof()` builds the identifiers into the record
//! (`lib/curl_trc.c:242-243`) while `Curl_debug()` emits them alongside it
//! (`lib/curl_trc.c:158-164`). Second, `[TCP]` carries no `-0` suffix: the
//! socket index is appended only when it is greater than zero
//! (`lib/curl_trc.c:247-251`).
//!
//! # One exhaustive `match` replaces a hand-maintained parallel array
//!
//! `lib/multihandle.h:48-49` tells maintainers: "if you add a state here, add
//! the name to the statenames[] array in curl_trc.c as well!". That note has
//! itself drifted, and the drift is measured rather than supposed: no
//! `statenames[]` exists in `lib/curl_trc.c`, where the real array is
//! `Curl_trc_mstate_names[]` at `lib/curl_trc.c:334`; the identifier the note
//! gives survives in the tree only at `lib/mqtt.c:628`, an unrelated MQTT
//! array; and the SOCKS equivalent is spelled `cf_socks_statename[]`
//! (`lib/socks.c:71`). A maintainer following the comment literally searches
//! for a symbol that is not in the file it names.
//!
//! This module holds **no** multi-state strings. [`mstate_name`] delegates to
//! [`crate::multi::state::CurlMstate`], which derives every name from one
//! exhaustive `match`, so a state added without a name no longer compiles
//! (AAP section 0.3.3 P3). [`TimerId`] applies the same discipline to
//! `Curl_trc_timer_names[]` (`lib/curl_trc.c:281-297`): the enumeration and
//! its names live together in one exhaustive `match` instead of an array
//! indexed by a separately declared `expire_id` (`lib/urldata.h:887-904`).
//!
//! # Deliberate divergences, each with its reason
//!
//! * **The SMTP trace feature is omitted.** C registers `"SMTP"`
//!   (`lib/curl_trc.c:426`), but SMTP is out of scope (AAP section 0.2.2) and
//!   requests for it answer `CURLE_UNSUPPORTED_PROTOCOL`. The asymmetry that
//!   governs the version banner governs this too (AAP section 0.6.5):
//!   under-reporting a capability is safe, over-reporting is not.
//! * **The `CURL_DEBUG` environment override is absent.** In C it exists only
//!   under `DEBUGBUILD` (`lib/curl_trc.c:642-649`), and this build
//!   deliberately does not advertise `Debug` (AAP section 0.6.6). It is
//!   recorded here so its absence reads as a decision, not an oversight; were
//!   the debug posture reversed it would belong in [`TraceConfig::init`].
//! * **`Curl_trc_init()` is a no-op.** Outside a debug build the C function
//!   is exactly `return CURLE_OK` (`lib/curl_trc.c:653-660`), and
//!   [`TraceConfig::init`] reproduces that.
//!
//! # Two corrections to beliefs about the C code
//!
//! Both were found by measurement and both change the implementation, so
//! they are recorded where the code that depends on them can be checked
//! against them.
//!
//! 1. **A `--trace-config` token longer than 32 bytes is not truncated: it
//!    aborts the entire parse.** `curlx_str_until(&config, &out, 32, ',')`
//!    returns `STRE_BIG` once the length exceeds `max`
//!    (`lib/curlx/strparse.c:48-53`), and `trc_opt()`'s
//!    `while(!curlx_str_until(...))` therefore stops
//!    (`lib/curl_trc.c:607`). An empty token stops it the same way through
//!    `STRE_SHORT` (`lib/curlx/strparse.c:54-55`), which is why a *leading*
//!    comma discards everything after it while a *trailing* one is harmless.
//!    Confirmed against the C library: a 33-byte token followed by `multi`
//!    produced no `[MULTI]` output, a 32-byte one produced all of it.
//! 2. **`struct Curl_cftype` is not layout-compatible with
//!    `struct curl_trc_feat`.** It is `{name, flags, log_level, ...}`
//!    (`lib/cfilters.h:210-226`), so `flags` sits between the two fields a
//!    pun would need adjacent. C keeps two separate tables, `trc_feats[]` and
//!    `trc_cfts[]`, and reaches into each through its own type
//!    (`lib/curl_trc.c:572-588`). [`TraceFeature`] and [`TraceFilter`] mirror
//!    that real shape, and being distinct types they cannot be conflated even
//!    by accident.
//!
//! # A compile-time check where C has a runtime one
//!
//! `DEBUGASSERT(!strchr(fmt, '\n'))` opens every C emitter: a format string
//! must not contain a newline, because the emitter appends the terminator
//! itself (`lib/curl_trc.c:178`, `:260`, `:308`, `:363`, and the rest). The
//! macros in this module take the format as a `literal` and assert on it in
//! const context, so a newline is a build failure on every profile rather
//! than a debug-build panic -- `error[E0080]` naming the offending call site.
//! That is strictly stronger than C, whose assertion is compiled out of a
//! release build and so never fires where it would matter. No runtime
//! `debug_assert!` sits beside it: the condition depends only on a literal, so
//! there is nothing left to learn at run time, and asserting a constant is a
//! lint in its own right.
//!
//! # Scope
//!
//! This module owns diagnostic output and nothing else. The multi-state
//! enumeration belongs to [`crate::multi::state`]; `CURLcode` belongs to
//! [`crate::error`]; the transfer, connection and protocol modules call the
//! macros here but keep their own state. Presentation *policy* -- which
//! stream a trace goes to, the terminal suppression of data blocks, the
//! per-line prefixing that `--trace` performs across a multi-line payload,
//! and the platform clock -- belongs to the command-line adapter in
//! `curl-rs/src/callbacks/debug.rs`, because it needs process-wide state and
//! a local-time conversion that cannot be written without `unsafe`. The
//! geometry that policy arranges is here, in one place, rather than being
//! re-derived there.
//!
//! There is no `unsafe` in this module, in keeping with the crate root's
//! `forbid(unsafe_code)` (AAP section 0.1.1 G6).

use core::fmt;
use std::borrow::Cow;
use std::io;

use crate::error::{CURLcode, CodeResult};
use crate::multi::state::CurlMstate;

/// Longest trace line, including its terminator and terminating NUL.
///
/// `TRC_LINE_MAX` (`lib/curl_trc.c:76`), commented there as the "max length
/// we trace before ending in `'...'`". C declares `char buf[TRC_LINE_MAX]`
/// and fills it with `curl_msnprintf()`, which stores at most
/// `maxlength - 1` bytes because it always writes a NUL
/// (`lib/mprintf.c:1088-1098`); [`LineBuffer`] reproduces that budget rather
/// than the nominal size.
pub(crate) const TRC_LINE_MAX: usize = 2048;

/// Size of the caller-supplied `CURLOPT_ERRORBUFFER`, NUL included.
///
/// `CURL_ERROR_SIZE` (`include/curl/curl.h:865`). `Curl_failf()` formats with
/// this as the bound (`lib/curl_trc.c:184`), so a failure message carries at
/// most `CURL_ERROR_SIZE - 1` bytes before its newline.
pub(crate) const CURL_ERROR_SIZE: usize = 256;

/// Longest `--trace-config` token, in bytes.
///
/// The `max` argument of `curlx_str_until(&config, &out, 32, ',')`
/// (`lib/curl_trc.c:607`). Exceeding it aborts the parse; see the module
/// documentation and [`TraceConfig::apply`].
pub(crate) const TRACE_CONFIG_TOKEN_MAX: usize = 32;

/// How much of a component's activity is logged.
///
/// The C scheme is two-valued -- `CURL_LOG_LVL_NONE 0` and
/// `CURL_LOG_LVL_INFO 1` (`lib/curl_trc.h:69-70`) -- and is compared with
/// `>=` throughout (`lib/curl_trc.h:311-320`). It is not a syslog ladder, and
/// modelling it as an enumeration rather than an `int` removes the third
/// value that never existed.
#[repr(i32)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum TraceLevel {
    /// `CURL_LOG_LVL_NONE` -- the component stays silent. Every feature and
    /// filter starts here (`lib/curl_trc.c:85`, `:207`, and so on for all
    /// eleven), which is why this is also the [`Default`].
    #[default]
    None = 0,
    /// `CURL_LOG_LVL_INFO` -- the component emits informational records.
    Info = 1,
}

impl TraceLevel {
    /// The C integer, for the FFI crate and for `curl_easy_getinfo`-style
    /// reporting.
    pub(crate) const fn as_i32(self) -> i32 {
        self as i32
    }

    /// Whether this level admits informational output.
    ///
    /// Exactly `log_level >= CURL_LOG_LVL_INFO`, the comparison every C guard
    /// macro performs (`lib/curl_trc.h:314`, `:317`, `:320`).
    pub(crate) const fn is_info(self) -> bool {
        matches!(self, Self::Info)
    }

    /// Interpret a raw C `log_level`.
    ///
    /// C stores an `int` and only ever tests it with `>=
    /// CURL_LOG_LVL_INFO`, so any positive value behaves as [`Info`] and any
    /// other value as [`None`]. Saturating rather than rejecting keeps that
    /// behaviour for integers arriving across the C ABI.
    ///
    /// [`Info`]: TraceLevel::Info
    /// [`None`]: TraceLevel::None
    pub(crate) const fn from_i32(raw: i32) -> Self {
        if raw >= Self::Info as i32 {
            Self::Info
        } else {
            Self::None
        }
    }
}

/// Group a `--trace-config` keyword can switch as a unit.
///
/// The four C macros `TRC_CT_PROTOCOL`, `TRC_CT_NETWORK`, `TRC_CT_PROXY` and
/// `TRC_CT_INTERNALS`, plus `TRC_CT_NONE` (`lib/curl_trc.c:497-501`). A
/// newtype over the bit set rather than an enumeration, because C stores a
/// mask in `unsigned int category` and tests it with `&`
/// (`lib/curl_trc.c:595`, `:599`) -- a value here is a *set*, and the
/// selector `all` passes the empty one.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub(crate) struct TraceCategory(u32);

impl TraceCategory {
    /// `TRC_CT_NONE 0`. Carried by the `READ` and `WRITE` features, which
    /// belong to no group (`lib/curl_trc.c:511-512`), and passed as the
    /// selector by the `all` keyword (`lib/curl_trc.c:619`), where it means
    /// the opposite -- see [`matches_selector`](Self::matches_selector).
    pub(crate) const NONE: Self = Self(0);
    /// `TRC_CT_PROTOCOL (1 << 0)`.
    pub(crate) const PROTOCOL: Self = Self(1 << 0);
    /// `TRC_CT_NETWORK (1 << 1)`.
    pub(crate) const NETWORK: Self = Self(1 << 1);
    /// `TRC_CT_PROXY (1 << 2)`.
    pub(crate) const PROXY: Self = Self(1 << 2);
    /// `TRC_CT_INTERNALS (1 << 3)`.
    pub(crate) const INTERNALS: Self = Self(1 << 3);

    /// The raw mask, for the FFI crate and for tests that pin the bits.
    pub(crate) const fn bits(self) -> u32 {
        self.0
    }

    /// Whether this is the empty set, `TRC_CT_NONE`.
    pub(crate) const fn is_none(self) -> bool {
        self.0 == 0
    }

    /// Whether a registry entry in this category is switched by `selector`.
    ///
    /// `trc_apply_level_by_category()` verbatim: `if(!category ||
    /// (entry.category & category))` (`lib/curl_trc.c:595`, `:599`). The
    /// empty selector is the `all` keyword and matches *everything*,
    /// including the entries whose own category is empty -- which is the only
    /// way `READ` and `WRITE` are ever reached by a keyword. Reading `!category`
    /// as "matches nothing" would silently make `all` mean "only the
    /// uncategorised", so the two uses of the empty set are kept distinct here
    /// by naming: `self` is a membership, `selector` is a query.
    pub(crate) const fn matches_selector(self, selector: Self) -> bool {
        selector.is_none() || (self.0 & selector.0) != 0
    }

    /// The category a `--trace-config` keyword selects, if it is one.
    ///
    /// The four case-insensitive keywords of `trc_opt()`
    /// (`lib/curl_trc.c:618-625`). `None` means the token was not a keyword
    /// and must be matched against component names instead.
    pub(crate) fn from_keyword(token: &str) -> Option<Self> {
        // `eq_ignore_ascii_case` is `curlx_str_casecompare()`'s comparison:
        // that helper requires equal lengths and then defers to
        // `curl_strnequal()`, which is ASCII-only (`lib/curlx/strparse.c:239-243`).
        if token.eq_ignore_ascii_case("all") {
            Some(Self::NONE)
        } else if token.eq_ignore_ascii_case("protocol") {
            Some(Self::PROTOCOL)
        } else if token.eq_ignore_ascii_case("network") {
            Some(Self::NETWORK)
        } else if token.eq_ignore_ascii_case("proxy") {
            Some(Self::PROXY)
        } else {
            None
        }
    }
}

/// The `doh` alias, rewritten to this name before any lookup.
///
/// `trc_opt()` special-cases the token and substitutes a literal
/// `struct Curl_str dns = { "dns", 3 }` (`lib/curl_trc.c:626-629`). Naming the
/// target once means the alias cannot come to point at a feature that has been
/// renamed: the constant is asserted against [`TraceFeature::Dns`] by test.
const TRACE_CONFIG_DOH_ALIAS_TARGET: &str = "DNS";

/// A traceable library component, other than a connection filter.
///
/// The `struct curl_trc_feat` instances of `lib/curl_trc.c`, in the order
/// `trc_feats[]` lists them (`lib/curl_trc.c:508-530`). Each variant's
/// documentation gives the C symbol and the source line, so the table can be
/// diffed against the original entry by entry.
///
/// Ten variants where C has eleven. `Curl_trc_feat_smtp` (`"SMTP"`,
/// `lib/curl_trc.c:426`) has no counterpart because SMTP is out of scope (AAP
/// section 0.2.2); the reasoning is in the module documentation.
///
/// The conditional variants mirror C's `#ifdef`s exactly, which is AAP section
/// 0.4.2's transformation rule -- `#ifndef CURL_DISABLE_FTP` becomes
/// `#[cfg(feature = "ftp")]`. `SSLS` is unconditional where C guards it with
/// `#ifdef USE_SSL`, because rustls is the sole TLS implementation and is a
/// non-optional dependency of this crate, so `USE_SSL` is always satisfied
/// (AAP section 0.8.2).
///
/// The discriminants are storage slots for [`TraceConfig`], not part of any
/// ABI: they must be distinct and below [`SLOTS`](Self::SLOTS), and they stay
/// fixed under every feature combination so that turning a Cargo feature off
/// cannot renumber the ones that remain. A test asserts both properties.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum TraceFeature {
    /// `Curl_trc_feat_ids` (`lib/curl_trc.c:83`) -- prefixes records with the
    /// transfer and connection identifiers. Read through
    /// `CURL_TRC_IDS(data)` (`lib/curl_trc.c:87-89`) rather than the usual
    /// guard, because it decorates other features' output instead of emitting
    /// any of its own.
    Ids = 0,
    /// `Curl_trc_feat_multi` (`lib/curl_trc.c:205`) -- the multi-handle state
    /// machine.
    Multi = 1,
    /// `Curl_trc_feat_read` (`lib/curl_trc.c:209`) -- the reader chain.
    Read = 2,
    /// `Curl_trc_feat_write` (`lib/curl_trc.c:213`) -- the writer chain.
    Write = 3,
    /// `Curl_trc_feat_dns` (`lib/curl_trc.c:217`) -- name resolution. Also the
    /// target of the `doh` alias.
    Dns = 4,
    /// `Curl_trc_feat_timer` (`lib/curl_trc.c:221`) -- expiry scheduling. Its
    /// records name a [`TimerId`].
    Timer = 5,
    /// `Curl_trc_feat_ftp` (`lib/curl_trc.c:408`), C-guarded by
    /// `#ifndef CURL_DISABLE_FTP`.
    #[cfg(feature = "ftp")]
    Ftp = 6,
    /// `Curl_trc_feat_ssls` (`lib/curl_trc.c:444`) -- the TLS session cache.
    /// C-guarded by `#ifdef USE_SSL`, always present here.
    Ssls = 7,
    /// `Curl_trc_feat_ssh` (`lib/curl_trc.c:462`), C-guarded by
    /// `#ifdef USE_SSH`.
    #[cfg(feature = "ssh")]
    Ssh = 8,
    /// `Curl_trc_feat_ws` (`lib/curl_trc.c:480`), C-guarded by
    /// `#if !defined(CURL_DISABLE_WEBSOCKETS) && !defined(CURL_DISABLE_HTTP)`.
    #[cfg(feature = "websockets")]
    Ws = 9,
}

impl TraceFeature {
    /// Number of storage slots reserved, counting the conditional variants.
    ///
    /// One more than the largest discriminant. Sized for every variant that
    /// *could* exist so that a disabled Cargo feature leaves a hole rather
    /// than shifting its neighbours; the cost is a handful of bytes in
    /// [`TraceConfig`].
    pub(crate) const SLOTS: usize = 10;

    /// Every feature this build registers, in `trc_feats[]` order.
    ///
    /// The iteration order matters: `trc_apply_level_by_name()` stops at the
    /// first match (`lib/curl_trc.c:582-587`), so the order fixes which entry
    /// wins were two ever to share a name.
    pub(crate) const ALL: &'static [Self] = &[
        Self::Ids,
        Self::Multi,
        Self::Read,
        Self::Write,
        Self::Dns,
        Self::Timer,
        #[cfg(feature = "ftp")]
        Self::Ftp,
        Self::Ssls,
        #[cfg(feature = "ssh")]
        Self::Ssh,
        #[cfg(feature = "websockets")]
        Self::Ws,
    ];

    /// The name `--trace-config` matches and `trc_infof()` prints in brackets.
    ///
    /// Frozen output: these strings reach `--trace` logs verbatim as
    /// `"[%s] "` (`lib/curl_trc.c:245`). Transcribed from the `name` member of
    /// each `struct curl_trc_feat`, including `"LIB-IDS"`, whose hyphen and
    /// upper case are load-bearing -- the command-line tool spells it exactly
    /// that way when it appends `,-lib-ids` to every configuration string it
    /// forwards (`src/tool_getparam.c:789`, `:803`).
    ///
    /// No `_` arm, so a variant added without a name is a compile error.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Ids => "LIB-IDS",
            Self::Multi => "MULTI",
            Self::Read => "READ",
            Self::Write => "WRITE",
            Self::Dns => "DNS",
            Self::Timer => "TIMER",
            #[cfg(feature = "ftp")]
            Self::Ftp => "FTP",
            Self::Ssls => "SSLS",
            #[cfg(feature = "ssh")]
            Self::Ssh => "SSH",
            #[cfg(feature = "websockets")]
            Self::Ws => "WS",
        }
    }

    /// The group a `--trace-config` keyword switches this feature through.
    ///
    /// The `category` member of each `trc_feats[]` row
    /// (`lib/curl_trc.c:509-529`). `READ` and `WRITE` are genuinely
    /// uncategorised, so only the `all` keyword reaches them.
    pub(crate) const fn category(self) -> TraceCategory {
        match self {
            Self::Ids => TraceCategory::INTERNALS,
            Self::Multi => TraceCategory::NETWORK,
            Self::Read => TraceCategory::NONE,
            Self::Write => TraceCategory::NONE,
            Self::Dns => TraceCategory::NETWORK,
            Self::Timer => TraceCategory::NETWORK,
            #[cfg(feature = "ftp")]
            Self::Ftp => TraceCategory::PROTOCOL,
            Self::Ssls => TraceCategory::NETWORK,
            #[cfg(feature = "ssh")]
            Self::Ssh => TraceCategory::PROTOCOL,
            #[cfg(feature = "websockets")]
            Self::Ws => TraceCategory::PROTOCOL,
        }
    }

    /// Index of this feature's level inside [`TraceConfig`].
    const fn slot(self) -> usize {
        self as usize
    }

    /// Look a feature up by name, case-insensitively.
    ///
    /// The second loop of `trc_apply_level_by_name()`
    /// (`lib/curl_trc.c:582-587`), which breaks at the first match. Unknown
    /// names simply do not match; C treats that as success, not as an error.
    pub(crate) fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|feature| feature.name().eq_ignore_ascii_case(name))
    }
}

/// Formats as the trace name, so a feature can be spliced into a message
/// directly. `{:?}` still gives the Rust variant, which keeps the two
/// spellings distinguishable in diagnostics.
impl fmt::Display for TraceFeature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A traceable connection filter type.
///
/// The `struct Curl_cftype` instances that `trc_cfts[]` registers, in its order
/// (`lib/curl_trc.c:537-570`). Sixteen entries; C's table appears to hold
/// seventeen only because `Curl_cft_ip_happy` is easy to count twice.
///
/// A separate type from [`TraceFeature`] on purpose. C needs two tables
/// because `struct Curl_cftype` is `{name, flags, log_level, ...}`
/// (`lib/cfilters.h:210-226`) and so is *not* interchangeable with
/// `struct curl_trc_feat`; it reaches into each through its own type rather
/// than casting between them (`lib/curl_trc.c:572-588`). Two Rust enumerations
/// reproduce that arrangement and make the conflation unrepresentable, which
/// is the class of pattern AAP section 0.6.9 removes.
///
/// Filters carry their own level rather than inheriting one, because
/// `Curl_trc_cf_is_verbose()` tests `cf->cft->log_level` independently of the
/// transfer's current feature (`lib/curl_trc.h:315-317`). A `ConnFilter`
/// implementation in `crate::conn::filters` names itself by returning one of
/// these, which is how a filter supplies a trace identity without any
/// dependence on struct layout.
///
/// As with [`TraceFeature`], the discriminants are storage slots, fixed under
/// every feature combination.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum TraceFilter {
    /// `Curl_cft_tcp` -- the TCP socket filter.
    Tcp = 0,
    /// `Curl_cft_udp` -- the UDP socket filter, under QUIC.
    Udp = 1,
    /// `Curl_cft_unix` -- the AF_UNIX socket filter.
    Unix = 2,
    /// `Curl_cft_tcp_accept` -- the listening socket used by active FTP.
    TcpAccept = 3,
    /// `Curl_cft_ip_happy` -- dual-stack connection racing.
    IpHappy = 4,
    /// `Curl_cft_setup` -- the outermost filter, which builds the rest.
    Setup = 5,
    /// `Curl_cft_nghttp2` -- the HTTP/2 filter. C-guarded by
    /// `#if !defined(CURL_DISABLE_HTTP) && defined(USE_NGHTTP2)`. The Rust
    /// identifier drops the reference to the C library, which the `h2` crate
    /// replaces (AAP section 0.4.1), but the emitted name is unchanged: the C
    /// symbol's `name` member is the literal `"HTTP/2"`, so nothing in a trace
    /// log ever said `nghttp2` and nothing here will either.
    #[cfg(feature = "http2")]
    Http2 = 6,
    /// `Curl_cft_ssl` -- the TLS filter. C-guarded by `#ifdef USE_SSL`,
    /// always present here.
    Ssl = 7,
    /// `Curl_cft_ssl_proxy` -- TLS to the proxy itself.
    SslProxy = 8,
    /// `Curl_cft_h1_proxy` -- `CONNECT` tunnelling over HTTP/1.
    H1Proxy = 9,
    /// `Curl_cft_h2_proxy` -- `CONNECT` tunnelling over HTTP/2. C-guarded by
    /// `#ifdef USE_NGHTTP2` inside the proxy block.
    #[cfg(feature = "http2")]
    H2Proxy = 10,
    /// `Curl_cft_http_proxy` -- the HTTP proxy filter that selects between the
    /// two tunnelling versions.
    HttpProxy = 11,
    /// `Curl_cft_haproxy` -- the PROXY protocol header.
    HaProxy = 12,
    /// `Curl_cft_socks_proxy` -- SOCKS4 and SOCKS5.
    SocksProxy = 13,
    /// `Curl_cft_http3` -- the HTTP/3 filter. Already a filter in the C design
    /// (`lib/vquic/vquic.h:48`), which is why QUIC needs no parallel
    /// abstraction here (AAP section 0.3.3 P2). C-guarded by
    /// `#if !defined(CURL_DISABLE_HTTP) && defined(USE_HTTP3)`.
    #[cfg(feature = "http3")]
    Http3 = 14,
    /// `Curl_cft_http_connect` -- HTTPS version negotiation, the filter that
    /// races HTTP/3 against HTTP/2 and HTTP/1.
    HttpConnect = 15,
}

impl TraceFilter {
    /// Number of storage slots reserved, counting the conditional variants.
    pub(crate) const SLOTS: usize = 16;

    /// Every filter this build registers, in `trc_cfts[]` order.
    pub(crate) const ALL: &'static [Self] = &[
        Self::Tcp,
        Self::Udp,
        Self::Unix,
        Self::TcpAccept,
        Self::IpHappy,
        Self::Setup,
        #[cfg(feature = "http2")]
        Self::Http2,
        Self::Ssl,
        Self::SslProxy,
        Self::H1Proxy,
        #[cfg(feature = "http2")]
        Self::H2Proxy,
        Self::HttpProxy,
        Self::HaProxy,
        Self::SocksProxy,
        #[cfg(feature = "http3")]
        Self::Http3,
        Self::HttpConnect,
    ];

    /// The name `--trace-config` matches and `Curl_trc_cf_infof()` prints.
    ///
    /// Frozen output, transcribed from the `name` member of each
    /// `struct Curl_cftype`. Three spellings are worth pointing at because a
    /// tidying pass would get them wrong: `"HAPPY-EYEBALLS"` is hyphenated
    /// where the timer of nearly the same name uses an underscore
    /// (`"HAPPY_EYEBALLS"`, see [`TimerId::HappyEyeballs`]); `"SOCKS"` is not
    /// `"SOCKS-PROXY"`, unlike every other proxy filter; and `"HTTP/2"` and
    /// `"HTTP/3"` contain a solidus.
    ///
    /// No `_` arm, so a variant added without a name is a compile error.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
            Self::Unix => "UNIX",
            Self::TcpAccept => "TCP-ACCEPT",
            Self::IpHappy => "HAPPY-EYEBALLS",
            Self::Setup => "SETUP",
            #[cfg(feature = "http2")]
            Self::Http2 => "HTTP/2",
            Self::Ssl => "SSL",
            Self::SslProxy => "SSL-PROXY",
            Self::H1Proxy => "H1-PROXY",
            #[cfg(feature = "http2")]
            Self::H2Proxy => "H2-PROXY",
            Self::HttpProxy => "HTTP-PROXY",
            Self::HaProxy => "HAPROXY",
            Self::SocksProxy => "SOCKS",
            #[cfg(feature = "http3")]
            Self::Http3 => "HTTP/3",
            Self::HttpConnect => "HTTPS-CONNECT",
        }
    }

    /// The group a `--trace-config` keyword switches this filter through.
    ///
    /// The `category` member of each `trc_cfts[]` row
    /// (`lib/curl_trc.c:538-569`). Note that `SSL` is `NETWORK` while
    /// `SSL-PROXY` is `PROXY`: the same implementation is categorised by what
    /// it is protecting, not by what it is.
    pub(crate) const fn category(self) -> TraceCategory {
        match self {
            Self::Tcp => TraceCategory::NETWORK,
            Self::Udp => TraceCategory::NETWORK,
            Self::Unix => TraceCategory::NETWORK,
            Self::TcpAccept => TraceCategory::NETWORK,
            Self::IpHappy => TraceCategory::NETWORK,
            Self::Setup => TraceCategory::PROTOCOL,
            #[cfg(feature = "http2")]
            Self::Http2 => TraceCategory::PROTOCOL,
            Self::Ssl => TraceCategory::NETWORK,
            Self::SslProxy => TraceCategory::PROXY,
            Self::H1Proxy => TraceCategory::PROXY,
            #[cfg(feature = "http2")]
            Self::H2Proxy => TraceCategory::PROXY,
            Self::HttpProxy => TraceCategory::PROXY,
            Self::HaProxy => TraceCategory::PROXY,
            Self::SocksProxy => TraceCategory::PROXY,
            #[cfg(feature = "http3")]
            Self::Http3 => TraceCategory::PROTOCOL,
            Self::HttpConnect => TraceCategory::PROTOCOL,
        }
    }

    /// Index of this filter's level inside [`TraceConfig`].
    const fn slot(self) -> usize {
        self as usize
    }

    /// Look a filter up by name, case-insensitively.
    ///
    /// The first loop of `trc_apply_level_by_name()`
    /// (`lib/curl_trc.c:576-581`), which breaks at the first match.
    pub(crate) fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|filter| filter.name().eq_ignore_ascii_case(name))
    }
}

/// Formats as the trace name, matching [`TraceFeature`]'s `Display`.
impl fmt::Display for TraceFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Which components are logging, and at what level.
///
/// The mutable half of C's registry. There, each `struct curl_trc_feat` and
/// each `struct Curl_cftype` is a process-global whose `log_level` member
/// `trc_opt()` writes through (`lib/curl_trc.c:578`, `:584`, `:596`, `:600`).
/// Here the levels are gathered into one owned value instead.
///
/// That is not a stylistic preference. AAP section 0.3.3 P12 makes dependency
/// injection an architectural requirement so the protocol and transfer modules
/// can be tested to the mandated coverage without live network access, and a
/// process-global trace level would make those tests order-dependent -- one
/// test enabling `WRITE` would change what another observes. Keeping the levels
/// in a value also removes the need for `static mut` or a `OnceLock`, neither
/// of which this crate may use.
///
/// The externally visible behaviour is unchanged: the command-line tool holds a
/// single instance for the process, applies `--trace-config` to it once through
/// the exported `curl_global_trace()`, and lends it to each transfer, which is
/// what C's globals amount to in the only configuration curl itself ships.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct TraceConfig {
    /// Levels indexed by [`TraceFeature::slot`].
    features: [TraceLevel; TraceFeature::SLOTS],
    /// Levels indexed by [`TraceFilter::slot`].
    filters: [TraceLevel; TraceFilter::SLOTS],
}

impl TraceConfig {
    /// A configuration with every component silent.
    ///
    /// The state C's statics are initialised to: every one of the eleven
    /// features and every filter starts at `CURL_LOG_LVL_NONE`
    /// (`lib/curl_trc.c:85`, `:207`, `:211`, `:215`, `:219`, `:223`, `:410`,
    /// `:446`, `:464`, `:482`).
    pub(crate) const fn new() -> Self {
        Self {
            features: [TraceLevel::None; TraceFeature::SLOTS],
            filters: [TraceLevel::None; TraceFilter::SLOTS],
        }
    }

    /// Start-up hook, the counterpart of `Curl_trc_init()`.
    ///
    /// Outside a debug build the C function body is exactly `return CURLE_OK`
    /// (`lib/curl_trc.c:653-660`), so this returns a silent configuration and
    /// cannot fail. It is fallible in shape because the C signature is, and
    /// because `curl_global_init()` propagates its result
    /// (`lib/easy.c:138-139`).
    ///
    /// Under `DEBUGBUILD` the C function instead calls `Curl_trc_opt(NULL)`,
    /// which consults the `CURL_DEBUG` environment variable
    /// (`lib/curl_trc.c:642-649`). That path is deliberately absent: this
    /// build does not advertise `Debug` (AAP section 0.6.6), and were that
    /// posture reversed, the override belongs here.
    pub(crate) fn init() -> CodeResult<Self> {
        Ok(Self::new())
    }

    /// The level a feature is logging at.
    pub(crate) fn feature_level(&self, feature: TraceFeature) -> TraceLevel {
        self.features[feature.slot()]
    }

    /// The level a filter type is logging at.
    pub(crate) fn filter_level(&self, filter: TraceFilter) -> TraceLevel {
        self.filters[filter.slot()]
    }

    /// Set one feature's level, as `trc_apply_level_by_name()` does.
    pub(crate) fn set_feature_level(&mut self, feature: TraceFeature, level: TraceLevel) {
        self.features[feature.slot()] = level;
    }

    /// Set one filter type's level.
    pub(crate) fn set_filter_level(&mut self, filter: TraceFilter, level: TraceLevel) {
        self.filters[filter.slot()] = level;
    }

    /// Whether a feature is logging informationally.
    ///
    /// The `ft->log_level >= CURL_LOG_LVL_INFO` half of
    /// `Curl_trc_ft_is_verbose()` (`lib/curl_trc.h:318-320`). The transfer's
    /// own verbosity is the other half and lives on [`Tracer`], because it is
    /// per-transfer rather than per-configuration.
    pub(crate) fn feature_is_info(&self, feature: TraceFeature) -> bool {
        self.feature_level(feature).is_info()
    }

    /// Whether a filter type is logging informationally.
    ///
    /// The `cf->cft->log_level >= CURL_LOG_LVL_INFO` half of
    /// `Curl_trc_cf_is_verbose()` (`lib/curl_trc.h:315-317`).
    pub(crate) fn filter_is_info(&self, filter: TraceFilter) -> bool {
        self.filter_level(filter).is_info()
    }

    /// Apply a level to every component in a category.
    ///
    /// `trc_apply_level_by_category()` (`lib/curl_trc.c:590-602`), filters
    /// first and then features, with the empty selector meaning *everything*
    /// -- see [`TraceCategory::matches_selector`]. Unlike the by-name form this
    /// does not stop at the first match; it is a broadcast.
    pub(crate) fn apply_level_by_category(&mut self, selector: TraceCategory, level: TraceLevel) {
        for &filter in TraceFilter::ALL {
            if filter.category().matches_selector(selector) {
                self.set_filter_level(filter, level);
            }
        }
        for &feature in TraceFeature::ALL {
            if feature.category().matches_selector(selector) {
                self.set_feature_level(feature, level);
            }
        }
    }

    /// Apply a level to whichever component carries `name`.
    ///
    /// `trc_apply_level_by_name()` (`lib/curl_trc.c:572-588`). Both tables are
    /// consulted -- filters first, then features -- and each stops at its own
    /// first match, so a name present in both lists would set both. No such
    /// collision exists among the registered names, and a test asserts that it
    /// stays that way.
    ///
    /// An unrecognised name matches nothing and is not an error. That leniency
    /// is documented behaviour: `Curl_trc_opt()`'s contract says "Unknown names
    /// are ignored" (`lib/curl_trc.h:40`).
    pub(crate) fn apply_level_by_name(&mut self, name: &str, level: TraceLevel) {
        if let Some(filter) = TraceFilter::from_name(name) {
            self.set_filter_level(filter, level);
        }
        if let Some(feature) = TraceFeature::from_name(name) {
            self.set_feature_level(feature, level);
        }
    }

    /// Apply a `--trace-config` string, the body of `curl_global_trace()`.
    ///
    /// `Curl_trc_opt()` (`lib/curl_trc.c:639-651`) delegating to `trc_opt()`
    /// (`lib/curl_trc.c:604-637`). `None` is C's `NULL` argument, which is a
    /// no-op returning success.
    ///
    /// # Grammar
    ///
    /// Comma-separated tokens. A leading `-` selects [`TraceLevel::None`], a
    /// leading `+` or no sign selects [`TraceLevel::Info`]. The sign counts
    /// towards the token's length, because C strips it with
    /// `curlx_str_nudge()` only after the token has been measured
    /// (`lib/curl_trc.c:611-616`). Four keywords select a category --
    /// `all`, `protocol`, `network`, `proxy` -- `doh` is an alias for the
    /// `dns` feature, and anything else is matched against component names.
    /// All comparisons are ASCII case-insensitive. Later tokens override
    /// earlier ones, so `all,-multi` enables everything and then silences
    /// `MULTI`.
    ///
    /// # Where the parse stops
    ///
    /// Two conditions end it, and both discard the remainder of the string
    /// while still returning success -- this is the correction recorded in the
    /// module documentation, and it is C's real behaviour rather than the
    /// truncation one might expect from a length cap:
    ///
    /// * a token longer than [`TRACE_CONFIG_TOKEN_MAX`] bytes, which
    ///   `curlx_str_until()` reports as `STRE_BIG`
    ///   (`lib/curlx/strparse.c:48-53`);
    /// * an empty token, reported as `STRE_SHORT`
    ///   (`lib/curlx/strparse.c:54-55`) -- so `",dns"` applies nothing at all
    ///   and `"multi,,dns"` applies only `MULTI`, whereas a *trailing* comma is
    ///   harmless because the loop was going to end anyway.
    ///
    /// Both were confirmed against the C library built from this tree: a
    /// 33-byte token followed by `multi` produced no `[MULTI]` records, a
    /// 32-byte one produced them all.
    ///
    /// # Errors
    ///
    /// Never. The signature is fallible because `Curl_trc_opt()`'s is, and
    /// because `curl_global_trace()` must return a `CURLcode`; C's own body
    /// can only produce `CURLE_OK`, and a caller that treated a malformed
    /// configuration as fatal would be a behaviour change.
    pub(crate) fn apply(&mut self, config: Option<&str>) -> CodeResult<()> {
        let Some(config) = config else {
            return Ok(());
        };

        // A byte cursor rather than `&str` slicing: token boundaries are byte
        // offsets in C, and a multi-byte character straddling one would make
        // `&config[a..b]` panic. Bytes cannot, and a non-ASCII token simply
        // matches no name -- which is what C does too, since it compares raw
        // bytes against ASCII literals.
        let mut rest = config.as_bytes();
        while let Some(token) = next_config_token(&mut rest) {
            // `curlx_str_nudge(&out, 1)` after inspecting the first byte
            // (`lib/curl_trc.c:611-616`). A lone `"-"` or `"+"` leaves an empty
            // token, which matches neither a keyword nor a name; C reaches the
            // same conclusion because `curlx_str_casecompare()` requires equal
            // lengths (`lib/curlx/strparse.c:242`).
            let (level, name) = match token.first() {
                Some(b'-') => (TraceLevel::None, &token[1..]),
                Some(b'+') => (TraceLevel::Info, &token[1..]),
                _ => (TraceLevel::Info, token),
            };

            // Tokens are split on ASCII bytes and the sign stripped is ASCII, so
            // a `&str` input yields valid UTF-8 here every time. The result is
            // matched rather than unwrapped so that the invariant is not load
            // bearing: were this ever fed raw bytes, an invalid sequence would
            // become the same silent no-op an unrecognised name is, which is
            // what C does when it compares raw bytes against ASCII literals.
            if let Ok(name) = core::str::from_utf8(name) {
                if let Some(selector) = TraceCategory::from_keyword(name) {
                    self.apply_level_by_category(selector, level);
                } else if name.eq_ignore_ascii_case("doh") {
                    self.apply_level_by_name(TRACE_CONFIG_DOH_ALIAS_TARGET, level);
                } else {
                    self.apply_level_by_name(name, level);
                }
            }

            // `if(curlx_str_single(&config, ',')) break;`
            // (`lib/curl_trc.c:633-634`): consume the separator or stop.
            match rest.first() {
                Some(b',') => rest = &rest[1..],
                _ => break,
            }
        }

        Ok(())
    }

    /// [`apply`](Self::apply) with the C return convention.
    ///
    /// `curl_global_trace()` is declared `CURLcode curl_global_trace(const char
    /// *config)` (`include/curl/curl.h:2791`) and is one of the exported
    /// symbols (`lib/libcurl.def:34`), so the ABI shim needs the code rather
    /// than a `Result`. Provided here so that the mapping is written once
    /// instead of in `curl-rs-ffi`.
    pub(crate) fn apply_code(&mut self, config: Option<&str>) -> CURLcode {
        match self.apply(config) {
            Ok(()) => CURLcode::Ok,
            Err(code) => code,
        }
    }
}

/// Take the next `--trace-config` token, or stop the parse.
///
/// `curlx_str_until(&config, &out, 32, ',')` (`lib/curlx/strparse.c:40-60`)
/// specialised to this one call site. On success `rest` is left pointing at the
/// delimiter, exactly as C leaves `*linep` at "the first byte after the word".
///
/// `None` covers both of C's failure codes, because `trc_opt()`'s
/// `while(!curlx_str_until(...))` cannot distinguish them: `STRE_BIG` for a
/// token over the cap and `STRE_SHORT` for an empty one.
fn next_config_token<'a>(rest: &mut &'a [u8]) -> Option<&'a [u8]> {
    let len = rest
        .iter()
        .position(|&byte| byte == b',')
        .unwrap_or(rest.len());

    // `if(++len > max) return STRE_BIG;` -- the scan aborts on the byte that
    // takes the length past the cap, so a token of exactly the cap is accepted.
    if len > TRACE_CONFIG_TOKEN_MAX {
        return None;
    }
    // `if(!len) return STRE_SHORT;`
    if len == 0 {
        return None;
    }

    let (token, tail) = rest.split_at(len);
    *rest = tail;
    Some(token)
}

/// One of the expiry timers a transfer can arm.
///
/// The `expire_id` enumeration (`lib/urldata.h:887-904`), whose fifteen real
/// values are named by `Curl_trc_timer_names[]` (`lib/curl_trc.c:281-297`).
/// C's sixteenth token, `EXPIRE_LAST`, is commented "not an actual timer, used
/// as a marker only" and has no name; it survives here as the integers
/// [`COUNT`](Self::COUNT) and [`LAST`](Self::LAST) so a bound is still
/// available without a value that must never be used being constructible.
///
/// # Why the enumeration is declared here
///
/// `Curl_trc_timer_names[]` lives in `lib/curl_trc.c` while `expire_id` lives in
/// `lib/urldata.h`, so C splits identity from naming exactly as it does for the
/// multi state -- and with the same consequence, that adding a timer without
/// naming it compiles. Keeping both halves in one module closes that: the
/// discriminants and [`name`](Self::name)'s exhaustive `match` cannot disagree,
/// and a variant added without a name is a compile error.
///
/// This is the one place where the target module differs from the plan sketched
/// in [`crate::multi::state`], which anticipated the enumeration living in
/// `crate::multi::events`. The scheduler will `use` this type rather than
/// declare a second one; a parallel enumeration there would rebuild precisely
/// the drift this arrangement removes, and the C original is a trace-module
/// table in any case.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum TimerId {
    /// `EXPIRE_100_TIMEOUT`, `"100_TIMEOUT"` -- how long to wait for a
    /// `100 Continue` interim response before sending the body anyway.
    Expect100Timeout = 0,
    /// `EXPIRE_ASYNC_NAME`, `"ASYNC_NAME"` -- the asynchronous resolver's own
    /// deadline.
    AsyncName = 1,
    /// `EXPIRE_CONNECTTIMEOUT`, `"CONNECTTIMEOUT"` -- `--connect-timeout`.
    ConnectTimeout = 2,
    /// `EXPIRE_DNS_PER_NAME`, `"DNS_PER_NAME"` -- C comments this "family1".
    DnsPerName = 3,
    /// `EXPIRE_DNS_PER_NAME2`, `"DNS_PER_NAME2"` -- C comments this "family2".
    DnsPerName2 = 4,
    /// `EXPIRE_HAPPY_EYEBALLS_DNS`, `"HAPPY_EYEBALLS_DNS"` -- the resolver half
    /// of dual-stack racing.
    HappyEyeballsDns = 5,
    /// `EXPIRE_HAPPY_EYEBALLS`, `"HAPPY_EYEBALLS"` -- the connect half. Note the
    /// underscores: the connection filter of nearly the same name is spelled
    /// with a hyphen (`"HAPPY-EYEBALLS"`, [`TraceFilter::IpHappy`]).
    HappyEyeballs = 6,
    /// `EXPIRE_MULTI_PENDING`, `"MULTI_PENDING"` -- retry of a transfer parked
    /// for want of a connection.
    MultiPending = 7,
    /// `EXPIRE_SPEEDCHECK`, `"SPEEDCHECK"` -- `--speed-limit` sampling.
    SpeedCheck = 8,
    /// `EXPIRE_TIMEOUT`, `"TIMEOUT"` -- the overall `--max-time`.
    Timeout = 9,
    /// `EXPIRE_TOOFAST`, `"TOOFAST"` -- the pause `--limit-rate` imposes.
    TooFast = 10,
    /// `EXPIRE_QUIC`, `"QUIC"` -- the QUIC transport's own loss and idle
    /// timers.
    Quic = 11,
    /// `EXPIRE_FTP_ACCEPT`, `"FTP_ACCEPT"` -- `--ftp-account`-style active-mode
    /// accept wait.
    FtpAccept = 12,
    /// `EXPIRE_ALPN_EYEBALLS`, `"ALPN_EYEBALLS"` -- the HTTP-version race run by
    /// [`TraceFilter::HttpConnect`].
    AlpnEyeballs = 13,
    /// `EXPIRE_SHUTDOWN`, `"SHUTDOWN"` -- how long a graceful connection
    /// shutdown may take.
    Shutdown = 14,
}

impl TimerId {
    /// Number of real timers, and so the length of C's name table.
    ///
    /// `EXPIRE_LAST` read as a count, which is what
    /// `CURL_ARRAYSIZE(Curl_trc_timer_names)` evaluates to
    /// (`lib/curl_trc.c:301`).
    pub(crate) const COUNT: usize = 15;

    /// Integer value of C's `EXPIRE_LAST` marker (`lib/urldata.h:903`).
    ///
    /// Published as a number rather than a variant, because the header says it
    /// is not a timer.
    pub(crate) const LAST: u8 = 15;

    /// Name answered when an integer does not denote a timer.
    ///
    /// `"UNKNOWN?"`, exactly as `trc_timer_name()` answers when its bounds
    /// check fails (`lib/curl_trc.c:303`).
    ///
    /// **This is not the multi-state fallback.** That one is `"?"`
    /// (`lib/curl_trc.c:358`, reached through [`mstate_name`]). The two strings
    /// are different, both are frozen output, and unifying them would change
    /// what a trace log says.
    pub(crate) const UNKNOWN_NAME: &'static str = "UNKNOWN?";

    /// Every timer, in `Curl_trc_timer_names[]` order.
    pub(crate) const ALL: &'static [Self] = &[
        Self::Expect100Timeout,
        Self::AsyncName,
        Self::ConnectTimeout,
        Self::DnsPerName,
        Self::DnsPerName2,
        Self::HappyEyeballsDns,
        Self::HappyEyeballs,
        Self::MultiPending,
        Self::SpeedCheck,
        Self::Timeout,
        Self::TooFast,
        Self::Quic,
        Self::FtpAccept,
        Self::AlpnEyeballs,
        Self::Shutdown,
    ];

    /// The timer's trace name.
    ///
    /// One exhaustive `match` in place of `Curl_trc_timer_names[]`
    /// (`lib/curl_trc.c:281-297`). Frozen output: `Curl_trc_timer()` passes the
    /// result as the bracketed identifier of a `TIMER` record
    /// (`lib/curl_trc.c:310-313`), which the C library was observed emitting as
    /// `* [0-0] [TIMER] [HAPPY_EYEBALLS] cleared`.
    ///
    /// The spellings keep C's inconsistencies rather than regularising them:
    /// `"100_TIMEOUT"` leads with a digit, `"CONNECTTIMEOUT"` and `"TOOFAST"`
    /// have no separator where `"MULTI_PENDING"` and `"FTP_ACCEPT"` do, and
    /// `"DNS_PER_NAME2"` ends in a bare digit. No `_` arm.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Expect100Timeout => "100_TIMEOUT",
            Self::AsyncName => "ASYNC_NAME",
            Self::ConnectTimeout => "CONNECTTIMEOUT",
            Self::DnsPerName => "DNS_PER_NAME",
            Self::DnsPerName2 => "DNS_PER_NAME2",
            Self::HappyEyeballsDns => "HAPPY_EYEBALLS_DNS",
            Self::HappyEyeballs => "HAPPY_EYEBALLS",
            Self::MultiPending => "MULTI_PENDING",
            Self::SpeedCheck => "SPEEDCHECK",
            Self::Timeout => "TIMEOUT",
            Self::TooFast => "TOOFAST",
            Self::Quic => "QUIC",
            Self::FtpAccept => "FTP_ACCEPT",
            Self::AlpnEyeballs => "ALPN_EYEBALLS",
            Self::Shutdown => "SHUTDOWN",
        }
    }

    /// Validate a raw integer as a timer, or `None` outside `0..COUNT`.
    ///
    /// The bounds check of `trc_timer_name()` (`lib/curl_trc.c:301`).
    /// Unreachable from safe Rust, where a [`TimerId`] is valid by
    /// construction; it exists because `Curl_trc_timer()` takes a plain `int`
    /// (`lib/curl_trc.h:96`) and because integers arrive unvalidated across the
    /// C ABI.
    pub(crate) const fn from_i32(tid: i32) -> Option<Self> {
        match tid {
            0 => Some(Self::Expect100Timeout),
            1 => Some(Self::AsyncName),
            2 => Some(Self::ConnectTimeout),
            3 => Some(Self::DnsPerName),
            4 => Some(Self::DnsPerName2),
            5 => Some(Self::HappyEyeballsDns),
            6 => Some(Self::HappyEyeballs),
            7 => Some(Self::MultiPending),
            8 => Some(Self::SpeedCheck),
            9 => Some(Self::Timeout),
            10 => Some(Self::TooFast),
            11 => Some(Self::Quic),
            12 => Some(Self::FtpAccept),
            13 => Some(Self::AlpnEyeballs),
            14 => Some(Self::Shutdown),
            // This arm matches an `i32`, not a `TimerId`: it is C's failed
            // bounds check, not a wildcard over the enumeration.
            _ => None,
        }
    }

    /// The C integer, for the ABI shim.
    pub(crate) const fn as_i32(self) -> i32 {
        self as i32
    }

    /// Trace name for a raw integer, `"UNKNOWN?"` when it is not a timer.
    ///
    /// `trc_timer_name()` verbatim (`lib/curl_trc.c:299-304`). Routed through
    /// [`name`](Self::name) so a timer's string is still written in exactly one
    /// place.
    pub(crate) const fn name_from_i32(tid: i32) -> &'static str {
        match Self::from_i32(tid) {
            Some(timer) => timer.name(),
            None => Self::UNKNOWN_NAME,
        }
    }
}

/// Formats as the trace name, matching [`TraceFeature`]'s `Display`.
impl fmt::Display for TimerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Trace name of a multi-handle state, `"?"` when the integer is not a state.
///
/// `Curl_trc_mstate_name()` (`lib/curl_trc.c:354-358`), which is declared in
/// `lib/curl_trc.h:86` and reached through the `CURL_MSTATE_NAME()` macro
/// (`lib/curl_trc.h:321`).
///
/// **The seventeen strings are not here.** They are derived from
/// [`CurlMstate`]'s own exhaustive `match`, which is the point of this
/// module's central requirement: `lib/multihandle.h:48-49` makes keeping a
/// parallel array in step a manual obligation, that note has already drifted,
/// and deriving the names from the enumeration makes the drift impossible. See
/// the module documentation for the measurement.
///
/// This wrapper exists for the ABI shim, where a state arrives as a raw `int`
/// and may be anything. Inside the crate, prefer [`CurlMstate::name`] on a
/// typed value, which cannot fail.
pub(crate) fn mstate_name(state: i32) -> &'static str {
    CurlMstate::name_from_i32(state)
}

/// The kind of data a trace record carries.
///
/// `curl_infotype` (`include/curl/curl.h:479-488`), the first argument of the
/// `CURLOPT_DEBUGFUNCTION` callback (`include/curl/curl.h:490-495`). C's
/// eighth token, `CURLINFO_END`, is a count rather than a kind and so has no
/// variant; it survives as [`COUNT`](Self::COUNT).
#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum InfoType {
    /// `CURLINFO_TEXT` -- an informational line the library wrote itself.
    Text = 0,
    /// `CURLINFO_HEADER_IN` -- protocol header bytes received.
    HeaderIn = 1,
    /// `CURLINFO_HEADER_OUT` -- protocol header bytes sent.
    HeaderOut = 2,
    /// `CURLINFO_DATA_IN` -- body bytes received.
    DataIn = 3,
    /// `CURLINFO_DATA_OUT` -- body bytes sent.
    DataOut = 4,
    /// `CURLINFO_SSL_DATA_IN` -- TLS record bytes received.
    SslDataIn = 5,
    /// `CURLINFO_SSL_DATA_OUT` -- TLS record bytes sent.
    SslDataOut = 6,
}

impl InfoType {
    /// Number of kinds, C's `CURLINFO_END`.
    pub(crate) const COUNT: usize = 7;

    /// Every kind, in declaration order.
    pub(crate) const ALL: &'static [Self] = &[
        Self::Text,
        Self::HeaderIn,
        Self::HeaderOut,
        Self::DataIn,
        Self::DataOut,
        Self::SslDataIn,
        Self::SslDataOut,
    ];

    /// Width of every [`prefix`](Self::prefix), in bytes.
    ///
    /// C writes the prefix with an explicit length -- `fwrite(s_infotype[type],
    /// 2, 1, ...)` (`lib/curl_trc.c:65`, `:163`) -- so the two-byte width is
    /// part of the format, not an accident of the strings.
    pub(crate) const PREFIX_LEN: usize = 2;

    /// The two-byte marker a stream writer puts in front of the payload.
    ///
    /// `s_infotype[CURLINFO_END][3]` -- `{"* ", "< ", "> ", "{ ", "} ", "{ ",
    /// "} "}`. Frozen output, and the trailing space in each is significant.
    ///
    /// The table appears three times in the C tree: twice within
    /// `lib/curl_trc.c` alone (`:59-60` in `trc_write()` and `:129-130` in
    /// `Curl_debug()`) and again in `src/tool_cb_dbg.c:57-59`. Three copies of
    /// one frozen table is the same maintenance hazard as the state names, so
    /// it is written once here and the command-line adapter reads it from here
    /// rather than restating it.
    ///
    /// The duplication *inside* the table is C's, not a transcription slip:
    /// `DataIn` and `SslDataIn` both give `"{ "`, and `DataOut` and
    /// `SslDataOut` both give `"} "`.
    pub(crate) const fn prefix(self) -> &'static str {
        match self {
            Self::Text => "* ",
            Self::HeaderIn => "< ",
            Self::HeaderOut => "> ",
            Self::DataIn => "{ ",
            Self::DataOut => "} ",
            Self::SslDataIn => "{ ",
            Self::SslDataOut => "} ",
        }
    }

    /// Whether a plain stream writer prints this kind at all.
    ///
    /// The `switch` in `trc_write()` and `Curl_debug()` lists exactly
    /// `CURLINFO_TEXT`, `CURLINFO_HEADER_OUT` and `CURLINFO_HEADER_IN`, and
    /// its `default` arm is commented "nada" (`lib/curl_trc.c:61-70`,
    /// `:153-168`). Body and TLS payloads are dropped by the library's own
    /// writer; only a `CURLOPT_DEBUGFUNCTION` -- or the command-line tool's
    /// dump -- ever renders them.
    pub(crate) const fn is_written_plain(self) -> bool {
        matches!(self, Self::Text | Self::HeaderOut | Self::HeaderIn)
    }

    /// The heading a hex dump gives this kind, or `None` if it has none.
    ///
    /// The `text` assignments of `tool_debug_cb()`
    /// (`src/tool_cb_dbg.c:249-265`). Frozen output: [`dump`] prints it in the
    /// `"<text>, <n> bytes (0x<n>)"` heading. `Text` has no heading because C
    /// prints that kind directly and falls through instead of dumping it
    /// (`src/tool_cb_dbg.c:246-248`).
    ///
    /// Directions are asymmetric in the original and stay that way: sends use
    /// `"=> "` and receives `"<= "`.
    pub(crate) const fn dump_label(self) -> Option<&'static str> {
        match self {
            Self::Text => None,
            Self::HeaderIn => Some("<= Recv header"),
            Self::HeaderOut => Some("=> Send header"),
            Self::DataIn => Some("<= Recv data"),
            Self::DataOut => Some("=> Send data"),
            Self::SslDataIn => Some("<= Recv SSL data"),
            Self::SslDataOut => Some("=> Send SSL data"),
        }
    }

    /// The C integer, for the ABI shim and for callback dispatch.
    pub(crate) const fn as_i32(self) -> i32 {
        self as i32
    }

    /// Validate a raw `curl_infotype`, or `None` outside `0..COUNT`.
    ///
    /// Needed because the value reaches a `CURLOPT_DEBUGFUNCTION` as a plain C
    /// enumeration and C's own `switch` guards against unknown values with a
    /// `default` arm commented "in case a new one is introduced to shock us"
    /// (`src/tool_cb_dbg.c:247`).
    pub(crate) const fn from_i32(raw: i32) -> Option<Self> {
        match raw {
            0 => Some(Self::Text),
            1 => Some(Self::HeaderIn),
            2 => Some(Self::HeaderOut),
            3 => Some(Self::DataIn),
            4 => Some(Self::DataOut),
            5 => Some(Self::SslDataIn),
            6 => Some(Self::SslDataOut),
            _ => None,
        }
    }
}

/// The transfer and connection identifiers a record is tagged with.
///
/// `data->id` and either `data->conn->connection_id` or
/// `data->state.recent_conn_id`, the two values `trc_print_ids()` renders
/// (`lib/curl_trc.c:91-106`). Both are `curl_off_t` in C, which is 64-bit on
/// every target in the mandated matrix (AAP section 0.1.1 G8), so `i64` is
/// exact rather than merely wide enough.
///
/// A negative value means "not assigned", which is how C spells it: every test
/// is `>= 0`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct TraceIds {
    /// `data->id`, the transfer identifier reported by `CURLINFO_XFER_ID`.
    pub(crate) xfer: i64,
    /// The connection identifier, reported by `CURLINFO_CONN_ID`. C prefers
    /// the live connection's and falls back to `data->state.recent_conn_id`
    /// once it has gone (`lib/curl_trc.c:93-94`), so this field holds whichever
    /// of the two applies.
    pub(crate) conn: i64,
}

impl TraceIds {
    /// The placeholder C prints for an unassigned identifier.
    ///
    /// The `x` of `"[x-x] "` (`lib/curl_trc.c:104`) and of the two mixed forms
    /// `CURL_TRC_FMT_IDSC` and `CURL_TRC_FMT_IDSD` (`lib/curl_trc.c:78-79`).
    pub(crate) const UNASSIGNED_PLACEHOLDER: &'static str = "x";

    /// Neither identifier assigned, which renders as `"[x-x] "`.
    pub(crate) const UNASSIGNED: Self = Self { xfer: -1, conn: -1 };

    /// Both identifiers known.
    pub(crate) const fn new(xfer: i64, conn: i64) -> Self {
        Self { xfer, conn }
    }

    /// A transfer that has not yet been attached to a connection.
    pub(crate) const fn xfer_only(xfer: i64) -> Self {
        Self { xfer, conn: -1 }
    }

    /// Whether the transfer identifier is assigned, C's `data->id >= 0`.
    ///
    /// Consulted outside rendering too: `Curl_trc_multi()` includes the
    /// multi-state name only for a transfer that has an id
    /// (`lib/curl_trc.c:364-365`).
    pub(crate) const fn has_xfer_id(&self) -> bool {
        self.xfer >= 0
    }

    /// Whether the connection identifier is assigned, C's `cid >= 0`.
    pub(crate) const fn has_conn_id(&self) -> bool {
        self.conn >= 0
    }
}

impl Default for TraceIds {
    /// [`UNASSIGNED`](Self::UNASSIGNED), not zero: zero is a valid identifier,
    /// and the C library was observed printing `[0-0]` for the first transfer
    /// on the first connection.
    fn default() -> Self {
        Self::UNASSIGNED
    }
}

/// Renders the identifier block, trailing space included.
///
/// `trc_print_ids()` (`lib/curl_trc.c:91-106`) and its three format macros
/// (`lib/curl_trc.c:78-81`), which the command-line tool restates as
/// `TRC_IDS_FORMAT_IDS_1` and `TRC_IDS_FORMAT_IDS_2`
/// (`src/tool_cb_dbg.c:122-124`) and which are written once here instead.
///
/// Four shapes, selected exactly as C selects them:
///
/// ```text
/// [12-3] both assigned          CURL_TRC_FMT_IDSDC
/// [12-x] transfer only          CURL_TRC_FMT_IDSD
/// [x-3]  connection only        CURL_TRC_FMT_IDSC
/// [x-x]  neither
/// ```
///
/// The trailing space belongs to the block, so a caller concatenates without
/// adding one.
impl fmt::Display for TraceIds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let placeholder = Self::UNASSIGNED_PLACEHOLDER;
        match (self.has_xfer_id(), self.has_conn_id()) {
            (true, true) => write!(f, "[{}-{}] ", self.xfer, self.conn),
            (true, false) => write!(f, "[{}-{}] ", self.xfer, placeholder),
            (false, true) => write!(f, "[{}-{}] ", placeholder, self.conn),
            (false, false) => write!(f, "[{}-{}] ", placeholder, placeholder),
        }
    }
}

/// A trace line under construction, with C's length budget and truncation.
///
/// Replaces the `char buf[TRC_LINE_MAX]` that `trc_infof()` and `Curl_debug()`
/// fill with successive `curl_msnprintf()` calls (`lib/curl_trc.c:239-254`,
/// `:131-140`). Two behaviours of that arrangement are behaviourally visible
/// and are reproduced here rather than approximated:
///
/// * **The budget is `TRC_LINE_MAX - 1`, not `TRC_LINE_MAX`.**
///   `curl_msnprintf()` always terminates, so it stores at most
///   `maxlength - 1` bytes and returns that count (`lib/mprintf.c:1088-1098`,
///   with the byte-level cap at `lib/mprintf.c:1067-1074`). Successive calls
///   pass `TRC_LINE_MAX - len`, so the content can never exceed 2047 bytes.
/// * **Overlong lines end in `"...\n"`.** [`finish`](Self::finish) is
///   `trc_end_buf()` (`lib/curl_trc.c:108-123`).
///
/// The buffer holds bytes, not text. Trace payloads are protocol bytes and C
/// truncates without regard to character boundaries; a `String` would either
/// have to reject that or silently move a boundary, and both would change the
/// output.
///
/// The budget is a field rather than a constant because C uses two of them: the
/// 2048-byte trace line, and the `CURL_ERROR_SIZE`-byte error line that
/// `Curl_failf()` formats into (`lib/curl_trc.c:183-186`). Both truncate the
/// same way, so one type serves both with [`with_content_max`].
///
/// [`with_content_max`]: Self::with_content_max
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LineBuffer {
    buf: Vec<u8>,
    content_max: usize,
}

impl LineBuffer {
    /// Most content bytes a trace line can hold before its terminator.
    ///
    /// `TRC_LINE_MAX - 1`; see the type documentation for why the nominal size
    /// is one larger.
    pub(crate) const CONTENT_MAX: usize = TRC_LINE_MAX - 1;

    /// The marker an overlong line ends with, newline included.
    ///
    /// The four bytes `trc_end_buf()` appends one at a time
    /// (`lib/curl_trc.c:114-117`).
    const TRUNCATION_MARKER: &'static [u8] = b"...\n";

    /// An empty trace line buffer, pre-sized so assembly never reallocates.
    pub(crate) fn new() -> Self {
        Self::with_content_max(Self::CONTENT_MAX)
    }

    /// An empty buffer with a caller-chosen content budget.
    ///
    /// `content_max` is C's `maxlength - 1`: the most bytes
    /// `curl_msnprintf()` would store given that nominal size. Values below
    /// four leave no room for the truncation marker, so they are raised to
    /// four; C never uses one that small, and silently producing a shorter
    /// marker would be worse than declining to.
    pub(crate) fn with_content_max(content_max: usize) -> Self {
        let content_max = content_max.max(Self::TRUNCATION_MARKER.len());
        Self {
            buf: Vec::with_capacity(content_max + 1),
            content_max,
        }
    }

    /// This buffer's content budget, C's `maxlen - 1`.
    pub(crate) fn content_max(&self) -> usize {
        self.content_max
    }

    /// Offset `trc_end_buf()` truncates to before appending `"...\n"`.
    ///
    /// C's `len = maxlen - 5` (`lib/curl_trc.c:113`), which leaves room for
    /// three dots, the newline and the NUL that C writes and this buffer does
    /// not need. Expressed against [`content_max`] because `maxlen` is
    /// `content_max + 1`.
    ///
    /// [`content_max`]: Self::content_max
    fn truncate_at(&self) -> usize {
        self.content_max - Self::TRUNCATION_MARKER.len()
    }

    /// Bytes assembled so far.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Number of bytes assembled so far, C's running `len`.
    pub(crate) fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether nothing has been appended yet.
    pub(crate) fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Reset for reuse, keeping the allocation.
    pub(crate) fn clear(&mut self) {
        self.buf.clear();
    }

    /// Append bytes, dropping whatever does not fit.
    ///
    /// One `curl_msnprintf()` call's worth of truncation: the excess is
    /// discarded silently, exactly as C's `addbyter()` discards it once
    /// `length == max` (`lib/mprintf.c:1067-1074`).
    pub(crate) fn push_bytes(&mut self, bytes: &[u8]) {
        let room = self.content_max.saturating_sub(self.buf.len());
        let take = room.min(bytes.len());
        self.buf.extend_from_slice(&bytes[..take]);
    }

    /// Append a string's bytes, dropping whatever does not fit.
    pub(crate) fn push_str(&mut self, text: &str) {
        self.push_bytes(text.as_bytes());
    }

    /// Append formatted output, dropping whatever does not fit.
    ///
    /// The `curl_mvsnprintf(buf + len, TRC_LINE_MAX - len, fmt, ap)` of
    /// `trc_infof()` (`lib/curl_trc.c:253`). Formatting into this buffer cannot
    /// fail -- [`fmt::Write`] is implemented infallibly -- so the result is
    /// discarded deliberately rather than through oversight.
    pub(crate) fn push_fmt(&mut self, args: fmt::Arguments<'_>) {
        // `fmt::Write::write_fmt` only reports the sink's errors, and this
        // sink has none. A `Display` implementation could still panic, which
        // is its own bug and not something to be swallowed here.
        let _ = fmt::Write::write_fmt(self, args);
    }

    /// Terminate the line and hand back the bytes to emit.
    ///
    /// `trc_end_buf()` (`lib/curl_trc.c:108-123`) with `maxlen` fixed at
    /// [`TRC_LINE_MAX`]. `add_newline` is C's `addnl`: informational lines pass
    /// `TRUE` (`lib/curl_trc.c:254`) and the identifier-prefixed raw payload of
    /// `Curl_debug()` passes `FALSE` (`lib/curl_trc.c:140`), because that
    /// payload already carries its own line endings.
    ///
    /// The returned slice excludes the NUL that C writes at `buf[len]`, since
    /// the length is what C passes onward and the NUL is not part of it.
    pub(crate) fn finish(&mut self, add_newline: bool) -> &[u8] {
        // C's `maxlen`, one more than the content budget.
        let maxlen = self.content_max + 1;
        let reserved = if add_newline { 2 } else { 1 };
        if self.buf.len() >= maxlen - reserved {
            self.buf.truncate(self.truncate_at());
            self.buf.extend_from_slice(Self::TRUNCATION_MARKER);
        } else if add_newline {
            self.buf.push(b'\n');
        }
        &self.buf
    }

    /// Append the line terminator unconditionally, past the content budget.
    ///
    /// `Curl_failf()` formats into `char error[CURL_ERROR_SIZE + 2]` but caps
    /// the formatting at `CURL_ERROR_SIZE`, then writes `error[len++] = '\n'`
    /// with no length test at all (`lib/curl_trc.c:183-191`). A full 255-byte
    /// message therefore emits 256 bytes ending in a newline, where
    /// [`finish`](Self::finish) would have truncated it to `"...\n"`. The two
    /// paths differ in C and so they differ here.
    pub(crate) fn push_newline(&mut self) {
        self.buf.push(b'\n');
    }
}

/// An empty trace line buffer; same as [`LineBuffer::new`].
impl Default for LineBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// Appending text is infallible, which is what lets [`push_fmt`] discard its
/// result.
///
/// [`push_fmt`]: LineBuffer::push_fmt
impl fmt::Write for LineBuffer {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        self.push_bytes(text.as_bytes());
        Ok(())
    }
}

/// Where finished trace records go.
///
/// C has two destinations and chooses between them on every record: the
/// caller's `CURLOPT_DEBUGFUNCTION` if `data->set.fdebug` is set, otherwise
/// `fwrite()` to `data->set.err` (`lib/curl_trc.c:50-71`, `:128-169`). This
/// trait is that choice, made once at construction instead of per record.
///
/// The sink is injected into [`Tracer`] rather than being reached for globally
/// (AAP section 0.3.3 P12), so a test can capture output without touching
/// process state and two tests cannot influence each other.
pub(crate) trait TraceSink {
    /// Whether this sink is a caller-supplied `CURLOPT_DEBUGFUNCTION`.
    ///
    /// C branches on `data->set.fdebug` in two places where the *content*, not
    /// merely the destination, differs: `Curl_debug()` builds the identifiers
    /// into the record for a callback but emits them alongside it for a stream
    /// (`lib/curl_trc.c:133-169`). [`Tracer::debug`] needs the same
    /// distinction, and this is the only thing it asks of a sink.
    ///
    /// The default is `false`, the stream case, because that is the shape a
    /// writer has and a callback adapter is the special one.
    fn is_user_callback(&self) -> bool {
        false
    }

    /// Deliver one record.
    ///
    /// `ids` is the already-rendered identifier block, `""` when there is none.
    /// It is passed separately rather than concatenated because C places it
    /// differently in the two cases, and the contract is exactly C's:
    ///
    /// * a stream sink writes `ids`, then [`InfoType::prefix`], then `payload`
    ///   (`lib/curl_trc.c:158-164`), which is why a raw-data line reads
    ///   `[0-0] > GET / HTTP/1.1`;
    /// * a callback sink delivers `ids` immediately followed by `payload` as one
    ///   record and adds no prefix (`lib/curl_trc.c:136-143`), leaving
    ///   presentation to the caller.
    ///
    /// Informational lines built by [`Tracer::infof`] and friends carry their
    /// identifiers *inside* `payload` and pass `""` here, which is why those
    /// read `* [0-0] [MULTI] ...` with the prefix first. Both orders were
    /// observed from the C library and both are reproduced.
    ///
    /// Errors are not reported. C ignores every `fwrite()` result on this path
    /// and discards the callback's return value with an explicit `(void)` cast
    /// (`lib/curl_trc.c:54`, `:142`); a sink that wants to count failures does
    /// so itself, as [`WriterSink::error_count`] shows.
    fn emit(&mut self, kind: InfoType, ids: &str, payload: &[u8]);
}

/// A [`TraceSink`] that writes to a stream, reproducing C's `fwrite()` path.
///
/// The `else` branches of `trc_write()` and `Curl_debug()`
/// (`lib/curl_trc.c:58-71`, `:152-169`): the two-character kind prefix followed
/// by the payload, and only for the three kinds a plain writer renders at all
/// (see [`InfoType::is_written_plain`]).
///
/// This is `data->set.err`, which defaults to standard error. The command-line
/// tool never reaches it, because it always installs a
/// `CURLOPT_DEBUGFUNCTION`; it is the library's own behaviour for an embedding
/// application that sets only `CURLOPT_VERBOSE`, and it is what the capture used
/// to verify this module's layouts exercised.
#[derive(Clone, Debug)]
pub(crate) struct WriterSink<W> {
    writer: W,
    errors: usize,
}

impl<W: io::Write> WriterSink<W> {
    /// Wrap a stream.
    pub(crate) fn new(writer: W) -> Self {
        Self { writer, errors: 0 }
    }

    /// How many records failed to write.
    ///
    /// C cannot answer this: it ignores every `fwrite()` result. Counting is
    /// strictly additional information and changes no output, which keeps it
    /// inside the preservation mandate while making a broken destination
    /// diagnosable.
    pub(crate) fn error_count(&self) -> usize {
        self.errors
    }

    /// The wrapped stream, for a caller that needs to flush or reclaim it.
    pub(crate) fn into_inner(self) -> W {
        self.writer
    }

    /// Write the three parts of a record, reporting the first failure.
    fn write_record(&mut self, ids: &str, prefix: &str, payload: &[u8]) -> io::Result<()> {
        // Three writes in C's order. `write_all` rather than `write`, because
        // `fwrite()` of a single element either transfers it or fails.
        self.writer.write_all(ids.as_bytes())?;
        self.writer.write_all(prefix.as_bytes())?;
        self.writer.write_all(payload)
    }
}

impl<W: io::Write> TraceSink for WriterSink<W> {
    fn emit(&mut self, kind: InfoType, ids: &str, payload: &[u8]) {
        // C's `switch` drops every other kind through a `default` arm commented
        // "nada" (`lib/curl_trc.c:68-69`, `:166-167`).
        if !kind.is_written_plain() {
            return;
        }
        if self.write_record(ids, kind.prefix(), payload).is_err() {
            self.errors += 1;
        }
    }
}

/// Wall-clock time of day, decomposed, for the `--trace-time` prefix.
///
/// The fields `hms_for_sec()` reads out of `struct tm` plus the microseconds
/// `tool_debug_cb()` appends (`src/tool_cb_dbg.c:36-50`, `:147-150`).
///
/// Decomposed rather than an instant because the conversion is the part that
/// cannot be written here: C uses `toolx_localtime()`, and reproducing *local*
/// time needs a platform call that this crate may not make under
/// `forbid(unsafe_code)`. Emitting UTC instead would be a behaviour change, so
/// the split is deliberate -- whoever can perform the conversion supplies these
/// fields, and this module owns only their rendering.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct TraceTime {
    /// Hour, `0..=23`. C's `now.tm_hour`.
    pub(crate) hour: u8,
    /// Minute, `0..=59`. C's `now.tm_min`.
    pub(crate) minute: u8,
    /// Second, `0..=60` -- C prints `now.tm_sec` unaltered, and a leap second
    /// is 60 there.
    pub(crate) second: u8,
    /// Microsecond within the second, `0..=999_999`. C's `(long)tv.tv_usec`
    /// under `%06ld`.
    pub(crate) microsecond: u32,
}

impl TraceTime {
    /// The value C prints when the local-time conversion fails.
    ///
    /// `hms_for_sec()` zeroes the whole `struct tm` on error
    /// (`src/tool_cb_dbg.c:44-45`), so the hour, minute and second all read
    /// zero. A clock implementation that cannot convert returns this rather
    /// than inventing a plausible time or failing the trace.
    pub(crate) const CONVERSION_FAILED: Self = Self {
        hour: 0,
        minute: 0,
        second: 0,
        microsecond: 0,
    };
}

/// Renders the `--trace-time` prefix, trailing space included.
///
/// `"%02d:%02d:%02d"` from `hms_for_sec()` (`src/tool_cb_dbg.c:46-47`) inside
/// `"%s.%06ld "` from `tool_debug_cb()` (`src/tool_cb_dbg.c:149-150`), giving
/// `09:32:55.600049 ` -- sixteen bytes, the last of them a space that belongs to
/// the prefix.
///
/// The widths are minima in C too: `%02d` and `%06ld` pad but do not truncate,
/// so an out-of-range field widens the line here exactly as it would there.
impl fmt::Display for TraceTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02}:{:02}:{:02}.{:06} ",
            self.hour, self.minute, self.second, self.microsecond
        )
    }
}

/// Source of the time `--trace-time` prints.
///
/// Injected rather than read from the process clock, because AAP section 0.3.3
/// P12 requires it and because a trace containing an unpinnable timestamp cannot
/// be compared byte for byte in a test. Nothing in this module calls
/// `SystemTime::now()` or `Instant::now()`; the platform implementation belongs
/// to `crate::ffi::sys`, which owns the local-time conversion and the `unsafe`
/// it needs, or to the command-line adapter.
pub(crate) trait TraceClock {
    /// The current local time of day.
    ///
    /// Returns [`TraceTime::CONVERSION_FAILED`] if the platform cannot convert,
    /// which is what C prints in that case rather than an error.
    fn now(&self) -> TraceTime;
}

/// The caller's `CURLOPT_ERRORBUFFER`, and whether it has been filled.
///
/// `data->set.errorbuffer` together with the `data->state.errorbuf` flag that
/// records whether a message has already been stored
/// (`lib/curl_trc.c:186-189`).
///
/// The flag is the whole point: it makes the *first* failure the one the
/// application sees. Later `failf()` calls still reach the trace log but leave
/// the buffer alone, so a root cause is not overwritten by the consequences it
/// provoked -- which is why `Curl_reset_fail()` exists to clear it deliberately
/// when a happy-eyeballs attempt that failed is superseded by one that
/// succeeded (`lib/curl_trc.h:64-67`).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ErrorBuffer {
    message: Vec<u8>,
    written: bool,
}

impl ErrorBuffer {
    /// Size of the C buffer, its NUL included: `CURL_ERROR_SIZE`.
    pub(crate) const CAPACITY: usize = CURL_ERROR_SIZE;

    /// Most message bytes storable, `CURL_ERROR_SIZE - 1`.
    ///
    /// `Curl_failf()` formats with `curl_mvsnprintf(error, CURL_ERROR_SIZE,
    /// ...)` (`lib/curl_trc.c:184`), which reserves one byte for the
    /// terminator.
    pub(crate) const CONTENT_MAX: usize = CURL_ERROR_SIZE - 1;

    /// An empty, unfilled buffer.
    pub(crate) fn new() -> Self {
        Self {
            message: Vec::new(),
            written: false,
        }
    }

    /// Whether a message has been stored, C's `data->state.errorbuf`.
    pub(crate) fn is_set(&self) -> bool {
        self.written
    }

    /// The stored message as bytes, without a terminator and without the
    /// newline that the trace copy carries.
    ///
    /// C stores the message *before* appending `'\n'`
    /// (`lib/curl_trc.c:187-190`), so the buffer an application reads has no
    /// line ending. That difference between the two copies is preserved.
    pub(crate) fn message_bytes(&self) -> &[u8] {
        &self.message
    }

    /// The stored message as text, with invalid sequences replaced.
    ///
    /// Lossy because the bytes come from format output that may have spliced in
    /// arbitrary protocol data, and because C makes no encoding promise about
    /// this buffer at all.
    pub(crate) fn message_lossy(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.message)
    }

    /// Store `message` if nothing has been stored yet.
    ///
    /// The `if(data->set.errorbuffer && !data->state.errorbuf)` guard of
    /// `Curl_failf()` (`lib/curl_trc.c:186-189`). Returns whether the message
    /// was taken. Input longer than [`CONTENT_MAX`](Self::CONTENT_MAX) is
    /// truncated, which is what C's bounded copy does.
    pub(crate) fn set_first(&mut self, message: &[u8]) -> bool {
        if self.written {
            return false;
        }
        let take = message.len().min(Self::CONTENT_MAX);
        self.message.clear();
        self.message.extend_from_slice(&message[..take]);
        self.written = true;
        true
    }

    /// Clear the buffer and the flag, so the next failure is recorded again.
    ///
    /// `Curl_reset_fail()` (`lib/curl_trc.c:197-202`). C only writes a NUL at
    /// offset zero rather than wiping the whole array, which for an owned
    /// buffer is emptying it.
    pub(crate) fn reset(&mut self) {
        self.message.clear();
        self.written = false;
    }
}

/// Per-transfer trace state: the three `struct Curl_easy` members every emitter
/// reads.
///
/// * `verbose` is `data->set.verbose`, set by `CURLOPT_VERBOSE`.
/// * `feat` is `data->state.feat`, the feature a protocol installs for the
///   duration of its own work so that its lines are labelled and can be
///   suppressed as a group. `Curl_infof()` and `Curl_trc_cf_infof()` both pass
///   it straight through (`lib/curl_trc.c:261`, `:275`), which is why a
///   connection-filter line inherits the protocol's label.
/// * `ids` is the transfer and connection identifier pair that
///   `trc_print_ids()` renders (`lib/curl_trc.c:91-106`).
///
/// Grouped into one `Copy` value so a caller can save, replace and restore the
/// feature label around a nested operation, which is what C does by assigning
/// to `data->state.feat` directly.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct TraceState {
    /// `data->set.verbose`: whether tracing is on for this transfer at all.
    pub(crate) verbose: bool,
    /// `data->state.feat`: the feature label currently in force, if any.
    pub(crate) feat: Option<TraceFeature>,
    /// `data->id` and the connection id, as rendered by `trc_print_ids()`.
    pub(crate) ids: TraceIds,
}

impl TraceState {
    /// Silent state: not verbose, no feature label, no identifiers.
    ///
    /// What a freshly initialised easy handle carries.
    pub(crate) const SILENT: Self = Self {
        verbose: false,
        feat: None,
        ids: TraceIds::UNASSIGNED,
    };

    /// Verbose state with no feature label and no identifiers.
    ///
    /// The state `CURLOPT_VERBOSE` alone produces, before a transfer has been
    /// given an id or a protocol has installed a label.
    pub(crate) fn verbose() -> Self {
        Self {
            verbose: true,
            ..Self::SILENT
        }
    }
}

/// Emits trace records for one transfer.
///
/// This is the `Curl_easy`-plus-globals bundle that every `Curl_trc_*` entry
/// point in `lib/curl_trc.c` operates on, made explicit:
///
/// | C | here |
/// |---|------|
/// | `Curl_trc_feat_*.log_level`, file-scope mutable globals | [`TraceConfig`], borrowed |
/// | `data->set.fdebug` / `data->set.err` | [`TraceSink`], borrowed |
/// | `data->set.errorbuffer`, `data->state.errorbuf` | [`ErrorBuffer`], borrowed |
/// | `data->set.verbose`, `data->state.feat`, `data->id` | [`TraceState`], owned |
///
/// Everything is borrowed rather than owned or reached for, which is AAP section
/// 0.3.3 P12 applied to observability: two tests can each hold their own
/// `Tracer` over their own capture buffer and neither observes the other. No
/// item in this module reads process state, and there is no `static mut` and no
/// singleton anywhere in it.
///
/// # Level guards
///
/// Every emitter re-tests its level before formatting, exactly as C does, and
/// the [`infof!`] family of macros tests again at the call site. The duplication
/// is deliberate and is *behavioural*, not an optimisation: C's macros exist so
/// that a suppressed trace never evaluates its arguments
/// (`lib/curl_trc.h:138-208`), and an argument may have a side effect or be
/// expensive enough that evaluating it changes observable timing. Performance is
/// an explicit non-goal (AAP section 0.1.1); preserving the shape is not.
///
/// # Example
///
/// Marked `ignore` because every item here is `pub(crate)` and a doctest
/// compiles as a separate crate, so it could not reach them. The snippet is
/// therefore reproduced verbatim by a unit test -- see
/// `tests::the_documented_example_writes_the_line_it_claims` -- rather than
/// being left to drift.
///
/// ```ignore
/// let mut config = TraceConfig::new();
/// config.apply(Some("multi,lib-ids"))?;
/// let mut sink = WriterSink::new(std::io::stderr());
/// let mut tracer = Tracer::new(&config, &mut sink);
/// tracer.set_state(TraceState { verbose: true, feat: None, ids: TraceIds::new(0, 0) });
/// trc_multi!(&mut tracer, CurlMstate::Connecting, "-> [{}]", CurlMstate::ProtoConnect);
/// // writes: * [0-0] [MULTI] [CONNECTING] -> [PROTOCONNECT]
/// ```
pub(crate) struct Tracer<'a> {
    config: &'a TraceConfig,
    sink: &'a mut dyn TraceSink,
    error_buffer: Option<&'a mut ErrorBuffer>,
    state: TraceState,
    line: LineBuffer,
}

impl<'a> Tracer<'a> {
    /// A tracer over `config` and `sink`, initially silent and unlabelled.
    ///
    /// Silent because `data->set.verbose` defaults to false: a handle traces
    /// nothing until `CURLOPT_VERBOSE` is set.
    pub(crate) fn new(config: &'a TraceConfig, sink: &'a mut dyn TraceSink) -> Self {
        Self {
            config,
            sink,
            error_buffer: None,
            state: TraceState::SILENT,
            line: LineBuffer::new(),
        }
    }

    /// Attach the caller's `CURLOPT_ERRORBUFFER`.
    ///
    /// Without one, [`failf`](Self::failf) still writes to the trace log; with
    /// one, the first failure is also stored. That is C's arrangement, where the
    /// buffer is optional and its absence changes nothing else.
    pub(crate) fn with_error_buffer(mut self, buffer: &'a mut ErrorBuffer) -> Self {
        self.error_buffer = Some(buffer);
        self
    }

    /// Start from a known trace state.
    pub(crate) fn with_state(mut self, state: TraceState) -> Self {
        self.state = state;
        self
    }

    /// The trace configuration in force.
    pub(crate) fn config(&self) -> &TraceConfig {
        self.config
    }

    /// The current trace state.
    pub(crate) fn state(&self) -> TraceState {
        self.state
    }

    /// Replace the whole trace state.
    pub(crate) fn set_state(&mut self, state: TraceState) {
        self.state = state;
    }

    /// Set `data->set.verbose`.
    pub(crate) fn set_verbose(&mut self, verbose: bool) {
        self.state.verbose = verbose;
    }

    /// Set `data->state.feat`, returning the label it replaced.
    ///
    /// Returning the previous value is what makes save-and-restore around a
    /// nested operation possible without the caller keeping its own copy; C
    /// assigns through the pointer and remembers the old one by hand.
    pub(crate) fn set_feature(&mut self, feat: Option<TraceFeature>) -> Option<TraceFeature> {
        let previous = self.state.feat;
        self.state.feat = feat;
        previous
    }

    /// Set the transfer and connection identifiers.
    pub(crate) fn set_ids(&mut self, ids: TraceIds) {
        self.state.ids = ids;
    }

    /// The attached error buffer, if any.
    pub(crate) fn error_buffer(&self) -> Option<&ErrorBuffer> {
        self.error_buffer.as_deref()
    }

    /// `Curl_trc_is_verbose()`: is this transfer tracing at all?
    ///
    /// `data->set.verbose && (!data->state.feat || feat->log_level >= INFO)`
    /// (`lib/curl_trc.h:311-314`). The second clause is what lets
    /// `--trace-config -ftp` silence a whole protocol's ordinary `infof()`
    /// output, not merely the lines that name FTP explicitly.
    pub(crate) fn is_verbose(&self) -> bool {
        if !self.state.verbose {
            return false;
        }
        match self.state.feat {
            // No label in force: nothing further to gate on.
            None => true,
            Some(feat) => self.config.feature_is_info(feat),
        }
    }

    /// `Curl_trc_ft_is_verbose()`: is `feature` tracing?
    ///
    /// `Curl_trc_is_verbose(data) && ft->log_level >= INFO`
    /// (`lib/curl_trc.h:318-320`). Note both feature levels are consulted: the
    /// label in force *and* the one being emitted for.
    pub(crate) fn is_feature_verbose(&self, feature: TraceFeature) -> bool {
        self.is_verbose() && self.config.feature_is_info(feature)
    }

    /// `Curl_trc_cf_is_verbose()`: is `filter` tracing?
    ///
    /// `Curl_trc_is_verbose(data) && cf->cft->log_level >= INFO`
    /// (`lib/curl_trc.h:315-317`).
    pub(crate) fn is_filter_verbose(&self, filter: TraceFilter) -> bool {
        self.is_verbose() && self.config.filter_is_info(filter)
    }

    /// `CURL_TRC_IDS()`: should records carry the identifier prefix?
    ///
    /// `Curl_trc_is_verbose(data) && Curl_trc_feat_ids.log_level >= INFO`
    /// (`lib/curl_trc.c:87-89`).
    ///
    /// Off by default and unreachable through the command-line tool, which
    /// appends `,-lib-ids` to whatever it forwards to `curl_global_trace()`
    /// (`src/tool_getparam.c:766-800`); an embedding application that asks for
    /// `lib-ids` directly does get it.
    pub(crate) fn is_ids_verbose(&self) -> bool {
        self.is_verbose() && self.config.feature_is_info(TraceFeature::Ids)
    }

    /// `Curl_infof()`: an informational line under the current feature label.
    ///
    /// `lib/curl_trc.c:256-265`. Prefer the [`infof!`] macro, which also
    /// enforces the no-newline invariant at compile time.
    pub(crate) fn infof(&mut self, args: fmt::Arguments<'_>) {
        if self.is_verbose() {
            let feat = self.state.feat;
            self.assemble(feat, None, 0, args);
        }
    }

    /// `Curl_failf()`: state why the transfer failed.
    ///
    /// `lib/curl_trc.c:176-195`. Three details of that function are
    /// behaviourally visible and all three are reproduced:
    ///
    /// * The gate is `verbose || errorbuffer`, *not* `Curl_trc_is_verbose()`. A
    ///   failure reaches the caller's buffer even when tracing is off, and it is
    ///   not filtered by the feature label -- an error must not be swallowed by
    ///   a `--trace-config` selection.
    /// * The message is capped at `CURL_ERROR_SIZE - 1` bytes, a tighter budget
    ///   than a trace line's.
    /// * The copy stored in the buffer has no newline; the copy written to the
    ///   log has one, appended unconditionally.
    pub(crate) fn failf(&mut self, args: fmt::Arguments<'_>) {
        if !(self.state.verbose || self.error_buffer.is_some()) {
            return;
        }

        // C's `char error[CURL_ERROR_SIZE + 2]` filled by
        // `curl_mvsnprintf(error, CURL_ERROR_SIZE, ...)`: the array is two
        // bytes larger than the cap so that the newline and terminator always
        // fit, which is why the newline is appended without a length test.
        let mut message = LineBuffer::with_content_max(ErrorBuffer::CONTENT_MAX);
        message.push_fmt(args);

        if let Some(buffer) = self.error_buffer.as_deref_mut() {
            // Stored before the newline is appended, and only if this is the
            // first failure.
            buffer.set_first(message.as_bytes());
        }

        message.push_newline();
        if self.state.verbose {
            // `trc_write()` re-tests `data->set.verbose`
            // (`lib/curl_trc.c:50`), so a handle with only an error buffer
            // stores the message without logging it.
            self.sink.emit(InfoType::Text, "", message.as_bytes());
        }
    }

    /// `Curl_reset_fail()`: forget the stored failure.
    ///
    /// `lib/curl_trc.c:197-202`. Called when an attempt that failed is
    /// superseded by one that succeeded, so the surviving path's error -- or no
    /// error at all -- is what the application reads.
    pub(crate) fn reset_fail(&mut self) {
        if let Some(buffer) = self.error_buffer.as_deref_mut() {
            buffer.reset();
        }
    }

    /// The `Curl_trc_read()`, `_write()`, `_dns()`, `_ftp()`, `_ssls()`,
    /// `_ssh()` and `_ws()` family: a line labelled with `feature`.
    ///
    /// Those seven functions are identical but for the feature they name
    /// (`lib/curl_trc.c:373-489`), so they are one method here. Each passes no
    /// `opt_id`, which is why such lines read `* [READ] ...` with a single
    /// bracket group.
    pub(crate) fn feature(&mut self, feature: TraceFeature, args: fmt::Arguments<'_>) {
        if self.is_feature_verbose(feature) {
            self.assemble(Some(feature), None, 0, args);
        }
    }

    /// `Curl_trc_multi()`: a multi-handle line carrying the transfer's state.
    ///
    /// `lib/curl_trc.c:361-372`. The state name becomes the second bracket
    /// group, giving `* [MULTI] [CONNECTING] -> [PROTOCONNECT]`, and is included
    /// only when the transfer has an assigned id -- C's
    /// `(data->id >= 0) ? Curl_trc_mstate_name(data->mstate) : NULL`. A transfer
    /// not yet added to a multi handle has no meaningful state to report, so the
    /// group is omitted rather than filled with a placeholder.
    ///
    /// **This is where AAP section 0.3.3 P3 pays off.** The name comes from
    /// [`CurlMstate::name`], an exhaustive `match` in the module that owns the
    /// enum. C instead keeps `Curl_trc_mstate_names[]` in this file and asks
    /// maintainers to remember it (`lib/multihandle.h:48-49`) -- a note that has
    /// itself gone stale, since the array it names was renamed. Adding a state
    /// without naming it is a compile error here and cannot be one there.
    pub(crate) fn multi(&mut self, mstate: CurlMstate, args: fmt::Arguments<'_>) {
        if self.is_feature_verbose(TraceFeature::Multi) {
            let name = if self.state.ids.has_xfer_id() {
                Some(mstate.name())
            } else {
                None
            };
            self.assemble(Some(TraceFeature::Multi), name, 0, args);
        }
    }

    /// `Curl_trc_timer()`: a timer line naming `timer`.
    ///
    /// `lib/curl_trc.c:306-316`, giving `* [TIMER] [HAPPY_EYEBALLS] cleared`.
    pub(crate) fn timer(&mut self, timer: TimerId, args: fmt::Arguments<'_>) {
        if self.is_feature_verbose(TraceFeature::Timer) {
            self.assemble(Some(TraceFeature::Timer), Some(timer.name()), 0, args);
        }
    }

    /// `Curl_trc_timer()` reached with a raw timer number.
    ///
    /// C's parameter is an `int` and `trc_timer_name()` bounds-checks it,
    /// yielding `"UNKNOWN?"` when it is out of range (`lib/curl_trc.c:299-304`).
    /// Rust callers use [`timer`](Self::timer) and cannot be out of range; this
    /// exists for the C ABI shim, where the value arrives from outside the
    /// crate and the fallback is genuinely reachable.
    pub(crate) fn timer_id(&mut self, timer: i32, args: fmt::Arguments<'_>) {
        if self.is_feature_verbose(TraceFeature::Timer) {
            let name = TimerId::name_from_i32(timer);
            self.assemble(Some(TraceFeature::Timer), Some(name), 0, args);
        }
    }

    /// `Curl_trc_easy_timers()`: dump every pending timer's remaining time.
    ///
    /// `lib/curl_trc.c:318-332`. Takes the transfer's timeout list as an
    /// iterator of `(timer, remaining)` pairs, because this module does not own
    /// the list and should not learn its shape.
    ///
    /// The whole loop is skipped when the timer feature is off, matching C's
    /// outer `CURL_TRC_TIMER_is_verbose(data)` guard: the caller's iterator is
    /// then never advanced, so walking the list costs nothing.
    ///
    /// # The `ns` label
    ///
    /// C formats `curlx_ptimediff_us()` -- a value in **microseconds** -- under
    /// the literal suffix `ns` (`lib/curl_trc.c:327-328`). The suffix is wrong
    /// and it is reproduced verbatim. AAP section 0.8.1 freezes observable
    /// output and section 0.8.2 forbids a behaviour change justified as an
    /// improvement, so `remaining_micros` is printed with `ns` after it. Callers
    /// must pass microseconds; passing nanoseconds to make the label true would
    /// change the numbers curl prints.
    pub(crate) fn easy_timers<I>(&mut self, timers: I)
    where
        I: IntoIterator<Item = (TimerId, i64)>,
    {
        if !self.is_feature_verbose(TraceFeature::Timer) {
            return;
        }
        for (timer, remaining_micros) in timers {
            self.timer(timer, format_args!("expires in {remaining_micros}ns"));
        }
    }

    /// `Curl_trc_cf_infof()`: a line attributed to a connection filter.
    ///
    /// `lib/curl_trc.c:267-278`. The filter's name becomes the second bracket
    /// group and its socket index is appended when non-zero, so a line reads
    /// `* [TCP] connected` for socket 0 and `* [TCP-1] connected` for socket 1.
    /// Zero is the primary socket and is left implicit -- the captured C output
    /// confirms `[TCP]` with no suffix there.
    ///
    /// The feature label passed on is `data->state.feat`, the *protocol's*
    /// label, not the filter's: a filter line is labelled by whichever protocol
    /// is driving it, while the gate is the filter's own level.
    pub(crate) fn filter(&mut self, filter: TraceFilter, sockindex: i32, args: fmt::Arguments<'_>) {
        if self.is_filter_verbose(filter) {
            let feat = self.state.feat;
            self.assemble(feat, Some(filter.name()), sockindex, args);
        }
    }

    /// `Curl_debug()`: emit protocol bytes or text with a kind prefix.
    ///
    /// `lib/curl_trc.c:125-171`. This is the path headers and payload take, and
    /// it is the one place where the destination changes the record's *content*:
    ///
    /// * **Stream destination.** The identifiers, then the two-character kind
    ///   prefix, then the bytes -- and only for the three kinds a plain writer
    ///   renders, the rest falling through C's `default: /* nada */`. Hence
    ///   `[0-0] > GET /data.txt HTTP/1.1`, identifiers *before* the prefix.
    /// * **Callback destination.** The identifiers are built into the record and
    ///   no prefix is added, leaving presentation to the caller. That only
    ///   happens when identifiers are enabled *and* the payload is shorter than
    ///   [`TRC_LINE_MAX`]; otherwise the bytes are handed over untouched, at
    ///   their true length, because a large body must not be truncated to fit a
    ///   trace buffer.
    ///
    /// One consequence of C's `"%.*s"` is preserved in the identifier-prefixed
    /// callback case: `out_string()` copies with `for(; len && *str; len--)`
    /// (`lib/mprintf.c:879`), which stops at the first NUL even with an explicit
    /// precision. A payload containing a NUL is therefore cut there. It is
    /// reachable only with `lib-ids` enabled, and it is C's behaviour, so it is
    /// reproduced rather than quietly corrected.
    pub(crate) fn debug(&mut self, kind: InfoType, payload: &[u8]) {
        // `Curl_debug()` gates on `data->set.verbose` alone: the kind prefix
        // path is not filtered by the feature label.
        if !self.state.verbose {
            return;
        }

        if self.sink.is_user_callback() {
            if self.is_ids_verbose() && payload.len() < TRC_LINE_MAX {
                let ids = self.state.ids;
                self.line.clear();
                self.line.push_fmt(format_args!("{ids}"));
                // `%.*s` stops at a NUL; see the method documentation.
                let text = match payload.iter().position(|&byte| byte == 0) {
                    Some(nul) => &payload[..nul],
                    None => payload,
                };
                self.line.push_bytes(text);
                let record = self.line.finish(false);
                self.sink.emit(kind, "", record);
            } else {
                self.sink.emit(kind, "", payload);
            }
        } else if self.is_ids_verbose() && kind.is_written_plain() {
            // C renders the identifiers with the same bounded buffer, then
            // writes them ahead of the prefix.
            let ids = self.state.ids;
            self.line.clear();
            self.line.push_fmt(format_args!("{ids}"));
            let ids = String::from_utf8_lossy(self.line.as_bytes()).into_owned();
            self.sink.emit(kind, &ids, payload);
        } else {
            self.sink.emit(kind, "", payload);
        }
    }

    /// `trc_infof()`: assemble one informational line and hand it to the sink.
    ///
    /// `lib/curl_trc.c:234-256`, in C's order and with C's spacing:
    ///
    /// 1. the identifier block, when [`is_ids_verbose`](Self::is_ids_verbose);
    /// 2. `"[{feat}] "` when a feature label applies;
    /// 3. `"[{opt_id}] "`, or `"[{opt_id}-{idx}] "` when `opt_id_idx > 0`;
    /// 4. the caller's message;
    /// 5. `trc_end_buf()` with a newline.
    ///
    /// Every part shares one 2047-byte budget, so a long message is truncated to
    /// `"...\n"` rather than displacing the prefixes.
    fn assemble(
        &mut self,
        feat: Option<TraceFeature>,
        opt_id: Option<&str>,
        opt_id_idx: i32,
        args: fmt::Arguments<'_>,
    ) {
        self.line.clear();

        if self.is_ids_verbose() {
            let ids = self.state.ids;
            self.line.push_fmt(format_args!("{ids}"));
        }
        if let Some(feat) = feat {
            let name = feat.name();
            self.line.push_fmt(format_args!("[{name}] "));
        }
        if let Some(opt_id) = opt_id {
            if opt_id_idx > 0 {
                self.line.push_fmt(format_args!("[{opt_id}-{opt_id_idx}] "));
            } else {
                self.line.push_fmt(format_args!("[{opt_id}] "));
            }
        }
        self.line.push_fmt(args);

        let record = self.line.finish(true);
        // `trc_write()` tests `data->set.verbose` again (`lib/curl_trc.c:50`).
        // Every caller has already established it; the test is kept because it
        // is C's, and because it makes this the single place a record can be
        // suppressed.
        if self.state.verbose {
            self.sink.emit(InfoType::Text, "", record);
        }
    }
}

/// A [`Tracer`] borrows its sink mutably, so it cannot be `Clone`; this shows
/// what it is configured with without exposing either borrow.
impl fmt::Debug for Tracer<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tracer")
            .field("state", &self.state)
            .field("has_error_buffer", &self.error_buffer.is_some())
            .field("is_user_callback", &self.sink.is_user_callback())
            .finish_non_exhaustive()
    }
}

/// Layout of a [`dump`] block: with hex columns, or characters only.
///
/// The two of C's four `trace` values that reach `dump()`
/// (`src/tool_sdecls.h:104-109`). `TRACE_NONE` disables tracing before any dump
/// happens and `TRACE_PLAIN` writes the payload verbatim through
/// [`Tracer::debug`], so neither has a variant here: an enumerant that cannot
/// occur is a state to be made unrepresentable, not carried.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum DumpStyle {
    /// `TRACE_BIN`, `--trace`: hex columns then the character column.
    Hex,
    /// `TRACE_ASCII`, `--trace-ascii`: characters only, and CRLF starts a new
    /// line.
    Ascii,
}

impl DumpStyle {
    /// Bytes per output line.
    ///
    /// `0x10` for hex and `0x40` for ASCII, C's `width`
    /// (`src/tool_cb_dbg.c:75-79`); the wider setting exists because "without
    /// the hex output, we can fit more on screen".
    pub(crate) const fn width(self) -> usize {
        match self {
            Self::Hex => 0x10,
            Self::Ascii => 0x40,
        }
    }

    /// Whether this style shows the hex columns.
    const fn shows_hex(self) -> bool {
        matches!(self, Self::Hex)
    }

    /// Whether this style breaks a line at CRLF.
    ///
    /// Only `--trace-ascii` does; the hex layout keeps fixed 16-byte rows so its
    /// offsets stay aligned.
    const fn breaks_at_crlf(self) -> bool {
        matches!(self, Self::Ascii)
    }
}

/// The character an unprintable byte is shown as.
///
/// `UNPRINTABLE_CHAR` (`src/tool_setup.h:63`).
const UNPRINTABLE_CHAR: u8 = b'.';

/// Lowest byte value shown as itself, C's `>= 0x20` test
/// (`src/tool_cb_dbg.c:106-108`).
const PRINTABLE_LOW: u8 = 0x20;

/// First byte value above the printable range, C's `< 0x7F` test.
const PRINTABLE_HIGH: u8 = 0x7F;

/// Render a hex/ASCII dump block, the body of `--trace` and `--trace-ascii`.
///
/// `dump()` (`src/tool_cb_dbg.c:68-119`), reproduced geometry for geometry
/// because AAP section 0.8.1 freezes it and fixtures compare it. A header line
/// then one line per row:
///
/// ```text
/// == Info: ...
/// <= Recv data, 52 bytes (0x34)
/// 0000: 48 65 6c 6c 6f 2c 20 63 75 72 6c 20 74 72 61 63 Hello, curl trac
/// 0010: 65 20 6f 72 61 63 6c 65 21 0d 0a 53 65 63 6f 6e e oracle!..Secon
/// 0020: 64 20 6c 69 6e 65 20 68 65 72 65 0d 0a 74 68 69 d line here..thi
/// 0030: 72 64 0d 0a                                     rd..
/// ```
///
/// Exact details, each of them observable:
///
/// * Header: `"{time}{ids}{label}, {n} bytes (0x{n:x})"`. The count appears
///   twice, decimal then lower-case hex, and the label supplies its own leading
///   marker (see [`InfoType::dump_label`]).
/// * Offsets are `%04zx`: lower case, zero padded to four, widening past
///   64 KiB rather than wrapping.
/// * Hex columns are `"{:02x} "` with a trailing space each, and a short final
///   row is padded with three spaces per missing byte so the character column
///   stays aligned. That padding is why the last row above lines up.
/// * A byte in `0x20..0x7F` prints as itself, anything else as `.`.
/// * Under [`DumpStyle::Ascii`] a CRLF ends the row early and is skipped, which
///   is why the ASCII form shows one protocol line per output line. C expresses
///   the skip as `i += (c + 2 - width)` relying on the loop's own
///   `i += width`; that intermediate value underflows `size_t`, so the advance
///   is computed directly here. The resulting offsets are identical -- and were
///   checked against a capture from the C tool, which produced offsets
///   `0000`, `001b`, `002d` for the payload above.
/// * Every row ends with `\n`, and the block is flushed, as C's `fflush()` does.
///
/// C's `dump()` also takes a `curl_infotype` and immediately discards it with
/// `(void)infotype` (`src/tool_cb_dbg.c:105`). It is not a parameter here: it is
/// provably unused, and carrying it would imply otherwise.
///
/// Errors are returned rather than ignored. C checks no `fprintf()` result on
/// this path; propagating gives the caller the option, and no caller is obliged
/// to act, so no output changes.
pub(crate) fn dump(
    out: &mut dyn io::Write,
    time_prefix: &str,
    ids_prefix: &str,
    label: &str,
    payload: &[u8],
    style: DumpStyle,
) -> io::Result<()> {
    let width = style.width();
    let size = payload.len();

    // `"%s%s%s, %zu bytes (0x%zx)\n"` (`src/tool_cb_dbg.c:81-82`).
    writeln!(
        out,
        "{time_prefix}{ids_prefix}{label}, {size} bytes (0x{size:x})"
    )?;

    let mut i = 0usize;
    while i < size {
        // `"%04zx: "` (`src/tool_cb_dbg.c:86`).
        write!(out, "{i:04x}: ")?;

        if style.shows_hex() {
            for column in 0..width {
                match payload.get(i + column) {
                    Some(byte) => write!(out, "{byte:02x} ")?,
                    // `fputs("   ", stream)`: three spaces per absent byte, so
                    // the character column of a short final row stays aligned.
                    None => out.write_all(b"   ")?,
                }
            }
        }

        // Where the next row starts. C reaches the same value by adjusting `i`
        // inside the loop and letting `i += width` finish the sum; done directly
        // to keep every intermediate in range.
        let mut next = i + width;
        let mut column = 0usize;
        while column < width && i + column < size {
            // "check for 0D0A; if found, skip past and start a new line of
            // output" (`src/tool_cb_dbg.c:98-103`). C's `i += (c + 2 - width)`
            // plus `i += width` is `i + c + 2`.
            if style.breaks_at_crlf()
                && i + column + 1 < size
                && payload[i + column] == b'\r'
                && payload[i + column + 1] == b'\n'
            {
                next = i + column + 2;
                break;
            }

            let byte = payload[i + column];
            let shown = if (PRINTABLE_LOW..PRINTABLE_HIGH).contains(&byte) {
                byte
            } else {
                UNPRINTABLE_CHAR
            };
            out.write_all(&[shown])?;

            // "check again for 0D0A, to avoid an extra \n if it is at width"
            // (`src/tool_cb_dbg.c:110-115`). C's `i += (c + 3 - width)` plus
            // `i += width` is `i + c + 3`: the byte just written, then the CRLF.
            if style.breaks_at_crlf()
                && i + column + 2 < size
                && payload[i + column + 1] == b'\r'
                && payload[i + column + 2] == b'\n'
            {
                next = i + column + 3;
                break;
            }

            column += 1;
        }

        out.write_all(b"\n")?;
        i = next;
    }

    out.flush()
}

/// Whether a trace format string contains a line feed.
///
/// Backs the compile-time check in every emitter macro. C asserts the same
/// property at run time in every one of its entry points --
/// `DEBUGASSERT(!strchr(fmt, '\n'))` -- because the emitter appends the line
/// terminator itself and an embedded one splits a record in two, breaking the
/// prefix on the fragment that follows.
///
/// `const fn`, so the macros can reject a bad format string when the crate is
/// compiled rather than when the line is first traced. That is strictly stronger
/// than C, whose assertion is compiled out of a release build entirely and so
/// never fires where it would matter.
///
/// Only the line feed is tested, matching the assertion. `Curl_failf()`'s
/// comment asks for neither LF nor CR (`lib/curl_trc.c:174-175`), but the check
/// C actually performs is LF alone, and a carriage return does appear in
/// legitimate messages that quote protocol text.
pub(crate) const fn fmt_has_newline(fmt: &str) -> bool {
    let bytes = fmt.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\n' {
            return true;
        }
        index += 1;
    }
    false
}

/// `infof()`: an informational line, guarded and newline-checked.
///
/// The `#define infof` of `lib/curl_trc.h:138-146`. The first argument is a
/// `&mut Tracer`; the rest is a format string and its arguments.
///
/// Two properties C's macro has and this one keeps:
///
/// * **The level is tested before the arguments are evaluated.** A suppressed
///   trace must not run its arguments, which may have side effects.
///   [`Tracer::infof`] tests again, exactly as `Curl_infof()` does.
/// * **The format string must not contain a newline.** Checked here at compile
///   time via [`fmt_has_newline`], where C asserts at run time and only in a
///   debug build.
///
/// ```ignore
/// infof!(tracer, "Connected to {host} port {port}");
/// ```
macro_rules! infof {
    ($tracer:expr, $fmt:literal $(, $arg:expr)* $(,)?) => {{
        const _: () = ::core::assert!(
            !$crate::trace::fmt_has_newline($fmt),
            "a trace format string must not contain a newline: the emitter appends one"
        );
        let tracer: &mut $crate::trace::Tracer<'_> = $tracer;
        if tracer.is_verbose() {
            tracer.infof(::core::format_args!($fmt $(, $arg)*));
        }
    }};
}
pub(crate) use infof;

/// `failf()`: state why the transfer failed.
///
/// `#define failf Curl_failf` (`lib/curl_trc.h:62`) -- a plain alias with **no**
/// level guard, and that absence is deliberate on both sides. The gate is
/// `verbose || errorbuffer` and lives inside [`Tracer::failf`], so a failure
/// still reaches the caller's `CURLOPT_ERRORBUFFER` when tracing is off. Adding
/// a guard here would lose that.
///
/// The newline check applies: `Curl_failf()` asserts it too.
///
/// ```ignore
/// failf!(tracer, "Could not resolve host: {host}");
/// ```
macro_rules! failf {
    ($tracer:expr, $fmt:literal $(, $arg:expr)* $(,)?) => {{
        const _: () = ::core::assert!(
            !$crate::trace::fmt_has_newline($fmt),
            "an error format string must not contain a newline: the emitter appends one"
        );
        let tracer: &mut $crate::trace::Tracer<'_> = $tracer;
        tracer.failf(::core::format_args!($fmt $(, $arg)*));
    }};
}
pub(crate) use failf;

/// `CURL_TRC_READ()`, `CURL_TRC_WRITE()`, `CURL_TRC_DNS()`, `CURL_TRC_FTP()`,
/// `CURL_TRC_SSLS()`, `CURL_TRC_SSH()`, `CURL_TRC_WS()`: a line labelled with a
/// feature.
///
/// `lib/curl_trc.h:153-208`, seven macros that differ only in the feature they
/// name, so one macro takes it as an argument.
///
/// ```ignore
/// trc_feat!(tracer, TraceFeature::Read, "client read {} bytes", n);
/// ```
macro_rules! trc_feat {
    ($tracer:expr, $feature:expr, $fmt:literal $(, $arg:expr)* $(,)?) => {{
        const _: () = ::core::assert!(
            !$crate::trace::fmt_has_newline($fmt),
            "a trace format string must not contain a newline: the emitter appends one"
        );
        let tracer: &mut $crate::trace::Tracer<'_> = $tracer;
        let feature: $crate::trace::TraceFeature = $feature;
        if tracer.is_feature_verbose(feature) {
            tracer.feature(feature, ::core::format_args!($fmt $(, $arg)*));
        }
    }};
}
pub(crate) use trc_feat;

/// `CURL_TRC_M()`: a multi-handle line carrying the transfer's state.
///
/// `lib/curl_trc.h:129-131` and `:163-166`. The state is a [`CurlMstate`], whose
/// name comes from an exhaustive `match` in the module that owns it, so a new
/// state cannot reach a trace line unnamed.
///
/// ```ignore
/// trc_multi!(tracer, mstate, "-> [{}]", next);
/// ```
macro_rules! trc_multi {
    ($tracer:expr, $mstate:expr, $fmt:literal $(, $arg:expr)* $(,)?) => {{
        const _: () = ::core::assert!(
            !$crate::trace::fmt_has_newline($fmt),
            "a trace format string must not contain a newline: the emitter appends one"
        );
        let tracer: &mut $crate::trace::Tracer<'_> = $tracer;
        if tracer.is_feature_verbose($crate::trace::TraceFeature::Multi) {
            let mstate: $crate::multi::state::CurlMstate = $mstate;
            tracer.multi(mstate, ::core::format_args!($fmt $(, $arg)*));
        }
    }};
}
pub(crate) use trc_multi;

/// `CURL_TRC_TIMER()`: a timer line naming the timer.
///
/// `lib/curl_trc.h:168-173`.
///
/// ```ignore
/// trc_timer!(tracer, TimerId::HappyEyeballs, "cleared");
/// ```
macro_rules! trc_timer {
    ($tracer:expr, $timer:expr, $fmt:literal $(, $arg:expr)* $(,)?) => {{
        const _: () = ::core::assert!(
            !$crate::trace::fmt_has_newline($fmt),
            "a trace format string must not contain a newline: the emitter appends one"
        );
        let tracer: &mut $crate::trace::Tracer<'_> = $tracer;
        if tracer.is_feature_verbose($crate::trace::TraceFeature::Timer) {
            let timer: $crate::trace::TimerId = $timer;
            tracer.timer(timer, ::core::format_args!($fmt $(, $arg)*));
        }
    }};
}
pub(crate) use trc_timer;

/// `CURL_TRC_CF()`: a line attributed to a connection filter.
///
/// `lib/curl_trc.h:148-152`. C reads the filter's name, level and socket index
/// out of `cf->cft` and `cf->sockindex`; here the filter identity and the socket
/// index are passed explicitly, which is what keeps the trace table typed rather
/// than reached through a vtable that merely happens to start with the right two
/// fields.
///
/// ```ignore
/// trc_cf!(tracer, TraceFilter::Tcp, sockindex, "connected to {peer}");
/// ```
macro_rules! trc_cf {
    ($tracer:expr, $filter:expr, $sockindex:expr, $fmt:literal $(, $arg:expr)* $(,)?) => {{
        const _: () = ::core::assert!(
            !$crate::trace::fmt_has_newline($fmt),
            "a trace format string must not contain a newline: the emitter appends one"
        );
        let tracer: &mut $crate::trace::Tracer<'_> = $tracer;
        let filter: $crate::trace::TraceFilter = $filter;
        if tracer.is_filter_verbose(filter) {
            tracer.filter(filter, $sockindex, ::core::format_args!($fmt $(, $arg)*));
        }
    }};
}
pub(crate) use trc_cf;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multi::state::CurlMstate;
    use std::cell::Cell;

    // ---------------------------------------------------------------------
    // Test doubles. Everything this module needs is injected, so no test
    // touches process state and the order tests run in cannot matter.
    // ---------------------------------------------------------------------

    /// Stands in for a `CURLOPT_DEBUGFUNCTION`, keeping every record whole.
    #[derive(Debug, Default)]
    struct CallbackSink {
        records: Vec<(InfoType, Vec<u8>)>,
    }

    impl TraceSink for CallbackSink {
        fn is_user_callback(&self) -> bool {
            true
        }

        fn emit(&mut self, kind: InfoType, ids: &str, payload: &[u8]) {
            let mut record = Vec::from(ids.as_bytes());
            record.extend_from_slice(payload);
            self.records.push((kind, record));
        }
    }

    /// A [`TraceClock`] pinned to one instant, which is the point of injecting
    /// it: `--trace-time` output is otherwise uncomparable.
    struct FixedClock(TraceTime);

    impl TraceClock for FixedClock {
        fn now(&self) -> TraceTime {
            self.0
        }
    }

    /// Run `body` against a stream-backed tracer and return what was written.
    fn stream_output<F>(config: &TraceConfig, state: TraceState, body: F) -> String
    where
        F: FnOnce(&mut Tracer<'_>),
    {
        let mut sink = WriterSink::new(Vec::<u8>::new());
        {
            let mut tracer = Tracer::new(config, &mut sink).with_state(state);
            body(&mut tracer);
        }
        assert_eq!(
            sink.error_count(),
            0,
            "a Vec sink cannot fail to accept bytes"
        );
        String::from_utf8(sink.into_inner()).expect("trace output is UTF-8 in these tests")
    }

    /// Run `body` against a callback-backed tracer and return the records.
    fn callback_records<F>(
        config: &TraceConfig,
        state: TraceState,
        body: F,
    ) -> Vec<(InfoType, Vec<u8>)>
    where
        F: FnOnce(&mut Tracer<'_>),
    {
        let mut sink = CallbackSink::default();
        {
            let mut tracer = Tracer::new(config, &mut sink).with_state(state);
            body(&mut tracer);
        }
        sink.records
    }

    /// Verbose, with identifiers on and every component enabled -- the state the
    /// `curl_global_trace("all")` capture ran in, except that `lib-ids` is on
    /// because the capture enabled it too.
    fn traced_all() -> TraceConfig {
        let mut config = TraceConfig::new();
        config
            .apply(Some("all"))
            .expect("applying \"all\" cannot fail");
        config.set_feature_level(TraceFeature::Ids, TraceLevel::Info);
        config
    }

    fn state_with(ids: TraceIds) -> TraceState {
        TraceState {
            verbose: true,
            feat: None,
            ids,
        }
    }

    // ---------------------------------------------------------------------
    // Name and category tables. Every string below was transcribed from the C
    // source independently of the implementation, so a typo in one does not
    // hide a typo in the other.
    // ---------------------------------------------------------------------

    /// `struct curl_trc_feat` initialisers in `lib/curl_trc.c`, in the order C
    /// declares them. `SMTP` is absent by design; see
    /// [`smtp_feature_is_deliberately_absent`].
    fn expected_features() -> Vec<(TraceFeature, &'static str, TraceCategory)> {
        let mut expected = vec![
            (TraceFeature::Ids, "LIB-IDS", TraceCategory::INTERNALS),
            (TraceFeature::Multi, "MULTI", TraceCategory::NETWORK),
            (TraceFeature::Read, "READ", TraceCategory::NONE),
            (TraceFeature::Write, "WRITE", TraceCategory::NONE),
            (TraceFeature::Dns, "DNS", TraceCategory::NETWORK),
            (TraceFeature::Timer, "TIMER", TraceCategory::NETWORK),
        ];
        #[cfg(feature = "ftp")]
        expected.push((TraceFeature::Ftp, "FTP", TraceCategory::PROTOCOL));
        expected.push((TraceFeature::Ssls, "SSLS", TraceCategory::NETWORK));
        #[cfg(feature = "ssh")]
        expected.push((TraceFeature::Ssh, "SSH", TraceCategory::PROTOCOL));
        #[cfg(feature = "websockets")]
        expected.push((TraceFeature::Ws, "WS", TraceCategory::PROTOCOL));
        expected
    }

    /// The `trc_feats[]` filter rows of `lib/curl_trc.c:508-570`, each name read
    /// out of the corresponding `struct Curl_cftype` initialiser.
    fn expected_filters() -> Vec<(TraceFilter, &'static str, TraceCategory)> {
        let mut expected = vec![
            (TraceFilter::Tcp, "TCP", TraceCategory::NETWORK),
            (TraceFilter::Udp, "UDP", TraceCategory::NETWORK),
            (TraceFilter::Unix, "UNIX", TraceCategory::NETWORK),
            (TraceFilter::TcpAccept, "TCP-ACCEPT", TraceCategory::NETWORK),
            (
                TraceFilter::IpHappy,
                "HAPPY-EYEBALLS",
                TraceCategory::NETWORK,
            ),
            (TraceFilter::Setup, "SETUP", TraceCategory::PROTOCOL),
        ];
        #[cfg(feature = "http2")]
        expected.push((TraceFilter::Http2, "HTTP/2", TraceCategory::PROTOCOL));
        expected.push((TraceFilter::Ssl, "SSL", TraceCategory::NETWORK));
        expected.push((TraceFilter::SslProxy, "SSL-PROXY", TraceCategory::PROXY));
        expected.push((TraceFilter::H1Proxy, "H1-PROXY", TraceCategory::PROXY));
        #[cfg(feature = "http2")]
        expected.push((TraceFilter::H2Proxy, "H2-PROXY", TraceCategory::PROXY));
        expected.push((TraceFilter::HttpProxy, "HTTP-PROXY", TraceCategory::PROXY));
        expected.push((TraceFilter::HaProxy, "HAPROXY", TraceCategory::PROXY));
        expected.push((TraceFilter::SocksProxy, "SOCKS", TraceCategory::PROXY));
        #[cfg(feature = "http3")]
        expected.push((TraceFilter::Http3, "HTTP/3", TraceCategory::PROTOCOL));
        expected.push((
            TraceFilter::HttpConnect,
            "HTTPS-CONNECT",
            TraceCategory::PROTOCOL,
        ));
        expected
    }

    /// `Curl_trc_timer_names[]` (`lib/curl_trc.c:281-297`), all fifteen, in
    /// order.
    ///
    /// Written as one comma-joined string rather than an array of literals, and
    /// deliberately so: this file must contain **no second name table**, only a
    /// check that the exhaustive `match` in [`TimerId::name`] agrees with the C
    /// source. A joined constant reads the same, cannot be indexed into by
    /// accident, and makes it evident at a glance that nothing outside
    /// `#[cfg(test)]` reads it.
    const EXPECTED_TIMER_NAMES: &str = "100_TIMEOUT,ASYNC_NAME,CONNECTTIMEOUT,\
         DNS_PER_NAME,DNS_PER_NAME2,HAPPY_EYEBALLS_DNS,HAPPY_EYEBALLS,\
         MULTI_PENDING,SPEEDCHECK,TIMEOUT,TOOFAST,QUIC,FTP_ACCEPT,\
         ALPN_EYEBALLS,SHUTDOWN";

    /// `Curl_trc_mstate_names[]` (`lib/curl_trc.c:334-352`), all seventeen and
    /// no `"LAST"`.
    ///
    /// Joined for the same reason as [`EXPECTED_TIMER_NAMES`], and here the
    /// reason is sharper still: the strings this crate emits are owned by
    /// `crate::multi::state`, and a literal array of them in *this* file would
    /// recreate exactly the hand-maintained parallel table that
    /// `lib/multihandle.h:48-49` asks maintainers to keep in step -- the drift
    /// Phase 2 exists to remove. This constant only asserts that
    /// [`super::mstate_name`] delegates faithfully.
    const EXPECTED_MSTATE_NAMES: &str = "INIT,PENDING,SETUP,CONNECT,RESOLVING,\
         CONNECTING,PROTOCONNECT,PROTOCONNECTING,DO,DOING,DOING_MORE,DID,\
         PERFORMING,RATELIMITING,DONE,COMPLETED,MSGSENT";

    #[test]
    fn feature_names_and_categories_match_c() {
        let expected = expected_features();
        assert_eq!(
            expected.len(),
            TraceFeature::ALL.len(),
            "every compiled feature must be in ALL"
        );
        for (index, &(feature, name, category)) in expected.iter().enumerate() {
            assert_eq!(feature.name(), name, "name of {feature:?}");
            assert_eq!(feature.category(), category, "category of {feature:?}");
            assert_eq!(TraceFeature::ALL[index], feature, "ALL order at {index}");
            assert_eq!(
                TraceFeature::from_name(name),
                Some(feature),
                "{name} must resolve back to {feature:?}"
            );
            // C compares with `curlx_str_casecompare()`, which is
            // case-insensitive (`lib/curlx/strparse.c:239-243`).
            assert_eq!(TraceFeature::from_name(&name.to_lowercase()), Some(feature));
            assert_eq!(feature.to_string(), name, "Display must be the C name");
        }
    }

    #[test]
    fn feature_slots_are_distinct_and_in_range() {
        let mut seen = [false; TraceFeature::SLOTS];
        for &feature in TraceFeature::ALL {
            let slot = feature.slot();
            assert!(
                slot < TraceFeature::SLOTS,
                "{feature:?} slot {slot} out of range"
            );
            assert!(!seen[slot], "{feature:?} reuses slot {slot}");
            seen[slot] = true;
        }
    }

    #[test]
    fn smtp_feature_is_deliberately_absent() {
        // `Curl_trc_feat_smtp` exists in C (`lib/curl_trc.c:426`), but SMTP is
        // out of scope (AAP section 0.2.2) and advertising a trace feature for a
        // protocol that answers `CURLE_UNSUPPORTED_PROTOCOL` would be
        // over-reporting. Omission is safe; over-claiming is not.
        assert_eq!(TraceFeature::from_name("SMTP"), None);
        assert_eq!(TraceFeature::from_name("smtp"), None);
        assert!(TraceFeature::ALL
            .iter()
            .all(|feature| feature.name() != "SMTP"));
    }

    #[test]
    fn filter_names_and_categories_match_c() {
        let expected = expected_filters();
        assert_eq!(
            expected.len(),
            TraceFilter::ALL.len(),
            "every compiled filter must be in ALL"
        );
        for (index, &(filter, name, category)) in expected.iter().enumerate() {
            assert_eq!(filter.name(), name, "name of {filter:?}");
            assert_eq!(filter.category(), category, "category of {filter:?}");
            assert_eq!(TraceFilter::ALL[index], filter, "ALL order at {index}");
            assert_eq!(TraceFilter::from_name(name), Some(filter));
            assert_eq!(TraceFilter::from_name(&name.to_lowercase()), Some(filter));
            assert_eq!(filter.to_string(), name, "Display must be the C name");
        }
    }

    #[test]
    fn filter_slots_are_distinct_and_in_range() {
        let mut seen = [false; TraceFilter::SLOTS];
        for &filter in TraceFilter::ALL {
            let slot = filter.slot();
            assert!(
                slot < TraceFilter::SLOTS,
                "{filter:?} slot {slot} out of range"
            );
            assert!(!seen[slot], "{filter:?} reuses slot {slot}");
            seen[slot] = true;
        }
    }

    #[cfg(feature = "http2")]
    #[test]
    fn http2_filter_keeps_the_name_c_emits() {
        // `Curl_cft_nghttp2` is *called* nghttp2 but its `.name` is "HTTP/2",
        // measured from `lib/http2.c`. The emitted string is the contract, so the
        // library it happens to be implemented with does not appear in output.
        assert_eq!(TraceFilter::Http2.name(), "HTTP/2");
        assert_eq!(TraceFilter::from_name("nghttp2"), None);
        assert_eq!(TraceFilter::from_name("http/2"), Some(TraceFilter::Http2));
    }

    #[test]
    fn no_name_is_shared_by_a_feature_and_a_filter() {
        // `trc_apply_level_by_name()` consults both tables and does not stop
        // between them, so a shared name would silently set two levels.
        for &filter in TraceFilter::ALL {
            assert_eq!(
                TraceFeature::from_name(filter.name()),
                None,
                "{} names both a filter and a feature",
                filter.name()
            );
        }
    }

    #[test]
    fn category_bits_match_c() {
        // `lib/curl_trc.c:497-501`.
        assert_eq!(TraceCategory::NONE.bits(), 0);
        assert_eq!(TraceCategory::PROTOCOL.bits(), 1 << 0);
        assert_eq!(TraceCategory::NETWORK.bits(), 1 << 1);
        assert_eq!(TraceCategory::PROXY.bits(), 1 << 2);
        assert_eq!(TraceCategory::INTERNALS.bits(), 1 << 3);
        assert!(TraceCategory::NONE.is_none());
        assert!(!TraceCategory::PROTOCOL.is_none());
    }

    #[test]
    fn empty_category_selector_matches_everything() {
        // `TRC_CT_NONE` is used two ways: as "uncategorised" on READ and WRITE,
        // and as the selector `all` passes. `trc_apply_level_by_category()` tests
        // `!category || (feat->category & category)`, so the empty selector is a
        // broadcast -- which is why `all` genuinely means everything, READ and
        // WRITE included.
        for category in [
            TraceCategory::NONE,
            TraceCategory::PROTOCOL,
            TraceCategory::NETWORK,
            TraceCategory::PROXY,
            TraceCategory::INTERNALS,
        ] {
            assert!(category.matches_selector(TraceCategory::NONE));
        }
        assert!(!TraceCategory::NONE.matches_selector(TraceCategory::NETWORK));
        assert!(TraceCategory::NETWORK.matches_selector(TraceCategory::NETWORK));
        assert!(!TraceCategory::PROTOCOL.matches_selector(TraceCategory::NETWORK));
    }

    #[test]
    fn category_keywords_match_c() {
        // `lib/curl_trc.c:619-628`, matched case-insensitively.
        assert_eq!(
            TraceCategory::from_keyword("all"),
            Some(TraceCategory::NONE)
        );
        assert_eq!(
            TraceCategory::from_keyword("ALL"),
            Some(TraceCategory::NONE)
        );
        assert_eq!(
            TraceCategory::from_keyword("protocol"),
            Some(TraceCategory::PROTOCOL)
        );
        assert_eq!(
            TraceCategory::from_keyword("Network"),
            Some(TraceCategory::NETWORK)
        );
        assert_eq!(
            TraceCategory::from_keyword("PROXY"),
            Some(TraceCategory::PROXY)
        );
        // There is no `internals` keyword: the category exists but only
        // `lib-ids` carries it, and it is reachable by name alone.
        assert_eq!(TraceCategory::from_keyword("internals"), None);
        assert_eq!(TraceCategory::from_keyword("multi"), None);
    }

    #[test]
    fn timer_names_match_c() {
        let expected: Vec<&str> = EXPECTED_TIMER_NAMES.split(',').collect();
        assert_eq!(TimerId::COUNT, expected.len());
        assert_eq!(TimerId::ALL.len(), expected.len());
        for (index, expected) in expected.iter().enumerate() {
            let timer = TimerId::ALL[index];
            assert_eq!(timer.as_i32(), index as i32, "{timer:?} discriminant");
            assert_eq!(timer.name(), *expected, "name of {timer:?}");
            assert_eq!(TimerId::name_from_i32(index as i32), *expected);
            assert_eq!(TimerId::from_i32(index as i32), Some(timer));
            assert_eq!(timer.to_string(), *expected);
        }
    }

    #[test]
    fn timer_names_are_distinct_and_never_empty() {
        // A duplicate would make two timers indistinguishable in a trace log,
        // and an empty one would emit `[] `.
        let mut seen: Vec<&str> = Vec::new();
        for &timer in TimerId::ALL {
            let name = timer.name();
            assert!(!name.is_empty(), "{timer:?} has no name");
            assert!(!seen.contains(&name), "{name} is used twice");
            assert_ne!(
                name,
                TimerId::UNKNOWN_NAME,
                "a real timer must not claim the fallback"
            );
            seen.push(name);
        }
        assert_eq!(seen.len(), TimerId::COUNT);
    }

    #[test]
    fn timer_out_of_range_is_unknown_question_mark() {
        // `trc_timer_name()` returns "UNKNOWN?" outside the array
        // (`lib/curl_trc.c:299-304`). `EXPIRE_LAST` is 15 and is one of those.
        assert_eq!(TimerId::LAST, 15);
        for raw in [-1, 15, 16, i32::MAX, i32::MIN] {
            assert_eq!(
                TimerId::name_from_i32(raw),
                TimerId::UNKNOWN_NAME,
                "for {raw}"
            );
            assert_eq!(TimerId::name_from_i32(raw), "UNKNOWN?", "for {raw}");
            assert_eq!(TimerId::from_i32(raw), None, "for {raw}");
        }
    }

    #[test]
    fn mstate_names_match_c_and_come_from_the_enum() {
        let expected: Vec<&str> = EXPECTED_MSTATE_NAMES.split(',').collect();
        assert_eq!(CurlMstate::COUNT, expected.len());
        for (index, expected) in expected.iter().enumerate() {
            assert_eq!(mstate_name(index as i32), *expected, "state {index}");
        }
        // No `"LAST"` entry: C's name array is one shorter than the enumeration,
        // because `MSTATE_LAST` "is not a true state".
        assert!(!expected.contains(&"LAST"));
    }

    #[test]
    fn mstate_name_only_delegates_and_holds_no_strings_of_its_own() {
        // The delegation itself, checked without naming a single state: for every
        // in-range value the answer must be exactly what the owning enum says,
        // and out of range it must be the fallback. If `mstate_name` ever grew a
        // table of its own, this would keep passing while the drift it is
        // supposed to prevent came back -- which is why the byte-exact captures
        // above also pin the real strings, as emitted output rather than as a
        // table.
        for index in 0..CurlMstate::COUNT {
            let state = CurlMstate::from_i32(index as i32).expect("in range");
            assert_eq!(mstate_name(index as i32), state.name(), "state {index}");
            assert_eq!(
                mstate_name(index as i32),
                state.to_string(),
                "state {index}"
            );
        }
        assert_eq!(mstate_name(CurlMstate::LAST as i32), "?");
    }

    #[test]
    fn mstate_out_of_range_is_a_bare_question_mark() {
        // `Curl_trc_mstate_name()` (`lib/curl_trc.c:354-359`). `MSTATE_LAST` is
        // 17 and is out of range, because it "is not a true state".
        assert_eq!(CurlMstate::LAST, 17);
        for raw in [-1, 17, 18, i32::MAX, i32::MIN] {
            assert_eq!(mstate_name(raw), "?", "for {raw}");
        }
    }

    #[test]
    fn the_two_out_of_range_fallbacks_are_different_strings() {
        // Measured, and easy to unify by accident: the multi-state fallback is
        // "?" while the timer fallback is "UNKNOWN?". Both are frozen output.
        assert_ne!(mstate_name(-1), TimerId::name_from_i32(-1));
        assert_eq!(mstate_name(-1), "?");
        assert_eq!(TimerId::name_from_i32(-1), "UNKNOWN?");
    }

    #[test]
    fn infotype_prefixes_and_labels_match_c() {
        // `s_infotype[CURLINFO_END][3]`, and the `text` assignments of
        // `tool_debug_cb()`.
        let expected: [(InfoType, &str, Option<&str>, bool); 7] = [
            (InfoType::Text, "* ", None, true),
            (InfoType::HeaderIn, "< ", Some("<= Recv header"), true),
            (InfoType::HeaderOut, "> ", Some("=> Send header"), true),
            (InfoType::DataIn, "{ ", Some("<= Recv data"), false),
            (InfoType::DataOut, "} ", Some("=> Send data"), false),
            (InfoType::SslDataIn, "{ ", Some("<= Recv SSL data"), false),
            (InfoType::SslDataOut, "} ", Some("=> Send SSL data"), false),
        ];
        assert_eq!(InfoType::COUNT, expected.len());
        assert_eq!(InfoType::ALL.len(), expected.len());
        for (index, &(kind, prefix, label, plain)) in expected.iter().enumerate() {
            assert_eq!(InfoType::ALL[index], kind);
            assert_eq!(kind.as_i32(), index as i32, "{kind:?} discriminant");
            assert_eq!(InfoType::from_i32(index as i32), Some(kind));
            assert_eq!(kind.prefix(), prefix, "prefix of {kind:?}");
            assert_eq!(kind.prefix().len(), InfoType::PREFIX_LEN);
            assert_eq!(kind.dump_label(), label, "dump label of {kind:?}");
            assert_eq!(
                kind.is_written_plain(),
                plain,
                "plain rendering of {kind:?}"
            );
        }
        for raw in [-1, 7, i32::MAX] {
            assert_eq!(InfoType::from_i32(raw), None);
        }
    }

    #[test]
    fn trace_levels_match_c() {
        // `CURL_LOG_LVL_NONE 0` / `CURL_LOG_LVL_INFO 1` (`lib/curl_trc.h:69-70`).
        assert_eq!(TraceLevel::None.as_i32(), 0);
        assert_eq!(TraceLevel::Info.as_i32(), 1);
        assert!(!TraceLevel::None.is_info());
        assert!(TraceLevel::Info.is_info());
        assert_eq!(TraceLevel::default(), TraceLevel::None);
        // C stores an `int` and only ever tests `>= CURL_LOG_LVL_INFO`, so the
        // conversion saturates rather than rejecting: any positive value behaves
        // as Info, anything else as None.
        assert_eq!(TraceLevel::from_i32(0), TraceLevel::None);
        assert_eq!(TraceLevel::from_i32(1), TraceLevel::Info);
        assert_eq!(TraceLevel::from_i32(2), TraceLevel::Info);
        assert_eq!(TraceLevel::from_i32(i32::MAX), TraceLevel::Info);
        assert_eq!(TraceLevel::from_i32(-1), TraceLevel::None);
        assert_eq!(TraceLevel::from_i32(i32::MIN), TraceLevel::None);
    }

    // ---------------------------------------------------------------------
    // The --trace-config grammar. The abort cases were confirmed against the
    // C library built from this tree, not inferred.
    // ---------------------------------------------------------------------

    #[test]
    fn new_config_is_entirely_silent() {
        let config = TraceConfig::new();
        for &feature in TraceFeature::ALL {
            assert_eq!(config.feature_level(feature), TraceLevel::None);
            assert!(!config.feature_is_info(feature));
        }
        for &filter in TraceFilter::ALL {
            assert_eq!(config.filter_level(filter), TraceLevel::None);
            assert!(!config.filter_is_info(filter));
        }
    }

    #[test]
    fn init_yields_a_silent_config_and_cannot_fail() {
        // `Curl_trc_init()` is `return CURLE_OK` outside a debug build.
        let config = TraceConfig::init().expect("Curl_trc_init cannot fail here");
        assert_eq!(config, TraceConfig::new());
    }

    #[test]
    fn apply_none_is_a_no_op() {
        let mut config = TraceConfig::new();
        assert!(config.apply(None).is_ok());
        assert_eq!(config, TraceConfig::new());
        assert_eq!(config.apply_code(None), CURLcode::Ok);
    }

    #[test]
    fn apply_all_enables_every_component() {
        let mut config = TraceConfig::new();
        assert_eq!(config.apply_code(Some("all")), CURLcode::Ok);
        for &feature in TraceFeature::ALL {
            assert!(config.feature_is_info(feature), "{feature:?} should be on");
        }
        for &filter in TraceFilter::ALL {
            assert!(config.filter_is_info(filter), "{filter:?} should be on");
        }
        // READ and WRITE carry TRC_CT_NONE and are still reached, because the
        // empty selector is a broadcast.
        assert!(config.feature_is_info(TraceFeature::Read));
        assert!(config.feature_is_info(TraceFeature::Write));
    }

    #[test]
    fn apply_minus_all_disables_every_component() {
        let mut config = TraceConfig::new();
        config.apply(Some("all")).unwrap();
        config.apply(Some("-all")).unwrap();
        assert_eq!(config, TraceConfig::new());
    }

    #[test]
    fn apply_plus_and_bare_name_are_the_same() {
        let mut plus = TraceConfig::new();
        plus.apply(Some("+multi")).unwrap();
        let mut bare = TraceConfig::new();
        bare.apply(Some("multi")).unwrap();
        assert_eq!(plus, bare);
        assert!(plus.feature_is_info(TraceFeature::Multi));
        assert!(!plus.feature_is_info(TraceFeature::Dns));
    }

    #[test]
    fn apply_is_case_insensitive() {
        for spelling in ["multi", "MULTI", "MuLtI"] {
            let mut config = TraceConfig::new();
            config.apply(Some(spelling)).unwrap();
            assert!(
                config.feature_is_info(TraceFeature::Multi),
                "{spelling} should match"
            );
        }
    }

    #[test]
    fn apply_category_keywords_select_their_members() {
        let mut config = TraceConfig::new();
        config.apply(Some("protocol,network")).unwrap();
        for &filter in TraceFilter::ALL {
            let expected = matches!(
                filter.category(),
                TraceCategory::PROTOCOL | TraceCategory::NETWORK
            );
            assert_eq!(config.filter_is_info(filter), expected, "{filter:?}");
        }
        // PROXY was not selected.
        assert!(!config.filter_is_info(TraceFilter::SocksProxy));
        // INTERNALS was not selected either.
        assert!(!config.feature_is_info(TraceFeature::Ids));
        // NETWORK features were.
        assert!(config.feature_is_info(TraceFeature::Dns));
        // Uncategorised features were not.
        assert!(!config.feature_is_info(TraceFeature::Read));
    }

    #[test]
    fn apply_proxy_category_selects_only_proxy_filters() {
        let mut config = TraceConfig::new();
        config.apply(Some("proxy")).unwrap();
        for &filter in TraceFilter::ALL {
            let expected = filter.category() == TraceCategory::PROXY;
            assert_eq!(config.filter_is_info(filter), expected, "{filter:?}");
        }
    }

    #[test]
    fn apply_doh_is_an_alias_for_dns() {
        // `lib/curl_trc.c:629-630`: `doh` is rewritten to `dns` before lookup.
        let mut alias = TraceConfig::new();
        alias.apply(Some("doh")).unwrap();
        let mut direct = TraceConfig::new();
        direct.apply(Some("dns")).unwrap();
        assert_eq!(alias, direct);
        assert!(alias.feature_is_info(TraceFeature::Dns));

        // And it works with a sign, as any name does.
        let mut off = TraceConfig::new();
        off.apply(Some("all,-DOH")).unwrap();
        assert!(!off.feature_is_info(TraceFeature::Dns));
        assert!(off.feature_is_info(TraceFeature::Multi));
    }

    #[test]
    fn apply_minus_name_silences_only_that_name() {
        let mut config = TraceConfig::new();
        config.apply(Some("all")).unwrap();
        config.apply(Some("-ssls")).unwrap();
        assert!(!config.feature_is_info(TraceFeature::Ssls));
        assert!(config.feature_is_info(TraceFeature::Multi));
        assert!(config.filter_is_info(TraceFilter::Ssl));
    }

    #[test]
    fn apply_later_tokens_override_earlier_ones() {
        let mut config = TraceConfig::new();
        config.apply(Some("all,-multi")).unwrap();
        assert!(!config.feature_is_info(TraceFeature::Multi));
        assert!(config.feature_is_info(TraceFeature::Dns));

        let mut reverse = TraceConfig::new();
        reverse.apply(Some("-multi,all")).unwrap();
        assert!(reverse.feature_is_info(TraceFeature::Multi));
    }

    #[test]
    fn apply_unknown_name_is_a_silent_no_op_not_an_error() {
        // "Unknown names are ignored" (`lib/curl_trc.h:40`), and the parse
        // continues -- confirmed against the C library, where "nosuch,multi"
        // still produced MULTI records.
        let mut config = TraceConfig::new();
        assert!(config.apply(Some("nosuchname")).is_ok());
        assert_eq!(config, TraceConfig::new());

        let mut carried_on = TraceConfig::new();
        carried_on.apply(Some("nosuch,multi")).unwrap();
        assert!(carried_on.feature_is_info(TraceFeature::Multi));
    }

    #[test]
    fn apply_non_ascii_name_is_a_silent_no_op() {
        let mut config = TraceConfig::new();
        assert!(config.apply(Some("caf\u{e9}")).is_ok());
        assert_eq!(config, TraceConfig::new());
        // And the parse continues past it, as it does past any unknown name.
        let mut carried_on = TraceConfig::new();
        carried_on.apply(Some("caf\u{e9},multi")).unwrap();
        assert!(carried_on.feature_is_info(TraceFeature::Multi));
    }

    #[test]
    fn apply_token_at_the_cap_is_accepted_and_one_over_aborts() {
        // THE CORRECTION: an overlong token does not get truncated, it ends the
        // parse. `curlx_str_until()` returns STRE_BIG and `trc_opt()`'s
        // `while(!...)` stops. Both halves were measured against the C library:
        // 32 bytes then ",multi" produced MULTI records; 33 bytes did not.
        assert_eq!(TRACE_CONFIG_TOKEN_MAX, 32);

        let at_cap = "x".repeat(TRACE_CONFIG_TOKEN_MAX);
        let mut accepted = TraceConfig::new();
        accepted.apply(Some(&format!("{at_cap},multi"))).unwrap();
        assert!(
            accepted.feature_is_info(TraceFeature::Multi),
            "a 32-byte token must be consumed and the parse continue"
        );

        let over_cap = "x".repeat(TRACE_CONFIG_TOKEN_MAX + 1);
        let mut aborted = TraceConfig::new();
        aborted.apply(Some(&format!("{over_cap},multi"))).unwrap();
        assert_eq!(
            aborted,
            TraceConfig::new(),
            "a 33-byte token must abort the parse, not be truncated to 32"
        );

        // And an overlong token after a good one keeps the good one's effect.
        let mut partial = TraceConfig::new();
        partial
            .apply(Some(&format!("multi,{over_cap},dns")))
            .unwrap();
        assert!(partial.feature_is_info(TraceFeature::Multi));
        assert!(!partial.feature_is_info(TraceFeature::Dns));
    }

    #[test]
    fn apply_counts_the_sign_towards_the_cap() {
        // C measures the token before `curlx_str_nudge()` strips the sign, so a
        // sign plus 32 bytes is 33 bytes and aborts.
        let name = "x".repeat(TRACE_CONFIG_TOKEN_MAX);
        let mut config = TraceConfig::new();
        config.apply(Some(&format!("+{name},multi"))).unwrap();
        assert_eq!(
            config,
            TraceConfig::new(),
            "the sign counts towards the cap"
        );
    }

    #[test]
    fn apply_empty_token_aborts_but_a_trailing_comma_does_not() {
        // STRE_SHORT ends the parse too, which makes the leading and trailing
        // comma cases asymmetric. Both were measured.
        let mut leading = TraceConfig::new();
        leading.apply(Some(",multi")).unwrap();
        assert_eq!(leading, TraceConfig::new(), "a leading comma aborts");

        let mut trailing = TraceConfig::new();
        trailing.apply(Some("multi,")).unwrap();
        assert!(
            trailing.feature_is_info(TraceFeature::Multi),
            "a trailing comma is harmless: the loop was ending anyway"
        );

        let mut doubled = TraceConfig::new();
        doubled.apply(Some("multi,,dns")).unwrap();
        assert!(doubled.feature_is_info(TraceFeature::Multi));
        assert!(
            !doubled.feature_is_info(TraceFeature::Dns),
            "the remainder is discarded"
        );

        let mut empty = TraceConfig::new();
        empty.apply(Some("")).unwrap();
        assert_eq!(empty, TraceConfig::new());
    }

    #[test]
    fn apply_lone_sign_matches_nothing_but_does_not_abort() {
        // A one-byte "-" is a valid token; stripping the sign leaves an empty
        // name, and `curlx_str_casecompare()` requires equal lengths, so nothing
        // matches. The separator is still consumed.
        let mut config = TraceConfig::new();
        config.apply(Some("-,multi")).unwrap();
        assert!(config.feature_is_info(TraceFeature::Multi));

        let mut alone = TraceConfig::new();
        alone.apply(Some("+")).unwrap();
        assert_eq!(alone, TraceConfig::new());
    }

    #[test]
    fn apply_matches_filter_names_too() {
        let mut config = TraceConfig::new();
        config.apply(Some("tcp,socks,https-connect")).unwrap();
        assert!(config.filter_is_info(TraceFilter::Tcp));
        assert!(config.filter_is_info(TraceFilter::SocksProxy));
        assert!(config.filter_is_info(TraceFilter::HttpConnect));
        assert!(!config.filter_is_info(TraceFilter::Udp));
    }

    #[test]
    fn apply_can_reach_lib_ids_by_name() {
        // The command-line tool appends ",-lib-ids" to whatever it forwards
        // (`src/tool_getparam.c`), so this is only reachable by an embedding
        // application calling `curl_global_trace()` -- which is exactly how the
        // capture that verified this module's layouts was taken.
        let mut config = TraceConfig::new();
        config.apply(Some("lib-ids")).unwrap();
        assert!(config.feature_is_info(TraceFeature::Ids));
        assert!(!config.feature_is_info(TraceFeature::Multi));
    }

    #[test]
    fn next_config_token_leaves_the_cursor_on_the_delimiter() {
        let mut rest: &[u8] = b"multi,dns";
        assert_eq!(next_config_token(&mut rest), Some(&b"multi"[..]));
        assert_eq!(rest, b",dns");
        rest = &rest[1..];
        assert_eq!(next_config_token(&mut rest), Some(&b"dns"[..]));
        assert_eq!(rest, b"");
        assert_eq!(
            next_config_token(&mut rest),
            None,
            "STRE_SHORT on an empty tail"
        );
    }

    #[test]
    fn set_level_accessors_round_trip() {
        let mut config = TraceConfig::new();
        config.set_feature_level(TraceFeature::Dns, TraceLevel::Info);
        assert_eq!(config.feature_level(TraceFeature::Dns), TraceLevel::Info);
        config.set_feature_level(TraceFeature::Dns, TraceLevel::None);
        assert_eq!(config.feature_level(TraceFeature::Dns), TraceLevel::None);

        config.set_filter_level(TraceFilter::Ssl, TraceLevel::Info);
        assert_eq!(config.filter_level(TraceFilter::Ssl), TraceLevel::Info);

        config.apply_level_by_name("udp", TraceLevel::Info);
        assert!(config.filter_is_info(TraceFilter::Udp));

        config.apply_level_by_category(TraceCategory::PROXY, TraceLevel::Info);
        assert!(config.filter_is_info(TraceFilter::HaProxy));
    }

    // ---------------------------------------------------------------------
    // LineBuffer: C's length budget and its "...\n" truncation.
    // ---------------------------------------------------------------------

    #[test]
    fn line_max_matches_c() {
        assert_eq!(TRC_LINE_MAX, 2048);
        assert_eq!(LineBuffer::CONTENT_MAX, 2047);
        assert_eq!(CURL_ERROR_SIZE, 256);
        assert_eq!(ErrorBuffer::CAPACITY, 256);
        assert_eq!(ErrorBuffer::CONTENT_MAX, 255);
    }

    #[test]
    fn line_buffer_starts_empty() {
        let buffer = LineBuffer::new();
        assert!(buffer.is_empty());
        assert_eq!(buffer.len(), 0);
        assert_eq!(buffer.as_bytes(), b"");
        assert_eq!(buffer.content_max(), LineBuffer::CONTENT_MAX);
        assert_eq!(LineBuffer::default(), LineBuffer::new());
    }

    #[test]
    fn line_buffer_caps_content_at_the_budget() {
        let mut buffer = LineBuffer::new();
        buffer.push_bytes(&vec![b'a'; 3000]);
        assert_eq!(
            buffer.len(),
            LineBuffer::CONTENT_MAX,
            "2047, not 2048 and not 3000"
        );
        // A further push adds nothing rather than growing.
        buffer.push_str("more");
        assert_eq!(buffer.len(), LineBuffer::CONTENT_MAX);
    }

    #[test]
    fn line_buffer_truncates_an_overlong_line_with_the_marker() {
        // `trc_end_buf()`: `len = maxlen - 5` then "...\n", so the result is
        // 2043 + 4 = 2047 bytes ending in "...\n".
        let mut buffer = LineBuffer::new();
        buffer.push_bytes(&vec![b'a'; 3000]);
        let line = buffer.finish(true);
        assert_eq!(line.len(), 2047);
        assert_eq!(&line[line.len() - 4..], b"...\n");
        assert_eq!(&line[..2043], &vec![b'a'; 2043][..]);
    }

    #[test]
    fn line_buffer_truncation_boundary_matches_c_exactly() {
        // With `addnl`, C truncates when `len >= maxlen - 2`, so 2046 truncates
        // and 2045 does not. Off by one here would be a visible change.
        let mut just_short = LineBuffer::new();
        just_short.push_bytes(&vec![b'a'; 2045]);
        let line = just_short.finish(true);
        assert_eq!(line.len(), 2046);
        assert_eq!(line[2045], b'\n');
        assert_ne!(&line[line.len() - 4..], b"...\n");

        let mut at_boundary = LineBuffer::new();
        at_boundary.push_bytes(&vec![b'a'; 2046]);
        let line = at_boundary.finish(true);
        assert_eq!(line.len(), 2047);
        assert_eq!(&line[line.len() - 4..], b"...\n");
    }

    #[test]
    fn line_buffer_truncation_boundary_without_a_newline() {
        // Without `addnl` the test is `len >= maxlen - 1`, so 2047 truncates and
        // 2046 is left alone. This is `Curl_debug()`'s path.
        let mut left_alone = LineBuffer::new();
        left_alone.push_bytes(&vec![b'a'; 2046]);
        let line = left_alone.finish(false);
        assert_eq!(line.len(), 2046);
        assert_ne!(&line[line.len() - 4..], b"...\n");

        let mut truncated = LineBuffer::new();
        truncated.push_bytes(&vec![b'a'; 2047]);
        let line = truncated.finish(false);
        assert_eq!(line.len(), 2047);
        assert_eq!(&line[line.len() - 4..], b"...\n");
    }

    #[test]
    fn line_buffer_short_line_just_gains_a_newline() {
        let mut buffer = LineBuffer::new();
        buffer.push_str("hello");
        assert_eq!(buffer.finish(true), b"hello\n");

        let mut without = LineBuffer::new();
        without.push_str("hello");
        assert_eq!(without.finish(false), b"hello");
    }

    #[test]
    fn line_buffer_clear_keeps_the_budget() {
        let mut buffer = LineBuffer::with_content_max(16);
        buffer.push_str("0123456789abcdefGHI");
        assert_eq!(buffer.len(), 16);
        buffer.clear();
        assert!(buffer.is_empty());
        assert_eq!(buffer.content_max(), 16);
    }

    #[test]
    fn line_buffer_honours_the_error_size_budget() {
        let mut buffer = LineBuffer::with_content_max(ErrorBuffer::CONTENT_MAX);
        buffer.push_bytes(&vec![b'e'; 400]);
        assert_eq!(buffer.len(), 255);
    }

    #[test]
    fn push_newline_ignores_the_budget_as_failf_does() {
        // `Curl_failf()` writes `error[len++] = '\n'` with no length test, into
        // an array two bytes larger than the cap. A full message therefore emits
        // 256 bytes, not a truncated 255.
        let mut buffer = LineBuffer::with_content_max(ErrorBuffer::CONTENT_MAX);
        buffer.push_bytes(&vec![b'e'; 400]);
        buffer.push_newline();
        assert_eq!(buffer.len(), 256);
        assert_eq!(buffer.as_bytes()[255], b'\n');
    }

    #[test]
    fn line_buffer_accepts_formatted_output() {
        let mut buffer = LineBuffer::new();
        buffer.push_fmt(format_args!("{}-{:04x}", 7, 255));
        assert_eq!(buffer.as_bytes(), b"7-00ff");
        fmt::Write::write_str(&mut buffer, "!").expect("infallible");
        assert_eq!(buffer.as_bytes(), b"7-00ff!");
    }

    #[test]
    fn line_buffer_tiny_budget_is_raised_to_fit_the_marker() {
        // A budget below four would leave no room for "...\n"; raising it beats
        // emitting a shortened marker. C never asks for one this small.
        let buffer = LineBuffer::with_content_max(0);
        assert_eq!(buffer.content_max(), 4);
    }

    #[test]
    fn line_buffer_holds_bytes_not_text() {
        // Trace payloads are protocol bytes; a truncation may land mid-character
        // and must not panic or move.
        let mut buffer = LineBuffer::with_content_max(4);
        buffer.push_bytes("\u{e9}\u{e9}\u{e9}".as_bytes());
        assert_eq!(buffer.as_bytes(), &[0xc3, 0xa9, 0xc3, 0xa9]);
    }

    // ---------------------------------------------------------------------
    // TraceIds: the four bracket shapes.
    // ---------------------------------------------------------------------

    #[test]
    fn trace_ids_render_c_four_shapes() {
        assert_eq!(TraceIds::new(12, 3).to_string(), "[12-3] ");
        assert_eq!(TraceIds::xfer_only(12).to_string(), "[12-x] ");
        assert_eq!(TraceIds { xfer: -1, conn: 3 }.to_string(), "[x-3] ");
        assert_eq!(TraceIds::UNASSIGNED.to_string(), "[x-x] ");
        // Zero is a real identifier, and the C library was observed printing it.
        assert_eq!(TraceIds::new(0, 0).to_string(), "[0-0] ");
        assert_eq!(TraceIds::xfer_only(0).to_string(), "[0-x] ");
    }

    #[test]
    fn trace_ids_default_is_unassigned_not_zero() {
        assert_eq!(TraceIds::default(), TraceIds::UNASSIGNED);
        assert_eq!(TraceIds::UNASSIGNED_PLACEHOLDER, "x");
        assert!(!TraceIds::UNASSIGNED.has_xfer_id());
        assert!(!TraceIds::UNASSIGNED.has_conn_id());
        assert!(TraceIds::new(0, 0).has_xfer_id());
        assert!(TraceIds::new(0, 0).has_conn_id());
        assert!(TraceIds::xfer_only(5).has_xfer_id());
        assert!(!TraceIds::xfer_only(5).has_conn_id());
    }

    #[test]
    fn trace_ids_render_wide_values() {
        // `curl_off_t` is 64-bit on every mandated target.
        assert_eq!(
            TraceIds::new(i64::MAX, 0).to_string(),
            format!("[{}-0] ", i64::MAX)
        );
    }

    // ---------------------------------------------------------------------
    // TraceTime and the injected clock.
    // ---------------------------------------------------------------------

    #[test]
    fn trace_time_renders_the_c_prefix() {
        let time = TraceTime {
            hour: 9,
            minute: 32,
            second: 55,
            microsecond: 600_049,
        };
        assert_eq!(time.to_string(), "09:32:55.600049 ");
        assert_eq!(
            time.to_string().len(),
            16,
            "fifteen characters and the trailing space"
        );
    }

    #[test]
    fn trace_time_conversion_failure_renders_zeroes() {
        // `hms_for_sec()` zeroes the whole `struct tm` when it cannot convert.
        assert_eq!(TraceTime::CONVERSION_FAILED.to_string(), "00:00:00.000000 ");
        assert_eq!(TraceTime::default(), TraceTime::CONVERSION_FAILED);
    }

    #[test]
    fn trace_time_widths_are_minima_as_in_c() {
        // `%02d` and `%06ld` pad but never truncate.
        let time = TraceTime {
            hour: 100,
            minute: 0,
            second: 60,
            microsecond: 1_234_567,
        };
        assert_eq!(time.to_string(), "100:00:60.1234567 ");
    }

    #[test]
    fn an_injected_clock_is_what_makes_the_prefix_comparable() {
        let clock = FixedClock(TraceTime {
            hour: 1,
            minute: 2,
            second: 3,
            microsecond: 4,
        });
        assert_eq!(clock.now().to_string(), "01:02:03.000004 ");
        // Twice, to show it does not advance: no test in this module reads the
        // process clock.
        assert_eq!(clock.now(), clock.now());
    }

    // ---------------------------------------------------------------------
    // ErrorBuffer: first failure wins.
    // ---------------------------------------------------------------------

    #[test]
    fn error_buffer_keeps_the_first_message() {
        let mut buffer = ErrorBuffer::new();
        assert!(!buffer.is_set());
        assert!(buffer.set_first(b"root cause"));
        assert!(buffer.is_set());
        assert!(
            !buffer.set_first(b"consequence"),
            "a later failure must not overwrite"
        );
        assert_eq!(buffer.message_bytes(), b"root cause");
        assert_eq!(buffer.message_lossy(), "root cause");
    }

    #[test]
    fn error_buffer_reset_re_arms_it() {
        let mut buffer = ErrorBuffer::new();
        buffer.set_first(b"first");
        buffer.reset();
        assert!(!buffer.is_set());
        assert_eq!(buffer.message_bytes(), b"");
        assert!(buffer.set_first(b"second"));
        assert_eq!(buffer.message_bytes(), b"second");
    }

    #[test]
    fn error_buffer_truncates_to_the_c_capacity() {
        let mut buffer = ErrorBuffer::new();
        buffer.set_first(&vec![b'e'; 1000]);
        assert_eq!(buffer.message_bytes().len(), ErrorBuffer::CONTENT_MAX);
    }

    #[test]
    fn error_buffer_lossily_decodes_invalid_bytes() {
        let mut buffer = ErrorBuffer::new();
        buffer.set_first(&[0xff, b'!']);
        assert_eq!(buffer.message_lossy(), "\u{fffd}!");
        assert_eq!(buffer.message_bytes(), &[0xff, b'!']);
    }

    // ---------------------------------------------------------------------
    // Tracer. The first five assertions are byte-for-byte against lines
    // captured from the libcurl built from this tree, driven through
    // curl_global_trace("all") with CURLOPT_VERBOSE and no debug callback.
    // ---------------------------------------------------------------------

    #[test]
    fn oracle_multi_state_transition_line() {
        let config = traced_all();
        let out = stream_output(&config, state_with(TraceIds::new(0, 0)), |tracer| {
            tracer.multi(
                CurlMstate::Connecting,
                format_args!("-> [{}]", mstate_name(6)),
            );
        });
        assert_eq!(out, "* [0-0] [MULTI] [CONNECTING] -> [PROTOCONNECT]\n");
    }

    /// Reproduces the `ignore`d snippet on [`Tracer`], including its output.
    ///
    /// A rustdoc example cannot be compiled here: every item in this module is
    /// `pub(crate)` per AAP 0.4.2, and a doctest is built as a separate crate,
    /// so the snippet is necessarily `ignore`d and no compiler ever reads it.
    /// That is a real drift hazard -- one such snippet was measured to name a
    /// `CurlMstate` variant that does not exist -- so this test stands in for
    /// the doctest and fails if the documentation stops being true.
    ///
    /// The one necessary difference from the snippet is the macro receiver:
    /// `stream_output` hands the closure a `&mut Tracer`, so it passes `tracer`
    /// where the snippet, holding a `Tracer` by value, passes `&mut tracer`.
    /// Everything the snippet asserts -- the config string, the state, the
    /// variant spellings and the emitted line -- is checked exactly.
    #[test]
    fn the_documented_example_writes_the_line_it_claims() {
        let mut config = TraceConfig::new();
        config
            .apply(Some("multi,lib-ids"))
            .expect("the documented config string must parse");
        let state = TraceState {
            verbose: true,
            feat: None,
            ids: TraceIds::new(0, 0),
        };
        let out = stream_output(&config, state, |tracer| {
            crate::trace::trc_multi!(
                tracer,
                CurlMstate::Connecting,
                "-> [{}]",
                CurlMstate::ProtoConnect
            );
        });
        assert_eq!(out, "* [0-0] [MULTI] [CONNECTING] -> [PROTOCONNECT]\n");
    }

    #[test]
    fn oracle_multi_init_line_with_unassigned_connection() {
        let config = traced_all();
        let out = stream_output(&config, state_with(TraceIds::xfer_only(0)), |tracer| {
            tracer.multi(
                CurlMstate::Init,
                format_args!("added to multi, mid={}, running={}, total={}", 1, 1, 2),
            );
        });
        assert_eq!(
            out,
            "* [0-x] [MULTI] [INIT] added to multi, mid=1, running=1, total=2\n"
        );
    }

    #[test]
    fn oracle_connection_filter_line_has_no_suffix_for_socket_zero() {
        let config = traced_all();
        let out = stream_output(&config, state_with(TraceIds::new(0, 0)), |tracer| {
            tracer.filter(
                TraceFilter::Tcp,
                0,
                format_args!("adjust_pollset, !connected, POLLOUT fd={}", 4),
            );
        });
        assert_eq!(
            out,
            "* [0-0] [TCP] adjust_pollset, !connected, POLLOUT fd=4\n"
        );
    }

    #[test]
    fn oracle_timer_line() {
        let config = traced_all();
        let out = stream_output(&config, state_with(TraceIds::new(0, 0)), |tracer| {
            tracer.timer(TimerId::HappyEyeballs, format_args!("cleared"));
        });
        assert_eq!(out, "* [0-0] [TIMER] [HAPPY_EYEBALLS] cleared\n");
    }

    #[test]
    fn oracle_header_out_line_puts_ids_before_the_prefix() {
        // The other ordering: `Curl_debug()` writes the identifiers, then the
        // kind prefix, then the bytes -- whereas an informational line carries
        // its identifiers inside the payload and so shows them after "* ".
        let config = traced_all();
        let out = stream_output(&config, state_with(TraceIds::new(0, 0)), |tracer| {
            tracer.debug(InfoType::HeaderOut, b"GET /data.txt HTTP/1.1\r\n");
        });
        assert_eq!(out, "[0-0] > GET /data.txt HTTP/1.1\r\n");
    }

    #[test]
    fn filter_line_appends_a_non_zero_socket_index() {
        let config = traced_all();
        let out = stream_output(&config, state_with(TraceIds::new(0, 0)), |tracer| {
            tracer.filter(TraceFilter::Tcp, 1, format_args!("connected"));
        });
        assert_eq!(out, "* [0-0] [TCP-1] connected\n");
    }

    #[test]
    fn filter_line_carries_the_protocols_label_not_its_own() {
        // C passes `data->state.feat` as the feature and the filter name as the
        // second group, so a filter line is labelled by whatever protocol is
        // driving it.
        let mut config = traced_all();
        config.set_feature_level(TraceFeature::Ids, TraceLevel::None);
        let state = TraceState {
            verbose: true,
            feat: Some(TraceFeature::Dns),
            ids: TraceIds::new(0, 0),
        };
        let out = stream_output(&config, state, |tracer| {
            tracer.filter(TraceFilter::Udp, 0, format_args!("probing"));
        });
        assert_eq!(out, "* [DNS] [UDP] probing\n");
    }

    #[test]
    fn infof_without_identifiers_has_no_bracket_group() {
        let mut config = TraceConfig::new();
        config.apply(Some("all,-lib-ids")).unwrap();
        let out = stream_output(&config, state_with(TraceIds::new(0, 0)), |tracer| {
            tracer.infof(format_args!("Connected to {} port {}", "localhost", 18049));
        });
        assert_eq!(out, "* Connected to localhost port 18049\n");
    }

    #[test]
    fn infof_carries_the_current_feature_label() {
        let config = TraceConfig::new();
        let state = TraceState {
            verbose: true,
            feat: None,
            ids: TraceIds::UNASSIGNED,
        };
        // With no label, and with the label's feature silent, output differs.
        let out = stream_output(&config, state, |tracer| {
            tracer.infof(format_args!("unlabelled"));
        });
        assert_eq!(out, "* unlabelled\n");

        let mut labelled_config = TraceConfig::new();
        labelled_config.set_feature_level(TraceFeature::Dns, TraceLevel::Info);
        let labelled = TraceState {
            verbose: true,
            feat: Some(TraceFeature::Dns),
            ids: TraceIds::UNASSIGNED,
        };
        let out = stream_output(&labelled_config, labelled, |tracer| {
            tracer.infof(format_args!("resolving"));
        });
        assert_eq!(out, "* [DNS] resolving\n");
    }

    #[test]
    fn multi_line_omits_the_state_when_the_transfer_has_no_id() {
        // C: `(data->id >= 0) ? Curl_trc_mstate_name(data->mstate) : NULL`.
        let config = traced_all();
        let out = stream_output(
            &config,
            state_with(TraceIds { xfer: -1, conn: 4 }),
            |tracer| {
                tracer.multi(CurlMstate::Init, format_args!("not yet added"));
            },
        );
        assert_eq!(out, "* [x-4] [MULTI] not yet added\n");
    }

    #[test]
    fn feature_lines_use_a_single_bracket_group() {
        let mut config = TraceConfig::new();
        config.apply(Some("all,-lib-ids")).unwrap();
        let state = state_with(TraceIds::new(0, 0));
        for &(feature, name, _) in expected_features().iter() {
            if feature == TraceFeature::Ids {
                continue;
            }
            let out = stream_output(&config, state, |tracer| {
                tracer.feature(feature, format_args!("payload"));
            });
            assert_eq!(out, format!("* [{name}] payload\n"), "for {feature:?}");
        }
    }

    #[test]
    fn nothing_is_emitted_when_the_transfer_is_not_verbose() {
        let config = traced_all();
        let state = TraceState {
            verbose: false,
            feat: None,
            ids: TraceIds::new(0, 0),
        };
        let out = stream_output(&config, state, |tracer| {
            assert!(!tracer.is_verbose());
            assert!(!tracer.is_feature_verbose(TraceFeature::Multi));
            assert!(!tracer.is_filter_verbose(TraceFilter::Tcp));
            assert!(!tracer.is_ids_verbose());
            tracer.infof(format_args!("suppressed"));
            tracer.multi(CurlMstate::Init, format_args!("suppressed"));
            tracer.timer(TimerId::Timeout, format_args!("suppressed"));
            tracer.filter(TraceFilter::Tcp, 0, format_args!("suppressed"));
            tracer.feature(TraceFeature::Dns, format_args!("suppressed"));
            tracer.debug(InfoType::HeaderIn, b"suppressed\r\n");
        });
        assert_eq!(out, "");
    }

    #[test]
    fn nothing_is_emitted_when_the_component_is_silent() {
        let config = TraceConfig::new();
        let out = stream_output(&config, state_with(TraceIds::new(0, 0)), |tracer| {
            assert!(tracer.is_verbose(), "the transfer is verbose");
            assert!(!tracer.is_feature_verbose(TraceFeature::Multi));
            assert!(!tracer.is_filter_verbose(TraceFilter::Tcp));
            tracer.multi(CurlMstate::Init, format_args!("suppressed"));
            tracer.timer(TimerId::Timeout, format_args!("suppressed"));
            tracer.filter(TraceFilter::Tcp, 0, format_args!("suppressed"));
            tracer.feature(TraceFeature::Dns, format_args!("suppressed"));
        });
        assert_eq!(out, "");
    }

    #[test]
    fn a_silent_feature_label_suppresses_even_plain_infof() {
        // The second clause of `Curl_trc_is_verbose()`: with a label in force
        // whose level is NONE, ordinary `infof()` output goes away too. This is
        // what lets "--trace-config -ftp" silence a protocol wholesale.
        let config = TraceConfig::new();
        let state = TraceState {
            verbose: true,
            feat: Some(TraceFeature::Dns),
            ids: TraceIds::UNASSIGNED,
        };
        let out = stream_output(&config, state, |tracer| {
            assert!(!tracer.is_verbose());
            tracer.infof(format_args!("suppressed"));
        });
        assert_eq!(out, "");
    }

    #[test]
    fn set_feature_returns_the_label_it_replaced() {
        let config = TraceConfig::new();
        let mut sink = CallbackSink::default();
        let mut tracer = Tracer::new(&config, &mut sink);
        assert_eq!(tracer.state(), TraceState::SILENT);
        assert_eq!(tracer.set_feature(Some(TraceFeature::Dns)), None);
        assert_eq!(
            tracer.set_feature(Some(TraceFeature::Multi)),
            Some(TraceFeature::Dns)
        );
        assert_eq!(tracer.set_feature(None), Some(TraceFeature::Multi));

        tracer.set_verbose(true);
        assert!(tracer.state().verbose);
        tracer.set_ids(TraceIds::new(7, 8));
        assert_eq!(tracer.state().ids, TraceIds::new(7, 8));
        tracer.set_state(TraceState::verbose());
        assert_eq!(
            tracer.state(),
            TraceState {
                verbose: true,
                feat: None,
                ids: TraceIds::UNASSIGNED
            }
        );
        assert!(std::ptr::eq(tracer.config(), &config));
        assert!(tracer.error_buffer().is_none());
    }

    #[test]
    fn tracer_debug_formatting_does_not_leak_its_borrows() {
        let config = TraceConfig::new();
        let mut buffer = ErrorBuffer::new();
        let mut sink = CallbackSink::default();
        let tracer = Tracer::new(&config, &mut sink)
            .with_state(TraceState::verbose())
            .with_error_buffer(&mut buffer);
        let rendered = format!("{tracer:?}");
        assert!(rendered.starts_with("Tracer {"), "{rendered}");
        assert!(rendered.contains("has_error_buffer: true"), "{rendered}");
        assert!(rendered.contains("is_user_callback: true"), "{rendered}");
    }

    #[test]
    fn a_long_message_is_truncated_with_the_marker_and_keeps_its_prefixes() {
        let config = traced_all();
        let out = stream_output(&config, state_with(TraceIds::new(0, 0)), |tracer| {
            tracer.multi(CurlMstate::Init, format_args!("{}", "z".repeat(4000)));
        });
        assert!(
            out.starts_with("* [0-0] [MULTI] [INIT] zzz"),
            "prefixes survive"
        );
        assert!(out.ends_with("...\n"), "and the tail is the marker");
        // "* " from the sink plus 2047 assembled bytes.
        assert_eq!(out.len(), InfoType::PREFIX_LEN + 2047);
    }

    // ---------------------------------------------------------------------
    // failf: the error path, which is gated differently from everything else.
    // ---------------------------------------------------------------------

    #[test]
    fn failf_writes_the_log_and_fills_the_buffer() {
        let config = TraceConfig::new();
        let mut buffer = ErrorBuffer::new();
        let mut sink = WriterSink::new(Vec::<u8>::new());
        {
            let mut tracer = Tracer::new(&config, &mut sink)
                .with_state(TraceState::verbose())
                .with_error_buffer(&mut buffer);
            tracer.failf(format_args!("Could not resolve host: {}", "nosuch.invalid"));
        }
        assert_eq!(
            String::from_utf8(sink.into_inner()).unwrap(),
            "* Could not resolve host: nosuch.invalid\n"
        );
        // The stored copy has no newline: C copies before appending it.
        assert_eq!(
            buffer.message_bytes(),
            b"Could not resolve host: nosuch.invalid"
        );
    }

    #[test]
    fn failf_fills_the_buffer_even_when_tracing_is_off() {
        // The gate is `verbose || errorbuffer`. An application that sets only
        // CURLOPT_ERRORBUFFER still learns why the transfer failed.
        let config = TraceConfig::new();
        let mut buffer = ErrorBuffer::new();
        let mut sink = WriterSink::new(Vec::<u8>::new());
        {
            let mut tracer = Tracer::new(&config, &mut sink).with_error_buffer(&mut buffer);
            assert!(!tracer.is_verbose());
            tracer.failf(format_args!("boom"));
        }
        assert_eq!(sink.into_inner(), b"", "nothing logged");
        assert_eq!(buffer.message_bytes(), b"boom", "but the buffer is filled");
    }

    #[test]
    fn failf_is_not_filtered_by_a_silent_feature_label() {
        // An error must not be swallowed by a --trace-config selection.
        let config = TraceConfig::new();
        let state = TraceState {
            verbose: true,
            feat: Some(TraceFeature::Dns),
            ids: TraceIds::UNASSIGNED,
        };
        let out = stream_output(&config, state, |tracer| {
            assert!(!tracer.is_verbose(), "infof would be suppressed here");
            tracer.failf(format_args!("resolver failed"));
        });
        assert_eq!(out, "* resolver failed\n");
    }

    #[test]
    fn failf_keeps_the_first_error_and_reset_fail_re_arms() {
        let config = TraceConfig::new();
        let mut buffer = ErrorBuffer::new();
        let mut sink = WriterSink::new(Vec::<u8>::new());
        {
            let mut tracer = Tracer::new(&config, &mut sink)
                .with_state(TraceState::verbose())
                .with_error_buffer(&mut buffer);
            tracer.failf(format_args!("root cause"));
            tracer.failf(format_args!("consequence"));
            assert_eq!(
                tracer.error_buffer().map(ErrorBuffer::message_bytes),
                Some(&b"root cause"[..])
            );
            tracer.reset_fail();
            assert_eq!(tracer.error_buffer().map(ErrorBuffer::is_set), Some(false));
            tracer.failf(format_args!("after reset"));
        }
        // Every call still reached the log, only the buffer is first-wins.
        assert_eq!(
            String::from_utf8(sink.into_inner()).unwrap(),
            "* root cause\n* consequence\n* after reset\n"
        );
        assert_eq!(buffer.message_bytes(), b"after reset");
    }

    #[test]
    fn reset_fail_without_a_buffer_is_harmless() {
        let config = TraceConfig::new();
        let mut sink = CallbackSink::default();
        let mut tracer = Tracer::new(&config, &mut sink).with_state(TraceState::verbose());
        tracer.reset_fail();
        assert!(tracer.error_buffer().is_none());
    }

    #[test]
    fn failf_caps_the_message_at_the_error_size_and_still_ends_in_a_newline() {
        let config = TraceConfig::new();
        let mut buffer = ErrorBuffer::new();
        let mut sink = WriterSink::new(Vec::<u8>::new());
        {
            let mut tracer = Tracer::new(&config, &mut sink)
                .with_state(TraceState::verbose())
                .with_error_buffer(&mut buffer);
            tracer.failf(format_args!("{}", "e".repeat(1000)));
        }
        let logged = sink.into_inner();
        // "* " plus 255 content bytes plus the newline: no "..." marker, because
        // `Curl_failf()` does not call `trc_end_buf()`.
        assert_eq!(logged.len(), InfoType::PREFIX_LEN + 256);
        assert_eq!(logged[logged.len() - 1], b'\n');
        assert_ne!(&logged[logged.len() - 4..], b"...\n");
        assert_eq!(buffer.message_bytes().len(), 255);
    }

    // ---------------------------------------------------------------------
    // debug(): the two destinations that differ in content, not just target.
    // ---------------------------------------------------------------------

    #[test]
    fn a_stream_sink_drops_body_and_tls_payloads() {
        // C's `default: /* nada */`. Only a debug callback -- or the tool's own
        // dump -- ever renders these.
        let mut config = traced_all();
        config.set_feature_level(TraceFeature::Ids, TraceLevel::None);
        for kind in [
            InfoType::DataIn,
            InfoType::DataOut,
            InfoType::SslDataIn,
            InfoType::SslDataOut,
        ] {
            let out = stream_output(&config, state_with(TraceIds::new(0, 0)), |tracer| {
                tracer.debug(kind, b"body bytes");
            });
            assert_eq!(out, "", "{kind:?} must not reach a plain writer");
        }
        for (kind, prefix) in [
            (InfoType::Text, "* "),
            (InfoType::HeaderIn, "< "),
            (InfoType::HeaderOut, "> "),
        ] {
            let out = stream_output(&config, state_with(TraceIds::new(0, 0)), |tracer| {
                tracer.debug(kind, b"line\r\n");
            });
            assert_eq!(out, format!("{prefix}line\r\n"), "{kind:?}");
        }
    }

    #[test]
    fn a_callback_sink_receives_every_kind_untouched() {
        let mut config = traced_all();
        config.set_feature_level(TraceFeature::Ids, TraceLevel::None);
        let records = callback_records(&config, state_with(TraceIds::new(0, 0)), |tracer| {
            for &kind in InfoType::ALL {
                tracer.debug(kind, b"\x00\x01raw");
            }
        });
        assert_eq!(records.len(), InfoType::COUNT);
        for (index, (kind, payload)) in records.iter().enumerate() {
            assert_eq!(*kind, InfoType::ALL[index]);
            assert_eq!(payload, b"\x00\x01raw", "no prefix and no truncation");
        }
    }

    #[test]
    fn a_callback_sink_gets_identifiers_built_into_the_record() {
        let config = traced_all();
        let records = callback_records(&config, state_with(TraceIds::new(0, 0)), |tracer| {
            tracer.debug(InfoType::HeaderOut, b"GET / HTTP/1.1\r\n");
        });
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].0, InfoType::HeaderOut);
        assert_eq!(
            records[0].1, b"[0-0] GET / HTTP/1.1\r\n",
            "identifiers, no prefix"
        );
    }

    #[test]
    fn a_callback_sink_gets_a_large_payload_at_its_true_length() {
        // C only builds the identifier-prefixed copy when `size < TRC_LINE_MAX`;
        // beyond that the bytes are handed over as they are, because a body must
        // not be truncated to fit a trace buffer.
        let config = traced_all();
        let payload = vec![b'p'; TRC_LINE_MAX];
        let records = callback_records(&config, state_with(TraceIds::new(0, 0)), |tracer| {
            tracer.debug(InfoType::DataIn, &payload);
        });
        assert_eq!(
            records[0].1.len(),
            TRC_LINE_MAX,
            "no identifiers, no truncation"
        );
        assert_eq!(records[0].1, payload);

        let just_under = vec![b'p'; TRC_LINE_MAX - 1];
        let records = callback_records(&config, state_with(TraceIds::new(0, 0)), |tracer| {
            tracer.debug(InfoType::DataIn, &just_under);
        });
        assert!(
            records[0].1.starts_with(b"[0-0] "),
            "identifiers are prefixed below the cap"
        );
        // 6 bytes of identifiers plus 2047 payload bytes exceeds the budget, so
        // `trc_end_buf(addnl = FALSE)` truncates with the marker.
        assert_eq!(records[0].1.len(), 2047);
        assert!(records[0].1.ends_with(b"...\n"));
    }

    #[test]
    fn a_callback_sink_with_identifiers_stops_at_a_nul_as_c_does() {
        // `curl_msnprintf("%.*s", ...)` copies with `for(; len && *str; len--)`
        // (`lib/mprintf.c:879`), which halts at a NUL despite the precision.
        // Reachable only with `lib-ids` on; reproduced because it is C's output.
        let config = traced_all();
        let records = callback_records(&config, state_with(TraceIds::new(0, 0)), |tracer| {
            tracer.debug(InfoType::DataIn, b"visible\x00hidden");
        });
        assert_eq!(records[0].1, b"[0-0] visible");
    }

    #[test]
    fn debug_without_identifiers_passes_the_payload_straight_through() {
        let mut config = traced_all();
        config.set_feature_level(TraceFeature::Ids, TraceLevel::None);
        let records = callback_records(&config, state_with(TraceIds::new(0, 0)), |tracer| {
            tracer.debug(InfoType::DataIn, b"visible\x00also visible");
        });
        assert_eq!(
            records[0].1, b"visible\x00also visible",
            "no NUL truncation on this path"
        );
    }

    // ---------------------------------------------------------------------
    // easy_timers: the preserved unit-label defect, and the skip.
    // ---------------------------------------------------------------------

    #[test]
    fn easy_timers_prints_microseconds_labelled_ns_exactly_as_c_does() {
        // `curlx_ptimediff_us()` under `"expires in %" FMT_TIMEDIFF_T "ns"`
        // (`lib/curl_trc.c:327-328`). The label is wrong in C and is frozen
        // output, so it is wrong here too: AAP section 0.8.2 forbids a change
        // justified as an improvement.
        let mut config = TraceConfig::new();
        config.apply(Some("timer")).unwrap();
        let out = stream_output(&config, state_with(TraceIds::new(0, 0)), |tracer| {
            tracer.easy_timers(vec![
                (TimerId::Timeout, 1_500_000_i64),
                (TimerId::ConnectTimeout, -25_i64),
            ]);
        });
        assert_eq!(
            out,
            "* [TIMER] [TIMEOUT] expires in 1500000ns\n\
             * [TIMER] [CONNECTTIMEOUT] expires in -25ns\n"
        );
    }

    #[test]
    fn easy_timers_does_not_walk_the_list_when_the_feature_is_off() {
        // C's outer guard means the timeout list is never traversed. The
        // iterator here counts, so the skip is observable rather than assumed.
        let visits = Cell::new(0_usize);
        let config = TraceConfig::new();
        let out = stream_output(&config, state_with(TraceIds::new(0, 0)), |tracer| {
            tracer.easy_timers(TimerId::ALL.iter().map(|&timer| {
                visits.set(visits.get() + 1);
                (timer, 0_i64)
            }));
        });
        assert_eq!(out, "");
        assert_eq!(
            visits.get(),
            0,
            "the caller's iterator must not be advanced"
        );
    }

    #[test]
    fn easy_timers_with_an_empty_list_emits_nothing() {
        let mut config = TraceConfig::new();
        config.apply(Some("timer")).unwrap();
        let out = stream_output(&config, state_with(TraceIds::new(0, 0)), |tracer| {
            tracer.easy_timers(Vec::new());
        });
        assert_eq!(out, "");
    }

    #[test]
    fn a_raw_timer_number_outside_the_range_renders_unknown() {
        let mut config = TraceConfig::new();
        config.apply(Some("timer")).unwrap();
        let out = stream_output(&config, state_with(TraceIds::new(0, 0)), |tracer| {
            tracer.timer_id(99, format_args!("armed"));
            tracer.timer_id(TimerId::Shutdown.as_i32(), format_args!("armed"));
        });
        assert_eq!(
            out,
            "* [TIMER] [UNKNOWN?] armed\n* [TIMER] [SHUTDOWN] armed\n"
        );
    }

    // ---------------------------------------------------------------------
    // The emitter macros.
    // ---------------------------------------------------------------------

    #[test]
    fn every_macro_produces_its_c_layout() {
        let config = traced_all();
        let out = stream_output(&config, state_with(TraceIds::new(0, 0)), |tracer| {
            infof!(tracer, "plain {} {}", "one", 2);
            failf!(tracer, "failed with {}", 7);
            trc_feat!(tracer, TraceFeature::Dns, "resolving {}", "host");
            trc_multi!(tracer, CurlMstate::Performing, "sending");
            trc_timer!(tracer, TimerId::Shutdown, "armed for {}ms", 250);
            trc_cf!(tracer, TraceFilter::Ssl, 0, "handshake done");
            trc_cf!(tracer, TraceFilter::Ssl, 2, "handshake done");
        });
        assert_eq!(
            out,
            "* [0-0] plain one 2\n\
             * failed with 7\n\
             * [0-0] [DNS] resolving host\n\
             * [0-0] [MULTI] [PERFORMING] sending\n\
             * [0-0] [TIMER] [SHUTDOWN] armed for 250ms\n\
             * [0-0] [SSL] handshake done\n\
             * [0-0] [SSL-2] handshake done\n"
        );
    }

    #[test]
    fn every_macro_is_reachable_by_path_from_another_module() {
        // `macro_rules!` is only textually in scope within this module and its
        // descendants, so the `pub(crate) use` re-exports are what let
        // `crate::protocols`, `crate::conn` and the rest reach them. Invoking
        // through the path here is how those modules will, and it checks the
        // re-export rather than the textual scope.
        let config = traced_all();
        let out = stream_output(&config, state_with(TraceIds::new(1, 2)), |tracer| {
            crate::trace::infof!(tracer, "by path");
            crate::trace::failf!(tracer, "by path");
            crate::trace::trc_feat!(tracer, TraceFeature::Write, "by path");
            crate::trace::trc_multi!(tracer, CurlMstate::Setup, "by path");
            crate::trace::trc_timer!(tracer, TimerId::TooFast, "by path");
            crate::trace::trc_cf!(tracer, TraceFilter::Setup, 0, "by path");
        });
        assert_eq!(
            out,
            "* [1-2] by path\n\
             * by path\n\
             * [1-2] [WRITE] by path\n\
             * [1-2] [MULTI] [SETUP] by path\n\
             * [1-2] [TIMER] [TOOFAST] by path\n\
             * [1-2] [SETUP] by path\n"
        );
    }

    /// Compiles the six macro doc-examples in the exact shape they are written.
    ///
    /// Each `macro_rules!` above carries an `ignore`d snippet, and the same
    /// reasoning as [`the_documented_example_writes_the_line_it_claims`]
    /// applies: nothing compiles those snippets, so they can drift silently.
    /// This reproduces every one -- inline format captures, trailing positional
    /// arguments and the `trc_cf!` socket index included -- so a change to any
    /// macro's arity or to an enum variant's spelling breaks the build here.
    #[test]
    fn the_documented_macro_examples_compile_in_the_shape_they_are_written() {
        let host = "example.com";
        let port = 443_u16;
        let n = 42_usize;
        let mstate = CurlMstate::Connecting;
        let next = CurlMstate::ProtoConnect;
        // `int` in C -- `struct Curl_cfilter`'s `sockindex` -- so `i32` here.
        let sockindex = 0_i32;
        let peer = "127.0.0.1:80";

        let config = traced_all();
        let out = stream_output(&config, state_with(TraceIds::new(0, 0)), |tracer| {
            crate::trace::infof!(tracer, "Connected to {host} port {port}");
            crate::trace::failf!(tracer, "Could not resolve host: {host}");
            crate::trace::trc_feat!(tracer, TraceFeature::Read, "client read {} bytes", n);
            crate::trace::trc_multi!(tracer, mstate, "-> [{}]", next);
            crate::trace::trc_timer!(tracer, TimerId::HappyEyeballs, "cleared");
            crate::trace::trc_cf!(tracer, TraceFilter::Tcp, sockindex, "connected to {peer}");
        });
        assert_eq!(
            out,
            "* [0-0] Connected to example.com port 443\n\
             * Could not resolve host: example.com\n\
             * [0-0] [READ] client read 42 bytes\n\
             * [0-0] [MULTI] [CONNECTING] -> [PROTOCONNECT]\n\
             * [0-0] [TIMER] [HAPPY_EYEBALLS] cleared\n\
             * [0-0] [TCP] connected to 127.0.0.1:80\n"
        );
    }

    #[test]
    fn macros_accept_a_trailing_comma_and_no_arguments() {
        let config = traced_all();
        let out = stream_output(&config, state_with(TraceIds::UNASSIGNED), |tracer| {
            infof!(tracer, "bare");
            infof!(tracer, "trailing {}", 1,);
            trc_feat!(tracer, TraceFeature::Read, "bare");
            trc_multi!(tracer, CurlMstate::Done, "bare");
            trc_timer!(tracer, TimerId::Quic, "bare");
            trc_cf!(tracer, TraceFilter::Udp, 0, "bare");
            failf!(tracer, "bare");
        });
        assert_eq!(out.lines().count(), 7);
    }

    #[test]
    fn a_suppressed_macro_does_not_evaluate_its_arguments() {
        // C's macros exist for exactly this: an argument may have a side effect,
        // so a disabled trace must not run it. Behaviour, not speed.
        let evaluations = Cell::new(0_usize);
        let count = || {
            evaluations.set(evaluations.get() + 1);
            evaluations.get()
        };

        let silent = TraceConfig::new();
        let out = stream_output(&silent, state_with(TraceIds::new(0, 0)), |tracer| {
            trc_feat!(tracer, TraceFeature::Dns, "value {}", count());
            trc_multi!(tracer, CurlMstate::Init, "value {}", count());
            trc_timer!(tracer, TimerId::Timeout, "value {}", count());
            trc_cf!(tracer, TraceFilter::Tcp, 0, "value {}", count());
        });
        assert_eq!(out, "");
        assert_eq!(
            evaluations.get(),
            0,
            "no argument may be evaluated while suppressed"
        );

        // And with everything enabled, each one is evaluated exactly once.
        let loud = traced_all();
        let out = stream_output(&loud, state_with(TraceIds::new(0, 0)), |tracer| {
            trc_feat!(tracer, TraceFeature::Dns, "value {}", count());
            trc_multi!(tracer, CurlMstate::Init, "value {}", count());
            trc_timer!(tracer, TimerId::Timeout, "value {}", count());
            trc_cf!(tracer, TraceFilter::Tcp, 0, "value {}", count());
        });
        assert_eq!(evaluations.get(), 4);
        assert!(out.contains("value 1"), "{out}");
        assert!(out.contains("value 4"), "{out}");
    }

    #[test]
    fn a_suppressed_infof_macro_does_not_evaluate_its_arguments() {
        let evaluations = Cell::new(0_usize);
        let config = TraceConfig::new();
        let state = TraceState {
            verbose: true,
            feat: Some(TraceFeature::Dns),
            ids: TraceIds::UNASSIGNED,
        };
        let out = stream_output(&config, state, |tracer| {
            infof!(tracer, "value {}", {
                evaluations.set(evaluations.get() + 1);
                1
            });
        });
        assert_eq!(out, "");
        assert_eq!(evaluations.get(), 0);
    }

    #[test]
    fn the_failf_macro_is_deliberately_unguarded() {
        // `#define failf Curl_failf` has no level test, so the message reaches
        // the error buffer even with tracing off. A guard here would lose that.
        let evaluations = Cell::new(0_usize);
        let config = TraceConfig::new();
        let mut buffer = ErrorBuffer::new();
        let mut sink = WriterSink::new(Vec::<u8>::new());
        {
            let mut tracer = Tracer::new(&config, &mut sink).with_error_buffer(&mut buffer);
            let tracer = &mut tracer;
            failf!(tracer, "value {}", {
                evaluations.set(evaluations.get() + 1);
                9
            });
        }
        assert_eq!(sink.into_inner(), b"");
        assert_eq!(buffer.message_bytes(), b"value 9");
        assert_eq!(
            evaluations.get(),
            1,
            "failf always evaluates: it has no guard"
        );
    }

    // ---------------------------------------------------------------------
    // The no-newline invariant.
    // ---------------------------------------------------------------------

    #[test]
    fn fmt_has_newline_detects_a_line_feed_anywhere() {
        assert!(!fmt_has_newline(""));
        assert!(!fmt_has_newline("no newline here"));
        assert!(!fmt_has_newline("a carriage return \r is not tested"));
        assert!(fmt_has_newline("\n"));
        assert!(fmt_has_newline("trailing\n"));
        assert!(fmt_has_newline("\nleading"));
        assert!(fmt_has_newline("in the \n middle"));
        assert!(fmt_has_newline("two\nof\nthem"));
        // Multi-byte input is scanned by byte, as C's `strchr()` is.
        assert!(!fmt_has_newline("caf\u{e9}"));
        assert!(fmt_has_newline("caf\u{e9}\n"));
    }

    #[test]
    fn fmt_has_newline_is_usable_in_a_const_context() {
        // This is what lets the macros reject a bad format string at compile
        // time, where C's `DEBUGASSERT` only fires in a debug build at run time.
        const CLEAN: bool = fmt_has_newline("clean");
        const DIRTY: bool = fmt_has_newline("dirty\n");
        // Compared as an array rather than asserted individually: both operands
        // are compile-time constants, and `assert!` on a constant is itself a
        // lint. The values are what matter, and they are checked here.
        assert_eq!([CLEAN, DIRTY], [false, true]);
        // The anonymous-constant form the macros use, which fails the build
        // rather than a test run.
        const _: () = assert!(!fmt_has_newline("this is what every macro asserts"));
    }

    #[test]
    fn no_format_string_emitted_by_this_module_contains_a_newline() {
        // The invariant C asserts in every entry point, checked over every fixed
        // string this module can put into a record. The emitter appends the line
        // terminator, so an embedded one would split a record and leave the
        // fragment after it without a prefix.
        let mut fixed: Vec<String> = Vec::new();
        for &feature in TraceFeature::ALL {
            fixed.push(feature.name().to_string());
            fixed.push(format!("[{}] ", feature.name()));
        }
        for &filter in TraceFilter::ALL {
            fixed.push(filter.name().to_string());
            fixed.push(format!("[{}] ", filter.name()));
            fixed.push(format!("[{}-{}] ", filter.name(), 1));
        }
        for &timer in TimerId::ALL {
            fixed.push(timer.name().to_string());
        }
        fixed.push(TimerId::UNKNOWN_NAME.to_string());
        for index in 0..CurlMstate::COUNT {
            fixed.push(mstate_name(index as i32).to_string());
        }
        fixed.push(mstate_name(-1).to_string());
        for &kind in InfoType::ALL {
            fixed.push(kind.prefix().to_string());
            if let Some(label) = kind.dump_label() {
                fixed.push(label.to_string());
            }
        }
        for ids in [
            TraceIds::new(1, 2),
            TraceIds::xfer_only(1),
            TraceIds { xfer: -1, conn: 2 },
            TraceIds::UNASSIGNED,
        ] {
            fixed.push(ids.to_string());
        }
        fixed.push(
            TraceTime {
                hour: 1,
                minute: 2,
                second: 3,
                microsecond: 4,
            }
            .to_string(),
        );
        fixed.push(TRACE_CONFIG_DOH_ALIAS_TARGET.to_string());

        for candidate in &fixed {
            assert!(
                !fmt_has_newline(candidate),
                "{candidate:?} contains a newline"
            );
            assert!(
                !candidate.contains('\n'),
                "{candidate:?} contains a newline"
            );
        }
        assert!(fixed.len() > 60, "the sweep must actually cover the tables");
    }

    #[test]
    fn every_emitter_terminates_its_record_with_exactly_one_newline() {
        let config = traced_all();
        let out = stream_output(&config, state_with(TraceIds::new(0, 0)), |tracer| {
            tracer.infof(format_args!("a"));
            tracer.failf(format_args!("b"));
            tracer.feature(TraceFeature::Dns, format_args!("c"));
            tracer.multi(CurlMstate::Init, format_args!("d"));
            tracer.timer(TimerId::Timeout, format_args!("e"));
            tracer.filter(TraceFilter::Tcp, 0, format_args!("f"));
        });
        assert_eq!(out.matches('\n').count(), 6);
        assert!(out.ends_with('\n'));
        assert!(!out.contains("\n\n"));
    }

    // ---------------------------------------------------------------------
    // dump(): the --trace and --trace-ascii geometry, byte for byte against a
    // capture from the C command-line tool built from this tree.
    // ---------------------------------------------------------------------

    /// The 52-byte payload the captures were taken over.
    const ORACLE_PAYLOAD: &[u8] = b"Hello, curl trace oracle!\r\nSecond line here\r\nthird\r\n";

    fn dumped(payload: &[u8], style: DumpStyle) -> String {
        let mut out = Vec::new();
        dump(
            &mut out,
            "",
            "",
            InfoType::DataIn.dump_label().expect("data in has a label"),
            payload,
            style,
        )
        .expect("a Vec cannot fail to accept bytes");
        String::from_utf8(out).expect("dump output is ASCII")
    }

    #[test]
    fn dump_hex_matches_the_c_capture() {
        assert_eq!(ORACLE_PAYLOAD.len(), 52);
        let expected = concat!(
            "<= Recv data, 52 bytes (0x34)\n",
            "0000: 48 65 6c 6c 6f 2c 20 63 75 72 6c 20 74 72 61 63 Hello, curl trac\n",
            "0010: 65 20 6f 72 61 63 6c 65 21 0d 0a 53 65 63 6f 6e e oracle!..Secon\n",
            "0020: 64 20 6c 69 6e 65 20 68 65 72 65 0d 0a 74 68 69 d line here..thi\n",
            "0030: 72 64 0d 0a                                     rd..\n",
        );
        assert_eq!(dumped(ORACLE_PAYLOAD, DumpStyle::Hex), expected);
    }

    #[test]
    fn dump_ascii_matches_the_c_capture() {
        // The offsets are the load-bearing part: 0x1b and 0x2d fall out of C's
        // CRLF skip, and getting the advance wrong would move them.
        let expected = concat!(
            "<= Recv data, 52 bytes (0x34)\n",
            "0000: Hello, curl trace oracle!\n",
            "001b: Second line here\n",
            "002d: third\n",
        );
        assert_eq!(dumped(ORACLE_PAYLOAD, DumpStyle::Ascii), expected);
    }

    #[test]
    fn dump_widths_match_c() {
        assert_eq!(DumpStyle::Hex.width(), 0x10);
        assert_eq!(DumpStyle::Ascii.width(), 0x40);
    }

    #[test]
    fn dump_pads_a_short_final_row_so_the_character_column_aligns() {
        let rendered = dumped(ORACLE_PAYLOAD, DumpStyle::Hex);
        let last = rendered.lines().last().expect("at least one row");
        // "0030: " is 6, sixteen hex columns are 48, and "rd.." is 4.
        assert_eq!(last.len(), 6 + 48 + 4);
        assert!(last.ends_with("rd.."), "{last}");
        assert!(
            last.contains("0d 0a    "),
            "padding follows the last real byte"
        );
    }

    #[test]
    fn dump_renders_unprintable_bytes_as_dots() {
        let payload: Vec<u8> = vec![0x00, 0x1f, 0x20, b'A', 0x7e, 0x7f, 0x80, 0xff];
        let rendered = dumped(&payload, DumpStyle::Hex);
        let row = rendered.lines().nth(1).expect("one row");
        // 0x20 is the space, and it is printable: the boundary is inclusive
        // below and exclusive above, C's `>= 0x20 && < 0x7F`.
        assert!(row.ends_with(".. A~..."), "{row}");
        assert_eq!(UNPRINTABLE_CHAR, b'.');
        assert_eq!(PRINTABLE_LOW, 0x20);
        assert_eq!(PRINTABLE_HIGH, 0x7f);
    }

    #[test]
    fn dump_of_an_empty_payload_is_the_header_alone() {
        assert_eq!(dumped(b"", DumpStyle::Hex), "<= Recv data, 0 bytes (0x0)\n");
        assert_eq!(
            dumped(b"", DumpStyle::Ascii),
            "<= Recv data, 0 bytes (0x0)\n"
        );
    }

    #[test]
    fn dump_offsets_widen_past_four_digits() {
        // `%04zx` is a minimum width, so a payload over 64 KiB keeps counting
        // rather than wrapping.
        let payload = vec![b'.'; 0x1_0010];
        let rendered = dumped(&payload, DumpStyle::Hex);
        assert!(
            rendered.contains("\nfff0: "),
            "the last four-digit row is fff0"
        );
        assert!(rendered.contains("\n10000: "), "and then five digits");
        assert!(rendered.starts_with("<= Recv data, 65552 bytes (0x10010)\n"));
    }

    #[test]
    fn dump_writes_the_time_and_identifier_prefixes_before_the_label() {
        let mut out = Vec::new();
        let clock = FixedClock(TraceTime {
            hour: 9,
            minute: 32,
            second: 55,
            microsecond: 600_049,
        });
        let time = clock.now().to_string();
        let ids = TraceIds::new(0, 0).to_string();
        dump(
            &mut out,
            &time,
            &ids,
            InfoType::HeaderOut
                .dump_label()
                .expect("header out has a label"),
            b"GET / HTTP/1.1\r\n",
            DumpStyle::Ascii,
        )
        .expect("a Vec cannot fail");
        let rendered = String::from_utf8(out).expect("ASCII");
        assert!(
            rendered.starts_with("09:32:55.600049 [0-0] => Send header, 16 bytes (0x10)\n"),
            "{rendered}"
        );
        assert!(rendered.ends_with("0000: GET / HTTP/1.1\n"), "{rendered}");
    }

    #[test]
    fn dump_ascii_breaks_at_a_crlf_that_lands_on_the_row_boundary() {
        // C checks for CRLF twice per byte precisely to handle the case where it
        // straddles the row width, "to avoid an extra \n if it is at width".
        let mut payload = vec![b'a'; 0x3f];
        payload.extend_from_slice(b"\r\ntail");
        let rendered = dumped(&payload, DumpStyle::Ascii);
        let rows: Vec<&str> = rendered.lines().skip(1).collect();
        assert_eq!(rows.len(), 2, "{rendered}");
        assert_eq!(rows[0], format!("0000: {}", "a".repeat(0x3f)));
        assert_eq!(rows[1], "0041: tail");
    }

    #[test]
    fn dump_ascii_keeps_a_trailing_lone_carriage_return() {
        // The CRLF tests both require the LF to be within the payload, so a
        // trailing CR is rendered as an unprintable byte rather than skipped.
        assert_eq!(
            dumped(b"ab\r", DumpStyle::Ascii),
            "<= Recv data, 3 bytes (0x3)\n0000: ab.\n"
        );
    }

    #[test]
    fn dump_hex_does_not_break_at_crlf() {
        // Only `--trace-ascii` breaks; the hex layout keeps fixed rows so its
        // offsets stay aligned.
        let rendered = dumped(b"a\r\nb", DumpStyle::Hex);
        assert_eq!(
            rendered,
            "<= Recv data, 4 bytes (0x4)\n\
             0000: 61 0d 0a 62                                     a..b\n"
        );
    }
}
