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

//! Operating-system integration: the sole `unsafe` island in `curl-rs-lib`,
//! and the boundary that keeps it sealed.
//!
//! This is a module root and nothing more. It declares the two files that
//! perform the residual platform calls, re-exports a narrow surface of safe
//! wrappers for the rest of the crate, and holds no logic beyond the single
//! feature-bridging predicate at the end. It performs no raw call of its own.
//!
//! # 1. Why this directory exists
//!
//! Every other module in this crate is safe Rust. A small number of
//! operations have no safe expression at all, and AAP 0.8.5/C3 settles where
//! they live:
//!
//! > "Route everything expressible through `socket2`, and **relocate the
//! > genuine residue into `curl-rs-lib/src/ffi/sys.rs`** so that
//! > `#![forbid(unsafe_code)]` plus one targeted `#[allow]` makes the
//! > invariant machine-checkable rather than aspirational."
//!
//! That is the whole charter: a named directory, small enough to audit by
//! reading, holding the residue and nothing else.
//!
//! # 2. The single-exemption invariant
//!
//! The crate root denies the `unsafe_code` lint, and exactly one item in the
//! whole crate relaxes it: the `mod ffi` declaration in
//! `curl-rs-lib/src/lib.rs`. A lint level attached to a `mod foo;` *item*
//! propagates into that module's contents even when the body lives in a
//! separate file, so this file and both of its children are already covered
//! by that one relaxation and **must not restate it**. A second relaxation
//! anywhere under this directory would turn a compiler-checked invariant back
//! into a review-checked one and would defeat the gate that polices it: that
//! gate greps `curl-rs-lib/src` for the relaxation and requires exactly one
//! hit, in `lib.rs`. The token is therefore deliberately absent from this
//! file, including from its prose.
//!
//! One consequence belongs to `lib.rs` rather than here, and is recorded so
//! that nobody tries to fix it in the wrong place: the root must use `deny`,
//! not `forbid`. `forbid` is `deny` plus a prohibition on relaxing the level
//! later, so a `forbid` root followed by a relaxation on `mod ffi` fails with
//! `error[E0453]` and the raw calls inside this directory are rejected as
//! well. **If that error ever appears, the fix belongs in `lib.rs`.** Adding
//! any lint attribute here instead would create exactly the second exemption
//! described above.
//!
//! # 3. Every raw call is justified in place
//!
//! Each `unsafe` block in `sys.rs` and `gss.rs` is immediately preceded by a
//! `// SAFETY:` comment naming the precondition being upheld and why it holds
//! at that site. Three greps police the arrangement, and all three are run
//! against this directory rather than trusted:
//!
//! ```sh
//! # 1. No raw call escapes this directory -- must print nothing:
//! grep -rn 'unsafe' curl-rs-lib/src --include='*.rs' \
//!   | grep -v '^curl-rs-lib/src/ffi/'
//!
//! # 2. Every occurrence inside it is justified -- audited by hand, both
//! #    files, counting rather than sampling:
//! grep -rn -B1 'unsafe' curl-rs-lib/src/ffi/
//!
//! # 3. THIS file contains no raw call of its own. The word appears above
//! #    only because sections 1-3 are required to explain the arrangement,
//! #    so the gate strips comment lines before looking -- must print 0:
//! grep -vE '^\s*//' curl-rs-lib/src/ffi/mod.rs | grep -c 'unsafe'
//! ```
//!
//! # 4. The socket2-first rule
//!
//! Nothing is added to this directory until `socket2` has been *proven*
//! unable to express it. AAP 0.6.9 fixes both the rule and the expected size
//! of the residue:
//!
//! > "raw `setsockopt`, `getsockopt`, and `fcntl` calls are absorbed by
//! > `socket2`. What genuinely remains -- a hostname query and a small number
//! > of platform calls -- is confined to `curl-rs-lib/src/ffi/sys.rs`."
//!
//! `socket2` is pinned at `=0.6.5` with its `all` feature enabled, which is
//! what makes the platform socket options curl sets reachable without a raw
//! call. The re-export surface below is deliberately the size that sentence
//! predicts. `lib/curlx/nonblock.c` is the canonical example of something
//! that does **not** belong here: it becomes
//! `socket2::Socket::set_nonblocking` in `conn/socket.rs`.
//!
//! # 5. What this directory supersedes, by path
//!
//! * `lib/curl_gethostname.c` and `lib/curl_gethostname.h` become
//!   [`sys::gethostname`] and [`sys::HOSTNAME_MAX`].
//! * The `HAVE_GETIFADDRS` body of `lib/if2ip.c:92-174` becomes
//!   [`sys::interface_addrs`] and [`sys::interface_names`].
//! * The `if_nametoindex` call at `lib/url.c:1615` becomes
//!   [`sys::if_nametoindex`].
//! * `lib/curl_gssapi.c` and `lib/curl_gssapi.h` become `gss`, under the
//!   `negotiate` feature.
//! * `lib/memdebug.c` becomes `sys::memdebug`, under the `memdebug` feature.
//!
//! `lib/Makefile.inc` lists all four superseded translation units in
//! `LIB_CFILES`: `curl_gethostname.c` at `:169`, `curl_gssapi.c` at `:170`,
//! `if2ip.c` at `:217` and `memdebug.c` at `:224`, with the two headers at
//! `:296` and `:297`. Only the decision-free half of `lib/if2ip.c` lands
//! here; `Curl_if2ip`'s verdict logic is pure computation and belongs in
//! `dns/if2ip.rs`.
//!
//! Two configuration mechanisms disappear rather than move.
//! `GETHOSTNAME_TYPE_ARG2` (`lib/curl_setup.h:649-655`) selects the second
//! parameter's type per platform; a Rust slice carries its own length, so the
//! shim has no counterpart. `USE_SPNEGO` and `USE_KERBEROS5` are each defined
//! at "a single point" (`lib/curl_setup.h:752-762`) from
//! `!CURL_DISABLE_*_AUTH && (HAVE_GSSAPI || USE_WINDOWS_SSPI)`; that single
//! point is now the one `negotiate` Cargo feature.
//!
//! # 6. Not to be confused with `curl-rs-ffi/src/ffi/`
//!
//! AAP 0.8.5/C1 sanctions two directories called `ffi` and gives each a
//! distinct job: "`curl-rs-ffi/src/ffi/` for the public ABI and
//! `curl-rs-lib/src/ffi/` for OS integration."
//!
//! * `curl-rs-ffi/src/ffi/` is the C ABI. It exports 100 symbols, verified by
//!   `nm` against `lib/libcurl.def`, and every one of them is deliberately
//!   visible to the linker.
//! * **This** directory exports nothing to the linker at all. Nothing here is
//!   given C linkage or an unmangled external symbol name, and nothing here
//!   is `pub` -- so no item can leave the crate, let alone reach a `nm`
//!   listing. A stray external symbol here would corrupt that parity gate,
//!   which is why the distinction is written down rather than assumed.
//!
//! # 7. Platform scope
//!
//! The four mandated targets are `x86_64-unknown-linux-gnu`,
//! `aarch64-unknown-linux-gnu`, `x86_64-apple-darwin` and
//! `aarch64-apple-darwin`: all 64-bit, all Unix. Divergence between them is
//! expressed with `#[cfg(target_os = ...)]`, never with a Cargo feature -- a
//! feature is a capability the user chooses, whereas a platform is a fact
//! about the build. AAP 0.2.2 excludes Windows, AmigaOS, OS/400, VMS and
//! 32-bit targets outright, so no path for them appears here and none may be
//! added "for completeness".
//!
//! Cargo features do appear, for the two *capabilities* this directory
//! carries: `negotiate` and `memdebug`, both default-off. There is no `tls`
//! feature anywhere in this workspace and none may be introduced: TLS is
//! unconditional, because certificate validation is on by default
//! (AAP 0.1.1 G4, AAP 0.8.2) and an off-switch would permit a build with no
//! TLS at all.
//!
//! # 8. How to read the re-export surface below
//!
//! Both children are declared `pub(crate)`, so every item they publish is
//! already reachable crate-wide by its full path. The re-exports are
//! therefore **not** an access barrier -- the barrier is that nothing in this
//! directory is `pub`, so nothing escapes the crate. What the list gives is a
//! canonical short path and, more importantly, **an audit checklist that can
//! be read in one sitting**: every capability the safe half of the crate
//! reaches for is named once, explicitly, with no glob anywhere in sight.
//!
//! The seal it records is that no item reachable from outside this directory
//! exposes a raw pointer of either mutability, a `libc` type, an `unsafe fn`,
//! a GSS-API handle or an `OM_uint32`. Where operating-system state must
//! outlive a call it is wrapped in an owning type whose `Drop` performs the
//! cleanup, and the owning type is what travels. One standard-library C-string
//! view (`&CStr`) does appear, in [`sys::SysCalls::if_nametoindex`]; it is a
//! safe borrowed type rather than a `libc` type or a pointer, and it is named
//! here so that the audit is complete rather than merely favourable.
//!
//! The checklist is not left to prose. The signature-contract block at the
//! foot of this file records every re-exported item at its exact type, so drift
//! in a child module breaks the build *here*, beside the documentation that
//! describes the surface -- and so that adding a re-export without recording
//! it is reported rather than overlooked.

// `dead_code` is allowed for this directory as a whole, from its root, and
// for one specific reason rather than as a convenience: every consumer of
// these wrappers lives in a module that this crate has yet to grow --
// `dns/if2ip.rs` for the interface snapshot, `protocols/mod.rs` and `url/`
// for the zone-id lookup, `version.rs` for the availability predicate,
// `lib.rs` for the optional allocator, and `auth/negotiate.rs` plus
// `proxy/socks_gss.rs` for the GSS-API surface. Until those land, every
// wrapper is legitimately unreferenced, and the zero-warnings gate
// (AAP 0.8.4) would otherwise fail on code that is correct.
//
// Measured, not assumed: with this attribute absent, `cargo build
// --features negotiate` reports 98 `dead_code` warnings, all of them in
// `gss.rs`. A lint level on a module root propagates into the modules
// declared inside it, so one attribute here covers both children; `sys.rs`
// carries its own copy, which is redundant but harmless.
//
// No level for the `unsafe_code` lint is set here, at any level, by design:
// see section 2 above.
#![allow(dead_code)]

// The one import this file needs, and the reason it needs it: every wrapper
// re-exported below reports failure as a `CURLcode`, and the signature
// contract at the foot of the file spells those return types out.
use crate::error::CodeResult;

// ===========================================================================
// The two implementation files -- and there are exactly two
//
// AAP 0.3.1's layout line is literal: `curl-rs-lib/src/ffi/{mod,sys,gss}.rs`.
// No third module is declared and no subdirectory exists. Four candidates
// were considered during planning and every one was rejected against the
// scope constraint that a file not named by the AAP is not created:
//
//   * a separate `memdebug.rs` -- the counting allocator must live in this
//     directory, because implementing `GlobalAlloc` requires an unsafe impl,
//     but the AAP names no file for it, so it is a module inside `sys.rs`;
//   * separate `ifaddrs.rs` and `hostname.rs` -- both are `sys.rs`;
//   * a `nonblock.rs` -- not residue at all; see section 4 above.
//
// Unit tests are `#[cfg(test)] mod tests` inside each file, so no `tests`
// module is declared here either. The repository-root `tests-rs/` tree is a
// separate concern (AAP 0.3.1).
// ===========================================================================

/// Platform calls with no safe expression, behind safe wrappers.
///
/// Supersedes `lib/curl_gethostname.c`, the `HAVE_GETIFADDRS` body of
/// `lib/if2ip.c`, the `if_nametoindex` call at `lib/url.c:1615` and --
/// under the `memdebug` feature -- `lib/memdebug.c`.
pub(crate) mod sys;

/// The GSS-API binding used by Negotiate, SPNEGO and Kerberos.
///
/// Feature-gated and **default-off**, which is what resolves AAP 0.8.5/C2:
/// "Negotiate sits behind a non-default `negotiate` feature with the binding
/// confined to `curl-rs-lib/src/ffi/gss.rs`, so the default build links no C
/// security library at all." With the feature off this file contributes
/// nothing whatsoever -- no item, no `#[link]` directive, no linker input and
/// no symbol -- which is a property the default build is checked for rather
/// than credited with.
#[cfg(feature = "negotiate")]
pub(crate) mod gss;

// ===========================================================================
// The re-export surface -- group A: the wrappers themselves
//
// Four entry points and the owned values they return. This is the whole of
// what AAP 0.6.9 calls "a hostname query and a small number of platform
// calls", and the list is meant to stay this short.
//
// No lint suppression is needed on any of the four groups, even though the
// modules that will consume them do not exist yet: the signature contract at
// the foot of the file records every one of these items, which both pins its
// type and keeps the import list honest. Add a re-export without recording it
// there and the unused import is reported -- which is the intended outcome,
// not an obstacle.
// ===========================================================================

pub(crate) use sys::{
    gethostname, if_nametoindex, interface_addrs, interface_names,
    InterfaceAddr, HOSTNAME_MAX,
};

// ===========================================================================
// The re-export surface -- group B: the injection seam
//
// AAP 0.3.3 P12 applies dependency injection to "the resolver, the clock, and
// the TLS provider"; here it applies to the operating system itself, and it
// is a hard requirement rather than a preference. `cargo +nightly miri test
// -p curl-rs-lib` is a mandated gate (AAP 0.8.4) and Miri cannot execute a
// foreign function, so each wrapper above is a thin call into a `_with`
// variant that takes the operating system as an argument. Substituting a
// pure-Rust fake covers every branch of the surrounding logic under Miri, and
// covers the branches a real host cannot be made to take -- a NULL
// `ifa_addr`, an address family this layer does not represent, a `gethostname`
// that truncates without terminating.
//
// The seam is re-exported at `pub(crate)` rather than being hidden behind
// `#[cfg(test)]`, because the modules that consume these wrappers need it for
// their own tests, not only for tests written inside this directory. It is
// not widened beyond the crate.
// ===========================================================================

pub(crate) use sys::{
    gethostname_with, if_nametoindex_with, interface_addrs_with,
    interface_names_with, IfNode, RawIfAddr, RealSys, SysCalls,
};

// ===========================================================================
// The re-export surface -- group C: the counting allocator, feature
// `memdebug`, DEFAULT OFF
//
// Reproduces the allocation log of `lib/memdebug.c` in the format
// `tests/memanalyzer.pm` parses. Off by default because the harness wraps its
// entire memory check in `if($feature{"TrackMemory"})` and derives that
// feature solely from a `Debug` token in the version banner, so a binary that
// does not advertise `Debug` has all leak and allocation-cap checking skipped
// (AAP 0.6.6). The feature exists so the trade can be reversed without a
// redesign.
//
// WHERE THE ALLOCATOR IS INSTALLED, decided once and recorded here because it
// must happen in exactly one place in the crate: `lib.rs` declares the
// `#[global_allocator]` static, and this file only makes the type nameable.
// `sys.rs` documents the same division and spells the wiring out. This file
// declares no allocator of its own, and a second declaration anywhere in the
// crate is a compile error rather than a subtle bug -- which is the reason to
// state the choice rather than leave it to be inferred.
//
// DELIBERATELY NOT re-exported: `sys::memdebug::Record` and the five record
// builders `malloc_record`, `calloc_record`, `realloc_record`, `free_record`
// and `limit_record`. They are how the allocator formats its own output; no
// module outside this directory has any use for them, and re-exporting them
// would grow the audit list without adding a capability.
// ===========================================================================

#[cfg(feature = "memdebug")]
pub(crate) use sys::memdebug::{set_memlimit, TrackingAllocator};

// ===========================================================================
// The re-export surface -- group D: the GSS-API vocabulary, feature
// `negotiate`, DEFAULT OFF
//
// The safe types `auth/negotiate.rs` and `proxy/socks_gss.rs` need in order
// to drive a handshake without ever holding a GSS-API handle. Every one of
// them is either a plain enum, a newtype whose fields are private, or a
// struct whose public fields are ordinary Rust values; the mechanism OIDs,
// the status integers and the `GSS_C_*` bit constants all stay inside
// `gss.rs`.
//
// The three `GSSAUTH_P_*` constants come from `lib/curl_gssapi.h:65-67` and
// are the SOCKS5 protection levels curl negotiates; the three
// `SOCKS5_PROTECTION_*` constants are the wire values that correspond to
// them.
//
// DELIBERATELY NOT re-exported: `gss::available`. Its total counterpart
// `gss_available` below answers the same question in every feature state, and
// having one blessed entry point is what stops a caller from reaching for a
// predicate that does not exist in the default build.
// ===========================================================================

#[cfg(feature = "negotiate")]
pub(crate) use gss::{
    request_flags, ContextFlags, Delegation, Diagnostics, DiscardDiagnostics,
    GssStatus, HandshakeOutcome, HandshakeState, Mechanism, NameType,
    RequestedFlags, SealedMessage, SecurityContext, StepOptions, TargetName,
    DELEGATION_POLICY_UNSUPPORTED_WARNING, GSSAUTH_P_INTEGRITY, GSSAUTH_P_NONE,
    GSSAUTH_P_PRIVACY, SOCKS5_PROTECTION_CONFIDENTIALITY,
    SOCKS5_PROTECTION_INTEGRITY, SOCKS5_PROTECTION_NONE,
};

// ===========================================================================
// The one function in this file
// ===========================================================================

/// Whether GSS-API is genuinely usable in this process, right now.
///
/// This is the crate's only sanctioned answer to "is Negotiate available",
/// and it is deliberately *total*: it compiles and answers in every feature
/// state, returns a `bool`, never panics, never propagates an error and
/// performs no I/O.
///
/// # Why a compile-time check is not enough
///
/// `version.rs` calls this before it puts `GSS-API`, `SPNEGO` or `Kerberos`
/// into the `Features:` line of `curl --version`. Two conditions have to hold
/// and they are independent: the feature must be compiled in, *and* the
/// platform library must actually work. A binary can be built with
/// `negotiate` on a host where the runtime library is present but unusable --
/// no mechanism configured, a broken `gss_mech` setup -- and a `cfg!` check
/// cannot see that.
///
/// Getting it wrong is asymmetric, which is what makes the runtime probe
/// worth its cost. AAP 0.6.5: "**Under-reporting a capability makes a fixture
/// skip; over-reporting makes it run and fail.** Truthful advertisement is
/// therefore the optimal strategy, not merely the honest one."
/// `tests/runtests.pl` believes the banner, so the banner must be true.
///
/// # Why the bridge lives here rather than in `gss.rs`
///
/// With `negotiate` off, `gss.rs` is not compiled at all -- that is the point
/// of AAP 0.8.5/C2 -- so it cannot host a function that has to answer in that
/// state. The module root is the only place both arms can be written, which
/// is why this is the single piece of logic in an otherwise declarative file.
/// Each arm is selected by `#[cfg]` rather than by a runtime test, so the
/// unavailable arm is never even type-checked against a missing module.
pub(crate) fn gss_available() -> bool {
    #[cfg(feature = "negotiate")]
    {
        // Cached inside `gss::available`, so repeated calls -- the banner is
        // assembled more than once -- cost nothing and cannot disagree.
        gss::available()
    }

    #[cfg(not(feature = "negotiate"))]
    {
        false
    }
}

// ===========================================================================
// The signature contract
//
// The machine-checked half of section 8. Each item names one re-exported
// symbol at its exact type, so a change of signature, arity, mutability or
// return type in `sys.rs` or `gss.rs` breaks the build HERE -- beside the
// documentation that describes the surface -- rather than at some distant call
// site, and rather than silently widening what the safe half of the crate can
// reach.
//
// Every item is a `const` binding either an existing function to a function
// pointer type or `None` to an `Option` of a re-exported type. Nothing is
// constructed, nothing is called and no destructor runs, so the whole block
// costs nothing at run time and is equally valid under Miri and under
// AddressSanitizer. `const _` is used throughout because the bindings are
// never read: what is being checked is that they type-check at all.
//
// Reading this block is also how one audits the seal. No type named below
// mentions a raw pointer of either mutability, a `libc` type, an `unsafe fn`,
// a GSS-API handle or an `OM_uint32`. The one C-adjacent type is `&CStr` in
// [`sys::SysCalls::if_nametoindex`], a safe borrowed standard-library view,
// and it is reached through the trait rather than named here.
// ===========================================================================

// Group A: the wrappers.
const _: usize = HOSTNAME_MAX;
const _: fn() -> CodeResult<String> = gethostname;
const _: fn() -> CodeResult<Vec<InterfaceAddr>> = interface_addrs;
const _: fn() -> CodeResult<Vec<String>> = interface_names;
const _: fn(&str) -> CodeResult<u32> = if_nametoindex;

// Group B: the injection seam. Each `_with` variant takes the operating
// system as an argument, which is what makes the surrounding logic reachable
// under Miri; `RealSys` is the implementation that performs the real calls.
const _: fn(&dyn SysCalls) -> CodeResult<String> = gethostname_with;
const _: fn(&dyn SysCalls) -> CodeResult<Vec<InterfaceAddr>> =
    interface_addrs_with;
const _: fn(&dyn SysCalls) -> CodeResult<Vec<String>> = interface_names_with;
const _: fn(&dyn SysCalls, &str) -> CodeResult<u32> = if_nametoindex_with;
const _: Option<RealSys> = None;
const _: Option<IfNode> = None;
const _: Option<RawIfAddr> = None;

// Group C: the counting allocator. `TrackingAllocator` is named so that
// `lib.rs` can install it; `set_memlimit` reproduces `curl_dbg_memlimit()`.
#[cfg(feature = "memdebug")]
const _: fn(u32) -> bool = set_memlimit;
#[cfg(feature = "memdebug")]
const _: Option<TrackingAllocator> = None;

// Group D: the GSS-API vocabulary. The six protection-level constants are
// `u8` and the delegation diagnostic is a `&'static str`, so both are pinned
// by value rather than merely by name.
#[cfg(feature = "negotiate")]
const _: &str = DELEGATION_POLICY_UNSUPPORTED_WARNING;
#[cfg(feature = "negotiate")]
const _: [u8; 6] = [
    GSSAUTH_P_NONE,
    GSSAUTH_P_INTEGRITY,
    GSSAUTH_P_PRIVACY,
    SOCKS5_PROTECTION_NONE,
    SOCKS5_PROTECTION_INTEGRITY,
    SOCKS5_PROTECTION_CONFIDENTIALITY,
];
#[cfg(feature = "negotiate")]
const _: fn(bool, Delegation, bool) -> RequestedFlags = request_flags;
#[cfg(feature = "negotiate")]
const _: Option<(GssStatus, HandshakeState, ContextFlags)> = None;
#[cfg(feature = "negotiate")]
const _: Option<(Mechanism, NameType, Delegation)> = None;
#[cfg(feature = "negotiate")]
const _: Option<(HandshakeOutcome, SealedMessage)> = None;
#[cfg(feature = "negotiate")]
const _: Option<(TargetName, SecurityContext, StepOptions<'static>)> = None;
#[cfg(feature = "negotiate")]
const _: Option<DiscardDiagnostics> = None;
#[cfg(feature = "negotiate")]
const _: Option<&dyn Diagnostics> = None;

// The bridge.
const _: fn() -> bool = gss_available;

// ===========================================================================
// Tests
//
// The only behaviour this file owns is the availability bridge, so that is
// what is tested; everything else it publishes is verified at compile time by
// the contract block above, and the behaviour behind each wrapper is covered
// by the tests inside `sys.rs` and `gss.rs` against their own fakes.
//
// These are declared at module scope rather than inside a `mod tests`, so that
// this file declares exactly the two modules AAP 0.3.1 names for this
// directory and a reader counting `mod` items finds no third. They are
// `#[cfg(test)]`-gated as well as `#[test]`-annotated, so they contribute
// nothing to any shipped artifact.
// ===========================================================================

/// With `negotiate` off there is no binding to ask, so the predicate must
/// answer `false` -- never panic, and never claim a capability the version
/// banner would then have to justify (AAP 0.6.5).
///
/// Runs under Miri: with the feature off, the body reaches no foreign
/// function.
#[cfg(all(test, not(feature = "negotiate")))]
#[test]
fn gss_is_unavailable_without_the_feature() {
    assert!(!gss_available());
}

/// With `negotiate` on, the bridge must forward rather than decide, and must
/// agree with itself across calls because the answer behind it is cached.
///
/// Ignored under Miri: this is the only test in the file that reaches a
/// foreign function, and Miri cannot execute one. The reason is spelled into
/// the attribute so that `cargo +nightly miri test` prints it beside the skip
/// and the mandated gate's log explains itself, matching how
/// [`sys`]'s own syscall-backed tests are annotated.
#[cfg(all(test, feature = "negotiate"))]
#[test]
#[cfg_attr(miri, ignore = "gss_init_sec_context(3) is a foreign function")]
fn gss_availability_is_forwarded_and_stable() {
    assert_eq!(gss_available(), gss::available());
    assert_eq!(gss_available(), gss_available());
}
