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
//! # Why this directory exists
//!
//! Every other module in this crate is safe Rust. A small number of operations
//! have no safe expression at all; this directory is where they are confined,
//! small enough to audit by reading, holding the residue and nothing else.
//!
//! # The single-exemption invariant
//!
//! The crate root denies the `unsafe_code` lint, and exactly one item in the
//! whole crate relaxes it: the `mod ffi` declaration in
//! `curl-rs-lib/src/lib.rs`. A lint level attached to a `mod foo;` *item*
//! propagates into that module's contents even when the body lives in a
//! separate file, so this file and both of its children are already covered by
//! that one relaxation and **must not restate it**. A second relaxation
//! anywhere under this directory would defeat the gate that polices the
//! invariant, which greps `curl-rs-lib/src` for the relaxation and requires
//! exactly one hit, in `lib.rs`. The token is therefore deliberately absent
//! from this file, including from its prose.
//!
//! Why the root uses `deny` rather than `forbid`, and what that choice leaves
//! to the gate, is recorded in `lib.rs` beside the attribute itself. It belongs
//! there and not here for a practical reason: if `error[E0453]` ever appears,
//! **the fix belongs in `lib.rs`**. Adding a lint attribute here instead would
//! create exactly the second exemption described above.
//!
//! # Every raw call is justified in place
//!
//! Each `unsafe` block in `sys.rs` and `gss.rs` is preceded by a `// SAFETY:`
//! comment block naming the precondition being upheld and why it holds at that
//! site. The greps that police that convention are recorded in `lib.rs`. The
//! one specific to this file is that **this** file performs no raw call of its
//! own; the word appears in the prose above only because the arrangement has to
//! be explained, so the check strips comment lines before looking:
//!
//! ```sh
//! grep -vE '^\s*//' curl-rs-lib/src/ffi/mod.rs | grep -c 'unsafe'   # 0
//! ```
//!
//! # The socket2-first rule
//!
//! Nothing is added to this directory until `socket2` has been *proven*
//! unable to express it. Raw `setsockopt`, `getsockopt` and `fcntl` calls are
//! absorbed by it, and what genuinely remains is a hostname query and a small
//! number of platform calls. `socket2` is pinned at `=0.6.5` with its `all`
//! feature enabled, which is what makes the platform socket options curl sets
//! reachable without a raw call, and the re-export surface below is
//! deliberately that small. `lib/curlx/nonblock.c` is the canonical example of
//! something that does **not** belong here: it becomes
//! `socket2::Socket::set_nonblocking` in `conn/socket.rs`.
//!
//! # What this directory supersedes, by path
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
//! Only the decision-free half of `lib/if2ip.c` lands here; `Curl_if2ip`'s
//! verdict logic is pure computation and belongs in `dns/if2ip.rs`.
//!
//! Two configuration mechanisms disappear rather than move.
//! `GETHOSTNAME_TYPE_ARG2` (`lib/curl_setup.h:649-655`) selects the second
//! parameter's type per platform; a Rust slice carries its own length, so the
//! shim has no counterpart. `USE_SPNEGO` and `USE_KERBEROS5` are each defined
//! at a single point (`lib/curl_setup.h:752-762`) from
//! `!CURL_DISABLE_*_AUTH && (HAVE_GSSAPI || USE_WINDOWS_SSPI)`; that single
//! point is now the one `negotiate` Cargo feature.
//!
//! # Not to be confused with `curl-rs-ffi/src/ffi/`
//!
//! Two directories in this workspace are called `ffi`, and each has a distinct
//! job: `curl-rs-ffi/src/ffi/` is to hold the public C ABI, and this one holds
//! operating-system integration.
//!
//! * `curl-rs-ffi/src/ffi/` is to export 100 symbols, checked by `nm` against
//!   `lib/libcurl.def`, every one of them deliberately visible to the linker.
//!   Neither that directory nor that check exists yet, so the 100 is the
//!   contract it owes rather than a count of anything present.
//! * **This** directory exports nothing to the linker at all. Nothing here is
//!   given C linkage or an unmangled external symbol name, and nothing here is
//!   `pub`, so no item can leave the crate, let alone reach a `nm` listing. A
//!   stray external symbol here would corrupt that parity check, which is why
//!   the distinction is written down rather than assumed.
//!
//! # Platform scope
//!
//! The four mandated targets are `x86_64-unknown-linux-gnu`,
//! `aarch64-unknown-linux-gnu`, `x86_64-apple-darwin` and
//! `aarch64-apple-darwin`: all 64-bit, all Unix. Divergence between them is
//! expressed with `#[cfg(target_os = ...)]`, never with a Cargo feature -- a
//! feature is a capability the user chooses, whereas a platform is a fact about
//! the build. Windows, AmigaOS, OS/400, VMS and 32-bit targets are out of
//! scope, so no path for them appears here and none may be added "for
//! completeness".
//!
//! Cargo features do appear, for the two *capabilities* this directory carries:
//! `negotiate` and `memdebug`, both default-off. There is no `tls` feature
//! anywhere in this workspace and none may be introduced: TLS is unconditional,
//! because certificate validation is on by default and an off-switch would
//! permit a build with no TLS at all.
//!
//! # How to read the re-export surface below
//!
//! Both children are declared `pub(crate)`, so every item they publish is
//! already reachable crate-wide by its full path. The re-exports are
//! therefore **not** an access barrier -- the barrier is that nothing in this
//! directory is `pub`, so nothing escapes the crate. What the list gives is a
//! canonical short path and an audit checklist that can be read in one
//! sitting: every capability the safe half of the crate reaches for is named
//! once, explicitly, with no glob anywhere in sight.
//!
//! The seal it records is that no item reachable from outside this directory
//! exposes a raw pointer of either mutability, a `libc` type, an `unsafe fn`,
//! a GSS-API handle or an `OM_uint32`. Where operating-system state must
//! outlive a call it is wrapped in an owning type whose `Drop` performs the
//! cleanup, and the owning type is what travels. One standard-library
//! C-string view (`&CStr`) does appear, in [`sys::SysCalls::if_nametoindex`];
//! it is a safe borrowed type rather than a `libc` type or a pointer, and it
//! is named here so that the audit is complete rather than merely favourable.
//!
//! The checklist is not left to prose. The signature-contract block at the
//! foot of this file records every re-exported item at its exact type, so
//! drift in a child module breaks the build *here*, beside the documentation
//! that describes the surface -- and so that adding a re-export without
//! recording it is reported rather than overlooked.

// `dead_code` is NOT allowed for this module as a whole. Every item below that
// has no consumer yet carries its own `#[allow(dead_code)]`, written at the
// item, so the suppression reads as an inventory rather than a blanket: each
// one is load-bearing, deleting any one of them restores a warning, and an
// item added later with no consumer is still reported. Each is removed when
// its consumer lands. A module- or crate-scoped `#![allow(dead_code)]` would
// instead silence the NEXT item somebody adds, which hides incomplete
// scaffolding rather than recording it; the rule and the executable gate that
// enforces it across the workspace live in `curl-rs-lib/src/lib.rs`
// (`mod source_policy`).
//
// Nearly every consumer of these wrappers lives in a module this crate has
// yet to grow -- `dns/if2ip.rs` for the interface snapshot,
// `protocols/mod.rs` and `url/` for the zone-id lookup, `version.rs` for the
// availability predicate, `lib.rs` for the optional allocator, and
// `auth/negotiate.rs` for the SPNEGO half of the GSS-API surface, which needs
// an HTTP exchange to reach. `proxy/socks_gss.rs` is the one that has LANDED:
// in a `negotiate` build it drives the RFC 1961 sub-negotiation through `gss`,
// `SecurityContext`, `ContextFlags` and `Diagnostics`, so that part of the
// surface has a consumer today. Until the others land the remaining wrappers
// are legitimately unreferenced and the zero-warnings gate would otherwise
// fail on code that is correct. Without those per-item allowances a
// `negotiate` build reports scores of `dead_code` diagnostics, nearly all of
// them in `gss.rs`.
//
// A lint level on a module root propagates into the modules declared inside
// it, which is exactly why none is set here: one attribute at this root
// would silence `sys.rs` and `gss.rs` wholesale. Each of those files states
// its own position and carries its own per-item allowances.
//
// No level for the `unsafe_code` lint is set here, at any level, by design:
// see section 2 above.

// The imports this file needs, and the reason it needs them: the signature
// contract at the foot of the file spells out every wrapper's return type, and
// those types are a `CURLcode` result for the wrappers whose failure is a
// curl-level condition, or an `io::Result` for the descriptor primitives whose
// caller inspects the underlying error the way C inspects `ferror`. ONE
// descriptor spelling appears, `BorrowedFd`, for every wrapper that takes a
// descriptor at all -- the guard-returning ones and the single-call ones alike.
// `RawFd` is deliberately absent: see the audit block near the foot of this
// file for why the single-call wrappers no longer take one either.
use std::io;
use std::os::fd::BorrowedFd;

use crate::error::CodeResult;

// The two implementation files -- and there are exactly two
//
// The directory is `{mod,sys,gss}.rs`. No third module is declared and no
// subdirectory exists: the counting allocator is a module inside `sys.rs`
// rather than a `memdebug.rs`, the interface and hostname wrappers are both
// `sys.rs`, and non-blocking sockets are not residue at all -- `socket2`
// expresses them, per the rule above.
//
// Unit tests are `#[cfg(test)] mod tests` inside each file, so no `tests`
// module is declared here either.

/// Platform calls with no safe expression, behind safe wrappers.
///
/// Supersedes `lib/curl_gethostname.c`, the `HAVE_GETIFADDRS` body of
/// `lib/if2ip.c`, the `if_nametoindex` call at `lib/url.c:1615` and --
/// under the `memdebug` feature -- `lib/memdebug.c`.
pub(crate) mod sys;

/// The GSS-API binding used by Negotiate, SPNEGO and Kerberos.
///
/// Feature-gated and **default-off**, which is what reconciles Negotiate with
/// "no C TLS linkage at any configuration": GSS-API is an authentication
/// mechanism rather than a TLS library, and confining it to a non-default
/// feature means the default build links no C security library at all. With the
/// feature off this file contributes nothing whatsoever -- no item, no
/// `#[link]` directive, no linker input and no symbol -- which is a property
/// the default build is checked for rather than credited with.
#[cfg(feature = "negotiate")]
pub(crate) mod gss;

// The re-export surface -- group A: the wrappers themselves
//
// Eight entry points and the owned values they return -- the hostname query
// and the small number of platform calls that are the whole of the residue.
// The list is meant to stay this short.
//
// The membership test is AAP 0.6.9's own: anything `socket2` absorbs -- socket
// options, non-blocking flags, `getsockname`, `getpeername` -- is deliberately
// absent, and what remains is what neither `socket2` nor `std` covers. Four of
// the eight exist because the capability each wraps traced back to a missing
// platform primitive rather than to a defect at the call site:
//
//   suppress_echo  terminal echo control      F15 -- `terminal.rs` hard-coded
//                  (`tcgetattr`/`tcsetattr`)         `echo_disabled = false`
//   localtime      `localtime_r`              F16 -- `util.rs` returned `None`
//                                                    unconditionally, so
//                                                    `--trace-time` rendered
//                                                    midnight
//   set_xattr      `fsetxattr`                F17 -- `xattr.rs` discarded its
//                                                    arguments and returned Ok
//   effective_uid  `geteuid`                  F21 -- `keylog.rs` could not
//                                                    check the owner of a
//                                                    pre-existing key log
//   regular_file_  `lseek` + `fstat`          F23 -- `formparse.rs` could not
//     extent                                        tell a regular standard
//     / read_fd     `read`                           input from a pipe, so it
//     / seek_fd     `lseek`                          buffered every one of them
//
// The last three arrived together because they are one capability: deciding
// that standard input is a regular file is useless without also being able to
// read and reposition that same descriptor, and reading it through
// `io::Stdin` instead would leave a user-space buffer holding bytes from
// before a seek. C has no such hazard -- `fseek` on a `FILE *` discards its
// own buffer -- so the three are kept together to avoid inventing one.
//
// `O_NOFOLLOW` and `O_CLOEXEC` travel with them, and they are the one pair here
// that is not a call. They are `libc` integers, evaluated at compile time, and
// they are re-exported from this directory for the single reason that this
// directory is the only place in `curl-rs-lib` that names `libc` at all --
// measured, not assumed: every `libc::` token in the crate is under
// `src/ffi/`. `tls/keylog.rs` needs `O_NOFOLLOW` to refuse a symlinked
// `SSLKEYLOGFILE` (F21) and `std` exposes no equivalent, so the alternative was
// either a hard-coded number that means something different on macOS than on
// Linux, or a `libc` dependency in the TLS module. Both are worse.
//
// No lint suppression is needed on any of the four groups, even though the
// modules that will consume them do not exist yet: the signature contract at
// the foot of the file records every one of these items, which both pins its
// type and keeps the import list honest. Add a re-export without recording it
// there and the unused import is reported -- which is the intended outcome,
// not an obstacle.

pub(crate) use sys::{
    effective_uid, gethostname, if_nametoindex, interface_addrs,
    interface_names, read_fd, regular_file_extent, seek_fd, InterfaceAddr,
    HOSTNAME_MAX, O_CLOEXEC, O_NOFOLLOW,
};

// The re-export surface -- group B: the injection seam
//
// Dependency injection, applied to the operating system itself, and a hard
// requirement rather than a preference: `cargo +nightly miri test
// -p curl-rs-lib` is a required gate and Miri cannot execute a foreign
// function, so each wrapper above is a thin call into a `_with` variant that
// takes the operating system as an argument. Substituting a pure-Rust fake
// covers every branch of the surrounding logic under Miri, and covers the
// branches a real host cannot be made to take -- a NULL `ifa_addr`, an address
// family this layer does not represent, a `gethostname` that truncates without
// terminating.
//
// The seam is re-exported at `pub(crate)` rather than being hidden behind
// `#[cfg(test)]`, because the modules that consume these wrappers need it for
// their own tests, not only for tests written inside this directory. It is
// not widened beyond the crate.

pub(crate) use sys::{
    effective_uid_with, gethostname_with, if_nametoindex_with,
    interface_addrs_with, interface_names_with, read_fd_with,
    regular_file_extent_with, seek_fd_with, IfNode, RawIfAddr, RealSys,
    SysCalls,
};

// The re-export surface -- group C: the counting allocator, feature
// `memdebug`, DEFAULT OFF
//
// Reproduces the allocation log of `lib/memdebug.c` in the format
// `tests/memanalyzer.pm` parses. Off by default because the harness wraps its
// entire memory check in `if($feature{"TrackMemory"})` and derives that
// feature solely from a `Debug` token in the version banner, so a binary that
// does not advertise `Debug` has all leak and allocation-cap checking skipped.
// The feature exists so the trade can be reversed without a redesign.
//
// WHERE THE ALLOCATOR IS INSTALLED, decided once and recorded here because it
// must happen in exactly one place in the crate: `lib.rs` declares the
// `#[global_allocator]` static, and this file only makes the type nameable.
// `sys.rs` documents the same division and spells the wiring out. This file
// declares no allocator of its own, and a second declaration anywhere in the
// crate is a compile error rather than a subtle bug -- which is the reason to
// state the choice rather than leave it to be inferred.
//
// `init_from_env` is the `CURL_MEMLIMIT` entry point, and it is re-exported
// rather than kept private because the cap otherwise has no production
// consumer at all. It reproduces
// `src/tool_main.c:117-125`, the only place outside the C test programs that
// calls `curl_dbg_memlimit()`. The allocator also arms itself from the same
// variable on first use, so the cap works today; this hook exists so that the
// command-line tool's `main` can arm it at the same point in start-up the C
// does, which is what closes the two-allocation offset documented on
// `sys::memdebug::ensure_limit_armed`.
//
// DELIBERATELY NOT re-exported: `sys::memdebug::Record` and the five record
// builders `malloc_record`, `calloc_record`, `realloc_record`, `free_record`
// and `limit_record`. They are how the allocator formats its own output; no
// module outside this directory has any use for them, and re-exporting them
// would grow the audit list without adding a capability.

#[cfg(feature = "memdebug")]
pub(crate) use sys::memdebug::{
    init_from_env, set_memlimit, TrackingAllocator,
};

// The re-export surface -- group E: the platform facade the command-line
// tool consumes
//
// These seven functions and one guard type are the only items in this directory
// re-exported at `pub` rather than `pub(crate)`, and the reason is structural
// rather than a relaxation. `curl-rs` carries `#![forbid(unsafe_code)]` and
// has no `mod ffi` of its own, and AAP 0.8.5 conflict C3 reserves
// `curl-rs-lib/src/ffi/` for genuine operating-system residue -- so the five
// capabilities the tool needs (suppressing terminal echo while a password is
// typed, reading the terminal width, writing an extended attribute, rendering
// local and locale-dependent time, and wiping a credential out of the process
// argument vector) can only reach it from here.
//
// `scrub_argument` is the newest of them and the one whose absence was a
// security defect rather than a missing convenience: `cleanarg`
// (`src/tool_getparam.c:625-637`) is what keeps a `-u bob:pw` out of `ps` for
// the life of the transfer, `HAVE_WRITABLE_ARGV` is defined on all four
// mandated targets, and no safe crate can reach the loader's argument vector.
// `crate::lib` re-exports exactly this list at the crate root, and nothing
// else from this directory crosses the crate boundary.
//
// What this does NOT widen, stated because the distinction is the whole
// point: `mod ffi` remains `pub(crate)`, so no consumer can name a path into
// the `unsafe` island; the seam traits, `RealSys`, `SavedTerminal` and every
// `_with` variant stay `pub(crate)`; and each item below is a safe function
// over safe standard-library types. The `unsafe` blocks themselves are
// reachable from outside this crate only through these seven names, each of
// which is total and each of which owns the raw pointer it forms for the
// duration of a single call.

pub use sys::{
    disable_echo, local_utc_offset_secs, scrub_argument, set_file_xattr,
    set_locale_from_environment, strftime_gmt, terminal_columns, EchoGuard,
};

// The re-export surface -- group F: the injection seams behind group E
//
// One trait per concern rather than more methods on `SysCalls`, so that a
// module faking terminal handling is not made to fake `getifaddrs` as well.
// `pub(crate)` for the same reason group B is: the modules that consume the
// wrappers need these for their own tests, and nothing outside the crate does.

pub(crate) use sys::{
    disable_echo_with, local_utc_offset_secs_with, scrub_argument_with,
    set_file_xattr_with, set_locale_from_environment_with, strftime_gmt_with,
    terminal_columns_with, ArgvCalls, RealArgv, SavedTerminal, TerminalCalls,
    TimeCalls, XattrCalls,
};

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
// The three `SOCKS5_PROTECTION_*` constants are the RFC 1961 wire values a
// SOCKS5 GSS-API negotiation carries, computed by
// `ContextFlags::socks5_protection_level` from `lib/socks_gssapi.c:330-335`.
//
// DELIBERATELY NOT re-exported, and each absence is a decision:
//
//   * `gss::available`. Its total counterpart `gss_available` below answers the
//     same question in every feature state, and having one blessed entry point
//     is what stops a caller from reaching for a predicate that does not exist
//     in the default build.
//   * `GSSAUTH_P_NONE`, `GSSAUTH_P_INTEGRITY` and `GSSAUTH_P_PRIVACY`. These
//     were re-exported and anchored here, and a comment above this list
//     described them as "the SOCKS5 protection levels curl negotiates" -- which
//     they are not. They are the RFC 4752 SASL security-layer bitmask from
//     `lib/curl_gssapi.h:65-67`, a different encoding for a different protocol
//     (1/2/4, not 0/1/2), and the whole C tree reads them only in
//     `lib/vauth/krb5_gssapi.c`, on the SASL path that serves SMTP, IMAP and
//     POP3 -- protocols AAP section 0.2.2 excludes. No module outside `gss.rs`
//     has any use for them, so re-exporting them widened the audit list without
//     adding a capability, and the anchor below created the appearance of a
//     consumer where there was none. They stay in `gss.rs`, with a per-item
//     allowance and the reason written beside each one, and their values stay
//     pinned by `protection_level_constants_match_the_c_header` there.

#[cfg(feature = "negotiate")]
pub(crate) use gss::{
    request_flags, ContextFlags, Delegation, Diagnostics, DiscardDiagnostics,
    GssStatus, HandshakeOutcome, HandshakeState, Mechanism, NameType,
    RequestedFlags, SealedMessage, SecurityContext, StepOptions, TargetName,
    DELEGATION_POLICY_UNSUPPORTED_WARNING, SOCKS5_PROTECTION_CONFIDENTIALITY,
    SOCKS5_PROTECTION_INTEGRITY, SOCKS5_PROTECTION_NONE,
};

// The one function in this file

/// Whether GSS-API is genuinely usable in this process, right now.
///
/// This is the crate's only sanctioned answer to "is Negotiate available",
/// and it is deliberately *total*: it compiles and answers in every feature
/// state, returns a `bool`, never panics, never propagates an error and
/// performs no I/O.
///
/// # Why a compile-time check is not enough
///
/// This is the predicate `version.rs` consults before it puts `GSS-API`,
/// `SPNEGO` or `Kerberos` into the `Features:` line of `curl --version`, and
/// before the `curlinfo` diagnostic prints its `negotiate-auth: ` row. Two
/// conditions have to hold and they are independent -- the feature must be
/// compiled in, *and* the platform library must actually work. A binary can
/// be built with `negotiate` on a host where the runtime library is present
/// but unusable -- no mechanism configured, a broken `gss_mech` setup -- and
/// a `cfg!` check cannot see that.
///
/// Both consumers are reached through `version.rs` rather than by calling this
/// directly, because it is `pub(crate)`: `version::gss_present` wraps it as the
/// three rows' `present` predicate, which `Feature::is_present` folds in per
/// `lib/version.c:684-688`, and `version::negotiate_usable` pairs it with the
/// compile-time half for the diagnostic.
///
/// Getting it wrong is asymmetric, which is what makes the runtime probe worth
/// its cost: under-reporting a capability makes a fixture skip, whereas
/// over-reporting makes it run and fail. `tests/runtests.pl` believes the
/// banner, so the banner must be true.
///
/// # Why the bridge lives here rather than in `gss.rs`
///
/// With `negotiate` off, `gss.rs` is not compiled at all -- that is the point
/// of the feature -- so it cannot host a function that has to answer in that
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

// The signature contract
//
// The machine-checked half of the re-export surface. Each item names one
// re-exported symbol at its exact type, so a change of signature, arity,
// mutability or return type in `sys.rs` or `gss.rs` breaks the build HERE --
// beside the documentation that describes the surface -- rather than at some
// distant call site, and rather than silently widening what the safe half of
// the crate can reach.
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
// a GSS-API handle or an `OM_uint32`. Four types are C-adjacent and each is
// accounted for:
//
//   * `&CStr` in [`sys::SysCalls::if_nametoindex`] and
//     [`sys::XattrCalls::fsetxattr`] -- a safe borrowed standard-library view,
//     reached through the trait rather than named here.
//   * `BorrowedFd` -- it appears below because a descriptor is the one thing
//     the terminal, extended-attribute and descriptor calls must be handed. It
//     is now the ONLY descriptor spelling in this file, for two distinct
//     reasons that happen to point the same way. Where a GUARD is returned it
//     carries the lifetime of the open file, so the guard from
//     [`sys::disable_echo`] cannot outlive the descriptor it restores. Where
//     a single call borrows a descriptor -- `fd_offset`,
//     `fd_regular_size`, `read_fd`, `seek_fd`, `fsetxattr` -- it is what makes
//     "the caller still owns this, open, for the duration of the call" a
//     checked fact rather than a convention.
//
//     A bare `RawFd` used to appear on the four single-call descriptor
//     wrappers, defended on the grounds that it is a standard-library alias
//     for `i32` rather than a `libc` type. True, and beside the point: an
//     integer carries no lifetime, so it cannot distinguish a live descriptor
//     from a closed one whose number the kernel has since reissued to an
//     unrelated file. The alias made the type look safe while leaving exactly
//     the hazard a descriptor type exists to remove, and the caller was
//     already holding a `BorrowedFd` it had to discard to make the call.
//   * `SavedTerminal` -- opaque by construction. It wraps an
//     `Option<libc::termios>` in a private field, so the foreign struct is
//     unnameable from outside `sys`, and the only way to inspect it is the
//     `bool`-valued `is_restorable`. The `Option` is not decoration: it is how
//     "`tcgetattr` failed, so there is nothing to put back" is represented,
//     which is what keeps a zeroed attribute set from ever reaching a real
//     terminal.

// Group A: the wrappers.
const _: usize = HOSTNAME_MAX;
// `i32` and not `libc::c_int`: `custom_flags` takes an `i32`, so that is the
// type the flags have to be, and pinning it here is what stops a platform whose
// `c_int` is not `i32` from compiling silently.
const _: i32 = O_NOFOLLOW;
const _: i32 = O_CLOEXEC;
const _: fn() -> CodeResult<String> = gethostname;
const _: fn() -> CodeResult<Vec<InterfaceAddr>> = interface_addrs;
// Interface names and zone identifiers are BYTES, not `String`/`&str`, and
// these two lines are what keeps them that way. Neither kernel promises UTF-8
// in an interface name and `lib/if2ip.c:113` compares `ifa_name` with
// `curl_strequal`, so a lossy decode anywhere on this path would permanently
// prevent a non-UTF-8 name from matching `--interface` or an IPv6 `%<zoneid>`.
// Widening either type back to a string breaks the build here.
const _: fn() -> CodeResult<Vec<Vec<u8>>> = interface_names;
const _: fn(&[u8]) -> CodeResult<u32> = if_nametoindex;
const _: fn() -> u32 = effective_uid;
const _: fn(BorrowedFd<'_>) -> Option<(i64, i64)> = regular_file_extent;
const _: fn(BorrowedFd<'_>, &mut [u8]) -> io::Result<usize> = read_fd;
const _: fn(BorrowedFd<'_>, i64) -> io::Result<()> = seek_fd;

// Group B: the injection seam. Each `_with` variant takes the operating
// system as an argument, which is what makes the surrounding logic reachable
// under Miri; `RealSys` is the implementation that performs the real calls.
const _: fn(&dyn SysCalls) -> CodeResult<String> = gethostname_with;
const _: fn(&dyn SysCalls) -> CodeResult<Vec<InterfaceAddr>> =
    interface_addrs_with;
const _: fn(&dyn SysCalls) -> CodeResult<Vec<Vec<u8>>> = interface_names_with;
const _: fn(&dyn SysCalls, &[u8]) -> CodeResult<u32> = if_nametoindex_with;
const _: fn(&dyn SysCalls) -> u32 = effective_uid_with;
const _: fn(&dyn SysCalls, BorrowedFd<'_>) -> Option<(i64, i64)> =
    regular_file_extent_with;
const _: fn(&dyn SysCalls, BorrowedFd<'_>, &mut [u8]) -> io::Result<usize> =
    read_fd_with;
const _: fn(&dyn SysCalls, BorrowedFd<'_>, i64) -> io::Result<()> =
    seek_fd_with;
const _: Option<RealSys> = None;
const _: Option<IfNode> = None;
const _: Option<RawIfAddr> = None;

// Group E: the platform facade. Written with explicit `for<'a>` binders where
// a lifetime is shared between an argument and the return type, because the
// elided `'_` inside a function-pointer type introduces a *separate* fresh
// lifetime for each position and would therefore assert something weaker than
// intended -- namely that the guard's lifetime is unrelated to the
// descriptor's, which is the one property this signature exists to pin.
const _: for<'a> fn(BorrowedFd<'a>) -> EchoGuard<'a> = disable_echo;
const _: fn() -> Option<u32> = terminal_columns;
const _: fn(BorrowedFd<'_>, &[u8], &[u8]) -> io::Result<()> = set_file_xattr;
const _: fn(i64) -> Option<i32> = local_utc_offset_secs;
const _: fn(&[u8], i64, &mut [u8]) -> Option<usize> = strftime_gmt;
const _: fn() -> bool = set_locale_from_environment;
// The scrubber takes BYTES and returns a count, and both halves are pinned
// here. A credential is arbitrary bytes on the four mandated targets, so a
// `&str` parameter would make an argument this must wipe unrepresentable; the
// `usize` is how many elements were overwritten, which is what makes "the
// vector was not writable" reportable as `0` rather than indistinguishable
// from success.
const _: fn(&[u8]) -> usize = scrub_argument;

// Group F: their injection seams.
const _: for<'a> fn(&'a dyn TerminalCalls, BorrowedFd<'a>) -> EchoGuard<'a> =
    disable_echo_with;
const _: fn(&dyn TerminalCalls) -> Option<u32> = terminal_columns_with;
const _: fn(&dyn XattrCalls, BorrowedFd<'_>, &[u8], &[u8]) -> io::Result<()> =
    set_file_xattr_with;
const _: fn(&dyn TimeCalls, i64) -> Option<i32> = local_utc_offset_secs_with;
const _: fn(&dyn TimeCalls, &[u8], i64, &mut [u8]) -> Option<usize> =
    strftime_gmt_with;
const _: fn(&dyn TimeCalls) -> bool = set_locale_from_environment_with;
const _: fn(&dyn ArgvCalls, &[u8]) -> usize = scrub_argument_with;
const _: Option<SavedTerminal> = None;
const _: Option<RealArgv> = None;

// Group C: the counting allocator. `TrackingAllocator` is named so that
// `lib.rs` can install it; `set_memlimit` reproduces `curl_dbg_memlimit()`.
#[cfg(feature = "memdebug")]
const _: fn(u32) -> bool = set_memlimit;
#[cfg(feature = "memdebug")]
const _: fn() -> bool = init_from_env;
#[cfg(feature = "memdebug")]
const _: Option<TrackingAllocator> = None;

// Group D: the GSS-API vocabulary. The three protection-level constants are
// `u8` and the delegation diagnostic is a `&'static str`, so both are pinned
// by value rather than merely by name.
//
// WHAT AN ANCHOR IS AND IS NOT. Naming a constant in an anonymous `const` pins
// its type and its value at compile time, which is this block's whole purpose,
// and it is genuinely useful for an item that has a consumer elsewhere: it makes
// a change of type break the build HERE, beside the documentation, rather than
// at a distant call site. What it is NOT is a "use" for the `dead_code` lint --
// measured, the three `GSSAUTH_P_*` constants warned as unreferenced while
// anchored here. An anchor is therefore never the answer to an unreferenced
// item; either the item has a consumer, or it carries a justified per-item
// allowance where it is declared. Every constant named below has a real
// consumer inside `gss.rs`.
#[cfg(feature = "negotiate")]
const _: &str = DELEGATION_POLICY_UNSUPPORTED_WARNING;
#[cfg(feature = "negotiate")]
const _: [u8; 3] = [
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

// Tests
//
// The only behaviour this file owns is the availability bridge, so that is
// what is tested; everything else it publishes is verified at compile time by
// the contract block above, and the behaviour behind each wrapper is covered
// by the tests inside `sys.rs` and `gss.rs` against their own fakes.
//
// These are declared at module scope rather than inside a `mod tests`, so that
// this file declares exactly the two modules this directory has and a reader
// counting `mod` items finds no third. They are `#[cfg(test)]`-gated as well
// as `#[test]`-annotated, so they contribute nothing to any shipped artifact.

/// With `negotiate` off there is no binding to ask, so the predicate must
/// answer `false` -- never panic, and never claim a capability the version
/// banner would then have to justify.
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
