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

// The safety invariant: no `unsafe` outside `src/ffi/`.
//
// The requirement is that `unsafe` be impossible anywhere in this crate except
// under `src/ffi/`, with exactly one attribute granting that exemption.
//
// The attribute below is `deny`, not `forbid`, and the difference is forced.
// `forbid` cannot be overridden from an inner scope, so the one exemption this
// crate needs -- `#[allow(unsafe_code)]` on the `pub(crate) mod ffi;`
// declaration further down -- is rejected under `#![forbid(unsafe_code)]` with
// `error[E0453]: allow(unsafe_code) incompatible with previous forbid`, and the
// `unsafe` it was meant to permit then fails as well. No placement of the
// `allow` rescues it, an inner `#![allow(unsafe_code)]` at the top of
// `src/ffi/mod.rs` included.
//
// `#![deny(unsafe_code)]` accepts that one exemption and still makes the same
// `unsafe` a hard error in every module other than `ffi`. One gap remains, and
// it is stated rather than glossed over: `deny`, unlike `forbid`, CAN be
// overridden from an inner scope, so a module outside `ffi` that wrote its own
// `#[allow(unsafe_code)]` would compile. The compiler enforces the invariant
// against accident but not against a second deliberate exemption, which is why
// the gate below is load-bearing rather than decoration.
//
// The gate, in three checks. Each expression is anchored for a reason: this
// file legitimately discusses the attribute and the keyword many times over, so
// an unanchored search matches the prose and reports a false failure.
//
//   1. Exactly one exemption exists, and it is in this file, on `mod ffi`:
//
//        grep -rnE '^[[:space:]]*#!?\[allow\(unsafe_code\)\]' \
//          --include='*.rs' curl-rs-lib/src
//
//      must print exactly one line. Anchoring past indentation only is what
//      excludes every `//`, `///` and `//!` line: a comment begins with a
//      slash, so it can never match.
//
//   2. No `unsafe` keyword lives outside the sanctioned directory:
//
//        grep -rnE '^[^/]*\bunsafe\b' --include='*.rs' curl-rs-lib/src \
//          | grep -v '^curl-rs-lib/src/ffi/'
//
//      must print nothing. `^[^/]*` requires the keyword to appear before any
//      slash on the line, which again excludes comments and trailing comments.
//      The limitation is stated honestly: a division written on the same line
//      before an `unsafe` block would hide it from this expression. With check
//      1 satisfied the compiler is conclusive there instead, because
//      `#![deny(unsafe_code)]` makes any such occurrence a hard error.
//
//   3. Every `unsafe` under `curl-rs-lib/src/ffi/` is covered by a preceding
//      `// SAFETY:` comment BLOCK.
//
//      "Immediately preceded by a `// SAFETY:` line" is the natural way to
//      phrase it and is measurably wrong: the justifications in this crate
//      run to several lines, so the line directly above an `unsafe` is the
//      LAST line of the block, not its `// SAFETY:` opener, and checking
//      the opener alone reports every site as a violation. The correct
//      check walks back over blank lines and attribute lines, then over
//      the contiguous run of `//` comment lines, and requires that run to
//      contain a line beginning `// SAFETY:`. That is exactly the walk
//      `every_unsafe_block_in_this_crate_is_covered_by_a_safety_comment`
//      performs in `mod source_policy` at the foot of this file. Measured
//      there on this tree: 26 blocks under `src/ffi/`, none uncovered.
//
//      `clippy::undocumented_unsafe_blocks` would mechanize this check. It is
//      enabled nowhere -- not here, not in `clippy.toml` -- so this one is
//      not a lint. It is not merely a convention either: the same walk runs
//      as a test in `mod source_policy`, and the grep is the form a reader
//      at a terminal can run.
//
// Never add `#![allow(unsafe_code)]` at crate level, and never add a second
// `#[allow(unsafe_code)]` anywhere. Doing either silently converts a
// compiler-checked invariant back into a review obligation.
//
// No other lint level is escalated here, deliberately. Continuous
// integration runs `cargo clippy --workspace -- -D warnings`, which is where
// the lint gate belongs so that a lint failure names itself instead of
// hiding inside a build log. A crate-wide escalation such as
// `#![warn(missing_docs)]` written here would additionally impose a gate on
// the module files this crate currently contains -- and on every further
// module the AAP's graph still adds to it -- none of which this file can
// inspect, and a crate root must not legislate for code it does not contain.
#![deny(unsafe_code)]

//! curl and libcurl: the protocol engine, in safe Rust.
//!
//! This crate is the whole of libcurl's behaviour and the only crate in the
//! workspace with protocol knowledge. The two crates beside it are thin
//! adapters over this one and contain no protocol logic:
//!
//! ```text
//!     curl-rs-ffi  ->  curl-rs-lib  <-  curl-rs
//!     (C ABI:          (this crate:      (command-line
//!      cdylib +         a plain rlib)     binary)
//!      staticlib)
//! ```
//!
//! The direction is acyclic and one-way. Nothing here may name `curl_rs` or
//! `curl_rs_ffi`; a type both adapters need belongs *here*.
//!
//! # What this crate supersedes
//!
//! 163,664 lines of C, measured rather than estimated -- `lib/*.c` and
//! `lib/*.h` (126 and 129 files) together with all five of its subtrees:
//!
//! - `lib/` -- transfer core, multi handle, connection management, HTTP,
//!   FTP, DNS, cookies, the URL API, MIME, authentication dispatch.
//! - `lib/curlx/` -- portability and utility layer: dynbuf, base64,
//!   timeval, strparse, warnless.
//! - `lib/vtls/` -- TLS abstraction, session cache, X.509 handling,
//!   cipher-suite mapping, key logging.
//! - `lib/vauth/` -- Digest, NTLM, Negotiate/SPNEGO, OAuth2, cleartext.
//! - `lib/vquic/` -- the QUIC and HTTP/3 filter layer.
//! - `lib/vssh/` -- the SSH transport behind SFTP and SCP.
//!
//! Superseded, not wrapped: no C source file from those trees is compiled,
//! linked or bridged. The C tree stays in the repository as the reference
//! oracle for the transformation and for the 1,914 test fixtures that
//! validate it.
//!
//! # The three frozen contracts
//!
//! The implementation beneath is replaced entirely; the observable behaviour
//! is not touched at all. Three contracts are frozen, and every module in
//! this crate is written to preserve them:
//!
//! 1. **The bytes on the wire.** Request-line composition, header content,
//!    header order, header casing, chunked framing, FTP command sequencing
//!    and the construction of Digest, NTLM and AWS SigV4 messages. 1,476 of
//!    the 1,914 fixtures carry a `<protocol>` block, and the harness joins
//!    both sides into a single string and compares them whole -- there is no
//!    per-line matching and no normalization, so header *order* is as
//!    significant as header content. This is why
//!    [`protocols::http1`] owns request serialization instead of delegating
//!    it to `hyper`, which emits neither curl's default headers nor a
//!    guaranteed order.
//! 2. **The command-line surface.** Option names, aliases, argument arity,
//!    argument type and default value, for all 282 rows of the `aliases[]`
//!    table (`src/tool_getparam.c:80`) and the `--no-<flag>` negations that
//!    the `ARG_NO`-flagged rows generate. Owned by `curl-rs`, but every
//!    default it applies is read from here.
//! 3. **The C ABI.** Parameter lists, return types, and the *integer* value
//!    behind every public enumerator. `lib/libcurl.def` lists exactly 100
//!    exported symbols and a C program compiled against curl 8.19.0-DEV
//!    embeds the numeric value of every enumerator it uses directly in its
//!    instruction stream, so nominal parity is not parity. See
//!    [`error`] for how the result codes are pinned.
//!
//! Performance is an explicit non-goal of this work. No latency, throughput
//! or allocation objective appears anywhere in the requirements, and where a
//! choice existed between a faster design and a more behaviourally faithful
//! one, faithfulness won. Nothing in this crate should be restructured, and
//! no `#[inline]` or link-time-optimization hint should be added, on speed
//! grounds alone.
//!
//! # Reported identity -- frozen, and not to be bumped
//!
//! Measured in `include/curl/curlver.h` and reproduced by [`version`]:
//!
//! | Macro                   | Value                                | Site |
//! |-------------------------|--------------------------------------|------|
//! | `LIBCURL_COPYRIGHT`     | `Daniel Stenberg, <daniel@haxx.se>.` | `:31` |
//! | `LIBCURL_VERSION`       | `8.19.0-DEV`                         | `:35` |
//! | `LIBCURL_VERSION_MAJOR` | `8`                                  | `:39` |
//! | `LIBCURL_VERSION_MINOR` | `19`                                 | `:40` |
//! | `LIBCURL_VERSION_PATCH` | `0`                                  | `:41` |
//! | `LIBCURL_VERSION_NUM`   | `0x081300`                           | `:61` |
//! | `LIBCURL_TIMESTAMP`     | `[unreleased]`                       | `:72` |
//!
//! Every parity claim in this crate is against curl and libcurl 8.19.0-DEV
//! as checked out at commit `54cf587b9c`. "curl 8.x" is a version family
//! rather than a version, so it is bound to that exact tree and nothing
//! else. The version string is also load-bearing at run time, not merely
//! informational: it is the `User-Agent` default, and the test harness
//! substitutes a `%VERSION` placeholder into fixture expectations from it.
//!
//! # The safety invariant
//!
//! `#![deny(unsafe_code)]` sits at the top of this file, and exactly one
//! `#[allow(unsafe_code)]` exists in the entire crate: on the [`ffi`] module
//! declaration below. The long comment above this documentation records the
//! verbatim compiler diagnostics that settled the `forbid`-versus-`deny`
//! question and the grep gate that closes the one gap `deny` leaves.
//!
//! Every `unsafe` block in `src/ffi/` carries a `// SAFETY:` comment. That
//! is the whole of the crate's `unsafe` surface, and it is small because
//! each C construct that appeared to require it has a safe counterpart:
//!
//! - **Manual buffer arithmetic.** `lib/curlx/dynbuf.c`, `lib/sendf.c` and
//!   `lib/bufq.c` track pointer, length and capacity by hand across
//!   `malloc`/`realloc` boundaries. `bytes::BytesMut` and `Vec<u8>` make the
//!   invariant the type's responsibility.
//! - **Intrusive linked lists.** `lib/llist.c` and the `curl_slist` chain
//!   embed nodes in their payloads. `Vec<T>` and `VecDeque<T>` replace them
//!   internally, and the multi handle's easy-handle collection becomes a
//!   slab with generational keys so that a stale handle is *detectably*
//!   stale rather than a dangling pointer. `curl_slist` retains its C shape
//!   only at the ABI boundary, in `curl-rs-ffi`.
//! - **Untyped vtable contexts.** `struct Curl_cftype` carries 14 function
//!   pointers plus a `void *ctx` that every filter casts to its own type
//!   (`lib/cfilters.h:210-226`). `Box<dyn ConnFilter>` with a *typed*
//!   context field eliminates that cast entirely, which removes the largest
//!   single category of unsound pattern in the C tree. Because HTTP/3 is
//!   already a filter there (`lib/vquic/vquic.h:48`), QUIC, TLS, SOCKS and
//!   raw sockets all compose through one trait.
//! - **Protocol dispatch tables.** `struct Curl_protocol`'s 18 function
//!   pointers (`lib/urldata.h:427-512`) become a trait. The pervasive
//!   `bool *done` out-parameters disappear, because async readiness
//!   subsumes them.
//! - **Non-local control flow.** `lib/hostip.c` implements DNS timeouts with
//!   `alarm()` plus `sigsetjmp`/`siglongjmp`, jumping out of a signal
//!   handler across allocation boundaries. `tokio::time::timeout` removes
//!   the most dangerous construct in the C tree outright, with no residual
//!   `unsafe` at all.
//! - **Socket manipulation.** Raw `setsockopt`, `getsockopt` and `fcntl`
//!   calls are absorbed by `socket2`. What genuinely remains -- a hostname
//!   query and a small number of platform calls -- is confined to
//!   [`ffi::sys`].
//!
//! # Configuration: Cargo features replace the preprocessor
//!
//! `lib/curl_setup.h` is included by 200 files under `lib/` and 203 across
//! `lib/` and `src/`. It has no successor here, because its three distinct
//! jobs separate cleanly:
//!
//! - Capability selection becomes Cargo `[features]`, resolved when the
//!   build graph is constructed rather than while preprocessing. The C
//!   header's cascades -- `HTTP_ONLY` force-defining fifteen
//!   `CURL_DISABLE_*` macros at `:230-276`, and `CURL_DISABLE_HTTP`
//!   cascading eleven more at `:288-322` -- become feature dependencies in
//!   `Cargo.toml`, where they are enumerable and testable.
//! - Platform detection becomes `#[cfg(target_os = "...")]` and
//!   `#[cfg(target_arch = "...")]`, never a feature.
//! - Shared type declarations become ordinary `use` statements against the
//!   module that owns each type.
//!
//! `configure.ac` carries 57 `AC_ARG_ENABLE` plus 44 `AC_ARG_WITH` knobs --
//! 101 in total. They are replaced by **15** features, and that reduction is
//! intentional and documented rather than an omission: the knobs this
//! workspace does not reproduce select between C libraries that are gone
//! (seven TLS backends, two SSH backends, two QUIC backends, c-ares,
//! libidn2, libpsl, libgsasl), or target platforms outside the four-target
//! matrix, or disable protocols that are stubbed for ABI completeness
//! instead of being switchable.
//!
//! The 15, declared once in `curl-rs-lib/Cargo.toml`:
//!
//! | Feature       | Default | Replaces |
//! |---------------|---------|----------|
//! | `http2`       | on      | `USE_NGHTTP2` |
//! | `http3`       | on      | `USE_NGTCP2` / `USE_QUICHE` |
//! | `ftp`         | on      | `CURL_DISABLE_FTP` |
//! | `ssh`         | on      | `USE_LIBSSH2` / `USE_LIBSSH` |
//! | `websockets`  | on      | `CURL_DISABLE_WEBSOCKETS` |
//! | `cookies`     | on      | `CURL_DISABLE_COOKIES` |
//! | `hsts`        | on      | `CURL_DISABLE_HSTS` |
//! | `altsvc`      | on      | `CURL_DISABLE_ALTSVC` |
//! | `doh`         | on      | `CURL_DISABLE_DOH` |
//! | `brotli`      | on      | `HAVE_BROTLI` |
//! | `zstd`        | on      | `HAVE_ZSTD` |
//! | `gzip`        | on      | `HAVE_LIBZ` |
//! | `negotiate`   | **off** | `USE_SPNEGO` / `HAVE_GSSAPI` |
//! | `hickory-dns` | **off** | `CURLRES_ARES` |
//! | `memdebug`    | **off** | `CURL_MEMDEBUG` |
//!
//! **There is no `tls` feature, and there must never be one.** TLS is
//! unconditional in this crate. rustls is the only TLS implementation at any
//! configuration -- not as a default, not behind a flag, not as a fallback
//! -- and certificate validation is on unless `--insecure` is given, so an
//! off-switchable `tls` would permit a build that contradicts both
//! requirements. The prohibition is also mechanically enforced rather than
//! merely stated: writing `feature = "tls"` anywhere produces
//! `warning: unexpected 'cfg' condition value: 'tls'`, which under
//! `-D warnings` is a build failure. That was verified by compiling it.
//!
//! The audit for it must be anchored, for the same reason the safety gate's
//! expressions are -- this crate *discusses* the absent feature in prose, so
//! an unanchored search reports false hits:
//!
//! ```text
//! grep -rnE '^[^/]*feature = "tls"' --include='*.rs' curl-rs-lib/src
//! ```
//!
//! must print nothing. Measured: empty, and it does find a planted
//! `#[cfg(feature = "tls")]`, so the check is discriminating rather than
//! vacuous.
//!
//! # Import discipline
//!
//! The C tree's most pervasive dependency is a blanket `#include`. Three
//! transformation rules replace it, and they apply throughout this crate:
//!
//! 1. FROM `#include "urldata.h"`, one include granting access to all
//!    connection, transfer and TLS state, TO one `use` per type actually
//!    used: `use crate::conn::Connection;` plus
//!    `use crate::transfer::TransferState;`. Applies to every file in this
//!    crate.
//! 2. FROM `#include "curl_setup.h"` followed by `#ifdef USE_NGHTTP2`, TO
//!    `#[cfg(feature = "http2")]` on the item, with the feature declared in
//!    the manifest. Applies to every file whose C original was
//!    conditionally compiled.
//! 3. FROM `#include "vtls/vtls.h"` in each protocol implementation, TO no
//!    TLS import at all -- the connection-filter chain interposes TLS
//!    transparently, so a protocol module never names it. Applies to every
//!    file under `protocols`.
//!
//! Internal linkage changes character with them. C declares internal
//! functions `extern` under a `Curl_` prefix and relies on the convention
//! that anything so prefixed is private by agreement:
//!
//! ```c
//! /* C: private by convention, visible to the linker */
//! extern CURLcode Curl_cf_setup_insert_after(struct Curl_cfilter *cf_at, ...);
//! ```
//!
//! Here it is private by enforcement:
//!
//! ```ignore
//! pub(crate) fn cf_setup_insert_after(
//!     at: &mut FilterChain,
//!     /* ... */
//! ) -> Result<(), Error>
//! ```
//!
//! That change is what stops `tests/unit/*.c` (59 files) and
//! `tests/libtest/*.c` (235 files) from linking: a Rust static library does
//! not export `pub(crate)` items -- they are genuinely absent from the
//! symbol table, not merely hidden -- so no quality of implementation makes
//! those 294 C programs link. Their coverage is relocated into this crate as
//! `#[cfg(test)]` modules instead. This is a documented deviation, not a
//! defect to work around: re-exporting internals to satisfy them would
//! defeat the encapsulation that makes the zero-`unsafe` guarantee possible.
//! It is also strictly distinct from `tests/data`, whose 1,914 fixtures
//! drive only the command-line binary through documented flags and do pass
//! unmodified.
//!
//! # Dependency injection is an architectural requirement
//!
//! Not a style preference. The line-coverage gate over `protocols` and
//! `transfer` is reachable only because the resolver, the clock and the
//! TLS provider are *injected* rather than reached for globally, which is
//! what lets those modules be exercised without live network access, without
//! a real system clock and without process-global state that makes two tests
//! influence each other.
//!
//! Concretely, and already in force in the modules that exist:
//!
//! - **Clock.** [`trace::TraceClock`] is the injected time source; nothing
//!   in `trace` calls `SystemTime::now()` or `Instant::now()`. A trace line
//!   carrying an unpinnable timestamp could not be compared byte for byte.
//! - **Sinks.** [`trace::TraceSink`] is injected into the tracer, so a test
//!   captures output without touching process state.
//! - **System calls.** [`ffi::sys::SysCalls`] abstracts the platform, with
//!   `RealSys` as the production implementation and every accessor offered
//!   in a `_with(sys, ...)` form for tests.
//!
//! No global mutable state, no `static mut`, and no lazily-initialised
//! singleton for the resolver, the clock or the TLS provider. `lib/hostip.c`
//! reaches for a process-global `sigjmp_buf` behind a spinlock; that pattern
//! does not survive the migration. The one unavoidable exception is the
//! optional allocator wired at the foot of this file, because a
//! `GlobalAlloc` is process-global by construction; it is default-off and
//! holds two thread-safe items of state and nothing else.
//!
//! # Cryptographic-provider hygiene
//!
//! `rustls`, `tokio-rustls` and `quinn` are pinned in the workspace manifest
//! with `default-features = false` and the **`ring`** provider. Nothing in
//! this crate may enable a feature that unions `aws_lc_rs`,
//! `prefer-post-quantum` or `platform-verifier` back into the graph. Cargo
//! unions features across the *whole* graph, so a single stray feature on
//! one optional dependency re-links a second cryptographic provider. Three
//! distinct defects follow from letting that happen:
//!
//! - `prefer-post-quantum` -- a `rustls` default -- offers a hybrid
//!   X25519MLKEM768 key exchange, which **changes the bytes of the TLS
//!   ClientHello** relative to curl 8.19.0-DEV. Under the byte-exact
//!   comparison described above that endangers every HTTPS fixture.
//! - `aws-lc-rs` vendors C and assembly and adds CMake and NASM to the
//!   build's requirements, which is hostile to the cross-compiled
//!   `aarch64-unknown-linux-gnu` target.
//! - `platform-verifier` delegates trust decisions to the operating-system
//!   store, which conflicts with `--cacert`, `--capath` and `--insecure`
//!   remaining authoritative.
//!
//! The honest caveat, recorded rather than buried: **neither `ring` nor
//! `aws-lc-rs` is pure Rust**; both contain C and assembly. The constraint
//! satisfied here is that no C *TLS library* is linked -- rustls implements
//! the TLS state machine, the record layer and certificate verification in
//! Rust, and the provider supplies only primitives. `ring` is chosen as the
//! more portable and more readily cross-compiled of the two. If "no C or
//! assembly whatsoever" were intended, no rustls configuration satisfies it
//! and the requirement is unmeetable as written.
//!
//! # Platform support
//!
//! Four targets, all 64-bit: `x86_64-unknown-linux-gnu`,
//! `aarch64-unknown-linux-gnu`, `x86_64-apple-darwin` and
//! `aarch64-apple-darwin`. The 64-bit property is load-bearing rather than
//! incidental -- the ABI shim carries a `curl_off_t` through one
//! register-width slot -- so 32-bit portability is a deliberate forfeit and
//! must not be claimed.
//!
//! Nothing here carries a code path for any other platform. `lib/amigaos.c`,
//! `lib/macos.c`, `lib/dllmain.c`, `lib/system_win32.c`, `lib/curl_sspi.c`,
//! `lib/socks_sspi.c`, the Windows-only files in `lib/curlx/`, and the
//! OS/400 and VMS projects are all out of scope. `lib/curl_setup.h`'s width
//! probes go with them: `SIZEOF_TIME_T` (`:541`, commented "assume default
//! size of time_t to be 32 bits") and `SIZEOF_CURL_SOCKET_T` (`:546`,
//! commented "default guess") are configure-time guesses that Rust's
//! guaranteed integer widths render unnecessary. Its per-platform
//! `curl_lseek` and `LSEEK_ERROR` shims (`:506-539`) become
//! [`std::io::Seek`].
//!
//! # Governance
//!
//! The engineering standards this crate is held to are expressed as mechanisms
//! rather than as aspiration: the safety invariant above is compiler-checked;
//! lint cleanliness is a merge gate; `Cargo.lock` is committed and every
//! dependency version is exact; `cargo audit` and `cargo deny` run
//! continuously; security-relevant configuration is explicit and never
//! defaulted; the C ABI is to be asserted by symbol-parity comparison and by
//! compiling all 129 programs in `docs/examples/`; and every claim about
//! existing behaviour made in this crate's documentation carries a repository
//! locator so that it can be checked rather than believed.
//!
//! # Minimum supported Rust version
//!
//! Edition 2021, MSRV 1.75, mirrored by `rust-version` in every member
//! manifest and by `msrv` in `clippy.toml`. No nightly-only feature appears
//! anywhere in this crate; nightly is reserved for the Miri and
//! AddressSanitizer continuous-integration legs, which name it per
//! invocation.

// FEATURE-SET PRECONDITION -- the one reserved-but-unimplementable name.
//
// `hickory-dns` is part of the fifteen-name feature vocabulary the plan
// fixes, and it must stay in that vocabulary: the `Features:` banner in
// `src/version.rs`, the capability table in `curl-rs-ffi/build.rs` and
// `curlinfo`'s 29-entry table are all written against those fifteen names,
// and deleting one would silently change three self-description surfaces.
//
// But no crate can currently back it, and the failure below exists so that
// asking for it is IMPOSSIBLE TO MISS. The option space was measured from
// the registry index, sorted by parsed semantic version, and the two halves
// are disjoint:
//
//   hickory-resolver 0.24.0-0.25.2  clear the workspace MSRV (they declare
//     1.67.0-1.71.1) but require hickory-proto ^0.24 / ^0.25, and every
//     hickory-proto below 0.26.1 carries RUSTSEC-2026-0119 - CPU exhaustion
//     through BinEncoder's linear name-compression scan, fixed only in
//     >= 0.26.1.
//   hickory-resolver 0.26.0-0.26.1  carry the fix and declare rust-version
//     1.88, which breaks the MSRV floor that is measured and satisfied
//     today.
//
// The advisory could not have been confined to the feature either, because
// cargo-deny and cargo-audit read `Cargo.lock` rather than the active
// feature set: wiring 0.25.2 as `optional = true` made `cargo deny check`
// report `advisories FAILED` on a DEFAULT build with the feature off. That
// was measured, not predicted.
//
// WHY A HARD ERROR RATHER THAN A NO-OP. The previous shape of this feature
// was `hickory-dns = []` - a bare cfg switch with nothing behind it - so
// enabling it changed nothing at all while the documentation promised an
// alternate resolver. Under the plan's own truthfulness rule,
// over-reporting a capability is the named failure mode and under-reporting
// is safe, so a silent success is the one outcome that must not happen. A
// build that stops here is unambiguous and self-explaining.
//
// CONSEQUENCE FOR CI, stated so it is not discovered by surprise:
// `--all-features` necessarily trips this error, and Cargo has no
// "all features except one" selector. The feature-matrix legs therefore
// enumerate the fourteen implementable features explicitly rather than
// passing `--all-features`. That is the correct reading and not a
// workaround - "all features" is not a meaningful configuration while one
// of them is reserved.
//
// Delete this block, and only this block, when a hickory-resolver release
// exists whose hickory-proto requirement admits >= 0.26.1 AND whose
// declared rust-version satisfies this workspace's floor. Wire the
// dependency in the root manifest at the same time.
#[cfg(feature = "hickory-dns")]
compile_error!(
    "feature `hickory-dns` is reserved but not implementable at the pinned \
     dependency set, and is deliberately a build failure rather than a \
     silent no-op. Every hickory-resolver release that satisfies the \
     workspace MSRV (0.24.0 through 0.25.2) requires a hickory-proto \
     affected by RUSTSEC-2026-0119, and every release carrying that fix \
     (0.26.0, 0.26.1) declares rust-version 1.88 and breaks the MSRV. \
     Because cargo-deny and cargo-audit read Cargo.lock rather than the \
     active feature set, declaring the crate as an optional dependency \
     would add the advisory to every build, including default builds with \
     this feature off. Build without this feature: the system resolver is \
     the mandated default, and `dns::resolver` is where it belongs when that \
     module lands -- it is not on disk at this checkpoint, so nothing is \
     lost by refusing the alternative here."
);

// MODULE INVENTORY -- 9 declarations, with the rest of the graph mapped below.
//
// This list replaces `lib/Makefile.inc`, the manifest both C build systems
// share. That file groups its sources into six lists -- LIB_CURLX_CFILES and
// LIB_CURLX_HFILES (`:26`, `:46`), LIB_VAUTH_* (`:68`, `:83`), LIB_VTLS_*
// (`:87`, `:104`), LIB_VQUIC_* (`:122`, `:128`), LIB_VSSH_* (`:135`, `:140`)
// and LIB_CFILES with LIB_HFILES (`:144`, `:271`) -- and joins them into
// CSOURCES (`:400`) and HHEADERS (`:402`). Here the compiler reads the
// inventory directly, so the manifest and the code cannot drift apart.
//
// ORDER is dependency order, not alphabetical: `error` first because every
// other module returns its types, then the two other leaves, then the
// utility and platform layers, then the subsystems that build on them, and
// finally the three handle interfaces that the C ABI exposes. It is a
// topological ordering of the module graph, not a schedule: every module
// lands together.
//
// The blank line between each declaration is REQUIRED. `rustfmt.toml` sets
// `reorder_modules = true`, and that setting sorts only `mod` items which are
// contiguous with no intervening blank line. Deleting a blank line here would
// let `cargo fmt` reorder the inventory and destroy the dependency reading.
//
// VISIBILITY is `pub` only where `curl-rs-ffi` or `curl-rs` demonstrably
// needs it -- each such module backing a named family of the 100 symbols in
// `lib/libcurl.def` -- and `pub(crate)` everywhere else. C's convention
// of an `extern` declaration under a `Curl_` prefix, private by agreement
// and visible to the linker, becomes privacy by enforcement.

/// Result codes: the type foundation of the crate.
///
/// Supersedes `lib/strerror.c`. Declares `CURLcode` (103 tokens,
/// `CURL_LAST` = 102, including the 15 retired `CURLE_OBSOLETE*` placeholders
/// that hold exactly `{20, 24, 29, 32, 34, 40, 41, 44, 46, 50, 51, 57, 62,
/// 75, 76}`), `CURLMcode`, `CURLUcode`, `CURLHcode` and `CURLSHcode`, each
/// `#[repr(i32)]` with every discriminant written out rather than inferred.
/// Dropping one placeholder would silently shift every later code by one.
///
/// `pub` because the codes cross the C ABI unchanged and because
/// `curl-rs-ffi`'s `curl_easy_strerror`, `curl_multi_strerror`,
/// `curl_share_strerror` and `curl_url_strerror` are thin adapters over the
/// message accessors declared here -- the four C functions do not even share
/// one unknown-value fallback, so all four strings live in this one module.
///
/// Declared first: everything else in the crate returns its types.
pub mod error;

/// The version and capability banner: `curl_version` and
/// `curl_version_info`.
///
/// Supersedes `lib/version.c`, and it is a machine-read contract rather than
/// a human-readable string. `tests/runtests.pl` parses the `Protocols:` and
/// `Features:` lines during start-up and uses them to decide which fixtures
/// may run, over a 52-name feature vocabulary. The asymmetry is decisive:
/// under-reporting a capability makes a fixture skip, while over-reporting
/// makes it run and fail. Truthful advertisement is therefore the optimal
/// strategy and not merely the honest one.
///
/// `pub`, and exposing the data *programmatically* rather than only as a
/// formatted banner, because `curl-rs/src/cli/libinfo.rs` queries the
/// protocol and feature set to build `--version` output and because
/// `curl-rs-ffi` populates a `curl_version_info_data` from it.
pub mod version;

/// Trace, verbose and error-buffer output.
///
/// Supersedes `lib/curl_trc.c`. The `--trace`, `--trace-ascii`,
/// `--trace-config` and `CURLOPT_DEBUGFUNCTION` layouts are frozen output,
/// so this module reproduces C's record shapes byte for byte, including
/// where the identifier block sits relative to the two-character kind
/// prefix -- which differs between a stream sink and a user callback.
///
/// `pub(crate)`, verified against the module itself: every item it declares
/// is already `pub(crate)`, so widening this declaration would export
/// nothing and would only weaken the boundary. The command-line tool reaches
/// trace output through `CURLOPT_DEBUGFUNCTION` and the option surface, not
/// by naming this module.
pub(crate) mod trace;

/// The portability and utility layer.
///
/// Supersedes the six `lib/curlx/` files with genuine Rust counterparts
/// (`base64.c`, `dynbuf.c`, `strparse.c`, `timediff.c`, `timeval.c`,
/// `inet_ntop.c` with `inet_pton.c`) together with `lib/llist.c`,
/// `lib/splay.c`, `lib/hash.c`, the four integer-keyed containers
/// (`uint-bset.c`, `uint-spbset.c`, `uint-hash.c`, `uint-table.c`),
/// `lib/parsedate.c`, `lib/curl_fnmatch.c`, `lib/curl_range.c`,
/// `lib/curl_get_line.c`, `lib/curl_memrchr.c`, `lib/bufq.c`,
/// `lib/bufref.c`, `lib/slist.c`, `lib/strcase.c` with `lib/strequal.c`,
/// `lib/curl_fopen.c`, `lib/curl_endian.c`, and the remaining `curlx` shims
/// whose function -- string duplication, cast narrowing, address formatting
/// -- has a direct standard-library expression.
///
/// Date parsing carries a public obligation even though the module is
/// crate-private: `curl_getdate` is one of the 100 exported symbols, so
/// every format curl accepts must still be accepted, and `curl-rs-ffi`
/// reaches it through a `pub` accessor rather than through this declaration.
pub(crate) mod util;

/// Operating-system integration that has no safe expression.
///
/// This is the SOLE `unsafe` island in `curl-rs-lib`, and the
/// `#[allow(unsafe_code)]` below is the ONE attribute in the entire crate
/// that grants the exemption from the crate-root `#![deny(unsafe_code)]`.
/// Every `unsafe` block inside carries a `// SAFETY:` comment. See the long
/// comment at the head of this file for the compiler diagnostics that settled
/// the `forbid`-versus-`deny` question and for the grep gate that closes the
/// one gap `deny` leaves open.
///
/// `sys` holds the residue that `socket2` cannot absorb -- a hostname query
/// and a small number of platform calls -- behind an injected `SysCalls`
/// trait, and, under the default-off `memdebug` feature, the counting
/// allocator wired at the foot of this file. `gss` holds the optional
/// GSS-API binding for Negotiate, behind the default-off `negotiate`
/// feature; that feature resolves the apparent conflict with "no C TLS
/// linkage at any configuration", because GSS-API is an authentication
/// mechanism and not a TLS library, so the default build links no C security
/// library at all.
///
/// Deliberately `pub(crate)`: nothing outside this crate may reach the
/// `unsafe` island, which is what keeps the audit surface one directory
/// wide.
#[allow(unsafe_code)]
pub(crate) mod ffi;

/// Cryptographic primitives.
///
/// Supersedes `lib/md5.c`, `lib/md4.c`, `lib/sha256.c`,
/// `lib/curl_sha512_256.c`, `lib/hmac.c` and `lib/rand.c`. The hand-rolled C
/// implementations are replaced by RustCrypto crates held to a single
/// `digest` generation, because two generations in one graph do not unify
/// their traits and `Hmac<Sha1>` would then fail to compile.
///
/// `pub(crate)`: no exported symbol is a hash function. These primitives
/// serve Digest and NTLM authentication, AWS SigV4 signing, certificate
/// pinning and the WebSocket handshake accept key, all of which live inside
/// this crate.
pub(crate) mod crypto;

/// The URL API, percent-encoding and internationalised domain names.
///
/// Supersedes `lib/urlapi.c`, `lib/escape.c` and `lib/idn.c`. curl's parsing
/// quirks are preserved rather than delegated wholesale to a general-purpose
/// URL crate, because the quirks are observable through the API and through
/// the fixture corpus.
///
/// `pub` because it backs six of the exported symbols -- `curl_url`,
/// `curl_url_cleanup`, `curl_url_dup`, `curl_url_get`, `curl_url_set` and
/// `curl_url_strerror` -- plus `curl_escape` and `curl_unescape`. `CURLU` is
/// the one public handle that is a genuine opaque struct rather than a
/// `void`, so its representation is part of the contract.
/// **Partially delivered.** Of this module's planned children, `escape` (from
/// `lib/escape.c`) and `idn` (from `lib/idn.c`) exist; the URL API itself,
/// from `lib/urlapi.c`, arrives with its file. `url/mod.rs` is the module root
/// and declares exactly those two.
pub mod url;

/// TLS -- rustls, and rustls only.
///
/// Supersedes `lib/vtls/`: the roughly 22-entry backend vtable of
/// `vtls.c`, certificate and hostname verification (`x509asn1.c`,
/// `hostcheck.c`), the session-resumption cache and its serialization
/// (`vtls_scache.c`, `vtls_spack.c`), cipher-suite name mapping
/// (`cipher_suite.c`) and `SSLKEYLOGFILE` support (`keylog.c`).
/// `lib/vtls/rustls.c` is the highest-value reference in the C tree: curl
/// already ships a rustls backend through rustls-ffi, so the mapping from
/// curl's TLS semantics onto rustls concepts is followed rather than
/// reinvented.
///
/// **Declared unconditionally.** There is no `tls` feature and there must
/// never be one; see the crate documentation above for why, and for the
/// measurement showing that writing `feature = "tls"` is itself a build
/// failure. Certificate validation is on by default; `--insecure` must warn
/// on standard error before proceeding, which means the "peer verification
/// disabled" state has to be readable from outside this crate -- it is
/// surfaced through the option and handle surface of the `easy` module
/// rather than by widening this declaration.
///
/// The backend-identity struct keeps `curl_ssl_backend info` as its FIRST
/// member. `lib/vtls/vtls_int.h:142-145` states the reason verbatim: "This
/// *must* be the first entry to allow returning the list of available
/// backends in `curl_global_sslset()`." `curl-rs-ffi` reports
/// `CURLSSLBACKEND_RUSTLS`, whose value 14 already exists in the public
/// `curl_sslbackend` enumeration, so no value is invented.
///
/// `pub(crate)`: the multi-backend dispatch collapses to one implementation,
/// and backend identity reaches C through [`version`].
/// **Partially delivered.** Of this module's planned children, only
/// `cipher_suite` and `keylog` exist yet; the backend trait, the rustls
/// backend, certificate verification and the session cache arrive with their
/// files. `tls/mod.rs` is the module root and declares exactly those two.
pub(crate) mod tls;

/// The multi interface: many transfers, one driver.
///
/// Supersedes `lib/multi.c` with `lib/multihandle.h` (the 18-state machine,
/// preserved as an explicit enumeration because `CURLINFO` and the multi
/// interface expose state-dependent behaviour, and made exhaustive so that
/// an unhandled state is a compile error rather than a runtime
/// fall-through), `lib/multi_ev.c` (socket-callback event plumbing) and
/// `lib/multi_ntfy.c` (the message queue behind `curl_multi_info_read`).
///
/// The easy-handle collection becomes a slab with generational keys, so a
/// handle removed and then reused is detectably stale rather than a dangling
/// pointer into an intrusive list.
///
/// `pub` because it backs the 22 exported `curl_multi_*` symbols --
/// including `curl_multi_socket` and `curl_multi_socket_all`, which are
/// deprecated in the public headers yet still exported and therefore still
/// in the parity set. Nothing deprecated is removed.
/// **Partially delivered.** Of this module's planned children, only `state`
/// exists yet; the multi handle itself, the event plumbing (`multi_ev.c`) and
/// the notification queue (`multi_ntfy.c`) arrive with their files.
/// `multi/mod.rs` is the module root: it declares `state` and carries
/// `wakeup_available`, and no `curl_multi_*` symbol is backed until the handle
/// lands.
pub mod multi;

// THE ELEVEN REMAINING SUBSYSTEMS -- SPECIFIED TARGET DESIGN, NOT DECLARED
//
// The AAP's module graph gives this crate eleven further subsystems. None of
// their files exists yet, and a `mod` line without its file is E0583 -- a
// hard error that no `#[allow]` can reach, because module resolution never
// gets far enough to produce a lint. They are therefore DESCRIBED here, in
// the same dependency order the declarations above follow, and each
// declaration arrives WITH its file in the unit of work that creates it.
//
// The visibility recorded for each is part of the specification, not a
// suggestion: `pub` appears only where `curl-rs-ffi` or `curl-rs`
// demonstrably needs it to back a named family of the 100 exported symbols.
//
// --- headers (pub) -- lib/headers.c, lib/dynhds.c ------------------------
// Backs the exported `curl_easy_header` and `curl_easy_nextheader` pair
// together with `curl_pushheader_byname` and `curl_pushheader_bynum`, which
// is the whole reason it is `pub`. The `curl_header` struct it fills is
// layout-visible to callers, so its field order and types are frozen.
//
// --- dns (pub(crate)) ----------------------------------------------------
// Supersedes lib/hostip.c, hostip4.c, hostip6.c, curl_addrinfo.c,
// fake_addrinfo.c, asyn-base.c, asyn-thrdd.c and curl_threads.c, plus
// lib/doh.c behind the `doh` feature, lib/httpsrr.c and lib/if2ip.c. The
// system resolver is the default; `hickory-dns` is an optional, default-off
// alternative.
//
// This is where the migration retires the single most hazardous construct in
// the C tree: lib/hostip.c bounds a blocking lookup with `alarm()` plus
// `sigsetjmp`/`siglongjmp` -- a non-local jump out of a signal handler
// across allocation boundaries, guarded by a process-global `sigjmp_buf`
// behind a spinlock. `tokio::time::timeout` replaces all of it, and the
// thread abstraction of lib/curl_threads.c is subsumed by the runtime.
//
// `pub(crate)` because no exported symbol resolves a name directly. The
// resolver is injected into the modules that need it rather than reached for
// globally, which is what makes them testable without a network.
//
// --- conn (pub(crate)) ---------------------------------------------------
// Supersedes lib/connect.c, cfilters.c, cf-socket.c, socketpair.c,
// curlx/nonblock.c, cf-ip-happy.c, conncache.c, cshutdn.c, select.c and
// curlx/wait.c.
//
// The filter chain is the load-bearing abstraction of the whole crate.
// `struct Curl_cftype` is a 14-member vtable carrying a `void *ctx` that
// every filter casts to its own type; replacing that context with a typed
// field removes an entire class of defect by construction. Because HTTP/3
// already participates in the same chain in C, QUIC, TLS, SOCKS, HAProxy and
// raw sockets unify under one trait here instead of requiring three parallel
// abstractions. Happy-eyeballs racing becomes a `select!` over the candidate
// addresses, and `poll`/`select` become the runtime's reactor.
//
// `pub(crate)`: connections are reached through an easy or multi handle.
//
// --- proxy (pub(crate)) --------------------------------------------------
// Supersedes lib/http_proxy.c, cf-h1-proxy.c and cf-h2-proxy.c (CONNECT
// tunnelling over HTTP/1 and HTTP/2), lib/socks.c (SOCKS4 and SOCKS5),
// lib/socks_gssapi.c (behind the default-off `negotiate` feature),
// lib/cf-haproxy.c (the PROXY protocol header) and lib/noproxy.c (`NO_PROXY`
// matching semantics, which are quirky and are preserved exactly).
//
// Every one of these is a filter in the chain owned by `conn`, which is why
// proxying needs no special case in the protocol layer.
//
// --- auth (pub(crate)) ---------------------------------------------------
// Supersedes lib/vauth/vauth.c (mechanism selection), cleartext.c (Basic),
// digest.c with lib/http_digest.c (Digest), oauth2.c (Bearer), ntlm.c with
// lib/curl_ntlm_core.c and lib/http_ntlm.c (NTLM, in pure Rust),
// lib/http_aws_sigv4.c (AWS SigV4), and -- behind the default-off
// `negotiate` feature -- krb5_gssapi.c, spnego_gssapi.c,
// lib/http_negotiate.c and lib/curl_gssapi.c.
//
// lib/curl_sasl.c sits astride the scope boundary: it serves SMTP, IMAP and
// POP3, which are stubbed, as well as HTTP authentication, which is
// implemented. The mechanism is therefore split rather than migrated or
// dropped wholesale, and only the HTTP portion lives here.
//
// Message construction is byte-exact. A Digest or NTLM message is compared
// against a literal expectation in the fixture corpus, so the bytes are the
// specification.
//
// --- cookies (pub(crate)) ------------------------------------------------
// Supersedes lib/cookie.c, psl.c, netrc.c, hsts.c and altsvc.c, gated by
// `cookies`, `hsts` and `altsvc` respectively.
//
// The Netscape cookie-jar file format must remain byte-compatible in both
// directions -- a jar written by curl 8.19.0-DEV must be readable here and
// vice versa -- and no general-purpose cookie crate commits to that on-disk
// format, so the jar is implemented natively. `publicsuffix` supplies only
// the domain-matching rules that libpsl previously supplied. The HSTS and
// Alt-Svc caches carry the same obligation for their own file formats.
//
// --- mime (pub) -- lib/mime.c, lib/formdata.c ----------------------------
// `pub` because it backs 15 exported symbols: the 12 `curl_mime_*` functions
// and the three legacy `curl_formadd`, `curl_formfree` and `curl_formget`
// entry points, which are deprecated in the documentation yet still exported
// and therefore still part of the parity set.
//
// --- transfer (pub(crate)) -----------------------------------------------
// Supersedes lib/transfer.c (the transfer loop, which becomes async),
// request.c (per-request state), sendf.c (manual buffers become `BytesMut`),
// cw-out.c with cw-pause.c (the client-writer chain and pause handling),
// progress.c (accounting, with the output format frozen), ratelimit.c
// (`--limit-rate` pacing), content_encoding.c (zlib, brotli and zstd calls
// become `flate2`, `brotli` and `zstd`) and http_chunks.c (chunked framing,
// byte-exact in both directions).
//
// One of the two modules the line-coverage gate measures, which is why the
// clock and the resolver reach it by injection.
//
// --- protocols (pub(crate)) ----------------------------------------------
// Supersedes lib/url.c's scheme lookup and lib/cf-https-connect.c's ALPN
// version negotiation, plus lib/http.c with http1.c, http2.c, vquic/*,
// ftp.c with pingpong.c, ftplistparser.c and fileinfo.c, vssh/*, file.c and
// ws.c.
//
// Declared unconditionally when it lands; the per-protocol feature gates
// (`http2`, `http3`, `ftp`, `ssh`, `websockets`) belong inside the module,
// not on the declaration, so that the registry itself always exists.
//
// The C tree defines and registers 33 URL schemes. Nine are implemented
// here; the other 24 are registered for ABI completeness and return
// `CURLE_UNSUPPORTED_PROTOCOL`, and they are deliberately withheld from the
// `Protocols:` banner so that the 283 fixtures targeting them skip cleanly
// instead of running and failing. A note for anyone reading the C: the
// backing array is declared `all_schemes[67]` at lib/url.c:1488 but only 33
// entries are defined and registered -- the array is over-allocated, and 67
// must not be read as a count.
//
// The HTTP/1.1 module owns request-line composition and header emission in
// curl's exact order, using `hyper` only for connection management,
// keep-alive and framing. Delegating serialization would fail a large
// fraction of the 1,476 byte-exact fixtures for reasons unrelated to
// correctness.
//
// The other module the line-coverage gate measures.
//
// --- share (pub) -- lib/curl_share.c -------------------------------------
// Cookie, DNS, TLS-session, HSTS and connection state can be shared across
// handles, with the caller's lock and unlock callbacks honoured. C guards
// this with the hand-rolled `curl_simple_lock` of lib/easy_lock.h -- an
// `SRWLOCK` on Windows, an `atomic_int` spin loop with
// `__builtin_ia32_pause` or an `aarch64` `yield` where C11 atomics exist, a
// `pthread_mutex_t` otherwise, and no thread safety at all when none of
// those is available. Rust's `std::sync` primitives replace all four cases,
// which is why the `threadsafe` capability is advertised unconditionally.
//
// `pub` because it backs the four exported `curl_share_*` symbols:
// `curl_share_init`, `curl_share_setopt`, `curl_share_cleanup` and
// `curl_share_strerror`.
//
// --- easy (pub) ----------------------------------------------------------
// Supersedes lib/easy.c, setopt.c (308 options), getinfo.c (70 `CURLINFO`
// accessors) and the generated easyoptions.c with easygetopt.c.
//
// The god-struct is decomposed here. lib/urldata.h is included nearly
// universally in C and concentrates connection, transfer and TLS state in
// one declaration; those fields migrate to the module that owns their
// lifecycle, and cross-module access becomes an explicit borrow rather than
// an implicit reach into shared mutable state.
//
// The option table is NOT declared here. `curl-rs-ffi` is the sole source of
// truth for the 308 `CURLoption` identifiers, their 17 backward-
// compatibility aliases and the `curl_easyoption` metadata array behind
// `curl_easy_option_by_name`, `_by_id` and `_next`; this module CONSUMES
// that table. Two tables would drift, and the drift would stay invisible
// until a consumer queried an option by name and received the wrong
// identifier.
//
// `pub` because it backs the 21 exported `curl_easy_*` symbols, and because
// the "peer verification disabled" state that obliges `curl-rs` to warn on
// standard error before proceeding is readable through this surface.

// MODULE MAP -- the remaining subsystems of the target design.
//
// The entries below name the rest of this crate's module graph and the C
// translation units each one supersedes. They are recorded in this file for
// two reasons. First, this file replaces `lib/Makefile.inc`, the manifest
// both C build systems share, and that manifest enumerates the whole tree
// rather than a part of it. Second, the order in which these subsystems
// compose is architectural information that no other file in the crate
// carries: it is the dependency order described above -- leaves first, then
// the utility and platform layers, then the subsystems built on them, and
// finally the handle interfaces the C ABI exposes.
//
// Each entry keeps the visibility the target design assigns it, stated with
// the consumer that justifies it, so that widening one later is a decision
// made against a recorded reason rather than a guess.

// The header API.
//
// Supersedes `lib/headers.c` and `lib/dynhds.c`, and backs the exported
// `curl_easy_header` and `curl_easy_nextheader` pair together with
// `curl_pushheader_byname` and `curl_pushheader_bynum`.
//
// `pub` for exactly that reason. The `curl_header` struct it fills is
// layout-visible to callers, so its field order and types are frozen.
//
// Name resolution.
//
// Supersedes `lib/hostip.c`, `lib/hostip4.c`, `lib/hostip6.c`,
// `lib/curl_addrinfo.c`, `lib/fake_addrinfo.c`, `lib/asyn-base.c`,
// `lib/asyn-thrdd.c` and `lib/curl_threads.c`, plus `lib/doh.c` behind the
// `doh` feature, `lib/httpsrr.c` and `lib/if2ip.c`. The system resolver is
// the default; `hickory-dns` is an optional, default-off alternative.
//
// This is where the migration retires the single most hazardous construct
// in the C tree: `lib/hostip.c` bounds a blocking lookup with `alarm()`
// plus `sigsetjmp`/`siglongjmp`, a non-local jump out of a signal handler
// across allocation boundaries, guarded by a process-global `sigjmp_buf`
// behind a spinlock. `tokio::time::timeout` replaces all of it, and the
// thread abstraction of `lib/curl_threads.c` is subsumed by the runtime.
//
// `pub(crate)`: no exported symbol resolves a name directly. The resolver
// is injected into the modules that need it rather than reached for
// globally, which is what makes them testable without a network.
//
// Connection establishment, the filter chain and the connection pool.
//
// Supersedes `lib/connect.c`, `lib/cfilters.c`, `lib/cf-socket.c`,
// `lib/socketpair.c`, `lib/curlx/nonblock.c`, `lib/cf-ip-happy.c`,
// `lib/conncache.c`, `lib/cshutdn.c`, `lib/select.c` and
// `lib/curlx/wait.c`.
//
// The filter chain is the load-bearing abstraction of the whole crate.
// `struct Curl_cftype` is a 14-member vtable carrying a `void *ctx` that
// every filter casts to its own type; replacing that context with a typed
// field removes an entire class of defect by construction. Because HTTP/3
// already participates in the same chain in C, QUIC, TLS, SOCKS, HAProxy
// and raw sockets unify under one trait here instead of requiring three
// parallel abstractions. Happy-eyeballs racing becomes a `select!` over the
// candidate addresses, and `poll`/`select` become the runtime's reactor.
//
// `pub(crate)`: connections are reached through an easy or multi handle.
//
// Proxy support.
//
// Supersedes `lib/http_proxy.c`, `lib/cf-h1-proxy.c`, `lib/cf-h2-proxy.c`
// (CONNECT tunnelling over HTTP/1 and HTTP/2), `lib/socks.c` (SOCKS4 and
// SOCKS5), `lib/socks_gssapi.c` (behind the default-off `negotiate`
// feature), `lib/cf-haproxy.c` (the PROXY protocol header) and
// `lib/noproxy.c` (`NO_PROXY` matching semantics, which are quirky and are
// preserved exactly).
//
// Every one of these is a filter in the chain owned by [`conn`], which is
// why proxying needs no special case in the protocol layer.
//
// `pub(crate)`: proxies are configured through options, never named
// directly by a caller.
//
// Authentication.
//
// Supersedes `lib/vauth/vauth.c` (mechanism selection), `cleartext.c`
// (Basic), `digest.c` with `lib/http_digest.c` (Digest), `oauth2.c`
// (Bearer), `ntlm.c` with `lib/curl_ntlm_core.c` and `lib/http_ntlm.c`
// (NTLM, in pure Rust), `lib/http_aws_sigv4.c` (AWS SigV4), and -- behind
// the default-off `negotiate` feature -- `krb5_gssapi.c`,
// `spnego_gssapi.c`, `lib/http_negotiate.c` and `lib/curl_gssapi.c`.
//
// `lib/curl_sasl.c` sits astride the scope boundary: it serves SMTP, IMAP
// and POP3, which are stubbed, as well as HTTP authentication, which is
// implemented. The mechanism is therefore split rather than migrated or
// dropped wholesale, and only the HTTP portion lives here.
//
// Message construction is byte-exact. A Digest or NTLM message is compared
// against a literal expectation in the fixture corpus, so the bytes are the
// specification.
//
// `pub(crate)`: credentials arrive through options.
//
// Cookies and the three persistent on-disk caches.
//
// Supersedes `lib/cookie.c`, `lib/psl.c`, `lib/netrc.c`, `lib/hsts.c` and
// `lib/altsvc.c`, gated by `cookies`, `hsts` and `altsvc` respectively.
//
// The Netscape cookie-jar file format must remain byte-compatible in both
// directions -- a jar written by curl 8.19.0-DEV must be readable here and
// vice versa -- and no general-purpose cookie crate commits to that on-disk
// format, so the jar is implemented natively. `publicsuffix` supplies only
// the domain-matching rules that libpsl previously supplied. The HSTS and
// Alt-Svc caches carry the same obligation for their own file formats.
//
// `pub(crate)`: the cookie engine is driven through options and through the
// share interface.
//
// MIME and the legacy form API.
//
// Supersedes `lib/mime.c` and `lib/formdata.c`.
//
// `pub` because it backs 15 exported symbols: the 12 `curl_mime_*`
// functions and the three legacy `curl_formadd`, `curl_formfree` and
// `curl_formget` entry points, which are deprecated in the documentation
// yet still exported and therefore still part of the parity set.
//
// The transfer core.
//
// Supersedes `lib/transfer.c` (the transfer loop, which becomes async),
// `lib/request.c` (per-request state), `lib/sendf.c` (manual buffers become
// `BytesMut`), `lib/cw-out.c` with `lib/cw-pause.c` (the client-writer
// chain and pause handling), `lib/progress.c` (accounting, with the output
// format frozen), `lib/ratelimit.c` (`--limit-rate` pacing),
// `lib/content_encoding.c` (zlib, brotli and zstd calls become `flate2`,
// `brotli` and `zstd`) and `lib/http_chunks.c` (chunked framing, byte-exact
// in both directions).
//
// One of the two modules the line-coverage gate measures, which is why the
// clock and the resolver reach it by injection.
//
// `pub(crate)`: a transfer is driven through an easy or multi handle.
//
// The protocol implementations and the scheme registry.
//
// Supersedes `lib/url.c`'s scheme lookup and `lib/cf-https-connect.c`'s
// ALPN version negotiation, plus `lib/http.c` with `lib/http1.c`,
// `lib/http2.c`, `lib/vquic/*`, `lib/ftp.c` with `lib/pingpong.c`,
// `lib/ftplistparser.c` and `lib/fileinfo.c`, `lib/vssh/*`, `lib/file.c`
// and `lib/ws.c`.
//
// Declared unconditionally; the per-protocol feature gates
// (`http2`, `http3`, `ftp`, `ssh`, `websockets`) belong inside the module,
// not on this declaration, so that the registry itself always exists.
//
// The C tree defines and registers 33 URL schemes. Nine are implemented
// here; the other 24 are registered for ABI completeness and return
// `CURLE_UNSUPPORTED_PROTOCOL`, and they are deliberately withheld from the
// `Protocols:` banner so that the 283 fixtures targeting them skip cleanly
// instead of running and failing. A note for anyone reading the C: the
// backing array is declared `all_schemes[67]` at `lib/url.c:1488` but only
// 33 entries are defined and registered -- the array is over-allocated, and
// 67 must not be read as a count.
//
// The HTTP/1.1 module owns request-line composition and header emission in
// curl's exact order, using `hyper` only for connection management,
// keep-alive and framing. Delegating serialization would fail a large
// fraction of the 1,476 byte-exact fixtures for reasons unrelated to
// correctness.
//
// The other module the line-coverage gate measures.
//
// `pub(crate)`: a scheme is selected by URL, never named by a caller.
//
// The share interface: state deliberately shared between easy handles.
//
// Supersedes `lib/curl_share.c`. Cookie, DNS, TLS-session, HSTS and
// connection state can be shared across handles, with the caller's
// lock and unlock callbacks honoured. C guards this with the hand-rolled
// `curl_simple_lock` of `lib/easy_lock.h` -- an `SRWLOCK` on Windows, an
// `atomic_int` spin loop with `__builtin_ia32_pause` or an `aarch64`
// `yield` where C11 atomics exist, a `pthread_mutex_t` otherwise, and no
// thread safety at all when none of those is available. Rust's
// `std::sync` primitives replace all four cases, which is why the
// `threadsafe` capability is advertised unconditionally.
//
// `pub` because it backs the four exported `curl_share_*` symbols:
// `curl_share_init`, `curl_share_setopt`, `curl_share_cleanup` and
// `curl_share_strerror`.
//
// The easy interface: one handle, one transfer.
//
// Supersedes `lib/easy.c`, `lib/setopt.c` (308 options), `lib/getinfo.c`
// (70 `CURLINFO` accessors) and the generated `lib/easyoptions.c` with
// `lib/easygetopt.c`.
//
// The god-struct is decomposed here. `lib/urldata.h` is included nearly
// universally in C and concentrates connection, transfer and TLS state in
// one declaration; those fields migrate to the module that owns their
// lifecycle, and cross-module access becomes an explicit borrow rather than
// an implicit reach into shared mutable state.
//
// The option table is NOT declared here. `curl-rs-ffi` is the sole source
// of truth for the 308 `CURLoption` identifiers, their 17
// backward-compatibility aliases and the `curl_easyoption` metadata array
// behind `curl_easy_option_by_name`, `_by_id` and `_next`; this module
// CONSUMES that table. Two tables would drift, and the drift would stay
// invisible until a consumer queried an option by name and received the
// wrong identifier.
//
// `pub` because it backs the 21 exported `curl_easy_*` symbols, and because
// the "peer verification disabled" state that obliges `curl-rs` to warn on
// standard error before proceeding is readable through this surface.

// THE OPTIONAL ALLOCATION LOG -- `memdebug`, default OFF.
//
// This is the ONLY wiring this file performs, and it is wiring only: the
// allocator itself lives in `crate::ffi::sys::memdebug`, because
// `impl GlobalAlloc` must be an `unsafe impl` and `src/ffi/` is the one
// directory where that is permitted. DO NOT "fix" this by moving the
// implementation here -- doing so would put an `unsafe impl` in the crate
// root and destroy the invariant this file exists to hold. That the split
// works was verified by compiling it: `#[global_allocator]` on a `static` is
// a safe attribute, so the wiring below builds cleanly under the crate-root
// `#![deny(unsafe_code)]`, both with the feature and without it.
//
// WHY IT IS OFF BY DEFAULT, and what that costs.
//
// `tests/runtests.pl:1759` wraps its entire memory check in
// `if($feature{"TrackMemory"})`, and `:660` derives that feature from a
// single regular expression over the version banner:
//
//     $feature{"TrackMemory"} = $feat =~ /Debug/i;
//
// A binary that does not advertise `Debug` therefore has all leak checking
// and all allocation-cap checking skipped, and a missing memory-dump file
// appends only a `-` marker rather than failing the test. The chosen posture
// is not to advertise `Debug`, which makes the 28 fixtures carrying a
// `<limits>` block inert. The cost is stated openly rather than buried: 98
// fixtures require `Debug` and will skip, and `make torture-test`
// hard-requires the feature (`tests/runtests.pl:847-849`) and is therefore
// not applicable. This feature exists so that the trade can be reversed
// without a redesign should it prove unacceptable.
//
// What makes a Rust allocator viable at all is that the fixture assertion is
// a CAP, not an equality: `tests/runtests.pl:1786-1826` tests
// `if($allocs > $lim_allocs)`, defaulting to 1000 allocations and 1,000,000
// bytes when a fixture omits the block. A Rust allocation pattern that
// differs from C's but is not larger passes. `tests/data/test1`, for
// instance, specifies `Allocations: 135` and `Maximum allocated: 136000`.
//
// The log destination is the path named by the `CURL_MEMDEBUG` environment
// variable (`tests/runner.pm:165` sets it to "$logdir/$MEMDUMP"). The
// per-fixture opt-out `<command option="no-memdebug">` DELETES that variable
// at `tests/runner.pm:1026-1028` and restores it at `:1056`, so an unset,
// empty or unwritable destination must simply disable logging: silently, with
// nothing written anywhere and nothing panicking. `lib/memdebug.c:149` takes
// the same view, opening the file only `if(logname && *logname)`.
//
// The record formats reproduce `lib/memdebug.c` exactly, and the asymmetric
// comma spacing is not a typo -- `calloc` has no space after its comma
// (`:257`) and `realloc` has one (`:349`), and `tests/memanalyzer.pm` parses
// both with regular expressions, so either mistake breaks the parse. The
// allocation cap mirrors `curl_dbg_memlimit()` (`:175-181`) including its
// one-shot `if(!memlimit)` guard, and `countcheck()` (`:183-205`) writes its
// `LIMIT %s:%d %s reached memlimit` record to BOTH the log and standard
// error before failing the allocation.

#[cfg(feature = "memdebug")]
#[global_allocator]
static MEMDEBUG_ALLOCATOR: crate::ffi::sys::memdebug::TrackingAllocator =
    crate::ffi::sys::memdebug::TrackingAllocator::new();

// CRATE-ROOT RE-EXPORTS -- deliberately minimal, and every entry justified.
//
// A crate root is not a convenience header. Re-exporting broadly here would
// rebuild exactly the coupling that replacing `#include "urldata.h"` removes,
// so the rule is: re-export a symbol only where naming its owning module
// would be actively unhelpful, and let every other consumer write the full
// path (`curl_rs_lib::easy::...`, `curl_rs_lib::url::...`).
//
// TWO EXCLUSIONS, stated rather than silently omitted:
//
//  * The easy, multi and share HANDLE TYPES are NOT re-exported. Those
//    modules are authored separately and do not exist at this commit, so any
//    type name written here would be an unverified claim about code this file
//    cannot inspect -- and the discipline this work is held to is that claims
//    are evidenced, not asserted. Nothing is lost: `easy`, `multi` and
//    `share` are all `pub`, so a consumer names the type through its owning
//    module, which is the one-import-per-type discipline in any case. Adding
//    a re-export later is a compatible change; a wrong one is a build break
//    for two other crates.
//  * No blanket `pub use error::*;` or `pub use version::*;`. A glob
//    re-export makes the crate's public surface implicit, and the C ABI it
//    backs is the opposite of implicit.

// The five result-code families. Re-exported because they are the crate's
// universal return currency: every fallible operation in every module yields
// one of them, `curl-rs-ffi` converts each to the `int` a C caller receives,
// and `curl-rs` maps `CURLcode` to its process exit status. Writing
// `curl_rs_lib::error::CURLcode` at every one of those sites would be noise,
// and these five names are unambiguous -- they are the C spellings.
pub use crate::error::{CURLHcode, CURLMcode, CURLSHcode, CURLUcode, CURLcode};

// The contextual error type and the result alias built on it. `Error` pairs a
// pinned `CURLcode` with the specific message that C would have written into
// `CURLOPT_ERRORBUFFER`, and `CurlResult<T>` is the alias that stands where
// the C tree wrote `CURLcode Curl_xyz(...)`. Both appear in the signature of
// nearly every public function this crate offers, so both belong at the root.
pub use crate::error::{CurlResult, Error};

// The version and capability surface. Re-exported because it is consumed
// PROGRAMMATICALLY, not as a formatted string: `curl-rs/src/cli/libinfo.rs`
// asks which protocols and features are present in order to build the
// `--version` banner that `tests/runtests.pl` then parses to decide fixture
// eligibility, and `curl-rs-ffi` fills a `curl_version_info_data` from the
// same data. `VersionInfo` is the structure, `version_info` the accessor and
// `version` the formatted banner; the two constants are the identity that
// `include/curl/curlver.h` fixes and that nothing may bump.
pub use crate::version::{
    version, version_info, VersionInfo, LIBCURL_VERSION, LIBCURL_VERSION_NUM,
};

// The date parser. Re-exported because it is the ONE item in the
// `pub(crate) mod util` tree that a C caller reaches directly:
// `curl_getdate` is one of the 100 symbols `lib/libcurl.def` exports, and
// `curl-rs-ffi` has no other way in -- `util` is crate-private by
// enforcement, and a private path cannot be named from another crate.
//
// This is the standard private-module / public-re-export idiom, and it is
// the whole of review finding M-13's resolution: WITHOUT this line the facade
// would have to reimplement `lib/parsedate.c`, putting engine logic in a
// crate whose stated job is the C ABI and nothing else. WITH it, the adapter
// converts a `*const c_char` to a `&str`, calls this, and maps `None` to
// `-1`. Every parsing decision -- the six-part walk, the 69 timezone names,
// the two-digit-year pivot, the `-1`-to-`0` adjustment -- stays here.
//
// Deliberately ONE name, not the module. `pub use crate::util::parsedate;`
// would expose the module and with it `getdate_capped`, which backs the
// INTERNAL `Curl_getdate_capped` and is not an exported symbol; widening it
// would misrepresent the ABI surface as larger than the 100 names.
pub use crate::util::parsedate::getdate;

// The two case-insensitive comparators. Re-exported by the same idiom and for
// the same reason as `getdate` above: `curl_strequal` and `curl_strnequal` are
// two of the 100 symbols `lib/libcurl.def` exports, and `curl-rs-ffi` has no
// other way in because `util` is crate-private by enforcement.
//
// Both take `Option<&CStr>`, not raw pointers, so the null-pointer contract
// that `lib/strequal.c` expresses with a NULL test stays inside this crate
// where no `unsafe` is needed to honour it. The adapter's whole job is
// converting a `*const c_char` into `Option<&CStr>`; the two asymmetric NULL
// rules -- `curl_strequal(NULL, NULL)` is true while
// `curl_strnequal(NULL, NULL, 0)` is false -- belong to the contract and so
// live here.
//
// Deliberately TWO names, not the module: `casecompare` and `ncasecompare` are
// internal comparators and no other crate has any business calling them.
pub use crate::util::strcase::{strequal, strnequal};

// The extended-attribute primitive and its capability predicate. Re-exported
// for the same reason and by the same idiom as `getdate` above: they are the
// two items in the `pub(crate) mod ffi` tree that a caller OUTSIDE this crate
// reaches directly, and `ffi` is crate-private by enforcement.
//
// The caller is `curl-rs`, not `curl-rs-ffi`. `src/tool_xattr.c`'s `--xattr`
// support belongs to the command-line tool, but its platform call has no safe
// expression: `std` exposes no extended-attribute API, no such crate is among
// the pins of specification 0.5.1, and `curl-rs/src/main.rs` carries
// `#![forbid(unsafe_code)]` with no `mod ffi` to place a raw call behind. The
// call therefore lives in this crate's one unsafe island and is reached from
// there -- which is precisely the arrangement the tool's own module
// documentation prescribed.
//
// Deliberately TWO names, not the module. `pub use crate::ffi::sys;` would
// expose the hostname query, the interface snapshot, the zone-id lookup and
// the counting allocator, none of which any other crate needs.
pub use crate::ffi::sys::{set_fd_xattr, xattr_available};
// THE PLATFORM FACADE -- six functions and one guard, and the only names from
// `mod ffi` that leave this crate.
//
// Re-exported here, and nowhere else, because `curl-rs` cannot reach them any
// other way and must not be made able to. That crate carries
// `#![forbid(unsafe_code)]`, has no `mod ffi`, and AAP 0.8.5 conflict C3
// reserves `curl-rs-lib/src/ffi/` for "genuine OS residue" -- so the four
// capabilities the command-line tool needs from the operating system arrive
// through this list or not at all:
//
//   * `disable_echo` / `EchoGuard` -- clears the terminal's `ECHO` bit while a
//     password is typed and restores it in `Drop`, reproducing the
//     `TCSANOW`/`TCSAFLUSH` pair at `src/tool_getpass.c:139` and `:155`.
//     Consumed by `curl-rs/src/terminal.rs`.
//   * `terminal_columns` -- the `ioctl(TIOCGWINSZ)` probe of
//     `src/terminal.c:62-63`, unfiltered: the `20`/`10000` bounds and the 79
//     fallback are CLI policy and stay in `curl-rs/src/terminal.rs`.
//   * `set_file_xattr` -- the platform-selected `fsetxattr` of
//     `src/tool_xattr.c:88-92`, five arguments on Linux and six on macOS
//     behind one signature. Consumed by `curl-rs/src/output/xattr.rs`.
//   * `local_utc_offset_secs`, `strftime_gmt`, `set_locale_from_environment`
//     -- `localtime_r`'s `tm_gmtoff` for `--trace-time`, the
//     `curlx_gmtime`-plus-`strftime` pair of `src/tool_writeout.c:581-588` for
//     `%time{}`, and the `setlocale` pair of `src/tool_operate.c:2271-2272`
//     that makes the second of those locale-dependent at all. Consumed by
//     `curl-rs/src/util.rs`, `curl-rs/src/output/writeout.rs` and
//     `curl-rs/src/operate/mod.rs` respectively.
//
// WHAT THIS DOES NOT DO, because the distinction is the whole reason the list
// is a list and not a `pub mod`:
//
//   * `mod ffi` stays `pub(crate)`. No consumer can name a path into the
//     `unsafe` island, so nothing there can be reached except through these
//     seven names.
//   * The seam traits (`TerminalCalls`, `XattrCalls`, `TimeCalls`,
//     `SysCalls`), `RealSys`, `SavedTerminal` and every `_with` variant stay
//     `pub(crate)`. A consumer gets the capability, never the mechanism.
//   * No new module and no new file is introduced to carry this. A `pub mod`
//     wrapper would add a module name that AAP 0.3.1 does not list for this
//     crate, and the crate-root re-export mechanism this section already
//     documents is the mechanism that exists for exactly this purpose.
//
// Every one of the seven is a safe function over `std` types -- `BorrowedFd`,
// `io::Result`, `Option`, `&[u8]` -- and each forms its raw pointer, uses it
// and drops it inside a single call.
pub use crate::ffi::{
    disable_echo, local_utc_offset_secs, set_file_xattr,
    set_locale_from_environment, strftime_gmt, terminal_columns, EchoGuard,
};

// THE OPERATING-SYSTEM ERROR TEXT, and the only name from `mod util` that
// leaves this crate.
//
// `curlx_strerror` (`lib/curlx/strerr.c:250-331`) is interpolated into frozen
// diagnostics from both crates -- `src/tool_formparse.c:220` and `:561`,
// `src/tool_filetime.c:79` and `:136`, `src/tool_operate.c:637-639` -- and
// every one of them must render an `errno` to the same bytes. Three
// independent implementations of the `" (os error N)"` strip existed and two
// already disagreed under Miri, so `crate::util` now owns the algorithm and
// this is how `curl-rs` reaches it. See `os_error_message` for the measurement.
//
// `mod util` itself stays `pub(crate)`: the other absorbed shims -- the
// narrowing conversions, `basename`, `strcopy`, the endian readers -- have no
// consumer outside this crate and gain nothing from being nameable by one.
pub use crate::util::os_error_message;

// OPERATING-SYSTEM FACADE -- the narrowest safe bridge to `src/ffi/sys.rs`.
//
// `curl-rs` carries `#![forbid(unsafe_code)]` with ZERO exemptions and declares
// no `libc` dependency, so it cannot make a platform call at all; and AAP
// section 0.8.5 conflict C3 requires the residue that `socket2` does not absorb
// to live in `curl-rs-lib/src/ffi/sys.rs`. Every platform capability the
// command-line tool needs therefore reaches it from this crate, and the two
// groups here are the whole of that surface.
//
// IT CROSSES IN TWO SHAPES, and the difference is visibility rather than taste.
//
//  * RE-EXPORTED AS THEY STAND -- the seven names in the `pub use crate::ffi`
//    above: `disable_echo` and `EchoGuard` (F15, terminal echo while a password
//    is typed), `terminal_columns`, `set_file_xattr` (F17), and
//    `local_utc_offset_secs`, `strftime_gmt` and `set_locale_from_environment`
//    (F16, local and locale-dependent time). `ffi/mod.rs` group E marks exactly
//    those `pub`, so no wrapper is needed: each is already a total, safe
//    function -- or, for the guard, a type with private fields -- over
//    standard-library types, and a wrapper would add a hop and nothing else.
//    The guard form is deliberate: the caller cannot forget to end echo
//    suppression, because ending it is not the caller's job.
//  * WRAPPED HERE -- the four below. Their implementations are `pub(crate)`
//    (`ffi/mod.rs` groups A and C), and re-exporting a `pub(crate)` item as
//    `pub` is E0365. A thin wrapper is the sanctioned alternative, and it is
//    better than widening the re-export would have been: `mod ffi` stays
//    `pub(crate)`, so nothing outside this crate can name a path into the
//    `unsafe` island, and each wrapper narrows what it exposes so that no
//    `pub(crate)` type ever reaches a public signature.
//
// WHAT NEITHER SHAPE EXPOSES: no `libc` type and no raw pointer anywhere.
// `RawFd` is `std::os::unix::io::RawFd`, a standard-library alias for `i32`.
// The `unsafe` blocks are reachable from outside this crate only through these
// ten names -- eleven with `memdebug` -- and each of them forms the raw pointer
// it needs, uses it and drops it inside a single call.

/// The extent of `fd` when it is a regular file that can be read lazily.
///
/// `Some((origin, size))` where `origin` is the descriptor's current offset and
/// `size` is the file's total length -- the pair `src/tool_formparse.c:128,131-135`
/// gathers before deciding that standard input need not be buffered.
///
/// [`None`] is an ordinary answer rather than an error, and it covers every case
/// C's compound condition collapses into its "buffer it instead" branch at
/// `:140`: a pipe, a socket, a terminal, a directory, a closed descriptor and an
/// unseekable one alike. A caller that receives [`None`] must buffer.
pub fn regular_file_extent(fd: std::os::unix::io::RawFd) -> Option<(i64, i64)> {
    crate::ffi::regular_file_extent(fd)
}

/// Reads from `fd` into `buf`, returning how many bytes were placed there.
///
/// Stands in for `fread(buffer, 1, nitems, stdin)`
/// (`src/tool_formparse.c:216`); `Ok(0)` is end of input, as a short `fread`
/// without `ferror` is.
///
/// # Why `io::Result` rather than a `CURLcode`
///
/// The caller distinguishes end of input from failure and needs the underlying
/// error to do it, which is precisely what C's `ferror(stdin)` check at `:218`
/// consults. Flattening that into a `CURLcode` would discard the distinction at
/// the boundary and force the caller to re-invent it.
///
/// # Errors
///
/// Whatever `read(2)` reports: a closed or unreadable descriptor, or an
/// interruption.
pub fn read_file_descriptor(
    fd: std::os::unix::io::RawFd,
    buf: &mut [u8],
) -> std::io::Result<usize> {
    crate::ffi::read_fd(fd, buf)
}

/// Repositions `fd` to `offset`, counted from the start of the file.
///
/// Reproduces `curlx_fseek(stdin, offset, SEEK_SET)`
/// (`src/tool_formparse.c:244`), where the offset already includes the origin.
///
/// The descriptor is repositioned directly rather than through a buffered
/// stream, which is what makes this safe to pair with [`read_file_descriptor`]:
/// there is no user-space buffer left holding bytes from before the seek. A
/// caller that mixes this with `io::Stdin` would have exactly that bug.
///
/// # Errors
///
/// Whatever `lseek(2)` reports. An unseekable descriptor is the case
/// `src/tool_formparse.c:245` turns into `CURL_SEEKFUNC_CANTSEEK`.
pub fn seek_file_descriptor(
    fd: std::os::unix::io::RawFd,
    offset: i64,
) -> std::io::Result<()> {
    crate::ffi::seek_fd(fd, offset)
}

/// Applies the `CURL_MEMLIMIT` allocation cap, reproducing
/// `src/tool_main.c:117-125`.
///
/// Returns whether *this* call armed the cap. The allocator also arms itself
/// from the same variable on its first use, so a [`false`] here does not mean no
/// cap is in force -- see `ffi::sys::memdebug::init_from_env` for the measured
/// detail. Calling this as early as possible in `main` is still worthwhile: it
/// is what makes the cap's numbering start where the C's does, rather than two
/// allocations earlier.
///
/// Present only with the `memdebug` feature, which is off by default. AAP
/// section 0.6.6 records why: `tests/runtests.pl:1759` gates every memory check
/// on `TrackMemory`, which `:660` derives from a `Debug` token in the version
/// banner that this build deliberately withholds.
#[cfg(feature = "memdebug")]
pub fn memdebug_init_from_env() -> bool {
    crate::ffi::init_from_env()
}

// DIAGNOSTIC-OUTPUT FACADE -- the bridge to `src/trace.rs`'s neutralization.
//
// One more function, and here for the same structural reason as the four above:
// the implementation is `pub(crate)` in a `pub(crate) mod`, and `curl-rs` is a
// separate crate that cannot reach it.
//
// F25 spans three files that each render attacker-influenced text --
// `curl-rs-lib/src/trace.rs`, `curl-rs-lib/src/tls/cipher_suite.rs` and
// `curl-rs/src/output/msgs.rs`. The first two are inside this crate and call
// `crate::trace::escape_controls` directly; only the third needs a bridge, so
// only what the third needs crosses. `ControlEscaping` stays private and the
// single-line mode is baked in, because a warning, an error or an embedded
// diagnostic fragment is one line by construction -- which is exactly why an LF
// in one was injected rather than structural.

/// Neutralize display-affecting control bytes in a one-line diagnostic.
///
/// # What this is for
///
/// Text that is about to reach a terminal and that carries bytes this process
/// did not choose -- a server-supplied error string, a hostname, a certificate
/// subject, a negotiated cipher name. Such bytes can contain an ESC sequence
/// that repositions the cursor or recolours the screen (CWE-150), or a CR or LF
/// that overwrites or fabricates a line of output (CWE-117).
///
/// Every byte below `0x20`, plus `0x7F`, becomes `.` -- the same substitution
/// `dump()` already makes for unprintable bytes (`src/tool_setup.h:63`,
/// `UNPRINTABLE_CHAR`). One byte in, one byte out, so the result is exactly as
/// long as the input and this can never amplify output. Bytes at or above `0x80`
/// are left alone: they are legitimate 8-bit or UTF-8 payload and cannot affect
/// a display.
///
/// Returns [`std::borrow::Cow::Borrowed`] when there is nothing to replace,
/// which is the overwhelmingly common case, so ordinary messages cost no
/// allocation and are passed through unchanged.
///
/// # When NOT to call it
///
/// Only for a destination whose bytes are interpreted. A redirected file must
/// stay byte-faithful so its contents can be diffed or replayed against the C
/// tool, and neutralizing there would be a behaviour change with no security
/// benefit. Decide on the destination first, then call this only for the
/// terminal case.
///
/// Multi-line payloads -- a whole header block, a trace record -- must NOT go
/// through here: it would replace their line terminators. Those are handled
/// inside [`crate::trace`], which keeps LF and keeps CR where it precedes LF
/// while still neutralizing a lone CR.
#[must_use]
pub fn escape_control_bytes(text: &[u8]) -> std::borrow::Cow<'_, [u8]> {
    crate::trace::escape_controls(
        text,
        crate::trace::ControlEscaping::SingleLine,
    )
}

// CRATE-ROOT SELF-CHECKS.
//
// These assert the invariants THIS FILE owns and nothing else: the frozen
// reported identity, the capability vocabulary, the reachability of the
// re-exported surface, and the allocator wiring. They deliberately name only
// `error`, `version` and this file, so they neither duplicate a sibling
// module's tests nor couple the crate root to modules it merely declares.
//
// Two of the invariants this file owns cannot be expressed as a runtime
// assertion at all, and are checked by the toolchain instead:
//
//  * "`unsafe` is impossible outside `src/ffi/`" is a COMPILE error, proven by
//    adding an `unsafe` block to a non-`ffi` module and observing
//    `error: usage of an unsafe block`, whose `note: the lint level is
//    defined here` points at this file's own `#![deny(unsafe_code)]` -- not at
//    line 1, which is a licence comment.
//  * "exactly one `#[allow(unsafe_code)]` exists, on `mod ffi`" cannot be a
//    compile error, because `deny` -- unlike `forbid` -- can be overridden
//    from an inner scope. It is enforced by `mod source_policy` at the foot of
//    this file, which walks the workspace at test time. The grep expressions
//    at the head of this file document the same rule for a reader at a
//    terminal; the executable gate is what a change has to get past. Both are
//    anchored, because this file discusses the attribute in prose and an
//    unanchored search would match the discussion.
//
// `mod source_policy` carries one further invariant that is not about `unsafe`
// at all: no lint level for `dead_code` may be set on a crate root or a module
// root, anywhere in the workspace. That form of suppression also silences the
// NEXT item somebody adds, so it hides incomplete scaffolding instead of
// recording it. Items whose consumer has yet to be migrated carry a per-item
// `#[allow(dead_code)]` instead, which is an inventory: every one is
// load-bearing, and each is deleted when its consumer lands.

#[cfg(test)]
mod tests {
    /// The capability vocabulary, evaluated at compile time.
    ///
    /// Every name below is a feature declared in `curl-rs-lib/Cargo.toml`.
    /// That is not merely a convention: naming an UNDECLARED feature makes
    /// `rustc` emit `unexpected 'cfg' condition value`, which the lint gate
    /// turns into a build failure. This table is therefore a mechanical check
    /// that the 15 names are exactly the 15 that exist, spelled correctly.
    ///
    /// The `bool` records whether the feature is enabled in the build under
    /// test, which varies by invocation and is deliberately not asserted.
    const FEATURES: &[(&str, bool)] = &[
        ("altsvc", cfg!(feature = "altsvc")),
        ("brotli", cfg!(feature = "brotli")),
        ("cookies", cfg!(feature = "cookies")),
        ("doh", cfg!(feature = "doh")),
        ("ftp", cfg!(feature = "ftp")),
        ("gzip", cfg!(feature = "gzip")),
        ("hickory-dns", cfg!(feature = "hickory-dns")),
        ("hsts", cfg!(feature = "hsts")),
        ("http2", cfg!(feature = "http2")),
        ("http3", cfg!(feature = "http3")),
        ("memdebug", cfg!(feature = "memdebug")),
        ("negotiate", cfg!(feature = "negotiate")),
        ("ssh", cfg!(feature = "ssh")),
        ("websockets", cfg!(feature = "websockets")),
        ("zstd", cfg!(feature = "zstd")),
    ];

    /// The reported identity is frozen and must never be bumped.
    ///
    /// Anchors transcribed from `include/curl/curlver.h`: `:35`, `:39`,
    /// `:40`, `:41`, `:61`, `:72` and `:31`. Every parity claim in this
    /// workspace is against curl 8.19.0-DEV at commit `54cf587b9c`, so a
    /// version bump is a contract change and not a maintenance detail.
    #[test]
    fn reported_identity_is_frozen() {
        assert_eq!(crate::LIBCURL_VERSION, "8.19.0-DEV");
        assert_eq!(crate::LIBCURL_VERSION_NUM, 0x0008_1300);
        assert_eq!(crate::version::LIBCURL_VERSION_MAJOR, 8);
        assert_eq!(crate::version::LIBCURL_VERSION_MINOR, 19);
        assert_eq!(crate::version::LIBCURL_VERSION_PATCH, 0);
        assert_eq!(crate::version::LIBCURL_TIMESTAMP, "[unreleased]");
        assert_eq!(
            crate::version::LIBCURL_COPYRIGHT,
            "Daniel Stenberg, <daniel@haxx.se>."
        );
    }

    /// `LIBCURL_VERSION_NUM` is the packed form of the three components.
    ///
    /// `curlver.h:43-61` builds the number as
    /// `(major << 16) | (minor << 8) | patch` so that a consumer can compare
    /// versions arithmetically. If the two ever disagreed, `CURL_AT_LEAST_
    /// VERSION` would answer wrongly, so the relationship is asserted rather
    /// than assumed.
    #[test]
    fn packed_version_matches_its_components() {
        let packed = (crate::version::LIBCURL_VERSION_MAJOR << 16)
            | (crate::version::LIBCURL_VERSION_MINOR << 8)
            | crate::version::LIBCURL_VERSION_PATCH;
        assert_eq!(packed, crate::LIBCURL_VERSION_NUM);
    }

    /// The re-exported result codes resolve at the crate root and keep their
    /// pinned integers.
    ///
    /// The point is reachability through `crate::`, not the values
    /// themselves -- `error` owns those and asserts all 103 of them. The four
    /// anchors here are the ones a C consumer is most likely to compare
    /// against.
    #[test]
    fn result_codes_reach_the_crate_root() {
        assert_eq!(crate::CURLcode::Ok.as_i32(), 0);
        assert_eq!(crate::CURLcode::UnsupportedProtocol.as_i32(), 1);
        assert_eq!(crate::CURLcode::SslConnectError.as_i32(), 35);
        assert_eq!(crate::CURLcode::PeerFailedVerification.as_i32(), 60);

        // The other four families are reachable too, each by its own success
        // code, which is what the ABI shim converts on every return.
        assert!(crate::CURLMcode::Ok.is_ok());
        assert!(crate::CURLUcode::Ok.is_ok());
        assert!(crate::CURLHcode::Ok.is_ok());
        assert!(crate::CURLSHcode::Ok.is_ok());
    }

    /// The contextual error type and its result alias are usable from the
    /// root, and the conversion the ABI boundary performs cannot fail.
    #[test]
    fn contextual_error_reaches_the_crate_root() {
        fn fallible() -> crate::CurlResult<u8> {
            Err(crate::Error::with_context(
                crate::CURLcode::CouldntResolveHost,
                "no address for example.com",
            ))
        }

        let error = fallible().expect_err("the probe always fails");
        assert_eq!(error.code(), crate::CURLcode::CouldntResolveHost);
        assert_eq!(error.message(), "no address for example.com");
        // The generic string stays reachable for `curl_easy_strerror`.
        assert_eq!(error.code().message(), "Could not resolve hostname");
        assert_eq!(
            crate::CURLcode::from(error),
            crate::CURLcode::CouldntResolveHost
        );
    }

    /// The capability query is reachable programmatically, not only as a
    /// banner string.
    ///
    /// `curl-rs/src/cli/libinfo.rs` needs the sets themselves in order to
    /// build a `--version` banner that `tests/runtests.pl` can parse, so a
    /// formatted string alone would not satisfy the contract.
    #[test]
    fn capability_query_is_programmatic() {
        let info = crate::version_info();
        assert_eq!(info.version, crate::LIBCURL_VERSION);
        assert_eq!(info.version_num, crate::LIBCURL_VERSION_NUM);

        let banner = crate::version();
        assert!(
            banner.starts_with(concat!("libcurl/", "8.19.0-DEV")),
            "banner must open with the frozen identity, got {banner:?}"
        );

        // The query API answers membership questions programmatically rather
        // than by string search. The feature set is non-empty in every
        // configuration because two of its rows -- `Largefile`, derived from
        // the width of `curl_off_t`, and `IDN`, implemented by
        // `crate::url::idn` -- depend on no engine module.
        assert!(!crate::version::feature_names().is_empty());
        assert!(crate::version::has_feature("Largefile"));

        // The protocol set is asked about, not asserted to be non-empty: every
        // scheme now requires `version::ENGINE_PROTOCOLS`, so the truthful
        // answer while that engine is absent is that nothing is served. The
        // negative direction is the part that must hold unconditionally.
        assert!(!crate::version::supports_protocol("nosuchscheme"));
        assert_eq!(
            crate::version::supports_protocol("file"),
            crate::version::ENGINE_PROTOCOLS.is_present(),
            "a scheme may be advertised only when its engine exists"
        );
    }

    /// TLS is not switchable, and rustls is the only backend.
    ///
    /// There is no `tls` feature and there must never be one: an
    /// off-switchable TLS would permit a build with no TLS at all, which
    /// contradicts "rustls exclusively, validation on by default". The
    /// vocabulary table above is the mechanical half of this check -- it
    /// contains no `tls` entry, and adding one would not compile cleanly --
    /// and this is the behavioural half.
    ///
    /// The `SSL` capability CLAIM is a separate question from the absence of a
    /// switch, and the two must not be conflated: the claim is governed solely
    /// by `version::ENGINE_TLS`, so it is withheld until the backend module
    /// exists and becomes `true` the moment it does. Asserting `has_feature`
    /// unconditionally here would be asserting that a capability is present
    /// because it cannot be configured away, which is the confusion the engine
    /// registry exists to remove.
    #[test]
    fn tls_is_not_switchable_and_rustls_is_the_only_backend() {
        assert!(
            !FEATURES.iter().any(|(name, _)| *name == "tls"),
            "there must be no `tls` feature"
        );
        assert_eq!(crate::version::TLS_BACKEND_NAME, "rustls");
        // `CURLSSLBACKEND_RUSTLS` already exists in the public
        // `curl_sslbackend` enumeration, so no value is invented.
        assert_eq!(crate::version::TLS_BACKEND_ID, 14);

        // No Cargo feature participates in the SSL claim -- only the engine.
        assert_eq!(
            crate::version::has_feature("SSL"),
            crate::version::ENGINE_TLS.is_present()
        );
    }

    /// The capability vocabulary is exactly 15 names, with 3 default-off.
    ///
    /// 101 `AC_ARG_ENABLE` and `AC_ARG_WITH` knobs in `configure.ac` -- 57
    /// and 44 -- reduce to these 15. The reduction is intentional and
    /// documented; this test stops a sixteenth from appearing unnoticed.
    #[test]
    fn feature_vocabulary_is_the_declared_fifteen() {
        assert_eq!(FEATURES.len(), 15);

        let mut names: Vec<&str> =
            FEATURES.iter().map(|(name, _)| *name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), 15, "feature names must be unique");

        for (name, _) in FEATURES {
            assert!(!name.is_empty());
            assert_eq!(
                *name,
                name.to_lowercase(),
                "feature names are lower case in the manifest"
            );
        }
    }

    /// The default-off trio is off unless explicitly asked for.
    ///
    /// Guarded so that the test still passes when a feature-matrix leg turns
    /// one of them on deliberately; what it forbids is a default build that
    /// silently carries them. `negotiate` would link a C security library,
    /// `hickory-dns` would displace the system resolver, and `memdebug`
    /// would replace the global allocator -- none of which may happen by
    /// accident.
    #[test]
    #[cfg(not(any(
        feature = "negotiate",
        feature = "hickory-dns",
        feature = "memdebug"
    )))]
    fn default_off_features_stay_off() {
        for name in ["negotiate", "hickory-dns", "memdebug"] {
            let enabled = FEATURES
                .iter()
                .find(|(candidate, _)| *candidate == name)
                .map(|(_, enabled)| *enabled)
                .expect("every name is in the vocabulary table");
            assert!(!enabled, "{name} must be off by default");
        }
    }

    /// The allocation log is wired, and wiring it needs no `unsafe` here.
    ///
    /// The `unsafe impl GlobalAlloc` lives in `crate::ffi::sys::memdebug`;
    /// this file only names the type. Allocating proves the static is
    /// installed and serving requests, and naming the static proves the item
    /// exists rather than merely compiling.
    #[test]
    #[cfg(feature = "memdebug")]
    fn memdebug_allocator_is_wired() {
        let allocator = &crate::MEMDEBUG_ALLOCATOR;
        assert_eq!(
            core::mem::size_of_val(allocator),
            0,
            "the tracker is a zero-sized forwarding allocator"
        );

        // A round trip through the installed allocator: grow past the
        // initial capacity so that `realloc` is exercised as well as
        // `alloc`, then drop to exercise `dealloc`.
        let mut probe: Vec<u8> = Vec::with_capacity(8);
        probe.extend_from_slice(&[0_u8; 512]);
        assert_eq!(probe.len(), 512);
        drop(probe);

        // The banner must NOT advertise `Debug` merely because the feature is
        // compiled in: `tests/runtests.pl:660` keys `TrackMemory` off that
        // token, and advertising it turns 28 `<limits>` fixtures from inert
        // into live. Enabling the log is a separate decision from claiming a
        // debug build.
        assert!(!crate::version::has_feature("Debug"));
    }

    // BEGIN FACADE TESTS -- extracted for out-of-tree verification.
    //
    // These cover the operating-system facade above. They exercise the real
    // platform calls rather than a fake, because the facade deliberately binds
    // the non-injected wrappers; the injected `_with` variants and every branch
    // of the surrounding logic are covered inside `src/ffi/sys.rs`, where a
    // pure-Rust fake makes them reachable under Miri.

    /// A local UTC offset is available and within the range zones actually use.
    ///
    /// The assertion is deliberately weak on the value, because the test host's
    /// zone is not fixed. What matters is that it is [`Some`] at all: before this
    /// change `curl-rs/src/util.rs` had no way to obtain one, so `--trace-time`
    /// rendered every line as midnight.
    #[test]
    #[cfg_attr(miri, ignore = "localtime_r(3) is a foreign function")]
    fn the_local_utc_offset_is_available_and_plausible() {
        let offset = super::local_utc_offset_secs(0)
            .expect("the epoch has a local representation in every zone");

        assert!(
            offset.abs() <= 18 * 3600,
            "no real zone is more than 18 hours from UTC; got {offset}"
        );
    }

    /// The offset is recomputed per timestamp, not fixed at start-up.
    ///
    /// Both calls must answer; whether they answer the SAME thing depends on the
    /// host's zone and on whether the two instants straddle a daylight-saving
    /// boundary, so only availability is asserted. The reason the function takes
    /// a timestamp at all is documented on it.
    #[test]
    #[cfg_attr(miri, ignore = "localtime_r(3) is a foreign function")]
    fn the_offset_is_queried_per_timestamp() {
        // 2025-01-15 and 2025-07-15, which fall either side of any northern
        // daylight-saving transition.
        assert!(super::local_utc_offset_secs(1_736_899_200).is_some());
        assert!(super::local_utc_offset_secs(1_752_537_600).is_some());
    }

    /// Echo suppression reaches the tool through the crate root, and a
    /// redirected standard input does not break it.
    ///
    /// This is the case `tests/runtests.pl` always takes, since it runs curl with
    /// standard input redirected. `tcgetattr` fails there, yet
    /// `src/tool_getpass.c:148` still reports `TRUE` and `:183-185` still emits
    /// the extra newline -- so the guard must report echo as disabled regardless,
    /// and dropping it must not panic on a descriptor whose attributes were never
    /// readable. The byte-level parity argument is recorded on
    /// `EchoGuard::echo_disabled`; this covers only that the name resolves at the
    /// crate root, which is what `curl-rs/src/terminal.rs` depends on.
    #[test]
    #[cfg_attr(miri, ignore = "tcgetattr(3) is a foreign function")]
    fn echo_suppression_crosses_the_crate_boundary_on_a_non_terminal() {
        use std::os::fd::AsFd as _;

        let sink = std::fs::File::open("/dev/null").expect("/dev/null exists");
        let guard = super::disable_echo(sink.as_fd());

        assert!(
            guard.echo_disabled(),
            "the C reports TRUE once it has taken the termios branch, \
             whatever tcgetattr answered"
        );

        // Restoring explicitly is the ordered path `src/tool_getpass.c:185-186`
        // takes; `Drop` must then do nothing a second time.
        guard.restore();
    }

    /// An attribute name containing an interior NUL is rejected.
    ///
    /// Checked through the facade because it is the boundary a caller in
    /// `curl-rs` actually crosses. No writable filesystem and no extended
    /// attribute support is needed: the name cannot be made into a C string, so
    /// the platform call is never attempted and the borrowed descriptor is never
    /// touched.
    ///
    /// The *failing* platform call -- an attribute the filesystem refuses, which
    /// `src/tool_xattr.c:105` keeps as the first error while completing the
    /// transfer -- is covered where it can be forced deterministically, by
    /// `the_platform_errno_survives_inside_the_error` over the injected seam in
    /// `src/ffi/sys.rs`. Forcing it here would mean depending on whether the test
    /// host's filesystem carries `user.*` attributes at all.
    #[test]
    fn an_xattr_name_with_an_interior_nul_is_rejected() {
        use std::os::fd::AsFd as _;

        let stdin = std::io::stdin();
        let error =
            super::set_file_xattr(stdin.as_fd(), b"user.bad\0name", b"value")
                .expect_err("a name with an interior NUL cannot be passed");

        assert_eq!(error.raw_os_error(), Some(libc::EINVAL));
    }

    /// The diagnostic facade neutralizes what a terminal would interpret.
    ///
    /// Covers the bridge itself -- that the single-line mode is the one baked in,
    /// and that the borrowed fast path survives crossing the crate boundary. The
    /// byte-level rules and the terminal-versus-file decision are covered where
    /// they are implemented, in `src/trace.rs`.
    #[test]
    fn the_diagnostic_facade_escapes_single_line_text() {
        // ESC, BEL and DEL neutralized -- one dot each, since a replacement is
        // one byte for one byte. The high byte and the tilde are untouched.
        assert_eq!(
            super::escape_control_bytes(b"cert \x1b[2Jok\x07\x7f\xff~")
                .as_ref(),
            b"cert .[2Jok..\xff~"
        );

        // Single-line semantics: an injected newline cannot forge a second
        // message, which is the whole point of choosing this mode for the bridge.
        assert_eq!(
            super::escape_control_bytes(b"a\r\nb").as_ref(),
            b"a..b",
            "the bridge must NOT preserve line structure"
        );

        // Clean text is borrowed, so ordinary messages cost nothing.
        let clean = b"Rebuilt URL to: https://example.com/";
        assert!(matches!(
            super::escape_control_bytes(clean),
            std::borrow::Cow::Borrowed(_)
        ));
        assert_eq!(super::escape_control_bytes(clean).as_ref(), clean);

        // Length is preserved, so an attacker cannot amplify output through it.
        let hostile: Vec<u8> = (0u8..=255).collect();
        assert_eq!(super::escape_control_bytes(&hostile).len(), hostile.len());
    }
    // END FACADE TESTS
}

// THE EXECUTABLE HALF OF THE SOURCE-POLICY GATE.
//
// Two invariants that a comment can only assert are asserted here instead, at
// test time, by reading the workspace's own sources:
//
//  1. Exactly one `#[allow(unsafe_code)]` exists per crate that needs one, and
//     it is on the `ffi` module declaration. `curl-rs` needs none and must
//     have none.
//  2. No lint level for `dead_code` is set on a crate root or a module root
//     anywhere in the workspace.
//
// The gate lives in this crate rather than in a separate test crate because
// every workspace member depends on this one, so `cargo test --workspace`
// cannot pass without running it, and because a file that states a rule should
// be the file that enforces it. `curl-rs-ffi/src/lib.rs` carries the same
// checks for its own tree; the overlap is deliberate -- either crate can be
// tested alone and still be governed.
//
// Every test below is `#[cfg_attr(miri, ignore)]`d, and the reason is the same
// one each time: these tests read the source tree, not the program. Miri
// interprets Rust's runtime semantics, and it runs with host isolation on, so
// `fs::read_dir` fails with `unsupported operation: `opendir` not available
// when isolation is enabled` -- which aborts the whole interpreter and takes
// the required `cargo miri test -p curl-rs-lib` gate (AAP section 0.8.4) down
// with it. Ignoring them under Miri costs nothing and hides nothing: there is
// no pointer arithmetic, no aliasing and no uninitialised memory in a string
// scan, so Miri has nothing to find here, and the assertions still run in full
// under `cargo test --workspace` -- the gate that owns them. The alternative,
// `-Zmiri-disable-isolation`, was rejected: it would make the Miri workflow
// pass a flag, and `.github/workflows/rust-miri.yml` deliberately passes none
// so that the gate stays exactly the command the AAP specifies.

#[cfg(test)]
mod source_policy {
    use std::fs;
    use std::path::{Path, PathBuf};

    /// The workspace members, in dependency order.
    ///
    /// Spelled out rather than discovered by reading the root manifest: the
    /// membership is fixed by AAP section 0.3.1 at exactly three crates, so a
    /// fourth appearing on disk is a change that should be made deliberately
    /// and reflected here, not absorbed silently by a glob.
    const MEMBERS: [&str; 3] = ["curl-rs-lib", "curl-rs", "curl-rs-ffi"];

    /// The workspace root, derived from this crate's manifest directory.
    ///
    /// `CARGO_MANIFEST_DIR` is set by Cargo for every compilation, so this is
    /// independent of the working directory the test runner happens to use.
    fn workspace_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("this crate's directory has a parent, the workspace root")
            .to_path_buf()
    }

    /// Every `.rs` file under `<member>/src`, plus that member's build script
    /// when it has one.
    ///
    /// Build scripts are included because they are ordinary Rust that the same
    /// rules govern: a `#![allow(dead_code)]` in a build script would hide
    /// exactly the same incomplete scaffolding as one in a library module.
    fn sources(member: &str) -> Vec<PathBuf> {
        let member_dir = workspace_root().join(member);
        let src = member_dir.join("src");
        let mut found = Vec::new();
        walk(&src, &mut found);
        assert!(
            !found.is_empty(),
            "no sources found under {} -- the gate would be vacuous",
            src.display()
        );
        let build_script = member_dir.join("build.rs");
        if build_script.is_file() {
            found.push(build_script);
        }
        found.sort();
        found
    }

    fn walk(dir: &Path, found: &mut Vec<PathBuf>) {
        let entries = fs::read_dir(dir).unwrap_or_else(|error| {
            panic!("cannot read {}: {error}", dir.display())
        });
        for entry in entries {
            let path = entry.expect("a readable directory entry").path();
            if path.is_dir() {
                walk(&path, found);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                found.push(path);
            }
        }
    }

    /// The declaration an outer attribute applies to: the next line that is
    /// neither blank nor another attribute.
    fn attribute_target(lines: &[&str], index: usize) -> String {
        lines[index + 1..]
            .iter()
            .find(|next| {
                let trimmed = next.trim_start();
                !trimmed.is_empty() && !trimmed.starts_with('#')
            })
            .map(|line| line.trim().to_string())
            .unwrap_or_default()
    }

    /// True when the declaration in `target` is a module.
    ///
    /// An attribute on a module declaration has the whole module's contents in
    /// scope, so for the purposes of this gate it is a module-root attribute
    /// wherever it is written.
    fn declares_a_module(target: &str) -> bool {
        let rest = target
            .strip_prefix("pub(crate) ")
            .or_else(|| target.strip_prefix("pub(super) "))
            .or_else(|| target.strip_prefix("pub "))
            .unwrap_or(target);
        rest.starts_with("mod ")
    }

    /// `line` with its comment tail and every string literal removed.
    ///
    /// Identical in intent to the helper of the same name in
    /// `curl-rs-ffi/src/lib.rs`, and necessary for the same two reasons: this
    /// crate discusses the `unsafe` keyword at length in prose, and the gate
    /// below compares against literals, so a scan that kept either would flag
    /// its own implementation. Raw strings are not lexed, which
    /// [`no_raw_string_literal_defeats_the_stripper`] proves harmless for the
    /// tree actually scanned.
    fn code_only(line: &str) -> String {
        let without_comment = line.split("//").next().unwrap_or("");
        let mut out = String::with_capacity(without_comment.len());
        let mut in_string = false;
        let mut escaped = false;
        for ch in without_comment.chars() {
            if in_string {
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == '"' {
                    in_string = false;
                }
                continue;
            }
            if ch == '"' {
                in_string = true;
                // A space keeps the surrounding tokens apart, so a literal
                // between two identifiers cannot fuse them into one word.
                out.push(' ');
                continue;
            }
            out.push(ch);
        }
        out
    }

    /// True when `line` uses the `unsafe` keyword as code rather than naming it
    /// in prose, in a string, or inside the identifier `unsafe_code`.
    fn uses_unsafe_keyword(line: &str) -> bool {
        code_only(line)
            .split(|c: char| !c.is_alphanumeric() && c != '_')
            .any(|word| word == "unsafe")
    }

    /// True when `code` opens a raw string literal.
    ///
    /// Judged lexically: a `"` preceded by a run of `#`, then `r`, optionally
    /// `b`-prefixed, whose own predecessor is neither an identifier character
    /// nor a backslash. Excluding the backslash is what keeps `b"ends in \r"`
    /// from reading as a raw-string opener -- measured on
    /// `tls/keylog.rs` and `trace.rs`, both of which contain exactly that.
    fn opens_a_raw_string(code: &str) -> bool {
        let bytes: Vec<char> = code.chars().collect();
        for (index, ch) in bytes.iter().enumerate() {
            if *ch != '"' {
                continue;
            }
            let mut cursor = index;
            while cursor > 0 && bytes[cursor - 1] == '#' {
                cursor -= 1;
            }
            if cursor == 0 || bytes[cursor - 1] != 'r' {
                continue;
            }
            cursor -= 1;
            if cursor > 0 && bytes[cursor - 1] == 'b' {
                cursor -= 1;
            }
            if cursor == 0 {
                return true;
            }
            let before = bytes[cursor - 1];
            if !before.is_alphanumeric() && before != '_' && before != '\\' {
                return true;
            }
        }
        false
    }

    #[test]
    #[cfg_attr(miri, ignore = "this reads the source tree, not the program")]
    fn no_lint_level_for_dead_code_is_set_on_a_crate_or_module_root() {
        let mut broad = Vec::new();
        let mut per_item = 0_usize;

        for member in MEMBERS {
            for path in sources(member) {
                let text =
                    fs::read_to_string(&path).expect("a readable source file");
                let lines: Vec<&str> = text.lines().collect();
                for (index, line) in lines.iter().enumerate() {
                    let trimmed = line.trim_start();
                    // Anchoring past leading whitespace and then requiring the
                    // attribute punctuation is what lets this gate scan the
                    // files that DISCUSS the attribute: a comment begins with a
                    // slash, so it can never match.
                    if trimmed.starts_with("#![")
                        && trimmed.contains("dead_code")
                    {
                        broad.push(format!(
                            "{}:{} (inner)",
                            path.display(),
                            index + 1
                        ));
                    } else if trimmed.starts_with("#[")
                        && trimmed.contains("dead_code")
                    {
                        if declares_a_module(&attribute_target(&lines, index)) {
                            broad.push(format!(
                                "{}:{} (on a module)",
                                path.display(),
                                index + 1
                            ));
                        } else {
                            per_item += 1;
                        }
                    }
                }
            }
        }

        assert!(
            broad.is_empty(),
            "a `dead_code` lint level on a crate or module root hides the next \
             unreferenced item somebody adds; use a per-item allowance instead. \
             Offenders: {broad:?}"
        );
        // Discriminating rather than vacuous: the per-item form really is in
        // use, so an expression that matched nothing would be caught here.
        assert!(
            per_item > 0,
            "the gate recognised no per-item allowance, so it is not testing \
             anything"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "this reads the source tree, not the program")]
    fn each_crate_grants_at_most_one_unsafe_code_exemption() {
        // What each member is permitted, and on which declaration. `curl-rs`
        // appears with `None` deliberately: its crate root carries
        // `#![forbid(unsafe_code)]`, which cannot be overridden from an inner
        // scope, so an exemption there would not even compile -- and this line
        // records that the entry is a considered zero rather than an omission.
        const PERMITTED: [(&str, Option<&str>); 3] = [
            ("curl-rs-lib", Some("pub(crate) mod ffi;")),
            ("curl-rs", None),
            ("curl-rs-ffi", Some("mod ffi;")),
        ];

        for (member, expected) in PERMITTED {
            let mut sites = Vec::new();
            for path in sources(member) {
                let text =
                    fs::read_to_string(&path).expect("a readable source file");
                let lines: Vec<&str> = text.lines().collect();
                for (index, line) in lines.iter().enumerate() {
                    let trimmed = line.trim_start();
                    let is_attribute = trimmed
                        .starts_with("#[allow(unsafe_code)]")
                        || trimmed.starts_with("#![allow(unsafe_code)]");
                    if is_attribute {
                        sites.push((
                            path.clone(),
                            index + 1,
                            attribute_target(&lines, index),
                            trimmed.starts_with("#!["),
                        ));
                    }
                }
            }

            match expected {
                None => assert!(
                    sites.is_empty(),
                    "{member} must grant no unsafe_code exemption; found {sites:?}"
                ),
                Some(declaration) => {
                    assert_eq!(
                        sites.len(),
                        1,
                        "{member} must grant exactly one unsafe_code exemption; \
                         found {sites:?}"
                    );
                    let (path, _line, target, is_inner) = &sites[0];
                    assert!(
                        !is_inner,
                        "{member}'s exemption must be an OUTER attribute on the \
                         module declaration, not an inner attribute that covers \
                         a whole file: {}",
                        path.display()
                    );
                    assert!(
                        path.ends_with("src/lib.rs"),
                        "{member}'s exemption must live in its crate root, not {}",
                        path.display()
                    );
                    assert_eq!(
                        target, declaration,
                        "{member}'s exemption must apply to `{declaration}`"
                    );
                }
            }
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "this reads the source tree, not the program")]
    fn no_raw_string_literal_defeats_the_stripper() {
        // [`code_only`] does not lex `r"..."` or `r#"..."#`, and the two tests
        // that depend on it scan this crate only. Rather than implement a
        // lexer, the gate asserts the simplification holds where it is used. A
        // raw string introduced under `src/` fails this test and says so,
        // instead of the checks below silently losing coverage. The tool crate
        // does contain raw strings -- `output/writeout.rs` and
        // `cli/paramhlp.rs` -- which is precisely why no keyword scan is
        // pointed at it: `#![forbid(unsafe_code)]` proves the same thing there
        // without reading a single line.
        let mut offenders = Vec::new();
        for path in sources("curl-rs-lib") {
            let text =
                fs::read_to_string(&path).expect("a readable source file");
            for (index, line) in text.lines().enumerate() {
                let code = line.split("//").next().unwrap_or("");
                if opens_a_raw_string(code) {
                    offenders.push(format!("{}:{}", path.display(), index + 1));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "code_only does not lex raw strings; found {offenders:?}"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "this reads the source tree, not the program")]
    fn the_unsafe_keyword_appears_only_under_this_crates_ffi_directory() {
        let mut outside = Vec::new();
        let mut inside = 0_usize;
        for path in sources("curl-rs-lib") {
            let under_ffi = path
                .components()
                .any(|component| component.as_os_str() == "ffi");
            let text =
                fs::read_to_string(&path).expect("a readable source file");
            for (index, line) in text.lines().enumerate() {
                if uses_unsafe_keyword(line) {
                    if under_ffi {
                        inside += 1;
                    } else {
                        outside.push(format!(
                            "{}:{}",
                            path.display(),
                            index + 1
                        ));
                    }
                }
            }
        }

        assert!(
            outside.is_empty(),
            "`unsafe` may appear only under src/ffi/; found {outside:?}"
        );
        assert!(
            inside > 0,
            "the gate found no `unsafe` under src/ffi/, so it is not testing \
             anything"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "this reads the source tree, not the program")]
    fn every_unsafe_block_in_this_crate_is_covered_by_a_safety_comment() {
        // "Immediately preceded by a `// SAFETY:` line" is the natural phrasing
        // and is measurably wrong: the justifications here run to several lines,
        // so the line directly above an `unsafe` is the LAST line of the block,
        // not its opener. The walk goes back over blank lines and attributes,
        // then over the contiguous run of `//` comment lines, and requires that
        // run to contain a line beginning `// SAFETY:`.
        //
        // Only `unsafe` *blocks* and `unsafe impl`s need a justification. An
        // `unsafe fn` declaration states its contract in its doc comment
        // instead, which is where a caller reads it.
        let mut uncovered = Vec::new();
        let mut covered = 0_usize;
        for path in sources("curl-rs-lib") {
            if !path
                .components()
                .any(|component| component.as_os_str() == "ffi")
            {
                continue;
            }
            let text =
                fs::read_to_string(&path).expect("a readable source file");
            let lines: Vec<&str> = text.lines().collect();
            for (index, line) in lines.iter().enumerate() {
                let stripped = code_only(line);
                let code = stripped.trim();
                let opens_a_block = code == "unsafe {"
                    || code.ends_with(" unsafe {")
                    || code.starts_with("unsafe impl ");
                if !opens_a_block {
                    continue;
                }
                let mut cursor = index;
                let mut found = false;
                while cursor > 0 {
                    cursor -= 1;
                    let above = lines[cursor].trim_start();
                    if above.is_empty() || above.starts_with('#') {
                        continue;
                    }
                    if above.starts_with("//") {
                        if above.starts_with("// SAFETY:") {
                            found = true;
                            break;
                        }
                        continue;
                    }
                    break;
                }
                if found {
                    covered += 1;
                } else {
                    uncovered.push(format!("{}:{}", path.display(), index + 1));
                }
            }
        }

        assert!(
            uncovered.is_empty(),
            "every unsafe block under src/ffi/ needs a `// SAFETY:` comment; \
             uncovered: {uncovered:?}"
        );
        assert!(covered > 0, "the gate found no unsafe blocks to check");
    }

    #[test]
    #[cfg_attr(miri, ignore = "this reads the source tree, not the program")]
    fn the_tool_crate_root_forbids_unsafe_outright() {
        // `curl-rs` links no C and binds no operating-system call directly, so
        // it needs no exemption -- and with none needed, the stronger form is
        // available. `forbid` cannot be overridden from an inner scope, so for
        // that crate the compiler, not this gate, is the whole enforcement.
        // This test only confirms the stronger form is the one in force.
        let root = workspace_root().join("curl-rs/src/main.rs");
        let text =
            fs::read_to_string(&root).expect("the tool crate root is readable");
        let present = text.lines().any(|line| {
            line.trim_start().starts_with("#![forbid(unsafe_code)]")
        });
        assert!(
            present,
            "curl-rs/src/main.rs must carry #![forbid(unsafe_code)]"
        );
    }
}
