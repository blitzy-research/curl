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
// `#![deny(unsafe_code)]` accepts that one exemption and still makes the same
// `unsafe` a hard error in every module other than `ffi`. One gap remains, and
// it is stated rather than glossed over: `deny`, unlike `forbid`, CAN be
// overridden from an inner scope, so a module outside `ffi` that wrote its own
// `#[allow(unsafe_code)]` would compile. The compiler enforces the invariant
// against accident but not against a second deliberate exemption, which is why
// the gate below is load-bearing rather than decoration.
//
//   1. Exactly one exemption exists, and it is in this file, on `mod ffi`:
//
//      must print exactly one line. Anchoring past indentation only is what
//      excludes every `//`, `///` and `//!` line: a comment begins with a
//      slash, so it can never match.
//
//   2. No `unsafe` keyword lives outside the sanctioned directory:
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
#![deny(unsafe_code)]

//! curl and libcurl: the protocol engine, in safe Rust.
//!
//! Its section numbers are stable, and a citation marks a decision the
//! specification fixes rather than one this code is free to change.
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

// FEATURE-SET NOTE -- the one declared name with no crate behind it.
//
// The feature therefore EXISTS, is default-off, BUILDS, and advertises
// nothing. It carries no dependency, and the option space that explains why
// was measured from the registry index, sorted by parsed semantic version.
// The two halves are disjoint:
//
// The advisory could not have been confined to the feature either, because
// cargo-deny and cargo-audit read `Cargo.lock` rather than the active
// feature set: wiring 0.25.2 as `optional = true` made `cargo deny check`
// report `advisories FAILED` on a DEFAULT build with the feature off. That
// was measured, not predicted.
//
//   * A bare `hickory-dns = []` cfg switch that the banner still keys off.
//     WRONG: enabling it adds `hickory-resolver/0.25.2` to the banner while no
//     resolver in the graph uses it.
//   * `compile_error!` on the feature. Also wrong. It converts a DECLARED
//     feature into a hard build failure, which makes `--all-features`
//     impossible for a workspace whose
//     own `deny.toml` sets `all-features = true`, forces four workflows to
//     enumerate fourteen feature names in lockstep instead, and breaks
//     `rust-audit.yml`'s check that an enabled feature actually resolves
//     something. A declared-but-unbuildable feature is a defect in its own
//     right, not a safety measure.
//   * `configured && implementation_ready`, which is the rule this workspace
//     already applies to every other capability
//     (`version.rs`: `compiled_in = configured && engine.is_present()`).
//     `ENGINE_DNS` is `Engine::inert("curl-rs-lib/src/dns/resolver.rs")` --
//     the module is on disk, and what it lacks is a caller -- so
//     `version_parts` withholds the resolver token no matter how the feature
//     is set, and the feature compiles to nothing observable. This is
//     under-reporting, which is safe.
//
// The third is what is implemented. The feature is a reserved NAME whose
// engine cannot execute, recorded in exactly the same registry as the other
// twenty-two unavailable capabilities rather than in a special case here.
//
// Wire the dependency in the root manifest, and flip `ENGINE_DNS` to
// `working`, when a hickory-resolver release exists whose hickory-proto
// requirement admits >= 0.26.1 AND whose declared rust-version satisfies
// this workspace's floor. Nothing in this file needs to change then.

// MODULE INVENTORY -- 9 declarations, with the rest of the graph mapped below.
//
// ORDER is dependency order, not alphabetical: `error` first because every
// other module returns its types, then the two other leaves, then the
// utility and platform layers, then the subsystems that build on them, and
// finally the three handle interfaces that the C ABI exposes. It is a
// topological ordering of the module graph, not a schedule: every module
// lands together.

/// Result codes: the type foundation of the crate.
///
/// `pub` because the codes cross the C ABI unchanged and because
/// `curl-rs-ffi`'s `curl_easy_strerror`, `curl_multi_strerror`,
/// `curl_share_strerror` and `curl_url_strerror` are thin adapters over the
/// message accessors declared here -- the four C functions do not even share
/// one unknown-value fallback, so all four strings live in this one module.
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
pub mod version;

/// Trace, verbose and error-buffer output.
///
/// Supersedes `lib/curl_trc.c`. The `--trace`, `--trace-ascii`,
/// `--trace-config` and `CURLOPT_DEBUGFUNCTION` layouts are frozen output,
/// so this module reproduces C's record shapes byte for byte, including
/// where the identifier block sits relative to the two-character kind
/// prefix -- which differs between a stream sink and a user callback.
pub(crate) mod trace;

/// The portability and utility layer.
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
#[allow(unsafe_code)]
pub(crate) mod ffi;

/// Cryptographic primitives.
pub(crate) mod crypto;

/// The URL API, percent-encoding and internationalised domain names.
///
/// Supersedes `lib/urlapi.c`, `lib/escape.c` and `lib/idn.c`. curl's parsing
/// quirks are preserved rather than delegated wholesale to a general-purpose
/// URL crate, because the quirks are observable through the API and through
/// the fixture corpus.
pub mod url;

/// TLS -- rustls, and rustls only.
///
/// **Declared unconditionally.** There is no `tls` feature and there must
/// never be one; see the crate documentation above for why, and for the
/// measurement showing that writing `feature = "tls"` is itself a build
/// failure. Certificate validation is on by default; `--insecure` must warn
/// on standard error before proceeding, which means the "peer verification
/// disabled" state has to be readable from outside this crate -- it is
/// surfaced through the option and handle surface of the `easy` module
/// rather than by widening this declaration.
pub(crate) mod tls;

/// The multi interface: many transfers, one driver.
pub mod multi;

/// Name resolution: the DNS cache, the address types and the resolver seam.
///
/// This is where the migration retires the single most hazardous construct
/// in the C tree: `lib/hostip.c` bounds a blocking lookup with `alarm()`
/// plus `sigsetjmp`/`siglongjmp`, a non-local jump out of a signal handler
/// across allocation boundaries, guarded by a process-global `sigjmp_buf`
/// behind a spinlock. `tokio::time::timeout` replaces all of it, and the
/// thread abstraction of `lib/curl_threads.c` is subsumed by the runtime.
pub(crate) mod dns;

/// Connection establishment, the filter chain and socket readiness.
pub(crate) mod conn;

/// The easy interface: one handle, one transfer.
///
/// The option table is NOT declared here. `curl-rs-ffi` is the sole source of
/// truth for the 308 `CURLoption` identifiers, their backward-compatibility
/// aliases and the `curl_easyoption` metadata array behind
/// `curl_easy_option_by_name`, `_by_id` and `_next`; this module CONSUMES that
/// table. Two tables would drift, and the drift would stay invisible until a
/// consumer queried an option by name and received the wrong identifier. The
/// consumption happens in `easy::options`, which owns the lookup algorithm and
/// the option-identity vocabulary and owns no rows -- and which takes the table
/// as an argument, because the crate that holds it depends on this one and this
/// one may never name it.
pub mod easy;

/// Header storage and the header-inspection API.
///
/// `pub` because it backs four of the 100 exported symbols: the
/// `curl_easy_header` and `curl_easy_nextheader` pair, and
/// `curl_pushheader_byname` with `curl_pushheader_bynum`. The `curl_header`
/// struct those fill is layout-visible to callers, so its field order and
/// types are frozen; this module supplies the borrowed projection that fills
/// it, and `curl-rs-ffi` owns the `#[repr(C)]` mirror.
pub mod headers;

/// Persisted client state: the cookie jar, `.netrc`, HSTS and Alt-Svc.
pub(crate) mod cookies;

/// Authentication mechanism selection, vocabulary and shared plumbing.
pub(crate) mod auth;

/// The transfer core: the loop, its buffers and its accounting.
pub(crate) mod transfer;

/// The protocol implementations and the scheme registry.
///
/// The C tree defines and registers 33 URL schemes. Nine are implemented here;
/// the other 24 are registered for ABI completeness, return
/// `CURLE_UNSUPPORTED_PROTOCOL`, and are deliberately withheld from the
/// `Protocols:` banner so that the 283 fixtures targeting them skip cleanly
/// instead of running and failing. A note for anyone reading the C: the backing
/// array is declared `all_schemes[67]` at `lib/url.c:1488` but only 33 entries
/// are defined and registered -- the array is over-allocated, and 67 must not be
/// read as a count.
pub(crate) mod protocols;

/// Proxy support: tunnelling, SOCKS, the PROXY protocol header, and the
/// no-proxy predicate.
pub(crate) mod proxy;

/// MIME multipart bodies and the legacy form API.
///
/// `pub` because it backs 15 of the 100 exported symbols: the 12
/// `curl_mime_*` functions of `lib/libcurl.def:37-48`, and the three legacy
/// `curl_formadd`, `curl_formfree` and `curl_formget` entry points
/// (`:24-26`), which are deprecated in the documentation yet still exported
/// and therefore still part of the parity set.
pub mod mime;

/// State deliberately shared between easy handles.
///
/// Supersedes `lib/curl_share.c` and `lib/curl_share.h`. Cookie, DNS,
/// TLS-session, HSTS, Public-Suffix-List and connection state can be shared
/// across handles, with the caller's `CURLSHOPT_LOCKFUNC` and
/// `CURLSHOPT_UNLOCKFUNC` callbacks honoured at exactly the points the C
/// invokes them. C guards its own global initialization with the hand-rolled
/// `curl_simple_lock` of `lib/easy_lock.h` -- an `SRWLOCK` on Windows, an
/// `atomic_int` spin loop with `__builtin_ia32_pause` or an `aarch64`
/// `yield` where C11 atomics exist, a `pthread_mutex_t` otherwise, and no
/// thread safety at all when none of those is available -- and gives the
/// share itself no internal lock whatsoever, delegating that entirely to the
/// application's callbacks. Rust's `std::sync` primitives replace all four
/// cases, which is why the `threadsafe` capability is advertised
/// unconditionally, and they additionally give the share the interior
/// locking the C leaves to its caller.
pub mod share;

// MODULE MAP -- the remaining subsystems of the target design.

// Name resolution -- NOW DECLARED above as `pub(crate) mod dns;`, whose own
// documentation carries the detail this entry used to. It is kept in the map
// because the map enumerates the whole tree rather than only its unwritten
// part, which is the point of replacing `lib/Makefile.inc` with this file.
//
// Proxy support is no longer described here: it is DECLARED above, with its
// map entry promoted to the documentation on `pub(crate) mod proxy`, because
// the first of its children -- the `NO_PROXY` predicate of `lib/noproxy.c` --
// now exists. This map holds only the subsystems that have no file yet.
//
// MIME and the legacy form API are no longer described here either: they are
// DECLARED above as `pub mod mime`, which carries the detail this entry used
// to, because the multipart engine of `lib/mime.c` now exists -- and so, since
// that entry was written, does `formdata`, its child covering the three legacy
// `curl_form*` exports. Neither is reachable from a transfer yet, which is a
// wiring gap and not a missing file; `version.rs`'s `ENGINE_MIME` and
// `ENGINE_FORM` record it on those terms.
//
// The share interface is no longer described here either: it is DECLARED
// above as `pub mod share`, which carries the detail this entry used to,
// because `lib/curl_share.c`'s successor now exists. With it the map holds
// no unwritten subsystem at all -- every entry above names a module that is
// declared, and what remains unwritten is children of those modules rather
// than subsystems of their own.
//
// WHICH CHILDREN, measured against this checkout rather than left vague,
// because "children remain" is the kind of statement that survives long after
// it stops being true. TWO of the files AAP 0.4.1 assigns to this crate
// are not on disk, and both are the same child: `easy/{setopt,getinfo}.rs`.
// `easy/handle.rs` was the third and has LANDED: the decomposed easy handle,
// with `struct Curl_easy`'s 24 members apportioned to the modules that own
// their lifecycles, `Curl_init_userdefined`'s frozen defaults, the
// generational identity token and the four injected seams. What is still
// absent is the pair that WRITES an option onto a handle and READS a
// statistic off one, which is why every `run:` row below stays `None`.
// **No per-scheme executor is absent any more**, and neither
// `protocols/` nor `proxy/` has an absent file at all: `protocols/http3.rs`
// was the last of the executors and it has landed, and
// `proxy/http_connect.rs` was the last of the proxy mechanisms and it has
// landed too.
// Every other assigned file exists -- `protocols/file.rs`,
// `protocols/http1.rs`, `protocols/http2.rs`, `protocols/http3.rs`,
// `protocols/sftp.rs`,
// `protocols/scp.rs`, `protocols/stub.rs`, `protocols/ws.rs`,
// `protocols/ftp/pingpong.rs`,
// `transfer/chunked.rs`,
// `transfer/content_encoding.rs`, `proxy/socks.rs`,
// `proxy/haproxy.rs`, `proxy/socks_gss.rs` and `proxy/http_connect.rs` among
// them, which is why this count reads three and not the eighteen it once did,
// and why `protocols/`, `transfer/` and `proxy/` now all three have no absent
// file at all.
//
// `proxy/http_connect.rs` completes the proxy directory: it supersedes six C
// files -- `lib/http_proxy.{c,h}`, `lib/cf-h1-proxy.{c,h}` and
// `lib/cf-h2-proxy.{c,h}` -- with the three CONNECT filters the C registers,
// and it owns the `CONNECT` request bytes that 31 `<verify><proxy>` fixtures
// compare literally. Every proxy mechanism curl has is therefore written; none
// is REACHABLE, because no production `conn::ConnectionFilterFactories` exists
// to install a filter, and `version.rs`'s `ENGINE_PROXY` records that as
// `inert` rather than as `unwritten`.
//
// `protocols/file.rs` is worth its own sentence for the same reason
// `protocols/stub.rs` is, and for the opposite reason: it is the FIRST
// per-scheme EXECUTOR to land, superseding the whole of `lib/file.c` -- the
// URL-to-path decode, the synthesised `Content-Length:`, `Accept-ranges:` and
// `Last-Modified:` lines, `--range`, uploads with `--append`, the directory
// listing and every one of the five `CURLcode` values that file selects -- and
// it fills 5 of `struct Curl_protocol`'s 17 slots, which is the sparsest
// handler in the C tree and therefore the cheap proof that the trait's twelve
// defaults really do stand in for `ZERO_NULL`. What it does NOT do is make
// `file://` reachable: `protocols/mod.rs`'s `SCHEMES` is a `const` table, so
// it can hold neither a reference to a `static` nor a reference to
// interior-mutable data, and a handler that binds one transfer's state has
// both properties; `crate::transfer::TransferIo::xfer_ctx` borrows its owner
// mutably, so the transfer core cannot hand `do_it` a context AND the
// transfer-side seam. So `version.rs`'s `ENGINE_PROTOCOLS` stays inert and the
// `Protocols:` banner still withholds `file` -- a wiring gap between delivered
// files rather than an absent one, which is exactly the distinction this
// paragraph exists to keep.
//
//
// `protocols/sftp.rs` is the first per-scheme executor whose registry row is
// WIRED, and is worth naming for what it changes: the `SFTP` row of
// `protocols/mod.rs`'s registry now carries an implementation, so `Scheme::run`
// is no longer uniformly `None`, and `protocols/mod.rs`'s own
// `nothing_is_runnable_in_this_checkout` -- whose documentation said it was to
// be DELETED rather than edited by exactly this checkpoint -- has been
// deleted. That module also HOSTS the shared russh SSH session core, because
// `Curl_protocol_sftp` and `Curl_protocol_scp` are byte-identical in 14 of
// their 17 slots (`lib/vssh/libssh2.c:3846-3864` against `:3823-3841`) and AAP
// 0.4.1 names no third file to put it in; `protocols/scp.rs` will import it.
// What `sftp.rs` cannot yet do is reach a transfer's OPTIONS, because
// `easy/setopt.rs` is one of the three above, which is why
// `version.rs`'s `ENGINE_PROTOCOLS` stays inert and the `Protocols:` banner
// still withholds `sftp` -- under-reporting a capability makes a fixture skip
// and over-reporting makes it run and fail.
//
// `proxy/socks_gss.rs` is the first
// module in this crate that exists only behind a non-default feature: it is
// compiled when `negotiate` is on and is genuinely absent from the default
// build, which is the C's `#if defined(HAVE_GSSAPI)` and not a gap. That
// distinction is what `version.rs`'s engine registry records per capability,
// and `curl-rs/src/bin/curlinfo.rs` checks each of its claims against the tree.
//
// `protocols/http1.rs` is worth a paragraph of its own, because it is the
// largest of these landings and the one most likely to be misread as making
// HTTP work. It carries the whole of `lib/http.c`'s request writer -- the
// 20-slot default header order of `lib/http.c:2827-2853`, the three `Host:`
// forms, the request target, the status-line parse and the 8-of-17 vtable that
// `Curl_scheme_http` and `Curl_scheme_https` both point at -- and it exports
// the two assembled registry rows. It does NOT make an HTTP transfer possible:
// nothing constructs a request specification. `easy/handle.rs` has landed, so
// a handle can now be built and defaulted, but `easy/setopt.rs` -- one of the
// two paths above -- is what would put a URL on it, so `protocols/mod.rs`
// deliberately keeps `run: None` on both HTTP rows and `version.rs` keeps
// `ENGINE_PROTOCOLS` inert. Writing a file and reaching it are separate obligations; only the
// second is open for HTTP, and the `Protocols:` banner stays empty until it
// closes.
//
// `protocols/http2.rs` has now landed too. It implements the HTTP/2 connection
// filter, curl-compatible SETTINGS and h2c upgrade bytes, HPACK-backed stream
// processing, flow-control updates, trailers and push headers. Like the HTTP/1
// writer, it is not yet reachable from an easy handle: request construction and
// protocol dispatch still depend on the absent easy modules above. Its source
// is therefore complete while `version.rs` correctly keeps the capability
// inert.
//
// `protocols/stub.rs` is worth one sentence of its own, because its landing
// changes what is left rather than what this build can do: it REGISTERS the 24
// schemes AAP 0.2.2 excludes from implementation, every row carrying no
// executor, and it is deliberately absent from `version.rs`'s `Protocols:`
// banner so that the 283 fixtures targeting those schemes skip instead of
// failing. Registering a scheme and serving one are separate obligations.
//
// `protocols/ftp/` is worth one more, because it is now complete as a
// directory: `pingpong.rs` carries the request/response cadence of
// `lib/pingpong.c` -- the command writer that owns the terminating CRLF, the
// reply-line framer, the per-response timeout and the readiness loop --
// `listparser.rs` carries `lib/ftplistparser.c` with `lib/fileinfo.c`, and
// `mod.rs` now carries the `lib/ftp.c` command sequencing that drives both:
// the 37-state machine and its single mutator, the two data-channel modes,
// the five quote lists, the wildcard driver and the exhaustive reply
// dispatcher, with its own two registry rows assembled beside them. What it
// still performs no transfer for is the same reason HTTP does not: nothing
// constructs a request specification, so `protocols/mod.rs` keeps `run: None`
// on both FTP rows, `version.rs` keeps `ftp` out of the `Protocols:` banner
// and its fixtures keep skipping.
//
// `protocols/ws.rs` is worth another, and for a reason none of the others
// share: it is the only executor whose handler is almost entirely SOMEBODY
// ELSE'S. `Curl_protocol_ws` (`lib/ws.c:1918-1936`) fills eight slots and
// seven of them point at the HTTP implementation, so the Rust handler wraps
// `protocols/http1.rs`'s and overrides `setup_connection` alone -- which is
// why this file could not have landed before that one. What it does own is
// everything below the vtable: the three-header handshake in curl's exact
// order, the `Sec-WebSocket-Accept` hash, the frame encoder with its three
// big-endian length forms and its per-connection mask, the decoder with its
// fourteen first-byte arms, the automatic PONG, and the engine behind the four
// `curl_ws_*` exports. Two things it deliberately does NOT do: advertise
// `ws`/`wss` in the `Protocols:` banner, because the registry rows still carry
// `run: None` for want of an easy handle; and enforce the three RFC 6455
// response obligations that `lib/ws.c:1359-1377` records as comments with no
// code beneath them -- the algorithm is implemented and tested, but applying
// it would fail all 28 WebSocket fixtures, and AAP 0.8.1 makes the fixtures the
// oracle rather than the target. The module documents that divergence at the
// function that embodies it.
//
// `protocols/http3.rs` is worth the LAST one, because it is the file that
// emptied this directory of absences and because it is the only filter in the
// tree that terminates its own chain. `Curl_cft_http3`
// (`lib/vquic/curl_ngtcp2.c:2894`) carries four type flags --
// `IP_CONNECT | SSL | MULTIPLEX | HTTP` -- where every other filter carries one
// or two, and it does so because it performs all four jobs itself: there is no
// socket filter and no TLS filter beneath it. The Rust module holds the whole of
// that: all fifteen typed queries, the eight control events, the five `quinn`
// transport parameters `quic_settings` sets (which travel in the ClientHello
// and are therefore wire-visible), the handshake deadline enforced from the
// injected clock, `QLOGDIR`, and the QUIC row of
// `conn/happy_eyeballs.rs`'s transport registry -- with `quinn` + `h3` +
// `h3-quinn` in place of ngtcp2 and nghttp3, and with no `unsafe` and no
// `use crate::tls` anywhere in it. Two things it deliberately does NOT do:
// advertise `HTTP3` or `h3` in the banner, for want of the easy handle every
// other executor is waiting on; and store a `:status` pseudo-header, because
// `cb_h3_recv_header` never pushes one -- `lib/http2.c:1512` is the only
// `Curl_headers_push` call site outside `lib/headers.c`, so an HTTP/3 transfer
// in curl 8.19.0-DEV has no pseudo-header in its store and adding one would be
// an API-visible change AAP 0.8.1 forbids.
//
// Those same three paths are held as data, not prose, by
// `absent_target_gate` in `curl-rs/src/bin/curlinfo.rs`, alongside the thirteen
// `curl-rs` and one `curl-rs-ffi` target that are also unwritten -- 17
// across the workspace. The ABI figure read three, and the total 37, until
// `curl-rs-ffi/src/ffi/share.rs` landed, and two until `ffi/ws.rs` took the
// whole `curl_ws_*` family with it; the engine figure read five, and the
// total 20, until `protocols/http3.rs` and `proxy/http_connect.rs` did. That
// gate fails, naming the file, as
// soon as one of
// them lands, which is what keeps this paragraph from outliving its accuracy
// the way its predecessor did. It has done exactly that three times over for
// this crate's siblings: `curl-rs/src/cli/help.rs`, `curl-rs/src/cli/ipfs.rs`
// and `curl-rs/src/config/parseconfig.rs` have all landed, which is why the
// `curl-rs` figure reads thirteen rather than the sixteen it was.
// Registry granularity and file granularity are deliberately both recorded:
// the registry answers "can this capability run", the gate answers "what is
// left to write", and neither substitutes for the other.
//
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
// `tests/runtests.pl:1759` wraps its entire memory check in
// `if($feature{"TrackMemory"})`, and `:660` derives that feature from a
// single regular expression over the version banner:
//
//     $feature{"TrackMemory"} = $feat =~ /Debug/i;

#[cfg(feature = "memdebug")]
#[global_allocator]
static MEMDEBUG_ALLOCATOR: crate::ffi::sys::memdebug::TrackingAllocator =
    crate::ffi::sys::memdebug::TrackingAllocator::new();

// CRATE-ROOT RE-EXPORTS -- deliberately minimal, and every entry justified.
//
// TWO EXCLUSIONS, stated rather than silently omitted:
//
//  * The easy, multi and share HANDLE TYPES are NOT re-exported.
//    `share::Share` does exist, and it is left unexported for consistency with
//    the other two rather than for want of a name: re-exporting one handle
//    type and not its siblings would make the root's surface depend on
//    authoring order. Nothing is lost: `easy`, `multi` and `share` are all
//    `pub`, so a consumer names the type through its owning module, which is
//    the one-import-per-type discipline in any case. Adding a re-export later
//    is a compatible change; a wrong one is a build break for two other
//    crates.
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
pub use crate::util::strcase::{strequal, strnequal};

// The trace configuration. Re-exported by the same idiom and for the same
// reason as `getdate` and the two comparators above: `curl_global_trace` is one
// of the 100 symbols `lib/libcurl.def` exports (`:34`), its whole body in C is
// `Curl_trc_opt(config)` (`lib/easy.c:292-308`), and `curl-rs-ffi` has no other
// way in because `trace` is crate-private by enforcement.
//
// WHY THE PROCESS-WIDE INSTANCE IS NOT HERE. C keeps the levels in file-scope
// statics that `trc_opt()` writes through (`lib/curl_trc.c:578`, `:584`,
// `:596`, `:600`). This crate deliberately holds them in an owned value
// instead, because the protocol and transfer modules are tested by injection
// and a process-global level would make those tests order-dependent. So the
// single instance lives in the ABI facade -- `curl-rs-ffi/src/ffi/global.rs`,
// which already owns the `curl_global_init` reference count and the five
// allocator hooks -- and is lent to each transfer. A C consumer has no
// command-line tool to hold one on its behalf, so somebody must, and the
// facade is the only layer that may.
pub use crate::trace::TraceConfig;

// The scheme table. Re-exported by the same idiom and for the same reason as
// `getdate`, the two comparators and `TraceConfig` above: `curl_url` is one of
// the 100 symbols `lib/libcurl.def` exports (`:90`), it takes NO arguments
// (`include/curl/urlapi.h:113`), and `crate::url::Url::new` requires a
// `&'static dyn crate::url::SchemeRegistry` -- so `curl-rs-ffi/src/ffi/url.rs`
// must obtain the table without being handed one, and `protocols` is
// crate-private by enforcement.
//
// Deliberately ONE name, not the module, and NOT a glob. `pub use
// crate::protocols::*;` would expose whatever the protocol modules add next --
// none of which is an exported symbol -- and would misrepresent the ABI surface
// as larger than the 100 names. `protocols` itself stays `pub(crate)`.
pub use crate::protocols::scheme_registry;

// THE EXTENDED-ATTRIBUTE PRIMITIVE IS NOT RE-EXPORTED HERE, and the absence is
// deliberate rather than an omission.
//
// The surface is exactly one function and one predicate, because two public
// names for one capability are two ways for the answer to differ from itself:
//
//   * `set_file_xattr` -- below, with the rest of the platform facade. It takes
//     `BorrowedFd<'_>` and `&[u8]` names, and applies the `strlen(value)`
//     measurement `src/tool_xattr.c:88-92` applies.
//   * `version::supports_xattr` -- the engine-owned capability query, which
//     answers from `ffi::sys::xattr_available` through the crate-internal path.
//     `xattr_available` is `pub(crate)` accordingly: it has a real consumer, and
//     that consumer is inside this crate.
//
// Re-exported here, and nowhere else, because `curl-rs` cannot reach them any
// other way and must not be made able to.
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
//   * `scrub_argument` -- `cleanarg` (`src/tool_getparam.c:625-637`), which
//     overwrites a credential in the process's own argument vector with `*` so
//     that `ps` and `/proc/<pid>/cmdline` stop showing it. Consumed by
//     `curl-rs/src/cli/args.rs`, once per `ARG_CLEAR` option. It is here rather
//     than in the tool for the same structural reason as the rest of this list
//     and one of its own: the loader's argument vector is unreachable from safe
//     Rust -- `std::env::args_os` copies -- so the capability exists only
//     inside this crate's one `unsafe` island, and `HAVE_WRITABLE_ARGV` is
//     defined on all four mandated targets, so the alternative was a silent
//     security regression.
//
// WHAT THIS DOES NOT DO, because the distinction is the whole reason the list
// is a list and not a `pub mod`:
//
//   * `mod ffi` stays `pub(crate)`.
//   * The seam traits (`TerminalCalls`, `XattrCalls`, `TimeCalls`,
//     `SysCalls`), `RealSys`, `SavedTerminal` and every `_with` variant stay
//     `pub(crate)`. A consumer gets the capability, never the mechanism.
//   * No new module and no new file is introduced to carry this.
pub use crate::ffi::{
    disable_echo, local_utc_offset_secs, scrub_argument, set_file_xattr,
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
pub use crate::util::os_error_message;

// THE BASE64 CODEC, and the second reason a name leaves `mod util`.
//
// `getdate`, the two comparators and `TraceConfig` above are re-exported
// because they back exported C symbols. These two are not: `curlx_base64_encode`
// and `curlx_base64_decode` (`lib/curlx/base64.c:241-246`, `:61-163`) are
// `curlx` internals and appear nowhere in `lib/libcurl.def`. They are here for
// the other reason, the one the platform facade below is also here for --
// `curl-rs` cannot reach them any other way, and reproducing them there would
// be a second implementation of a codec whose exact behaviour is contract.
//
// The consumer is `curl-rs/src/cli/vars.rs`, which needs both for the
// `{{name:b64}}` and `{{name:64dec}}` variable functions of `src/var.c:141-181`.
// Those two functions do not merely encode and decode: the C's `:64dec` arm
// puts the literal `[64dec-fail]` in the output for input the decoder REFUSES
// and carries on, so the tool has to be able to tell "this is not valid
// base64" from "this could not be attempted". Only a real codec can make that
// distinction, and only this one makes it the way curl does -- it requires
// canonical padding, which RFC 4648 does not, and it accepts non-canonical
// trailing bits, which the `base64` crate does not. A tool-side reimplementation
// would diverge on both, silently, on real input.
//
// Deliberately TWO names, not the module, by the same rule as every entry
// above. `pub use crate::util::base64;` would additionally expose
// `CURL_MAX_BASE64_INPUT` and `url_encode` -- the unpadded URL-alphabet variant
// that `protocols/ws` uses for `Sec-WebSocket-Key` -- neither of which has a
// consumer outside this crate. `base64` itself stays `pub(crate)`.
//
// Renamed on the way out, because at the crate root `encode` and `decode` name
// no particular codec. Inside `mod util::base64` the module qualifies them; here
// nothing would.
pub use crate::util::base64::{
    decode as base64_decode, encode as base64_encode,
};

// OPERATING-SYSTEM FACADE -- the narrowest safe bridge to `src/ffi/sys.rs`.
//
//  * RE-EXPORTED AS THEY STAND -- the eight names in the `pub use crate::ffi`
//    above: `disable_echo` and `EchoGuard` (F15, terminal echo while a password
//    is typed), `terminal_columns`, `set_file_xattr` (F17),
//    `local_utc_offset_secs`, `strftime_gmt` and `set_locale_from_environment`
//    (F16, local and locale-dependent time), and `scrub_argument` (`cleanarg`,
//    the credential wipe over the process argument vector).
//    `ffi/mod.rs` group E marks exactly
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

/// The extent of `fd` when it is a regular file that can be read lazily.
pub fn regular_file_extent(
    fd: std::os::fd::BorrowedFd<'_>,
) -> Option<(i64, i64)> {
    crate::ffi::regular_file_extent(fd)
}

/// Reads from `fd` into `buf`, returning how many bytes were placed there.
///
/// # Errors
///
/// Whatever `read(2)` reports: a closed or unreadable descriptor, or an
/// interruption.
pub fn read_file_descriptor(
    fd: std::os::fd::BorrowedFd<'_>,
    buf: &mut [u8],
) -> std::io::Result<usize> {
    crate::ffi::read_fd(fd, buf)
}

/// Repositions `fd` to `offset`, counted from the start of the file.
///
/// # Errors
///
/// Whatever `lseek(2)` reports. An unseekable descriptor is the case
/// `src/tool_formparse.c:245` turns into `CURL_SEEKFUNC_CANTSEEK`.
pub fn seek_file_descriptor(
    fd: std::os::fd::BorrowedFd<'_>,
    offset: i64,
) -> std::io::Result<()> {
    crate::ffi::seek_fd(fd, offset)
}

/// Applies the `CURL_MEMLIMIT` allocation cap, reproducing
/// `src/tool_main.c:117-125`.
#[cfg(feature = "memdebug")]
pub fn memdebug_init_from_env() -> bool {
    crate::ffi::init_from_env()
}

// DIAGNOSTIC-OUTPUT FACADE -- the bridge to `src/trace.rs`'s neutralization.

/// Neutralize display-affecting control bytes in a one-line diagnostic.
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

#[cfg(test)]
mod tests {
    /// The capability vocabulary, evaluated at compile time.
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
    #[test]
    fn packed_version_matches_its_components() {
        let packed = (crate::version::LIBCURL_VERSION_MAJOR << 16)
            | (crate::version::LIBCURL_VERSION_MINOR << 8)
            | crate::version::LIBCURL_VERSION_PATCH;
        assert_eq!(packed, crate::LIBCURL_VERSION_NUM);
    }

    /// The re-exported result codes resolve at the crate root and keep their
    /// pinned integers.
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
//
// Every test below is `#[cfg_attr(miri, ignore)]`d, and the reason is the same
// one each time: these tests read the source tree, not the program. Miri
// interprets Rust's runtime semantics, and it runs with host isolation on, so
// `fs::read_dir` fails with `unsupported operation: `opendir` not available
// when isolation is enabled` -- which aborts the whole interpreter and takes
// the required `cargo miri test -p curl-rs-lib` gate down with it. Ignoring
// them under Miri costs nothing and hides nothing: there is no pointer
// arithmetic, no aliasing and no uninitialised memory in a string scan, so
// Miri has nothing to find here, and the assertions still run in full under
// `cargo test --workspace` -- the gate that owns them.

#[cfg(test)]
mod source_policy {
    use std::fs;
    use std::path::{Path, PathBuf};

    /// The workspace members, in dependency order.
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

    /// The C scalar widths live only in the FFI island.
    ///
    /// `core::ffi::c_int`, `c_uint` and `c_long` are the widths a C compiler
    /// chose, and letting them into the engine's own types makes a native-width
    /// assumption part of the engine API. The engine therefore speaks in
    /// fixed-width Rust integers and the `c_*` spellings appear only where a
    /// real C boundary is being crossed: `curl-rs-lib/src/ffi/`, the sanctioned
    /// island, and `curl-rs-ffi`, which owns the ABI.
    #[test]
    #[cfg_attr(miri, ignore = "this reads the source tree, not the program")]
    fn c_scalar_types_appear_only_inside_the_ffi_island() {
        // The `ffi` directory is the one place in this crate permitted to name
        // a C width, because it is the one place that calls C.
        let island =
            workspace_root().join("curl-rs-lib").join("src").join("ffi");

        // Word-bounded so that an identifier merely CONTAINING one of these --
        // `as_c_int`, `from_c_int`, both of which are method names kept for
        // symmetry with the FFI crate -- is not mistaken for a type use.
        const WIDTHS: [&str; 3] = ["c_int", "c_uint", "c_long"];

        let mut offenders: Vec<String> = Vec::new();
        let mut island_uses = 0usize;

        for path in sources("curl-rs-lib") {
            let inside_island = path.starts_with(&island);
            let text = fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("{}: {error}", path.display()));

            for (number, line) in text.lines().enumerate() {
                let code = code_only(line);
                for width in WIDTHS {
                    if !mentions_word(&code, width) {
                        continue;
                    }
                    if inside_island {
                        island_uses += 1;
                    } else {
                        offenders.push(format!(
                            "{}:{} names {width}",
                            path.display(),
                            number + 1
                        ));
                    }
                }
            }
        }

        assert!(
            offenders.is_empty(),
            "the engine must speak in fixed-width integers; \
             move the conversion to curl-rs-ffi:\n{}",
            offenders.join("\n")
        );

        // Non-vacuity: the island really does use them, so a scan that found
        // nothing anywhere would be a broken scan rather than a clean bill.
        assert!(
            island_uses > 0,
            "no C width found even inside src/ffi -- the gate is not scanning"
        );
    }

    /// True when `haystack` contains `word` delimited by non-identifier bytes.
    ///
    /// Rust identifiers are `[A-Za-z0-9_]`, so `as_c_int` must not count as a
    /// use of `c_int`: the byte before `c` is `_`, which is an identifier byte.
    fn mentions_word(haystack: &str, word: &str) -> bool {
        let bytes = haystack.as_bytes();
        let ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
        haystack.match_indices(word).any(|(at, _)| {
            let before_ok = at == 0 || !ident(bytes[at - 1]);
            let end = at + word.len();
            let after_ok = end == bytes.len() || !ident(bytes[end]);
            before_ok && after_ok
        })
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
