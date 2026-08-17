// ***************************************************************************
// *                                  _   _ ____  _
// *  Project                     ___| | | |  _ \| |
// *                             / __| | | | |_) | |
// *                            | (__| |_| |  _ <| |___
// *                             \___|\___/|_| \_\_____|
// *
// * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
// *
// * This software is licensed as described in the file COPYING, which
// * you should have received as part of this distribution. The terms
// * are also available at https://curl.se/docs/copyright.html.
// *
// * You may opt to use, copy, modify, merge, publish, distribute and/or sell
// * copies of the Software, and permit persons to whom the Software is
// * furnished to do so, under the terms of the COPYING file.
// *
// * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
// * KIND, either express or implied.
// *
// * SPDX-License-Identifier: curl
// *
// ***************************************************************************

//! The share interface: state deliberately shared between easy handles.
//!
//! Supersedes `lib/curl_share.c` and `lib/curl_share.h`, and backs four of the
//! 100 exported symbols of `lib/libcurl.def` -- rows 81 to 84,
//! `curl_share_cleanup`, `curl_share_init`, `curl_share_setopt` and
//! `curl_share_strerror` -- which `curl-rs-ffi/src/ffi/share.rs` surfaces to
//! C.
//!
//! # What is shared, and who owns each store
//!
//! This module owns no store. It owns the *sharing decision*: which of the
//! seven `curl_lock_data` kinds an application asked for, the lock and unlock
//! callbacks it supplied, the reference count that decides whether the share
//! may be reconfigured or destroyed, and the interior locking that makes
//! concurrent access sound. The stores themselves belong to their own
//! modules and are wrapped here:
//!
//! | Kind | Store | Owner |
//! |------|-------|-------|
//! | `CURL_LOCK_DATA_COOKIE` | `CookieInfo` | [`crate::cookies`] |
//! | `CURL_LOCK_DATA_DNS` | `DnsCache` | [`crate::dns`] |
//! | `CURL_LOCK_DATA_SSL_SESSION` | `SessionCache` | [`crate::tls::session_cache`] |
//! | `CURL_LOCK_DATA_CONNECT` | `ConnectionPool` | [`crate::conn::pool`] |
//! | `CURL_LOCK_DATA_PSL` | `PslCache` | [`crate::cookies::psl`] |
//! | `CURL_LOCK_DATA_HSTS` | `HstsCache` | [`crate::cookies::hsts`] |
//!
//! Alt-Svc and `.netrc` are deliberately absent: there is no
//! `CURL_LOCK_DATA_ALTSVC` in `include/curl/curl.h:3026-3040` and no netrc
//! kind either, so neither is shareable and neither is added here.
//!
//! # Interior mutability, and why the user callbacks are not the protection
//!
//! `struct Curl_share` has no lock of its own. The C calls the application's
//! callbacks around every access to shared state and, when the application
//! supplies none, performs no locking at all --
//! `docs/libcurl/opts/CURLSHOPT_SHARE.md` states that *"If any of the data is
//! to be shared in multiple threads then mutex callbacks must be set as
//! well"*. Sharing without callbacks across threads is therefore documented
//! as unsafe in the C API.
//!
//! Here the protection is genuine and unconditional: one [`Mutex`] per kind
//! -- the shape `tests/libtest/lib3207.c:135` gives its own
//! `curl_mutex_t mutexes[CURL_LOCK_DATA_LAST - 1]` -- plus one [`RwLock`] for
//! the Public Suffix List, which is the only kind that ever asks for shared
//! access (`lib/psl.c:51` and `:89`; measured, those are the only two of the
//! 19 `Curl_share_lock` call sites outside `lib/curl_share.c` that pass
//! `CURL_LOCK_ACCESS_SHARED` -- the other 17 pass `CURL_LOCK_ACCESS_SINGLE`).
//! The application's callbacks are invoked in addition, at exactly
//! the points the C invokes them, and are treated as *observable
//! notifications* rather than as the mechanism. Soundness never depends on a
//! C callback being correct.
//!
//! That is strictly sounder than the C and deliberately so, but it changes no
//! observable result: the callbacks fire with the same arguments in the same
//! order, and every return code is the C's.
//!
//! ## Callbacks are never nested for one kind
//!
//! `tests/libtest/lib506.c:71-76` carries explicit double-lock detection --
//! it prints `"lock: double locked %s"` and gives up -- which proves the C
//! never nests lock callbacks for one data kind. Two rules keep that true
//! here. A guard emits exactly one lock notification when it is taken and
//! exactly one unlock notification when it is dropped, and no helper that
//! already holds a kind takes it again. `lib/conncache.c:39-60` corroborates
//! the intent from the other side: the pool's own `locked` bit there is a
//! re-entrancy assertion, not a lock.
//!
//! ## No panics, and what a poisoned lock does
//!
//! Nothing in this file can panic: no `unwrap`, no indexing, no shift or
//! arithmetic that can overflow. Two reasons, and the second is specific to
//! this module. A panic unwinding into a C caller through `curl-rs-ffi` is
//! undefined behaviour at the ABI boundary; and a panic while a [`Mutex`] is
//! held poisons it, which would convert a transient fault into a permanent
//! failure for every later access to that share. Every lock is therefore
//! taken with `unwrap_or_else(PoisonError::into_inner)`, the idiom
//! `crate::util::timeval` already uses: a poisoned lock is recovered and the
//! operation proceeds, because C has no notion of poisoning and a share that
//! stopped working would be a behaviour change.
//!
//! ## The lifecycle is serialised, where the C's is not
//!
//! `struct Curl_share` has two states: `magic == CURL_GOOD_SHARE` and the zero
//! `curl_share_cleanup` writes at `lib/curl_share.c:263`. It has no state for
//! *"a teardown has been claimed but has not finished"*, and the consequence
//! is measurable in the C's own text: `curl_share_cleanup` tests the tag at
//! `:224`, reads `share->dirty` at `:231` and clears the tag at `:263`, none
//! of it synchronised, so two threads entering together both pass the test,
//! both read a zero count and both return `CURLSHE_OK`. In the C that frees
//! one allocation twice; here it would call `Box::from_raw` twice. The same
//! gap lets a `CURLOPT_SHARE` on another thread raise the count between `:231`
//! and the teardown at `:237`, so a store is destroyed while a handle holds
//! it.
//!
//! `Lifecycle` adds the missing middle state and closes both. The teardown
//! is *claimed* with one compare-and-exchange, so exactly one caller can ever
//! reach the free; [`ShareCore::attach`] refuses while the claim is held, so
//! the count cannot rise behind it; [`ShareCore::detach`] and the
//! notifications are still admitted, because a lost decrement would be
//! permanent and because the C's own teardown notifies. Nothing an
//! application can observe changes for a program that does what
//! `docs/libcurl/curl_share_cleanup.md` requires
//! -- *"Passing in a share pointer that is in use"* is its own error -- and a
//! program that races gets a defined [`CURLSHcode`] where the C gave it
//! undefined behaviour.
//!
//! ## Ownership changes are transactions, not return values
//!
//! `lib/setopt.c:1493-1550` performs the count change **and** the easy
//! handle's repointing inside one `CURL_LOCK_DATA_SHARE` critical section:
//! attach increments at `:1527` and then repoints at `:1529-1547`, detach
//! repoints at `:1497-1512` and then decrements at `:1514`. That placement is
//! observable, because the application's lock callback is what serialises an
//! attaching handle's view of the shared stores against every other handle's.
//! [`ShareCore::attach`] and [`ShareCore::detach`] therefore take the caller's
//! ownership change as a closure and run it inside the bracket, in the C's
//! order, rather than returning a mask for the caller to act on after the
//! unlock -- which would deliver a critical section that ends before the work
//! it is supposed to cover.
//!
//! # `Send` and `Sync`: delivered over the split, and asserted rather than
//! claimed
//!
//! **[`Share`] is `Send + Sync`, and a static assertion in this file's tests
//! fails the build if that ever stops being true.** That is what makes one
//! `CURLSH` usable from two threads, which is supported C behaviour:
//! `tests/libtest/lib506.c` drives one share from two threads with
//! `CURL_LOCK_DATA_COOKIE` and `CURL_LOCK_DATA_DNS`, `lib3207.c` does the same
//! with `CURL_LOCK_DATA_SSL_SESSION`, and
//! `docs/libcurl/opts/CURLSHOPT_SHARE.md` is written for exactly that.
//!
//! Two changes together deliver it, and the history is worth keeping because
//! it explains the shape of both this module and `conn/`.
//!
//! ## The split: where the state lives
//!
//! * [`ShareCore`] carries the validity tag, the metadata -- specifier,
//!   reference count, callbacks, user pointer -- and five of the six stores:
//!   DNS, cookies, the Public Suffix List, HSTS and the TLS session cache,
//!   together with every operation on them.
//! * [`Share`] is the owner: an [`Arc<ShareCore>`] plus the connection pool
//!   and the `ShareAdmin` that destroys it. It is the value `curl_share_init`
//!   hands out and `curl_share_cleanup` frees, and it [`Deref`]s to the core
//!   so no call site reads differently.
//! * `Share::stores` is the seam between them: it hands another thread an
//!   [`Arc<ShareCore>`] -- the same state under the same locks delivering the
//!   same notifications, never a copy. `crate::easy` and `crate::multi` reach
//!   a share from a worker task through it.
//!
//! ## The bounds: why the sixth store now travels too
//!
//! Five of the six stores were `Send + Sync` from the start, as their own
//! modules define them. The sixth,
//! [`crate::conn::pool::ConnectionPool`], was not, because it holds
//! `Box<dyn ShutdownTimer>`, `Option<Box<dyn ProtocolDisconnect>>` and a
//! `FilterChains` of `Box<dyn ConnFilter>`, and none of those three traits
//! carried a `Send` bound. `struct Curl_share` holds the pool by value
//! (`lib/curl_share.h:52`), so [`Share`] holds it too and inherited the
//! affinity. There is no unsafe-free way to hold a `!Send` value inside a
//! `Send + Sync` container, and `#![deny(unsafe_code)]` makes an
//! `unsafe impl Send` unavailable by design rather than by preference. Leaving
//! the pool out of the share was equally unavailable: it would make
//! `CURLSHOPT_SHARE` with `CURL_LOCK_DATA_CONNECT` set a bit and share
//! nothing -- a stub rather than an implementation. So the faithful model was
//! kept and the three traits were bound instead.
//!
//! What that cost, measured on this tree rather than estimated: `Send` on
//! `ConnFilter`, `ShutdownTimer` and `ProtocolDisconnect`, and `Send + Sync`
//! on the injected seams behind them -- `ConnMeta`, `Deadline`,
//! `ExpireScheduler`, `TransportProvider`, `OpenSocket`, `CloseSocket`,
//! `SockOpt`, `MultiCloseObserver`, `ConnState`, `ReadinessProbe`,
//! `BindResolver` and `If2Ip` -- plus `Send + Sync` on `TlsBackend` and `Send`
//! on its `State`. That turned every `Rc<dyn Seam>` in `conn/socket.rs`,
//! `conn/happy_eyeballs.rs`, `conn/filters.rs`, `conn/shutdown.rs` and
//! `crate::tls` into an [`Arc`], and `util/bufq.rs`'s `SharedPool` from
//! `Rc<RefCell<ChunkPool>>` into `Arc<Mutex<ChunkPool>>` -- the one
//! substitution that file's own documentation had already pre-authorised,
//! because all three of its pool call sites already treated acquisition as
//! fallible. No `unsafe` was added anywhere, and no lock was added to the
//! connection pool: `CURL_LOCK_DATA_CONNECT` is still owned here, and the pool
//! still exposes mutation through `&mut self` alone.
//!
//! The pool therefore stays where the C puts it, and the split stays because
//! it is the seam a worker task reaches a share through. Two consequences are
//! worth stating so they are not rediscovered:
//!
//! * **`curl-rs-ffi/src/ffi/share.rs` may treat `CURLSH` as shareable.** It
//!   can form a shared reference for a second thread soundly, because the type
//!   is `Sync`; it does not have to document thread affinity in its safety
//!   comment.
//! * **The `threadsafe` capability `crate::version` advertises is still not
//!   about shares.** `docs/libcurl/curl_version_info.md:345-351` defines it as
//!   *"thread-safety support (Atomic or SRWLOCK) to protect curl
//!   initialization"*, and `crate::version` gates it on its global-init engine
//!   token accordingly. This module being `Sync` neither adds to nor
//!   subtracts from that token, so no over-report was introduced that
//!   `tests/runtests.pl` would punish.
//!
//! The AAP's own directive of a multi-thread Tokio runtime for the multi
//! handle (section 0.8.3) points the same way: a connection driven by such a
//! task must be `Send`, so this was load-bearing for `multi/` and not only
//! for shares.
//!
//! # Visibility, and the `error[E0446]` this module resolves
//!
//! `crate::share` is `pub` while `crate::cookies`, `crate::conn`,
//! `crate::dns` and `crate::tls` are `pub(crate)`. Naming any store type in
//! a `pub` signature here would be `error[E0446]: private type in public
//! interface`. The resolution, which four sibling modules record and all four
//! assign to this one, is the C's own: `CURLSH` is literally
//! `typedef void CURLSH` (`include/curl/curl.h:110`) and `struct Curl_share`
//! carries *"this struct is libcurl-private, do not export details"*
//! (`lib/curl_share.h:42`). [`Share`] is that opaque handle. Its `pub`
//! surface -- construction, teardown, the option setter, the validity check,
//! the specifier and the attach and detach operations -- names no store type,
//! and every accessor that does is `pub(crate)`. No sibling was asked to
//! widen anything, and nothing here is re-exported from the crate root.
//!
//! # The contract `curl-rs-ffi/src/ffi/share.rs` implements
//!
//! That file does not exist yet, so its contract is written down here.
//!
//! 1. **`CURLSH` is `*mut c_void` at the boundary**, never
//!    `typedef struct CURLSH CURLSH;`. `include/curl/curl.h:109-110` makes
//!    `CURL` and `CURLSH` `void`, `include/curl/multi.h:57` makes `CURLM`
//!    `void`, and only `include/curl/urlapi.h:107`'s `CURLU` is a genuine
//!    opaque struct. cbindgen's natural output for an opaque Rust type
//!    diverges from all three, so `cbindgen.toml` must pin these
//!    declarations in a verbatim prologue; otherwise the widespread
//!    `CURLSH *` to `void *` idiom in `docs/examples/` stops compiling.
//! 2. **`curl_share_setopt` is declared non-variadic**, taking one trailing
//!    `*mut c_void`. A true C-variadic `extern "C"` function is unstable at
//!    the declared MSRV of 1.75 (`error[E0658]`, tracking issue 44930). The
//!    public header already presents exactly that shape: it macro-ises the
//!    name to precisely three arguments in both branches of its selector,
//!    at `include/curl/curl.h:3337-3338` and at
//!    `include/curl/typecheck-gcc.h:265-266`, whose comment is *"For now,
//!    just make sure that the functions are called with three arguments"*.
//!    Both macros must survive into the generated header or the compile-time
//!    arity contract silently disappears. `lib/curl_share.c:57`'s
//!    `#undef curl_share_setopt` exists for the same reason.
//! 3. **The trailing slot's low 32 bits are the payload** for
//!    `CURLSHOPT_SHARE` and `CURLSHOPT_UNSHARE`.
//!    `lib/curl_share.c:81` and `:149` both read `va_arg(param, int)` into an
//!    `int`, while `docs/libcurl/opts/CURLSHOPT_SHARE.md:26` documents the
//!    argument as `long`; on all four mandated LP64 little-endian targets a
//!    promoted `long` read back as an `int` yields the low 32 bits, which is
//!    why the mismatch is invisible. For `CURLSHOPT_LOCKFUNC`,
//!    `CURLSHOPT_UNLOCKFUNC` and `CURLSHOPT_USERDATA` the slot is a function
//!    or data pointer instead. The option identifier says which, before the
//!    slot is read. [`ShareOption`] fuses the identifier with its one
//!    payload so that pairing cannot be got wrong.
//! 4. **`Box::into_raw` in `curl_share_init`, `Box::from_raw` in
//!    `curl_share_cleanup` -- and `Box::from_raw` is FORBIDDEN on the error
//!    paths.** `docs/libcurl/curl_share_cleanup.md:59-60` states *"If an
//!    error occurs, then the share object is not deleted."*
//!    [`Share::cleanup`] therefore takes `&self`, cannot consume, and
//!    reports [`CURLSHcode::InUse`] or [`CURLSHcode::Invalid`] with the
//!    object intact and still usable. Only [`CURLSHcode::Ok`] permits the
//!    free -- and **at most one caller can ever receive it for a given
//!    share**, because the teardown is claimed with a single
//!    compare-and-exchange (`ShareCore::claim_cleanup`). Two threads calling
//!    `curl_share_cleanup` on one handle therefore produce one `Ok` and one
//!    [`CURLSHcode::Invalid`], never two frees, where the C's three
//!    unsynchronised steps produce two `CURLSHE_OK`s.
//! 5. **The four symbols** must appear in `nm` output to satisfy rows 81
//!    (`curl_share_cleanup`), 82 (`curl_share_init`), 83
//!    (`curl_share_setopt`) and 84 (`curl_share_strerror`) of
//!    `lib/libcurl.def`. Nothing in this crate is `#[no_mangle]` or
//!    `extern "C"`; an extra exported symbol would fail that parity gate.
//! 6. **Escalated ambiguity A4.** On `aarch64-apple-darwin` Apple's ABI
//!    passes variadic arguments on the stack while a non-variadic callee
//!    reached through a variadic prototype reads a register. That is a
//!    genuine, silent hazard on one of the four mandated targets. It is
//!    escalated to the user rather than accepted, and no fix is attempted
//!    here -- this module never touches the ABI boundary.
//!
//! # What this module deliberately does not do
//!
//! The `CURLSHcode` enumeration, its six messages and the
//! `"CURLSHcode unknown"` fallback belong to [`crate::error`] and are
//! consumed, never restated. The `CURLSHoption` integers belong to
//! `curl-rs-ffi`'s option table, the single source of truth for option
//! identity, so [`ShareOption`] is a typed enumeration here rather than a
//! second copy of those numbers. Raw-pointer marshalling of the callbacks
//! and their `void *userptr`, the variadic boundary and the arity macros all
//! belong to `curl-rs-ffi`. The `Protocols:` and `Features:` banner belongs
//! to [`crate::version`].
//!
//! Implicit multi-handle sharing belongs to `crate::multi`:
//! `docs/libcurl/opts/CURLSHOPT_SHARE.md` records that *"when you use the
//! multi interface, all easy handles added to the same multi handle share the
//! DNS cache"* -- and likewise the TLS session cache, the connection cache
//! and the PSL cache -- *"by default without using this option"*. That
//! handle holds the same store types this module wraps, and the guard shapes
//! here are usable from it: a multi handle's own store is simply one with no
//! notification attached, which is what `LockData`-keyed notification with an
//! absent callback already expresses.
//!
//! Link targets for the prose above.
//!
//! Written as Markdown reference definitions with absolute paths, because
//! this module carries its documentation in two places -- an outer `///`
//! block on `pub mod share` in the crate root and this inner one -- and
//! rustdoc resolves the merged result in the crate root's scope, where a
//! bare `Share` is not in scope. The prose therefore reads unqualified and
//! still links.
//!
//! [`Share`]: crate::share::Share
//! [`ShareCore`]: crate::share::ShareCore
//! [`Arc<ShareCore>`]: crate::share::ShareCore
//! [`ShareCore::attach`]: crate::share::ShareCore::attach
//! [`ShareCore::detach`]: crate::share::ShareCore::detach
//! [`Share::cleanup`]: crate::share::Share::cleanup
//! [`ShareOption`]: crate::share::ShareOption
//! [`CURLSHcode`]: crate::error::CURLSHcode
//! [`CURLSHcode::Ok`]: crate::error::CURLSHcode::Ok
//! [`CURLSHcode::InUse`]: crate::error::CURLSHcode::InUse
//! [`CURLSHcode::Invalid`]: crate::error::CURLSHcode::Invalid
//! [`Mutex`]: std::sync::Mutex
//! [`RwLock`]: std::sync::RwLock
//! [`Deref`]: core::ops::Deref

use core::fmt;
use core::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

// The reader-writer lock is the Public Suffix List's alone: it is the only
// datum the C ever asks for with `CURL_LOCK_ACCESS_SHARED` (`lib/psl.c:51`,
// `:89`), and that cache lives behind the `cookies` feature because
// `crate::cookies` declares its `psl` child there. Gated with it so that a
// build without cookies imports nothing it cannot use.
//
// Both guards are named because both phases exist: the writer is the
// exclusive refresh of `lib/psl.c:58-88`, and the reader is what the caller is
// handed afterwards, matching the shared notification of `:89` and the
// `const psl_ctx_t *` of `:94`.
#[cfg(feature = "cookies")]
use std::sync::{RwLock, RwLockReadGuard};

#[cfg(feature = "cookies")]
use publicsuffix::List;

use crate::conn::filters::{CallCtx, ConnId, FilterChains};
use crate::conn::pool::ConnectionPool;
use crate::conn::shutdown::{ShutdownHandle, ShutdownHost, ShutdownQueue};
#[cfg(feature = "hsts")]
use crate::cookies::hsts::HstsCache;
#[cfg(feature = "cookies")]
use crate::cookies::psl::{PslCache, PslSource};
#[cfg(feature = "cookies")]
use crate::cookies::CookieInfo;
use crate::dns::DnsCache;
use crate::error::{CURLMcode, CURLSHcode};
use crate::tls::session_cache::SessionCache;
use crate::trace::TimerId;
use crate::util::timediff::TimeDiff;
#[cfg(feature = "cookies")]
use crate::util::timeval::Clock;
use crate::util::timeval::SystemClock;

// The public vocabulary: the two enumerations an application's callbacks see

/// Which shared datum a lock or unlock notification is about.
///
/// `curl_lock_data` (`include/curl/curl.h:3026-3040`). Nine tokens, of which
/// [`Self::Last`] is a bound rather than a datum -- the C comment calls it
/// *"never use"*'s sibling by placing it after `CURL_LOCK_DATA_HSTS` -- and
/// [`Self::None`] is the zero the C spells explicitly.
///
/// [`Self::Share`] stores nothing. The C's own comment
/// (`include/curl/curl.h:3028-3031`) is that it *"is used internally to say
/// that the locking is just made to change the internal state of the share
/// itself"*, which here means the reference count that
/// [`ShareCore::attach`] and [`ShareCore::detach`] maintain.
///
/// Both out-of-band tokens are retained as variants rather than dropped,
/// because an application may pass either to `CURLSHOPT_SHARE` and both must
/// reach the same [`CURLSHcode::BadOption`] arm the C's `default:` reaches
/// (`lib/curl_share.c:140-141`, `:190-192`). Keeping them makes every
/// `match` in this file exhaustive over the real enumeration instead of
/// needing a catch-all that could swallow a future addition.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum LockData {
    /// `CURL_LOCK_DATA_NONE` = 0.
    None = 0,
    /// `CURL_LOCK_DATA_SHARE` = 1: the share's own internal state.
    Share = 1,
    /// `CURL_LOCK_DATA_COOKIE` = 2.
    Cookie = 2,
    /// `CURL_LOCK_DATA_DNS` = 3.
    Dns = 3,
    /// `CURL_LOCK_DATA_SSL_SESSION` = 4.
    SslSession = 4,
    /// `CURL_LOCK_DATA_CONNECT` = 5.
    Connect = 5,
    /// `CURL_LOCK_DATA_PSL` = 6: the Public Suffix List.
    Psl = 6,
    /// `CURL_LOCK_DATA_HSTS` = 7.
    Hsts = 7,
    /// `CURL_LOCK_DATA_LAST` = 8: a bound, never a datum.
    Last = 8,
}

impl LockData {
    /// Every token, in declaration order.
    pub const VARIANTS: &'static [Self] = &[
        Self::None,
        Self::Share,
        Self::Cookie,
        Self::Dns,
        Self::SslSession,
        Self::Connect,
        Self::Psl,
        Self::Hsts,
        Self::Last,
    ];

    /// The integer an application holds for this token.
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
    }

    /// The token for `raw`, or [`None`] when `raw` names none.
    #[must_use]
    pub const fn from_i32(raw: i32) -> Option<Self> {
        match raw {
            0 => Some(Self::None),
            1 => Some(Self::Share),
            2 => Some(Self::Cookie),
            3 => Some(Self::Dns),
            4 => Some(Self::SslSession),
            5 => Some(Self::Connect),
            6 => Some(Self::Psl),
            7 => Some(Self::Hsts),
            8 => Some(Self::Last),
            _ => None,
        }
    }

    /// The C spelling, for diagnostics and for tests that compare against the
    /// header.
    #[must_use]
    pub const fn c_name(self) -> &'static str {
        match self {
            Self::None => "CURL_LOCK_DATA_NONE",
            Self::Share => "CURL_LOCK_DATA_SHARE",
            Self::Cookie => "CURL_LOCK_DATA_COOKIE",
            Self::Dns => "CURL_LOCK_DATA_DNS",
            Self::SslSession => "CURL_LOCK_DATA_SSL_SESSION",
            Self::Connect => "CURL_LOCK_DATA_CONNECT",
            Self::Psl => "CURL_LOCK_DATA_PSL",
            Self::Hsts => "CURL_LOCK_DATA_HSTS",
            Self::Last => "CURL_LOCK_DATA_LAST",
        }
    }

    /// This token's bit in a [`Specifier`]: the C's `1 << type`.
    ///
    /// Written as an exhaustive `match` over literals rather than as a shift.
    /// The values are identical -- `1 << 0` through `1 << 8` -- and the
    /// difference is that a `match` cannot overflow, so this function is
    /// provably free of the panic a shift by an out-of-range amount would
    /// cause in a debug build and of the undefined behaviour the same shift
    /// causes in C. It also documents the mapping the C leaves implicit at
    /// `lib/curl_share.c:144` and `:150`.
    #[must_use]
    pub const fn bit(self) -> u32 {
        match self {
            Self::None => 1 << 0,
            Self::Share => 1 << 1,
            Self::Cookie => 1 << 2,
            Self::Dns => 1 << 3,
            Self::SslSession => 1 << 4,
            Self::Connect => 1 << 5,
            Self::Psl => 1 << 6,
            Self::Hsts => 1 << 7,
            Self::Last => 1 << 8,
        }
    }
}

impl fmt::Display for LockData {
    /// The C spelling, so that a formatted diagnostic reads like the header.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.c_name())
    }
}

/// How a lock notification asks for the datum to be held.
///
/// `curl_lock_access` (`include/curl/curl.h:3043-3048`), whose own comments
/// are preserved on the variants.
///
/// Only two values are ever passed. Thirty-eight of the C tree's 39
/// `Curl_share_lock` call sites request [`Self::Single`]; the one exception is
/// `lib/psl.c`, which is the only user of [`Self::Shared`] and requests both
/// during the refresh sequence [`ShareCore::psl_use`] reproduces. The other two
/// tokens exist so that the vocabulary is complete rather than partly
/// invented.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum LockAccess {
    /// `CURL_LOCK_ACCESS_NONE` = 0: *"unspecified action"*.
    None = 0,
    /// `CURL_LOCK_ACCESS_SHARED` = 1: *"for read perhaps"*.
    Shared = 1,
    /// `CURL_LOCK_ACCESS_SINGLE` = 2: *"for write perhaps"*.
    Single = 2,
    /// `CURL_LOCK_ACCESS_LAST` = 3: *"never use"*.
    Last = 3,
}

impl LockAccess {
    /// Every token, in declaration order.
    pub const VARIANTS: &'static [Self] =
        &[Self::None, Self::Shared, Self::Single, Self::Last];

    /// The integer an application's callback receives.
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
    }

    /// The token for `raw`, or [`None`] when `raw` names none.
    #[must_use]
    pub const fn from_i32(raw: i32) -> Option<Self> {
        match raw {
            0 => Some(Self::None),
            1 => Some(Self::Shared),
            2 => Some(Self::Single),
            3 => Some(Self::Last),
            _ => None,
        }
    }

    /// The C spelling.
    #[must_use]
    pub const fn c_name(self) -> &'static str {
        match self {
            Self::None => "CURL_LOCK_ACCESS_NONE",
            Self::Shared => "CURL_LOCK_ACCESS_SHARED",
            Self::Single => "CURL_LOCK_ACCESS_SINGLE",
            Self::Last => "CURL_LOCK_ACCESS_LAST",
        }
    }
}

impl fmt::Display for LockAccess {
    /// The C spelling, so that a formatted diagnostic reads like the header.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.c_name())
    }
}

// The two opaque application pointers, as integer tokens

/// The `CURL *handle` argument of a lock or unlock notification.
///
/// `curl_lock_function`'s and `curl_unlock_function`'s first parameter
/// (`include/curl/curl.h:3050`, `:3054`). Which handle it names is
/// observable, and the two cases differ:
///
/// * `Curl_share_lock` and `Curl_share_unlock` pass the easy handle
///   performing the operation (`lib/curl_share.c:279`, `:295`).
/// * `curl_share_cleanup` passes `NULL` (`lib/curl_share.c:228`, `:233`,
///   `:262`), because no transfer is performing it.
///
/// [`Self::NONE`] is that `NULL`. Every entry point here takes an owner so
/// that the distinction reaches the callback intact; the caller supplies it
/// because `crate::easy` owns the handle and this module must not depend on
/// it -- `crate::easy` will hold the share, so the reverse edge would be a
/// cycle.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LockOwner(usize);

impl LockOwner {
    /// The null handle: what `curl_share_cleanup` passes.
    pub const NONE: Self = Self(0);

    /// Wraps the bit pattern of an application handle.
    #[must_use]
    pub const fn from_bits(bits: usize) -> Self {
        Self(bits)
    }

    /// The bit pattern, for the shim that turns it back into a pointer.
    #[must_use]
    pub const fn bits(self) -> usize {
        self.0
    }

    /// Whether this is the null handle.
    #[must_use]
    pub const fn is_none(self) -> bool {
        self.0 == 0
    }
}

/// The `void *userptr` a lock or unlock notification receives.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ShareUserData(usize);

impl ShareUserData {
    /// The null pointer: what a freshly initialised share carries.
    pub const NONE: Self = Self(0);

    /// Wraps the bit pattern of an application pointer.
    #[must_use]
    pub const fn from_bits(bits: usize) -> Self {
        Self(bits)
    }

    /// The bit pattern, for the shim that turns it back into a pointer.
    #[must_use]
    pub const fn bits(self) -> usize {
        self.0
    }

    /// Whether this is the null pointer.
    #[must_use]
    pub const fn is_none(self) -> bool {
        self.0 == 0
    }
}

/// The application's `CURLSHOPT_LOCKFUNC`, as a safe Rust value.
///
/// `curl_lock_function` is
/// `void (*)(CURL *handle, curl_lock_data data, curl_lock_access locktype,
/// void *userptr)` (`include/curl/curl.h:3050-3053`). All four arguments
/// survive, because all four are observable.
pub type LockCallback =
    Arc<dyn Fn(LockOwner, LockData, LockAccess, ShareUserData) + Send + Sync>;

/// The application's `CURLSHOPT_UNLOCKFUNC`, as a safe Rust value.
///
/// `curl_unlock_function` is
/// `void (*)(CURL *handle, curl_lock_data data, void *userptr)`
/// (`include/curl/curl.h:3054-3056`). **It has no access-type argument**, and
/// that asymmetry with [`LockCallback`] is reproduced rather than smoothed
/// over: an unlock does not need to say what it is releasing, and adding the
/// parameter would hand applications an argument the C never passes.
pub type UnlockCallback =
    Arc<dyn Fn(LockOwner, LockData, ShareUserData) + Send + Sync>;

/// Which data kinds a share is sharing: `share->specifier`.
///
/// Bit 1, [`LockData::Share`], is set by `curl_share_init`
/// (`lib/curl_share.c:38`) and no code path in this module clears it
/// deliberately. It can nevertheless be cleared, and that is measured rather
/// than theoretical -- see [`Share::setopt`]'s account of the unconditional
/// clear at `lib/curl_share.c:150`.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Specifier(u32);

impl Specifier {
    /// Sharing nothing: the mask a `curlx_calloc`'d share would have before
    /// `lib/curl_share.c:38` runs.
    pub const EMPTY: Self = Self(0);

    /// The raw mask.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Whether `kind` is being shared -- the C's
    /// `share->specifier & (1 << type)` (`lib/curl_share.c:277`, `:293`).
    #[must_use]
    pub const fn contains(self, kind: LockData) -> bool {
        self.0 & kind.bit() != 0
    }

    /// `CURL_SHARE_KEEP_CONNECT` (`lib/curl_share.h:39-40`).
    ///
    /// The predicate `lib/conncache.c:44` and `:57` use to decide whether the
    /// pool's critical section needs the external `CURL_LOCK_DATA_CONNECT`
    /// notification at all. The C macro also tests that the share pointer is
    /// non-null, which here is expressed by having a [`Specifier`] to ask.
    #[must_use]
    pub const fn keep_connect(self) -> bool {
        self.contains(LockData::Connect)
    }

    /// `CURL_SHARE_ssl_scache` (`lib/curl_share.h:73-75`).
    ///
    /// The predicate `Curl_ssl_scache_lock` and `_unlock`
    /// (`lib/vtls/vtls_scache.c:587`, `:594`) use for the same purpose.
    #[must_use]
    pub const fn ssl_scache(self) -> bool {
        self.contains(LockData::SslSession)
    }
}

impl fmt::Display for Specifier {
    /// The C names of the kinds present, comma-separated, or `(none)`.
    ///
    /// For diagnostics and for test failure messages: a bare hexadecimal mask
    /// makes a wrong bit hard to see, and the C names are what a reader has in
    /// front of them in `include/curl/curl.h`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut written = false;
        for kind in LockData::VARIANTS {
            if !self.contains(*kind) {
                continue;
            }
            if written {
                f.write_str(", ")?;
            }
            f.write_str(kind.c_name())?;
            written = true;
        }
        if !written {
            f.write_str("(none)")?;
        }
        Ok(())
    }
}

/// One `curl_share_setopt` call: the option identifier fused with its single
/// payload.
///
/// # The two payload shapes
///
/// [`Self::Share`] and [`Self::Unshare`] carry a raw [`i32`] rather than a
/// [`LockData`], deliberately. `lib/curl_share.c:81` and `:149` read
/// `va_arg(param, int)` into an `int` with no validation, and a value naming
/// no kind must reach [`CURLSHcode::BadOption`] exactly as the C's `default:`
/// arm does. Accepting the raw integer keeps that decision -- and the
/// undefined-behaviour-free rejection [`LockData::from_i32`] performs -- in one
/// place instead of asking the shim to guess.
pub enum ShareOption {
    /// `CURLSHOPT_NONE`: *"do not use"*
    /// (`include/curl/curl.h:3069`). Reaches the C's `default:` arm at
    /// `lib/curl_share.c:211-213` and yields
    /// [`CURLSHcode::BadOption`].
    None,
    /// `CURLSHOPT_SHARE`: *"specify a data type to share"*, with the trailing
    /// slot's low 32 bits (`lib/curl_share.c:79-145`).
    Share(i32),
    /// `CURLSHOPT_UNSHARE`: *"specify which data type to stop sharing"*, with
    /// the trailing slot's low 32 bits (`lib/curl_share.c:147-194`).
    Unshare(i32),
    /// `CURLSHOPT_LOCKFUNC`: *"pass in a 'curl_lock_function' pointer"*
    /// (`lib/curl_share.c:196-199`). [`None`] is the null pointer.
    LockFunc(Option<LockCallback>),
    /// `CURLSHOPT_UNLOCKFUNC`: *"pass in a 'curl_unlock_function' pointer"*
    /// (`lib/curl_share.c:201-204`). [`None`] is the null pointer.
    UnlockFunc(Option<UnlockCallback>),
    /// `CURLSHOPT_USERDATA`: *"pass in a user data pointer used in the
    /// lock/unlock callback functions"* (`lib/curl_share.c:206-209`).
    UserData(ShareUserData),
    /// `CURLSHOPT_LAST`: *"never use"*
    /// (`include/curl/curl.h:3076`). Reaches the same `default:` arm as
    /// [`Self::None`].
    Last,
    /// An option identifier this build does not recognise.
    ///
    /// Named rather than implicit so that the shim has somewhere honest to put
    /// an out-of-range `CURLSHoption` instead of coercing it to a variant that
    /// means something else. It reaches the same `default:` arm, which is
    /// exactly what the C does with any value its `switch` does not name.
    Unknown(i32),
}

impl fmt::Debug for ShareOption {
    /// Hand-written because the three callback payloads are function values
    /// and no function value implements [`fmt::Debug`].
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => f.write_str("CURLSHOPT_NONE"),
            Self::Share(kind) => write!(f, "CURLSHOPT_SHARE({kind})"),
            Self::Unshare(kind) => write!(f, "CURLSHOPT_UNSHARE({kind})"),
            Self::LockFunc(callback) => write!(
                f,
                "CURLSHOPT_LOCKFUNC({})",
                if callback.is_some() { "set" } else { "null" }
            ),
            Self::UnlockFunc(callback) => write!(
                f,
                "CURLSHOPT_UNLOCKFUNC({})",
                if callback.is_some() { "set" } else { "null" }
            ),
            Self::UserData(data) => {
                write!(f, "CURLSHOPT_USERDATA({:#x})", data.bits())
            }
            Self::Last => f.write_str("CURLSHOPT_LAST"),
            Self::Unknown(raw) => write!(f, "CURLSHoption({raw})"),
        }
    }
}

// The measured capacity constants
//
// All three are behaviour-affecting numbers taken from `lib/curl_share.c`, and
// all three are named rather than written inline so that a reader can check
// them against the C without reading the code that uses them.

/// The DNS cache's slot count: `Curl_dnscache_init(&share->dnscache, 23)`
/// (`lib/curl_share.c:39`).
pub(crate) const DNS_CACHE_SLOTS: usize = 23;

/// The TLS session cache's peer capacity: the first argument of
/// `Curl_ssl_scache_create(25, 2, &share->ssl_scache)`
/// (`lib/curl_share.c:119`).
pub(crate) const SCACHE_MAX_PEERS: usize = 25;

/// The TLS session cache's sessions per peer: the second argument of the same
/// call (`lib/curl_share.c:119`).
pub(crate) const SCACHE_MAX_SESSIONS_PER_PEER: usize = 2;

/// The connection pool's slot count: the last argument of
/// `Curl_cpool_init(&share->cpool, share->admin, share, 103)`
/// (`lib/curl_share.c:130`).
#[allow(dead_code)] // No consumer: ConnectionPool::new takes no size.
pub(crate) const CPOOL_SLOTS: usize = 103;

/// The share's own mutable state, everything but the stores.
///
/// The four fields the C keeps beside its six stores
/// (`lib/curl_share.h:45-50`), held together under one lock because they are
/// read and written together: every entry point reads the specifier and the
/// callbacks, and the two that change anything change the count.
///
/// `magic` is deliberately **not** here; see [`ShareCore::magic`].
struct Meta {
    /// `share->specifier` (`lib/curl_share.h:45`).
    specifier: u32,
    /// `share->dirty` (`lib/curl_share.h:46`): how many easy handles
    /// currently reference this share.
    ///
    /// The C declares it `volatile unsigned int`, which is legacy signalling
    /// rather than a memory-ordering guarantee -- every increment and
    /// decrement in the C tree is bracketed by a
    /// `CURL_LOCK_DATA_SHARE` / `CURL_LOCK_ACCESS_SINGLE` pair
    /// (`lib/setopt.c:1494`-`:1516`, `:1525`-`:1549`, `lib/url.c:291`-`:293`).
    /// A plain [`u32`] under this lock is the faithful reading. It is not an
    /// atomic on purpose: an atomic would be a lock-free design where a
    /// correct one is asked for, and it would move the count out of the
    /// critical section the C puts it in.
    dirty: u32,
    /// `share->lockfunc` (`lib/curl_share.h:48`).
    lockfunc: Option<LockCallback>,
    /// `share->unlockfunc` (`lib/curl_share.h:49`).
    ///
    /// Independent of `lockfunc`, because the C tests the two separately
    /// (`lib/curl_share.c:227` against `:232`) and an application may install
    /// or clear either alone.
    unlockfunc: Option<UnlockCallback>,
    /// `share->clientdata` (`lib/curl_share.h:50`).
    clientdata: ShareUserData,
}

impl Meta {
    /// The state `curlx_calloc` leaves, plus the one bit
    /// `curl_share_init` sets.
    fn new() -> Self {
        Self {
            specifier: LockData::Share.bit(),
            dirty: 0,
            lockfunc: None,
            unlockfunc: None,
            clientdata: ShareUserData::NONE,
        }
    }

    /// The lock notification to deliver for `kind`, if any.
    ///
    /// `Curl_share_lock` (`lib/curl_share.c:277-280`): the callback fires only
    /// when the kind's specifier bit is set **and** a callback is installed.
    /// Returning the pair rather than calling it here is what lets the caller
    /// release this lock first, so that the application's callback never runs
    /// with the share's metadata locked.
    fn lock_notification(
        &self,
        kind: LockData,
    ) -> Option<(LockCallback, ShareUserData)> {
        if self.specifier & kind.bit() == 0 {
            // C: lib/curl_share.c:281 -- "else if we do not share this,
            // pretend successful lock". Nothing is delivered and the
            // operation still succeeds.
            return None;
        }
        // C: lib/curl_share.c:278 -- "only call this if set!".
        self.lockfunc
            .as_ref()
            .map(|callback| (Arc::clone(callback), self.clientdata))
    }

    /// The unlock notification to deliver for `kind`, if any.
    ///
    /// `Curl_share_unlock` (`lib/curl_share.c:293-296`), the mirror of
    /// [`Self::lock_notification`] with no access type, because
    /// `curl_unlock_function` has no such parameter.
    fn unlock_notification(
        &self,
        kind: LockData,
    ) -> Option<(UnlockCallback, ShareUserData)> {
        if self.specifier & kind.bit() == 0 {
            return None;
        }
        self.unlockfunc
            .as_ref()
            .map(|callback| (Arc::clone(callback), self.clientdata))
    }
}

/// The share's internal handle: `share->admin` (`lib/curl_share.h:51`).
///
/// `curl_share_init` creates one eagerly -- `share->admin = curl_easy_init()`
/// (`lib/curl_share.c:40`), with `mid = 0` and `state.internal = TRUE`
/// (`:46-47`) -- and `Curl_cpool_init(&share->cpool, share->admin, share, 103)`
/// (`:130`) hands it to the connection pool as its `idata`. The pool then
/// drives every disposal through it, which is what makes
/// `Curl_cpool_destroy`'s guard `if(cpool && cpool->initialised &&
/// cpool->idata)` (`lib/conncache.c:233`) meaningful: **without a retained
/// admin context the C does not destroy the pool at all**, it merely frees the
/// structure around it.
///
/// This is that context, reduced to what the destroy actually consults. It is
/// not an easy handle: `crate::easy` has no handle type at this commit, and
/// none of the eleven questions [`ShutdownHost`] asks needs one. What it does
/// need is somewhere to answer them from, and somewhere to keep the
/// [`ShutdownQueue`] and the clock the disposal path takes as arguments.
///
/// # The answers, and why each is the C's
///
/// * **`has_admin` -- `false`.** `data->multi && data->multi->admin`
///   (`lib/cshutdn.c:139`): a share's admin handle has no multi handle, so
///   the conjunct is false in the C too.
/// * **`has_multi` -- `false`.** `data->multi` (`:157`, `:161`), likewise.
///   This one is load-bearing: with no multi handle `cpool_discard_conn`
///   terminates each connection in place instead of queueing it, which is
///   what makes a synchronous destroy correct.
/// * **`is_internal` -- `true`.** `data->state.internal` (`:51`), which
///   `lib/curl_share.c:47` sets on exactly this handle. It is what caps a
///   blocking disposal at the internal budget rather than the transfer's.
/// * **`set_operation_timeout_ms` and `restart_operation_timing` -- no-ops.**
///   `data->set.timeout` and `Curl_pgrsTime(data, TIMER_STARTOP)`
///   (`:52-53`) are writes into a handle, and there is no handle here to
///   write into; the external cap in `run_conn_handler` enforces the same
///   budget regardless.
/// * **`socket_cb_installed` -- `false`.** `cshutdn->multi->socket_cb`
///   (`:411`): no multi handle, no socket callback, so no event state to
///   maintain.
/// * **`assess_conn` -- [`CURLMcode::Ok`].** Reached through
///   `cshutdn_update_ev` (`:380-393`), which the C skips entirely when no
///   socket callback is installed.
/// * **`conn_done`, `connchanged` and `expire` -- no-ops.** All three act on
///   the multi handle (`:158`, `:163`, `:263`) and are gated on
///   `data->multi`.
/// * **`max_total_connections` -- `0`.** `multi->max_total_connections`
///   (`lib/multihandle.h:152`); zero is the C's *unlimited*, and a share has
///   no such option of its own.
///
/// A share's admin is therefore the *simplest* host the shutdown layer
/// admits, and every simplification is one the C makes for the same reason.
struct ShareAdmin {
    /// The queue `ConnectionPool::destroy` takes.
    ///
    /// Owned rather than borrowed because the C's lives on the multi handle
    /// (`&data->multi->cshutdn`) and a share has none. It stays empty:
    /// `ShareAdminHost::has_multi` is false, so `lib/conncache.c:225-228`
    /// takes the
    /// `Curl_cshutdn_terminate` branch for every connection and never reaches
    /// `Curl_cshutdn_add`. Kept anyway, because the parameter is not optional
    /// and because a queue that silently could not be reached would be worse
    /// than one that provably is not.
    queue: ShutdownQueue,
    /// The clock the disposal path measures with.
    ///
    /// The production clock, zero-sized, so retaining it costs nothing. C
    /// reads `curlx_now()` through the same handle it attributes everything
    /// else to.
    clock: SystemClock,
}

impl ShareAdmin {
    /// The admin context `curl_share_init` creates (`lib/curl_share.c:40-47`).
    fn new() -> Self {
        Self {
            queue: ShutdownQueue::new(),
            clock: SystemClock,
        }
    }

    /// Destroys `pool` -- `Curl_cpool_destroy` (`lib/conncache.c:231-254`).
    ///
    /// Every remaining connection goes through the pool's own disposal path,
    /// which sends the protocol farewell, shuts the filter chains down and
    /// closes the socket, in the C's order. The alternative -- dropping the
    /// pool -- reclaims the same memory while performing none of that, which
    /// is what this method exists to stop.
    ///
    /// # Driving an `async` teardown from a synchronous ABI function
    ///
    /// `curl_share_cleanup` is synchronous and `ConnectionPool::destroy` is
    /// `async`, exactly as the C's disposal is synchronous and blocks. The
    /// future is therefore driven to completion here, and *how* is chosen so
    /// that neither outcome the module forbids -- a panic or a hang -- is
    /// reachable:
    ///
    /// * **Inside a `tokio` context**, the ambient runtime's time driver is in
    ///   scope, so `futures::executor::block_on` can drive the one timer the
    ///   path may arm: `ShuttingDownConnection::run_conn_handler` documents
    ///   that `tokio::time::timeout` is reached exactly when the handle is
    ///   internal -- which a share's admin is -- and the scheme has a
    ///   disconnect handler.
    /// * **Outside one**, a `current_thread` runtime with the time driver is
    ///   built for the call, so that same cap still works. It is dropped when
    ///   the call returns.
    /// * If a runtime cannot be built at all, the future is driven without
    ///   one. That path reaches no timer for a connection whose scheme has no
    ///   disconnect handler, which is every connection at this commit.
    ///
    /// What is NOT this method's business is the readiness of sockets
    /// registered with the engine's own runtime; their wakeups come from that
    /// runtime's driver, which the FFI keeps alive for the lifetime of the
    /// library. `docs/libcurl/curl_share_cleanup.md` already requires that
    /// this call not race the transfers using the share.
    fn destroy_pool(&mut self, pool: &mut ConnectionPool) {
        let Self { queue, clock } = self;
        let mut cx = CallCtx::new(clock);
        // The host's answers are constants, so it is a separate zero-sized
        // value rather than this one: `destroy` takes the host and the queue as
        // two independent `&mut` borrows, and both live here.
        let mut host = ShareAdminHost;
        let destroy = pool.destroy(&mut cx, &mut host, queue);
        match tokio::runtime::Handle::try_current() {
            // Already inside a runtime: its time driver is in scope.
            Ok(_) => futures::executor::block_on(destroy),
            Err(_) => {
                match tokio::runtime::Builder::new_current_thread()
                    .enable_time()
                    .build()
                {
                    Ok(runtime) => runtime.block_on(destroy),
                    // No runtime could be built. Every connection whose scheme
                    // has no disconnect handler completes without one.
                    Err(_) => futures::executor::block_on(destroy),
                }
            }
        }
    }
}

/// The [`ShutdownHost`] answers a share's admin handle gives.
///
/// A separate zero-sized type rather than an `impl` on [`ShareAdmin`] itself,
/// because `ConnectionPool::destroy` takes the host and the queue as two
/// independent `&mut` borrows and [`ShareAdmin`] owns both. Splitting the
/// answers out is what lets one call site hold both without fighting the
/// borrow checker, and it costs nothing: every answer is a constant, for the
/// reasons [`ShareAdmin`] tabulates.
#[derive(Clone, Copy, Debug, Default)]
struct ShareAdminHost;

impl ShutdownHost for ShareAdminHost {
    /// `data->multi && data->multi->admin` (`lib/cshutdn.c:139`): a share's
    /// admin handle has no multi handle.
    fn has_admin(&self) -> bool {
        false
    }

    /// `data->multi` (`lib/cshutdn.c:157`, `:161`). False, which is what makes
    /// every connection terminate in place rather than being queued
    /// (`lib/conncache.c:225-228`).
    fn has_multi(&self) -> bool {
        false
    }

    /// `data->state.internal` (`lib/cshutdn.c:51`), which
    /// `lib/curl_share.c:47` sets on exactly this handle.
    fn is_internal(&self, _handle: ShutdownHandle) -> bool {
        true
    }

    /// `data->set.timeout = DEFAULT_SHUTDOWN_TIMEOUT_MS`
    /// (`lib/cshutdn.c:52`).
    ///
    /// There is no handle to write; `ShareAdmin`'s table records what a
    /// handle would have been given, and the external cap in
    /// `run_conn_handler` enforces the same budget regardless.
    fn set_operation_timeout_ms(
        &mut self,
        _handle: ShutdownHandle,
        _timeout_ms: TimeDiff,
    ) {
    }

    /// `Curl_pgrsTime(data, TIMER_STARTOP)` (`lib/cshutdn.c:53`).
    fn restart_operation_timing(&mut self, _handle: ShutdownHandle) {}

    /// `cshutdn->multi->socket_cb` (`lib/cshutdn.c:411`): no multi handle, so
    /// no socket callback and no event state to maintain.
    fn socket_cb_installed(&self) -> bool {
        false
    }

    /// `Curl_multi_ev_assess_conn` (`lib/multi_ev.h:59`), reached through
    /// `cshutdn_update_ev` (`lib/cshutdn.c:380-393`) only when a socket
    /// callback is installed. Unreachable here, and success is the answer that
    /// keeps a connection on the ordinary disposal path if it ever is reached.
    fn assess_conn(
        &mut self,
        _handle: ShutdownHandle,
        _id: ConnId,
        _cx: &mut CallCtx<'_, '_>,
        _chains: &mut FilterChains,
    ) -> CURLMcode {
        CURLMcode::Ok
    }

    /// `Curl_multi_ev_conn_done` (`lib/cshutdn.c:158`), gated on
    /// `data->multi`.
    fn conn_done(
        &mut self,
        _handle: ShutdownHandle,
        _id: ConnId,
        _cx: &mut CallCtx<'_, '_>,
        _chains: &mut FilterChains,
    ) {
    }

    /// `Curl_multi_connchanged` (`lib/cshutdn.c:163`), which wakes transfers
    /// parked for want of a connection. There is no multi handle to wake.
    fn connchanged(&mut self) {}

    /// `Curl_expire_ex(data, milli, id)` (`lib/cshutdn.c:263`), which arms a
    /// timer on the multi handle.
    fn expire(
        &mut self,
        _handle: ShutdownHandle,
        _timeout_ms: TimeDiff,
        _timer: TimerId,
    ) {
    }

    /// `multi->max_total_connections` (`lib/multihandle.h:152`): zero is the
    /// C's "unlimited", and a share has no such option.
    fn max_total_connections(&self) -> usize {
        0
    }
}

/// Where a share is in its life, as its validity tag records it.
///
/// The C has only two of these three states -- `CURL_GOOD_SHARE` and the zero
/// `curl_share_cleanup` writes at `lib/curl_share.c:263` -- and the missing
/// middle is what lets two concurrent `curl_share_cleanup` calls both succeed
/// there. [`ShareCore::claim_cleanup`] states the full argument;
/// [`ShareCore::CLEANING_MAGIC`] is the tag value that carries
/// [`Self::Cleaning`].
///
/// Which entry points accept which phase is deliberate and is the whole of the
/// lifecycle serialisation:
///
/// | Phase | `setopt`, accessors, `attach` | `detach`, `lock`, `unlock` |
/// |-------|-------------------------------|----------------------------|
/// | [`Self::Live`] | accepted | accepted |
/// | [`Self::Cleaning`] | refused | accepted |
/// | [`Self::Dead`] | refused | refused |
///
/// *Refused* is [`CURLSHcode::Invalid`] where the entry point returns a code
/// and [`None`] where it returns an [`Option`]. `cleanup` is the fourth
/// column and does not fit one: it *claims* in [`Self::Live`] and reports
/// [`CURLSHcode::Invalid`] in the other two.
///
/// `detach` is deliberately accepted while a teardown is in progress: a
/// refusal there would swallow a decrement the caller has already committed
/// to -- `lib/setopt.c:1514` and `lib/url.c:292` both perform it
/// unconditionally once they hold the lock -- and leave a count that no
/// later cleanup could ever bring to zero. `lock` and `unlock` are accepted
/// for the same reason the C accepts them: its tag is still
/// `CURL_GOOD_SHARE` throughout the teardown, and the teardown itself
/// delivers notifications (`lib/conncache.c:41-60`, reached from
/// `Curl_cpool_destroy`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Lifecycle {
    /// `magic == CURL_GOOD_SHARE`: `GOOD_SHARE_HANDLE` holds.
    Live,
    /// A [`Share::cleanup`] has claimed this share and is running.
    Cleaning,
    /// `magic == 0`: the teardown finished, and the FFI may free.
    Dead,
}

impl Lifecycle {
    /// Classifies a tag read.
    ///
    /// Any value that is neither of the two known tags is [`Self::Dead`],
    /// which is the same conservative answer `GOOD_SHARE_HANDLE`
    /// (`lib/curl_share.h:37`) gives for a tag it does not recognise. The
    /// tag is private and only this module writes it, so no other value is
    /// reachable; classifying it anyway keeps the function total without a
    /// panicking arm.
    fn of(magic: u32) -> Self {
        match magic {
            ShareCore::GOOD_MAGIC => Self::Live,
            ShareCore::CLEANING_MAGIC => Self::Cleaning,
            _ => Self::Dead,
        }
    }

    /// Whether this share still exists as far as a notification is concerned.
    ///
    /// True for [`Self::Live`] and [`Self::Cleaning`]: the C's tag is
    /// `CURL_GOOD_SHARE` for both, so `Curl_share_lock` and
    /// `Curl_share_unlock` (`lib/curl_share.c:269-299`) deliver in both.
    fn is_present(self) -> bool {
        !matches!(self, Self::Dead)
    }
}

/// The thread-safe part of a share: everything but the connection pool.
///
/// The state of `struct Curl_share` (`lib/curl_share.h:43-66`) minus its
/// `cpool` and `admin` members, which is exactly the part that is
/// `Send + Sync` -- and therefore exactly the part one share can genuinely
/// serve to several threads with, which
/// `docs/libcurl/opts/CURLSHOPT_SHARE.md` and `tests/libtest/lib506.c` and
/// `lib3207.c` require of `CURL_LOCK_DATA_DNS`, `CURL_LOCK_DATA_SSL_SESSION`,
/// `CURL_LOCK_DATA_COOKIE`, `CURL_LOCK_DATA_HSTS` and `CURL_LOCK_DATA_PSL`.
/// [`Share`] owns one of these behind an [`Arc`] and hands clones out through
/// `Share::stores`.
///
/// # Why this type exists at all
///
/// Because `crate::conn::pool::ConnectionPool` is not `Send`, and a container
/// holding a `!Send` value is not `Send` either. Splitting the share in two
/// confines that to the one datum that causes it instead of letting it decide
/// the thread-safety of all six, and it does so without weakening anything:
/// the pool stays a real pool, owned by [`Share`], reachable through
/// `Share::pool`, destroyed by [`Share::cleanup`]. The module documentation
/// carries the measurement, the exact blockers and what removing them
/// requires.
///
/// # `pub`, and why that does not export any store
///
/// [`Share`] dereferences to this type, so it must be at least as visible.
/// Its `pub` surface is the same shape as [`Share`]'s -- the validity check,
/// the specifier, the reference count and the two ownership transactions --
/// and every accessor that names a `pub(crate)` store type is itself
/// `pub(crate)`, which is what keeps `error[E0446]` away. Its fields are all
/// private, exactly as `struct Curl_share`'s are *"libcurl-private, do not
/// export details"* (`lib/curl_share.h:42`).
///
/// # Locking layout
///
/// One lock per datum, which is the shape `tests/libtest/lib3207.c:135`
/// gives its own `curl_mutex_t mutexes[CURL_LOCK_DATA_LAST - 1]`, plus one for
/// the metadata. Separate locks rather than one lock over everything for a
/// reason that is behavioural and not performance: the C's callbacks are
/// per-kind, and a single lock would serialise kinds the C keeps independent,
/// making a nested `CURL_LOCK_DATA_COOKIE`-then-`CURL_LOCK_DATA_PSL` sequence
/// -- which `lib/cookie.c` performs around `Curl_psl_use` -- deadlock.
///
/// Lock ordering is fixed and shallow. Metadata is always taken **before** a
/// store lock and never after one: [`Share::setopt`] holds the metadata across
/// the whole `CURLSHOPT_SHARE` switch, whose arms take a store lock, so the
/// pair `meta -> store` occurs and the pair `store -> meta` must not. That is
/// why `ShareGuard` and `PslGuard` declare their store guard before their
/// unlock token: the store lock is released first, and the metadata the
/// notification needs is taken only after it is gone. A store lock is never
/// taken while another store lock is held except for the one nesting the C
/// itself performs, cookie then PSL. That is what keeps the callbacks
/// non-nested per kind, which `tests/libtest/lib506.c`'s double-lock detector
/// proves the C guarantees.
pub struct ShareCore {
    /// `share->magic` (`lib/curl_share.h:44`): the validity tag.
    ///
    /// An [`AtomicU32`] and not part of [`Meta`], because the C reads it
    /// before taking any lock -- `GOOD_SHARE_HANDLE(share)` is the first thing
    /// `curl_share_setopt` (`lib/curl_share.c:68`) and `curl_share_cleanup`
    /// (`:224`) do -- and because a validity check that could itself block on
    /// a poisoned lock would be no check at all.
    magic: AtomicU32,
    /// The specifier, the reference count and the callbacks.
    meta: Mutex<Meta>,
    /// `share->dnscache` (`lib/curl_share.h:53`): held **by value** in the C
    /// and initialised eagerly, so there is no [`Option`] here.
    dnscache: Mutex<DnsCache>,
    /// `share->cookies` (`lib/curl_share.h:55`): a **pointer** in the C, so an
    /// [`Option`] here.
    ///
    /// Created lazily by `CURLSHOPT_SHARE` (`lib/curl_share.c:89-93`) and
    /// destroyed by `CURLSHOPT_UNSHARE` (`:157-160`).
    #[cfg(feature = "cookies")]
    cookies: Mutex<Option<CookieInfo>>,
    /// `share->psl` (`lib/curl_share.h:58`): held **by value** in the C, and
    /// -- uniquely -- never initialised by any code path.
    ///
    /// An [`RwLock`] rather than a [`Mutex`] because this is the only datum
    /// the C ever asks for with `CURL_LOCK_ACCESS_SHARED`
    /// (`lib/psl.c:51`, `:89`).
    #[cfg(feature = "cookies")]
    psl: RwLock<PslCache>,
    /// `share->hsts` (`lib/curl_share.h:61`): a **pointer** in the C, so an
    /// [`Option`] here.
    ///
    /// Created lazily (`lib/curl_share.c:101-105`) and destroyed by
    /// `CURLSHOPT_UNSHARE` (`:168-170`).
    #[cfg(feature = "hsts")]
    hsts: Mutex<Option<HstsCache>>,
    /// `share->ssl_scache` (`lib/curl_share.h:64`): a **pointer** in the C, so
    /// an [`Option`] here.
    ssl_scache: Mutex<Option<SessionCache>>,
}

/// A share: state deliberately shared between easy handles.
///
/// Supersedes `struct Curl_share` (`lib/curl_share.h:43-66`), which carries
/// the comment *"this struct is libcurl-private, do not export details"*
/// (`:42`). That comment is this type's specification as much as its
/// documentation: the C hands applications a `void *`
/// (`include/curl/curl.h:110`), and every field here is private for the same
/// reason.
///
/// # What this type is, and what [`ShareCore`] is
///
/// This is the **owner**: the value `curl_share_init` hands out and
/// `curl_share_cleanup` frees. It holds the two members that cannot travel --
/// the connection pool and the admin context that destroys it -- and an
/// [`Arc`] of the rest. Everything in that rest is `Send + Sync`, so a clone
/// of it, which `Share::stores` returns, serves one share to as many threads
/// as the application has. This type is neither, because
/// `crate::conn::pool::ConnectionPool` is not `Send`; the module
/// documentation carries the measurement and what removing that requires.
///
/// It dereferences to [`ShareCore`], so every operation on the shared state --
/// [`ShareCore::attach`], [`ShareCore::detach`], the store accessors, the
/// notifications, the specifier and the reference count -- is available
/// directly on a [`Share`] and reads exactly as it did before the split.
///
/// # Ownership at the C boundary
///
/// `curl_share_init` performs `Box::into_raw` on one of these and
/// `curl_share_cleanup` performs `Box::from_raw` -- but **only** after
/// [`Self::cleanup`] has returned [`CURLSHcode::Ok`], and at most one caller
/// per share can ever receive it. Every entry point takes `&self`, so the
/// object can never be consumed by an operation that is supposed to fail
/// leaving it usable, which `docs/libcurl/curl_share_cleanup.md:59-60`
/// requires: *"If an error occurs, then the share object is not deleted."*
pub struct Share {
    /// The shared, thread-safe state: the metadata and five of the six stores.
    ///
    /// An [`Arc`] rather than a plain value so that [`Self::stores`] can hand
    /// a second thread a handle to the same state. The count also decides
    /// when the state is reclaimed, which is strictly safer than the C's
    /// `curlx_free(share)` at `lib/curl_share.c:264`: a handle that outlives
    /// the `CURLSH` sees a retired share and reports
    /// [`CURLSHcode::Invalid`], where the C would read freed memory.
    core: Arc<ShareCore>,
    /// `share->cpool` (`lib/curl_share.h:52`): held **by value** in the C but
    /// guarded by its own `cpool.initialised` flag, which an [`Option`]
    /// expresses without a second field.
    ///
    /// Created lazily on the first `CURLSHOPT_SHARE` with
    /// `CURL_LOCK_DATA_CONNECT` (`lib/curl_share.c:127-132`, whose comment is
    /// *"It is safe to set this option several times on a share."*), **not**
    /// destroyed by `CURLSHOPT_UNSHARE` (`:187-188` is a bare `break`), and
    /// destroyed at cleanup only when the specifier bit is still set
    /// (`:237-239`).
    ///
    /// This was the field that made [`Share`] neither `Send` nor `Sync`. The
    /// connection layer's seam traits now carry `Send`/`Send + Sync` bounds and
    /// share their injected objects through [`Arc`], so a pool is [`Send`] and
    /// a `Mutex` of one is `Send + Sync`. The module documentation records what
    /// changed and where.
    cpool: Mutex<Option<ConnectionPool>>,
    /// `share->admin` (`lib/curl_share.h:51`): the internal handle the pool's
    /// disposal path is driven through.
    ///
    /// Created eagerly, as `curl_share_init` creates its
    /// (`lib/curl_share.c:40`), and retained for the whole life of the share
    /// because that is what `Curl_cpool_destroy`'s `cpool->idata` guard
    /// (`lib/conncache.c:233`) requires: a pool with no admin context is a
    /// pool the C does not destroy. [`ShareAdmin`] records what it answers and
    /// why each answer is the C's. It sits beside the pool, not in the core,
    /// because it exists only to destroy the pool.
    admin: Mutex<ShareAdmin>,
}

impl Deref for Share {
    type Target = ShareCore;

    /// The shared state, so that a [`Share`] answers every question
    /// [`ShareCore`] answers.
    ///
    /// This is what makes the split invisible to a caller: `share.attach(..)`,
    /// `share.specifier()`, `share.cookies(..)` and the rest resolve here,
    /// while `share.pool(..)` and `share.cleanup()` -- the two that need the
    /// pool -- resolve on [`Share`] itself.
    fn deref(&self) -> &Self::Target {
        &self.core
    }
}

impl Default for Share {
    /// [`Share::new`], so that the type satisfies the convention a
    /// no-argument constructor implies.
    fn default() -> Self {
        Self::new()
    }
}

/// `Some(true)` present, `Some(false)` absent, [`None`] locked.
///
/// Free rather than nested inside a `fmt` method because both [`Share`] and
/// [`ShareCore`] report their slots this way.
fn presence<T>(slot: &Mutex<Option<T>>) -> Option<bool> {
    slot.try_lock().ok().map(|guard| guard.is_some())
}

/// `<locked>` for a lock the caller could not take.
fn describe(state: Option<bool>) -> &'static str {
    match state {
        Some(true) => "present",
        Some(false) => "absent",
        None => "<locked>",
    }
}

impl fmt::Debug for ShareCore {
    /// Hand-written for two reasons.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = f.debug_struct("ShareCore");
        out.field("magic", &format_args!("{:#x}", self.magic()))
            .field("valid", &self.is_valid());
        match self.meta.try_lock() {
            Ok(meta) => {
                out.field(
                    "specifier",
                    &format_args!("{}", Specifier(meta.specifier)),
                )
                .field("dirty", &meta.dirty)
                .field("lockfunc", &meta.lockfunc.is_some())
                .field("unlockfunc", &meta.unlockfunc.is_some())
                .field(
                    "clientdata",
                    &format_args!("{:#x}", meta.clientdata.bits()),
                );
            }
            Err(_) => {
                out.field("meta", &"<locked>");
            }
        }
        #[cfg(feature = "cookies")]
        out.field("cookies", &describe(presence(&self.cookies)));
        #[cfg(feature = "cookies")]
        out.field(
            "psl",
            &describe(self.psl.try_read().ok().map(|psl| psl.has_list())),
        );
        #[cfg(feature = "hsts")]
        out.field("hsts", &describe(presence(&self.hsts)));
        out.field("ssl_scache", &describe(presence(&self.ssl_scache)))
            .finish()
    }
}

impl fmt::Debug for Share {
    /// The shared state, plus the one store this type owns.
    ///
    /// [`ShareCore`]'s implementation does the work and states why every lock
    /// is probed rather than taken; this adds the connection pool, reported the
    /// same way.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Share")
            .field("core", &self.core)
            .field("cpool", &describe(presence(&self.cpool)))
            .finish()
    }
}

impl ShareCore {
    /// `CURL_GOOD_SHARE` (`lib/curl_share.h:36`): the validity tag a live
    /// share carries.
    pub const GOOD_MAGIC: u32 = 0x7e11_7a1e;

    /// The tag a share carries while its teardown is in progress.
    ///
    /// **No C counterpart.** The C has two states, `CURL_GOOD_SHARE` and the
    /// zero `lib/curl_share.c:263` writes, and therefore no way to say *"a
    /// teardown has been claimed but has not finished"* -- which is why two
    /// threads can both pass its `GOOD_SHARE_HANDLE` check and both reach
    /// `CURLSHE_OK`. [`ShareCore::claim_cleanup`] records the full argument.
    ///
    /// The one's complement of [`Self::GOOD_MAGIC`], so it can collide with
    /// neither the tag nor the zero, and so that a value seen in a debugger is
    /// recognisably derived from the C's rather than arbitrary. It is private:
    /// nothing outside this module has a use for it, and
    /// `GOOD_SHARE_HANDLE`'s answer for it is `false`, which
    /// [`ShareCore::is_valid`] delivers.
    const CLEANING_MAGIC: u32 = Self::GOOD_MAGIC ^ u32::MAX;

    /// `curl_share_init` (`lib/curl_share.c:33-55`).
    ///
    /// The observable sequence, in the C's order:
    ///
    /// 1. `:35` allocate zeroed.
    /// 2. `:37` `share->magic = CURL_GOOD_SHARE`.
    /// 3. `:38` `share->specifier |= (1 << CURL_LOCK_DATA_SHARE)` -- bit 1 is
    ///    set from birth, before an application asks for anything.
    /// 4. `:39` `Curl_dnscache_init(&share->dnscache, 23)` -- the DNS cache is
    ///    the one store built eagerly.
    /// 5. `:40-51` create the internal `admin` easy handle; see below.
    ///
    /// # Why this cannot fail
    ///
    /// The C returns `NULL` from two paths: a failed `curlx_calloc` (`:36`
    /// falls through to `return share`, which is the null it just got) and a
    /// failed `curl_easy_init` for the admin handle (`:41-44`). Neither has a
    /// Rust counterpart -- the `calloc` is one fixed-size struct whose size this
    /// crate chooses, so it is not an externally sized allocation and there is
    /// no stable fallible spelling for it; a refusal aborts rather than yielding a
    /// null, and there is no admin handle to fail. `curl_share_init`
    /// consequently never returns `NULL` in this implementation, which is a
    /// divergence a caller cannot observe except by no longer taking a branch
    /// it was already required to handle.
    ///
    /// # The `admin` handle, and why it has no counterpart here
    ///
    /// `lib/curl_share.c:40-47` creates a `struct Curl_easy`, gives it `mid =
    /// 0` and sets `state.internal = TRUE`, so that the connection pool and
    /// the trace machinery have a handle to attribute callbacks and
    /// diagnostics to. The two jobs the admin handle does in the C are
    /// therefore carried differently here. The `CURL *handle` a callback
    /// receives is supplied per call as a [`LockOwner`], because it varies per
    /// call and the C varies it too -- `Curl_share_lock` passes the transfer's
    /// handle while `curl_share_cleanup` passes `NULL`. Trace attribution has
    /// no subject because this module emits no diagnostics; `lib/curl_share.c`
    /// emits none either.
    ///
    /// `:48-51`'s `#ifdef DEBUGBUILD` block, which sets `set.verbose` when
    /// `CURL_DEBUG` is in the environment, is deliberately **omitted**. There
    /// is no debug-build feature in this crate's fifteen to gate it on -- the
    /// vocabulary is fixed and contains no `debug` -- and inventing one to
    /// carry a diagnostic default would add a build configuration for
    /// something with no observable effect on any contract. It also has
    /// nothing to act on, for the same reason the admin handle does not.
    ///
    /// This constructs the shared half; [`Share::new`] is the entry point and
    /// adds the connection pool and the admin context to it.
    ///
    /// Private, and deliberately not `Default`: a bare [`ShareCore`] is not a
    /// share. `curl_share_init` returns one thing, and here that is a
    /// [`Share`] -- the owner that holds the pool and the admin context this
    /// leaves out.
    fn new() -> Self {
        Self {
            // C: lib/curl_share.c:37.
            magic: AtomicU32::new(Self::GOOD_MAGIC),
            // C: lib/curl_share.c:38, inside Meta::new.
            meta: Mutex::new(Meta::new()),
            // C: lib/curl_share.c:39 -- eager, with 23 slots.
            dnscache: Mutex::new(DnsCache::with_size(DNS_CACHE_SLOTS)),
            // C: lib/curl_share.h:55 -- a null pointer after calloc.
            #[cfg(feature = "cookies")]
            cookies: Mutex::new(None),
            // C: lib/curl_share.h:58 -- zeroed, and therefore stale, so the
            // first use refreshes it. No initialization call exists.
            #[cfg(feature = "cookies")]
            psl: RwLock::new(PslCache::new()),
            // C: lib/curl_share.h:61 -- a null pointer after calloc.
            #[cfg(feature = "hsts")]
            hsts: Mutex::new(None),
            // C: lib/curl_share.h:64 -- a null pointer after calloc.
            ssl_scache: Mutex::new(None),
        }
    }

    /// The validity tag as it stands: `share->magic`
    /// (`lib/curl_share.h:44`).
    ///
    /// [`Self::GOOD_MAGIC`] for a live share and zero once [`Share::cleanup`]
    /// has succeeded, which is the transition `lib/curl_share.c:263` performs
    /// immediately before `curlx_free`.
    #[must_use]
    pub fn magic(&self) -> u32 {
        // `Acquire`, paired with the `Release` in `cleanup`, so that a thread
        // observing the tag as zero also observes the teardown that preceded
        // it. The C reads a plain `unsigned int` with no ordering at all;
        // adding one cannot change an observable result and cannot cost
        // anything measurable on any of the four mandated targets.
        self.magic.load(Ordering::Acquire)
    }

    /// `GOOD_SHARE_HANDLE(share)` (`lib/curl_share.h:37`).
    ///
    /// # This is a heuristic in C and remains one here
    ///
    /// It exists so that a second `curl_share_cleanup` on the same pointer
    /// returns [`CURLSHcode::Invalid`] instead of corrupting memory, and it
    /// works in the C only because freed storage usually still holds the zero
    /// that `:263` wrote. Reading through a dangling pointer is undefined
    /// behaviour in both languages, so `curl-rs-ffi` gets the same best-effort
    /// guarantee the C offers and no more. What is guaranteed is the ordering:
    /// the tag is cleared before the object is dropped, never after, so the
    /// window in which a stale pointer reads as valid is empty.
    ///
    /// # One window where this answers `false` and the C answers `true`
    ///
    /// While a [`Share::cleanup`] is in progress the tag holds
    /// `Lifecycle::Cleaning`'s value, so this reports `false` where the C --
    /// which does not zero `magic` until `:263`, after the teardown -- would
    /// still report `true`. That window is reachable only by calling an entry
    /// point concurrently with `curl_share_cleanup`, which in the C races the
    /// teardown into freed memory. Answering [`CURLSHcode::Invalid`] there is
    /// the defined result where the C has none, and it is what makes the
    /// claim below able to serialise the lifecycle.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.lifecycle() == Lifecycle::Live
    }

    /// Which phase of its life this share is in.
    ///
    /// The tag is read once and classified once, so that a caller cannot see
    /// two different answers from two reads of the same value.
    fn lifecycle(&self) -> Lifecycle {
        Lifecycle::of(self.magic())
    }

    /// Claims the right to tear this share down, exactly once.
    ///
    /// The whole of [`Share::cleanup`]'s serialisation, and the reason the
    /// FFI's `Box::from_raw` cannot run twice. `curl_share_cleanup`
    /// (`lib/curl_share.c:221-267`) tests `GOOD_SHARE_HANDLE` at `:224`,
    /// reads `share->dirty` at `:231` and clears the tag at `:263` -- three
    /// unsynchronised steps, so two threads entering it together both pass
    /// `:224`, both read a zero count and both reach `:266` with
    /// `CURLSHE_OK`. Under the FFI's ownership rule that is two
    /// `Box::from_raw` calls on one allocation.
    ///
    /// A single compare-and-exchange from [`Lifecycle::Live`] to
    /// [`Lifecycle::Cleaning`] closes it: the loser observes
    /// [`Lifecycle::Cleaning`] or [`Lifecycle::Dead`] and reports
    /// [`CURLSHcode::Invalid`], which is the code the C reports for the
    /// second cleanup of a share it has already freed. It closes the other
    /// half too: [`Self::attach`] refuses while the claim is held, so the
    /// count this function's caller goes on to read cannot be raised behind
    /// it.
    ///
    /// `AcqRel` on success so that everything the winner does next is ordered
    /// after every attach that preceded the claim; `Acquire` on failure so
    /// that a loser which observes [`Lifecycle::Dead`] also observes the
    /// teardown that produced it.
    fn claim_cleanup(&self) -> bool {
        self.magic
            .compare_exchange(
                Self::GOOD_MAGIC,
                Self::CLEANING_MAGIC,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// Gives the claim back, leaving the share exactly as it was.
    ///
    /// The [`CURLSHcode::InUse`] path of `curl_share_cleanup`
    /// (`lib/curl_share.c:231-235`), which `docs/libcurl/curl_share_cleanup.md`
    /// requires to leave the object usable: *"If an error occurs, then the
    /// share object is not deleted."* A share that refused to be cleaned up
    /// must therefore return to [`Lifecycle::Live`] and accept everything it
    /// accepted before, this call included.
    fn release_claim(&self) {
        self.magic.store(Self::GOOD_MAGIC, Ordering::Release);
    }

    /// Retires the share: `share->magic = 0` (`lib/curl_share.c:263`).
    ///
    /// Called only by the thread holding the claim, and only after the
    /// teardown, so `Release` publishes that teardown to whoever next reads
    /// the tag.
    fn finish_cleanup(&self) {
        self.magic.store(0, Ordering::Release);
    }

    /// The metadata lock, recovering from poisoning rather than panicking.
    fn meta(&self) -> MutexGuard<'_, Meta> {
        self.meta.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Which kinds this share is sharing: `share->specifier`.
    ///
    /// A snapshot. `curl_share_setopt` refuses to change the specifier while
    /// any handle references the share (`lib/curl_share.c:71-74`), so for the
    /// whole time a transfer could be reading this it cannot change.
    #[must_use]
    pub fn specifier(&self) -> Specifier {
        Specifier(self.meta().specifier)
    }

    /// How many easy handles reference this share: `share->dirty`
    /// (`lib/curl_share.h:46`).
    #[must_use]
    pub fn dirty(&self) -> u32 {
        self.meta().dirty
    }

    /// Whether any handle references this share.
    ///
    /// The predicate behind both of the C's refusals: `curl_share_setopt`
    /// returns `CURLSHE_IN_USE` at `lib/curl_share.c:71-74` and
    /// `curl_share_cleanup` at `:231-235`.
    #[must_use]
    pub fn is_in_use(&self) -> bool {
        self.dirty() != 0
    }

    /// Whether `kind` is being shared.
    ///
    /// The question `dnscache_get` (`lib/hostip.c:300`),
    /// `CURL_SHARE_KEEP_CONNECT` (`lib/curl_share.h:39-40`) and
    /// `CURL_SHARE_ssl_scache` (`:73-75`) each ask of the specifier.
    #[allow(dead_code)] // consumers: crate::conn, crate::tls, crate::easy
    pub(crate) fn is_shared(&self, kind: LockData) -> bool {
        self.specifier().contains(kind)
    }

    /// `Curl_share_lock` (`lib/curl_share.c:269-284`).
    ///
    /// # Return value
    ///
    /// The C's `if(!share) return CURLSHE_INVALID` (`:274-275`) tests the easy
    /// handle's share pointer, which is unrepresentable here because the
    /// receiver *is* the share -- a caller with no share does not call. What
    /// remains is [`CURLSHcode::Ok`] for every live share, exactly as the C
    /// returns, and [`CURLSHcode::Invalid`] for a torn-down one. That second
    /// arm is an addition, and it can only fire where the C would already have
    /// been reading freed memory; its effect is that a stale share delivers no
    /// callback rather than an unpredictable one.
    ///
    /// A share whose teardown is in progress still delivers, because the C's
    /// tag is still `CURL_GOOD_SHARE` until `:263` and its own teardown
    /// notifies through this path: `Curl_cpool_destroy` brackets its removal
    /// loop with `CPOOL_LOCK`/`CPOOL_UNLOCK` (`lib/conncache.c:41-60`), which
    /// are `Curl_share_lock` and `Curl_share_unlock` for
    /// `CURL_LOCK_DATA_CONNECT`. [`Lifecycle`] tabulates which phase each
    /// entry point accepts.
    ///
    /// # This does not take a Rust lock
    ///
    /// It is the notification and nothing else, which is what
    /// `lib/conncache.c:41-50`, `lib/hostip.c:307-312`,
    /// `lib/vtls/vtls_scache.c:585-589` and `lib/psl.c` all call it for. The
    /// Rust lock over a store is taken by that store's accessor, and those
    /// accessors call this once each, so a caller must not pair this with an
    /// accessor for the same kind -- that would be the nesting
    /// `tests/libtest/lib506.c`'s double-lock detector rejects.
    #[allow(dead_code)] // consumers: crate::conn, crate::tls, crate::cookies
    pub(crate) fn lock(
        &self,
        owner: LockOwner,
        kind: LockData,
        access: LockAccess,
    ) -> CURLSHcode {
        if !self.lifecycle().is_present() {
            return CURLSHcode::Invalid;
        }
        // The notification is chosen under the metadata lock and delivered
        // after it is released: an application callback must never run with
        // this share's own lock held, or a callback that reached back into the
        // share would deadlock and one that panicked would poison the single
        // lock every entry point needs.
        let notification = self.meta().lock_notification(kind);
        if let Some((callback, clientdata)) = notification {
            callback(owner, kind, access, clientdata);
        }
        CURLSHcode::Ok
    }

    /// `Curl_share_unlock` (`lib/curl_share.c:286-299`).
    ///
    /// The mirror of [`Self::lock`], with **no access type**, because
    /// `curl_unlock_function` has no such parameter
    /// (`include/curl/curl.h:3054-3056`). The same specifier-bit and
    /// callback-presence conditions apply (`:293-296`).
    #[allow(dead_code)] // consumers: crate::conn, crate::tls, crate::cookies
    pub(crate) fn unlock(
        &self,
        owner: LockOwner,
        kind: LockData,
    ) -> CURLSHcode {
        if !self.lifecycle().is_present() {
            return CURLSHcode::Invalid;
        }
        let notification = self.meta().unlock_notification(kind);
        if let Some((callback, clientdata)) = notification {
            callback(owner, kind, clientdata);
        }
        CURLSHcode::Ok
    }

    /// Registers an easy handle against this share, returning what it must
    /// repoint at.
    ///
    /// `lib/setopt.c:1520-1550`, the second half of `CURLOPT_SHARE`:
    ///
    /// ```text
    /// if(GOOD_SHARE_HANDLE(set))
    ///   data->share = set;
    /// if(data->share) {
    ///   Curl_share_lock(data, CURL_LOCK_DATA_SHARE, CURL_LOCK_ACCESS_SINGLE);
    ///   data->share->dirty++;
    ///   ... repoint cookies, hsts and psl ...
    ///   Curl_share_unlock(data, CURL_LOCK_DATA_SHARE);
    /// }
    /// ```
    ///
    /// The count and the bracketing live here so that `crate::easy` and
    /// `crate::multi` cannot get them wrong. What the C decides the repointing
    /// from is the specifier -- `:1530` tests the shared cookie jar, `:1538`
    /// the shared HSTS cache and `:1545` the `CURL_LOCK_DATA_PSL` bit -- so
    /// the specifier is read inside the critical section and handed to
    /// `repoint`.
    ///
    /// # Why the repointing is a closure and not a returned mask
    ///
    /// Because `lib/setopt.c` performs it **between** the lock and the unlock,
    /// and that placement is observable: the application's lock callback is
    /// what serialises an attaching handle's view of the shared stores against
    /// every other handle's. Returning the mask for the caller to act on after
    /// the unlock would deliver a critical section that ends before the work
    /// it is supposed to cover -- the shared jar could be replaced, or the
    /// share torn down, between the two.
    ///
    /// `repoint` therefore runs inside the bracket, in the C's order:
    /// `dirty++` first (`:1527`), then the repointing (`:1529-1547`). It runs
    /// with none of this module's own locks held, so it may call back into the
    /// share for a different datum -- which is what the C does when it reads
    /// `share->cookies` -- and the unlock notification is delivered by
    /// `Release`, so a `repoint` that panics cannot leave an application
    /// mutex held for the rest of the process.
    ///
    /// # Returns
    ///
    /// `Some(repoint's value)` when the handle was registered, [`None`] when
    /// the share refused it and `repoint` was never called. That refusal is
    /// the C's `GOOD_SHARE_HANDLE(set)` guard at `:1520` -- a share that fails
    /// it is never assigned and never counted -- plus the one case the C
    /// cannot express: a share whose teardown has already been claimed, which
    /// must not acquire a new reference behind the claim.
    /// `ShareCore::claim_cleanup` gives the full argument.
    pub fn attach<R>(
        &self,
        owner: LockOwner,
        repoint: impl FnOnce(Specifier) -> R,
    ) -> Option<R> {
        // C: lib/setopt.c:1520 -- `if(GOOD_SHARE_HANDLE(set))`.
        if !self.is_valid() {
            return None;
        }
        // C: lib/setopt.c:1525.
        self.lock(owner, LockData::Share, LockAccess::Single);
        // C: lib/setopt.c:1549, on every path out of this scope from here on,
        // unwinding included.
        let _release = Release {
            core: self,
            owner,
            kind: LockData::Share,
        };
        let specifier = {
            let mut meta = self.meta();
            // Re-tested under the metadata lock, because the test above and
            // the increment below are not one step: a cleanup claimed in
            // between must not be handed a new reference it has already
            // decided it does not have. This is the half of the
            // stale-snapshot race that lives on the attaching side.
            if !self.is_valid() {
                return None;
            }
            // C: lib/setopt.c:1527 -- `data->share->dirty++` on an
            // `unsigned int`, which wraps. `wrapping_add` is that arithmetic
            // exactly, and it cannot panic in any build. The wrap point is
            // 4,294,967,296 concurrent handles; under the balanced lifecycle
            // this API enforces -- one attach per handle, one detach per
            // close -- it is unreachable, and diverging from C there would be
            // a behaviour change rather than a safeguard.
            meta.dirty = meta.dirty.wrapping_add(1);
            Specifier(meta.specifier)
        };
        // C: lib/setopt.c:1529-1547 -- inside the bracket, after the
        // increment.
        Some(repoint(specifier))
    }

    /// Deregisters an easy handle, returning what it must stop pointing at.
    ///
    /// The first half of `CURLOPT_SHARE` (`lib/setopt.c:1493-1518`) and all of
    /// `Curl_close`'s share handling (`lib/url.c:289-294`), which are the same
    /// three steps: take `CURL_LOCK_DATA_SHARE` exclusively, decrement, and
    /// release.
    ///
    /// `unlink` runs inside the bracket for the same reason [`Self::attach`]'s
    /// `repoint` does, and it matters more here: `lib/setopt.c:1509-1512`
    /// unlinks **both** of the handle's resolver entries when the
    /// `CURL_LOCK_DATA_DNS` bit is set, and `:1497-1507` nulls the cookie and
    /// HSTS pointers and repoints the PSL cache at the multi handle's or at
    /// nothing. Every one of those touches state the share still owns, so
    /// doing them after the unlock notification would race the next handle --
    /// or a cleanup -- for the stores being let go of.
    ///
    /// # The order is the C's, and the C's order is the safe one
    ///
    /// `unlink` runs **before** the decrement, because `lib/setopt.c` does the
    /// repointing at `:1497-1512` and the `dirty--` at `:1514`. That way the
    /// handle has finished letting go of every shared store before the count
    /// can reach zero and permit a teardown. `Curl_close`'s path
    /// (`lib/url.c:291-293`) has no repointing at all, which a closure that
    /// does nothing expresses exactly.
    ///
    /// # Underflow
    ///
    /// The C writes `dirty--` on an `unsigned int`, so an unbalanced call
    /// wraps to `UINT_MAX` and the share can never be cleaned up again. Both C
    /// call sites are guarded by `if(data->share)`, so libcurl itself never
    /// reaches it. `wrapping_sub` is that arithmetic exactly -- it cannot
    /// panic in any build, and it keeps the consequence the C's rather than
    /// inventing a friendlier one, which under a frozen API would be a
    /// behaviour change: an application that unbalanced its handles would
    /// otherwise see a share that cleans up here and refuses to in curl 8.x.
    ///
    /// # Returns
    ///
    /// `Some(unlink's value)`, or [`None`] when the share is already retired --
    /// in which case there is no count to lower and nothing for `unlink` to
    /// let go of. A teardown in progress is **not** a refusal: see
    /// `Lifecycle`.
    pub fn detach<R>(
        &self,
        owner: LockOwner,
        unlink: impl FnOnce(Specifier) -> R,
    ) -> Option<R> {
        if !self.lifecycle().is_present() {
            return None;
        }
        // C: lib/setopt.c:1494, lib/url.c:291.
        self.lock(owner, LockData::Share, LockAccess::Single);
        // C: lib/setopt.c:1516, lib/url.c:293, on every path out from here.
        let _release = Release {
            core: self,
            owner,
            kind: LockData::Share,
        };
        let specifier = self.specifier();
        // C: lib/setopt.c:1497-1512 -- inside the bracket, before the
        // decrement.
        let outcome = unlink(specifier);
        // C: lib/setopt.c:1514, lib/url.c:292.
        let mut meta = self.meta();
        meta.dirty = meta.dirty.wrapping_sub(1);
        drop(meta);
        Some(outcome)
    }
}

// `curl_share_init` (`lib/curl_share.c:33-55`), and the handle a second thread
// holds

impl Share {
    /// `CURL_GOOD_SHARE` (`lib/curl_share.h:36`): the validity tag a live
    /// share carries.
    ///
    /// The same constant as [`ShareCore::GOOD_MAGIC`], which is where the tag
    /// itself lives. It is restated here because an associated constant is not
    /// reached through [`Deref`], and `curl-rs-ffi` compares against
    /// `Share::GOOD_MAGIC`.
    pub const GOOD_MAGIC: u32 = ShareCore::GOOD_MAGIC;

    /// `curl_share_init` (`lib/curl_share.c:33-55`).
    ///
    /// The observable sequence, in the C's order:
    ///
    /// 1. `:35` allocate zeroed.
    /// 2. `:37` `share->magic = CURL_GOOD_SHARE`.
    /// 3. `:38` `share->specifier |= (1 << CURL_LOCK_DATA_SHARE)` -- bit 1 is
    ///    set from birth, before an application asks for anything.
    /// 4. `:39` `Curl_dnscache_init(&share->dnscache, 23)` -- the DNS cache is
    ///    the one store built eagerly.
    /// 5. `:40-47` create the internal `admin` handle, `mid = 0` and
    ///    `state.internal = TRUE`, which the connection pool's disposal path is
    ///    driven through. `ShareAdmin` is that context.
    ///
    /// Steps 2 to 4 belong to `ShareCore::new`; this adds the two members
    /// that cannot be shared between threads, the pool and its admin.
    ///
    /// # Why this cannot fail
    ///
    /// The C returns `NULL` from two paths: a failed `curlx_calloc` (`:36`
    /// falls through to `return share`, which is the null it just got) and a
    /// failed `curl_easy_init` for the admin handle (`:41-44`). Neither has a
    /// Rust counterpart -- an allocation failure aborts rather than yielding a
    /// null, and the admin context here is infallible. `curl_share_init`
    /// consequently never returns `NULL` in this implementation, which is a
    /// divergence a caller cannot observe except by no longer taking a branch
    /// it was already required to handle.
    ///
    /// `:48-51`'s `#ifdef DEBUGBUILD` block, which sets `set.verbose` when
    /// `CURL_DEBUG` is in the environment, is deliberately **omitted**. There
    /// is no debug-build feature in this crate's fifteen to gate it on -- the
    /// vocabulary is fixed and contains no `debug` -- and inventing one to
    /// carry a diagnostic default would add a build configuration for
    /// something with no observable effect on any contract.
    #[must_use]
    pub fn new() -> Self {
        Self {
            // C: lib/curl_share.c:37-39.
            core: Arc::new(ShareCore::new()),
            // C: lib/curl_share.h:52 -- `cpool.initialised` is false after
            // calloc, which `None` expresses.
            cpool: Mutex::new(None),
            // C: lib/curl_share.c:40-47 -- `share->admin = curl_easy_init()`,
            // eager, with `mid = 0` and `state.internal = TRUE`.
            admin: Mutex::new(ShareAdmin::new()),
        }
    }

    /// A handle on this share's thread-safe state, for another thread.
    ///
    /// The answer to the requirement `docs/libcurl/opts/CURLSHOPT_SHARE.md`
    /// states and `tests/libtest/lib506.c` and `lib3207.c` exercise: **one
    /// share, several threads**. lib506 drives one share from two threads with
    /// `CURL_LOCK_DATA_COOKIE` and `CURL_LOCK_DATA_DNS`, and lib3207 does the
    /// same with `CURL_LOCK_DATA_SSL_SESSION`; every kind those two programs
    /// use lives in [`ShareCore`], which is `Send + Sync`, so a clone of this
    /// handle serves them.
    ///
    /// What it does **not** carry is `CURL_LOCK_DATA_CONNECT`. The connection
    /// pool is not `Send`, so it stays with the [`Share`] and is reachable only
    /// through [`Self::pool`] on the thread that owns the handle. The module
    /// documentation records the measurement, names the three trait objects
    /// that cause it and states exactly what removing them requires; nothing
    /// in this file needs to change when they are.
    ///
    /// The handle keeps the state alive. A clone that outlives the `CURLSH`
    /// observes a retired share -- [`ShareCore::is_valid`] answers `false` and
    /// every operation reports [`CURLSHcode::Invalid`] -- where the C would
    /// read freed memory, so an application that gets its teardown order wrong
    /// gets a diagnosis rather than corruption.
    #[allow(dead_code)] // consumers: crate::easy, crate::multi, curl-rs-ffi
    #[must_use]
    pub(crate) fn stores(&self) -> Arc<ShareCore> {
        Arc::clone(&self.core)
    }
}

// `curl_share_setopt` (`lib/curl_share.c:57-219`)

impl Share {
    /// `curl_share_setopt` (`lib/curl_share.c:57-219`).
    ///
    /// The observable sequence is part of the ABI and is reproduced in the C's
    /// order:
    ///
    /// 1. `:68-69` an invalid handle yields [`CURLSHcode::Invalid`], before
    ///    anything else at all.
    /// 2. `:71-74` a share with any handle attached yields
    ///    [`CURLSHcode::InUse`], **before** the switch -- so every option is
    ///    refused while the share is in use, the two callback options and the
    ///    user pointer included. The C's comment is *"do not allow setting
    ///    options while one or more handles are already using this share"*.
    /// 3. `:76`-`:214` the switch.
    /// 4. `:216-218` return.
    pub fn setopt(&self, option: ShareOption) -> CURLSHcode {
        // C: lib/curl_share.c:68-69.
        if !self.is_valid() {
            return CURLSHcode::Invalid;
        }
        let mut meta = self.meta();
        // C: lib/curl_share.c:71-74.
        if meta.dirty != 0 {
            return CURLSHcode::InUse;
        }
        match option {
            // C: lib/curl_share.c:79-145.
            ShareOption::Share(kind) => self.share_kind(&mut meta, kind),
            // C: lib/curl_share.c:147-194.
            ShareOption::Unshare(kind) => self.unshare_kind(&mut meta, kind),
            // C: lib/curl_share.c:196-199. No validation of any kind, and a
            // null pointer clears it -- `tests/libtest/lib3207.c:154` does
            // exactly that.
            ShareOption::LockFunc(callback) => {
                meta.lockfunc = callback;
                CURLSHcode::Ok
            }
            // C: lib/curl_share.c:201-204, and `lib3207.c:155`.
            ShareOption::UnlockFunc(callback) => {
                meta.unlockfunc = callback;
                CURLSHcode::Ok
            }
            // C: lib/curl_share.c:206-209.
            ShareOption::UserData(clientdata) => {
                meta.clientdata = clientdata;
                CURLSHcode::Ok
            }
            // C: lib/curl_share.c:211-213 -- the outer `default:`, which every
            // option identifier the switch does not name reaches.
            ShareOption::None | ShareOption::Last | ShareOption::Unknown(_) => {
                CURLSHcode::BadOption
            }
        }
    }

    /// `CURLSHOPT_SHARE` (`lib/curl_share.c:79-145`).
    fn share_kind(&self, meta: &mut Meta, raw: i32) -> CURLSHcode {
        // C: lib/curl_share.c:81, made total.
        let Some(kind) = LockData::from_i32(raw) else {
            return CURLSHcode::BadOption;
        };
        let res = match kind {
            // C: lib/curl_share.c:84-85 -- a bare `break`. The cache was
            // built by `curl_share_init`, so there is nothing to create and
            // only the specifier bit distinguishes shared from unshared.
            LockData::Dns => CURLSHcode::Ok,
            // C: lib/curl_share.c:87-97.
            LockData::Cookie => self.core.share_cookies(),
            // C: lib/curl_share.c:99-109.
            LockData::Hsts => self.core.share_hsts(),
            // C: lib/curl_share.c:111-125.
            LockData::SslSession => self.core.share_ssl_scache(),
            // C: lib/curl_share.c:127-132. The one arm this type serves
            // itself, because the pool is the one store it owns.
            LockData::Connect => self.share_cpool(),
            // C: lib/curl_share.c:134-138.
            LockData::Psl => ShareCore::share_psl(),
            // C: lib/curl_share.c:140-141 -- the inner `default:`. Note that
            // `CURL_LOCK_DATA_SHARE` lands here too: the C's inner switch has
            // no case for it, so asking to share the share's own internal
            // state is a bad option even though its bit is already set.
            LockData::None | LockData::Share | LockData::Last => {
                CURLSHcode::BadOption
            }
        };
        // C: lib/curl_share.c:143-144.
        if res.is_ok() {
            meta.specifier |= kind.bit();
        }
        res
    }

    /// `CURL_LOCK_DATA_CONNECT` under `CURLSHOPT_SHARE`
    /// (`lib/curl_share.c:127-132`).
    ///
    /// The C's `if(!share->cpool.initialised)` is the [`Option`] being empty,
    /// which is why no separate flag is kept. Its size argument,
    /// [`CPOOL_SLOTS`], has nothing to receive it: `ConnectionPool::new` takes
    /// none, because the C's value is a hash bucket count and the Rust pool
    /// keys destinations with a `BTreeMap`.
    ///
    /// The one `CURLSHOPT_SHARE` arm that belongs to this type rather than to
    /// [`ShareCore`], because the pool is the one store the owner keeps.
    fn share_cpool(&self) -> CURLSHcode {
        let mut slot =
            self.cpool.lock().unwrap_or_else(PoisonError::into_inner);
        // C: lib/curl_share.c:129-131.
        if slot.is_none() {
            *slot = Some(ConnectionPool::new());
        }
        CURLSHcode::Ok
    }
}

// The stores' own `CURLSHOPT_SHARE` and `CURLSHOPT_UNSHARE` arms
//
// Every arm below builds or destroys one of the five `Send + Sync` stores and
// nothing else, so it is a [`ShareCore`] method: the state it touches is the
// core's. [`Share::setopt`] still arbitrates -- the C refuses every option
// while any handle is attached (`lib/curl_share.c:71-74`), which keeps these
// out of reach of a second thread by construction rather than by convention.

impl ShareCore {
    /// `CURL_LOCK_DATA_COOKIE` under `CURLSHOPT_SHARE`
    /// (`lib/curl_share.c:87-97`).
    ///
    /// The C's `CURLSHE_NOMEM` at `:92` is unreachable here: it reports a failed
    /// `Curl_cookie_init`, and `CookieInfo::new` allocates one fixed-size store
    /// whose size this crate chooses -- not an externally sized allocation, and
    /// with no stable fallible spelling at the declared minimum Rust version.
    /// The variant stays in [`CURLSHcode`] because it is public ABI.
    #[cfg(feature = "cookies")]
    fn share_cookies(&self) -> CURLSHcode {
        let mut slot =
            self.cookies.lock().unwrap_or_else(PoisonError::into_inner);
        // C: lib/curl_share.c:89 -- `if(!share->cookies)`, which is what makes
        // setting the option twice cheap and non-destructive.
        if slot.is_none() {
            *slot = Some(CookieInfo::new());
        }
        CURLSHcode::Ok
    }

    /// The `#else` arm of `lib/curl_share.c:94-96`.
    #[cfg(not(feature = "cookies"))]
    fn share_cookies(&self) -> CURLSHcode {
        CURLSHcode::NotBuiltIn
    }

    /// `CURL_LOCK_DATA_HSTS` under `CURLSHOPT_SHARE`
    /// (`lib/curl_share.c:99-109`).
    ///
    /// `:104`'s `CURLSHE_NOMEM` is unreachable for the same reason as the
    /// cookie arm's.
    #[cfg(feature = "hsts")]
    fn share_hsts(&self) -> CURLSHcode {
        let mut slot = self.hsts.lock().unwrap_or_else(PoisonError::into_inner);
        // C: lib/curl_share.c:101.
        if slot.is_none() {
            *slot = Some(HstsCache::new());
        }
        CURLSHcode::Ok
    }

    /// The `#else` arm of `lib/curl_share.c:106-108`, whose C guard is
    /// `#ifndef CURL_DISABLE_HSTS`.
    #[cfg(not(feature = "hsts"))]
    fn share_hsts(&self) -> CURLSHcode {
        CURLSHcode::NotBuiltIn
    }

    /// `CURL_LOCK_DATA_SSL_SESSION` under `CURLSHOPT_SHARE`
    /// (`lib/curl_share.c:111-125`).
    fn share_ssl_scache(&self) -> CURLSHcode {
        let mut slot = self
            .ssl_scache
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // C: lib/curl_share.c:113.
        if slot.is_none() {
            // C: lib/curl_share.c:119. `Curl_ssl_scache_create` returns a
            // `CURLcode` the C maps to `CURLSHE_NOMEM` at `:120`;
            // `SessionCache::new` cannot fail, so that arm is unreachable.
            *slot = Some(SessionCache::new(
                SCACHE_MAX_PEERS,
                SCACHE_MAX_SESSIONS_PER_PEER,
            ));
        }
        CURLSHcode::Ok
    }

    /// `CURL_LOCK_DATA_PSL` under `CURLSHOPT_SHARE`
    /// (`lib/curl_share.c:134-138`).
    #[cfg(feature = "cookies")]
    fn share_psl() -> CURLSHcode {
        CURLSHcode::Ok
    }

    /// The `#ifndef USE_LIBPSL` arm of `lib/curl_share.c:135-137`.
    ///
    /// Gated on `cookies` rather than on a `psl` feature because there is no
    /// `psl` feature in this crate's fifteen and `crate::cookies` declares
    /// `pub(crate) mod psl` under `#[cfg(feature = "cookies")]`. With cookies
    /// off there is no Public Suffix List to share.
    #[cfg(not(feature = "cookies"))]
    fn share_psl() -> CURLSHcode {
        CURLSHcode::NotBuiltIn
    }
}

// `CURLSHOPT_UNSHARE`'s dispatcher, which the owner performs
//
// The dispatcher stays with [`Share`] for the same reason its counterpart does:
// `CURL_LOCK_DATA_CONNECT` names the pool, which only the owner holds.

impl Share {
    /// `CURLSHOPT_UNSHARE` (`lib/curl_share.c:147-194`).
    ///
    /// # Quirk 1: the specifier bit is cleared unconditionally
    ///
    /// This is also how the `CURL_LOCK_DATA_SHARE` bit -- set at birth by
    /// `curl_share_init` (`:38`) and never cleared deliberately -- can be
    /// cleared after all: `CURLSHOPT_UNSHARE` with `CURL_LOCK_DATA_SHARE`
    /// clears bit 1 at `:150` and then falls to `default:` for
    /// [`CURLSHcode::BadOption`], because the switch has no case for it. That
    /// is precisely why [`Self::cleanup`] delivers its notifications without
    /// consulting the specifier while [`ShareCore::lock`] consults it: after
    /// such a
    /// call the two would otherwise disagree.
    fn unshare_kind(&self, meta: &mut Meta, raw: i32) -> CURLSHcode {
        // C: lib/curl_share.c:149, made total. An unrecognised value performs
        // no clear, because there is no bit to name -- the C would shift by it
        // instead, which is undefined behaviour rather than a documented
        // effect, so there is nothing here to reproduce.
        let Some(kind) = LockData::from_i32(raw) else {
            return CURLSHcode::BadOption;
        };
        // C: lib/curl_share.c:150 -- QUIRK 1. Unconditional, before the
        // switch, unguarded by the result.
        meta.specifier &= !kind.bit();
        match kind {
            // C: lib/curl_share.c:152-153 -- a bare `break`. The cache stays;
            // only the bit distinguishes shared from unshared.
            LockData::Dns => CURLSHcode::Ok,
            // C: lib/curl_share.c:155-164.
            LockData::Cookie => self.core.unshare_cookies(),
            // C: lib/curl_share.c:166-174.
            LockData::Hsts => self.core.unshare_hsts(),
            // C: lib/curl_share.c:176-185.
            LockData::SslSession => self.core.unshare_ssl_scache(),
            // C: lib/curl_share.c:187-188 -- a bare `break`. The pool is
            // deliberately NOT destroyed: only `curl_share_cleanup` destroys
            // it, and only when the bit is still set.
            LockData::Connect => CURLSHcode::Ok,
            // C: lib/curl_share.c:190-192 -- the `default:`. QUIRK 2 puts
            // `CURL_LOCK_DATA_PSL` here, alongside the three out-of-band
            // tokens and `CURL_LOCK_DATA_SHARE`.
            LockData::Psl
            | LockData::None
            | LockData::Share
            | LockData::Last => CURLSHcode::BadOption,
        }
    }
}

// The stores' own `CURLSHOPT_UNSHARE` arms

impl ShareCore {
    /// `CURL_LOCK_DATA_COOKIE` under `CURLSHOPT_UNSHARE`
    /// (`lib/curl_share.c:155-164`).
    #[cfg(feature = "cookies")]
    fn unshare_cookies(&self) -> CURLSHcode {
        let mut slot =
            self.cookies.lock().unwrap_or_else(PoisonError::into_inner);
        // C: lib/curl_share.c:157-160.
        if let Some(jar) = slot.as_mut() {
            jar.cleanup();
        }
        *slot = None;
        CURLSHcode::Ok
    }

    /// The `#else` arm of `lib/curl_share.c:161-163`.
    #[cfg(not(feature = "cookies"))]
    fn unshare_cookies(&self) -> CURLSHcode {
        CURLSHcode::NotBuiltIn
    }

    /// `CURL_LOCK_DATA_HSTS` under `CURLSHOPT_UNSHARE`
    /// (`lib/curl_share.c:166-174`).
    #[cfg(feature = "hsts")]
    fn unshare_hsts(&self) -> CURLSHcode {
        let mut slot = self.hsts.lock().unwrap_or_else(PoisonError::into_inner);
        // C: lib/curl_share.c:168-170 -- `Curl_hsts_cleanup(&share->hsts)`,
        // which frees the cache and nulls the pointer through the double
        // indirection.
        if let Some(cache) = slot.as_mut() {
            cache.cleanup();
        }
        *slot = None;
        CURLSHcode::Ok
    }

    /// The `#else` arm of `lib/curl_share.c:171-173`.
    #[cfg(not(feature = "hsts"))]
    fn unshare_hsts(&self) -> CURLSHcode {
        CURLSHcode::NotBuiltIn
    }

    /// `CURL_LOCK_DATA_SSL_SESSION` under `CURLSHOPT_UNSHARE`
    /// (`lib/curl_share.c:176-185`).
    ///
    /// Unconditional, for the reason [`Self::share_ssl_scache`] gives: there
    /// is no TLS feature, so `:182-183`'s `CURLSHE_NOT_BUILT_IN` is
    /// unreachable.
    fn unshare_ssl_scache(&self) -> CURLSHcode {
        let mut slot = self
            .ssl_scache
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // C: lib/curl_share.c:178-181 -- `Curl_ssl_scache_destroy` then
        // `share->ssl_scache = NULL`.
        *slot = None;
        CURLSHcode::Ok
    }
}

// `curl_share_cleanup` (`lib/curl_share.c:221-267`)

impl Share {
    /// `curl_share_cleanup` (`lib/curl_share.c:221-267`), **without the free**.
    ///
    /// The most error-prone function in the module, and the ordering below is
    /// the whole of its contract:
    ///
    /// 1. `:224-225` an invalid handle yields [`CURLSHcode::Invalid`], with no
    ///    lock taken and no notification delivered.
    /// 2. `:227-229` `if(share->lockfunc)` deliver a lock notification for
    ///    `CURL_LOCK_DATA_SHARE` with `CURL_LOCK_ACCESS_SINGLE` and a **null**
    ///    handle. Unconditional on the specifier -- see below.
    /// 3. `:231-235` if any handle is attached, deliver the matching unlock
    ///    notification and return [`CURLSHcode::InUse`] **without tearing
    ///    anything down**.
    /// 4. `:237-259` tear the six stores down, in the C's exact order.
    /// 5. `:261-262` deliver the unlock notification.
    /// 6. `:263` zero the validity tag.
    ///
    /// # Exactly one caller can ever reach step 4
    ///
    /// Step 1 is not a test here but a **claim**: a single
    /// compare-and-exchange takes the share from `Lifecycle::Live` to
    /// `Lifecycle::Cleaning`, and only its winner continues.
    /// `ShareCore::claim_cleanup` states why that matters -- the C's three
    /// unsynchronised steps let two concurrent callers both return
    /// `CURLSHE_OK`, which under the FFI's ownership rule is two
    /// `Box::from_raw` calls on one allocation -- and it closes the other side
    /// of the same race too: while the claim is held [`ShareCore::attach`]
    /// refuses,
    /// so the count read at step 3 cannot be raised behind this function.
    /// A claim that ends in [`CURLSHcode::InUse`] is given back, because the
    /// share must survive that path intact.
    ///
    /// # The caller frees, and only on success
    ///
    /// This takes `&self` and cannot consume, because
    /// `docs/libcurl/curl_share_cleanup.md:59-60` requires that *"If an error
    /// occurs, then the share object is not deleted."* On
    /// [`CURLSHcode::Invalid`] and [`CURLSHcode::InUse`] the object is intact
    /// and still usable, and `curl-rs-ffi` must **not** call `Box::from_raw`.
    /// On [`CURLSHcode::Ok`] it must, exactly once. Getting that backwards is
    /// a double free or a leak, and the split return is what makes it hard to
    /// get backwards.
    ///
    /// # Step 3's unlock is not optional
    ///
    /// A cleanup that fails with [`CURLSHcode::InUse`] and skips the unlock
    /// notification leaves an application-level mutex held for the rest of the
    /// process -- a visible deadlock in the application, caused by us. The C
    /// delivers it at `:232-233`, and so does this.
    ///
    /// # Why step 2 ignores the specifier
    ///
    /// `Curl_share_lock` fires a notification only when the kind's bit is set
    /// (`:277`); this function tests only `if(share->lockfunc)`. The
    /// difference is observable, because the `CURL_LOCK_DATA_SHARE` bit can be
    /// cleared -- [`Self::unshare_kind`] records exactly how -- and after that
    /// the two behave differently. The C's asymmetry is therefore reproduced
    /// by delivering these three notifications directly rather than through
    /// [`ShareCore::lock`] and [`ShareCore::unlock`].
    pub fn cleanup(&self) -> CURLSHcode {
        // C: lib/curl_share.c:224-225. No lock is taken first -- and the
        // validity test and the claim are one atomic step rather than two, so
        // that two threads entering here together cannot both proceed. The
        // loser gets the code the C gives the second cleanup of an
        // already-freed share; `claim_cleanup` records the argument in full.
        if !self.claim_cleanup() {
            return CURLSHcode::Invalid;
        }

        // The callbacks and the user pointer are read once and cloned out, so
        // that the notifications below run with no lock of ours held. They
        // cannot change underneath this function: `setopt` is the only writer
        // and it refuses while the claim is held.
        let (lockfunc, unlockfunc, clientdata) = {
            let meta = self.meta();
            (
                meta.lockfunc.clone(),
                meta.unlockfunc.clone(),
                meta.clientdata,
            )
        };

        // C: lib/curl_share.c:227-229. Note the null handle, and note that no
        // specifier check is performed.
        if let Some(callback) = &lockfunc {
            callback(
                LockOwner::NONE,
                LockData::Share,
                LockAccess::Single,
                clientdata,
            );
        }

        // C: lib/curl_share.c:231 and `:237` -- read AFTER the notification,
        // exactly where the C reads them, and under one hold so the count and
        // the mask agree. The count is stable from here: the claim above bars
        // `attach`, so nothing can raise it, and this is the whole of the
        // stale-snapshot fix. A concurrent `detach` may still lower it, which
        // is the same benign race the C has at `:231` and costs at most one
        // refused cleanup that the application repeats.
        let (dirty, specifier) = {
            let meta = self.meta();
            (meta.dirty, Specifier(meta.specifier))
        };

        // C: lib/curl_share.c:231-235.
        if dirty != 0 {
            if let Some(callback) = &unlockfunc {
                callback(LockOwner::NONE, LockData::Share, clientdata);
            }
            // `docs/libcurl/curl_share_cleanup.md:59-60` -- *"If an error
            // occurs, then the share object is not deleted."* Nothing was torn
            // down, so the claim goes back and the share is exactly as usable
            // as it was, this call included.
            self.release_claim();
            return CURLSHcode::InUse;
        }

        self.teardown(specifier);

        // C: lib/curl_share.c:261-262.
        if let Some(callback) = &unlockfunc {
            callback(LockOwner::NONE, LockData::Share, clientdata);
        }

        // C: lib/curl_share.c:263 -- `share->magic = 0`, immediately before
        // `curlx_free(share)` at `:264`. The store pairs with the `Acquire`
        // in `ShareCore::magic` so that a thread seeing the tag cleared also
        // sees the teardown above it.
        self.finish_cleanup();

        // C: lib/curl_share.c:266. Reached by exactly one caller per share, so
        // `curl-rs-ffi`'s `Box::from_raw` runs exactly once.
        CURLSHcode::Ok
    }

    /// The six store teardowns of `lib/curl_share.c:237-259`, in the C's
    /// order.
    ///
    /// The order is written to match the C statement for statement. It is not
    /// externally observable in Rust -- no store's disposal can see another --
    /// but it is kept because the C's is the specification and because a
    /// future store whose disposal *did* have a visible effect would then be
    /// placed correctly without anybody re-deriving the sequence.
    ///
    /// # The one resource divergence, and why it is an improvement rather than
    /// a change
    ///
    /// `:237-239` destroys the connection pool **only when the
    /// `CURL_LOCK_DATA_CONNECT` bit is still set**. Since `CURLSHOPT_UNSHARE`
    /// clears that bit without destroying the pool (`:150`, `:187-188`), an
    /// application that shares connections and then unshares them leaves the C
    /// freeing the enclosing structure at `:264` with the by-value `cpool`
    /// members never released -- a genuine leak in the C. The conditional
    /// destroy is reproduced here because it is what the C does, and Rust's
    /// drop glue then reclaims the pool when the [`Share`] itself is dropped.
    /// No API result differs; the C's leak simply does not happen.
    ///
    /// # The pool is DESTROYED, not dropped
    ///
    /// `Curl_cpool_destroy` (`lib/conncache.c:231-254`) is not a free: it
    /// moves every remaining connection through `cpool_discard_conn`, which
    /// sends the protocol farewell, shuts the filter chains down and closes
    /// the socket -- and it does all of that inside a
    /// `CURL_LOCK_DATA_CONNECT` critical section, because `CPOOL_LOCK` and
    /// `CPOOL_UNLOCK` (`lib/conncache.c:41-60`) are `Curl_share_lock` and
    /// `Curl_share_unlock` for that datum whenever
    /// `CURL_SHARE_KEEP_CONNECT` holds, which on this path it does by
    /// construction. Dropping the pool instead would reclaim the same memory
    /// while delivering neither notification and performing none of the
    /// shutdown, so an application's close callbacks would never fire and a
    /// peer would see a truncated connection rather than a farewell.
    /// [`ShareAdmin`] is the retained context that makes the real destroy
    /// reachable, exactly as `cpool->idata` is in the C.
    fn teardown(&self, specifier: Specifier) {
        // C: lib/curl_share.c:237-239 -- `Curl_cpool_destroy`, conditional.
        if specifier.keep_connect() {
            // C: lib/conncache.c:243 -- `CPOOL_LOCK(cpool, cpool->idata)`,
            // whose handle argument is the admin context.
            self.lock(LockOwner::NONE, LockData::Connect, LockAccess::Single);
            // C: lib/conncache.c:251 -- `CPOOL_UNLOCK`, on every path out.
            // Declared before the store locks so that it is dropped after
            // them: the notification that ends the critical section must
            // follow the release of our own locks, which is the discipline
            // `ShareGuard` documents and the order `CPOOL_UNLOCK` itself uses
            // (`(c)->locked = FALSE;` then `Curl_share_unlock`).
            let _release = Release {
                core: self,
                owner: LockOwner::NONE,
                kind: LockData::Connect,
            };
            let mut slot =
                self.cpool.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(pool) = slot.as_mut() {
                // C: lib/conncache.c:245-250 -- the removal loop, driven
                // through the admin context.
                self.admin
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .destroy_pool(pool);
            }
            // C: lib/conncache.c:253 --
            // `Curl_hash_destroy(&cpool->dest2bundle)` leaves the pool
            // unusable; the slot is emptied for the same reason, and
            // `Curl_cpool_destroy` is never called twice.
            *slot = None;
        }

        // C: lib/curl_share.c:241-258 -- the five stores the core owns. They
        // are destroyed through the core rather than here because the core is
        // what an `Arc` handle can still reach: emptying them is what makes a
        // surviving handle harmless.
        self.core.teardown_stores();
    }
}

// The five stores are destroyed by the core that owns them
//
// `Curl_share_cleanup`'s remaining destroys (`lib/curl_share.c:241-258`) touch
// only state that lives in [`ShareCore`], so they are performed by it. The
// division is load-bearing rather than tidy: a [`ShareCore`] handed to another
// thread by [`Share::stores`] keeps the allocation alive after its [`Share`] is
// gone, and what makes that harmless is that teardown has already emptied every
// store and marked the lifecycle dead. The handle then refuses every operation
// against zero remaining state, which is the isolation SHARE-1 asks for.

impl ShareCore {
    /// The store half of `Curl_share_cleanup` (`lib/curl_share.c:241-258`).
    ///
    /// Called by [`Share::teardown`] once the pool half is complete, in the
    /// C's order and with the C's conditionality: only the connection pool is
    /// gated on a specifier bit, and every store below is destroyed whether it
    /// was shared or not, because the C destroys members it may never have
    /// initialised.
    ///
    /// Every store is left empty rather than merely released, so a surviving
    /// [`Arc<ShareCore>`] holds nothing.
    fn teardown_stores(&self) {
        // C: lib/curl_share.c:241 -- `Curl_dnscache_destroy`, unconditional
        // and not gated on the DNS bit. The cache is a by-value member, so
        // what the C destroys is its contents, which is `clear`.
        self.dnscache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();

        // C: lib/curl_share.c:243-245 -- `Curl_cookie_cleanup`, which the C
        // calls unconditionally because it tolerates a null argument.
        #[cfg(feature = "cookies")]
        {
            let mut slot =
                self.cookies.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(jar) = slot.as_mut() {
                jar.cleanup();
            }
            *slot = None;
        }

        // C: lib/curl_share.c:247-249 -- `Curl_hsts_cleanup`, likewise
        // null-tolerant and likewise unconditional.
        #[cfg(feature = "hsts")]
        {
            let mut slot =
                self.hsts.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(cache) = slot.as_mut() {
                cache.cleanup();
            }
            *slot = None;
        }

        // C: lib/curl_share.c:251-256 -- `Curl_ssl_scache_destroy` then
        // `share->ssl_scache = NULL`.
        {
            let mut slot = self
                .ssl_scache
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            *slot = None;
        }

        // C: lib/curl_share.c:258 -- `Curl_psl_destroy`, UNCONDITIONAL,
        // regardless of the `CURL_LOCK_DATA_PSL` bit. That is why the C can
        // destroy a cache it never initialised: the zeroed state is a valid
        // one to destroy.
        #[cfg(feature = "cookies")]
        self.psl
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .destroy();

        // C: lib/curl_share.c:259 -- `Curl_close(&share->admin)`. No
        // counterpart; `Share::new` records why there is no admin handle.
    }
}

// The stores, reached through RAII guards

/// The unlock notification a guard owes when its critical section ends.
///
/// Split out so that the release is [`Drop`] rather than a call every exit
/// path has to remember. The C needs `bool locked` plus a `goto out` in one
/// function to get this right -- `Curl_ssl_session_import`
/// (`lib/vtls/vtls_scache.c:1079`, `:1095-1096`, `:1136-1138`) does exactly
/// that, because it has nine exit paths.
struct Release<'a> {
    /// The shared state whose callback is owed the notification.
    core: &'a ShareCore,
    /// The handle the notification names, which the lock notification named
    /// too.
    owner: LockOwner,
    /// The datum being released.
    kind: LockData,
}

impl Drop for Release<'_> {
    /// `Curl_share_unlock`, on every path out of the scope -- early return,
    /// `?` propagation and unwinding included.
    fn drop(&mut self) {
        self.core.unlock(self.owner, self.kind);
    }
}

/// A shared store, locked, with its unlock notification pending.
///
/// # For the lazily created stores, the payload is an [`Option`]
///
/// `T` is the store for a datum the C holds by value and the
/// `Option<Store>` for a datum the C holds behind a pointer, which keeps the C
/// distinction visible. An accessor only yields a guard when the datum's
/// specifier bit is set, and a set bit implies a created store, so that
/// [`Option`] is always `Some` -- a fact the type cannot state, because
/// narrowing a guard to a field needs `MappedMutexGuard`, which is unstable at
/// the declared MSRV of 1.75. Callers therefore write `as_mut` and get a
/// branch that cannot be taken rather than a `panic` that cannot fire, which
/// is the right way round for a library that must never unwind into C.
pub(crate) struct ShareGuard<'a, T> {
    /// The locked store. Declared first so that it is released first.
    inner: MutexGuard<'a, T>,
    /// The unlock notification, delivered when this goes out of scope.
    release: Release<'a>,
}

impl<T> Deref for ShareGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T> DerefMut for ShareGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<T: fmt::Debug> fmt::Debug for ShareGuard<'_, T> {
    /// The store, plus which datum is held and on whose behalf.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShareGuard")
            .field("kind", &self.release.kind.c_name())
            .field("owner", &format_args!("{:#x}", self.release.owner.bits()))
            .field("store", &*self.inner)
            .finish()
    }
}

impl ShareCore {
    /// Delivers the lock notification for `kind` and enters `slot`.
    ///
    /// The two halves of every C lock helper in one place:
    /// `Curl_share_lock(data, kind, CURL_LOCK_ACCESS_SINGLE)` followed by
    /// entry into the critical section. [`LockAccess::Single`] is
    /// unconditional here because it is unconditional in the C -- 38 of the
    /// 39 `Curl_share_lock` call sites request it, and the one exception is
    /// the Public Suffix List, which has its own entry point.
    fn guard<'a, T>(
        &'a self,
        owner: LockOwner,
        kind: LockData,
        slot: &'a Mutex<T>,
    ) -> ShareGuard<'a, T> {
        self.lock(owner, kind, LockAccess::Single);
        ShareGuard {
            inner: slot.lock().unwrap_or_else(PoisonError::into_inner),
            release: Release {
                core: self,
                owner,
                kind,
            },
        }
    }

    /// The shared DNS cache, or [`None`] when DNS is not shared.
    ///
    /// `dnscache_get` (`lib/hostip.c:298-305`) plus `dnscache_lock`
    /// (`:307-312`): the cache is the share's only when
    /// `share->specifier & (1 << CURL_LOCK_DATA_DNS)`, and only then is the
    /// notification delivered. A multi handle's own cache is never locked at
    /// all, which is why the selection between the two belongs to the caller
    /// and not here.
    #[allow(dead_code)] // consumers: crate::dns, crate::easy, crate::multi
    pub(crate) fn dnscache(
        &self,
        owner: LockOwner,
    ) -> Option<ShareGuard<'_, DnsCache>> {
        if !self.is_valid() || !self.is_shared(LockData::Dns) {
            return None;
        }
        Some(self.guard(owner, LockData::Dns, &self.dnscache))
    }

    /// The shared cookie jar, or [`None`] when cookies are not shared.
    #[cfg(feature = "cookies")]
    #[allow(dead_code)] // consumers: crate::cookies, crate::easy, crate::multi
    pub(crate) fn cookies(
        &self,
        owner: LockOwner,
    ) -> Option<ShareGuard<'_, Option<CookieInfo>>> {
        if !self.is_valid() || !self.is_shared(LockData::Cookie) {
            return None;
        }
        Some(self.guard(owner, LockData::Cookie, &self.cookies))
    }

    /// The shared HSTS cache, or [`None`] when HSTS is not shared.
    #[cfg(feature = "hsts")]
    #[allow(dead_code)] // consumers: crate::cookies::hsts, crate::easy
    pub(crate) fn hsts(
        &self,
        owner: LockOwner,
    ) -> Option<ShareGuard<'_, Option<HstsCache>>> {
        if !self.is_valid() || !self.is_shared(LockData::Hsts) {
            return None;
        }
        Some(self.guard(owner, LockData::Hsts, &self.hsts))
    }

    /// The shared TLS session cache, or [`None`] when sessions are not shared.
    ///
    /// `Curl_ssl_scache_lock` (`lib/vtls/vtls_scache.c:585-589`) reduced to one
    /// call:
    ///
    /// ```text
    /// void Curl_ssl_scache_lock(struct Curl_easy *data)
    /// {
    ///   if(CURL_SHARE_ssl_scache(data))
    ///     Curl_share_lock(data, CURL_LOCK_DATA_SSL_SESSION,
    ///                     CURL_LOCK_ACCESS_SINGLE);
    /// }
    /// ```
    ///
    /// `crate::tls::session_cache` declares a narrow `ScacheLock` seam for the
    /// same two calls, and its `SelectedCache::acquire` yields a guard from an
    /// `&mut SessionCache`. This accessor is the other route to the same
    /// discipline and cannot feed that one, because a `MutexGuard` cannot hand
    /// out a borrow that outlives it; the seam remains the right shape for a
    /// multi handle's own cache, which is not behind a lock at all.
    #[allow(dead_code)] // consumers: crate::tls, crate::easy, crate::multi
    pub(crate) fn ssl_scache(
        &self,
        owner: LockOwner,
    ) -> Option<ShareGuard<'_, Option<SessionCache>>> {
        if !self.is_valid() || !self.is_shared(LockData::SslSession) {
            return None;
        }
        Some(self.guard(owner, LockData::SslSession, &self.ssl_scache))
    }
}

// The connection pool is reached through the owner, not the core
//
// Every accessor above is a [`ShareCore`] method because its store is
// `Send + Sync` and therefore safe to reach from any thread holding an
// [`Arc<ShareCore>`]. The pool is the one store that is not, so its accessor
// stays on [`Share`], which is the thread-affine owner. That is the whole shape
// of the isolation: the type system, not a comment, decides which stores a
// second thread can name.

impl Share {
    /// The shared connection pool, or [`None`] when connections are not
    /// shared.
    ///
    /// `CPOOL_LOCK` and `CPOOL_UNLOCK` (`lib/conncache.c:41-60`), whose
    /// external half is `Curl_share_lock(d, CURL_LOCK_DATA_CONNECT,
    /// CURL_LOCK_ACCESS_SINGLE)` guarded by `CURL_SHARE_KEEP_CONNECT`. The
    /// macros' remaining half is a `locked` bit under `DEBUGASSERT`, which is
    /// a re-entrancy assertion rather than a lock; `crate::conn::pool`
    /// deliberately has no such field and states that
    /// `CURL_LOCK_DATA_CONNECT` is this module's to own.
    #[allow(dead_code)] // consumers: crate::conn, crate::easy, crate::multi
    pub(crate) fn pool(
        &self,
        owner: LockOwner,
    ) -> Option<ShareGuard<'_, Option<ConnectionPool>>> {
        if !self.is_valid() || !self.is_shared(LockData::Connect) {
            return None;
        }
        Some(self.guard(owner, LockData::Connect, &self.cpool))
    }
}

/// The shared Public Suffix List, locked, with its unlock pending.
///
/// The one datum whose critical section outlives the call that opened it.
/// `Curl_psl_use` (`lib/psl.c:42-95`) returns `const psl_ctx_t *` **while
/// still holding** `CURL_LOCK_DATA_PSL`, and `Curl_psl_release`
/// (`:97-100`) is a pure unlock with no state change. A scoped
/// `with_psl(|psl| ...)` accessor cannot express that, so this is a guard.
/// `crate::cookies::psl` records the same requirement from the other side,
/// down to *"dropping the borrow is the release"*.
///
/// # The internal lock matches the notification: a reader is a reader
///
/// The guard holds a **read** lock, because the phase it represents is the
/// C's shared one: `lib/psl.c:89` re-takes `CURL_LOCK_ACCESS_SHARED` before
/// `:91` reads `pslcache->psl` and `:94` returns it, and that read mutates
/// nothing. Every mutation the C performs -- the recheck and the load at
/// `:60-87` -- happens in the exclusive phase, which [`ShareCore::psl_use`]
/// completes before this guard exists.
///
/// That is load-bearing rather than cosmetic. A guard that held a writer
/// while the application had been told `CURL_LOCK_ACCESS_SHARED` would let a
/// refresh run under a notification that promised no writer, which is
/// precisely the promise an application's read-write lock acts on: its
/// readers would be running against a mutating cache. Holding a reader also
/// restores the concurrency the C has -- two transfers may hold the list at
/// once, exactly as two `Curl_psl_use` callers may.
#[cfg(feature = "cookies")]
pub(crate) struct PslGuard<'a> {
    /// The locked cache. Declared first so that it is released first.
    inner: RwLockReadGuard<'a, PslCache>,
    /// The unlock notification, delivered when this goes out of scope --
    /// `Curl_psl_release`.
    release: Release<'a>,
}

#[cfg(feature = "cookies")]
impl PslGuard<'_> {
    /// The cached list -- what `Curl_psl_use` returns.
    ///
    /// `pslcache->psl` as `lib/psl.c:91` reads it and `:94` returns it: the
    /// selection is already made, so this refreshes nothing, reads no clock
    /// and takes no source. `&self`, because a reader is all the C holds here
    /// and all this needs.
    ///
    /// Never [`None`] in practice: [`ShareCore::psl_use`] releases the lock and
    /// yields [`None`] itself when no list could be obtained
    /// (`lib/psl.c:92-93`), so a guard exists only when a list does. The
    /// [`Option`] survives because `PslCache::list` is fallible by signature,
    /// and answering that with an `expect` would put a panic on the path to a
    /// C caller.
    #[allow(dead_code)] // consumer: crate::cookies' public-suffix checks
    pub(crate) fn list(&self) -> Option<&List> {
        self.inner.list()
    }
}

#[cfg(feature = "cookies")]
impl Deref for PslGuard<'_> {
    type Target = PslCache;

    /// Read access to the cache's own state -- whether a list is held, its
    /// deadline and whether it is dynamic.
    ///
    /// Immutable deliberately: the only mutation the C performs under this
    /// lock is the refresh, and the refresh is [`Self::list`]'s.
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[cfg(feature = "cookies")]
impl fmt::Debug for PslGuard<'_> {
    /// The cache's state and on whose behalf it is held.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PslGuard")
            .field("owner", &format_args!("{:#x}", self.release.owner.bits()))
            .field("has_list", &self.inner.has_list())
            .field("expires", &self.inner.expires())
            .field("dynamic", &self.inner.is_dynamic())
            .finish()
    }
}

#[cfg(feature = "cookies")]
impl ShareCore {
    /// `Curl_psl_use` (`lib/psl.c:42-95`), notification for notification.
    ///
    /// The only entry point that emits more than one notification, and the
    /// only user of [`LockAccess::Shared`] anywhere. The C's sequence, and
    /// this function's:
    ///
    /// | C line | Notification | Why |
    /// |--------|--------------|-----|
    /// | `:51` | lock, shared | read the clock and the cache |
    /// | `:55` | unlock | *"Let a chance to other threads to do the job: avoids deadlock."* |
    /// | `:58` | lock, exclusive | *"Update cache: this needs an exclusive lock."* |
    /// | `:88` | unlock | *"Release exclusive lock."* |
    /// | `:89` | lock, shared | so the returned list stays valid |
    ///
    /// # Returns
    ///
    /// [`None`] in two cases, and both are the C's. `:48-49`'s
    /// `if(!pslcache) return NULL;` is *"no cache selected"*, which here is the
    /// `CURL_LOCK_DATA_PSL` bit being clear -- `lib/setopt.c:1545-1546`
    /// repoints a handle at the share's cache only when that bit is set, so a
    /// clear bit means the share's cache was never selected. The second case
    /// is `:92-93`, which releases the lock and returns `NULL` when the
    /// refresh produced nothing.
    ///
    /// A caller that gets [`None`] must **fail closed**, exactly as
    /// `lib/cookie.c:801-802` does: log *"libpsl problem, rejecting cookie for
    /// safety"* and drop the cookie. It must not read it as *"no public-suffix
    /// checking is configured"*, which is a different question with a
    /// different answer.
    #[allow(dead_code)] // consumer: crate::cookies' public-suffix checks
    pub(crate) fn psl_use<'a>(
        &'a self,
        owner: LockOwner,
        clock: &'a dyn Clock,
        source: &'a dyn PslSource,
    ) -> Option<PslGuard<'a>> {
        // C: lib/psl.c:48-49, by way of lib/setopt.c:1545-1546.
        if !self.is_valid() || !self.is_shared(LockData::Psl) {
            return None;
        }

        // C: lib/psl.c:51.
        self.lock(owner, LockData::Psl, LockAccess::Shared);

        // C: lib/psl.c:52-53 -- `!pslcache->psl || pslcache->expires <=
        // now_sec`, with `<=` so that a deadline equal to the current second
        // is already stale. Read under a reader, which is what the C holds
        // here.
        let stale = {
            let cache = self.psl.read().unwrap_or_else(PoisonError::into_inner);
            !cache.has_list() || cache.expires() <= clock.now().secs
        };

        if stale {
            // C: lib/psl.c:55.
            self.unlock(owner, LockData::Psl);
            // C: lib/psl.c:58.
            self.lock(owner, LockData::Psl, LockAccess::Single);
            {
                let mut cache =
                    self.psl.write().unwrap_or_else(PoisonError::into_inner);
                // C: lib/psl.c:60-87 -- the recheck and the load, which
                // `PslCache::use_list` is the whole of. This is the ONLY place
                // the cache is mutated, and it sits inside the exclusive
                // notification, which is what makes the shared one honest.
                // Its return is the list, which this phase does not need; the
                // borrow ends here so that the lock can be released next.
                let _ = cache.use_list(clock, source);
            }
            // C: lib/psl.c:88.
            self.unlock(owner, LockData::Psl);
            // C: lib/psl.c:89.
            self.lock(owner, LockData::Psl, LockAccess::Shared);
        }

        // The guard the caller receives: a READER, matching the shared
        // notification the application has just been given, and matching the
        // `const psl_ctx_t *` the C returns. `PslGuard` records why that
        // matters.
        let cache = self.psl.read().unwrap_or_else(PoisonError::into_inner);

        // C: lib/psl.c:91-93 -- `psl = pslcache->psl; if(!psl)
        // Curl_share_unlock(...)`, then `return psl`. A missing list releases
        // the lock before returning, so the caller owes nothing.
        if cache.list().is_none() {
            drop(cache);
            self.unlock(owner, LockData::Psl);
            return None;
        }

        // C: lib/psl.c:94 -- returns holding the shared lock, which
        // `Curl_psl_release` (`:97-100`) later releases. Here that is `Drop`.
        Some(PslGuard {
            inner: cache,
            release: Release {
                core: self,
                owner,
                kind: LockData::Psl,
            },
        })
    }
}

// Tests
//
// What is asserted here, and why each group exists:
//
//   * The frozen integers. Every `curl_lock_data` and `curl_lock_access`
//     discriminant against `include/curl/curl.h:3026-3048`, and every bit
//     against the `1 << type` the C builds. An application holds these
//     numbers, so a reordering must be a test failure and not a surprise in
//     somebody's callback.
//   * The three orderings that are part of the ABI: `curl_share_init`'s,
//     `curl_share_setopt`'s refusals before its switch, and
//     `curl_share_cleanup`'s six steps.
//   * Both measured quirks of `CURLSHOPT_UNSHARE`, as regressions, so that a
//     later reader who thinks they are bugs finds a test saying otherwise.
//   * The notification contract: the exact `(owner, kind, access)` triples the
//     C delivers, that they are balanced, and that they are never nested for
//     one kind -- which is what `lib506.c`'s own callback checks.
//   * That `cleanup` never consumes on an error path, because the object must
//     survive for `curl-rs-ffi` to be allowed to free it only on success.
//   * That [`Share`] itself, and every component of it, is `Send + Sync`, so
//     that the claim in the module documentation is a fact under test rather
//     than prose -- and so that a later change which reintroduces a
//     thread-affine value anywhere in the connection or TLS graph fails here
//     rather than in somebody's application.
//   * One share driven from four threads at once through the lock callbacks,
//     which is the half of `lib506.c` that a `!Sync` share could not express.

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::{Barrier, Condvar};

    use crate::conn::filters::{ShutdownTimer, SocketIndex};
    use crate::conn::pool::ConnectionSpec;
    use crate::conn::shutdown::{DisconnectFuture, ProtocolDisconnect};
    #[cfg(feature = "cookies")]
    use crate::cookies::psl::MemoryPslSource;
    use crate::util::timeval::CurlTime;
    #[cfg(feature = "cookies")]
    use crate::util::timeval::TestClock;

    /// A handle for the notifications to name, distinct from
    /// [`LockOwner::NONE`] so that a test can tell the two apart.
    const OWNER: LockOwner = LockOwner::from_bits(0x1234_5678);

    /// The user pointer `CURLSHOPT_USERDATA` installs in these tests.
    const USERDATA: ShareUserData = ShareUserData::from_bits(0xdead_beef);

    /// One notification, as the application's callback saw it.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Event {
        /// `curl_lock_function(handle, data, locktype, userptr)`.
        Lock(LockOwner, LockData, LockAccess, ShareUserData),
        /// `curl_unlock_function(handle, data, userptr)` -- no access type.
        Unlock(LockOwner, LockData, ShareUserData),
    }

    /// The recording mock, modelled on `tests/libtest/lib506.c`'s callbacks.
    #[derive(Debug, Default)]
    struct Recorder {
        events: Mutex<Vec<Event>>,
        held: Mutex<Vec<LockData>>,
        faults: Mutex<Vec<String>>,
    }

    impl Recorder {
        fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }

        fn on_lock(
            &self,
            owner: LockOwner,
            kind: LockData,
            access: LockAccess,
            userdata: ShareUserData,
        ) {
            let mut held =
                self.held.lock().unwrap_or_else(PoisonError::into_inner);
            if held.contains(&kind) {
                self.fault(format!("lock: double locked {}", kind.c_name()));
            } else {
                held.push(kind);
            }
            drop(held);
            self.push(Event::Lock(owner, kind, access, userdata));
        }

        fn on_unlock(
            &self,
            owner: LockOwner,
            kind: LockData,
            userdata: ShareUserData,
        ) {
            let mut held =
                self.held.lock().unwrap_or_else(PoisonError::into_inner);
            match held.iter().rposition(|entry| *entry == kind) {
                Some(at) => {
                    held.remove(at);
                }
                None => self.fault(format!(
                    "unlock: double unlocked {}",
                    kind.c_name()
                )),
            }
            drop(held);
            self.push(Event::Unlock(owner, kind, userdata));
        }

        fn push(&self, event: Event) {
            self.events
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(event);
        }

        fn fault(&self, message: String) {
            self.faults
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(message);
        }

        /// Everything recorded so far, in order.
        fn events(&self) -> Vec<Event> {
            self.events
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }

        /// Everything recorded so far, clearing the log.
        fn drain(&self) -> Vec<Event> {
            let mut events =
                self.events.lock().unwrap_or_else(PoisonError::into_inner);
            core::mem::take(&mut *events)
        }

        /// Fails the test if any double lock or double unlock was seen, or if
        /// anything is still held.
        fn assert_balanced(&self) {
            let faults =
                self.faults.lock().unwrap_or_else(PoisonError::into_inner);
            assert!(faults.is_empty(), "callback faults: {faults:?}");
            let held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
            assert!(held.is_empty(), "still held at the end: {held:?}");
        }
    }

    /// Installs a recorder as the share's lock and unlock callbacks, with
    /// [`USERDATA`] as the user pointer.
    ///
    /// The three options are set separately because the C stores three
    /// separate fields and this test suite depends on that independence.
    fn install(share: &Share, recorder: &Arc<Recorder>) {
        let for_lock = Arc::clone(recorder);
        let for_unlock = Arc::clone(recorder);
        assert_eq!(
            share.setopt(ShareOption::LockFunc(Some(Arc::new(
                move |owner, kind, access, userdata| {
                    for_lock.on_lock(owner, kind, access, userdata);
                }
            )))),
            CURLSHcode::Ok
        );
        assert_eq!(
            share.setopt(ShareOption::UnlockFunc(Some(Arc::new(
                move |owner, kind, userdata| {
                    for_unlock.on_unlock(owner, kind, userdata);
                }
            )))),
            CURLSHcode::Ok
        );
        assert_eq!(
            share.setopt(ShareOption::UserData(USERDATA)),
            CURLSHcode::Ok
        );
    }

    /// A share with a recorder installed, and the recorder.
    fn recorded() -> (Share, Arc<Recorder>) {
        let share = Share::new();
        let recorder = Recorder::new();
        install(&share, &recorder);
        let _ = recorder.drain();
        (share, recorder)
    }

    // Fixtures for the connection pool's teardown

    /// A shutdown deadline that never starts and never expires.
    ///
    /// The real one belongs to `conn/mod.rs`. Nothing this module drives reads
    /// a deadline -- the disposal path consults the handler's cap instead --
    /// so a null implementation is honest rather than lazy. It is the same
    /// fixture `crate::conn::pool`'s own tests use, for the same reason.
    #[derive(Clone, Copy, Debug, Default)]
    struct NullTimer;

    impl ShutdownTimer for NullTimer {
        fn started(&self, _sockindex: SocketIndex) -> bool {
            false
        }

        fn start(&mut self, _sockindex: SocketIndex, _timeout_ms: TimeDiff) {}

        fn time_left_ms(&self, _sockindex: SocketIndex) -> TimeDiff {
            0
        }

        fn clear(&mut self, _sockindex: SocketIndex) {}
    }

    /// A scheme disconnect handler that records having been asked.
    ///
    /// `conn->scheme->run->disconnect` (`lib/urldata.h:427-512`), which
    /// `Curl_cshutdn_terminate` calls for every connection the C disposes of
    /// (`lib/cshutdn.c:62`). It is what distinguishes a **destroyed** pool from
    /// a dropped one: dropping reclaims the memory and asks no scheme
    /// anything.
    #[derive(Debug)]
    struct RecordingDisconnect {
        /// How many times `disconnect` was awaited, and with what `dead` flag.
        calls: Arc<Mutex<Vec<bool>>>,
    }

    impl ProtocolDisconnect for RecordingDisconnect {
        fn disconnect<'a>(
            &'a mut self,
            _cx: &'a mut CallCtx<'_, '_>,
            _chains: &'a mut FilterChains,
            dead: bool,
        ) -> DisconnectFuture<'a> {
            Box::pin(async move {
                self.calls
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(dead);
                Ok(())
            })
        }
    }

    /// A pooled connection to `destination`, with a recording disconnect
    /// handler when `calls` is supplied.
    fn connection(
        destination: &str,
        calls: Option<&Arc<Mutex<Vec<bool>>>>,
    ) -> ConnectionSpec {
        let spec = ConnectionSpec::new(
            destination,
            FilterChains::new(None),
            Box::new(NullTimer),
            CurlTime::new(10, 0),
        );
        match calls {
            Some(calls) => spec.with_handler(Box::new(RecordingDisconnect {
                calls: Arc::clone(calls),
            })),
            None => spec,
        }
    }

    // The frozen integers

    /// `curl_lock_data` (`include/curl/curl.h:3026-3040`).
    ///
    /// Only `CURL_LOCK_DATA_NONE = 0` is explicit in the C; the rest come from
    /// declaration order, and an application compiled against curl
    /// 8.19.0-DEV holds the resulting numbers.
    #[test]
    fn lock_data_discriminants_match_the_public_header() {
        assert_eq!(LockData::None.as_i32(), 0);
        assert_eq!(LockData::Share.as_i32(), 1);
        assert_eq!(LockData::Cookie.as_i32(), 2);
        assert_eq!(LockData::Dns.as_i32(), 3);
        assert_eq!(LockData::SslSession.as_i32(), 4);
        assert_eq!(LockData::Connect.as_i32(), 5);
        assert_eq!(LockData::Psl.as_i32(), 6);
        assert_eq!(LockData::Hsts.as_i32(), 7);
        assert_eq!(LockData::Last.as_i32(), 8);
        assert_eq!(LockData::VARIANTS.len(), 9);
    }

    /// `curl_lock_access` (`include/curl/curl.h:3043-3048`), where the C
    /// writes the first three explicitly.
    #[test]
    fn lock_access_discriminants_match_the_public_header() {
        assert_eq!(LockAccess::None.as_i32(), 0);
        assert_eq!(LockAccess::Shared.as_i32(), 1);
        assert_eq!(LockAccess::Single.as_i32(), 2);
        assert_eq!(LockAccess::Last.as_i32(), 3);
        assert_eq!(LockAccess::VARIANTS.len(), 4);
    }

    /// Every token round-trips through its integer, and nothing outside the
    /// enumeration is accepted.
    ///
    /// The rejection is what lets `CURLSHOPT_SHARE` reach
    /// `CURLSHE_BAD_OPTION` for a value the C would have shifted by --
    /// undefined behaviour at `lib/curl_share.c:144` and `:150`.
    #[test]
    fn the_enumerations_round_trip_and_reject_everything_else() {
        for kind in LockData::VARIANTS {
            assert_eq!(LockData::from_i32(kind.as_i32()), Some(*kind));
        }
        for access in LockAccess::VARIANTS {
            assert_eq!(LockAccess::from_i32(access.as_i32()), Some(*access));
        }
        for raw in [-1, -2_147_483_648, 9, 31, 32, 99, 2_147_483_647] {
            assert_eq!(LockData::from_i32(raw), None, "{raw} names no datum");
        }
        for raw in [-1, 4, 99] {
            assert_eq!(
                LockAccess::from_i32(raw),
                None,
                "{raw} names no access"
            );
        }
    }

    /// [`LockData::bit`] equals the C's `1 << type` for every token.
    ///
    /// Asserted against the shift rather than against literals, because the
    /// shift is what `lib/curl_share.c:144` and `:150` compute; the
    /// implementation uses a `match` so that it cannot overflow, and this is
    /// the check that the two agree.
    #[test]
    fn every_bit_equals_one_shifted_by_the_discriminant() {
        for kind in LockData::VARIANTS {
            let shifted = 1_u32 << u32::try_from(kind.as_i32()).expect("0..=8");
            assert_eq!(kind.bit(), shifted, "{}", kind.c_name());
        }
        // The two the C spells as macros: `lib/curl_share.h:39-40` and
        // `:73-75`.
        assert_eq!(LockData::Connect.bit(), 1 << 5);
        assert_eq!(LockData::SslSession.bit(), 1 << 4);
    }

    /// The C spellings, which `lib506.c`'s callback switches on and which a
    /// diagnostic quotes.
    #[test]
    fn the_c_names_are_the_header_spellings() {
        assert_eq!(LockData::Share.c_name(), "CURL_LOCK_DATA_SHARE");
        assert_eq!(LockData::Cookie.c_name(), "CURL_LOCK_DATA_COOKIE");
        assert_eq!(LockData::Dns.c_name(), "CURL_LOCK_DATA_DNS");
        assert_eq!(LockData::SslSession.c_name(), "CURL_LOCK_DATA_SSL_SESSION");
        assert_eq!(LockData::Connect.c_name(), "CURL_LOCK_DATA_CONNECT");
        assert_eq!(LockData::Psl.c_name(), "CURL_LOCK_DATA_PSL");
        assert_eq!(LockData::Hsts.c_name(), "CURL_LOCK_DATA_HSTS");
        assert_eq!(LockData::Last.c_name(), "CURL_LOCK_DATA_LAST");
        assert_eq!(LockAccess::Shared.c_name(), "CURL_LOCK_ACCESS_SHARED");
        assert_eq!(LockAccess::Single.c_name(), "CURL_LOCK_ACCESS_SINGLE");
        assert_eq!(LockData::Dns.to_string(), "CURL_LOCK_DATA_DNS");
        assert_eq!(LockAccess::Single.to_string(), "CURL_LOCK_ACCESS_SINGLE");
    }

    /// The two opaque tokens are transparent about being pointers and nothing
    /// more.
    #[test]
    fn the_pointer_tokens_carry_a_bit_pattern_and_a_null() {
        assert!(LockOwner::NONE.is_none());
        assert_eq!(LockOwner::NONE.bits(), 0);
        assert!(!OWNER.is_none());
        assert_eq!(LockOwner::from_bits(OWNER.bits()), OWNER);
        assert!(ShareUserData::NONE.is_none());
        assert_eq!(ShareUserData::default(), ShareUserData::NONE);
        assert_eq!(ShareUserData::from_bits(USERDATA.bits()), USERDATA);
    }

    /// [`Specifier`] reads as the C mask it is, and its two macro predicates
    /// answer what the C macros answer.
    #[test]
    fn the_specifier_is_a_mask_with_the_two_c_predicates() {
        assert_eq!(Specifier::EMPTY.bits(), 0);
        assert_eq!(Specifier::EMPTY.to_string(), "(none)");
        assert!(!Specifier::EMPTY.keep_connect());
        assert!(!Specifier::EMPTY.ssl_scache());

        let share = Share::new();
        assert_eq!(share.setopt(ShareOption::Share(5)), CURLSHcode::Ok);
        assert_eq!(share.setopt(ShareOption::Share(4)), CURLSHcode::Ok);
        let specifier = share.specifier();
        assert!(specifier.keep_connect());
        assert!(specifier.ssl_scache());
        assert!(specifier.contains(LockData::Share));
        assert!(!specifier.contains(LockData::Cookie));
        assert_eq!(
            specifier.bits(),
            LockData::Share.bit()
                | LockData::SslSession.bit()
                | LockData::Connect.bit()
        );
        assert_eq!(
            specifier.to_string(),
            "CURL_LOCK_DATA_SHARE, CURL_LOCK_DATA_SSL_SESSION, \
             CURL_LOCK_DATA_CONNECT"
        );
    }

    // `curl_share_init` (`lib/curl_share.c:33-55`)

    /// A new share is valid, shares only its own internal state, and has no
    /// user.
    ///
    /// `:37` sets the tag, `:38` sets bit 1 before an application asks for
    /// anything, and `curlx_calloc` at `:35` leaves everything else zero.
    #[test]
    fn a_new_share_carries_the_good_magic_and_only_the_share_bit() {
        let share = Share::new();
        assert_eq!(share.magic(), Share::GOOD_MAGIC);
        assert_eq!(Share::GOOD_MAGIC, 0x7e11_7a1e);
        assert!(share.is_valid());
        assert_eq!(share.specifier().bits(), LockData::Share.bit());
        assert!(share.is_shared(LockData::Share));
        assert_eq!(share.dirty(), 0);
        assert!(!share.is_in_use());
        // `Default` and `new` are the same construction.
        assert_eq!(Share::default().specifier(), share.specifier());
    }

    /// No datum but `CURL_LOCK_DATA_SHARE` is shared, and therefore no store
    /// is reachable, on a share nobody has configured.
    #[test]
    fn a_new_share_exposes_no_store() {
        let share = Share::new();
        assert!(share.dnscache(OWNER).is_none());
        assert!(share.ssl_scache(OWNER).is_none());
        assert!(share.pool(OWNER).is_none());
        #[cfg(feature = "cookies")]
        assert!(share.cookies(OWNER).is_none());
        #[cfg(feature = "hsts")]
        assert!(share.hsts(OWNER).is_none());
    }

    /// The three capacities `lib/curl_share.c` passes to its store
    /// constructors.
    #[test]
    fn the_measured_capacities_are_the_c_values() {
        assert_eq!(DNS_CACHE_SLOTS, 23);
        assert_eq!(SCACHE_MAX_PEERS, 25);
        assert_eq!(SCACHE_MAX_SESSIONS_PER_PEER, 2);
        assert_eq!(CPOOL_SLOTS, 103);

        let share = Share::new();
        assert_eq!(share.setopt(ShareOption::Share(4)), CURLSHcode::Ok);
        let guard = share
            .ssl_scache(OWNER)
            .expect("shared after CURLSHOPT_SHARE");
        let cache = guard.as_ref().expect("a set bit implies a created store");
        assert_eq!(cache.peer_count(), SCACHE_MAX_PEERS);
        drop(guard);

        assert_eq!(share.setopt(ShareOption::Share(3)), CURLSHcode::Ok);
        let dns = share.dnscache(OWNER).expect("shared after CURLSHOPT_SHARE");
        assert!(dns.is_empty());
    }

    /// A share does not propagate itself, and two shares are independent.
    ///
    /// `grep -n share lib/easy.c` returns nothing, which is the measurement
    /// behind this: `curl_easy_duphandle` does **not** copy the share pointer,
    /// so a duplicated handle starts with no share and does not increment
    /// anybody's count. This module offers no propagation operation at all --
    /// [`ShareCore::attach`] is the only thing that increments -- and this test
    /// pins the consequence: counting one share never touches another.
    #[test]
    fn shares_are_independent_and_nothing_propagates_a_share() {
        let first = Share::new();
        let second = Share::new();
        let _ = first.attach(OWNER, |_| ());
        assert_eq!(first.dirty(), 1);
        assert_eq!(second.dirty(), 0);
        let _ = first.detach(OWNER, |_| ());
        assert_eq!(first.dirty(), 0);
        assert_eq!(second.dirty(), 0);
    }

    // `CURLSHOPT_SHARE` and `CURLSHOPT_UNSHARE`
    // (`lib/curl_share.c:79-145`, `:147-194`)

    /// Every datum the C accepts can be shared, and each sets its own bit.
    ///
    /// The six arms of `lib/curl_share.c:83-138`. The Public Suffix List and
    /// the HSTS cache are feature-gated here, so their expected code depends
    /// on the build; everything else is unconditional.
    #[test]
    fn every_datum_the_c_accepts_can_be_shared() {
        let expected_cookie = if cfg!(feature = "cookies") {
            CURLSHcode::Ok
        } else {
            CURLSHcode::NotBuiltIn
        };
        let expected_hsts = if cfg!(feature = "hsts") {
            CURLSHcode::Ok
        } else {
            CURLSHcode::NotBuiltIn
        };
        for (kind, expected) in [
            (LockData::Cookie, expected_cookie),
            (LockData::Dns, CURLSHcode::Ok),
            (LockData::SslSession, CURLSHcode::Ok),
            (LockData::Connect, CURLSHcode::Ok),
            (LockData::Psl, expected_cookie),
            (LockData::Hsts, expected_hsts),
        ] {
            let share = Share::new();
            assert_eq!(
                share.setopt(ShareOption::Share(kind.as_i32())),
                expected,
                "CURLSHOPT_SHARE with {}",
                kind.c_name()
            );
            // C: lib/curl_share.c:143-144 -- the bit is set ONLY on success.
            assert_eq!(
                share.specifier().contains(kind),
                expected.is_ok(),
                "specifier bit for {}",
                kind.c_name()
            );
            // The share's own bit is untouched throughout.
            assert!(share.specifier().contains(LockData::Share));
        }
    }

    /// Sharing a datum makes exactly that datum's store reachable.
    #[test]
    fn sharing_a_datum_makes_its_store_reachable() {
        let share = Share::new();
        assert_eq!(share.setopt(ShareOption::Share(3)), CURLSHcode::Ok);
        assert!(share.dnscache(OWNER).is_some());
        assert!(share.ssl_scache(OWNER).is_none());

        assert_eq!(share.setopt(ShareOption::Share(4)), CURLSHcode::Ok);
        assert!(share.ssl_scache(OWNER).is_some());

        assert_eq!(share.setopt(ShareOption::Share(5)), CURLSHcode::Ok);
        assert!(share.pool(OWNER).is_some());

        #[cfg(feature = "cookies")]
        {
            assert_eq!(share.setopt(ShareOption::Share(2)), CURLSHcode::Ok);
            assert!(share.cookies(OWNER).is_some());
        }
        #[cfg(feature = "hsts")]
        {
            assert_eq!(share.setopt(ShareOption::Share(7)), CURLSHcode::Ok);
            assert!(share.hsts(OWNER).is_some());
        }
    }

    /// Un-sharing each datum the C's switch names clears its bit and succeeds.
    ///
    /// `lib/curl_share.c:152-188`. The Public Suffix List is deliberately
    /// absent from this list; it has its own test, because the C has no case
    /// for it.
    #[test]
    fn every_datum_the_unshare_switch_names_clears_and_succeeds() {
        let expected_cookie = if cfg!(feature = "cookies") {
            CURLSHcode::Ok
        } else {
            CURLSHcode::NotBuiltIn
        };
        let expected_hsts = if cfg!(feature = "hsts") {
            CURLSHcode::Ok
        } else {
            CURLSHcode::NotBuiltIn
        };
        for (kind, expected) in [
            (LockData::Cookie, expected_cookie),
            (LockData::Dns, CURLSHcode::Ok),
            (LockData::SslSession, CURLSHcode::Ok),
            (LockData::Connect, CURLSHcode::Ok),
            (LockData::Hsts, expected_hsts),
        ] {
            let share = Share::new();
            let _ = share.setopt(ShareOption::Share(kind.as_i32()));
            assert_eq!(
                share.setopt(ShareOption::Unshare(kind.as_i32())),
                expected,
                "CURLSHOPT_UNSHARE with {}",
                kind.c_name()
            );
            // C: lib/curl_share.c:150 -- cleared regardless of the result.
            assert!(
                !share.specifier().contains(kind),
                "bit still set for {}",
                kind.c_name()
            );
        }
    }

    /// Un-sharing destroys the store the C destroys, and leaves the two it
    /// leaves.
    #[test]
    fn unsharing_destroys_only_what_the_c_destroys() {
        let share = Share::new();
        assert_eq!(share.setopt(ShareOption::Share(4)), CURLSHcode::Ok);
        {
            let mut guard = share.ssl_scache(OWNER).expect("shared");
            let cache = guard.as_mut().expect("created");
            cache.set_default_lifetime_secs(4321);
        }
        assert_eq!(share.setopt(ShareOption::Unshare(4)), CURLSHcode::Ok);
        assert!(share.ssl_scache(OWNER).is_none());
        // Re-sharing builds a NEW cache, because the old one was destroyed.
        assert_eq!(share.setopt(ShareOption::Share(4)), CURLSHcode::Ok);
        let guard = share.ssl_scache(OWNER).expect("shared again");
        assert_ne!(
            guard.as_ref().expect("created").default_lifetime_secs(),
            4321
        );
        drop(guard);

        // The pool survives an unshare, so its transfer counter keeps going.
        assert_eq!(share.setopt(ShareOption::Share(5)), CURLSHcode::Ok);
        let first = {
            let mut guard = share.pool(OWNER).expect("shared");
            guard
                .as_mut()
                .expect("created")
                .xfer_init()
                .transfer_id
                .get()
        };
        assert_eq!(share.setopt(ShareOption::Unshare(5)), CURLSHcode::Ok);
        assert!(share.pool(OWNER).is_none(), "the bit is clear");
        assert_eq!(share.setopt(ShareOption::Share(5)), CURLSHcode::Ok);
        let second = {
            let mut guard = share.pool(OWNER).expect("shared again");
            guard
                .as_mut()
                .expect("created")
                .xfer_init()
                .transfer_id
                .get()
        };
        assert_eq!(
            second,
            first + 1,
            "lib/curl_share.c:187-188 does not destroy the pool"
        );
    }

    /// Setting the same datum twice succeeds twice and does not rebuild the
    /// store.
    #[test]
    fn sharing_a_datum_twice_is_idempotent_and_keeps_the_store() {
        let share = Share::new();

        assert_eq!(share.setopt(ShareOption::Share(4)), CURLSHcode::Ok);
        {
            let mut guard = share.ssl_scache(OWNER).expect("shared");
            guard
                .as_mut()
                .expect("created")
                .set_default_lifetime_secs(1234);
        }
        assert_eq!(share.setopt(ShareOption::Share(4)), CURLSHcode::Ok);
        assert_eq!(
            share
                .ssl_scache(OWNER)
                .expect("still shared")
                .as_ref()
                .expect("still created")
                .default_lifetime_secs(),
            1234,
            "the second CURLSHOPT_SHARE rebuilt the session cache"
        );

        assert_eq!(share.setopt(ShareOption::Share(5)), CURLSHcode::Ok);
        let first = {
            let mut guard = share.pool(OWNER).expect("shared");
            guard
                .as_mut()
                .expect("created")
                .xfer_init()
                .transfer_id
                .get()
        };
        assert_eq!(share.setopt(ShareOption::Share(5)), CURLSHcode::Ok);
        let second = {
            let mut guard = share.pool(OWNER).expect("still shared");
            guard
                .as_mut()
                .expect("created")
                .xfer_init()
                .transfer_id
                .get()
        };
        assert_eq!(
            second,
            first + 1,
            "the second CURLSHOPT_SHARE rebuilt the pool"
        );

        #[cfg(feature = "cookies")]
        {
            assert_eq!(share.setopt(ShareOption::Share(2)), CURLSHcode::Ok);
            {
                let mut guard = share.cookies(OWNER).expect("shared");
                guard.as_mut().expect("created").set_newsession(true);
            }
            assert_eq!(share.setopt(ShareOption::Share(2)), CURLSHcode::Ok);
            assert!(
                share
                    .cookies(OWNER)
                    .expect("still shared")
                    .as_ref()
                    .expect("still created")
                    .newsession(),
                "the second CURLSHOPT_SHARE rebuilt the cookie jar"
            );
        }

        #[cfg(feature = "hsts")]
        {
            assert_eq!(share.setopt(ShareOption::Share(7)), CURLSHcode::Ok);
            {
                let mut guard = share.hsts(OWNER).expect("shared");
                guard.as_mut().expect("created").set_flags(0x2a);
            }
            assert_eq!(share.setopt(ShareOption::Share(7)), CURLSHcode::Ok);
            assert_eq!(
                share
                    .hsts(OWNER)
                    .expect("still shared")
                    .as_ref()
                    .expect("still created")
                    .flags(),
                0x2a,
                "the second CURLSHOPT_SHARE rebuilt the HSTS cache"
            );
        }
    }

    /// Every diagnostic spelling is exercised, including the tokens the share
    /// path never reaches.
    #[test]
    fn every_diagnostic_spelling_is_the_header_spelling() {
        assert_eq!(LockData::None.c_name(), "CURL_LOCK_DATA_NONE");
        assert_eq!(LockData::Last.c_name(), "CURL_LOCK_DATA_LAST");
        assert_eq!(LockAccess::None.c_name(), "CURL_LOCK_ACCESS_NONE");
        assert_eq!(LockAccess::Last.c_name(), "CURL_LOCK_ACCESS_LAST");

        // `Display` is the C spelling for both enumerations.
        assert_eq!(LockData::Psl.to_string(), "CURL_LOCK_DATA_PSL");
        assert_eq!(LockAccess::Shared.to_string(), "CURL_LOCK_ACCESS_SHARED");

        // The mask renders the set, in declaration order, and says so
        // explicitly when it is empty rather than printing nothing at all.
        assert_eq!(Specifier::EMPTY.to_string(), "(none)");
        let share = Share::new();
        assert_eq!(share.specifier().to_string(), "CURL_LOCK_DATA_SHARE");
        assert_eq!(share.setopt(ShareOption::Share(3)), CURLSHcode::Ok);
        assert_eq!(
            share.specifier().to_string(),
            "CURL_LOCK_DATA_SHARE, CURL_LOCK_DATA_DNS",
            "the separator or the order moved"
        );

        // The metadata arm of `Debug for Share` reports a held lock instead of
        // blocking on it, exactly as the store arms do: `Debug` is reachable
        // from inside a critical section, and a formatter that deadlocked
        // there would be worse than one that admits what it cannot see.
        let held = share.meta();
        let rendered = format!("{share:?}");
        drop(held);
        assert!(
            rendered.contains("meta: \"<locked>\""),
            "the metadata lock was not reported as held: {rendered}"
        );
        assert!(
            rendered.contains("magic"),
            "the tag is absent from the rendering: {rendered}"
        );
    }

    /// A writer that fails is propagated, never unwrapped.
    #[test]
    fn a_failing_writer_is_propagated_rather_than_unwrapped() {
        /// Succeeds `remaining` times, then fails for good.
        struct FailAfter {
            remaining: usize,
        }

        impl fmt::Write for FailAfter {
            fn write_str(&mut self, _: &str) -> fmt::Result {
                if self.remaining == 0 {
                    return Err(fmt::Error);
                }
                self.remaining -= 1;
                Ok(())
            }
        }

        let share = Share::new();
        assert_eq!(share.setopt(ShareOption::Share(3)), CURLSHcode::Ok);
        let mask = share.specifier();

        // The first name written fails: `f.write_str(kind.c_name())?`.
        let mut writer = FailAfter { remaining: 0 };
        assert!(fmt::write(&mut writer, format_args!("{mask}")).is_err());

        // The first name succeeds and the separator then fails:
        // `f.write_str(", ")?` between the two set bits.
        let mut writer = FailAfter { remaining: 1 };
        assert!(fmt::write(&mut writer, format_args!("{mask}")).is_err());

        // And the empty-mask arm: `f.write_str("(none)")?`.
        let mut writer = FailAfter { remaining: 0 };
        let empty = Specifier::EMPTY;
        assert!(fmt::write(&mut writer, format_args!("{empty}")).is_err());

        // A writer with room to spare still renders the whole mask, so the
        // fixture above is measuring the writer and not a broken formatter.
        let mut writer = FailAfter { remaining: 8 };
        assert!(fmt::write(&mut writer, format_args!("{mask}")).is_ok());
    }

    /// The Public Suffix List guard describes what it is holding.
    ///
    /// The guard is the one place a reader can be handed a lock that outlives
    /// the call that took it (`lib/psl.c:89` returns with the shared lock
    /// held), so its `Debug` is the only window onto that state.
    #[cfg(feature = "cookies")]
    #[test]
    fn the_public_suffix_list_guard_describes_its_cache() {
        let share = Share::new();
        assert_eq!(share.setopt(ShareOption::Share(6)), CURLSHcode::Ok);
        let clock = TestClock::new(CurlTime::new(1_000, 0));
        let source = MemoryPslSource::latest(PSL_LIST);

        let guard = share.psl_use(OWNER, &clock, &source).expect("a list");
        let rendered = format!("{guard:?}");
        assert!(
            rendered.starts_with("PslGuard {"),
            "unexpected rendering: {rendered}"
        );
        assert!(
            rendered.contains("has_list: true"),
            "the loaded list is not reported: {rendered}"
        );
        assert!(
            rendered.contains("owner"),
            "the holder is not reported: {rendered}"
        );
        assert!(
            rendered.contains("expires"),
            "the deadline is not reported: {rendered}"
        );
        assert!(
            rendered.contains("dynamic"),
            "the provenance is not reported: {rendered}"
        );
    }

    /// Un-sharing a datum that was never shared succeeds and touches nothing.
    #[test]
    fn unsharing_a_datum_that_was_never_shared_is_still_successful() {
        let expected_cookie = if cfg!(feature = "cookies") {
            CURLSHcode::Ok
        } else {
            CURLSHcode::NotBuiltIn
        };
        let expected_hsts = if cfg!(feature = "hsts") {
            CURLSHcode::Ok
        } else {
            CURLSHcode::NotBuiltIn
        };
        for (kind, expected) in [
            (LockData::Cookie, expected_cookie),
            (LockData::Dns, CURLSHcode::Ok),
            (LockData::SslSession, CURLSHcode::Ok),
            (LockData::Connect, CURLSHcode::Ok),
            (LockData::Hsts, expected_hsts),
        ] {
            let share = Share::new();
            assert!(
                !share.specifier().contains(kind),
                "{} was set before the test began",
                kind.c_name()
            );

            assert_eq!(
                share.setopt(ShareOption::Unshare(kind.as_i32())),
                expected,
                "CURLSHOPT_UNSHARE with an unshared {}",
                kind.c_name()
            );

            // Nothing was created on the way out, and the bit is still clear:
            // only `CURLSHOPT_SHARE` builds a store.
            assert!(
                !share.specifier().contains(kind),
                "bit set by an un-share of {}",
                kind.c_name()
            );
            assert_eq!(
                share.specifier().bits(),
                Specifier::EMPTY.bits() | LockData::Share.bit(),
                "the specifier moved for {}",
                kind.c_name()
            );

            // And the share is still perfectly serviceable afterwards.
            assert!(share.is_valid());
            assert_eq!(share.cleanup(), CURLSHcode::Ok);
        }
    }

    /// An option identifier the C's outer switch does not name yields
    /// `CURLSHE_BAD_OPTION` (`lib/curl_share.c:211-213`).
    #[test]
    fn an_unknown_option_is_a_bad_option() {
        let share = Share::new();
        assert_eq!(share.setopt(ShareOption::None), CURLSHcode::BadOption);
        assert_eq!(share.setopt(ShareOption::Last), CURLSHcode::BadOption);
        assert_eq!(
            share.setopt(ShareOption::Unknown(6)),
            CURLSHcode::BadOption
        );
        assert_eq!(
            share.setopt(ShareOption::Unknown(-1)),
            CURLSHcode::BadOption
        );
        assert_eq!(
            share.setopt(ShareOption::Unknown(i32::MAX)),
            CURLSHcode::BadOption
        );
        // Nothing changed.
        assert_eq!(share.specifier().bits(), LockData::Share.bit());
    }

    /// A datum the C's inner switch does not name yields
    /// `CURLSHE_BAD_OPTION`, and `CURLSHOPT_SHARE` leaves the mask alone.
    ///
    /// `lib/curl_share.c:140-141` for the recognised-but-unhandled tokens, and
    /// `:143`'s `if(!res)` for why no bit is set.
    #[test]
    fn an_unhandled_datum_is_a_bad_option_on_the_share_path() {
        for raw in [
            LockData::None.as_i32(),
            LockData::Share.as_i32(),
            LockData::Last.as_i32(),
            9,
            99,
            -1,
        ] {
            let share = Share::new();
            assert_eq!(
                share.setopt(ShareOption::Share(raw)),
                CURLSHcode::BadOption,
                "CURLSHOPT_SHARE with {raw}"
            );
            assert_eq!(
                share.specifier().bits(),
                LockData::Share.bit(),
                "CURLSHOPT_SHARE with {raw} changed the mask"
            );
        }
    }

    /// QUIRK 1: `CURLSHOPT_UNSHARE` clears the bit before it can fail.
    ///
    /// `lib/curl_share.c:150` runs **before** the switch and is not guarded by
    /// the result, so an unshare that returns `CURLSHE_BAD_OPTION` has already
    /// cleared the bit. This is a regression test: the behaviour is
    /// deliberate, `lib/curl_share.c:150` is the locator, and
    /// `:190-192` is the arm that returns the error afterwards. Do not "fix"
    /// it by moving or guarding the clear.
    #[test]
    fn unshare_clears_the_bit_even_when_it_then_reports_a_bad_option() {
        // `CURL_LOCK_DATA_SHARE` is the sharpest demonstration: its bit is set
        // at birth by `lib/curl_share.c:38`, the unshare switch has no case
        // for it, and the C clears it anyway.
        let share = Share::new();
        assert!(share.specifier().contains(LockData::Share));
        assert_eq!(
            share.setopt(ShareOption::Unshare(LockData::Share.as_i32())),
            CURLSHcode::BadOption
        );
        assert!(
            !share.specifier().contains(LockData::Share),
            "lib/curl_share.c:150 clears the bit unconditionally"
        );
        assert_eq!(share.specifier(), Specifier::EMPTY);

        // The out-of-band tokens behave the same way.
        for kind in [LockData::None, LockData::Last] {
            let share = Share::new();
            // Give the bit something to clear.
            assert_eq!(
                share.setopt(ShareOption::Unshare(kind.as_i32())),
                CURLSHcode::BadOption,
                "{}",
                kind.c_name()
            );
            assert!(!share.specifier().contains(kind));
        }
    }

    /// A raw datum outside the enumeration reports the same error and changes
    /// nothing.
    ///
    /// The one deliberate divergence in this function, and it is confined to
    /// inputs the C leaves undefined: `lib/curl_share.c:150` would evaluate
    /// `1 << type` for a value like 99 or -1, which is undefined behaviour
    /// rather than a documented effect. There is therefore no C behaviour to
    /// reproduce, and refusing before the shift is the only defined choice.
    /// Every value the C *does* define is handled identically, which the test
    /// above asserts.
    #[test]
    fn unshare_with_a_datum_outside_the_enumeration_changes_nothing() {
        let share = Share::new();
        assert_eq!(share.setopt(ShareOption::Share(3)), CURLSHcode::Ok);
        let before = share.specifier();
        for raw in [9, 31, 32, 99, -1, i32::MIN, i32::MAX] {
            assert_eq!(
                share.setopt(ShareOption::Unshare(raw)),
                CURLSHcode::BadOption,
                "CURLSHOPT_UNSHARE with {raw}"
            );
            assert_eq!(
                share.specifier(),
                before,
                "CURLSHOPT_UNSHARE with {raw} changed the mask"
            );
        }
    }

    /// QUIRK 2: un-sharing the Public Suffix List is a bad option, and clears
    /// its bit anyway.
    #[test]
    fn unshare_with_the_public_suffix_list_is_a_bad_option_and_still_clears() {
        let share = Share::new();
        let shared = share.setopt(ShareOption::Share(LockData::Psl.as_i32()));
        if cfg!(feature = "cookies") {
            assert_eq!(shared, CURLSHcode::Ok);
            assert!(share.specifier().contains(LockData::Psl));
        } else {
            assert_eq!(shared, CURLSHcode::NotBuiltIn);
        }

        assert_eq!(
            share.setopt(ShareOption::Unshare(LockData::Psl.as_i32())),
            CURLSHcode::BadOption,
            "lib/curl_share.c:190-192: there is no PSL case"
        );
        assert!(
            !share.specifier().contains(LockData::Psl),
            "lib/curl_share.c:150 cleared the bit before the switch"
        );
        // The HSTS case, which the same document omits, is handled.
        let share = Share::new();
        let expected = if cfg!(feature = "hsts") {
            CURLSHcode::Ok
        } else {
            CURLSHcode::NotBuiltIn
        };
        assert_eq!(
            share.setopt(ShareOption::Unshare(LockData::Hsts.as_i32())),
            expected
        );
    }

    /// `CURL_LOCK_DATA_SSL_SESSION` can never report
    /// `CURLSHE_NOT_BUILT_IN`.
    #[test]
    fn tls_session_sharing_is_never_reported_as_missing() {
        let share = Share::new();
        assert_eq!(share.setopt(ShareOption::Share(4)), CURLSHcode::Ok);
        assert_eq!(share.setopt(ShareOption::Unshare(4)), CURLSHcode::Ok);
        assert_eq!(share.setopt(ShareOption::Share(4)), CURLSHcode::Ok);
    }

    /// With the `cookies` feature off, the cookie jar and the Public Suffix
    /// List report `CURLSHE_NOT_BUILT_IN`.
    ///
    /// The `#else` arms of `lib/curl_share.c:94-96`, `:135-137` and
    /// `:161-163`. `crate::cookies` gates its `psl` child on the same feature,
    /// which is why one Rust feature answers two C guards.
    #[cfg(not(feature = "cookies"))]
    #[test]
    fn without_the_cookies_feature_cookies_and_the_psl_are_not_built_in() {
        let share = Share::new();
        assert_eq!(share.setopt(ShareOption::Share(2)), CURLSHcode::NotBuiltIn);
        assert_eq!(share.setopt(ShareOption::Share(6)), CURLSHcode::NotBuiltIn);
        assert_eq!(
            share.setopt(ShareOption::Unshare(2)),
            CURLSHcode::NotBuiltIn
        );
        // The PSL still has no unshare case, so it is a bad option either way.
        assert_eq!(
            share.setopt(ShareOption::Unshare(6)),
            CURLSHcode::BadOption
        );
        // No bit was set for either.
        assert_eq!(share.specifier().bits(), LockData::Share.bit());
    }

    /// With the `hsts` feature off, the HSTS cache reports
    /// `CURLSHE_NOT_BUILT_IN`.
    ///
    /// The `#else` arms of `lib/curl_share.c:106-108` and `:171-173`.
    #[cfg(not(feature = "hsts"))]
    #[test]
    fn without_the_hsts_feature_hsts_is_not_built_in() {
        let share = Share::new();
        assert_eq!(share.setopt(ShareOption::Share(7)), CURLSHcode::NotBuiltIn);
        assert_eq!(
            share.setopt(ShareOption::Unshare(7)),
            CURLSHcode::NotBuiltIn
        );
        assert_eq!(share.specifier().bits(), LockData::Share.bit());
    }

    /// [`ShareOption`]'s hand-written [`fmt::Debug`] names the C option and
    /// says whether a callback is present.
    #[test]
    fn the_option_debug_output_names_the_c_option() {
        assert_eq!(format!("{:?}", ShareOption::None), "CURLSHOPT_NONE");
        assert_eq!(format!("{:?}", ShareOption::Last), "CURLSHOPT_LAST");
        assert_eq!(
            format!("{:?}", ShareOption::Share(2)),
            "CURLSHOPT_SHARE(2)"
        );
        assert_eq!(
            format!("{:?}", ShareOption::Unshare(6)),
            "CURLSHOPT_UNSHARE(6)"
        );
        assert_eq!(
            format!("{:?}", ShareOption::LockFunc(None)),
            "CURLSHOPT_LOCKFUNC(null)"
        );
        assert_eq!(
            format!(
                "{:?}",
                ShareOption::LockFunc(Some(Arc::new(|_, _, _, _| {})))
            ),
            "CURLSHOPT_LOCKFUNC(set)"
        );
        assert_eq!(
            format!("{:?}", ShareOption::UnlockFunc(None)),
            "CURLSHOPT_UNLOCKFUNC(null)"
        );
        assert_eq!(
            format!(
                "{:?}",
                ShareOption::UnlockFunc(Some(Arc::new(|_, _, _| {})))
            ),
            "CURLSHOPT_UNLOCKFUNC(set)"
        );
        assert_eq!(
            format!("{:?}", ShareOption::UserData(USERDATA)),
            "CURLSHOPT_USERDATA(0xdeadbeef)"
        );
        assert_eq!(
            format!("{:?}", ShareOption::Unknown(42)),
            "CURLSHoption(42)"
        );
    }

    // The reference count, and the two refusals it drives

    /// Attaching and detaching move the count and are exactly balanced.
    ///
    /// `lib/setopt.c:1527` increments, `:1514` and `lib/url.c:292` decrement,
    /// and all three sit between a `CURL_LOCK_DATA_SHARE` lock and unlock with
    /// `CURL_LOCK_ACCESS_SINGLE`.
    #[test]
    fn attaching_and_detaching_move_the_reference_count() {
        let share = Share::new();
        assert_eq!(share.dirty(), 0);
        let _ = share.attach(OWNER, |_| ());
        let _ = share.attach(LockOwner::from_bits(0x2000), |_| ());
        assert_eq!(share.dirty(), 2);
        assert!(share.is_in_use());
        let _ = share.detach(LockOwner::from_bits(0x2000), |_| ());
        assert_eq!(share.dirty(), 1);
        let _ = share.detach(OWNER, |_| ());
        assert_eq!(share.dirty(), 0);
        assert!(!share.is_in_use());
    }

    /// Both operations hand the caller the mask it needs for its repointing.
    ///
    /// `lib/setopt.c:1530`, `:1538` and `:1545` read the shared cookie jar,
    /// the shared HSTS cache and the `CURL_LOCK_DATA_PSL` bit to decide what an
    /// attaching handle points at; `:1497-1512` reads the same mask, plus the
    /// `CURL_LOCK_DATA_DNS` bit, to decide what a detaching one must unlink.
    #[test]
    fn attach_and_detach_report_the_specifier_the_caller_must_act_on() {
        let share = Share::new();
        assert_eq!(share.setopt(ShareOption::Share(3)), CURLSHcode::Ok);
        let on_attach = share.attach(OWNER, |mask| mask).expect("registered");
        assert!(on_attach.contains(LockData::Dns));
        assert!(on_attach.contains(LockData::Share));
        assert_eq!(
            share.detach(OWNER, |mask| mask).expect("deregistered"),
            on_attach
        );
    }

    /// The repointing runs **inside** the user-visible `CURL_LOCK_DATA_SHARE`
    /// critical section, on both operations.
    ///
    /// This is the placement `lib/setopt.c` gives it and it is observable: the
    /// application's lock callback is what serialises an attaching handle's
    /// view of the shared stores. Attach does `dirty++` at `:1527` and then
    /// the repointing at `:1529-1547`; detach does the repointing at
    /// `:1497-1512` and then `dirty--` at `:1514`. The closure therefore sees
    /// the count already raised on attach and not yet lowered on detach, and
    /// in both cases sees the lock notification delivered and the unlock still
    /// owed.
    #[test]
    fn the_ownership_change_happens_inside_the_share_lock() {
        let (share, recorder) = recorded();
        assert_eq!(share.setopt(ShareOption::Share(3)), CURLSHcode::Ok);
        let _ = recorder.drain();

        let seen = share
            .attach(OWNER, |mask| {
                // C: lib/setopt.c:1527 has already run.
                assert_eq!(share.dirty(), 1);
                // The lock notification has been delivered and the unlock has
                // not.
                assert_eq!(
                    recorder.events(),
                    vec![Event::Lock(
                        OWNER,
                        LockData::Share,
                        LockAccess::Single,
                        USERDATA
                    )],
                    "the repointing must run inside the bracket"
                );
                // A different datum is reachable from inside it, which is what
                // `lib/setopt.c:1530-1535` does when it reads `share->cookies`.
                assert!(share.dnscache(OWNER).is_some());
                mask
            })
            .expect("registered");
        assert!(seen.contains(LockData::Dns));
        assert_eq!(
            recorder.drain().last().copied(),
            Some(Event::Unlock(OWNER, LockData::Share, USERDATA)),
            "the unlock closes the bracket after the repointing"
        );

        share
            .detach(OWNER, |_| {
                // C: lib/setopt.c:1514 has NOT run yet -- the handle lets go of
                // every shared store before the count can reach zero.
                assert_eq!(share.dirty(), 1);
                assert_eq!(
                    recorder.events(),
                    vec![Event::Lock(
                        OWNER,
                        LockData::Share,
                        LockAccess::Single,
                        USERDATA
                    )]
                );
            })
            .expect("deregistered");
        assert_eq!(share.dirty(), 0);
        assert_eq!(
            recorder.drain().last().copied(),
            Some(Event::Unlock(OWNER, LockData::Share, USERDATA))
        );
        recorder.assert_balanced();
    }

    /// An unbalanced detach wraps to `UINT_MAX`, exactly as the C's does.
    ///
    /// `lib/setopt.c:1514` and `lib/url.c:292` write `dirty--` on an
    /// `unsigned int`, so a decrement with nothing attached wraps and the
    /// share can never be cleaned up again -- `lib/curl_share.c:231-235`
    /// reports `CURLSHE_IN_USE` for ever after. Both C call sites are guarded
    /// by `if(data->share)`, so libcurl itself never reaches it, and this API
    /// makes it reachable only by an unbalanced caller.
    ///
    /// Reproduced rather than softened: `wrapping_sub` cannot panic in any
    /// build, so nothing is bought by saturating, while the consequence an
    /// application observes stays the one curl 8.x produces.
    #[test]
    fn a_detach_with_nothing_attached_wraps_exactly_as_the_c_does() {
        let share = Share::new();
        share.detach(OWNER, |_| ()).expect("a live share");
        assert_eq!(share.dirty(), u32::MAX);
        assert!(share.is_in_use());
        assert_eq!(share.cleanup(), CURLSHcode::InUse);
        // Refused, so the object is intact and the claim was given back.
        assert!(share.is_valid());
        assert_eq!(share.magic(), Share::GOOD_MAGIC);

        // The matching attach restores the balance, and cleanup then succeeds.
        share.attach(OWNER, |_| ()).expect("a live share");
        assert_eq!(share.dirty(), 0);
        assert_eq!(share.cleanup(), CURLSHcode::Ok);
    }

    /// An invalid share is not counted and runs no transaction.
    ///
    /// `lib/setopt.c:1520`'s `if(GOOD_SHARE_HANDLE(set))`: a share that fails
    /// the check is never assigned to the handle and never counted. Both
    /// operations answer [`None`] and neither closure runs, so a caller cannot
    /// repoint itself at a store that no longer exists.
    #[test]
    fn attaching_to_a_torn_down_share_changes_nothing() {
        let share = Share::new();
        assert_eq!(share.cleanup(), CURLSHcode::Ok);
        assert!(!share.is_valid());
        let ran = AtomicUsize::new(0);
        assert!(share
            .attach(OWNER, |_| ran.fetch_add(1, Ordering::Relaxed))
            .is_none());
        assert!(share
            .detach(OWNER, |_| ran.fetch_add(1, Ordering::Relaxed))
            .is_none());
        assert_eq!(ran.load(Ordering::Relaxed), 0, "neither closure ran");
        assert_eq!(share.dirty(), 0);
    }

    /// While a teardown is claimed, nothing can take a new reference, no
    /// option can be set and a second teardown is refused -- but a detach and
    /// the notifications still land.
    ///
    /// The claim is the whole of [`Share::cleanup`]'s serialisation and the
    /// state the C does not have: its `magic` is `CURL_GOOD_SHARE` from
    /// `lib/curl_share.c:224` right up to `:263`, so two threads in that span
    /// both pass the validity test, both read `share->dirty` and both reach
    /// `CURLSHE_OK`. The transition is driven directly here rather than raced,
    /// because that makes the property a deterministic assertion rather than a
    /// probabilistic one; `crate::share`'s multi-threaded test covers the
    /// contended case.
    ///
    /// The three admissions are as deliberate as the three refusals.
    /// [`ShareCore::detach`] must land or a decrement the caller has already
    /// committed to is lost for ever, leaving a count no cleanup can bring to
    /// zero; and `lock`/`unlock` must still deliver, because the C's own
    /// teardown notifies through them -- `Curl_cpool_destroy` brackets its
    /// loop with `CPOOL_LOCK`/`CPOOL_UNLOCK` (`lib/conncache.c:41-60`).
    #[test]
    fn a_claimed_teardown_refuses_new_references_and_a_second_cleanup() {
        let (share, recorder) = recorded();
        assert_eq!(share.setopt(ShareOption::Share(3)), CURLSHcode::Ok);
        share.attach(OWNER, |_| ()).expect("a live share");
        let _ = recorder.drain();

        assert!(share.claim_cleanup(), "the first claim wins");

        // Refused: a second claim, every option, every store accessor and any
        // new reference.
        assert!(!share.claim_cleanup(), "the second claim loses");
        assert_eq!(share.cleanup(), CURLSHcode::Invalid);
        assert!(!share.is_valid());
        // `CURL_LOCK_DATA_SSL_SESSION`, which is the one datum no feature can
        // turn off, so this reads the same in every build.
        assert_eq!(share.setopt(ShareOption::Share(4)), CURLSHcode::Invalid);
        assert!(share.dnscache(OWNER).is_none());
        assert!(share.attach(OWNER, |_| ()).is_none(), "no new reference");
        assert_eq!(share.dirty(), 1, "and therefore no new count");

        // Admitted: the notifications, so that a teardown can notify.
        assert_eq!(
            share.lock(OWNER, LockData::Dns, LockAccess::Single),
            CURLSHcode::Ok
        );
        assert_eq!(share.unlock(OWNER, LockData::Dns), CURLSHcode::Ok);
        assert_eq!(
            recorder.drain(),
            vec![
                Event::Lock(OWNER, LockData::Dns, LockAccess::Single, USERDATA),
                Event::Unlock(OWNER, LockData::Dns, USERDATA),
            ]
        );

        // Admitted: the detach, so no decrement is lost.
        assert!(share.detach(OWNER, |_| ()).is_some());
        assert_eq!(share.dirty(), 0);
        let _ = recorder.drain();

        // Giving the claim back restores everything, which is what the
        // `CURLSHE_IN_USE` path does.
        share.release_claim();
        assert!(share.is_valid());
        assert_eq!(share.magic(), Share::GOOD_MAGIC);
        assert_eq!(share.setopt(ShareOption::Share(4)), CURLSHcode::Ok);
        assert!(share.attach(OWNER, |_| ()).is_some());
        assert!(share.detach(OWNER, |_| ()).is_some());
        assert_eq!(share.cleanup(), CURLSHcode::Ok);

        // And once retired, even the notifications stop.
        assert_eq!(
            share.lock(OWNER, LockData::Dns, LockAccess::Single),
            CURLSHcode::Invalid
        );
        assert_eq!(share.unlock(OWNER, LockData::Dns), CURLSHcode::Invalid);
        assert!(share.detach(OWNER, |_| ()).is_none());
        recorder.assert_balanced();
    }

    /// The three lifecycle phases are exactly the three tag values, and the
    /// middle one has no C counterpart.
    ///
    /// `CURL_GOOD_SHARE` is `0x7e117a1e` (`lib/curl_share.h:36`) and
    /// `lib/curl_share.c:263` writes zero; the claim's tag is the one's
    /// complement of the first, so it can collide with neither.
    #[test]
    fn the_lifecycle_tags_are_distinct_and_classified() {
        assert_eq!(Share::GOOD_MAGIC, 0x7e11_7a1e);
        assert_eq!(ShareCore::CLEANING_MAGIC, 0x81ee_85e1);
        assert_ne!(ShareCore::CLEANING_MAGIC, Share::GOOD_MAGIC);
        assert_ne!(ShareCore::CLEANING_MAGIC, 0);

        assert_eq!(Lifecycle::of(Share::GOOD_MAGIC), Lifecycle::Live);
        assert_eq!(
            Lifecycle::of(ShareCore::CLEANING_MAGIC),
            Lifecycle::Cleaning
        );
        assert_eq!(Lifecycle::of(0), Lifecycle::Dead);
        // Any other value is classified conservatively, exactly as
        // `GOOD_SHARE_HANDLE` classifies it.
        assert_eq!(Lifecycle::of(0xdead_beef), Lifecycle::Dead);

        assert!(Lifecycle::Live.is_present());
        assert!(Lifecycle::Cleaning.is_present());
        assert!(!Lifecycle::Dead.is_present());
    }

    /// **Every** option is refused while a handle is attached, including the
    /// three that only install callbacks.
    #[test]
    fn every_option_is_refused_while_the_share_is_in_use() {
        let share = Share::new();
        let _ = share.attach(OWNER, |_| ());
        assert!(share.is_in_use());
        for option in [
            ShareOption::None,
            ShareOption::Share(LockData::Cookie.as_i32()),
            ShareOption::Share(LockData::Dns.as_i32()),
            ShareOption::Unshare(LockData::Dns.as_i32()),
            ShareOption::Unshare(LockData::Psl.as_i32()),
            ShareOption::LockFunc(None),
            ShareOption::LockFunc(Some(Arc::new(|_, _, _, _| {}))),
            ShareOption::UnlockFunc(None),
            ShareOption::UnlockFunc(Some(Arc::new(|_, _, _| {}))),
            ShareOption::UserData(USERDATA),
            ShareOption::Last,
            ShareOption::Unknown(9),
        ] {
            let description = format!("{option:?}");
            assert_eq!(
                share.setopt(option),
                CURLSHcode::InUse,
                "{description} was not refused"
            );
        }
        // Nothing was applied, not even the unconditional clear of quirk 1.
        assert_eq!(share.specifier().bits(), LockData::Share.bit());

        // And the refusal lifts when the last handle detaches.
        let _ = share.detach(OWNER, |_| ());
        assert_eq!(share.setopt(ShareOption::Share(3)), CURLSHcode::Ok);
    }

    // `curl_share_cleanup` (`lib/curl_share.c:221-267`)

    /// Cleanup refuses while a handle is attached, leaves the object usable,
    /// and still delivers the unlock notification.
    ///
    /// `lib/curl_share.c:231-235`. Three separate obligations, and the third
    /// is the one that is easy to forget: a failed cleanup that skips the
    /// unlock leaves the application's mutex held for the rest of the process.
    #[test]
    fn cleanup_refuses_while_in_use_and_leaves_the_share_intact() {
        let (share, recorder) = recorded();
        assert_eq!(share.setopt(ShareOption::Share(3)), CURLSHcode::Ok);
        let _ = share.attach(OWNER, |_| ());
        let _ = recorder.drain();

        assert_eq!(share.cleanup(), CURLSHcode::InUse);

        // C: :227-229 then :232-233 -- a lock with a NULL handle, then its
        // matching unlock, and nothing else.
        assert_eq!(
            recorder.drain(),
            vec![
                Event::Lock(
                    LockOwner::NONE,
                    LockData::Share,
                    LockAccess::Single,
                    USERDATA
                ),
                Event::Unlock(LockOwner::NONE, LockData::Share, USERDATA),
            ]
        );
        recorder.assert_balanced();

        // The object survived and is still usable: the tag is intact, the
        // stores are reachable, and the count is unchanged.
        assert!(share.is_valid());
        assert_eq!(share.dirty(), 1);
        assert!(share.dnscache(OWNER).is_some());

        // Once the handle detaches, cleanup succeeds.
        let _ = share.detach(OWNER, |_| ());
        let _ = recorder.drain();
        assert_eq!(share.cleanup(), CURLSHcode::Ok);
        assert!(!share.is_valid());
        recorder.assert_balanced();
    }

    /// The refusal is delivered with no callbacks installed at all.
    ///
    /// Both notifications in `lib/curl_share.c:221-267` are guarded --
    /// `if(share->lockfunc)` at `:227` and `if(share->unlockfunc)` at `:232`
    /// and `:261` -- so a share that never received `CURLSHOPT_LOCKFUNC`
    /// still reaches `:234`'s `return CURLSHE_IN_USE` and still declines to
    /// free. This is the sequence `docs/examples/shared-connection-cache.c`
    /// would take if its two `curl_share_setopt` callback calls were removed,
    /// and the un-notified path must be as safe as the notified one.
    #[test]
    fn cleanup_refuses_while_in_use_with_no_callbacks_installed() {
        let share = Share::new();
        assert_eq!(share.setopt(ShareOption::Share(3)), CURLSHcode::Ok);
        let _ = share.attach(OWNER, |_| ());

        assert_eq!(share.cleanup(), CURLSHcode::InUse);

        // Refused, and therefore still whole: C never reaches `:263`'s
        // `share->magic = 0` on this path, so the handle stays good.
        assert!(share.is_valid());
        assert_eq!(share.magic(), Share::GOOD_MAGIC);
        assert_eq!(share.dirty(), 1);
        assert!(share.dnscache(OWNER).is_some());

        let _ = share.detach(OWNER, |_| ());
        assert_eq!(share.cleanup(), CURLSHcode::Ok);
        assert!(!share.is_valid());
    }

    /// A successful cleanup clears the tag, and a second one reports
    /// `CURLSHE_INVALID` without delivering anything.
    ///
    /// `lib/curl_share.c:263` zeroes the tag immediately before the free, and
    /// `:224-225` is what makes the second call safe rather than a crash. Note
    /// that the invalid path takes no lock and therefore delivers no
    /// notification at all.
    #[test]
    fn a_second_cleanup_is_invalid_and_silent() {
        let (share, recorder) = recorded();
        assert_eq!(share.cleanup(), CURLSHcode::Ok);
        assert_eq!(share.magic(), 0);
        assert!(!share.is_valid());
        let _ = recorder.drain();

        assert_eq!(share.cleanup(), CURLSHcode::Invalid);
        assert!(recorder.events().is_empty(), "the invalid path is silent");
        recorder.assert_balanced();
    }

    /// A torn-down share refuses everything.
    ///
    /// `lib/curl_share.c:68-69` and `:224-225` both test the tag first, and
    /// the store accessors here test it too so that a stale share cannot
    /// deliver a callback.
    #[test]
    fn a_torn_down_share_refuses_every_operation() {
        let (share, recorder) = recorded();
        assert_eq!(share.cleanup(), CURLSHcode::Ok);
        let _ = recorder.drain();

        assert_eq!(share.setopt(ShareOption::Share(3)), CURLSHcode::Invalid);
        assert_eq!(share.setopt(ShareOption::Unshare(3)), CURLSHcode::Invalid);
        assert_eq!(
            share.setopt(ShareOption::UserData(USERDATA)),
            CURLSHcode::Invalid
        );
        assert_eq!(
            share.lock(OWNER, LockData::Dns, LockAccess::Single),
            CURLSHcode::Invalid
        );
        assert_eq!(share.unlock(OWNER, LockData::Dns), CURLSHcode::Invalid);
        assert!(share.dnscache(OWNER).is_none());
        assert!(share.ssl_scache(OWNER).is_none());
        assert!(share.pool(OWNER).is_none());
        assert!(recorder.events().is_empty(), "nothing was delivered");
    }

    /// Cleanup tears down all six stores, and does so even for data whose
    /// specifier bit is clear.
    #[test]
    fn cleanup_tears_down_every_store() {
        let share = Share::new();
        for kind in [2, 3, 4, 5, 6, 7] {
            let _ = share.setopt(ShareOption::Share(kind));
        }
        assert_eq!(share.cleanup(), CURLSHcode::Ok);

        // Reading the slots directly, because every accessor now refuses on
        // the cleared tag -- which is itself the point of the tag.
        assert!(share
            .dnscache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_empty());
        assert!(share
            .ssl_scache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_none());
        assert!(share
            .cpool
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_none());
        #[cfg(feature = "cookies")]
        {
            assert!(share
                .cookies
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .is_none());
            assert!(!share
                .psl
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .has_list());
        }
        #[cfg(feature = "hsts")]
        assert!(share
            .hsts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_none());
    }

    /// The connection pool's teardown is gated on its bit, exactly as the C's
    /// is.
    #[test]
    fn the_pool_is_destroyed_only_while_its_bit_is_set() {
        let share = Share::new();
        assert_eq!(share.setopt(ShareOption::Share(5)), CURLSHcode::Ok);
        assert_eq!(share.setopt(ShareOption::Unshare(5)), CURLSHcode::Ok);
        assert_eq!(share.cleanup(), CURLSHcode::Ok);
        assert!(
            share
                .cpool
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .is_some(),
            "lib/curl_share.c:237-239 skips a pool whose bit is clear"
        );

        let share = Share::new();
        assert_eq!(share.setopt(ShareOption::Share(5)), CURLSHcode::Ok);
        assert_eq!(share.cleanup(), CURLSHcode::Ok);
        assert!(share
            .cpool
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_none());
    }

    /// The shared pool is **destroyed** at cleanup -- every connection is asked
    /// to disconnect -- and the destroy runs inside the connect notification.
    ///
    /// `Curl_cpool_destroy` (`lib/conncache.c:231-254`) is not a free: it moves
    /// every remaining connection through `cpool_discard_conn`, which sends the
    /// protocol farewell (`lib/cshutdn.c:62`), and it does so between
    /// `CPOOL_LOCK` and `CPOOL_UNLOCK` (`lib/conncache.c:41-60`) -- a
    /// `CURL_LOCK_DATA_CONNECT` / `CURL_LOCK_ACCESS_SINGLE` pair naming
    /// `cpool->idata`, the admin handle. Dropping the pool instead would
    /// reclaim the same memory while asking no scheme anything and telling the
    /// application nothing, so this test asserts both halves: the handler was
    /// called, and the bracket was delivered.
    ///
    /// The handle the connect notification names is [`LockOwner::NONE`] rather
    /// than a pointer, because there is no easy handle to name:
    /// `crate::easy` has no handle type at this commit, and
    /// `curl_share_cleanup` already delivers its own notifications with
    /// `NULL`
    /// (`lib/curl_share.c:228`). Fabricating a non-null value an application
    /// might dereference would be worse than the honest null.
    #[test]
    fn cleanup_destroys_the_shared_pool_through_the_retained_admin() {
        let (share, recorder) = recorded();
        assert_eq!(share.setopt(ShareOption::Share(5)), CURLSHcode::Ok);
        let calls: Arc<Mutex<Vec<bool>>> = Arc::new(Mutex::new(Vec::new()));

        // Populate it the way `crate::protocols` will.
        {
            let clock = SystemClock;
            let mut cx = CallCtx::new(&clock);
            let mut guard = share.pool(OWNER).expect("connections are shared");
            let pool = guard.as_mut().expect("a set bit implies a pool");
            for destination in ["a:80", "b:80"] {
                pool.add(&mut cx, connection(destination, Some(&calls)));
            }
            assert_eq!(pool.count(), 2);
        }
        let _ = recorder.drain();

        assert_eq!(share.cleanup(), CURLSHcode::Ok);

        // Both connections were asked to disconnect, with `dead = false`:
        // `cpool_discard_conn(cpool, idata, conn, FALSE)`
        // (`lib/conncache.c:247`) passes `aborted = FALSE`, so a farewell is
        // sent rather than suppressed.
        assert_eq!(
            calls
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .as_slice(),
            [false, false],
            "a destroyed pool asks every scheme; a dropped one asks none"
        );

        // C: :227-229, then the pool's own bracket, then :261-262.
        assert_eq!(
            recorder.drain(),
            vec![
                Event::Lock(
                    LockOwner::NONE,
                    LockData::Share,
                    LockAccess::Single,
                    USERDATA
                ),
                Event::Lock(
                    LockOwner::NONE,
                    LockData::Connect,
                    LockAccess::Single,
                    USERDATA
                ),
                Event::Unlock(LockOwner::NONE, LockData::Connect, USERDATA),
                Event::Unlock(LockOwner::NONE, LockData::Share, USERDATA),
            ],
            "lib/conncache.c:243-252 nested inside lib/curl_share.c:227-262"
        );
        recorder.assert_balanced();
        assert!(share
            .cpool
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_none());
    }

    /// A pool whose bit was cleared keeps its connections, because the C skips
    /// it.
    ///
    /// The other half of `lib/curl_share.c:237-239`. `CURLSHOPT_UNSHARE` clears
    /// the bit without destroying the pool (`:150`, `:187-188`), so no scheme
    /// is asked anything and no notification is delivered -- and in the C the
    /// pool's members are then leaked at `:264`. Rust's drop glue reclaims them
    /// instead, which is the one divergence [`Share::teardown`] records.
    #[test]
    fn an_unshared_pool_is_neither_destroyed_nor_notified() {
        let (share, recorder) = recorded();
        assert_eq!(share.setopt(ShareOption::Share(5)), CURLSHcode::Ok);
        let calls: Arc<Mutex<Vec<bool>>> = Arc::new(Mutex::new(Vec::new()));
        {
            let clock = SystemClock;
            let mut cx = CallCtx::new(&clock);
            let mut guard = share.pool(OWNER).expect("connections are shared");
            let pool = guard.as_mut().expect("a set bit implies a pool");
            pool.add(&mut cx, connection("a:80", Some(&calls)));
        }
        assert_eq!(share.setopt(ShareOption::Unshare(5)), CURLSHcode::Ok);
        let _ = recorder.drain();

        assert_eq!(share.cleanup(), CURLSHcode::Ok);

        assert!(
            calls
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .is_empty(),
            "lib/curl_share.c:237-239 skips a pool whose bit is clear"
        );
        // Only the share's own pair: no connect bracket at all.
        assert_eq!(
            recorder.drain(),
            vec![
                Event::Lock(
                    LockOwner::NONE,
                    LockData::Share,
                    LockAccess::Single,
                    USERDATA
                ),
                Event::Unlock(LockOwner::NONE, LockData::Share, USERDATA),
            ]
        );
        // And the pool itself survived the teardown, connection included.
        let slot = share.cpool.lock().unwrap_or_else(PoisonError::into_inner);
        assert_eq!(
            slot.as_ref().expect("the pool was not destroyed").count(),
            1
        );
        drop(slot);
        recorder.assert_balanced();
    }

    /// The retained admin context empties a pool through the disposal path.
    ///
    /// `Curl_cpool_destroy`'s loop (`lib/conncache.c:242-249`) takes the first
    /// connection out and discards it until none is left, and its guard --
    /// `if(cpool && cpool->initialised && cpool->idata)` (`:233`) -- is why the
    /// admin context has to be retained: a pool with no `idata` is a pool the C
    /// does not destroy at all.
    ///
    /// This also exercises the driver [`ShareAdmin::destroy_pool`] chooses. The
    /// connections carry a disconnect handler and the admin reports itself
    /// internal, which is exactly the pair that reaches
    /// `tokio::time::timeout` in `run_conn_handler`; the test runs in a plain
    /// `#[test]` with no ambient runtime, so it passes only because the driver
    /// supplies a time driver of its own.
    #[test]
    fn the_admin_context_destroys_a_pool_rather_than_dropping_it() {
        let mut admin = ShareAdmin::new();
        let clock = SystemClock;
        let mut pool = ConnectionPool::new();
        let calls: Arc<Mutex<Vec<bool>>> = Arc::new(Mutex::new(Vec::new()));
        {
            let mut cx = CallCtx::new(&clock);
            for destination in ["a:80", "a:80", "b:80"] {
                pool.add(&mut cx, connection(destination, Some(&calls)));
            }
        }
        assert_eq!(pool.count(), 3);
        assert_eq!(pool.destinations(), 2);

        admin.destroy_pool(&mut pool);

        assert!(pool.is_empty(), "lib/conncache.c:242-249 empties the pool");
        assert_eq!(pool.destinations(), 0);
        assert_eq!(
            calls.lock().unwrap_or_else(PoisonError::into_inner).len(),
            3,
            "every connection was asked to disconnect"
        );
    }

    /// The admin answers the eleven questions the C's admin handle answers.
    ///
    /// `share->admin` is an internal handle with no multi handle
    /// (`lib/curl_share.c:40-47`), and every answer follows from that pair.
    /// [`ShareAdmin`] tabulates the C locator for each; this pins them so a
    /// later edit cannot quietly turn the share's teardown into a multi
    /// handle's.
    #[test]
    fn the_admin_reports_an_internal_handle_with_no_multi_handle() {
        let mut host = ShareAdminHost;

        // C: lib/cshutdn.c:139 and :157 -- no multi handle, so no admin
        // substitution and no multi notifications.
        assert!(!host.has_admin());
        assert!(!host.has_multi());
        // C: lib/curl_share.c:47 -- `share->admin->state.internal = TRUE`,
        // which is what caps a blocking disconnect handler.
        assert!(host.is_internal(ShutdownHandle::Caller));
        assert!(host.is_internal(ShutdownHandle::Admin));
        // C: lib/cshutdn.c:411 -- no socket callback, so no event state.
        assert!(!host.socket_cb_installed());
        // C: lib/multihandle.h:152 -- zero is "unlimited".
        assert_eq!(host.max_total_connections(), 0);

        // The four that act on a multi handle are no-ops, and the assessment
        // succeeds so that a connection stays on the ordinary path.
        let clock = SystemClock;
        let mut cx = CallCtx::new(&clock);
        let mut chains = FilterChains::new(None);
        let id = ConnId::new(1);
        assert_eq!(
            host.assess_conn(ShutdownHandle::Admin, id, &mut cx, &mut chains),
            CURLMcode::Ok
        );
        host.conn_done(ShutdownHandle::Admin, id, &mut cx, &mut chains);
        host.connchanged();
        host.expire(ShutdownHandle::Admin, 0, TimerId::Shutdown);
        host.set_operation_timeout_ms(ShutdownHandle::Admin, 2_000);
        host.restart_operation_timing(ShutdownHandle::Admin);
    }

    /// Cleanup's notifications ignore the specifier, unlike every other
    /// notification in this module.
    ///
    /// `lib/curl_share.c:227` and `:261` test only `if(share->lockfunc)` and
    /// `if(share->unlockfunc)`, where `Curl_share_lock` tests the bit as well
    /// (`:277`). The difference is reachable, because
    /// `CURLSHOPT_UNSHARE` with `CURL_LOCK_DATA_SHARE` clears bit 1 -- quirk 1
    /// -- and this test drives exactly that sequence.
    #[test]
    fn cleanup_notifies_even_with_the_share_bit_cleared() {
        let (share, recorder) = recorded();
        assert_eq!(
            share.setopt(ShareOption::Unshare(LockData::Share.as_i32())),
            CURLSHcode::BadOption
        );
        assert_eq!(share.specifier(), Specifier::EMPTY);
        let _ = recorder.drain();

        // `lock` consults the bit and therefore stays silent.
        assert_eq!(
            share.lock(OWNER, LockData::Share, LockAccess::Single),
            CURLSHcode::Ok
        );
        assert_eq!(share.unlock(OWNER, LockData::Share), CURLSHcode::Ok);
        assert!(
            recorder.events().is_empty(),
            "Curl_share_lock:277 gates on the bit"
        );

        // `cleanup` does not, so both notifications are delivered.
        assert_eq!(share.cleanup(), CURLSHcode::Ok);
        assert_eq!(
            recorder.drain(),
            vec![
                Event::Lock(
                    LockOwner::NONE,
                    LockData::Share,
                    LockAccess::Single,
                    USERDATA
                ),
                Event::Unlock(LockOwner::NONE, LockData::Share, USERDATA),
            ]
        );
        recorder.assert_balanced();
    }

    // The notification contract

    /// `Curl_share_lock` delivers nothing for a datum that is not shared, and
    /// still succeeds.
    ///
    /// `lib/curl_share.c:277-283`, whose comment at `:281` is *"else if we do
    /// not share this, pretend successful lock"*.
    #[test]
    fn locking_an_unshared_datum_is_silent_and_successful() {
        let (share, recorder) = recorded();
        for kind in LockData::VARIANTS {
            if *kind == LockData::Share {
                continue;
            }
            assert_eq!(
                share.lock(OWNER, *kind, LockAccess::Single),
                CURLSHcode::Ok,
                "{}",
                kind.c_name()
            );
            assert_eq!(share.unlock(OWNER, *kind), CURLSHcode::Ok);
        }
        assert!(recorder.events().is_empty());
        recorder.assert_balanced();
    }

    /// A shared datum delivers exactly the triple the C delivers.
    ///
    /// The owner is the caller's handle, the datum is the one asked for, and
    /// the access is whatever was requested -- `lib/curl_share.c:279`. The
    /// unlock carries no access, because `curl_unlock_function` has no such
    /// parameter.
    #[test]
    fn a_shared_datum_delivers_the_triple_the_c_delivers() {
        let (share, recorder) = recorded();
        assert_eq!(share.setopt(ShareOption::Share(3)), CURLSHcode::Ok);
        let _ = recorder.drain();

        for access in [LockAccess::None, LockAccess::Shared, LockAccess::Single]
        {
            assert_eq!(
                share.lock(OWNER, LockData::Dns, access),
                CURLSHcode::Ok
            );
            assert_eq!(share.unlock(OWNER, LockData::Dns), CURLSHcode::Ok);
            assert_eq!(
                recorder.drain(),
                vec![
                    Event::Lock(OWNER, LockData::Dns, access, USERDATA),
                    Event::Unlock(OWNER, LockData::Dns, USERDATA),
                ]
            );
        }
        recorder.assert_balanced();
    }

    /// Each store accessor delivers one exclusive lock on entry and one unlock
    /// on drop.
    #[test]
    fn every_store_accessor_brackets_its_critical_section() {
        let (share, recorder) = recorded();
        for kind in [2, 3, 4, 5, 7] {
            let _ = share.setopt(ShareOption::Share(kind));
        }
        let _ = recorder.drain();

        /// Drives one accessor and returns what the callbacks saw.
        macro_rules! bracket {
            ($kind:expr, $accessor:expr) => {{
                let guard = $accessor.expect("shared");
                assert_eq!(
                    recorder.drain(),
                    vec![Event::Lock(
                        OWNER,
                        $kind,
                        LockAccess::Single,
                        USERDATA
                    )],
                    "entering {}",
                    $kind.c_name()
                );
                drop(guard);
                assert_eq!(
                    recorder.drain(),
                    vec![Event::Unlock(OWNER, $kind, USERDATA)],
                    "leaving {}",
                    $kind.c_name()
                );
            }};
        }

        bracket!(LockData::Dns, share.dnscache(OWNER));
        bracket!(LockData::SslSession, share.ssl_scache(OWNER));
        bracket!(LockData::Connect, share.pool(OWNER));
        #[cfg(feature = "cookies")]
        bracket!(LockData::Cookie, share.cookies(OWNER));
        #[cfg(feature = "hsts")]
        bracket!(LockData::Hsts, share.hsts(OWNER));
        recorder.assert_balanced();
    }

    /// No datum is ever locked twice without an intervening release, and the
    /// one nesting the C performs is of two different data.
    ///
    /// `tests/libtest/lib506.c:71-76` prints `"lock: double locked %s"` and
    /// fails when the C nests a lock for one datum; the recorder used here
    /// applies the same rule. `lib/cookie.c` nests `CURL_LOCK_DATA_COOKIE`
    /// around `Curl_psl_use`'s `CURL_LOCK_DATA_PSL`, which is two data and is
    /// therefore permitted -- and is exercised here so that the ordering is
    /// under test rather than assumed.
    #[test]
    fn no_datum_is_ever_locked_twice_and_the_c_nesting_still_works() {
        let (share, recorder) = recorded();
        for kind in [2, 3, 4, 5, 6, 7] {
            let _ = share.setopt(ShareOption::Share(kind));
        }
        let _ = recorder.drain();

        // Every accessor, in sequence: each brackets its own datum.
        for _ in 0..3 {
            drop(share.dnscache(OWNER));
            drop(share.ssl_scache(OWNER));
            drop(share.pool(OWNER));
        }
        recorder.assert_balanced();

        // The C's own nesting: cookies outside, the Public Suffix List inside.
        #[cfg(feature = "cookies")]
        {
            let clock = TestClock::new(CurlTime::new(1_000, 0));
            let source = MemoryPslSource::latest(PSL_LIST);
            let jar = share.cookies(OWNER).expect("shared");
            let psl = share.psl_use(OWNER, &clock, &source).expect("a list");
            drop(psl);
            drop(jar);
            recorder.assert_balanced();
        }
    }

    /// The callbacks are clearable with a null pointer, and their absence is
    /// tolerated.
    #[test]
    fn the_callbacks_are_clearable_and_their_absence_is_tolerated() {
        let (share, recorder) = recorded();
        assert_eq!(share.setopt(ShareOption::Share(3)), CURLSHcode::Ok);
        let _ = recorder.drain();

        drop(share.dnscache(OWNER));
        assert_eq!(recorder.drain().len(), 2, "both callbacks were installed");

        // Clear the lock callback only. The unlock callback still fires, which
        // is the asymmetry the C's two independent tests permit.
        assert_eq!(share.setopt(ShareOption::LockFunc(None)), CURLSHcode::Ok);
        drop(share.dnscache(OWNER));
        assert_eq!(
            recorder.drain(),
            vec![Event::Unlock(OWNER, LockData::Dns, USERDATA)]
        );

        // Clear the unlock callback too: now nothing fires and everything
        // still works.
        assert_eq!(share.setopt(ShareOption::UnlockFunc(None)), CURLSHcode::Ok);
        drop(share.dnscache(OWNER));
        assert!(recorder.drain().is_empty());
        assert_eq!(share.cleanup(), CURLSHcode::Ok);

        // A share that never had callbacks behaves the same way.
        let bare = Share::new();
        assert_eq!(bare.setopt(ShareOption::Share(3)), CURLSHcode::Ok);
        assert!(bare.dnscache(OWNER).is_some());
        assert_eq!(bare.cleanup(), CURLSHcode::Ok);
    }

    /// The user pointer reaches both callbacks and survives a callback change.
    #[test]
    fn the_user_pointer_is_independent_of_the_callbacks() {
        let (share, recorder) = recorded();
        assert_eq!(share.setopt(ShareOption::Share(3)), CURLSHcode::Ok);

        let replacement = ShareUserData::from_bits(0x4242);
        assert_eq!(
            share.setopt(ShareOption::UserData(replacement)),
            CURLSHcode::Ok
        );
        let _ = recorder.drain();
        drop(share.dnscache(OWNER));
        assert_eq!(
            recorder.drain(),
            vec![
                Event::Lock(
                    OWNER,
                    LockData::Dns,
                    LockAccess::Single,
                    replacement
                ),
                Event::Unlock(OWNER, LockData::Dns, replacement),
            ]
        );
        recorder.assert_balanced();

        // Clearing a callback leaves the pointer alone.
        //
        // The balance checker is deliberately not consulted past this point.
        // The C tests `if(share->lockfunc)` and `if(share->unlockfunc)`
        // separately (`lib/curl_share.c:227` against `:232`, `:278` against
        // `:294`), so an application that clears one and not the other gets an
        // unbalanced notification stream by its own request. Reproducing that
        // is the point of this test; `lib506.c`'s detector would flag it, which
        // is why it is only asserted where both callbacks are installed.
        assert_eq!(share.setopt(ShareOption::LockFunc(None)), CURLSHcode::Ok);
        drop(share.dnscache(OWNER));
        assert_eq!(
            recorder.drain(),
            vec![Event::Unlock(OWNER, LockData::Dns, replacement)]
        );
    }

    // The Public Suffix List: the only shared-access datum

    /// A Public Suffix List with one rule per section, which is the minimum
    /// `publicsuffix` accepts: the section markers are load-bearing, because
    /// the parser stores no rule until it has seen one.
    #[cfg(feature = "cookies")]
    const PSL_LIST: &str = concat!(
        "// ===BEGIN ICANN DOMAINS===\n",
        "com\n",
        "co.uk\n",
        "// ===END ICANN DOMAINS===\n",
    );

    /// A fresh cache takes the shared lock once and keeps it until the guard
    /// is dropped.
    #[cfg(feature = "cookies")]
    #[test]
    fn a_fresh_public_suffix_list_takes_the_shared_lock_once() {
        let (share, recorder) = recorded();
        assert_eq!(share.setopt(ShareOption::Share(6)), CURLSHcode::Ok);
        let clock = TestClock::new(CurlTime::new(1_000, 0));
        let source = MemoryPslSource::latest(PSL_LIST);
        let _ = recorder.drain();

        // The first use is a refresh, because a zeroed cache is stale.
        let first = share.psl_use(OWNER, &clock, &source).expect("a list");
        drop(first);
        let _ = recorder.drain();

        // The second is not: the deadline is 72 hours out.
        let guard = share.psl_use(OWNER, &clock, &source).expect("a list");
        assert_eq!(
            recorder.drain(),
            vec![Event::Lock(
                OWNER,
                LockData::Psl,
                LockAccess::Shared,
                USERDATA
            )],
            "a fresh cache performs no upgrade"
        );
        assert!(guard.has_list());
        assert!(guard.list().is_some(), "the list survives the return");
        drop(guard);
        assert_eq!(
            recorder.drain(),
            vec![Event::Unlock(OWNER, LockData::Psl, USERDATA)]
        );
        recorder.assert_balanced();
    }

    /// A stale cache performs the C's five-step upgrade and ends holding a
    /// shared lock.
    #[cfg(feature = "cookies")]
    #[test]
    fn a_stale_public_suffix_list_performs_the_upgrade_sequence() {
        let (share, recorder) = recorded();
        assert_eq!(share.setopt(ShareOption::Share(6)), CURLSHcode::Ok);
        let clock = TestClock::new(CurlTime::new(1_000, 0));
        let source = MemoryPslSource::latest(PSL_LIST);
        let _ = recorder.drain();

        let guard = share.psl_use(OWNER, &clock, &source).expect("a list");
        assert_eq!(
            recorder.drain(),
            vec![
                Event::Lock(OWNER, LockData::Psl, LockAccess::Shared, USERDATA),
                Event::Unlock(OWNER, LockData::Psl, USERDATA),
                Event::Lock(OWNER, LockData::Psl, LockAccess::Single, USERDATA),
                Event::Unlock(OWNER, LockData::Psl, USERDATA),
                Event::Lock(OWNER, LockData::Psl, LockAccess::Shared, USERDATA),
            ],
            "lib/psl.c:51, :55, :58, :88, :89"
        );
        // The deadline moved 72 hours out -- `PSL_TTL`, `lib/psl.c:72-73`.
        assert_eq!(guard.expires(), 1_000 + 72 * 3600);
        assert!(guard.is_dynamic(), "the refreshable tier supplied the list");
        drop(guard);
        assert_eq!(
            recorder.drain(),
            vec![Event::Unlock(OWNER, LockData::Psl, USERDATA)]
        );
        recorder.assert_balanced();

        // And it goes stale again once the deadline passes.
        clock.advance(std::time::Duration::from_secs(72 * 3600 + 1));
        let _ = recorder.drain();
        let guard = share.psl_use(OWNER, &clock, &source).expect("a list");
        assert_eq!(recorder.drain().len(), 5, "a second upgrade");
        drop(guard);
        recorder.assert_balanced();
    }

    /// Nothing is mutated while the application has been told
    /// `CURL_LOCK_ACCESS_SHARED`.
    ///
    /// This is the whole point of the guard being a reader. `Curl_psl_use`
    /// refreshes only between `lib/psl.c:58` and `:88`, under
    /// `CURL_LOCK_ACCESS_SINGLE`; from `:89` onwards it holds a shared lock,
    /// reads `pslcache->psl` at `:91` and returns it as a `const psl_ctx_t *`
    /// at `:94`. So once a caller holds the returned list:
    ///
    /// * the cache's state cannot change under it -- not even when the
    ///   deadline passes while the guard is alive, which this test forces;
    /// * no further notification is delivered, because no phase change
    ///   happens; and
    /// * a second reader still fits, which is the concurrency the C has
    ///   between two `Curl_psl_use` callers and which a writer would have
    ///   destroyed.
    ///
    /// The last point is asserted through the lock itself rather than by
    /// taking a second guard, because a second guard would deliver a second
    /// `CURL_LOCK_DATA_PSL` notification and the recorder -- modelled on
    /// `lib506.c`'s strict per-kind detector -- would report it as a double
    /// lock.
    #[cfg(feature = "cookies")]
    #[test]
    fn a_held_public_suffix_list_is_never_refreshed_under_the_shared_lock() {
        let (share, recorder) = recorded();
        assert_eq!(share.setopt(ShareOption::Share(6)), CURLSHcode::Ok);
        let clock = TestClock::new(CurlTime::new(1_000, 0));
        let source = MemoryPslSource::latest(PSL_LIST);

        // One refresh, so that what follows starts from a fresh cache.
        drop(share.psl_use(OWNER, &clock, &source).expect("a list"));
        let _ = recorder.drain();

        let guard = share.psl_use(OWNER, &clock, &source).expect("a list");
        let deadline = guard.expires();
        assert_eq!(deadline, 1_000 + 72 * 3600, "lib/psl.c:72-73");

        // The guard holds a READER: another reader fits, a writer does not.
        assert!(
            share.psl.try_read().is_ok(),
            "lib/psl.c:89 holds CURL_LOCK_ACCESS_SHARED, so readers still fit"
        );
        assert!(
            share.psl.try_write().is_err(),
            "and the cache is genuinely locked for the guard's lifetime"
        );

        // Go stale underneath the held guard. The C cannot refresh here and
        // neither can this: `list` reads `pslcache->psl` and nothing else.
        clock.advance(std::time::Duration::from_secs(72 * 3600 + 1));
        assert!(guard.list().is_some(), "the selection survives the return");
        assert!(guard.list().is_some(), "and repeats without side effects");
        assert_eq!(guard.expires(), deadline, "no refresh happened");
        assert!(guard.is_dynamic());
        assert_eq!(
            recorder.events(),
            vec![Event::Lock(
                OWNER,
                LockData::Psl,
                LockAccess::Shared,
                USERDATA
            )],
            "one shared phase, so no notification beyond its own lock"
        );

        drop(guard);
        assert_eq!(
            recorder.drain(),
            vec![
                Event::Lock(OWNER, LockData::Psl, LockAccess::Shared, USERDATA),
                Event::Unlock(OWNER, LockData::Psl, USERDATA),
            ]
        );
        recorder.assert_balanced();

        // The next call is the one that refreshes, because it can take the
        // exclusive phase: five notifications, per `lib/psl.c:51-89`.
        let guard = share.psl_use(OWNER, &clock, &source).expect("a list");
        assert_eq!(recorder.drain().len(), 5);
        assert!(guard.expires() > deadline, "now it moved");
        drop(guard);
        recorder.assert_balanced();
    }

    /// A source that cannot produce a list releases the lock and yields
    /// [`None`].
    ///
    /// `lib/psl.c:92-93`: `if(!psl) Curl_share_unlock(...)`, then
    /// `return psl`. The caller owes nothing, and must fail closed exactly as
    /// `lib/cookie.c:801-802` does.
    #[cfg(feature = "cookies")]
    #[test]
    fn a_public_suffix_list_that_cannot_load_releases_the_lock() {
        let (share, recorder) = recorded();
        assert_eq!(share.setopt(ShareOption::Share(6)), CURLSHcode::Ok);
        let clock = TestClock::new(CurlTime::new(1_000, 0));
        let source = MemoryPslSource::latest("not a list at all");
        let _ = recorder.drain();

        assert!(share.psl_use(OWNER, &clock, &source).is_none());
        // Five notifications from the failed upgrade, plus the release at
        // `:93`, so the count is even and nothing is left held.
        assert_eq!(recorder.drain().len(), 6);
        recorder.assert_balanced();
    }

    /// The Public Suffix List is unreachable while its bit is clear.
    ///
    /// `lib/psl.c:48-49`'s `if(!pslcache) return NULL;` reached by way of
    /// `lib/setopt.c:1545-1546`, which points a handle at the share's cache
    /// only when the `CURL_LOCK_DATA_PSL` bit is set.
    #[cfg(feature = "cookies")]
    #[test]
    fn the_public_suffix_list_is_unreachable_while_its_bit_is_clear() {
        let (share, recorder) = recorded();
        let clock = TestClock::new(CurlTime::new(1_000, 0));
        let source = MemoryPslSource::latest(PSL_LIST);

        assert!(share.psl_use(OWNER, &clock, &source).is_none());
        assert!(recorder.events().is_empty(), "nothing was delivered");

        // Sharing it makes it reachable; un-sharing it -- which reports a bad
        // option, per quirk 2 -- makes it unreachable again.
        assert_eq!(share.setopt(ShareOption::Share(6)), CURLSHcode::Ok);
        assert!(share.psl_use(OWNER, &clock, &source).is_some());
        assert_eq!(
            share.setopt(ShareOption::Unshare(6)),
            CURLSHcode::BadOption
        );
        assert!(share.psl_use(OWNER, &clock, &source).is_none());
        recorder.assert_balanced();
    }

    // Robustness: poisoning, formatting and the measured thread-safety state

    /// A panic that poisons a store lock does not break the share.
    #[test]
    fn a_poisoned_store_lock_is_recovered_rather_than_propagated() {
        let (share, recorder) = recorded();
        assert_eq!(share.setopt(ShareOption::Share(3)), CURLSHcode::Ok);
        let _ = recorder.drain();

        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let outcome =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _guard = share.dnscache(OWNER).expect("shared");
                panic!("poison the DNS cache lock");
            }));
        std::panic::set_hook(previous);
        assert!(outcome.is_err(), "the panic was expected");

        // The unlock notification was still delivered, because `Drop` runs
        // during unwinding.
        assert_eq!(
            recorder.drain(),
            vec![
                Event::Lock(OWNER, LockData::Dns, LockAccess::Single, USERDATA),
                Event::Unlock(OWNER, LockData::Dns, USERDATA),
            ]
        );
        recorder.assert_balanced();

        // And the share is entirely usable afterwards.
        assert!(share.is_valid());
        assert!(share.dnscache(OWNER).is_some());
        assert_eq!(
            share.specifier().bits(),
            LockData::Share.bit() | LockData::Dns.bit()
        );
        assert_eq!(share.setopt(ShareOption::Share(4)), CURLSHcode::Ok);
        assert_eq!(share.cleanup(), CURLSHcode::Ok);
    }

    /// A derived [`fmt::Debug`] would take every lock, so formatting from
    /// inside a critical section -- which is exactly when a diagnostic is
    /// wanted -- would deadlock. Every lock is probed with `try_lock` instead
    /// and reported as `<locked>`.
    #[test]
    fn formatting_a_share_reports_a_held_lock_instead_of_blocking() {
        let share = Share::new();
        assert_eq!(share.setopt(ShareOption::Share(4)), CURLSHcode::Ok);
        let guard = share.ssl_scache(OWNER).expect("shared");
        let text = format!("{share:?}");
        assert!(text.contains("ssl_scache: \"<locked>\""), "{text}");
        assert!(text.contains("valid: true"), "{text}");
        assert!(text.contains("CURL_LOCK_DATA_SSL_SESSION"), "{text}");
        // The guard itself reports which datum it holds and for whom.
        let guard_text = format!("{guard:?}");
        assert!(
            guard_text.contains("CURL_LOCK_DATA_SSL_SESSION"),
            "{guard_text}"
        );
        assert!(guard_text.contains("0x12345678"), "{guard_text}");
        drop(guard);
        let text = format!("{share:?}");
        assert!(text.contains("ssl_scache: \"present\""), "{text}");
    }

    /// [`Share`], [`ShareCore`] and every component of them is `Send + Sync`.
    ///
    /// The first assertion is the one that matters and the one an application
    /// depends on: a `CURLSH` is usable from two threads
    /// (`tests/libtest/lib506.c`, `lib3207.c`), so the type backing it must be
    /// `Send + Sync`. The component assertions below it are diagnosis rather
    /// than contract -- when the first line fails, they say which store
    /// regressed instead of leaving a reader to bisect a type graph.
    ///
    /// [`ShareCore`] is asserted separately because it is the value
    /// `Share::stores` hands another thread, and
    /// `one_share_serves_two_threads_through_its_core` drives one share from
    /// two threads through exactly that handle.
    ///
    /// [`crate::conn::pool::ConnectionPool`] is included deliberately. It was
    /// the one component that did not qualify, because `ConnFilter`,
    /// `ShutdownTimer` and `ProtocolDisconnect` carried no `Send` bound and the
    /// seams behind them held `Rc`. Those bounds now exist, so a change that
    /// reintroduces a thread-affine value anywhere in the connection or TLS
    /// graph fails here -- which is the whole point of asserting the pool
    /// rather than only the share.
    #[test]
    fn the_share_and_every_component_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}

        // The contract.
        assert_send_sync::<Share>();

        // The handle a second thread holds.
        assert_send_sync::<ShareCore>();
        assert_send_sync::<Arc<ShareCore>>();

        // The diagnosis, innermost first.
        //
        // The pool is asserted `Send` and NOT `Sync`, which is exact rather
        // than lenient: its `Box<dyn ConnFilter>`, `Box<dyn ShutdownTimer>`
        // and `Option<Box<dyn ProtocolDisconnect>>` carry `Send` and not
        // `Sync`, because the pool exposes mutation through `&mut self` alone
        // and never needs to be aliased. `Mutex<T>: Sync` needs only
        // `T: Send`, so the field below supplies the `Sync` that `Share`
        // requires. Asserting the pool itself `Sync` would demand a bound
        // nothing uses.
        fn assert_send<T: Send>() {}
        assert_send::<ConnectionPool>();
        assert_send_sync::<Mutex<Option<ConnectionPool>>>();
        assert_send_sync::<LockData>();
        assert_send_sync::<LockAccess>();
        assert_send_sync::<LockOwner>();
        assert_send_sync::<ShareUserData>();
        assert_send_sync::<Specifier>();
        assert_send_sync::<LockCallback>();
        assert_send_sync::<UnlockCallback>();
        assert_send_sync::<Meta>();
        assert_send_sync::<Mutex<Meta>>();
        assert_send_sync::<AtomicU32>();
        assert_send_sync::<Mutex<DnsCache>>();
        assert_send_sync::<Mutex<Option<SessionCache>>>();
        assert_send_sync::<Mutex<Option<ConnectionPool>>>();
        #[cfg(feature = "cookies")]
        assert_send_sync::<Mutex<Option<CookieInfo>>>();
        #[cfg(feature = "cookies")]
        assert_send_sync::<RwLock<PslCache>>();
        #[cfg(feature = "hsts")]
        assert_send_sync::<Mutex<Option<HstsCache>>>();
    }

    /// One share, four threads, the whole of `lib506.c`'s shape.
    ///
    /// This is the half that a `!Sync` share could not express, and it is now
    /// the primary concurrency assertion: `tests/libtest/lib506.c` drives ONE
    /// share from several threads with `CURL_LOCK_DATA_COOKIE` and
    /// `CURL_LOCK_DATA_DNS`, and `lib3207.c` does the same with
    /// `CURL_LOCK_DATA_SSL_SESSION`. Each thread attaches, takes all four
    /// shared stores in turn, and detaches, `ROUNDS` times.
    ///
    /// Three properties are being asserted, and each one would have been
    /// unobservable before:
    ///
    /// * **Soundness under contention.** Every store is reached through this
    ///   module's locks from several threads at once. This is the test Miri and
    ///   the AddressSanitizer gate have something to say about.
    /// * **The callbacks fire exactly as often as the guards are taken.**
    ///   `lib506.c:71-76` carries double-lock detection, so the C's contract is
    ///   that notifications are balanced and never nested for one kind. The
    ///   counter is incremented from every thread and compared against the
    ///   arithmetic, which pins both.
    /// * **No notification is lost or duplicated.** The count is exact, not a
    ///   bound: a lost wake-up or a double delivery moves it.
    ///
    /// The pool is included in the stores taken, deliberately: it is the store
    /// whose `!Send` seams were what made a share thread-affine, so a test that
    /// took the other three and skipped it would pass without touching the
    /// thing that changed.
    #[test]
    fn four_threads_drive_one_shared_handle() {
        const THREADS: usize = 4;
        const ROUNDS: usize = 64;

        let share = Share::new();
        let unlocks = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&unlocks);
        assert_eq!(
            share.setopt(ShareOption::UnlockFunc(Some(Arc::new(
                move |_owner, _kind, _userdata| {
                    counter.fetch_add(1, Ordering::Relaxed);
                }
            )))),
            CURLSHcode::Ok
        );
        // `CURL_LOCK_DATA_DNS` (3), `SSL_SESSION` (4) and `CONNECT` (5) are the
        // three the C's own two-thread tests share.
        for kind in [3, 4, 5] {
            assert_eq!(share.setopt(ShareOption::Share(kind)), CURLSHcode::Ok);
        }

        // `&Share` crossing a scope boundary is the property under test: it
        // compiles only because `Share` is `Sync`.
        let shared: &Share = &share;
        std::thread::scope(|scope| {
            for _ in 0..THREADS {
                scope.spawn(move || {
                    for _ in 0..ROUNDS {
                        // The ownership change runs inside the
                        // `CURL_LOCK_DATA_SHARE` bracket
                        // (`lib/setopt.c:1493-1550`); a handle with nothing
                        // to repoint passes a closure that does nothing, as
                        // `lib/url.c:291-293` does.
                        let _ = shared.attach(OWNER, |_| ());
                        drop(shared.dnscache(OWNER));
                        drop(shared.ssl_scache(OWNER));
                        drop(shared.pool(OWNER));
                        let _ = shared.detach(OWNER, |_| ());
                    }
                });
            }
        });

        // Every easy handle detached again, so the share is free to go.
        assert_eq!(share.dirty(), 0);
        // Five unlocks per round -- attach, three stores, detach -- across
        // every thread. Exact, not a bound.
        assert_eq!(
            unlocks.load(Ordering::Relaxed),
            THREADS * ROUNDS * 5,
            "one notification per guard, from every thread"
        );
        // `cleanup` delivers TWO more, and the second one is the point of
        // sharing `CURL_LOCK_DATA_CONNECT` here. The first is the specifier
        // teardown's own `CURL_LOCK_DATA_SHARE` bracket
        // (`lib/curl_share.c:227-262`); the second is the
        // `CURL_LOCK_DATA_CONNECT` bracket that `CPOOL_LOCK`/`CPOOL_UNLOCK`
        // (`lib/conncache.c:41-60`) place around `Curl_cpool_destroy`
        // (`:243-252`), which runs nested inside the first because the pool bit
        // is set. A share without that bit gets one, which
        // `an_unshared_pool_is_neither_destroyed_nor_notified` pins.
        assert_eq!(share.cleanup(), CURLSHcode::Ok);
        assert_eq!(unlocks.load(Ordering::Relaxed), THREADS * ROUNDS * 5 + 2);
    }

    /// Several threads drive one share each, one callback, and one pool each.
    ///
    /// The owner-side half of `tests/libtest/lib506.c` and `lib3207.c`: the
    /// full lifecycle -- `CURLSHOPT_SHARE`, attach, the store accessors, the
    /// **connection pool**, detach and `curl_share_cleanup` -- performed
    /// concurrently on as many threads as there are shares, with one counter
    /// shared by every callback proving the closures really did run on
    /// different threads. A share per thread is the right shape here and not a
    /// concession: the pool is the one store that cannot be reached from
    /// another thread at all, so exercising it concurrently means exercising
    /// one per thread.
    ///
    /// The other half -- **one** share reached from two threads, which is what
    /// those two C programs actually do -- is
    /// `one_share_serves_two_threads_through_its_core`, which drives the five
    /// kinds that [`ShareCore`] carries through a single [`Arc<ShareCore>`].
    /// Between them the two tests cover every kind: five shared across
    /// threads, and the sixth exercised on its own.
    ///
    /// [`several_threads_drive_one_shared_handle`] adds a third shape: one
    /// share reached from four threads including its **pool**, which only
    /// compiles because [`Share`] is `Sync`. Independent shares would pass
    /// even if [`Share`] were merely `Send`, so both are needed.
    #[test]
    fn many_threads_drive_one_callback_and_independent_shares() {
        const THREADS: usize = 4;
        const ROUNDS: usize = 32;

        let unlocks = Arc::new(AtomicUsize::new(0));
        std::thread::scope(|scope| {
            for _ in 0..THREADS {
                let unlocks = Arc::clone(&unlocks);
                scope.spawn(move || {
                    let share = Share::new();
                    let recorder = Recorder::new();
                    install(&share, &recorder);

                    // A second unlock callback that also counts, replacing the
                    // recorder's: the counter is what crosses threads.
                    let counting = Arc::clone(&recorder);
                    let counter = Arc::clone(&unlocks);
                    assert_eq!(
                        share.setopt(ShareOption::UnlockFunc(Some(Arc::new(
                            move |owner, kind, userdata| {
                                counting.on_unlock(owner, kind, userdata);
                                counter.fetch_add(1, Ordering::Relaxed);
                            }
                        )))),
                        CURLSHcode::Ok
                    );
                    for kind in [3, 4, 5] {
                        assert_eq!(
                            share.setopt(ShareOption::Share(kind)),
                            CURLSHcode::Ok
                        );
                    }
                    let _ = recorder.drain();

                    for _ in 0..ROUNDS {
                        let _ = share.attach(OWNER, |_| ());
                        drop(share.dnscache(OWNER));
                        drop(share.ssl_scache(OWNER));
                        drop(share.pool(OWNER));
                        let _ = share.detach(OWNER, |_| ());
                    }

                    recorder.assert_balanced();
                    assert_eq!(share.dirty(), 0);
                    assert_eq!(share.cleanup(), CURLSHcode::Ok);
                });
            }
        });

        // Five unlocks per round -- attach, three stores, detach -- plus the
        // two `cleanup` delivers per thread: its own `CURL_LOCK_DATA_SHARE`
        // pair (`lib/curl_share.c:261-262`) and the
        // `CURL_LOCK_DATA_CONNECT` pair the pool's destroy runs inside
        // (`lib/conncache.c:41-60`, reached from `Curl_cpool_destroy`), because
        // these shares have the connect bit set.
        assert_eq!(unlocks.load(Ordering::Relaxed), THREADS * (ROUNDS * 5 + 2));
    }

    /// The application's callbacks as `lib506.c` actually writes them: a lock
    /// that blocks.
    ///
    /// `tests/libtest/lib506.c:47-63` and `:100-116` install
    /// `pthread_mutex_lock` and `pthread_mutex_unlock` per datum, so the
    /// callback pair **is** the mutual exclusion -- the C keeps no internal
    /// lock of its own. [`Recorder`] on its own cannot stand in for that under
    /// real concurrency: it records and returns, so two threads would both be
    /// told they hold one datum and its `lib506.c`-modelled detector would
    /// rightly report a double lock. This gate supplies the blocking half, and
    /// the two compose -- gate first, then record -- so the detector stays
    /// meaningful.
    ///
    /// A [`Condvar`] over a stack of held kinds rather than a mutex per kind,
    /// because a [`MutexGuard`] cannot be held between two separate callback
    /// invocations the way a raw `pthread_mutex_t` can.
    ///
    /// That this cannot deadlock against the module is a property of the
    /// module, and is the second thing the test using it proves: every
    /// notification is delivered with no internal lock held --
    /// [`ShareCore::lock`] and [`ShareCore::unlock`] release the metadata
    /// before calling out, [`ShareCore::guard`] notifies before taking the
    /// store, and [`ShareGuard`] releases the store before the unlock
    /// notification.
    #[derive(Debug, Default)]
    struct Gate {
        /// The kinds currently held, in acquisition order.
        held: Mutex<Vec<LockData>>,
        /// Signalled on every release.
        wake: Condvar,
    }

    impl Gate {
        /// Blocks until nobody holds `kind`, then takes it.
        fn acquire(&self, kind: LockData) {
            let mut held =
                self.held.lock().unwrap_or_else(PoisonError::into_inner);
            while held.contains(&kind) {
                held = self
                    .wake
                    .wait(held)
                    .unwrap_or_else(PoisonError::into_inner);
            }
            held.push(kind);
        }

        /// Gives `kind` back and wakes whoever is waiting for it.
        fn release(&self, kind: LockData) {
            let mut held =
                self.held.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(at) = held.iter().rposition(|entry| *entry == kind) {
                held.remove(at);
            }
            drop(held);
            self.wake.notify_all();
        }
    }

    /// Installs a gated recorder: the callbacks record *and* mutually exclude.
    fn install_gated(
        share: &Share,
        recorder: &Arc<Recorder>,
        gate: &Arc<Gate>,
    ) {
        let for_lock = Arc::clone(recorder);
        let lock_gate = Arc::clone(gate);
        assert_eq!(
            share.setopt(ShareOption::LockFunc(Some(Arc::new(
                move |owner, kind, access, userdata| {
                    lock_gate.acquire(kind);
                    for_lock.on_lock(owner, kind, access, userdata);
                }
            )))),
            CURLSHcode::Ok
        );
        let for_unlock = Arc::clone(recorder);
        let unlock_gate = Arc::clone(gate);
        assert_eq!(
            share.setopt(ShareOption::UnlockFunc(Some(Arc::new(
                move |owner, kind, userdata| {
                    for_unlock.on_unlock(owner, kind, userdata);
                    unlock_gate.release(kind);
                }
            )))),
            CURLSHcode::Ok
        );
        assert_eq!(
            share.setopt(ShareOption::UserData(USERDATA)),
            CURLSHcode::Ok
        );
    }

    /// ONE share, two easy-handle stand-ins, two threads -- `lib506.c`'s shape.
    ///
    /// The test the split exists for. `tests/libtest/lib506.c` runs two
    /// threads against a single share with `CURL_LOCK_DATA_COOKIE` and
    /// `CURL_LOCK_DATA_DNS`, and `lib3207.c` does the same with
    /// `CURL_LOCK_DATA_SSL_SESSION`; both are supported libcurl behaviour, so
    /// a test giving each thread its own share would not stand in for them.
    /// Here each thread holds an [`Arc<ShareCore>`] from [`Share::stores`] --
    /// the same state, the same locks, the same callbacks -- and drives every
    /// kind [`ShareCore`] carries.
    ///
    /// Four things are asserted:
    ///
    /// 1. **It is one share.** A [`Barrier`] makes both threads attach before
    ///    either proceeds, so the reference count read after it is exactly
    ///    [`THREADS`] rather than 1. Two independent shares would each read 1.
    ///    The same barrier is waited on a second time so that the read happens
    ///    while both references are still held: the first rendezvous proves
    ///    they landed, the second keeps them landed, and without it a thread
    ///    released early can finish the loop and detach before a parked thread
    ///    reads -- a race measured at roughly one run in fifty under load.
    /// 2. **Every shared store is reachable from both threads**, including the
    ///    cookie-then-Public-Suffix-List nesting `lib/cookie.c` performs.
    /// 3. **The notifications stay balanced and never double-lock** under a
    ///    callback that really blocks, which is what [`Gate`] supplies.
    /// 4. **The count returns to zero**, so `curl_share_cleanup` then
    ///    succeeds -- the C's `CURLSHE_IN_USE` guard is not tripped by a
    ///    decrement lost to a race.
    ///
    /// The connection pool is absent on purpose: it is the one kind that
    /// cannot cross a thread boundary, which
    /// `the_shared_core_is_send_and_sync_and_the_owner_is_not` records and
    /// `many_threads_drive_one_callback_and_independent_shares` exercises
    /// instead.
    #[test]
    fn one_share_serves_two_threads_through_its_core() {
        const THREADS: usize = 2;
        const ROUNDS: usize = 32;

        let share = Share::new();
        let recorder = Recorder::new();
        let gate = Arc::new(Gate::default());
        install_gated(&share, &recorder, &gate);

        // Every kind the core carries. Cookies, the Public Suffix List and
        // HSTS are feature-gated, so a build without them shares fewer kinds
        // rather than failing.
        for kind in [LockData::Dns, LockData::SslSession] {
            assert_eq!(
                share.setopt(ShareOption::Share(kind.as_i32())),
                CURLSHcode::Ok
            );
        }
        #[cfg(feature = "cookies")]
        for kind in [LockData::Cookie, LockData::Psl] {
            assert_eq!(
                share.setopt(ShareOption::Share(kind.as_i32())),
                CURLSHcode::Ok
            );
        }
        #[cfg(feature = "hsts")]
        assert_eq!(
            share.setopt(ShareOption::Share(LockData::Hsts.as_i32())),
            CURLSHcode::Ok
        );
        let _ = recorder.drain();

        // One handle per thread on the SAME state, which is what
        // `Share::stores` is for.
        let core = share.stores();
        let barrier = Barrier::new(THREADS);
        std::thread::scope(|scope| {
            for slot in 0..THREADS {
                let core = Arc::clone(&core);
                let barrier = &barrier;
                scope.spawn(move || {
                    // A distinct handle per thread, as two easy handles are
                    // distinct: the notifications name whoever caused them.
                    let owner = LockOwner::from_bits(0x0001_0000 + slot);

                    // C: lib/setopt.c:1520-1550 -- the attach every easy
                    // handle performs when `CURLOPT_SHARE` is set.
                    let specifier = core
                        .attach(owner, |specifier| specifier)
                        .expect("a live share accepts a reference");
                    assert!(specifier.contains(LockData::Dns));
                    assert!(specifier.contains(LockData::SslSession));

                    // Both references are now on ONE counter, which is the
                    // whole claim being tested.
                    barrier.wait();
                    // Read while every thread is provably still attached, and
                    // hold them there for the duration of the read. The
                    // barrier above proves both attaches landed; on its own it
                    // does not prove they are still landed, because a thread
                    // released from it can run the whole loop below and give
                    // its reference back at `:detach` before a thread the
                    // scheduler has parked gets to look. That leaves the
                    // parked reader seeing one reference where the claim is
                    // two -- measured deterministically by delaying one thread
                    // here, and observed as roughly one run in fifty under CPU
                    // contention without the delay. The count is captured
                    // between the two rendezvous and asserted after the
                    // second, so that nothing between them can panic and leave
                    // the other thread waiting: a genuine violation still
                    // fails in whichever thread observed it.
                    let attached = core.dirty();
                    barrier.wait();
                    assert_eq!(
                        attached, THREADS as u32,
                        "one share, {THREADS} handles"
                    );

                    for _ in 0..ROUNDS {
                        assert!(
                            core.dnscache(owner)
                                .expect("DNS is shared")
                                .is_empty(),
                            "nothing resolves in this test"
                        );
                        drop(
                            core.ssl_scache(owner)
                                .expect("TLS sessions are shared"),
                        );
                        #[cfg(feature = "cookies")]
                        {
                            // The C's own nesting: the cookie lock held while
                            // the Public Suffix List is consulted
                            // (`lib/cookie.c:795-802`).
                            let jar = core.cookies(owner).expect("cookies");
                            let clock = TestClock::new(CurlTime::new(1_000, 0));
                            let source = MemoryPslSource::latest(PSL_LIST);
                            let list = core
                                .psl_use(owner, &clock, &source)
                                .expect("a list");
                            assert!(list.list().is_some());
                            drop(list);
                            drop(jar);
                        }
                        #[cfg(feature = "hsts")]
                        drop(core.hsts(owner).expect("HSTS is shared"));
                    }

                    // C: lib/url.c:289-294 -- the detach `Curl_close`
                    // performs.
                    assert!(
                        core.detach(owner, |_| ()).is_some(),
                        "a live share accepts the release"
                    );
                });
            }
        });

        recorder.assert_balanced();
        assert_eq!(share.dirty(), 0, "every reference was given back");

        // The list those threads loaded is the SHARE's own and not a copy of
        // it: a reader arriving afterwards with the same clock finds it fresh,
        // so it takes one `CURL_LOCK_ACCESS_SHARED` notification and performs
        // no upgrade -- which is only true if a worker's refresh landed in this
        // cache.
        #[cfg(feature = "cookies")]
        {
            let _ = recorder.drain();
            let clock = TestClock::new(CurlTime::new(1_000, 0));
            let source = MemoryPslSource::latest(PSL_LIST);
            let guard = share.psl_use(OWNER, &clock, &source).expect("a list");
            assert_eq!(
                recorder.drain(),
                vec![Event::Lock(
                    OWNER,
                    LockData::Psl,
                    LockAccess::Shared,
                    USERDATA
                )],
                "lib/psl.c:51 only -- the cache the workers filled is fresh"
            );
            drop(guard);
            recorder.assert_balanced();
        }

        assert_eq!(share.cleanup(), CURLSHcode::Ok);
    }

    /// Two threads race for one teardown, and exactly one wins.
    ///
    /// The contended form of
    /// `a_claimed_teardown_refuses_new_references_and_a_second_cleanup`, which
    /// can only be driven in sequence because [`Share::cleanup`] lives
    /// on the owner. The claim itself lives on [`ShareCore`], which is
    /// `Send + Sync`, so the race can be run for real -- and it is the race
    /// `curl_share_cleanup` (`lib/curl_share.c:221-267`) loses: its
    /// `GOOD_SHARE_HANDLE` test at `:224`, its `share->dirty` read at `:231`
    /// and its `share->magic = 0` at `:263` are three unsynchronised steps, so
    /// two threads entering together both return `CURLSHE_OK` and the
    /// application frees one allocation twice.
    ///
    /// Every thread arrives at a [`Barrier`] first so that the
    /// compare-and-exchange is genuinely contended rather than merely
    /// sequential, and the winner count is asserted to be exactly one.
    #[test]
    fn two_threads_race_one_teardown_claim() {
        const THREADS: usize = 8;

        let share = Share::new();
        let core = share.stores();
        let winners = Arc::new(AtomicUsize::new(0));
        let barrier = Barrier::new(THREADS);

        std::thread::scope(|scope| {
            for _ in 0..THREADS {
                let core = Arc::clone(&core);
                let winners = Arc::clone(&winners);
                let barrier = &barrier;
                scope.spawn(move || {
                    barrier.wait();
                    if core.claim_cleanup() {
                        winners.fetch_add(1, Ordering::Relaxed);
                    }
                });
            }
        });

        assert_eq!(
            winners.load(Ordering::Relaxed),
            1,
            "exactly one caller may ever reach `Box::from_raw`"
        );
        assert_eq!(core.lifecycle(), Lifecycle::Cleaning);
        assert!(
            core.attach(OWNER, |_| ()).is_none(),
            "a claimed share accepts no new reference"
        );

        // The winner's teardown is what `Share::cleanup` performs; here the
        // claim is handed back so that the owner can run the real one, which
        // proves the share survived the race intact.
        core.release_claim();
        assert_eq!(share.cleanup(), CURLSHcode::Ok);
        assert_eq!(core.lifecycle(), Lifecycle::Dead);
    }

    /// A lock callback that really locks, as `lib3207.c:135`'s
    /// `curl_mutex_t mutexes[CURL_LOCK_DATA_LAST - 1]` does.
    ///
    /// [`Recorder`] is a *recorder*: it notes a second lock of one kind as the
    /// fault `lib506.c:71-76` prints, which is the right check when one thread
    /// drives one share. It is the wrong double for several threads driving
    /// ONE share, because in C the second thread does not fault -- it BLOCKS
    /// inside the application's callback until the first releases. Substituting
    /// a recorder for a mutex there would report a fault the C never sees.
    ///
    /// So this is a real mutual exclusion, per kind, built from a held-set and
    /// a [`Condvar`] rather than from one [`Mutex`] per kind, because a
    /// `MutexGuard` cannot be parked between the lock and unlock callbacks
    /// without either `unsafe` or a self-referential type, and this module
    /// permits neither. The exclusion it provides is the same, and it is what
    /// makes the accounting below meaningful: `locks` and `unlocks` can only
    /// balance if every acquisition was serialised.
    #[derive(Debug, Default)]
    struct KindMutexes {
        held: Mutex<Vec<LockData>>,
        released: Condvar,
        locks: AtomicUsize,
        unlocks: AtomicUsize,
        faults: Mutex<Vec<String>>,
    }

    impl KindMutexes {
        fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }

        /// Blocks until this kind is free, then takes it.
        fn acquire(&self, kind: LockData) {
            let mut held =
                self.held.lock().unwrap_or_else(PoisonError::into_inner);
            while held.contains(&kind) {
                held = self
                    .released
                    .wait(held)
                    .unwrap_or_else(PoisonError::into_inner);
            }
            held.push(kind);
            drop(held);
            self.locks.fetch_add(1, Ordering::Relaxed);
        }

        /// Releases this kind, waking any thread waiting for it.
        ///
        /// An unlock for a kind that is not held is `lib506.c:112-116`'s
        /// `"unlock: double unlocked %s"` and is recorded as a fault rather
        /// than ignored.
        fn release(&self, kind: LockData) {
            let mut held =
                self.held.lock().unwrap_or_else(PoisonError::into_inner);
            match held.iter().rposition(|entry| *entry == kind) {
                Some(at) => {
                    held.remove(at);
                }
                None => self
                    .faults
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(format!("unlock: double unlocked {}", kind.c_name())),
            }
            drop(held);
            self.unlocks.fetch_add(1, Ordering::Relaxed);
            self.released.notify_all();
        }

        fn assert_idle(&self) {
            let faults =
                self.faults.lock().unwrap_or_else(PoisonError::into_inner);
            assert!(faults.is_empty(), "callback faults: {faults:?}");
            let held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
            assert!(held.is_empty(), "still held at the end: {held:?}");
        }
    }

    /// One share, several threads -- `tests/libtest/lib506.c`'s actual shape.
    ///
    /// `lib506.c` drives a single `CURLSH` from two threads with
    /// `CURL_LOCK_DATA_COOKIE` and `CURL_LOCK_DATA_DNS`, and `lib3207.c` does
    /// the same with `CURL_LOCK_DATA_SSL_SESSION`. This is that contract
    /// expressed against this module directly, and it is the test that
    /// exercises `Sync` rather than merely `Send`: every thread holds a
    /// `&Share` to the *same* share and reaches every store through it. Before
    /// the seam bounds landed, the `scope.spawn` below did not compile.
    ///
    /// Four properties are asserted, and each would fail differently:
    ///
    /// * **No deadlock.** The store accessors take the internal lock and
    ///   invoke the application callback around it. An inversion -- a
    ///   notification delivered while the internal lock is held -- would hang
    ///   here rather than in a consumer, because [`KindMutexes`] is a real
    ///   mutual exclusion.
    /// * **Mutual exclusion per kind is honoured, and balanced.** Every
    ///   acquisition is matched, nothing is left held, and no kind is released
    ///   without having been taken.
    /// * **The refcount is exact.** `THREADS * ROUNDS` attaches and as many
    ///   detaches leave `dirty` at zero, so `cleanup` is permitted. An
    ///   increment that escaped its lock would leave a non-zero remainder and
    ///   turn the final `cleanup` into `CURLSHE_IN_USE`.
    /// * **No notification was lost or duplicated.** Five locks and five
    ///   unlocks per round -- attach, the three stores, detach -- counted
    ///   across every thread.
    #[test]
    fn several_threads_drive_one_shared_handle() {
        const THREADS: usize = 4;
        const ROUNDS: usize = 64;

        let share = Share::new();
        let gate = KindMutexes::new();

        let for_lock = Arc::clone(&gate);
        assert_eq!(
            share.setopt(ShareOption::LockFunc(Some(Arc::new(
                move |_owner, kind, _access, _userdata| {
                    for_lock.acquire(kind);
                }
            )))),
            CURLSHcode::Ok
        );
        let for_unlock = Arc::clone(&gate);
        assert_eq!(
            share.setopt(ShareOption::UnlockFunc(Some(Arc::new(
                move |_owner, kind, _userdata| {
                    for_unlock.release(kind);
                }
            )))),
            CURLSHcode::Ok
        );

        // DNS, TLS sessions and connections -- the three kinds every build
        // has, independent of the `cookies` and `hsts` features.
        for kind in [3, 4, 5] {
            assert_eq!(share.setopt(ShareOption::Share(kind)), CURLSHcode::Ok);
        }
        gate.assert_idle();
        gate.locks.store(0, Ordering::Relaxed);
        gate.unlocks.store(0, Ordering::Relaxed);

        // `&Share` crossing a thread boundary is what needs `Sync`.
        std::thread::scope(|scope| {
            for _ in 0..THREADS {
                let share: &Share = &share;
                scope.spawn(move || {
                    for _ in 0..ROUNDS {
                        // `attach` and `detach` run the caller's ownership
                        // change inside the `CURL_LOCK_DATA_SHARE` bracket,
                        // the way `lib/setopt.c:1493-1550` does; a handle
                        // with nothing to repoint passes a closure that does
                        // nothing, as `lib/url.c:291-293` does.
                        let _ = share.attach(OWNER, |_| ());
                        drop(share.dnscache(OWNER));
                        drop(share.ssl_scache(OWNER));
                        drop(share.pool(OWNER));
                        let _ = share.detach(OWNER, |_| ());
                    }
                });
            }
        });

        gate.assert_idle();
        assert_eq!(share.dirty(), 0, "every attach was matched by a detach");
        let expected = THREADS * ROUNDS * 5;
        assert_eq!(
            gate.locks.load(Ordering::Relaxed),
            expected,
            "no lock notification was lost or duplicated across threads"
        );
        assert_eq!(
            gate.unlocks.load(Ordering::Relaxed),
            expected,
            "no unlock notification was lost or duplicated across threads"
        );
        assert_eq!(share.cleanup(), CURLSHcode::Ok);
    }
}
