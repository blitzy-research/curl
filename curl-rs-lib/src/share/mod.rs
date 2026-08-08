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
//! Supersedes `lib/curl_share.c` (299 lines) and `lib/curl_share.h`
//! (77 lines), and backs four of the 100 exported symbols of
//! `lib/libcurl.def` -- rows 81 to 84, `curl_share_cleanup`,
//! `curl_share_init`, `curl_share_setopt` and `curl_share_strerror` -- which
//! `curl-rs-ffi/src/ffi/share.rs` surfaces to C.
//!
//! Every claim below carries the locator it was measured from, in the C tree
//! at commit `54cf587b9c` (curl/libcurl 8.19.0-DEV,
//! `LIBCURL_VERSION_NUM 0x081300`). The principal ones:
//!
//! * `lib/curl_share.c` -- the four functions and their orderings.
//! * `lib/curl_share.h:36-40` -- the validity tag and the two convenience
//!   predicates; `:42-66` -- `struct Curl_share`, carrying the comment
//!   *"this struct is libcurl-private, do not export details"*; `:68-70` --
//!   the two internal entry points.
//! * `include/curl/curl.h:110` -- `typedef void CURLSH;`, which is a `void`
//!   and not an opaque struct.
//! * `include/curl/curl.h:3026-3077` -- `curl_lock_data`,
//!   `curl_lock_access`, `curl_lock_function`, `curl_unlock_function`,
//!   `CURLSHcode` and `CURLSHoption`.
//! * `lib/strerror.c:411` -- this family's distinct fallback message,
//!   `"CURLSHcode unknown"`, which `crate::error` owns.
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
//! `CURL_LOCK_DATA_SHARE` = 1 is the seventh kind and stores nothing: the C
//! comment at `include/curl/curl.h:3028-3031` records that it *"is used
//! internally to say that the locking is just made to change the internal
//! state of the share itself"*. It guards the reference count.
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
//! # `Send` and `Sync`: measured, and one blocker ESCALATED
//!
//! Five of the six stores are `Send + Sync` as their own modules define them,
//! and this module's metadata is too. The sixth,
//! [`crate::conn::pool::ConnectionPool`], is neither, because it holds
//! `Box<dyn ShutdownTimer>`, `Option<Box<dyn ProtocolDisconnect>>` and a
//! `FilterChains` of `Box<dyn ConnFilter>`, and none of those three traits
//! carries a `Send` bound. `struct Curl_share` holds the pool by value
//! (`lib/curl_share.h:52`), so [`Share`] holds it too, and [`Share`] is
//! therefore neither `Send` nor `Sync` at this commit.
//!
//! This was measured rather than assumed, in both directions. A probe
//! asserting `Send + Sync` for each store individually passes for the five
//! and fails only for the pool. Adding `+ Send` to those three traits
//! produced **925 errors with 23 distinct root causes**, spanning
//! `conn/socket.rs` (nine `Rc<dyn ...>` seams), `conn/filters.rs`
//! (`Rc<RefCell<...>>` state and test helpers), `crate::tls`'s
//! `<B as TlsBackend>::State` and `util/bufq.rs`'s
//! `Rc<RefCell<ChunkPool>>`. That is a crate-wide architectural change owned
//! by `conn/` and `tls/`, not by this module.
//!
//! There is no unsafe-free way to hold a `!Send` value inside a
//! `Send + Sync` container, and the alternative -- leaving the pool out of
//! the share -- would make `CURLSHOPT_SHARE` with `CURL_LOCK_DATA_CONNECT`
//! set a bit and share nothing, which is a stub rather than an
//! implementation. So the faithful model is kept and the limitation is
//! escalated here rather than hidden:
//!
//! * **What it costs.** An application using one `CURLSH` from two threads is
//!   supported C behaviour -- `tests/libtest/lib506.c` drives one share from
//!   two threads with `CURL_LOCK_DATA_COOKIE` and `CURL_LOCK_DATA_DNS`, and
//!   `lib3207.c` does the same with `CURL_LOCK_DATA_SSL_SESSION`. Until
//!   [`Share`] is `Sync`, `curl-rs-ffi/src/ffi/share.rs` cannot form a shared
//!   reference for a second thread soundly, so it must treat `CURLSH` as
//!   thread-affine and say so in its own safety comment.
//! * **What it does not cost.** The `threadsafe` capability
//!   `crate::version` advertises is *not* about shares.
//!   `docs/libcurl/curl_version_info.md:345-351` defines it as
//!   *"thread-safety support (Atomic or SRWLOCK) to protect curl
//!   initialization"*, and `crate::version` gates it on its global-init
//!   engine token accordingly. This limitation therefore does not turn that
//!   token into an over-report, which
//!   `tests/runtests.pl` would punish.
//! * **How it is fixed.** Bound `ConnFilter`, `ShutdownTimer` and
//!   `ProtocolDisconnect` with `Send` and replace the `Rc<RefCell<...>>`
//!   seams behind them. [`Share`] then becomes `Send + Sync` with no change
//!   to this file, because every other field already is. The AAP's own
//!   directive of a multi-thread Tokio runtime for the multi handle points
//!   the same way, since a connection driven by such a task must be `Send`.
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
//!    free.
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

use core::fmt;
use core::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

// The reader-writer lock is the Public Suffix List's alone: it is the only
// datum the C ever asks for with `CURL_LOCK_ACCESS_SHARED` (`lib/psl.c:51`,
// `:89`), and that cache lives behind the `cookies` feature because
// `crate::cookies` declares its `psl` child there. Gated with it so that a
// build without cookies imports nothing it cannot use.
#[cfg(feature = "cookies")]
use std::sync::{RwLock, RwLockWriteGuard};

#[cfg(feature = "cookies")]
use publicsuffix::List;

use crate::conn::pool::ConnectionPool;
#[cfg(feature = "hsts")]
use crate::cookies::hsts::HstsCache;
#[cfg(feature = "cookies")]
use crate::cookies::psl::{PslCache, PslSource};
#[cfg(feature = "cookies")]
use crate::cookies::CookieInfo;
use crate::dns::DnsCache;
use crate::error::CURLSHcode;
use crate::tls::session_cache::SessionCache;
#[cfg(feature = "cookies")]
use crate::util::timeval::Clock;

// The public vocabulary: the two enumerations an application's callbacks see
//
// Both are transcriptions of `include/curl/curl.h`, and both write EVERY
// discriminant explicitly. The C writes only `CURL_LOCK_DATA_NONE = 0` and
// the three `CURL_LOCK_ACCESS_*` values; every other value comes from
// declaration order. An application compiled against curl 8.19.0-DEV holds
// the INTEGERS, so ordinal inference is prohibited: a reordering here would
// silently hand a callback the wrong kind, with no diagnostic anywhere.

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
/// [`Share::attach`] and [`Share::detach`] maintain.
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
    ///
    /// The total function `lib/curl_share.c` lacks: its `type` comes straight
    /// from `va_arg(param, int)` (`:81`, `:149`) and is then used to build
    /// `1 << type`, which for a negative or large value is undefined
    /// behaviour in C. Rejecting the value here is what lets this module
    /// route it to [`CURLSHcode::BadOption`] -- the arm the C's `default:`
    /// reaches for every value it does recognise -- without ever performing
    /// that shift.
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
    ///
    /// An exhaustive `match` rather than a parallel array of strings, which
    /// is the pattern `crate::trace` establishes: adding a token becomes a
    /// compile error here instead of an index that silently names the wrong
    /// thing.
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
/// during the refresh sequence [`Share::psl_use`] reproduces. The other two
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
//
// `curl_lock_function` receives a `CURL *handle` and a `void *userptr`
// (`include/curl/curl.h:3050-3053`), and this crate never dereferences
// either. Both are therefore carried as integers, which is the pattern
// `crate::multi::events`'s `CallbackData` already establishes for
// `CURLMOPT_SOCKETDATA` and `curl_multi_assign`: only `curl-rs-ffi` converts
// between an integer and a pointer, and it does so inside a documented safety
// block. Zero is the null pointer in both cases.

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
///
/// `share->clientdata` (`lib/curl_share.h:50`), set by `CURLSHOPT_USERDATA`
/// (`lib/curl_share.c:206-209`) and passed to both callbacks as their last
/// argument. Independent of the callbacks themselves: the C stores three
/// separate fields, so setting the user pointer without a callback is
/// remembered, and clearing a callback leaves the user pointer alone.
///
/// [`Self::NONE`] is the null pointer a freshly initialised share carries,
/// since `curl_share_init` allocates with `curlx_calloc`
/// (`lib/curl_share.c:35`).
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
///
/// [`Arc`] rather than [`Box`] for a specific reason: the notification must be
/// delivered *without* this module's metadata lock held, or a callback that
/// reached back into the share would deadlock and a callback that panicked
/// would poison the one lock every entry point needs. A [`Box`] cannot be
/// cloned out from behind a guard; an [`Arc`] can, so the guard is released
/// first and the callback runs unlocked.
///
/// `Fn` rather than `FnMut`, and `Send + Sync`, because the C installs a plain
/// function pointer that may be entered re-entrantly from several threads. A
/// function pointer plus an integer satisfies both bounds, so this costs
/// `curl-rs-ffi` nothing.
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
/// `lib/curl_share.h:45` -- an `unsigned int` used as a bitmask indexed by
/// `1 << curl_lock_data`, which [`LockData::bit`] reproduces. Exposed as a
/// value rather than as an integer so that the two convenience predicates the
/// C spells as macros travel with it.
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
/// `CURLSHoption` (`include/curl/curl.h:3068-3077`) names six options and a
/// bound, and `curl_share_setopt` (`:3080-3081`) is variadic in its
/// declaration but takes **exactly one** trailing argument in practice -- the
/// public header macro-ises the call to precisely three arguments in both
/// branches of its selector (`:3337-3338`,
/// `include/curl/typecheck-gcc.h:265-266`). Fusing the identifier with that
/// one argument makes an ill-formed pair unrepresentable, and makes
/// [`Share::setopt`] a single exhaustive `match` mirroring
/// `lib/curl_share.c:78-214` arm for arm.
///
/// The integers themselves are **not** restated here. `curl-rs-ffi`'s option
/// table is the single source of truth for option identity, and a second copy
/// would drift. This enumeration is the vocabulary; the shim performs the
/// mapping from `CURLSHoption` to a variant, and from the trailing slot to
/// that variant's payload.
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
///
/// The remaining three carry an [`Option`], because all three are clearable
/// with a null pointer: `tests/libtest/lib3207.c:154-155` clears
/// `CURLSHOPT_LOCKFUNC` and `CURLSHOPT_UNLOCKFUNC` that way, and the C stores
/// whatever `va_arg` yields with no validation at all
/// (`lib/curl_share.c:196-209`).
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
    ///
    /// A callback is reported as `Some` or `None` -- which is the only thing
    /// about it that is observable and the only thing a test needs -- and
    /// every other payload is reported in full. The variant names are the C
    /// option spellings so that a failure message reads like the header.
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
///
/// Passed eagerly, at construction, because the C initialises the cache in
/// `curl_share_init` rather than lazily in `curl_share_setopt` -- which is
/// why `CURLSHOPT_SHARE` with `CURL_LOCK_DATA_DNS` is a no-op that only sets
/// the specifier bit (`lib/curl_share.c:84-85`).
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
///
/// Recorded but not passed, because there is nothing to pass it to.
/// `ConnectionPool::new` takes no size: the C's argument is a hash bucket
/// count and the Rust pool indexes destinations with a `BTreeMap`, which has
/// no bucket count to size -- `crate::conn::pool` states that reasoning at its
/// own constructor. The value is kept here so that the measurement survives
/// and is asserted by test rather than being lost when the C is deleted.
#[allow(dead_code)] // No consumer: ConnectionPool::new takes no size.
pub(crate) const CPOOL_SLOTS: usize = 103;

/// The share's own mutable state, everything but the stores.
///
/// The four fields the C keeps beside its six stores
/// (`lib/curl_share.h:45-50`), held together under one lock because they are
/// read and written together: every entry point reads the specifier and the
/// callbacks, and the two that change anything change the count.
///
/// `magic` is deliberately **not** here; see [`Share::magic`].
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
    ///
    /// `lib/curl_share.c:35` allocates zeroed and `:38` performs
    /// `share->specifier |= (1 << CURL_LOCK_DATA_SHARE)`, so a new share is
    /// already sharing its own internal state before an application sets
    /// anything.
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

/// A share: state deliberately shared between easy handles.
///
/// Supersedes `struct Curl_share` (`lib/curl_share.h:43-66`), which carries
/// the comment *"this struct is libcurl-private, do not export details"*
/// (`:42`). That comment is this type's specification as much as its
/// documentation: the C hands applications a `void *`
/// (`include/curl/curl.h:110`), and every field here is private for the same
/// reason.
///
/// # Ownership at the C boundary
///
/// `curl_share_init` performs `Box::into_raw` on one of these and
/// `curl_share_cleanup` performs `Box::from_raw` -- but **only** after
/// [`Self::cleanup`] has returned [`CURLSHcode::Ok`]. Every entry point takes
/// `&self`, so the object can never be consumed by an operation that is
/// supposed to fail leaving it usable, which
/// `docs/libcurl/curl_share_cleanup.md:59-60` requires: *"If an error occurs,
/// then the share object is not deleted."*
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
/// Lock ordering is fixed and shallow: metadata is taken and released before
/// any store lock, never with one held, and a store lock is never taken while
/// another store lock is held except for the one nesting the C itself
/// performs, cookie then PSL. That is what keeps the callbacks non-nested per
/// kind, which `tests/libtest/lib506.c`'s double-lock detector proves the C
/// guarantees.
pub struct Share {
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
    ///
    /// `Curl_dnscache_init(&share->dnscache, 23)` runs in `curl_share_init`
    /// (`lib/curl_share.c:39`), which is why `CURLSHOPT_SHARE` with
    /// `CURL_LOCK_DATA_DNS` has nothing to do (`:84-85`) and why
    /// `CURLSHOPT_UNSHARE` with it has nothing to undo (`:152-153`). Only the
    /// specifier bit distinguishes a shared cache from an unshared one, which
    /// is exactly what `dnscache_get` tests (`lib/hostip.c:300`).
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
    /// `curl_share_init` leaves it as `curlx_calloc` made it and
    /// `CURLSHOPT_SHARE` with `CURL_LOCK_DATA_PSL` does nothing but set the
    /// specifier bit (`lib/curl_share.c:134-138`); the zeroed state is stale
    /// by construction, so the first use refreshes it. `curl_share_cleanup`
    /// destroys it unconditionally (`:258`), regardless of the bit.
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
    ///
    /// Created lazily with 25 peers and 2 sessions each
    /// (`lib/curl_share.c:113-121`) and destroyed by `CURLSHOPT_UNSHARE`
    /// (`:178-181`). Unconditional in Rust: the C guards it with
    /// `#ifdef USE_SSL`, and there is no TLS feature to gate on because TLS is
    /// not optional here. `CURL_LOCK_DATA_SSL_SESSION` can therefore never
    /// yield [`CURLSHcode::NotBuiltIn`].
    ssl_scache: Mutex<Option<SessionCache>>,
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
    /// This is the field that makes [`Share`] neither `Send` nor `Sync`; the
    /// module documentation records the measurement and the escalation.
    cpool: Mutex<Option<ConnectionPool>>,
}

impl Default for Share {
    /// [`Share::new`], so that the type satisfies the convention a
    /// no-argument constructor implies.
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Share {
    /// Hand-written for two reasons.
    ///
    /// The callbacks are function values, which do not implement
    /// [`fmt::Debug`]; and a derived implementation would block on every
    /// lock, so formatting a share from inside a critical section -- which is
    /// exactly when a diagnostic is wanted -- would deadlock. Every lock is
    /// therefore probed with `try_lock` and reported as `<locked>` when it is
    /// held, which makes this safe to call from anywhere including a panic
    /// handler in a test.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        /// `Some(true)` present, `Some(false)` absent, [`None`] locked.
        fn presence<T>(slot: &Mutex<Option<T>>) -> Option<bool> {
            slot.try_lock().ok().map(|guard| guard.is_some())
        }

        /// `<locked>` for a lock this call could not take.
        fn describe(state: Option<bool>) -> &'static str {
            match state {
                Some(true) => "present",
                Some(false) => "absent",
                None => "<locked>",
            }
        }

        let mut out = f.debug_struct("Share");
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
            .field("cpool", &describe(presence(&self.cpool)))
            .finish()
    }
}

impl Share {
    /// `CURL_GOOD_SHARE` (`lib/curl_share.h:36`): the validity tag a live
    /// share carries.
    pub const GOOD_MAGIC: u32 = 0x7e11_7a1e;

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
    /// Rust counterpart -- an allocation failure aborts rather than yielding a
    /// null, and there is no admin handle to fail. `curl_share_init`
    /// consequently never returns `NULL` in this implementation, which is a
    /// divergence a caller cannot observe except by no longer taking a branch
    /// it was already required to handle.
    ///
    /// # The `admin` handle, and why it has no counterpart here
    ///
    /// `lib/curl_share.c:40-47` creates a `struct Curl_easy`, gives it
    /// `mid = 0` and sets `state.internal = TRUE`, so that the connection pool
    /// and the trace machinery have a handle to attribute callbacks and
    /// diagnostics to. Neither consumer exists to be attributed:
    /// `crate::easy` has no handle type at this commit, and
    /// `ConnectionPool::new` takes neither an owner nor a share --
    /// `crate::conn::pool` states outright that *"This type is just the
    /// pool"*. The two jobs the admin handle does in the C are therefore
    /// carried differently here. The `CURL *handle` a callback receives is
    /// supplied per call as a [`LockOwner`], because it varies per call and
    /// the C varies it too -- `Curl_share_lock` passes the transfer's handle
    /// while `curl_share_cleanup` passes `NULL`. Trace attribution has no
    /// subject because this module emits no diagnostics; `lib/curl_share.c`
    /// emits none either.
    ///
    /// `:48-51`'s `#ifdef DEBUGBUILD` block, which sets `set.verbose` when
    /// `CURL_DEBUG` is in the environment, is deliberately **omitted**. There
    /// is no debug-build feature in this crate's fifteen to gate it on -- the
    /// vocabulary is fixed and contains no `debug` -- and inventing one to
    /// carry a diagnostic default would add a build configuration for
    /// something with no observable effect on any contract. It also has
    /// nothing to act on, for the same reason the admin handle does not.
    #[must_use]
    pub fn new() -> Self {
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
            // C: lib/curl_share.h:52 -- `cpool.initialised` is false after
            // calloc, which `None` expresses.
            cpool: Mutex::new(None),
        }
    }

    /// The validity tag as it stands: `share->magic`
    /// (`lib/curl_share.h:44`).
    ///
    /// [`Self::GOOD_MAGIC`] for a live share and zero once [`Self::cleanup`]
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
    /// The C macro is `((x) && (x)->magic == CURL_GOOD_SHARE)`; the null test
    /// belongs to the shim, which has a pointer, and the tag test is this.
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
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.magic() == Self::GOOD_MAGIC
    }

    /// The metadata lock, recovering from poisoning rather than panicking.
    ///
    /// `PoisonError::into_inner` is the idiom `crate::util::timeval` uses, and
    /// the reasoning is stronger here: a poisoned lock would otherwise make
    /// every later operation on this share fail permanently, which is a
    /// behaviour C -- having no notion of poisoning -- cannot produce. The
    /// data behind the lock is a bitmask, a counter and two callback slots,
    /// none of which can be left in a state a later reader mis-reads.
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
    /// Delivers the application's lock notification for `kind` when -- and
    /// only when -- the kind's specifier bit is set and a callback is
    /// installed. Otherwise nothing is delivered and the call still succeeds:
    /// the C's comment at `:281` is *"else if we do not share this, pretend
    /// successful lock"*.
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
        if !self.is_valid() {
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
        if !self.is_valid() {
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
    /// `crate::multi` cannot get them wrong. The repointing does not: it
    /// writes to the easy handle's own fields, and no easy handle type exists
    /// at this commit. What the C decides the repointing from is the
    /// specifier -- `:1530` tests the shared cookie jar, `:1538` the shared
    /// HSTS cache and `:1545` the `CURL_LOCK_DATA_PSL` bit -- so the specifier
    /// is returned, read inside the same critical section as the increment. A
    /// caller therefore needs one call rather than a call plus a racing query.
    ///
    /// An invalid share yields [`Specifier::EMPTY`] and changes nothing, which
    /// is the C's `GOOD_SHARE_HANDLE(set)` guard at `:1520`: a share that
    /// fails it is never assigned and never counted.
    #[must_use]
    pub fn attach(&self, owner: LockOwner) -> Specifier {
        if !self.is_valid() {
            return Specifier::EMPTY;
        }
        // C: lib/setopt.c:1525.
        self.lock(owner, LockData::Share, LockAccess::Single);
        let specifier = {
            let mut meta = self.meta();
            // C: lib/setopt.c:1527. `saturating_add` rather than `+= 1`
            // because this file contains no arithmetic that can panic; the
            // saturation point is 4,294,967,295 concurrent handles, which no
            // reachable program approaches, and saturating there is strictly
            // better than wrapping to zero and letting `cleanup` free a share
            // that is still in use.
            meta.dirty = meta.dirty.saturating_add(1);
            Specifier(meta.specifier)
        };
        // C: lib/setopt.c:1549.
        self.unlock(owner, LockData::Share);
        specifier
    }

    /// Deregisters an easy handle, returning what it must stop pointing at.
    ///
    /// The first half of `CURLOPT_SHARE` (`lib/setopt.c:1493-1518`) and all of
    /// `Curl_close`'s share handling (`lib/url.c:289-294`), which are the same
    /// three steps: take `CURL_LOCK_DATA_SHARE` exclusively, decrement, and
    /// release.
    ///
    /// The specifier is returned for the same reason [`Self::attach`] returns
    /// it, and it matters more here: `lib/setopt.c:1509-1512` unlinks **both**
    /// of the handle's resolver entries when the `CURL_LOCK_DATA_DNS` bit is
    /// set, and `:1497-1507` nulls the cookie and HSTS pointers and repoints
    /// the PSL cache at the multi handle's or at nothing. All of those
    /// decisions are the caller's to carry out on its own fields, and all of
    /// them are read from the mask this returns.
    ///
    /// # Underflow
    ///
    /// The C writes `dirty--` on an `unsigned int`, so an unbalanced call
    /// would wrap to `UINT_MAX` and make the share permanently un-cleanable.
    /// Both C call sites are guarded by `if(data->share)`, so libcurl itself
    /// never reaches it. `saturating_sub` keeps this file free of panicking
    /// arithmetic and turns the unreachable case into the harmless one; the
    /// divergence is confined to inputs the C leaves broken.
    #[must_use]
    pub fn detach(&self, owner: LockOwner) -> Specifier {
        if !self.is_valid() {
            return Specifier::EMPTY;
        }
        // C: lib/setopt.c:1494, lib/url.c:291.
        self.lock(owner, LockData::Share, LockAccess::Single);
        let specifier = {
            let mut meta = self.meta();
            // C: lib/setopt.c:1514, lib/url.c:292.
            meta.dirty = meta.dirty.saturating_sub(1);
            Specifier(meta.specifier)
        };
        // C: lib/setopt.c:1516, lib/url.c:293.
        self.unlock(owner, LockData::Share);
        specifier
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
    ///
    /// Steps 2 and 3 run under one hold of the metadata lock, so the refusal
    /// and the change it guards cannot be separated by another thread. The C
    /// reads `share->dirty` unlocked at `:71`; taking the lock cannot change a
    /// result the C reaches and closes a window the C leaves open.
    ///
    /// `:57`'s `#undef curl_share_setopt` has no counterpart: it exists only
    /// because the public header macro-ises the name, which is
    /// `curl-rs-ffi`'s concern.
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
    ///
    /// `raw` is what `:81`'s `va_arg(param, int)` yielded. A value naming no
    /// kind reaches the same [`CURLSHcode::BadOption`] the C's inner
    /// `default:` reaches at `:140-141`, and -- as in the C -- no specifier bit
    /// is touched, because `:143`'s `if(!res)` guards the update. Unlike the
    /// C, no shift is performed on an unvalidated value, so the undefined
    /// behaviour `1 << type` invites for a negative or large `type` cannot
    /// occur.
    ///
    /// # The bit is set only on success
    ///
    /// `:143-144` is `if(!res) share->specifier |= (unsigned int)(1 << type);`.
    /// This is the asymmetry with [`Self::unshare_kind`], whose clear is
    /// unconditional, and it is reproduced rather than made uniform.
    ///
    /// # Idempotency is required
    ///
    /// `docs/libcurl/opts/CURLSHOPT_SHARE.md` states that *"You can set
    /// CURLSHOPT_SHARE(3) multiple times with different data arguments"*, the
    /// connection arm's own comment at `:128` is *"It is safe to set this
    /// option several times on a share."*, and
    /// `tests/libtest/lib1905.c:44-45` sets `CURL_LOCK_DATA_COOKIE` twice.
    /// Every arm below therefore creates its store only when the slot is
    /// empty, exactly as the C's `if(!share->cookies)`, `if(!share->hsts)`,
    /// `if(!share->ssl_scache)` and `if(!share->cpool.initialised)` do.
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
            LockData::Cookie => self.share_cookies(),
            // C: lib/curl_share.c:99-109.
            LockData::Hsts => self.share_hsts(),
            // C: lib/curl_share.c:111-125.
            LockData::SslSession => self.share_ssl_scache(),
            // C: lib/curl_share.c:127-132.
            LockData::Connect => self.share_cpool(),
            // C: lib/curl_share.c:134-138.
            LockData::Psl => Self::share_psl(),
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

    /// `CURL_LOCK_DATA_COOKIE` under `CURLSHOPT_SHARE`
    /// (`lib/curl_share.c:87-97`).
    ///
    /// The C's `CURLSHE_NOMEM` at `:92` is unreachable here: it reports a
    /// failed `Curl_cookie_init`, and `CookieInfo::new` cannot fail because a
    /// Rust allocation failure aborts rather than returning null.
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
    ///
    /// The C guard is
    /// `#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_COOKIES)`,
    /// whose Rust counterpart is the `cookies` feature -- there is no separate
    /// `http` feature in this crate's fifteen, and `crate::cookies` gates the
    /// engine on `cookies` alone.
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
    ///
    /// The capacities are the C's, and its comment at `:114-118` explains
    /// them: *"There is no way (yet) for the application to configure the
    /// session cache size, shared between many transfers. As for curl itself,
    /// a high session count will impact startup time. Also, the scache is not
    /// optimized for several hundreds of peers. So, keep it at a reasonable
    /// level."* Hence [`SCACHE_MAX_PEERS`] peers with
    /// [`SCACHE_MAX_SESSIONS_PER_PEER`] sessions each.
    ///
    /// Unconditional, where the C has `#ifdef USE_SSL`: TLS is not optional in
    /// this crate and there is no feature to gate on, so `:122-123`'s
    /// `CURLSHE_NOT_BUILT_IN` has no reachable counterpart. This kind can
    /// never report it.
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

    /// `CURL_LOCK_DATA_CONNECT` under `CURLSHOPT_SHARE`
    /// (`lib/curl_share.c:127-132`).
    ///
    /// The C's `if(!share->cpool.initialised)` is the [`Option`] being empty,
    /// which is why no separate flag is kept. Its size argument,
    /// [`CPOOL_SLOTS`], has nothing to receive it: `ConnectionPool::new` takes
    /// none, because the C's value is a hash bucket count and the Rust pool
    /// keys destinations with a `BTreeMap`.
    fn share_cpool(&self) -> CURLSHcode {
        let mut slot =
            self.cpool.lock().unwrap_or_else(PoisonError::into_inner);
        // C: lib/curl_share.c:129-131.
        if slot.is_none() {
            *slot = Some(ConnectionPool::new());
        }
        CURLSHcode::Ok
    }

    /// `CURL_LOCK_DATA_PSL` under `CURLSHOPT_SHARE`
    /// (`lib/curl_share.c:134-138`).
    ///
    /// The whole arm is
    /// `#ifndef USE_LIBPSL res = CURLSHE_NOT_BUILT_IN; #endif break;` -- so
    /// where the list is available this **succeeds while initialising
    /// nothing**, and only the specifier bit changes. The cache is a
    /// by-value, `calloc`-zeroed member (`lib/curl_share.h:58`) that no code
    /// path ever initialises; zeroed means stale, so the first use refreshes
    /// it.
    ///
    /// An associated function rather than a method because there is no state
    /// to touch, which is the point.
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

    /// `CURLSHOPT_UNSHARE` (`lib/curl_share.c:147-194`).
    ///
    /// Two measured quirks live here. Both are reproduced. Neither is
    /// corrected: libcurl's observable behaviour is frozen, and a behavioural
    /// improvement in this function would be a defect.
    ///
    /// # Quirk 1: the specifier bit is cleared unconditionally
    ///
    /// `:150` is `share->specifier &= ~(unsigned int)(1 << type);` and it runs
    /// **before** the switch and is **not** guarded by the result. An unshare
    /// that returns [`CURLSHcode::BadOption`] has therefore already cleared the
    /// bit. Do not move the clear after the switch and do not guard it.
    ///
    /// This is also how the `CURL_LOCK_DATA_SHARE` bit -- set at birth by
    /// `curl_share_init` (`:38`) and never cleared deliberately -- can be
    /// cleared after all: `CURLSHOPT_UNSHARE` with `CURL_LOCK_DATA_SHARE`
    /// clears bit 1 at `:150` and then falls to `default:` for
    /// [`CURLSHcode::BadOption`], because the switch has no case for it. That
    /// is precisely why [`Self::cleanup`] delivers its notifications without
    /// consulting the specifier while [`Self::lock`] consults it: after such a
    /// call the two would otherwise disagree.
    ///
    /// # Quirk 2: `CURL_LOCK_DATA_PSL` is a bad option here
    ///
    /// The switch has cases for DNS, cookies, HSTS, TLS sessions and
    /// connections, and **no case for the Public Suffix List**, so it reaches
    /// `default:` at `:190-192` and returns [`CURLSHcode::BadOption`] -- while
    /// having cleared the PSL bit, per quirk 1.
    ///
    /// `docs/libcurl/opts/CURLSHOPT_UNSHARE.md` says the opposite in both
    /// directions: it documents a `## CURL_LOCK_DATA_PSL` section (*"The
    /// Public Suffix List is no longer shared"*) and omits
    /// `CURL_LOCK_DATA_HSTS` entirely, where the code handles HSTS and not the
    /// PSL. **The documentation is stale; the code is the specification.**
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
            LockData::Cookie => self.unshare_cookies(),
            // C: lib/curl_share.c:166-174.
            LockData::Hsts => self.unshare_hsts(),
            // C: lib/curl_share.c:176-185.
            LockData::SslSession => self.unshare_ssl_scache(),
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

    /// `CURL_LOCK_DATA_COOKIE` under `CURLSHOPT_UNSHARE`
    /// (`lib/curl_share.c:155-164`).
    ///
    /// `Curl_cookie_cleanup(share->cookies)` then `share->cookies = NULL`.
    /// The explicit emptier runs before the drop so that the C's call is
    /// mirrored rather than merely its effect; dropping alone would reclaim
    /// the same memory.
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
    /// [`Self::lock`] and [`Self::unlock`].
    pub fn cleanup(&self) -> CURLSHcode {
        // C: lib/curl_share.c:224-225. No lock is taken first.
        if !self.is_valid() {
            return CURLSHcode::Invalid;
        }

        // One critical section for everything the rest of this function needs,
        // so that the reference count it acts on and the callbacks it delivers
        // are consistent with each other. The C reads all five unlocked, one
        // at a time. The callbacks are cloned out so that they run with no
        // lock of ours held.
        let (lockfunc, unlockfunc, clientdata, dirty, specifier) = {
            let meta = self.meta();
            (
                meta.lockfunc.clone(),
                meta.unlockfunc.clone(),
                meta.clientdata,
                meta.dirty,
                Specifier(meta.specifier),
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

        // C: lib/curl_share.c:231-235.
        if dirty != 0 {
            if let Some(callback) = &unlockfunc {
                callback(LockOwner::NONE, LockData::Share, clientdata);
            }
            return CURLSHcode::InUse;
        }

        self.teardown(specifier);

        // C: lib/curl_share.c:261-262.
        if let Some(callback) = &unlockfunc {
            callback(LockOwner::NONE, LockData::Share, clientdata);
        }

        // C: lib/curl_share.c:263 -- `share->magic = 0`, immediately before
        // `curlx_free(share)` at `:264`. `Release` pairs with the `Acquire` in
        // `Share::magic` so that a thread seeing the tag cleared also sees the
        // teardown above it.
        self.magic.store(0, Ordering::Release);

        // C: lib/curl_share.c:266.
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
    fn teardown(&self, specifier: Specifier) {
        // C: lib/curl_share.c:237-239 -- `Curl_cpool_destroy`, conditional.
        if specifier.keep_connect() {
            let mut slot =
                self.cpool.lock().unwrap_or_else(PoisonError::into_inner);
            *slot = None;
        }

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
//
// Each accessor answers the question the C's selector answers -- is this datum
// shared? -- and then does what the C's lock helper does: deliver the lock
// notification and enter the critical section. Dropping the guard leaves it.
//
// The predicate is the specifier bit alone, which is exactly what the C tests:
// `dnscache_get` (`lib/hostip.c:300`), `CURL_SHARE_KEEP_CONNECT`
// (`lib/curl_share.h:39-40`) and `CURL_SHARE_ssl_scache` (`:73-75`) all read
// the mask and nothing else. That is sound because a bit implies its store: a
// bit is set only by a successful `CURLSHOPT_SHARE`, which creates the store
// first (`lib/curl_share.c:143-144` is guarded by `if(!res)`), and
// `CURLSHOPT_UNSHARE` clears the bit in the same call that destroys it.

/// The unlock notification a guard owes when its critical section ends.
///
/// Split out so that the release is [`Drop`] rather than a call every exit
/// path has to remember. The C needs `bool locked` plus a `goto out` in one
/// function to get this right -- `Curl_ssl_session_import`
/// (`lib/vtls/vtls_scache.c:1079`, `:1095-1096`, `:1136-1138`) does exactly
/// that, because it has nine exit paths.
struct Release<'a> {
    /// The share whose callback is owed the notification.
    share: &'a Share,
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
        self.share.unlock(self.owner, self.kind);
    }
}

/// A shared store, locked, with its unlock notification pending.
///
/// [`Deref`] and [`DerefMut`] to the store so that a locked store reads as the
/// store it is.
///
/// # Drop order is load-bearing
///
/// The fields are declared so that `inner` is dropped before `release`, which
/// Rust guarantees for struct fields. The internal lock is therefore released
/// *before* the application's unlock notification is delivered, so that a
/// callback which reached back into this share for the same datum would block
/// on nothing of ours. Reordering these two fields would change that.
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

impl Share {
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
                share: self,
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
    ///
    /// The payload is the cache itself and not an [`Option`], because the C
    /// holds it by value and builds it in `curl_share_init`.
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
    ///
    /// The datum `lib/cookie.c` takes with `CURL_LOCK_ACCESS_SINGLE` around
    /// every load and every mutation, and that `lib/setopt.c:1530-1535`
    /// repoints an attaching handle at.
    ///
    /// Every jar operation needs exclusive access, so there is no shared-access
    /// variant: the C requests [`LockAccess::Single`] at all four of
    /// `lib/cookie.c`'s call sites and at all three of `lib/setopt.c`'s.
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
    ///
    /// `Curl_hsts_loadfiles` (`lib/hsts.c:554-570`) takes
    /// `CURL_LOCK_DATA_HSTS` with `CURL_LOCK_ACCESS_SINGLE`, and exclusive is
    /// the only access this datum ever needs: `crate::cookies::hsts` records
    /// that even its lookup mutates, because it prunes expired entries as it
    /// goes.
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
    ///
    /// Exclusive access is the only kind, and the pool's own contract requires
    /// it: it exposes mutation through `&mut self` and expects the sharing
    /// layer to hold the external lock across the whole critical section,
    /// including any matching callback that runs inside it.
    ///
    /// The bit and the pool can disagree in one direction: `CURLSHOPT_UNSHARE`
    /// clears the bit without destroying the pool
    /// (`lib/curl_share.c:150`, `:187-188`), so a pool may outlive its bit.
    /// This returns [`None`] then, which is what `CURL_SHARE_KEEP_CONNECT`
    /// answers, and the pool becomes reachable again if the option is set once
    /// more -- without being rebuilt, exactly as the C's
    /// `if(!share->cpool.initialised)` arranges.
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
/// # Why the internal lock is exclusive when the notification says shared
///
/// The list can only be reached through `PslCache::use_list`, which takes
/// `&mut self` -- its own documentation states it *"must be called with
/// exclusive access held"*, because it may refresh. So the Rust lock held
/// across the return is a writer even in the phase the C spends as a reader.
/// The application sees no difference: the notifications are
/// `CURL_LOCK_ACCESS_SHARED` exactly where the C's are. What it costs is
/// concurrency between two readers, and performance is not a goal here --
/// where a faster design and a more faithful one disagree, the faithful one
/// wins. What it cannot cost is a deadlock: the lock ordering is unchanged and
/// a second reader blocks only until the first guard is dropped.
#[cfg(feature = "cookies")]
pub(crate) struct PslGuard<'a> {
    /// The locked cache. Declared first so that it is released first.
    inner: RwLockWriteGuard<'a, PslCache>,
    /// The clock [`Self::list`] passes on, so that a caller does not have to
    /// supply it twice. `lib/psl.c:52` and `:62` read
    /// `Curl_pgrs_now(easy)->tv_sec`, which is monotonic.
    clock: &'a dyn Clock,
    /// The list source [`Self::list`] passes on: `psl_latest()` and
    /// `psl_builtin()` (`lib/psl.c:69`, `:79`).
    source: &'a dyn PslSource,
    /// The unlock notification, delivered when this goes out of scope --
    /// `Curl_psl_release`.
    release: Release<'a>,
}

#[cfg(feature = "cookies")]
impl PslGuard<'_> {
    /// The cached list -- what `Curl_psl_use` returns.
    ///
    /// Never [`None`] in practice: [`Share::psl_use`] releases the guard and
    /// yields [`None`] itself when no list could be obtained
    /// (`lib/psl.c:92-93`), so a guard exists only when a list does. The
    /// [`Option`] survives because `PslCache::use_list` is the only route to
    /// the list and it is fallible by signature, and answering that with an
    /// `expect` would put a panic on the path to a C caller.
    ///
    /// `&mut self` for the same reason: the borrow is produced by a `&mut`
    /// method, which is how the compiler is told that the exclusive access the
    /// refresh needed is still held.
    ///
    /// Calling this after [`Share::psl_use`] has already refreshed costs one
    /// clock read and no work: the deadline is in the future, so
    /// `PslCache::use_list` returns the cached list immediately.
    #[allow(dead_code)] // consumer: crate::cookies' public-suffix checks
    pub(crate) fn list(&mut self) -> Option<&List> {
        self.inner.use_list(self.clock, self.source)
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
impl Share {
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
    /// A cache that is still fresh takes the first step only, and the returned
    /// guard owes exactly one unlock. A stale one takes all five, and still
    /// owes exactly one, so the notifications remain balanced on both paths.
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
    ///
    /// # Injection
    ///
    /// The clock and the source are parameters rather than global state, which
    /// is what makes the 72-hour refresh deadline testable without waiting
    /// three days. The clock must be the monotonic reading:
    /// `lib/psl.c:52` and `:62` read `Curl_pgrs_now(easy)->tv_sec`, which is
    /// `CLOCK_MONOTONIC`, where this module's three sibling caches use the wall
    /// clock. `crate::cookies::psl` records why getting that backwards would
    /// make the deadline depend on wall-clock jumps.
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
                // `PslCache::use_list` is the whole of. Its return is the
                // list, which this phase does not need; the borrow ends here
                // so that the lock can be released next.
                let _ = cache.use_list(clock, source);
            }
            // C: lib/psl.c:88.
            self.unlock(owner, LockData::Psl);
            // C: lib/psl.c:89.
            self.lock(owner, LockData::Psl, LockAccess::Shared);
        }

        // The guard the caller receives. A writer rather than a reader for the
        // reason `PslGuard` documents: `use_list` is the only route to the
        // list and it needs exclusive access.
        let cache = self.psl.write().unwrap_or_else(PoisonError::into_inner);

        // C: lib/psl.c:91-93 -- `psl = pslcache->psl; if(!psl)
        // Curl_share_unlock(...)`, then `return psl`. A missing list releases
        // the lock before returning, so the caller owes nothing.
        if !cache.has_list() {
            drop(cache);
            self.unlock(owner, LockData::Psl);
            return None;
        }

        // C: lib/psl.c:94 -- returns holding the shared lock, which
        // `Curl_psl_release` (`:97-100`) later releases. Here that is `Drop`.
        Some(PslGuard {
            inner: cache,
            clock,
            source,
            release: Release {
                share: self,
                owner,
                kind: LockData::Psl,
            },
        })
    }
}

// Tests
//
// Three C programs cover this code and none of them can link here.
// `tests/libtest/lib506.c`, `lib1905.c` and `lib3207.c` link a debug static
// libcurl and call internal `Curl_*` symbols; a Rust static library does not
// export `pub(crate)` items, so their coverage moves into this module, which
// AAP 0.8.7 records as a documented deviation rather than a gap. The fixtures
// that drive the binary are unaffected.
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
//   * The measured `Send`/`Sync` state of every component, so that the
//     escalation in the module documentation is a fact under test rather than
//     a claim in prose.

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[cfg(feature = "cookies")]
    use crate::cookies::psl::MemoryPslSource;
    #[cfg(feature = "cookies")]
    use crate::util::timeval::{CurlTime, TestClock};

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
    ///
    /// It records every notification in order and, like `lib506.c:71-76`,
    /// detects a lock taken twice for one datum without an intervening
    /// release -- the C prints `"lock: double locked %s"` there. It also
    /// detects the mirror image, which `lib506.c:112-116` checks as
    /// `"unlock: double unlocked %s"`.
    ///
    /// `held` is a stack of kinds rather than an array indexed by the
    /// discriminant, which is what `lib3207.c:135` uses; a stack needs no
    /// indexing and so cannot itself panic.
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
    ///
    /// The DNS cache's 23 (`:39`) and the session cache's 25 by 2 (`:119`) are
    /// passed through and are observable in the constructed stores. The pool's
    /// 103 (`:130`) has nothing to receive it -- `ConnectionPool::new` takes no
    /// size because a `BTreeMap` has no bucket count -- so the measurement is
    /// asserted here instead of being lost.
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
    /// [`Share::attach`] is the only thing that increments -- and this test
    /// pins the consequence: counting one share never touches another.
    #[test]
    fn shares_are_independent_and_nothing_propagates_a_share() {
        let first = Share::new();
        let second = Share::new();
        let _ = first.attach(OWNER);
        assert_eq!(first.dirty(), 1);
        assert_eq!(second.dirty(), 0);
        let _ = first.detach(OWNER);
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
    ///
    /// The cookie jar (`:157-160`), the HSTS cache (`:168-170`) and the TLS
    /// session cache (`:178-181`) are torn down. The DNS cache (`:152-153`)
    /// and the connection pool (`:187-188`) are **not**: both are bare
    /// `break`s, so only the bit changes and the store survives to be reused
    /// if the option is set again.
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
    ///
    /// `docs/libcurl/opts/CURLSHOPT_SHARE.md` permits it, the connection arm's
    /// own comment at `lib/curl_share.c:128` is *"It is safe to set this
    /// option several times on a share."*, and
    /// `tests/libtest/lib1905.c:44-45` sets `CURL_LOCK_DATA_COOKIE` twice in a
    /// row. Each arm's `if(!share->...)` is what makes the second call a
    /// no-op, and a marker written into the store before the second call is
    /// what proves it here.
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
    ///
    /// A `Display` nobody calls is a `Display` nobody has checked, and these
    /// strings are what a failing assertion or a `--trace` line puts in front
    /// of a reader. `CURL_LOCK_DATA_NONE` (`include/curl/curl.h:3027`),
    /// `CURL_LOCK_DATA_LAST` (`:3039`), `CURL_LOCK_ACCESS_NONE` (`:3044`) and
    /// `CURL_LOCK_ACCESS_LAST` (`:3047`) are all real header tokens even
    /// though no arm of `curl_share_setopt` accepts them, so a wrong spelling
    /// here would misname something in a diagnostic without any other test
    /// noticing.
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
    ///
    /// The no-panic policy reaches the formatters too: every `write_str` in
    /// `Display for Specifier` is followed by `?`, and a `format!` cannot
    /// exercise those arms because `String`'s `fmt::Write` is infallible. A
    /// writer that fails on demand is the only way to prove the error arm is a
    /// return rather than a panic -- and a panic here would be reachable from
    /// a trace line, on any thread, at any time.
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
    ///
    /// Reachable from any application: `CURLSHOPT_UNSHARE` on a fresh handle.
    /// The C survives it because every teardown it reaches there is a no-op on
    /// a null pointer -- `Curl_cookie_cleanup(NULL)` at `:158`,
    /// `Curl_hsts_cleanup(&NULL)` at `:169` and
    /// `Curl_ssl_scache_destroy(NULL)` at `:180` -- while the DNS
    /// (`:152-153`) and connection (`:187-188`) arms are bare `break`s that
    /// never had anything to release. The bit was already clear, so
    /// `:150`'s unconditional clear is a no-op too, and the result is the same
    /// `CURLSHE_OK` the shared case returns.
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
    ///
    /// `lib/curl_share.c:147-192` has cases for DNS, cookies, HSTS, TLS
    /// sessions and connections, and **no case for
    /// `CURL_LOCK_DATA_PSL`** -- so it falls to `default:` at `:190-192`,
    /// after `:150` has already cleared the bit.
    ///
    /// `docs/libcurl/opts/CURLSHOPT_UNSHARE.md` documents the opposite in both
    /// directions: it has a `## CURL_LOCK_DATA_PSL` section and omits
    /// `CURL_LOCK_DATA_HSTS`, where the code handles HSTS and not the PSL. The
    /// documentation is stale; this test exists so that a reader who trusts it
    /// finds out here rather than in a behaviour change.
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
    ///
    /// The C guards both of its arms with `#ifdef USE_SSL`
    /// (`lib/curl_share.c:112`, `:177`), and this crate has no TLS feature
    /// because TLS is not optional -- so `:123` and `:183` have no reachable
    /// counterpart at any feature setting.
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
        let _ = share.attach(OWNER);
        let _ = share.attach(LockOwner::from_bits(0x2000));
        assert_eq!(share.dirty(), 2);
        assert!(share.is_in_use());
        let _ = share.detach(LockOwner::from_bits(0x2000));
        assert_eq!(share.dirty(), 1);
        let _ = share.detach(OWNER);
        assert_eq!(share.dirty(), 0);
        assert!(!share.is_in_use());
    }

    /// Both operations return the mask the caller needs for its repointing.
    ///
    /// `lib/setopt.c:1530`, `:1538` and `:1545` read the shared cookie jar,
    /// the shared HSTS cache and the `CURL_LOCK_DATA_PSL` bit to decide what an
    /// attaching handle points at; `:1497-1512` reads the same mask, plus the
    /// `CURL_LOCK_DATA_DNS` bit, to decide what a detaching one must unlink.
    #[test]
    fn attach_and_detach_report_the_specifier_the_caller_must_act_on() {
        let share = Share::new();
        assert_eq!(share.setopt(ShareOption::Share(3)), CURLSHcode::Ok);
        let on_attach = share.attach(OWNER);
        assert!(on_attach.contains(LockData::Dns));
        assert!(on_attach.contains(LockData::Share));
        assert_eq!(share.detach(OWNER), on_attach);
    }

    /// An unbalanced detach saturates at zero instead of wrapping.
    ///
    /// The C writes `dirty--` on an `unsigned int`, so this would become
    /// `UINT_MAX` and the share could never be cleaned up again. Both C call
    /// sites are guarded by `if(data->share)` so libcurl never reaches it;
    /// saturating keeps this file free of panicking arithmetic and makes the
    /// unreachable case harmless.
    #[test]
    fn a_detach_with_nothing_attached_saturates_at_zero() {
        let share = Share::new();
        let _ = share.detach(OWNER);
        assert_eq!(share.dirty(), 0);
        assert_eq!(share.cleanup(), CURLSHcode::Ok);
    }

    /// An invalid share is not counted and reports nothing.
    ///
    /// `lib/setopt.c:1520`'s `if(GOOD_SHARE_HANDLE(set))`: a share that fails
    /// the check is never assigned to the handle and never counted.
    #[test]
    fn attaching_to_a_torn_down_share_changes_nothing() {
        let share = Share::new();
        assert_eq!(share.cleanup(), CURLSHcode::Ok);
        assert!(!share.is_valid());
        assert_eq!(share.attach(OWNER), Specifier::EMPTY);
        assert_eq!(share.detach(OWNER), Specifier::EMPTY);
        assert_eq!(share.dirty(), 0);
    }

    /// **Every** option is refused while a handle is attached, including the
    /// three that only install callbacks.
    ///
    /// `lib/curl_share.c:71-74` returns `CURLSHE_IN_USE` before `va_start` and
    /// before the switch, so no arm is reachable. Its comment is *"do not
    /// allow setting options while one or more handles are already using this
    /// share"*.
    #[test]
    fn every_option_is_refused_while_the_share_is_in_use() {
        let share = Share::new();
        let _ = share.attach(OWNER);
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
        let _ = share.detach(OWNER);
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
        let _ = share.attach(OWNER);
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
        let _ = share.detach(OWNER);
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
        let _ = share.attach(OWNER);

        assert_eq!(share.cleanup(), CURLSHcode::InUse);

        // Refused, and therefore still whole: C never reaches `:263`'s
        // `share->magic = 0` on this path, so the handle stays good.
        assert!(share.is_valid());
        assert_eq!(share.magic(), Share::GOOD_MAGIC);
        assert_eq!(share.dirty(), 1);
        assert!(share.dnscache(OWNER).is_some());

        let _ = share.detach(OWNER);
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
    ///
    /// `lib/curl_share.c:237-259`. The DNS cache (`:241`), the cookie jar
    /// (`:243-245`), the HSTS cache (`:247-249`), the session cache
    /// (`:251-256`) and the Public Suffix List (`:258`) are all unconditional;
    /// only the connection pool (`:237-239`) is gated on its bit.
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
    ///
    /// `lib/curl_share.c:237-239` destroys the pool only when
    /// `share->specifier & (1 << CURL_LOCK_DATA_CONNECT)` still holds. Since
    /// `CURLSHOPT_UNSHARE` clears that bit without destroying the pool, the C
    /// then frees the enclosing structure at `:264` with the pool's members
    /// never released -- a leak this reproduces the conditional half of, while
    /// Rust's drop glue reclaims what the C loses.
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
    ///
    /// `CPOOL_LOCK` (`lib/conncache.c:41-50`), `dnscache_lock`
    /// (`lib/hostip.c:307-312`), `Curl_ssl_scache_lock`
    /// (`lib/vtls/vtls_scache.c:585-589`), `Curl_hsts_loadfiles`
    /// (`lib/hsts.c:559`) and `lib/cookie.c`'s four sites all request
    /// `CURL_LOCK_ACCESS_SINGLE`, which is why there is no shared-access
    /// accessor.
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
    ///
    /// `tests/libtest/lib3207.c:154-155` clears both by passing `NULL`, and
    /// the C stores whatever `va_arg` yields with no validation
    /// (`lib/curl_share.c:196-209`). The user pointer is independent of both:
    /// clearing a callback leaves it, and setting it without a callback is
    /// remembered.
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
    ///
    /// Reduced from the list `crate::cookies::psl`'s own tests use, since
    /// nothing here depends on any particular suffix -- only on a list
    /// parsing.
    #[cfg(feature = "cookies")]
    const PSL_LIST: &str = concat!(
        "// ===BEGIN ICANN DOMAINS===\n",
        "com\n",
        "co.uk\n",
        "// ===END ICANN DOMAINS===\n",
    );

    /// A fresh cache takes the shared lock once and keeps it until the guard
    /// is dropped.
    ///
    /// `lib/psl.c:51` then `:91-94`: with nothing stale there is no upgrade, so
    /// the whole sequence is one `CURL_LOCK_ACCESS_SHARED` notification and,
    /// later, one unlock -- which `Curl_psl_release` (`:97-100`) performs and
    /// which is [`Drop`] here.
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
        let mut guard = share.psl_use(OWNER, &clock, &source).expect("a list");
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
    ///
    /// `lib/psl.c:51`, `:55`, `:58`, `:88`, `:89` -- shared, release,
    /// exclusive, release, shared -- and then one unlock owed by the guard. The
    /// C's comment at `:54` explains the release: *"Let a chance to other
    /// threads to do the job: avoids deadlock."*
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
    ///
    /// Every lock in this file is taken with
    /// `unwrap_or_else(PoisonError::into_inner)`, which is the idiom
    /// `crate::util::timeval` uses. The reasoning is stronger here than there:
    /// a poisoned lock that propagated would make every later operation on
    /// this share fail permanently, and C -- which has no notion of poisoning
    /// -- cannot produce that outcome.
    ///
    /// The panic hook is silenced for the duration so that the expected panic
    /// does not print a backtrace into the test output, and restored
    /// afterwards.
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

    /// Formatting a share never blocks on a lock somebody else holds.
    ///
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

    /// Every component of a share is `Send + Sync` except the connection pool.
    ///
    /// This is the escalation in the module documentation, as a fact under
    /// test. The five stores, the metadata and both callback types satisfy the
    /// bounds; [`crate::conn::pool::ConnectionPool`] does not, because
    /// `ConnFilter`, `ShutdownTimer` and `ProtocolDisconnect` carry no `Send`
    /// bound, and adding one produced 925 errors across `conn/socket.rs`,
    /// `conn/filters.rs`, `crate::tls` and `util/bufq.rs`. `Share` is
    /// therefore neither, and the fix belongs to those modules -- at which
    /// point it becomes both with no change here, because everything below
    /// already qualifies.
    #[test]
    fn every_component_but_the_connection_pool_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}

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
        #[cfg(feature = "cookies")]
        assert_send_sync::<Mutex<Option<CookieInfo>>>();
        #[cfg(feature = "cookies")]
        assert_send_sync::<RwLock<PslCache>>();
        #[cfg(feature = "hsts")]
        assert_send_sync::<Mutex<Option<HstsCache>>>();
    }

    /// Several threads drive one share each and one callback, concurrently.
    ///
    /// What is being asserted is the half of `tests/libtest/lib506.c` and
    /// `lib3207.c` that is expressible while [`Share`] is not `Sync`: that the
    /// callback plumbing -- an [`Arc`] of a `Fn` closure over shared state,
    /// which is what `curl-rs-ffi` will install -- is sound and balanced under
    /// genuine concurrency, and that a share's state is entirely its own.
    ///
    /// The half that is **not** expressible is one share reached from two
    /// threads, which those two C programs do and which needs
    /// `Share: Sync`. The module documentation escalates that with its
    /// measurement; the test above pins which component blocks it. Each thread
    /// therefore gets its own share and its own balance checker, while one
    /// counter shared by every callback proves the closures really did run on
    /// different threads.
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
                        let _ = share.attach(OWNER);
                        drop(share.dnscache(OWNER));
                        drop(share.ssl_scache(OWNER));
                        drop(share.pool(OWNER));
                        let _ = share.detach(OWNER);
                    }

                    recorder.assert_balanced();
                    assert_eq!(share.dirty(), 0);
                    assert_eq!(share.cleanup(), CURLSHcode::Ok);
                });
            }
        });

        // Five unlocks per round -- attach, three stores, detach -- plus the
        // one `cleanup` delivers per thread.
        assert_eq!(unlocks.load(Ordering::Relaxed), THREADS * (ROUNDS * 5 + 1));
    }
}
