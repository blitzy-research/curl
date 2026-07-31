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

//! Operating-system integration: the residue that no safe crate expresses.
//!
//! # Why this module exists at all
//!
//! `curl-rs-lib` is a safe crate. Its root denies the `unsafe_code` lint, and
//! exactly one module in the whole crate is exempt: `mod ffi`, whose
//! declaration in `curl-rs-lib/src/lib.rs` carries the crate's one and only
//! relaxation of that lint. A lint level attached to a `mod foo;` *item*
//! propagates into that module's contents even when the body lives in a
//! separate file, so this file inherits the exemption and **must not restate
//! it** -- a second relaxation anywhere under `src/ffi/` would turn a
//! compiler-checked invariant back into a review-checked one, and would defeat
//! the grep gate that polices it. That gate greps `curl-rs-lib/src` for the
//! relaxation and requires exactly one hit, in `lib.rs`; the token is
//! therefore deliberately absent from this file, including its prose.
//!
//! A related detail, recorded because it decides an implementation choice in
//! `lib.rs` rather than here: the root must use `deny`, not `forbid`. `forbid`
//! is `deny` plus a prohibition on relaxing the level later, so a `forbid` root
//! followed by a relaxation on `mod ffi` yields `error[E0453]`. If that error
//! ever appears while building this file, the fix belongs in `lib.rs`; adding
//! any lint attribute here instead would create the second exemption above.
//!
//! Two files sit inside that exemption. `ffi/gss.rs` binds the optional
//! GSS-API used by Negotiate, behind the non-default `negotiate` feature. This
//! file is the other and the larger: every operating-system call that
//! `socket2` cannot express, behind safe wrappers, and nowhere else in the
//! crate. Each raw call is paired with a `// SAFETY:` comment that names the
//! precondition being upheld and why it holds at that site.
//!
//! # What it supersedes, measured
//!
//! | C source | Lines | Reproduced here as |
//! |----------|-------|--------------------|
//! | `lib/curl_gethostname.c:44-96` | 96 | [`gethostname`] |
//! | `lib/curl_gethostname.h:28,31` | -- | [`HOSTNAME_MAX`], the wrapper's signature |
//! | `lib/curl_setup.h:649-655` | -- | the `usize` length parameter (see below) |
//! | `lib/if2ip.c:92-174` | 262 | [`interface_addrs`], [`interface_names`] |
//! | `lib/if2ip.h:29-45` | -- | referenced only; the verdict logic lives elsewhere |
//! | `lib/url.c:1615` | -- | [`if_nametoindex`] |
//! | `lib/memdebug.c:184-368` | 577 | `memdebug`, behind a default-off feature |
//!
//! # The `socket2`-first obligation
//!
//! Every function here enlarges the audit burden permanently, so the module is
//! deliberately small. The following were each checked against the C source
//! and are covered by `socket2`; they belong in `conn/socket.rs` and must
//! never appear in this file:
//!
//! * `lib/curlx/nonblock.c:48-63` -- on all four mandated targets the C takes
//!   the `HAVE_FCNTL_O_NONBLOCK` branch, `fcntl(F_GETFL)` then
//!   `fcntl(F_SETFL, flags | O_NONBLOCK)`, which is precisely
//!   `socket2::Socket::set_nonblocking`. The short-circuit at `nonblock.c:57`
//!   is a pure optimisation and performance is an explicit non-goal. The
//!   Amiga `IoctlSocket`, Windows `ioctlsocket` and Orbis `SO_NONBLOCK`
//!   branches at `nonblock.c:65-88` are excluded platforms.
//! * `getsockname` / `getpeername` (`lib/cf-socket.c:1006,1996`,
//!   `lib/socketpair.c:187`, `lib/ftp.c:1024,1107`) -- `Socket::local_addr`
//!   and `Socket::peer_addr`.
//! * every `setsockopt`, `getsockopt` and `fcntl` -- `socket2` methods.
//! * the `ioctl(dummy, SIOCGIFADDR, &req)` fallback at `lib/if2ip.c:218` --
//!   dead on all four targets, and its own comment at `lib/if2ip.c:223-225`
//!   admits it "cannot tell the difference between an interface that does not
//!   exist and an interface that has no address of the correct family".
//!
//! # The testability seam
//!
//! Miri cannot execute a foreign function, and a clean Miri run over this
//! crate is a required gate. Every raw call therefore sits behind
//! [`SysCalls`]: [`RealSys`] is the only implementation that touches the
//! kernel, and it hands back **owned** Rust values -- never a raw pointer,
//! never a borrowed `sockaddr`, never a live `getifaddrs` list. All of the
//! logic that can go wrong (buffer termination, truncation, address decoding,
//! error mapping, interior-NUL rejection) lives on the safe side of that seam
//! and is exercised in `mod tests` against a pure-Rust fake, so Miri covers it
//! without a syscall. The handful of tests that do call the kernel are
//! `#[cfg_attr(miri, ignore)]`d and say so.
//!
//! The seam carries no state: [`RealSys`] is a unit struct, and there is no
//! `static mut` and no lazily initialised singleton anywhere in the module.
//! The one exception is unavoidable and documented in the `memdebug` module
//! below, because a `GlobalAlloc` is necessarily process-global.
//!
//! # Platform scope
//!
//! The four mandated targets are `x86_64-unknown-linux-gnu`,
//! `aarch64-unknown-linux-gnu`, `x86_64-apple-darwin` and
//! `aarch64-apple-darwin`: all 64-bit, all Unix. Divergence between them is
//! expressed with `#[cfg(target_os = ...)]`, never with a Cargo feature. No
//! Windows, AmigaOS, OS/400 or VMS path appears here, and none may be added
//! "for completeness" -- those platforms are excluded outright.
//!
//! One layout difference between the two operating systems is load-bearing and
//! is handled by construction rather than by branching. On Linux
//! `struct sockaddr` is `{ sa_family: u16, sa_data }`, so the family sits at
//! offset 0; on Darwin it is `{ sa_len: u8, sa_family: u8, sa_data }`, so the
//! family sits at offset 1 and is one byte wide. Reading a `u16` from offset 0
//! would silently produce nonsense on two of the four targets. Every field is
//! therefore addressed through `core::ptr::addr_of!` on the matching `libc`
//! struct, which encodes each platform's offsets, and loaded with
//! `read_unaligned`, which additionally removes any assumption about the
//! alignment of memory this crate did not allocate. Only the bytes actually
//! needed are read: copying a whole 16-byte `sockaddr` out of a node whose
//! real family is `AF_PACKET` or `AF_LINK` could over-read the allocation and
//! trip AddressSanitizer.

// `dead_code` is allowed for this module alone, and for one specific reason
// rather than as a convenience: every consumer of these wrappers lives in
// another module -- `dns/if2ip.rs` for the interface snapshot, `protocols/mod.rs`
// and `url/` for the zone-id lookup, and `lib.rs` for the optional allocator --
// so until those land each wrapper is legitimately unreferenced inside the
// crate, and the zero-warnings gate would otherwise fail on code that is
// correct. No lint level for `unsafe_code` is set here, at any level, by
// design: see the module documentation above.
#![allow(dead_code)]

use core::ptr;
use std::ffi::{CStr, CString};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::{CURLcode, CodeResult};

/// Hostname buffer size, from `lib/curl_gethostname.h:28`
/// (`#define HOSTNAME_MAX 1024`).
///
/// Exposed so that a caller which needs to size its own buffer sizes it
/// identically to the C tree. Its sole C consumer is `lib/smtp.c:187`, which
/// declares `char localhost[HOSTNAME_MAX + 1]` and passes
/// `sizeof(localhost)` at `lib/smtp.c:191` -- so the effective `namelen` in C
/// is 1025, and [`gethostname`] uses exactly that many bytes.
pub(crate) const HOSTNAME_MAX: usize = 1024;

// ===========================================================================
// The syscall seam
// ===========================================================================

/// One address of one interface, copied out of operating-system memory.
///
/// This is the raw shape [`SysCalls::ifaddrs`] returns: a faithful,
/// *undecided* snapshot of one `struct ifaddrs` node. Nothing here is
/// interpreted -- that happens in [`interface_addrs`] on the safe side of the
/// seam, which is what lets a pure-Rust fake drive it under Miri.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IfNode {
    /// `ifa_name`, as raw bytes with no trailing NUL.
    ///
    /// Kept as bytes rather than a `String` because the kernel does not
    /// promise UTF-8 and this layer does not decide policy. A NULL `ifa_name`
    /// -- which POSIX does not permit but which costs nothing to tolerate --
    /// is reported as an empty name rather than dereferenced.
    pub(crate) name: Vec<u8>,

    /// The decoded `ifa_addr`, or [`None`] when `ifa_addr` was NULL.
    ///
    /// The NULL case is not merely possible, it is common: `lib/if2ip.c:111`
    /// guards every dereference with `if(iface->ifa_addr)`. Encoding it as
    /// [`None`] rather than dropping the node lets the safe layer reproduce
    /// that skip, and lets a fake prove the skip happens.
    pub(crate) addr: Option<RawIfAddr>,
}

/// An interface address as the kernel reported it, before any policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RawIfAddr {
    /// `AF_INET`: the four octets of `sin_addr`, in network order.
    V4([u8; 4]),

    /// `AF_INET6`: the sixteen octets of `sin6_addr`, plus `sin6_scope_id`.
    V6 {
        /// `sin6_addr.s6_addr`, in network order.
        octets: [u8; 16],
        /// `sin6_scope_id`, read at `lib/if2ip.c:138-139`. Zero when unscoped.
        scope_id: u32,
    },

    /// An address family this layer does not represent.
    ///
    /// Every interface reported by `getifaddrs(3)` has at least one such node
    /// on the mandated targets -- `AF_PACKET` on Linux, `AF_LINK` on Darwin --
    /// and `lib/if2ip.c:163-166` depends on seeing them: a node whose family
    /// does not match the requested one but whose *name* does downgrades the
    /// verdict to `IF2IP_AF_NOT_SUPPORTED`, which is materially different from
    /// `IF2IP_NOT_FOUND`. Preserving the variant is what lets
    /// [`interface_names`] reproduce that distinction.
    Unrepresentable,
}

/// The operating-system calls this module performs.
///
/// Split out as a trait for one reason: `cargo +nightly miri test` is a
/// required gate and Miri cannot call a foreign function. [`RealSys`] performs
/// the real calls; `mod tests` substitutes a pure-Rust fake and thereby covers
/// every branch of the surrounding logic under Miri.
///
/// The trait is deliberately narrow. It exposes the three primitives that have
/// no safe equivalent and nothing else, and every method returns owned data so
/// that no raw pointer or foreign-owned allocation can escape an
/// implementation.
pub(crate) trait SysCalls {
    /// Fills `buf` with the local hostname, as `gethostname(2)` does.
    ///
    /// The buffer is passed through verbatim. The callee is **not** required to
    /// NUL-terminate it: POSIX permits `gethostname` to truncate without a
    /// terminator when the buffer is too small, and reproducing
    /// `lib/curl_gethostname.c:84` is the *caller's* job precisely because the
    /// C does it unconditionally, after the call, whether or not it failed.
    fn gethostname(&self, buf: &mut [u8]) -> io::Result<()>;

    /// Snapshots every interface address, as `getifaddrs(3)` reports them.
    ///
    /// Order is preserved, duplicates are preserved, and nodes with a NULL
    /// `ifa_addr` are preserved as [`IfNode::addr`] = [`None`]: the list is a
    /// transcription, not a selection.
    fn ifaddrs(&self) -> io::Result<Vec<IfNode>>;

    /// Resolves an interface name to its numeric index.
    ///
    /// [`None`] on failure. `if_nametoindex(3)` signals failure by returning
    /// `0`, which is never a valid index, so the mapping is exact and loses
    /// nothing.
    fn if_nametoindex(&self, name: &CStr) -> Option<u32>;
}

/// The real operating system.
///
/// The only implementation of [`SysCalls`] that performs a foreign call, and
/// therefore the only place in `curl-rs-lib` outside `ffi/gss.rs` where a raw
/// call appears. It carries no state, so constructing it is free and it is
/// interchangeable with a fake at every call site.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct RealSys;

impl SysCalls for RealSys {
    fn gethostname(&self, buf: &mut [u8]) -> io::Result<()> {
        // `gethostname(2)` is specified over a non-empty buffer; a zero-length
        // one has no valid outcome, and forwarding it would hand the kernel a
        // one-past-the-end pointer. Reject it the way the kernel would, before
        // any raw call happens.
        if buf.is_empty() {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }

        // SAFETY: `libc::gethostname` writes at most `len` bytes into `name` and
        // never reads it. `buf` is a live, uniquely borrowed slice of exactly
        // `buf.len()` initialised bytes; `as_mut_ptr` yields a pointer valid for
        // that many writes and the length argument is that same value, so the
        // write cannot overrun. `libc::c_char` is `i8` on all four mandated
        // targets and `u8` and `i8` share size and alignment, so the cast
        // changes only the signedness the C prototype spells. The result is NOT
        // assumed to be NUL-terminated -- POSIX permits truncation without a
        // terminator -- and `gethostname_with` forces one, reproducing
        // lib/curl_gethostname.c:84.
        let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast::<libc::c_char>(), buf.len()) };

        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn ifaddrs(&self) -> io::Result<Vec<IfNode>> {
        let mut head: *mut libc::ifaddrs = ptr::null_mut();

        // SAFETY: `libc::getifaddrs` writes one pointer through its argument and
        // reads nothing; `&mut head` is a valid, uniquely borrowed, properly
        // aligned `*mut *mut ifaddrs` over live stack storage. On success it
        // transfers ownership of a linked list to this thread, which is why the
        // next statement moves that pointer into `IfAddrsList` -- a guard whose
        // `Drop` calls `freeifaddrs` on every path out of this function,
        // including an early `?` and an unwind, so the list cannot leak under
        // Miri or LeakSanitizer. On failure it stores nothing and there is
        // nothing to release.
        let rc = unsafe { libc::getifaddrs(&mut head) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }

        let list = IfAddrsList(head);
        let mut nodes = Vec::new();
        let mut cursor: *mut libc::ifaddrs = list.0;
        while !cursor.is_null() {
            // SAFETY: `cursor` is either the head `getifaddrs` just produced or
            // an `ifa_next` read out of a node of that same list, and `list`
            // keeps the whole list alive for the duration of this loop, so it
            // points at a live, initialised `struct ifaddrs`. `read_if_node`
            // copies out everything it needs, so its result borrows nothing from
            // the list and stays valid after the guard releases it.
            let node = unsafe { read_if_node(cursor) };
            nodes.push(node);

            // SAFETY: same justification as the read above. `addr_of!` forms the
            // address of the `ifa_next` field without loading the node, and
            // `read_unaligned` then copies that single pointer without assuming
            // the node is aligned. The list is terminated by a null `ifa_next`,
            // which the loop condition tests before the next dereference.
            cursor = unsafe { ptr::addr_of!((*cursor).ifa_next).read_unaligned() };
        }

        Ok(nodes)
    }

    fn if_nametoindex(&self, name: &CStr) -> Option<u32> {
        // SAFETY: `libc::if_nametoindex` reads a NUL-terminated C string and
        // writes nothing. `CStr::as_ptr` yields exactly that -- a pointer to a
        // live, NUL-terminated byte sequence owned by the caller and borrowed
        // for no longer than this call. The function is specified to return `0`
        // on failure and `0` is never a valid index, so no other channel needs
        // consulting to classify the outcome.
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };

        if index == 0 {
            None
        } else {
            Some(index)
        }
    }
}

/// Owns the list `getifaddrs(3)` allocates and releases it in `Drop`.
///
/// A guard rather than a hand-placed `freeifaddrs` call because leak-freedom
/// here is a gate rather than a nicety: Miri and AddressSanitizer both run over
/// this crate. `Drop` runs on the normal path, on every `?`, and on an unwind,
/// so adding an early return to the walk in [`SysCalls::ifaddrs`] cannot
/// silently start leaking.
struct IfAddrsList(*mut libc::ifaddrs);

impl Drop for IfAddrsList {
    fn drop(&mut self) {
        // `getifaddrs` may legitimately report success while storing NULL -- a
        // host with no interfaces at all -- and `freeifaddrs(NULL)` is not
        // specified, so it is never called with one.
        if self.0.is_null() {
            return;
        }

        // SAFETY: `self.0` is the head pointer a successful `getifaddrs`
        // returned, and it has just been null-checked. Ownership moved into this
        // guard at construction and no copy of it is handed out, so this is the
        // one and only release of that list and it happens exactly once, when
        // the guard is dropped.
        unsafe { libc::freeifaddrs(self.0) };
    }
}

/// Copies one `struct ifaddrs` node into owned Rust storage.
///
/// The whole of the raw address decoding, kept in one function so that the
/// audit surface is a single place. It allocates no foreign memory and the
/// value it returns borrows nothing.
///
/// # Safety
///
/// `node` must point at a live, initialised `struct ifaddrs` as produced by
/// `getifaddrs(3)` and not yet released by `freeifaddrs(3)`. Its `ifa_name`
/// must be NULL or a NUL-terminated C string, and its `ifa_addr` must be NULL
/// or a `struct sockaddr` whose `sa_family` truthfully describes the storage
/// that follows it. `getifaddrs(3)` guarantees all three.
// SAFETY: this item is `unsafe fn` because it cannot validate its argument; the
// contract it requires is stated in the `# Safety` section above and every
// dereference below is justified inline against it. Reads are confined to
// `ifa_name`, `ifa_addr`, and the family-appropriate prefix of the address.
unsafe fn read_if_node(node: *const libc::ifaddrs) -> IfNode {
    // SAFETY: `node` points at a live `struct ifaddrs` per this function's
    // contract. `addr_of!` forms the address of `ifa_name` without loading the
    // node, and `read_unaligned` copies that one pointer without assuming the
    // node is aligned.
    let name_ptr = unsafe { ptr::addr_of!((*node).ifa_name).read_unaligned() };

    let name = if name_ptr.is_null() {
        // POSIX does not permit a NULL `ifa_name` and the C never checks for one
        // -- `lib/if2ip.c:113` hands it straight to `curl_strequal`. Tolerating
        // it costs nothing, an empty name can never match a real interface, and
        // it turns a hypothetical NULL dereference into a value.
        Vec::new()
    } else {
        // SAFETY: `name_ptr` is non-null and, per this function's contract, is a
        // NUL-terminated C string inside the `getifaddrs` allocation, which
        // outlives this call. `CStr::from_ptr` borrows it only for this
        // expression and `to_vec` copies the bytes out before that borrow ends,
        // so no reference to foreign memory escapes.
        unsafe { CStr::from_ptr(name_ptr) }.to_bytes().to_vec()
    };

    // SAFETY: `node` is a live `getifaddrs` entry for the whole of this
    // function, per this function's own safety contract, so projecting to its
    // `ifa_addr` field is in bounds of an allocated object. `addr_of!` forms the
    // field pointer without ever creating a reference to a possibly-unaligned
    // or possibly-null place, and `read_unaligned` copies out only the pointer
    // value itself -- the `sockaddr` it designates is not loaded here, which
    // matters because that pointee may be shorter than a `sockaddr` and may be
    // null. Both cases are handled below rather than by this read.
    let addr_ptr = unsafe { ptr::addr_of!((*node).ifa_addr).read_unaligned() };

    let addr = if addr_ptr.is_null() {
        // lib/if2ip.c:111 -- `if(iface->ifa_addr)`. Not defensive programming: a
        // node with no address is ordinary, and the C skips it too.
        None
    } else {
        // SAFETY: `addr_ptr` is non-null and points at a `struct sockaddr` per
        // this function's contract. Only `sa_family` is read, through `addr_of!`
        // on the `libc` struct so the offset is the one this target actually
        // uses -- offset 0 and two bytes wide on Linux, offset 1 and one byte
        // wide on Darwin -- and with `read_unaligned` so no alignment is
        // assumed. Reading only this field cannot over-read even when the real
        // family is `AF_PACKET` or `AF_LINK`, because every `sockaddr` variant
        // begins with it.
        let family = unsafe { ptr::addr_of!((*addr_ptr).sa_family).read_unaligned() };

        // `sa_family_t` is `u16` on Linux and `u8` on Darwin; widening either to
        // the `c_int` that the `AF_*` constants are spelled as is exact.
        match i32::from(family) {
            libc::AF_INET => {
                let sin = addr_ptr.cast::<libc::sockaddr_in>();
                // SAFETY: the family read above states that this node's address
                // is a `struct sockaddr_in`, so the pointee really is that type
                // and `sin_addr` lies within it. `addr_of!` plus
                // `read_unaligned` copies only that field, so nothing beyond the
                // 16 bytes an `AF_INET` node always has is touched.
                let raw = unsafe { ptr::addr_of!((*sin).sin_addr).read_unaligned() };
                // `s_addr` is held in network byte order, so its in-memory bytes
                // ARE the dotted-quad octets; `to_ne_bytes` yields them in that
                // order on a little-endian and a big-endian host alike.
                Some(RawIfAddr::V4(raw.s_addr.to_ne_bytes()))
            }
            libc::AF_INET6 => {
                let sin6 = addr_ptr.cast::<libc::sockaddr_in6>();
                // SAFETY: the family read above states that this node's address
                // is a `struct sockaddr_in6`, so both fields read here lie
                // within the pointee. `addr_of!` plus `read_unaligned` copies
                // each one without assuming the node is 4-byte aligned.
                let raw = unsafe { ptr::addr_of!((*sin6).sin6_addr).read_unaligned() };
                // SAFETY: as immediately above -- `sin6_scope_id` is a field of
                // the same `struct sockaddr_in6` that the family identified, and
                // is read the same way. This is the value lib/if2ip.c:138-139
                // reads and without which a link-local `--interface` cannot
                // work.
                let scope_id = unsafe { ptr::addr_of!((*sin6).sin6_scope_id).read_unaligned() };
                Some(RawIfAddr::V6 {
                    octets: raw.s6_addr,
                    scope_id,
                })
            }
            // `AF_PACKET` on Linux, `AF_LINK` on Darwin, and anything else.
            // Neither an error nor a silent drop; see `RawIfAddr::Unrepresentable`.
            _ => Some(RawIfAddr::Unrepresentable),
        }
    };

    IfNode { name, addr }
}

// ===========================================================================
// gethostname -- supersedes lib/curl_gethostname.c:44-96
// ===========================================================================

/// The local machine's **un-qualified** hostname.
///
/// # What the C does, and therefore what this does
///
/// `Curl_gethostname` is `int Curl_gethostname(char * const name,
/// GETHOSTNAME_TYPE_ARG2 namelen)`. `GETHOSTNAME_TYPE_ARG2` is `int` only
/// `#ifdef USE_WINSOCK` and `size_t` otherwise (`lib/curl_setup.h:649-655`),
/// and Windows is an excluded platform, so the length is a `usize` -- which is
/// exactly the `size_t` that `libc::gethostname` declares.
///
/// The five observable steps of `lib/curl_gethostname.c` are reproduced in
/// order, and the order matters:
///
/// 1. `name[0] = '\0'` **before** the call (`:69` / `:75`).
/// 2. `gethostname(name, namelen)` (`:70` / `:79`).
/// 3. `name[namelen - 1] = '\0'` **unconditionally** (`:84`). This statement
///    sits outside the `if`/`else`, so it runs even when the call failed;
///    getting this wrong is how a truncated, unterminated buffer becomes an
///    over-read.
/// 4. `if(err) return err;` (`:86-87`) -- only now is failure reported.
/// 5. `dot = strchr(name, '.'); if(dot) *dot = '\0';` (`:90-92`) -- truncate at
///    the **first** dot, then `return 0` (`:94`).
///
/// Step 5 is the defining semantic and the reason no crate substitutes for
/// this. `lib/curl_gethostname.c:40-41` states it outright: "The function
/// always returns the un-qualified hostname rather than being provider
/// dependent."
///
/// # Deliberate omissions, with the evidence for each
///
/// * **The `CURL_GETHOSTNAME` environment override is not implemented.** It is
///   `#ifdef DEBUGBUILD`-only (`lib/curl_gethostname.c:57-71`) and
///   `grep -rn "CURL_GETHOSTNAME" tests/` returns zero hits -- no fixture, no
///   harness module and no test server sets it. The chosen posture of not
///   advertising the `Debug` feature makes it unreachable in any case. It is
///   recorded here rather than dropped silently.
/// * **The `__AMIGA__` branch (`:76-78`) is not implemented.** AmigaOS is an
///   excluded platform.
/// * **The C doc comment's NTLM justification is stale; do not act on it.**
///   `lib/curl_gethostname.c:32-34` claims the override "is used by the test
///   suite to verify exact matching of NTLM authentication". That is no longer
///   true. Modern curl never puts the real hostname in an NTLM message:
///   `lib/vauth/ntlm.c:579-581` declares
///   `static const char host[] = "WORKSTATION";` with the comment "The fixed
///   hostname we provide, in order to not leak our real local host name", and
///   the Type-1 message at `lib/vauth/ntlm.c:448` uses
///   `const char *host = ""; /* empty */` while `:459` discards the `hostname`
///   parameter outright with `(void)hostname;`. **`auth/ntlm.rs` must hard-code
///   `"WORKSTATION"` for Type-3 and `""` for Type-1 and must not call this
///   function.** That is a byte-exactness requirement, not a style preference:
///   53 fixtures gate on the `NTLM` feature and their messages are compared
///   byte for byte.
/// * **There is currently no in-scope caller.**
///   `grep -rn "Curl_gethostname" lib/ src/ tests/` finds exactly one call
///   site, `lib/smtp.c:191`, and SMTP is out of scope. The wrapper exists
///   because it is the canonical example of the residue this module was created
///   for; it is not dead code to be deleted, and it is not to be wired into
///   NTLM.
///
/// # Errors
///
/// [`CURLcode::FailedInit`] when `gethostname(2)` fails. C returns the raw
/// `errno` and its one caller treats the result as a boolean
/// (`if(!Curl_gethostname(...))` at `lib/smtp.c:191`), so no integer contract
/// exists to preserve and the mapping is a free choice made here:
/// `CURLE_FAILED_INIT` is documented as covering "a resource problem where
/// something fundamental could not get done", which is exactly a failing local
/// host query. The operating-system detail is read through
/// [`io::Error::last_os_error`] inside [`RealSys`] rather than by touching
/// `errno` directly, and is deliberately not propagated: the error channel here
/// is a bare code, and no fixture compares this text.
///
/// A non-UTF-8 hostname is **not** an error. C hands the raw bytes back and
/// introducing a new failure mode would be a behaviour change, so invalid
/// sequences are replaced through [`String::from_utf8_lossy`]. In practice a
/// hostname is ASCII; this path exists so that a hostile one cannot panic.
pub(crate) fn gethostname() -> CodeResult<String> {
    gethostname_with(&RealSys)
}

/// [`gethostname`] over an injected [`SysCalls`].
///
/// Separated so that every branch above -- the forced terminator, the first-dot
/// truncation, the error mapping and the non-UTF-8 path -- is reachable under
/// Miri, which cannot call `gethostname(2)`.
pub(crate) fn gethostname_with(sys: &dyn SysCalls) -> CodeResult<String> {
    // Byte-for-byte the buffer the sole C call site uses: `lib/smtp.c:187`
    // declares `char localhost[HOSTNAME_MAX + 1]` and `lib/smtp.c:191` passes
    // `sizeof(localhost)`, so `namelen` is 1025 and the forced terminator of
    // lib/curl_gethostname.c:84 lands at index 1024.
    let mut buf = vec![0_u8; HOSTNAME_MAX + 1];

    // Step 1, lib/curl_gethostname.c:69 / :75 -- `name[0] = '\0'` happens before
    // the call. Written explicitly rather than relying on the zeroed allocation,
    // so the step survives any later change to how the buffer is created.
    buf[0] = 0;

    // Step 2, lib/curl_gethostname.c:70 / :79.
    let outcome = sys.gethostname(&mut buf);

    // Step 3, lib/curl_gethostname.c:84 -- UNCONDITIONAL. The C statement is
    // outside the `if`/`else`, so it runs even on failure, and it is what makes
    // the buffer safe to scan when the kernel truncated without terminating.
    let last = buf.len() - 1;
    buf[last] = 0;

    // Step 4, lib/curl_gethostname.c:86-87 -- report failure only after the
    // terminator has been forced.
    if outcome.is_err() {
        return Err(CURLcode::FailedInit);
    }

    // Step 5, lib/curl_gethostname.c:90-92 -- `strchr(name, '.')` stops at the
    // FIRST dot, leaving only the machine name. `position` is the direct
    // equivalent; `unwrap_or` supplies a total fallback rather than a panic, and
    // `buf[last]` was just set to 0 so the NUL search always succeeds anyway.
    let end = buf.iter().position(|&b| b == 0).unwrap_or(last);
    let host = &buf[..end];
    let dot = host.iter().position(|&b| b == b'.').unwrap_or(host.len());

    // Step 6, lib/curl_gethostname.c:94.
    Ok(String::from_utf8_lossy(&host[..dot]).into_owned())
}

// ===========================================================================
// Interface enumeration -- supersedes the HAVE_GETIFADDRS body of
// lib/if2ip.c:92-174
// ===========================================================================

/// One interface address, owned.
///
/// The snapshot [`interface_addrs`] returns. It holds no borrow of
/// operating-system memory, so it remains valid after `freeifaddrs(3)` has run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct InterfaceAddr {
    /// `ifa_name`, decoded losslessly where it is UTF-8.
    ///
    /// Comparison against a user-supplied `--interface` value is the caller's
    /// job and is **case-insensitive** in C (`lib/if2ip.c:113` uses
    /// `curl_strequal`); this field is the raw name, unfolded.
    pub(crate) name: String,

    /// The address itself.
    pub(crate) addr: IpAddr,

    /// IPv6 `sin6_scope_id`; `0` for IPv4 and for unscoped IPv6.
    ///
    /// Read at `lib/if2ip.c:138-139`. Surfacing it is not optional: without it
    /// the caller can neither match `local_scope_id` (`:142-147`) nor build the
    /// `%<scopeid>` suffix (`:149-150`, `:159`), and `--interface` with a
    /// link-local IPv6 address stops working.
    pub(crate) scope_id: u32,
}

/// Every IPv4 and IPv6 address currently configured on this host.
///
/// # Scope of this function
///
/// This is enumeration only. **None** of `Curl_if2ip`'s decision logic lives
/// here; all of it is safe code and belongs in `dns/if2ip.rs`:
///
/// * the verdict enum `if2ip_result_t` -- `IF2IP_NOT_FOUND = 0`,
///   `IF2IP_AF_NOT_SUPPORTED = 1`, `IF2IP_FOUND = 2` (`lib/if2ip.h:41-45`);
/// * the case-insensitive interface-name comparison (`lib/if2ip.c:113`, via
///   `curl_strequal`);
/// * the scope match against `remote_scope` and the `IF2IP_AF_NOT_SUPPORTED`
///   downgrade (`lib/if2ip.c:125-132`, `:142-147`);
/// * `Curl_ipv6_scope()` (`lib/if2ip.c:61-87`), pure logic over the address
///   bytes, with the constants `IPV6_SCOPE_GLOBAL 0`, `LINKLOCAL 1`,
///   `SITELOCAL 2`, `UNIQUELOCAL 3`, `NODELOCAL 4` (`lib/if2ip.h:29-33`);
/// * the `%<scopeid>` suffix, which C renders as
///   `curl_msnprintf(scope, sizeof(scope), "%%%u", scopeid)` into
///   `char scope[12]` (`lib/if2ip.c:150`) and appends as `"%s%s"` (`:159`).
///
/// Only the `HAVE_GETIFADDRS` body of `lib/if2ip.c` is reproduced. Both Linux
/// and macOS provide `getifaddrs`, so all four mandated targets take that
/// branch; the `HAVE_IOCTL_SIOCGIFADDR` fallback (`:176-237`) and the `#else`
/// stub (`:239-258`) are dead code here. `lib/if2ip.c:90` guards the file with
/// `#if !defined(CURL_DISABLE_BINDLOCAL) || !defined(CURL_DISABLE_FTP)`; both
/// `--interface` binding and FTP are in scope, so no feature gate applies.
///
/// # Errors
///
/// [`CURLcode::InterfaceFailed`] when `getifaddrs(3)` fails.
///
/// **A caller reproducing `Curl_if2ip` must map that error to
/// `IF2IP_NOT_FOUND`, not to a failure.** The C guards the entire walk with
/// `if(getifaddrs(&head) >= 0)` at `lib/if2ip.c:109` and falls through to
/// `return res` at `:173` with `res` still `IF2IP_NOT_FOUND`, so an
/// enumeration failure is indistinguishable from an absent interface and
/// `bindlocal` then retries the string as a hostname. Surfacing it as an error
/// here loses no information and keeps the syscall's outcome visible; silently
/// returning an empty list would hide it.
pub(crate) fn interface_addrs() -> CodeResult<Vec<InterfaceAddr>> {
    interface_addrs_with(&RealSys)
}

/// [`interface_addrs`] over an injected [`SysCalls`].
pub(crate) fn interface_addrs_with(sys: &dyn SysCalls) -> CodeResult<Vec<InterfaceAddr>> {
    let nodes = sys.ifaddrs().map_err(|_| CURLcode::InterfaceFailed)?;
    let mut addrs = Vec::with_capacity(nodes.len());

    for node in nodes {
        let raw = match node.addr {
            Some(raw) => raw,
            // lib/if2ip.c:111 -- `if(iface->ifa_addr)`. A node without an
            // address contributes nothing and is never dereferenced.
            None => continue,
        };

        // lib/if2ip.c:112 -- `if(iface->ifa_addr->sa_family == af)`. Only the two
        // internet families carry an address this layer can represent; see
        // `interface_names` for the family-mismatch case the C handles at
        // `:163-166`.
        let (addr, scope_id) = match raw {
            RawIfAddr::V4(octets) => (IpAddr::V4(Ipv4Addr::from(octets)), 0),
            RawIfAddr::V6 { octets, scope_id } => (IpAddr::V6(Ipv6Addr::from(octets)), scope_id),
            RawIfAddr::Unrepresentable => continue,
        };

        addrs.push(InterfaceAddr {
            name: String::from_utf8_lossy(&node.name).into_owned(),
            addr,
            scope_id,
        });
    }

    Ok(addrs)
}

/// Every interface name `getifaddrs(3)` reports, in list order.
///
/// # Why this exists alongside [`interface_addrs`]
///
/// Because [`InterfaceAddr::addr`] is an [`IpAddr`], the snapshot cannot
/// represent an interface that has no internet address at all -- and on both
/// mandated operating systems such an interface still appears in the list, with
/// an `AF_PACKET` node on Linux or an `AF_LINK` node on Darwin.
///
/// That case is observable. `lib/if2ip.c:163-166` reads:
///
/// ```text
/// else if((res == IF2IP_NOT_FOUND) &&
///         curl_strequal(iface->ifa_name, interf)) {
///   res = IF2IP_AF_NOT_SUPPORTED;
/// }
/// ```
///
/// so an interface that exists but has no address of the requested family
/// yields `IF2IP_AF_NOT_SUPPORTED`, which `bindlocal` turns into
/// `CURLE_INTERFACE_FAILED` -- whereas `IF2IP_NOT_FOUND` makes it fall back to
/// resolving the string as a hostname. Without the name list a caller cannot
/// tell those apart, and `--interface` on an address-less interface would
/// change behaviour. Providing the names closes that gap and adds no raw call:
/// it is a second projection of the same [`SysCalls::ifaddrs`] snapshot.
///
/// Nodes whose `ifa_addr` is NULL are excluded, because `lib/if2ip.c:111`
/// excludes them from the name comparison too. Duplicates are preserved: one
/// interface normally contributes several nodes, and collapsing them would
/// misrepresent the list.
///
/// # Errors
///
/// [`CURLcode::InterfaceFailed`], on the same terms as [`interface_addrs`].
pub(crate) fn interface_names() -> CodeResult<Vec<String>> {
    interface_names_with(&RealSys)
}

/// [`interface_names`] over an injected [`SysCalls`].
pub(crate) fn interface_names_with(sys: &dyn SysCalls) -> CodeResult<Vec<String>> {
    let nodes = sys.ifaddrs().map_err(|_| CURLcode::InterfaceFailed)?;

    Ok(nodes
        .iter()
        .filter(|node| node.addr.is_some())
        .map(|node| String::from_utf8_lossy(&node.name).into_owned())
        .collect())
}

// ===========================================================================
// if_nametoindex -- supersedes the call at lib/url.c:1615
// ===========================================================================

/// Resolves an IPv6 zone identifier to a numeric scope id.
///
/// This is the `%eth0` form of an IPv6 URL. `lib/url.c` parses the zone id at
/// `:1600`, uses it directly when it is numeric (`:1607-1610`), and otherwise
/// calls `if_nametoindex(zoneid)` at `:1615`. Neither `socket2` nor the
/// standard library exposes that call, so it is genuine residue.
///
/// The wrapper is total and free of side effects: it neither logs nor mutates
/// anything, which keeps it usable from the URL parser without dragging a
/// handle into this module.
///
/// # Errors
///
/// * [`CURLcode::BadFunctionArgument`] when `name` contains an interior NUL and
///   therefore cannot be a C string. [`CString::new`] reports this as an error
///   and the error is propagated rather than unwrapped -- a zone id comes from a
///   URL, so it is attacker-influenced input and must never panic.
/// * [`CURLcode::InterfaceFailed`] when no interface bears that name.
///   `if_nametoindex(3)` reports failure by returning `0`, which is never a
///   valid index.
///
/// **A caller reproducing `lib/url.c` must not propagate the second error.**
/// The C does not fail the transfer: `lib/url.c:1616-1623` merely emits
/// `infof(data, "Invalid zoneid: %s; %s", zoneid, strerror(errno))` under
/// `CURLVERBOSE` and leaves `conn->scope_id` untouched. No fixture compares
/// that text -- `grep -rl "Invalid zoneid" tests/data/` finds nothing -- but
/// turning a logged diagnostic into a hard failure would still be a behaviour
/// change.
pub(crate) fn if_nametoindex(name: &str) -> CodeResult<u32> {
    if_nametoindex_with(&RealSys, name)
}

/// [`if_nametoindex`] over an injected [`SysCalls`].
pub(crate) fn if_nametoindex_with(sys: &dyn SysCalls, name: &str) -> CodeResult<u32> {
    let cname = CString::new(name).map_err(|_| CURLcode::BadFunctionArgument)?;

    sys.if_nametoindex(&cname).ok_or(CURLcode::InterfaceFailed)
}

// ===========================================================================
// The counting allocator -- feature `memdebug`, DEFAULT OFF
// ===========================================================================

/// An allocation log in the format `tests/memanalyzer.pm` parses.
///
/// # Why it lives here
///
/// `impl GlobalAlloc` must be an `unsafe impl`, and this directory is the only
/// place in the crate where that is permitted. `curl-rs-lib/src/lib.rs`
/// therefore only *wires* the allocator; the implementation is here.
///
/// # Why it is off by default, and what that costs
///
/// `tests/runtests.pl:1759` wraps the whole memory check in
/// `if($feature{"TrackMemory"})`, and `:660` derives that feature from one
/// regex over the version banner: `$feature{"TrackMemory"} = $feat =~ /Debug/i;`
/// The chosen posture is not to advertise `Debug`, which makes all leak checking
/// and all 28 `<limits>` fixtures inert. The cost is stated openly rather than
/// hidden: 98 fixtures require `Debug` and skip, and `make torture-test`
/// hard-requires it (`tests/runtests.pl:847-849`) and is not applicable. This
/// module exists so that the trade can be reversed without a redesign.
///
/// What makes a Rust allocator viable at all is that the fixture assertion is a
/// **cap, not an equality**: `tests/runtests.pl:1786-1826` tests
/// `if($allocs > $lim_allocs)`, defaulting to 1000 allocations and 1,000,000
/// bytes when a fixture omits the block. A different-but-not-larger count
/// passes.
///
/// # Wiring
///
/// ```text
/// // in curl-rs-lib/src/lib.rs, and nowhere else:
/// #[cfg(feature = "memdebug")]
/// #[global_allocator]
/// static MEMDEBUG_ALLOCATOR: crate::ffi::sys::memdebug::TrackingAllocator =
///     crate::ffi::sys::memdebug::TrackingAllocator::new();
/// ```
///
/// # The record formats, measured
///
/// Every emitter in `lib/memdebug.c` was read and transcribed literally. The
/// asymmetric comma spacing is **not** a typo: `calloc` has none and `realloc`
/// has one, and `tests/memanalyzer.pm` parses both with regular expressions, so
/// either mistake breaks the parse.
///
/// | Line | Format |
/// |------|--------|
/// | `:228` | `MEM %s:%d malloc(%zu) = %p\n` |
/// | `:257` | `MEM %s:%d calloc(%zu,%zu) = %p\n` -- **no** space after the comma |
/// | `:282` | `MEM %s:%d strdup(%p) (%zu) = %p\n` |
/// | `:308` | `MEM %s:%d wcsdup(%p) (%zu) = %p\n` |
/// | `:349` | `MEM %s:%d realloc(%p, %zu) = %p\n` -- **one** space after the comma |
/// | `:368` | `MEM %s:%d free(%p)\n` |
/// | `:191` | `LIMIT %s:%d %s reached memlimit\n` |
/// | `:399`, `:414`, `:432`, `:450`, `:461` | `FD %s:%d socket() = %d`, socketpair/accept/sclose |
/// | `:478`, `:490`, `:502`, `:514` | `FILE %s:%d fopen("%s","%s") = %p`, freopen, fdopen, fclose |
/// | `:136` | `BT %s:%d -- %s\n` -- backtrace, `USE_BACKTRACE`-gated in C |
///
/// **There is no `ADDR` record.** `grep -c "ADDR" lib/memdebug.c` returns `0`;
/// the five prefixes actually emitted are `MEM`, `LIMIT`, `FD`, `FILE` and
/// `BT`. This is a correction, established by measurement, to a list given
/// elsewhere.
///
/// A `GlobalAlloc` can honestly produce only the `MEM` and `LIMIT` records, so
/// only those are emitted. The `strdup`, `wcsdup`, `FD`, `FILE` and `BT`
/// formats are recorded above as evidence and deliberately not written: there is
/// no `strdup` in Rust, and file-descriptor and stream tracking is not an
/// allocator's business.
///
/// # Two details the C formats hide, and which the parser does not forgive
///
/// * Pointers must render the way glibc's `%p` does, because
///   `tests/memanalyzer.pm` matches `0x([0-9a-f]*)` and the literal string
///   `(nil)` (`:132`, `:159`, `:164`, `:209`). Lower-case hexadecimal, an `0x`
///   prefix, no leading zeros, and `(nil)` for null.
/// * Sizes are decimal, and the source token must contain no space, because the
///   record is split with `^MEM ([^ ]*):(\d*) (.*)` (`:127`).
///
/// # Destination
///
/// The `CURL_MEMDEBUG` environment variable. `tests/runner.pm:165` sets it to
/// `"$logdir/$MEMDUMP"`, and `tests/runner.pm:1026-1028` *deletes* it -- with
/// `:1056` restoring it -- to implement the per-fixture
/// `<command option="no-memdebug">` opt-out. An unset, empty or unwritable
/// destination therefore disables logging **silently**: nothing is written to
/// standard output or standard error and nothing panics. `lib/memdebug.c:149`
/// takes the same view, opening the file only `if(logname && *logname)`.
///
/// Records are written unbuffered, one `write(2)` per record. That is a
/// deliberate divergence from `lib/memdebug.c`, which buffers into
/// `membuf[10000]` and needs `curl_dbg_cleanup()` (`:100-117`) to flush at exit
/// "because LeakSanitizer calls `_exit()`" after the atexit handlers
/// (curl/curl#6620). Holding no buffer removes that hazard by construction
/// rather than reproducing its remedy.
#[cfg(feature = "memdebug")]
pub(crate) mod memdebug {
    use core::cell::Cell;
    use core::ptr;
    use core::sync::atomic::{AtomicI64, Ordering};
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::ffi::OsString;
    use std::fs::File;
    use std::io::Write as _;
    use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

    /// The `%s` of every record: this file, so a reader can find the emitter.
    ///
    /// `file!()` rather than a literal, so the token cannot drift if the module
    /// moves. It contains no space, which `^MEM ([^ ]*):` requires.
    const SOURCE: &str = file!();

    /// Capacity of the stack buffer a record is formatted into.
    ///
    /// The longest record this module writes is a `realloc` with two 64-bit
    /// pointers and a `usize` size, which is 107 bytes with the current
    /// [`SOURCE`]. 192 leaves room without putting a large frame on the
    /// allocation hot path.
    const RECORD_MAX: usize = 192;

    /// The sentinel [`LIMIT`] holds when no allocation cap is configured.
    ///
    /// `lib/memdebug.c` uses a separate `memlimit` boolean beside its `memsize`
    /// counter; one negative sentinel expresses the same two states in a single
    /// atomic, which is what makes the check lock-free.
    const NO_LIMIT: i64 = -1;

    /// Remaining allocations before the cap denies one, or [`NO_LIMIT`].
    ///
    /// This and [`LOG`] are the module's only mutable state. A `GlobalAlloc` is
    /// process-global by construction, so the state cannot be injected; it is
    /// kept to two items, both of them thread-safe, and nothing else in this
    /// file holds any.
    static LIMIT: AtomicI64 = AtomicI64::new(NO_LIMIT);

    /// The log destination, resolved once. [`None`] means logging is disabled.
    static LOG: OnceLock<Option<Mutex<File>>> = OnceLock::new();

    thread_local! {
        /// Raised while this thread is inside the logger.
        ///
        /// Resolving the destination reads the environment, and reading the
        /// environment allocates, so the logger can re-enter the allocator. The
        /// flag makes that nested allocation take the plain path: it is served
        /// normally and simply not logged. Without it the first allocation of
        /// the process would recurse into `OnceLock::get_or_init` and deadlock.
        static IN_LOG: Cell<bool> = const { Cell::new(false) };
    }

    /// A record formatted on the stack.
    ///
    /// The allocation hot path must not allocate, so `format!` is unavailable
    /// and [`core::fmt::Write`] is implemented over a fixed array instead.
    #[derive(Clone, Copy)]
    pub(crate) struct Record {
        buf: [u8; RECORD_MAX],
        len: usize,
    }

    impl Record {
        const fn new() -> Self {
            Self {
                buf: [0; RECORD_MAX],
                len: 0,
            }
        }

        /// The formatted text, or [`None`] if it somehow is not UTF-8.
        ///
        /// Every record this module writes is ASCII, so the [`None`] arm is
        /// unreachable in practice; it exists so that the type has no panicking
        /// accessor at all.
        pub(crate) fn as_str(&self) -> Option<&str> {
            core::str::from_utf8(&self.buf[..self.len]).ok()
        }
    }

    impl core::fmt::Write for Record {
        fn write_str(&mut self, text: &str) -> core::fmt::Result {
            let bytes = text.as_bytes();
            let end = self.len + bytes.len();
            if end > self.buf.len() {
                return Err(core::fmt::Error);
            }
            self.buf[self.len..end].copy_from_slice(bytes);
            self.len = end;
            Ok(())
        }
    }

    /// Renders an address exactly as glibc's `%p` does.
    ///
    /// `tests/memanalyzer.pm` matches `0x([0-9a-f]*)` and the literal `(nil)`,
    /// so lower case, an `0x` prefix, no leading zeros, and `(nil)` for null are
    /// all load-bearing rather than cosmetic.
    struct Addr(usize);

    impl core::fmt::Display for Addr {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            if self.0 == 0 {
                f.write_str("(nil)")
            } else {
                write!(f, "0x{:x}", self.0)
            }
        }
    }

    /// Formats one record, or [`None`] if it would not fit.
    ///
    /// A record longer than [`RECORD_MAX`] would reach `memanalyzer.pm`
    /// truncated and be reported as "Not recognized input line", so it is
    /// dropped rather than emitted damaged. [`RECORD_MAX`] is sized so that this
    /// cannot happen for any record this module produces.
    fn build(args: core::fmt::Arguments<'_>) -> Option<Record> {
        let mut record = Record::new();
        if core::fmt::write(&mut record, args).is_err() {
            return None;
        }
        Some(record)
    }

    /// `lib/memdebug.c:228` -- `MEM %s:%d malloc(%zu) = %p\n`.
    pub(crate) fn malloc_record(size: usize, addr: usize) -> Option<Record> {
        build(format_args!(
            "MEM {}:{} malloc({}) = {}\n",
            SOURCE,
            line!(),
            size,
            Addr(addr)
        ))
    }

    /// `lib/memdebug.c:257` -- `MEM %s:%d calloc(%zu,%zu) = %p\n`, no space.
    pub(crate) fn calloc_record(count: usize, size: usize, addr: usize) -> Option<Record> {
        build(format_args!(
            "MEM {}:{} calloc({},{}) = {}\n",
            SOURCE,
            line!(),
            count,
            size,
            Addr(addr)
        ))
    }

    /// `lib/memdebug.c:349` -- `MEM %s:%d realloc(%p, %zu) = %p\n`, one space.
    pub(crate) fn realloc_record(old: usize, size: usize, addr: usize) -> Option<Record> {
        build(format_args!(
            "MEM {}:{} realloc({}, {}) = {}\n",
            SOURCE,
            line!(),
            Addr(old),
            size,
            Addr(addr)
        ))
    }

    /// `lib/memdebug.c:368` -- `MEM %s:%d free(%p)\n`.
    pub(crate) fn free_record(addr: usize) -> Option<Record> {
        build(format_args!(
            "MEM {}:{} free({})\n",
            SOURCE,
            line!(),
            Addr(addr)
        ))
    }

    /// `lib/memdebug.c:191` -- `LIMIT %s:%d %s reached memlimit\n`.
    pub(crate) fn limit_record(func: &str) -> Option<Record> {
        build(format_args!(
            "LIMIT {}:{} {} reached memlimit\n",
            SOURCE,
            line!(),
            func
        ))
    }

    /// Decides the destination from a candidate `CURL_MEMDEBUG` value.
    ///
    /// Split out as a pure function so the "unset" and "empty" cases can be
    /// tested without mutating the process environment. `lib/memdebug.c:149`
    /// opens the file only `if(logname && *logname)`, so an empty value is
    /// exactly as disabling as an absent one -- which is what makes
    /// `tests/runner.pm:1026-1028`'s per-fixture opt-out work.
    fn log_path(value: Option<OsString>) -> Option<OsString> {
        match value {
            Some(path) if !path.is_empty() => Some(path),
            _ => None,
        }
    }

    /// Opens the destination, or reports that there is none.
    ///
    /// Truncating, matching the `"w"` mode of `FOPEN_WRITETEXT` at
    /// `lib/memdebug.c:150`. An unwritable path yields [`None`] rather than a
    /// panic or a diagnostic, because a fixture that cannot write its dump must
    /// still run.
    fn open_log() -> Option<Mutex<File>> {
        let path = log_path(std::env::var_os("CURL_MEMDEBUG"))?;
        File::create(path).ok().map(Mutex::new)
    }

    /// The log destination, opening it on first use.
    ///
    /// Must be called only with [`IN_LOG`] raised: the first call reads the
    /// environment, which allocates.
    fn destination() -> Option<&'static Mutex<File>> {
        LOG.get_or_init(open_log).as_ref()
    }

    /// Exclusive access to the log, with the re-entrancy flag raised.
    ///
    /// Exists as an RAII token for two reasons. It lowers the flag in `Drop`, so
    /// no path -- including an unwind -- can leave a thread permanently unable to
    /// log. And it lets [`TrackingAllocator::realloc`] hold the lock *across* the
    /// reallocation, which is the ordering guarantee `lib/memdebug.c:330-332`
    /// spells out: the record must be written under the same lock, "as we get
    /// out-of-order log entries otherwise, since another thread might alloc the
    /// memory released by realloc() before otherwise would log it".
    struct Logger {
        file: MutexGuard<'static, File>,
    }

    impl Logger {
        /// [`Some`] only when logging is enabled and this thread is not already
        /// inside the logger.
        fn enter() -> Option<Self> {
            let entered = IN_LOG.try_with(|flag| {
                if flag.get() {
                    false
                } else {
                    flag.set(true);
                    true
                }
            });
            if !matches!(entered, Ok(true)) {
                return None;
            }

            match destination() {
                Some(lock) => Some(Self {
                    // A panic elsewhere while this lock was held poisons it. The
                    // log is a diagnostic, so recovering the handle is strictly
                    // better than discarding every subsequent record.
                    file: lock.lock().unwrap_or_else(PoisonError::into_inner),
                }),
                None => {
                    let _ = IN_LOG.try_with(|flag| flag.set(false));
                    None
                }
            }
        }

        /// Writes one record, ignoring an I/O failure.
        ///
        /// A full disk must not change the behaviour of the program under test.
        fn write(&mut self, record: Option<Record>) {
            if let Some(text) = record.as_ref().and_then(Record::as_str) {
                let _ = self.file.write_all(text.as_bytes());
            }
        }
    }

    impl Drop for Logger {
        fn drop(&mut self) {
            // `try_with` rather than `with`: during thread teardown the storage
            // may already be gone, and this must never panic.
            let _ = IN_LOG.try_with(|flag| flag.set(false));
        }
    }

    /// The countdown half of `countcheck()` (`lib/memdebug.c:186-204`).
    ///
    /// Returns `true` when this allocation must be denied. Taken as a function
    /// over its counter rather than over the global so that it can be tested
    /// without touching process-wide state.
    ///
    /// The C reads `if(memlimit && source) { if(!memsize) { ...deny... } else
    /// memsize--; }`, so the cap denies once the counter reaches zero and
    /// decrements otherwise. A negative counter is [`NO_LIMIT`] and denies
    /// nothing.
    fn take_allocation(counter: &AtomicI64) -> bool {
        let mut current = counter.load(Ordering::Relaxed);
        loop {
            if current < 0 {
                return false;
            }
            if current == 0 {
                return true;
            }
            match counter.compare_exchange_weak(
                current,
                current - 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return false,
                Err(observed) => current = observed,
            }
        }
    }

    /// Reports a denied allocation, then denies it.
    ///
    /// `lib/memdebug.c:191-194` writes the `LIMIT` line to **both** the log file
    /// and standard error; both halves are reproduced, and in that order.
    ///
    /// The C additionally sets `errno = ENOMEM` at `:198`. That is deliberately
    /// **not** reproduced: a `GlobalAlloc` signals failure by returning null,
    /// which the standard library turns into `handle_alloc_error`, so `errno` is
    /// never consulted; and setting it would need a second platform-specific raw
    /// call (`__errno_location` on glibc, `__error` on Darwin) for no observable
    /// effect on any harness check.
    fn deny(func: &str) -> bool {
        let record = limit_record(func);

        // lib/memdebug.c:191 -- the log file first.
        if let Some(mut logger) = Logger::enter() {
            logger.write(record);
        }

        // lib/memdebug.c:193-194 -- then standard error, unconditionally, so a
        // torture run says why it stopped even with no log configured. Rust's
        // `Stderr` is unbuffered, so the `fflush` at :196 has no counterpart.
        if let Some(text) = record.as_ref().and_then(Record::as_str) {
            let _ = std::io::stderr().write_all(text.as_bytes());
        }

        true
    }

    /// Applies `countcheck()` to the process-wide cap.
    fn capped(func: &str) -> bool {
        take_allocation(&LIMIT) && deny(func)
    }

    /// Caps the number of allocations that will succeed.
    ///
    /// Reproduces `curl_dbg_memlimit()` (`lib/memdebug.c:175-181`), including its
    /// one-shot behaviour: the C guards the whole body with `if(!memlimit)`, so a
    /// second call is ignored. Returns whether this call took effect.
    pub(crate) fn set_memlimit(allocations: u32) -> bool {
        LIMIT
            .compare_exchange(
                NO_LIMIT,
                i64::from(allocations),
                Ordering::Relaxed,
                Ordering::Relaxed,
            )
            .is_ok()
    }

    /// A `GlobalAlloc` that logs every operation in `memanalyzer.pm`'s format.
    ///
    /// Forwards every request to [`System`] unchanged. It adds no header, no
    /// padding and no alignment adjustment of its own -- `lib/memdebug.c` does
    /// prepend a `struct memdebug` header, but it can, because it also owns the
    /// matching `free`; a `GlobalAlloc` is handed a `Layout` by the compiler and
    /// must return a block that matches it exactly.
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub(crate) struct TrackingAllocator;

    impl TrackingAllocator {
        /// Constructs the allocator. `const` so it can initialise a `static`.
        pub(crate) const fn new() -> Self {
            Self
        }
    }

    // SAFETY: `GlobalAlloc` requires that an implementation behave as a correct
    // allocator. Every requirement is met by delegation rather than by
    // reimplementation: each method forwards its `Layout` to `System`
    // unmodified, so a returned block always has exactly the size and alignment
    // the caller asked for and is never a pointer this code invented, adjusted
    // or reused; `dealloc` forwards the very `Layout` it was given, so a block is
    // never released under a layout different from the one it was created with;
    // and failure is reported the way the trait requires, by returning null,
    // never by panicking. The logging is observation only: it reads the size and
    // the numeric value of the address and writes to a file, never dereferencing
    // a block. It cannot recurse into the allocator either, because
    // `Logger::enter` raises a per-thread flag before any step that allocates.
    unsafe impl GlobalAlloc for TrackingAllocator {
        // SAFETY: `layout` arrives from the caller, which the trait already
        // obliges to pass a non-zero-sized layout with a power-of-two alignment,
        // and it is forwarded to `System` untouched -- so `System` sees a layout
        // it accepts and the block it returns is the block returned from here.
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            if capped("malloc") {
                return ptr::null_mut();
            }

            // SAFETY: `GlobalAlloc::alloc`'s contract already obliges this
            // method's caller to pass a `layout` of non-zero size, and that is
            // the only precondition `System::alloc` imposes. The value is
            // forwarded verbatim, so neither size nor alignment can drift
            // between the two calls and the block returned is valid for exactly
            // the `layout` the caller will later deallocate with. The pointer is
            // not dereferenced here; only its address is formatted for the log.
            let block = unsafe { System.alloc(layout) };

            if let Some(mut logger) = Logger::enter() {
                logger.write(malloc_record(layout.size(), block as usize));
            }

            block
        }

        // SAFETY: `block` and `layout` arrive from the caller, which the trait
        // obliges to pass a block currently allocated by this allocator together
        // with the exact layout it was allocated with. Both are forwarded to
        // `System` unchanged, and since `alloc` forwarded the same layout when
        // the block was created, the pair `System` sees is the pair it issued.
        unsafe fn dealloc(&self, block: *mut u8, layout: Layout) {
            // lib/memdebug.c:366-369 logs before releasing, so the record still
            // names memory that is live at the moment it is written.
            if let Some(mut logger) = Logger::enter() {
                logger.write(free_record(block as usize));
            }

            // SAFETY: `GlobalAlloc::dealloc`'s contract obliges this method's
            // caller to pass a block that this same allocator returned together
            // with the exact `layout` it was allocated under. Both are forwarded
            // to `System::dealloc` unmodified, so the layout cannot be
            // mismatched here, and because this is the only release of `block`
            // on this path it cannot be freed twice. The block is not read
            // before release -- the log records only its address.
            unsafe { System.dealloc(block, layout) };
        }

        // SAFETY: identical to `alloc`; `layout` is forwarded to
        // `System::alloc_zeroed` untouched, so the returned block matches the
        // requested size and alignment and is fully zeroed by `System`.
        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            if capped("calloc") {
                return ptr::null_mut();
            }

            // SAFETY: `layout` arrives from the caller having already satisfied
            // `GlobalAlloc::alloc_zeroed`'s precondition of a non-zero size, and
            // it is forwarded to the system allocator byte-for-byte, so no
            // size or alignment can be widened or narrowed on the way through.
            // The returned pointer is only ever handed back to the caller, who
            // owns it under that same `layout`; this function neither reads nor
            // writes the block, so a null return needs no special handling here.
            let block = unsafe { System.alloc_zeroed(layout) };

            // `curl_dbg_calloc` logs the caller's `(elements, size)` pair
            // (lib/memdebug.c:257); a `Layout` carries one size, so the element
            // count is written as 1. `tests/memanalyzer.pm:165` computes
            // `$1 * $2`, so the byte total it derives is still exact.
            if let Some(mut logger) = Logger::enter() {
                logger.write(calloc_record(1, layout.size(), block as usize));
            }

            block
        }

        // SAFETY: `block`, `layout` and `new_size` arrive from the caller, which
        // the trait obliges to pass a block currently allocated by this
        // allocator, the exact layout it was allocated with, and a `new_size`
        // that is greater than zero and does not overflow when rounded up to
        // `layout.align()`. All three are forwarded to `System::realloc`
        // unchanged. This method is overridden rather than left to the default
        // implementation precisely so that one `realloc` record is written where
        // the default would have emitted an unrelated `malloc`/`free` pair.
        unsafe fn realloc(&self, block: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            if capped("realloc") {
                return ptr::null_mut();
            }

            let old = block as usize;

            // Taken BEFORE the reallocation and held across it. That ordering is
            // the whole point: lib/memdebug.c:330-332 explains that the record
            // must be written under the same lock, "as we get out-of-order log
            // entries otherwise, since another thread might alloc the memory
            // released by realloc() before otherwise would log it". The C takes
            // its debug mutex at :334 and logs through `curl_dbg_log_locked` at
            // :349; holding this guard does the same. When logging is disabled
            // there is no lock and no ordering to preserve.
            let mut logger = Logger::enter();

            // SAFETY: `GlobalAlloc::realloc`'s contract obliges this method's
            // caller to pass a block this allocator returned, the exact `layout`
            // it was allocated under, and a non-zero `new_size` that does not
            // overflow when rounded up to `layout.align()`. All three are
            // forwarded to `System::realloc` unmodified, so it sees precisely
            // the arguments the trait guarantees. `block` is invalidated by this
            // call, which is why its address was captured into `old` beforehand
            // rather than being read afterwards.
            let resized = unsafe { System.realloc(block, layout, new_size) };

            if let Some(logger) = logger.as_mut() {
                logger.write(realloc_record(old, new_size, resized as usize));
            }

            resized
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// The `MEM` prefix `tests/memanalyzer.pm:127` splits on, with this
        /// file's path as the space-free source token.
        fn mem_prefix() -> String {
            format!("MEM {}:", SOURCE)
        }

        #[test]
        fn malloc_record_matches_memdebug_c_228() {
            let record = malloc_record(135, 0x7f_2a_00_10).expect("record fits");
            let text = record.as_str().expect("record is ASCII");

            assert!(text.starts_with(&mem_prefix()), "{text}");
            assert!(text.ends_with(" malloc(135) = 0x7f2a0010\n"), "{text}");
        }

        #[test]
        fn calloc_record_has_no_space_after_the_comma() {
            let record = calloc_record(1, 64, 0xabc).expect("record fits");
            let text = record.as_str().expect("record is ASCII");

            assert!(text.contains(" calloc(1,64) = 0xabc\n"), "{text}");
            assert!(!text.contains("calloc(1, 64)"), "{text}");
        }

        #[test]
        fn realloc_record_has_one_space_after_the_comma() {
            let record = realloc_record(0x10, 32, 0x20).expect("record fits");
            let text = record.as_str().expect("record is ASCII");

            assert!(text.contains(" realloc(0x10, 32) = 0x20\n"), "{text}");
            assert!(!text.contains("realloc(0x10,32)"), "{text}");
        }

        #[test]
        fn free_record_matches_memdebug_c_368() {
            let record = free_record(0xdeadbeef).expect("record fits");
            let text = record.as_str().expect("record is ASCII");

            assert!(text.ends_with(" free(0xdeadbeef)\n"), "{text}");
        }

        /// `tests/memanalyzer.pm:132` and `:209` accept the literal `(nil)`
        /// wherever a pointer may be null, and nothing else.
        #[test]
        fn a_null_address_renders_as_nil() {
            let freed = free_record(0).expect("record fits");
            assert!(
                freed.as_str().expect("ASCII").ends_with(" free((nil))\n"),
                "{:?}",
                freed.as_str()
            );

            let grown = realloc_record(0, 8, 0x40).expect("record fits");
            assert!(
                grown
                    .as_str()
                    .expect("ASCII")
                    .contains(" realloc((nil), 8) = 0x40\n"),
                "{:?}",
                grown.as_str()
            );
        }

        /// Hexadecimal must be lower case and unpadded: the parser's character
        /// class is `[0-9a-f]`.
        #[test]
        fn addresses_render_in_lowercase_hex_without_padding() {
            let record = malloc_record(1, 0xABCDEF).expect("record fits");
            let text = record.as_str().expect("record is ASCII");

            assert!(text.contains("= 0xabcdef\n"), "{text}");
        }

        #[test]
        fn limit_record_matches_memdebug_c_191() {
            let record = limit_record("realloc").expect("record fits");
            let text = record.as_str().expect("record is ASCII");

            assert!(text.starts_with(&format!("LIMIT {SOURCE}:")), "{text}");
            assert!(text.ends_with(" realloc reached memlimit\n"), "{text}");
        }

        /// A record that cannot fit is dropped, not truncated: a truncated line
        /// would reach `memanalyzer.pm` as "Not recognized input line".
        #[test]
        fn an_oversized_record_is_dropped_rather_than_truncated() {
            let long = "x".repeat(RECORD_MAX);
            assert!(limit_record(&long).is_none());
        }

        #[test]
        fn an_unset_or_empty_destination_disables_logging() {
            assert!(log_path(None).is_none());
            assert!(log_path(Some(OsString::new())).is_none());

            let path = OsString::from("/tmp/curl-rs-memdebug.log");
            assert_eq!(log_path(Some(path.clone())), Some(path));
        }

        /// An unwritable destination must disable logging silently. `/` is a
        /// directory on every mandated target, so `File::create` fails there.
        #[test]
        fn an_unwritable_destination_does_not_panic() {
            assert!(File::create("/").ok().map(Mutex::new).is_none());
        }

        /// `countcheck()` counts down and then denies, and a negative counter
        /// denies nothing at all.
        #[test]
        fn the_cap_counts_down_then_denies() {
            let counter = AtomicI64::new(2);
            assert!(!take_allocation(&counter));
            assert!(!take_allocation(&counter));
            assert!(take_allocation(&counter));
            // Still denying: the C never re-arms either.
            assert!(take_allocation(&counter));

            let unlimited = AtomicI64::new(NO_LIMIT);
            assert!(!take_allocation(&unlimited));
            assert_eq!(unlimited.load(Ordering::Relaxed), NO_LIMIT);
        }

        /// `curl_dbg_memlimit()` is one-shot (`lib/memdebug.c:177`).
        #[test]
        fn the_process_cap_is_one_shot() {
            assert!(set_memlimit(4));
            assert!(!set_memlimit(9));
            assert_eq!(LIMIT.load(Ordering::Relaxed), 4);

            // Leave the cap where the first call put it, exactly as the C would;
            // no other test in this module reads it.
            assert!(!set_memlimit(0));
        }

        /// The allocator round-trips every `GlobalAlloc` entry point under the
        /// real `Layout` contract. This is the test the AddressSanitizer and
        /// Miri legs exercise: a misaligned return or a mismatched `Layout`
        /// shows up here and nowhere else.
        #[test]
        fn the_allocator_round_trips_every_entry_point() {
            let allocator = TrackingAllocator::new();
            let layout = Layout::from_size_align(64, 16).expect("valid layout");

            // SAFETY: `layout` is non-zero-sized with a power-of-two alignment,
            // which is `GlobalAlloc::alloc`'s whole precondition.
            let block = unsafe { allocator.alloc(layout) };
            assert!(!block.is_null());
            assert_eq!(block as usize % layout.align(), 0);

            // SAFETY: `block` was just returned by this allocator for `layout`,
            // and 128 is greater than zero and does not overflow when rounded up
            // to `layout.align()` -- the exact precondition of `realloc`.
            let grown = unsafe { allocator.realloc(block, layout, 128) };
            assert!(!grown.is_null());
            assert_eq!(grown as usize % layout.align(), 0);

            // SAFETY: `grown` is currently allocated by this allocator, and the
            // layout below is the one it now has: the original alignment with
            // the size `realloc` grew it to, which is what `GlobalAlloc`
            // requires of a reallocated block.
            unsafe {
                allocator.dealloc(
                    grown,
                    Layout::from_size_align(128, layout.align()).expect("valid layout"),
                );
            }

            // SAFETY: `layout` was built by `Layout::from_size_align(64, 16)`
            // and so has a non-zero size, which is `alloc_zeroed`'s only
            // precondition. The block it returns is not yet owned by anything
            // else, and it is released by the matching `dealloc` at the end of
            // this test under this same `layout`.
            let zeroed = unsafe { allocator.alloc_zeroed(layout) };
            assert!(!zeroed.is_null());
            // SAFETY: `alloc_zeroed` returned a non-null block of
            // `layout.size()` readable bytes, which is exactly the slice built
            // here, and nothing else aliases it.
            let bytes = unsafe { core::slice::from_raw_parts(zeroed, layout.size()) };
            assert!(bytes.iter().all(|&byte| byte == 0));

            // SAFETY: `zeroed` is currently allocated by this allocator with
            // exactly `layout`, which is the pair `dealloc` requires.
            unsafe { allocator.dealloc(zeroed, layout) };
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    /// A pure-Rust [`SysCalls`] with scripted answers.
    ///
    /// This is the seam that makes the module testable at all. Miri cannot call
    /// `gethostname(2)`, `getifaddrs(3)` or `if_nametoindex(3)`, so every branch
    /// of the surrounding logic -- the forced terminator, the first-dot
    /// truncation, the NULL `ifa_addr` skip, the scope-id pass-through, the
    /// error mapping and the interior-NUL rejection -- is driven from here
    /// instead, and is therefore covered under Miri without a syscall.
    ///
    /// It also *observes*: two interior cells record what the wrapper handed the
    /// seam, which is how the pre-call `name[0] = '\0'` of
    /// `lib/curl_gethostname.c:69` and the NUL termination of the zone-id string
    /// are asserted rather than assumed.
    struct FakeSys {
        /// Bytes `gethostname` writes, or the `errno` it reports.
        hostname: Result<Vec<u8>, i32>,
        /// The snapshot `ifaddrs` returns, or the `errno` it reports.
        ifaddrs: Result<Vec<IfNode>, i32>,
        /// The index `if_nametoindex` reports, if any.
        index: Option<u32>,
        /// The buffer's first byte as the seam received it.
        observed_first_byte: Cell<Option<u8>>,
        /// The bytes, including the terminator, that `if_nametoindex` received.
        observed_name: RefCell<Option<Vec<u8>>>,
    }

    impl FakeSys {
        fn new() -> Self {
            Self {
                hostname: Ok(Vec::new()),
                ifaddrs: Ok(Vec::new()),
                index: None,
                observed_first_byte: Cell::new(None),
                observed_name: RefCell::new(None),
            }
        }

        fn with_hostname(bytes: &[u8]) -> Self {
            Self {
                hostname: Ok(bytes.to_vec()),
                ..Self::new()
            }
        }

        fn failing_hostname(errno: i32) -> Self {
            Self {
                hostname: Err(errno),
                ..Self::new()
            }
        }

        fn with_ifaddrs(nodes: Vec<IfNode>) -> Self {
            Self {
                ifaddrs: Ok(nodes),
                ..Self::new()
            }
        }

        fn failing_ifaddrs(errno: i32) -> Self {
            Self {
                ifaddrs: Err(errno),
                ..Self::new()
            }
        }

        fn with_index(index: Option<u32>) -> Self {
            Self {
                index,
                ..Self::new()
            }
        }
    }

    impl SysCalls for FakeSys {
        fn gethostname(&self, buf: &mut [u8]) -> io::Result<()> {
            self.observed_first_byte.set(buf.first().copied());

            match &self.hostname {
                Ok(bytes) => {
                    // The kernel writes as much as fits and promises no
                    // terminator, so exactly that many bytes are copied and
                    // nothing is appended.
                    let written = bytes.len().min(buf.len());
                    buf[..written].copy_from_slice(&bytes[..written]);
                    Ok(())
                }
                Err(errno) => Err(io::Error::from_raw_os_error(*errno)),
            }
        }

        fn ifaddrs(&self) -> io::Result<Vec<IfNode>> {
            match &self.ifaddrs {
                Ok(nodes) => Ok(nodes.clone()),
                Err(errno) => Err(io::Error::from_raw_os_error(*errno)),
            }
        }

        fn if_nametoindex(&self, name: &CStr) -> Option<u32> {
            *self.observed_name.borrow_mut() = Some(name.to_bytes_with_nul().to_vec());
            self.index
        }
    }

    fn v4_node(name: &str, octets: [u8; 4]) -> IfNode {
        IfNode {
            name: name.as_bytes().to_vec(),
            addr: Some(RawIfAddr::V4(octets)),
        }
    }

    fn v6_node(name: &str, octets: [u8; 16], scope_id: u32) -> IfNode {
        IfNode {
            name: name.as_bytes().to_vec(),
            addr: Some(RawIfAddr::V6 { octets, scope_id }),
        }
    }

    /// A node whose family this layer cannot represent: `AF_PACKET` on Linux,
    /// `AF_LINK` on Darwin. Every interface has one.
    fn link_node(name: &str) -> IfNode {
        IfNode {
            name: name.as_bytes().to_vec(),
            addr: Some(RawIfAddr::Unrepresentable),
        }
    }

    /// A node whose `ifa_addr` was NULL -- the case `lib/if2ip.c:111` guards.
    fn addrless_node(name: &str) -> IfNode {
        IfNode {
            name: name.as_bytes().to_vec(),
            addr: None,
        }
    }

    // -- HOSTNAME_MAX -------------------------------------------------------

    /// `lib/curl_gethostname.h:28` -- `#define HOSTNAME_MAX 1024`.
    #[test]
    fn hostname_max_matches_the_c_header() {
        assert_eq!(HOSTNAME_MAX, 1024);
    }

    // -- gethostname --------------------------------------------------------

    /// `lib/curl_gethostname.c:90-92` truncates at the FIRST dot, leaving the
    /// un-qualified machine name -- the semantic `:40-41` calls out explicitly.
    #[test]
    fn a_qualified_hostname_is_truncated_at_the_first_dot() {
        let sys = FakeSys::with_hostname(b"host.example.com");

        assert_eq!(gethostname_with(&sys), Ok(String::from("host")));
    }

    /// Not the last dot, and not merely the last label.
    #[test]
    fn truncation_stops_at_the_first_dot_not_the_last() {
        let sys = FakeSys::with_hostname(b"a.b.c.d");

        assert_eq!(gethostname_with(&sys), Ok(String::from("a")));
    }

    #[test]
    fn an_unqualified_hostname_is_returned_verbatim() {
        let sys = FakeSys::with_hostname(b"buildhost");

        assert_eq!(gethostname_with(&sys), Ok(String::from("buildhost")));
    }

    /// A leading dot yields an empty name, which is what `strchr` plus
    /// `*dot = '\0'` produces in C. No special case exists there and none is
    /// invented here.
    #[test]
    fn a_leading_dot_yields_an_empty_name() {
        let sys = FakeSys::with_hostname(b".example.com");

        assert_eq!(gethostname_with(&sys), Ok(String::new()));
    }

    /// `lib/curl_gethostname.c:69` / `:75` -- `name[0] = '\0'` runs BEFORE the
    /// call, so the seam must observe a cleared first byte.
    #[test]
    fn the_buffer_is_cleared_before_the_call() {
        let sys = FakeSys::with_hostname(b"host");
        let _ = gethostname_with(&sys);

        assert_eq!(sys.observed_first_byte.get(), Some(0));
    }

    /// `lib/curl_gethostname.c:84` -- `name[namelen - 1] = '\0'`. POSIX lets
    /// `gethostname` truncate without a terminator, and this is the statement
    /// that makes the subsequent scan safe. A seam that fills every byte and
    /// succeeds must therefore yield exactly `HOSTNAME_MAX` characters: the
    /// forced terminator at index 1024 bounds the scan.
    #[test]
    fn an_unterminated_buffer_is_bounded_by_the_forced_terminator() {
        let filled = vec![b'a'; HOSTNAME_MAX + 1];
        let sys = FakeSys::with_hostname(&filled);

        let name = gethostname_with(&sys).expect("a filled buffer is not a failure");

        assert_eq!(name.len(), HOSTNAME_MAX);
        assert!(name.bytes().all(|byte| byte == b'a'));
    }

    /// The same buffer, but the call fails: `lib/curl_gethostname.c:84` still
    /// runs, and `:86-87` then reports the failure. The observable requirement
    /// is that nothing panics and no scan happens.
    #[test]
    fn a_failure_is_reported_after_the_terminator_is_forced() {
        let sys = FakeSys::failing_hostname(libc::ENAMETOOLONG);

        assert_eq!(gethostname_with(&sys), Err(CURLcode::FailedInit));
    }

    #[test]
    fn a_failing_call_maps_to_failed_init_and_does_not_panic() {
        for errno in [libc::EPERM, libc::EFAULT, libc::ENAMETOOLONG] {
            let sys = FakeSys::failing_hostname(errno);
            assert_eq!(gethostname_with(&sys), Err(CURLcode::FailedInit));
        }
    }

    /// C hands the raw bytes back, so introducing a failure for a non-UTF-8
    /// hostname would be a behaviour change. The replacement character is used
    /// instead, and nothing panics.
    #[test]
    fn a_non_utf8_hostname_does_not_panic() {
        let sys = FakeSys::with_hostname(&[0xff, 0xfe, b'.', b'x']);

        let name = gethostname_with(&sys).expect("invalid UTF-8 is not a failure");

        assert!(!name.is_empty());
        assert!(name.contains('\u{fffd}'));
        assert!(!name.contains('.'));
    }

    /// An empty result is success in C: `gethostname` returned 0 and left the
    /// buffer as `name[0] = '\0'` put it.
    #[test]
    fn an_empty_hostname_is_success() {
        let sys = FakeSys::with_hostname(b"");

        assert_eq!(gethostname_with(&sys), Ok(String::new()));
    }

    /// The real syscall. Ignored under Miri, which cannot call a foreign
    /// function; the logic it would cover is covered by the fake above.
    #[test]
    #[cfg_attr(miri, ignore = "gethostname(2) is a foreign function")]
    fn the_real_hostname_is_non_empty_and_unqualified() {
        let name = gethostname().expect("the host has a name");

        assert!(!name.is_empty());
        assert!(!name.contains('.'), "not un-qualified: {name}");
    }

    /// A zero-length buffer has no valid outcome, so [`RealSys`] rejects it
    /// before any raw call rather than handing the kernel a one-past-the-end
    /// pointer. Safe to run under Miri: no foreign function is reached.
    #[test]
    fn the_real_seam_rejects_an_empty_buffer() {
        let mut empty: [u8; 0] = [];
        let outcome = RealSys.gethostname(&mut empty);

        assert!(outcome.is_err());
        assert_eq!(
            outcome.err().and_then(|err| err.raw_os_error()),
            Some(libc::EINVAL)
        );
    }

    // -- interface_addrs ----------------------------------------------------

    /// `lib/if2ip.c:111` -- a node whose `ifa_addr` is NULL is skipped, never
    /// dereferenced.
    #[test]
    fn a_node_without_an_address_is_skipped() {
        let sys = FakeSys::with_ifaddrs(vec![
            addrless_node("dummy0"),
            v4_node("eth0", [10, 0, 0, 7]),
        ]);

        let addrs = interface_addrs_with(&sys).expect("enumeration succeeds");

        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].name, "eth0");
        assert_eq!(addrs[0].addr, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)));
    }

    /// `lib/if2ip.c:138-139` -- `sin6_scope_id` is surfaced for IPv6 and is
    /// zero for IPv4. Without it a link-local `--interface` cannot work.
    #[test]
    fn the_scope_id_is_surfaced_for_ipv6_and_zero_for_ipv4() {
        let link_local = [
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x1a, 0x4a, 0xff, 0xfe, 0x00, 0x00, 0x01,
        ];
        let sys = FakeSys::with_ifaddrs(vec![
            v4_node("eth0", [192, 168, 1, 5]),
            v6_node("eth0", link_local, 3),
        ]);

        let addrs = interface_addrs_with(&sys).expect("enumeration succeeds");

        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0].scope_id, 0);
        assert_eq!(addrs[1].scope_id, 3);
        assert_eq!(addrs[1].addr, IpAddr::V6(Ipv6Addr::from(link_local)));
    }

    /// An unscoped IPv6 address keeps a zero scope id, which is what
    /// `lib/if2ip.c:149` tests before appending the `%<scopeid>` suffix.
    #[test]
    fn an_unscoped_ipv6_address_has_a_zero_scope_id() {
        let global = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let sys = FakeSys::with_ifaddrs(vec![v6_node("eth0", global, 0)]);

        let addrs = interface_addrs_with(&sys).expect("enumeration succeeds");

        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].scope_id, 0);
    }

    /// `lib/if2ip.c:112` admits only the requested family, and this layer can
    /// only represent the two internet ones, so an `AF_PACKET` or `AF_LINK`
    /// node contributes no address.
    #[test]
    fn an_unrepresentable_family_contributes_no_address() {
        let sys = FakeSys::with_ifaddrs(vec![link_node("eth0"), v4_node("eth0", [10, 0, 0, 1])]);

        let addrs = interface_addrs_with(&sys).expect("enumeration succeeds");

        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].addr, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn a_non_utf8_interface_name_does_not_panic() {
        let node = IfNode {
            name: vec![0xff, 0xfe],
            addr: Some(RawIfAddr::V4([127, 0, 0, 1])),
        };
        let sys = FakeSys::with_ifaddrs(vec![node]);

        let addrs = interface_addrs_with(&sys).expect("enumeration succeeds");

        assert_eq!(addrs.len(), 1);
        assert!(addrs[0].name.contains('\u{fffd}'));
    }

    /// A failing `getifaddrs(3)` becomes [`CURLcode::InterfaceFailed`]. A
    /// caller reproducing `Curl_if2ip` must fold that back to
    /// `IF2IP_NOT_FOUND`; see the function's documentation.
    #[test]
    fn a_failing_enumeration_maps_to_interface_failed() {
        let sys = FakeSys::failing_ifaddrs(libc::ENOMEM);

        assert_eq!(
            interface_addrs_with(&sys),
            Err(CURLcode::InterfaceFailed),
            "getifaddrs failure must be reported, not hidden as an empty list"
        );
        assert_eq!(interface_names_with(&sys), Err(CURLcode::InterfaceFailed));
    }

    #[test]
    fn an_empty_snapshot_is_not_an_error() {
        let sys = FakeSys::new();

        assert_eq!(interface_addrs_with(&sys), Ok(Vec::new()));
        assert_eq!(interface_names_with(&sys), Ok(Vec::new()));
    }

    // -- interface_names ----------------------------------------------------

    /// The names must include the families [`interface_addrs`] cannot represent,
    /// because `lib/if2ip.c:163-166` distinguishes "interface exists but has no
    /// address of this family" from "interface not found", and the two lead to
    /// different `CURLcode`s in `bindlocal`.
    #[test]
    fn the_name_list_keeps_families_the_address_list_drops() {
        let sys = FakeSys::with_ifaddrs(vec![link_node("eth9")]);

        assert_eq!(interface_addrs_with(&sys), Ok(Vec::new()));
        assert_eq!(interface_names_with(&sys), Ok(vec![String::from("eth9")]));
    }

    /// Order and duplicates are preserved, and NULL-address nodes are excluded
    /// exactly as `lib/if2ip.c:111` excludes them from the name comparison.
    #[test]
    fn the_name_list_preserves_order_and_duplicates() {
        let sys = FakeSys::with_ifaddrs(vec![
            link_node("lo"),
            v4_node("lo", [127, 0, 0, 1]),
            addrless_node("hidden0"),
            link_node("eth0"),
        ]);

        assert_eq!(
            interface_names_with(&sys),
            Ok(vec![
                String::from("lo"),
                String::from("lo"),
                String::from("eth0"),
            ])
        );
    }

    /// The real syscall, and the proof that the snapshot is owned: every value
    /// below is read after `freeifaddrs(3)` has already released the list, so a
    /// borrow of operating-system memory would show up here.
    #[test]
    #[cfg_attr(miri, ignore = "getifaddrs(3) is a foreign function")]
    fn the_real_snapshot_contains_loopback_and_outlives_the_list() {
        let addrs = interface_addrs().expect("enumeration succeeds");

        assert!(!addrs.is_empty(), "a host always has at least loopback");
        assert!(
            addrs
                .iter()
                .any(|entry| entry.addr == IpAddr::V4(Ipv4Addr::LOCALHOST)
                    || entry.addr == IpAddr::V6(Ipv6Addr::LOCALHOST)),
            "no loopback address in {addrs:?}"
        );
        assert!(
            addrs.iter().all(|entry| !entry.name.is_empty()),
            "every interface has a name: {addrs:?}"
        );

        let names = interface_names().expect("enumeration succeeds");
        assert!(names.len() >= addrs.len());
        for entry in &addrs {
            assert!(names.contains(&entry.name), "{} missing", entry.name);
        }
    }

    // -- if_nametoindex -----------------------------------------------------

    /// `if_nametoindex(3)` reports failure as `0`, which is never a valid
    /// index, so the seam maps it to [`None`] and the wrapper to an error --
    /// never to `Ok(0)`.
    #[test]
    fn an_unknown_interface_name_is_an_error_not_zero() {
        let sys = FakeSys::with_index(None);

        assert_eq!(
            if_nametoindex_with(&sys, "definitely-not-an-interface"),
            Err(CURLcode::InterfaceFailed)
        );
    }

    #[test]
    fn a_known_interface_name_yields_its_index() {
        let sys = FakeSys::with_index(Some(7));

        assert_eq!(if_nametoindex_with(&sys, "eth0"), Ok(7));
    }

    /// The name reaches the seam NUL-terminated and otherwise unaltered.
    #[test]
    fn the_name_reaches_the_seam_nul_terminated() {
        let sys = FakeSys::with_index(Some(1));
        let _ = if_nametoindex_with(&sys, "eth0");

        assert_eq!(
            sys.observed_name.borrow().as_deref(),
            Some(&b"eth0\0"[..]),
            "the seam must receive a NUL-terminated C string"
        );
    }

    /// A zone identifier comes from a URL, so it is attacker-influenced input.
    /// An interior NUL must be an error, never a panic, and the seam must not
    /// be reached at all.
    #[test]
    fn an_interior_nul_is_an_error_and_never_a_panic() {
        let sys = FakeSys::with_index(Some(1));

        assert_eq!(
            if_nametoindex_with(&sys, "eth\0 0"),
            Err(CURLcode::BadFunctionArgument)
        );
        assert!(
            sys.observed_name.borrow().is_none(),
            "the seam must not be called with a rejected name"
        );
    }

    #[test]
    fn an_empty_name_is_rejected_by_the_seam_not_by_a_panic() {
        let sys = FakeSys::with_index(None);

        assert_eq!(
            if_nametoindex_with(&sys, ""),
            Err(CURLcode::InterfaceFailed)
        );
    }

    /// The real syscall against the loopback interface, whose name differs
    /// between the two mandated operating systems.
    #[test]
    #[cfg_attr(miri, ignore = "if_nametoindex(3) is a foreign function")]
    fn the_real_loopback_interface_has_a_non_zero_index() {
        #[cfg(target_os = "linux")]
        let loopback = "lo";
        #[cfg(target_os = "macos")]
        let loopback = "lo0";

        let index = if_nametoindex(loopback).expect("loopback always exists");

        assert!(index > 0);
    }

    #[test]
    #[cfg_attr(miri, ignore = "if_nametoindex(3) is a foreign function")]
    fn a_real_unknown_interface_name_fails() {
        assert_eq!(
            if_nametoindex("curl-rs-no-such-if"),
            Err(CURLcode::InterfaceFailed)
        );
    }
}
