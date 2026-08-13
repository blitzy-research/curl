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
//! | `src/tool_getparam.c:625-637` | 13 | [`scrub_argument`] |
//! | `lib/memdebug.c:184-368` | 577 | `memdebug`, behind a default-off feature |
//!
//! The `cleanarg` row is the one entry that comes from the command-line tool
//! rather than the library, and it is here because the capability it needs --
//! writing to the process's own argument vector -- is unreachable from safe
//! Rust and `curl-rs` carries `#![forbid(unsafe_code)]`. It is also the one
//! entry whose C guard, `HAVE_WRITABLE_ARGV`, is defined on all four mandated
//! targets (`configure.ac:1809`, `CMakeLists.txt:619`), so implementing the
//! no-op arm instead would have left a credential visible in every process
//! listing for the life of a transfer.
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
//!   is a pure optimization and performance is an explicit non-goal. The
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
// The consumers named above are all in other modules -- `dns/if2ip.rs` for
// the interface snapshot, `protocols/mod.rs` and `url/` for the zone-id
// lookup, and `lib.rs` for the optional allocator -- so until they land each
// wrapper is legitimately unreferenced and the zero-warnings gate
// (AAP section 0.8.4) would otherwise fail on code that is correct. No lint
// level for `unsafe_code` is set here, at any level, by design: see the
// module documentation above.

use core::mem::MaybeUninit;
use core::ptr;
use std::ffi::{CStr, CString};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};

use crate::error::{CURLcode, CodeResult};

/// Hostname buffer size, from `lib/curl_gethostname.h:28`
/// (`#define HOSTNAME_MAX 1024`).
///
/// Exposed so that a caller which needs to size its own buffer sizes it
/// identically to the C tree. Its sole C consumer is `lib/smtp.c:187`, which
/// declares `char localhost[HOSTNAME_MAX + 1]` and passes
/// `sizeof(localhost)` at `lib/smtp.c:191` -- so the effective `namelen` in C
/// is 1025, and [`gethostname`] uses exactly that many bytes.
#[allow(dead_code)]
pub(crate) const HOSTNAME_MAX: usize = 1024;

/// `O_NOFOLLOW`, for [`std::os::unix::fs::OpenOptionsExt::custom_flags`].
///
/// Re-exported from `libc` rather than spelled as a literal because the value
/// is not the same on every mandated target -- `0o400000` on Linux and
/// `0x0000_0100` on macOS -- so a hard-coded number would silently mean
/// something else on one of the four. `libc` is the crate's only description
/// of platform constants and it lives here, which is why this constant lives
/// here too: nothing outside this directory names `libc`, and this keeps that
/// property while still letting `tls/keylog.rs` ask the kernel not to follow a
/// symbolic link.
///
/// Not a syscall and not `unsafe`: an integer, evaluated at compile time. It is
/// grouped with the seam below only because that is where the platform lives.
///
/// The flag refuses the *final* path component when it is a symbolic link. It
/// says nothing about the directories leading to it, so a caller that must also
/// resist a redirected parent needs `O_PATH`-style directory traversal, which
/// no curl behaviour requires.
pub(crate) const O_NOFOLLOW: i32 = libc::O_NOFOLLOW;

/// `O_CLOEXEC`, for [`std::os::unix::fs::OpenOptionsExt::custom_flags`].
///
/// Rust's [`std::fs::File`] already opens every descriptor with this flag set,
/// so passing it changes nothing today. It is passed anyway, and exported for
/// that purpose, because the property matters -- a key log descriptor must not
/// survive into a child process -- and a guarantee that is stated in the call
/// is a guarantee a reader can check. `tls/keylog.rs` asserts the resulting
/// descriptor really carries it rather than trusting either layer.
pub(crate) const O_CLOEXEC: i32 = libc::O_CLOEXEC;

/// `SOCKEINPROGRESS` (`lib/curlx/../curl_setup.h`, `EINPROGRESS` on Unix).
///
/// Here for exactly the reason [`O_NOFOLLOW`] is: the number differs between
/// the mandated targets -- 115 on Linux and 36 on Apple platforms -- so a
/// literal would silently mean something else on one of the four, and `libc` is
/// named nowhere outside this directory.
///
/// Its consumer is `conn/socket.rs`, which needs it because
/// [`std::io::ErrorKind`] cannot express the condition under the mandated
/// minimum Rust version: `ErrorKind::InProgress` exists only behind the
/// unstable `io_error_more` feature, and `rustc 1.75.0` rejects it with
/// `error[E0599]: no variant or associated item named 'InProgress' found for
/// enum 'ErrorKind'`. The distinction is not cosmetic -- `cf_socket_send`
/// treats `SOCKEINPROGRESS` as `CURLE_AGAIN` (`lib/cf-socket.c:1441`) and
/// `cf_socket_recv` deliberately does NOT (`:1512-1514`) -- so the two
/// classifications differ by precisely this value and it has to be nameable.
///
/// Not a syscall and not `unsafe`: an integer, evaluated at compile time.
#[allow(dead_code)]
pub(crate) const SOCKEINPROGRESS: i32 = libc::EINPROGRESS;

/// `SOCKEAFNOSUPPORT` (`EAFNOSUPPORT` on Unix).
///
/// The `errno` `Curl_addr2string` sets for a family that is neither `AF_INET`,
/// `AF_INET6` nor `AF_UNIX`: `errno = SOCKEAFNOSUPPORT; return FALSE;`
/// (`lib/connect.c:256-257`). Its consumer is `crate::conn::addr2string`, whose
/// failure is reported to the user as *"... inet_ntop() failed with errno %d"*
/// -- so the number is observable output and cannot be approximated.
///
/// Exported from here rather than written as a literal for the same reason as
/// [`SOCKEINPROGRESS`]: it is 97 on Linux and 47 on Apple platforms.
#[allow(dead_code)]
pub(crate) const SOCKEAFNOSUPPORT: i32 = libc::EAFNOSUPPORT;

// The syscall seam

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
/// The trait is deliberately narrow. It exposes only primitives that have no
/// safe equivalent -- the ones `socket2` and `std` between them do not cover --
/// and every method returns owned data so that no raw pointer or foreign-owned
/// allocation can escape an implementation. AAP section 0.6.9 fixes the
/// membership test: socket options, non-blocking flags, `getsockname` and
/// `getpeername` are absorbed by `socket2` and are therefore absent here, while
/// the hostname query, `getifaddrs`, `if_nametoindex`, `fsetxattr`, `geteuid`
/// and the descriptor primitives behind a lazily read upload -- `lseek`,
/// `fstat` and `read` -- genuinely remain.
///
/// Terminal handling, broken-down time and the locale are seams of their own --
/// [`TerminalCalls`], [`TimeCalls`] and [`XattrCalls`] -- rather than more
/// methods here, so that a module faking one concern is not made to fake the
/// others. The reasoning is recorded on each of them.
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

    /// The effective user id of the calling process.
    ///
    /// Total: `geteuid(2)` cannot fail. Used to decide whether a file this
    /// process is about to write secrets into is owned by this process,
    /// which is a hardening check with no counterpart in the C tree.
    fn effective_uid(&self) -> u32;

    /// The descriptor's current offset, as `ftell` reports it for a stream.
    ///
    /// `lseek(fd, 0, SEEK_CUR)`, which is what `ftell(stdin)` reduces to for an
    /// unbuffered descriptor. Reproduces `src/tool_formparse.c:128`'s
    /// `origin = ftell(stdin)`.
    fn fd_offset(&self, fd: BorrowedFd<'_>) -> io::Result<i64>;

    /// The size of `fd` when it refers to a regular file, otherwise [`None`].
    ///
    /// `fstat(fd, &sbuf)` followed by `S_ISREG(sbuf.st_mode)`, the pair
    /// `src/tool_formparse.c:131-135` uses to decide whether standard input can
    /// be read lazily. A descriptor that is a pipe, a socket, a terminal or a
    /// directory yields `Ok(None)` -- not an error, because C treats it as an
    /// ordinary "buffer it instead" answer rather than a failure.
    fn fd_regular_size(&self, fd: BorrowedFd<'_>) -> io::Result<Option<i64>>;

    /// Reads from `fd` into `buf`, as `read(2)` does.
    ///
    /// Stands in for `fread(buffer, 1, nitems, stdin)`
    /// (`src/tool_formparse.c:216`). It reads the descriptor rather than a
    /// buffered stream deliberately: the same descriptor is repositioned by
    /// [`SysCalls::seek_fd`] for a retry, and a user-space buffer between the
    /// two would still hold bytes from before the seek. C has no such hazard
    /// because `fseek` on a `FILE *` discards its own buffer.
    fn read_fd(&self, fd: BorrowedFd<'_>, buf: &mut [u8]) -> io::Result<usize>;

    /// Repositions `fd` to an absolute offset, as `fseek(.., SEEK_SET)` does.
    ///
    /// Reproduces `curlx_fseek(stdin, offset, SEEK_SET)`
    /// (`src/tool_formparse.c:244`), where the offset already includes the
    /// origin. A failure is the non-zero `fseek` return that `:245` turns into
    /// `CURL_SEEKFUNC_CANTSEEK`.
    fn seek_fd(&self, fd: BorrowedFd<'_>, offset: i64) -> io::Result<()>;
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
        let rc = unsafe {
            libc::gethostname(
                buf.as_mut_ptr().cast::<libc::c_char>(),
                buf.len(),
            )
        };

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
            cursor =
                unsafe { ptr::addr_of!((*cursor).ifa_next).read_unaligned() };
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

    fn effective_uid(&self) -> u32 {
        // Returned directly, with no conversion: `uid_t` is exactly `u32` on
        // both mandated platforms, so there is nothing to convert and clippy
        // rejects any attempt to write one. The declared return type is what
        // pins the assumption.
        //
        // SAFETY: `geteuid` takes no argument, touches no caller memory and is
        // specified never to fail, so there is no precondition to uphold and no
        // error channel to consult.
        unsafe { libc::geteuid() }
    }

    fn fd_offset(&self, fd: BorrowedFd<'_>) -> io::Result<i64> {
        // SAFETY: `lseek` takes three scalars, touches no caller memory and
        // reports every failure through its return value. A closed or
        // unseekable `fd` is therefore a runtime error, not undefined
        // behaviour.
        let offset = unsafe { libc::lseek(fd.as_raw_fd(), 0, libc::SEEK_CUR) };
        if offset < 0 {
            return Err(io::Error::last_os_error());
        }
        // `off_t` is 64-bit on all four mandated targets, which AAP section
        // 0.6.2 records as load-bearing for this workspace, so the value is
        // already an `i64` and needs no conversion.
        Ok(offset)
    }

    fn fd_regular_size(&self, fd: BorrowedFd<'_>) -> io::Result<Option<i64>> {
        // SAFETY: `core::mem::zeroed::<libc::stat>()` is sound for the same
        // reason it is for `libc::termios` -- the type is a plain aggregate of
        // integers and nested integer aggregates on both mandated platforms,
        // with no member for which an all-zero bit pattern would be invalid,
        // and no member is read before `fstat` has written it.
        let mut info: libc::stat = unsafe { core::mem::zeroed() };

        // SAFETY: `fstat` writes one `struct stat` through its second argument
        // and reads nothing else through it. The pointer is derived from a
        // live, initialised, properly aligned local that outlives the call, and
        // the borrow ends when the call returns.
        let queried = unsafe { libc::fstat(fd.as_raw_fd(), &mut info) };
        if queried != 0 {
            return Err(io::Error::last_os_error());
        }

        // `S_ISREG(m)` is `(m & S_IFMT) == S_IFREG`; the macro is not exposed
        // by the `libc` crate, so the mask is written out.
        if (info.st_mode & libc::S_IFMT) != libc::S_IFREG {
            return Ok(None);
        }
        Ok(Some(info.st_size))
    }

    fn read_fd(&self, fd: BorrowedFd<'_>, buf: &mut [u8]) -> io::Result<usize> {
        let capacity = buf.len();
        let ptr = buf.as_mut_ptr().cast::<libc::c_void>();

        // SAFETY: `read` writes at most `capacity` bytes through `ptr` and
        // reads nothing through it. `ptr` is derived from a live, properly
        // aligned mutable slice of exactly `capacity` bytes that outlives the
        // call, the borrow ends when the call returns, and every failure is
        // reported through the return value.
        let read = unsafe { libc::read(fd.as_raw_fd(), ptr, capacity) };
        if read < 0 {
            return Err(io::Error::last_os_error());
        }
        // `read` is non-negative here and cannot exceed `capacity`, which the
        // call itself guarantees, so the narrowing is exact.
        Ok(read as usize)
    }

    fn seek_fd(&self, fd: BorrowedFd<'_>, offset: i64) -> io::Result<()> {
        // SAFETY: as for `fd_offset` -- three scalars, no caller memory, and
        // every failure reported through the return value.
        let moved =
            unsafe { libc::lseek(fd.as_raw_fd(), offset, libc::SEEK_SET) };
        if moved < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
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
        let family =
            unsafe { ptr::addr_of!((*addr_ptr).sa_family).read_unaligned() };

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
                let raw =
                    unsafe { ptr::addr_of!((*sin).sin_addr).read_unaligned() };
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
                let raw = unsafe {
                    ptr::addr_of!((*sin6).sin6_addr).read_unaligned()
                };
                // SAFETY: as immediately above -- `sin6_scope_id` is a field of
                // the same `struct sockaddr_in6` that the family identified, and
                // is read the same way. This is the value lib/if2ip.c:138-139
                // reads and without which a link-local `--interface` cannot
                // work.
                let scope_id = unsafe {
                    ptr::addr_of!((*sin6).sin6_scope_id).read_unaligned()
                };
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

// gethostname -- supersedes lib/curl_gethostname.c:44-96

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
///   hostname we provide, in order to not leak our real local host
///   name", and the Type-1 message at `lib/vauth/ntlm.c:448` uses
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
#[allow(dead_code)]
pub(crate) fn gethostname() -> CodeResult<String> {
    gethostname_with(&RealSys)
}

/// [`gethostname`] over an injected [`SysCalls`].
///
/// Separated so that every branch above -- the forced terminator, the first-dot
/// truncation, the error mapping and the non-UTF-8 path -- is reachable under
/// Miri, which cannot call `gethostname(2)`.
#[allow(dead_code)]
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

// Interface enumeration -- supersedes the HAVE_GETIFADDRS body of
// lib/if2ip.c:92-174

/// One interface address, owned.
///
/// The snapshot [`interface_addrs`] returns. It holds no borrow of
/// operating-system memory, so it remains valid after `freeifaddrs(3)` has run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct InterfaceAddr {
    /// `ifa_name`, as the kernel reported it: raw bytes, no trailing NUL.
    ///
    /// # Why bytes and not a `String`
    ///
    /// An interface name is an arbitrary NUL-terminated byte string as far as
    /// both mandated kernels are concerned. Linux permits any byte except
    /// `/` and NUL in an `IFNAMSIZ`-bounded name -- `ip link set dev NAME`
    /// accepts UTF-8, Latin-1 and outright invalid sequences alike -- and the
    /// C tree never decodes it: `lib/if2ip.c:113` hands `iface->ifa_name`
    /// straight to `curl_strequal`, which folds ASCII and compares bytes.
    ///
    /// Decoding through [`String::from_utf8_lossy`] would replace every
    /// invalid sequence with U+FFFD, and that replacement is not reversible:
    /// the name could then never again equal the `--interface` value the user
    /// typed, nor the zone identifier parsed out of an IPv6 URL, so
    /// `--interface` and `%<zoneid>` would silently stop working on exactly
    /// the hosts whose names need care. Keeping the bytes is what makes the
    /// comparison possible at all.
    ///
    /// `OsString` was the alternative the same information supports, and is
    /// rejected on the grounds that it buys nothing here: on all four mandated
    /// targets it *is* a `Vec<u8>` behind `OsStrExt`, this value is never used
    /// as a path, and both of its consumers -- [`CString::new`] for
    /// [`if_nametoindex`] and `util::strcase`'s `curl_strequal` for the name
    /// comparison -- want bytes, so an `OsString` would only add a conversion
    /// at each end.
    ///
    /// # Comparison is the caller's job
    ///
    /// This field is the raw name, **unfolded**. Comparison against a
    /// user-supplied `--interface` value is case-insensitive in C
    /// (`lib/if2ip.c:113` uses `curl_strequal`), and the ASCII-folding byte
    /// comparison that reproduces it belongs to `util::strcase`, which
    /// supersedes `lib/strcase.c` and `lib/strequal.c` and backs the exported
    /// `curl_strequal`. It is deliberately not duplicated here: this module
    /// enumerates, it does not decide, and a second folding implementation
    /// would be a second thing to keep in step.
    pub(crate) name: Vec<u8>,

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
#[allow(dead_code)]
pub(crate) fn interface_addrs() -> CodeResult<Vec<InterfaceAddr>> {
    interface_addrs_with(&RealSys)
}

/// [`interface_addrs`] over an injected [`SysCalls`].
#[allow(dead_code)]
pub(crate) fn interface_addrs_with(
    sys: &dyn SysCalls,
) -> CodeResult<Vec<InterfaceAddr>> {
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
        // Internet families carry an address this layer can represent; see
        // `interface_names` for the family-mismatch case the C handles at
        // `lib/if2ip.c:163-166`.
        let (addr, scope_id) = match raw {
            RawIfAddr::V4(octets) => (IpAddr::V4(Ipv4Addr::from(octets)), 0),
            RawIfAddr::V6 { octets, scope_id } => {
                (IpAddr::V6(Ipv6Addr::from(octets)), scope_id)
            }
            RawIfAddr::Unrepresentable => continue,
        };

        // The name moves across unchanged. No decoding happens anywhere on
        // this path, so a name the kernel reported as non-UTF-8 still compares
        // equal to the `--interface` value the user typed.
        addrs.push(InterfaceAddr {
            name: node.name,
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
/// represent an interface that has no Internet address at all -- and on both
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
#[allow(dead_code)]
pub(crate) fn interface_names() -> CodeResult<Vec<Vec<u8>>> {
    interface_names_with(&RealSys)
}

/// [`interface_names`] over an injected [`SysCalls`].
///
/// Each name is the kernel's own bytes, for the reasons given on
/// [`InterfaceAddr::name`]: this list exists so a caller can reproduce the
/// `curl_strequal(iface->ifa_name, interf)` comparison at `lib/if2ip.c:164`,
/// and a lossy decode would make that comparison unable to succeed.
#[allow(dead_code)]
pub(crate) fn interface_names_with(
    sys: &dyn SysCalls,
) -> CodeResult<Vec<Vec<u8>>> {
    let nodes = sys.ifaddrs().map_err(|_| CURLcode::InterfaceFailed)?;

    Ok(nodes
        .into_iter()
        .filter(|node| node.addr.is_some())
        .map(|node| node.name)
        .collect())
}

// if_nametoindex -- supersedes the call at lib/url.c:1615

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
/// The parameter is bytes rather than `&str` deliberately. A zone identifier
/// is the substring of a URL between `%` and the closing `]`, and
/// `lib/url.c:1615` passes it to `if_nametoindex` exactly as it was received;
/// nothing on the C path decodes it, and nothing here does either, so a name
/// that is not valid UTF-8 still resolves. [`CString`] is built straight from
/// these bytes, which is the only construction that can preserve them.
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
#[allow(dead_code)]
pub(crate) fn if_nametoindex(name: &[u8]) -> CodeResult<u32> {
    if_nametoindex_with(&RealSys, name)
}

/// [`if_nametoindex`] over an injected [`SysCalls`].
#[allow(dead_code)]
pub(crate) fn if_nametoindex_with(
    sys: &dyn SysCalls,
    name: &[u8],
) -> CodeResult<u32> {
    // Built from the caller's bytes verbatim. `CString::new` appends the
    // terminator and rejects an interior NUL; it performs no validation and no
    // transformation of what precedes it, so the name the kernel sees is the
    // name the URL carried.
    let cname =
        CString::new(name).map_err(|_| CURLcode::BadFunctionArgument)?;

    sys.if_nametoindex(&cname).ok_or(CURLcode::InterfaceFailed)
}

// Extended attributes -- supersedes the primitive at src/tool_xattr.c:77-104

/// Whether this target provides the extended-attribute write primitive.
///
/// The authority for `USE_XATTR`, and therefore for the `xattr: ` row of
/// `src/curlinfo.c:176-181`, which prints `OFF` from `#ifndef USE_XATTR`.
///
/// # How the answer is computed
///
/// `src/tool_xattr.h:28-36` defines `USE_XATTR` from one of two probes: a
/// configure-detected `HAVE_FSETXATTR` (the `<sys/xattr.h>` route, which covers
/// both Linux and Darwin), or a FreeBSD/MidnightBSD version macro selecting
/// `extattr_set_fd`. Those are *platform* tests, not `--disable-` switches, so
/// this predicate is a `cfg!` over the target rather than over a Cargo feature.
///
/// Both operating systems in the four-target matrix provide `fsetxattr(2)`,
/// with `libc 0.2.189` declaring the five-argument Linux form and the
/// six-argument Darwin form, so the answer is `true` on all four targets. It is
/// nonetheless written as a target test rather than as a bare `true`: a target
/// outside the matrix reports `OFF` truthfully instead of inheriting an
/// unexamined `ON`, and under-reporting a capability is the safe direction
/// (AAP section 0.6.5).
///
/// The BSD `extattr_set_fd` arm has no counterpart here because no BSD is in
/// the matrix; adding one would be a claim this workspace cannot test.
///
/// # Visibility
///
/// `pub(crate)`, with one consumer: [`crate::version::supports_xattr`], which is
/// the engine-owned capability query the command-line tool reads. This function
/// was `pub` and re-exported from the crate root as `curl_rs_lib::xattr_available`
/// alongside a `set_fd_xattr` that nothing called. Both were withdrawn -- see the
/// note in `lib.rs` beside the platform facade -- because a second public name
/// for a capability is a second place the answer can be given, and the two can
/// then disagree. The measured example of exactly that failure is recorded on
/// `supports_xattr` itself.
///
/// The observable answer is unchanged: `supports_xattr` returns what this returns,
/// and it is still `true` on all four mandated targets. Its behaviour is asserted
/// by `the_xattr_primitive_is_available_on_every_supported_target` and
/// `the_xattr_predicate_tracks_the_operating_system` below, which is where the
/// doctest that used to sit here has gone. A doctest could not stay: rustdoc does
/// not run examples on private items, so it would have been silently dead.
pub(crate) fn xattr_available() -> bool {
    cfg!(any(target_os = "linux", target_os = "macos"))
}

// Terminal attributes -- supersedes ttyecho() (src/tool_getpass.c:125-160)
// and the ioctl probe inside get_terminal_columns() (src/terminal.c:56-63)

/// The terminal attributes captured before `ECHO` was cleared.
///
/// Opaque by construction: the `termios` it carries is a private field, so no
/// consumer -- inside this crate or outside it -- can name a `libc` type
/// through this value. The only operations offered are "restore this" and "is
/// there anything to restore".
///
/// [`None`] models the state C is left in when `tcgetattr` fails.
/// `src/tool_getpass.c:127-129` declares `withecho` and `noecho` as
/// **function-scope `static` variables**, so a failed `tcgetattr` leaves
/// `withecho` all-zero and the restoring `tcsetattr` at `:155` then hands the
/// kernel an attribute set that describes no terminal. On the only occasion
/// this happens in practice -- a descriptor that is not a terminal -- that
/// call fails with `ENOTTY` and changes nothing, which is why the C is safe by
/// accident rather than by design. Representing "nothing was captured"
/// explicitly and skipping the restore reproduces the observable outcome
/// exactly while removing the possibility of writing a zeroed attribute set
/// to a real terminal on any other `tcgetattr` failure.
#[derive(Clone, Copy)]
pub(crate) struct SavedTerminal {
    attrs: Option<libc::termios>,
}

impl SavedTerminal {
    /// Nothing was captured, so there is nothing to put back.
    pub(crate) const fn unavailable() -> Self {
        Self { attrs: None }
    }

    /// Whether attributes were captured and can therefore be restored.
    #[allow(dead_code)]
    pub(crate) const fn is_restorable(&self) -> bool {
        self.attrs.is_some()
    }
}

/// The terminal calls `ttyecho` and `get_terminal_columns` perform.
///
/// A seam of its own rather than three more methods on [`SysCalls`], for two
/// reasons. [`SysCalls`] is documented as exposing the hostname, interface and
/// descriptor primitives and nothing else, and widening it would
/// force `dns/if2ip.rs` to supply a fake for terminal handling it never
/// touches. Keeping one trait per concern keeps every fake as small as the
/// logic it drives.
///
/// Both echo methods are **total**: they return no error, because the C
/// ignores the return value of every one of `tcgetattr`, `tcsetattr` and
/// `ioctl`. Inventing a failure channel the C does not have would invite a
/// caller to act on it and diverge.
pub(crate) trait TerminalCalls {
    /// `tcgetattr`, clear `ECHO`, `tcsetattr(TCSANOW)`
    /// (`src/tool_getpass.c:136-139`).
    ///
    /// Returns what was captured, so that the restore can put it back.
    fn echo_disable(&self, fd: BorrowedFd<'_>) -> SavedTerminal;

    /// `tcsetattr(TCSAFLUSH, &withecho)` (`src/tool_getpass.c:155`).
    ///
    /// The action differs from the disabling call on purpose. C uses
    /// `TCSANOW` to clear the bit -- take effect immediately, discard
    /// nothing -- and `TCSAFLUSH` to put it back, which additionally
    /// discards input that arrived while echo was off. That asymmetry is
    /// what stops the newline terminating the password from being echoed
    /// after the fact, so it is reproduced rather than tidied.
    fn echo_restore(&self, fd: BorrowedFd<'_>, saved: &SavedTerminal);

    /// `ioctl(fd, TIOCGWINSZ, &ts)` then `ts.ws_col` (`src/terminal.c:62-63`).
    ///
    /// [`None`] when the `ioctl` fails, which is C's `cols` staying `0`.
    /// The value is returned **unfiltered**: the `cols < 10000` test at
    /// `src/terminal.c:80` sits outside the `ioctl` in C and belongs to the
    /// caller, so applying it here would move a documented CLI bound into the
    /// operating-system layer.
    fn window_columns(&self, fd: BorrowedFd<'_>) -> Option<u32>;
}

impl TerminalCalls for RealSys {
    fn echo_disable(&self, fd: BorrowedFd<'_>) -> SavedTerminal {
        let mut current = MaybeUninit::<libc::termios>::uninit();

        // SAFETY: `libc::tcgetattr` writes a complete `struct termios` through
        // its second argument and reads nothing through it.
        // `MaybeUninit::as_mut_ptr` yields a properly aligned, uniquely
        // borrowed pointer to storage of exactly that size and type, which is
        // the only requirement the call has. `fd.as_raw_fd()` is the descriptor
        // behind a live `BorrowedFd`, so it is open for at least the duration
        // of this call. The return value is inspected before the storage is
        // read, and the storage is left untouched on failure.
        let rc =
            unsafe { libc::tcgetattr(fd.as_raw_fd(), current.as_mut_ptr()) };
        if rc != 0 {
            return SavedTerminal::unavailable();
        }

        // SAFETY: `tcgetattr` returned `0`, which POSIX specifies as having
        // filled every field of the structure, so the storage is initialised.
        let saved = unsafe { current.assume_init() };

        // `src/tool_getpass.c:137-138` -- copy, then clear one bit. The copy is
        // what makes the original restorable.
        let mut noecho = saved;
        noecho.c_lflag &= !libc::ECHO;

        // SAFETY: `libc::tcsetattr` reads a complete `struct termios` through
        // its third argument and writes nothing through it. `&noecho` is a
        // fully initialised value of that type. The descriptor is valid as
        // above. The result is discarded because `src/tool_getpass.c:139`
        // discards it too; a caller must not be able to tell success from
        // failure here, because C cannot.
        let _ =
            unsafe { libc::tcsetattr(fd.as_raw_fd(), libc::TCSANOW, &noecho) };

        SavedTerminal { attrs: Some(saved) }
    }

    fn echo_restore(&self, fd: BorrowedFd<'_>, saved: &SavedTerminal) {
        let Some(attrs) = saved.attrs.as_ref() else {
            // Nothing was captured; see [`SavedTerminal`] for why skipping is
            // the faithful action rather than restoring a zeroed structure.
            return;
        };

        // SAFETY: identical to the `tcsetattr` above -- the call reads the
        // referenced `termios` and writes nothing through it, `attrs` borrows a
        // fully initialised value produced by a successful `tcgetattr`, and the
        // descriptor is live for the duration of the call. `TCSAFLUSH` rather
        // than `TCSANOW` reproduces `src/tool_getpass.c:155`.
        let _ =
            unsafe { libc::tcsetattr(fd.as_raw_fd(), libc::TCSAFLUSH, attrs) };
    }

    fn window_columns(&self, fd: BorrowedFd<'_>) -> Option<u32> {
        let mut size = MaybeUninit::<libc::winsize>::uninit();

        // SAFETY: `TIOCGWINSZ` is a read-only request whose argument is a
        // pointer to one `struct winsize`, which the kernel fills and never
        // reads. `MaybeUninit::as_mut_ptr` yields an aligned, uniquely borrowed
        // pointer to storage of exactly that size and type; passing any other
        // type for this request would be the error, and the type is named here
        // rather than inferred. The descriptor is live for the call. The return
        // value is inspected before the storage is read.
        let rc = unsafe {
            libc::ioctl(fd.as_raw_fd(), libc::TIOCGWINSZ, size.as_mut_ptr())
        };
        if rc != 0 {
            return None;
        }

        // SAFETY: the `ioctl` returned `0`, so the kernel wrote a complete
        // `struct winsize`.
        let size = unsafe { size.assume_init() };

        // `ws_col` is `unsigned short`, so the widening is exact and the value
        // can never be negative -- which is why `src/terminal.c:80`'s
        // `cols >= 0` half is always true on this platform and only the
        // `cols < 10000` half discriminates.
        Some(u32::from(size.ws_col))
    }
}

/// Terminal echo, suppressed for as long as this value lives.
///
/// The RAII counterpart of the `ttyecho(FALSE, fd)` / `ttyecho(TRUE, fd)` pair
/// at `src/tool_getpass.c:174` and `:186`. Restoration happens in [`Drop`], so
/// it runs on the normal path, on an early `return`, and on an unwind --
/// which the C cannot claim, because a `longjmp` or an `abort` between its two
/// calls would leave the terminal with echo off.
///
/// # Ordering, and why [`Self::restore`] exists
///
/// C emits the newline **before** re-enabling echo:
///
/// ```text
/// if(disabled) {
///   fputs("\n", tool_stderr);       /* src/tool_getpass.c:185 */
///   (void)ttyecho(TRUE, fd);        /* src/tool_getpass.c:186 */
/// }
/// ```
///
/// A guard that only restored in `Drop` would leave that order to the accident
/// of where the value happens to fall out of scope, so [`Self::restore`]
/// consumes the guard and restores immediately. Write the newline, then call
/// it; `Drop` remains as the unwind safety net and does nothing a second time.
pub struct EchoGuard<'a> {
    sys: &'a dyn TerminalCalls,
    fd: BorrowedFd<'a>,
    saved: SavedTerminal,
    restored: bool,
}

impl<'a> EchoGuard<'a> {
    /// Whether the caller should treat echo as having been disabled.
    ///
    /// **Always `true`**, and that is not a simplification. The C returns
    /// `TRUE` unconditionally once it has taken the `HAVE_TERMIOS_H` branch
    /// (`src/tool_getpass.c:148`), having discarded the result of both
    /// `tcgetattr` and `tcsetattr`. Only the `#else` arm at `:145-149`, where
    /// neither header exists, returns `FALSE`, and neither mandated target
    /// selects it.
    ///
    /// The distinction is observable and therefore not negotiable. The value
    /// is what `src/tool_getpass.c:183` tests before emitting the extra
    /// newline to standard error, and `tests/runtests.pl` runs curl with
    /// standard input redirected -- so `tcgetattr` fails, yet the C still
    /// emits that newline. Deriving this from
    /// `SavedTerminal::is_restorable` instead -- named in plain text here
    /// because that type is crate-private and an intra-doc link from this
    /// public method to it would be unresolvable for an outside reader --
    /// would suppress a byte the C build writes.
    pub const fn echo_disabled(&self) -> bool {
        true
    }

    /// Restores the saved attributes now, consuming the guard.
    ///
    /// Call this after writing the newline described on the type, so the two
    /// happen in C's order.
    pub fn restore(mut self) {
        self.restore_once();
    }

    /// The single restore path, shared by [`Self::restore`] and [`Drop`].
    fn restore_once(&mut self) {
        if self.restored {
            return;
        }
        self.restored = true;
        self.sys.echo_restore(self.fd, &self.saved);
    }
}

impl Drop for EchoGuard<'_> {
    fn drop(&mut self) {
        self.restore_once();
    }
}

/// Clears the terminal's `ECHO` bit until the returned guard is dropped.
///
/// `fd` is borrowed rather than owned, and the guard cannot outlive it, so the
/// descriptor is still open when the restore runs. `src/tool_getpass.c:170-172`
/// opens `/dev/tty` read-only and falls back to standard input, and
/// `:189-190` closes the descriptor only when it is not standard input;
/// choosing the descriptor and closing it are the caller's business, and
/// `BorrowedFd` is what keeps this function out of that decision.
pub fn disable_echo(fd: BorrowedFd<'_>) -> EchoGuard<'_> {
    // `&RealSys` is promoted to a `'static` reference: `RealSys` is a unit
    // struct with no interior mutability and no destructor, so this introduces
    // neither a `static mut` nor a lazily initialised singleton.
    disable_echo_with(&RealSys, fd)
}

/// [`disable_echo`] over an injected [`TerminalCalls`].
pub(crate) fn disable_echo_with<'a>(
    sys: &'a dyn TerminalCalls,
    fd: BorrowedFd<'a>,
) -> EchoGuard<'a> {
    let saved = sys.echo_disable(fd);

    EchoGuard {
        sys,
        fd,
        saved,
        restored: false,
    }
}

/// The terminal's width in columns, as `src/terminal.c:62-63` reads it.
///
/// The descriptor is **standard input**, which is what the C hard-codes at
/// `src/terminal.c:59` and `:62` -- not standard output and not standard
/// error. That choice is load-bearing: under `tests/runtests.pl` standard
/// input is redirected, so the probe fails in the C build too and the width
/// falls back to 79.
///
/// The result is unfiltered. `src/terminal.c:80` applies
/// `cols >= 0 && cols < 10000` and `:83-84` supplies the 79 fallback; both
/// are CLI-side policy and belong to `curl-rs/src/terminal.rs`.
pub fn terminal_columns() -> Option<u32> {
    terminal_columns_with(&RealSys)
}

/// [`terminal_columns`] over an injected [`TerminalCalls`].
pub(crate) fn terminal_columns_with(sys: &dyn TerminalCalls) -> Option<u32> {
    // `io::Stdin` implements `AsFd`, so descriptor 0 is borrowed through a safe
    // standard-library handle rather than reconstructed from the raw number.
    // Nothing here locks or reads it.
    let stdin = io::stdin();

    sys.window_columns(stdin.as_fd())
}

// Extended attributes -- supersedes xattr() (src/tool_xattr.c:76-102)

/// The extended-attribute call, behind one signature for both operating
/// systems.
pub(crate) trait XattrCalls {
    /// `fsetxattr(fd, name, value, value.len(), ...)`.
    ///
    /// The two mandated operating systems spell this differently and the C
    /// selects between them with `HAVE_FSETXATTR_6` and `HAVE_FSETXATTR_5`
    /// (`src/tool_xattr.c:88-92`): macOS takes six arguments, with a
    /// `position` before the flags, and Linux takes five. Both extra
    /// arguments are `0` in C, and both spellings collapse into this one
    /// method so that no caller has to know which target it is building for.
    fn fsetxattr(
        &self,
        fd: BorrowedFd<'_>,
        name: &CStr,
        value: &[u8],
    ) -> io::Result<()>;
}

impl XattrCalls for RealSys {
    fn fsetxattr(
        &self,
        fd: BorrowedFd<'_>,
        name: &CStr,
        value: &[u8],
    ) -> io::Result<()> {
        // SAFETY: `fsetxattr` reads `name` as a NUL-terminated C string and
        // reads exactly `value.len()` bytes through the value pointer; it
        // writes through neither. `CStr::as_ptr` yields the first, and
        // `value.as_ptr()` with `value.len()` yields the second over a
        // uniquely borrowed slice, so the read cannot overrun. An empty
        // `value` gives a dangling-but-aligned pointer with a length of `0`,
        // which no read touches. The descriptor is live for the whole call.
        // The trailing zero is C's own literal at `src/tool_xattr.c:91`.
        #[cfg(target_os = "linux")]
        let rc = unsafe {
            libc::fsetxattr(
                fd.as_raw_fd(),
                name.as_ptr(),
                value.as_ptr().cast::<libc::c_void>(),
                value.len(),
                0,
            )
        };

        // SAFETY: as for the Linux arm above. Darwin's form takes two
        // trailing arguments rather than one -- `position` and `options` --
        // and both are C's own literals at `src/tool_xattr.c:89`.
        #[cfg(target_os = "macos")]
        let rc = unsafe {
            libc::fsetxattr(
                fd.as_raw_fd(),
                name.as_ptr(),
                value.as_ptr().cast::<libc::c_void>(),
                value.len(),
                0,
                0,
            )
        };

        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

/// Records one extended attribute on an open file.
///
/// Supersedes `xattr()` at `src/tool_xattr.c:76-102`, whose whole body is one
/// platform-selected `fsetxattr` call. The absent-value guard at `:82` and the
/// `CURL_FAKE_XATTR` debug short-circuit at `:84-87` are CLI-side policy and
/// stay in `curl-rs/src/output/xattr.rs`, which already separates them.
///
/// # The value length reproduces `strlen`, deliberately
///
/// C measures the value with `strlen(value)` (`src/tool_xattr.c:89`), so a
/// value containing an interior NUL is written only up to that byte. The
/// truncation happens here because in C it happens inside the function this
/// one supersedes. Values reaching this path come from `curl_easy_getinfo`
/// and are NUL-terminated C strings in the first place, so the case is
/// theoretical -- but reproducing it costs one line and removes a difference
/// that would otherwise have to be argued about.
///
/// # Errors
///
/// The platform error, carrying its `errno`, so a caller can render the
/// diagnostic C composes at `src/tool_operate.c:637-639`:
/// `warnf("Error setting extended attributes on '%s': %s", ...,
/// curlx_strerror(errno, ...))`. C reads the thread-global `errno` after the
/// call returns; Rust has no such global to consult, so the number travels
/// inside [`io::Error`] instead and
/// [`io::Error::raw_os_error`] recovers it.
///
/// A `name` containing an interior NUL cannot be a C string and yields
/// `EINVAL` without any call being made. The attribute names are fixed ASCII
/// literals in the C tree (`user.creator`, `user.xdg.origin.url`,
/// `user.xdg.referrer.url`, `user.mime_type`), so this is a total-function
/// guarantee rather than a reachable path.
pub fn set_file_xattr(
    fd: BorrowedFd<'_>,
    name: &[u8],
    value: &[u8],
) -> io::Result<()> {
    set_file_xattr_with(&RealSys, fd, name, value)
}

/// [`set_file_xattr`] over an injected [`XattrCalls`].
pub(crate) fn set_file_xattr_with(
    sys: &dyn XattrCalls,
    fd: BorrowedFd<'_>,
    name: &[u8],
    value: &[u8],
) -> io::Result<()> {
    let name = CString::new(name)
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;

    // `strlen(value)` -- see the note on the wrapper.
    let end = value.iter().position(|&byte| byte == 0);
    let measured = match end {
        Some(index) => value.get(..index).unwrap_or_default(),
        None => value,
    };

    sys.fsetxattr(fd, &name, measured)
}

// Broken-down time and the locale -- supersedes the curlx_gmtime/strftime
// pair at src/tool_writeout.c:581-588, the local-time rendering behind
// --trace-time, and the setlocale calls at src/tool_operate.c:2271-2272

/// The time and locale calls that have no safe equivalent.
///
/// Every one of these is a C library function rather than a system call, and
/// every one of them is here for the same reason: its result depends on
/// process-wide state -- the time zone database and the current locale -- that
/// no Rust crate in this workspace's dependency set reads.
pub(crate) trait TimeCalls {
    /// `localtime_r(&epoch, &tm)` then `tm.tm_gmtoff`.
    ///
    /// The signed offset in seconds that must be added to UTC to obtain local
    /// time at `epoch`, or [`None`] when the conversion fails. The offset is
    /// asked for **at a given instant** rather than in the abstract, because
    /// it changes across a daylight-saving transition and a trace line
    /// written either side of one must carry the offset that applied then.
    fn utc_offset_secs(&self, epoch: i64) -> Option<i64>;

    /// `strftime(out, out.len(), format, gmtime_r(&epoch))`.
    ///
    /// The number of bytes written, or [`None`] when `strftime` returns `0`.
    /// `src/tool_writeout.c:588` treats that as "write nothing at all", so
    /// the two outcomes -- did not fit, and produced nothing -- collapse
    /// exactly as they do in C.
    ///
    /// The broken-down time is built **inside** the implementation, from
    /// `gmtime_r`, rather than being passed in. That is what makes the result
    /// byte-identical to C: `curlx_gmtime` is `gmtime_r`, and the fields it
    /// sets that a hand-built structure would have to guess at --
    /// `tm_gmtoff`, `tm_zone`, `tm_isdst` -- are exactly the ones a locale's
    /// own `%c`, `%x`, `%X` or `%r` expansion may go on to read.
    fn strftime_gmt(
        &self,
        format: &CStr,
        epoch: i64,
        out: &mut [u8],
    ) -> Option<usize>;

    /// `setlocale(LC_ALL, "")` followed by `setlocale(LC_NUMERIC, "C")`.
    ///
    /// `false` if either call fails. Reproduces
    /// `src/tool_operate.c:2271-2272` exactly, including the order and the
    /// deliberate reversal of `LC_NUMERIC`: the tool wants the user's locale
    /// for time and messages, and the C locale for numbers, so that a decimal
    /// point stays a decimal point.
    fn set_locale_from_environment(&self) -> bool;
}

impl TimeCalls for RealSys {
    fn utc_offset_secs(&self, epoch: i64) -> Option<i64> {
        let when = libc::time_t::try_from(epoch).ok()?;
        let mut broken = MaybeUninit::<libc::tm>::uninit();

        // SAFETY: `localtime_r` reads one `time_t` through its first argument
        // and writes a complete `struct tm` through its second, reading nothing
        // through it. `&when` borrows a live, initialised local, and
        // `MaybeUninit::as_mut_ptr` yields an aligned, uniquely borrowed
        // to storage of exactly the right type and size. The returned pointer
        // aliases that same storage and is used only for the null test, never
        // dereferenced, so no aliasing rule is engaged.
        let result = unsafe { libc::localtime_r(&when, broken.as_mut_ptr()) };
        if result.is_null() {
            return None;
        }

        // SAFETY: `localtime_r` returned non-null, which POSIX specifies as
        // having filled the structure.
        let broken = unsafe { broken.assume_init() };

        // `tm_gmtoff` is `c_long`, which is `i64` on all four mandated targets,
        // so this is an annotated binding rather than a conversion -- writing
        // `i64::from` here would be a conversion between one type and itself,
        // which `clippy::useless_conversion` rejects. On a target where
        // `c_long` were narrower this line would fail to compile, which is the
        // right outcome: the FFI design forfeits 32-bit deliberately
        // (AAP 0.6.2), and a compile error at the exact site beats a silent
        // widening on a platform nothing else here supports.
        let offset: i64 = broken.tm_gmtoff;

        Some(offset)
    }

    fn strftime_gmt(
        &self,
        format: &CStr,
        epoch: i64,
        out: &mut [u8],
    ) -> Option<usize> {
        if out.is_empty() {
            // `strftime` is specified over a buffer with room for at least the
            // terminator; a zero-length one has no valid outcome, and handing
            // C library a one-past-the-end pointer is not one either. The
            // wrapper rejects this case too, which is where it is covered by
            // test; this copy is a local guarantee, so the SAFETY note below
            // does not have to reason about who called.
            return None;
        }

        let when = libc::time_t::try_from(epoch).ok()?;
        let mut broken = MaybeUninit::<libc::tm>::uninit();

        // SAFETY: `gmtime_r` has the same contract as `localtime_r` above --
        // it reads one `time_t`, writes one complete `struct tm`, and returns
        // a pointer aliasing the storage it filled. The pointer is used only
        // for the null test, never dereferenced. This is `curlx_gmtime`
        // (`src/tool_writeout.c:581`).
        let result = unsafe { libc::gmtime_r(&when, broken.as_mut_ptr()) };
        if result.is_null() {
            return None;
        }

        // SAFETY: non-null return means the structure is initialised.
        let broken = unsafe { broken.assume_init() };

        // SAFETY: `strftime` writes at most `maxsize` bytes -- terminator
        // included -- through the first argument and never reads it; it reads
        // `format` as a NUL-terminated C string and reads the `struct tm`
        // through the last argument. `out.as_mut_ptr()` with `out.len()` covers
        // a live, uniquely borrowed slice of exactly that many initialised
        // bytes, `CStr::as_ptr` supplies the terminated format, and `&broken`
        // borrows the fully initialised structure `gmtime_r` just produced.
        // `libc::c_char` is `i8` on all four mandated targets and shares size
        // and alignment with `u8`, so the cast changes only signedness. The
        // return value is a length that never exceeds `maxsize`.
        let written = unsafe {
            libc::strftime(
                out.as_mut_ptr().cast::<libc::c_char>(),
                out.len(),
                format.as_ptr(),
                &broken,
            )
        };

        if written == 0 {
            None
        } else {
            Some(written)
        }
    }

    fn set_locale_from_environment(&self) -> bool {
        // Two NUL-terminated literals, so no allocation and no fallible
        // conversion stands between the caller and the call.
        const FROM_ENVIRONMENT: &[u8] = b"\0";
        const C_LOCALE: &[u8] = b"C\0";

        // SAFETY: `setlocale` reads its second argument as a NUL-terminated C
        // string and writes nothing through it. Both literals above are
        // NUL-terminated `&'static [u8]`, so the pointers are valid for the
        // whole program. The returned pointer addresses storage the C library
        // owns; it is used only for the null test and is never dereferenced,
        // retained or freed, which is what keeps this free of the lifetime
        // hazard `setlocale`'s return value otherwise carries.
        let all = unsafe {
            libc::setlocale(
                libc::LC_ALL,
                FROM_ENVIRONMENT.as_ptr().cast::<libc::c_char>(),
            )
        };
        if all.is_null() {
            return false;
        }

        // SAFETY: as above.
        let numeric = unsafe {
            libc::setlocale(
                libc::LC_NUMERIC,
                C_LOCALE.as_ptr().cast::<libc::c_char>(),
            )
        };

        !numeric.is_null()
    }
}

/// The local time zone's offset from UTC, in seconds, at `epoch`.
///
/// Positive east of Greenwich. [`None`] when the platform cannot answer, which
/// a caller must render as UTC rather than as a guess -- exactly what
/// `curl-rs/src/util.rs` does with it.
///
/// The offset is narrowed to [`i32`] because that is the width the trace
/// formatter needs and because the narrowing is where an implausible value
/// gets rejected: every real offset lies within 14 hours of UTC, so a value
/// that does not fit is a broken time zone database, not a location.
pub fn local_utc_offset_secs(epoch: i64) -> Option<i32> {
    local_utc_offset_secs_with(&RealSys, epoch)
}

/// [`local_utc_offset_secs`] over an injected [`TimeCalls`].
pub(crate) fn local_utc_offset_secs_with(
    sys: &dyn TimeCalls,
    epoch: i64,
) -> Option<i32> {
    i32::try_from(sys.utc_offset_secs(epoch)?).ok()
}

/// Formats `epoch` in UTC with the platform's `strftime`, into `out`.
///
/// Returns the number of bytes written, or [`None`] when nothing should be
/// written at all -- `strftime` returning `0`, which
/// `src/tool_writeout.c:588` tests before its `fputs`.
///
/// # Why the platform's implementation and not a Rust one
///
/// Because the output is locale-dependent and the C tool sets the locale.
/// `src/tool_operate.c:2271` calls `setlocale(LC_ALL, "")`, so `LC_TIME`
/// governs `%a`, `%A`, `%b`, `%B`, `%h`, `%c`, `%p`, `%r`, `%x` and `%X`, and
/// a table of English names cannot reproduce them. `src/tool_writeout.c:588`
/// hands the format to the platform `strftime`, and so does this.
///
/// # Errors
///
/// [`None`] also when `format` contains an interior NUL -- it cannot then be
/// a C format string -- and when `out` is empty. Neither is reachable from
/// `%time{}`, whose format is delimited by `}` and whose buffer is C's
/// `char output[256]` (`src/tool_writeout.c:529`), but both are answered
/// rather than assumed away because a `--write-out` format is user input.
pub fn strftime_gmt(
    format: &[u8],
    epoch: i64,
    out: &mut [u8],
) -> Option<usize> {
    strftime_gmt_with(&RealSys, format, epoch, out)
}

/// [`strftime_gmt`] over an injected [`TimeCalls`].
pub(crate) fn strftime_gmt_with(
    sys: &dyn TimeCalls,
    format: &[u8],
    epoch: i64,
    out: &mut [u8],
) -> Option<usize> {
    if out.is_empty() {
        // Rejected on this side of the seam so that the guarantee holds for
        // every implementation of `TimeCalls`, not only `RealSys`, and so that
        // it is reachable by test without a real `strftime`. `RealSys` repeats
        // the check as a local invariant of its own `unsafe` block.
        return None;
    }

    let format = CString::new(format).ok()?;

    sys.strftime_gmt(&format, epoch, out)
}

/// Adopts the environment's locale, keeping numbers in the C locale.
///
/// `false` when the platform refuses either half. Reproduces
/// `src/tool_operate.c:2271-2272`.
///
/// # This mutates process-wide state, and that is the point
///
/// `setlocale` is the one call in this module with a global effect, which is
/// why it is a single explicit function rather than something done lazily on
/// first use. It must be called **once, from the command-line tool's start-up,
/// before any thread is spawned**, exactly where C calls it -- the C library's
/// locale is not thread-safe to change once other threads are running. Its
/// owner is therefore `curl-rs/src/operate/mod.rs`, which supersedes
/// `src/tool_operate.c`; no library path may call it, because a library that
/// changes its host process's locale is a defect.
///
/// Until that owner calls it, the process stays in the `"C"` locale, and every
/// [`strftime_gmt`] result is the C locale's -- which is what an unlocalised
/// build produces and is byte-identical to the English names it would
/// otherwise have to hard-code.
pub fn set_locale_from_environment() -> bool {
    set_locale_from_environment_with(&RealSys)
}

/// [`set_locale_from_environment`] over an injected [`TimeCalls`].
pub(crate) fn set_locale_from_environment_with(sys: &dyn TimeCalls) -> bool {
    sys.set_locale_from_environment()
}

// Process identity -- the safe side

/// The effective user id of this process.
///
/// Total, because `geteuid(2)` is. Used by `tls/keylog.rs` to reject a
/// pre-existing `SSLKEYLOGFILE` owned by somebody else before writing session
/// secrets into it.
pub(crate) fn effective_uid() -> u32 {
    effective_uid_with(&RealSys)
}

/// [`effective_uid`] over an injected [`SysCalls`].
pub(crate) fn effective_uid_with(sys: &dyn SysCalls) -> u32 {
    sys.effective_uid()
}

// Descriptor extent, reads and seeks -- the safe side
//
// These three exist for one caller: `curl-rs/src/output/formparse.rs` decides
// whether standard input is a regular file it can read lazily, and reads and
// repositions it if so. `src/tool_formparse.c:121-143,216,244` does it with
// `fileno`, `ftell`, `fstat`, `fread` and `fseek` on the `stdin` stream.

/// The extent of `fd` when it is a regular file that can be read lazily.
///
/// `Some((origin, size))` where `origin` is the descriptor's current offset and
/// `size` is the file's total length -- exactly the pair
/// `src/tool_formparse.c:128,131-135` gathers before deciding not to buffer.
///
/// [`None`] is the ordinary answer, not an error: it covers a pipe, a socket, a
/// terminal, a directory, a closed descriptor and an unseekable one alike,
/// because C's compound condition at `:131-135` collapses all of them into the
/// same "buffer it instead" branch at `:140`. C additionally requires
/// `origin >= 0`, which a successful `lseek` already guarantees.
pub(crate) fn regular_file_extent(fd: BorrowedFd<'_>) -> Option<(i64, i64)> {
    regular_file_extent_with(&RealSys, fd)
}

/// [`regular_file_extent`] over an injected [`SysCalls`].
pub(crate) fn regular_file_extent_with(
    sys: &dyn SysCalls,
    fd: BorrowedFd<'_>,
) -> Option<(i64, i64)> {
    // Ordered as the C's `&&` chain is, so a descriptor that cannot report its
    // offset is never also stat'ed.
    let origin = sys.fd_offset(fd).ok()?;
    let size = sys.fd_regular_size(fd).ok()??;
    Some((origin, size))
}

/// Reads from `fd` into `buf`, returning the number of bytes placed there.
///
/// `Ok(0)` is end of input, which is what a short `fread` without `ferror`
/// means at `src/tool_formparse.c:216-219`.
pub(crate) fn read_fd(fd: BorrowedFd<'_>, buf: &mut [u8]) -> io::Result<usize> {
    read_fd_with(&RealSys, fd, buf)
}

/// [`read_fd`] over an injected [`SysCalls`].
pub(crate) fn read_fd_with(
    sys: &dyn SysCalls,
    fd: BorrowedFd<'_>,
    buf: &mut [u8],
) -> io::Result<usize> {
    sys.read_fd(fd, buf)
}

/// Repositions `fd` to `offset`, counted from the start of the file.
pub(crate) fn seek_fd(fd: BorrowedFd<'_>, offset: i64) -> io::Result<()> {
    seek_fd_with(&RealSys, fd, offset)
}

/// [`seek_fd`] over an injected [`SysCalls`].
pub(crate) fn seek_fd_with(
    sys: &dyn SysCalls,
    fd: BorrowedFd<'_>,
    offset: i64,
) -> io::Result<()> {
    sys.seek_fd(fd, offset)
}

// The argument vector -- supersedes cleanarg() (src/tool_getparam.c:625-637)

/// The process's argument vector, as the scrubber needs to see it.
///
/// A seam of its own, for the reason every other seam in this file is one:
/// Miri cannot be handed a real argument vector, and a clean Miri run over this
/// crate is a required gate. Every byte of the *decision* -- which element
/// matches, at which offset, and how many bytes are overwritten -- therefore
/// runs above this trait and is covered against a pure-Rust fake, while the
/// implementation that touches the loader's memory is three lines long.
///
/// Both methods are **total**. C's `cleanarg` returns `void` and ignores every
/// failure it could observe, so inventing a failure channel here would invite a
/// caller to act on one the C does not have.
pub(crate) trait ArgvCalls {
    /// How many elements the vector has, `argv[0]` included.
    ///
    /// Zero means "there is no writable argument vector in this process",
    /// which is the state Miri and any platform without the capture mechanism
    /// are in. It is the runtime answer to the question C answers at configure
    /// time with `HAVE_WRITABLE_ARGV`.
    fn count(&self) -> usize;

    /// The bytes of element `index`, up to but excluding its terminator.
    ///
    /// Copied out rather than borrowed. A borrow would have to name the
    /// lifetime of memory this process does not own, and would alias the very
    /// bytes [`ArgvCalls::wipe`] then writes; an owned copy makes the scanning
    /// loop an ordinary safe function.
    fn read(&self, index: usize) -> Option<Vec<u8>>;

    /// Overwrites `len` bytes of element `index`, starting at `at`, with `*`.
    ///
    /// `at + len` never exceeds the length [`ArgvCalls::read`] reported for
    /// the same index, so the terminator is never touched: C's
    /// `memset(str, '*', strlen(str))` leaves the NUL in place and so does
    /// this, which is what keeps the element a valid C string for `/proc` and
    /// for `ps`.
    fn wipe(&self, index: usize, at: usize, len: usize);
}

/// Where the loader's `argv` was recorded, and how many elements it had.
///
/// `-1` and null are the "never captured" state, which is what
/// [`RealArgv::count`] reports as zero. Two statics rather than one struct
/// because they are written by a function that runs before anything in this
/// crate can have initialised a lock, and an [`AtomicIsize`] plus an
/// [`AtomicPtr`] need no initialisation at all.
///
/// Both carry the same `#[cfg]` as [`capture_argv`], the only writer, because
/// macOS reads the vector from `_NSGetArgv` instead and Miri has none: leaving
/// them compiled on a target that never writes them would be two dead statics,
/// and the mandated four-target build allows no warning on any of them.
///
/// [`AtomicIsize`]: core::sync::atomic::AtomicIsize
/// [`AtomicPtr`]: core::sync::atomic::AtomicPtr
#[cfg(all(not(miri), target_os = "linux"))]
static ARGV_COUNT: core::sync::atomic::AtomicIsize =
    core::sync::atomic::AtomicIsize::new(-1);

/// The captured `argv` base pointer. See [`ARGV_COUNT`].
#[cfg(all(not(miri), target_os = "linux"))]
static ARGV_BASE: core::sync::atomic::AtomicPtr<*mut libc::c_char> =
    core::sync::atomic::AtomicPtr::new(ptr::null_mut());

/// Records `argc` and `argv` as the dynamic loader passes them.
///
/// # Why a constructor is the only way in
///
/// `std::env::args_os` copies; it cannot hand back the loader's memory, and
/// nothing else in the standard library can either. On an ELF platform the
/// loader calls every function pointer in `.init_array` with the same
/// `(argc, argv, envp)` triple it gives `main`, which is the one moment those
/// values are observable. Recording them here and nowhere else is what lets
/// [`scrub_argument`] be an ordinary safe function later.
///
/// # Why it is absent under Miri
///
/// Miri does execute `.init_array` entries, but it calls them with **no
/// arguments**; a three-parameter callee then reads parameters that were never
/// passed, which Miri correctly reports as undefined behaviour ("calling a
/// function with fewer arguments than it requires"). Measured, not assumed.
/// Miri also models no process argument vector for `ps` to show, so the
/// capability has nothing to do there. The constructor is therefore compiled
/// out under Miri and [`RealArgv::count`] answers zero, which
/// [`scrub_argument_with`] turns into the documented no-op.
#[cfg(all(not(miri), target_os = "linux"))]
extern "C" fn capture_argv(
    argc: libc::c_int,
    argv: *mut *mut libc::c_char,
    _envp: *mut *mut libc::c_char,
) {
    use core::sync::atomic::Ordering;

    // A negative or zero `argc`, or a null vector, stays the "never captured"
    // state rather than being stored and defended against at every use.
    if argc > 0 && !argv.is_null() {
        // `Release` pairs with the `Acquire` load in `RealArgv`, so a reader
        // that sees the pointer also sees the count.
        ARGV_COUNT.store(argc as isize, Ordering::Relaxed);
        ARGV_BASE.store(argv, Ordering::Release);
    }
}

/// The `.init_array` slot holding [`capture_argv`].
///
/// `#[used]` is what keeps it: the symbol has no caller, so without it the
/// compiler is free to discard the static and the linker's `--gc-sections`
/// certainly would. Verified in this workspace at both optimisation levels and
/// inside a `cargo test` harness binary, which is why the test below can assert
/// that the capture happened.
#[cfg(all(not(miri), target_os = "linux"))]
#[used]
#[link_section = ".init_array"]
static CAPTURE_ARGV: extern "C" fn(
    libc::c_int,
    *mut *mut libc::c_char,
    *mut *mut libc::c_char,
) = capture_argv;

/// The loader's argument vector, or nothing.
///
/// On Linux the answer comes from [`CAPTURE_ARGV`]. On macOS it comes from
/// `_NSGetArgv`/`_NSGetArgc`, which libSystem exports for exactly this purpose
/// and which may be called at any time -- so no constructor is needed there,
/// and none is declared, because `.init_array` is not how Mach-O spells
/// initialisers and a `#[link_section]` naming it would be silently inert.
pub(crate) struct RealArgv;

impl RealArgv {
    /// The base pointer and element count, once, so that a scan cannot see the
    /// two disagree.
    #[cfg(all(not(miri), target_os = "macos"))]
    fn vector(&self) -> Option<(*mut *mut libc::c_char, usize)> {
        extern "C" {
            fn _NSGetArgv() -> *mut *mut *mut libc::c_char;
            fn _NSGetArgc() -> *mut libc::c_int;
        }

        // SAFETY: both functions are libSystem exports that return the address
        // of a process-global variable and take no arguments, so there is no
        // precondition to uphold at the call. Each result is checked for null
        // before it is read, and each read is a single aligned load of a value
        // the dynamic loader initialised before any user code ran.
        let (argv, argc) = unsafe {
            let argv_slot = _NSGetArgv();
            let argc_slot = _NSGetArgc();
            if argv_slot.is_null() || argc_slot.is_null() {
                return None;
            }
            (*argv_slot, *argc_slot)
        };

        if argv.is_null() || argc <= 0 {
            return None;
        }
        Some((argv, argc as usize))
    }

    /// The base pointer and element count recorded by [`capture_argv`].
    #[cfg(all(not(miri), target_os = "linux"))]
    fn vector(&self) -> Option<(*mut *mut libc::c_char, usize)> {
        use core::sync::atomic::Ordering;

        let base = ARGV_BASE.load(Ordering::Acquire);
        let count = ARGV_COUNT.load(Ordering::Relaxed);
        if base.is_null() || count <= 0 {
            return None;
        }
        Some((base, count as usize))
    }

    /// No vector: neither capture mechanism is compiled in.
    ///
    /// Reached under Miri, and on any target that is neither Linux nor macOS.
    /// The four mandated targets are all one or the other, so this arm exists
    /// to keep the module compiling rather than to serve a platform.
    #[cfg(any(miri, not(any(target_os = "linux", target_os = "macos"))))]
    fn vector(&self) -> Option<(*mut *mut libc::c_char, usize)> {
        None
    }

    /// Element `index`, as a raw pointer, bounds-checked against the count.
    fn slot(&self, index: usize) -> Option<*mut libc::c_char> {
        let (base, count) = self.vector()?;
        if index >= count {
            return None;
        }
        // SAFETY: `index < count`, and the loader guarantees `count`
        // consecutive readable pointers at `base` -- that is what `argc` means.
        // The offset therefore stays inside one allocated object, and the load
        // is of a `*mut c_char` the loader wrote before `main` was entered.
        let slot = unsafe { *base.add(index) };
        if slot.is_null() {
            None
        } else {
            Some(slot)
        }
    }
}

impl ArgvCalls for RealArgv {
    fn count(&self) -> usize {
        self.vector().map_or(0, |(_, count)| count)
    }

    fn read(&self, index: usize) -> Option<Vec<u8>> {
        let slot = self.slot(index)?;
        // SAFETY: `slot` is a non-null element of the loader's argument
        // vector, so it points at a NUL-terminated string that lives for the
        // whole process. `to_bytes` measures to that terminator and the result
        // is copied immediately, so no borrow of foreign memory escapes.
        let bytes = unsafe { CStr::from_ptr(slot) }.to_bytes();
        Some(bytes.to_vec())
    }

    fn wipe(&self, index: usize, at: usize, len: usize) {
        let Some(slot) = self.slot(index) else {
            return;
        };
        // Re-measure rather than trusting the caller's arithmetic: this is the
        // one operation in the module that writes to memory the process does
        // not own, so the bound is established here, immediately above the
        // write, from the string as it is right now.
        // SAFETY: as in `read` -- `slot` is a live NUL-terminated string from
        // the argument vector.
        let length = unsafe { CStr::from_ptr(slot) }.to_bytes().len();
        let Some(end) = at.checked_add(len) else {
            return;
        };
        if end > length {
            return;
        }
        // SAFETY: `at + len <= length`, and `length` is the number of bytes
        // before this element's terminator, so the written range lies wholly
        // inside the element and never reaches the NUL. The pointer is
        // `*mut c_char` from the vector the loader made writable -- which is
        // the whole premise of `HAVE_WRITABLE_ARGV` -- and `u8` and `c_char`
        // have the same size and alignment on every mandated target. The
        // caller's exclusive access for the duration of the scan is the
        // documented precondition of `scrub_argument`.
        unsafe {
            ptr::write_bytes(slot.cast::<u8>().add(at), b'*', len);
        }
    }
}

/// Where `needle` sits at the end of `element`, when C would have wiped it.
///
/// C hands `cleanarg` the very pointer the parser was reading, so it wipes
/// from that offset to the end of that string and nothing else. This function
/// recovers the same offset from the bytes alone, which is what lets the
/// capability be reached without threading a vector index and a byte offset
/// through every layer of the parser.
///
/// Two conditions, and the second is what makes the rule precise rather than
/// merely plausible:
///
/// * `element` must **end** with `needle`. A separate argument (`--user
///   bob:pw`) matches wholly; a glued one (`-ubob:pw`, `--user=bob:pw`)
///   matches at the offset the parser's own pointer had, so the wipe reproduces
///   `-u******` and `--user=******` exactly.
/// * a match that is not the whole element is accepted only when the element
///   begins with `-`. Without it, `curl https://h/bob:pw -u bob:pw` would wipe
///   the tail of the URL, and every argument that merely happens to end with a
///   credential's bytes would be at risk. With it, the only elements that can
///   match partially are the option-bearing ones -- which are the only ones a
///   parser pointer can point into.
///
/// Returns [`None`] when the element must be left alone, including for an empty
/// `needle`: `strlen("")` is zero, so C's `memset` writes nothing.
fn wipe_offset(element: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || element.len() < needle.len() {
        return None;
    }
    let at = element.len() - needle.len();
    if element.get(at..)? != needle {
        return None;
    }
    if at != 0 && element.first() != Some(&b'-') {
        return None;
    }
    Some(at)
}

/// Overwrites `argument` with `*` wherever it appears in this process's
/// argument vector, reproducing `cleanarg` (`src/tool_getparam.c:625-637`).
///
/// Returns how many elements were overwritten. C's `cleanarg` returns `void`
/// and its caller discards the outcome; the count exists so that the behaviour
/// can be asserted, and discarding it is correct.
///
/// # What this is for
///
/// The C comment at `:628-630` states the purpose exactly: "now that getstr has
/// copied the contents of nextarg, wipe the next argument out so that the
/// username:password is not displayed in the system process list". Eleven rows
/// of the option table carry `ARG_CLEAR`, all of them credential-bearing, and
/// every one of them is a value that `ps`, `/proc/<pid>/cmdline` and any
/// process listing would otherwise show to every other user on the host for as
/// long as the transfer runs.
///
/// # Why `HAVE_WRITABLE_ARGV` is not optional here
///
/// `src/tool_getparam.c:637` does define the no-op arm, and it is a supported
/// configuration -- but it is not the configuration the mandated targets build.
/// `configure.ac:1809` defines `HAVE_WRITABLE_ARGV` when its runtime probe
/// succeeds and forces it on when cross-compiling for Apple, and
/// `CMakeLists.txt:619` sets it unconditionally for `APPLE`. On all four
/// mandated targets the C build really does wipe the argument, so implementing
/// the no-op arm would have been a silent security regression dressed as a
/// configuration choice.
///
/// # Concurrency, stated because it is a real precondition
///
/// The argument vector is process-global memory that this process does not own,
/// and `std::env::args_os` reads the same bytes. This function must therefore
/// be called only while nothing else is reading or writing that vector -- which
/// is exactly the position C's `cleanarg` is in, called from inside argument
/// parsing. The sole caller satisfies it by construction:
/// `curl-rs/src/main.rs` collects the command line into owned `OsString`s once,
/// before parsing begins, and no other code in the workspace reads the argument
/// vector at all (measured: one `args_os` call in the whole workspace).
/// Concurrent calls to *this* function are serialised below, so a caller cannot
/// create a race by scrubbing two values at once.
///
/// # When it does nothing
///
/// Under Miri, and on a target where no capture mechanism is compiled in, there
/// is no vector to write and the return value is `0`. That is a genuine no-op
/// and is reported as one rather than being presented as a wipe.
pub fn scrub_argument(argument: &[u8]) -> usize {
    // `Mutex::new` is a `const fn`, so this needs no lazy initialisation. A
    // poisoned lock is recovered rather than propagated: the guarded region
    // performs byte stores of a single constant and holds no invariant that a
    // panic elsewhere could have broken.
    static SERIALISE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _held = SERIALISE.lock().unwrap_or_else(|error| error.into_inner());

    scrub_argument_with(&RealArgv, argument)
}

/// [`scrub_argument`] over an injected [`ArgvCalls`].
///
/// Scans **every** element rather than stopping at the first match, and the
/// difference matters. C wipes one location because it holds the pointer; this
/// holds only the bytes, and a credential can appear more than once on a
/// command line -- `-u bob:pw --proxy-user bob:pw` is the ordinary case.
/// Stopping early would leave the second occurrence legible in `ps`, which is
/// the one outcome this capability exists to prevent, so the scan continues.
/// `argv[0]` is skipped: it is the program name, it is not an option value, and
/// C's parser never points into it.
pub(crate) fn scrub_argument_with(
    argv: &dyn ArgvCalls,
    argument: &[u8],
) -> usize {
    if argument.is_empty() {
        return 0;
    }

    let mut wiped = 0;
    for index in 1..argv.count() {
        let Some(element) = argv.read(index) else {
            continue;
        };
        if let Some(at) = wipe_offset(&element, argument) {
            argv.wipe(index, at, argument.len());
            wiped += 1;
        }
    }
    wiped
}

// The counting allocator -- feature `memdebug`, DEFAULT OFF

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
    use core::sync::atomic::{AtomicBool, AtomicI64, Ordering};
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
    pub(crate) fn calloc_record(
        count: usize,
        size: usize,
        addr: usize,
    ) -> Option<Record> {
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
    pub(crate) fn realloc_record(
        old: usize,
        size: usize,
        addr: usize,
    ) -> Option<Record> {
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
    /// log, and it lets [`TrackingAllocator::realloc`] hold the lock *across* the
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
    ///
    /// The single choke point through which every allocation passes, and
    /// therefore the one place the cap can be armed from without an
    /// initialization hook -- see [`ensure_limit_armed`] for why that is
    /// necessary and why it is also faithful.
    fn capped(func: &str) -> bool {
        ensure_limit_armed();

        take_allocation(&LIMIT) && deny(func)
    }

    /// The arming half of `curl_dbg_memlimit()` (`lib/memdebug.c:175-181`).
    ///
    /// Returns whether this call took effect. The C guards the whole body with
    /// `if(!memlimit)`, so only the first call arms the cap and every later one
    /// is ignored -- including one asking for a zero cap. The compare-exchange
    /// against [`NO_LIMIT`] says exactly that, and arming is one-shot by
    /// construction, so nothing can disarm it again.
    ///
    /// Taken as a function over its counter rather than over the global, for the
    /// same reason [`take_allocation`] is: it makes the one-shot semantics
    /// testable without arming the process-wide cap. That matters more than it
    /// looks. `curl-rs-lib/src/lib.rs` installs [`TrackingAllocator`] as the
    /// `#[global_allocator]`, so arming [`LIMIT`] in a test would impose the cap
    /// on the whole test binary: unrelated tests allocating in parallel spend
    /// the counter, and every allocation after that is denied, which
    /// `handle_alloc_error` turns into a process abort. Only production code may
    /// arm the global, and `the_process_cap_starts_disarmed` guards that.
    fn arm_cap(counter: &AtomicI64, allocations: u32) -> bool {
        counter
            .compare_exchange(
                NO_LIMIT,
                i64::from(allocations),
                Ordering::Relaxed,
                Ordering::Relaxed,
            )
            .is_ok()
    }

    /// Caps the number of allocations that will succeed, process-wide.
    ///
    /// Reproduces `curl_dbg_memlimit()` (`lib/memdebug.c:175-181`). This is the
    /// torture-mode entry point; it is one-shot, and there is deliberately no
    /// way to disarm it, because the C offers none either.
    ///
    /// The behaviour itself is covered by [`arm_cap`]'s tests: arming the
    /// process-wide counter from inside a test binary would deny that binary's
    /// own allocations.
    pub(crate) fn set_memlimit(allocations: u32) -> bool {
        arm_cap(&LIMIT, allocations)
    }

    /// Parses a `CURL_MEMLIMIT` value the way `curlx_str_number` does.
    ///
    /// # Why this function exists at all
    ///
    /// Without it the cap is unreachable in production. `src/tool_main.c:117-125`
    /// is the *only* caller of `curl_dbg_memlimit()` outside the test programs:
    ///
    /// ```c
    /// env = curl_getenv("CURL_MEMLIMIT");
    /// if(env) {
    ///   curl_off_t num;
    ///   const char *p = env;
    ///   if(!curlx_str_number(&p, &num, LONG_MAX))
    ///     curl_dbg_memlimit((long)num);
    ///   curl_free(env);
    /// }
    /// ```
    ///
    /// and `tests/runner.pm:508` is what sets the variable, once per torture
    /// iteration, clearing it again at `:526`. `STRE_OK` is `0`, so the
    /// apparently inverted `if(!...)` applies the limit when the parse
    /// *succeeded*.
    ///
    /// # The grammar, reproduced exactly
    ///
    /// `str_num_base` (`lib/curlx/strparse.c`) with base 10 is stricter than
    /// [`str::parse`] in three ways and laxer in one, and all four matter:
    ///
    /// * No sign is accepted. `-5` fails at the first character, because `-` is
    ///   not a digit, so it does not become a huge unsigned value.
    /// * No leading whitespace is accepted, for the same reason.
    /// * At least one digit is required, so an empty value is `STRE_NO_NUM` and
    ///   arms nothing -- which is what makes clearing the variable work.
    /// * Trailing non-digits are *not* an error. The C stops at the first one and
    ///   returns `STRE_OK`, and `tool_main.c` ignores the remainder, so `10abc`
    ///   is a limit of ten.
    ///
    /// Values above `LONG_MAX` are `STRE_OVERFLOW` and arm nothing, matching the
    /// `max` argument the C passes.
    ///
    /// # Saturation
    ///
    /// [`set_memlimit`] counts in [`u32`] while the C counts in `long`. A value
    /// between `u32::MAX` and `LONG_MAX` therefore saturates instead of
    /// overflowing. This is observationally exact: the cap only ever matters when
    /// it is reached, and a process cannot perform four billion allocations
    /// inside one torture iteration. The alternative -- widening the counter --
    /// would cost a wider atomic on the hot path of every allocation for a
    /// distinction nothing can observe.
    fn memlimit_from_env(value: Option<OsString>) -> Option<u32> {
        use std::os::unix::ffi::OsStrExt as _;

        // Bytes rather than a `&str`: the environment is not required to hold
        // UTF-8, and rejecting a value for that reason would be a behaviour the C
        // does not have. The digits this grammar accepts are ASCII either way.
        let raw = value?;
        let bytes = raw.as_bytes();

        // `if(!valid_digit(*p, m)) return STRE_NO_NUM;` -- the first byte decides
        // whether there is a number here at all.
        let mut digits = bytes.iter().copied().take_while(u8::is_ascii_digit);
        let first = digits.next()?;

        // `LONG_MAX` on every mandated target, which is what the C passes as
        // `max`. Accumulating in `i64` and checking against this bound reproduces
        // the C's overflow test rather than approximating it.
        const LONG_MAX: i64 = i64::MAX;

        let mut num = i64::from(first - b'0');
        for digit in digits {
            let n = i64::from(digit - b'0');

            // `if(num > ((max - n) / base)) return STRE_OVERFLOW;` -- the C
            // checks before multiplying, so the multiplication itself can never
            // overflow. Transcribed rather than replaced by `checked_mul`,
            // because the two agree on every input and the transcription is what
            // a reader can verify against the source.
            if num > (LONG_MAX - n) / 10 {
                return None;
            }

            num = num * 10 + n;
        }

        // The saturating step documented above. `num` is non-negative by
        // construction -- no sign was accepted -- so this cannot wrap.
        Some(u32::try_from(num).unwrap_or(u32::MAX))
    }

    /// Suppresses allocator bookkeeping on this thread while alive.
    ///
    /// [`Logger::enter`] cannot serve this purpose, even though it raises the
    /// same flag: it returns [`None`] when no log destination is configured, and
    /// `CURL_MEMLIMIT` is independent of `CURL_MEMDEBUG`. `lib/memdebug.c` keeps
    /// them independent in exactly the same way -- `countcheck()` writes its
    /// `LIMIT` line to standard error at `:193-194` whether or not a log file was
    /// ever opened -- so a cap must still work with logging switched off.
    struct Bookkeeping;

    impl Bookkeeping {
        /// [`Some`] only when this thread was not already inside bookkeeping.
        fn enter() -> Option<Self> {
            let entered = IN_LOG.try_with(|flag| {
                if flag.get() {
                    false
                } else {
                    flag.set(true);
                    true
                }
            });

            if matches!(entered, Ok(true)) {
                Some(Self)
            } else {
                None
            }
        }
    }

    impl Drop for Bookkeeping {
        fn drop(&mut self) {
            // `try_with` rather than `with`: during thread teardown the
            // thread-local may already be destroyed, and that must not panic
            // inside a `Drop` running in the allocator.
            let _ = IN_LOG.try_with(|flag| flag.set(false));
        }
    }

    /// Whether the environment has been consulted for a cap yet.
    ///
    /// Separate from [`LIMIT`] because "no cap was requested" and "the question
    /// has not been asked" are different states, and conflating them would make
    /// the environment be read on every single allocation.
    static LIMIT_ARMED: AtomicBool = AtomicBool::new(false);

    /// Arms the process-wide cap from `CURL_MEMLIMIT`, at most once.
    ///
    /// # Why this is lazy rather than eager
    ///
    /// Reading the environment allocates, so it cannot happen unguarded inside
    /// the allocator, and there is no earlier hook to do it from: this crate is a
    /// library, `#[global_allocator]` has no initialization callback, and
    /// `curl-rs/src/main.rs` -- the analogue of the C's `tool_main.c` -- is
    /// outside this checkpoint's file set. Doing it on first use keeps the cap
    /// working end-to-end today, and [`init_from_env`] additionally exposes it as
    /// an explicit hook for that `main` to call when it lands.
    ///
    /// # What laziness costs, measured rather than estimated
    ///
    /// Arming on the first allocation means the allocations the Rust runtime
    /// performs before `main` are counted, whereas the C's counting begins
    /// partway through `main()`. Measured on this platform with a probe that
    /// installs [`TrackingAllocator`] as the `#[global_allocator]`: exactly two
    /// allocations precede `main`, so `CURL_MEMLIMIT=1` and `=2` deny inside
    /// start-up and abort through `handle_alloc_error` (`SIGABRT`), while `>=3`
    /// reaches `main` and denies where expected. The offset is a constant two,
    /// not a leak.
    ///
    /// That is disclosed rather than smoothed over, but it is inert in practice
    /// for an independent reason: torture mode is the only consumer of small
    /// caps, and `tests/runtests.pl:847-849` hard-requires the `Debug` feature,
    /// which this build deliberately withholds (AAP section 0.6.6). Closing the
    /// gap properly needs the arming call to move into the command-line tool's
    /// `main`, exactly where `src/tool_main.c:117-125` has it -- which is what
    /// [`init_from_env`] exists for, and why it is `pub(crate)` rather than
    /// private.
    ///
    /// # Why the fast path must stay this cheap
    ///
    /// It runs before every allocation in the process. It is one relaxed atomic
    /// load and a branch; the environment is touched only on the first few calls,
    /// and only from a thread that is not already inside bookkeeping.
    fn ensure_limit_armed() {
        if LIMIT_ARMED.load(Ordering::Relaxed) {
            return;
        }

        // A re-entrant allocation -- one performed *by* the environment read
        // below -- takes this branch and leaves the flag clear, so the next
        // non-re-entrant allocation retries. That is why this is not a `Once`:
        // the work must be abandonable, not merely skipped.
        let Some(_suppressed) = Bookkeeping::enter() else {
            return;
        };

        // `swap` rather than `store`, so that two threads racing here cannot both
        // read the environment and both call `arm_cap`. The loser observes `true`
        // and does nothing.
        if LIMIT_ARMED.swap(true, Ordering::Relaxed) {
            return;
        }

        if let Some(limit) =
            memlimit_from_env(std::env::var_os("CURL_MEMLIMIT"))
        {
            arm_cap(&LIMIT, limit);
        }
    }

    /// Applies `CURL_MEMLIMIT` explicitly, reproducing `src/tool_main.c:117-125`.
    ///
    /// Idempotent, and safe to call from anywhere. [`ensure_limit_armed`] already
    /// performs the same work on first allocation, so this exists so that the
    /// command-line tool can arm the cap at the same point in start-up that the C
    /// does, rather than leaving the timing to whichever allocation happens
    /// first.
    ///
    /// Returns whether a cap was armed by *this* call: [`false`] both when the
    /// variable is absent or unparsable and when a cap was already in place,
    /// which mirrors `curl_dbg_memlimit()`'s `if(!memlimit)` guard.
    ///
    /// # A measured caveat on that return value
    ///
    /// In a process that has already allocated -- which is every process, since
    /// the runtime allocates before `main` -- [`ensure_limit_armed`] will have
    /// read the environment first, so this returns [`false`] even though a cap
    /// *is* armed and came from the same variable. Verified with the probe
    /// described on [`ensure_limit_armed`]: the hook reported `false` in all six
    /// environment cases, while the cap itself engaged correctly in each case
    /// where the value was parsable. The return value therefore answers "did I
    /// arm it", not "is a cap in force", and a caller wanting the latter should
    /// not infer it from here.
    pub(crate) fn init_from_env() -> bool {
        let already = LIMIT_ARMED.swap(true, Ordering::Relaxed);

        if already {
            return false;
        }

        // Through `set_memlimit`, not `arm_cap` directly, so that the Rust
        // call graph is the C's: `memory_tracking_init()`
        // (`src/tool_main.c:117-125`) parses the variable and then calls
        // `curl_dbg_memlimit()`, which is what `set_memlimit` supersedes. The
        // two are behaviourally identical -- `set_memlimit(n)` IS
        // `arm_cap(&LIMIT, n)` -- so this changes no outcome; what it changes is
        // that the cap has exactly one production entry point instead of a
        // second private path around it, which is also what stops
        // `set_memlimit` from being an unreferenced item.
        match memlimit_from_env(std::env::var_os("CURL_MEMLIMIT")) {
            Some(limit) => set_memlimit(limit),
            None => false,
        }
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
        unsafe fn realloc(
            &self,
            block: *mut u8,
            layout: Layout,
            new_size: usize,
        ) -> *mut u8 {
            if capped("realloc") {
                return ptr::null_mut();
            }

            let old = block as usize;

            // Taken BEFORE the reallocation and held across it. That ordering is
            // the whole point: lib/memdebug.c:330-332 explains that the record
            // must be written under the same lock, "as we get out-of-order log
            // entries otherwise, since another thread might alloc the memory
            // released by realloc() before otherwise would log it". The C takes
            // its debug mutex at `:334` and logs through
            // `curl_dbg_log_locked` at `:349`; holding this guard does the
            // same. When logging is disabled there is no lock and no ordering
            // to preserve.
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
            let record =
                malloc_record(135, 0x7f_2a_00_10).expect("record fits");
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
        ///
        /// Ignored under Miri because the assertion is about what the operating
        /// system refuses, and Miri's isolation refuses `open` before the
        /// operating system is ever consulted -- "unsupported operation: `open`
        /// not available when isolation is enabled". The gate this crate is held
        /// to (`.github/workflows/rust-miri.yml`) deliberately passes no
        /// `-Zmiri-disable-isolation`, so the only alternatives are to skip this
        /// one assertion or to weaken the interpreter for the whole run. Note
        /// that a single un-ignored offender aborts the entire Miri run rather
        /// than failing one test, so this matters to every other test here.
        #[test]
        #[cfg_attr(
            miri,
            ignore = "File::create is refused by Miri's isolation before the OS sees it"
        )]
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
        ///
        /// Exercised through [`arm_cap`] against a local counter rather than
        /// through [`set_memlimit`] against [`LIMIT`]. That is deliberate and
        /// it is not a weaker test: the two differ only in which counter they
        /// address, and arming the real one here would be fatal. Arming is
        /// one-shot, so nothing could disarm it again, and from that moment the
        /// `#[global_allocator]` would deny the test binary's own allocations
        /// once the cap ran out -- which `handle_alloc_error` reports by
        /// aborting the process, taking every other test with it.
        /// `CURL_MEMLIMIT` unset, or set to nothing, arms nothing.
        ///
        /// Both must be inert: `tests/runner.pm:526` clears the variable after
        /// each torture iteration, and `str_num_base` reports `STRE_NO_NUM` for
        /// an empty string because its first byte is not a digit.
        #[test]
        fn an_absent_or_empty_memlimit_arms_nothing() {
            assert_eq!(memlimit_from_env(None), None);
            assert_eq!(memlimit_from_env(Some(OsString::from(""))), None);
        }

        /// A plain decimal value is taken verbatim, zero included.
        ///
        /// Zero is not a no-op: `countcheck()` denies on `memsize <= 0`
        /// (`lib/memdebug.c:186`), so a cap of zero denies the next
        /// allocation. `135` is the count `tests/data/test1` records.
        #[test]
        fn a_decimal_memlimit_is_taken_verbatim() {
            assert_eq!(memlimit_from_env(Some(OsString::from("0"))), Some(0));
            assert_eq!(memlimit_from_env(Some(OsString::from("1"))), Some(1));
            assert_eq!(
                memlimit_from_env(Some(OsString::from("135"))),
                Some(135)
            );
            assert_eq!(
                memlimit_from_env(Some(OsString::from("0135"))),
                Some(135),
                "leading zeros are digits like any other"
            );
        }

        /// Trailing non-digits end the number without failing it.
        ///
        /// `str_num_base` stops at the first non-digit and returns `STRE_OK`, and
        /// `src/tool_main.c:121-122` ignores whatever `p` was left pointing at.
        /// This is laxer than [`str::parse`] and the difference is deliberate.
        #[test]
        fn trailing_non_digits_are_ignored_rather_than_rejected() {
            assert_eq!(
                memlimit_from_env(Some(OsString::from("10abc"))),
                Some(10)
            );
            assert_eq!(memlimit_from_env(Some(OsString::from("7 "))), Some(7));
            assert_eq!(
                memlimit_from_env(Some(OsString::from("42,99"))),
                Some(42)
            );
        }

        /// A value that does not begin with a digit is `STRE_NO_NUM`.
        ///
        /// The sign cases matter most: `str_num_base` never accepts `-` or `+`,
        /// so a negative value arms nothing instead of becoming an enormous
        /// unsigned cap. Leading whitespace is rejected for the same reason.
        #[test]
        fn a_value_not_starting_with_a_digit_arms_nothing() {
            for value in ["-5", "+5", " 5", "\t5", "abc", "x1", ".5"] {
                assert_eq!(
                    memlimit_from_env(Some(OsString::from(value))),
                    None,
                    "{value:?} must not arm a cap"
                );
            }
        }

        /// A value above `LONG_MAX` is `STRE_OVERFLOW` and arms nothing.
        #[test]
        fn an_overflowing_memlimit_arms_nothing() {
            // i64::MAX + 1, and a value far beyond any width.
            assert_eq!(
                memlimit_from_env(Some(OsString::from("9223372036854775808"))),
                None
            );
            assert_eq!(
                memlimit_from_env(Some(OsString::from(
                    "99999999999999999999999"
                ))),
                None
            );
        }

        /// A value between `u32::MAX` and `LONG_MAX` saturates rather than wraps.
        #[test]
        fn a_huge_but_valid_memlimit_saturates() {
            assert_eq!(
                memlimit_from_env(Some(OsString::from("9223372036854775807"))),
                Some(u32::MAX),
                "LONG_MAX is a valid cap in the C and must not wrap here"
            );
            assert_eq!(
                memlimit_from_env(Some(OsString::from("4294967295"))),
                Some(u32::MAX),
                "u32::MAX itself is exact"
            );
            assert_eq!(
                memlimit_from_env(Some(OsString::from("4294967296"))),
                Some(u32::MAX)
            );
        }

        /// A non-UTF-8 environment value is parsed, not rejected.
        ///
        /// The C reads bytes, so a stray invalid byte after the digits must not
        /// change the outcome. Rejecting the value for not being UTF-8 would be
        /// a behaviour the C does not have.
        #[test]
        fn a_non_utf8_memlimit_still_parses() {
            use std::os::unix::ffi::OsStringExt as _;

            let value = OsString::from_vec(vec![b'1', b'2', 0xFF, 0xFE]);

            assert_eq!(memlimit_from_env(Some(value)), Some(12));
        }

        /// The environment-driven arming path never touches the global cap here.
        ///
        /// [`ensure_limit_armed`] and [`init_from_env`] arm [`LIMIT`], which is
        /// the counter this test binary's own `#[global_allocator]` consults, so
        /// exercising them here could abort the whole binary -- the same hazard
        /// documented on [`arm_cap`]. The parsing is therefore covered through
        /// [`memlimit_from_env`], which is pure, and this test records that the
        /// separation is deliberate by asserting the global is still disarmed.
        #[test]
        fn the_environment_path_leaves_the_global_cap_alone() {
            assert_eq!(
                LIMIT.load(Ordering::Relaxed),
                NO_LIMIT,
                "no test may arm the process-wide allocation cap"
            );
        }

        /// The re-entrancy guard is exclusive per thread, and releases.
        ///
        /// This is what stops the environment read inside [`ensure_limit_armed`]
        /// from recursing into the allocator bookkeeping that called it.
        #[test]
        fn bookkeeping_is_exclusive_and_releases() {
            {
                let outer = Bookkeeping::enter();
                assert!(outer.is_some(), "the first entry must succeed");
                assert!(
                    Bookkeeping::enter().is_none(),
                    "a nested entry must be refused, which is what breaks the \
                     recursion"
                );
            }

            assert!(
                Bookkeeping::enter().is_some(),
                "the flag must be lowered again on drop"
            );
        }

        #[test]
        fn the_process_cap_is_one_shot() {
            // Exercised over a LOCAL counter, never over the process-wide
            // `LIMIT`. `set_memlimit` is the thin wrapper that applies this to
            // the global, and arming the global here would abort the test
            // binary -- see the reasoning on `arm_cap` and the guard below.
            let counter = AtomicI64::new(NO_LIMIT);

            assert!(arm_cap(&counter, 4), "the first call must arm the cap");
            assert!(!arm_cap(&counter, 9), "a second call must be ignored");
            assert_eq!(
                counter.load(Ordering::Relaxed),
                4,
                "the ignored call must not move the counter"
            );

            // A zero cap is refused like any other second call, so an armed
            // counter can never be reset to "deny everything".
            assert!(!arm_cap(&counter, 0), "still armed, so still ignored");
            assert_eq!(
                counter.load(Ordering::Relaxed),
                4,
                "the refused zero cap must not move the counter"
            );
        }

        /// No test may arm the process-wide cap, and a disarmed cap denies
        /// nothing.
        ///
        /// A regression guard, not a property of the C. Because
        /// `curl-rs-lib/src/lib.rs` installs [`TrackingAllocator`] as the
        /// `#[global_allocator]` under this feature, an armed [`LIMIT`] applies
        /// to the entire test binary: unrelated tests allocating in parallel
        /// spend the counter, and the next allocation is denied and aborts the
        /// process through `handle_alloc_error`. That failure is hard to
        /// trace back to its cause, so this test names the cause once.
        ///
        /// The second assertion records the plain-`memdebug` guarantee: a
        /// disarmed cap denies nothing until a torture run asks it to. Do not
        /// delete either one as trivial.
        #[test]
        fn the_process_cap_starts_disarmed() {
            assert_eq!(
                LIMIT.load(Ordering::Relaxed),
                NO_LIMIT,
                "a test armed the process-wide allocation cap; only production \
                 code may call set_memlimit(), because this allocator is the \
                 global allocator and the cap would abort the test binary"
            );
            assert!(!take_allocation(&LIMIT), "a disarmed cap denies nothing");
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
                    Layout::from_size_align(128, layout.align())
                        .expect("valid layout"),
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
            let bytes =
                unsafe { core::slice::from_raw_parts(zeroed, layout.size()) };
            assert!(bytes.iter().all(|&byte| byte == 0));

            // SAFETY: `zeroed` is currently allocated by this allocator with
            // exactly `layout`, which is the pair `dealloc` requires.
            unsafe { allocator.dealloc(zeroed, layout) };
        }
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    // Only the two independent-observation helpers below take a
    // descriptor integer: they re-read `ECHO` and an extended
    // attribute straight from the descriptor to check an assertion
    // against something other than the code under test. No wrapper
    // signature uses it -- see the audit block in `ffi/mod.rs`.
    use std::os::unix::io::RawFd;
    // Needed only here: the production wrappers take a `BorrowedFd` that a
    // caller has already produced, so nothing outside the tests converts one.
    use std::os::fd::AsFd;
    use std::panic::{self, AssertUnwindSafe};

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
        /// The uid `effective_uid` reports.
        uid: u32,
        /// The offset `fd_offset` reports, or the `errno` it reports.
        fd_offset: Result<i64, i32>,
        /// The size `fd_regular_size` reports: `Ok(None)` is "not a regular
        /// file", which is an answer rather than a failure.
        fd_regular_size: Result<Option<i64>, i32>,
        /// Bytes `read_fd` hands out, consumed from the front, or its `errno`.
        fd_bytes: RefCell<Result<Vec<u8>, i32>>,
        /// What `seek_fd` reports.
        fd_seek: Result<(), i32>,
        /// Every offset `seek_fd` received, in order.
        observed_seeks: RefCell<Vec<i64>>,
    }

    impl FakeSys {
        fn new() -> Self {
            Self {
                hostname: Ok(Vec::new()),
                ifaddrs: Ok(Vec::new()),
                index: None,
                observed_first_byte: Cell::new(None),
                observed_name: RefCell::new(None),
                uid: 0,
                fd_offset: Ok(0),
                fd_regular_size: Ok(None),
                fd_bytes: RefCell::new(Ok(Vec::new())),
                fd_seek: Ok(()),
                observed_seeks: RefCell::new(Vec::new()),
            }
        }

        /// A descriptor that is a regular file of `size`, positioned at
        /// `origin`, whose contents are `bytes`.
        fn with_regular_file(origin: i64, size: i64, bytes: &[u8]) -> Self {
            Self {
                fd_offset: Ok(origin),
                fd_regular_size: Ok(Some(size)),
                fd_bytes: RefCell::new(Ok(bytes.to_vec())),
                ..Self::new()
            }
        }

        fn with_uid(uid: u32) -> Self {
            Self { uid, ..Self::new() }
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
            *self.observed_name.borrow_mut() =
                Some(name.to_bytes_with_nul().to_vec());
            self.index
        }

        fn effective_uid(&self) -> u32 {
            self.uid
        }

        fn fd_offset(&self, _fd: BorrowedFd<'_>) -> io::Result<i64> {
            self.fd_offset.map_err(io::Error::from_raw_os_error)
        }

        fn fd_regular_size(
            &self,
            _fd: BorrowedFd<'_>,
        ) -> io::Result<Option<i64>> {
            self.fd_regular_size.map_err(io::Error::from_raw_os_error)
        }

        fn read_fd(
            &self,
            _fd: BorrowedFd<'_>,
            buf: &mut [u8],
        ) -> io::Result<usize> {
            let mut held = self.fd_bytes.borrow_mut();
            match &mut *held {
                Ok(bytes) => {
                    // Front of the queue, so a caller reading twice sees the
                    // second half -- the property `read(2)` has and a plain
                    // clone would not.
                    let taken = bytes.len().min(buf.len());
                    buf[..taken].copy_from_slice(&bytes[..taken]);
                    bytes.drain(..taken);
                    Ok(taken)
                }
                Err(errno) => Err(io::Error::from_raw_os_error(*errno)),
            }
        }

        fn seek_fd(&self, _fd: BorrowedFd<'_>, offset: i64) -> io::Result<()> {
            self.observed_seeks.borrow_mut().push(offset);
            self.fd_seek.map_err(io::Error::from_raw_os_error)
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

        let name =
            gethostname_with(&sys).expect("a filled buffer is not a failure");

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

        let name =
            gethostname_with(&sys).expect("invalid UTF-8 is not a failure");

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
        assert_eq!(addrs[0].name, b"eth0");
        assert_eq!(addrs[0].addr, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)));
    }

    /// `lib/if2ip.c:138-139` -- `sin6_scope_id` is surfaced for IPv6 and is
    /// zero for IPv4. Without it a link-local `--interface` cannot work.
    #[test]
    fn the_scope_id_is_surfaced_for_ipv6_and_zero_for_ipv4() {
        let link_local = [
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x1a, 0x4a, 0xff, 0xfe, 0x00,
            0x00, 0x01,
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
    /// only represent the two Internet ones, so an `AF_PACKET` or `AF_LINK`
    /// node contributes no address.
    #[test]
    fn an_unrepresentable_family_contributes_no_address() {
        let sys = FakeSys::with_ifaddrs(vec![
            link_node("eth0"),
            v4_node("eth0", [10, 0, 0, 1]),
        ]);

        let addrs = interface_addrs_with(&sys).expect("enumeration succeeds");

        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].addr, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    }

    /// A non-UTF-8 interface name survives enumeration **byte for byte**.
    ///
    /// Decoding it -- which [`String::from_utf8_lossy`] would do, substituting
    /// U+FFFD -- destroys the only thing the name is for: `lib/if2ip.c:113`
    /// compares it against the `--interface` value with `curl_strequal`, and a
    /// replaced byte can never compare equal again. The two byte sequences
    /// below are both invalid UTF-8 and would collapse onto the *same* decoded
    /// string, so the assertion that they remain distinct is what actually
    /// pins the property.
    #[test]
    fn a_non_utf8_interface_name_survives_byte_for_byte() {
        let first = IfNode {
            name: vec![0xff, 0xfe],
            addr: Some(RawIfAddr::V4([127, 0, 0, 1])),
        };
        let second = IfNode {
            name: vec![0xfe, 0xff],
            addr: Some(RawIfAddr::V4([127, 0, 0, 2])),
        };
        let sys = FakeSys::with_ifaddrs(vec![first, second]);

        let addrs = interface_addrs_with(&sys).expect("enumeration succeeds");

        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0].name, [0xff, 0xfe]);
        assert_eq!(addrs[1].name, [0xfe, 0xff]);
        assert_ne!(
            addrs[0].name, addrs[1].name,
            "a lossy decode would make these two names equal"
        );

        // The same property through the second projection.
        assert_eq!(
            interface_names_with(&sys),
            Ok(vec![vec![0xff, 0xfe], vec![0xfe, 0xff]])
        );
    }

    /// The bytes reach [`if_nametoindex`] unaltered, which is the other half of
    /// the same property: a zone identifier that is not valid UTF-8 must still
    /// be resolvable, because `lib/url.c:1615` passes it through untouched.
    #[test]
    fn a_non_utf8_zone_identifier_reaches_the_seam_unaltered() {
        let sys = FakeSys::with_index(Some(4));

        assert_eq!(if_nametoindex_with(&sys, &[b'e', 0xff, b'0']), Ok(4));
        assert_eq!(
            sys.observed_name.borrow().as_deref(),
            Some(&[b'e', 0xff, b'0', 0][..]),
            "the raw bytes must reach the seam, NUL-terminated and unchanged"
        );
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
        assert_eq!(interface_names_with(&sys), Ok(vec![b"eth9".to_vec()]));
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
            Ok(vec![b"lo".to_vec(), b"lo".to_vec(), b"eth0".to_vec()])
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
            assert!(names.contains(&entry.name), "{:?} missing", entry.name);
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
            if_nametoindex_with(&sys, b"definitely-not-an-interface"),
            Err(CURLcode::InterfaceFailed)
        );
    }

    #[test]
    fn a_known_interface_name_yields_its_index() {
        let sys = FakeSys::with_index(Some(7));

        assert_eq!(if_nametoindex_with(&sys, b"eth0"), Ok(7));
    }

    /// The name reaches the seam NUL-terminated and otherwise unaltered.
    #[test]
    fn the_name_reaches_the_seam_nul_terminated() {
        let sys = FakeSys::with_index(Some(1));
        let _ = if_nametoindex_with(&sys, b"eth0");

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
            if_nametoindex_with(&sys, b"eth\0 0"),
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
            if_nametoindex_with(&sys, b""),
            Err(CURLcode::InterfaceFailed)
        );
    }

    /// The real syscall against the loopback interface, whose name differs
    /// between the two mandated operating systems.
    #[test]
    #[cfg_attr(miri, ignore = "if_nametoindex(3) is a foreign function")]
    fn the_real_loopback_interface_has_a_non_zero_index() {
        #[cfg(target_os = "linux")]
        let loopback = b"lo".as_slice();
        #[cfg(target_os = "macos")]
        let loopback = b"lo0".as_slice();

        let index = if_nametoindex(loopback).expect("loopback always exists");

        assert!(index > 0);
    }

    #[test]
    #[cfg_attr(miri, ignore = "if_nametoindex(3) is a foreign function")]
    fn a_real_unknown_interface_name_fails() {
        assert_eq!(
            if_nametoindex(b"curl-rs-no-such-if"),
            Err(CURLcode::InterfaceFailed)
        );
    }

    // -- Extended attributes ------------------------------------------------

    /// Every target in the mandated matrix provides `fsetxattr(2)`, so the
    /// `xattr: ` row of `src/curlinfo.c:176-181` reports `ON` on all four.
    #[test]
    fn the_xattr_primitive_is_available_on_every_supported_target() {
        assert!(xattr_available());
    }

    /// Not a tautology: the assertion is that the answer is *derived* from the
    /// operating system rather than asserted, which is precisely what
    /// `src/tool_xattr.h:28-36` derives it from. A target outside the matrix
    /// would report `OFF` rather than claim a primitive it does not have.
    #[test]
    fn the_xattr_predicate_tracks_the_operating_system() {
        assert_eq!(
            xattr_available(),
            cfg!(any(target_os = "linux", target_os = "macos"))
        );
    }

    // THE FIVE SEAM TESTS AND THE REAL-SYSCALL TEST OF `set_fd_xattr` ARE GONE
    // WITH THE WRAPPER THEY EXERCISED, and their coverage is not.
    //
    // Four of the five asserted properties `set_file_xattr` asserts too, and its
    // versions are the ones that survive:
    //
    //   name arrives NUL-terminated   an_xattr_name_reaches_the_seam_nul_terminated
    //   an empty value still writes   an_empty_xattr_value_reaches_the_seam_as_a_zero_length_slice
    //   an interior NUL in the name   an_interior_nul_in_an_xattr_name_is_einval_without_a_call
    //   the errno survives            the_platform_errno_survives_inside_the_error
    //   the real syscall round-trips  a_written_attribute_is_readable_back_byte_for_byte
    //
    // The fifth, `a_value_may_contain_an_interior_nul`, is not carried over,
    // because it asserted a DIVERGENCE from the C rather than agreement with it.
    // Every arm of `src/tool_xattr.c:88-97` passes `strlen(value)` -- the six-
    // argument Darwin `fsetxattr`, the five-argument Linux one and the BSD
    // `extattr_set_fd` alike -- so C stops at the first NUL. The withdrawn
    // wrapper passed `value.len()` and would have written the bytes past it;
    // that test pinned the wrong behaviour. `set_file_xattr` measures with
    // `strlen`, and two tests hold it to that:
    // `an_xattr_value_is_measured_with_strlen` over the seam and
    // `an_interior_zero_ends_the_value_exactly_as_strlen_does` on a real file.

    // Terminal attributes -- the EchoGuard contract

    /// A `termios` whose every field is zero.
    ///
    /// The "attributes were captured" state cannot be reached without a real
    /// terminal, and `libc::termios` has no `Default`, so [`FakeTerminal`]
    /// fabricates one. It never reaches the operating system: only the fake
    /// ever holds it, and the only property any test reads back out of it is
    /// whether [`SavedTerminal::is_restorable`] reports it.
    fn zeroed_termios() -> libc::termios {
        // SAFETY: `libc::termios` is a `#[repr(C)]` aggregate of integer
        // scalars and arrays of integer scalars on both mandated operating
        // systems -- no reference, no enum, no niche -- and every bit pattern
        // of such a type is a valid value, the all-zero one included.
        // `MaybeUninit::zeroed` writes exactly that pattern over storage of
        // exactly that size, so the value is fully initialised.
        unsafe { MaybeUninit::<libc::termios>::zeroed().assume_init() }
    }

    /// A pure-Rust [`TerminalCalls`] that counts what it was asked to do.
    ///
    /// `tcgetattr`, `tcsetattr` and `ioctl` are foreign functions that need a
    /// real terminal, so the guard's whole contract -- disable once, restore
    /// exactly once, restore on drop, restore on unwind -- is asserted through
    /// this instead and is therefore covered under Miri.
    struct FakeTerminal {
        /// Whether `echo_disable` reports having captured attributes.
        captures: bool,
        /// The width `window_columns` reports, if any.
        columns: Option<u32>,
        /// How many times `echo_disable` was called.
        disable_calls: Cell<usize>,
        /// How many times `echo_restore` was called.
        restore_calls: Cell<usize>,
        /// Whether the last restore was handed restorable attributes.
        restored_restorable: Cell<Option<bool>>,
    }

    impl FakeTerminal {
        fn new(captures: bool) -> Self {
            Self {
                captures,
                columns: None,
                disable_calls: Cell::new(0),
                restore_calls: Cell::new(0),
                restored_restorable: Cell::new(None),
            }
        }

        fn with_columns(columns: Option<u32>) -> Self {
            Self {
                columns,
                ..Self::new(true)
            }
        }
    }

    impl TerminalCalls for FakeTerminal {
        fn echo_disable(&self, _fd: BorrowedFd<'_>) -> SavedTerminal {
            self.disable_calls.set(self.disable_calls.get() + 1);

            if self.captures {
                SavedTerminal {
                    attrs: Some(zeroed_termios()),
                }
            } else {
                SavedTerminal::unavailable()
            }
        }

        fn echo_restore(&self, _fd: BorrowedFd<'_>, saved: &SavedTerminal) {
            self.restore_calls.set(self.restore_calls.get() + 1);
            self.restored_restorable.set(Some(saved.is_restorable()));
        }

        fn window_columns(&self, _fd: BorrowedFd<'_>) -> Option<u32> {
            self.columns
        }
    }

    /// The state a failed `tcgetattr` leaves. `RealSys::echo_restore` keys its
    /// skip off exactly this predicate, which is why the predicate is asserted
    /// rather than only the skip it drives.
    #[test]
    fn an_unavailable_saved_terminal_is_not_restorable() {
        assert!(!SavedTerminal::unavailable().is_restorable());
    }

    #[test]
    fn a_captured_saved_terminal_is_restorable() {
        let saved = SavedTerminal {
            attrs: Some(zeroed_termios()),
        };

        assert!(saved.is_restorable());
    }

    /// `src/tool_getpass.c:148` returns `TRUE` unconditionally once it has
    /// taken the termios branch, having discarded both return values, so the
    /// guard must report echo as disabled even when nothing could be captured
    /// -- otherwise the extra newline at `:185` would go missing under the
    /// redirected standard input `tests/runtests.pl` uses.
    #[test]
    fn echo_is_reported_disabled_even_when_nothing_was_captured() {
        let stdin = io::stdin();
        let fake = FakeTerminal::new(false);

        let guard = disable_echo_with(&fake, stdin.as_fd());

        assert!(guard.echo_disabled());
    }

    #[test]
    fn echo_is_reported_disabled_when_attributes_were_captured() {
        let stdin = io::stdin();
        let fake = FakeTerminal::new(true);

        let guard = disable_echo_with(&fake, stdin.as_fd());

        assert!(guard.echo_disabled());
    }

    #[test]
    fn creating_the_guard_disables_echo_once_and_restores_nothing() {
        let stdin = io::stdin();
        let fake = FakeTerminal::new(true);

        let guard = disable_echo_with(&fake, stdin.as_fd());

        assert_eq!(fake.disable_calls.get(), 1);
        assert_eq!(
            fake.restore_calls.get(),
            0,
            "nothing may be restored while the guard is alive"
        );
        drop(guard);
    }

    /// [`EchoGuard::restore`] exists so the caller can order the newline
    /// before the restoration, as `src/tool_getpass.c:185-186` does. It must
    /// restore, and the `Drop` that immediately follows it must not restore a
    /// second time -- a second `tcsetattr(TCSAFLUSH)` would discard a second
    /// helping of pending input.
    #[test]
    fn restore_puts_the_attributes_back_exactly_once() {
        let stdin = io::stdin();
        let fake = FakeTerminal::new(true);

        let guard = disable_echo_with(&fake, stdin.as_fd());
        guard.restore();

        assert_eq!(fake.restore_calls.get(), 1);
    }

    #[test]
    fn dropping_the_guard_restores_when_restore_was_not_called() {
        let stdin = io::stdin();
        let fake = FakeTerminal::new(true);

        {
            let _guard = disable_echo_with(&fake, stdin.as_fd());
            assert_eq!(fake.restore_calls.get(), 0);
        }

        assert_eq!(fake.restore_calls.get(), 1);
    }

    /// The property the C cannot claim: a non-local jump between its two
    /// `ttyecho` calls leaves the terminal with echo off for the rest of the
    /// session.
    #[test]
    fn an_unwind_through_the_guard_still_restores() {
        let stdin = io::stdin();
        let fake = FakeTerminal::new(true);

        let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
            let _guard = disable_echo_with(&fake, stdin.as_fd());
            panic!("the password prompt failed");
        }));

        assert!(outcome.is_err());
        assert_eq!(
            fake.restore_calls.get(),
            1,
            "an unwind must not leave echo disabled"
        );
    }

    /// What was captured is what is put back, in both polarities -- including
    /// the "nothing was captured" one, which is the only case
    /// `RealSys::echo_restore` skips.
    #[test]
    fn the_guard_hands_back_exactly_what_it_captured() {
        let stdin = io::stdin();

        let captured = FakeTerminal::new(true);
        disable_echo_with(&captured, stdin.as_fd()).restore();
        assert_eq!(captured.restored_restorable.get(), Some(true));

        let uncaptured = FakeTerminal::new(false);
        disable_echo_with(&uncaptured, stdin.as_fd()).restore();
        assert_eq!(uncaptured.restored_restorable.get(), Some(false));
    }

    // -- terminal width -----------------------------------------------------

    #[test]
    fn a_reported_window_width_is_returned_unchanged() {
        let fake = FakeTerminal::with_columns(Some(132));

        assert_eq!(terminal_columns_with(&fake), Some(132));
    }

    /// The `cols < 10000` test at `src/terminal.c:80` sits outside the `ioctl`
    /// in C and belongs to the caller, so an implausible width must arrive
    /// intact rather than being filtered by this layer.
    #[test]
    fn an_implausible_window_width_is_not_filtered_here() {
        let fake = FakeTerminal::with_columns(Some(65535));

        assert_eq!(terminal_columns_with(&fake), Some(65535));
    }

    /// A failed `ioctl` is C's `cols` staying `0`, which `src/terminal.c:80`
    /// then rejects in favour of the `79` fallback.
    #[test]
    fn an_unavailable_window_width_is_none() {
        let fake = FakeTerminal::with_columns(None);

        assert_eq!(terminal_columns_with(&fake), None);
    }

    /// A zero width is reported as `Some(0)` rather than hidden: the `ioctl`
    /// succeeded, and discarding the value is `src/terminal.c:80`'s decision.
    #[test]
    fn a_zero_window_width_is_reported_rather_than_hidden() {
        let fake = FakeTerminal::with_columns(Some(0));

        assert_eq!(terminal_columns_with(&fake), Some(0));
    }

    /// The real `ioctl`, whose answer depends on how the test binary was
    /// invoked. Determinism is the property worth asserting: `src/terminal.c`
    /// reads the width once per run and two reads must not disagree.
    #[test]
    #[cfg_attr(miri, ignore = "ioctl(2) is a foreign function")]
    fn the_real_terminal_width_is_deterministic() {
        assert_eq!(terminal_columns(), terminal_columns());
    }

    /// The real `tcgetattr`/`tcsetattr` pair against whatever standard input
    /// is. Under `cargo test` it is usually not a terminal, which is the
    /// failure path [`SavedTerminal::unavailable`] exists for; either way the
    /// guard must report echo disabled and must restore without panicking.
    #[test]
    #[cfg_attr(miri, ignore = "tcgetattr(3) is a foreign function")]
    fn the_real_echo_guard_completes_on_any_descriptor() {
        let stdin = io::stdin();

        let guard = disable_echo(stdin.as_fd());

        assert!(guard.echo_disabled());
        guard.restore();
    }

    // Extended attributes

    /// A pure-Rust [`XattrCalls`] that records what it was handed.
    ///
    /// `fsetxattr` needs a file on a filesystem that supports extended
    /// attributes, which no test can assume, so the wrapper's two decisions --
    /// the `strlen` measurement of the value and the rejection of a name that
    /// cannot be a C string -- are asserted through this instead.
    struct FakeXattr {
        /// What the seam reports: success, or the `errno` it fails with.
        outcome: Result<(), i32>,
        /// The name bytes, including the terminator, that the seam received.
        observed_name: RefCell<Option<Vec<u8>>>,
        /// The value bytes the seam received.
        observed_value: RefCell<Option<Vec<u8>>>,
        /// How many times the seam was called.
        calls: Cell<usize>,
    }

    impl FakeXattr {
        fn succeeding() -> Self {
            Self {
                outcome: Ok(()),
                observed_name: RefCell::new(None),
                observed_value: RefCell::new(None),
                calls: Cell::new(0),
            }
        }

        fn failing(errno: i32) -> Self {
            Self {
                outcome: Err(errno),
                ..Self::succeeding()
            }
        }
    }

    impl XattrCalls for FakeXattr {
        fn fsetxattr(
            &self,
            _fd: BorrowedFd<'_>,
            name: &CStr,
            value: &[u8],
        ) -> io::Result<()> {
            self.calls.set(self.calls.get() + 1);
            *self.observed_name.borrow_mut() =
                Some(name.to_bytes_with_nul().to_vec());
            *self.observed_value.borrow_mut() = Some(value.to_vec());

            match self.outcome {
                Ok(()) => Ok(()),
                Err(errno) => Err(io::Error::from_raw_os_error(errno)),
            }
        }
    }

    /// The four names `src/tool_xattr.c:60-71` maps must reach the platform as
    /// C strings, terminator included.
    #[test]
    fn an_xattr_name_reaches_the_seam_nul_terminated() {
        let stdin = io::stdin();
        let fake = FakeXattr::succeeding();

        set_file_xattr_with(
            &fake,
            stdin.as_fd(),
            b"user.xdg.origin.url",
            b"https://example.com/",
        )
        .expect("the seam succeeds");

        assert_eq!(
            fake.observed_name.borrow().as_deref(),
            Some(&b"user.xdg.origin.url\0"[..])
        );
        assert_eq!(
            fake.observed_value.borrow().as_deref(),
            Some(&b"https://example.com/"[..])
        );
    }

    /// `src/tool_xattr.c:89` passes `strlen(value)`, so an interior NUL ends
    /// the value and everything after it is never written.
    #[test]
    fn an_xattr_value_is_measured_with_strlen() {
        let stdin = io::stdin();
        let fake = FakeXattr::succeeding();

        set_file_xattr_with(
            &fake,
            stdin.as_fd(),
            b"user.mime_type",
            b"text/html\0discarded",
        )
        .expect("the seam succeeds");

        assert_eq!(
            fake.observed_value.borrow().as_deref(),
            Some(&b"text/html"[..])
        );
    }

    /// `strlen` of a value that begins with NUL is zero, so the attribute is
    /// set to an empty value rather than skipped.
    #[test]
    fn a_value_that_begins_with_nul_is_measured_as_empty() {
        let stdin = io::stdin();
        let fake = FakeXattr::succeeding();

        set_file_xattr_with(&fake, stdin.as_fd(), b"user.creator", b"\0curl")
            .expect("the seam succeeds");

        assert_eq!(fake.observed_value.borrow().as_deref(), Some(&b""[..]));
        assert_eq!(fake.calls.get(), 1, "an empty value still gets written");
    }

    /// An empty slice must reach the seam as a zero-length read, not as a
    /// reason to skip the call. `value.as_ptr()` on an empty slice is
    /// dangling-but-aligned and the length of `0` means no byte is read, which
    /// is the SAFETY argument `RealSys::fsetxattr` relies on.
    #[test]
    fn an_empty_xattr_value_reaches_the_seam_as_a_zero_length_slice() {
        let stdin = io::stdin();
        let fake = FakeXattr::succeeding();

        set_file_xattr_with(&fake, stdin.as_fd(), b"user.creator", b"")
            .expect("the seam succeeds");

        assert_eq!(fake.observed_value.borrow().as_deref(), Some(&b""[..]));
        assert_eq!(fake.calls.get(), 1);
    }

    /// A name with an interior NUL cannot be a C string. `EINVAL`, and the
    /// seam is never reached -- the same shape as the zone-identifier
    /// rejection above.
    #[test]
    fn an_interior_nul_in_an_xattr_name_is_einval_without_a_call() {
        let stdin = io::stdin();
        let fake = FakeXattr::succeeding();

        let error =
            set_file_xattr_with(&fake, stdin.as_fd(), b"user.\0creator", b"x")
                .expect_err("a name with an interior NUL cannot be passed");

        assert_eq!(error.raw_os_error(), Some(libc::EINVAL));
        assert_eq!(
            fake.calls.get(),
            0,
            "the seam must not be called with a rejected name"
        );
    }

    /// The number `src/tool_operate.c:637-639` renders with
    /// `curlx_strerror(errno, ...)` must survive the trip back, because Rust
    /// has no thread-global `errno` for the caller to consult afterwards.
    #[test]
    fn the_platform_errno_survives_inside_the_error() {
        let stdin = io::stdin();
        let fake = FakeXattr::failing(libc::ENOTSUP);

        let error = set_file_xattr_with(
            &fake,
            stdin.as_fd(),
            b"user.mime_type",
            b"text/plain",
        )
        .expect_err("the seam fails");

        assert_eq!(error.raw_os_error(), Some(libc::ENOTSUP));
    }

    /// A different `errno` must not be flattened into the same value.
    #[test]
    fn distinct_platform_errnos_stay_distinct() {
        let stdin = io::stdin();
        let denied = FakeXattr::failing(libc::EACCES);
        let missing = FakeXattr::failing(libc::ENOENT);

        let first =
            set_file_xattr_with(&denied, stdin.as_fd(), b"user.creator", b"c")
                .expect_err("the seam fails");
        let second =
            set_file_xattr_with(&missing, stdin.as_fd(), b"user.creator", b"c")
                .expect_err("the seam fails");

        assert_ne!(first.raw_os_error(), second.raw_os_error());
    }

    // Broken-down time and the locale

    /// A pure-Rust [`TimeCalls`] with scripted answers.
    ///
    /// `localtime_r`, `strftime` and `setlocale` all read process-wide state
    /// that a test must not depend on -- the time zone database and the
    /// current locale -- so the narrowing, the interior-NUL rejection and the
    /// empty-buffer rejection are driven from here.
    struct FakeTime {
        /// The offset `utc_offset_secs` reports, if any.
        offset: Option<i64>,
        /// The bytes `strftime` produces, or [`None`] for "produced nothing".
        rendered: Option<Vec<u8>>,
        /// What `set_locale_from_environment` reports.
        locale: bool,
        /// The format bytes, terminator included, that the seam received.
        observed_format: RefCell<Option<Vec<u8>>>,
        /// The epoch the seam received.
        observed_epoch: Cell<Option<i64>>,
        /// How many times `strftime_gmt` was called.
        strftime_calls: Cell<usize>,
    }

    impl FakeTime {
        fn new() -> Self {
            Self {
                offset: None,
                rendered: None,
                locale: true,
                observed_format: RefCell::new(None),
                observed_epoch: Cell::new(None),
                strftime_calls: Cell::new(0),
            }
        }

        fn with_offset(offset: Option<i64>) -> Self {
            Self {
                offset,
                ..Self::new()
            }
        }

        fn rendering(bytes: &[u8]) -> Self {
            Self {
                rendered: Some(bytes.to_vec()),
                ..Self::new()
            }
        }

        fn rendering_nothing() -> Self {
            Self::new()
        }

        fn with_locale(locale: bool) -> Self {
            Self {
                locale,
                ..Self::new()
            }
        }
    }

    impl TimeCalls for FakeTime {
        fn utc_offset_secs(&self, _epoch: i64) -> Option<i64> {
            self.offset
        }

        fn strftime_gmt(
            &self,
            format: &CStr,
            epoch: i64,
            out: &mut [u8],
        ) -> Option<usize> {
            self.strftime_calls.set(self.strftime_calls.get() + 1);
            *self.observed_format.borrow_mut() =
                Some(format.to_bytes_with_nul().to_vec());
            self.observed_epoch.set(Some(epoch));

            let rendered = self.rendered.as_ref()?;

            // `strftime` needs room for its terminator as well as the result,
            // and returns `0` when the whole thing does not fit -- which
            // `src/tool_writeout.c:588` reads as "write nothing".
            if rendered.len() + 1 > out.len() {
                return None;
            }

            out[..rendered.len()].copy_from_slice(rendered);
            Some(rendered.len())
        }

        fn set_locale_from_environment(&self) -> bool {
            self.locale
        }
    }

    // -- the local UTC offset -----------------------------------------------

    #[test]
    fn a_local_offset_is_narrowed_to_i32() {
        let fake = FakeTime::with_offset(Some(3600));

        assert_eq!(local_utc_offset_secs_with(&fake, 0), Some(3600));
    }

    /// West of Greenwich the offset is negative, and the sign must survive the
    /// narrowing -- a trace timestamp rendered with the wrong sign is off by
    /// twice the offset.
    #[test]
    fn a_negative_local_offset_keeps_its_sign() {
        let fake = FakeTime::with_offset(Some(-18000));

        assert_eq!(local_utc_offset_secs_with(&fake, 0), Some(-18000));
    }

    /// `tm_gmtoff` is a `long`, which is 64 bits wide on every mandated
    /// target, so a value no `i32` can hold is representable at the seam. The
    /// narrowing is where it is rejected, rather than wrapping into a
    /// plausible-looking wrong answer.
    #[test]
    fn an_offset_too_large_for_i32_is_rejected_rather_than_wrapped() {
        let fake = FakeTime::with_offset(Some(i64::from(i32::MAX) + 1));

        assert_eq!(local_utc_offset_secs_with(&fake, 0), None);
    }

    #[test]
    fn an_offset_too_small_for_i32_is_rejected_rather_than_wrapped() {
        let fake = FakeTime::with_offset(Some(i64::from(i32::MIN) - 1));

        assert_eq!(local_utc_offset_secs_with(&fake, 0), None);
    }

    /// The extremes an `i32` can hold pass through, so the rejection above is
    /// the range check it claims to be and not a narrower one.
    #[test]
    fn the_extremes_of_i32_pass_through_the_narrowing() {
        let high = FakeTime::with_offset(Some(i64::from(i32::MAX)));
        let low = FakeTime::with_offset(Some(i64::from(i32::MIN)));

        assert_eq!(local_utc_offset_secs_with(&high, 0), Some(i32::MAX));
        assert_eq!(local_utc_offset_secs_with(&low, 0), Some(i32::MIN));
    }

    #[test]
    fn an_unavailable_local_offset_is_none() {
        let fake = FakeTime::with_offset(None);

        assert_eq!(local_utc_offset_secs_with(&fake, 0), None);
    }

    // -- strftime -----------------------------------------------------------

    #[test]
    fn strftime_writes_the_platform_result_and_reports_its_length() {
        let fake = FakeTime::rendering(b"Thu");
        let mut out = [0_u8; 16];

        let written = strftime_gmt_with(&fake, b"%a", 0, &mut out);

        assert_eq!(written, Some(3));
        assert_eq!(&out[..3], b"Thu");
    }

    /// The format must arrive as a C string, because `strftime` reads it as
    /// one.
    #[test]
    fn a_time_format_reaches_the_seam_nul_terminated() {
        let fake = FakeTime::rendering(b"1970");
        let mut out = [0_u8; 16];

        strftime_gmt_with(&fake, b"%Y", 0, &mut out).expect("it fits");

        assert_eq!(
            fake.observed_format.borrow().as_deref(),
            Some(&b"%Y\0"[..])
        );
    }

    /// The epoch is passed through untouched, including a pre-epoch instant --
    /// `curlx_gmtime` accepts a negative `time_t` and so must this.
    #[test]
    fn the_epoch_reaches_the_seam_unchanged() {
        let fake = FakeTime::rendering(b"1969");
        let mut out = [0_u8; 16];

        strftime_gmt_with(&fake, b"%Y", -86_400, &mut out).expect("it fits");

        assert_eq!(fake.observed_epoch.get(), Some(-86_400));
    }

    /// `src/tool_writeout.c:588` tests `strftime`'s return value and writes
    /// nothing at all when it is `0`. The two outcomes -- produced nothing,
    /// and did not fit -- collapse into [`None`] exactly as they do there.
    #[test]
    fn a_time_format_that_produces_nothing_is_none() {
        let fake = FakeTime::rendering_nothing();
        let mut out = [0_u8; 16];

        assert_eq!(strftime_gmt_with(&fake, b"%%", 0, &mut out), None);
    }

    #[test]
    fn a_result_that_does_not_fit_the_buffer_is_none() {
        let fake = FakeTime::rendering(b"1970-01-01");
        let mut out = [0_u8; 4];

        assert_eq!(strftime_gmt_with(&fake, b"%F", 0, &mut out), None);
    }

    /// A `--write-out` format is user input, so an interior NUL must be an
    /// error rather than a panic, and the seam must not be reached.
    #[test]
    fn an_interior_nul_in_a_time_format_is_rejected_without_a_call() {
        let fake = FakeTime::rendering(b"1970");
        let mut out = [0_u8; 16];

        assert_eq!(strftime_gmt_with(&fake, b"%Y\0%m", 0, &mut out), None);
        assert_eq!(
            fake.strftime_calls.get(),
            0,
            "the seam must not be called with a rejected format"
        );
    }

    /// An empty buffer has no valid `strftime` outcome, and it is rejected on
    /// this side of the seam so the guarantee holds for every implementation
    /// of [`TimeCalls`] rather than only for `RealSys`.
    #[test]
    fn an_empty_output_buffer_is_rejected_without_a_call() {
        let fake = FakeTime::rendering(b"1970");
        let mut out = [0_u8; 0];

        assert_eq!(strftime_gmt_with(&fake, b"%Y", 0, &mut out), None);
        assert_eq!(
            fake.strftime_calls.get(),
            0,
            "the seam must not be handed a zero-length buffer"
        );
    }

    /// A buffer of exactly the result plus its terminator is the boundary
    /// case, and it must succeed.
    #[test]
    fn a_buffer_of_exactly_the_result_plus_terminator_succeeds() {
        let fake = FakeTime::rendering(b"UTC");
        let mut out = [0_u8; 4];

        assert_eq!(strftime_gmt_with(&fake, b"%Z", 0, &mut out), Some(3));
    }

    // -- the locale ---------------------------------------------------------

    /// Only the injected form is exercised. The real
    /// [`set_locale_from_environment`] mutates process-wide state, and every
    /// test in this crate shares one process, so calling it here would change
    /// the locale under every other test -- which is precisely why the
    /// function documents its owner as the command-line tool's start-up path.
    #[test]
    fn the_locale_result_is_reported_as_the_platform_gave_it() {
        let accepted = FakeTime::with_locale(true);
        let refused = FakeTime::with_locale(false);

        assert!(set_locale_from_environment_with(&accepted));
        assert!(!set_locale_from_environment_with(&refused));
    }

    // -- the argument vector, src/tool_getparam.c:625-637 -------------------

    /// A pure-Rust [`ArgvCalls`] that records every wipe it is asked for.
    ///
    /// The seam that makes `cleanarg` testable at all: Miri has no process
    /// argument vector, so the whole of the matching rule and the scan are
    /// driven from here instead and are covered without touching the loader's
    /// memory.
    struct FakeArgv {
        /// The vector, `argv[0]` included, mutated in place by [`Self::wipe`].
        elements: RefCell<Vec<Vec<u8>>>,
        /// Every `(index, at, len)` the scan asked for, in order.
        wipes: RefCell<Vec<(usize, usize, usize)>>,
    }

    impl FakeArgv {
        fn new(elements: &[&[u8]]) -> Self {
            Self {
                elements: RefCell::new(
                    elements.iter().map(|item| item.to_vec()).collect(),
                ),
                wipes: RefCell::new(Vec::new()),
            }
        }

        fn element(&self, index: usize) -> Vec<u8> {
            self.elements.borrow()[index].clone()
        }
    }

    impl ArgvCalls for FakeArgv {
        fn count(&self) -> usize {
            self.elements.borrow().len()
        }

        fn read(&self, index: usize) -> Option<Vec<u8>> {
            self.elements.borrow().get(index).cloned()
        }

        fn wipe(&self, index: usize, at: usize, len: usize) {
            self.wipes.borrow_mut().push((index, at, len));
            let mut elements = self.elements.borrow_mut();
            let element = &mut elements[index];
            assert!(
                at + len <= element.len(),
                "a wipe must stay inside the element it was measured against"
            );
            for byte in &mut element[at..at + len] {
                *byte = b'*';
            }
        }
    }

    /// The three spellings C's parser can point into, and the offset each one
    /// leaves `nextarg` at.
    #[test]
    fn every_argument_spelling_wipes_exactly_what_the_c_pointer_covered() {
        // `--user bob:pw` -- a separate element, wiped whole.
        assert_eq!(wipe_offset(b"bob:pw", b"bob:pw"), Some(0));
        // `-ubob:pw` -- C's `nextarg` is `argv[i] + 2`, so `-u` survives.
        assert_eq!(wipe_offset(b"-ubob:pw", b"bob:pw"), Some(2));
        // `--user=bob:pw` -- `nextarg` is just past the `=`.
        assert_eq!(wipe_offset(b"--user=bob:pw", b"bob:pw"), Some(7));
    }

    /// The rule that keeps the wipe off arguments the parser never pointed
    /// into.
    #[test]
    fn a_value_that_merely_ends_an_unrelated_argument_is_left_alone() {
        // The regression this guards: `curl https://h/bob:pw -u bob:pw` must
        // wipe the credential, not the tail of the URL.
        assert_eq!(wipe_offset(b"https://h/bob:pw", b"bob:pw"), None);
        // Not a suffix at all.
        assert_eq!(wipe_offset(b"bob:pw-and-more", b"bob:pw"), None);
        // Shorter than the value.
        assert_eq!(wipe_offset(b"pw", b"bob:pw"), None);
        // `strlen("")` is zero, so C's `memset` writes nothing.
        assert_eq!(wipe_offset(b"-u", b""), None);
        assert_eq!(wipe_offset(b"", b""), None);
    }

    /// Every occurrence is wiped, not just the first.
    ///
    /// C holds the parser's pointer and so wipes one location per call. This
    /// holds only the bytes, and `-u bob:pw --proxy-user bob:pw` is an ordinary
    /// command line: stopping at the first match would leave the second
    /// credential legible in `ps`, which is the whole exposure being closed.
    #[test]
    fn a_credential_repeated_on_the_command_line_is_wiped_everywhere() {
        let argv = FakeArgv::new(&[
            b"curl",
            b"-u",
            b"bob:pw",
            b"--proxy-user",
            b"bob:pw",
            b"https://example.com/",
        ]);

        assert_eq!(scrub_argument_with(&argv, b"bob:pw"), 2);
        assert_eq!(argv.element(2), b"******".to_vec());
        assert_eq!(argv.element(4), b"******".to_vec());
        assert_eq!(argv.element(5), b"https://example.com/".to_vec());
        assert_eq!(
            *argv.wipes.borrow(),
            vec![(2, 0, 6), (4, 0, 6)],
            "each wipe covers exactly the value's bytes"
        );
    }

    /// `argv[0]` is the program name and C's parser never points into it.
    #[test]
    fn the_program_name_is_never_wiped() {
        let argv = FakeArgv::new(&[b"-ubob:pw", b"--url", b"https://h/"]);

        assert_eq!(scrub_argument_with(&argv, b"bob:pw"), 0);
        assert_eq!(argv.element(0), b"-ubob:pw".to_vec());
        assert!(argv.wipes.borrow().is_empty());
    }

    /// The glued forms keep their option text, byte for byte as C leaves it.
    #[test]
    fn a_glued_option_keeps_its_flag_and_loses_only_the_value() {
        let argv =
            FakeArgv::new(&[b"curl", b"-ubob:pw", b"--proxy-user=bob:pw"]);

        assert_eq!(scrub_argument_with(&argv, b"bob:pw"), 2);
        assert_eq!(argv.element(1), b"-u******".to_vec());
        assert_eq!(argv.element(2), b"--proxy-user=******".to_vec());
    }

    /// An empty vector -- the state Miri and any uncaptured platform are in --
    /// is a no-op that reports itself as one.
    #[test]
    fn an_absent_vector_is_a_no_op_that_reports_zero() {
        let argv = FakeArgv::new(&[]);
        assert_eq!(scrub_argument_with(&argv, b"bob:pw"), 0);

        // And an empty value writes nothing even when the vector is there,
        // matching `memset(str, '*', strlen(""))`.
        let present = FakeArgv::new(&[b"curl", b"-u", b""]);
        assert_eq!(scrub_argument_with(&present, b""), 0);
        assert!(present.wipes.borrow().is_empty());
    }

    /// A value that is not valid UTF-8 is wiped like any other.
    ///
    /// `--user` takes arbitrary bytes on all four mandated targets, so a
    /// credential that Unicode cannot spell must not be the one that stays
    /// visible in `ps`.
    #[test]
    fn an_undecodable_credential_is_wiped_too() {
        let argv = FakeArgv::new(&[b"curl", b"-u", b"bob:\xff\xfe"]);

        assert_eq!(scrub_argument_with(&argv, b"bob:\xff\xfe"), 1);
        assert_eq!(argv.element(2), b"******".to_vec());
    }

    /// The capture really ran in this process.
    ///
    /// The mechanism is a `.init_array` entry in an rlib, which survives only
    /// because of `#[used]`; this is the assertion that would fail if a future
    /// toolchain or linker flag discarded it. Reading element `0` also proves
    /// the pointer is dereferenceable, not merely non-null.
    ///
    /// Ignored under Miri, which does not model a process argument vector and
    /// for which the constructor is deliberately not compiled.
    #[test]
    #[cfg_attr(miri, ignore = "Miri models no process argument vector")]
    fn the_real_argument_vector_was_captured() {
        assert!(
            RealArgv.count() > 0,
            "the .init_array capture did not run -- see CAPTURE_ARGV"
        );

        let program = RealArgv
            .read(0)
            .expect("argv[0] is always present in a real process");
        assert!(!program.is_empty());

        // Past the end reports absence rather than reading out of bounds.
        assert_eq!(RealArgv.read(RealArgv.count()), None);

        // A value no command line can contain changes nothing, which exercises
        // the real read path without mutating this process.
        assert_eq!(scrub_argument(b"\x01curl-rs-no-such-argument\x01"), 0);
    }

    /// The environment variable that puts the round-trip test below into its
    /// child role.
    const ARGV_PROBE_ROLE: &str = "CURL_RS_ARGV_SCRUB_PROBE";

    /// The argument the child is given, and then wipes out of its own vector.
    const ARGV_PROBE_VALUE: &str = "curl-rs-argv-scrub-probe-value";

    /// Printed by the child once it has observed the wipe.
    const ARGV_PROBE_DONE: &str = "argv-scrub-probe-ok";

    /// The end-to-end assertion: a real argument, in a real process, really
    /// overwritten.
    ///
    /// Every other test above drives the seam. This one drives the platform,
    /// and it is the only way to prove the write lands, because the memory it
    /// writes belongs to the process that owns it. The test re-executes this
    /// same test binary with [`ARGV_PROBE_VALUE`] as an extra filter -- so the
    /// value becomes a genuine element of the child's `argv` -- and the child
    /// then scrubs it and reads the element back through [`RealArgv`].
    ///
    /// `--exact` with the test's own name is what keeps the child running one
    /// test rather than the whole suite, and the printed marker is what
    /// distinguishes "the child ran and observed the wipe" from "the child
    /// filtered everything out and exited successfully".
    ///
    /// Ignored under Miri: it spawns a process and mutates the loader's memory,
    /// neither of which Miri models.
    #[test]
    #[cfg_attr(miri, ignore = "spawns a process and writes to argv")]
    fn a_real_argument_is_overwritten_in_this_process() {
        if std::env::var_os(ARGV_PROBE_ROLE).is_some() {
            // The child. Its own `argv` carries the probe value as one element.
            let at = (1..RealArgv.count())
                .find(|index| {
                    RealArgv.read(*index).as_deref()
                        == Some(ARGV_PROBE_VALUE.as_bytes())
                })
                .expect("the parent passed the probe value as an argument");

            assert_eq!(scrub_argument(ARGV_PROBE_VALUE.as_bytes()), 1);

            let after = RealArgv
                .read(at)
                .expect("the element is still a valid C string");
            assert_eq!(
                after,
                vec![b'*'; ARGV_PROBE_VALUE.len()],
                "the value must be asterisks of its own length, terminator \
                 untouched"
            );
            println!("{ARGV_PROBE_DONE}");
            return;
        }

        // The parent.
        let exe = std::env::current_exe().expect("the test binary's own path");
        let output = std::process::Command::new(exe)
            .args([
                "--exact",
                "ffi::sys::tests::a_real_argument_is_overwritten_in_this_process",
                "--nocapture",
                ARGV_PROBE_VALUE,
            ])
            .env(ARGV_PROBE_ROLE, "1")
            .output()
            .expect("the test binary is executable");

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "child failed: {stdout}{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            stdout.contains(ARGV_PROBE_DONE),
            "the child never reached the assertion: {stdout}"
        );
    }

    // -- the real implementations -------------------------------------------

    /// The buffer `src/tool_writeout.c:529` declares -- `char output[256]`.
    /// Stated here rather than imported because the constant that mirrors it
    /// belongs to the `--write-out` implementation in `curl-rs`, and this
    /// module must not depend on the crate above it.
    const C_TIME_BUFFER: usize = 256;

    /// The real `localtime_r`. The container's zone is not known to the test,
    /// so the assertion is the one that holds everywhere: an offset exists and
    /// lies inside the range of real zones, which run from -12:00 to +14:00.
    #[test]
    #[cfg_attr(miri, ignore = "localtime_r(3) is a foreign function")]
    fn the_real_local_offset_is_within_the_range_of_real_zones() {
        let offset =
            local_utc_offset_secs(0).expect("a zone is always available");

        assert!(
            (-12 * 3600..=14 * 3600).contains(&offset),
            "{offset} is outside every real UTC offset"
        );
    }

    /// The real `gmtime_r` plus `strftime` over a format whose every
    /// conversion is numeric and therefore locale-independent, so the expected
    /// bytes hold in any locale the process might be in.
    #[test]
    #[cfg_attr(miri, ignore = "strftime(3) is a foreign function")]
    fn the_real_strftime_formats_the_epoch_in_utc() {
        let mut out = [0_u8; C_TIME_BUFFER];

        let written = strftime_gmt(b"%Y-%m-%dT%H:%M:%S", 0, &mut out)
            .expect("the format fits");

        assert_eq!(&out[..written], b"1970-01-01T00:00:00");
    }

    /// A second instant, so the previous test is exercising the conversion
    /// rather than a constant. 2001-09-09T01:46:40Z.
    #[test]
    #[cfg_attr(miri, ignore = "strftime(3) is a foreign function")]
    fn the_real_strftime_converts_a_later_instant() {
        let mut out = [0_u8; C_TIME_BUFFER];

        let written =
            strftime_gmt(b"%Y-%m-%dT%H:%M:%S", 1_000_000_000, &mut out)
                .expect("the format fits");

        assert_eq!(&out[..written], b"2001-09-09T01:46:40");
    }

    #[test]
    #[cfg_attr(miri, ignore = "strftime(3) is a foreign function")]
    fn the_real_strftime_reports_nothing_when_the_buffer_is_too_small() {
        let mut out = [0_u8; 4];

        assert_eq!(strftime_gmt(b"%Y-%m-%d", 0, &mut out), None);
    }

    #[test]
    #[cfg_attr(miri, ignore = "strftime(3) is a foreign function")]
    fn the_real_strftime_rejects_an_empty_buffer() {
        let mut out = [0_u8; 0];

        assert_eq!(strftime_gmt(b"%Y", 0, &mut out), None);
    }

    // Terminal echo suppression

    // The real `termios` path, against a pseudo-terminal.
    //
    // Everything above drives the injected [`SysCalls`], which proves the
    // guard's *sequencing* -- restore exactly once, on every path including an
    // unwind -- and nothing about whether `<RealSys as SysCalls>::echo_disable`
    // actually clears `ECHO`. That is the half a fake cannot reach, and it is
    // the half a password depends on, so it is measured here against a real
    // terminal.
    //
    // A plain `File::open("/dev/ptmx")` allocates a pseudo-terminal pair and
    // hands back the master, which `isatty` accepts and which `tcgetattr` and
    // `tcsetattr` both serve -- verified on this platform before the test was
    // written. No `unsafe` is needed to obtain it; the only `unsafe` is the
    // observation below, which reads the attributes back.

    /// Reads `ECHO` back from `fd`, for use as an independent observation.
    ///
    /// Deliberately does not go through [`SysCalls`]: a test that observed
    /// through the same code path it is testing could not detect that path
    /// doing nothing at all.
    #[cfg(test)]
    fn echo_bit_of(fd: RawFd) -> Option<bool> {
        // SAFETY: `core::mem::zeroed::<libc::termios>()` is sound for the reason
        // given at `<RealSys as SysCalls>::echo_disable` -- the type is a plain
        // aggregate of integers and integer arrays on both mandated platforms,
        // with no member for which an all-zero bit pattern would be invalid.
        let mut attrs: libc::termios = unsafe { core::mem::zeroed() };

        // SAFETY: `tcgetattr` writes one `struct termios` through its second
        // argument and reads nothing else. The pointer is derived from a live,
        // properly aligned local that outlives the call, and the borrow ends
        // when the call returns. A non-terminal `fd` is reported through the
        // return value.
        let read = unsafe { libc::tcgetattr(fd, &mut attrs) };
        if read != 0 {
            return None;
        }
        Some((attrs.c_lflag & libc::ECHO) != 0)
    }

    /// Opens a pseudo-terminal master, or `None` where the platform has none.
    #[cfg(test)]
    fn open_pty_master() -> Option<std::fs::File> {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/ptmx")
            .ok()
    }

    /// The guard really clears `ECHO`, and really puts it back.
    ///
    /// This is the assertion the whole echo-suppression path exists to
    /// support: while the guard is held a typed password is not displayed, and
    /// once the guard is gone the user's terminal is as it was found. Both
    /// halves are read back with [`echo_bit_of`], which does not go through the
    /// code under test -- the injected [`FakeTerminal`] records what
    /// `echo_disable` *asked* for, which cannot tell a wrapper that issues
    /// `tcsetattr` apart from one that quietly does not.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "tcgetattr(3) and tcsetattr(3) are foreign functions"
    )]
    fn a_real_terminal_has_echo_cleared_and_then_restored() {
        use std::os::fd::{AsFd as _, AsRawFd as _};

        let master = match open_pty_master() {
            Some(file) => file,
            // Not a skip that can hide a defect: the assertions below are
            // about a pseudo-terminal, and without one there is nothing to
            // assert. Every other property of the guard is covered through the
            // fake.
            None => return,
        };
        let fd = master.as_raw_fd();

        assert_eq!(
            echo_bit_of(fd),
            Some(true),
            "a fresh pseudo-terminal starts with ECHO set"
        );

        let guard = disable_echo(master.as_fd());
        assert!(
            guard.echo_disabled(),
            "the guard reports echo disabled unconditionally, as C does"
        );
        assert_eq!(
            echo_bit_of(fd),
            Some(false),
            "ECHO must be cleared while the guard is held"
        );

        drop(guard);
        assert_eq!(
            echo_bit_of(fd),
            Some(true),
            "the restore must put back the attributes tcgetattr reported"
        );
    }

    /// A terminal that already had `ECHO` off is left off, not turned on.
    ///
    /// The restore reapplies the whole captured `struct termios`, exactly as
    /// `ttyecho(TRUE, fd)` reapplies its `withecho` static
    /// (`src/tool_getpass.c:154-155`), so a terminal the user had configured
    /// with echo off has to come back that way. The inner guard below captures
    /// while the outer one holds the bit clear, which is the only way to reach
    /// that state without configuring the terminal by hand.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "tcgetattr(3) and tcsetattr(3) are foreign functions"
    )]
    fn a_terminal_that_already_had_echo_off_stays_off() {
        use std::os::fd::{AsFd as _, AsRawFd as _};

        let master = match open_pty_master() {
            Some(file) => file,
            None => return,
        };
        let fd = master.as_raw_fd();

        let outer = disable_echo(master.as_fd());
        assert_eq!(
            echo_bit_of(fd),
            Some(false),
            "the outer guard clears the bit the inner one then captures"
        );

        let inner = disable_echo(master.as_fd());
        drop(inner);
        assert_eq!(
            echo_bit_of(fd),
            Some(false),
            "the inner restore must not switch ECHO back on"
        );

        drop(outer);
        assert_eq!(
            echo_bit_of(fd),
            Some(true),
            "the outer restore returns the terminal to how it was found"
        );
    }

    /// Reads one extended attribute back, for use as an independent observation.
    ///
    /// The counterpart of [`echo_bit_of`] for `fsetxattr`, and it exists for the
    /// same reason: the injected fake records what `set_xattr` *asked* for, which
    /// cannot distinguish a wrapper that issues the syscall from one that quietly
    /// does not. `fgetxattr` is not part of [`SysCalls`] and is not used in
    /// production; it is only ever an observer.
    ///
    /// [`None`] when the attribute is absent or the platform refuses the read,
    /// which the caller must not confuse with an empty value -- hence the
    /// `Option<Vec<u8>>` rather than a bare `Vec<u8>`.
    #[cfg(test)]
    fn xattr_value_of(fd: RawFd, name: &CStr) -> Option<Vec<u8>> {
        // Sized generously: every name this crate writes carries a URL or a MIME
        // type, and the assertions below use short literals.
        let mut buffer = vec![0u8; 4096];
        let capacity = buffer.len();
        let ptr = buffer.as_mut_ptr().cast::<libc::c_void>();
        // Bound separately so that each call below fits one line and its
        // `// SAFETY:` comment stays adjacent to the `unsafe` it justifies.
        let key = name.as_ptr();

        #[cfg(target_os = "macos")]
        // SAFETY: `fgetxattr` writes at most `capacity` bytes through `ptr` and
        // reads the NUL-terminated name through `key`, writing nothing through
        // it. `ptr` is derived from a live `Vec` of exactly `capacity` bytes
        // that outlives the call, `key` is NUL-terminated by `CStr`'s invariant,
        // and both borrows end when the call returns. The two trailing
        // arguments are Darwin's `position` and `options`, both zero, matching
        // the write at `<RealSys as SysCalls>::fsetxattr`.
        let read = unsafe { libc::fgetxattr(fd, key, ptr, capacity, 0, 0) };

        #[cfg(target_os = "linux")]
        // SAFETY: as for the Darwin arm above; the Linux form takes no
        // `position` or `options`.
        let read = unsafe { libc::fgetxattr(fd, key, ptr, capacity) };

        if read < 0 {
            return None;
        }
        // `read` is non-negative and cannot exceed `capacity`, which the call
        // enforces by returning ERANGE instead of overrunning.
        let len = read as usize;
        buffer.truncate(len);
        Some(buffer)
    }

    /// A descriptor that cannot carry a `user.*` extended attribute.
    ///
    /// Linux permits those names on regular files and directories only, so a
    /// socket is refused deterministically rather than by accident of the host's
    /// filesystem. Used to prove the refusal is reported rather than swallowed.
    #[cfg(test)]
    fn open_non_file() -> Option<std::os::unix::net::UnixStream> {
        std::os::unix::net::UnixStream::pair().ok().map(|(a, _b)| a)
    }

    // The extended-attribute wrapper, measured against a real file system
    //
    // The same division as the terminal tests above: the injected fake records
    // the name and value `set_xattr` *asked* for, which cannot tell a wrapper
    // that issues the syscall apart from one that quietly does not. These read
    // the attribute back with `fgetxattr`, which is not part of `SysCalls`.

    /// The bytes handed in are the bytes the file system holds afterwards.
    #[test]
    #[cfg_attr(miri, ignore = "fsetxattr(2) is a foreign function")]
    fn a_written_attribute_is_readable_back_byte_for_byte() {
        use std::os::fd::{AsFd as _, AsRawFd as _};

        let file = match tempfile::NamedTempFile::new() {
            Ok(file) => file,
            Err(_) => return,
        };
        let fd = file.as_file().as_raw_fd();
        // Not valid UTF-8: the value is a server-supplied header, so it is
        // carried rather than interpreted. It holds no interior zero, which is
        // the case C's `strlen` argument leaves whole; the other case is the
        // test immediately below.
        let value: &[u8] = &[0xff, b'a', 0xfe];

        let written = set_file_xattr(
            file.as_file().as_fd(),
            b"user.xdg.origin.url",
            value,
        );
        if written.is_err() {
            // This file system does not support extended attributes at all, so
            // there is nothing to read back and the assertion would be about the
            // host. The refusal itself is asserted by the test below.
            return;
        }

        let name =
            CString::new("user.xdg.origin.url").expect("no interior NUL");
        assert_eq!(
            xattr_value_of(fd, &name).as_deref(),
            Some(value),
            "the value must survive the boundary unaltered"
        );
    }

    /// An interior zero ends the value, exactly as C's `strlen` does.
    ///
    /// C hands `fsetxattr` a length of `strlen(value)` at
    /// `src/tool_xattr.c:89` and `:91`, because what it holds is a `char *`.
    /// A value carrying an interior zero is therefore written up to that zero
    /// and no further, and reproducing the length computation is what keeps the
    /// attribute this tool writes identical to the one curl writes. Carrying
    /// the whole slice instead would be a behaviour change dressed as a fix,
    /// which specification 0.8.1 puts outside this work's authority -- so the
    /// truncation is asserted rather than left to be rediscovered.
    #[test]
    #[cfg_attr(miri, ignore = "fsetxattr(2) is a foreign function")]
    fn an_interior_zero_ends_the_value_exactly_as_strlen_does() {
        use std::os::fd::{AsFd as _, AsRawFd as _};

        let file = match tempfile::NamedTempFile::new() {
            Ok(file) => file,
            Err(_) => return,
        };
        let fd = file.as_file().as_raw_fd();

        let written = set_file_xattr(
            file.as_file().as_fd(),
            b"user.xdg.origin.url",
            &[0xff, 0x00, b'a', 0xfe],
        );
        if written.is_err() {
            // No extended-attribute support on this file system; the refusal
            // itself is asserted by the test below.
            return;
        }

        let name =
            CString::new("user.xdg.origin.url").expect("no interior NUL");
        assert_eq!(
            xattr_value_of(fd, &name).as_deref(),
            Some(&[0xff][..]),
            "the value must end at the interior zero, as strlen would"
        );
    }

    /// An empty value is written as an empty value, not skipped.
    ///
    /// `src/tool_xattr.c:90,92` passes `strlen(value)`, which is zero for an
    /// empty string, and the syscall stores a zero-length attribute. The
    /// distinction from an absent attribute is what `Option` preserves here.
    #[test]
    #[cfg_attr(miri, ignore = "fsetxattr(2) is a foreign function")]
    fn an_empty_value_is_stored_rather_than_dropped() {
        use std::os::fd::{AsFd as _, AsRawFd as _};

        let file = match tempfile::NamedTempFile::new() {
            Ok(file) => file,
            Err(_) => return,
        };
        let fd = file.as_file().as_raw_fd();

        if set_file_xattr(file.as_file().as_fd(), b"user.mime_type", b"")
            .is_err()
        {
            return;
        }

        let name = CString::new("user.mime_type").expect("no interior NUL");
        assert_eq!(
            xattr_value_of(fd, &name),
            Some(Vec::new()),
            "present and empty, which is not the same as absent"
        );
    }

    /// A platform refusal is reported, not swallowed.
    ///
    /// The defect this wrapper replaced returned success unconditionally, so a
    /// descriptor that cannot carry the attribute is the sharpest available
    /// probe. A socket is used because Linux permits `user.*` names on regular
    /// files and directories only, making the refusal deterministic rather than
    /// dependent on which file system the host mounted.
    #[test]
    #[cfg_attr(miri, ignore = "fsetxattr(2) is a foreign function")]
    fn a_descriptor_that_cannot_hold_attributes_reports_the_refusal() {
        use std::os::fd::{AsFd as _, AsRawFd as _};

        let socket = match open_non_file() {
            Some(socket) => socket,
            None => return,
        };
        let fd = socket.as_raw_fd();

        let refused = set_file_xattr(
            socket.as_fd(),
            b"user.xdg.origin.url",
            b"https://example.com/",
        )
        .expect_err("a socket cannot carry a user.* attribute");
        // The errno is carried rather than collapsed, which is what lets
        // `curl-rs/src/output/xattr.rs` render the system's own text.
        assert!(
            refused.raw_os_error().is_some(),
            "the platform's errno must survive the wrapper: {refused}"
        );
        let name =
            CString::new("user.xdg.origin.url").expect("no interior NUL");
        assert_eq!(
            xattr_value_of(fd, &name),
            None,
            "and nothing may have been recorded"
        );
    }

    // Descriptor extent, reads and seeks
    //
    // The fake covers the branch logic; these three measure the real calls
    // against `std`'s own view of the same file, which is an independent
    // observation for the same reason `echo_bit_of` and `xattr_value_of` are.

    /// A regular file reports the offset and size `std` reports.
    #[test]
    #[cfg_attr(miri, ignore = "lseek(2) and fstat(2) are foreign functions")]
    fn a_regular_file_reports_its_offset_and_size() {
        use std::io::{Seek, SeekFrom, Write};

        let mut file = match tempfile::NamedTempFile::new() {
            Ok(file) => file,
            Err(_) => return,
        };
        let contents = b"0123456789";
        if file.write_all(contents).is_err() {
            return;
        }

        // The descriptor is borrowed AT each call rather than once up front.
        // That is not a style choice: `BorrowedFd` holds an immutable borrow of
        // `file`, and `as_file_mut` below needs a mutable one, so a single
        // long-lived binding would not compile. The borrow checker is making the
        // same point the type exists to make -- the descriptor is live exactly
        // where it is used.

        // Positioned at the start, as a freshly opened stdin would be.
        if file.as_file_mut().seek(SeekFrom::Start(0)).is_err() {
            return;
        }
        assert_eq!(
            regular_file_extent(file.as_file().as_fd()),
            Some((0, contents.len() as i64)),
            "origin and size must match what std sees"
        );

        // And after a seek, the origin moves with it -- which is the whole
        // reason C reads `ftell` rather than assuming zero (`:128`).
        if file.as_file_mut().seek(SeekFrom::Start(4)).is_err() {
            return;
        }
        assert_eq!(
            regular_file_extent(file.as_file().as_fd()),
            Some((4, contents.len() as i64))
        );
    }

    /// A descriptor that is not a regular file is `None`, not an error.
    ///
    /// The three cases are not interchangeable, and only the last of them
    /// reaches the file-type test. A socket, a terminal and a closed descriptor
    /// are all refused by `lseek` before `fstat` is ever called, so they prove
    /// the offset gate and nothing about `S_ISREG`. A character device is
    /// seekable, so `lseek` succeeds and the file-type test is the only thing
    /// that can reject it -- which is why `/dev/null` is here.
    #[test]
    #[cfg_attr(miri, ignore = "fstat(2) is a foreign function")]
    fn a_descriptor_that_is_not_a_regular_file_selects_buffering() {
        if let Some(socket) = open_non_file() {
            assert_eq!(
                regular_file_extent(socket.as_fd()),
                None,
                "a socket must select the buffering branch"
            );
        }
        if let Some(pty) = open_pty_master() {
            assert_eq!(
                regular_file_extent(pty.as_fd()),
                None,
                "a terminal must select the buffering branch"
            );
        }
        // A seekable descriptor that is still not a regular file: this is the
        // case the `S_ISREG` test itself decides. A host without `/dev/null`
        // would make the assertion a statement about the host, so it is
        // conditional -- but this container has one, and the same observation is
        // made independently through a redirected standard input by
        // `curl-rs/src/output/formparse.rs`'s
        // `a_character_device_standard_input_is_buffered_instead`.
        if let Ok(null) = std::fs::File::open("/dev/null") {
            assert!(
                RealSys.fd_offset(null.as_fd()).is_ok(),
                "/dev/null is seekable, which is what makes this case reach \
                 the file-type test"
            );
            assert_eq!(
                regular_file_extent(null.as_fd()),
                None,
                "a character device must select the buffering branch"
            );
        }

        // A CLOSED descriptor used to be checked here, as `regular_file_extent(-1)`.
        // It cannot be written any more, and that is the improvement rather than a
        // loss of coverage: the boundary takes `BorrowedFd`, and `-1` is not a
        // descriptor a caller can hand it without `unsafe` -- `BorrowedFd::borrow_raw`
        // forbids that value outright. The case is now unreachable from safe code, so
        // it is asserted where it remains expressible, at the seam, with the errno a
        // closed descriptor actually produces.
        let closed = FakeSys {
            fd_offset: Err(libc::EBADF),
            ..FakeSys::new()
        };
        let stdin = io::stdin();
        assert_eq!(
            regular_file_extent_with(&closed, stdin.as_fd()),
            None,
            "EBADF -- what lseek reports for a closed descriptor -- must be the \
             ordinary buffering answer, not a panic"
        );
    }

    /// Reading and repositioning the descriptor agree with `std`.
    #[test]
    #[cfg_attr(miri, ignore = "read(2) and lseek(2) are foreign functions")]
    fn a_descriptor_can_be_read_and_repositioned() {
        use std::io::Write;

        let mut file = match tempfile::NamedTempFile::new() {
            Ok(file) => file,
            Err(_) => return,
        };
        if file.write_all(b"abcdefgh").is_err() {
            return;
        }
        // One binding is enough here: nothing below needs `file` mutably again.
        let fd = file.as_file().as_fd();
        if seek_fd(fd, 0).is_err() {
            return;
        }

        let mut buffer = [0u8; 3];
        assert_eq!(read_fd(fd, &mut buffer).ok(), Some(3));
        assert_eq!(&buffer, b"abc");
        // The descriptor advanced, so the next read continues rather than
        // repeating -- the property `read(2)` has and a stateless helper
        // would not.
        assert_eq!(read_fd(fd, &mut buffer).ok(), Some(3));
        assert_eq!(&buffer, b"def");

        // Rewinding to an absolute offset is what a retry needs.
        assert!(seek_fd(fd, 1).is_ok());
        assert_eq!(read_fd(fd, &mut buffer).ok(), Some(3));
        assert_eq!(&buffer, b"bcd");

        // End of input is `Ok(0)`, not an error -- which is how the caller
        // distinguishes it from `ferror`.
        assert!(seek_fd(fd, 8).is_ok());
        assert_eq!(read_fd(fd, &mut buffer).ok(), Some(0));

        // And an unseekable descriptor reports the failure C turns into
        // CURL_SEEKFUNC_CANTSEEK.
        if let Some(socket) = open_non_file() {
            assert!(seek_fd(socket.as_fd(), 0).is_err());
        }
    }

    /// The branch logic, over the fake, so Miri covers it.
    #[test]
    fn the_extent_branches_follow_the_c_condition() {
        // The seam takes a `BorrowedFd`, which cannot be built from a literal
        // integer without `unsafe`. Standard input is borrowed instead: every
        // `FakeSys` method receives the descriptor as `_fd` and never inspects
        // it, and `Stdin::as_fd` is a value construction rather than a call, so
        // this stays Miri-clean.
        let stdin = io::stdin();
        let fd = stdin.as_fd();

        // A regular file with a non-zero origin: both values are carried.
        let sys = FakeSys::with_regular_file(7, 99, b"payload");
        assert_eq!(regular_file_extent_with(&sys, fd), Some((7, 99)));

        // Not a regular file: `Ok(None)` is an answer, so the result is None
        // without any error being invented.
        let sys = FakeSys::new();
        assert_eq!(regular_file_extent_with(&sys, fd), None);

        // The offset call failing short-circuits before the size call, as C's
        // `&&` chain does.
        let sys = FakeSys {
            fd_offset: Err(libc::ESPIPE),
            fd_regular_size: Ok(Some(10)),
            ..FakeSys::new()
        };
        assert_eq!(regular_file_extent_with(&sys, fd), None);

        // And the size call failing is equally just None.
        let sys = FakeSys {
            fd_regular_size: Err(libc::EBADF),
            ..FakeSys::new()
        };
        assert_eq!(regular_file_extent_with(&sys, fd), None);
    }

    /// Reads consume from the front and errors propagate, over the fake.
    #[test]
    fn the_read_and_seek_seams_carry_their_arguments() {
        // As above: a borrowed descriptor the fake ignores.
        let stdin = io::stdin();
        let fd = stdin.as_fd();

        let sys = FakeSys::with_regular_file(0, 6, b"abcdef");
        let mut buffer = [0u8; 4];

        assert_eq!(read_fd_with(&sys, fd, &mut buffer).ok(), Some(4));
        assert_eq!(&buffer, b"abcd");
        assert_eq!(read_fd_with(&sys, fd, &mut buffer).ok(), Some(2));
        assert_eq!(&buffer[..2], b"ef");
        assert_eq!(read_fd_with(&sys, fd, &mut buffer).ok(), Some(0));

        assert!(seek_fd_with(&sys, fd, 42).is_ok());
        assert_eq!(sys.observed_seeks.borrow().as_slice(), &[42]);

        let failing = FakeSys {
            fd_bytes: RefCell::new(Err(libc::EIO)),
            fd_seek: Err(libc::ESPIPE),
            ..FakeSys::new()
        };
        assert!(read_fd_with(&failing, fd, &mut buffer).is_err());
        assert!(seek_fd_with(&failing, fd, 0).is_err());
    }

    // Local time

    // The broken-down-time probe that used to sit here is gone with the
    // `localtime` wrapper it exercised: the facade this module publishes is
    // `local_utc_offset_secs`, and its real-host measurement lives above in
    // `the_real_local_offset_is_within_the_range_of_real_zones`, which bounds
    // the offset more tightly than that probe did.

    // Extended attributes

    // Process identity

    /// The uid crosses the seam unaltered.
    #[test]
    fn the_effective_uid_is_reported_verbatim() {
        assert_eq!(effective_uid_with(&FakeSys::with_uid(1000)), 1000);
        assert_eq!(effective_uid_with(&FakeSys::with_uid(0)), 0);
    }

    /// The real `geteuid` is callable and total.
    #[test]
    #[cfg_attr(miri, ignore = "geteuid(2) is a foreign function")]
    fn the_real_effective_uid_answers() {
        assert_eq!(
            effective_uid(),
            effective_uid(),
            "geteuid cannot fail and cannot change under us"
        );
    }

    // -- Assertions ported from the second termios implementation ------------
    //
    // A parallel unit implemented terminal echo suppression a second way, as
    // `tcgetattr`/`tcsetattr` methods on [`SysCalls`] with a `TerminalEcho`
    // guard. One implementation survives -- the [`TerminalCalls`] seam above,
    // which keeps terminal handling out of [`SysCalls`] so that a fake for the
    // hostname or interface primitives need not supply terminal behaviour it
    // never exercises -- but three of that implementation's measurements were
    // not covered here, so they are asserted below against the surviving API.
    // Its remaining eight assertions are already covered: disable-exactly-once,
    // restore-exactly-once, restore-on-drop, restore-on-unwind, the
    // unconditional `echo_disabled()`, the skip when nothing was captured, and
    // the two `SavedTerminal` predicates. Its `Debug`-rendering assertion has
    // no counterpart because [`SavedTerminal`] deliberately implements no
    // `Debug` and hands out no accessor, so nothing can render the attributes.

    /// Clearing echo must change exactly one bit.
    ///
    /// `RealSys::echo_disable` copies the captured attributes and clears
    /// `ECHO` alone (`src/tool_getpass.c:137-138`); the copy is what makes the
    /// original restorable, and every other local flag has to survive it.
    /// Clearing `ICANON` as well would turn the prompt into a raw read, and
    /// clearing `ISIG` would stop Ctrl-C from interrupting it -- neither is
    /// what C does. The bit arithmetic is asserted directly rather than through
    /// the seam because `tcsetattr` is a foreign function while this one step
    /// is pure.
    #[test]
    fn clearing_echo_leaves_every_other_local_flag_untouched() {
        let mut attrs = zeroed_termios();
        attrs.c_lflag = libc::ECHO | libc::ICANON | libc::ISIG | libc::IEXTEN;

        let mut cleared = attrs;
        cleared.c_lflag &= !libc::ECHO;

        assert_eq!(cleared.c_lflag & libc::ECHO, 0, "ECHO must be cleared");
        assert_eq!(
            cleared.c_lflag | libc::ECHO,
            attrs.c_lflag,
            "no other local flag may change"
        );
    }

    /// The disabling and restoring moments are two different POSIX constants,
    /// and the difference is load-bearing rather than incidental.
    ///
    /// `src/tool_getpass.c:139` clears the bit with `TCSANOW` -- take effect
    /// immediately, discard nothing -- and `:155` puts it back with
    /// `TCSAFLUSH`, which additionally discards input that arrived while echo
    /// was off. That is what stops the newline terminating the password from
    /// being echoed after the fact. If the two ever collapsed to one value the
    /// asymmetry `TerminalCalls` documents would become unobservable, so the
    /// distinctness is asserted where it can be seen.
    #[test]
    fn the_two_set_moments_are_distinct_posix_constants() {
        assert_ne!(
            libc::TCSANOW,
            libc::TCSAFLUSH,
            "echo_disable uses TCSANOW and echo_restore TCSAFLUSH; \
             they must remain two different requests"
        );
    }

    /// Two guards over one terminal keep two independent snapshots.
    ///
    /// [`SavedTerminal`] is `Copy` and each [`EchoGuard`] owns its own, so a
    /// nested guard cannot steal or share the outer one's attributes and each
    /// restores exactly what it captured. Asserted because the alternative --
    /// one shared snapshot -- would silently restore the inner guard's state
    /// twice and the outer guard's never.
    #[test]
    fn two_guards_do_not_share_one_saved_snapshot() {
        let stdin = io::stdin();
        let fake = FakeTerminal::new(true);

        {
            let _first = disable_echo_with(&fake, stdin.as_fd());
            let _second = disable_echo_with(&fake, stdin.as_fd());

            assert_eq!(
                fake.disable_calls.get(),
                2,
                "each guard captures for itself"
            );
            assert_eq!(fake.restore_calls.get(), 0);
        }

        assert_eq!(
            fake.restore_calls.get(),
            2,
            "each guard restores its own snapshot"
        );
    }
}
