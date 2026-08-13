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

//! `--interface` resolution: an interface name to a local source address.
//!
//! Supersedes `lib/if2ip.c` and `lib/if2ip.h`. Two functions, and between them
//! they answer the only question the C file exists to answer: given the name a
//! user typed after `--interface` (or `CURLOPT_INTERFACE`, or an FTP
//! `PORT`/`EPRT` interface argument), which local address should the socket
//! bind to?
//!
//! * [`ipv6_scope`] classifies an address into one of the five scopes of
//!   `lib/if2ip.h:29-33`. It supersedes `Curl_ipv6_scope`
//!   (`lib/if2ip.c:61-87`) and is pure arithmetic over the sixteen address
//!   bytes.
//! * [`if2ip`] walks the host's interface list and returns the three-valued
//!   verdict of `if2ip_result_t` (`lib/if2ip.h:41-45`). It supersedes
//!   `Curl_if2ip` (`lib/if2ip.c:94-174`).
//!
//! # ONLY ONE OF C's THREE IMPLEMENTATIONS IS PORTED
//!
//! `lib/if2ip.c` defines `Curl_if2ip` three times, under mutually exclusive
//! preprocessor conditions. This module reproduces exactly one of them, and
//! the other two are named here so that a later reader does not mistake
//! their absence for an omission and "restore" one:
//!
//! | C span | Selector | Disposition |
//! |---|---|---|
//! | `:92-174` | `#ifdef HAVE_GETIFADDRS` | **PORTED.** Both mandated operating systems provide `getifaddrs(3)`, so all four mandated targets take this branch. |
//! | `:176-237` | `#elif defined(HAVE_IOCTL_SIOCGIFADDR)` | **DELIBERATELY NOT PORTED.** A legacy `ioctl(SIOCGIFADDR)` fallback for platforms outside the four-target matrix. Its own comment at `:223-225` concedes that it "cannot tell the difference between an interface that does not exist and an interface that has no address of the correct family" -- so it is not merely redundant here, it is strictly less informative than the branch above. |
//! | `:239-258` | `#else` | **DELIBERATELY NOT PORTED.** A stub that discards every argument and returns `IF2IP_NOT_FOUND`. |
//!
//! # Deviations from the C, all three of them deliberate
//!
//! **1. Two snapshots where C takes one.** C makes a single `getifaddrs`
//! call and sees every node, including the `AF_PACKET` node Linux reports for
//! each interface and the `AF_LINK` node Darwin reports. Those carry no
//! Internet address, so [`crate::ffi::interface_addrs`] cannot represent them
//! and drops them -- which matters, because `lib/if2ip.c:163-166` uses
//! exactly such a node to distinguish "this interface exists but has no
//! address of the family you asked for" from "no such interface".
//! [`crate::ffi::interface_names`] is the seam's second projection of the
//! same snapshot, provided for this purpose, and this file consults it only
//! when the address walk has produced no name match at all.
//!
//! **3. `af` is an enumeration, not an integer.** C threads `int af` and
//! compares it against `sa_family`. `AF_INET6` is 10 on Linux and 30 on
//! Darwin, so carrying the integer would put a platform constant in an engine
//! signature; [`AddressFamily`] carries the same information without one.
//!
//! # This module is silent
//!
//! `lib/if2ip.c` emits no trace, no warning and no error text anywhere; it
//! communicates through its return value alone, and its callers do the
//! reporting (`lib/cf-socket.c:611-617`, `:630-631`). Nothing here logs
//! either. Adding a diagnostic would change output that is frozen.

use std::net::IpAddr;

use crate::dns::AddressFamily;
use crate::ffi::{
    interface_addrs_with, interface_names_with, RealSys, SysCalls,
};
use crate::util::inet::{ntop4, ntop6};
use crate::util::strcase::casecompare;

// IPv6 address scopes. `lib/if2ip.h:28-33`.

// The five values are C's own, and they are pinned rather than merely
// reproduced: a caller passes one of them to `if2ip` as `remote_scope`, which
// compares it for equality against the scope it computes (`lib/if2ip.c:125`),
// so the *numbers* are part of the contract and not an implementation detail.
// C declares them as `#define`s and returns them from a function typed
// `unsigned int`, which is why the Rust type is `u32` and not an enumeration:
// the comparison at `:125` is between two `unsigned int`s, one of which
// arrives from outside, and an enumeration would have to describe what an
// out-of-range integer means when C simply never matches it.
#[rustfmt::skip]
mod scope {
    /// `IPV6_SCOPE_GLOBAL 0` -- *"Global scope."*
    pub(super) const GLOBAL:      u32 = 0;
    /// `IPV6_SCOPE_LINKLOCAL 1` -- *"Link-local scope."*
    pub(super) const LINKLOCAL:   u32 = 1;
    /// `IPV6_SCOPE_SITELOCAL 2` -- *"Site-local scope (deprecated)."*
    pub(super) const SITELOCAL:   u32 = 2;
    /// `IPV6_SCOPE_UNIQUELOCAL 3` -- *"Unique local"*
    pub(super) const UNIQUELOCAL: u32 = 3;
    /// `IPV6_SCOPE_NODELOCAL 4` -- *"Loopback."*
    pub(super) const NODELOCAL:   u32 = 4;
}

/// `IPV6_SCOPE_GLOBAL 0` -- *"Global scope."* (`lib/if2ip.h:29`)
///
/// Also the answer for every non-IPv6 address, and the answer the whole
/// function collapses to in a build without IPv6: `lib/if2ip.h:38` reads
/// `#define Curl_ipv6_scope(x) 0`.
#[allow(dead_code)] // consumers: conn/ and protocols/ftp/
pub(crate) const IPV6_SCOPE_GLOBAL: u32 = scope::GLOBAL;

/// `IPV6_SCOPE_LINKLOCAL 1` -- *"Link-local scope."* (`lib/if2ip.h:30`)
#[allow(dead_code)] // consumers: conn/ and protocols/ftp/
pub(crate) const IPV6_SCOPE_LINKLOCAL: u32 = scope::LINKLOCAL;

/// `IPV6_SCOPE_SITELOCAL 2` -- *"Site-local scope (deprecated)."*
/// (`lib/if2ip.h:31`)
///
/// Deprecated by RFC 3879 and kept because the classifier still reports it:
/// `fec0::/10` is matched at `lib/if2ip.c:74-75`, so an address in that range
/// binds only to a site-local source address and never to a global one.
#[allow(dead_code)] // consumers: conn/ and protocols/ftp/
pub(crate) const IPV6_SCOPE_SITELOCAL: u32 = scope::SITELOCAL;

/// `IPV6_SCOPE_UNIQUELOCAL 3` -- *"Unique local"* (`lib/if2ip.h:32`)
#[allow(dead_code)] // consumers: conn/ and protocols/ftp/
pub(crate) const IPV6_SCOPE_UNIQUELOCAL: u32 = scope::UNIQUELOCAL;

/// `IPV6_SCOPE_NODELOCAL 4` -- *"Loopback."* (`lib/if2ip.h:33`)
#[allow(dead_code)] // consumers: conn/ and protocols/ftp/
pub(crate) const IPV6_SCOPE_NODELOCAL: u32 = scope::NODELOCAL;

// The verdict. `lib/if2ip.h:41-45`.

/// The three outcomes of an interface lookup -- supersedes `if2ip_result_t`.
///
/// ```text
/// typedef enum {
///   IF2IP_NOT_FOUND = 0, /* Interface not found */
///   IF2IP_AF_NOT_SUPPORTED = 1, /* Int. exists but has no address for this af */
///   IF2IP_FOUND = 2 /* The address has been stored in "buf" */
/// } if2ip_result_t;
/// ```
///
/// # Why this is not an `Option<String>`
///
/// The gap between the first two variants is load-bearing, and both callers
/// act on it differently:
///
/// * `bindlocal` treats `IF2IP_NOT_FOUND` as "that was not an interface
///   name" and falls back to resolving the string as a hostname, or fails
///   with `CURLE_INTERFACE_FAILED` when the user wrote `--interface if!name`
///   and forbade the fallback (`lib/cf-socket.c:612-621`). It turns
///   `IF2IP_AF_NOT_SUPPORTED` into `CURLE_UNSUPPORTED_PROTOCOL`, which
///   signals its own caller to *try the other address family*
///   (`:622-624`) -- a retry, not a failure.
/// * The FTP `PORT`/`EPRT` path uses the string as a hostname on
///   `IF2IP_NOT_FOUND` and abandons the transfer on
///   `IF2IP_AF_NOT_SUPPORTED` (`lib/ftp.c:1003-1008`).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[allow(dead_code)] // consumers: conn/socket.rs and protocols/ftp/
pub(crate) enum If2IpResult {
    /// `IF2IP_NOT_FOUND` -- *"Interface not found"*.
    ///
    /// Also the verdict when interface enumeration itself failed, for the
    /// reason given in this module's documentation.
    NotFound,

    /// `IF2IP_AF_NOT_SUPPORTED` -- *"Int. exists but has no address for this
    /// af"*.
    AfNotSupported,

    /// `IF2IP_FOUND` -- *"The address has been stored in `buf`"*.
    ///
    /// The payload is the text `lib/if2ip.c:158-159` builds: the address as
    /// `curlx_inet_ntop` renders it, followed by `%<scopeid>` when the
    /// interface address carried a non-zero IPv6 scope id.
    Found(String),
}

impl If2IpResult {
    /// The `if2ip_result_t` integer this verdict corresponds to.
    #[allow(dead_code)] // consumer: the ABI shim, which converts through it
    pub(crate) const fn verdict(&self) -> u32 {
        match self {
            Self::NotFound => 0,
            Self::AfNotSupported => 1,
            Self::Found(_) => 2,
        }
    }
}

// The scope classifier. `lib/if2ip.c:59-88`.

/// The scope of an address -- supersedes `Curl_ipv6_scope`
/// (`lib/if2ip.c:61-87`).
///
/// # The transcription is literal, and three details are why
///
/// **The loopback test ORs bytes 1 through 14 and tests byte 15 separately**
/// (`:77-81`):
///
/// ```text
/// w = b[1] | b[2] | b[3] | b[4] | b[5] | b[6] | b[7] | b[8] | b[9] |
///     b[10] | b[11] | b[12] | b[13] | b[14];
/// if(w || b[15] != 0x01)
///   break;
/// return IPV6_SCOPE_NODELOCAL;
/// ```
#[allow(dead_code)] // conn/ and protocols/ftp/ call it.
#[must_use]
pub(crate) fn ipv6_scope(addr: IpAddr) -> u32 {
    // `if(sa->sa_family == AF_INET6) { ... }` and the `return
    // IPV6_SCOPE_GLOBAL` that follows the block (`lib/if2ip.c:63`, `:86`).
    let v6 = match addr {
        IpAddr::V6(v6) => v6,
        IpAddr::V4(_) => return scope::GLOBAL,
    };

    // `const unsigned char *b = sa6->sin6_addr.s6_addr;` (`:66`). Destructured
    // rather than indexed so that every byte the algorithm reads is named once
    // and no subscript can go out of range.
    let [b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15] =
        v6.octets();

    // `unsigned short w = (unsigned short)((b[0] << 8) | b[1]);` (`:67`).
    let w = (u16::from(b0) << 8) | u16::from(b1);

    // `if((b[0] & 0xFE) == 0xFC) return IPV6_SCOPE_UNIQUELOCAL;` -- `/* Handle
    // ULAs */` (`:69-70`). BEFORE the switch, and therefore ahead of every arm
    // of it.
    if (b0 & 0xFE) == 0xFC {
        return scope::UNIQUELOCAL;
    }

    // `switch(w & 0xFFC0)` (`:71`). C's `break` in each non-returning arm
    // leaves the switch and falls to `:86`; here that is the `_` arm plus the
    // failed loopback test, both of which reach the final expression.
    match w & 0xFFC0 {
        // `case 0xFE80: return IPV6_SCOPE_LINKLOCAL;` (`:72-73`).
        0xFE80 => scope::LINKLOCAL,

        // `case 0xFEC0: return IPV6_SCOPE_SITELOCAL;` (`:74-75`).
        0xFEC0 => scope::SITELOCAL,

        // `case 0x0000:` (`:76`) -- the loopback test of `:77-81`, transcribed
        // byte for byte. `b0` is excluded from the OR because this arm has
        // already established it, and `b15` is excluded because it is tested
        // for equality with `0x01` rather than for zero-ness.
        0x0000 => {
            let rest = b1
                | b2
                | b3
                | b4
                | b5
                | b6
                | b7
                | b8
                | b9
                | b10
                | b11
                | b12
                | b13
                | b14;

            // `if(w || b[15] != 0x01) break;` then `return
            // IPV6_SCOPE_NODELOCAL;` (`:79-81`).
            if rest != 0 || b15 != 0x01 {
                scope::GLOBAL
            } else {
                scope::NODELOCAL
            }
        }

        // `default: break;` (`:82-83`), reaching `:86`.
        _ => scope::GLOBAL,
    }
}

// The interface walk. `lib/if2ip.c:94-174`, the HAVE_GETIFADDRS body.

/// The address family an [`IpAddr`] belongs to.
const fn family_of(addr: IpAddr) -> AddressFamily {
    match addr {
        IpAddr::V4(_) => AddressFamily::Inet,
        IpAddr::V6(_) => AddressFamily::Inet6,
    }
}

/// Whether any interface at all bears this name, whatever address it has.
fn interface_name_exists(sys: &dyn SysCalls, interf: &[u8]) -> bool {
    match interface_names_with(sys) {
        // `curl_strequal(iface->ifa_name, interf)` (`lib/if2ip.c:164`).
        Ok(names) => names.iter().any(|name| casecompare(name, interf)),
        Err(_) => false,
    }
}

/// Resolves an interface name to a local source address -- supersedes
/// `Curl_if2ip` (`lib/if2ip.c:94-174`).
///
/// # Parameters
///
/// * `af` -- the family the socket will be. Only an interface address of this
///   family can satisfy the request; one of another family contributes only
///   the [`If2IpResult::AfNotSupported`] downgrade.
/// * `remote_scope` -- the scope of the address about to be connected to, as
///   [`ipv6_scope`] classifies it. An IPv6 interface address whose scope
///   differs is rejected, because C is *"interested only in interface
///   addresses whose scope matches the remote address we want to connect to:
///   global for global, link-local for link-local, etc..."* (`:126-128`).
///   Ignored for IPv4, exactly as `:153-156` ignores it.
/// * `local_scope_id` -- an IPv6 scope id the interface address must carry,
///   or **`0` for no constraint**. C's guard is
///   `if(local_scope_id && scopeid != local_scope_id)` (`:142`), so zero does
///   not mean "must be unscoped"; it means the test is skipped.
/// * `interf` -- the name to look for, compared **case-insensitively** and as
///   raw bytes. C uses `curl_strequal` (`:113`), and neither mandated kernel
///   promises an interface name is UTF-8, so no decoding happens on this path
///   in either direction.
///
/// # The verdict, and the two ways a match is abandoned mid-walk
///
/// Both abandonments set [`If2IpResult::AfNotSupported`] *only if no verdict
/// has been reached yet* and then **keep scanning** -- C's `continue`, not its
/// `break`. A later address on the same interface can still satisfy the
/// request, and a `Found` already reached can never be overwritten:
///
/// * the scope differs from `remote_scope` (`:125-132`);
/// * `local_scope_id` is non-zero and differs from the address's scope id
///   (`:142-147`).
#[allow(dead_code)] // consumers: conn/socket.rs and protocols/ftp/
#[must_use]
pub(crate) fn if2ip(
    af: AddressFamily,
    remote_scope: u32,
    local_scope_id: u32,
    interf: &[u8],
) -> If2IpResult {
    if2ip_with(&RealSys, af, remote_scope, local_scope_id, interf)
}

/// [`if2ip`] over an injected operating system.
#[must_use]
pub(crate) fn if2ip_with(
    sys: &dyn SysCalls,
    af: AddressFamily,
    remote_scope: u32,
    local_scope_id: u32,
    interf: &[u8],
) -> If2IpResult {
    // `if2ip_result_t res = IF2IP_NOT_FOUND;` (`:103`).
    let mut res = If2IpResult::NotFound;

    // `if(getifaddrs(&head) >= 0)` (`:109`). The seam owns the call, the NULL
    // `ifa_addr` guard of `:111` and the `freeifaddrs(head)` of `:170`; a
    // failure is C's skipped loop, which returns the initial verdict.
    let addrs = match interface_addrs_with(sys) {
        Ok(addrs) => addrs,
        Err(_) => return If2IpResult::NotFound,
    };

    // `for(iface = head; iface != NULL; iface = iface->ifa_next)` (`:110`),
    // in the order the operating system reported.
    for iface in &addrs {
        // `if(iface->ifa_addr->sa_family == af)` (`:112`), inverted so that
        // the mismatch arm of `:163-166` reads beside its own condition.
        if family_of(iface.addr) != af {
            // `else if((res == IF2IP_NOT_FOUND) &&
            //          curl_strequal(iface->ifa_name, interf))
            //   res = IF2IP_AF_NOT_SUPPORTED;` (`:163-166`).
            if res == If2IpResult::NotFound && casecompare(&iface.name, interf)
            {
                res = If2IpResult::AfNotSupported;
            }
            continue;
        }

        // `if(curl_strequal(iface->ifa_name, interf))` (`:113`). A
        // family match under another name contributes nothing at all: C
        // has no `else` on this test.
        if !casecompare(&iface.name, interf) {
            continue;
        }

        // `char scope[12] = "";` (`:116`) -- empty unless an IPv6 scope id
        // fills it at `:150`. In C its twelve bytes cap the suffix; a
        // `String` cannot clip, which this module records as a deviation.
        let mut scope_suffix = String::new();

        let rendered = match iface.addr {
            // `if(af == AF_INET6) {` (`:119`). The family test above has
            // already established that this arm and that condition coincide.
            IpAddr::V6(v6) => {
                // `unsigned int ifscope = Curl_ipv6_scope(iface->ifa_addr);`
                // (`:123`) -- the scope of the INTERFACE's address.
                let ifscope = ipv6_scope(iface.addr);

                // `if(ifscope != remote_scope) { ... continue; }` (`:125-132`)
                // -- *"We are interested only in interface addresses whose
                // scope matches the remote address we want to connect to:
                // global for global, link-local for link-local, etc..."*
                if ifscope != remote_scope {
                    if res == If2IpResult::NotFound {
                        res = If2IpResult::AfNotSupported;
                    }
                    continue;
                }

                // `scopeid = ((struct sockaddr_in6 *)...)->sin6_scope_id;`
                // (`:138-139`) -- */* Include the scope of this interface as
                // part of the address */*.
                let scopeid = iface.scope_id;

                // `if(local_scope_id && scopeid != local_scope_id) { ...
                // continue; }` (`:141-147`) -- */* If given, scope id should
                // match. */*. The leading `local_scope_id &&` is why zero
                // means "no constraint" rather than "must be zero".
                if local_scope_id != 0 && scopeid != local_scope_id {
                    if res == If2IpResult::NotFound {
                        res = If2IpResult::AfNotSupported;
                    }
                    continue;
                }

                // `if(scopeid)
                //    curl_msnprintf(scope, sizeof(scope), "%%%u", scopeid);`
                // (`:149-150`). The `%%` is printf's escape for one literal
                // per cent, so the suffix is `%<scopeid>` -- `%2`, not `%%2`
                // -- and it is written only for a non-zero id.
                if scopeid != 0 {
                    scope_suffix = format!("%{scopeid}");
                }

                // `ip = curlx_inet_ntop(af, addr, ipstr, sizeof(ipstr));`
                // (`:158`) with `addr = &sin6_addr` from `:134-135`. The arm
                // has discriminated on the family, so the call fuses into
                // `ntop6` -- which is `lib/curlx/inet_ntop.c:88-197`, not
                // `std::net`'s formatter.
                ntop6(&v6.octets())
            }

            // `else addr = &((struct sockaddr_in *)...)->sin_addr;`
            // (`:153-156`), then the same `curlx_inet_ntop` at `:158`. There
            // is no scope handling on this path at all, so `scope_suffix`
            // stays empty however the seam reported `scope_id`.
            IpAddr::V4(v4) => ntop4(&v4.octets()),
        };

        // `res = IF2IP_FOUND;` (`:157`) and
        // `curl_msnprintf(buf, buf_size, "%s%s", ip, scope);` (`:159`) --
        // concatenated with no separator, because the per cent is already the
        // first byte of the suffix.
        res = If2IpResult::Found(format!("{rendered}{scope_suffix}"));

        // `break;` (`:160`). The first match wins and the rest of the list is
        // never examined.
        break;
    }

    // Not a line of C, but the behaviour of one: see [`interface_name_exists`]
    // and this module's first deviation. Reaching here still holding
    // `NotFound` proves that no address-bearing node carried this name, so
    // consulting the name list can only discover a node whose family the
    // address projection could not represent -- which is exactly the node C
    // sees at `:163-166` and this walk cannot.
    if res == If2IpResult::NotFound && interface_name_exists(sys, interf) {
        res = If2IpResult::AfNotSupported;
    }

    // `return res;` (`:173`).
    res
}

#[cfg(test)]
mod tests {
    use super::{
        family_of, if2ip_with, ipv6_scope, If2IpResult, IPV6_SCOPE_GLOBAL,
        IPV6_SCOPE_LINKLOCAL, IPV6_SCOPE_NODELOCAL, IPV6_SCOPE_SITELOCAL,
        IPV6_SCOPE_UNIQUELOCAL,
    };
    use crate::dns::AddressFamily;
    use crate::ffi::{IfNode, RawIfAddr, RealSys, SysCalls};
    use std::cell::Cell;
    use std::ffi::CStr;
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::os::fd::BorrowedFd;

    // -- the fake operating system -----------------------------------------

    /// A pure-Rust [`SysCalls`] whose interface list the test chooses.
    struct FakeSys {
        /// The snapshot `ifaddrs` reports; [`None`] reports a failure.
        nodes: Option<Vec<IfNode>>,
        /// How many times `ifaddrs` has been called.
        calls: Cell<usize>,
    }

    impl FakeSys {
        fn with(nodes: Vec<IfNode>) -> Self {
            Self {
                nodes: Some(nodes),
                calls: Cell::new(0),
            }
        }

        /// A host whose interface list is empty but readable.
        fn empty() -> Self {
            Self::with(Vec::new())
        }

        /// A host on which `getifaddrs(3)` fails.
        fn failing() -> Self {
            Self {
                nodes: None,
                calls: Cell::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.calls.get()
        }
    }

    /// The seven methods below `ifaddrs` are irrelevant here and say so.
    ///
    /// They report [`io::ErrorKind::Unsupported`] rather than an `errno`,
    /// which is deliberate: an `errno` would mean naming `libc`, and no file
    /// outside `src/ffi/` may. Nothing on this module's paths reaches them.
    impl SysCalls for FakeSys {
        fn ifaddrs(&self) -> io::Result<Vec<IfNode>> {
            self.calls.set(self.calls.get() + 1);
            match &self.nodes {
                Some(nodes) => Ok(nodes.clone()),
                None => Err(io::Error::from(io::ErrorKind::Other)),
            }
        }

        fn gethostname(&self, _buf: &mut [u8]) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }

        fn if_nametoindex(&self, _name: &CStr) -> Option<u32> {
            None
        }

        fn effective_uid(&self) -> u32 {
            0
        }

        fn fd_offset(&self, _fd: BorrowedFd<'_>) -> io::Result<i64> {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }

        fn fd_regular_size(
            &self,
            _fd: BorrowedFd<'_>,
        ) -> io::Result<Option<i64>> {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }

        fn read_fd(
            &self,
            _fd: BorrowedFd<'_>,
            _buf: &mut [u8],
        ) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }

        fn seek_fd(&self, _fd: BorrowedFd<'_>, _offset: i64) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
    }

    /// A node carrying one IPv4 address.
    fn v4_node(name: &str, octets: [u8; 4]) -> IfNode {
        IfNode {
            name: name.as_bytes().to_vec(),
            addr: Some(RawIfAddr::V4(octets)),
        }
    }

    /// A node carrying one IPv6 address and its `sin6_scope_id`.
    fn v6_node(name: &str, text: &str, scope_id: u32) -> IfNode {
        IfNode {
            name: name.as_bytes().to_vec(),
            addr: Some(RawIfAddr::V6 {
                octets: v6(text).octets(),
                scope_id,
            }),
        }
    }

    /// A node whose family this crate does not represent.
    ///
    /// `AF_PACKET` on Linux, `AF_LINK` on Darwin. Every interface has one, and
    /// `lib/if2ip.c:163-166` depends on seeing it.
    fn link_node(name: &str) -> IfNode {
        IfNode {
            name: name.as_bytes().to_vec(),
            addr: Some(RawIfAddr::Unrepresentable),
        }
    }

    /// A node whose `ifa_addr` was NULL -- the `lib/if2ip.c:111` case.
    fn addrless_node(name: &str) -> IfNode {
        IfNode {
            name: name.as_bytes().to_vec(),
            addr: None,
        }
    }

    /// An IPv6 address from its textual form.
    ///
    /// Parsing is `std`'s, which is safe here because nothing about the
    /// *parser* is under test; the classifier reads octets and the renderer is
    /// `util::inet`'s. `expect` is confined to test code by design.
    fn v6(text: &str) -> Ipv6Addr {
        text.parse().expect("a well-formed IPv6 literal")
    }

    /// The classification of an IPv6 literal.
    fn scope_of(text: &str) -> u32 {
        ipv6_scope(IpAddr::V6(v6(text)))
    }

    /// The classification of the address whose first two bytes are given and
    /// whose remaining fourteen are zero but for a trailing `0x01`.
    ///
    /// The tail is `::1`'s so that the `0x0000` arm's loopback test is
    /// genuinely exercised by the sweep rather than trivially failed.
    fn scope_of_prefix(b0: u8, b1: u8) -> u32 {
        let mut octets = [0u8; 16];
        octets[0] = b0;
        octets[1] = b1;
        octets[15] = 0x01;
        ipv6_scope(IpAddr::V6(Ipv6Addr::from(octets)))
    }

    /// The text of a `Found`, or a message naming what was returned instead.
    fn found_text(result: &If2IpResult) -> &str {
        match result {
            If2IpResult::Found(text) => text,
            If2IpResult::NotFound => "<NotFound>",
            If2IpResult::AfNotSupported => "<AfNotSupported>",
        }
    }

    // -- ipv6_scope: the five scopes ---------------------------------------

    /// `lib/if2ip.h:29-33` -- the five values are the ABI of this function.
    #[test]
    fn the_scope_constants_are_the_headers_own() {
        assert_eq!(IPV6_SCOPE_GLOBAL, 0);
        assert_eq!(IPV6_SCOPE_LINKLOCAL, 1);
        assert_eq!(IPV6_SCOPE_SITELOCAL, 2);
        assert_eq!(IPV6_SCOPE_UNIQUELOCAL, 3);
        assert_eq!(IPV6_SCOPE_NODELOCAL, 4);
    }

    /// `::1` is the ONLY address the `0x0000` arm accepts (`lib/if2ip.c:79`).
    #[test]
    fn the_loopback_address_is_node_local() {
        assert_eq!(scope_of("::1"), IPV6_SCOPE_NODELOCAL);
    }

    /// The all-zero address is global, because `b[15] != 0x01`.
    ///
    /// Pins the half of `if(w || b[15] != 0x01)` that an implementation
    /// reaching for `Ipv6Addr::is_loopback` would still get right and one
    /// testing only zero-ness of the whole address would get wrong.
    #[test]
    fn the_unspecified_address_is_global_not_node_local() {
        assert_eq!(scope_of("::"), IPV6_SCOPE_GLOBAL);
    }

    /// `::2` is global: byte 15 must equal `0x01` exactly, not merely be
    /// non-zero.
    #[test]
    fn a_low_address_other_than_one_is_global() {
        assert_eq!(scope_of("::2"), IPV6_SCOPE_GLOBAL);
        assert_eq!(scope_of("::ff"), IPV6_SCOPE_GLOBAL);
    }

    /// A non-zero byte anywhere in `b[1]`..`b[14]` defeats the loopback test.
    ///
    /// `::1:0:0:1` has `b[9] == 0x01` and `b[15] == 0x01`, so it passes the
    /// byte-15 test and fails the OR. It is the case an implementation that
    /// narrowed the OR range would classify as node-local, and the reason the
    /// range is transcribed literally.
    #[test]
    fn a_non_zero_byte_inside_the_or_range_is_global() {
        assert_eq!(scope_of("::1:0:0:1"), IPV6_SCOPE_GLOBAL);

        // Every interior byte, one at a time: b[1] through b[14], each with
        // b[15] left at 0x01 so only the OR can reject the address.
        for index in 1..=14usize {
            let mut octets = [0u8; 16];
            octets[index] = 0x01;
            octets[15] = 0x01;
            assert_eq!(
                ipv6_scope(IpAddr::V6(Ipv6Addr::from(octets))),
                IPV6_SCOPE_GLOBAL,
                "byte {index} is inside the OR of lib/if2ip.c:77-78"
            );
        }
    }

    /// `fe80::/10` is link-local, and the boundary is the `0xFFC0` mask.
    #[test]
    fn the_link_local_prefix_and_its_boundaries() {
        assert_eq!(scope_of("fe80::1"), IPV6_SCOPE_LINKLOCAL);
        // The top of fe80::/10: 0xfebf & 0xFFC0 == 0xFE80.
        assert_eq!(scope_of("febf::1"), IPV6_SCOPE_LINKLOCAL);
        // Just below it: 0xfe7f & 0xFFC0 == 0xFE40, which no arm matches.
        assert_eq!(scope_of("fe7f::1"), IPV6_SCOPE_GLOBAL);
    }

    /// `fec0::/10` is site-local -- deprecated by RFC 3879, still classified.
    #[test]
    fn the_site_local_prefix_and_its_boundaries() {
        assert_eq!(scope_of("fec0::1"), IPV6_SCOPE_SITELOCAL);
        // The top of fec0::/10: 0xfeff & 0xFFC0 == 0xFEC0.
        assert_eq!(scope_of("feff::1"), IPV6_SCOPE_SITELOCAL);
    }

    /// `(b[0] & 0xFE) == 0xFC` catches `fc00::/8` and `fd00::/8` and nothing
    /// else (`lib/if2ip.c:69`).
    #[test]
    fn the_unique_local_test_is_the_masked_first_byte() {
        assert_eq!(scope_of("fc00::1"), IPV6_SCOPE_UNIQUELOCAL);
        assert_eq!(scope_of("fd00::1"), IPV6_SCOPE_UNIQUELOCAL);
        assert_eq!(scope_of("fcff:ffff::abcd"), IPV6_SCOPE_UNIQUELOCAL);
        assert_eq!(scope_of("fdff:ffff::abcd"), IPV6_SCOPE_UNIQUELOCAL);
        // One below and one above the pair the mask accepts.
        assert_eq!(scope_of("fb00::1"), IPV6_SCOPE_GLOBAL);
        assert_eq!(scope_of("fe00::1"), IPV6_SCOPE_GLOBAL);
    }

    /// The early return is what makes a unique-local address unique-local.
    ///
    /// Without it `fc00::1` would reach `default: break;` (`lib/if2ip.c:82`)
    /// and come back global, so this is the observable half of the ordering at
    /// `:69-71`.
    #[test]
    fn the_unique_local_test_wins_over_the_switch_default() {
        for text in ["fc00::1", "fd00::1", "fcff::", "fd12:3456:789a::1"] {
            assert_eq!(
                scope_of(text),
                IPV6_SCOPE_UNIQUELOCAL,
                "{text} must not fall through to the switch"
            );
        }
    }

    /// The unique-local test and every RETURNING arm of the switch are
    /// disjoint, so their relative order cannot be observed.
    #[test]
    fn the_unique_local_test_and_the_switch_arms_are_disjoint() {
        let mut unique_local = 0_usize;

        for b0 in 0..=u8::MAX {
            for b1 in 0..=u8::MAX {
                let masked = ((u16::from(b0) << 8) | u16::from(b1)) & 0xFFC0;
                let is_ula = (b0 & 0xFE) == 0xFC;
                let hits_a_returning_arm =
                    matches!(masked, 0xFE80 | 0xFEC0 | 0x0000);

                assert!(
                    !(is_ula && hits_a_returning_arm),
                    "b0={b0:#04x} b1={b1:#04x} satisfies both conditions"
                );

                if is_ula {
                    unique_local += 1;
                    // Discriminating rather than vacuous: the condition really
                    // does fire, and on exactly the addresses it should.
                    assert_eq!(
                        scope_of_prefix(b0, b1),
                        IPV6_SCOPE_UNIQUELOCAL,
                        "b0={b0:#04x} b1={b1:#04x}"
                    );
                }
            }
        }

        // Two values of b[0] times 256 values of b[1].
        assert_eq!(unique_local, 512);
    }

    /// The mask decides the two prefixed scopes, over every first-two-byte
    /// pair.
    ///
    /// A sweep rather than four point tests, because the failure this guards
    /// against is a wrong mask -- `0xFFE0` or `0xFF80` would each keep
    /// `fe80::1` and `fec0::1` correct while moving the boundary.
    #[test]
    fn the_mask_boundaries_hold_across_every_first_two_bytes() {
        for b0 in 0..=u8::MAX {
            for b1 in 0..=u8::MAX {
                let word = (u16::from(b0) << 8) | u16::from(b1);
                let expected = if (b0 & 0xFE) == 0xFC {
                    IPV6_SCOPE_UNIQUELOCAL
                } else if (0xFE80..=0xFEBF).contains(&word) {
                    IPV6_SCOPE_LINKLOCAL
                } else if (0xFEC0..=0xFEFF).contains(&word) {
                    IPV6_SCOPE_SITELOCAL
                } else if word == 0x0000 {
                    // b[1] is zero here, and the helper's remaining bytes are
                    // zero but for the trailing 0x01, so this is `::1`.
                    IPV6_SCOPE_NODELOCAL
                } else {
                    IPV6_SCOPE_GLOBAL
                };

                assert_eq!(
                    scope_of_prefix(b0, b1),
                    expected,
                    "b0={b0:#04x} b1={b1:#04x}"
                );
            }
        }
    }

    /// An ordinary documentation-range address is global.
    #[test]
    fn a_global_unicast_address_is_global() {
        assert_eq!(scope_of("2001:db8::1"), IPV6_SCOPE_GLOBAL);
        assert_eq!(scope_of("2606:4700::1111"), IPV6_SCOPE_GLOBAL);
    }

    /// Every IPv4 address is global -- C's `sa_family != AF_INET6`
    /// fall-through (`lib/if2ip.c:63`, `:86`), and the same answer as
    /// `#define Curl_ipv6_scope(x) 0` (`lib/if2ip.h:38`).
    #[test]
    fn every_ipv4_address_is_global() {
        for octets in [
            [0, 0, 0, 0],
            [127, 0, 0, 1],
            [10, 0, 0, 7],
            [169, 254, 1, 1],
            [192, 0, 2, 5],
            [255, 255, 255, 255],
        ] {
            assert_eq!(
                ipv6_scope(IpAddr::V4(Ipv4Addr::from(octets))),
                IPV6_SCOPE_GLOBAL,
                "{octets:?}"
            );
        }
    }

    // -- the verdict -------------------------------------------------------

    /// `lib/if2ip.h:41-45` -- `0`, `1`, `2`, in that order.
    #[test]
    fn the_verdict_integers_are_the_headers_own() {
        assert_eq!(If2IpResult::NotFound.verdict(), 0);
        assert_eq!(If2IpResult::AfNotSupported.verdict(), 1);
        assert_eq!(If2IpResult::Found(String::new()).verdict(), 2);
    }

    /// The family projection has exactly the two reachable cases.
    #[test]
    fn the_family_projection_covers_both_internet_families() {
        assert_eq!(
            family_of(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5))),
            AddressFamily::Inet
        );
        assert_eq!(
            family_of(IpAddr::V6(v6("2001:db8::1"))),
            AddressFamily::Inet6
        );
    }

    // -- if2ip: finding an address ----------------------------------------

    /// The ordinary case: one interface, one IPv4 address, asked for by name.
    #[test]
    fn an_ipv4_interface_resolves_to_its_dotted_quad() {
        let sys = FakeSys::with(vec![v4_node("eth0", [192, 0, 2, 5])]);

        let got = if2ip_with(
            &sys,
            AddressFamily::Inet,
            IPV6_SCOPE_GLOBAL,
            0,
            b"eth0",
        );

        assert_eq!(got, If2IpResult::Found("192.0.2.5".to_owned()));
        // One snapshot: the address walk decided, so the name list was never
        // consulted.
        assert_eq!(sys.calls(), 1);
    }

    /// `curl_strequal` folds ASCII case, in both directions
    /// (`lib/if2ip.c:113`).
    ///
    /// Interface names are conventionally lower case, but C accepts any
    /// spelling and that is reachable through `--interface`.
    #[test]
    fn the_name_comparison_is_case_insensitive() {
        let lower = FakeSys::with(vec![v4_node("eth0", [10, 0, 0, 7])]);
        let upper = FakeSys::with(vec![v4_node("ETH0", [10, 0, 0, 8])]);

        for requested in [&b"ETH0"[..], b"Eth0", b"eTh0", b"eth0"] {
            assert_eq!(
                if2ip_with(
                    &lower,
                    AddressFamily::Inet,
                    IPV6_SCOPE_GLOBAL,
                    0,
                    requested
                ),
                If2IpResult::Found("10.0.0.7".to_owned()),
                "{requested:?} against a lower-case interface"
            );
            assert_eq!(
                if2ip_with(
                    &upper,
                    AddressFamily::Inet,
                    IPV6_SCOPE_GLOBAL,
                    0,
                    requested
                ),
                If2IpResult::Found("10.0.0.8".to_owned()),
                "{requested:?} against an upper-case interface"
            );
        }
    }

    /// The folding is ASCII-only, so a name that is not UTF-8 still matches.
    ///
    /// Neither mandated kernel promises UTF-8 in an interface name, and the
    /// seam hands the bytes across undecoded for exactly this reason. A lossy
    /// decode anywhere on the path would make such a name unmatchable.
    #[test]
    fn a_non_utf8_interface_name_still_matches() {
        let name = [b'e', 0xFF, 0xFE, b'0'];
        let sys = FakeSys::with(vec![IfNode {
            name: name.to_vec(),
            addr: Some(RawIfAddr::V4([10, 1, 2, 3])),
        }]);

        assert_eq!(
            if2ip_with(&sys, AddressFamily::Inet, IPV6_SCOPE_GLOBAL, 0, &name),
            If2IpResult::Found("10.1.2.3".to_owned())
        );
    }

    /// The FIRST match wins and the walk stops (`lib/if2ip.c:157-160`).
    #[test]
    fn the_first_matching_address_wins() {
        let sys = FakeSys::with(vec![
            v4_node("eth0", [192, 0, 2, 1]),
            v4_node("eth0", [192, 0, 2, 2]),
            v4_node("eth0", [192, 0, 2, 3]),
        ]);

        assert_eq!(
            if2ip_with(
                &sys,
                AddressFamily::Inet,
                IPV6_SCOPE_GLOBAL,
                0,
                b"eth0"
            ),
            If2IpResult::Found("192.0.2.1".to_owned())
        );
    }

    /// An interface of another name contributes nothing: C has no `else` on
    /// the name test at `lib/if2ip.c:113`.
    #[test]
    fn an_unrelated_interface_is_ignored() {
        let sys = FakeSys::with(vec![
            v4_node("lo", [127, 0, 0, 1]),
            v4_node("wlan0", [192, 168, 1, 5]),
            v4_node("eth0", [192, 0, 2, 9]),
        ]);

        assert_eq!(
            if2ip_with(
                &sys,
                AddressFamily::Inet,
                IPV6_SCOPE_GLOBAL,
                0,
                b"eth0"
            ),
            If2IpResult::Found("192.0.2.9".to_owned())
        );
    }

    // -- if2ip: the two negative verdicts ---------------------------------

    /// A name that is on no interface at all is `IF2IP_NOT_FOUND`.
    #[test]
    fn an_absent_interface_is_not_found() {
        let sys = FakeSys::with(vec![
            v4_node("lo", [127, 0, 0, 1]),
            link_node("lo"),
            v4_node("eth0", [192, 0, 2, 5]),
            link_node("eth0"),
        ]);

        assert_eq!(
            if2ip_with(
                &sys,
                AddressFamily::Inet,
                IPV6_SCOPE_GLOBAL,
                0,
                b"eth9"
            ),
            If2IpResult::NotFound
        );
    }

    /// An empty interface list is `IF2IP_NOT_FOUND`.
    #[test]
    fn an_empty_interface_list_is_not_found() {
        let sys = FakeSys::empty();

        assert_eq!(
            if2ip_with(
                &sys,
                AddressFamily::Inet,
                IPV6_SCOPE_GLOBAL,
                0,
                b"eth0"
            ),
            If2IpResult::NotFound
        );
    }

    /// A failing `getifaddrs(3)` is `IF2IP_NOT_FOUND`, NOT an error.
    ///
    /// C tests `if(getifaddrs(&head) >= 0)` (`lib/if2ip.c:109`) and on failure
    /// skips the walk entirely, returning the `res` it initialised at `:103`.
    /// Propagating the seam's `CURLcode` instead would change what `bindlocal`
    /// does: `IF2IP_NOT_FOUND` makes it retry the string as a hostname.
    #[test]
    fn a_failing_enumeration_is_not_found() {
        let sys = FakeSys::failing();

        assert_eq!(
            if2ip_with(
                &sys,
                AddressFamily::Inet,
                IPV6_SCOPE_GLOBAL,
                0,
                b"eth0"
            ),
            If2IpResult::NotFound
        );
        // The failure was observed on the address walk and short-circuited the
        // whole function: the name list is not consulted after it.
        assert_eq!(sys.calls(), 1);
    }

    /// A name present only with the WRONG family is `IF2IP_AF_NOT_SUPPORTED`
    /// (`lib/if2ip.c:163-166`), which is materially different from
    /// `IF2IP_NOT_FOUND`.
    #[test]
    fn a_wrong_family_only_interface_is_af_not_supported() {
        let sys = FakeSys::with(vec![v4_node("eth0", [192, 0, 2, 5])]);

        assert_eq!(
            if2ip_with(
                &sys,
                AddressFamily::Inet6,
                IPV6_SCOPE_GLOBAL,
                0,
                b"eth0"
            ),
            If2IpResult::AfNotSupported
        );
    }

    /// The reverse direction: an IPv6-only interface asked for as IPv4.
    #[test]
    fn an_ipv6_only_interface_asked_for_as_ipv4_is_af_not_supported() {
        let sys = FakeSys::with(vec![v6_node("eth0", "2001:db8::1", 0)]);

        assert_eq!(
            if2ip_with(
                &sys,
                AddressFamily::Inet,
                IPV6_SCOPE_GLOBAL,
                0,
                b"eth0"
            ),
            If2IpResult::AfNotSupported
        );
    }

    /// An interface with no Internet address at all is
    /// `IF2IP_AF_NOT_SUPPORTED`.
    #[test]
    fn an_interface_without_an_internet_address_is_af_not_supported() {
        let sys = FakeSys::with(vec![
            link_node("dummy0"),
            v4_node("eth0", [192, 0, 2, 5]),
        ]);

        assert_eq!(
            if2ip_with(
                &sys,
                AddressFamily::Inet,
                IPV6_SCOPE_GLOBAL,
                0,
                b"dummy0"
            ),
            If2IpResult::AfNotSupported
        );
        // The address walk found no name match, so the name list was
        // consulted: exactly two snapshots, and only in this case.
        assert_eq!(sys.calls(), 2);
    }

    /// A node whose `ifa_addr` was NULL contributes NOTHING, not even the
    /// downgrade (`lib/if2ip.c:111`).
    #[test]
    fn an_address_less_node_contributes_nothing() {
        let sys = FakeSys::with(vec![
            addrless_node("eth0"),
            v4_node("lo", [127, 0, 0, 1]),
        ]);

        assert_eq!(
            if2ip_with(
                &sys,
                AddressFamily::Inet,
                IPV6_SCOPE_GLOBAL,
                0,
                b"eth0"
            ),
            If2IpResult::NotFound
        );
    }

    /// The family-mismatch arm does NOT break, so a later node can still win.
    #[test]
    fn a_wrong_family_node_does_not_stop_the_walk() {
        let sys = FakeSys::with(vec![
            link_node("eth0"),
            v4_node("eth0", [192, 0, 2, 5]),
            v6_node("eth0", "2001:db8::1", 0),
        ]);

        assert_eq!(
            if2ip_with(
                &sys,
                AddressFamily::Inet6,
                IPV6_SCOPE_GLOBAL,
                0,
                b"eth0"
            ),
            If2IpResult::Found("2001:db8::1".to_owned())
        );
        assert_eq!(sys.calls(), 1);
    }

    /// A downgrade already reached is not allowed to mask a later success.
    ///
    /// The complement of the test above, from the `res == IF2IP_NOT_FOUND`
    /// guard's side: the guard exists so a verdict is never *lowered*, and a
    /// `FOUND` reached after any number of downgrades still stands.
    #[test]
    fn a_success_after_several_downgrades_still_stands() {
        let sys = FakeSys::with(vec![
            v4_node("eth0", [192, 0, 2, 5]),
            link_node("eth0"),
            v6_node("eth0", "fe80::1", 3),
            v6_node("eth0", "2001:db8::7", 0),
            v6_node("eth0", "2001:db8::8", 0),
        ]);

        assert_eq!(
            if2ip_with(
                &sys,
                AddressFamily::Inet6,
                IPV6_SCOPE_GLOBAL,
                0,
                b"eth0"
            ),
            If2IpResult::Found("2001:db8::7".to_owned())
        );
    }

    // -- if2ip: IPv6 scope matching ---------------------------------------

    /// `if(ifscope != remote_scope) { ...; continue; }` (`lib/if2ip.c:125-132`)
    /// -- *"global for global, link-local for link-local"*.
    #[test]
    fn a_scope_mismatch_is_af_not_supported() {
        let sys = FakeSys::with(vec![v6_node("eth0", "fe80::1", 0)]);

        assert_eq!(
            if2ip_with(
                &sys,
                AddressFamily::Inet6,
                IPV6_SCOPE_GLOBAL,
                0,
                b"eth0"
            ),
            If2IpResult::AfNotSupported
        );
    }

    /// The same interface satisfies a request whose scope it matches.
    #[test]
    fn a_scope_match_is_found() {
        let sys = FakeSys::with(vec![v6_node("eth0", "fe80::1", 0)]);

        assert_eq!(
            if2ip_with(
                &sys,
                AddressFamily::Inet6,
                IPV6_SCOPE_LINKLOCAL,
                0,
                b"eth0"
            ),
            If2IpResult::Found("fe80::1".to_owned())
        );
    }

    /// Scope selection picks the right address out of several on one
    /// interface.
    ///
    /// The realistic shape: one interface holding a link-local address and a
    /// global one, as nearly every IPv6 interface does. Each request must
    /// reach past the other.
    #[test]
    fn scope_selects_among_several_addresses_of_one_interface() {
        let nodes = vec![
            v6_node("eth0", "fe80::1", 2),
            v6_node("eth0", "fd00::1", 0),
            v6_node("eth0", "2001:db8::1", 0),
        ];

        let sys = FakeSys::with(nodes.clone());
        assert_eq!(
            if2ip_with(
                &sys,
                AddressFamily::Inet6,
                IPV6_SCOPE_LINKLOCAL,
                0,
                b"eth0"
            ),
            If2IpResult::Found("fe80::1%2".to_owned())
        );

        let sys = FakeSys::with(nodes.clone());
        assert_eq!(
            if2ip_with(
                &sys,
                AddressFamily::Inet6,
                IPV6_SCOPE_UNIQUELOCAL,
                0,
                b"eth0"
            ),
            If2IpResult::Found("fd00::1".to_owned())
        );

        let sys = FakeSys::with(nodes);
        assert_eq!(
            if2ip_with(
                &sys,
                AddressFamily::Inet6,
                IPV6_SCOPE_GLOBAL,
                0,
                b"eth0"
            ),
            If2IpResult::Found("2001:db8::1".to_owned())
        );
    }

    // -- if2ip: the scope id ----------------------------------------------

    /// `if(scopeid) curl_msnprintf(scope, sizeof(scope), "%%%u", scopeid);`
    /// (`lib/if2ip.c:149-150`) appended as `"%s%s"` (`:159`).
    ///
    /// The `%%` is printf's escape for one literal per cent, so the suffix is
    /// `%2` and not `%%2`.
    #[test]
    fn a_non_zero_scope_id_becomes_a_percent_suffix() {
        for (scope_id, expected) in [
            (1_u32, "fe80::1%1"),
            (2, "fe80::1%2"),
            (4_294_967_295, "fe80::1%4294967295"),
        ] {
            let sys = FakeSys::with(vec![v6_node("eth0", "fe80::1", scope_id)]);

            let got = if2ip_with(
                &sys,
                AddressFamily::Inet6,
                IPV6_SCOPE_LINKLOCAL,
                0,
                b"eth0",
            );

            assert_eq!(
                found_text(&got),
                expected,
                "scope id {scope_id} must render as a %-suffix"
            );
        }
    }

    /// A zero scope id leaves the suffix empty -- C's `char scope[12] = ""`
    /// (`lib/if2ip.c:116`) untouched.
    #[test]
    fn a_zero_scope_id_adds_no_suffix() {
        let sys = FakeSys::with(vec![v6_node("eth0", "fe80::1", 0)]);

        let got = if2ip_with(
            &sys,
            AddressFamily::Inet6,
            IPV6_SCOPE_LINKLOCAL,
            0,
            b"eth0",
        );

        assert_eq!(found_text(&got), "fe80::1");
        assert!(!found_text(&got).contains('%'));
    }

    /// A ten-digit scope id would have overrun C's twelve-byte buffer's
    /// margin; here nothing can clip.
    #[test]
    fn the_scope_suffix_has_no_width_limit() {
        let sys = FakeSys::with(vec![v6_node("eth0", "fe80::1", u32::MAX)]);

        let got = if2ip_with(
            &sys,
            AddressFamily::Inet6,
            IPV6_SCOPE_LINKLOCAL,
            0,
            b"eth0",
        );

        // A per cent plus ten digits: eleven characters, and C's buffer had
        // exactly twelve bytes including its terminator.
        assert_eq!(found_text(&got), "fe80::1%4294967295");
        assert_eq!(found_text(&got).len() - "fe80::1".len(), 11);
    }

    /// `if(local_scope_id && scopeid != local_scope_id)` (`lib/if2ip.c:142`)
    /// -- *"If given, scope id should match."*
    #[test]
    fn a_local_scope_id_that_differs_is_af_not_supported() {
        let sys = FakeSys::with(vec![v6_node("eth0", "fe80::1", 2)]);

        assert_eq!(
            if2ip_with(
                &sys,
                AddressFamily::Inet6,
                IPV6_SCOPE_LINKLOCAL,
                3,
                b"eth0"
            ),
            If2IpResult::AfNotSupported
        );
    }

    /// A matching `local_scope_id` is accepted, suffix and all.
    #[test]
    fn a_local_scope_id_that_matches_is_found() {
        let sys = FakeSys::with(vec![v6_node("eth0", "fe80::1", 2)]);

        assert_eq!(
            if2ip_with(
                &sys,
                AddressFamily::Inet6,
                IPV6_SCOPE_LINKLOCAL,
                2,
                b"eth0"
            ),
            If2IpResult::Found("fe80::1%2".to_owned())
        );
    }

    /// A zero `local_scope_id` means NO CONSTRAINT, not "must be zero".
    ///
    /// The `local_scope_id &&` that leads C's condition at
    /// `lib/if2ip.c:142` is what makes this so, and reading the condition
    /// without it would reject every scoped address whenever the caller did
    /// not ask for one -- which is the ordinary case.
    #[test]
    fn a_zero_local_scope_id_constrains_nothing() {
        for scope_id in [0_u32, 1, 2, 77, u32::MAX] {
            let sys = FakeSys::with(vec![v6_node("eth0", "fe80::1", scope_id)]);

            let got = if2ip_with(
                &sys,
                AddressFamily::Inet6,
                IPV6_SCOPE_LINKLOCAL,
                0,
                b"eth0",
            );

            assert!(
                matches!(got, If2IpResult::Found(_)),
                "scope id {scope_id} must satisfy an unconstrained request, \
                 got {got:?}"
            );
        }
    }

    /// `local_scope_id` selects among several scoped addresses.
    #[test]
    fn a_local_scope_id_selects_among_scoped_addresses() {
        let sys = FakeSys::with(vec![
            v6_node("eth0", "fe80::1", 2),
            v6_node("eth0", "fe80::2", 3),
        ]);

        assert_eq!(
            if2ip_with(
                &sys,
                AddressFamily::Inet6,
                IPV6_SCOPE_LINKLOCAL,
                3,
                b"eth0"
            ),
            If2IpResult::Found("fe80::2%3".to_owned())
        );
    }

    /// The IPv4 path has no scope handling at all (`lib/if2ip.c:153-156`).
    ///
    /// Neither `remote_scope` nor `local_scope_id` is read, and no suffix is
    /// appended however the seam reported the node's `scope_id` -- a value
    /// that comes from `sin6_scope_id` and has no IPv4 counterpart.
    #[test]
    fn an_ipv4_result_never_carries_a_scope_suffix() {
        let node = IfNode {
            name: b"eth0".to_vec(),
            addr: Some(RawIfAddr::V4([192, 0, 2, 5])),
        };

        for remote_scope in [
            IPV6_SCOPE_GLOBAL,
            IPV6_SCOPE_LINKLOCAL,
            IPV6_SCOPE_SITELOCAL,
            IPV6_SCOPE_UNIQUELOCAL,
            IPV6_SCOPE_NODELOCAL,
        ] {
            for local_scope_id in [0_u32, 1, 9] {
                let sys = FakeSys::with(vec![node.clone()]);

                let got = if2ip_with(
                    &sys,
                    AddressFamily::Inet,
                    remote_scope,
                    local_scope_id,
                    b"eth0",
                );

                assert_eq!(
                    got,
                    If2IpResult::Found("192.0.2.5".to_owned()),
                    "remote_scope {remote_scope}, \
                     local_scope_id {local_scope_id}"
                );
            }
        }
    }

    // -- if2ip: rendering --------------------------------------------------

    /// The address is rendered by `util::inet`, not by `std::net`.
    #[test]
    fn rendering_goes_through_the_curl_formatter() {
        let sys = FakeSys::with(vec![v6_node("eth0", "::192.168.0.1", 0)]);

        // Global, because the `0x0000` arm's OR finds a non-zero byte at
        // b[12] (0xc0).
        let got = if2ip_with(
            &sys,
            AddressFamily::Inet6,
            IPV6_SCOPE_GLOBAL,
            0,
            b"eth0",
        );

        assert_eq!(found_text(&got), "::192.168.0.1");
    }

    /// Zero-run compression is curl's, over a shape that exercises it.
    #[test]
    fn a_compressed_ipv6_address_renders_compressed() {
        let sys =
            FakeSys::with(vec![v6_node("eth0", "2001:db8:0:0:0:0:2:1", 0)]);

        let got = if2ip_with(
            &sys,
            AddressFamily::Inet6,
            IPV6_SCOPE_GLOBAL,
            0,
            b"eth0",
        );

        assert_eq!(found_text(&got), "2001:db8::2:1");
    }

    /// A single zero group is NOT compressed -- `lib/curlx/inet_ntop.c:136-137`
    /// discards a run shorter than two.
    #[test]
    fn a_single_zero_group_is_not_compressed() {
        let sys =
            FakeSys::with(vec![v6_node("eth0", "2001:db8:1:0:2:3:4:5", 0)]);

        let got = if2ip_with(
            &sys,
            AddressFamily::Inet6,
            IPV6_SCOPE_GLOBAL,
            0,
            b"eth0",
        );

        assert_eq!(found_text(&got), "2001:db8:1:0:2:3:4:5");
    }

    // -- if2ip: the remaining family -------------------------------------

    /// A Unix-domain request can never match, and downgrades instead.
    #[test]
    fn a_unix_family_request_never_matches() {
        let sys = FakeSys::with(vec![
            v4_node("eth0", [192, 0, 2, 5]),
            v6_node("eth0", "2001:db8::1", 0),
        ]);

        assert_eq!(
            if2ip_with(
                &sys,
                AddressFamily::Unix,
                IPV6_SCOPE_GLOBAL,
                0,
                b"eth0"
            ),
            If2IpResult::AfNotSupported
        );

        let sys = FakeSys::with(vec![v4_node("lo", [127, 0, 0, 1])]);
        assert_eq!(
            if2ip_with(
                &sys,
                AddressFamily::Unix,
                IPV6_SCOPE_GLOBAL,
                0,
                b"eth0"
            ),
            If2IpResult::NotFound
        );
    }

    /// An empty name matches nothing, and does not panic.
    ///
    /// `casecompare` compares lengths first, so an empty request can only
    /// equal an empty interface name -- which no kernel produces.
    #[test]
    fn an_empty_name_matches_nothing() {
        let sys = FakeSys::with(vec![
            v4_node("eth0", [192, 0, 2, 5]),
            link_node("eth0"),
        ]);

        assert_eq!(
            if2ip_with(&sys, AddressFamily::Inet, IPV6_SCOPE_GLOBAL, 0, b""),
            If2IpResult::NotFound
        );
    }

    /// A name that is a prefix of an interface's name does not match.
    ///
    /// `casecompare` is whole-string equality including length
    /// (`lib/strequal.c:44-48`), not a prefix test, so `--interface eth`
    /// must not bind to `eth0`.
    #[test]
    fn a_prefix_of_an_interface_name_does_not_match() {
        let sys = FakeSys::with(vec![v4_node("eth0", [192, 0, 2, 5])]);

        for requested in [&b"eth"[..], b"eth00", b"th0", b"0"] {
            assert_eq!(
                if2ip_with(
                    &sys,
                    AddressFamily::Inet,
                    IPV6_SCOPE_GLOBAL,
                    0,
                    requested
                ),
                If2IpResult::NotFound,
                "{requested:?} must not match eth0"
            );
        }
    }

    // -- the one host-dependent test --------------------------------------

    /// The real seam, against the loopback interface only.
    #[test]
    #[cfg_attr(miri, ignore = "getifaddrs(3) is a foreign function")]
    fn the_real_seam_agrees_about_the_loopback_interface() {
        // Linux names it `lo`; Darwin names it `lo0`. Only the NAME differs,
        // which is why this is the one `cfg` in the file.
        #[cfg(target_os = "linux")]
        let name: &[u8] = b"lo";
        #[cfg(not(target_os = "linux"))]
        let name: &[u8] = b"lo0";

        let got = super::if2ip(AddressFamily::Inet, IPV6_SCOPE_GLOBAL, 0, name);

        match got {
            If2IpResult::Found(text) => {
                let parsed: Result<Ipv4Addr, _> = text.parse();
                assert!(
                    parsed.is_ok(),
                    "the real seam rendered {text:?}, which is not an IPv4 \
                     address"
                );
            }
            // Both are legitimate on a host without a loopback interface, or
            // with one that has no IPv4 address. Neither is a defect here.
            If2IpResult::NotFound | If2IpResult::AfNotSupported => {}
        }
    }

    /// The real entry point and the injected one agree on the real host.
    #[test]
    #[cfg_attr(miri, ignore = "getifaddrs(3) is a foreign function")]
    fn the_public_entry_point_delegates_to_the_seam() {
        for name in [&b"lo"[..], b"lo0", b"eth0", b"no-such-interface"] {
            let direct =
                super::if2ip(AddressFamily::Inet, IPV6_SCOPE_GLOBAL, 0, name);
            let injected = if2ip_with(
                &RealSys,
                AddressFamily::Inet,
                IPV6_SCOPE_GLOBAL,
                0,
                name,
            );

            assert_eq!(direct, injected, "{name:?}");
        }
    }
}
