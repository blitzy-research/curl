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

//! FTP and FTPS.
//!
//! Supersedes `lib/ftp.c` (command sequencing), `lib/pingpong.c` (the
//! request/response cadence shared with the stubbed SMTP, IMAP and POP3
//! schemes) and `lib/ftplistparser.c` with `lib/fileinfo.c` (directory-listing
//! parsing and `curl_fileinfo` population) -- the four C files AAP section
//! 0.4.1 maps onto this directory's three modules.
//!
//! FTPS needs no separate module and no separate feature: it is this protocol
//! over the crate's unconditional TLS stack, reached by inserting a TLS filter
//! into the chain `crate::conn` owns, which is why the `ftp` capability has no
//! exclusive external dependency.
//!
//! # The bytes are the specification
//!
//! Command sequencing is byte-exact in both directions. 257 fixtures name the
//! `ftp` server and 9 name `ftps`, and their `<protocol>` blocks are compared
//! as a single joined string -- every command, its argument spelling and its
//! order are part of the expectation, not an implementation detail. That is why
//! the sequencing is transcribed from the C rather than reconstructed from the
//! RFCs, which permit sequences curl does not emit.
//!
//! # Partially delivered
//!
//! Two of this directory's three modules exist: [`listparser`] and
//! [`pingpong`]. The protocol engine itself (`lib/ftp.c`) -- the command
//! sequencing, the state machine and the `Protocol` implementation -- arrives
//! with its own file, and it is what will implement
//! [`pingpong::PingPongOps`] and [`pingpong::PingPongIo`] and turn the cadence
//! engine into a working scheme. Until it does, no FTP transfer can be
//! attempted and `crate::version` withholds the `ftp` protocol from the
//! `Protocols:` banner, so the fixtures that target it skip rather than fail.
//! This file is the module root and declares exactly the children that exist,
//! per the crate convention recorded in `curl-rs-lib/src/lib.rs`.
//!
//! `pub(crate)`, and so is everything it declares: no exported symbol of
//! `lib/libcurl.def` is backed from this directory. The listing parser's
//! results reach a caller through the chunk callbacks configured on an easy
//! handle, and the `struct curl_fileinfo` those callbacks receive is the
//! C-layout mirror owned by `curl-rs-ffi`, never a type from here.

/// Directory-listing parsing for wildcard downloading -- supersedes
/// `lib/ftplistparser.c` with `lib/ftplistparser.h` and `lib/fileinfo.c` with
/// `lib/fileinfo.h`.
///
/// It owns the crate-private, memory-safe `FileInfo` that wildcard processing
/// uses internally -- owned data, no pointer into a shared buffer -- and the
/// incremental parser the C installs as the transfer's write callback for the
/// duration of `LIST`. The C-layout ABI mirror of `struct curl_fileinfo`
/// belongs to `curl-rs-ffi` and is deliberately not duplicated here.
///
/// No `#[allow(dead_code)]` on this declaration, deliberately: the allowances
/// belong on the ITEMS whose consumers have yet to land, so that an item added
/// later with no consumer is still reported.
pub(crate) mod listparser;

/// The request/response cadence -- supersedes `lib/pingpong.c` with
/// `lib/pingpong.h`.
///
/// The non-blocking command writer, the reply-line framer, the per-response
/// timeout and the readiness loop that drives an FTP state machine one reply at
/// a time. It owns the two bytes that terminate every command, and it hands
/// every complete reply line on with its LF intact.
///
/// It lives here rather than beside `lib/`'s other utilities because FTP is its
/// only possible consumer: the C compiles the mechanism in for FTP, IMAP, POP3
/// and SMTP, and specification 0.2.2 excludes the other three from
/// implementation. Nothing in it is FTP-specific for all that -- deciding which
/// line ends a reply is the callback the protocol module implements.
///
/// The same allowance policy as [`listparser`]: per-item, never on this
/// declaration.
pub(crate) mod pingpong;
