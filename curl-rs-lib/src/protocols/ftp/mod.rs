// /***************************************************************************
//  *                                  _   _ ____  _
//  *  Project                     ___| | | |  _ \| |
//  *                             / __| | | | |_) | |
//  *                            | (__| |_| |  _ <| |___
//  *                             \___|\___/|_| \_\_____|
//  *
//  * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//  *
//  * This software is licensed as described in the file COPYING, which
//  * you should have received as part of this distribution. The terms
//  * are also available at https://curl.se/docs/copyright.html.
//  *
//  * You may opt to use, copy, modify, merge, publish, distribute and/or sell
//  * copies of the Software, and permit persons to whom the Software is
//  * furnished to do so, under the terms of the COPYING file.
//  *
//  * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
//  * KIND, either express or implied.
//  *
//  * SPDX-License-Identifier: curl
//  *
//  ***************************************************************************/
//! FTP and FTPS -- the protocol engine.
//!
//! Supersedes `lib/ftp.c` (4,380 lines) and `lib/ftp.h` (173 lines). The two
//! sibling modules carry the mechanisms FTP composes: [`pingpong`] is
//! `lib/pingpong.c`'s request/response cadence and [`listparser`] is
//! `lib/ftplistparser.c` with `lib/fileinfo.c`. Nothing else was split out --
//! the wildcard driver, the command sequencing and the two data-channel modes
//! all live here, as they do in the C.
//!
//! # What each region of the C became
//!
//! * `lib/ftp.c:88-151` -- the 37 state names, `FTP_CSTATE` and the single
//!   state mutator; [`FtpState`], [`FTP_STATE_NAMES`] and
//!   [`FtpConnState::set_state`].
//! * `:196-337` -- `ftp_parse_url_path`; [`FtpConnState::parse_url_path`].
//! * `:425-575` -- `ftp_check_ctrl_on_data_wait` and `ftp_initiate_transfer`.
//! * `:575-620` -- `ftp_endofresp` and `ftp_readresp`, including the 421 rule
//!   that holds wherever the reply arrives.
//! * `:620-735` -- `getftpresponse`, the blocking full-response read.
//! * `:739-800` -- `ftp_state_user`, `ftp_state_pwd`, `ftp_pollset` and
//!   `ftp_domore_pollset`.
//! * `:800-1265` -- `ftp_state_cwd` and `ftp_state_use_port`, the active mode.
//! * `:1272-1456` -- `ftp_state_use_pasv`, `ftp_state_prepare_transfer`,
//!   `ftp_state_rest`, `ftp_state_size` and `ftp_state_list`.
//! * `:1456-1840` -- MDTM, TYPE, the upload setup, `ftp_state_retr` and the
//!   five quote lists.
//! * `:1916-2355` -- `ftp_state_pasv_resp`, `ftp_do_more` and
//!   `ftp_state_port_resp`.
//! * `:2400-2790` -- the MDTM, TYPE, SIZE, REST, STOR and LIST/RETR replies.
//! * `:2800-3364` -- login, FTPS negotiation and the exhaustive reply
//!   dispatcher.
//! * `:3490-3774` -- `ftp_done`, `ftp_nb_type` and `ftp_perform`.
//! * `:3776-4007` -- `init_wc_data` and `wc_statemach`, the wildcard driver.
//! * `:4055-4177` -- `ftp_do`, `ftp_quit`, `ftp_disconnect` and `ftp_doing`.
//! * `:4255-4380` -- `ftp_setup_connection`, `ftp_conns_match`,
//!   `Curl_protocol_ftp` and the two scheme rows.
//! * `lib/ftp.h:41-80` -- the state enumeration; `:95-100` --
//!   `curl_ftpfile`; `:102-169` -- `struct FTP`, `struct pathcomp` and
//!   `struct ftp_conn`.
//!
//! Three contracts outside this file's own sources are consumed rather than
//! restated: `lib/url.c:1016-1034` reaches [`ftp_conns_match`] when the
//! connection pool considers a candidate, `lib/curl_trc.c:294,408,516` owns the
//! `FTP` trace feature and the `FTP_ACCEPT` timer this module arms, and
//! `lib/urldata.h:126-127,421-422,526-558` owns the timeout, socket-index and
//! per-scheme option vocabularies.
//!
//! # The state count is 37, measured
//!
//! An earlier reading of this enumeration reported 36 states. **It carries
//! 37**, `FTP_STOP` through `FTP_QUIT`, and `FTP_LAST` is a sentinel the C
//! marks *"never used"* rather than a state. Counted twice from independent
//! places: `lib/ftp.h:41-80` declares 37 named constants before `FTP_LAST`,
//! and `lib/ftp.c:88-126` initialises `ftp_state_names[]` with 37 strings. The
//! correction is recorded here because the two counts differ by exactly the
//! sentinel, which is the mistake it invites: indexing the name table with
//! `FTP_LAST` reads one past the end. [`FTP_LAST`] is therefore a checked
//! boundary that can never become the live state, and
//! [`FtpState::VARIANTS`] holds 37 entries.
//!
//! # The bytes are the specification
//!
//! 257 fixtures name the `ftp` server and 9 name `ftps`, and
//! `tests/getpart.pm:351` joins both sides of a `<protocol>` block into one
//! string before comparing, so command spelling, argument text, order and the
//! terminating CRLF are all part of the expectation. The sequences this module
//! emits were transcribed from the C rather than rebuilt from the RFCs, which
//! permit orders curl does not use. The measured shapes the tests below pin
//! include `tests/data/test1003` (a passive binary GET: `USER`, `PASS`, `PWD`,
//! `CWD`, `EPSV`, `TYPE I`, `SIZE`, `RETR`, `QUIT` -- note `EPSV` BEFORE
//! `TYPE`), `test100` (`TYPE A` then `LIST`), `test101` (active `PORT`),
//! `test102` (`EPSV` refused, then `PASV`), `test104` and `test141`
//! (`--head`: `MDTM`, `TYPE I`, `SIZE`, `REST 0`), `test105` (`--use-ascii`
//! skips `SIZE`), `test400`, `test401` and `test403` (`PBSZ 0`, `PROT C`,
//! `CCC`), `test402` (`AUTH SSL` then `AUTH TLS`), `test1107` (`PRET RETR`),
//! and `test574` with `test1113` (wildcard: one `LIST`, then `RETR` per match).
//!
//! # Safety and layering
//!
//! Memory-safe Rust throughout: no operating-system call and no C-layout
//! declaration appears here, because the C-layout ABI lives in `curl-rs-ffi`
//! and the platform calls live behind the seams below. TLS is never reached
//! directly either -- this module does not name `crate::tls` at all. FTPS asks
//! `crate::conn` to insert a filter on the control channel and to remove it
//! again for `CCC`, which is why explicit and implicit FTPS need no code of
//! their own beyond the commands that negotiate them.
//!
//! # Why the items below carry `#[allow(dead_code)]`
//!
//! The engine is complete and its unit suite drives every part of it, but no
//! caller outside this module reaches it yet, so the compiler's reachability
//! analysis reports the whole graph as unused. Two wiring points are still
//! owned by other files:
//!
//! * `protocols/mod.rs` holds the `ftp` and `ftps` rows with `run: None`
//!   (`:1050-1051`) and installs [`SCHEMES`] when it lands the handler column;
//! * the seven asynchronous [`Protocol`] slots receive a [`TransferCtx`], which
//!   carries the filter chains, the clock, the scheme and the socket index and
//!   nothing else. Building an [`FtpSession`] additionally needs an
//!   [`FtpClient`] and an [`FtpSeams`], both of which the easy handle supplies,
//!   so the slots report [`CURLcode::NotBuiltIn`] until `easy/` can hand them
//!   over -- the shape `protocols/sftp.rs` and `protocols/file.rs` already
//!   carry.
//!
//! The allowance therefore sits per ITEM with the consumer named, never on the
//! module or on either child declaration, exactly as `ftp/pingpong.rs`,
//! `ftp/listparser.rs` and `protocols/sftp.rs` do it. An item added later with
//! no consumer at all is still reported, which is the property a blanket
//! `#![allow(dead_code)]` would destroy.

/// Directory-listing parsing for wildcard downloading -- supersedes
/// `lib/ftplistparser.c` with `lib/ftplistparser.h` and `lib/fileinfo.c` with
/// `lib/fileinfo.h`.
///
/// It owns the crate-private, memory-safe `FileInfo` that wildcard processing
/// uses internally -- owned data, no pointer into a shared buffer -- and the
/// incremental parser the C installs as the transfer's write callback for the
/// duration of `LIST`. The C-layout mirror of `struct curl_fileinfo` belongs
/// to `curl-rs-ffi` and is deliberately not duplicated here.
///
/// The eight wildcard states, the two chunk-callback vocabularies and the
/// file-info flags are all consumed FROM here by the driver below; none is
/// redeclared.
pub(crate) mod listparser;

/// The request/response cadence -- supersedes `lib/pingpong.c` with
/// `lib/pingpong.h`.
///
/// The non-blocking command writer, the reply-line framer, the per-response
/// timeout and the readiness loop that drives this file's state machine one
/// reply at a time. It owns the two bytes that terminate every command, and it
/// hands every complete reply line on with its LF intact.
///
/// It lives here rather than beside `lib/`'s other utilities because FTP is its
/// only possible consumer: the C compiles the mechanism in for FTP, IMAP, POP3
/// and SMTP, and specification 0.2.2 excludes the other three from
/// implementation. Nothing in it is FTP-specific for all that -- deciding which
/// line ends a reply is [`FtpMachine::end_of_response`], implemented here.
pub(crate) mod pingpong;

use core::fmt;
use core::ops::Range;

use crate::conn::filters::{CallCtx, FilterChains, SocketIndex};
use crate::conn::select::{
    EasyPollset, PollAction, Socket, CURL_CSELECT_IN, CURL_SOCKET_BAD,
};
use crate::dns::if2ip::If2IpResult;
use crate::error::{CURLcode, CodeResult, CurlResult, Error};
use crate::protocols::ftp::listparser::{
    ChunkBgn, ChunkEnd, FileInfo, FileType, FtpWildcard, WildcardData,
    WildcardState, WriteBackup,
};
use crate::protocols::ftp::pingpong::{
    ConnAccess, PingPong, PingPongIo, PingPongOps, PpResponse, PpTransfer,
};
use crate::protocols::{
    Proto, ProtoFuture, Protocol, Scheme, TransferCtx, FLAGS_FTP, FLAGS_FTPS,
    PORT_FTP, PORT_FTPS,
};
use crate::trace::{InfoType, TimerId};
use crate::transfer::sendf::ClientWriteFlags;
use crate::transfer::{DoMoreStep, TimeCondition};
use crate::url::escape::{urldecode, UrlReject};
use crate::util::inet::{ntop4, ntop6, pton6};
use crate::util::parsedate::getdate_capped;
use crate::util::range::parse as range_parse;
use crate::util::strcase::{casecompare, timestrcmp};
use crate::util::strparse::{str_number, str_single};
use crate::util::timediff::TimeDiff;
use crate::util::timeval::{timediff_ms, Clock, CurlTime};

// The state machine's vocabulary

/// One step of the FTP command sequence -- `enum { FTP_STOP, ... }`
/// (`lib/ftp.h:41-80`).
///
/// Every discriminant is written out. The C takes them from declaration order
/// and the trace table is indexed by them, so a reordering would silently
/// rename every state in the log and change which arm of the dispatcher a
/// reply reached. `FTP_LAST` is NOT a variant: see [`FTP_LAST`].
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
pub(crate) enum FtpState {
    /// `FTP_STOP` -- *"do nothing state, stops the state machine"*, and the
    /// zero value a freshly allocated connection starts in.
    #[default]
    Stop = 0,
    /// `FTP_WAIT220` -- *"waiting for the initial 220 response immediately
    /// after a connect"*.
    Wait220 = 1,
    /// `FTP_AUTH` -- an `AUTH SSL` or `AUTH TLS` is outstanding.
    Auth = 2,
    /// `FTP_USER`.
    User = 3,
    /// `FTP_PASS`.
    Pass = 4,
    /// `FTP_ACCT`.
    Acct = 5,
    /// `FTP_PBSZ`.
    Pbsz = 6,
    /// `FTP_PROT`.
    Prot = 7,
    /// `FTP_CCC`.
    Ccc = 8,
    /// `FTP_PWD`.
    Pwd = 9,
    /// `FTP_SYST`.
    Syst = 10,
    /// `FTP_NAMEFMT`.
    NameFmt = 11,
    /// `FTP_QUOTE` -- *"waiting for a response to a command sent in a quote
    /// list"*.
    Quote = 12,
    /// `FTP_RETR_PREQUOTE`.
    RetrPrequote = 13,
    /// `FTP_STOR_PREQUOTE`.
    StorPrequote = 14,
    /// `FTP_LIST_PREQUOTE`.
    ListPrequote = 15,
    /// `FTP_POSTQUOTE`.
    Postquote = 16,
    /// `FTP_CWD` -- change directory.
    Cwd = 17,
    /// `FTP_MKD` -- *"if the directory did not exist"*.
    Mkd = 18,
    /// `FTP_MDTM` -- *"to figure out the datestamp"*.
    Mdtm = 19,
    /// `FTP_TYPE` -- *"to set type when doing a head-like request"*.
    Type = 20,
    /// `FTP_LIST_TYPE` -- *"set type when about to do a directory list"*.
    ListType = 21,
    /// `FTP_RETR_LIST_TYPE`.
    RetrListType = 22,
    /// `FTP_RETR_TYPE` -- *"set type when about to RETR a file"*.
    RetrType = 23,
    /// `FTP_STOR_TYPE` -- *"set type when about to STOR a file"*.
    StorType = 24,
    /// `FTP_SIZE` -- *"get the remote file's size for head-like request"*.
    Size = 25,
    /// `FTP_RETR_SIZE`.
    RetrSize = 26,
    /// `FTP_STOR_SIZE`.
    StorSize = 27,
    /// `FTP_REST` -- *"when used to check if the server supports it in
    /// head-like"*.
    Rest = 28,
    /// `FTP_RETR_REST` -- *"when asking for "resume" in for RETR"*.
    RetrRest = 29,
    /// `FTP_PORT` -- *"generic state for PORT, LPRT and EPRT, check count1"*.
    Port = 30,
    /// `FTP_PRET` -- *"generic state for PRET RETR, PRET STOR and PRET
    /// LIST/NLST"*.
    Pret = 31,
    /// `FTP_PASV` -- *"generic state for PASV and EPSV, check count1"*.
    Pasv = 32,
    /// `FTP_LIST` -- *"generic state for LIST, NLST or a custom list
    /// command"*.
    List = 33,
    /// `FTP_RETR`.
    Retr = 34,
    /// `FTP_STOR` -- *"generic state for STOR and APPE"*.
    Stor = 35,
    /// `FTP_QUIT`.
    Quit = 36,
}

/// The trace names, `ftp_state_names[]` (`lib/ftp.c:88-126`).
///
/// `#[rustfmt::skip]` because these strings appear verbatim in `--trace-ids`
/// output and in the `[%s] -> [%s]` transition line: they are observable text,
/// not layout. Indexed by [`FtpState`]'s discriminant, and 37 entries long --
/// one per real state and none for the sentinel.
#[rustfmt::skip]
pub(crate) const FTP_STATE_NAMES: [&str; 37] = [
    "STOP",           "WAIT220",        "AUTH",           "USER",
    "PASS",           "ACCT",           "PBSZ",           "PROT",
    "CCC",            "PWD",            "SYST",           "NAMEFMT",
    "QUOTE",          "RETR_PREQUOTE",  "STOR_PREQUOTE",  "LIST_PREQUOTE",
    "POSTQUOTE",      "CWD",            "MKD",            "MDTM",
    "TYPE",           "LIST_TYPE",      "RETR_LIST_TYPE", "RETR_TYPE",
    "STOR_TYPE",      "SIZE",           "RETR_SIZE",      "STOR_SIZE",
    "REST",           "RETR_REST",      "PORT",           "PRET",
    "PASV",           "LIST",           "RETR",           "STOR",
    "QUIT",
];

/// `FTP_LAST`, the C's *"never used"* sentinel (`lib/ftp.h:80`).
///
/// It exists to bound the enumeration and is deliberately NOT a [`FtpState`]
/// variant: the live state can never hold it, so the name table can never be
/// indexed out of range. Declared as the integer the C's `enum` would give it,
/// which is one past the last real state.
#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
pub(crate) const FTP_LAST: u8 = 37;

/// What the trace renders for a state -- `FTP_CSTATE(ftpc)`
/// (`lib/ftp.c:126`).
///
/// The C's macro answers `"???"` for a missing connection, which is what
/// [`None`] means here. An out-of-range integer cannot arise from a
/// [`FtpState`], and the checked lookup is kept anyway so that a future
/// numeric round-trip cannot reintroduce the read past the end.
pub(crate) fn cstate(state: Option<FtpState>) -> &'static str {
    match state {
        Some(live) => state_name(live),
        None => "???",
    }
}

/// One state's trace name, looked up rather than matched.
///
/// Total by construction: every discriminant is below 37 and the table has 37
/// entries, and the fallback is unreachable in practice while keeping the
/// lookup free of indexing that could panic.
pub(crate) fn state_name(state: FtpState) -> &'static str {
    match FTP_STATE_NAMES.get(state as usize) {
        Some(name) => name,
        None => "???",
    }
}

#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
impl FtpState {
    /// Every real state, in declaration order.
    #[rustfmt::skip]
    pub(crate) const VARIANTS: [Self; 37] = [
        Self::Stop,         Self::Wait220,      Self::Auth,
        Self::User,         Self::Pass,         Self::Acct,
        Self::Pbsz,         Self::Prot,         Self::Ccc,
        Self::Pwd,          Self::Syst,         Self::NameFmt,
        Self::Quote,        Self::RetrPrequote, Self::StorPrequote,
        Self::ListPrequote, Self::Postquote,    Self::Cwd,
        Self::Mkd,          Self::Mdtm,         Self::Type,
        Self::ListType,     Self::RetrListType, Self::RetrType,
        Self::StorType,     Self::Size,         Self::RetrSize,
        Self::StorSize,     Self::Rest,         Self::RetrRest,
        Self::Port,         Self::Pret,         Self::Pasv,
        Self::List,         Self::Retr,         Self::Stor,
        Self::Quit,
    ];

    /// This state's integer, the value the C's `ftpstate` byte holds.
    pub(crate) const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Whether this is one of the five states that await a quote list's reply.
    ///
    /// The dispatcher groups them, and so does `ftp_state_quote`'s selection of
    /// WHICH list to walk, so the membership is stated once.
    pub(crate) const fn is_quote_state(self) -> bool {
        matches!(
            self,
            Self::Quote
                | Self::RetrPrequote
                | Self::StorPrequote
                | Self::ListPrequote
                | Self::Postquote
        )
    }
}

impl fmt::Display for FtpState {
    /// The trace name, so a transition line can be assembled with `{}`.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(state_name(*self))
    }
}

/// How much of the URL path becomes `CWD` commands -- `curl_ftpfile`
/// (`lib/ftp.h:95-100`).
///
/// The integers are pinned because `CURLOPT_FTP_FILEMETHOD` is a public option
/// and an application passes them as longs.
// The three names are `CURLOPT_FTP_FILEMETHOD`'s own -- `FTPFILE_MULTICWD`,
// `FTPFILE_NOCWD` and `FTPFILE_SINGLECWD` at `include/curl/curl.h` -- and the
// shared postfix is what the option is about, so `clippy::enum_variant_names` is
// allowed rather than obeyed: renaming them would put a second vocabulary
// between a reader and the public option. `auth/negotiate.rs:201` refuses the
// same trade for the same reason.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[allow(dead_code, clippy::enum_variant_names)] // consumer: the phase drivers
pub(crate) enum FileMethod {
    /// `FTPFILE_MULTICWD = 1` -- *"as defined by RFC1738"*, one `CWD` per
    /// path component. The C's `default:` arm as well as its named case.
    #[default]
    MultiCwd = 1,
    /// `FTPFILE_NOCWD = 2` -- *"use SIZE / RETR / STOR on the full path"*.
    NoCwd = 2,
    /// `FTPFILE_SINGLECWD = 3` -- *"make one CWD, then SIZE / RETR / STOR on
    /// the file"*.
    SingleCwd = 3,
}

#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
impl FileMethod {
    /// Every method, in declaration order.
    pub(crate) const VARIANTS: [Self; 3] =
        [Self::MultiCwd, Self::NoCwd, Self::SingleCwd];

    /// The option value an application sets.
    pub(crate) const fn as_u8(self) -> u8 {
        self as u8
    }

    /// The C's `switch` on `data->set.ftp_filemethod`, whose `default:` shares
    /// its body with `FTPFILE_MULTICWD`.
    pub(crate) const fn from_u8(raw: u8) -> Self {
        match raw {
            2 => Self::NoCwd,
            3 => Self::SingleCwd,
            _ => Self::MultiCwd,
        }
    }
}

/// `FTP_MAX_DIR_DEPTH` (`lib/ftp.c:193`): the depth at which a path is
/// *"suspiciously deep"* and refused.
///
/// The C tests `dirAlloc >= FTP_MAX_DIR_DEPTH` against the SLASH COUNT before
/// allocating, so a path with exactly 1000 slashes is already refused.
#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
pub(crate) const FTP_MAX_DIR_DEPTH: usize = 1000;

/// `DEFAULT_ACCEPT_TIMEOUT` (`lib/ftp.h:171`): *"milliseconds == one
/// minute"*, the wait for a server to connect back in active mode.
pub(crate) const DEFAULT_ACCEPT_TIMEOUT: TimeDiff = 60_000;

/// Which active-mode command is being tried -- `ftpport` (`lib/ftp.c:868`).
///
/// The order is the fallback order: `EPRT` first, `PORT` second, and `DONE`
/// past the end. `ftp_state_port_resp` increments through it, which is why the
/// integers are written out.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum FtpPortCmd {
    /// `EPRT` -- RFC 2428, and the first attempt.
    Eprt = 0,
    /// `PORT` -- RFC 959, IPv4 only.
    Port = 1,
    /// `DONE` -- past the last command; nothing left to try.
    Done = 2,
}

#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
impl FtpPortCmd {
    /// Every value, in declaration order.
    pub(crate) const VARIANTS: [Self; 3] = [Self::Eprt, Self::Port, Self::Done];

    /// The integer stored in `ftpc->count1`.
    pub(crate) const fn as_u8(self) -> u8 {
        self as u8
    }

    /// `fcmd++`: the next command to try.
    pub(crate) const fn next(self) -> Self {
        match self {
            Self::Eprt => Self::Port,
            Self::Port | Self::Done => Self::Done,
        }
    }

    /// `(ftpport)ftpc->count1`, checked.
    pub(crate) const fn from_i32(raw: i32) -> Self {
        match raw {
            0 => Self::Eprt,
            1 => Self::Port,
            _ => Self::Done,
        }
    }

    /// This command's wire spelling, or [`None`] for [`Self::Done`], which is
    /// not a command.
    pub(crate) fn word(self) -> Option<&'static str> {
        match self {
            Self::Eprt | Self::Port => {
                FTP_PORT_MODES.get(self as usize).copied()
            }
            Self::Done => None,
        }
    }
}

/// `static const char mode[][5] = { "EPRT", "PORT" }` (`lib/ftp.c:889`).
///
/// `#[rustfmt::skip]`: wire text.
#[rustfmt::skip]
pub(crate) const FTP_PORT_MODES: [&str; 2] = ["EPRT", "PORT"];

/// `static const char mode[][5] = { "EPSV", "PASV" }` (`lib/ftp.c:1291`).
///
/// Selected by `ftpc->count1`, which is the offset rather than a flag: 0 is
/// `EPSV` and 1 is `PASV`, and `ftp_state_pasv_resp` reads it back to decide
/// which reply format to parse.
#[rustfmt::skip]
pub(crate) const FTP_PASSIVE_MODES: [&str; 2] = ["EPSV", "PASV"];

/// `static const char * const ftpauth[] = { "SSL", "TLS" }`
/// (`lib/ftp.c:2998`).
///
/// The argument to `AUTH`. `CURLFTPAUTH_DEFAULT` and `CURLFTPAUTH_SSL` start at
/// index 0 and step forward; `CURLFTPAUTH_TLS` starts at index 1 and steps
/// back. One retry only.
#[rustfmt::skip]
pub(crate) const FTP_AUTH_MODES: [&str; 2] = ["SSL", "TLS"];

/// `CURLOPT_FTPSSLAUTH`'s value, as the C reads it.
///
/// A newtype rather than an enum because the C's `default:` arm reports the
/// integer it was given -- *"unsupported parameter to CURLOPT_FTPSSLAUTH:
/// %d"* -- so an unknown value must survive as data long enough to be printed.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub(crate) struct FtpSslAuth(pub(crate) i32);

#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
impl FtpSslAuth {
    /// `CURLFTPAUTH_DEFAULT` -- try `SSL` first.
    pub(crate) const DEFAULT: Self = Self(0);
    /// `CURLFTPAUTH_SSL` -- try `SSL` first, explicitly.
    pub(crate) const SSL: Self = Self(1);
    /// `CURLFTPAUTH_TLS` -- try `TLS` first.
    pub(crate) const TLS: Self = Self(2);

    /// The `(start, step)` pair the C computes into `count1` and `count2`, or
    /// [`None`] for a value it refuses.
    pub(crate) const fn attempt_order(self) -> Option<(i32, i32)> {
        match self.0 {
            0 | 1 => Some((0, 1)),
            2 => Some((1, -1)),
            _ => None,
        }
    }
}

/// `CURLOPT_USE_SSL`'s four levels -- `curl_usessl` (`include/curl/curl.h`).
///
/// Ordered, and the order is load-bearing: the C compares with `<=` and `>` to
/// decide whether a refused `AUTH` or a refused `PROT` is fatal.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
pub(crate) enum UseSsl {
    /// `CURLUSESSL_NONE` -- plain FTP; do not attempt `AUTH`.
    #[default]
    None = 0,
    /// `CURLUSESSL_TRY` -- attempt it, and continue in the clear if refused.
    Try = 1,
    /// `CURLUSESSL_CONTROL` -- the control channel must be secure; the data
    /// channel need not be, which is what makes `PROT C` reachable.
    Control = 2,
    /// `CURLUSESSL_ALL` -- both channels must be secure.
    All = 3,
}

#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
impl UseSsl {
    /// Every level, in declaration order.
    pub(crate) const VARIANTS: [Self; 4] =
        [Self::None, Self::Try, Self::Control, Self::All];

    /// The option value.
    pub(crate) const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Whether any TLS is wanted at all -- the C's `if(data->set.use_ssl)`.
    pub(crate) const fn wants_tls(self) -> bool {
        !matches!(self, Self::None)
    }

    /// The `PROT` argument: `C` for control-only, `P` otherwise
    /// (`lib/ftp.c:3131-3133`).
    pub(crate) const fn prot_level(self) -> u8 {
        match self {
            Self::Control => b'C',
            _ => b'P',
        }
    }
}

/// `CURLOPT_FTP_SSL_CCC`'s levels -- `curl_ftpccc`.
///
/// `CCC` is sent for either non-`None` level; the level decides only whether
/// the shutdown is sent actively or waited for passively.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
pub(crate) enum CccMode {
    /// `CURLFTPSSL_CCC_NONE` -- do not clear the command channel.
    #[default]
    None = 0,
    /// `CURLFTPSSL_CCC_PASSIVE` -- *"Do not initiate the shutdown, but wait
    /// for the server to do it"*.
    Passive = 1,
    /// `CURLFTPSSL_CCC_ACTIVE` -- *"Initiate the shutdown"*.
    Active = 2,
}

#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
impl CccMode {
    /// Every level, in declaration order.
    pub(crate) const VARIANTS: [Self; 3] =
        [Self::None, Self::Passive, Self::Active];

    /// The option value.
    pub(crate) const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Whether `CCC` is to be sent at all -- the C's `if(data->set.ftp_ccc)`.
    pub(crate) const fn requested(self) -> bool {
        !matches!(self, Self::None)
    }

    /// The C's `data->set.ftp_ccc == CURLFTPSSL_CCC_ACTIVE` argument to the
    /// filter removal: whether to send our own shutdown.
    pub(crate) const fn shuts_down_actively(self) -> bool {
        matches!(self, Self::Active)
    }
}

// Per-transfer and per-connection state

/// One path component of the decoded path -- `struct pathcomp`
/// (`lib/ftp.h:117-120`).
///
/// The C stores a start column and a length into `ftpc->rawpath`; this stores
/// the same pair and hands out a checked [`Range`], so a component can only be
/// read through a bounds-checked slice of the one buffer that owns the bytes.
/// No self-referential pointer survives, which is what lets the state move.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub(crate) struct PathComp {
    /// `start` -- the byte offset of the component's first byte.
    pub(crate) start: usize,
    /// `len` -- the component's length in bytes.
    pub(crate) len: usize,
}

impl PathComp {
    /// The half-open range this component occupies.
    pub(crate) const fn range(self) -> Range<usize> {
        self.start..self.start.saturating_add(self.len)
    }
}

/// The per-transfer state -- `struct FTP` (`lib/ftp.h:106-114`).
///
/// The C's `path` points either into `data->state.up.path` or at its own
/// `pathalloc`; both spellings are one owned buffer here, with `pathalloc`
/// recording the wildcard driver's override so that the URL's own path survives
/// underneath it.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct FtpTransfer {
    /// The URL's path with the leading slash removed --
    /// `ftp->path = &data->state.up.path[1]` (`lib/ftp.c:4326`).
    url_path: Vec<u8>,
    /// `pathalloc` -- the wildcard driver's `"%s%s"` concatenation of the
    /// wildcard directory and the current filename, when one is in force.
    pathalloc: Option<Vec<u8>>,
    /// `transfer` -- whether a body, only headers, or nothing at all is to
    /// move.
    pub(crate) transfer: PpTransfer,
    /// `downloadsize` -- what `RETR` is expected to deliver, or `-1` when
    /// unknown.
    pub(crate) downloadsize: i64,
}

#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
impl FtpTransfer {
    /// A transfer over `path`, which is the URL path WITHOUT its leading
    /// slash.
    pub(crate) fn new(path: &[u8]) -> Self {
        Self {
            url_path: path.to_vec(),
            pathalloc: None,
            transfer: PpTransfer::Body,
            downloadsize: 0,
        }
    }

    /// `ftp->path` -- the path in force, override first.
    pub(crate) fn path(&self) -> &[u8] {
        match self.pathalloc.as_deref() {
            Some(allocated) => allocated,
            None => &self.url_path,
        }
    }

    /// `curlx_free(ftp->pathalloc); ftp->pathalloc = ftp->path = tmp_path;`
    /// -- the wildcard driver's switch to a concrete filename. The previous
    /// override is released by the assignment, which is what the C's `free`
    /// does by hand.
    pub(crate) fn set_path_override(&mut self, path: Vec<u8>) {
        self.pathalloc = Some(path);
    }

    /// Whether an override is in force, which the wildcard tests assert
    /// directly.
    pub(crate) const fn has_path_override(&self) -> bool {
        self.pathalloc.is_some()
    }

    /// `last_slash[0] = '\0'` and `path[0] = '\0'` -- the wildcard
    /// initialiser cutting the pattern off the end of the path in place.
    ///
    /// Truncation, not reallocation, so the buffer identity the C relies on is
    /// preserved; it applies to the override when one is in force, exactly as
    /// the C's write through `ftp->path` does.
    pub(crate) fn truncate_path(&mut self, len: usize) {
        match self.pathalloc.as_mut() {
            Some(allocated) => allocated.truncate(len),
            None => self.url_path.truncate(len),
        }
    }

    /// `type_url_check` (`lib/ftp.c:4222-4249`): consume a trailing
    /// `;type=<code>` and answer what it asked for.
    ///
    /// The suffix is seven bytes -- `;type=` plus one code -- and is cut off
    /// the path, so it never reaches a command. The code is upper-cased before
    /// the comparison, and anything other than `A` or `D` means binary, which
    /// is the C's `case 'I': default:` sharing one body.
    pub(crate) fn type_url_check(&mut self) -> Option<UrlTypeCode> {
        let path = self.path();
        let len = path.len();
        if len < 7 {
            return None;
        }
        let tail_at = len.saturating_sub(7);
        let tail = path.get(tail_at..)?;
        if !tail.starts_with(b";type=") {
            return None;
        }
        let code = tail.get(6).copied().unwrap_or(0).to_ascii_uppercase();
        self.truncate_path(tail_at);
        Some(match code {
            b'A' => UrlTypeCode::Ascii,
            b'D' => UrlTypeCode::Directory,
            _ => UrlTypeCode::Binary,
        })
    }
}

/// What a `;type=` suffix asked for (`lib/ftp.c:4232-4248`).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
pub(crate) enum UrlTypeCode {
    /// `;type=A` -- *"ASCII mode"*, which sets `prefer_ascii`.
    Ascii,
    /// `;type=D` -- *"directory mode"*, which sets `list_only`.
    Directory,
    /// `;type=I`, and every unrecognised code -- *"switch off ASCII"*.
    Binary,
}

/// The per-connection state -- `struct ftp_conn` minus its `pingpong`
/// (`lib/ftp.h:124-164`).
///
/// # Why the cadence engine is not a field here
///
/// The C reaches it as `conn->proto.ftpc.pp` and hands `&ftpc->pp` to
/// `Curl_pp_readresp` while the same `ftpc` is the callback's context. A Rust
/// type owning both could not hand one out while the other is borrowed, which
/// is the aliasing [`pingpong::PingPongOps`] documents. [`FtpConn`] therefore
/// owns the pair and [`FtpConn::split`] borrows them disjointly -- the state is
/// still connection-owned, exactly as the C says it must be.
///
/// # The live state is private
///
/// [`Self::state`] is a private field with no setter other than
/// [`Self::set_state`], which is the Rust expression of the C's comment
/// *"always use ftp.c:state() to change state!"*. The comment is advice there
/// and a compile error here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FtpConnState {
    /// `state` -- the live state. Private: see the type's documentation.
    state: FtpState,
    /// `account` -- `CURLOPT_FTP_ACCOUNT`, cloned per connection so that
    /// [`ftp_conns_match`] can compare it.
    pub(crate) account: Option<Vec<u8>>,
    /// `alternative_to_user` -- `CURLOPT_FTP_ALTERNATIVE_TO_USER`.
    pub(crate) alternative_to_user: Option<Vec<u8>>,
    /// `entrypath` -- *"the PWD reply when we logged on"*.
    pub(crate) entrypath: Option<Vec<u8>>,
    /// `rawpath` -- *"URL decoded, allocated, version of the path"*, and the
    /// one buffer every component and the filename point into.
    rawpath: Vec<u8>,
    /// `file` -- *"url-decoded filename (or path), points into rawpath"*, as a
    /// range rather than a pointer. [`None`] is the C's deliberate `NULL`,
    /// which it uses to mean *"no file, this is a directory operation"* rather
    /// than an empty name.
    file: Option<Range<usize>>,
    /// `dirs` -- one entry per path component, in order.
    dirs: Vec<PathComp>,
    /// `prevpath` -- *"url-decoded conn->path from the previous transfer"*.
    pub(crate) prevpath: Option<Vec<u8>>,
    /// `transfertype` -- `b'A'`, `b'I'` or `0` while unknown.
    pub(crate) transfertype: u8,
    /// `server_os` -- *"The target server operating system"*, from `SYST`.
    pub(crate) server_os: Option<Vec<u8>>,
    /// `known_filesize` -- set by the wildcard driver from a listing entry,
    /// and `-1` when unknown.
    pub(crate) known_filesize: i64,
    /// `count1` -- *"general purpose counter for the state machine"*: the
    /// active or passive command offset, and the quote list's index.
    pub(crate) count1: i32,
    /// `count2` -- the second counter: failed `CWD`s, and whether the current
    /// quote command may fail.
    pub(crate) count2: i32,
    /// `count3` -- the third counter: `AUTH` retries, and `MKD` tolerance.
    pub(crate) count3: i32,
    /// `dirdepth` -- *"number of entries used in the 'dirs' array"*.
    dirdepth: u16,
    /// `cwdcount` -- *"number of CWD commands issued"*.
    pub(crate) cwdcount: u16,
    /// `use_ssl` -- the connection's snapshot of `CURLOPT_USE_SSL`.
    pub(crate) use_ssl: UseSsl,
    /// `ccc` -- the connection's snapshot of `CURLOPT_FTP_SSL_CCC`.
    pub(crate) ccc: CccMode,
    /// `ftp_trying_alternative` -- the alternative-to-user command has been
    /// sent, so a second failure is final.
    pub(crate) ftp_trying_alternative: bool,
    /// `dont_check` -- *"prevent the final (post-transfer) file size and
    /// 226/250 status check. It should still read the line, just ignore the
    /// result."*
    pub(crate) dont_check: bool,
    /// `ctl_valid` -- whether `QUIT` may still be sent.
    pub(crate) ctl_valid: bool,
    /// `cwddone` -- *"the proper CWD combo already has been done"*.
    pub(crate) cwddone: bool,
    /// `cwdfail` -- a `CWD` failed, so the current directory must not be
    /// remembered.
    pub(crate) cwdfail: bool,
    /// `wait_data_conn` -- the data connection is being waited for.
    pub(crate) wait_data_conn: bool,
    /// `shutdown` -- the connection is going away, e.g. `QUIT`.
    pub(crate) shutdown: bool,
}

impl Default for FtpConnState {
    /// `curlx_calloc` plus `ftp_setup_connection`'s four assignments
    /// (`lib/ftp.c:4327-4331`): every counter zero, no path known, and a
    /// file size of `-1` rather than `0`.
    fn default() -> Self {
        Self {
            state: FtpState::Stop,
            account: None,
            alternative_to_user: None,
            entrypath: None,
            rawpath: Vec::new(),
            file: None,
            dirs: Vec::new(),
            prevpath: None,
            transfertype: 0,
            server_os: None,
            known_filesize: -1,
            count1: 0,
            count2: 0,
            count3: 0,
            dirdepth: 0,
            cwdcount: 0,
            use_ssl: UseSsl::None,
            ccc: CccMode::None,
            ftp_trying_alternative: false,
            dont_check: false,
            ctl_valid: false,
            cwddone: false,
            cwdfail: false,
            wait_data_conn: false,
            shutdown: false,
        }
    }
}

#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
impl FtpConnState {
    /// The live state.
    pub(crate) const fn state(&self) -> FtpState {
        self.state
    }

    /// **The only way to change FTP state** -- `ftp_state_low`
    /// (`lib/ftp.c:131-150`).
    ///
    /// Emits the `[%s] -> [%s]` line on the `FTP` trace feature when the state
    /// actually changes, and then assigns unconditionally -- both halves in the
    /// C's order, so a self-transition is silent but still an assignment. The C
    /// adds `(line %d)` under `DEBUGBUILD`; the successor of that is the
    /// caller's own `#[track_caller]`-free trace, and it is deliberately not
    /// reproduced because the line number of a Rust helper would name this
    /// function rather than the transition.
    pub(crate) fn set_state(
        &mut self,
        new: FtpState,
        client: &mut dyn FtpClient,
    ) {
        if self.state != new {
            client.trc_ftp(format_args!(
                "[{}] -> [{}]",
                cstate(Some(self.state)),
                state_name(new)
            ));
        }
        self.state = new;
    }

    /// `freedirs` (`lib/ftp.c:169-175`): release the components, the decoded
    /// path and the filename together.
    pub(crate) fn freedirs(&mut self) {
        self.dirs.clear();
        self.dirdepth = 0;
        self.rawpath.clear();
        self.file = None;
    }

    /// `ftpc->rawpath` -- the decoded path every range indexes.
    pub(crate) fn rawpath(&self) -> &[u8] {
        &self.rawpath
    }

    /// `ftpc->file`, resolved against the buffer that owns it.
    ///
    /// [`None`] both when the C's pointer is `NULL` and when a stored range
    /// would fall outside the buffer, which cannot happen from
    /// [`Self::parse_url_path`] and is checked anyway.
    pub(crate) fn file(&self) -> Option<&[u8]> {
        let range = self.file.clone()?;
        self.rawpath.get(range)
    }

    /// Whether a filename is known -- the C's `if(ftpc->file)`, which is a
    /// question about the pointer and not about the name's length.
    pub(crate) const fn has_file(&self) -> bool {
        self.file.is_some()
    }

    /// `ftpc->dirdepth`.
    pub(crate) const fn dirdepth(&self) -> u16 {
        self.dirdepth
    }

    /// The path components, in order.
    pub(crate) fn dirs(&self) -> &[PathComp] {
        &self.dirs
    }

    /// `pathpiece(ftpc, num)` with `pathlen(ftpc, num)`
    /// (`lib/ftp.c:803-815`): the `num`th component's bytes.
    ///
    /// The C asserts the index and then indexes; this answers [`None`], which
    /// is what lets the two `CWD` emitters refuse to send an empty parameter
    /// rather than send a malformed one.
    pub(crate) fn pathpiece(&self, num: usize) -> Option<&[u8]> {
        let comp = self.dirs.get(num)?;
        self.rawpath.get(comp.range())
    }
}

/// The per-connection state and its cadence engine -- `struct ftp_conn`
/// (`lib/ftp.h:124-164`) in full.
#[derive(Debug)]
#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
pub(crate) struct FtpConn {
    /// `pp` -- the command writer and reply framer.
    pp: PingPong,
    /// Everything else the connection owns.
    ftpc: FtpConnState,
}

impl Default for FtpConn {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
impl FtpConn {
    /// A zeroed connection, as `curlx_calloc(1, sizeof(*ftpc))` gives.
    pub(crate) fn new() -> Self {
        Self {
            pp: PingPong::new(),
            ftpc: FtpConnState::default(),
        }
    }

    /// The two halves, borrowed disjointly. See [`FtpConnState`] for why this
    /// exists rather than an accessor pair.
    pub(crate) fn split(&mut self) -> (&mut PingPong, &mut FtpConnState) {
        (&mut self.pp, &mut self.ftpc)
    }

    /// The cadence engine alone.
    pub(crate) fn pp(&self) -> &PingPong {
        &self.pp
    }

    /// The cadence engine alone, mutably.
    pub(crate) fn pp_mut(&mut self) -> &mut PingPong {
        &mut self.pp
    }

    /// The rest of the connection state.
    pub(crate) fn ftpc(&self) -> &FtpConnState {
        &self.ftpc
    }

    /// The rest of the connection state, mutably.
    pub(crate) fn ftpc_mut(&mut self) -> &mut FtpConnState {
        &mut self.ftpc
    }

    /// `ftp_conn_dtor` (`lib/ftp.c:4200-4211`): release the paths, the strings
    /// and the cadence engine's buffers.
    ///
    /// Everything but the engine releases itself when this value is dropped,
    /// which is why the C needed a destructor and this needs only to reach
    /// `Curl_pp_disconnect`'s reset. Called explicitly by
    /// [`ftp_disconnect`] so that the reset is observable in a test.
    pub(crate) fn dtor(&mut self) -> CurlResult<()> {
        self.ftpc.freedirs();
        self.ftpc.account = None;
        self.ftpc.alternative_to_user = None;
        self.ftpc.entrypath = None;
        self.ftpc.prevpath = None;
        self.ftpc.server_os = None;
        self.pp.disconnect()
    }
}

// The two seams: the easy handle, and the operations no chain performs

/// The `CURLOPT_*` values FTP reads and does not change -- the subset of
/// `data->set` that `lib/ftp.c` touches.
///
/// A plain record rather than thirty accessors, because these are data: an easy
/// handle fills it once per transfer and the engine only reads it. The mutable
/// half is [`FtpRequest`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct FtpOptions {
    /// `conn->user` -- an empty user is legal and is sent as `USER `.
    pub(crate) user: Vec<u8>,
    /// `conn->passwd`.
    pub(crate) password: Vec<u8>,
    /// `STRING_FTP_ACCOUNT` -- `CURLOPT_FTP_ACCOUNT`.
    pub(crate) account: Option<Vec<u8>>,
    /// `STRING_FTP_ALTERNATIVE_TO_USER`.
    pub(crate) alternative_to_user: Option<Vec<u8>>,
    /// `data->set.use_ssl`.
    pub(crate) use_ssl: UseSsl,
    /// `data->set.ftp_ccc`.
    pub(crate) ccc: CccMode,
    /// `data->set.ftpsslauth`.
    pub(crate) ftpsslauth: FtpSslAuth,
    /// `data->set.ftp_use_port` -- `CURLOPT_FTPPORT` was given, so the data
    /// channel is active.
    pub(crate) use_port: bool,
    /// `STRING_FTPPORT` -- the address specification `--ftp-port` supplied.
    pub(crate) ftpport: Option<Vec<u8>>,
    /// `data->set.ftp_use_pret`.
    pub(crate) use_pret: bool,
    /// `data->set.ftp_skip_ip` -- ignore the address in a `227` reply.
    pub(crate) skip_ip: bool,
    /// `data->set.ftp_create_missing_dirs` -- `0`, `1`, or `2` for *"retry
    /// once"*.
    pub(crate) create_missing_dirs: u8,
    /// `data->set.accepttimeout`, in milliseconds; `0` means use
    /// [`DEFAULT_ACCEPT_TIMEOUT`].
    pub(crate) accept_timeout_ms: TimeDiff,
    /// `data->set.quote`.
    pub(crate) quote: Vec<Vec<u8>>,
    /// `data->set.prequote`.
    pub(crate) prequote: Vec<Vec<u8>>,
    /// `data->set.postquote`.
    pub(crate) postquote: Vec<Vec<u8>>,
    /// `STRING_CUSTOMREQUEST` -- replaces `LIST`/`NLST` entirely.
    pub(crate) custom_request: Option<Vec<u8>>,
    /// `data->set.remote_append` -- `APPE` rather than `STOR`.
    pub(crate) remote_append: bool,
    /// `data->req.no_body`.
    pub(crate) no_body: bool,
    /// `data->set.ignorecl` -- `CURLOPT_IGNORE_CONTENT_LENGTH`, which also
    /// suppresses the `SIZE` before a `RETR`.
    pub(crate) ignore_content_length: bool,
    /// `data->set.crlf`.
    pub(crate) crlf: bool,
    /// `data->set.get_filetime`.
    pub(crate) get_filetime: bool,
    /// `data->set.timecondition`.
    pub(crate) timecondition: TimeCondition,
    /// `data->set.timevalue`.
    pub(crate) timevalue: i64,
    /// `data->set.max_filesize`; `0` disables the check.
    pub(crate) max_filesize: i64,
    /// `data->set.str[STRING_RANGE]` -- the `--range` text, parsed by
    /// [`crate::util::range`].
    pub(crate) range: Option<Vec<u8>>,
    /// `data->set.server_response_timeout`, in milliseconds.
    pub(crate) server_response_timeout_ms: TimeDiff,
}

/// The mutable request state FTP both reads and writes -- the subset of
/// `data->state`, `data->req`, `data->info` and `conn->bits` that
/// `lib/ftp.c` assigns to.
///
/// Separate from [`FtpOptions`] precisely because these change during a
/// transfer: `EPSV` disables itself, `NOCWD` becomes `MULTICWD` under a
/// wildcard, `resume_from` is filled in from a `SIZE` reply, and both
/// `ftp_use_control_ssl` and `ftp_use_data_ssl` are set by the negotiation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct FtpRequest {
    /// `data->set.ftp_filemethod`. Mutable: `init_wc_data` coerces
    /// [`FileMethod::NoCwd`] to [`FileMethod::MultiCwd`].
    pub(crate) file_method: FileMethod,
    /// `conn->bits.ftp_use_epsv`.
    pub(crate) use_epsv: bool,
    /// `conn->bits.ftp_use_eprt`.
    pub(crate) use_eprt: bool,
    /// `data->state.prefer_ascii`.
    pub(crate) prefer_ascii: bool,
    /// `data->state.list_only`.
    pub(crate) list_only: bool,
    /// `data->state.upload`.
    pub(crate) upload: bool,
    /// `data->state.resume_from`.
    pub(crate) resume_from: i64,
    /// `data->state.infilesize`.
    pub(crate) infilesize: i64,
    /// `data->req.maxdownload`.
    pub(crate) maxdownload: i64,
    /// `data->req.size`.
    pub(crate) size: i64,
    /// `data->req.bytecount`.
    pub(crate) bytecount: i64,
    /// `data->req.writebytecount`.
    pub(crate) writebytecount: i64,
    /// `data->state.wildcardmatch`.
    pub(crate) wildcardmatch: bool,
    /// `conn->bits.reuse`.
    pub(crate) reuse: bool,
    /// `conn->bits.ipv6`.
    pub(crate) ipv6: bool,
    /// `conn->bits.tunnel_proxy || conn->bits.socksproxy`.
    pub(crate) tunnel_or_socks: bool,
    /// `conn->bits.proxy`.
    pub(crate) proxy: bool,
    /// `conn->bits.ftp_use_control_ssl`.
    pub(crate) control_ssl: bool,
    /// `conn->bits.ftp_use_data_ssl`.
    pub(crate) data_ssl: bool,
    /// `conn->bits.do_more`.
    pub(crate) do_more: bool,
    /// `conn->host.name` -- used by the skip-address message and by the
    /// tunnelled form of `ftp_control_addr_dup`.
    pub(crate) host_name: Vec<u8>,
    /// `ipquad.remote_ip` for the control connection -- what
    /// `ftp_control_addr_dup` answers when no proxy is in the way, and the
    /// address a passive data connection is made to when the reply's own is
    /// skipped or absent.
    pub(crate) control_remote_ip: Option<Vec<u8>>,
    /// `ipquad.remote_port` for the control connection -- the port a proxied
    /// data connection is made to, since the proxy is what is actually
    /// contacted.
    pub(crate) control_remote_port: u16,
    /// `conn->socks_proxy.host.name` or `conn->http_proxy.host.name` --
    /// whichever proxy the connection is using, when it is using one.
    pub(crate) proxy_host: Option<Vec<u8>>,
    /// `conn->secondaryhostname`.
    pub(crate) secondary_hostname: Option<Vec<u8>>,
    /// `conn->secondary_port`.
    pub(crate) secondary_port: u16,
    /// `conn->scope_id`.
    pub(crate) scope_id: u32,
    /// `data->info.filetime`.
    pub(crate) filetime: i64,
    /// `data->info.timecond`.
    pub(crate) timecond_met: bool,
    /// `data->info.httpcode` -- FTP stores its reply code here, which is what
    /// `CURLINFO_RESPONSE_CODE` reports for an FTP transfer.
    pub(crate) httpcode: i32,
    /// `data->state.errorbuf`.
    pub(crate) errorbuf: bool,
    /// `data->state.most_recent_ftp_entrypath`.
    pub(crate) most_recent_entrypath: Option<Vec<u8>>,
}

/// What a seek on the upload source reported -- `CURL_SEEKFUNC_*`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
pub(crate) enum SeekOutcome {
    /// `CURL_SEEKFUNC_OK`, and also the state when no seek callback is set at
    /// all -- the C initialises `seekerr` to it.
    Ok,
    /// `CURL_SEEKFUNC_CANTSEEK` -- *"cannot seek to offset"*, so the bytes
    /// must be read and discarded instead.
    CantSeek,
    /// `CURL_SEEKFUNC_FAIL`, or any other value the callback returned.
    Fail,
}

/// Why a listening socket could not be created, bound or listened on.
///
/// The C reads `SOCKERRNO` and renders it with `curlx_strerror`. Both travel as
/// data here, because the engine's job is to decide what to do next -- retry the
/// next port, fall back to the control address, or give up -- and that decision
/// is made from [`Self::kind`] while [`Self::message`] only reaches the failure
/// text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SockFailure {
    /// `SOCKERRNO`.
    pub(crate) errno: i32,
    /// Which of the three conditions the C branches on this is.
    pub(crate) kind: SockFailureKind,
    /// `curlx_strerror(error, ...)` -- the text the failure message carries.
    pub(crate) message: String,
}

/// The three conditions `ftp_state_use_port` distinguishes
/// (`lib/ftp.c:1100-1122`).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
pub(crate) enum SockFailureKind {
    /// `SOCKEADDRNOTAVAIL` -- *"The requested bind address is not local"*, so
    /// the control connection's own address is tried instead and the port loop
    /// restarts.
    AddrNotAvail,
    /// `SOCKEADDRINUSE` or `SOCKEACCES` -- try the next port in the range.
    AddrInUse,
    /// Anything else -- report and give up.
    Other,
}

/// The operations FTP needs that no filter chain performs -- name resolution,
/// a listening socket, filter installation and the readiness probe.
///
/// # Why this is a seam rather than direct calls
///
/// Three of the five groups cannot be reached from a protocol module at all
/// without one. Name resolution needs the resolver the easy handle owns; a
/// listening socket needs `Curl_socket_open`, `bind` and `listen`, which are
/// operating-system calls this crate confines to `src/ffi/`; and installing a
/// TLS filter needs the factory `crate::conn` holds -- reaching
/// `crate::tls` from here would be the layer violation the filter design exists
/// to prevent, which is why **this module does not name that module anywhere**.
///
/// The other two groups -- connecting a chain and closing one -- are in the
/// seam because their C originals are blocking, and a test that had to build a
/// real multi-step handshake to reach the *"data connection was not available
/// immediately"* branch would be testing the transport rather than the
/// protocol.
pub(crate) trait FtpSeams: fmt::Debug + Send {
    /// `Curl_resolv_blocking(data, host, port, ip_version, &dns_entry)`.
    ///
    /// # Errors
    ///
    /// Whatever the resolver reports; an empty answer is a failure, not an
    /// empty success, because the C tests `if(!res)`.
    fn resolve(
        &mut self,
        host: &[u8],
        port: u16,
    ) -> CodeResult<Vec<std::net::IpAddr>>;

    /// `getsockname(conn->sock[FIRSTSOCKET], ...)` -- the local address of the
    /// control connection.
    fn control_local_addr(&mut self) -> Option<std::net::IpAddr>;

    /// `Curl_conn_get_remote_addr(data, FIRSTSOCKET)`'s family, which decides
    /// whether `PORT` is even possible and which family `if2ip` is asked
    /// about.
    fn control_family(&mut self) -> crate::dns::AddressFamily;

    /// `Curl_ipv6_scope(&remote_addr->curl_sa_addr)` -- the scope of the
    /// control connection's remote address, which is the second argument
    /// `Curl_if2ip` is given.
    ///
    /// Defaults to [`crate::dns::if2ip::IPV6_SCOPE_GLOBAL`], which is what the
    /// C's own helper answers for every IPv4 address and for a global IPv6 one.
    fn control_remote_scope(&mut self) -> u32 {
        crate::dns::if2ip::IPV6_SCOPE_GLOBAL
    }

    /// `Curl_if2ip(...)` -- resolve an interface name to an address.
    ///
    /// Defaults to the real implementation in [`crate::dns::if2ip`], so a
    /// production seam inherits it and only a test overrides it. The three-way
    /// answer is the C's and is handled by the caller.
    fn if2ip(
        &mut self,
        family: crate::dns::AddressFamily,
        remote_scope: u32,
        scope_id: u32,
        iface: &[u8],
    ) -> If2IpResult {
        crate::dns::if2ip::if2ip(family, remote_scope, scope_id, iface)
    }

    /// `Curl_socket_open(...)` for the address family of `addr`.
    ///
    /// # Errors
    ///
    /// [`SockFailure`], whose message reaches the C's *"socket failure: %s"*.
    fn listener_open(
        &mut self,
        addr: std::net::IpAddr,
    ) -> Result<(), SockFailure>;

    /// `bind(portsock, sa, sslen)` followed by the `getsockname` that reads
    /// back the port actually assigned.
    ///
    /// # Errors
    ///
    /// [`SockFailure`], whose [`SockFailureKind`] selects the retry.
    fn listener_bind(
        &mut self,
        addr: std::net::IpAddr,
        port: u16,
    ) -> Result<u16, SockFailure>;

    /// `listen(portsock, 1)`.
    ///
    /// # Errors
    ///
    /// [`SockFailure`] -- the C reports *"socket failure: %s"* here too.
    fn listener_listen(&mut self) -> Result<(), SockFailure>;

    /// `Curl_conn_tcp_listen_set(data, conn, SECONDARYSOCKET, &portsock)` --
    /// hand the listening socket to the secondary chain, which owns it
    /// afterwards.
    ///
    /// # Errors
    ///
    /// Whatever the chain reports.
    fn listener_install(
        &mut self,
        chains: &mut FilterChains,
        cx: &mut CallCtx<'_, '_>,
    ) -> CodeResult<()>;

    /// `Curl_socket_close(data, conn, portsock)` for a socket never installed.
    fn listener_close(&mut self);

    /// `Curl_conn_setup(data, conn, SECONDARYSOCKET, dns, ssl_mode)`.
    ///
    /// # Errors
    ///
    /// Whatever the setup reports. A failure on the first `EPSV` attempt is
    /// what sends the engine back to `PASV`.
    fn setup_secondary(
        &mut self,
        chains: &mut FilterChains,
        cx: &mut CallCtx<'_, '_>,
        target: SecondaryTarget<'_>,
    ) -> CodeResult<()>;

    /// `Curl_ssl_cfilter_add(data, conn, sockindex)` -- ask `crate::conn` for
    /// a TLS filter and splice it in.
    ///
    /// # Errors
    ///
    /// Whatever the factory reports; the control-channel caller turns any
    /// failure into [`CURLcode::UseSslFailed`].
    fn add_tls_filter(
        &mut self,
        chains: &mut FilterChains,
        cx: &mut CallCtx<'_, '_>,
        sockindex: SocketIndex,
    ) -> CodeResult<()>;

    /// `Curl_ssl_cfilter_remove(data, sockindex, send_shutdown)` -- the `CCC`
    /// teardown.
    ///
    /// # Errors
    ///
    /// Whatever the shutdown reports.
    fn remove_tls_filter(
        &mut self,
        chains: &mut FilterChains,
        cx: &mut CallCtx<'_, '_>,
        sockindex: SocketIndex,
        send_shutdown: bool,
    ) -> CodeResult<()>;

    /// `Curl_conn_connect(data, sockindex, blocking, &done)`.
    ///
    /// # Errors
    ///
    /// Whatever the chain reports.
    fn connect(
        &mut self,
        chains: &mut FilterChains,
        cx: &mut CallCtx<'_, '_>,
        sockindex: SocketIndex,
        blocking: bool,
    ) -> CodeResult<bool>;

    /// `SOCKET_READABLE(ctrl_sock, 0)` -- a zero-timeout readability probe,
    /// answering the C's `CURL_CSELECT_*` bitmask or a negative value for an
    /// error.
    fn readable_now(&mut self, sock: Socket) -> i32;
}

/// Where a passive data connection is to be made -- the arguments
/// `Curl_conn_setup` is given after a `227` or `229` reply.
///
/// A record rather than five parameters, so that the seam stays inside
/// `clippy.toml`'s argument budget and so that a test can print what it was
/// asked for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SecondaryTarget<'a> {
    /// The host text the reply named, or the control connection's address when
    /// the reply's own address is skipped.
    pub(crate) host: &'a [u8],
    /// The resolved addresses for that host.
    pub(crate) addrs: &'a [std::net::IpAddr],
    /// The port to connect to -- the reply's port, or the proxy's.
    pub(crate) port: u16,
    /// `conn->bits.ftp_use_data_ssl ? CURL_CF_SSL_ENABLE : CURL_CF_SSL_DISABLE`.
    pub(crate) tls: bool,
}

/// The easy handle, as this module reaches it.
///
/// `lib/ftp.c` threads `struct Curl_easy *data` through every function and
/// uses it for four distinct things: reading options, writing request state,
/// emitting diagnostics, and wiring the transfer. This trait is those four, and
/// nothing else -- it deliberately does not carry the connection, whose state
/// lives in [`FtpConn`], nor the filter chains, which arrive through
/// [`FtpIo`].
///
/// The shape follows `protocols/file.rs`'s `FileClient`, for the same reason:
/// [`TransferCtx`] carries the chains, the clock, the scheme and the socket
/// index and no more, so a protocol that needs an option takes a seam and a
/// test supplies one. Every branch of the sequencing below is reachable through
/// it without a network.
#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
pub(crate) trait FtpClient: fmt::Debug + Send {
    /// The immutable option snapshot.
    fn options(&self) -> &FtpOptions;

    /// The mutable request state.
    fn request(&self) -> &FtpRequest;

    /// The mutable request state, mutably.
    fn request_mut(&mut self) -> &mut FtpRequest;

    /// `CURL_TRC_FTP(data, ...)` -- a line on the `FTP` trace feature.
    ///
    /// Implementations route it to [`crate::trace::Tracer::feature`] with
    /// [`crate::trace::TraceFeature::Ftp`]; the engine never formats a level or
    /// a prefix itself.
    fn trc_ftp(&mut self, args: fmt::Arguments<'_>);

    /// `infof(data, ...)`.
    fn infof(&mut self, args: fmt::Arguments<'_>);

    /// `failf(data, ...)`.
    fn failf(&mut self, args: fmt::Arguments<'_>);

    /// `Curl_debug(data, kind, ptr, len)`.
    fn debug(&mut self, kind: InfoType, payload: &[u8]);

    /// `Curl_client_write(data, flags, ptr, len)`.
    ///
    /// # Errors
    ///
    /// Whatever the writer chain reports.
    fn client_write(
        &mut self,
        flags: ClientWriteFlags,
        buf: &[u8],
    ) -> CodeResult<()>;

    /// `client_write_header` (`lib/ftp.c:2374-2404`): a header line that FTP
    /// always shows the body writer.
    ///
    /// The C sets `data->set.include_header` around the call and restores it,
    /// with the comment that *"For historic reasons, FTP never played this
    /// game and expects all its headers to do that always"*. The forcing is
    /// the implementation's to perform, which is why this has a body here: the
    /// flag belongs to the writer chain, not to the protocol.
    ///
    /// # Errors
    ///
    /// As [`Self::client_write`].
    fn write_header(&mut self, buf: &[u8]) -> CodeResult<()> {
        self.client_write(ClientWriteFlags::HEADER, buf)
    }

    /// `data->req.headerbytecount += gotbytes`.
    fn add_header_bytes(&mut self, count: u32);

    /// `Curl_pgrsSetDownloadSize(data, size)`.
    fn pgrs_set_download_size(&mut self, size: i64);

    /// `Curl_pgrsSetUploadSize(data, size)`.
    fn pgrs_set_upload_size(&mut self, size: i64);

    /// `Curl_pgrsCheck(data)`.
    ///
    /// # Errors
    ///
    /// The low-speed and callback-cancellation codes.
    fn pgrs_check(&mut self) -> CodeResult<()>;

    /// `Curl_pgrsUpdate(data)`.
    ///
    /// # Errors
    ///
    /// As [`Self::pgrs_check`].
    fn pgrs_update(&mut self) -> CodeResult<()>;

    /// `Curl_pgrsReset(data)`.
    fn pgrs_reset(&mut self);

    /// `Curl_pgrsTime(data, TIMER_STARTACCEPT)`.
    fn pgrs_time_start_accept(&mut self);

    /// `Curl_expire(data, delay, id)` -- arm a timer.
    fn expire(&mut self, delay_ms: TimeDiff, timer: TimerId);

    /// `Curl_timeleft_ms(data)`.
    fn timeleft_ms(&self) -> TimeDiff;

    /// `SOCKERRNO`.
    fn sock_errno(&self) -> i32;

    /// `Curl_xfer_setup_send(data, sockindex)`.
    fn xfer_setup_send(&mut self, sockindex: SocketIndex);

    /// `Curl_xfer_setup_recv(data, sockindex, size)`.
    fn xfer_setup_recv(&mut self, sockindex: SocketIndex, size: i64);

    /// `Curl_xfer_setup_nop(data)`.
    fn xfer_setup_nop(&mut self);

    /// `Curl_xfer_set_shutdown(data, shutdown, ignore_errors)`.
    fn xfer_set_shutdown(&mut self, shutdown: bool, ignore_errors: bool);

    /// `data->set.seek_func(data->set.seek_client, offset, SEEK_SET)`.
    fn seek(&mut self, offset: i64) -> SeekOutcome;

    /// `data->state.fread_func(...)` -- read from the upload source, for the
    /// discard loop a non-seekable stream needs.
    ///
    /// # Errors
    ///
    /// Whatever the read callback reports.
    fn read_input(&mut self, into: &mut [u8]) -> CodeResult<usize>;

    /// `data->set.chunk_bgn(finfo, data->set.wildcardptr, remaining)`, or
    /// [`None`] when no callback is set.
    ///
    /// `remaining` is the C's `(int)Curl_llist_count(&wildcard->filelist)`,
    /// which counts the entry being offered as well as those after it.
    fn chunk_bgn(
        &mut self,
        finfo: &FileInfo,
        remaining: i32,
    ) -> Option<ChunkBgn>;

    /// `data->set.chunk_end(data->set.wildcardptr)`, or [`None`] when no
    /// callback is set.
    fn chunk_end(&mut self) -> Option<ChunkEnd>;

    /// Install the listing parser as the transfer's write callback, answering
    /// what was displaced.
    ///
    /// The C swaps `data->set.fwrite_func` and `data->set.out`
    /// (`lib/ftp.c:3855-3862`) and keeps the pair in `ftpwc->backup`. The
    /// second half of that pair is a `FILE *`, which has no successor here:
    /// the destination is the transfer's own writer, so what has to be recorded
    /// is only WHETHER the swap happened. [`WriteBackup`] is that record, owned
    /// by [`listparser`], and the restore is [`Self::restore_listing_writer`].
    fn install_listing_writer(&mut self) -> WriteBackup;

    /// Put the displaced write callback back.
    fn restore_listing_writer(&mut self, backup: WriteBackup);

    /// `connclose(conn, reason)` -- mark the connection for closure.
    fn conn_close(&mut self, reason: &str);
}

/// The connection and the easy handle, as the cadence engine reaches them.
///
/// [`pingpong::PingPongIo`] is the C's `data`-plus-`conn` pair reduced to what
/// sending a command and reading a reply needs; this is the FTP implementation
/// of it, and it is production code rather than a test double. A test drives it
/// over [`crate::conn::filters`]'s in-memory transport, so the same type serves
/// both and there is no second implementation to keep in step.
pub(crate) struct FtpIo<'a> {
    /// `conn->cfilter[]` -- both chains, because the data connection is the
    /// secondary one.
    chains: &'a mut FilterChains,
    /// `curlx_now()`, injected. No wall-clock constructor is called here.
    clock: &'a (dyn Clock + Send + Sync),
    /// `data`.
    client: &'a mut dyn FtpClient,
}

#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
impl<'a> FtpIo<'a> {
    /// The three borrows the engine works through.
    pub(crate) fn new(
        chains: &'a mut FilterChains,
        clock: &'a (dyn Clock + Send + Sync),
        client: &'a mut dyn FtpClient,
    ) -> Self {
        Self {
            chains,
            clock,
            client,
        }
    }

    /// `data`, for a read.
    pub(crate) fn client(&self) -> &dyn FtpClient {
        self.client
    }

    /// `data`, for a write.
    pub(crate) fn client_mut(&mut self) -> &mut dyn FtpClient {
        self.client
    }

    /// `data->set` -- the option snapshot, reached often enough to deserve the
    /// short spelling.
    pub(crate) fn opts(&self) -> &FtpOptions {
        self.client.options()
    }

    /// `data->state` and `data->req`, for a read.
    pub(crate) fn req(&self) -> &FtpRequest {
        self.client.request()
    }

    /// `data->state` and `data->req`, for a write.
    pub(crate) fn req_mut(&mut self) -> &mut FtpRequest {
        self.client.request_mut()
    }

    /// The chains and a filter-layer context over the same injected clock.
    ///
    /// The pair travels together for the reason
    /// [`TransferCtx::split`](crate::protocols::TransferCtx::split) documents:
    /// every synchronous filter call needs both at once, and composing two
    /// accessors would borrow this value mutably and immutably in one
    /// expression.
    pub(crate) fn split(
        &mut self,
    ) -> (&mut FilterChains, CallCtx<'a, 'static>) {
        let clock = self.clock;
        (self.chains, CallCtx::new(clock))
    }

    /// `conn->sock[sockindex]`, asked of the chain.
    pub(crate) fn socket_of(&mut self, sockindex: SocketIndex) -> Socket {
        let (chains, mut cx) = self.split();
        chains.chain_mut(sockindex).socket(&mut cx)
    }

    /// `Curl_conn_is_connected(conn, sockindex)`.
    pub(crate) fn is_connected(&mut self, sockindex: SocketIndex) -> bool {
        let (chains, _cx) = self.split();
        chains.chain_mut(sockindex).is_head_connected()
    }

    /// `Curl_conn_is_setup(conn, sockindex)` -- whether a chain exists at all.
    pub(crate) fn is_setup(&mut self, sockindex: SocketIndex) -> bool {
        let (chains, _cx) = self.split();
        chains.chain(sockindex).is_setup()
    }

    /// `Curl_conn_is_ssl(conn, sockindex)`.
    pub(crate) fn is_ssl(&mut self, sockindex: SocketIndex) -> bool {
        let (chains, _cx) = self.split();
        chains.chain(sockindex).is_ssl()
    }

    /// `Curl_conn_is_ip_connected(data, sockindex)`.
    pub(crate) fn is_ip_connected(&mut self, sockindex: SocketIndex) -> bool {
        let (chains, _cx) = self.split();
        chains.chain(sockindex).is_ip_connected()
    }

    /// `Curl_conn_is_tcp_listen(data, sockindex)` -- whether the chain's head
    /// is the listening filter active mode installed.
    ///
    /// `ftp_do_more` reads this to tell an `EPRT` data channel from an `EPSV`
    /// one: a listener never "connects", so a chain that is one must not be
    /// judged by [`Self::is_connected`] (`lib/ftp.c:2158-2171`).
    pub(crate) fn is_tcp_listen(&mut self, sockindex: SocketIndex) -> bool {
        let (chains, _cx) = self.split();
        crate::conn::socket::conn_is_tcp_listen(chains.chain(sockindex))
    }

    /// `close_secondarysocket` (`lib/ftp.c:352-359`): close the data
    /// connection and discard its whole chain.
    pub(crate) fn close_secondary(&mut self) {
        let (chains, mut cx) = self.split();
        let chain = chains.chain_mut(SocketIndex::Secondary);
        chain.close(&mut cx);
        chain.discard_chain(&mut cx);
    }
}

impl fmt::Debug for FtpIo<'_> {
    /// Opaque, like [`ConnAccess`]: printing the chains would print every
    /// filter's state at every trace point.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("FtpIo").finish()
    }
}

impl PingPongIo for FtpIo<'_> {
    fn has_connection(&self) -> bool {
        true
    }

    fn conn(&mut self) -> Option<ConnAccess<'_>> {
        Some(ConnAccess::new(self.chains, self.clock))
    }

    fn clock(&self) -> &dyn Clock {
        self.clock
    }

    fn debug(&mut self, kind: InfoType, payload: &[u8]) {
        self.client.debug(kind, payload);
    }

    fn client_write(
        &mut self,
        flags: ClientWriteFlags,
        buf: &[u8],
    ) -> CurlResult<()> {
        self.client.client_write(flags, buf).map_err(Error::new)
    }

    fn failf(&mut self, args: fmt::Arguments<'_>) {
        self.client.failf(args);
    }

    fn add_header_bytes(&mut self, count: u32) {
        self.client.add_header_bytes(count);
    }

    fn server_response_timeout_ms(&self) -> TimeDiff {
        self.client.options().server_response_timeout_ms
    }

    fn timeleft_ms(&self) -> TimeDiff {
        self.client.timeleft_ms()
    }

    fn pgrs_check(&mut self) -> CurlResult<()> {
        self.client.pgrs_check().map_err(Error::new)
    }

    fn sock_errno(&self) -> i32 {
        self.client.sock_errno()
    }
}

// The session, and the state machine the cadence engine calls back into

/// Everything one FTP connection owns, plus the injected seam.
///
/// The C keeps these in three places -- `Curl_conn_meta_get(conn,
/// CURL_META_FTP_CONN)`, `Curl_meta_get(data, CURL_META_FTP_EASY)` and
/// `data->wildcard` -- reached through **string-keyed meta tables**. Both keys
/// are eliminated: this is one typed value, so a lookup cannot miss, cannot
/// return the wrong type, and needs no downcast.
#[derive(Debug)]
#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
pub(crate) struct FtpSession {
    /// `struct ftp_conn` -- the connection's state and its cadence engine.
    conn: FtpConn,
    /// `struct FTP` -- the transfer's state.
    transfer: FtpTransfer,
    /// `data->wildcard` -- the wildcard driver's state, which is per transfer
    /// but outlives one DO phase because the driver is re-entered per match.
    wildcard: WildcardData,
    /// The injected operations of [`FtpSeams`].
    seams: Box<dyn FtpSeams>,
}

#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
impl FtpSession {
    /// A session for `path` -- the URL path WITHOUT its leading slash, which is
    /// what `ftp->path = &data->state.up.path[1]` produces.
    pub(crate) fn new(path: &[u8], seams: Box<dyn FtpSeams>) -> Self {
        Self {
            conn: FtpConn::new(),
            transfer: FtpTransfer::new(path),
            wildcard: WildcardData::default(),
            seams,
        }
    }

    /// The connection state.
    pub(crate) fn conn(&self) -> &FtpConn {
        &self.conn
    }

    /// The connection state, mutably.
    pub(crate) fn conn_mut(&mut self) -> &mut FtpConn {
        &mut self.conn
    }

    /// The transfer state.
    pub(crate) fn transfer(&self) -> &FtpTransfer {
        &self.transfer
    }

    /// The transfer state, mutably.
    pub(crate) fn transfer_mut(&mut self) -> &mut FtpTransfer {
        &mut self.transfer
    }

    /// The wildcard driver's state.
    pub(crate) fn wildcard(&self) -> &WildcardData {
        &self.wildcard
    }

    /// The wildcard driver's state, mutably.
    pub(crate) fn wildcard_mut(&mut self) -> &mut WildcardData {
        &mut self.wildcard
    }

    /// The injected seam.
    pub(crate) fn seams_mut(&mut self) -> &mut dyn FtpSeams {
        &mut *self.seams
    }

    /// The cadence engine and the state machine that drives it, borrowed
    /// disjointly.
    ///
    /// This is the split [`FtpConnState`] documents: `Curl_pp_readresp` takes
    /// `&pp` while `ftp_pp_statemachine` is its callback, and one value owning
    /// both could not satisfy the borrow checker.
    pub(crate) fn split(&mut self) -> (&mut PingPong, FtpMachine<'_>) {
        let Self {
            conn,
            transfer,
            seams,
            ..
        } = self;
        let (pp, ftpc) = conn.split();
        (
            pp,
            FtpMachine {
                ftpc,
                transfer,
                seams: &mut **seams,
            },
        )
    }
}

/// The state machine `PINGPONG_SETUP` installs -- `ftp_pp_statemachine` and
/// `ftp_endofresp` (`lib/ftp.c:3046` and `:575`).
///
/// A bundle of borrows rather than a value: the connection state, the transfer
/// state and the seam, taken apart from the cadence engine the callback is
/// handed.
///
/// `data->wildcard` is deliberately NOT among them. The reply dispatcher never
/// reads it -- the C's `ftp_pp_statemachine` does not either, and the one
/// listing fact a reply handler needs, `ftpc->known_filesize`, the wildcard
/// driver writes onto the connection state before the transfer starts. Holding
/// a borrow no arm reads would cost [`FtpSession::split`] a conflict for
/// nothing, so [`wc_statemach`] reaches the wildcard state through the session
/// directly.
#[derive(Debug)]
pub(crate) struct FtpMachine<'a> {
    /// `Curl_conn_meta_get(conn, CURL_META_FTP_CONN)` minus its `pingpong`.
    ftpc: &'a mut FtpConnState,
    /// `Curl_meta_get(data, CURL_META_FTP_EASY)`.
    transfer: &'a mut FtpTransfer,
    /// The injected operations.
    seams: &'a mut dyn FtpSeams,
}

impl<'c> PingPongOps<FtpIo<'c>> for FtpMachine<'_> {
    /// `ftp_pp_statemachine` (`lib/ftp.c:3046-3364`).
    ///
    /// Synchronous work in an immediately-ready future, deliberately. Every
    /// step this performs -- flushing a half-sent command, framing a reply,
    /// sending the next command, splicing a filter -- is synchronous in this
    /// crate as it is in the C; the only thing that ever waits is the readiness
    /// check, and that belongs to [`PingPong::statemach`] one level up. Boxing
    /// a synchronous body is what `ProtoFuture` costs, and it is what keeps the
    /// dispatch `dyn`-compatible.
    fn statemachine<'a>(
        &'a mut self,
        pp: &'a mut PingPong,
        io: &'a mut FtpIo<'c>,
    ) -> ProtoFuture<'a, ()> {
        let outcome =
            ftp_pp_statemachine(self, pp, io).map_err(|error| error.code());
        Box::pin(core::future::ready(outcome))
    }

    /// `ftp_endofresp` (`lib/ftp.c:575-588`).
    fn end_of_response(&mut self, line: &[u8], code: &mut i32) -> bool {
        ftp_endofresp(line, code)
    }
}

// Response framing

/// `ftp_endofresp` (`lib/ftp.c:575-588`): is this the last line of a reply,
/// and what is its code?
///
/// The C is one condition:
///
/// ```c
/// if((len > 3) && LASTLINE(line) && !curlx_str_number(&line, &status, 999))
/// ```
///
/// with `LASTLINE(line)` being `(ISDIGIT(line[0]) && ISDIGIT(line[1]) &&
/// ISDIGIT(line[2]) && (' ' == line[3]))`. All four parts matter and each is
/// reproduced: a line shorter than four bytes cannot be final, `NNN-` is a
/// continuation and not final, and a value above 999 is refused by the bound
/// [`str_number`] is given rather than by a comparison afterwards.
pub(crate) fn ftp_endofresp(line: &[u8], code: &mut i32) -> bool {
    if line.len() <= 3 {
        return false;
    }
    let leading = match line.get(..4) {
        Some(bytes) => bytes,
        None => return false,
    };
    let digits = leading.iter().take(3).all(u8::is_ascii_digit);
    if !digits || leading.get(3) != Some(&b' ') {
        return false;
    }
    // `curlx_str_number` returns zero on success and stops at the first
    // non-digit, so the space terminates it; the bound refuses 1000 and above.
    let mut cursor: &[u8] = line;
    match str_number(&mut cursor, 999) {
        Ok(status) => {
            *code = i32::try_from(status).unwrap_or(0);
            true
        }
        Err(_) => false,
    }
}

/// The text `ftp_readresp` reports when a `421` arrives -- `lib/ftp.c:615`.
pub(crate) const TIMEOUT_421_MESSAGE: &str = "We got a 421 - timeout";

/// The text `getftpresponse` reports when its own deadline passes --
/// `lib/ftp.c:664`.
#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
pub(crate) const RESPONSE_TIMEOUT_MESSAGE: &str = "FTP response timeout";

/// `ftp_readresp` (`lib/ftp.c:590-620`): read one reply and apply the two
/// rules that hold wherever it arrives.
///
/// The first rule is bookkeeping: the reply code becomes
/// `CURLINFO_RESPONSE_CODE` unless the connection is shutting down, so a `221`
/// answering `QUIT` does not overwrite the transfer's own outcome.
///
/// The second is a real protocol rule. `421` is *"Service not available,
/// closing control connection"*, which a server sends when an idle session
/// times out, and the C's comment explains why it is handled here rather than
/// in each state: *"This response code can come at any point so having it
/// treated generically is a good idea."* It stops the machine and reports
/// [`CURLcode::OperationTimedout`].
///
/// # Errors
///
/// [`CURLcode::OperationTimedout`] for a `421`, and whatever the framer
/// reports otherwise.
pub(crate) fn ftp_readresp(
    machine: &mut FtpMachine<'_>,
    pp: &mut PingPong,
    io: &mut FtpIo<'_>,
    sockindex: SocketIndex,
) -> CurlResult<PpResponse> {
    let outcome = pp.readresp(io, machine, sockindex)?;

    if !machine.ftpc.shutdown {
        io.req_mut().httpcode = outcome.code;
    }

    if outcome.code == 421 {
        io.client_mut().infof(format_args!("{TIMEOUT_421_MESSAGE}"));
        machine.ftpc.set_state(FtpState::Stop, io.client_mut());
        return Err(Error::with_context(
            CURLcode::OperationTimedout,
            TIMEOUT_421_MESSAGE,
        ));
    }

    Ok(outcome)
}

/// `Curl_pp_state_timeout` with the response deadline's origin supplied by the
/// caller -- the C's `pp->response = *Curl_pgrs_now(data)` restamp.
///
/// # Why this is not a duplicate of the cadence engine's own budget
///
/// Two FTP callers restamp that origin before a blocking read
/// (`lib/ftp.c:3474` in the quote sender and `:3603` in `ftp_done`), and both
/// have to: the command whose reply they are about to read was sent before a
/// transfer that may have lasted minutes, so measuring the per-response
/// allowance from when it went out would report a timeout that never happened.
///
/// [`PingPong`] owns that origin and publishes it read-only. The restamp is
/// therefore expressed here as a parameter rather than as a write into a
/// sibling module's state, and this function is
/// [`PingPong::state_timeout`]'s formula with `origin` substituted for
/// `pp.response()` and nothing else changed -- same fallback to
/// [`pingpong::RESP_TIMEOUT`], same *"`0` means no timeout applies"* reading of
/// [`FtpClient::timeleft_ms`], same saturating subtraction. Applying a
/// correction to the engine's answer instead would be wrong rather than merely
/// indirect: when the transfer's own deadline is the binding one, shifting the
/// origin must not move it, and a correction cannot tell the two halves apart
/// from the outside.
///
/// The ordinary, un-restamped path in [`getftpresponse`] does not come through
/// here at all; it asks the owner directly.
#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
pub(crate) fn response_budget_ms(io: &FtpIo<'_>, origin: CurlTime) -> TimeDiff {
    let configured = io.server_response_timeout_ms();
    let response_time = if configured == 0 {
        pingpong::RESP_TIMEOUT
    } else {
        configured
    };
    let elapsed = timediff_ms(io.clock().now(), origin);
    let timeout_ms = response_time.saturating_sub(elapsed);

    let xfer_timeout_ms = io.client().timeleft_ms();
    if xfer_timeout_ms != 0 && xfer_timeout_ms < timeout_ms {
        return xfer_timeout_ms;
    }
    timeout_ms
}

/// `getftpresponse` (`lib/ftp.c:626-735`): read a complete reply, waiting for
/// it.
///
/// The C calls this BLOCKING and it is, in the sense that it does not return to
/// the multi loop; the successor awaits instead, so nothing is blocked but the
/// caller. Everything else is the C's:
///
/// * the deadline is re-read every lap from `Curl_pp_state_timeout`, and
///   reaching zero reports [`RESPONSE_TIMEOUT_MESSAGE`];
/// * `origin` carries the C's `pp->response = *Curl_pgrs_now(data)` restamp
///   that two callers perform immediately beforehand -- see
///   [`response_budget_ms`] for why it is a parameter here;
/// * the wait is capped at one second per lap *"to make the timeout check
///   run"*;
/// * a cached reply skips the wait, but only twice in a row -- the C's
///   `cache_skip` counter, which stops a busy loop when the cache is not
///   enough to act on;
/// * a wait that times out updates the progress meter and goes round again;
/// * a half-sent command is flushed before the read;
/// * a failed wait reports [`CURLcode::RecvError`].
///
/// Returns the total number of reply bytes read and the reply code, which are
/// the C's two out-parameters.
///
/// # Errors
///
/// [`CURLcode::OperationTimedout`], [`CURLcode::RecvError`], or whatever the
/// framer or the progress check reports.
#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
pub(crate) async fn getftpresponse(
    machine: &mut FtpMachine<'_>,
    pp: &mut PingPong,
    io: &mut FtpIo<'_>,
    origin: Option<CurlTime>,
) -> CurlResult<(usize, i32)> {
    io.client_mut()
        .trc_ftp(format_args!("getftpresponse start"));

    let mut nread_total = 0_usize;
    let mut ftpcode = 0_i32;
    let mut cache_skip = 0_u8;
    let mut outcome: CurlResult<()> = Ok(());

    while ftpcode == 0 && outcome.is_ok() {
        let timeout_ms = match origin {
            None => pp.state_timeout(io),
            Some(origin) => response_budget_ms(io, origin),
        };
        if timeout_ms <= 0 {
            io.client_mut()
                .failf(format_args!("{RESPONSE_TIMEOUT_MESSAGE}"));
            return Err(Error::with_context(
                CURLcode::OperationTimedout,
                RESPONSE_TIMEOUT_MESSAGE,
            ));
        }
        let interval_ms = timeout_ms.min(1000);

        let cached = !pp.recvbuf().is_empty() && cache_skip < 2;
        if !cached && !io.data_pending(SocketIndex::First) {
            // `Curl_socket_check(sockfd, CURL_SOCKET_BAD, wsock, interval_ms)`
            // watches the control socket for reading and, while a command is
            // half-sent, for writing too. The seam takes one direction, and
            // the write half is the one that matters: the reply cannot arrive
            // before the command that asks for it has gone out.
            let want = if pp.needs_flush() {
                PollAction::OUT
            } else {
                PollAction::IN
            };
            let sock = io.socket_of(SocketIndex::First);
            match io.wait_ready(sock, want, interval_ms).await {
                Err(_) => {
                    let errno = io.client().sock_errno();
                    let message = format!(
                        "FTP response aborted due to select/poll error: \
                         {errno}"
                    );
                    io.client_mut().failf(format_args!("{message}"));
                    return Err(Error::with_context(
                        CURLcode::RecvError,
                        message,
                    ));
                }
                Ok(0) => {
                    outcome = io.client_mut().pgrs_update().map_err(Error::new);
                    continue;
                }
                Ok(_) => {}
            }
        }

        if pp.needs_flush() {
            if let Err(error) = pp.flushsend(io) {
                outcome = Err(error);
                break;
            }
        }

        let response = match ftp_readresp(machine, pp, io, SocketIndex::First) {
            Ok(response) => response,
            Err(error) => {
                outcome = Err(error);
                break;
            }
        };
        ftpcode = response.code;

        if response.size == 0 && !pp.recvbuf().is_empty() {
            cache_skip = cache_skip.saturating_add(1);
        } else {
            cache_skip = 0;
        }
        nread_total = nread_total.saturating_add(response.size);
    }

    pp.set_pending_resp(false);
    io.client_mut().trc_ftp(format_args!(
        "getftpresponse -> nread={nread_total}, ftpcode={ftpcode}"
    ));

    outcome.map(|()| (nread_total, ftpcode))
}

/// `ftp_statemach` (`lib/ftp.c:2105-2121`): one non-blocking lap, answering
/// whether the machine has stopped.
///
/// The C's comment on the readiness test is preserved by keeping it outside the
/// error path: *"Check for the state outside of the Curl_socket_check() return
/// code checks since at times we are in fact already in this state when this
/// function gets called."*
///
/// # Errors
///
/// Whatever the cadence engine or the state machine reports.
#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
pub(crate) async fn ftp_statemach(
    session: &mut FtpSession,
    io: &mut FtpIo<'_>,
) -> CurlResult<bool> {
    {
        let (pp, mut machine) = session.split();
        pp.statemach(io, &mut machine, false, false).await?;
    }
    Ok(session.conn().ftpc().state() == FtpState::Stop)
}

/// `ftp_block_statemach` (`lib/ftp.c:3374-3388`): drive the machine to
/// [`FtpState::Stop`], waiting as long as it takes.
///
/// Used only where the C uses it -- consuming the reply to `QUIT` -- and it
/// passes `disconnecting = TRUE`, which makes a wait that times out an error
/// rather than another lap.
///
/// # Errors
///
/// Whatever the cadence engine or the state machine reports.
#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
pub(crate) async fn ftp_block_statemach(
    session: &mut FtpSession,
    io: &mut FtpIo<'_>,
) -> CurlResult<()> {
    while session.conn().ftpc().state() != FtpState::Stop {
        if session.conn().ftpc().shutdown {
            io.client_mut().trc_ftp(format_args!(
                "in shutdown, waiting for server response"
            ));
        }
        let (pp, mut machine) = session.split();
        pp.statemach(io, &mut machine, true, true).await?;
    }
    Ok(())
}

// URL path parsing and connection setup

/// `lib/ftp.c:223` -- a decoded path carrying a control character is refused.
#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
pub(crate) const CONTROL_CHARS_MESSAGE: &str =
    "path contains control characters";

/// `lib/ftp.c:312` -- an upload with no filename to store under.
#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
pub(crate) const UPLOAD_NO_FILENAME_MESSAGE: &str =
    "Uploading to a URL without a filename";

/// `lib/ftp.c:330` -- the reused connection is already in the right
/// directory.
#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
pub(crate) const SAME_PATH_MESSAGE: &str =
    "Request has same path as previous transfer";

#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
impl FtpConnState {
    /// `ftp_parse_url_path` (`lib/ftp.c:196-337`): split the URL path into
    /// the components `CWD` will walk and the filename the transfer will name.
    ///
    /// The decoding is [`crate::url::escape`]'s, under
    /// [`UrlReject::Ctrl`] -- the C's `REJECT_CTRL` -- so `%00` and `%0a` are
    /// refused before they can reach a command line. Nothing is decoded by
    /// hand.
    ///
    /// The three file methods differ only in how much of the path becomes
    /// directory components:
    ///
    /// * [`FileMethod::NoCwd`] makes the whole path the filename, unless it
    ///   ends in a slash, in which case there is no filename at all and the
    ///   path is a directory;
    /// * [`FileMethod::SingleCwd`] makes one component of everything before
    ///   the last slash -- one byte, `/`, when the path is rooted -- and the
    ///   remainder the filename;
    /// * [`FileMethod::MultiCwd`] makes one component per slash, keeps a
    ///   leading `/` as a component of its own, and SKIPS empty components so
    ///   that `x//y` does not emit a `CWD` with no parameter. The C's reason is
    ///   worth repeating: *"the FTP command CWD requires a parameter and a
    ///   non-existent parameter a) does not work on many servers and b) has no
    ///   effect on the others"*.
    ///
    /// # Errors
    ///
    /// [`CURLcode::UrlMalformat`] for a path that decodes to a control
    /// character, for one deeper than [`FTP_MAX_DIR_DEPTH`], and for an upload
    /// with no filename.
    pub(crate) fn parse_url_path(
        &mut self,
        transfer: &FtpTransfer,
        io: &mut FtpIo<'_>,
    ) -> CodeResult<()> {
        self.ctl_valid = false;
        self.cwdfail = false;
        if !self.rawpath.is_empty() || !self.dirs.is_empty() {
            self.freedirs();
        }

        self.rawpath = match urldecode(transfer.path(), UrlReject::Ctrl) {
            Ok(decoded) => decoded,
            Err(code) => {
                io.client_mut()
                    .failf(format_args!("{CONTROL_CHARS_MESSAGE}"));
                return Err(code);
            }
        };

        let path_len = self.rawpath.len();
        let method = io.req().file_method;
        let file_start = match method {
            FileMethod::NoCwd => {
                if path_len > 0 && self.rawpath.last() != Some(&b'/') {
                    Some(0)
                } else {
                    // The C leaves `fileName` NULL here and says why: the
                    // field "is not used anywhere other than for operations on
                    // a file", so its absence is the directory case.
                    None
                }
            }
            FileMethod::SingleCwd => {
                match self.rawpath.iter().rposition(|&byte| byte == b'/') {
                    Some(slash) => {
                        // "get path before last slash, except for /"
                        let dirlen = if slash == 0 { 1 } else { slash };
                        self.dirs.push(PathComp {
                            start: 0,
                            len: dirlen,
                        });
                        self.dirdepth = 1;
                        Some(slash.saturating_add(1))
                    }
                    None => Some(0),
                }
            }
            FileMethod::MultiCwd => Some(self.split_multicwd()?),
        };

        self.file = match file_start {
            // "if(fileName && *fileName)": a pointer at the terminator is an
            // empty name, and the C stores NULL for it rather than an empty
            // string.
            Some(start) if start < path_len => Some(start..path_len),
            _ => None,
        };

        if io.req().upload
            && self.file.is_none()
            && transfer.transfer == PpTransfer::Body
        {
            io.client_mut()
                .failf(format_args!("{UPLOAD_NO_FILENAME_MESSAGE}"));
            return Err(CURLcode::UrlMalformat);
        }

        self.cwddone = false;
        if method == FileMethod::NoCwd && self.rawpath.first() == Some(&b'/') {
            // "skip CWD for absolute paths"
            self.cwddone = true;
            return Ok(());
        }

        // "newly created FTP connections are already in entry path", which the
        // C expresses by comparing against an empty string rather than by
        // testing the reuse flag twice.
        let old_path = if io.req().reuse {
            self.prevpath.clone()
        } else {
            Some(Vec::new())
        };
        if let Some(old) = old_path {
            let compared = if method == FileMethod::NoCwd {
                // "CWD to entry for relative paths"
                0
            } else {
                let file_len = self.file().map_or(0, <[u8]>::len);
                path_len.saturating_sub(file_len)
            };
            if old.len() == compared
                && self.rawpath.get(..compared) == Some(old.as_slice())
            {
                io.client_mut().infof(format_args!("{SAME_PATH_MESSAGE}"));
                self.cwddone = true;
            }
        }

        Ok(())
    }

    /// The [`FileMethod::MultiCwd`] arm of [`Self::parse_url_path`]
    /// (`lib/ftp.c:256-303`), answering where the filename begins.
    ///
    /// # Errors
    ///
    /// [`CURLcode::UrlMalformat`] for a *"suspiciously deep directory
    /// hierarchy"* -- the C's test is on the SLASH COUNT and is `>=`, so a
    /// path with exactly [`FTP_MAX_DIR_DEPTH`] slashes is already refused.
    fn split_multicwd(&mut self) -> CodeResult<usize> {
        let slashes = self.rawpath.iter().filter(|&&byte| byte == b'/').count();
        if slashes >= FTP_MAX_DIR_DEPTH {
            return Err(CURLcode::UrlMalformat);
        }

        let mut cursor = 0_usize;
        for _ in 0..slashes {
            let Some(tail) = self.rawpath.get(cursor..) else {
                break;
            };
            let Some(offset) = tail.iter().position(|&byte| byte == b'/')
            else {
                break;
            };
            let spos = cursor.saturating_add(offset);
            let mut clen = spos.saturating_sub(cursor);
            if clen == 0 && self.dirdepth == 0 {
                // "path starts with a slash: add that as a directory"
                clen = 1;
            }
            if clen > 0 {
                self.dirs.push(PathComp {
                    start: cursor,
                    len: clen,
                });
                self.dirdepth = self.dirdepth.saturating_add(1);
            }
            cursor = spos.saturating_add(1);
        }
        Ok(cursor)
    }

    /// `ftp_need_type` (`lib/ftp.c:344-349`): does the wanted mode differ from
    /// the one in force?
    pub(crate) const fn need_type(&self, ascii_wanted: bool) -> bool {
        let want = if ascii_wanted { b'A' } else { b'I' };
        self.transfertype != want
    }
}

/// `ftp_setup_connection` (`lib/ftp.c:4251-4302`): allocate the two state
/// carriers and take the snapshots the connection must keep.
///
/// The account and the alternative-to-user command are CLONED onto the
/// connection rather than read from the easy handle later, and the reason is
/// [`ftp_conns_match`]: the pool compares a candidate connection against a
/// needle, and by then the easy handle that set them may be gone.
///
/// The `;type=` suffix is consumed here too, before any command can carry it.
///
/// # Errors
///
/// None of its own -- the C's only failures are allocations. The signature
/// keeps the result so that a caller sees the same shape the vtable slot has.
#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
pub(crate) fn ftp_setup_connection(
    session: &mut FtpSession,
    io: &mut FtpIo<'_>,
) -> CodeResult<()> {
    let (account, alternative, use_ssl, ccc) = {
        let opts = io.opts();
        (
            opts.account.clone(),
            opts.alternative_to_user.clone(),
            opts.use_ssl,
            opts.ccc,
        )
    };

    if let Some(code) = session.transfer.type_url_check() {
        match code {
            UrlTypeCode::Ascii => io.req_mut().prefer_ascii = true,
            UrlTypeCode::Directory => io.req_mut().list_only = true,
            UrlTypeCode::Binary => io.req_mut().prefer_ascii = false,
        }
    }

    session.transfer.transfer = PpTransfer::Body;
    session.transfer.downloadsize = 0;

    let ftpc = session.conn.ftpc_mut();
    ftpc.account = account;
    ftpc.alternative_to_user = alternative;
    ftpc.known_filesize = -1;
    ftpc.use_ssl = use_ssl;
    ftpc.ccc = ccc;

    let state = session.conn.ftpc().state();
    io.client_mut().trc_ftp(format_args!(
        "[{}] setup connection -> 0",
        cstate(Some(state))
    ));
    Ok(())
}

/// `ftp_conns_match` (`lib/ftp.c:4304-4318`), reached from
/// `lib/url.c:1016-1034` when the pool considers a candidate.
///
/// Four things must agree, and the first two are credential-like, so they are
/// compared with [`timestrcmp`] -- the repository's constant-time string
/// comparator -- rather than with `==`. The C does the same and for the same
/// reason: a pool lookup that leaked how much of an account name matched would
/// be an oracle. The two enumerations that follow are not secrets and are
/// compared directly.
///
/// A connection without FTP state cannot match, which is the C's `if(!nftpc ||
/// !cftpc)`. Here that is expressed as [`Option`], because typed state cannot
/// be present with the wrong type.
///
/// Only the predicate is exported. `lib/url.c` decides what to do with the
/// answer -- its `else if` after the SSH case -- and that control flow belongs
/// to the parent registry, not here.
#[allow(dead_code)] // consumer: protocols/mod.rs, which installs the rows
pub(crate) fn ftp_conns_match(
    needle: Option<&FtpConnState>,
    candidate: Option<&FtpConnState>,
) -> bool {
    let (needle, candidate) = match (needle, candidate) {
        (Some(needle), Some(candidate)) => (needle, candidate),
        _ => return false,
    };
    timestrcmp(needle.account.as_deref(), candidate.account.as_deref()) == 0
        && timestrcmp(
            needle.alternative_to_user.as_deref(),
            candidate.alternative_to_user.as_deref(),
        ) == 0
        && needle.use_ssl == candidate.use_ssl
        && needle.ccc == candidate.ccc
}

// Command emission: one function per `ftp_state_*` in the C

impl FtpMachine<'_> {
    /// [`FtpConnState::set_state`], reached through the borrowed state.
    fn set_state(&mut self, new: FtpState, io: &mut FtpIo<'_>) {
        self.ftpc.set_state(new, io.client_mut());
    }

    /// `Curl_pp_sendf(data, &ftpc->pp, "%s", cmd)` for a command whose text is
    /// already assembled.
    ///
    /// Bytes rather than a format string throughout, because a path is not
    /// text: an FTP filename may hold any byte except CR, LF and NUL, and
    /// routing it through `{}` would demand UTF-8 that the wire does not
    /// promise. The terminating CRLF is [`PingPong`]'s, added exactly once.
    ///
    /// # Errors
    ///
    /// Whatever the command writer reports.
    fn send(
        &mut self,
        pp: &mut PingPong,
        io: &mut FtpIo<'_>,
        cmd: &[u8],
    ) -> CurlResult<()> {
        pp.sendn(io, cmd)
    }

    /// A command built as `<verb><space><argument>`.
    fn command_with(verb: &[u8], argument: &[u8]) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(verb.len().saturating_add(argument.len()));
        out.extend_from_slice(verb);
        out.extend_from_slice(argument);
        out
    }

    /// `ftp_state_user` (`lib/ftp.c:737-750`): `USER`, with an empty user name
    /// allowed.
    ///
    /// # Errors
    ///
    /// As [`Self::send`].
    fn state_user(
        &mut self,
        pp: &mut PingPong,
        io: &mut FtpIo<'_>,
    ) -> CurlResult<()> {
        let cmd = Self::command_with(b"USER ", &io.opts().user.clone());
        self.send(pp, io, &cmd)?;
        self.ftpc.ftp_trying_alternative = false;
        self.set_state(FtpState::User, io);
        Ok(())
    }

    /// `ftp_state_pwd` (`lib/ftp.c:752-766`): the literal `PWD`.
    ///
    /// # Errors
    ///
    /// As [`Self::send`].
    fn state_pwd(
        &mut self,
        pp: &mut PingPong,
        io: &mut FtpIo<'_>,
    ) -> CurlResult<()> {
        self.send(pp, io, b"PWD")?;
        self.set_state(FtpState::Pwd, io);
        Ok(())
    }

    /// `ftp_state_loggedin` (`lib/ftp.c:2796-2825`): after `USER`, `PASS` and
    /// `ACCT`.
    ///
    /// On a secure control channel the draft quoted in the C requires `PBSZ`
    /// before `PROT`, with a parameter of exactly `0` *"to indicate that no
    /// buffering is taking place"*. Otherwise the login is finished and `PWD`
    /// follows.
    ///
    /// # Errors
    ///
    /// As [`Self::send`].
    fn state_loggedin(
        &mut self,
        pp: &mut PingPong,
        io: &mut FtpIo<'_>,
    ) -> CurlResult<()> {
        if io.req().control_ssl {
            self.send(pp, io, b"PBSZ 0")?;
            self.set_state(FtpState::Pbsz, io);
            Ok(())
        } else {
            self.state_pwd(pp, io)
        }
    }

    /// `ftp_state_quote` (`lib/ftp.c:1719-1837`): walk one quote list, then
    /// continue where that list leads.
    ///
    /// Three things are load-bearing and all three are the C's. `count1` is the
    /// index into the list, so an entry is sent per reply rather than all at
    /// once. `count2` records whether the entry may fail: a leading `*` is
    /// removed and permits any reply, which is why the marker never reaches the
    /// wire. And the continuation depends on WHICH list ran out -- the regular
    /// list leads to `CWD`, the three prequote lists to the transfer they
    /// precede, and the postquote list to nothing.
    ///
    /// # Errors
    ///
    /// As [`Self::send`], plus whatever the continuation reports.
    fn state_quote(
        &mut self,
        pp: &mut PingPong,
        io: &mut FtpIo<'_>,
        init: bool,
        instate: FtpState,
    ) -> CurlResult<()> {
        if init {
            self.ftpc.count1 = 0;
        } else {
            self.ftpc.count1 = self.ftpc.count1.saturating_add(1);
        }

        let index = usize::try_from(self.ftpc.count1).unwrap_or(usize::MAX);
        let entry = {
            let opts = io.opts();
            let list = match instate {
                FtpState::RetrPrequote
                | FtpState::StorPrequote
                | FtpState::ListPrequote => &opts.prequote,
                FtpState::Postquote => &opts.postquote,
                _ => &opts.quote,
            };
            list.get(index).cloned()
        };

        if let Some(entry) = entry {
            let allows_failure = entry.first() == Some(&b'*');
            let cmd: &[u8] = if allows_failure {
                entry.get(1..).unwrap_or(&[])
            } else {
                &entry
            };
            self.ftpc.count2 = i32::from(allows_failure);
            let cmd = cmd.to_vec();
            self.send(pp, io, &cmd)?;
            self.set_state(instate, io);
            return Ok(());
        }

        match instate {
            FtpState::RetrPrequote => self.retr_prequote_done(pp, io),
            FtpState::StorPrequote => self.state_ul_setup(pp, io, false),
            FtpState::Postquote => Ok(()),
            FtpState::ListPrequote => {
                self.set_state(FtpState::ListType, io);
                self.state_list(pp, io)
            }
            _ => self.state_cwd(pp, io),
        }
    }

    /// The `FTP_RETR_PREQUOTE` continuation of [`Self::state_quote`]
    /// (`lib/ftp.c:1789-1826`).
    ///
    /// `SIZE` is skipped in two cases and the C explains both: with
    /// `CURLOPT_IGNORE_CONTENT_LENGTH`, because *"it prevents the state machine
    /// from requesting the file size from the server"* so a growing file can be
    /// followed; and in ASCII mode, because *"servers do not report the
    /// converted size"*. A size the wildcard driver already knows skips it too.
    ///
    /// # Errors
    ///
    /// As [`Self::send`].
    fn retr_prequote_done(
        &mut self,
        pp: &mut PingPong,
        io: &mut FtpIo<'_>,
    ) -> CurlResult<()> {
        if self.transfer.transfer != PpTransfer::Body {
            self.set_state(FtpState::Stop, io);
            return Ok(());
        }

        let known = self.ftpc.known_filesize;
        if known != -1 {
            io.client_mut().pgrs_set_download_size(known);
            return self.state_retr(pp, io, known);
        }

        let skip_size =
            io.opts().ignore_content_length || io.req().prefer_ascii;
        let file = self.ftpc.file().unwrap_or(&[]).to_vec();
        if skip_size {
            let cmd = Self::command_with(b"RETR ", &file);
            self.send(pp, io, &cmd)?;
            self.set_state(FtpState::Retr, io);
        } else {
            let cmd = Self::command_with(b"SIZE ", &file);
            self.send(pp, io, &cmd)?;
            self.set_state(FtpState::RetrSize, io);
        }
        Ok(())
    }

    /// `ftp_state_cwd` (`lib/ftp.c:817-866`): the range of `CWD` commands that
    /// reaches the transfer's directory.
    ///
    /// A reused connection is walked back to its entry path first, because the
    /// previous transfer left it somewhere else -- unless the path is absolute,
    /// in which case there is nowhere to go back to. `cwdcount` starts at zero
    /// for that first `CWD` and at one otherwise, which is what makes the reply
    /// handler's `cwdcount >= dirdepth` test come out right in both cases.
    ///
    /// # Errors
    ///
    /// As [`Self::send`].
    fn state_cwd(
        &mut self,
        pp: &mut PingPong,
        io: &mut FtpIo<'_>,
    ) -> CurlResult<()> {
        if self.ftpc.cwddone {
            return self.state_mdtm(pp, io);
        }

        self.ftpc.count2 = 0;
        let absolute = self.ftpc.dirdepth() > 0
            && self.ftpc.rawpath().first() == Some(&b'/');
        let entry = self.ftpc.entrypath.clone();

        if io.req().reuse && entry.is_some() && !absolute {
            let entry = entry.unwrap_or_default();
            self.ftpc.cwdcount = 0;
            let cmd = Self::command_with(b"CWD ", &entry);
            self.send(pp, io, &cmd)?;
            self.set_state(FtpState::Cwd, io);
            return Ok(());
        }

        if self.ftpc.dirdepth() > 0 {
            self.ftpc.cwdcount = 1;
            let piece = self.ftpc.pathpiece(0).unwrap_or(&[]).to_vec();
            let cmd = Self::command_with(b"CWD ", &piece);
            self.send(pp, io, &cmd)?;
            self.set_state(FtpState::Cwd, io);
            return Ok(());
        }

        self.state_mdtm(pp, io)
    }

    /// `ftp_state_mdtm` (`lib/ftp.c:1515-1535`): ask for the modification
    /// time, when one was requested.
    ///
    /// The C's own note: `MDTM` *"is not mentioned in RFC959"*, so it is sent
    /// only when the answer is wanted.
    ///
    /// # Errors
    ///
    /// As [`Self::send`].
    fn state_mdtm(
        &mut self,
        pp: &mut PingPong,
        io: &mut FtpIo<'_>,
    ) -> CurlResult<()> {
        let wanted = io.opts().get_filetime
            || io.opts().timecondition != TimeCondition::None;
        if wanted && self.ftpc.has_file() {
            let file = self.ftpc.file().unwrap_or(&[]).to_vec();
            let cmd = Self::command_with(b"MDTM ", &file);
            self.send(pp, io, &cmd)?;
            self.set_state(FtpState::Mdtm, io);
            return Ok(());
        }
        self.state_type(pp, io)
    }

    /// `ftp_state_type` (`lib/ftp.c:1478-1513`): a head-like request needs the
    /// transfer type set before `SIZE`, because *"some servers return different
    /// sizes for different modes"*.
    ///
    /// # Errors
    ///
    /// As [`Self::send`].
    fn state_type(
        &mut self,
        pp: &mut PingPong,
        io: &mut FtpIo<'_>,
    ) -> CurlResult<()> {
        let ascii = io.req().prefer_ascii;
        if io.opts().no_body
            && self.ftpc.has_file()
            && self.ftpc.need_type(ascii)
        {
            // "this means no actual transfer will be made"
            self.transfer.transfer = PpTransfer::Info;
            return self.nb_type(pp, io, ascii, FtpState::Type);
        }
        self.state_size(pp, io)
    }

    /// `ftp_state_size` (`lib/ftp.c:1379-1402`): `SIZE` for a head-like
    /// request on a file.
    ///
    /// # Errors
    ///
    /// As [`Self::send`].
    fn state_size(
        &mut self,
        pp: &mut PingPong,
        io: &mut FtpIo<'_>,
    ) -> CurlResult<()> {
        if self.transfer.transfer == PpTransfer::Info && self.ftpc.has_file() {
            let file = self.ftpc.file().unwrap_or(&[]).to_vec();
            let cmd = Self::command_with(b"SIZE ", &file);
            self.send(pp, io, &cmd)?;
            self.set_state(FtpState::Size, io);
            return Ok(());
        }
        self.state_rest(pp, io)
    }

    /// `ftp_state_rest` (`lib/ftp.c:1358-1377`): `REST 0`, which asks whether
    /// the server supports ranges at all.
    ///
    /// The literal zero is the C's `Curl_pp_sendf(..., "REST %d", 0)`, and it
    /// appears on the wire as `REST 0` -- `tests/data/test104` and
    /// `test141` both pin it.
    ///
    /// # Errors
    ///
    /// As [`Self::send`].
    fn state_rest(
        &mut self,
        pp: &mut PingPong,
        io: &mut FtpIo<'_>,
    ) -> CurlResult<()> {
        if self.transfer.transfer != PpTransfer::Body && self.ftpc.has_file() {
            self.send(pp, io, b"REST 0")?;
            self.set_state(FtpState::Rest, io);
            return Ok(());
        }
        self.state_prepare_transfer(pp, io)
    }

    /// The `LIST`, `NLST` or custom command word, without an argument
    /// (`lib/ftp.c:1341-1346` and `:1435-1440`).
    fn list_verb(io: &FtpIo<'_>) -> Vec<u8> {
        match io.opts().custom_request.as_deref() {
            Some(custom) => custom.to_vec(),
            None => {
                if io.req().list_only {
                    b"NLST".to_vec()
                } else {
                    b"LIST".to_vec()
                }
            }
        }
    }

    /// `ftp_state_prepare_transfer` (`lib/ftp.c:1311-1354`): start `PORT`,
    /// `PASV` or `PRET`.
    ///
    /// The C's comment marks this as the point of no return: *"REST is the last
    /// command in the chain of commands when a "head"-like request is made.
    /// Thus, if an actual transfer is to be made this is where we take off for
    /// real."*
    ///
    /// # Errors
    ///
    /// As [`Self::send`], plus whatever the active or passive setup reports.
    fn state_prepare_transfer(
        &mut self,
        pp: &mut PingPong,
        io: &mut FtpIo<'_>,
    ) -> CurlResult<()> {
        if self.transfer.transfer != PpTransfer::Body {
            // "does not transfer any data" -- but the prequote list still runs.
            self.set_state(FtpState::RetrPrequote, io);
            return self.state_quote(pp, io, true, FtpState::RetrPrequote);
        }

        if io.opts().use_port {
            return self.state_use_port(pp, io, FtpPortCmd::Eprt);
        }

        if io.opts().use_pret {
            let cmd = if self.ftpc.has_file() {
                let file = self.ftpc.file().unwrap_or(&[]).to_vec();
                if io.req().upload {
                    Self::command_with(b"PRET STOR ", &file)
                } else {
                    Self::command_with(b"PRET RETR ", &file)
                }
            } else {
                Self::command_with(b"PRET ", &Self::list_verb(io))
            };
            self.send(pp, io, &cmd)?;
            self.set_state(FtpState::Pret, io);
            return Ok(());
        }

        self.state_use_pasv(pp, io)
    }

    /// `ftp_state_list` (`lib/ftp.c:1404-1461`): the listing command, with its
    /// one conditional argument.
    ///
    /// The composition is `"%s%s%.*s"`: the verb, a single space ONLY when an
    /// argument follows, and the argument. The argument exists only under
    /// [`FileMethod::NoCwd`], where no `CWD` has moved the server into the
    /// directory, and it is the decoded path up to the last slash -- with the
    /// slash kept when the path is exactly `/`.
    ///
    /// # Errors
    ///
    /// As [`Self::send`].
    fn state_list(
        &mut self,
        pp: &mut PingPong,
        io: &mut FtpIo<'_>,
    ) -> CurlResult<()> {
        let mut cmd = Self::list_verb(io);

        if io.req().file_method == FileMethod::NoCwd {
            let raw = self.ftpc.rawpath();
            if let Some(slash) = raw.iter().rposition(|&byte| byte == b'/') {
                // "chop off the file part if format is dir/file otherwise
                // remove the trailing slash for dir/dir/ except for absolute
                // path /"
                let len = if slash == 0 { 1 } else { slash };
                if let Some(argument) = raw.get(..len) {
                    let argument = argument.to_vec();
                    cmd.push(b' ');
                    cmd.extend_from_slice(&argument);
                }
            }
        }

        self.send(pp, io, &cmd)?;
        self.set_state(FtpState::List, io);
        Ok(())
    }

    /// `ftp_state_ul_setup` (`lib/ftp.c:1540-1636`): `STOR` or `APPE`, after
    /// whatever the resume offset requires.
    ///
    /// Resuming an upload does not use `REST`. The C's numbered comment
    /// explains: *"This used to set REST. But since we can do append, we do not
    /// another ftp command. We just skip the source file offset and then we
    /// APPEND the rest on the file instead"*. Skipping means seeking, and a
    /// source that cannot seek is read and discarded instead -- the only place
    /// in this module that reads the upload body.
    ///
    /// # Errors
    ///
    /// [`CURLcode::FtpCouldntUseRest`] when the source can neither seek nor be
    /// read past the offset, and whatever [`Self::send`] reports.
    fn state_ul_setup(
        &mut self,
        pp: &mut PingPong,
        io: &mut FtpIo<'_>,
        sizechecked: bool,
    ) -> CurlResult<()> {
        let mut append = io.opts().remote_append;
        let resume_from = io.req().resume_from;

        if (resume_from != 0 && !sizechecked)
            || (resume_from > 0 && sizechecked)
        {
            if resume_from < 0 {
                // "Got no given size to start from, figure it out"
                let file = self.ftpc.file().unwrap_or(&[]).to_vec();
                let cmd = Self::command_with(b"SIZE ", &file);
                self.send(pp, io, &cmd)?;
                self.set_state(FtpState::StorSize, io);
                return Ok(());
            }

            append = true;
            self.skip_upload_prefix(io, resume_from)?;

            if io.req().infilesize > 0 {
                let left = io.req().infilesize.saturating_sub(resume_from);
                io.req_mut().infilesize = left;
                if left <= 0 {
                    io.client_mut().infof(format_args!(
                        "File already completely uploaded"
                    ));
                    io.client_mut().xfer_setup_nop();
                    // "Set ->transfer so that we will not get any error in
                    // ftp_done() because we did not transfer anything!"
                    self.transfer.transfer = PpTransfer::None;
                    self.set_state(FtpState::Stop, io);
                    return Ok(());
                }
            }
        }

        let file = self.ftpc.file().unwrap_or(&[]).to_vec();
        let cmd = if append {
            Self::command_with(b"APPE ", &file)
        } else {
            Self::command_with(b"STOR ", &file)
        };
        self.send(pp, io, &cmd)?;
        self.set_state(FtpState::Stor, io);
        Ok(())
    }

    /// The seek-or-discard half of [`Self::state_ul_setup`]
    /// (`lib/ftp.c:1572-1608`).
    ///
    /// # Errors
    ///
    /// [`CURLcode::FtpCouldntUseRest`] with the C's two texts: *"Could not
    /// seek stream"* for a refusal, and *"Failed to read data"* for a source
    /// that ends early or over-reports.
    fn skip_upload_prefix(
        &mut self,
        io: &mut FtpIo<'_>,
        resume_from: i64,
    ) -> CurlResult<()> {
        match io.client_mut().seek(resume_from) {
            SeekOutcome::Ok => return Ok(()),
            SeekOutcome::Fail => {
                io.client_mut().failf(format_args!("Could not seek stream"));
                return Err(Error::with_context(
                    CURLcode::FtpCouldntUseRest,
                    "Could not seek stream",
                ));
            }
            SeekOutcome::CantSeek => {}
        }

        let mut passed = 0_i64;
        while passed < resume_from {
            let mut scratch = [0_u8; 4 * 1024];
            let remaining = resume_from.saturating_sub(passed);
            let want = usize::try_from(remaining)
                .unwrap_or(scratch.len())
                .min(scratch.len());
            let slice = match scratch.get_mut(..want) {
                Some(slice) => slice,
                None => break,
            };
            let read = io.client_mut().read_input(slice).map_err(Error::new)?;
            passed = passed.saturating_add(i64::try_from(read).unwrap_or(0));
            // "this checks for greater-than only to make sure that the
            // CURL_READFUNC_ABORT return code still aborts"
            if read == 0 || read > want {
                io.client_mut().failf(format_args!("Failed to read data"));
                return Err(Error::with_context(
                    CURLcode::FtpCouldntUseRest,
                    "Failed to read data",
                ));
            }
        }
        Ok(())
    }

    /// `ftp_state_retr` (`lib/ftp.c:1639-1719`): `RETR`, with `REST` in front
    /// of it when the download resumes.
    ///
    /// # Errors
    ///
    /// [`CURLcode::FilesizeExceeded`] past `CURLOPT_MAXFILESIZE`,
    /// [`CURLcode::BadDownloadResume`] for an offset beyond the file, and
    /// whatever [`Self::send`] reports.
    fn state_retr(
        &mut self,
        pp: &mut PingPong,
        io: &mut FtpIo<'_>,
        filesize: i64,
    ) -> CurlResult<()> {
        let state = self.ftpc.state();
        io.client_mut().trc_ftp(format_args!(
            "[{}] ftp_state_retr()",
            cstate(Some(state))
        ));

        let max_filesize = io.opts().max_filesize;
        if max_filesize != 0 && filesize > max_filesize {
            io.client_mut()
                .failf(format_args!("Maximum file size exceeded"));
            return Err(Error::with_context(
                CURLcode::FilesizeExceeded,
                "Maximum file size exceeded",
            ));
        }
        self.transfer.downloadsize = filesize;

        let resume_from = io.req().resume_from;
        if resume_from == 0 {
            let file = self.ftpc.file().unwrap_or(&[]).to_vec();
            let cmd = Self::command_with(b"RETR ", &file);
            self.send(pp, io, &cmd)?;
            self.set_state(FtpState::Retr, io);
            return Ok(());
        }

        if filesize == -1 {
            // "We could not get the size and therefore we cannot know if there
            // really is a part of the file left to get"
            io.client_mut()
                .infof(format_args!("ftp server does not support SIZE"));
        } else if resume_from < 0 {
            // "We are supposed to download the last abs(from) bytes"
            if filesize < resume_from.saturating_neg() {
                return Err(self.resume_beyond(io, resume_from, filesize));
            }
            self.transfer.downloadsize = resume_from.saturating_neg();
            io.req_mut().resume_from =
                filesize.saturating_sub(self.transfer.downloadsize);
        } else {
            if filesize < resume_from {
                return Err(self.resume_beyond(io, resume_from, filesize));
            }
            self.transfer.downloadsize = filesize.saturating_sub(resume_from);
        }

        if self.transfer.downloadsize == 0 {
            io.client_mut().xfer_setup_nop();
            io.client_mut()
                .infof(format_args!("File already completely downloaded"));
            self.transfer.transfer = PpTransfer::None;
            self.set_state(FtpState::Stop, io);
            return Ok(());
        }

        let resume_from = io.req().resume_from;
        io.client_mut().infof(format_args!(
            "Instructs server to resume from offset {resume_from}"
        ));
        let cmd = format!("REST {resume_from}").into_bytes();
        self.send(pp, io, &cmd)?;
        self.set_state(FtpState::RetrRest, io);
        Ok(())
    }

    /// The two identical `failf` sites of [`Self::state_retr`]
    /// (`lib/ftp.c:1667-1671` and `:1679-1683`), which report the same text
    /// with the same two numbers.
    fn resume_beyond(
        &mut self,
        io: &mut FtpIo<'_>,
        resume_from: i64,
        filesize: i64,
    ) -> Error {
        let message =
            format!("Offset ({resume_from}) was beyond file size ({filesize})");
        io.client_mut().failf(format_args!("{message}"));
        Error::with_context(CURLcode::BadDownloadResume, message)
    }

    /// `ftp_nb_type` (`lib/ftp.c:3697-3726`): set the transfer type, or notice
    /// that it is already set.
    ///
    /// When it is already set the C sends NOTHING and calls the reply handler
    /// with a synthetic `200` -- *"If the transfer type is not sent, simulate
    /// on OK response in newstate"* -- which is why a second transfer over one
    /// connection emits no second `TYPE`. Reproducing that exactly is what
    /// keeps `tests/data/test1113`'s wildcard sequence byte-identical: one
    /// `TYPE A` for the listing, one `TYPE I` for the first file, and none for
    /// the files after it.
    ///
    /// # Errors
    ///
    /// As [`Self::send`], plus whatever the synthetic reply's handler reports.
    fn nb_type(
        &mut self,
        pp: &mut PingPong,
        io: &mut FtpIo<'_>,
        ascii: bool,
        newstate: FtpState,
    ) -> CurlResult<()> {
        let want = if ascii { b'A' } else { b'I' };
        if self.ftpc.transfertype == want {
            self.set_state(newstate, io);
            return self.state_type_resp(pp, io, 200, newstate);
        }

        let cmd = [b'T', b'Y', b'P', b'E', b' ', want];
        self.send(pp, io, &cmd)?;
        self.set_state(newstate, io);
        self.ftpc.transfertype = want;
        Ok(())
    }

    /// `ftp_initiate_transfer` (`lib/ftp.c:533-573`): the data connection is
    /// up, so wire the transfer to it.
    ///
    /// The two directions differ in exactly the way the C's comments say. An
    /// upload shuts the data connection down and IGNORES errors doing so,
    /// *"as we rely on the server response on the CONTROL connection"*; a
    /// download does not ignore them. Both then expect a reply on the control
    /// channel, which is what `pending_resp` records.
    ///
    /// # Errors
    ///
    /// Whatever the connect reports.
    fn initiate_transfer(
        &mut self,
        pp: &mut PingPong,
        io: &mut FtpIo<'_>,
    ) -> CurlResult<()> {
        io.client_mut()
            .trc_ftp(format_args!("ftp_initiate_transfer()"));

        let connected = {
            let (chains, mut cx) = io.split();
            self.seams
                .connect(chains, &mut cx, SocketIndex::Secondary, true)
                .map_err(Error::new)?
        };
        if !connected {
            return Ok(());
        }

        if io.req().upload {
            let infilesize = io.req().infilesize;
            io.client_mut().pgrs_set_upload_size(infilesize);
            io.client_mut().xfer_setup_send(SocketIndex::Secondary);
            io.client_mut().xfer_set_shutdown(true, true);
        } else {
            let size = io.req().size;
            io.client_mut()
                .xfer_setup_recv(SocketIndex::Secondary, size);
            io.client_mut().xfer_set_shutdown(true, false);
        }

        pp.set_pending_resp(true);
        self.set_state(FtpState::Stop, io);
        Ok(())
    }

    /// Read whatever complete reply is already available, without waiting.
    ///
    /// `getftpresponse` is the C's blocking read and is preserved as
    /// [`getftpresponse`] for the two callers that can await -- `ftp_done` and
    /// the postquote list. This is the third caller's form:
    /// [`Self::check_ctrl_on_data_wait`] runs inside the synchronous state
    /// machine and reaches the read only after establishing that bytes are
    /// already there, so nothing has to wait. A reply that is nevertheless
    /// incomplete answers code `0`, which the caller treats as *"no verdict
    /// yet"* and returns to the wait -- where the C would have blocked.
    ///
    /// # Errors
    ///
    /// Whatever the framer reports.
    fn read_response_now(
        &mut self,
        pp: &mut PingPong,
        io: &mut FtpIo<'_>,
    ) -> CurlResult<(usize, i32)> {
        let mut total = 0_usize;
        // A bound rather than a `loop`: each lap either completes a reply or
        // consumes what was buffered, so the cap is never reached in practice
        // and its presence means a transport that reports readable bytes it
        // then refuses to deliver cannot spin here.
        for _ in 0..64_u32 {
            let response = ftp_readresp(self, pp, io, SocketIndex::First)?;
            total = total.saturating_add(response.size);
            if response.code != 0 {
                pp.set_pending_resp(false);
                return Ok((total, response.code));
            }
            if pp.overflow() == 0 && !io.data_pending(SocketIndex::First) {
                break;
            }
        }
        Ok((total, 0))
    }

    /// `ftp_check_ctrl_on_data_wait` (`lib/ftp.c:455-529`): while waiting for
    /// the server to connect back, watch the control channel.
    ///
    /// Three outcomes, and the middle one is the subtle one:
    ///
    /// * a cached reply whose first digit is above `3` means the data
    ///   connection will never come, and the wait is abandoned;
    /// * a cached `226` means the transfer has ALREADY finished on the control
    ///   channel before the data channel was noticed -- *"funny timing
    ///   situation"* -- and the C deliberately leaves the reply in the buffer
    ///   and treats it as a trigger to read the data socket, so this reports
    ///   success and changes nothing;
    /// * any other reply is read and judged: `4xx` and above is an accept
    ///   failure, anything else is a weird reply.
    ///
    /// # Errors
    ///
    /// [`CURLcode::FtpAcceptFailed`] and [`CURLcode::WeirdServerReply`], as the
    /// C reports them.
    fn check_ctrl_on_data_wait(
        &mut self,
        pp: &mut PingPong,
        io: &mut FtpIo<'_>,
    ) -> CurlResult<()> {
        if let Some(&first) = pp.recvbuf().first() {
            if !first.is_ascii_digit() || first > b'3' {
                io.client_mut().infof(format_args!(
                    "There is negative response in cache while serv connect"
                ));
                let _ = self.read_response_now(pp, io)?;
                return Err(Error::new(CURLcode::FtpAcceptFailed));
            }
        }

        let mut response = pp.overflow() != 0;
        if !response {
            let sock = io.socket_of(SocketIndex::First);
            let state = self.seams.readable_now(sock);
            if state < 0 {
                io.client_mut().failf(format_args!(
                    "Error while waiting for server connect"
                ));
                return Err(Error::with_context(
                    CURLcode::FtpAcceptFailed,
                    "Error while waiting for server connect",
                ));
            }
            let bits = u32::try_from(state).unwrap_or(0);
            response = bits & CURL_CSELECT_IN != 0;
        }

        if !response {
            return Ok(());
        }

        io.client_mut().infof(format_args!(
            "Ctrl conn has data while waiting for data conn"
        ));

        if pp.overflow() > 3 {
            let buffered = pp.recvbuf();
            if let Some(rest) = buffered.get(pp.nfinal()..) {
                let mut code = 0_i32;
                if ftp_endofresp(rest, &mut code) && code == 226 {
                    io.client_mut()
                        .infof(format_args!("Got 226 before data activity"));
                    return Ok(());
                }
            }
        }

        let (_nread, ftpcode) = self.read_response_now(pp, io)?;
        io.client_mut()
            .infof(format_args!("FTP code: {ftpcode:03}"));

        if ftpcode / 100 > 3 {
            return Err(Error::new(CURLcode::FtpAcceptFailed));
        }
        Err(Error::new(CURLcode::WeirdServerReply))
    }
}

// Active mode: CURLOPT_FTPPORT, EPRT and PORT

/// What a `CURLOPT_FTPPORT` string asked for -- the result of
/// `ftp_state_use_port`'s *"Step 1, figure out what is requested"*
/// (`lib/ftp.c:906-981`).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct FtpPortSpec {
    /// The address, interface name or host name, if one was given.
    pub(crate) addr: Option<Vec<u8>>,
    /// The first port to try.
    pub(crate) port_min: u16,
    /// The last port to try.
    pub(crate) port_max: u16,
}

/// Parse `CURLOPT_FTPPORT` -- *"(ipv4|ipv6|domain|interface)?(:port(-range)?)?"*
/// (`lib/ftp.c:903-981`).
///
/// The forms, all measured from the C and all tested below: a bare host,
/// address or interface name; a bracketed IPv6 literal with an optional port;
/// a bare IPv6 literal, which is recognised by [`pton6`] and carries no port
/// because its colons are its own; `:port`; and `host:min-max`.
///
/// # The lone-port case is the AAP's, not the C's
///
/// For `:1234` the C parses `port_min = 1234` and leaves `port_max` at zero,
/// because its `else port_max = port_min;` sits on the branch where the FIRST
/// number FAILED to parse rather than on the branch where no dash followed
/// (`lib/ftp.c:953-981`). The correction that follows -- *"if(port_min >
/// port_max) port_min = port_max = 0"* -- then discards the port entirely, so
/// the C binds to any port for a specification that named one. The AAP resolves
/// this explicitly: **a lone port sets `port_min == port_max`**, which is what
/// the option's documentation describes and what this implements. An inverted
/// or otherwise invalid range still zeroes both, exactly as the C does.
pub(crate) fn parse_ftpport(spec: &[u8]) -> FtpPortSpec {
    let mut parsed = FtpPortSpec::default();
    // "strlen(data->set.str[STRING_FTPPORT]) > 1" -- a one-byte specification
    // is ignored outright, which is how `-P -` reaches the default path.
    if spec.len() <= 1 {
        return parsed;
    }

    let mut port_text: Option<&[u8]> = None;
    match spec.first() {
        Some(&b'[') => {
            // "[ipv6]:port(-range)"
            if let Some(close) = spec.iter().position(|&byte| byte == b']') {
                parsed.addr = spec.get(1..close).map(<[u8]>::to_vec);
                port_text = spec.get(close..);
            }
        }
        Some(&b':') => {
            // ":port"
            port_text = Some(spec);
        }
        _ => {
            match spec.iter().position(|&byte| byte == b':') {
                Some(colon) => {
                    if pton6(spec).is_some() {
                        // A bare IPv6 literal: "this got no port !"
                        parsed.addr = Some(spec.to_vec());
                    } else {
                        parsed.addr = spec.get(..colon).map(<[u8]>::to_vec);
                        port_text = spec.get(colon..);
                    }
                }
                // "ipv4|interface"
                None => parsed.addr = Some(spec.to_vec()),
            }
        }
    }

    if let Some(text) = port_text {
        if let Some(after) = text.iter().position(|&byte| byte == b':') {
            let mut cursor = text.get(after.saturating_add(1)..).unwrap_or(&[]);
            if let Ok(first) = str_number(&mut cursor, 0xffff) {
                parsed.port_min = u16::try_from(first).unwrap_or(0);
                // The AAP's resolution: a lone port is a one-port range.
                parsed.port_max = parsed.port_min;
                if str_single(&mut cursor, b'-').is_ok() {
                    match str_number(&mut cursor, 0xffff) {
                        Ok(last) => {
                            parsed.port_max = u16::try_from(last).unwrap_or(0);
                        }
                        // "correct errors like :1234-1230 / :-4711": a dash
                        // with nothing usable after it leaves the range
                        // inverted, which the check below zeroes.
                        Err(_) => parsed.port_max = 0,
                    }
                }
            }
        }
    }

    if parsed.port_min > parsed.port_max {
        parsed.port_min = 0;
        parsed.port_max = 0;
    }
    parsed
}

/// Render an address exactly as `curlx_inet_ntop` does.
///
/// [`ntop4`] and [`ntop6`] are the crate's own successors of it, and they are
/// used here rather than [`std::net::IpAddr`]'s [`fmt::Display`] because the two
/// disagree for IPv6: the standard library lower-cases and compresses by its own
/// rules, and an `EPRT` argument is wire text whose exact spelling the fixtures
/// compare. `lib/ftp.c:1029-1036` selects between the two by family, and so
/// does this.
pub(crate) fn printable_address(addr: std::net::IpAddr) -> String {
    match addr {
        std::net::IpAddr::V4(v4) => ntop4(&v4.octets()),
        std::net::IpAddr::V6(v6) => ntop6(&v6.octets()),
    }
}

/// The `EPRT` argument's family digit -- `sa->sa_family == AF_INET ? 1 : 2`
/// (`lib/ftp.c:1202`).
pub(crate) const fn eprt_family(addr: std::net::IpAddr) -> u8 {
    match addr {
        std::net::IpAddr::V4(_) => 1,
        std::net::IpAddr::V6(_) => 2,
    }
}

/// The `EPRT` command for an address and port.
///
/// `Curl_pp_sendf(data, &ftpc->pp, "%s |%d|%s|%hu|", mode[fcmd], family,
/// myhost, port)`, with the C's own two examples from RFC 2428 as the tests:
/// `EPRT |1|132.235.1.2|6275|` and `EPRT |2|1080::8:800:200C:417A|5282|`.
pub(crate) fn eprt_command(
    host: &str,
    addr: std::net::IpAddr,
    port: u16,
) -> Vec<u8> {
    let family = eprt_family(addr);
    format!("EPRT |{family}|{host}|{port}|").into_bytes()
}

/// The `PORT` command for an IPv4 address and port.
///
/// `lib/ftp.c:1210-1229`: every dot becomes a comma, then `,<high>,<low>` is
/// appended. `132.235.1.2` on port `6275` becomes exactly
/// `PORT 132,235,1,2,24,131`.
pub(crate) fn port_command(host: &str, port: u16) -> Vec<u8> {
    let mut target = String::with_capacity(host.len().saturating_add(8));
    for ch in host.chars() {
        target.push(if ch == '.' { ',' } else { ch });
    }
    let high = port >> 8;
    let low = port & 0xff;
    format!("PORT {target},{high},{low}").into_bytes()
}

impl FtpMachine<'_> {
    /// `ftp_state_use_port` (`lib/ftp.c:874-1270`): open a listening socket and
    /// tell the server where to connect.
    ///
    /// The five steps are the C's, in its order and with its diagnostics:
    /// decide what was requested, create a socket, bind it -- retrying across
    /// the port range and falling back to the control connection's own address
    /// when the requested one is not local -- listen, and send `EPRT` or
    /// `PORT`.
    ///
    /// Two conditionals are easy to get backwards and are called out. `EPRT` is
    /// FORCED back on for an IPv6 control connection even when it was disabled,
    /// because `PORT` cannot express an IPv6 address; and `PORT` is skipped for
    /// every family except IPv4 for the same reason.
    ///
    /// # Errors
    ///
    /// [`CURLcode::FtpPortFailed`] for every failure of the setup, which is the
    /// C's single `result` value on the `out:` path.
    fn state_use_port(
        &mut self,
        pp: &mut PingPong,
        io: &mut FtpIo<'_>,
        fcmd: FtpPortCmd,
    ) -> CurlResult<()> {
        let outcome = self.use_port_inner(pp, io, fcmd);
        match outcome {
            Ok(()) => {
                // "successfully setup the list socket filter. Do we need more?"
                let wants_data_tls = io.req().data_ssl && io.opts().use_port;
                if wants_data_tls && !io.is_ssl(SocketIndex::Secondary) {
                    let (chains, mut cx) = io.split();
                    self.seams
                        .add_tls_filter(chains, &mut cx, SocketIndex::Secondary)
                        .map_err(Error::new)?;
                }
                io.req_mut().do_more = false;
                io.client_mut().pgrs_time_start_accept();
                let configured = io.opts().accept_timeout_ms;
                let delay = if configured > 0 {
                    configured
                } else {
                    DEFAULT_ACCEPT_TIMEOUT
                };
                io.client_mut().expire(delay, TimerId::FtpAccept);
                Ok(())
            }
            Err(error) => {
                self.seams.listener_close();
                self.set_state(FtpState::Stop, io);
                Err(error)
            }
        }
    }

    /// Steps one to five of [`Self::state_use_port`], so that the C's `out:`
    /// label becomes an ordinary early return.
    ///
    /// # Errors
    ///
    /// As [`Self::state_use_port`].
    fn use_port_inner(
        &mut self,
        pp: &mut PingPong,
        io: &mut FtpIo<'_>,
        fcmd: FtpPortCmd,
    ) -> CurlResult<()> {
        let spec = io.opts().ftpport.clone().unwrap_or_default();
        let parsed = parse_ftpport(&spec);
        let mut possibly_non_local = true;

        let host = match parsed.addr.as_deref() {
            Some(addr) => {
                let family = self.seams.control_family();
                let scope = self.seams.control_remote_scope();
                let scope_id = io.req().scope_id;
                match self.seams.if2ip(family, scope, scope_id, addr) {
                    // "not an interface, use the given string as hostname
                    // instead"
                    If2IpResult::NotFound => addr.to_vec(),
                    If2IpResult::AfNotSupported => {
                        return Err(Error::with_context(
                            CURLcode::FtpPortFailed,
                            "the interface's address family is unsupported",
                        ))
                    }
                    If2IpResult::Found(text) => text.into_bytes(),
                }
            }
            None => {
                // "not an interface and not a hostname, get default by
                // extracting the IP from the control connection"
                let Some(local) = self.seams.control_local_addr() else {
                    let errno = io.client().sock_errno();
                    let message = format!("getsockname() failed: {errno}");
                    io.client_mut().failf(format_args!("{message}"));
                    return Err(Error::with_context(
                        CURLcode::FtpPortFailed,
                        message,
                    ));
                };
                possibly_non_local = false; // "we know it is local now"
                printable_address(local).into_bytes()
            }
        };

        let addrs = match self.seams.resolve(&host, 0) {
            Ok(addrs) if !addrs.is_empty() => addrs,
            _ => {
                let shown = String::from_utf8_lossy(&host).into_owned();
                let message = format!(
                    "failed to resolve the address provided to PORT: {shown}"
                );
                io.client_mut().failf(format_args!("{message}"));
                return Err(Error::with_context(
                    CURLcode::FtpPortFailed,
                    message,
                ));
            }
        };

        // Step 2: "create a socket for the requested address", taking the first
        // address the transport accepts.
        let mut opened: Option<std::net::IpAddr> = None;
        let mut last: Option<SockFailure> = None;
        for candidate in &addrs {
            match self.seams.listener_open(*candidate) {
                Ok(()) => {
                    opened = Some(*candidate);
                    break;
                }
                Err(failure) => last = Some(failure),
            }
        }
        let Some(resolved) = opened else {
            let reason =
                last.map(|failure| failure.message).unwrap_or_default();
            let message = format!("socket failure: {reason}");
            io.client_mut().failf(format_args!("{message}"));
            return Err(Error::with_context(CURLcode::FtpPortFailed, message));
        };
        let state = self.ftpc.state();
        io.client_mut().trc_ftp(format_args!(
            "[{}] ftp_state_use_port(), opened socket",
            cstate(Some(state))
        ));

        // Step 3: "bind to a suitable local address".
        let (bound_addr, port) =
            self.bind_listener(io, resolved, &parsed, &mut possibly_non_local)?;
        let state = self.ftpc.state();
        io.client_mut().trc_ftp(format_args!(
            "[{}] ftp_state_use_port(), socket bound to port {port}",
            cstate(Some(state))
        ));

        // Step 4: "listen on the socket".
        if let Err(failure) = self.seams.listener_listen() {
            let message = format!("socket failure: {}", failure.message);
            io.client_mut().failf(format_args!("{message}"));
            return Err(Error::with_context(CURLcode::FtpPortFailed, message));
        }
        let state = self.ftpc.state();
        io.client_mut().trc_ftp(format_args!(
            "[{}] ftp_state_use_port(), listening on {port}",
            cstate(Some(state))
        ));

        // Step 5: "send the proper FTP command". `myhost` is the printable form
        // of the RESOLVED address, which is what the C prints even after the
        // non-local fallback replaced the address it bound to; the family digit
        // comes from the address actually bound, as the C's `sa->sa_family`
        // does. The two differ only in that fallback case, which no fixture
        // reaches, and the divergence is the C's rather than this file's.
        let myhost = printable_address(resolved);

        if !io.req().use_eprt && io.req().ipv6 {
            // "EPRT is disabled but we are connected to an IPv6 host, so we
            // ignore the request and enable EPRT again!"
            io.req_mut().use_eprt = true;
        }

        let mut chosen = fcmd;
        while chosen != FtpPortCmd::Done {
            if chosen == FtpPortCmd::Eprt && !io.req().use_eprt {
                chosen = chosen.next();
                continue;
            }
            if chosen == FtpPortCmd::Port && !bound_addr.is_ipv4() {
                // "PORT is IPv4 only"
                chosen = chosen.next();
                continue;
            }
            let cmd = match chosen {
                FtpPortCmd::Eprt => eprt_command(&myhost, bound_addr, port),
                FtpPortCmd::Port => port_command(&myhost, port),
                FtpPortCmd::Done => break,
            };
            if let Err(error) = self.send(pp, io, &cmd) {
                let verb = chosen.word().unwrap_or("");
                let message = format!(
                    "Failure sending {verb} command: {}",
                    error.code().message()
                );
                io.client_mut().failf(format_args!("{message}"));
                return Err(Error::with_context(
                    CURLcode::FtpPortFailed,
                    message,
                ));
            }
            break;
        }

        // "store which command was sent"
        self.ftpc.count1 = i32::from(chosen.as_u8());
        self.set_state(FtpState::Port, io);

        let (chains, mut cx) = io.split();
        self.seams
            .listener_install(chains, &mut cx)
            .map_err(Error::new)
    }

    /// The bind loop of [`Self::use_port_inner`] (`lib/ftp.c:1082-1145`).
    ///
    /// Three failures, three different answers, all the C's: an address that is
    /// not local restarts the loop against the control connection's own address
    /// and only once; an address or port already in use, or refused, moves to
    /// the next port and reports *"ran out of ports"* at the top of the range;
    /// and anything else is fatal.
    ///
    /// # Errors
    ///
    /// [`CURLcode::FtpPortFailed`], with the C's texts.
    fn bind_listener(
        &mut self,
        io: &mut FtpIo<'_>,
        resolved: std::net::IpAddr,
        parsed: &FtpPortSpec,
        possibly_non_local: &mut bool,
    ) -> CurlResult<(std::net::IpAddr, u16)> {
        let mut bind_addr = resolved;
        let mut port = parsed.port_min;
        loop {
            match self.seams.listener_bind(bind_addr, port) {
                Ok(bound) => return Ok((bind_addr, bound)),
                Err(failure) => match failure.kind {
                    SockFailureKind::AddrNotAvail if *possibly_non_local => {
                        io.client_mut().infof(format_args!(
                            "bind(port={port}) on non-local address failed: {}",
                            failure.message
                        ));
                        let Some(local) = self.seams.control_local_addr()
                        else {
                            let errno = io.client().sock_errno();
                            let message =
                                format!("getsockname() failed: {errno}");
                            io.client_mut().failf(format_args!("{message}"));
                            return Err(Error::with_context(
                                CURLcode::FtpPortFailed,
                                message,
                            ));
                        };
                        bind_addr = local;
                        port = parsed.port_min;
                        // "do not try this again"
                        *possibly_non_local = false;
                        continue;
                    }
                    SockFailureKind::AddrInUse => {
                        // "check if port is the maximum value here, because it
                        // might be 0xffff and then the increment below will
                        // wrap the 16-bit counter"
                        if port >= parsed.port_max {
                            let message = "bind() failed, ran out of ports";
                            io.client_mut().failf(format_args!("{message}"));
                            return Err(Error::with_context(
                                CURLcode::FtpPortFailed,
                                message,
                            ));
                        }
                        port = port.saturating_add(1);
                        continue;
                    }
                    SockFailureKind::AddrNotAvail | SockFailureKind::Other => {
                        let message = format!(
                            "bind(port={port}) failed: {}",
                            failure.message
                        );
                        io.client_mut().failf(format_args!("{message}"));
                        return Err(Error::with_context(
                            CURLcode::FtpPortFailed,
                            message,
                        ));
                    }
                },
            }
        }
    }

    /// `ftp_state_port_resp` (`lib/ftp.c:2318-2355`): the reply to `EPRT` or
    /// `PORT`.
    ///
    /// *"The FTP spec tells a positive response should have code 200. Be more
    /// permissive here to tolerate deviant servers"* -- so any `2xx` is
    /// accepted. A refusal disables `EPRT` for the rest of the connection and
    /// falls through to `PORT`; running out of commands is
    /// [`CURLcode::FtpPortFailed`].
    ///
    /// # Errors
    ///
    /// [`CURLcode::FtpPortFailed`], and whatever the retry reports.
    fn state_port_resp(
        &mut self,
        pp: &mut PingPong,
        io: &mut FtpIo<'_>,
        ftpcode: i32,
    ) -> CurlResult<()> {
        let fcmd = FtpPortCmd::from_i32(self.ftpc.count1);

        if ftpcode / 100 != 2 {
            if fcmd == FtpPortCmd::Eprt {
                io.client_mut().infof(format_args!("disabling EPRT usage"));
                io.req_mut().use_eprt = false;
            }
            let next = fcmd.next();
            if next == FtpPortCmd::Done {
                io.client_mut().failf(format_args!("Failed to do PORT"));
                return Err(Error::with_context(
                    CURLcode::FtpPortFailed,
                    "Failed to do PORT",
                ));
            }
            return self.state_use_port(pp, io, next);
        }

        io.client_mut()
            .infof(format_args!("Connect data stream actively"));
        // "end of DO phase"
        self.set_state(FtpState::Stop, io);
        // The data channel is a listener that the server has not connected to
        // yet, so `connected` is FALSE by construction and the DO_MORE phase is
        // requested rather than run from here. See [`Self::dophase_done`].
        self.dophase_done(pp, io, false)?;
        Ok(())
    }
}

// Passive mode: EPSV, PASV and the secondary connection

/// `lib/ftp.c:1307` -- the passive counterpart of *"Connect data stream
/// actively"*.
pub(crate) const PASSIVE_INFO_MESSAGE: &str = "Connect data stream passively";

/// What an `EPSV` `229` reply parsed to (`lib/ftp.c:1930-1957`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EpsvReply {
    /// The port the server is listening on.
    Port(u16),
    /// The delimiters were right but the number was not -- *"Illegal port
    /// number in EPSV reply"*.
    IllegalPort,
    /// No `(` , or the three delimiters did not agree -- *"Weirdly formatted
    /// EPSV reply"*.
    Weird,
}

/// `lib/ftp.c:1942`.
pub(crate) const EPSV_ILLEGAL_PORT_MESSAGE: &str =
    "Illegal port number in EPSV reply";

/// `lib/ftp.c:1954`.
pub(crate) const EPSV_WEIRD_MESSAGE: &str = "Weirdly formatted EPSV reply";

/// `lib/ftp.c:1979`.
pub(crate) const PASV_227_MESSAGE: &str =
    "Could not interpret the 227-response";

/// Parse the `(|||port|)` of an `EPSV` reply (`lib/ftp.c:1930-1957`).
///
/// The server chooses the delimiter and RFC 2428 requires it four times: three
/// empty fields and then the port. The C reads `ptr[0]` as the delimiter and
/// insists that `ptr[1]` and `ptr[2]` match it and that `ptr[3]` is a digit,
/// which is why a reply using `|` as its delimiter and one using `!` both
/// parse.
pub(crate) fn parse_epsv_reply(text: &[u8]) -> EpsvReply {
    let Some(open) = text.iter().position(|&byte| byte == b'(') else {
        return EpsvReply::Weird;
    };
    let after = open.saturating_add(1);
    let Some(rest) = text.get(after..) else {
        return EpsvReply::Weird;
    };
    let (Some(&sep), Some(&second), Some(&third), Some(&digit)) =
        (rest.first(), rest.get(1), rest.get(2), rest.get(3))
    else {
        return EpsvReply::Weird;
    };
    if second != sep || third != sep || !digit.is_ascii_digit() {
        return EpsvReply::Weird;
    }
    let mut cursor = rest.get(3..).unwrap_or(&[]);
    match str_number(&mut cursor, 0xffff) {
        Ok(port) if cursor.first() == Some(&sep) => {
            EpsvReply::Port(u16::try_from(port).unwrap_or(0))
        }
        _ => EpsvReply::IllegalPort,
    }
}

/// `match_pasv_6nums` (`lib/ftp.c:1898-1913`): six comma-separated numbers,
/// each at most 255, starting exactly here.
pub(crate) fn match_pasv_6nums(text: &[u8]) -> Option<[u32; 6]> {
    let mut cursor = text;
    let mut out = [0_u32; 6];
    for (index, slot) in out.iter_mut().enumerate() {
        if index > 0 {
            str_single(&mut cursor, b',').ok()?;
        }
        let value = str_number(&mut cursor, 0xff).ok()?;
        *slot = u32::try_from(value).ok()?;
    }
    Some(out)
}

/// Scan a `227` reply for the first six-number sequence in it
/// (`lib/ftp.c:1971-1980`).
///
/// The surrounding prose is deliberately not matched, because servers disagree
/// about it. The C's own examples: *"227 Entering Passive Mode
/// (127,0,0,1,4,51)"*, *"227 Data transfer will passively listen to
/// 127,0,0,1,4,51"* and *"227 Entering passive mode. 127,0,0,1,4,51"*.
pub(crate) fn parse_pasv_reply(text: &[u8]) -> Option<[u32; 6]> {
    for at in 0..text.len() {
        let tail = text.get(at..)?;
        if let Some(found) = match_pasv_6nums(tail) {
            return Some(found);
        }
    }
    None
}

/// The address and port a `227` reply names -- `(p1 << 8) + p2` and the four
/// address bytes (`lib/ftp.c:1985-1995`).
pub(crate) fn pasv_endpoint(ip: [u32; 6]) -> (String, u16) {
    let host = format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
    let port = u16::try_from(((ip[4] << 8) + ip[5]) & 0xffff).unwrap_or(0);
    (host, port)
}

impl FtpMachine<'_> {
    /// `ftp_state_use_pasv` (`lib/ftp.c:1272-1309`): ask the server to listen.
    ///
    /// The command is `EPSV` unless it has been disabled, and it CANNOT be
    /// disabled on an IPv6 connection -- the C ignores the request and turns it
    /// back on, because `PASV` cannot express an IPv6 address. The offset it
    /// chose is remembered in `count1`, which is how the reply handler knows
    /// which format to parse.
    ///
    /// # Errors
    ///
    /// As [`Self::send`].
    fn state_use_pasv(
        &mut self,
        pp: &mut PingPong,
        io: &mut FtpIo<'_>,
    ) -> CurlResult<()> {
        if !io.req().use_epsv && io.req().ipv6 {
            io.req_mut().use_epsv = true;
        }
        let modeoff = usize::from(!io.req().use_epsv);
        let word = FTP_PASSIVE_MODES.get(modeoff).copied().unwrap_or("PASV");
        let cmd = word.as_bytes().to_vec();
        self.send(pp, io, &cmd)?;
        self.ftpc.count1 = i32::try_from(modeoff).unwrap_or(0);
        self.set_state(FtpState::Pasv, io);
        io.client_mut()
            .infof(format_args!("{PASSIVE_INFO_MESSAGE}"));
        Ok(())
    }

    /// `ftp_epsv_disable` (`lib/ftp.c:1840-1869`): fall back from `EPSV` to
    /// `PASV`.
    ///
    /// Impossible on IPv6 without a tunnel or a SOCKS proxy, because there
    /// would be no way to name the address -- *"We cannot disable EPSV when
    /// doing IPv6, so this is instead a fail"*. Otherwise the data chain is
    /// discarded, the error buffer is released so the next failure can write
    /// into it, and a literal `PASV` goes out with `count1` advanced so the
    /// reply is parsed as a `227`.
    ///
    /// # Errors
    ///
    /// [`CURLcode::WeirdServerReply`] on IPv6, and whatever [`Self::send`]
    /// reports.
    fn epsv_disable(
        &mut self,
        pp: &mut PingPong,
        io: &mut FtpIo<'_>,
    ) -> CurlResult<()> {
        if io.req().ipv6 && !io.req().tunnel_or_socks {
            io.client_mut()
                .failf(format_args!("Failed EPSV attempt, exiting"));
            return Err(Error::with_context(
                CURLcode::WeirdServerReply,
                "Failed EPSV attempt, exiting",
            ));
        }

        io.client_mut()
            .infof(format_args!("Failed EPSV attempt. Disabling EPSV"));
        // "disable it for next transfer"
        io.req_mut().use_epsv = false;
        io.close_secondary();
        // "allow error message to get rewritten"
        io.req_mut().errorbuf = false;

        self.send(pp, io, b"PASV")?;
        self.ftpc.count1 = self.ftpc.count1.saturating_add(1);
        // "remain in/go to the FTP_PASV state"
        self.set_state(FtpState::Pasv, io);
        Ok(())
    }

    /// `ftp_control_addr_dup` (`lib/ftp.c:1871-1896`): the address a data
    /// connection should be made to when the reply's own is unusable.
    ///
    /// Through a tunnel or a SOCKS proxy this is the ORIGINAL host name and not
    /// the control connection's peer, because the peer is the proxy. The C
    /// explains: *"returns the original hostname instead, because the effective
    /// control connection address is the proxy address, not the ftp host"*.
    ///
    /// # Errors
    ///
    /// [`CURLcode::FtpCantGetHost`] when neither is available.
    fn control_addr(&mut self, io: &mut FtpIo<'_>) -> CurlResult<Vec<u8>> {
        if io.req().tunnel_or_socks {
            return Ok(io.req().host_name.clone());
        }
        match io.req().control_remote_ip.clone() {
            Some(ip) if !ip.is_empty() => Ok(ip),
            _ => {
                let message = "unable to get peername of DATA connection";
                io.client_mut().failf(format_args!("{message}"));
                Err(Error::with_context(CURLcode::FtpCantGetHost, message))
            }
        }
    }

    /// `ftp_state_pasv_resp` (`lib/ftp.c:1915-2104`): read the reply, resolve
    /// the endpoint, and set the data connection up.
    ///
    /// # Errors
    ///
    /// [`CURLcode::FtpWeirdPasvReply`], [`CURLcode::FtpWeird227Format`],
    /// [`CURLcode::FtpCantGetHost`], [`CURLcode::CouldntResolveProxy`], and
    /// whatever the secondary setup reports -- except that a setup failure on
    /// the first `EPSV` attempt becomes a `PASV` retry instead.
    fn state_pasv_resp(
        &mut self,
        pp: &mut PingPong,
        io: &mut FtpIo<'_>,
        ftpcode: i32,
    ) -> CurlResult<()> {
        // "start on the first letter" -- past the three digits and the space.
        let reply = pp.recvbuf().get(4..).unwrap_or(&[]).to_vec();
        let epsv_attempt = self.ftpc.count1 == 0;

        let (newhost, newport) = if epsv_attempt && ftpcode == 229 {
            match parse_epsv_reply(&reply) {
                EpsvReply::Port(port) => (self.control_addr(io)?, port),
                EpsvReply::IllegalPort => {
                    io.client_mut()
                        .failf(format_args!("{EPSV_ILLEGAL_PORT_MESSAGE}"));
                    return Err(Error::with_context(
                        CURLcode::FtpWeirdPasvReply,
                        EPSV_ILLEGAL_PORT_MESSAGE,
                    ));
                }
                EpsvReply::Weird => {
                    io.client_mut().failf(format_args!("{EPSV_WEIRD_MESSAGE}"));
                    return Err(Error::with_context(
                        CURLcode::FtpWeirdPasvReply,
                        EPSV_WEIRD_MESSAGE,
                    ));
                }
            }
        } else if !epsv_attempt && ftpcode == 227 {
            let Some(ip) = parse_pasv_reply(&reply) else {
                io.client_mut().failf(format_args!("{PASV_227_MESSAGE}"));
                return Err(Error::with_context(
                    CURLcode::FtpWeird227Format,
                    PASV_227_MESSAGE,
                ));
            };
            let (host, port) = pasv_endpoint(ip);
            if io.opts().skip_ip {
                // "told to ignore the remotely given IP but instead use the
                // host we used for the control connection"
                let reused =
                    String::from_utf8_lossy(&io.req().host_name).into_owned();
                io.client_mut().infof(format_args!(
                    "Skip {}.{}.{}.{} for data connection, reuse {reused} \
                     instead",
                    ip[0], ip[1], ip[2], ip[3]
                ));
                (self.control_addr(io)?, port)
            } else {
                (host.into_bytes(), port)
            }
        } else if epsv_attempt {
            // "EPSV failed, move on to PASV"
            return self.epsv_disable(pp, io);
        } else {
            let message = format!("Bad PASV/EPSV response: {ftpcode:03}");
            io.client_mut().failf(format_args!("{message}"));
            return Err(Error::with_context(
                CURLcode::FtpWeirdPasvReply,
                message,
            ));
        };

        let (target_host, connectport, resolve_failure) = if io.req().proxy {
            // "This connection uses a proxy and we need to connect to the
            // proxy again here. We do not want to rely on a former host lookup
            // that might have expired now"
            let proxy = io.req().proxy_host.clone().unwrap_or_default();
            let port = io.req().control_remote_port;
            (proxy, port, CURLcode::CouldntResolveProxy)
        } else {
            (newhost.clone(), newport, CURLcode::FtpCantGetHost)
        };

        let addrs = match self.seams.resolve(&target_host, connectport) {
            Ok(addrs) if !addrs.is_empty() => addrs,
            _ => {
                let shown = String::from_utf8_lossy(&target_host).into_owned();
                let message = if resolve_failure
                    == CURLcode::CouldntResolveProxy
                {
                    format!("cannot resolve proxy host {shown}:{connectport}")
                } else {
                    format!("cannot resolve new host {shown}:{connectport}")
                };
                io.client_mut().failf(format_args!("{message}"));
                return Err(Error::with_context(resolve_failure, message));
            }
        };

        let tls = io.req().data_ssl;
        let setup = {
            let (chains, mut cx) = io.split();
            self.seams.setup_secondary(
                chains,
                &mut cx,
                SecondaryTarget {
                    host: &target_host,
                    addrs: &addrs,
                    port: connectport,
                    tls,
                },
            )
        };
        if let Err(code) = setup {
            if code != CURLcode::OutOfMemory && epsv_attempt && ftpcode == 229 {
                return self.epsv_disable(pp, io);
            }
            return Err(Error::new(code));
        }

        if let Some(first) = addrs.first() {
            let shown = String::from_utf8_lossy(&newhost).into_owned();
            let printable = printable_address(*first);
            io.client_mut().infof(format_args!(
                "Connecting to {shown} ({printable}) port {connectport}"
            ));
        }

        io.req_mut().secondary_hostname = Some(newhost);
        io.req_mut().secondary_port = newport;
        io.req_mut().do_more = true;
        // "this phase is completed"
        self.set_state(FtpState::Stop, io);
        Ok(())
    }
}

// Reply parsing helpers

/// `ftp_pwd_resp`'s quote-doubling scan (`lib/ftp.c:2900-2950`).
///
/// RFC 959's rule, quoted in the C: *"The directory name can contain any
/// character; embedded double-quotes should be escaped by double-quotes (the
/// "quote-doubling" convention)"*. The scan skips whatever precedes the first
/// quote, which is what lets a non-standard `257 "/" is current directory`
/// prefix through, and stops at the first unpaired quote. [`None`] is the C's
/// `entry_extracted == FALSE`, which includes the case of an empty name between
/// two quotes.
pub(crate) fn parse_pwd_reply(text: &[u8]) -> Option<Vec<u8>> {
    let mut bytes = text.iter().copied();
    // "scan for the first double-quote for non-standard responses", stopping at
    // a line feed as the C does.
    loop {
        match bytes.next() {
            Some(b'"') => break,
            Some(b'\n') | None => return None,
            Some(_) => {}
        }
    }

    let mut out = Vec::new();
    let mut pending_quote = false;
    for byte in bytes {
        if pending_quote {
            if byte == b'"' {
                // "quote-doubling"
                out.push(b'"');
                pending_quote = false;
                continue;
            }
            break;
        }
        if byte == b'"' {
            pending_quote = true;
            continue;
        }
        out.push(byte);
    }

    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// The `SYST` reply's operating-system word (`lib/ftp.c:3178-3195`).
///
/// *"Reply format is like 215<space><OS-name><space><commentary>"*, so leading
/// spaces are skipped and the word ends at the next one.
pub(crate) fn parse_syst_reply(text: &[u8]) -> Vec<u8> {
    let start = text.iter().position(|&byte| byte != b' ').unwrap_or(0);
    let rest = text.get(start..).unwrap_or(&[]);
    let end = rest
        .iter()
        .position(|&byte| byte == b' ' || byte == b'\r' || byte == b'\n')
        .unwrap_or(rest.len());
    rest.get(..end).unwrap_or(&[]).to_vec()
}

/// A timestamp from a `213` reply to `MDTM`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Ftp213Date {
    /// The four-digit year.
    pub(crate) year: i32,
    /// The month, 1 to 12.
    pub(crate) month: i32,
    /// The day, 1 to 31.
    pub(crate) day: i32,
    /// The hour, 0 to 23.
    pub(crate) hour: i32,
    /// The minute, 0 to 59.
    pub(crate) minute: i32,
    /// The second, 0 to 60 -- the C admits 60, for a leap second.
    pub(crate) second: i32,
}

impl Ftp213Date {
    /// The text `Curl_getdate_capped` is handed --
    /// `"%04d%02d%02d %02d:%02d:%02d GMT"` (`lib/ftp.c:2424-2426`).
    pub(crate) fn as_getdate_text(&self) -> String {
        format!(
            "{:04}{:02}{:02} {:02}:{:02}:{:02} GMT",
            self.year,
            self.month,
            self.day,
            self.hour,
            self.minute,
            self.second
        )
    }
}

/// `ftp_213_date` (`lib/ftp.c:2358-2372`): read `YYYYMMDDHHMMSS`, ignoring
/// any `.sss` fraction after it.
///
/// The arithmetic is the C's `twodigit()` -- two bytes read as decimal digits
/// without checking that they are digits -- and so are the four upper bounds it
/// validates. A field built from non-digits therefore produces a number the
/// bounds usually reject, and where they do not,
/// [`crate::util::parsedate::getdate_capped`] is the second gate, exactly as in
/// the C.
pub(crate) fn ftp_213_date(text: &[u8]) -> Option<Ftp213Date> {
    if text.len() < 14 {
        return None;
    }
    let two = |at: usize| -> i32 {
        let high = i32::from(text.get(at).copied().unwrap_or(b'0'));
        let low =
            i32::from(text.get(at.saturating_add(1)).copied().unwrap_or(b'0'));
        (high - 48) * 10 + (low - 48)
    };
    let parsed = Ftp213Date {
        year: two(0) * 100 + two(2),
        month: two(4),
        day: two(6),
        hour: two(8),
        minute: two(10),
        second: two(12),
    };
    if parsed.month > 12
        || parsed.day > 31
        || parsed.hour > 23
        || parsed.minute > 59
        || parsed.second > 60
    {
        return None;
    }
    Some(parsed)
}

/// The `Last-Modified:` pseudo-header FTP emits for a `--head` request
/// (`lib/ftp.c:2455-2469`).
///
/// The C builds it from `gmtime` with `Curl_wkday` and `Curl_month`, and the
/// weekday subscript is `tm_wday ? tm_wday - 1 : 6` because that table starts
/// at Monday while `tm_wday` starts at Sunday. Both tables and the broken-down
/// time are consumed from the modules that own them.
pub(crate) fn last_modified_header(filetime: i64) -> Option<Vec<u8>> {
    let tm = crate::util::timeval::gmtime(filetime).ok()?;
    let wday_index = if tm.wday > 0 {
        usize::try_from(tm.wday.saturating_sub(1)).ok()?
    } else {
        6
    };
    let wday = crate::util::parsedate::WKDAY.get(wday_index)?;
    let month =
        crate::util::parsedate::MONTH.get(usize::try_from(tm.mon).ok()?)?;
    Some(
        format!(
            "Last-Modified: {wday}, {:02} {month} {:4} {:02}:{:02}:{:02} \
             GMT\r\n",
            tm.mday, tm.year, tm.hour, tm.min, tm.sec
        )
        .into_bytes(),
    )
}

/// `ftp_state_size_resp`'s trailing-digit scan (`lib/ftp.c:2559-2576`).
///
/// *"To allow servers to prepend "rubbish" in the response string, we scan for
/// all the digits at the end of the response and parse only those as a
/// number."* `line` is the final reply line including its CRLF, which is what
/// `pp->nfinal` bounds in the C. A reply whose digits do not parse answers `-1`
/// -- *"size remain unknown"*.
pub(crate) fn parse_size_reply(line: &[u8]) -> i64 {
    let Some(start) = line.get(4..) else {
        return -1;
    };
    let mut at = match start.iter().position(|&byte| byte == b'\r') {
        Some(cr) => {
            let mut index = cr.saturating_sub(1);
            if start.get(index) == Some(&b'\n') {
                index = index.saturating_sub(1);
            }
            while index > 0
                && start
                    .get(index.saturating_sub(1))
                    .is_some_and(u8::is_ascii_digit)
            {
                index = index.saturating_sub(1);
            }
            index
        }
        None => 0,
    };
    // A reply of exactly "213 " leaves nothing to read.
    if at >= start.len() {
        at = start.len();
    }
    let mut cursor = start.get(at..).unwrap_or(&[]);
    str_number(&mut cursor, i64::MAX).unwrap_or(-1)
}

/// `ftp_state_get_resp`'s size inference (`lib/ftp.c:2732-2751`).
///
/// The reply to `RETR` often carries the size in prose -- *"150 Opening BINARY
/// mode data connection for /etc/passwd (2241 bytes)"* -- and the C scans the
/// whole reply for a number followed by a space and the word `bytes`. The
/// window is `len - 7`, because *"1 bytes"* is the shortest match.
pub(crate) fn parse_bytes_in_reply(reply: &[u8]) -> Option<i64> {
    let len = reply.len();
    if len < 7 {
        return None;
    }
    for at in 0..len.saturating_sub(7) {
        let mut cursor = reply.get(at..)?;
        let Ok(number) = str_number(&mut cursor, i64::MAX) else {
            continue;
        };
        if str_single(&mut cursor, b' ').is_err() {
            continue;
        }
        if cursor.starts_with(b"bytes") {
            return Some(number);
        }
    }
    None
}

// The reply handlers, and the dispatcher that selects between them

impl FtpMachine<'_> {
    /// `ftp_wait_resp` (`lib/ftp.c:3000-3044`): the greeting, and the decision
    /// whether to negotiate TLS before logging in.
    ///
    /// A `230` here means the server logged us in without being asked, which is
    /// accepted only when TLS is not required -- otherwise the greeting is
    /// treated as the `220` it stands in for and the negotiation proceeds. Any
    /// other code but `220` is a weird reply.
    ///
    /// # Errors
    ///
    /// [`CURLcode::WeirdServerReply`] for an unexpected greeting,
    /// [`CURLcode::UnknownOption`] for an unrecognised
    /// `CURLOPT_FTPSSLAUTH`, and whatever [`Self::send`] reports.
    fn wait_resp(
        &mut self,
        pp: &mut PingPong,
        io: &mut FtpIo<'_>,
        ftpcode: i32,
    ) -> CurlResult<()> {
        if ftpcode == 230 {
            // "230 User logged in - already! Take as 220 if TLS required."
            if io.opts().use_ssl <= UseSsl::Try || io.req().control_ssl {
                return self.state_user_resp(pp, io, ftpcode);
            }
        } else if ftpcode != 220 {
            let message = format!(
                "Got a {ftpcode:03} ftp-server response when 220 was expected"
            );
            io.client_mut().failf(format_args!("{message}"));
            return Err(Error::with_context(
                CURLcode::WeirdServerReply,
                message,
            ));
        }

        if io.opts().use_ssl.wants_tls() && !io.req().control_ssl {
            // "We do not have an SSL/TLS control connection yet, but FTPS is
            // requested. Try an FTPS connection now"
            let auth = io.opts().ftpsslauth;
            let Some((start, step)) = auth.attempt_order() else {
                let message = format!(
                    "unsupported parameter to CURLOPT_FTPSSLAUTH: {}",
                    auth.0
                );
                io.client_mut().failf(format_args!("{message}"));
                return Err(Error::with_context(
                    CURLcode::UnknownOption,
                    message,
                ));
            };
            self.ftpc.count3 = 0;
            self.ftpc.count1 = start;
            self.ftpc.count2 = step;
            let cmd = self.auth_command();
            self.send(pp, io, &cmd)?;
            self.set_state(FtpState::Auth, io);
            return Ok(());
        }

        self.state_user(pp, io)
    }

    /// `AUTH <mechanism>` for the attempt `count1` selects
    /// (`lib/ftp.c:3038`).
    fn auth_command(&self) -> Vec<u8> {
        let index = usize::try_from(self.ftpc.count1).unwrap_or(0);
        let mechanism = FTP_AUTH_MODES.get(index).copied().unwrap_or("SSL");
        format!("AUTH {mechanism}").into_bytes()
    }

    /// The `FTP_AUTH` arm of the dispatcher (`lib/ftp.c:3069-3117`).
    ///
    /// RFC 2228's rule, quoted in the C: *"If the server is willing to accept
    /// the named security mechanism, and does not require any security data, it
    /// must respond with reply code 234/334."* Nothing else is a success, and a
    /// pipelined reply is refused outright -- a server that answered before the
    /// handshake could start cannot be trusted to have understood it.
    ///
    /// One retry only, at the other mechanism. After that, a required TLS level
    /// is [`CURLcode::UseSslFailed`] and an optional one continues in the clear.
    ///
    /// # Errors
    ///
    /// [`CURLcode::WeirdServerReply`], [`CURLcode::UseSslFailed`], and whatever
    /// [`Self::send`] reports.
    fn auth_resp(
        &mut self,
        pp: &mut PingPong,
        io: &mut FtpIo<'_>,
        ftpcode: i32,
    ) -> CurlResult<()> {
        if pp.overflow() != 0 {
            // "Forbid pipelining in response."
            return Err(Error::with_context(
                CURLcode::WeirdServerReply,
                "pipelined reply to AUTH",
            ));
        }

        if ftpcode == 234 || ftpcode == 334 {
            if !io.is_ssl(SocketIndex::First) {
                let inserted = {
                    let (chains, mut cx) = io.split();
                    self.seams.add_tls_filter(
                        chains,
                        &mut cx,
                        SocketIndex::First,
                    )
                };
                if inserted.is_err() {
                    // "we failed and bail out"
                    return Err(Error::with_context(
                        CURLcode::UseSslFailed,
                        "could not install the control-channel TLS filter",
                    ));
                }
            }
            let connected = {
                let (chains, mut cx) = io.split();
                self.seams
                    .connect(chains, &mut cx, SocketIndex::First, true)
                    .map_err(Error::new)
            };
            connected?;
            // "clear-text data" until PROT says otherwise, "SSL on control"
            io.req_mut().data_ssl = false;
            io.req_mut().control_ssl = true;
            return self.state_user(pp, io);
        }

        if self.ftpc.count3 < 1 {
            self.ftpc.count3 = self.ftpc.count3.saturating_add(1);
            // "get next attempt"
            self.ftpc.count1 =
                self.ftpc.count1.saturating_add(self.ftpc.count2);
            let cmd = self.auth_command();
            // "remain in this same state"
            return self.send(pp, io, &cmd);
        }

        if io.opts().use_ssl > UseSsl::Try {
            // "we failed and CURLUSESSL_CONTROL or CURLUSESSL_ALL is set"
            return Err(Error::with_context(
                CURLcode::UseSslFailed,
                "the server refused both AUTH mechanisms",
            ));
        }
        // "ignore the failure and continue"
        self.state_user(pp, io)
    }

    /// `ftp_state_user_resp` (`lib/ftp.c:2827-2884`): the replies to `USER`
    /// and `PASS`.
    ///
    /// # Errors
    ///
    /// [`CURLcode::LoginDenied`], and whatever [`Self::send`] reports.
    fn state_user_resp(
        &mut self,
        pp: &mut PingPong,
        io: &mut FtpIo<'_>,
        ftpcode: i32,
    ) -> CurlResult<()> {
        if ftpcode == 331 && self.ftpc.state() == FtpState::User {
            // "331 Password required for ..."
            let password = io.opts().password.clone();
            let cmd = Self::command_with(b"PASS ", &password);
            self.send(pp, io, &cmd)?;
            self.set_state(FtpState::Pass, io);
            return Ok(());
        }

        if ftpcode / 100 == 2 {
            // "230 User ... logged in."
            return self.state_loggedin(pp, io);
        }

        if ftpcode == 332 {
            let account = io.opts().account.clone();
            return match account {
                Some(account) => {
                    let cmd = Self::command_with(b"ACCT ", &account);
                    self.send(pp, io, &cmd)?;
                    self.set_state(FtpState::Acct, io);
                    Ok(())
                }
                None => {
                    let message = "ACCT requested but none available";
                    io.client_mut().failf(format_args!("{message}"));
                    Err(Error::with_context(CURLcode::LoginDenied, message))
                }
            };
        }

        // "530 User ... access denied"
        let alternative = io.opts().alternative_to_user.clone();
        match alternative {
            Some(command) if !self.ftpc.ftp_trying_alternative => {
                // "Ok, USER failed. Let's try the supplied command."
                self.send(pp, io, &command)?;
                self.ftpc.ftp_trying_alternative = true;
                self.set_state(FtpState::User, io);
                Ok(())
            }
            _ => {
                let message = format!("Access denied: {ftpcode:03}");
                io.client_mut().failf(format_args!("{message}"));
                Err(Error::with_context(CURLcode::LoginDenied, message))
            }
        }
    }

    /// `ftp_state_acct_resp` (`lib/ftp.c:2886-2899`).
    ///
    /// # Errors
    ///
    /// [`CURLcode::FtpWeirdPassReply`], which the C marks `/* FIX */` and which
    /// is preserved as-is: an application matching on it must keep matching.
    fn state_acct_resp(
        &mut self,
        pp: &mut PingPong,
        io: &mut FtpIo<'_>,
        ftpcode: i32,
    ) -> CurlResult<()> {
        if ftpcode != 230 {
            let message = format!("ACCT rejected by server: {ftpcode:03}");
            io.client_mut().failf(format_args!("{message}"));
            return Err(Error::with_context(
                CURLcode::FtpWeirdPassReply,
                message,
            ));
        }
        self.state_loggedin(pp, io)
    }

    /// `ftp_pwd_resp` (`lib/ftp.c:2896-2995`): remember where the login left
    /// us.
    ///
    /// A path that does not begin with `/` triggers a `SYST`, and the C explains
    /// why in full: an OS/400 server *"supports two name syntaxes, the default
    /// one being incompatible with standard paths"*, and it switches syntax the
    /// moment a regular path appears in a command -- which would leave the entry
    /// path recorded in the wrong one. The check is deliberately narrow, *"only
    /// if the path name looks strange to minimize overhead on other systems"*.
    ///
    /// # Errors
    ///
    /// As [`Self::send`].
    fn pwd_resp(
        &mut self,
        pp: &mut PingPong,
        io: &mut FtpIo<'_>,
        ftpcode: i32,
    ) -> CurlResult<()> {
        if ftpcode == 257 {
            let reply = pp.recvbuf().get(4..).unwrap_or(&[]).to_vec();
            match parse_pwd_reply(&reply) {
                Some(dir) => {
                    let needs_syst = self.ftpc.server_os.is_none()
                        && dir.first() != Some(&b'/');
                    if needs_syst {
                        self.send(pp, io, b"SYST")?;
                    }
                    let shown = String::from_utf8_lossy(&dir).into_owned();
                    self.ftpc.entrypath = Some(dir.clone());
                    io.client_mut()
                        .infof(format_args!("Entry path is '{shown}'"));
                    // "also save it where getinfo can access it"
                    io.req_mut().most_recent_entrypath = Some(dir);
                    if needs_syst {
                        self.set_state(FtpState::Syst, io);
                        return Ok(());
                    }
                }
                None => {
                    io.client_mut()
                        .infof(format_args!("Failed to figure out path"));
                }
            }
        }

        // "we are done with CONNECT phase!"
        self.set_state(FtpState::Stop, io);
        let state = self.ftpc.state();
        io.client_mut().trc_ftp(format_args!(
            "[{}] protocol connect phase DONE",
            cstate(Some(state))
        ));
        Ok(())
    }

    /// The `FTP_SYST` arm (`lib/ftp.c:3175-3220`): identify the server and, on
    /// OS/400, switch its name format.
    ///
    /// # Errors
    ///
    /// As [`Self::send`].
    fn syst_resp(
        &mut self,
        pp: &mut PingPong,
        io: &mut FtpIo<'_>,
        ftpcode: i32,
    ) -> CurlResult<()> {
        if ftpcode == 215 {
            let reply = pp.recvbuf().get(4..).unwrap_or(&[]).to_vec();
            let os = parse_syst_reply(&reply);
            if casecompare(&os, b"OS/400") {
                // "Force OS400 name format 1."
                self.send(pp, io, b"SITE NAMEFMT 1")?;
                self.ftpc.server_os = Some(os);
                self.set_state(FtpState::NameFmt, io);
                return Ok(());
            }
            // "Nothing special for the target server."
            self.ftpc.server_os = Some(os);
        }
        // "Cannot identify server OS. Continue anyway and cross fingers."
        self.set_state(FtpState::Stop, io);
        let state = self.ftpc.state();
        io.client_mut().trc_ftp(format_args!(
            "[{}] protocol connect phase DONE",
            cstate(Some(state))
        ));
        Ok(())
    }

    /// `ftp_state_mdtm_resp` (`lib/ftp.c:2406-2517`): the timestamp, the
    /// pseudo-header and the time condition.
    ///
    /// # Errors
    ///
    /// Whatever the header write or the continuation reports.
    fn state_mdtm_resp(
        &mut self,
        pp: &mut PingPong,
        io: &mut FtpIo<'_>,
        ftpcode: i32,
    ) -> CurlResult<()> {
        match ftpcode {
            213 => {
                let reply = pp.recvbuf().get(4..).unwrap_or(&[]).to_vec();
                let mut showtime = false;
                if let Some(parsed) = ftp_213_date(&reply) {
                    if let Some(filetime) =
                        getdate_capped(&parsed.as_getdate_text())
                    {
                        io.req_mut().filetime = filetime;
                        showtime = true;
                    }
                }
                // "If we asked for a time of the file and we actually got one
                // as well, we "emulate" an HTTP-style header in our output."
                if io.opts().no_body
                    && self.ftpc.has_file()
                    && io.opts().get_filetime
                    && showtime
                {
                    let filetime = io.req().filetime;
                    if let Some(header) = last_modified_header(filetime) {
                        io.client_mut()
                            .write_header(&header)
                            .map_err(Error::new)?;
                    }
                }
            }
            550 => {
                // "550 is used for several different problems ... It does not
                // mean that the file does not exist at all."
                io.client_mut().infof(format_args!(
                    "MDTM failed: file does not exist or permission problem, \
                     continuing"
                ));
            }
            _ => {
                io.client_mut()
                    .infof(format_args!("unsupported MDTM reply format"));
            }
        }

        let condition = io.opts().timecondition;
        if condition != TimeCondition::None {
            let filetime = io.req().filetime;
            let timevalue = io.opts().timevalue;
            if filetime > 0 && timevalue > 0 {
                let short_circuit = match condition {
                    TimeCondition::IfUnmodSince => filetime > timevalue,
                    _ => filetime <= timevalue,
                };
                if short_circuit {
                    let message = if condition == TimeCondition::IfUnmodSince {
                        "The requested document is not old enough"
                    } else {
                        "The requested document is not new enough"
                    };
                    io.client_mut().infof(format_args!("{message}"));
                    // "mark to not transfer data"
                    self.transfer.transfer = PpTransfer::None;
                    io.req_mut().timecond_met = true;
                    self.set_state(FtpState::Stop, io);
                    return Ok(());
                }
            } else {
                io.client_mut()
                    .infof(format_args!("Skipping time comparison"));
            }
        }

        self.state_type(pp, io)
    }

    /// `ftp_state_type_resp` (`lib/ftp.c:2519-2549`): the reply to `TYPE`, and
    /// the fork into whatever the type was set for.
    ///
    /// Any `2xx` is accepted, and the C names the servers that made that
    /// necessary: *""sasserftpd" and "(u)r(x)bot ftpd" both responds with 226
    /// after a successful 'TYPE I'"*.
    ///
    /// # Errors
    ///
    /// [`CURLcode::FtpCouldntSetType`], and whatever the continuation reports.
    fn state_type_resp(
        &mut self,
        pp: &mut PingPong,
        io: &mut FtpIo<'_>,
        ftpcode: i32,
        instate: FtpState,
    ) -> CurlResult<()> {
        if ftpcode / 100 != 2 {
            let message = "Could not set desired mode";
            io.client_mut().failf(format_args!("{message}"));
            return Err(Error::with_context(
                CURLcode::FtpCouldntSetType,
                message,
            ));
        }
        if ftpcode != 200 {
            io.client_mut().infof(format_args!(
                "Got a {ftpcode:03} response code instead of the assumed 200"
            ));
        }

        match instate {
            FtpState::Type => self.state_size(pp, io),
            FtpState::ListType => self.state_list(pp, io),
            FtpState::RetrType => {
                self.state_quote(pp, io, true, FtpState::RetrPrequote)
            }
            FtpState::StorType => {
                self.state_quote(pp, io, true, FtpState::StorPrequote)
            }
            FtpState::RetrListType => {
                self.state_quote(pp, io, true, FtpState::ListPrequote)
            }
            _ => Ok(()),
        }
    }

    /// `ftp_state_size_resp` (`lib/ftp.c:2551-2610`): the reply to `SIZE`, in
    /// each of the three states that can be waiting for one.
    ///
    /// # Errors
    ///
    /// [`CURLcode::RemoteFileNotFound`] for a `550` that is not a probe before
    /// an upload -- the C allows that one *"when probing what command to
    /// use"* -- and whatever the continuation reports.
    fn state_size_resp(
        &mut self,
        pp: &mut PingPong,
        io: &mut FtpIo<'_>,
        ftpcode: i32,
        instate: FtpState,
    ) -> CurlResult<()> {
        let mut filesize = -1_i64;
        if ftpcode == 213 {
            let nfinal = pp.nfinal();
            let line = pp.recvbuf().get(..nfinal).unwrap_or(&[]).to_vec();
            filesize = parse_size_reply(&line);
        } else if ftpcode == 550 && instate != FtpState::StorSize {
            let message = "The file does not exist";
            io.client_mut().failf(format_args!("{message}"));
            return Err(Error::with_context(
                CURLcode::RemoteFileNotFound,
                message,
            ));
        }

        match instate {
            FtpState::Size => {
                if filesize != -1 {
                    let header =
                        format!("Content-Length: {filesize}\r\n").into_bytes();
                    io.client_mut()
                        .write_header(&header)
                        .map_err(Error::new)?;
                }
                io.client_mut().pgrs_set_download_size(filesize);
                self.state_rest(pp, io)
            }
            FtpState::RetrSize => {
                io.client_mut().pgrs_set_download_size(filesize);
                self.state_retr(pp, io, filesize)
            }
            FtpState::StorSize => {
                io.req_mut().resume_from = filesize;
                self.state_ul_setup(pp, io, true)
            }
            _ => Ok(()),
        }
    }

    /// `ftp_state_rest_resp` (`lib/ftp.c:2612-2650`): the reply to `REST`.
    ///
    /// `350` after the probing `REST 0` means ranges are supported, which FTP
    /// reports to the client as the HTTP-shaped `Accept-ranges: bytes` header.
    /// `350` after a real offset is required, and anything else is
    /// [`CURLcode::FtpCouldntUseRest`].
    ///
    /// # Errors
    ///
    /// [`CURLcode::FtpCouldntUseRest`], and whatever the continuation reports.
    fn state_rest_resp(
        &mut self,
        pp: &mut PingPong,
        io: &mut FtpIo<'_>,
        ftpcode: i32,
        instate: FtpState,
    ) -> CurlResult<()> {
        if instate == FtpState::RetrRest {
            if ftpcode != 350 {
                let message = "Could not use REST";
                io.client_mut().failf(format_args!("{message}"));
                return Err(Error::with_context(
                    CURLcode::FtpCouldntUseRest,
                    message,
                ));
            }
            let file = self.ftpc.file().unwrap_or(&[]).to_vec();
            let cmd = Self::command_with(b"RETR ", &file);
            self.send(pp, io, &cmd)?;
            self.set_state(FtpState::Retr, io);
            return Ok(());
        }

        if ftpcode == 350 {
            io.client_mut()
                .write_header(b"Accept-ranges: bytes\r\n")
                .map_err(Error::new)?;
        }
        self.state_prepare_transfer(pp, io)
    }

    /// `ftp_state_stor_resp` (`lib/ftp.c:2652-2683`): the reply to `STOR` or
    /// `APPE`.
    ///
    /// # Errors
    ///
    /// [`CURLcode::UploadFailed`] for a `4xx` or `5xx`, and whatever the data
    /// connection reports.
    fn state_stor_resp(
        &mut self,
        pp: &mut PingPong,
        io: &mut FtpIo<'_>,
        ftpcode: i32,
    ) -> CurlResult<()> {
        if ftpcode >= 400 {
            let message = format!("Failed FTP upload: {ftpcode:0}");
            io.client_mut().failf(format_args!("{message}"));
            self.set_state(FtpState::Stop, io);
            return Err(Error::with_context(CURLcode::UploadFailed, message));
        }

        if io.opts().use_port {
            // "PORT means we are now awaiting the server to connect to us."
            self.set_state(FtpState::Stop, io);
            let connected = {
                let (chains, mut cx) = io.split();
                self.seams
                    .connect(chains, &mut cx, SocketIndex::Secondary, false)
                    .map_err(Error::new)?
            };
            if !connected {
                io.client_mut().infof(format_args!(
                    "Data conn was not available immediately"
                ));
                self.ftpc.wait_data_conn = true;
                return self.check_ctrl_on_data_wait(pp, io);
            }
            self.ftpc.wait_data_conn = false;
        }
        self.initiate_transfer(pp, io)
    }

    /// `ftp_state_get_resp` (`lib/ftp.c:2685-2792`): the reply to `LIST` or
    /// `RETR`.
    ///
    /// The size handling is the fiddliest part of the module and every clause is
    /// the C's. A directory listing's size is not inferred, because *"directory
    /// listings either do not show the size or often uses size 0 anyway"*; an
    /// ASCII transfer's size is discarded afterwards, *"for servers that
    /// understate ASCII mode file size"*; and a `SIZE` that reported zero is
    /// overridden from the reply text, because some servers report zero for
    /// every file in binary mode.
    ///
    /// # Errors
    ///
    /// [`CURLcode::RemoteFileNotFound`] for a `550` answering `RETR`,
    /// [`CURLcode::FtpCouldntRetrFile`] otherwise, and whatever the data
    /// connection reports.
    fn state_get_resp(
        &mut self,
        pp: &mut PingPong,
        io: &mut FtpIo<'_>,
        ftpcode: i32,
        instate: FtpState,
    ) -> CurlResult<()> {
        if ftpcode != 150 && ftpcode != 125 {
            if instate == FtpState::List && ftpcode == 450 {
                // "simply no matching files in the directory listing"
                self.transfer.transfer = PpTransfer::None;
                self.set_state(FtpState::Stop, io);
                return Ok(());
            }
            let message = format!("RETR response: {ftpcode:03}");
            io.client_mut().failf(format_args!("{message}"));
            let code = if instate == FtpState::Retr && ftpcode == 550 {
                CURLcode::RemoteFileNotFound
            } else {
                CURLcode::FtpCouldntRetrFile
            };
            return Err(Error::with_context(code, message));
        }

        // "default unknown size"
        io.req_mut().size = -1;

        let listing = instate == FtpState::List;
        let ascii = io.req().prefer_ascii;
        let ignorecl = io.opts().ignore_content_length;
        if !listing && !ascii && !ignorecl && self.transfer.downloadsize < 1 {
            let reply = pp.recvbuf().to_vec();
            if let Some(size) = parse_bytes_in_reply(&reply) {
                io.req_mut().size = size;
            }
        } else if self.transfer.downloadsize > -1 {
            io.req_mut().size = self.transfer.downloadsize;
        }

        let maxdownload = io.req().maxdownload;
        let size = io.req().size;
        if size > maxdownload && maxdownload > 0 {
            io.req_mut().size = maxdownload;
        } else if !listing && ascii {
            io.req_mut().size = -1;
        }

        let maxdownload = io.req().maxdownload;
        io.client_mut()
            .infof(format_args!("Maxdownload = {maxdownload}"));
        if !listing {
            let size = io.req().size;
            io.client_mut()
                .infof(format_args!("Getting file with size: {size}"));
        }

        if io.opts().use_port {
            let connected = {
                let (chains, mut cx) = io.split();
                self.seams
                    .connect(chains, &mut cx, SocketIndex::Secondary, false)
                    .map_err(Error::new)?
            };
            if !connected {
                io.client_mut().infof(format_args!(
                    "Data conn was not available immediately"
                ));
                self.set_state(FtpState::Stop, io);
                self.ftpc.wait_data_conn = true;
                return self.check_ctrl_on_data_wait(pp, io);
            }
            self.ftpc.wait_data_conn = false;
        }
        self.initiate_transfer(pp, io)
    }

    /// The `FTP_CWD` arm (`lib/ftp.c:3231-3291`): walk the components, and
    /// create a missing one when asked to.
    ///
    /// `count2` is the guard against a `CWD`-`MKD` loop and `count3` is the
    /// tolerance the two-valued `CURLOPT_FTP_CREATE_MISSING_DIRS` buys, whose
    /// purpose the C states: it *"allows for a second try to CWD to it"* when
    /// another session created the directory first.
    ///
    /// # Errors
    ///
    /// [`CURLcode::RemoteAccessDenied`], and whatever [`Self::send`] reports.
    fn cwd_resp(
        &mut self,
        pp: &mut PingPong,
        io: &mut FtpIo<'_>,
        ftpcode: i32,
    ) -> CurlResult<()> {
        if ftpcode / 100 != 2 {
            let creating = io.opts().create_missing_dirs;
            if creating > 0 && self.ftpc.cwdcount > 0 && self.ftpc.count2 == 0 {
                // "counter to prevent CWD-MKD loops"
                self.ftpc.count2 = self.ftpc.count2.saturating_add(1);
                self.ftpc.count3 = i32::from(creating == 2);
                let index = usize::from(self.ftpc.cwdcount.saturating_sub(1));
                let piece = self.ftpc.pathpiece(index).unwrap_or(&[]).to_vec();
                let cmd = Self::command_with(b"MKD ", &piece);
                self.send(pp, io, &cmd)?;
                self.set_state(FtpState::Mkd, io);
                return Ok(());
            }
            let message = "Server denied you to change to the given directory";
            io.client_mut().failf(format_args!("{message}"));
            // "do not remember this path as we failed to enter it"
            self.ftpc.cwdfail = true;
            return Err(Error::with_context(
                CURLcode::RemoteAccessDenied,
                message,
            ));
        }

        self.ftpc.count2 = 0;
        if self.ftpc.cwdcount >= self.ftpc.dirdepth() {
            return self.state_mdtm(pp, io);
        }
        self.ftpc.cwdcount = self.ftpc.cwdcount.saturating_add(1);
        let index = usize::from(self.ftpc.cwdcount.saturating_sub(1));
        let piece = self.ftpc.pathpiece(index).unwrap_or(&[]).to_vec();
        let cmd = Self::command_with(b"CWD ", &piece);
        self.send(pp, io, &cmd)
    }

    /// The `FTP_MKD` arm (`lib/ftp.c:3293-3305`).
    ///
    /// The C's condition is `(ftpcode / 100 != 2) && !ftpc->count3--`, whose
    /// post-decrement runs whether or not the first half was true; that is
    /// reproduced exactly, because the decrement is what spends the tolerance.
    ///
    /// # Errors
    ///
    /// [`CURLcode::RemoteAccessDenied`], and whatever [`Self::send`] reports.
    fn mkd_resp(
        &mut self,
        pp: &mut PingPong,
        io: &mut FtpIo<'_>,
        ftpcode: i32,
    ) -> CurlResult<()> {
        let tolerance = self.ftpc.count3;
        self.ftpc.count3 = tolerance.saturating_sub(1);
        if ftpcode / 100 != 2 && tolerance == 0 {
            let message = format!("Failed to MKD dir: {ftpcode:03}");
            io.client_mut().failf(format_args!("{message}"));
            return Err(Error::with_context(
                CURLcode::RemoteAccessDenied,
                message,
            ));
        }

        self.set_state(FtpState::Cwd, io);
        let index = usize::from(self.ftpc.cwdcount.saturating_sub(1));
        let piece = self.ftpc.pathpiece(index).unwrap_or(&[]).to_vec();
        let cmd = Self::command_with(b"CWD ", &piece);
        self.send(pp, io, &cmd)
    }

    /// The five quote arms (`lib/ftp.c:3222-3229`).
    ///
    /// # Errors
    ///
    /// [`CURLcode::QuoteError`] for a refused command that was not marked with
    /// `*`, and whatever the list's continuation reports.
    fn quote_resp(
        &mut self,
        pp: &mut PingPong,
        io: &mut FtpIo<'_>,
        ftpcode: i32,
        instate: FtpState,
    ) -> CurlResult<()> {
        if ftpcode >= 400 && self.ftpc.count2 == 0 {
            let message = format!("QUOT command failed with {ftpcode:03}");
            io.client_mut().failf(format_args!("{message}"));
            return Err(Error::with_context(CURLcode::QuoteError, message));
        }
        self.state_quote(pp, io, false, instate)
    }

    /// The `FTP_PRET` arm (`lib/ftp.c:3330-3338`).
    ///
    /// # Errors
    ///
    /// [`CURLcode::FtpPretFailed`] -- *"there only is this one standard OK
    /// return code"* -- and whatever the passive setup reports.
    fn pret_resp(
        &mut self,
        pp: &mut PingPong,
        io: &mut FtpIo<'_>,
        ftpcode: i32,
    ) -> CurlResult<()> {
        if ftpcode != 200 {
            let message = format!("PRET command not accepted: {ftpcode:03}");
            io.client_mut().failf(format_args!("{message}"));
            return Err(Error::with_context(CURLcode::FtpPretFailed, message));
        }
        self.state_use_pasv(pp, io)
    }
}

/// `ftp_pp_statemachine` (`lib/ftp.c:3046-3364`): flush, read, and dispatch on
/// the live state.
///
/// The dispatcher is an **exhaustive match over every real state**, which is
/// what makes adding a state a compile error rather than a silent
/// fall-through. The C's `default:` shares its body with `FTP_QUIT` and stops
/// the machine, and that pairing is preserved -- but only for the states that
/// genuinely reach it, never as a catch-all.
///
/// [`FTP_LAST`] cannot arrive here: it is not a [`FtpState`] variant, so the
/// sentinel is excluded by the type rather than by an arm.
///
/// # Errors
///
/// Whatever the arm that ran reports.
pub(crate) fn ftp_pp_statemachine(
    machine: &mut FtpMachine<'_>,
    pp: &mut PingPong,
    io: &mut FtpIo<'_>,
) -> CurlResult<()> {
    if pp.needs_flush() {
        return pp.flushsend(io);
    }

    let response = ftp_readresp(machine, pp, io, SocketIndex::First)?;
    if !response.is_complete() {
        return Ok(());
    }
    let ftpcode = response.code;

    // "we have now received a full FTP server response"
    match machine.ftpc.state() {
        FtpState::Wait220 => machine.wait_resp(pp, io, ftpcode),
        FtpState::Auth => machine.auth_resp(pp, io, ftpcode),
        FtpState::User | FtpState::Pass => {
            machine.state_user_resp(pp, io, ftpcode)
        }
        FtpState::Acct => machine.state_acct_resp(pp, io, ftpcode),
        FtpState::Pbsz => {
            let level = io.opts().use_ssl.prot_level();
            let cmd = [b'P', b'R', b'O', b'T', b' ', level];
            machine.send(pp, io, &cmd)?;
            machine.set_state(FtpState::Prot, io);
            Ok(())
        }
        FtpState::Prot => {
            if ftpcode / 100 == 2 {
                // "We have enabled SSL for the data connection!"
                io.req_mut().data_ssl = io.opts().use_ssl != UseSsl::Control;
            } else if io.opts().use_ssl > UseSsl::Control {
                // "FTP servers typically responds with 500 if they decide to
                // reject our 'P' request"
                return Err(Error::with_context(
                    CURLcode::UseSslFailed,
                    "the server refused the requested data protection",
                ));
            }
            if io.opts().ccc.requested() {
                machine.send(pp, io, b"CCC")?;
                machine.set_state(FtpState::Ccc, io);
                Ok(())
            } else {
                machine.state_pwd(pp, io)
            }
        }
        FtpState::Ccc => {
            if ftpcode < 500 {
                // "First shut down the SSL layer (note: this call will block)"
                let active = io.opts().ccc.shuts_down_actively();
                let removed = {
                    let (chains, mut cx) = io.split();
                    machine.seams.remove_tls_filter(
                        chains,
                        &mut cx,
                        SocketIndex::First,
                        active,
                    )
                };
                if let Err(code) = removed {
                    io.client_mut().failf(format_args!(
                        "Failed to clear the command channel (CCC)"
                    ));
                    return Err(Error::with_context(
                        code,
                        "Failed to clear the command channel (CCC)",
                    ));
                }
            }
            // "Then continue as normal"
            machine.state_pwd(pp, io)
        }
        FtpState::Pwd => machine.pwd_resp(pp, io, ftpcode),
        FtpState::Syst => machine.syst_resp(pp, io, ftpcode),
        FtpState::NameFmt => {
            if ftpcode == 250 {
                // "Name format change successful: reload initial path."
                return machine.state_pwd(pp, io);
            }
            machine.set_state(FtpState::Stop, io);
            let state = machine.ftpc.state();
            io.client_mut().trc_ftp(format_args!(
                "[{}] protocol connect phase DONE",
                cstate(Some(state))
            ));
            Ok(())
        }
        state @ (FtpState::Quote
        | FtpState::Postquote
        | FtpState::RetrPrequote
        | FtpState::StorPrequote
        | FtpState::ListPrequote) => machine.quote_resp(pp, io, ftpcode, state),
        FtpState::Cwd => machine.cwd_resp(pp, io, ftpcode),
        FtpState::Mkd => machine.mkd_resp(pp, io, ftpcode),
        FtpState::Mdtm => machine.state_mdtm_resp(pp, io, ftpcode),
        state @ (FtpState::Type
        | FtpState::ListType
        | FtpState::RetrType
        | FtpState::StorType
        | FtpState::RetrListType) => {
            machine.state_type_resp(pp, io, ftpcode, state)
        }
        state @ (FtpState::Size | FtpState::RetrSize | FtpState::StorSize) => {
            machine.state_size_resp(pp, io, ftpcode, state)
        }
        state @ (FtpState::Rest | FtpState::RetrRest) => {
            machine.state_rest_resp(pp, io, ftpcode, state)
        }
        FtpState::Pret => machine.pret_resp(pp, io, ftpcode),
        FtpState::Pasv => machine.state_pasv_resp(pp, io, ftpcode),
        FtpState::Port => machine.state_port_resp(pp, io, ftpcode),
        state @ (FtpState::List | FtpState::Retr) => {
            machine.state_get_resp(pp, io, ftpcode, state)
        }
        FtpState::Stor => machine.state_stor_resp(pp, io, ftpcode),
        // The C's `case FTP_QUIT: default:` -- "internal error" for anything
        // that has no reply to handle, and the reply to `QUIT` itself, which is
        // read and discarded.
        FtpState::Quit | FtpState::Stop => {
            machine.set_state(FtpState::Stop, io);
            Ok(())
        }
    }
}

// The DO phase, the DO_MORE phase, and what closes them

/// `ftp_connect` (`lib/ftp.c:3391-3429`): everything that counts as connecting.
///
/// The cadence engine is set up once per transfer, an already-secure control
/// filter is completed blockingly -- implicit FTPS, where the `990` port carries
/// TLS from the first byte and there is no `AUTH` to negotiate -- and the
/// machine starts waiting for the greeting.
///
/// # Errors
///
/// Whatever the TLS handshake or the state machine reports.
#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
pub(crate) async fn ftp_connect(
    session: &mut FtpSession,
    io: &mut FtpIo<'_>,
) -> CurlResult<bool> {
    if io.is_ssl(SocketIndex::First) {
        // BLOCKING, as the C marks it.
        let connected = {
            let (chains, mut cx) = io.split();
            session
                .seams_mut()
                .connect(chains, &mut cx, SocketIndex::First, true)
                .map_err(Error::new)
        };
        if !connected? {
            // The blocking form of the C's `Curl_conn_connect` does not
            // return until it is done or has failed, so an incomplete
            // handshake here is the successor's "come back later" and the
            // greeting has to keep waiting.
            return Ok(false);
        }
        io.req_mut().control_ssl = true;
    }

    // `Curl_pp_init(pp, Curl_pgrs_now(data))` -- *"once per transfer"*.
    let now = io.clock().now();
    session.conn_mut().pp_mut().init(now);

    // "When we connect, we start in the state where we await the 220 response"
    {
        let (_pp, machine) = session.split();
        machine.ftpc.set_state(FtpState::Wait220, io.client_mut());
    }

    ftp_statemach(session, io).await
}

/// `ftp_sendquote` (`lib/ftp.c:3435-3484`): send a list of custom commands and
/// wait for each reply.
///
/// A command beginning with `*` may fail, and the C explains the choice of
/// marker: *"if a command starts with an asterisk, which a legal FTP command
/// never can, the command will be allowed to fail without it causing any aborts
/// or cancels etc."* The marker is removed before the command goes out, so the
/// bytes on the wire never carry it.
///
/// BLOCKING, and used only by the post-transfer quote list.
///
/// # Errors
///
/// [`CURLcode::QuoteError`] for a refused command that was not marked, and
/// whatever the send or the read reports.
#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
pub(crate) async fn ftp_sendquote(
    session: &mut FtpSession,
    io: &mut FtpIo<'_>,
    quote: &[Vec<u8>],
) -> CurlResult<()> {
    for item in quote {
        if item.is_empty() {
            continue;
        }
        let (cmd, acceptfail) = match item.first() {
            Some(&b'*') => (item.get(1..).unwrap_or(&[]), true),
            _ => (item.as_slice(), false),
        };

        let now = io.clock().now();
        let (pp, mut machine) = session.split();
        pp.sendn(io, cmd)?;
        // "timeout relative now"
        let (nread, ftpcode) =
            getftpresponse(&mut machine, pp, io, Some(now)).await?;
        let _ = nread;

        if !acceptfail && ftpcode >= 400 {
            let shown = String::from_utf8_lossy(cmd).into_owned();
            let message = format!("QUOT string not accepted: {shown}");
            io.client_mut().failf(format_args!("{message}"));
            return Err(Error::with_context(CURLcode::QuoteError, message));
        }
    }
    Ok(())
}

/// `ftp_do_more` (`lib/ftp.c:2133-2287`): drive the data channel, and report
/// which of the three ways it ended.
///
/// The C's own explanation of why the secondary connection may not complete on
/// the first call is worth keeping whole, because it is the reason this phase
/// exists at all: *"we do EPTR and the server will not connect to our listen
/// socket until we send more FTP commands"*, or *"an SSL filter is in place and
/// the server will not start the TLS handshake until we send more FTP
/// commands"*. Either way the commands and the connection have to advance
/// together, which no single-shot connect can express.
///
/// [`DoMoreStep::Retry`] -- the C's `-1` -- is reached in exactly one place: an
/// `EPSV` data connection that failed to connect, on the first attempt, when
/// the chain is not a listener. That is what sends the engine back to `DOING`
/// to try `PASV`.
///
/// # Errors
///
/// Whatever the connect, the state machine, the range parser or the transfer
/// setup reports.
#[allow(clippy::too_many_lines)]
// The C function is 155 lines and every
// branch of it is a distinct outcome; splitting it would hide the order the
// branches are tested in, which is what makes the phase's contract.
#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
pub(crate) async fn ftp_do_more(
    session: &mut FtpSession,
    io: &mut FtpIo<'_>,
) -> CurlResult<DoMoreStep> {
    // "default to stay in the state"
    let mut step = DoMoreStep::Pending;

    if io.is_setup(SocketIndex::Secondary) {
        let is_eptr = io.is_tcp_listen(SocketIndex::Secondary);
        let outcome = {
            let (chains, mut cx) = io.split();
            session.seams_mut().connect(
                chains,
                &mut cx,
                SocketIndex::Secondary,
                false,
            )
        };
        let connected = match outcome {
            Ok(connected) => Some(connected),
            Err(CURLcode::OutOfMemory) => {
                return Err(Error::new(CURLcode::OutOfMemory));
            }
            Err(_) => None,
        };
        let failed = connected.is_none();
        let stalled = connected == Some(false)
            && !is_eptr
            && !io.is_ip_connected(SocketIndex::Secondary);
        if failed || stalled {
            let count1 = session.conn().ftpc().count1;
            if failed && !is_eptr && count1 == 0 {
                // "this is a EPSV connect failing, try PASV instead"
                let (pp, mut machine) = session.split();
                machine.epsv_disable(pp, io)?;
                // "go back to DOING please"
                return Ok(DoMoreStep::Retry);
            }
            return match outcome {
                Ok(_) => Ok(DoMoreStep::Pending),
                Err(code) => Err(Error::new(code)),
            };
        }
    }

    if session.conn().ftpc().state() != FtpState::Stop {
        // "already in a state so skip the initial commands. They are only done
        // to kickstart the do_more state"
        let complete = ftp_statemach(session, io).await?;
        step = if complete {
            DoMoreStep::Advance
        } else {
            DoMoreStep::Pending
        };
        if !session.conn().ftpc().wait_data_conn {
            return Ok(step);
        }
        // "if we reach the end of the FTP state machine here, *complete will be
        // TRUE but so is ftpc->wait_data_conn, which says we need to wait for
        // the data connection and therefore we are not actually complete"
        step = DoMoreStep::Pending;
    }

    if session.transfer().transfer > PpTransfer::Info {
        // "no data to transfer"
        io.client_mut().xfer_setup_nop();
        if !session.conn().ftpc().wait_data_conn {
            // "no waiting for the data connection so this is now complete"
            let state = session.conn().ftpc().state();
            io.client_mut().trc_ftp(format_args!(
                "[{}] DO-MORE phase ends with 0",
                cstate(Some(state))
            ));
            return Ok(DoMoreStep::Advance);
        }
        return Ok(step);
    }

    // "a transfer is about to take place, or if not a filename was given so we
    // will do a SIZE on it later and then we need the right TYPE first"
    if session.conn().ftpc().wait_data_conn {
        let serv_conned = {
            let (chains, mut cx) = io.split();
            session
                .seams_mut()
                .connect(chains, &mut cx, SocketIndex::Secondary, false)
                // "Failed to accept data connection"
                .map_err(Error::new)?
        };
        if serv_conned {
            // "It looks data connection is established"
            session.conn_mut().ftpc_mut().wait_data_conn = false;
            let (pp, mut machine) = session.split();
            machine.initiate_transfer(pp, io)?;
            // "this state is now complete when the server has connected back
            // to us"
            return Ok(DoMoreStep::Advance);
        }
        let (pp, mut machine) = session.split();
        machine.check_ctrl_on_data_wait(pp, io)?;
        return Ok(step);
    }

    if io.req().upload {
        let ascii = io.req().prefer_ascii;
        {
            let (pp, mut machine) = session.split();
            machine.nb_type(pp, io, ascii, FtpState::StorType)?;
        }
        let complete = ftp_statemach(session, io).await?;
        // "ftp_nb_type() might have skipped sending `TYPE A|I` when not deemed
        // necessary and directly sent `STORE name`. If this was then complete,
        // but we are still waiting on the data connection, the transfer has not
        // been initiated yet."
        step = if session.conn().ftpc().wait_data_conn || !complete {
            DoMoreStep::Pending
        } else {
            DoMoreStep::Advance
        };
        return Ok(step);
    }

    // "download"
    session.transfer_mut().downloadsize = -1; // "unknown as of yet"

    let ranged = ftp_apply_range(io);
    if ranged.is_ok() && io.req().maxdownload >= 0 {
        // "Do not check for successful transfer"
        session.conn_mut().ftpc_mut().dont_check = true;
    }
    ranged?;

    let list_only = io.req().list_only;
    let has_file = session.conn().ftpc().has_file();
    let has_prequote = !io.opts().prequote.is_empty();
    if (list_only || !has_file) && !has_prequote {
        // "The specified path ends with a slash, and therefore we think this is
        // a directory that is requested, use LIST. But before that we need to
        // set ASCII transfer mode."
        if session.transfer().transfer == PpTransfer::Body {
            // "But only if a body transfer was requested."
            let (pp, mut machine) = session.split();
            machine.nb_type(pp, io, true, FtpState::ListType)?;
        }
        // "otherwise just fall through"
    } else if has_prequote && !has_file {
        let (pp, mut machine) = session.split();
        machine.nb_type(pp, io, true, FtpState::RetrListType)?;
    } else {
        let ascii = io.req().prefer_ascii;
        let (pp, mut machine) = session.split();
        machine.nb_type(pp, io, ascii, FtpState::RetrType)?;
    }

    let complete = ftp_statemach(session, io).await?;
    Ok(if complete {
        DoMoreStep::Advance
    } else {
        DoMoreStep::Pending
    })
}

/// `Curl_range(data)` as the download path calls it (`lib/ftp.c:2236`).
///
/// [`crate::util::range`] owns the grammar; this is the FTP-side application of
/// what it answers, in the shape [`RangeSpec::maxdownload`]'s own documentation
/// prescribes -- `resume_from` unconditionally, `maxdownload` only where the C
/// writes it.
///
/// **The `else` branch matters as much as the `if`.** With no range in force the
/// C assigns `data->req.maxdownload = -1` (`lib/curl_range.c:87`), and
/// `ftp_do_more` then tests `maxdownload >= 0` to decide `dont_check`. Skipping
/// the assignment would leave a stale limit behind and suppress the transfer
/// check for a request that asked for no range at all.
///
/// The C's guard is `data->state.use_range && data->state.range`; the two are
/// one condition here because `use_range` is `set_range` copied at
/// `Curl_init_do` and the only thing that separates them afterwards is a
/// redirect, which FTP does not perform.
///
/// # Errors
///
/// [`CURLcode::RangeError`] for a range this protocol cannot honour, which is
/// what the shared parser reports.
#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
fn ftp_apply_range(io: &mut FtpIo<'_>) -> CurlResult<()> {
    let Some(range) = io.opts().range.clone() else {
        io.req_mut().maxdownload = -1;
        return Ok(());
    };
    let spec = range_parse(&range).map_err(Error::new)?;
    io.req_mut().resume_from = spec.resume_from();
    if let Some(limit) = spec.maxdownload() {
        io.req_mut().maxdownload = limit;
    }
    Ok(())
}

impl FtpMachine<'_> {
    /// `ftp_dophase_done` (`lib/ftp.c:2290-2312`): *"call this when the DO
    /// phase has completed"*.
    ///
    /// The C calls `ftp_do_more` from here when the data connection is already
    /// up, which the successor cannot do without recursing through an async
    /// boundary the synchronous state machine has no runtime for. The split is
    /// exact and is preserved by [`Self::dophase_done`] answering **whether the
    /// caller must run the DO_MORE phase itself**: the two async callers do,
    /// and the one synchronous caller -- the reply to `EPRT`/`PORT`, which by
    /// construction has NOT connected yet -- never needed to.
    ///
    /// # Errors
    ///
    /// Never; the signature carries a result because the C's does and because
    /// both callers forward it.
    fn dophase_done(
        &mut self,
        pp: &mut PingPong,
        io: &mut FtpIo<'_>,
        connected: bool,
    ) -> CurlResult<bool> {
        let _ = pp;
        if self.transfer.transfer != PpTransfer::Body {
            // "no data to transfer"
            io.client_mut().xfer_setup_nop();
        } else if !connected {
            // "since we did not connect now, we want do_more to get called"
            io.req_mut().do_more = true;
        }

        self.ftpc.ctl_valid = true; // "seems good"
        Ok(connected)
    }
}

/// The half of `ftp_dophase_done` that has to run the DO_MORE phase
/// (`lib/ftp.c:2295-2302`).
///
/// # Errors
///
/// Whatever DO_MORE reports. A failure closes the data connection first, as the
/// C does.
#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
async fn ftp_dophase_done(
    session: &mut FtpSession,
    io: &mut FtpIo<'_>,
    connected: bool,
) -> CurlResult<()> {
    if connected {
        let outcome = ftp_do_more(session, io).await;
        if let Err(error) = outcome {
            io.close_secondary();
            session.conn_mut().ftpc_mut().freedirs();
            return Err(error);
        }
    }

    let (pp, mut machine) = session.split();
    machine.dophase_done(pp, io, connected)?;
    Ok(())
}

/// `ftp_perform` (`lib/ftp.c:3734-3773`): the DO phase proper.
///
/// Answers `(connected, dophase_done)` -- the C's two out-parameters.
///
/// # Errors
///
/// Whatever the first quote list or the state machine reports.
#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
pub(crate) async fn ftp_perform(
    session: &mut FtpSession,
    io: &mut FtpIo<'_>,
) -> CurlResult<(bool, bool)> {
    {
        let state = session.conn().ftpc().state();
        io.client_mut()
            .trc_ftp(format_args!("[{}] DO phase starts", cstate(Some(state))));
    }

    if io.opts().no_body {
        // "requested no body means no transfer..."
        session.transfer_mut().transfer = PpTransfer::Info;
    }

    {
        // "start the first command in the DO phase"
        let (pp, mut machine) = session.split();
        machine.state_quote(pp, io, true, FtpState::Quote)?;
    }

    // "run the state-machine"
    let dophase_done = ftp_statemach(session, io).await?;
    let connected = io.is_connected(SocketIndex::Secondary);

    let state = session.conn().ftpc().state();
    if connected {
        io.client_mut().infof(format_args!(
            "[FTP] [{}] perform, DATA connection established",
            cstate(Some(state))
        ));
    } else {
        io.client_mut().trc_ftp(format_args!(
            "[{}] perform, awaiting DATA connect",
            cstate(Some(state))
        ));
    }
    if dophase_done {
        io.client_mut().trc_ftp(format_args!(
            "[{}] DO phase is complete1",
            cstate(Some(state))
        ));
    }

    Ok((connected, dophase_done))
}

/// `ftp_regular_transfer` (`lib/ftp.c:4015-4043`): everything a normal
/// transfer does before the data flows.
///
/// # Errors
///
/// Whatever the DO phase reports. A failure releases the path components, as
/// the C's `freedirs` does.
#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
pub(crate) async fn ftp_regular_transfer(
    session: &mut FtpSession,
    io: &mut FtpIo<'_>,
) -> CurlResult<bool> {
    // "make sure this is unknown at this point"
    io.req_mut().size = -1;
    io.client_mut().pgrs_reset();
    session.conn_mut().ftpc_mut().ctl_valid = true; // "starts good"

    let performed = ftp_perform(session, io).await;
    let (connected, dophase_done) = match performed {
        Ok(pair) => pair,
        Err(error) => {
            session.conn_mut().ftpc_mut().freedirs();
            return Err(error);
        }
    };

    if !dophase_done {
        // "the DO phase has not completed yet"
        return Ok(false);
    }

    ftp_dophase_done(session, io, connected).await?;
    Ok(true)
}

/// `ftp_do` (`lib/ftp.c:4064-4111`): the registered DO entry point.
///
/// The C's `#ifdef CURL_PREFER_LF_LINEENDS` block installs a line-ending
/// converting client writer, and that platform is outside the four-target
/// matrix, so there is nothing here to install: the writer chain is left as the
/// transfer built it.
///
/// # Errors
///
/// Whatever the wildcard driver, the path parser, or the DO phase reports.
#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
pub(crate) async fn ftp_do(
    session: &mut FtpSession,
    io: &mut FtpIo<'_>,
) -> CurlResult<bool> {
    // "default to no such wait"
    session.conn_mut().ftpc_mut().wait_data_conn = false;

    if io.req().wildcardmatch {
        let outcome = wc_statemach(session, io);
        let state = session.wildcard().state;
        if state == WildcardState::Skip || state == WildcardState::Done {
            // "do not call ftp_regular_transfer"
            return Ok(true);
        }
        // "error, loop or skipping the file"
        outcome?;
    } else {
        // "no wildcard FSM needed"
        let (_pp, machine) = session.split();
        machine
            .ftpc
            .parse_url_path(machine.transfer, io)
            .map_err(Error::new)?;
    }

    ftp_regular_transfer(session, io).await
}

/// `ftp_doing` (`lib/ftp.c:4180-4198`): *"called from multi.c while DOing"*.
///
/// # Errors
///
/// Whatever the state machine or the DO-phase completion reports.
#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
pub(crate) async fn ftp_doing(
    session: &mut FtpSession,
    io: &mut FtpIo<'_>,
) -> CurlResult<bool> {
    let outcome = ftp_statemach(session, io).await;
    let state = session.conn().ftpc().state();
    match outcome {
        Err(error) => {
            io.client_mut().trc_ftp(format_args!(
                "[{}] DO phase failed",
                cstate(Some(state))
            ));
            Err(error)
        }
        Ok(false) => Ok(false),
        Ok(true) => {
            // "not connected"
            ftp_dophase_done(session, io, false).await?;
            let state = session.conn().ftpc().state();
            io.client_mut().trc_ftp(format_args!(
                "[{}] DO phase is complete2",
                cstate(Some(state))
            ));
            Ok(true)
        }
    }
}

// The wildcard driver

/// `lib/ftp.c:3860` -- what the listing parser's installation announces.
#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
pub(crate) const WILDCARD_PARSING_MESSAGE: &str = "Wildcard - Parsing started";

/// `init_wc_data` (`lib/ftp.c:3784-3871`): cut the pattern off the path, and
/// hand the listing to the parser.
///
/// # The three shapes a wildcard path can have
///
/// | Path | Pattern | Directory left behind |
/// |------|---------|-----------------------|
/// | `dir/*.txt` | `*.txt` | `dir/` |
/// | `*.txt` | `*.txt` | empty |
/// | `dir/` or empty | none -- [`WildcardState::Clean`], list only | unchanged |
///
/// The third row is the one that is easy to get wrong: a path ending in a slash
/// is **not** an error and **not** a match of everything. It sets
/// [`WildcardState::Clean`] and performs an ordinary path parse, so the request
/// becomes a plain directory listing and the driver's next lap tears the
/// wildcard machinery down without transferring anything.
///
/// [`FileMethod::NoCwd`] is coerced to [`FileMethod::MultiCwd`] here, not
/// refused: the C's line is `if(data->set.ftp_filemethod == FTPFILE_NOCWD)
/// data->set.ftp_filemethod = FTPFILE_MULTICWD;` (`lib/ftp.c:3839-3841`), whose
/// comment reads *"wildcard does not support NOCWD option (assert it?)"* -- the
/// parenthetical is the C author wondering aloud, not a rejection.
///
/// # Errors
///
/// Whatever the path parser reports. The C's three `CURLE_OUT_OF_MEMORY` exits
/// guard allocations that cannot fail here, and its `fail:` label releases the
/// parser and the pattern -- which ownership does instead: [`WildcardData`]
/// keeps neither on the error path because neither is stored until the parse has
/// succeeded.
#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
fn init_wc_data(
    session: &mut FtpSession,
    io: &mut FtpIo<'_>,
) -> CurlResult<()> {
    let path = session.transfer().path().to_vec();

    let pattern = match path.iter().rposition(|&byte| byte == b'/') {
        Some(slash) => {
            let after = slash.saturating_add(1);
            if after >= path.len() {
                // "wildcard->state = CURLWC_CLEAN; return
                // ftp_parse_url_path(...)"
                session.wildcard_mut().state = WildcardState::Clean;
                let (_pp, machine) = session.split();
                return machine
                    .ftpc
                    .parse_url_path(machine.transfer, io)
                    .map_err(Error::new);
            }
            let pattern = path.get(after..).unwrap_or(&[]).to_vec();
            // "cut file from path"
            session.transfer_mut().truncate_path(after);
            pattern
        }
        None => {
            // "there is only 'wildcard pattern' or nothing"
            if path.is_empty() {
                // "only list"
                session.wildcard_mut().state = WildcardState::Clean;
                let (_pp, machine) = session.split();
                return machine
                    .ftpc
                    .parse_url_path(machine.transfer, io)
                    .map_err(Error::new);
            }
            session.transfer_mut().truncate_path(0);
            path
        }
    };

    // "program continues only if URL is not ending with slash, allocate needed
    // resources for wildcard transfer"
    let ftpwc = FtpWildcard::new(&pattern);

    // "wildcard does not support NOCWD option"
    if io.req().file_method == FileMethod::NoCwd {
        io.req_mut().file_method = FileMethod::MultiCwd;
    }

    // "try to parse ftp URL"
    {
        let (_pp, machine) = session.split();
        machine
            .ftpc
            .parse_url_path(machine.transfer, io)
            .map_err(Error::new)?;
    }

    let dir = String::from_utf8_lossy(session.transfer().path()).into_owned();
    let backup = io.client_mut().install_listing_writer();
    let wildcard = session.wildcard_mut();
    wildcard.pattern = Some(String::from_utf8_lossy(&pattern).into_owned());
    wildcard.path = Some(dir);
    wildcard.ftpwc = Some(FtpWildcard { backup, ..ftpwc });

    io.client_mut()
        .infof(format_args!("{WILDCARD_PARSING_MESSAGE}"));
    Ok(())
}

/// `wc_statemach` (`lib/ftp.c:3878-4005`): one lap of the wildcard driver.
///
/// The C's loop is a `for(;;)` whose arms either `continue` or `return`; that is
/// preserved literally, because which arms fall through to the next state
/// without returning is what decides how many transfers one call sets up. Only
/// [`WildcardState::Downloading`] and [`WildcardState::Init`] ever return with a
/// concrete file prepared.
///
/// # Where the parsed entries come from
///
/// The C's listing parser appends straight into `wildcard->filelist`, because
/// both are reachable through `data`. Here the parser owns its own accepted
/// queue and the driver moves it across at the [`WildcardState::Matching`]
/// transition with [`ParselistData::take_accepted`] -- one move, order preserved,
/// no borrow of the structure that owns the parser.
///
/// # Errors
///
/// [`CURLcode::RemoteFileNotFound`] when the listing matched nothing,
/// [`CURLcode::ChunkFailed`] when the chunk-begin callback refused, the parser's
/// latched error, and whatever the path parser reports.
#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
fn wc_statemach(
    session: &mut FtpSession,
    io: &mut FtpIo<'_>,
) -> CurlResult<()> {
    loop {
        match session.wildcard().state {
            WildcardState::Init => {
                let outcome = init_wc_data(session, io);
                if session.wildcard().state == WildcardState::Clean {
                    // "only listing!"
                    return outcome;
                }
                session.wildcard_mut().state = if outcome.is_err() {
                    WildcardState::Error
                } else {
                    WildcardState::Matching
                };
                return outcome;
            }

            WildcardState::Matching => {
                // "In this state is LIST response successfully parsed, so lets
                // restore previous WRITEFUNCTION callback and WRITEDATA
                // pointer"
                let (backup, parser_error, accepted) = {
                    let Some(ftpwc) = session.wildcard_mut().ftpwc.as_mut()
                    else {
                        // The C dereferences `wildcard->ftpwc` unconditionally
                        // here; it cannot be absent, because MATCHING is only
                        // ever reached from a successful INIT. The type says so
                        // and this arm is what says it without a panic.
                        session.wildcard_mut().state = WildcardState::Clean;
                        continue;
                    };
                    let backup = core::mem::take(&mut ftpwc.backup);
                    let error = ftpwc.parser.geterror();
                    let accepted = ftpwc.parser.take_accepted();
                    (backup, error, accepted)
                };
                io.client_mut().restore_listing_writer(backup);
                session.wildcard_mut().filelist.extend(accepted);
                session.wildcard_mut().state = WildcardState::Downloading;

                if parser_error != CURLcode::Ok {
                    // "error found in LIST parsing"
                    session.wildcard_mut().state = WildcardState::Clean;
                    continue;
                }
                if session.wildcard().filelist.is_empty() {
                    // "no corresponding file"
                    session.wildcard_mut().state = WildcardState::Clean;
                    return Err(Error::with_context(
                        CURLcode::RemoteFileNotFound,
                        "the listing matched no file",
                    ));
                }
                continue;
            }

            WildcardState::Downloading => {
                // "filelist has at least one file, lets get first one"
                let Some(finfo) = session.wildcard().filelist.front().cloned()
                else {
                    // Unreachable by construction: MATCHING refuses to enter
                    // this state with an empty queue and every exit from it
                    // either leaves one entry behind or moves to CLEAN.
                    session.wildcard_mut().state = WildcardState::Clean;
                    continue;
                };

                // "switch default ftp->path and tmp_path" -- `"%s%s"`, exactly.
                let dir = session.wildcard().path.clone().unwrap_or_default();
                let mut tmp_path = dir.into_bytes();
                tmp_path.extend_from_slice(finfo.filename.as_bytes());
                session.transfer_mut().set_path_override(tmp_path);

                let name = finfo.filename.clone();
                io.client_mut()
                    .infof(format_args!("Wildcard - START of \"{name}\""));
                let remaining =
                    i32::try_from(session.wildcard().filelist.len())
                        .unwrap_or(i32::MAX);
                match io.client_mut().chunk_bgn(&finfo, remaining) {
                    Some(ChunkBgn::Skip) => {
                        io.client_mut().infof(format_args!(
                            "Wildcard - \"{name}\" skipped by user"
                        ));
                        session.wildcard_mut().state = WildcardState::Skip;
                        continue;
                    }
                    Some(ChunkBgn::Fail) => {
                        return Err(Error::with_context(
                            CURLcode::ChunkFailed,
                            "the chunk-begin callback refused the entry",
                        ));
                    }
                    Some(ChunkBgn::Ok) | None => {}
                }

                if finfo.filetype != FileType::File {
                    session.wildcard_mut().state = WildcardState::Skip;
                    continue;
                }

                if finfo.flags & FileInfo::KNOWN_SIZE != 0 {
                    session.conn_mut().ftpc_mut().known_filesize = finfo.size;
                }

                {
                    let (_pp, machine) = session.split();
                    machine
                        .ftpc
                        .parse_url_path(machine.transfer, io)
                        .map_err(Error::new)?;
                }

                // "we do not need the Curl_fileinfo of first file anymore"
                session.wildcard_mut().filelist.pop_front();

                if session.wildcard().filelist.is_empty() {
                    // "remains only one file to down." -- and then "after that
                    // will be ftp_do called once again and no transfer will be
                    // done because of CURLWC_CLEAN state"
                    session.wildcard_mut().state = WildcardState::Clean;
                }
                return Ok(());
            }

            WildcardState::Skip => {
                if let Some(outcome) = io.client_mut().chunk_end() {
                    let _ = outcome;
                }
                session.wildcard_mut().filelist.pop_front();
                session.wildcard_mut().state =
                    if session.wildcard().filelist.is_empty() {
                        WildcardState::Clean
                    } else {
                        WildcardState::Downloading
                    };
                continue;
            }

            WildcardState::Clean => {
                let error = match session.wildcard().ftpwc.as_ref() {
                    Some(ftpwc) => ftpwc.parser.geterror(),
                    None => CURLcode::Ok,
                };
                session.wildcard_mut().state = if error == CURLcode::Ok {
                    WildcardState::Done
                } else {
                    WildcardState::Error
                };
                return if error == CURLcode::Ok {
                    Ok(())
                } else {
                    Err(Error::new(error))
                };
            }

            WildcardState::Done
            | WildcardState::Error
            | WildcardState::Clear => {
                // `wildcard->dtor(wildcard->ftpwc); wildcard->ftpwc = NULL;`
                // The destructor existed to free the parser through a
                // type-erased pointer; dropping the owned value does it, and
                // does it whether or not the C would have registered one.
                session.wildcard_mut().ftpwc = None;
                return Ok(());
            }
        }
    }
}

// Completion, disconnection, and the pollsets

/// `lib/ftp.c:3641`.
#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
pub(crate) const ABOR_FAILURE_PREFIX: &str = "Failure sending ABOR command: ";

/// `lib/ftp.c:3592`.
#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
pub(crate) const CONTROL_DEAD_MESSAGE: &str = "control connection looks dead";

/// `lib/ftp.c:3634`.
#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
pub(crate) const DISK_FULL_MESSAGE: &str = "Exceeded storage allocation";

/// Which of `ftp_done`'s two classes a status code falls into
/// (`lib/ftp.c:3512-3541`).
///
/// The C's `switch` lists thirteen codes that share `CURLE_OK`'s arm, and the
/// comment on that arm is the whole point: *"the connection stays alive fine
/// even though this happened"*. Everything else means *"the control connection
/// is wedged and should not be used anymore"*.
///
/// `premature` folds into the second class through a deliberate
/// `FALLTHROUGH()`, whose comment records that it is a stopgap: *"until we cope
/// better with prematurely ended requests, let them fallback as if in complete
/// failure"*.
#[rustfmt::skip]
#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
pub(crate) const DONE_SURVIVABLE: [CURLcode; 13] = [
    CURLcode::BadDownloadResume,
    CURLcode::FtpWeirdPasvReply,
    CURLcode::FtpPortFailed,
    CURLcode::FtpAcceptFailed,
    CURLcode::FtpAcceptTimeout,
    CURLcode::FtpCouldntSetType,
    CURLcode::FtpCouldntRetrFile,
    CURLcode::PartialFile,
    CURLcode::UploadFailed,
    CURLcode::RemoteAccessDenied,
    CURLcode::FilesizeExceeded,
    CURLcode::RemoteFileNotFound,
    CURLcode::WriteError,
];

/// Whether `status` leaves the control connection usable (`lib/ftp.c:3512`).
#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
pub(crate) fn done_status_survivable(
    status: CURLcode,
    premature: bool,
) -> bool {
    if premature {
        // The `FALLTHROUGH()` at `:3533`: every code, including
        // [`CURLcode::Ok`], joins the wedged class.
        return false;
    }
    status == CURLcode::Ok || DONE_SURVIVABLE.contains(&status)
}

/// `ftp_done` (`lib/ftp.c:3496-3714`): everything a completed DO has left to do.
///
/// # The one clause most easily got wrong
///
/// `dont_check` suppresses **interpretation** of the closing reply, never the
/// **read** of it. The C's shape is one `if` that performs the read followed by
/// a separate `if(!ftpc->dont_check)` that judges what came back
/// (`:3604-3646`), and skipping the read instead would leave an unread `226` in
/// the receive buffer for the next transfer on the same connection to mistake
/// for its own.
///
/// # Errors
///
/// `status` itself for a wedged connection, [`CURLcode::RemoteDiskFull`] for a
/// `552`, [`CURLcode::PartialFile`] for any other unexpected closing code or a
/// byte count that does not add up, [`CURLcode::FtpCouldntRetrFile`] when
/// nothing arrived at all, and whatever the closing read or the post-transfer
/// quote list reports.
#[allow(clippy::too_many_lines)]
// 218 lines in the C, and the order of its
// clauses is the contract: each one can change `result`, and a later clause
// reads what an earlier one decided.
#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
pub(crate) async fn ftp_done(
    session: &mut FtpSession,
    io: &mut FtpIo<'_>,
    status: CURLcode,
    premature: bool,
) -> CurlResult<()> {
    let mut result: CurlResult<()> = Ok(());

    if !done_status_survivable(status, premature) {
        // "by default, an error means the control connection is wedged and
        // should not be used anymore"
        session.conn_mut().ftpc_mut().ctl_valid = false;
        // "set this TRUE to prevent us to remember the current path, as this
        // connection is going"
        session.conn_mut().ftpc_mut().cwdfail = true;
        io.client_mut().conn_close("FTP ended with bad error code");
        // "use the already set error code"
        result = Err(Error::new(status));
    }

    if io.req().wildcardmatch {
        if session.conn().ftpc().has_file() {
            if let Some(outcome) = io.client_mut().chunk_end() {
                let _ = outcome;
            }
            session.conn_mut().ftpc_mut().freedirs();
        }
        session.conn_mut().ftpc_mut().known_filesize = -1;
    }

    if result.is_err() {
        // "We can limp along anyway (and should try to since we may already be
        // in the error path)"
        session.conn_mut().ftpc_mut().ctl_valid = false;
        io.client_mut().conn_close("FTP: out of memory!");
        // "no path remembering"
        session.conn_mut().ftpc_mut().prevpath = None;
    } else {
        // "remember working directory for connection reuse"
        let rawpath = session.conn().ftpc().rawpath().to_vec();
        if !rawpath.is_empty() {
            let nocwd = io.req().file_method == FileMethod::NoCwd;
            if nocwd && rawpath.first() == Some(&b'/') {
                // "full path => no CWDs happened => keep ftpc->prevpath"
            } else {
                let ftpc = session.conn_mut().ftpc_mut();
                if ftpc.cwdfail {
                    ftpc.prevpath = None; // "no path"
                } else {
                    let path_len = if nocwd {
                        // "relative path => working directory is FTP home"
                        0
                    } else {
                        // "file is url-decoded"
                        let file_len = ftpc.file().map_or(0, <[u8]>::len);
                        rawpath.len().saturating_sub(file_len)
                    };
                    ftpc.prevpath =
                        Some(rawpath.get(..path_len).unwrap_or(&[]).to_vec());
                }
            }
        }
        if let Some(prevpath) = session.conn().ftpc().prevpath.clone() {
            let shown = String::from_utf8_lossy(&prevpath).into_owned();
            io.client_mut().infof(format_args!(
                "Remembering we are in directory \"{shown}\""
            ));
        }
    }

    // "shut down the socket to inform the server we are done"
    if io.is_setup(SocketIndex::Secondary) {
        let abort = result.is_ok()
            && session.conn().ftpc().dont_check
            && io.req().maxdownload > 0;
        if abort {
            // "partial download completed"
            let (pp, _machine) = session.split();
            if let Err(error) = pp.sendn(io, b"ABOR") {
                let text = error.code().message();
                io.client_mut()
                    .failf(format_args!("{ABOR_FAILURE_PREFIX}{text}"));
                // "mark control connection as bad"
                session.conn_mut().ftpc_mut().ctl_valid = false;
                io.client_mut().conn_close("ABOR command failed");
            }
        }
        io.close_secondary();
    }

    let read_closing = result.is_ok()
        && session.transfer().transfer == PpTransfer::Body
        && session.conn().ftpc().ctl_valid
        && session.conn().pp().pending_resp()
        && !premature;
    if read_closing {
        // "Let's see what the server says about the transfer we just performed,
        // but lower the timeout as sometimes this connection has died while the
        // data has been transferred. This happens when doing through NATs etc
        // that abandon old silent connections."
        let now = io.clock().now();
        let (pp, mut machine) = session.split();
        let read = getftpresponse(&mut machine, pp, io, Some(now)).await;

        let (nread, ftpcode) = match read {
            Ok(pair) => pair,
            Err(error) => {
                if error.code() == CURLcode::OperationTimedout {
                    io.client_mut()
                        .failf(format_args!("{CONTROL_DEAD_MESSAGE}"));
                    session.conn_mut().ftpc_mut().ctl_valid = false;
                    io.client_mut()
                        .conn_close("Timeout or similar in FTP DONE operation");
                }
                return Err(error);
            }
        };
        // The C tests `!nread && (result == CURLE_OPERATION_TIMEDOUT)`; a
        // timeout is the error path above, so what remains here is the
        // successful read, and `nread` is what it measured.
        let _ = nread;

        if session.conn().ftpc().dont_check && io.req().maxdownload > 0 {
            // "we have just sent ABOR and there is no reliable way to check if
            // it was successful or not; we have to close the connection now"
            io.client_mut().infof(format_args!(
                "partial download completed, closing connection"
            ));
            io.client_mut()
                .conn_close("Partial download with no ability to check");
            return Ok(());
        }

        if !session.conn().ftpc().dont_check {
            // "226 Transfer complete, 250 Requested file action okay,
            // completed."
            match ftpcode {
                226 | 250 => {}
                552 => {
                    io.client_mut().failf(format_args!("{DISK_FULL_MESSAGE}"));
                    result = Err(Error::with_context(
                        CURLcode::RemoteDiskFull,
                        DISK_FULL_MESSAGE,
                    ));
                }
                _ => {
                    let message =
                        format!("server did not report OK, got {ftpcode}");
                    io.client_mut().failf(format_args!("{message}"));
                    result = Err(Error::with_context(
                        CURLcode::PartialFile,
                        message,
                    ));
                }
            }
        }
    }

    if result.is_ok() && !premature {
        // "the response code from the transfer showed an error already so no
        // use checking further"
        if io.req().upload {
            let body = session.transfer().transfer == PpTransfer::Body;
            let infilesize = io.req().infilesize;
            let written = io.req().writebytecount;
            let converting = io.opts().crlf || io.req().prefer_ascii;
            let unaligned = if converting {
                // "maybe crlf conv"
                infilesize > written
            } else {
                // "no conversion"
                infilesize != written
            };
            if body && infilesize != -1 && unaligned {
                let message = format!(
                    "Uploaded unaligned file size ({written} out of \
                     {infilesize} bytes)"
                );
                io.client_mut().failf(format_args!("{message}"));
                result =
                    Err(Error::with_context(CURLcode::PartialFile, message));
            }
        } else {
            let size = io.req().size;
            let bytecount = io.req().bytecount;
            let maxdownload = io.req().maxdownload;
            if size != -1 && size != bytecount && maxdownload != bytecount {
                let message =
                    format!("Received only partial file: {bytecount} bytes");
                io.client_mut().failf(format_args!("{message}"));
                result =
                    Err(Error::with_context(CURLcode::PartialFile, message));
            } else if !session.conn().ftpc().dont_check
                && bytecount == 0
                && size > 0
            {
                let message = "No data was received";
                io.client_mut().failf(format_args!("{message}"));
                result = Err(Error::with_context(
                    CURLcode::FtpCouldntRetrFile,
                    message,
                ));
            }
        }
    }

    // "clear these for next connection"
    session.transfer_mut().transfer = PpTransfer::Body;
    session.conn_mut().ftpc_mut().dont_check = false;

    // "Send any post-transfer QUOTE strings?"
    let postquote = io.opts().postquote.clone();
    if status == CURLcode::Ok
        && result.is_ok()
        && !premature
        && !postquote.is_empty()
    {
        result = ftp_sendquote(session, io, &postquote).await;
    }

    let state = session.conn().ftpc().state();
    let code = match &result {
        Ok(()) => CURLcode::Ok,
        Err(error) => error.code(),
    };
    io.client_mut().trc_ftp(format_args!(
        "[{}] done, result={}",
        cstate(Some(state)),
        code.as_i32()
    ));
    result
}

/// `ftp_quit` (`lib/ftp.c:4123-4147`): say goodbye, and wait to be answered.
///
/// The C's own caution is the reason `ctl_valid` gates this: *"This should be
/// called before calling sclose() on an ftp control connection (not data
/// connections). We should then wait for the response from the server before
/// returning."*
///
/// # Errors
///
/// Whatever the send or the blocking read reports. The disconnect caller
/// discards them.
#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
pub(crate) async fn ftp_quit(
    session: &mut FtpSession,
    io: &mut FtpIo<'_>,
) -> CurlResult<()> {
    if !session.conn().ftpc().ctl_valid {
        return Ok(());
    }

    io.client_mut()
        .trc_ftp(format_args!("sending QUIT to close session"));
    {
        let (pp, _machine) = session.split();
        if let Err(error) = pp.sendn(io, b"QUIT") {
            let text = error.code().message();
            io.client_mut()
                .failf(format_args!("Failure sending QUIT command: {text}"));
            // "mark control connection as bad"
            session.conn_mut().ftpc_mut().ctl_valid = false;
            io.client_mut().conn_close("QUIT command failed");
            let (_pp, mut machine) = session.split();
            machine.set_state(FtpState::Stop, io);
            return Err(error);
        }
    }

    {
        let (_pp, mut machine) = session.split();
        machine.set_state(FtpState::Quit, io);
    }
    ftp_block_statemach(session, io).await
}

/// `ftp_disconnect` (`lib/ftp.c:4155-4176`): BLOCKING teardown.
///
/// The C's reasoning for not always sending `QUIT` is preserved verbatim in its
/// own words: *"We cannot send quit unconditionally. If this connection is stale
/// or bad in any way, sending quit and waiting around here will make the
/// disconnect wait in vain and cause more problems than we need to."*
///
/// Errors from the goodbye are discarded -- `(void)ftp_quit(...)`, *"ignore
/// errors on the QUIT"* -- and the cadence engine and the connection's FTP state
/// are released afterwards.
///
/// # Errors
///
/// Never in practice. The C ignores `Curl_pp_disconnect`'s answer and
/// `return CURLE_OK`s; the release is forwarded here instead of discarded,
/// which is the same outcome because [`PingPong::disconnect`] cannot fail.
#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
pub(crate) async fn ftp_disconnect(
    session: &mut FtpSession,
    io: &mut FtpIo<'_>,
    dead_connection: bool,
) -> CurlResult<()> {
    session.conn_mut().ftpc_mut().shutdown = true;
    if dead_connection || session.conn().pp().needs_flush() {
        session.conn_mut().ftpc_mut().ctl_valid = false;
    }

    // "The FTP session may or may not have been allocated/setup at this point!"
    let _ = ftp_quit(session, io).await;
    session.conn_mut().dtor()
}

#[allow(dead_code)] // consumer: the FTP phase drivers, and mod tests
impl FtpMachine<'_> {
    /// `ftp_pollset` (`lib/ftp.c:762-772`), which serves both `proto_pollset`
    /// and `doing_pollset`.
    ///
    /// # Errors
    ///
    /// Whatever the pollset change reports.
    fn pollset(
        &mut self,
        pp: &PingPong,
        io: &mut FtpIo<'_>,
        ps: &mut EasyPollset,
    ) -> CodeResult<()> {
        let _ = &self.ftpc;
        pp.pollset(io, ps, None)
    }

    /// `ftp_domore_pollset` (`lib/ftp.c:774-800`): the dual-channel pollset.
    ///
    /// The C's comment carries the whole reason this slot is overridden at all:
    /// *"When in DO_MORE state, we could be either waiting for us to connect to
    /// a remote site, or we could wait for that site to connect to us. Or just
    /// handle ordinary commands."* In the first two cases the secondary chain
    /// contributes its own descriptor and the control socket is watched for
    /// reading alongside it, so a server that changes its mind mid-wait is
    /// noticed.
    ///
    /// # Errors
    ///
    /// Whatever the pollset change reports.
    fn domore_pollset(
        &mut self,
        pp: &PingPong,
        io: &mut FtpIo<'_>,
        ps: &mut EasyPollset,
    ) -> CodeResult<()> {
        if self.ftpc.state() == FtpState::Stop {
            // "we are waiting for a connect to happen, the secondary filter
            // chain contributes its own socket; watch the control connection
            // for input at the same time"
            let sock = io.socket_of(SocketIndex::First);
            if sock != CURL_SOCKET_BAD {
                return ps.change(sock, PollAction::IN, PollAction::NONE, None);
            }
            return Ok(());
        }
        pp.pollset(io, ps, None)
    }
}

// The handler, and the two registry rows

/// `Curl_protocol_ftp` (`lib/ftp.c:4323-4341`) -- the one handler both FTP
/// schemes point at.
///
/// # Eleven of seventeen slots, and the six that stay empty
///
/// The C fills `setup_connection`, `do_it`, `done`, `do_more`, `connect_it`,
/// `connecting`, `doing`, `proto_pollset`, `doing_pollset`, `domore_pollset` and
/// `disconnect`, and writes `ZERO_NULL` into `perform_pollset`, `write_resp`,
/// `write_resp_hd`, `connection_check`, `attach` and `follow`. All six defaults
/// are what a `NULL` slot means to the C's caller, so not writing them is the
/// faithful choice rather than an omission:
///
/// ```text
/// perform_pollset  -> the generic default one runs (lib/urldata.h:473-474)
/// write_resp       -> the generic client-writer chain runs
/// write_resp_hd    -> likewise
/// connection_check -> CONNRESULT_NONE; the pool learns nothing extra
/// attach           -> nothing to re-point at a new transfer
/// follow           -> CURLE_TOO_MANY_REDIRECTS; FTP has no redirects
/// ```
///
/// `proto_pollset` and `doing_pollset` are filled with the SAME function in the
/// C, and that is reproduced: both members below call
/// [`FtpMachine::pollset`].
///
/// # What the seven asynchronous members can and cannot reach
///
/// Each one delegates to a free function in this file that is implemented in
/// full -- [`ftp_do`], [`ftp_done`], [`ftp_do_more`], [`ftp_connect`],
/// [`ftp_statemach`], [`ftp_doing`], [`ftp_disconnect`] -- and every one of
/// those is exercised end to end by [`mod tests`](self) over an in-memory
/// transport. What none of them can be reached WITH is an [`FtpSession`]:
/// [`TransferCtx`] carries the filter chains, the clock, the scheme and the
/// socket index and nothing else, so there is nowhere for a transfer's FTP state
/// to travel from. The C keeps it in
/// `Curl_conn_meta_set(conn, CURL_META_FTP_CONN, ...)` and
/// `Curl_meta_set(data, CURL_META_FTP_EASY, ...)`, and specification 0.3.3's
/// requirement that those two string-keyed meta slots be ELIMINATED is met by
/// [`FtpSession`] owning both as typed fields -- which is the right shape and is
/// not yet something a `TransferCtx` can hand over.
///
/// So those seven report [`CURLcode::NotBuiltIn`], following the precedent
/// `protocols::sftp` sets, and the reason is worth stating plainly: answering
/// `Ok(true)` instead would tell the transfer core that a phase had completed
/// and hand an empty body to the client. Specification 0.6.5 measures that
/// asymmetry exactly -- under-reporting a capability makes a fixture SKIP, and
/// over-reporting makes it RUN AND FAIL -- so the honest report is the one that
/// keeps the 266 FTP and FTPS fixtures skipping cleanly until a caller exists.
/// `crate::version`'s protocol banner withholds `ftp` for the same reason.
///
/// The three pollsets are different, and they WORK: the readiness a pollset
/// records is a function of the control chain's descriptor and of whether a
/// command is half-sent, and [`TransferCtx`] supplies the first while the second
/// is `false` with no cadence engine in play. That is exactly the C's behaviour
/// for a connection whose send buffer is empty.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct FtpProtocol;

/// The one instance, which both rows point at.
///
/// A `const` rather than a `static`, for the reason `protocols::sftp`'s own
/// instance records: under **MSRV 1.75** a `const` initialiser may not refer to
/// a `static` (`error[E0013]`), and every consumer here is a `const` --
/// [`RUN_FTP`], [`SCHEME_FTP`], [`SCHEME_FTPS`], and `protocols/mod.rs`'s
/// `IN_SCOPE_SCHEMES`, which is a `const` table. [`FtpProtocol`] is zero-sized,
/// so `&FTP` in a `const` context is const-promoted to a `&'static` reference to
/// a zero-sized allocation and there is no storage for a `static` to reserve.
pub(crate) const FTP: FtpProtocol = FtpProtocol;

/// The implementation column BOTH rows carry -- the C's
/// `&Curl_protocol_ftp`, written once.
///
/// One constant rather than two `Some(&FTP)` literals, and that is the point:
/// the C registers ONE handler object and `Curl_scheme_ftp` and
/// `Curl_scheme_ftps` both name it (`lib/ftp.c:4352` and `:4373`). Writing it
/// once here is what makes that shared identity a fact of the source rather than
/// a coincidence of two independent spellings, and
/// `both_rows_share_one_handler_column` asserts it from the rows.
///
/// The C's `#ifdef CURL_DISABLE_FTP ZERO_NULL #else &Curl_protocol_ftp #endif`
/// is the parent's business, not this file's: the whole module is declared
/// `#[cfg(feature = "ftp")]` by `protocols/mod.rs`, so a build without the
/// feature does not compile these rows at all and the registry keeps its own
/// `run: None` for both schemes. There is deliberately no second
/// implementation value and no feature gate of this file's own.
pub(crate) const RUN_FTP: Option<&'static dyn Protocol> = Some(&FTP);

/// The `ftp` row -- `Curl_scheme_ftp` (`lib/ftp.c:4348-4362`).
///
/// ```text
/// "ftp",                           /* scheme */
/// &Curl_protocol_ftp,
/// CURLPROTO_FTP,                   /* protocol */
/// CURLPROTO_FTP,                   /* family */
/// PROTOPT_DUAL | PROTOPT_CLOSEACTION | PROTOPT_NEEDSPWD |
/// PROTOPT_NOURLQUERY | PROTOPT_PROXY_AS_HTTP |
/// PROTOPT_WILDCARD | PROTOPT_SSL_REUSE |
/// PROTOPT_CONN_REUSE,              /* flags */
/// PORT_FTP,                        /* defport */
/// ```
///
/// `flags` and `defport` are CONSUMED from `protocols/mod.rs`, which owns the
/// one transcription of `FLAGS_FTP` and `PORT_FTP`, so this row and the registry
/// table cannot disagree about either. What this file adds is the `run` column.
#[rustfmt::skip]
pub(crate) const SCHEME_FTP: Scheme = Scheme {
    name: b"ftp",
    run: RUN_FTP,
    protocol: Proto::FTP,
    family: Proto::FTP,
    flags: FLAGS_FTP,
    defport: PORT_FTP,
};

/// The `ftps` row -- `Curl_scheme_ftps` (`lib/ftp.c:4367-4380`).
///
/// ```text
/// "ftps",                          /* scheme */
/// &Curl_protocol_ftp,
/// CURLPROTO_FTPS,                  /* protocol */
/// CURLPROTO_FTP,                   /* family */
/// PROTOPT_SSL | PROTOPT_DUAL | PROTOPT_CLOSEACTION |
/// PROTOPT_NEEDSPWD | PROTOPT_NOURLQUERY | PROTOPT_WILDCARD |
/// PROTOPT_CONN_REUSE,              /* flags */
/// PORT_FTPS,                       /* defport */
/// ```
///
/// Two columns are worth naming. The FAMILY is `CURLPROTO_FTP`, not
/// `CURLPROTO_FTPS`, which is what makes every `PROTO_FAMILY_FTP` test in the
/// tree admit FTPS -- including the reuse predicate's. And the flags deliberately
/// carry NEITHER `PROTOPT_PROXY_AS_HTTP` nor `PROTOPT_SSL_REUSE`, both of which
/// plain `ftp` does: `ftps` cannot be handed to an HTTP proxy as HTTP, and it has
/// no need to borrow another scheme's TLS because it carries `PROTOPT_SSL`
/// itself.
#[rustfmt::skip]
pub(crate) const SCHEME_FTPS: Scheme = Scheme {
    name: b"ftps",
    run: RUN_FTP,
    protocol: Proto::FTPS,
    family: Proto::FTP,
    flags: FLAGS_FTPS,
    defport: PORT_FTPS,
};

/// Both rows, in the C's registration order.
///
/// `protocols/mod.rs` assembles the registry; this is what it takes from here.
/// The order is `lib/url.c:1490-1491`'s -- `ftp` then `ftps` -- and it is the
/// order of `IN_SCOPE_SCHEMES`, so adopting these two is a substitution and not
/// a reordering.
#[rustfmt::skip]
#[allow(dead_code)] // consumer: protocols/mod.rs, which installs the rows
pub(crate) const SCHEMES: [Scheme; 2] = [SCHEME_FTP, SCHEME_FTPS];

/// `ftp_attach`-equivalent precondition: the scheme really belongs to the FTP
/// family.
///
/// The C has no `attach` slot for FTP -- it is `ZERO_NULL` -- so this is not a
/// port of one. It is the precondition every other member assumes, made
/// checkable: one handler serves two schemes, and both have family
/// `CURLPROTO_FTP`, so a row reaching this handler with any other family has
/// been registered wrongly.
fn ftp_family_matches(ctx: &TransferCtx<'_>) -> bool {
    ctx.scheme().family == Proto::FTP
}

impl Protocol for FtpProtocol {
    // -- 1. setup_connection ------------------------------------------------

    /// `ftp_setup_connection` (`lib/ftp.c:4255-4300`): allocate this scheme's
    /// per-connection and per-transfer state.
    ///
    /// The allocation itself is [`ftp_setup_connection`], which builds the
    /// [`FtpSession`] both halves live in and is implemented in full. There is
    /// nowhere to STORE it yet, for the reason [`FtpProtocol`] gives, so this
    /// member validates what it can.
    fn setup_connection(&self, ctx: &mut TransferCtx<'_>) -> CodeResult<()> {
        if ftp_family_matches(ctx) {
            Ok(())
        } else {
            Err(CURLcode::FailedInit)
        }
    }

    // -- 2. do_it -----------------------------------------------------------

    /// `ftp_do` (`lib/ftp.c:4064-4111`) into `ftp_perform` (`:3734-3773`).
    ///
    /// The phase is [`ftp_do`], which drives the wildcard state machine or the
    /// path parser and then [`ftp_regular_transfer`]. The C's `bool *done` is
    /// gone: that function answers the readiness directly.
    fn do_it<'a>(
        &'a self,
        ctx: &'a mut TransferCtx<'_>,
    ) -> ProtoFuture<'a, bool> {
        let _ = ctx;
        Box::pin(core::future::ready(Err(CURLcode::NotBuiltIn)))
    }

    // -- 3. done ------------------------------------------------------------

    /// `ftp_done` (`lib/ftp.c:3496-3714`).
    ///
    /// The decision this member makes is [`ftp_done`]'s and is implemented and
    /// tested in full; what it cannot do is carry it out. Reporting the
    /// transfer's own status unchanged when there is one is what keeps a failed
    /// transfer faithful -- the C's classification at `:3512` uses `status` for
    /// exactly that -- and a successful one cannot occur while [`Self::do_it`]
    /// reports the gap.
    fn done<'a>(
        &'a self,
        ctx: &'a mut TransferCtx<'_>,
        status: CURLcode,
        premature: bool,
    ) -> ProtoFuture<'a, ()> {
        let _ = (ctx, premature);
        Box::pin(core::future::ready(if status == CURLcode::Ok {
            Err(CURLcode::NotBuiltIn)
        } else {
            Err(status)
        }))
    }

    // -- 4. do_more ---------------------------------------------------------

    /// `ftp_do_more` (`lib/ftp.c:2133-2287`) -- the second half of the DO
    /// phase, and the slot no other in-scope scheme fills.
    ///
    /// FTP is the only scheme carrying [`crate::conn::ProtocolOptions::DUAL`],
    /// which is what makes this member and [`Self::domore_pollset`] FTP's alone.
    /// The phase is [`ftp_do_more`], whose three outcomes are
    /// [`DoMoreStep`]; the trait's `bool` is that step's completion half, and
    /// [`DoMoreStep::Retry`] -- the C's `-1`, for an `EPSV` connect that must be
    /// retried as `PASV` -- has no `bool` to travel in, which is a second reason
    /// this member cannot stand in for the function.
    fn do_more<'a>(
        &'a self,
        ctx: &'a mut TransferCtx<'_>,
    ) -> ProtoFuture<'a, bool> {
        let _ = ctx;
        Box::pin(core::future::ready(Err(CURLcode::NotBuiltIn)))
    }

    // -- 5. connect_it ------------------------------------------------------

    /// `ftp_connect` (`lib/ftp.c:3391-3429`): set the cadence engine up, finish
    /// an implicit-FTPS handshake, and start waiting for the `220`.
    ///
    /// The phase is [`ftp_connect`], implemented in full.
    fn connect_it<'a>(
        &'a self,
        ctx: &'a mut TransferCtx<'_>,
    ) -> ProtoFuture<'a, bool> {
        let _ = ctx;
        Box::pin(core::future::ready(Err(CURLcode::NotBuiltIn)))
    }

    // -- 6. connecting ------------------------------------------------------

    /// `ftp_multi_statemach` (`lib/ftp.c:3367-3372`): *"called repeatedly until
    /// done from multi.c"*.
    ///
    /// Its whole body is `ftp_statemach`, which is [`ftp_statemach`] here.
    fn connecting<'a>(
        &'a self,
        ctx: &'a mut TransferCtx<'_>,
    ) -> ProtoFuture<'a, bool> {
        let _ = ctx;
        Box::pin(core::future::ready(Err(CURLcode::NotBuiltIn)))
    }

    // -- 7. doing -----------------------------------------------------------

    /// `ftp_doing` (`lib/ftp.c:4180-4198`): continue what [`Self::do_it`] left
    /// unfinished, and close the DO phase when it finishes.
    ///
    /// The phase is [`ftp_doing`], implemented in full.
    fn doing<'a>(
        &'a self,
        ctx: &'a mut TransferCtx<'_>,
    ) -> ProtoFuture<'a, bool> {
        let _ = ctx;
        Box::pin(core::future::ready(Err(CURLcode::NotBuiltIn)))
    }

    // -- 8, 9. proto_pollset and doing_pollset, the same function -----------

    /// `ftp_pollset` (`lib/ftp.c:762-772`) during PROTOCONNECT.
    ///
    /// Unlike the seven members above, this one WORKS. `ftp_pollset`'s body is
    /// `Curl_pp_pollset`, whose direction is `pp->sendleft ? CURL_POLL_OUT :
    /// CURL_POLL_IN` -- and with no cadence engine in play nothing is
    /// half-sent, so the control socket is watched for reading, which is what
    /// the C records for a connection whose send buffer is empty.
    fn proto_pollset(
        &self,
        ctx: &mut TransferCtx<'_>,
        ps: &mut EasyPollset,
    ) -> CodeResult<()> {
        let sock = {
            let (chain, mut cx) = ctx.chain_with_ctx();
            chain.socket(&mut cx)
        };
        if sock == CURL_SOCKET_BAD {
            return Ok(());
        }
        ps.change(sock, PollAction::IN, PollAction::NONE, None)
    }

    /// `ftp_pollset` during DOING -- the SAME function in the C, filled into a
    /// second slot (`lib/ftp.c:4331-4332`).
    ///
    /// Delegated to [`Self::proto_pollset`] rather than duplicated, so the two
    /// slots cannot drift apart the way two transcriptions could.
    fn doing_pollset(
        &self,
        ctx: &mut TransferCtx<'_>,
        ps: &mut EasyPollset,
    ) -> CodeResult<()> {
        self.proto_pollset(ctx, ps)
    }

    // -- 10. domore_pollset -------------------------------------------------

    /// `ftp_domore_pollset` (`lib/ftp.c:774-800`) -- the dual-channel pollset,
    /// and the only override of this slot in the tree.
    ///
    /// The C's comment carries the reason it exists: *"When in DO_MORE state, we
    /// could be either waiting for us to connect to a remote site, or we could
    /// wait for that site to connect to us. Or just handle ordinary commands."*
    /// In the first two cases the secondary chain contributes its own descriptor
    /// and the control socket is watched for reading alongside it, so a server
    /// that changes its mind mid-wait is noticed rather than waited out.
    ///
    /// With no session the state is [`FtpState::Stop`], which is precisely the
    /// waiting case, so this member records the control socket for reading --
    /// the same answer [`FtpMachine::domore_pollset`] gives for that state.
    fn domore_pollset(
        &self,
        ctx: &mut TransferCtx<'_>,
        ps: &mut EasyPollset,
    ) -> CodeResult<()> {
        self.proto_pollset(ctx, ps)
    }

    // -- 12. disconnect -----------------------------------------------------

    /// `ftp_disconnect` (`lib/ftp.c:4155-4176`): BLOCKING teardown.
    ///
    /// The phase is [`ftp_disconnect`], which sets `shutdown`, decides whether
    /// the control connection can still be spoken to, sends `QUIT` only when it
    /// can, and drives the blocking machine to consume the reply.
    ///
    /// Answers `Ok(())` rather than reporting the wiring gap, and that is
    /// deliberate rather than inconsistent with the seven members above: the C's
    /// caller closes the connection regardless of what this returns, so a
    /// failure here would add a diagnostic without changing an outcome. With no
    /// session there is genuinely nothing to shut down -- and `dead_connection`
    /// would forbid sending anything even if there were.
    fn disconnect<'a>(
        &'a self,
        ctx: &'a mut TransferCtx<'_>,
        dead_connection: bool,
    ) -> ProtoFuture<'a, ()> {
        let _ = (ctx, dead_connection);
        Box::pin(core::future::ready(Ok(())))
    }

    // -- 11, 13, 14, 15, 16, 17. the six ZERO_NULL slots -------------------
    //
    // `perform_pollset`, `write_resp`, `write_resp_hd`, `connection_check`,
    // `attach` and `follow` are all `ZERO_NULL` in `Curl_protocol_ftp`
    // (`lib/ftp.c:4334-4340`), so all six take the trait's defaults. See
    // [`FtpProtocol`] for what each default does and why not writing them is
    // the faithful choice.
}

// Tests

/// The unit suite for the FTP engine.
///
/// # No network, no server, no clock
///
/// Every test below drives the real engine over
/// [`crate::conn::filters::tests`]'s in-memory transport with
/// [`crate::util::timeval::TestClock`] and scripted [`FtpSeams`]. Nothing opens
/// a socket, nothing resolves a name, nothing sleeps, and no FTP server is
/// involved -- which is what lets a byte-exact assertion be an assertion about
/// the engine rather than about a server's mood.
///
/// # What the wire assertions are checked against
///
/// The command streams come from the immutable fixtures named in the module
/// documentation, read out of `tests/data/`. `tests/getpart.pm:351+` joins a
/// fixture's `<protocol>` array into ONE string and compares it as one string,
/// so order, spelling, spacing and CRLF are all significant and every assertion
/// here is written the same way: the whole stream, in order, with its
/// terminators.
#[cfg(test)]
#[allow(clippy::too_many_lines)] // Every wire-stream test asserts a whole
                                 // dialogue; splitting one would hide the order, which is the thing under test.
mod tests {
    use super::*;
    use crate::conn::filters::link;
    use crate::conn::filters::tests::{new_log, InMemory, TransportHandle};
    use crate::conn::ProtocolOptions;
    use crate::dns::AddressFamily;
    use crate::util::timeval::TestClock;
    use std::collections::VecDeque;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;

    // -- the doubles --------------------------------------------------------

    /// What [`TestClient`] recorded, and what it was told to answer.
    #[derive(Debug)]
    struct ClientLog {
        /// Every `CURL_TRC_FTP` line, in order.
        trc: Vec<String>,
        /// Every `infof` line, in order.
        info: Vec<String>,
        /// Every `failf` line, in order.
        fail: Vec<String>,
        /// Every client write, with its flags.
        writes: Vec<(ClientWriteFlags, Vec<u8>)>,
        /// Every `connclose` reason.
        closes: Vec<String>,
        /// Every `expire` call.
        expiries: Vec<(TimeDiff, TimerId)>,
        /// Every transfer-setup call, as a short tag.
        xfer: Vec<String>,
        /// Progress sizes, download then upload.
        download_size: Vec<i64>,
        upload_size: Vec<i64>,
        /// How many times the writer was swapped and restored.
        listing_installed: usize,
        listing_restored: usize,
        /// Whether the listing writer is installed right now.
        listing_live: bool,
        /// Chunk callbacks: the recorded arguments and the scripted answers.
        chunk_bgn_calls: Vec<(String, i32)>,
        chunk_bgn: VecDeque<ChunkBgn>,
        chunk_bgn_absent: bool,
        chunk_end_calls: usize,
        chunk_end_absent: bool,
        /// Seek and read scripts.
        seek: SeekOutcome,
        seek_calls: Vec<i64>,
        read_fill: u8,
        /// `SOCKERRNO`.
        errno: i32,
        /// Progress counters.
        pgrs_resets: usize,
        pgrs_updates: usize,
        header_bytes: u32,
        accepts: usize,
    }

    impl Default for ClientLog {
        fn default() -> Self {
            Self {
                trc: Vec::new(),
                info: Vec::new(),
                fail: Vec::new(),
                writes: Vec::new(),
                closes: Vec::new(),
                expiries: Vec::new(),
                xfer: Vec::new(),
                download_size: Vec::new(),
                upload_size: Vec::new(),
                listing_installed: 0,
                listing_restored: 0,
                listing_live: false,
                chunk_bgn_calls: Vec::new(),
                chunk_bgn: VecDeque::new(),
                chunk_bgn_absent: false,
                chunk_end_calls: 0,
                chunk_end_absent: false,
                // `CURL_SEEKFUNC_OK` -- the value the C initialises
                // `seekerr` to, and what "no seek callback is set" means.
                seek: SeekOutcome::Ok,
                seek_calls: Vec::new(),
                read_fill: b'x',
                errno: 0,
                pgrs_resets: 0,
                pgrs_updates: 0,
                header_bytes: 0,
                accepts: 0,
            }
        }
    }

    /// A scripted [`FtpClient`].
    #[derive(Debug)]
    struct TestClient {
        opts: FtpOptions,
        req: FtpRequest,
        log: ClientLog,
        timeleft: TimeDiff,
    }

    impl TestClient {
        /// A client with curl's own defaults for everything this module reads.
        fn new() -> Self {
            Self {
                opts: FtpOptions {
                    user: b"anonymous".to_vec(),
                    password: b"ftp@example.com".to_vec(),
                    ..FtpOptions::default()
                },
                req: FtpRequest {
                    // `conn->bits.ftp_use_epsv` and `_eprt` both start TRUE.
                    use_epsv: true,
                    use_eprt: true,
                    file_method: FileMethod::MultiCwd,
                    resume_from: 0,
                    infilesize: -1,
                    maxdownload: -1,
                    size: -1,
                    filetime: 0,
                    // What `Curl_conn_get_remote_addr(data, FIRSTSOCKET)`
                    // reports for a connected control channel, which is what an
                    // `EPSV` reply's address is taken from.
                    host_name: b"127.0.0.1".to_vec(),
                    control_remote_ip: Some(b"127.0.0.1".to_vec()),
                    control_remote_port: 21,
                    ..FtpRequest::default()
                },
                log: ClientLog::default(),
                timeleft: 0,
            }
        }
    }

    impl FtpClient for TestClient {
        fn options(&self) -> &FtpOptions {
            &self.opts
        }

        fn request(&self) -> &FtpRequest {
            &self.req
        }

        fn request_mut(&mut self) -> &mut FtpRequest {
            &mut self.req
        }

        fn trc_ftp(&mut self, args: fmt::Arguments<'_>) {
            self.log.trc.push(args.to_string());
        }

        fn infof(&mut self, args: fmt::Arguments<'_>) {
            self.log.info.push(args.to_string());
        }

        fn failf(&mut self, args: fmt::Arguments<'_>) {
            self.log.fail.push(args.to_string());
        }

        fn debug(&mut self, _kind: InfoType, _payload: &[u8]) {}

        fn client_write(
            &mut self,
            flags: ClientWriteFlags,
            buf: &[u8],
        ) -> CodeResult<()> {
            self.log.writes.push((flags, buf.to_vec()));
            Ok(())
        }

        fn add_header_bytes(&mut self, count: u32) {
            self.log.header_bytes = self.log.header_bytes.saturating_add(count);
        }

        fn pgrs_set_download_size(&mut self, size: i64) {
            self.log.download_size.push(size);
        }

        fn pgrs_set_upload_size(&mut self, size: i64) {
            self.log.upload_size.push(size);
        }

        fn pgrs_check(&mut self) -> CodeResult<()> {
            Ok(())
        }

        fn pgrs_update(&mut self) -> CodeResult<()> {
            self.log.pgrs_updates = self.log.pgrs_updates.saturating_add(1);
            Ok(())
        }

        fn pgrs_reset(&mut self) {
            self.log.pgrs_resets = self.log.pgrs_resets.saturating_add(1);
        }

        fn pgrs_time_start_accept(&mut self) {
            self.log.accepts = self.log.accepts.saturating_add(1);
        }

        fn expire(&mut self, delay_ms: TimeDiff, timer: TimerId) {
            self.log.expiries.push((delay_ms, timer));
        }

        fn timeleft_ms(&self) -> TimeDiff {
            self.timeleft
        }

        fn sock_errno(&self) -> i32 {
            self.log.errno
        }

        fn xfer_setup_send(&mut self, sockindex: SocketIndex) {
            self.log.xfer.push(format!("send:{sockindex:?}"));
        }

        fn xfer_setup_recv(&mut self, sockindex: SocketIndex, size: i64) {
            self.log.xfer.push(format!("recv:{sockindex:?}:{size}"));
        }

        fn xfer_setup_nop(&mut self) {
            self.log.xfer.push("nop".to_owned());
        }

        fn xfer_set_shutdown(&mut self, shutdown: bool, ignore_errors: bool) {
            self.log
                .xfer
                .push(format!("shutdown:{shutdown}:{ignore_errors}"));
        }

        fn seek(&mut self, offset: i64) -> SeekOutcome {
            self.log.seek_calls.push(offset);
            self.log.seek
        }

        fn read_input(&mut self, into: &mut [u8]) -> CodeResult<usize> {
            for slot in into.iter_mut() {
                *slot = self.log.read_fill;
            }
            Ok(into.len())
        }

        fn chunk_bgn(
            &mut self,
            finfo: &FileInfo,
            remaining: i32,
        ) -> Option<ChunkBgn> {
            if self.log.chunk_bgn_absent {
                return None;
            }
            self.log
                .chunk_bgn_calls
                .push((finfo.filename.clone(), remaining));
            Some(self.log.chunk_bgn.pop_front().unwrap_or(ChunkBgn::Ok))
        }

        fn chunk_end(&mut self) -> Option<ChunkEnd> {
            if self.log.chunk_end_absent {
                return None;
            }
            self.log.chunk_end_calls =
                self.log.chunk_end_calls.saturating_add(1);
            Some(ChunkEnd::Ok)
        }

        fn install_listing_writer(&mut self) -> WriteBackup {
            self.log.listing_installed =
                self.log.listing_installed.saturating_add(1);
            self.log.listing_live = true;
            WriteBackup {
                listing_writer_installed: true,
            }
        }

        fn restore_listing_writer(&mut self, backup: WriteBackup) {
            assert!(
                backup.listing_writer_installed,
                "the driver restores exactly what it installed"
            );
            self.log.listing_restored =
                self.log.listing_restored.saturating_add(1);
            self.log.listing_live = false;
        }

        fn conn_close(&mut self, reason: &str) {
            self.log.closes.push(reason.to_owned());
        }
    }

    /// What [`TestSeams`] recorded, and what it was told to answer.
    #[derive(Debug)]
    struct SeamLog {
        resolved: Vec<(Vec<u8>, u16)>,
        resolve_answer: CodeResult<Vec<IpAddr>>,
        local_addr: Option<IpAddr>,
        family: AddressFamily,
        remote_scope: u32,
        if2ip: Option<If2IpResult>,
        if2ip_calls: Vec<Vec<u8>>,
        opened: Vec<IpAddr>,
        open_fails: Option<SockFailure>,
        binds: Vec<(IpAddr, u16)>,
        bind_script: VecDeque<Result<u16, SockFailure>>,
        listens: usize,
        listen_fails: Option<SockFailure>,
        installs: usize,
        closes: usize,
        secondary: Vec<(Vec<u8>, u16, bool)>,
        secondary_fails: Option<CURLcode>,
        tls_added: Vec<SocketIndex>,
        tls_add_fails: Option<CURLcode>,
        tls_removed: Vec<(SocketIndex, bool)>,
        tls_remove_fails: Option<CURLcode>,
        connects: Vec<(SocketIndex, bool)>,
        connect_script: VecDeque<CodeResult<bool>>,
        readable: i32,
    }

    impl Default for SeamLog {
        fn default() -> Self {
            Self {
                resolved: Vec::new(),
                resolve_answer: Ok(vec![IpAddr::V4(Ipv4Addr::new(
                    127, 0, 0, 1,
                ))]),
                local_addr: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
                family: AddressFamily::Inet,
                remote_scope: crate::dns::if2ip::IPV6_SCOPE_GLOBAL,
                if2ip: None,
                if2ip_calls: Vec::new(),
                opened: Vec::new(),
                open_fails: None,
                binds: Vec::new(),
                bind_script: VecDeque::new(),
                listens: 0,
                listen_fails: None,
                installs: 0,
                closes: 0,
                secondary: Vec::new(),
                secondary_fails: None,
                tls_added: Vec::new(),
                tls_add_fails: None,
                tls_removed: Vec::new(),
                tls_remove_fails: None,
                connects: Vec::new(),
                connect_script: VecDeque::new(),
                readable: 0,
            }
        }
    }

    /// A scripted [`FtpSeams`] over a shared log.
    ///
    /// The log is behind an [`Arc`] so a test can read it after the session has
    /// taken ownership of the seam -- [`FtpSession::new`] takes a
    /// `Box<dyn FtpSeams>`, and there is no way back to the concrete type.
    #[derive(Clone, Debug)]
    struct TestSeams {
        log: Arc<crate::util::sync_cell::SyncCell<SeamLog>>,
    }

    impl TestSeams {
        fn new() -> Self {
            Self {
                log: Arc::new(crate::util::sync_cell::SyncCell::new(
                    SeamLog::default(),
                )),
            }
        }

        fn handle(&self) -> Arc<crate::util::sync_cell::SyncCell<SeamLog>> {
            Arc::clone(&self.log)
        }
    }

    impl FtpSeams for TestSeams {
        fn resolve(
            &mut self,
            host: &[u8],
            port: u16,
        ) -> CodeResult<Vec<IpAddr>> {
            let mut log = self.log.borrow_mut();
            log.resolved.push((host.to_vec(), port));
            match &log.resolve_answer {
                Ok(addrs) => Ok(addrs.clone()),
                Err(code) => Err(*code),
            }
        }

        fn control_local_addr(&mut self) -> Option<IpAddr> {
            self.log.borrow().local_addr
        }

        fn control_family(&mut self) -> AddressFamily {
            self.log.borrow().family
        }

        fn control_remote_scope(&mut self) -> u32 {
            self.log.borrow().remote_scope
        }

        /// The scripted answer, and never the host's own interfaces.
        ///
        /// The unscripted default is [`If2IpResult::NotFound`], which is
        /// deliberately the same answer the real lookup gives for a string that
        /// is not an interface name -- the ordinary case, where the C treats the
        /// bytes as a host name instead. Calling through to the real lookup would
        /// make the outcome depend on the machine the suite runs on, and it puts
        /// `getifaddrs` on the path, which Miri cannot call at all.
        fn if2ip(
            &mut self,
            _family: AddressFamily,
            _remote_scope: u32,
            _scope_id: u32,
            iface: &[u8],
        ) -> If2IpResult {
            let mut log = self.log.borrow_mut();
            log.if2ip_calls.push(iface.to_vec());
            log.if2ip.clone().unwrap_or(If2IpResult::NotFound)
        }

        fn listener_open(&mut self, addr: IpAddr) -> Result<(), SockFailure> {
            let mut log = self.log.borrow_mut();
            log.opened.push(addr);
            match log.open_fails.clone() {
                Some(failure) => Err(failure),
                None => Ok(()),
            }
        }

        fn listener_bind(
            &mut self,
            addr: IpAddr,
            port: u16,
        ) -> Result<u16, SockFailure> {
            let mut log = self.log.borrow_mut();
            log.binds.push((addr, port));
            log.bind_script.pop_front().unwrap_or(Ok(port))
        }

        fn listener_listen(&mut self) -> Result<(), SockFailure> {
            let mut log = self.log.borrow_mut();
            log.listens = log.listens.saturating_add(1);
            match log.listen_fails.clone() {
                Some(failure) => Err(failure),
                None => Ok(()),
            }
        }

        fn listener_install(
            &mut self,
            _chains: &mut FilterChains,
            _cx: &mut CallCtx<'_, '_>,
        ) -> CodeResult<()> {
            let mut log = self.log.borrow_mut();
            log.installs = log.installs.saturating_add(1);
            Ok(())
        }

        fn listener_close(&mut self) {
            let mut log = self.log.borrow_mut();
            log.closes = log.closes.saturating_add(1);
        }

        fn setup_secondary(
            &mut self,
            _chains: &mut FilterChains,
            _cx: &mut CallCtx<'_, '_>,
            target: SecondaryTarget<'_>,
        ) -> CodeResult<()> {
            let mut log = self.log.borrow_mut();
            log.secondary
                .push((target.host.to_vec(), target.port, target.tls));
            match log.secondary_fails {
                Some(code) => Err(code),
                None => Ok(()),
            }
        }

        fn add_tls_filter(
            &mut self,
            _chains: &mut FilterChains,
            _cx: &mut CallCtx<'_, '_>,
            sockindex: SocketIndex,
        ) -> CodeResult<()> {
            let mut log = self.log.borrow_mut();
            log.tls_added.push(sockindex);
            match log.tls_add_fails {
                Some(code) => Err(code),
                None => Ok(()),
            }
        }

        fn remove_tls_filter(
            &mut self,
            _chains: &mut FilterChains,
            _cx: &mut CallCtx<'_, '_>,
            sockindex: SocketIndex,
            send_shutdown: bool,
        ) -> CodeResult<()> {
            let mut log = self.log.borrow_mut();
            log.tls_removed.push((sockindex, send_shutdown));
            match log.tls_remove_fails {
                Some(code) => Err(code),
                None => Ok(()),
            }
        }

        fn connect(
            &mut self,
            _chains: &mut FilterChains,
            _cx: &mut CallCtx<'_, '_>,
            sockindex: SocketIndex,
            blocking: bool,
        ) -> CodeResult<bool> {
            let mut log = self.log.borrow_mut();
            log.connects.push((sockindex, blocking));
            log.connect_script.pop_front().unwrap_or(Ok(true))
        }

        fn readable_now(&mut self, _sock: Socket) -> i32 {
            self.log.borrow().readable
        }
    }

    /// The socket number every test uses for the control connection.
    const CTRL_SOCK: Socket = 7;

    /// A chain with a connected in-memory transport on the control socket.
    fn chains_with_transport(
        clock: &TestClock,
    ) -> (FilterChains, TransportHandle) {
        let log = new_log();
        let mut chains = FilterChains::new(None);
        let (transport, state) = InMemory::new("FTP", &log);
        state.borrow_mut().socket = CTRL_SOCK;
        let mut cx = CallCtx::new(clock);
        let chain = chains.chain_mut(SocketIndex::First);
        chain.add(&mut cx, link(transport));
        assert!(
            chain.connect_head(&mut cx).is_ok_and(|done| done),
            "the in-memory transport connects in one step"
        );
        (chains, state)
    }

    /// Everything one test needs, assembled.
    struct Harness {
        session: FtpSession,
        chains: FilterChains,
        wire: TransportHandle,
        clock: Arc<TestClock>,
        client: TestClient,
        seams: Arc<crate::util::sync_cell::SyncCell<SeamLog>>,
    }

    impl Harness {
        /// A harness for a transfer of `path`.
        fn new(path: &[u8]) -> Self {
            let clock = Arc::new(TestClock::new(CurlTime::new(10, 0)));
            let (chains, wire) = chains_with_transport(clock.as_ref());
            let seams = TestSeams::new();
            let handle = seams.handle();
            let session = FtpSession::new(path, Box::new(seams));
            Self {
                session,
                chains,
                wire,
                clock,
                client: TestClient::new(),
                seams: handle,
            }
        }

        /// `Curl_pp_init(pp, Curl_pgrs_now(data))` -- *"once per transfer"*.
        ///
        /// Left to the caller rather than done in [`Self::new`], because
        /// [`ftp_connect`] performs it and the C's own
        /// `DEBUGASSERT(!pp->initialised)` refuses a second call. A test that
        /// starts mid-dialogue calls this; a test that starts at the greeting
        /// lets `ftp_connect` do it.
        fn init_pp(&mut self) {
            let now = self.clock.now();
            self.session.conn_mut().pp_mut().init(now);
        }

        /// Queues `bytes` for the engine to read.
        fn feed(&mut self, bytes: &[u8]) {
            self.wire.borrow_mut().input.extend_from_slice(bytes);
        }

        /// Whether another reply is available -- on the wire, or already cached
        /// in the receive buffer.
        ///
        /// One read commonly frames several replies at once, and the ones after
        /// the first sit in [`PingPong`]'s overflow rather than on the
        /// transport. A driver that looked only at the transport would stop with
        /// a complete reply still unread, which is the same mistake the C's
        /// `cache_skip` accounting exists to avoid.
        fn has_more_input(&self) -> bool {
            !self.wire.borrow().input.is_empty()
                || self.session.conn().pp().overflow() != 0
        }

        /// Everything the engine has put on the wire so far.
        fn sent(&self) -> Vec<u8> {
            self.wire.borrow().output.clone()
        }

        /// Everything the engine has put on the wire, as text.
        fn sent_text(&self) -> String {
            String::from_utf8_lossy(&self.sent()).into_owned()
        }

        /// `ftp_setup_connection` over this harness.
        fn setup(&mut self) -> CodeResult<()> {
            let mut io = FtpIo::new(
                &mut self.chains,
                self.clock.as_ref(),
                &mut self.client,
            );
            ftp_setup_connection(&mut self.session, &mut io)
        }

        /// Runs `body` with the session and the engine's three borrows, held
        /// disjointly.
        ///
        /// [`Self::io`] borrows the whole harness, so it cannot be composed with
        /// a second borrow of the session. Taking a closure lets the compiler
        /// see that the four fields are disjoint, which is the same reason
        /// [`FtpSession::split`] exists.
        fn with<T>(
            &mut self,
            body: impl FnOnce(&mut FtpSession, &mut FtpIo<'_>) -> T,
        ) -> T {
            let mut io = FtpIo::new(
                &mut self.chains,
                self.clock.as_ref(),
                &mut self.client,
            );
            body(&mut self.session, &mut io)
        }

        /// Runs `body` with the cadence engine, the state machine and the
        /// engine's three borrows.
        fn with_machine<T>(
            &mut self,
            body: impl FnOnce(
                &mut PingPong,
                &mut FtpMachine<'_>,
                &mut FtpIo<'_>,
            ) -> T,
        ) -> T {
            let mut io = FtpIo::new(
                &mut self.chains,
                self.clock.as_ref(),
                &mut self.client,
            );
            let (pp, mut machine) = self.session.split();
            body(pp, &mut machine, &mut io)
        }

        /// The three borrows the engine works through.
        fn io(&mut self) -> FtpIo<'_> {
            FtpIo::new(&mut self.chains, self.clock.as_ref(), &mut self.client)
        }

        /// One synchronous lap of the reply dispatcher.
        fn step(&mut self) -> CurlResult<()> {
            let mut io = FtpIo::new(
                &mut self.chains,
                self.clock.as_ref(),
                &mut self.client,
            );
            let (pp, mut machine) = self.session.split();
            ftp_pp_statemachine(&mut machine, pp, &mut io)
        }

        /// Feed a reply, then dispatch it.
        fn reply(&mut self, bytes: &[u8]) -> CurlResult<()> {
            self.feed(bytes);
            self.step()
        }

        /// The live state.
        fn state(&self) -> FtpState {
            self.session.conn().ftpc().state()
        }

        /// Gives the data connection an in-memory transport of its own.
        ///
        /// `ftp_done` asks whether the secondary chain exists before it shuts it
        /// down, and `ABOR` is sent inside that branch, so a test about the
        /// closing sequence needs the chain to be there.
        fn open_secondary(&mut self) {
            let log = new_log();
            let (transport, state) = InMemory::new("FTP-data", &log);
            state.borrow_mut().socket = CTRL_SOCK.saturating_add(1);
            let mut cx = CallCtx::new(self.clock.as_ref());
            let chain = self.chains.chain_mut(SocketIndex::Secondary);
            chain.add(&mut cx, link(transport));
            assert!(
                chain.connect_head(&mut cx).is_ok_and(|done| done),
                "the in-memory transport connects in one step"
            );
        }

        /// Puts the machine into `state` without a dialogue, for a test that is
        /// about one arm rather than about the sequence reaching it.
        fn force_state(&mut self, state: FtpState) {
            let mut io = FtpIo::new(
                &mut self.chains,
                self.clock.as_ref(),
                &mut self.client,
            );
            let (_pp, machine) = self.session.split();
            machine.ftpc.set_state(state, io.client_mut());
        }
    }

    // -- Phase 3: the 37 states, their names, and the single mutator ---------

    /// Every state's discriminant, in the C's declaration order
    /// (`lib/ftp.h:41-80`).
    #[test]
    fn the_thirty_seven_states_carry_the_c_discriminants() {
        let expected: [(FtpState, u8, &str); 37] = [
            (FtpState::Stop, 0, "STOP"),
            (FtpState::Wait220, 1, "WAIT220"),
            (FtpState::Auth, 2, "AUTH"),
            (FtpState::User, 3, "USER"),
            (FtpState::Pass, 4, "PASS"),
            (FtpState::Acct, 5, "ACCT"),
            (FtpState::Pbsz, 6, "PBSZ"),
            (FtpState::Prot, 7, "PROT"),
            (FtpState::Ccc, 8, "CCC"),
            (FtpState::Pwd, 9, "PWD"),
            (FtpState::Syst, 10, "SYST"),
            (FtpState::NameFmt, 11, "NAMEFMT"),
            (FtpState::Quote, 12, "QUOTE"),
            (FtpState::RetrPrequote, 13, "RETR_PREQUOTE"),
            (FtpState::StorPrequote, 14, "STOR_PREQUOTE"),
            (FtpState::ListPrequote, 15, "LIST_PREQUOTE"),
            (FtpState::Postquote, 16, "POSTQUOTE"),
            (FtpState::Cwd, 17, "CWD"),
            (FtpState::Mkd, 18, "MKD"),
            (FtpState::Mdtm, 19, "MDTM"),
            (FtpState::Type, 20, "TYPE"),
            (FtpState::ListType, 21, "LIST_TYPE"),
            (FtpState::RetrListType, 22, "RETR_LIST_TYPE"),
            (FtpState::RetrType, 23, "RETR_TYPE"),
            (FtpState::StorType, 24, "STOR_TYPE"),
            (FtpState::Size, 25, "SIZE"),
            (FtpState::RetrSize, 26, "RETR_SIZE"),
            (FtpState::StorSize, 27, "STOR_SIZE"),
            (FtpState::Rest, 28, "REST"),
            (FtpState::RetrRest, 29, "RETR_REST"),
            (FtpState::Port, 30, "PORT"),
            (FtpState::Pret, 31, "PRET"),
            (FtpState::Pasv, 32, "PASV"),
            (FtpState::List, 33, "LIST"),
            (FtpState::Retr, 34, "RETR"),
            (FtpState::Stor, 35, "STOR"),
            (FtpState::Quit, 36, "QUIT"),
        ];

        assert_eq!(FtpState::VARIANTS.len(), 37);
        assert_eq!(FTP_STATE_NAMES.len(), 37);
        for (index, (state, discriminant, name)) in expected.iter().enumerate()
        {
            assert_eq!(
                FtpState::VARIANTS.get(index).copied(),
                Some(*state),
                "declaration order at {index}"
            );
            assert_eq!(state.as_u8(), *discriminant, "discriminant of {name}");
            assert_eq!(state_name(*state), *name, "trace name at {index}");
            assert_eq!(cstate(Some(*state)), *name, "FTP_CSTATE of {name}");
            assert_eq!(state.to_string(), *name, "Display of {name}");
        }
    }

    /// `FTP_LAST` is 37, is never a live state, and never indexes the table.
    #[test]
    fn ftp_last_is_a_sentinel_and_not_a_state() {
        assert_eq!(FTP_LAST, 37);
        assert_eq!(FTP_LAST as usize, FTP_STATE_NAMES.len());
        // Every real state is strictly below the sentinel, so the table index
        // is always in range.
        for state in FtpState::VARIANTS {
            assert!(state.as_u8() < FTP_LAST);
            assert!(FTP_STATE_NAMES.get(usize::from(state.as_u8())).is_some());
        }
        // The C renders `"???"` when the connection has no FTP state.
        assert_eq!(cstate(None), "???");
    }

    /// The quote states, which the dispatcher groups.
    #[test]
    fn the_five_quote_states_are_the_ones_that_run_a_list() {
        let quote: Vec<FtpState> = FtpState::VARIANTS
            .into_iter()
            .filter(|state| state.is_quote_state())
            .collect();
        assert_eq!(
            quote,
            vec![
                FtpState::Quote,
                FtpState::RetrPrequote,
                FtpState::StorPrequote,
                FtpState::ListPrequote,
                FtpState::Postquote,
            ]
        );
    }

    /// Every transition goes through the one mutator, and it traces exactly
    /// `[%s] -> [%s]` -- and only when the state actually changes.
    #[test]
    fn the_single_mutator_traces_only_a_real_change() {
        let mut harness = Harness::new(b"dir/file.txt");
        harness.force_state(FtpState::Wait220);
        harness.force_state(FtpState::Wait220);
        harness.force_state(FtpState::User);

        let traces: Vec<&String> = harness
            .client
            .log
            .trc
            .iter()
            .filter(|line| line.contains("] -> ["))
            .collect();
        assert_eq!(
            traces,
            vec!["[STOP] -> [WAIT220]", "[WAIT220] -> [USER]"],
            "a no-op transition emits nothing"
        );
        assert_eq!(harness.state(), FtpState::User);
    }

    /// The state field is private: the only writer in this file is the mutator.
    #[test]
    fn only_the_mutator_assigns_the_state_field() {
        let source = code_only();
        let writes: Vec<&str> = source
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with("self.state = "))
            .collect();
        assert_eq!(
            writes.len(),
            1,
            "exactly one assignment to the state field, in set_state"
        );
        assert!(
            !source.contains("ftpc.state ="),
            "no caller reaches the field directly"
        );
    }

    // -- Phase 3: the file methods, the depth cap, the accept default -------

    /// `FTPFILE_MULTICWD` = 1, `FTPFILE_NOCWD` = 2, `FTPFILE_SINGLECWD` = 3.
    #[test]
    fn the_file_methods_carry_their_pinned_integers() {
        assert_eq!(FileMethod::MultiCwd.as_u8(), 1);
        assert_eq!(FileMethod::NoCwd.as_u8(), 2);
        assert_eq!(FileMethod::SingleCwd.as_u8(), 3);
        assert_eq!(
            FileMethod::VARIANTS,
            [
                FileMethod::MultiCwd,
                FileMethod::NoCwd,
                FileMethod::SingleCwd
            ]
        );
        // `Curl_setopt`'s range check admits 1..=3; anything else is the C's
        // own fallback to MULTICWD.
        assert_eq!(FileMethod::from_u8(1), FileMethod::MultiCwd);
        assert_eq!(FileMethod::from_u8(2), FileMethod::NoCwd);
        assert_eq!(FileMethod::from_u8(3), FileMethod::SingleCwd);
        assert_eq!(FileMethod::from_u8(0), FileMethod::MultiCwd);
        assert_eq!(FileMethod::from_u8(9), FileMethod::MultiCwd);
    }

    /// `FTP_MAX_DIR_DEPTH` and `DEFAULT_ACCEPT_TIMEOUT`, from `lib/ftp.h`.
    #[test]
    fn the_two_measured_limits_are_the_c_values() {
        assert_eq!(FTP_MAX_DIR_DEPTH, 1000);
        assert_eq!(DEFAULT_ACCEPT_TIMEOUT, 60_000);
    }

    /// The wire-bearing mode tables.
    #[test]
    fn the_mode_tables_hold_the_exact_command_words() {
        assert_eq!(FTP_PORT_MODES, ["EPRT", "PORT"]);
        assert_eq!(FTP_PASSIVE_MODES, ["EPSV", "PASV"]);
        assert_eq!(FTP_AUTH_MODES, ["SSL", "TLS"]);
        assert_eq!(FtpPortCmd::Eprt.as_u8(), 0);
        assert_eq!(FtpPortCmd::Port.as_u8(), 1);
        assert_eq!(FtpPortCmd::Done.as_u8(), 2);
        assert_eq!(
            FtpPortCmd::VARIANTS,
            [FtpPortCmd::Eprt, FtpPortCmd::Port, FtpPortCmd::Done]
        );
        assert_eq!(FtpPortCmd::Eprt.word(), Some("EPRT"));
        assert_eq!(FtpPortCmd::Port.word(), Some("PORT"));
        assert_eq!(FtpPortCmd::Done.word(), None);
    }

    /// `CURLOPT_FTPSSLAUTH`: DEFAULT and SSL try SSL first, TLS tries TLS
    /// first, and anything else is refused.
    #[test]
    fn the_auth_order_is_the_c_step_and_start_pair() {
        // CURLFTPAUTH_DEFAULT = 0, CURLFTPAUTH_SSL = 1, CURLFTPAUTH_TLS = 2.
        assert_eq!(FtpSslAuth(0).attempt_order(), Some((0, 1)));
        assert_eq!(FtpSslAuth(1).attempt_order(), Some((0, 1)));
        assert_eq!(FtpSslAuth(2).attempt_order(), Some((1, -1)));
        assert_eq!(FtpSslAuth(3).attempt_order(), None);
        assert_eq!(FtpSslAuth(-1).attempt_order(), None);
    }

    // -- Phase 2: the two registry rows and the shared handler --------------

    /// The `ftp` row, column for column against `lib/ftp.c:4348-4362`.
    #[test]
    fn the_ftp_row_is_the_c_row() {
        assert_eq!(SCHEME_FTP.name, b"ftp");
        assert_eq!(SCHEME_FTP.protocol, Proto::FTP);
        assert_eq!(SCHEME_FTP.family, Proto::FTP);
        assert_eq!(SCHEME_FTP.defport, 21);
        assert_eq!(PORT_FTP, 21);
        let flags = SCHEME_FTP.flags;
        for wanted in [
            ProtocolOptions::DUAL,
            ProtocolOptions::CLOSEACTION,
            ProtocolOptions::NEEDSPWD,
            ProtocolOptions::NOURLQUERY,
            ProtocolOptions::PROXY_AS_HTTP,
            ProtocolOptions::WILDCARD,
            ProtocolOptions::SSL_REUSE,
            ProtocolOptions::CONN_REUSE,
        ] {
            assert!(flags.intersects(wanted), "ftp carries {wanted:?}");
        }
        assert!(
            !flags.intersects(ProtocolOptions::SSL),
            "plain ftp is clear"
        );
        assert!(SCHEME_FTP.run.is_some());
    }

    /// The `ftps` row, column for column against `lib/ftp.c:4367-4380`.
    #[test]
    fn the_ftps_row_is_the_c_row_including_its_ftp_family() {
        assert_eq!(SCHEME_FTPS.name, b"ftps");
        assert_eq!(SCHEME_FTPS.protocol, Proto::FTPS);
        assert_eq!(
            SCHEME_FTPS.family,
            Proto::FTP,
            "the family is FTP, which is what PROTO_FAMILY_FTP tests need"
        );
        assert_eq!(SCHEME_FTPS.defport, 990);
        assert_eq!(PORT_FTPS, 990);
        let flags = SCHEME_FTPS.flags;
        for wanted in [
            ProtocolOptions::SSL,
            ProtocolOptions::DUAL,
            ProtocolOptions::CLOSEACTION,
            ProtocolOptions::NEEDSPWD,
            ProtocolOptions::NOURLQUERY,
            ProtocolOptions::WILDCARD,
            ProtocolOptions::CONN_REUSE,
        ] {
            assert!(flags.intersects(wanted), "ftps carries {wanted:?}");
        }
        assert!(
            !flags.intersects(ProtocolOptions::PROXY_AS_HTTP),
            "ftps cannot be handed to an HTTP proxy as HTTP"
        );
        assert!(
            !flags.intersects(ProtocolOptions::SSL_REUSE),
            "ftps carries PROTOPT_SSL itself and borrows nobody's TLS"
        );
        assert!(SCHEME_FTPS.run.is_some());
    }

    /// One handler, two rows -- the C's `&Curl_protocol_ftp` twice.
    #[test]
    fn both_rows_share_one_handler_column() {
        assert_eq!(SCHEMES.len(), 2);
        assert_eq!(SCHEMES[0].name, SCHEME_FTP.name);
        assert_eq!(SCHEMES[1].name, SCHEME_FTPS.name);
        // The column is written ONCE, as `RUN_FTP`, and both rows take it.
        // Asserted from the source rather than by comparing two const-promoted
        // references, whose addresses a compiler is free to duplicate.
        let source = code_only();
        assert_eq!(
            source.matches("run: RUN_FTP,").count(),
            2,
            "both rows carry the one handler column"
        );
        assert_eq!(
            source
                .matches(
                    "pub(crate) const RUN_FTP: Option<&'static dyn Protocol>"
                )
                .count(),
            1,
            "and that column is defined exactly once"
        );
        // Behavioural identity, which is what "the same vtable" means to a
        // caller: both rows answer alike.
        let ftp = SCHEME_FTP.run.expect("the ftp row carries the handler");
        let ftps = SCHEME_FTPS.run.expect("the ftps row carries the handler");
        assert_eq!(format!("{ftp:?}"), format!("{ftps:?}"));
        assert_eq!(format!("{FTP:?}"), "FtpProtocol");
    }

    /// Exactly eleven slots are overridden and six take the trait's defaults.
    #[test]
    fn exactly_eleven_of_seventeen_slots_are_overridden() {
        let source = code_only();
        let overridden = [
            "fn setup_connection(",
            "fn do_it<'a>(",
            "fn done<'a>(",
            "fn do_more<'a>(",
            "fn connect_it<'a>(",
            "fn connecting<'a>(",
            "fn doing<'a>(",
            "fn proto_pollset(",
            "fn doing_pollset(",
            "fn domore_pollset(",
            "fn disconnect<'a>(",
        ];
        assert_eq!(overridden.len(), 11);
        let body = source
            .split("impl Protocol for FtpProtocol {")
            .nth(1)
            .expect("the trait implementation");
        for slot in overridden {
            assert!(body.contains(slot), "{slot} is overridden");
        }
        for defaulted in [
            "fn perform_pollset(",
            "fn write_resp",
            "fn write_resp_hd",
            "fn connection_check(",
            "fn attach(",
            "fn follow(",
        ] {
            assert!(
                !body.contains(defaulted),
                "{defaulted} takes the trait default"
            );
        }
    }

    /// `setup_connection` refuses a row whose family is not FTP.
    #[test]
    fn setup_connection_validates_the_family() {
        let clock = TestClock::new(CurlTime::new(1, 0));
        let mut chains = FilterChains::new(None);
        let mut ctx = TransferCtx::new(&mut chains, &clock, &SCHEME_FTP);
        assert_eq!(FTP.setup_connection(&mut ctx), Ok(()));

        let mut other = FilterChains::new(None);
        let mut ctx = TransferCtx::new(&mut other, &clock, &SCHEME_SFTP_LIKE);
        assert_eq!(
            FTP.setup_connection(&mut ctx),
            Err(CURLcode::FailedInit),
            "a row from another family has been registered wrongly"
        );
    }

    /// A row with a non-FTP family, for the negative half of the test above.
    #[rustfmt::skip]
    const SCHEME_SFTP_LIKE: Scheme = Scheme {
        name: b"ftp",
        run: RUN_FTP,
        protocol: Proto::FTP,
        family: Proto::HTTP,
        flags: FLAGS_FTP,
        defport: PORT_FTP,
    };

    /// The seven asynchronous slots report the wiring gap rather than a
    /// silent success, and `disconnect` answers `Ok(())`.
    #[test]
    fn the_asynchronous_slots_report_the_wiring_gap() {
        let clock = TestClock::new(CurlTime::new(1, 0));
        let mut chains = FilterChains::new(None);
        let mut ctx = TransferCtx::new(&mut chains, &clock, &SCHEME_FTP);

        assert_eq!(drive(FTP.do_it(&mut ctx)), Err(CURLcode::NotBuiltIn));
        assert_eq!(drive(FTP.do_more(&mut ctx)), Err(CURLcode::NotBuiltIn));
        assert_eq!(drive(FTP.connect_it(&mut ctx)), Err(CURLcode::NotBuiltIn));
        assert_eq!(drive(FTP.connecting(&mut ctx)), Err(CURLcode::NotBuiltIn));
        assert_eq!(drive(FTP.doing(&mut ctx)), Err(CURLcode::NotBuiltIn));
        assert_eq!(
            drive(FTP.done(&mut ctx, CURLcode::Ok, false)),
            Err(CURLcode::NotBuiltIn)
        );
        assert_eq!(
            drive(FTP.done(&mut ctx, CURLcode::PartialFile, true)),
            Err(CURLcode::PartialFile),
            "a failed transfer keeps its own code"
        );
        assert_eq!(drive(FTP.disconnect(&mut ctx, true)), Ok(()));
        assert_eq!(drive(FTP.disconnect(&mut ctx, false)), Ok(()));
    }

    /// The three pollsets work, and all three record the control descriptor.
    #[test]
    fn the_three_pollsets_record_the_control_socket_for_reading() {
        let clock = TestClock::new(CurlTime::new(1, 0));
        let (mut chains, _wire) = chains_with_transport(&clock);
        let mut ctx = TransferCtx::new(&mut chains, &clock, &SCHEME_FTP);

        for (name, run) in [("proto", 0_u8), ("doing", 1), ("domore", 2)] {
            let mut ps = EasyPollset::new();
            let outcome = match run {
                0 => FTP.proto_pollset(&mut ctx, &mut ps),
                1 => FTP.doing_pollset(&mut ctx, &mut ps),
                _ => FTP.domore_pollset(&mut ctx, &mut ps),
            };
            assert_eq!(outcome, Ok(()), "{name}_pollset succeeds");
            assert_eq!(ps.len(), 1, "{name}_pollset records one descriptor");
            let watched: Vec<(Socket, PollAction)> = ps.iter().collect();
            assert_eq!(
                watched,
                vec![(CTRL_SOCK, PollAction::IN)],
                "{name}_pollset watches the control socket for reading"
            );
        }
    }

    /// A chain with no descriptor records nothing rather than failing.
    #[test]
    fn a_pollset_without_a_descriptor_records_nothing() {
        let clock = TestClock::new(CurlTime::new(1, 0));
        let mut chains = FilterChains::new(None);
        let mut ctx = TransferCtx::new(&mut chains, &clock, &SCHEME_FTP);
        let mut ps = EasyPollset::new();
        assert_eq!(FTP.proto_pollset(&mut ctx, &mut ps), Ok(()));
        assert_eq!(ps.len(), 0);
    }

    /// Runs a future to completion without a `tokio` runtime.
    ///
    /// The crate's own idiom, shared with `ftp/pingpong.rs`, `conn/pool.rs`,
    /// `conn/shutdown.rs` and `protocols/mod.rs`. No timer is involved, because
    /// every wait in these tests is scripted -- which is itself part of the
    /// contract: a protocol that needed a reactor to be tested could not be
    /// tested without a network.
    fn drive<F: core::future::Future>(future: F) -> F::Output {
        futures::executor::block_on(future)
    }

    /// Dispatches every scripted reply that is still queued, stopping early
    /// when the machine reaches [`FtpState::Stop`].
    ///
    /// The lap bound is what makes a mis-sequenced machine fail the test rather
    /// than hang it; no dialogue in this suite needs more than a dozen laps.
    fn pump(harness: &mut Harness, laps: usize) {
        for _ in 0..laps {
            if harness.state() == FtpState::Stop {
                return;
            }
            if !harness.has_more_input() {
                return;
            }
            harness.step().expect("the dialogue is scripted");
        }
        panic!("the machine did not settle within {laps} laps");
    }

    /// `ftp_connect`, driven to completion.
    fn connect(harness: &mut Harness) -> CurlResult<bool> {
        let mut io = FtpIo::new(
            &mut harness.chains,
            harness.clock.as_ref(),
            &mut harness.client,
        );
        drive(ftp_connect(&mut harness.session, &mut io))
    }

    /// `ftp_do`, driven to completion.
    fn do_it(harness: &mut Harness) -> CurlResult<bool> {
        let mut io = FtpIo::new(
            &mut harness.chains,
            harness.clock.as_ref(),
            &mut harness.client,
        );
        drive(ftp_do(&mut harness.session, &mut io))
    }

    /// One `ftp_doing` lap.
    fn doing(harness: &mut Harness) -> CurlResult<bool> {
        let mut io = FtpIo::new(
            &mut harness.chains,
            harness.clock.as_ref(),
            &mut harness.client,
        );
        drive(ftp_doing(&mut harness.session, &mut io))
    }

    /// `ftp_doing` until the DO phase completes, or until `laps` are spent.
    fn doing_until_done(harness: &mut Harness, laps: usize) {
        for _ in 0..laps {
            if doing(harness).expect("the dialogue is scripted") {
                return;
            }
        }
        panic!("the DO phase did not complete within {laps} laps");
    }

    /// One `ftp_do_more` lap.
    fn do_more(harness: &mut Harness) -> CurlResult<DoMoreStep> {
        let mut io = FtpIo::new(
            &mut harness.chains,
            harness.clock.as_ref(),
            &mut harness.client,
        );
        drive(ftp_do_more(&mut harness.session, &mut io))
    }

    /// `ftp_do_more` until it advances, or until `laps` are spent.
    fn do_more_until_advance(harness: &mut Harness, laps: usize) {
        for _ in 0..laps {
            match do_more(harness) {
                Ok(DoMoreStep::Advance) => return,
                Ok(_) => {}
                Err(error) => panic!("do_more reported {:?}", error.code()),
            }
        }
        panic!("do_more did not advance within {laps} laps");
    }

    /// `ftp_done`, driven to completion.
    fn done(
        harness: &mut Harness,
        status: CURLcode,
        premature: bool,
    ) -> CurlResult<()> {
        let mut io = FtpIo::new(
            &mut harness.chains,
            harness.clock.as_ref(),
            &mut harness.client,
        );
        drive(ftp_done(&mut harness.session, &mut io, status, premature))
    }

    /// `ftp_quit`, driven to completion.
    fn quit(harness: &mut Harness) -> CurlResult<()> {
        let mut io = FtpIo::new(
            &mut harness.chains,
            harness.clock.as_ref(),
            &mut harness.client,
        );
        drive(ftp_quit(&mut harness.session, &mut io))
    }

    /// `ftp_disconnect`, driven to completion.
    fn disconnect(
        harness: &mut Harness,
        dead_connection: bool,
    ) -> CurlResult<()> {
        let mut io = FtpIo::new(
            &mut harness.chains,
            harness.clock.as_ref(),
            &mut harness.client,
        );
        drive(ftp_disconnect(
            &mut harness.session,
            &mut io,
            dead_connection,
        ))
    }

    // -- Phase 12: the whole-session passive GET, byte for byte -------------

    /// `tests/data/test1003`'s command stream, in its order and with its
    /// terminators.
    ///
    /// The fixture's `<protocol>` block is, verbatim:
    ///
    /// ```text
    /// USER anonymous
    /// PASS ftp@example.com
    /// PWD
    /// CWD path
    /// EPSV
    /// TYPE I
    /// SIZE 1003
    /// RETR 1003
    /// QUIT
    /// ```
    ///
    /// **`EPSV` precedes `TYPE I` and `SIZE`**, which is the order the source
    /// produces and the order the fixture pins: the data channel is arranged in
    /// the DO phase and the transfer type and size are settled in DO_MORE. A
    /// checklist that put `TYPE` first would be describing a different protocol.
    #[test]
    fn a_passive_binary_get_puts_the_fixture_stream_on_the_wire() {
        // `ftp://%HOSTIP:%FTPPORT/path/%TESTNUMBER` -- one directory named
        // `path`, then the file named for the test.
        let mut harness = Harness::new(b"path/1003");

        // The connect phase: greeting, login, and the entry path.
        harness.feed(b"220 ready\r\n");
        assert!(
            !connect(&mut harness).expect("the greeting is scripted"),
            "the connect phase is not finished by the greeting alone"
        );
        harness.feed(b"331 give me a password\r\n");
        harness.feed(b"230 logged in\r\n");
        harness.feed(b"257 \"/\" is the current directory\r\n");
        pump(&mut harness, 8);
        assert_eq!(harness.state(), FtpState::Stop);
        assert_eq!(
            harness.sent_text(),
            "USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\n"
        );

        // The DO phase: one CWD, then the data channel.
        harness.feed(b"250 CWD command successful\r\n");
        assert!(!do_it(&mut harness).expect("the CWD reply is scripted"));
        harness.feed(b"229 Entering Extended Passive Mode (|||8888|)\r\n");
        doing_until_done(&mut harness, 4);
        assert!(harness.client.req.do_more, "DO_MORE was requested");

        // The DO_MORE phase: type, size, and the transfer command.
        harness.feed(b"200 Type set to I\r\n");
        harness.feed(b"213 4096\r\n");
        harness.feed(b"150 Opening BINARY mode data connection\r\n");
        do_more_until_advance(&mut harness, 8);

        // The goodbye.
        harness.session.conn_mut().ftpc_mut().ctl_valid = true;
        harness.feed(b"221 bye\r\n");
        quit(&mut harness).expect("the goodbye is scripted");

        assert_eq!(
            harness.sent_text(),
            concat!(
                "USER anonymous\r\n",
                "PASS ftp@example.com\r\n",
                "PWD\r\n",
                "CWD path\r\n",
                "EPSV\r\n",
                "TYPE I\r\n",
                "SIZE 1003\r\n",
                "RETR 1003\r\n",
                "QUIT\r\n",
            ),
            "tests/data/test1003's protocol block, joined as getpart.pm joins it"
        );
    }

    /// Every command ends with exactly one CRLF, and nothing else does.
    #[test]
    fn every_command_carries_exactly_one_terminator() {
        let mut harness = Harness::new(b"path/1003");
        harness.feed(b"220 ready\r\n");
        let _ = connect(&mut harness).expect("the greeting is scripted");
        harness.feed(b"331 password\r\n");
        harness.feed(b"230 in\r\n");
        pump(&mut harness, 6);

        let wire = harness.sent();
        assert!(!wire.is_empty());
        // Split on the line feed: every piece but the trailing empty one is a
        // command, and no piece holds a stray carriage return.
        let mut pieces: Vec<&[u8]> =
            wire.split(|&byte| byte == b'\n').collect();
        let last = pieces.pop();
        assert_eq!(last, Some(&b""[..]), "the stream ends with a terminator");
        for piece in pieces {
            assert_eq!(
                piece.last(),
                Some(&b'\r'),
                "each line ends CR LF: {:?}",
                String::from_utf8_lossy(piece)
            );
            assert!(
                !piece
                    .get(..piece.len().saturating_sub(1))
                    .unwrap_or(&[])
                    .contains(&b'\r'),
                "no doubled terminator"
            );
        }
    }

    // -- Phase 12: the login sequence and its branches ----------------------

    /// A greeting that is not `220` is a weird reply, with the C's exact text.
    #[test]
    fn a_greeting_other_than_220_is_a_weird_server_reply() {
        let mut harness = Harness::new(b"file");
        harness.force_state(FtpState::Wait220);
        let error = harness
            .reply(b"550 go away\r\n")
            .expect_err("a 550 greeting is refused");
        assert_eq!(error.code(), CURLcode::WeirdServerReply);
        assert_eq!(
            harness.client.log.fail,
            vec!["Got a 550 ftp-server response when 220 was expected"]
        );
    }

    /// `230` in place of the greeting logs us straight in when TLS is not
    /// wanted.
    #[test]
    fn a_230_greeting_is_accepted_as_a_login_without_tls() {
        let mut harness = Harness::new(b"file");
        harness.force_state(FtpState::Wait220);
        harness.reply(b"230 already in\r\n").expect("accepted");
        assert_eq!(harness.state(), FtpState::Pwd);
        assert_eq!(harness.sent_text(), "PWD\r\n");
    }

    /// With TLS required, the same `230` is treated as the `220` it stands in
    /// for and the negotiation proceeds.
    #[test]
    fn a_230_greeting_still_negotiates_tls_when_it_is_required() {
        let mut harness = Harness::new(b"file");
        harness.client.opts.use_ssl = UseSsl::All;
        harness.force_state(FtpState::Wait220);
        harness.reply(b"230 already in\r\n").expect("accepted");
        assert_eq!(harness.state(), FtpState::Auth);
        assert_eq!(harness.sent_text(), "AUTH SSL\r\n");
    }

    /// `331` then `230`: the ordinary login.
    #[test]
    fn the_login_is_user_then_pass_then_pwd() {
        let mut harness = Harness::new(b"file");
        harness.client.opts.user = b"me".to_vec();
        harness.client.opts.password = b"secret".to_vec();
        harness.force_state(FtpState::Wait220);
        harness.reply(b"220 hi\r\n").expect("greeting");
        assert_eq!(harness.state(), FtpState::User);
        harness.reply(b"331 password\r\n").expect("password wanted");
        assert_eq!(harness.state(), FtpState::Pass);
        harness.reply(b"230 in\r\n").expect("logged in");
        assert_eq!(harness.state(), FtpState::Pwd);
        assert_eq!(harness.sent_text(), "USER me\r\nPASS secret\r\nPWD\r\n");
    }

    /// An empty user is legal and reaches the wire as `USER ` with nothing
    /// after it.
    #[test]
    fn an_empty_user_is_sent_as_a_bare_user_command() {
        let mut harness = Harness::new(b"file");
        harness.client.opts.user = Vec::new();
        harness.force_state(FtpState::Wait220);
        harness.reply(b"220 hi\r\n").expect("greeting");
        assert_eq!(harness.sent_text(), "USER \r\n");
    }

    /// `332` asks for an account, and the account is sent when there is one.
    #[test]
    fn a_332_sends_the_configured_account() {
        let mut harness = Harness::new(b"file");
        harness.client.opts.account = Some(b"billing".to_vec());
        harness.force_state(FtpState::User);
        harness
            .reply(b"332 need account\r\n")
            .expect("account sent");
        assert_eq!(harness.state(), FtpState::Acct);
        assert_eq!(harness.sent_text(), "ACCT billing\r\n");
        harness.reply(b"230 in\r\n").expect("accepted");
        assert_eq!(harness.state(), FtpState::Pwd);
    }

    /// A `332` with no account configured is a login denial, with the C's text.
    #[test]
    fn a_332_without_an_account_is_a_login_denial() {
        let mut harness = Harness::new(b"file");
        harness.force_state(FtpState::User);
        let error = harness
            .reply(b"332 need account\r\n")
            .expect_err("nothing to send");
        assert_eq!(error.code(), CURLcode::LoginDenied);
        assert_eq!(
            harness.client.log.fail,
            vec!["ACCT requested but none available"]
        );
    }

    /// An account the server rejects is `CURLE_FTP_WEIRD_PASS_REPLY`, which the
    /// C marks `/* FIX */` and which is preserved.
    #[test]
    fn a_rejected_account_keeps_the_c_error_code() {
        let mut harness = Harness::new(b"file");
        harness.force_state(FtpState::Acct);
        let error = harness
            .reply(b"530 no\r\n")
            .expect_err("the account was refused");
        assert_eq!(error.code(), CURLcode::FtpWeirdPassReply);
        assert_eq!(
            harness.client.log.fail,
            vec!["ACCT rejected by server: 530"]
        );
    }

    /// `CURLOPT_FTP_ALTERNATIVE_TO_USER` is sent raw, once, after a refusal.
    #[test]
    fn the_alternative_to_user_command_is_sent_raw_and_only_once() {
        let mut harness = Harness::new(b"file");
        harness.client.opts.alternative_to_user =
            Some(b"SITE AUTH me/secret".to_vec());
        harness.force_state(FtpState::User);
        harness
            .reply(b"530 denied\r\n")
            .expect("the alternative runs");
        assert_eq!(harness.state(), FtpState::User);
        assert_eq!(harness.sent_text(), "SITE AUTH me/secret\r\n");
        // A second refusal has nothing left to try.
        let error = harness
            .reply(b"530 denied again\r\n")
            .expect_err("out of options");
        assert_eq!(error.code(), CURLcode::LoginDenied);
        assert_eq!(harness.client.log.fail, vec!["Access denied: 530"]);
    }

    /// A refusal with nothing to fall back on is `Access denied: %03d`.
    #[test]
    fn a_refused_login_reports_access_denied_with_the_code() {
        let mut harness = Harness::new(b"file");
        harness.force_state(FtpState::Pass);
        let error = harness.reply(b"530 nope\r\n").expect_err("denied");
        assert_eq!(error.code(), CURLcode::LoginDenied);
        assert_eq!(harness.client.log.fail, vec!["Access denied: 530"]);
    }

    // -- Phase 12: PWD, SYST and the OS/400 name format ---------------------

    /// The quote-doubling rule of a `257` reply.
    #[test]
    fn the_pwd_reply_parser_follows_the_quote_doubling_convention() {
        // Escaped rather than raw literals throughout: the crate root's
        // `source_policy::no_raw_string_literal_defeats_the_stripper` forbids
        // `r"..."` anywhere under `curl-rs-lib/src`, because the stripper its
        // keyword scans rely on does not lex one.
        assert_eq!(
            parse_pwd_reply(b"\"/pub\" is current"),
            Some(b"/pub".to_vec())
        );
        // A doubled quote is one literal quote.
        assert_eq!(
            parse_pwd_reply(b"\"/a\"\"b\" is current"),
            Some(b"/a\"b".to_vec())
        );
        // Rubbish before the first quote is skipped.
        assert_eq!(
            parse_pwd_reply(b"directory \"/x\" now"),
            Some(b"/x".to_vec())
        );
        // No quote at all, an empty name, and a line feed that ends the scan.
        assert_eq!(parse_pwd_reply(b"/pub is current"), None);
        assert_eq!(parse_pwd_reply(b"\"\" is current"), None);
        assert_eq!(parse_pwd_reply(b"no quote here\n\"/x\""), None);
    }

    /// A `257` records the entry path and reports it.
    #[test]
    fn a_257_records_the_entry_path_and_finishes_the_connect_phase() {
        let mut harness = Harness::new(b"file");
        harness.force_state(FtpState::Pwd);
        harness
            .reply(b"257 \"/home/me\" is the current directory\r\n")
            .expect("parsed");
        assert_eq!(
            harness.session.conn().ftpc().entrypath.as_deref(),
            Some(&b"/home/me"[..])
        );
        assert_eq!(
            harness.client.req.most_recent_entrypath.as_deref(),
            Some(&b"/home/me"[..])
        );
        assert!(harness
            .client
            .log
            .info
            .contains(&"Entry path is '/home/me'".to_owned()));
        assert_eq!(harness.state(), FtpState::Stop);
    }

    /// An unparsable `257` reports the C's text and still finishes.
    #[test]
    fn an_unparsable_257_reports_failure_to_figure_out_the_path() {
        let mut harness = Harness::new(b"file");
        harness.force_state(FtpState::Pwd);
        harness
            .reply(b"257 no quotes at all\r\n")
            .expect("tolerated");
        assert!(harness
            .client
            .log
            .info
            .contains(&"Failed to figure out path".to_owned()));
        assert_eq!(harness.state(), FtpState::Stop);
    }

    /// A relative entry path triggers `SYST`.
    #[test]
    fn a_relative_entry_path_asks_the_server_what_it_is() {
        let mut harness = Harness::new(b"file");
        harness.force_state(FtpState::Pwd);
        harness
            .reply(b"257 \"MYLIB\" is current library\r\n")
            .expect("parsed");
        assert_eq!(harness.state(), FtpState::Syst);
        assert_eq!(harness.sent_text(), "SYST\r\n");
    }

    /// The `SYST` reply's operating-system word.
    #[test]
    fn the_syst_reply_parser_takes_the_first_word() {
        assert_eq!(parse_syst_reply(b" UNIX Type: L8"), b"UNIX".to_vec());
        assert_eq!(parse_syst_reply(b"   OS/400 is here"), b"OS/400".to_vec());
        assert_eq!(
            parse_syst_reply(b" Windows_NT\r\n"),
            b"Windows_NT".to_vec()
        );
        assert_eq!(parse_syst_reply(b""), Vec::<u8>::new());
    }

    /// An OS/400 server has its name format switched, and the `PWD` repeats.
    #[test]
    fn an_os400_server_gets_site_namefmt_1_and_a_second_pwd() {
        let mut harness = Harness::new(b"file");
        harness.force_state(FtpState::Syst);
        harness
            .reply(b"215 OS/400 is the OS here\r\n")
            .expect("parsed");
        assert_eq!(harness.state(), FtpState::NameFmt);
        assert_eq!(harness.sent_text(), "SITE NAMEFMT 1\r\n");
        assert_eq!(
            harness.session.conn().ftpc().server_os.as_deref(),
            Some(&b"OS/400"[..])
        );
        harness.reply(b"250 format changed\r\n").expect("accepted");
        assert_eq!(harness.state(), FtpState::Pwd);
        assert_eq!(harness.sent_text(), "SITE NAMEFMT 1\r\nPWD\r\n");
    }

    /// Any other operating system needs nothing special.
    #[test]
    fn a_unix_server_needs_no_name_format_change() {
        let mut harness = Harness::new(b"file");
        harness.force_state(FtpState::Syst);
        harness.reply(b"215 UNIX Type: L8\r\n").expect("parsed");
        assert_eq!(harness.state(), FtpState::Stop);
        assert_eq!(harness.sent_text(), "");
        assert_eq!(
            harness.session.conn().ftpc().server_os.as_deref(),
            Some(&b"UNIX"[..])
        );
    }

    /// A `SYST` the server refuses is tolerated -- *"cross fingers"*.
    #[test]
    fn a_refused_syst_is_tolerated() {
        let mut harness = Harness::new(b"file");
        harness.force_state(FtpState::Syst);
        harness
            .reply(b"500 unknown command\r\n")
            .expect("tolerated");
        assert_eq!(harness.state(), FtpState::Stop);
        assert!(harness.session.conn().ftpc().server_os.is_none());
    }

    /// A name-format change the server refuses still finishes the phase.
    #[test]
    fn a_refused_name_format_change_still_finishes_the_connect_phase() {
        let mut harness = Harness::new(b"file");
        harness.force_state(FtpState::NameFmt);
        harness.reply(b"500 no\r\n").expect("tolerated");
        assert_eq!(harness.state(), FtpState::Stop);
    }

    // -- Phase 12: response framing and the 421 rule ------------------------

    /// `ftp_endofresp`'s four conditions, each one exercised alone.
    #[test]
    fn ftp_endofresp_requires_three_digits_a_space_and_a_length() {
        let mut code = -1;

        // Too short: the C's `len > 3` is a length of FOUR at minimum.
        assert!(!ftp_endofresp(b"220", &mut code));
        assert!(!ftp_endofresp(b"22", &mut code));
        assert!(!ftp_endofresp(b"", &mut code));

        // A continuation line: `NNN-` is not final.
        code = -1;
        assert!(!ftp_endofresp(b"220-first of many\r\n", &mut code));

        // Non-digits in any of the three positions.
        assert!(!ftp_endofresp(b"2x0 no\r\n", &mut code));
        assert!(!ftp_endofresp(b"x20 no\r\n", &mut code));
        assert!(!ftp_endofresp(b"22x no\r\n", &mut code));
        assert!(!ftp_endofresp(b" 220 no\r\n", &mut code));

        // A final line, with the code read out.
        code = 0;
        assert!(ftp_endofresp(b"220 hello\r\n", &mut code));
        assert_eq!(code, 220);
        assert!(ftp_endofresp(b"999 highest\r\n", &mut code));
        assert_eq!(code, 999);
        assert!(ftp_endofresp(b"000 lowest\r\n", &mut code));
        assert_eq!(code, 0);
        // Exactly four bytes is enough: `"213 "`.
        assert!(ftp_endofresp(b"213 ", &mut code));
        assert_eq!(code, 213);
    }

    /// A code above 999 cannot be spelled in three digits, so the fourth byte
    /// is not a space and the line is not final.
    #[test]
    fn a_four_digit_code_is_not_a_final_line() {
        let mut code = 0;
        assert!(!ftp_endofresp(b"1000 too big\r\n", &mut code));
    }

    /// The reply code reaches `CURLINFO_RESPONSE_CODE`, except during shutdown.
    #[test]
    fn the_reply_code_is_recorded_unless_the_connection_is_shutting_down() {
        let mut harness = Harness::new(b"file");
        harness.force_state(FtpState::Syst);
        harness.reply(b"215 UNIX\r\n").expect("read");
        assert_eq!(harness.client.req.httpcode, 215);

        harness.session.conn_mut().ftpc_mut().shutdown = true;
        harness.force_state(FtpState::Quit);
        harness.reply(b"221 bye\r\n").expect("read");
        assert_eq!(
            harness.client.req.httpcode, 215,
            "a shutdown reply does not overwrite the transfer's code"
        );
    }

    /// A `421` is a timeout wherever it arrives, with the C's exact text, and it
    /// forces the machine to stop.
    #[test]
    fn a_421_is_a_timeout_from_any_state() {
        for state in [FtpState::Wait220, FtpState::Cwd, FtpState::Retr] {
            let mut harness = Harness::new(b"file");
            harness.force_state(state);
            let error = harness
                .reply(b"421 Timeout, closing control connection\r\n")
                .expect_err("a 421 ends the transfer");
            assert_eq!(error.code(), CURLcode::OperationTimedout);
            assert_eq!(
                harness.client.log.info,
                vec![TIMEOUT_421_MESSAGE.to_owned()],
                "from {state}"
            );
            assert_eq!(harness.state(), FtpState::Stop, "from {state}");
        }
        assert_eq!(TIMEOUT_421_MESSAGE, "We got a 421 - timeout");
    }

    /// The two blocking-read texts are the C's.
    #[test]
    fn the_blocking_read_texts_are_the_c_strings() {
        assert_eq!(RESPONSE_TIMEOUT_MESSAGE, "FTP response timeout");
        assert_eq!(
            code_only()
                .matches("FTP response aborted due to select/poll error")
                .count(),
            1,
            "the select/poll failure text appears exactly once"
        );
    }

    /// The restamped deadline is the engine's own formula with a new origin.
    #[test]
    fn a_restamped_response_deadline_measures_from_the_new_origin() {
        let mut harness = Harness::new(b"file");
        harness.init_pp();
        // No configured response timeout: the engine's default applies.
        {
            let io = harness.io();
            let now = io.clock().now();
            assert_eq!(
                response_budget_ms(&io, now),
                pingpong::RESP_TIMEOUT,
                "an origin of now leaves the whole allowance"
            );
            // An origin one second in the past has spent a second of it.
            let earlier = CurlTime::new(now.secs.saturating_sub(1), now.usec);
            assert_eq!(
                response_budget_ms(&io, earlier),
                pingpong::RESP_TIMEOUT - 1000
            );
        }

        // A configured timeout replaces the default, and the transfer's own
        // deadline wins when it is nearer -- both the C's rules.
        harness.client.opts.server_response_timeout_ms = 5_000;
        harness.client.timeleft = 250;
        {
            let io = harness.io();
            let now = io.clock().now();
            assert_eq!(response_budget_ms(&io, now), 250);
        }

        harness.client.timeleft = 0;
        let io = harness.io();
        let now = io.clock().now();
        assert_eq!(
            response_budget_ms(&io, now),
            5_000,
            "a timeleft of zero means no transfer deadline applies"
        );
    }

    // -- Phase 12: URL path parsing -----------------------------------------

    /// `ftp_parse_url_path` over a harness, answering what it produced.
    fn parse_path(harness: &mut Harness) -> CodeResult<()> {
        let mut io = FtpIo::new(
            &mut harness.chains,
            harness.clock.as_ref(),
            &mut harness.client,
        );
        let (_pp, machine) = harness.session.split();
        machine.ftpc.parse_url_path(machine.transfer, &mut io)
    }

    /// The pseudo-headers the engine wrote, in order.
    ///
    /// `Curl_pp_readresp` shows every reply line to the client as
    /// [`ClientWriteFlags::INFO`] -- curl's own `CLIENTWRITE_INFO` echo, which
    /// is what puts `220 ready` in a verbose log -- so a test about headers has
    /// to filter. That echo is asserted in its own right by
    /// [`the_reply_lines_are_echoed_to_the_client`].
    fn headers(harness: &Harness) -> Vec<String> {
        harness
            .client
            .log
            .writes
            .iter()
            .filter(|(flags, _)| *flags == ClientWriteFlags::HEADER)
            .map(|(_, bytes)| String::from_utf8_lossy(bytes).into_owned())
            .collect()
    }

    /// The reply lines the engine echoed to the client.
    fn echoed(harness: &Harness) -> Vec<String> {
        harness
            .client
            .log
            .writes
            .iter()
            .filter(|(flags, _)| *flags == ClientWriteFlags::INFO)
            .map(|(_, bytes)| String::from_utf8_lossy(bytes).into_owned())
            .collect()
    }

    /// Every reply line reaches the client as informational output, which is
    /// what a verbose log shows.
    #[test]
    fn the_reply_lines_are_echoed_to_the_client() {
        let mut harness = Harness::new(b"file");
        harness.force_state(FtpState::Syst);
        harness.reply(b"215 UNIX Type: L8\r\n").expect("read");
        assert_eq!(echoed(&harness), vec!["215 UNIX Type: L8\r\n".to_owned()]);
        assert!(headers(&harness).is_empty());
    }

    /// The components and the filename a parse produced, as text.
    fn parsed(harness: &Harness) -> (Vec<String>, Option<String>) {
        let ftpc = harness.session.conn().ftpc();
        let dirs = (0..usize::from(ftpc.dirdepth()))
            .map(|index| {
                String::from_utf8_lossy(ftpc.pathpiece(index).unwrap_or(&[]))
                    .into_owned()
            })
            .collect();
        let file = ftpc
            .file()
            .map(|bytes| String::from_utf8_lossy(bytes).into_owned());
        (dirs, file)
    }

    /// `FTPFILE_MULTICWD` -- one `CWD` per component.
    #[test]
    fn multicwd_splits_the_path_at_every_slash() {
        let mut harness = Harness::new(b"a/b/c/file.txt");
        parse_path(&mut harness).expect("parsed");
        let (dirs, file) = parsed(&harness);
        assert_eq!(dirs, vec!["a", "b", "c"]);
        assert_eq!(file.as_deref(), Some("file.txt"));
        assert_eq!(harness.session.conn().ftpc().dirdepth(), 3);
    }

    /// An initial slash is kept as a component of its own, so the first `CWD`
    /// is `CWD /`.
    #[test]
    fn multicwd_keeps_a_leading_slash_as_its_own_component() {
        let mut harness = Harness::new(b"/pub/file");
        parse_path(&mut harness).expect("parsed");
        let (dirs, file) = parsed(&harness);
        assert_eq!(dirs, vec!["/", "pub"]);
        assert_eq!(file.as_deref(), Some("file"));
    }

    /// An empty component is skipped -- `x//y` is one directory, not two.
    #[test]
    fn multicwd_skips_an_empty_component() {
        let mut harness = Harness::new(b"x//y");
        parse_path(&mut harness).expect("parsed");
        let (dirs, file) = parsed(&harness);
        assert_eq!(dirs, vec!["x"]);
        assert_eq!(file.as_deref(), Some("y"));
    }

    /// A path ending in a slash has directories and no filename.
    #[test]
    fn a_trailing_slash_leaves_no_filename() {
        let mut harness = Harness::new(b"pub/dir/");
        parse_path(&mut harness).expect("parsed");
        let (dirs, file) = parsed(&harness);
        assert_eq!(dirs, vec!["pub", "dir"]);
        assert_eq!(file, None);
        assert!(!harness.session.conn().ftpc().has_file());
    }

    /// `FTPFILE_SINGLECWD` -- one `CWD` to the whole directory.
    #[test]
    fn singlecwd_makes_one_component_of_the_whole_directory() {
        let mut harness = Harness::new(b"a/b/c/file.txt");
        harness.client.req.file_method = FileMethod::SingleCwd;
        parse_path(&mut harness).expect("parsed");
        let (dirs, file) = parsed(&harness);
        assert_eq!(dirs, vec!["a/b/c"]);
        assert_eq!(file.as_deref(), Some("file.txt"));
    }

    /// Under `SINGLECWD` the root stays a one-byte component.
    #[test]
    fn singlecwd_keeps_the_root_as_a_single_slash() {
        let mut harness = Harness::new(b"/file.txt");
        harness.client.req.file_method = FileMethod::SingleCwd;
        parse_path(&mut harness).expect("parsed");
        let (dirs, file) = parsed(&harness);
        assert_eq!(dirs, vec!["/"]);
        assert_eq!(file.as_deref(), Some("file.txt"));
    }

    /// `FTPFILE_NOCWD` -- no `CWD` at all, the whole path is the filename.
    #[test]
    fn nocwd_uses_the_whole_path_as_the_filename() {
        let mut harness = Harness::new(b"a/b/file.txt");
        harness.client.req.file_method = FileMethod::NoCwd;
        parse_path(&mut harness).expect("parsed");
        let (dirs, file) = parsed(&harness);
        assert!(dirs.is_empty());
        assert_eq!(file.as_deref(), Some("a/b/file.txt"));
    }

    /// An absolute path under `NOCWD` marks the walk already done.
    #[test]
    fn nocwd_marks_an_absolute_path_as_needing_no_walk() {
        let mut harness = Harness::new(b"/a/b/file.txt");
        harness.client.req.file_method = FileMethod::NoCwd;
        parse_path(&mut harness).expect("parsed");
        assert!(harness.session.conn().ftpc().cwddone);
        let (_dirs, file) = parsed(&harness);
        assert_eq!(file.as_deref(), Some("/a/b/file.txt"));
    }

    /// Under `NOCWD` a path ending in a slash still has no filename.
    #[test]
    fn nocwd_leaves_no_filename_for_a_directory() {
        let mut harness = Harness::new(b"a/b/");
        harness.client.req.file_method = FileMethod::NoCwd;
        parse_path(&mut harness).expect("parsed");
        let (_dirs, file) = parsed(&harness);
        assert_eq!(file, None);
    }

    /// The path is percent-decoded by the module that owns escaping.
    #[test]
    fn the_path_is_percent_decoded() {
        let mut harness = Harness::new(b"a%20b/c%2Fd");
        parse_path(&mut harness).expect("parsed");
        let (dirs, file) = parsed(&harness);
        assert_eq!(
            dirs,
            vec!["a b", "c"],
            "the whole path is decoded BEFORE it is split, so %2F becomes a \
             separator -- `Curl_urldecode(ftp->path, ...)` precedes the switch \
             at `lib/ftp.c:221-227`"
        );
        assert_eq!(file.as_deref(), Some("d"));
    }

    /// A control character in the path is refused, with the C's exact text.
    #[test]
    fn a_control_character_in_the_path_is_refused() {
        let mut harness = Harness::new(b"a%09b/file");
        assert_eq!(parse_path(&mut harness), Err(CURLcode::UrlMalformat));
        assert_eq!(
            harness.client.log.fail,
            vec![CONTROL_CHARS_MESSAGE.to_owned()]
        );
        assert_eq!(CONTROL_CHARS_MESSAGE, "path contains control characters");
    }

    /// An upload with no filename in the URL is refused, with the C's text.
    #[test]
    fn an_upload_without_a_filename_is_refused() {
        let mut harness = Harness::new(b"dir/");
        harness.client.req.upload = true;
        assert_eq!(parse_path(&mut harness), Err(CURLcode::UrlMalformat));
        assert_eq!(
            harness.client.log.fail,
            vec![UPLOAD_NO_FILENAME_MESSAGE.to_owned()]
        );
        assert_eq!(
            UPLOAD_NO_FILENAME_MESSAGE,
            "Uploading to a URL without a filename"
        );
    }

    /// A path 999 components deep parses; 1000 is refused.
    #[test]
    fn the_directory_depth_is_capped_at_a_thousand() {
        let deep = |count: usize| -> Vec<u8> {
            let mut path = Vec::new();
            for _ in 0..count {
                path.extend_from_slice(b"d/");
            }
            path.extend_from_slice(b"file");
            path
        };

        let mut harness = Harness::new(&deep(999));
        parse_path(&mut harness).expect("999 components fit");
        assert_eq!(harness.session.conn().ftpc().dirdepth(), 999);

        let mut harness = Harness::new(&deep(1000));
        assert_eq!(
            parse_path(&mut harness),
            Err(CURLcode::UrlMalformat),
            "the thousandth component is refused"
        );
    }

    /// The `;type=` suffix, in all four of its forms.
    #[test]
    fn the_type_suffix_selects_the_transfer_mode() {
        for (path, ascii, list_only, expected) in [
            (&b"file;type=A"[..], true, false, "file"),
            (&b"file;type=a"[..], true, false, "file"),
            (&b"dir;type=D"[..], false, true, "dir"),
            (&b"dir;type=d"[..], false, true, "dir"),
            (&b"file;type=I"[..], false, false, "file"),
            (&b"file;type=i"[..], false, false, "file"),
        ] {
            let mut harness = Harness::new(path);
            harness.setup().expect("setup succeeds");
            assert_eq!(
                harness.client.req.prefer_ascii,
                ascii,
                "prefer_ascii for {}",
                String::from_utf8_lossy(path)
            );
            assert_eq!(
                harness.client.req.list_only,
                list_only,
                "list_only for {}",
                String::from_utf8_lossy(path)
            );
            parse_path(&mut harness).expect("parsed");
            let (_dirs, file) = parsed(&harness);
            assert_eq!(
                file.as_deref(),
                Some(expected),
                "the suffix is cut from {}",
                String::from_utf8_lossy(path)
            );
        }
    }

    /// An unrecognised `;type=` value is still CUT, and turns ASCII off.
    ///
    /// The C's `switch` puts `'I'` and `default:` in the same arm
    /// (`lib/ftp.c:4246-4250`), and the cut at `:4235` happens before the switch
    /// -- so the suffix never survives, whatever code follows it.
    #[test]
    fn an_unknown_type_suffix_is_cut_and_selects_binary() {
        let mut harness = Harness::new(b"file;type=Z");
        harness.client.req.prefer_ascii = true;
        harness.setup().expect("setup succeeds");
        assert!(!harness.client.req.prefer_ascii);
        parse_path(&mut harness).expect("parsed");
        let (_dirs, file) = parsed(&harness);
        assert_eq!(file.as_deref(), Some("file"));
    }

    /// A path too short to hold a suffix, and one whose tail merely resembles
    /// one, are both left alone.
    #[test]
    fn a_path_without_a_type_suffix_is_untouched() {
        for path in [&b"f"[..], b"type=A", b";type", b"a;typex=A"] {
            let mut harness = Harness::new(path);
            harness.setup().expect("setup succeeds");
            parse_path(&mut harness).expect("parsed");
            let (_dirs, file) = parsed(&harness);
            assert_eq!(
                file.as_deref(),
                Some(String::from_utf8_lossy(path).as_ref()),
                "{} keeps its whole name",
                String::from_utf8_lossy(path)
            );
        }
    }

    /// `ftp_setup_connection` snapshots the four connection-owned settings and
    /// traces with the state prefix.
    #[test]
    fn setup_connection_snapshots_the_connection_settings() {
        let mut harness = Harness::new(b"file");
        harness.client.opts.account = Some(b"acct".to_vec());
        harness.client.opts.alternative_to_user = Some(b"SITE X".to_vec());
        harness.client.opts.use_ssl = UseSsl::Control;
        harness.client.opts.ccc = CccMode::Passive;
        harness.setup().expect("setup");

        let ftpc = harness.session.conn().ftpc();
        assert_eq!(ftpc.account.as_deref(), Some(&b"acct"[..]));
        assert_eq!(ftpc.alternative_to_user.as_deref(), Some(&b"SITE X"[..]));
        assert_eq!(ftpc.use_ssl, UseSsl::Control);
        assert_eq!(ftpc.ccc, CccMode::Passive);
        assert_eq!(ftpc.known_filesize, -1);
        assert_eq!(harness.session.transfer().transfer, PpTransfer::Body);
        assert_eq!(harness.session.transfer().downloadsize, 0);
        assert!(harness
            .client
            .log
            .trc
            .contains(&"[STOP] setup connection -> 0".to_owned()));
    }

    /// A reused connection whose path is unchanged skips the walk, with the
    /// C's exact info line.
    #[test]
    fn a_reused_connection_with_the_same_path_skips_the_walk() {
        let mut harness = Harness::new(b"pub/file");
        harness.client.req.reuse = true;
        harness.session.conn_mut().ftpc_mut().prevpath = Some(b"pub/".to_vec());
        parse_path(&mut harness).expect("parsed");
        assert!(harness.session.conn().ftpc().cwddone);
        assert!(harness
            .client
            .log
            .info
            .contains(&SAME_PATH_MESSAGE.to_owned()));
        assert_eq!(
            SAME_PATH_MESSAGE,
            "Request has same path as previous transfer"
        );
    }

    /// A reused connection whose path differs does walk.
    #[test]
    fn a_reused_connection_with_a_different_path_walks_again() {
        let mut harness = Harness::new(b"other/file");
        harness.client.req.reuse = true;
        harness.session.conn_mut().ftpc_mut().prevpath = Some(b"pub/".to_vec());
        parse_path(&mut harness).expect("parsed");
        assert!(!harness.session.conn().ftpc().cwddone);
        assert!(!harness
            .client
            .log
            .info
            .contains(&SAME_PATH_MESSAGE.to_owned()));
    }

    // -- Phase 12: the quote lists ------------------------------------------

    /// The regular quote list runs in order, one entry per reply, and leads to
    /// the `CWD` walk.
    #[test]
    fn the_quote_list_runs_in_order_and_then_walks() {
        let mut harness = Harness::new(b"pub/file");
        harness.client.opts.quote =
            vec![b"SITE UMASK 022".to_vec(), b"SITE HELP".to_vec()];
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine
                .state_quote(pp, io, true, FtpState::Quote)
                .expect("the first entry goes out");
        });
        assert_eq!(harness.state(), FtpState::Quote);
        harness.reply(b"200 ok\r\n").expect("second entry");
        harness.reply(b"200 ok\r\n").expect("list exhausted");
        assert_eq!(harness.state(), FtpState::Cwd);
        assert_eq!(
            harness.sent_text(),
            "SITE UMASK 022\r\nSITE HELP\r\nCWD pub\r\n"
        );
    }

    /// A refused quote command is `CURLE_QUOTE_ERROR`, with the C's text.
    #[test]
    fn a_refused_quote_command_is_a_quote_error() {
        let mut harness = Harness::new(b"file");
        harness.client.opts.quote = vec![b"SITE NOPE".to_vec()];
        harness.with_machine(|pp, machine, io| {
            machine
                .state_quote(pp, io, true, FtpState::Quote)
                .expect("sent");
        });
        let error = harness.reply(b"500 unknown\r\n").expect_err("refused");
        assert_eq!(error.code(), CURLcode::QuoteError);
        assert_eq!(
            harness.client.log.fail,
            vec!["QUOT command failed with 500"]
        );
    }

    /// A leading `*` permits failure, and never reaches the wire.
    #[test]
    fn a_starred_quote_command_may_fail_and_loses_its_marker() {
        let mut harness = Harness::new(b"file");
        harness.client.opts.quote = vec![b"*SITE NOPE".to_vec()];
        harness.with_machine(|pp, machine, io| {
            machine
                .state_quote(pp, io, true, FtpState::Quote)
                .expect("sent");
        });
        assert_eq!(
            harness.sent_text(),
            "SITE NOPE\r\n",
            "the marker is stripped before the command goes out"
        );
        harness
            .reply(b"500 unknown\r\n")
            .expect("a starred command may fail");
        assert_eq!(
            harness.sent_text(),
            "SITE NOPE\r\nEPSV\r\n",
            "the list is exhausted and the machine runs on to the data channel"
        );
        assert_eq!(harness.state(), FtpState::Pasv);
    }

    /// The `RETR` prequote list leads to `SIZE`; the `STOR` one to the upload
    /// setup; the `LIST` one to the listing.
    #[test]
    fn each_prequote_list_leads_where_the_c_sends_it() {
        // RETR_PREQUOTE -> SIZE, then RETR.
        let mut harness = Harness::new(b"file");
        harness.client.opts.prequote = vec![b"SITE PRE".to_vec()];
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine
                .state_quote(pp, io, true, FtpState::RetrPrequote)
                .expect("sent");
        });
        harness.reply(b"200 ok\r\n").expect("list exhausted");
        assert_eq!(harness.state(), FtpState::RetrSize);
        assert_eq!(harness.sent_text(), "SITE PRE\r\nSIZE file\r\n");

        // LIST_PREQUOTE -> the listing command.
        let mut harness = Harness::new(b"dir/");
        harness.client.opts.prequote = vec![b"SITE PRE".to_vec()];
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine
                .state_quote(pp, io, true, FtpState::ListPrequote)
                .expect("sent");
        });
        harness.reply(b"200 ok\r\n").expect("list exhausted");
        assert_eq!(harness.state(), FtpState::List);
        assert_eq!(harness.sent_text(), "SITE PRE\r\nLIST\r\n");

        // STOR_PREQUOTE -> the upload command.
        let mut harness = Harness::new(b"file");
        harness.client.req.upload = true;
        harness.client.opts.prequote = vec![b"SITE PRE".to_vec()];
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine
                .state_quote(pp, io, true, FtpState::StorPrequote)
                .expect("sent");
        });
        harness.reply(b"200 ok\r\n").expect("list exhausted");
        assert_eq!(harness.state(), FtpState::Stor);
        assert_eq!(harness.sent_text(), "SITE PRE\r\nSTOR file\r\n");
    }

    /// The postquote list runs after the transfer and leads nowhere.
    #[test]
    fn the_postquote_list_leads_nowhere() {
        let mut harness = Harness::new(b"file");
        harness.client.opts.postquote = vec![b"SITE POST".to_vec()];
        harness.with_machine(|pp, machine, io| {
            machine
                .state_quote(pp, io, true, FtpState::Postquote)
                .expect("sent");
        });
        assert_eq!(harness.sent_text(), "SITE POST\r\n");
        harness.reply(b"200 ok\r\n").expect("list exhausted");
        assert_eq!(
            harness.state(),
            FtpState::Postquote,
            "the C's FTP_POSTQUOTE arm falls out with the state unchanged"
        );
    }

    /// `ftp_sendquote`, the blocking form used by the post-transfer list.
    #[test]
    fn the_blocking_quote_sender_walks_the_list_and_refuses_a_failure() {
        let mut harness = Harness::new(b"file");
        harness.init_pp();
        harness.feed(b"200 one\r\n250 two\r\n");
        let list = vec![b"SITE A".to_vec(), b"SITE B".to_vec()];
        harness
            .with(|session, io| drive(ftp_sendquote(session, io, &list)))
            .expect("both accepted");
        assert_eq!(harness.sent_text(), "SITE A\r\nSITE B\r\n");

        let mut harness = Harness::new(b"file");
        harness.init_pp();
        harness.feed(b"500 no\r\n");
        let list = vec![b"SITE C".to_vec()];
        let error = harness
            .with(|session, io| drive(ftp_sendquote(session, io, &list)))
            .expect_err("refused");
        assert_eq!(error.code(), CURLcode::QuoteError);
        assert_eq!(
            harness.client.log.fail,
            vec!["QUOT string not accepted: SITE C"]
        );

        // A starred entry is tolerated and loses its marker.
        let mut harness = Harness::new(b"file");
        harness.init_pp();
        harness.feed(b"500 no\r\n");
        let list = vec![b"*SITE D".to_vec()];
        harness
            .with(|session, io| drive(ftp_sendquote(session, io, &list)))
            .expect("tolerated");
        assert_eq!(harness.sent_text(), "SITE D\r\n");

        // An empty entry is skipped entirely -- the C's `if(item->data)`.
        let mut harness = Harness::new(b"file");
        harness.init_pp();
        let list = vec![Vec::new()];
        harness
            .with(|session, io| drive(ftp_sendquote(session, io, &list)))
            .expect("nothing to send");
        assert_eq!(harness.sent_text(), "");
    }

    // -- Phase 12: the CWD walk and MKD ------------------------------------

    /// Every component gets its own `CWD`, in order.
    #[test]
    fn the_walk_issues_one_cwd_per_component() {
        let mut harness = Harness::new(b"a/b/c/file");
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine.state_cwd(pp, io).expect("first CWD");
        });
        harness.reply(b"250 ok\r\n").expect("second");
        harness.reply(b"250 ok\r\n").expect("third");
        harness.reply(b"250 ok\r\n").expect("walk done");
        assert_eq!(
            harness.sent_text(),
            "CWD a\r\nCWD b\r\nCWD c\r\nEPSV\r\n",
            "three components, three commands, no empty parameter -- and then \
             the walk is done and the data channel begins"
        );
    }

    /// A reused connection is walked back to its entry path first.
    #[test]
    fn a_reused_relative_connection_returns_to_the_entry_path_first() {
        let mut harness = Harness::new(b"pub/file");
        harness.client.req.reuse = true;
        harness.session.conn_mut().ftpc_mut().entrypath =
            Some(b"/home/me".to_vec());
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine.state_cwd(pp, io).expect("entry-path CWD");
        });
        assert_eq!(harness.sent_text(), "CWD /home/me\r\n");
        harness.reply(b"250 ok\r\n").expect("then the component");
        assert_eq!(harness.sent_text(), "CWD /home/me\r\nCWD pub\r\n");
    }

    /// An absolute path has nowhere to go back to, so the entry path is skipped.
    #[test]
    fn an_absolute_path_does_not_return_to_the_entry_path() {
        let mut harness = Harness::new(b"/pub/file");
        harness.client.req.reuse = true;
        harness.session.conn_mut().ftpc_mut().entrypath =
            Some(b"/home/me".to_vec());
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine.state_cwd(pp, io).expect("first component");
        });
        assert_eq!(harness.sent_text(), "CWD /\r\n");
    }

    /// A refused `CWD` with no creation requested is a remote access denial,
    /// and it forbids remembering the path.
    #[test]
    fn a_refused_cwd_denies_access_and_forgets_the_path() {
        let mut harness = Harness::new(b"a/b/file");
        parse_path(&mut harness).expect("parsed");
        harness.force_state(FtpState::Cwd);
        harness.session.conn_mut().ftpc_mut().cwdcount = 1;
        let error = harness.reply(b"550 no such\r\n").expect_err("denied");
        assert_eq!(error.code(), CURLcode::RemoteAccessDenied);
        assert_eq!(
            harness.client.log.fail,
            vec!["Server denied you to change to the given directory"]
        );
        assert!(harness.session.conn().ftpc().cwdfail);
    }

    /// `CURLOPT_FTP_CREATE_MISSING_DIRS` = 1: create it, then enter it.
    #[test]
    fn a_missing_directory_is_created_once_when_asked() {
        let mut harness = Harness::new(b"a/b/file");
        harness.client.opts.create_missing_dirs = 1;
        parse_path(&mut harness).expect("parsed");
        harness.force_state(FtpState::Cwd);
        harness.session.conn_mut().ftpc_mut().cwdcount = 1;
        harness.reply(b"550 no such\r\n").expect("MKD instead");
        assert_eq!(harness.state(), FtpState::Mkd);
        assert_eq!(harness.sent_text(), "MKD a\r\n");
        harness.reply(b"257 created\r\n").expect("now enter it");
        assert_eq!(harness.state(), FtpState::Cwd);
        assert_eq!(harness.sent_text(), "MKD a\r\nCWD a\r\n");
    }

    /// A refused `MKD` with `create_missing_dirs` = 1 has no tolerance left.
    #[test]
    fn a_refused_mkd_reports_the_code() {
        let mut harness = Harness::new(b"a/b/file");
        harness.client.opts.create_missing_dirs = 1;
        parse_path(&mut harness).expect("parsed");
        harness.force_state(FtpState::Cwd);
        harness.session.conn_mut().ftpc_mut().cwdcount = 1;
        harness.reply(b"550 no such\r\n").expect("MKD");
        let error = harness.reply(b"550 cannot\r\n").expect_err("refused");
        assert_eq!(error.code(), CURLcode::RemoteAccessDenied);
        assert_eq!(harness.client.log.fail, vec!["Failed to MKD dir: 550"]);
    }

    /// `create_missing_dirs` = 2 tolerates one refused `MKD` -- another session
    /// may have created the directory first.
    #[test]
    fn create_missing_dirs_two_tolerates_one_refused_mkd() {
        let mut harness = Harness::new(b"a/b/file");
        harness.client.opts.create_missing_dirs = 2;
        parse_path(&mut harness).expect("parsed");
        harness.force_state(FtpState::Cwd);
        harness.session.conn_mut().ftpc_mut().cwdcount = 1;
        harness.reply(b"550 no such\r\n").expect("MKD");
        harness
            .reply(b"550 already exists\r\n")
            .expect("tolerated once");
        assert_eq!(harness.state(), FtpState::Cwd);
        assert_eq!(harness.sent_text(), "MKD a\r\nCWD a\r\n");
    }

    /// The `CWD`-`MKD` loop guard: a second refusal in one walk does not
    /// retry.
    #[test]
    fn the_walk_does_not_loop_between_cwd_and_mkd() {
        let mut harness = Harness::new(b"a/b/file");
        harness.client.opts.create_missing_dirs = 1;
        parse_path(&mut harness).expect("parsed");
        harness.force_state(FtpState::Cwd);
        harness.session.conn_mut().ftpc_mut().cwdcount = 1;
        harness.reply(b"550 no such\r\n").expect("MKD");
        harness.reply(b"257 created\r\n").expect("CWD again");
        let error = harness
            .reply(b"550 still no\r\n")
            .expect_err("no second MKD");
        assert_eq!(error.code(), CURLcode::RemoteAccessDenied);
    }

    // -- Phase 12: MDTM, TYPE, SIZE and REST -------------------------------

    /// `ftp_213_date` reads fourteen digits and validates four fields.
    #[test]
    fn the_mdtm_timestamp_parser_matches_the_c() {
        let parsed = ftp_213_date(b"20030405060708").expect("valid");
        assert_eq!(
            parsed,
            Ftp213Date {
                year: 2003,
                month: 4,
                day: 5,
                hour: 6,
                minute: 7,
                second: 8,
            }
        );
        assert_eq!(parsed.as_getdate_text(), "20030405 06:07:08 GMT");

        // A fractional part after the seconds is ignored.
        assert!(ftp_213_date(b"20030405060708.123").is_some());
        // A leap second is admitted; 61 is not.
        assert!(ftp_213_date(b"20030405060760").is_some());
        assert!(ftp_213_date(b"20030405060761").is_none());
        // Each of the four bounds.
        assert!(ftp_213_date(b"20031305060708").is_none());
        assert!(ftp_213_date(b"20030432060708").is_none());
        assert!(ftp_213_date(b"20030405240708").is_none());
        assert!(ftp_213_date(b"20030405066008").is_none());
        // Too short.
        assert!(ftp_213_date(b"2003040506070").is_none());
        assert!(ftp_213_date(b"").is_none());
    }

    /// A `213` records the timestamp and, for a head request, emits the
    /// pseudo-header.
    #[test]
    fn a_213_emits_the_last_modified_pseudo_header_for_a_head_request() {
        let mut harness = Harness::new(b"file");
        harness.client.opts.no_body = true;
        harness.client.opts.get_filetime = true;
        parse_path(&mut harness).expect("parsed");
        harness.force_state(FtpState::Mdtm);
        harness
            .reply(b"213 20030405060708\r\n")
            .expect("timestamp read");

        assert_eq!(
            headers(&harness),
            vec!["Last-Modified: Sat, 05 Apr 2003 06:07:08 GMT\r\n".to_owned()]
        );
        assert!(harness.client.req.filetime > 0);
    }

    /// Without `CURLOPT_FILETIME` there is no header, even with a `213`.
    #[test]
    fn no_filetime_request_means_no_pseudo_header() {
        let mut harness = Harness::new(b"file");
        harness.client.opts.no_body = true;
        parse_path(&mut harness).expect("parsed");
        harness.force_state(FtpState::Mdtm);
        harness.reply(b"213 20030405060708\r\n").expect("read");
        assert!(headers(&harness).is_empty());
    }

    /// A `550` to `MDTM` is not fatal, and the C says why.
    #[test]
    fn a_550_to_mdtm_is_not_fatal() {
        let mut harness = Harness::new(b"file");
        parse_path(&mut harness).expect("parsed");
        harness.force_state(FtpState::Mdtm);
        harness.reply(b"550 no such file\r\n").expect("tolerated");
        assert!(harness.client.log.info.iter().any(|line| line
            .starts_with("MDTM failed: file does not exist or permission")));
    }

    /// Any other reply to `MDTM` is an unsupported format.
    #[test]
    fn an_odd_reply_to_mdtm_is_an_unsupported_format() {
        let mut harness = Harness::new(b"file");
        parse_path(&mut harness).expect("parsed");
        harness.force_state(FtpState::Mdtm);
        harness.reply(b"500 what\r\n").expect("tolerated");
        assert!(harness
            .client
            .log
            .info
            .contains(&"unsupported MDTM reply format".to_owned()));
    }

    /// `CURLOPT_TIMECONDITION` short-circuits the transfer in both directions.
    #[test]
    fn a_time_condition_can_short_circuit_the_transfer() {
        // IfModSince: the file is not newer, so nothing is fetched.
        let mut harness = Harness::new(b"file");
        harness.client.opts.timecondition = TimeCondition::IfModSince;
        harness.client.opts.timevalue = i64::MAX;
        parse_path(&mut harness).expect("parsed");
        harness.force_state(FtpState::Mdtm);
        harness.reply(b"213 20030405060708\r\n").expect("compared");
        assert_eq!(harness.state(), FtpState::Stop);
        assert_eq!(harness.session.transfer().transfer, PpTransfer::None);
        assert!(harness.client.req.timecond_met);
        assert!(harness
            .client
            .log
            .info
            .contains(&"The requested document is not new enough".to_owned()));

        // IfUnmodSince: the file is newer, so nothing is fetched.
        let mut harness = Harness::new(b"file");
        harness.client.opts.timecondition = TimeCondition::IfUnmodSince;
        harness.client.opts.timevalue = 1;
        parse_path(&mut harness).expect("parsed");
        harness.force_state(FtpState::Mdtm);
        harness.reply(b"213 20030405060708\r\n").expect("compared");
        assert_eq!(harness.state(), FtpState::Stop);
        assert!(harness
            .client
            .log
            .info
            .contains(&"The requested document is not old enough".to_owned()));
    }

    /// With no timestamp to compare, the comparison is skipped.
    #[test]
    fn a_time_condition_without_a_timestamp_is_skipped() {
        let mut harness = Harness::new(b"file");
        harness.client.opts.timecondition = TimeCondition::IfModSince;
        harness.client.opts.timevalue = 0;
        parse_path(&mut harness).expect("parsed");
        harness.force_state(FtpState::Mdtm);
        harness.reply(b"213 20030405060708\r\n").expect("skipped");
        assert!(harness
            .client
            .log
            .info
            .contains(&"Skipping time comparison".to_owned()));
        assert_ne!(harness.session.transfer().transfer, PpTransfer::None);
    }

    /// `TYPE A` and `TYPE I`, and the short-circuit when the mode already
    /// matches.
    #[test]
    fn type_is_sent_only_when_the_mode_has_to_change() {
        // Binary from the initial unset state: a command goes out.
        let mut harness = Harness::new(b"file");
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine
                .nb_type(pp, io, false, FtpState::RetrType)
                .expect("TYPE I");
        });
        assert_eq!(harness.sent_text(), "TYPE I\r\n");
        assert_eq!(harness.state(), FtpState::RetrType);
        harness.reply(b"200 ok\r\n").expect("accepted");
        assert_eq!(harness.session.conn().ftpc().transfertype, b'I');

        // The same mode again: NO `TYPE` command, and the positive reply is
        // simulated -- which is what carries the machine straight on to the
        // next step. This is the clause that keeps a wildcard transfer's stream
        // byte-identical: one `TYPE A`, one `TYPE I`, and none after.
        harness.with_machine(|pp, machine, io| {
            machine
                .nb_type(pp, io, false, FtpState::RetrType)
                .expect("short-circuit");
        });
        assert_eq!(
            harness.sent_text().matches("TYPE").count(),
            1,
            "an unchanged mode sends no second TYPE"
        );
        assert_eq!(
            harness.sent_text(),
            "TYPE I\r\nSIZE file\r\nSIZE file\r\n",
            "the simulated reply took the machine on to SIZE again"
        );

        // ASCII: a command goes out again.
        let mut harness = Harness::new(b"file");
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine
                .nb_type(pp, io, true, FtpState::ListType)
                .expect("TYPE A");
        });
        assert_eq!(harness.sent_text(), "TYPE A\r\n");
        harness.reply(b"200 ok\r\n").expect("accepted");
        assert_eq!(harness.session.conn().ftpc().transfertype, b'A');
    }

    /// A `2xx` other than `200` is accepted, with the C's note about the two
    /// servers that made it necessary.
    #[test]
    fn a_226_to_type_is_accepted_with_a_remark() {
        let mut harness = Harness::new(b"dir/");
        parse_path(&mut harness).expect("parsed");
        harness.force_state(FtpState::ListType);
        harness.reply(b"226 done\r\n").expect("accepted");
        assert!(harness.client.log.info.contains(
            &"Got a 226 response code instead of the assumed 200".to_owned()
        ));
        assert_eq!(harness.state(), FtpState::List);
    }

    /// A refused `TYPE` is `CURLE_FTP_COULDNT_SET_TYPE`.
    #[test]
    fn a_refused_type_reports_the_c_code_and_text() {
        let mut harness = Harness::new(b"file");
        harness.force_state(FtpState::Type);
        let error = harness.reply(b"500 no\r\n").expect_err("refused");
        assert_eq!(error.code(), CURLcode::FtpCouldntSetType);
        assert_eq!(harness.client.log.fail, vec!["Could not set desired mode"]);
    }

    /// The trailing-digit scan of a `213` reply, with the C's tolerance for
    /// rubbish in front of the number.
    #[test]
    fn the_size_reply_parser_reads_the_trailing_digits() {
        assert_eq!(parse_size_reply(b"213 4096\r\n"), 4096);
        assert_eq!(parse_size_reply(b"213 rubbish 4096\r\n"), 4096);
        assert_eq!(parse_size_reply(b"213 0\r\n"), 0);
        // No digits at all, and no terminator at all.
        assert_eq!(parse_size_reply(b"213 unknown\r\n"), -1);
        assert_eq!(parse_size_reply(b"213 "), -1);
        assert_eq!(parse_size_reply(b"213"), -1);
    }

    /// A `SIZE` for a head request emits `Content-Length` and sets the progress
    /// size.
    #[test]
    fn a_size_reply_emits_content_length_for_an_info_request() {
        let mut harness = Harness::new(b"file");
        parse_path(&mut harness).expect("parsed");
        harness.session.transfer_mut().transfer = PpTransfer::Info;
        harness.force_state(FtpState::Size);
        harness.reply(b"213 4096\r\n").expect("read");
        assert_eq!(
            headers(&harness),
            vec!["Content-Length: 4096\r\n".to_owned()]
        );
        assert_eq!(harness.client.log.download_size, vec![4096]);
    }

    /// An unknown size emits no header at all.
    #[test]
    fn an_unknown_size_emits_no_content_length() {
        let mut harness = Harness::new(b"file");
        parse_path(&mut harness).expect("parsed");
        harness.session.transfer_mut().transfer = PpTransfer::Info;
        harness.force_state(FtpState::Size);
        harness.reply(b"213 unknown\r\n").expect("read");
        assert!(headers(&harness).is_empty());
        assert_eq!(harness.client.log.download_size, vec![-1]);
    }

    /// A `550` to `SIZE` means the file is absent -- except when the `SIZE` was
    /// a probe before an upload.
    #[test]
    fn a_550_to_size_is_fatal_except_before_an_upload() {
        let mut harness = Harness::new(b"file");
        parse_path(&mut harness).expect("parsed");
        harness.force_state(FtpState::RetrSize);
        let error = harness.reply(b"550 no such\r\n").expect_err("absent");
        assert_eq!(error.code(), CURLcode::RemoteFileNotFound);
        assert_eq!(harness.client.log.fail, vec!["The file does not exist"]);

        let mut harness = Harness::new(b"file");
        harness.client.req.upload = true;
        parse_path(&mut harness).expect("parsed");
        harness.force_state(FtpState::StorSize);
        harness
            .reply(b"550 no such\r\n")
            .expect("a probe may come back empty");
        assert_eq!(harness.client.req.resume_from, -1);
        assert_eq!(harness.state(), FtpState::Stor);
    }

    /// `REST 0` probes for range support, and `350` answers with the
    /// `Accept-ranges` pseudo-header.
    #[test]
    fn rest_zero_probes_for_ranges_and_reports_the_answer() {
        let mut harness = Harness::new(b"file");
        parse_path(&mut harness).expect("parsed");
        harness.session.transfer_mut().transfer = PpTransfer::Info;
        harness.with_machine(|pp, machine, io| {
            machine.state_rest(pp, io).expect("REST 0");
        });
        assert_eq!(harness.sent_text(), "REST 0\r\n");
        assert_eq!(harness.state(), FtpState::Rest);
        harness.reply(b"350 ready\r\n").expect("supported");
        assert_eq!(
            headers(&harness),
            vec!["Accept-ranges: bytes\r\n".to_owned()]
        );
    }

    /// A refused probe emits no header and is not an error.
    #[test]
    fn a_refused_rest_probe_is_not_an_error() {
        let mut harness = Harness::new(b"file");
        parse_path(&mut harness).expect("parsed");
        harness.session.transfer_mut().transfer = PpTransfer::Info;
        harness.force_state(FtpState::Rest);
        harness.reply(b"500 no\r\n").expect("tolerated");
        assert!(headers(&harness).is_empty());
    }

    /// A real `REST <offset>` must be answered with `350`.
    #[test]
    fn a_refused_real_rest_is_an_error() {
        let mut harness = Harness::new(b"file");
        parse_path(&mut harness).expect("parsed");
        harness.force_state(FtpState::RetrRest);
        let error = harness.reply(b"500 no\r\n").expect_err("refused");
        assert_eq!(error.code(), CURLcode::FtpCouldntUseRest);
        assert_eq!(harness.client.log.fail, vec!["Could not use REST"]);

        let mut harness = Harness::new(b"file");
        parse_path(&mut harness).expect("parsed");
        harness.force_state(FtpState::RetrRest);
        harness.reply(b"350 ready\r\n").expect("accepted");
        assert_eq!(harness.sent_text(), "RETR file\r\n");
        assert_eq!(harness.state(), FtpState::Retr);
    }

    // -- Phase 12: the LIST composition matrix -----------------------------

    /// Builds a listing command for one configuration and answers its bytes.
    fn list_command(
        path: &[u8],
        method: FileMethod,
        list_only: bool,
        custom: Option<&[u8]>,
    ) -> String {
        let mut harness = Harness::new(path);
        harness.client.req.file_method = method;
        harness.client.req.list_only = list_only;
        harness.client.opts.custom_request = custom.map(<[u8]>::to_vec);
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine.state_list(pp, io).expect("sent");
        });
        harness.sent_text()
    }

    /// The whole matrix: verb, and the one conditional space.
    #[test]
    fn the_listing_command_has_exactly_one_conditional_space() {
        // MULTICWD: the CWDs did the work, so no argument.
        assert_eq!(
            list_command(b"pub/dir/", FileMethod::MultiCwd, false, None),
            "LIST\r\n"
        );
        assert_eq!(
            list_command(b"pub/dir/", FileMethod::MultiCwd, true, None),
            "NLST\r\n"
        );
        assert_eq!(
            list_command(
                b"pub/dir/",
                FileMethod::MultiCwd,
                false,
                Some(b"LIST -a")
            ),
            "LIST -a\r\n"
        );
        // A custom command overrides list-only too.
        assert_eq!(
            list_command(
                b"pub/dir/",
                FileMethod::MultiCwd,
                true,
                Some(b"MLSD")
            ),
            "MLSD\r\n"
        );

        // NOCWD: the directory travels as the argument, with ONE space.
        assert_eq!(
            list_command(b"pub/dir/", FileMethod::NoCwd, false, None),
            "LIST pub/dir\r\n"
        );
        assert_eq!(
            list_command(b"pub/file", FileMethod::NoCwd, false, None),
            "LIST pub\r\n"
        );
        assert_eq!(
            list_command(b"pub/dir/", FileMethod::NoCwd, true, None),
            "NLST pub/dir\r\n"
        );
        // The absolute root keeps its slash rather than becoming empty.
        assert_eq!(
            list_command(b"/", FileMethod::NoCwd, false, None),
            "LIST /\r\n"
        );
        // A path with no slash at all has no argument, so no space either.
        assert_eq!(
            list_command(b"file", FileMethod::NoCwd, false, None),
            "LIST\r\n"
        );
    }

    // -- Phase 12: CURLOPT_FTPPORT parsing ----------------------------------

    /// Every form the specification admits, and the two that zero the range.
    #[test]
    fn the_ftpport_specification_parses_in_every_measured_form() {
        // A bare host or interface name.
        let parsed = parse_ftpport(b"eth0");
        assert_eq!(parsed.addr.as_deref(), Some(&b"eth0"[..]));
        assert_eq!((parsed.port_min, parsed.port_max), (0, 0));

        // A bare IPv4 address.
        let parsed = parse_ftpport(b"192.168.0.1");
        assert_eq!(parsed.addr.as_deref(), Some(&b"192.168.0.1"[..]));
        assert_eq!((parsed.port_min, parsed.port_max), (0, 0));

        // A bracketed IPv6 literal, with and without a port.
        let parsed = parse_ftpport(b"[fe80::1]");
        assert_eq!(parsed.addr.as_deref(), Some(&b"fe80::1"[..]));
        assert_eq!((parsed.port_min, parsed.port_max), (0, 0));
        let parsed = parse_ftpport(b"[fe80::1]:8000");
        assert_eq!(parsed.addr.as_deref(), Some(&b"fe80::1"[..]));
        assert_eq!((parsed.port_min, parsed.port_max), (8000, 8000));

        // A bare IPv6 literal carries no port: its colons are its own.
        let parsed = parse_ftpport(b"1080::8:800:200c:417a");
        assert_eq!(parsed.addr.as_deref(), Some(&b"1080::8:800:200c:417a"[..]));
        assert_eq!((parsed.port_min, parsed.port_max), (0, 0));

        // A lone port, with no host at all. The AAP resolves this to
        // `min == max`; see `parse_ftpport`'s own note on the C's branch.
        let parsed = parse_ftpport(b":1234");
        assert_eq!(parsed.addr, None);
        assert_eq!(
            (parsed.port_min, parsed.port_max),
            (1234, 1234),
            "a lone port sets both ends of the range"
        );

        // A host and a range.
        let parsed = parse_ftpport(b"192.168.0.1:1000-1010");
        assert_eq!(parsed.addr.as_deref(), Some(&b"192.168.0.1"[..]));
        assert_eq!((parsed.port_min, parsed.port_max), (1000, 1010));

        // A host and a lone port.
        let parsed = parse_ftpport(b"eth0:5000");
        assert_eq!(parsed.addr.as_deref(), Some(&b"eth0"[..]));
        assert_eq!((parsed.port_min, parsed.port_max), (5000, 5000));

        // An inverted range zeroes both -- the C's own correction.
        let parsed = parse_ftpport(b"eth0:2000-1000");
        assert_eq!(parsed.addr.as_deref(), Some(&b"eth0"[..]));
        assert_eq!((parsed.port_min, parsed.port_max), (0, 0));

        // The whole 16-bit range is admitted.
        let parsed = parse_ftpport(b":0-65535");
        assert_eq!((parsed.port_min, parsed.port_max), (0, 65535));

        // A one-byte specification is ignored, as the C's `strlen(...) > 1`
        // requires -- `-` is the documented "use the default" spelling.
        let parsed = parse_ftpport(b"-");
        assert_eq!(parsed.addr, None);
        assert_eq!((parsed.port_min, parsed.port_max), (0, 0));
    }

    /// A port beyond 16 bits is not a port.
    #[test]
    fn an_out_of_range_port_is_refused() {
        let parsed = parse_ftpport(b":65536");
        assert_eq!((parsed.port_min, parsed.port_max), (0, 0));
        let parsed = parse_ftpport(b":1000-70000");
        assert_eq!((parsed.port_min, parsed.port_max), (0, 0));
    }

    // -- Phase 12: EPRT and PORT, byte for byte -----------------------------

    /// RFC 2428's two examples, which the C quotes and this reproduces.
    #[test]
    fn the_eprt_command_is_the_rfc_2428_example() {
        let v4 = IpAddr::V4(Ipv4Addr::new(132, 235, 1, 2));
        assert_eq!(
            eprt_command("132.235.1.2", v4, 6275),
            b"EPRT |1|132.235.1.2|6275|".to_vec()
        );
        let v6 = IpAddr::V6("1080::8:800:200C:417A".parse().expect("literal"));
        assert_eq!(
            eprt_command("1080::8:800:200C:417A", v6, 5282),
            b"EPRT |2|1080::8:800:200C:417A|5282|".to_vec()
        );
        assert_eq!(eprt_family(v4), 1);
        assert_eq!(eprt_family(v6), 2);
    }

    /// The `PORT` translation: dots become commas, then the two port bytes.
    #[test]
    fn the_port_command_translates_dots_to_commas() {
        assert_eq!(
            port_command("132.235.1.2", 6275),
            b"PORT 132,235,1,2,24,131".to_vec()
        );
        // `tests/data/test101`'s exact command.
        assert_eq!(
            port_command("127.0.0.1", 62420),
            b"PORT 127,0,0,1,243,212".to_vec()
        );
        // The two edges of the port range.
        assert_eq!(port_command("0.0.0.0", 0), b"PORT 0,0,0,0,0,0".to_vec());
        assert_eq!(
            port_command("255.255.255.255", 65535),
            b"PORT 255,255,255,255,255,255".to_vec()
        );
    }

    /// Addresses are formatted only by the module that owns the conversion.
    #[test]
    fn addresses_are_printed_through_the_inet_helpers() {
        assert_eq!(
            printable_address(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            "10.0.0.1"
        );
        let v6 = IpAddr::V6(Ipv6Addr::new(
            0x1080, 0, 0, 0, 8, 0x800, 0x200c, 0x417a,
        ));
        assert_eq!(
            printable_address(v6),
            ntop6(
                &Ipv6Addr::new(0x1080, 0, 0, 0, 8, 0x800, 0x200c, 0x417a)
                    .octets()
            )
        );
        assert!(
            !code_only().contains("to_string()) // IpAddr"),
            "no standard Display formatting of an address reaches the wire"
        );
    }

    // -- Phase 12: the active-mode dialogue ---------------------------------

    /// Puts a harness into active mode with a fixed listener port.
    fn active_harness(port: u16) -> Harness {
        let mut harness = Harness::new(b"file");
        harness.client.opts.use_port = true;
        harness.client.opts.ftpport = Some(b"127.0.0.1".to_vec());
        harness.seams.borrow_mut().bind_script.push_back(Ok(port));
        harness
    }

    /// `EPRT` goes out first, with the address the specification named.
    #[test]
    fn active_mode_sends_eprt_with_the_requested_address() {
        let mut harness = active_harness(62420);
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine
                .state_use_port(pp, io, FtpPortCmd::Eprt)
                .expect("the listener is scripted");
        });
        assert_eq!(harness.sent_text(), "EPRT |1|127.0.0.1|62420|\r\n");
        assert_eq!(harness.state(), FtpState::Port);
        assert_eq!(harness.session.conn().ftpc().count1, 0);
        let seams = harness.seams.borrow();
        assert_eq!(seams.opened.len(), 1);
        assert_eq!(seams.listens, 1);
        assert_eq!(seams.installs, 1);
    }

    /// A `2xx` reply ends the command phase and reports the C's info line.
    #[test]
    fn a_positive_eprt_reply_ends_the_do_phase() {
        let mut harness = active_harness(62420);
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine
                .state_use_port(pp, io, FtpPortCmd::Eprt)
                .expect("sent");
        });
        harness
            .reply(b"200 EPRT command successful\r\n")
            .expect("ok");
        assert_eq!(harness.state(), FtpState::Stop);
        assert!(harness
            .client
            .log
            .info
            .contains(&"Connect data stream actively".to_owned()));
        assert!(harness.client.req.do_more, "DO_MORE was requested");
    }

    /// Any `2xx` is accepted, not only `200` -- *"be more permissive here to
    /// tolerate deviant servers"*.
    #[test]
    fn a_deviant_but_positive_eprt_reply_is_accepted() {
        let mut harness = active_harness(62420);
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine
                .state_use_port(pp, io, FtpPortCmd::Eprt)
                .expect("sent");
        });
        harness.reply(b"250 fine\r\n").expect("accepted");
        assert_eq!(harness.state(), FtpState::Stop);
    }

    /// A refused `EPRT` disables it and falls back to `PORT`.
    #[test]
    fn a_refused_eprt_disables_it_and_tries_port() {
        let mut harness = active_harness(62420);
        parse_path(&mut harness).expect("parsed");
        harness.seams.borrow_mut().bind_script.push_back(Ok(62420));
        harness.with_machine(|pp, machine, io| {
            machine
                .state_use_port(pp, io, FtpPortCmd::Eprt)
                .expect("sent");
        });
        harness
            .reply(b"500 unknown command\r\n")
            .expect("fall back");
        assert_eq!(
            harness.sent_text(),
            "EPRT |1|127.0.0.1|62420|\r\nPORT 127,0,0,1,243,212\r\n"
        );
        assert!(!harness.client.req.use_eprt, "EPRT is disabled");
        assert!(harness
            .client
            .log
            .info
            .contains(&"disabling EPRT usage".to_owned()));
        assert_eq!(harness.session.conn().ftpc().count1, 1);
    }

    /// Running out of commands is `CURLE_FTP_PORT_FAILED`.
    #[test]
    fn a_refused_port_after_a_refused_eprt_is_fatal() {
        let mut harness = active_harness(62420);
        parse_path(&mut harness).expect("parsed");
        harness.seams.borrow_mut().bind_script.push_back(Ok(62420));
        harness.with_machine(|pp, machine, io| {
            machine
                .state_use_port(pp, io, FtpPortCmd::Eprt)
                .expect("sent");
        });
        harness.reply(b"500 no EPRT\r\n").expect("fall back");
        let error =
            harness.reply(b"500 no PORT\r\n").expect_err("out of ideas");
        assert_eq!(error.code(), CURLcode::FtpPortFailed);
        assert_eq!(harness.client.log.fail, vec!["Failed to do PORT"]);
    }

    /// With `EPRT` already disabled the engine starts at `PORT`.
    #[test]
    fn active_mode_starts_at_port_when_eprt_is_disabled() {
        let mut harness = active_harness(62420);
        harness.client.req.use_eprt = false;
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine
                .state_use_port(pp, io, FtpPortCmd::Eprt)
                .expect("sent");
        });
        assert_eq!(harness.sent_text(), "PORT 127,0,0,1,243,212\r\n");
    }

    /// `PORT` is impossible for anything but IPv4, so an IPv6 control
    /// connection forces `EPRT` back on even when it was disabled.
    #[test]
    fn an_ipv6_control_connection_forces_eprt() {
        let mut harness = Harness::new(b"file");
        harness.client.opts.use_port = true;
        harness.client.opts.ftpport = Some(b"[fe80::1]".to_vec());
        harness.client.req.use_eprt = false;
        harness.client.req.ipv6 = true;
        {
            let mut seams = harness.seams.borrow_mut();
            seams.family = AddressFamily::Inet6;
            seams.local_addr = Some(IpAddr::V6("fe80::1".parse().expect("ok")));
            seams.resolve_answer =
                Ok(vec![IpAddr::V6("fe80::1".parse().expect("ok"))]);
            seams.bind_script.push_back(Ok(5282));
        }
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine
                .state_use_port(pp, io, FtpPortCmd::Eprt)
                .expect("sent");
        });
        assert_eq!(harness.sent_text(), "EPRT |2|fe80::1|5282|\r\n");
        assert!(
            harness.client.req.use_eprt,
            "EPRT is re-enabled for an IPv6 control connection"
        );
    }

    /// With no address in the specification the control connection's own local
    /// address is used, formatted through the inet helpers.
    #[test]
    fn active_mode_without_an_address_uses_the_control_connections_own() {
        let mut harness = Harness::new(b"file");
        harness.client.opts.use_port = true;
        harness.client.opts.ftpport = Some(b":62420".to_vec());
        {
            let mut seams = harness.seams.borrow_mut();
            seams.local_addr = Some(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)));
            // `getsockname`'s answer is printed and then handed to the resolver
            // like any other host string, so the seam answers with it.
            seams.resolve_answer =
                Ok(vec![IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))]);
            seams.bind_script.push_back(Ok(62420));
        }
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine
                .state_use_port(pp, io, FtpPortCmd::Eprt)
                .expect("sent");
        });
        assert_eq!(harness.sent_text(), "EPRT |1|10.1.2.3|62420|\r\n");
        assert_eq!(
            harness.seams.borrow().resolved,
            vec![(b"10.1.2.3".to_vec(), 0)],
            "the printed local address is what is resolved"
        );
        assert_eq!(
            harness.seams.borrow().binds,
            vec![(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)), 62420)]
        );
    }

    /// `if2ip`'s three answers, each with the behaviour the C gives it.
    #[test]
    fn the_three_if2ip_outcomes_are_handled_as_the_c_handles_them() {
        // FOUND: the resolved address is used and no name is resolved.
        let mut harness = Harness::new(b"file");
        harness.client.opts.use_port = true;
        harness.client.opts.ftpport = Some(b"eth0".to_vec());
        {
            let mut seams = harness.seams.borrow_mut();
            seams.if2ip = Some(If2IpResult::Found("10.9.8.7".to_owned()));
            // The C's comment on this arm is *"use the address as host name"*,
            // so the address it found still goes through the resolver.
            seams.resolve_answer =
                Ok(vec![IpAddr::V4(Ipv4Addr::new(10, 9, 8, 7))]);
            seams.bind_script.push_back(Ok(1234));
        }
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine
                .state_use_port(pp, io, FtpPortCmd::Eprt)
                .expect("sent");
        });
        assert_eq!(harness.sent_text(), "EPRT |1|10.9.8.7|1234|\r\n");
        assert_eq!(harness.seams.borrow().if2ip_calls, vec![b"eth0".to_vec()]);
        assert_eq!(
            harness.seams.borrow().resolved,
            vec![(b"10.9.8.7".to_vec(), 0)],
            "the found address is handed on as a host name, as the C's comment \
             says"
        );

        // NOT_FOUND: the bytes are treated as a host name and resolved.
        let mut harness = Harness::new(b"file");
        harness.client.opts.use_port = true;
        harness.client.opts.ftpport = Some(b"ftp.example.com".to_vec());
        {
            let mut seams = harness.seams.borrow_mut();
            seams.if2ip = Some(If2IpResult::NotFound);
            seams.resolve_answer =
                Ok(vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5))]);
            seams.bind_script.push_back(Ok(1234));
        }
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine
                .state_use_port(pp, io, FtpPortCmd::Eprt)
                .expect("sent");
        });
        assert_eq!(harness.sent_text(), "EPRT |1|203.0.113.5|1234|\r\n");
        assert_eq!(
            harness.seams.borrow().resolved,
            vec![(b"ftp.example.com".to_vec(), 0)]
        );

        // AF_NOT_SUPPORTED: active mode is abandoned.
        let mut harness = Harness::new(b"file");
        harness.client.opts.use_port = true;
        harness.client.opts.ftpport = Some(b"eth0".to_vec());
        harness.seams.borrow_mut().if2ip = Some(If2IpResult::AfNotSupported);
        parse_path(&mut harness).expect("parsed");
        let error = harness.with_machine(|pp, machine, io| {
            machine
                .state_use_port(pp, io, FtpPortCmd::Eprt)
                .expect_err("the family is impossible")
        });
        assert_eq!(error.code(), CURLcode::FtpPortFailed);
    }

    /// A bind that reports the address is not local falls back to the control
    /// connection's own, once.
    #[test]
    fn a_non_local_bind_address_falls_back_to_the_control_address() {
        let mut harness = Harness::new(b"file");
        harness.client.opts.use_port = true;
        harness.client.opts.ftpport = Some(b"203.0.113.9".to_vec());
        {
            let mut seams = harness.seams.borrow_mut();
            seams.local_addr = Some(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)));
            // The specification names an address, and the C hands it to the
            // resolver as a host name whatever it looks like -- see
            // `use_port_inner`'s `host` -- so the seam has to answer with it.
            seams.resolve_answer =
                Ok(vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))]);
            seams.bind_script.push_back(Err(SockFailure {
                errno: 99,
                kind: SockFailureKind::AddrNotAvail,
                message: "Cannot assign requested address".to_owned(),
            }));
            seams.bind_script.push_back(Ok(1234));
        }
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine
                .state_use_port(pp, io, FtpPortCmd::Eprt)
                .expect("the fallback binds");
        });
        let binds = harness.seams.borrow().binds.clone();
        assert_eq!(
            binds,
            vec![
                (IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 0),
                (IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)), 0),
            ],
            "the requested address is tried first, then the control address"
        );
        assert!(harness
            .client
            .log
            .info
            .iter()
            .any(|line| line
                .contains("bind(port=0) on non-local address failed")));
    }

    /// An address already in use walks the port range.
    #[test]
    fn an_address_in_use_walks_the_requested_port_range() {
        let mut harness = Harness::new(b"file");
        harness.client.opts.use_port = true;
        harness.client.opts.ftpport = Some(b"127.0.0.1:1000-1002".to_vec());
        {
            let mut seams = harness.seams.borrow_mut();
            for _ in 0..2 {
                seams.bind_script.push_back(Err(SockFailure {
                    errno: 98,
                    kind: SockFailureKind::AddrInUse,
                    message: "Address already in use".to_owned(),
                }));
            }
            seams.bind_script.push_back(Ok(1002));
        }
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine
                .state_use_port(pp, io, FtpPortCmd::Eprt)
                .expect("the third port binds");
        });
        let ports: Vec<u16> = harness
            .seams
            .borrow()
            .binds
            .iter()
            .map(|&(_, port)| port)
            .collect();
        assert_eq!(ports, vec![1000, 1001, 1002]);
        assert_eq!(harness.sent_text(), "EPRT |1|127.0.0.1|1002|\r\n");
    }

    /// Running off the end of the range is the C's *"ran out of ports"*.
    #[test]
    fn running_out_of_ports_reports_the_c_text() {
        let mut harness = Harness::new(b"file");
        harness.client.opts.use_port = true;
        harness.client.opts.ftpport = Some(b"127.0.0.1:1000-1001".to_vec());
        {
            let mut seams = harness.seams.borrow_mut();
            for _ in 0..2 {
                seams.bind_script.push_back(Err(SockFailure {
                    errno: 98,
                    kind: SockFailureKind::AddrInUse,
                    message: "Address already in use".to_owned(),
                }));
            }
        }
        parse_path(&mut harness).expect("parsed");
        let error = harness.with_machine(|pp, machine, io| {
            machine
                .state_use_port(pp, io, FtpPortCmd::Eprt)
                .expect_err("no port is free")
        });
        assert_eq!(error.code(), CURLcode::FtpPortFailed);
        assert_eq!(
            harness.client.log.fail,
            vec!["bind() failed, ran out of ports"]
        );
    }

    /// The accept timer takes the configured value, or the default of 60
    /// seconds, on the timer the trace module owns.
    #[test]
    fn the_accept_timer_uses_the_option_or_the_sixty_second_default() {
        let mut harness = active_harness(62420);
        harness.client.opts.accept_timeout_ms = 7_500;
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine
                .state_use_port(pp, io, FtpPortCmd::Eprt)
                .expect("sent");
        });
        assert_eq!(
            harness.client.log.expiries,
            vec![(7_500, TimerId::FtpAccept)]
        );

        let mut harness = active_harness(62420);
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine
                .state_use_port(pp, io, FtpPortCmd::Eprt)
                .expect("sent");
        });
        assert_eq!(
            harness.client.log.expiries,
            vec![(DEFAULT_ACCEPT_TIMEOUT, TimerId::FtpAccept)]
        );
        assert_eq!(DEFAULT_ACCEPT_TIMEOUT, 60_000);
    }

    // -- Phase 12: passive mode ---------------------------------------------

    /// The `EPSV` reply's delimiter grammar.
    #[test]
    fn the_epsv_reply_parser_follows_the_delimiter_grammar() {
        assert_eq!(
            parse_epsv_reply(b"Entering Extended Passive Mode (|||8888|)\r\n"),
            EpsvReply::Port(8888)
        );
        // Any delimiter the server chose, repeated consistently.
        assert_eq!(
            parse_epsv_reply(b"ok (!!!1234!)\r\n"),
            EpsvReply::Port(1234)
        );
        // The delimiters must agree.
        assert_eq!(parse_epsv_reply(b"ok (|!|1234|)\r\n"), EpsvReply::Weird);
        // No opening bracket at all.
        assert_eq!(parse_epsv_reply(b"ok 8888\r\n"), EpsvReply::Weird);
        // A number that is not a port.
        assert_eq!(
            parse_epsv_reply(b"ok (|||70000|)\r\n"),
            EpsvReply::IllegalPort
        );
        // The three delimiters agreed and a digit followed, so the C is past
        // the shape test and into the number: a missing TERMINATING delimiter
        // is therefore the illegal-port branch, not the weird-format one
        // (`lib/ftp.c:1943-1946`).
        assert_eq!(
            parse_epsv_reply(b"ok (|||1234)\r\n"),
            EpsvReply::IllegalPort
        );
        // A non-digit where the number should start fails the SHAPE test.
        assert_eq!(parse_epsv_reply(b"ok (|||x|)\r\n"), EpsvReply::Weird);
        // A reply that ends inside the delimiters.
        assert_eq!(parse_epsv_reply(b"ok (||"), EpsvReply::Weird);
        assert_eq!(
            EPSV_ILLEGAL_PORT_MESSAGE,
            "Illegal port number in EPSV reply"
        );
        assert_eq!(EPSV_WEIRD_MESSAGE, "Weirdly formatted EPSV reply");
    }

    /// The `227` reply's loose six-number scan.
    #[test]
    fn the_pasv_reply_parser_finds_six_numbers_in_any_prose() {
        assert_eq!(
            match_pasv_6nums(b"127,0,0,1,243,212"),
            Some([127, 0, 0, 1, 243, 212])
        );
        assert_eq!(
            parse_pasv_reply(b"Entering Passive Mode (127,0,0,1,243,212)\r\n"),
            Some([127, 0, 0, 1, 243, 212])
        );
        assert_eq!(
            parse_pasv_reply(b"=127,0,0,1,243,212 whatever\r\n"),
            Some([127, 0, 0, 1, 243, 212])
        );
        // Each number must be a byte.
        assert_eq!(parse_pasv_reply(b"(127,0,0,1,256,212)\r\n"), None);
        // Five numbers is not six.
        assert_eq!(parse_pasv_reply(b"(127,0,0,1,243)\r\n"), None);
        assert_eq!(parse_pasv_reply(b"no numbers here\r\n"), None);
        assert_eq!(PASV_227_MESSAGE, "Could not interpret the 227-response");
    }

    /// The endpoint a `227` names: the four address bytes and `(p1<<8)+p2`.
    #[test]
    fn the_pasv_endpoint_is_built_from_the_six_numbers() {
        assert_eq!(
            pasv_endpoint([127, 0, 0, 1, 243, 212]),
            ("127.0.0.1".to_owned(), 62420)
        );
        assert_eq!(
            pasv_endpoint([10, 20, 30, 40, 0, 21]),
            ("10.20.30.40".to_owned(), 21)
        );
        assert_eq!(
            pasv_endpoint([1, 2, 3, 4, 255, 255]),
            ("1.2.3.4".to_owned(), 65535)
        );
    }

    /// `EPSV` goes out first, with the C's exact info line.
    #[test]
    fn passive_mode_sends_epsv_first() {
        let mut harness = Harness::new(b"file");
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine.state_use_pasv(pp, io).expect("sent");
        });
        assert_eq!(harness.sent_text(), "EPSV\r\n");
        assert_eq!(harness.state(), FtpState::Pasv);
        assert_eq!(harness.session.conn().ftpc().count1, 0);
        assert!(harness
            .client
            .log
            .info
            .contains(&PASSIVE_INFO_MESSAGE.to_owned()));
        assert_eq!(PASSIVE_INFO_MESSAGE, "Connect data stream passively");
    }

    /// With `EPSV` disabled the engine sends `PASV`.
    #[test]
    fn passive_mode_sends_pasv_when_epsv_is_disabled() {
        let mut harness = Harness::new(b"file");
        harness.client.req.use_epsv = false;
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine.state_use_pasv(pp, io).expect("sent");
        });
        assert_eq!(harness.sent_text(), "PASV\r\n");
        assert_eq!(harness.session.conn().ftpc().count1, 1);
    }

    /// On IPv6 a disabled `EPSV` is ignored and re-enabled: `PASV` cannot carry
    /// an IPv6 address.
    #[test]
    fn an_ipv6_connection_re_enables_epsv() {
        let mut harness = Harness::new(b"file");
        harness.client.req.use_epsv = false;
        harness.client.req.ipv6 = true;
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine.state_use_pasv(pp, io).expect("sent");
        });
        assert_eq!(harness.sent_text(), "EPSV\r\n");
        assert!(harness.client.req.use_epsv);
    }

    /// A `229` sets the secondary connection up at the control address.
    #[test]
    fn a_229_sets_the_data_connection_up_at_the_control_address() {
        let mut harness = Harness::new(b"file");
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine.state_use_pasv(pp, io).expect("sent");
        });
        harness
            .reply(b"229 Entering Extended Passive Mode (|||8888|)\r\n")
            .expect("parsed");
        assert_eq!(harness.state(), FtpState::Stop);
        assert!(harness.client.req.do_more);
        assert_eq!(
            harness.seams.borrow().secondary,
            vec![(b"127.0.0.1".to_vec(), 8888, false)]
        );
        assert_eq!(harness.client.req.secondary_port, 8888);
    }

    /// A `227` sets it up at the address the reply named.
    #[test]
    fn a_227_sets_the_data_connection_up_at_the_replys_address() {
        let mut harness = Harness::new(b"file");
        harness.client.req.use_epsv = false;
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine.state_use_pasv(pp, io).expect("sent");
        });
        harness
            .reply(b"227 Entering Passive Mode (10,20,30,40,243,212)\r\n")
            .expect("parsed");
        assert_eq!(
            harness.seams.borrow().secondary,
            vec![(b"10.20.30.40".to_vec(), 62420, false)]
        );
    }

    /// `CURLOPT_FTP_SKIP_PASV_IP` ignores the reply's address.
    #[test]
    fn skip_pasv_ip_uses_the_control_address_instead() {
        let mut harness = Harness::new(b"file");
        harness.client.req.use_epsv = false;
        harness.client.opts.skip_ip = true;
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine.state_use_pasv(pp, io).expect("sent");
        });
        harness
            .reply(b"227 Entering Passive Mode (10,20,30,40,243,212)\r\n")
            .expect("parsed");
        assert_eq!(
            harness.seams.borrow().secondary,
            vec![(b"127.0.0.1".to_vec(), 62420, false)]
        );
        assert!(harness
            .client
            .log
            .info
            .iter()
            .any(|line| line
                .contains("Skip 10.20.30.40 for data connection, reuse")));
    }

    /// A malformed `229` and a malformed `227` each report their own text.
    #[test]
    fn a_malformed_passive_reply_reports_its_own_text() {
        let mut harness = Harness::new(b"file");
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine.state_use_pasv(pp, io).expect("sent");
        });
        let error = harness
            .reply(b"229 nonsense\r\n")
            .expect_err("no delimiters");
        assert_eq!(error.code(), CURLcode::FtpWeirdPasvReply);
        assert_eq!(harness.client.log.fail, vec![EPSV_WEIRD_MESSAGE]);

        let mut harness = Harness::new(b"file");
        harness.client.req.use_epsv = false;
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine.state_use_pasv(pp, io).expect("sent");
        });
        let error = harness
            .reply(b"227 nonsense\r\n")
            .expect_err("no six numbers");
        assert_eq!(error.code(), CURLcode::FtpWeird227Format);
        assert_eq!(harness.client.log.fail, vec![PASV_227_MESSAGE]);
    }

    /// A `229` with an out-of-range port reports the illegal-port text.
    #[test]
    fn an_illegal_epsv_port_reports_its_own_text() {
        let mut harness = Harness::new(b"file");
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine.state_use_pasv(pp, io).expect("sent");
        });
        let error = harness
            .reply(b"229 (|||99999|)\r\n")
            .expect_err("not a port");
        assert_eq!(error.code(), CURLcode::FtpWeirdPasvReply);
        assert_eq!(harness.client.log.fail, vec![EPSV_ILLEGAL_PORT_MESSAGE]);
    }

    /// A refused `EPSV` falls back to a literal `PASV` -- `tests/data/test102`
    /// and `test105` both pin the pair.
    #[test]
    fn a_refused_epsv_falls_back_to_pasv() {
        let mut harness = Harness::new(b"file");
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine.state_use_pasv(pp, io).expect("sent");
        });
        harness
            .reply(b"500 unknown command\r\n")
            .expect("fall back");
        assert_eq!(
            harness.sent_text(),
            "EPSV\r\nPASV\r\n",
            "tests/data/test102's EPSV-then-PASV pair"
        );
        assert!(!harness.client.req.use_epsv);
        assert!(harness
            .client
            .log
            .info
            .contains(&"Failed EPSV attempt. Disabling EPSV".to_owned()));
    }

    /// On IPv6 with no tunnel there is nothing to fall back to.
    #[test]
    fn a_refused_epsv_on_ipv6_cannot_fall_back() {
        let mut harness = Harness::new(b"file");
        harness.client.req.ipv6 = true;
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine.state_use_pasv(pp, io).expect("sent");
        });
        let error = harness
            .reply(b"500 unknown command\r\n")
            .expect_err("nothing to fall back to");
        assert_eq!(
            error.code(),
            CURLcode::WeirdServerReply,
            "`ftp_epsv_disable` reports CURLE_WEIRD_SERVER_REPLY when it cannot \
             disable EPSV (`lib/ftp.c:1851-1853`)"
        );
        assert_eq!(
            harness.client.log.fail,
            vec!["Failed EPSV attempt, exiting"],
            "the C reports this one with `failf`, not `infof`"
        );
    }

    /// A resolver failure on the data host is reported as such.
    #[test]
    fn a_data_host_that_cannot_be_resolved_is_reported() {
        let mut harness = Harness::new(b"file");
        harness.client.req.use_epsv = false;
        harness.seams.borrow_mut().resolve_answer =
            Err(CURLcode::CouldntResolveHost);
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine.state_use_pasv(pp, io).expect("sent");
        });
        let error = harness
            .reply(b"227 Entering Passive Mode (10,20,30,40,243,212)\r\n")
            .expect_err("unresolvable");
        assert_eq!(
            error.code(),
            CURLcode::FtpCantGetHost,
            "a direct data connection reports CURLE_FTP_CANT_GET_HOST, not the \
             resolver's own code (`lib/ftp.c:2055-2059`)"
        );
        assert!(harness
            .client
            .log
            .fail
            .iter()
            .any(|line| line.starts_with("cannot resolve new host")));
    }

    /// An unexpected code to `EPSV` or `PASV` reports the C's `%03d` text.
    #[test]
    fn a_bad_passive_response_code_reports_the_code() {
        let mut harness = Harness::new(b"file");
        harness.client.req.use_epsv = false;
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine.state_use_pasv(pp, io).expect("sent");
        });
        let error = harness.reply(b"550 no\r\n").expect_err("refused");
        assert_eq!(error.code(), CURLcode::FtpWeirdPasvReply);
        assert_eq!(
            harness.client.log.fail,
            vec!["Bad PASV/EPSV response: 550"]
        );
    }

    /// A data channel that wants TLS asks `conn/` for it, and never this
    /// module's own TLS knowledge -- there is none.
    #[test]
    fn a_protected_data_channel_asks_conn_for_the_filter() {
        let mut harness = Harness::new(b"file");
        harness.client.req.data_ssl = true;
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine.state_use_pasv(pp, io).expect("sent");
        });
        harness
            .reply(b"229 Entering Extended Passive Mode (|||8888|)\r\n")
            .expect("parsed");
        assert_eq!(
            harness.seams.borrow().secondary,
            vec![(b"127.0.0.1".to_vec(), 8888, true)],
            "the secondary chain is set up with TLS enabled"
        );
    }

    // -- Phase 12: AUTH, PBSZ, PROT and CCC ---------------------------------

    /// `CURLFTPAUTH_DEFAULT` tries `SSL` and then `TLS`.
    #[test]
    fn the_default_auth_order_is_ssl_then_tls() {
        let mut harness = Harness::new(b"file");
        harness.client.opts.use_ssl = UseSsl::All;
        harness.force_state(FtpState::Wait220);
        harness.reply(b"220 ready\r\n").expect("greeting");
        assert_eq!(harness.sent_text(), "AUTH SSL\r\n");
        harness.reply(b"500 unknown\r\n").expect("retry");
        assert_eq!(
            harness.sent_text(),
            "AUTH SSL\r\nAUTH TLS\r\n",
            "tests/data/test402's exact pair"
        );
        assert_eq!(harness.state(), FtpState::Auth);
    }

    /// `CURLFTPAUTH_TLS` tries `TLS` and then `SSL`.
    #[test]
    fn the_tls_first_auth_order_is_tls_then_ssl() {
        let mut harness = Harness::new(b"file");
        harness.client.opts.use_ssl = UseSsl::All;
        harness.client.opts.ftpsslauth = FtpSslAuth(2);
        harness.force_state(FtpState::Wait220);
        harness.reply(b"220 ready\r\n").expect("greeting");
        harness.reply(b"500 unknown\r\n").expect("retry");
        assert_eq!(harness.sent_text(), "AUTH TLS\r\nAUTH SSL\r\n");
    }

    /// `CURLFTPAUTH_SSL` behaves as the default does.
    #[test]
    fn the_ssl_first_auth_order_matches_the_default() {
        let mut harness = Harness::new(b"file");
        harness.client.opts.use_ssl = UseSsl::All;
        harness.client.opts.ftpsslauth = FtpSslAuth(1);
        harness.force_state(FtpState::Wait220);
        harness.reply(b"220 ready\r\n").expect("greeting");
        assert_eq!(harness.sent_text(), "AUTH SSL\r\n");
    }

    /// An unrecognised `CURLOPT_FTPSSLAUTH` is refused with the C's exact text.
    #[test]
    fn an_unknown_ftpsslauth_is_an_unknown_option() {
        let mut harness = Harness::new(b"file");
        harness.client.opts.use_ssl = UseSsl::All;
        harness.client.opts.ftpsslauth = FtpSslAuth(7);
        harness.force_state(FtpState::Wait220);
        let error = harness.reply(b"220 ready\r\n").expect_err("refused");
        assert_eq!(error.code(), CURLcode::UnknownOption);
        assert_eq!(
            harness.client.log.fail,
            vec!["unsupported parameter to CURLOPT_FTPSSLAUTH: 7"]
        );
    }

    /// Only one retry: a second refusal gives up.
    #[test]
    fn auth_retries_exactly_once() {
        let mut harness = Harness::new(b"file");
        harness.client.opts.use_ssl = UseSsl::All;
        harness.force_state(FtpState::Wait220);
        harness.reply(b"220 ready\r\n").expect("greeting");
        harness.reply(b"500 no\r\n").expect("one retry");
        let error = harness.reply(b"500 no\r\n").expect_err("no second retry");
        assert_eq!(error.code(), CURLcode::UseSslFailed);
        assert_eq!(harness.sent_text(), "AUTH SSL\r\nAUTH TLS\r\n");
    }

    /// With TLS merely attempted, both refusals are tolerated and the login
    /// continues in the clear.
    #[test]
    fn a_try_level_auth_failure_continues_in_the_clear() {
        let mut harness = Harness::new(b"file");
        harness.client.opts.use_ssl = UseSsl::Try;
        harness.force_state(FtpState::Wait220);
        harness.reply(b"220 ready\r\n").expect("greeting");
        assert_eq!(harness.sent_text(), "AUTH SSL\r\n");
        harness.reply(b"500 no\r\n").expect("one retry");
        harness.reply(b"500 no\r\n").expect("tolerated");
        assert_eq!(
            harness.sent_text(),
            "AUTH SSL\r\nAUTH TLS\r\nUSER anonymous\r\n"
        );
        assert!(!harness.client.req.control_ssl);
    }

    /// `234` installs the control-channel filter through `conn/`, then logs in.
    #[test]
    fn a_234_installs_the_control_filter_and_logs_in() {
        let mut harness = Harness::new(b"file");
        harness.client.opts.use_ssl = UseSsl::All;
        harness.force_state(FtpState::Wait220);
        harness.reply(b"220 ready\r\n").expect("greeting");
        harness.reply(b"234 proceed\r\n").expect("negotiated");
        assert_eq!(
            harness.seams.borrow().tls_added,
            vec![SocketIndex::First],
            "the filter is asked of conn/, on the control socket"
        );
        assert!(harness.client.req.control_ssl);
        assert!(!harness.client.req.data_ssl, "PROT has not run yet");
        assert_eq!(harness.sent_text(), "AUTH SSL\r\nUSER anonymous\r\n");
    }

    /// `334` is accepted on the same terms as `234`.
    #[test]
    fn a_334_is_accepted_too() {
        let mut harness = Harness::new(b"file");
        harness.client.opts.use_ssl = UseSsl::All;
        harness.force_state(FtpState::Auth);
        harness.reply(b"334 security data\r\n").expect("negotiated");
        assert_eq!(harness.seams.borrow().tls_added, vec![SocketIndex::First]);
    }

    /// A filter `conn/` cannot supply is `CURLE_USE_SSL_FAILED`.
    #[test]
    fn a_filter_that_cannot_be_installed_is_a_use_ssl_failure() {
        let mut harness = Harness::new(b"file");
        harness.client.opts.use_ssl = UseSsl::All;
        harness.seams.borrow_mut().tls_add_fails =
            Some(CURLcode::SslConnectError);
        harness.force_state(FtpState::Auth);
        let error = harness.reply(b"234 proceed\r\n").expect_err("no filter");
        assert_eq!(error.code(), CURLcode::UseSslFailed);
    }

    /// A pipelined reply to `AUTH` is refused outright.
    #[test]
    fn a_pipelined_reply_to_auth_is_refused() {
        let mut harness = Harness::new(b"file");
        harness.client.opts.use_ssl = UseSsl::All;
        harness.force_state(FtpState::Auth);
        // Two replies in one read: the second is the overflow the C forbids.
        let error = harness
            .reply(b"234 proceed\r\n230 and logged in\r\n")
            .expect_err("pipelining is forbidden here");
        assert_eq!(error.code(), CURLcode::WeirdServerReply);
    }

    /// After a secure login: `PBSZ 0`, then `PROT P` for a protected data
    /// channel -- and `PROT C` for a control-only one, as
    /// `tests/data/test400` pins.
    #[test]
    fn a_secure_login_sends_pbsz_zero_and_then_prot() {
        for (level, letter, data_ssl) in
            [(UseSsl::Control, 'C', false), (UseSsl::All, 'P', true)]
        {
            let mut harness = Harness::new(b"file");
            harness.client.opts.use_ssl = level;
            harness.client.req.control_ssl = true;
            harness.force_state(FtpState::Pass);
            harness.reply(b"230 logged in\r\n").expect("logged in");
            assert_eq!(harness.sent_text(), "PBSZ 0\r\n");
            assert_eq!(harness.state(), FtpState::Pbsz);
            harness.reply(b"200 ok\r\n").expect("PBSZ accepted");
            assert_eq!(
                harness.sent_text(),
                format!("PBSZ 0\r\nPROT {letter}\r\n")
            );
            assert_eq!(harness.state(), FtpState::Prot);
            harness.reply(b"200 ok\r\n").expect("PROT accepted");
            assert_eq!(
                harness.client.req.data_ssl, data_ssl,
                "data protection for {level:?}"
            );
            assert_eq!(harness.state(), FtpState::Pwd);
        }
    }

    /// A refused `PROT` is fatal when protection was required.
    #[test]
    fn a_refused_prot_is_fatal_when_protection_was_required() {
        let mut harness = Harness::new(b"file");
        harness.client.opts.use_ssl = UseSsl::All;
        harness.client.req.control_ssl = true;
        harness.force_state(FtpState::Prot);
        let error = harness.reply(b"500 rejected\r\n").expect_err("required");
        assert_eq!(error.code(), CURLcode::UseSslFailed);
        assert!(!harness.client.req.data_ssl);
    }

    /// A refused `PROT` is tolerated at the control-only level.
    #[test]
    fn a_refused_prot_is_tolerated_at_the_control_level() {
        let mut harness = Harness::new(b"file");
        harness.client.opts.use_ssl = UseSsl::Control;
        harness.client.req.control_ssl = true;
        harness.force_state(FtpState::Prot);
        harness.reply(b"500 rejected\r\n").expect("tolerated");
        assert_eq!(harness.state(), FtpState::Pwd);
        assert!(!harness.client.req.data_ssl);
    }

    /// `CURLOPT_FTP_SSL_CCC` sends the literal `CCC` and then asks `conn/` to
    /// take the control filter away -- `tests/data/test403`'s dialogue.
    #[test]
    fn ccc_clears_the_command_channel_through_conn() {
        for (mode, send_shutdown) in
            [(CccMode::Passive, false), (CccMode::Active, true)]
        {
            let mut harness = Harness::new(b"file");
            harness.client.opts.use_ssl = UseSsl::Control;
            harness.client.opts.ccc = mode;
            harness.client.req.control_ssl = true;
            harness.force_state(FtpState::Pbsz);
            harness.reply(b"200 ok\r\n").expect("PROT next");
            assert_eq!(harness.sent_text(), "PROT C\r\n");
            harness.reply(b"200 ok\r\n").expect("CCC next");
            assert_eq!(harness.sent_text(), "PROT C\r\nCCC\r\n");
            assert_eq!(harness.state(), FtpState::Ccc);
            harness.reply(b"200 cleared\r\n").expect("cleared");
            assert_eq!(
                harness.seams.borrow().tls_removed,
                vec![(SocketIndex::First, send_shutdown)],
                "{mode:?} decides whether a shutdown is sent"
            );
            assert_eq!(harness.state(), FtpState::Pwd);
            assert_eq!(harness.sent_text(), "PROT C\r\nCCC\r\nPWD\r\n");
        }
    }

    /// A `CCC` the server refuses does not take the filter away, and the login
    /// continues.
    #[test]
    fn a_refused_ccc_leaves_the_filter_in_place() {
        let mut harness = Harness::new(b"file");
        harness.client.opts.ccc = CccMode::Passive;
        harness.force_state(FtpState::Ccc);
        harness.reply(b"500 refused\r\n").expect("continues");
        assert!(harness.seams.borrow().tls_removed.is_empty());
        assert_eq!(harness.state(), FtpState::Pwd);
    }

    /// A `CCC` teardown that fails reports the C's exact text.
    #[test]
    fn a_failed_ccc_teardown_reports_the_c_text() {
        let mut harness = Harness::new(b"file");
        harness.client.opts.ccc = CccMode::Passive;
        harness.seams.borrow_mut().tls_remove_fails =
            Some(CURLcode::SslShutdownFailed);
        harness.force_state(FtpState::Ccc);
        let error = harness.reply(b"200 cleared\r\n").expect_err("teardown");
        assert_eq!(error.code(), CURLcode::SslShutdownFailed);
        assert_eq!(
            harness.client.log.fail,
            vec!["Failed to clear the command channel (CCC)"]
        );
    }

    /// Implicit FTPS: an already-secure control filter needs no `AUTH` at all.
    #[test]
    fn implicit_ftps_skips_the_auth_negotiation() {
        let mut harness = Harness::new(b"file");
        harness.client.opts.use_ssl = UseSsl::All;
        // The chain is already secure, as it is on port 990.
        harness
            .wire
            .borrow_mut()
            .input
            .extend_from_slice(b"220 ready\r\n");
        harness.client.req.control_ssl = true;
        harness.force_state(FtpState::Wait220);
        harness.step().expect("greeting");
        assert_eq!(
            harness.sent_text(),
            "USER anonymous\r\n",
            "an already-secure control channel goes straight to the login"
        );
        assert!(harness.seams.borrow().tls_added.is_empty());
    }

    // -- Phase 12: PRET, RETR, STOR and APPE --------------------------------

    /// `PRET` precedes the passive setup and names the command it is preparing
    /// for -- `tests/data/test1107` pins `PRET RETR` before `EPSV`.
    #[test]
    fn pret_names_the_command_it_prepares_for() {
        // A download.
        let mut harness = Harness::new(b"n");
        harness.client.opts.use_pret = true;
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine.state_prepare_transfer(pp, io).expect("sent");
        });
        assert_eq!(harness.sent_text(), "PRET RETR n\r\n");
        assert_eq!(harness.state(), FtpState::Pret);
        harness.reply(b"200 ready\r\n").expect("accepted");
        assert_eq!(
            harness.sent_text(),
            "PRET RETR n\r\nEPSV\r\n",
            "tests/data/test1107's order"
        );

        // An upload.
        let mut harness = Harness::new(b"n");
        harness.client.opts.use_pret = true;
        harness.client.req.upload = true;
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine.state_prepare_transfer(pp, io).expect("sent");
        });
        assert_eq!(harness.sent_text(), "PRET STOR n\r\n");

        // A listing, which takes the listing verb.
        let mut harness = Harness::new(b"dir/");
        harness.client.opts.use_pret = true;
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine.state_prepare_transfer(pp, io).expect("sent");
        });
        assert_eq!(harness.sent_text(), "PRET LIST\r\n");

        // A listing with `-l`, and one with a custom command.
        let mut harness = Harness::new(b"dir/");
        harness.client.opts.use_pret = true;
        harness.client.req.list_only = true;
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine.state_prepare_transfer(pp, io).expect("sent");
        });
        assert_eq!(harness.sent_text(), "PRET NLST\r\n");

        let mut harness = Harness::new(b"dir/");
        harness.client.opts.use_pret = true;
        harness.client.opts.custom_request = Some(b"MLSD".to_vec());
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine.state_prepare_transfer(pp, io).expect("sent");
        });
        assert_eq!(harness.sent_text(), "PRET MLSD\r\n");
    }

    /// A refused `PRET` is `CURLE_FTP_PRET_FAILED`, with the C's exact text.
    #[test]
    fn a_refused_pret_reports_the_c_code_and_text() {
        let mut harness = Harness::new(b"n");
        harness.client.opts.use_pret = true;
        parse_path(&mut harness).expect("parsed");
        harness.force_state(FtpState::Pret);
        let error = harness.reply(b"550 no\r\n").expect_err("refused");
        assert_eq!(error.code(), CURLcode::FtpPretFailed);
        assert_eq!(
            harness.client.log.fail,
            vec!["PRET command not accepted: 550"]
        );
    }

    /// A plain download sends `SIZE` then `RETR`.
    #[test]
    fn a_plain_download_sizes_the_file_then_fetches_it() {
        let mut harness = Harness::new(b"file");
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine
                .state_quote(pp, io, true, FtpState::RetrPrequote)
                .expect("no prequote list");
        });
        assert_eq!(harness.sent_text(), "SIZE file\r\n");
        harness.reply(b"213 4096\r\n").expect("sized");
        assert_eq!(harness.sent_text(), "SIZE file\r\nRETR file\r\n");
        assert_eq!(harness.session.transfer().downloadsize, 4096);
    }

    /// ASCII mode skips the `SIZE` -- *"servers do not report the converted
    /// size"* -- which is what `tests/data/test105` pins.
    #[test]
    fn an_ascii_download_skips_the_size() {
        let mut harness = Harness::new(b"file");
        harness.client.req.prefer_ascii = true;
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine
                .state_quote(pp, io, true, FtpState::RetrPrequote)
                .expect("no prequote list");
        });
        assert_eq!(
            harness.sent_text(),
            "RETR file\r\n",
            "tests/data/test105 has no SIZE at all"
        );
        assert_eq!(harness.state(), FtpState::Retr);
    }

    /// `CURLOPT_IGNORE_CONTENT_LENGTH` skips it too.
    #[test]
    fn ignoring_the_content_length_skips_the_size() {
        let mut harness = Harness::new(b"file");
        harness.client.opts.ignore_content_length = true;
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine
                .state_quote(pp, io, true, FtpState::RetrPrequote)
                .expect("no prequote list");
        });
        assert_eq!(harness.sent_text(), "RETR file\r\n");
    }

    /// A size the wildcard driver already knows skips it as well.
    #[test]
    fn a_known_wildcard_size_skips_the_size() {
        let mut harness = Harness::new(b"file");
        harness.session.conn_mut().ftpc_mut().known_filesize = 1234;
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine
                .state_quote(pp, io, true, FtpState::RetrPrequote)
                .expect("no prequote list");
        });
        assert_eq!(harness.sent_text(), "RETR file\r\n");
        assert_eq!(harness.client.log.download_size, vec![1234]);
        assert_eq!(harness.session.transfer().downloadsize, 1234);
    }

    /// A resumed download sends `REST <offset>` and then `RETR`.
    #[test]
    fn a_resumed_download_sends_rest_before_retr() {
        let mut harness = Harness::new(b"file");
        harness.client.req.resume_from = 2048;
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine.state_retr(pp, io, 4096).expect("sent");
        });
        assert_eq!(harness.sent_text(), "REST 2048\r\n");
        assert_eq!(harness.state(), FtpState::RetrRest);
        harness.reply(b"350 ready\r\n").expect("accepted");
        assert_eq!(harness.sent_text(), "REST 2048\r\nRETR file\r\n");
    }

    /// A negative offset counts back from the end of the file.
    #[test]
    fn a_negative_resume_offset_counts_from_the_end() {
        let mut harness = Harness::new(b"file");
        harness.client.req.resume_from = -100;
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine.state_retr(pp, io, 4096).expect("sent");
        });
        assert_eq!(harness.sent_text(), "REST 3996\r\n");
    }

    /// An offset past the end of the file is a bad resume.
    #[test]
    fn an_offset_past_the_end_of_the_file_is_a_bad_resume() {
        let mut harness = Harness::new(b"file");
        harness.client.req.resume_from = -8192;
        parse_path(&mut harness).expect("parsed");
        let error = harness.with_machine(|pp, machine, io| {
            machine
                .state_retr(pp, io, 4096)
                .expect_err("nothing left to fetch")
        });
        assert_eq!(error.code(), CURLcode::BadDownloadResume);
    }

    /// `CURLOPT_MAXFILESIZE` refuses a file that is too big.
    #[test]
    fn a_file_beyond_the_maximum_size_is_refused() {
        let mut harness = Harness::new(b"file");
        harness.client.opts.max_filesize = 1024;
        parse_path(&mut harness).expect("parsed");
        let error = harness.with_machine(|pp, machine, io| {
            machine.state_retr(pp, io, 4096).expect_err("too big")
        });
        assert_eq!(error.code(), CURLcode::FilesizeExceeded);
        assert_eq!(harness.client.log.fail, vec!["Maximum file size exceeded"]);
    }

    /// A `550` to `RETR` is a missing file; a `550` to `LIST` is not.
    #[test]
    fn a_550_to_retr_is_a_missing_file() {
        let mut harness = Harness::new(b"file");
        parse_path(&mut harness).expect("parsed");
        harness.force_state(FtpState::Retr);
        let error = harness.reply(b"550 no such file\r\n").expect_err("absent");
        assert_eq!(error.code(), CURLcode::RemoteFileNotFound);
        assert_eq!(harness.client.log.fail, vec!["RETR response: 550"]);

        let mut harness = Harness::new(b"dir/");
        parse_path(&mut harness).expect("parsed");
        harness.force_state(FtpState::List);
        let error = harness.reply(b"550 no\r\n").expect_err("refused");
        assert_eq!(error.code(), CURLcode::FtpCouldntRetrFile);
    }

    /// A `450` to `LIST` means an empty directory, not a failure.
    #[test]
    fn a_450_to_list_is_an_empty_directory() {
        let mut harness = Harness::new(b"dir/");
        parse_path(&mut harness).expect("parsed");
        harness.force_state(FtpState::List);
        harness.reply(b"450 no files\r\n").expect("tolerated");
        assert_eq!(harness.session.transfer().transfer, PpTransfer::None);
        assert_eq!(harness.state(), FtpState::Stop);
    }

    /// `150` and `125` both start a transfer, and the size is read out of the
    /// reply's prose.
    #[test]
    fn a_preliminary_reply_starts_the_transfer_and_may_carry_the_size() {
        for code in [150, 125] {
            let mut harness = Harness::new(b"file");
            parse_path(&mut harness).expect("parsed");
            harness.force_state(FtpState::Retr);
            let reply = format!(
                "{code} Opening BINARY mode data connection for /etc/passwd \
                 (2241 bytes)\r\n"
            );
            harness.reply(reply.as_bytes()).expect("transfer starts");
            assert_eq!(harness.client.req.size, 2241, "from a {code} reply");
            assert_eq!(harness.state(), FtpState::Stop);
            assert!(harness
                .client
                .log
                .xfer
                .iter()
                .any(|tag| tag.starts_with("recv:Secondary:")));
        }
    }

    /// The `<n> bytes` scan, alone.
    #[test]
    fn the_bytes_in_reply_scan_finds_the_number_before_the_word() {
        assert_eq!(
            parse_bytes_in_reply(b"150 Opening (2241 bytes)\r\n"),
            Some(2241)
        );
        assert_eq!(parse_bytes_in_reply(b"150 1 bytes\r\n"), Some(1));
        assert_eq!(parse_bytes_in_reply(b"150 no size here\r\n"), None);
        // Shorter than the shortest possible match.
        assert_eq!(parse_bytes_in_reply(b"150 ok"), None);
        assert_eq!(parse_bytes_in_reply(b""), None);
        // A number not followed by the word does not count.
        assert_eq!(parse_bytes_in_reply(b"150 12 blocks\r\n"), None);
    }

    /// A listing's size is never inferred from its reply.
    ///
    /// The C's condition excludes `FTP_LIST` outright, so the `else if` runs
    /// instead and the size comes from `ftp->downloadsize` -- which the download
    /// path sets to `-1` before the transfer command goes out. Both halves are
    /// asserted, because the SECOND is what makes the first observable.
    #[test]
    fn a_listing_does_not_take_its_size_from_the_reply() {
        let mut harness = Harness::new(b"dir/");
        parse_path(&mut harness).expect("parsed");
        // What `ftp_do_more`'s download branch assigns: *"unknown as of yet"*.
        harness.session.transfer_mut().downloadsize = -1;
        harness.force_state(FtpState::List);
        harness
            .reply(b"150 Opening ASCII mode data connection (2241 bytes)\r\n")
            .expect("transfer starts");
        assert_eq!(
            harness.client.req.size, -1,
            "a directory listing's size is not to be trusted"
        );

        // A size the driver already knows IS adopted, through the same `else`.
        let mut harness = Harness::new(b"dir/");
        parse_path(&mut harness).expect("parsed");
        harness.session.transfer_mut().downloadsize = 99;
        harness.force_state(FtpState::List);
        harness
            .reply(b"150 Opening ASCII mode data connection (2241 bytes)\r\n")
            .expect("transfer starts");
        assert_eq!(harness.client.req.size, 99);
    }

    /// An ASCII transfer's inferred size is discarded afterwards.
    #[test]
    fn an_ascii_transfer_discards_its_inferred_size() {
        let mut harness = Harness::new(b"file");
        harness.client.req.prefer_ascii = true;
        parse_path(&mut harness).expect("parsed");
        harness.force_state(FtpState::Retr);
        harness
            .reply(b"150 Opening ASCII mode data connection (2241 bytes)\r\n")
            .expect("transfer starts");
        assert_eq!(harness.client.req.size, -1);
    }

    /// `STOR`, and `APPE` when appending was asked for.
    #[test]
    fn an_upload_sends_stor_or_appe() {
        let mut harness = Harness::new(b"file");
        harness.client.req.upload = true;
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine.state_ul_setup(pp, io, false).expect("sent");
        });
        assert_eq!(harness.sent_text(), "STOR file\r\n");
        assert_eq!(harness.state(), FtpState::Stor);

        let mut harness = Harness::new(b"file");
        harness.client.req.upload = true;
        harness.client.opts.remote_append = true;
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine.state_ul_setup(pp, io, false).expect("sent");
        });
        assert_eq!(harness.sent_text(), "APPE file\r\n");
    }

    /// A resumed upload appends rather than using `REST`, and seeks the source.
    #[test]
    fn a_resumed_upload_appends_and_seeks_the_source() {
        let mut harness = Harness::new(b"file");
        harness.client.req.upload = true;
        harness.client.req.resume_from = 512;
        harness.client.req.infilesize = 2048;
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine.state_ul_setup(pp, io, true).expect("sent");
        });
        assert_eq!(
            harness.sent_text(),
            "APPE file\r\n",
            "a resumed upload appends; the C's comment says why"
        );
        assert_eq!(harness.client.log.seek_calls, vec![512]);
        assert_eq!(
            harness.client.req.infilesize, 1536,
            "the remaining size is what is left to send"
        );
    }

    /// An unknown remote size probes with `SIZE` first.
    #[test]
    fn an_upload_resuming_from_an_unknown_offset_probes_with_size() {
        let mut harness = Harness::new(b"file");
        harness.client.req.upload = true;
        harness.client.req.resume_from = -1;
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine.state_ul_setup(pp, io, false).expect("sent");
        });
        assert_eq!(harness.sent_text(), "SIZE file\r\n");
        assert_eq!(harness.state(), FtpState::StorSize);
        harness.reply(b"213 512\r\n").expect("probed");
        assert_eq!(harness.client.req.resume_from, 512);
        assert_eq!(harness.sent_text(), "SIZE file\r\nAPPE file\r\n");
    }

    /// A source that cannot seek is read and discarded up to the offset.
    #[test]
    fn a_source_that_cannot_seek_is_read_and_discarded() {
        let mut harness = Harness::new(b"file");
        harness.client.req.upload = true;
        harness.client.req.resume_from = 8192;
        harness.client.log.seek = SeekOutcome::CantSeek;
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine.state_ul_setup(pp, io, true).expect("sent");
        });
        assert_eq!(harness.sent_text(), "APPE file\r\n");
        assert_eq!(harness.client.log.seek_calls, vec![8192]);
    }

    /// A source that refuses to seek at all is `CURLE_FTP_COULDNT_USE_REST`.
    #[test]
    fn a_source_that_refuses_to_seek_is_a_rest_failure() {
        let mut harness = Harness::new(b"file");
        harness.client.req.upload = true;
        harness.client.req.resume_from = 512;
        harness.client.log.seek = SeekOutcome::Fail;
        parse_path(&mut harness).expect("parsed");
        let error = harness.with_machine(|pp, machine, io| {
            machine
                .state_ul_setup(pp, io, true)
                .expect_err("cannot position the source")
        });
        assert_eq!(error.code(), CURLcode::FtpCouldntUseRest);
        assert_eq!(harness.client.log.fail, vec!["Could not seek stream"]);
    }

    /// An upload that is already complete transfers nothing.
    #[test]
    fn an_upload_that_is_already_complete_does_nothing() {
        let mut harness = Harness::new(b"file");
        harness.client.req.upload = true;
        harness.client.req.resume_from = 2048;
        harness.client.req.infilesize = 2048;
        parse_path(&mut harness).expect("parsed");
        harness.with_machine(|pp, machine, io| {
            machine.state_ul_setup(pp, io, true).expect("nothing to do");
        });
        assert_eq!(harness.sent_text(), "");
        assert_eq!(harness.session.transfer().transfer, PpTransfer::None);
        assert_eq!(harness.state(), FtpState::Stop);
        assert!(harness
            .client
            .log
            .info
            .contains(&"File already completely uploaded".to_owned()));
        assert!(harness.client.log.xfer.contains(&"nop".to_owned()));
    }

    /// A refused `STOR` is `CURLE_UPLOAD_FAILED`, with the C's `%0d` text.
    #[test]
    fn a_refused_upload_reports_the_c_code_and_text() {
        let mut harness = Harness::new(b"file");
        harness.client.req.upload = true;
        parse_path(&mut harness).expect("parsed");
        harness.force_state(FtpState::Stor);
        let error =
            harness.reply(b"550 permission denied\r\n").expect_err("no");
        assert_eq!(error.code(), CURLcode::UploadFailed);
        assert_eq!(harness.client.log.fail, vec!["Failed FTP upload: 550"]);
        assert_eq!(harness.state(), FtpState::Stop);
    }

    /// An accepted `STOR` sets the transfer up for sending.
    #[test]
    fn an_accepted_upload_sets_the_transfer_up_for_sending() {
        let mut harness = Harness::new(b"file");
        harness.client.req.upload = true;
        harness.client.req.infilesize = 2048;
        parse_path(&mut harness).expect("parsed");
        harness.force_state(FtpState::Stor);
        harness.reply(b"150 ok to send\r\n").expect("accepted");
        assert_eq!(harness.client.log.upload_size, vec![2048]);
        assert!(harness
            .client
            .log
            .xfer
            .contains(&"send:Secondary".to_owned()));
        assert!(harness
            .client
            .log
            .xfer
            .contains(&"shutdown:true:true".to_owned()));
        assert_eq!(harness.state(), FtpState::Stop);
    }

    // -- Phase 12: the DO_MORE phase ---------------------------------------

    /// A transfer with nothing to send completes DO_MORE at once.
    #[test]
    fn do_more_advances_when_there_is_nothing_to_transfer() {
        let mut harness = Harness::new(b"file");
        harness.init_pp();
        harness.session.transfer_mut().transfer = PpTransfer::None;
        assert_eq!(
            do_more(&mut harness).expect("nothing to move"),
            DoMoreStep::Advance
        );
        assert!(harness.client.log.xfer.contains(&"nop".to_owned()));
        assert!(harness
            .client
            .log
            .trc
            .iter()
            .any(|line| line.contains("DO-MORE phase ends with 0")));
    }

    /// A transfer still awaiting the server's connect stays pending.
    #[test]
    fn do_more_stays_pending_while_the_data_connection_is_awaited() {
        let mut harness = Harness::new(b"file");
        harness.init_pp();
        harness.session.transfer_mut().transfer = PpTransfer::None;
        harness.session.conn_mut().ftpc_mut().wait_data_conn = true;
        assert_eq!(
            do_more(&mut harness).expect("still waiting"),
            DoMoreStep::Pending
        );
    }

    /// An active transfer completes as soon as the server has connected back.
    #[test]
    fn do_more_advances_when_the_server_connects_back() {
        let mut harness = Harness::new(b"file");
        harness.init_pp();
        parse_path(&mut harness).expect("parsed");
        harness.session.conn_mut().ftpc_mut().wait_data_conn = true;
        assert_eq!(
            do_more(&mut harness).expect("connected back"),
            DoMoreStep::Advance
        );
        assert!(!harness.session.conn().ftpc().wait_data_conn);
        assert!(harness
            .client
            .log
            .xfer
            .iter()
            .any(|tag| tag.starts_with("recv:Secondary:")));
    }

    /// An active transfer whose server has not connected yet checks the control
    /// channel and stays pending.
    #[test]
    fn do_more_checks_the_control_channel_while_waiting_for_an_accept() {
        let mut harness = Harness::new(b"file");
        harness.init_pp();
        parse_path(&mut harness).expect("parsed");
        harness.session.conn_mut().ftpc_mut().wait_data_conn = true;
        harness
            .seams
            .borrow_mut()
            .connect_script
            .push_back(Ok(false));
        assert_eq!(
            do_more(&mut harness).expect("still waiting"),
            DoMoreStep::Pending
        );
        assert!(harness.session.conn().ftpc().wait_data_conn);
    }

    /// A download drives `TYPE`, `SIZE` and `RETR` from DO_MORE.
    #[test]
    fn do_more_drives_the_download_commands() {
        let mut harness = Harness::new(b"file");
        harness.init_pp();
        parse_path(&mut harness).expect("parsed");
        harness.feed(b"200 type set\r\n");
        harness.feed(b"213 4096\r\n");
        harness.feed(b"150 opening\r\n");
        do_more_until_advance(&mut harness, 6);
        assert_eq!(harness.sent_text(), "TYPE I\r\nSIZE file\r\nRETR file\r\n");
    }

    /// An upload drives `TYPE` and `STOR` from DO_MORE.
    #[test]
    fn do_more_drives_the_upload_commands() {
        let mut harness = Harness::new(b"file");
        harness.init_pp();
        harness.client.req.upload = true;
        parse_path(&mut harness).expect("parsed");
        harness.feed(b"200 type set\r\n");
        harness.feed(b"150 ok to send\r\n");
        do_more_until_advance(&mut harness, 6);
        assert_eq!(harness.sent_text(), "TYPE I\r\nSTOR file\r\n");
    }

    /// A listing takes ASCII mode and the listing command.
    #[test]
    fn do_more_drives_a_listing_in_ascii_mode() {
        let mut harness = Harness::new(b"dir/");
        harness.init_pp();
        parse_path(&mut harness).expect("parsed");
        harness.feed(b"200 type set\r\n");
        harness.feed(b"150 opening\r\n");
        do_more_until_advance(&mut harness, 6);
        assert_eq!(
            harness.sent_text(),
            "TYPE A\r\nLIST\r\n",
            "tests/data/test100's pair"
        );
    }

    /// A prequote list with no filename takes the `RETR_LIST_TYPE` path.
    #[test]
    fn a_prequote_list_without_a_filename_takes_the_list_type_path() {
        let mut harness = Harness::new(b"dir/");
        harness.init_pp();
        harness.client.opts.prequote = vec![b"SITE PRE".to_vec()];
        parse_path(&mut harness).expect("parsed");
        harness.feed(b"200 type set\r\n");
        harness.feed(b"200 prequote ok\r\n");
        harness.feed(b"150 opening\r\n");
        do_more_until_advance(&mut harness, 6);
        assert_eq!(harness.sent_text(), "TYPE A\r\nSITE PRE\r\nLIST\r\n");
    }

    /// A range makes `dont_check` true, which is what suppresses the closing
    /// check.
    #[test]
    fn a_bounded_range_suppresses_the_closing_check() {
        let mut harness = Harness::new(b"file");
        harness.init_pp();
        harness.client.opts.range = Some(b"0-99".to_vec());
        parse_path(&mut harness).expect("parsed");
        harness.feed(b"200 type set\r\n");
        let _ = do_more(&mut harness);
        assert!(harness.session.conn().ftpc().dont_check);
        assert_eq!(harness.client.req.maxdownload, 100);
        assert_eq!(harness.client.req.resume_from, 0);
    }

    /// An open-ended range resumes without a limit, so the check stays on.
    #[test]
    fn an_open_ended_range_leaves_the_closing_check_on() {
        let mut harness = Harness::new(b"file");
        harness.init_pp();
        harness.client.opts.range = Some(b"100-".to_vec());
        parse_path(&mut harness).expect("parsed");
        harness.feed(b"200 type set\r\n");
        let _ = do_more(&mut harness);
        assert_eq!(harness.client.req.resume_from, 100);
        assert_eq!(harness.client.req.maxdownload, -1);
        assert!(!harness.session.conn().ftpc().dont_check);
    }

    /// A suffix range asks for the last bytes, with the C's negative offset.
    #[test]
    fn a_suffix_range_asks_for_the_last_bytes() {
        let mut harness = Harness::new(b"file");
        harness.init_pp();
        harness.client.opts.range = Some(b"-256".to_vec());
        parse_path(&mut harness).expect("parsed");
        harness.feed(b"200 type set\r\n");
        let _ = do_more(&mut harness);
        assert_eq!(harness.client.req.maxdownload, 256);
        assert_eq!(
            harness.client.req.resume_from, -256,
            "the sign is how *measure from the end* travels"
        );
    }

    /// A range this protocol cannot honour is refused.
    #[test]
    fn an_impossible_range_is_refused() {
        let mut harness = Harness::new(b"file");
        harness.init_pp();
        harness.client.opts.range = Some(b"nonsense".to_vec());
        parse_path(&mut harness).expect("parsed");
        let error = do_more(&mut harness).expect_err("not a range");
        assert_eq!(error.code(), CURLcode::RangeError);
    }

    /// With no range at all the limit returns to `-1`, which is what keeps the
    /// closing check on.
    #[test]
    fn no_range_resets_the_download_limit() {
        let mut harness = Harness::new(b"file");
        harness.init_pp();
        harness.client.req.maxdownload = 42;
        parse_path(&mut harness).expect("parsed");
        harness.feed(b"200 type set\r\n");
        let _ = do_more(&mut harness);
        assert_eq!(
            harness.client.req.maxdownload, -1,
            "`Curl_range`'s else branch (`lib/curl_range.c:87`)"
        );
        assert!(!harness.session.conn().ftpc().dont_check);
    }

    /// The DO_MORE pollset watches the control socket while a connect is
    /// awaited, and delegates otherwise.
    #[test]
    fn the_domore_pollset_watches_the_control_socket_while_waiting() {
        let mut harness = Harness::new(b"file");
        harness.init_pp();
        let mut ps = EasyPollset::new();
        harness.with_machine(|pp, machine, io| {
            machine.domore_pollset(pp, io, &mut ps).expect("recorded");
        });
        assert_eq!(
            ps.iter().collect::<Vec<_>>(),
            vec![(CTRL_SOCK, PollAction::IN)],
            "in STOP the control socket is watched for input"
        );

        // In any other state the cadence engine's own direction applies, which
        // for an empty send buffer is also input.
        let mut harness = Harness::new(b"file");
        harness.init_pp();
        harness.force_state(FtpState::Retr);
        let mut ps = EasyPollset::new();
        harness.with_machine(|pp, machine, io| {
            machine.domore_pollset(pp, io, &mut ps).expect("recorded");
        });
        assert_eq!(
            ps.iter().collect::<Vec<_>>(),
            vec![(CTRL_SOCK, PollAction::IN)]
        );
    }

    /// The PROTOCONNECT and DOING pollsets are the same function, and both
    /// follow the cadence engine's direction.
    #[test]
    fn the_protocol_pollset_follows_the_send_direction() {
        let mut harness = Harness::new(b"file");
        harness.init_pp();
        let mut ps = EasyPollset::new();
        harness.with_machine(|pp, machine, io| {
            machine.pollset(pp, io, &mut ps).expect("recorded");
        });
        assert_eq!(
            ps.iter().collect::<Vec<_>>(),
            vec![(CTRL_SOCK, PollAction::IN)]
        );
    }

    // -- Phase 12: ftp_done -------------------------------------------------

    /// The thirteen survivable codes, and everything else.
    #[test]
    fn the_done_classification_is_the_c_switch() {
        assert_eq!(DONE_SURVIVABLE.len(), 13);
        assert!(done_status_survivable(CURLcode::Ok, false));
        for code in DONE_SURVIVABLE {
            assert!(
                done_status_survivable(code, false),
                "{code:?} leaves the connection usable"
            );
            assert!(
                !done_status_survivable(code, true),
                "{code:?} does not survive a premature end"
            );
        }
        assert!(!done_status_survivable(CURLcode::Ok, true));
        assert!(!done_status_survivable(CURLcode::OutOfMemory, false));
        assert!(!done_status_survivable(CURLcode::SendError, false));
    }

    /// A `226` closes the transfer cleanly.
    #[test]
    fn a_226_closes_the_transfer_cleanly() {
        let mut harness = Harness::new(b"pub/file");
        harness.init_pp();
        parse_path(&mut harness).expect("parsed");
        harness.session.conn_mut().ftpc_mut().ctl_valid = true;
        harness.session.conn_mut().pp_mut().set_pending_resp(true);
        harness.feed(b"226 Transfer complete\r\n");
        done(&mut harness, CURLcode::Ok, false).expect("clean");
        assert_eq!(
            harness.session.transfer().transfer,
            PpTransfer::Body,
            "the transfer state is reset for the next request"
        );
        assert!(!harness.session.conn().ftpc().dont_check);
    }

    /// A `250` closes it just as cleanly.
    #[test]
    fn a_250_closes_the_transfer_cleanly() {
        let mut harness = Harness::new(b"pub/file");
        harness.init_pp();
        parse_path(&mut harness).expect("parsed");
        harness.session.conn_mut().ftpc_mut().ctl_valid = true;
        harness.session.conn_mut().pp_mut().set_pending_resp(true);
        harness.feed(b"250 Requested file action okay\r\n");
        done(&mut harness, CURLcode::Ok, false).expect("clean");
    }

    /// A `552` is a full disk, with the C's exact text.
    #[test]
    fn a_552_is_a_full_remote_disk() {
        let mut harness = Harness::new(b"pub/file");
        harness.init_pp();
        parse_path(&mut harness).expect("parsed");
        harness.session.conn_mut().ftpc_mut().ctl_valid = true;
        harness.session.conn_mut().pp_mut().set_pending_resp(true);
        harness.feed(b"552 Exceeded storage allocation\r\n");
        let error = done(&mut harness, CURLcode::Ok, false).expect_err("full");
        assert_eq!(error.code(), CURLcode::RemoteDiskFull);
        assert_eq!(harness.client.log.fail, vec![DISK_FULL_MESSAGE.to_owned()]);
        assert_eq!(DISK_FULL_MESSAGE, "Exceeded storage allocation");
    }

    /// Any other closing code is a partial file, with the code in the text.
    #[test]
    fn an_unexpected_closing_code_is_a_partial_file() {
        let mut harness = Harness::new(b"pub/file");
        harness.init_pp();
        parse_path(&mut harness).expect("parsed");
        harness.session.conn_mut().ftpc_mut().ctl_valid = true;
        harness.session.conn_mut().pp_mut().set_pending_resp(true);
        harness.feed(b"451 Requested action aborted\r\n");
        let error =
            done(&mut harness, CURLcode::Ok, false).expect_err("partial");
        assert_eq!(error.code(), CURLcode::PartialFile);
        assert_eq!(
            harness.client.log.fail,
            vec!["server did not report OK, got 451"]
        );
    }

    /// `dont_check` suppresses the JUDGEMENT of the closing reply and never the
    /// READ of it -- the clause most easily got wrong.
    #[test]
    fn dont_check_still_reads_the_closing_reply() {
        let mut harness = Harness::new(b"pub/file");
        harness.init_pp();
        parse_path(&mut harness).expect("parsed");
        harness.session.conn_mut().ftpc_mut().ctl_valid = true;
        harness.session.conn_mut().ftpc_mut().dont_check = true;
        harness.session.conn_mut().pp_mut().set_pending_resp(true);
        // A code that WOULD be a partial file if it were judged.
        harness.feed(b"451 aborted\r\n");
        done(&mut harness, CURLcode::Ok, false)
            .expect("the reply is read but not judged");
        assert!(
            harness.wire.borrow().input.is_empty(),
            "the reply was consumed, so the next transfer cannot mistake it \\
             for its own"
        );
        assert_eq!(
            echoed(&harness),
            vec!["451 aborted\r\n".to_owned()],
            "and it reached the client, which is proof it was read"
        );
    }

    /// A partial download that has already sent `ABOR` closes the connection.
    #[test]
    fn a_partial_download_with_abor_closes_the_connection() {
        let mut harness = Harness::new(b"pub/file");
        harness.init_pp();
        parse_path(&mut harness).expect("parsed");
        harness.client.req.maxdownload = 100;
        harness.session.conn_mut().ftpc_mut().ctl_valid = true;
        harness.session.conn_mut().ftpc_mut().dont_check = true;
        harness.session.conn_mut().pp_mut().set_pending_resp(true);
        harness.feed(b"226 done\r\n");
        done(&mut harness, CURLcode::Ok, false).expect("tolerated");
        assert!(harness.client.log.info.contains(
            &"partial download completed, closing connection".to_owned()
        ));
        assert!(harness
            .client
            .log
            .closes
            .contains(&"Partial download with no ability to check".to_owned()));
    }

    /// A byte count that does not add up is a partial file.
    #[test]
    fn a_short_download_is_a_partial_file() {
        let mut harness = Harness::new(b"pub/file");
        harness.init_pp();
        parse_path(&mut harness).expect("parsed");
        harness.client.req.size = 4096;
        harness.client.req.bytecount = 100;
        let error = done(&mut harness, CURLcode::Ok, false).expect_err("short");
        assert_eq!(error.code(), CURLcode::PartialFile);
        assert_eq!(
            harness.client.log.fail,
            vec!["Received only partial file: 100 bytes"]
        );
    }

    /// A transfer that produced nothing at all is a retrieval failure.
    #[test]
    fn a_download_of_nothing_is_a_retrieval_failure() {
        let mut harness = Harness::new(b"pub/file");
        harness.init_pp();
        parse_path(&mut harness).expect("parsed");
        harness.client.req.size = 4096;
        harness.client.req.bytecount = 0;
        harness.client.req.maxdownload = 0;
        let error =
            done(&mut harness, CURLcode::Ok, false).expect_err("nothing");
        assert_eq!(error.code(), CURLcode::FtpCouldntRetrFile);
        assert_eq!(harness.client.log.fail, vec!["No data was received"]);
    }

    /// An upload whose byte count does not match the source size is a partial
    /// file -- and a converting upload is judged on `>` rather than `!=`.
    #[test]
    fn a_short_upload_is_a_partial_file() {
        let mut harness = Harness::new(b"pub/file");
        harness.init_pp();
        parse_path(&mut harness).expect("parsed");
        harness.client.req.upload = true;
        harness.client.req.infilesize = 2048;
        harness.client.req.writebytecount = 1000;
        let error = done(&mut harness, CURLcode::Ok, false).expect_err("short");
        assert_eq!(error.code(), CURLcode::PartialFile);
        assert_eq!(
            harness.client.log.fail,
            vec!["Uploaded unaligned file size (1000 out of 2048 bytes)"]
        );

        // A converting upload is judged with `>` rather than `!=`
        // (`lib/ftp.c:3658-3661`), because turning every LF into CRLF puts MORE
        // bytes on the wire than the source holds. Writing more is therefore
        // expected; writing fewer is still a short upload.
        let mut harness = Harness::new(b"pub/file");
        harness.init_pp();
        parse_path(&mut harness).expect("parsed");
        harness.client.req.upload = true;
        harness.client.opts.crlf = true;
        harness.client.req.infilesize = 2048;
        harness.client.req.writebytecount = 2100;
        done(&mut harness, CURLcode::Ok, false)
            .expect("a converting upload may write more than it read");

        // The same counts without conversion are a short upload, which is what
        // makes the `crlf` clause load-bearing rather than decorative.
        let mut harness = Harness::new(b"pub/file");
        harness.init_pp();
        parse_path(&mut harness).expect("parsed");
        harness.client.req.upload = true;
        harness.client.req.infilesize = 2048;
        harness.client.req.writebytecount = 2100;
        let error =
            done(&mut harness, CURLcode::Ok, false).expect_err("unaligned");
        assert_eq!(error.code(), CURLcode::PartialFile);

        // An ASCII transfer converts too, and takes the same tolerance.
        let mut harness = Harness::new(b"pub/file");
        harness.init_pp();
        parse_path(&mut harness).expect("parsed");
        harness.client.req.upload = true;
        harness.client.req.prefer_ascii = true;
        harness.client.req.infilesize = 2048;
        harness.client.req.writebytecount = 2100;
        done(&mut harness, CURLcode::Ok, false)
            .expect("an ASCII upload converts as well");
    }

    /// The path is remembered for reuse, with the C's exact info line.
    #[test]
    fn a_clean_finish_remembers_the_working_directory() {
        let mut harness = Harness::new(b"pub/file");
        harness.init_pp();
        parse_path(&mut harness).expect("parsed");
        done(&mut harness, CURLcode::Ok, false).expect("clean");
        assert_eq!(
            harness.session.conn().ftpc().prevpath.as_deref(),
            Some(&b"pub/"[..])
        );
        assert!(harness
            .client
            .log
            .info
            .contains(&"Remembering we are in directory \"pub/\"".to_owned()));
    }

    /// Under `NOCWD` a relative path leaves the working directory at the FTP
    /// home, so the remembered path is empty.
    #[test]
    fn nocwd_remembers_the_home_directory_for_a_relative_path() {
        let mut harness = Harness::new(b"pub/file");
        harness.init_pp();
        harness.client.req.file_method = FileMethod::NoCwd;
        parse_path(&mut harness).expect("parsed");
        done(&mut harness, CURLcode::Ok, false).expect("clean");
        assert_eq!(
            harness.session.conn().ftpc().prevpath.as_deref(),
            Some(&b""[..])
        );
    }

    /// Under `NOCWD` an absolute path performed no walk at all, so whatever was
    /// remembered before is kept.
    #[test]
    fn nocwd_keeps_the_previous_path_for_an_absolute_one() {
        let mut harness = Harness::new(b"/pub/file");
        harness.init_pp();
        harness.client.req.file_method = FileMethod::NoCwd;
        parse_path(&mut harness).expect("parsed");
        harness.session.conn_mut().ftpc_mut().prevpath =
            Some(b"kept/".to_vec());
        done(&mut harness, CURLcode::Ok, false).expect("clean");
        assert_eq!(
            harness.session.conn().ftpc().prevpath.as_deref(),
            Some(&b"kept/"[..]),
            "a full path means no CWDs happened"
        );
    }

    /// A failed walk forbids remembering anything.
    #[test]
    fn a_failed_walk_forgets_the_path() {
        let mut harness = Harness::new(b"pub/file");
        harness.init_pp();
        parse_path(&mut harness).expect("parsed");
        harness.session.conn_mut().ftpc_mut().cwdfail = true;
        done(&mut harness, CURLcode::Ok, false).expect("clean");
        assert!(harness.session.conn().ftpc().prevpath.is_none());
    }

    /// A wedged status closes the connection and keeps its own code.
    #[test]
    fn a_wedging_status_closes_the_connection_and_keeps_its_code() {
        let mut harness = Harness::new(b"pub/file");
        harness.init_pp();
        parse_path(&mut harness).expect("parsed");
        let error = done(&mut harness, CURLcode::SendError, false)
            .expect_err("the status is kept");
        assert_eq!(error.code(), CURLcode::SendError);
        assert!(!harness.session.conn().ftpc().ctl_valid);
        assert!(harness.session.conn().ftpc().cwdfail);
        assert!(harness
            .client
            .log
            .closes
            .contains(&"FTP ended with bad error code".to_owned()));
        assert!(harness.session.conn().ftpc().prevpath.is_none());
    }

    /// A survivable status leaves the connection usable.
    #[test]
    fn a_survivable_status_leaves_the_connection_usable() {
        let mut harness = Harness::new(b"pub/file");
        harness.init_pp();
        parse_path(&mut harness).expect("parsed");
        harness.session.conn_mut().ftpc_mut().ctl_valid = true;
        harness.feed(b"226 done\r\n");
        done(&mut harness, CURLcode::PartialFile, false)
            .expect("the connection survives");
        assert!(harness.session.conn().ftpc().ctl_valid);
        assert!(harness.client.log.closes.is_empty());
    }

    /// The post-transfer quote list runs on a clean finish and not otherwise.
    #[test]
    fn the_postquote_list_runs_only_on_a_clean_finish() {
        let mut harness = Harness::new(b"pub/file");
        harness.init_pp();
        harness.client.opts.postquote = vec![b"SITE POST".to_vec()];
        parse_path(&mut harness).expect("parsed");
        harness.feed(b"200 ok\r\n");
        done(&mut harness, CURLcode::Ok, false).expect("clean");
        assert_eq!(harness.sent_text(), "SITE POST\r\n");

        // Not after a failure.
        let mut harness = Harness::new(b"pub/file");
        harness.init_pp();
        harness.client.opts.postquote = vec![b"SITE POST".to_vec()];
        parse_path(&mut harness).expect("parsed");
        let _ = done(&mut harness, CURLcode::SendError, false);
        assert_eq!(harness.sent_text(), "");

        // Nor after a premature end.
        let mut harness = Harness::new(b"pub/file");
        harness.init_pp();
        harness.client.opts.postquote = vec![b"SITE POST".to_vec()];
        parse_path(&mut harness).expect("parsed");
        let _ = done(&mut harness, CURLcode::Ok, true);
        assert_eq!(harness.sent_text(), "");
    }

    // -- Phase 12: QUIT and the disconnect ---------------------------------

    /// `QUIT` goes out on a healthy connection, and its reply is consumed.
    #[test]
    fn quit_says_goodbye_and_waits_to_be_answered() {
        let mut harness = Harness::new(b"file");
        harness.init_pp();
        harness.session.conn_mut().ftpc_mut().ctl_valid = true;
        harness.feed(b"221 bye\r\n");
        quit(&mut harness).expect("answered");
        assert_eq!(harness.sent_text(), "QUIT\r\n");
        assert!(harness
            .client
            .log
            .trc
            .contains(&"sending QUIT to close session".to_owned()));
    }

    /// An invalid control connection sends nothing at all.
    #[test]
    fn quit_says_nothing_on_a_broken_connection() {
        let mut harness = Harness::new(b"file");
        harness.init_pp();
        harness.session.conn_mut().ftpc_mut().ctl_valid = false;
        quit(&mut harness).expect("nothing to do");
        assert_eq!(harness.sent_text(), "");
    }

    /// The disconnect marks the shutdown, says goodbye, and releases the
    /// connection's state.
    #[test]
    fn the_disconnect_says_goodbye_and_releases_the_state() {
        let mut harness = Harness::new(b"file");
        harness.init_pp();
        harness.session.conn_mut().ftpc_mut().ctl_valid = true;
        harness.feed(b"221 bye\r\n");
        disconnect(&mut harness, false).expect("never fails");
        assert_eq!(harness.sent_text(), "QUIT\r\n");
        assert!(harness.session.conn().ftpc().shutdown);
        assert!(
            !harness.session.conn().pp().is_initialised(),
            "the cadence engine is released"
        );
    }

    /// A dead connection is never spoken to.
    #[test]
    fn a_dead_connection_is_not_spoken_to() {
        let mut harness = Harness::new(b"file");
        harness.init_pp();
        harness.session.conn_mut().ftpc_mut().ctl_valid = true;
        disconnect(&mut harness, true).expect("never fails");
        assert_eq!(harness.sent_text(), "");
        assert!(!harness.session.conn().ftpc().ctl_valid);
    }

    /// Errors from the goodbye are discarded at the disconnect boundary.
    #[test]
    fn a_failed_goodbye_does_not_fail_the_disconnect() {
        let mut harness = Harness::new(b"file");
        harness.init_pp();
        harness.session.conn_mut().ftpc_mut().ctl_valid = true;
        // A `421` from any state is `CURLE_OPERATION_TIMEDOUT`, so the goodbye
        // reports an error -- which the disconnect discards, because
        // `ftp_disconnect` ends with *"ignore errors on the QUIT"*.
        harness.feed(b"421 service closing\r\n");
        disconnect(&mut harness, false).expect("errors are ignored here");
        assert_eq!(harness.sent_text(), "QUIT\r\n");
        assert!(harness.session.conn().ftpc().shutdown);
    }

    // -- Phase 12: the connection-reuse predicate --------------------------

    /// A candidate without FTP state cannot match.
    #[test]
    fn a_connection_without_ftp_state_never_matches() {
        let state = FtpConnState::default();
        assert!(!ftp_conns_match(None, None));
        assert!(!ftp_conns_match(Some(&state), None));
        assert!(!ftp_conns_match(None, Some(&state)));
        assert!(ftp_conns_match(Some(&state), Some(&state)));
    }

    /// All four fields must agree, and each one alone can refuse.
    #[test]
    fn all_four_reuse_fields_must_agree() {
        let base = || FtpConnState {
            account: Some(b"acct".to_vec()),
            alternative_to_user: Some(b"SITE X".to_vec()),
            use_ssl: UseSsl::Control,
            ccc: CccMode::Passive,
            ..FtpConnState::default()
        };
        assert!(ftp_conns_match(Some(&base()), Some(&base())));

        let mut other = base();
        other.account = Some(b"different".to_vec());
        assert!(!ftp_conns_match(Some(&base()), Some(&other)));

        let mut other = base();
        other.account = None;
        assert!(!ftp_conns_match(Some(&base()), Some(&other)));

        let mut other = base();
        other.alternative_to_user = Some(b"SITE Y".to_vec());
        assert!(!ftp_conns_match(Some(&base()), Some(&other)));

        let mut other = base();
        other.alternative_to_user = None;
        assert!(!ftp_conns_match(Some(&base()), Some(&other)));

        let mut other = base();
        other.use_ssl = UseSsl::All;
        assert!(!ftp_conns_match(Some(&base()), Some(&other)));

        let mut other = base();
        other.ccc = CccMode::Active;
        assert!(!ftp_conns_match(Some(&base()), Some(&other)));
    }

    /// Two connections with no credentials at all match.
    #[test]
    fn two_credential_free_connections_match() {
        let left = FtpConnState::default();
        let right = FtpConnState::default();
        assert!(ftp_conns_match(Some(&left), Some(&right)));
    }

    /// The credential-like fields are compared with the repository's
    /// constant-time comparator, not with `==`.
    #[test]
    fn the_credential_fields_are_compared_in_constant_time() {
        let source = code_only();
        let predicate = source
            .split("pub(crate) fn ftp_conns_match(")
            .nth(1)
            .expect("the predicate")
            .split("\n}\n")
            .next()
            .expect("its body");
        assert_eq!(
            predicate.matches("timestrcmp(").count(),
            2,
            "both credential-like fields go through the constant-time \\
             comparator"
        );
        // And the comparator itself agrees with equality on the cases above,
        // which is what makes the substitution behaviour-preserving.
        assert_eq!(timestrcmp(Some(b"acct"), Some(b"acct")), 0);
        assert_ne!(timestrcmp(Some(b"acct"), Some(b"acc")), 0);
        assert_eq!(timestrcmp(None, None), 0);
        assert_ne!(timestrcmp(Some(b"acct"), None), 0);
    }

    // -- Phase 12: the wildcard driver --------------------------------------

    /// One `wc_statemach` lap.
    fn wc_lap(harness: &mut Harness) -> CurlResult<()> {
        let mut io = FtpIo::new(
            &mut harness.chains,
            harness.clock.as_ref(),
            &mut harness.client,
        );
        wc_statemach(&mut harness.session, &mut io)
    }

    /// One `init_wc_data` call.
    fn wc_init(harness: &mut Harness) -> CurlResult<()> {
        let mut io = FtpIo::new(
            &mut harness.chains,
            harness.clock.as_ref(),
            &mut harness.client,
        );
        init_wc_data(&mut harness.session, &mut io)
    }

    /// A harness whose transfer is a wildcard match of `path`.
    fn wildcard_harness(path: &[u8]) -> Harness {
        let mut harness = Harness::new(path);
        harness.client.req.wildcardmatch = true;
        harness
    }

    /// A listing entry, built directly rather than parsed, for the arms that
    /// are about the queue and not about the parser.
    fn entry(
        name: &str,
        filetype: FileType,
        size: i64,
        known: bool,
    ) -> FileInfo {
        FileInfo {
            filename: name.to_owned(),
            filetype,
            size,
            flags: if known { FileInfo::KNOWN_SIZE } else { 0 },
            ..FileInfo::default()
        }
    }

    /// Seeds a wildcard already past matching, with `names` queued in order.
    fn seed_queue(harness: &mut Harness, names: &[&str]) {
        let wildcard = harness.session.wildcard_mut();
        wildcard.path = Some("pub/".to_owned());
        wildcard.pattern = Some("*".to_owned());
        wildcard.ftpwc = Some(FtpWildcard::new(b"*"));
        wildcard.state = WildcardState::Downloading;
        for name in names {
            wildcard
                .filelist
                .push_back(entry(name, FileType::File, 8, false));
        }
    }

    /// The eight states are the sibling's, at the C's integers.
    #[test]
    fn the_eight_wildcard_states_come_from_the_sibling() {
        assert_eq!(WildcardState::VARIANTS.len(), 8);
        assert_eq!(WildcardState::Clear.as_u8(), 0);
        assert_eq!(WildcardState::Init.as_u8(), 1);
        assert_eq!(WildcardState::Matching.as_u8(), 2);
        assert_eq!(WildcardState::Downloading.as_u8(), 3);
        assert_eq!(WildcardState::Clean.as_u8(), 4);
        assert_eq!(WildcardState::Skip.as_u8(), 5);
        assert_eq!(WildcardState::Error.as_u8(), 6);
        assert_eq!(WildcardState::Done.as_u8(), 7);
        assert_eq!(
            WildcardData::default().state,
            WildcardState::Init,
            "`Curl_wildcard_init` leaves INIT behind"
        );
    }

    /// The pattern is the text after the last slash, and it is cut from the
    /// directory.
    #[test]
    fn the_pattern_is_the_text_after_the_last_slash() {
        let mut harness = wildcard_harness(b"pub/incoming/*.txt");
        wc_init(&mut harness).expect("initialised");
        assert_eq!(
            harness.session.wildcard().pattern.as_deref(),
            Some("*.txt")
        );
        assert_eq!(
            harness.session.wildcard().path.as_deref(),
            Some("pub/incoming/"),
            "the pattern is cut, leaving the directory"
        );
        assert_eq!(harness.session.transfer().path(), b"pub/incoming/");
    }

    /// With no slash at all the whole path is the pattern.
    #[test]
    fn a_path_without_a_slash_is_all_pattern() {
        let mut harness = wildcard_harness(b"*.txt");
        wc_init(&mut harness).expect("initialised");
        assert_eq!(
            harness.session.wildcard().pattern.as_deref(),
            Some("*.txt")
        );
        assert_eq!(harness.session.wildcard().path.as_deref(), Some(""));
        assert_eq!(harness.session.transfer().path(), b"");
    }

    /// A path ending in a slash has no pattern: it is an ordinary listing, and
    /// the driver goes straight to CLEAN.
    #[test]
    fn a_trailing_slash_is_a_plain_listing() {
        let mut harness = wildcard_harness(b"pub/incoming/");
        wc_init(&mut harness).expect("only a listing");
        assert_eq!(harness.session.wildcard().state, WildcardState::Clean);
        assert!(harness.session.wildcard().pattern.is_none());
        assert!(
            harness.session.wildcard().ftpwc.is_none(),
            "no parser is allocated for a plain listing"
        );
        assert_eq!(
            harness.client.log.listing_installed, 0,
            "and no writer is displaced"
        );
        // The ordinary path parse still happened.
        assert_eq!(parsed(&harness).0, vec!["pub", "incoming"]);
    }

    /// An empty path is the same case.
    #[test]
    fn an_empty_path_is_a_plain_listing() {
        let mut harness = wildcard_harness(b"");
        wc_init(&mut harness).expect("only a listing");
        assert_eq!(harness.session.wildcard().state, WildcardState::Clean);
        assert!(harness.session.wildcard().ftpwc.is_none());
    }

    /// `NOCWD` is coerced to `MULTICWD` rather than refused.
    #[test]
    fn nocwd_is_coerced_to_multicwd_for_a_wildcard() {
        let mut harness = wildcard_harness(b"pub/*.txt");
        harness.client.req.file_method = FileMethod::NoCwd;
        wc_init(&mut harness).expect("initialised");
        assert_eq!(
            harness.client.req.file_method,
            FileMethod::MultiCwd,
            "`lib/ftp.c:3839-3841` coerces; it does not report an error"
        );
        // And the coercion took effect: the path was split into components.
        assert_eq!(parsed(&harness).0, vec!["pub"]);
    }

    /// Initialization displaces the writer exactly once and announces itself.
    #[test]
    fn initialization_displaces_the_writer_once() {
        let mut harness = wildcard_harness(b"pub/*.txt");
        wc_init(&mut harness).expect("initialised");
        assert_eq!(harness.client.log.listing_installed, 1);
        assert_eq!(harness.client.log.listing_restored, 0);
        assert!(harness.client.log.listing_live);
        assert_eq!(
            harness.client.log.info,
            vec![WILDCARD_PARSING_MESSAGE.to_owned()]
        );
        assert_eq!(WILDCARD_PARSING_MESSAGE, "Wildcard - Parsing started");
    }

    /// A path the parser refuses leaves no parser and no displaced writer
    /// behind.
    #[test]
    fn a_refused_path_leaves_nothing_installed() {
        let mut harness = wildcard_harness(b"pub/%00/*.txt");
        let error = wc_init(&mut harness).expect_err("control character");
        assert_eq!(error.code(), CURLcode::UrlMalformat);
        assert!(harness.session.wildcard().ftpwc.is_none());
        assert_eq!(
            harness.client.log.listing_installed, 0,
            "the writer is displaced only after the path parses"
        );
    }

    /// `INIT` reports CLEAN's outcome directly for a plain listing, and
    /// otherwise moves to MATCHING.
    #[test]
    fn init_leads_to_matching_or_straight_to_clean() {
        let mut harness = wildcard_harness(b"pub/incoming/");
        wc_lap(&mut harness).expect("only a listing");
        assert_eq!(harness.session.wildcard().state, WildcardState::Clean);

        let mut harness = wildcard_harness(b"pub/*.txt");
        wc_lap(&mut harness).expect("initialised");
        assert_eq!(harness.session.wildcard().state, WildcardState::Matching);

        let mut harness = wildcard_harness(b"pub/%00/*.txt");
        let _ = wc_lap(&mut harness).expect_err("control character");
        assert_eq!(harness.session.wildcard().state, WildcardState::Error);
    }

    /// A listing the parser matched becomes the transfer queue, in the server's
    /// order, and the writer goes back.
    #[test]
    fn matching_restores_the_writer_and_takes_the_queue() {
        const LISTING: &str = concat!(
            "-rw-r--r--   1 user group      100 Jan 29 23:32 alpha.txt\n",
            "-rw-r--r--   1 user group      200 Jan 29 23:32 beta.txt\n",
            "drwxr-xr-x   2 user group      512 Jan 29 23:32 sub\n",
            "-rw-r--r--   1 user group      300 Jan 29 23:32 gamma.txt\n",
        );
        let mut harness = wildcard_harness(b"pub/*.txt");
        wc_init(&mut harness).expect("initialised");
        if let Some(ftpwc) = harness.session.wildcard_mut().ftpwc.as_mut() {
            ftpwc.parser.push(LISTING.as_bytes()).expect("parsed");
        }
        harness.session.wildcard_mut().state = WildcardState::Matching;

        wc_lap(&mut harness).expect("a file is prepared");

        assert_eq!(harness.client.log.listing_restored, 1);
        assert!(!harness.client.log.listing_live);
        // MATCHING fell through to DOWNLOADING, which took the head; two
        // matches remain of the three the pattern accepted.
        assert_eq!(
            harness
                .session
                .wildcard()
                .filelist
                .iter()
                .map(|finfo| finfo.filename.clone())
                .collect::<Vec<_>>(),
            vec!["beta.txt".to_owned(), "gamma.txt".to_owned()],
            "arrival order is the transfer order"
        );
        assert_eq!(
            harness.client.log.chunk_bgn_calls,
            vec![("alpha.txt".to_owned(), 3)],
            "the count includes the entry being started"
        );
    }

    /// A parser that latched an error goes through CLEAN and reports it.
    #[test]
    fn a_parser_error_is_reported_through_clean() {
        let mut harness = wildcard_harness(b"pub/*.txt");
        wc_init(&mut harness).expect("initialised");
        if let Some(ftpwc) = harness.session.wildcard_mut().ftpwc.as_mut() {
            let _ = ftpwc.parser.push(b"this is not a listing at all\n");
        }
        harness.session.wildcard_mut().state = WildcardState::Matching;
        let error = wc_lap(&mut harness).expect_err("the parser latched");
        assert_ne!(error.code(), CURLcode::Ok);
        assert_eq!(harness.session.wildcard().state, WildcardState::Error);
        assert_eq!(
            harness.client.log.listing_restored, 1,
            "the writer goes back before the error is reported"
        );
    }

    /// A listing that matched nothing is a missing file, and CLEAN is where the
    /// driver leaves it.
    #[test]
    fn an_empty_match_is_a_missing_remote_file() {
        let mut harness = wildcard_harness(b"pub/*.zip");
        wc_init(&mut harness).expect("initialised");
        if let Some(ftpwc) = harness.session.wildcard_mut().ftpwc.as_mut() {
            ftpwc
                .parser
                .push(b"-rw-r--r--   1 u g   1 Jan 29 23:32 a.txt\n")
                .expect("parsed");
        }
        harness.session.wildcard_mut().state = WildcardState::Matching;
        let error = wc_lap(&mut harness).expect_err("nothing matched");
        assert_eq!(error.code(), CURLcode::RemoteFileNotFound);
        assert_eq!(harness.session.wildcard().state, WildcardState::Clean);
    }

    /// The concrete path is the directory and the filename concatenated, with
    /// nothing between them.
    #[test]
    fn the_concrete_path_is_a_plain_concatenation() {
        let mut harness = wildcard_harness(b"pub/*.txt");
        seed_queue(&mut harness, &["alpha.txt"]);
        wc_lap(&mut harness).expect("prepared");
        assert_eq!(
            harness.session.transfer().path(),
            b"pub/alpha.txt",
            "`\"%s%s\"` -- the directory already ends in its slash"
        );
        assert!(harness.session.transfer().has_path_override());
        assert_eq!(
            parsed(&harness),
            (vec!["pub".to_owned()], Some("alpha.txt".to_owned()))
        );
    }

    /// The remaining count counts the entry being started.
    #[test]
    fn the_remaining_count_includes_the_current_entry() {
        let mut harness = wildcard_harness(b"pub/*.txt");
        seed_queue(&mut harness, &["a", "b", "c"]);
        wc_lap(&mut harness).expect("prepared");
        assert_eq!(
            harness.client.log.chunk_bgn_calls,
            vec![("a".to_owned(), 3)]
        );
        wc_lap(&mut harness).expect("prepared");
        assert_eq!(
            harness.client.log.chunk_bgn_calls,
            vec![("a".to_owned(), 3), ("b".to_owned(), 2)]
        );
    }

    /// The queue head is removed once its transfer is prepared, and the last
    /// entry leaves CLEAN behind so the loop makes one final pass that transfers
    /// nothing.
    #[test]
    fn the_last_entry_leaves_clean_behind() {
        let mut harness = wildcard_harness(b"pub/*.txt");
        seed_queue(&mut harness, &["only.txt"]);
        wc_lap(&mut harness).expect("prepared");
        assert!(harness.session.wildcard().filelist.is_empty());
        assert_eq!(harness.session.wildcard().state, WildcardState::Clean);
        // The final pass releases the parser and reports the parser's verdict.
        wc_lap(&mut harness).expect("nothing left to do");
        assert_eq!(harness.session.wildcard().state, WildcardState::Done);
        wc_lap(&mut harness).expect("idempotent");
        assert!(harness.session.wildcard().ftpwc.is_none());
    }

    /// A skip asked for by the callback runs the chunk-end callback and moves
    /// on.
    #[test]
    fn a_skipped_entry_runs_the_end_callback_and_moves_on() {
        let mut harness = wildcard_harness(b"pub/*.txt");
        seed_queue(&mut harness, &["skipme", "next"]);
        harness.client.log.chunk_bgn.push_back(ChunkBgn::Skip);
        wc_lap(&mut harness).expect("prepared the next one");
        assert!(harness
            .client
            .log
            .info
            .iter()
            .any(|line| line == "Wildcard - \"skipme\" skipped by user"));
        assert_eq!(harness.client.log.chunk_end_calls, 1);
        assert_eq!(
            harness.session.transfer().path(),
            b"pub/next",
            "the skip fell through to the next entry in the same lap"
        );
    }

    /// A skip of the only entry ends the wildcard.
    #[test]
    fn a_skip_of_the_last_entry_ends_the_wildcard() {
        let mut harness = wildcard_harness(b"pub/*.txt");
        seed_queue(&mut harness, &["skipme"]);
        harness.client.log.chunk_bgn.push_back(ChunkBgn::Skip);
        wc_lap(&mut harness).expect("nothing left");
        assert_eq!(harness.session.wildcard().state, WildcardState::Done);
        assert!(harness.session.wildcard().filelist.is_empty());
    }

    /// A missing chunk-end callback is not an error.
    #[test]
    fn a_skip_without_an_end_callback_is_fine() {
        let mut harness = wildcard_harness(b"pub/*.txt");
        seed_queue(&mut harness, &["skipme"]);
        harness.client.log.chunk_bgn.push_back(ChunkBgn::Skip);
        harness.client.log.chunk_end_absent = true;
        wc_lap(&mut harness).expect("nothing left");
        assert_eq!(harness.client.log.chunk_end_calls, 0);
    }

    /// A refusal from the callback fails the transfer.
    #[test]
    fn a_refused_entry_is_a_chunk_failure() {
        let mut harness = wildcard_harness(b"pub/*.txt");
        seed_queue(&mut harness, &["nope"]);
        harness.client.log.chunk_bgn.push_back(ChunkBgn::Fail);
        let error = wc_lap(&mut harness).expect_err("refused");
        assert_eq!(error.code(), CURLcode::ChunkFailed);
    }

    /// Anything that is not a regular file is skipped, callback or no callback.
    #[test]
    fn a_directory_entry_is_skipped() {
        let mut harness = wildcard_harness(b"pub/*");
        {
            let wildcard = harness.session.wildcard_mut();
            wildcard.path = Some("pub/".to_owned());
            wildcard.ftpwc = Some(FtpWildcard::new(b"*"));
            wildcard.state = WildcardState::Downloading;
            wildcard.filelist.push_back(entry(
                "sub",
                FileType::Directory,
                512,
                true,
            ));
            wildcard.filelist.push_back(entry(
                "real.txt",
                FileType::File,
                10,
                true,
            ));
        }
        harness.client.log.chunk_end_absent = true;
        wc_lap(&mut harness).expect("prepared the file");
        assert_eq!(harness.session.transfer().path(), b"pub/real.txt");
        assert_eq!(
            harness.session.conn().ftpc().known_filesize,
            10,
            "the size came from the listing entry, not from a SIZE reply"
        );
    }

    /// A symlink is skipped too.
    #[test]
    fn a_symlink_entry_is_skipped() {
        let mut harness = wildcard_harness(b"pub/*");
        {
            let wildcard = harness.session.wildcard_mut();
            wildcard.path = Some("pub/".to_owned());
            wildcard.ftpwc = Some(FtpWildcard::new(b"*"));
            wildcard.state = WildcardState::Downloading;
            wildcard.filelist.push_back(entry(
                "link",
                FileType::Symlink,
                0,
                false,
            ));
        }
        harness.client.log.chunk_end_absent = true;
        wc_lap(&mut harness).expect("nothing transferable");
        assert_eq!(harness.session.wildcard().state, WildcardState::Done);
    }

    /// An entry whose size is unknown leaves the known size alone.
    #[test]
    fn an_unsized_entry_leaves_the_known_size_unset() {
        let mut harness = wildcard_harness(b"pub/*.txt");
        seed_queue(&mut harness, &["alpha.txt"]);
        wc_lap(&mut harness).expect("prepared");
        assert_eq!(
            harness.session.conn().ftpc().known_filesize,
            -1,
            "without the flag the C copies nothing"
        );
    }

    /// A known size becomes the connection's, which is what lets `RETR` skip
    /// `SIZE`.
    #[test]
    fn a_known_size_reaches_the_connection_state() {
        let mut harness = wildcard_harness(b"pub/*.txt");
        {
            let wildcard = harness.session.wildcard_mut();
            wildcard.path = Some("pub/".to_owned());
            wildcard.ftpwc = Some(FtpWildcard::new(b"*"));
            wildcard.state = WildcardState::Downloading;
            wildcard.filelist.push_back(entry(
                "alpha.txt",
                FileType::File,
                4096,
                true,
            ));
        }
        wc_lap(&mut harness).expect("prepared");
        assert_eq!(harness.session.conn().ftpc().known_filesize, 4096);
    }

    /// The completed transfer's chunk-end callback runs in `ftp_done`, and the
    /// known size is released there.
    #[test]
    fn a_completed_wildcard_transfer_ends_its_chunk_in_done() {
        let mut harness = wildcard_harness(b"pub/*.txt");
        seed_queue(&mut harness, &["alpha.txt"]);
        wc_lap(&mut harness).expect("prepared");
        harness.init_pp();
        harness.session.conn_mut().ftpc_mut().known_filesize = 4096;
        done(&mut harness, CURLcode::Ok, false).expect("clean");
        assert_eq!(
            harness.client.log.chunk_end_calls, 1,
            "`lib/ftp.c:3555-3563` ends the chunk once the file is done"
        );
        assert_eq!(harness.session.conn().ftpc().known_filesize, -1);
    }

    /// `ftp_done` runs no chunk-end callback when no concrete file was in
    /// progress.
    #[test]
    fn done_ends_no_chunk_without_a_file() {
        let mut harness = wildcard_harness(b"pub/");
        harness.init_pp();
        parse_path(&mut harness).expect("parsed");
        done(&mut harness, CURLcode::Ok, false).expect("clean");
        assert_eq!(harness.client.log.chunk_end_calls, 0);
    }

    /// The terminal states release the parser and are idempotent.
    #[test]
    fn the_terminal_states_release_the_parser() {
        for state in [
            WildcardState::Done,
            WildcardState::Error,
            WildcardState::Clear,
        ] {
            let mut harness = wildcard_harness(b"pub/*.txt");
            harness.session.wildcard_mut().ftpwc = Some(FtpWildcard::new(b"*"));
            harness.session.wildcard_mut().state = state;
            wc_lap(&mut harness).expect("terminal");
            assert!(
                harness.session.wildcard().ftpwc.is_none(),
                "{state:?} releases the parser"
            );
            assert_eq!(harness.session.wildcard().state, state);
        }
    }

    /// The whole driver, over a listing, in the order the server gave.
    #[test]
    fn the_driver_walks_a_listing_in_order() {
        const LISTING: &str = concat!(
            "-rw-r--r--   1 u g  1 Jan 29 23:32 one.txt\n",
            "-rw-r--r--   1 u g  2 Jan 29 23:32 two.txt\n",
            "-rw-r--r--   1 u g  3 Jan 29 23:32 three.txt\n",
        );
        let mut harness = wildcard_harness(b"pub/*.txt");
        wc_lap(&mut harness).expect("initialised");
        assert_eq!(harness.session.wildcard().state, WildcardState::Matching);
        if let Some(ftpwc) = harness.session.wildcard_mut().ftpwc.as_mut() {
            ftpwc.parser.push(LISTING.as_bytes()).expect("parsed");
        }

        let mut visited = Vec::new();
        for _ in 0..4_u8 {
            wc_lap(&mut harness).expect("a lap");
            let path = harness.session.transfer().path().to_vec();
            let text = String::from_utf8_lossy(&path).into_owned();
            if !visited.last().is_some_and(|last| last == &text) {
                visited.push(text);
            }
            if harness.session.wildcard().state == WildcardState::Done {
                break;
            }
        }
        assert_eq!(
            visited,
            vec![
                "pub/one.txt".to_owned(),
                "pub/two.txt".to_owned(),
                "pub/three.txt".to_owned(),
            ]
        );
        assert_eq!(
            harness
                .client
                .log
                .chunk_bgn_calls
                .iter()
                .map(|(name, remaining)| (name.as_str(), *remaining))
                .collect::<Vec<_>>(),
            vec![("one.txt", 3), ("two.txt", 2), ("three.txt", 1)]
        );
        assert_eq!(harness.session.wildcard().state, WildcardState::Done);
    }

    // -- Phase 12: the immutable fixtures, driven end to end ----------------
    //
    // Each test below reproduces one `tests/data/test*` `<protocol>` block --
    // the bytes the harness compares against, joined into one string by
    // `tests/getpart.pm:351+` and therefore order-, case- and
    // terminator-significant. The fixtures are read-only inputs: an assertion
    // here that disagrees with one is an implementation defect, never a reason
    // to touch the fixture.
    //
    // `%TESTNUMBER` is substituted by the harness; the literal number appears
    // below because that is what reaches the wire.
    //
    // Three files named in this module's source lineage carry no FTP command
    // stream and so have nothing to assert here: `tests/data/test576` is a
    // wildcard transfer verified through its chunk callbacks and has no
    // `<protocol>` block at all, and `tests/data/test779` and
    // `tests/data/test2074` are bearer-token fixtures over IMAP and HTTP. The
    // wildcard sequence `test576` exercises is pinned by `test574` below.

    /// Runs the login half of a session, leaving the connect phase finished.
    fn login(harness: &mut Harness) {
        harness.feed(b"220 ready\r\n");
        let _ = connect(harness).expect("the greeting is scripted");
        harness.feed(b"331 give me a password\r\n");
        harness.feed(b"230 logged in\r\n");
        harness.feed(b"257 \"/\" is the current directory\r\n");
        pump(harness, 8);
        assert_eq!(harness.state(), FtpState::Stop, "the login finished");
    }

    /// Sends `QUIT` and consumes its reply.
    fn goodbye(harness: &mut Harness) {
        harness.session.conn_mut().ftpc_mut().ctl_valid = true;
        harness.feed(b"221 bye\r\n");
        quit(harness).expect("the goodbye is scripted");
    }

    /// Scripts `replies` and drives the DO phase to its end.
    ///
    /// The replies are queued BEFORE the phase starts, because the cadence
    /// engine waits for readiness when its buffer runs dry and this suite has no
    /// runtime to wait in. Queueing several at once is safe: FTP forbids
    /// pipelining in exactly one state, the reply to `AUTH`
    /// (`lib/ftp.c:2884-2889`), and the tests that exercise it feed one at a
    /// time.
    fn do_phase(harness: &mut Harness, replies: &[&[u8]]) {
        for reply in replies {
            harness.feed(reply);
        }
        // One reply per lap, as `Curl_pp_statemach` does, and a lap only while
        // something is there to read -- which is the multi loop's own condition,
        // `Curl_socket_check` answering that the control socket is readable.
        let mut done = do_it(harness).expect("the DO phase is scripted");
        let mut laps = 0_u8;
        while !done && harness.has_more_input() && laps < 32 {
            done = doing(harness).expect("the DO phase is scripted");
            laps = laps.saturating_add(1);
        }
        assert_eq!(
            harness.state(),
            FtpState::Stop,
            "the DO phase settled; the wire so far is {:?}",
            harness.sent_text()
        );
    }

    /// Finishes one transfer the way the multi loop finishes one.
    ///
    /// `ftp_done` is not optional between two transfers over one connection: it
    /// is what remembers the working directory in `prevpath`, and
    /// `ftp_parse_url_path` consults that -- together with the reuse flag the
    /// next lap through `MSTATE_INIT` sets (`lib/multi.c`'s wildcard branch
    /// returns to it) -- to decide that the directory walk can be skipped
    /// (`lib/ftp.c:316-333`). A test that skipped the completion would see a
    /// second set of `CWD`s that curl does not send.
    fn finish_transfer(harness: &mut Harness) {
        harness.session.conn_mut().ftpc_mut().ctl_valid = true;
        harness.client.req.bytecount = harness.client.req.size;
        harness.feed(b"226 Transfer complete\r\n");
        done(harness, CURLcode::Ok, false).expect("the transfer finished");
        harness.client.req.reuse = true;
    }

    /// Scripts `replies` and drives DO_MORE until it advances.
    fn do_more_phase(harness: &mut Harness, replies: &[&[u8]]) {
        for reply in replies {
            harness.feed(reply);
        }
        do_more_until_advance(harness, 16);
    }

    /// `tests/data/test100` -- a directory listing.
    ///
    /// ```text
    /// USER anonymous / PASS ftp@example.com / PWD / CWD test-100
    /// EPSV / TYPE A / LIST / QUIT
    /// ```
    #[test]
    fn test100_lists_a_directory() {
        let mut harness = Harness::new(b"test-100/");
        login(&mut harness);

        do_phase(
            &mut harness,
            &[
                b"250 CWD command successful\r\n",
                b"229 Entering Extended Passive Mode (|||8888|)\r\n",
            ],
        );
        do_more_phase(
            &mut harness,
            &[
                b"200 Type set to A\r\n",
                b"150 Opening ASCII mode data connection\r\n",
            ],
        );
        goodbye(&mut harness);

        assert_eq!(
            harness.sent_text(),
            concat!(
                "USER anonymous\r\n",
                "PASS ftp@example.com\r\n",
                "PWD\r\n",
                "CWD test-100\r\n",
                "EPSV\r\n",
                "TYPE A\r\n",
                "LIST\r\n",
                "QUIT\r\n",
            )
        );
    }

    /// `tests/data/test101` -- an active listing of the root, with `-P`.
    ///
    /// ```text
    /// USER anonymous / PASS ftp@example.com / PWD
    /// PORT 127,0,0,1,243,212 / TYPE A / LIST / QUIT
    /// ```
    ///
    /// No `CWD`, because the path is the root, and no `EPSV`, because `-P`
    /// selects active mode. `243,212` is port 62420, which is what the harness's
    /// listener happened to bind.
    #[test]
    fn test101_lists_the_root_actively() {
        let mut harness = Harness::new(b"");
        harness.client.opts.use_port = true;
        harness.client.opts.ftpport = Some(b"127.0.0.1".to_vec());
        harness.client.req.use_eprt = false;
        harness.seams.borrow_mut().bind_script.push_back(Ok(62420));
        login(&mut harness);

        do_phase(&mut harness, &[b"200 PORT command successful\r\n"]);
        do_more_phase(
            &mut harness,
            &[
                b"200 Type set to A\r\n",
                b"150 Opening ASCII mode data connection\r\n",
            ],
        );
        goodbye(&mut harness);

        assert_eq!(
            harness.sent_text(),
            concat!(
                "USER anonymous\r\n",
                "PASS ftp@example.com\r\n",
                "PWD\r\n",
                "PORT 127,0,0,1,243,212\r\n",
                "TYPE A\r\n",
                "LIST\r\n",
                "QUIT\r\n",
            )
        );
    }

    /// `tests/data/test102` -- `EPSV` refused, then `PASV`.
    ///
    /// ```text
    /// USER anonymous / PASS ftp@example.com / PWD
    /// EPSV / PASV / TYPE I / SIZE 102 / RETR 102 / QUIT
    /// ```
    #[test]
    fn test102_falls_back_from_epsv_to_pasv() {
        let mut harness = Harness::new(b"102");
        login(&mut harness);

        do_phase(
            &mut harness,
            &[
                b"500 unknown command\r\n",
                b"227 Entering Passive Mode (127,0,0,1,34,187)\r\n",
            ],
        );
        do_more_phase(
            &mut harness,
            &[
                b"200 Type set to I\r\n",
                b"213 4096\r\n",
                b"150 Opening BINARY mode data connection\r\n",
            ],
        );
        goodbye(&mut harness);

        assert_eq!(
            harness.sent_text(),
            concat!(
                "USER anonymous\r\n",
                "PASS ftp@example.com\r\n",
                "PWD\r\n",
                "EPSV\r\n",
                "PASV\r\n",
                "TYPE I\r\n",
                "SIZE 102\r\n",
                "RETR 102\r\n",
                "QUIT\r\n",
            )
        );
    }

    /// `tests/data/test104` -- `--head` over two directories.
    ///
    /// ```text
    /// USER anonymous / PASS ftp@example.com / PWD / CWD a / CWD path
    /// MDTM 104 / TYPE I / SIZE 104 / REST 0 / QUIT
    /// ```
    ///
    /// No data channel at all: a headers-only transfer settles the timestamp,
    /// the size and whether ranges are supported, and stops.
    #[test]
    fn test104_asks_only_for_the_headers() {
        let mut harness = Harness::new(b"a/path/104");
        harness.client.opts.no_body = true;
        harness.client.opts.get_filetime = true;
        login(&mut harness);

        do_phase(
            &mut harness,
            &[
                b"250 CWD command successful\r\n",
                b"250 CWD command successful\r\n",
                b"213 20030405060708\r\n",
                b"200 Type set to I\r\n",
                b"213 4096\r\n",
                b"350 Restarting at 0\r\n",
            ],
        );
        goodbye(&mut harness);

        assert_eq!(
            harness.sent_text(),
            concat!(
                "USER anonymous\r\n",
                "PASS ftp@example.com\r\n",
                "PWD\r\n",
                "CWD a\r\n",
                "CWD path\r\n",
                "MDTM 104\r\n",
                "TYPE I\r\n",
                "SIZE 104\r\n",
                "REST 0\r\n",
                "QUIT\r\n",
            )
        );
    }

    /// `tests/data/test141` -- `-I` over one directory, the same shape as
    /// `test104` with a single `CWD`.
    #[test]
    fn test141_asks_only_for_the_headers_of_one_directory() {
        let mut harness = Harness::new(b"blalbla/141");
        harness.client.opts.no_body = true;
        harness.client.opts.get_filetime = true;
        login(&mut harness);

        do_phase(
            &mut harness,
            &[
                b"250 CWD command successful\r\n",
                b"213 20030405060708\r\n",
                b"200 Type set to I\r\n",
                b"213 4096\r\n",
                b"350 Restarting at 0\r\n",
            ],
        );
        goodbye(&mut harness);

        assert_eq!(
            harness.sent_text(),
            concat!(
                "USER anonymous\r\n",
                "PASS ftp@example.com\r\n",
                "PWD\r\n",
                "CWD blalbla\r\n",
                "MDTM 141\r\n",
                "TYPE I\r\n",
                "SIZE 141\r\n",
                "REST 0\r\n",
                "QUIT\r\n",
            )
        );
    }

    /// `tests/data/test105` -- named credentials, `--use-ascii`.
    ///
    /// ```text
    /// USER userdude / PASS passfellow / PWD
    /// EPSV / PASV / TYPE A / RETR 105 / QUIT
    /// ```
    ///
    /// No `SIZE`: an ASCII transfer's byte count on the wire is not the file's,
    /// so the C does not ask.
    #[test]
    fn test105_fetches_a_file_in_ascii_mode() {
        let mut harness = Harness::new(b"105");
        harness.client.opts.user = b"userdude".to_vec();
        harness.client.opts.password = b"passfellow".to_vec();
        harness.client.req.prefer_ascii = true;
        login(&mut harness);

        do_phase(
            &mut harness,
            &[
                b"500 unknown command\r\n",
                b"227 Entering Passive Mode (127,0,0,1,34,187)\r\n",
            ],
        );
        do_more_phase(
            &mut harness,
            &[
                b"200 Type set to A\r\n",
                b"150 Opening ASCII mode data connection\r\n",
            ],
        );
        goodbye(&mut harness);

        assert_eq!(
            harness.sent_text(),
            concat!(
                "USER userdude\r\n",
                "PASS passfellow\r\n",
                "PWD\r\n",
                "EPSV\r\n",
                "PASV\r\n",
                "TYPE A\r\n",
                "RETR 105\r\n",
                "QUIT\r\n",
            )
        );
    }

    /// `tests/data/test1107` -- `PRET` before the passive setup.
    ///
    /// ```text
    /// USER anonymous / PASS ftp@example.com / PWD / PRET RETR 1107
    /// EPSV / TYPE I / SIZE 1107 / RETR 1107 / QUIT
    /// ```
    #[test]
    fn test1107_prepares_the_server_before_going_passive() {
        let mut harness = Harness::new(b"1107");
        harness.client.opts.use_pret = true;
        login(&mut harness);

        do_phase(
            &mut harness,
            &[
                b"200 PRET command successful\r\n",
                b"229 Entering Extended Passive Mode (|||8888|)\r\n",
            ],
        );
        do_more_phase(
            &mut harness,
            &[
                b"200 Type set to I\r\n",
                b"213 4096\r\n",
                b"150 Opening BINARY mode data connection\r\n",
            ],
        );
        goodbye(&mut harness);

        assert_eq!(
            harness.sent_text(),
            concat!(
                "USER anonymous\r\n",
                "PASS ftp@example.com\r\n",
                "PWD\r\n",
                "PRET RETR 1107\r\n",
                "EPSV\r\n",
                "TYPE I\r\n",
                "SIZE 1107\r\n",
                "RETR 1107\r\n",
                "QUIT\r\n",
            )
        );
    }

    /// A secure session whose control channel is already up, as the three
    /// `test40x` fixtures reach the login.
    fn secure_login(harness: &mut Harness) {
        harness.client.req.control_ssl = true;
        harness.feed(b"220 ready\r\n");
        let _ = connect(harness).expect("the greeting is scripted");
        harness.feed(b"331 give me a password\r\n");
        harness.feed(b"230 logged in\r\n");
    }

    /// `tests/data/test400` -- explicit FTPS, control-only protection.
    ///
    /// ```text
    /// USER anonymous / PASS ftp@example.com / PBSZ 0 / PROT C / PWD
    /// EPSV / TYPE A / LIST / QUIT
    /// ```
    ///
    /// `PBSZ` and `PROT` sit between the login and `PWD`, which is where the C
    /// puts them and where the fixture pins them.
    #[test]
    fn test400_protects_the_control_channel_only() {
        let mut harness = Harness::new(b"");
        harness.client.opts.use_ssl = UseSsl::Control;
        secure_login(&mut harness);
        harness.feed(b"200 PBSZ=0\r\n");
        harness.feed(b"200 PROT command successful\r\n");
        harness.feed(b"257 \"/\" is the current directory\r\n");
        pump(&mut harness, 10);
        assert_eq!(harness.state(), FtpState::Stop);

        do_phase(
            &mut harness,
            &[b"229 Entering Extended Passive Mode (|||8888|)\r\n"],
        );
        do_more_phase(
            &mut harness,
            &[
                b"200 Type set to A\r\n",
                b"150 Opening ASCII mode data connection\r\n",
            ],
        );
        goodbye(&mut harness);

        assert_eq!(
            harness.sent_text(),
            concat!(
                "USER anonymous\r\n",
                "PASS ftp@example.com\r\n",
                "PBSZ 0\r\n",
                "PROT C\r\n",
                "PWD\r\n",
                "EPSV\r\n",
                "TYPE A\r\n",
                "LIST\r\n",
                "QUIT\r\n",
            )
        );
        assert!(
            harness.seams.borrow().tls_added.is_empty(),
            "`PROT C` leaves the data channel in the clear"
        );
    }

    /// `tests/data/test401` -- explicit FTPS, uploading.
    ///
    /// ```text
    /// USER anonymous / PASS ftp@example.com / PBSZ 0 / PROT C / PWD
    /// EPSV / TYPE I / STOR 401 / QUIT
    /// ```
    #[test]
    fn test401_uploads_over_a_protected_control_channel() {
        let mut harness = Harness::new(b"401");
        harness.client.opts.use_ssl = UseSsl::Control;
        harness.client.req.upload = true;
        harness.client.req.infilesize = 16;
        secure_login(&mut harness);
        harness.feed(b"200 PBSZ=0\r\n");
        harness.feed(b"200 PROT command successful\r\n");
        harness.feed(b"257 \"/\" is the current directory\r\n");
        pump(&mut harness, 10);

        do_phase(
            &mut harness,
            &[b"229 Entering Extended Passive Mode (|||8888|)\r\n"],
        );
        do_more_phase(
            &mut harness,
            &[b"200 Type set to I\r\n", b"150 Ok to send data\r\n"],
        );
        goodbye(&mut harness);

        assert_eq!(
            harness.sent_text(),
            concat!(
                "USER anonymous\r\n",
                "PASS ftp@example.com\r\n",
                "PBSZ 0\r\n",
                "PROT C\r\n",
                "PWD\r\n",
                "EPSV\r\n",
                "TYPE I\r\n",
                "STOR 401\r\n",
                "QUIT\r\n",
            )
        );
    }

    /// `tests/data/test402` -- both `AUTH` attempts refused.
    ///
    /// ```text
    /// AUTH SSL
    /// AUTH TLS
    /// ```
    ///
    /// The whole fixture: a server that refuses both spellings never sees a
    /// `USER`, and the transfer fails with the requested protection unmet.
    #[test]
    fn test402_tries_both_auth_spellings_and_stops() {
        let mut harness = Harness::new(b"402");
        harness.client.opts.use_ssl = UseSsl::All;
        harness.feed(b"220 ready\r\n");
        let _ = connect(&mut harness).expect("the greeting is scripted");
        // One reply at a time: the C forbids pipelining in this state
        // (`lib/ftp.c:2884-2889`), so a second reply already in the buffer is
        // itself an error and would mask the one under test.
        harness.feed(b"500 unknown command\r\n");
        harness
            .step()
            .expect("the first refusal tries the other spelling");
        harness.feed(b"500 unknown command\r\n");
        let error = harness.step().expect_err("both spellings were refused");
        assert_eq!(error.code(), CURLcode::UseSslFailed);
        assert_eq!(harness.sent_text(), "AUTH SSL\r\nAUTH TLS\r\n");
    }

    /// `tests/data/test403` -- `CCC` after the protection is established.
    ///
    /// ```text
    /// USER anonymous / PASS ftp@example.com / PBSZ 0 / PROT C / CCC / PWD
    /// EPSV / TYPE A / LIST / QUIT
    /// ```
    #[test]
    fn test403_clears_the_command_channel() {
        let mut harness = Harness::new(b"");
        harness.client.opts.use_ssl = UseSsl::Control;
        harness.client.opts.ccc = CccMode::Passive;
        secure_login(&mut harness);
        harness.feed(b"200 PBSZ=0\r\n");
        harness.feed(b"200 PROT command successful\r\n");
        harness.feed(b"200 CCC command successful\r\n");
        harness.feed(b"257 \"/\" is the current directory\r\n");
        pump(&mut harness, 12);
        assert_eq!(harness.state(), FtpState::Stop);

        do_phase(
            &mut harness,
            &[b"229 Entering Extended Passive Mode (|||8888|)\r\n"],
        );
        do_more_phase(
            &mut harness,
            &[
                b"200 Type set to A\r\n",
                b"150 Opening ASCII mode data connection\r\n",
            ],
        );
        goodbye(&mut harness);

        assert_eq!(
            harness.sent_text(),
            concat!(
                "USER anonymous\r\n",
                "PASS ftp@example.com\r\n",
                "PBSZ 0\r\n",
                "PROT C\r\n",
                "CCC\r\n",
                "PWD\r\n",
                "EPSV\r\n",
                "TYPE A\r\n",
                "LIST\r\n",
                "QUIT\r\n",
            )
        );
        assert_eq!(
            harness.seams.borrow().tls_removed,
            vec![(SocketIndex::First, false)],
            "the control filter came off, passively"
        );
    }

    /// A matcher that accepts every filename, as `tests/libtest/lib574.c`'s
    /// `CURLOPT_FNMATCH_FUNCTION` does.
    #[derive(Debug, Default)]
    struct AcceptEverything {
        /// Every `(pattern, filename)` pair it was asked about.
        asked: Vec<(Vec<u8>, Vec<u8>)>,
        /// The in-callback guard's transitions, in order.
        guard: Vec<bool>,
    }

    impl listparser::FilenameMatcher for AcceptEverything {
        fn compare(&mut self, pattern: &[u8], filename: &[u8]) -> i32 {
            self.asked.push((pattern.to_vec(), filename.to_vec()));
            0
        }

        fn set_in_callback(&mut self, inside: bool) {
            self.guard.push(inside);
        }
    }

    /// Drives one whole wildcard download, from the driver's INIT to the last
    /// match, and answers the names it fetched.
    ///
    /// `listing` reaches the parser through `matcher`, which is how
    /// `CURLOPT_FNMATCH_FUNCTION` reaches it in the C, and `listing_replies`
    /// scripts the listing transfer's DO phase -- which includes the directory
    /// walk on the first perform and nothing but the passive reply on a later
    /// one, because the connection is reused by then.
    fn wildcard_cycle(
        harness: &mut Harness,
        listing: &str,
        matcher: &mut AcceptEverything,
        listing_replies: &[&[u8]],
        matches: usize,
    ) -> Vec<String> {
        // The listing transfer. `ftp_do` runs the wildcard driver itself
        // (`lib/ftp.c:4066-4079`): INIT installs the parser and falls through to
        // the ordinary transfer, which walks into the directory on the first
        // perform and asks for `LIST` over a data channel.
        do_phase(harness, listing_replies);
        assert_eq!(
            harness.session.wildcard().state,
            WildcardState::Matching,
            "INIT led to MATCHING and the listing transfer went ahead"
        );
        do_more_phase(
            harness,
            &[
                b"200 Type set to A\r\n",
                b"150 Opening ASCII mode data connection\r\n",
            ],
        );

        // The server's listing arrives through the parser the driver installed,
        // and the custom matcher decides what it accepts.
        if let Some(ftpwc) = harness.session.wildcard_mut().ftpwc.as_mut() {
            ftpwc
                .parser
                .push_matching(listing.as_bytes(), matcher)
                .expect("the listing parses");
        }
        finish_transfer(harness);

        // One transfer per match, each with a data channel of its own. The
        // first of them always sends `TYPE I`, in every perform: the listing
        // transfer just before it set the mode to `A`, so the mode genuinely has
        // to change again -- which is why the fixture holds one `TYPE A` and one
        // `TYPE I` per perform rather than one of each overall.
        let mut fetched = Vec::new();
        let mut first = true;
        for _ in 0..matches {
            do_phase(
                harness,
                &[b"229 Entering Extended Passive Mode (|||8888|)\r\n"],
            );
            let path = harness.session.transfer().path().to_vec();
            let text = String::from_utf8_lossy(&path).into_owned();
            match text.rsplit('/').next() {
                Some(name) => fetched.push(name.to_owned()),
                None => fetched.push(text.clone()),
            }
            if first {
                do_more_phase(
                    harness,
                    &[
                        b"200 Type set to I\r\n",
                        b"150 Opening BINARY mode data connection\r\n",
                    ],
                );
                first = false;
            } else {
                do_more_phase(
                    harness,
                    &[b"150 Opening BINARY mode data connection\r\n"],
                );
            }
            finish_transfer(harness);
        }

        // The last match left CLEAN behind, so one more pass through `ftp_do`
        // moves the driver to DONE and performs no transfer at all -- the C's
        // *"after that will be ftp_do called once again and no transfer will be
        // done because of CURLWC_CLEAN state"*. Nothing reaches the wire.
        assert_eq!(harness.session.wildcard().state, WildcardState::Clean);
        let before = harness.sent();
        let _ = do_it(harness).expect("the final, empty pass");
        assert_eq!(
            harness.session.wildcard().state,
            WildcardState::Done,
            "the final pass ends the wildcard"
        );
        assert_eq!(harness.sent(), before, "and sends nothing");
        fetched
    }

    /// The command stream both wildcard fixtures pin, assembled the way the
    /// fixture spells it: one listing cycle, then one `EPSV` and one `RETR` per
    /// match, with `TYPE A` once per listing and `TYPE I` once per burst of
    /// files.
    fn wildcard_expected(
        directory: &str,
        names: &[&str],
        performs: usize,
    ) -> String {
        let mut out = format!(
            "USER anonymous\r\nPASS ftp@example.com\r\nPWD\r\n\
             CWD fully_simulated\r\nCWD {directory}\r\n"
        );
        for _ in 0..performs {
            out.push_str("EPSV\r\nTYPE A\r\nLIST\r\n");
            for (index, name) in names.iter().enumerate() {
                out.push_str("EPSV\r\n");
                if index == 0 {
                    out.push_str("TYPE I\r\n");
                }
                out.push_str(&format!("RETR {name}\r\n"));
            }
        }
        out.push_str("QUIT\r\n");
        out
    }

    /// `tests/data/test574` -- a wildcard download, command for command.
    ///
    /// The fixture is driven by `tests/libtest/lib574.c` rather than by the
    /// command line: `<tool>lib574</tool>`, named *"FTP wildcard download -
    /// changed fnmatch, 2x perform (Unix LIST response)"*. Both halves of that
    /// name are load-bearing and are reproduced here rather than approximated.
    /// The URL's pattern is `*.txt`, yet the fixture retrieves `chmod1` and
    /// `empty_file.dat` as well, because the test installs a
    /// `CURLOPT_FNMATCH_FUNCTION` that accepts everything -- and it performs
    /// twice, so the whole listing-plus-files cycle appears twice over one
    /// connection, with the two `CWD`s only at the front.
    ///
    /// Section 0.8.7 records that `tests/libtest` cannot link against a Rust
    /// static library; this is where the coverage it provided lives instead.
    ///
    /// Two properties of the stream are what this test exists for. `TYPE A`
    /// appears once per listing and `TYPE I` once per burst of files, because
    /// `ftp_nb_type` sends nothing when the mode already matches and simulates
    /// the `200` instead. And every transfer gets its own `EPSV`, because a data
    /// channel serves exactly one transfer.
    #[test]
    fn test574_downloads_every_match_in_listing_order() {
        const LISTING: &str = concat!(
            "-r--r--r--   1 user group  1 Jan  9 10:10 chmod1\n",
            "-r-xr-xr-x   1 user group  2 Jan  9 10:10 chmod2\n",
            "----------   1 user group  3 Jan  9 10:10 chmod3\n",
            "-rw-rw-rw-   1 user group  0 Jan  9 10:10 empty_file.dat\n",
            "-rw-rw-rw-   1 user group  5 Jan  9 10:10 file.txt\n",
            "-rw-rw-rw-   1 user group  6 Jan  9 10:10 someothertext.txt\n",
        );
        let names = [
            "chmod1",
            "chmod2",
            "chmod3",
            "empty_file.dat",
            "file.txt",
            "someothertext.txt",
        ];
        let url = b"fully_simulated/UNIX/*.txt";

        let mut harness = wildcard_harness(url);
        let mut matcher = AcceptEverything::default();
        login(&mut harness);

        let walk: [&[u8]; 3] = [
            b"250 CWD command successful\r\n",
            b"250 CWD command successful\r\n",
            b"229 Entering Extended Passive Mode (|||8888|)\r\n",
        ];
        let reused: [&[u8]; 1] =
            [b"229 Entering Extended Passive Mode (|||8888|)\r\n"];

        let first = wildcard_cycle(
            &mut harness,
            LISTING,
            &mut matcher,
            &walk,
            names.len(),
        );
        assert_eq!(first, names, "arrival order is the transfer order");

        // The second `curl_easy_perform`. A fresh perform builds fresh
        // per-transfer state and a fresh wildcard, and reuses the connection --
        // which is why no second pair of `CWD`s appears.
        *harness.session.transfer_mut() = FtpTransfer::new(url);
        harness.session.wildcard_mut().reset();
        let second = wildcard_cycle(
            &mut harness,
            LISTING,
            &mut matcher,
            &reused,
            names.len(),
        );
        assert_eq!(second, names);

        goodbye(&mut harness);
        assert_eq!(
            harness.sent_text(),
            wildcard_expected("UNIX", &names, 2),
            "tests/data/test574's protocol block"
        );

        // The custom matcher really was consulted, with the URL's pattern, once
        // per listing entry per perform, and the in-callback guard was set and
        // cleared around each call.
        assert_eq!(matcher.asked.len(), names.len() * 2);
        assert!(matcher.asked.iter().all(|(pattern, _)| pattern == b"*.txt"));
        assert_eq!(matcher.guard.len(), names.len() * 4);
        assert!(matcher.guard.chunks(2).all(|pair| pair == [true, false]));
    }

    /// `tests/data/test1113` -- the same `lib574` driver over a DOS-format
    /// listing, which is what makes the driver's behaviour independent of the
    /// listing format the server chose.
    #[test]
    fn test1113_downloads_every_match_of_a_dos_listing() {
        const LISTING: &str = concat!(
            "01-09-11  10:10AM                    1 chmod1\r\n",
            "01-09-11  10:10AM                    2 chmod2\r\n",
            "01-09-11  10:10AM                    3 chmod3\r\n",
            "01-09-11  10:10AM                    0 empty_file.dat\r\n",
            "01-09-11  10:10AM                    5 file.txt\r\n",
            "01-09-11  10:10AM                    6 someothertext.txt\r\n",
        );
        let names = [
            "chmod1",
            "chmod2",
            "chmod3",
            "empty_file.dat",
            "file.txt",
            "someothertext.txt",
        ];
        let url = b"fully_simulated/DOS/*.txt";

        let mut harness = wildcard_harness(url);
        let mut matcher = AcceptEverything::default();
        login(&mut harness);

        let walk: [&[u8]; 3] = [
            b"250 CWD command successful\r\n",
            b"250 CWD command successful\r\n",
            b"229 Entering Extended Passive Mode (|||8888|)\r\n",
        ];
        let reused: [&[u8]; 1] =
            [b"229 Entering Extended Passive Mode (|||8888|)\r\n"];

        let first = wildcard_cycle(
            &mut harness,
            LISTING,
            &mut matcher,
            &walk,
            names.len(),
        );
        assert_eq!(first, names);

        *harness.session.transfer_mut() = FtpTransfer::new(url);
        harness.session.wildcard_mut().reset();
        let second = wildcard_cycle(
            &mut harness,
            LISTING,
            &mut matcher,
            &reused,
            names.len(),
        );
        assert_eq!(second, names);

        goodbye(&mut harness);
        assert_eq!(
            harness.sent_text(),
            wildcard_expected("DOS", &names, 2),
            "tests/data/test1113's protocol block"
        );
    }

    /// A quote list around a transfer, as the `quote` fixtures pin it: the
    /// pre-transfer commands go out raw before the walk, and the post-transfer
    /// ones after the closing reply.
    #[test]
    fn a_quoted_session_sends_its_commands_raw_around_the_transfer() {
        let mut harness = Harness::new(b"file");
        harness.client.opts.quote = vec![b"SITE CHMOD 0644 file".to_vec()];
        harness.client.opts.postquote = vec![b"DELE file".to_vec()];
        login(&mut harness);

        do_phase(
            &mut harness,
            &[
                b"200 SITE command successful\r\n",
                b"229 Entering Extended Passive Mode (|||8888|)\r\n",
            ],
        );
        do_more_phase(
            &mut harness,
            &[
                b"200 Type set to I\r\n",
                b"213 4096\r\n",
                b"150 Opening BINARY mode data connection\r\n",
            ],
        );

        harness.session.conn_mut().ftpc_mut().ctl_valid = true;
        harness.client.req.bytecount = harness.client.req.size;
        harness.feed(b"226 Transfer complete\r\n");
        harness.feed(b"250 DELE command successful\r\n");
        done(&mut harness, CURLcode::Ok, false).expect("clean");
        goodbye(&mut harness);

        assert_eq!(
            harness.sent_text(),
            concat!(
                "USER anonymous\r\n",
                "PASS ftp@example.com\r\n",
                "PWD\r\n",
                "SITE CHMOD 0644 file\r\n",
                "EPSV\r\n",
                "TYPE I\r\n",
                "SIZE file\r\n",
                "RETR file\r\n",
                "DELE file\r\n",
                "QUIT\r\n",
            )
        );
    }

    /// A resumed download, as the range fixtures pin it: `REST` carries the
    /// offset and precedes `RETR`.
    #[test]
    fn a_resumed_session_sends_rest_before_retr() {
        let mut harness = Harness::new(b"file");
        harness.client.opts.range = Some(b"100-".to_vec());
        login(&mut harness);

        do_phase(
            &mut harness,
            &[b"229 Entering Extended Passive Mode (|||8888|)\r\n"],
        );
        do_more_phase(
            &mut harness,
            &[
                b"200 Type set to I\r\n",
                b"213 4096\r\n",
                b"350 Restarting at 100\r\n",
                b"150 Opening BINARY mode data connection\r\n",
            ],
        );
        goodbye(&mut harness);

        assert_eq!(
            harness.sent_text(),
            concat!(
                "USER anonymous\r\n",
                "PASS ftp@example.com\r\n",
                "PWD\r\n",
                "EPSV\r\n",
                "TYPE I\r\n",
                "SIZE file\r\n",
                "REST 100\r\n",
                "RETR file\r\n",
                "QUIT\r\n",
            )
        );
    }

    /// An appending upload, as the append fixtures pin it: `APPE` replaces
    /// `STOR` and no `SIZE` probe is needed.
    #[test]
    fn an_appending_session_sends_appe() {
        let mut harness = Harness::new(b"file");
        harness.client.req.upload = true;
        harness.client.req.infilesize = 16;
        harness.client.opts.remote_append = true;
        login(&mut harness);

        do_phase(
            &mut harness,
            &[b"229 Entering Extended Passive Mode (|||8888|)\r\n"],
        );
        do_more_phase(
            &mut harness,
            &[b"200 Type set to I\r\n", b"150 Ok to send data\r\n"],
        );
        goodbye(&mut harness);

        assert_eq!(
            harness.sent_text(),
            concat!(
                "USER anonymous\r\n",
                "PASS ftp@example.com\r\n",
                "PWD\r\n",
                "EPSV\r\n",
                "TYPE I\r\n",
                "APPE file\r\n",
                "QUIT\r\n",
            )
        );
    }

    /// A transfer cut short sends `ABOR`, which is the one command form no
    /// other test above reaches.
    #[test]
    fn an_aborted_transfer_sends_abor() {
        let mut harness = Harness::new(b"file");
        login(&mut harness);

        do_phase(
            &mut harness,
            &[b"229 Entering Extended Passive Mode (|||8888|)\r\n"],
        );
        do_more_phase(
            &mut harness,
            &[
                b"200 Type set to I\r\n",
                b"213 4096\r\n",
                b"150 Opening BINARY mode data connection\r\n",
            ],
        );

        // A bounded range is what makes the closing reply unjudgeable, which is
        // the condition `ABOR` is sent under, and the data connection has to
        // exist for the branch that sends it to be reached at all.
        harness.open_secondary();
        harness.session.conn_mut().ftpc_mut().dont_check = true;
        harness.client.req.maxdownload = 100;
        harness.session.conn_mut().ftpc_mut().ctl_valid = true;
        harness.feed(b"226 Transfer complete\r\n");
        done(&mut harness, CURLcode::Ok, false).expect("tolerated");

        assert!(
            harness.sent_text().ends_with("RETR file\r\nABOR\r\n"),
            "got {:?}",
            harness.sent_text()
        );
    }

    /// This file's own source, for the structural assertions above.
    fn own_source() -> String {
        let path =
            concat!(env!("CARGO_MANIFEST_DIR"), "/src/protocols/ftp/mod.rs");
        std::fs::read_to_string(path).expect("this file is readable")
    }

    /// The production half of this file: everything before `mod tests`.
    fn code_only() -> String {
        let source = own_source();
        match source.find("\nmod tests {") {
            Some(at) => source.get(..at).unwrap_or_default().to_owned(),
            None => source,
        }
    }

    // -- this file's own policy --------------------------------------------
    //
    // The gates below read this file from disk and assert properties of it. The
    // crate root's `mod source_policy` already scans every source in the crate
    // for `unsafe`, for C scalar widths and for raw strings; these are the ones
    // specific to this module, and they live here so that a violation names THIS
    // file rather than appearing as one entry in a workspace-wide list. The
    // sibling `ftp/pingpong.rs` carries the same set, deliberately: a policy
    // asserted in one file of a directory and not its neighbour is a policy that
    // holds by luck.
    //
    // Each is ignored under Miri, as every filesystem-reading test in this crate
    // is: Miri runs with host isolation on, where reading a file fails outright
    // and would take the interpreter down. Nothing is lost -- a string scan has
    // no pointer arithmetic for Miri to check -- and the assertions still run in
    // full under `cargo test`.

    /// `line` with its comment tail and every string literal removed.
    ///
    /// Necessary because this file DISCUSSES the forbidden constructs in prose
    /// and asserts on their names in the tests above; a scan that could not tell
    /// prose from code would report every paragraph as a violation.
    fn code_of(line: &str) -> String {
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
                out.push(' ');
                continue;
            }
            out.push(ch);
        }
        out
    }

    /// The `unsafe` keyword appears nowhere as code, and no marker of the FFI
    /// island appears in code at all.
    #[test]
    #[cfg_attr(miri, ignore = "this reads the source tree, not the program")]
    fn no_unsafe_and_no_ffi_marker_appears_anywhere() {
        let source = own_source();
        for (number, line) in source.lines().enumerate() {
            let code = code_of(line);
            let names_it = code
                .split(|c: char| !c.is_alphanumeric() && c != '_')
                .any(|word| word == "unsafe");
            assert!(
                !names_it,
                "line {}: no `unsafe` outside src/ffi/",
                number + 1
            );
            for marker in ["no_mangle", "libc", "extern"] {
                assert!(
                    !code.contains(marker),
                    "line {}: {marker} belongs to the FFI island",
                    number + 1
                );
            }
        }
    }

    /// No TLS module is imported and no `tls` feature is named.
    ///
    /// FTPS is this protocol over the crate's unconditional TLS stack, reached
    /// by a filter the connection layer installs on request -- so this module
    /// has no business naming the TLS module, and there is no `tls` feature to
    /// gate on in the first place.
    #[test]
    #[cfg_attr(miri, ignore = "this reads the source tree, not the program")]
    fn no_tls_import_and_no_tls_feature_gate() {
        let source = own_source();
        for (number, line) in source.lines().enumerate() {
            let code = code_of(line);
            assert!(
                !code.contains("crate::tls"),
                "line {}: the TLS module is not imported here",
                number + 1
            );
            let trimmed = line.trim_start();
            if trimmed.starts_with("#[") || trimmed.starts_with("#![") {
                assert!(
                    !trimmed.contains("feature = \"tls\""),
                    "line {}: there is no `tls` feature",
                    number + 1
                );
            }
        }
        // And the filter work really does go through the connection layer.
        let production = code_only();
        for asked in ["add_tls_filter", "remove_tls_filter"] {
            assert!(
                production.contains(asked),
                "FTPS asks `conn/` for {asked}"
            );
        }
    }

    /// No wall-clock constructor is reached for: every reading comes from the
    /// injected clock.
    #[test]
    #[cfg_attr(miri, ignore = "this reads the source tree, not the program")]
    fn no_wall_clock_constructor_is_called() {
        let source = own_source();
        for (number, line) in source.lines().enumerate() {
            let code = code_of(line);
            for forbidden in [
                "SystemClock",
                "Instant::now",
                "SystemTime::now",
                "curlx_now",
            ] {
                assert!(
                    !code.contains(forbidden),
                    "line {}: {forbidden} bypasses the injected clock",
                    number + 1
                );
            }
        }
    }

    /// No trait declares an `async fn` or returns `impl Future`.
    ///
    /// Either would make the trait un-`dyn`-compatible at the declared minimum
    /// Rust version, and the protocol dispatch is `&dyn Protocol`.
    #[test]
    #[cfg_attr(miri, ignore = "this reads the source tree, not the program")]
    fn no_trait_method_is_an_async_fn_or_returns_impl_future() {
        let source = own_source();
        let mut in_trait = false;
        for (number, line) in source.lines().enumerate() {
            let code = code_of(line);
            let trimmed = code.trim_start();
            if trimmed.starts_with("pub(crate) trait ")
                || trimmed.starts_with("trait ")
            {
                in_trait = true;
            }
            // A trait body ends at a closing brace in the first column.
            if in_trait && code.starts_with('}') {
                in_trait = false;
            }
            if in_trait {
                assert!(
                    !trimmed.contains("async fn"),
                    "line {}: an `async fn` in a trait is not dyn-compatible",
                    number + 1
                );
                assert!(
                    !trimmed.contains("impl Future"),
                    "line {}: `impl Future` in a trait is not dyn-compatible",
                    number + 1
                );
            }
        }
    }

    /// The production half panics nowhere and unwraps nothing.
    ///
    /// `debug_assert!` is exempt and is the only exemption: it is the C's own
    /// `DEBUGASSERT`, it compiles out of a release build, and every site that
    /// carries one carries the checked path beside it. The test module is exempt
    /// too, because an assertion that cannot fail the test is not a test.
    #[test]
    #[cfg_attr(miri, ignore = "this reads the source tree, not the program")]
    fn the_production_half_cannot_panic() {
        let production = code_only();
        for (number, line) in production.lines().enumerate() {
            let code = code_of(line);
            for forbidden in [
                "unwrap()",
                "expect(",
                "panic!",
                "unreachable!",
                "todo!",
                "unimplemented!",
                "assert!",
                "assert_eq!",
            ] {
                let hit = code.contains(forbidden)
                    && !code.contains("debug_assert!")
                    && !code.contains("unwrap_or");
                assert!(
                    !hit,
                    "line {}: {forbidden} is panic-based control flow",
                    number + 1
                );
            }
        }
    }

    /// Nothing in the production half reaches for a type-erased value, and no
    /// unordered or sorted collection stands where order is observable.
    ///
    /// The two C string-keyed metadata slots this module supersedes --
    /// `CURL_META_FTP_CONN` and `CURL_META_FTP_EASY` -- are typed fields here,
    /// so nothing needs a downcast. And the transfer queue's order IS the
    /// server's listing order, which a set or a sort would destroy.
    #[test]
    #[cfg_attr(miri, ignore = "this reads the source tree, not the program")]
    fn nothing_is_type_erased_and_nothing_reorders_the_queue() {
        let production = code_only();
        for (number, line) in production.lines().enumerate() {
            let code = code_of(line);
            for forbidden in [
                "downcast",
                "dyn Any",
                "HashMap",
                "HashSet",
                "BTreeMap",
                "BTreeSet",
                ".sort(",
                ".sort_by",
                ".sort_unstable",
            ] {
                assert!(
                    !code.contains(forbidden),
                    "line {}: {forbidden} has no place here",
                    number + 1
                );
            }
        }
    }

    /// Nothing in this file is gated on the `ftp` feature, because the parent
    /// gates the whole directory, and no third child module is declared.
    #[test]
    #[cfg_attr(miri, ignore = "this reads the source tree, not the program")]
    fn this_file_adds_no_feature_gate_and_no_third_child() {
        let source = own_source();
        let mut children = Vec::new();
        for (number, line) in source.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("#[cfg") || trimmed.starts_with("#![cfg") {
                assert!(
                    !trimmed.contains("feature ="),
                    "line {}: the parent's `mod ftp` gate is the only one",
                    number + 1
                );
            }
            let code = code_of(line);
            if code.starts_with("pub(crate) mod ") || code.starts_with("mod ") {
                children.push(code.trim().to_owned());
            }
        }
        assert_eq!(
            children,
            vec![
                "pub(crate) mod listparser;".to_owned(),
                "pub(crate) mod pingpong;".to_owned(),
                "mod tests {".to_owned(),
            ],
            "exactly two child declarations, and this file's own test module"
        );
    }

    /// The version this module reports is never written into it.
    ///
    /// The `User-Agent` a fixture compares against is the harness's
    /// `%VERSION` substitution, so a hard-coded development version here would
    /// be a second source of truth for something `version.rs` owns.
    #[test]
    #[cfg_attr(miri, ignore = "this reads the source tree, not the program")]
    fn no_curl_version_is_written_into_this_file() {
        let source = own_source();
        for (number, line) in source.lines().enumerate() {
            // Assembled from pieces for the same reason the SPDX assertion
            // below is: written whole, this scan's own literal would be the
            // violation it looks for.
            let forbidden = concat!("8.", "19.", "0");
            assert!(
                !line.contains(forbidden),
                "line {}: the version belongs to version.rs",
                number + 1
            );
        }
    }

    /// The licence banner is the generic 23-line one, with SPDX on line 21 and
    /// the closer on line 23.
    #[test]
    #[cfg_attr(miri, ignore = "this reads the source tree, not the program")]
    fn the_banner_is_the_measured_twenty_three_lines() {
        let source = own_source();
        let lines: Vec<&str> = source.lines().collect();
        assert!(lines.len() > 23, "the banner is 23 lines and then some");
        assert!(lines[0].starts_with("// /****"), "line 1: {}", lines[0]);
        assert_eq!(
            lines[7].trim(),
            "//  * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al."
        );
        // The tag is assembled from two pieces rather than written whole:
        // `reuse lint` scans a file for every occurrence of the identifier and
        // would read this assertion's trailing punctuation as a second,
        // malformed licence expression. Splitting it keeps the file's single
        // real tag -- line 21 -- the only one there is.
        assert_eq!(
            lines[20].trim(),
            concat!("//  * SPDX-License", "-Identifier: curl")
        );
        assert!(lines[22].trim_end().ends_with("***/"), "line 23 closes it");
    }

    /// This file is UTF-8, indented with spaces, free of trailing whitespace,
    /// and ends in exactly one newline -- `.editorconfig`'s `[*]` section.
    #[test]
    #[cfg_attr(miri, ignore = "this reads the source tree, not the program")]
    fn the_file_obeys_the_editorconfig() {
        let source = own_source();
        for (number, line) in source.lines().enumerate() {
            assert!(
                !line.contains('\t'),
                "line {}: indent_style = space",
                number + 1
            );
            assert_eq!(
                line.trim_end(),
                line,
                "line {}: trim_trailing_whitespace = true",
                number + 1
            );
        }
        assert!(
            source.ends_with('\n') && !source.ends_with("\n\n"),
            "insert_final_newline = true, and exactly one"
        );
    }

    /// No dependency beyond this crate's own modules is named.
    ///
    /// The specification adds no crate for FTP, and there is no FTP crate in the
    /// graph to reach for: every import is `crate::`, `core::` or `std::`.
    #[test]
    #[cfg_attr(miri, ignore = "this reads the source tree, not the program")]
    fn every_import_is_from_this_crate_or_the_standard_library() {
        let production = code_only();
        for (number, line) in production.lines().enumerate() {
            let code = code_of(line);
            let trimmed = code.trim_start();
            if let Some(rest) = trimmed.strip_prefix("use ") {
                let root = rest
                    .split([':', ';', ' '])
                    .find(|piece| !piece.is_empty())
                    .unwrap_or_default();
                assert!(
                    matches!(root, "crate" | "core" | "std" | "super"),
                    "line {}: {root} is not this crate or the standard library",
                    number + 1
                );
            }
        }
    }
}
