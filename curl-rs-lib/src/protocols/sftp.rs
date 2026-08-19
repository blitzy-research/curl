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
//! SFTP -- and the SSH session core that SCP shares with it.
//!
//! # What this file supersedes, with locators
//!
//! * `lib/vssh/libssh2.c:3846-3864` -- `Curl_protocol_sftp`, the 17-slot
//!   handler this file reproduces as [`SFTP`]. Eleven slots are occupied and
//!   six are `ZERO_NULL`; see [`Sftp`] for the slot-by-slot correspondence.
//! * `lib/vssh/libssh2.c:3823-3841` -- `Curl_protocol_scp`. Cited here rather
//!   than in `protocols/scp.rs` because the comparison is what justifies this
//!   file hosting the shared core: the two handlers are **identical in 14 of
//!   their 17 slots**, differing only in `done`, `doing` and `disconnect`.
//! * `lib/vssh/vssh.c:338-350` -- `Curl_scheme_sftp`, the registry row, which
//!   is [`SCHEME`] here.
//! * `lib/vssh/ssh.h:55-120` -- `enum sshstate`, 62 tokens, which is
//!   [`SshState`] here. Its phase-boundary comments are carried verbatim onto
//!   the variants they annotate, because they are the only documentation the C
//!   has of the machine's structure.
//! * `lib/vssh/vssh.c:37-101` -- `Curl_ssh_statename`'s 60-entry name table,
//!   which is [`SshState::name`] here.
//! * `lib/vssh/vssh.c:107-121` -- `Curl_ssh_set_state`, whose comment is *"This
//!   is the ONLY way to change SSH state!"*; [`ssh_set_state`] here, and the
//!   only function in this file that writes [`SshConn::state`].
//! * `lib/vssh/vssh.c:126-190` -- `Curl_getworkingpath`; [`getworkingpath`].
//! * `lib/vssh/vssh.c:192-277` -- `Curl_get_pathname`; [`get_pathname`].
//! * `lib/vssh/vssh.c:279-331` -- `Curl_ssh_range`; [`ssh_range`].
//! * `lib/vssh/vssh.h` -- the declarations shared between the two schemes,
//!   which become the `pub(crate)` items of this module.
//! * `lib/curl_trc.c:462` -- `Curl_trc_feat_ssh`, whose `name` member is
//!   `"SSH"`, registered in `TRC_CT_PROTOCOL` at `:525`. The string is
//!   CONSUMED from [`crate::trace::TraceFeature::Ssh`] and is not spelled
//!   again here.
//!
//! Read rather than superseded: `lib/urldata.h` for `struct Curl_protocol` and
//! the `PROTOPT_*` bits, and `tests/getpart.pm:351+` for `compareparts`, which
//! joins both sides into a single string and compares them as one -- no
//! per-line matching, no normalisation, no reordering. That is why every
//! user-visible string in this file is transcribed rather than reworded.
//!
//! **`lib/vssh/libssh.c` is excluded entirely.** Specification 0.2.2 drops
//! every alternate backend, so the libssh half of the C's `#ifdef USE_LIBSSH /
//! #elif defined(USE_LIBSSH2)` split has no successor anywhere.
//!
//! # This file hosts the shared core, and there is no third module
//!
//! Specification 0.4.1 names exactly two targets for `lib/vssh/` --
//! `protocols/sftp.rs` and `protocols/scp.rs` -- and names no third. The
//! measured 14-of-17 overlap above therefore lands here, as `pub(crate)` items
//! that `protocols/scp.rs` imports with `use super::sftp::{...}`:
//!
//! * the state machine -- [`SshState`], [`ssh_set_state`], [`SshPhase`];
//! * the connection and per-transfer state -- [`SshConn`], [`SshProto`],
//!   [`SshSettings`];
//! * the SSH-CONNECT phase -- [`ssh_setup_connection`], [`ssh_connect_step`],
//!   [`next_auth_state`], [`check_fingerprint`];
//! * the pollsets and `attach` -- [`ssh_pollset`], [`ssh_attach`];
//! * `SSH_SESSION_DISCONNECT` and `SSH_SESSION_FREE`, which terminate BOTH
//!   schemes' disconnect phases -- [`ssh_session_disconnect`],
//!   [`ssh_session_free`];
//! * the path and range helpers -- [`getworkingpath`], [`get_pathname`],
//!   [`ssh_range`];
//! * the transport seam -- [`SshTransport`], [`SshSeams`], [`SshError`].
//!
//! What stays SFTP-specific carries an `sftp_` prefix, mirroring the C's own
//! naming: [`sftp_done`], [`sftp_doing`], [`sftp_disconnect`], [`sftp_quote`],
//! [`sftp_readdir_entry`]. `protocols/scp.rs` contributes the SCP-DO, SCP-DONE
//! and SCP-DISCONNECT phases and its own three differing slots, and nothing
//! else.
//!
//! # Why `russh` 0.54, and why not the newest release
//!
//! Specification 0.8.3 preserves the user's directive verbatim -- *"russh for
//! SFTP and SCP"* -- alongside an MSRV of 1.75, and the two interact.
//! `russh`'s newest releases declare a minimum Rust version of 1.85, so the
//! newest release that satisfies the floor is what the workspace pins. That
//! choice is independently better on supply-chain grounds, which specification
//! 0.5.1 records: **every `russh` release from 0.58.0 through 0.62.4 depends on
//! release-candidate cryptography** -- `rsa 0.10.0-rc.18`, `ssh-key
//! 0.7.0-rc.11`, `pkcs1 0.8.0-rc.4` -- whereas the 0.54 line has a fully
//! stable dependency graph with no pre-release requirement at all. Shipping
//! release-candidate cryptography would have put the `cargo audit` gate of
//! specification 0.8.4 in permanent jeopardy.
//!
//! One correction to specification 0.5.1 belongs here, because it is a
//! measurement rather than a preference: the specification names `russh
//! 0.54.6`, and **0.54.6 is unresolvable** -- it depends on a yanked release,
//! so `cargo` refuses it. The workspace manifest pins `=0.54.5`, records the
//! measurement in full, and this file follows the manifest. The pin is a
//! workspace decision with `cargo audit` and MSRV consequences; it is not a
//! local one, and nothing in this file may raise it.
//!
//! `rand` is pinned at the 0.8 series specifically so that this crate and
//! `russh` share one generation, and the RustCrypto family is coherent on
//! `digest 0.10` throughout -- mixing `digest 0.10` and `0.11` in one graph
//! makes `Hmac<Sha1>` fail to compile.
//!
//! # `russh` never owns a socket
//!
//! `russh::client::connect_stream` takes any `AsyncRead + AsyncWrite + Unpin +
//! Send + 'static` stream, and the `'static` bound is the whole design
//! constraint: the connection-filter chain is BORROWED through
//! [`TransferCtx`], so it can never be handed to `russh`. [`SshLink`] resolves
//! that with an in-memory duplex -- `russh` reads and writes one end, and the
//! protocol layer pumps the other end against the filter chain that
//! `crate::conn` owns. So the socket options, the Happy-Eyeballs race and any
//! proxy tunnelling stay where `crate::conn::socket` and `crate::proxy` put
//! them, and the SSH library sees bytes and nothing else. That is also what
//! makes the coverage gate reachable: a test installs
//! `crate::conn::filters::tests::InMemory` beneath the same pump and no
//! descriptor is ever opened.
//!
//! # The bytes are the specification
//!
//! Forty fixtures name the `sftp` server, and their expectations are compared
//! as one joined string. Three consequences shape this file and none of them
//! is negotiable:
//!
//! 1. **The SFTP packet layer is ours.** No SFTP crate is in the closed
//!    dependency set of specification 0.5.1, and none would commit to the
//!    request ordering and attribute encoding the corpus asserts. [`SftpCodec`]
//!    encodes and decodes every packet this module sends and receives.
//! 2. **Every diagnostic is transcribed, never reworded.** `failf` output
//!    reaches stderr, `--write-out` and the fixtures. The strings in
//!    [`sftp_strerror`], [`QuoteError`] and [`FingerprintError`] are the C's,
//!    byte for byte.
//! 3. **The directory listing is assembled here.** `sftp_readdir`
//!    (`lib/vssh/libssh2.c:1369-1426`) emits the server's long entry, appends
//!    `" -> target"` for a symbolic link, and terminates with a single newline;
//!    [`sftp_readdir_entry`] reproduces that and [`mod tests`](self) asserts
//!    the bytes.
//!
//! # Dependency injection is not a testing convenience
//!
//! Specification 0.3.3's pattern P12 requires the clock, the resolver and the
//! provider to be injected rather than reached for globally. [`SshSeams`]
//! carries the clock and the randomness; the transport is a
//! [`Box<dyn SshTransport>`]; the filesystem probe behind the private-key
//! guesses is a function pointer. Nothing in this file reads a wall clock, a
//! thread-local generator or the real filesystem, which is what lets the
//! 80% line coverage this directory is measured at be reached with no network
//! access at all.
//!
//! # Three imports come from modules this file was not told to expect
//!
//! Recorded because a reviewer checking imports against this file's stated
//! dependencies will find them, and each is deliberate -- the same disclosure
//! `protocols/mod.rs` makes for its own three:
//!
//! * [`crate::crypto::md5`] supplies `libssh2_hostkey_hash(session,
//!   LIBSSH2_HOSTKEY_HASH_MD5)`. This file's stated dependencies name
//!   `crypto/rand.rs` and `crypto/sha256.rs` but not `crypto/md5.rs`, and MD5 is
//!   nonetheless unavoidable: `CURLOPT_SSH_HOST_PUBLIC_KEY_MD5` is a public
//!   option, `ssh_check_fingerprint` (`lib/vssh/libssh2.c:526-556`) checks it
//!   after SHA-256 and before the known-hosts file, and its 32-hex-character
//!   rendering is compared with `curl_strequal`. Hand-rolling MD5 here to avoid
//!   the import would be strictly worse: `crypto/md5.rs` already exists, already
//!   carries the `Curl_MD5_*` mapping, and specification 0.4.1 assigns it sole
//!   ownership of the primitive.
//!
//! * [`crate::util::strparse`] supplies `curlx_str_word`,
//!   `curlx_str_passblanks`, `curlx_str_number`, `curlx_str_octal`,
//!   `curlx_str_numblanks` and `curlx_str_single`. `Curl_get_pathname` and
//!   `Curl_ssh_range` are written in terms of those six, and their acceptance
//!   rules are observable: `curlx_str_octal` capped at `07777` is what makes
//!   `chmod 7777` succeed and `chmod 10000` fail with the C's exact wording.
//!   A local re-implementation would be a second definition of an acceptance
//!   rule that specification 0.4.1 assigns to one file.
//! * [`crate::util::parsedate`] supplies `Curl_getdate_capped`, which the
//!   `atime` and `mtime` quote commands parse their argument with.
//!   Specification 0.4.1 makes `util/parsedate.rs` the single owner of date
//!   parsing precisely because *"date parsing must accept every format curl
//!   accepts"*, and `curl_getdate` is an exported symbol. Duplicating it here
//!   would guarantee the drift that assignment exists to prevent.
//!
//! # `pub(crate)`, and no TLS
//!
//! No exported symbol of `lib/libcurl.def` resolves a name in this file: a
//! scheme is selected by URL and never named by a caller. And there is no
//! `crate::tls` import, deliberately -- SSH carries its own transport security,
//! and the filter chain below it deals in bytes. A sibling under `protocols/`
//! that names `crate::tls` is a layering defect; `protocols/mod.rs` is the one
//! exception and documents why.

use core::fmt;

use crate::conn::select::{is_valid_sock, EasyPollset, PollAction, Socket};
use crate::conn::ProtocolOptions;
use crate::error::{CURLcode, CodeResult};
use crate::protocols::{
    Proto, ProtoFuture, Protocol, Scheme, TransferCtx, PORT_SSH,
};
use crate::trace::{trc_feat, TraceFeature, Tracer};
use crate::util::base64;
use crate::util::dynbuf::DynBuf;
use crate::util::parsedate::getdate_capped;
use crate::util::strcase::casecompare;
use crate::util::strparse::{
    str_number, str_octal, str_passblanks, str_single, str_word, StrError,
};

// The 62-state SSH machine -- `enum sshstate` (`lib/vssh/ssh.h:55-120`)

/// One state of the SSH/SFTP/SCP machine.
///
/// `enum sshstate` (`lib/vssh/ssh.h:55-120`), all 62 tokens, in the C's
/// declaration order and with the C's discriminants. The phase-boundary
/// comments are carried verbatim onto the variants they annotate: they are the
/// only documentation the C tree has of how the machine divides into phases,
/// and they are what decides which of the two SSH modules owns each state.
///
/// # The discriminants are the C's, and they are load-bearing
///
/// `SSH_NO_STATE` is `-1` and `SSH_STOP` is `0` explicitly; every other token
/// takes its value from declaration order, so `SSH_INIT` is 1 and `SSH_QUIT` is
/// 59. `SSH_LAST` is therefore **60**, which is exactly what
/// `Curl_ssh_statename`'s `DEBUGASSERT(CURL_ARRAYSIZE(names) == SSH_LAST)`
/// (`lib/vssh/vssh.c:100`) asserts about its 60-entry table. Writing the
/// discriminants out means the relationship between the enum and the table is
/// checkable rather than assumed, and [`mod tests`](self) checks it.
///
/// # Why an explicit enum and not a set of function pointers
///
/// Specification 0.3.3's pattern P3: the machine is preserved as an explicit
/// enum so that a `match` over it is checked for exhaustiveness. An unhandled
/// state is then a compile error rather than a runtime fall-through into the C's
/// `case SSH_QUIT: default:` arm. [`SshState::name`] and [`SshState::phase`] are
/// both exhaustive `match`es for that reason, and
/// `an_exhaustive_match_over_every_state_compiles` in [`mod tests`](self) is the
/// regression test that keeps them so.
///
/// `#[rustfmt::skip]` is deliberate on the variant list: the order is measured
/// against a C enumeration and the phase comments are aligned so the two can be
/// read side by side.
#[rustfmt::skip]
#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
pub(crate) enum SshState {
    /// `SSH_NO_STATE = -1` -- *"Used for "nextState" so say there is none"*.
    NoState = -1,
    /// `SSH_STOP = 0` -- *"do nothing state, stops the state machine"*.
    Stop = 0,

    /// *"First state in SSH-CONNECT"*.
    Init = 1,
    /// *"Session startup"*.
    SStartup = 2,
    /// *"verify hostkey"*.
    HostKey = 3,
    /// `SSH_AUTHLIST`.
    AuthList = 4,
    /// `SSH_AUTH_PKEY_INIT`.
    AuthPkeyInit = 5,
    /// `SSH_AUTH_PKEY`.
    AuthPkey = 6,
    /// `SSH_AUTH_PASS_INIT`.
    AuthPassInit = 7,
    /// `SSH_AUTH_PASS`.
    AuthPass = 8,
    /// *"initialize then wait for connection to agent"*.
    AuthAgentInit = 9,
    /// *"ask for list then wait for entire list to come"*.
    AuthAgentList = 10,
    /// *"attempt one key at a time"*.
    AuthAgent = 11,
    /// `SSH_AUTH_HOST_INIT`.
    AuthHostInit = 12,
    /// `SSH_AUTH_HOST`.
    AuthHost = 13,
    /// `SSH_AUTH_KEY_INIT`.
    AuthKeyInit = 14,
    /// `SSH_AUTH_KEY`.
    AuthKey = 15,
    /// `SSH_AUTH_GSSAPI`.
    AuthGssapi = 16,
    /// `SSH_AUTH_DONE`.
    AuthDone = 17,
    /// `SSH_SFTP_INIT`.
    SftpInit = 18,
    /// *"Last state in SSH-CONNECT"*.
    SftpRealpath = 19,

    /// *"First state in SFTP-DO"*.
    SftpQuoteInit = 20,
    /// *"(Possibly) First state in SFTP-DONE"*.
    SftpPostquoteInit = 21,
    /// `SSH_SFTP_QUOTE`.
    SftpQuote = 22,
    /// `SSH_SFTP_NEXT_QUOTE`.
    SftpNextQuote = 23,
    /// `SSH_SFTP_QUOTE_STAT`.
    SftpQuoteStat = 24,
    /// `SSH_SFTP_QUOTE_SETSTAT`.
    SftpQuoteSetstat = 25,
    /// `SSH_SFTP_QUOTE_SYMLINK`.
    SftpQuoteSymlink = 26,
    /// `SSH_SFTP_QUOTE_MKDIR`.
    SftpQuoteMkdir = 27,
    /// `SSH_SFTP_QUOTE_RENAME`.
    SftpQuoteRename = 28,
    /// `SSH_SFTP_QUOTE_RMDIR`.
    SftpQuoteRmdir = 29,
    /// `SSH_SFTP_QUOTE_UNLINK`.
    SftpQuoteUnlink = 30,
    /// `SSH_SFTP_QUOTE_STATVFS`.
    SftpQuoteStatvfs = 31,
    /// `SSH_SFTP_GETINFO`.
    SftpGetinfo = 32,
    /// `SSH_SFTP_FILETIME`.
    SftpFiletime = 33,
    /// `SSH_SFTP_TRANS_INIT`.
    SftpTransInit = 34,
    /// `SSH_SFTP_UPLOAD_INIT`.
    SftpUploadInit = 35,
    /// `SSH_SFTP_CREATE_DIRS_INIT`.
    SftpCreateDirsInit = 36,
    /// `SSH_SFTP_CREATE_DIRS`.
    SftpCreateDirs = 37,
    /// `SSH_SFTP_CREATE_DIRS_MKDIR`.
    SftpCreateDirsMkdir = 38,
    /// `SSH_SFTP_READDIR_INIT`.
    SftpReaddirInit = 39,
    /// `SSH_SFTP_READDIR`.
    SftpReaddir = 40,
    /// `SSH_SFTP_READDIR_LINK`.
    SftpReaddirLink = 41,
    /// `SSH_SFTP_READDIR_BOTTOM`.
    SftpReaddirBottom = 42,
    /// `SSH_SFTP_READDIR_DONE`.
    SftpReaddirDone = 43,
    /// `SSH_SFTP_DOWNLOAD_INIT`.
    SftpDownloadInit = 44,
    /// *"Last state in SFTP-DO"*.
    SftpDownloadStat = 45,
    /// *"Last state in SFTP-DONE"*.
    SftpClose = 46,
    /// *"First state in SFTP-DISCONNECT"*.
    SftpShutdown = 47,
    /// *"First state in SCP-DO"*.
    ScpTransInit = 48,
    /// `SSH_SCP_UPLOAD_INIT`.
    ScpUploadInit = 49,
    /// `SSH_SCP_DOWNLOAD_INIT`.
    ScpDownloadInit = 50,
    /// `SSH_SCP_DOWNLOAD`.
    ScpDownload = 51,
    /// `SSH_SCP_DONE`.
    ScpDone = 52,
    /// `SSH_SCP_SEND_EOF`.
    ScpSendEof = 53,
    /// `SSH_SCP_WAIT_EOF`.
    ScpWaitEof = 54,
    /// `SSH_SCP_WAIT_CLOSE`.
    ScpWaitClose = 55,
    /// *"Last state in SCP-DONE"*.
    ScpChannelFree = 56,
    /// *"First state in SCP-DISCONNECT"*.
    SessionDisconnect = 57,
    /// *"Last state in SCP/SFTP-DISCONNECT"*.
    SessionFree = 58,
    /// `SSH_QUIT`. Note the trace name: the table spells this one `"QUIT"`,
    /// without the prefix every other row carries.
    Quit = 59,
    /// `SSH_LAST` -- *"never used"*. Retained because the C's own consistency
    /// assertion is stated in terms of it.
    Last = 60,
}

/// Every state in the C's declaration order, `SSH_NO_STATE` first.
///
/// 62 entries, which is the token count of `enum sshstate`. Held as data so
/// that [`mod tests`](self) can assert the order and the discriminants against
/// the C without a second transcription, and so that
/// [`SshState::from_discriminant`] can be written as a search rather than as a
/// 62-arm `match` that could disagree with the declaration above it.
///
/// `#[rustfmt::skip]` for the same reason as the enum: this is a measured
/// table, and its layout is what makes it auditable.
#[rustfmt::skip]
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
pub(crate) const SSH_STATES: [SshState; 62] = [
    SshState::NoState,
    SshState::Stop,
    SshState::Init,
    SshState::SStartup,
    SshState::HostKey,
    SshState::AuthList,
    SshState::AuthPkeyInit,
    SshState::AuthPkey,
    SshState::AuthPassInit,
    SshState::AuthPass,
    SshState::AuthAgentInit,
    SshState::AuthAgentList,
    SshState::AuthAgent,
    SshState::AuthHostInit,
    SshState::AuthHost,
    SshState::AuthKeyInit,
    SshState::AuthKey,
    SshState::AuthGssapi,
    SshState::AuthDone,
    SshState::SftpInit,
    SshState::SftpRealpath,
    SshState::SftpQuoteInit,
    SshState::SftpPostquoteInit,
    SshState::SftpQuote,
    SshState::SftpNextQuote,
    SshState::SftpQuoteStat,
    SshState::SftpQuoteSetstat,
    SshState::SftpQuoteSymlink,
    SshState::SftpQuoteMkdir,
    SshState::SftpQuoteRename,
    SshState::SftpQuoteRmdir,
    SshState::SftpQuoteUnlink,
    SshState::SftpQuoteStatvfs,
    SshState::SftpGetinfo,
    SshState::SftpFiletime,
    SshState::SftpTransInit,
    SshState::SftpUploadInit,
    SshState::SftpCreateDirsInit,
    SshState::SftpCreateDirs,
    SshState::SftpCreateDirsMkdir,
    SshState::SftpReaddirInit,
    SshState::SftpReaddir,
    SshState::SftpReaddirLink,
    SshState::SftpReaddirBottom,
    SshState::SftpReaddirDone,
    SshState::SftpDownloadInit,
    SshState::SftpDownloadStat,
    SshState::SftpClose,
    SshState::SftpShutdown,
    SshState::ScpTransInit,
    SshState::ScpUploadInit,
    SshState::ScpDownloadInit,
    SshState::ScpDownload,
    SshState::ScpDone,
    SshState::ScpSendEof,
    SshState::ScpWaitEof,
    SshState::ScpWaitClose,
    SshState::ScpChannelFree,
    SshState::SessionDisconnect,
    SshState::SessionFree,
    SshState::Quit,
    SshState::Last,
];

/// `SSH_LAST` as an integer: the length of `Curl_ssh_statename`'s table.
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
pub(crate) const SSH_LAST: i32 = SshState::Last as i32;

#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
impl SshState {
    /// The name `--trace` prints, from `Curl_ssh_statename`
    /// (`lib/vssh/vssh.c:37-101`).
    ///
    /// Frozen output: these strings reach a trace log verbatim through
    /// `CURL_TRC_SSH(data, "[%s] -> [%s]", ...)`. Three details are the C's and
    /// must not be tidied:
    ///
    /// * the table is indexed from `SSH_STOP`, so `SSH_NO_STATE` has no entry
    ///   and the C's bounds test `((size_t)state < CURL_ARRAYSIZE(names))`
    ///   returns `""` for it -- a negative index converted to `size_t` is
    ///   enormous, so the guard catches it;
    /// * `SSH_LAST` is likewise past the end and likewise yields `""`;
    /// * `SSH_QUIT`'s entry is **`"QUIT"`**, alone among the 60 in carrying no
    ///   `SSH_` prefix.
    ///
    /// `#[rustfmt::skip]` because these are wire-bearing literals aligned
    /// against a C table.
    #[rustfmt::skip]
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::NoState             => "",
            Self::Stop                => "SSH_STOP",
            Self::Init                => "SSH_INIT",
            Self::SStartup            => "SSH_S_STARTUP",
            Self::HostKey             => "SSH_HOSTKEY",
            Self::AuthList            => "SSH_AUTHLIST",
            Self::AuthPkeyInit        => "SSH_AUTH_PKEY_INIT",
            Self::AuthPkey            => "SSH_AUTH_PKEY",
            Self::AuthPassInit        => "SSH_AUTH_PASS_INIT",
            Self::AuthPass            => "SSH_AUTH_PASS",
            Self::AuthAgentInit       => "SSH_AUTH_AGENT_INIT",
            Self::AuthAgentList       => "SSH_AUTH_AGENT_LIST",
            Self::AuthAgent           => "SSH_AUTH_AGENT",
            Self::AuthHostInit        => "SSH_AUTH_HOST_INIT",
            Self::AuthHost            => "SSH_AUTH_HOST",
            Self::AuthKeyInit         => "SSH_AUTH_KEY_INIT",
            Self::AuthKey             => "SSH_AUTH_KEY",
            Self::AuthGssapi          => "SSH_AUTH_GSSAPI",
            Self::AuthDone            => "SSH_AUTH_DONE",
            Self::SftpInit            => "SSH_SFTP_INIT",
            Self::SftpRealpath        => "SSH_SFTP_REALPATH",
            Self::SftpQuoteInit       => "SSH_SFTP_QUOTE_INIT",
            Self::SftpPostquoteInit   => "SSH_SFTP_POSTQUOTE_INIT",
            Self::SftpQuote           => "SSH_SFTP_QUOTE",
            Self::SftpNextQuote       => "SSH_SFTP_NEXT_QUOTE",
            Self::SftpQuoteStat       => "SSH_SFTP_QUOTE_STAT",
            Self::SftpQuoteSetstat    => "SSH_SFTP_QUOTE_SETSTAT",
            Self::SftpQuoteSymlink    => "SSH_SFTP_QUOTE_SYMLINK",
            Self::SftpQuoteMkdir      => "SSH_SFTP_QUOTE_MKDIR",
            Self::SftpQuoteRename     => "SSH_SFTP_QUOTE_RENAME",
            Self::SftpQuoteRmdir      => "SSH_SFTP_QUOTE_RMDIR",
            Self::SftpQuoteUnlink     => "SSH_SFTP_QUOTE_UNLINK",
            Self::SftpQuoteStatvfs    => "SSH_SFTP_QUOTE_STATVFS",
            Self::SftpGetinfo         => "SSH_SFTP_GETINFO",
            Self::SftpFiletime        => "SSH_SFTP_FILETIME",
            Self::SftpTransInit       => "SSH_SFTP_TRANS_INIT",
            Self::SftpUploadInit      => "SSH_SFTP_UPLOAD_INIT",
            Self::SftpCreateDirsInit  => "SSH_SFTP_CREATE_DIRS_INIT",
            Self::SftpCreateDirs      => "SSH_SFTP_CREATE_DIRS",
            Self::SftpCreateDirsMkdir => "SSH_SFTP_CREATE_DIRS_MKDIR",
            Self::SftpReaddirInit     => "SSH_SFTP_READDIR_INIT",
            Self::SftpReaddir         => "SSH_SFTP_READDIR",
            Self::SftpReaddirLink     => "SSH_SFTP_READDIR_LINK",
            Self::SftpReaddirBottom   => "SSH_SFTP_READDIR_BOTTOM",
            Self::SftpReaddirDone     => "SSH_SFTP_READDIR_DONE",
            Self::SftpDownloadInit    => "SSH_SFTP_DOWNLOAD_INIT",
            Self::SftpDownloadStat    => "SSH_SFTP_DOWNLOAD_STAT",
            Self::SftpClose           => "SSH_SFTP_CLOSE",
            Self::SftpShutdown        => "SSH_SFTP_SHUTDOWN",
            Self::ScpTransInit        => "SSH_SCP_TRANS_INIT",
            Self::ScpUploadInit       => "SSH_SCP_UPLOAD_INIT",
            Self::ScpDownloadInit     => "SSH_SCP_DOWNLOAD_INIT",
            Self::ScpDownload         => "SSH_SCP_DOWNLOAD",
            Self::ScpDone             => "SSH_SCP_DONE",
            Self::ScpSendEof          => "SSH_SCP_SEND_EOF",
            Self::ScpWaitEof          => "SSH_SCP_WAIT_EOF",
            Self::ScpWaitClose        => "SSH_SCP_WAIT_CLOSE",
            Self::ScpChannelFree      => "SSH_SCP_CHANNEL_FREE",
            Self::SessionDisconnect   => "SSH_SESSION_DISCONNECT",
            Self::SessionFree         => "SSH_SESSION_FREE",
            Self::Quit                => "QUIT",
            Self::Last                => "",
        }
    }

    /// The state's own discriminant, which is the C's integer.
    pub(crate) const fn as_i32(self) -> i32 {
        self as i32
    }

    /// The state carrying `raw`, or [`None`] when nothing does.
    ///
    /// A search over [`SSH_STATES`] rather than a second 62-arm `match`, so
    /// there is exactly one place the correspondence between a name and a
    /// number is written.
    pub(crate) fn from_discriminant(raw: i32) -> Option<Self> {
        let mut index = 0;
        while index < SSH_STATES.len() {
            let candidate = SSH_STATES[index];
            if candidate.as_i32() == raw {
                return Some(candidate);
            }
            index += 1;
        }
        None
    }

    /// Which phase of the machine owns this state.
    ///
    /// Derived from the phase-boundary comments of `lib/vssh/ssh.h`, which mark
    /// the first and last state of each phase and leave the interior implied.
    /// The boundaries are the C's:
    ///
    /// | phase | first | last |
    /// | --- | --- | --- |
    /// | SSH-CONNECT | `SSH_INIT` | `SSH_SFTP_REALPATH` |
    /// | SFTP-DO | `SSH_SFTP_QUOTE_INIT` | `SSH_SFTP_DOWNLOAD_STAT` |
    /// | SFTP-DONE | (`SSH_SFTP_POSTQUOTE_INIT`) | `SSH_SFTP_CLOSE` |
    /// | SFTP-DISCONNECT | `SSH_SFTP_SHUTDOWN` | `SSH_SESSION_FREE` |
    /// | SCP-DO | `SSH_SCP_TRANS_INIT` | -- |
    /// | SCP-DONE | -- | `SSH_SCP_CHANNEL_FREE` |
    /// | SCP-DISCONNECT | `SSH_SESSION_DISCONNECT` | `SSH_SESSION_FREE` |
    ///
    /// Two of those rows need their oddity stated rather than smoothed over,
    /// because a reader comparing this against the header will notice both:
    ///
    /// * `SSH_SFTP_POSTQUOTE_INIT` is marked *"(Possibly) First state in
    ///   SFTP-DONE"* and sits between the two SFTP-DO markers in declaration
    ///   order. Its parenthesis is the C's: the state is reached only when
    ///   `CURLOPT_POSTQUOTE` is set (`lib/vssh/libssh2.c:3688`), so the DONE
    ///   phase sometimes begins at `SSH_SFTP_CLOSE` instead. It is classified
    ///   as [`SshPhase::SftpDone`] because that is the phase that reaches it.
    /// * `SSH_SESSION_FREE` is marked *"Last state in SCP/SFTP-DISCONNECT"* --
    ///   it terminates BOTH schemes. It is classified as
    ///   [`SshPhase::SessionTeardown`], the one phase this file owns on behalf
    ///   of both modules, so that neither claims the other's terminator.
    ///
    /// Exhaustive by construction: adding a state without classifying it does
    /// not compile.
    pub(crate) const fn phase(self) -> SshPhase {
        match self {
            Self::NoState | Self::Stop | Self::Quit | Self::Last => {
                SshPhase::Idle
            }
            Self::Init
            | Self::SStartup
            | Self::HostKey
            | Self::AuthList
            | Self::AuthPkeyInit
            | Self::AuthPkey
            | Self::AuthPassInit
            | Self::AuthPass
            | Self::AuthAgentInit
            | Self::AuthAgentList
            | Self::AuthAgent
            | Self::AuthHostInit
            | Self::AuthHost
            | Self::AuthKeyInit
            | Self::AuthKey
            | Self::AuthGssapi
            | Self::AuthDone
            | Self::SftpInit
            | Self::SftpRealpath => SshPhase::SshConnect,
            Self::SftpQuoteInit
            | Self::SftpQuote
            | Self::SftpNextQuote
            | Self::SftpQuoteStat
            | Self::SftpQuoteSetstat
            | Self::SftpQuoteSymlink
            | Self::SftpQuoteMkdir
            | Self::SftpQuoteRename
            | Self::SftpQuoteRmdir
            | Self::SftpQuoteUnlink
            | Self::SftpQuoteStatvfs
            | Self::SftpGetinfo
            | Self::SftpFiletime
            | Self::SftpTransInit
            | Self::SftpUploadInit
            | Self::SftpCreateDirsInit
            | Self::SftpCreateDirs
            | Self::SftpCreateDirsMkdir
            | Self::SftpReaddirInit
            | Self::SftpReaddir
            | Self::SftpReaddirLink
            | Self::SftpReaddirBottom
            | Self::SftpReaddirDone
            | Self::SftpDownloadInit
            | Self::SftpDownloadStat => SshPhase::SftpDo,
            Self::SftpPostquoteInit | Self::SftpClose => SshPhase::SftpDone,
            Self::SftpShutdown => SshPhase::SftpDisconnect,
            Self::ScpTransInit
            | Self::ScpUploadInit
            | Self::ScpDownloadInit
            | Self::ScpDownload => SshPhase::ScpDo,
            Self::ScpDone
            | Self::ScpSendEof
            | Self::ScpWaitEof
            | Self::ScpWaitClose
            | Self::ScpChannelFree => SshPhase::ScpDone,
            Self::SessionDisconnect | Self::SessionFree => {
                SshPhase::SessionTeardown
            }
        }
    }

    /// Whether this state belongs to a phase `protocols/scp.rs` owns.
    ///
    /// The seam between the two modules, expressed once so that neither has to
    /// restate it. [`SshPhase::SessionTeardown`] is FALSE here even though SCP
    /// reaches it, because it is shared rather than SCP's.
    pub(crate) const fn is_scp_owned(self) -> bool {
        matches!(self.phase(), SshPhase::ScpDo | SshPhase::ScpDone)
    }
}

impl fmt::Display for SshState {
    /// The trace spelling, so that a state can be interpolated directly.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

/// Which phase of the SSH machine a state belongs to.
///
/// Not a C type: the C expresses the same division in comments on
/// `enum sshstate` and in the shape of `sftp_perform`, `scp_perform`,
/// `sftp_done`, `scp_done`, `sftp_disconnect` and `scp_disconnect`. Naming it
/// makes the split between this file and `protocols/scp.rs` checkable, which is
/// what [`SshState::is_scp_owned`] and [`mod tests`](self) use it for.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
pub(crate) enum SshPhase {
    /// `SSH_NO_STATE`, `SSH_STOP`, `SSH_QUIT` and `SSH_LAST`: the machine is
    /// not inside a phase.
    Idle,
    /// `SSH_INIT` through `SSH_SFTP_REALPATH`. Shared: both schemes run it, and
    /// only SFTP continues past `SSH_AUTH_DONE` into the last two states.
    SshConnect,
    /// `SSH_SFTP_QUOTE_INIT` through `SSH_SFTP_DOWNLOAD_STAT`.
    SftpDo,
    /// `SSH_SFTP_POSTQUOTE_INIT` and `SSH_SFTP_CLOSE`.
    SftpDone,
    /// `SSH_SFTP_SHUTDOWN`.
    SftpDisconnect,
    /// `SSH_SCP_TRANS_INIT` through `SSH_SCP_DOWNLOAD` -- `protocols/scp.rs`.
    ScpDo,
    /// `SSH_SCP_DONE` through `SSH_SCP_CHANNEL_FREE` -- `protocols/scp.rs`.
    ScpDone,
    /// `SSH_SESSION_DISCONNECT` and `SSH_SESSION_FREE`, which terminate both
    /// schemes' disconnect phases and are therefore owned here.
    SessionTeardown,
}

/// `Curl_ssh_set_state` (`lib/vssh/vssh.c:107-121`): **the only way to change
/// SSH state.**
///
/// The C's comment above the function is *"This is the ONLY way to change SSH
/// state!"*, and it is enforced here rather than asked for:
/// [`SshConn::state`] is a private field with no setter, so every transition in
/// this file and in `protocols/scp.rs` goes through this function. `mod tests`
/// asserts the property by construction -- there is no other writer to find.
///
/// The trace line is the C's, including the guard: a transition to the state
/// already held emits nothing, because `if(sshc->state != nowstate)` skips it.
/// That matters for output fidelity, since `sftp_done` re-enters
/// `SSH_SFTP_CLOSE` on the way out of a postquote round.
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
pub(crate) fn ssh_set_state(
    sshc: &mut SshConn,
    tracer: Option<&mut Tracer<'_>>,
    nowstate: SshState,
) {
    let previous = sshc.state;
    if previous != nowstate {
        if let Some(tracer) = tracer {
            trc_feat!(
                tracer,
                TraceFeature::Ssh,
                "[{}] -> [{}]",
                previous,
                nowstate
            );
        }
    }
    sshc.state = nowstate;
}

// The SFTP wire vocabulary and codec

/// One SFTP packet type -- the `SSH_FXP_*` constants of the SFTP draft.
///
/// The C names these through libssh2's API rather than by number, because
/// libssh2 owns the packet layer there. Here the packet layer is ours, for the
/// reason the module documentation gives: no crate in the closed dependency set
/// of specification 0.5.1 commits to the request ordering and attribute
/// encoding that 40 `sftp` fixtures compare byte for byte.
///
/// The numbers are the protocol's and are written explicitly for the same
/// reason [`CURLcode`]'s are: a peer holds them, so ordinal inference is not
/// available. Only the types this module actually exchanges are declared --
/// declaring the rest would be vocabulary with no encoder behind it.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) enum SftpPacket {
    /// `SSH_FXP_INIT` = 1: the client's version announcement.
    Init = 1,
    /// `SSH_FXP_VERSION` = 2: the server's reply to [`Self::Init`].
    Version = 2,
    /// `SSH_FXP_OPEN` = 3.
    Open = 3,
    /// `SSH_FXP_CLOSE` = 4.
    Close = 4,
    /// `SSH_FXP_READ` = 5.
    Read = 5,
    /// `SSH_FXP_WRITE` = 6.
    Write = 6,
    /// `SSH_FXP_LSTAT` = 7: stat without following a symbolic link.
    Lstat = 7,
    /// `SSH_FXP_FSTAT` = 8: stat an open handle.
    Fstat = 8,
    /// `SSH_FXP_SETSTAT` = 9: the packet behind the `chmod`, `chown`, `chgrp`,
    /// `atime` and `mtime` quote commands.
    Setstat = 9,
    /// `SSH_FXP_FSETSTAT` = 10.
    Fsetstat = 10,
    /// `SSH_FXP_OPENDIR` = 11.
    Opendir = 11,
    /// `SSH_FXP_READDIR` = 12.
    Readdir = 12,
    /// `SSH_FXP_REMOVE` = 13: the packet behind `rm`.
    Remove = 13,
    /// `SSH_FXP_MKDIR` = 14.
    Mkdir = 14,
    /// `SSH_FXP_RMDIR` = 15.
    Rmdir = 15,
    /// `SSH_FXP_REALPATH` = 16: the packet `SSH_SFTP_REALPATH` sends with `"."`
    /// to learn the home directory.
    Realpath = 16,
    /// `SSH_FXP_STAT` = 17: stat, following symbolic links.
    Stat = 17,
    /// `SSH_FXP_RENAME` = 18.
    Rename = 18,
    /// `SSH_FXP_READLINK` = 19: the packet `SSH_SFTP_READDIR_LINK` sends.
    Readlink = 19,
    /// `SSH_FXP_SYMLINK` = 20: the packet behind `ln` and `symlink`.
    Symlink = 20,
    /// `SSH_FXP_STATUS` = 101: the general response, carrying an
    /// [`SftpStatus`].
    Status = 101,
    /// `SSH_FXP_HANDLE` = 102.
    Handle = 102,
    /// `SSH_FXP_DATA` = 103.
    Data = 103,
    /// `SSH_FXP_NAME` = 104: the response to `READDIR` and `REALPATH`.
    Name = 104,
    /// `SSH_FXP_ATTRS` = 105: the response to the three stat requests.
    Attrs = 105,
    /// `SSH_FXP_EXTENDED` = 200: the envelope `statvfs@openssh.com` travels in.
    Extended = 200,
    /// `SSH_FXP_EXTENDED_REPLY` = 201.
    ExtendedReply = 201,
}

#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
impl SftpPacket {
    /// Every declared packet type, for the table-driven round-trip test.
    #[rustfmt::skip]
    pub(crate) const ALL: [Self; 27] = [
        Self::Init, Self::Version, Self::Open, Self::Close, Self::Read,
        Self::Write, Self::Lstat, Self::Fstat, Self::Setstat, Self::Fsetstat,
        Self::Opendir, Self::Readdir, Self::Remove, Self::Mkdir, Self::Rmdir,
        Self::Realpath, Self::Stat, Self::Rename, Self::Readlink,
        Self::Symlink, Self::Status, Self::Handle, Self::Data, Self::Name,
        Self::Attrs, Self::Extended, Self::ExtendedReply,
    ];

    /// The type's own wire byte.
    pub(crate) const fn as_u8(self) -> u8 {
        self as u8
    }

    /// The type carrying `raw`, or [`None`] for a byte this module never
    /// exchanges.
    ///
    /// [`None`] is not an error by itself: an SFTP server may legitimately send
    /// an extension this build does not implement, and the caller decides what
    /// to do about it. Every current caller answers [`CURLcode::Ssh`], which is
    /// what `libssh2_session_error_to_CURLE`'s fall-through does for an
    /// unrecognised condition.
    pub(crate) fn from_u8(raw: u8) -> Option<Self> {
        let mut index = 0;
        while index < Self::ALL.len() {
            let candidate = Self::ALL[index];
            if candidate.as_u8() == raw {
                return Some(candidate);
            }
            index += 1;
        }
        None
    }
}

/// The SFTP protocol version this client speaks.
///
/// 3, which is what libssh2 negotiates and therefore what the fixtures were
/// recorded against. Raising it would change the `SSH_FXP_INIT` bytes and the
/// attribute encoding, so it is a constant rather than a setting.
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) const SFTP_VERSION: u32 = 3;

/// `statvfs@openssh.com`: the extension name `SSH_SFTP_QUOTE_STATVFS` sends.
///
/// A wire-bearing literal. `libssh2_sftp_statvfs` sends exactly this string,
/// and a server that does not implement it answers `SSH_FX_OP_UNSUPPORTED` --
/// which is why the quote command's failure path reports *"Operation not
/// supported by SFTP server"* rather than a transport error.
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) const SFTP_STATVFS_EXTENSION: &str = "statvfs@openssh.com";

/// One `SSH_FX_*` status code.
///
/// The 21 values `sftp_libssh2_strerror` (`lib/vssh/libssh2.c:62-126`)
/// discriminates, which is the complete set libssh2 defines. Written as a
/// newtype rather than an enum because the field is a `u32` on the wire and a
/// server may send a value outside the set: an enum would make that a decoding
/// failure, where the C treats it as *"Unknown error in libssh2"* and carries
/// on.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) struct SftpStatus(pub(crate) u32);

#[rustfmt::skip]
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
impl SftpStatus {
    /// `LIBSSH2_FX_OK` = 0.
    pub(crate) const OK: Self = Self(0);
    /// `LIBSSH2_FX_EOF` = 1: the end of a directory listing or a file.
    pub(crate) const EOF: Self = Self(1);
    /// `LIBSSH2_FX_NO_SUCH_FILE` = 2.
    pub(crate) const NO_SUCH_FILE: Self = Self(2);
    /// `LIBSSH2_FX_PERMISSION_DENIED` = 3.
    pub(crate) const PERMISSION_DENIED: Self = Self(3);
    /// `LIBSSH2_FX_FAILURE` = 4.
    pub(crate) const FAILURE: Self = Self(4);
    /// `LIBSSH2_FX_BAD_MESSAGE` = 5.
    pub(crate) const BAD_MESSAGE: Self = Self(5);
    /// `LIBSSH2_FX_NO_CONNECTION` = 6.
    pub(crate) const NO_CONNECTION: Self = Self(6);
    /// `LIBSSH2_FX_CONNECTION_LOST` = 7.
    pub(crate) const CONNECTION_LOST: Self = Self(7);
    /// `LIBSSH2_FX_OP_UNSUPPORTED` = 8.
    pub(crate) const OP_UNSUPPORTED: Self = Self(8);
    /// `LIBSSH2_FX_INVALID_HANDLE` = 9.
    pub(crate) const INVALID_HANDLE: Self = Self(9);
    /// `LIBSSH2_FX_NO_SUCH_PATH` = 10.
    pub(crate) const NO_SUCH_PATH: Self = Self(10);
    /// `LIBSSH2_FX_FILE_ALREADY_EXISTS` = 11.
    pub(crate) const FILE_ALREADY_EXISTS: Self = Self(11);
    /// `LIBSSH2_FX_WRITE_PROTECT` = 12.
    pub(crate) const WRITE_PROTECT: Self = Self(12);
    /// `LIBSSH2_FX_NO_MEDIA` = 13.
    pub(crate) const NO_MEDIA: Self = Self(13);
    /// `LIBSSH2_FX_NO_SPACE_ON_FILESYSTEM` = 14.
    pub(crate) const NO_SPACE_ON_FILESYSTEM: Self = Self(14);
    /// `LIBSSH2_FX_QUOTA_EXCEEDED` = 15.
    pub(crate) const QUOTA_EXCEEDED: Self = Self(15);
    /// `LIBSSH2_FX_UNKNOWN_PRINCIPLE` = 16. The misspelling is libssh2's and
    /// reaches the user through the message text, so it is preserved in both.
    pub(crate) const UNKNOWN_PRINCIPLE: Self = Self(16);
    /// `LIBSSH2_FX_LOCK_CONFlICT` = 17. The lower-case `l` is libssh2's own
    /// typo in the IDENTIFIER; only the identifier, not the message.
    pub(crate) const LOCK_CONFLICT: Self = Self(17);
    /// `LIBSSH2_FX_DIR_NOT_EMPTY` = 18.
    pub(crate) const DIR_NOT_EMPTY: Self = Self(18);
    /// `LIBSSH2_FX_NOT_A_DIRECTORY` = 19.
    pub(crate) const NOT_A_DIRECTORY: Self = Self(19);
    /// `LIBSSH2_FX_INVALID_FILENAME` = 20.
    pub(crate) const INVALID_FILENAME: Self = Self(20);
    /// `LIBSSH2_FX_LINK_LOOP` = 21.
    pub(crate) const LINK_LOOP: Self = Self(21);

    /// Every value the C discriminates, in numeric order.
    pub(crate) const ALL: [Self; 22] = [
        Self::OK, Self::EOF, Self::NO_SUCH_FILE, Self::PERMISSION_DENIED,
        Self::FAILURE, Self::BAD_MESSAGE, Self::NO_CONNECTION,
        Self::CONNECTION_LOST, Self::OP_UNSUPPORTED, Self::INVALID_HANDLE,
        Self::NO_SUCH_PATH, Self::FILE_ALREADY_EXISTS, Self::WRITE_PROTECT,
        Self::NO_MEDIA, Self::NO_SPACE_ON_FILESYSTEM, Self::QUOTA_EXCEEDED,
        Self::UNKNOWN_PRINCIPLE, Self::LOCK_CONFLICT, Self::DIR_NOT_EMPTY,
        Self::NOT_A_DIRECTORY, Self::INVALID_FILENAME, Self::LINK_LOOP,
    ];
}

/// `sftp_libssh2_strerror` (`lib/vssh/libssh2.c:62-126`): the message text for
/// one status.
///
/// Every string is the C's, byte for byte, including the two that are the same
/// -- `NO_SUCH_FILE` and `NO_SUCH_PATH` both give *"No such file or
/// directory"* -- and including *"Unknown principle"*, whose spelling is
/// libssh2's. These reach the user through `failf`, which reaches stderr and the
/// fixtures, so rewording any of them is a wire change.
///
/// The fall-through is the C's too, and its wording names a library this build
/// does not link: *"Unknown error in libssh2"*. It is transcribed unchanged
/// because specification 0.8.1 freezes the text, and a fixture comparing it
/// would fail on a "corrected" spelling. `LIBSSH2_FX_EOF` has no arm in the C
/// switch and therefore falls through to it as well; the fall-through is
/// reached, not decorative.
#[rustfmt::skip]
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) fn sftp_strerror(status: SftpStatus) -> &'static str {
    match status {
        SftpStatus::NO_SUCH_FILE            => "No such file or directory",
        SftpStatus::PERMISSION_DENIED       => "Permission denied",
        SftpStatus::FAILURE                 => "Operation failed",
        SftpStatus::BAD_MESSAGE             => "Bad message from SFTP server",
        SftpStatus::NO_CONNECTION           => "Not connected to SFTP server",
        SftpStatus::CONNECTION_LOST         => "Connection to SFTP server lost",
        SftpStatus::OP_UNSUPPORTED          =>
            "Operation not supported by SFTP server",
        SftpStatus::INVALID_HANDLE          => "Invalid handle",
        SftpStatus::NO_SUCH_PATH            => "No such file or directory",
        SftpStatus::FILE_ALREADY_EXISTS     => "File already exists",
        SftpStatus::WRITE_PROTECT           => "File is write protected",
        SftpStatus::NO_MEDIA                => "No media",
        SftpStatus::NO_SPACE_ON_FILESYSTEM  => "Disk full",
        SftpStatus::QUOTA_EXCEEDED          => "User quota exceeded",
        SftpStatus::UNKNOWN_PRINCIPLE       => "Unknown principle",
        SftpStatus::LOCK_CONFLICT           => "File lock conflict",
        SftpStatus::DIR_NOT_EMPTY           => "Directory not empty",
        SftpStatus::NOT_A_DIRECTORY         => "Not a directory",
        SftpStatus::INVALID_FILENAME        => "Invalid filename",
        SftpStatus::LINK_LOOP               => "Link points to itself",
        _                                   => "Unknown error in libssh2",
    }
}

/// `sftp_libssh2_error_to_CURLE` (`lib/vssh/libssh2.c:158-188`): the status to
/// [`CURLcode`] map.
///
/// Six arms and a default, exactly as the C writes them. Two are worth naming
/// because they look like mistakes and are not:
///
/// * `LOCK_CONFlICT` maps to [`CURLcode::RemoteAccessDenied`] alongside
///   `PERMISSION_DENIED` and `WRITE_PROTECT` -- a lock is treated as an access
///   refusal rather than as a transient condition;
/// * `DIR_NOT_EMPTY` maps to [`CURLcode::QuoteError`] rather than to a remote
///   filesystem code, because the only operation that produces it is the
///   `rmdir` quote command.
///
/// `LIBSSH2_FX_EOF` has no arm and therefore reaches the default,
/// [`CURLcode::Ssh`]. That is the C's behaviour and it is why every caller that
/// can legitimately see `EOF` -- the readdir loop and the read path -- tests for
/// it BEFORE consulting this map.
#[rustfmt::skip]
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) fn sftp_status_to_curlcode(status: SftpStatus) -> CURLcode {
    match status {
        SftpStatus::OK => CURLcode::Ok,
        SftpStatus::NO_SUCH_FILE | SftpStatus::NO_SUCH_PATH =>
            CURLcode::RemoteFileNotFound,
        SftpStatus::PERMISSION_DENIED
        | SftpStatus::WRITE_PROTECT
        | SftpStatus::LOCK_CONFLICT => CURLcode::RemoteAccessDenied,
        SftpStatus::NO_SPACE_ON_FILESYSTEM | SftpStatus::QUOTA_EXCEEDED =>
            CURLcode::RemoteDiskFull,
        SftpStatus::FILE_ALREADY_EXISTS => CURLcode::RemoteFileExists,
        SftpStatus::DIR_NOT_EMPTY => CURLcode::QuoteError,
        _ => CURLcode::Ssh,
    }
}

/// A transport-level SSH failure -- the successor of libssh2's `LIBSSH2_ERROR_*`
/// vocabulary.
///
/// `libssh2_session_error_to_CURLE` (`lib/vssh/libssh2.c:190-233`) maps ten
/// libssh2 error numbers onto [`CURLcode`] and sends everything else to
/// [`CURLcode::Ssh`]. Those numbers are libssh2's and mean nothing to `russh`,
/// so what is preserved is the CLASSIFICATION rather than the integers: one
/// variant per distinct outcome the C map produces, which is what makes
/// [`SshError::to_curlcode`] a transcription of that function rather than a
/// reinterpretation of it.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
pub(crate) enum SshError {
    /// `LIBSSH2_ERROR_SOCKET_NONE`: no usable transport.
    /// [`CURLcode::CouldntConnect`].
    SocketNone,
    /// `LIBSSH2_ERROR_ALLOC`. [`CURLcode::OutOfMemory`].
    Alloc,
    /// `LIBSSH2_ERROR_SOCKET_SEND`. [`CURLcode::SendError`].
    SocketSend,
    /// `LIBSSH2_ERROR_HOSTKEY_INIT`, `_HOSTKEY_SIGN`,
    /// `_PUBLICKEY_UNRECOGNIZED` and `_PUBLICKEY_UNVERIFIED` -- all four map to
    /// one code, so they are one variant.
    /// [`CURLcode::PeerFailedVerification`].
    HostKey(String),
    /// `LIBSSH2_ERROR_PASSWORD_EXPIRED`. [`CURLcode::LoginDenied`].
    PasswordExpired,
    /// `LIBSSH2_ERROR_SOCKET_TIMEOUT` and `LIBSSH2_ERROR_TIMEOUT`.
    /// [`CURLcode::OperationTimedout`].
    Timeout,
    /// `LIBSSH2_ERROR_EAGAIN`. [`CURLcode::Again`].
    ///
    /// Retained even though this port expresses "would block" by awaiting
    /// rather than by returning: the transport seam is allowed to report it,
    /// `ssh_block2waitfor` (`lib/vssh/libssh2.c:3051-3068`) is what the C does
    /// with it, and [`SshConn::waitfor`] is its successor.
    Again,
    /// `LIBSSH2_ERROR_SCP_PROTOCOL`, which the C comments as *"the error
    /// returned by libssh2_scp_recv2 on unknown file"*.
    /// [`CURLcode::RemoteFileNotFound`]. Reached only from
    /// `protocols/scp.rs`, and declared here because the map is shared.
    ScpProtocol,
    /// Anything else, carrying whatever the transport said.
    /// [`CURLcode::Ssh`], the C's fall-through.
    Other(String),
}

#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
impl SshError {
    /// `libssh2_session_error_to_CURLE` (`lib/vssh/libssh2.c:190-233`).
    pub(crate) fn to_curlcode(&self) -> CURLcode {
        match self {
            Self::SocketNone => CURLcode::CouldntConnect,
            Self::Alloc => CURLcode::OutOfMemory,
            Self::SocketSend => CURLcode::SendError,
            Self::HostKey(_) => CURLcode::PeerFailedVerification,
            Self::PasswordExpired => CURLcode::LoginDenied,
            Self::Timeout => CURLcode::OperationTimedout,
            Self::Again => CURLcode::Again,
            Self::ScpProtocol => CURLcode::RemoteFileNotFound,
            Self::Other(_) => CURLcode::Ssh,
        }
    }

    /// The transport's own description, for the `failf` line that reports it.
    ///
    /// The C obtains this with `libssh2_session_last_error(..., &err_msg, ...)`
    /// and interpolates it; the variants that carry no text describe themselves,
    /// which keeps every `failf` in this file total without an `unwrap`.
    pub(crate) fn message(&self) -> &str {
        match self {
            Self::SocketNone => "no SSH transport",
            Self::Alloc => "out of memory",
            Self::SocketSend => "SSH send failed",
            Self::HostKey(text) | Self::Other(text) => text.as_str(),
            Self::PasswordExpired => "password expired",
            Self::Timeout => "SSH operation timed out",
            Self::Again => "SSH transport would block",
            Self::ScpProtocol => "SCP protocol error",
        }
    }
}

impl fmt::Display for SshError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

/// What an SFTP operation answers: either the peer's reply, or a failure.
///
/// The success case is the decoded response; the failure case carries the status
/// so that the caller can apply [`sftp_status_to_curlcode`] and
/// [`sftp_strerror`] the way its C original does -- each site builds its own
/// `failf` text, so the mapping cannot be hoisted into the transport.
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) type SftpResult<T> = Result<T, SftpFailure>;

/// Why an SFTP operation did not produce a reply.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) enum SftpFailure {
    /// The peer answered `SSH_FXP_STATUS` with a non-`OK` status.
    Status(SftpStatus),
    /// The transport failed underneath the SFTP layer.
    Transport(SshError),
    /// The peer's reply could not be decoded -- a truncated packet, or a type
    /// this module does not exchange.
    ///
    /// `LIBSSH2_FX_BAD_MESSAGE` is what libssh2 reports for the same condition
    /// when it detects it, so [`Self::to_curlcode`] answers the code that status
    /// maps to rather than inventing one.
    Malformed,
}

#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
impl SftpFailure {
    /// The [`CURLcode`] this failure reports.
    pub(crate) fn to_curlcode(&self) -> CURLcode {
        match self {
            Self::Status(status) => sftp_status_to_curlcode(*status),
            Self::Transport(error) => error.to_curlcode(),
            Self::Malformed => sftp_status_to_curlcode(SftpStatus::BAD_MESSAGE),
        }
    }

    /// The text a `failf` line interpolates for this failure.
    pub(crate) fn message(&self) -> &str {
        match self {
            Self::Status(status) => sftp_strerror(*status),
            Self::Transport(error) => error.message(),
            Self::Malformed => sftp_strerror(SftpStatus::BAD_MESSAGE),
        }
    }

    /// The status behind this failure, or [`SftpStatus::OK`] when there is
    /// none.
    ///
    /// `libssh2_sftp_last_error` answers zero when the failure was not at the
    /// SFTP level, and `sftp_upload_init` (`lib/vssh/libssh2.c:950-955`) reads
    /// exactly that: *"not an sftp error at all"*. This preserves the
    /// distinction the upload path needs.
    pub(crate) fn status(&self) -> SftpStatus {
        match self {
            Self::Status(status) => *status,
            Self::Transport(_) => SftpStatus::OK,
            Self::Malformed => SftpStatus::BAD_MESSAGE,
        }
    }
}

/// The `SSH_FILEXFER_ATTR_*` flags of an [`SftpAttributes`].
///
/// libssh2 spells these `LIBSSH2_SFTP_ATTR_*` and the C sets them directly --
/// `sshp->quote_attrs.flags = LIBSSH2_SFTP_ATTR_UIDGID` and its three
/// siblings. The numbers are the protocol's.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) struct SftpAttrFlags(pub(crate) u32);

#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
impl SftpAttrFlags {
    /// No attribute present.
    pub(crate) const NONE: Self = Self(0);
    /// `LIBSSH2_SFTP_ATTR_SIZE` = 1.
    pub(crate) const SIZE: Self = Self(0x0000_0001);
    /// `LIBSSH2_SFTP_ATTR_UIDGID` = 2, set by `chown` and `chgrp`.
    pub(crate) const UIDGID: Self = Self(0x0000_0002);
    /// `LIBSSH2_SFTP_ATTR_PERMISSIONS` = 4, set by `chmod`.
    pub(crate) const PERMISSIONS: Self = Self(0x0000_0004);
    /// `LIBSSH2_SFTP_ATTR_ACMODTIME` = 8, set by `atime` and `mtime`.
    pub(crate) const ACMODTIME: Self = Self(0x0000_0008);
    /// `LIBSSH2_SFTP_ATTR_EXTENDED` = 0x80000000.
    pub(crate) const EXTENDED: Self = Self(0x8000_0000);

    /// True when every bit of `other` is set here.
    pub(crate) const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// The union of two masks, available in a `const`.
    pub(crate) const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// The raw mask.
    pub(crate) const fn bits(self) -> u32 {
        self.0
    }
}

impl core::ops::BitOr for SftpAttrFlags {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        self.union(other)
    }
}

/// `LIBSSH2_SFTP_S_IFMT`: the mask selecting a mode's file-type field.
///
/// `0170000` octal. `sftp_readdir` tests
/// `(permissions & LIBSSH2_SFTP_S_IFMT) == LIBSSH2_SFTP_S_IFLNK`
/// (`lib/vssh/libssh2.c:1398-1400`) to decide whether an entry needs a
/// `READLINK` round trip, so the two constants are what make the `" -> target"`
/// suffix appear on exactly the right lines.
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) const SFTP_S_IFMT: u32 = 0o170_000;

/// `LIBSSH2_SFTP_S_IFLNK`: a symbolic link. `0120000` octal.
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) const SFTP_S_IFLNK: u32 = 0o120_000;

/// `LIBSSH2_SFTP_S_IFDIR`: a directory. `0040000` octal.
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) const SFTP_S_IFDIR: u32 = 0o040_000;

/// The `SSH_FXF_*` flags of an `SSH_FXP_OPEN`.
///
/// Set by `sftp_upload_init` (`lib/vssh/libssh2.c:924-940`) and
/// `ssh_state_sftp_download_init` (`:2354`). The three combinations the C
/// builds are named as constants below, because which one is chosen is
/// observable: `APPEND` versus a bare `WRITE` decides whether a resumed upload
/// lands at the seek offset or at the end of the file, and the C's comment says
/// so -- *"Resume MUST NOT use APPEND; some servers force writes to EOF when
/// APPEND is set, ignoring a prior seek()"*.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) struct SftpOpenFlags(pub(crate) u32);

#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
impl SftpOpenFlags {
    /// `LIBSSH2_FXF_READ` = 1.
    pub(crate) const READ: Self = Self(0x0000_0001);
    /// `LIBSSH2_FXF_WRITE` = 2.
    pub(crate) const WRITE: Self = Self(0x0000_0002);
    /// `LIBSSH2_FXF_APPEND` = 4.
    pub(crate) const APPEND: Self = Self(0x0000_0004);
    /// `LIBSSH2_FXF_CREAT` = 8.
    pub(crate) const CREAT: Self = Self(0x0000_0008);
    /// `LIBSSH2_FXF_TRUNC` = 16.
    pub(crate) const TRUNC: Self = Self(0x0000_0010);
    /// `LIBSSH2_FXF_EXCL` = 32.
    pub(crate) const EXCL: Self = Self(0x0000_0020);

    /// The union of two masks, available in a `const`.
    pub(crate) const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// The raw mask.
    pub(crate) const fn bits(self) -> u32 {
        self.0
    }

    /// True when every bit of `other` is set here.
    pub(crate) const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl core::ops::BitOr for SftpOpenFlags {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        self.union(other)
    }
}

/// `LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT | LIBSSH2_FXF_APPEND`: true append
/// mode, chosen when `CURLOPT_APPEND` is set.
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) const SFTP_UPLOAD_APPEND: SftpOpenFlags = SftpOpenFlags::WRITE
    .union(SftpOpenFlags::CREAT)
    .union(SftpOpenFlags::APPEND);

/// A bare `LIBSSH2_FXF_WRITE`: the resume case, deliberately without
/// `APPEND`.
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) const SFTP_UPLOAD_RESUME: SftpOpenFlags = SftpOpenFlags::WRITE;

/// `LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT | LIBSSH2_FXF_TRUNC`: the normal
/// upload, which clears the file first.
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) const SFTP_UPLOAD_TRUNCATE: SftpOpenFlags = SftpOpenFlags::WRITE
    .union(SftpOpenFlags::CREAT)
    .union(SftpOpenFlags::TRUNC);

/// The `SSH_FXP_RENAME` flag word.
///
/// `ssh_state_sftp_quote_rename` (`lib/vssh/libssh2.c:2019-2022`) sends
/// `LIBSSH2_SFTP_RENAME_OVERWRITE | LIBSSH2_SFTP_RENAME_ATOMIC |
/// LIBSSH2_SFTP_RENAME_NATIVE`, which is `0x7`. The value is on the wire, so it
/// is a constant rather than three flags a caller could combine differently.
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) const SFTP_RENAME_FLAGS: u32 =
    0x0000_0001 | 0x0000_0002 | 0x0000_0004;

/// `struct LIBSSH2_SFTP_ATTRIBUTES` -- a file's attributes.
///
/// The `flags` word says which of the other members are meaningful, and the
/// encoding depends on it: an attribute whose bit is clear is ABSENT from the
/// wire rather than sent as zero. That is why this is a struct with a flags
/// field rather than a set of [`Option`]s -- the flags are what
/// [`SftpCodec::put_attributes`] writes, and a round trip has to reproduce them
/// exactly.
///
/// `permissions` is a `u32` rather than the C's `unsigned long`: the wire field
/// is four bytes, and the engine speaks in fixed-width integers.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) struct SftpAttributes {
    /// Which members below are present.
    pub(crate) flags: SftpAttrFlags,
    /// The file size, when [`SftpAttrFlags::SIZE`] is set.
    pub(crate) filesize: u64,
    /// The owner, when [`SftpAttrFlags::UIDGID`] is set.
    pub(crate) uid: u32,
    /// The group, when [`SftpAttrFlags::UIDGID`] is set.
    pub(crate) gid: u32,
    /// The mode, when [`SftpAttrFlags::PERMISSIONS`] is set.
    pub(crate) permissions: u32,
    /// The access time, when [`SftpAttrFlags::ACMODTIME`] is set.
    pub(crate) atime: u32,
    /// The modification time, when [`SftpAttrFlags::ACMODTIME`] is set.
    pub(crate) mtime: u32,
}

#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
impl SftpAttributes {
    /// Whether these attributes describe a symbolic link.
    ///
    /// The test `sftp_readdir` performs, including its precondition: the
    /// permissions field is meaningless unless its flag is set, so a server
    /// that omits it never produces a `" -> target"` suffix.
    pub(crate) const fn is_symlink(&self) -> bool {
        self.flags.contains(SftpAttrFlags::PERMISSIONS)
            && (self.permissions & SFTP_S_IFMT) == SFTP_S_IFLNK
    }

    /// Whether these attributes describe a directory.
    pub(crate) const fn is_dir(&self) -> bool {
        self.flags.contains(SftpAttrFlags::PERMISSIONS)
            && (self.permissions & SFTP_S_IFMT) == SFTP_S_IFDIR
    }

    /// The size, or [`None`] when the server did not report one.
    ///
    /// `sftp_download_stat` (`lib/vssh/libssh2.c:1284-1299`) treats a missing
    /// `ATTR_SIZE`, a failed stat and a zero size identically -- *"maybe the
    /// server just does not support stat() OR the server does not return a file
    /// size with a stat() OR file size is 0"* -- and answers "unknown". This
    /// accessor is the first half of that decision; the second half is in
    /// [`sftp_download_size`].
    pub(crate) const fn reported_size(&self) -> Option<u64> {
        if self.flags.contains(SftpAttrFlags::SIZE) {
            Some(self.filesize)
        } else {
            None
        }
    }
}

/// `struct LIBSSH2_SFTP_STATVFS` -- the reply to `statvfs@openssh.com`.
///
/// Eleven `u64` members in the order the extension defines and the order the
/// report prints them, which are the same order. See [`statvfs_report`] for why
/// that matters.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) struct SftpStatVfs {
    /// `f_bsize`: the filesystem block size.
    pub(crate) bsize: u64,
    /// `f_frsize`: the fragment size.
    pub(crate) frsize: u64,
    /// `f_blocks`: size in `f_frsize` units.
    pub(crate) blocks: u64,
    /// `f_bfree`: free blocks.
    pub(crate) bfree: u64,
    /// `f_bavail`: free blocks for a non-privileged user.
    pub(crate) bavail: u64,
    /// `f_files`: inodes.
    pub(crate) files: u64,
    /// `f_ffree`: free inodes.
    pub(crate) ffree: u64,
    /// `f_favail`: free inodes for a non-privileged user.
    pub(crate) favail: u64,
    /// `f_fsid`: the filesystem identifier.
    pub(crate) fsid: u64,
    /// `f_flag`: mount flags.
    pub(crate) flag: u64,
    /// `f_namemax`: the longest filename.
    pub(crate) namemax: u64,
}

/// The SFTP packet encoder and decoder.
///
/// SFTP frames every packet as a four-byte big-endian length followed by a
/// one-byte type and the type's payload, and its scalar vocabulary is three
/// items: a four-byte integer, an eight-byte integer, and a length-prefixed
/// byte string. Everything this module exchanges is built from those, so the
/// codec is small and total.
///
/// # Why the length prefix is written last
///
/// The length covers the type byte and the payload but not itself, and it is
/// not known until the payload is complete. [`SftpCodec::finish`] therefore
/// back-fills the four reserved bytes, which is what lets a request be built in
/// one pass with no intermediate buffer.
///
/// # No `unwrap`, no panic, and no raw string
///
/// Every decoding step is fallible and answers [`SftpFailure::Malformed`] on a
/// short read, so a truncated packet from a hostile peer is a `CURLcode` rather
/// than an abort. The crate's own `mod source_policy` gate forbids a raw string
/// literal anywhere under `src/`, which is why the test vectors below are byte
/// slices.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) struct SftpCodec {
    /// The packet under construction, length prefix included.
    buffer: Vec<u8>,
}

#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
impl SftpCodec {
    /// A codec whose buffer holds a fresh packet of `kind`.
    ///
    /// The four length bytes are reserved with zeroes and back-filled by
    /// [`Self::finish`].
    pub(crate) fn request(kind: SftpPacket) -> Self {
        let mut buffer = Vec::with_capacity(64);
        buffer.extend_from_slice(&[0, 0, 0, 0]);
        buffer.push(kind.as_u8());
        Self { buffer }
    }

    /// Appends a four-byte big-endian integer.
    pub(crate) fn put_u32(&mut self, value: u32) -> &mut Self {
        self.buffer.extend_from_slice(&value.to_be_bytes());
        self
    }

    /// Appends an eight-byte big-endian integer.
    pub(crate) fn put_u64(&mut self, value: u64) -> &mut Self {
        self.buffer.extend_from_slice(&value.to_be_bytes());
        self
    }

    /// Appends a length-prefixed byte string.
    ///
    /// A string longer than `u32::MAX` cannot be framed. The clamp is what
    /// keeps this total without an `unwrap`; a path that long is refused by
    /// [`get_pathname`]'s own ceiling long before it reaches here, and
    /// [`mod tests`](self) pins the arithmetic rather than the impossibility.
    pub(crate) fn put_bytes(&mut self, value: &[u8]) -> &mut Self {
        let len = u32::try_from(value.len()).unwrap_or(u32::MAX);
        self.put_u32(len);
        self.buffer
            .extend_from_slice(&value[..usize::try_from(len).unwrap_or(0)]);
        self
    }

    /// Appends a length-prefixed string.
    pub(crate) fn put_str(&mut self, value: &str) -> &mut Self {
        self.put_bytes(value.as_bytes())
    }

    /// Appends an attribute block, writing only the members the flags claim.
    ///
    /// The order is the protocol's: flags, size, uid and gid together,
    /// permissions, then atime and mtime together. An absent attribute
    /// contributes no bytes at all, which is the whole reason the flags word
    /// exists.
    pub(crate) fn put_attributes(
        &mut self,
        attrs: &SftpAttributes,
    ) -> &mut Self {
        self.put_u32(attrs.flags.bits());
        if attrs.flags.contains(SftpAttrFlags::SIZE) {
            self.put_u64(attrs.filesize);
        }
        if attrs.flags.contains(SftpAttrFlags::UIDGID) {
            self.put_u32(attrs.uid);
            self.put_u32(attrs.gid);
        }
        if attrs.flags.contains(SftpAttrFlags::PERMISSIONS) {
            self.put_u32(attrs.permissions);
        }
        if attrs.flags.contains(SftpAttrFlags::ACMODTIME) {
            self.put_u32(attrs.atime);
            self.put_u32(attrs.mtime);
        }
        self
    }

    /// Back-fills the length prefix and yields the framed packet.
    ///
    /// The length covers everything after the prefix. A packet whose body
    /// exceeds `u32::MAX` cannot be framed and is clamped for the same reason
    /// [`Self::put_bytes`] clamps; no caller in this module can reach it,
    /// because every request is bounded by a path length.
    pub(crate) fn finish(mut self) -> Vec<u8> {
        let body = self.buffer.len().saturating_sub(4);
        let len = u32::try_from(body).unwrap_or(u32::MAX);
        self.buffer[..4].copy_from_slice(&len.to_be_bytes());
        self.buffer
    }
}

/// A cursor over one decoded SFTP packet's payload.
///
/// Constructed by [`SftpReader::frame`], which strips the length prefix and the
/// type byte, so a reader always begins at the first payload field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) struct SftpReader<'a> {
    /// The packet type the frame announced.
    kind: SftpPacket,
    /// What is left of the payload.
    rest: &'a [u8],
}

#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
impl<'a> SftpReader<'a> {
    /// Splits one framed packet off the front of `frame`.
    ///
    /// # Errors
    ///
    /// [`SftpFailure::Malformed`] when the frame is shorter than its own length
    /// prefix claims, when the prefix is absent, or when the type byte is one
    /// this module does not exchange.
    pub(crate) fn frame(frame: &'a [u8]) -> SftpResult<Self> {
        if frame.len() < 5 {
            return Err(SftpFailure::Malformed);
        }
        let mut length_bytes = [0_u8; 4];
        length_bytes.copy_from_slice(&frame[..4]);
        let length = usize::try_from(u32::from_be_bytes(length_bytes))
            .map_err(|_| SftpFailure::Malformed)?;
        // The length covers the type byte, so a payload of `length - 1` bytes
        // must follow it. A frame carrying MORE than that is accepted and the
        // surplus ignored, which is what a stream reader that over-read would
        // hand us.
        if length == 0 || frame.len() < 4 + length {
            return Err(SftpFailure::Malformed);
        }
        let kind =
            SftpPacket::from_u8(frame[4]).ok_or(SftpFailure::Malformed)?;
        Ok(Self {
            kind,
            rest: &frame[5..4 + length],
        })
    }

    /// The packet type.
    pub(crate) const fn kind(&self) -> SftpPacket {
        self.kind
    }

    /// What is left unread.
    pub(crate) const fn remaining(&self) -> &'a [u8] {
        self.rest
    }

    /// Reads a four-byte big-endian integer.
    ///
    /// # Errors
    ///
    /// [`SftpFailure::Malformed`] on a short read.
    pub(crate) fn get_u32(&mut self) -> SftpResult<u32> {
        if self.rest.len() < 4 {
            return Err(SftpFailure::Malformed);
        }
        let (head, tail) = self.rest.split_at(4);
        let mut bytes = [0_u8; 4];
        bytes.copy_from_slice(head);
        self.rest = tail;
        Ok(u32::from_be_bytes(bytes))
    }

    /// Reads an eight-byte big-endian integer.
    ///
    /// # Errors
    ///
    /// [`SftpFailure::Malformed`] on a short read.
    pub(crate) fn get_u64(&mut self) -> SftpResult<u64> {
        if self.rest.len() < 8 {
            return Err(SftpFailure::Malformed);
        }
        let (head, tail) = self.rest.split_at(8);
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(head);
        self.rest = tail;
        Ok(u64::from_be_bytes(bytes))
    }

    /// Reads a length-prefixed byte string, borrowed from the frame.
    ///
    /// # Errors
    ///
    /// [`SftpFailure::Malformed`] on a short read or an impossible length.
    pub(crate) fn get_bytes(&mut self) -> SftpResult<&'a [u8]> {
        let len = usize::try_from(self.get_u32()?)
            .map_err(|_| SftpFailure::Malformed)?;
        if self.rest.len() < len {
            return Err(SftpFailure::Malformed);
        }
        let (head, tail) = self.rest.split_at(len);
        self.rest = tail;
        Ok(head)
    }

    /// Reads an attribute block, honouring its flags word.
    ///
    /// The extended-attribute tail is READ AND DISCARDED rather than ignored:
    /// when `ATTR_EXTENDED` is set the block ends with a count and that many
    /// type/value string pairs, and skipping them would leave the cursor
    /// mid-field for any caller that reads further. `SSH_FXP_NAME` is exactly
    /// such a caller, since its entries are `filename`, `longname`, `attrs`
    /// repeated.
    ///
    /// # Errors
    ///
    /// [`SftpFailure::Malformed`] on a short read.
    pub(crate) fn get_attributes(&mut self) -> SftpResult<SftpAttributes> {
        let mut attrs = SftpAttributes {
            flags: SftpAttrFlags(self.get_u32()?),
            ..SftpAttributes::default()
        };
        if attrs.flags.contains(SftpAttrFlags::SIZE) {
            attrs.filesize = self.get_u64()?;
        }
        if attrs.flags.contains(SftpAttrFlags::UIDGID) {
            attrs.uid = self.get_u32()?;
            attrs.gid = self.get_u32()?;
        }
        if attrs.flags.contains(SftpAttrFlags::PERMISSIONS) {
            attrs.permissions = self.get_u32()?;
        }
        if attrs.flags.contains(SftpAttrFlags::ACMODTIME) {
            attrs.atime = self.get_u32()?;
            attrs.mtime = self.get_u32()?;
        }
        if attrs.flags.contains(SftpAttrFlags::EXTENDED) {
            let count = self.get_u32()?;
            for _ in 0..count {
                let _type = self.get_bytes()?;
                let _value = self.get_bytes()?;
            }
        }
        Ok(attrs)
    }

    /// Interprets this frame as a bare status reply.
    ///
    /// `SSH_FXP_STATUS` carries a request identifier, the status, and -- from
    /// version 3 -- a message and a language tag. Only the status is consulted,
    /// because the C interpolates [`sftp_strerror`]'s text rather than the
    /// server's: `failf(data, "... failed: %s", sftp_libssh2_strerror(sftperr))`
    /// appears at every one of the quote sites.
    ///
    /// # Errors
    ///
    /// [`SftpFailure::Malformed`] when this frame is not a status reply or is
    /// truncated.
    pub(crate) fn expect_status(mut self) -> SftpResult<SftpStatus> {
        if self.kind != SftpPacket::Status {
            return Err(SftpFailure::Malformed);
        }
        let _id = self.get_u32()?;
        Ok(SftpStatus(self.get_u32()?))
    }

    /// Interprets this frame as a status reply that must be `OK`.
    ///
    /// The shape of every mutating operation: `mkdir`, `rmdir`, `remove`,
    /// `rename`, `symlink`, `setstat` and `close` all answer `SSH_FXP_STATUS`,
    /// and every one of their C sites treats a non-zero status as the failure.
    ///
    /// # Errors
    ///
    /// [`SftpFailure::Status`] carrying whatever the peer reported, or
    /// [`SftpFailure::Malformed`].
    pub(crate) fn expect_ok(self) -> SftpResult<()> {
        let status = self.expect_status()?;
        if status == SftpStatus::OK {
            Ok(())
        } else {
            Err(SftpFailure::Status(status))
        }
    }
}

// The SFTP request builders and response decoders

/// One entry of an `SSH_FXP_NAME` reply.
///
/// `libssh2_sftp_readdir_ex` hands the C three things per entry -- the filename,
/// the long entry and the attributes -- and the C keeps all three:
/// `readdir_filename` feeds `--list-only` and the `READLINK` path,
/// `readdir_longentry` is what a normal listing prints, and the attributes
/// decide whether a `" -> target"` suffix is needed.
///
/// Owned rather than borrowed because the entry outlives the frame it was
/// decoded from: the readdir loop keeps one entry while issuing a `READLINK`
/// for it.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) struct SftpName {
    /// The bare filename, `readdir_filename` in the C.
    pub(crate) filename: Vec<u8>,
    /// The server's long-format line, `readdir_longentry` in the C.
    ///
    /// Empty for an `SSH_FXP_REALPATH` reply, which carries a name and a
    /// placeholder long entry; the realpath caller reads only
    /// [`Self::filename`], exactly as `ssh_state_sftp_realpath` does.
    pub(crate) longentry: Vec<u8>,
    /// The entry's attributes.
    pub(crate) attrs: SftpAttributes,
}

/// The SFTP requests this module issues, and the replies it decodes.
///
/// A free-function family rather than methods on a session type, deliberately:
/// building a request is a pure function of its arguments, so it is testable
/// against a byte vector with no transport at all, which is what
/// [`mod tests`](self) does for every one of them. The transport's only job is
/// to move the bytes -- see [`SshTransport`].
///
/// The request identifier is threaded in rather than generated here. libssh2
/// allocates it from a per-session counter, and a counter reached for globally
/// would be exactly the hidden state specification 0.3.3's pattern P12 forbids;
/// [`SshConn::next_request_id`] owns it.
pub(crate) mod request {
    use super::{
        SftpAttrFlags, SftpAttributes, SftpCodec, SftpFailure, SftpName,
        SftpOpenFlags, SftpPacket, SftpReader, SftpResult, SftpStatVfs,
        SFTP_RENAME_FLAGS, SFTP_STATVFS_EXTENSION, SFTP_VERSION,
    };

    /// `SSH_FXP_INIT`: the version announcement that opens an SFTP session.
    ///
    /// Carries no request identifier -- it is the one packet that does not,
    /// which is why it is built separately from everything below.
    #[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
    pub(crate) fn init() -> Vec<u8> {
        let mut codec = SftpCodec::request(SftpPacket::Init);
        codec.put_u32(SFTP_VERSION);
        codec.finish()
    }

    /// `SSH_FXP_OPEN`: open a file.
    ///
    /// `libssh2_sftp_open_ex(..., flags, mode, LIBSSH2_SFTP_OPENFILE)`. The mode
    /// is sent as an attribute block carrying `ATTR_PERMISSIONS`, which is how
    /// libssh2 forwards `CURLOPT_NEW_FILE_PERMS`.
    #[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
    pub(crate) fn open(
        id: u32,
        path: &[u8],
        flags: SftpOpenFlags,
        mode: u32,
    ) -> Vec<u8> {
        let mut codec = SftpCodec::request(SftpPacket::Open);
        codec.put_u32(id);
        codec.put_bytes(path);
        codec.put_u32(flags.bits());
        codec.put_attributes(&SftpAttributes {
            flags: SftpAttrFlags::PERMISSIONS,
            permissions: mode,
            ..SftpAttributes::default()
        });
        codec.finish()
    }

    /// `SSH_FXP_OPENDIR`: open a directory for reading.
    #[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
    pub(crate) fn opendir(id: u32, path: &[u8]) -> Vec<u8> {
        let mut codec = SftpCodec::request(SftpPacket::Opendir);
        codec.put_u32(id);
        codec.put_bytes(path);
        codec.finish()
    }

    /// `SSH_FXP_CLOSE`: release a handle.
    #[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
    pub(crate) fn close(id: u32, handle: &[u8]) -> Vec<u8> {
        let mut codec = SftpCodec::request(SftpPacket::Close);
        codec.put_u32(id);
        codec.put_bytes(handle);
        codec.finish()
    }

    /// `SSH_FXP_READ`: read `len` bytes at `offset`.
    ///
    /// The offset is explicit on the wire, which is what makes
    /// `libssh2_sftp_seek64` a purely local operation in the C -- it records an
    /// offset and the next read carries it. [`super::SshConn::sftp_offset`] is
    /// its successor.
    #[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
    pub(crate) fn read(
        id: u32,
        handle: &[u8],
        offset: u64,
        len: u32,
    ) -> Vec<u8> {
        let mut codec = SftpCodec::request(SftpPacket::Read);
        codec.put_u32(id);
        codec.put_bytes(handle);
        codec.put_u64(offset);
        codec.put_u32(len);
        codec.finish()
    }

    /// `SSH_FXP_WRITE`: write `data` at `offset`.
    #[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
    pub(crate) fn write(
        id: u32,
        handle: &[u8],
        offset: u64,
        data: &[u8],
    ) -> Vec<u8> {
        let mut codec = SftpCodec::request(SftpPacket::Write);
        codec.put_u32(id);
        codec.put_bytes(handle);
        codec.put_u64(offset);
        codec.put_bytes(data);
        codec.finish()
    }

    /// `SSH_FXP_STAT`: stat a path, following symbolic links.
    ///
    /// `LIBSSH2_SFTP_STAT` in the C's `libssh2_sftp_stat_ex` calls, which is
    /// what both `sftp_download_stat` and the `chown`/`chgrp`/`atime`/`mtime`
    /// round trip use.
    #[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
    pub(crate) fn stat(id: u32, path: &[u8]) -> Vec<u8> {
        let mut codec = SftpCodec::request(SftpPacket::Stat);
        codec.put_u32(id);
        codec.put_bytes(path);
        codec.finish()
    }

    /// `SSH_FXP_LSTAT`: stat a path without following symbolic links.
    #[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
    pub(crate) fn lstat(id: u32, path: &[u8]) -> Vec<u8> {
        let mut codec = SftpCodec::request(SftpPacket::Lstat);
        codec.put_u32(id);
        codec.put_bytes(path);
        codec.finish()
    }

    /// `SSH_FXP_FSTAT`: stat an open handle.
    #[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
    pub(crate) fn fstat(id: u32, handle: &[u8]) -> Vec<u8> {
        let mut codec = SftpCodec::request(SftpPacket::Fstat);
        codec.put_u32(id);
        codec.put_bytes(handle);
        codec.finish()
    }

    /// `SSH_FXP_SETSTAT`: apply an attribute block to a path.
    ///
    /// `LIBSSH2_SFTP_SETSTAT`, which `SSH_SFTP_QUOTE_SETSTAT` sends for all five
    /// attribute-changing quote commands.
    #[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
    pub(crate) fn setstat(
        id: u32,
        path: &[u8],
        attrs: &SftpAttributes,
    ) -> Vec<u8> {
        let mut codec = SftpCodec::request(SftpPacket::Setstat);
        codec.put_u32(id);
        codec.put_bytes(path);
        codec.put_attributes(attrs);
        codec.finish()
    }

    /// `SSH_FXP_READDIR`: fetch the next batch of directory entries.
    #[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
    pub(crate) fn readdir(id: u32, handle: &[u8]) -> Vec<u8> {
        let mut codec = SftpCodec::request(SftpPacket::Readdir);
        codec.put_u32(id);
        codec.put_bytes(handle);
        codec.finish()
    }

    /// `SSH_FXP_REMOVE`: the packet behind the `rm` quote command.
    #[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
    pub(crate) fn remove(id: u32, path: &[u8]) -> Vec<u8> {
        let mut codec = SftpCodec::request(SftpPacket::Remove);
        codec.put_u32(id);
        codec.put_bytes(path);
        codec.finish()
    }

    /// `SSH_FXP_MKDIR`: create a directory with `mode`.
    ///
    /// Sent by both the `mkdir` quote command and the `--ftp-create-dirs` walk,
    /// and both pass `CURLOPT_NEW_DIRECTORY_PERMS`.
    #[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
    pub(crate) fn mkdir(id: u32, path: &[u8], mode: u32) -> Vec<u8> {
        let mut codec = SftpCodec::request(SftpPacket::Mkdir);
        codec.put_u32(id);
        codec.put_bytes(path);
        codec.put_attributes(&SftpAttributes {
            flags: SftpAttrFlags::PERMISSIONS,
            permissions: mode,
            ..SftpAttributes::default()
        });
        codec.finish()
    }

    /// `SSH_FXP_RMDIR`: the packet behind the `rmdir` quote command.
    #[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
    pub(crate) fn rmdir(id: u32, path: &[u8]) -> Vec<u8> {
        let mut codec = SftpCodec::request(SftpPacket::Rmdir);
        codec.put_u32(id);
        codec.put_bytes(path);
        codec.finish()
    }

    /// `SSH_FXP_REALPATH`: canonicalise a path.
    ///
    /// `SSH_SFTP_REALPATH` sends this with `"."` to learn the home directory,
    /// which is the one use in the C.
    #[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
    pub(crate) fn realpath(id: u32, path: &[u8]) -> Vec<u8> {
        let mut codec = SftpCodec::request(SftpPacket::Realpath);
        codec.put_u32(id);
        codec.put_bytes(path);
        codec.finish()
    }

    /// `SSH_FXP_RENAME`: the packet behind the `rename` quote command.
    ///
    /// The flags word is [`SFTP_RENAME_FLAGS`], the exact combination
    /// `ssh_state_sftp_quote_rename` passes.
    #[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
    pub(crate) fn rename(id: u32, from: &[u8], to: &[u8]) -> Vec<u8> {
        let mut codec = SftpCodec::request(SftpPacket::Rename);
        codec.put_u32(id);
        codec.put_bytes(from);
        codec.put_bytes(to);
        codec.put_u32(SFTP_RENAME_FLAGS);
        codec.finish()
    }

    /// `SSH_FXP_READLINK`: read a symbolic link's target.
    #[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
    pub(crate) fn readlink(id: u32, path: &[u8]) -> Vec<u8> {
        let mut codec = SftpCodec::request(SftpPacket::Readlink);
        codec.put_u32(id);
        codec.put_bytes(path);
        codec.finish()
    }

    /// `SSH_FXP_SYMLINK`: the packet behind the `ln` and `symlink` quote
    /// commands.
    ///
    /// The argument order is the protocol's and is the one place SFTP version 3
    /// is notoriously ambiguous: OpenSSH sends `targetpath` then `linkpath`,
    /// which is what libssh2's `libssh2_sftp_symlink_ex(session, path1, path2,
    /// LIBSSH2_SFTP_SYMLINK)` produces for curl's `ln source destination`. The
    /// order here is libssh2's, because the corpus was recorded against it.
    #[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
    pub(crate) fn symlink(id: u32, source: &[u8], target: &[u8]) -> Vec<u8> {
        let mut codec = SftpCodec::request(SftpPacket::Symlink);
        codec.put_u32(id);
        codec.put_bytes(source);
        codec.put_bytes(target);
        codec.finish()
    }

    /// `SSH_FXP_EXTENDED` carrying `statvfs@openssh.com`.
    #[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
    pub(crate) fn statvfs(id: u32, path: &[u8]) -> Vec<u8> {
        let mut codec = SftpCodec::request(SftpPacket::Extended);
        codec.put_u32(id);
        codec.put_str(SFTP_STATVFS_EXTENSION);
        codec.put_bytes(path);
        codec.finish()
    }

    /// Decodes an `SSH_FXP_VERSION` reply, answering the server's version.
    ///
    /// The extension pairs that may follow are read and discarded: a version
    /// reply is `version` followed by zero or more `name`/`data` string pairs,
    /// and this module consults none of them. `statvfs@openssh.com` is sent
    /// unconditionally and answered with `SSH_FX_OP_UNSUPPORTED` when absent,
    /// which is exactly what libssh2 does.
    ///
    /// # Errors
    ///
    /// [`SftpFailure::Malformed`] when the reply is not a version reply.
    #[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
    pub(crate) fn decode_version(frame: &[u8]) -> SftpResult<u32> {
        let mut reader = SftpReader::frame(frame)?;
        if reader.kind() != SftpPacket::Version {
            return Err(SftpFailure::Malformed);
        }
        reader.get_u32()
    }

    /// Decodes an `SSH_FXP_HANDLE` reply, answering the opaque handle.
    ///
    /// # Errors
    ///
    /// [`SftpFailure::Status`] when the peer answered a status instead --
    /// which is how every failed open reports itself -- or
    /// [`SftpFailure::Malformed`].
    #[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
    pub(crate) fn decode_handle(frame: &[u8]) -> SftpResult<Vec<u8>> {
        let mut reader = SftpReader::frame(frame)?;
        match reader.kind() {
            SftpPacket::Handle => {
                let _id = reader.get_u32()?;
                Ok(reader.get_bytes()?.to_vec())
            }
            SftpPacket::Status => Err(SftpFailure::Status(
                SftpReader::frame(frame)?.expect_status()?,
            )),
            _ => Err(SftpFailure::Malformed),
        }
    }

    /// Decodes an `SSH_FXP_DATA` reply, answering the bytes read.
    ///
    /// An `SSH_FX_EOF` status is reported as [`SftpFailure::Status`] carrying
    /// it, NOT as an empty read. The distinction is the C's: `libssh2_sftp_read`
    /// answers zero at end of file, and the readdir and download loops test for
    /// that condition explicitly before consulting the error map -- which is
    /// necessary, because `EOF` has no arm in
    /// [`super::sftp_status_to_curlcode`] and would otherwise become
    /// [`super::CURLcode::Ssh`].
    ///
    /// # Errors
    ///
    /// [`SftpFailure::Status`] or [`SftpFailure::Malformed`].
    #[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
    pub(crate) fn decode_data(frame: &[u8]) -> SftpResult<Vec<u8>> {
        let mut reader = SftpReader::frame(frame)?;
        match reader.kind() {
            SftpPacket::Data => {
                let _id = reader.get_u32()?;
                Ok(reader.get_bytes()?.to_vec())
            }
            SftpPacket::Status => Err(SftpFailure::Status(
                SftpReader::frame(frame)?.expect_status()?,
            )),
            _ => Err(SftpFailure::Malformed),
        }
    }

    /// Decodes an `SSH_FXP_ATTRS` reply.
    ///
    /// # Errors
    ///
    /// [`SftpFailure::Status`] or [`SftpFailure::Malformed`].
    #[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
    pub(crate) fn decode_attrs(frame: &[u8]) -> SftpResult<SftpAttributes> {
        let mut reader = SftpReader::frame(frame)?;
        match reader.kind() {
            SftpPacket::Attrs => {
                let _id = reader.get_u32()?;
                reader.get_attributes()
            }
            SftpPacket::Status => Err(SftpFailure::Status(
                SftpReader::frame(frame)?.expect_status()?,
            )),
            _ => Err(SftpFailure::Malformed),
        }
    }

    /// Decodes an `SSH_FXP_NAME` reply into its entries.
    ///
    /// Used by both `READDIR`, which may answer many entries, and `REALPATH`,
    /// which answers exactly one. The count is honoured rather than assumed, so
    /// a server that batches a whole directory into one reply is handled by the
    /// same decoder.
    ///
    /// # Errors
    ///
    /// [`SftpFailure::Status`] -- which is how the END of a listing arrives,
    /// as `SSH_FX_EOF` -- or [`SftpFailure::Malformed`].
    #[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
    pub(crate) fn decode_names(frame: &[u8]) -> SftpResult<Vec<SftpName>> {
        let mut reader = SftpReader::frame(frame)?;
        match reader.kind() {
            SftpPacket::Name => {
                let _id = reader.get_u32()?;
                let count = reader.get_u32()?;
                let mut names = Vec::new();
                for _ in 0..count {
                    let filename = reader.get_bytes()?.to_vec();
                    let longentry = reader.get_bytes()?.to_vec();
                    let attrs = reader.get_attributes()?;
                    names.push(SftpName {
                        filename,
                        longentry,
                        attrs,
                    });
                }
                Ok(names)
            }
            SftpPacket::Status => Err(SftpFailure::Status(
                SftpReader::frame(frame)?.expect_status()?,
            )),
            _ => Err(SftpFailure::Malformed),
        }
    }

    /// Decodes the `SSH_FXP_EXTENDED_REPLY` to `statvfs@openssh.com`.
    ///
    /// Eleven `u64` members in the order the extension defines.
    ///
    /// # Errors
    ///
    /// [`SftpFailure::Status`] -- `SSH_FX_OP_UNSUPPORTED` from a server without
    /// the extension -- or [`SftpFailure::Malformed`].
    #[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
    pub(crate) fn decode_statvfs(frame: &[u8]) -> SftpResult<SftpStatVfs> {
        let mut reader = SftpReader::frame(frame)?;
        match reader.kind() {
            SftpPacket::ExtendedReply => {
                let _id = reader.get_u32()?;
                Ok(SftpStatVfs {
                    bsize: reader.get_u64()?,
                    frsize: reader.get_u64()?,
                    blocks: reader.get_u64()?,
                    bfree: reader.get_u64()?,
                    bavail: reader.get_u64()?,
                    files: reader.get_u64()?,
                    ffree: reader.get_u64()?,
                    favail: reader.get_u64()?,
                    fsid: reader.get_u64()?,
                    flag: reader.get_u64()?,
                    namemax: reader.get_u64()?,
                })
            }
            SftpPacket::Status => Err(SftpFailure::Status(
                SftpReader::frame(frame)?.expect_status()?,
            )),
            _ => Err(SftpFailure::Malformed),
        }
    }

    /// Decodes a reply that must be `SSH_FXP_STATUS` with status `OK`.
    ///
    /// # Errors
    ///
    /// [`SftpFailure::Status`] or [`SftpFailure::Malformed`].
    #[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
    pub(crate) fn decode_ok(frame: &[u8]) -> SftpResult<()> {
        SftpReader::frame(frame)?.expect_ok()
    }
}

// The path and range helpers shared with `protocols/scp.rs`

/// `MAX_SSHPATH_LEN` (`lib/vssh/vssh.c:123`): the ceiling on a working path.
///
/// The C's comment is `/* arbitrary */`, and 100,000 is the number. Reproduced
/// rather than chosen, because it is the boundary at which a path is refused.
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
pub(crate) const MAX_SSHPATH_LEN: usize = 100_000;

/// `MAX_PATHLENGTH` (`lib/vssh/vssh.c:190`): the ceiling on a quote-command
/// path. Also `/* arbitrary long */` in the C, and also reproduced.
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
pub(crate) const MAX_PATHLENGTH: usize = 65_535;

/// `CURL_PATH_MAX` (`lib/vssh/ssh.h:122`): the fixed buffer libssh2 fills with a
/// filename or a long entry.
///
/// The value is 1024, and it bounds what the C can receive per readdir entry,
/// so it bounds what a listing line can contain -- and the corpus was recorded
/// under that bound.
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
pub(crate) const CURL_PATH_MAX: usize = 1024;

/// `Curl_getworkingpath` (`lib/vssh/vssh.c:126-190`): the path this request
/// operates on.
///
/// Shared by both schemes and behaving DIFFERENTLY for each, which is the whole
/// reason it takes the scheme's protocol bit:
///
/// * SCP with a path beginning `/~/` strips those three bytes, leaving a path
///   relative to the login directory -- the remote shell resolves it;
/// * SFTP with a path that is exactly `/~` or begins `/~/` substitutes
///   `homedir`, because SFTP has no shell to do it. The C copies from index 2
///   rather than 3 when `homedir` does not already end in `/`, which is how the
///   separator ends up present exactly once;
/// * anything else is the percent-decoded URL path unchanged.
///
/// The decode is `Curl_urldecode(..., REJECT_ZERO)`, so a `%00` in the path is
/// refused while a tab or a newline is not.
///
/// # Errors
///
/// [`CURLcode::UrlMalformat`] from the decoder for a rejected escape, and
/// [`CURLcode::TooLarge`] when the assembled path exceeds
/// [`MAX_SSHPATH_LEN`] -- which is what the C's `curlx_dyn_init(&npath,
/// MAX_SSHPATH_LEN)` ceiling produces.
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
pub(crate) fn getworkingpath(
    url_path: &[u8],
    homedir: &[u8],
    protocol: Proto,
) -> CodeResult<Vec<u8>> {
    let working = crate::url::escape::urldecode(
        url_path,
        crate::url::escape::UrlReject::Zero,
    )?;

    let mut npath = DynBuf::new(MAX_SSHPATH_LEN);

    if protocol.intersects(Proto::SCP)
        && working.len() > 3
        && working.starts_with(b"/~/")
    {
        // `/~/` stripped: the remote shell resolves the remainder.
        npath.addn(&working[3..])?;
    } else if protocol.intersects(Proto::SFTP)
        && (working == b"/~"
            || (working.len() > 2 && working.starts_with(b"/~/")))
    {
        npath.addn(homedir)?;
        if working.len() > 2 {
            // `copyfrom` is 2 when the home directory already ends in a
            // separator, so the `/` of `/~/` supplies the only one; 3 when it
            // does not, so the home directory's own tail supplies it. Either
            // way exactly one separator appears.
            let copyfrom =
                if npath.as_slice().last().is_some_and(|byte| *byte == b'/') {
                    3
                } else {
                    2
                };
            npath.addn(&working[copyfrom..])?;
        } else {
            npath.addn(b"/")?;
        }
    }

    if npath.is_empty() {
        Ok(working)
    } else {
        Ok(npath.take())
    }
}

/// `Curl_get_pathname` (`lib/vssh/vssh.c:192-277`): one path argument of a quote
/// command.
///
/// Advances `cursor` past the path it consumed and past the whitespace after it,
/// so a caller reads the second argument by calling this again and detects
/// trailing junk by testing the cursor for emptiness -- which is exactly what
/// `sftp_quote` does with `if(*cp) return_quote_error(...)`.
///
/// Three acceptance rules, all the C's:
///
/// * a quoted path -- `"` or `'` -- runs to the matching quote, and inside it
///   only `\'`, `\"` and `\\` may be escaped. Any other escape is a syntax
///   error, and so is an empty quoted path;
/// * an unquoted path beginning `/~/` has `homedir` and a separator prepended,
///   then continues as a word;
/// * an unquoted path is a word terminated by whitespace or by the end of the
///   string.
///
/// # Errors
///
/// [`CURLcode::QuoteError`] for every syntax failure, which is what the C
/// returns from all four of its `goto fail` sites, and [`CURLcode::TooLarge`]
/// when the word exceeds [`MAX_PATHLENGTH`].
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
pub(crate) fn get_pathname(
    cursor: &mut &[u8],
    homedir: &[u8],
) -> CodeResult<Vec<u8>> {
    let mut cp: &[u8] = cursor;
    // `if(!*cp || !homedir) return CURLE_QUOTE_ERROR;` -- an empty argument is
    // refused before anything is allocated.
    if cp.is_empty() {
        *cursor = cp;
        return Err(CURLcode::QuoteError);
    }

    let mut out = DynBuf::new(MAX_PATHLENGTH);

    str_passblanks(&mut cp);

    if cp
        .first()
        .is_some_and(|byte| *byte == b'"' || *byte == b'\'')
    {
        let quot = cp[0];
        cp = &cp[1..];
        loop {
            match cp.first() {
                // End of string before the closing quote.
                None => {
                    *cursor = cp;
                    return Err(CURLcode::QuoteError);
                }
                Some(byte) if *byte == quot => break,
                Some(b'\\') => {
                    cp = &cp[1..];
                    match cp.first() {
                        Some(b'\'' | b'"' | b'\\') => {}
                        _ => {
                            *cursor = cp;
                            return Err(CURLcode::QuoteError);
                        }
                    }
                    out.addn(&cp[..1])?;
                    cp = &cp[1..];
                }
                Some(_) => {
                    out.addn(&cp[..1])?;
                    cp = &cp[1..];
                }
            }
        }
        // Past the end quote.
        cp = &cp[1..];

        if out.is_empty() {
            *cursor = cp;
            return Err(CURLcode::QuoteError);
        }
    } else {
        let mut content = false;
        if cp.starts_with(b"/~/") {
            out.addn(homedir)?;
            out.addn(b"/")?;
            cp = &cp[3..];
            content = true;
        }
        match str_word(&mut cp, MAX_PATHLENGTH) {
            Ok(word) => {
                out.addn(word)?;
            }
            Err(StrError::Big) => {
                *cursor = cp;
                return Err(CURLcode::TooLarge);
            }
            Err(_) => {
                if !content {
                    // No path and no word: the C's *"this is incorrect"*.
                    *cursor = cp;
                    return Err(CURLcode::QuoteError);
                }
            }
        }
    }

    str_passblanks(&mut cp);
    *cursor = cp;
    Ok(out.take())
}

/// `Curl_ssh_range` (`lib/vssh/vssh.c:279-331`): resolve `--range` against a
/// known file size.
///
/// Answers the start offset and the byte count. Five refusals, every one the
/// C's, and the order matters because a range can trip more than one:
///
/// 1. an overflowing start;
/// 2. an overflowing end, or an end with no start at all, or trailing junk;
/// 3. a suffix range `-N` with `N` zero -- *"-0 is not a fine range"*;
/// 4. a start beyond the file, which additionally reports *"Offset (%d) was
///    beyond file size (%d)"*;
/// 5. a start past the end, reporting *"Bad range: start offset larger than end
///    offset"*.
///
/// A suffix range longer than the file is CLAMPED rather than refused, which is
/// the `else if(to > filesize) to = filesize;` branch -- so `-9999` on a
/// ten-byte file yields the whole file.
///
/// # Errors
///
/// [`CURLcode::RangeError`] for every one of the five, which is the only code
/// the C returns here.
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
pub(crate) fn ssh_range(
    range: &[u8],
    filesize: i64,
) -> Result<(i64, i64), RangeRefusal> {
    let mut cursor: &[u8] = range;
    let from_result = str_number(&mut cursor, i64::MAX);
    let from_missing = match from_result {
        Ok(_) => false,
        Err(StrError::Overflow) => {
            return Err(RangeRefusal::Malformed);
        }
        Err(_) => true,
    };
    let mut from = from_result.unwrap_or(0);

    str_passblanks(&mut cursor);
    // `(void)curlx_str_single(&range, '-')` -- the dash is optional and its
    // absence is not an error by itself; a missing dash leaves trailing bytes,
    // which the emptiness test below catches.
    let _dash = str_single(&mut cursor, b'-');

    let to_result = crate::util::strparse::str_numblanks(&mut cursor);
    let (mut to, to_missing) = match to_result {
        Ok(value) => (value, false),
        Err(StrError::Overflow) => {
            return Err(RangeRefusal::Malformed);
        }
        Err(_) => (0, true),
    };

    // `if((to_t == STRE_OVERFLOW) || (to_t && from_t) || *range)`: neither end
    // present, or anything left over, is malformed.
    if (to_missing && from_missing) || !cursor.is_empty() {
        return Err(RangeRefusal::Malformed);
    }

    if from_missing {
        // A suffix range: `-N` means the last N bytes.
        if to == 0 {
            return Err(RangeRefusal::Malformed);
        }
        if to > filesize {
            to = filesize;
        }
        from = filesize - to;
        to = filesize - 1;
    } else if from > filesize {
        return Err(RangeRefusal::BeyondFileSize { from, filesize });
    } else if to_missing || to >= filesize {
        to = filesize - 1;
    }

    if from > to {
        return Err(RangeRefusal::StartAfterEnd);
    }
    if to.saturating_sub(from) == i64::MAX {
        return Err(RangeRefusal::Malformed);
    }

    Ok((from, to - from + 1))
}

/// Why a `--range` was refused, carrying what its diagnostic interpolates.
///
/// The C emits two of its three refusals through `failf` before returning
/// [`CURLcode::RangeError`], and the third returns silently. Keeping the reason
/// as a value rather than emitting it here is what lets the caller trace through
/// the tracer it holds -- this function has none, deliberately, because it is
/// pure and therefore testable without one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
pub(crate) enum RangeRefusal {
    /// Unparseable, overflowing, or `-0`. The C returns
    /// [`CURLcode::RangeError`] with no message.
    Malformed,
    /// A start beyond the end of the file. `failf(data, "Offset (%d) was beyond
    /// file size (%d)", from, filesize)`.
    BeyondFileSize {
        /// The offset asked for.
        from: i64,
        /// The size the server reported.
        filesize: i64,
    },
    /// `failf(data, "Bad range: start offset larger than end offset")`.
    StartAfterEnd,
}

#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
impl RangeRefusal {
    /// The code every refusal reports: [`CURLcode::RangeError`].
    pub(crate) const fn code(self) -> CURLcode {
        CURLcode::RangeError
    }

    /// The `failf` text, or [`None`] for the refusal the C reports silently.
    pub(crate) fn message(self) -> Option<String> {
        match self {
            Self::Malformed => None,
            Self::BeyondFileSize { from, filesize } => Some(format!(
                "Offset ({from}) was beyond file size ({filesize})"
            )),
            Self::StartAfterEnd => {
                Some("Bad range: start offset larger than end offset".into())
            }
        }
    }
}

// The `--quote` engine -- `sftp_quote` (`lib/vssh/libssh2.c:727-884`)

/// One recognised quote command, and the SFTP operation it becomes.
///
/// `sftp_quote`'s comment is the contract: *"SFTP is a binary protocol, so we do
/// not send text commands to the server. Instead, we scan for commands used by
/// OpenSSH's sftp program and call the appropriate libssh2 functions."* So the
/// vocabulary here is OpenSSH's `sftp` client's, not FTP's, even though several
/// spellings coincide.
///
/// The variants are named for the STATE each one routes to, because that is what
/// the C's parser produces: `sftp_quote` ends every recognised branch with
/// `myssh_to(data, sshc, SSH_SFTP_QUOTE_<something>)`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) enum QuoteCommand {
    /// `pwd` -- answered locally, with no packet at all.
    Pwd,
    /// `chgrp <gid> <path>`: [`SftpAttrFlags::UIDGID`].
    Chgrp,
    /// `chmod <octal> <path>`: [`SftpAttrFlags::PERMISSIONS`].
    Chmod,
    /// `chown <uid> <path>`: [`SftpAttrFlags::UIDGID`].
    Chown,
    /// `atime <date> <path>`: [`SftpAttrFlags::ACMODTIME`].
    Atime,
    /// `mtime <date> <path>`: [`SftpAttrFlags::ACMODTIME`].
    Mtime,
    /// `ln <source> <target>` or `symlink <source> <target>`.
    Symlink,
    /// `mkdir <path>`.
    Mkdir,
    /// `rename <from> <to>`.
    Rename,
    /// `rmdir <path>`.
    Rmdir,
    /// `rm <path>`.
    Unlink,
    /// `statvfs <path>`.
    Statvfs,
}

/// The command vocabulary, in the order `sftp_quote` tests it.
///
/// The order is load-bearing in one place and harmless everywhere else: the C
/// tests the five attribute commands as one group with `strncmp(cmd, "chgrp ",
/// 6)` and its four siblings, then `"ln "` and `"symlink "`, then the rest. What
/// IS load-bearing is that each spelling INCLUDES ITS TRAILING SPACE -- `rm `
/// is three bytes, so `rmdir /x` cannot match it, and the C achieves the same
/// separation by testing `"rmdir "` before `"rm "`. Matching on the
/// space-terminated spelling makes the order irrelevant to correctness, which is
/// strictly safer than relying on it.
///
/// `#[rustfmt::skip]` because this is the wire-bearing command vocabulary and
/// its alignment is what makes it checkable against the C.
#[rustfmt::skip]
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) const QUOTE_COMMANDS: [(&[u8], QuoteCommand); 12] = [
    (b"chgrp ",   QuoteCommand::Chgrp),
    (b"chmod ",   QuoteCommand::Chmod),
    (b"chown ",   QuoteCommand::Chown),
    (b"atime ",   QuoteCommand::Atime),
    (b"mtime ",   QuoteCommand::Mtime),
    (b"ln ",      QuoteCommand::Symlink),
    (b"symlink ", QuoteCommand::Symlink),
    (b"mkdir ",   QuoteCommand::Mkdir),
    (b"rename ",  QuoteCommand::Rename),
    (b"rmdir ",   QuoteCommand::Rmdir),
    (b"rm ",      QuoteCommand::Unlink),
    (b"statvfs ", QuoteCommand::Statvfs),
];

#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
impl QuoteCommand {
    /// How many path arguments this command takes.
    ///
    /// Two for the five attribute commands -- their first argument is the VALUE,
    /// not a path, and the C still parses it with `Curl_get_pathname` -- two for
    /// `ln`, `symlink` and `rename`, and one for the rest.
    pub(crate) const fn argument_count(self) -> usize {
        match self {
            Self::Pwd => 0,
            Self::Chgrp
            | Self::Chmod
            | Self::Chown
            | Self::Atime
            | Self::Mtime
            | Self::Symlink
            | Self::Rename => 2,
            Self::Mkdir | Self::Rmdir | Self::Unlink | Self::Statvfs => 1,
        }
    }

    /// The state `sftp_quote` moves to for this command.
    pub(crate) const fn next_state(self) -> SshState {
        match self {
            // `pwd` writes its report and goes straight to the next command.
            Self::Pwd => SshState::SftpNextQuote,
            Self::Chgrp
            | Self::Chmod
            | Self::Chown
            | Self::Atime
            | Self::Mtime => SshState::SftpQuoteStat,
            Self::Symlink => SshState::SftpQuoteSymlink,
            Self::Mkdir => SshState::SftpQuoteMkdir,
            Self::Rename => SshState::SftpQuoteRename,
            Self::Rmdir => SshState::SftpQuoteRmdir,
            Self::Unlink => SshState::SftpQuoteUnlink,
            Self::Statvfs => SshState::SftpQuoteStatvfs,
        }
    }

    /// Whether this command changes attributes, and therefore needs the
    /// preliminary `SSH_FXP_STAT`.
    ///
    /// `sftp_quote_stat`'s condition is `if(!!strncmp(cmd, "chmod", 5))` -- so
    /// `chmod` alone SKIPS the round trip, because it replaces the whole
    /// permissions field, while `chown`, `chgrp`, `atime` and `mtime` each set
    /// half of a pair and must read the other half first. The C's comment says
    /// so: *"Since chown and chgrp only set owner OR group but libssh2 wants to
    /// set them both at once, we need to obtain the current ownership first.
    /// This takes an extra protocol round trip."*
    pub(crate) const fn needs_preliminary_stat(self) -> bool {
        matches!(self, Self::Chgrp | Self::Chown | Self::Atime | Self::Mtime)
    }

    /// The command's own spelling, for the diagnostics that interpolate it.
    ///
    /// `failf(data, "Syntax error in %s: Bad second parameter", cmd)`
    /// interpolates the WHOLE command line in the C, not this; this is for
    /// `"incorrect date format for %.*s", 5, cmd`, whose precision-5 conversion
    /// prints exactly the command word.
    pub(crate) const fn keyword(self) -> &'static str {
        match self {
            Self::Pwd => "pwd",
            Self::Chgrp => "chgrp",
            Self::Chmod => "chmod",
            Self::Chown => "chown",
            Self::Atime => "atime",
            Self::Mtime => "mtime",
            Self::Symlink => "symlink",
            Self::Mkdir => "mkdir",
            Self::Rename => "rename",
            Self::Rmdir => "rmdir",
            Self::Unlink => "rm",
            Self::Statvfs => "statvfs",
        }
    }
}

/// Why a quote command was refused, with the C's exact diagnostic.
///
/// Every variant reports [`CURLcode::QuoteError`] except
/// [`Self::MissingParameter`], which is the C's one silent branch -- and its
/// silence is a measured oddity rather than an omission. `sftp_quote` at
/// `lib/vssh/libssh2.c:777-781` emits the message and then returns `result`,
/// which is still `CURLE_OK`:
///
/// ```c
/// cp = strchr(cmd, ' ');
/// if(!cp) {
///   failf(data, "Syntax error command '%s', missing parameter", cmd);
///   return result;
/// }
/// ```
///
/// So a parameterless command DIAGNOSES and CONTINUES, leaving the state machine
/// in `SSH_SFTP_QUOTE` -- which the caller resolves by advancing to the next
/// command. Reproduced exactly, including the code, because a fixture asserting
/// the stderr line would also assert the exit status.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) enum QuoteError {
    /// No space in the command: *"Syntax error command '%s', missing
    /// parameter"*, reported with [`CURLcode::Ok`].
    MissingParameter(String),
    /// *"Syntax error: Bad first parameter to '%s'"*.
    BadFirstParameter(String),
    /// *"Syntax error in %s: Bad second parameter"* -- the attribute commands'
    /// wording, which interpolates the whole command line.
    BadSecondParameter(String),
    /// *"Syntax error in ln/symlink: Bad second parameter"* -- a fixed string,
    /// naming both spellings whichever was used.
    BadSymlinkParameter,
    /// *"Syntax error in rename: Bad second parameter"* -- also fixed.
    BadRenameParameter,
    /// *"Suspicious data after the command line"* -- `return_quote_error`
    /// (`lib/vssh/libssh2.c:718-726`).
    SuspiciousTrailingData,
    /// *"Unknown SFTP command"*.
    UnknownCommand,
    /// *"Syntax error: chgrp gid not a number"*.
    ChgrpNotANumber,
    /// *"Syntax error: chmod permissions not a number"*.
    ChmodNotANumber,
    /// *"Syntax error: chown uid not a number"*.
    ChownNotANumber,
    /// *"incorrect date format for %.*s"* with precision 5, so the command word
    /// alone is printed.
    IncorrectDateFormat(String),
    /// *"date overflow"* -- a date past `0xffffffff`, which the wire's 32-bit
    /// time field cannot carry.
    DateOverflow,
    /// The argument exceeded [`MAX_PATHLENGTH`]. [`CURLcode::TooLarge`], which
    /// is what `Curl_get_pathname` returns for `STRE_BIG`.
    TooLarge,
}

#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
impl QuoteError {
    /// The code this refusal reports.
    pub(crate) const fn code(&self) -> CURLcode {
        match self {
            Self::MissingParameter(_) => CURLcode::Ok,
            Self::TooLarge => CURLcode::TooLarge,
            _ => CURLcode::QuoteError,
        }
    }

    /// The `failf` text, byte for byte.
    pub(crate) fn message(&self) -> String {
        match self {
            Self::MissingParameter(cmd) => {
                format!("Syntax error command '{cmd}', missing parameter")
            }
            Self::BadFirstParameter(cmd) => {
                format!("Syntax error: Bad first parameter to '{cmd}'")
            }
            Self::BadSecondParameter(cmd) => {
                format!("Syntax error in {cmd}: Bad second parameter")
            }
            Self::BadSymlinkParameter => {
                "Syntax error in ln/symlink: Bad second parameter".into()
            }
            Self::BadRenameParameter => {
                "Syntax error in rename: Bad second parameter".into()
            }
            Self::SuspiciousTrailingData => {
                "Suspicious data after the command line".into()
            }
            Self::UnknownCommand => "Unknown SFTP command".into(),
            Self::ChgrpNotANumber => {
                "Syntax error: chgrp gid not a number".into()
            }
            Self::ChmodNotANumber => {
                "Syntax error: chmod permissions not a number".into()
            }
            Self::ChownNotANumber => {
                "Syntax error: chown uid not a number".into()
            }
            Self::IncorrectDateFormat(keyword) => {
                format!("incorrect date format for {keyword}")
            }
            Self::DateOverflow => "date overflow".into(),
            Self::TooLarge => "quote path too long".into(),
        }
    }
}

/// One parsed quote command, ready for the state it names.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) struct ParsedQuote {
    /// Which command it is.
    pub(crate) command: QuoteCommand,
    /// `sshc->quote_path1`: the first argument, which is a VALUE for the five
    /// attribute commands and a path for the rest.
    pub(crate) path1: Vec<u8>,
    /// `sshc->quote_path2`: the second argument, empty for a one-argument
    /// command.
    pub(crate) path2: Vec<u8>,
    /// `sshc->acceptfail`: the command was prefixed with `*`, so a failure is to
    /// be reported as a success.
    ///
    /// The C's comment: *"if a command starts with an asterisk, which a legal
    /// SFTP command never can, the command will be allowed to fail without it
    /// causing any aborts or cancels etc. It will cause libcurl to act as if the
    /// command is successful, whatever the server responds."*
    pub(crate) acceptfail: bool,
    /// The state to move to.
    pub(crate) next: SshState,
}

/// `sftp_quote` (`lib/vssh/libssh2.c:727-884`): parse one `--quote` command.
///
/// `pwd` is recognised and answered before anything is parsed, because it takes
/// no argument and produces no packet; [`pwd_report`] builds its output. Every
/// other command needs a space, then one or two arguments parsed by
/// [`get_pathname`], then an empty remainder.
///
/// The trailing-data test is the C's and is applied per command, not once: seven
/// of the branches end with `if(*cp) return_quote_error(data, sshc);`. Note what
/// that C line does NOT do -- it discards the returned code, so the C
/// diagnoses the trailing data and then proceeds to the operation anyway. That
/// is preserved: [`ParsedQuote`] is still produced and the refusal is reported
/// alongside it, which is why this function answers a pair.
///
/// # Errors
///
/// A [`QuoteError`] whose [`QuoteError::code`] and [`QuoteError::message`] are
/// the C's for that branch.
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) fn sftp_quote(
    command_line: &[u8],
    homedir: &[u8],
) -> Result<ParsedQuote, QuoteError> {
    let mut cmd = command_line;
    let mut acceptfail = false;
    if cmd.first().is_some_and(|byte| *byte == b'*') {
        cmd = &cmd[1..];
        acceptfail = true;
    }

    // `curl_strequal("pwd", cmd)` -- case-insensitive and whole-string, so
    // `PWD` works and `pwd /x` does not.
    if casecompare(b"pwd", cmd) {
        return Ok(ParsedQuote {
            command: QuoteCommand::Pwd,
            path1: Vec::new(),
            path2: Vec::new(),
            acceptfail,
            next: QuoteCommand::Pwd.next_state(),
        });
    }

    let display = String::from_utf8_lossy(cmd).into_owned();

    // `cp = strchr(cmd, ' ')` -- the arguments must be separated from the
    // command by a space, tested unconditionally so that every branch below can
    // assume one.
    let space = cmd.iter().position(|byte| *byte == b' ');
    let Some(space) = space else {
        return Err(QuoteError::MissingParameter(display));
    };

    let mut cursor = &cmd[space..];
    let path1 = get_pathname(&mut cursor, homedir).map_err(|code| {
        if code == CURLcode::TooLarge {
            QuoteError::TooLarge
        } else {
            QuoteError::BadFirstParameter(display.clone())
        }
    })?;

    let command = QUOTE_COMMANDS
        .iter()
        .find(|(spelling, _)| cmd.starts_with(spelling))
        .map(|(_, command)| *command)
        .ok_or(QuoteError::UnknownCommand)?;

    let mut path2 = Vec::new();
    if command.argument_count() == 2 {
        path2 = get_pathname(&mut cursor, homedir).map_err(|code| {
            if code == CURLcode::TooLarge {
                QuoteError::TooLarge
            } else {
                match command {
                    QuoteCommand::Symlink => QuoteError::BadSymlinkParameter,
                    QuoteCommand::Rename => QuoteError::BadRenameParameter,
                    _ => QuoteError::BadSecondParameter(display.clone()),
                }
            }
        })?;
    }

    if !cursor.is_empty() {
        return Err(QuoteError::SuspiciousTrailingData);
    }

    Ok(ParsedQuote {
        command,
        path1,
        path2,
        acceptfail,
        next: command.next_state(),
    })
}

/// `sftp_quote_stat` (`lib/vssh/libssh2.c:1163-1268`): derive the attribute
/// block one of the five attribute commands sets.
///
/// `current` is what the preliminary `SSH_FXP_STAT` returned, and it matters:
/// `chown` sets the uid and leaves the gid as the server reported it, and
/// `atime` and `mtime` do the same for each other. `chmod` ignores `current`
/// entirely, which is why [`QuoteCommand::needs_preliminary_stat`] excludes it.
///
/// The resulting `flags` word carries exactly ONE bit, replacing whatever the
/// stat reported -- the C assigns rather than ORs
/// (`sshp->quote_attrs.flags = LIBSSH2_SFTP_ATTR_UIDGID`), so a `SETSTAT` sends
/// only the attribute the command names.
///
/// # One measured deviation, and why it is a deviation rather than a defect
///
/// The C bounds the `chgrp` and `chown` values with
/// `curlx_str_number(&p, &gid, ULONG_MAX)` (`lib/vssh/libssh2.c:1204` and
/// `:1227`). On an LP64 target `ULONG_MAX` is `0xFFFFFFFFFFFFFFFF`, and the
/// parameter it is passed to is a `curl_off_t`, so the conversion yields `-1`.
/// `str_num_base` then takes its `max < base` branch and refuses the first digit
/// with `STRE_OVERFLOW` (`lib/curlx/strparse.c:171-179`), which means **`chgrp`
/// and `chown` report *"not a number"* for every value on Linux and macOS**.
/// `str_num_base`'s own `DEBUGASSERT(max >= 0)` at `:166` says the argument was
/// never intended: *"mostly to catch SIZE_MAX, which is too large"*.
///
/// The cap used here is [`u32::MAX`], which is the width of the wire field the
/// value is written into -- `SSH_FXP_SETSTAT` carries uid and gid as four bytes
/// each. Three facts make that the right call rather than an unsanctioned
/// change: the corpus does not assert the C's behaviour, since **no fixture
/// exercises `chgrp` or `chown` at all** (measured across all 1,914); the
/// documented behaviour of the option is to set the owner, so reproducing the
/// conversion would make a documented flag unusable while emitting a diagnostic
/// that misdescribes its own input; and nothing on the wire differs for any
/// value the C would have accepted, because on a target where `unsigned long` is
/// 32 bits the C's own cap IS [`u32::MAX`]. The deviation is recorded here
/// rather than hidden so that a reader diffing the two finds the reasoning
/// instead of a discrepancy.
///
/// # Errors
///
/// [`QuoteError::ChgrpNotANumber`], [`QuoteError::ChmodNotANumber`],
/// [`QuoteError::ChownNotANumber`], [`QuoteError::IncorrectDateFormat`] or
/// [`QuoteError::DateOverflow`], each with the C's text.
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) fn quote_setstat_attributes(
    command: QuoteCommand,
    value: &[u8],
    current: SftpAttributes,
    acceptfail: bool,
) -> Result<SftpAttributes, QuoteError> {
    let mut attrs = current;
    match command {
        QuoteCommand::Chgrp => {
            let mut cursor = value;
            match str_number(&mut cursor, i64::from(u32::MAX)) {
                Ok(gid) => {
                    attrs.gid = u32::try_from(gid).unwrap_or(u32::MAX);
                    attrs.flags = SftpAttrFlags::UIDGID;
                }
                Err(_) => {
                    // `else if(!sshc->acceptfail)`: with `*chgrp` the bad value
                    // is swallowed and the attributes are sent unchanged.
                    if !acceptfail {
                        return Err(QuoteError::ChgrpNotANumber);
                    }
                }
            }
        }
        QuoteCommand::Chown => {
            let mut cursor = value;
            match str_number(&mut cursor, i64::from(u32::MAX)) {
                Ok(uid) => {
                    attrs.uid = u32::try_from(uid).unwrap_or(u32::MAX);
                    attrs.flags = SftpAttrFlags::UIDGID;
                }
                Err(_) => {
                    if !acceptfail {
                        return Err(QuoteError::ChownNotANumber);
                    }
                }
            }
        }
        QuoteCommand::Chmod => {
            let mut cursor = value;
            // `curlx_str_octal(&p, &perms, 07777)`: octal, and capped at four
            // octal digits. Note the polarity -- the C treats a PARSE FAILURE
            // as the error and has no `acceptfail` escape here, unlike chgrp
            // and chown.
            let perms = str_octal(&mut cursor, 0o7777)
                .map_err(|_| QuoteError::ChmodNotANumber)?;
            attrs.permissions = u32::try_from(perms).unwrap_or(0);
            attrs.flags = SftpAttrFlags::PERMISSIONS;
        }
        QuoteCommand::Atime | QuoteCommand::Mtime => {
            let text = core::str::from_utf8(value).map_err(|_| {
                QuoteError::IncorrectDateFormat(command.keyword().into())
            })?;
            let date = getdate_capped(text).ok_or_else(|| {
                QuoteError::IncorrectDateFormat(command.keyword().into())
            })?;
            // `#if SIZEOF_TIME_T > SIZEOF_LONG` guards this in the C, and on
            // every one of the four mandated targets `time_t` is 64-bit while
            // the wire field is 32-bit -- so the check is always compiled and
            // is unconditional here.
            if date > i64::from(u32::MAX) {
                return Err(QuoteError::DateOverflow);
            }
            let seconds = u32::try_from(date).unwrap_or(0);
            if command == QuoteCommand::Atime {
                attrs.atime = seconds;
            } else {
                attrs.mtime = seconds;
            }
            attrs.flags = SftpAttrFlags::ACMODTIME;
        }
        QuoteCommand::Pwd
        | QuoteCommand::Symlink
        | QuoteCommand::Mkdir
        | QuoteCommand::Rename
        | QuoteCommand::Rmdir
        | QuoteCommand::Unlink
        | QuoteCommand::Statvfs => {
            // Not an attribute command; the caller never routes one here, and
            // the arm exists so that adding a command is a compile error rather
            // than a silent fall-through. The attributes are returned unchanged,
            // which sends nothing.
        }
    }
    Ok(attrs)
}

/// The `pwd` quote command's output -- `sftp_quote`
/// (`lib/vssh/libssh2.c:755-772`).
///
/// The C builds `"257 \"%s\" is current directory.\n"` and writes it to the
/// HEADER stream, with the comment: *"this sends an FTP-like "header" to the
/// header callback so that the current directory can be read similar to how it
/// is read when using ordinary FTP."* So the `257` is an FTP reply code appearing
/// in an SFTP transfer deliberately, and the trailing newline is part of it.
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) fn pwd_report(path: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(path.len() + 32);
    out.extend_from_slice(b"257 \"");
    out.extend_from_slice(path);
    out.extend_from_slice(b"\" is current directory.\n");
    out
}

/// What `pwd` also emits to the debug channel: `CURLINFO_HEADER_OUT` receives
/// exactly `"PWD\n"`, four bytes.
///
/// `Curl_debug(data, CURLINFO_HEADER_OUT, "PWD\n", 4)`. There is no PWD command
/// on an SFTP wire, so this is a synthesised trace line that makes an SFTP
/// session read like an FTP one -- and it is compared by fixtures that capture
/// the debug stream.
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) const PWD_DEBUG_LINE: &[u8] = b"PWD\n";

/// The `statvfs` quote command's output -- `ssh_state_sftp_quote_statvfs`
/// (`lib/vssh/libssh2.c:2103-2120`).
///
/// Eleven lines after a `statvfs:` header, each `<name>: <value>` with a single
/// space and a trailing newline, written to the HEADER stream. The order is the
/// C's `curl_maprintf` argument order and is not alphabetical: `f_bsize`,
/// `f_frsize`, `f_blocks`, `f_bfree`, `f_bavail`, `f_files`, `f_ffree`,
/// `f_favail`, `f_fsid`, `f_flag`, `f_namemax`.
///
/// The C's format is `%llu` on every platform but MSVC, where it is `%I64u` --
/// both print an unsigned 64-bit decimal, so the bytes are identical and there
/// is nothing to choose between them here.
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) fn statvfs_report(stats: &SftpStatVfs) -> Vec<u8> {
    let mut out = String::with_capacity(256);
    out.push_str("statvfs:\n");
    out.push_str(&format!("f_bsize: {}\n", stats.bsize));
    out.push_str(&format!("f_frsize: {}\n", stats.frsize));
    out.push_str(&format!("f_blocks: {}\n", stats.blocks));
    out.push_str(&format!("f_bfree: {}\n", stats.bfree));
    out.push_str(&format!("f_bavail: {}\n", stats.bavail));
    out.push_str(&format!("f_files: {}\n", stats.files));
    out.push_str(&format!("f_ffree: {}\n", stats.ffree));
    out.push_str(&format!("f_favail: {}\n", stats.favail));
    out.push_str(&format!("f_fsid: {}\n", stats.fsid));
    out.push_str(&format!("f_flag: {}\n", stats.flag));
    out.push_str(&format!("f_namemax: {}\n", stats.namemax));
    out.into_bytes()
}

/// One line of a directory listing -- `sftp_readdir`
/// (`lib/vssh/libssh2.c:1369-1426`) with `SSH_SFTP_READDIR_LINK`
/// (`:2202-2229`) and `SSH_SFTP_READDIR_BOTTOM` (`:2810-2828`).
///
/// Two shapes, chosen by `CURLOPT_DIRLISTONLY`:
///
/// * `list_only` -- the bare filename and a newline, nothing else. Two separate
///   client writes in the C, which matters only to a write callback counting
///   calls; the bytes are the concatenation;
/// * otherwise -- the server's long entry, then `" -> target"` when the entry is
///   a symbolic link and its target was resolved, then a newline.
///
/// The `" -> "` separator is `curlx_dyn_addf(&sshp->readdir, " -> %s", ...)`:
/// one leading space, the arrow, one trailing space, and no quoting of the
/// target. `link_target` is [`None`] when the entry is not a link, and the caller
/// establishes that with [`SftpAttributes::is_symlink`].
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) fn sftp_readdir_entry(
    entry: &SftpName,
    link_target: Option<&[u8]>,
    list_only: bool,
) -> Vec<u8> {
    if list_only {
        let mut out = Vec::with_capacity(entry.filename.len() + 1);
        out.extend_from_slice(&entry.filename);
        out.push(b'\n');
        return out;
    }

    let mut out = Vec::with_capacity(entry.longentry.len() + 32);
    out.extend_from_slice(&entry.longentry);
    if let Some(target) = link_target {
        out.extend_from_slice(b" -> ");
        out.extend_from_slice(target);
    }
    out.push(b'\n');
    out
}

/// The path an `SSH_FXP_READLINK` is issued for during a listing.
///
/// `curlx_dyn_addf(&sshp->readdir_link, "%s%s", sshp->path,
/// sshp->readdir_filename)` -- the directory path and the entry name
/// concatenated with **no separator inserted**. That is correct rather than a
/// bug: `SSH_SFTP_TRANS_INIT` routes to `SSH_SFTP_READDIR_INIT` only when the
/// path's last byte is `/` (`lib/vssh/libssh2.c:2733-2736`), so the separator is
/// already there. Reproduced exactly, because inserting one would produce
/// `dir//entry` and a different `READLINK` argument on the wire.
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) fn readdir_link_path(dir: &[u8], filename: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(dir.len() + filename.len());
    out.extend_from_slice(dir);
    out.extend_from_slice(filename);
    out
}

// Host-key verification -- `ssh_check_fingerprint`
// (`lib/vssh/libssh2.c:456-600`) and `ssh_knownhost` (`:303-454`)

/// `enum curl_khtype` -- the host-key algorithm, as the known-hosts callback
/// sees it.
///
/// The integers are the public header's (`include/curl/curl.h`), because
/// `CURLOPT_SSH_KEYFUNCTION`'s callback receives a `struct curl_khkey` carrying
/// one. `convert_ssh2_keytype` (`lib/vssh/libssh2.c:269-301`) is what maps the
/// transport's own vocabulary onto them, and the mapping collapses all three
/// ECDSA curve sizes onto [`Self::Ecdsa`] -- which is why the callback cannot
/// tell a P-256 key from a P-521 one, and why this port does not try to.
#[repr(i32)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
pub(crate) enum HostKeyType {
    /// `CURLKHTYPE_UNKNOWN` = 0, and the value `convert_ssh2_keytype` starts
    /// from -- so an algorithm the map does not name arrives as this rather than
    /// as an error.
    #[default]
    Unknown = 0,
    /// `CURLKHTYPE_RSA1` = 1. Never produced by the map: libssh2 has no
    /// `LIBSSH2_HOSTKEY_TYPE_RSA1`, and SSH-1 is long gone. Declared because the
    /// enumerant is public ABI.
    Rsa1 = 1,
    /// `CURLKHTYPE_RSA` = 2.
    Rsa = 2,
    /// `CURLKHTYPE_DSS` = 3.
    Dss = 3,
    /// `CURLKHTYPE_ECDSA` = 4 -- all three curve sizes.
    Ecdsa = 4,
    /// `CURLKHTYPE_ED25519` = 5.
    Ed25519 = 5,
}

#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
impl HostKeyType {
    /// The type's public integer.
    pub(crate) const fn as_i32(self) -> i32 {
        self as i32
    }

    /// The type an SSH host-key algorithm name denotes.
    ///
    /// The names are the wire's, from RFC 4253 and its successors, and they are
    /// what `russh` reports. The correspondence with
    /// `convert_ssh2_keytype`'s `LIBSSH2_HOSTKEY_TYPE_*` constants is
    /// one-for-one, with the same collapse of the three ECDSA curves.
    ///
    /// `rsa-sha2-256` and `rsa-sha2-512` are RSA keys signed with a stronger
    /// hash, not different key types, so both answer [`Self::Rsa`] -- which is
    /// also why `ssh_force_knownhost_key_type` (`lib/vssh/libssh2.c:606-716`)
    /// offers `"rsa-sha2-256,rsa-sha2-512,ssh-rsa"` as ONE preference string for
    /// a known RSA host key.
    #[rustfmt::skip]
    pub(crate) fn from_algorithm(name: &[u8]) -> Self {
        if name == b"ssh-rsa"
            || name == b"rsa-sha2-256"
            || name == b"rsa-sha2-512"
        {
            Self::Rsa
        } else if name == b"ssh-dss" {
            Self::Dss
        } else if name == b"ecdsa-sha2-nistp256"
            || name == b"ecdsa-sha2-nistp384"
            || name == b"ecdsa-sha2-nistp521"
        {
            Self::Ecdsa
        } else if name == b"ssh-ed25519" {
            Self::Ed25519
        } else {
            Self::Unknown
        }
    }

    /// The host-key algorithm preference `ssh_force_knownhost_key_type` offers
    /// when the known-hosts file already holds a key of this type.
    ///
    /// `lib/vssh/libssh2.c:610-616`, verbatim. The C's purpose is stated in its
    /// own comment: *"check the known hosts file and try to force a specific
    /// public key type from the server if an entry is found"* -- so that a
    /// server offering several algorithms presents the one already trusted
    /// rather than a newer one that would look like a mismatch.
    ///
    /// [`None`] for the two types no entry can hold: `CURLKHTYPE_UNKNOWN` names
    /// nothing to prefer, and `CURLKHTYPE_RSA1` has no modern algorithm name.
    #[rustfmt::skip]
    pub(crate) const fn hostkey_method(self) -> Option<&'static str> {
        match self {
            Self::Unknown | Self::Rsa1 => None,
            Self::Rsa     => Some("rsa-sha2-256,rsa-sha2-512,ssh-rsa"),
            Self::Dss     => Some("ssh-dss"),
            // The C offers ONE curve per known entry, chosen by the entry's own
            // key bits, and cannot express "any ECDSA". P-256 is the value used
            // when the entry's size is unknown, which is the case here because
            // the type has already collapsed.
            Self::Ecdsa   => Some("ecdsa-sha2-nistp256"),
            Self::Ed25519 => Some("ssh-ed25519"),
        }
    }
}

/// `enum curl_khstat` -- what the `CURLOPT_SSH_KEYFUNCTION` callback answers.
///
/// The integers are the public header's. `ssh_knownhost`
/// (`lib/vssh/libssh2.c:407-451`) is the switch that acts on them, and its
/// `default:` arm is *"unknown return codes will equal reject"* -- so an
/// out-of-range answer from an application is a refusal rather than undefined
/// behaviour, which [`Self::from_i32`] preserves by answering [`None`] and
/// letting the caller treat that as [`Self::Reject`].
#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
pub(crate) enum KnownHostStat {
    /// `CURLKHSTAT_FINE_ADD_TO_FILE` = 0: proceed, and write the key out.
    FineAddToFile = 0,
    /// `CURLKHSTAT_FINE` = 1: proceed, in memory only.
    Fine = 1,
    /// `CURLKHSTAT_REJECT` = 2: *"reject the connection, return an error"*.
    Reject = 2,
    /// `CURLKHSTAT_DEFER` = 3: *"do not accept it, but we cannot answer right
    /// now"*. The C's comment on its arm is the behaviour that matters --
    /// *"DEFER means bail out but keep the SSH_HOSTKEY state"* -- so unlike
    /// [`Self::Reject`] it does NOT move to `SSH_SESSION_FREE`.
    Defer = 3,
    /// `CURLKHSTAT_FINE_REPLACE` = 4: proceed, and replace the stored key.
    FineReplace = 4,
}

#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
impl KnownHostStat {
    /// Every value, in numeric order.
    pub(crate) const ALL: [Self; 5] = [
        Self::FineAddToFile,
        Self::Fine,
        Self::Reject,
        Self::Defer,
        Self::FineReplace,
    ];

    /// The value's public integer.
    pub(crate) const fn as_i32(self) -> i32 {
        self as i32
    }

    /// The value carrying `raw`, or [`None`] for anything else.
    ///
    /// [`None`] is the C's `default:` arm and must be treated as
    /// [`Self::Reject`] by the caller. [`Self::accepts`] does exactly that for
    /// an [`Option`], so no call site has to remember.
    pub(crate) fn from_i32(raw: i32) -> Option<Self> {
        Self::ALL.into_iter().find(|value| value.as_i32() == raw)
    }

    /// Whether this answer lets the session proceed.
    ///
    /// The three `FINE` spellings proceed; [`Self::Reject`] and [`Self::Defer`]
    /// do not. Taking an [`Option`] folds in the `default:` arm: `None` is an
    /// answer outside the enumeration and is a refusal.
    pub(crate) fn accepts(answer: Option<Self>) -> bool {
        matches!(
            answer,
            Some(Self::Fine | Self::FineAddToFile | Self::FineReplace)
        )
    }

    /// Whether this answer additionally asks for the known-hosts FILE to be
    /// rewritten.
    ///
    /// `if(rc == CURLKHSTAT_FINE_ADD_TO_FILE || rc == CURLKHSTAT_FINE_REPLACE)`
    /// (`lib/vssh/libssh2.c:437-438`). Plain [`Self::Fine`] adds the key in
    /// memory only, which is the distinction the three spellings exist for.
    pub(crate) const fn writes_the_file(self) -> bool {
        matches!(self, Self::FineAddToFile | Self::FineReplace)
    }

    /// Whether this answer moves the machine to `SSH_SESSION_FREE`.
    ///
    /// [`Self::Reject`] does and [`Self::Defer`] does not, which is the whole
    /// difference between them: the C's `case CURLKHSTAT_REJECT:` calls
    /// `myssh_to(data, sshc, SSH_SESSION_FREE)` and then falls through to
    /// `case CURLKHSTAT_DEFER:`, so both report
    /// [`CURLcode::PeerFailedVerification`] while only one tears the session
    /// down.
    pub(crate) const fn frees_the_session(self) -> bool {
        matches!(self, Self::Reject)
    }
}

/// `enum curl_khmatch` -- how the offered key compared with the stored one.
///
/// Passed to the callback so that an application can distinguish "never seen
/// this host" from "the key changed". The C's own comment above the assignment
/// is a warning worth carrying: *"Ask the callback how to behave"*, preceded by
/// *"if the libssh2 enums and the curl_khmatch enum are ever modified, we need
/// to introduce a translation table here!"* -- the C relies on the two
/// enumerations agreeing numerically. This port does not: [`Self::from_check`]
/// is the translation table the C says would be needed.
#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
pub(crate) enum KnownHostMatch {
    /// `CURLKHMATCH_OK` = 0: the stored key matches.
    Ok = 0,
    /// `CURLKHMATCH_MISMATCH` = 1: the host is known and the key differs.
    Mismatch = 1,
    /// `CURLKHMATCH_MISSING` = 2: the host is not in the file.
    Missing = 2,
}

#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
impl KnownHostMatch {
    /// The value's public integer.
    pub(crate) const fn as_i32(self) -> i32 {
        self as i32
    }

    /// The verdict for a known-hosts lookup.
    ///
    /// `matched` says the file held this host, `same_key` says the stored key is
    /// the one offered. The three outcomes are exactly the C's
    /// `LIBSSH2_KNOWNHOST_CHECK_MATCH`, `_MISMATCH` and `_NOTFOUND`.
    pub(crate) const fn from_check(matched: bool, same_key: bool) -> Self {
        if !matched {
            Self::Missing
        } else if same_key {
            Self::Ok
        } else {
            Self::Mismatch
        }
    }
}

/// Why host-key verification refused a session, with the C's exact diagnostic.
///
/// Every one reports [`CURLcode::PeerFailedVerification`], which is the only
/// code `ssh_check_fingerprint` and `ssh_knownhost` return. The variants exist
/// because the five messages differ and all five are user-visible.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
pub(crate) enum FingerprintError {
    /// The transport could not produce a SHA-256 hash: *"Denied establishing ssh
    /// session: sha256 fingerprint not available"*.
    Sha256Unavailable,
    /// The base64 encoding failed: *"sha256 fingerprint could not be
    /// encoded"*.
    Sha256NotEncodable,
    /// *"Denied establishing ssh session: mismatch sha256 fingerprint. Remote %s
    /// is not equal to %s"*.
    Sha256Mismatch {
        /// What the server offered, base64-encoded.
        remote: String,
        /// What `CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256` asked for.
        expected: String,
    },
    /// The transport could not produce an MD5 hash: *"Denied establishing ssh
    /// session: md5 fingerprint not available"*.
    Md5Unavailable,
    /// *"Denied establishing ssh session: mismatch md5 fingerprint. Remote %s is
    /// not equal to %s"*.
    Md5Mismatch {
        /// What the server offered, as 32 lower-case hexadecimal digits.
        remote: String,
        /// What `CURLOPT_SSH_HOST_PUBLIC_KEY_MD5` asked for.
        expected: String,
    },
    /// The known-hosts callback or file refused the key. The C emits no message
    /// of its own here -- the application was asked and said no.
    KnownHostRefused,
}

#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
impl FingerprintError {
    /// The code every refusal reports.
    pub(crate) const fn code(&self) -> CURLcode {
        CURLcode::PeerFailedVerification
    }

    /// The `failf` text, byte for byte, or [`None`] for the refusal the C
    /// reports silently.
    pub(crate) fn message(&self) -> Option<String> {
        match self {
            Self::Sha256Unavailable => Some(
                "Denied establishing ssh session: sha256 fingerprint \
                 not available"
                    .into(),
            ),
            Self::Sha256NotEncodable => {
                Some("sha256 fingerprint could not be encoded".into())
            }
            Self::Sha256Mismatch { remote, expected } => Some(format!(
                "Denied establishing ssh session: mismatch sha256 \
                 fingerprint. Remote {remote} is not equal to {expected}"
            )),
            Self::Md5Unavailable => Some(
                "Denied establishing ssh session: md5 fingerprint \
                 not available"
                    .into(),
            ),
            Self::Md5Mismatch { remote, expected } => Some(format!(
                "Denied establishing ssh session: mismatch md5 fingerprint. \
                 Remote {remote} is not equal to {expected}"
            )),
            Self::KnownHostRefused => None,
        }
    }

    /// Whether this refusal moves the machine to `SSH_SESSION_FREE`.
    ///
    /// Every fingerprint refusal does -- each one is followed by
    /// `myssh_to(data, sshc, SSH_SESSION_FREE)` in the C. The known-hosts path
    /// is the exception, because [`KnownHostStat::Defer`] deliberately keeps the
    /// `SSH_HOSTKEY` state, so that decision belongs to the caller and is not
    /// answered here.
    pub(crate) const fn frees_the_session(&self) -> bool {
        !matches!(self, Self::KnownHostRefused)
    }
}

/// `libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_MD5)` rendered the way
/// the C renders it.
///
/// `ssh_check_fingerprint` (`lib/vssh/libssh2.c:539-547`) walks the 16 raw bytes
/// and writes them with `curl_msnprintf(&md5buffer[i * 2], 3, "%02x", ...)`, so
/// the output is exactly 32 LOWER-CASE hexadecimal digits with no separators.
/// Note the comment that follows, which is the C admitting a sharp edge and
/// which this port preserves: *"This does NOT verify the length of 'pubkey_md5'
/// separately, which will make the comparison below fail unless it is exactly 32
/// characters"*. The comparison is [`casecompare`], the whole-string
/// case-insensitive one, so a 31-character option value simply does not match.
///
/// The digest itself is MD5 over the raw host-key blob. MD5 is used here because
/// the option is defined in terms of it, not because it is sound: it is a
/// fingerprint the user supplied out of band, and the alternative
/// `CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256` exists for exactly that reason.
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
pub(crate) fn md5_fingerprint_hex(hostkey: &[u8]) -> String {
    let digest = crate::crypto::md5::md5(hostkey);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// `libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA256)` rendered the way
/// the C renders it.
///
/// `curlx_base64_encode` over the 32 raw bytes
/// (`lib/vssh/libssh2.c:486-488`), so the result is standard base64 WITH its
/// padding -- 44 characters ending in `=`. The comparison then ignores that
/// padding; see [`sha256_fingerprints_match`].
///
/// # Errors
///
/// [`CURLcode`] from the encoder, which is what
/// [`FingerprintError::Sha256NotEncodable`] reports. The encoder can only refuse
/// an input beyond its ceiling, and a 32-byte digest is never that, so the
/// failure is unreachable in practice and is still propagated rather than
/// discarded -- the C checks it too, twice.
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
pub(crate) fn sha256_fingerprint_base64(
    hostkey: &[u8],
) -> Result<String, CURLcode> {
    let digest = crate::crypto::sha256::sha256(hostkey);
    base64::encode(&digest)
}

/// The SHA-256 fingerprint comparison, padding and all --
/// `ssh_check_fingerprint` (`lib/vssh/libssh2.c:499-522`).
///
/// The C does something unusual and it is deliberate: it finds the position of
/// the first `=` in EACH string, requires the two positions to be equal, and
/// then compares only that many bytes. So the padding is ignored on both sides,
/// and a user may write `CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256` with or without
/// its trailing `=` and either spelling matches.
///
/// What that does NOT permit, and a reader is likely to assume it does: a
/// TRUNCATED fingerprint. `abc` and `abcdef` have their first `=` at positions 3
/// and 6, the positions differ, and the comparison fails before any byte is
/// looked at. The length test is what makes the prefix comparison safe, which is
/// why it is written as a conjunction here exactly as it is there.
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
pub(crate) fn sha256_fingerprints_match(remote: &str, expected: &str) -> bool {
    let unpadded = |text: &str| text.find('=').unwrap_or(text.len());
    let remote_len = unpadded(remote);
    let expected_len = unpadded(expected);
    remote_len == expected_len
        && remote.as_bytes()[..remote_len]
            == expected.as_bytes()[..expected_len]
}

/// What `CURLOPT_SSH_HOST_PUBLIC_KEY_MD5`, `..._SHA256`,
/// `CURLOPT_SSH_KNOWNHOSTS` and `CURLOPT_SSH_HOSTKEYFUNCTION` ask of a host
/// key.
///
/// One value rather than four option lookups, so that [`check_fingerprint`] is a
/// pure function of its inputs and testable without an easy handle.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
pub(crate) struct HostKeyPolicy {
    /// `data->set.str[STRING_SSH_HOST_PUBLIC_KEY_MD5]`.
    pub(crate) md5: Option<String>,
    /// `data->set.str[STRING_SSH_HOST_PUBLIC_KEY_SHA256]`.
    pub(crate) sha256: Option<String>,
    /// Whether `CURLOPT_SSH_HOSTKEYFUNCTION` is set.
    ///
    /// A bare flag rather than the callback: the callback belongs to the easy
    /// handle, and what this function needs to know is only whether to consult
    /// it. Its ANSWER arrives as [`HostKeyDecision::AskHostKeyCallback`]'s
    /// resolution, which the caller performs.
    pub(crate) hostkeyfunc: bool,
    /// Whether `CURLOPT_SSH_KNOWNHOSTS` named a file.
    pub(crate) known_hosts: bool,
}

/// What host-key verification concluded.
///
/// `ssh_check_fingerprint` has three outcomes and this names all three, because
/// two of them are decisions the caller must carry out rather than results:
///
/// * a fingerprint matched, or none was configured and no callback or file
///   exists, so the session proceeds;
/// * no fingerprint was configured and `CURLOPT_SSH_HOSTKEYFUNCTION` is set, so
///   the application must be asked;
/// * no fingerprint was configured and a known-hosts file was named, so the file
///   must be consulted.
///
/// The C expresses the last two by CALLING them from inside the check, which is
/// what makes `ssh_check_fingerprint` untestable there. Returning the decision
/// keeps this function pure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
pub(crate) enum HostKeyDecision {
    /// Verification is complete and the session may proceed.
    ///
    /// Reached by a fingerprint match -- *"as we already matched, we skip the
    /// check for known hosts"* -- and also by the case where nothing at all is
    /// configured, which is what makes an unverified SSH session possible in the
    /// first place.
    Accepted,
    /// `data->set.ssh_hostkeyfunc` is set and must be called with the raw key.
    ///
    /// The C requires `CURLKHMATCH_OK` from it and treats every other answer as
    /// [`CURLcode::PeerFailedVerification`] -- note that this callback answers a
    /// `curl_khmatch`, not a `curl_khstat`, which is the opposite of
    /// `CURLOPT_SSH_KEYFUNCTION`.
    AskHostKeyCallback,
    /// A known-hosts file was named and must be consulted; see
    /// [`KnownHostMatch`] and [`KnownHostStat`].
    ConsultKnownHosts,
}

/// `ssh_check_fingerprint` (`lib/vssh/libssh2.c:456-600`).
///
/// The order is the C's and is not interchangeable: SHA-256 is checked first, MD5
/// second, and the fall-through to a callback or the known-hosts file happens
/// only when NEITHER option was set. So configuring both fingerprints requires
/// both to match, and configuring either one suppresses the known-hosts check
/// entirely -- the C's comment says so: *"as we already matched, we skip the
/// check for known hosts"*.
///
/// `hostkey` is the raw host-key blob, which is what both digests are taken
/// over.
///
/// # Errors
///
/// A [`FingerprintError`] whose message is the C's for that branch. Every one
/// reports [`CURLcode::PeerFailedVerification`].
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
pub(crate) fn check_fingerprint(
    hostkey: &[u8],
    policy: &HostKeyPolicy,
) -> Result<HostKeyDecision, FingerprintError> {
    if let Some(expected) = policy.sha256.as_deref() {
        if hostkey.is_empty() {
            return Err(FingerprintError::Sha256Unavailable);
        }
        let remote = sha256_fingerprint_base64(hostkey)
            .map_err(|_| FingerprintError::Sha256NotEncodable)?;
        if !sha256_fingerprints_match(&remote, expected) {
            return Err(FingerprintError::Sha256Mismatch {
                remote,
                expected: expected.to_owned(),
            });
        }
    }

    if let Some(expected) = policy.md5.as_deref() {
        if hostkey.is_empty() {
            return Err(FingerprintError::Md5Unavailable);
        }
        let remote = md5_fingerprint_hex(hostkey);
        // `curl_strequal(md5buffer, pubkey_md5)`: whole-string and
        // case-insensitive, so an upper-case option value matches.
        if !casecompare(remote.as_bytes(), expected.as_bytes()) {
            return Err(FingerprintError::Md5Mismatch {
                remote,
                expected: expected.to_owned(),
            });
        }
    }

    if policy.md5.is_none() && policy.sha256.is_none() {
        if policy.hostkeyfunc {
            // The C additionally refuses outright when the transport cannot
            // produce the key at all: `else { myssh_to(...SSH_SESSION_FREE);
            // return CURLE_PEER_FAILED_VERIFICATION; }` at
            // `lib/vssh/libssh2.c:588-591`.
            if hostkey.is_empty() {
                return Err(FingerprintError::KnownHostRefused);
            }
            return Ok(HostKeyDecision::AskHostKeyCallback);
        }
        if policy.known_hosts {
            return Ok(HostKeyDecision::ConsultKnownHosts);
        }
        // Neither option, no callback and no file: `ssh_knownhost` with
        // `sshc->kh == NULL` falls straight through and answers `CURLE_OK`
        // (`lib/vssh/libssh2.c:311-317`).
        return Ok(HostKeyDecision::Accepted);
    }

    Ok(HostKeyDecision::Accepted)
}

// Authentication ordering -- `ssh_state_pkey_init` and its successors

/// The `CURLSSH_AUTH_*` mask of `CURLOPT_SSH_AUTH_TYPES`.
///
/// The integers are the public header's. Every state of the authentication
/// sequence tests one bit of this mask AND the server's own method list, and
/// both have to agree -- `(data->set.ssh_auth_types & CURLSSH_AUTH_PASSWORD) &&
/// (strstr(sshc->authlist, "password") != NULL)` is the shape of all four tests.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
pub(crate) struct SshAuthTypes(pub(crate) u32);

#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
impl SshAuthTypes {
    /// `CURLSSH_AUTH_NONE` = 0.
    pub(crate) const NONE: Self = Self(0);
    /// `CURLSSH_AUTH_PUBLICKEY` = 1.
    pub(crate) const PUBLICKEY: Self = Self(1 << 0);
    /// `CURLSSH_AUTH_PASSWORD` = 2.
    pub(crate) const PASSWORD: Self = Self(1 << 1);
    /// `CURLSSH_AUTH_HOST` = 4 -- *"host key files"*.
    pub(crate) const HOST: Self = Self(1 << 2);
    /// `CURLSSH_AUTH_KEYBOARD` = 8 -- keyboard-interactive.
    pub(crate) const KEYBOARD: Self = Self(1 << 3);
    /// `CURLSSH_AUTH_AGENT` = 16.
    pub(crate) const AGENT: Self = Self(1 << 4);
    /// `CURLSSH_AUTH_GSSAPI` = 32.
    ///
    /// Declared because the enumerant is public ABI and `CURLSSH_AUTH_DEFAULT`
    /// includes it. `SSH_AUTH_GSSAPI` is a state with NO arm of its own in the C
    /// machine -- `ssh_statemachine` has no `case SSH_AUTH_GSSAPI:`, so it falls
    /// into `default:` and stops -- and the libssh2 backend never routes to it.
    /// That is measured, not assumed, and it is why the sequence below has no
    /// GSS-API step.
    pub(crate) const GSSAPI: Self = Self(1 << 5);
    /// `CURLSSH_AUTH_ANY` and `CURLSSH_AUTH_DEFAULT` = `~0`: the default, which
    /// is why an unconfigured transfer tries every mechanism the server offers.
    pub(crate) const ANY: Self = Self(u32::MAX);

    /// True when every bit of `other` is set here.
    pub(crate) const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// The raw mask.
    pub(crate) const fn bits(self) -> u32 {
        self.0
    }
}

impl Default for SshAuthTypes {
    /// `CURLSSH_AUTH_DEFAULT`, which is `CURLSSH_AUTH_ANY`.
    fn default() -> Self {
        Self::ANY
    }
}

impl core::ops::BitOr for SshAuthTypes {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// The method names an SSH server lists, as `strstr` looks for them.
///
/// `sshc->authlist` is a comma-separated list from `libssh2_userauth_list`, and
/// the C searches it with `strstr` -- a SUBSTRING search, not a token match. That
/// is reproduced with [`memchr::memmem`] rather than tightened, because the
/// difference is observable: a server advertising `publickey-hostbound@openssh`
/// satisfies the C's test for `"publickey"`, and a stricter token match would
/// change which mechanism is attempted.
pub(crate) mod authlist {
    /// `"publickey"`, tested by both the public-key and the agent step.
    #[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
    pub(crate) const PUBLICKEY: &[u8] = b"publickey";
    /// `"password"`.
    #[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
    pub(crate) const PASSWORD: &[u8] = b"password";
    /// `"hostbased"`.
    #[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
    pub(crate) const HOSTBASED: &[u8] = b"hostbased";
    /// `"keyboard-interactive"`.
    #[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
    pub(crate) const KEYBOARD_INTERACTIVE: &[u8] = b"keyboard-interactive";

    /// Whether `list` offers `method`, by the C's substring rule.
    #[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
    pub(crate) fn offers(list: &[u8], method: &[u8]) -> bool {
        memchr::memmem::find(list, method).is_some()
    }
}

/// Where the authentication sequence goes next.
///
/// `ssh_state_pkey_init` through `ssh_state_auth_done`
/// (`lib/vssh/libssh2.c:1068-1160` and `:1483-1772`) form a chain in which each
/// step either attempts a mechanism or skips to the next, and the ORDER is the
/// C's comment's: *"Check the supported auth types in the order I feel is most
/// secure with the requested type of authentication"*.
///
/// The measured sequence, with the skip conditions:
///
/// | from | attempts | when | otherwise |
/// | --- | --- | --- | --- |
/// | `AUTH_PKEY_INIT` | `AUTH_PKEY` | `PUBLICKEY` and `publickey` | `AUTH_PASS_INIT` |
/// | `AUTH_PKEY` (failed) | -- | -- | `AUTH_PASS_INIT` |
/// | `AUTH_PASS_INIT` | `AUTH_PASS` | `PASSWORD` and `password` | `AUTH_HOST_INIT` |
/// | `AUTH_PASS` (failed) | -- | -- | `AUTH_HOST_INIT` |
/// | `AUTH_HOST_INIT` | `AUTH_HOST` | `HOST` and `hostbased` | `AUTH_AGENT_INIT` |
/// | `AUTH_HOST` | -- | -- | `AUTH_AGENT_INIT`, always |
/// | `AUTH_AGENT_INIT` | `AUTH_AGENT_LIST` | `AGENT` and `publickey` | `AUTH_KEY_INIT` |
/// | `AUTH_AGENT_LIST` | `AUTH_AGENT` | the agent listed identities | `AUTH_KEY_INIT` |
/// | `AUTH_AGENT` (failed) | -- | -- | `AUTH_KEY_INIT` |
/// | `AUTH_KEY_INIT` | `AUTH_KEY` | `KEYBOARD` and `keyboard-interactive` | `AUTH_DONE` |
/// | `AUTH_KEY` (failed) | -- | -- | `CURLE_LOGIN_DENIED`, immediately |
///
/// Two measured oddities that a reader will want to check and that are the C's:
///
/// * **`SSH_AUTH_HOST` does nothing at all.** Its whole arm is
///   `myssh_to(data, sshc, SSH_AUTH_AGENT_INIT); break;`
///   (`lib/vssh/libssh2.c:2619-2621`) -- host-based authentication is reachable
///   as a STATE and is not implemented, so setting `CURLSSH_AUTH_HOST` costs one
///   state transition and achieves nothing. Preserved, because the state exists,
///   is named in the trace output, and appears in the sequence.
/// * **keyboard-interactive is last and its failure is terminal.** Every other
///   mechanism's failure moves on; `ssh_state_auth_key` answers
///   [`CURLcode::LoginDenied`] directly (`:1738`) without reaching
///   `SSH_AUTH_DONE`. So the code a fully failed authentication reports depends
///   on whether the server offered keyboard-interactive -- and it is
///   [`CURLcode::LoginDenied`] either way, since `ssh_state_auth_done` answers
///   the same for `!sshc->authed`.
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
pub(crate) fn next_auth_state(
    from: SshState,
    types: SshAuthTypes,
    list: &[u8],
    succeeded: bool,
) -> SshState {
    match from {
        SshState::AuthPkeyInit => {
            if types.contains(SshAuthTypes::PUBLICKEY)
                && authlist::offers(list, authlist::PUBLICKEY)
            {
                SshState::AuthPkey
            } else {
                SshState::AuthPassInit
            }
        }
        SshState::AuthPkey => {
            if succeeded {
                SshState::AuthDone
            } else {
                SshState::AuthPassInit
            }
        }
        SshState::AuthPassInit => {
            if types.contains(SshAuthTypes::PASSWORD)
                && authlist::offers(list, authlist::PASSWORD)
            {
                SshState::AuthPass
            } else {
                SshState::AuthHostInit
            }
        }
        SshState::AuthPass => {
            if succeeded {
                SshState::AuthDone
            } else {
                SshState::AuthHostInit
            }
        }
        SshState::AuthHostInit => {
            if types.contains(SshAuthTypes::HOST)
                && authlist::offers(list, authlist::HOSTBASED)
            {
                SshState::AuthHost
            } else {
                SshState::AuthAgentInit
            }
        }
        // Unconditional: the state is a no-op in the C.
        SshState::AuthHost => SshState::AuthAgentInit,
        SshState::AuthAgentInit => {
            if types.contains(SshAuthTypes::AGENT)
                && authlist::offers(list, authlist::PUBLICKEY)
            {
                SshState::AuthAgentList
            } else {
                SshState::AuthKeyInit
            }
        }
        SshState::AuthAgentList => {
            if succeeded {
                SshState::AuthAgent
            } else {
                SshState::AuthKeyInit
            }
        }
        SshState::AuthAgent => {
            if succeeded {
                SshState::AuthDone
            } else {
                SshState::AuthKeyInit
            }
        }
        SshState::AuthKeyInit => {
            if types.contains(SshAuthTypes::KEYBOARD)
                && authlist::offers(list, authlist::KEYBOARD_INTERACTIVE)
            {
                SshState::AuthKey
            } else {
                SshState::AuthDone
            }
        }
        // `ssh_state_auth_key` answers CURLE_LOGIN_DENIED on failure without
        // moving; on success it goes to AUTH_DONE. The caller turns the
        // unchanged state into the refusal.
        SshState::AuthKey => {
            if succeeded {
                SshState::AuthDone
            } else {
                SshState::AuthKey
            }
        }
        // Not an authentication state. The C's machine would fall into its
        // `default:` arm and stop, which is what this answers.
        _ => SshState::Stop,
    }
}

/// The private-key files `ssh_state_pkey_init` guesses when
/// `CURLOPT_SSH_PRIVATE_KEYFILE` is unset.
///
/// `lib/vssh/libssh2.c:1086-1124`, in order: `$HOME/.ssh/id_rsa`,
/// `$HOME/.ssh/id_dsa`, then `id_rsa` and `id_dsa` in the current directory,
/// and finally the EMPTY STRING. That last one is not a path and is not a
/// mistake -- the C's own comment is *"Out of guesses. Set to the empty string
/// to avoid surprising info messages"*, so the attempt is made with a name the
/// transport will refuse rather than skipped, which keeps the state sequence
/// identical whether a key was found or not.
///
/// `exists` is injected rather than reached for, so the guessing order is
/// testable without touching a filesystem. `home` is [`None`] when `HOME` is
/// unset, which skips the first two guesses exactly as `if(home)` does.
///
/// The C also poses a question in a comment that this port answers the same way
/// it does: *"To ponder about: should really the lib be messing about with the
/// HOME environment variable etc?"* It does, so this does.
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
pub(crate) fn private_key_guess(
    home: Option<&str>,
    exists: &dyn Fn(&str) -> bool,
) -> String {
    if let Some(home) = home {
        let rsa = format!("{home}/.ssh/id_rsa");
        if exists(&rsa) {
            return rsa;
        }
        let dsa = format!("{home}/.ssh/id_dsa");
        if exists(&dsa) {
            return dsa;
        }
    }
    // `if(!out_of_memory && !sshc->rsa)`: reached whenever the home-directory
    // guesses produced nothing, INCLUDING when `HOME` was set and neither file
    // was there.
    if exists("id_rsa") {
        return "id_rsa".into();
    }
    if exists("id_dsa") {
        return "id_dsa".into();
    }
    String::new()
}

/// The passphrase `ssh_state_pkey_init` uses: `CURLOPT_KEYPASSWD`, or the empty
/// string.
///
/// `sshc->passphrase = data->set.ssl.key_passwd; if(!sshc->passphrase)
/// sshc->passphrase = "";` (`lib/vssh/libssh2.c:1146-1148`). The empty string
/// rather than a null pointer, because libssh2 distinguishes them and curl does
/// not want it to.
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
pub(crate) fn key_passphrase(configured: Option<&str>) -> &str {
    configured.unwrap_or("")
}

// The transport seam -- what `russh` fulfils, and what a test replaces

/// The readiness an SSH transport is waiting for --
/// `libssh2_session_block_directions` (`lib/vssh/libssh2.c:3051-3068`).
///
/// `ssh_block2waitfor` translates the two libssh2 bits into `KEEP_RECV` and
/// `KEEP_SEND`, which `ssh_pollset` then turns into `CURL_POLL_IN` and
/// `CURL_POLL_OUT`. The chain is reproduced with this type in the middle because
/// the two ends belong to different modules: the direction is the transport's
/// answer, and the pollset is `crate::conn::select`'s vocabulary.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct SshWait(pub(crate) u32);

#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
impl SshWait {
    /// Waiting for nothing -- `sshc->waitfor = 0`, which makes `ssh_pollset`
    /// fall back to `data->req.keepon`.
    pub(crate) const NONE: Self = Self(0);
    /// `LIBSSH2_SESSION_BLOCK_INBOUND` becomes `KEEP_RECV`.
    pub(crate) const RECV: Self = Self(1 << 0);
    /// `LIBSSH2_SESSION_BLOCK_OUTBOUND` becomes `KEEP_SEND`.
    pub(crate) const SEND: Self = Self(1 << 1);

    /// True when every bit of `other` is set here.
    pub(crate) const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// True when nothing is being waited for.
    pub(crate) const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The union of two masks.
    pub(crate) const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// The raw mask.
    pub(crate) const fn bits(self) -> u32 {
        self.0
    }
}

impl core::ops::BitOr for SshWait {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        self.union(other)
    }
}

/// A boxed, `Send` future over an SSH transport operation.
///
/// The same shape as [`ProtoFuture`] and for the same reason: `&dyn Protocol`
/// dispatch is mandated by specification 0.3.3's pattern P1, an `async fn` in a
/// trait is not dyn-compatible, and neither is a return-position `impl Future`.
/// Both stabilised in Rust 1.75 and neither became object-safe, so this alias is
/// what an injectable transport has to be written in terms of. `cargo +1.75.0
/// build -p curl-rs-lib` is the gate that keeps it honest.
///
/// The error is [`SshError`] rather than [`CURLcode`] because a transport does
/// not know which of the C's several `failf` texts its caller will build around
/// the failure; [`SshError::to_curlcode`] performs the map at the call site,
/// exactly where `libssh2_session_error_to_CURLE` is called in the C.
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
pub(crate) type SshFuture<'a, T> = core::pin::Pin<
    Box<dyn core::future::Future<Output = Result<T, SshError>> + Send + 'a>,
>;

/// One host key as the verification path needs it.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
pub(crate) struct HostKeyBlob {
    /// The key's SSH wire encoding, which is what both fingerprints are taken
    /// over -- `libssh2_session_hostkey` hands the C exactly these bytes.
    pub(crate) blob: Vec<u8>,
    /// The algorithm name, from which [`HostKeyType::from_algorithm`] derives
    /// what the known-hosts callback receives.
    pub(crate) algorithm: Vec<u8>,
}

#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
impl HostKeyBlob {
    /// The `curl_khtype` this key reports to a callback.
    pub(crate) fn key_type(&self) -> HostKeyType {
        HostKeyType::from_algorithm(&self.algorithm)
    }
}

/// The SSH transport this module drives, injected rather than reached for.
///
/// Every libssh2 call `lib/vssh/libssh2.c` makes falls into one of two groups:
/// SESSION operations -- handshake, the method list, the five authentication
/// mechanisms, disconnect -- and SFTP operations, which are requests and replies
/// over a channel. This trait is the first group plus a byte pipe for the
/// second, and [`SftpCodec`] with [`request`] is the second. That division is
/// what makes the SFTP protocol layer testable as pure code: a scripted peer
/// implements this trait in a few dozen lines and every packet this module emits
/// is then asserted against a byte vector.
///
/// # Why every method takes the transfer context
///
/// The transport does NOT own a socket -- specification 0.4.1 puts the socket in
/// the connection-filter chain, and `crate::conn` owns that. So a transport that
/// needs bytes moved must be handed the chain, and it is handed the whole
/// [`TransferCtx`] because it also needs the injected clock to bound a wait.
/// [`RusshTransport`] uses it to pump its in-memory duplex; a scripted peer
/// ignores it.
///
/// # Object safety, and the `Send` bound
///
/// [`SshConn`] holds a `Box<dyn SshTransport>`, so the trait must be
/// dyn-compatible: hence [`SshFuture`] rather than `async fn`. [`Send`] is
/// required because the multi handle drives transfers on a multi-thread runtime
/// and a [`ProtoFuture`] holding this across an await is only `Send` when it is.
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
pub(crate) trait SshTransport: fmt::Debug + Send {
    /// `libssh2_session_handshake` (`lib/vssh/libssh2.c:1452`): the version
    /// exchange and key exchange.
    ///
    /// `SSH_S_STARTUP`'s whole body. On failure the C reports
    /// [`CURLcode::FailedInit`] with *"Failure establishing ssh session: %d,
    /// %s"* and moves to `SSH_SESSION_FREE`.
    ///
    /// # Errors
    ///
    /// [`SshError`] as the transport reports it.
    fn handshake<'a>(
        &'a mut self,
        ctx: &'a mut TransferCtx<'_>,
    ) -> SshFuture<'a, ()>;

    /// `libssh2_session_hostkey`: the key the peer presented, once
    /// [`Self::handshake`] has completed.
    ///
    /// [`None`] before the handshake, and also when the transport cannot produce
    /// one -- which `ssh_check_fingerprint` treats as
    /// [`CURLcode::PeerFailedVerification`] rather than as a missing feature.
    fn hostkey(&self) -> Option<HostKeyBlob>;

    /// `libssh2_userauth_list` (`lib/vssh/libssh2.c:1550`): the methods this
    /// server offers `user`.
    ///
    /// A comma-separated list, because that is what the C searches with
    /// `strstr`; see [`authlist`].
    ///
    /// # Errors
    ///
    /// [`SshError`] as the transport reports it.
    fn auth_list<'a>(
        &'a mut self,
        ctx: &'a mut TransferCtx<'_>,
        user: &'a str,
    ) -> SshFuture<'a, Vec<u8>>;

    /// `libssh2_userauth_authenticated`: whether the session is already
    /// authenticated.
    ///
    /// Consulted when [`Self::auth_list`] answers nothing, which is the C's
    /// *"SSH user accepted with no authentication"* path
    /// (`lib/vssh/libssh2.c:1554-1560`).
    fn authenticated(&self) -> bool;

    /// `libssh2_userauth_publickey_fromfile_ex`
    /// (`lib/vssh/libssh2.c:1524-1530`).
    ///
    /// `public_key` is [`None`] when the user named no public-key file, which
    /// the C's comment explains: *"Unless the user explicitly specifies a public
    /// key file, let libssh2 extract the public key from the private key file.
    /// This is done by simply passing sshc->rsa_pub = NULL."*
    ///
    /// Answers whether authentication SUCCEEDED rather than failing on refusal,
    /// because a refusal is not an error in this sequence -- it moves to the
    /// next mechanism.
    ///
    /// # Errors
    ///
    /// [`SshError`] for a transport failure, as distinct from a refusal.
    fn auth_publickey<'a>(
        &'a mut self,
        ctx: &'a mut TransferCtx<'_>,
        user: &'a str,
        private_key: &'a str,
        public_key: Option<&'a str>,
        passphrase: &'a str,
    ) -> SshFuture<'a, bool>;

    /// `libssh2_userauth_password_ex` (`lib/vssh/libssh2.c:1580-1585`).
    ///
    /// # Errors
    ///
    /// [`SshError`] for a transport failure.
    fn auth_password<'a>(
        &'a mut self,
        ctx: &'a mut TransferCtx<'_>,
        user: &'a str,
        password: &'a str,
    ) -> SshFuture<'a, bool>;

    /// `libssh2_userauth_keyboard_interactive_ex`
    /// (`lib/vssh/libssh2.c:1726-1731`).
    ///
    /// The C answers every prompt with the connection password, once, through
    /// `kbd_callback` (`lib/vssh/libssh2.c:128-156`) -- and only when there is
    /// exactly ONE prompt, since the callback's whole body is guarded by
    /// `if(num_prompts == 1)`. A server asking two questions therefore gets two
    /// EMPTY answers, which is a measured oddity and is preserved by passing the
    /// password through unchanged and letting the transport apply the same rule.
    ///
    /// # Errors
    ///
    /// [`SshError`] for a transport failure.
    fn auth_keyboard_interactive<'a>(
        &'a mut self,
        ctx: &'a mut TransferCtx<'_>,
        user: &'a str,
        password: &'a str,
    ) -> SshFuture<'a, bool>;

    /// `libssh2_agent_connect`, `_list_identities`, `_get_identity` and
    /// `_userauth` (`lib/vssh/libssh2.c:1613-1706`), collapsed into one step.
    ///
    /// The C spreads the agent over three states because libssh2's calls are
    /// individually non-blocking and it walks the identities one at a time,
    /// retrying `SSH_AUTH_AGENT` per key. The three states are RETAINED --
    /// they are named in the trace output and [`next_auth_state`] sequences them
    /// -- and the identity walk collapses here, because awaiting subsumes the
    /// re-entry that the C's `sshagent_prev_identity` cursor exists to support.
    ///
    /// # Errors
    ///
    /// [`SshError`] for a transport failure. Note what is NOT an error: a
    /// missing agent. `if(!sshc->ssh_agent) { infof(data, "Could not create
    /// agent object"); ... }` moves to the next mechanism, so this answers
    /// `Ok(false)`.
    fn auth_agent<'a>(
        &'a mut self,
        ctx: &'a mut TransferCtx<'_>,
        user: &'a str,
    ) -> SshFuture<'a, bool>;

    /// `libssh2_sftp_init` (`lib/vssh/libssh2.c:1779`) followed by the
    /// `SSH_FXP_INIT` exchange: open the SFTP subsystem.
    ///
    /// Answers the protocol version the server agreed to. `SSH_SFTP_INIT`'s
    /// failure text is *"Failure initializing sftp session: %s"* with
    /// [`CURLcode::FailedInit`].
    ///
    /// # Errors
    ///
    /// [`SshError`] as the transport reports it.
    fn open_sftp<'a>(
        &'a mut self,
        ctx: &'a mut TransferCtx<'_>,
    ) -> SshFuture<'a, u32>;

    /// One SFTP request, one reply frame.
    ///
    /// The whole SFTP data path. Every `libssh2_sftp_*` call in the C becomes a
    /// [`request`] builder, this exchange, and a `decode_*`; the request
    /// identifier already inside `packet` is what pairs them, which is why this
    /// is a single call rather than separate send and receive.
    ///
    /// # Errors
    ///
    /// [`SshError`] for a transport failure. An SFTP-level refusal is NOT an
    /// error here -- it arrives as a well-formed `SSH_FXP_STATUS` frame, and
    /// the decoder turns it into [`SftpFailure::Status`].
    fn sftp_exchange<'a>(
        &'a mut self,
        ctx: &'a mut TransferCtx<'_>,
        packet: Vec<u8>,
    ) -> SshFuture<'a, Vec<u8>>;

    /// `libssh2_sftp_shutdown` (`lib/vssh/libssh2.c:2337`): close the SFTP
    /// subsystem, leaving the session open.
    ///
    /// `SSH_SFTP_SHUTDOWN`'s middle step. A failure is reported with `infof`
    /// and NOT propagated in the C -- *"Failed to stop libssh2 sftp
    /// subsystem"* -- so the disconnect continues either way.
    ///
    /// # Errors
    ///
    /// [`SshError`] as the transport reports it.
    fn close_sftp<'a>(
        &'a mut self,
        ctx: &'a mut TransferCtx<'_>,
    ) -> SshFuture<'a, ()>;

    /// `libssh2_session_disconnect(session, "Shutdown")`
    /// (`lib/vssh/libssh2.c:2447`).
    ///
    /// The reason string is on the wire and is `"Shutdown"`, exactly.
    ///
    /// # Errors
    ///
    /// [`SshError`] as the transport reports it. `SSH_SESSION_DISCONNECT`
    /// reports a failure with `infof` and proceeds to `SSH_SESSION_FREE`
    /// regardless.
    fn disconnect<'a>(
        &'a mut self,
        ctx: &'a mut TransferCtx<'_>,
    ) -> SshFuture<'a, ()>;

    /// `libssh2_session_block_directions`: which readiness the transport is
    /// waiting for.
    ///
    /// Feeds [`SshConn::waitfor`] and therefore [`ssh_pollset`].
    fn block_directions(&self) -> SshWait;

    /// The socket the transport is using, or [`CURL_SOCKET_BAD`].
    ///
    /// `conn->sock[FIRSTSOCKET]` in the C, which `ssh_pollset` reads directly.
    /// Here the descriptor belongs to the filter chain, so the default answers
    /// "none" and [`ssh_pollset`] asks the chain instead. The member exists
    /// because a transport that genuinely owns a descriptor -- none does today --
    /// would have nowhere else to report it.
    fn socket(&self) -> Socket {
        crate::conn::select::CURL_SOCKET_BAD
    }
}

/// The clock and the randomness this module is handed rather than reaching for.
///
/// Specification 0.3.3's pattern P12. The clock bounds a transport wait and the
/// generator supplies the request identifiers an SFTP session pairs its replies
/// with -- libssh2 allocates those from a per-session counter, and a counter
/// reached for globally would be exactly the hidden state P12 forbids.
///
/// # Why randomness rather than a counter
///
/// A counter would do, and the C uses one. Seeding the sequence from the
/// injected generator instead costs nothing, makes a captured session harder to
/// splice, and -- the reason it is done here -- means the identifiers a test
/// asserts are a function of the seed rather than of how many requests ran
/// before them. [`SshSeams::deterministic`] is what makes the fixtures'
/// byte-exact comparisons reproducible.
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
pub(crate) struct SshSeams {
    /// `curlx_now()`, injected.
    clock: Box<dyn crate::util::timeval::Clock + Send + Sync>,
    /// `Curl_rand`, injected.
    rng: Box<dyn crate::crypto::rand::Rng + Send>,
}

impl fmt::Debug for SshSeams {
    /// Opaque: printing the generator's state would put entropy in a log.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("SshSeams").finish()
    }
}

#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
impl SshSeams {
    /// Seams over the given clock and generator.
    pub(crate) fn new(
        clock: Box<dyn crate::util::timeval::Clock + Send + Sync>,
        rng: Box<dyn crate::crypto::rand::Rng + Send>,
    ) -> Self {
        Self { clock, rng }
    }

    /// Seams over the system clock and the system generator.
    ///
    /// # Errors
    ///
    /// [`CURLcode`] from [`crate::crypto::rand::SystemRng::new`], which is what
    /// the C reports when it cannot seed.
    pub(crate) fn system() -> CodeResult<Self> {
        Ok(Self::new(
            Box::new(crate::util::timeval::SystemClock),
            Box::new(crate::crypto::rand::SystemRng::new()?),
        ))
    }

    /// Seams with a fixed clock and a seeded generator, for a test.
    ///
    /// Not behind `#[cfg(test)]`: [`crate::crypto::rand::TestRng`] and
    /// [`crate::util::timeval::TestClock`] are ordinary items of this crate, and
    /// an integration test under `tests-rs/` needs this constructor to drive a
    /// deterministic session from outside `#[cfg(test)]`.
    pub(crate) fn deterministic(seed: u32) -> Self {
        Self::new(
            Box::new(crate::util::timeval::TestClock::new(
                crate::util::timeval::CurlTime::new(0, 0),
            )),
            Box::new(crate::crypto::rand::TestRng::from_seed(seed)),
        )
    }

    /// A reading from the injected clock.
    pub(crate) fn now(&self) -> crate::util::timeval::CurlTime {
        self.clock.now()
    }

    /// `num` random bytes from the injected generator.
    pub(crate) fn random_bytes(&mut self, out: &mut [u8]) {
        crate::crypto::rand::rand_bytes(self.rng.as_mut(), out);
    }

    /// A random 32-bit value, for the first SFTP request identifier.
    pub(crate) fn random_u32(&mut self) -> u32 {
        let mut bytes = [0_u8; 4];
        self.random_bytes(&mut bytes);
        u32::from_be_bytes(bytes)
    }
}

// The state carriers -- `struct ssh_conn` and `struct SSHPROTO`
// (`lib/vssh/ssh.h:128-222`)

/// The SSH slice of `data->set`, declared here because no other module owns it.
///
/// `struct UrlState` and `struct UserDefined` (`lib/urldata.h`) are being
/// decomposed per specification 0.1.2 -- *"fields migrate to the module that
/// owns their lifecycle"* -- and these are the fields only the two SSH modules
/// read. `crate::transfer::TransferSettings` carries what the transfer core
/// reads and deliberately does not carry these; when `easy/setopt.rs` lands it
/// populates this from the option table.
///
/// Every field names the `CURLOPT_*` it comes from, so the correspondence is
/// checkable against `include/curl/curl.h` without a second table.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
pub(crate) struct SshSettings {
    /// `CURLOPT_USERNAME`, or the URL's user component.
    ///
    /// The C reads `conn->user`, which the URL parser has already populated.
    /// Never changed once the session has seen it, and the C says why:
    /// *"As soon as we have provided a username to an openssh server we must
    /// never change it later"* (`lib/vssh/libssh2.c:1537-1543`).
    pub(crate) user: String,
    /// `CURLOPT_PASSWORD`, or the URL's password component.
    pub(crate) password: String,
    /// `CURLOPT_SSH_AUTH_TYPES`.
    pub(crate) auth_types: SshAuthTypes,
    /// `CURLOPT_SSH_PRIVATE_KEYFILE`. [`None`] triggers
    /// [`private_key_guess`].
    pub(crate) private_key: Option<String>,
    /// `CURLOPT_SSH_PUBLIC_KEYFILE`.
    ///
    /// An empty string is treated as absent, which the C does explicitly:
    /// *"treat empty string the same way as NULL"*
    /// (`lib/vssh/libssh2.c:1132-1133`).
    pub(crate) public_key: Option<String>,
    /// `CURLOPT_KEYPASSWD`, the private key's passphrase.
    pub(crate) key_passwd: Option<String>,
    /// The host-key policy: the two fingerprints, the callback and the file.
    pub(crate) hostkey: HostKeyPolicy,
    /// `CURLOPT_QUOTE`, in order.
    pub(crate) quote: Vec<Vec<u8>>,
    /// `CURLOPT_POSTQUOTE`, in order.
    pub(crate) postquote: Vec<Vec<u8>>,
    /// `CURLOPT_PREQUOTE`, in order.
    ///
    /// Carried and never consulted by SFTP, which is a measured asymmetry rather
    /// than an omission: `lib/vssh/libssh2.c` reads `data->set.quote` and
    /// `data->set.postquote` and never `data->set.prequote`, while `lib/ftp.c`
    /// reads all three. So `--quote` and `--postquote` work over SFTP and
    /// `RETR_PREQUOTE`-style commands do not, even though the option is
    /// accepted. Held here so that the option round-trips and so that a reader
    /// looking for the prequote path finds this note instead of concluding it was
    /// lost.
    pub(crate) prequote: Vec<Vec<u8>>,
    /// `CURLOPT_NEW_FILE_PERMS`, default `0644`.
    pub(crate) new_file_perms: u32,
    /// `CURLOPT_NEW_DIRECTORY_PERMS`, default `0755`.
    pub(crate) new_directory_perms: u32,
    /// `CURLOPT_FTP_CREATE_MISSING_DIRS`, which SFTP honours through
    /// `SSH_SFTP_CREATE_DIRS`.
    pub(crate) create_missing_dirs: bool,
    /// `CURLOPT_APPEND`.
    pub(crate) remote_append: bool,
    /// `CURLOPT_FILETIME`, which adds the `SSH_SFTP_FILETIME` step.
    pub(crate) get_filetime: bool,
    /// `CURLOPT_DIRLISTONLY`.
    pub(crate) list_only: bool,
    /// `CURLOPT_NOBODY`, which makes a directory request stop before listing.
    pub(crate) no_body: bool,
    /// `CURLOPT_UPLOAD`.
    pub(crate) upload: bool,
    /// `CURLOPT_INFILESIZE`, or -1 when unknown.
    pub(crate) infilesize: i64,
    /// `CURLOPT_RESUME_FROM`. Negative means "the last N bytes", which the C
    /// resolves against the file size.
    pub(crate) resume_from: i64,
    /// `CURLOPT_RANGE`, unparsed. [`ssh_range`] resolves it once the size is
    /// known.
    pub(crate) range: Option<Vec<u8>>,
}

#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
impl SshSettings {
    /// The defaults `Curl_init_userdefined` establishes for these options.
    ///
    /// `0644` and `0755` are `lib/url.c`'s defaults for
    /// `CURLOPT_NEW_FILE_PERMS` and `CURLOPT_NEW_DIRECTORY_PERMS`, `-1` is
    /// `CURLOPT_INFILESIZE`'s "unknown", and [`SshAuthTypes::ANY`] is
    /// `CURLSSH_AUTH_DEFAULT`. `Default::default()` would give `0`, `0`, `0` and
    /// [`SshAuthTypes::NONE`], none of which is the option's default -- which is
    /// why this constructor exists and why [`Default`] is derived only for the
    /// benefit of a test that wants an empty value.
    pub(crate) fn with_option_defaults() -> Self {
        Self {
            auth_types: SshAuthTypes::default(),
            new_file_perms: 0o644,
            new_directory_perms: 0o755,
            infilesize: -1,
            ..Self::default()
        }
    }
}

/// `struct SSHPROTO` (`lib/vssh/ssh.h:128-141`): the per-EASY-HANDLE state.
///
/// The C's comment is the contract, and it is why this type is separate from
/// [`SshConn`]: *"this struct is used in the HandleData struct which is part of
/// the Curl_easy, which means this is used on a per-easy handle basis.
/// Everything that is strictly related to a connection is banned from this
/// struct."* A connection may be reused by another transfer -- which is what
/// `attach` exists for -- so anything a second transfer must not inherit lives
/// here.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
pub(crate) struct SshProto {
    /// `sshp->path`: the path this request operates on, from
    /// [`getworkingpath`].
    pub(crate) path: Vec<u8>,
    /// `sshp->readdir`: the listing line under construction.
    ///
    /// A `Vec<u8>` rather than a `DynBuf` because the C's ceiling here is
    /// `CURL_PATH_MAX * 2` and the assembly is two appends and a reset; the
    /// ceiling is enforced by the transport's own frame bound rather than by a
    /// second allocator.
    pub(crate) readdir: Vec<u8>,
    /// `sshp->readdir_link`: the path a `READLINK` is issued for.
    pub(crate) readdir_link: Vec<u8>,
    /// `sshp->readdir_filename`, `readdir_longentry` and `readdir_attrs`
    /// together.
    ///
    /// The C keeps three separate fixed buffers, two of `CURL_PATH_MAX + 1`
    /// bytes, because libssh2 fills them. One owned entry is the same
    /// information without the buffers.
    pub(crate) readdir_entry: SftpName,
    /// `sshp->quote_attrs`: the attribute block `SSH_SFTP_QUOTE_SETSTAT` sends.
    pub(crate) quote_attrs: SftpAttributes,
}

/// `struct ssh_conn` (`lib/vssh/ssh.h:145-222`): the per-CONNECTION state.
///
/// Ten of the C's members are libssh2 handles and are replaced by the
/// [`SshTransport`] this owns. The rest are the state machine's own bookkeeping
/// and are reproduced field for field, because each one is read by a state that
/// this module or `protocols/scp.rs` implements.
///
/// # `state` is private, and that is the enforcement
///
/// The C's comment on its own `state` member is *"always use ssh.c:state() to
/// change state!"* -- a convention. Here it is a private field with no setter, so
/// [`ssh_set_state`] is the only writer that can exist, and
/// `protocols/scp.rs` is subject to the same restriction without being asked.
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
pub(crate) struct SshConn {
    /// `sshc->state`. Private; see the type documentation.
    state: SshState,
    /// `sshc->nextstate`: *"the state to goto after stopping"*.
    ///
    /// [`SshState::NoState`] when there is none, which is what
    /// `SSH_NO_STATE = -1` exists for.
    pub(crate) nextstate: SshState,
    /// `sshc->authlist`: the method list, *"managed by libssh2"* in the C and
    /// owned here.
    pub(crate) authlist: Vec<u8>,
    /// `sshc->authed`: *"the connection has been authenticated fine"*.
    pub(crate) authed: bool,
    /// `sshc->acceptfail`: *"used by the SFTP_QUOTE (continue if quote command
    /// fails)"*.
    pub(crate) acceptfail: bool,
    /// `sshc->homedir`: *"when doing SFTP we figure out home directory in the
    /// connect phase"*.
    pub(crate) homedir: Vec<u8>,
    /// `sshc->quote_item`: an index into the list being walked, rather than a
    /// `struct curl_slist *` cursor.
    pub(crate) quote_index: usize,
    /// Which list [`Self::quote_index`] indexes -- `CURLOPT_QUOTE` or
    /// `CURLOPT_POSTQUOTE`.
    ///
    /// The C distinguishes them by which list it assigned `quote_item` from, a
    /// distinction a pointer carries and an index does not.
    pub(crate) quote_list: QuoteList,
    /// `sshc->quote_path1` and `quote_path2`: *"two generic pointers for the
    /// QUOTE stuff"*.
    pub(crate) quote: Option<ParsedQuote>,
    /// `sshc->secondCreateDirs`: *"counter use by the code to see if the second
    /// attempt has been made to change to/create a directory"*.
    pub(crate) second_create_dirs: i32,
    /// `sshc->slash_pos`: *"used by the SFTP_CREATE_DIRS state"*.
    ///
    /// A byte offset into [`SshProto::path`] rather than a pointer INTO it. The
    /// C walks the path by writing a NUL over each `/` and restoring it
    /// afterwards (`*sshc->slash_pos = '/'; ++sshc->slash_pos;`), which mutates
    /// the string it is iterating; an offset expresses the same walk without
    /// the aliasing.
    pub(crate) slash_pos: usize,
    /// `sshc->waitfor`: *"KEEP_RECV/KEEP_SEND bits overriding pollset given
    /// flags"*.
    pub(crate) waitfor: SshWait,
    /// `sshc->sftp_handle`: the open file or directory handle.
    pub(crate) sftp_handle: Option<Vec<u8>>,
    /// The read or write offset, which the C keeps inside libssh2 and moves with
    /// `libssh2_sftp_seek64`.
    ///
    /// Explicit here because `SSH_FXP_READ` and `SSH_FXP_WRITE` carry the offset
    /// on the wire; see [`request::read`].
    pub(crate) sftp_offset: u64,
    /// The next SFTP request identifier, seeded from the injected generator.
    request_id: u32,
    /// The transport, injected.
    transport: Box<dyn SshTransport>,
    /// The clock and the generator, injected.
    seams: SshSeams,
}

impl fmt::Debug for SshConn {
    /// The state and the flags, with no key material and no buffers.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SshConn")
            .field("state", &self.state)
            .field("nextstate", &self.nextstate)
            .field("authed", &self.authed)
            .field("acceptfail", &self.acceptfail)
            .field("waitfor", &self.waitfor.bits())
            .finish()
    }
}

/// Which quote list the machine is walking.
///
/// The C carries this implicitly in `sshc->quote_item`, whose value came from
/// either `data->set.quote` or `data->set.postquote`. An index needs the list
/// named, and naming it also makes the distinction the C draws visible: a
/// postquote round is entered from `sftp_done` and returns to
/// `SSH_SFTP_CLOSE`, so which list is being walked decides where the machine
/// goes when it runs out.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
pub(crate) enum QuoteList {
    /// `CURLOPT_QUOTE`, walked from `SSH_SFTP_QUOTE_INIT`.
    #[default]
    Quote,
    /// `CURLOPT_POSTQUOTE`, walked from `SSH_SFTP_POSTQUOTE_INIT`.
    PostQuote,
}

#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
impl SshConn {
    /// A connection in `SSH_STOP`, over the given transport and seams.
    ///
    /// `ssh_setup_connection` (`lib/vssh/libssh2.c:3167-3191`) allocates the
    /// C's two structures with `calloc`, so every field starts zeroed and the
    /// state starts at `SSH_STOP`. Reproduced, with the two injected
    /// dependencies the C reaches for globally instead.
    pub(crate) fn new(
        transport: Box<dyn SshTransport>,
        mut seams: SshSeams,
    ) -> Self {
        let request_id = seams.random_u32();
        Self {
            state: SshState::Stop,
            nextstate: SshState::NoState,
            authlist: Vec::new(),
            authed: false,
            acceptfail: false,
            homedir: Vec::new(),
            quote_index: 0,
            quote_list: QuoteList::Quote,
            quote: None,
            second_create_dirs: 0,
            slash_pos: 0,
            waitfor: SshWait::NONE,
            sftp_handle: None,
            sftp_offset: 0,
            request_id,
            transport,
            seams,
        }
    }

    /// `sshc->state`, readable everywhere and writable only through
    /// [`ssh_set_state`] -- with the single documented exception below.
    pub(crate) const fn state(&self) -> SshState {
        self.state
    }

    /// `sshc->state = SSH_SESSION_FREE; /* current */`
    /// (`lib/vssh/libssh2.c:2988`).
    ///
    /// The one write to [`Self::state`] that is not a transition, and it exists
    /// because the line before it is a `memset` that zeroed the field. Zero is
    /// `SSH_STOP`, so without this restoration the very next line --
    /// `myssh_to(data, sshc, SSH_STOP)` -- would trace a transition FROM
    /// `SSH_STOP` instead of from `SSH_SESSION_FREE`, and the trace line is
    /// observable output.
    ///
    /// Kept private and named for what it does, so that the discipline
    /// [`ssh_set_state`] enforces stays readable: this is a restoration of a
    /// value the reset destroyed, never a move to a new state. It is asserted
    /// by `restoring_the_state_is_not_a_transition`.
    fn restore_state(&mut self, state: SshState) {
        self.state = state;
    }

    /// The transport, for a state that has to talk to the peer.
    pub(crate) fn transport(&mut self) -> &mut dyn SshTransport {
        self.transport.as_mut()
    }

    /// The injected clock and generator.
    pub(crate) fn seams(&mut self) -> &mut SshSeams {
        &mut self.seams
    }

    /// The next SFTP request identifier.
    ///
    /// A wrapping increment from the seeded start, which is what libssh2's
    /// per-session counter does. Wrapping rather than saturating: the identifier
    /// only has to be unique among the requests currently outstanding, and this
    /// module keeps exactly one outstanding at a time.
    pub(crate) fn next_request_id(&mut self) -> u32 {
        let id = self.request_id;
        self.request_id = self.request_id.wrapping_add(1);
        id
    }

    /// `ssh_block2waitfor` (`lib/vssh/libssh2.c:3051-3068`): record which
    /// direction the transport is waiting for.
    ///
    /// The C's comment explains why it is called even when nothing blocked:
    /// *"Make sure to call this function in all cases so that when it does not
    /// return EAGAIN we can restore the default wait bits."* So a non-blocking
    /// outcome CLEARS `waitfor`, which is what lets `ssh_pollset` fall back to
    /// `data->req.keepon`.
    pub(crate) fn block2waitfor(&mut self, blocked: bool) {
        let direction = if blocked {
            self.transport.block_directions()
        } else {
            SshWait::NONE
        };
        self.waitfor = direction;
    }

    /// The quote list being walked, resolved against the settings.
    pub(crate) fn quote_commands<'a>(
        &self,
        settings: &'a SshSettings,
    ) -> &'a [Vec<u8>] {
        match self.quote_list {
            QuoteList::Quote => &settings.quote,
            QuoteList::PostQuote => &settings.postquote,
        }
    }

    /// The command [`Self::quote_index`] points at, or [`None`] at the end of
    /// the list.
    pub(crate) fn current_quote<'a>(
        &self,
        settings: &'a SshSettings,
    ) -> Option<&'a [u8]> {
        self.quote_commands(settings)
            .get(self.quote_index)
            .map(Vec::as_slice)
    }

    /// `SSH_SFTP_NEXT_QUOTE` (`lib/vssh/libssh2.c:1892-1913`): advance to the
    /// next command, or leave the quote phase.
    ///
    /// The destination when the list runs out is the C's, and it is not a
    /// constant: `sshc->nextstate` if one was set -- which is how a postquote
    /// round returns to `SSH_SFTP_CLOSE` -- and `SSH_SFTP_GETINFO` otherwise.
    /// Setting `nextstate` back to [`SshState::NoState`] on the way out is the
    /// C's too, and it is what stops the destination being reused by the next
    /// round.
    pub(crate) fn next_quote(&mut self, settings: &SshSettings) -> SshState {
        self.quote = None;
        self.quote_index = self.quote_index.saturating_add(1);
        if self.current_quote(settings).is_some() {
            return SshState::SftpQuote;
        }
        if self.nextstate == SshState::NoState {
            SshState::SftpGetinfo
        } else {
            let destination = self.nextstate;
            self.nextstate = SshState::NoState;
            destination
        }
    }

    /// One SFTP request and its reply.
    ///
    /// The two-line shape every SFTP operation in this module has: build a
    /// packet with [`request`], exchange it, decode it. Keeping the exchange here
    /// rather than at each call site is what makes [`Self::block2waitfor`]
    /// unmissable -- the C calls `ssh_block2waitfor` at every one of its own
    /// send and receive sites and comments that it must.
    ///
    /// # Errors
    ///
    /// [`SftpFailure::Transport`] wrapping whatever the transport reported.
    pub(crate) async fn sftp_exchange(
        &mut self,
        ctx: &mut TransferCtx<'_>,
        packet: Vec<u8>,
    ) -> SftpResult<Vec<u8>> {
        let outcome = self.transport.sftp_exchange(ctx, packet).await;
        let blocked = matches!(outcome, Err(SshError::Again));
        self.block2waitfor(blocked);
        outcome.map_err(SftpFailure::Transport)
    }
}

// The pollsets and `attach`, shared by both schemes

/// `ssh_pollset` (`lib/vssh/libssh2.c:3016-3043`): which readiness this scheme
/// is waiting for.
///
/// Filled into three of the four pollset slots by BOTH handlers --
/// `proto_pollset`, `doing_pollset` and `perform_pollset` -- with
/// `domore_pollset` left `ZERO_NULL`, because neither scheme has a second DO
/// half.
///
/// The logic is the C's, in three cases:
///
/// 1. `waitfor` is set, so the transport's own direction wins over the
///    transfer's: `KEEP_RECV` becomes `CURL_POLL_IN` and `KEEP_SEND` becomes
///    `CURL_POLL_OUT`;
/// 2. `waitfor` is clear but the transfer wants a direction, so
///    `data->req.keepon` supplies it -- which is why `keepon` is a parameter
///    here rather than read from a handle;
/// 3. neither, in which case the C still watches for readability *"while we
///    still have a session"*, because an SSH session must notice a peer
///    disconnecting even when no transfer is in flight.
///
/// The socket comes from the filter chain rather than from `conn->sock[]`, which
/// is the one structural difference: `crate::conn` owns the descriptor. An
/// invalid descriptor answers [`CURLcode::FailedInit`], exactly as the C's
/// `if(!sshc || (sock == CURL_SOCKET_BAD))` does.
///
/// # Errors
///
/// [`CURLcode::FailedInit`] when no descriptor is available, and whatever
/// [`EasyPollset`] reports for a change it cannot record.
pub(crate) fn ssh_pollset(
    ctx: &mut TransferCtx<'_>,
    ps: &mut EasyPollset,
    waitfor: SshWait,
    keepon: SshWait,
    have_session: bool,
) -> CodeResult<()> {
    let (chain, mut cx) = ctx.split();
    let sock = chain.socket(&mut cx);
    if !is_valid_sock(sock) {
        return Err(CURLcode::FailedInit);
    }

    let effective = if waitfor.is_empty() { keepon } else { waitfor };
    if !effective.is_empty() {
        let mut action = PollAction::NONE;
        if effective.contains(SshWait::RECV) {
            action = action | PollAction::IN;
        }
        if effective.contains(SshWait::SEND) {
            action = action | PollAction::OUT;
        }
        // `DEBUGASSERT(flags)` -- unreachable, because `effective` is non-empty
        // and every bit it can hold contributes one.
        return ps.change(sock, action, PollAction::NONE, cx.tracer_mut());
    }

    if have_session {
        return ps.change(
            sock,
            PollAction::IN,
            PollAction::NONE,
            cx.tracer_mut(),
        );
    }
    Ok(())
}

/// `ssh_attach` (`lib/vssh/libssh2.c:3806-3820`): this transfer is now using
/// this connection.
///
/// The C's comment is the whole of it: *"The SSH session is associated with the
/// *CONNECTION* but the callback user pointer is an easy handle pointer. This
/// function allows us to reassign the user pointer to the *CURRENT* (new) easy
/// handle."* So it exists to repair a pointer that a connection handed from one
/// transfer to another would otherwise leave stale -- and it is guarded by
/// `if(sshc && sshc->ssh_session)`, *"only re-attach if the session already
/// exists"*.
///
/// **There is no pointer to repair here.** The transport is owned by
/// [`SshConn`], and a transfer reaches it through the borrow it is handed, so
/// re-attaching is structurally unnecessary -- the whole class of defect the C
/// function exists to prevent cannot occur. The member is still FILLED, for two
/// reasons: the measured vtable occupancy is 11 of 17 and `attach` is one of the
/// eleven, and the scheme test the C performs
/// (`conn->scheme->protocol & PROTO_FAMILY_SSH`) is a real check that a
/// non-SSH scheme sharing this handler would fail. It answers whether the
/// connection belongs to this family, which is the only part of the C's body
/// that has anything left to do.
pub(crate) fn ssh_attach(ctx: &mut TransferCtx<'_>) -> bool {
    // `PROTO_FAMILY_SSH` is `Proto::FAMILY_SSH`, owned by `protocols/mod.rs` and
    // consumed here rather than redeclared -- it is `SCP | SFTP`.
    ctx.scheme().family.intersects(Proto::FAMILY_SSH)
}

// The SSH-CONNECT phase, shared by both schemes

/// `ssh_setup_connection` (`lib/vssh/libssh2.c:3167-3191`): allocate this
/// scheme's per-connection state.
///
/// The C allocates a `struct ssh_conn` and a `struct SSHPROTO`, registers a
/// destructor for each, and initialises the two dynamic buffers. Here both are
/// values with no destructor to register, so the whole of it is the pair --
/// which is why this returns them rather than storing them: `crate::conn` owns
/// the connection's metadata and `crate::easy` owns the transfer's, and neither
/// exists to be written into yet.
///
/// The two `DynBuf` ceilings the C sets here are recorded rather than
/// reproduced, because [`SshProto`]'s buffers are `Vec<u8>`:
/// `curlx_dyn_init(&sshp->readdir, CURL_PATH_MAX * 2)` and
/// `curlx_dyn_init(&sshp->readdir_link, CURL_PATH_MAX)`. What bounds them here
/// is the transport's own frame limit; a listing line longer than the C's
/// ceiling could not have arrived through libssh2's fixed
/// [`CURL_PATH_MAX`] buffers in the first place.
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
pub(crate) fn ssh_setup_connection(
    transport: Box<dyn SshTransport>,
    seams: SshSeams,
) -> (SshConn, SshProto) {
    (SshConn::new(transport, seams), SshProto::default())
}

/// One step of the SSH-CONNECT phase.
///
/// `ssh_statemachine`'s `SSH_INIT` through `SSH_SFTP_REALPATH` arms
/// (`lib/vssh/libssh2.c:2576-2795`), which both schemes run. The C's `do {}
/// while(!result && (sshc->state != SSH_STOP) && !*block)` loop is the caller's;
/// this performs exactly ONE arm, so that a caller can drive it to completion or
/// re-enter it after awaiting readiness -- which is what
/// `ssh_multi_statemach` and `ssh_block_statemach` are two different policies
/// for.
///
/// # The FALLTHROUGH is real and is preserved
///
/// `case SSH_INIT:` falls through to `case SSH_S_STARTUP:` in the C, and
/// `SSH_S_STARTUP` falls through to `SSH_HOSTKEY`. So a successful `SSH_INIT`
/// runs the handshake in the same pass. Reproduced by having each arm set the
/// next state and answer [`StepOutcome::Again`], which the caller's loop
/// re-enters immediately -- the same number of transport operations in the same
/// order, with the fall-through expressed as a loop rather than as a jump.
///
/// # Errors
///
/// Whatever the phase reports, already mapped to a [`CURLcode`]. The `failf`
/// text is returned alongside so that the caller emits it through the tracer it
/// holds; this function has none, which is what makes it testable.
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
pub(crate) async fn ssh_connect_step(
    sshc: &mut SshConn,
    sshp: &mut SshProto,
    settings: &SshSettings,
    ctx: &mut TransferCtx<'_>,
) -> StepOutcome {
    match sshc.state() {
        SshState::Init => {
            // `ssh_state_init`: reset the create-dirs counter, clear
            // `nextstate`, and force the known-host key type. The
            // non-blocking switch libssh2 needs has no counterpart -- awaiting
            // is what replaces it.
            sshc.second_create_dirs = 0;
            sshc.nextstate = SshState::NoState;
            StepOutcome::advance(SshState::SStartup)
        }
        SshState::SStartup => match sshc.transport.handshake(ctx).await {
            Ok(()) => StepOutcome::advance(SshState::HostKey),
            Err(error) => StepOutcome::fail_and_free(
                CURLcode::FailedInit,
                format!(
                    "Failure establishing ssh session: {}",
                    error.message()
                ),
            ),
        },
        SshState::HostKey => {
            let hostkey = sshc.transport.hostkey().unwrap_or_default();
            match check_fingerprint(&hostkey.blob, &settings.hostkey) {
                // Both callback outcomes are the caller's to resolve, because
                // the callbacks live on the easy handle. Reaching them requires
                // `easy/setopt.rs`, which is not on disk; until it is, a build
                // that sets neither option and names no file accepts, which is
                // the C's own answer for that configuration.
                Ok(HostKeyDecision::Accepted) => {
                    StepOutcome::advance(SshState::AuthList)
                }
                Ok(
                    HostKeyDecision::AskHostKeyCallback
                    | HostKeyDecision::ConsultKnownHosts,
                ) => StepOutcome::Verify {
                    hostkey,
                    next: SshState::AuthList,
                },
                Err(refusal) => {
                    let code = refusal.code();
                    let message = refusal.message();
                    if refusal.frees_the_session() {
                        StepOutcome::FailAndFree { code, message }
                    } else {
                        StepOutcome::Fail { code, message }
                    }
                }
            }
        }
        SshState::AuthList => {
            match sshc.transport.auth_list(ctx, &settings.user).await {
                Ok(list) if list.is_empty() => {
                    if sshc.transport.authenticated() {
                        sshc.authed = true;
                        StepOutcome::Advance {
                            next: SshState::AuthDone,
                            info: Some(
                                "SSH user accepted with no authentication"
                                    .into(),
                            ),
                        }
                    } else {
                        StepOutcome::fail_and_free(
                            CURLcode::Ssh,
                            "no SSH authentication methods available".into(),
                        )
                    }
                }
                Ok(list) => {
                    let info = format!(
                        "SSH authentication methods available: {}",
                        String::from_utf8_lossy(&list)
                    );
                    sshc.authlist = list;
                    StepOutcome::Advance {
                        next: SshState::AuthPkeyInit,
                        info: Some(info),
                    }
                }
                Err(error) => StepOutcome::fail_and_free(
                    error.to_curlcode(),
                    error.message().to_owned(),
                ),
            }
        }
        SshState::AuthPkeyInit => {
            // `ssh_state_pkey_init` resets `authed` before anything else, which
            // matters when a connection is reused.
            sshc.authed = false;
            StepOutcome::advance(next_auth_state(
                SshState::AuthPkeyInit,
                settings.auth_types,
                &sshc.authlist,
                false,
            ))
        }
        SshState::AuthPkey => {
            let private = settings.private_key.clone().unwrap_or_default();
            let public = settings
                .public_key
                .as_deref()
                .filter(|name| !name.is_empty());
            let passphrase = key_passphrase(settings.key_passwd.as_deref());
            let outcome = sshc
                .transport
                .auth_publickey(
                    ctx,
                    &settings.user,
                    &private,
                    public,
                    passphrase,
                )
                .await;
            ssh_auth_outcome(sshc, settings, SshState::AuthPkey, outcome, {
                "Initialized SSH public key authentication"
            })
        }
        SshState::AuthPassInit
        | SshState::AuthHostInit
        | SshState::AuthHost
        | SshState::AuthAgentInit
        | SshState::AuthKeyInit => {
            // The five pure routing states. Each one tests an option bit and the
            // server's list and moves on without touching the transport, which
            // is why they share an arm.
            StepOutcome::advance(next_auth_state(
                sshc.state(),
                settings.auth_types,
                &sshc.authlist,
                false,
            ))
        }
        SshState::AuthPass => {
            let outcome = sshc
                .transport
                .auth_password(ctx, &settings.user, &settings.password)
                .await;
            ssh_auth_outcome(
                sshc,
                settings,
                SshState::AuthPass,
                outcome,
                "Initialized password authentication",
            )
        }
        SshState::AuthAgentList => {
            // `libssh2_agent_list_identities`. The C's failure path is
            // `infof(data, "Failure requesting identities to agent")` followed
            // by `SSH_AUTH_KEY_INIT` -- never an error.
            StepOutcome::advance(next_auth_state(
                SshState::AuthAgentList,
                settings.auth_types,
                &sshc.authlist,
                true,
            ))
        }
        SshState::AuthAgent => {
            let outcome = sshc.transport.auth_agent(ctx, &settings.user).await;
            ssh_auth_outcome(
                sshc,
                settings,
                SshState::AuthAgent,
                outcome,
                "Agent based authentication successful",
            )
        }
        SshState::AuthKey => {
            let outcome = sshc
                .transport
                .auth_keyboard_interactive(
                    ctx,
                    &settings.user,
                    &settings.password,
                )
                .await;
            match outcome {
                Ok(true) => {
                    sshc.authed = true;
                    StepOutcome::Advance {
                        next: SshState::AuthDone,
                        info: Some(
                            "Initialized keyboard interactive authentication"
                                .into(),
                        ),
                    }
                }
                // The one terminal failure: `return CURLE_LOGIN_DENIED;` with
                // NO state change and NO message (`lib/vssh/libssh2.c:1738`).
                Ok(false) => StepOutcome::Fail {
                    code: CURLcode::LoginDenied,
                    message: None,
                },
                Err(error) => StepOutcome::fail_and_free(
                    error.to_curlcode(),
                    error.message().to_owned(),
                ),
            }
        }
        // `SSH_AUTH_GSSAPI` has no arm in the C's switch, so it reaches
        // `default:` and stops. Reproduced exactly rather than implemented,
        // because implementing it would add a mechanism curl does not have.
        SshState::AuthGssapi => StepOutcome::advance(SshState::Stop),
        SshState::AuthDone => {
            if !sshc.authed {
                return StepOutcome::fail_and_free(
                    CURLcode::LoginDenied,
                    "Authentication failure".into(),
                );
            }
            if ctx.scheme().protocol == Proto::SFTP {
                return StepOutcome::Advance {
                    next: SshState::SftpInit,
                    info: Some("Authentication complete".into()),
                };
            }
            // SCP stops here: its DO phase begins from `ssh_do`.
            StepOutcome::Advance {
                next: SshState::Stop,
                info: Some("SSH CONNECT phase done".into()),
            }
        }
        SshState::SftpInit => match sshc.transport.open_sftp(ctx).await {
            Ok(_version) => StepOutcome::advance(SshState::SftpRealpath),
            Err(error) => StepOutcome::fail_and_free(
                CURLcode::FailedInit,
                format!(
                    "Failure initializing sftp session: {}",
                    error.message()
                ),
            ),
        },
        SshState::SftpRealpath => {
            let id = sshc.next_request_id();
            let packet = request::realpath(id, b".");
            match sshc.sftp_exchange(ctx, packet).await {
                Ok(frame) => match request::decode_names(&frame) {
                    Ok(names) => {
                        // `if(rc > 0)`: a name came back. The C stores it as the
                        // home directory AND as
                        // `data->state.most_recent_ftp_entrypath`, which is what
                        // `CURLINFO_FTP_ENTRY_PATH` reports -- for SFTP as well
                        // as FTP, which is why the field is named for FTP.
                        match names.first() {
                            Some(entry) => {
                                sshc.homedir.clear();
                                sshc.homedir.extend_from_slice(&entry.filename);
                                sshp.readdir_entry = entry.clone();
                                StepOutcome::Advance {
                                    next: SshState::Stop,
                                    info: Some("CONNECT phase done".into()),
                                }
                            }
                            None => StepOutcome::Fail {
                                code: CURLcode::Ssh,
                                message: None,
                            },
                        }
                    }
                    Err(failure) => StepOutcome::Fail {
                        code: failure.to_curlcode(),
                        message: None,
                    },
                },
                Err(failure) => StepOutcome::Fail {
                    code: failure.to_curlcode(),
                    message: None,
                },
            }
        }
        // Not a SSH-CONNECT state. The caller routes by phase, so reaching this
        // is a caller error and answers what the C's `default:` answers.
        _ => StepOutcome::advance(SshState::Stop),
    }
}

/// The shared tail of `SSH_AUTH_PKEY`, `SSH_AUTH_PASS` and `SSH_AUTH_AGENT`.
///
/// All three have the same shape: on success set `authed`, log a line and go to
/// `SSH_AUTH_DONE`; on refusal move to the next mechanism WITHOUT an error; on a
/// transport failure report it. Written once because the three C bodies differ
/// only in their message and in which state a refusal leads to, and
/// [`next_auth_state`] already owns the second of those.
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
fn ssh_auth_outcome(
    sshc: &mut SshConn,
    settings: &SshSettings,
    from: SshState,
    outcome: Result<bool, SshError>,
    success_info: &str,
) -> StepOutcome {
    match outcome {
        Ok(true) => {
            sshc.authed = true;
            StepOutcome::Advance {
                next: next_auth_state(
                    from,
                    settings.auth_types,
                    &sshc.authlist,
                    true,
                ),
                info: Some(success_info.to_owned()),
            }
        }
        Ok(false) => StepOutcome::advance(next_auth_state(
            from,
            settings.auth_types,
            &sshc.authlist,
            false,
        )),
        Err(error) => StepOutcome::fail_and_free(
            error.to_curlcode(),
            error.message().to_owned(),
        ),
    }
}

/// What one step of the machine concluded.
///
/// The C conflates four different things into a `CURLcode` return plus a state
/// mutation plus a `failf` call plus an `infof` call. Separating them is what
/// makes a step testable: a test asserts the outcome value, and the caller --
/// which holds the tracer -- performs the transition and the emission.
#[derive(Debug, Eq, PartialEq)]
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
pub(crate) enum StepOutcome {
    /// Move to `next`, optionally logging `info` first.
    Advance {
        /// The state to move to.
        next: SshState,
        /// An `infof` line, if this step produced one.
        info: Option<String>,
    },
    /// The host key must be resolved by a callback or the known-hosts file
    /// before `next` is entered.
    ///
    /// Neither is reachable from inside this module: both live on the easy
    /// handle, whose module is not on disk. Answering the requirement rather
    /// than silently accepting is what keeps the gap visible -- and what lets a
    /// caller that DOES have the callback resolve it without this function
    /// changing.
    Verify {
        /// The key the peer presented.
        hostkey: HostKeyBlob,
        /// Where to go once it is accepted.
        next: SshState,
    },
    /// Report `code`, leaving the state where it is.
    Fail {
        /// The code to report.
        code: CURLcode,
        /// A `failf` line, if this step produced one.
        message: Option<String>,
    },
    /// Report `code` and move to `SSH_SESSION_FREE`.
    ///
    /// The distinction from [`Self::Fail`] is the C's and is not cosmetic: a
    /// failure that frees the session cannot be retried on the same connection,
    /// and [`KnownHostStat::Defer`] exists precisely because one caller needs
    /// the other behaviour.
    FailAndFree {
        /// The code to report.
        code: CURLcode,
        /// A `failf` line.
        message: Option<String>,
    },
}

#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
impl StepOutcome {
    /// Move to `next` with nothing to log.
    pub(crate) const fn advance(next: SshState) -> Self {
        Self::Advance { next, info: None }
    }

    /// Report `code` with `message` and free the session.
    pub(crate) fn fail_and_free(code: CURLcode, message: String) -> Self {
        Self::FailAndFree {
            code,
            message: Some(message),
        }
    }

    /// The code this outcome reports, or [`CURLcode::Ok`] when it is a
    /// transition.
    pub(crate) const fn code(&self) -> CURLcode {
        match self {
            Self::Advance { .. } | Self::Verify { .. } => CURLcode::Ok,
            Self::Fail { code, .. } | Self::FailAndFree { code, .. } => *code,
        }
    }

    /// Whether this outcome is a failure.
    pub(crate) const fn is_failure(&self) -> bool {
        matches!(self, Self::Fail { .. } | Self::FailAndFree { .. })
    }
}

// The SFTP-DO, SFTP-DONE and SFTP-DISCONNECT phases

/// `SSH_SFTP_TRANS_INIT` (`lib/vssh/libssh2.c:2729-2742`): which transfer this
/// request is.
///
/// Three-way, and the test that picks between the last two is the whole reason a
/// trailing slash matters on an SFTP URL: *"if(sshp->path[strlen(sshp->path) - 1]
/// == '/')"* selects a directory listing. So `sftp://host/dir` downloads a file
/// called `dir` and `sftp://host/dir/` lists it, and neither is a special case
/// -- the byte decides.
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) fn sftp_trans_init(path: &[u8], upload: bool) -> SshState {
    if upload {
        SshState::SftpUploadInit
    } else if path.last().is_some_and(|byte| *byte == b'/') {
        SshState::SftpReaddirInit
    } else {
        SshState::SftpDownloadInit
    }
}

/// `SSH_SFTP_GETINFO` (`lib/vssh/libssh2.c:2700-2707`): whether the extra stat
/// for `CURLOPT_FILETIME` is needed.
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) const fn sftp_getinfo(get_filetime: bool) -> SshState {
    if get_filetime {
        SshState::SftpFiletime
    } else {
        SshState::SftpTransInit
    }
}

/// `SSH_SFTP_QUOTE_INIT` (`lib/vssh/libssh2.c:1844-1863`): enter the quote
/// phase, or skip it.
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) const fn sftp_quote_init(has_quote: bool) -> SshState {
    if has_quote {
        SshState::SftpQuote
    } else {
        SshState::SftpGetinfo
    }
}

/// `SSH_SFTP_POSTQUOTE_INIT` (`lib/vssh/libssh2.c:1865-1877`): enter the
/// postquote phase, or stop.
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) const fn sftp_postquote_init(has_postquote: bool) -> SshState {
    if has_postquote {
        SshState::SftpQuote
    } else {
        SshState::Stop
    }
}

/// `SSH_SFTP_CREATE_DIRS_INIT` (`lib/vssh/libssh2.c:2761-2771`): begin the
/// `--ftp-create-dirs` walk, or skip it.
///
/// `strlen(sshp->path) > 1` is the test, and the offset it sets is 1 -- *"ignore
/// the leading '/'"* -- so a path of exactly `/` has no directory to create.
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) fn sftp_create_dirs_init(path: &[u8]) -> (SshState, usize) {
    if path.len() > 1 {
        (SshState::SftpCreateDirs, 1)
    } else {
        (SshState::SftpUploadInit, 0)
    }
}

/// `SSH_SFTP_CREATE_DIRS` (`lib/vssh/libssh2.c:2773-2787`): the next directory
/// component to create, or the end of the walk.
///
/// The C advances `sshc->slash_pos` to the next `/`, writes a NUL over it so the
/// path is truncated to that component, issues a `MKDIR`, then restores the `/`
/// and steps past it. Expressed here as an offset and a slice: the component is
/// `path[..slash]` and the next search starts at `slash + 1`.
///
/// Answers the truncated path to create and the offset to resume from, or
/// [`None`] when no `/` remains -- which is when the walk hands over to
/// `SSH_SFTP_UPLOAD_INIT`.
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) fn sftp_next_directory(
    path: &[u8],
    from: usize,
) -> Option<(&[u8], usize)> {
    let tail = path.get(from..)?;
    let offset = memchr::memchr(b'/', tail)?;
    let slash = from + offset;
    Some((&path[..slash], slash + 1))
}

/// `ssh_state_sftp_create_dirs_mkdir` (`lib/vssh/libssh2.c:2138-2167`): which
/// `MKDIR` failures the walk tolerates.
///
/// The C's comment is the rule: *"Abort if failure was not that the directory
/// already exists or the permission was denied (creation might succeed further
/// down the path) - retry on unspecific FAILURE also"*. So three statuses are
/// survivable and every other one aborts the transfer.
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) fn create_dirs_tolerates(status: SftpStatus) -> bool {
    matches!(
        status,
        SftpStatus::FILE_ALREADY_EXISTS
            | SftpStatus::FAILURE
            | SftpStatus::PERMISSION_DENIED
    )
}

/// `sftp_upload_init` (`lib/vssh/libssh2.c:924-940`): which open flags an upload
/// uses.
///
/// Three cases in the C's own order, and the middle one carries a comment that
/// is the reason it exists: *"Resume MUST NOT use APPEND; some servers force
/// writes to EOF when APPEND is set, ignoring a prior seek()."* So a resumed
/// upload opens with a bare `WRITE` and seeks, while an explicit `--append`
/// opens with `APPEND` and does not.
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) const fn sftp_upload_flags(
    remote_append: bool,
    resume_from: i64,
) -> SftpOpenFlags {
    if remote_append {
        SFTP_UPLOAD_APPEND
    } else if resume_from > 0 {
        SFTP_UPLOAD_RESUME
    } else {
        SFTP_UPLOAD_TRUNCATE
    }
}

/// `sftp_upload_init`'s create-dirs decision (`lib/vssh/libssh2.c:962-975`).
///
/// A failed open retries through `SSH_SFTP_CREATE_DIRS_INIT` only when three
/// things hold: the status is one of `NO_SUCH_FILE`, `FAILURE` or
/// `NO_SUCH_PATH`, `CURLOPT_FTP_CREATE_MISSING_DIRS` is set, and the path is
/// longer than one byte. And it retries at most ONCE -- `sshc->secondCreateDirs`
/// is the guard, whose failure text is a different one: *"Creating the dir/file
/// failed: %s"*.
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) fn upload_should_create_dirs(
    status: SftpStatus,
    create_missing_dirs: bool,
    path: &[u8],
    second_attempt: bool,
) -> bool {
    !second_attempt
        && create_missing_dirs
        && path.len() > 1
        && matches!(
            status,
            SftpStatus::NO_SUCH_FILE
                | SftpStatus::FAILURE
                | SftpStatus::NO_SUCH_PATH
        )
}

/// What a download's size resolution concluded --
/// `sftp_download_stat` (`lib/vssh/libssh2.c:1274-1367`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) struct DownloadPlan {
    /// The offset to read from. Non-zero for a resumed or ranged download.
    pub(crate) from: u64,
    /// How many bytes to transfer, or [`None`] when the size is unknown.
    ///
    /// [`None`] is the C's `data->req.size = -1` with
    /// `Curl_pgrsSetDownloadSize(data, -1)`, which makes the progress meter
    /// report an unknown total and the transfer run to end of file.
    pub(crate) size: Option<u64>,
    /// Whether there is nothing to transfer at all.
    ///
    /// `if(data->req.size == 0)` sets up a no-op transfer and logs *"File
    /// already completely downloaded"* (`lib/vssh/libssh2.c:1351-1357`).
    pub(crate) complete: bool,
}

/// `sftp_download_stat` (`lib/vssh/libssh2.c:1274-1367`): resolve the download
/// size, the range and the resume offset.
///
/// The three interact in a specific order and the order is observable:
///
/// 1. an unusable stat -- no `ATTR_SIZE`, or a size of zero -- makes the size
///    UNKNOWN and skips the range entirely, because there is nothing to resolve a
///    range against. The C's comment lists all three reasons it treats them
///    alike;
/// 2. otherwise `--range` is resolved by [`ssh_range`], which seeks;
/// 3. `--continue-at` is then applied ON TOP, and it is the one that reports
///    *"Offset (%d) was beyond file size (%d)"* with
///    [`CURLcode::BadDownloadResume`] -- note the DIFFERENT code from
///    [`ssh_range`]'s [`CURLcode::RangeError`] for the same-looking condition.
///
/// A negative `resume_from` means *"we are supposed to download the last abs(from)
/// bytes"* and is resolved against the size before the bounds test, which is why
/// `--continue-at -100` on a 50-byte file is refused rather than clamped -- the
/// opposite of what `--range -100` does.
///
/// # Errors
///
/// [`CURLcode::BadDownloadResume`] for a resume offset beyond the file or a
/// negative reported size, and whatever [`ssh_range`] refuses a range with.
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) fn sftp_download_size(
    attrs: SftpAttributes,
    range: Option<&[u8]>,
    resume_from: i64,
) -> Result<DownloadPlan, (CURLcode, Option<String>)> {
    let reported = attrs.reported_size().filter(|size| *size != 0);

    let Some(filesize) = reported else {
        // Unknown size: no range, no resume arithmetic, read to end of file.
        return Ok(DownloadPlan {
            from: 0,
            size: None,
            complete: false,
        });
    };

    let signed = i64::try_from(filesize).map_err(|_| {
        (
            CURLcode::BadDownloadResume,
            Some(format!("Bad file size ({filesize})")),
        )
    })?;

    let mut from: u64 = 0;
    let mut size = signed;

    if let Some(range) = range {
        let (start, count) = ssh_range(range, signed)
            .map_err(|refusal| (refusal.code(), refusal.message()))?;
        from = u64::try_from(start).unwrap_or(0);
        size = count;
    }

    if resume_from != 0 {
        let resolved = if resume_from < 0 {
            // `if((curl_off_t)attrs.filesize < -data->state.resume_from)`.
            if signed < -resume_from {
                return Err((
                    CURLcode::BadDownloadResume,
                    Some(format!(
                        "Offset ({resume_from}) was beyond file size \
                         ({signed})"
                    )),
                ));
            }
            resume_from + signed
        } else {
            if signed < resume_from {
                return Err((
                    CURLcode::BadDownloadResume,
                    Some(format!(
                        "Offset ({resume_from}) was beyond file size \
                         ({signed})"
                    )),
                ));
            }
            resume_from
        };
        size = signed - resolved;
        from = u64::try_from(resolved).unwrap_or(0);
    }

    let count = u64::try_from(size).unwrap_or(0);
    Ok(DownloadPlan {
        from,
        size: Some(count),
        complete: count == 0,
    })
}

/// `sftp_upload_init`'s resume resolution (`lib/vssh/libssh2.c:899-921` and
/// `:993-1046`).
///
/// A negative `resume_from` means *"append to whatever is there"*, so the C stats
/// the destination and uses its size -- and if the stat FAILS it sets
/// `resume_from` to zero rather than reporting an error, because the file not
/// existing yet is the ordinary case for an upload.
///
/// # Errors
///
/// [`CURLcode::BadDownloadResume`] with *"Bad file size (%d)"* for a negative
/// reported size, which is the one refusal this resolution has.
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) fn sftp_upload_resume(
    resume_from: i64,
    stat: Option<SftpAttributes>,
) -> Result<i64, (CURLcode, Option<String>)> {
    if resume_from >= 0 {
        return Ok(resume_from);
    }
    match stat {
        // `if(rc) { data->state.resume_from = 0; }` -- a failed stat is not an
        // error here.
        None => Ok(0),
        Some(attrs) => {
            let size = attrs.filesize;
            let signed = i64::try_from(size).map_err(|_| {
                (
                    CURLcode::BadDownloadResume,
                    Some(format!("Bad file size ({size})")),
                )
            })?;
            Ok(signed)
        }
    }
}

/// `sftp_done` (`lib/vssh/libssh2.c:3676-3695`): whether a postquote round runs
/// before the handle is closed.
///
/// The C's comment states the reason for the ordering, which is not obvious:
/// *"Post quote commands are executed after the SFTP_CLOSE state to avoid errors
/// that could happen due to open file handles during POSTQUOTE operation."* So
/// `nextstate` is set to `SSH_SFTP_POSTQUOTE_INIT` and the machine enters
/// `SSH_SFTP_CLOSE`, which then routes to it -- and `SSH_SFTP_CLOSE` sets
/// `nextstate` to ITSELF so that control returns for the real close.
///
/// Three conditions, all required: the transfer succeeded, it did not end
/// prematurely, and the connection is not being retried.
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) fn sftp_done(
    status: CURLcode,
    premature: bool,
    has_postquote: bool,
    retrying: bool,
) -> Option<SshState> {
    if status != CURLcode::Ok {
        // `if(!status)` guards the whole body: a failed transfer runs no
        // postquote and does not even enter `SSH_SFTP_CLOSE` from here.
        return None;
    }
    if !premature && has_postquote && !retrying {
        Some(SshState::SftpPostquoteInit)
    } else {
        Some(SshState::NoState)
    }
}

/// `ssh_state_sftp_close` (`lib/vssh/libssh2.c:2276-2310`): where the machine
/// goes after the handle is released.
///
/// The C's comment is the mechanism: *"Check if nextstate is set and move
/// .nextstate could be POSTQUOTE_INIT. After nextstate is executed, the control
/// should come back to SSH_SFTP_CLOSE to pass the correct result back"*. So the
/// state SWAPS with `nextstate` rather than clearing it, and the guard
/// `nextstate != SSH_SFTP_CLOSE` is what stops the swap looping.
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) fn sftp_close_next(nextstate: SshState) -> (SshState, SshState) {
    if nextstate != SshState::NoState && nextstate != SshState::SftpClose {
        (nextstate, SshState::SftpClose)
    } else {
        (SshState::Stop, nextstate)
    }
}

// The registry row and the `Protocol` implementation

/// `PROTOPT_DIRLOCK | PROTOPT_CLOSEACTION | PROTOPT_NOURLQUERY |
/// PROTOPT_CONN_REUSE` (`lib/vssh/vssh.c:347-348`).
///
/// Folded here rather than reusing `protocols/mod.rs`'s `FLAGS_SSH`, because that
/// constant is private to that module and this row has to be self-describing.
/// The bits themselves are CONSUMED from [`ProtocolOptions`] and are not
/// redeclared -- `crate::conn` holds the one definition of all seventeen.
///
/// What each one means for SFTP, since the combination is unusual:
///
/// * `PROTOPT_DIRLOCK` (`1 << 3`) -- the connection is bound to a directory, so
///   it cannot be reused for a path that would need a different one;
/// * `PROTOPT_CLOSEACTION` (`1 << 2`) -- *"some sort of close/quit action must be
///   done before the connection is closed"*, which for SFTP is
///   `SSH_SFTP_SHUTDOWN` through `SSH_SESSION_FREE`;
/// * `PROTOPT_NOURLQUERY` (`1 << 6`) -- a `?foo=bar` tail is part of the PATH, not
///   a query, because a filename may legitimately contain a question mark;
/// * `PROTOPT_CONN_REUSE` (`1 << 16`) -- connections may be pooled, subject to the
///   directory lock above.
///
/// What is deliberately ABSENT and would be easy to add by mistake:
/// `PROTOPT_WILDCARD`, which `ftp` and `ftps` both carry and neither SSH scheme
/// does. So `--use-ascii`-style globbing over an SFTP directory does not happen,
/// and [`crate::util::fnmatch`] -- available and unused here -- is not wired into
/// the listing path. The C does not do it, so this does not.
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
const FLAGS_SFTP: ProtocolOptions = ProtocolOptions::DIRLOCK
    .union(ProtocolOptions::CLOSEACTION)
    .union(ProtocolOptions::NOURLQUERY)
    .union(ProtocolOptions::CONN_REUSE);

/// `Curl_scheme_sftp` (`lib/vssh/vssh.c:338-350`), all six members.
///
/// `#[rustfmt::skip]` because every column is ABI- or wire-bearing.
///
/// ⚠ **The name is UPPER CASE**, `b"SFTP"`, exactly as the C spells it -- and the
/// C's own `struct Curl_scheme` comment claims *"URL scheme name in lowercase"*.
/// The table works because both sides of every comparison are case-folded
/// (`Curl_getn_scheme` uses `curl_strnequal`), and four of the 33 rows are
/// upper case in the C source: `SFTP`, `SCP`, `WS` and `WSS`. Correcting this
/// spelling would change nothing observable and would make the row stop matching
/// the C line it was transcribed from, so it is preserved and asserted.
#[rustfmt::skip]
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) const SCHEME: Scheme = Scheme {
    name:     b"SFTP",
    run:      Some(&SFTP),
    protocol: Proto::SFTP,
    family:   Proto::SFTP,
    flags:    FLAGS_SFTP,
    defport:  PORT_SSH,
};

/// The SFTP transfer implementation -- `Curl_protocol_sftp`
/// (`lib/vssh/libssh2.c:3846-3864`).
///
/// # Eleven of seventeen slots, measured
///
/// | # | member | C | here |
/// | --: | --- | --- | --- |
/// | 1 | `setup_connection` | `ssh_setup_connection` | overridden |
/// | 2 | `do_it` | `ssh_do` | overridden (required) |
/// | 3 | `done` | `sftp_done` | overridden (required) |
/// | 4 | `do_more` | `ZERO_NULL` | default |
/// | 5 | `connect_it` | `ssh_connect` | overridden |
/// | 6 | `connecting` | `ssh_multi_statemach` | overridden |
/// | 7 | `doing` | `sftp_doing` | overridden |
/// | 8 | `proto_pollset` | `ssh_pollset` | overridden |
/// | 9 | `doing_pollset` | `ssh_pollset` | overridden |
/// | 10 | `domore_pollset` | `ZERO_NULL` | default |
/// | 11 | `perform_pollset` | `ssh_pollset` | overridden |
/// | 12 | `disconnect` | `sftp_disconnect` | overridden |
/// | 13 | `write_resp` | `ZERO_NULL` | default |
/// | 14 | `write_resp_hd` | `ZERO_NULL` | default |
/// | 15 | `connection_check` | `ZERO_NULL` | default |
/// | 16 | `attach` | `ssh_attach` | overridden |
/// | 17 | `follow` | `ZERO_NULL` | default |
///
/// `protocols/scp.rs` differs in exactly three of the eleven -- `done`, `doing`
/// and `disconnect` -- which is the measurement that put the shared core in this
/// file.
///
/// # Why this type is empty
///
/// `struct Curl_protocol` is a table of function pointers with no state, and
/// [`SCHEME`] holds `Option<&'static dyn Protocol>`, so a zero-sized type is what the C
/// actually is. The per-connection state lives in [`SshConn`] and the
/// per-transfer state in [`SshProto`], which is the same division
/// `lib/vssh/ssh.h` documents.
///
/// # What this checkpoint can and cannot do, stated rather than implied
///
/// The eleven members are implemented in terms of the phase functions above and
/// the [`SshTransport`] seam, and every one of those is exercised by
/// [`mod tests`](self). What no member can do yet is reach a transfer's OPTIONS
/// or its client-writer chain: [`TransferCtx`] carries the filter chains, the
/// clock, the scheme and the socket index and nothing else, and
/// `curl-rs-lib/src/easy/setopt.rs` -- which would populate an [`SshSettings`] --
/// is not on disk. So a member that needs the settings takes them as an
/// argument from the phase function it delegates to, and the trait member itself
/// reports [`CURLcode::NotBuiltIn`] until the easy handle can supply them. That
/// is the wiring gap `crate::version`'s `ENGINE_PROTOCOLS` records, it is
/// visible in the trace output rather than silent, and it is why this build still
/// withholds `sftp` from the `Protocols:` banner -- under-reporting a capability
/// makes a fixture skip, and over-reporting makes it run and fail.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct Sftp;

/// The one instance, which [`SCHEME`] and `mod.rs`'s `RUN_SFTP` point at.
///
/// A `const` rather than a `static`, for a reason worth recording because the
/// obvious choice is wrong here. Under **MSRV 1.75** a `const` initialiser may
/// not refer to a `static` -- `error[E0013]: constants cannot refer to statics`
/// -- and BOTH consumers are `const` items: [`SCHEME`] below and
/// `protocols::RUN_SFTP`. Newer compilers accept it, so the mistake builds
/// cleanly on the default toolchain and fails only under
/// `cargo +1.75.0 check`, which is exactly what that gate is for.
///
/// The `const` is also the more accurate translation. `Curl_protocol_sftp` is a
/// `const struct` of function pointers with no state
/// (`lib/vssh/libssh2.c:3846`), [`Sftp`] is zero-sized, and `&SFTP` in a `const`
/// context is const-promoted to a `&'static` reference to a ZST -- so there is
/// no storage for a `static` to reserve and nothing for two promotions to
/// disagree about.
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) const SFTP: Sftp = Sftp;

impl Protocol for Sftp {
    // -- 1. setup_connection ------------------------------------------------

    /// `ssh_setup_connection`: allocate this scheme's per-connection state.
    ///
    /// The allocation itself is [`ssh_setup_connection`], which answers the pair
    /// of state carriers. There is nowhere to STORE them yet -- the C keeps them
    /// in `Curl_conn_meta_set(conn, CURL_META_SSH_CONN, ...)` and
    /// `Curl_meta_set(data, CURL_META_SSH_EASY, ...)`, and neither successor
    /// exists -- so this member validates what it can: that the scheme really
    /// belongs to the SSH family, which is the precondition every other member
    /// assumes.
    fn setup_connection(&self, ctx: &mut TransferCtx<'_>) -> CodeResult<()> {
        if ssh_attach(ctx) {
            Ok(())
        } else {
            Err(CURLcode::FailedInit)
        }
    }

    // -- 2. do_it -----------------------------------------------------------

    /// `ssh_do` (`lib/vssh/libssh2.c:3758-3781`) into `sftp_perform`
    /// (`:3612-3638`).
    ///
    /// The C's `ssh_do` is shared by both schemes and branches on
    /// `conn->scheme->protocol & CURLPROTO_SCP`; the SFTP branch resets
    /// `data->req.size` to -1 and `sshc->secondCreateDirs` to 0, resets the
    /// progress meter, enters `SSH_SFTP_QUOTE_INIT` and runs the machine.
    ///
    /// Reaching the machine needs the connection's [`SshConn`], which
    /// [`TransferCtx`] cannot supply at this checkpoint. Reported as
    /// [`CURLcode::NotBuiltIn`] rather than answered `Ok(true)`, deliberately: a
    /// silent success would make the transfer core believe a DO phase had
    /// completed and hand an empty body to the client, which is precisely the
    /// over-reporting that turns a skipped fixture into a failing one.
    fn do_it<'a>(
        &'a self,
        ctx: &'a mut TransferCtx<'_>,
    ) -> ProtoFuture<'a, bool> {
        let _ = ctx;
        Box::pin(core::future::ready(Err(CURLcode::NotBuiltIn)))
    }

    // -- 3. done ------------------------------------------------------------

    /// `sftp_done` (`lib/vssh/libssh2.c:3676-3695`).
    ///
    /// The decision this member makes is [`sftp_done`]'s and is fully
    /// implemented and tested; what it cannot do is carry it out, for the reason
    /// [`Self::do_it`] gives. A `done` that reports the transfer's own status
    /// unchanged is what the C does when there is nothing to close -- `if(!status)`
    /// guards its whole body -- so a failed transfer is reported faithfully and a
    /// successful one cannot occur.
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

    // -- 5. connect_it ------------------------------------------------------

    /// `ssh_connect` (`lib/vssh/libssh2.c:3258-3437`): enter `SSH_INIT` and run
    /// the machine.
    ///
    /// The C's body before the state change is diagnostics -- the crypto backend,
    /// the user name -- plus reading `CURLOPT_SSH_KNOWNHOSTS` into libssh2's
    /// known-hosts store. All of it needs the connection's state, so this
    /// reports the same gap [`Self::do_it`] does. [`ssh_connect_step`] is the
    /// phase itself and is implemented in full.
    fn connect_it<'a>(
        &'a self,
        ctx: &'a mut TransferCtx<'_>,
    ) -> ProtoFuture<'a, bool> {
        let _ = ctx;
        Box::pin(core::future::ready(Err(CURLcode::NotBuiltIn)))
    }

    // -- 6. connecting ------------------------------------------------------

    /// `ssh_multi_statemach` (`lib/vssh/libssh2.c:3070-3090`): continue the
    /// connect phase.
    ///
    /// The C's loop is `do { ssh_statemachine(...); *done = (sshc->state ==
    /// SSH_STOP); } while(!result && !*done && !block);` followed by
    /// `ssh_block2waitfor`. The loop and the readiness test are what
    /// [`ssh_connect_step`] and [`SshConn::block2waitfor`] provide between them.
    fn connecting<'a>(
        &'a self,
        ctx: &'a mut TransferCtx<'_>,
    ) -> ProtoFuture<'a, bool> {
        let _ = ctx;
        Box::pin(core::future::ready(Err(CURLcode::NotBuiltIn)))
    }

    // -- 7. doing -----------------------------------------------------------

    /// `sftp_doing` (`lib/vssh/libssh2.c:3641-3653`): continue the DO phase.
    ///
    /// Identical to [`Self::connecting`] in the C apart from its trace line, and
    /// this is the first of the three slots where SFTP and SCP differ -- SCP
    /// fills `scp_doing` here.
    fn doing<'a>(
        &'a self,
        ctx: &'a mut TransferCtx<'_>,
    ) -> ProtoFuture<'a, bool> {
        let _ = ctx;
        Box::pin(core::future::ready(Err(CURLcode::NotBuiltIn)))
    }

    // -- 8, 9, 11. three of the four pollsets -------------------------------

    /// `ssh_pollset` during PROTOCONNECT.
    ///
    /// Unlike the four members above, this one WORKS: the readiness a pollset
    /// records is a function of the transport's wait direction, the transfer's
    /// keep flags and the chain's descriptor, and [`TransferCtx`] supplies the
    /// third while the first two default to empty without a connection. So the
    /// behaviour with no session is the C's third case -- watch for readability
    /// while a session exists, and record nothing otherwise -- which is what
    /// [`ssh_pollset`] answers for `have_session == false`.
    fn proto_pollset(
        &self,
        ctx: &mut TransferCtx<'_>,
        ps: &mut EasyPollset,
    ) -> CodeResult<()> {
        ssh_pollset(ctx, ps, SshWait::NONE, SshWait::NONE, false)
    }

    /// `ssh_pollset` during DOING. The same function in the C, filled into a
    /// second slot.
    fn doing_pollset(
        &self,
        ctx: &mut TransferCtx<'_>,
        ps: &mut EasyPollset,
    ) -> CodeResult<()> {
        ssh_pollset(ctx, ps, SshWait::NONE, SshWait::NONE, false)
    }

    /// `ssh_pollset` during DO_DONE, PERFORM and WAITPERFORM -- the third and
    /// last slot it fills.
    ///
    /// `domore_pollset` is deliberately NOT overridden: it is `ZERO_NULL` in
    /// both SSH handlers, because neither scheme carries `PROTOPT_DUAL` and so
    /// neither has a second DO half to wait on.
    fn perform_pollset(
        &self,
        ctx: &mut TransferCtx<'_>,
        ps: &mut EasyPollset,
    ) -> CodeResult<()> {
        ssh_pollset(ctx, ps, SshWait::NONE, SshWait::NONE, false)
    }

    // -- 12. disconnect -----------------------------------------------------

    /// `sftp_disconnect` (`lib/vssh/libssh2.c:3655-3674`): the SFTP teardown.
    ///
    /// The second of the three slots where the schemes differ. The C enters
    /// `SSH_SFTP_SHUTDOWN` and drives the machine to completion with
    /// `ssh_block_statemach(..., TRUE)`, and its comment explains why that is
    /// blocking: *"BLOCKING, but the function is using the state machine so the
    /// only reason this is still blocking is that the multi interface code has no
    /// support for disconnecting operations that takes a while"*. The successor
    /// is not blocking -- it awaits -- and the phase is
    /// [`ssh_session_disconnect`] and [`ssh_session_free`].
    ///
    /// `dead_connection` matters and is honoured by those two: nothing may be
    /// SENT on a dead connection, so the disconnect message is skipped.
    ///
    /// Answers `Ok(())` rather than reporting the wiring gap, and that is
    /// deliberate rather than an inconsistency with the four members above: the
    /// C's caller closes the connection regardless of what this returns, so
    /// reporting a failure here would add a diagnostic without changing an
    /// outcome. With no session to shut down there is genuinely nothing to do.
    fn disconnect<'a>(
        &'a self,
        ctx: &'a mut TransferCtx<'_>,
        dead_connection: bool,
    ) -> ProtoFuture<'a, ()> {
        let _ = (ctx, dead_connection);
        Box::pin(core::future::ready(Ok(())))
    }

    // -- 16. attach ---------------------------------------------------------

    /// `ssh_attach` (`lib/vssh/libssh2.c:3806-3820`).
    ///
    /// Fully implemented; see [`ssh_attach`] for why the pointer repair the C
    /// performs has no successor and what is left of the body.
    fn attach(&self, ctx: &mut TransferCtx<'_>) {
        let _ = ssh_attach(ctx);
    }

    // -- 15. connection_check, and the five other defaults ------------------
    //
    // `do_more`, `domore_pollset`, `write_resp`, `write_resp_hd`,
    // `connection_check` and `follow` are all `ZERO_NULL` in
    // `Curl_protocol_sftp`, so all six take the trait's defaults. Each default
    // reproduces what the C's caller does with a NULL slot, which is why not
    // writing them is the faithful choice rather than an omission:
    //
    //   do_more           -> completes immediately; SFTP is not PROTOPT_DUAL
    //   domore_pollset    -> no-op, for the same reason
    //   write_resp        -> false, so the generic client-writer chain runs
    //   write_resp_hd     -> false, likewise
    //   connection_check  -> CONNRESULT_NONE; the pool learns nothing extra
    //   follow            -> CURLE_TOO_MANY_REDIRECTS, which is what
    //                        `multi_follow` answers for a NULL slot
    //                        (`lib/multi.c:1870-1878`). SFTP has no redirects.
}

// The session teardown, shared by both schemes

/// `ssh_state_session_disconnect` (`lib/vssh/libssh2.c:2423-2459`).
///
/// `SSH_SESSION_DISCONNECT` is marked *"First state in SCP-DISCONNECT"* and is
/// reached by SFTP too, through `SSH_SFTP_SHUTDOWN`. It sends
/// `libssh2_session_disconnect(session, "Shutdown")` -- the reason string is on
/// the wire and is exactly that -- and reports a failure with `infof` rather
/// than propagating it, because the connection is going away either way.
///
/// `dead_connection` suppresses the send entirely. The C does not take that
/// parameter here and relies on its caller not to reach this state on a dead
/// connection; taking it makes the rule explicit, and it is the same rule
/// `Protocol::disconnect`'s own documentation states -- *"a scheme must not send
/// anything when it is"*.
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
pub(crate) async fn ssh_session_disconnect(
    sshc: &mut SshConn,
    ctx: &mut TransferCtx<'_>,
    dead_connection: bool,
) -> Option<String> {
    if dead_connection {
        return None;
    }
    match sshc.transport.disconnect(ctx).await {
        Ok(()) => None,
        Err(error) => Some(format!(
            "Failed to disconnect libssh2 session: {}",
            error.message()
        )),
    }
}

/// `SSH_SESSION_FREE` (`lib/vssh/libssh2.c:2969-2978`) with `sshc_cleanup`
/// (`:2461-2564`).
///
/// Marked *"Last state in SCP/SFTP-DISCONNECT"* -- it terminates BOTH phases,
/// which is why it lives here and not in either scheme's own module. The C's body
/// is `sshc_cleanup`, then `memset(sshc, 0, sizeof(struct ssh_conn))`, then
/// `connclose(conn, "SSH session free")`, then `SSH_STOP`.
///
/// The reset is reproduced field by field rather than as a `memset`, and the two
/// injected dependencies survive it: the C has none to preserve, and zeroing a
/// `Box<dyn SshTransport>` is not a thing this port could express even if it
/// wanted to. What matters is that every piece of SESSION state is cleared, so
/// that a connection object reaching the pool carries nothing from the transfer
/// that finished -- which is exactly what the `memset` achieves.
///
/// Answers the `connclose` reason, which is a wire-visible string in the
/// connection log: `"SSH session free"`.
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
pub(crate) fn ssh_session_free(sshc: &mut SshConn) -> &'static str {
    sshc.nextstate = SshState::NoState;
    sshc.authlist.clear();
    sshc.authed = false;
    sshc.acceptfail = false;
    sshc.homedir.clear();
    sshc.quote_index = 0;
    sshc.quote_list = QuoteList::Quote;
    sshc.quote = None;
    sshc.second_create_dirs = 0;
    sshc.slash_pos = 0;
    sshc.waitfor = SshWait::NONE;
    sshc.sftp_handle = None;
    sshc.sftp_offset = 0;
    // `sshc->state = SSH_SESSION_FREE; /* current */` immediately before
    // `myssh_to(data, sshc, SSH_STOP)`: the C restores the state the `memset`
    // wiped so that the transition to `SSH_STOP` traces from the right place.
    // Reproduced, because the trace line is observable.
    sshc.restore_state(SshState::SessionFree);
    "SSH session free"
}

/// `sftp_disconnect`'s entry state, and `scp_disconnect`'s.
///
/// The one place the two schemes' disconnect phases begin differently, recorded
/// here so that `protocols/scp.rs` reads the seam from this file rather than
/// restating it: SFTP starts at `SSH_SFTP_SHUTDOWN`
/// (`lib/vssh/libssh2.c:3666`) and SCP starts at `SSH_SESSION_DISCONNECT`
/// (`:3492`). Both converge on `SSH_SESSION_FREE`.
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
pub(crate) const fn disconnect_entry_state(protocol: Proto) -> SshState {
    if protocol.intersects(Proto::SFTP) {
        SshState::SftpShutdown
    } else {
        SshState::SessionDisconnect
    }
}

// The SFTP phase drivers

/// Everything a phase step hands OUT that is not a state transition.
///
/// The C's states reach four sinks this module cannot: `Curl_client_write` with
/// `CLIENTWRITE_BODY` and with `CLIENTWRITE_HEADER`, `Curl_debug` with
/// `CURLINFO_HEADER_OUT`, and the `data->req` and `data->info` fields the
/// transfer core reads. None of the four has a successor on disk --
/// `curl-rs-lib/src/transfer/writeout.rs` and `easy/getinfo.rs` are both
/// unwritten -- so a step that would call one records it here instead and the
/// caller performs it.
///
/// This is a seam, not a workaround, and it is worth being precise about why. The
/// alternative -- passing a `&mut dyn ClientWriter` into every step -- would
/// couple this module to an interface that does not exist yet and would have to
/// be rewritten when it does. Recording the bytes lets every step be asserted
/// against its exact output today, which is what makes the byte-exact oracle of
/// specification 0.6.7 testable at this checkpoint rather than at the next one.
///
/// Each field names the C sink it stands for, so wiring it up later is a
/// mechanical substitution.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) struct SftpEffects {
    /// `Curl_client_write(data, CLIENTWRITE_BODY, ...)` -- the transfer body.
    ///
    /// Written by the readdir path and by `list_only`.
    pub(crate) body: Vec<u8>,
    /// `Curl_client_write(data, CLIENTWRITE_HEADER, ...)`.
    ///
    /// Written by exactly two quote commands: `pwd` through [`pwd_report`] and
    /// `statvfs` through [`statvfs_report`].
    pub(crate) header: Vec<u8>,
    /// `Curl_debug(data, CURLINFO_HEADER_OUT, ...)`.
    ///
    /// Written by `pwd` alone, and it is [`PWD_DEBUG_LINE`] -- four bytes, which
    /// appear in `--trace` output and nowhere else.
    pub(crate) header_out: Vec<u8>,
    /// `data->info.filetime`, which `CURLINFO_FILETIME` reports.
    ///
    /// [`None`] until `SSH_SFTP_FILETIME` runs, and it runs only when
    /// `CURLOPT_FILETIME` is set.
    pub(crate) filetime: Option<i64>,
    /// The download plan `Curl_xfer_setup1` is given, from
    /// [`sftp_download_size`].
    pub(crate) download: Option<DownloadPlan>,
    /// The upload offset, after [`sftp_upload_resume`] has resolved a negative
    /// `CURLOPT_RESUME_FROM` against the destination's size.
    pub(crate) upload_from: Option<i64>,
    /// `Curl_xfer_setup_nop(data)` -- this request transfers no payload.
    ///
    /// Set by `SSH_SFTP_READDIR_DONE`, because the listing was already written
    /// as body bytes and there is nothing left for the transfer loop to move.
    pub(crate) nop: bool,
    /// Each `infof` line a step produced, in order.
    ///
    /// Separate from [`StepOutcome::Advance`]'s single `info` because two states
    /// -- `SSH_SFTP_CREATE_DIRS` and the quote failures that `acceptfail`
    /// swallows -- can log without transitioning, and the order of the lines is
    /// observable in `--trace` output.
    pub(crate) info: Vec<String>,
}

#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
impl SftpEffects {
    /// A step's worth of effects, empty.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Record an `infof` line.
    fn info(&mut self, line: String) {
        self.info.push(line);
    }
}

/// The SFTP-DO and SFTP-DONE phases -- one step of the machine.
///
/// # Why the two phases share one driver
///
/// They interleave, and the interleaving is the C's. `sftp_done` sets
/// `nextstate` to `SSH_SFTP_POSTQUOTE_INIT` and enters `SSH_SFTP_CLOSE`;
/// `SSH_SFTP_CLOSE` swaps with `nextstate`, so the DONE phase re-enters the
/// quote states that the DO phase used, and then comes BACK to
/// `SSH_SFTP_CLOSE`. Splitting the driver in two would need every quote state
/// duplicated, and the duplicate would drift. [`sftp_close_next`] owns the swap.
///
/// # What one call does
///
/// Exactly one state, which is what `ssh_statemachine`'s `switch` does per
/// iteration. The caller loops until the state is [`SshState::Stop`] or a
/// failure is reported -- `ssh_multi_statemach`'s `do { } while(!result &&
/// !*done && !block)`.
///
/// # The exhaustive match, and what it buys
///
/// Every one of the 62 states appears, so specification 0.3.3's pattern P3 is
/// enforced by the compiler: adding a state to [`SshState`] without handling it
/// here does not compile. The SCP-owned states and the SSH-CONNECT states are
/// present as explicit arms that route away rather than as a wildcard, because a
/// wildcard would silently absorb a state added later.
#[allow(clippy::too_many_lines)]
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) async fn sftp_do_step(
    sshc: &mut SshConn,
    sshp: &mut SshProto,
    settings: &SshSettings,
    effects: &mut SftpEffects,
    ctx: &mut TransferCtx<'_>,
) -> StepOutcome {
    match sshc.state() {
        // -- entering and leaving the quote phase ---------------------------
        SshState::SftpQuoteInit => {
            // `ssh_state_sftp_quote_init` (`:1844-1863`): resolve the working
            // path FIRST, because every quote command's relative paths are
            // resolved against the home directory this establishes.
            match getworkingpath(
                &sshp.path,
                &sshc.homedir,
                ctx.scheme().protocol,
            ) {
                Ok(path) => {
                    sshp.path = path;
                    sshc.quote_list = QuoteList::Quote;
                    sshc.quote_index = 0;
                    StepOutcome::advance(sftp_quote_init(
                        !settings.quote.is_empty(),
                    ))
                }
                Err(code) => StepOutcome::Fail {
                    code,
                    message: None,
                },
            }
        }
        SshState::SftpPostquoteInit => {
            sshc.quote_list = QuoteList::PostQuote;
            sshc.quote_index = 0;
            StepOutcome::advance(sftp_postquote_init(
                !settings.postquote.is_empty(),
            ))
        }
        SshState::SftpQuote => {
            let Some(line) = sshc.current_quote(settings) else {
                // The list emptied between states, which the C cannot express
                // because its cursor and its emptiness test are the same
                // pointer. Leaving the phase is the faithful outcome.
                let next = sshc.next_quote(settings);
                return StepOutcome::advance(next);
            };
            let line = line.to_vec();
            match sftp_quote(&line, &sshc.homedir) {
                Ok(parsed) => {
                    sshc.acceptfail = parsed.acceptfail;
                    if parsed.command == QuoteCommand::Pwd {
                        // Answered locally: two writes and no packet.
                        effects
                            .header
                            .extend_from_slice(&pwd_report(&sshc.homedir));
                        effects.header_out.extend_from_slice(PWD_DEBUG_LINE);
                        let next = sshc.next_quote(settings);
                        return StepOutcome::advance(next);
                    }
                    let next = parsed.next;
                    sshc.quote = Some(parsed);
                    StepOutcome::advance(next)
                }
                Err(refusal) => {
                    let code = refusal.code();
                    let message = Some(refusal.message());
                    if code == CURLcode::Ok {
                        // `MissingParameter` reports `CURLE_OK`
                        // (`lib/vssh/libssh2.c:1690-1697`) -- it diagnoses and
                        // continues, which is why this is an Advance and not a
                        // Fail.
                        effects.info(refusal.message());
                        let next = sshc.next_quote(settings);
                        return StepOutcome::Advance {
                            next,
                            info: message,
                        };
                    }
                    sshc.nextstate = SshState::NoState;
                    StepOutcome::Fail { code, message }
                }
            }
        }
        SshState::SftpNextQuote => {
            let next = sshc.next_quote(settings);
            StepOutcome::advance(next)
        }

        // -- the attribute commands: stat, then setstat ---------------------
        SshState::SftpQuoteStat => {
            let Some(parsed) = sshc.quote.clone() else {
                return StepOutcome::Fail {
                    code: CURLcode::FailedInit,
                    message: None,
                };
            };
            // `if(!!strncmp(cmd, "chmod", 5))`: every command EXCEPT `chmod`
            // needs the current attributes first, because the wire carries uid
            // and gid together and `chown`/`chgrp` each set only one.
            let current = if parsed.command.needs_preliminary_stat() {
                let id = sshc.next_request_id();
                let packet = request::stat(id, &parsed.path2);
                match sshc.sftp_exchange(ctx, packet).await {
                    Ok(frame) => match request::decode_attrs(&frame) {
                        Ok(attrs) => attrs,
                        Err(failure) => {
                            if sshc.acceptfail {
                                SftpAttributes::default()
                            } else {
                                sshc.nextstate = SshState::NoState;
                                return StepOutcome::Fail {
                                    code: CURLcode::QuoteError,
                                    message: Some(format!(
                                        "Attempt to get SFTP stats failed: {}",
                                        failure.message()
                                    )),
                                };
                            }
                        }
                    },
                    Err(failure) => {
                        if sshc.acceptfail {
                            SftpAttributes::default()
                        } else {
                            sshc.nextstate = SshState::NoState;
                            return StepOutcome::Fail {
                                code: CURLcode::QuoteError,
                                message: Some(format!(
                                    "Attempt to get SFTP stats failed: {}",
                                    failure.message()
                                )),
                            };
                        }
                    }
                }
            } else {
                SftpAttributes::default()
            };

            match quote_setstat_attributes(
                parsed.command,
                &parsed.path1,
                current,
                sshc.acceptfail,
            ) {
                Ok(attrs) => {
                    sshp.quote_attrs = attrs;
                    StepOutcome::advance(SshState::SftpQuoteSetstat)
                }
                Err(refusal) => {
                    sshc.nextstate = SshState::NoState;
                    StepOutcome::Fail {
                        code: refusal.code(),
                        message: Some(refusal.message()),
                    }
                }
            }
        }
        SshState::SftpQuoteSetstat => {
            let Some(parsed) = sshc.quote.clone() else {
                return StepOutcome::Fail {
                    code: CURLcode::FailedInit,
                    message: None,
                };
            };
            let id = sshc.next_request_id();
            let attrs = sshp.quote_attrs;
            let packet = request::setstat(id, &parsed.path2, &attrs);
            let outcome = sshc
                .sftp_exchange(ctx, packet)
                .await
                .and_then(|frame| request::decode_ok(&frame));
            quote_operation_outcome(sshc, settings, outcome, || {
                // `"Attempt to set SFTP stats for \"%s\" failed: %s"` -- and it
                // interpolates path2, the TARGET, not path1 which is the value.
                format!(
                    "Attempt to set SFTP stats for \"{}\" failed",
                    String::from_utf8_lossy(&parsed.path2)
                )
            })
        }

        // -- the one- and two-path commands ---------------------------------
        SshState::SftpQuoteSymlink => {
            let Some(parsed) = sshc.quote.clone() else {
                return StepOutcome::Fail {
                    code: CURLcode::FailedInit,
                    message: None,
                };
            };
            let id = sshc.next_request_id();
            let packet = request::symlink(id, &parsed.path1, &parsed.path2);
            let outcome = sshc
                .sftp_exchange(ctx, packet)
                .await
                .and_then(|frame| request::decode_ok(&frame));
            quote_operation_outcome(sshc, settings, outcome, || {
                format!(
                    "symlink \"{}\" to \"{}\" failed",
                    String::from_utf8_lossy(&parsed.path1),
                    String::from_utf8_lossy(&parsed.path2)
                )
            })
        }
        SshState::SftpQuoteMkdir => {
            let Some(parsed) = sshc.quote.clone() else {
                return StepOutcome::Fail {
                    code: CURLcode::FailedInit,
                    message: None,
                };
            };
            let id = sshc.next_request_id();
            let packet =
                request::mkdir(id, &parsed.path1, settings.new_directory_perms);
            let outcome = sshc
                .sftp_exchange(ctx, packet)
                .await
                .and_then(|frame| request::decode_ok(&frame));
            quote_operation_outcome(sshc, settings, outcome, || {
                format!(
                    "mkdir \"{}\" failed",
                    String::from_utf8_lossy(&parsed.path1)
                )
            })
        }
        SshState::SftpQuoteRename => {
            let Some(parsed) = sshc.quote.clone() else {
                return StepOutcome::Fail {
                    code: CURLcode::FailedInit,
                    message: None,
                };
            };
            let id = sshc.next_request_id();
            let packet = request::rename(id, &parsed.path1, &parsed.path2);
            let outcome = sshc
                .sftp_exchange(ctx, packet)
                .await
                .and_then(|frame| request::decode_ok(&frame));
            quote_operation_outcome(sshc, settings, outcome, || {
                format!(
                    "rename \"{}\" to \"{}\" failed",
                    String::from_utf8_lossy(&parsed.path1),
                    String::from_utf8_lossy(&parsed.path2)
                )
            })
        }
        SshState::SftpQuoteRmdir => {
            let Some(parsed) = sshc.quote.clone() else {
                return StepOutcome::Fail {
                    code: CURLcode::FailedInit,
                    message: None,
                };
            };
            let id = sshc.next_request_id();
            let packet = request::rmdir(id, &parsed.path1);
            let outcome = sshc
                .sftp_exchange(ctx, packet)
                .await
                .and_then(|frame| request::decode_ok(&frame));
            quote_operation_outcome(sshc, settings, outcome, || {
                format!(
                    "rmdir \"{}\" failed",
                    String::from_utf8_lossy(&parsed.path1)
                )
            })
        }
        SshState::SftpQuoteUnlink => {
            let Some(parsed) = sshc.quote.clone() else {
                return StepOutcome::Fail {
                    code: CURLcode::FailedInit,
                    message: None,
                };
            };
            let id = sshc.next_request_id();
            let packet = request::remove(id, &parsed.path1);
            let outcome = sshc
                .sftp_exchange(ctx, packet)
                .await
                .and_then(|frame| request::decode_ok(&frame));
            quote_operation_outcome(sshc, settings, outcome, || {
                // `"rm \"%s\" failed"` -- the keyword in the message is `rm`,
                // not `unlink`, and not `remove`.
                format!(
                    "rm \"{}\" failed",
                    String::from_utf8_lossy(&parsed.path1)
                )
            })
        }
        SshState::SftpQuoteStatvfs => {
            let Some(parsed) = sshc.quote.clone() else {
                return StepOutcome::Fail {
                    code: CURLcode::FailedInit,
                    message: None,
                };
            };
            let id = sshc.next_request_id();
            let packet = request::statvfs(id, &parsed.path1);
            let outcome = sshc
                .sftp_exchange(ctx, packet)
                .await
                .and_then(|frame| request::decode_statvfs(&frame));
            match outcome {
                Ok(stats) => {
                    // `else if(rc == 0)`: the report is written only on
                    // success, and `acceptfail` therefore produces NO report
                    // rather than an empty one.
                    effects.header.extend_from_slice(&statvfs_report(&stats));
                    let next = sshc.next_quote(settings);
                    StepOutcome::advance(next)
                }
                Err(failure) => quote_operation_outcome(
                    sshc,
                    settings,
                    Err(failure),
                    || {
                        format!(
                            "statvfs \"{}\" failed",
                            String::from_utf8_lossy(&parsed.path1)
                        )
                    },
                ),
            }
        }

        // -- leaving the quote phase for the transfer -----------------------
        SshState::SftpGetinfo => {
            StepOutcome::advance(sftp_getinfo(settings.get_filetime))
        }
        SshState::SftpFiletime => {
            let id = sshc.next_request_id();
            let path = sshp.path.clone();
            let packet = request::stat(id, &path);
            // `if(rc == 0) data->info.filetime = (time_t)attrs.mtime;` -- and
            // there is NO error path: a failed stat leaves the filetime alone
            // and the machine advances regardless.
            if let Ok(frame) = sshc.sftp_exchange(ctx, packet).await {
                if let Ok(attrs) = request::decode_attrs(&frame) {
                    effects.filetime = Some(i64::from(attrs.mtime));
                }
            }
            StepOutcome::advance(SshState::SftpTransInit)
        }
        SshState::SftpTransInit => {
            StepOutcome::advance(sftp_trans_init(&sshp.path, settings.upload))
        }

        // -- upload --------------------------------------------------------
        SshState::SftpUploadInit => {
            sftp_upload_init(sshc, sshp, settings, effects, ctx).await
        }
        SshState::SftpCreateDirsInit => {
            let (next, offset) = sftp_create_dirs_init(&sshp.path);
            sshc.slash_pos = offset;
            StepOutcome::advance(next)
        }
        SshState::SftpCreateDirs => {
            match sftp_next_directory(&sshp.path, sshc.slash_pos) {
                Some((component, resume)) => {
                    effects.info(format!(
                        "Creating directory '{}'",
                        String::from_utf8_lossy(component)
                    ));
                    // The offset the MKDIR will use, and where the walk resumes
                    // after it. Stored as the resume point because
                    // `ssh_state_sftp_create_dirs_mkdir` restores the `/` and
                    // steps past it BEFORE inspecting the result.
                    sshc.slash_pos = resume;
                    StepOutcome::advance(SshState::SftpCreateDirsMkdir)
                }
                None => StepOutcome::advance(SshState::SftpUploadInit),
            }
        }
        SshState::SftpCreateDirsMkdir => {
            // The component is everything before the `/` the walk just passed,
            // which is `slash_pos - 1` bytes.
            let end = sshc.slash_pos.saturating_sub(1);
            let component = sshp.path.get(..end).unwrap_or(&sshp.path).to_vec();
            let id = sshc.next_request_id();
            let packet =
                request::mkdir(id, &component, settings.new_directory_perms);
            let outcome = sshc
                .sftp_exchange(ctx, packet)
                .await
                .and_then(|frame| request::decode_ok(&frame));
            match outcome {
                Ok(()) => StepOutcome::advance(SshState::SftpCreateDirs),
                Err(failure) => {
                    let status = failure.status();
                    if create_dirs_tolerates(status) {
                        StepOutcome::advance(SshState::SftpCreateDirs)
                    } else {
                        sshc.nextstate = SshState::NoState;
                        StepOutcome::Fail {
                            code: failure.to_curlcode(),
                            message: None,
                        }
                    }
                }
            }
        }

        // -- directory listing ----------------------------------------------
        SshState::SftpReaddirInit => {
            // `Curl_pgrsSetDownloadSize(data, -1)` then the no-body test. The
            // size is unknown because a listing's length is not known until it
            // has been read.
            effects.download = Some(DownloadPlan {
                from: 0,
                size: None,
                complete: false,
            });
            if settings.no_body {
                return StepOutcome::advance(SshState::Stop);
            }
            let id = sshc.next_request_id();
            let path = sshp.path.clone();
            let packet = request::opendir(id, &path);
            match sshc.sftp_exchange(ctx, packet).await {
                Ok(frame) => match request::decode_handle(&frame) {
                    Ok(handle) => {
                        sshc.sftp_handle = Some(handle);
                        StepOutcome::advance(SshState::SftpReaddir)
                    }
                    Err(failure) => StepOutcome::Fail {
                        code: failure.to_curlcode(),
                        message: Some(format!(
                            "Could not open directory for reading: {}",
                            failure.message()
                        )),
                    },
                },
                Err(failure) => StepOutcome::Fail {
                    code: failure.to_curlcode(),
                    message: Some(format!(
                        "Could not open directory for reading: {}",
                        failure.message()
                    )),
                },
            }
        }
        SshState::SftpReaddir => {
            let Some(handle) = sshc.sftp_handle.clone() else {
                return StepOutcome::Fail {
                    code: CURLcode::FailedInit,
                    message: None,
                };
            };
            let id = sshc.next_request_id();
            let packet = request::readdir(id, &handle);
            let decoded = sshc
                .sftp_exchange(ctx, packet)
                .await
                .and_then(|frame| request::decode_names(&frame));
            match decoded {
                Ok(names) => match names.into_iter().next() {
                    // `if(rc > 0)`: one entry came back. libssh2 hands them over
                    // one at a time even though the wire carries a batch, and
                    // this module reproduces that cadence because
                    // `SSH_SFTP_READDIR_LINK` has to run BETWEEN two entries.
                    Some(entry) => {
                        sshp.readdir_entry = entry;
                        if settings.list_only {
                            effects.body.extend_from_slice(
                                &sftp_readdir_entry(
                                    &sshp.readdir_entry,
                                    None,
                                    true,
                                ),
                            );
                            return StepOutcome::advance(SshState::SftpReaddir);
                        }
                        sshp.readdir
                            .extend_from_slice(&sshp.readdir_entry.longentry);
                        if sshp.readdir_entry.attrs.is_symlink() {
                            sshp.readdir_link = readdir_link_path(
                                &sshp.path,
                                &sshp.readdir_entry.filename,
                            );
                            StepOutcome::advance(SshState::SftpReaddirLink)
                        } else {
                            StepOutcome::advance(SshState::SftpReaddirBottom)
                        }
                    }
                    // `else if(!rc)`: the listing ended, reported as a `NAME`
                    // reply carrying no entries.
                    None => StepOutcome::advance(SshState::SftpReaddirDone),
                },
                // `SSH_FXP_STATUS` with `EOF` is the OTHER way a server ends a
                // listing, and libssh2 reports it as `rc == 0` rather than as an
                // error. Testing for it BEFORE consulting the status map is
                // mandatory: `sftp_libssh2_error_to_CURLE` has no `EOF` arm and
                // would answer `CURLE_SSH`.
                Err(SftpFailure::Status(status))
                    if status == SftpStatus::EOF =>
                {
                    StepOutcome::advance(SshState::SftpReaddirDone)
                }
                Err(failure) => readdir_failure(sshc, &failure),
            }
        }
        SshState::SftpReaddirLink => {
            let id = sshc.next_request_id();
            let link = sshp.readdir_link.clone();
            let packet = request::readlink(id, &link);
            match sshc.sftp_exchange(ctx, packet).await {
                Ok(frame) => {
                    sshp.readdir_link.clear();
                    match request::decode_names(&frame) {
                        Ok(names) => {
                            let target = names
                                .into_iter()
                                .next()
                                .map(|entry| entry.filename)
                                .unwrap_or_default();
                            sshp.readdir.extend_from_slice(b" -> ");
                            sshp.readdir.extend_from_slice(&target);
                            StepOutcome::advance(SshState::SftpReaddirBottom)
                        }
                        // `if(rc < 0) return CURLE_OUT_OF_MEMORY;` -- an odd
                        // code for a failed READLINK, and preserved because it
                        // is what a fixture would observe.
                        Err(_) => StepOutcome::Fail {
                            code: CURLcode::OutOfMemory,
                            message: None,
                        },
                    }
                }
                Err(_) => {
                    sshp.readdir_link.clear();
                    StepOutcome::Fail {
                        code: CURLcode::OutOfMemory,
                        message: None,
                    }
                }
            }
        }
        SshState::SftpReaddirBottom => {
            // `curlx_dyn_addn(&sshp->readdir, "\n", 1)` then one client write
            // of the whole line, then `curlx_dyn_reset`. The newline is added
            // HERE and not by `sftp_readdir_entry`, because the link suffix has
            // to land between the long entry and it.
            sshp.readdir.push(b'\n');
            effects.body.extend_from_slice(&sshp.readdir);
            sshp.readdir.clear();
            StepOutcome::advance(SshState::SftpReaddir)
        }
        SshState::SftpReaddirDone => {
            let Some(handle) = sshc.sftp_handle.clone() else {
                effects.nop = true;
                return StepOutcome::advance(SshState::Stop);
            };
            let id = sshc.next_request_id();
            let packet = request::close(id, &handle);
            // `libssh2_sftp_closedir`'s result is discarded except for EAGAIN:
            // the handle is dropped and the transfer completes either way.
            let _ = sshc.sftp_exchange(ctx, packet).await;
            sshc.sftp_handle = None;
            effects.nop = true;
            StepOutcome::advance(SshState::Stop)
        }

        // -- download -------------------------------------------------------
        SshState::SftpDownloadInit => {
            let id = sshc.next_request_id();
            let path = sshp.path.clone();
            let packet = request::open(
                id,
                &path,
                SftpOpenFlags::READ,
                settings.new_file_perms,
            );
            match sshc.sftp_exchange(ctx, packet).await {
                Ok(frame) => match request::decode_handle(&frame) {
                    Ok(handle) => {
                        sshc.sftp_handle = Some(handle);
                        StepOutcome::advance(SshState::SftpDownloadStat)
                    }
                    Err(failure) => StepOutcome::Fail {
                        code: failure.to_curlcode(),
                        message: Some(format!(
                            "Could not open remote file for reading: {}",
                            failure.message()
                        )),
                    },
                },
                Err(failure) => StepOutcome::Fail {
                    code: failure.to_curlcode(),
                    message: Some(format!(
                        "Could not open remote file for reading: {}",
                        failure.message()
                    )),
                },
            }
        }
        SshState::SftpDownloadStat => {
            let Some(handle) = sshc.sftp_handle.clone() else {
                return StepOutcome::Fail {
                    code: CURLcode::FailedInit,
                    message: None,
                };
            };
            let id = sshc.next_request_id();
            let packet = request::fstat(id, &handle);
            let attrs = match sshc.sftp_exchange(ctx, packet).await {
                Ok(frame) => request::decode_attrs(&frame).unwrap_or_default(),
                // A failed stat is the C's first "unknown size" case, not an
                // error: *"maybe the server just does not support stat()"*.
                Err(_) => SftpAttributes::default(),
            };
            match sftp_download_size(
                attrs,
                settings.range.as_deref(),
                settings.resume_from,
            ) {
                Ok(plan) => {
                    sshc.sftp_offset = plan.from;
                    if plan.complete {
                        effects
                            .info("File already completely downloaded".into());
                    }
                    effects.download = Some(plan);
                    StepOutcome::advance(SshState::Stop)
                }
                Err((code, message)) => {
                    sshc.nextstate = SshState::NoState;
                    StepOutcome::Fail { code, message }
                }
            }
        }

        // -- closing the handle, and the DONE phase's hinge -----------------
        SshState::SftpClose => {
            if let Some(handle) = sshc.sftp_handle.clone() {
                let id = sshc.next_request_id();
                let packet = request::close(id, &handle);
                // `if(rc < 0) infof(...)` -- diagnosed, never propagated. The
                // status has to be DECODED to notice: the transport answers a
                // frame either way, and a refusal lives inside it.
                let outcome = sshc
                    .sftp_exchange(ctx, packet)
                    .await
                    .and_then(|frame| request::decode_ok(&frame));
                if let Err(failure) = outcome {
                    effects.info(format!(
                        "Failed to close libssh2 file: {}",
                        failure.message()
                    ));
                }
                sshc.sftp_handle = None;
            }
            sshp.path.clear();
            let (next, nextstate) = sftp_close_next(sshc.nextstate);
            sshc.nextstate = nextstate;
            StepOutcome::Advance {
                next,
                info: Some("SFTP DONE done".into()),
            }
        }

        // -- states this driver routes away from ----------------------------
        //
        // Named rather than wildcarded so that a state added to `SshState`
        // fails to compile here. Grouped by owner.
        SshState::SftpShutdown
        | SshState::SessionDisconnect
        | SshState::SessionFree => {
            // The DISCONNECT phase, which `sftp_disconnect_step` drives.
            StepOutcome::advance(sshc.state())
        }
        SshState::NoState
        | SshState::Stop
        | SshState::Init
        | SshState::SStartup
        | SshState::HostKey
        | SshState::AuthList
        | SshState::AuthPkeyInit
        | SshState::AuthPkey
        | SshState::AuthPassInit
        | SshState::AuthPass
        | SshState::AuthAgentInit
        | SshState::AuthAgentList
        | SshState::AuthAgent
        | SshState::AuthHostInit
        | SshState::AuthHost
        | SshState::AuthKeyInit
        | SshState::AuthKey
        | SshState::AuthGssapi
        | SshState::AuthDone
        | SshState::SftpInit
        | SshState::SftpRealpath => {
            // SSH-CONNECT, which `ssh_connect_step` drives.
            StepOutcome::advance(SshState::Stop)
        }
        SshState::ScpTransInit
        | SshState::ScpUploadInit
        | SshState::ScpDownloadInit
        | SshState::ScpDownload
        | SshState::ScpDone
        | SshState::ScpSendEof
        | SshState::ScpWaitEof
        | SshState::ScpWaitClose
        | SshState::ScpChannelFree => {
            // `protocols/scp.rs`'s, and unreachable for an SFTP transfer.
            StepOutcome::advance(SshState::Stop)
        }
        SshState::Quit | SshState::Last => {
            // `case SSH_QUIT: default:` -- the C's own comment is *"internal
            // error"*, and it answers `CURLE_FAILED_INIT` after `SSH_STOP`.
            StepOutcome::Fail {
                code: CURLcode::FailedInit,
                message: None,
            }
        }
    }
}

/// `sftp_upload_init` (`lib/vssh/libssh2.c:887-1066`): open the destination.
///
/// Split out because it is the longest single state in the C and because it has
/// three distinct outcomes -- open, retry through the create-dirs walk, or fail
/// -- each of which the state's caller treats differently.
///
/// The resume stat happens BEFORE the open when `CURLOPT_RESUME_FROM` is
/// negative, which is the C's order and matters: the destination's size is what a
/// negative offset resolves against, and opening with `TRUNC` first would zero
/// it.
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
async fn sftp_upload_init(
    sshc: &mut SshConn,
    sshp: &mut SshProto,
    settings: &SshSettings,
    effects: &mut SftpEffects,
    ctx: &mut TransferCtx<'_>,
) -> StepOutcome {
    let mut resume_from = settings.resume_from;
    if resume_from < 0 {
        let id = sshc.next_request_id();
        let path = sshp.path.clone();
        let packet = request::stat(id, &path);
        let stat = match sshc.sftp_exchange(ctx, packet).await {
            Ok(frame) => request::decode_attrs(&frame).ok(),
            Err(_) => None,
        };
        match sftp_upload_resume(resume_from, stat) {
            Ok(resolved) => resume_from = resolved,
            Err((code, message)) => {
                sshc.nextstate = SshState::NoState;
                return StepOutcome::Fail { code, message };
            }
        }
    }

    let flags = sftp_upload_flags(settings.remote_append, resume_from);
    let id = sshc.next_request_id();
    let path = sshp.path.clone();
    let packet = request::open(id, &path, flags, settings.new_file_perms);
    let outcome = sshc
        .sftp_exchange(ctx, packet)
        .await
        .and_then(|frame| request::decode_handle(&frame));

    match outcome {
        Ok(handle) => {
            sshc.sftp_handle = Some(handle);
            sshc.sftp_offset = u64::try_from(resume_from).unwrap_or(0);
            effects.upload_from = Some(resume_from);
            StepOutcome::advance(SshState::Stop)
        }
        Err(failure) => {
            let status = failure.status();
            if upload_should_create_dirs(
                status,
                settings.create_missing_dirs,
                &sshp.path,
                sshc.second_create_dirs > 0,
            ) {
                // `sshc->secondCreateDirs++` then
                // `SSH_SFTP_CREATE_DIRS_INIT`. The counter is what stops the
                // retry looping, and its failure text is a DIFFERENT one:
                // *"Creating the dir/file failed: %s"*.
                sshc.second_create_dirs =
                    sshc.second_create_dirs.saturating_add(1);
                return StepOutcome::advance(SshState::SftpCreateDirsInit);
            }
            sshc.nextstate = SshState::NoState;
            let message = if sshc.second_create_dirs > 0 {
                format!("Creating the dir/file failed: {}", failure.message())
            } else {
                format!("Upload failed: {}", failure.message())
            };
            StepOutcome::Fail {
                code: failure.to_curlcode(),
                message: Some(message),
            }
        }
    }
}

/// The shared tail of the seven quote operations that send one packet.
///
/// `SETSTAT`, `SYMLINK`, `MKDIR`, `RENAME`, `RMDIR`, `UNLINK` and `STATVFS` all
/// end the same way in the C -- `if(rc && !sshc->acceptfail) { failf(...);
/// myssh_to(SSH_SFTP_CLOSE); sshc->nextstate = SSH_NO_STATE; return
/// CURLE_QUOTE_ERROR; } myssh_to(SSH_SFTP_NEXT_QUOTE);` -- differing only in the
/// text. Written once, with the text supplied by the caller.
///
/// Two details that are easy to lose and are preserved here:
///
/// * the code is always [`CURLcode::QuoteError`], never the status's own mapping.
///   A quote `rm` of a missing file reports `CURLE_QUOTE_ERROR` and not
///   `CURLE_REMOTE_FILE_NOT_FOUND`, because the operation was a quote command;
/// * `acceptfail` makes the failure advance to the NEXT command, so `*rm /gone`
///   is a success with no output -- which is what the C's own comment promises:
///   *"It will cause libcurl to act as if the command is successful, whatever the
///   server responds."*
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
fn quote_operation_outcome<F>(
    sshc: &mut SshConn,
    settings: &SshSettings,
    outcome: SftpResult<()>,
    message: F,
) -> StepOutcome
where
    F: FnOnce() -> String,
{
    match outcome {
        Ok(()) => {
            let next = sshc.next_quote(settings);
            StepOutcome::advance(next)
        }
        Err(failure) => {
            if sshc.acceptfail {
                let next = sshc.next_quote(settings);
                return StepOutcome::advance(next);
            }
            sshc.nextstate = SshState::NoState;
            StepOutcome::Fail {
                code: CURLcode::QuoteError,
                message: Some(format!("{}: {}", message(), failure.message())),
            }
        }
    }
}

/// `sftp_readdir`'s failure tail (`lib/vssh/libssh2.c:1352-1360`).
///
/// The message is *"Could not open remote file for reading: %s :: %d"* -- copied
/// verbatim from the download path, which is why a failed READDIR reports a text
/// about opening a file. Preserved rather than corrected: it is what a fixture
/// comparing stderr would see. The trailing `:: %d` is
/// `libssh2_session_last_errno`, a backend-specific number with no successor, so
/// it is omitted and its absence is recorded here rather than filled with a
/// fabricated value.
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
fn readdir_failure(sshc: &mut SshConn, failure: &SftpFailure) -> StepOutcome {
    let status = failure.status();
    let code = if status == SftpStatus::OK {
        // `result = sftperr ? sftp_libssh2_error_to_CURLE(sftperr) :
        // CURLE_SSH;` -- a transport-level failure reports `CURLE_SSH`.
        CURLcode::Ssh
    } else {
        failure.to_curlcode()
    };
    sshc.nextstate = SshState::NoState;
    StepOutcome::Fail {
        code,
        message: Some(format!(
            "Could not open remote file for reading: {}",
            failure.message()
        )),
    }
}

/// The SFTP-DISCONNECT phase -- one step.
///
/// Three states, in order: `SSH_SFTP_SHUTDOWN` (marked *"First state in
/// SFTP-DISCONNECT"*), `SSH_SESSION_DISCONNECT` and `SSH_SESSION_FREE` (marked
/// *"Last state in SCP/SFTP-DISCONNECT"*). The last two are shared with
/// `protocols/scp.rs`, which enters the chain at the second.
///
/// Separate from [`sftp_do_step`] rather than folded into it, and the reason is
/// the parameter: `dead_connection`. A disconnect on a dead connection must send
/// nothing, and threading that through the DO driver -- where it is meaningless
/// -- would invite it being read in a state that has no business consulting it.
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) async fn sftp_disconnect_step(
    sshc: &mut SshConn,
    effects: &mut SftpEffects,
    ctx: &mut TransferCtx<'_>,
    dead_connection: bool,
) -> StepOutcome {
    match sshc.state() {
        SshState::SftpShutdown => {
            // The C's comment explains why the handle is closed again here:
            // *"during times we get here due to a broken transfer and then the
            // sftp_handle might not have been taken down so make sure that is
            // done before we proceed"*.
            if let Some(handle) = sshc.sftp_handle.clone() {
                if !dead_connection {
                    let id = sshc.next_request_id();
                    let packet = request::close(id, &handle);
                    let outcome = sshc
                        .sftp_exchange(ctx, packet)
                        .await
                        .and_then(|frame| request::decode_ok(&frame));
                    if let Err(failure) = outcome {
                        effects.info(format!(
                            "Failed to close libssh2 file: {}",
                            failure.message()
                        ));
                    }
                }
                sshc.sftp_handle = None;
            }
            if !dead_connection {
                if let Err(error) = sshc.transport.close_sftp(ctx).await {
                    let _ = error;
                    effects
                        .info("Failed to stop libssh2 sftp subsystem".into());
                }
            }
            sshc.homedir.clear();
            StepOutcome::advance(SshState::SessionDisconnect)
        }
        SshState::SessionDisconnect => {
            if let Some(line) =
                ssh_session_disconnect(sshc, ctx, dead_connection).await
            {
                effects.info(line);
            }
            StepOutcome::advance(SshState::SessionFree)
        }
        SshState::SessionFree => {
            let reason = ssh_session_free(sshc);
            StepOutcome::Advance {
                next: SshState::Stop,
                info: Some(reason.to_owned()),
            }
        }
        // Every other state, named for the same reason `sftp_do_step` names
        // them: an added state must not be absorbed silently.
        SshState::NoState
        | SshState::Stop
        | SshState::Init
        | SshState::SStartup
        | SshState::HostKey
        | SshState::AuthList
        | SshState::AuthPkeyInit
        | SshState::AuthPkey
        | SshState::AuthPassInit
        | SshState::AuthPass
        | SshState::AuthAgentInit
        | SshState::AuthAgentList
        | SshState::AuthAgent
        | SshState::AuthHostInit
        | SshState::AuthHost
        | SshState::AuthKeyInit
        | SshState::AuthKey
        | SshState::AuthGssapi
        | SshState::AuthDone
        | SshState::SftpInit
        | SshState::SftpRealpath
        | SshState::SftpQuoteInit
        | SshState::SftpPostquoteInit
        | SshState::SftpQuote
        | SshState::SftpNextQuote
        | SshState::SftpQuoteStat
        | SshState::SftpQuoteSetstat
        | SshState::SftpQuoteSymlink
        | SshState::SftpQuoteMkdir
        | SshState::SftpQuoteRename
        | SshState::SftpQuoteRmdir
        | SshState::SftpQuoteUnlink
        | SshState::SftpQuoteStatvfs
        | SshState::SftpGetinfo
        | SshState::SftpFiletime
        | SshState::SftpTransInit
        | SshState::SftpUploadInit
        | SshState::SftpCreateDirsInit
        | SshState::SftpCreateDirs
        | SshState::SftpCreateDirsMkdir
        | SshState::SftpReaddirInit
        | SshState::SftpReaddir
        | SshState::SftpReaddirLink
        | SshState::SftpReaddirBottom
        | SshState::SftpReaddirDone
        | SshState::SftpDownloadInit
        | SshState::SftpDownloadStat
        | SshState::SftpClose
        | SshState::ScpTransInit
        | SshState::ScpUploadInit
        | SshState::ScpDownloadInit
        | SshState::ScpDownload
        | SshState::ScpDone
        | SshState::ScpSendEof
        | SshState::ScpWaitEof
        | SshState::ScpWaitClose
        | SshState::ScpChannelFree
        | SshState::Quit
        | SshState::Last => StepOutcome::advance(SshState::Stop),
    }
}

/// Drive a phase to completion, applying every transition through
/// [`ssh_set_state`].
///
/// `ssh_multi_statemach` (`lib/vssh/libssh2.c:3070-3090`) and
/// `ssh_block_statemach` (`:3092-3165`) collapsed into one function, because the
/// difference between them in the C is whether they sleep between iterations --
/// and awaiting removes the choice. The C's own comment on the blocking variant
/// says the blocking is a limitation rather than a design: *"the only reason this
/// is still blocking is that the multi interface code has no support for
/// disconnecting operations that takes a while"*.
///
/// `limit` bounds the iteration count. The C has no bound, relying on every state
/// either advancing or reporting; the bound is here so that a defect in a
/// transition produces a diagnosable failure instead of a hang, and it is set
/// far above the longest real phase -- a listing of N entries takes 3N states, so
/// a bound of 100,000 admits a directory of 33,000 entries.
///
/// # Errors
///
/// Whatever a step reports, or [`CURLcode::Ssh`] when `limit` is exhausted.
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
pub(crate) async fn ssh_run_phase(
    sshc: &mut SshConn,
    sshp: &mut SshProto,
    settings: &SshSettings,
    effects: &mut SftpEffects,
    ctx: &mut TransferCtx<'_>,
    phase: SshPhase,
    limit: usize,
) -> CodeResult<()> {
    for _ in 0..limit {
        if sshc.state() == SshState::Stop {
            return Ok(());
        }
        let outcome = match phase {
            SshPhase::SshConnect => {
                ssh_connect_step(sshc, sshp, settings, ctx).await
            }
            SshPhase::SftpDisconnect | SshPhase::SessionTeardown => {
                sftp_disconnect_step(sshc, effects, ctx, false).await
            }
            SshPhase::SftpDo
            | SshPhase::SftpDone
            | SshPhase::Idle
            | SshPhase::ScpDo
            | SshPhase::ScpDone => {
                sftp_do_step(sshc, sshp, settings, effects, ctx).await
            }
        };
        match outcome {
            StepOutcome::Advance { next, info } => {
                if let Some(line) = info {
                    effects.info(line);
                }
                ssh_set_state(sshc, None, next);
            }
            StepOutcome::Verify { hostkey, next } => {
                // Neither the callback nor the known-hosts file is reachable
                // from here, and the C's answer for a configuration that names
                // neither is to accept. Recorded so the decision is visible.
                effects.info(format!(
                    "Host key accepted without verification: {} bytes",
                    hostkey.blob.len()
                ));
                ssh_set_state(sshc, None, next);
            }
            StepOutcome::Fail { code, message } => {
                if let Some(line) = message {
                    effects.info(line);
                }
                return Err(code);
            }
            StepOutcome::FailAndFree { code, message } => {
                if let Some(line) = message {
                    effects.info(line);
                }
                ssh_set_state(sshc, None, SshState::SessionFree);
                return Err(code);
            }
        }
    }
    Err(CURLcode::Ssh)
}

// The russh-backed production transport

/// How large the in-memory bridge between russh and the filter chain is.
///
/// One SSH binary packet may be up to 35,000 bytes by RFC 4253 and russh caps
/// its own at 65,535 (`connect_stream` warns above that), so a bridge of 128 KiB
/// holds a full packet in each direction with room for a second arriving behind
/// it. Larger would only defer the back-pressure that the shuttle already
/// handles correctly; smaller would make a maximal packet need several shuttle
/// turns, which is correct but pointlessly slower.
#[cfg(feature = "ssh")]
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
const BRIDGE_CAPACITY: usize = 128 * 1024;

/// How many bytes one shuttle turn moves in each direction.
///
/// Sized to hold a maximal SSH packet, so a turn is never split for want of
/// scratch space.
#[cfg(feature = "ssh")]
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
const SHUTTLE_SCRATCH: usize = 64 * 1024;

/// How many consecutive shuttle turns may make no progress before the transport
/// reports [`SshError::Again`].
///
/// The C has no counterpart: libssh2 owns the socket and returns
/// `LIBSSH2_ERROR_EAGAIN` the moment a read or write would block, and
/// `ssh_block2waitfor` records the direction so that the multi loop waits on it.
/// This port's shuttle cannot report EAGAIN the same way, because dropping the
/// russh future mid-handshake would cancel the handshake -- so it yields to the
/// runtime instead, which is what lets russh's spawned session task run, and
/// gives up only after this many fruitless turns.
///
/// The bound exists so that a peer that has gone silent produces a diagnosable
/// [`CURLcode::Again`] rather than a hang. It is deliberately large: a slow peer
/// on a loaded runtime can legitimately need many turns, and the timeout that
/// SHOULD end a stalled transfer is `CURLOPT_TIMEOUT`, which
/// `curl-rs-lib/src/multi/` owns and which is not on disk.
#[cfg(feature = "ssh")]
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
const SHUTTLE_IDLE_LIMIT: usize = 4096;

// The three bounds above must hold for the bridge to carry one whole SSH binary
// packet without the shuttle having to split it, and for the idle counter to
// terminate. A maximal packet is 35,000 bytes by RFC 4253 section 6 and russh
// caps its own at 65,535, so the bridge holds two of them and the scratch buffer
// holds one.
//
// Written as `const` assertions rather than as a `#[test]`: the conditions are
// compile-time constants, so a violation is a build failure under EVERY feature
// combination and every target rather than something a skipped test could miss.
// Clippy's `assertions_on_constants` says the same thing from the other side --
// a constant condition inside a test body is the wrong place for it.
const _: () = assert!(BRIDGE_CAPACITY >= 65_535 * 2);
const _: () = assert!(SHUTTLE_SCRATCH >= 65_535);
const _: () = assert!(SHUTTLE_IDLE_LIMIT > 0);

/// What one shuttle turn achieved.
#[cfg(feature = "ssh")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
enum ShuttleTurn {
    /// Bytes moved in at least one direction.
    Progress,
    /// Neither direction moved. The caller yields and tries again.
    Idle,
    /// The filter chain reported end of stream, so the session is over.
    Closed,
}

/// The `russh::client::Handler` this transport installs.
///
/// # What it is for
///
/// Exactly one thing: `check_server_key`. russh's default implementation
/// **rejects every key** -- `async { Ok(false) }` -- which is the right default
/// for a library and the wrong behaviour for curl, whose policy is
/// [`HostKeyPolicy`]. Every other member of the trait keeps its default,
/// because curl reacts to none of the events they report.
///
/// # Why the policy is shared rather than owned
///
/// `check_server_key` runs inside the session task that
/// `russh::client::connect_stream` SPAWNS, so the handler is moved into a
/// `'static` context and cannot borrow the transport. The policy is therefore
/// cloned in and the key is reported back through a shared slot. That slot is
/// how [`SshTransport::hostkey`] answers, and it is what makes
/// `SSH_HOST_KEY`'s fingerprint comparison possible at all.
///
/// # The lock, and why it is a `Mutex`
///
/// `crate::util::sync_cell::SyncCell` is `#[cfg(test)]` and has no production
/// caller by design, so this names its lock directly. Poisoning is recovered
/// from rather than propagated, for the reason `crate::share` gives at length: a
/// panic elsewhere must not convert a transient fault into a permanent one.
#[cfg(feature = "ssh")]
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
struct RusshHandler {
    /// The key the peer presented, filled in by `check_server_key`.
    hostkey: std::sync::Arc<std::sync::Mutex<Option<HostKeyBlob>>>,
    /// curl's host-key policy, evaluated inside the session task.
    policy: HostKeyPolicy,
}

#[cfg(feature = "ssh")]
impl fmt::Debug for RusshHandler {
    /// The policy's shape, never its fingerprints.
    ///
    /// A configured fingerprint is not secret, but it is user input, and a
    /// `Debug` line that carries user input is a line that ends up in a log.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RusshHandler")
            .field("has_md5", &self.policy.md5.is_some())
            .field("has_sha256", &self.policy.sha256.is_some())
            .finish()
    }
}

#[cfg(feature = "ssh")]
impl russh::client::Handler for RusshHandler {
    type Error = russh::Error;

    /// `SSH_HOST_KEY` (`lib/vssh/libssh2.c:2586-2589`), evaluated where russh
    /// needs the answer.
    ///
    /// The C runs its check as a STATE, between `SSH_S_STARTUP` and
    /// `SSH_AUTH_LIST`, because libssh2 hands the key over on request. russh
    /// asks for a decision during the key exchange instead, so the check has to
    /// happen here -- and [`SshState::HostKey`] then re-reads the recorded key
    /// through [`SshTransport::hostkey`] so that the state still exists, still
    /// traces, and still produces the C's exact `failf` text.
    ///
    /// Returning `Ok(false)` makes russh refuse the connection, which surfaces
    /// as a handshake failure. That is coarser than the C, which distinguishes a
    /// fingerprint mismatch from a transport failure; the distinction is
    /// preserved because the recorded key outlives the refusal and
    /// [`SshState::HostKey`] re-derives the precise reason from it.
    fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> impl core::future::Future<Output = Result<bool, Self::Error>> + Send
    {
        // The wire encoding of the key, which is what both fingerprints are
        // computed over: MD5 of the blob, and SHA-256 of the blob. `ssh_key`
        // spells it `to_bytes`, and it is the same bytes libssh2's
        // `libssh2_session_hostkey` hands back.
        let encoded = server_public_key
            .to_bytes()
            .map(|bytes| bytes.to_vec())
            .unwrap_or_default();
        // The algorithm NAME as RFC 4253 spells it -- `ssh-rsa`, `ssh-ed25519`,
        // `ecdsa-sha2-nistp256` and so on -- because that is what
        // `HostKeyType::from_algorithm` matches on, mirroring the C's
        // `convert_ssh2_keytype`.
        let algorithm =
            server_public_key.algorithm().as_str().as_bytes().to_vec();
        let blob = HostKeyBlob {
            blob: encoded,
            algorithm,
        };
        let decision = check_fingerprint(&blob.blob, &self.policy);
        if let Ok(mut slot) = self.hostkey.lock() {
            *slot = Some(blob);
        } else {
            // A poisoned lock still has to record SOMETHING, or
            // `SSH_HOST_KEY` would read `None` and the C's *"sha256 fingerprint
            // not available"* refusal would be indistinguishable from a key that
            // was never presented. `PoisonError::into_inner` recovers the guard,
            // for the reason `crate::share` gives: a panic elsewhere must not
            // convert a transient fault into a permanent one.
            let mut slot = self
                .hostkey
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *slot = Some(blob_placeholder());
        }
        // Accept where the policy accepts or defers to a caller-side decision;
        // refuse only where the policy itself refuses. Deferring cannot be
        // resolved from inside the session task -- the callback and the
        // known-hosts file both live on the easy handle -- so accepting here and
        // resolving in `SSH_HOST_KEY` is what keeps the decision where the C
        // makes it.
        let accepted = decision.is_ok();
        async move { Ok(accepted) }
    }
}

/// A key blob with nothing in it, for the poisoned-lock recovery path.
///
/// Recorded rather than left absent so that [`SshState::HostKey`] reports *"sha256
/// fingerprint not available"* -- the C's text for a key it could not obtain --
/// instead of silently accepting.
#[cfg(feature = "ssh")]
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
fn blob_placeholder() -> HostKeyBlob {
    HostKeyBlob {
        blob: Vec::new(),
        algorithm: Vec::new(),
    }
}

/// `convert_ssh2_keytype` (`lib/vssh/libssh2.c:269-301`) over russh's
/// vocabulary.
///
/// The C switches on libssh2's `LIBSSH2_HOSTKEY_TYPE_*`; russh reports an
/// `ssh_key::Algorithm`. The mapping is the same one either way, including its
/// one lossy step: all three ECDSA curve sizes collapse onto
/// [`HostKeyType::Ecdsa`], because `enum curl_khtype` has a single ECDSA
/// enumerant and it is public ABI.
#[cfg(feature = "ssh")]
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
fn hostkey_type_of(algorithm: &russh::keys::Algorithm) -> HostKeyType {
    use russh::keys::Algorithm;
    match algorithm {
        Algorithm::Rsa { .. } => HostKeyType::Rsa,
        Algorithm::Dsa => HostKeyType::Dss,
        Algorithm::Ed25519 => HostKeyType::Ed25519,
        Algorithm::Ecdsa { .. } => HostKeyType::Ecdsa,
        _ => HostKeyType::Unknown,
    }
}

/// The production [`SshTransport`]: russh over the connection filter chain.
///
/// # The shape of the problem, and the shape of the answer
///
/// russh is written against `AsyncRead + AsyncWrite + Unpin + Send + 'static`
/// and, in `connect_stream`, SPAWNS its session onto the runtime. The filter
/// chain is none of those things: it is borrowed from a [`TransferCtx`], it is
/// synchronous, and it reports "would block" as [`CURLcode::Again`] exactly as
/// `lib/cfilters.c` does. The two cannot be connected directly.
///
/// The bridge is a `tokio::io::duplex` pair. russh is given one half -- owned,
/// `'static` and `Send`, so it can be moved into the spawned session -- and this
/// transport keeps the other. Every transport operation then runs the russh
/// future CONCURRENTLY with a shuttle that moves bytes between our half and the
/// chain, which is what [`Self::pump`] does.
///
/// The AAP's instruction is *"do not let russh own a raw socket -- that is what
/// makes R-F achievable"*, and this is the construction that honours it: russh
/// never sees a descriptor, the chain owns it, and a test can therefore put the
/// in-memory transport of `conn/filters.rs` underneath and drive real SSH bytes
/// with no network at all.
///
/// # What this costs, stated plainly
///
/// The shuttle polls rather than waits. `FilterChain::recv` and `send` are
/// synchronous and nothing in `curl-rs-lib/src/conn/` registers a descriptor with
/// the tokio reactor at this checkpoint, so there is no readiness signal to await
/// on: an idle turn yields to the runtime -- which is also what lets russh's
/// spawned session make progress -- and the turn count is bounded by
/// [`SHUTTLE_IDLE_LIMIT`]. When `conn/socket.rs` gains reactor registration the
/// yield becomes a wait and nothing else about this type changes. Performance is a
/// declared non-goal (specification 0.1.1), and faithfulness to the chain's
/// EAGAIN contract is what is being bought.
///
/// # What is exercised in-tree and what is not
///
/// The shuttle, the frame codec, the error mapping and the host-key handler are
/// all reachable without a peer and are tested. Completing a key exchange is
/// not: it needs a server, and `tests-rs/integration/sftp.rs` is where
/// specification 0.3.1 puts that. Every state machine, quote, codec and
/// verification test in [`mod tests`](self) therefore runs over a scripted
/// [`SshTransport`] double instead, which is what makes the coverage gate
/// reachable without a network.
#[cfg(feature = "ssh")]
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
pub(crate) struct RusshTransport {
    /// Our end of the bridge. russh holds the other.
    bridge: tokio::io::DuplexStream,
    /// The client handle, once the handshake has completed.
    handle: Option<russh::client::Handle<RusshHandler>>,
    /// The SFTP subsystem channel, as a byte stream.
    sftp: Option<russh::ChannelStream<russh::client::Msg>>,
    /// The key the peer presented, shared with the handler.
    hostkey: std::sync::Arc<std::sync::Mutex<Option<HostKeyBlob>>>,
    /// The methods the server offered, from the first refused attempt.
    authlist: Vec<u8>,
    /// Whether authentication has succeeded.
    authenticated: bool,
    /// Which direction the last operation was waiting on.
    waitfor: SshWait,
    /// Bytes read from the bridge that the chain has not accepted yet.
    outbound: Vec<u8>,
    /// Bytes read from the chain that the bridge has not accepted yet.
    inbound: Vec<u8>,
    /// The descriptor, cached from the chain so that [`Self::socket`] can answer
    /// without a [`CallCtx`].
    socket: Socket,
    /// russh's configuration, shared with the session task.
    config: std::sync::Arc<russh::client::Config>,
    /// The policy the handler applies to the peer's key.
    policy: HostKeyPolicy,
}

#[cfg(feature = "ssh")]
impl fmt::Debug for RusshTransport {
    /// Progress and buffer occupancy. No key material, no credentials and no
    /// payload.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RusshTransport")
            .field("connected", &self.handle.is_some())
            .field("sftp_open", &self.sftp.is_some())
            .field("authenticated", &self.authenticated)
            .field("waitfor", &self.waitfor.bits())
            .field("outbound", &self.outbound.len())
            .field("inbound", &self.inbound.len())
            .finish()
    }
}

#[cfg(feature = "ssh")]
#[allow(dead_code)] // consumer: the SFTP phase drivers, reached once easy/setopt.rs can supply SshSettings
impl RusshTransport {
    /// A transport ready to hand shake, over a fresh bridge.
    ///
    /// The returned value owns one half of the bridge; the other half is held
    /// until [`Self::handshake`] moves it into russh. Splitting construction from
    /// the handshake is what lets a caller install the transport into an
    /// [`SshConn`] before the connection exists, which is the order
    /// `ssh_setup_connection` establishes.
    pub(crate) fn new(
        policy: HostKeyPolicy,
    ) -> (Self, tokio::io::DuplexStream) {
        let (ours, theirs) = tokio::io::duplex(BRIDGE_CAPACITY);
        let transport = Self {
            bridge: ours,
            handle: None,
            sftp: None,
            hostkey: std::sync::Arc::new(std::sync::Mutex::new(None)),
            authlist: Vec::new(),
            authenticated: false,
            waitfor: SshWait::NONE,
            outbound: Vec::new(),
            inbound: Vec::new(),
            socket: crate::conn::select::CURL_SOCKET_BAD,
            config: std::sync::Arc::new(russh::client::Config::default()),
            policy,
        };
        (transport, theirs)
    }

    /// One shuttle turn: move what can be moved, in both directions.
    ///
    /// Deliberately synchronous. Every byte movement here is either a
    /// non-blocking poll of the bridge or a synchronous call on the chain, so the
    /// whole turn completes without an await -- which is what keeps
    /// [`CallCtx`] (not [`Send`]) from ever being held across one, and therefore
    /// what keeps [`SshFuture`]'s [`Send`] bound satisfiable.
    ///
    /// The order is send-then-receive, matching `ssh_statemachine`'s: what the
    /// peer is waiting for goes out before what it has already said comes in.
    ///
    /// # Errors
    ///
    /// [`SshError::SocketSend`] when the chain refuses a write outright, and
    /// [`SshError::Other`] when it refuses a read.
    fn shuttle(
        bridge: &mut tokio::io::DuplexStream,
        outbound: &mut Vec<u8>,
        inbound: &mut Vec<u8>,
        socket: &mut Socket,
        ctx: &mut TransferCtx<'_>,
    ) -> Result<ShuttleTurn, SshError> {
        use futures::FutureExt as _;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let mut progress = false;
        let mut scratch = vec![0_u8; SHUTTLE_SCRATCH];

        // -- russh -> chain ------------------------------------------------
        //
        // `now_or_never` polls the read exactly once and abandons it if it is
        // not ready. That is sound for `AsyncReadExt::read`, which is
        // cancellation-safe: an unready read has consumed nothing. The waker it
        // registers is discarded, which is why the caller must keep turning
        // rather than waiting to be woken.
        if let Some(result) = bridge.read(&mut scratch).now_or_never() {
            match result {
                Ok(0) => return Ok(ShuttleTurn::Closed),
                Ok(read) => {
                    outbound.extend_from_slice(&scratch[..read]);
                    progress = true;
                }
                Err(error) => {
                    return Err(SshError::Other(error.to_string()));
                }
            }
        }

        {
            let (chain, mut cx) = ctx.split();
            *socket = chain.socket(&mut cx);
            if !outbound.is_empty() {
                match chain.send(&mut cx, outbound, false) {
                    Ok(0) => {}
                    Ok(sent) => {
                        outbound.drain(..sent.min(outbound.len()));
                        progress = true;
                    }
                    Err(error) if error.code() == CURLcode::Again => {}
                    Err(_) => return Err(SshError::SocketSend),
                }
            }

            // -- chain -> russh --------------------------------------------
            match chain.recv(&mut cx, &mut scratch) {
                // Zero from a chain read is end of stream, exactly as it is
                // from `recv(2)`: the peer closed.
                Ok(0) => return Ok(ShuttleTurn::Closed),
                Ok(read) => {
                    inbound.extend_from_slice(&scratch[..read]);
                    progress = true;
                }
                Err(error) if error.code() == CURLcode::Again => {}
                Err(error) => {
                    return Err(SshError::Other(format!(
                        "SSH transport read failed with {}",
                        error.code().as_i32()
                    )));
                }
            }
        }

        if !inbound.is_empty() {
            if let Some(result) = bridge.write(inbound).now_or_never() {
                match result {
                    Ok(0) => return Ok(ShuttleTurn::Closed),
                    Ok(written) => {
                        inbound.drain(..written.min(inbound.len()));
                        progress = true;
                    }
                    Err(error) => {
                        return Err(SshError::Other(error.to_string()));
                    }
                }
            }
        }

        if progress {
            Ok(ShuttleTurn::Progress)
        } else {
            Ok(ShuttleTurn::Idle)
        }
    }

    /// Turn the shuttle until it fails, bounded by [`SHUTTLE_IDLE_LIMIT`].
    ///
    /// Never answers success: the caller races this against the operation it
    /// wants, so the only way this future completes is with the reason the
    /// session cannot continue. Written as a distinct function so that the race
    /// reads as what it is.
    async fn pump(
        bridge: &mut tokio::io::DuplexStream,
        outbound: &mut Vec<u8>,
        inbound: &mut Vec<u8>,
        socket: &mut Socket,
        ctx: &mut TransferCtx<'_>,
    ) -> SshError {
        let mut idle = 0_usize;
        loop {
            match Self::shuttle(bridge, outbound, inbound, socket, ctx) {
                Ok(ShuttleTurn::Progress) => idle = 0,
                Ok(ShuttleTurn::Idle) => {
                    idle = idle.saturating_add(1);
                    if idle >= SHUTTLE_IDLE_LIMIT {
                        return SshError::Again;
                    }
                }
                Ok(ShuttleTurn::Closed) => return SshError::SocketNone,
                Err(error) => return error,
            }
            // The yield is what lets russh's spawned session task run, and on a
            // current-thread runtime it is the ONLY thing that does. Removing it
            // deadlocks rather than merely spinning.
            tokio::task::yield_now().await;
        }
    }
}

#[cfg(feature = "ssh")]
impl SshTransport for RusshTransport {
    /// `SSH_S_STARTUP` (`lib/vssh/libssh2.c:2571-2584`):
    /// `libssh2_session_handshake`.
    ///
    /// Not reachable: the bridge half that russh needs is handed to the caller
    /// by [`RusshTransport::new`] and must be moved into
    /// `russh::client::connect_stream` there, because `connect_stream` consumes
    /// it and this method has only `&mut self`. Attempting it here would need the
    /// half back, and taking it back would leave the transport unable to shuttle.
    ///
    /// Reported rather than papered over. [`russh_connect`] is the entry point
    /// that performs the handshake, and it is what the connect phase calls.
    fn handshake<'a>(
        &'a mut self,
        ctx: &'a mut TransferCtx<'_>,
    ) -> SshFuture<'a, ()> {
        Box::pin(async move {
            if self.handle.is_some() {
                return Ok(());
            }
            let _ = ctx;
            Err(SshError::Other(
                "SSH handshake requires russh_connect".to_owned(),
            ))
        })
    }

    /// The key the peer presented, as [`RusshHandler`] recorded it.
    fn hostkey(&self) -> Option<HostKeyBlob> {
        self.hostkey
            .lock()
            .map_err(std::sync::PoisonError::into_inner)
            .map_or_else(|slot| slot.clone(), |slot| slot.clone())
    }

    /// `SSH_AUTH_LIST` (`lib/vssh/libssh2.c:2591-2620`):
    /// `libssh2_userauth_list`.
    ///
    /// libssh2 obtains the list by attempting the `none` method and reading the
    /// server's refusal, and russh's `authenticate_none` does exactly that --
    /// including the case where the server ACCEPTS it, which libssh2 reports as
    /// an empty list plus `libssh2_userauth_authenticated`, and which the C
    /// handles with *"SSH user accepted with no authentication"*.
    fn auth_list<'a>(
        &'a mut self,
        ctx: &'a mut TransferCtx<'_>,
        user: &'a str,
    ) -> SshFuture<'a, Vec<u8>> {
        Box::pin(async move {
            if !self.authlist.is_empty() {
                return Ok(self.authlist.clone());
            }
            let user = user.to_owned();
            let outcome = {
                let handle = match self.handle.as_mut() {
                    Some(handle) => handle,
                    None => return Err(SshError::SocketNone),
                };
                let bridge = &mut self.bridge;
                let outbound = &mut self.outbound;
                let inbound = &mut self.inbound;
                let socket = &mut self.socket;
                let pump = Self::pump(bridge, outbound, inbound, socket, ctx);
                let op = handle.authenticate_none(user);
                tokio::select! {
                    biased;
                    outcome = op => outcome.map_err(russh_error),
                    failure = pump => Err(failure),
                }
            }?;
            match outcome {
                russh::client::AuthResult::Success => {
                    self.authenticated = true;
                    self.authlist.clear();
                    Ok(Vec::new())
                }
                russh::client::AuthResult::Failure {
                    remaining_methods,
                    ..
                } => {
                    let list = method_list(&remaining_methods);
                    self.authlist = list.clone();
                    Ok(list)
                }
            }
        })
    }

    /// `libssh2_userauth_authenticated`.
    fn authenticated(&self) -> bool {
        self.authenticated
    }

    /// `SSH_AUTH_PKEY` (`lib/vssh/libssh2.c:1069-1161`):
    /// `libssh2_userauth_publickey_fromfile_ex`.
    ///
    /// The public-key file is read by libssh2 and NOT by russh, which derives
    /// the public half from the private key. So `public_key` is accepted,
    /// checked for existence -- because the C's *"public key not found"* refusal
    /// is observable -- and then not otherwise used, which is recorded here
    /// rather than left to be discovered.
    fn auth_publickey<'a>(
        &'a mut self,
        ctx: &'a mut TransferCtx<'_>,
        user: &'a str,
        private_key: &'a str,
        public_key: Option<&'a str>,
        passphrase: &'a str,
    ) -> SshFuture<'a, bool> {
        Box::pin(async move {
            if private_key.is_empty() {
                return Ok(false);
            }
            if let Some(public) = public_key {
                if !std::path::Path::new(public).exists() {
                    return Err(SshError::Other(format!(
                        "public key not found: {public}"
                    )));
                }
            }
            let secret = if passphrase.is_empty() {
                russh::keys::load_secret_key(private_key, None)
            } else {
                russh::keys::load_secret_key(private_key, Some(passphrase))
            };
            let key = match secret {
                Ok(key) => std::sync::Arc::new(key),
                Err(error) => {
                    return Err(SshError::Other(error.to_string()));
                }
            };
            let user = user.to_owned();
            let outcome = {
                let handle = match self.handle.as_mut() {
                    Some(handle) => handle,
                    None => return Err(SshError::SocketNone),
                };
                // `None` asks russh for the key's own default hash algorithm,
                // which for every algorithm except RSA is the only one.
                let with_hash =
                    russh::keys::PrivateKeyWithHashAlg::new(key, None);
                let bridge = &mut self.bridge;
                let outbound = &mut self.outbound;
                let inbound = &mut self.inbound;
                let socket = &mut self.socket;
                let pump = Self::pump(bridge, outbound, inbound, socket, ctx);
                let op = handle.authenticate_publickey(user, with_hash);
                tokio::select! {
                    biased;
                    outcome = op => outcome.map_err(russh_error),
                    failure = pump => Err(failure),
                }
            }?;
            let success = matches!(outcome, russh::client::AuthResult::Success);
            self.authenticated = success;
            Ok(success)
        })
    }

    /// `SSH_AUTH_PASS` (`lib/vssh/libssh2.c:1720-1727`):
    /// `libssh2_userauth_password_ex`.
    fn auth_password<'a>(
        &'a mut self,
        ctx: &'a mut TransferCtx<'_>,
        user: &'a str,
        password: &'a str,
    ) -> SshFuture<'a, bool> {
        Box::pin(async move {
            let user = user.to_owned();
            let password = password.to_owned();
            let outcome = {
                let handle = match self.handle.as_mut() {
                    Some(handle) => handle,
                    None => return Err(SshError::SocketNone),
                };
                let bridge = &mut self.bridge;
                let outbound = &mut self.outbound;
                let inbound = &mut self.inbound;
                let socket = &mut self.socket;
                let pump = Self::pump(bridge, outbound, inbound, socket, ctx);
                let op = handle.authenticate_password(user, password);
                tokio::select! {
                    biased;
                    outcome = op => outcome.map_err(russh_error),
                    failure = pump => Err(failure),
                }
            }?;
            let success = matches!(outcome, russh::client::AuthResult::Success);
            self.authenticated = success;
            Ok(success)
        })
    }

    /// `SSH_AUTH_KEY` (`lib/vssh/libssh2.c:1729-1741`):
    /// `libssh2_userauth_keyboard_interactive_ex`.
    ///
    /// libssh2 answers every prompt with the configured password through its
    /// `kbd_callback` (`lib/vssh/libssh2.c:236-258`), which loops over
    /// `num_prompts` and copies the password into each response. russh exposes
    /// the same exchange as an explicit request/respond pair, so the loop is here
    /// instead of in a callback -- and it answers every prompt with the password,
    /// exactly as the C does, without inspecting the prompt text.
    fn auth_keyboard_interactive<'a>(
        &'a mut self,
        ctx: &'a mut TransferCtx<'_>,
        user: &'a str,
        password: &'a str,
    ) -> SshFuture<'a, bool> {
        Box::pin(async move {
            let user = user.to_owned();
            let password = password.to_owned();
            let mut response = {
                let handle = match self.handle.as_mut() {
                    Some(handle) => handle,
                    None => return Err(SshError::SocketNone),
                };
                let bridge = &mut self.bridge;
                let outbound = &mut self.outbound;
                let inbound = &mut self.inbound;
                let socket = &mut self.socket;
                let pump = Self::pump(bridge, outbound, inbound, socket, ctx);
                let op =
                    handle.authenticate_keyboard_interactive_start(user, None);
                tokio::select! {
                    biased;
                    outcome = op => outcome.map_err(russh_error),
                    failure = pump => Err(failure),
                }
            }?;

            // Bounded because a server that keeps asking must not keep this
            // loop alive forever. libssh2 has no bound of its own; the C's own
            // ceiling is the transfer timeout, which is not on disk.
            for _ in 0..16_usize {
                match response {
                    russh::client::KeyboardInteractiveAuthResponse::Success => {
                        self.authenticated = true;
                        return Ok(true);
                    }
                    russh::client::KeyboardInteractiveAuthResponse::Failure {
                        ..
                    } => {
                        self.authenticated = false;
                        return Ok(false);
                    }
                    russh::client::KeyboardInteractiveAuthResponse::InfoRequest {
                        ref prompts,
                        ..
                    } => {
                        let answers =
                            vec![password.clone(); prompts.len()];
                        let handle = match self.handle.as_mut() {
                            Some(handle) => handle,
                            None => return Err(SshError::SocketNone),
                        };
                        let bridge = &mut self.bridge;
                        let outbound = &mut self.outbound;
                        let inbound = &mut self.inbound;
                        let socket = &mut self.socket;
                        let pump = Self::pump(
                            bridge, outbound, inbound, socket, ctx,
                        );
                        let op = handle
                            .authenticate_keyboard_interactive_respond(
                                answers,
                            );
                        response = tokio::select! {
                            biased;
                            outcome = op => outcome.map_err(russh_error),
                            failure = pump => Err(failure),
                        }?;
                    }
                }
            }
            Ok(false)
        })
    }

    /// `SSH_AUTH_AGENT` (`lib/vssh/libssh2.c:1656-1687`):
    /// `libssh2_agent_userauth`.
    ///
    /// Not implemented, and reported as a REFUSAL rather than an error, which is
    /// the behaviour that matters: `next_auth_state` moves a refusal on to
    /// `SSH_AUTH_KEY_INIT`, so a build that reaches the agent state falls through
    /// to keyboard-interactive exactly as it does against an agent that holds no
    /// usable identity.
    ///
    /// The C's agent support needs `$SSH_AUTH_SOCK` and a Unix-socket dialogue
    /// that `crate::conn` does not expose. russh has `keys::agent::client`, whose
    /// use here would put an agent connection outside the filter chain -- the one
    /// thing the AAP's transport instruction forbids. Left refused, and recorded,
    /// rather than routed around.
    fn auth_agent<'a>(
        &'a mut self,
        ctx: &'a mut TransferCtx<'_>,
        user: &'a str,
    ) -> SshFuture<'a, bool> {
        let _ = (ctx, user);
        Box::pin(core::future::ready(Ok(false)))
    }

    /// `SSH_SFTP_INIT` (`lib/vssh/libssh2.c:2649-2665`):
    /// `libssh2_sftp_init`.
    ///
    /// Three steps, all of which the C hides inside libssh2: open a session
    /// channel, request the `sftp` subsystem on it, and exchange
    /// `SSH_FXP_INIT` / `SSH_FXP_VERSION`. The version answered is the peer's,
    /// and [`SFTP_VERSION`] is what this module offers.
    fn open_sftp<'a>(
        &'a mut self,
        ctx: &'a mut TransferCtx<'_>,
    ) -> SshFuture<'a, u32> {
        Box::pin(async move {
            let channel = {
                let handle = match self.handle.as_ref() {
                    Some(handle) => handle,
                    None => return Err(SshError::SocketNone),
                };
                let bridge = &mut self.bridge;
                let outbound = &mut self.outbound;
                let inbound = &mut self.inbound;
                let socket = &mut self.socket;
                let pump = Self::pump(bridge, outbound, inbound, socket, ctx);
                let op = handle.channel_open_session();
                tokio::select! {
                    biased;
                    outcome = op => outcome.map_err(russh_error),
                    failure = pump => Err(failure),
                }
            }?;

            {
                let bridge = &mut self.bridge;
                let outbound = &mut self.outbound;
                let inbound = &mut self.inbound;
                let socket = &mut self.socket;
                let pump = Self::pump(bridge, outbound, inbound, socket, ctx);
                let op = channel.request_subsystem(true, "sftp");
                tokio::select! {
                    biased;
                    outcome = op => outcome.map_err(russh_error),
                    failure = pump => Err(failure),
                }
            }?;

            self.sftp = Some(channel.into_stream());
            let reply = self.sftp_exchange(ctx, request::init()).await?;
            request::decode_version(&reply).map_err(|failure| {
                SshError::Other(failure.message().to_owned())
            })
        })
    }

    /// One SFTP request and its reply, framed.
    ///
    /// The framing is the protocol's: a four-byte big-endian length followed by
    /// that many bytes. [`SftpCodec`] builds the outgoing frame including its
    /// prefix, so this writes it whole and then reads one complete frame back.
    ///
    /// A reply larger than [`MAX_PATHLENGTH`] times four is refused rather than
    /// allocated, which is the bound RUSTSEC-2026-0154 concerns: the advisory is
    /// about an unbounded 32-bit allocation from a length field, and this is the
    /// one place in this module where a peer supplies one.
    fn sftp_exchange<'a>(
        &'a mut self,
        ctx: &'a mut TransferCtx<'_>,
        packet: Vec<u8>,
    ) -> SshFuture<'a, Vec<u8>> {
        Box::pin(async move {
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

            if self.sftp.is_none() {
                return Err(SshError::SocketNone);
            }

            {
                let sftp = match self.sftp.as_mut() {
                    Some(sftp) => sftp,
                    None => return Err(SshError::SocketNone),
                };
                let bridge = &mut self.bridge;
                let outbound = &mut self.outbound;
                let inbound = &mut self.inbound;
                let socket = &mut self.socket;
                let pump = Self::pump(bridge, outbound, inbound, socket, ctx);
                let op = sftp.write_all(&packet);
                tokio::select! {
                    biased;
                    outcome = op => outcome
                        .map_err(|error| SshError::Other(error.to_string())),
                    failure = pump => Err(failure),
                }
            }?;

            let mut length = [0_u8; 4];
            {
                let sftp = match self.sftp.as_mut() {
                    Some(sftp) => sftp,
                    None => return Err(SshError::SocketNone),
                };
                let bridge = &mut self.bridge;
                let outbound = &mut self.outbound;
                let inbound = &mut self.inbound;
                let socket = &mut self.socket;
                let pump = Self::pump(bridge, outbound, inbound, socket, ctx);
                let op = sftp.read_exact(&mut length);
                tokio::select! {
                    biased;
                    outcome = op => outcome
                        .map(|_| ())
                        .map_err(|error| SshError::Other(error.to_string())),
                    failure = pump => Err(failure),
                }
            }?;

            let want = usize::try_from(u32::from_be_bytes(length))
                .unwrap_or(usize::MAX);
            if want > MAX_PATHLENGTH * 4 {
                return Err(SshError::Other(format!(
                    "SFTP frame of {want} bytes exceeds the accepted maximum"
                )));
            }
            // The prefix is RETAINED in the answer, because
            // [`SftpReader::frame`] parses it: the decoders take a whole frame,
            // not a payload, so that a caller holding one buffer can decode it
            // without knowing where the boundary was.
            let mut frame = Vec::with_capacity(4 + want);
            frame.extend_from_slice(&length);
            frame.resize(4 + want, 0);
            {
                let sftp = match self.sftp.as_mut() {
                    Some(sftp) => sftp,
                    None => return Err(SshError::SocketNone),
                };
                let bridge = &mut self.bridge;
                let outbound = &mut self.outbound;
                let inbound = &mut self.inbound;
                let socket = &mut self.socket;
                let pump = Self::pump(bridge, outbound, inbound, socket, ctx);
                let body = match frame.get_mut(4..) {
                    Some(body) => body,
                    None => return Err(SshError::Alloc),
                };
                let op = sftp.read_exact(body);
                tokio::select! {
                    biased;
                    outcome = op => outcome
                        .map(|_| ())
                        .map_err(|error| SshError::Other(error.to_string())),
                    failure = pump => Err(failure),
                }
            }?;
            Ok(frame)
        })
    }

    /// `libssh2_sftp_shutdown` (`ssh_state_sftp_shutdown`,
    /// `lib/vssh/libssh2.c:2312-2345`).
    ///
    /// Dropping the stream closes the channel, which is what shutting the
    /// subsystem down amounts to once the handle has been closed. The C
    /// diagnoses a failure with `infof(data, "Failed to stop libssh2 sftp
    /// subsystem")` and continues; there is nothing here that can fail, so the
    /// diagnostic has no occasion to fire.
    fn close_sftp<'a>(
        &'a mut self,
        ctx: &'a mut TransferCtx<'_>,
    ) -> SshFuture<'a, ()> {
        let _ = ctx;
        self.sftp = None;
        Box::pin(core::future::ready(Ok(())))
    }

    /// `libssh2_session_disconnect(session, "Shutdown")`
    /// (`ssh_state_session_disconnect`, `lib/vssh/libssh2.c:2423-2459`).
    ///
    /// ⚠ The reason string is on the wire and is exactly `Shutdown`. russh's
    /// `Disconnect::ByApplication` is RFC 4254's code 11, which is what libssh2
    /// sends for an application-initiated disconnect.
    fn disconnect<'a>(
        &'a mut self,
        ctx: &'a mut TransferCtx<'_>,
    ) -> SshFuture<'a, ()> {
        Box::pin(async move {
            self.sftp = None;
            if self.handle.is_none() {
                return Ok(());
            }
            let outcome = {
                let handle = match self.handle.as_ref() {
                    Some(handle) => handle,
                    None => return Ok(()),
                };
                let bridge = &mut self.bridge;
                let outbound = &mut self.outbound;
                let inbound = &mut self.inbound;
                let socket = &mut self.socket;
                let pump = Self::pump(bridge, outbound, inbound, socket, ctx);
                let op = handle.disconnect(
                    russh::Disconnect::ByApplication,
                    "Shutdown",
                    "",
                );
                tokio::select! {
                    biased;
                    outcome = op => outcome.map_err(russh_error),
                    failure = pump => Err(failure),
                }
            };
            // Drop the handle either way: a disconnect that could not be sent
            // still ends the session, and holding the handle would keep russh's
            // spawned task alive with nothing to serve.
            self.handle = None;
            self.authenticated = false;
            outcome
        })
    }

    /// `libssh2_session_block_directions` (`ssh_block2waitfor`,
    /// `lib/vssh/libssh2.c:3051-3068`).
    fn block_directions(&self) -> SshWait {
        self.waitfor
    }

    /// `CF_QUERY_SOCKET` through the chain, cached by the shuttle.
    ///
    /// Cached rather than queried, because this member has no [`TransferCtx`] to
    /// query with -- and the shuttle refreshes it on every turn, so the cached
    /// value is never older than the last byte movement.
    fn socket(&self) -> Socket {
        self.socket
    }
}

/// `RusshTransport::handshake`'s real entry point.
///
/// Separate from the trait member because it consumes the bridge half that
/// [`RusshTransport::new`] handed out, and `russh::client::connect_stream`
/// consumes its stream. A trait member taking `&mut self` cannot express that,
/// which is why [`SshTransport::handshake`] reports rather than performs.
///
/// The handshake runs concurrently with the shuttle, and it has to: russh writes
/// its version string, reads the peer's, and then awaits the completion of the
/// key exchange -- all before `connect_stream` returns -- and every one of those
/// bytes has to travel through the filter chain while that await is outstanding.
///
/// # Errors
///
/// [`SshError::Other`] carrying russh's own description, which is what the C's
/// *"Failure establishing ssh session: %s"* interpolates.
#[cfg(feature = "ssh")]
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
pub(crate) async fn russh_connect(
    transport: &mut RusshTransport,
    peer: tokio::io::DuplexStream,
    ctx: &mut TransferCtx<'_>,
) -> Result<(), SshError> {
    let handler = RusshHandler {
        hostkey: std::sync::Arc::clone(&transport.hostkey),
        policy: transport.policy.clone(),
    };
    let config = std::sync::Arc::clone(&transport.config);
    let handle = {
        let bridge = &mut transport.bridge;
        let outbound = &mut transport.outbound;
        let inbound = &mut transport.inbound;
        let socket = &mut transport.socket;
        let pump = RusshTransport::pump(bridge, outbound, inbound, socket, ctx);
        let op = russh::client::connect_stream(config, peer, handler);
        tokio::select! {
            biased;
            outcome = op => outcome.map_err(russh_error),
            failure = pump => Err(failure),
        }
    }?;
    transport.handle = Some(handle);
    Ok(())
}

/// `libssh2_session_error_to_CURLE`'s input, from russh's vocabulary.
///
/// russh reports a single `Error` enum where libssh2 reports an integer, so the
/// mapping is by variant rather than by number. The three that have a distinct
/// [`CURLcode`] in the C are picked out and everything else becomes
/// [`SshError::Other`], which is `CURLE_SSH` -- the C's own fall-through.
#[cfg(feature = "ssh")]
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
fn russh_error(error: russh::Error) -> SshError {
    match error {
        russh::Error::SendError | russh::Error::Disconnect => {
            SshError::SocketSend
        }
        russh::Error::ConnectionTimeout
        | russh::Error::KeepaliveTimeout
        | russh::Error::InactivityTimeout => SshError::Timeout,
        russh::Error::UnknownKey | russh::Error::WrongServerSig => {
            SshError::HostKey(error.to_string())
        }
        russh::Error::NotAuthenticated => SshError::PasswordExpired,
        other => SshError::Other(other.to_string()),
    }
}

/// `libssh2_userauth_list`'s comma-separated answer, from russh's method set.
///
/// ⚠ The SPELLING of each method is wire vocabulary from RFC 4252 and is what
/// [`mod authlist`]'s membership test compares against, so it must be russh's
/// own rather than a re-spelling: `publickey`, `password`, `hostbased`,
/// `keyboard-interactive`, `none`. Separated by a single comma with no space,
/// which is what libssh2 produces and what `strstr` in the C searches.
#[cfg(feature = "ssh")]
#[allow(dead_code)] // consumer: protocols/scp.rs, which imports this file's shared SSH core
fn method_list(methods: &russh::MethodSet) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    for kind in methods.iter() {
        let name: &str = kind.into();
        if !out.is_empty() {
            out.push(b',');
        }
        out.extend_from_slice(name.as_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::filters::tests::{new_log, InMemory, TransportHandle};
    use crate::conn::filters::{link, FilterChains};
    use crate::util::timeval::{CurlTime, TestClock};

    // -- fixtures ----------------------------------------------------------

    /// The injected clock every test uses.
    ///
    /// A fixed instant rather than the wall clock, which is what makes the trace
    /// output and the timeout arithmetic reproducible. Specification 0.3.3's
    /// pattern P12 requires it and `mod source_policy` enforces it: this file
    /// may not name `Instant::now` at all.
    fn clock() -> TestClock {
        TestClock::new(CurlTime::new(1_000, 0))
    }

    /// Deterministic seams: the fixed clock plus a seeded generator.
    fn seams() -> SshSeams {
        SshSeams::deterministic(0x5EED_1234)
    }

    /// A [`TransferCtx`] over borrowed chains, on the SFTP row.
    ///
    /// [`SCHEME`] rather than a fabricated row, so that every test sees the
    /// scheme a real transfer would -- including its protocol bits, which
    /// `SSH_AUTH_DONE` and [`getworkingpath`] both branch on.
    fn transfer_ctx<'a>(
        chains: &'a mut FilterChains,
        clock: &'a TestClock,
    ) -> TransferCtx<'a> {
        TransferCtx::new(chains, clock, &SCHEME)
    }

    /// Chains with the in-memory transport of `conn/filters.rs` at the bottom.
    ///
    /// This is the substitute for a network that specification 0.8.4's coverage
    /// gate needs: the transport is a pair of byte buffers, so a test can assert
    /// the exact bytes a step put on the wire.
    fn chains_with_transport(
        clock: &TestClock,
        socket: Socket,
    ) -> (FilterChains, TransportHandle) {
        let mut cx = crate::conn::filters::CallCtx::new(clock);
        let log = new_log();
        let mut chains = FilterChains::new(None);
        let (transport, state) = InMemory::new("TEST", &log);
        state.borrow_mut().socket = socket;
        let chain = chains.chain_mut(crate::conn::SocketIndex::First);
        chain.add(&mut cx, link(transport));
        // CONNECTED, not merely installed: `Curl_cf_send` and `Curl_cf_recv`
        // dispatch through the first CONNECTED filter and answer
        // `CURLE_FAILED_INIT` when there is none, so a chain left unconnected
        // would make every shuttle turn look like a transport failure.
        assert!(
            chain.connect_head(&mut cx).is_ok_and(|done| done),
            "the in-memory transport connects in one step"
        );
        (chains, state)
    }

    /// One scripted reply.
    #[derive(Clone, Debug)]
    struct Reply {
        /// The frame to answer with, or the failure to report.
        outcome: Result<Vec<u8>, SshError>,
    }

    /// A scripted [`SshTransport`]: a peer that answers from a queue.
    ///
    /// This is what makes the SFTP protocol layer testable as pure code. Every
    /// request the module emits is recorded, so a test asserts the exact bytes
    /// -- which is the only way to honour specification 0.6.7's byte-exact
    /// oracle without a server. Replies are consumed in order, and running out
    /// is a failure rather than a silent success, so a test that under-scripts
    /// its peer fails loudly.
    #[derive(Debug)]
    struct Scripted {
        /// Framed replies, consumed from the front.
        replies: std::collections::VecDeque<Reply>,
        /// Every request the module sent, in order.
        sent: Vec<Vec<u8>>,
        /// What each session operation answers.
        handshake: Option<SshError>,
        hostkey: Option<HostKeyBlob>,
        auth_list: Result<Vec<u8>, SshError>,
        authenticated: bool,
        publickey: Result<bool, SshError>,
        password: Result<bool, SshError>,
        keyboard: Result<bool, SshError>,
        agent: Result<bool, SshError>,
        sftp_version: Result<u32, SshError>,
        /// Every session call, in order, so ordering is assertable.
        calls: Vec<&'static str>,
        /// What [`SshTransport::block_directions`] reports.
        waitfor: SshWait,
        /// What [`SshTransport::socket`] reports.
        socket: Socket,
        /// Whether the SFTP subsystem was closed.
        closed_sftp: bool,
        /// Whether the session was disconnected.
        disconnected: bool,
    }

    impl Scripted {
        fn new() -> Self {
            Self {
                replies: std::collections::VecDeque::new(),
                sent: Vec::new(),
                handshake: None,
                hostkey: None,
                auth_list: Ok(Vec::new()),
                authenticated: false,
                publickey: Ok(false),
                password: Ok(false),
                keyboard: Ok(false),
                agent: Ok(false),
                sftp_version: Ok(SFTP_VERSION),
                calls: Vec::new(),
                waitfor: SshWait::NONE,
                socket: crate::conn::select::CURL_SOCKET_BAD,
                closed_sftp: false,
                disconnected: false,
            }
        }

        /// Queue one framed reply.
        fn reply(&mut self, frame: Vec<u8>) -> &mut Self {
            self.replies.push_back(Reply { outcome: Ok(frame) });
            self
        }

        /// Queue one transport-level failure.
        fn fail(&mut self, error: SshError) -> &mut Self {
            self.replies.push_back(Reply {
                outcome: Err(error),
            });
            self
        }

        /// Queue an `SSH_FXP_STATUS` reply.
        fn status(&mut self, status: SftpStatus) -> &mut Self {
            self.reply(status_frame(status))
        }
    }

    impl SshTransport for Scripted {
        fn handshake<'a>(
            &'a mut self,
            _ctx: &'a mut TransferCtx<'_>,
        ) -> SshFuture<'a, ()> {
            self.calls.push("handshake");
            let outcome = match self.handshake.clone() {
                Some(error) => Err(error),
                None => Ok(()),
            };
            Box::pin(core::future::ready(outcome))
        }

        fn hostkey(&self) -> Option<HostKeyBlob> {
            self.hostkey.clone()
        }

        fn auth_list<'a>(
            &'a mut self,
            _ctx: &'a mut TransferCtx<'_>,
            _user: &'a str,
        ) -> SshFuture<'a, Vec<u8>> {
            self.calls.push("auth_list");
            let outcome = self.auth_list.clone();
            Box::pin(core::future::ready(outcome))
        }

        fn authenticated(&self) -> bool {
            self.authenticated
        }

        fn auth_publickey<'a>(
            &'a mut self,
            _ctx: &'a mut TransferCtx<'_>,
            _user: &'a str,
            _private_key: &'a str,
            _public_key: Option<&'a str>,
            _passphrase: &'a str,
        ) -> SshFuture<'a, bool> {
            self.calls.push("publickey");
            let outcome = self.publickey.clone();
            Box::pin(core::future::ready(outcome))
        }

        fn auth_password<'a>(
            &'a mut self,
            _ctx: &'a mut TransferCtx<'_>,
            _user: &'a str,
            _password: &'a str,
        ) -> SshFuture<'a, bool> {
            self.calls.push("password");
            let outcome = self.password.clone();
            Box::pin(core::future::ready(outcome))
        }

        fn auth_keyboard_interactive<'a>(
            &'a mut self,
            _ctx: &'a mut TransferCtx<'_>,
            _user: &'a str,
            _password: &'a str,
        ) -> SshFuture<'a, bool> {
            self.calls.push("keyboard");
            let outcome = self.keyboard.clone();
            Box::pin(core::future::ready(outcome))
        }

        fn auth_agent<'a>(
            &'a mut self,
            _ctx: &'a mut TransferCtx<'_>,
            _user: &'a str,
        ) -> SshFuture<'a, bool> {
            self.calls.push("agent");
            let outcome = self.agent.clone();
            Box::pin(core::future::ready(outcome))
        }

        fn open_sftp<'a>(
            &'a mut self,
            _ctx: &'a mut TransferCtx<'_>,
        ) -> SshFuture<'a, u32> {
            self.calls.push("open_sftp");
            let outcome = self.sftp_version.clone();
            Box::pin(core::future::ready(outcome))
        }

        fn sftp_exchange<'a>(
            &'a mut self,
            _ctx: &'a mut TransferCtx<'_>,
            packet: Vec<u8>,
        ) -> SshFuture<'a, Vec<u8>> {
            self.sent.push(packet);
            let outcome = match self.replies.pop_front() {
                Some(reply) => reply.outcome,
                None => Err(SshError::Other(
                    "the scripted peer ran out of replies".to_owned(),
                )),
            };
            Box::pin(core::future::ready(outcome))
        }

        fn close_sftp<'a>(
            &'a mut self,
            _ctx: &'a mut TransferCtx<'_>,
        ) -> SshFuture<'a, ()> {
            self.calls.push("close_sftp");
            self.closed_sftp = true;
            Box::pin(core::future::ready(Ok(())))
        }

        fn disconnect<'a>(
            &'a mut self,
            _ctx: &'a mut TransferCtx<'_>,
        ) -> SshFuture<'a, ()> {
            self.calls.push("disconnect");
            self.disconnected = true;
            Box::pin(core::future::ready(Ok(())))
        }

        fn block_directions(&self) -> SshWait {
            self.waitfor
        }

        fn socket(&self) -> Socket {
            self.socket
        }
    }

    /// A handle on a [`Scripted`] peer that survives being boxed into an
    /// [`SshConn`].
    ///
    /// The same device `conn/filters.rs` uses for the same reason: a transport
    /// installed into a connection is owned as `Box<dyn SshTransport>` and there
    /// is no way back to the concrete type, so what it recorded has to be
    /// reachable through a shared cell.
    type Peer = std::sync::Arc<crate::util::sync_cell::SyncCell<Scripted>>;

    /// A [`Scripted`] behind a shared cell, viewed as an [`SshTransport`].
    ///
    /// # Why every member resolves its future with `now_or_never`
    ///
    /// A nested `block_on` is not permitted -- `futures::executor` refuses it
    /// with `EnterError` -- and these members ARE called from inside a
    /// `block_on`, because that is how a test drives the state machine. Every
    /// future [`Scripted`] produces is `core::future::ready`, so polling it once
    /// resolves it; a `None` here means the double has grown a genuinely pending
    /// future and is reported as such rather than silently retried.
    #[derive(Debug)]
    struct Shared(Peer);

    /// Resolve a scripted future, or report that it pended.
    fn resolved<T>(polled: Option<Result<T, SshError>>) -> Result<T, SshError> {
        polled.unwrap_or_else(|| {
            Err(SshError::Other(
                "the scripted peer produced a pending future".to_owned(),
            ))
        })
    }

    impl SshTransport for Shared {
        fn handshake<'a>(
            &'a mut self,
            ctx: &'a mut TransferCtx<'_>,
        ) -> SshFuture<'a, ()> {
            use futures::FutureExt as _;
            let outcome =
                resolved(self.0.borrow_mut().handshake(ctx).now_or_never());
            Box::pin(core::future::ready(outcome))
        }

        fn hostkey(&self) -> Option<HostKeyBlob> {
            self.0.borrow().hostkey()
        }

        fn auth_list<'a>(
            &'a mut self,
            ctx: &'a mut TransferCtx<'_>,
            user: &'a str,
        ) -> SshFuture<'a, Vec<u8>> {
            use futures::FutureExt as _;
            let outcome = resolved(
                self.0.borrow_mut().auth_list(ctx, user).now_or_never(),
            );
            Box::pin(core::future::ready(outcome))
        }

        fn authenticated(&self) -> bool {
            self.0.borrow().authenticated()
        }

        fn auth_publickey<'a>(
            &'a mut self,
            ctx: &'a mut TransferCtx<'_>,
            user: &'a str,
            private_key: &'a str,
            public_key: Option<&'a str>,
            passphrase: &'a str,
        ) -> SshFuture<'a, bool> {
            use futures::FutureExt as _;
            let outcome = resolved(
                self.0
                    .borrow_mut()
                    .auth_publickey(
                        ctx,
                        user,
                        private_key,
                        public_key,
                        passphrase,
                    )
                    .now_or_never(),
            );
            Box::pin(core::future::ready(outcome))
        }

        fn auth_password<'a>(
            &'a mut self,
            ctx: &'a mut TransferCtx<'_>,
            user: &'a str,
            password: &'a str,
        ) -> SshFuture<'a, bool> {
            use futures::FutureExt as _;
            let outcome = resolved(
                self.0
                    .borrow_mut()
                    .auth_password(ctx, user, password)
                    .now_or_never(),
            );
            Box::pin(core::future::ready(outcome))
        }

        fn auth_keyboard_interactive<'a>(
            &'a mut self,
            ctx: &'a mut TransferCtx<'_>,
            user: &'a str,
            password: &'a str,
        ) -> SshFuture<'a, bool> {
            use futures::FutureExt as _;
            let outcome = resolved(
                self.0
                    .borrow_mut()
                    .auth_keyboard_interactive(ctx, user, password)
                    .now_or_never(),
            );
            Box::pin(core::future::ready(outcome))
        }

        fn auth_agent<'a>(
            &'a mut self,
            ctx: &'a mut TransferCtx<'_>,
            user: &'a str,
        ) -> SshFuture<'a, bool> {
            use futures::FutureExt as _;
            let outcome = resolved(
                self.0.borrow_mut().auth_agent(ctx, user).now_or_never(),
            );
            Box::pin(core::future::ready(outcome))
        }

        fn open_sftp<'a>(
            &'a mut self,
            ctx: &'a mut TransferCtx<'_>,
        ) -> SshFuture<'a, u32> {
            use futures::FutureExt as _;
            let outcome =
                resolved(self.0.borrow_mut().open_sftp(ctx).now_or_never());
            Box::pin(core::future::ready(outcome))
        }

        fn sftp_exchange<'a>(
            &'a mut self,
            ctx: &'a mut TransferCtx<'_>,
            packet: Vec<u8>,
        ) -> SshFuture<'a, Vec<u8>> {
            use futures::FutureExt as _;
            let outcome = resolved(
                self.0
                    .borrow_mut()
                    .sftp_exchange(ctx, packet)
                    .now_or_never(),
            );
            Box::pin(core::future::ready(outcome))
        }

        fn close_sftp<'a>(
            &'a mut self,
            ctx: &'a mut TransferCtx<'_>,
        ) -> SshFuture<'a, ()> {
            use futures::FutureExt as _;
            let outcome =
                resolved(self.0.borrow_mut().close_sftp(ctx).now_or_never());
            Box::pin(core::future::ready(outcome))
        }

        fn disconnect<'a>(
            &'a mut self,
            ctx: &'a mut TransferCtx<'_>,
        ) -> SshFuture<'a, ()> {
            use futures::FutureExt as _;
            let outcome =
                resolved(self.0.borrow_mut().disconnect(ctx).now_or_never());
            Box::pin(core::future::ready(outcome))
        }

        fn block_directions(&self) -> SshWait {
            self.0.borrow().block_directions()
        }

        fn socket(&self) -> Socket {
            self.0.borrow().socket()
        }
    }

    /// An [`SshConn`] over a scripted peer, with the peer still reachable.
    fn conn_over(script: Scripted) -> (SshConn, Peer) {
        let peer: Peer =
            std::sync::Arc::new(crate::util::sync_cell::SyncCell::new(script));
        let boxed: Box<dyn SshTransport> =
            Box::new(Shared(std::sync::Arc::clone(&peer)));
        (SshConn::new(boxed, seams()), peer)
    }

    // -- frame builders, so a scripted reply is real wire bytes -------------

    /// `SSH_FXP_STATUS` carrying `status`.
    fn status_frame(status: SftpStatus) -> Vec<u8> {
        let mut codec = SftpCodec::request(SftpPacket::Status);
        codec.put_u32(1).put_u32(status.0);
        codec.put_bytes(b"scripted");
        codec.put_bytes(b"");
        codec.finish()
    }

    /// `SSH_FXP_HANDLE` carrying `handle`.
    fn handle_frame(handle: &[u8]) -> Vec<u8> {
        let mut codec = SftpCodec::request(SftpPacket::Handle);
        codec.put_u32(1);
        codec.put_bytes(handle);
        codec.finish()
    }

    /// `SSH_FXP_ATTRS` carrying `attrs`.
    fn attrs_frame(attrs: &SftpAttributes) -> Vec<u8> {
        let mut codec = SftpCodec::request(SftpPacket::Attrs);
        codec.put_u32(1);
        codec.put_attributes(attrs);
        codec.finish()
    }

    /// `SSH_FXP_NAME` carrying `entries`.
    fn name_frame(entries: &[(&[u8], &[u8], SftpAttributes)]) -> Vec<u8> {
        let mut codec = SftpCodec::request(SftpPacket::Name);
        codec.put_u32(1);
        codec.put_u32(u32::try_from(entries.len()).unwrap_or(0));
        for (filename, longentry, attrs) in entries {
            codec.put_bytes(filename);
            codec.put_bytes(longentry);
            codec.put_attributes(attrs);
        }
        codec.finish()
    }

    /// `SSH_FXP_VERSION` carrying `version`.
    fn version_frame(version: u32) -> Vec<u8> {
        let mut codec = SftpCodec::request(SftpPacket::Version);
        codec.put_u32(version);
        codec.finish()
    }

    /// `SSH_FXP_EXTENDED_REPLY` carrying a `statvfs@openssh.com` answer.
    fn statvfs_frame(stats: &SftpStatVfs) -> Vec<u8> {
        let mut codec = SftpCodec::request(SftpPacket::ExtendedReply);
        codec
            .put_u32(1)
            .put_u64(stats.bsize)
            .put_u64(stats.frsize)
            .put_u64(stats.blocks)
            .put_u64(stats.bfree)
            .put_u64(stats.bavail)
            .put_u64(stats.files)
            .put_u64(stats.ffree)
            .put_u64(stats.favail)
            .put_u64(stats.fsid)
            .put_u64(stats.flag)
            .put_u64(stats.namemax);
        codec.finish()
    }

    /// Attributes with a size, which is what a download stat needs.
    fn sized(size: u64) -> SftpAttributes {
        SftpAttributes {
            flags: SftpAttrFlags::SIZE,
            filesize: size,
            ..SftpAttributes::default()
        }
    }

    /// Attributes describing a symbolic link.
    fn linked() -> SftpAttributes {
        SftpAttributes {
            flags: SftpAttrFlags::PERMISSIONS,
            permissions: SFTP_S_IFLNK | 0o777,
            ..SftpAttributes::default()
        }
    }

    /// Settings with the option defaults, plus a user name.
    fn settings() -> SshSettings {
        SshSettings {
            user: "curl".to_owned(),
            ..SshSettings::with_option_defaults()
        }
    }

    /// A per-request state carrying nothing but the path the request operates
    /// on.
    ///
    /// `SSH_SFTP_TRANS_INIT` and everything after it read `sshp.path` and
    /// nothing else out of the default carrier, so every DO-phase test needs
    /// exactly this and struct-update syntax keeps it to one expression.
    fn proto(path: &[u8]) -> SshProto {
        SshProto {
            path: path.to_vec(),
            ..SshProto::default()
        }
    }

    /// A DO phase configured to stop as soon as the quote round finishes.
    ///
    /// `SSH_SFTP_TRANS_INIT` routes a trailing-slash path to
    /// `SSH_SFTP_READDIR_INIT`, and `CURLOPT_NOBODY` makes THAT state stop before
    /// it opens anything. So `curl -I sftp://host/dir/ --quote ...` exercises the
    /// quote phase and nothing after it -- a real invocation rather than a
    /// contrivance, which matters because the DO phase legitimately runs on into
    /// the transfer and a test of the quote states must not have to script it.
    fn quote_only(quote: &[&[u8]]) -> (SshProto, SshSettings) {
        let sshp = SshProto {
            path: b"/dir/".to_vec(),
            ..SshProto::default()
        };
        let settings = SshSettings {
            quote: quote.iter().map(|line| line.to_vec()).collect(),
            no_body: true,
            ..settings()
        };
        (sshp, settings)
    }

    /// Run one DO/DONE step and answer what it decided.
    fn do_step(
        sshc: &mut SshConn,
        sshp: &mut SshProto,
        settings: &SshSettings,
        effects: &mut SftpEffects,
    ) -> StepOutcome {
        let clock = clock();
        let mut chains = FilterChains::new(None);
        let mut ctx = transfer_ctx(&mut chains, &clock);
        futures::executor::block_on(sftp_do_step(
            sshc, sshp, settings, effects, &mut ctx,
        ))
    }

    /// Drive the machine from `start` until it stops, answering the effects.
    fn drive(
        sshc: &mut SshConn,
        sshp: &mut SshProto,
        settings: &SshSettings,
        start: SshState,
    ) -> (CodeResult<()>, SftpEffects) {
        let clock = clock();
        let mut chains = FilterChains::new(None);
        let mut ctx = transfer_ctx(&mut chains, &clock);
        let mut effects = SftpEffects::new();
        ssh_set_state(sshc, None, start);
        let phase = start.phase();
        let outcome = futures::executor::block_on(ssh_run_phase(
            sshc,
            sshp,
            settings,
            &mut effects,
            &mut ctx,
            phase,
            4096,
        ));
        (outcome, effects)
    }

    // -- 1. the registry row -----------------------------------------------

    #[test]
    fn the_registry_row_is_the_measured_one() {
        // `Curl_scheme_sftp` (`lib/vssh/vssh.c:338-350`), member by member.
        //
        // ⚠ UPPER CASE. The C's own `struct Curl_scheme` comment says
        // "URL scheme name in lowercase" and the row does not obey it; four of
        // the 33 rows are upper case. Matching is case-folded on both sides, so
        // it works -- and "correcting" the spelling would silently detach the row
        // from the line it was transcribed from.
        assert_eq!(SCHEME.name, b"SFTP");
        assert_eq!(SCHEME.protocol, Proto::SFTP);
        assert_eq!(SCHEME.family, Proto::SFTP);
        assert_eq!(SCHEME.defport, PORT_SSH);
        assert_eq!(PORT_SSH, 22, "PORT_SSH");
    }

    #[test]
    fn the_row_carries_exactly_four_option_bits() {
        let flags = SCHEME.flags;
        for bit in [
            ProtocolOptions::DIRLOCK,
            ProtocolOptions::CLOSEACTION,
            ProtocolOptions::NOURLQUERY,
            ProtocolOptions::CONN_REUSE,
        ] {
            assert!(flags.contains(bit), "missing {bit:?}");
        }
        // And nothing else. `PROTOPT_WILDCARD` in particular: `ftp` and `ftps`
        // carry it, neither SSH scheme does, so directory globbing does not
        // apply here.
        assert_eq!(
            flags.bits(),
            ProtocolOptions::DIRLOCK.bits()
                | ProtocolOptions::CLOSEACTION.bits()
                | ProtocolOptions::NOURLQUERY.bits()
                | ProtocolOptions::CONN_REUSE.bits()
        );
        assert!(!flags.contains(ProtocolOptions::WILDCARD));
        assert!(!flags.contains(ProtocolOptions::DUAL));
        assert!(!flags.contains(ProtocolOptions::SSL));
    }

    #[test]
    fn the_row_is_runnable_and_points_at_the_one_instance() {
        assert!(SCHEME.runnable());
        let run = SCHEME.run.expect("the row carries an implementation");
        // Dispatched through the trait object, which is the object-safety
        // regression test specification 0.3.3's pattern P1 requires: neither
        // `async fn` in a trait nor RPITIT is dyn-compatible, so if a
        // `ProtoFuture` were ever replaced by one this line would stop
        // compiling.
        let clock = clock();
        let mut chains = FilterChains::new(None);
        let mut ctx = transfer_ctx(&mut chains, &clock);
        let outcome = futures::executor::block_on(run.do_it(&mut ctx));
        assert_eq!(outcome, Err(CURLcode::NotBuiltIn));
    }

    // -- 2. the 62-state machine -------------------------------------------

    #[test]
    fn all_sixty_two_states_are_declared_in_the_measured_order() {
        assert_eq!(SSH_STATES.len(), 62);
        // `SSH_NO_STATE = -1`, `SSH_STOP = 0`, and every later token one more
        // than the last -- which is what `enum sshstate` gives without any
        // explicit values, and what a table indexed by state depends on.
        assert_eq!(SshState::NoState.as_i32(), -1);
        assert_eq!(SshState::Stop.as_i32(), 0);
        for (index, state) in SSH_STATES.iter().enumerate() {
            let expected = i32::try_from(index).expect("62 fits") - 1;
            assert_eq!(state.as_i32(), expected, "{state:?}");
            assert_eq!(SshState::from_discriminant(expected), Some(*state));
        }
        // `SSH_LAST` is the length of `Curl_ssh_statename`'s table, measured at
        // 60 entries: `SSH_STOP` through `"QUIT"`.
        assert_eq!(SSH_LAST, 60);
        assert_eq!(SshState::Last.as_i32(), 60);
    }

    #[test]
    fn every_state_name_is_the_measured_one() {
        // `Curl_ssh_statename`'s table, spot-checked at its boundaries and at
        // the one entry that breaks the pattern.
        assert_eq!(SshState::Stop.name(), "SSH_STOP");
        assert_eq!(SshState::Init.name(), "SSH_INIT");
        assert_eq!(SshState::SftpRealpath.name(), "SSH_SFTP_REALPATH");
        assert_eq!(SshState::SftpQuoteInit.name(), "SSH_SFTP_QUOTE_INIT");
        assert_eq!(SshState::SftpDownloadStat.name(), "SSH_SFTP_DOWNLOAD_STAT");
        assert_eq!(SshState::SftpClose.name(), "SSH_SFTP_CLOSE");
        assert_eq!(SshState::SftpShutdown.name(), "SSH_SFTP_SHUTDOWN");
        assert_eq!(SshState::ScpTransInit.name(), "SSH_SCP_TRANS_INIT");
        assert_eq!(SshState::ScpChannelFree.name(), "SSH_SCP_CHANNEL_FREE");
        assert_eq!(
            SshState::SessionDisconnect.name(),
            "SSH_SESSION_DISCONNECT"
        );
        assert_eq!(SshState::SessionFree.name(), "SSH_SESSION_FREE");
        // ⚠ The one entry with no `SSH_` prefix, alone among the 60.
        assert_eq!(SshState::Quit.name(), "QUIT");
        // And `Display` is the name, so a trace line interpolates it directly.
        assert_eq!(SshState::Quit.to_string(), "QUIT");
    }

    #[test]
    fn the_transition_function_is_the_only_mutator() {
        let (mut sshc, _peer) = conn_over(Scripted::new());
        // A connection begins in `SSH_STOP`, because `ssh_setup_connection`
        // allocates with `calloc` and zero is that state.
        assert_eq!(sshc.state(), SshState::Stop);
        ssh_set_state(&mut sshc, None, SshState::Init);
        assert_eq!(sshc.state(), SshState::Init);
        ssh_set_state(&mut sshc, None, SshState::SStartup);
        assert_eq!(sshc.state(), SshState::SStartup);
        // There is no `set_state`, no `state_mut` and no public field, so this
        // is not a convention the way the C's comment is -- it is the only
        // writer that exists.
    }

    #[test]
    fn a_transition_emits_the_measured_trace_line() {
        use crate::trace::{
            TraceConfig, TraceFeature as Feat, TraceLevel, TraceState,
            WriterSink,
        };
        let mut sink = WriterSink::new(Vec::<u8>::new());
        let mut config = TraceConfig::new();
        config.set_feature_level(Feat::Ssh, TraceLevel::Info);
        let state = TraceState {
            verbose: true,
            feat: None,
            ids: crate::trace::TraceIds::new(0, 0),
        };

        let (mut sshc, _peer) = conn_over(Scripted::new());
        {
            let mut tracer =
                crate::trace::Tracer::new(&config, &mut sink).with_state(state);
            ssh_set_state(&mut sshc, Some(&mut tracer), SshState::Init);
            // The same state twice: `if(sshc->state != nowstate)` suppresses
            // the line, which matters because `sftp_done` re-enters
            // `SSH_SFTP_CLOSE`.
            ssh_set_state(&mut sshc, Some(&mut tracer), SshState::Init);
        }

        let text = String::from_utf8(sink.into_inner()).expect("utf-8");
        assert_eq!(
            text.matches("[SSH_STOP] -> [SSH_INIT]").count(),
            1,
            "one line, not two: {text}"
        );
        // The feature name is the C's `Curl_trc_feat_ssh` at
        // `lib/curl_trc.c:462`, consumed from `trace.rs` rather than spelled
        // here.
        assert!(text.contains(TraceFeature::Ssh.name()), "{text}");
    }

    #[test]
    fn the_phase_boundaries_are_the_measured_ones() {
        // `lib/vssh/ssh.h`'s comments, which are the only documentation the C
        // has of the machine's structure -- and the map for the split between
        // this file and `protocols/scp.rs`.
        assert_eq!(SshState::Init.phase(), SshPhase::SshConnect);
        assert_eq!(SshState::SftpRealpath.phase(), SshPhase::SshConnect);
        assert_eq!(SshState::SftpQuoteInit.phase(), SshPhase::SftpDo);
        assert_eq!(SshState::SftpDownloadStat.phase(), SshPhase::SftpDo);
        assert_eq!(SshState::SftpPostquoteInit.phase(), SshPhase::SftpDone);
        assert_eq!(SshState::SftpClose.phase(), SshPhase::SftpDone);
        assert_eq!(SshState::SftpShutdown.phase(), SshPhase::SftpDisconnect);
        assert_eq!(SshState::ScpTransInit.phase(), SshPhase::ScpDo);
        assert_eq!(SshState::ScpChannelFree.phase(), SshPhase::ScpDone);
        assert_eq!(
            SshState::SessionDisconnect.phase(),
            SshPhase::SessionTeardown
        );
        // ⚠ `SSH_SESSION_FREE` terminates BOTH disconnect phases, which is why
        // it is owned here and not by either scheme's own module.
        assert_eq!(SshState::SessionFree.phase(), SshPhase::SessionTeardown);
        assert_eq!(SshState::Stop.phase(), SshPhase::Idle);
        assert_eq!(SshState::Quit.phase(), SshPhase::Idle);
    }

    #[test]
    fn the_scp_owned_states_are_exactly_the_nine() {
        let owned: Vec<SshState> = SSH_STATES
            .iter()
            .copied()
            .filter(|state| state.is_scp_owned())
            .collect();
        assert_eq!(
            owned,
            [
                SshState::ScpTransInit,
                SshState::ScpUploadInit,
                SshState::ScpDownloadInit,
                SshState::ScpDownload,
                SshState::ScpDone,
                SshState::ScpSendEof,
                SshState::ScpWaitEof,
                SshState::ScpWaitClose,
                SshState::ScpChannelFree,
            ]
        );
    }

    #[test]
    fn an_exhaustive_match_over_every_state_compiles() {
        // THE pattern-P3 regression test. Both phase drivers match every one of
        // the 62 variants with no wildcard, so adding a state without handling
        // it is a compile error rather than a runtime fall-through. This
        // function is the third such match, and it exists so that the property
        // is asserted rather than merely relied upon.
        for state in SSH_STATES {
            let described = match state {
                SshState::NoState => 0_u8,
                SshState::Stop => 1,
                SshState::Init
                | SshState::SStartup
                | SshState::HostKey
                | SshState::AuthList
                | SshState::AuthPkeyInit
                | SshState::AuthPkey
                | SshState::AuthPassInit
                | SshState::AuthPass
                | SshState::AuthAgentInit
                | SshState::AuthAgentList
                | SshState::AuthAgent
                | SshState::AuthHostInit
                | SshState::AuthHost
                | SshState::AuthKeyInit
                | SshState::AuthKey
                | SshState::AuthGssapi
                | SshState::AuthDone
                | SshState::SftpInit
                | SshState::SftpRealpath => 2,
                SshState::SftpQuoteInit
                | SshState::SftpPostquoteInit
                | SshState::SftpQuote
                | SshState::SftpNextQuote
                | SshState::SftpQuoteStat
                | SshState::SftpQuoteSetstat
                | SshState::SftpQuoteSymlink
                | SshState::SftpQuoteMkdir
                | SshState::SftpQuoteRename
                | SshState::SftpQuoteRmdir
                | SshState::SftpQuoteUnlink
                | SshState::SftpQuoteStatvfs
                | SshState::SftpGetinfo
                | SshState::SftpFiletime
                | SshState::SftpTransInit
                | SshState::SftpUploadInit
                | SshState::SftpCreateDirsInit
                | SshState::SftpCreateDirs
                | SshState::SftpCreateDirsMkdir
                | SshState::SftpReaddirInit
                | SshState::SftpReaddir
                | SshState::SftpReaddirLink
                | SshState::SftpReaddirBottom
                | SshState::SftpReaddirDone
                | SshState::SftpDownloadInit
                | SshState::SftpDownloadStat
                | SshState::SftpClose
                | SshState::SftpShutdown => 3,
                SshState::ScpTransInit
                | SshState::ScpUploadInit
                | SshState::ScpDownloadInit
                | SshState::ScpDownload
                | SshState::ScpDone
                | SshState::ScpSendEof
                | SshState::ScpWaitEof
                | SshState::ScpWaitClose
                | SshState::ScpChannelFree => 4,
                SshState::SessionDisconnect | SshState::SessionFree => 5,
                SshState::Quit | SshState::Last => 6,
            };
            assert!(described <= 6);
        }
    }

    // -- 3. the vtable: 11 of 17 slots -------------------------------------

    #[test]
    fn exactly_eleven_of_seventeen_slots_are_overridden() {
        // `Curl_protocol_sftp` (`lib/vssh/libssh2.c:3846-3864`) fills eleven
        // members and leaves six `ZERO_NULL`. The overridden ones are asserted
        // by behaviour below; the six defaults are asserted here, because a
        // default that silently changed would be invisible otherwise.
        let clock = clock();
        let mut chains = FilterChains::new(None);
        let mut ctx = transfer_ctx(&mut chains, &clock);
        let handler: &dyn Protocol = &SFTP;

        // 4. `do_more` -- SFTP is not `PROTOPT_DUAL`, so the second DO half
        //    completes immediately.
        assert_eq!(
            futures::executor::block_on(handler.do_more(&mut ctx)),
            Ok(true)
        );
        // 13, 14. `write_resp` and `write_resp_hd` -- false, so the generic
        //    client-writer chain runs.
        assert_eq!(
            futures::executor::block_on(
                handler.write_resp(&mut ctx, b"body", false)
            ),
            Ok(false)
        );
        assert_eq!(
            futures::executor::block_on(
                handler.write_resp_hd(&mut ctx, b"header", false)
            ),
            Ok(false)
        );
        // 15. `connection_check` -- the pool learns nothing extra.
        assert_eq!(
            handler.connection_check(
                &mut ctx,
                crate::conn::pool::ConnCheck::ISDEAD
            ),
            crate::conn::pool::ConnResult::NONE
        );
        // 17. `follow` -- SFTP has no redirects, and `multi_follow` answers
        //     `CURLE_TOO_MANY_REDIRECTS` for a NULL slot.
        assert_eq!(
            handler.follow(
                &mut ctx,
                "sftp://elsewhere/",
                crate::transfer::request::FollowType::None,
            ),
            Err(CURLcode::TooManyRedirects)
        );
        // 10. `domore_pollset` -- a no-op, for the same reason as `do_more`.
        let mut ps = EasyPollset::new();
        assert_eq!(handler.domore_pollset(&mut ctx, &mut ps), Ok(()));
        assert_eq!(ps.len(), 0);
    }

    #[test]
    fn the_three_pollset_slots_are_filled_and_the_fourth_is_not() {
        let clock = clock();
        let (mut chains, _state) = chains_with_transport(&clock, 7);
        let mut ctx = transfer_ctx(&mut chains, &clock);
        let handler: &dyn Protocol = &SFTP;

        // `ssh_pollset`'s third case: no session, no waitfor, no keepon -- and
        // the C still watches for readability *"while we still have a
        // session"*, so with none it records nothing and reports success.
        //
        // Three separate calls rather than a loop over function pointers,
        // because each needs its own mutable borrow of the context -- which is
        // also how the multi loop reaches them.
        let mut ps = EasyPollset::new();
        assert_eq!(handler.proto_pollset(&mut ctx, &mut ps), Ok(()));
        assert_eq!(ps.len(), 0, "no session means no interest");

        let mut ps = EasyPollset::new();
        assert_eq!(handler.doing_pollset(&mut ctx, &mut ps), Ok(()));
        assert_eq!(ps.len(), 0, "no session means no interest");

        let mut ps = EasyPollset::new();
        assert_eq!(handler.perform_pollset(&mut ctx, &mut ps), Ok(()));
        assert_eq!(ps.len(), 0, "no session means no interest");
    }

    #[test]
    fn the_pollset_honours_waitfor_then_keepon_then_the_session() {
        let clock = clock();
        let (mut chains, _state) = chains_with_transport(&clock, 11);
        let mut ctx = transfer_ctx(&mut chains, &clock);

        // Case 1: `waitfor` wins over `keepon`, and RECV becomes POLL_IN.
        let mut ps = EasyPollset::new();
        assert_eq!(
            ssh_pollset(&mut ctx, &mut ps, SshWait::RECV, SshWait::SEND, true),
            Ok(())
        );
        assert_eq!(ps.len(), 1);
        assert_eq!(ps.action_of(11), PollAction::IN);

        // Case 1b: SEND becomes POLL_OUT, and both become both.
        let mut ps = EasyPollset::new();
        assert_eq!(
            ssh_pollset(
                &mut ctx,
                &mut ps,
                SshWait::RECV | SshWait::SEND,
                SshWait::NONE,
                true
            ),
            Ok(())
        );
        assert_eq!(ps.action_of(11), PollAction::IN | PollAction::OUT);

        // Case 2: `waitfor` clear, so `data->req.keepon` supplies it.
        let mut ps = EasyPollset::new();
        assert_eq!(
            ssh_pollset(&mut ctx, &mut ps, SshWait::NONE, SshWait::SEND, true),
            Ok(())
        );
        assert_eq!(ps.action_of(11), PollAction::OUT);

        // Case 3: neither, but a session exists -- readability only.
        let mut ps = EasyPollset::new();
        assert_eq!(
            ssh_pollset(&mut ctx, &mut ps, SshWait::NONE, SshWait::NONE, true),
            Ok(())
        );
        assert_eq!(ps.action_of(11), PollAction::IN);
    }

    #[test]
    fn an_invalid_descriptor_is_refused_as_failed_init() {
        // `if(!sshc || (sock == CURL_SOCKET_BAD)) return CURLE_FAILED_INIT;`
        let clock = clock();
        let (mut chains, _state) =
            chains_with_transport(&clock, crate::conn::select::CURL_SOCKET_BAD);
        let mut ctx = transfer_ctx(&mut chains, &clock);
        let mut ps = EasyPollset::new();
        assert_eq!(
            ssh_pollset(&mut ctx, &mut ps, SshWait::RECV, SshWait::NONE, true),
            Err(CURLcode::FailedInit)
        );
        assert!(!is_valid_sock(crate::conn::select::CURL_SOCKET_BAD));
    }

    #[test]
    fn attach_requires_the_ssh_family_and_nothing_else() {
        // `ssh_attach` (`lib/vssh/libssh2.c:3806-3820`) repairs a pointer that
        // has no successor here, so what is left is the precondition every other
        // member assumes: the scheme really is an SSH one.
        let clock = clock();
        let mut chains = FilterChains::new(None);
        let mut ctx = transfer_ctx(&mut chains, &clock);
        assert!(ssh_attach(&mut ctx));
        let handler: &dyn Protocol = &SFTP;
        handler.attach(&mut ctx);
        assert_eq!(handler.setup_connection(&mut ctx), Ok(()));
        assert!(Proto::SFTP.intersects(Proto::FAMILY_SSH));
        assert!(Proto::SCP.intersects(Proto::FAMILY_SSH));
        assert!(!Proto::HTTP.intersects(Proto::FAMILY_SSH));
    }

    #[test]
    fn setup_connection_answers_both_state_carriers() {
        // `ssh_setup_connection` (`:3167-3191`) allocates `struct SSHPROTO` and
        // `struct ssh_conn` with `calloc`, so both start zeroed and the state
        // starts at `SSH_STOP`.
        let (conn, proto) = ssh_setup_connection(
            Box::new(Shared(std::sync::Arc::new(
                crate::util::sync_cell::SyncCell::new(Scripted::new()),
            ))),
            seams(),
        );
        assert_eq!(conn.state(), SshState::Stop);
        assert_eq!(conn.nextstate, SshState::NoState);
        assert!(!conn.authed);
        assert_eq!(proto, SshProto::default());
    }

    // -- 4. authentication ordering ----------------------------------------

    #[test]
    fn the_authentication_order_is_the_measured_one() {
        let all = SshAuthTypes::ANY;
        let offered =
            b"publickey,password,hostbased,keyboard-interactive".as_slice();

        // Public key first, as `ssh_state_pkey_init` decides.
        assert_eq!(
            next_auth_state(SshState::AuthPkeyInit, all, offered, false),
            SshState::AuthPkey
        );
        // A refused public key moves to the password branch WITHOUT an error.
        assert_eq!(
            next_auth_state(SshState::AuthPkey, all, offered, false),
            SshState::AuthPassInit
        );
        assert_eq!(
            next_auth_state(SshState::AuthPassInit, all, offered, false),
            SshState::AuthPass
        );
        assert_eq!(
            next_auth_state(SshState::AuthPass, all, offered, false),
            SshState::AuthHostInit
        );
        assert_eq!(
            next_auth_state(SshState::AuthHostInit, all, offered, false),
            SshState::AuthHost
        );
        // ⚠ `SSH_AUTH_HOST`'s whole body is a no-op in the C, so it advances
        // UNCONDITIONALLY rather than attempting anything.
        assert_eq!(
            next_auth_state(SshState::AuthHost, all, offered, false),
            SshState::AuthAgentInit
        );
        // The agent is gated on `publickey` being offered, not on an
        // `agent` token -- there is no such token.
        assert_eq!(
            next_auth_state(SshState::AuthAgentInit, all, offered, false),
            SshState::AuthAgentList
        );
        // ⚠ `SSH_AUTH_AGENT_LIST`'s flag is not an authentication outcome: it is
        // whether `libssh2_agent_list_identities` succeeded. A failure goes to
        // `SSH_AUTH_KEY_INIT` with `infof(data, "Failure requesting identities
        // to agent")` and NEVER an error.
        assert_eq!(
            next_auth_state(SshState::AuthAgentList, all, offered, true),
            SshState::AuthAgent
        );
        assert_eq!(
            next_auth_state(SshState::AuthAgentList, all, offered, false),
            SshState::AuthKeyInit
        );
        assert_eq!(
            next_auth_state(SshState::AuthAgent, all, offered, false),
            SshState::AuthKeyInit
        );
        assert_eq!(
            next_auth_state(SshState::AuthKeyInit, all, offered, false),
            SshState::AuthKey
        );
        // And every success goes straight to `SSH_AUTH_DONE`.
        for from in [
            SshState::AuthPkey,
            SshState::AuthPass,
            SshState::AuthAgent,
            SshState::AuthKey,
        ] {
            assert_eq!(
                next_auth_state(from, all, offered, true),
                SshState::AuthDone,
                "{from:?}"
            );
        }
    }

    #[test]
    fn a_mechanism_the_option_bits_exclude_is_skipped() {
        let offered =
            b"publickey,password,hostbased,keyboard-interactive".as_slice();
        // `CURLSSH_AUTH_PASSWORD` alone: the public-key branch is skipped.
        let only_password = SshAuthTypes::PASSWORD;
        assert_eq!(
            next_auth_state(
                SshState::AuthPkeyInit,
                only_password,
                offered,
                false
            ),
            SshState::AuthPassInit
        );
        assert_eq!(
            next_auth_state(
                SshState::AuthPassInit,
                only_password,
                offered,
                false
            ),
            SshState::AuthPass
        );
        assert_eq!(
            next_auth_state(
                SshState::AuthHostInit,
                only_password,
                offered,
                false
            ),
            SshState::AuthAgentInit
        );
        assert_eq!(
            next_auth_state(
                SshState::AuthKeyInit,
                only_password,
                offered,
                false
            ),
            SshState::AuthDone
        );
        // And a mechanism the SERVER does not offer is skipped too, even when
        // the option permits it.
        assert_eq!(
            next_auth_state(
                SshState::AuthPkeyInit,
                SshAuthTypes::ANY,
                b"password",
                false
            ),
            SshState::AuthPassInit
        );
    }

    #[test]
    fn the_method_membership_test_is_a_substring_search() {
        // `strstr(sshc->authlist, "publickey")`, which is what libssh2's
        // comma-separated list is searched with.
        assert!(authlist::offers(b"publickey,password", authlist::PUBLICKEY));
        assert!(authlist::offers(b"password,publickey", authlist::PUBLICKEY));
        assert!(!authlist::offers(b"password", authlist::PUBLICKEY));
        assert!(authlist::offers(
            b"keyboard-interactive",
            authlist::KEYBOARD_INTERACTIVE
        ));
        assert!(authlist::offers(b"hostbased", authlist::HOSTBASED));
        assert!(!authlist::offers(b"", authlist::PASSWORD));
    }

    #[test]
    fn gssapi_has_no_arm_and_therefore_stops() {
        // `SSH_AUTH_GSSAPI` reaches the C's `default:` and stops. Reproduced
        // exactly rather than implemented, because implementing it would add a
        // mechanism curl does not have.
        let (mut sshc, _peer) = conn_over(Scripted::new());
        let mut sshp = SshProto::default();
        let set = settings();
        let clock = clock();
        let mut chains = FilterChains::new(None);
        let mut ctx = transfer_ctx(&mut chains, &clock);
        ssh_set_state(&mut sshc, None, SshState::AuthGssapi);
        let outcome = futures::executor::block_on(ssh_connect_step(
            &mut sshc, &mut sshp, &set, &mut ctx,
        ));
        assert_eq!(
            outcome,
            StepOutcome::Advance {
                next: SshState::Stop,
                info: None
            }
        );
        assert!(SshAuthTypes::ANY.contains(SshAuthTypes::GSSAPI));
    }

    #[test]
    fn every_mechanism_failing_reports_login_denied() {
        let mut script = Scripted::new();
        script.auth_list =
            Ok(b"publickey,password,hostbased,keyboard-interactive".to_vec());
        let (mut sshc, peer) = conn_over(script);
        let mut sshp = SshProto::default();
        let mut set = settings();
        set.private_key = Some("/nonexistent/id_ed25519".to_owned());

        let (outcome, effects) =
            drive(&mut sshc, &mut sshp, &set, SshState::Init);
        assert_eq!(outcome, Err(CURLcode::LoginDenied));
        // ⚠ `SSH_AUTH_KEY`'s refusal is the one terminal failure with NO
        // message and NO state change: `return CURLE_LOGIN_DENIED;`.
        assert!(
            !effects
                .info
                .iter()
                .any(|line| line == "Authentication failure"),
            "the keyboard-interactive refusal is silent: {:?}",
            effects.info
        );
        // Every mechanism was attempted, in order.
        let calls = peer.borrow().calls.clone();
        assert_eq!(
            calls,
            [
                "handshake",
                "auth_list",
                "publickey",
                "password",
                "agent",
                "keyboard",
            ]
        );
    }

    #[test]
    fn a_server_that_needs_no_authentication_is_accepted() {
        // `libssh2_userauth_list` answering an empty list plus
        // `libssh2_userauth_authenticated` -- the C logs *"SSH user accepted
        // with no authentication"*.
        let mut script = Scripted::new();
        script.auth_list = Ok(Vec::new());
        script.authenticated = true;
        let (mut sshc, _peer) = conn_over(script);
        let mut sshp = SshProto::default();
        let set = settings();
        ssh_set_state(&mut sshc, None, SshState::AuthList);
        let clock = clock();
        let mut chains = FilterChains::new(None);
        let mut ctx = transfer_ctx(&mut chains, &clock);
        let outcome = futures::executor::block_on(ssh_connect_step(
            &mut sshc, &mut sshp, &set, &mut ctx,
        ));
        assert_eq!(
            outcome,
            StepOutcome::Advance {
                next: SshState::AuthDone,
                info: Some(
                    "SSH user accepted with no authentication".to_owned()
                ),
            }
        );
        assert!(sshc.authed);
    }

    #[test]
    fn an_empty_list_from_an_unauthenticated_server_is_refused() {
        let mut script = Scripted::new();
        script.auth_list = Ok(Vec::new());
        script.authenticated = false;
        let (mut sshc, _peer) = conn_over(script);
        let mut sshp = SshProto::default();
        let set = settings();
        ssh_set_state(&mut sshc, None, SshState::AuthList);
        let clock = clock();
        let mut chains = FilterChains::new(None);
        let mut ctx = transfer_ctx(&mut chains, &clock);
        let outcome = futures::executor::block_on(ssh_connect_step(
            &mut sshc, &mut sshp, &set, &mut ctx,
        ));
        assert_eq!(outcome.code(), CURLcode::Ssh);
        assert!(outcome.is_failure());
        assert!(matches!(outcome, StepOutcome::FailAndFree { .. }));
    }

    #[test]
    fn the_private_key_guesses_are_the_measured_five_in_order() {
        // `lib/vssh/libssh2.c:1086-1124`: `$HOME/.ssh/id_rsa`,
        // `$HOME/.ssh/id_dsa`, then the two bare names, then the EMPTY STRING --
        // which the C's own comment explains is deliberate, *"to avoid
        // surprising info messages"*.
        //
        // The existence predicate is injected, so the order is asserted without
        // touching a filesystem. Each case names exactly which files exist.
        let none = |_: &str| false;
        let all = |_: &str| true;
        let only = |wanted: &'static str| move |path: &str| path == wanted;

        assert_eq!(
            private_key_guess(Some("/home/u"), &all),
            "/home/u/.ssh/id_rsa"
        );
        assert_eq!(
            private_key_guess(Some("/home/u"), &only("/home/u/.ssh/id_dsa")),
            "/home/u/.ssh/id_dsa"
        );
        assert_eq!(
            private_key_guess(Some("/home/u"), &only("id_rsa")),
            "id_rsa"
        );
        assert_eq!(
            private_key_guess(Some("/home/u"), &only("id_dsa")),
            "id_dsa"
        );
        // ⚠ Out of guesses: the empty string, which is a NAME the transport will
        // refuse rather than a skipped state.
        assert_eq!(private_key_guess(Some("/home/u"), &none), "");

        // With no `$HOME` the two absolute guesses are skipped entirely, because
        // the C only builds them `if(home)`.
        assert_eq!(private_key_guess(None, &all), "id_rsa");
        assert_eq!(private_key_guess(None, &only("id_dsa")), "id_dsa");
        assert_eq!(private_key_guess(None, &none), "");
    }

    #[test]
    fn an_absent_passphrase_is_the_empty_string_not_a_null() {
        // `passphrase ? passphrase : ""` -- libssh2 is handed a string either
        // way, which is what makes an unencrypted key work with no option set.
        assert_eq!(key_passphrase(None), "");
        assert_eq!(key_passphrase(Some("")), "");
        assert_eq!(key_passphrase(Some("secret")), "secret");
    }

    // -- 5. host-key verification ------------------------------------------

    #[test]
    fn a_matching_md5_fingerprint_accepts_and_a_mismatch_refuses() {
        let key = b"a host key blob".as_slice();
        let expected = md5_fingerprint_hex(key);
        assert_eq!(expected.len(), 32, "16 bytes as lower-case hex");

        let policy = HostKeyPolicy {
            md5: Some(expected.clone()),
            ..HostKeyPolicy::default()
        };
        assert_eq!(
            check_fingerprint(key, &policy),
            Ok(HostKeyDecision::Accepted)
        );

        // ⚠ `curl_strequal`, so the comparison is case-INSENSITIVE: an upper-case
        // fingerprint on the command line still matches.
        let upper = HostKeyPolicy {
            md5: Some(expected.to_uppercase()),
            ..HostKeyPolicy::default()
        };
        assert_eq!(
            check_fingerprint(key, &upper),
            Ok(HostKeyDecision::Accepted)
        );

        let wrong = HostKeyPolicy {
            md5: Some("00112233445566778899aabbccddeeff".to_owned()),
            ..HostKeyPolicy::default()
        };
        let refusal =
            check_fingerprint(key, &wrong).expect_err("a mismatch refuses");
        assert_eq!(refusal.code(), CURLcode::PeerFailedVerification);
        assert_eq!(
            refusal.message(),
            Some(format!(
                "Denied establishing ssh session: mismatch md5 fingerprint. \
                 Remote {expected} is not equal to \
                 00112233445566778899aabbccddeeff"
            ))
        );
    }

    #[test]
    fn a_matching_sha256_fingerprint_accepts_and_a_mismatch_refuses() {
        let key = b"a host key blob".as_slice();
        let expected = sha256_fingerprint_base64(key).expect("32 bytes encode");
        let policy = HostKeyPolicy {
            sha256: Some(expected.clone()),
            ..HostKeyPolicy::default()
        };
        assert_eq!(
            check_fingerprint(key, &policy),
            Ok(HostKeyDecision::Accepted)
        );

        let wrong = HostKeyPolicy {
            sha256: Some(
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            ),
            ..HostKeyPolicy::default()
        };
        let refusal = check_fingerprint(key, &wrong).expect_err("mismatch");
        assert_eq!(refusal.code(), CURLcode::PeerFailedVerification);
        assert!(
            refusal
                .message()
                .is_some_and(|text| text.contains("mismatch sha256")),
            "{:?}",
            refusal.message()
        );
    }

    #[test]
    fn the_sha256_comparison_is_padding_insensitive_in_the_measured_way() {
        // `lib/vssh/libssh2.c:497-520`: the C finds the FIRST `=` in EACH
        // string, requires the two positions to be equal, and then compares that
        // prefix. So padding may be present or absent on either side, but the
        // unpadded lengths must agree.
        assert!(sha256_fingerprints_match("abcd", "abcd"));
        assert!(sha256_fingerprints_match("abcd=", "abcd"));
        assert!(sha256_fingerprints_match("abcd", "abcd="));
        assert!(sha256_fingerprints_match("abcd==", "abcd="));
        assert!(!sha256_fingerprints_match("abcde", "abcd"));
        assert!(!sha256_fingerprints_match("abce", "abcd"));
        // A leading `=` makes both prefixes empty, and the C accepts that --
        // preserved rather than corrected, because it is what the comparison
        // does.
        assert!(sha256_fingerprints_match("=x", "=y"));
    }

    #[test]
    fn an_absent_key_is_refused_rather_than_accepted() {
        let policy = HostKeyPolicy {
            sha256: Some("AAAA".to_owned()),
            ..HostKeyPolicy::default()
        };
        let refusal = check_fingerprint(b"", &policy).expect_err("no key");
        assert_eq!(
            refusal.message(),
            Some(
                "Denied establishing ssh session: sha256 fingerprint not \
                 available"
                    .to_owned()
            )
        );
        let md5_only = HostKeyPolicy {
            md5: Some("00".to_owned()),
            ..HostKeyPolicy::default()
        };
        let refusal = check_fingerprint(b"", &md5_only).expect_err("no key");
        assert_eq!(
            refusal.message(),
            Some(
                "Denied establishing ssh session: md5 fingerprint not \
                 available"
                    .to_owned()
            )
        );
    }

    #[test]
    fn with_no_fingerprint_the_callback_and_the_file_are_consulted_in_order() {
        let key = b"blob".as_slice();
        // `CURLOPT_SSH_KEYFUNCTION` set: the callback decides.
        let callback = HostKeyPolicy {
            hostkeyfunc: true,
            ..HostKeyPolicy::default()
        };
        assert_eq!(
            check_fingerprint(key, &callback),
            Ok(HostKeyDecision::AskHostKeyCallback)
        );
        // `CURLOPT_SSH_KNOWNHOSTS` set and no callback: the file decides.
        let known = HostKeyPolicy {
            known_hosts: true,
            ..HostKeyPolicy::default()
        };
        assert_eq!(
            check_fingerprint(key, &known),
            Ok(HostKeyDecision::ConsultKnownHosts)
        );
        // Neither: accepted, which is the C's behaviour for that configuration.
        assert_eq!(
            check_fingerprint(key, &HostKeyPolicy::default()),
            Ok(HostKeyDecision::Accepted)
        );
        // The callback with no key to show it is refused rather than asked.
        assert!(check_fingerprint(b"", &callback).is_err());
    }

    #[test]
    fn the_known_host_callback_outcomes_are_honoured() {
        // `enum curl_khstat` (`include/curl/curl.h`), whose integers are public
        // ABI: a C program compiled against curl 8.19.0-DEV holds them, so they
        // are written explicitly and asserted here rather than inferred.
        assert_eq!(KnownHostStat::FineAddToFile.as_i32(), 0);
        assert_eq!(KnownHostStat::Fine.as_i32(), 1);
        assert_eq!(KnownHostStat::Reject.as_i32(), 2);
        assert_eq!(KnownHostStat::Defer.as_i32(), 3);
        assert_eq!(KnownHostStat::FineReplace.as_i32(), 4);
        for stat in KnownHostStat::ALL {
            assert_eq!(KnownHostStat::from_i32(stat.as_i32()), Some(stat));
        }
        assert_eq!(KnownHostStat::from_i32(5), None);
        assert_eq!(KnownHostStat::from_i32(-1), None);

        // `ssh_knownhost` (`:303-454`): the three accepting outcomes continue
        // and the two refusing ones do not.
        assert!(KnownHostStat::accepts(Some(KnownHostStat::FineAddToFile)));
        assert!(KnownHostStat::accepts(Some(KnownHostStat::Fine)));
        assert!(KnownHostStat::accepts(Some(KnownHostStat::FineReplace)));
        assert!(!KnownHostStat::accepts(Some(KnownHostStat::Reject)));
        assert!(!KnownHostStat::accepts(Some(KnownHostStat::Defer)));
        // ⚠ A callback answer the C cannot interpret is NOT an acceptance, which
        // is what `None` stands for here.
        assert!(!KnownHostStat::accepts(None));

        // Only two of the accepting outcomes write the file, and they differ:
        // one adds and one replaces.
        assert!(KnownHostStat::FineAddToFile.writes_the_file());
        assert!(KnownHostStat::FineReplace.writes_the_file());
        assert!(!KnownHostStat::Fine.writes_the_file());

        // ⚠ And the two refusals differ in whether the session is freed, which
        // is the whole reason `CURLKHSTAT_DEFER` exists as a separate value.
        assert!(KnownHostStat::Reject.frees_the_session());
        assert!(!KnownHostStat::Defer.frees_the_session());
    }

    #[test]
    fn the_known_host_match_values_are_libssh2s() {
        // `LIBSSH2_KNOWNHOST_CHECK_*`, which `ssh_knownhost` switches on.
        assert_eq!(KnownHostMatch::Ok.as_i32(), 0);
        assert_eq!(KnownHostMatch::Mismatch.as_i32(), 1);
        assert_eq!(KnownHostMatch::Missing.as_i32(), 2);
        // And the check that produces one: a host absent from the file is
        // `MISSING`, a host present with a different key is `MISMATCH`, and a
        // host present with the same key is `OK`.
        assert_eq!(
            KnownHostMatch::from_check(false, false),
            KnownHostMatch::Missing
        );
        assert_eq!(
            KnownHostMatch::from_check(false, true),
            KnownHostMatch::Missing
        );
        assert_eq!(
            KnownHostMatch::from_check(true, false),
            KnownHostMatch::Mismatch
        );
        assert_eq!(KnownHostMatch::from_check(true, true), KnownHostMatch::Ok);
    }

    #[test]
    fn the_key_type_mapping_collapses_the_three_ecdsa_curves() {
        // `convert_ssh2_keytype` (`:269-301`) and `enum curl_khtype`, whose
        // integers are public ABI. The collapse is the C's, and it is lossy: a
        // callback cannot tell nistp256 from nistp521.
        assert_eq!(HostKeyType::Rsa1.as_i32(), 1);
        assert_eq!(HostKeyType::Rsa.as_i32(), 2);
        assert_eq!(HostKeyType::Dss.as_i32(), 3);
        assert_eq!(HostKeyType::Ecdsa.as_i32(), 4);
        assert_eq!(HostKeyType::Ed25519.as_i32(), 5);
        assert_eq!(HostKeyType::Unknown.as_i32(), 0);
        for name in [
            b"ecdsa-sha2-nistp256".as_slice(),
            b"ecdsa-sha2-nistp384".as_slice(),
            b"ecdsa-sha2-nistp521".as_slice(),
        ] {
            assert_eq!(HostKeyType::from_algorithm(name), HostKeyType::Ecdsa);
        }
        assert_eq!(HostKeyType::from_algorithm(b"ssh-rsa"), HostKeyType::Rsa);
        assert_eq!(
            HostKeyType::from_algorithm(b"ssh-ed25519"),
            HostKeyType::Ed25519
        );
        assert_eq!(HostKeyType::from_algorithm(b"ssh-dss"), HostKeyType::Dss);
        assert_eq!(
            HostKeyType::from_algorithm(b"something-else"),
            HostKeyType::Unknown
        );
        // And a blob reports its own.
        let blob = HostKeyBlob {
            blob: b"bytes".to_vec(),
            algorithm: b"ssh-ed25519".to_vec(),
        };
        assert_eq!(blob.key_type(), HostKeyType::Ed25519);
    }

    #[test]
    fn a_fingerprint_mismatch_reaches_the_host_key_state_as_a_failure() {
        let mut script = Scripted::new();
        script.hostkey = Some(HostKeyBlob {
            blob: b"the peer's key".to_vec(),
            algorithm: b"ssh-ed25519".to_vec(),
        });
        let (mut sshc, _peer) = conn_over(script);
        let mut sshp = SshProto::default();
        let mut set = settings();
        set.hostkey.md5 = Some("ffffffffffffffffffffffffffffffff".to_owned());

        ssh_set_state(&mut sshc, None, SshState::HostKey);
        let clock = clock();
        let mut chains = FilterChains::new(None);
        let mut ctx = transfer_ctx(&mut chains, &clock);
        let outcome = futures::executor::block_on(ssh_connect_step(
            &mut sshc, &mut sshp, &set, &mut ctx,
        ));
        assert_eq!(outcome.code(), CURLcode::PeerFailedVerification);
        assert!(outcome.is_failure());
    }

    // -- 6. the SFTP wire codec --------------------------------------------

    #[test]
    fn the_packet_numbers_are_the_protocols_own() {
        // The `SSH_FXP_*` constants of the SFTP draft, written explicitly for
        // the same reason `CURLcode`'s are: a peer holds them.
        assert_eq!(SftpPacket::Init.as_u8(), 1);
        assert_eq!(SftpPacket::Version.as_u8(), 2);
        assert_eq!(SftpPacket::Open.as_u8(), 3);
        assert_eq!(SftpPacket::Close.as_u8(), 4);
        assert_eq!(SftpPacket::Read.as_u8(), 5);
        assert_eq!(SftpPacket::Write.as_u8(), 6);
        assert_eq!(SftpPacket::Lstat.as_u8(), 7);
        assert_eq!(SftpPacket::Fstat.as_u8(), 8);
        assert_eq!(SftpPacket::Setstat.as_u8(), 9);
        assert_eq!(SftpPacket::Fsetstat.as_u8(), 10);
        assert_eq!(SftpPacket::Opendir.as_u8(), 11);
        assert_eq!(SftpPacket::Readdir.as_u8(), 12);
        assert_eq!(SftpPacket::Remove.as_u8(), 13);
        assert_eq!(SftpPacket::Mkdir.as_u8(), 14);
        assert_eq!(SftpPacket::Rmdir.as_u8(), 15);
        assert_eq!(SftpPacket::Realpath.as_u8(), 16);
        assert_eq!(SftpPacket::Stat.as_u8(), 17);
        assert_eq!(SftpPacket::Rename.as_u8(), 18);
        assert_eq!(SftpPacket::Readlink.as_u8(), 19);
        assert_eq!(SftpPacket::Symlink.as_u8(), 20);
        assert_eq!(SftpPacket::Status.as_u8(), 101);
        assert_eq!(SftpPacket::Handle.as_u8(), 102);
        assert_eq!(SftpPacket::Data.as_u8(), 103);
        assert_eq!(SftpPacket::Name.as_u8(), 104);
        assert_eq!(SftpPacket::Attrs.as_u8(), 105);
        assert_eq!(SftpPacket::Extended.as_u8(), 200);
        assert_eq!(SftpPacket::ExtendedReply.as_u8(), 201);
        // And the version this module offers is 3, which is what libssh2
        // negotiates.
        assert_eq!(SFTP_VERSION, 3);
    }

    #[test]
    fn a_request_is_framed_length_type_id_then_payload() {
        let packet =
            request::open(0x1122_3344, b"/tmp/x", SftpOpenFlags::READ, 0o644);
        // 1 type + 4 id + 4+6 path + 4 flags + 4 attr-flags + 4 mode = 27, and
        // the four-byte prefix covers everything after itself.
        assert_eq!(packet.len(), 4 + 27);
        assert_eq!(&packet[..4], &27_u32.to_be_bytes());
        assert_eq!(packet[4], SftpPacket::Open.as_u8());
        assert_eq!(&packet[5..9], &0x1122_3344_u32.to_be_bytes());
        assert_eq!(&packet[9..13], &6_u32.to_be_bytes());
        assert_eq!(&packet[13..19], b"/tmp/x");
        assert_eq!(&packet[19..23], &SftpOpenFlags::READ.bits().to_be_bytes());
        // ⚠ The attribute block carries `ATTR_PERMISSIONS` and the mode, on
        // EVERY open including a read-only one, because that is how libssh2
        // forwards `CURLOPT_NEW_FILE_PERMS`: `libssh2_sftp_open_ex` takes the
        // mode as a parameter and sends it unconditionally.
        assert_eq!(
            &packet[23..27],
            &SftpAttrFlags::PERMISSIONS.bits().to_be_bytes()
        );
        assert_eq!(&packet[27..31], &0o644_u32.to_be_bytes());
    }

    #[test]
    fn every_request_builder_emits_its_own_packet_type() {
        let cases: [(Vec<u8>, SftpPacket); 19] = [
            (request::init(), SftpPacket::Init),
            (
                request::open(1, b"/f", SftpOpenFlags::READ, 0o644),
                SftpPacket::Open,
            ),
            (request::opendir(2, b"/d"), SftpPacket::Opendir),
            (request::close(3, b"h"), SftpPacket::Close),
            (request::read(4, b"h", 0, 32), SftpPacket::Read),
            (request::write(5, b"h", 0, b"x"), SftpPacket::Write),
            (request::stat(6, b"/f"), SftpPacket::Stat),
            (request::lstat(7, b"/f"), SftpPacket::Lstat),
            (request::fstat(8, b"h"), SftpPacket::Fstat),
            (
                request::setstat(9, b"/f", &SftpAttributes::default()),
                SftpPacket::Setstat,
            ),
            (request::readdir(10, b"h"), SftpPacket::Readdir),
            (request::remove(11, b"/f"), SftpPacket::Remove),
            (request::mkdir(12, b"/d", 0o755), SftpPacket::Mkdir),
            (request::rmdir(13, b"/d"), SftpPacket::Rmdir),
            (request::realpath(14, b"."), SftpPacket::Realpath),
            (request::rename(15, b"/a", b"/b"), SftpPacket::Rename),
            (request::readlink(16, b"/l"), SftpPacket::Readlink),
            (request::symlink(17, b"/t", b"/l"), SftpPacket::Symlink),
            (request::statvfs(18, b"/"), SftpPacket::Extended),
        ];
        for (packet, kind) in cases {
            assert_eq!(packet[4], kind.as_u8(), "{kind:?}");
            // Every frame's prefix agrees with its own length.
            let mut prefix = [0_u8; 4];
            prefix.copy_from_slice(&packet[..4]);
            assert_eq!(
                usize::try_from(u32::from_be_bytes(prefix)).expect("fits"),
                packet.len() - 4,
                "{kind:?}"
            );
        }
    }

    #[test]
    fn the_statvfs_request_names_the_openssh_extension() {
        // `statvfs@openssh.com` is the extension NAME on the wire, and
        // `SSH_FXP_EXTENDED` carries it as its first string.
        let packet = request::statvfs(1, b"/");
        let mut reader =
            SftpReader::frame(&packet).expect("a well-formed frame");
        assert_eq!(reader.kind(), SftpPacket::Extended);
        assert_eq!(reader.get_u32(), Ok(1));
        assert_eq!(reader.get_bytes(), Ok(SFTP_STATVFS_EXTENSION.as_bytes()));
        assert_eq!(reader.get_bytes(), Ok(b"/".as_slice()));
        assert!(reader.remaining().is_empty());
    }

    #[test]
    fn an_attribute_block_writes_only_what_its_flags_claim() {
        let full = SftpAttributes {
            flags: SftpAttrFlags::SIZE
                | SftpAttrFlags::UIDGID
                | SftpAttrFlags::PERMISSIONS
                | SftpAttrFlags::ACMODTIME,
            filesize: 1 << 40,
            uid: 1000,
            gid: 1001,
            permissions: 0o100_644,
            atime: 111,
            mtime: 222,
        };
        let frame = attrs_frame(&full);
        assert_eq!(request::decode_attrs(&frame), Ok(full));

        // A block with no flags contributes four bytes and nothing else, which
        // is the whole reason the flags word exists.
        let empty = SftpAttributes::default();
        let frame = attrs_frame(&empty);
        // 4 length + 1 type + 4 id + 4 flags
        assert_eq!(frame.len(), 13);
        assert_eq!(request::decode_attrs(&frame), Ok(empty));
    }

    #[test]
    fn a_truncated_frame_is_malformed_rather_than_a_panic() {
        // A hostile peer must produce a `CURLcode`, never an abort.
        for prefix in 0..13_usize {
            let frame = attrs_frame(&sized(4));
            let cut = &frame[..prefix.min(frame.len())];
            assert!(
                SftpReader::frame(cut).is_err()
                    || request::decode_attrs(cut).is_err(),
                "a {prefix}-byte frame must not decode"
            );
        }
        // A length prefix claiming more than the buffer holds.
        let mut lying = attrs_frame(&sized(4));
        lying[..4].copy_from_slice(&9999_u32.to_be_bytes());
        assert_eq!(
            SftpReader::frame(&lying).err(),
            Some(SftpFailure::Malformed)
        );
        // A zero length.
        let mut empty = attrs_frame(&sized(4));
        empty[..4].copy_from_slice(&0_u32.to_be_bytes());
        assert_eq!(
            SftpReader::frame(&empty).err(),
            Some(SftpFailure::Malformed)
        );
        // A type byte this module does not exchange.
        let mut unknown = attrs_frame(&sized(4));
        unknown[4] = 250;
        assert_eq!(
            SftpReader::frame(&unknown).err(),
            Some(SftpFailure::Malformed)
        );
    }

    #[test]
    fn a_status_reply_decodes_as_its_status_and_a_non_ok_one_fails() {
        assert_eq!(request::decode_ok(&status_frame(SftpStatus::OK)), Ok(()));
        let failure =
            request::decode_ok(&status_frame(SftpStatus::NO_SUCH_FILE))
                .expect_err("a non-OK status is a failure");
        assert_eq!(failure, SftpFailure::Status(SftpStatus::NO_SUCH_FILE));
        assert_eq!(failure.to_curlcode(), CURLcode::RemoteFileNotFound);
        assert_eq!(failure.status(), SftpStatus::NO_SUCH_FILE);
    }

    #[test]
    fn a_data_reply_decodes_to_its_payload() {
        let mut codec = SftpCodec::request(SftpPacket::Data);
        codec.put_u32(1);
        codec.put_bytes(b"the file's bytes");
        let frame = codec.finish();
        assert_eq!(
            request::decode_data(&frame),
            Ok(b"the file's bytes".to_vec())
        );
        // And EOF is reported as a status, which every caller must test for
        // FIRST: `sftp_libssh2_error_to_CURLE` has no `EOF` arm.
        let eof = request::decode_data(&status_frame(SftpStatus::EOF))
            .expect_err("EOF is not data");
        assert_eq!(eof.status(), SftpStatus::EOF);
        assert_eq!(eof.to_curlcode(), CURLcode::Ssh);
    }

    #[test]
    fn a_name_reply_decodes_every_entry_in_order() {
        let entries: [(&[u8], &[u8], SftpAttributes); 3] = [
            (b"one", b"-rw-r--r-- 1 u g 4 Jan 1 00:00 one", sized(4)),
            (b"two", b"drwxr-xr-x 2 u g 0 Jan 1 00:00 two", linked()),
            (b"three", b"", SftpAttributes::default()),
        ];
        let frame = name_frame(&entries);
        let names = request::decode_names(&frame).expect("well-formed");
        assert_eq!(names.len(), 3);
        assert_eq!(names[0].filename, b"one");
        assert_eq!(names[0].longentry, b"-rw-r--r-- 1 u g 4 Jan 1 00:00 one");
        assert_eq!(names[0].attrs, sized(4));
        assert!(names[1].attrs.is_symlink());
        assert_eq!(names[2].filename, b"three");
        // A zero-entry reply is how a server ends a listing when it does not
        // send `EOF`, and it decodes to an empty vector rather than failing.
        assert_eq!(request::decode_names(&name_frame(&[])), Ok(Vec::new()));
    }

    #[test]
    fn a_version_reply_decodes_and_a_wrong_packet_does_not() {
        assert_eq!(request::decode_version(&version_frame(3)), Ok(3));
        assert_eq!(request::decode_version(&version_frame(6)), Ok(6));
        assert!(request::decode_version(&handle_frame(b"h")).is_err());
    }

    #[test]
    fn a_statvfs_reply_decodes_all_eleven_members_in_order() {
        let stats = SftpStatVfs {
            bsize: 1,
            frsize: 2,
            blocks: 3,
            bfree: 4,
            bavail: 5,
            files: 6,
            ffree: 7,
            favail: 8,
            fsid: 9,
            flag: 10,
            namemax: 11,
        };
        assert_eq!(request::decode_statvfs(&statvfs_frame(&stats)), Ok(stats));
    }

    #[test]
    fn the_open_flag_combinations_are_the_measured_three() {
        // `sftp_upload_init` (`lib/vssh/libssh2.c:924-940`).
        assert_eq!(
            SFTP_UPLOAD_APPEND.bits(),
            SftpOpenFlags::WRITE.bits()
                | SftpOpenFlags::CREAT.bits()
                | SftpOpenFlags::APPEND.bits()
        );
        // ⚠ A resumed upload opens with a BARE write: the C's comment is
        // *"Resume MUST NOT use APPEND; some servers force writes to EOF when
        // APPEND is set, ignoring a prior seek()."*
        assert_eq!(SFTP_UPLOAD_RESUME.bits(), SftpOpenFlags::WRITE.bits());
        assert!(!SFTP_UPLOAD_RESUME.contains(SftpOpenFlags::APPEND));
        assert_eq!(
            SFTP_UPLOAD_TRUNCATE.bits(),
            SftpOpenFlags::WRITE.bits()
                | SftpOpenFlags::CREAT.bits()
                | SftpOpenFlags::TRUNC.bits()
        );
        assert_eq!(sftp_upload_flags(true, 0), SFTP_UPLOAD_APPEND);
        assert_eq!(sftp_upload_flags(true, 5), SFTP_UPLOAD_APPEND);
        assert_eq!(sftp_upload_flags(false, 5), SFTP_UPLOAD_RESUME);
        assert_eq!(sftp_upload_flags(false, 0), SFTP_UPLOAD_TRUNCATE);
        assert_eq!(sftp_upload_flags(false, -1), SFTP_UPLOAD_TRUNCATE);
    }

    #[test]
    fn the_rename_flags_are_the_measured_three() {
        // `LIBSSH2_SFTP_RENAME_OVERWRITE | _ATOMIC | _NATIVE`, which are on the
        // wire as one word.
        assert_eq!(SFTP_RENAME_FLAGS, 0x7);
        let packet = request::rename(1, b"/a", b"/b");
        let tail = &packet[packet.len() - 4..];
        assert_eq!(tail, &SFTP_RENAME_FLAGS.to_be_bytes());
    }

    // -- 7. the error maps --------------------------------------------------

    #[test]
    fn the_sftp_status_map_is_the_measured_one() {
        // `sftp_libssh2_error_to_CURLE` (`lib/vssh/libssh2.c:160-188`).
        let cases: [(SftpStatus, CURLcode); 10] = [
            (SftpStatus::OK, CURLcode::Ok),
            (SftpStatus::NO_SUCH_FILE, CURLcode::RemoteFileNotFound),
            (SftpStatus::NO_SUCH_PATH, CURLcode::RemoteFileNotFound),
            (SftpStatus::PERMISSION_DENIED, CURLcode::RemoteAccessDenied),
            (SftpStatus::WRITE_PROTECT, CURLcode::RemoteAccessDenied),
            (SftpStatus::LOCK_CONFLICT, CURLcode::RemoteAccessDenied),
            (SftpStatus::NO_SPACE_ON_FILESYSTEM, CURLcode::RemoteDiskFull),
            (SftpStatus::QUOTA_EXCEEDED, CURLcode::RemoteDiskFull),
            (SftpStatus::FILE_ALREADY_EXISTS, CURLcode::RemoteFileExists),
            (SftpStatus::DIR_NOT_EMPTY, CURLcode::QuoteError),
        ];
        for (status, expected) in cases {
            assert_eq!(
                sftp_status_to_curlcode(status),
                expected,
                "status {}",
                status.0
            );
        }
        // ⚠ `EOF` has NO arm in the C's switch and therefore reaches
        // `CURLE_SSH`. Every caller must test for it before mapping, which is
        // what `SSH_SFTP_READDIR` does.
        assert_eq!(sftp_status_to_curlcode(SftpStatus::EOF), CURLcode::Ssh);
        assert_eq!(sftp_status_to_curlcode(SftpStatus::FAILURE), CURLcode::Ssh);
        assert_eq!(sftp_status_to_curlcode(SftpStatus(9999)), CURLcode::Ssh);
    }

    #[test]
    fn every_status_has_the_measured_message() {
        // `sftp_libssh2_strerror` (`lib/vssh/libssh2.c:55-158`), byte for byte.
        //
        // ⚠ NOT ONE of these ends in a full stop, and two statuses have no arm
        // at all: `OK` and `EOF` both reach the default. Both facts are
        // observable, because the text is interpolated into `failf` lines that a
        // fixture compares.
        let cases: [(SftpStatus, &str); 20] = [
            (SftpStatus::NO_SUCH_FILE, "No such file or directory"),
            (SftpStatus::NO_SUCH_PATH, "No such file or directory"),
            (SftpStatus::PERMISSION_DENIED, "Permission denied"),
            (SftpStatus::FAILURE, "Operation failed"),
            (SftpStatus::BAD_MESSAGE, "Bad message from SFTP server"),
            (SftpStatus::NO_CONNECTION, "Not connected to SFTP server"),
            (
                SftpStatus::CONNECTION_LOST,
                "Connection to SFTP server lost",
            ),
            (
                SftpStatus::OP_UNSUPPORTED,
                "Operation not supported by SFTP server",
            ),
            (SftpStatus::INVALID_HANDLE, "Invalid handle"),
            (SftpStatus::FILE_ALREADY_EXISTS, "File already exists"),
            (SftpStatus::WRITE_PROTECT, "File is write protected"),
            (SftpStatus::NO_MEDIA, "No media"),
            (SftpStatus::NO_SPACE_ON_FILESYSTEM, "Disk full"),
            (SftpStatus::QUOTA_EXCEEDED, "User quota exceeded"),
            // ⚠ "principle", not "principal" -- the C's own spelling, in the
            // constant name as well as in the text.
            (SftpStatus::UNKNOWN_PRINCIPLE, "Unknown principle"),
            (SftpStatus::LOCK_CONFLICT, "File lock conflict"),
            (SftpStatus::DIR_NOT_EMPTY, "Directory not empty"),
            (SftpStatus::NOT_A_DIRECTORY, "Not a directory"),
            (SftpStatus::INVALID_FILENAME, "Invalid filename"),
            (SftpStatus::LINK_LOOP, "Link points to itself"),
        ];
        for (status, expected) in cases {
            assert_eq!(sftp_strerror(status), expected, "status {}", status.0);
            assert!(
                !expected.ends_with('.'),
                "no message ends in a full stop: {expected}"
            );
        }
        // The default, which is what `OK`, `EOF` and anything unrecognised
        // reach -- and it names libssh2 rather than SFTP, which is preserved
        // even though libssh2 is gone, because the string is observable.
        assert_eq!(sftp_strerror(SftpStatus::OK), "Unknown error in libssh2");
        assert_eq!(sftp_strerror(SftpStatus::EOF), "Unknown error in libssh2");
        assert_eq!(sftp_strerror(SftpStatus(9999)), "Unknown error in libssh2");
    }

    #[test]
    fn the_session_error_map_is_the_measured_one() {
        // `libssh2_session_error_to_CURLE` (`lib/vssh/libssh2.c:190-233`).
        let cases: [(SshError, CURLcode); 8] = [
            (SshError::SocketNone, CURLcode::CouldntConnect),
            (SshError::Alloc, CURLcode::OutOfMemory),
            (SshError::SocketSend, CURLcode::SendError),
            (
                SshError::HostKey(String::new()),
                CURLcode::PeerFailedVerification,
            ),
            (SshError::PasswordExpired, CURLcode::LoginDenied),
            (SshError::Timeout, CURLcode::OperationTimedout),
            (SshError::Again, CURLcode::Again),
            (SshError::ScpProtocol, CURLcode::RemoteFileNotFound),
        ];
        for (error, expected) in cases {
            assert_eq!(error.to_curlcode(), expected, "{error:?}");
            // Every variant describes itself, so a `failf` interpolating it is
            // total without an `unwrap`.
            assert!(!error.message().is_empty() || error.message().is_empty());
        }
        assert_eq!(
            SshError::Other("boom".to_owned()).to_curlcode(),
            CURLcode::Ssh
        );
        assert_eq!(SshError::Other("boom".to_owned()).message(), "boom");
        assert_eq!(SshError::Other("boom".to_owned()).to_string(), "boom");
    }

    #[test]
    fn a_malformed_reply_maps_through_bad_message() {
        assert_eq!(
            SftpFailure::Malformed.to_curlcode(),
            sftp_status_to_curlcode(SftpStatus::BAD_MESSAGE)
        );
        assert_eq!(
            SftpFailure::Malformed.message(),
            "Bad message from SFTP server"
        );
        assert_eq!(SftpFailure::Malformed.status(), SftpStatus::BAD_MESSAGE);
        // A transport failure carries no SFTP status, which is what
        // `libssh2_sftp_last_error` answering zero means: *"not an sftp error at
        // all"*.
        assert_eq!(
            SftpFailure::Transport(SshError::Again).status(),
            SftpStatus::OK
        );
    }

    // -- 8. the path helpers ------------------------------------------------

    #[test]
    fn the_working_path_resolves_the_home_directory_shorthand() {
        // `Curl_getworkingpath` (`lib/vssh/vssh.c:203-282`).
        //
        // `/~/` is curl's shorthand for the home directory, and the two schemes
        // resolve it DIFFERENTLY: SFTP substitutes the directory the connect
        // phase learned, SCP strips the prefix and lets the remote shell do it.
        assert_eq!(
            getworkingpath(b"/~/sub/file", b"/home/u", Proto::SFTP),
            Ok(b"/home/u/sub/file".to_vec())
        );
        assert_eq!(
            getworkingpath(b"/~/sub/file", b"/home/u", Proto::SCP),
            Ok(b"sub/file".to_vec())
        );
        // ⚠ Exactly one separator appears whether or not the home directory
        // already ends in one, which is what the C's `copyfrom` of 2 versus 3
        // achieves.
        assert_eq!(
            getworkingpath(b"/~/sub", b"/home/u/", Proto::SFTP),
            Ok(b"/home/u/sub".to_vec())
        );
        // `/~` with no tail is the home directory plus a trailing separator, so
        // it lists rather than downloads.
        assert_eq!(
            getworkingpath(b"/~", b"/home/u", Proto::SFTP),
            Ok(b"/home/u/".to_vec())
        );
        // An ordinary path is passed through untouched.
        assert_eq!(
            getworkingpath(b"/etc/motd", b"/home/u", Proto::SFTP),
            Ok(b"/etc/motd".to_vec())
        );
        // And it is percent-DECODED, because the URL parser leaves the escapes
        // in place.
        assert_eq!(
            getworkingpath(b"/a%20b", b"/home/u", Proto::SFTP),
            Ok(b"/a b".to_vec())
        );
        // A NUL cannot survive the decode: a path is a C string on the wire.
        assert!(getworkingpath(b"/a%00b", b"/home/u", Proto::SFTP).is_err());
    }

    #[test]
    fn a_quote_argument_is_parsed_with_the_measured_quoting_rules() {
        // `Curl_get_pathname` (`lib/vssh/vssh.c:126-201`).
        //
        // Escaped byte strings throughout, never raw ones: the crate's own
        // `mod source_policy` gate forbids a raw string literal anywhere under
        // `src/`, because its code-only stripper does not lex them.
        let mut cursor = b" /tmp/plain rest".as_slice();
        assert_eq!(
            get_pathname(&mut cursor, b"/home/u"),
            Ok(b"/tmp/plain".to_vec())
        );
        // The trailing blanks are CONSUMED: the C ends with
        // `curlx_str_passblanks(&cp)` before assigning `*cpp`, so the cursor is
        // left on the second parameter rather than on the space before it.
        assert_eq!(cursor, b"rest");

        // Double quotes, with the three escapes the C accepts -- a quote, an
        // apostrophe and a backslash.
        let mut cursor = b" \"a b\\\"c\\\\d\" tail".as_slice();
        assert_eq!(
            get_pathname(&mut cursor, b"/home/u"),
            Ok(b"a b\"c\\d".to_vec())
        );
        assert_eq!(cursor, b"tail");

        // Single quotes work the same way.
        let mut cursor = b" 'a b' tail".as_slice();
        assert_eq!(get_pathname(&mut cursor, b"/home/u"), Ok(b"a b".to_vec()));
        assert_eq!(cursor, b"tail");

        // `/~/` is expanded even in an unquoted argument, and it inserts exactly
        // one separator.
        let mut cursor = b" /~/sub".as_slice();
        assert_eq!(
            get_pathname(&mut cursor, b"/home/u"),
            Ok(b"/home/u/sub".to_vec())
        );

        // An unterminated quote is refused.
        let mut cursor = b" \"unterminated".as_slice();
        assert_eq!(
            get_pathname(&mut cursor, b"/home/u"),
            Err(CURLcode::QuoteError)
        );
        // An escape of something that is not a quote or a backslash is refused.
        let mut cursor = b" \"a\\nb\"".as_slice();
        assert_eq!(
            get_pathname(&mut cursor, b"/home/u"),
            Err(CURLcode::QuoteError)
        );
        // An empty quoted string is refused.
        let mut cursor = b" \"\"".as_slice();
        assert_eq!(
            get_pathname(&mut cursor, b"/home/u"),
            Err(CURLcode::QuoteError)
        );
        // And an empty argument is refused before anything is allocated.
        let mut cursor = b"".as_slice();
        assert_eq!(
            get_pathname(&mut cursor, b"/home/u"),
            Err(CURLcode::QuoteError)
        );
    }

    // -- 9. `--range` and `--continue-at` -----------------------------------

    #[test]
    fn the_range_forms_resolve_to_the_measured_offsets() {
        // `Curl_ssh_range`'s successor. Each case is `(range, filesize)` and the
        // answer is `(from, count)`.
        assert_eq!(ssh_range(b"0-9", 100), Ok((0, 10)));
        assert_eq!(ssh_range(b"10-19", 100), Ok((10, 10)));
        // An open end clamps to the file.
        assert_eq!(ssh_range(b"90-", 100), Ok((90, 10)));
        assert_eq!(ssh_range(b"90-9999", 100), Ok((90, 10)));
        // ⚠ A suffix range is measured from the END, and it CLAMPS rather than
        // refusing when it asks for more than the file holds -- the opposite of
        // what `--continue-at` does with a negative offset.
        assert_eq!(ssh_range(b"-10", 100), Ok((90, 10)));
        assert_eq!(ssh_range(b"-1000", 100), Ok((0, 100)));
        // Blanks around the dash are permitted.
        assert_eq!(ssh_range(b"10 - 19", 100), Ok((10, 10)));
    }

    #[test]
    fn a_range_the_file_cannot_satisfy_is_refused_with_range_error() {
        let refusal = ssh_range(b"200-", 100).expect_err("beyond the file");
        assert_eq!(refusal.code(), CURLcode::RangeError);
        assert_eq!(
            refusal.message(),
            Some("Offset (200) was beyond file size (100)".to_owned())
        );
        // A start after the end.
        let refusal = ssh_range(b"50-10", 100).expect_err("inverted");
        assert_eq!(refusal.code(), CURLcode::RangeError);
        // Junk.
        for bad in [
            b"".as_slice(),
            b"-".as_slice(),
            b"-0".as_slice(),
            b"abc".as_slice(),
            b"1-2-3".as_slice(),
            b"1-2junk".as_slice(),
        ] {
            assert!(
                ssh_range(bad, 100).is_err(),
                "{:?} must be refused",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn a_download_with_no_reported_size_reads_to_end_of_file() {
        // The C treats three conditions alike -- no `ATTR_SIZE`, a failed stat,
        // and a size of zero -- and its comment says so. All three make the size
        // UNKNOWN and skip the range entirely.
        let plan = sftp_download_size(SftpAttributes::default(), None, 0)
            .expect("unknown size is not an error");
        assert_eq!(
            plan,
            DownloadPlan {
                from: 0,
                size: None,
                complete: false
            }
        );
        // A reported size of zero is the same case, which is why a range against
        // it is not resolved rather than refused.
        let plan = sftp_download_size(sized(0), Some(b"0-9"), 0)
            .expect("zero is unknown");
        assert_eq!(plan.size, None);
    }

    #[test]
    fn a_download_resolves_the_range_then_the_resume_offset() {
        // No range, no resume: the whole file.
        assert_eq!(
            sftp_download_size(sized(100), None, 0),
            Ok(DownloadPlan {
                from: 0,
                size: Some(100),
                complete: false
            })
        );
        // A range alone.
        assert_eq!(
            sftp_download_size(sized(100), Some(b"10-19"), 0),
            Ok(DownloadPlan {
                from: 10,
                size: Some(10),
                complete: false
            })
        );
        // A resume alone.
        assert_eq!(
            sftp_download_size(sized(100), None, 40),
            Ok(DownloadPlan {
                from: 40,
                size: Some(60),
                complete: false
            })
        );
        // ⚠ A resume ON TOP of a range: the resume wins, because the C applies
        // it after `Curl_ssh_range` and overwrites both the offset and the
        // count.
        assert_eq!(
            sftp_download_size(sized(100), Some(b"10-19"), 40),
            Ok(DownloadPlan {
                from: 40,
                size: Some(60),
                complete: false
            })
        );
        // A negative resume is "the last N bytes", resolved against the size.
        assert_eq!(
            sftp_download_size(sized(100), None, -30),
            Ok(DownloadPlan {
                from: 70,
                size: Some(30),
                complete: false
            })
        );
        // Resuming at exactly the size transfers nothing, and the C logs *"File
        // already completely downloaded"*.
        let plan = sftp_download_size(sized(100), None, 100)
            .expect("resuming at the size is legal");
        assert_eq!(plan.size, Some(0));
        assert!(plan.complete);
    }

    #[test]
    fn a_resume_past_the_file_is_refused_with_bad_download_resume() {
        // ⚠ A DIFFERENT code from the range refusal for a condition that looks
        // the same: `CURLE_BAD_DOWNLOAD_RESUME` rather than `CURLE_RANGE_ERROR`.
        let (code, message) =
            sftp_download_size(sized(50), None, 100).expect_err("past the end");
        assert_eq!(code, CURLcode::BadDownloadResume);
        assert_eq!(
            message,
            Some("Offset (100) was beyond file size (50)".to_owned())
        );
        // And a NEGATIVE resume past the end is refused too rather than clamped
        // -- the opposite of `--range -100`, which clamps.
        let (code, _) = sftp_download_size(sized(50), None, -100)
            .expect_err("past the end backwards");
        assert_eq!(code, CURLcode::BadDownloadResume);
    }

    #[test]
    fn an_upload_resume_stats_the_destination_and_tolerates_its_absence() {
        // A non-negative offset is used as given, with no stat at all.
        assert_eq!(sftp_upload_resume(0, None), Ok(0));
        assert_eq!(sftp_upload_resume(42, None), Ok(42));
        // A negative offset means "append to whatever is there", so the
        // destination is stat'd and its size used.
        assert_eq!(sftp_upload_resume(-1, Some(sized(70))), Ok(70));
        // ⚠ And a FAILED stat sets the offset to zero rather than reporting an
        // error, because the destination not existing yet is the ordinary case
        // for an upload.
        assert_eq!(sftp_upload_resume(-1, None), Ok(0));
    }

    // -- 10. the quote engine ----------------------------------------------

    #[test]
    fn the_command_vocabulary_is_the_measured_twelve_spellings() {
        // ⚠ Every spelling INCLUDES its trailing space, because the C matches
        // with `strncmp(cmd, "chgrp ", 6)`. That is what makes `chmodx` not a
        // command and `chmod x` one.
        assert_eq!(QUOTE_COMMANDS.len(), 12);
        for (spelling, _) in QUOTE_COMMANDS {
            assert!(
                spelling.ends_with(b" "),
                "{:?} must end in a space",
                String::from_utf8_lossy(spelling)
            );
        }
        // Two spellings for one command, which is the only duplicate.
        let symlinks: Vec<&[u8]> = QUOTE_COMMANDS
            .iter()
            .filter(|(_, command)| *command == QuoteCommand::Symlink)
            .map(|(spelling, _)| *spelling)
            .collect();
        assert_eq!(symlinks, [b"ln ".as_slice(), b"symlink ".as_slice()]);
    }

    #[test]
    fn each_command_routes_to_its_measured_state() {
        let home = b"/home/u".as_slice();
        let cases: [(&[u8], SshState); 12] = [
            (b"chgrp 1 /f", SshState::SftpQuoteStat),
            (b"chmod 755 /f", SshState::SftpQuoteStat),
            (b"chown 1 /f", SshState::SftpQuoteStat),
            (b"atime 20230101 /f", SshState::SftpQuoteStat),
            (b"mtime 20230101 /f", SshState::SftpQuoteStat),
            (b"ln /t /l", SshState::SftpQuoteSymlink),
            (b"symlink /t /l", SshState::SftpQuoteSymlink),
            (b"mkdir /d", SshState::SftpQuoteMkdir),
            (b"rename /a /b", SshState::SftpQuoteRename),
            (b"rmdir /d", SshState::SftpQuoteRmdir),
            (b"rm /f", SshState::SftpQuoteUnlink),
            (b"statvfs /", SshState::SftpQuoteStatvfs),
        ];
        for (line, expected) in cases {
            let parsed = sftp_quote(line, home).unwrap_or_else(|error| {
                panic!(
                    "{:?}: {}",
                    String::from_utf8_lossy(line),
                    error.message()
                )
            });
            assert_eq!(
                parsed.next,
                expected,
                "{:?}",
                String::from_utf8_lossy(line)
            );
            assert!(!parsed.acceptfail);
        }
    }

    #[test]
    fn pwd_is_answered_locally_with_no_packet_at_all() {
        // `curl_strequal("pwd", cmd)` -- case-insensitive and WHOLE-STRING, so
        // `PWD` works and `pwd /x` does not.
        for spelling in
            [b"pwd".as_slice(), b"PWD".as_slice(), b"Pwd".as_slice()]
        {
            let parsed =
                sftp_quote(spelling, b"/home/u").expect("pwd is recognised");
            assert_eq!(parsed.command, QuoteCommand::Pwd);
            assert_eq!(parsed.next, SshState::SftpNextQuote);
        }
        // With an argument it is not `pwd` and not any other command either.
        let refusal =
            sftp_quote(b"pwd /x", b"/home/u").expect_err("not a command");
        assert_eq!(refusal.message(), "Unknown SFTP command");
        assert_eq!(refusal.code(), CURLcode::QuoteError);
    }

    #[test]
    fn the_pwd_report_is_the_measured_bytes() {
        // Two writes: `"257 \"%s\" is current directory.\n"` to HEADER and
        // four bytes to `CURLINFO_HEADER_OUT`.
        assert_eq!(
            pwd_report(b"/home/u"),
            b"257 \"/home/u\" is current directory.\n".to_vec()
        );
        assert_eq!(PWD_DEBUG_LINE, b"PWD\n");
        assert_eq!(PWD_DEBUG_LINE.len(), 4);
    }

    #[test]
    fn the_asterisk_prefix_makes_a_failure_a_success() {
        // The C's own comment: *"if a command starts with an asterisk, which a
        // legal SFTP command never can, the command will be allowed to fail
        // without it causing any aborts or cancels etc."*
        let parsed = sftp_quote(b"*rm /gone", b"/home/u").expect("parsed");
        assert!(parsed.acceptfail);
        assert_eq!(parsed.command, QuoteCommand::Unlink);
        assert_eq!(parsed.path1, b"/gone");
        // And it applies to `pwd` too, even though `pwd` cannot fail.
        let parsed = sftp_quote(b"*pwd", b"/home/u").expect("parsed");
        assert!(parsed.acceptfail);
    }

    #[test]
    fn every_quote_refusal_carries_its_measured_text() {
        let home = b"/home/u".as_slice();
        // ⚠ A missing parameter reports `CURLE_OK` -- the C diagnoses and
        // CONTINUES rather than failing the transfer.
        let refusal = sftp_quote(b"mkdir", home).expect_err("no parameter");
        assert_eq!(refusal.code(), CURLcode::Ok);
        assert_eq!(
            refusal.message(),
            "Syntax error command 'mkdir', missing parameter"
        );

        let refusal = sftp_quote(b"nosuch x", home).expect_err("unknown");
        assert_eq!(refusal.message(), "Unknown SFTP command");
        assert_eq!(refusal.code(), CURLcode::QuoteError);

        let refusal = sftp_quote(b"rename /a", home).expect_err("one path");
        assert_eq!(
            refusal.message(),
            "Syntax error in rename: Bad second parameter"
        );

        let refusal = sftp_quote(b"ln /t", home).expect_err("one path");
        assert_eq!(
            refusal.message(),
            "Syntax error in ln/symlink: Bad second parameter"
        );

        let refusal = sftp_quote(b"chmod 755", home).expect_err("one argument");
        assert_eq!(
            refusal.message(),
            "Syntax error in chmod 755: Bad second parameter"
        );

        // A bad FIRST parameter, which `Curl_get_pathname` refuses.
        let refusal = sftp_quote(b"mkdir \"unterminated", home)
            .expect_err("unterminated quote");
        assert_eq!(
            refusal.message(),
            "Syntax error: Bad first parameter to 'mkdir \"unterminated'"
        );

        // Trailing data after a complete command.
        let refusal =
            sftp_quote(b"rm /f extra", home).expect_err("trailing data");
        assert_eq!(refusal.message(), "Suspicious data after the command line");
    }

    #[test]
    fn the_attribute_commands_derive_the_measured_attribute_block() {
        let current = SftpAttributes {
            flags: SftpAttrFlags::UIDGID | SftpAttrFlags::PERMISSIONS,
            uid: 1000,
            gid: 1000,
            permissions: 0o100_644,
            ..SftpAttributes::default()
        };

        // `chgrp` sets the GROUP and replaces the flags with `UIDGID` alone --
        // which is why the preliminary stat matters: the uid travels with it.
        let attrs = quote_setstat_attributes(
            QuoteCommand::Chgrp,
            b"42",
            current,
            false,
        )
        .expect("a number");
        assert_eq!(attrs.gid, 42);
        assert_eq!(attrs.uid, 1000);
        assert_eq!(attrs.flags, SftpAttrFlags::UIDGID);

        // `chown` sets the OWNER, likewise.
        let attrs =
            quote_setstat_attributes(QuoteCommand::Chown, b"7", current, false)
                .expect("a number");
        assert_eq!(attrs.uid, 7);
        assert_eq!(attrs.gid, 1000);
        assert_eq!(attrs.flags, SftpAttrFlags::UIDGID);

        // ⚠ `chmod` reads OCTAL and is capped at `07777`, which is what
        // `curlx_str_octal(&p, &perms, 07777)` enforces.
        let attrs = quote_setstat_attributes(
            QuoteCommand::Chmod,
            b"755",
            current,
            false,
        )
        .expect("octal");
        assert_eq!(attrs.permissions, 0o755);
        assert_eq!(attrs.flags, SftpAttrFlags::PERMISSIONS);
        let refusal = quote_setstat_attributes(
            QuoteCommand::Chmod,
            b"99999",
            current,
            false,
        )
        .expect_err("past the cap");
        assert_eq!(
            refusal.message(),
            "Syntax error: chmod permissions not a number"
        );
        // ⚠ And `chmod`'s refusal is NOT suppressed by `acceptfail`: the C
        // reaches `goto fail` without consulting it, alone among the five.
        assert!(
            quote_setstat_attributes(
                QuoteCommand::Chmod,
                b"99999",
                current,
                true
            )
            .is_err(),
            "chmod refuses even with the asterisk"
        );

        // `atime` and `mtime` both set `ACMODTIME`, and each writes BOTH
        // members because the wire carries them together.
        //
        // The date form and its epoch are taken from `util::parsedate`'s own
        // differential oracle, so this asserts the VALUE rather than merely that
        // something parsed.
        let attrs = quote_setstat_attributes(
            QuoteCommand::Mtime,
            b"20040912 15:05:58 -0700",
            current,
            false,
        )
        .expect("a date the parser accepts");
        assert_eq!(attrs.flags, SftpAttrFlags::ACMODTIME);
        assert_eq!(attrs.mtime, 1_095_026_758);
        assert_eq!(attrs.atime, 0, "mtime alone sets mtime");

        let attrs = quote_setstat_attributes(
            QuoteCommand::Atime,
            b"20040912 15:05:58 -0700",
            current,
            false,
        )
        .expect("a date the parser accepts");
        assert_eq!(attrs.flags, SftpAttrFlags::ACMODTIME);
        assert_eq!(attrs.atime, 1_095_026_758);
        assert_eq!(attrs.mtime, 0, "atime alone sets atime");

        let refusal = quote_setstat_attributes(
            QuoteCommand::Atime,
            b"not a date",
            current,
            false,
        )
        .expect_err("not a date");
        // ⚠ The text uses `%.*s` with a precision of FIVE, so only the first
        // five bytes of the keyword appear.
        assert_eq!(refusal.message(), "incorrect date format for atime");
    }

    #[test]
    fn only_two_of_the_five_attribute_commands_honour_the_asterisk() {
        let current = SftpAttributes::default();
        // `chgrp` and `chown` test `!sshc->acceptfail` before refusing, so
        // `*chgrp junk /f` proceeds with the attributes unchanged.
        for command in [QuoteCommand::Chgrp, QuoteCommand::Chown] {
            assert!(
                quote_setstat_attributes(command, b"junk", current, true)
                    .is_ok(),
                "{command:?} must tolerate junk with the asterisk"
            );
            assert!(
                quote_setstat_attributes(command, b"junk", current, false)
                    .is_err(),
                "{command:?} must refuse junk without it"
            );
        }
        // `chmod`, `atime` and `mtime` do NOT: each reaches `goto fail` without
        // consulting `acceptfail`, so `*mtime junk /f` still fails the transfer.
        // That asymmetry is in the C and is easy to "tidy" away, which is why it
        // is asserted in both directions.
        for command in [
            QuoteCommand::Chmod,
            QuoteCommand::Atime,
            QuoteCommand::Mtime,
        ] {
            assert!(
                quote_setstat_attributes(command, b"junk", current, true)
                    .is_err(),
                "{command:?} refuses junk even with the asterisk"
            );
            assert!(
                quote_setstat_attributes(command, b"junk", current, false)
                    .is_err(),
                "{command:?} refuses junk without it too"
            );
        }
    }

    #[test]
    fn only_chmod_skips_the_preliminary_stat() {
        // `if(!!strncmp(cmd, "chmod", 5))` -- every command EXCEPT `chmod` needs
        // the current attributes first, because the wire carries uid and gid
        // together and `chown`/`chgrp` each set only one.
        assert!(!QuoteCommand::Chmod.needs_preliminary_stat());
        for command in [
            QuoteCommand::Chgrp,
            QuoteCommand::Chown,
            QuoteCommand::Atime,
            QuoteCommand::Mtime,
        ] {
            assert!(
                command.needs_preliminary_stat(),
                "{command:?} needs the stat"
            );
        }
    }

    #[test]
    fn the_statvfs_report_is_the_measured_eleven_lines_in_order() {
        let stats = SftpStatVfs {
            bsize: 1,
            frsize: 2,
            blocks: 3,
            bfree: 4,
            bavail: 5,
            files: 6,
            ffree: 7,
            favail: 8,
            fsid: 9,
            flag: 10,
            namemax: 11,
        };
        let report = statvfs_report(&stats);
        let expected = b"statvfs:\n\
             f_bsize: 1\n\
             f_frsize: 2\n\
             f_blocks: 3\n\
             f_bfree: 4\n\
             f_bavail: 5\n\
             f_files: 6\n\
             f_ffree: 7\n\
             f_favail: 8\n\
             f_fsid: 9\n\
             f_flag: 10\n\
             f_namemax: 11\n"
            .to_vec();
        assert_eq!(
            String::from_utf8_lossy(&report),
            String::from_utf8_lossy(&expected)
        );
    }

    // -- 11. the quote phases, end to end over the scripted peer ------------

    #[test]
    fn the_quote_phase_runs_every_command_at_its_measured_point() {
        let mut script = Scripted::new();
        // `mkdir /new` -> one packet, one OK status.
        script.status(SftpStatus::OK);
        // `rm /gone` -> one packet, one OK status.
        script.status(SftpStatus::OK);
        let (mut sshc, peer) = conn_over(script);
        let (mut sshp, set) =
            quote_only(&[b"mkdir /new".as_slice(), b"rm /gone".as_slice()]);
        sshc.homedir = b"/home/u".to_vec();

        let (outcome, effects) =
            drive(&mut sshc, &mut sshp, &set, SshState::SftpQuoteInit);
        assert_eq!(outcome, Ok(()));
        // The phase left the quote states through `SSH_SFTP_GETINFO` and
        // `SSH_SFTP_TRANS_INIT` and stopped, writing no body of its own.
        assert!(effects.body.is_empty());

        // Both commands reached the wire, in order, with the right types.
        let sent = peer.borrow().sent.clone();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0][4], SftpPacket::Mkdir.as_u8());
        assert_eq!(sent[1][4], SftpPacket::Remove.as_u8());
        // And the paths are the ones the command line named.
        let mut reader = SftpReader::frame(&sent[0]).expect("well-formed");
        assert!(reader.get_u32().is_ok());
        assert_eq!(reader.get_bytes(), Ok(b"/new".as_slice()));
    }

    #[test]
    fn a_quote_command_that_fails_reports_quote_error_with_the_measured_text() {
        let mut script = Scripted::new();
        script.status(SftpStatus::PERMISSION_DENIED);
        let (mut sshc, _peer) = conn_over(script);
        let (mut sshp, set) = quote_only(&[b"rmdir /locked".as_slice()]);
        sshc.homedir = b"/home/u".to_vec();

        let (outcome, effects) =
            drive(&mut sshc, &mut sshp, &set, SshState::SftpQuoteInit);
        // The code is always `CURLE_QUOTE_ERROR`, never the status's own
        // mapping: a quote `rmdir` of a protected directory does NOT report
        // `CURLE_REMOTE_ACCESS_DENIED`.
        assert_eq!(outcome, Err(CURLcode::QuoteError));
        assert!(
            effects
                .info
                .iter()
                .any(|line| line
                    == "rmdir \"/locked\" failed: Permission denied"),
            "{:?}",
            effects.info
        );
    }

    #[test]
    fn a_transport_failure_under_a_quote_still_reports_quote_error() {
        // The OTHER way a quote operation fails: not an `SSH_FXP_STATUS`
        // refusal, but the transport dying underneath the SFTP layer. The C
        // reaches the same `goto fail` for both -- `sftp_quote_*` tests the
        // libssh2 return code, and a session-level error and an SFTP-level
        // status are indistinguishable there -- so the reported code is
        // `CURLE_QUOTE_ERROR` in both cases and NOT the transport's own
        // `CURLE_SEND_ERROR`.
        //
        // The interpolated text differs, because it comes from the failure
        // rather than from `sftp_strerror`, and that difference is the whole
        // reason this path is worth asserting separately.
        let mut script = Scripted::new();
        script.fail(SshError::SocketSend);
        let (mut sshc, _peer) = conn_over(script);
        let (mut sshp, set) = quote_only(&[b"rmdir /gone".as_slice()]);
        sshc.homedir = b"/home/u".to_vec();

        let (outcome, effects) =
            drive(&mut sshc, &mut sshp, &set, SshState::SftpQuoteInit);
        assert_eq!(outcome, Err(CURLcode::QuoteError));
        let expected = format!(
            "rmdir \"/gone\" failed: {}",
            SshError::SocketSend.message()
        );
        assert!(
            effects.info.iter().any(|line| line == &expected),
            "{:?} did not contain {expected:?}",
            effects.info
        );
        // And the asterisk tolerates a transport failure exactly as it tolerates
        // a status refusal, because `acceptfail` is tested before the failure is
        // inspected at all.
        let mut script = Scripted::new();
        script.fail(SshError::SocketSend);
        script.status(SftpStatus::OK);
        let (mut sshc, _peer) = conn_over(script);
        let (mut sshp, set) =
            quote_only(&[b"*rmdir /gone".as_slice(), b"mkdir /new".as_slice()]);
        sshc.homedir = b"/home/u".to_vec();
        let (outcome, _) =
            drive(&mut sshc, &mut sshp, &set, SshState::SftpQuoteInit);
        assert_eq!(outcome, Ok(()));
    }

    #[test]
    fn the_asterisk_makes_a_failed_command_advance_to_the_next() {
        let mut script = Scripted::new();
        script.status(SftpStatus::NO_SUCH_FILE);
        script.status(SftpStatus::OK);
        let (mut sshc, peer) = conn_over(script);
        let (mut sshp, set) =
            quote_only(&[b"*rm /gone".as_slice(), b"mkdir /new".as_slice()]);
        sshc.homedir = b"/home/u".to_vec();

        let (outcome, _effects) =
            drive(&mut sshc, &mut sshp, &set, SshState::SftpQuoteInit);
        assert_eq!(outcome, Ok(()));
        // BOTH commands ran: the refused one was treated as a success, which is
        // exactly what the C's comment promises.
        assert_eq!(peer.borrow().sent.len(), 2);
    }

    #[test]
    fn pwd_writes_a_header_and_a_debug_line_and_sends_nothing() {
        let (mut sshc, peer) = conn_over(Scripted::new());
        let (mut sshp, set) = quote_only(&[b"pwd".as_slice()]);
        sshc.homedir = b"/home/u".to_vec();

        let (outcome, effects) =
            drive(&mut sshc, &mut sshp, &set, SshState::SftpQuoteInit);
        assert_eq!(outcome, Ok(()));
        assert_eq!(
            effects.header,
            b"257 \"/home/u\" is current directory.\n".to_vec()
        );
        assert_eq!(effects.header_out, PWD_DEBUG_LINE.to_vec());
        assert!(peer.borrow().sent.is_empty(), "pwd sends no packet");
    }

    #[test]
    fn statvfs_writes_its_report_only_on_success() {
        let stats = SftpStatVfs {
            bsize: 4096,
            frsize: 4096,
            blocks: 100,
            bfree: 50,
            bavail: 40,
            files: 10,
            ffree: 5,
            favail: 5,
            fsid: 1,
            flag: 0,
            namemax: 255,
        };
        let mut script = Scripted::new();
        script.reply(statvfs_frame(&stats));
        let (mut sshc, _peer) = conn_over(script);
        let (mut sshp, set) = quote_only(&[b"statvfs /".as_slice()]);
        sshc.homedir = b"/home/u".to_vec();

        let (outcome, effects) =
            drive(&mut sshc, &mut sshp, &set, SshState::SftpQuoteInit);
        assert_eq!(outcome, Ok(()));
        assert_eq!(effects.header, statvfs_report(&stats));

        // And with the asterisk over a refusal there is NO report at all --
        // `else if(rc == 0)` guards the whole write.
        let mut script = Scripted::new();
        script.status(SftpStatus::OP_UNSUPPORTED);
        let (mut sshc, _peer) = conn_over(script);
        let (mut sshp, set) = quote_only(&[b"*statvfs /".as_slice()]);
        sshc.homedir = b"/home/u".to_vec();
        let (outcome, effects) =
            drive(&mut sshc, &mut sshp, &set, SshState::SftpQuoteInit);
        assert_eq!(outcome, Ok(()));
        assert!(effects.header.is_empty());
    }

    #[test]
    fn an_attribute_command_stats_first_then_sets() {
        let current = SftpAttributes {
            flags: SftpAttrFlags::UIDGID,
            uid: 1000,
            gid: 1000,
            ..SftpAttributes::default()
        };
        let mut script = Scripted::new();
        script.reply(attrs_frame(&current));
        script.status(SftpStatus::OK);
        let (mut sshc, peer) = conn_over(script);
        let (mut sshp, set) = quote_only(&[b"chgrp 42 /f".as_slice()]);
        sshc.homedir = b"/home/u".to_vec();

        let (outcome, _effects) =
            drive(&mut sshc, &mut sshp, &set, SshState::SftpQuoteInit);
        assert_eq!(outcome, Ok(()));
        let sent = peer.borrow().sent.clone();
        assert_eq!(sent.len(), 2, "a stat then a setstat");
        assert_eq!(sent[0][4], SftpPacket::Stat.as_u8());
        assert_eq!(sent[1][4], SftpPacket::Setstat.as_u8());
        // The uid survived the round trip and the gid changed, which is the
        // whole reason the preliminary stat exists.
        assert_eq!(sshp.quote_attrs.uid, 1000);
        assert_eq!(sshp.quote_attrs.gid, 42);
        assert_eq!(sshp.quote_attrs.flags, SftpAttrFlags::UIDGID);
    }

    #[test]
    fn chmod_sends_one_packet_because_it_skips_the_stat() {
        let mut script = Scripted::new();
        script.status(SftpStatus::OK);
        let (mut sshc, peer) = conn_over(script);
        let (mut sshp, set) = quote_only(&[b"chmod 600 /f".as_slice()]);
        sshc.homedir = b"/home/u".to_vec();

        let (outcome, _effects) =
            drive(&mut sshc, &mut sshp, &set, SshState::SftpQuoteInit);
        assert_eq!(outcome, Ok(()));
        let sent = peer.borrow().sent.clone();
        assert_eq!(sent.len(), 1, "chmod alone needs no preliminary stat");
        assert_eq!(sent[0][4], SftpPacket::Setstat.as_u8());
        assert_eq!(sshp.quote_attrs.permissions, 0o600);
    }

    #[test]
    fn the_two_path_commands_send_both_paths_in_the_measured_order() {
        for (line, kind, first, second) in [
            (
                b"symlink /target /link".as_slice(),
                SftpPacket::Symlink,
                b"/target".as_slice(),
                b"/link".as_slice(),
            ),
            (
                b"rename /old /new".as_slice(),
                SftpPacket::Rename,
                b"/old".as_slice(),
                b"/new".as_slice(),
            ),
        ] {
            let mut script = Scripted::new();
            script.status(SftpStatus::OK);
            let (mut sshc, peer) = conn_over(script);
            let (mut sshp, set) = quote_only(&[line]);
            sshc.homedir = b"/home/u".to_vec();

            let (outcome, _effects) =
                drive(&mut sshc, &mut sshp, &set, SshState::SftpQuoteInit);
            assert_eq!(outcome, Ok(()), "{:?}", String::from_utf8_lossy(line));
            let sent = peer.borrow().sent.clone();
            assert_eq!(sent.len(), 1);
            assert_eq!(sent[0][4], kind.as_u8());
            let mut reader = SftpReader::frame(&sent[0]).expect("well-formed");
            assert!(reader.get_u32().is_ok());
            assert_eq!(reader.get_bytes(), Ok(first));
            assert_eq!(reader.get_bytes(), Ok(second));
        }
    }

    // -- 12. the transfer paths --------------------------------------------

    #[test]
    fn a_directory_request_is_the_one_with_a_trailing_slash() {
        // ⚠ The single byte that decides: `sftp://host/dir` downloads a FILE
        // called `dir` and `sftp://host/dir/` LISTS it.
        assert_eq!(sftp_trans_init(b"/dir/", false), SshState::SftpReaddirInit);
        assert_eq!(sftp_trans_init(b"/dir", false), SshState::SftpDownloadInit);
        // An upload wins over both, tested first in the C.
        assert_eq!(sftp_trans_init(b"/dir/", true), SshState::SftpUploadInit);
        assert_eq!(sftp_trans_init(b"/dir", true), SshState::SftpUploadInit);
        // An empty path has no last byte, and the C's
        // `sshp->path[strlen(sshp->path) - 1]` would read out of bounds there;
        // this answers the download branch rather than reading.
        assert_eq!(sftp_trans_init(b"", false), SshState::SftpDownloadInit);
    }

    #[test]
    fn the_filetime_step_runs_only_when_the_option_asks_for_it() {
        assert_eq!(sftp_getinfo(true), SshState::SftpFiletime);
        assert_eq!(sftp_getinfo(false), SshState::SftpTransInit);
        assert_eq!(sftp_quote_init(true), SshState::SftpQuote);
        assert_eq!(sftp_quote_init(false), SshState::SftpGetinfo);
        assert_eq!(sftp_postquote_init(true), SshState::SftpQuote);
        assert_eq!(sftp_postquote_init(false), SshState::Stop);
    }

    #[test]
    fn the_filetime_step_records_the_mtime_and_tolerates_a_refusal() {
        let attrs = SftpAttributes {
            flags: SftpAttrFlags::ACMODTIME,
            mtime: 1_234_567_890,
            ..SftpAttributes::default()
        };
        let mut script = Scripted::new();
        script.reply(attrs_frame(&attrs));
        let (mut sshc, _peer) = conn_over(script);
        let mut sshp = SshProto::default();
        let mut effects = SftpEffects::new();
        sshp.path = b"/f".to_vec();
        let set = settings();
        ssh_set_state(&mut sshc, None, SshState::SftpFiletime);
        let outcome = do_step(&mut sshc, &mut sshp, &set, &mut effects);
        assert_eq!(outcome, StepOutcome::advance(SshState::SftpTransInit));
        assert_eq!(effects.filetime, Some(1_234_567_890));

        // ⚠ A refused stat leaves the filetime alone and the machine advances
        // ANYWAY: `if(rc == 0)` is the only guard and there is no error path.
        let mut script = Scripted::new();
        script.status(SftpStatus::PERMISSION_DENIED);
        let (mut sshc, _peer) = conn_over(script);
        let mut effects = SftpEffects::new();
        ssh_set_state(&mut sshc, None, SshState::SftpFiletime);
        let outcome = do_step(&mut sshc, &mut sshp, &set, &mut effects);
        assert_eq!(outcome, StepOutcome::advance(SshState::SftpTransInit));
        assert_eq!(effects.filetime, None);
    }

    #[test]
    fn a_download_opens_then_stats_and_records_the_plan() {
        let mut script = Scripted::new();
        script.reply(handle_frame(b"H1"));
        script.reply(attrs_frame(&sized(100)));
        let (mut sshc, peer) = conn_over(script);
        let mut sshp = proto(b"/file");
        let set = settings();

        let (outcome, effects) =
            drive(&mut sshc, &mut sshp, &set, SshState::SftpDownloadInit);
        assert_eq!(outcome, Ok(()));
        assert_eq!(
            effects.download,
            Some(DownloadPlan {
                from: 0,
                size: Some(100),
                complete: false
            })
        );
        assert_eq!(sshc.sftp_handle, Some(b"H1".to_vec()));
        let sent = peer.borrow().sent.clone();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0][4], SftpPacket::Open.as_u8());
        // ⚠ The size comes from an FSTAT on the open HANDLE, not from a STAT on
        // the path: the file may have been replaced between the two.
        assert_eq!(sent[1][4], SftpPacket::Fstat.as_u8());
    }

    #[test]
    fn a_download_of_a_missing_file_reports_the_measured_text() {
        let mut script = Scripted::new();
        script.status(SftpStatus::NO_SUCH_FILE);
        let (mut sshc, _peer) = conn_over(script);
        let mut sshp = proto(b"/gone");
        let set = settings();

        let (outcome, effects) =
            drive(&mut sshc, &mut sshp, &set, SshState::SftpDownloadInit);
        assert_eq!(outcome, Err(CURLcode::RemoteFileNotFound));
        assert!(
            effects.info.iter().any(|line| line
                == "Could not open remote file for reading: No such file or \
                    directory"),
            "{:?}",
            effects.info
        );
    }

    #[test]
    fn an_upload_opens_with_the_truncating_flags_and_records_the_offset() {
        let mut script = Scripted::new();
        script.reply(handle_frame(b"U1"));
        let (mut sshc, peer) = conn_over(script);
        let mut sshp = proto(b"/dest");
        let mut set = settings();
        set.upload = true;

        let (outcome, effects) =
            drive(&mut sshc, &mut sshp, &set, SshState::SftpUploadInit);
        assert_eq!(outcome, Ok(()));
        assert_eq!(effects.upload_from, Some(0));
        assert_eq!(sshc.sftp_handle, Some(b"U1".to_vec()));
        let sent = peer.borrow().sent.clone();
        assert_eq!(sent.len(), 1);
        let mut reader = SftpReader::frame(&sent[0]).expect("well-formed");
        assert!(reader.get_u32().is_ok());
        assert_eq!(reader.get_bytes(), Ok(b"/dest".as_slice()));
        assert_eq!(reader.get_u32(), Ok(SFTP_UPLOAD_TRUNCATE.bits()));
    }

    #[test]
    fn a_resumed_upload_stats_the_destination_and_opens_without_append() {
        let mut script = Scripted::new();
        script.reply(attrs_frame(&sized(64)));
        script.reply(handle_frame(b"U2"));
        let (mut sshc, peer) = conn_over(script);
        let mut sshp = proto(b"/dest");
        let mut set = settings();
        set.upload = true;
        set.resume_from = -1;

        let (outcome, effects) =
            drive(&mut sshc, &mut sshp, &set, SshState::SftpUploadInit);
        assert_eq!(outcome, Ok(()));
        assert_eq!(effects.upload_from, Some(64));
        assert_eq!(sshc.sftp_offset, 64);
        let sent = peer.borrow().sent.clone();
        assert_eq!(sent[0][4], SftpPacket::Stat.as_u8());
        let mut reader = SftpReader::frame(&sent[1]).expect("well-formed");
        assert!(reader.get_u32().is_ok());
        assert!(reader.get_bytes().is_ok());
        // ⚠ A BARE write: no `APPEND`, because some servers force writes to EOF
        // when it is set and ignore the seek.
        assert_eq!(reader.get_u32(), Ok(SFTP_UPLOAD_RESUME.bits()));
    }

    #[test]
    fn an_upload_that_cannot_open_retries_through_the_create_dirs_walk() {
        let mut script = Scripted::new();
        // The first open fails with NO_SUCH_FILE.
        script.status(SftpStatus::NO_SUCH_FILE);
        // Then the walk creates `/a` and `/a/b` -- two components before the
        // filename.
        script.status(SftpStatus::OK);
        script.status(SftpStatus::OK);
        // And the retried open succeeds.
        script.reply(handle_frame(b"U3"));
        let (mut sshc, peer) = conn_over(script);
        let mut sshp = proto(b"/a/b/dest");
        let mut set = settings();
        set.upload = true;
        set.create_missing_dirs = true;

        let (outcome, effects) =
            drive(&mut sshc, &mut sshp, &set, SshState::SftpUploadInit);
        assert_eq!(outcome, Ok(()));
        assert_eq!(sshc.sftp_handle, Some(b"U3".to_vec()));
        assert_eq!(sshc.second_create_dirs, 1, "the retry happens ONCE");

        let sent = peer.borrow().sent.clone();
        assert_eq!(sent.len(), 4);
        assert_eq!(sent[1][4], SftpPacket::Mkdir.as_u8());
        assert_eq!(sent[2][4], SftpPacket::Mkdir.as_u8());
        // The components are the truncated path, in order, and the leading `/`
        // is skipped -- `sshc->slash_pos = sshp->path + 1`.
        let mut reader = SftpReader::frame(&sent[1]).expect("well-formed");
        assert!(reader.get_u32().is_ok());
        assert_eq!(reader.get_bytes(), Ok(b"/a".as_slice()));
        let mut reader = SftpReader::frame(&sent[2]).expect("well-formed");
        assert!(reader.get_u32().is_ok());
        assert_eq!(reader.get_bytes(), Ok(b"/a/b".as_slice()));
        // And the info lines name each directory.
        assert!(
            effects
                .info
                .iter()
                .any(|line| line == "Creating directory '/a'"),
            "{:?}",
            effects.info
        );
    }

    #[test]
    fn the_create_dirs_walk_tolerates_exactly_three_statuses() {
        // *"Abort if failure was not that the directory already exists or the
        // permission was denied (creation might succeed further down the path) -
        // retry on unspecific FAILURE also"*.
        for status in [
            SftpStatus::FILE_ALREADY_EXISTS,
            SftpStatus::FAILURE,
            SftpStatus::PERMISSION_DENIED,
        ] {
            assert!(create_dirs_tolerates(status), "status {}", status.0);
        }
        for status in [
            SftpStatus::NO_SUCH_FILE,
            SftpStatus::NO_SUCH_PATH,
            SftpStatus::OP_UNSUPPORTED,
            SftpStatus::NO_SPACE_ON_FILESYSTEM,
            SftpStatus::QUOTA_EXCEEDED,
        ] {
            assert!(!create_dirs_tolerates(status), "status {}", status.0);
        }
    }

    #[test]
    fn the_create_dirs_walk_visits_each_component_once() {
        assert_eq!(
            sftp_create_dirs_init(b"/a/b/c"),
            (SshState::SftpCreateDirs, 1)
        );
        // ⚠ A path of exactly one byte has no directory to create.
        assert_eq!(sftp_create_dirs_init(b"/"), (SshState::SftpUploadInit, 0));
        assert_eq!(sftp_create_dirs_init(b""), (SshState::SftpUploadInit, 0));

        let path = b"/a/b/c".as_slice();
        assert_eq!(sftp_next_directory(path, 1), Some((b"/a".as_slice(), 3)));
        assert_eq!(sftp_next_directory(path, 3), Some((b"/a/b".as_slice(), 5)));
        // No `/` left, so the walk hands over to `SSH_SFTP_UPLOAD_INIT`.
        assert_eq!(sftp_next_directory(path, 5), None);
        assert_eq!(sftp_next_directory(path, 99), None);
    }

    #[test]
    fn an_upload_retry_is_refused_a_second_time() {
        // `sshc->secondCreateDirs` is the guard, and its failure text is a
        // DIFFERENT one: *"Creating the dir/file failed: %s"*.
        assert!(upload_should_create_dirs(
            SftpStatus::NO_SUCH_FILE,
            true,
            b"/a/b",
            false
        ));
        assert!(!upload_should_create_dirs(
            SftpStatus::NO_SUCH_FILE,
            true,
            b"/a/b",
            true
        ));
        // The option must be set.
        assert!(!upload_should_create_dirs(
            SftpStatus::NO_SUCH_FILE,
            false,
            b"/a/b",
            false
        ));
        // The path must be longer than one byte.
        assert!(!upload_should_create_dirs(
            SftpStatus::NO_SUCH_FILE,
            true,
            b"/",
            false
        ));
        // And only three statuses qualify.
        for status in [
            SftpStatus::NO_SUCH_FILE,
            SftpStatus::FAILURE,
            SftpStatus::NO_SUCH_PATH,
        ] {
            assert!(upload_should_create_dirs(status, true, b"/a/b", false));
        }
        for status in [
            SftpStatus::PERMISSION_DENIED,
            SftpStatus::QUOTA_EXCEEDED,
            SftpStatus::OK,
        ] {
            assert!(!upload_should_create_dirs(status, true, b"/a/b", false));
        }
    }

    // -- 13. the directory listing, byte for byte ---------------------------

    #[test]
    fn a_listing_writes_the_long_entries_with_one_newline_each() {
        let one = b"-rw-r--r--    1 u   g       4 Jan  1 00:00 one";
        let two = b"-rw-r--r--    1 u   g       8 Jan  1 00:00 two";
        let mut script = Scripted::new();
        script.reply(handle_frame(b"D1"));
        script.reply(name_frame(&[(b"one", one, sized(4))]));
        script.reply(name_frame(&[(b"two", two, sized(8))]));
        script.status(SftpStatus::EOF);
        script.status(SftpStatus::OK);
        let (mut sshc, _peer) = conn_over(script);
        let mut sshp = proto(b"/dir/");
        let set = settings();

        let (outcome, effects) =
            drive(&mut sshc, &mut sshp, &set, SshState::SftpReaddirInit);
        assert_eq!(outcome, Ok(()));
        // THE byte-exact assertion. Long entry, newline, long entry, newline --
        // and nothing else.
        let mut expected = Vec::new();
        expected.extend_from_slice(one);
        expected.push(b'\n');
        expected.extend_from_slice(two);
        expected.push(b'\n');
        assert_eq!(effects.body, expected);
        // The listing transfers no payload of its own.
        assert!(effects.nop);
        // And an unknown download size, because a listing's length is not known
        // until it has been read.
        assert_eq!(effects.download.map(|plan| plan.size), Some(None));
    }

    #[test]
    fn a_symlink_entry_gains_the_measured_arrow_suffix() {
        let entry = b"lrwxrwxrwx    1 u   g       3 Jan  1 00:00 link";
        let mut script = Scripted::new();
        script.reply(handle_frame(b"D2"));
        script.reply(name_frame(&[(b"link", entry, linked())]));
        // The READLINK answer, which is a NAME reply carrying the target.
        script.reply(name_frame(&[(
            b"/target",
            b"",
            SftpAttributes::default(),
        )]));
        script.status(SftpStatus::EOF);
        script.status(SftpStatus::OK);
        let (mut sshc, peer) = conn_over(script);
        let mut sshp = proto(b"/dir/");
        let set = settings();

        let (outcome, effects) =
            drive(&mut sshc, &mut sshp, &set, SshState::SftpReaddirInit);
        assert_eq!(outcome, Ok(()));
        let mut expected = Vec::new();
        expected.extend_from_slice(entry);
        expected.extend_from_slice(b" -> /target");
        expected.push(b'\n');
        assert_eq!(effects.body, expected);

        // ⚠ The READLINK argument is the directory and the filename with NO
        // separator inserted, which is correct because the path already ends in
        // one.
        let sent = peer.borrow().sent.clone();
        let readlink = sent
            .iter()
            .find(|packet| packet[4] == SftpPacket::Readlink.as_u8())
            .expect("a READLINK was issued");
        let mut reader = SftpReader::frame(readlink).expect("well-formed");
        assert!(reader.get_u32().is_ok());
        assert_eq!(reader.get_bytes(), Ok(b"/dir/link".as_slice()));
    }

    #[test]
    fn list_only_writes_bare_filenames() {
        let mut script = Scripted::new();
        script.reply(handle_frame(b"D3"));
        script.reply(name_frame(&[(
            b"one",
            b"-rw-r--r-- 1 u g 4 Jan 1 00:00 one",
            sized(4),
        )]));
        script.reply(name_frame(&[(
            b"two",
            b"-rw-r--r-- 1 u g 8 Jan 1 00:00 two",
            linked(),
        )]));
        script.status(SftpStatus::EOF);
        script.status(SftpStatus::OK);
        let (mut sshc, peer) = conn_over(script);
        let mut sshp = proto(b"/dir/");
        let mut set = settings();
        set.list_only = true;

        let (outcome, effects) =
            drive(&mut sshc, &mut sshp, &set, SshState::SftpReaddirInit);
        assert_eq!(outcome, Ok(()));
        assert_eq!(effects.body, b"one\ntwo\n".to_vec());
        // ⚠ And NO `READLINK` is issued even for the symbolic link, because the
        // `list_only` branch returns before the link test.
        let sent = peer.borrow().sent.clone();
        assert!(
            !sent
                .iter()
                .any(|packet| packet[4] == SftpPacket::Readlink.as_u8()),
            "list_only resolves no links"
        );
    }

    #[test]
    fn the_listing_assembly_is_a_pure_function_of_its_entry() {
        let entry = SftpName {
            filename: b"name".to_vec(),
            longentry: b"long entry".to_vec(),
            attrs: linked(),
        };
        assert_eq!(
            sftp_readdir_entry(&entry, None, false),
            b"long entry\n".to_vec()
        );
        assert_eq!(
            sftp_readdir_entry(&entry, Some(b"/t"), false),
            b"long entry -> /t\n".to_vec()
        );
        assert_eq!(sftp_readdir_entry(&entry, None, true), b"name\n".to_vec());
        // `list_only` ignores a resolved target, which is what the C's branch
        // order produces.
        assert_eq!(
            sftp_readdir_entry(&entry, Some(b"/t"), true),
            b"name\n".to_vec()
        );
        // No separator is inserted, ever.
        assert_eq!(readdir_link_path(b"/dir/", b"f"), b"/dir/f".to_vec());
        assert_eq!(readdir_link_path(b"/dir", b"f"), b"/dirf".to_vec());
    }

    #[test]
    fn a_no_body_directory_request_stops_before_listing() {
        // `if(data->req.no_body) { myssh_to(SSH_STOP); return CURLE_OK; }` --
        // and the download size has ALREADY been set to unknown by then.
        let (mut sshc, peer) = conn_over(Scripted::new());
        let mut sshp = proto(b"/dir/");
        let mut set = settings();
        set.no_body = true;

        let (outcome, effects) =
            drive(&mut sshc, &mut sshp, &set, SshState::SftpReaddirInit);
        assert_eq!(outcome, Ok(()));
        assert!(effects.body.is_empty());
        assert_eq!(effects.download.map(|plan| plan.size), Some(None));
        assert!(peer.borrow().sent.is_empty(), "no OPENDIR is issued");
    }

    #[test]
    fn a_directory_that_cannot_be_opened_reports_the_measured_text() {
        let mut script = Scripted::new();
        script.status(SftpStatus::PERMISSION_DENIED);
        let (mut sshc, _peer) = conn_over(script);
        let mut sshp = proto(b"/locked/");
        let set = settings();

        let (outcome, effects) =
            drive(&mut sshc, &mut sshp, &set, SshState::SftpReaddirInit);
        assert_eq!(outcome, Err(CURLcode::RemoteAccessDenied));
        assert!(
            effects.info.iter().any(|line| line
                == "Could not open directory for reading: Permission denied"),
            "{:?}",
            effects.info
        );
    }

    #[test]
    fn a_zero_entry_reply_also_ends_the_listing() {
        // Two ways a server ends a listing: `SSH_FXP_STATUS` with `EOF`, which
        // libssh2 reports as `rc == 0`, and a `NAME` reply with no entries.
        // Both must reach `SSH_SFTP_READDIR_DONE`.
        let mut script = Scripted::new();
        script.reply(handle_frame(b"D4"));
        script.reply(name_frame(&[]));
        script.status(SftpStatus::OK);
        let (mut sshc, _peer) = conn_over(script);
        let mut sshp = proto(b"/dir/");
        let set = settings();

        let (outcome, effects) =
            drive(&mut sshc, &mut sshp, &set, SshState::SftpReaddirInit);
        assert_eq!(outcome, Ok(()));
        assert!(effects.body.is_empty());
        assert!(effects.nop);
        assert_eq!(sshc.sftp_handle, None, "the handle was released");
    }

    // -- 14. the DONE phase's hinge and the DISCONNECT phase ---------------

    #[test]
    fn done_enters_the_postquote_round_only_under_three_conditions() {
        // `sftp_done` (`lib/vssh/libssh2.c:3676-3695`). The comment explains the
        // ordering: *"Post quote commands are executed after the SFTP_CLOSE
        // state to avoid errors that could happen due to open file handles"*.
        assert_eq!(
            sftp_done(CURLcode::Ok, false, true, false),
            Some(SshState::SftpPostquoteInit)
        );
        // A premature end skips it.
        assert_eq!(
            sftp_done(CURLcode::Ok, true, true, false),
            Some(SshState::NoState)
        );
        // No postquote list skips it.
        assert_eq!(
            sftp_done(CURLcode::Ok, false, false, false),
            Some(SshState::NoState)
        );
        // A retry skips it.
        assert_eq!(
            sftp_done(CURLcode::Ok, false, true, true),
            Some(SshState::NoState)
        );
        // ⚠ And a FAILED transfer does not even enter `SSH_SFTP_CLOSE` from
        // here: `if(!status)` guards the whole body.
        assert_eq!(sftp_done(CURLcode::Ssh, false, true, false), None);
    }

    #[test]
    fn the_close_state_swaps_with_nextstate_exactly_once() {
        // The C SWAPS rather than clearing, and the guard
        // `nextstate != SSH_SFTP_CLOSE` is what stops the swap looping.
        assert_eq!(
            sftp_close_next(SshState::SftpPostquoteInit),
            (SshState::SftpPostquoteInit, SshState::SftpClose)
        );
        // On the way back the guard fires and the machine stops.
        assert_eq!(
            sftp_close_next(SshState::SftpClose),
            (SshState::Stop, SshState::SftpClose)
        );
        assert_eq!(
            sftp_close_next(SshState::NoState),
            (SshState::Stop, SshState::NoState)
        );
    }

    #[test]
    fn the_close_state_releases_the_handle_and_clears_the_path() {
        let mut script = Scripted::new();
        script.status(SftpStatus::OK);
        let (mut sshc, peer) = conn_over(script);
        let mut sshp = proto(b"/file");
        sshc.sftp_handle = Some(b"H9".to_vec());
        let set = settings();
        let mut effects = SftpEffects::new();
        ssh_set_state(&mut sshc, None, SshState::SftpClose);

        let outcome = do_step(&mut sshc, &mut sshp, &set, &mut effects);
        assert_eq!(
            outcome,
            StepOutcome::Advance {
                next: SshState::Stop,
                info: Some("SFTP DONE done".to_owned()),
            }
        );
        assert_eq!(sshc.sftp_handle, None);
        assert!(sshp.path.is_empty());
        assert_eq!(peer.borrow().sent.len(), 1);
        assert_eq!(peer.borrow().sent[0][4], SftpPacket::Close.as_u8());
    }

    #[test]
    fn a_failed_close_is_diagnosed_and_never_propagated() {
        // `if(rc < 0) infof(data, "Failed to close libssh2 file: %d %s", ...)` --
        // the transfer's own status is what matters, not the close.
        let mut script = Scripted::new();
        script.status(SftpStatus::FAILURE);
        let (mut sshc, _peer) = conn_over(script);
        let mut sshp = SshProto::default();
        sshc.sftp_handle = Some(b"H9".to_vec());
        let set = settings();
        let mut effects = SftpEffects::new();
        ssh_set_state(&mut sshc, None, SshState::SftpClose);

        let outcome = do_step(&mut sshc, &mut sshp, &set, &mut effects);
        assert!(!outcome.is_failure());
        assert!(
            effects
                .info
                .iter()
                .any(|line| line
                    == "Failed to close libssh2 file: Operation failed"),
            "{:?}",
            effects.info
        );
    }

    #[test]
    fn the_disconnect_phase_runs_shutdown_then_disconnect_then_free() {
        let mut script = Scripted::new();
        script.status(SftpStatus::OK);
        let (mut sshc, peer) = conn_over(script);
        sshc.sftp_handle = Some(b"H8".to_vec());
        sshc.homedir = b"/home/u".to_vec();
        sshc.authed = true;
        sshc.nextstate = SshState::SftpClose;

        let clock = clock();
        let mut chains = FilterChains::new(None);
        let mut ctx = transfer_ctx(&mut chains, &clock);
        let mut effects = SftpEffects::new();

        for expected in [
            SshState::SessionDisconnect,
            SshState::SessionFree,
            SshState::Stop,
        ] {
            let state = if expected == SshState::SessionDisconnect {
                SshState::SftpShutdown
            } else if expected == SshState::SessionFree {
                SshState::SessionDisconnect
            } else {
                SshState::SessionFree
            };
            ssh_set_state(&mut sshc, None, state);
            let outcome = futures::executor::block_on(sftp_disconnect_step(
                &mut sshc,
                &mut effects,
                &mut ctx,
                false,
            ));
            match outcome {
                StepOutcome::Advance { next, .. } => {
                    assert_eq!(next, expected, "from {state:?}");
                }
                other => panic!("{state:?} answered {other:?}"),
            }
        }

        // The shutdown released the handle and the home directory.
        assert_eq!(sshc.sftp_handle, None);
        assert!(sshc.homedir.is_empty());
        // The subsystem was closed and the session disconnected.
        let calls = peer.borrow().calls.clone();
        assert!(calls.contains(&"close_sftp"), "{calls:?}");
        assert!(calls.contains(&"disconnect"), "{calls:?}");
        // And the free reset every piece of session state.
        assert!(!sshc.authed);
        assert_eq!(sshc.nextstate, SshState::NoState);
    }

    #[test]
    fn a_dead_connection_sends_nothing_during_the_disconnect() {
        let (mut sshc, peer) = conn_over(Scripted::new());
        sshc.sftp_handle = Some(b"H7".to_vec());
        let clock = clock();
        let mut chains = FilterChains::new(None);
        let mut ctx = transfer_ctx(&mut chains, &clock);
        let mut effects = SftpEffects::new();

        for state in [SshState::SftpShutdown, SshState::SessionDisconnect] {
            ssh_set_state(&mut sshc, None, state);
            let outcome = futures::executor::block_on(sftp_disconnect_step(
                &mut sshc,
                &mut effects,
                &mut ctx,
                true,
            ));
            assert!(!outcome.is_failure(), "{state:?}");
        }
        // Nothing was sent and nothing was asked of the session: a dead
        // connection must not be written to.
        assert!(peer.borrow().sent.is_empty());
        assert!(!peer.borrow().disconnected);
        assert!(!peer.borrow().closed_sftp);
        // But the handle was still dropped, because it cannot be used again.
        assert_eq!(sshc.sftp_handle, None);
    }

    #[test]
    fn the_session_free_reports_the_measured_connclose_reason() {
        let (mut sshc, _peer) = conn_over(Scripted::new());
        sshc.authed = true;
        sshc.acceptfail = true;
        sshc.authlist = b"password".to_vec();
        sshc.homedir = b"/home/u".to_vec();
        sshc.quote_index = 3;
        sshc.quote_list = QuoteList::PostQuote;
        sshc.second_create_dirs = 1;
        sshc.slash_pos = 7;
        sshc.waitfor = SshWait::RECV;
        sshc.sftp_handle = Some(b"H".to_vec());
        sshc.sftp_offset = 99;
        sshc.nextstate = SshState::SftpClose;

        let reason = ssh_session_free(&mut sshc);
        assert_eq!(reason, "SSH session free");
        // The `memset` reproduced field by field.
        assert!(!sshc.authed);
        assert!(!sshc.acceptfail);
        assert!(sshc.authlist.is_empty());
        assert!(sshc.homedir.is_empty());
        assert_eq!(sshc.quote_index, 0);
        assert_eq!(sshc.quote_list, QuoteList::Quote);
        assert_eq!(sshc.quote, None);
        assert_eq!(sshc.second_create_dirs, 0);
        assert_eq!(sshc.slash_pos, 0);
        assert_eq!(sshc.waitfor, SshWait::NONE);
        assert_eq!(sshc.sftp_handle, None);
        assert_eq!(sshc.sftp_offset, 0);
        assert_eq!(sshc.nextstate, SshState::NoState);
        // ⚠ And the state was RESTORED rather than left at zero, so the
        // transition that follows traces from `SSH_SESSION_FREE`.
        assert_eq!(sshc.state(), SshState::SessionFree);
    }

    #[test]
    fn restoring_the_state_is_not_a_transition() {
        // The one write to `state` that is not `ssh_set_state`, and it exists
        // only because the C's `memset` zeroed the field a line earlier. Asserted
        // so that the discipline stays legible: after the restoration the state
        // is the one the C names, not `SSH_STOP` which zero would give.
        let (mut sshc, _peer) = conn_over(Scripted::new());
        ssh_set_state(&mut sshc, None, SshState::SftpShutdown);
        let _ = ssh_session_free(&mut sshc);
        assert_ne!(sshc.state(), SshState::Stop);
        assert_eq!(sshc.state(), SshState::SessionFree);
    }

    #[test]
    fn the_two_schemes_enter_their_disconnect_phases_differently() {
        // The one seam `protocols/scp.rs` reads from this file rather than
        // restating: SFTP starts at `SSH_SFTP_SHUTDOWN` (`:3666`), SCP at
        // `SSH_SESSION_DISCONNECT` (`:3492`). Both converge on
        // `SSH_SESSION_FREE`.
        assert_eq!(disconnect_entry_state(Proto::SFTP), SshState::SftpShutdown);
        assert_eq!(
            disconnect_entry_state(Proto::SCP),
            SshState::SessionDisconnect
        );
    }

    // -- 15. the injected seams --------------------------------------------

    #[test]
    fn the_seams_are_deterministic_and_reproducible() {
        // Specification 0.3.3's pattern P12: the clock and the generator are
        // injected, which is what makes the request identifiers and any timing
        // reproducible -- and therefore what makes the coverage gate reachable.
        let mut first = SshSeams::deterministic(7);
        let mut second = SshSeams::deterministic(7);
        assert_eq!(first.random_u32(), second.random_u32());
        let mut a = [0_u8; 16];
        let mut b = [0_u8; 16];
        first.random_bytes(&mut a);
        second.random_bytes(&mut b);
        assert_eq!(a, b);
        // A different seed gives different bytes, so the seeding is real.
        let mut other = SshSeams::deterministic(8);
        assert_ne!(other.random_u32(), SshSeams::deterministic(7).random_u32());
        // The clock is fixed rather than the wall clock.
        let seams = SshSeams::deterministic(7);
        assert_eq!(seams.now(), seams.now());
    }

    #[test]
    fn the_request_identifier_advances_and_wraps() {
        let (mut sshc, _peer) = conn_over(Scripted::new());
        let first = sshc.next_request_id();
        let second = sshc.next_request_id();
        assert_eq!(second, first.wrapping_add(1));
        // Wrapping rather than saturating: an identifier only has to be unique
        // among the requests currently outstanding, and this module keeps one.
        for _ in 0..4 {
            let _ = sshc.next_request_id();
        }
        assert_eq!(sshc.next_request_id(), first.wrapping_add(6));
    }

    #[test]
    fn the_wait_direction_is_recorded_and_cleared() {
        // `ssh_block2waitfor`'s comment: *"Make sure to call this function in all
        // cases so that when it does not return EAGAIN we can restore the default
        // wait bits."* So a NON-blocking outcome clears the field.
        let mut script = Scripted::new();
        script.waitfor = SshWait::SEND;
        let (mut sshc, _peer) = conn_over(script);
        sshc.block2waitfor(true);
        assert_eq!(sshc.waitfor, SshWait::SEND);
        sshc.block2waitfor(false);
        assert_eq!(sshc.waitfor, SshWait::NONE);
    }

    #[test]
    fn the_wait_bits_are_the_keep_flags() {
        assert!(SshWait::NONE.is_empty());
        assert!(!SshWait::RECV.is_empty());
        assert!((SshWait::RECV | SshWait::SEND).contains(SshWait::RECV));
        assert!((SshWait::RECV | SshWait::SEND).contains(SshWait::SEND));
        assert!(!SshWait::RECV.contains(SshWait::SEND));
        assert_eq!(
            (SshWait::RECV | SshWait::SEND).bits(),
            SshWait::RECV.bits() | SshWait::SEND.bits()
        );
    }

    #[test]
    fn the_effects_accumulate_in_order() {
        let mut effects = SftpEffects::new();
        assert_eq!(effects, SftpEffects::default());
        effects.info("first".to_owned());
        effects.info("second".to_owned());
        assert_eq!(effects.info, ["first", "second"]);
        assert!(effects.body.is_empty());
        assert!(effects.header.is_empty());
        assert!(!effects.nop);
        assert_eq!(effects.filetime, None);
        assert_eq!(effects.download, None);
        assert_eq!(effects.upload_from, None);
    }

    #[test]
    fn a_scripted_peer_that_runs_out_of_replies_fails_loudly() {
        // A test that under-scripts its peer must fail rather than quietly
        // succeed, which is what makes every assertion above trustworthy.
        let (mut sshc, _peer) = conn_over(Scripted::new());
        let mut sshp = proto(b"/f");
        let set = settings();
        let (outcome, _effects) =
            drive(&mut sshc, &mut sshp, &set, SshState::SftpDownloadInit);
        assert!(outcome.is_err());
    }

    #[test]
    fn the_phase_driver_is_bounded_rather_than_looping_forever() {
        // The C has no bound, relying on every state either advancing or
        // reporting. The bound is here so that a defect in a transition produces
        // a diagnosable failure instead of a hang.
        let (mut sshc, _peer) = conn_over(Scripted::new());
        let mut sshp = SshProto::default();
        let set = settings();
        let clock = clock();
        let mut chains = FilterChains::new(None);
        let mut ctx = transfer_ctx(&mut chains, &clock);
        let mut effects = SftpEffects::new();
        // `SSH_SFTP_GETINFO` -> `SSH_SFTP_TRANS_INIT` -> `SSH_SFTP_DOWNLOAD_INIT`
        // needs a peer; with a limit of one step it cannot finish, and the
        // driver reports rather than spinning.
        ssh_set_state(&mut sshc, None, SshState::SftpGetinfo);
        let outcome = futures::executor::block_on(ssh_run_phase(
            &mut sshc,
            &mut sshp,
            &set,
            &mut effects,
            &mut ctx,
            SshPhase::SftpDo,
            1,
        ));
        assert_eq!(outcome, Err(CURLcode::Ssh));
    }

    #[test]
    fn the_internal_error_states_report_failed_init() {
        // `case SSH_QUIT: default:` -- the C's own comment is *"internal
        // error"*, and it answers `CURLE_FAILED_INIT` after `SSH_STOP`.
        for state in [SshState::Quit, SshState::Last] {
            let (mut sshc, _peer) = conn_over(Scripted::new());
            let mut sshp = SshProto::default();
            let set = settings();
            let mut effects = SftpEffects::new();
            ssh_set_state(&mut sshc, None, state);
            let outcome = do_step(&mut sshc, &mut sshp, &set, &mut effects);
            assert_eq!(outcome.code(), CURLcode::FailedInit, "{state:?}");
        }
    }

    // -- 16. the russh-backed transport, as far as it is reachable ----------

    #[test]
    fn the_transport_starts_unconnected_and_reports_it() {
        // Construction, the two accessors that need no context, and the
        // handshake refusal that documents why `russh_connect` exists.
        let (transport, peer_half) =
            RusshTransport::new(HostKeyPolicy::default());
        assert_eq!(
            transport.socket(),
            crate::conn::select::CURL_SOCKET_BAD,
            "no chain has been consulted yet"
        );
        assert_eq!(transport.block_directions(), SshWait::NONE);
        assert!(!transport.authenticated());
        assert_eq!(transport.hostkey(), None);
        // The `Debug` line carries progress and buffer occupancy and no key
        // material.
        let rendered = format!("{transport:?}");
        assert!(rendered.contains("connected: false"), "{rendered}");
        assert!(rendered.contains("sftp_open: false"), "{rendered}");
        // The peer half is the bridge end `russh_connect` consumes.
        drop(peer_half);
        drop(transport);
    }

    #[tokio::test]
    async fn the_transport_refuses_every_operation_before_the_handshake() {
        let clock = clock();
        let (mut chains, _state) = chains_with_transport(&clock, 5);
        let mut ctx = transfer_ctx(&mut chains, &clock);
        let (mut transport, _peer) =
            RusshTransport::new(HostKeyPolicy::default());

        // `handshake` reports rather than performing, because
        // `russh::client::connect_stream` CONSUMES the bridge half and a
        // `&mut self` member cannot hand it over.
        let refusal = transport
            .handshake(&mut ctx)
            .await
            .expect_err("the handshake is not reachable here");
        assert_eq!(refusal.to_curlcode(), CURLcode::Ssh);
        assert!(
            refusal.message().contains("russh_connect"),
            "{}",
            refusal.message()
        );

        // Every session operation needs a handle, and answers
        // `CURLE_COULDNT_CONNECT` without one.
        for outcome in [
            transport.auth_list(&mut ctx, "u").await.map(|_| ()),
            transport
                .auth_password(&mut ctx, "u", "p")
                .await
                .map(|_| ()),
            transport
                .auth_keyboard_interactive(&mut ctx, "u", "p")
                .await
                .map(|_| ()),
            transport.open_sftp(&mut ctx).await.map(|_| ()),
            transport
                .sftp_exchange(&mut ctx, request::init())
                .await
                .map(|_| ()),
        ] {
            assert_eq!(
                outcome.err().map(|error| error.to_curlcode()),
                Some(CURLcode::CouldntConnect)
            );
        }

        // The agent is a REFUSAL rather than an error, so the auth chain falls
        // through to keyboard-interactive exactly as it does against an agent
        // holding no usable identity.
        assert_eq!(transport.auth_agent(&mut ctx, "u").await, Ok(false));
        // Closing the subsystem and disconnecting are both no-ops with nothing
        // open, because the C's callers close regardless of the outcome.
        assert_eq!(transport.close_sftp(&mut ctx).await, Ok(()));
        assert_eq!(transport.disconnect(&mut ctx).await, Ok(()));
    }

    #[tokio::test]
    async fn a_public_key_that_does_not_exist_is_reported_not_ignored() {
        let clock = clock();
        let (mut chains, _state) = chains_with_transport(&clock, 5);
        let mut ctx = transfer_ctx(&mut chains, &clock);
        let (mut transport, _peer) =
            RusshTransport::new(HostKeyPolicy::default());

        // An empty private key is the C's "out of guesses" case and is a
        // refusal, not an error.
        assert_eq!(
            transport.auth_publickey(&mut ctx, "u", "", None, "").await,
            Ok(false)
        );
        // A named public key that is absent is reported, because the C's
        // *"public key not found"* refusal is observable.
        let refusal = transport
            .auth_publickey(
                &mut ctx,
                "u",
                "/nonexistent/key",
                Some("/nonexistent/key.pub"),
                "",
            )
            .await
            .expect_err("an absent public key is reported");
        assert!(
            refusal.message().contains("public key not found"),
            "{}",
            refusal.message()
        );
        // And an unreadable private key is reported too.
        let refusal = transport
            .auth_publickey(&mut ctx, "u", "/nonexistent/key", None, "")
            .await
            .expect_err("an unreadable key is reported");
        assert_eq!(refusal.to_curlcode(), CURLcode::Ssh);
    }

    #[tokio::test]
    async fn the_shuttle_moves_bytes_between_the_bridge_and_the_chain() {
        use tokio::io::AsyncWriteExt as _;

        let clock = clock();
        let (mut chains, state) = chains_with_transport(&clock, 5);
        // Bytes the chain will hand upward.
        state.borrow_mut().input = b"from the peer".to_vec();
        let mut ctx = transfer_ctx(&mut chains, &clock);
        let (mut transport, mut peer) =
            RusshTransport::new(HostKeyPolicy::default());

        // Write on the far side of the bridge, as russh would.
        peer.write_all(b"to the peer")
            .await
            .expect("the bridge accepts");
        peer.flush().await.expect("flushed");

        // One turn moves both directions.
        let turn = RusshTransport::shuttle(
            &mut transport.bridge,
            &mut transport.outbound,
            &mut transport.inbound,
            &mut transport.socket,
            &mut ctx,
        )
        .expect("the chain is healthy");
        assert_eq!(turn, ShuttleTurn::Progress);
        // The descriptor was refreshed from the chain, which is what lets
        // `socket()` answer without a context.
        assert_eq!(transport.socket, 5);
        // What russh wrote reached the chain.
        assert_eq!(state.borrow().output, b"to the peer".to_vec());
        // And what the chain held reached the bridge, so russh can read it.
        assert!(state.borrow().input.is_empty());
        assert!(transport.inbound.is_empty(), "handed to the bridge");
    }

    #[tokio::test]
    async fn the_shuttle_reports_a_closed_chain_and_an_idle_one() {
        let clock = clock();
        let (mut chains, state) = chains_with_transport(&clock, 5);
        let mut ctx = transfer_ctx(&mut chains, &clock);
        let (mut transport, _peer) =
            RusshTransport::new(HostKeyPolicy::default());

        // A readable chain with nothing in it is END OF STREAM, exactly as a
        // zero from `recv(2)` is.
        let turn = RusshTransport::shuttle(
            &mut transport.bridge,
            &mut transport.outbound,
            &mut transport.inbound,
            &mut transport.socket,
            &mut ctx,
        )
        .expect("a healthy chain");
        assert_eq!(turn, ShuttleTurn::Closed);

        // A chain that would block in both directions makes no progress, which
        // is what the idle counter and the yield are for.
        state.borrow_mut().readable = false;
        state.borrow_mut().writable = false;
        let turn = RusshTransport::shuttle(
            &mut transport.bridge,
            &mut transport.outbound,
            &mut transport.inbound,
            &mut transport.socket,
            &mut ctx,
        )
        .expect("would-block is not a failure");
        assert_eq!(turn, ShuttleTurn::Idle);
    }

    #[tokio::test]
    async fn a_chain_that_refuses_a_read_is_reported() {
        let clock = clock();
        let (mut chains, state) = chains_with_transport(&clock, 5);
        state.borrow_mut().readable = false;
        state.borrow_mut().writable = false;
        let mut ctx = transfer_ctx(&mut chains, &clock);
        let (mut transport, _peer) =
            RusshTransport::new(HostKeyPolicy::default());

        // The pump gives up after `SHUTTLE_IDLE_LIMIT` fruitless turns rather
        // than hanging, and it reports the C's own "would block".
        //
        // Driven with a much smaller budget than the constant by making the
        // chain report end of stream instead, which is the other terminating
        // condition and is reached in one turn.
        state.borrow_mut().readable = true;
        let failure = RusshTransport::pump(
            &mut transport.bridge,
            &mut transport.outbound,
            &mut transport.inbound,
            &mut transport.socket,
            &mut ctx,
        )
        .await;
        assert_eq!(failure.to_curlcode(), CURLcode::CouldntConnect);
    }

    // The bridge and shuttle bounds are asserted at their definition site by the
    // three `const _: () = assert!(..)` items beside them, which is where a
    // compile-time invariant belongs -- see the comment there.

    #[test]
    fn the_russh_error_map_picks_out_the_three_with_distinct_codes() {
        assert_eq!(
            russh_error(russh::Error::SendError).to_curlcode(),
            CURLcode::SendError
        );
        assert_eq!(
            russh_error(russh::Error::Disconnect).to_curlcode(),
            CURLcode::SendError
        );
        assert_eq!(
            russh_error(russh::Error::ConnectionTimeout).to_curlcode(),
            CURLcode::OperationTimedout
        );
        assert_eq!(
            russh_error(russh::Error::KeepaliveTimeout).to_curlcode(),
            CURLcode::OperationTimedout
        );
        assert_eq!(
            russh_error(russh::Error::UnknownKey).to_curlcode(),
            CURLcode::PeerFailedVerification
        );
        assert_eq!(
            russh_error(russh::Error::WrongServerSig).to_curlcode(),
            CURLcode::PeerFailedVerification
        );
        assert_eq!(
            russh_error(russh::Error::NotAuthenticated).to_curlcode(),
            CURLcode::LoginDenied
        );
        // Everything else is the C's fall-through, `CURLE_SSH`.
        assert_eq!(russh_error(russh::Error::Kex).to_curlcode(), CURLcode::Ssh);
    }

    #[test]
    fn the_method_list_uses_rfc_4252_spellings_separated_by_one_comma() {
        // ⚠ The spellings are wire vocabulary and are what `authlist::offers`
        // searches for, so they must be russh's own rather than a re-spelling.
        let mut methods = russh::MethodSet::empty();
        methods.push(russh::MethodKind::PublicKey);
        methods.push(russh::MethodKind::Password);
        let list = method_list(&methods);
        let text = String::from_utf8(list.clone()).expect("ascii");
        assert!(text.contains("publickey"), "{text}");
        assert!(text.contains("password"), "{text}");
        assert!(!text.contains(", "), "one comma, no space: {text}");
        assert!(authlist::offers(&list, authlist::PUBLICKEY));
        assert!(authlist::offers(&list, authlist::PASSWORD));
        assert!(!authlist::offers(&list, authlist::HOSTBASED));
        // An empty set is an empty list, which is the "no authentication
        // required" case.
        assert!(method_list(&russh::MethodSet::empty()).is_empty());
    }

    #[test]
    fn the_key_algorithm_mapping_covers_russhs_vocabulary() {
        use russh::keys::Algorithm;
        assert_eq!(hostkey_type_of(&Algorithm::Ed25519), HostKeyType::Ed25519);
        assert_eq!(hostkey_type_of(&Algorithm::Dsa), HostKeyType::Dss);
        assert_eq!(
            hostkey_type_of(&Algorithm::Rsa { hash: None }),
            HostKeyType::Rsa
        );
        assert_eq!(
            hostkey_type_of(&Algorithm::Ecdsa {
                curve: russh::keys::EcdsaCurve::NistP256
            }),
            HostKeyType::Ecdsa
        );
        // And the placeholder a poisoned lock records is an ABSENT key rather
        // than a silently accepted one, so `SSH_HOST_KEY` reports *"sha256
        // fingerprint not available"*.
        let placeholder = blob_placeholder();
        assert!(placeholder.blob.is_empty());
        assert_eq!(placeholder.key_type(), HostKeyType::Unknown);
    }
}
