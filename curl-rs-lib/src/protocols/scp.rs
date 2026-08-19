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
//! SCP, layered on the shared russh SSH session core in [`super::sftp`].
//!
//! # What this file supersedes, with locators
//!
//! * `lib/vssh/libssh2.c:3823-3841` -- `Curl_protocol_scp`, the 17-slot handler
//!   this file reproduces as [`SCP`]. Eleven slots are occupied and six are
//!   `ZERO_NULL`; [`Scp`] carries the slot-by-slot correspondence.
//! * `lib/vssh/libssh2.c:3846-3864` -- `Curl_protocol_sftp`. Cited here because
//!   the comparison with the row above is the whole justification for this
//!   file's shape: the two handlers are **identical in 14 of their 17 slots**,
//!   differing only in `done`, `doing` and `disconnect`. So the shared core
//!   lives in `protocols/sftp.rs` and this file imports it.
//! * `lib/vssh/vssh.c:352-359` -- `Curl_scheme_scp`, the registry row, which is
//!   [`SCHEME`] here.
//! * `lib/vssh/ssh.h:107-117` -- the four phase-boundary comments that decide
//!   which states this file owns. They are carried verbatim onto the arms of
//!   [`scp_do_step`] that implement them:
//!   `SSH_SCP_TRANS_INIT` *"First state in SCP-DO"*,
//!   `SSH_SCP_CHANNEL_FREE` *"Last state in SCP-DONE"*,
//!   `SSH_SESSION_DISCONNECT` *"First state in SCP-DISCONNECT"* and
//!   `SSH_SESSION_FREE` *"Last state in SCP/SFTP-DISCONNECT"* -- the last of
//!   which terminates BOTH schemes and therefore stays in `protocols/sftp.rs`.
//! * `lib/vssh/libssh2.c:2867-2975` -- the eight `case SSH_SCP_*` arms of
//!   `ssh_statemachine`, plus `ssh_state_scp_upload_init` (`:2376-2424`) and
//!   `ssh_state_scp_download_init` (`:2231-2273`).
//! * `lib/vssh/libssh2.c:3439-3597` -- `scp_perform`, `scp_doing`,
//!   `scp_disconnect`, `ssh_done`, `scp_done`, `scp_send` and `scp_recv`.
//! * `lib/curl_trc.c:462` -- `Curl_trc_feat_ssh`, whose `name` member is
//!   `"SSH"`, registered in `TRC_CT_PROTOCOL` at `:525`. The string is
//!   CONSUMED from [`TraceFeature::Ssh`] and is not spelled again here.
//!
//! Read rather than superseded: `lib/vssh/vssh.h` for the declarations the two
//! schemes share, `lib/urldata.h` for `struct Curl_protocol` and the
//! `PROTOPT_*` bits, and `tests/getpart.pm:351+` for `compareparts`, which
//! joins both sides into a single string and compares them as one -- no
//! per-line matching, no normalisation, no reordering. That is why every byte
//! this file puts on the wire is a transcribed literal rather than a formatted
//! approximation, and it matters acutely for SCP: the protocol is a handful of
//! terse control messages and there is nothing else to get right.
//!
//! **`lib/vssh/libssh.c` is excluded entirely.** Specification 0.2.2 drops
//! every alternate backend, so the libssh half of the C's
//! `#ifdef USE_LIBSSH / #elif defined(USE_LIBSSH2)` split has no successor.
//!
//! # What this file contributes, and what it must not
//!
//! Specification 0.4.1 assigns `lib/vssh/` exactly two targets --
//! `protocols/sftp.rs` and `protocols/scp.rs` -- and names no third. The
//! 14-of-17 overlap therefore lands in the sibling, and this file contributes
//! ONLY the SCP-specific remainder:
//!
//! * the registry row -- [`SCHEME`], [`FLAGS_SCP`];
//! * the three differing vtable slots -- [`Scp::done`], [`Scp::doing`] and
//!   [`Scp::disconnect`], reached through [`scp_done`] and [`scp_run_phase`];
//! * the SCP-DO and SCP-DONE phases of the shared machine -- [`scp_do_step`];
//! * the SCP wire dialogue, which libssh2 owns in the C and nothing in the
//!   closed dependency set owns here -- [`ScpFileHeader`], [`ScpMessage`],
//!   [`scp_command`] and the dialogue on [`ScpConn`];
//! * the channel that dialogue runs over -- [`ScpChannel`], [`ScpSession`],
//!   [`ScpStream`] -- and the per-connection state holding it, [`ScpConn`].
//!
//! Everything else is imported. [`SshState`] is imported rather than
//! redeclared, [`ssh_set_state`] is the only writer of the state field in
//! either module, and SCP-DISCONNECT is not implemented here at all: its two
//! states are `SSH_SESSION_DISCONNECT` and `SSH_SESSION_FREE`, both of which
//! terminate SFTP's disconnect phase too, so [`scp_run_phase`] hands that phase
//! straight to the sibling's [`ssh_run_phase`].
//!
//! # Why SCP needs a channel seam when SFTP does not
//!
//! `struct ssh_conn` (`lib/vssh/ssh.h:145-222`) carries an `ssh_channel`
//! member and a `sftp_handle` member. `SshConn` reproduces the second and not
//! the first, because SFTP's data path is a request/reply exchange that
//! [`SshTransport::sftp_exchange`] expresses, while SCP's is a raw byte stream
//! over a channel running a remote `scp` command. So the channel is SCP's own
//! state and lives in [`ScpConn`], and the operations on it are SCP's own seam.
//!
//! This is not a second transport abstraction competing with
//! [`SshTransport`]. The division mirrors the C exactly: every libssh2 call in
//! `lib/vssh/libssh2.c` is either a SESSION operation -- handshake, the method
//! list, the five authentication mechanisms, disconnect -- or a CHANNEL
//! operation. [`SshTransport`] is the first group and is shared;
//! [`ScpChannel`] is the `libssh2_channel_*` and `libssh2_scp_*` subset that
//! only SCP reaches.
//!
//! # The dialogue libssh2 hides, written out
//!
//! The C never spells the SCP protocol: `libssh2_scp_recv2` and
//! `libssh2_scp_send64` perform it inside libssh2. `russh` has no SCP support
//! at all -- it is an SSH implementation, and SCP is a program invoked over
//! SSH -- so the dialogue is reproduced here from its specification, one
//! documented byte at a time. [`ScpFileHeader`] and [`ScpMessage`] are that
//! reproduction, and every literal they emit is asserted as a whole byte string
//! by [`mod tests`](self), mirroring `compareparts`.
//!
//! # Four measured facts a reader will look for and not find
//!
//! Each is an absence in the C that this file preserves, recorded here because
//! each one looks like an omission:
//!
//! 1. **SCP runs no quote commands.** `scp_perform` (`:3439`) enters
//!    `SSH_SCP_TRANS_INIT` directly, and no `SSH_SFTP_QUOTE_*` state is
//!    reachable from any SCP arm. So `--quote`, `--postquote` and `--prequote`
//!    are accepted on an `scp://` URL and silently ignored. [`SshSettings`]
//!    still carries all three, because the option round-trips.
//! 2. **SCP ignores `--range` and `--continue-at`, and refuses neither.**
//!    `Curl_ssh_range` (`lib/vssh/vssh.c:287`) has exactly one caller,
//!    `ssh_state_sftp_download_stat` (`lib/vssh/libssh2.c:1310`).
//!    `ssh_state_scp_download_init` reads neither `data->state.range` nor
//!    `data->state.resume_from`, and `ssh_state_scp_upload_init` uses
//!    `data->state.infilesize` unadjusted where the SFTP path subtracts the
//!    resume offset from it (`:1042`). `lib/url.c:1861-1867` turns
//!    `--continue-at` into a range string for every scheme; SCP never consults
//!    it. So neither option produces a diagnostic and neither changes a byte.
//! 3. **SCP has no directory operations.** No `readdir`, no `stat`, no
//!    `mkdir`, and no trailing-slash test -- that test is SFTP's, in
//!    `SSH_SFTP_TRANS_INIT`. A directory named on an `scp://` URL is handed to
//!    the remote `scp -f`, which answers with an error message, and the
//!    dialogue reports it as [`SshError::ScpProtocol`] --
//!    [`CURLcode::RemoteFileNotFound`], the same code
//!    `tests/data/test605` expects for a file that does not exist.
//! 4. **`SSH_SCP_DOWNLOAD` has no `case` in the C's switch.** The token exists
//!    in the C state enumeration and no arm implements it, because libssh2
//!    moves the
//!    payload inside `scp_recv` rather than in a state. It therefore falls into
//!    `case SSH_QUIT: default:` (`:2993-2997`), whose whole body is
//!    `/* internal error */ myssh_to(data, sshc, SSH_STOP); break;` -- and which
//!    assigns no code, `result` having been initialised to `CURLE_OK` at
//!    `:2571`. [`scp_do_step`] reproduces that: the arm exists, moves to
//!    `SSH_STOP`, and reports nothing.
//!
//! # `pub(crate)`, and no TLS
//!
//! No exported symbol of `lib/libcurl.def` resolves a name in this file: a
//! scheme is selected by URL and never named by a caller. And there is no
//! `crate::tls` import, deliberately -- SSH carries its own transport
//! security, and the filter chain below it deals in bytes. The socket beneath
//! `russh` belongs to that chain and never to `russh`, which is what makes
//! every test below reachable without a network.

use core::fmt;

use crate::conn::select::{EasyPollset, Socket};
use crate::conn::ProtocolOptions;
use crate::error::{CURLcode, CodeResult};
use crate::protocols::{
    Proto, ProtoFuture, Protocol, Scheme, TransferCtx, PORT_SSH,
};
use crate::trace::{trc_feat, TraceFeature};

use super::sftp::{
    disconnect_entry_state, getworkingpath, sftp_disconnect_step, ssh_attach,
    ssh_pollset, ssh_run_phase, ssh_set_state, DownloadPlan, SftpEffects,
    SshConn, SshError, SshFuture, SshPhase, SshProto, SshSettings, SshState,
    SshWait, StepOutcome, CURL_PATH_MAX,
};

// The SCP wire dialogue -- what libssh2 performs inside `libssh2_scp_recv2`
// and `libssh2_scp_send64`, written out

/// The acknowledgement byte: a single zero.
///
/// Sent and expected in both directions. The sink acknowledges the header and
/// the source acknowledges the sink's readiness with exactly this one byte, and
/// there is no other in-band success signal in the protocol.
#[allow(dead_code)] // consumer: the SCP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) const SCP_ACK: u8 = 0x00;

/// The warning prefix: `\x01`, followed by text and a newline.
///
/// A recoverable complaint. The protocol allows the transfer to continue after
/// one, which is why [`ScpMessage`] keeps it distinct from
/// [`Self::SCP_ERROR`](SCP_ERROR) rather than folding the two together.
#[allow(dead_code)] // consumer: the SCP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) const SCP_WARNING: u8 = 0x01;

/// The error prefix: `\x02`, followed by text and a newline.
///
/// Fatal. The remote `scp` sends this and stops, which is the byte sequence a
/// missing file or an unwritable directory actually produces -- and therefore
/// the byte sequence behind `tests/data/test605`'s `errorcode 78` and
/// `test623`'s `errorcode 25`.
#[allow(dead_code)] // consumer: the SCP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) const SCP_ERROR: u8 = 0x02;

/// The file-header prefix: `C`, as in `C0644 1234 name`.
///
/// libssh2 writes the header as `C0%o %<size> %<name>\n`, so the digit after
/// the `C` is a literal `0` and the octal permission bits follow it. A
/// four-digit-looking `0644` is therefore `C` + `0` + `644`, and a mode with a
/// set-user-id bit would render five digits. Reproduced exactly; see
/// [`ScpFileHeader::encode`].
#[allow(dead_code)] // consumer: the SCP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) const SCP_FILE: u8 = b'C';

/// The directory-header prefix: `D`.
///
/// Recognised and refused. Recursive SCP is `scp -r`, which curl never
/// requests -- neither `libssh2_scp_recv2` nor `libssh2_scp_send64` passes
/// `-r`, so a `D` header can only arrive from a peer answering a request curl
/// did not make. Naming it is what lets [`ScpFileHeader::parse`] report
/// [`SshError::ScpProtocol`] for it rather than mistaking it for corruption.
#[allow(dead_code)] // consumer: the SCP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) const SCP_DIRECTORY: u8 = b'D';

/// The end-of-directory header prefix: `E`.
///
/// Refused for the same reason as [`SCP_DIRECTORY`].
#[allow(dead_code)] // consumer: the SCP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) const SCP_END_DIRECTORY: u8 = b'E';

/// The timestamp header prefix: `T`, as in `T<mtime> 0 <atime> 0`.
///
/// ACCEPTED on the source path and never SENT. libssh2 emits a `T` header only
/// when `libssh2_scp_send64` is given a non-zero mtime or atime, and curl
/// passes `0, 0` (`lib/vssh/libssh2.c:2387-2389`) -- so curl never sends one.
/// It is accepted because a remote `scp` may send one unprompted, and libssh2's
/// source path acknowledges it and reads the next header; that behaviour is
/// reproduced in [`ScpConn::read_header`].
#[allow(dead_code)] // consumer: the SCP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) const SCP_TIMESTAMP: u8 = b'T';

/// `scp -f `, the source command: the peer sends, we receive.
///
/// `libssh2_scp_recv2` builds `"scp -f "` followed by the shell-quoted path and
/// runs it as the channel's `exec` request. The trailing space is part of the
/// literal, so [`scp_command`] concatenates without inserting one.
///
/// `#[rustfmt::skip]` because the byte string is the wire.
#[rustfmt::skip]
#[allow(dead_code)] // consumer: the SCP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) const SCP_SOURCE_COMMAND: &[u8] = b"scp -f ";

/// `scp -t `, the sink command: we send, the peer receives.
///
/// `libssh2_scp_send64`'s counterpart to [`SCP_SOURCE_COMMAND`]. Note what is
/// absent: no `-p`, because curl passes zero timestamps, and no `-r`, because
/// curl never requests a recursive transfer.
///
/// `#[rustfmt::skip]` because the byte string is the wire.
#[rustfmt::skip]
#[allow(dead_code)] // consumer: the SCP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) const SCP_SINK_COMMAND: &[u8] = b"scp -t ";

/// How long a control line may be before the dialogue gives up on it.
///
/// libssh2 reads a header into a fixed buffer and treats an overrun as a
/// protocol error. The ceiling here is [`CURL_PATH_MAX`] plus room for the
/// prefix, the mode, the size and the two separators -- a header carries a file
/// NAME, and a name longer than the C's own path ceiling could not have been
/// requested in the first place.
#[allow(dead_code)] // consumer: the SCP phase drivers, reached once easy/setopt.rs can supply SshSettings
const SCP_MAX_LINE: usize = CURL_PATH_MAX + 64;

/// One control message of the SCP dialogue.
///
/// The protocol has exactly three in-band forms and this enumerates all three.
/// Anything else is [`SshError::ScpProtocol`], which is what libssh2 reports as
/// `LIBSSH2_ERROR_SCP_PROTOCOL` and what the C maps to
/// [`CURLcode::RemoteFileNotFound`] (`lib/vssh/libssh2.c:197-201`).
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)] // consumer: the SCP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) enum ScpMessage {
    /// A single [`SCP_ACK`] byte: proceed.
    Ack,
    /// [`SCP_WARNING`] followed by text: a complaint the transfer may survive.
    ///
    /// The text is carried WITHOUT its terminating newline, because the newline
    /// is a frame delimiter rather than content -- and because the text reaches
    /// a `failf` line, where a trailing newline would produce a blank line in
    /// the error output.
    Warning(Vec<u8>),
    /// [`SCP_ERROR`] followed by text: fatal.
    Error(Vec<u8>),
}

#[allow(dead_code)] // consumer: the SCP phase drivers, reached once easy/setopt.rs can supply SshSettings
impl ScpMessage {
    /// The bytes this message occupies on the wire, terminator included.
    ///
    /// The inverse of [`Self::parse`], and the reason both exist: a test can
    /// assert a whole byte string in either direction, which is the only way to
    /// honour `compareparts` without a peer.
    pub(crate) fn encode(&self) -> Vec<u8> {
        match self {
            Self::Ack => vec![SCP_ACK],
            Self::Warning(text) => Self::encode_text(SCP_WARNING, text),
            Self::Error(text) => Self::encode_text(SCP_ERROR, text),
        }
    }

    /// `<prefix><text>\n` -- one prefix byte, the text, one newline.
    fn encode_text(prefix: u8, text: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(text.len() + 2);
        out.push(prefix);
        out.extend_from_slice(text);
        out.push(b'\n');
        out
    }

    /// Classify one control message that has already been framed.
    ///
    /// `line` is a complete message with its terminating newline REMOVED for
    /// the text forms, and is a single byte for [`Self::Ack`]. Framing is
    /// [`ScpDialogue`]'s job because it owns the reader; classification is here
    /// because it is pure.
    ///
    /// # Errors
    ///
    /// [`SshError::ScpProtocol`] for an empty message or an unrecognised
    /// prefix. libssh2 makes no finer distinction, and neither does the C's
    /// error map: everything that is not a well-formed reply is
    /// `LIBSSH2_ERROR_SCP_PROTOCOL`.
    pub(crate) fn parse(line: &[u8]) -> Result<Self, SshError> {
        match line.split_first() {
            // An acknowledgement is the WHOLE frame: one zero byte and nothing
            // after it. A zero followed by more bytes is not an
            // acknowledgement, so the empty-tail pattern is load-bearing rather
            // than a tidiness.
            Some((&SCP_ACK, [])) => Ok(Self::Ack),
            Some((&SCP_WARNING, rest)) => {
                Ok(Self::Warning(Self::trim_newline(rest).to_vec()))
            }
            Some((&SCP_ERROR, rest)) => {
                Ok(Self::Error(Self::trim_newline(rest).to_vec()))
            }
            _ => Err(SshError::ScpProtocol),
        }
    }

    /// Drop one trailing newline if the caller left it on.
    ///
    /// Tolerant on purpose: [`ScpDialogue`] strips the delimiter it framed on,
    /// but [`Self::parse`] is also reachable from a test that passes the raw
    /// wire bytes, and both must classify identically.
    fn trim_newline(text: &[u8]) -> &[u8] {
        match text.split_last() {
            Some((&b'\n', head)) => head,
            _ => text,
        }
    }

    /// The text a `failf` line reports for this message.
    ///
    /// Empty for [`Self::Ack`], which never reaches a diagnostic.
    pub(crate) fn text(&self) -> &[u8] {
        match self {
            Self::Ack => &[],
            Self::Warning(text) | Self::Error(text) => text.as_slice(),
        }
    }

    /// Whether this message ends the transfer.
    ///
    /// [`Self::Error`] alone. A warning is survivable by the protocol's own
    /// definition, and libssh2 continues past one.
    pub(crate) const fn is_fatal(&self) -> bool {
        matches!(self, Self::Error(_))
    }
}

/// A file header: `C<mode> <size> <name>` -- the whole of SCP's metadata.
///
/// Three fields and nothing else. SCP transmits no owner, no group and no
/// timestamps unless a separate `T` header precedes it, which is why
/// `--remote-time` has nothing to read on an `scp://` transfer and why
/// [`SftpEffects::filetime`] stays [`None`] on this path.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)] // consumer: the SCP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) struct ScpFileHeader {
    /// The POSIX permission bits, as the header spells them.
    ///
    /// On the sink path this is `CURLOPT_NEW_FILE_PERMS`, which the C passes
    /// as `(int)data->set.new_file_perms` (`lib/vssh/libssh2.c:2388`) and whose
    /// default is `0644`. On the source path it is whatever the peer sent, and
    /// curl discards it -- `libssh2_scp_recv2` fills a `struct stat` whose
    /// `st_mode` `ssh_state_scp_download_init` never reads.
    pub(crate) mode: u32,
    /// The payload length in bytes, which SCP requires UP FRONT.
    ///
    /// This is the structural difference from SFTP and the reason
    /// [`scp_trans_init`] can refuse an upload: there is no way to express an
    /// unknown length in this header, so a stream of unknown size cannot be
    /// sent at all.
    pub(crate) size: u64,
    /// The file name -- the BASENAME of the path, never the path.
    ///
    /// `libssh2_scp_send64` takes `strrchr(path, '/') + 1`, so `/tmp/a/b.txt`
    /// is announced as `b.txt` and the directory comes from the `scp -t`
    /// argument instead. [`basename`] is that derivation.
    pub(crate) name: Vec<u8>,
}

#[allow(dead_code)] // consumer: the SCP phase drivers, reached once easy/setopt.rs can supply SshSettings
impl ScpFileHeader {
    /// A header for `path` with `mode` and `size`, taking the basename.
    ///
    /// The sink-side constructor, which is where the basename rule applies.
    pub(crate) fn for_upload(path: &[u8], mode: u32, size: u64) -> Self {
        Self {
            mode,
            size,
            name: basename(path).to_vec(),
        }
    }

    /// The bytes this header occupies on the wire, newline included.
    ///
    /// `C0%o %<size> %<name>\n`, exactly as `libssh2_scp_send64` composes it.
    /// Three details are the protocol's and none may be tidied:
    ///
    /// * the literal `0` after the `C` is part of the format, not a leading
    ///   zero of the mode -- mode `0o644` renders `C0644` and mode `0o4755`
    ///   renders `C04755`;
    /// * the mode is OCTAL and unpadded;
    /// * the separators are single spaces and the terminator is a bare
    ///   newline, not CRLF.
    ///
    /// `#[rustfmt::skip]` on the body: the format string is the wire, and a
    /// formatter that reflowed it would change the bytes.
    #[rustfmt::skip]
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.name.len() + 24);
        out.push(SCP_FILE);
        out.push(b'0');
        out.extend_from_slice(format!("{:o}", self.mode).as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.size.to_string().as_bytes());
        out.push(b' ');
        out.extend_from_slice(&self.name);
        out.push(b'\n');
        out
    }

    /// Parse one `C` header, newline already stripped or still attached.
    ///
    /// The acceptance rules are libssh2's and are strict, because a lenient
    /// reader here would turn a peer's error message into a plausible-looking
    /// transfer:
    ///
    /// * the first byte must be [`SCP_FILE`];
    /// * the mode must be octal digits, at least one, terminated by a space;
    /// * the size must be decimal digits, at least one, terminated by a space;
    /// * the name must be non-empty and runs to the end of the line.
    ///
    /// # Errors
    ///
    /// [`SshError::ScpProtocol`] for every violation, which is the single
    /// classification libssh2 offers.
    pub(crate) fn parse(line: &[u8]) -> Result<Self, SshError> {
        let body = match line.split_first() {
            Some((&SCP_FILE, rest)) => ScpMessage::trim_newline(rest),
            _ => return Err(SshError::ScpProtocol),
        };

        let space = body
            .iter()
            .position(|byte| *byte == b' ')
            .ok_or(SshError::ScpProtocol)?;
        let (mode_text, rest) = body.split_at(space);
        let mode = parse_octal(mode_text)?;

        // `rest` still carries the separator; step over exactly one.
        let rest = rest.get(1..).ok_or(SshError::ScpProtocol)?;
        let space = rest
            .iter()
            .position(|byte| *byte == b' ')
            .ok_or(SshError::ScpProtocol)?;
        let (size_text, rest) = rest.split_at(space);
        let size = parse_decimal(size_text)?;

        let name = rest.get(1..).ok_or(SshError::ScpProtocol)?;
        if name.is_empty() {
            return Err(SshError::ScpProtocol);
        }

        Ok(Self {
            mode,
            size,
            name: name.to_vec(),
        })
    }
}

/// Octal digits to a value, refusing anything else.
///
/// Written here rather than taken from [`crate::util::strparse`] because the
/// failure this must report is [`SshError::ScpProtocol`] and because the
/// acceptance rule is narrower: no sign, no whitespace, no prefix, and at
/// least one digit.
///
/// # Errors
///
/// [`SshError::ScpProtocol`] for an empty string, a non-octal byte or a value
/// that would not fit.
#[allow(dead_code)] // consumer: the SCP phase drivers, reached once easy/setopt.rs can supply SshSettings
fn parse_octal(text: &[u8]) -> Result<u32, SshError> {
    if text.is_empty() {
        return Err(SshError::ScpProtocol);
    }
    let mut value: u32 = 0;
    for byte in text {
        let digit = match byte {
            b'0'..=b'7' => u32::from(byte - b'0'),
            _ => return Err(SshError::ScpProtocol),
        };
        value = value
            .checked_mul(8)
            .and_then(|shifted| shifted.checked_add(digit))
            .ok_or(SshError::ScpProtocol)?;
    }
    Ok(value)
}

/// Decimal digits to a value, refusing anything else.
///
/// The same narrow rule as [`parse_octal`]. A size is unsigned in this header:
/// SCP has no way to express a negative length, so a `-` is a protocol error
/// rather than a parse of a signed field.
///
/// # Errors
///
/// [`SshError::ScpProtocol`] for an empty string, a non-decimal byte or a
/// value that would not fit.
#[allow(dead_code)] // consumer: the SCP phase drivers, reached once easy/setopt.rs can supply SshSettings
fn parse_decimal(text: &[u8]) -> Result<u64, SshError> {
    if text.is_empty() {
        return Err(SshError::ScpProtocol);
    }
    let mut value: u64 = 0;
    for byte in text {
        let digit = match byte {
            b'0'..=b'9' => u64::from(byte - b'0'),
            _ => return Err(SshError::ScpProtocol),
        };
        value = value
            .checked_mul(10)
            .and_then(|shifted| shifted.checked_add(digit))
            .ok_or(SshError::ScpProtocol)?;
    }
    Ok(value)
}

/// The last path component, which is what a `C` header announces.
///
/// `libssh2_scp_send64`'s `strrchr(path, '/')`, with the same two edge
/// behaviours: a path with no separator IS its own basename, and a path ending
/// in a separator yields an EMPTY basename rather than the component before it.
/// The second is worth stating because it is not the shell's `basename(1)`
/// behaviour -- but it is what a `char *` scan produces, and it is what the
/// remote `scp` therefore receives.
#[allow(dead_code)] // consumer: the SCP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) fn basename(path: &[u8]) -> &[u8] {
    match path.iter().rposition(|byte| *byte == b'/') {
        Some(at) => path.get(at + 1..).unwrap_or(&[]),
        None => path,
    }
}

/// Which end of the transfer we are.
///
/// Named because the SCP specification's own vocabulary inverts the intuitive
/// reading, and getting it backwards swaps the two commands: the SOURCE is the
/// end that PRODUCES the file, so curl asks for `scp -f` (from) when
/// DOWNLOADING and `scp -t` (to) when UPLOADING.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)] // consumer: the SCP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) enum ScpDirection {
    /// The peer is the source: `scp -f`. curl downloads.
    Source,
    /// The peer is the sink: `scp -t`. curl uploads.
    Sink,
}

#[allow(dead_code)] // consumer: the SCP phase drivers, reached once easy/setopt.rs can supply SshSettings
impl ScpDirection {
    /// Which direction a transfer with this `upload` flag runs in.
    ///
    /// `data->state.upload`, which `SSH_SCP_TRANS_INIT` branches on
    /// (`lib/vssh/libssh2.c:2875`).
    pub(crate) const fn for_upload(upload: bool) -> Self {
        if upload {
            Self::Sink
        } else {
            Self::Source
        }
    }

    /// The command literal this direction runs on the peer.
    pub(crate) const fn command(self) -> &'static [u8] {
        match self {
            Self::Source => SCP_SOURCE_COMMAND,
            Self::Sink => SCP_SINK_COMMAND,
        }
    }
}

/// The `exec` request one direction makes: the command, then the quoted path.
///
/// `libssh2_scp_recv2` and `libssh2_scp_send64` both build their command by
/// concatenating the literal -- which already ends in a space -- with
/// [`shell_quotearg`] of the path. No further separator and no terminator: an
/// `exec` request carries a length-prefixed string, not a line.
#[allow(dead_code)] // consumer: the SCP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) fn scp_command(direction: ScpDirection, path: &[u8]) -> Vec<u8> {
    let quoted = shell_quotearg(path);
    let literal = direction.command();
    let mut out = Vec::with_capacity(literal.len() + quoted.len());
    out.extend_from_slice(literal);
    out.extend_from_slice(&quoted);
    out
}

/// Quote one path for the remote shell -- libssh2's `_libssh2_shell_quotearg`.
///
/// The remote side of an `exec` request is a SHELL, so the path is subject to
/// word splitting, glob expansion and variable substitution unless it is
/// quoted. libssh2 quotes it with a three-state scanner and this reproduces
/// that scanner:
///
/// * bytes in `[A-Za-z0-9]` and `/_.-` are SAFE and emitted bare;
/// * a single quote cannot appear inside single quotes, so it is emitted
///   inside DOUBLE quotes;
/// * every other byte is emitted inside SINGLE quotes, which suppresses every
///   shell expansion there is.
///
/// The scanner opens a quote only when it must and closes it only when it
/// must, so a run of like bytes shares one pair -- which is why the output for
/// a path of safe bytes is the path itself, byte for byte.
///
/// # Why the identity case is the one that matters
///
/// All 13 `scp` fixtures name paths built from `%LOGDIR` and a file name, whose
/// bytes are letters, digits, `/`, `-`, `.` and `_` -- every one of them safe.
/// So the observable behaviour under the corpus is that the path is passed
/// through unaltered, and that is what [`mod tests`](self) pins first. The
/// quoting paths are tested too, but they are what keeps a path containing a
/// space or a `$` from being reinterpreted rather than what the fixtures
/// exercise.
///
/// libssh2's own source is not in this tree -- specification 0.2.2 replaces
/// libssh2 outright -- so this is a reproduction of the algorithm rather than a
/// transcription of numbered lines, and it is documented as such.
#[allow(dead_code)] // consumer: the SCP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) fn shell_quotearg(path: &[u8]) -> Vec<u8> {
    /// Which quoting context the scanner is in.
    #[derive(Clone, Copy, Eq, PartialEq)]
    enum Quoting {
        /// Outside any quotes.
        None,
        /// Inside `'...'`.
        Single,
        /// Inside `"..."`.
        Double,
    }

    let mut out = Vec::with_capacity(path.len());
    let mut state = Quoting::None;

    for byte in path {
        let wanted = if byte.is_ascii_alphanumeric()
            || matches!(byte, b'/' | b'_' | b'.' | b'-')
        {
            Quoting::None
        } else if *byte == b'\'' {
            Quoting::Double
        } else {
            Quoting::Single
        };

        if wanted != state {
            // Close what is open, then open what is wanted. Both steps are
            // conditional, so a transition between the two quoted states emits
            // two delimiters and a transition out of or into `None` emits one.
            match state {
                Quoting::None => {}
                Quoting::Single => out.push(b'\''),
                Quoting::Double => out.push(b'"'),
            }
            match wanted {
                Quoting::None => {}
                Quoting::Single => out.push(b'\''),
                Quoting::Double => out.push(b'"'),
            }
            state = wanted;
        }
        out.push(*byte);
    }

    match state {
        Quoting::None => {}
        Quoting::Single => out.push(b'\''),
        Quoting::Double => out.push(b'"'),
    }
    out
}

// The channel this dialogue runs over -- the `libssh2_channel_*` subset that
// only SCP reaches

/// One channel running a remote `scp` command.
///
/// The successor of the `libssh2_channel_*` calls in `lib/vssh/libssh2.c` that
/// the SCP path makes, and of nothing else. `struct ssh_conn`'s `ssh_channel`
/// member (`lib/vssh/ssh.h`) is what an implementor stands in for.
///
/// # Why this is separate from [`SshTransport`](super::sftp::SshTransport)
///
/// Every libssh2 call the C makes is either a SESSION operation or a CHANNEL
/// operation, and the two have different lifetimes: a session spans the
/// connection and a channel spans one transfer. `protocols/sftp.rs` owns the
/// session seam because both schemes share it; this is the channel seam, and
/// only SCP reaches it, so it lives here. Nothing is duplicated -- there is no
/// handshake, no authentication and no disconnect on this trait.
///
/// # Object safety, and the `Send` bound
///
/// [`ScpConn`] holds a `Box<dyn ScpChannel>`, so the trait must be
/// dyn-compatible: hence [`SshFuture`] rather than `async fn`, which is the
/// same constraint `&dyn Protocol` places on [`Protocol`] itself. [`Send`] is
/// required because the multi handle drives transfers on a multi-thread runtime
/// and a [`ProtoFuture`] holding this across an await is only [`Send`] when it
/// is.
///
/// # Why every method takes the transfer context
///
/// The channel does NOT own a socket. Specification 0.4.1 puts the socket in
/// the connection-filter chain and `crate::conn` owns that, so an implementor
/// that has to move bytes must be handed the chain -- and it is handed the
/// whole [`TransferCtx`] because it also needs the injected clock. This is the
/// same seam shape `SshTransport` uses, for the same reason.
#[allow(dead_code)] // consumer: the SCP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) trait ScpChannel: fmt::Debug + Send {
    /// `libssh2_channel_read` (`lib/vssh/libssh2.c:3588`): read into `buf`.
    ///
    /// Answers how many bytes arrived, which is `0` at end of stream. The C's
    /// `scp_recv` calls `ssh_block2waitfor` around this and reports
    /// `CURLE_AGAIN` for `LIBSSH2_ERROR_EAGAIN`; the wrapper that preserves
    /// both is [`ScpConn::channel_read`].
    ///
    /// # Errors
    ///
    /// [`SshError`] as the channel reports it, including [`SshError::Again`].
    fn read<'a>(
        &'a mut self,
        ctx: &'a mut TransferCtx<'_>,
        buf: &'a mut [u8],
    ) -> SshFuture<'a, usize>;

    /// `libssh2_channel_write` (`lib/vssh/libssh2.c:3556`): write `data`.
    ///
    /// Answers how many bytes were accepted, which may be fewer than offered --
    /// the C propagates a short write through `*pnwritten` and lets the transfer
    /// loop re-offer the remainder.
    ///
    /// # Errors
    ///
    /// [`SshError`] as the channel reports it, including [`SshError::Again`].
    fn write<'a>(
        &'a mut self,
        ctx: &'a mut TransferCtx<'_>,
        data: &'a [u8],
    ) -> SshFuture<'a, usize>;

    /// `libssh2_channel_send_eof` (`lib/vssh/libssh2.c:2907`): no more data.
    ///
    /// `SSH_SCP_SEND_EOF`'s whole body. This is how an SCP upload signals
    /// completion: libssh2 sends no trailing zero byte after the payload, so
    /// EOF is the only terminator on the wire.
    ///
    /// # Errors
    ///
    /// [`SshError`] as the channel reports it. A failure is reported with
    /// `infof` and NOT propagated by the C, so the phase continues either way.
    fn send_eof<'a>(
        &'a mut self,
        ctx: &'a mut TransferCtx<'_>,
    ) -> SshFuture<'a, ()>;

    /// `libssh2_channel_wait_eof` (`:2926`): await the peer's EOF.
    ///
    /// # Errors
    ///
    /// [`SshError`] as the channel reports it; reported with `infof` and not
    /// propagated.
    fn wait_eof<'a>(
        &'a mut self,
        ctx: &'a mut TransferCtx<'_>,
    ) -> SshFuture<'a, ()>;

    /// `libssh2_channel_wait_closed` (`:2943`): await the close exchange.
    ///
    /// # Errors
    ///
    /// [`SshError`] as the channel reports it; reported with `infof` and not
    /// propagated.
    fn wait_close<'a>(
        &'a mut self,
        ctx: &'a mut TransferCtx<'_>,
    ) -> SshFuture<'a, ()>;

    /// `libssh2_channel_free` (`:2960`): release the channel.
    ///
    /// The C nulls `sshc->ssh_channel` afterwards regardless of the outcome,
    /// which [`ScpConn`] reproduces by dropping the box.
    ///
    /// # Errors
    ///
    /// [`SshError`] as the channel reports it. The C tests `rc < 0` rather than
    /// `rc` here -- a positive return is not a failure -- and reports with
    /// `infof` either way.
    fn free<'a>(
        &'a mut self,
        ctx: &'a mut TransferCtx<'_>,
    ) -> SshFuture<'a, ()>;

    /// `libssh2_session_block_directions`: which readiness this channel awaits.
    ///
    /// Feeds [`SshConn::block2waitfor`] and therefore [`ssh_pollset`], exactly
    /// as the session seam's own `block_directions` does.
    fn block_directions(&self) -> SshWait;

    /// The descriptor this channel is using, or `CURL_SOCKET_BAD`.
    ///
    /// Defaulted to "none" for the same reason the session seam defaults it:
    /// the descriptor belongs to the filter chain, and [`ssh_pollset`] asks the
    /// chain. The member exists because a channel that genuinely owned one
    /// would have nowhere else to report it.
    fn socket(&self) -> Socket {
        crate::conn::select::CURL_SOCKET_BAD
    }
}

/// The session operation SCP needs and SFTP does not: open a channel.
///
/// One method, because there is exactly one thing the SCP path asks of a
/// session that the shared seam does not already offer.
/// `libssh2_scp_recv2` and `libssh2_scp_send64` each begin by allocating a
/// channel and issuing an `exec` request, and that allocation is the only part
/// of them that needs the session rather than the channel.
///
/// # Why this is a trait and not a method on
/// [`SshTransport`](super::sftp::SshTransport)
///
/// Because `protocols/sftp.rs` owns that trait and this file contributes SCP.
/// Specification 0.4.1 gives `lib/vssh/` two targets, the sibling hosts what
/// both schemes share, and an SCP-only operation is not shared -- adding it
/// there would put an SCP concern in the shared core, which is the opposite of
/// the division the measured 14-of-17 overlap establishes.
#[allow(dead_code)] // consumer: the SCP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) trait ScpSession: fmt::Debug + Send {
    /// Open a channel and run `command` on it -- the `exec` request.
    ///
    /// `command` is what [`scp_command`] built: the literal plus the
    /// shell-quoted path, with no terminator.
    ///
    /// # Errors
    ///
    /// [`SshError`] as the session reports it. The C's two callers treat a
    /// failure identically: `failf(data, "%s", err_msg)`, move to
    /// `SSH_SCP_CHANNEL_FREE`, and map the code with
    /// `libssh2_session_error_to_CURLE`.
    fn open_scp<'a>(
        &'a mut self,
        ctx: &'a mut TransferCtx<'_>,
        command: &'a [u8],
    ) -> SshFuture<'a, Box<dyn ScpChannel>>;
}

/// An [`ScpChannel`] over any asynchronous byte stream.
///
/// This is the production implementor. `russh::Channel::into_stream` answers a
/// `russh::ChannelStream<russh::client::Msg>`, which implements
/// [`tokio::io::AsyncRead`] and [`tokio::io::AsyncWrite`] -- so an SSH channel
/// running a remote `scp` satisfies the bound, and so does the
/// `tokio::io::duplex` pair every test below drives. One implementor serves
/// both, which is what makes the dialogue's bytes assertable without a network
/// and therefore what makes the coverage gate of specification 0.8.4
/// reachable.
///
/// # What a byte stream can and cannot express
///
/// Read, write and EOF map directly. The three remaining operations do not have
/// distinct stream expressions and are mapped as follows, with the C's own
/// treatment of each recorded because it is what makes the mapping safe:
///
/// * `send_eof` is [`tokio::io::AsyncWriteExt::shutdown`], which closes the
///   write half -- the SSH `channel_eof` message on a `ChannelStream`;
/// * `wait_eof` reads until the read half reports end of stream, discarding
///   what arrives. The remote `scp` sends nothing after its final
///   acknowledgement, so this drains that acknowledgement and stops;
/// * `wait_close` is a no-op once EOF has been observed, because a stream has
///   no separate close exchange to await;
/// * `free` flushes and marks the channel spent.
///
/// The C reports a failure of all four with `infof` and never propagates one
/// (`lib/vssh/libssh2.c:2906-2974`), so a mapping that cannot fail where the C
/// could is not a loss of a diagnostic that changed an outcome.
#[derive(Debug)]
#[allow(dead_code)] // consumer: the SCP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) struct ScpStream<S> {
    /// The stream, which the transport below it has already connected.
    stream: S,
    /// Whether the write half has been shut down.
    ///
    /// Tracked so that a second `send_eof` is a no-op rather than an error,
    /// which is what the C's `if(sshc->ssh_channel)` guard achieves for a
    /// channel it has already finished with.
    eof_sent: bool,
    /// Whether the read half has reported end of stream.
    eof_seen: bool,
    /// Which direction the last operation was waiting on.
    ///
    /// A stream that returned `Poll::Pending` was waiting on the direction it
    /// was polled in, which is the whole of what
    /// `libssh2_session_block_directions` reports.
    waitfor: SshWait,
}

#[allow(dead_code)] // consumer: the SCP phase drivers, reached once easy/setopt.rs can supply SshSettings
impl<S> ScpStream<S> {
    /// A channel over `stream`.
    ///
    /// The stream must already be connected and already be running the remote
    /// command: opening the channel and issuing the `exec` request is
    /// [`ScpSession::open_scp`]'s job, and this type is what that method
    /// answers with.
    pub(crate) const fn new(stream: S) -> Self {
        Self {
            stream,
            eof_sent: false,
            eof_seen: false,
            waitfor: SshWait::NONE,
        }
    }

    /// Whether the read half has reported end of stream.
    ///
    /// Read by [`Self::wait_eof`] and by a test asserting the dialogue reached
    /// the end of the payload rather than stopping short.
    pub(crate) const fn eof_seen(&self) -> bool {
        self.eof_seen
    }
}

impl<S> ScpChannel for ScpStream<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + fmt::Debug,
{
    fn read<'a>(
        &'a mut self,
        ctx: &'a mut TransferCtx<'_>,
        buf: &'a mut [u8],
    ) -> SshFuture<'a, usize> {
        let _ = ctx;
        Box::pin(async move {
            use tokio::io::AsyncReadExt as _;
            match self.stream.read(buf).await {
                Ok(0) => {
                    self.eof_seen = true;
                    self.waitfor = SshWait::NONE;
                    Ok(0)
                }
                Ok(read) => {
                    self.waitfor = SshWait::NONE;
                    Ok(read)
                }
                Err(error) => {
                    self.waitfor = SshWait::RECV;
                    Err(io_to_ssh(&error))
                }
            }
        })
    }

    fn write<'a>(
        &'a mut self,
        ctx: &'a mut TransferCtx<'_>,
        data: &'a [u8],
    ) -> SshFuture<'a, usize> {
        let _ = ctx;
        Box::pin(async move {
            use tokio::io::AsyncWriteExt as _;
            match self.stream.write(data).await {
                Ok(written) => {
                    self.waitfor = SshWait::NONE;
                    Ok(written)
                }
                Err(error) => {
                    self.waitfor = SshWait::SEND;
                    // `LIBSSH2_ERROR_SOCKET_SEND` is the C's classification for
                    // a refused write, and it is the one that reaches
                    // `CURLE_SEND_ERROR` rather than `CURLE_SSH`.
                    Err(match io_to_ssh(&error) {
                        SshError::Other(_) => SshError::SocketSend,
                        classified => classified,
                    })
                }
            }
        })
    }

    fn send_eof<'a>(
        &'a mut self,
        ctx: &'a mut TransferCtx<'_>,
    ) -> SshFuture<'a, ()> {
        let _ = ctx;
        Box::pin(async move {
            if self.eof_sent {
                return Ok(());
            }
            use tokio::io::AsyncWriteExt as _;
            self.stream
                .flush()
                .await
                .map_err(|error| io_to_ssh(&error))?;
            self.stream
                .shutdown()
                .await
                .map_err(|error| io_to_ssh(&error))?;
            self.eof_sent = true;
            self.waitfor = SshWait::NONE;
            Ok(())
        })
    }

    fn wait_eof<'a>(
        &'a mut self,
        ctx: &'a mut TransferCtx<'_>,
    ) -> SshFuture<'a, ()> {
        let _ = ctx;
        Box::pin(async move {
            if self.eof_seen {
                return Ok(());
            }
            use tokio::io::AsyncReadExt as _;
            // Bounded by the control-line ceiling rather than unbounded: the
            // remote `scp` sends at most one acknowledgement after the payload,
            // so anything beyond this is a peer that is not going to stop and a
            // drain that would never finish.
            let mut scratch = [0_u8; SCP_MAX_LINE];
            loop {
                match self.stream.read(&mut scratch).await {
                    Ok(0) => {
                        self.eof_seen = true;
                        self.waitfor = SshWait::NONE;
                        return Ok(());
                    }
                    Ok(_) => {}
                    Err(error) => {
                        self.waitfor = SshWait::RECV;
                        return Err(io_to_ssh(&error));
                    }
                }
            }
        })
    }

    fn wait_close<'a>(
        &'a mut self,
        ctx: &'a mut TransferCtx<'_>,
    ) -> SshFuture<'a, ()> {
        let _ = ctx;
        Box::pin(async move {
            self.waitfor = SshWait::NONE;
            Ok(())
        })
    }

    fn free<'a>(
        &'a mut self,
        ctx: &'a mut TransferCtx<'_>,
    ) -> SshFuture<'a, ()> {
        let _ = ctx;
        Box::pin(async move {
            use tokio::io::AsyncWriteExt as _;
            // A flush rather than a shutdown: `libssh2_channel_free` releases
            // the channel without sending anything, and an upload that reached
            // here has already sent its EOF from `SSH_SCP_SEND_EOF`.
            let outcome =
                self.stream.flush().await.map_err(|error| io_to_ssh(&error));
            self.waitfor = SshWait::NONE;
            outcome
        })
    }

    fn block_directions(&self) -> SshWait {
        self.waitfor
    }
}

/// Classify a stream failure the way `libssh2_session_error_to_CURLE` does.
///
/// Three of the C's ten libssh2 numbers have an [`std::io::ErrorKind`]
/// counterpart and the rest do not, so those three are mapped and everything
/// else takes the C's own fall-through:
///
/// * [`std::io::ErrorKind::WouldBlock`] is `LIBSSH2_ERROR_EAGAIN`;
/// * [`std::io::ErrorKind::TimedOut`] is `LIBSSH2_ERROR_TIMEOUT`;
/// * [`std::io::ErrorKind::OutOfMemory`] is `LIBSSH2_ERROR_ALLOC`;
/// * anything else is [`SshError::Other`], which is [`CURLcode::Ssh`].
///
/// The message carries the operating system's text, which is what the C
/// interpolates from `libssh2_session_last_error`'s `err_msg`.
#[allow(dead_code)] // consumer: the SCP phase drivers, reached once easy/setopt.rs can supply SshSettings
fn io_to_ssh(error: &std::io::Error) -> SshError {
    match error.kind() {
        std::io::ErrorKind::WouldBlock => SshError::Again,
        std::io::ErrorKind::TimedOut => SshError::Timeout,
        std::io::ErrorKind::OutOfMemory => SshError::Alloc,
        _ => SshError::Other(error.to_string()),
    }
}

// The per-connection SCP state -- the slice of `struct ssh_conn` that
// `SshConn` deliberately does not carry

/// What an SCP operation answers instead of a reply.
///
/// Modelled on [`super::sftp::SftpFailure`], and for the same reason: the
/// mapping from a peer's refusal to a [`CURLcode`] happens at the CALL SITE in
/// the C, because each site builds its own `failf` text, so the failure has to
/// carry enough for any of them.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)] // consumer: the SCP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) enum ScpFailure {
    /// The peer sent an [`ScpMessage::Warning`] or [`ScpMessage::Error`].
    ///
    /// [`CURLcode::RemoteFileNotFound`], through
    /// [`SshError::ScpProtocol`]'s own map -- which the C comments as *"the
    /// error returned by libssh2_scp_recv2 on unknown file"*
    /// (`lib/vssh/libssh2.c:197-201`). That is exactly the code
    /// `tests/data/test605` expects for `scp://.../not-a-valid-file-moooo`.
    ///
    /// # One divergence in a diagnostic, stated rather than hidden
    ///
    /// The C interpolates `libssh2_session_last_error`'s `err_msg` here, which
    /// is libssh2's OWN description of the failure and not the remote's text --
    /// libssh2 frames the message, classifies it as
    /// `LIBSSH2_ERROR_SCP_PROTOCOL` and does not forward its content. libssh2's
    /// source is not in this tree, so the exact string it would have produced
    /// is not reproducible. This carries the REMOTE's text instead, which is
    /// strictly more informative and reports the same code. No fixture is
    /// affected: none of the 13 `scp` fixtures carries a `<stderr>` block, so
    /// the corpus compares the code and not the sentence.
    Remote(Vec<u8>),
    /// The transport or the framing failed underneath the dialogue.
    Transport(SshError),
    /// A control message arrived that the protocol does not define.
    ///
    /// A `D` or `E` header, a header with a malformed mode or size, an
    /// unrecognised prefix byte, or a control line longer than
    /// [`SCP_MAX_LINE`]. libssh2 reports every one of these as
    /// `LIBSSH2_ERROR_SCP_PROTOCOL`, so this answers the same code.
    Malformed,
}

#[allow(dead_code)] // consumer: the SCP phase drivers, reached once easy/setopt.rs can supply SshSettings
impl ScpFailure {
    /// The [`CURLcode`] this failure reports.
    ///
    /// [`Self::Remote`] and [`Self::Malformed`] both route through
    /// [`SshError::ScpProtocol`] rather than naming
    /// [`CURLcode::RemoteFileNotFound`] directly, so that the map stays in the
    /// one function that transcribes `libssh2_session_error_to_CURLE`.
    pub(crate) fn to_curlcode(&self) -> CURLcode {
        match self {
            Self::Remote(_) | Self::Malformed => {
                SshError::ScpProtocol.to_curlcode()
            }
            Self::Transport(error) => error.to_curlcode(),
        }
    }

    /// The text a `failf` line interpolates for this failure.
    ///
    /// The remote's own sentence for [`Self::Remote`], decoded lossily because
    /// a remote `scp` writes whatever its locale produces and a diagnostic must
    /// not fail on it.
    pub(crate) fn message(&self) -> String {
        match self {
            Self::Remote(text) => String::from_utf8_lossy(text).into_owned(),
            Self::Transport(error) => error.message().to_owned(),
            Self::Malformed => SshError::ScpProtocol.message().to_owned(),
        }
    }

    /// Whether this failure came from the transport rather than the protocol.
    ///
    /// Read by `SSH_SCP_UPLOAD_INIT`, which remaps [`CURLcode::Ssh`] and
    /// [`CURLcode::RemoteFileNotFound`] to [`CURLcode::UploadFailed`] and needs
    /// to apply that remap to both sources of either code.
    pub(crate) const fn is_transport(&self) -> bool {
        matches!(self, Self::Transport(_))
    }
}

/// What an SCP operation answers: either its result, or an [`ScpFailure`].
#[allow(dead_code)] // consumer: the SCP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) type ScpResult<T> = Result<T, ScpFailure>;

/// `struct ssh_conn`'s SCP members -- the channel and its framing buffer.
///
/// `SshConn` reproduces `struct ssh_conn` (`lib/vssh/ssh.h:145-222`) field for
/// field EXCEPT for `ssh_channel`, which only the SCP path uses. This holds
/// that member and the buffer libssh2 keeps privately for the same purpose, so
/// that the two modules' state stays disjoint and neither has to reach into the
/// other.
///
/// # Why the framing buffer is state rather than a local
///
/// The dialogue reads control LINES from a stream that also carries the
/// PAYLOAD, and a read can return bytes belonging to both. libssh2 has the same
/// problem and solves it with an internal buffer; [`Self::pending`] is that
/// buffer. It is state because the surplus from framing the header is the first
/// of the payload, and the payload is read by a later state.
#[allow(dead_code)] // consumer: the SCP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) struct ScpConn {
    /// The session, injected. Opens channels and does nothing else.
    session: Box<dyn ScpSession>,
    /// `sshc->ssh_channel`: the channel running the remote `scp`.
    ///
    /// [`None`] before `SSH_SCP_UPLOAD_INIT` or `SSH_SCP_DOWNLOAD_INIT` has
    /// opened one and after `SSH_SCP_CHANNEL_FREE` has released one, which is
    /// exactly the C's `if(sshc->ssh_channel)` guard on all four of the
    /// SCP-DONE states.
    channel: Option<Box<dyn ScpChannel>>,
    /// The `C` header this transfer sent or received.
    ///
    /// The successor of the `libssh2_struct_stat` that `libssh2_scp_recv2`
    /// fills and of the arguments `libssh2_scp_send64` is given. Retained after
    /// the dialogue so that a test -- and eventually the transfer core -- can
    /// read the size the peer announced.
    header: Option<ScpFileHeader>,
    /// Bytes read from the channel that framing has not consumed.
    ///
    /// See the type documentation. Drained by [`Self::take_pending`] before the
    /// payload reader touches the channel.
    pending: Vec<u8>,
    /// Payload bytes still owed by the side named in [`Self::header`].
    ///
    /// The terminal zero-byte status follows exactly this many payload bytes.
    /// Tracking it is what keeps that status byte out of a download body and
    /// what lets an upload emit its status immediately after the final byte.
    payload_remaining: Option<u64>,
    /// Whether the terminal status/acknowledgement exchange has completed.
    payload_complete: bool,
}

impl fmt::Debug for ScpConn {
    /// Progress and buffer occupancy. No payload and no path.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScpConn")
            .field("channel_open", &self.channel.is_some())
            .field("header", &self.header)
            .field("pending", &self.pending.len())
            .field("payload_remaining", &self.payload_remaining)
            .field("payload_complete", &self.payload_complete)
            .finish()
    }
}

#[allow(dead_code)] // consumer: the SCP phase drivers, reached once easy/setopt.rs can supply SshSettings
impl ScpConn {
    /// A connection with no channel yet, over `session`.
    ///
    /// `ssh_setup_connection` (`lib/vssh/libssh2.c:3167-3191`) allocates the
    /// C's structures with `calloc`, so `ssh_channel` starts NULL. Reproduced.
    pub(crate) fn new(session: Box<dyn ScpSession>) -> Self {
        Self {
            session,
            channel: None,
            header: None,
            pending: Vec::new(),
            payload_remaining: None,
            payload_complete: false,
        }
    }

    /// `if(sshc->ssh_channel)` -- whether a channel is open.
    pub(crate) const fn has_channel(&self) -> bool {
        self.channel.is_some()
    }

    /// The header this transfer sent or received, if the dialogue reached one.
    pub(crate) const fn header(&self) -> Option<&ScpFileHeader> {
        self.header.as_ref()
    }

    /// How many framing bytes are held back for the payload reader.
    pub(crate) fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Take the held-back bytes, leaving the buffer empty.
    ///
    /// Called once before the payload is read, because those bytes ARE the
    /// first of the payload -- the header's newline was the last byte framing
    /// needed and everything after it belongs to the transfer.
    pub(crate) fn take_pending(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.pending)
    }

    /// Open a channel and run the remote `scp` command on it.
    ///
    /// The first half of `libssh2_scp_recv2` and `libssh2_scp_send64`: allocate
    /// a channel, issue the `exec` request. The second half is the dialogue,
    /// which the two `*_init` states perform.
    ///
    /// # Errors
    ///
    /// [`ScpFailure::Transport`] as the session reports it.
    pub(crate) async fn open(
        &mut self,
        ctx: &mut TransferCtx<'_>,
        direction: ScpDirection,
        path: &[u8],
    ) -> ScpResult<()> {
        let command = scp_command(direction, path);
        let channel = self
            .session
            .open_scp(ctx, &command)
            .await
            .map_err(ScpFailure::Transport)?;
        self.channel = Some(channel);
        self.pending.clear();
        self.header = None;
        self.payload_remaining = None;
        self.payload_complete = false;
        Ok(())
    }

    /// The open channel, or [`ScpFailure::Transport`] with
    /// [`SshError::SocketNone`].
    ///
    /// The C's states guard on `if(sshc->ssh_channel)` and skip themselves when
    /// there is none; the states that CANNOT skip -- the two `*_init` states,
    /// which have just opened one -- reach it unconditionally. This is for the
    /// second group, and the code it reports is the one
    /// `libssh2_session_error_to_CURLE` gives `LIBSSH2_ERROR_SOCKET_NONE`:
    /// [`CURLcode::CouldntConnect`].
    fn channel_mut(&mut self) -> ScpResult<&mut Box<dyn ScpChannel>> {
        self.channel
            .as_mut()
            .ok_or(ScpFailure::Transport(SshError::SocketNone))
    }

    /// Move one read's worth of bytes from the channel into [`Self::pending`].
    ///
    /// Answers how many arrived, `0` at end of stream. The ceiling is
    /// [`SCP_MAX_LINE`] because this is the FRAMING reader: it exists to
    /// assemble a control line, and reading further ahead than a line's worth
    /// would hold back more of the payload than necessary.
    ///
    /// # Errors
    ///
    /// [`ScpFailure::Transport`], and [`ScpFailure::Malformed`] when the buffer
    /// has already grown past a line's worth without a terminator.
    async fn fill(&mut self, ctx: &mut TransferCtx<'_>) -> ScpResult<usize> {
        if self.pending.len() >= SCP_MAX_LINE {
            return Err(ScpFailure::Malformed);
        }
        let mut scratch = [0_u8; 256];
        let channel = self.channel_mut()?;
        let read = channel
            .read(ctx, &mut scratch)
            .await
            .map_err(ScpFailure::Transport)?;
        if let Some(fresh) = scratch.get(..read) {
            self.pending.extend_from_slice(fresh);
        }
        Ok(read)
    }

    /// Frame one control message: a lone [`SCP_ACK`], or a line.
    ///
    /// The framing rule is the protocol's and is not uniform, which is the
    /// detail worth stating: an acknowledgement is ONE byte with no terminator,
    /// while a warning, an error and a header are all newline-terminated. So
    /// the first byte decides how many more to read, and a reader that looked
    /// for a newline unconditionally would block forever on a successful
    /// transfer.
    ///
    /// # Errors
    ///
    /// [`ScpFailure::Transport`] from the channel,
    /// [`ScpFailure::Transport`] with [`SshError::ScpProtocol`] at an
    /// unexpected end of stream, and [`ScpFailure::Malformed`] for an
    /// over-long line.
    async fn read_control(
        &mut self,
        ctx: &mut TransferCtx<'_>,
    ) -> ScpResult<Vec<u8>> {
        // One byte first, because it decides the frame's shape.
        while self.pending.is_empty() {
            if self.fill(ctx).await? == 0 {
                return Err(ScpFailure::Transport(SshError::ScpProtocol));
            }
        }
        if self.pending.first() == Some(&SCP_ACK) {
            return Ok(vec![self.pending.remove(0)]);
        }

        loop {
            if let Some(at) =
                self.pending.iter().position(|byte| *byte == b'\n')
            {
                // Split at the terminator INCLUSIVE: the delimiter belongs to
                // the frame and `ScpMessage::parse` strips it. Everything after
                // it is the next frame's, or the payload's.
                let rest = self.pending.split_off(at + 1);
                let line = core::mem::replace(&mut self.pending, rest);
                return Ok(line);
            }
            if self.fill(ctx).await? == 0 {
                return Err(ScpFailure::Transport(SshError::ScpProtocol));
            }
        }
    }

    /// Read one control message and classify it.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::read_control`] reports, and
    /// [`ScpFailure::Malformed`] for a prefix [`ScpMessage::parse`] refuses.
    pub(crate) async fn read_reply(
        &mut self,
        ctx: &mut TransferCtx<'_>,
    ) -> ScpResult<ScpMessage> {
        let line = self.read_control(ctx).await?;
        ScpMessage::parse(&line).map_err(|_| ScpFailure::Malformed)
    }

    /// Read one message and require it to be an acknowledgement.
    ///
    /// The sink path does this twice: once for the peer's readiness after the
    /// `exec` request, and once for its acceptance of the header. Either can
    /// answer an error message instead -- which is precisely how
    /// `tests/data/test623` produces `errorcode 25`, the remote `scp` refusing
    /// to create a file in a directory that does not exist.
    ///
    /// # Errors
    ///
    /// [`ScpFailure::Remote`] carrying the peer's text when it sent one, and
    /// whatever [`Self::read_reply`] reports otherwise. A WARNING is treated as
    /// a refusal here rather than survived: the peer owed an acknowledgement
    /// and did not send one, so there is nothing to continue with.
    pub(crate) async fn expect_ack(
        &mut self,
        ctx: &mut TransferCtx<'_>,
    ) -> ScpResult<()> {
        match self.read_reply(ctx).await? {
            ScpMessage::Ack => Ok(()),
            other => Err(ScpFailure::Remote(other.text().to_vec())),
        }
    }

    /// Write one [`SCP_ACK`] byte.
    ///
    /// The source path sends this twice: once to start the transfer and once to
    /// accept the header.
    ///
    /// # Errors
    ///
    /// [`ScpFailure::Transport`] as the channel reports it.
    pub(crate) async fn send_ack(
        &mut self,
        ctx: &mut TransferCtx<'_>,
    ) -> ScpResult<()> {
        self.write_all(ctx, &ScpMessage::Ack.encode()).await
    }

    /// Write every byte of `data`, re-offering a short write.
    ///
    /// # Errors
    ///
    /// [`ScpFailure::Transport`], including
    /// [`ScpFailure::Transport`] with [`SshError::SocketSend`] when the channel
    /// accepts nothing at all -- an infinite loop is the alternative, and the C
    /// classifies a refused write as `LIBSSH2_ERROR_SOCKET_SEND`.
    pub(crate) async fn write_all(
        &mut self,
        ctx: &mut TransferCtx<'_>,
        data: &[u8],
    ) -> ScpResult<()> {
        let channel = self.channel_mut()?;
        let mut offset = 0_usize;
        while offset < data.len() {
            let chunk = data.get(offset..).unwrap_or(&[]);
            let written = channel
                .write(ctx, chunk)
                .await
                .map_err(ScpFailure::Transport)?;
            if written == 0 {
                return Err(ScpFailure::Transport(SshError::SocketSend));
            }
            offset = offset.saturating_add(written);
        }
        Ok(())
    }

    /// The source dialogue's header read, `T` headers accepted on the way.
    ///
    /// Three forms may arrive and all three are handled:
    ///
    /// * a `C` header, which is the answer;
    /// * a `T` header, which libssh2 acknowledges and then reads the next
    ///   header. curl never SENDS one -- it passes `0, 0` for mtime and atime
    ///   (`lib/vssh/libssh2.c:2387-2389`) -- but a remote `scp` may send one
    ///   unprompted, so it is accepted;
    /// * a warning or an error, which is the peer refusing.
    ///
    /// A `D` or `E` header is [`ScpFailure::Malformed`]: recursive SCP is
    /// `scp -r` and curl never requests it, so those prefixes can only mean the
    /// peer is answering a request curl did not make.
    ///
    /// Exactly one `T` header is accepted before a `C`. A peer that sent two in
    /// a row would be looping, and bounding it here keeps the state machine's
    /// progress guarantee local to the reader rather than resting on the
    /// driver's iteration limit.
    ///
    /// # Errors
    ///
    /// [`ScpFailure::Remote`] for a refusal, [`ScpFailure::Malformed`] for a
    /// prefix the protocol does not define here, and
    /// [`ScpFailure::Transport`] from the channel.
    pub(crate) async fn read_header(
        &mut self,
        ctx: &mut TransferCtx<'_>,
    ) -> ScpResult<ScpFileHeader> {
        let mut timestamp_seen = false;
        loop {
            let line = self.read_control(ctx).await?;
            match line.first() {
                Some(&SCP_FILE) => {
                    let header = ScpFileHeader::parse(&line)
                        .map_err(|_| ScpFailure::Malformed)?;
                    self.payload_remaining = Some(header.size);
                    self.payload_complete = false;
                    self.header = Some(header.clone());
                    return Ok(header);
                }
                Some(&SCP_TIMESTAMP) if !timestamp_seen => {
                    timestamp_seen = true;
                    // libssh2 acknowledges a `T` header and reads on. The
                    // contents are discarded: curl reads `st_mtime` from the
                    // `struct stat` libssh2 fills and `SSH_SCP_DOWNLOAD_INIT`
                    // never touches it, so there is nothing here to keep.
                    self.send_ack(ctx).await?;
                }
                Some(&SCP_WARNING) | Some(&SCP_ERROR) => {
                    let message = ScpMessage::parse(&line)
                        .map_err(|_| ScpFailure::Malformed)?;
                    return Err(ScpFailure::Remote(message.text().to_vec()));
                }
                _ => return Err(ScpFailure::Malformed),
            }
        }
    }

    /// The sink dialogue: wait for readiness, send the header, wait for
    /// acceptance.
    ///
    /// `libssh2_scp_send64`'s body, in the order it performs it. The order is
    /// observable and is not the obvious one: the peer acknowledges FIRST,
    /// before it has been told anything, because `scp -t` announces its
    /// readiness as soon as it starts.
    ///
    /// # Errors
    ///
    /// [`ScpFailure::Remote`] when the peer refuses at either point, and
    /// [`ScpFailure::Transport`] from the channel.
    pub(crate) async fn send_header(
        &mut self,
        ctx: &mut TransferCtx<'_>,
        header: ScpFileHeader,
    ) -> ScpResult<()> {
        self.expect_ack(ctx).await?;
        let encoded = header.encode();
        self.write_all(ctx, &encoded).await?;
        self.expect_ack(ctx).await?;
        self.payload_remaining = Some(header.size);
        self.payload_complete = false;
        self.header = Some(header);
        Ok(())
    }

    /// `libssh2_channel_send_eof`, then the channel's own bookkeeping.
    ///
    /// Answers the `infof` line the C emits on failure, or [`None`]. Returning
    /// the line rather than propagating a failure is what the C does:
    /// `SSH_SCP_SEND_EOF` logs and moves on regardless
    /// (`lib/vssh/libssh2.c:2906-2922`).
    pub(crate) async fn send_eof(
        &mut self,
        ctx: &mut TransferCtx<'_>,
    ) -> Option<String> {
        let channel = self.channel.as_mut()?;
        match channel.send_eof(ctx).await {
            Ok(()) => None,
            // `infof(data, "Failed to send libssh2 channel EOF: %d %s", rc,
            // err_msg)`. The `%d` is libssh2's return code and has no successor
            // -- `russh` reports no such integer -- so it is dropped and the
            // message is kept, which is the treatment `protocols/sftp.rs`
            // already gives the identically shaped
            // *"Failed to close libssh2 file: %d %s"*.
            Err(error) => Some(format!(
                "Failed to send libssh2 channel EOF: {}",
                error.message()
            )),
        }
    }

    /// `libssh2_channel_wait_eof`.
    ///
    /// Answers the `infof` line on failure, or [`None`].
    pub(crate) async fn wait_eof(
        &mut self,
        ctx: &mut TransferCtx<'_>,
    ) -> Option<String> {
        let channel = self.channel.as_mut()?;
        match channel.wait_eof(ctx).await {
            Ok(()) => None,
            // `infof(data, "Failed to get channel EOF: %d %s", rc, err_msg)`.
            Err(error) => {
                Some(format!("Failed to get channel EOF: {}", error.message()))
            }
        }
    }

    /// `libssh2_channel_wait_closed`.
    ///
    /// Answers the `infof` line on failure, or [`None`].
    pub(crate) async fn wait_close(
        &mut self,
        ctx: &mut TransferCtx<'_>,
    ) -> Option<String> {
        let channel = self.channel.as_mut()?;
        match channel.wait_close(ctx).await {
            Ok(()) => None,
            // `infof(data, "Channel failed to close: %d %s", rc, err_msg)`.
            Err(error) => {
                Some(format!("Channel failed to close: {}", error.message()))
            }
        }
    }

    /// `libssh2_channel_free`, then `sshc->ssh_channel = NULL`.
    ///
    /// Answers the `infof` line on failure, or [`None`]. The channel is
    /// released either way, which is the C's own order: it nulls the member
    /// after the call regardless of what the call reported.
    pub(crate) async fn free_channel(
        &mut self,
        ctx: &mut TransferCtx<'_>,
    ) -> Option<String> {
        let mut channel = self.channel.take()?;
        let line = match channel.free(ctx).await {
            Ok(()) => None,
            // `infof(data, "Failed to free libssh2 scp subsystem: %d %s", rc,
            // err_msg)` -- and note the C tests `rc < 0` rather than `rc` at
            // this one site, so a positive return is not a failure. The seam
            // answers `Result`, which has no positive-but-not-negative case, so
            // the distinction is preserved by construction.
            Err(error) => Some(format!(
                "Failed to free libssh2 scp subsystem: {}",
                error.message()
            )),
        };
        drop(channel);
        self.pending.clear();
        self.payload_remaining = None;
        self.payload_complete = false;
        line
    }

    /// Limit one payload operation to the bytes the header announced.
    ///
    /// A control byte follows the payload on the same stream. Never allowing a
    /// payload read past this limit is what prevents that byte from being
    /// delivered to the client as file data.
    fn payload_limit(&self, offered: usize) -> usize {
        self.payload_remaining.map_or(offered, |remaining| {
            usize::try_from(remaining)
                .unwrap_or(usize::MAX)
                .min(offered)
        })
    }

    /// Account for bytes successfully transferred.
    fn consume_payload(&mut self, amount: usize) {
        if let Some(remaining) = self.payload_remaining.as_mut() {
            *remaining = remaining
                .saturating_sub(u64::try_from(amount).unwrap_or(u64::MAX));
        }
    }

    /// Complete the source dialogue after the announced download bytes.
    ///
    /// The source sends one status byte after the payload. A zero is success;
    /// warnings and errors use the two text forms [`ScpMessage`] models. The
    /// sink acknowledges success with one final zero.
    async fn finish_download(
        &mut self,
        ctx: &mut TransferCtx<'_>,
    ) -> ScpResult<()> {
        if self.payload_complete {
            return Ok(());
        }
        if self.payload_remaining != Some(0) {
            return Err(ScpFailure::Malformed);
        }
        self.expect_ack(ctx).await?;
        self.send_ack(ctx).await?;
        self.payload_complete = true;
        Ok(())
    }

    /// Complete the sink dialogue after the announced upload bytes.
    ///
    /// The sender emits one zero status byte and waits for the sink's final
    /// acknowledgement. libssh2 hides this exchange inside its SCP channel;
    /// the russh stream does not, so it is explicit here.
    async fn finish_upload(
        &mut self,
        ctx: &mut TransferCtx<'_>,
    ) -> ScpResult<()> {
        if self.payload_complete {
            return Ok(());
        }
        if self.payload_remaining != Some(0) {
            return Err(ScpFailure::Malformed);
        }
        self.send_ack(ctx).await?;
        self.expect_ack(ctx).await?;
        self.payload_complete = true;
        Ok(())
    }

    /// `scp_recv` (`lib/vssh/libssh2.c:3571-3597`): one payload read.
    ///
    /// The held-back framing bytes come out FIRST, because they are the first
    /// of the payload -- see the type documentation. Only when they are gone
    /// does this touch the channel.
    ///
    /// `sshc` is taken because the C calls `ssh_block2waitfor` here and that
    /// records the direction on the SESSION, not on the channel:
    /// `libssh2_session_block_directions(sshc->ssh_session)`. Keeping the call
    /// on [`SshConn`] is what preserves that, and the C's comment says why it is
    /// unconditional -- *"Make sure to call this function in all cases so that
    /// when it does not return EAGAIN we can restore the default wait bits."*
    ///
    /// # Errors
    ///
    /// [`ScpFailure::Transport`] as the channel reports it, including
    /// [`SshError::Again`], which the C surfaces as [`CURLcode::Again`].
    pub(crate) async fn recv(
        &mut self,
        sshc: &mut SshConn,
        ctx: &mut TransferCtx<'_>,
        buf: &mut [u8],
    ) -> ScpResult<usize> {
        if self.payload_complete {
            sshc.block2waitfor(false);
            return Ok(0);
        }
        if self.payload_remaining == Some(0) {
            let completion = self.finish_download(ctx).await;
            sshc.block2waitfor(matches!(
                &completion,
                Err(ScpFailure::Transport(SshError::Again))
            ));
            completion?;
            return Ok(0);
        }

        let limit = self.payload_limit(buf.len());
        if limit == 0 {
            sshc.block2waitfor(false);
            return Ok(0);
        }
        if !self.pending.is_empty() {
            let take = self.pending.len().min(limit);
            let head = self.pending.drain(..take);
            for (slot, byte) in buf.iter_mut().zip(head) {
                *slot = byte;
            }
            self.consume_payload(take);
            let completion = if self.payload_remaining == Some(0) {
                self.finish_download(ctx).await
            } else {
                Ok(())
            };
            sshc.block2waitfor(matches!(
                &completion,
                Err(ScpFailure::Transport(SshError::Again))
            ));
            completion?;
            return Ok(take);
        }
        let outcome = {
            let channel = self.channel_mut()?;
            channel.read(ctx, &mut buf[..limit]).await
        };
        let blocked = matches!(outcome, Err(SshError::Again));
        sshc.block2waitfor(blocked);
        let read = outcome.map_err(ScpFailure::Transport)?;
        self.consume_payload(read);
        if self.payload_remaining == Some(0) {
            let completion = self.finish_download(ctx).await;
            sshc.block2waitfor(matches!(
                &completion,
                Err(ScpFailure::Transport(SshError::Again))
            ));
            completion?;
        }
        Ok(read)
    }

    /// `scp_send` (`lib/vssh/libssh2.c:3539-3569`): one payload write.
    ///
    /// A SHORT write is propagated rather than looped, which is the C's
    /// behaviour and not an accident: `*pnwritten` carries however much
    /// `libssh2_channel_write` accepted and the transfer loop re-offers the
    /// remainder. [`Self::write_all`] is the looping variant and is used for
    /// CONTROL bytes, where there is no transfer loop to re-offer them.
    ///
    /// # Errors
    ///
    /// [`ScpFailure::Transport`] as the channel reports it.
    pub(crate) async fn send(
        &mut self,
        sshc: &mut SshConn,
        ctx: &mut TransferCtx<'_>,
        data: &[u8],
    ) -> ScpResult<usize> {
        if self.payload_complete {
            sshc.block2waitfor(false);
            return Ok(0);
        }
        if self.payload_remaining == Some(0) {
            let completion = self.finish_upload(ctx).await;
            sshc.block2waitfor(matches!(
                &completion,
                Err(ScpFailure::Transport(SshError::Again))
            ));
            completion?;
            return Ok(0);
        }

        let limit = self.payload_limit(data.len());
        if limit == 0 {
            sshc.block2waitfor(false);
            return Ok(0);
        }
        let outcome = {
            let channel = self.channel_mut()?;
            channel.write(ctx, &data[..limit]).await
        };
        let blocked = matches!(outcome, Err(SshError::Again));
        sshc.block2waitfor(blocked);
        let written = outcome.map_err(ScpFailure::Transport)?;
        self.consume_payload(written);
        if self.payload_remaining == Some(0) {
            let completion = self.finish_upload(ctx).await;
            sshc.block2waitfor(matches!(
                &completion,
                Err(ScpFailure::Transport(SshError::Again))
            ));
            completion?;
        }
        Ok(written)
    }

    /// Which readiness the channel is waiting for, or none when there is no
    /// channel.
    ///
    /// Feeds the `waitfor` argument of [`ssh_pollset`].
    pub(crate) fn block_directions(&self) -> SshWait {
        self.channel
            .as_ref()
            .map_or(SshWait::NONE, |channel| channel.block_directions())
    }
}

// The SCP-DO, SCP-DONE and SCP-DISCONNECT phases

/// The text `SSH_SCP_TRANS_INIT` reports when an upload has no known size.
///
/// `failf(data, "SCP requires a known file size for upload")`
/// (`lib/vssh/libssh2.c:2877`), verbatim. This is SCP's defining limitation
/// against SFTP: the `C` header carries the length and there is no way to write
/// "unknown" into it, so a stream of unknown size cannot be sent at all.
///
/// `#[rustfmt::skip]` because the sentence reaches a user.
#[rustfmt::skip]
#[allow(dead_code)] // consumer: the SCP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) const SCP_UPLOAD_NEEDS_SIZE: &str =
    "SCP requires a known file size for upload";

/// The trace line `SSH_SCP_CHANNEL_FREE` emits when the phase completes.
///
/// `CURL_TRC_SSH(data, "SCP DONE phase complete")`
/// (`lib/vssh/libssh2.c:2974`), verbatim, emitted through
/// [`TraceFeature::Ssh`] -- whose own name string is `"SSH"`, consumed from
/// `crate::trace` rather than spelled here.
///
/// `#[rustfmt::skip]` because the sentence reaches a trace log.
#[rustfmt::skip]
#[allow(dead_code)] // consumer: the SCP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) const SCP_DONE_PHASE_COMPLETE: &str = "SCP DONE phase complete";

/// The trace line `scp_perform` emits when it enters the DO phase.
///
/// `CURL_TRC_SSH(data, "DO phase starts")` (`lib/vssh/libssh2.c:3446`).
///
/// `#[rustfmt::skip]` because the sentence reaches a trace log.
#[rustfmt::skip]
#[allow(dead_code)] // consumer: the SCP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) const SCP_DO_PHASE_STARTS: &str = "DO phase starts";

/// The trace line `scp_perform` and `scp_doing` both emit on completion.
///
/// `CURL_TRC_SSH(data, "DO phase is complete")` (`:3461` and `:3475`). Both
/// spell it identically, which is why one constant serves both.
///
/// `#[rustfmt::skip]` because the sentence reaches a trace log.
#[rustfmt::skip]
#[allow(dead_code)] // consumer: the SCP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) const SCP_DO_PHASE_COMPLETE: &str = "DO phase is complete";

/// How many state transitions one SCP phase may take.
///
/// The C has no bound. This one is far above the longest real phase -- SCP-DO
/// is at most three states and SCP-DONE at most five -- and exists so that a
/// defect in a transition produces a diagnosable failure instead of a hang. The
/// same reasoning and the same role as [`ssh_run_phase`]'s own `limit`, set much
/// lower because SCP's phases are much shorter than a directory listing.
#[allow(dead_code)] // consumer: the SCP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) const SCP_PHASE_LIMIT: usize = 64;

/// `SSH_SCP_TRANS_INIT` (`lib/vssh/libssh2.c:2867-2887`): which transfer this
/// is.
///
/// Two-way rather than SFTP's three-way, and the missing third way is the point:
/// SFTP tests the path's last byte for `/` and lists a directory, and SCP has no
/// listing to do. So a trailing slash on an `scp://` URL is not special -- the
/// remote `scp -f` is handed the path as given.
///
/// The upload branch refuses an unknown size, and the destination it refuses TO
/// is `SSH_SCP_CHANNEL_FREE` rather than `SSH_STOP`. That looks odd and is
/// correct: the C moves there and reports, its caller's
/// `do { } while(!result && ...)` loop stops on the non-zero result, and the
/// state is simply where the machine is parked when the DO phase reports its
/// failure. `scp_done` then declines to run anything because `status` is
/// non-zero, so the state is never executed.
///
/// # Errors
///
/// [`CURLcode::UploadFailed`] with [`SCP_UPLOAD_NEEDS_SIZE`] when
/// `CURLOPT_UPLOAD` is set and `CURLOPT_INFILESIZE` is negative.
#[allow(dead_code)] // consumer: the SCP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) fn scp_trans_init(
    upload: bool,
    infilesize: i64,
) -> Result<SshState, (SshState, CURLcode, &'static str)> {
    if upload {
        if infilesize < 0 {
            return Err((
                SshState::ScpChannelFree,
                CURLcode::UploadFailed,
                SCP_UPLOAD_NEEDS_SIZE,
            ));
        }
        return Ok(SshState::ScpUploadInit);
    }
    Ok(SshState::ScpDownloadInit)
}

/// `SSH_SCP_DONE` (`lib/vssh/libssh2.c:2899-2904`): where the DONE phase goes
/// first.
///
/// An upload has an EOF to send and a download does not, so the two enter the
/// phase at different states and converge on `SSH_SCP_CHANNEL_FREE`.
#[allow(dead_code)] // consumer: the SCP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) const fn scp_done_next(upload: bool) -> SshState {
    if upload {
        SshState::ScpSendEof
    } else {
        SshState::ScpChannelFree
    }
}

/// `scp_done` (`lib/vssh/libssh2.c:3527-3537`): the `done` vtable slot's
/// decision.
///
/// The first of the three slots where SCP and SFTP differ, and the comparison
/// with [`super::sftp::sftp_done`] shows how little of the difference is
/// structural: SFTP chooses between a postquote round and a plain close, and SCP
/// has no quote phase at all, so its whole decision is *"enter `SSH_SCP_DONE` if
/// the transfer succeeded"*.
///
/// `premature` is taken and NOT read, which is the C's own `(void)premature;`
/// (`:3530`). It is in the signature because the vtable slot has it, and SFTP
/// does read it. Stated rather than dropped so that a reader looking for SCP's
/// premature handling finds the answer instead of concluding it was lost.
///
/// [`None`] means no transition: `if(sshc && !status)` guards the whole body, so
/// a failed transfer runs no part of the DONE phase.
pub(crate) const fn scp_done(
    status: CURLcode,
    premature: bool,
) -> Option<SshState> {
    let _ = premature;
    if matches!(status, CURLcode::Ok) {
        Some(SshState::ScpDone)
    } else {
        None
    }
}

/// `scp_disconnect` (`lib/vssh/libssh2.c:3483-3499`): where SCP's teardown
/// begins.
///
/// `SSH_SESSION_DISCONNECT`, which `lib/vssh/ssh.h:116` annotates *"First state
/// in SCP-DISCONNECT"*. Derived from [`disconnect_entry_state`] rather than
/// written as a constant, so that the seam between the two schemes' disconnect
/// entry points is stated once, in the module that owns both of its outcomes.
///
/// The third of the three differing slots. SFTP enters at
/// `SSH_SFTP_SHUTDOWN` -- it has a subsystem to close first -- and SCP has no
/// subsystem, so it starts one state later. Both converge on
/// `SSH_SESSION_FREE`, *"Last state in SCP/SFTP-DISCONNECT"*, which is why
/// neither state is implemented here: [`ssh_run_phase`] with
/// [`SshPhase::SessionTeardown`] serves both.
#[allow(dead_code)] // consumer: the SCP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) fn scp_disconnect_entry() -> SshState {
    disconnect_entry_state(Proto::SCP)
}

/// One step of the SCP-DO or SCP-DONE phase.
///
/// The successor of the eight `case SSH_SCP_*` arms of `ssh_statemachine`
/// (`lib/vssh/libssh2.c:2867-2975`), with `ssh_state_scp_upload_init`
/// (`:2376-2424`) and `ssh_state_scp_download_init` (`:2231-2273`) inlined into
/// the two arms that call them -- the C splits them out because they are long,
/// and the split has no meaning here.
///
/// # What one call does
///
/// Exactly one state, which is what the C's `switch` does per iteration.
/// [`scp_run_phase`] loops until the state is [`SshState::Stop`] or a failure is
/// reported, which is `ssh_multi_statemach`'s
/// `do { } while(!result && !*done && !block)`.
///
/// # The exhaustive match, and what it buys
///
/// Every one of the 62 states appears. Specification 0.3.3's pattern P3 is then
/// enforced by the compiler: adding a state to [`SshState`] without handling it
/// here does not compile. The states this file does NOT own are present as
/// explicit arms that route away rather than as a wildcard, because a wildcard
/// would silently absorb a state added later -- the same discipline
/// [`super::sftp::sftp_do_step`] applies from the other side of the seam.
///
/// # Every transition goes through [`ssh_set_state`]
///
/// [`SshConn`]'s state field is private with no setter, so this function CANNOT
/// write it directly -- the discipline `lib/vssh/vssh.c:107` states as *"This is
/// the ONLY way to change SSH state!"* is structural here rather than
/// conventional. Two arms transition AND report, which
/// [`StepOutcome::Fail`] expresses because it leaves the state where the step
/// left it; both are the C's own `myssh_to(...); result = ...; break;` shape and
/// both are commented at the site.
#[allow(clippy::too_many_lines)]
#[allow(dead_code)] // consumer: the SCP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) async fn scp_do_step(
    sshc: &mut SshConn,
    scpc: &mut ScpConn,
    sshp: &mut SshProto,
    settings: &SshSettings,
    effects: &mut SftpEffects,
    ctx: &mut TransferCtx<'_>,
) -> StepOutcome {
    match sshc.state() {
        // -- SCP-DO ---------------------------------------------------------
        SshState::ScpTransInit => {
            // *"First state in SCP-DO"* (`lib/vssh/ssh.h:107`). The working
            // path is resolved FIRST, exactly as the C does, and for SCP that
            // resolution has one scheme-specific rule: a path beginning `/~/`
            // has those three bytes stripped so the remote SHELL resolves the
            // remainder. `getworkingpath` owns it and branches on the protocol
            // bit this context carries.
            match getworkingpath(
                &sshp.path,
                &sshc.homedir,
                ctx.scheme().protocol,
            ) {
                Ok(path) => sshp.path = path,
                Err(code) => {
                    // `if(result) { myssh_to(data, sshc, SSH_STOP); break; }`
                    // -- a transition AND a report.
                    ssh_set_state(sshc, None, SshState::Stop);
                    return StepOutcome::Fail {
                        code,
                        message: None,
                    };
                }
            }

            match scp_trans_init(settings.upload, settings.infilesize) {
                Ok(next) => StepOutcome::advance(next),
                Err((parked, code, message)) => {
                    // `failf(...); result = CURLE_UPLOAD_FAILED;
                    //  myssh_to(data, sshc, SSH_SCP_CHANNEL_FREE); break;`
                    ssh_set_state(sshc, None, parked);
                    StepOutcome::Fail {
                        code,
                        message: Some(message.to_owned()),
                    }
                }
            }
        }

        SshState::ScpUploadInit => {
            // `ssh_state_scp_upload_init` (`:2376-2424`), which is
            // `libssh2_scp_send64(session, path, (int)new_file_perms,
            //  (libssh2_int64_t)infilesize, 0, 0)` plus its error handling.
            //
            // The two zeros are the mtime and atime, and they are why curl
            // never sends a `T` header: libssh2 emits one only for a non-zero
            // pair.
            //
            // The size is not negative -- `SSH_SCP_TRANS_INIT` refused that
            // already -- so the cast cannot lose a value. `unsigned_abs` states
            // that without a fallible conversion, and the guard is restated
            // here because this state is reachable directly from a test.
            if settings.infilesize < 0 {
                ssh_set_state(sshc, None, SshState::ScpChannelFree);
                return StepOutcome::Fail {
                    code: CURLcode::UploadFailed,
                    message: Some(SCP_UPLOAD_NEEDS_SIZE.to_owned()),
                };
            }
            let size = settings.infilesize.unsigned_abs();
            let header = ScpFileHeader::for_upload(
                &sshp.path,
                settings.new_file_perms,
                size,
            );

            let outcome = async {
                scpc.open(ctx, ScpDirection::Sink, &sshp.path).await?;
                scpc.send_header(ctx, header).await
            }
            .await;

            match outcome {
                Ok(()) => {
                    // `data->req.size = data->state.infilesize;
                    //  Curl_pgrsSetUploadSize(data, data->state.infilesize);
                    //  Curl_xfer_setup_send(data, FIRSTSOCKET);`
                    //
                    // Recorded rather than performed, for the reason
                    // `SftpEffects` documents: the transfer core's successor
                    // cannot be reached from a protocol module at this
                    // checkpoint. `upload_from` is the offset the send starts
                    // at and it is ZERO for SCP under every configuration --
                    // measured fact 2 in this module's documentation.
                    effects.upload_from = Some(0);
                    StepOutcome::advance(SshState::Stop)
                }
                Err(failure) => {
                    // `failf(data, "%s", err_msg);
                    //  myssh_to(data, sshc, SSH_SCP_CHANNEL_FREE);`
                    ssh_set_state(sshc, None, SshState::ScpChannelFree);
                    StepOutcome::Fail {
                        code: upload_failure_code(&failure),
                        message: Some(failure.message()),
                    }
                }
            }
        }

        SshState::ScpDownloadInit => {
            // `ssh_state_scp_download_init` (`:2231-2273`), which is
            // `libssh2_scp_recv2(session, path, &sb)` plus its error handling.
            //
            // The C's comment above the call is worth carrying because it
            // explains an absence: *"We must check the remote file; if it is a
            // directory no values will be set in sb"*. There is no stat to
            // make -- the `C` header IS the check, and a directory produces an
            // error message instead of one.
            let outcome: ScpResult<ScpFileHeader> = async {
                scpc.open(ctx, ScpDirection::Source, &sshp.path).await?;
                // The source announces nothing until it is asked, so the
                // dialogue opens with our acknowledgement rather than with the
                // peer's.
                scpc.send_ack(ctx).await?;
                let header = scpc.read_header(ctx).await?;
                scpc.send_ack(ctx).await?;
                Ok(header)
            }
            .await;

            match outcome {
                Ok(header) => {
                    // `bytecount = (curl_off_t)sb.st_size;
                    //  data->req.maxdownload = (curl_off_t)sb.st_size;
                    //  Curl_xfer_setup_recv(data, FIRSTSOCKET, bytecount);`
                    //
                    // `from` is 0 and `complete` is false unconditionally, and
                    // both are measured rather than defaulted. `from` is zero
                    // because the SCP path consults neither `--range` nor
                    // `--continue-at` -- measured fact 2 above -- and
                    // `complete` is false because the C's *"File already
                    // completely downloaded"* branch is SFTP's alone
                    // (`:1351-1357`). A zero-length file therefore arrives as
                    // `size: Some(0)`, which is what `tests/data/test617`
                    // exercises.
                    effects.download = Some(DownloadPlan {
                        from: 0,
                        size: Some(header.size),
                        complete: false,
                    });
                    StepOutcome::advance(SshState::Stop)
                }
                Err(failure) => {
                    ssh_set_state(sshc, None, SshState::ScpChannelFree);
                    StepOutcome::Fail {
                        code: failure.to_curlcode(),
                        message: Some(failure.message()),
                    }
                }
            }
        }

        SshState::ScpDownload => {
            // **No `case SSH_SCP_DOWNLOAD:` exists in the C's switch.** The
            // token is declared in the C state enumeration and no arm
            // implements it,
            // because libssh2 moves the payload inside `scp_recv` rather than
            // in a state. It therefore reaches `case SSH_QUIT: default:`
            // (`:2993-2997`), whose whole body is
            // `/* internal error */ myssh_to(data, sshc, SSH_STOP); break;` --
            // and which assigns no code, `result` having been initialised to
            // `CURLE_OK` at `:2571`. So the faithful outcome is a move to
            // `SSH_STOP` reporting nothing, which is what this is. Naming the
            // state rather than folding it into the routed-away group is what
            // records that the absence was measured.
            StepOutcome::advance(SshState::Stop)
        }

        // -- SCP-DONE -------------------------------------------------------
        SshState::ScpDone => {
            StepOutcome::advance(scp_done_next(settings.upload))
        }

        SshState::ScpSendEof => {
            // The generic transfer loop calls `ScpConn::send` for every
            // non-empty payload and the final call completes the SCP status
            // exchange. A zero-length upload has no such call, so DONE is the
            // fallback that emits its terminal zero and reads the peer's
            // acknowledgement before closing the SSH channel.
            if let Err(failure) = scpc.finish_upload(ctx).await {
                return StepOutcome::Fail {
                    code: upload_failure_code(&failure),
                    message: Some(failure.message()),
                };
            }
            if let Some(line) = scpc.send_eof(ctx).await {
                effects.info.push(line);
            }
            StepOutcome::advance(SshState::ScpWaitEof)
        }

        SshState::ScpWaitEof => {
            if let Some(line) = scpc.wait_eof(ctx).await {
                effects.info.push(line);
            }
            StepOutcome::advance(SshState::ScpWaitClose)
        }

        SshState::ScpWaitClose => {
            if let Some(line) = scpc.wait_close(ctx).await {
                effects.info.push(line);
            }
            StepOutcome::advance(SshState::ScpChannelFree)
        }

        SshState::ScpChannelFree => {
            // *"Last state in SCP-DONE"* (`lib/vssh/ssh.h:115`).
            if let Some(line) = scpc.free_channel(ctx).await {
                effects.info.push(line);
            }
            // `CURL_TRC_SSH(data, "SCP DONE phase complete")` -- a TRACE line,
            // not an `infof`, so it goes to the tracer the context carries and
            // not into `effects.info`. The feature's own name is `"SSH"` and is
            // consumed from `crate::trace`.
            {
                let (_chain, mut cx) = ctx.split();
                if let Some(tracer) = cx.tracer_mut() {
                    trc_feat!(
                        tracer,
                        TraceFeature::Ssh,
                        "{}",
                        SCP_DONE_PHASE_COMPLETE
                    );
                }
            }
            StepOutcome::advance(SshState::Stop)
        }

        // -- states this file does not own, named rather than wildcarded -----
        SshState::NoState | SshState::Stop => {
            // The machine is not inside a phase. `SSH_STOP` is the terminator
            // the driver tests for before it ever calls this, so reaching it
            // here means a caller entered with nothing to do.
            StepOutcome::advance(SshState::Stop)
        }
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
        | SshState::SftpRealpath => {
            // SSH-CONNECT, which both schemes share and which
            // `super::sftp::ssh_connect_step` drives. Authentication and
            // host-key verification are the shared core's job and are neither
            // duplicated nor weakened here.
            StepOutcome::advance(SshState::Stop)
        }
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
        | SshState::SftpShutdown => {
            // `protocols/sftp.rs`'s, and unreachable for an SCP transfer.
            // Twelve of these are the quote states, which is where measured
            // fact 1 of this module's documentation lands: `scp_perform` never
            // enters them, so `--quote` on an `scp://` URL is accepted and
            // ignored rather than refused.
            StepOutcome::advance(SshState::Stop)
        }
        SshState::SessionDisconnect | SshState::SessionFree => {
            // SCP-DISCONNECT. `SSH_SESSION_FREE` is *"Last state in
            // SCP/SFTP-DISCONNECT"* and terminates BOTH schemes, so the whole
            // phase is the shared core's: `scp_run_phase` hands
            // `SshPhase::SessionTeardown` to `ssh_run_phase`, which routes it
            // to `sftp_disconnect_step`. Routing away here rather than
            // implementing it is what keeps the terminator single.
            StepOutcome::advance(SshState::Stop)
        }
        SshState::Quit | SshState::Last => {
            // `case SSH_QUIT: default:` -- *"internal error"*, which moves to
            // `SSH_STOP` and assigns NO code in this tree (`:2993-2997`, with
            // `result` initialised to `CURLE_OK` at `:2571`). Reproduced
            // exactly, which is a deliberate difference from
            // `super::sftp::sftp_do_step`'s arm for the same two states: that
            // one answers `CURLE_FAILED_INIT`, which matches older curl but not
            // the tree this port is measured against. The divergence is
            // recorded rather than propagated.
            StepOutcome::advance(SshState::Stop)
        }
    }
}

/// `ssh_state_scp_upload_init`'s error remap (`lib/vssh/libssh2.c:2409-2414`).
///
/// The C's own comment is *"Map generic errors to upload failed"*, and the
/// remap covers exactly two codes:
///
/// ```text
/// if(result == CURLE_SSH || result == CURLE_REMOTE_FILE_NOT_FOUND)
///   result = CURLE_UPLOAD_FAILED;
/// ```
///
/// This is what makes `tests/data/test623` -- an upload into
/// `nonexistent-directory/` -- expect `errorcode 25` rather than 78: the remote
/// `scp -t` cannot create the file, the dialogue reports
/// [`ScpFailure::Remote`], its own code is
/// [`CURLcode::RemoteFileNotFound`], and this remaps it.
///
/// Note which codes survive: [`CURLcode::LoginDenied`],
/// [`CURLcode::PeerFailedVerification`], [`CURLcode::OperationTimedout`] and
/// the rest pass through unchanged, so an authentication failure during an
/// upload still reports 67 -- which is what `test607` and `test629` require of
/// the download path and what would equally hold for an upload.
#[allow(dead_code)] // consumer: the SCP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) fn upload_failure_code(failure: &ScpFailure) -> CURLcode {
    let code = failure.to_curlcode();
    if matches!(code, CURLcode::Ssh | CURLcode::RemoteFileNotFound) {
        CURLcode::UploadFailed
    } else {
        code
    }
}

/// `scp_doing` (`lib/vssh/libssh2.c:3468-3479`): continue SCP-DO.
///
/// The C wrapper runs the shared multi state-machine driver and traces
/// [`SCP_DO_PHASE_COMPLETE`] when it reaches `SSH_STOP`. The driver here
/// returns the same completion bit; trace ownership remains with the caller's
/// context, as in [`scp_run_phase`].
#[allow(dead_code)] // consumer: Protocol::doing once connection metadata can supply the state carriers
pub(crate) async fn scp_doing(
    sshc: &mut SshConn,
    scpc: &mut ScpConn,
    sshp: &mut SshProto,
    settings: &SshSettings,
    effects: &mut SftpEffects,
    ctx: &mut TransferCtx<'_>,
) -> CodeResult<bool> {
    scp_run_phase(sshc, scpc, sshp, settings, effects, ctx, SshPhase::ScpDo)
        .await
}

/// Drive an SCP phase to completion, applying every transition through
/// [`ssh_set_state`].
///
/// `scp_perform` (`lib/vssh/libssh2.c:3439-3465`), `scp_doing` (`:3468-3479`)
/// and the `ssh_multi_statemach` loop they both run, collapsed into one
/// function -- because the difference between the C's blocking and non-blocking
/// drivers is whether they sleep between iterations, and awaiting removes the
/// choice.
///
/// [`SshPhase::SessionTeardown`] is handed STRAIGHT to [`ssh_run_phase`]: its
/// two states terminate both schemes' disconnect phases and the shared core
/// owns them. Every other phase runs [`scp_do_step`].
///
/// Answers whether the phase reached [`SshState::Stop`], which is the `bool`
/// the C writes through `*done`.
///
/// # Errors
///
/// Whatever a step reports, or [`CURLcode::Ssh`] when [`SCP_PHASE_LIMIT`] is
/// exhausted -- the same bound-exhaustion code [`ssh_run_phase`] answers.
#[allow(dead_code)] // consumer: the SCP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) async fn scp_run_phase(
    sshc: &mut SshConn,
    scpc: &mut ScpConn,
    sshp: &mut SshProto,
    settings: &SshSettings,
    effects: &mut SftpEffects,
    ctx: &mut TransferCtx<'_>,
    phase: SshPhase,
) -> CodeResult<bool> {
    if matches!(phase, SshPhase::SessionTeardown | SshPhase::SftpDisconnect) {
        // The shared terminator. Nothing of SCP-DISCONNECT is implemented in
        // this file, which is the whole point of the seam.
        ssh_run_phase(
            sshc,
            sshp,
            settings,
            effects,
            ctx,
            SshPhase::SessionTeardown,
            SCP_PHASE_LIMIT,
        )
        .await?;
        return Ok(sshc.state() == SshState::Stop);
    }

    for _ in 0..SCP_PHASE_LIMIT {
        if sshc.state() == SshState::Stop {
            return Ok(true);
        }
        let outcome =
            scp_do_step(sshc, scpc, sshp, settings, effects, ctx).await;
        match outcome {
            StepOutcome::Advance { next, info } => {
                if let Some(line) = info {
                    effects.info.push(line);
                }
                ssh_set_state(sshc, None, next);
            }
            StepOutcome::Verify { hostkey, next } => {
                // Unreachable from an SCP phase: the host key is resolved
                // during SSH-CONNECT, which the shared core drives. Handled
                // rather than ignored so that the match stays total and so that
                // a future arm producing one cannot fall through silently.
                effects.info.push(format!(
                    "Host key accepted without verification: {} bytes",
                    hostkey.blob.len()
                ));
                ssh_set_state(sshc, None, next);
            }
            StepOutcome::Fail { code, message } => {
                if let Some(line) = message {
                    effects.info.push(line);
                }
                return Err(code);
            }
            StepOutcome::FailAndFree { code, message } => {
                if let Some(line) = message {
                    effects.info.push(line);
                }
                ssh_set_state(sshc, None, SshState::SessionFree);
                return Err(code);
            }
        }
    }
    Err(CURLcode::Ssh)
}

/// `scp_disconnect` (`lib/vssh/libssh2.c:3483-3499`).
///
/// SCP enters the shared teardown at [`SshState::SessionDisconnect`], then
/// delegates both states to [`sftp_disconnect_step`]. Unlike the generic phase
/// wrapper, this function carries `dead_connection`: the C must not send the
/// SSH disconnect message on a socket already known dead.
#[allow(dead_code)] // consumer: Protocol::disconnect once connection metadata can supply SshConn
pub(crate) async fn scp_disconnect(
    sshc: &mut SshConn,
    effects: &mut SftpEffects,
    ctx: &mut TransferCtx<'_>,
    dead_connection: bool,
) -> CodeResult<bool> {
    ssh_set_state(sshc, None, scp_disconnect_entry());
    for _ in 0..SCP_PHASE_LIMIT {
        if sshc.state() == SshState::Stop {
            return Ok(true);
        }
        let outcome =
            sftp_disconnect_step(sshc, effects, ctx, dead_connection).await;
        match outcome {
            StepOutcome::Advance { next, info } => {
                if let Some(line) = info {
                    effects.info.push(line);
                }
                ssh_set_state(sshc, None, next);
            }
            StepOutcome::Verify { hostkey, next } => {
                effects.info.push(format!(
                    "Host key accepted without verification: {} bytes",
                    hostkey.blob.len()
                ));
                ssh_set_state(sshc, None, next);
            }
            StepOutcome::Fail { code, message } => {
                if let Some(line) = message {
                    effects.info.push(line);
                }
                return Err(code);
            }
            StepOutcome::FailAndFree { code, message } => {
                if let Some(line) = message {
                    effects.info.push(line);
                }
                ssh_set_state(sshc, None, SshState::SessionFree);
                return Err(code);
            }
        }
    }
    Err(CURLcode::Ssh)
}

// The registry row and the `Protocol` implementation

/// `PROTOPT_DIRLOCK | PROTOPT_CLOSEACTION | PROTOPT_NOURLQUERY |
/// PROTOPT_CONN_REUSE` (`lib/vssh/vssh.c:356-357`).
///
/// **Byte for byte the same combination `Curl_scheme_sftp` carries**
/// (`:347-348`), which is a measured fact rather than a coincidence and is
/// asserted as one by [`mod tests`](self). The bits themselves are CONSUMED
/// from [`ProtocolOptions`] and are not redeclared -- `crate::conn` holds the
/// one definition of all seventeen.
///
/// What each one means for SCP:
///
/// * `PROTOPT_DIRLOCK` (`1 << 3`) -- the connection is bound to a directory, so
///   it cannot be reused for a path that would need a different one;
/// * `PROTOPT_CLOSEACTION` (`1 << 2`) -- *"some sort of close/quit action must
///   be done before the connection is closed"*, which for SCP is
///   `SSH_SESSION_DISCONNECT` through `SSH_SESSION_FREE`. One state shorter than
///   SFTP's action, because there is no subsystem to shut down first;
/// * `PROTOPT_NOURLQUERY` (`1 << 6`) -- a `?foo=bar` tail is part of the PATH,
///   not a query. It matters more here than anywhere: the path becomes an
///   argument to a remote shell command, so a question mark that had been
///   stripped as a query would silently change which file was fetched;
/// * `PROTOPT_CONN_REUSE` (`1 << 16`) -- connections may be pooled, subject to
///   the directory lock above.
///
/// What is deliberately ABSENT and would be easy to add by mistake:
/// `PROTOPT_WILDCARD`, which `ftp` and `ftps` carry and neither SSH scheme does;
/// and `PROTOPT_DUAL`, which is why `domore_pollset` stays defaulted below.
#[allow(dead_code)] // consumer: the SCP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) const FLAGS_SCP: ProtocolOptions = ProtocolOptions::DIRLOCK
    .union(ProtocolOptions::CLOSEACTION)
    .union(ProtocolOptions::NOURLQUERY)
    .union(ProtocolOptions::CONN_REUSE);

/// `Curl_scheme_scp` (`lib/vssh/vssh.c:352-359`), all six members.
///
/// `#[rustfmt::skip]` because every column is ABI- or wire-bearing.
///
/// ⚠ **The name is UPPER CASE**, `b"SCP"`, exactly as the C spells it -- and the
/// C's own `struct Curl_scheme` comment claims *"URL scheme name in
/// lowercase"*. The table works because both sides of every comparison are
/// case-folded (`Curl_getn_scheme` uses `curl_strnequal`), and four of the 33
/// rows are upper case in the C source: `SFTP`, `SCP`, `WS` and `WSS`.
/// Correcting this spelling would change nothing observable and would make the
/// row stop matching the C line it was transcribed from, so it is preserved and
/// asserted.
///
/// The `protocol` and `family` columns are the SAME bit, which is true of five
/// in-scope rows and not of the other four -- `ftps`'s family is `FTP`, and
/// `https`, `WS` and `WSS` all have `HTTP`. `PROTO_FAMILY_SSH` is
/// [`Proto::FAMILY_SSH`], which is `SCP | SFTP`, and it is consumed from
/// `protocols/mod.rs` rather than redeclared.
#[rustfmt::skip]
#[allow(dead_code)] // consumer: the SCP phase drivers, reached once easy/setopt.rs can supply SshSettings
pub(crate) const SCHEME: Scheme = Scheme {
    name:     b"SCP",
    run:      Some(&SCP),
    protocol: Proto::SCP,
    family:   Proto::SCP,
    flags:    FLAGS_SCP,
    defport:  PORT_SSH,
};

/// The SCP transfer implementation -- `Curl_protocol_scp`
/// (`lib/vssh/libssh2.c:3823-3841`).
///
/// # Eleven of seventeen slots, measured
///
/// | # | member | C | here |
/// | --: | --- | --- | --- |
/// | 1 | `setup_connection` | `ssh_setup_connection` | overridden, SHARED |
/// | 2 | `do_it` | `ssh_do` | overridden (required), SHARED |
/// | 3 | `done` | **`scp_done`** | overridden (required), SCP's own |
/// | 4 | `do_more` | `ZERO_NULL` | default |
/// | 5 | `connect_it` | `ssh_connect` | overridden, SHARED |
/// | 6 | `connecting` | `ssh_multi_statemach` | overridden, SHARED |
/// | 7 | `doing` | **`scp_doing`** | overridden, SCP's own |
/// | 8 | `proto_pollset` | `ssh_pollset` | overridden, SHARED |
/// | 9 | `doing_pollset` | `ssh_pollset` | overridden, SHARED |
/// | 10 | `domore_pollset` | `ZERO_NULL` | default |
/// | 11 | `perform_pollset` | `ssh_pollset` | overridden, SHARED |
/// | 12 | `disconnect` | **`scp_disconnect`** | overridden, SCP's own |
/// | 13 | `write_resp` | `ZERO_NULL` | default |
/// | 14 | `write_resp_hd` | `ZERO_NULL` | default |
/// | 15 | `connection_check` | `ZERO_NULL` | default |
/// | 16 | `attach` | `ssh_attach` | overridden, SHARED |
/// | 17 | `follow` | `ZERO_NULL` | default |
///
/// Eight of the eleven occupied slots delegate to a function
/// `protocols/sftp.rs` defines, and the three marked *SCP's own* are the
/// measured difference between `Curl_protocol_scp` and `Curl_protocol_sftp`
/// (`:3846-3864`). That 14-of-17 identity is the whole reason this file exists
/// as a thin layer rather than as a second SSH implementation, and
/// [`mod tests`](self) asserts the eight shared slots really do reach the same
/// functions the sibling's row reaches.
///
/// # Why this type is empty
///
/// `struct Curl_protocol` is a table of function pointers with no state, and
/// [`SCHEME`] holds `Option<&'static dyn Protocol>`, so a zero-sized type is
/// what the C actually is. Per-connection state lives in [`SshConn`] and
/// [`ScpConn`], and per-transfer state in [`SshProto`] -- the same division
/// `lib/vssh/ssh.h` documents.
///
/// # What this checkpoint can and cannot do, stated rather than implied
///
/// The eleven members are implemented in terms of the phase functions above and
/// the two seams, and every one of those is exercised by [`mod tests`](self).
/// What no member can do yet is reach a transfer's OPTIONS or its
/// client-writer chain: [`TransferCtx`] carries the filter chains, the clock,
/// the scheme and the socket index and nothing else, and
/// `curl-rs-lib/src/easy/setopt.rs` -- which would populate an
/// [`SshSettings`] -- is not on disk. A member that needs the settings
/// therefore takes them as an argument from the phase function it delegates to,
/// and the trait member itself reports [`CURLcode::NotBuiltIn`] until the easy
/// handle can supply them.
///
/// That is precisely the state `protocols/sftp.rs` documents for its own row,
/// and it is why `crate::version`'s `ENGINE_PROTOCOLS` stays inert and this
/// build still withholds `scp` from the `Protocols:` banner: specification
/// 0.6.5 measures the asymmetry exactly -- under-reporting a capability makes a
/// fixture SKIP and over-reporting makes it RUN AND FAIL. The gap is a WIRING
/// gap in a delivered file, visible in the trace output rather than silent.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct Scp;

/// The one instance, which [`SCHEME`] and `mod.rs`'s `RUN_SCP` point at.
///
/// A `const` rather than a `static`, for the reason `protocols/sftp.rs` records
/// about its own: under **MSRV 1.75** a `const` initialiser may not refer to a
/// `static` -- `error[E0013]: constants cannot refer to statics` -- and BOTH
/// consumers are `const` items, [`SCHEME`] above and `protocols::RUN_SCP`.
/// Newer compilers accept it, so the mistake builds cleanly on the default
/// toolchain and fails only under `cargo +1.75.0 check`.
///
/// The `const` is also the more accurate translation: `Curl_protocol_scp` is a
/// `const struct` of function pointers with no state, [`Scp`] is zero-sized, and
/// `&SCP` in a `const` context is const-promoted to a `&'static` reference to a
/// ZST -- so there is no storage for a `static` to reserve.
pub(crate) const SCP: Scp = Scp;

impl Protocol for Scp {
    // -- 1. setup_connection -------------------------------------------------

    /// `ssh_setup_connection` -- SHARED with SFTP.
    ///
    /// The C's body allocates a `struct ssh_conn` and a `struct SSHPROTO` and
    /// then installs this scheme's read and write functions:
    /// `if(conn->scheme->protocol & CURLPROTO_SCP) { conn->recv[FIRSTSOCKET] =
    /// scp_recv; conn->send[FIRSTSOCKET] = scp_send; }`
    /// (`lib/vssh/libssh2.c:3386-3389`). Those two are [`ScpConn::recv`] and
    /// [`ScpConn::send`] here, and they are reached through the connection's
    /// own state rather than through a function-pointer pair -- which is the
    /// whole of the difference.
    ///
    /// There is nowhere to STORE the allocation yet: the C keeps it in
    /// `Curl_conn_meta_set(conn, CURL_META_SSH_CONN, ...)` and
    /// `Curl_meta_set(data, CURL_META_SSH_EASY, ...)`, and neither successor
    /// exists. So this member validates what it can -- that the scheme really
    /// belongs to the SSH family, which is the precondition every other member
    /// assumes -- through the same [`ssh_attach`] the sibling uses.
    fn setup_connection(&self, ctx: &mut TransferCtx<'_>) -> CodeResult<()> {
        if ssh_attach(ctx) {
            Ok(())
        } else {
            Err(CURLcode::FailedInit)
        }
    }

    // -- 2. do_it ------------------------------------------------------------

    /// `ssh_do` (`lib/vssh/libssh2.c:3758-3781`) into `scp_perform`
    /// (`:3439-3465`) -- `ssh_do` SHARED, `scp_perform` SCP's.
    ///
    /// The C's `ssh_do` is shared and branches on
    /// `conn->scheme->protocol & CURLPROTO_SCP`; before the branch it resets
    /// `data->req.size` to -1, resets `sshc->secondCreateDirs` to 0 and calls
    /// `Curl_pgrsReset`. The SCP branch then traces
    /// [`SCP_DO_PHASE_STARTS`], enters `SSH_SCP_TRANS_INIT` and runs the
    /// machine, which is [`scp_run_phase`] with [`SshPhase::ScpDo`].
    ///
    /// Reaching the machine needs the connection's [`SshConn`] and
    /// [`ScpConn`], which [`TransferCtx`] cannot supply at this checkpoint.
    /// Reported as [`CURLcode::NotBuiltIn`] rather than answered `Ok(true)`,
    /// deliberately: a silent success would make the transfer core believe a DO
    /// phase had completed and hand an empty body to the client, which is
    /// exactly the over-reporting that turns a skipped fixture into a failing
    /// one.
    fn do_it<'a>(
        &'a self,
        ctx: &'a mut TransferCtx<'_>,
    ) -> ProtoFuture<'a, bool> {
        let _ = ctx;
        Box::pin(core::future::ready(Err(CURLcode::NotBuiltIn)))
    }

    // -- 3. done -------------------------------------------------------------

    /// `scp_done` (`lib/vssh/libssh2.c:3527-3537`) -- **SCP's own**, the first
    /// of the three differing slots.
    ///
    /// The decision this member makes is [`scp_done`]'s and is fully
    /// implemented and tested; what it cannot do is carry it out, for the
    /// reason [`Self::do_it`] gives. A `done` that reports the transfer's own
    /// status unchanged is what the C does when there is nothing to close --
    /// `if(sshc && !status)` guards its transition and `ssh_done` returns
    /// `status` for a failed transfer -- so a failed transfer is reported
    /// faithfully and a successful one cannot occur.
    fn done<'a>(
        &'a self,
        ctx: &'a mut TransferCtx<'_>,
        status: CURLcode,
        premature: bool,
    ) -> ProtoFuture<'a, ()> {
        let _ = ctx;
        // The decision is computed even though it cannot be applied, so that
        // the slot's behaviour and the phase function's cannot drift: a
        // successful transfer is the only case with a transition to make, and it
        // is the only case that reports the wiring gap.
        let outcome = match scp_done(status, premature) {
            Some(_) => Err(CURLcode::NotBuiltIn),
            None => Err(status),
        };
        Box::pin(core::future::ready(outcome))
    }

    // -- 5. connect_it -------------------------------------------------------

    /// `ssh_connect` (`lib/vssh/libssh2.c:3258-3437`) -- SHARED with SFTP.
    ///
    /// Enters `SSH_INIT` and runs the machine. The C's body before the state
    /// change is diagnostics plus reading `CURLOPT_SSH_KNOWNHOSTS` into
    /// libssh2's known-hosts store, all of which needs the connection's state,
    /// so this reports the same gap [`Self::do_it`] does.
    /// `super::sftp::ssh_connect_step` is the phase itself and is implemented in
    /// full there -- SCP adds nothing to it, which is why authentication and
    /// host-key verification appear nowhere in this file.
    fn connect_it<'a>(
        &'a self,
        ctx: &'a mut TransferCtx<'_>,
    ) -> ProtoFuture<'a, bool> {
        let _ = ctx;
        Box::pin(core::future::ready(Err(CURLcode::NotBuiltIn)))
    }

    // -- 6. connecting -------------------------------------------------------

    /// `ssh_multi_statemach` (`lib/vssh/libssh2.c:3070-3090`) -- SHARED.
    ///
    /// Continues the connect phase. Both handlers name the same function in
    /// this slot, so both reach `super::sftp::ssh_run_phase` with
    /// [`SshPhase::SshConnect`].
    fn connecting<'a>(
        &'a self,
        ctx: &'a mut TransferCtx<'_>,
    ) -> ProtoFuture<'a, bool> {
        let _ = ctx;
        Box::pin(core::future::ready(Err(CURLcode::NotBuiltIn)))
    }

    // -- 7. doing ------------------------------------------------------------

    /// `scp_doing` (`lib/vssh/libssh2.c:3468-3479`) -- **SCP's own**, the
    /// second of the three differing slots.
    ///
    /// Identical to [`Self::connecting`] in the C apart from the phase it
    /// drives and its trace line, which is [`SCP_DO_PHASE_COMPLETE`]. SFTP
    /// fills this slot with `sftp_doing`; the two differ only in which phase
    /// they continue, and [`scp_run_phase`] with [`SshPhase::ScpDo`] is this
    /// one.
    fn doing<'a>(
        &'a self,
        ctx: &'a mut TransferCtx<'_>,
    ) -> ProtoFuture<'a, bool> {
        let _ = ctx;
        Box::pin(core::future::ready(Err(CURLcode::NotBuiltIn)))
    }

    // -- 8, 9, 11. three of the four pollsets --------------------------------

    /// `ssh_pollset` during PROTOCONNECT -- SHARED.
    ///
    /// Unlike the four members above, this one WORKS: the readiness a pollset
    /// records is a function of the transport's wait direction, the transfer's
    /// keep flags and the chain's descriptor, and [`TransferCtx`] supplies the
    /// third while the first two default to empty without a connection. So the
    /// behaviour with no session is the C's third case -- watch for readability
    /// while a session exists, and record nothing otherwise.
    fn proto_pollset(
        &self,
        ctx: &mut TransferCtx<'_>,
        ps: &mut EasyPollset,
    ) -> CodeResult<()> {
        ssh_pollset(ctx, ps, SshWait::NONE, SshWait::NONE, false)
    }

    /// `ssh_pollset` during DOING -- SHARED. The same function in the C, filled
    /// into a second slot.
    fn doing_pollset(
        &self,
        ctx: &mut TransferCtx<'_>,
        ps: &mut EasyPollset,
    ) -> CodeResult<()> {
        ssh_pollset(ctx, ps, SshWait::NONE, SshWait::NONE, false)
    }

    /// `ssh_pollset` during DO_DONE, PERFORM and WAITPERFORM -- SHARED, and the
    /// third and last slot it fills.
    ///
    /// `domore_pollset` is deliberately NOT overridden: it is `ZERO_NULL` in
    /// both SSH handlers, because neither scheme carries `PROTOPT_DUAL` and so
    /// neither has a second DO half to wait on. See [`FLAGS_SCP`].
    fn perform_pollset(
        &self,
        ctx: &mut TransferCtx<'_>,
        ps: &mut EasyPollset,
    ) -> CodeResult<()> {
        ssh_pollset(ctx, ps, SshWait::NONE, SshWait::NONE, false)
    }

    // -- 12. disconnect ------------------------------------------------------

    /// `scp_disconnect` (`lib/vssh/libssh2.c:3483-3499`) -- **SCP's own**, the
    /// third and last differing slot.
    ///
    /// The C enters `SSH_SESSION_DISCONNECT` -- one state LATER than SFTP,
    /// which starts at `SSH_SFTP_SHUTDOWN` because it has a subsystem to close
    /// first -- and drives the machine to completion with
    /// `ssh_block_statemach(..., TRUE)`. Its comment explains why that is
    /// blocking: *"BLOCKING, but the function is using the state machine so the
    /// only reason this is still blocking is that the multi interface code has
    /// no support for disconnecting operations that takes a while"*. The
    /// successor is not blocking -- it awaits -- and the phase itself is the
    /// SHARED `super::sftp::ssh_session_disconnect` and
    /// `super::sftp::ssh_session_free`. [`scp_disconnect_entry`] is the one
    /// scheme-specific part.
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

    // -- 16. attach ----------------------------------------------------------

    /// `ssh_attach` (`lib/vssh/libssh2.c:3806-3820`) -- SHARED.
    ///
    /// Fully implemented; see `super::sftp::ssh_attach` for why the pointer
    /// repair the C performs has no successor and what is left of the body. The
    /// scheme test it performs is `conn->scheme->protocol & PROTO_FAMILY_SSH`,
    /// which passes for `SCP` and `SFTP` alike -- the family check is what makes
    /// one implementation correct for both.
    fn attach(&self, ctx: &mut TransferCtx<'_>) {
        let _ = ssh_attach(ctx);
    }

    // -- 15. connection_check, and the five other defaults -------------------
    //
    // `do_more`, `domore_pollset`, `write_resp`, `write_resp_hd`,
    // `connection_check` and `follow` are all `ZERO_NULL` in
    // `Curl_protocol_scp`, so all six take the trait's defaults -- the same six
    // `Curl_protocol_sftp` leaves empty. Each default reproduces what the C's
    // caller does with a NULL slot, which is why not writing them is the
    // faithful choice rather than an omission:
    //
    //   do_more           -> completes immediately; SCP is not PROTOPT_DUAL
    //   domore_pollset    -> no-op, for the same reason
    //   write_resp        -> false, so the generic client-writer chain runs
    //   write_resp_hd     -> false, likewise
    //   connection_check  -> CONNRESULT_NONE; the pool learns nothing extra
    //   follow            -> CURLE_TOO_MANY_REDIRECTS, which is what
    //                        `multi_follow` answers for a NULL slot
    //                        (`lib/multi.c:1870-1878`). SCP has no redirects.
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::filters::tests::{new_log, InMemory, TransportHandle};
    use crate::conn::filters::{link, FilterChains};
    use crate::protocols::sftp;
    use crate::util::timeval::{CurlTime, TestClock};

    // -- fixtures ------------------------------------------------------------

    /// The injected clock every test uses.
    ///
    /// A fixed instant rather than the wall clock, which is what makes the
    /// trace output and the timeout arithmetic reproducible. Specification
    /// 0.3.3's pattern P12 requires it and the crate root's `mod source_policy`
    /// enforces it: this file may not reach a wall-clock constructor at all.
    fn clock() -> TestClock {
        TestClock::new(CurlTime::new(1_000, 0))
    }

    /// Deterministic seams: the fixed clock plus a SEEDED generator.
    ///
    /// The randomness is injected for the same reason the clock is. SCP does not
    /// pair requests by identifier the way SFTP does, so nothing in this
    /// module's own dialogue consumes a random byte -- but `SshConn::new` seeds
    /// its request counter from the generator, and reaching for a thread-local
    /// one there would be exactly the hidden state P12 forbids.
    fn seams() -> sftp::SshSeams {
        sftp::SshSeams::deterministic(0x5CE0_1234)
    }

    /// A [`TransferCtx`] over borrowed chains, on the SCP row.
    ///
    /// [`SCHEME`] rather than a fabricated row, so that every test sees the
    /// scheme a real transfer would -- including its protocol bit, which
    /// `getworkingpath` branches on to apply SCP's `/~/` rule.
    fn transfer_ctx<'a>(
        chains: &'a mut FilterChains,
        clock: &'a TestClock,
    ) -> TransferCtx<'a> {
        TransferCtx::new(chains, clock, &SCHEME)
    }

    /// Chains with the in-memory transport of `conn/filters.rs` at the bottom.
    ///
    /// This is the substitute for a network that specification 0.8.4's coverage
    /// gate needs. Nothing in this module reads or writes through the chain --
    /// the channel seam is what moves SCP's bytes -- but every seam method takes
    /// a [`TransferCtx`], and a context over a CONNECTED chain is what a real
    /// transfer would hand them.
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
        // `CURLE_FAILED_INIT` when there is none.
        assert!(
            chain.connect_head(&mut cx).is_ok_and(|done| done),
            "the in-memory transport connects in one step"
        );
        (chains, state)
    }

    /// A scripted [`ScpChannel`]: a peer that answers from a byte script.
    ///
    /// This is what makes the SCP dialogue testable as pure code. Everything the
    /// module writes is recorded in one contiguous buffer, so a test asserts a
    /// WHOLE byte string -- which is the only way to honour specification
    /// 0.6.7's byte-exact oracle without a server, and which mirrors
    /// `compareparts` joining both sides into one string.
    #[derive(Debug, Default)]
    struct Scripted {
        /// What the peer will say, consumed from the front.
        inbound: Vec<u8>,
        /// Everything the module wrote, in order and undelimited.
        sent: Vec<u8>,
        /// How many bytes one `read` may answer, or [`None`] for "as many as
        /// asked".
        ///
        /// Set to `1` by the short-read tests, because a dialogue that only
        /// works when a whole control line arrives in one read is a dialogue
        /// that works on a fast loopback and fails on a real network.
        read_chunk: Option<usize>,
        /// How many bytes one `write` may accept, or [`None`] for all of them.
        write_chunk: Option<usize>,
        /// A failure to report on the next `read`, once.
        read_error: Option<SshError>,
        /// A failure to report on the next `write`, once.
        write_error: Option<SshError>,
        /// Which channel-control calls were made, in order.
        calls: Vec<&'static str>,
        /// A failure to report from `send_eof`.
        eof_error: Option<SshError>,
        /// A failure to report from `wait_eof`.
        wait_eof_error: Option<SshError>,
        /// A failure to report from `wait_close`.
        wait_close_error: Option<SshError>,
        /// A failure to report from `free`.
        free_error: Option<SshError>,
        /// What `block_directions` reports.
        waitfor: SshWait,
    }

    impl Scripted {
        /// A peer that will say `inbound` and nothing else.
        fn saying(inbound: &[u8]) -> Self {
            Self {
                inbound: inbound.to_vec(),
                ..Self::default()
            }
        }
    }

    impl ScpChannel for Scripted {
        fn read<'a>(
            &'a mut self,
            ctx: &'a mut TransferCtx<'_>,
            buf: &'a mut [u8],
        ) -> SshFuture<'a, usize> {
            let _ = ctx;
            Box::pin(async move {
                if let Some(error) = self.read_error.take() {
                    return Err(error);
                }
                let want = self.read_chunk.unwrap_or(buf.len()).min(buf.len());
                let take = want.min(self.inbound.len());
                for (slot, byte) in
                    buf.iter_mut().zip(self.inbound.drain(..take))
                {
                    *slot = byte;
                }
                Ok(take)
            })
        }

        fn write<'a>(
            &'a mut self,
            ctx: &'a mut TransferCtx<'_>,
            data: &'a [u8],
        ) -> SshFuture<'a, usize> {
            let _ = ctx;
            Box::pin(async move {
                if let Some(error) = self.write_error.take() {
                    return Err(error);
                }
                let take =
                    self.write_chunk.unwrap_or(data.len()).min(data.len());
                self.sent.extend_from_slice(data.get(..take).unwrap_or(&[]));
                Ok(take)
            })
        }

        fn send_eof<'a>(
            &'a mut self,
            ctx: &'a mut TransferCtx<'_>,
        ) -> SshFuture<'a, ()> {
            let _ = ctx;
            Box::pin(async move {
                self.calls.push("send_eof");
                self.eof_error.take().map_or(Ok(()), Err)
            })
        }

        fn wait_eof<'a>(
            &'a mut self,
            ctx: &'a mut TransferCtx<'_>,
        ) -> SshFuture<'a, ()> {
            let _ = ctx;
            Box::pin(async move {
                self.calls.push("wait_eof");
                self.wait_eof_error.take().map_or(Ok(()), Err)
            })
        }

        fn wait_close<'a>(
            &'a mut self,
            ctx: &'a mut TransferCtx<'_>,
        ) -> SshFuture<'a, ()> {
            let _ = ctx;
            Box::pin(async move {
                self.calls.push("wait_close");
                self.wait_close_error.take().map_or(Ok(()), Err)
            })
        }

        fn free<'a>(
            &'a mut self,
            ctx: &'a mut TransferCtx<'_>,
        ) -> SshFuture<'a, ()> {
            let _ = ctx;
            Box::pin(async move {
                self.calls.push("free");
                self.free_error.take().map_or(Ok(()), Err)
            })
        }

        fn block_directions(&self) -> SshWait {
            self.waitfor
        }
    }

    /// A shared handle on a [`Scripted`] peer, so a test can inspect it after
    /// the dialogue has consumed it.
    ///
    /// [`ScpSession::open_scp`] hands the channel AWAY as a `Box<dyn
    /// ScpChannel>`, so the only way to read what it recorded is to share it.
    /// An `Arc<Mutex<..>>` because the channel is handed away behind a
    /// [`Send`] trait object while the test retains an inspection handle.
    type Peer = std::sync::Arc<std::sync::Mutex<Scripted>>;

    /// A [`ScpChannel`] that forwards to a shared [`Scripted`].
    #[derive(Debug)]
    struct Shared(Peer);

    impl Shared {
        /// The peer behind this channel, locked.
        fn with<T>(&self, body: impl FnOnce(&mut Scripted) -> T) -> T {
            let mut guard =
                self.0.lock().expect("the scripted peer is never poisoned");
            body(&mut guard)
        }
    }

    impl ScpChannel for Shared {
        fn read<'a>(
            &'a mut self,
            ctx: &'a mut TransferCtx<'_>,
            buf: &'a mut [u8],
        ) -> SshFuture<'a, usize> {
            let _ = ctx;
            Box::pin(async move {
                self.with(|peer| {
                    if let Some(error) = peer.read_error.take() {
                        return Err(error);
                    }
                    let want =
                        peer.read_chunk.unwrap_or(buf.len()).min(buf.len());
                    let take = want.min(peer.inbound.len());
                    for (slot, byte) in
                        buf.iter_mut().zip(peer.inbound.drain(..take))
                    {
                        *slot = byte;
                    }
                    Ok(take)
                })
            })
        }

        fn write<'a>(
            &'a mut self,
            ctx: &'a mut TransferCtx<'_>,
            data: &'a [u8],
        ) -> SshFuture<'a, usize> {
            let _ = ctx;
            Box::pin(async move {
                self.with(|peer| {
                    if let Some(error) = peer.write_error.take() {
                        return Err(error);
                    }
                    let take =
                        peer.write_chunk.unwrap_or(data.len()).min(data.len());
                    peer.sent
                        .extend_from_slice(data.get(..take).unwrap_or(&[]));
                    Ok(take)
                })
            })
        }

        fn send_eof<'a>(
            &'a mut self,
            ctx: &'a mut TransferCtx<'_>,
        ) -> SshFuture<'a, ()> {
            let _ = ctx;
            Box::pin(async move {
                self.with(|peer| {
                    peer.calls.push("send_eof");
                    peer.eof_error.take().map_or(Ok(()), Err)
                })
            })
        }

        fn wait_eof<'a>(
            &'a mut self,
            ctx: &'a mut TransferCtx<'_>,
        ) -> SshFuture<'a, ()> {
            let _ = ctx;
            Box::pin(async move {
                self.with(|peer| {
                    peer.calls.push("wait_eof");
                    peer.wait_eof_error.take().map_or(Ok(()), Err)
                })
            })
        }

        fn wait_close<'a>(
            &'a mut self,
            ctx: &'a mut TransferCtx<'_>,
        ) -> SshFuture<'a, ()> {
            let _ = ctx;
            Box::pin(async move {
                self.with(|peer| {
                    peer.calls.push("wait_close");
                    peer.wait_close_error.take().map_or(Ok(()), Err)
                })
            })
        }

        fn free<'a>(
            &'a mut self,
            ctx: &'a mut TransferCtx<'_>,
        ) -> SshFuture<'a, ()> {
            let _ = ctx;
            Box::pin(async move {
                self.with(|peer| {
                    peer.calls.push("free");
                    peer.free_error.take().map_or(Ok(()), Err)
                })
            })
        }

        fn block_directions(&self) -> SshWait {
            self.0.lock().map_or(SshWait::NONE, |peer| peer.waitfor)
        }
    }

    /// A scripted [`ScpSession`]: hands out one shared channel and records the
    /// command it was asked to run.
    #[derive(Debug)]
    struct ScriptedSession {
        /// The channel to hand out.
        peer: Peer,
        /// Every `exec` command requested, in order.
        commands: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
        /// A failure to report instead of opening.
        open_error: Option<SshError>,
    }

    impl ScpSession for ScriptedSession {
        fn open_scp<'a>(
            &'a mut self,
            ctx: &'a mut TransferCtx<'_>,
            command: &'a [u8],
        ) -> SshFuture<'a, Box<dyn ScpChannel>> {
            let _ = ctx;
            Box::pin(async move {
                self.commands
                    .lock()
                    .expect("the command log is never poisoned")
                    .push(command.to_vec());
                if let Some(error) = self.open_error.take() {
                    return Err(error);
                }
                let channel: Box<dyn ScpChannel> =
                    Box::new(Shared(std::sync::Arc::clone(&self.peer)));
                Ok(channel)
            })
        }
    }

    /// A session over a peer saying `inbound`, plus handles on both.
    #[allow(clippy::type_complexity)]
    fn scripted_session(
        inbound: &[u8],
    ) -> (
        ScpConn,
        Peer,
        std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    ) {
        let peer = std::sync::Arc::new(std::sync::Mutex::new(
            Scripted::saying(inbound),
        ));
        let commands = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let session = ScriptedSession {
            peer: std::sync::Arc::clone(&peer),
            commands: std::sync::Arc::clone(&commands),
            open_error: None,
        };
        (ScpConn::new(Box::new(session)), peer, commands)
    }

    /// An [`SshConn`] over a session transport that is never reached.
    ///
    /// SCP's dialogue never calls a [`sftp::SshTransport`] method: the session
    /// seam is the shared core's and SCP only borrows `block2waitfor` from the
    /// connection. So a transport that reports "no transport" for every session
    /// operation is not a weakened double -- it is a double whose every method
    /// is unreachable from this module, which is itself the assertion that the
    /// two seams are disjoint.
    #[derive(Debug)]
    struct NoSession {
        /// What `block_directions` reports, which SCP's `block2waitfor` DOES
        /// read -- `ssh_block2waitfor` asks the SESSION for the direction even
        /// for a channel operation (`lib/vssh/libssh2.c:3051-3068`).
        waitfor: SshWait,
        /// Number of SSH disconnect messages the shared teardown requested.
        disconnects: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl sftp::SshTransport for NoSession {
        fn handshake<'a>(
            &'a mut self,
            ctx: &'a mut TransferCtx<'_>,
        ) -> SshFuture<'a, ()> {
            let _ = ctx;
            Box::pin(core::future::ready(Err(SshError::SocketNone)))
        }

        fn hostkey(&self) -> Option<sftp::HostKeyBlob> {
            None
        }

        fn auth_list<'a>(
            &'a mut self,
            ctx: &'a mut TransferCtx<'_>,
            user: &'a str,
        ) -> SshFuture<'a, Vec<u8>> {
            let _ = (ctx, user);
            Box::pin(core::future::ready(Err(SshError::SocketNone)))
        }

        fn authenticated(&self) -> bool {
            false
        }

        fn auth_publickey<'a>(
            &'a mut self,
            ctx: &'a mut TransferCtx<'_>,
            user: &'a str,
            private_key: &'a str,
            public_key: Option<&'a str>,
            passphrase: &'a str,
        ) -> SshFuture<'a, bool> {
            let _ = (ctx, user, private_key, public_key, passphrase);
            Box::pin(core::future::ready(Err(SshError::SocketNone)))
        }

        fn auth_password<'a>(
            &'a mut self,
            ctx: &'a mut TransferCtx<'_>,
            user: &'a str,
            password: &'a str,
        ) -> SshFuture<'a, bool> {
            let _ = (ctx, user, password);
            Box::pin(core::future::ready(Err(SshError::SocketNone)))
        }

        fn auth_keyboard_interactive<'a>(
            &'a mut self,
            ctx: &'a mut TransferCtx<'_>,
            user: &'a str,
            password: &'a str,
        ) -> SshFuture<'a, bool> {
            let _ = (ctx, user, password);
            Box::pin(core::future::ready(Err(SshError::SocketNone)))
        }

        fn auth_agent<'a>(
            &'a mut self,
            ctx: &'a mut TransferCtx<'_>,
            user: &'a str,
        ) -> SshFuture<'a, bool> {
            let _ = (ctx, user);
            Box::pin(core::future::ready(Err(SshError::SocketNone)))
        }

        fn open_sftp<'a>(
            &'a mut self,
            ctx: &'a mut TransferCtx<'_>,
        ) -> SshFuture<'a, u32> {
            let _ = ctx;
            Box::pin(core::future::ready(Err(SshError::SocketNone)))
        }

        fn sftp_exchange<'a>(
            &'a mut self,
            ctx: &'a mut TransferCtx<'_>,
            packet: Vec<u8>,
        ) -> SshFuture<'a, Vec<u8>> {
            let _ = (ctx, packet);
            Box::pin(core::future::ready(Err(SshError::SocketNone)))
        }

        fn close_sftp<'a>(
            &'a mut self,
            ctx: &'a mut TransferCtx<'_>,
        ) -> SshFuture<'a, ()> {
            let _ = ctx;
            Box::pin(core::future::ready(Err(SshError::SocketNone)))
        }

        fn disconnect<'a>(
            &'a mut self,
            ctx: &'a mut TransferCtx<'_>,
        ) -> SshFuture<'a, ()> {
            let _ = ctx;
            Box::pin(async move {
                self.disconnects
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            })
        }

        fn block_directions(&self) -> SshWait {
            self.waitfor
        }
    }

    /// An [`SshConn`] in `SSH_STOP` over a [`NoSession`].
    fn ssh_conn() -> SshConn {
        ssh_conn_with_disconnects().0
    }

    /// An SSH connection plus its disconnect-message counter.
    fn ssh_conn_with_disconnects(
    ) -> (SshConn, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        let disconnects =
            std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let conn = SshConn::new(
            Box::new(NoSession {
                waitfor: SshWait::NONE,
                disconnects: std::sync::Arc::clone(&disconnects),
            }),
            seams(),
        );
        (conn, disconnects)
    }

    /// A settings block with the option defaults, then `body` applied.
    fn settings(body: impl FnOnce(&mut SshSettings)) -> SshSettings {
        let mut value = SshSettings::with_option_defaults();
        body(&mut value);
        value
    }

    /// Run one future to completion on a current-thread runtime.
    ///
    /// Specification 0.8.3 names a current-thread runtime for the CLI, and a
    /// test drives the same shape.
    fn block_on<F: core::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a current-thread runtime")
            .block_on(future)
    }

    // -- 1. registry and the shared vtable core -----------------------------

    #[test]
    fn the_registry_row_is_the_measured_scp_row() {
        assert_eq!(SCHEME.name, b"SCP");
        assert_eq!(SCHEME.protocol, Proto::SCP);
        assert_eq!(SCHEME.family, Proto::SCP);
        assert_eq!(SCHEME.defport, 22);
        assert_eq!(SCHEME.defport, sftp::SCHEME.defport);
        assert_eq!(SCHEME.flags, sftp::SCHEME.flags);

        let expected = ProtocolOptions::DIRLOCK
            .union(ProtocolOptions::CLOSEACTION)
            .union(ProtocolOptions::NOURLQUERY)
            .union(ProtocolOptions::CONN_REUSE);
        assert_eq!(SCHEME.flags, expected);
        assert_eq!(
            SCHEME.flags.bits(),
            (1_u32 << 3) | (1_u32 << 2) | (1_u32 << 6) | (1_u32 << 16)
        );
        assert_eq!(Proto::FAMILY_SSH, Proto::SCP | Proto::SFTP);
        assert!(SCHEME.runnable());
    }

    #[test]
    fn the_eight_shared_slots_match_sftp_through_dyn_dispatch() {
        let scp: &dyn Protocol = &SCP;
        let sftp: &dyn Protocol = &sftp::SFTP;
        let clock = clock();

        let mut scp_chains = FilterChains::new(None);
        let mut scp_ctx = transfer_ctx(&mut scp_chains, &clock);
        let mut sftp_chains = FilterChains::new(None);
        let mut sftp_ctx =
            TransferCtx::new(&mut sftp_chains, &clock, &sftp::SCHEME);

        assert_eq!(
            scp.setup_connection(&mut scp_ctx),
            sftp.setup_connection(&mut sftp_ctx)
        );
        assert_eq!(
            block_on(scp.do_it(&mut scp_ctx)),
            block_on(sftp.do_it(&mut sftp_ctx))
        );
        assert_eq!(
            block_on(scp.connect_it(&mut scp_ctx)),
            block_on(sftp.connect_it(&mut sftp_ctx))
        );
        assert_eq!(
            block_on(scp.connecting(&mut scp_ctx)),
            block_on(sftp.connecting(&mut sftp_ctx))
        );

        let mut scp_ps = EasyPollset::new();
        let mut sftp_ps = EasyPollset::new();
        assert_eq!(
            scp.proto_pollset(&mut scp_ctx, &mut scp_ps),
            sftp.proto_pollset(&mut sftp_ctx, &mut sftp_ps)
        );
        assert_eq!(scp_ps.len(), sftp_ps.len());

        let mut scp_ps = EasyPollset::new();
        let mut sftp_ps = EasyPollset::new();
        assert_eq!(
            scp.doing_pollset(&mut scp_ctx, &mut scp_ps),
            sftp.doing_pollset(&mut sftp_ctx, &mut sftp_ps)
        );
        assert_eq!(scp_ps.len(), sftp_ps.len());

        let mut scp_ps = EasyPollset::new();
        let mut sftp_ps = EasyPollset::new();
        assert_eq!(
            scp.perform_pollset(&mut scp_ctx, &mut scp_ps),
            sftp.perform_pollset(&mut sftp_ctx, &mut sftp_ps)
        );
        assert_eq!(scp_ps.len(), sftp_ps.len());

        scp.attach(&mut scp_ctx);
        sftp.attach(&mut sftp_ctx);

        let mut first = ssh_conn();
        let mut second = ssh_conn();
        assert_eq!(first.next_request_id(), second.next_request_id());
    }

    #[test]
    fn exactly_eleven_slots_are_occupied_and_six_use_defaults() {
        const OCCUPIED: [&str; 11] = [
            "setup_connection",
            "do_it",
            "done",
            "connect_it",
            "connecting",
            "doing",
            "proto_pollset",
            "doing_pollset",
            "perform_pollset",
            "disconnect",
            "attach",
        ];
        const DEFAULTED: [&str; 6] = [
            "do_more",
            "domore_pollset",
            "write_resp",
            "write_resp_hd",
            "connection_check",
            "follow",
        ];
        assert_eq!(OCCUPIED.len() + DEFAULTED.len(), 17);

        let handler: &dyn Protocol = &SCP;
        let clock = clock();
        let (mut chains, _transport) = chains_with_transport(&clock, 17);
        let mut ctx = transfer_ctx(&mut chains, &clock);

        assert_eq!(handler.setup_connection(&mut ctx), Ok(()));
        assert_eq!(
            block_on(handler.do_it(&mut ctx)),
            Err(CURLcode::NotBuiltIn)
        );
        assert_eq!(
            block_on(handler.done(&mut ctx, CURLcode::Ok, false)),
            Err(CURLcode::NotBuiltIn)
        );
        assert_eq!(
            block_on(handler.connect_it(&mut ctx)),
            Err(CURLcode::NotBuiltIn)
        );
        assert_eq!(
            block_on(handler.connecting(&mut ctx)),
            Err(CURLcode::NotBuiltIn)
        );
        assert_eq!(
            block_on(handler.doing(&mut ctx)),
            Err(CURLcode::NotBuiltIn)
        );

        for poll in [
            Protocol::proto_pollset,
            Protocol::doing_pollset,
            Protocol::perform_pollset,
        ] {
            let mut ps = EasyPollset::new();
            assert_eq!(poll(handler, &mut ctx, &mut ps), Ok(()));
            assert_eq!(ps.len(), 0);
        }
        assert_eq!(block_on(handler.disconnect(&mut ctx, false)), Ok(()));
        handler.attach(&mut ctx);

        assert_eq!(block_on(handler.do_more(&mut ctx)), Ok(true));
        let mut ps = EasyPollset::new();
        assert_eq!(handler.domore_pollset(&mut ctx, &mut ps), Ok(()));
        assert_eq!(ps.len(), 0);
        assert_eq!(
            block_on(handler.write_resp(&mut ctx, b"body", false)),
            Ok(false)
        );
        assert_eq!(
            block_on(handler.write_resp_hd(&mut ctx, b"header", false)),
            Ok(false)
        );
        assert_eq!(
            handler.connection_check(
                &mut ctx,
                crate::conn::pool::ConnCheck::ISDEAD
            ),
            crate::conn::pool::ConnResult::NONE
        );
        assert_eq!(
            handler.follow(
                &mut ctx,
                "scp://elsewhere/file",
                crate::transfer::request::FollowType::None,
            ),
            Err(CURLcode::TooManyRedirects)
        );
    }

    #[test]
    fn only_done_doing_and_disconnect_select_scp_specific_phases() {
        assert_eq!(scp_done(CURLcode::Ok, false), Some(SshState::ScpDone));
        assert_eq!(
            sftp::sftp_done(CURLcode::Ok, false, false, false),
            Some(SshState::NoState)
        );
        assert_eq!(scp_disconnect_entry(), SshState::SessionDisconnect);
        assert_eq!(
            sftp::disconnect_entry_state(Proto::SFTP),
            SshState::SftpShutdown
        );
        assert_eq!(SshState::ScpTransInit.phase(), SshPhase::ScpDo);
        assert_eq!(SshState::SftpQuoteInit.phase(), SshPhase::SftpDo);
    }

    // -- 2. byte-exact control dialogue ------------------------------------

    #[test]
    fn every_control_message_is_one_exact_wire_string() {
        #[rustfmt::skip]
        let expected_header = b"C0644 12 report.txt\n";
        let header =
            ScpFileHeader::for_upload(b"/srv/out/report.txt", 0o644, 12);
        assert_eq!(header.encode(), expected_header);
        assert_eq!(ScpFileHeader::parse(expected_header), Ok(header.clone()));

        #[rustfmt::skip]
        let expected_ack = b"\x00";
        #[rustfmt::skip]
        let expected_warning = b"\x01recoverable warning\n";
        #[rustfmt::skip]
        let expected_error = b"\x02fatal error\n";
        assert_eq!(ScpMessage::Ack.encode(), expected_ack);
        assert_eq!(
            ScpMessage::Warning(b"recoverable warning".to_vec()).encode(),
            expected_warning
        );
        assert_eq!(
            ScpMessage::Error(b"fatal error".to_vec()).encode(),
            expected_error
        );
        assert_eq!(ScpMessage::parse(expected_ack), Ok(ScpMessage::Ack));
        assert_eq!(
            ScpMessage::parse(expected_warning),
            Ok(ScpMessage::Warning(b"recoverable warning".to_vec()))
        );
        let error = ScpMessage::parse(expected_error)
            .expect("the fatal form is a valid control message");
        assert_eq!(error, ScpMessage::Error(b"fatal error".to_vec()));
        assert!(error.is_fatal());
    }

    #[test]
    fn header_modes_and_commands_preserve_curls_exact_spelling() {
        #[rustfmt::skip]
        let setuid = b"C04755 3 tool\n";
        assert_eq!(
            ScpFileHeader::for_upload(b"/bin/tool", 0o4755, 3).encode(),
            setuid
        );
        assert_eq!(basename(b"plain"), b"plain");
        assert_eq!(basename(b"/path/ending/"), b"");

        #[rustfmt::skip]
        let source = b"scp -f /safe/path";
        #[rustfmt::skip]
        let sink = b"scp -t /safe/path";
        assert_eq!(
            scp_command(ScpDirection::for_upload(false), b"/safe/path"),
            source
        );
        assert_eq!(
            scp_command(ScpDirection::for_upload(true), b"/safe/path"),
            sink
        );
        assert_eq!(shell_quotearg(b"/a path/$name"), b"/a' 'path/'$'name");
        assert_eq!(shell_quotearg(b"a'b"), b"a\"'\"b");
    }

    #[test]
    fn malformed_control_forms_are_scp_protocol_errors() {
        for line in [
            &b""[..],
            b"\x00trailing",
            b"notice\n",
            b"D0755 0 dir\n",
            b"E\n",
        ] {
            assert_eq!(ScpMessage::parse(line), Err(SshError::ScpProtocol));
        }
        for line in [
            &b"C 1 name\n"[..],
            b"C0688 1 name\n",
            b"C0644 -1 name\n",
            b"C0644 1 \n",
            b"D0644 1 name\n",
        ] {
            assert_eq!(ScpFileHeader::parse(line), Err(SshError::ScpProtocol));
        }
    }

    // -- 3. scripted download and upload -----------------------------------

    #[test]
    fn download_round_trip_ignores_range_resume_quotes_and_hides_the_ack() {
        #[rustfmt::skip]
        let peer_script = b"C0644 5 file.txt\nhello\x00";
        let (mut scpc, peer, commands) = scripted_session(peer_script);
        peer.lock().expect("the peer is available").read_chunk = Some(2);

        let clock = clock();
        let (mut chains, _transport) = chains_with_transport(&clock, 23);
        let mut ctx = transfer_ctx(&mut chains, &clock);
        let mut sshc = ssh_conn();
        let mut sshp = SshProto {
            path: b"/remote/file.txt".to_vec(),
            ..SshProto::default()
        };
        let set = settings(|value| {
            value.resume_from = 3;
            value.range = Some(b"3-4".to_vec());
            value.quote.push(b"mkdir ignored".to_vec());
            value.postquote.push(b"rm ignored".to_vec());
            value.prequote.push(b"pwd ignored".to_vec());
        });
        let mut effects = SftpEffects::new();

        ssh_set_state(&mut sshc, None, SshState::ScpTransInit);
        assert_eq!(
            block_on(scp_doing(
                &mut sshc,
                &mut scpc,
                &mut sshp,
                &set,
                &mut effects,
                &mut ctx,
            )),
            Ok(true)
        );
        assert_eq!(sshc.state(), SshState::Stop);
        assert_eq!(
            effects.download,
            Some(DownloadPlan {
                from: 0,
                size: Some(5),
                complete: false,
            })
        );
        assert_eq!(
            commands
                .lock()
                .expect("the commands are available")
                .as_slice(),
            &[b"scp -f /remote/file.txt".to_vec()]
        );
        assert_eq!(
            peer.lock().expect("the peer is available").sent,
            b"\x00\x00"
        );

        let mut body = Vec::new();
        while body.len() < 5 {
            let mut chunk = [0_u8; 8];
            let read = block_on(scpc.recv(&mut sshc, &mut ctx, &mut chunk))
                .expect("the scripted peer supplies the payload");
            assert!(read > 0);
            body.extend_from_slice(&chunk[..read]);
        }
        assert_eq!(body, b"hello");
        let mut chunk = [0_u8; 8];
        assert_eq!(block_on(scpc.recv(&mut sshc, &mut ctx, &mut chunk)), Ok(0));
        let peer_after_body = peer.lock().expect("the peer is available");
        assert_eq!(peer_after_body.sent, b"\x00\x00\x00");
        assert!(peer_after_body.inbound.is_empty());
        drop(peer_after_body);

        ssh_set_state(&mut sshc, None, SshState::ScpDone);
        assert_eq!(
            block_on(scp_run_phase(
                &mut sshc,
                &mut scpc,
                &mut sshp,
                &set,
                &mut effects,
                &mut ctx,
                SshPhase::ScpDone,
            )),
            Ok(true)
        );
        assert_eq!(peer.lock().expect("the peer is available").calls, ["free"]);
        assert!(!scpc.has_channel());
    }

    #[test]
    fn upload_round_trip_ignores_resume_range_and_uses_custom_mode() {
        #[rustfmt::skip]
        let peer_script = b"\x00\x00\x00";
        let (mut scpc, peer, commands) = scripted_session(peer_script);
        {
            let mut scripted = peer.lock().expect("the peer is available");
            scripted.read_chunk = Some(1);
            scripted.write_chunk = Some(2);
        }

        let clock = clock();
        let (mut chains, _transport) = chains_with_transport(&clock, 29);
        let mut ctx = transfer_ctx(&mut chains, &clock);
        let mut sshc = ssh_conn();
        let mut sshp = SshProto {
            path: b"/remote/report.txt".to_vec(),
            ..SshProto::default()
        };
        let set = settings(|value| {
            value.upload = true;
            value.infilesize = 5;
            value.new_file_perms = 0o600;
            value.resume_from = 2;
            value.range = Some(b"2-4".to_vec());
            value.quote.push(b"ignored".to_vec());
        });
        let mut effects = SftpEffects::new();

        ssh_set_state(&mut sshc, None, SshState::ScpTransInit);
        assert_eq!(
            block_on(scp_doing(
                &mut sshc,
                &mut scpc,
                &mut sshp,
                &set,
                &mut effects,
                &mut ctx,
            )),
            Ok(true)
        );
        assert_eq!(effects.upload_from, Some(0));
        assert_eq!(
            commands
                .lock()
                .expect("the commands are available")
                .as_slice(),
            &[b"scp -t /remote/report.txt".to_vec()]
        );
        assert_eq!(
            peer.lock().expect("the peer is available").sent,
            b"C0600 5 report.txt\n"
        );

        let mut offset = 0_usize;
        while offset < b"hello".len() {
            let written =
                block_on(scpc.send(&mut sshc, &mut ctx, &b"hello"[offset..]))
                    .expect("the scripted peer accepts the payload");
            assert!(written > 0);
            offset += written;
        }
        let peer_after_body = peer.lock().expect("the peer is available");
        assert_eq!(peer_after_body.sent, b"C0600 5 report.txt\nhello\x00");
        assert!(peer_after_body.inbound.is_empty());
        drop(peer_after_body);

        ssh_set_state(&mut sshc, None, SshState::ScpDone);
        assert_eq!(
            block_on(scp_run_phase(
                &mut sshc,
                &mut scpc,
                &mut sshp,
                &set,
                &mut effects,
                &mut ctx,
                SshPhase::ScpDone,
            )),
            Ok(true)
        );
        assert_eq!(
            peer.lock().expect("the peer is available").calls,
            ["send_eof", "wait_eof", "wait_close", "free"]
        );
        assert!(!scpc.has_channel());
    }

    // -- 4. option and operation semantics ---------------------------------

    #[test]
    fn an_unknown_upload_size_is_refused_with_curls_exact_error() {
        let (mut scpc, _peer, commands) = scripted_session(b"");
        let clock = clock();
        let (mut chains, _transport) = chains_with_transport(&clock, 31);
        let mut ctx = transfer_ctx(&mut chains, &clock);
        let mut sshc = ssh_conn();
        let mut sshp = SshProto {
            path: b"/remote/file".to_vec(),
            ..SshProto::default()
        };
        let set = settings(|value| {
            value.upload = true;
            value.infilesize = -1;
        });
        let mut effects = SftpEffects::new();

        ssh_set_state(&mut sshc, None, SshState::ScpTransInit);
        assert_eq!(
            block_on(scp_run_phase(
                &mut sshc,
                &mut scpc,
                &mut sshp,
                &set,
                &mut effects,
                &mut ctx,
                SshPhase::ScpDo,
            )),
            Err(CURLcode::UploadFailed)
        );
        assert_eq!(sshc.state(), SshState::ScpChannelFree);
        assert_eq!(effects.info, [SCP_UPLOAD_NEEDS_SIZE]);
        assert!(commands
            .lock()
            .expect("the commands are available")
            .is_empty());
    }

    #[test]
    fn directory_style_requests_use_the_scp_failure_codes() {
        #[rustfmt::skip]
        let download_refusal = b"\x02not a regular file\n";
        let (mut scpc, peer, _commands) = scripted_session(download_refusal);
        let clock = clock();
        let (mut chains, _transport) = chains_with_transport(&clock, 37);
        let mut ctx = transfer_ctx(&mut chains, &clock);
        let mut sshc = ssh_conn();
        let mut sshp = SshProto {
            path: b"/remote/directory/".to_vec(),
            ..SshProto::default()
        };
        let set = settings(|value| {
            value.list_only = true;
            value.no_body = true;
            value.create_missing_dirs = true;
        });
        let mut effects = SftpEffects::new();
        ssh_set_state(&mut sshc, None, SshState::ScpTransInit);
        assert_eq!(
            block_on(scp_run_phase(
                &mut sshc,
                &mut scpc,
                &mut sshp,
                &set,
                &mut effects,
                &mut ctx,
                SshPhase::ScpDo,
            )),
            Err(CURLcode::RemoteFileNotFound)
        );
        assert_eq!(effects.info, ["not a regular file"]);
        assert_eq!(peer.lock().expect("the peer is available").sent, b"\x00");

        #[rustfmt::skip]
        let upload_refusal = b"\x02No such file or directory\n";
        let (mut scpc, peer, _commands) = scripted_session(upload_refusal);
        let (mut chains, _transport) = chains_with_transport(&clock, 41);
        let mut ctx = transfer_ctx(&mut chains, &clock);
        let mut sshc = ssh_conn();
        let mut sshp = SshProto {
            path: b"/missing/directory/file".to_vec(),
            ..SshProto::default()
        };
        let set = settings(|value| {
            value.upload = true;
            value.infilesize = 4;
            value.create_missing_dirs = true;
        });
        let mut effects = SftpEffects::new();
        ssh_set_state(&mut sshc, None, SshState::ScpTransInit);
        assert_eq!(
            block_on(scp_run_phase(
                &mut sshc,
                &mut scpc,
                &mut sshp,
                &set,
                &mut effects,
                &mut ctx,
                SshPhase::ScpDo,
            )),
            Err(CURLcode::UploadFailed)
        );
        assert_eq!(effects.info, ["No such file or directory"]);
        assert!(peer.lock().expect("the peer is available").sent.is_empty());
    }

    #[test]
    fn zero_length_upload_uses_the_default_mode_and_full_dialogue() {
        #[rustfmt::skip]
        let peer_script = b"\x00\x00\x00";
        let (mut scpc, peer, _commands) = scripted_session(peer_script);
        let clock = clock();
        let (mut chains, _transport) = chains_with_transport(&clock, 43);
        let mut ctx = transfer_ctx(&mut chains, &clock);
        let mut sshc = ssh_conn();
        let mut sshp = SshProto {
            path: b"/remote/empty.bin".to_vec(),
            ..SshProto::default()
        };
        let set = settings(|value| {
            value.upload = true;
            value.infilesize = 0;
        });
        let mut effects = SftpEffects::new();

        ssh_set_state(&mut sshc, None, SshState::ScpTransInit);
        assert_eq!(
            block_on(scp_run_phase(
                &mut sshc,
                &mut scpc,
                &mut sshp,
                &set,
                &mut effects,
                &mut ctx,
                SshPhase::ScpDo,
            )),
            Ok(true)
        );
        assert_eq!(
            peer.lock().expect("the peer is available").sent,
            b"C0644 0 empty.bin\n"
        );

        ssh_set_state(&mut sshc, None, SshState::ScpDone);
        assert_eq!(
            block_on(scp_run_phase(
                &mut sshc,
                &mut scpc,
                &mut sshp,
                &set,
                &mut effects,
                &mut ctx,
                SshPhase::ScpDone,
            )),
            Ok(true)
        );
        let scripted = peer.lock().expect("the peer is available");
        assert_eq!(scripted.sent, b"C0644 0 empty.bin\n\x00");
        assert!(scripted.inbound.is_empty());
    }

    // -- 5. state ownership, teardown, and error mapping -------------------

    #[test]
    fn scp_done_then_shared_disconnect_visits_every_measured_state() {
        #[rustfmt::skip]
        let peer_script = b"\x00\x00\x00";
        let (mut scpc, peer, _commands) = scripted_session(peer_script);
        let clock = clock();
        let (mut chains, _transport) = chains_with_transport(&clock, 47);
        let mut ctx = transfer_ctx(&mut chains, &clock);
        let mut sshc = ssh_conn();
        let mut sshp = SshProto {
            path: b"/remote/empty".to_vec(),
            ..SshProto::default()
        };
        let set = settings(|value| {
            value.upload = true;
            value.infilesize = 0;
        });
        let mut effects = SftpEffects::new();

        ssh_set_state(&mut sshc, None, SshState::ScpTransInit);
        assert_eq!(
            block_on(scp_run_phase(
                &mut sshc,
                &mut scpc,
                &mut sshp,
                &set,
                &mut effects,
                &mut ctx,
                SshPhase::ScpDo,
            )),
            Ok(true)
        );

        ssh_set_state(&mut sshc, None, SshState::ScpDone);
        for next in [
            SshState::ScpSendEof,
            SshState::ScpWaitEof,
            SshState::ScpWaitClose,
            SshState::ScpChannelFree,
            SshState::Stop,
        ] {
            let from = sshc.state();
            let outcome = block_on(scp_do_step(
                &mut sshc,
                &mut scpc,
                &mut sshp,
                &set,
                &mut effects,
                &mut ctx,
            ));
            let StepOutcome::Advance { next: observed, .. } = outcome else {
                panic!("{from:?} did not advance");
            };
            assert_eq!(observed, next, "from {from:?}");
            ssh_set_state(&mut sshc, None, observed);
        }
        assert_eq!(
            peer.lock().expect("the peer is available").calls,
            ["send_eof", "wait_eof", "wait_close", "free"]
        );

        sshc.homedir = b"/home/test".to_vec();
        sshc.authed = true;
        sshc.nextstate = SshState::ScpDone;
        ssh_set_state(&mut sshc, None, scp_disconnect_entry());
        let outcome = block_on(sftp::sftp_disconnect_step(
            &mut sshc,
            &mut effects,
            &mut ctx,
            false,
        ));
        assert_eq!(
            outcome,
            StepOutcome::Advance {
                next: SshState::SessionFree,
                info: None,
            }
        );
        ssh_set_state(&mut sshc, None, SshState::SessionFree);

        let outcome = block_on(sftp::sftp_disconnect_step(
            &mut sshc,
            &mut effects,
            &mut ctx,
            false,
        ));
        assert_eq!(sshc.state(), SshState::SessionFree);
        assert_eq!(
            outcome,
            StepOutcome::Advance {
                next: SshState::Stop,
                info: Some("SSH session free".to_owned()),
            }
        );
        assert!(sshc.homedir.is_empty());
        assert!(!sshc.authed);
        assert_eq!(sshc.nextstate, SshState::NoState);
        ssh_set_state(&mut sshc, None, SshState::Stop);
        assert_eq!(sshc.state(), SshState::Stop);
        assert_eq!(TraceFeature::Ssh.name(), "SSH");
    }

    #[test]
    fn scp_disconnect_skips_the_message_for_a_dead_connection() {
        for (dead_connection, expected_disconnects, socket) in
            [(false, 1_usize, 50), (true, 0_usize, 49)]
        {
            let (mut sshc, disconnects) = ssh_conn_with_disconnects();
            sshc.homedir = b"/home/test".to_vec();
            sshc.authed = true;
            let clock = clock();
            let (mut chains, _transport) =
                chains_with_transport(&clock, socket);
            let mut ctx = transfer_ctx(&mut chains, &clock);
            let mut effects = SftpEffects::new();

            assert_eq!(
                block_on(scp_disconnect(
                    &mut sshc,
                    &mut effects,
                    &mut ctx,
                    dead_connection,
                )),
                Ok(true)
            );
            assert_eq!(sshc.state(), SshState::Stop);
            assert!(sshc.homedir.is_empty());
            assert!(!sshc.authed);
            assert_eq!(
                disconnects.load(std::sync::atomic::Ordering::SeqCst),
                expected_disconnects
            );
            assert_eq!(effects.info, ["SSH session free"]);
        }
    }

    #[test]
    fn the_scp_driver_match_is_exhaustive_over_the_shared_enum() {
        fn owner(state: SshState) -> u8 {
            match state {
                SshState::NoState | SshState::Stop => 0,
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
                | SshState::SftpRealpath => 1,
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
                | SshState::SftpShutdown => 2,
                SshState::ScpTransInit
                | SshState::ScpUploadInit
                | SshState::ScpDownloadInit
                | SshState::ScpDownload
                | SshState::ScpDone
                | SshState::ScpSendEof
                | SshState::ScpWaitEof
                | SshState::ScpWaitClose
                | SshState::ScpChannelFree => 3,
                SshState::SessionDisconnect | SshState::SessionFree => 4,
                SshState::Quit | SshState::Last => 5,
            }
        }

        let owned: Vec<SshState> = sftp::SSH_STATES
            .iter()
            .copied()
            .filter(|state| owner(*state) == 3)
            .collect();
        assert_eq!(owned.len(), 9);
        assert!(owned.iter().all(|state| state.is_scp_owned()));
    }

    #[test]
    fn failure_mapping_is_table_driven_over_every_scp_condition() {
        let cases = [
            (
                ScpFailure::Remote(b"remote refusal".to_vec()),
                CURLcode::RemoteFileNotFound,
                CURLcode::UploadFailed,
            ),
            (
                ScpFailure::Malformed,
                CURLcode::RemoteFileNotFound,
                CURLcode::UploadFailed,
            ),
            (
                ScpFailure::Transport(SshError::ScpProtocol),
                CURLcode::RemoteFileNotFound,
                CURLcode::UploadFailed,
            ),
            (
                ScpFailure::Transport(SshError::Other("generic".to_owned())),
                CURLcode::Ssh,
                CURLcode::UploadFailed,
            ),
            (
                ScpFailure::Transport(SshError::PasswordExpired),
                CURLcode::LoginDenied,
                CURLcode::LoginDenied,
            ),
            (
                ScpFailure::Transport(SshError::HostKey("host key".to_owned())),
                CURLcode::PeerFailedVerification,
                CURLcode::PeerFailedVerification,
            ),
            (
                ScpFailure::Transport(SshError::SocketNone),
                CURLcode::CouldntConnect,
                CURLcode::CouldntConnect,
            ),
            (
                ScpFailure::Transport(SshError::Alloc),
                CURLcode::OutOfMemory,
                CURLcode::OutOfMemory,
            ),
            (
                ScpFailure::Transport(SshError::SocketSend),
                CURLcode::SendError,
                CURLcode::SendError,
            ),
            (
                ScpFailure::Transport(SshError::Timeout),
                CURLcode::OperationTimedout,
                CURLcode::OperationTimedout,
            ),
            (
                ScpFailure::Transport(SshError::Again),
                CURLcode::Again,
                CURLcode::Again,
            ),
        ];

        let mut observed = Vec::new();
        for (failure, expected, upload_expected) in cases {
            assert_eq!(failure.to_curlcode(), expected, "{failure:?}");
            assert_eq!(
                upload_failure_code(&failure),
                upload_expected,
                "{failure:?}"
            );
            observed.push(expected);
        }
        assert!(!observed.contains(&CURLcode::RemoteAccessDenied));
        assert!(!observed.contains(&CURLcode::QuoteError));
        assert!(ScpFailure::Transport(SshError::Again).is_transport());
        assert!(!ScpFailure::Malformed.is_transport());
        assert_eq!(
            ScpFailure::Remote(b"peer text".to_vec()).message(),
            "peer text"
        );
    }

    #[test]
    fn eof_close_and_free_failures_are_informational_only() {
        #[rustfmt::skip]
        let peer_script = b"\x00\x00\x00";
        let (mut scpc, peer, _commands) = scripted_session(peer_script);
        {
            let mut scripted = peer.lock().expect("the peer is available");
            scripted.eof_error = Some(SshError::Other("eof".to_owned()));
            scripted.wait_eof_error =
                Some(SshError::Other("wait eof".to_owned()));
            scripted.wait_close_error =
                Some(SshError::Other("wait close".to_owned()));
            scripted.free_error = Some(SshError::Other("free".to_owned()));
        }
        let clock = clock();
        let (mut chains, _transport) = chains_with_transport(&clock, 53);
        let mut ctx = transfer_ctx(&mut chains, &clock);
        let mut sshc = ssh_conn();
        let mut sshp = SshProto {
            path: b"/remote/empty".to_vec(),
            ..SshProto::default()
        };
        let set = settings(|value| {
            value.upload = true;
            value.infilesize = 0;
        });
        let mut effects = SftpEffects::new();

        ssh_set_state(&mut sshc, None, SshState::ScpTransInit);
        assert_eq!(
            block_on(scp_run_phase(
                &mut sshc,
                &mut scpc,
                &mut sshp,
                &set,
                &mut effects,
                &mut ctx,
                SshPhase::ScpDo,
            )),
            Ok(true)
        );
        ssh_set_state(&mut sshc, None, SshState::ScpDone);
        assert_eq!(
            block_on(scp_run_phase(
                &mut sshc,
                &mut scpc,
                &mut sshp,
                &set,
                &mut effects,
                &mut ctx,
                SshPhase::ScpDone,
            )),
            Ok(true)
        );
        assert_eq!(
            effects.info,
            [
                "Failed to send libssh2 channel EOF: eof",
                "Failed to get channel EOF: wait eof",
                "Channel failed to close: wait close",
                "Failed to free libssh2 scp subsystem: free",
            ]
        );
        assert_eq!(sshc.state(), SshState::Stop);
        assert!(!scpc.has_channel());
    }
}
