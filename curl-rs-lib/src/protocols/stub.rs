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
//! The 24 URL schemes that are REGISTERED for ABI completeness and
//! deliberately not implemented.
//!
//! # What this file supersedes, with locators and measured sizes
//!
//! Thirteen C protocol implementations, none of which is ported:
//!
//! | source | lines | schemes it registers |
//! | ------ | ----: | -------------------- |
//! | `lib/imap.c` | 2,361 | `imap`, `imaps` |
//! | `lib/smtp.c` | 2,041 | `smtp`, `smtps` |
//! | `lib/pop3.c` | 1,749 | `pop3`, `pop3s` |
//! | `lib/telnet.c` | 1,608 | `telnet` |
//! | `lib/tftp.c` | 1,371 | `tftp` |
//! | `lib/openldap.c` | 1,287 | (the LDAP back end) |
//! | `lib/smb.c` | 1,262 | `smb`, `smbs` |
//! | `lib/rtsp.c` | 1,084 | `rtsp` |
//! | `lib/mqtt.c` | 1,043 | `mqtt`, `mqtts` |
//! | `lib/ldap.c` | 1,035 | `ldap`, `ldaps` |
//! | `lib/curl_rtmp.c` | 326 | the six RTMP spellings |
//! | `lib/dict.c` | 314 | `dict` |
//! | `lib/gopher.c` | 243 | `gopher`, `gophers` |
//!
//! Every per-file figure above is `wc -l` over this checkout and matches
//! specification 0.2.2 row for row. **Their sum is 15,724**, and it is written
//! here as measured: specification 0.2.2 totals the same thirteen rows as
//! 17,724, which the enumeration does not support -- the twelve companion
//! headers only carry the figure to 16,096. The per-file counts are the
//! evidence; the total is arithmetic over them.
//!
//! What is superseded is the REGISTRATION, not the behaviour: each of those
//! files ends in one or two `const struct Curl_scheme` definitions, and those
//! definitions -- their names, protocol bits, family bits, `PROTOPT_*` flags
//! and default ports -- are what [`SCHEMES`] below reproduces. The transfer
//! logic above them is excluded from implementation by specification 0.2.2 and
//! is not reproduced anywhere.
//!
//! Read rather than superseded:
//!
//! * `lib/url.c:1543-1573` -- `findprotocol`, which decides what a caller sees
//!   for one of these schemes. Quoted in full below, because every observable
//!   consequence of this file follows from it.
//! * `lib/url.c:1474-1477` -- `Curl_getn_scheme`'s contract: *"Returns a struct
//!   scheme pointer if the name is a known scheme. Check the ->run struct field
//!   for non-NULL to figure out if an implementation is present."*
//! * `lib/url.c:1488-1522` -- `all_schemes[67]`, which registers all 33 rows
//!   including every one of these 24.
//! * `lib/dict.c:278-296` -- `Curl_protocol_dict`, the 17-slot vtable with only
//!   `do_it` set. That is what an ENABLED dict looks like, and it is exactly
//!   what this file does NOT write.
//! * `lib/dict.c:303-314` -- `Curl_scheme_dict`, whose `run` member is
//!   `ZERO_NULL` under `#ifdef CURL_DISABLE_DICT` (`:305-306`) *while the row
//!   stays registered*. The C's own idiom for a compiled-out protocol, and the
//!   precedent this whole file follows. The `#endif` that closes the
//!   compiled-out region is `:298`, so everything between the vtable and the
//!   registration disappears with the feature while the registration itself
//!   does not -- which is precisely the state this module reproduces.
//! * `include/curl/curl.h:1076-1107` -- the 32 public `CURLPROTO_*` values: 31
//!   protocol bits plus `CURLPROTO_ALL`. Twenty-four of those bits belong to
//!   the rows below and remain in the public header whatever this build does,
//!   because specification 0.8.2 forbids removing public ABI.
//!
//! # `run: None` is the entire mechanism, and it must not be "improved"
//!
//! `findprotocol` (`lib/url.c:1543-1573`) is the whole of the observable
//! behaviour:
//!
//! ```c
//! const struct Curl_scheme *p = Curl_get_scheme(protostr);
//! if(p && p->run && (data->set.allowed_protocols & p->protocol)) {
//!   if(data->state.this_is_a_follow &&
//!      !(data->set.redir_protocols & p->protocol))
//!     ;
//!   else {
//!     conn->scheme = conn->given = p;
//!     return CURLE_OK;
//!   }
//! }
//! failf(data, "Protocol \"%s\" %s%s", protostr,
//!       p ? "disabled" : "not supported",
//!       data->state.this_is_a_follow ? " (in redirect)" : "");
//! return CURLE_UNSUPPORTED_PROTOCOL;
//! ```
//!
//! Read the `p ? ... : ...` carefully, because it decides which of two
//! user-visible strings a scheme produces:
//!
//! * A name the table KNOWS, whose `run` is NULL, is **found and then
//!   rejected**: `Protocol "smtp" disabled`.
//! * A name the table does not know at all is `Protocol "xyz" not supported`.
//! * Either way, following a redirect appends `" (in redirect)"`, giving
//!   `Protocol "smtp" disabled (in redirect)`.
//! * Either way, the returned code is `CURLE_UNSUPPORTED_PROTOCOL`.
//!
//! So the 24 rows below carry `run: None` and **this module implements no
//! [`Protocol`](super::Protocol) at all**. Three tempting alternatives are all
//! wrong, and each is wrong in a way a test here catches:
//!
//! 1. *Omitting the rows.* The scheme would then be unknown, the message would
//!    change to `not supported`, and `CURLOPT_PROTOCOLS_STR` could no longer
//!    name it.
//! 2. *Writing an empty `Protocol` impl.* `p->run` becomes non-NULL, so
//!    `findprotocol` SUCCEEDS and the failure moves to a later stage with
//!    different text and a different code -- a different observable behaviour,
//!    which specification 0.8.1 freezes.
//! 3. *Writing a `Protocol` impl whose `do_it` returns
//!    `CURLE_UNSUPPORTED_PROTOCOL`.* Same defect as 2: the code happens to
//!    match, the message does not, and the transfer has already been set up by
//!    the time it fails.
//!
//! The C reaches the same state by the same means: `lib/dict.c:305-306` writes
//! `ZERO_NULL` into `run` under `#ifdef CURL_DISABLE_DICT` and leaves the row
//! registered. This file is that configuration for 24 schemes at once.
//!
//! # Truthful advertisement is what makes 283 fixtures skip
//!
//! Registration is deliberately NOT advertisement. [`crate::version`]'s
//! `PROTOCOLS` table carries a row for each of the nine schemes specification
//! 0.2.1 puts in scope and for none of these 24, so `curl --version` never
//! names them on its `Protocols:` line.
//!
//! That asymmetry is measured in specification 0.6.5 and it is not symmetric:
//! **under-reporting a capability makes a fixture SKIP, over-reporting makes it
//! RUN AND FAIL.** `tests/runtests.pl` parses the banner at start-up and feeds
//! `Protocols:` to `parseprotocols()` to decide which fixtures are eligible.
//! The 283 fixtures targeting these schemes -- 14.8% of the 1,914-fixture
//! corpus: `smtp` 91, `imap` 73, `pop3` 54, `mqtt` 22, `tftp` 18, `rtsp` 10,
//! `gopher` 6, `telnet` 4, `smb` 2, `dict` 2, `ldap` 1 -- therefore skip
//! cleanly. A fixture from that set that RUNS is evidence the banner is
//! over-reporting, and the fix is the banner: specification 0.8.1 makes the
//! fixtures immutable.
//!
//! Nothing here exports a name list that would make adding these schemes to the
//! banner convenient. [`SCHEMES`] is a registry row array whose consumer is the
//! lookup in [`super`], and `crate::version` builds its own lower-case literals
//! from `lib/version.c:302`'s `supported_protocols[]` rather than from a table
//! in this directory.
//!
//! # Unconditional, and `pub(crate)`
//!
//! `super` declares this module with no `#[cfg]`. The registry must be 33 rows
//! long under every feature combination, including `--no-default-features`:
//! `curl_easy_setopt(CURLOPT_URL, "smtp://...")` has to answer
//! `CURLE_UNSUPPORTED_PROTOCOL` rather than fail to compile, and
//! `CURLOPT_PROTOCOLS_STR` has to keep accepting the names whatever this build
//! implements. Nothing below is feature-gated for the same reason.
//!
//! Everything is `pub(crate)`: no symbol of `lib/libcurl.def` resolves a name
//! here, and a scheme is selected by URL rather than named by a caller.
//!
//! # Safety
//!
//! No `unsafe` anywhere -- this module is a data table. It also names no TLS
//! type: three of these rows carry `PROTOPT_SSL` and two more carry
//! `PROTOPT_SSL_REUSE`, and both are flags on a row rather than a session, so
//! `crate::tls` has no business being imported here.

use crate::conn::ProtocolOptions;

use super::{
    protopt, Proto, Scheme, PORT_DICT, PORT_GOPHER, PORT_IMAP, PORT_IMAPS,
    PORT_LDAP, PORT_LDAPS, PORT_MQTT, PORT_MQTTS, PORT_POP3, PORT_POP3S,
    PORT_RTMP, PORT_RTMPS, PORT_RTMPT, PORT_RTSP, PORT_SMB, PORT_SMBS,
    PORT_SMTP, PORT_SMTPS, PORT_TELNET, PORT_TFTP,
};

/// How many schemes this module registers.
///
/// Twenty-four, reconciled by C source file: `dict` 1, `gopher` 2, `imap` 2,
/// `ldap` 2, `mqtt` 2, `pop3` 2, `rtmp` 6, `rtsp` 1, `smb` 2, `smtp` 2,
/// `telnet` 1, `tftp` 1. With the nine schemes specification 0.2.1 puts in
/// scope that is 9 + 24 = 33, which is the number of non-NULL entries in
/// `all_schemes[67]` (`lib/url.c:1488-1522`) -- and 67 is that array's hash
/// modulus, never a count.
pub(crate) const STUB_SCHEME_COUNT: usize = 24;

// The `PROTOPT_*` masks, one per distinct C registration
//
// `crate::conn::ProtocolOptions` owns all 17 bits and `super::protopt` folds a
// list of them in a `const` context; both are CONSUMED here so that a flag
// cannot acquire a second definition. Each constant is written as the LIST the
// C writes with `|`, in the C's order, which is what makes the two readable
// side by side.

/// `lib/smtp.c:2021-2022`: `PROTOPT_CLOSEACTION | PROTOPT_NOURLQUERY |
/// PROTOPT_URLOPTIONS | PROTOPT_SSL_REUSE | PROTOPT_CONN_REUSE`.
const FLAGS_SMTP: ProtocolOptions = protopt(&[
    ProtocolOptions::CLOSEACTION,
    ProtocolOptions::NOURLQUERY,
    ProtocolOptions::URLOPTIONS,
    ProtocolOptions::SSL_REUSE,
    ProtocolOptions::CONN_REUSE,
]);

/// `lib/smtp.c:2038-2039`: [`FLAGS_SMTP`] with `PROTOPT_SSL` in place of
/// `PROTOPT_SSL_REUSE`.
///
/// The substitution is the pattern every `s`-suffixed mail scheme follows: a
/// scheme that IS TLS needs no permission to borrow another's session.
const FLAGS_SMTPS: ProtocolOptions = protopt(&[
    ProtocolOptions::CLOSEACTION,
    ProtocolOptions::SSL,
    ProtocolOptions::NOURLQUERY,
    ProtocolOptions::URLOPTIONS,
    ProtocolOptions::CONN_REUSE,
]);

/// `lib/imap.c:2340-2342`: `PROTOPT_CLOSEACTION | PROTOPT_URLOPTIONS |
/// PROTOPT_SSL_REUSE | PROTOPT_CONN_REUSE`.
///
/// No `PROTOPT_NOURLQUERY`, unlike every other mail scheme: an IMAP URL's
/// `?`-tail IS a query, and `lib/imap.c` parses it.
const FLAGS_IMAP: ProtocolOptions = protopt(&[
    ProtocolOptions::CLOSEACTION,
    ProtocolOptions::URLOPTIONS,
    ProtocolOptions::SSL_REUSE,
    ProtocolOptions::CONN_REUSE,
]);

/// `lib/imap.c:2358-2359`: [`FLAGS_IMAP`] with `PROTOPT_SSL` for
/// `PROTOPT_SSL_REUSE`.
const FLAGS_IMAPS: ProtocolOptions = protopt(&[
    ProtocolOptions::CLOSEACTION,
    ProtocolOptions::SSL,
    ProtocolOptions::URLOPTIONS,
    ProtocolOptions::CONN_REUSE,
]);

/// `lib/pop3.c:1729-1730`: the same five bits as [`FLAGS_SMTP`].
const FLAGS_POP3: ProtocolOptions = protopt(&[
    ProtocolOptions::CLOSEACTION,
    ProtocolOptions::NOURLQUERY,
    ProtocolOptions::URLOPTIONS,
    ProtocolOptions::SSL_REUSE,
    ProtocolOptions::CONN_REUSE,
]);

/// `lib/pop3.c:1746-1747`: the same five bits as [`FLAGS_SMTPS`].
const FLAGS_POP3S: ProtocolOptions = protopt(&[
    ProtocolOptions::CLOSEACTION,
    ProtocolOptions::SSL,
    ProtocolOptions::NOURLQUERY,
    ProtocolOptions::URLOPTIONS,
    ProtocolOptions::CONN_REUSE,
]);

/// `lib/telnet.c:1606`: `PROTOPT_NONE | PROTOPT_NOURLQUERY`.
///
/// The C writes the redundant `PROTOPT_NONE` explicitly. It is the identity, so
/// the mask is `NOURLQUERY` alone; the list keeps the C's shape.
const FLAGS_TELNET: ProtocolOptions =
    protopt(&[ProtocolOptions::NONE, ProtocolOptions::NOURLQUERY]);

/// `lib/tftp.c:1369`: `PROTOPT_NOTCPPROXY | PROTOPT_NOURLQUERY`.
///
/// `PROTOPT_NOTCPPROXY` appears on this row and on NO other of the 33, here or
/// in the C: TFTP runs over UDP, so a TCP proxy cannot carry it. Asserted over
/// the whole assembled registry by [`mod tests`](self).
const FLAGS_TFTP: ProtocolOptions =
    protopt(&[ProtocolOptions::NOTCPPROXY, ProtocolOptions::NOURLQUERY]);

/// `lib/smb.c:1243`: `PROTOPT_CONN_REUSE` alone.
const FLAGS_SMB: ProtocolOptions = protopt(&[ProtocolOptions::CONN_REUSE]);

/// `lib/smb.c:1260`: `PROTOPT_SSL | PROTOPT_CONN_REUSE`.
const FLAGS_SMBS: ProtocolOptions =
    protopt(&[ProtocolOptions::SSL, ProtocolOptions::CONN_REUSE]);

/// `lib/ldap.c:1017`: `PROTOPT_SSL_REUSE` alone -- and notably NO
/// `PROTOPT_CONN_REUSE`, which makes `ldap` the only non-`file` row that may
/// borrow a TLS session yet never reuse a connection.
const FLAGS_LDAP: ProtocolOptions = protopt(&[ProtocolOptions::SSL_REUSE]);

/// `lib/ldap.c:1033`: `PROTOPT_SSL` alone.
const FLAGS_LDAPS: ProtocolOptions = protopt(&[ProtocolOptions::SSL]);

/// `lib/rtsp.c:1082`: `PROTOPT_CONN_REUSE` alone.
const FLAGS_RTSP: ProtocolOptions = protopt(&[ProtocolOptions::CONN_REUSE]);

/// `lib/mqtt.c:1041`: `PROTOPT_NONE`.
const FLAGS_MQTT: ProtocolOptions = protopt(&[ProtocolOptions::NONE]);

/// `lib/mqtt.c:1024`: `PROTOPT_SSL`.
const FLAGS_MQTTS: ProtocolOptions = protopt(&[ProtocolOptions::SSL]);

/// `lib/curl_rtmp.c:259`, `:272`, `:285`, `:298`, `:311` and `:324`:
/// `PROTOPT_NONE`, for all six RTMP rows.
///
/// One constant for the six because the C registers `PROTOPT_NONE` for every
/// one of them -- including `rtmps` and `rtmpts`, which carry NO `PROTOPT_SSL`
/// because librtmp performs its own transport security rather than sitting on
/// curl's TLS filter.
const FLAGS_RTMP: ProtocolOptions = protopt(&[ProtocolOptions::NONE]);

/// `lib/dict.c:312`: `PROTOPT_NONE | PROTOPT_NOURLQUERY`.
const FLAGS_DICT: ProtocolOptions =
    protopt(&[ProtocolOptions::NONE, ProtocolOptions::NOURLQUERY]);

/// `lib/gopher.c:228`: `PROTOPT_NONE`.
const FLAGS_GOPHER: ProtocolOptions = protopt(&[ProtocolOptions::NONE]);

/// `lib/gopher.c:241`: `PROTOPT_SSL`.
const FLAGS_GOPHERS: ProtocolOptions = protopt(&[ProtocolOptions::SSL]);

/// The 24 schemes registered for ABI completeness, in the C's registration
/// order.
///
/// Grouped by the C source that defines each row, which is the order
/// specification 0.2.2 enumerates them in and the order [`super`]'s registry
/// appends them in: `lib/smtp.c`, `lib/imap.c`, `lib/pop3.c`, `lib/telnet.c`,
/// `lib/tftp.c`, `lib/smb.c`, `lib/ldap.c`, `lib/rtsp.c`, `lib/mqtt.c`,
/// `lib/curl_rtmp.c`, `lib/dict.c`, `lib/gopher.c`. The order is observable
/// through nothing -- the lookup compares names -- but it is asserted, so a row
/// cannot be quietly moved and lose its correspondence with the C.
///
/// `#[rustfmt::skip]` because every column is ABI-bearing and the alignment is
/// what makes the table auditable against the C side by side. A formatter that
/// rewrapped these rows would also be free to reflow the scheme-name bytes.
///
/// # Six things a reader should not try to tidy
///
/// * **Every `run` is [`None`]**, which is the whole mechanism -- see this
///   module's documentation.
/// * **All 24 names are lower case**, and all are at most seven bytes. The four
///   UPPER CASE names in the registry -- `"SFTP"`, `"SCP"`, `"WS"` and `"WSS"`
///   -- are in-scope rows and belong to [`super`]. Seven bytes matters:
///   `Curl_getn_scheme`'s `if(len && (len <= 7))` gate (`lib/url.c:1524`)
///   rejects a longer name before the table is consulted, and `"gophers"` sits
///   exactly on the bound.
/// * **`gophers` has its own vtable in the C**, `Curl_protocol_gophers`
///   (`lib/gopher.c:196`), rather than sharing `gopher`'s -- unlike `imaps`,
///   `pop3s`, `smtps`, `smbs` and `ldaps`, each of which points at its
///   non-TLS sibling's. Both rows become `run: None` here, so the distinction
///   survives only as this note.
/// * **The six RTMP rows have FOUR distinct families**: `rtmp` and `rtmps` are
///   `RTMP`, `rtmpt` and `rtmpts` are `RTMPT`, `rtmpe` is `RTMPE` and `rtmpte`
///   is `RTMPTE`. Collapsing them would change which rows the connection pool
///   considers related.
/// * **`smb` and `smbs` share port 445.** `PORT_SMBS` really is 445 in
///   `lib/urldata.h:44`; the TLS spelling has no port of its own.
/// * **`mqtts` and the internal `ws` are the same protocol bit**, `1 << 30`.
///   [`Proto`] documents the collision and [`mod tests`](self) asserts it, so
///   that renumbering a public integer is not mistaken for a repair.
#[rustfmt::skip]
pub(crate) const SCHEMES: [Scheme; STUB_SCHEME_COUNT] = [
    // -- lib/smtp.c:2012-2041 ------------------------------------------------
    Scheme { name: b"smtp",    run: None, protocol: Proto::SMTP,    family: Proto::SMTP,    flags: FLAGS_SMTP,    defport: PORT_SMTP },
    Scheme { name: b"smtps",   run: None, protocol: Proto::SMTPS,   family: Proto::SMTP,    flags: FLAGS_SMTPS,   defport: PORT_SMTPS },
    // -- lib/imap.c:2331-2361 ------------------------------------------------
    Scheme { name: b"imap",    run: None, protocol: Proto::IMAP,    family: Proto::IMAP,    flags: FLAGS_IMAP,    defport: PORT_IMAP },
    Scheme { name: b"imaps",   run: None, protocol: Proto::IMAPS,   family: Proto::IMAP,    flags: FLAGS_IMAPS,   defport: PORT_IMAPS },
    // -- lib/pop3.c:1720-1749 ------------------------------------------------
    Scheme { name: b"pop3",    run: None, protocol: Proto::POP3,    family: Proto::POP3,    flags: FLAGS_POP3,    defport: PORT_POP3 },
    Scheme { name: b"pop3s",   run: None, protocol: Proto::POP3S,   family: Proto::POP3,    flags: FLAGS_POP3S,   defport: PORT_POP3S },
    // -- lib/telnet.c:1597-1608 ----------------------------------------------
    Scheme { name: b"telnet",  run: None, protocol: Proto::TELNET,  family: Proto::TELNET,  flags: FLAGS_TELNET,  defport: PORT_TELNET },
    // -- lib/tftp.c:1360-1371 ------------------------------------------------
    Scheme { name: b"tftp",    run: None, protocol: Proto::TFTP,    family: Proto::TFTP,    flags: FLAGS_TFTP,    defport: PORT_TFTP },
    // -- lib/smb.c:1234-1262 -------------------------------------------------
    Scheme { name: b"smb",     run: None, protocol: Proto::SMB,     family: Proto::SMB,     flags: FLAGS_SMB,     defport: PORT_SMB },
    Scheme { name: b"smbs",    run: None, protocol: Proto::SMBS,    family: Proto::SMB,     flags: FLAGS_SMBS,    defport: PORT_SMBS },
    // -- lib/ldap.c:1008-1035 ------------------------------------------------
    Scheme { name: b"ldap",    run: None, protocol: Proto::LDAP,    family: Proto::LDAP,    flags: FLAGS_LDAP,    defport: PORT_LDAP },
    Scheme { name: b"ldaps",   run: None, protocol: Proto::LDAPS,   family: Proto::LDAP,    flags: FLAGS_LDAPS,   defport: PORT_LDAPS },
    // -- lib/rtsp.c:1073-1084 ------------------------------------------------
    Scheme { name: b"rtsp",    run: None, protocol: Proto::RTSP,    family: Proto::RTSP,    flags: FLAGS_RTSP,    defport: PORT_RTSP },
    // -- lib/mqtt.c:1015-1043 ------------------------------------------------
    Scheme { name: b"mqtt",    run: None, protocol: Proto::MQTT,    family: Proto::MQTT,    flags: FLAGS_MQTT,    defport: PORT_MQTT },
    Scheme { name: b"mqtts",   run: None, protocol: Proto::MQTTS,   family: Proto::MQTT,    flags: FLAGS_MQTTS,   defport: PORT_MQTTS },
    // -- lib/curl_rtmp.c:250-326 ---------------------------------------------
    Scheme { name: b"rtmp",    run: None, protocol: Proto::RTMP,    family: Proto::RTMP,    flags: FLAGS_RTMP,    defport: PORT_RTMP },
    Scheme { name: b"rtmpt",   run: None, protocol: Proto::RTMPT,   family: Proto::RTMPT,   flags: FLAGS_RTMP,    defport: PORT_RTMPT },
    Scheme { name: b"rtmpe",   run: None, protocol: Proto::RTMPE,   family: Proto::RTMPE,   flags: FLAGS_RTMP,    defport: PORT_RTMP },
    Scheme { name: b"rtmpte",  run: None, protocol: Proto::RTMPTE,  family: Proto::RTMPTE,  flags: FLAGS_RTMP,    defport: PORT_RTMPT },
    Scheme { name: b"rtmps",   run: None, protocol: Proto::RTMPS,   family: Proto::RTMP,    flags: FLAGS_RTMP,    defport: PORT_RTMPS },
    Scheme { name: b"rtmpts",  run: None, protocol: Proto::RTMPTS,  family: Proto::RTMPT,   flags: FLAGS_RTMP,    defport: PORT_RTMPS },
    // -- lib/dict.c:303-314 --------------------------------------------------
    Scheme { name: b"dict",    run: None, protocol: Proto::DICT,    family: Proto::DICT,    flags: FLAGS_DICT,    defport: PORT_DICT },
    // -- lib/gopher.c:219-243 ------------------------------------------------
    Scheme { name: b"gopher",  run: None, protocol: Proto::GOPHER,  family: Proto::GOPHER,  flags: FLAGS_GOPHER,  defport: PORT_GOPHER },
    Scheme { name: b"gophers", run: None, protocol: Proto::GOPHERS, family: Proto::GOPHER,  flags: FLAGS_GOPHERS, defport: PORT_GOPHER },
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CURLcode;
    use crate::protocols::{
        findprotocol, get_scheme, MAX_RESOLVABLE_SCHEME_LEN,
    };
    // The ASSEMBLED 33-row registry, reached under a second name so that
    // `SCHEMES` keeps meaning this module's 24 rows. Private to
    // `crate::protocols` and therefore visible here, this module being one of
    // its descendants.
    use crate::protocols::SCHEMES as REGISTRY;

    /// Every row of [`SCHEMES`], transcribed a SECOND time straight from the C
    /// registrations, as `(name, protocol, family, PROTOPT_* list, defport)`.
    ///
    /// Independent of the production table on purpose: comparing that table
    /// against itself would assert nothing. The flags are a LIST rather than a
    /// folded mask so that the expectation reads like the C's `|` expression,
    /// and the ports are LITERALS rather than the `PORT_*` constants so that a
    /// constant with the wrong value cannot satisfy both sides.
    ///
    /// `#[rustfmt::skip]` for the same reason the production table carries it.
    #[rustfmt::skip]
    const EXPECTED: [(&str, Proto, Proto, &[ProtocolOptions], u16); 24] = [
        // lib/smtp.c:2012-2041
        ("smtp",    Proto::SMTP,    Proto::SMTP,    &[ProtocolOptions::CLOSEACTION, ProtocolOptions::NOURLQUERY, ProtocolOptions::URLOPTIONS, ProtocolOptions::SSL_REUSE, ProtocolOptions::CONN_REUSE], 25),
        ("smtps",   Proto::SMTPS,   Proto::SMTP,    &[ProtocolOptions::CLOSEACTION, ProtocolOptions::SSL, ProtocolOptions::NOURLQUERY, ProtocolOptions::URLOPTIONS, ProtocolOptions::CONN_REUSE], 465),
        // lib/imap.c:2331-2361
        ("imap",    Proto::IMAP,    Proto::IMAP,    &[ProtocolOptions::CLOSEACTION, ProtocolOptions::URLOPTIONS, ProtocolOptions::SSL_REUSE, ProtocolOptions::CONN_REUSE], 143),
        ("imaps",   Proto::IMAPS,   Proto::IMAP,    &[ProtocolOptions::CLOSEACTION, ProtocolOptions::SSL, ProtocolOptions::URLOPTIONS, ProtocolOptions::CONN_REUSE], 993),
        // lib/pop3.c:1720-1749
        ("pop3",    Proto::POP3,    Proto::POP3,    &[ProtocolOptions::CLOSEACTION, ProtocolOptions::NOURLQUERY, ProtocolOptions::URLOPTIONS, ProtocolOptions::SSL_REUSE, ProtocolOptions::CONN_REUSE], 110),
        ("pop3s",   Proto::POP3S,   Proto::POP3,    &[ProtocolOptions::CLOSEACTION, ProtocolOptions::SSL, ProtocolOptions::NOURLQUERY, ProtocolOptions::URLOPTIONS, ProtocolOptions::CONN_REUSE], 995),
        // lib/telnet.c:1597-1608
        ("telnet",  Proto::TELNET,  Proto::TELNET,  &[ProtocolOptions::NONE, ProtocolOptions::NOURLQUERY], 23),
        // lib/tftp.c:1360-1371
        ("tftp",    Proto::TFTP,    Proto::TFTP,    &[ProtocolOptions::NOTCPPROXY, ProtocolOptions::NOURLQUERY], 69),
        // lib/smb.c:1234-1262
        ("smb",     Proto::SMB,     Proto::SMB,     &[ProtocolOptions::CONN_REUSE], 445),
        ("smbs",    Proto::SMBS,    Proto::SMB,     &[ProtocolOptions::SSL, ProtocolOptions::CONN_REUSE], 445),
        // lib/ldap.c:1008-1035
        ("ldap",    Proto::LDAP,    Proto::LDAP,    &[ProtocolOptions::SSL_REUSE], 389),
        ("ldaps",   Proto::LDAPS,   Proto::LDAP,    &[ProtocolOptions::SSL], 636),
        // lib/rtsp.c:1073-1084
        ("rtsp",    Proto::RTSP,    Proto::RTSP,    &[ProtocolOptions::CONN_REUSE], 554),
        // lib/mqtt.c:1015-1043
        ("mqtt",    Proto::MQTT,    Proto::MQTT,    &[ProtocolOptions::NONE], 1883),
        ("mqtts",   Proto::MQTTS,   Proto::MQTT,    &[ProtocolOptions::SSL], 8883),
        // lib/curl_rtmp.c:250-326
        ("rtmp",    Proto::RTMP,    Proto::RTMP,    &[ProtocolOptions::NONE], 1935),
        ("rtmpt",   Proto::RTMPT,   Proto::RTMPT,   &[ProtocolOptions::NONE], 80),
        ("rtmpe",   Proto::RTMPE,   Proto::RTMPE,   &[ProtocolOptions::NONE], 1935),
        ("rtmpte",  Proto::RTMPTE,  Proto::RTMPTE,  &[ProtocolOptions::NONE], 80),
        ("rtmps",   Proto::RTMPS,   Proto::RTMP,    &[ProtocolOptions::NONE], 443),
        ("rtmpts",  Proto::RTMPTS,  Proto::RTMPT,   &[ProtocolOptions::NONE], 443),
        // lib/dict.c:303-314
        ("dict",    Proto::DICT,    Proto::DICT,    &[ProtocolOptions::NONE, ProtocolOptions::NOURLQUERY], 2628),
        // lib/gopher.c:219-243
        ("gopher",  Proto::GOPHER,  Proto::GOPHER,  &[ProtocolOptions::NONE], 70),
        ("gophers", Proto::GOPHERS, Proto::GOPHER,  &[ProtocolOptions::SSL], 70),
    ];

    /// The nine names [`crate::protocols`] registers for the schemes
    /// specification 0.2.1 puts in scope, spelled as its table spells them --
    /// upper case included.
    const IN_SCOPE: [&str; 9] = [
        "http", "https", "ftp", "ftps", "SFTP", "SCP", "file", "WS", "WSS",
    ];

    /// The six schemes whose C registration carries `PROTOPT_URLOPTIONS`.
    const MAIL: [&str; 6] = ["smtp", "smtps", "imap", "imaps", "pop3", "pop3s"];

    /// Folds an expectation's `PROTOPT_*` list the way the C's `|` does.
    fn fold(list: &[ProtocolOptions]) -> ProtocolOptions {
        let mut mask = ProtocolOptions::NONE;
        for option in list {
            mask = mask.union(*option);
        }
        mask
    }

    #[test]
    fn there_are_exactly_twenty_four_rows() {
        assert_eq!(SCHEMES.len(), STUB_SCHEME_COUNT);
        assert_eq!(STUB_SCHEME_COUNT, 24);
        assert_eq!(EXPECTED.len(), 24);
    }

    #[test]
    fn nine_in_scope_plus_these_twenty_four_are_the_c_registry() {
        // `all_schemes[67]` (`lib/url.c:1488-1522`) holds 33 non-NULL entries,
        // and 67 is the hash modulus rather than a count. The arithmetic is
        // asserted against the ASSEMBLED registry rather than restated, so a
        // row added on either side of the seam is caught here.
        assert_eq!(IN_SCOPE.len(), 9);
        assert_eq!(IN_SCOPE.len() + SCHEMES.len(), 33);
        assert_eq!(REGISTRY.len(), 33);
    }

    #[test]
    fn the_registry_appends_these_rows_after_the_nine_in_scope_ones() {
        // The seam itself: the assembled table's first nine rows are the
        // in-scope names, and its last 24 are these, in this order. A
        // reordering inside the assembly would leave every individual column
        // correct and still break the correspondence with the C.
        for (row, name) in REGISTRY.iter().take(IN_SCOPE.len()).zip(IN_SCOPE) {
            assert_eq!(row.name, name.as_bytes());
        }

        let tail = &REGISTRY[IN_SCOPE.len()..];
        assert_eq!(tail.len(), SCHEMES.len());
        for (assembled, mine) in tail.iter().zip(SCHEMES.iter()) {
            assert_eq!(assembled.name, mine.name);
            assert_eq!(assembled.protocol, mine.protocol);
            assert_eq!(assembled.family, mine.family);
            assert_eq!(assembled.flags, mine.flags);
            assert_eq!(assembled.defport, mine.defport);
            assert!(assembled.run.is_none());
        }
    }

    #[test]
    fn every_row_matches_the_c_registration() {
        // The WHOLE table, column by column, in the C's registration order --
        // not a sample. A single transposed flag or port is the kind of defect
        // that surfaces only as a wrong default port or a wrongly reused
        // connection, long after this file is forgotten.
        assert_eq!(SCHEMES.len(), EXPECTED.len());

        for (row, expected) in SCHEMES.iter().zip(EXPECTED) {
            let (name, protocol, family, flags, defport) = expected;
            assert_eq!(
                row.name,
                name.as_bytes(),
                "the table is out of the C's registration order at {name}"
            );
            assert_eq!(row.protocol, protocol, "{name}'s protocol column");
            assert_eq!(row.family, family, "{name}'s family column");
            assert_eq!(row.flags, fold(flags), "{name}'s PROTOPT_* column");
            assert_eq!(row.defport, defport, "{name}'s default port");
        }
    }

    #[test]
    fn every_row_carries_no_implementation() {
        // The whole mechanism, asserted: `run: None` is what makes
        // `findprotocol`'s `p->run` gate refuse, and an implementation
        // appearing on any row here would change the user-visible message.
        for row in SCHEMES.iter() {
            // The name is rendered BEFORE the assertion rather than inside its
            // message, here and throughout this module: a message argument is
            // evaluated only on failure, so it would be an uncovered line in a
            // passing run. Rendering it eagerly keeps this file at full line
            // coverage, which is the specification 0.8.4 gate this directory
            // has to clear.
            let name = String::from_utf8_lossy(row.name);
            assert!(row.run.is_none(), "{name} must carry no implementation");
        }
    }

    #[test]
    fn no_row_is_in_core_scope_and_none_is_runnable() {
        // The production guard, independent of `run`: even if somebody wired an
        // executor to one of these rows, `Scheme::runnable` conjoins
        // `in_core_scope`, so the row still could not run. `mqtts` is the row
        // that makes this worth asserting -- it shares bit 30 with the
        // in-scope `ws`, so the protocol column alone would report it in scope.
        for row in SCHEMES.iter() {
            let name = String::from_utf8_lossy(row.name);
            assert!(!row.in_core_scope(), "{name} must be out of core scope");
            assert!(!row.runnable(), "{name} must not be runnable");
        }
    }

    #[test]
    fn every_protocol_and_family_column_is_a_single_bit() {
        // `struct Curl_scheme`'s own comments: *"this needs to be the single
        // specific protocol bit"* and *"single bit for protocol family"*
        // (`lib/urldata.h:517-521`). A mask in either column would make the
        // `allowed_protocols` gate and the pool's family match answer for
        // schemes they were never meant to.
        for row in SCHEMES.iter() {
            let name = String::from_utf8_lossy(row.name);
            assert!(row.protocol.is_single_bit(), "{name}'s protocol column");
            assert!(row.family.is_single_bit(), "{name}'s family column");
        }
    }

    #[test]
    fn every_name_is_lower_case_and_at_most_seven_bytes() {
        // Lower case because the C spells all 24 that way; at most seven bytes
        // because `Curl_getn_scheme`'s `if(len && (len <= 7))` gate
        // (`lib/url.c:1524`) rejects a longer name before the table is
        // consulted, so an eight-byte row would be unreachable.
        for name in SCHEMES.iter().map(|row| row.name) {
            let shown = String::from_utf8_lossy(name);
            assert!(
                name.iter().all(|byte| !byte.is_ascii_uppercase()),
                "{shown} must be lower case"
            );
            let len = name.len();
            assert!(
                !name.is_empty() && len <= MAX_RESOLVABLE_SCHEME_LEN,
                "{shown} is {len} bytes, past the lookup's bound"
            );
        }

        // And the bound is actually reached -- `gophers` sits exactly on it --
        // so the assertion above is discriminating rather than vacuous.
        assert!(SCHEMES
            .iter()
            .any(|row| row.name.len() == MAX_RESOLVABLE_SCHEME_LEN));
    }

    #[test]
    fn no_name_repeats_and_none_collides_with_an_in_scope_scheme() {
        // Folded comparisons throughout, because the lookup folds: a row
        // spelled `SMTP` would collide with `smtp` even though the bytes
        // differ, and a row colliding with an in-scope name would shadow a
        // scheme this build can actually serve.
        for (index, row) in SCHEMES.iter().enumerate() {
            let mine = String::from_utf8_lossy(row.name);
            for other in SCHEMES.iter().skip(index + 1) {
                let theirs = String::from_utf8_lossy(other.name);
                assert!(
                    !row.name.eq_ignore_ascii_case(other.name),
                    "{mine} and {theirs} collide when folded"
                );
            }
            for in_scope in IN_SCOPE {
                assert!(
                    !row.name.eq_ignore_ascii_case(in_scope.as_bytes()),
                    "{in_scope} is in scope and must not be registered here",
                );
            }
        }
    }

    #[test]
    fn every_name_resolves_through_the_registry_lookup() {
        // Registration is only useful if the lookup finds it, and the lookup
        // folds case: `SMTP://` must resolve to the `smtp` row exactly as
        // `curl_strnequal` makes it in the C.
        for row in SCHEMES.iter() {
            let found =
                get_scheme(row.name).expect("a registered name must resolve");
            assert_eq!(found.name, row.name);
            assert_eq!(found.protocol, row.protocol);

            let upper = String::from_utf8_lossy(row.name).to_uppercase();
            let folded =
                get_scheme(upper.as_bytes()).expect("the lookup folds case");
            assert_eq!(folded.name, row.name);
        }
    }

    #[test]
    fn a_stub_scheme_is_found_and_then_rejected_as_disabled() {
        // The observable consequence of `run: None`, asserted BYTE FOR BYTE for
        // every one of the 24 rows -- `lib/url.c:1568-1570` writes
        // `Protocol "%s" %s%s` with `p ? "disabled" : "not supported"`, and a
        // row that IS in the table takes the first branch. Both protocol masks
        // are `CURLPROTO_ALL`, so gates 2 and 3 cannot be what refuses.
        for row in SCHEMES.iter() {
            let name = String::from_utf8_lossy(row.name).into_owned();
            let refusal = findprotocol(row.name, Proto::ALL, Proto::ALL, false)
                .expect_err("a row with no implementation must be refused");

            assert_eq!(refusal.code(), CURLcode::UnsupportedProtocol);
            assert_eq!(
                refusal.message(),
                format!("Protocol \"{name}\" disabled"),
                "{name}'s refusal text"
            );
            // There is exactly one space before `disabled` and no trailing
            // space, which a `%s%s` with an empty second argument guarantees.
            assert!(!refusal.message().ends_with(' '));
        }
    }

    #[test]
    fn the_refusal_appends_in_redirect_while_following_one() {
        // `data->state.this_is_a_follow ? " (in redirect)" : ""` (`:1570`). The
        // suffix carries its own leading space, so the plain and the redirect
        // spellings differ by exactly those 14 bytes.
        for row in SCHEMES.iter() {
            let name = String::from_utf8_lossy(row.name).into_owned();
            let refusal = findprotocol(row.name, Proto::ALL, Proto::ALL, true)
                .expect_err("a row with no implementation must be refused");

            assert_eq!(refusal.code(), CURLcode::UnsupportedProtocol);
            assert_eq!(
                refusal.message(),
                format!("Protocol \"{name}\" disabled (in redirect)"),
                "{name}'s refusal text while following a redirect"
            );
        }
    }

    #[test]
    fn one_scheme_from_each_family_group_reads_exactly_as_the_c_writes_it() {
        // The same assertion as above, written as literals rather than as a
        // format, for one row from each family group the specification names --
        // mail, RTMP, LDAP and TFTP. A format string that were wrong in the
        // same way as the production code would satisfy the loops above and
        // fail here.
        let cases: [(&[u8], &str, &str); 5] = [
            (
                b"smtp",
                "Protocol \"smtp\" disabled",
                "Protocol \"smtp\" disabled (in redirect)",
            ),
            (
                b"imap",
                "Protocol \"imap\" disabled",
                "Protocol \"imap\" disabled (in redirect)",
            ),
            (
                b"rtmpte",
                "Protocol \"rtmpte\" disabled",
                "Protocol \"rtmpte\" disabled (in redirect)",
            ),
            (
                b"ldaps",
                "Protocol \"ldaps\" disabled",
                "Protocol \"ldaps\" disabled (in redirect)",
            ),
            (
                b"tftp",
                "Protocol \"tftp\" disabled",
                "Protocol \"tftp\" disabled (in redirect)",
            ),
        ];

        for (scheme, plain, redirected) in cases {
            let direct = findprotocol(scheme, Proto::ALL, Proto::ALL, false)
                .expect_err("a stub scheme is always refused");
            assert_eq!(direct.message(), plain);
            assert_eq!(direct.code(), CURLcode::UnsupportedProtocol);

            let follow = findprotocol(scheme, Proto::ALL, Proto::ALL, true)
                .expect_err("a stub scheme is always refused");
            assert_eq!(follow.message(), redirected);
            assert_eq!(follow.code(), CURLcode::UnsupportedProtocol);
        }
    }

    #[test]
    fn an_unregistered_name_is_not_supported_rather_than_disabled() {
        // The contrast that gives `disabled` its meaning. Omitting these 24
        // rows would move every one of them into THIS branch, which is a
        // different user-visible string for the same request -- and the reason
        // the rows exist at all.
        for unknown in ["xyz", "gopherss", "smtpx", "rtm"] {
            let refusal =
                findprotocol(unknown.as_bytes(), Proto::ALL, Proto::ALL, false)
                    .expect_err("an unregistered name cannot resolve");
            assert_eq!(
                refusal.message(),
                format!("Protocol \"{unknown}\" not supported")
            );
            assert_eq!(refusal.code(), CURLcode::UnsupportedProtocol);
            assert!(get_scheme(unknown.as_bytes()).is_none());
        }

        // And the two spellings really are different, so a single-branch
        // implementation could not pass both this test and the ones above.
        let known = findprotocol(b"smtp", Proto::ALL, Proto::ALL, false)
            .expect_err("smtp carries no implementation");
        let unknown = findprotocol(b"smtpx", Proto::ALL, Proto::ALL, false)
            .expect_err("smtpx is not registered");
        assert_ne!(known.message(), unknown.message());
    }

    #[test]
    fn the_six_rtmp_rows_carry_four_distinct_families() {
        // `lib/curl_rtmp.c` gives `rtmps` the family of `rtmp` and `rtmpts` the
        // family of `rtmpt`, while `rtmpe` and `rtmpte` each keep their own.
        // Collapsing them would change which rows the connection pool treats as
        // related, so each pairing is asserted individually.
        let family = |name: &[u8]| {
            SCHEMES
                .iter()
                .find(|row| row.name == name)
                .expect("an RTMP row")
                .family
        };

        assert_eq!(family(b"rtmp"), Proto::RTMP);
        assert_eq!(family(b"rtmpt"), Proto::RTMPT);
        assert_eq!(family(b"rtmpe"), Proto::RTMPE);
        assert_eq!(family(b"rtmpte"), Proto::RTMPTE);
        assert_eq!(family(b"rtmps"), Proto::RTMP);
        assert_eq!(family(b"rtmpts"), Proto::RTMPT);

        // Four distinct values across six rows, counted rather than asserted by
        // eye. Counted by hand over an ordered slice rather than gathered into a
        // set, because a set would reorder the rows and this table's order is
        // part of what is being checked.
        let rtmp_rows: Vec<&Scheme> = SCHEMES
            .iter()
            .filter(|row| row.name.starts_with(b"rtmp"))
            .collect();
        assert_eq!(rtmp_rows.len(), 6);

        let mut distinct: Vec<u32> = Vec::with_capacity(4);
        for row in &rtmp_rows {
            let bits = row.family.bits();
            if !distinct.contains(&bits) {
                distinct.push(bits);
            }
        }
        assert_eq!(
            distinct,
            vec![
                Proto::RTMP.bits(),
                Proto::RTMPT.bits(),
                Proto::RTMPE.bits(),
                Proto::RTMPTE.bits(),
            ],
            "the six RTMP rows carry these four families, first seen in this \
             order"
        );

        // Every PROTOCOL column, by contrast, is unique to its own row: six
        // rows, six bits, which is what stops two RTMP spellings from being
        // permitted or refused together by `CURLOPT_PROTOCOLS`.
        for (index, row) in rtmp_rows.iter().enumerate() {
            for other in rtmp_rows.iter().skip(index + 1) {
                assert_ne!(row.protocol, other.protocol);
            }
        }

        // None of the six carries `PROTOPT_SSL`, including the two TLS
        // spellings: librtmp performs its own transport security.
        for row in rtmp_rows {
            let name = String::from_utf8_lossy(row.name);
            assert!(!row.is_ssl(), "{name} must carry no PROTOPT_SSL");
            assert_eq!(row.flags, ProtocolOptions::NONE);
        }
    }

    #[test]
    fn tftp_is_the_only_row_in_the_whole_registry_with_notcpproxy() {
        // Asserted over the ASSEMBLED 33 rows rather than over these 24, because
        // the claim is about the registry: `PROTOPT_NOTCPPROXY` appears once in
        // the C tree, on `lib/tftp.c:1369`, because TFTP runs over UDP.
        let carriers: Vec<String> = REGISTRY
            .iter()
            .filter(|row| row.flags.intersects(ProtocolOptions::NOTCPPROXY))
            .map(|row| String::from_utf8_lossy(row.name).into_owned())
            .collect();

        assert_eq!(carriers, vec![String::from("tftp")]);
    }

    #[test]
    fn only_the_six_mail_rows_carry_urloptions() {
        // `PROTOPT_URLOPTIONS` (`lib/urldata.h:545`) is what admits the
        // `;AUTH=` style option in the userinfo field, and the C sets it on the
        // six mail schemes and nowhere else. `crate::url` derives
        // `SchemeInfo::url_options` from this bit, so a seventh carrier would
        // change how a URL parses.
        let carriers: Vec<String> = REGISTRY
            .iter()
            .filter(|row| row.flags.intersects(ProtocolOptions::URLOPTIONS))
            .map(|row| String::from_utf8_lossy(row.name).into_owned())
            .collect();

        assert_eq!(carriers, MAIL.map(String::from).to_vec());

        // Every carrier is one of ours, which is the other half of the claim.
        for name in MAIL {
            assert!(SCHEMES.iter().any(|row| row.name == name.as_bytes()));
        }
    }

    #[test]
    fn mqtts_and_the_internal_websocket_bit_are_the_same_bit() {
        // `CURLPROTO_MQTTS` is `1L << 30` in the PUBLIC header
        // (`include/curl/curl.h:1107`) and `CURLPROTO_WS` is `1L << 30`
        // INTERNALLY (`lib/urldata.h:70`). Upstream reused the bit; renumbering
        // either would change a public integer, so the collision is asserted
        // here to make a silent "repair" impossible.
        assert_eq!(Proto::MQTTS.bits(), 1 << 30);
        assert_eq!(Proto::WS.bits(), 1 << 30);
        assert_eq!(Proto::MQTTS, Proto::WS);

        // And the `mqtts` ROW is still distinguishable from the `ws` row,
        // because the family columns do not collide: `MQTT` against `HTTP`.
        let mqtts = SCHEMES
            .iter()
            .find(|row| row.name == b"mqtts")
            .expect("the mqtts row");
        assert_eq!(mqtts.protocol, Proto::MQTTS);
        assert_eq!(mqtts.family, Proto::MQTT);
        assert_ne!(mqtts.family, Proto::HTTP);
        assert!(!mqtts.in_core_scope());
    }

    #[test]
    fn the_default_ports_keep_the_c_aliases_and_the_shared_values() {
        // `PORT_RTMPT` is DEFINED as `PORT_HTTP` and `PORT_RTMPS` as
        // `PORT_HTTPS` (`lib/urldata.h:49-50`), and `PORT_SMBS` really is 445
        // like `PORT_SMB` (`:43-44`). All three look like slips and are not.
        let port = |name: &[u8]| {
            SCHEMES
                .iter()
                .find(|row| row.name == name)
                .expect("a registered row")
                .defport
        };

        assert_eq!(port(b"rtmpt"), crate::protocols::PORT_HTTP);
        assert_eq!(port(b"rtmpte"), crate::protocols::PORT_HTTP);
        assert_eq!(port(b"rtmps"), crate::protocols::PORT_HTTPS);
        assert_eq!(port(b"rtmpts"), crate::protocols::PORT_HTTPS);
        assert_eq!(port(b"smb"), 445);
        assert_eq!(port(b"smbs"), 445);
        assert_eq!(port(b"smtps"), 465);
        assert_eq!(port(b"gopher"), port(b"gophers"));

        // No row has a zero default port: `file` is the only scheme without a
        // network endpoint and it is in scope, not here.
        for row in SCHEMES.iter() {
            let name = String::from_utf8_lossy(row.name);
            assert_ne!(row.defport, 0, "{name} must have a default port");
        }
    }

    #[test]
    fn the_version_banner_names_none_of_these_schemes() {
        // The regression test for truthful advertisement, and the one that keeps
        // 283 fixtures SKIPPING instead of FAILING. `crate::version::PROTOCOLS`
        // is checked rather than only the advertised subset, because a row added
        // there would be advertised the moment its engine landed -- catching it
        // at the table is catching it early.
        for row in SCHEMES.iter() {
            let name = String::from_utf8_lossy(row.name);
            assert!(
                !crate::version::PROTOCOLS
                    .iter()
                    .any(|entry| entry.name().eq_ignore_ascii_case(&name)),
                "{name} must not appear in the Protocols: table"
            );
            // `contains` rather than a folded `any`: `protocols()` returns an
            // EMPTY slice while no scheme has an executor, and a closure applied
            // to an empty iterator is a region this file would never execute.
            // Exactness is sound here because both sides are lower case -- these
            // 24 names by the test above, the banner by its own contract -- and
            // the case-insensitive question is asked by `supports_protocol`
            // immediately below, which does its folding inside
            // `crate::version`.
            assert!(
                !crate::version::protocols().contains(&name.as_ref()),
                "{name} must not be advertised"
            );
            assert!(
                !crate::version::supports_protocol(&name),
                "{name} must not be reported as supported"
            );
        }

        // The banner table is the nine in-scope names and nothing else, so the
        // exclusion above is a consequence of a complete table rather than of
        // an accidentally short one.
        assert_eq!(crate::version::PROTOCOLS.len(), IN_SCOPE.len());
    }

    #[test]
    fn the_table_is_present_whatever_the_feature_set() {
        // This module is declared with no `#[cfg]` and nothing in it is
        // feature-gated, so these 24 names are present under
        // `--no-default-features` and under every individual feature. Asserted
        // by NAME rather than by count, because a count would still pass if one
        // row were swapped for another.
        let names: Vec<String> = SCHEMES
            .iter()
            .map(|row| String::from_utf8_lossy(row.name).into_owned())
            .collect();

        assert_eq!(
            names,
            vec![
                "smtp", "smtps", "imap", "imaps", "pop3", "pop3s", "telnet",
                "tftp", "smb", "smbs", "ldap", "ldaps", "rtsp", "mqtt",
                "mqtts", "rtmp", "rtmpt", "rtmpe", "rtmpte", "rtmps", "rtmpts",
                "dict", "gopher", "gophers",
            ]
        );
    }
}
