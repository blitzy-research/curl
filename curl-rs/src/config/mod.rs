// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! The command-line tool's configuration model -- `src/tool_cfgable.c` and
//! `src/tool_cfgable.h`, with the ordered string list of `src/slist_wc.c`.
//!
//! Everything in this module is `pub(crate)`: this crate exports no C ABI and
//! must not be reachable from one, so the 100-symbol export set that `nm`
//! grades cannot be perturbed from here.
//!
//! # Measured composition, so nothing is invented and nothing is dropped
//!
//! `struct OperationConfig` spans `src/tool_cfgable.h:60-322` and holds, by
//! count taken from the header rather than estimated: one `struct dynbuf`, 83
//! `char *`, 11 `struct curl_slist *`, five `struct getout *` cursors with a
//! `size_t num_urls`, two `struct tool_mime *` with one `curl_mime *`, 10
//! `curl_off_t`, 27 `long`, four `unsigned long`, one `HttpReq`, one anonymous
//! clobber enum, three `unsigned char`, one `unsigned short`, the
//! `prev`/`next` pair and **84** `BIT(...)` one-bit bitfields. `struct
//! GlobalConfig` spans `:331-367` and holds 14 bitfields, of which the two
//! under `#ifdef DEBUGBUILD` (`:351-354`) are omitted here because
//! `DEBUGBUILD` is not a Cargo feature. The `#ifdef _WIN32` members `:324-329`
//! and `:341-343` are omitted too: the four mandated targets are `x86_64` and
//! `aarch64` on Linux and macOS.
//!
//! `ipfs_gateway` (`:108-110`) is *not* conditional here even though C guards
//! it with `#ifndef CURL_DISABLE_IPFS`, because `CURL_DISABLE_IPFS` is not a
//! Cargo feature either and the module that consumes it exists
//! unconditionally.
//!
//! # Gaps reported rather than worked around
//!
//! Three values this file needs belong to owners that cannot supply them yet.
//! None is defined here, because none is this file's to define, and none is
//! silently dropped:
//!
//! * `CURL_HET_DEFAULT` (`include/curl/curl.h:967`, `200L`) and
//!   `CURLULFLAG_SEEN` (`:1042`, `1L << 4`) are public libcurl constants. The
//!   two frozen defaults are therefore written as the header's own values at
//!   the single site that needs them, with the header line cited, and no
//!   competing named constant is declared. When `curl-rs-lib` re-exports them,
//!   that site adopts the names.
//! * Same treatment, same single site.
//! * `MAX_FILE2MEMORY` (`src/tool_paramhlp.h:33`) is private to
//!   `crate::cli::paramhlp`. Nothing is needed from it here:
//!   [`OperationConfig::postdata`] starts empty, and the cap belongs to the
//!   append site that already enforces it.

pub(crate) mod findfile;

use std::collections::TryReserveError;
use std::fmt;
use std::fs::File;
use std::path::PathBuf;

use curl_rs_lib::error::{CURLcode, Error};

use crate::cli::libinfo::LibInfo;
use crate::cli::paramhlp::{GetOutSeq, NewGetOut};
use crate::cli::vars::Variables;
use crate::output::formparse::MimeTree;
use crate::output::msgs::{errorf, DiagnosticSink, InsecureRequest, MsgConfig};
use crate::urlglob::UrlGlob;

/// What a redacting formatter prints in place of a value.
///
/// One spelling, so a test can assert both its presence and the absence of the
/// value it replaced. It matches `curl-rs-lib`'s marker deliberately: the two
/// crates' diagnostics are read together, and two spellings of "we did not
/// print this" would read as two different things.
#[allow(dead_code)] // Reached only from the redacting
                    // formatters below, which are themselves dead until the option parser is
                    // wired; see the module's other dead-code allowances.
const REDACTED: &str = "<redacted>";

/// A [`fmt::Debug`] adaptor rendering a byte length in place of the bytes.
///
/// Used by the formatters below for every caller-supplied value. A length
/// rather than a fixed mask, because whether a password is set, and whether it
/// is plausibly the one the user meant, is the question a reader of a
/// configuration dump actually has -- and a length answers it while disclosing
/// nothing an attacker holding the ciphertext does not already have.
#[allow(dead_code)] // Reached only from the redacting
                    // formatters below, which are themselves dead until the option parser is
                    // wired; see the module's other dead-code allowances.
struct Hidden(usize);

impl fmt::Debug for Hidden {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{REDACTED}, {} bytes>", self.0)
    }
}

/// `Some(<redacted, N bytes>)` or `None`, keeping unset distinct from empty.
#[allow(dead_code)] // Reached only from the redacting
                    // formatters below, which are themselves dead until the option parser is
                    // wired; see the module's other dead-code allowances.
fn hidden_str(value: Option<&String>) -> Option<Hidden> {
    value.map(|text| Hidden(text.len()))
}

/// The same for a byte string.
#[allow(dead_code)] // Reached only from the redacting
                    // formatters below, which are themselves dead until the option parser is
                    // wired; see the module's other dead-code allowances.
fn hidden_bytes(value: Option<&Vec<u8>>) -> Option<Hidden> {
    value.map(|bytes| Hidden(bytes.len()))
}

/// The same for a path, whose text can disclose a filesystem layout or a
/// tenant identity.
#[allow(dead_code)] // Reached only from the redacting
                    // formatters below, which are themselves dead until the option parser is
                    // wired; see the module's other dead-code allowances.
fn hidden_path(value: Option<&PathBuf>) -> Option<Hidden> {
    value.map(|path| Hidden(path.as_os_str().len()))
}

/// `MAX_CONFIG_LINE_LENGTH` -- `src/tool_cfgable.h:32`.
#[allow(dead_code)]
pub(crate) const MAX_CONFIG_LINE_LENGTH: usize = 10 * 1024 * 1024;

/// `DEFAULT_MAXREDIRS` -- `src/tool_main.h:28`, `50L`.
#[allow(dead_code)]
pub(crate) const DEFAULT_MAXREDIRS: i64 = 50;

/// The `fail` tri-state -- `src/tool_cfgable.h:56-58`.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(u8)]
#[allow(dead_code)]
pub(crate) enum FailMode {
    /// `FAIL_NONE 0` -- neither `--fail` nor `--fail-with-body`.
    #[default]
    None = 0,
    /// `FAIL_WITH_BODY 1` -- `--fail-with-body`.
    WithBody = 1,
    /// `FAIL_WO_BODY 2` -- `--fail`.
    WithoutBody = 2,
}

/// The output-clobbering mode -- the anonymous enum at
/// `src/tool_cfgable.h:212-220`.
///
/// The explanatory comment is carried verbatim from the header, because it is
/// the specification of the compatibility behaviour rather than a remark about
/// it.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(u8)]
#[allow(dead_code)]
pub(crate) enum ClobberMode {
    /// Provides compatibility with previous versions of curl, by using the
    /// default behavior for -o, -O, and -J. If those options would have
    /// overwritten files, like -o and -O would, then overwrite them. In the
    /// case of -J, this will not overwrite any files.
    #[default]
    Default = 0,
    /// If the file exists, always fail.
    Never = 1,
    /// If the file exists, always overwrite it.
    Always = 2,
}

/// `trace` -- `src/tool_sdecls.h:104-109`, the type of
/// [`GlobalConfig::tracetype`].
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(u8)]
#[allow(dead_code)]
pub(crate) enum TraceType {
    /// `TRACE_NONE` -- no trace or verbose output at all.
    #[default]
    None = 0,
    /// `TRACE_BIN` -- `--trace`, the tcpdump inspired look.
    Bin = 1,
    /// `TRACE_ASCII` -- `--trace-ascii`, like `Bin` without the hex output.
    Ascii = 2,
    /// `TRACE_PLAIN` -- the `-v`/`--verbose` type.
    Plain = 3,
}

/// `HttpReq` -- `src/tool_sdecls.h:114-121`, the type of
/// [`OperationConfig::httpreq`].
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(u8)]
#[allow(dead_code)]
pub(crate) enum HttpReq {
    /// `TOOL_HTTPREQ_UNSPEC` -- first in list.
    #[default]
    Unspec = 0,
    /// `TOOL_HTTPREQ_GET`.
    Get = 1,
    /// `TOOL_HTTPREQ_HEAD`.
    Head = 2,
    /// `TOOL_HTTPREQ_MIMEPOST`.
    MimePost = 3,
    /// `TOOL_HTTPREQ_SIMPLEPOST`.
    SimplePost = 4,
    /// `TOOL_HTTPREQ_PUT`.
    Put = 5,
}

/// One URL node -- `struct getout` (`src/tool_sdecls.h:85-99`).
///
/// C chains these with `struct getout *next` (`:86`) and keeps five pointers
/// into the chain on the owning configuration. Here the chain is
/// [`OperationConfig::url_list`], an owned `Vec`, so `next` has no counterpart
/// and every cursor is an index into that vector.
///
/// The three byte strings are `Vec<u8>` rather than `String` or `PathBuf`
/// because all three are inputs to `crate::urlglob`'s byte-oriented API before
/// they ever reach the filesystem: `UrlGlob::parse` takes `&[u8]` and
/// `UrlGlob::match_url` takes `&[u8]` and yields `Vec<u8>`. Converting here
/// and back would be two lossy conversions where C performs none, and the
/// conversion that does happen -- to an `OsStr` at the point a file is
/// opened -- is exact on every mandated target.
#[derive(Clone, Default, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct GetOut {
    /// `char *url` -- the URL this node deals with (`:87`).
    pub(crate) url: Option<Vec<u8>>,
    /// `char *outfile` -- where to store the output (`:88`).
    pub(crate) outfile: Option<Vec<u8>>,
    /// `char *infile` -- the file to upload, when `uploadset` is set (`:89`).
    pub(crate) infile: Option<Vec<u8>>,
    /// `curl_off_t num` -- which URL number in an invocation (`:90`).
    ///
    /// Issued by [`GetOutSeq`], which `crate::cli::paramhlp` documents as the
    /// replacement for the `static int outnum` of
    /// `src/tool_paramhlp.c:40`. `curl_off_t` widens C's `int` there, so the
    /// widening is part of the original.
    pub(crate) num: i64,
    /// `BIT(outset)` -- `outfile` is set (`:92`).
    pub(crate) outset: bool,
    /// `BIT(urlset)` -- the URL is set (`:93`).
    pub(crate) urlset: bool,
    /// `BIT(uploadset)` -- `-T` was given (`:94`).
    pub(crate) uploadset: bool,
    /// `BIT(useremote)` -- use the remote filename locally (`:95`).
    pub(crate) useremote: bool,
    /// `BIT(noupload)` -- `-T ""` was used (`:96`).
    pub(crate) noupload: bool,
    /// `BIT(noglob)` -- globbing is disabled for this URL (`:97`).
    pub(crate) noglob: bool,
    /// `BIT(out_null)` -- discard the output for this URL (`:98`).
    pub(crate) out_null: bool,
}

/// Lengths in place of the URL and the two filenames; every flag in full.
///
/// # Why this is not `#[derive(Debug)]`
///
/// [`Self::url`] is a command-line URL, and a URL carries credentials: userinfo
/// in the authority, a signed query parameter, a one-time token in a path.
/// `curl_rs_lib`'s own `Url` formatter redacts userinfo for that reason, so
/// rendering the raw bytes here would have reinstated the disclosure one layer
/// up. [`Self::outfile`] and [`Self::infile`] are local paths, which disclose a
/// filesystem layout and often a user name.
///
/// Every flag and the sequence number render in full: they are what a reader
/// debugging `-o`/`-O`/`-T` interaction needs, and none is a secret.
impl fmt::Debug for GetOut {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GetOut")
            .field("url", &hidden_bytes(self.url.as_ref()))
            .field("outfile", &hidden_bytes(self.outfile.as_ref()))
            .field("infile", &hidden_bytes(self.infile.as_ref()))
            .field("num", &self.num)
            .field("outset", &self.outset)
            .field("urlset", &self.urlset)
            .field("uploadset", &self.uploadset)
            .field("useremote", &self.useremote)
            .field("noupload", &self.noupload)
            .field("noglob", &self.noglob)
            .field("out_null", &self.out_null)
            .finish()
    }
}

/// The ordered string list that replaces `src/slist_wc.c`.
///
/// # Deliberately not shared with the `--libcurl` emitter
///
/// `curl-rs/src/libcurl_src.rs` keeps its own accumulators in the target
/// design and states that it must not use this type. The divergence is
/// recorded on both sides on purpose, so that nobody unifies them on the
/// grounds that both happen to be a `Vec<String>`: this one is the general
/// list, and the emitter's are five distinct sections whose order and content
/// are frozen separately.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct SlistWc {
    /// The nodes, oldest first, exactly as the chain ordered them.
    items: Vec<String>,
}

#[allow(dead_code)]
impl SlistWc {
    /// An empty list -- C's `NULL` head, which `slist_wc_append` also accepts
    /// as its "create the list" case (`src/slist_wc.c:41-52`).
    pub(crate) const fn new() -> Self {
        Self { items: Vec::new() }
    }

    /// `slist_wc_append` -- `src/slist_wc.c:34-57`.
    ///
    /// # Errors
    ///
    /// [`TryReserveError`] when the node cannot be stored. C reports that as a
    /// `NULL` return from `curl_slist_append` (`:38-39`) or from
    /// `curlx_malloc` (`:44-47`) and the caller propagates it, so the failure
    /// is preserved rather than dropped on the grounds that `Vec::push` aborts
    /// instead of reporting. On failure the list is left exactly as it was.
    pub(crate) fn append(&mut self, data: &str) -> Result<(), TryReserveError> {
        self.items.try_reserve(1)?;
        self.items.push(data.to_owned());
        Ok(())
    }

    /// The nodes in order, which is what an easysrc consumer walks.
    pub(crate) fn items(&self) -> &[String] {
        &self.items
    }

    /// How many nodes the list holds.
    pub(crate) fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the list is C's `NULL` head.
    pub(crate) fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// One transfer operation's configuration -- `struct OperationConfig`
/// (`src/tool_cfgable.h:60-322`).
///
/// The field order is the header's, so the two can be compared line by line;
/// see the module documentation for why the struct is flat. Every field carries
/// the header line it comes from.
///
/// # Which fields own their storage
///
/// `free_config_fields` (`src/tool_cfgable.c:59-191`) is the authoritative
/// list of what C has to release, and it is what decides the Rust type of every
/// field: a name that appears there is an owned `String`, `PathBuf`,
/// `Vec<u8>` or `Vec<String>` here, and a name that does not is a scalar. Rust
/// ownership makes the function itself unnecessary -- dropping this value drops
/// every one of them -- so there is no `free` counterpart and no `Option::take`
/// dance to reproduce `tool_safefree` (`src/tool_cfgable.h:36-40`).
///
/// Two spellings are used for the 83 `char *` fields, and the split follows the
/// consumer rather than the C type. A value the tool hands to the filesystem is
/// a [`PathBuf`], because that is what this crate's file operations take --
/// `crate::output::dirhie::create_dir_hierarchy` and
/// `crate::output::filetime::getfiletime` both take `&Path`. Everything else is
/// a `String`, which is the spelling `crate::cli::paramhlp` already fixed for
/// option values: `add2list` takes `&mut Vec<String>` and `&str`, and `str2num`
/// takes `&str`. Following those rather than contradicting them is what keeps a
/// value from being converted twice on its way through the tool.
///
/// # Mutated during option application
///
/// `src/config2setopts.c:216-217` writes a resolved path back into the
/// configuration -- `config->knownhosts = known;`, commented "store it in
/// global to avoid repeated checks" -- so the type that applies options needs
/// `&mut OperationConfig`. Every field here is reachable mutably through an
/// ordinary exclusive borrow; nothing is wrapped in a cell, because a plain
/// `&mut` suffices and interior mutability would hide the aliasing rule that
/// makes the borrow safe.
#[derive(Clone, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct OperationConfig {
    /// `struct dynbuf postdata` -- `:61`, the `--data` accumulator.
    pub(crate) postdata: Vec<u8>,
    /// `char *useragent` -- `:62`.
    pub(crate) useragent: Option<Vec<u8>>,
    /// `struct curl_slist *cookies` -- `:63`, cookies to serialize into a
    /// single line.
    pub(crate) cookies: Vec<Vec<u8>>,
    /// `char *cookiejar` -- `:64`, write to this file.
    pub(crate) cookiejar: Option<PathBuf>,
    /// `struct curl_slist *cookiefiles` -- `:65`, file(s) to load cookies
    /// from.
    ///
    /// A `Vec<String>` and not of paths: the option accepts the literal `-`
    /// for standard input as well as filenames, so the values are not all
    /// paths and the distinction is made where they are opened.
    pub(crate) cookiefiles: Vec<Vec<u8>>,
    /// `char *altsvc` -- `:66`, the alt-svc cache filename.
    pub(crate) altsvc: Option<PathBuf>,
    /// `char *hsts` -- `:67`, the HSTS cache filename.
    pub(crate) hsts: Option<PathBuf>,
    /// `char *proto_str` -- `:68`, the `--proto` argument.
    pub(crate) proto_str: Option<Vec<u8>>,
    /// `char *proto_redir_str` -- `:69`, the `--proto-redir` argument.
    pub(crate) proto_redir_str: Option<Vec<u8>>,
    /// `char *proto_default` -- `:70`, the `--proto-default` argument.
    pub(crate) proto_default: Option<Vec<u8>>,
    /// `curl_off_t resume_from` -- `:71`.
    pub(crate) resume_from: i64,
    /// `char *postfields` -- `:72`, reduced to the flag it functionally is.
    ///
    /// C's field is a pointer, but it never points anywhere of its own: it is
    /// assigned `curlx_dyn_ptr(&config->postdata)` at
    /// `src/tool_getparam.c:1006` and cleared to `NULL` at
    /// `src/tool_operate.c:1418` once the bytes have moved to
    /// `state->httpgetfields`. Those are its only two assignments in the whole
    /// tree, and it is absent from `free_config_fields` precisely because
    /// `postdata` owns the storage.
    pub(crate) postfields: bool,
    /// `char *referer` -- `:73`.
    pub(crate) referer: Option<Vec<u8>>,
    /// `char *query` -- `:74`, the `--url-query` accumulator.
    pub(crate) query: Option<Vec<u8>>,
    /// `curl_off_t max_filesize` -- `:75`.
    pub(crate) max_filesize: i64,
    /// `char *output_dir` -- `:76`, the `--output-dir` argument.
    pub(crate) output_dir: Option<PathBuf>,
    /// `char *headerfile` -- `:77`, the `-D`/`--dump-header` argument.
    pub(crate) headerfile: Option<PathBuf>,
    /// `char *ftpport` -- `:78`, the `-P`/`--ftp-port` argument.
    pub(crate) ftpport: Option<Vec<u8>>,
    /// `char *iface` -- `:79`, the `--interface` argument.
    pub(crate) iface: Option<Vec<u8>>,
    /// `char *range` -- `:80`, the `-r`/`--range` argument.
    pub(crate) range: Option<Vec<u8>>,
    /// `char *dns_servers` -- `:81`, dot notation: `1.1.1.1;2.2.2.2`.
    pub(crate) dns_servers: Option<Vec<u8>>,
    /// `char *dns_interface` -- `:82`, an interface name.
    pub(crate) dns_interface: Option<Vec<u8>>,
    /// `char *dns_ipv4_addr` -- `:83`, dot notation.
    pub(crate) dns_ipv4_addr: Option<Vec<u8>>,
    /// `char *dns_ipv6_addr` -- `:84`, dot notation.
    pub(crate) dns_ipv6_addr: Option<Vec<u8>>,
    /// `char *userpwd` -- `:85`.
    pub(crate) userpwd: Option<Vec<u8>>,
    /// `char *login_options` -- `:86`.
    pub(crate) login_options: Option<Vec<u8>>,
    /// `char *tls_username` -- `:87`.
    pub(crate) tls_username: Option<Vec<u8>>,
    /// `char *tls_password` -- `:88`.
    pub(crate) tls_password: Option<Vec<u8>>,
    /// `char *tls_authtype` -- `:89`.
    pub(crate) tls_authtype: Option<Vec<u8>>,
    /// `char *proxy_tls_username` -- `:90`.
    pub(crate) proxy_tls_username: Option<Vec<u8>>,
    /// `char *proxy_tls_password` -- `:91`.
    pub(crate) proxy_tls_password: Option<Vec<u8>>,
    /// `char *proxy_tls_authtype` -- `:92`.
    pub(crate) proxy_tls_authtype: Option<Vec<u8>>,
    /// `char *proxyuserpwd` -- `:93`.
    pub(crate) proxyuserpwd: Option<Vec<u8>>,
    /// `char *proxy` -- `:94`.
    pub(crate) proxy: Option<Vec<u8>>,
    /// `char *noproxy` -- `:95`.
    pub(crate) noproxy: Option<Vec<u8>>,
    /// `char *knownhosts` -- `:96`, resolved in place by the option applier;
    /// see the struct documentation.
    pub(crate) knownhosts: Option<PathBuf>,
    /// `char *mail_from` -- `:97`.
    pub(crate) mail_from: Option<Vec<u8>>,
    /// `struct curl_slist *mail_rcpt` -- `:98`.
    pub(crate) mail_rcpt: Vec<Vec<u8>>,
    /// `char *mail_auth` -- `:99`.
    pub(crate) mail_auth: Option<Vec<u8>>,
    /// `char *sasl_authzid` -- `:100`, the authorization identity to use.
    pub(crate) sasl_authzid: Option<Vec<u8>>,
    /// `char *netrc_file` -- `:101`.
    pub(crate) netrc_file: Option<PathBuf>,
    /// `struct getout *url_list` -- `:102`, C's "point to the first node".
    pub(crate) url_list: Vec<GetOut>,
    /// `struct getout *url_get` -- `:104`, the node to fill in the URL.
    pub(crate) url_get: Option<usize>,
    /// `struct getout *url_out` -- `:105`, the node to fill in `outfile`.
    pub(crate) url_out: Option<usize>,
    /// `struct getout *url_ul` -- `:106`, the node to fill in the upload.
    pub(crate) url_ul: Option<usize>,
    /// `size_t num_urls` -- `:107`, the number of URLs added to the list.
    ///
    /// Kept as its own counter rather than derived from
    /// [`OperationConfig::url_list`]: C counts URLs and the list holds nodes,
    /// and `src/tool_getparam.c` increments this only for a node that receives
    /// a URL, so the two are not the same number.
    pub(crate) num_urls: usize,
    /// The `static int outnum` of `src/tool_paramhlp.c:40`, as a field.
    pub(crate) getout_seq: GetOutSeq,
    /// `char *ipfs_gateway` -- `:109`.
    ///
    /// Unconditional here. C guards it with `#ifndef CURL_DISABLE_IPFS`
    /// (`:108-110`), which is not a Cargo feature, and the module that
    /// translates an IPFS URL exists unconditionally.
    pub(crate) ipfs_gateway: Option<Vec<u8>>,
    /// `char *doh_url` -- `:111`.
    pub(crate) doh_url: Option<Vec<u8>>,
    /// `char *cipher_list` -- `:112`.
    pub(crate) cipher_list: Option<Vec<u8>>,
    /// `char *proxy_cipher_list` -- `:113`.
    pub(crate) proxy_cipher_list: Option<Vec<u8>>,
    /// `char *cipher13_list` -- `:114`.
    pub(crate) cipher13_list: Option<Vec<u8>>,
    /// `char *proxy_cipher13_list` -- `:115`.
    pub(crate) proxy_cipher13_list: Option<Vec<u8>>,
    /// `char *cert` -- `:116`.
    pub(crate) cert: Option<PathBuf>,
    /// `char *proxy_cert` -- `:117`.
    pub(crate) proxy_cert: Option<PathBuf>,
    /// `char *cert_type` -- `:118`.
    pub(crate) cert_type: Option<Vec<u8>>,
    /// `char *proxy_cert_type` -- `:119`.
    pub(crate) proxy_cert_type: Option<Vec<u8>>,
    /// `char *cacert` -- `:120`.
    pub(crate) cacert: Option<PathBuf>,
    /// `char *proxy_cacert` -- `:121`.
    pub(crate) proxy_cacert: Option<PathBuf>,
    /// `char *capath` -- `:122`, a directory rather than a file.
    pub(crate) capath: Option<PathBuf>,
    /// `char *proxy_capath` -- `:123`.
    pub(crate) proxy_capath: Option<PathBuf>,
    /// `char *crlfile` -- `:124`.
    pub(crate) crlfile: Option<PathBuf>,
    /// `char *proxy_crlfile` -- `:125`.
    pub(crate) proxy_crlfile: Option<PathBuf>,
    /// `char *pinnedpubkey` -- `:126`.
    ///
    /// Text, not a path: the option accepts either a filename or a
    /// `sha256//<base64>` digest list, and only the option applier can tell
    /// them apart.
    pub(crate) pinnedpubkey: Option<Vec<u8>>,
    /// `char *proxy_pinnedpubkey` -- `:127`.
    pub(crate) proxy_pinnedpubkey: Option<Vec<u8>>,
    /// `char *key` -- `:128`.
    pub(crate) key: Option<PathBuf>,
    /// `char *proxy_key` -- `:129`.
    pub(crate) proxy_key: Option<PathBuf>,
    /// `char *key_type` -- `:130`.
    pub(crate) key_type: Option<Vec<u8>>,
    /// `char *proxy_key_type` -- `:131`.
    pub(crate) proxy_key_type: Option<Vec<u8>>,
    /// `char *key_passwd` -- `:132`.
    pub(crate) key_passwd: Option<Vec<u8>>,
    /// `char *proxy_key_passwd` -- `:133`.
    pub(crate) proxy_key_passwd: Option<Vec<u8>>,
    /// `char *pubkey` -- `:134`.
    pub(crate) pubkey: Option<PathBuf>,
    /// `char *hostpubmd5` -- `:135`, a hex digest rather than a path.
    pub(crate) hostpubmd5: Option<Vec<u8>>,
    /// `char *hostpubsha256` -- `:136`, a base64 digest rather than a path.
    pub(crate) hostpubsha256: Option<Vec<u8>>,
    /// `char *engine` -- `:137`.
    pub(crate) engine: Option<Vec<u8>>,
    /// `char *etag_save_file` -- `:138`.
    pub(crate) etag_save_file: Option<PathBuf>,
    /// `char *etag_compare_file` -- `:139`.
    pub(crate) etag_compare_file: Option<PathBuf>,
    /// `char *customrequest` -- `:140`, the `-X` argument.
    pub(crate) customrequest: Option<Vec<u8>>,
    /// `char *ssl_ec_curves` -- `:141`.
    pub(crate) ssl_ec_curves: Option<Vec<u8>>,
    /// `char *ssl_signature_algorithms` -- `:142`.
    pub(crate) ssl_signature_algorithms: Option<Vec<u8>>,
    /// `char *krblevel` -- `:143`.
    pub(crate) krblevel: Option<Vec<u8>>,
    /// `char *request_target` -- `:144`.
    pub(crate) request_target: Option<Vec<u8>>,
    /// `char *writeout` -- `:145`, the `%`-styled format string to output.
    pub(crate) writeout: Option<Vec<u8>>,
    /// `struct curl_slist *quote` -- `:146`.
    pub(crate) quote: Vec<Vec<u8>>,
    /// `struct curl_slist *postquote` -- `:147`.
    pub(crate) postquote: Vec<Vec<u8>>,
    /// `struct curl_slist *prequote` -- `:148`.
    pub(crate) prequote: Vec<Vec<u8>>,
    /// `struct curl_slist *headers` -- `:149`.
    pub(crate) headers: Vec<Vec<u8>>,
    /// `struct curl_slist *proxyheaders` -- `:150`.
    pub(crate) proxyheaders: Vec<Vec<u8>>,
    /// `struct tool_mime *mimeroot` and `*mimecurrent` -- `:151-152`.
    ///
    /// `curl_mime *mimepost` (`:153`) has no field here. Its only purpose in C
    /// is the deferred `curl_mime_free` at `src/tool_cfgable.c:171-172`, and
    /// its Rust type is `MimeBuilder::Mime` -- an associated type chosen by the
    /// builder that applies the options, since `tool2curlmime` is generic over
    /// it. Ownership therefore sits with that builder, where dropping it
    /// releases the handle, and a field typed here could only name one
    /// builder's choice.
    pub(crate) mime: Option<MimeTree>,
    /// `struct curl_slist *telnet_options` -- `:154`.
    pub(crate) telnet_options: Vec<Vec<u8>>,
    /// `struct curl_slist *resolve` -- `:155`.
    pub(crate) resolve: Vec<Vec<u8>>,
    /// `struct curl_slist *connect_to` -- `:156`.
    pub(crate) connect_to: Vec<Vec<u8>>,
    /// `char *preproxy` -- `:157`.
    pub(crate) preproxy: Option<Vec<u8>>,
    /// `char *proxy_service_name` -- `:158-159`, the authentication service
    /// name for HTTP and SOCKS5 proxies.
    pub(crate) proxy_service_name: Option<Vec<u8>>,
    /// `char *service_name` -- `:160-161`, the authentication service name for
    /// DIGEST-MD5, Kerberos 5 and SPNEGO.
    pub(crate) service_name: Option<Vec<u8>>,
    /// `char *ftp_account` -- `:162`, for `ACCT`.
    pub(crate) ftp_account: Option<Vec<u8>>,
    /// `char *ftp_alternative_to_user` -- `:163`, the command to send if
    /// `USER`/`PASS` fails.
    pub(crate) ftp_alternative_to_user: Option<Vec<u8>>,
    /// `char *oauth_bearer` -- `:164`, the OAuth 2.0 bearer token.
    pub(crate) oauth_bearer: Option<Vec<u8>>,
    /// `char *unix_socket_path` -- `:165`, the path to a Unix domain socket.
    pub(crate) unix_socket_path: Option<PathBuf>,
    /// `char *haproxy_clientip` -- `:166`, the client IP for the HAProxy
    /// protocol.
    pub(crate) haproxy_clientip: Option<Vec<u8>>,
    /// `char *aws_sigv4` -- `:167`.
    pub(crate) aws_sigv4: Option<Vec<u8>>,
    /// `char *ech` -- `:168`, set by `--ech` keywords.
    pub(crate) ech: Option<Vec<u8>>,
    /// `char *ech_config` -- `:169`, set by the `--ech esl:` option.
    pub(crate) ech_config: Option<Vec<u8>>,
    /// `char *ech_public` -- `:170`, set by the `--ech pn:` option.
    pub(crate) ech_public: Option<Vec<u8>>,
    /// `curl_off_t condtime` -- `:173`.
    ///
    /// `prev` and `next` (`:171-172`, "Always last in the struct") have no
    /// counterpart; see [`ConfigChain`].
    pub(crate) condtime: i64,
    /// `curl_off_t sendpersecond` -- `:175`, send to peer.
    pub(crate) sendpersecond: i64,
    /// `curl_off_t recvpersecond` -- `:176`, receive from peer.
    pub(crate) recvpersecond: i64,
    /// `long proxy_ssl_version` -- `:178`.
    pub(crate) proxy_ssl_version: i64,
    /// `long ip_version` -- `:179`.
    pub(crate) ip_version: i64,
    /// `long create_file_mode` -- `:180`, `CURLOPT_NEW_FILE_PERMS`.
    pub(crate) create_file_mode: i64,
    /// `long low_speed_limit` -- `:181`.
    pub(crate) low_speed_limit: i64,
    /// `long low_speed_time` -- `:182`.
    pub(crate) low_speed_time: i64,
    /// `long ip_tos` -- `:183`, IP Type of Service.
    pub(crate) ip_tos: i64,
    /// `long vlan_priority` -- `:184`.
    pub(crate) vlan_priority: i64,
    /// `long localport` -- `:185`.
    pub(crate) localport: i64,
    /// `long localportrange` -- `:186`.
    pub(crate) localportrange: i64,
    /// `unsigned long authtype` -- `:187`, an auth bitmask.
    pub(crate) authtype: u64,
    /// `long timeout_ms` -- `:188`.
    pub(crate) timeout_ms: i64,
    /// `long connecttimeout_ms` -- `:189`.
    pub(crate) connecttimeout_ms: i64,
    /// `long maxredirs` -- `:190`, defaulting to [`DEFAULT_MAXREDIRS`].
    pub(crate) maxredirs: i64,
    /// `long httpversion` -- `:191`.
    pub(crate) httpversion: i64,
    /// `unsigned long socks5_auth` -- `:192`, an auth bitmask for SOCKS5
    /// proxies.
    pub(crate) socks5_auth: u64,
    /// `long req_retry` -- `:193`, the number of retries.
    pub(crate) req_retry: i64,
    /// `long retry_delay_ms` -- `:194-195`, the delay between retries; 0 means
    /// increase exponentially.
    pub(crate) retry_delay_ms: i64,
    /// `long retry_maxtime_ms` -- `:196`, the maximum time to keep retrying.
    pub(crate) retry_maxtime_ms: i64,
    /// `unsigned long mime_options` -- `:198`, MIME option flags.
    pub(crate) mime_options: u64,
    /// `long tftp_blksize` -- `:199`, the TFTP `BLKSIZE` option.
    pub(crate) tftp_blksize: i64,
    /// `long alivetime` -- `:200`, `--keepalive-time`.
    pub(crate) alivetime: i64,
    /// `long alivecnt` -- `:201`, `--keepalive-cnt`.
    pub(crate) alivecnt: i64,
    /// `long gssapi_delegation` -- `:202`.
    pub(crate) gssapi_delegation: i64,
    /// `long expect100timeout_ms` -- `:203`.
    pub(crate) expect100timeout_ms: i64,
    /// `long happy_eyeballs_timeout_ms` -- `:204-205`.
    ///
    /// The header's comment records that "0 is valid" and that the default is
    /// `CURL_HET_DEFAULT`, so zero cannot stand in for "unset" and the default
    /// has to be written explicitly.
    pub(crate) happy_eyeballs_timeout_ms: i64,
    /// `unsigned long timecond` -- `:206`.
    pub(crate) timecond: u64,
    /// `long followlocation` -- `:207`, the follow-redirects mode.
    pub(crate) followlocation: i64,
    /// `HttpReq httpreq` -- `:208`.
    pub(crate) httpreq: HttpReq,
    /// `long proxyver` -- `:209`, set to a `CURLPROXY_HTTP*` value.
    pub(crate) proxyver: i64,
    /// `long ftp_ssl_ccc_mode` -- `:210`.
    pub(crate) ftp_ssl_ccc_mode: i64,
    /// `long ftp_filemethod` -- `:211`.
    pub(crate) ftp_filemethod: i64,
    /// The clobber mode -- `:212-220`.
    pub(crate) file_clobber_mode: ClobberMode,
    /// `unsigned char upload_flags` -- `:221`, the `--upload-flags` bitmask.
    pub(crate) upload_flags: u8,
    /// `unsigned short porttouse` -- `:222`.
    pub(crate) porttouse: u16,
    /// `unsigned char ssl_version` -- `:223`, 0 to 4 with 0 the default.
    pub(crate) ssl_version: u8,
    /// `unsigned char ssl_version_max` -- `:224`, 0 to 4 with 0 the default.
    pub(crate) ssl_version_max: u8,
    /// `unsigned char fail` -- `:225`.
    pub(crate) fail: FailMode,
    /// `BIT(remote_name_all)` -- `:226`, `--remote-name-all`.
    pub(crate) remote_name_all: bool,
    /// `BIT(remote_time)` -- `:227`.
    pub(crate) remote_time: bool,
    /// `BIT(cookiesession)` -- `:228`, a new session.
    pub(crate) cookiesession: bool,
    /// `BIT(encoding)` -- `:229`, `Accept-Encoding` please.
    pub(crate) encoding: bool,
    /// `BIT(tr_encoding)` -- `:230`, `Transfer-Encoding` please.
    pub(crate) tr_encoding: bool,
    /// `BIT(use_resume)` -- `:231`.
    pub(crate) use_resume: bool,
    /// `BIT(resume_from_current)` -- `:232`.
    pub(crate) resume_from_current: bool,
    /// `BIT(disable_epsv)` -- `:233`.
    pub(crate) disable_epsv: bool,
    /// `BIT(disable_eprt)` -- `:234`.
    pub(crate) disable_eprt: bool,
    /// `BIT(ftp_pret)` -- `:235`.
    pub(crate) ftp_pret: bool,
    /// `BIT(proto_present)` -- `:236`.
    pub(crate) proto_present: bool,
    /// `BIT(proto_redir_present)` -- `:237`.
    pub(crate) proto_redir_present: bool,
    /// `BIT(mail_rcpt_allowfails)` -- `:238`, `--mail-rcpt-allowfails`.
    pub(crate) mail_rcpt_allowfails: bool,
    /// `BIT(sasl_ir)` -- `:239`, enable or disable the SASL initial response.
    pub(crate) sasl_ir: bool,
    /// `BIT(proxytunnel)` -- `:240`.
    pub(crate) proxytunnel: bool,
    /// `BIT(ftp_append)` -- `:241`, `APPE` on FTP.
    pub(crate) ftp_append: bool,
    /// `BIT(use_ascii)` -- `:242`, select ASCII or text transfer.
    pub(crate) use_ascii: bool,
    /// `BIT(autoreferer)` -- `:243`, automatically set the referer.
    pub(crate) autoreferer: bool,
    /// `BIT(show_headers)` -- `:244`, show headers to the data output.
    pub(crate) show_headers: bool,
    /// `BIT(no_body)` -- `:245`, do not get the body.
    pub(crate) no_body: bool,
    /// `BIT(dirlistonly)` -- `:246`, only get the FTP directory list.
    pub(crate) dirlistonly: bool,
    /// `BIT(unrestricted_auth)` -- `:247-249`, continue to send the user and
    /// password when following redirects, even when the hostname changed.
    pub(crate) unrestricted_auth: bool,
    /// `BIT(netrc_opt)` -- `:250`.
    pub(crate) netrc_opt: bool,
    /// `BIT(netrc)` -- `:251`.
    pub(crate) netrc: bool,
    /// `BIT(crlf)` -- `:252`.
    pub(crate) crlf: bool,
    /// `BIT(http09_allowed)` -- `:253`.
    pub(crate) http09_allowed: bool,
    /// `BIT(nobuffer)` -- `:254`.
    pub(crate) nobuffer: bool,
    /// `BIT(readbusy)` -- `:255`, set when reading input returns `EAGAIN`.
    pub(crate) readbusy: bool,
    /// `BIT(globoff)` -- `:256`.
    pub(crate) globoff: bool,
    /// `BIT(use_httpget)` -- `:257`.
    pub(crate) use_httpget: bool,
    /// `BIT(insecure_ok)` -- `:258`, set true to allow insecure TLS connects.
    ///
    /// One of the three flags that switch certificate verification off. See
    /// [`OperationConfig::default`] for why all three start false and why that
    /// is not an incidental consequence of the C using `calloc`.
    pub(crate) insecure_ok: bool,
    /// `BIT(doh_insecure_ok)` -- `:259-260`, the same for DoH.
    pub(crate) doh_insecure_ok: bool,
    /// `BIT(proxy_insecure_ok)` -- `:261-262`, the same for the proxy.
    pub(crate) proxy_insecure_ok: bool,
    /// `BIT(terminal_binary_ok)` -- `:263`.
    pub(crate) terminal_binary_ok: bool,
    /// `BIT(verifystatus)` -- `:264`.
    pub(crate) verifystatus: bool,
    /// `BIT(doh_verifystatus)` -- `:265`.
    pub(crate) doh_verifystatus: bool,
    /// `BIT(create_dirs)` -- `:266`.
    pub(crate) create_dirs: bool,
    /// `BIT(ftp_create_dirs)` -- `:267`.
    pub(crate) ftp_create_dirs: bool,
    /// `BIT(ftp_skip_ip)` -- `:268`.
    pub(crate) ftp_skip_ip: bool,
    /// `BIT(proxynegotiate)` -- `:269`.
    pub(crate) proxynegotiate: bool,
    /// `BIT(proxyntlm)` -- `:270`.
    pub(crate) proxyntlm: bool,
    /// `BIT(proxydigest)` -- `:271`.
    pub(crate) proxydigest: bool,
    /// `BIT(proxybasic)` -- `:272`.
    pub(crate) proxybasic: bool,
    /// `BIT(proxyanyauth)` -- `:273`.
    pub(crate) proxyanyauth: bool,
    /// `BIT(jsoned)` -- `:274`, added a JSON content type.
    pub(crate) jsoned: bool,
    /// `BIT(ftp_ssl)` -- `:275`.
    pub(crate) ftp_ssl: bool,
    /// `BIT(ftp_ssl_reqd)` -- `:276`.
    pub(crate) ftp_ssl_reqd: bool,
    /// `BIT(ftp_ssl_control)` -- `:277`.
    pub(crate) ftp_ssl_control: bool,
    /// `BIT(ftp_ssl_ccc)` -- `:278`.
    pub(crate) ftp_ssl_ccc: bool,
    /// `BIT(socks5_gssapi_nec)` -- `:279-280`, the NEC reference server does
    /// not protect the encryption type exchange.
    pub(crate) socks5_gssapi_nec: bool,
    /// `BIT(tcp_nodelay)` -- `:281`, enabled by default.
    pub(crate) tcp_nodelay: bool,
    /// `BIT(tcp_fastopen)` -- `:282`.
    pub(crate) tcp_fastopen: bool,
    /// `BIT(retry_all_errors)` -- `:283`, retry on any error.
    pub(crate) retry_all_errors: bool,
    /// `BIT(retry_connrefused)` -- `:284`, treat a refused connection as a
    /// transient error.
    pub(crate) retry_connrefused: bool,
    /// `BIT(tftp_no_options)` -- `:285`, do not send TFTP options requests.
    pub(crate) tftp_no_options: bool,
    /// `BIT(ignorecl)` -- `:286`, `--ignore-content-length`.
    pub(crate) ignorecl: bool,
    /// `BIT(disable_sessionid)` -- `:287`.
    pub(crate) disable_sessionid: bool,
    /// `BIT(raw)` -- `:289`.
    pub(crate) raw: bool,
    /// `BIT(post301)` -- `:290`.
    pub(crate) post301: bool,
    /// `BIT(post302)` -- `:291`.
    pub(crate) post302: bool,
    /// `BIT(post303)` -- `:292`.
    pub(crate) post303: bool,
    /// `BIT(nokeepalive)` -- `:293`, for keepalive needs.
    pub(crate) nokeepalive: bool,
    /// `BIT(content_disposition)` -- `:294`, use the `Content-Disposition`
    /// filename.
    pub(crate) content_disposition: bool,
    /// `BIT(xattr)` -- `:296`, store metadata in extended attributes.
    pub(crate) xattr: bool,
    /// `BIT(ssl_allow_beast)` -- `:297`, allow this TLS vulnerability.
    pub(crate) ssl_allow_beast: bool,
    /// `BIT(ssl_allow_earlydata)` -- `:298`, allow use of TLSv1.3 early data.
    pub(crate) ssl_allow_earlydata: bool,
    /// `BIT(proxy_ssl_allow_beast)` -- `:299`, the same for the proxy.
    pub(crate) proxy_ssl_allow_beast: bool,
    /// `BIT(ssl_no_revoke)` -- `:300`, disable certificate revocation checks.
    pub(crate) ssl_no_revoke: bool,
    /// `BIT(ssl_revoke_best_effort)` -- `:301-302`, ignore offline or missing
    /// revocation list errors.
    pub(crate) ssl_revoke_best_effort: bool,
    /// `BIT(native_ca_store)` -- `:304`, use the native operating-system CA
    /// store.
    pub(crate) native_ca_store: bool,
    /// `BIT(proxy_native_ca_store)` -- `:305`, the same for the proxy.
    pub(crate) proxy_native_ca_store: bool,
    /// `BIT(ssl_auto_client_cert)` -- `:306-307`.
    pub(crate) ssl_auto_client_cert: bool,
    /// `BIT(proxy_ssl_auto_client_cert)` -- `:308`.
    pub(crate) proxy_ssl_auto_client_cert: bool,
    /// `BIT(noalpn)` -- `:309`, enable or disable the TLS ALPN extension.
    pub(crate) noalpn: bool,
    /// `BIT(abstract_unix_socket)` -- `:310`.
    pub(crate) abstract_unix_socket: bool,
    /// `BIT(path_as_is)` -- `:311`.
    pub(crate) path_as_is: bool,
    /// `BIT(suppress_connect_headers)` -- `:312-313`, suppress proxy `CONNECT`
    /// response headers from user callbacks.
    pub(crate) suppress_connect_headers: bool,
    /// `BIT(synthetic_error)` -- `:314`, this is a tool-internal error.
    pub(crate) synthetic_error: bool,
    /// `BIT(ssh_compression)` -- `:315`.
    pub(crate) ssh_compression: bool,
    /// `BIT(haproxy_protocol)` -- `:316`, whether to send HAProxy protocol v1.
    pub(crate) haproxy_protocol: bool,
    /// `BIT(disallow_username_in_url)` -- `:317`.
    pub(crate) disallow_username_in_url: bool,
    /// `BIT(mptcp)` -- `:318`, enable MPTCP support.
    pub(crate) mptcp: bool,
    /// `BIT(rm_partial)` -- `:319-320`, on error remove partially written
    /// output files.
    pub(crate) rm_partial: bool,
    /// `BIT(skip_existing)` -- `:321`.
    pub(crate) skip_existing: bool,
}

/// Shape, policy and counts -- never a credential, a body, a header or a URL.
///
/// # Why this is not `#[derive(Debug)]`
///
/// `struct OperationConfig` is `src/tool_cfgable.h:56-322` field for field, and
/// among its 228 fields are every credential a curl command line can carry:
/// `userpwd`, `proxyuserpwd`, `tls_password`, `proxy_tls_password`,
/// `key_passwd`, `proxy_key_passwd`, `oauth_bearer`, `aws_sigv4`; the request
/// body in `postdata`; every application header in `headers` and
/// `proxyheaders`; every URL in `url_list`; and the FTP command lists, which
/// carry a `USER`/`PASS` pair whenever `--ftp-alternative-to-user` is in play.
/// A derived formatter renders all of it, and this type is the argument every
/// option handler takes, so a single `{:?}` in any diagnostic -- present or
/// future -- would have written a password to a log.
///
/// # Why a chosen summary rather than 228 redacted fields
///
/// Two reasons, and the second is the load-bearing one:
///
/// 1. A 228-row dump is not a diagnostic. The fields a reader of a
///    configuration message wants are which request kind was selected, which
///    authentication was requested, whether verification was switched off, and
///    how many URLs, headers and cookies are in play.
/// 2. **A field-by-field redacted formatter would be safe only for as long as
///    everybody remembers to redact.** The 229th field, added later by somebody
///    who does not read this comment, would arrive unredacted. This formatter
///    names the fields it prints, so a new field is invisible to it by default
///    and the failure mode of forgetting is a missing line rather than a leaked
///    secret. `finish_non_exhaustive` says so in the output.
///
/// # What the credential fields report
///
/// Presence and length, through [`Hidden`]. That is enough to tell an unset
/// password from an empty one -- a distinction `crate::cli::args` acts on -- and
/// discloses nothing further. The three insecure flags render in full and
/// deliberately: `crate::output::msgs::warn_insecure_flags` is the mandated
/// warning path and this is the state it reports, so hiding it here would work
/// against the very thing AAP section 0.8.1 requires be visible.
impl fmt::Debug for OperationConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OperationConfig")
            // What the request is.
            .field("httpreq", &self.httpreq)
            .field("customrequest", &hidden_bytes(self.customrequest.as_ref()))
            .field("num_urls", &self.num_urls)
            .field("url_list", &self.url_list.len())
            .field("postdata", &Hidden(self.postdata.len()))
            .field("postfields", &self.postfields)
            .field("headers", &self.headers.len())
            .field("proxyheaders", &self.proxyheaders.len())
            .field("has_mime", &self.mime.is_some())
            // Who it authenticates as. Presence only.
            .field("authtype", &self.authtype)
            .field("has_userpwd", &self.userpwd.is_some())
            .field("has_proxyuserpwd", &self.proxyuserpwd.is_some())
            .field("has_tls_password", &self.tls_password.is_some())
            .field("has_proxy_tls_password", &self.proxy_tls_password.is_some())
            .field("has_key_passwd", &self.key_passwd.is_some())
            .field("has_proxy_key_passwd", &self.proxy_key_passwd.is_some())
            .field("has_oauth_bearer", &self.oauth_bearer.is_some())
            .field("has_aws_sigv4", &self.aws_sigv4.is_some())
            .field("netrc", &self.netrc)
            .field("netrc_opt", &self.netrc_opt)
            // The transport-security policy. Rendered in full on purpose.
            .field("insecure_ok", &self.insecure_ok)
            .field("doh_insecure_ok", &self.doh_insecure_ok)
            .field("proxy_insecure_ok", &self.proxy_insecure_ok)
            .field("verifystatus", &self.verifystatus)
            .field("doh_verifystatus", &self.doh_verifystatus)
            .field("ssl_version", &self.ssl_version)
            .field("ssl_version_max", &self.ssl_version_max)
            .field("has_cacert", &self.cacert.is_some())
            .field("has_capath", &self.capath.is_some())
            .field("has_cert", &self.cert.is_some())
            .field("has_key", &self.key.is_some())
            .field("has_pinnedpubkey", &self.pinnedpubkey.is_some())
            // State stores, by presence rather than by path.
            .field("cookies", &self.cookies.len())
            .field("cookiefiles", &self.cookiefiles.len())
            .field("cookiejar", &hidden_path(self.cookiejar.as_ref()))
            .field("has_altsvc", &self.altsvc.is_some())
            .field("has_hsts", &self.hsts.is_some())
            .field("has_netrc_file", &self.netrc_file.is_some())
            // Where it connects, without disclosing where.
            .field("has_proxy", &self.proxy.is_some())
            .field("has_preproxy", &self.preproxy.is_some())
            .field("has_doh_url", &self.doh_url.is_some())
            .field("has_unix_socket", &self.unix_socket_path.is_some())
            .field("resolve", &self.resolve.len())
            .field("connect_to", &self.connect_to.len())
            .field("ip_version", &self.ip_version)
            .field("httpversion", &self.httpversion)
            // FTP command lists carry credentials; count them only.
            .field("quote", &self.quote.len())
            .field("postquote", &self.postquote.len())
            .field("prequote", &self.prequote.len())
            // Timing and limits, which hold nothing sensitive.
            .field("timeout_ms", &self.timeout_ms)
            .field("connecttimeout_ms", &self.connecttimeout_ms)
            .field("maxredirs", &self.maxredirs)
            .field("followlocation", &self.followlocation)
            .field("max_filesize", &self.max_filesize)
            .finish_non_exhaustive()
    }
}

impl Default for OperationConfig {
    /// `config_alloc` -- `src/tool_cfgable.c:36-57`.
    ///
    /// # The three insecure flags are false, and that is a guarantee
    ///
    /// `insecure_ok`, `doh_insecure_ok` and `proxy_insecure_ok` are false here
    /// because the C `calloc` zeroes them, and that is the tool-side half of
    /// the default-on verification guarantee. The library side lives in
    /// `curl-rs-lib`; what this side has to get right is that nothing turns
    /// verification on, because it was never off. The option applier only ever
    /// turns it **off**, and only when one of these three bits is set --
    /// `src/config2setopts.c:378-381` -- so inverting the polarity of any of
    /// the three would silently disable verification for every invocation.
    /// That is why they are asserted by a test rather than left to inspection.
    fn default() -> Self {
        Self {
            // `curlx_dyn_init(&config->postdata, MAX_FILE2MEMORY)` -- `:55`.
            // Empty, and the ceiling belongs to the append site; see the field.
            postdata: Vec::new(),
            useragent: None,
            cookies: Vec::new(),
            cookiejar: None,
            cookiefiles: Vec::new(),
            altsvc: None,
            hsts: None,
            proto_str: None,
            proto_redir_str: None,
            // `config->proto_default = NULL` -- `:48`.
            proto_default: None,
            resume_from: 0,
            postfields: false,
            referer: None,
            query: None,
            max_filesize: 0,
            output_dir: None,
            headerfile: None,
            ftpport: None,
            iface: None,
            range: None,
            dns_servers: None,
            dns_interface: None,
            dns_ipv4_addr: None,
            dns_ipv6_addr: None,
            userpwd: None,
            login_options: None,
            tls_username: None,
            tls_password: None,
            tls_authtype: None,
            proxy_tls_username: None,
            proxy_tls_password: None,
            proxy_tls_authtype: None,
            proxyuserpwd: None,
            proxy: None,
            noproxy: None,
            knownhosts: None,
            mail_from: None,
            mail_rcpt: Vec::new(),
            mail_auth: None,
            sasl_authzid: None,
            netrc_file: None,
            url_list: Vec::new(),
            url_get: None,
            url_out: None,
            url_ul: None,
            num_urls: 0,
            getout_seq: GetOutSeq::new(),
            ipfs_gateway: None,
            doh_url: None,
            cipher_list: None,
            proxy_cipher_list: None,
            cipher13_list: None,
            proxy_cipher13_list: None,
            cert: None,
            proxy_cert: None,
            cert_type: None,
            proxy_cert_type: None,
            cacert: None,
            proxy_cacert: None,
            capath: None,
            proxy_capath: None,
            crlfile: None,
            proxy_crlfile: None,
            pinnedpubkey: None,
            proxy_pinnedpubkey: None,
            key: None,
            proxy_key: None,
            key_type: None,
            proxy_key_type: None,
            key_passwd: None,
            proxy_key_passwd: None,
            pubkey: None,
            hostpubmd5: None,
            hostpubsha256: None,
            engine: None,
            etag_save_file: None,
            etag_compare_file: None,
            customrequest: None,
            ssl_ec_curves: None,
            ssl_signature_algorithms: None,
            krblevel: None,
            request_target: None,
            writeout: None,
            quote: Vec::new(),
            postquote: Vec::new(),
            prequote: Vec::new(),
            headers: Vec::new(),
            proxyheaders: Vec::new(),
            mime: None,
            telnet_options: Vec::new(),
            resolve: Vec::new(),
            connect_to: Vec::new(),
            preproxy: None,
            proxy_service_name: None,
            service_name: None,
            ftp_account: None,
            ftp_alternative_to_user: None,
            oauth_bearer: None,
            unix_socket_path: None,
            haproxy_clientip: None,
            aws_sigv4: None,
            ech: None,
            ech_config: None,
            ech_public: None,
            condtime: 0,
            sendpersecond: 0,
            recvpersecond: 0,
            proxy_ssl_version: 0,
            ip_version: 0,
            create_file_mode: 0,
            low_speed_limit: 0,
            low_speed_time: 0,
            ip_tos: 0,
            vlan_priority: 0,
            localport: 0,
            localportrange: 0,
            authtype: 0,
            timeout_ms: 0,
            connecttimeout_ms: 0,
            // `config->maxredirs = DEFAULT_MAXREDIRS` -- `:45`.
            maxredirs: DEFAULT_MAXREDIRS,
            httpversion: 0,
            socks5_auth: 0,
            req_retry: 0,
            retry_delay_ms: 0,
            retry_maxtime_ms: 0,
            mime_options: 0,
            tftp_blksize: 0,
            alivetime: 0,
            alivecnt: 0,
            gssapi_delegation: 0,
            expect100timeout_ms: 0,
            // `config->happy_eyeballs_timeout_ms = CURL_HET_DEFAULT` -- `:50`.
            happy_eyeballs_timeout_ms: 200,
            timecond: 0,
            followlocation: 0,
            httpreq: HttpReq::Unspec,
            proxyver: 0,
            ftp_ssl_ccc_mode: 0,
            ftp_filemethod: 0,
            // `config->file_clobber_mode = CLOBBER_DEFAULT` -- `:53`.
            file_clobber_mode: ClobberMode::Default,
            // `config->upload_flags = CURLULFLAG_SEEN` -- `:54`.
            upload_flags: 1 << 4,
            porttouse: 0,
            ssl_version: 0,
            ssl_version_max: 0,
            fail: FailMode::None,
            remote_name_all: false,
            remote_time: false,
            cookiesession: false,
            encoding: false,
            tr_encoding: false,
            use_resume: false,
            resume_from_current: false,
            disable_epsv: false,
            disable_eprt: false,
            ftp_pret: false,
            // `config->proto_present = FALSE` -- `:46`.
            proto_present: false,
            // `config->proto_redir_present = FALSE` -- `:47`.
            proto_redir_present: false,
            mail_rcpt_allowfails: false,
            sasl_ir: false,
            proxytunnel: false,
            ftp_append: false,
            use_ascii: false,
            autoreferer: false,
            show_headers: false,
            no_body: false,
            dirlistonly: false,
            unrestricted_auth: false,
            netrc_opt: false,
            netrc: false,
            crlf: false,
            // `config->http09_allowed = FALSE` -- `:51`.
            http09_allowed: false,
            nobuffer: false,
            readbusy: false,
            globoff: false,
            // `config->use_httpget = FALSE` -- `:43`.
            use_httpget: false,
            insecure_ok: false,
            doh_insecure_ok: false,
            proxy_insecure_ok: false,
            terminal_binary_ok: false,
            verifystatus: false,
            doh_verifystatus: false,
            // `config->create_dirs = FALSE` -- `:44`.
            create_dirs: false,
            ftp_create_dirs: false,
            // `config->ftp_skip_ip = TRUE` -- `:52`.
            ftp_skip_ip: true,
            proxynegotiate: false,
            proxyntlm: false,
            proxydigest: false,
            proxybasic: false,
            proxyanyauth: false,
            jsoned: false,
            ftp_ssl: false,
            ftp_ssl_reqd: false,
            ftp_ssl_control: false,
            ftp_ssl_ccc: false,
            socks5_gssapi_nec: false,
            // `config->tcp_nodelay = TRUE; /* enabled by default */` -- `:49`.
            tcp_nodelay: true,
            tcp_fastopen: false,
            retry_all_errors: false,
            retry_connrefused: false,
            tftp_no_options: false,
            ignorecl: false,
            disable_sessionid: false,
            raw: false,
            post301: false,
            post302: false,
            post303: false,
            nokeepalive: false,
            content_disposition: false,
            xattr: false,
            ssl_allow_beast: false,
            ssl_allow_earlydata: false,
            proxy_ssl_allow_beast: false,
            ssl_no_revoke: false,
            ssl_revoke_best_effort: false,
            native_ca_store: false,
            proxy_native_ca_store: false,
            ssl_auto_client_cert: false,
            proxy_ssl_auto_client_cert: false,
            noalpn: false,
            abstract_unix_socket: false,
            path_as_is: false,
            suppress_connect_headers: false,
            synthetic_error: false,
            ssh_compression: false,
            haproxy_protocol: false,
            disallow_username_in_url: false,
            mptcp: false,
            rm_partial: false,
            skip_existing: false,
        }
    }
}

/// The three verification bits, read straight off the configuration that holds
/// them.
///
/// This is the whole point of [`InsecureRequest`] being a trait: the warning can
/// only be told what was requested by something that knows, and the thing that
/// knows is this struct -- `src/tool_cfgable.h:258-261` is where C keeps the
/// same three bits, and `src/config2setopts.c:378-393` is where it reads them.
///
/// No transformation, no defaulting and no interpretation. Each method returns
/// the field the option parser set at `crate::cli::args`
/// (`CmdKey::Insecure`, `CmdKey::DohInsecure` and `CmdKey::ProxyInsecure`), so
/// there is no step between "the user asked" and "the warning was emitted" that
/// could quietly disagree.
impl InsecureRequest for OperationConfig {
    fn insecure(&self) -> bool {
        self.insecure_ok
    }

    fn doh_insecure(&self) -> bool {
        self.doh_insecure_ok
    }

    fn proxy_insecure(&self) -> bool {
        self.proxy_insecure_ok
    }
}

// The inventory allowance this block has always carried: several accessors here
// stand in for `struct OperationConfig` members whose production consumers --
// `crate::config::to_setopts` chiefly -- have not landed, so today only tests
// call them. It sits on the inherent block and NOT on the trait implementation
// above, which needs no allowance: `InsecureRequest` is called from
// `crate::main` through `warn_insecure_flags`.
#[allow(dead_code)]
impl OperationConfig {
    /// `config_alloc` -- `src/tool_cfgable.c:36-57`.
    ///
    /// Named for the C function so that the correspondence is searchable;
    /// identical to [`OperationConfig::default`], which is where the twelve
    /// frozen assignments are documented.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// `config->url_last` -- `src/tool_cfgable.h:103`, "point to the
    /// last/current node".
    pub(crate) fn url_last(&self) -> Option<usize> {
        self.url_list.len().checked_sub(1)
    }

    /// Appends one node and reports the index it took.
    ///
    /// # Errors
    ///
    /// [`TryReserveError`] when the node cannot be stored, which is `:37`'s
    /// `curlx_calloc` returning `NULL`. The reservation is made *before* the
    /// push so that a failure leaves the list exactly as it was, which is what
    /// `:39`'s `if(node)` guarantees in the C. `Vec::push` on its own aborts
    /// the process instead of reporting, so the fallible reservation is what
    /// keeps the C's error path reachable.
    ///
    /// The caller that owns the parameter vocabulary maps this to its own
    /// out-of-memory variant, which every C call site turns into
    /// `PARAM_NO_MEM`. That mapping, and the two-line
    /// `impl crate::cli::paramhlp::UrlList for OperationConfig` that carries
    /// it, belong to the module that owns that vocabulary rather than to this
    /// one: the error type is declared in `curl-rs/src/cli/args.rs`, which is
    /// not among this file's dependencies, and `crate::cli::paramhlp` keeps it
    /// out of its own imports for the same reason. The three capabilities the
    /// port needs are this method, [`OperationConfig::remote_name_all`] and
    /// [`OperationConfig::getout_sequence_mut`].
    pub(crate) fn push_getout(
        &mut self,
        node: NewGetOut,
    ) -> Result<usize, TryReserveError> {
        self.url_list.try_reserve(1)?;
        let position = self.url_list.len();
        self.url_list.push(GetOut {
            num: node.num,
            useremote: node.useremote,
            ..GetOut::default()
        });
        Ok(position)
    }

    /// `config->remote_name_all` -- read by `new_getout` at
    /// `src/tool_paramhlp.c:51`.
    pub(crate) fn remote_name_all(&self) -> bool {
        self.remote_name_all
    }

    /// The counter behind `node->num`; see [`OperationConfig::getout_seq`].
    ///
    /// Handed out as a borrow rather than passed alongside the list because an
    /// owner that holds both cannot lend two exclusive borrows of itself at
    /// once, and a window in which the list has grown but the counter has not
    /// is exactly what `new_getout` exists to prevent.
    pub(crate) fn getout_sequence_mut(&mut self) -> &mut GetOutSeq {
        &mut self.getout_seq
    }
}

/// Where `--trace` output goes -- `FILE *trace_stream`
/// (`src/tool_cfgable.h:334`) together with `BIT(trace_fopened)` (`:359`).
///
/// C keeps the pair because a `FILE *` does not say who owns it, and only the
/// owner may close it: `free_globalconfig` calls `curlx_fclose` **only** when
/// `trace_fopened && trace_stream` (`src/tool_cfgable.c:259-260`) and then
/// clears the pointer unconditionally (`:261`). Closing a borrowed standard
/// stream instead would take the tool's own diagnostics down with it.
#[derive(Debug, Default)]
#[allow(dead_code)]
pub(crate) enum TraceStream {
    /// `trace_stream == NULL` -- nothing has been opened yet, which is the
    /// state `calloc` leaves and the state `:261` restores.
    #[default]
    Closed,
    /// `global->trace_stream = stdout` -- `--trace -` (`:171-172`). Borrowed,
    /// so `trace_fopened` stays false and nothing is closed.
    Stdout,
    /// `global->trace_stream = tool_stderr` -- `--trace %` (`:173-175`), which
    /// the C comment calls "somewhat hackish but we do it undocumented for
    /// now". Borrowed on the same terms.
    Stderr,
    /// `curlx_fopen(global->trace_dump, FOPEN_WRITETEXT)` with
    /// `trace_fopened = TRUE` (`:177-178`). Owned, and the only variant that
    /// closes anything.
    File(File),
}

#[allow(dead_code)]
impl TraceStream {
    /// `global->trace_fopened` -- whether this stream was opened here and must
    /// therefore be closed here.
    pub(crate) fn is_fopened(&self) -> bool {
        matches!(*self, Self::File(_))
    }

    /// `free_globalconfig`'s stream half -- `src/tool_cfgable.c:259-261`.
    ///
    /// Closes the handle when, and only when, this value owns one, and then
    /// returns to [`TraceStream::Closed`] unconditionally, which is `:261`'s
    /// `global->trace_stream = NULL`. Dropping the [`File`] is the `fclose`.
    pub(crate) fn close(&mut self) {
        let previous = std::mem::replace(self, Self::Closed);
        drop(previous);
    }
}

/// The per-invocation cursor set -- `struct State`
/// (`src/tool_cfgable.h:44-54`), whose C comment reads "for
/// create_transfer()".
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct State {
    /// `struct getout *urlnode` -- `:45`, an index into
    /// [`OperationConfig::url_list`] rather than a pointer into the chain.
    pub(crate) urlnode: Option<usize>,
    /// `struct URLGlob inglob` -- `:46`, the upload-name glob.
    pub(crate) inglob: Option<UrlGlob>,
    /// `struct URLGlob urlglob` -- `:47`, the URL glob, on the same terms.
    pub(crate) urlglob: Option<UrlGlob>,
    /// `char *httpgetfields` -- `:48`.
    ///
    /// `Vec<u8>` because these are the `--data` bytes: C moves the pointer here
    /// from `config->postfields` at `src/tool_operate.c:1417` and clears the
    /// source at `:1418`, which taking the bytes out of
    /// [`OperationConfig::postdata`] reproduces exactly.
    pub(crate) httpgetfields: Option<Vec<u8>>,
    /// `char *uploadfile` -- `:49`, a byte string for the same reason
    /// [`GetOut::infile`] is: it is globbed before it is opened.
    pub(crate) uploadfile: Option<Vec<u8>>,
    /// `curl_off_t upnum` -- `:50`, the number of files to upload.
    pub(crate) upnum: i64,
    /// `curl_off_t upidx` -- `:51`, the index for the upload glob.
    pub(crate) upidx: i64,
    /// `curl_off_t urlnum` -- `:52`, how many iterations this URL has with
    /// ranges and so on.
    pub(crate) urlnum: i64,
    /// `curl_off_t urlidx` -- `:53`, the index for globbed URLs.
    pub(crate) urlidx: i64,
}

/// The chain of operation configurations -- C's `first`, `current` and `last`
/// (`src/tool_cfgable.h:338-340`) over the `prev`/`next` links of
/// `src/tool_cfgable.h:171-172`.
///
/// `--next` (`-:`) starts a new operation, so the tool holds a sequence rather
/// than a single configuration. C threads it as a doubly-linked list and keeps
/// three pointers into it; this is the same sequence owned outright, with the
/// three pointers as indices. AAP section 0.6.9 prescribes exactly that
/// exchange, and it removes two failure modes that the C shape allows: a
/// `first` and `last` that disagree, and a retained pointer that outlives the
/// node.
///
/// # Teardown runs backwards, and that has to be arranged
///
/// `config_free` (`src/tool_cfgable.c:193-206`) is handed `global->last` and
/// walks `prev`, with the comment "Free each of the structures in reverse
/// order". A `Vec` does the opposite: its own drop glue releases element 0
/// first. Reproducing the C order therefore takes an explicit
/// [`Drop`] that pops, which is what [`ConfigChain::release`] does, rather than
/// letting the vector drop itself.
#[derive(Default)]
#[allow(dead_code)]
pub(crate) struct ConfigChain {
    /// The operations in command-line order. Index 0 is C's `first`, and the
    /// final element is C's `last`.
    configs: Vec<OperationConfig>,
    /// `global->current` -- `src/tool_cfgable.h:339`.
    ///
    /// [`None`] initially, because `globalconf_init` does not set it: the C
    /// `calloc` leaves it `NULL` and the option parser is what points it
    /// somewhere.
    current: Option<usize>,
}

/// The chain's shape, with each operation redacted by its own formatter.
///
/// Hand-written only because the derive was removed from [`OperationConfig`].
/// Rendering the operations rather than only their count is safe -- each one
/// redacts itself -- and it is what makes the chain's structure debuggable,
/// which matters because `--next` builds a chain whose length is the thing
/// usually in question. `current` is an index and holds nothing sensitive.
impl fmt::Debug for ConfigChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfigChain")
            .field("configs", &self.configs)
            .field("current", &self.current)
            .finish()
    }
}

#[allow(dead_code)]
impl ConfigChain {
    /// The chain `globalconf_init` builds at `src/tool_cfgable.c:229`:
    /// `global->first = global->last = config_alloc();`.
    ///
    /// One operation, so `first` and `last` are the same element, and no
    /// `current`.
    pub(crate) fn new(initial: OperationConfig) -> Self {
        Self {
            configs: vec![initial],
            current: None,
        }
    }

    /// How many operations the chain holds.
    pub(crate) fn len(&self) -> usize {
        self.configs.len()
    }

    /// Whether the chain has been released; a live chain always holds at least
    /// the operation `globalconf_init` allocated.
    pub(crate) fn is_empty(&self) -> bool {
        self.configs.is_empty()
    }

    /// `global->first` -- `src/tool_cfgable.h:338`.
    pub(crate) fn first(&self) -> Option<&OperationConfig> {
        self.configs.first()
    }

    /// `global->first`, mutably.
    pub(crate) fn first_mut(&mut self) -> Option<&mut OperationConfig> {
        self.configs.first_mut()
    }

    /// `global->last` -- `src/tool_cfgable.h:340`.
    pub(crate) fn last(&self) -> Option<&OperationConfig> {
        self.configs.last()
    }

    /// `global->last`, mutably. This is the receiver the option parser fills
    /// in, and the reason the model cannot be immutable.
    pub(crate) fn last_mut(&mut self) -> Option<&mut OperationConfig> {
        self.configs.last_mut()
    }

    /// The index of `global->last`.
    pub(crate) fn last_index(&self) -> Option<usize> {
        self.configs.len().checked_sub(1)
    }

    /// `global->current` -- [`None`] until the parser sets it.
    pub(crate) fn current(&self) -> Option<&OperationConfig> {
        self.current.and_then(|at| self.configs.get(at))
    }

    /// `global->current`, mutably; see
    /// [`ConfigChain::last_mut`] for why mutable access exists.
    pub(crate) fn current_mut(&mut self) -> Option<&mut OperationConfig> {
        match self.current {
            Some(at) => self.configs.get_mut(at),
            None => None,
        }
    }

    /// The index `global->current` holds, whether or not it is in range.
    pub(crate) fn current_index(&self) -> Option<usize> {
        self.current
    }

    /// Points `global->current` at `at`, or clears it with [`None`].
    pub(crate) fn set_current(&mut self, at: Option<usize>) -> bool {
        match at {
            Some(index) if index >= self.configs.len() => false,
            other => {
                self.current = other;
                true
            }
        }
    }

    /// One operation by index, which is what a stored cursor resolves to.
    pub(crate) fn get(&self, at: usize) -> Option<&OperationConfig> {
        self.configs.get(at)
    }

    /// One operation by index, mutably.
    pub(crate) fn get_mut(
        &mut self,
        at: usize,
    ) -> Option<&mut OperationConfig> {
        self.configs.get_mut(at)
    }

    /// Appends one operation and reports the index it took, which becomes the
    /// new `global->last`.
    ///
    /// # Errors
    ///
    /// [`TryReserveError`] when the operation cannot be stored, which is C's
    /// `config_alloc` returning `NULL`. Reserved before the push so that a
    /// failure leaves the chain exactly as it was.
    pub(crate) fn append(
        &mut self,
        config: OperationConfig,
    ) -> Result<usize, TryReserveError> {
        self.configs.try_reserve(1)?;
        let position = self.configs.len();
        self.configs.push(config);
        Ok(position)
    }

    /// The order `config_free` releases the chain in: last to first.
    ///
    /// Exposed rather than left implicit because it is the order
    /// [`ConfigChain::release`] uses, so a test can assert the sequence that
    /// teardown really follows instead of a restatement of it.
    pub(crate) fn teardown_order(&self) -> Vec<usize> {
        (0..self.configs.len()).rev().collect()
    }

    /// `config_free(global->last)` -- `src/tool_cfgable.c:193-206`, then
    /// `global->first = global->last = NULL` at `:283-284`.
    ///
    /// Pops rather than clears, so each operation is released after the one
    /// that follows it, which is the direction the `prev` walk takes. Leaves
    /// the chain empty, which is what the two `NULL` assignments do.
    pub(crate) fn release(&mut self) {
        self.current = None;
        while self.configs.pop().is_some() {
            // The pop *is* the release: dropping the popped value runs the
            // whole of `free_config_fields` (`:59-191`) for it, in one step
            // and with nothing left behind for a later pass to find.
        }
    }
}

impl Drop for ConfigChain {
    /// Releases the chain in `config_free`'s order even when this value is
    /// dropped on its own rather than through [`GlobalConfig`].
    fn drop(&mut self) {
        self.release();
    }
}

/// The whole tool's configuration -- `struct GlobalConfig`
/// (`src/tool_cfgable.h:331-367`).
#[allow(dead_code)]
pub(crate) struct GlobalConfig {
    /// `struct State state` -- `:332`, "for create_transfer()".
    pub(crate) state: State,
    /// `char *trace_dump` -- `:333`, the file to dump the network trace to.
    ///
    /// The name, not the handle: [`GlobalConfig::trace_stream`] is the handle,
    /// and `src/tool_cb_dbg.c:169-179` reads this name to decide which of the
    /// three destinations to open on first use.
    pub(crate) trace_dump: Option<PathBuf>,
    /// `FILE *trace_stream` -- `:334`, with `trace_fopened` folded in.
    pub(crate) trace_stream: TraceStream,
    /// `char *libcurl` -- `:335`, "Output libcurl code to this filename".
    pub(crate) libcurl: Option<PathBuf>,
    /// `char *ssl_sessions` -- `:336`, the file to load and save TLS session
    /// tickets from, which `--ssl-sessions` names.
    pub(crate) ssl_sessions: Option<PathBuf>,
    /// `struct tool_var *variables` -- `:337`.
    ///
    /// `crate::cli::vars` owns the type and documents the relocation of
    /// `varcleanup` (`src/var.c:37-46`); its single C call site is
    /// `src/tool_operate.c:2396`, and dropping this value is what replaces it.
    pub(crate) variables: Variables,
    /// `first`, `current` and `last` -- `:338-340`, as one owned chain.
    pub(crate) chain: ConfigChain,
    /// `timediff_t ms_per_transfer` -- `:344-345`, start the next transfer
    /// after at least this many milliseconds.
    pub(crate) ms_per_transfer: i64,
    /// `trace tracetype` -- `:346`.
    pub(crate) tracetype: TraceType,
    /// `int progressmode` -- `:347`, `CURL_PROGRESS_BAR` or
    /// `CURL_PROGRESS_STATS`.
    pub(crate) progressmode: i32,
    /// `unsigned short parallel_host` -- `:348`; `MAX_PARALLEL_HOST` is the
    /// maximum, and both bounds are `operate/`'s constants.
    pub(crate) parallel_host: u16,
    /// `unsigned short parallel_max` -- `:349`; `MAX_PARALLEL` is the maximum.
    pub(crate) parallel_max: u16,
    /// `unsigned char verbosity` -- `:350`, how verbose to be.
    pub(crate) verbosity: u8,
    /// What `get_libcurl_info()` returned at `src/tool_cfgable.c:235`.
    pub(crate) libinfo: LibInfo,
    /// `BIT(parallel)` -- `:355`.
    pub(crate) parallel: bool,
    /// `BIT(parallel_connect)` -- `:356`.
    pub(crate) parallel_connect: bool,
    /// `BIT(fail_early)` -- `:357`, exit on the first transfer error.
    pub(crate) fail_early: bool,
    /// `BIT(styled_output)` -- `:358`, enable fancy output style detection.
    pub(crate) styled_output: bool,
    /// `BIT(tracetime)` -- `:360`, include a timestamp.
    pub(crate) tracetime: bool,
    /// `BIT(traceids)` -- `:361`, include the transfer and connection
    /// identifiers.
    pub(crate) traceids: bool,
    /// `BIT(showerror)` -- `:362`, show errors when silent.
    pub(crate) showerror: bool,
    /// `BIT(silent)` -- `:363`, do not show messages, `--silent` given.
    pub(crate) silent: bool,
    /// `BIT(noprogress)` -- `:364`, do not show the progress bar.
    pub(crate) noprogress: bool,
    /// `BIT(isatty)` -- `:365`, updated internally if the output is a terminal.
    pub(crate) isatty: bool,
    /// `BIT(trace_set)` -- `:366`, `--trace-config` has been used.
    ///
    /// The bit only. What `--trace-config` parsed into is the engine's
    /// `TraceConfig`, which owns the component mask and its acceptance rules;
    /// this file holds the fact that the option was given, exactly as the C
    /// bitfield does.
    pub(crate) trace_set: bool,
}

/// `curl_global_init(CURL_GLOBAL_DEFAULT)` -- `src/tool_cfgable.c:232`.
///
/// The reason is structural rather than an omission. `curl_global_init` exists
/// to initialize process-global state -- C's `global_init`
/// (`lib/easy.c:124-192`) performs eight subsystem initializations behind a
/// reference count -- and in this workspace that reference count and those
/// subsystems belong to `curl-rs-ffi`, the crate that owns the C ABI.
fn library_init() -> CURLcode {
    CURLcode::Ok
}

#[allow(dead_code)]
impl GlobalConfig {
    /// `globalconf_init` -- `src/tool_cfgable.c:213-253`.
    ///
    /// # The value exists only on success, which is the whole point
    ///
    /// `src/tool_main.c:186-193` calls `globalconf_free()` **only** when
    /// `globalconf_init()` succeeded:
    ///
    /// ```c
    /// result = globalconf_init();
    /// if(!result) {
    ///   result = operate(argc, argv);
    ///   globalconf_free();
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// [`CURLcode::FailedInit`] when the initial operation cannot be allocated
    /// (`:248-249`), the code the library initialization reported (`:243`), or
    /// the code from `get_libcurl_info()` (`:238`). Each arrives with the
    /// frozen message described in [`GlobalConfig::init_with`].
    pub(crate) fn init(
        sink: &mut dyn DiagnosticSink,
        msgs: &MsgConfig,
    ) -> Result<Self, CURLcode> {
        Self::init_with(
            Some(OperationConfig::new()),
            library_init,
            crate::cli::libinfo::get_libcurl_info,
            sink,
            msgs,
        )
    }

    /// `globalconf_init`'s body, with its three outcomes supplied.
    ///
    /// [`GlobalConfig::init`] is this function with the real ones. The split
    /// exists because C's three failure branches are reachable and this
    /// design's are not reachable through the production arguments: the
    /// allocation the first branch guards is fixed-size, with no stable
    /// fallible spelling at the declared minimum Rust version, and the two
    /// calls that follow cannot fail on this path. The branches are
    /// nonetheless part of the frozen behaviour -- three messages, three
    /// codes, one ordering -- so they are written once, here, where a caller
    /// can drive each of them and assert the bytes and the code.
    fn init_with<L, I>(
        initial: Option<OperationConfig>,
        library: L,
        libcurl_info: I,
        sink: &mut dyn DiagnosticSink,
        msgs: &MsgConfig,
    ) -> Result<Self, CURLcode>
    where
        L: FnOnce() -> CURLcode,
        I: FnOnce() -> Result<LibInfo, Error>,
    {
        // `:229` -- `global->first = global->last = config_alloc();`, then
        // `:230`'s `if(global->first)`.
        let initial = match initial {
            Some(config) => config,
            None => {
                // `:248` -- the message, and `:249` -- the code. This is the
                // one branch that names its own code rather than reporting one
                // it was given.
                errorf(sink, msgs, format_args!("error initializing curl"));
                return Err(CURLcode::FailedInit);
            }
        };

        // `:232` -- `result = curl_global_init(CURL_GLOBAL_DEFAULT);`.
        let outcome = library();
        if outcome != CURLcode::Ok {
            // `:243` -- the message. C frees `global->first` at `:244` and
            // returns `result`; here the operation was never bound to a
            // configuration, so there is nothing to free.
            errorf(sink, msgs, format_args!("error initializing curl library"));
            return Err(outcome);
        }

        // `:235` -- `result = get_libcurl_info();`.
        let libinfo = match libcurl_info() {
            Ok(info) => info,
            Err(error) => {
                // `:238` -- the message, and `:239`'s free, which again has
                // nothing to release.
                errorf(
                    sink,
                    msgs,
                    format_args!("error retrieving curl library information"),
                );
                return Err(error.code());
            }
        };

        Ok(Self {
            state: State::default(),
            trace_dump: None,
            trace_stream: TraceStream::Closed,
            libcurl: None,
            ssl_sessions: None,
            variables: Variables::default(),
            // `:229` -- one operation, so `first` and `last` are the same
            // element. `global->current` stays unset: `globalconf_init` never
            // assigns it, the C `calloc` leaves it `NULL`, and the option
            // parser is what points it somewhere.
            chain: ConfigChain::new(initial),
            ms_per_transfer: 0,
            tracetype: TraceType::None,
            progressmode: 0,
            parallel_host: 0,
            // `:226` -- `global->parallel_max = PARALLEL_DEFAULT;`.
            //
            // One site, so one line to change when the name becomes
            // importable.
            parallel_max: 50,
            verbosity: 0,
            libinfo,
            parallel: false,
            parallel_connect: false,
            fail_early: false,
            // `:225` -- `global->styled_output = TRUE; /* enable detection */`.
            styled_output: true,
            tracetime: false,
            traceids: false,
            // `:224` -- `global->showerror = FALSE;`, whose C comment reads
            // "show errors when silent".
            showerror: false,
            silent: false,
            noprogress: false,
            isatty: false,
            trace_set: false,
        })
    }
}

impl Drop for GlobalConfig {
    /// `globalconf_free` -- `src/tool_cfgable.c:274-285`.
    ///
    /// The three steps are performed in the C's order, and the order is
    /// arranged here rather than left to Rust's drop glue, because that glue
    /// releases fields in declaration order and would run step 3 before step 2
    /// finished:
    ///
    /// 1. `curl_global_cleanup()` (`:278`). Nothing to call, for the reason
    ///    [`library_init`] gives about its counterpart: the reference count and
    ///    the subsystems it releases belong to `curl-rs-ffi`, not to this
    ///    crate's path into the engine. It keeps its position so that the two
    ///    steps below stay after it.
    /// 2. `free_globalconfig()` (`:279`, defined at `:255-268`): release
    ///    `trace_dump` (`:257`), close `trace_stream` **only** when it was
    ///    opened here and clear it either way (`:259-261`), then release
    ///    `ssl_sessions` (`:263`) and `libcurl` (`:264`). `Option::take` is
    ///    `tool_safefree` (`src/tool_cfgable.h:36-40`): it releases the value
    ///    and leaves the field empty, so a second pass finds nothing.
    /// 3. `config_free(global->last)` (`:282`) and the two `NULL` assignments
    ///    at `:283-284`, which [`ConfigChain::release`] performs in the reverse
    ///    order `:197` requires.
    fn drop(&mut self) {
        // Step 2 -- `free_globalconfig`.
        drop(self.trace_dump.take());
        self.trace_stream.close();
        drop(self.ssl_sessions.take());
        drop(self.libcurl.take());

        // Step 3 -- `config_free(global->last)`, last to first.
        self.chain.release();
    }
}

// Cross-checks
//
// These are that coverage for this module: every frozen default, every pinned
// discriminant, and every preserved ordering, asserted against the C original
// by line.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::msgs::ERROR_PREFIX;

    /// A configuration under which `errorf` emits.
    ///
    /// The gate at `src/tool_msgs.c:131` is `!global->silent ||
    /// global->showerror`, so a silent configuration would make every message
    /// assertion below vacuously true.
    fn loud() -> MsgConfig {
        MsgConfig::new(false, true, false)
    }

    /// The bytes `errorf` produces for a message short enough not to wrap.
    fn expected(message: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(ERROR_PREFIX.as_bytes());
        bytes.extend_from_slice(message.as_bytes());
        bytes.push(b'\n');
        bytes
    }

    #[test]
    fn config_alloc_reproduces_all_twelve_explicit_defaults() {
        let config = OperationConfig::new();

        // `src/tool_cfgable.c:43-54`, in the C's own order.
        assert!(!config.use_httpget, ":43");
        assert!(!config.create_dirs, ":44");
        assert_eq!(config.maxredirs, DEFAULT_MAXREDIRS, ":45");
        assert_eq!(config.maxredirs, 50, "DEFAULT_MAXREDIRS is 50L");
        assert!(!config.proto_present, ":46");
        assert!(!config.proto_redir_present, ":47");
        assert!(config.proto_default.is_none(), ":48");
        assert!(config.tcp_nodelay, ":49 -- enabled by default");
        assert_eq!(
            config.happy_eyeballs_timeout_ms, 200,
            ":50 -- CURL_HET_DEFAULT, include/curl/curl.h:967"
        );
        assert!(!config.http09_allowed, ":51");
        assert!(config.ftp_skip_ip, ":52");
        assert_eq!(config.file_clobber_mode, ClobberMode::Default, ":53");
        assert_eq!(
            config.upload_flags,
            1 << 4,
            ":54 -- CURLULFLAG_SEEN, include/curl/curl.h:1042"
        );

        // `:55` -- `curlx_dyn_init(&config->postdata, MAX_FILE2MEMORY)`.
        assert!(config.postdata.is_empty(), ":55");
        assert!(!config.postfields, "the designation bit starts clear");

        // `Default` and the named constructor are the same value, so no caller
        // can pick up a configuration missing the twelve.
        assert_eq!(config, OperationConfig::default());
    }

    #[test]
    fn the_three_insecure_flags_start_false() {
        // C gets this from `calloc`; a Rust `Default` has to state it, and
        // inverting any one of the three would disable certificate
        // verification for every invocation while still compiling and still
        // passing every other test in this file.
        let config = OperationConfig::default();
        assert!(!config.insecure_ok, "src/tool_cfgable.h:258");
        assert!(!config.doh_insecure_ok, "src/tool_cfgable.h:259-260");
        assert!(!config.proxy_insecure_ok, "src/tool_cfgable.h:261-262");

        // The neighbouring verification bits are not inverted either.
        assert!(!config.verifystatus, "src/tool_cfgable.h:264");
        assert!(!config.doh_verifystatus, "src/tool_cfgable.h:265");
        assert!(!config.ssl_no_revoke, "src/tool_cfgable.h:300");
    }

    #[test]
    fn the_constants_this_file_owns_hold_their_frozen_values() {
        // `src/tool_cfgable.h:32` and `src/tool_main.h:28`.
        assert_eq!(MAX_CONFIG_LINE_LENGTH, 10 * 1024 * 1024);
        assert_eq!(MAX_CONFIG_LINE_LENGTH, 10_485_760);
        assert_eq!(DEFAULT_MAXREDIRS, 50);
    }

    #[test]
    fn the_fail_tri_state_keeps_the_c_values() {
        // `src/tool_cfgable.h:56-58`.
        assert_eq!(FailMode::None as u8, 0);
        assert_eq!(FailMode::WithBody as u8, 1);
        assert_eq!(FailMode::WithoutBody as u8, 2);
        assert_eq!(FailMode::default(), FailMode::None);
    }

    #[test]
    fn the_clobber_mode_defaults_to_the_compatibility_behaviour() {
        // `src/tool_cfgable.h:212-220`. The first variant is the one `calloc`
        // leaves and the one `config_alloc` also assigns explicitly at `:53`.
        assert_eq!(ClobberMode::Default as u8, 0);
        assert_eq!(ClobberMode::Never as u8, 1);
        assert_eq!(ClobberMode::Always as u8, 2);
        assert_eq!(ClobberMode::default(), ClobberMode::Default);
    }

    #[test]
    fn the_trace_type_preserves_the_c_declaration_order() {
        // `src/tool_sdecls.h:104-109`. `TRACE_NONE` must be the zero value,
        // because that is what "tracing is off" is compared against.
        assert_eq!(TraceType::None as u8, 0);
        assert_eq!(TraceType::Bin as u8, 1);
        assert_eq!(TraceType::Ascii as u8, 2);
        assert_eq!(TraceType::Plain as u8, 3);
        assert_eq!(TraceType::default(), TraceType::None);
    }

    #[test]
    fn the_http_request_type_preserves_the_c_declaration_order() {
        // `src/tool_sdecls.h:114-121`, whose first variant is commented
        // "first in list".
        assert_eq!(HttpReq::Unspec as u8, 0);
        assert_eq!(HttpReq::Get as u8, 1);
        assert_eq!(HttpReq::Head as u8, 2);
        assert_eq!(HttpReq::MimePost as u8, 3);
        assert_eq!(HttpReq::SimplePost as u8, 4);
        assert_eq!(HttpReq::Put as u8, 5);
        assert_eq!(HttpReq::default(), HttpReq::Unspec);
        assert_eq!(OperationConfig::default().httpreq, HttpReq::Unspec);
    }

    #[test]
    fn the_ordered_list_appends_in_order_and_interprets_nothing() {
        let mut list = SlistWc::new();
        assert!(list.is_empty());
        assert_eq!(list.len(), 0);

        // Duplicates and empty strings are kept: C stores whatever
        // `curl_slist_append` was handed (`src/slist_wc.c:36`).
        for value in ["first", "second", "second", "", "last"] {
            assert!(list.append(value).is_ok());
        }

        assert_eq!(list.len(), 5);
        assert!(!list.is_empty());
        assert_eq!(
            list.items(),
            ["first", "second", "second", "", "last"],
            "appended order, duplicates and the empty string all preserved"
        );
    }

    #[test]
    fn the_ordered_list_performs_no_glob_or_wildcard_matching() {
        // "wc" is *with cache*, not *wildcard*: `src/slist_wc.h:30` reads
        // "linked-list structure with last node cache for easysrc" and neither
        // C function examines a byte of the data.
        let patterns = [
            "*",
            "?",
            "a*b?c",
            "[1-100]",
            "{one,two}",
            "http://example.com/[a-z]/#1",
            "**/*.rs",
        ];
        let mut list = SlistWc::new();
        for pattern in patterns {
            assert!(list.append(pattern).is_ok());
        }
        assert_eq!(list.items(), patterns, "every pattern round-trips");
        assert_eq!(list.len(), patterns.len(), "nothing was expanded");
    }

    #[test]
    fn the_chain_grows_and_its_tail_cursor_follows() {
        let mut chain = ConfigChain::new(OperationConfig::new());

        // `src/tool_cfgable.c:229` -- one operation, so `first` and `last` are
        // the same element and `current` is unset.
        assert_eq!(chain.len(), 1);
        assert_eq!(chain.last_index(), Some(0));
        assert!(chain.current().is_none());
        assert!(chain.current_index().is_none());
        assert_eq!(chain.first(), chain.last());

        // `--next` appends, and the tail follows because the tail is the last
        // element.
        for expected_index in 1..4 {
            let appended = chain.append(OperationConfig::new());
            assert_eq!(appended.ok(), Some(expected_index));
            assert_eq!(chain.last_index(), Some(expected_index));
            assert_eq!(chain.len(), expected_index + 1);
        }

        // A mutable borrow of one operation is what the option applier needs
        // (`src/config2setopts.c:216-217`).
        if let Some(last) = chain.last_mut() {
            last.num_urls = 7;
        }
        assert_eq!(chain.last().map(|config| config.num_urls), Some(7));
        assert_eq!(chain.first().map(|config| config.num_urls), Some(0));

        // `global->current` refuses an out-of-range index rather than storing
        // one, so a stale cursor cannot be observed.
        assert!(chain.set_current(Some(2)));
        assert_eq!(chain.current_index(), Some(2));
        assert!(!chain.set_current(Some(4)));
        assert_eq!(
            chain.current_index(),
            Some(2),
            "the refusal changed nothing"
        );
        assert!(chain.set_current(None));
        assert!(chain.current().is_none());
    }

    #[test]
    fn the_chain_is_released_last_to_first() {
        let mut chain = ConfigChain::new(OperationConfig::new());
        for index in 1..3_usize {
            let appended = chain.append(OperationConfig::new());
            assert!(appended.is_ok());
            if let Some(config) = chain.last_mut() {
                config.num_urls = index;
            }
        }

        // `config_free` is handed `global->last` and walks `prev`, commented
        // "Free each of the structures in reverse order"
        // (`src/tool_cfgable.c:193-206`). This is the sequence `release` --
        // and therefore `Drop` -- really follows, resolved against the
        // elements rather than restated as indices.
        assert_eq!(chain.teardown_order(), vec![2, 1, 0]);
        let released: Vec<usize> = chain
            .teardown_order()
            .into_iter()
            .filter_map(|at| chain.get(at).map(|config| config.num_urls))
            .collect();
        assert_eq!(released, vec![2, 1, 0], "the tail is released first");

        chain.release();
        assert!(chain.is_empty(), "src/tool_cfgable.c:283-284");
        assert!(chain.last_index().is_none());
        assert!(chain.first().is_none());
        assert!(chain.current_index().is_none());
        assert_eq!(chain.teardown_order(), Vec::<usize>::new());
    }

    #[test]
    fn a_url_node_is_appended_with_only_the_two_fields_new_getout_sets() {
        let mut config = OperationConfig::new();
        assert!(config.url_last().is_none(), "no nodes yet");

        // `src/tool_paramhlp.c:51-52` -- `node->useremote` and `node->num`,
        // and nothing else.
        let first = config.push_getout(NewGetOut {
            num: 0,
            useremote: true,
        });
        assert_eq!(first.ok(), Some(0));
        assert_eq!(config.url_last(), Some(0));

        let second = config.push_getout(NewGetOut {
            num: 1,
            useremote: false,
        });
        assert_eq!(second.ok(), Some(1));
        assert_eq!(config.url_last(), Some(1), "the tail follows the append");

        let node = config.url_list.first();
        assert_eq!(node.map(|entry| entry.num), Some(0));
        assert_eq!(node.map(|entry| entry.useremote), Some(true));
        // `:47`'s `calloc` leaves everything else alone.
        assert_eq!(node.map(|entry| entry.urlset), Some(false));
        assert_eq!(node.map(|entry| entry.outset), Some(false));
        assert_eq!(node.map(|entry| entry.uploadset), Some(false));
        assert_eq!(node.map(|entry| entry.noupload), Some(false));
        assert_eq!(node.map(|entry| entry.noglob), Some(false));
        assert_eq!(node.map(|entry| entry.out_null), Some(false));
        assert!(node.is_some_and(|entry| entry.url.is_none()));

        // The counter is reached through the aggregate, not through a static.
        assert_eq!(
            *config.getout_sequence_mut(),
            GetOutSeq::new(),
            "pushing a node does not advance the counter; new_getout does"
        );
        assert!(!config.remote_name_all());
    }

    #[test]
    fn non_utf8_option_values_round_trip_without_loss() {
        // curl accepts arbitrary bytes in a URL, an output filename and an
        // upload filename, so the three byte strings on a node have to carry
        // them unchanged.
        let raw: Vec<u8> = vec![b'/', 0xff, 0xfe, b'a', 0x80, b'b'];
        let mut config = OperationConfig::new();
        let appended = config.push_getout(NewGetOut {
            num: 0,
            useremote: false,
        });
        assert!(appended.is_ok());
        if let Some(node) = config.url_list.first_mut() {
            node.url = Some(raw.clone());
            node.outfile = Some(raw.clone());
            node.infile = Some(raw.clone());
            node.urlset = true;
        }
        let node = config.url_list.first();
        assert_eq!(node.and_then(|entry| entry.url.clone()), Some(raw.clone()));
        assert_eq!(
            node.and_then(|entry| entry.outfile.clone()),
            Some(raw.clone())
        );
        assert_eq!(
            node.and_then(|entry| entry.infile.clone()),
            Some(raw.clone())
        );

        // `--data` can carry NUL and any other byte.
        config.postdata = vec![0x00, 0xff, b'=', 0x0a];
        assert_eq!(config.postdata, vec![0x00, 0xff, b'=', 0x0a]);

        // And the per-invocation cursors carry the same bytes.
        let state = State {
            httpgetfields: Some(raw.clone()),
            uploadfile: Some(raw.clone()),
            ..State::default()
        };
        assert_eq!(state.httpgetfields, Some(raw.clone()));
        assert_eq!(state.uploadfile, Some(raw));
    }

    #[cfg(unix)]
    #[test]
    fn a_non_utf8_path_round_trips_without_loss() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt as _;

        let bytes: Vec<u8> =
            vec![b'/', b't', 0xff, 0xfe, b'/', b'j', b'a', b'r'];
        let path = PathBuf::from(OsString::from_vec(bytes.clone()));

        let mut config = OperationConfig::new();
        config.cookiejar = Some(path.clone());
        config.capath = Some(path.clone());

        assert_eq!(config.cookiejar.as_deref(), Some(path.as_path()));
        assert_eq!(config.capath.as_deref(), Some(path.as_path()));
        // The bytes are the bytes: no lossy conversion happened on the way in.
        assert_eq!(
            config
                .cookiejar
                .map(|value| value.into_os_string().into_vec()),
            Some(bytes)
        );
    }

    #[test]
    fn the_trace_stream_closes_only_what_it_opened() {
        // `src/tool_cfgable.c:259-261` -- `fclose` only when
        // `trace_fopened && trace_stream`, and clear the field either way.
        let mut borrowed = TraceStream::Stdout;
        assert!(!borrowed.is_fopened(), "src/tool_cb_dbg.c:171-172");
        borrowed.close();
        assert!(matches!(borrowed, TraceStream::Closed));

        let mut inherited = TraceStream::Stderr;
        assert!(!inherited.is_fopened(), "src/tool_cb_dbg.c:173-175");
        inherited.close();
        assert!(matches!(inherited, TraceStream::Closed));

        let mut nothing = TraceStream::default();
        assert!(matches!(nothing, TraceStream::Closed), "calloc leaves NULL");
        assert!(!nothing.is_fopened());
        nothing.close();
        assert!(matches!(nothing, TraceStream::Closed));

        let handle = tempfile::tempfile();
        assert!(handle.is_ok(), "a temporary file must be creatable");
        if let Ok(file) = handle {
            let mut opened = TraceStream::File(file);
            assert!(opened.is_fopened(), "src/tool_cb_dbg.c:177-178");
            opened.close();
            assert!(matches!(opened, TraceStream::Closed));
            assert!(!opened.is_fopened(), "and it is not closed twice");
        }
    }

    #[test]
    fn globalconf_init_applies_its_three_explicit_defaults() {
        let mut sink: Vec<u8> = Vec::new();
        let built = GlobalConfig::init(&mut sink, &loud());
        assert!(built.is_ok(), "the real initialization must succeed");
        assert!(sink.is_empty(), "a successful start emits nothing");

        if let Ok(global) = built {
            // `src/tool_cfgable.c:224-226`.
            assert!(!global.showerror, ":224 -- show errors when silent");
            assert!(global.styled_output, ":225 -- enable detection");
            assert_eq!(
                global.parallel_max, 50,
                ":226 -- PARALLEL_DEFAULT, src/tool_main.h:34"
            );

            // `:229` -- one operation, `first` and `last` the same element.
            assert_eq!(global.chain.len(), 1);
            assert_eq!(global.chain.last_index(), Some(0));
            assert_eq!(global.chain.first(), global.chain.last());

            // `global->current` is NOT initialized by `globalconf_init`.
            assert!(global.chain.current_index().is_none());

            // Everything `calloc` zeroes.
            assert!(global.trace_dump.is_none());
            assert!(!global.trace_stream.is_fopened());
            assert!(global.libcurl.is_none());
            assert!(global.ssl_sessions.is_none());
            assert_eq!(global.tracetype, TraceType::None);
            assert_eq!(global.progressmode, 0);
            assert_eq!(global.parallel_host, 0);
            assert_eq!(global.verbosity, 0);
            assert_eq!(global.ms_per_transfer, 0);
            assert!(!global.parallel);
            assert!(!global.parallel_connect);
            assert!(!global.fail_early);
            assert!(!global.tracetime);
            assert!(!global.traceids);
            assert!(!global.silent);
            assert!(!global.noprogress);
            assert!(!global.isatty);
            assert!(!global.trace_set);
            assert!(global.variables.is_empty());
            assert!(global.state.urlnode.is_none());
        }
    }

    #[test]
    fn a_failed_allocation_reports_the_frozen_message_and_failed_init() {
        // `src/tool_cfgable.c:247-250`. This is the branch that
        // `src/tool_main.c:187` does NOT free after, and the Rust shape makes
        // that automatic: nothing is bound on the error path, so nothing is
        // dropped.
        let mut sink: Vec<u8> = Vec::new();
        let built = GlobalConfig::init_with(
            None,
            library_init,
            crate::cli::libinfo::get_libcurl_info,
            &mut sink,
            &loud(),
        );

        assert!(built.is_err());
        assert_eq!(built.err(), Some(CURLcode::FailedInit), ":249");
        assert_eq!(sink, expected("error initializing curl"), ":248");
    }

    #[test]
    fn a_failed_library_start_reports_the_frozen_message_and_its_code() {
        // `src/tool_cfgable.c:242-245`: the message, then C returns the code
        // `curl_global_init` gave rather than one of its own.
        let mut sink: Vec<u8> = Vec::new();
        let built = GlobalConfig::init_with(
            Some(OperationConfig::new()),
            || CURLcode::OutOfMemory,
            crate::cli::libinfo::get_libcurl_info,
            &mut sink,
            &loud(),
        );

        assert!(built.is_err());
        assert_eq!(built.err(), Some(CURLcode::OutOfMemory), ":232 and :243");
        assert_eq!(sink, expected("error initializing curl library"), ":243");
    }

    #[test]
    fn a_failed_info_query_reports_the_frozen_message_and_its_code() {
        // `src/tool_cfgable.c:236-240`, and `:235`'s code is propagated.
        let mut sink: Vec<u8> = Vec::new();
        let built = GlobalConfig::init_with(
            Some(OperationConfig::new()),
            library_init,
            || Err(Error::new(CURLcode::FailedInit)),
            &mut sink,
            &loud(),
        );

        assert!(built.is_err());
        assert_eq!(built.err(), Some(CURLcode::FailedInit));
        assert_eq!(
            sink,
            expected("error retrieving curl library information"),
            ":238"
        );
    }

    #[test]
    fn the_library_query_is_never_reached_when_the_allocation_fails() {
        // `:230`'s `if(global->first)` guards both later steps, so the C order
        // is lazy and this reproduction has to be too.
        let mut library_ran = false;
        let mut info_ran = false;
        let mut sink: Vec<u8> = Vec::new();

        let built = GlobalConfig::init_with(
            None,
            || {
                library_ran = true;
                CURLcode::Ok
            },
            || {
                info_ran = true;
                crate::cli::libinfo::get_libcurl_info()
            },
            &mut sink,
            &loud(),
        );

        assert!(built.is_err());
        assert!(!library_ran, "the library start is guarded by :230");
        assert!(!info_ran, "and the info query is guarded by :233");
    }

    #[test]
    fn the_info_query_is_never_reached_when_the_library_start_fails() {
        let mut info_ran = false;
        let mut sink: Vec<u8> = Vec::new();

        let built = GlobalConfig::init_with(
            Some(OperationConfig::new()),
            || CURLcode::UnsupportedProtocol,
            || {
                info_ran = true;
                crate::cli::libinfo::get_libcurl_info()
            },
            &mut sink,
            &loud(),
        );

        assert!(built.is_err());
        assert_eq!(built.err(), Some(CURLcode::UnsupportedProtocol));
        assert!(!info_ran, "the info query is guarded by :233");
    }

    #[test]
    fn teardown_releases_the_trace_stream_and_the_chain() {
        // The observable half of `globalconf_free`: after it, the borrowed
        // handle is cleared and the chain is empty. Driven through the same
        // steps `Drop` performs, in the same order, so the assertion is about
        // the production path.
        let mut sink: Vec<u8> = Vec::new();
        let built = GlobalConfig::init(&mut sink, &loud());
        assert!(built.is_ok());

        if let Ok(mut global) = built {
            global.trace_dump = Some(PathBuf::from("/dev/null"));
            global.trace_stream = TraceStream::Stderr;
            global.ssl_sessions = Some(PathBuf::from("/dev/null"));
            global.libcurl = Some(PathBuf::from("/dev/null"));
            let appended = global.chain.append(OperationConfig::new());
            assert!(appended.is_ok());
            assert_eq!(global.chain.len(), 2);

            // Step 2 then step 3, exactly as `Drop` orders them.
            drop(global.trace_dump.take());
            global.trace_stream.close();
            drop(global.ssl_sessions.take());
            drop(global.libcurl.take());
            global.chain.release();

            assert!(global.trace_dump.is_none(), "src/tool_cfgable.c:257");
            assert!(matches!(global.trace_stream, TraceStream::Closed), ":261");
            assert!(global.ssl_sessions.is_none(), ":263");
            assert!(global.libcurl.is_none(), ":264");
            assert!(global.chain.is_empty(), ":282-284");
        }
    }

    /// No credential, body, header or URL can reach a formatted configuration.
    ///
    /// The single assertion that matters for `OperationConfig`: every secret a
    /// command line can carry is set to a distinctive value, and none of them
    /// appears. The list is deliberately the review's own -- credentials,
    /// request bodies, custom headers and URLs -- so a regression in any one
    /// of the four families fails here.
    #[test]
    fn no_secret_can_reach_a_formatted_operation_config() {
        // Built in one initializer rather than by reassignment: with 228
        // fields the struct-update form is the only spelling that does not
        // trip `clippy::field_reassign_with_default`, and it also states
        // plainly that every field not named here is its default.
        let config = OperationConfig {
            userpwd: Some(b"alice:hunter2".to_vec()),
            proxyuserpwd: Some(b"proxyuser:proxypass".to_vec()),
            tls_password: Some(b"tlssecret".to_vec()),
            proxy_tls_password: Some(b"proxytlssecret".to_vec()),
            key_passwd: Some(b"keysecret".to_vec()),
            proxy_key_passwd: Some(b"proxykeysecret".to_vec()),
            oauth_bearer: Some(b"bearer-token-value".to_vec()),
            aws_sigv4: Some(b"aws:amz:us-east-1:s3".to_vec()),
            postdata: b"password=hunter2&card=4111111111111111".to_vec(),
            headers: vec![b"Authorization: Basic c2VjcmV0".to_vec()],
            proxyheaders: vec![b"Proxy-Authorization: Bearer ptok".to_vec()],
            quote: vec![b"USER alice".to_vec()],
            cookies: vec![b"session=cafebabe".to_vec()],
            cookiejar: Some(PathBuf::from("/home/alice/.cookies")),
            doh_url: Some(b"https://tok@doh.example/q".to_vec()),
            proxy: Some(b"http://proxyuser:pw@proxy.example".to_vec()),
            customrequest: Some(b"PROPFIND".to_vec()),
            ..Default::default()
        };

        let text = format!("{config:?}");
        for secret in [
            "hunter2",
            "proxypass",
            "tlssecret",
            "proxytlssecret",
            "keysecret",
            "proxykeysecret",
            "bearer-token-value",
            "4111111111111111",
            "c2VjcmV0",
            "ptok",
            "USER alice",
            "cafebabe",
            "/home/alice/.cookies",
            "doh.example",
            "proxy.example",
            "PROPFIND",
        ] {
            assert!(!text.contains(secret), "{secret} leaked: {text}");
        }

        // What a reader needs still renders: presence, counts and the
        // transport-security policy the mandated warning reports.
        assert!(text.contains("has_userpwd: true"), "{text}");
        assert!(text.contains("has_oauth_bearer: true"), "{text}");
        assert!(text.contains("headers: 1"), "{text}");
        assert!(text.contains("insecure_ok: false"), "{text}");
        // And the dump says it is a summary rather than the whole struct, so a
        // reader does not mistake an omission for an unset field.
        assert!(text.contains(".."), "{text}");

        // A chain renders its operations through the same formatter.
        let mut chain = ConfigChain::new(config.clone());
        assert!(chain.append(config).is_ok());
        assert!(!format!("{chain:?}").contains("hunter2"));
    }
}
