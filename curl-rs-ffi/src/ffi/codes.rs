// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! The public result and identity enumerations, in their C ABI shape.
//!
//! Eleven enumerations reach C consumers through the generated header. Each is
//! declared here with **every discriminant written out as a literal**, because a
//! consumer compiled against curl 8.19.0-DEV holds the *numbers*, not the
//! names: the integer is baked into its instruction stream at its own compile
//! time. A program that tests a return value against `CURLE_SSL_CONNECT_ERROR`
//! is testing it against `35`. In the frozen header only `CURLE_OK = 0` is
//! written explicitly and the other 102 take their value from declaration
//! order, so dropping or reordering one member -- including one of the fifteen
//! retired `CURLE_OBSOLETE*` placeholders, which exist for no reason except to
//! hold a position -- silently renumbers every later code. Nothing warns; the
//! library links and then misreports. Spelling the literals turns that silent
//! failure mode into a diff.
//!
//! # Why the declarations are literal, and why the representation is `C`
//!
//! Both of these are forced by measured cbindgen behaviour, not chosen, and
//! neither is safe to "tidy up" later:
//!
//! * **No `macro_rules!`.** cbindgen parses this crate syntactically and
//!   expands nothing (`cbindgen.toml` leaves `[parse.expand]` empty on purpose,
//!   because expansion shells out to `cargo expand` and needs a nightly
//!   toolchain the pinned build does not have). A macro-generated enumeration
//!   is invisible to it and simply never reaches the header. The repetition
//!   below is the price of being visible; it is generated from the frozen
//!   headers rather than typed, so it cannot drift from them by hand.
//! * **`#[repr(C)]`, never `#[repr(i32)]`.** An explicit integer
//!   representation makes cbindgen emit the underlying type, which obliges it
//!   to name the enum: `enum CURLcode { ... };` guarded by
//!   `__STDC_VERSION__ >= 202311L`, plus a `typedef int32_t` fallback. The
//!   frozen headers use an anonymous `typedef enum { ... } CURLcode;`, which is
//!   what `style = "type"` produces -- but only for a representation that does
//!   not pin an integer width. `#[repr(C)]` is also the more accurate statement
//!   of intent: it means "whatever this platform's C ABI uses for an enum",
//!   which is a 32-bit signed `int` on all four supported targets and carries
//!   `CURLMcode`'s negative member correctly.
//!
//! A type also has to be named in `cbindgen.toml`'s `[export] include` list to
//! be emitted at all: cbindgen writes only what is reachable from an exported
//! signature, and most of these are reachable solely through prototypes that
//! are themselves pinned verbatim. Adding an enumeration here without adding it
//! there produces no header text and no error.
//!
//! # Why these are declared here as well as in the engine
//!
//! `curl-rs-lib/src/error.rs` owns `CURLcode`, `CURLMcode`, `CURLUcode`,
//! `CURLHcode` and `CURLSHcode` for the engine, with Rust-idiomatic member
//! names (`CURLcode::Ok`). This module declares the same five with the C
//! spelling (`CURLcode::CURLE_OK`). That duplication is deliberate and forced:
//!
//! * `cbindgen.toml` sets `parse_deps = false`, so cbindgen reads only this
//!   crate. That setting is what keeps `curl-rs-lib`'s `pub(crate)` internals
//!   out of the ABI, and it has to stay. An enumeration that must appear in the
//!   generated header therefore has to be declared inside this crate.
//! * cbindgen emits the Rust identifier verbatim. Its renaming controls apply a
//!   casing rule or a type-name prefix; none turns `Ok` into `CURLE_OK`, and
//!   `prefix_with_name` would yield `CURLcode_Ok`. So even pointing cbindgen at
//!   the engine's own source could not produce the frozen spelling.
//!
//! Drift is prevented by construction rather than by review. Each of the five
//! carries `From` conversions in **both** directions, built from exhaustive
//! `match` arms with no wildcard, no `unwrap` and no `unreachable!`. Adding,
//! removing or renaming a member on either side makes one of the two matches
//! non-exhaustive and **fails the build**. A fallible or wildcard-terminated
//! conversion would let a new member through unnoticed, which is the exact
//! failure this arrangement exists to prevent. The tests then compare the
//! discriminants against two independent authorities -- the frozen header's
//! documented anchors, and the engine's own `VARIANTS`/`c_name`/`as_i32` -- so
//! even a coordinated edit to both sides of a bridge still has to survive a
//! comparison with `include/curl/`. Because every set is contiguous, the
//! compiler catches more than the matches do: changing one value collides with
//! its neighbour and is rejected as a duplicate discriminant.
//!
//! `CURLINFO` and `CURLoption` are not result codes and are deliberately in
//! neither place: `ffi/opts.rs` is their sole source of truth.
//!
//! # The enumerations with no engine counterpart
//!
//! `CURLSHoption`, `CURLSTScode`, `CURLproxycode`, `curl_sslbackend` and
//! `CURLsslset` are declared here only. They are part of the header contract --
//! `curl_share_setopt`'s option identifiers, the HSTS callback's return set,
//! the SOCKS handshake error set, and the TLS backend identity pair -- but no
//! engine module names them yet, so there is nothing to bridge to. Declaring an
//! unused mirror inside `curl-rs-lib` would create precisely the second,
//! drifting copy this arrangement exists to avoid. They become bridged like the
//! other five when the share, HSTS, SOCKS and TLS-selection layers land; the
//! engine reports backend identity through `crate::version` in the meantime.
//!
//! # Two fidelity notes, recorded rather than left to be discovered
//!
//! * **`CURLversion` has thirteen members here and twelve in the engine.**
//!   `include/curl/curl.h:3101` annotates `CURLVERSION_LAST` as "never actually
//!   use this", and the engine follows its own `multi::state` precedent of not
//!   making an unusable sentinel constructible, keeping it as an integer bound.
//!   The ABI enumeration must still declare it, because the header does and a
//!   consumer may name it. So only one direction of that one conversion can be
//!   total; the reverse is `Option`-returning and names the single input it
//!   refuses.
//! * **`curl_sslbackend` is declared here but not generated from here.**
//!   Seven of its members carry `CURL_DEPRECATED(version, "")` in the frozen
//!   header, and cbindgen has no format that emits that macro, so the type is
//!   in `[export] exclude` and the header receives it verbatim from the
//!   prologue instead -- with all seven markers intact, which generation could
//!   not have managed. The Rust declaration below therefore reaches no C
//!   consumer directly; it exists so that `curl_global_sslset` has a typed
//!   backend identity to work with, and its members carry the deprecation
//!   release in their own documentation for a Rust reader. The exclusion is
//!   also what keeps this declaration from colliding with the verbatim one.

use curl_rs_lib::error as engine;
use curl_rs_lib::version::CURLversion as EngineVersion;

/// Every error a libcurl function can report.
///
/// Transcribed from `include/curl/curl.h:518-648`.
///
/// 103 members occupy `0..=102` with no gaps. Fifteen are retired
/// `CURLE_OBSOLETE*` placeholders at exactly `{20, 24, 29, 32, 34, 40, 41,
/// 44, 46, 50, 51, 57, 62, 75, 76}`; they are never returned and exist only
/// so that every later code keeps its number. `CURL_LAST` = 102 is a bound
/// for range checks, not a value -- the highest real error is
/// `CURLE_ECH_REQUIRED` = 101. The header's own instruction is the whole
/// specification: new codes go last, and none is ever removed.
///
/// Bridged to [`engine::CURLcode`] in both directions by exhaustive
/// `match`, so a divergence between the two declarations cannot compile.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CURLcode {
    CURLE_OK = 0,
    CURLE_UNSUPPORTED_PROTOCOL = 1,
    CURLE_FAILED_INIT = 2,
    CURLE_URL_MALFORMAT = 3,
    /// [was obsoleted in August 2007 for 7.17.0, reused in April 2011 for
    /// 7.21.5]
    CURLE_NOT_BUILT_IN = 4,
    CURLE_COULDNT_RESOLVE_PROXY = 5,
    CURLE_COULDNT_RESOLVE_HOST = 6,
    CURLE_COULDNT_CONNECT = 7,
    CURLE_WEIRD_SERVER_REPLY = 8,
    /// a service was denied by the server due to lack of access - when
    /// login fails this is not returned.
    CURLE_REMOTE_ACCESS_DENIED = 9,
    /// [was obsoleted in April 2006 for 7.15.4, reused in Dec 2011 for
    /// 7.24.0]
    CURLE_FTP_ACCEPT_FAILED = 10,
    CURLE_FTP_WEIRD_PASS_REPLY = 11,
    /// timeout occurred accepting server [was obsoleted in August 2007 for
    /// 7.17.0, reused in Dec 2011 for 7.24.0]
    CURLE_FTP_ACCEPT_TIMEOUT = 12,
    CURLE_FTP_WEIRD_PASV_REPLY = 13,
    CURLE_FTP_WEIRD_227_FORMAT = 14,
    CURLE_FTP_CANT_GET_HOST = 15,
    /// A problem in the http2 framing layer. [was obsoleted in August 2007
    /// for 7.17.0, reused in July 2014 for 7.38.0]
    CURLE_HTTP2 = 16,
    CURLE_FTP_COULDNT_SET_TYPE = 17,
    CURLE_PARTIAL_FILE = 18,
    CURLE_FTP_COULDNT_RETR_FILE = 19,
    /// NOT USED
    CURLE_OBSOLETE20 = 20,
    /// quote command failure
    CURLE_QUOTE_ERROR = 21,
    CURLE_HTTP_RETURNED_ERROR = 22,
    CURLE_WRITE_ERROR = 23,
    /// NOT USED
    CURLE_OBSOLETE24 = 24,
    /// failed upload "command"
    CURLE_UPLOAD_FAILED = 25,
    /// could not open/read from file
    CURLE_READ_ERROR = 26,
    CURLE_OUT_OF_MEMORY = 27,
    /// the timeout time was reached
    CURLE_OPERATION_TIMEDOUT = 28,
    /// NOT USED
    CURLE_OBSOLETE29 = 29,
    /// FTP PORT operation failed
    CURLE_FTP_PORT_FAILED = 30,
    /// the REST command failed
    CURLE_FTP_COULDNT_USE_REST = 31,
    /// NOT USED
    CURLE_OBSOLETE32 = 32,
    /// RANGE "command" did not work
    CURLE_RANGE_ERROR = 33,
    CURLE_OBSOLETE34 = 34,
    /// wrong when connecting with SSL
    CURLE_SSL_CONNECT_ERROR = 35,
    /// could not resume download
    CURLE_BAD_DOWNLOAD_RESUME = 36,
    CURLE_FILE_COULDNT_READ_FILE = 37,
    CURLE_LDAP_CANNOT_BIND = 38,
    CURLE_LDAP_SEARCH_FAILED = 39,
    /// NOT USED
    CURLE_OBSOLETE40 = 40,
    /// NOT USED starting with 7.53.0
    CURLE_OBSOLETE41 = 41,
    CURLE_ABORTED_BY_CALLBACK = 42,
    CURLE_BAD_FUNCTION_ARGUMENT = 43,
    /// NOT USED
    CURLE_OBSOLETE44 = 44,
    /// CURLOPT_INTERFACE failed
    CURLE_INTERFACE_FAILED = 45,
    /// NOT USED
    CURLE_OBSOLETE46 = 46,
    /// catch endless re-direct loops
    CURLE_TOO_MANY_REDIRECTS = 47,
    /// User specified an unknown option
    CURLE_UNKNOWN_OPTION = 48,
    /// Malformed setopt option
    CURLE_SETOPT_OPTION_SYNTAX = 49,
    /// NOT USED
    CURLE_OBSOLETE50 = 50,
    /// NOT USED
    CURLE_OBSOLETE51 = 51,
    /// when this is a specific error
    CURLE_GOT_NOTHING = 52,
    /// SSL crypto engine not found
    CURLE_SSL_ENGINE_NOTFOUND = 53,
    /// can not set SSL crypto engine as default
    CURLE_SSL_ENGINE_SETFAILED = 54,
    /// failed sending network data
    CURLE_SEND_ERROR = 55,
    /// failure in receiving network data
    CURLE_RECV_ERROR = 56,
    /// NOT IN USE
    CURLE_OBSOLETE57 = 57,
    /// problem with the local certificate
    CURLE_SSL_CERTPROBLEM = 58,
    /// could not use specified cipher
    CURLE_SSL_CIPHER = 59,
    /// peer's certificate or fingerprint was not verified fine
    CURLE_PEER_FAILED_VERIFICATION = 60,
    /// Unrecognized/bad encoding
    CURLE_BAD_CONTENT_ENCODING = 61,
    /// NOT IN USE since 7.82.0
    CURLE_OBSOLETE62 = 62,
    /// Maximum file size exceeded
    CURLE_FILESIZE_EXCEEDED = 63,
    /// Requested FTP SSL level failed
    CURLE_USE_SSL_FAILED = 64,
    /// Sending the data requires a rewind that failed
    CURLE_SEND_FAIL_REWIND = 65,
    /// failed to initialise ENGINE
    CURLE_SSL_ENGINE_INITFAILED = 66,
    /// user, password or similar was not accepted and we failed to login
    CURLE_LOGIN_DENIED = 67,
    /// file not found on server
    CURLE_TFTP_NOTFOUND = 68,
    /// permission problem on server
    CURLE_TFTP_PERM = 69,
    /// out of disk space on server
    CURLE_REMOTE_DISK_FULL = 70,
    /// Illegal TFTP operation
    CURLE_TFTP_ILLEGAL = 71,
    /// Unknown transfer ID
    CURLE_TFTP_UNKNOWNID = 72,
    /// File already exists
    CURLE_REMOTE_FILE_EXISTS = 73,
    /// No such user
    CURLE_TFTP_NOSUCHUSER = 74,
    /// NOT IN USE since 7.82.0
    CURLE_OBSOLETE75 = 75,
    /// NOT IN USE since 7.82.0
    CURLE_OBSOLETE76 = 76,
    /// could not load CACERT file, missing or wrong format
    CURLE_SSL_CACERT_BADFILE = 77,
    /// remote file not found
    CURLE_REMOTE_FILE_NOT_FOUND = 78,
    /// error from the SSH layer, somewhat generic so the error message will
    /// be of interest when this has happened
    CURLE_SSH = 79,
    /// Failed to shut down the SSL connection
    CURLE_SSL_SHUTDOWN_FAILED = 80,
    /// socket is not ready for send/recv, wait till it is ready and try
    /// again (Added in 7.18.2)
    CURLE_AGAIN = 81,
    /// could not load CRL file, missing or wrong format (Added in 7.19.0)
    CURLE_SSL_CRL_BADFILE = 82,
    /// Issuer check failed. (Added in 7.19.0)
    CURLE_SSL_ISSUER_ERROR = 83,
    /// a PRET command failed
    CURLE_FTP_PRET_FAILED = 84,
    /// mismatch of RTSP CSeq numbers
    CURLE_RTSP_CSEQ_ERROR = 85,
    /// mismatch of RTSP Session Ids
    CURLE_RTSP_SESSION_ERROR = 86,
    /// unable to parse FTP file list
    CURLE_FTP_BAD_FILE_LIST = 87,
    /// chunk callback reported error
    CURLE_CHUNK_FAILED = 88,
    /// No connection available, the session will be queued
    CURLE_NO_CONNECTION_AVAILABLE = 89,
    /// specified pinned public key did not match
    CURLE_SSL_PINNEDPUBKEYNOTMATCH = 90,
    /// invalid certificate status
    CURLE_SSL_INVALIDCERTSTATUS = 91,
    /// stream error in HTTP/2 framing layer
    CURLE_HTTP2_STREAM = 92,
    /// an api function was called from inside a callback
    CURLE_RECURSIVE_API_CALL = 93,
    /// an authentication function returned an error
    CURLE_AUTH_ERROR = 94,
    /// An HTTP/3 layer problem
    CURLE_HTTP3 = 95,
    /// QUIC connection error
    CURLE_QUIC_CONNECT_ERROR = 96,
    /// proxy handshake error
    CURLE_PROXY = 97,
    /// client-side certificate required
    CURLE_SSL_CLIENTCERT = 98,
    /// poll/select returned fatal error
    CURLE_UNRECOVERABLE_POLL = 99,
    /// a value/data met its maximum
    CURLE_TOO_LARGE = 100,
    /// ECH tried but failed
    CURLE_ECH_REQUIRED = 101,
    /// never use!
    CURL_LAST = 102,
}

impl CURLcode {
    /// Every member as `(C identifier, value)`, in declaration order.
    ///
    /// The single place the tests read, so neither the comparison against
    /// the frozen header nor the one against the engine needs a
    /// hand-maintained list that could drift on its own.
    #[allow(dead_code)]
    pub(crate) const ABI_VARIANTS: &'static [(&'static str, i32)] = &[
        ("CURLE_OK", 0),
        ("CURLE_UNSUPPORTED_PROTOCOL", 1),
        ("CURLE_FAILED_INIT", 2),
        ("CURLE_URL_MALFORMAT", 3),
        ("CURLE_NOT_BUILT_IN", 4),
        ("CURLE_COULDNT_RESOLVE_PROXY", 5),
        ("CURLE_COULDNT_RESOLVE_HOST", 6),
        ("CURLE_COULDNT_CONNECT", 7),
        ("CURLE_WEIRD_SERVER_REPLY", 8),
        ("CURLE_REMOTE_ACCESS_DENIED", 9),
        ("CURLE_FTP_ACCEPT_FAILED", 10),
        ("CURLE_FTP_WEIRD_PASS_REPLY", 11),
        ("CURLE_FTP_ACCEPT_TIMEOUT", 12),
        ("CURLE_FTP_WEIRD_PASV_REPLY", 13),
        ("CURLE_FTP_WEIRD_227_FORMAT", 14),
        ("CURLE_FTP_CANT_GET_HOST", 15),
        ("CURLE_HTTP2", 16),
        ("CURLE_FTP_COULDNT_SET_TYPE", 17),
        ("CURLE_PARTIAL_FILE", 18),
        ("CURLE_FTP_COULDNT_RETR_FILE", 19),
        ("CURLE_OBSOLETE20", 20),
        ("CURLE_QUOTE_ERROR", 21),
        ("CURLE_HTTP_RETURNED_ERROR", 22),
        ("CURLE_WRITE_ERROR", 23),
        ("CURLE_OBSOLETE24", 24),
        ("CURLE_UPLOAD_FAILED", 25),
        ("CURLE_READ_ERROR", 26),
        ("CURLE_OUT_OF_MEMORY", 27),
        ("CURLE_OPERATION_TIMEDOUT", 28),
        ("CURLE_OBSOLETE29", 29),
        ("CURLE_FTP_PORT_FAILED", 30),
        ("CURLE_FTP_COULDNT_USE_REST", 31),
        ("CURLE_OBSOLETE32", 32),
        ("CURLE_RANGE_ERROR", 33),
        ("CURLE_OBSOLETE34", 34),
        ("CURLE_SSL_CONNECT_ERROR", 35),
        ("CURLE_BAD_DOWNLOAD_RESUME", 36),
        ("CURLE_FILE_COULDNT_READ_FILE", 37),
        ("CURLE_LDAP_CANNOT_BIND", 38),
        ("CURLE_LDAP_SEARCH_FAILED", 39),
        ("CURLE_OBSOLETE40", 40),
        ("CURLE_OBSOLETE41", 41),
        ("CURLE_ABORTED_BY_CALLBACK", 42),
        ("CURLE_BAD_FUNCTION_ARGUMENT", 43),
        ("CURLE_OBSOLETE44", 44),
        ("CURLE_INTERFACE_FAILED", 45),
        ("CURLE_OBSOLETE46", 46),
        ("CURLE_TOO_MANY_REDIRECTS", 47),
        ("CURLE_UNKNOWN_OPTION", 48),
        ("CURLE_SETOPT_OPTION_SYNTAX", 49),
        ("CURLE_OBSOLETE50", 50),
        ("CURLE_OBSOLETE51", 51),
        ("CURLE_GOT_NOTHING", 52),
        ("CURLE_SSL_ENGINE_NOTFOUND", 53),
        ("CURLE_SSL_ENGINE_SETFAILED", 54),
        ("CURLE_SEND_ERROR", 55),
        ("CURLE_RECV_ERROR", 56),
        ("CURLE_OBSOLETE57", 57),
        ("CURLE_SSL_CERTPROBLEM", 58),
        ("CURLE_SSL_CIPHER", 59),
        ("CURLE_PEER_FAILED_VERIFICATION", 60),
        ("CURLE_BAD_CONTENT_ENCODING", 61),
        ("CURLE_OBSOLETE62", 62),
        ("CURLE_FILESIZE_EXCEEDED", 63),
        ("CURLE_USE_SSL_FAILED", 64),
        ("CURLE_SEND_FAIL_REWIND", 65),
        ("CURLE_SSL_ENGINE_INITFAILED", 66),
        ("CURLE_LOGIN_DENIED", 67),
        ("CURLE_TFTP_NOTFOUND", 68),
        ("CURLE_TFTP_PERM", 69),
        ("CURLE_REMOTE_DISK_FULL", 70),
        ("CURLE_TFTP_ILLEGAL", 71),
        ("CURLE_TFTP_UNKNOWNID", 72),
        ("CURLE_REMOTE_FILE_EXISTS", 73),
        ("CURLE_TFTP_NOSUCHUSER", 74),
        ("CURLE_OBSOLETE75", 75),
        ("CURLE_OBSOLETE76", 76),
        ("CURLE_SSL_CACERT_BADFILE", 77),
        ("CURLE_REMOTE_FILE_NOT_FOUND", 78),
        ("CURLE_SSH", 79),
        ("CURLE_SSL_SHUTDOWN_FAILED", 80),
        ("CURLE_AGAIN", 81),
        ("CURLE_SSL_CRL_BADFILE", 82),
        ("CURLE_SSL_ISSUER_ERROR", 83),
        ("CURLE_FTP_PRET_FAILED", 84),
        ("CURLE_RTSP_CSEQ_ERROR", 85),
        ("CURLE_RTSP_SESSION_ERROR", 86),
        ("CURLE_FTP_BAD_FILE_LIST", 87),
        ("CURLE_CHUNK_FAILED", 88),
        ("CURLE_NO_CONNECTION_AVAILABLE", 89),
        ("CURLE_SSL_PINNEDPUBKEYNOTMATCH", 90),
        ("CURLE_SSL_INVALIDCERTSTATUS", 91),
        ("CURLE_HTTP2_STREAM", 92),
        ("CURLE_RECURSIVE_API_CALL", 93),
        ("CURLE_AUTH_ERROR", 94),
        ("CURLE_HTTP3", 95),
        ("CURLE_QUIC_CONNECT_ERROR", 96),
        ("CURLE_PROXY", 97),
        ("CURLE_SSL_CLIENTCERT", 98),
        ("CURLE_UNRECOVERABLE_POLL", 99),
        ("CURLE_TOO_LARGE", 100),
        ("CURLE_ECH_REQUIRED", 101),
        ("CURL_LAST", 102),
    ];

    /// The C identifier, which is also this member's Rust identifier.
    ///
    /// An exhaustive `match` rather than a lookup keyed on the value, so
    /// it stays correct without depending on the set being contiguous.
    #[allow(dead_code)]
    pub(crate) const fn c_name(self) -> &'static str {
        match self {
            Self::CURLE_OK => "CURLE_OK",
            Self::CURLE_UNSUPPORTED_PROTOCOL => "CURLE_UNSUPPORTED_PROTOCOL",
            Self::CURLE_FAILED_INIT => "CURLE_FAILED_INIT",
            Self::CURLE_URL_MALFORMAT => "CURLE_URL_MALFORMAT",
            Self::CURLE_NOT_BUILT_IN => "CURLE_NOT_BUILT_IN",
            Self::CURLE_COULDNT_RESOLVE_PROXY => "CURLE_COULDNT_RESOLVE_PROXY",
            Self::CURLE_COULDNT_RESOLVE_HOST => "CURLE_COULDNT_RESOLVE_HOST",
            Self::CURLE_COULDNT_CONNECT => "CURLE_COULDNT_CONNECT",
            Self::CURLE_WEIRD_SERVER_REPLY => "CURLE_WEIRD_SERVER_REPLY",
            Self::CURLE_REMOTE_ACCESS_DENIED => "CURLE_REMOTE_ACCESS_DENIED",
            Self::CURLE_FTP_ACCEPT_FAILED => "CURLE_FTP_ACCEPT_FAILED",
            Self::CURLE_FTP_WEIRD_PASS_REPLY => "CURLE_FTP_WEIRD_PASS_REPLY",
            Self::CURLE_FTP_ACCEPT_TIMEOUT => "CURLE_FTP_ACCEPT_TIMEOUT",
            Self::CURLE_FTP_WEIRD_PASV_REPLY => "CURLE_FTP_WEIRD_PASV_REPLY",
            Self::CURLE_FTP_WEIRD_227_FORMAT => "CURLE_FTP_WEIRD_227_FORMAT",
            Self::CURLE_FTP_CANT_GET_HOST => "CURLE_FTP_CANT_GET_HOST",
            Self::CURLE_HTTP2 => "CURLE_HTTP2",
            Self::CURLE_FTP_COULDNT_SET_TYPE => "CURLE_FTP_COULDNT_SET_TYPE",
            Self::CURLE_PARTIAL_FILE => "CURLE_PARTIAL_FILE",
            Self::CURLE_FTP_COULDNT_RETR_FILE => "CURLE_FTP_COULDNT_RETR_FILE",
            Self::CURLE_OBSOLETE20 => "CURLE_OBSOLETE20",
            Self::CURLE_QUOTE_ERROR => "CURLE_QUOTE_ERROR",
            Self::CURLE_HTTP_RETURNED_ERROR => "CURLE_HTTP_RETURNED_ERROR",
            Self::CURLE_WRITE_ERROR => "CURLE_WRITE_ERROR",
            Self::CURLE_OBSOLETE24 => "CURLE_OBSOLETE24",
            Self::CURLE_UPLOAD_FAILED => "CURLE_UPLOAD_FAILED",
            Self::CURLE_READ_ERROR => "CURLE_READ_ERROR",
            Self::CURLE_OUT_OF_MEMORY => "CURLE_OUT_OF_MEMORY",
            Self::CURLE_OPERATION_TIMEDOUT => "CURLE_OPERATION_TIMEDOUT",
            Self::CURLE_OBSOLETE29 => "CURLE_OBSOLETE29",
            Self::CURLE_FTP_PORT_FAILED => "CURLE_FTP_PORT_FAILED",
            Self::CURLE_FTP_COULDNT_USE_REST => "CURLE_FTP_COULDNT_USE_REST",
            Self::CURLE_OBSOLETE32 => "CURLE_OBSOLETE32",
            Self::CURLE_RANGE_ERROR => "CURLE_RANGE_ERROR",
            Self::CURLE_OBSOLETE34 => "CURLE_OBSOLETE34",
            Self::CURLE_SSL_CONNECT_ERROR => "CURLE_SSL_CONNECT_ERROR",
            Self::CURLE_BAD_DOWNLOAD_RESUME => "CURLE_BAD_DOWNLOAD_RESUME",
            Self::CURLE_FILE_COULDNT_READ_FILE => {
                "CURLE_FILE_COULDNT_READ_FILE"
            }
            Self::CURLE_LDAP_CANNOT_BIND => "CURLE_LDAP_CANNOT_BIND",
            Self::CURLE_LDAP_SEARCH_FAILED => "CURLE_LDAP_SEARCH_FAILED",
            Self::CURLE_OBSOLETE40 => "CURLE_OBSOLETE40",
            Self::CURLE_OBSOLETE41 => "CURLE_OBSOLETE41",
            Self::CURLE_ABORTED_BY_CALLBACK => "CURLE_ABORTED_BY_CALLBACK",
            Self::CURLE_BAD_FUNCTION_ARGUMENT => "CURLE_BAD_FUNCTION_ARGUMENT",
            Self::CURLE_OBSOLETE44 => "CURLE_OBSOLETE44",
            Self::CURLE_INTERFACE_FAILED => "CURLE_INTERFACE_FAILED",
            Self::CURLE_OBSOLETE46 => "CURLE_OBSOLETE46",
            Self::CURLE_TOO_MANY_REDIRECTS => "CURLE_TOO_MANY_REDIRECTS",
            Self::CURLE_UNKNOWN_OPTION => "CURLE_UNKNOWN_OPTION",
            Self::CURLE_SETOPT_OPTION_SYNTAX => "CURLE_SETOPT_OPTION_SYNTAX",
            Self::CURLE_OBSOLETE50 => "CURLE_OBSOLETE50",
            Self::CURLE_OBSOLETE51 => "CURLE_OBSOLETE51",
            Self::CURLE_GOT_NOTHING => "CURLE_GOT_NOTHING",
            Self::CURLE_SSL_ENGINE_NOTFOUND => "CURLE_SSL_ENGINE_NOTFOUND",
            Self::CURLE_SSL_ENGINE_SETFAILED => "CURLE_SSL_ENGINE_SETFAILED",
            Self::CURLE_SEND_ERROR => "CURLE_SEND_ERROR",
            Self::CURLE_RECV_ERROR => "CURLE_RECV_ERROR",
            Self::CURLE_OBSOLETE57 => "CURLE_OBSOLETE57",
            Self::CURLE_SSL_CERTPROBLEM => "CURLE_SSL_CERTPROBLEM",
            Self::CURLE_SSL_CIPHER => "CURLE_SSL_CIPHER",
            Self::CURLE_PEER_FAILED_VERIFICATION => {
                "CURLE_PEER_FAILED_VERIFICATION"
            }
            Self::CURLE_BAD_CONTENT_ENCODING => "CURLE_BAD_CONTENT_ENCODING",
            Self::CURLE_OBSOLETE62 => "CURLE_OBSOLETE62",
            Self::CURLE_FILESIZE_EXCEEDED => "CURLE_FILESIZE_EXCEEDED",
            Self::CURLE_USE_SSL_FAILED => "CURLE_USE_SSL_FAILED",
            Self::CURLE_SEND_FAIL_REWIND => "CURLE_SEND_FAIL_REWIND",
            Self::CURLE_SSL_ENGINE_INITFAILED => "CURLE_SSL_ENGINE_INITFAILED",
            Self::CURLE_LOGIN_DENIED => "CURLE_LOGIN_DENIED",
            Self::CURLE_TFTP_NOTFOUND => "CURLE_TFTP_NOTFOUND",
            Self::CURLE_TFTP_PERM => "CURLE_TFTP_PERM",
            Self::CURLE_REMOTE_DISK_FULL => "CURLE_REMOTE_DISK_FULL",
            Self::CURLE_TFTP_ILLEGAL => "CURLE_TFTP_ILLEGAL",
            Self::CURLE_TFTP_UNKNOWNID => "CURLE_TFTP_UNKNOWNID",
            Self::CURLE_REMOTE_FILE_EXISTS => "CURLE_REMOTE_FILE_EXISTS",
            Self::CURLE_TFTP_NOSUCHUSER => "CURLE_TFTP_NOSUCHUSER",
            Self::CURLE_OBSOLETE75 => "CURLE_OBSOLETE75",
            Self::CURLE_OBSOLETE76 => "CURLE_OBSOLETE76",
            Self::CURLE_SSL_CACERT_BADFILE => "CURLE_SSL_CACERT_BADFILE",
            Self::CURLE_REMOTE_FILE_NOT_FOUND => "CURLE_REMOTE_FILE_NOT_FOUND",
            Self::CURLE_SSH => "CURLE_SSH",
            Self::CURLE_SSL_SHUTDOWN_FAILED => "CURLE_SSL_SHUTDOWN_FAILED",
            Self::CURLE_AGAIN => "CURLE_AGAIN",
            Self::CURLE_SSL_CRL_BADFILE => "CURLE_SSL_CRL_BADFILE",
            Self::CURLE_SSL_ISSUER_ERROR => "CURLE_SSL_ISSUER_ERROR",
            Self::CURLE_FTP_PRET_FAILED => "CURLE_FTP_PRET_FAILED",
            Self::CURLE_RTSP_CSEQ_ERROR => "CURLE_RTSP_CSEQ_ERROR",
            Self::CURLE_RTSP_SESSION_ERROR => "CURLE_RTSP_SESSION_ERROR",
            Self::CURLE_FTP_BAD_FILE_LIST => "CURLE_FTP_BAD_FILE_LIST",
            Self::CURLE_CHUNK_FAILED => "CURLE_CHUNK_FAILED",
            Self::CURLE_NO_CONNECTION_AVAILABLE => {
                "CURLE_NO_CONNECTION_AVAILABLE"
            }
            Self::CURLE_SSL_PINNEDPUBKEYNOTMATCH => {
                "CURLE_SSL_PINNEDPUBKEYNOTMATCH"
            }
            Self::CURLE_SSL_INVALIDCERTSTATUS => "CURLE_SSL_INVALIDCERTSTATUS",
            Self::CURLE_HTTP2_STREAM => "CURLE_HTTP2_STREAM",
            Self::CURLE_RECURSIVE_API_CALL => "CURLE_RECURSIVE_API_CALL",
            Self::CURLE_AUTH_ERROR => "CURLE_AUTH_ERROR",
            Self::CURLE_HTTP3 => "CURLE_HTTP3",
            Self::CURLE_QUIC_CONNECT_ERROR => "CURLE_QUIC_CONNECT_ERROR",
            Self::CURLE_PROXY => "CURLE_PROXY",
            Self::CURLE_SSL_CLIENTCERT => "CURLE_SSL_CLIENTCERT",
            Self::CURLE_UNRECOVERABLE_POLL => "CURLE_UNRECOVERABLE_POLL",
            Self::CURLE_TOO_LARGE => "CURLE_TOO_LARGE",
            Self::CURLE_ECH_REQUIRED => "CURLE_ECH_REQUIRED",
            Self::CURL_LAST => "CURL_LAST",
        }
    }

    /// The pinned discriminant, for handing back across the ABI.
    #[allow(dead_code)]
    pub(crate) const fn as_c_int(self) -> i32 {
        self as i32
    }

    /// The member with this discriminant, or `None` if C handed over a
    /// value this enumeration does not define.
    ///
    /// A C caller can pass any `int`. Returning `None` rather than
    /// transmuting keeps an out-of-range value from becoming an invalid
    /// enum, which would be undefined behaviour.
    #[allow(dead_code)]
    pub(crate) const fn from_c_int(raw: i32) -> Option<Self> {
        match raw {
            0 => Some(Self::CURLE_OK),
            1 => Some(Self::CURLE_UNSUPPORTED_PROTOCOL),
            2 => Some(Self::CURLE_FAILED_INIT),
            3 => Some(Self::CURLE_URL_MALFORMAT),
            4 => Some(Self::CURLE_NOT_BUILT_IN),
            5 => Some(Self::CURLE_COULDNT_RESOLVE_PROXY),
            6 => Some(Self::CURLE_COULDNT_RESOLVE_HOST),
            7 => Some(Self::CURLE_COULDNT_CONNECT),
            8 => Some(Self::CURLE_WEIRD_SERVER_REPLY),
            9 => Some(Self::CURLE_REMOTE_ACCESS_DENIED),
            10 => Some(Self::CURLE_FTP_ACCEPT_FAILED),
            11 => Some(Self::CURLE_FTP_WEIRD_PASS_REPLY),
            12 => Some(Self::CURLE_FTP_ACCEPT_TIMEOUT),
            13 => Some(Self::CURLE_FTP_WEIRD_PASV_REPLY),
            14 => Some(Self::CURLE_FTP_WEIRD_227_FORMAT),
            15 => Some(Self::CURLE_FTP_CANT_GET_HOST),
            16 => Some(Self::CURLE_HTTP2),
            17 => Some(Self::CURLE_FTP_COULDNT_SET_TYPE),
            18 => Some(Self::CURLE_PARTIAL_FILE),
            19 => Some(Self::CURLE_FTP_COULDNT_RETR_FILE),
            20 => Some(Self::CURLE_OBSOLETE20),
            21 => Some(Self::CURLE_QUOTE_ERROR),
            22 => Some(Self::CURLE_HTTP_RETURNED_ERROR),
            23 => Some(Self::CURLE_WRITE_ERROR),
            24 => Some(Self::CURLE_OBSOLETE24),
            25 => Some(Self::CURLE_UPLOAD_FAILED),
            26 => Some(Self::CURLE_READ_ERROR),
            27 => Some(Self::CURLE_OUT_OF_MEMORY),
            28 => Some(Self::CURLE_OPERATION_TIMEDOUT),
            29 => Some(Self::CURLE_OBSOLETE29),
            30 => Some(Self::CURLE_FTP_PORT_FAILED),
            31 => Some(Self::CURLE_FTP_COULDNT_USE_REST),
            32 => Some(Self::CURLE_OBSOLETE32),
            33 => Some(Self::CURLE_RANGE_ERROR),
            34 => Some(Self::CURLE_OBSOLETE34),
            35 => Some(Self::CURLE_SSL_CONNECT_ERROR),
            36 => Some(Self::CURLE_BAD_DOWNLOAD_RESUME),
            37 => Some(Self::CURLE_FILE_COULDNT_READ_FILE),
            38 => Some(Self::CURLE_LDAP_CANNOT_BIND),
            39 => Some(Self::CURLE_LDAP_SEARCH_FAILED),
            40 => Some(Self::CURLE_OBSOLETE40),
            41 => Some(Self::CURLE_OBSOLETE41),
            42 => Some(Self::CURLE_ABORTED_BY_CALLBACK),
            43 => Some(Self::CURLE_BAD_FUNCTION_ARGUMENT),
            44 => Some(Self::CURLE_OBSOLETE44),
            45 => Some(Self::CURLE_INTERFACE_FAILED),
            46 => Some(Self::CURLE_OBSOLETE46),
            47 => Some(Self::CURLE_TOO_MANY_REDIRECTS),
            48 => Some(Self::CURLE_UNKNOWN_OPTION),
            49 => Some(Self::CURLE_SETOPT_OPTION_SYNTAX),
            50 => Some(Self::CURLE_OBSOLETE50),
            51 => Some(Self::CURLE_OBSOLETE51),
            52 => Some(Self::CURLE_GOT_NOTHING),
            53 => Some(Self::CURLE_SSL_ENGINE_NOTFOUND),
            54 => Some(Self::CURLE_SSL_ENGINE_SETFAILED),
            55 => Some(Self::CURLE_SEND_ERROR),
            56 => Some(Self::CURLE_RECV_ERROR),
            57 => Some(Self::CURLE_OBSOLETE57),
            58 => Some(Self::CURLE_SSL_CERTPROBLEM),
            59 => Some(Self::CURLE_SSL_CIPHER),
            60 => Some(Self::CURLE_PEER_FAILED_VERIFICATION),
            61 => Some(Self::CURLE_BAD_CONTENT_ENCODING),
            62 => Some(Self::CURLE_OBSOLETE62),
            63 => Some(Self::CURLE_FILESIZE_EXCEEDED),
            64 => Some(Self::CURLE_USE_SSL_FAILED),
            65 => Some(Self::CURLE_SEND_FAIL_REWIND),
            66 => Some(Self::CURLE_SSL_ENGINE_INITFAILED),
            67 => Some(Self::CURLE_LOGIN_DENIED),
            68 => Some(Self::CURLE_TFTP_NOTFOUND),
            69 => Some(Self::CURLE_TFTP_PERM),
            70 => Some(Self::CURLE_REMOTE_DISK_FULL),
            71 => Some(Self::CURLE_TFTP_ILLEGAL),
            72 => Some(Self::CURLE_TFTP_UNKNOWNID),
            73 => Some(Self::CURLE_REMOTE_FILE_EXISTS),
            74 => Some(Self::CURLE_TFTP_NOSUCHUSER),
            75 => Some(Self::CURLE_OBSOLETE75),
            76 => Some(Self::CURLE_OBSOLETE76),
            77 => Some(Self::CURLE_SSL_CACERT_BADFILE),
            78 => Some(Self::CURLE_REMOTE_FILE_NOT_FOUND),
            79 => Some(Self::CURLE_SSH),
            80 => Some(Self::CURLE_SSL_SHUTDOWN_FAILED),
            81 => Some(Self::CURLE_AGAIN),
            82 => Some(Self::CURLE_SSL_CRL_BADFILE),
            83 => Some(Self::CURLE_SSL_ISSUER_ERROR),
            84 => Some(Self::CURLE_FTP_PRET_FAILED),
            85 => Some(Self::CURLE_RTSP_CSEQ_ERROR),
            86 => Some(Self::CURLE_RTSP_SESSION_ERROR),
            87 => Some(Self::CURLE_FTP_BAD_FILE_LIST),
            88 => Some(Self::CURLE_CHUNK_FAILED),
            89 => Some(Self::CURLE_NO_CONNECTION_AVAILABLE),
            90 => Some(Self::CURLE_SSL_PINNEDPUBKEYNOTMATCH),
            91 => Some(Self::CURLE_SSL_INVALIDCERTSTATUS),
            92 => Some(Self::CURLE_HTTP2_STREAM),
            93 => Some(Self::CURLE_RECURSIVE_API_CALL),
            94 => Some(Self::CURLE_AUTH_ERROR),
            95 => Some(Self::CURLE_HTTP3),
            96 => Some(Self::CURLE_QUIC_CONNECT_ERROR),
            97 => Some(Self::CURLE_PROXY),
            98 => Some(Self::CURLE_SSL_CLIENTCERT),
            99 => Some(Self::CURLE_UNRECOVERABLE_POLL),
            100 => Some(Self::CURLE_TOO_LARGE),
            101 => Some(Self::CURLE_ECH_REQUIRED),
            102 => Some(Self::CURL_LAST),
            _ => None,
        }
    }
}

impl From<engine::CURLcode> for CURLcode {
    /// Total: one arm per engine member, checked exhaustive.
    fn from(code: engine::CURLcode) -> Self {
        match code {
            engine::CURLcode::Ok => Self::CURLE_OK,
            engine::CURLcode::UnsupportedProtocol => {
                Self::CURLE_UNSUPPORTED_PROTOCOL
            }
            engine::CURLcode::FailedInit => Self::CURLE_FAILED_INIT,
            engine::CURLcode::UrlMalformat => Self::CURLE_URL_MALFORMAT,
            engine::CURLcode::NotBuiltIn => Self::CURLE_NOT_BUILT_IN,
            engine::CURLcode::CouldntResolveProxy => {
                Self::CURLE_COULDNT_RESOLVE_PROXY
            }
            engine::CURLcode::CouldntResolveHost => {
                Self::CURLE_COULDNT_RESOLVE_HOST
            }
            engine::CURLcode::CouldntConnect => Self::CURLE_COULDNT_CONNECT,
            engine::CURLcode::WeirdServerReply => {
                Self::CURLE_WEIRD_SERVER_REPLY
            }
            engine::CURLcode::RemoteAccessDenied => {
                Self::CURLE_REMOTE_ACCESS_DENIED
            }
            engine::CURLcode::FtpAcceptFailed => Self::CURLE_FTP_ACCEPT_FAILED,
            engine::CURLcode::FtpWeirdPassReply => {
                Self::CURLE_FTP_WEIRD_PASS_REPLY
            }
            engine::CURLcode::FtpAcceptTimeout => {
                Self::CURLE_FTP_ACCEPT_TIMEOUT
            }
            engine::CURLcode::FtpWeirdPasvReply => {
                Self::CURLE_FTP_WEIRD_PASV_REPLY
            }
            engine::CURLcode::FtpWeird227Format => {
                Self::CURLE_FTP_WEIRD_227_FORMAT
            }
            engine::CURLcode::FtpCantGetHost => Self::CURLE_FTP_CANT_GET_HOST,
            engine::CURLcode::Http2 => Self::CURLE_HTTP2,
            engine::CURLcode::FtpCouldntSetType => {
                Self::CURLE_FTP_COULDNT_SET_TYPE
            }
            engine::CURLcode::PartialFile => Self::CURLE_PARTIAL_FILE,
            engine::CURLcode::FtpCouldntRetrFile => {
                Self::CURLE_FTP_COULDNT_RETR_FILE
            }
            engine::CURLcode::Obsolete20 => Self::CURLE_OBSOLETE20,
            engine::CURLcode::QuoteError => Self::CURLE_QUOTE_ERROR,
            engine::CURLcode::HttpReturnedError => {
                Self::CURLE_HTTP_RETURNED_ERROR
            }
            engine::CURLcode::WriteError => Self::CURLE_WRITE_ERROR,
            engine::CURLcode::Obsolete24 => Self::CURLE_OBSOLETE24,
            engine::CURLcode::UploadFailed => Self::CURLE_UPLOAD_FAILED,
            engine::CURLcode::ReadError => Self::CURLE_READ_ERROR,
            engine::CURLcode::OutOfMemory => Self::CURLE_OUT_OF_MEMORY,
            engine::CURLcode::OperationTimedout => {
                Self::CURLE_OPERATION_TIMEDOUT
            }
            engine::CURLcode::Obsolete29 => Self::CURLE_OBSOLETE29,
            engine::CURLcode::FtpPortFailed => Self::CURLE_FTP_PORT_FAILED,
            engine::CURLcode::FtpCouldntUseRest => {
                Self::CURLE_FTP_COULDNT_USE_REST
            }
            engine::CURLcode::Obsolete32 => Self::CURLE_OBSOLETE32,
            engine::CURLcode::RangeError => Self::CURLE_RANGE_ERROR,
            engine::CURLcode::Obsolete34 => Self::CURLE_OBSOLETE34,
            engine::CURLcode::SslConnectError => Self::CURLE_SSL_CONNECT_ERROR,
            engine::CURLcode::BadDownloadResume => {
                Self::CURLE_BAD_DOWNLOAD_RESUME
            }
            engine::CURLcode::FileCouldntReadFile => {
                Self::CURLE_FILE_COULDNT_READ_FILE
            }
            engine::CURLcode::LdapCannotBind => Self::CURLE_LDAP_CANNOT_BIND,
            engine::CURLcode::LdapSearchFailed => {
                Self::CURLE_LDAP_SEARCH_FAILED
            }
            engine::CURLcode::Obsolete40 => Self::CURLE_OBSOLETE40,
            engine::CURLcode::Obsolete41 => Self::CURLE_OBSOLETE41,
            engine::CURLcode::AbortedByCallback => {
                Self::CURLE_ABORTED_BY_CALLBACK
            }
            engine::CURLcode::BadFunctionArgument => {
                Self::CURLE_BAD_FUNCTION_ARGUMENT
            }
            engine::CURLcode::Obsolete44 => Self::CURLE_OBSOLETE44,
            engine::CURLcode::InterfaceFailed => Self::CURLE_INTERFACE_FAILED,
            engine::CURLcode::Obsolete46 => Self::CURLE_OBSOLETE46,
            engine::CURLcode::TooManyRedirects => {
                Self::CURLE_TOO_MANY_REDIRECTS
            }
            engine::CURLcode::UnknownOption => Self::CURLE_UNKNOWN_OPTION,
            engine::CURLcode::SetoptOptionSyntax => {
                Self::CURLE_SETOPT_OPTION_SYNTAX
            }
            engine::CURLcode::Obsolete50 => Self::CURLE_OBSOLETE50,
            engine::CURLcode::Obsolete51 => Self::CURLE_OBSOLETE51,
            engine::CURLcode::GotNothing => Self::CURLE_GOT_NOTHING,
            engine::CURLcode::SslEngineNotfound => {
                Self::CURLE_SSL_ENGINE_NOTFOUND
            }
            engine::CURLcode::SslEngineSetfailed => {
                Self::CURLE_SSL_ENGINE_SETFAILED
            }
            engine::CURLcode::SendError => Self::CURLE_SEND_ERROR,
            engine::CURLcode::RecvError => Self::CURLE_RECV_ERROR,
            engine::CURLcode::Obsolete57 => Self::CURLE_OBSOLETE57,
            engine::CURLcode::SslCertproblem => Self::CURLE_SSL_CERTPROBLEM,
            engine::CURLcode::SslCipher => Self::CURLE_SSL_CIPHER,
            engine::CURLcode::PeerFailedVerification => {
                Self::CURLE_PEER_FAILED_VERIFICATION
            }
            engine::CURLcode::BadContentEncoding => {
                Self::CURLE_BAD_CONTENT_ENCODING
            }
            engine::CURLcode::Obsolete62 => Self::CURLE_OBSOLETE62,
            engine::CURLcode::FilesizeExceeded => Self::CURLE_FILESIZE_EXCEEDED,
            engine::CURLcode::UseSslFailed => Self::CURLE_USE_SSL_FAILED,
            engine::CURLcode::SendFailRewind => Self::CURLE_SEND_FAIL_REWIND,
            engine::CURLcode::SslEngineInitfailed => {
                Self::CURLE_SSL_ENGINE_INITFAILED
            }
            engine::CURLcode::LoginDenied => Self::CURLE_LOGIN_DENIED,
            engine::CURLcode::TftpNotfound => Self::CURLE_TFTP_NOTFOUND,
            engine::CURLcode::TftpPerm => Self::CURLE_TFTP_PERM,
            engine::CURLcode::RemoteDiskFull => Self::CURLE_REMOTE_DISK_FULL,
            engine::CURLcode::TftpIllegal => Self::CURLE_TFTP_ILLEGAL,
            engine::CURLcode::TftpUnknownid => Self::CURLE_TFTP_UNKNOWNID,
            engine::CURLcode::RemoteFileExists => {
                Self::CURLE_REMOTE_FILE_EXISTS
            }
            engine::CURLcode::TftpNosuchuser => Self::CURLE_TFTP_NOSUCHUSER,
            engine::CURLcode::Obsolete75 => Self::CURLE_OBSOLETE75,
            engine::CURLcode::Obsolete76 => Self::CURLE_OBSOLETE76,
            engine::CURLcode::SslCacertBadfile => {
                Self::CURLE_SSL_CACERT_BADFILE
            }
            engine::CURLcode::RemoteFileNotFound => {
                Self::CURLE_REMOTE_FILE_NOT_FOUND
            }
            engine::CURLcode::Ssh => Self::CURLE_SSH,
            engine::CURLcode::SslShutdownFailed => {
                Self::CURLE_SSL_SHUTDOWN_FAILED
            }
            engine::CURLcode::Again => Self::CURLE_AGAIN,
            engine::CURLcode::SslCrlBadfile => Self::CURLE_SSL_CRL_BADFILE,
            engine::CURLcode::SslIssuerError => Self::CURLE_SSL_ISSUER_ERROR,
            engine::CURLcode::FtpPretFailed => Self::CURLE_FTP_PRET_FAILED,
            engine::CURLcode::RtspCseqError => Self::CURLE_RTSP_CSEQ_ERROR,
            engine::CURLcode::RtspSessionError => {
                Self::CURLE_RTSP_SESSION_ERROR
            }
            engine::CURLcode::FtpBadFileList => Self::CURLE_FTP_BAD_FILE_LIST,
            engine::CURLcode::ChunkFailed => Self::CURLE_CHUNK_FAILED,
            engine::CURLcode::NoConnectionAvailable => {
                Self::CURLE_NO_CONNECTION_AVAILABLE
            }
            engine::CURLcode::SslPinnedpubkeynotmatch => {
                Self::CURLE_SSL_PINNEDPUBKEYNOTMATCH
            }
            engine::CURLcode::SslInvalidcertstatus => {
                Self::CURLE_SSL_INVALIDCERTSTATUS
            }
            engine::CURLcode::Http2Stream => Self::CURLE_HTTP2_STREAM,
            engine::CURLcode::RecursiveApiCall => {
                Self::CURLE_RECURSIVE_API_CALL
            }
            engine::CURLcode::AuthError => Self::CURLE_AUTH_ERROR,
            engine::CURLcode::Http3 => Self::CURLE_HTTP3,
            engine::CURLcode::QuicConnectError => {
                Self::CURLE_QUIC_CONNECT_ERROR
            }
            engine::CURLcode::Proxy => Self::CURLE_PROXY,
            engine::CURLcode::SslClientcert => Self::CURLE_SSL_CLIENTCERT,
            engine::CURLcode::UnrecoverablePoll => {
                Self::CURLE_UNRECOVERABLE_POLL
            }
            engine::CURLcode::TooLarge => Self::CURLE_TOO_LARGE,
            engine::CURLcode::EchRequired => Self::CURLE_ECH_REQUIRED,
            engine::CURLcode::Last => Self::CURL_LAST,
        }
    }
}

impl From<CURLcode> for engine::CURLcode {
    /// Total: one arm per ABI member, checked exhaustive.
    fn from(code: CURLcode) -> Self {
        match code {
            CURLcode::CURLE_OK => Self::Ok,
            CURLcode::CURLE_UNSUPPORTED_PROTOCOL => Self::UnsupportedProtocol,
            CURLcode::CURLE_FAILED_INIT => Self::FailedInit,
            CURLcode::CURLE_URL_MALFORMAT => Self::UrlMalformat,
            CURLcode::CURLE_NOT_BUILT_IN => Self::NotBuiltIn,
            CURLcode::CURLE_COULDNT_RESOLVE_PROXY => Self::CouldntResolveProxy,
            CURLcode::CURLE_COULDNT_RESOLVE_HOST => Self::CouldntResolveHost,
            CURLcode::CURLE_COULDNT_CONNECT => Self::CouldntConnect,
            CURLcode::CURLE_WEIRD_SERVER_REPLY => Self::WeirdServerReply,
            CURLcode::CURLE_REMOTE_ACCESS_DENIED => Self::RemoteAccessDenied,
            CURLcode::CURLE_FTP_ACCEPT_FAILED => Self::FtpAcceptFailed,
            CURLcode::CURLE_FTP_WEIRD_PASS_REPLY => Self::FtpWeirdPassReply,
            CURLcode::CURLE_FTP_ACCEPT_TIMEOUT => Self::FtpAcceptTimeout,
            CURLcode::CURLE_FTP_WEIRD_PASV_REPLY => Self::FtpWeirdPasvReply,
            CURLcode::CURLE_FTP_WEIRD_227_FORMAT => Self::FtpWeird227Format,
            CURLcode::CURLE_FTP_CANT_GET_HOST => Self::FtpCantGetHost,
            CURLcode::CURLE_HTTP2 => Self::Http2,
            CURLcode::CURLE_FTP_COULDNT_SET_TYPE => Self::FtpCouldntSetType,
            CURLcode::CURLE_PARTIAL_FILE => Self::PartialFile,
            CURLcode::CURLE_FTP_COULDNT_RETR_FILE => Self::FtpCouldntRetrFile,
            CURLcode::CURLE_OBSOLETE20 => Self::Obsolete20,
            CURLcode::CURLE_QUOTE_ERROR => Self::QuoteError,
            CURLcode::CURLE_HTTP_RETURNED_ERROR => Self::HttpReturnedError,
            CURLcode::CURLE_WRITE_ERROR => Self::WriteError,
            CURLcode::CURLE_OBSOLETE24 => Self::Obsolete24,
            CURLcode::CURLE_UPLOAD_FAILED => Self::UploadFailed,
            CURLcode::CURLE_READ_ERROR => Self::ReadError,
            CURLcode::CURLE_OUT_OF_MEMORY => Self::OutOfMemory,
            CURLcode::CURLE_OPERATION_TIMEDOUT => Self::OperationTimedout,
            CURLcode::CURLE_OBSOLETE29 => Self::Obsolete29,
            CURLcode::CURLE_FTP_PORT_FAILED => Self::FtpPortFailed,
            CURLcode::CURLE_FTP_COULDNT_USE_REST => Self::FtpCouldntUseRest,
            CURLcode::CURLE_OBSOLETE32 => Self::Obsolete32,
            CURLcode::CURLE_RANGE_ERROR => Self::RangeError,
            CURLcode::CURLE_OBSOLETE34 => Self::Obsolete34,
            CURLcode::CURLE_SSL_CONNECT_ERROR => Self::SslConnectError,
            CURLcode::CURLE_BAD_DOWNLOAD_RESUME => Self::BadDownloadResume,
            CURLcode::CURLE_FILE_COULDNT_READ_FILE => Self::FileCouldntReadFile,
            CURLcode::CURLE_LDAP_CANNOT_BIND => Self::LdapCannotBind,
            CURLcode::CURLE_LDAP_SEARCH_FAILED => Self::LdapSearchFailed,
            CURLcode::CURLE_OBSOLETE40 => Self::Obsolete40,
            CURLcode::CURLE_OBSOLETE41 => Self::Obsolete41,
            CURLcode::CURLE_ABORTED_BY_CALLBACK => Self::AbortedByCallback,
            CURLcode::CURLE_BAD_FUNCTION_ARGUMENT => Self::BadFunctionArgument,
            CURLcode::CURLE_OBSOLETE44 => Self::Obsolete44,
            CURLcode::CURLE_INTERFACE_FAILED => Self::InterfaceFailed,
            CURLcode::CURLE_OBSOLETE46 => Self::Obsolete46,
            CURLcode::CURLE_TOO_MANY_REDIRECTS => Self::TooManyRedirects,
            CURLcode::CURLE_UNKNOWN_OPTION => Self::UnknownOption,
            CURLcode::CURLE_SETOPT_OPTION_SYNTAX => Self::SetoptOptionSyntax,
            CURLcode::CURLE_OBSOLETE50 => Self::Obsolete50,
            CURLcode::CURLE_OBSOLETE51 => Self::Obsolete51,
            CURLcode::CURLE_GOT_NOTHING => Self::GotNothing,
            CURLcode::CURLE_SSL_ENGINE_NOTFOUND => Self::SslEngineNotfound,
            CURLcode::CURLE_SSL_ENGINE_SETFAILED => Self::SslEngineSetfailed,
            CURLcode::CURLE_SEND_ERROR => Self::SendError,
            CURLcode::CURLE_RECV_ERROR => Self::RecvError,
            CURLcode::CURLE_OBSOLETE57 => Self::Obsolete57,
            CURLcode::CURLE_SSL_CERTPROBLEM => Self::SslCertproblem,
            CURLcode::CURLE_SSL_CIPHER => Self::SslCipher,
            CURLcode::CURLE_PEER_FAILED_VERIFICATION => {
                Self::PeerFailedVerification
            }
            CURLcode::CURLE_BAD_CONTENT_ENCODING => Self::BadContentEncoding,
            CURLcode::CURLE_OBSOLETE62 => Self::Obsolete62,
            CURLcode::CURLE_FILESIZE_EXCEEDED => Self::FilesizeExceeded,
            CURLcode::CURLE_USE_SSL_FAILED => Self::UseSslFailed,
            CURLcode::CURLE_SEND_FAIL_REWIND => Self::SendFailRewind,
            CURLcode::CURLE_SSL_ENGINE_INITFAILED => Self::SslEngineInitfailed,
            CURLcode::CURLE_LOGIN_DENIED => Self::LoginDenied,
            CURLcode::CURLE_TFTP_NOTFOUND => Self::TftpNotfound,
            CURLcode::CURLE_TFTP_PERM => Self::TftpPerm,
            CURLcode::CURLE_REMOTE_DISK_FULL => Self::RemoteDiskFull,
            CURLcode::CURLE_TFTP_ILLEGAL => Self::TftpIllegal,
            CURLcode::CURLE_TFTP_UNKNOWNID => Self::TftpUnknownid,
            CURLcode::CURLE_REMOTE_FILE_EXISTS => Self::RemoteFileExists,
            CURLcode::CURLE_TFTP_NOSUCHUSER => Self::TftpNosuchuser,
            CURLcode::CURLE_OBSOLETE75 => Self::Obsolete75,
            CURLcode::CURLE_OBSOLETE76 => Self::Obsolete76,
            CURLcode::CURLE_SSL_CACERT_BADFILE => Self::SslCacertBadfile,
            CURLcode::CURLE_REMOTE_FILE_NOT_FOUND => Self::RemoteFileNotFound,
            CURLcode::CURLE_SSH => Self::Ssh,
            CURLcode::CURLE_SSL_SHUTDOWN_FAILED => Self::SslShutdownFailed,
            CURLcode::CURLE_AGAIN => Self::Again,
            CURLcode::CURLE_SSL_CRL_BADFILE => Self::SslCrlBadfile,
            CURLcode::CURLE_SSL_ISSUER_ERROR => Self::SslIssuerError,
            CURLcode::CURLE_FTP_PRET_FAILED => Self::FtpPretFailed,
            CURLcode::CURLE_RTSP_CSEQ_ERROR => Self::RtspCseqError,
            CURLcode::CURLE_RTSP_SESSION_ERROR => Self::RtspSessionError,
            CURLcode::CURLE_FTP_BAD_FILE_LIST => Self::FtpBadFileList,
            CURLcode::CURLE_CHUNK_FAILED => Self::ChunkFailed,
            CURLcode::CURLE_NO_CONNECTION_AVAILABLE => {
                Self::NoConnectionAvailable
            }
            CURLcode::CURLE_SSL_PINNEDPUBKEYNOTMATCH => {
                Self::SslPinnedpubkeynotmatch
            }
            CURLcode::CURLE_SSL_INVALIDCERTSTATUS => Self::SslInvalidcertstatus,
            CURLcode::CURLE_HTTP2_STREAM => Self::Http2Stream,
            CURLcode::CURLE_RECURSIVE_API_CALL => Self::RecursiveApiCall,
            CURLcode::CURLE_AUTH_ERROR => Self::AuthError,
            CURLcode::CURLE_HTTP3 => Self::Http3,
            CURLcode::CURLE_QUIC_CONNECT_ERROR => Self::QuicConnectError,
            CURLcode::CURLE_PROXY => Self::Proxy,
            CURLcode::CURLE_SSL_CLIENTCERT => Self::SslClientcert,
            CURLcode::CURLE_UNRECOVERABLE_POLL => Self::UnrecoverablePoll,
            CURLcode::CURLE_TOO_LARGE => Self::TooLarge,
            CURLcode::CURLE_ECH_REQUIRED => Self::EchRequired,
            CURLcode::CURL_LAST => Self::Last,
        }
    }
}

/// Every error a multi-interface function can report.
///
/// Transcribed from `include/curl/multi.h:59-78`.
///
/// The only public curl enumeration with a negative member.
/// `CURLM_CALL_MULTI_PERFORM` = -1 is a retired signal that once told a
/// caller to call `curl_multi_perform` again immediately; it is retained
/// because `CURLM_CALL_MULTI_SOCKET` is defined as an alias of it. The
/// negative member is why the representation must be signed.
///
/// Bridged to [`engine::CURLMcode`] in both directions by exhaustive
/// `match`, so a divergence between the two declarations cannot compile.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CURLMcode {
    /// please call curl_multi_perform() or curl_multi_socket*() soon
    CURLM_CALL_MULTI_PERFORM = -1,
    CURLM_OK = 0,
    /// the passed-in handle is not a valid CURLM handle
    CURLM_BAD_HANDLE = 1,
    /// an easy handle was not good/valid
    CURLM_BAD_EASY_HANDLE = 2,
    /// if you ever get this, you are in deep sh*t
    CURLM_OUT_OF_MEMORY = 3,
    /// this is a libcurl bug
    CURLM_INTERNAL_ERROR = 4,
    /// the passed in socket argument did not match
    CURLM_BAD_SOCKET = 5,
    /// curl_multi_setopt() with unsupported option
    CURLM_UNKNOWN_OPTION = 6,
    /// an easy handle already added to a multi handle was attempted to get
    /// added - again
    CURLM_ADDED_ALREADY = 7,
    /// an api function was called from inside a callback
    CURLM_RECURSIVE_API_CALL = 8,
    /// wakeup is unavailable or failed
    CURLM_WAKEUP_FAILURE = 9,
    /// function called with a bad parameter
    CURLM_BAD_FUNCTION_ARGUMENT = 10,
    CURLM_ABORTED_BY_CALLBACK = 11,
    CURLM_UNRECOVERABLE_POLL = 12,
    CURLM_LAST = 13,
}

impl CURLMcode {
    /// Every member as `(C identifier, value)`, in declaration order.
    ///
    /// The single place the tests read, so neither the comparison against
    /// the frozen header nor the one against the engine needs a
    /// hand-maintained list that could drift on its own.
    #[allow(dead_code)]
    pub(crate) const ABI_VARIANTS: &'static [(&'static str, i32)] = &[
        ("CURLM_CALL_MULTI_PERFORM", -1),
        ("CURLM_OK", 0),
        ("CURLM_BAD_HANDLE", 1),
        ("CURLM_BAD_EASY_HANDLE", 2),
        ("CURLM_OUT_OF_MEMORY", 3),
        ("CURLM_INTERNAL_ERROR", 4),
        ("CURLM_BAD_SOCKET", 5),
        ("CURLM_UNKNOWN_OPTION", 6),
        ("CURLM_ADDED_ALREADY", 7),
        ("CURLM_RECURSIVE_API_CALL", 8),
        ("CURLM_WAKEUP_FAILURE", 9),
        ("CURLM_BAD_FUNCTION_ARGUMENT", 10),
        ("CURLM_ABORTED_BY_CALLBACK", 11),
        ("CURLM_UNRECOVERABLE_POLL", 12),
        ("CURLM_LAST", 13),
    ];

    /// The C identifier, which is also this member's Rust identifier.
    ///
    /// An exhaustive `match` rather than a lookup keyed on the value, so
    /// it stays correct without depending on the set being contiguous.
    #[allow(dead_code)]
    pub(crate) const fn c_name(self) -> &'static str {
        match self {
            Self::CURLM_CALL_MULTI_PERFORM => "CURLM_CALL_MULTI_PERFORM",
            Self::CURLM_OK => "CURLM_OK",
            Self::CURLM_BAD_HANDLE => "CURLM_BAD_HANDLE",
            Self::CURLM_BAD_EASY_HANDLE => "CURLM_BAD_EASY_HANDLE",
            Self::CURLM_OUT_OF_MEMORY => "CURLM_OUT_OF_MEMORY",
            Self::CURLM_INTERNAL_ERROR => "CURLM_INTERNAL_ERROR",
            Self::CURLM_BAD_SOCKET => "CURLM_BAD_SOCKET",
            Self::CURLM_UNKNOWN_OPTION => "CURLM_UNKNOWN_OPTION",
            Self::CURLM_ADDED_ALREADY => "CURLM_ADDED_ALREADY",
            Self::CURLM_RECURSIVE_API_CALL => "CURLM_RECURSIVE_API_CALL",
            Self::CURLM_WAKEUP_FAILURE => "CURLM_WAKEUP_FAILURE",
            Self::CURLM_BAD_FUNCTION_ARGUMENT => "CURLM_BAD_FUNCTION_ARGUMENT",
            Self::CURLM_ABORTED_BY_CALLBACK => "CURLM_ABORTED_BY_CALLBACK",
            Self::CURLM_UNRECOVERABLE_POLL => "CURLM_UNRECOVERABLE_POLL",
            Self::CURLM_LAST => "CURLM_LAST",
        }
    }

    /// The pinned discriminant, for handing back across the ABI.
    #[allow(dead_code)]
    pub(crate) const fn as_c_int(self) -> i32 {
        self as i32
    }

    /// The member with this discriminant, or `None` if C handed over a
    /// value this enumeration does not define.
    ///
    /// A C caller can pass any `int`. Returning `None` rather than
    /// transmuting keeps an out-of-range value from becoming an invalid
    /// enum, which would be undefined behaviour.
    #[allow(dead_code)]
    pub(crate) const fn from_c_int(raw: i32) -> Option<Self> {
        match raw {
            -1 => Some(Self::CURLM_CALL_MULTI_PERFORM),
            0 => Some(Self::CURLM_OK),
            1 => Some(Self::CURLM_BAD_HANDLE),
            2 => Some(Self::CURLM_BAD_EASY_HANDLE),
            3 => Some(Self::CURLM_OUT_OF_MEMORY),
            4 => Some(Self::CURLM_INTERNAL_ERROR),
            5 => Some(Self::CURLM_BAD_SOCKET),
            6 => Some(Self::CURLM_UNKNOWN_OPTION),
            7 => Some(Self::CURLM_ADDED_ALREADY),
            8 => Some(Self::CURLM_RECURSIVE_API_CALL),
            9 => Some(Self::CURLM_WAKEUP_FAILURE),
            10 => Some(Self::CURLM_BAD_FUNCTION_ARGUMENT),
            11 => Some(Self::CURLM_ABORTED_BY_CALLBACK),
            12 => Some(Self::CURLM_UNRECOVERABLE_POLL),
            13 => Some(Self::CURLM_LAST),
            _ => None,
        }
    }
}

impl From<engine::CURLMcode> for CURLMcode {
    /// Total: one arm per engine member, checked exhaustive.
    fn from(code: engine::CURLMcode) -> Self {
        match code {
            engine::CURLMcode::CallMultiPerform => {
                Self::CURLM_CALL_MULTI_PERFORM
            }
            engine::CURLMcode::Ok => Self::CURLM_OK,
            engine::CURLMcode::BadHandle => Self::CURLM_BAD_HANDLE,
            engine::CURLMcode::BadEasyHandle => Self::CURLM_BAD_EASY_HANDLE,
            engine::CURLMcode::OutOfMemory => Self::CURLM_OUT_OF_MEMORY,
            engine::CURLMcode::InternalError => Self::CURLM_INTERNAL_ERROR,
            engine::CURLMcode::BadSocket => Self::CURLM_BAD_SOCKET,
            engine::CURLMcode::UnknownOption => Self::CURLM_UNKNOWN_OPTION,
            engine::CURLMcode::AddedAlready => Self::CURLM_ADDED_ALREADY,
            engine::CURLMcode::RecursiveApiCall => {
                Self::CURLM_RECURSIVE_API_CALL
            }
            engine::CURLMcode::WakeupFailure => Self::CURLM_WAKEUP_FAILURE,
            engine::CURLMcode::BadFunctionArgument => {
                Self::CURLM_BAD_FUNCTION_ARGUMENT
            }
            engine::CURLMcode::AbortedByCallback => {
                Self::CURLM_ABORTED_BY_CALLBACK
            }
            engine::CURLMcode::UnrecoverablePoll => {
                Self::CURLM_UNRECOVERABLE_POLL
            }
            engine::CURLMcode::Last => Self::CURLM_LAST,
        }
    }
}

impl From<CURLMcode> for engine::CURLMcode {
    /// Total: one arm per ABI member, checked exhaustive.
    fn from(code: CURLMcode) -> Self {
        match code {
            CURLMcode::CURLM_CALL_MULTI_PERFORM => Self::CallMultiPerform,
            CURLMcode::CURLM_OK => Self::Ok,
            CURLMcode::CURLM_BAD_HANDLE => Self::BadHandle,
            CURLMcode::CURLM_BAD_EASY_HANDLE => Self::BadEasyHandle,
            CURLMcode::CURLM_OUT_OF_MEMORY => Self::OutOfMemory,
            CURLMcode::CURLM_INTERNAL_ERROR => Self::InternalError,
            CURLMcode::CURLM_BAD_SOCKET => Self::BadSocket,
            CURLMcode::CURLM_UNKNOWN_OPTION => Self::UnknownOption,
            CURLMcode::CURLM_ADDED_ALREADY => Self::AddedAlready,
            CURLMcode::CURLM_RECURSIVE_API_CALL => Self::RecursiveApiCall,
            CURLMcode::CURLM_WAKEUP_FAILURE => Self::WakeupFailure,
            CURLMcode::CURLM_BAD_FUNCTION_ARGUMENT => Self::BadFunctionArgument,
            CURLMcode::CURLM_ABORTED_BY_CALLBACK => Self::AbortedByCallback,
            CURLMcode::CURLM_UNRECOVERABLE_POLL => Self::UnrecoverablePoll,
            CURLMcode::CURLM_LAST => Self::Last,
        }
    }
}

/// Every error the URL API can report.
///
/// Transcribed from `include/curl/urlapi.h:34-68`.
///
/// `CURLUE_LAST` = 32 is a bound, not a value.
///
/// Bridged to [`engine::CURLUcode`] in both directions by exhaustive
/// `match`, so a divergence between the two declarations cannot compile.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CURLUcode {
    CURLUE_OK = 0,
    CURLUE_BAD_HANDLE = 1,
    CURLUE_BAD_PARTPOINTER = 2,
    CURLUE_MALFORMED_INPUT = 3,
    CURLUE_BAD_PORT_NUMBER = 4,
    CURLUE_UNSUPPORTED_SCHEME = 5,
    CURLUE_URLDECODE = 6,
    CURLUE_OUT_OF_MEMORY = 7,
    CURLUE_USER_NOT_ALLOWED = 8,
    CURLUE_UNKNOWN_PART = 9,
    CURLUE_NO_SCHEME = 10,
    CURLUE_NO_USER = 11,
    CURLUE_NO_PASSWORD = 12,
    CURLUE_NO_OPTIONS = 13,
    CURLUE_NO_HOST = 14,
    CURLUE_NO_PORT = 15,
    CURLUE_NO_QUERY = 16,
    CURLUE_NO_FRAGMENT = 17,
    CURLUE_NO_ZONEID = 18,
    CURLUE_BAD_FILE_URL = 19,
    CURLUE_BAD_FRAGMENT = 20,
    CURLUE_BAD_HOSTNAME = 21,
    CURLUE_BAD_IPV6 = 22,
    CURLUE_BAD_LOGIN = 23,
    CURLUE_BAD_PASSWORD = 24,
    CURLUE_BAD_PATH = 25,
    CURLUE_BAD_QUERY = 26,
    CURLUE_BAD_SCHEME = 27,
    CURLUE_BAD_SLASHES = 28,
    CURLUE_BAD_USER = 29,
    CURLUE_LACKS_IDN = 30,
    CURLUE_TOO_LARGE = 31,
    CURLUE_LAST = 32,
}

impl CURLUcode {
    /// Every member as `(C identifier, value)`, in declaration order.
    ///
    /// The single place the tests read, so neither the comparison against
    /// the frozen header nor the one against the engine needs a
    /// hand-maintained list that could drift on its own.
    #[allow(dead_code)]
    pub(crate) const ABI_VARIANTS: &'static [(&'static str, i32)] = &[
        ("CURLUE_OK", 0),
        ("CURLUE_BAD_HANDLE", 1),
        ("CURLUE_BAD_PARTPOINTER", 2),
        ("CURLUE_MALFORMED_INPUT", 3),
        ("CURLUE_BAD_PORT_NUMBER", 4),
        ("CURLUE_UNSUPPORTED_SCHEME", 5),
        ("CURLUE_URLDECODE", 6),
        ("CURLUE_OUT_OF_MEMORY", 7),
        ("CURLUE_USER_NOT_ALLOWED", 8),
        ("CURLUE_UNKNOWN_PART", 9),
        ("CURLUE_NO_SCHEME", 10),
        ("CURLUE_NO_USER", 11),
        ("CURLUE_NO_PASSWORD", 12),
        ("CURLUE_NO_OPTIONS", 13),
        ("CURLUE_NO_HOST", 14),
        ("CURLUE_NO_PORT", 15),
        ("CURLUE_NO_QUERY", 16),
        ("CURLUE_NO_FRAGMENT", 17),
        ("CURLUE_NO_ZONEID", 18),
        ("CURLUE_BAD_FILE_URL", 19),
        ("CURLUE_BAD_FRAGMENT", 20),
        ("CURLUE_BAD_HOSTNAME", 21),
        ("CURLUE_BAD_IPV6", 22),
        ("CURLUE_BAD_LOGIN", 23),
        ("CURLUE_BAD_PASSWORD", 24),
        ("CURLUE_BAD_PATH", 25),
        ("CURLUE_BAD_QUERY", 26),
        ("CURLUE_BAD_SCHEME", 27),
        ("CURLUE_BAD_SLASHES", 28),
        ("CURLUE_BAD_USER", 29),
        ("CURLUE_LACKS_IDN", 30),
        ("CURLUE_TOO_LARGE", 31),
        ("CURLUE_LAST", 32),
    ];

    /// The C identifier, which is also this member's Rust identifier.
    ///
    /// An exhaustive `match` rather than a lookup keyed on the value, so
    /// it stays correct without depending on the set being contiguous.
    #[allow(dead_code)]
    pub(crate) const fn c_name(self) -> &'static str {
        match self {
            Self::CURLUE_OK => "CURLUE_OK",
            Self::CURLUE_BAD_HANDLE => "CURLUE_BAD_HANDLE",
            Self::CURLUE_BAD_PARTPOINTER => "CURLUE_BAD_PARTPOINTER",
            Self::CURLUE_MALFORMED_INPUT => "CURLUE_MALFORMED_INPUT",
            Self::CURLUE_BAD_PORT_NUMBER => "CURLUE_BAD_PORT_NUMBER",
            Self::CURLUE_UNSUPPORTED_SCHEME => "CURLUE_UNSUPPORTED_SCHEME",
            Self::CURLUE_URLDECODE => "CURLUE_URLDECODE",
            Self::CURLUE_OUT_OF_MEMORY => "CURLUE_OUT_OF_MEMORY",
            Self::CURLUE_USER_NOT_ALLOWED => "CURLUE_USER_NOT_ALLOWED",
            Self::CURLUE_UNKNOWN_PART => "CURLUE_UNKNOWN_PART",
            Self::CURLUE_NO_SCHEME => "CURLUE_NO_SCHEME",
            Self::CURLUE_NO_USER => "CURLUE_NO_USER",
            Self::CURLUE_NO_PASSWORD => "CURLUE_NO_PASSWORD",
            Self::CURLUE_NO_OPTIONS => "CURLUE_NO_OPTIONS",
            Self::CURLUE_NO_HOST => "CURLUE_NO_HOST",
            Self::CURLUE_NO_PORT => "CURLUE_NO_PORT",
            Self::CURLUE_NO_QUERY => "CURLUE_NO_QUERY",
            Self::CURLUE_NO_FRAGMENT => "CURLUE_NO_FRAGMENT",
            Self::CURLUE_NO_ZONEID => "CURLUE_NO_ZONEID",
            Self::CURLUE_BAD_FILE_URL => "CURLUE_BAD_FILE_URL",
            Self::CURLUE_BAD_FRAGMENT => "CURLUE_BAD_FRAGMENT",
            Self::CURLUE_BAD_HOSTNAME => "CURLUE_BAD_HOSTNAME",
            Self::CURLUE_BAD_IPV6 => "CURLUE_BAD_IPV6",
            Self::CURLUE_BAD_LOGIN => "CURLUE_BAD_LOGIN",
            Self::CURLUE_BAD_PASSWORD => "CURLUE_BAD_PASSWORD",
            Self::CURLUE_BAD_PATH => "CURLUE_BAD_PATH",
            Self::CURLUE_BAD_QUERY => "CURLUE_BAD_QUERY",
            Self::CURLUE_BAD_SCHEME => "CURLUE_BAD_SCHEME",
            Self::CURLUE_BAD_SLASHES => "CURLUE_BAD_SLASHES",
            Self::CURLUE_BAD_USER => "CURLUE_BAD_USER",
            Self::CURLUE_LACKS_IDN => "CURLUE_LACKS_IDN",
            Self::CURLUE_TOO_LARGE => "CURLUE_TOO_LARGE",
            Self::CURLUE_LAST => "CURLUE_LAST",
        }
    }

    /// The pinned discriminant, for handing back across the ABI.
    #[allow(dead_code)]
    pub(crate) const fn as_c_int(self) -> i32 {
        self as i32
    }

    /// The member with this discriminant, or `None` if C handed over a
    /// value this enumeration does not define.
    ///
    /// A C caller can pass any `int`. Returning `None` rather than
    /// transmuting keeps an out-of-range value from becoming an invalid
    /// enum, which would be undefined behaviour.
    #[allow(dead_code)]
    pub(crate) const fn from_c_int(raw: i32) -> Option<Self> {
        match raw {
            0 => Some(Self::CURLUE_OK),
            1 => Some(Self::CURLUE_BAD_HANDLE),
            2 => Some(Self::CURLUE_BAD_PARTPOINTER),
            3 => Some(Self::CURLUE_MALFORMED_INPUT),
            4 => Some(Self::CURLUE_BAD_PORT_NUMBER),
            5 => Some(Self::CURLUE_UNSUPPORTED_SCHEME),
            6 => Some(Self::CURLUE_URLDECODE),
            7 => Some(Self::CURLUE_OUT_OF_MEMORY),
            8 => Some(Self::CURLUE_USER_NOT_ALLOWED),
            9 => Some(Self::CURLUE_UNKNOWN_PART),
            10 => Some(Self::CURLUE_NO_SCHEME),
            11 => Some(Self::CURLUE_NO_USER),
            12 => Some(Self::CURLUE_NO_PASSWORD),
            13 => Some(Self::CURLUE_NO_OPTIONS),
            14 => Some(Self::CURLUE_NO_HOST),
            15 => Some(Self::CURLUE_NO_PORT),
            16 => Some(Self::CURLUE_NO_QUERY),
            17 => Some(Self::CURLUE_NO_FRAGMENT),
            18 => Some(Self::CURLUE_NO_ZONEID),
            19 => Some(Self::CURLUE_BAD_FILE_URL),
            20 => Some(Self::CURLUE_BAD_FRAGMENT),
            21 => Some(Self::CURLUE_BAD_HOSTNAME),
            22 => Some(Self::CURLUE_BAD_IPV6),
            23 => Some(Self::CURLUE_BAD_LOGIN),
            24 => Some(Self::CURLUE_BAD_PASSWORD),
            25 => Some(Self::CURLUE_BAD_PATH),
            26 => Some(Self::CURLUE_BAD_QUERY),
            27 => Some(Self::CURLUE_BAD_SCHEME),
            28 => Some(Self::CURLUE_BAD_SLASHES),
            29 => Some(Self::CURLUE_BAD_USER),
            30 => Some(Self::CURLUE_LACKS_IDN),
            31 => Some(Self::CURLUE_TOO_LARGE),
            32 => Some(Self::CURLUE_LAST),
            _ => None,
        }
    }
}

impl From<engine::CURLUcode> for CURLUcode {
    /// Total: one arm per engine member, checked exhaustive.
    fn from(code: engine::CURLUcode) -> Self {
        match code {
            engine::CURLUcode::Ok => Self::CURLUE_OK,
            engine::CURLUcode::BadHandle => Self::CURLUE_BAD_HANDLE,
            engine::CURLUcode::BadPartpointer => Self::CURLUE_BAD_PARTPOINTER,
            engine::CURLUcode::MalformedInput => Self::CURLUE_MALFORMED_INPUT,
            engine::CURLUcode::BadPortNumber => Self::CURLUE_BAD_PORT_NUMBER,
            engine::CURLUcode::UnsupportedScheme => {
                Self::CURLUE_UNSUPPORTED_SCHEME
            }
            engine::CURLUcode::Urldecode => Self::CURLUE_URLDECODE,
            engine::CURLUcode::OutOfMemory => Self::CURLUE_OUT_OF_MEMORY,
            engine::CURLUcode::UserNotAllowed => Self::CURLUE_USER_NOT_ALLOWED,
            engine::CURLUcode::UnknownPart => Self::CURLUE_UNKNOWN_PART,
            engine::CURLUcode::NoScheme => Self::CURLUE_NO_SCHEME,
            engine::CURLUcode::NoUser => Self::CURLUE_NO_USER,
            engine::CURLUcode::NoPassword => Self::CURLUE_NO_PASSWORD,
            engine::CURLUcode::NoOptions => Self::CURLUE_NO_OPTIONS,
            engine::CURLUcode::NoHost => Self::CURLUE_NO_HOST,
            engine::CURLUcode::NoPort => Self::CURLUE_NO_PORT,
            engine::CURLUcode::NoQuery => Self::CURLUE_NO_QUERY,
            engine::CURLUcode::NoFragment => Self::CURLUE_NO_FRAGMENT,
            engine::CURLUcode::NoZoneid => Self::CURLUE_NO_ZONEID,
            engine::CURLUcode::BadFileUrl => Self::CURLUE_BAD_FILE_URL,
            engine::CURLUcode::BadFragment => Self::CURLUE_BAD_FRAGMENT,
            engine::CURLUcode::BadHostname => Self::CURLUE_BAD_HOSTNAME,
            engine::CURLUcode::BadIpv6 => Self::CURLUE_BAD_IPV6,
            engine::CURLUcode::BadLogin => Self::CURLUE_BAD_LOGIN,
            engine::CURLUcode::BadPassword => Self::CURLUE_BAD_PASSWORD,
            engine::CURLUcode::BadPath => Self::CURLUE_BAD_PATH,
            engine::CURLUcode::BadQuery => Self::CURLUE_BAD_QUERY,
            engine::CURLUcode::BadScheme => Self::CURLUE_BAD_SCHEME,
            engine::CURLUcode::BadSlashes => Self::CURLUE_BAD_SLASHES,
            engine::CURLUcode::BadUser => Self::CURLUE_BAD_USER,
            engine::CURLUcode::LacksIdn => Self::CURLUE_LACKS_IDN,
            engine::CURLUcode::TooLarge => Self::CURLUE_TOO_LARGE,
            engine::CURLUcode::Last => Self::CURLUE_LAST,
        }
    }
}

impl From<CURLUcode> for engine::CURLUcode {
    /// Total: one arm per ABI member, checked exhaustive.
    fn from(code: CURLUcode) -> Self {
        match code {
            CURLUcode::CURLUE_OK => Self::Ok,
            CURLUcode::CURLUE_BAD_HANDLE => Self::BadHandle,
            CURLUcode::CURLUE_BAD_PARTPOINTER => Self::BadPartpointer,
            CURLUcode::CURLUE_MALFORMED_INPUT => Self::MalformedInput,
            CURLUcode::CURLUE_BAD_PORT_NUMBER => Self::BadPortNumber,
            CURLUcode::CURLUE_UNSUPPORTED_SCHEME => Self::UnsupportedScheme,
            CURLUcode::CURLUE_URLDECODE => Self::Urldecode,
            CURLUcode::CURLUE_OUT_OF_MEMORY => Self::OutOfMemory,
            CURLUcode::CURLUE_USER_NOT_ALLOWED => Self::UserNotAllowed,
            CURLUcode::CURLUE_UNKNOWN_PART => Self::UnknownPart,
            CURLUcode::CURLUE_NO_SCHEME => Self::NoScheme,
            CURLUcode::CURLUE_NO_USER => Self::NoUser,
            CURLUcode::CURLUE_NO_PASSWORD => Self::NoPassword,
            CURLUcode::CURLUE_NO_OPTIONS => Self::NoOptions,
            CURLUcode::CURLUE_NO_HOST => Self::NoHost,
            CURLUcode::CURLUE_NO_PORT => Self::NoPort,
            CURLUcode::CURLUE_NO_QUERY => Self::NoQuery,
            CURLUcode::CURLUE_NO_FRAGMENT => Self::NoFragment,
            CURLUcode::CURLUE_NO_ZONEID => Self::NoZoneid,
            CURLUcode::CURLUE_BAD_FILE_URL => Self::BadFileUrl,
            CURLUcode::CURLUE_BAD_FRAGMENT => Self::BadFragment,
            CURLUcode::CURLUE_BAD_HOSTNAME => Self::BadHostname,
            CURLUcode::CURLUE_BAD_IPV6 => Self::BadIpv6,
            CURLUcode::CURLUE_BAD_LOGIN => Self::BadLogin,
            CURLUcode::CURLUE_BAD_PASSWORD => Self::BadPassword,
            CURLUcode::CURLUE_BAD_PATH => Self::BadPath,
            CURLUcode::CURLUE_BAD_QUERY => Self::BadQuery,
            CURLUcode::CURLUE_BAD_SCHEME => Self::BadScheme,
            CURLUcode::CURLUE_BAD_SLASHES => Self::BadSlashes,
            CURLUcode::CURLUE_BAD_USER => Self::BadUser,
            CURLUcode::CURLUE_LACKS_IDN => Self::LacksIdn,
            CURLUcode::CURLUE_TOO_LARGE => Self::TooLarge,
            CURLUcode::CURLUE_LAST => Self::Last,
        }
    }
}

/// Every error the header API can report.
///
/// Transcribed from `include/curl/header.h:47-56`.
///
/// Unlike its siblings this set has no `_LAST` sentinel: the highest
/// member, `CURLHE_NOT_BUILT_IN` = 7, is a real value.
///
/// Bridged to [`engine::CURLHcode`] in both directions by exhaustive
/// `match`, so a divergence between the two declarations cannot compile.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CURLHcode {
    CURLHE_OK = 0,
    /// header exists but not with this index
    CURLHE_BADINDEX = 1,
    /// no such header exists
    CURLHE_MISSING = 2,
    /// no headers at all exist (yet)
    CURLHE_NOHEADERS = 3,
    /// no request with this number was used
    CURLHE_NOREQUEST = 4,
    /// out of memory while processing
    CURLHE_OUT_OF_MEMORY = 5,
    /// a function argument was not okay
    CURLHE_BAD_ARGUMENT = 6,
    /// if API was disabled in the build
    CURLHE_NOT_BUILT_IN = 7,
}

impl CURLHcode {
    /// Every member as `(C identifier, value)`, in declaration order.
    ///
    /// The single place the tests read, so neither the comparison against
    /// the frozen header nor the one against the engine needs a
    /// hand-maintained list that could drift on its own.
    #[allow(dead_code)]
    pub(crate) const ABI_VARIANTS: &'static [(&'static str, i32)] = &[
        ("CURLHE_OK", 0),
        ("CURLHE_BADINDEX", 1),
        ("CURLHE_MISSING", 2),
        ("CURLHE_NOHEADERS", 3),
        ("CURLHE_NOREQUEST", 4),
        ("CURLHE_OUT_OF_MEMORY", 5),
        ("CURLHE_BAD_ARGUMENT", 6),
        ("CURLHE_NOT_BUILT_IN", 7),
    ];

    /// The C identifier, which is also this member's Rust identifier.
    ///
    /// An exhaustive `match` rather than a lookup keyed on the value, so
    /// it stays correct without depending on the set being contiguous.
    #[allow(dead_code)]
    pub(crate) const fn c_name(self) -> &'static str {
        match self {
            Self::CURLHE_OK => "CURLHE_OK",
            Self::CURLHE_BADINDEX => "CURLHE_BADINDEX",
            Self::CURLHE_MISSING => "CURLHE_MISSING",
            Self::CURLHE_NOHEADERS => "CURLHE_NOHEADERS",
            Self::CURLHE_NOREQUEST => "CURLHE_NOREQUEST",
            Self::CURLHE_OUT_OF_MEMORY => "CURLHE_OUT_OF_MEMORY",
            Self::CURLHE_BAD_ARGUMENT => "CURLHE_BAD_ARGUMENT",
            Self::CURLHE_NOT_BUILT_IN => "CURLHE_NOT_BUILT_IN",
        }
    }

    /// The pinned discriminant, for handing back across the ABI.
    #[allow(dead_code)]
    pub(crate) const fn as_c_int(self) -> i32 {
        self as i32
    }

    /// The member with this discriminant, or `None` if C handed over a
    /// value this enumeration does not define.
    ///
    /// A C caller can pass any `int`. Returning `None` rather than
    /// transmuting keeps an out-of-range value from becoming an invalid
    /// enum, which would be undefined behaviour.
    #[allow(dead_code)]
    pub(crate) const fn from_c_int(raw: i32) -> Option<Self> {
        match raw {
            0 => Some(Self::CURLHE_OK),
            1 => Some(Self::CURLHE_BADINDEX),
            2 => Some(Self::CURLHE_MISSING),
            3 => Some(Self::CURLHE_NOHEADERS),
            4 => Some(Self::CURLHE_NOREQUEST),
            5 => Some(Self::CURLHE_OUT_OF_MEMORY),
            6 => Some(Self::CURLHE_BAD_ARGUMENT),
            7 => Some(Self::CURLHE_NOT_BUILT_IN),
            _ => None,
        }
    }
}

impl From<engine::CURLHcode> for CURLHcode {
    /// Total: one arm per engine member, checked exhaustive.
    fn from(code: engine::CURLHcode) -> Self {
        match code {
            engine::CURLHcode::Ok => Self::CURLHE_OK,
            engine::CURLHcode::Badindex => Self::CURLHE_BADINDEX,
            engine::CURLHcode::Missing => Self::CURLHE_MISSING,
            engine::CURLHcode::Noheaders => Self::CURLHE_NOHEADERS,
            engine::CURLHcode::Norequest => Self::CURLHE_NOREQUEST,
            engine::CURLHcode::OutOfMemory => Self::CURLHE_OUT_OF_MEMORY,
            engine::CURLHcode::BadArgument => Self::CURLHE_BAD_ARGUMENT,
            engine::CURLHcode::NotBuiltIn => Self::CURLHE_NOT_BUILT_IN,
        }
    }
}

impl From<CURLHcode> for engine::CURLHcode {
    /// Total: one arm per ABI member, checked exhaustive.
    fn from(code: CURLHcode) -> Self {
        match code {
            CURLHcode::CURLHE_OK => Self::Ok,
            CURLHcode::CURLHE_BADINDEX => Self::Badindex,
            CURLHcode::CURLHE_MISSING => Self::Missing,
            CURLHcode::CURLHE_NOHEADERS => Self::Noheaders,
            CURLHcode::CURLHE_NOREQUEST => Self::Norequest,
            CURLHcode::CURLHE_OUT_OF_MEMORY => Self::OutOfMemory,
            CURLHcode::CURLHE_BAD_ARGUMENT => Self::BadArgument,
            CURLHcode::CURLHE_NOT_BUILT_IN => Self::NotBuiltIn,
        }
    }
}

/// Every error a share-handle function can report.
///
/// Transcribed from `include/curl/curl.h:3058-3066`.
///
/// `CURLSHE_LAST` = 6 is a bound, not a value.
///
/// Bridged to [`engine::CURLSHcode`] in both directions by exhaustive
/// `match`, so a divergence between the two declarations cannot compile.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CURLSHcode {
    /// all is fine
    CURLSHE_OK = 0,
    CURLSHE_BAD_OPTION = 1,
    CURLSHE_IN_USE = 2,
    CURLSHE_INVALID = 3,
    /// out of memory
    CURLSHE_NOMEM = 4,
    /// feature not present in lib
    CURLSHE_NOT_BUILT_IN = 5,
    /// never use
    CURLSHE_LAST = 6,
}

impl CURLSHcode {
    /// Every member as `(C identifier, value)`, in declaration order.
    ///
    /// The single place the tests read, so neither the comparison against
    /// the frozen header nor the one against the engine needs a
    /// hand-maintained list that could drift on its own.
    #[allow(dead_code)]
    pub(crate) const ABI_VARIANTS: &'static [(&'static str, i32)] = &[
        ("CURLSHE_OK", 0),
        ("CURLSHE_BAD_OPTION", 1),
        ("CURLSHE_IN_USE", 2),
        ("CURLSHE_INVALID", 3),
        ("CURLSHE_NOMEM", 4),
        ("CURLSHE_NOT_BUILT_IN", 5),
        ("CURLSHE_LAST", 6),
    ];

    /// The C identifier, which is also this member's Rust identifier.
    ///
    /// An exhaustive `match` rather than a lookup keyed on the value, so
    /// it stays correct without depending on the set being contiguous.
    #[allow(dead_code)]
    pub(crate) const fn c_name(self) -> &'static str {
        match self {
            Self::CURLSHE_OK => "CURLSHE_OK",
            Self::CURLSHE_BAD_OPTION => "CURLSHE_BAD_OPTION",
            Self::CURLSHE_IN_USE => "CURLSHE_IN_USE",
            Self::CURLSHE_INVALID => "CURLSHE_INVALID",
            Self::CURLSHE_NOMEM => "CURLSHE_NOMEM",
            Self::CURLSHE_NOT_BUILT_IN => "CURLSHE_NOT_BUILT_IN",
            Self::CURLSHE_LAST => "CURLSHE_LAST",
        }
    }

    /// The pinned discriminant, for handing back across the ABI.
    #[allow(dead_code)]
    pub(crate) const fn as_c_int(self) -> i32 {
        self as i32
    }

    /// The member with this discriminant, or `None` if C handed over a
    /// value this enumeration does not define.
    ///
    /// A C caller can pass any `int`. Returning `None` rather than
    /// transmuting keeps an out-of-range value from becoming an invalid
    /// enum, which would be undefined behaviour.
    #[allow(dead_code)]
    pub(crate) const fn from_c_int(raw: i32) -> Option<Self> {
        match raw {
            0 => Some(Self::CURLSHE_OK),
            1 => Some(Self::CURLSHE_BAD_OPTION),
            2 => Some(Self::CURLSHE_IN_USE),
            3 => Some(Self::CURLSHE_INVALID),
            4 => Some(Self::CURLSHE_NOMEM),
            5 => Some(Self::CURLSHE_NOT_BUILT_IN),
            6 => Some(Self::CURLSHE_LAST),
            _ => None,
        }
    }
}

impl From<engine::CURLSHcode> for CURLSHcode {
    /// Total: one arm per engine member, checked exhaustive.
    fn from(code: engine::CURLSHcode) -> Self {
        match code {
            engine::CURLSHcode::Ok => Self::CURLSHE_OK,
            engine::CURLSHcode::BadOption => Self::CURLSHE_BAD_OPTION,
            engine::CURLSHcode::InUse => Self::CURLSHE_IN_USE,
            engine::CURLSHcode::Invalid => Self::CURLSHE_INVALID,
            engine::CURLSHcode::Nomem => Self::CURLSHE_NOMEM,
            engine::CURLSHcode::NotBuiltIn => Self::CURLSHE_NOT_BUILT_IN,
            engine::CURLSHcode::Last => Self::CURLSHE_LAST,
        }
    }
}

impl From<CURLSHcode> for engine::CURLSHcode {
    /// Total: one arm per ABI member, checked exhaustive.
    fn from(code: CURLSHcode) -> Self {
        match code {
            CURLSHcode::CURLSHE_OK => Self::Ok,
            CURLSHcode::CURLSHE_BAD_OPTION => Self::BadOption,
            CURLSHcode::CURLSHE_IN_USE => Self::InUse,
            CURLSHcode::CURLSHE_INVALID => Self::Invalid,
            CURLSHcode::CURLSHE_NOMEM => Self::Nomem,
            CURLSHcode::CURLSHE_NOT_BUILT_IN => Self::NotBuiltIn,
            CURLSHcode::CURLSHE_LAST => Self::Last,
        }
    }
}

/// The option identifiers `curl_share_setopt` accepts.
///
/// Transcribed from `include/curl/curl.h:3068-3077`.
///
/// An option enumeration rather than a result code, which is why it has no
/// engine counterpart in `curl-rs-lib/src/error.rs`.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CURLSHoption {
    /// do not use
    CURLSHOPT_NONE = 0,
    /// specify a data type to share
    CURLSHOPT_SHARE = 1,
    /// specify which data type to stop sharing
    CURLSHOPT_UNSHARE = 2,
    /// pass in a 'curl_lock_function' pointer
    CURLSHOPT_LOCKFUNC = 3,
    /// pass in a 'curl_unlock_function' pointer
    CURLSHOPT_UNLOCKFUNC = 4,
    /// pass in a user data pointer used in the lock/unlock callback
    /// functions
    CURLSHOPT_USERDATA = 5,
    /// never use
    CURLSHOPT_LAST = 6,
}

impl CURLSHoption {
    /// Every member as `(C identifier, value)`, in declaration order.
    ///
    /// The single place the tests read, so neither the comparison against
    /// the frozen header nor the one against the engine needs a
    /// hand-maintained list that could drift on its own.
    #[allow(dead_code)]
    pub(crate) const ABI_VARIANTS: &'static [(&'static str, i32)] = &[
        ("CURLSHOPT_NONE", 0),
        ("CURLSHOPT_SHARE", 1),
        ("CURLSHOPT_UNSHARE", 2),
        ("CURLSHOPT_LOCKFUNC", 3),
        ("CURLSHOPT_UNLOCKFUNC", 4),
        ("CURLSHOPT_USERDATA", 5),
        ("CURLSHOPT_LAST", 6),
    ];

    /// The C identifier, which is also this member's Rust identifier.
    ///
    /// An exhaustive `match` rather than a lookup keyed on the value, so
    /// it stays correct without depending on the set being contiguous.
    #[allow(dead_code)]
    pub(crate) const fn c_name(self) -> &'static str {
        match self {
            Self::CURLSHOPT_NONE => "CURLSHOPT_NONE",
            Self::CURLSHOPT_SHARE => "CURLSHOPT_SHARE",
            Self::CURLSHOPT_UNSHARE => "CURLSHOPT_UNSHARE",
            Self::CURLSHOPT_LOCKFUNC => "CURLSHOPT_LOCKFUNC",
            Self::CURLSHOPT_UNLOCKFUNC => "CURLSHOPT_UNLOCKFUNC",
            Self::CURLSHOPT_USERDATA => "CURLSHOPT_USERDATA",
            Self::CURLSHOPT_LAST => "CURLSHOPT_LAST",
        }
    }

    /// The pinned discriminant, for handing back across the ABI.
    #[allow(dead_code)]
    pub(crate) const fn as_c_int(self) -> i32 {
        self as i32
    }

    /// The member with this discriminant, or `None` if C handed over a
    /// value this enumeration does not define.
    ///
    /// A C caller can pass any `int`. Returning `None` rather than
    /// transmuting keeps an out-of-range value from becoming an invalid
    /// enum, which would be undefined behaviour.
    #[allow(dead_code)]
    pub(crate) const fn from_c_int(raw: i32) -> Option<Self> {
        match raw {
            0 => Some(Self::CURLSHOPT_NONE),
            1 => Some(Self::CURLSHOPT_SHARE),
            2 => Some(Self::CURLSHOPT_UNSHARE),
            3 => Some(Self::CURLSHOPT_LOCKFUNC),
            4 => Some(Self::CURLSHOPT_UNLOCKFUNC),
            5 => Some(Self::CURLSHOPT_USERDATA),
            6 => Some(Self::CURLSHOPT_LAST),
            _ => None,
        }
    }
}

/// The return set of the HSTS read and write callbacks.
///
/// Transcribed from `include/curl/curl.h:1056-1060`.
///
/// `CURLSTS_DONE` ends the callback sequence and `CURLSTS_FAIL` aborts the
/// transfer, so the two non-`OK` members are not interchangeable.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CURLSTScode {
    CURLSTS_OK = 0,
    CURLSTS_DONE = 1,
    CURLSTS_FAIL = 2,
}

impl CURLSTScode {
    /// Every member as `(C identifier, value)`, in declaration order.
    ///
    /// The single place the tests read, so neither the comparison against
    /// the frozen header nor the one against the engine needs a
    /// hand-maintained list that could drift on its own.
    #[allow(dead_code)]
    pub(crate) const ABI_VARIANTS: &'static [(&'static str, i32)] =
        &[("CURLSTS_OK", 0), ("CURLSTS_DONE", 1), ("CURLSTS_FAIL", 2)];

    /// The C identifier, which is also this member's Rust identifier.
    ///
    /// An exhaustive `match` rather than a lookup keyed on the value, so
    /// it stays correct without depending on the set being contiguous.
    #[allow(dead_code)]
    pub(crate) const fn c_name(self) -> &'static str {
        match self {
            Self::CURLSTS_OK => "CURLSTS_OK",
            Self::CURLSTS_DONE => "CURLSTS_DONE",
            Self::CURLSTS_FAIL => "CURLSTS_FAIL",
        }
    }

    /// The pinned discriminant, for handing back across the ABI.
    #[allow(dead_code)]
    pub(crate) const fn as_c_int(self) -> i32 {
        self as i32
    }

    /// The member with this discriminant, or `None` if C handed over a
    /// value this enumeration does not define.
    ///
    /// A C caller can pass any `int`. Returning `None` rather than
    /// transmuting keeps an out-of-range value from becoming an invalid
    /// enum, which would be undefined behaviour.
    #[allow(dead_code)]
    pub(crate) const fn from_c_int(raw: i32) -> Option<Self> {
        match raw {
            0 => Some(Self::CURLSTS_OK),
            1 => Some(Self::CURLSTS_DONE),
            2 => Some(Self::CURLSTS_FAIL),
            _ => None,
        }
    }
}

/// Every error the SOCKS proxy handshake can report.
///
/// Transcribed from `include/curl/curl.h:742-778`.
///
/// Reported through `CURLINFO_PROXY_ERROR` rather than as a function
/// return, which is why a transfer that fails inside the handshake surfaces
/// `CURLE_PROXY` = 97 to the caller and the detail here. `CURLPX_LAST` = 34
/// is a bound, not a value.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CURLproxycode {
    CURLPX_OK = 0,
    CURLPX_BAD_ADDRESS_TYPE = 1,
    CURLPX_BAD_VERSION = 2,
    CURLPX_CLOSED = 3,
    CURLPX_GSSAPI = 4,
    CURLPX_GSSAPI_PERMSG = 5,
    CURLPX_GSSAPI_PROTECTION = 6,
    CURLPX_IDENTD = 7,
    CURLPX_IDENTD_DIFFER = 8,
    CURLPX_LONG_HOSTNAME = 9,
    CURLPX_LONG_PASSWD = 10,
    CURLPX_LONG_USER = 11,
    CURLPX_NO_AUTH = 12,
    CURLPX_RECV_ADDRESS = 13,
    CURLPX_RECV_AUTH = 14,
    CURLPX_RECV_CONNECT = 15,
    CURLPX_RECV_REQACK = 16,
    CURLPX_REPLY_ADDRESS_TYPE_NOT_SUPPORTED = 17,
    CURLPX_REPLY_COMMAND_NOT_SUPPORTED = 18,
    CURLPX_REPLY_CONNECTION_REFUSED = 19,
    CURLPX_REPLY_GENERAL_SERVER_FAILURE = 20,
    CURLPX_REPLY_HOST_UNREACHABLE = 21,
    CURLPX_REPLY_NETWORK_UNREACHABLE = 22,
    CURLPX_REPLY_NOT_ALLOWED = 23,
    CURLPX_REPLY_TTL_EXPIRED = 24,
    CURLPX_REPLY_UNASSIGNED = 25,
    CURLPX_REQUEST_FAILED = 26,
    CURLPX_RESOLVE_HOST = 27,
    CURLPX_SEND_AUTH = 28,
    CURLPX_SEND_CONNECT = 29,
    CURLPX_SEND_REQUEST = 30,
    CURLPX_UNKNOWN_FAIL = 31,
    CURLPX_UNKNOWN_MODE = 32,
    CURLPX_USER_REJECTED = 33,
    /// never use
    CURLPX_LAST = 34,
}

impl CURLproxycode {
    /// Every member as `(C identifier, value)`, in declaration order.
    ///
    /// The single place the tests read, so neither the comparison against
    /// the frozen header nor the one against the engine needs a
    /// hand-maintained list that could drift on its own.
    #[allow(dead_code)]
    pub(crate) const ABI_VARIANTS: &'static [(&'static str, i32)] = &[
        ("CURLPX_OK", 0),
        ("CURLPX_BAD_ADDRESS_TYPE", 1),
        ("CURLPX_BAD_VERSION", 2),
        ("CURLPX_CLOSED", 3),
        ("CURLPX_GSSAPI", 4),
        ("CURLPX_GSSAPI_PERMSG", 5),
        ("CURLPX_GSSAPI_PROTECTION", 6),
        ("CURLPX_IDENTD", 7),
        ("CURLPX_IDENTD_DIFFER", 8),
        ("CURLPX_LONG_HOSTNAME", 9),
        ("CURLPX_LONG_PASSWD", 10),
        ("CURLPX_LONG_USER", 11),
        ("CURLPX_NO_AUTH", 12),
        ("CURLPX_RECV_ADDRESS", 13),
        ("CURLPX_RECV_AUTH", 14),
        ("CURLPX_RECV_CONNECT", 15),
        ("CURLPX_RECV_REQACK", 16),
        ("CURLPX_REPLY_ADDRESS_TYPE_NOT_SUPPORTED", 17),
        ("CURLPX_REPLY_COMMAND_NOT_SUPPORTED", 18),
        ("CURLPX_REPLY_CONNECTION_REFUSED", 19),
        ("CURLPX_REPLY_GENERAL_SERVER_FAILURE", 20),
        ("CURLPX_REPLY_HOST_UNREACHABLE", 21),
        ("CURLPX_REPLY_NETWORK_UNREACHABLE", 22),
        ("CURLPX_REPLY_NOT_ALLOWED", 23),
        ("CURLPX_REPLY_TTL_EXPIRED", 24),
        ("CURLPX_REPLY_UNASSIGNED", 25),
        ("CURLPX_REQUEST_FAILED", 26),
        ("CURLPX_RESOLVE_HOST", 27),
        ("CURLPX_SEND_AUTH", 28),
        ("CURLPX_SEND_CONNECT", 29),
        ("CURLPX_SEND_REQUEST", 30),
        ("CURLPX_UNKNOWN_FAIL", 31),
        ("CURLPX_UNKNOWN_MODE", 32),
        ("CURLPX_USER_REJECTED", 33),
        ("CURLPX_LAST", 34),
    ];

    /// The C identifier, which is also this member's Rust identifier.
    ///
    /// An exhaustive `match` rather than a lookup keyed on the value, so
    /// it stays correct without depending on the set being contiguous.
    #[allow(dead_code)]
    pub(crate) const fn c_name(self) -> &'static str {
        match self {
            Self::CURLPX_OK => "CURLPX_OK",
            Self::CURLPX_BAD_ADDRESS_TYPE => "CURLPX_BAD_ADDRESS_TYPE",
            Self::CURLPX_BAD_VERSION => "CURLPX_BAD_VERSION",
            Self::CURLPX_CLOSED => "CURLPX_CLOSED",
            Self::CURLPX_GSSAPI => "CURLPX_GSSAPI",
            Self::CURLPX_GSSAPI_PERMSG => "CURLPX_GSSAPI_PERMSG",
            Self::CURLPX_GSSAPI_PROTECTION => "CURLPX_GSSAPI_PROTECTION",
            Self::CURLPX_IDENTD => "CURLPX_IDENTD",
            Self::CURLPX_IDENTD_DIFFER => "CURLPX_IDENTD_DIFFER",
            Self::CURLPX_LONG_HOSTNAME => "CURLPX_LONG_HOSTNAME",
            Self::CURLPX_LONG_PASSWD => "CURLPX_LONG_PASSWD",
            Self::CURLPX_LONG_USER => "CURLPX_LONG_USER",
            Self::CURLPX_NO_AUTH => "CURLPX_NO_AUTH",
            Self::CURLPX_RECV_ADDRESS => "CURLPX_RECV_ADDRESS",
            Self::CURLPX_RECV_AUTH => "CURLPX_RECV_AUTH",
            Self::CURLPX_RECV_CONNECT => "CURLPX_RECV_CONNECT",
            Self::CURLPX_RECV_REQACK => "CURLPX_RECV_REQACK",
            Self::CURLPX_REPLY_ADDRESS_TYPE_NOT_SUPPORTED => {
                "CURLPX_REPLY_ADDRESS_TYPE_NOT_SUPPORTED"
            }
            Self::CURLPX_REPLY_COMMAND_NOT_SUPPORTED => {
                "CURLPX_REPLY_COMMAND_NOT_SUPPORTED"
            }
            Self::CURLPX_REPLY_CONNECTION_REFUSED => {
                "CURLPX_REPLY_CONNECTION_REFUSED"
            }
            Self::CURLPX_REPLY_GENERAL_SERVER_FAILURE => {
                "CURLPX_REPLY_GENERAL_SERVER_FAILURE"
            }
            Self::CURLPX_REPLY_HOST_UNREACHABLE => {
                "CURLPX_REPLY_HOST_UNREACHABLE"
            }
            Self::CURLPX_REPLY_NETWORK_UNREACHABLE => {
                "CURLPX_REPLY_NETWORK_UNREACHABLE"
            }
            Self::CURLPX_REPLY_NOT_ALLOWED => "CURLPX_REPLY_NOT_ALLOWED",
            Self::CURLPX_REPLY_TTL_EXPIRED => "CURLPX_REPLY_TTL_EXPIRED",
            Self::CURLPX_REPLY_UNASSIGNED => "CURLPX_REPLY_UNASSIGNED",
            Self::CURLPX_REQUEST_FAILED => "CURLPX_REQUEST_FAILED",
            Self::CURLPX_RESOLVE_HOST => "CURLPX_RESOLVE_HOST",
            Self::CURLPX_SEND_AUTH => "CURLPX_SEND_AUTH",
            Self::CURLPX_SEND_CONNECT => "CURLPX_SEND_CONNECT",
            Self::CURLPX_SEND_REQUEST => "CURLPX_SEND_REQUEST",
            Self::CURLPX_UNKNOWN_FAIL => "CURLPX_UNKNOWN_FAIL",
            Self::CURLPX_UNKNOWN_MODE => "CURLPX_UNKNOWN_MODE",
            Self::CURLPX_USER_REJECTED => "CURLPX_USER_REJECTED",
            Self::CURLPX_LAST => "CURLPX_LAST",
        }
    }

    /// The pinned discriminant, for handing back across the ABI.
    #[allow(dead_code)]
    pub(crate) const fn as_c_int(self) -> i32 {
        self as i32
    }

    /// The member with this discriminant, or `None` if C handed over a
    /// value this enumeration does not define.
    ///
    /// A C caller can pass any `int`. Returning `None` rather than
    /// transmuting keeps an out-of-range value from becoming an invalid
    /// enum, which would be undefined behaviour.
    #[allow(dead_code)]
    pub(crate) const fn from_c_int(raw: i32) -> Option<Self> {
        match raw {
            0 => Some(Self::CURLPX_OK),
            1 => Some(Self::CURLPX_BAD_ADDRESS_TYPE),
            2 => Some(Self::CURLPX_BAD_VERSION),
            3 => Some(Self::CURLPX_CLOSED),
            4 => Some(Self::CURLPX_GSSAPI),
            5 => Some(Self::CURLPX_GSSAPI_PERMSG),
            6 => Some(Self::CURLPX_GSSAPI_PROTECTION),
            7 => Some(Self::CURLPX_IDENTD),
            8 => Some(Self::CURLPX_IDENTD_DIFFER),
            9 => Some(Self::CURLPX_LONG_HOSTNAME),
            10 => Some(Self::CURLPX_LONG_PASSWD),
            11 => Some(Self::CURLPX_LONG_USER),
            12 => Some(Self::CURLPX_NO_AUTH),
            13 => Some(Self::CURLPX_RECV_ADDRESS),
            14 => Some(Self::CURLPX_RECV_AUTH),
            15 => Some(Self::CURLPX_RECV_CONNECT),
            16 => Some(Self::CURLPX_RECV_REQACK),
            17 => Some(Self::CURLPX_REPLY_ADDRESS_TYPE_NOT_SUPPORTED),
            18 => Some(Self::CURLPX_REPLY_COMMAND_NOT_SUPPORTED),
            19 => Some(Self::CURLPX_REPLY_CONNECTION_REFUSED),
            20 => Some(Self::CURLPX_REPLY_GENERAL_SERVER_FAILURE),
            21 => Some(Self::CURLPX_REPLY_HOST_UNREACHABLE),
            22 => Some(Self::CURLPX_REPLY_NETWORK_UNREACHABLE),
            23 => Some(Self::CURLPX_REPLY_NOT_ALLOWED),
            24 => Some(Self::CURLPX_REPLY_TTL_EXPIRED),
            25 => Some(Self::CURLPX_REPLY_UNASSIGNED),
            26 => Some(Self::CURLPX_REQUEST_FAILED),
            27 => Some(Self::CURLPX_RESOLVE_HOST),
            28 => Some(Self::CURLPX_SEND_AUTH),
            29 => Some(Self::CURLPX_SEND_CONNECT),
            30 => Some(Self::CURLPX_SEND_REQUEST),
            31 => Some(Self::CURLPX_UNKNOWN_FAIL),
            32 => Some(Self::CURLPX_UNKNOWN_MODE),
            33 => Some(Self::CURLPX_USER_REJECTED),
            34 => Some(Self::CURLPX_LAST),
            _ => None,
        }
    }
}

/// The TLS backend identifiers `curl_global_sslset` reports and selects.
///
/// Transcribed from `include/curl/curl.h:151-167`.
///
/// `CURLSSLBACKEND_RUSTLS` = 14 already existed in the frozen header, so
/// this implementation reports its backend without inventing a value. The
/// seven deprecated members and `CURLSSLBACKEND_OBSOLETE4` are reproduced
/// because a consumer may still name them and because removing one would
/// renumber the rest.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum curl_sslbackend {
    CURLSSLBACKEND_NONE = 0,
    CURLSSLBACKEND_OPENSSL = 1,
    CURLSSLBACKEND_GNUTLS = 2,
    /// Deprecated since 8.3.0.
    CURLSSLBACKEND_NSS = 3,
    /// Was QSOSSL.
    CURLSSLBACKEND_OBSOLETE4 = 4,
    /// Deprecated since 8.3.0.
    CURLSSLBACKEND_GSKIT = 5,
    /// Deprecated since 7.69.0.
    CURLSSLBACKEND_POLARSSL = 6,
    CURLSSLBACKEND_WOLFSSL = 7,
    CURLSSLBACKEND_SCHANNEL = 8,
    /// Deprecated since 8.15.0.
    CURLSSLBACKEND_SECURETRANSPORT = 9,
    /// Deprecated since 7.61.0.
    CURLSSLBACKEND_AXTLS = 10,
    CURLSSLBACKEND_MBEDTLS = 11,
    /// Deprecated since 7.82.0.
    CURLSSLBACKEND_MESALINK = 12,
    /// Deprecated since 8.15.0.
    CURLSSLBACKEND_BEARSSL = 13,
    CURLSSLBACKEND_RUSTLS = 14,
}

impl curl_sslbackend {
    /// Every member as `(C identifier, value)`, in declaration order.
    ///
    /// The single place the tests read, so neither the comparison against
    /// the frozen header nor the one against the engine needs a
    /// hand-maintained list that could drift on its own.
    #[allow(dead_code)]
    pub(crate) const ABI_VARIANTS: &'static [(&'static str, i32)] = &[
        ("CURLSSLBACKEND_NONE", 0),
        ("CURLSSLBACKEND_OPENSSL", 1),
        ("CURLSSLBACKEND_GNUTLS", 2),
        ("CURLSSLBACKEND_NSS", 3),
        ("CURLSSLBACKEND_OBSOLETE4", 4),
        ("CURLSSLBACKEND_GSKIT", 5),
        ("CURLSSLBACKEND_POLARSSL", 6),
        ("CURLSSLBACKEND_WOLFSSL", 7),
        ("CURLSSLBACKEND_SCHANNEL", 8),
        ("CURLSSLBACKEND_SECURETRANSPORT", 9),
        ("CURLSSLBACKEND_AXTLS", 10),
        ("CURLSSLBACKEND_MBEDTLS", 11),
        ("CURLSSLBACKEND_MESALINK", 12),
        ("CURLSSLBACKEND_BEARSSL", 13),
        ("CURLSSLBACKEND_RUSTLS", 14),
    ];

    /// The C identifier, which is also this member's Rust identifier.
    ///
    /// An exhaustive `match` rather than a lookup keyed on the value, so
    /// it stays correct without depending on the set being contiguous.
    #[allow(dead_code)]
    pub(crate) const fn c_name(self) -> &'static str {
        match self {
            Self::CURLSSLBACKEND_NONE => "CURLSSLBACKEND_NONE",
            Self::CURLSSLBACKEND_OPENSSL => "CURLSSLBACKEND_OPENSSL",
            Self::CURLSSLBACKEND_GNUTLS => "CURLSSLBACKEND_GNUTLS",
            Self::CURLSSLBACKEND_NSS => "CURLSSLBACKEND_NSS",
            Self::CURLSSLBACKEND_OBSOLETE4 => "CURLSSLBACKEND_OBSOLETE4",
            Self::CURLSSLBACKEND_GSKIT => "CURLSSLBACKEND_GSKIT",
            Self::CURLSSLBACKEND_POLARSSL => "CURLSSLBACKEND_POLARSSL",
            Self::CURLSSLBACKEND_WOLFSSL => "CURLSSLBACKEND_WOLFSSL",
            Self::CURLSSLBACKEND_SCHANNEL => "CURLSSLBACKEND_SCHANNEL",
            Self::CURLSSLBACKEND_SECURETRANSPORT => {
                "CURLSSLBACKEND_SECURETRANSPORT"
            }
            Self::CURLSSLBACKEND_AXTLS => "CURLSSLBACKEND_AXTLS",
            Self::CURLSSLBACKEND_MBEDTLS => "CURLSSLBACKEND_MBEDTLS",
            Self::CURLSSLBACKEND_MESALINK => "CURLSSLBACKEND_MESALINK",
            Self::CURLSSLBACKEND_BEARSSL => "CURLSSLBACKEND_BEARSSL",
            Self::CURLSSLBACKEND_RUSTLS => "CURLSSLBACKEND_RUSTLS",
        }
    }

    /// The pinned discriminant, for handing back across the ABI.
    #[allow(dead_code)]
    pub(crate) const fn as_c_int(self) -> i32 {
        self as i32
    }

    /// The member with this discriminant, or `None` if C handed over a
    /// value this enumeration does not define.
    ///
    /// A C caller can pass any `int`. Returning `None` rather than
    /// transmuting keeps an out-of-range value from becoming an invalid
    /// enum, which would be undefined behaviour.
    #[allow(dead_code)]
    pub(crate) const fn from_c_int(raw: i32) -> Option<Self> {
        match raw {
            0 => Some(Self::CURLSSLBACKEND_NONE),
            1 => Some(Self::CURLSSLBACKEND_OPENSSL),
            2 => Some(Self::CURLSSLBACKEND_GNUTLS),
            3 => Some(Self::CURLSSLBACKEND_NSS),
            4 => Some(Self::CURLSSLBACKEND_OBSOLETE4),
            5 => Some(Self::CURLSSLBACKEND_GSKIT),
            6 => Some(Self::CURLSSLBACKEND_POLARSSL),
            7 => Some(Self::CURLSSLBACKEND_WOLFSSL),
            8 => Some(Self::CURLSSLBACKEND_SCHANNEL),
            9 => Some(Self::CURLSSLBACKEND_SECURETRANSPORT),
            10 => Some(Self::CURLSSLBACKEND_AXTLS),
            11 => Some(Self::CURLSSLBACKEND_MBEDTLS),
            12 => Some(Self::CURLSSLBACKEND_MESALINK),
            13 => Some(Self::CURLSSLBACKEND_BEARSSL),
            14 => Some(Self::CURLSSLBACKEND_RUSTLS),
            _ => None,
        }
    }
}

/// The return set of `curl_global_sslset`.
///
/// Transcribed from `include/curl/curl.h:2831-2836`.
///
/// `CURLSSLSET_TOO_LATE` distinguishes a valid backend requested after
/// initialization from an unknown one, so a caller can tell a misordered
/// call from a misspelled backend.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CURLsslset {
    CURLSSLSET_OK = 0,
    CURLSSLSET_UNKNOWN_BACKEND = 1,
    CURLSSLSET_TOO_LATE = 2,
    /// libcurl was built without any SSL support
    CURLSSLSET_NO_BACKENDS = 3,
}

impl CURLsslset {
    /// Every member as `(C identifier, value)`, in declaration order.
    ///
    /// The single place the tests read, so neither the comparison against
    /// the frozen header nor the one against the engine needs a
    /// hand-maintained list that could drift on its own.
    #[allow(dead_code)]
    pub(crate) const ABI_VARIANTS: &'static [(&'static str, i32)] = &[
        ("CURLSSLSET_OK", 0),
        ("CURLSSLSET_UNKNOWN_BACKEND", 1),
        ("CURLSSLSET_TOO_LATE", 2),
        ("CURLSSLSET_NO_BACKENDS", 3),
    ];

    /// The C identifier, which is also this member's Rust identifier.
    ///
    /// An exhaustive `match` rather than a lookup keyed on the value, so
    /// it stays correct without depending on the set being contiguous.
    #[allow(dead_code)]
    pub(crate) const fn c_name(self) -> &'static str {
        match self {
            Self::CURLSSLSET_OK => "CURLSSLSET_OK",
            Self::CURLSSLSET_UNKNOWN_BACKEND => "CURLSSLSET_UNKNOWN_BACKEND",
            Self::CURLSSLSET_TOO_LATE => "CURLSSLSET_TOO_LATE",
            Self::CURLSSLSET_NO_BACKENDS => "CURLSSLSET_NO_BACKENDS",
        }
    }

    /// The pinned discriminant, for handing back across the ABI.
    #[allow(dead_code)]
    pub(crate) const fn as_c_int(self) -> i32 {
        self as i32
    }

    /// The member with this discriminant, or `None` if C handed over a
    /// value this enumeration does not define.
    ///
    /// A C caller can pass any `int`. Returning `None` rather than
    /// transmuting keeps an out-of-range value from becoming an invalid
    /// enum, which would be undefined behaviour.
    #[allow(dead_code)]
    pub(crate) const fn from_c_int(raw: i32) -> Option<Self> {
        match raw {
            0 => Some(Self::CURLSSLSET_OK),
            1 => Some(Self::CURLSSLSET_UNKNOWN_BACKEND),
            2 => Some(Self::CURLSSLSET_TOO_LATE),
            3 => Some(Self::CURLSSLSET_NO_BACKENDS),
            _ => None,
        }
    }
}

/// The `curl_version_info` struct ages.
///
/// Transcribed from `include/curl/curl.h:3088-3102`.
///
/// Each member marks the release that added fields to
/// `curl_version_info_data`, so a consumer built against an older header
/// can tell which trailing fields are present. `CURLVERSION_LAST` = 12 is
/// annotated "never actually use this" in the frozen header and is declared
/// here only because the header declares it.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CURLversion {
    /// 7.10
    CURLVERSION_FIRST = 0,
    /// 7.11.1
    CURLVERSION_SECOND = 1,
    /// 7.12.0
    CURLVERSION_THIRD = 2,
    /// 7.16.1
    CURLVERSION_FOURTH = 3,
    /// 7.57.0
    CURLVERSION_FIFTH = 4,
    /// 7.66.0
    CURLVERSION_SIXTH = 5,
    /// 7.70.0
    CURLVERSION_SEVENTH = 6,
    /// 7.72.0
    CURLVERSION_EIGHTH = 7,
    /// 7.75.0
    CURLVERSION_NINTH = 8,
    /// 7.77.0
    CURLVERSION_TENTH = 9,
    /// 7.87.0
    CURLVERSION_ELEVENTH = 10,
    /// 8.8.0
    CURLVERSION_TWELFTH = 11,
    /// never actually use this
    CURLVERSION_LAST = 12,
}

impl CURLversion {
    /// Every member as `(C identifier, value)`, in declaration order.
    ///
    /// The single place the tests read, so neither the comparison against
    /// the frozen header nor the one against the engine needs a
    /// hand-maintained list that could drift on its own.
    #[allow(dead_code)]
    pub(crate) const ABI_VARIANTS: &'static [(&'static str, i32)] = &[
        ("CURLVERSION_FIRST", 0),
        ("CURLVERSION_SECOND", 1),
        ("CURLVERSION_THIRD", 2),
        ("CURLVERSION_FOURTH", 3),
        ("CURLVERSION_FIFTH", 4),
        ("CURLVERSION_SIXTH", 5),
        ("CURLVERSION_SEVENTH", 6),
        ("CURLVERSION_EIGHTH", 7),
        ("CURLVERSION_NINTH", 8),
        ("CURLVERSION_TENTH", 9),
        ("CURLVERSION_ELEVENTH", 10),
        ("CURLVERSION_TWELFTH", 11),
        ("CURLVERSION_LAST", 12),
    ];

    /// The C identifier, which is also this member's Rust identifier.
    ///
    /// An exhaustive `match` rather than a lookup keyed on the value, so
    /// it stays correct without depending on the set being contiguous.
    #[allow(dead_code)]
    pub(crate) const fn c_name(self) -> &'static str {
        match self {
            Self::CURLVERSION_FIRST => "CURLVERSION_FIRST",
            Self::CURLVERSION_SECOND => "CURLVERSION_SECOND",
            Self::CURLVERSION_THIRD => "CURLVERSION_THIRD",
            Self::CURLVERSION_FOURTH => "CURLVERSION_FOURTH",
            Self::CURLVERSION_FIFTH => "CURLVERSION_FIFTH",
            Self::CURLVERSION_SIXTH => "CURLVERSION_SIXTH",
            Self::CURLVERSION_SEVENTH => "CURLVERSION_SEVENTH",
            Self::CURLVERSION_EIGHTH => "CURLVERSION_EIGHTH",
            Self::CURLVERSION_NINTH => "CURLVERSION_NINTH",
            Self::CURLVERSION_TENTH => "CURLVERSION_TENTH",
            Self::CURLVERSION_ELEVENTH => "CURLVERSION_ELEVENTH",
            Self::CURLVERSION_TWELFTH => "CURLVERSION_TWELFTH",
            Self::CURLVERSION_LAST => "CURLVERSION_LAST",
        }
    }

    /// The pinned discriminant, for handing back across the ABI.
    #[allow(dead_code)]
    pub(crate) const fn as_c_int(self) -> i32 {
        self as i32
    }

    /// The member with this discriminant, or `None` if C handed over a
    /// value this enumeration does not define.
    ///
    /// A C caller can pass any `int`. Returning `None` rather than
    /// transmuting keeps an out-of-range value from becoming an invalid
    /// enum, which would be undefined behaviour.
    #[allow(dead_code)]
    pub(crate) const fn from_c_int(raw: i32) -> Option<Self> {
        match raw {
            0 => Some(Self::CURLVERSION_FIRST),
            1 => Some(Self::CURLVERSION_SECOND),
            2 => Some(Self::CURLVERSION_THIRD),
            3 => Some(Self::CURLVERSION_FOURTH),
            4 => Some(Self::CURLVERSION_FIFTH),
            5 => Some(Self::CURLVERSION_SIXTH),
            6 => Some(Self::CURLVERSION_SEVENTH),
            7 => Some(Self::CURLVERSION_EIGHTH),
            8 => Some(Self::CURLVERSION_NINTH),
            9 => Some(Self::CURLVERSION_TENTH),
            10 => Some(Self::CURLVERSION_ELEVENTH),
            11 => Some(Self::CURLVERSION_TWELFTH),
            12 => Some(Self::CURLVERSION_LAST),
            _ => None,
        }
    }
}

impl From<EngineVersion> for CURLversion {
    /// Total: one arm per engine age, checked exhaustive.
    ///
    /// This direction is total because the engine declares only real ages and
    /// each has an ABI member. The reverse cannot be, which is why it is
    /// [`CURLversion::to_engine`] rather than a second `From`.
    fn from(age: EngineVersion) -> Self {
        match age {
            EngineVersion::First => Self::CURLVERSION_FIRST,
            EngineVersion::Second => Self::CURLVERSION_SECOND,
            EngineVersion::Third => Self::CURLVERSION_THIRD,
            EngineVersion::Fourth => Self::CURLVERSION_FOURTH,
            EngineVersion::Fifth => Self::CURLVERSION_FIFTH,
            EngineVersion::Sixth => Self::CURLVERSION_SIXTH,
            EngineVersion::Seventh => Self::CURLVERSION_SEVENTH,
            EngineVersion::Eighth => Self::CURLVERSION_EIGHTH,
            EngineVersion::Ninth => Self::CURLVERSION_NINTH,
            EngineVersion::Tenth => Self::CURLVERSION_TENTH,
            EngineVersion::Eleventh => Self::CURLVERSION_ELEVENTH,
            EngineVersion::Twelfth => Self::CURLVERSION_TWELFTH,
        }
    }
}

impl CURLversion {
    /// The engine age this ABI member names, or `None` for the sentinel.
    ///
    /// `CURLVERSION_LAST` is the one input with no answer. The frozen header
    /// annotates it "never actually use this" and the engine deliberately does
    /// not make it constructible, so there is no engine value to return and
    /// inventing one would defeat that decision. An `Option` states the gap in
    /// the type instead of hiding it behind a panic or a wrong age.
    #[allow(dead_code)]
    pub(crate) const fn to_engine(self) -> Option<EngineVersion> {
        match self {
            Self::CURLVERSION_FIRST => Some(EngineVersion::First),
            Self::CURLVERSION_SECOND => Some(EngineVersion::Second),
            Self::CURLVERSION_THIRD => Some(EngineVersion::Third),
            Self::CURLVERSION_FOURTH => Some(EngineVersion::Fourth),
            Self::CURLVERSION_FIFTH => Some(EngineVersion::Fifth),
            Self::CURLVERSION_SIXTH => Some(EngineVersion::Sixth),
            Self::CURLVERSION_SEVENTH => Some(EngineVersion::Seventh),
            Self::CURLVERSION_EIGHTH => Some(EngineVersion::Eighth),
            Self::CURLVERSION_NINTH => Some(EngineVersion::Ninth),
            Self::CURLVERSION_TENTH => Some(EngineVersion::Tenth),
            Self::CURLVERSION_ELEVENTH => Some(EngineVersion::Eleventh),
            Self::CURLVERSION_TWELFTH => Some(EngineVersion::Twelfth),
            Self::CURLVERSION_LAST => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every enumeration this module declares, for the checks that apply to
    /// all of them. A type missing from this table is a type nothing below
    /// covers, so the length is asserted too.
    const ALL: &[(&str, &[(&str, i32)])] = &[
        ("CURLcode", CURLcode::ABI_VARIANTS),
        ("CURLMcode", CURLMcode::ABI_VARIANTS),
        ("CURLUcode", CURLUcode::ABI_VARIANTS),
        ("CURLHcode", CURLHcode::ABI_VARIANTS),
        ("CURLSHcode", CURLSHcode::ABI_VARIANTS),
        ("CURLSHoption", CURLSHoption::ABI_VARIANTS),
        ("CURLSTScode", CURLSTScode::ABI_VARIANTS),
        ("CURLproxycode", CURLproxycode::ABI_VARIANTS),
        ("curl_sslbackend", curl_sslbackend::ABI_VARIANTS),
        ("CURLsslset", CURLsslset::ABI_VARIANTS),
        ("CURLversion", CURLversion::ABI_VARIANTS),
    ];

    #[test]
    fn the_table_covers_every_declared_enumeration() {
        assert_eq!(
            ALL.len(),
            11,
            "an enumeration was declared without a matching test entry"
        );
        let mut names: Vec<&str> = ALL.iter().map(|(n, _)| *n).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "duplicate entry in the table");
    }

    #[test]
    fn every_enumeration_is_contiguous_and_in_declaration_order() {
        // Contiguity is not cosmetic. The frozen header leaves almost every
        // value implicit, so a gap here would mean a member was dropped and
        // every later member silently renumbered. It is also what makes the
        // compiler catch a single-value edit as a duplicate discriminant.
        for (name, table) in ALL {
            assert!(!table.is_empty(), "{name} declares no members");
            let first = table[0].1;
            for (index, (member, value)) in table.iter().enumerate() {
                let expected = first + index as i32;
                assert_eq!(
                    *value, expected,
                    "{name}::{member} is {value}, expected {expected}: the set \
                     is not contiguous from {first}"
                );
            }
        }
    }

    /// Assert one enumeration's shape: its table, its accessors, and its
    /// refusal of values it does not declare.
    ///
    /// A macro rather than a function because each enumeration is a separate
    /// type; dispatching on a name string would test the dispatcher instead.
    /// Test-only code is invisible to cbindgen, so a macro is free here.
    macro_rules! check_shape {
        ($t:ty) => {{
            for &(member, value) in <$t>::ABI_VARIANTS {
                let recovered = <$t>::from_c_int(value).unwrap_or_else(|| {
                    panic!("{member} = {value} is not recoverable from its value")
                });
                assert_eq!(recovered.c_name(), member, "identity of {member}");
                assert_eq!(recovered.as_c_int(), value, "value of {member}");
            }
            // C may hand over any int. One past each end must be refused
            // rather than transmuted into an invalid enum, which would be UB.
            let low = <$t>::ABI_VARIANTS[0].1;
            let high = <$t>::ABI_VARIANTS[<$t>::ABI_VARIANTS.len() - 1].1;
            assert!(<$t>::from_c_int(low - 1).is_none(), "accepted {}", low - 1);
            assert!(<$t>::from_c_int(high + 1).is_none(), "accepted {}", high + 1);
        }};
    }

    #[test]
    fn every_enumeration_has_a_consistent_shape() {
        check_shape!(CURLcode);
        check_shape!(CURLMcode);
        check_shape!(CURLUcode);
        check_shape!(CURLHcode);
        check_shape!(CURLSHcode);
        check_shape!(CURLSHoption);
        check_shape!(CURLSTScode);
        check_shape!(CURLproxycode);
        check_shape!(curl_sslbackend);
        check_shape!(CURLsslset);
        check_shape!(CURLversion);
    }

    /// Prove one bridge total in both directions and value-preserving.
    ///
    /// Equal cardinality, plus name-and-value preservation in both
    /// directions, plus round-trip identity, together leave no room for a
    /// mismatch: a member on one side only breaks cardinality, and a member
    /// mapped to the wrong counterpart breaks identity.
    macro_rules! check_bridge {
        ($abi:ty, $engine:ty) => {{
            assert_eq!(
                <$abi>::ABI_VARIANTS.len(),
                <$engine>::VARIANTS.len(),
                "the two declarations have different numbers of members"
            );
            for &(member, value) in <$abi>::ABI_VARIANTS {
                let abi = <$abi>::from_c_int(value).expect("declared value");
                let engine: $engine = abi.into();
                assert_eq!(engine.as_i32(), value, "bridge moved {member}");
                assert_eq!(engine.c_name(), member, "bridge renamed {member}");
                let back: $abi = engine.into();
                assert_eq!(back, abi, "round trip lost {member}");
            }
            for engine in <$engine>::VARIANTS {
                let abi: $abi = (*engine).into();
                assert_eq!(abi.as_c_int(), engine.as_i32());
                assert_eq!(abi.c_name(), engine.c_name());
                let back: $engine = abi.into();
                assert_eq!(back, *engine);
            }
        }};
    }

    #[test]
    fn bridged_enumerations_match_the_engine_exactly() {
        // The independent cross-check: curl-rs-lib/src/error.rs was
        // transcribed from the same frozen header separately, so agreement
        // here means two independent transcriptions of one authority agree.
        check_bridge!(CURLcode, engine::CURLcode);
        check_bridge!(CURLMcode, engine::CURLMcode);
        check_bridge!(CURLUcode, engine::CURLUcode);
        check_bridge!(CURLHcode, engine::CURLHcode);
        check_bridge!(CURLSHcode, engine::CURLSHcode);
    }

    #[test]
    fn curlcode_anchors_hold_the_values_the_plan_names() {
        // Written out from the specification rather than derived from the
        // declaration above, so a coordinated edit to the declaration and its
        // generator still has to survive this comparison.
        assert_eq!(CURLcode::CURLE_OK as i32, 0);
        assert_eq!(CURLcode::CURLE_UNSUPPORTED_PROTOCOL as i32, 1);
        assert_eq!(CURLcode::CURLE_FAILED_INIT as i32, 2);
        assert_eq!(CURLcode::CURLE_URL_MALFORMAT as i32, 3);
        assert_eq!(CURLcode::CURLE_COULDNT_RESOLVE_HOST as i32, 6);
        assert_eq!(CURLcode::CURLE_COULDNT_CONNECT as i32, 7);
        assert_eq!(CURLcode::CURLE_OUT_OF_MEMORY as i32, 27);
        assert_eq!(CURLcode::CURLE_OPERATION_TIMEDOUT as i32, 28);
        assert_eq!(CURLcode::CURLE_SSL_CONNECT_ERROR as i32, 35);
        assert_eq!(CURLcode::CURLE_TOO_MANY_REDIRECTS as i32, 47);
        assert_eq!(CURLcode::CURLE_PEER_FAILED_VERIFICATION as i32, 60);
    }

    #[test]
    fn curlcode_obsolete_placeholders_hold_their_positions() {
        // These fifteen are never returned. They exist so that every later
        // code keeps its number, so their positions are the load-bearing part.
        let observed = [
            CURLcode::CURLE_OBSOLETE20 as i32,
            CURLcode::CURLE_OBSOLETE24 as i32,
            CURLcode::CURLE_OBSOLETE29 as i32,
            CURLcode::CURLE_OBSOLETE32 as i32,
            CURLcode::CURLE_OBSOLETE34 as i32,
            CURLcode::CURLE_OBSOLETE40 as i32,
            CURLcode::CURLE_OBSOLETE41 as i32,
            CURLcode::CURLE_OBSOLETE44 as i32,
            CURLcode::CURLE_OBSOLETE46 as i32,
            CURLcode::CURLE_OBSOLETE50 as i32,
            CURLcode::CURLE_OBSOLETE51 as i32,
            CURLcode::CURLE_OBSOLETE57 as i32,
            CURLcode::CURLE_OBSOLETE62 as i32,
            CURLcode::CURLE_OBSOLETE75 as i32,
            CURLcode::CURLE_OBSOLETE76 as i32,
        ];
        let expected =
            [20, 24, 29, 32, 34, 40, 41, 44, 46, 50, 51, 57, 62, 75, 76];
        assert_eq!(
            observed, expected,
            "an obsolete placeholder moved: every \
                                        later code is now wrong"
        );
        // And these really are all of them, so none was missed.
        let counted = CURLcode::ABI_VARIANTS
            .iter()
            .filter(|(member, _)| member.starts_with("CURLE_OBSOLETE"))
            .count();
        assert_eq!(counted, 15, "the obsolete set changed size");
    }

    #[test]
    fn curlcode_bounds_are_a_sentinel_and_a_real_error() {
        assert_eq!(CURLcode::CURL_LAST as i32, 102, "the bound moved");
        assert_eq!(
            CURLcode::CURLE_ECH_REQUIRED as i32,
            101,
            "the highest real error moved"
        );
        assert_eq!(CURLcode::ABI_VARIANTS.len(), 103);
    }

    #[test]
    fn curlmcode_is_the_only_enumeration_starting_below_zero() {
        for (name, table) in ALL {
            let first = table[0].1;
            if *name == "CURLMcode" {
                assert_eq!(first, -1, "CURLM_CALL_MULTI_PERFORM must stay -1");
            } else {
                assert_eq!(first, 0, "{name} starts at {first}, expected 0");
            }
        }
    }

    #[test]
    fn rustls_is_backend_fourteen() {
        // The value already existed in the frozen header, so reporting a
        // rustls backend needs no invented enumerant. Moving it would make
        // curl_global_sslset disagree with every consumer compiled before.
        assert_eq!(curl_sslbackend::CURLSSLBACKEND_RUSTLS as i32, 14);
        assert_eq!(curl_sslbackend::CURLSSLBACKEND_NONE as i32, 0);
        assert_eq!(curl_sslbackend::ABI_VARIANTS.len(), 15);
    }

    #[test]
    fn curlversion_covers_the_engine_and_adds_only_the_sentinel() {
        assert_eq!(
            CURLversion::ABI_VARIANTS.len(),
            EngineVersion::VARIANTS.len() + 1,
            "the ABI must declare exactly the engine ages plus CURLVERSION_LAST"
        );
        for engine in EngineVersion::VARIANTS {
            let abi: CURLversion = (*engine).into();
            assert_eq!(abi.as_c_int(), engine.as_c_int());
            assert_eq!(abi.c_name(), engine.c_name());
            assert_eq!(
                abi.to_engine(),
                Some(*engine),
                "{} did not round trip",
                engine.c_name()
            );
        }
        // The sentinel is the one member with no engine counterpart, and
        // to_engine must say so rather than guess an age.
        assert_eq!(CURLversion::CURLVERSION_LAST.to_engine(), None);
        assert_eq!(
            CURLversion::CURLVERSION_LAST as i32,
            EngineVersion::LAST,
            "the ABI sentinel and the engine bound disagree"
        );
    }

    #[test]
    fn header_only_enumerations_keep_their_documented_bounds() {
        // No engine counterpart exists to cross-check these against, so their
        // endpoints are pinned straight against the frozen header.
        assert_eq!(CURLSHoption::CURLSHOPT_NONE as i32, 0);
        assert_eq!(CURLSHoption::CURLSHOPT_LAST as i32, 6);
        assert_eq!(CURLSTScode::CURLSTS_OK as i32, 0);
        assert_eq!(CURLSTScode::CURLSTS_DONE as i32, 1);
        assert_eq!(CURLSTScode::CURLSTS_FAIL as i32, 2);
        assert_eq!(CURLproxycode::CURLPX_OK as i32, 0);
        assert_eq!(CURLproxycode::CURLPX_LAST as i32, 34);
        assert_eq!(CURLsslset::CURLSSLSET_OK as i32, 0);
        assert_eq!(CURLsslset::CURLSSLSET_UNKNOWN_BACKEND as i32, 1);
        assert_eq!(CURLsslset::CURLSSLSET_TOO_LATE as i32, 2);
        assert_eq!(CURLsslset::CURLSSLSET_NO_BACKENDS as i32, 3);
    }

    #[test]
    fn total_member_count_is_what_the_headers_declare() {
        // One number that moves if any transcription gains or loses a member.
        let total: usize = ALL.iter().map(|(_, table)| table.len()).sum();
        assert_eq!(total, 243, "the declared member count changed");
    }
}
