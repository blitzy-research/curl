// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! `CURLoption` identity and the `curl_easyoption` metadata authority.
//!
//! This module is the SOLE source of truth for option identity. AAP 0.1.2
//! is explicit about why a second population is not acceptable: "If those
//! are populated from two places, they will drift, and the drift will be
//! invisible until a consumer queries an option by name and receives the
//! wrong identifier." Two independent consumers read this data -- the
//! generated `include/curl/curl.h`, and the `curl_easy_option_by_name` /
//! `_by_id` / `_next` introspection API backed by `struct curl_easyoption`
//! (include/curl/options.h:51) -- so both are served from the tables
//! below and from nowhere else.
//!
//! # Why the integers are written out
//!
//! A C program compiled against curl 8.19.0-DEV embeds the NUMERIC value
//! of every option it names. Reproducing the names without the numbers
//! yields a library that links and then silently misbehaves. The frozen
//! header composes each value arithmetically,
//!
//! ```c
//! #define CURLOPT(na, t, nu) na = ((t) + (nu))
//! ```
//!
//! with the type bases pinned at `include/curl/curl.h:1111-1115` and
//! `:1127-1136`. Every value here is written explicitly rather than
//! recomputed, because an arithmetic slip in a base would move a whole
//! class of options at once and nothing would report it.
//!
//! # Measured reconciliation
//!
//! ```text
//! 291 CURLOPT(...) + 17 CURLOPTDEPRECATED(...) = 308 enum entries
//! CURLOPT_LASTENTRY = 10329;  10329 % 10000 = 329 = (328 + 1)
//! upstream Curl_easyopts[] = 324 rows
//!                          = 1 sentinel + 323 real
//!                          = 1 sentinel + 15 alias + 308 true options
//! ```
//!
//! The 308 true rows and the 308 enum entries are cross-checked against
//! each other by test. They come from two INDEPENDENT populations -- the
//! enum from the frozen header, the table from `lib/optiontable.pl` -- so
//! the check is a real bridge and not a tautology. `CURLoption` has no
//! counterpart in `curl-rs-lib`, deliberately: an unused mirror there
//! would be exactly the drifting second copy AAP 0.1.2 warns about.
//!
//! # What this module does NOT declare
//!
//! The `CURLOPTTYPE_*` bases and the `CURLOPT` / `CURLOPTDEPRECATED`
//! generator macros are pinned verbatim by the build script
//! (curl-rs-ffi/build.rs:1225, :1234-1235, :1250), so the Rust constants
//! for the bases are `pub(crate)`: making them `pub` would emit a second,
//! duplicate `#define` for each. `struct curl_easyoption` is likewise
//! verbatim (build.rs:849) because it is layout-visible.
//!
//! The 19 `#define CURLOPT_*` backward-compatibility aliases are NOT
//! emitted from here either, and that needs saying because
//! build.rs:1111 lists them alongside the enumeration. They cannot be:
//! the frozen header wraps them in `#ifndef CURL_NO_OLDIES` guards and
//! puts `#undef CURLOPT_DNS_USE_GLOBAL_CACHE` in the `#else` branch
//! (include/curl/curl.h:650-736, :2264-2295), and cbindgen emits no
//! preprocessor conditionals at all. Dropping the guards would change
//! observable behaviour for an application that defines
//! `CURL_NO_OLDIES`, which AAP 0.8.1 freezes. The guarded blocks are
//! therefore carried verbatim, and because every one of them expands to
//! an IDENTIFIER rather than a literal, they resolve THROUGH the
//! enumeration below and introduce no second population of values. The
//! alias -> target mapping is still held here, in [`OPTION_ALIASES`], and
//! asserted against the enumeration by test.
//!
//! # The identifier enumerations this module owns, and the four it does not
//!
//! The governing division is arithmetic rather than alphabetical: an
//! enumeration whose members are COMPOSED -- from the `CURLOPT(na, t, nu)`
//! macro, or from `CURLINFO_<BASE> + n` -- is option identity and belongs
//! here. An enumeration whose members are plain declaration ordinals is a
//! status, code or kind, and belongs to `ffi/codes.rs`. Four of the five
//! composed enumerations are therefore declared below: [`CURLoption`],
//! [`CURLINFO`], [`curl_easytype`] and [`CURLformoption`], together with
//! the [`EASY_OPTIONS`] metadata array, the nine `CURLOPTTYPE_*` bases,
//! the nine `CURLINFO_*` bases and the two `CURLOPT_WS_OPTIONS` argument
//! bits.
//!
//! Four types that a reader might expect here are deliberately absent, and
//! the reason is the same rule that put the rest here. `curl_easyoption`
//! (include/curl/options.h:51) is LAYOUT-visible -- a consumer reads its
//! fields through a returned pointer -- so it lives with the crate's other
//! `#[repr(C)]` layout types in `ffi/types.rs`, and `ffi/easy.rs` projects
//! this module's [`EasyOptionRow`] into it. `CURLMoption` and
//! `CURLMinfo_offt` are `ffi/types.rs`'s for the same reason they are
//! declared in `include/curl/multi.h` rather than `curl.h`: they belong to
//! the multi surface. `CURLSHoption` is `ffi/codes.rs`'s, its members being
//! bare ordinals.
//!
//! That split is not a matter of taste. Declaring `curl_easyoption` here as
//! well would give the crate two structurally identical but DISTINCT Rust
//! types for one C struct, and `ffi/easy.rs` would have to pick one -- the
//! second population this module exists to prevent, arriving by the back
//! door. It would also close a cycle, since this module would need
//! `ffi/types.rs` for the struct while `ffi/types.rs` needs this module for
//! nothing at all. The dependency runs one way, from `types` to `opts`
//! nowhere and from `easy` to both.
//!
//! # The `dead_code` allowances
//!
//! Several items below carry `#[allow(dead_code)]`. Every one of them is
//! exercised by this module's tests, but the plain `lib` target compiles
//! without `#[cfg(test)]` code, and the exported functions that will read
//! this data -- `curl_easy_setopt`, `curl_easy_getinfo`, `curl_multi_setopt`
//! and the `curl_form*` trio -- are not all landed yet. The allowances are
//! per ITEM rather than a blanket `#![allow(dead_code)]` on the module, so
//! each one disappears on its own as its consumer arrives and none of them
//! can mask an unrelated unused item in the meantime.

use core::ffi::{c_int, c_long, c_uint};

// Option type bases.
//
// `pub(crate)` is load-bearing. cbindgen would render a `pub` constant as
// a second `#define` for a name the verbatim prologue has already
// defined, and a duplicate `#define` with an identical body is a warning
// under `-Wall` in some consumers and an error under others.
//
// Four of the nine names are aliases in the frozen header
// (include/curl/curl.h:1127-1136) and are written here as aliases too,
// because that is what makes `curl_easytype` impossible to recover from
// `value / 10000`: three distinct bases share 10000.
#[allow(dead_code)]
pub(crate) const CURLOPTTYPE_LONG: i32 = 0;
#[allow(dead_code)]
pub(crate) const CURLOPTTYPE_OBJECTPOINT: i32 = 10000;
#[allow(dead_code)]
pub(crate) const CURLOPTTYPE_FUNCTIONPOINT: i32 = 20000;
#[allow(dead_code)]
pub(crate) const CURLOPTTYPE_OFF_T: i32 = 30000;
#[allow(dead_code)]
pub(crate) const CURLOPTTYPE_BLOB: i32 = 40000;

#[allow(dead_code)]
pub(crate) const CURLOPTTYPE_STRINGPOINT: i32 = CURLOPTTYPE_OBJECTPOINT;
#[allow(dead_code)]
pub(crate) const CURLOPTTYPE_SLISTPOINT: i32 = CURLOPTTYPE_OBJECTPOINT;
#[allow(dead_code)]
pub(crate) const CURLOPTTYPE_CBPOINT: i32 = CURLOPTTYPE_OBJECTPOINT;
#[allow(dead_code)]
pub(crate) const CURLOPTTYPE_VALUES: i32 = CURLOPTTYPE_LONG;

// Metadata types, emitted into `include/curl/options.h`.

/// The type of value a `CURLoption` takes, as reported by the
/// `curl_easy_option_*` introspection API.
/// Every member is implicit in the frozen header
/// (include/curl/options.h:31-41), so the values are the declaration
/// ordinals 0 through 8. They are written out here so that inserting a
/// member in the middle cannot silently renumber its successors.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
pub enum curl_easytype {
    /// long (a range of values)
    CURLOT_LONG = 0,
    /// (a defined set or bitmask)
    CURLOT_VALUES = 1,
    /// curl_off_t (a range of values)
    CURLOT_OFF_T = 2,
    /// pointer (void *)
    CURLOT_OBJECT = 3,
    /// (char * to null-terminated buffer)
    CURLOT_STRING = 4,
    /// (struct curl_slist *)
    CURLOT_SLIST = 5,
    /// (void * passed as-is to a callback)
    CURLOT_CBPTR = 6,
    /// blob (struct curl_blob *)
    CURLOT_BLOB = 7,
    /// function pointer
    CURLOT_FUNCTION = 8,
}

/// Flag bit marking a row that exists only so old programs keep working.
/// The frozen header defines it as `(1 << 0)` and it is the only flag bit
/// (include/curl/options.h:47).
#[allow(dead_code)]
pub const CURLOT_FLAG_ALIAS: c_uint = 1 << 0;

// The option enumeration, emitted into `include/curl/curl.h`.
//
// `cbindgen.toml:898` lists `CURLoption` under `[export] exclude`. AAP
// 0.1.2 overrides that, and `curl_h_export_exclusions` (build.rs:3101)
// lifts the one exclusion for the umbrella pass. The lift is recorded in
// `CURL_H_GENERATED_DESPITE_EXCLUSION` (build.rs:3144) so the divergence
// from the checked-in cbindgen configuration is deliberate and traceable
// rather than looking like a configuration bug.

/// Every `CURLOPT_*` identifier, with its integer pinned.
/// Values are NOT contiguous and are NOT ordered: the enumeration
/// interleaves five type bases, so a contiguity assertion of the kind
/// `ffi/codes.rs` uses would be wrong here. What is asserted instead is
/// that the values are unique, that each equals its base plus its ordinal,
/// and that the set matches the independently generated metadata table
/// exactly.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
pub enum CURLoption {
    /// This is the FILE * or void * the regular output should be written
    /// to.
    CURLOPT_WRITEDATA = 10001,
    /// The full URL to get/put
    CURLOPT_URL = 10002,
    /// Port number to connect to, if other than default.
    CURLOPT_PORT = 3,
    /// Name of proxy to use.
    CURLOPT_PROXY = 10004,
    /// "user:password;options" to use when fetching.
    CURLOPT_USERPWD = 10005,
    /// "user:password" to use with proxy.
    CURLOPT_PROXYUSERPWD = 10006,
    /// Range to get, specified as an ASCII string.
    CURLOPT_RANGE = 10007,
    /// Specified file stream to upload from (use as input):
    CURLOPT_READDATA = 10009,
    /// Buffer to receive error messages in, must be at least
    /// CURL_ERROR_SIZE bytes big.
    CURLOPT_ERRORBUFFER = 10010,
    /// Function that will be called to store the output (instead of
    /// fwrite). The parameters will use fwrite() syntax, make sure to
    /// follow them.
    CURLOPT_WRITEFUNCTION = 20011,
    /// Function that will be called to read the input (instead of fread).
    /// The parameters will use fread() syntax, make sure to follow them.
    CURLOPT_READFUNCTION = 20012,
    /// Time-out the read operation after this amount of seconds
    CURLOPT_TIMEOUT = 13,
    /// If CURLOPT_READDATA is used, this can be used to inform libcurl
    /// about how large the file being sent really is. That allows better
    /// error checking and better verifies that the upload was successful.
    /// -1 means unknown size. For large file support, there is also a
    /// _LARGE version of the key which takes an off_t type, allowing
    /// platforms with larger off_t sizes to handle larger files. See below
    /// for INFILESIZE_LARGE.
    CURLOPT_INFILESIZE = 14,
    /// POST static input fields.
    CURLOPT_POSTFIELDS = 10015,
    /// Set the referrer page (needed by some CGIs)
    CURLOPT_REFERER = 10016,
    /// Set the FTP PORT string (interface name, named or numerical IP
    /// address) Use i.e '-' to use default address.
    CURLOPT_FTPPORT = 10017,
    /// Set the User-Agent string (examined by some CGIs)
    CURLOPT_USERAGENT = 10018,
    /// Set the "low speed limit"
    CURLOPT_LOW_SPEED_LIMIT = 19,
    /// Set the "low speed time"
    CURLOPT_LOW_SPEED_TIME = 20,
    /// Set the continuation offset. Note there is also a _LARGE version of
    /// this key which uses off_t types, allowing for large file offsets on
    /// platforms which use larger-than-32-bit off_t's. Look below for
    /// RESUME_FROM_LARGE.
    CURLOPT_RESUME_FROM = 21,
    /// Set cookie in request:
    CURLOPT_COOKIE = 10022,
    /// This points to a linked list of headers, struct curl_slist kind.
    /// This list is also used for RTSP (in spite of its name)
    CURLOPT_HTTPHEADER = 10023,
    /// This points to a linked list of post entries, struct curl_httppost
    /// Deprecated since curl 7.56.0: Use CURLOPT_MIMEPOST.
    CURLOPT_HTTPPOST = 10024,
    /// name of the file keeping your private SSL-certificate
    CURLOPT_SSLCERT = 10025,
    /// password for the SSL or SSH private key
    CURLOPT_KEYPASSWD = 10026,
    /// send TYPE parameter?
    CURLOPT_CRLF = 27,
    /// send linked-list of QUOTE commands
    CURLOPT_QUOTE = 10028,
    /// send FILE * or void * to store headers to, if you use a callback it
    /// is simply passed to the callback unmodified
    CURLOPT_HEADERDATA = 10029,
    /// point to a file to read the initial cookies from, also enables
    /// "cookie awareness"
    CURLOPT_COOKIEFILE = 10031,
    /// What version to specifically try to use. See CURL_SSLVERSION defines
    /// below.
    CURLOPT_SSLVERSION = 32,
    /// What kind of HTTP time condition to use, see defines
    CURLOPT_TIMECONDITION = 33,
    /// Time to use with the above condition. Specified in number of seconds
    /// since 1 Jan 1970
    CURLOPT_TIMEVALUE = 34,
    CURLOPT_CUSTOMREQUEST = 10036,
    /// FILE handle to use instead of stderr
    CURLOPT_STDERR = 10037,
    /// send linked-list of post-transfer QUOTE commands
    CURLOPT_POSTQUOTE = 10039,
    /// talk a lot
    CURLOPT_VERBOSE = 41,
    /// throw the header out too
    CURLOPT_HEADER = 42,
    /// shut off the progress meter
    CURLOPT_NOPROGRESS = 43,
    /// use HEAD to get http document
    CURLOPT_NOBODY = 44,
    /// no output on http error codes >= 400
    CURLOPT_FAILONERROR = 45,
    /// this is an upload
    CURLOPT_UPLOAD = 46,
    /// HTTP POST method
    CURLOPT_POST = 47,
    /// bare names when listing directories
    CURLOPT_DIRLISTONLY = 48,
    /// Append instead of overwrite on upload!
    CURLOPT_APPEND = 50,
    /// Specify whether to read the user+password from the .netrc or the
    /// URL. This must be one of the CURL_NETRC_* enums below.
    CURLOPT_NETRC = 51,
    /// use Location: Luke!
    CURLOPT_FOLLOWLOCATION = 52,
    /// transfer data in text/ASCII format
    CURLOPT_TRANSFERTEXT = 53,
    /// HTTP PUT
    /// Deprecated since curl 7.12.1: Use CURLOPT_UPLOAD.
    CURLOPT_PUT = 54,
    /// DEPRECATED Function that will be called instead of the internal
    /// progress display function. This function should be defined as the
    /// curl_progress_callback prototype defines.
    /// Deprecated since curl 7.32.0: Use CURLOPT_XFERINFOFUNCTION.
    CURLOPT_PROGRESSFUNCTION = 20056,
    /// Data passed to the CURLOPT_PROGRESSFUNCTION and
    /// CURLOPT_XFERINFOFUNCTION callbacks
    CURLOPT_XFERINFODATA = 10057,
    /// We want the referrer field set automatically when following
    /// locations
    CURLOPT_AUTOREFERER = 58,
    /// Port of the proxy, can be set in the proxy string as well with:
    /// "[host]:[port]"
    CURLOPT_PROXYPORT = 59,
    /// size of the POST input data, if strlen() is not good to use
    CURLOPT_POSTFIELDSIZE = 60,
    /// tunnel non-http operations through an HTTP proxy
    CURLOPT_HTTPPROXYTUNNEL = 61,
    /// Set the interface string to use as outgoing network interface
    CURLOPT_INTERFACE = 10062,
    /// Set the krb4/5 security level, this also enables krb4/5 awareness.
    /// This is a string, 'clear', 'safe', 'confidential' or 'private'. If
    /// the string is set but does not match one of these, 'private' will be
    /// used.
    /// Deprecated since curl 8.17.0: removed.
    CURLOPT_KRBLEVEL = 10063,
    /// Set if we should verify the peer in ssl handshake, set 1 to verify.
    CURLOPT_SSL_VERIFYPEER = 64,
    /// The CApath or CAfile used to validate the peer certificate this
    /// option is used only if SSL_VERIFYPEER is true
    CURLOPT_CAINFO = 10065,
    /// Maximum number of http redirects to follow
    CURLOPT_MAXREDIRS = 68,
    /// Pass a long set to 1 to get the date of the requested document (if
    /// possible)! Pass a zero to shut it off.
    CURLOPT_FILETIME = 69,
    /// This points to a linked list of telnet options
    CURLOPT_TELNETOPTIONS = 10070,
    /// Max amount of cached alive connections
    CURLOPT_MAXCONNECTS = 71,
    CURLOPT_FRESH_CONNECT = 74,
    CURLOPT_FORBID_REUSE = 75,
    /// Set to a filename that contains random data for libcurl to use to
    /// seed the random engine when doing SSL connects.
    /// Deprecated since curl 7.84.0: Serves no purpose anymore.
    CURLOPT_RANDOM_FILE = 10076,
    /// Set to the Entropy Gathering Daemon socket pathname
    /// Deprecated since curl 7.84.0: Serves no purpose anymore.
    CURLOPT_EGDSOCKET = 10077,
    /// Time-out connect operations after this amount of seconds, if
    /// connects are OK within this time, then fine... This only aborts the
    /// connect phase.
    CURLOPT_CONNECTTIMEOUT = 78,
    /// Function that will be called to store headers (instead of fwrite).
    /// The parameters will use fwrite() syntax, make sure to follow them.
    CURLOPT_HEADERFUNCTION = 20079,
    CURLOPT_HTTPGET = 80,
    /// Set if we should verify the Common name from the peer certificate in
    /// ssl handshake, set 1 to check existence, 2 to ensure that it matches
    /// the provided hostname.
    CURLOPT_SSL_VERIFYHOST = 81,
    /// Specify which filename to write all known cookies in after completed
    /// operation. Set filename to "-" (dash) to make it go to stdout.
    CURLOPT_COOKIEJAR = 10082,
    /// Specify which TLS 1.2 (1.1, 1.0) ciphers to use
    CURLOPT_SSL_CIPHER_LIST = 10083,
    /// Specify which HTTP version to use! This must be set to one of the
    /// CURL_HTTP_VERSION* enums set below.
    CURLOPT_HTTP_VERSION = 84,
    CURLOPT_FTP_USE_EPSV = 85,
    /// type of the file keeping your SSL-certificate ("DER", "PEM", "ENG")
    CURLOPT_SSLCERTTYPE = 10086,
    /// name of the file keeping your private SSL-key
    CURLOPT_SSLKEY = 10087,
    /// type of the file keeping your private SSL-key ("DER", "PEM", "ENG")
    CURLOPT_SSLKEYTYPE = 10088,
    /// crypto engine for the SSL-sub system
    CURLOPT_SSLENGINE = 10089,
    CURLOPT_SSLENGINE_DEFAULT = 90,
    /// DEPRECATED, do not use!
    /// Deprecated since curl 7.11.1: Use CURLOPT_SHARE.
    CURLOPT_DNS_USE_GLOBAL_CACHE = 91,
    /// DNS cache timeout
    CURLOPT_DNS_CACHE_TIMEOUT = 92,
    /// send linked-list of pre-transfer QUOTE commands
    CURLOPT_PREQUOTE = 10093,
    /// set the debug function
    CURLOPT_DEBUGFUNCTION = 20094,
    /// set the data for the debug function
    CURLOPT_DEBUGDATA = 10095,
    /// mark this as start of a cookie session
    CURLOPT_COOKIESESSION = 96,
    /// The CApath directory used to validate the peer certificate this
    /// option is used only if SSL_VERIFYPEER is true
    CURLOPT_CAPATH = 10097,
    /// Instruct libcurl to use a smaller receive buffer
    CURLOPT_BUFFERSIZE = 98,
    CURLOPT_NOSIGNAL = 99,
    /// Provide a CURLShare for mutexing non-ts data
    CURLOPT_SHARE = 10100,
    CURLOPT_PROXYTYPE = 101,
    CURLOPT_ACCEPT_ENCODING = 10102,
    /// Set pointer to private data
    CURLOPT_PRIVATE = 10103,
    /// Set aliases for HTTP 200 in the HTTP Response header
    CURLOPT_HTTP200ALIASES = 10104,
    CURLOPT_UNRESTRICTED_AUTH = 105,
    CURLOPT_FTP_USE_EPRT = 106,
    CURLOPT_HTTPAUTH = 107,
    CURLOPT_SSL_CTX_FUNCTION = 20108,
    /// Set the userdata for the ssl context callback function's third
    /// argument
    CURLOPT_SSL_CTX_DATA = 10109,
    CURLOPT_FTP_CREATE_MISSING_DIRS = 110,
    CURLOPT_PROXYAUTH = 111,
    CURLOPT_SERVER_RESPONSE_TIMEOUT = 112,
    CURLOPT_IPRESOLVE = 113,
    CURLOPT_MAXFILESIZE = 114,
    /// See the comment for INFILESIZE above, but in short, specifies the
    /// size of the file being uploaded.  -1 means unknown.
    CURLOPT_INFILESIZE_LARGE = 30115,
    /// Sets the continuation offset. There is also a CURLOPTTYPE_LONG
    /// version of this; look above for RESUME_FROM.
    CURLOPT_RESUME_FROM_LARGE = 30116,
    /// Sets the maximum size of data that will be downloaded from an HTTP
    /// or FTP server. See MAXFILESIZE above for the LONG version.
    CURLOPT_MAXFILESIZE_LARGE = 30117,
    CURLOPT_NETRC_FILE = 10118,
    CURLOPT_USE_SSL = 119,
    /// The _LARGE version of the standard POSTFIELDSIZE option
    CURLOPT_POSTFIELDSIZE_LARGE = 30120,
    /// Enable/disable the TCP Nagle algorithm
    CURLOPT_TCP_NODELAY = 121,
    CURLOPT_FTPSSLAUTH = 129,
    /// Deprecated since curl 7.18.0: Use CURLOPT_SEEKFUNCTION.
    CURLOPT_IOCTLFUNCTION = 20130,
    /// Deprecated since curl 7.18.0: Use CURLOPT_SEEKDATA.
    CURLOPT_IOCTLDATA = 10131,
    /// null-terminated string for pass on to the FTP server when asked for
    /// "account" info
    CURLOPT_FTP_ACCOUNT = 10134,
    /// feed cookie into cookie engine
    CURLOPT_COOKIELIST = 10135,
    /// ignore Content-Length
    CURLOPT_IGNORE_CONTENT_LENGTH = 136,
    CURLOPT_FTP_SKIP_PASV_IP = 137,
    /// Select "file method" to use when doing FTP, see the curl_ftpmethod
    /// above.
    CURLOPT_FTP_FILEMETHOD = 138,
    /// Local port number to bind the socket to
    CURLOPT_LOCALPORT = 139,
    CURLOPT_LOCALPORTRANGE = 140,
    /// no transfer, set up connection and let application use the socket by
    /// extracting it with CURLINFO_LASTSOCKET
    CURLOPT_CONNECT_ONLY = 141,
    /// Function that will be called to convert from the network encoding
    /// (instead of using the iconv calls in libcurl)
    /// Deprecated since curl 7.82.0: Serves no purpose anymore.
    CURLOPT_CONV_FROM_NETWORK_FUNCTION = 20142,
    /// Function that will be called to convert to the network encoding
    /// (instead of using the iconv calls in libcurl)
    /// Deprecated since curl 7.82.0: Serves no purpose anymore.
    CURLOPT_CONV_TO_NETWORK_FUNCTION = 20143,
    /// Deprecated since curl 7.82.0: Serves no purpose anymore.
    CURLOPT_CONV_FROM_UTF8_FUNCTION = 20144,
    /// limit-rate: maximum number of bytes per second to send or receive
    CURLOPT_MAX_SEND_SPEED_LARGE = 30145,
    CURLOPT_MAX_RECV_SPEED_LARGE = 30146,
    /// Pointer to command string to send if USER/PASS fails.
    CURLOPT_FTP_ALTERNATIVE_TO_USER = 10147,
    /// callback function for setting socket options
    CURLOPT_SOCKOPTFUNCTION = 20148,
    CURLOPT_SOCKOPTDATA = 10149,
    /// set to 0 to disable session ID reuse for this transfer, default is
    /// enabled (== 1)
    CURLOPT_SSL_SESSIONID_CACHE = 150,
    /// allowed SSH authentication methods
    CURLOPT_SSH_AUTH_TYPES = 151,
    /// Used by scp/sftp to do public/private key authentication
    CURLOPT_SSH_PUBLIC_KEYFILE = 10152,
    CURLOPT_SSH_PRIVATE_KEYFILE = 10153,
    /// Send CCC (Clear Command Channel) after authentication
    CURLOPT_FTP_SSL_CCC = 154,
    /// Same as TIMEOUT and CONNECTTIMEOUT, but with ms resolution
    CURLOPT_TIMEOUT_MS = 155,
    CURLOPT_CONNECTTIMEOUT_MS = 156,
    /// set to zero to disable the libcurl's decoding and thus pass the raw
    /// body data to the application even when it is encoded/compressed
    CURLOPT_HTTP_TRANSFER_DECODING = 157,
    CURLOPT_HTTP_CONTENT_DECODING = 158,
    /// Permission used when creating new files and directories on the
    /// remote server for protocols that support it, SFTP/SCP/FILE
    CURLOPT_NEW_FILE_PERMS = 159,
    CURLOPT_NEW_DIRECTORY_PERMS = 160,
    /// Set the behavior of POST when redirecting. Values must be set to one
    /// of CURL_REDIR* defines below. This used to be called CURLOPT_POST301
    CURLOPT_POSTREDIR = 161,
    /// used by scp/sftp to verify the host's public key
    CURLOPT_SSH_HOST_PUBLIC_KEY_MD5 = 10162,
    CURLOPT_OPENSOCKETFUNCTION = 20163,
    CURLOPT_OPENSOCKETDATA = 10164,
    /// POST volatile input fields.
    CURLOPT_COPYPOSTFIELDS = 10165,
    /// set transfer mode (;type=<a|i>) when doing FTP via an HTTP proxy
    CURLOPT_PROXY_TRANSFER_MODE = 166,
    /// Callback function for seeking in the input stream
    CURLOPT_SEEKFUNCTION = 20167,
    CURLOPT_SEEKDATA = 10168,
    /// CRL file
    CURLOPT_CRLFILE = 10169,
    /// Issuer certificate
    CURLOPT_ISSUERCERT = 10170,
    /// (IPv6) Address scope
    CURLOPT_ADDRESS_SCOPE = 171,
    /// Collect certificate chain info and allow it to get retrievable with
    /// CURLINFO_CERTINFO after the transfer is complete.
    CURLOPT_CERTINFO = 172,
    /// "name" and "pwd" to use when fetching.
    CURLOPT_USERNAME = 10173,
    CURLOPT_PASSWORD = 10174,
    /// "name" and "pwd" to use with Proxy when fetching.
    CURLOPT_PROXYUSERNAME = 10175,
    CURLOPT_PROXYPASSWORD = 10176,
    CURLOPT_NOPROXY = 10177,
    /// block size for TFTP transfers
    CURLOPT_TFTP_BLKSIZE = 178,
    /// DEPRECATED, do not use!
    /// Deprecated since curl 7.49.0: Use CURLOPT_PROXY_SERVICE_NAME.
    CURLOPT_SOCKS5_GSSAPI_SERVICE = 10179,
    /// Socks Service
    CURLOPT_SOCKS5_GSSAPI_NEC = 180,
    /// Deprecated since curl 7.85.0: Use CURLOPT_PROTOCOLS_STR.
    CURLOPT_PROTOCOLS = 181,
    /// Deprecated since curl 7.85.0: Use CURLOPT_REDIR_PROTOCOLS_STR.
    CURLOPT_REDIR_PROTOCOLS = 182,
    /// set the SSH knownhost filename to use
    CURLOPT_SSH_KNOWNHOSTS = 10183,
    /// set the SSH host key callback, must point to a curl_sshkeycallback
    /// function
    CURLOPT_SSH_KEYFUNCTION = 20184,
    /// set the SSH host key callback custom pointer
    CURLOPT_SSH_KEYDATA = 10185,
    /// set the SMTP mail originator
    CURLOPT_MAIL_FROM = 10186,
    /// set the list of SMTP mail receiver(s)
    CURLOPT_MAIL_RCPT = 10187,
    /// FTP: send PRET before PASV
    CURLOPT_FTP_USE_PRET = 188,
    /// RTSP request method (OPTIONS, SETUP, PLAY, etc...)
    CURLOPT_RTSP_REQUEST = 189,
    /// The RTSP session identifier
    CURLOPT_RTSP_SESSION_ID = 10190,
    /// The RTSP stream URI
    CURLOPT_RTSP_STREAM_URI = 10191,
    /// The Transport: header to use in RTSP requests
    CURLOPT_RTSP_TRANSPORT = 10192,
    /// Manually initialize the client RTSP CSeq for this handle
    CURLOPT_RTSP_CLIENT_CSEQ = 193,
    /// Manually initialize the server RTSP CSeq for this handle
    CURLOPT_RTSP_SERVER_CSEQ = 194,
    /// The stream to pass to INTERLEAVEFUNCTION.
    CURLOPT_INTERLEAVEDATA = 10195,
    /// Let the application define a custom write method for RTP data
    CURLOPT_INTERLEAVEFUNCTION = 20196,
    /// Turn on wildcard matching
    CURLOPT_WILDCARDMATCH = 197,
    /// Directory matching callback called before downloading of an
    /// individual file (chunk) started
    CURLOPT_CHUNK_BGN_FUNCTION = 20198,
    /// Directory matching callback called after the file (chunk) was
    /// downloaded, or skipped
    CURLOPT_CHUNK_END_FUNCTION = 20199,
    /// Change match (fnmatch-like) callback for wildcard matching
    CURLOPT_FNMATCH_FUNCTION = 20200,
    /// Let the application define custom chunk data pointer
    CURLOPT_CHUNK_DATA = 10201,
    /// FNMATCH_FUNCTION user pointer
    CURLOPT_FNMATCH_DATA = 10202,
    /// send linked-list of name:port:address sets
    CURLOPT_RESOLVE = 10203,
    /// Set a username for authenticated TLS
    CURLOPT_TLSAUTH_USERNAME = 10204,
    /// Set a password for authenticated TLS
    CURLOPT_TLSAUTH_PASSWORD = 10205,
    /// Set authentication type for authenticated TLS
    CURLOPT_TLSAUTH_TYPE = 10206,
    CURLOPT_TRANSFER_ENCODING = 207,
    /// Callback function for closing socket (instead of close(2)). The
    /// callback should have type curl_closesocket_callback
    CURLOPT_CLOSESOCKETFUNCTION = 20208,
    CURLOPT_CLOSESOCKETDATA = 10209,
    /// allow GSSAPI credential delegation
    CURLOPT_GSSAPI_DELEGATION = 210,
    /// Set the name servers to use for DNS resolution. Only supported by
    /// the c-ares DNS backend
    CURLOPT_DNS_SERVERS = 10211,
    /// Time-out accept operations (currently for FTP only) after this
    /// amount of milliseconds.
    CURLOPT_ACCEPTTIMEOUT_MS = 212,
    /// Set TCP keepalive
    CURLOPT_TCP_KEEPALIVE = 213,
    /// non-universal keepalive knobs (Linux, AIX, HP-UX, more)
    CURLOPT_TCP_KEEPIDLE = 214,
    CURLOPT_TCP_KEEPINTVL = 215,
    /// Enable/disable specific SSL features with a bitmask, see
    /// CURLSSLOPT_*
    CURLOPT_SSL_OPTIONS = 216,
    /// Set the SMTP auth originator
    CURLOPT_MAIL_AUTH = 10217,
    /// Enable/disable SASL initial response
    CURLOPT_SASL_IR = 218,
    /// Function that will be called instead of the internal progress
    /// display function. This function should be defined as the
    /// curl_xferinfo_callback prototype defines. (Deprecates
    /// CURLOPT_PROGRESSFUNCTION)
    CURLOPT_XFERINFOFUNCTION = 20219,
    /// The XOAUTH2 bearer token
    CURLOPT_XOAUTH2_BEARER = 10220,
    /// Set the interface string to use as outgoing network interface for
    /// DNS requests. Only supported by the c-ares DNS backend
    CURLOPT_DNS_INTERFACE = 10221,
    /// Set the local IPv4 address to use for outgoing DNS requests. Only
    /// supported by the c-ares DNS backend
    CURLOPT_DNS_LOCAL_IP4 = 10222,
    /// Set the local IPv6 address to use for outgoing DNS requests. Only
    /// supported by the c-ares DNS backend
    CURLOPT_DNS_LOCAL_IP6 = 10223,
    /// Set authentication options directly
    CURLOPT_LOGIN_OPTIONS = 10224,
    /// Enable/disable TLS NPN extension (http2 over ssl might fail without)
    /// Deprecated since curl 7.86.0: Has no function.
    CURLOPT_SSL_ENABLE_NPN = 225,
    /// Enable/disable TLS ALPN extension (http2 over ssl might fail
    /// without)
    CURLOPT_SSL_ENABLE_ALPN = 226,
    /// Time to wait for a response to an HTTP request containing an Expect:
    /// 100-continue header before sending the data anyway.
    CURLOPT_EXPECT_100_TIMEOUT_MS = 227,
    /// This points to a linked list of headers used for proxy requests
    /// only, struct curl_slist kind
    CURLOPT_PROXYHEADER = 10228,
    /// Pass in a bitmask of "header options"
    CURLOPT_HEADEROPT = 229,
    /// The public key used to validate the peer public key
    CURLOPT_PINNEDPUBLICKEY = 10230,
    /// Path to Unix domain socket
    CURLOPT_UNIX_SOCKET_PATH = 10231,
    /// Set if we should verify the certificate status.
    CURLOPT_SSL_VERIFYSTATUS = 232,
    /// Set if we should enable TLS false start.
    /// Deprecated since curl 8.15.0: Has no function.
    CURLOPT_SSL_FALSESTART = 233,
    /// Do not squash dot-dot sequences
    CURLOPT_PATH_AS_IS = 234,
    /// Proxy Service Name
    CURLOPT_PROXY_SERVICE_NAME = 10235,
    /// Service Name
    CURLOPT_SERVICE_NAME = 10236,
    /// Wait/do not wait for pipe/mutex to clarify
    CURLOPT_PIPEWAIT = 237,
    /// Set the protocol used when curl is given a URL without a protocol
    CURLOPT_DEFAULT_PROTOCOL = 10238,
    /// Set stream weight, 1 - 256 (default is 16)
    CURLOPT_STREAM_WEIGHT = 239,
    /// Set stream dependency on another curl handle
    CURLOPT_STREAM_DEPENDS = 10240,
    /// Set E-xclusive stream dependency on another curl handle
    CURLOPT_STREAM_DEPENDS_E = 10241,
    /// Do not send any tftp option requests to the server
    CURLOPT_TFTP_NO_OPTIONS = 242,
    /// Linked-list of host:port:connect-to-host:connect-to-port, overrides
    /// the URL's host:port (only for the network layer)
    CURLOPT_CONNECT_TO = 10243,
    /// Set TCP Fast Open
    CURLOPT_TCP_FASTOPEN = 244,
    /// Continue to send data if the server responds early with an HTTP
    /// status code >= 300
    CURLOPT_KEEP_SENDING_ON_ERROR = 245,
    /// The CApath or CAfile used to validate the proxy certificate this
    /// option is used only if PROXY_SSL_VERIFYPEER is true
    CURLOPT_PROXY_CAINFO = 10246,
    /// The CApath directory used to validate the proxy certificate this
    /// option is used only if PROXY_SSL_VERIFYPEER is true
    CURLOPT_PROXY_CAPATH = 10247,
    /// Set if we should verify the proxy in ssl handshake, set 1 to verify.
    CURLOPT_PROXY_SSL_VERIFYPEER = 248,
    /// Set if we should verify the Common name from the proxy certificate
    /// in ssl handshake, set 1 to check existence, 2 to ensure that it
    /// matches the provided hostname.
    CURLOPT_PROXY_SSL_VERIFYHOST = 249,
    /// What version to specifically try to use for proxy. See
    /// CURL_SSLVERSION defines below.
    CURLOPT_PROXY_SSLVERSION = 250,
    /// Set a username for authenticated TLS for proxy
    CURLOPT_PROXY_TLSAUTH_USERNAME = 10251,
    /// Set a password for authenticated TLS for proxy
    CURLOPT_PROXY_TLSAUTH_PASSWORD = 10252,
    /// Set authentication type for authenticated TLS for proxy
    CURLOPT_PROXY_TLSAUTH_TYPE = 10253,
    /// name of the file keeping your private SSL-certificate for proxy
    CURLOPT_PROXY_SSLCERT = 10254,
    /// type of the file keeping your SSL-certificate ("DER", "PEM", "ENG")
    /// for proxy
    CURLOPT_PROXY_SSLCERTTYPE = 10255,
    /// name of the file keeping your private SSL-key for proxy
    CURLOPT_PROXY_SSLKEY = 10256,
    /// type of the file keeping your private SSL-key ("DER", "PEM", "ENG")
    /// for proxy
    CURLOPT_PROXY_SSLKEYTYPE = 10257,
    /// password for the SSL private key for proxy
    CURLOPT_PROXY_KEYPASSWD = 10258,
    /// Specify which TLS 1.2 (1.1, 1.0) ciphers to use for proxy
    CURLOPT_PROXY_SSL_CIPHER_LIST = 10259,
    /// CRL file for proxy
    CURLOPT_PROXY_CRLFILE = 10260,
    /// Enable/disable specific SSL features with a bitmask for proxy, see
    /// CURLSSLOPT_*
    CURLOPT_PROXY_SSL_OPTIONS = 261,
    /// Name of pre proxy to use.
    CURLOPT_PRE_PROXY = 10262,
    /// The public key in DER form used to validate the proxy public key
    /// this option is used only if PROXY_SSL_VERIFYPEER is true
    CURLOPT_PROXY_PINNEDPUBLICKEY = 10263,
    /// Path to an abstract Unix domain socket
    CURLOPT_ABSTRACT_UNIX_SOCKET = 10264,
    /// Suppress proxy CONNECT response headers from user callbacks
    CURLOPT_SUPPRESS_CONNECT_HEADERS = 265,
    /// The request target, instead of extracted from the URL
    CURLOPT_REQUEST_TARGET = 10266,
    /// bitmask of allowed auth methods for connections to SOCKS5 proxies
    CURLOPT_SOCKS5_AUTH = 267,
    /// Enable/disable SSH compression
    CURLOPT_SSH_COMPRESSION = 268,
    /// Post MIME data.
    CURLOPT_MIMEPOST = 10269,
    /// Time to use with the CURLOPT_TIMECONDITION. Specified in number of
    /// seconds since 1 Jan 1970.
    CURLOPT_TIMEVALUE_LARGE = 30270,
    /// Head start in milliseconds to give happy eyeballs.
    CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS = 271,
    /// Function that will be called before a resolver request is made
    CURLOPT_RESOLVER_START_FUNCTION = 20272,
    /// User data to pass to the resolver start callback.
    CURLOPT_RESOLVER_START_DATA = 10273,
    /// send HAProxy PROXY protocol header?
    CURLOPT_HAPROXYPROTOCOL = 274,
    /// shuffle addresses before use when DNS returns multiple
    CURLOPT_DNS_SHUFFLE_ADDRESSES = 275,
    /// Specify which TLS 1.3 ciphers suites to use
    CURLOPT_TLS13_CIPHERS = 10276,
    CURLOPT_PROXY_TLS13_CIPHERS = 10277,
    /// Disallow specifying username/login in URL.
    CURLOPT_DISALLOW_USERNAME_IN_URL = 278,
    /// DNS-over-HTTPS URL
    CURLOPT_DOH_URL = 10279,
    /// Preferred buffer size to use for uploads
    CURLOPT_UPLOAD_BUFFERSIZE = 280,
    /// Time in ms between connection upkeep calls for long-lived
    /// connections.
    CURLOPT_UPKEEP_INTERVAL_MS = 281,
    /// Specify URL using CURL URL API.
    CURLOPT_CURLU = 10282,
    /// add trailing data just after no more data is available
    CURLOPT_TRAILERFUNCTION = 20283,
    /// pointer to be passed to HTTP_TRAILER_FUNCTION
    CURLOPT_TRAILERDATA = 10284,
    /// set this to 1L to allow HTTP/0.9 responses or 0L to disallow
    CURLOPT_HTTP09_ALLOWED = 285,
    /// alt-svc control bitmask
    CURLOPT_ALTSVC_CTRL = 286,
    /// alt-svc cache filename to possibly read from/write to
    CURLOPT_ALTSVC = 10287,
    /// maximum age (idle time) of a connection to consider it for reuse (in
    /// seconds)
    CURLOPT_MAXAGE_CONN = 288,
    /// SASL authorization identity
    CURLOPT_SASL_AUTHZID = 10289,
    /// allow RCPT TO command to fail for some recipients
    CURLOPT_MAIL_RCPT_ALLOWFAILS = 290,
    /// the private SSL-certificate as a "blob"
    CURLOPT_SSLCERT_BLOB = 40291,
    CURLOPT_SSLKEY_BLOB = 40292,
    CURLOPT_PROXY_SSLCERT_BLOB = 40293,
    CURLOPT_PROXY_SSLKEY_BLOB = 40294,
    CURLOPT_ISSUERCERT_BLOB = 40295,
    /// Issuer certificate for proxy
    CURLOPT_PROXY_ISSUERCERT = 10296,
    CURLOPT_PROXY_ISSUERCERT_BLOB = 40297,
    /// the EC curves requested by the TLS client (RFC 8422, 5.1); OpenSSL
    /// support via 'set_groups'/'set_curves':
    /// https://docs.openssl.org/master/man3/SSL_CTX_set1_curves/
    CURLOPT_SSL_EC_CURVES = 10298,
    /// HSTS bitmask
    CURLOPT_HSTS_CTRL = 299,
    /// HSTS filename
    CURLOPT_HSTS = 10300,
    /// HSTS read callback
    CURLOPT_HSTSREADFUNCTION = 20301,
    CURLOPT_HSTSREADDATA = 10302,
    /// HSTS write callback
    CURLOPT_HSTSWRITEFUNCTION = 20303,
    CURLOPT_HSTSWRITEDATA = 10304,
    /// Parameters for V4 signature
    CURLOPT_AWS_SIGV4 = 10305,
    /// Same as CURLOPT_SSL_VERIFYPEER but for DoH (DNS-over-HTTPS) servers.
    CURLOPT_DOH_SSL_VERIFYPEER = 306,
    /// Same as CURLOPT_SSL_VERIFYHOST but for DoH (DNS-over-HTTPS) servers.
    CURLOPT_DOH_SSL_VERIFYHOST = 307,
    /// Same as CURLOPT_SSL_VERIFYSTATUS but for DoH (DNS-over-HTTPS)
    /// servers.
    CURLOPT_DOH_SSL_VERIFYSTATUS = 308,
    /// The CA certificates as "blob" used to validate the peer certificate
    /// this option is used only if SSL_VERIFYPEER is true
    CURLOPT_CAINFO_BLOB = 40309,
    /// The CA certificates as "blob" used to validate the proxy certificate
    /// this option is used only if PROXY_SSL_VERIFYPEER is true
    CURLOPT_PROXY_CAINFO_BLOB = 40310,
    /// used by scp/sftp to verify the host's public key
    CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256 = 10311,
    /// Function that will be called immediately before the initial request
    /// is made on a connection (after any protocol negotiation step).
    CURLOPT_PREREQFUNCTION = 20312,
    /// Data passed to the CURLOPT_PREREQFUNCTION callback
    CURLOPT_PREREQDATA = 10313,
    /// maximum age (since creation) of a connection to consider it for
    /// reuse (in seconds)
    CURLOPT_MAXLIFETIME_CONN = 314,
    /// Set MIME option flags.
    CURLOPT_MIME_OPTIONS = 315,
    /// set the SSH host key callback, must point to a curl_sshkeycallback
    /// function
    CURLOPT_SSH_HOSTKEYFUNCTION = 20316,
    /// set the SSH host key callback custom pointer
    CURLOPT_SSH_HOSTKEYDATA = 10317,
    CURLOPT_PROTOCOLS_STR = 10318,
    /// specify which protocols that libcurl is allowed to follow directs to
    CURLOPT_REDIR_PROTOCOLS_STR = 10319,
    /// WebSockets options
    CURLOPT_WS_OPTIONS = 320,
    /// CA cache timeout
    CURLOPT_CA_CACHE_TIMEOUT = 321,
    /// Can leak things, gonna exit() soon
    CURLOPT_QUICK_EXIT = 322,
    /// set a specific client IP for HAProxy PROXY protocol header?
    CURLOPT_HAPROXY_CLIENT_IP = 10323,
    /// millisecond version
    CURLOPT_SERVER_RESPONSE_TIMEOUT_MS = 324,
    /// set ECH configuration
    CURLOPT_ECH = 10325,
    /// maximum number of keepalive probes (Linux, *BSD, macOS, etc.)
    CURLOPT_TCP_KEEPCNT = 326,
    CURLOPT_UPLOAD_FLAGS = 327,
    /// set TLS supported signature algorithms
    CURLOPT_SSL_SIGNATURE_ALGORITHMS = 10328,
    /// One past the last real option, and **10329 -- not 328**.
    ///
    /// CORRECTION 1. 328 is the highest `nu` INDEX, carried by
    /// `CURLOPT(CURLOPT_SSL_SIGNATURE_ALGORITHMS, CURLOPTTYPE_STRINGPOINT,
    /// 328)` at `curl.h:2259`. The sentinel at `:2261` is written bare, so
    /// it takes the next ordinal after that member's COMPOSED value of
    /// 10328. Reading 328 as the sentinel's value understates it by 10001
    /// and shifts nothing else, which is why the mistake survives a
    /// compile: `CURLOPT_LASTENTRY` is a bound, never an option, so only
    /// code that compares against it misbehaves.
    ///
    /// curl proves the value itself. `Curl_easyopts_check` at
    /// `lib/easyoptions.c:388` returns an ERROR when
    /// `(CURLOPT_LASTENTRY % 10000) != (328 + 1)`, so a correct table
    /// satisfies the equality `10329 % 10000 == 329`. The `% 10000` is only
    /// necessary because the value is neither 328 nor 329.
    ///
    /// The same trap has a twin in the multi interface:
    /// `CURLMOPT_LASTENTRY` is 10020, an ordinal follow-on from
    /// `CURLMOPT_NOTIFYDATA = 10019` (`multi.h:407`), and not 20. That
    /// enumeration lives in `ffi/types.rs`, which already pins it
    /// correctly; it is noted here because the two are the same error.
    CURLOPT_LASTENTRY = 10329,
}

impl CURLoption {
    /// Every variant, in the frozen header's declaration order, with
    /// `CURLOPT_LASTENTRY` last. Used by [`CURLoption::from_c_int`] and by
    /// the tests that assert full coverage.
    #[allow(dead_code)]
    pub(crate) const ABI_VARIANTS: &'static [CURLoption] = &[
        CURLoption::CURLOPT_WRITEDATA,
        CURLoption::CURLOPT_URL,
        CURLoption::CURLOPT_PORT,
        CURLoption::CURLOPT_PROXY,
        CURLoption::CURLOPT_USERPWD,
        CURLoption::CURLOPT_PROXYUSERPWD,
        CURLoption::CURLOPT_RANGE,
        CURLoption::CURLOPT_READDATA,
        CURLoption::CURLOPT_ERRORBUFFER,
        CURLoption::CURLOPT_WRITEFUNCTION,
        CURLoption::CURLOPT_READFUNCTION,
        CURLoption::CURLOPT_TIMEOUT,
        CURLoption::CURLOPT_INFILESIZE,
        CURLoption::CURLOPT_POSTFIELDS,
        CURLoption::CURLOPT_REFERER,
        CURLoption::CURLOPT_FTPPORT,
        CURLoption::CURLOPT_USERAGENT,
        CURLoption::CURLOPT_LOW_SPEED_LIMIT,
        CURLoption::CURLOPT_LOW_SPEED_TIME,
        CURLoption::CURLOPT_RESUME_FROM,
        CURLoption::CURLOPT_COOKIE,
        CURLoption::CURLOPT_HTTPHEADER,
        CURLoption::CURLOPT_HTTPPOST,
        CURLoption::CURLOPT_SSLCERT,
        CURLoption::CURLOPT_KEYPASSWD,
        CURLoption::CURLOPT_CRLF,
        CURLoption::CURLOPT_QUOTE,
        CURLoption::CURLOPT_HEADERDATA,
        CURLoption::CURLOPT_COOKIEFILE,
        CURLoption::CURLOPT_SSLVERSION,
        CURLoption::CURLOPT_TIMECONDITION,
        CURLoption::CURLOPT_TIMEVALUE,
        CURLoption::CURLOPT_CUSTOMREQUEST,
        CURLoption::CURLOPT_STDERR,
        CURLoption::CURLOPT_POSTQUOTE,
        CURLoption::CURLOPT_VERBOSE,
        CURLoption::CURLOPT_HEADER,
        CURLoption::CURLOPT_NOPROGRESS,
        CURLoption::CURLOPT_NOBODY,
        CURLoption::CURLOPT_FAILONERROR,
        CURLoption::CURLOPT_UPLOAD,
        CURLoption::CURLOPT_POST,
        CURLoption::CURLOPT_DIRLISTONLY,
        CURLoption::CURLOPT_APPEND,
        CURLoption::CURLOPT_NETRC,
        CURLoption::CURLOPT_FOLLOWLOCATION,
        CURLoption::CURLOPT_TRANSFERTEXT,
        CURLoption::CURLOPT_PUT,
        CURLoption::CURLOPT_PROGRESSFUNCTION,
        CURLoption::CURLOPT_XFERINFODATA,
        CURLoption::CURLOPT_AUTOREFERER,
        CURLoption::CURLOPT_PROXYPORT,
        CURLoption::CURLOPT_POSTFIELDSIZE,
        CURLoption::CURLOPT_HTTPPROXYTUNNEL,
        CURLoption::CURLOPT_INTERFACE,
        CURLoption::CURLOPT_KRBLEVEL,
        CURLoption::CURLOPT_SSL_VERIFYPEER,
        CURLoption::CURLOPT_CAINFO,
        CURLoption::CURLOPT_MAXREDIRS,
        CURLoption::CURLOPT_FILETIME,
        CURLoption::CURLOPT_TELNETOPTIONS,
        CURLoption::CURLOPT_MAXCONNECTS,
        CURLoption::CURLOPT_FRESH_CONNECT,
        CURLoption::CURLOPT_FORBID_REUSE,
        CURLoption::CURLOPT_RANDOM_FILE,
        CURLoption::CURLOPT_EGDSOCKET,
        CURLoption::CURLOPT_CONNECTTIMEOUT,
        CURLoption::CURLOPT_HEADERFUNCTION,
        CURLoption::CURLOPT_HTTPGET,
        CURLoption::CURLOPT_SSL_VERIFYHOST,
        CURLoption::CURLOPT_COOKIEJAR,
        CURLoption::CURLOPT_SSL_CIPHER_LIST,
        CURLoption::CURLOPT_HTTP_VERSION,
        CURLoption::CURLOPT_FTP_USE_EPSV,
        CURLoption::CURLOPT_SSLCERTTYPE,
        CURLoption::CURLOPT_SSLKEY,
        CURLoption::CURLOPT_SSLKEYTYPE,
        CURLoption::CURLOPT_SSLENGINE,
        CURLoption::CURLOPT_SSLENGINE_DEFAULT,
        CURLoption::CURLOPT_DNS_USE_GLOBAL_CACHE,
        CURLoption::CURLOPT_DNS_CACHE_TIMEOUT,
        CURLoption::CURLOPT_PREQUOTE,
        CURLoption::CURLOPT_DEBUGFUNCTION,
        CURLoption::CURLOPT_DEBUGDATA,
        CURLoption::CURLOPT_COOKIESESSION,
        CURLoption::CURLOPT_CAPATH,
        CURLoption::CURLOPT_BUFFERSIZE,
        CURLoption::CURLOPT_NOSIGNAL,
        CURLoption::CURLOPT_SHARE,
        CURLoption::CURLOPT_PROXYTYPE,
        CURLoption::CURLOPT_ACCEPT_ENCODING,
        CURLoption::CURLOPT_PRIVATE,
        CURLoption::CURLOPT_HTTP200ALIASES,
        CURLoption::CURLOPT_UNRESTRICTED_AUTH,
        CURLoption::CURLOPT_FTP_USE_EPRT,
        CURLoption::CURLOPT_HTTPAUTH,
        CURLoption::CURLOPT_SSL_CTX_FUNCTION,
        CURLoption::CURLOPT_SSL_CTX_DATA,
        CURLoption::CURLOPT_FTP_CREATE_MISSING_DIRS,
        CURLoption::CURLOPT_PROXYAUTH,
        CURLoption::CURLOPT_SERVER_RESPONSE_TIMEOUT,
        CURLoption::CURLOPT_IPRESOLVE,
        CURLoption::CURLOPT_MAXFILESIZE,
        CURLoption::CURLOPT_INFILESIZE_LARGE,
        CURLoption::CURLOPT_RESUME_FROM_LARGE,
        CURLoption::CURLOPT_MAXFILESIZE_LARGE,
        CURLoption::CURLOPT_NETRC_FILE,
        CURLoption::CURLOPT_USE_SSL,
        CURLoption::CURLOPT_POSTFIELDSIZE_LARGE,
        CURLoption::CURLOPT_TCP_NODELAY,
        CURLoption::CURLOPT_FTPSSLAUTH,
        CURLoption::CURLOPT_IOCTLFUNCTION,
        CURLoption::CURLOPT_IOCTLDATA,
        CURLoption::CURLOPT_FTP_ACCOUNT,
        CURLoption::CURLOPT_COOKIELIST,
        CURLoption::CURLOPT_IGNORE_CONTENT_LENGTH,
        CURLoption::CURLOPT_FTP_SKIP_PASV_IP,
        CURLoption::CURLOPT_FTP_FILEMETHOD,
        CURLoption::CURLOPT_LOCALPORT,
        CURLoption::CURLOPT_LOCALPORTRANGE,
        CURLoption::CURLOPT_CONNECT_ONLY,
        CURLoption::CURLOPT_CONV_FROM_NETWORK_FUNCTION,
        CURLoption::CURLOPT_CONV_TO_NETWORK_FUNCTION,
        CURLoption::CURLOPT_CONV_FROM_UTF8_FUNCTION,
        CURLoption::CURLOPT_MAX_SEND_SPEED_LARGE,
        CURLoption::CURLOPT_MAX_RECV_SPEED_LARGE,
        CURLoption::CURLOPT_FTP_ALTERNATIVE_TO_USER,
        CURLoption::CURLOPT_SOCKOPTFUNCTION,
        CURLoption::CURLOPT_SOCKOPTDATA,
        CURLoption::CURLOPT_SSL_SESSIONID_CACHE,
        CURLoption::CURLOPT_SSH_AUTH_TYPES,
        CURLoption::CURLOPT_SSH_PUBLIC_KEYFILE,
        CURLoption::CURLOPT_SSH_PRIVATE_KEYFILE,
        CURLoption::CURLOPT_FTP_SSL_CCC,
        CURLoption::CURLOPT_TIMEOUT_MS,
        CURLoption::CURLOPT_CONNECTTIMEOUT_MS,
        CURLoption::CURLOPT_HTTP_TRANSFER_DECODING,
        CURLoption::CURLOPT_HTTP_CONTENT_DECODING,
        CURLoption::CURLOPT_NEW_FILE_PERMS,
        CURLoption::CURLOPT_NEW_DIRECTORY_PERMS,
        CURLoption::CURLOPT_POSTREDIR,
        CURLoption::CURLOPT_SSH_HOST_PUBLIC_KEY_MD5,
        CURLoption::CURLOPT_OPENSOCKETFUNCTION,
        CURLoption::CURLOPT_OPENSOCKETDATA,
        CURLoption::CURLOPT_COPYPOSTFIELDS,
        CURLoption::CURLOPT_PROXY_TRANSFER_MODE,
        CURLoption::CURLOPT_SEEKFUNCTION,
        CURLoption::CURLOPT_SEEKDATA,
        CURLoption::CURLOPT_CRLFILE,
        CURLoption::CURLOPT_ISSUERCERT,
        CURLoption::CURLOPT_ADDRESS_SCOPE,
        CURLoption::CURLOPT_CERTINFO,
        CURLoption::CURLOPT_USERNAME,
        CURLoption::CURLOPT_PASSWORD,
        CURLoption::CURLOPT_PROXYUSERNAME,
        CURLoption::CURLOPT_PROXYPASSWORD,
        CURLoption::CURLOPT_NOPROXY,
        CURLoption::CURLOPT_TFTP_BLKSIZE,
        CURLoption::CURLOPT_SOCKS5_GSSAPI_SERVICE,
        CURLoption::CURLOPT_SOCKS5_GSSAPI_NEC,
        CURLoption::CURLOPT_PROTOCOLS,
        CURLoption::CURLOPT_REDIR_PROTOCOLS,
        CURLoption::CURLOPT_SSH_KNOWNHOSTS,
        CURLoption::CURLOPT_SSH_KEYFUNCTION,
        CURLoption::CURLOPT_SSH_KEYDATA,
        CURLoption::CURLOPT_MAIL_FROM,
        CURLoption::CURLOPT_MAIL_RCPT,
        CURLoption::CURLOPT_FTP_USE_PRET,
        CURLoption::CURLOPT_RTSP_REQUEST,
        CURLoption::CURLOPT_RTSP_SESSION_ID,
        CURLoption::CURLOPT_RTSP_STREAM_URI,
        CURLoption::CURLOPT_RTSP_TRANSPORT,
        CURLoption::CURLOPT_RTSP_CLIENT_CSEQ,
        CURLoption::CURLOPT_RTSP_SERVER_CSEQ,
        CURLoption::CURLOPT_INTERLEAVEDATA,
        CURLoption::CURLOPT_INTERLEAVEFUNCTION,
        CURLoption::CURLOPT_WILDCARDMATCH,
        CURLoption::CURLOPT_CHUNK_BGN_FUNCTION,
        CURLoption::CURLOPT_CHUNK_END_FUNCTION,
        CURLoption::CURLOPT_FNMATCH_FUNCTION,
        CURLoption::CURLOPT_CHUNK_DATA,
        CURLoption::CURLOPT_FNMATCH_DATA,
        CURLoption::CURLOPT_RESOLVE,
        CURLoption::CURLOPT_TLSAUTH_USERNAME,
        CURLoption::CURLOPT_TLSAUTH_PASSWORD,
        CURLoption::CURLOPT_TLSAUTH_TYPE,
        CURLoption::CURLOPT_TRANSFER_ENCODING,
        CURLoption::CURLOPT_CLOSESOCKETFUNCTION,
        CURLoption::CURLOPT_CLOSESOCKETDATA,
        CURLoption::CURLOPT_GSSAPI_DELEGATION,
        CURLoption::CURLOPT_DNS_SERVERS,
        CURLoption::CURLOPT_ACCEPTTIMEOUT_MS,
        CURLoption::CURLOPT_TCP_KEEPALIVE,
        CURLoption::CURLOPT_TCP_KEEPIDLE,
        CURLoption::CURLOPT_TCP_KEEPINTVL,
        CURLoption::CURLOPT_SSL_OPTIONS,
        CURLoption::CURLOPT_MAIL_AUTH,
        CURLoption::CURLOPT_SASL_IR,
        CURLoption::CURLOPT_XFERINFOFUNCTION,
        CURLoption::CURLOPT_XOAUTH2_BEARER,
        CURLoption::CURLOPT_DNS_INTERFACE,
        CURLoption::CURLOPT_DNS_LOCAL_IP4,
        CURLoption::CURLOPT_DNS_LOCAL_IP6,
        CURLoption::CURLOPT_LOGIN_OPTIONS,
        CURLoption::CURLOPT_SSL_ENABLE_NPN,
        CURLoption::CURLOPT_SSL_ENABLE_ALPN,
        CURLoption::CURLOPT_EXPECT_100_TIMEOUT_MS,
        CURLoption::CURLOPT_PROXYHEADER,
        CURLoption::CURLOPT_HEADEROPT,
        CURLoption::CURLOPT_PINNEDPUBLICKEY,
        CURLoption::CURLOPT_UNIX_SOCKET_PATH,
        CURLoption::CURLOPT_SSL_VERIFYSTATUS,
        CURLoption::CURLOPT_SSL_FALSESTART,
        CURLoption::CURLOPT_PATH_AS_IS,
        CURLoption::CURLOPT_PROXY_SERVICE_NAME,
        CURLoption::CURLOPT_SERVICE_NAME,
        CURLoption::CURLOPT_PIPEWAIT,
        CURLoption::CURLOPT_DEFAULT_PROTOCOL,
        CURLoption::CURLOPT_STREAM_WEIGHT,
        CURLoption::CURLOPT_STREAM_DEPENDS,
        CURLoption::CURLOPT_STREAM_DEPENDS_E,
        CURLoption::CURLOPT_TFTP_NO_OPTIONS,
        CURLoption::CURLOPT_CONNECT_TO,
        CURLoption::CURLOPT_TCP_FASTOPEN,
        CURLoption::CURLOPT_KEEP_SENDING_ON_ERROR,
        CURLoption::CURLOPT_PROXY_CAINFO,
        CURLoption::CURLOPT_PROXY_CAPATH,
        CURLoption::CURLOPT_PROXY_SSL_VERIFYPEER,
        CURLoption::CURLOPT_PROXY_SSL_VERIFYHOST,
        CURLoption::CURLOPT_PROXY_SSLVERSION,
        CURLoption::CURLOPT_PROXY_TLSAUTH_USERNAME,
        CURLoption::CURLOPT_PROXY_TLSAUTH_PASSWORD,
        CURLoption::CURLOPT_PROXY_TLSAUTH_TYPE,
        CURLoption::CURLOPT_PROXY_SSLCERT,
        CURLoption::CURLOPT_PROXY_SSLCERTTYPE,
        CURLoption::CURLOPT_PROXY_SSLKEY,
        CURLoption::CURLOPT_PROXY_SSLKEYTYPE,
        CURLoption::CURLOPT_PROXY_KEYPASSWD,
        CURLoption::CURLOPT_PROXY_SSL_CIPHER_LIST,
        CURLoption::CURLOPT_PROXY_CRLFILE,
        CURLoption::CURLOPT_PROXY_SSL_OPTIONS,
        CURLoption::CURLOPT_PRE_PROXY,
        CURLoption::CURLOPT_PROXY_PINNEDPUBLICKEY,
        CURLoption::CURLOPT_ABSTRACT_UNIX_SOCKET,
        CURLoption::CURLOPT_SUPPRESS_CONNECT_HEADERS,
        CURLoption::CURLOPT_REQUEST_TARGET,
        CURLoption::CURLOPT_SOCKS5_AUTH,
        CURLoption::CURLOPT_SSH_COMPRESSION,
        CURLoption::CURLOPT_MIMEPOST,
        CURLoption::CURLOPT_TIMEVALUE_LARGE,
        CURLoption::CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS,
        CURLoption::CURLOPT_RESOLVER_START_FUNCTION,
        CURLoption::CURLOPT_RESOLVER_START_DATA,
        CURLoption::CURLOPT_HAPROXYPROTOCOL,
        CURLoption::CURLOPT_DNS_SHUFFLE_ADDRESSES,
        CURLoption::CURLOPT_TLS13_CIPHERS,
        CURLoption::CURLOPT_PROXY_TLS13_CIPHERS,
        CURLoption::CURLOPT_DISALLOW_USERNAME_IN_URL,
        CURLoption::CURLOPT_DOH_URL,
        CURLoption::CURLOPT_UPLOAD_BUFFERSIZE,
        CURLoption::CURLOPT_UPKEEP_INTERVAL_MS,
        CURLoption::CURLOPT_CURLU,
        CURLoption::CURLOPT_TRAILERFUNCTION,
        CURLoption::CURLOPT_TRAILERDATA,
        CURLoption::CURLOPT_HTTP09_ALLOWED,
        CURLoption::CURLOPT_ALTSVC_CTRL,
        CURLoption::CURLOPT_ALTSVC,
        CURLoption::CURLOPT_MAXAGE_CONN,
        CURLoption::CURLOPT_SASL_AUTHZID,
        CURLoption::CURLOPT_MAIL_RCPT_ALLOWFAILS,
        CURLoption::CURLOPT_SSLCERT_BLOB,
        CURLoption::CURLOPT_SSLKEY_BLOB,
        CURLoption::CURLOPT_PROXY_SSLCERT_BLOB,
        CURLoption::CURLOPT_PROXY_SSLKEY_BLOB,
        CURLoption::CURLOPT_ISSUERCERT_BLOB,
        CURLoption::CURLOPT_PROXY_ISSUERCERT,
        CURLoption::CURLOPT_PROXY_ISSUERCERT_BLOB,
        CURLoption::CURLOPT_SSL_EC_CURVES,
        CURLoption::CURLOPT_HSTS_CTRL,
        CURLoption::CURLOPT_HSTS,
        CURLoption::CURLOPT_HSTSREADFUNCTION,
        CURLoption::CURLOPT_HSTSREADDATA,
        CURLoption::CURLOPT_HSTSWRITEFUNCTION,
        CURLoption::CURLOPT_HSTSWRITEDATA,
        CURLoption::CURLOPT_AWS_SIGV4,
        CURLoption::CURLOPT_DOH_SSL_VERIFYPEER,
        CURLoption::CURLOPT_DOH_SSL_VERIFYHOST,
        CURLoption::CURLOPT_DOH_SSL_VERIFYSTATUS,
        CURLoption::CURLOPT_CAINFO_BLOB,
        CURLoption::CURLOPT_PROXY_CAINFO_BLOB,
        CURLoption::CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256,
        CURLoption::CURLOPT_PREREQFUNCTION,
        CURLoption::CURLOPT_PREREQDATA,
        CURLoption::CURLOPT_MAXLIFETIME_CONN,
        CURLoption::CURLOPT_MIME_OPTIONS,
        CURLoption::CURLOPT_SSH_HOSTKEYFUNCTION,
        CURLoption::CURLOPT_SSH_HOSTKEYDATA,
        CURLoption::CURLOPT_PROTOCOLS_STR,
        CURLoption::CURLOPT_REDIR_PROTOCOLS_STR,
        CURLoption::CURLOPT_WS_OPTIONS,
        CURLoption::CURLOPT_CA_CACHE_TIMEOUT,
        CURLoption::CURLOPT_QUICK_EXIT,
        CURLoption::CURLOPT_HAPROXY_CLIENT_IP,
        CURLoption::CURLOPT_SERVER_RESPONSE_TIMEOUT_MS,
        CURLoption::CURLOPT_ECH,
        CURLoption::CURLOPT_TCP_KEEPCNT,
        CURLoption::CURLOPT_UPLOAD_FLAGS,
        CURLoption::CURLOPT_SSL_SIGNATURE_ALGORITHMS,
        CURLoption::CURLOPT_LASTENTRY,
    ];

    /// Number of real options, excluding `CURLOPT_LASTENTRY`. AAP 0.6.1
    /// reconciles this as 291 `CURLOPT(...)` plus 17
    /// `CURLOPTDEPRECATED(...)`.
    #[allow(dead_code)]
    pub(crate) const REAL_COUNT: usize = 308;

    /// The identifier exactly as a C consumer spells it. An exhaustive
    /// `match` rather than a table lookup, so that adding a variant without
    /// giving it a name fails to compile instead of returning a wrong or
    /// placeholder string at run time.
    #[allow(dead_code)]
    pub(crate) fn c_name(self) -> &'static str {
        match self {
            CURLoption::CURLOPT_WRITEDATA => "CURLOPT_WRITEDATA",
            CURLoption::CURLOPT_URL => "CURLOPT_URL",
            CURLoption::CURLOPT_PORT => "CURLOPT_PORT",
            CURLoption::CURLOPT_PROXY => "CURLOPT_PROXY",
            CURLoption::CURLOPT_USERPWD => "CURLOPT_USERPWD",
            CURLoption::CURLOPT_PROXYUSERPWD => "CURLOPT_PROXYUSERPWD",
            CURLoption::CURLOPT_RANGE => "CURLOPT_RANGE",
            CURLoption::CURLOPT_READDATA => "CURLOPT_READDATA",
            CURLoption::CURLOPT_ERRORBUFFER => "CURLOPT_ERRORBUFFER",
            CURLoption::CURLOPT_WRITEFUNCTION => "CURLOPT_WRITEFUNCTION",
            CURLoption::CURLOPT_READFUNCTION => "CURLOPT_READFUNCTION",
            CURLoption::CURLOPT_TIMEOUT => "CURLOPT_TIMEOUT",
            CURLoption::CURLOPT_INFILESIZE => "CURLOPT_INFILESIZE",
            CURLoption::CURLOPT_POSTFIELDS => "CURLOPT_POSTFIELDS",
            CURLoption::CURLOPT_REFERER => "CURLOPT_REFERER",
            CURLoption::CURLOPT_FTPPORT => "CURLOPT_FTPPORT",
            CURLoption::CURLOPT_USERAGENT => "CURLOPT_USERAGENT",
            CURLoption::CURLOPT_LOW_SPEED_LIMIT => "CURLOPT_LOW_SPEED_LIMIT",
            CURLoption::CURLOPT_LOW_SPEED_TIME => "CURLOPT_LOW_SPEED_TIME",
            CURLoption::CURLOPT_RESUME_FROM => "CURLOPT_RESUME_FROM",
            CURLoption::CURLOPT_COOKIE => "CURLOPT_COOKIE",
            CURLoption::CURLOPT_HTTPHEADER => "CURLOPT_HTTPHEADER",
            CURLoption::CURLOPT_HTTPPOST => "CURLOPT_HTTPPOST",
            CURLoption::CURLOPT_SSLCERT => "CURLOPT_SSLCERT",
            CURLoption::CURLOPT_KEYPASSWD => "CURLOPT_KEYPASSWD",
            CURLoption::CURLOPT_CRLF => "CURLOPT_CRLF",
            CURLoption::CURLOPT_QUOTE => "CURLOPT_QUOTE",
            CURLoption::CURLOPT_HEADERDATA => "CURLOPT_HEADERDATA",
            CURLoption::CURLOPT_COOKIEFILE => "CURLOPT_COOKIEFILE",
            CURLoption::CURLOPT_SSLVERSION => "CURLOPT_SSLVERSION",
            CURLoption::CURLOPT_TIMECONDITION => "CURLOPT_TIMECONDITION",
            CURLoption::CURLOPT_TIMEVALUE => "CURLOPT_TIMEVALUE",
            CURLoption::CURLOPT_CUSTOMREQUEST => "CURLOPT_CUSTOMREQUEST",
            CURLoption::CURLOPT_STDERR => "CURLOPT_STDERR",
            CURLoption::CURLOPT_POSTQUOTE => "CURLOPT_POSTQUOTE",
            CURLoption::CURLOPT_VERBOSE => "CURLOPT_VERBOSE",
            CURLoption::CURLOPT_HEADER => "CURLOPT_HEADER",
            CURLoption::CURLOPT_NOPROGRESS => "CURLOPT_NOPROGRESS",
            CURLoption::CURLOPT_NOBODY => "CURLOPT_NOBODY",
            CURLoption::CURLOPT_FAILONERROR => "CURLOPT_FAILONERROR",
            CURLoption::CURLOPT_UPLOAD => "CURLOPT_UPLOAD",
            CURLoption::CURLOPT_POST => "CURLOPT_POST",
            CURLoption::CURLOPT_DIRLISTONLY => "CURLOPT_DIRLISTONLY",
            CURLoption::CURLOPT_APPEND => "CURLOPT_APPEND",
            CURLoption::CURLOPT_NETRC => "CURLOPT_NETRC",
            CURLoption::CURLOPT_FOLLOWLOCATION => "CURLOPT_FOLLOWLOCATION",
            CURLoption::CURLOPT_TRANSFERTEXT => "CURLOPT_TRANSFERTEXT",
            CURLoption::CURLOPT_PUT => "CURLOPT_PUT",
            CURLoption::CURLOPT_PROGRESSFUNCTION => "CURLOPT_PROGRESSFUNCTION",
            CURLoption::CURLOPT_XFERINFODATA => "CURLOPT_XFERINFODATA",
            CURLoption::CURLOPT_AUTOREFERER => "CURLOPT_AUTOREFERER",
            CURLoption::CURLOPT_PROXYPORT => "CURLOPT_PROXYPORT",
            CURLoption::CURLOPT_POSTFIELDSIZE => "CURLOPT_POSTFIELDSIZE",
            CURLoption::CURLOPT_HTTPPROXYTUNNEL => "CURLOPT_HTTPPROXYTUNNEL",
            CURLoption::CURLOPT_INTERFACE => "CURLOPT_INTERFACE",
            CURLoption::CURLOPT_KRBLEVEL => "CURLOPT_KRBLEVEL",
            CURLoption::CURLOPT_SSL_VERIFYPEER => "CURLOPT_SSL_VERIFYPEER",
            CURLoption::CURLOPT_CAINFO => "CURLOPT_CAINFO",
            CURLoption::CURLOPT_MAXREDIRS => "CURLOPT_MAXREDIRS",
            CURLoption::CURLOPT_FILETIME => "CURLOPT_FILETIME",
            CURLoption::CURLOPT_TELNETOPTIONS => "CURLOPT_TELNETOPTIONS",
            CURLoption::CURLOPT_MAXCONNECTS => "CURLOPT_MAXCONNECTS",
            CURLoption::CURLOPT_FRESH_CONNECT => "CURLOPT_FRESH_CONNECT",
            CURLoption::CURLOPT_FORBID_REUSE => "CURLOPT_FORBID_REUSE",
            CURLoption::CURLOPT_RANDOM_FILE => "CURLOPT_RANDOM_FILE",
            CURLoption::CURLOPT_EGDSOCKET => "CURLOPT_EGDSOCKET",
            CURLoption::CURLOPT_CONNECTTIMEOUT => "CURLOPT_CONNECTTIMEOUT",
            CURLoption::CURLOPT_HEADERFUNCTION => "CURLOPT_HEADERFUNCTION",
            CURLoption::CURLOPT_HTTPGET => "CURLOPT_HTTPGET",
            CURLoption::CURLOPT_SSL_VERIFYHOST => "CURLOPT_SSL_VERIFYHOST",
            CURLoption::CURLOPT_COOKIEJAR => "CURLOPT_COOKIEJAR",
            CURLoption::CURLOPT_SSL_CIPHER_LIST => "CURLOPT_SSL_CIPHER_LIST",
            CURLoption::CURLOPT_HTTP_VERSION => "CURLOPT_HTTP_VERSION",
            CURLoption::CURLOPT_FTP_USE_EPSV => "CURLOPT_FTP_USE_EPSV",
            CURLoption::CURLOPT_SSLCERTTYPE => "CURLOPT_SSLCERTTYPE",
            CURLoption::CURLOPT_SSLKEY => "CURLOPT_SSLKEY",
            CURLoption::CURLOPT_SSLKEYTYPE => "CURLOPT_SSLKEYTYPE",
            CURLoption::CURLOPT_SSLENGINE => "CURLOPT_SSLENGINE",
            CURLoption::CURLOPT_SSLENGINE_DEFAULT => {
                "CURLOPT_SSLENGINE_DEFAULT"
            }
            CURLoption::CURLOPT_DNS_USE_GLOBAL_CACHE => {
                "CURLOPT_DNS_USE_GLOBAL_CACHE"
            }
            CURLoption::CURLOPT_DNS_CACHE_TIMEOUT => {
                "CURLOPT_DNS_CACHE_TIMEOUT"
            }
            CURLoption::CURLOPT_PREQUOTE => "CURLOPT_PREQUOTE",
            CURLoption::CURLOPT_DEBUGFUNCTION => "CURLOPT_DEBUGFUNCTION",
            CURLoption::CURLOPT_DEBUGDATA => "CURLOPT_DEBUGDATA",
            CURLoption::CURLOPT_COOKIESESSION => "CURLOPT_COOKIESESSION",
            CURLoption::CURLOPT_CAPATH => "CURLOPT_CAPATH",
            CURLoption::CURLOPT_BUFFERSIZE => "CURLOPT_BUFFERSIZE",
            CURLoption::CURLOPT_NOSIGNAL => "CURLOPT_NOSIGNAL",
            CURLoption::CURLOPT_SHARE => "CURLOPT_SHARE",
            CURLoption::CURLOPT_PROXYTYPE => "CURLOPT_PROXYTYPE",
            CURLoption::CURLOPT_ACCEPT_ENCODING => "CURLOPT_ACCEPT_ENCODING",
            CURLoption::CURLOPT_PRIVATE => "CURLOPT_PRIVATE",
            CURLoption::CURLOPT_HTTP200ALIASES => "CURLOPT_HTTP200ALIASES",
            CURLoption::CURLOPT_UNRESTRICTED_AUTH => {
                "CURLOPT_UNRESTRICTED_AUTH"
            }
            CURLoption::CURLOPT_FTP_USE_EPRT => "CURLOPT_FTP_USE_EPRT",
            CURLoption::CURLOPT_HTTPAUTH => "CURLOPT_HTTPAUTH",
            CURLoption::CURLOPT_SSL_CTX_FUNCTION => "CURLOPT_SSL_CTX_FUNCTION",
            CURLoption::CURLOPT_SSL_CTX_DATA => "CURLOPT_SSL_CTX_DATA",
            CURLoption::CURLOPT_FTP_CREATE_MISSING_DIRS => {
                "CURLOPT_FTP_CREATE_MISSING_DIRS"
            }
            CURLoption::CURLOPT_PROXYAUTH => "CURLOPT_PROXYAUTH",
            CURLoption::CURLOPT_SERVER_RESPONSE_TIMEOUT => {
                "CURLOPT_SERVER_RESPONSE_TIMEOUT"
            }
            CURLoption::CURLOPT_IPRESOLVE => "CURLOPT_IPRESOLVE",
            CURLoption::CURLOPT_MAXFILESIZE => "CURLOPT_MAXFILESIZE",
            CURLoption::CURLOPT_INFILESIZE_LARGE => "CURLOPT_INFILESIZE_LARGE",
            CURLoption::CURLOPT_RESUME_FROM_LARGE => {
                "CURLOPT_RESUME_FROM_LARGE"
            }
            CURLoption::CURLOPT_MAXFILESIZE_LARGE => {
                "CURLOPT_MAXFILESIZE_LARGE"
            }
            CURLoption::CURLOPT_NETRC_FILE => "CURLOPT_NETRC_FILE",
            CURLoption::CURLOPT_USE_SSL => "CURLOPT_USE_SSL",
            CURLoption::CURLOPT_POSTFIELDSIZE_LARGE => {
                "CURLOPT_POSTFIELDSIZE_LARGE"
            }
            CURLoption::CURLOPT_TCP_NODELAY => "CURLOPT_TCP_NODELAY",
            CURLoption::CURLOPT_FTPSSLAUTH => "CURLOPT_FTPSSLAUTH",
            CURLoption::CURLOPT_IOCTLFUNCTION => "CURLOPT_IOCTLFUNCTION",
            CURLoption::CURLOPT_IOCTLDATA => "CURLOPT_IOCTLDATA",
            CURLoption::CURLOPT_FTP_ACCOUNT => "CURLOPT_FTP_ACCOUNT",
            CURLoption::CURLOPT_COOKIELIST => "CURLOPT_COOKIELIST",
            CURLoption::CURLOPT_IGNORE_CONTENT_LENGTH => {
                "CURLOPT_IGNORE_CONTENT_LENGTH"
            }
            CURLoption::CURLOPT_FTP_SKIP_PASV_IP => "CURLOPT_FTP_SKIP_PASV_IP",
            CURLoption::CURLOPT_FTP_FILEMETHOD => "CURLOPT_FTP_FILEMETHOD",
            CURLoption::CURLOPT_LOCALPORT => "CURLOPT_LOCALPORT",
            CURLoption::CURLOPT_LOCALPORTRANGE => "CURLOPT_LOCALPORTRANGE",
            CURLoption::CURLOPT_CONNECT_ONLY => "CURLOPT_CONNECT_ONLY",
            CURLoption::CURLOPT_CONV_FROM_NETWORK_FUNCTION => {
                "CURLOPT_CONV_FROM_NETWORK_FUNCTION"
            }
            CURLoption::CURLOPT_CONV_TO_NETWORK_FUNCTION => {
                "CURLOPT_CONV_TO_NETWORK_FUNCTION"
            }
            CURLoption::CURLOPT_CONV_FROM_UTF8_FUNCTION => {
                "CURLOPT_CONV_FROM_UTF8_FUNCTION"
            }
            CURLoption::CURLOPT_MAX_SEND_SPEED_LARGE => {
                "CURLOPT_MAX_SEND_SPEED_LARGE"
            }
            CURLoption::CURLOPT_MAX_RECV_SPEED_LARGE => {
                "CURLOPT_MAX_RECV_SPEED_LARGE"
            }
            CURLoption::CURLOPT_FTP_ALTERNATIVE_TO_USER => {
                "CURLOPT_FTP_ALTERNATIVE_TO_USER"
            }
            CURLoption::CURLOPT_SOCKOPTFUNCTION => "CURLOPT_SOCKOPTFUNCTION",
            CURLoption::CURLOPT_SOCKOPTDATA => "CURLOPT_SOCKOPTDATA",
            CURLoption::CURLOPT_SSL_SESSIONID_CACHE => {
                "CURLOPT_SSL_SESSIONID_CACHE"
            }
            CURLoption::CURLOPT_SSH_AUTH_TYPES => "CURLOPT_SSH_AUTH_TYPES",
            CURLoption::CURLOPT_SSH_PUBLIC_KEYFILE => {
                "CURLOPT_SSH_PUBLIC_KEYFILE"
            }
            CURLoption::CURLOPT_SSH_PRIVATE_KEYFILE => {
                "CURLOPT_SSH_PRIVATE_KEYFILE"
            }
            CURLoption::CURLOPT_FTP_SSL_CCC => "CURLOPT_FTP_SSL_CCC",
            CURLoption::CURLOPT_TIMEOUT_MS => "CURLOPT_TIMEOUT_MS",
            CURLoption::CURLOPT_CONNECTTIMEOUT_MS => {
                "CURLOPT_CONNECTTIMEOUT_MS"
            }
            CURLoption::CURLOPT_HTTP_TRANSFER_DECODING => {
                "CURLOPT_HTTP_TRANSFER_DECODING"
            }
            CURLoption::CURLOPT_HTTP_CONTENT_DECODING => {
                "CURLOPT_HTTP_CONTENT_DECODING"
            }
            CURLoption::CURLOPT_NEW_FILE_PERMS => "CURLOPT_NEW_FILE_PERMS",
            CURLoption::CURLOPT_NEW_DIRECTORY_PERMS => {
                "CURLOPT_NEW_DIRECTORY_PERMS"
            }
            CURLoption::CURLOPT_POSTREDIR => "CURLOPT_POSTREDIR",
            CURLoption::CURLOPT_SSH_HOST_PUBLIC_KEY_MD5 => {
                "CURLOPT_SSH_HOST_PUBLIC_KEY_MD5"
            }
            CURLoption::CURLOPT_OPENSOCKETFUNCTION => {
                "CURLOPT_OPENSOCKETFUNCTION"
            }
            CURLoption::CURLOPT_OPENSOCKETDATA => "CURLOPT_OPENSOCKETDATA",
            CURLoption::CURLOPT_COPYPOSTFIELDS => "CURLOPT_COPYPOSTFIELDS",
            CURLoption::CURLOPT_PROXY_TRANSFER_MODE => {
                "CURLOPT_PROXY_TRANSFER_MODE"
            }
            CURLoption::CURLOPT_SEEKFUNCTION => "CURLOPT_SEEKFUNCTION",
            CURLoption::CURLOPT_SEEKDATA => "CURLOPT_SEEKDATA",
            CURLoption::CURLOPT_CRLFILE => "CURLOPT_CRLFILE",
            CURLoption::CURLOPT_ISSUERCERT => "CURLOPT_ISSUERCERT",
            CURLoption::CURLOPT_ADDRESS_SCOPE => "CURLOPT_ADDRESS_SCOPE",
            CURLoption::CURLOPT_CERTINFO => "CURLOPT_CERTINFO",
            CURLoption::CURLOPT_USERNAME => "CURLOPT_USERNAME",
            CURLoption::CURLOPT_PASSWORD => "CURLOPT_PASSWORD",
            CURLoption::CURLOPT_PROXYUSERNAME => "CURLOPT_PROXYUSERNAME",
            CURLoption::CURLOPT_PROXYPASSWORD => "CURLOPT_PROXYPASSWORD",
            CURLoption::CURLOPT_NOPROXY => "CURLOPT_NOPROXY",
            CURLoption::CURLOPT_TFTP_BLKSIZE => "CURLOPT_TFTP_BLKSIZE",
            CURLoption::CURLOPT_SOCKS5_GSSAPI_SERVICE => {
                "CURLOPT_SOCKS5_GSSAPI_SERVICE"
            }
            CURLoption::CURLOPT_SOCKS5_GSSAPI_NEC => {
                "CURLOPT_SOCKS5_GSSAPI_NEC"
            }
            CURLoption::CURLOPT_PROTOCOLS => "CURLOPT_PROTOCOLS",
            CURLoption::CURLOPT_REDIR_PROTOCOLS => "CURLOPT_REDIR_PROTOCOLS",
            CURLoption::CURLOPT_SSH_KNOWNHOSTS => "CURLOPT_SSH_KNOWNHOSTS",
            CURLoption::CURLOPT_SSH_KEYFUNCTION => "CURLOPT_SSH_KEYFUNCTION",
            CURLoption::CURLOPT_SSH_KEYDATA => "CURLOPT_SSH_KEYDATA",
            CURLoption::CURLOPT_MAIL_FROM => "CURLOPT_MAIL_FROM",
            CURLoption::CURLOPT_MAIL_RCPT => "CURLOPT_MAIL_RCPT",
            CURLoption::CURLOPT_FTP_USE_PRET => "CURLOPT_FTP_USE_PRET",
            CURLoption::CURLOPT_RTSP_REQUEST => "CURLOPT_RTSP_REQUEST",
            CURLoption::CURLOPT_RTSP_SESSION_ID => "CURLOPT_RTSP_SESSION_ID",
            CURLoption::CURLOPT_RTSP_STREAM_URI => "CURLOPT_RTSP_STREAM_URI",
            CURLoption::CURLOPT_RTSP_TRANSPORT => "CURLOPT_RTSP_TRANSPORT",
            CURLoption::CURLOPT_RTSP_CLIENT_CSEQ => "CURLOPT_RTSP_CLIENT_CSEQ",
            CURLoption::CURLOPT_RTSP_SERVER_CSEQ => "CURLOPT_RTSP_SERVER_CSEQ",
            CURLoption::CURLOPT_INTERLEAVEDATA => "CURLOPT_INTERLEAVEDATA",
            CURLoption::CURLOPT_INTERLEAVEFUNCTION => {
                "CURLOPT_INTERLEAVEFUNCTION"
            }
            CURLoption::CURLOPT_WILDCARDMATCH => "CURLOPT_WILDCARDMATCH",
            CURLoption::CURLOPT_CHUNK_BGN_FUNCTION => {
                "CURLOPT_CHUNK_BGN_FUNCTION"
            }
            CURLoption::CURLOPT_CHUNK_END_FUNCTION => {
                "CURLOPT_CHUNK_END_FUNCTION"
            }
            CURLoption::CURLOPT_FNMATCH_FUNCTION => "CURLOPT_FNMATCH_FUNCTION",
            CURLoption::CURLOPT_CHUNK_DATA => "CURLOPT_CHUNK_DATA",
            CURLoption::CURLOPT_FNMATCH_DATA => "CURLOPT_FNMATCH_DATA",
            CURLoption::CURLOPT_RESOLVE => "CURLOPT_RESOLVE",
            CURLoption::CURLOPT_TLSAUTH_USERNAME => "CURLOPT_TLSAUTH_USERNAME",
            CURLoption::CURLOPT_TLSAUTH_PASSWORD => "CURLOPT_TLSAUTH_PASSWORD",
            CURLoption::CURLOPT_TLSAUTH_TYPE => "CURLOPT_TLSAUTH_TYPE",
            CURLoption::CURLOPT_TRANSFER_ENCODING => {
                "CURLOPT_TRANSFER_ENCODING"
            }
            CURLoption::CURLOPT_CLOSESOCKETFUNCTION => {
                "CURLOPT_CLOSESOCKETFUNCTION"
            }
            CURLoption::CURLOPT_CLOSESOCKETDATA => "CURLOPT_CLOSESOCKETDATA",
            CURLoption::CURLOPT_GSSAPI_DELEGATION => {
                "CURLOPT_GSSAPI_DELEGATION"
            }
            CURLoption::CURLOPT_DNS_SERVERS => "CURLOPT_DNS_SERVERS",
            CURLoption::CURLOPT_ACCEPTTIMEOUT_MS => "CURLOPT_ACCEPTTIMEOUT_MS",
            CURLoption::CURLOPT_TCP_KEEPALIVE => "CURLOPT_TCP_KEEPALIVE",
            CURLoption::CURLOPT_TCP_KEEPIDLE => "CURLOPT_TCP_KEEPIDLE",
            CURLoption::CURLOPT_TCP_KEEPINTVL => "CURLOPT_TCP_KEEPINTVL",
            CURLoption::CURLOPT_SSL_OPTIONS => "CURLOPT_SSL_OPTIONS",
            CURLoption::CURLOPT_MAIL_AUTH => "CURLOPT_MAIL_AUTH",
            CURLoption::CURLOPT_SASL_IR => "CURLOPT_SASL_IR",
            CURLoption::CURLOPT_XFERINFOFUNCTION => "CURLOPT_XFERINFOFUNCTION",
            CURLoption::CURLOPT_XOAUTH2_BEARER => "CURLOPT_XOAUTH2_BEARER",
            CURLoption::CURLOPT_DNS_INTERFACE => "CURLOPT_DNS_INTERFACE",
            CURLoption::CURLOPT_DNS_LOCAL_IP4 => "CURLOPT_DNS_LOCAL_IP4",
            CURLoption::CURLOPT_DNS_LOCAL_IP6 => "CURLOPT_DNS_LOCAL_IP6",
            CURLoption::CURLOPT_LOGIN_OPTIONS => "CURLOPT_LOGIN_OPTIONS",
            CURLoption::CURLOPT_SSL_ENABLE_NPN => "CURLOPT_SSL_ENABLE_NPN",
            CURLoption::CURLOPT_SSL_ENABLE_ALPN => "CURLOPT_SSL_ENABLE_ALPN",
            CURLoption::CURLOPT_EXPECT_100_TIMEOUT_MS => {
                "CURLOPT_EXPECT_100_TIMEOUT_MS"
            }
            CURLoption::CURLOPT_PROXYHEADER => "CURLOPT_PROXYHEADER",
            CURLoption::CURLOPT_HEADEROPT => "CURLOPT_HEADEROPT",
            CURLoption::CURLOPT_PINNEDPUBLICKEY => "CURLOPT_PINNEDPUBLICKEY",
            CURLoption::CURLOPT_UNIX_SOCKET_PATH => "CURLOPT_UNIX_SOCKET_PATH",
            CURLoption::CURLOPT_SSL_VERIFYSTATUS => "CURLOPT_SSL_VERIFYSTATUS",
            CURLoption::CURLOPT_SSL_FALSESTART => "CURLOPT_SSL_FALSESTART",
            CURLoption::CURLOPT_PATH_AS_IS => "CURLOPT_PATH_AS_IS",
            CURLoption::CURLOPT_PROXY_SERVICE_NAME => {
                "CURLOPT_PROXY_SERVICE_NAME"
            }
            CURLoption::CURLOPT_SERVICE_NAME => "CURLOPT_SERVICE_NAME",
            CURLoption::CURLOPT_PIPEWAIT => "CURLOPT_PIPEWAIT",
            CURLoption::CURLOPT_DEFAULT_PROTOCOL => "CURLOPT_DEFAULT_PROTOCOL",
            CURLoption::CURLOPT_STREAM_WEIGHT => "CURLOPT_STREAM_WEIGHT",
            CURLoption::CURLOPT_STREAM_DEPENDS => "CURLOPT_STREAM_DEPENDS",
            CURLoption::CURLOPT_STREAM_DEPENDS_E => "CURLOPT_STREAM_DEPENDS_E",
            CURLoption::CURLOPT_TFTP_NO_OPTIONS => "CURLOPT_TFTP_NO_OPTIONS",
            CURLoption::CURLOPT_CONNECT_TO => "CURLOPT_CONNECT_TO",
            CURLoption::CURLOPT_TCP_FASTOPEN => "CURLOPT_TCP_FASTOPEN",
            CURLoption::CURLOPT_KEEP_SENDING_ON_ERROR => {
                "CURLOPT_KEEP_SENDING_ON_ERROR"
            }
            CURLoption::CURLOPT_PROXY_CAINFO => "CURLOPT_PROXY_CAINFO",
            CURLoption::CURLOPT_PROXY_CAPATH => "CURLOPT_PROXY_CAPATH",
            CURLoption::CURLOPT_PROXY_SSL_VERIFYPEER => {
                "CURLOPT_PROXY_SSL_VERIFYPEER"
            }
            CURLoption::CURLOPT_PROXY_SSL_VERIFYHOST => {
                "CURLOPT_PROXY_SSL_VERIFYHOST"
            }
            CURLoption::CURLOPT_PROXY_SSLVERSION => "CURLOPT_PROXY_SSLVERSION",
            CURLoption::CURLOPT_PROXY_TLSAUTH_USERNAME => {
                "CURLOPT_PROXY_TLSAUTH_USERNAME"
            }
            CURLoption::CURLOPT_PROXY_TLSAUTH_PASSWORD => {
                "CURLOPT_PROXY_TLSAUTH_PASSWORD"
            }
            CURLoption::CURLOPT_PROXY_TLSAUTH_TYPE => {
                "CURLOPT_PROXY_TLSAUTH_TYPE"
            }
            CURLoption::CURLOPT_PROXY_SSLCERT => "CURLOPT_PROXY_SSLCERT",
            CURLoption::CURLOPT_PROXY_SSLCERTTYPE => {
                "CURLOPT_PROXY_SSLCERTTYPE"
            }
            CURLoption::CURLOPT_PROXY_SSLKEY => "CURLOPT_PROXY_SSLKEY",
            CURLoption::CURLOPT_PROXY_SSLKEYTYPE => "CURLOPT_PROXY_SSLKEYTYPE",
            CURLoption::CURLOPT_PROXY_KEYPASSWD => "CURLOPT_PROXY_KEYPASSWD",
            CURLoption::CURLOPT_PROXY_SSL_CIPHER_LIST => {
                "CURLOPT_PROXY_SSL_CIPHER_LIST"
            }
            CURLoption::CURLOPT_PROXY_CRLFILE => "CURLOPT_PROXY_CRLFILE",
            CURLoption::CURLOPT_PROXY_SSL_OPTIONS => {
                "CURLOPT_PROXY_SSL_OPTIONS"
            }
            CURLoption::CURLOPT_PRE_PROXY => "CURLOPT_PRE_PROXY",
            CURLoption::CURLOPT_PROXY_PINNEDPUBLICKEY => {
                "CURLOPT_PROXY_PINNEDPUBLICKEY"
            }
            CURLoption::CURLOPT_ABSTRACT_UNIX_SOCKET => {
                "CURLOPT_ABSTRACT_UNIX_SOCKET"
            }
            CURLoption::CURLOPT_SUPPRESS_CONNECT_HEADERS => {
                "CURLOPT_SUPPRESS_CONNECT_HEADERS"
            }
            CURLoption::CURLOPT_REQUEST_TARGET => "CURLOPT_REQUEST_TARGET",
            CURLoption::CURLOPT_SOCKS5_AUTH => "CURLOPT_SOCKS5_AUTH",
            CURLoption::CURLOPT_SSH_COMPRESSION => "CURLOPT_SSH_COMPRESSION",
            CURLoption::CURLOPT_MIMEPOST => "CURLOPT_MIMEPOST",
            CURLoption::CURLOPT_TIMEVALUE_LARGE => "CURLOPT_TIMEVALUE_LARGE",
            CURLoption::CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS => {
                "CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS"
            }
            CURLoption::CURLOPT_RESOLVER_START_FUNCTION => {
                "CURLOPT_RESOLVER_START_FUNCTION"
            }
            CURLoption::CURLOPT_RESOLVER_START_DATA => {
                "CURLOPT_RESOLVER_START_DATA"
            }
            CURLoption::CURLOPT_HAPROXYPROTOCOL => "CURLOPT_HAPROXYPROTOCOL",
            CURLoption::CURLOPT_DNS_SHUFFLE_ADDRESSES => {
                "CURLOPT_DNS_SHUFFLE_ADDRESSES"
            }
            CURLoption::CURLOPT_TLS13_CIPHERS => "CURLOPT_TLS13_CIPHERS",
            CURLoption::CURLOPT_PROXY_TLS13_CIPHERS => {
                "CURLOPT_PROXY_TLS13_CIPHERS"
            }
            CURLoption::CURLOPT_DISALLOW_USERNAME_IN_URL => {
                "CURLOPT_DISALLOW_USERNAME_IN_URL"
            }
            CURLoption::CURLOPT_DOH_URL => "CURLOPT_DOH_URL",
            CURLoption::CURLOPT_UPLOAD_BUFFERSIZE => {
                "CURLOPT_UPLOAD_BUFFERSIZE"
            }
            CURLoption::CURLOPT_UPKEEP_INTERVAL_MS => {
                "CURLOPT_UPKEEP_INTERVAL_MS"
            }
            CURLoption::CURLOPT_CURLU => "CURLOPT_CURLU",
            CURLoption::CURLOPT_TRAILERFUNCTION => "CURLOPT_TRAILERFUNCTION",
            CURLoption::CURLOPT_TRAILERDATA => "CURLOPT_TRAILERDATA",
            CURLoption::CURLOPT_HTTP09_ALLOWED => "CURLOPT_HTTP09_ALLOWED",
            CURLoption::CURLOPT_ALTSVC_CTRL => "CURLOPT_ALTSVC_CTRL",
            CURLoption::CURLOPT_ALTSVC => "CURLOPT_ALTSVC",
            CURLoption::CURLOPT_MAXAGE_CONN => "CURLOPT_MAXAGE_CONN",
            CURLoption::CURLOPT_SASL_AUTHZID => "CURLOPT_SASL_AUTHZID",
            CURLoption::CURLOPT_MAIL_RCPT_ALLOWFAILS => {
                "CURLOPT_MAIL_RCPT_ALLOWFAILS"
            }
            CURLoption::CURLOPT_SSLCERT_BLOB => "CURLOPT_SSLCERT_BLOB",
            CURLoption::CURLOPT_SSLKEY_BLOB => "CURLOPT_SSLKEY_BLOB",
            CURLoption::CURLOPT_PROXY_SSLCERT_BLOB => {
                "CURLOPT_PROXY_SSLCERT_BLOB"
            }
            CURLoption::CURLOPT_PROXY_SSLKEY_BLOB => {
                "CURLOPT_PROXY_SSLKEY_BLOB"
            }
            CURLoption::CURLOPT_ISSUERCERT_BLOB => "CURLOPT_ISSUERCERT_BLOB",
            CURLoption::CURLOPT_PROXY_ISSUERCERT => "CURLOPT_PROXY_ISSUERCERT",
            CURLoption::CURLOPT_PROXY_ISSUERCERT_BLOB => {
                "CURLOPT_PROXY_ISSUERCERT_BLOB"
            }
            CURLoption::CURLOPT_SSL_EC_CURVES => "CURLOPT_SSL_EC_CURVES",
            CURLoption::CURLOPT_HSTS_CTRL => "CURLOPT_HSTS_CTRL",
            CURLoption::CURLOPT_HSTS => "CURLOPT_HSTS",
            CURLoption::CURLOPT_HSTSREADFUNCTION => "CURLOPT_HSTSREADFUNCTION",
            CURLoption::CURLOPT_HSTSREADDATA => "CURLOPT_HSTSREADDATA",
            CURLoption::CURLOPT_HSTSWRITEFUNCTION => {
                "CURLOPT_HSTSWRITEFUNCTION"
            }
            CURLoption::CURLOPT_HSTSWRITEDATA => "CURLOPT_HSTSWRITEDATA",
            CURLoption::CURLOPT_AWS_SIGV4 => "CURLOPT_AWS_SIGV4",
            CURLoption::CURLOPT_DOH_SSL_VERIFYPEER => {
                "CURLOPT_DOH_SSL_VERIFYPEER"
            }
            CURLoption::CURLOPT_DOH_SSL_VERIFYHOST => {
                "CURLOPT_DOH_SSL_VERIFYHOST"
            }
            CURLoption::CURLOPT_DOH_SSL_VERIFYSTATUS => {
                "CURLOPT_DOH_SSL_VERIFYSTATUS"
            }
            CURLoption::CURLOPT_CAINFO_BLOB => "CURLOPT_CAINFO_BLOB",
            CURLoption::CURLOPT_PROXY_CAINFO_BLOB => {
                "CURLOPT_PROXY_CAINFO_BLOB"
            }
            CURLoption::CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256 => {
                "CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256"
            }
            CURLoption::CURLOPT_PREREQFUNCTION => "CURLOPT_PREREQFUNCTION",
            CURLoption::CURLOPT_PREREQDATA => "CURLOPT_PREREQDATA",
            CURLoption::CURLOPT_MAXLIFETIME_CONN => "CURLOPT_MAXLIFETIME_CONN",
            CURLoption::CURLOPT_MIME_OPTIONS => "CURLOPT_MIME_OPTIONS",
            CURLoption::CURLOPT_SSH_HOSTKEYFUNCTION => {
                "CURLOPT_SSH_HOSTKEYFUNCTION"
            }
            CURLoption::CURLOPT_SSH_HOSTKEYDATA => "CURLOPT_SSH_HOSTKEYDATA",
            CURLoption::CURLOPT_PROTOCOLS_STR => "CURLOPT_PROTOCOLS_STR",
            CURLoption::CURLOPT_REDIR_PROTOCOLS_STR => {
                "CURLOPT_REDIR_PROTOCOLS_STR"
            }
            CURLoption::CURLOPT_WS_OPTIONS => "CURLOPT_WS_OPTIONS",
            CURLoption::CURLOPT_CA_CACHE_TIMEOUT => "CURLOPT_CA_CACHE_TIMEOUT",
            CURLoption::CURLOPT_QUICK_EXIT => "CURLOPT_QUICK_EXIT",
            CURLoption::CURLOPT_HAPROXY_CLIENT_IP => {
                "CURLOPT_HAPROXY_CLIENT_IP"
            }
            CURLoption::CURLOPT_SERVER_RESPONSE_TIMEOUT_MS => {
                "CURLOPT_SERVER_RESPONSE_TIMEOUT_MS"
            }
            CURLoption::CURLOPT_ECH => "CURLOPT_ECH",
            CURLoption::CURLOPT_TCP_KEEPCNT => "CURLOPT_TCP_KEEPCNT",
            CURLoption::CURLOPT_UPLOAD_FLAGS => "CURLOPT_UPLOAD_FLAGS",
            CURLoption::CURLOPT_SSL_SIGNATURE_ALGORITHMS => {
                "CURLOPT_SSL_SIGNATURE_ALGORITHMS"
            }
            CURLoption::CURLOPT_LASTENTRY => "CURLOPT_LASTENTRY",
        }
    }

    /// The pinned integer, as it crosses the C boundary.
    #[allow(dead_code)]
    pub(crate) fn as_c_int(self) -> i32 {
        self as i32
    }

    /// Recover an option from the integer a C caller passed. Returns `None`
    /// for an unknown value; a caller that maps `None` onto
    /// `CURLE_UNKNOWN_OPTION` reproduces curl's own behaviour for an option
    /// the library does not recognise.
    #[allow(dead_code)]
    pub(crate) fn from_c_int(value: i32) -> Option<CURLoption> {
        CURLoption::ABI_VARIANTS
            .iter()
            .copied()
            .find(|candidate| candidate.as_c_int() == value)
    }

    /// The `CURLOPTTYPE_*` base this option was composed from. Recoverable
    /// by division because every ordinal is well under 10000: the largest
    /// is 329.
    #[allow(dead_code)]
    pub(crate) fn type_base(self) -> i32 {
        (self as i32) / 10_000 * 10_000
    }

    /// The ordinal this option was composed with -- the third argument to
    /// the `CURLOPT` macro in the frozen header.
    #[allow(dead_code)]
    pub(crate) fn type_ordinal(self) -> i32 {
        (self as i32) % 10_000
    }

    /// The declared value type, from the metadata table. `None` only for
    /// `CURLOPT_LASTENTRY`, whose row is the table sentinel.
    /// This cannot be derived from [`CURLoption::type_base`]:
    /// `CURLOPTTYPE_OBJECTPOINT`, `CURLOPTTYPE_STRINGPOINT`,
    /// `CURLOPTTYPE_SLISTPOINT` and `CURLOPTTYPE_CBPOINT` all equal 10000,
    /// so four distinct `curl_easytype` values share one base. The type has
    /// to be carried per row, which is why the table exists.
    #[allow(dead_code)]
    pub(crate) fn easy_type(self) -> Option<curl_easytype> {
        EASY_OPTIONS
            .iter()
            .find(|row| row.id == self && row.is_true_option())
            .map(|row| row.value_type)
    }
}

// The 19 `#define CURLOPT_*` aliases.
//
// Held here so the parity assertion AAP 0.1.2 requires has something to
// assert against, and NOT exported: the emitted form has to keep its
// `#ifndef CURL_NO_OLDIES` guards, which cbindgen cannot produce, so the
// guarded blocks are carried verbatim. See the module documentation.

/// One `#define CURLOPT_<old> <new>` line from the frozen header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct OptionAlias {
    /// The retired spelling a C program may still use.
    pub(crate) alias: &'static str,
    /// The token the alias expands to, verbatim from the frozen header.
    pub(crate) target: &'static str,
    /// The option the alias resolves to, or `None` when the target is a
    /// bare integer rather than an enumerator.
    pub(crate) resolves_to: Option<CURLoption>,
    /// The integer a C consumer ends up with either way.
    pub(crate) value: i32,
}

/// All 19 aliases. 15 expand to an enumerator and 2 to the bare integer
/// 9999; the remaining 2 expand to one of those two numeric names. Setting
/// aside the 2 numeric slots and the 2 aliases pointing at them leaves the
/// 15 alias rows the upstream metadata table carries, which is why it holds
/// fewer rows than there are aliases. Asserted by test.
#[allow(dead_code)]
pub(crate) const OPTION_ALIASES: &[OptionAlias] = &[
    OptionAlias {
        alias: "CURLOPT_ENCODING",
        target: "CURLOPT_ACCEPT_ENCODING",
        resolves_to: Some(CURLoption::CURLOPT_ACCEPT_ENCODING),
        value: 10102,
    },
    OptionAlias {
        alias: "CURLOPT_FILE",
        target: "CURLOPT_WRITEDATA",
        resolves_to: Some(CURLoption::CURLOPT_WRITEDATA),
        value: 10001,
    },
    OptionAlias {
        alias: "CURLOPT_INFILE",
        target: "CURLOPT_READDATA",
        resolves_to: Some(CURLoption::CURLOPT_READDATA),
        value: 10009,
    },
    OptionAlias {
        alias: "CURLOPT_WRITEHEADER",
        target: "CURLOPT_HEADERDATA",
        resolves_to: Some(CURLoption::CURLOPT_HEADERDATA),
        value: 10029,
    },
    OptionAlias {
        alias: "CURLOPT_WRITEINFO",
        target: "CURLOPT_OBSOLETE40",
        resolves_to: None,
        value: 9999,
    },
    OptionAlias {
        alias: "CURLOPT_CLOSEPOLICY",
        target: "CURLOPT_OBSOLETE72",
        resolves_to: None,
        value: 9999,
    },
    OptionAlias {
        alias: "CURLOPT_OBSOLETE72",
        target: "9999",
        resolves_to: None,
        value: 9999,
    },
    OptionAlias {
        alias: "CURLOPT_OBSOLETE40",
        target: "9999",
        resolves_to: None,
        value: 9999,
    },
    OptionAlias {
        alias: "CURLOPT_PROGRESSDATA",
        target: "CURLOPT_XFERINFODATA",
        resolves_to: Some(CURLoption::CURLOPT_XFERINFODATA),
        value: 10057,
    },
    OptionAlias {
        alias: "CURLOPT_POST301",
        target: "CURLOPT_POSTREDIR",
        resolves_to: Some(CURLoption::CURLOPT_POSTREDIR),
        value: 161,
    },
    OptionAlias {
        alias: "CURLOPT_SSLKEYPASSWD",
        target: "CURLOPT_KEYPASSWD",
        resolves_to: Some(CURLoption::CURLOPT_KEYPASSWD),
        value: 10026,
    },
    OptionAlias {
        alias: "CURLOPT_FTPAPPEND",
        target: "CURLOPT_APPEND",
        resolves_to: Some(CURLoption::CURLOPT_APPEND),
        value: 50,
    },
    OptionAlias {
        alias: "CURLOPT_FTPLISTONLY",
        target: "CURLOPT_DIRLISTONLY",
        resolves_to: Some(CURLoption::CURLOPT_DIRLISTONLY),
        value: 48,
    },
    OptionAlias {
        alias: "CURLOPT_FTP_SSL",
        target: "CURLOPT_USE_SSL",
        resolves_to: Some(CURLoption::CURLOPT_USE_SSL),
        value: 119,
    },
    OptionAlias {
        alias: "CURLOPT_SSLCERTPASSWD",
        target: "CURLOPT_KEYPASSWD",
        resolves_to: Some(CURLoption::CURLOPT_KEYPASSWD),
        value: 10026,
    },
    OptionAlias {
        alias: "CURLOPT_KRB4LEVEL",
        target: "CURLOPT_KRBLEVEL",
        resolves_to: Some(CURLoption::CURLOPT_KRBLEVEL),
        value: 10063,
    },
    OptionAlias {
        alias: "CURLOPT_FTP_RESPONSE_TIMEOUT",
        target: "CURLOPT_SERVER_RESPONSE_TIMEOUT",
        resolves_to: Some(CURLoption::CURLOPT_SERVER_RESPONSE_TIMEOUT),
        value: 112,
    },
    OptionAlias {
        alias: "CURLOPT_MAIL_RCPT_ALLLOWFAILS",
        target: "CURLOPT_MAIL_RCPT_ALLOWFAILS",
        resolves_to: Some(CURLoption::CURLOPT_MAIL_RCPT_ALLOWFAILS),
        value: 290,
    },
    OptionAlias {
        alias: "CURLOPT_RTSPHEADER",
        target: "CURLOPT_HTTPHEADER",
        resolves_to: Some(CURLoption::CURLOPT_HTTPHEADER),
        value: 10023,
    },
];

// The `curl_easyoption` metadata array.
//
// `struct curl_easyoption` itself is pinned verbatim (build.rs:849)
// because it is layout-visible, so this is the Rust-side authority that
// populates it rather than a redeclaration of it. Names are stored
// NUL-terminated so the exported introspection functions can hand out
// `*const c_char` without allocating or copying.
//
// Row order is `lib/optiontable.pl`'s: alphabetical by the STRIPPED
// name, with the sentinel last. `curl_easy_option_next` walks this array
// in order and a consumer may rely on that order, so it is preserved
// exactly rather than re-sorted.

/// One row of the option metadata table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct EasyOptionRow {
    /// The option name WITHOUT its `CURLOPT_` prefix, NUL-terminated.
    /// `None` marks the terminating sentinel, whose C `name` is NULL.
    pub(crate) name: Option<&'static [u8]>,
    /// The option this row describes. For an alias row this is the
    /// PREFERRED option, not the retired one the `name` spells.
    pub(crate) id: CURLoption,
    /// The declared value type.
    pub(crate) value_type: curl_easytype,
    /// `CURLOT_FLAG_ALIAS`, or zero.
    pub(crate) flags: c_uint,
}

impl EasyOptionRow {
    /// True when this row exists only for backward compatibility.
    ///
    /// `const` so that the row counts below can be COMPUTED from the table
    /// rather than transcribed beside it.
    #[allow(dead_code)]
    pub(crate) const fn is_alias(&self) -> bool {
        self.flags & CURLOT_FLAG_ALIAS != 0
    }

    /// True for a real, preferred option row -- neither an alias nor the
    /// sentinel.
    #[allow(dead_code)]
    pub(crate) const fn is_true_option(&self) -> bool {
        self.name.is_some() && !self.is_alias()
    }

    /// The name with its terminating NUL removed, for Rust-side comparison.
    /// `None` for the sentinel.
    #[allow(dead_code)]
    pub(crate) fn name_str(&self) -> Option<&'static str> {
        let bytes = self.name?;
        let trimmed = &bytes[..bytes.len() - 1];
        core::str::from_utf8(trimmed).ok()
    }
}

/// The table: 324 rows = 1 sentinel + 15 alias + 308 true options. The true
/// rows cover the enumeration exactly, which is the cross-population bridge
/// described in the module documentation.
#[allow(dead_code)]
pub(crate) const EASY_OPTIONS: &[EasyOptionRow] = &[
    EasyOptionRow {
        name: Some(b"ABSTRACT_UNIX_SOCKET\0"),
        id: CURLoption::CURLOPT_ABSTRACT_UNIX_SOCKET,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"ACCEPTTIMEOUT_MS\0"),
        id: CURLoption::CURLOPT_ACCEPTTIMEOUT_MS,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"ACCEPT_ENCODING\0"),
        id: CURLoption::CURLOPT_ACCEPT_ENCODING,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"ADDRESS_SCOPE\0"),
        id: CURLoption::CURLOPT_ADDRESS_SCOPE,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"ALTSVC\0"),
        id: CURLoption::CURLOPT_ALTSVC,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"ALTSVC_CTRL\0"),
        id: CURLoption::CURLOPT_ALTSVC_CTRL,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"APPEND\0"),
        id: CURLoption::CURLOPT_APPEND,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"AUTOREFERER\0"),
        id: CURLoption::CURLOPT_AUTOREFERER,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"AWS_SIGV4\0"),
        id: CURLoption::CURLOPT_AWS_SIGV4,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"BUFFERSIZE\0"),
        id: CURLoption::CURLOPT_BUFFERSIZE,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"CAINFO\0"),
        id: CURLoption::CURLOPT_CAINFO,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"CAINFO_BLOB\0"),
        id: CURLoption::CURLOPT_CAINFO_BLOB,
        value_type: curl_easytype::CURLOT_BLOB,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"CAPATH\0"),
        id: CURLoption::CURLOPT_CAPATH,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"CA_CACHE_TIMEOUT\0"),
        id: CURLoption::CURLOPT_CA_CACHE_TIMEOUT,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"CERTINFO\0"),
        id: CURLoption::CURLOPT_CERTINFO,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"CHUNK_BGN_FUNCTION\0"),
        id: CURLoption::CURLOPT_CHUNK_BGN_FUNCTION,
        value_type: curl_easytype::CURLOT_FUNCTION,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"CHUNK_DATA\0"),
        id: CURLoption::CURLOPT_CHUNK_DATA,
        value_type: curl_easytype::CURLOT_CBPTR,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"CHUNK_END_FUNCTION\0"),
        id: CURLoption::CURLOPT_CHUNK_END_FUNCTION,
        value_type: curl_easytype::CURLOT_FUNCTION,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"CLOSESOCKETDATA\0"),
        id: CURLoption::CURLOPT_CLOSESOCKETDATA,
        value_type: curl_easytype::CURLOT_CBPTR,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"CLOSESOCKETFUNCTION\0"),
        id: CURLoption::CURLOPT_CLOSESOCKETFUNCTION,
        value_type: curl_easytype::CURLOT_FUNCTION,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"CONNECTTIMEOUT\0"),
        id: CURLoption::CURLOPT_CONNECTTIMEOUT,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"CONNECTTIMEOUT_MS\0"),
        id: CURLoption::CURLOPT_CONNECTTIMEOUT_MS,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"CONNECT_ONLY\0"),
        id: CURLoption::CURLOPT_CONNECT_ONLY,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"CONNECT_TO\0"),
        id: CURLoption::CURLOPT_CONNECT_TO,
        value_type: curl_easytype::CURLOT_SLIST,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"CONV_FROM_NETWORK_FUNCTION\0"),
        id: CURLoption::CURLOPT_CONV_FROM_NETWORK_FUNCTION,
        value_type: curl_easytype::CURLOT_FUNCTION,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"CONV_FROM_UTF8_FUNCTION\0"),
        id: CURLoption::CURLOPT_CONV_FROM_UTF8_FUNCTION,
        value_type: curl_easytype::CURLOT_FUNCTION,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"CONV_TO_NETWORK_FUNCTION\0"),
        id: CURLoption::CURLOPT_CONV_TO_NETWORK_FUNCTION,
        value_type: curl_easytype::CURLOT_FUNCTION,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"COOKIE\0"),
        id: CURLoption::CURLOPT_COOKIE,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"COOKIEFILE\0"),
        id: CURLoption::CURLOPT_COOKIEFILE,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"COOKIEJAR\0"),
        id: CURLoption::CURLOPT_COOKIEJAR,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"COOKIELIST\0"),
        id: CURLoption::CURLOPT_COOKIELIST,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"COOKIESESSION\0"),
        id: CURLoption::CURLOPT_COOKIESESSION,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"COPYPOSTFIELDS\0"),
        id: CURLoption::CURLOPT_COPYPOSTFIELDS,
        value_type: curl_easytype::CURLOT_OBJECT,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"CRLF\0"),
        id: CURLoption::CURLOPT_CRLF,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"CRLFILE\0"),
        id: CURLoption::CURLOPT_CRLFILE,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"CURLU\0"),
        id: CURLoption::CURLOPT_CURLU,
        value_type: curl_easytype::CURLOT_OBJECT,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"CUSTOMREQUEST\0"),
        id: CURLoption::CURLOPT_CUSTOMREQUEST,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"DEBUGDATA\0"),
        id: CURLoption::CURLOPT_DEBUGDATA,
        value_type: curl_easytype::CURLOT_CBPTR,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"DEBUGFUNCTION\0"),
        id: CURLoption::CURLOPT_DEBUGFUNCTION,
        value_type: curl_easytype::CURLOT_FUNCTION,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"DEFAULT_PROTOCOL\0"),
        id: CURLoption::CURLOPT_DEFAULT_PROTOCOL,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"DIRLISTONLY\0"),
        id: CURLoption::CURLOPT_DIRLISTONLY,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"DISALLOW_USERNAME_IN_URL\0"),
        id: CURLoption::CURLOPT_DISALLOW_USERNAME_IN_URL,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"DNS_CACHE_TIMEOUT\0"),
        id: CURLoption::CURLOPT_DNS_CACHE_TIMEOUT,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"DNS_INTERFACE\0"),
        id: CURLoption::CURLOPT_DNS_INTERFACE,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"DNS_LOCAL_IP4\0"),
        id: CURLoption::CURLOPT_DNS_LOCAL_IP4,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"DNS_LOCAL_IP6\0"),
        id: CURLoption::CURLOPT_DNS_LOCAL_IP6,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"DNS_SERVERS\0"),
        id: CURLoption::CURLOPT_DNS_SERVERS,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"DNS_SHUFFLE_ADDRESSES\0"),
        id: CURLoption::CURLOPT_DNS_SHUFFLE_ADDRESSES,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"DNS_USE_GLOBAL_CACHE\0"),
        id: CURLoption::CURLOPT_DNS_USE_GLOBAL_CACHE,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"DOH_SSL_VERIFYHOST\0"),
        id: CURLoption::CURLOPT_DOH_SSL_VERIFYHOST,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"DOH_SSL_VERIFYPEER\0"),
        id: CURLoption::CURLOPT_DOH_SSL_VERIFYPEER,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"DOH_SSL_VERIFYSTATUS\0"),
        id: CURLoption::CURLOPT_DOH_SSL_VERIFYSTATUS,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"DOH_URL\0"),
        id: CURLoption::CURLOPT_DOH_URL,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"ECH\0"),
        id: CURLoption::CURLOPT_ECH,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"EGDSOCKET\0"),
        id: CURLoption::CURLOPT_EGDSOCKET,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"ENCODING\0"),
        id: CURLoption::CURLOPT_ACCEPT_ENCODING,
        value_type: curl_easytype::CURLOT_STRING,
        flags: CURLOT_FLAG_ALIAS,
    },
    EasyOptionRow {
        name: Some(b"ERRORBUFFER\0"),
        id: CURLoption::CURLOPT_ERRORBUFFER,
        value_type: curl_easytype::CURLOT_OBJECT,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"EXPECT_100_TIMEOUT_MS\0"),
        id: CURLoption::CURLOPT_EXPECT_100_TIMEOUT_MS,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"FAILONERROR\0"),
        id: CURLoption::CURLOPT_FAILONERROR,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"FILE\0"),
        id: CURLoption::CURLOPT_WRITEDATA,
        value_type: curl_easytype::CURLOT_CBPTR,
        flags: CURLOT_FLAG_ALIAS,
    },
    EasyOptionRow {
        name: Some(b"FILETIME\0"),
        id: CURLoption::CURLOPT_FILETIME,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"FNMATCH_DATA\0"),
        id: CURLoption::CURLOPT_FNMATCH_DATA,
        value_type: curl_easytype::CURLOT_CBPTR,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"FNMATCH_FUNCTION\0"),
        id: CURLoption::CURLOPT_FNMATCH_FUNCTION,
        value_type: curl_easytype::CURLOT_FUNCTION,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"FOLLOWLOCATION\0"),
        id: CURLoption::CURLOPT_FOLLOWLOCATION,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"FORBID_REUSE\0"),
        id: CURLoption::CURLOPT_FORBID_REUSE,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"FRESH_CONNECT\0"),
        id: CURLoption::CURLOPT_FRESH_CONNECT,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"FTPAPPEND\0"),
        id: CURLoption::CURLOPT_APPEND,
        value_type: curl_easytype::CURLOT_LONG,
        flags: CURLOT_FLAG_ALIAS,
    },
    EasyOptionRow {
        name: Some(b"FTPLISTONLY\0"),
        id: CURLoption::CURLOPT_DIRLISTONLY,
        value_type: curl_easytype::CURLOT_LONG,
        flags: CURLOT_FLAG_ALIAS,
    },
    EasyOptionRow {
        name: Some(b"FTPPORT\0"),
        id: CURLoption::CURLOPT_FTPPORT,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"FTPSSLAUTH\0"),
        id: CURLoption::CURLOPT_FTPSSLAUTH,
        value_type: curl_easytype::CURLOT_VALUES,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"FTP_ACCOUNT\0"),
        id: CURLoption::CURLOPT_FTP_ACCOUNT,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"FTP_ALTERNATIVE_TO_USER\0"),
        id: CURLoption::CURLOPT_FTP_ALTERNATIVE_TO_USER,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"FTP_CREATE_MISSING_DIRS\0"),
        id: CURLoption::CURLOPT_FTP_CREATE_MISSING_DIRS,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"FTP_FILEMETHOD\0"),
        id: CURLoption::CURLOPT_FTP_FILEMETHOD,
        value_type: curl_easytype::CURLOT_VALUES,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"FTP_RESPONSE_TIMEOUT\0"),
        id: CURLoption::CURLOPT_SERVER_RESPONSE_TIMEOUT,
        value_type: curl_easytype::CURLOT_LONG,
        flags: CURLOT_FLAG_ALIAS,
    },
    EasyOptionRow {
        name: Some(b"FTP_SKIP_PASV_IP\0"),
        id: CURLoption::CURLOPT_FTP_SKIP_PASV_IP,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"FTP_SSL\0"),
        id: CURLoption::CURLOPT_USE_SSL,
        value_type: curl_easytype::CURLOT_VALUES,
        flags: CURLOT_FLAG_ALIAS,
    },
    EasyOptionRow {
        name: Some(b"FTP_SSL_CCC\0"),
        id: CURLoption::CURLOPT_FTP_SSL_CCC,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"FTP_USE_EPRT\0"),
        id: CURLoption::CURLOPT_FTP_USE_EPRT,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"FTP_USE_EPSV\0"),
        id: CURLoption::CURLOPT_FTP_USE_EPSV,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"FTP_USE_PRET\0"),
        id: CURLoption::CURLOPT_FTP_USE_PRET,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"GSSAPI_DELEGATION\0"),
        id: CURLoption::CURLOPT_GSSAPI_DELEGATION,
        value_type: curl_easytype::CURLOT_VALUES,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"HAPPY_EYEBALLS_TIMEOUT_MS\0"),
        id: CURLoption::CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"HAPROXYPROTOCOL\0"),
        id: CURLoption::CURLOPT_HAPROXYPROTOCOL,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"HAPROXY_CLIENT_IP\0"),
        id: CURLoption::CURLOPT_HAPROXY_CLIENT_IP,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"HEADER\0"),
        id: CURLoption::CURLOPT_HEADER,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"HEADERDATA\0"),
        id: CURLoption::CURLOPT_HEADERDATA,
        value_type: curl_easytype::CURLOT_CBPTR,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"HEADERFUNCTION\0"),
        id: CURLoption::CURLOPT_HEADERFUNCTION,
        value_type: curl_easytype::CURLOT_FUNCTION,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"HEADEROPT\0"),
        id: CURLoption::CURLOPT_HEADEROPT,
        value_type: curl_easytype::CURLOT_VALUES,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"HSTS\0"),
        id: CURLoption::CURLOPT_HSTS,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"HSTSREADDATA\0"),
        id: CURLoption::CURLOPT_HSTSREADDATA,
        value_type: curl_easytype::CURLOT_CBPTR,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"HSTSREADFUNCTION\0"),
        id: CURLoption::CURLOPT_HSTSREADFUNCTION,
        value_type: curl_easytype::CURLOT_FUNCTION,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"HSTSWRITEDATA\0"),
        id: CURLoption::CURLOPT_HSTSWRITEDATA,
        value_type: curl_easytype::CURLOT_CBPTR,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"HSTSWRITEFUNCTION\0"),
        id: CURLoption::CURLOPT_HSTSWRITEFUNCTION,
        value_type: curl_easytype::CURLOT_FUNCTION,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"HSTS_CTRL\0"),
        id: CURLoption::CURLOPT_HSTS_CTRL,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"HTTP09_ALLOWED\0"),
        id: CURLoption::CURLOPT_HTTP09_ALLOWED,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"HTTP200ALIASES\0"),
        id: CURLoption::CURLOPT_HTTP200ALIASES,
        value_type: curl_easytype::CURLOT_SLIST,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"HTTPAUTH\0"),
        id: CURLoption::CURLOPT_HTTPAUTH,
        value_type: curl_easytype::CURLOT_VALUES,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"HTTPGET\0"),
        id: CURLoption::CURLOPT_HTTPGET,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"HTTPHEADER\0"),
        id: CURLoption::CURLOPT_HTTPHEADER,
        value_type: curl_easytype::CURLOT_SLIST,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"HTTPPOST\0"),
        id: CURLoption::CURLOPT_HTTPPOST,
        value_type: curl_easytype::CURLOT_OBJECT,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"HTTPPROXYTUNNEL\0"),
        id: CURLoption::CURLOPT_HTTPPROXYTUNNEL,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"HTTP_CONTENT_DECODING\0"),
        id: CURLoption::CURLOPT_HTTP_CONTENT_DECODING,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"HTTP_TRANSFER_DECODING\0"),
        id: CURLoption::CURLOPT_HTTP_TRANSFER_DECODING,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"HTTP_VERSION\0"),
        id: CURLoption::CURLOPT_HTTP_VERSION,
        value_type: curl_easytype::CURLOT_VALUES,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"IGNORE_CONTENT_LENGTH\0"),
        id: CURLoption::CURLOPT_IGNORE_CONTENT_LENGTH,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"INFILE\0"),
        id: CURLoption::CURLOPT_READDATA,
        value_type: curl_easytype::CURLOT_CBPTR,
        flags: CURLOT_FLAG_ALIAS,
    },
    EasyOptionRow {
        name: Some(b"INFILESIZE\0"),
        id: CURLoption::CURLOPT_INFILESIZE,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"INFILESIZE_LARGE\0"),
        id: CURLoption::CURLOPT_INFILESIZE_LARGE,
        value_type: curl_easytype::CURLOT_OFF_T,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"INTERFACE\0"),
        id: CURLoption::CURLOPT_INTERFACE,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"INTERLEAVEDATA\0"),
        id: CURLoption::CURLOPT_INTERLEAVEDATA,
        value_type: curl_easytype::CURLOT_CBPTR,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"INTERLEAVEFUNCTION\0"),
        id: CURLoption::CURLOPT_INTERLEAVEFUNCTION,
        value_type: curl_easytype::CURLOT_FUNCTION,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"IOCTLDATA\0"),
        id: CURLoption::CURLOPT_IOCTLDATA,
        value_type: curl_easytype::CURLOT_CBPTR,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"IOCTLFUNCTION\0"),
        id: CURLoption::CURLOPT_IOCTLFUNCTION,
        value_type: curl_easytype::CURLOT_FUNCTION,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"IPRESOLVE\0"),
        id: CURLoption::CURLOPT_IPRESOLVE,
        value_type: curl_easytype::CURLOT_VALUES,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"ISSUERCERT\0"),
        id: CURLoption::CURLOPT_ISSUERCERT,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"ISSUERCERT_BLOB\0"),
        id: CURLoption::CURLOPT_ISSUERCERT_BLOB,
        value_type: curl_easytype::CURLOT_BLOB,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"KEEP_SENDING_ON_ERROR\0"),
        id: CURLoption::CURLOPT_KEEP_SENDING_ON_ERROR,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"KEYPASSWD\0"),
        id: CURLoption::CURLOPT_KEYPASSWD,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"KRB4LEVEL\0"),
        id: CURLoption::CURLOPT_KRBLEVEL,
        value_type: curl_easytype::CURLOT_STRING,
        flags: CURLOT_FLAG_ALIAS,
    },
    EasyOptionRow {
        name: Some(b"KRBLEVEL\0"),
        id: CURLoption::CURLOPT_KRBLEVEL,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"LOCALPORT\0"),
        id: CURLoption::CURLOPT_LOCALPORT,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"LOCALPORTRANGE\0"),
        id: CURLoption::CURLOPT_LOCALPORTRANGE,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"LOGIN_OPTIONS\0"),
        id: CURLoption::CURLOPT_LOGIN_OPTIONS,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"LOW_SPEED_LIMIT\0"),
        id: CURLoption::CURLOPT_LOW_SPEED_LIMIT,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"LOW_SPEED_TIME\0"),
        id: CURLoption::CURLOPT_LOW_SPEED_TIME,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"MAIL_AUTH\0"),
        id: CURLoption::CURLOPT_MAIL_AUTH,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"MAIL_FROM\0"),
        id: CURLoption::CURLOPT_MAIL_FROM,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"MAIL_RCPT\0"),
        id: CURLoption::CURLOPT_MAIL_RCPT,
        value_type: curl_easytype::CURLOT_SLIST,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"MAIL_RCPT_ALLLOWFAILS\0"),
        id: CURLoption::CURLOPT_MAIL_RCPT_ALLOWFAILS,
        value_type: curl_easytype::CURLOT_LONG,
        flags: CURLOT_FLAG_ALIAS,
    },
    EasyOptionRow {
        name: Some(b"MAIL_RCPT_ALLOWFAILS\0"),
        id: CURLoption::CURLOPT_MAIL_RCPT_ALLOWFAILS,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"MAXAGE_CONN\0"),
        id: CURLoption::CURLOPT_MAXAGE_CONN,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"MAXCONNECTS\0"),
        id: CURLoption::CURLOPT_MAXCONNECTS,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"MAXFILESIZE\0"),
        id: CURLoption::CURLOPT_MAXFILESIZE,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"MAXFILESIZE_LARGE\0"),
        id: CURLoption::CURLOPT_MAXFILESIZE_LARGE,
        value_type: curl_easytype::CURLOT_OFF_T,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"MAXLIFETIME_CONN\0"),
        id: CURLoption::CURLOPT_MAXLIFETIME_CONN,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"MAXREDIRS\0"),
        id: CURLoption::CURLOPT_MAXREDIRS,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"MAX_RECV_SPEED_LARGE\0"),
        id: CURLoption::CURLOPT_MAX_RECV_SPEED_LARGE,
        value_type: curl_easytype::CURLOT_OFF_T,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"MAX_SEND_SPEED_LARGE\0"),
        id: CURLoption::CURLOPT_MAX_SEND_SPEED_LARGE,
        value_type: curl_easytype::CURLOT_OFF_T,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"MIMEPOST\0"),
        id: CURLoption::CURLOPT_MIMEPOST,
        value_type: curl_easytype::CURLOT_OBJECT,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"MIME_OPTIONS\0"),
        id: CURLoption::CURLOPT_MIME_OPTIONS,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"NETRC\0"),
        id: CURLoption::CURLOPT_NETRC,
        value_type: curl_easytype::CURLOT_VALUES,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"NETRC_FILE\0"),
        id: CURLoption::CURLOPT_NETRC_FILE,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"NEW_DIRECTORY_PERMS\0"),
        id: CURLoption::CURLOPT_NEW_DIRECTORY_PERMS,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"NEW_FILE_PERMS\0"),
        id: CURLoption::CURLOPT_NEW_FILE_PERMS,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"NOBODY\0"),
        id: CURLoption::CURLOPT_NOBODY,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"NOPROGRESS\0"),
        id: CURLoption::CURLOPT_NOPROGRESS,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"NOPROXY\0"),
        id: CURLoption::CURLOPT_NOPROXY,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"NOSIGNAL\0"),
        id: CURLoption::CURLOPT_NOSIGNAL,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"OPENSOCKETDATA\0"),
        id: CURLoption::CURLOPT_OPENSOCKETDATA,
        value_type: curl_easytype::CURLOT_CBPTR,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"OPENSOCKETFUNCTION\0"),
        id: CURLoption::CURLOPT_OPENSOCKETFUNCTION,
        value_type: curl_easytype::CURLOT_FUNCTION,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"PASSWORD\0"),
        id: CURLoption::CURLOPT_PASSWORD,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"PATH_AS_IS\0"),
        id: CURLoption::CURLOPT_PATH_AS_IS,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"PINNEDPUBLICKEY\0"),
        id: CURLoption::CURLOPT_PINNEDPUBLICKEY,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"PIPEWAIT\0"),
        id: CURLoption::CURLOPT_PIPEWAIT,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"PORT\0"),
        id: CURLoption::CURLOPT_PORT,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"POST\0"),
        id: CURLoption::CURLOPT_POST,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"POST301\0"),
        id: CURLoption::CURLOPT_POSTREDIR,
        value_type: curl_easytype::CURLOT_VALUES,
        flags: CURLOT_FLAG_ALIAS,
    },
    EasyOptionRow {
        name: Some(b"POSTFIELDS\0"),
        id: CURLoption::CURLOPT_POSTFIELDS,
        value_type: curl_easytype::CURLOT_OBJECT,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"POSTFIELDSIZE\0"),
        id: CURLoption::CURLOPT_POSTFIELDSIZE,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"POSTFIELDSIZE_LARGE\0"),
        id: CURLoption::CURLOPT_POSTFIELDSIZE_LARGE,
        value_type: curl_easytype::CURLOT_OFF_T,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"POSTQUOTE\0"),
        id: CURLoption::CURLOPT_POSTQUOTE,
        value_type: curl_easytype::CURLOT_SLIST,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"POSTREDIR\0"),
        id: CURLoption::CURLOPT_POSTREDIR,
        value_type: curl_easytype::CURLOT_VALUES,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"PREQUOTE\0"),
        id: CURLoption::CURLOPT_PREQUOTE,
        value_type: curl_easytype::CURLOT_SLIST,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"PREREQDATA\0"),
        id: CURLoption::CURLOPT_PREREQDATA,
        value_type: curl_easytype::CURLOT_CBPTR,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"PREREQFUNCTION\0"),
        id: CURLoption::CURLOPT_PREREQFUNCTION,
        value_type: curl_easytype::CURLOT_FUNCTION,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"PRE_PROXY\0"),
        id: CURLoption::CURLOPT_PRE_PROXY,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"PRIVATE\0"),
        id: CURLoption::CURLOPT_PRIVATE,
        value_type: curl_easytype::CURLOT_OBJECT,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"PROGRESSDATA\0"),
        id: CURLoption::CURLOPT_XFERINFODATA,
        value_type: curl_easytype::CURLOT_CBPTR,
        flags: CURLOT_FLAG_ALIAS,
    },
    EasyOptionRow {
        name: Some(b"PROGRESSFUNCTION\0"),
        id: CURLoption::CURLOPT_PROGRESSFUNCTION,
        value_type: curl_easytype::CURLOT_FUNCTION,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"PROTOCOLS\0"),
        id: CURLoption::CURLOPT_PROTOCOLS,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"PROTOCOLS_STR\0"),
        id: CURLoption::CURLOPT_PROTOCOLS_STR,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"PROXY\0"),
        id: CURLoption::CURLOPT_PROXY,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"PROXYAUTH\0"),
        id: CURLoption::CURLOPT_PROXYAUTH,
        value_type: curl_easytype::CURLOT_VALUES,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"PROXYHEADER\0"),
        id: CURLoption::CURLOPT_PROXYHEADER,
        value_type: curl_easytype::CURLOT_SLIST,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"PROXYPASSWORD\0"),
        id: CURLoption::CURLOPT_PROXYPASSWORD,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"PROXYPORT\0"),
        id: CURLoption::CURLOPT_PROXYPORT,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"PROXYTYPE\0"),
        id: CURLoption::CURLOPT_PROXYTYPE,
        value_type: curl_easytype::CURLOT_VALUES,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"PROXYUSERNAME\0"),
        id: CURLoption::CURLOPT_PROXYUSERNAME,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"PROXYUSERPWD\0"),
        id: CURLoption::CURLOPT_PROXYUSERPWD,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"PROXY_CAINFO\0"),
        id: CURLoption::CURLOPT_PROXY_CAINFO,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"PROXY_CAINFO_BLOB\0"),
        id: CURLoption::CURLOPT_PROXY_CAINFO_BLOB,
        value_type: curl_easytype::CURLOT_BLOB,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"PROXY_CAPATH\0"),
        id: CURLoption::CURLOPT_PROXY_CAPATH,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"PROXY_CRLFILE\0"),
        id: CURLoption::CURLOPT_PROXY_CRLFILE,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"PROXY_ISSUERCERT\0"),
        id: CURLoption::CURLOPT_PROXY_ISSUERCERT,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"PROXY_ISSUERCERT_BLOB\0"),
        id: CURLoption::CURLOPT_PROXY_ISSUERCERT_BLOB,
        value_type: curl_easytype::CURLOT_BLOB,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"PROXY_KEYPASSWD\0"),
        id: CURLoption::CURLOPT_PROXY_KEYPASSWD,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"PROXY_PINNEDPUBLICKEY\0"),
        id: CURLoption::CURLOPT_PROXY_PINNEDPUBLICKEY,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"PROXY_SERVICE_NAME\0"),
        id: CURLoption::CURLOPT_PROXY_SERVICE_NAME,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"PROXY_SSLCERT\0"),
        id: CURLoption::CURLOPT_PROXY_SSLCERT,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"PROXY_SSLCERTTYPE\0"),
        id: CURLoption::CURLOPT_PROXY_SSLCERTTYPE,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"PROXY_SSLCERT_BLOB\0"),
        id: CURLoption::CURLOPT_PROXY_SSLCERT_BLOB,
        value_type: curl_easytype::CURLOT_BLOB,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"PROXY_SSLKEY\0"),
        id: CURLoption::CURLOPT_PROXY_SSLKEY,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"PROXY_SSLKEYTYPE\0"),
        id: CURLoption::CURLOPT_PROXY_SSLKEYTYPE,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"PROXY_SSLKEY_BLOB\0"),
        id: CURLoption::CURLOPT_PROXY_SSLKEY_BLOB,
        value_type: curl_easytype::CURLOT_BLOB,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"PROXY_SSLVERSION\0"),
        id: CURLoption::CURLOPT_PROXY_SSLVERSION,
        value_type: curl_easytype::CURLOT_VALUES,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"PROXY_SSL_CIPHER_LIST\0"),
        id: CURLoption::CURLOPT_PROXY_SSL_CIPHER_LIST,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"PROXY_SSL_OPTIONS\0"),
        id: CURLoption::CURLOPT_PROXY_SSL_OPTIONS,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"PROXY_SSL_VERIFYHOST\0"),
        id: CURLoption::CURLOPT_PROXY_SSL_VERIFYHOST,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"PROXY_SSL_VERIFYPEER\0"),
        id: CURLoption::CURLOPT_PROXY_SSL_VERIFYPEER,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"PROXY_TLS13_CIPHERS\0"),
        id: CURLoption::CURLOPT_PROXY_TLS13_CIPHERS,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"PROXY_TLSAUTH_PASSWORD\0"),
        id: CURLoption::CURLOPT_PROXY_TLSAUTH_PASSWORD,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"PROXY_TLSAUTH_TYPE\0"),
        id: CURLoption::CURLOPT_PROXY_TLSAUTH_TYPE,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"PROXY_TLSAUTH_USERNAME\0"),
        id: CURLoption::CURLOPT_PROXY_TLSAUTH_USERNAME,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"PROXY_TRANSFER_MODE\0"),
        id: CURLoption::CURLOPT_PROXY_TRANSFER_MODE,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"PUT\0"),
        id: CURLoption::CURLOPT_PUT,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"QUICK_EXIT\0"),
        id: CURLoption::CURLOPT_QUICK_EXIT,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"QUOTE\0"),
        id: CURLoption::CURLOPT_QUOTE,
        value_type: curl_easytype::CURLOT_SLIST,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"RANDOM_FILE\0"),
        id: CURLoption::CURLOPT_RANDOM_FILE,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"RANGE\0"),
        id: CURLoption::CURLOPT_RANGE,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"READDATA\0"),
        id: CURLoption::CURLOPT_READDATA,
        value_type: curl_easytype::CURLOT_CBPTR,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"READFUNCTION\0"),
        id: CURLoption::CURLOPT_READFUNCTION,
        value_type: curl_easytype::CURLOT_FUNCTION,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"REDIR_PROTOCOLS\0"),
        id: CURLoption::CURLOPT_REDIR_PROTOCOLS,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"REDIR_PROTOCOLS_STR\0"),
        id: CURLoption::CURLOPT_REDIR_PROTOCOLS_STR,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"REFERER\0"),
        id: CURLoption::CURLOPT_REFERER,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"REQUEST_TARGET\0"),
        id: CURLoption::CURLOPT_REQUEST_TARGET,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"RESOLVE\0"),
        id: CURLoption::CURLOPT_RESOLVE,
        value_type: curl_easytype::CURLOT_SLIST,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"RESOLVER_START_DATA\0"),
        id: CURLoption::CURLOPT_RESOLVER_START_DATA,
        value_type: curl_easytype::CURLOT_CBPTR,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"RESOLVER_START_FUNCTION\0"),
        id: CURLoption::CURLOPT_RESOLVER_START_FUNCTION,
        value_type: curl_easytype::CURLOT_FUNCTION,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"RESUME_FROM\0"),
        id: CURLoption::CURLOPT_RESUME_FROM,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"RESUME_FROM_LARGE\0"),
        id: CURLoption::CURLOPT_RESUME_FROM_LARGE,
        value_type: curl_easytype::CURLOT_OFF_T,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"RTSPHEADER\0"),
        id: CURLoption::CURLOPT_HTTPHEADER,
        value_type: curl_easytype::CURLOT_SLIST,
        flags: CURLOT_FLAG_ALIAS,
    },
    EasyOptionRow {
        name: Some(b"RTSP_CLIENT_CSEQ\0"),
        id: CURLoption::CURLOPT_RTSP_CLIENT_CSEQ,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"RTSP_REQUEST\0"),
        id: CURLoption::CURLOPT_RTSP_REQUEST,
        value_type: curl_easytype::CURLOT_VALUES,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"RTSP_SERVER_CSEQ\0"),
        id: CURLoption::CURLOPT_RTSP_SERVER_CSEQ,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"RTSP_SESSION_ID\0"),
        id: CURLoption::CURLOPT_RTSP_SESSION_ID,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"RTSP_STREAM_URI\0"),
        id: CURLoption::CURLOPT_RTSP_STREAM_URI,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"RTSP_TRANSPORT\0"),
        id: CURLoption::CURLOPT_RTSP_TRANSPORT,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"SASL_AUTHZID\0"),
        id: CURLoption::CURLOPT_SASL_AUTHZID,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"SASL_IR\0"),
        id: CURLoption::CURLOPT_SASL_IR,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"SEEKDATA\0"),
        id: CURLoption::CURLOPT_SEEKDATA,
        value_type: curl_easytype::CURLOT_CBPTR,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"SEEKFUNCTION\0"),
        id: CURLoption::CURLOPT_SEEKFUNCTION,
        value_type: curl_easytype::CURLOT_FUNCTION,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"SERVER_RESPONSE_TIMEOUT\0"),
        id: CURLoption::CURLOPT_SERVER_RESPONSE_TIMEOUT,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"SERVER_RESPONSE_TIMEOUT_MS\0"),
        id: CURLoption::CURLOPT_SERVER_RESPONSE_TIMEOUT_MS,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"SERVICE_NAME\0"),
        id: CURLoption::CURLOPT_SERVICE_NAME,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"SHARE\0"),
        id: CURLoption::CURLOPT_SHARE,
        value_type: curl_easytype::CURLOT_OBJECT,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"SOCKOPTDATA\0"),
        id: CURLoption::CURLOPT_SOCKOPTDATA,
        value_type: curl_easytype::CURLOT_CBPTR,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"SOCKOPTFUNCTION\0"),
        id: CURLoption::CURLOPT_SOCKOPTFUNCTION,
        value_type: curl_easytype::CURLOT_FUNCTION,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"SOCKS5_AUTH\0"),
        id: CURLoption::CURLOPT_SOCKS5_AUTH,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"SOCKS5_GSSAPI_NEC\0"),
        id: CURLoption::CURLOPT_SOCKS5_GSSAPI_NEC,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"SOCKS5_GSSAPI_SERVICE\0"),
        id: CURLoption::CURLOPT_SOCKS5_GSSAPI_SERVICE,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"SSH_AUTH_TYPES\0"),
        id: CURLoption::CURLOPT_SSH_AUTH_TYPES,
        value_type: curl_easytype::CURLOT_VALUES,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"SSH_COMPRESSION\0"),
        id: CURLoption::CURLOPT_SSH_COMPRESSION,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"SSH_HOSTKEYDATA\0"),
        id: CURLoption::CURLOPT_SSH_HOSTKEYDATA,
        value_type: curl_easytype::CURLOT_CBPTR,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"SSH_HOSTKEYFUNCTION\0"),
        id: CURLoption::CURLOPT_SSH_HOSTKEYFUNCTION,
        value_type: curl_easytype::CURLOT_FUNCTION,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"SSH_HOST_PUBLIC_KEY_MD5\0"),
        id: CURLoption::CURLOPT_SSH_HOST_PUBLIC_KEY_MD5,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"SSH_HOST_PUBLIC_KEY_SHA256\0"),
        id: CURLoption::CURLOPT_SSH_HOST_PUBLIC_KEY_SHA256,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"SSH_KEYDATA\0"),
        id: CURLoption::CURLOPT_SSH_KEYDATA,
        value_type: curl_easytype::CURLOT_CBPTR,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"SSH_KEYFUNCTION\0"),
        id: CURLoption::CURLOPT_SSH_KEYFUNCTION,
        value_type: curl_easytype::CURLOT_FUNCTION,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"SSH_KNOWNHOSTS\0"),
        id: CURLoption::CURLOPT_SSH_KNOWNHOSTS,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"SSH_PRIVATE_KEYFILE\0"),
        id: CURLoption::CURLOPT_SSH_PRIVATE_KEYFILE,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"SSH_PUBLIC_KEYFILE\0"),
        id: CURLoption::CURLOPT_SSH_PUBLIC_KEYFILE,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"SSLCERT\0"),
        id: CURLoption::CURLOPT_SSLCERT,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"SSLCERTPASSWD\0"),
        id: CURLoption::CURLOPT_KEYPASSWD,
        value_type: curl_easytype::CURLOT_STRING,
        flags: CURLOT_FLAG_ALIAS,
    },
    EasyOptionRow {
        name: Some(b"SSLCERTTYPE\0"),
        id: CURLoption::CURLOPT_SSLCERTTYPE,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"SSLCERT_BLOB\0"),
        id: CURLoption::CURLOPT_SSLCERT_BLOB,
        value_type: curl_easytype::CURLOT_BLOB,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"SSLENGINE\0"),
        id: CURLoption::CURLOPT_SSLENGINE,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"SSLENGINE_DEFAULT\0"),
        id: CURLoption::CURLOPT_SSLENGINE_DEFAULT,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"SSLKEY\0"),
        id: CURLoption::CURLOPT_SSLKEY,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"SSLKEYPASSWD\0"),
        id: CURLoption::CURLOPT_KEYPASSWD,
        value_type: curl_easytype::CURLOT_STRING,
        flags: CURLOT_FLAG_ALIAS,
    },
    EasyOptionRow {
        name: Some(b"SSLKEYTYPE\0"),
        id: CURLoption::CURLOPT_SSLKEYTYPE,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"SSLKEY_BLOB\0"),
        id: CURLoption::CURLOPT_SSLKEY_BLOB,
        value_type: curl_easytype::CURLOT_BLOB,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"SSLVERSION\0"),
        id: CURLoption::CURLOPT_SSLVERSION,
        value_type: curl_easytype::CURLOT_VALUES,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"SSL_CIPHER_LIST\0"),
        id: CURLoption::CURLOPT_SSL_CIPHER_LIST,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"SSL_CTX_DATA\0"),
        id: CURLoption::CURLOPT_SSL_CTX_DATA,
        value_type: curl_easytype::CURLOT_CBPTR,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"SSL_CTX_FUNCTION\0"),
        id: CURLoption::CURLOPT_SSL_CTX_FUNCTION,
        value_type: curl_easytype::CURLOT_FUNCTION,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"SSL_EC_CURVES\0"),
        id: CURLoption::CURLOPT_SSL_EC_CURVES,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"SSL_ENABLE_ALPN\0"),
        id: CURLoption::CURLOPT_SSL_ENABLE_ALPN,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"SSL_ENABLE_NPN\0"),
        id: CURLoption::CURLOPT_SSL_ENABLE_NPN,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"SSL_FALSESTART\0"),
        id: CURLoption::CURLOPT_SSL_FALSESTART,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"SSL_OPTIONS\0"),
        id: CURLoption::CURLOPT_SSL_OPTIONS,
        value_type: curl_easytype::CURLOT_VALUES,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"SSL_SESSIONID_CACHE\0"),
        id: CURLoption::CURLOPT_SSL_SESSIONID_CACHE,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"SSL_SIGNATURE_ALGORITHMS\0"),
        id: CURLoption::CURLOPT_SSL_SIGNATURE_ALGORITHMS,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"SSL_VERIFYHOST\0"),
        id: CURLoption::CURLOPT_SSL_VERIFYHOST,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"SSL_VERIFYPEER\0"),
        id: CURLoption::CURLOPT_SSL_VERIFYPEER,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"SSL_VERIFYSTATUS\0"),
        id: CURLoption::CURLOPT_SSL_VERIFYSTATUS,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"STDERR\0"),
        id: CURLoption::CURLOPT_STDERR,
        value_type: curl_easytype::CURLOT_OBJECT,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"STREAM_DEPENDS\0"),
        id: CURLoption::CURLOPT_STREAM_DEPENDS,
        value_type: curl_easytype::CURLOT_OBJECT,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"STREAM_DEPENDS_E\0"),
        id: CURLoption::CURLOPT_STREAM_DEPENDS_E,
        value_type: curl_easytype::CURLOT_OBJECT,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"STREAM_WEIGHT\0"),
        id: CURLoption::CURLOPT_STREAM_WEIGHT,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"SUPPRESS_CONNECT_HEADERS\0"),
        id: CURLoption::CURLOPT_SUPPRESS_CONNECT_HEADERS,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"TCP_FASTOPEN\0"),
        id: CURLoption::CURLOPT_TCP_FASTOPEN,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"TCP_KEEPALIVE\0"),
        id: CURLoption::CURLOPT_TCP_KEEPALIVE,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"TCP_KEEPCNT\0"),
        id: CURLoption::CURLOPT_TCP_KEEPCNT,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"TCP_KEEPIDLE\0"),
        id: CURLoption::CURLOPT_TCP_KEEPIDLE,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"TCP_KEEPINTVL\0"),
        id: CURLoption::CURLOPT_TCP_KEEPINTVL,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"TCP_NODELAY\0"),
        id: CURLoption::CURLOPT_TCP_NODELAY,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"TELNETOPTIONS\0"),
        id: CURLoption::CURLOPT_TELNETOPTIONS,
        value_type: curl_easytype::CURLOT_SLIST,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"TFTP_BLKSIZE\0"),
        id: CURLoption::CURLOPT_TFTP_BLKSIZE,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"TFTP_NO_OPTIONS\0"),
        id: CURLoption::CURLOPT_TFTP_NO_OPTIONS,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"TIMECONDITION\0"),
        id: CURLoption::CURLOPT_TIMECONDITION,
        value_type: curl_easytype::CURLOT_VALUES,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"TIMEOUT\0"),
        id: CURLoption::CURLOPT_TIMEOUT,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"TIMEOUT_MS\0"),
        id: CURLoption::CURLOPT_TIMEOUT_MS,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"TIMEVALUE\0"),
        id: CURLoption::CURLOPT_TIMEVALUE,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"TIMEVALUE_LARGE\0"),
        id: CURLoption::CURLOPT_TIMEVALUE_LARGE,
        value_type: curl_easytype::CURLOT_OFF_T,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"TLS13_CIPHERS\0"),
        id: CURLoption::CURLOPT_TLS13_CIPHERS,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"TLSAUTH_PASSWORD\0"),
        id: CURLoption::CURLOPT_TLSAUTH_PASSWORD,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"TLSAUTH_TYPE\0"),
        id: CURLoption::CURLOPT_TLSAUTH_TYPE,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"TLSAUTH_USERNAME\0"),
        id: CURLoption::CURLOPT_TLSAUTH_USERNAME,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"TRAILERDATA\0"),
        id: CURLoption::CURLOPT_TRAILERDATA,
        value_type: curl_easytype::CURLOT_CBPTR,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"TRAILERFUNCTION\0"),
        id: CURLoption::CURLOPT_TRAILERFUNCTION,
        value_type: curl_easytype::CURLOT_FUNCTION,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"TRANSFERTEXT\0"),
        id: CURLoption::CURLOPT_TRANSFERTEXT,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"TRANSFER_ENCODING\0"),
        id: CURLoption::CURLOPT_TRANSFER_ENCODING,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"UNIX_SOCKET_PATH\0"),
        id: CURLoption::CURLOPT_UNIX_SOCKET_PATH,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"UNRESTRICTED_AUTH\0"),
        id: CURLoption::CURLOPT_UNRESTRICTED_AUTH,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"UPKEEP_INTERVAL_MS\0"),
        id: CURLoption::CURLOPT_UPKEEP_INTERVAL_MS,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"UPLOAD\0"),
        id: CURLoption::CURLOPT_UPLOAD,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"UPLOAD_BUFFERSIZE\0"),
        id: CURLoption::CURLOPT_UPLOAD_BUFFERSIZE,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"UPLOAD_FLAGS\0"),
        id: CURLoption::CURLOPT_UPLOAD_FLAGS,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"URL\0"),
        id: CURLoption::CURLOPT_URL,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"USERAGENT\0"),
        id: CURLoption::CURLOPT_USERAGENT,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"USERNAME\0"),
        id: CURLoption::CURLOPT_USERNAME,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"USERPWD\0"),
        id: CURLoption::CURLOPT_USERPWD,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"USE_SSL\0"),
        id: CURLoption::CURLOPT_USE_SSL,
        value_type: curl_easytype::CURLOT_VALUES,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"VERBOSE\0"),
        id: CURLoption::CURLOPT_VERBOSE,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"WILDCARDMATCH\0"),
        id: CURLoption::CURLOPT_WILDCARDMATCH,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"WRITEDATA\0"),
        id: CURLoption::CURLOPT_WRITEDATA,
        value_type: curl_easytype::CURLOT_CBPTR,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"WRITEFUNCTION\0"),
        id: CURLoption::CURLOPT_WRITEFUNCTION,
        value_type: curl_easytype::CURLOT_FUNCTION,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"WRITEHEADER\0"),
        id: CURLoption::CURLOPT_HEADERDATA,
        value_type: curl_easytype::CURLOT_CBPTR,
        flags: CURLOT_FLAG_ALIAS,
    },
    EasyOptionRow {
        name: Some(b"WS_OPTIONS\0"),
        id: CURLoption::CURLOPT_WS_OPTIONS,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"XFERINFODATA\0"),
        id: CURLoption::CURLOPT_XFERINFODATA,
        value_type: curl_easytype::CURLOT_CBPTR,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"XFERINFOFUNCTION\0"),
        id: CURLoption::CURLOPT_XFERINFOFUNCTION,
        value_type: curl_easytype::CURLOT_FUNCTION,
        flags: 0,
    },
    EasyOptionRow {
        name: Some(b"XOAUTH2_BEARER\0"),
        id: CURLoption::CURLOPT_XOAUTH2_BEARER,
        value_type: curl_easytype::CURLOT_STRING,
        flags: 0,
    },
    EasyOptionRow {
        name: None,
        id: CURLoption::CURLOPT_LASTENTRY,
        value_type: curl_easytype::CURLOT_LONG,
        flags: 0,
    },
];

// The four row counts, DERIVED from [`EASY_OPTIONS`] rather than
// transcribed beside it.
//
// Every one of these was previously a hand-written literal, which made the
// table and its own description two independent populations: a row added or
// removed without a matching edit here produced a silently wrong count, and
// only `metadata_table_shape_matches_optiontable_pl` below would have caught
// it, and only when tests ran. `curl-rs-ffi/src/ffi/easy.rs` uses
// `EASY_OPTION_ROWS` as an array length, so a stale literal there was a
// wrong-sized array rather than a wrong number in a comment.
//
// Computing them makes that class of drift unrepresentable instead of
// detectable. The `const` assertions immediately below then pin the DATA to
// the C oracle -- `perl lib/optiontable.pl < include/curl/curl.h` -- so the
// derivation cannot quietly agree with itself while both halves drift away
// from curl 8.19.0-DEV. Derivation and pinning answer different questions
// and both are needed: derivation keeps the numbers honest about the table,
// pinning keeps the table honest about curl.

/// Rows flagged `CURLOT_FLAG_ALIAS`, counted over the table.
///
/// A `const fn` with an index loop rather than an iterator chain, because
/// `Iterator::filter` is not callable in a `const` context on the pinned
/// minimum toolchain.
const fn count_alias_rows(rows: &[EasyOptionRow]) -> usize {
    let mut aliases = 0;
    let mut index = 0;
    while index < rows.len() {
        if rows[index].is_alias() {
            aliases += 1;
        }
        index += 1;
    }
    aliases
}

/// Rows that terminate the table -- those whose C `name` is NULL.
///
/// Counted rather than assumed to be one, so that a second sentinel spliced
/// into the middle of the table is a compile error rather than a silently
/// truncated `curl_easy_option_next` walk.
const fn count_sentinel_rows(rows: &[EasyOptionRow]) -> usize {
    let mut sentinels = 0;
    let mut index = 0;
    while index < rows.len() {
        if rows[index].name.is_none() {
            sentinels += 1;
        }
        index += 1;
    }
    sentinels
}

/// Rows in the table, including the sentinel.
#[allow(dead_code)]
pub(crate) const EASY_OPTION_ROWS: usize = EASY_OPTIONS.len();

/// Rows excluding the sentinel.
#[allow(dead_code)]
pub(crate) const EASY_OPTION_REAL_ROWS: usize =
    EASY_OPTION_ROWS - count_sentinel_rows(EASY_OPTIONS);

/// Rows flagged `CURLOT_FLAG_ALIAS`.
#[allow(dead_code)]
pub(crate) const EASY_OPTION_ALIAS_ROWS: usize = count_alias_rows(EASY_OPTIONS);

/// Rows describing a real, preferred option. Equals
/// [`CURLoption::REAL_COUNT`].
#[allow(dead_code)]
pub(crate) const EASY_OPTION_TRUE_ROWS: usize =
    EASY_OPTION_REAL_ROWS - EASY_OPTION_ALIAS_ROWS;

// The oracle. These four numbers come from RUNNING the C generator,
// `perl lib/optiontable.pl < include/curl/curl.h`, and counting its output
// with brace-balanced scanning: 324 rows, of which 1 is the terminating
// `{ NULL, CURLOPT_LASTENTRY, CURLOT_LONG, 0 }` and 15 carry
// `CURLOT_FLAG_ALIAS`, leaving 308 preferred options.
//
// A `const` assertion rather than a test, because a test reports drift and
// this refuses to build with it. `curl-rs-ffi/build.rs` re-derives the same
// four counts by reading THIS FILE as text, so the numbers are checked from
// both inside and outside the crate.
const _: () = assert!(
    EASY_OPTION_ROWS == 324,
    "lib/optiontable.pl emits 324 rows including the sentinel"
);
const _: () = assert!(
    count_sentinel_rows(EASY_OPTIONS) == 1,
    "the table must end with exactly one NULL-name sentinel"
);
const _: () = assert!(
    EASY_OPTION_ALIAS_ROWS == 15,
    "lib/optiontable.pl emits 15 CURLOT_FLAG_ALIAS rows"
);
const _: () = assert!(
    EASY_OPTION_TRUE_ROWS == 308,
    "curl 8.19.0-DEV has 308 preferred options (291 CURLOPT plus 17 \
     CURLOPTDEPRECATED)"
);

// ---------------------------------------------------------------------------
// CURLINFO: the second composed identifier space.
// ---------------------------------------------------------------------------

// Information type bases (include/curl/curl.h:2890-2898).
//
// `pub(crate)` is load-bearing here for exactly the reason it is on the
// `CURLOPTTYPE_*` bases above: `curl-rs-ffi/build.rs:2095-2103` carries
// these nine `#define` lines verbatim, and cbindgen would render a `pub`
// constant as a SECOND `#define` of the same name.
//
// The type is `c_int` rather than `i32` because every one of these is used
// as the right operand of a mask against a value that arrived from C as an
// `int` -- `lib/getinfo.c:636` is `type = CURLINFO_TYPEMASK & (int)info;`.
// `c_int` is `i32` on all four targets AAP 0.8.3 mandates, so nothing about
// the arithmetic changes; only the declared intent does.
//
// CORRECTION 2 -- `curl_easytype` is not recoverable from `id / 10000` --
// HAS AN EXACT TWIN HERE, and it is why [`InfoBase`] exists below instead
// of a bare integer. `CURLINFO_PTR` and `CURLINFO_SLIST` are DELIBERATELY
// the same value, and the frozen header says so in the comment `/* same as
// SLIST */`. Five members are affected: three are spelled `CURLINFO_PTR`
// (`CERTINFO`, `TLS_SESSION`, `TLS_SSL_PTR`) and two `CURLINFO_SLIST`
// (`SSL_ENGINES`, `COOKIELIST`). A renderer that recovered the spelling
// from the integer would emit the wrong one for all five, and the emitted
// header would still compile -- which is precisely the silent failure mode
// this module exists to make impossible.
pub(crate) const CURLINFO_STRING: c_int = 0x100000;
pub(crate) const CURLINFO_LONG: c_int = 0x200000;
pub(crate) const CURLINFO_DOUBLE: c_int = 0x300000;
pub(crate) const CURLINFO_SLIST: c_int = 0x400000;
/// Same value as [`CURLINFO_SLIST`], deliberately, and not a defect to fix.
pub(crate) const CURLINFO_PTR: c_int = 0x400000;
pub(crate) const CURLINFO_SOCKET: c_int = 0x500000;
pub(crate) const CURLINFO_OFF_T: c_int = 0x600000;
/// Isolates the ordinal from a composed `CURLINFO` value.
///
/// The one base with no production caller yet, so it carries the same
/// per-item allowance the `CURLOPTTYPE_*` bases above do. The other eight
/// are reached from [`InfoBase::value`] and [`info_value_kind`]; this one is
/// exercised only by the const assertion below and by the tests, and rustc
/// 1.75 -- the declared MSRV -- does not count a use inside
/// `const _: () = assert!(...)` as a use, though 1.97 does. Without the
/// allowance the floor build warns and the newer build does not, which is
/// the most confusing shape a warning can take.
///
/// `CURLINFO::ordinal` deliberately does NOT mask: it consults
/// [`INFO_COMPOSITION`] so that `CURLINFO_NONE` and `CURLINFO_LASTONE`
/// report `None` rather than the 0 and 70 a mask would hand back.
#[allow(dead_code)]
pub(crate) const CURLINFO_MASK: c_int = 0x0fffff;
/// Isolates the type base from a composed `CURLINFO` value.
pub(crate) const CURLINFO_TYPEMASK: c_int = 0xf00000;

// The two collisions above are asserted rather than described, so that
// "fixing" either one is a build failure and not a merge.
const _: () = assert!(
    CURLINFO_PTR == CURLINFO_SLIST,
    "curl.h:2894 defines CURLINFO_PTR as CURLINFO_SLIST; the getinfo \
     dispatch has no PTR arm because of it"
);
const _: () = assert!(
    CURLINFO_TYPEMASK == 0xf00000 && CURLINFO_MASK == 0x0fffff,
    "the two masks are frozen at curl.h:2897-2898"
);

/// The `CURLINFO_*` base a member was composed from, kept as a SPELLING.
///
/// Seven spellings, six distinct values. This type exists because the
/// arithmetic that produces a `CURLINFO` value is lossy in exactly one
/// place -- `Ptr` and `Slist` share 0x400000 -- so a table that stored only
/// the integer could not re-render the frozen header's
/// `= CURLINFO_<BASE> + n` form. `build.rs` renders that text from
/// [`INFO_COMPOSITION`], which carries this type per row.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)]
pub(crate) enum InfoBase {
    /// `CURLINFO_STRING`, 0x100000.
    String,
    /// `CURLINFO_LONG`, 0x200000.
    Long,
    /// `CURLINFO_DOUBLE`, 0x300000.
    Double,
    /// `CURLINFO_SLIST`, 0x400000.
    Slist,
    /// `CURLINFO_PTR`, 0x400000 -- the same value as `Slist`.
    Ptr,
    /// `CURLINFO_SOCKET`, 0x500000.
    Socket,
    /// `CURLINFO_OFF_T`, 0x600000.
    OffT,
}

impl InfoBase {
    /// Every spelling, in the order the frozen header declares them.
    #[allow(dead_code)]
    pub(crate) const ALL: &'static [InfoBase] = &[
        InfoBase::String,
        InfoBase::Long,
        InfoBase::Double,
        InfoBase::Slist,
        InfoBase::Ptr,
        InfoBase::Socket,
        InfoBase::OffT,
    ];

    /// The integer this base contributes to a composed value.
    #[allow(dead_code)]
    pub(crate) const fn value(self) -> c_int {
        match self {
            InfoBase::String => CURLINFO_STRING,
            InfoBase::Long => CURLINFO_LONG,
            InfoBase::Double => CURLINFO_DOUBLE,
            InfoBase::Slist => CURLINFO_SLIST,
            InfoBase::Ptr => CURLINFO_PTR,
            InfoBase::Socket => CURLINFO_SOCKET,
            InfoBase::OffT => CURLINFO_OFF_T,
        }
    }

    /// The C spelling, which is the half the arithmetic loses.
    #[allow(dead_code)]
    pub(crate) const fn name(self) -> &'static str {
        match self {
            InfoBase::String => "CURLINFO_STRING",
            InfoBase::Long => "CURLINFO_LONG",
            InfoBase::Double => "CURLINFO_DOUBLE",
            InfoBase::Slist => "CURLINFO_SLIST",
            InfoBase::Ptr => "CURLINFO_PTR",
            InfoBase::Socket => "CURLINFO_SOCKET",
            InfoBase::OffT => "CURLINFO_OFF_T",
        }
    }

    /// The value class a member on this base carries.
    ///
    /// This is where the seven spellings become six kinds: `Ptr` collapses
    /// onto `Slist`, because the two bases are one integer and the C
    /// dispatch can only see the integer.
    #[allow(dead_code)]
    pub(crate) const fn kind(self) -> InfoValueKind {
        match self {
            InfoBase::String => InfoValueKind::String,
            InfoBase::Long => InfoValueKind::Long,
            InfoBase::Double => InfoValueKind::Double,
            InfoBase::Slist | InfoBase::Ptr => InfoValueKind::Slist,
            InfoBase::Socket => InfoValueKind::Socket,
            InfoBase::OffT => InfoValueKind::OffT,
        }
    }
}

/// The six arms of `curl_easy_getinfo`'s type switch.
///
/// Six, not seven, and the missing one is not an omission: `lib/getinfo.c`
/// masks with `CURLINFO_TYPEMASK` and then switches on the result
/// (`:636-671`), so `CURLINFO_PTR` and `CURLINFO_SLIST` reach the same arm
/// and a `Ptr` arm would be unreachable. Rust would reject a duplicate
/// pattern outright, which is a better outcome than C's silent acceptance.
///
/// Each variant names the pointer type the caller must have passed, and
/// that is the whole reason the classification has to be right: reading the
/// wrong pointer type out of the variadic argument list is undefined
/// behaviour, not a wrong answer.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)]
pub(crate) enum InfoValueKind {
    /// `const char **`
    String,
    /// `long *`
    Long,
    /// `double *`
    Double,
    /// `struct curl_slist **`, and also every `CURLINFO_PTR` member.
    Slist,
    /// `curl_socket_t *`
    Socket,
    /// `curl_off_t *`
    OffT,
}

/// Classify a raw `CURLINFO` argument the way `curl_easy_getinfo` must.
///
/// Takes a `c_int` and not a [`CURLINFO`], deliberately. A C caller may
/// legally pass any `int`, so the value cannot be materialised as a
/// `#[repr(C)]` enum without undefined behaviour, and -- more importantly
/// for behavioural parity -- the C classifies BEFORE it validates. An
/// unrecognised id whose type bits are nonetheless valid still consumes the
/// matching varargs slot and only then fails in the per-type getter. Mapping
/// `None` onto `CURLE_UNKNOWN_OPTION` reproduces the `default:` arm at
/// `lib/getinfo.c:668`.
#[allow(dead_code)]
pub(crate) const fn info_value_kind(info: c_int) -> Option<InfoValueKind> {
    match info & CURLINFO_TYPEMASK {
        CURLINFO_STRING => Some(InfoValueKind::String),
        CURLINFO_LONG => Some(InfoValueKind::Long),
        CURLINFO_DOUBLE => Some(InfoValueKind::Double),
        // CURLINFO_PTR is this same value. One arm, by construction.
        CURLINFO_SLIST => Some(InfoValueKind::Slist),
        CURLINFO_SOCKET => Some(InfoValueKind::Socket),
        CURLINFO_OFF_T => Some(InfoValueKind::OffT),
        _ => None,
    }
}

// The information enumeration, carried verbatim into `include/curl/curl.h`.
//
// `cbindgen.toml:917` lists `CURLINFO` under `[export] exclude`, and unlike
// `CURLoption` that exclusion is NOT lifted: `CURL_H_GENERATED_DESPITE_
// EXCLUSION` (build.rs:6212) holds exactly one name. The reason is the nine
// `CURL_DEPRECATED` attributes below. cbindgen renders a deprecation note
// through `format.replace("{}", &format!("{note:?}"))`, which Debug-quotes
// the version token, while the frozen header needs it UNQUOTED and uses
// four different versions in this one enumeration. So `curl.h`'s CURLINFO
// block is carried verbatim (build.rs:2106-2996) and this declaration is
// the RUST-side authority that the verbatim text is asserted against --
// not a second population, because the assertion is what makes them one.
//
// Why the integers are written out rather than composed. A Rust
// `#[repr(C)]` enum discriminant is an `isize` expression, so it cannot
// name the `c_int` bases above without a cast that would obscure the value.
// Writing `0x100001` and asserting `== CURLINFO_STRING + 1` from
// [`INFO_COMPOSITION`] keeps both halves visible and pins the integer, which
// is what AAP 0.6.1 requires. The doc comment on each member carries the
// header's own `CURLINFO_<BASE> + n` spelling so a reader never has to do
// the hexadecimal in their head.

/// Every `CURLINFO_*` identifier, with its integer pinned.
///
/// 79 members. Two are not composed from a base -- `CURLINFO_NONE` is the
/// ordinal 0 and `CURLINFO_LASTONE` is a bare 70 -- and the remaining 77
/// are `CURLINFO_<BASE> + n`. The values are neither contiguous nor
/// ordered, so the contiguity assertion `ffi/codes.rs` uses would be wrong
/// here; what is asserted instead is that every value equals its base plus
/// its ordinal, that no two members share a value, and that no two share a
/// `(base, ordinal)` pair.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)]
// Frozen C ABI name: `include/curl/curl.h:2996` spells it this way and AAP
// 0.8.1 forbids changing a public typedef, so the style lints yield to the
// contract.
#[allow(clippy::upper_case_acronyms)]
#[allow(clippy::enum_variant_names)]
pub enum CURLINFO {
    /// Ordinal zero, and one of only two members that is not composed from a
    /// base. First, never use this.
    CURLINFO_NONE = 0,
    /// `CURLINFO_STRING + 1`. Last used URL.
    CURLINFO_EFFECTIVE_URL = 0x100001,
    /// `CURLINFO_LONG + 2`. Last received response code.
    CURLINFO_RESPONSE_CODE = 0x200002,
    /// `CURLINFO_DOUBLE + 3`. Total time of previous transfer.
    CURLINFO_TOTAL_TIME = 0x300003,
    /// `CURLINFO_DOUBLE + 4`. Time from start until name resolving completed as
    /// a double.
    CURLINFO_NAMELOOKUP_TIME = 0x300004,
    /// `CURLINFO_DOUBLE + 5`. The time it took from the start until the connect
    /// to the remote host (or proxy) was completed.
    CURLINFO_CONNECT_TIME = 0x300005,
    /// `CURLINFO_DOUBLE + 6`. The time it took from the start until the file
    /// transfer is just about to begin.
    CURLINFO_PRETRANSFER_TIME = 0x300006,
    /// `CURLINFO_DOUBLE + 7`. Number of bytes uploaded.
    ///
    /// `CURL_DEPRECATED(7.55.0, "Use CURLINFO_SIZE_UPLOAD_T")` in the frozen
    /// header. Kept, because AAP 0.8.2 forbids removing a deprecated public
    /// name.
    CURLINFO_SIZE_UPLOAD = 0x300007,
    /// `CURLINFO_OFF_T + 7`. Number of bytes uploaded.
    CURLINFO_SIZE_UPLOAD_T = 0x600007,
    /// `CURLINFO_DOUBLE + 8`. Number of bytes downloaded.
    ///
    /// `CURL_DEPRECATED(7.55.0, "Use CURLINFO_SIZE_DOWNLOAD_T")` in the frozen
    /// header. Kept, because AAP 0.8.2 forbids removing a deprecated public
    /// name.
    CURLINFO_SIZE_DOWNLOAD = 0x300008,
    /// `CURLINFO_OFF_T + 8`. Number of bytes downloaded.
    CURLINFO_SIZE_DOWNLOAD_T = 0x600008,
    /// `CURLINFO_DOUBLE + 9`. Average download speed.
    ///
    /// `CURL_DEPRECATED(7.55.0, "Use CURLINFO_SPEED_DOWNLOAD_T")` in the frozen
    /// header. Kept, because AAP 0.8.2 forbids removing a deprecated public
    /// name.
    CURLINFO_SPEED_DOWNLOAD = 0x300009,
    /// `CURLINFO_OFF_T + 9`. Average download speed.
    CURLINFO_SPEED_DOWNLOAD_T = 0x600009,
    /// `CURLINFO_DOUBLE + 10`. Average upload speed.
    ///
    /// `CURL_DEPRECATED(7.55.0, "Use CURLINFO_SPEED_UPLOAD_T")` in the frozen
    /// header. Kept, because AAP 0.8.2 forbids removing a deprecated public
    /// name.
    CURLINFO_SPEED_UPLOAD = 0x30000a,
    /// `CURLINFO_OFF_T + 10`. Average upload speed in number of bytes per
    /// second.
    CURLINFO_SPEED_UPLOAD_T = 0x60000a,
    /// `CURLINFO_LONG + 11`. Number of bytes of all headers received.
    CURLINFO_HEADER_SIZE = 0x20000b,
    /// `CURLINFO_LONG + 12`. Number of bytes sent in the issued HTTP requests.
    CURLINFO_REQUEST_SIZE = 0x20000c,
    /// `CURLINFO_LONG + 13`. Certificate verification result.
    CURLINFO_SSL_VERIFYRESULT = 0x20000d,
    /// `CURLINFO_LONG + 14`. Remote time of the retrieved document.
    CURLINFO_FILETIME = 0x20000e,
    /// `CURLINFO_OFF_T + 14`. Remote time of the retrieved document.
    CURLINFO_FILETIME_T = 0x60000e,
    /// `CURLINFO_DOUBLE + 15`. Content length from the Content-Length header.
    ///
    /// `CURL_DEPRECATED(7.55.0, "Use CURLINFO_CONTENT_LENGTH_DOWNLOAD_T")` in
    /// the frozen header. Kept, because AAP 0.8.2 forbids removing a deprecated
    /// public name.
    CURLINFO_CONTENT_LENGTH_DOWNLOAD = 0x30000f,
    /// `CURLINFO_OFF_T + 15`. Content length from the Content-Length header.
    CURLINFO_CONTENT_LENGTH_DOWNLOAD_T = 0x60000f,
    /// `CURLINFO_DOUBLE + 16`. Upload size.
    ///
    /// `CURL_DEPRECATED(7.55.0, "Use CURLINFO_CONTENT_LENGTH_UPLOAD_T")` in the
    /// frozen header. Kept, because AAP 0.8.2 forbids removing a deprecated
    /// public name.
    CURLINFO_CONTENT_LENGTH_UPLOAD = 0x300010,
    /// `CURLINFO_OFF_T + 16`. Upload size.
    CURLINFO_CONTENT_LENGTH_UPLOAD_T = 0x600010,
    /// `CURLINFO_DOUBLE + 17`. The time it took from the start until the first
    /// byte is received by libcurl.
    CURLINFO_STARTTRANSFER_TIME = 0x300011,
    /// `CURLINFO_STRING + 18`. Content type from the `Content-Type:` header.
    CURLINFO_CONTENT_TYPE = 0x100012,
    /// `CURLINFO_DOUBLE + 19`. The time it took for all redirection steps
    /// include name lookup, connect, pretransfer and transfer before final
    /// transaction was started.
    CURLINFO_REDIRECT_TIME = 0x300013,
    /// `CURLINFO_LONG + 20`. Total number of redirects that were followed.
    CURLINFO_REDIRECT_COUNT = 0x200014,
    /// `CURLINFO_STRING + 21`. User's private data pointer.
    CURLINFO_PRIVATE = 0x100015,
    /// `CURLINFO_LONG + 22`. Last proxy CONNECT response code.
    CURLINFO_HTTP_CONNECTCODE = 0x200016,
    /// `CURLINFO_LONG + 23`. Available HTTP authentication methods.
    CURLINFO_HTTPAUTH_AVAIL = 0x200017,
    /// `CURLINFO_LONG + 24`. Available HTTP proxy authentication methods.
    CURLINFO_PROXYAUTH_AVAIL = 0x200018,
    /// `CURLINFO_LONG + 25`. The errno from the last failure to connect.
    CURLINFO_OS_ERRNO = 0x200019,
    /// `CURLINFO_LONG + 26`. Number of new successful connections used for
    /// previous transfer.
    CURLINFO_NUM_CONNECTS = 0x20001a,
    /// `CURLINFO_SLIST + 27`. A list of OpenSSL crypto engines.
    CURLINFO_SSL_ENGINES = 0x40001b,
    /// `CURLINFO_SLIST + 28`. List of all known cookies.
    CURLINFO_COOKIELIST = 0x40001c,
    /// `CURLINFO_LONG + 29`. Last socket used.
    ///
    /// `CURL_DEPRECATED(7.45.0, "Use CURLINFO_ACTIVESOCKET")` in the frozen
    /// header. Kept, because AAP 0.8.2 forbids removing a deprecated public
    /// name.
    CURLINFO_LASTSOCKET = 0x20001d,
    /// `CURLINFO_STRING + 30`. The entry path after logging in to an FTP
    /// server.
    CURLINFO_FTP_ENTRY_PATH = 0x10001e,
    /// `CURLINFO_STRING + 31`. URL a redirect would take you to, had you
    /// enabled redirects.
    CURLINFO_REDIRECT_URL = 0x10001f,
    /// `CURLINFO_STRING + 32`. Destination IP address of the last connection.
    CURLINFO_PRIMARY_IP = 0x100020,
    /// `CURLINFO_DOUBLE + 33`. The time it took from the start until the SSL
    /// connect/handshake with the remote host was completed as a double in
    /// number of seconds.
    CURLINFO_APPCONNECT_TIME = 0x300021,
    /// `CURLINFO_PTR + 34`. Certificate chain.
    CURLINFO_CERTINFO = 0x400022,
    /// `CURLINFO_LONG + 35`. Whether or not a time conditional was met or 304
    /// HTTP response.
    CURLINFO_CONDITION_UNMET = 0x200023,
    /// `CURLINFO_STRING + 36`. RTSP session ID.
    CURLINFO_RTSP_SESSION_ID = 0x100024,
    /// `CURLINFO_LONG + 37`. The RTSP client CSeq that is expected next.
    CURLINFO_RTSP_CLIENT_CSEQ = 0x200025,
    /// `CURLINFO_LONG + 38`. The RTSP server CSeq that is expected next.
    CURLINFO_RTSP_SERVER_CSEQ = 0x200026,
    /// `CURLINFO_LONG + 39`. RTSP CSeq last received.
    CURLINFO_RTSP_CSEQ_RECV = 0x200027,
    /// `CURLINFO_LONG + 40`. Destination port of the last connection.
    CURLINFO_PRIMARY_PORT = 0x200028,
    /// `CURLINFO_STRING + 41`. Source IP address of the last connection.
    CURLINFO_LOCAL_IP = 0x100029,
    /// `CURLINFO_LONG + 42`. Source port number of the last connection.
    CURLINFO_LOCAL_PORT = 0x20002a,
    /// `CURLINFO_PTR + 43`. TLS session info that can be used for further
    /// processing.
    ///
    /// `CURL_DEPRECATED(7.48.0, "Use CURLINFO_TLS_SSL_PTR")` in the frozen
    /// header. Kept, because AAP 0.8.2 forbids removing a deprecated public
    /// name.
    CURLINFO_TLS_SESSION = 0x40002b,
    /// `CURLINFO_SOCKET + 44`. The session's active socket.
    CURLINFO_ACTIVESOCKET = 0x50002c,
    /// `CURLINFO_PTR + 45`. TLS session info that can be used for further
    /// processing.
    CURLINFO_TLS_SSL_PTR = 0x40002d,
    /// `CURLINFO_LONG + 46`. The http version used in the connection.
    CURLINFO_HTTP_VERSION = 0x20002e,
    /// `CURLINFO_LONG + 47`. Proxy certificate verification result.
    CURLINFO_PROXY_SSL_VERIFYRESULT = 0x20002f,
    /// `CURLINFO_LONG + 48`. The protocol used for the connection.
    ///
    /// `CURL_DEPRECATED(7.85.0, "Use CURLINFO_SCHEME")` in the frozen header.
    /// Kept, because AAP 0.8.2 forbids removing a deprecated public name.
    CURLINFO_PROTOCOL = 0x200030,
    /// `CURLINFO_STRING + 49`. The scheme used for the connection.
    CURLINFO_SCHEME = 0x100031,
    /// `CURLINFO_OFF_T + 50`. Total time of previous transfer.
    CURLINFO_TOTAL_TIME_T = 0x600032,
    /// `CURLINFO_OFF_T + 51`. Time from start until name resolving completed in
    /// number of microseconds.
    CURLINFO_NAMELOOKUP_TIME_T = 0x600033,
    /// `CURLINFO_OFF_T + 52`. The time it took from the start until the connect
    /// to the remote host (or proxy) was completed.
    CURLINFO_CONNECT_TIME_T = 0x600034,
    /// `CURLINFO_OFF_T + 53`. The time it took from the start until the file
    /// transfer is just about to begin.
    CURLINFO_PRETRANSFER_TIME_T = 0x600035,
    /// `CURLINFO_OFF_T + 54`. The time it took from the start until the first
    /// byte is received by libcurl.
    CURLINFO_STARTTRANSFER_TIME_T = 0x600036,
    /// `CURLINFO_OFF_T + 55`. The time it took for all redirection steps
    /// include name lookup, connect, pretransfer and transfer before final
    /// transaction was started.
    CURLINFO_REDIRECT_TIME_T = 0x600037,
    /// `CURLINFO_OFF_T + 56`. The time it took from the start until the SSL
    /// connect/handshake with the remote host was completed in number of
    /// microseconds.
    CURLINFO_APPCONNECT_TIME_T = 0x600038,
    /// `CURLINFO_OFF_T + 57`. The value from the Retry-After header.
    CURLINFO_RETRY_AFTER = 0x600039,
    /// `CURLINFO_STRING + 58`. Last used HTTP method.
    CURLINFO_EFFECTIVE_METHOD = 0x10003a,
    /// `CURLINFO_LONG + 59`. Detailed proxy error.
    CURLINFO_PROXY_ERROR = 0x20003b,
    /// `CURLINFO_STRING + 60`. Referrer header.
    CURLINFO_REFERER = 0x10003c,
    /// `CURLINFO_STRING + 61`. Get the default value for CURLOPT_CAINFO.
    CURLINFO_CAINFO = 0x10003d,
    /// `CURLINFO_STRING + 62`. Get the default value for CURLOPT_CAPATH.
    CURLINFO_CAPATH = 0x10003e,
    /// `CURLINFO_OFF_T + 63`. The ID of the transfer.
    CURLINFO_XFER_ID = 0x60003f,
    /// `CURLINFO_OFF_T + 64`. The ID of the last connection used by the
    /// transfer.
    CURLINFO_CONN_ID = 0x600040,
    /// `CURLINFO_OFF_T + 65`. The time during which the transfer was held in a
    /// waiting queue before it could start for real in number of microseconds.
    CURLINFO_QUEUE_TIME_T = 0x600041,
    /// `CURLINFO_LONG + 66`. Whether the proxy was used (Added in 8.7.0).
    CURLINFO_USED_PROXY = 0x200042,
    /// `CURLINFO_OFF_T + 67`. The time it took from the start until the last
    /// byte is sent by libcurl.
    CURLINFO_POSTTRANSFER_TIME_T = 0x600043,
    /// `CURLINFO_OFF_T + 68`. Amount of TLS early data sent (in number of
    /// bytes) when CURLSSLOPT_EARLYDATA is enabled.
    CURLINFO_EARLYDATA_SENT_T = 0x600044,
    /// `CURLINFO_LONG + 69`. Used HTTP authentication method.
    CURLINFO_HTTPAUTH_USED = 0x200045,
    /// `CURLINFO_LONG + 70`. Used HTTP proxy authentication methods.
    CURLINFO_PROXYAUTH_USED = 0x200046,
    /// Written in the frozen header as a BARE 70 (curl.h:2995): not a base
    /// composition, and not the 79 that is the token count.
    CURLINFO_LASTONE = 70,
}

impl CURLINFO {
    /// Every variant, in the frozen header's declaration order.
    ///
    /// `CURLINFO_LASTONE` is last, as in the header. Read by
    /// [`CURLINFO::from_c_int`] and by every test that asserts coverage.
    #[allow(dead_code)]
    pub(crate) const ABI_VARIANTS: &'static [CURLINFO] = &[
        CURLINFO::CURLINFO_NONE,
        CURLINFO::CURLINFO_EFFECTIVE_URL,
        CURLINFO::CURLINFO_RESPONSE_CODE,
        CURLINFO::CURLINFO_TOTAL_TIME,
        CURLINFO::CURLINFO_NAMELOOKUP_TIME,
        CURLINFO::CURLINFO_CONNECT_TIME,
        CURLINFO::CURLINFO_PRETRANSFER_TIME,
        CURLINFO::CURLINFO_SIZE_UPLOAD,
        CURLINFO::CURLINFO_SIZE_UPLOAD_T,
        CURLINFO::CURLINFO_SIZE_DOWNLOAD,
        CURLINFO::CURLINFO_SIZE_DOWNLOAD_T,
        CURLINFO::CURLINFO_SPEED_DOWNLOAD,
        CURLINFO::CURLINFO_SPEED_DOWNLOAD_T,
        CURLINFO::CURLINFO_SPEED_UPLOAD,
        CURLINFO::CURLINFO_SPEED_UPLOAD_T,
        CURLINFO::CURLINFO_HEADER_SIZE,
        CURLINFO::CURLINFO_REQUEST_SIZE,
        CURLINFO::CURLINFO_SSL_VERIFYRESULT,
        CURLINFO::CURLINFO_FILETIME,
        CURLINFO::CURLINFO_FILETIME_T,
        CURLINFO::CURLINFO_CONTENT_LENGTH_DOWNLOAD,
        CURLINFO::CURLINFO_CONTENT_LENGTH_DOWNLOAD_T,
        CURLINFO::CURLINFO_CONTENT_LENGTH_UPLOAD,
        CURLINFO::CURLINFO_CONTENT_LENGTH_UPLOAD_T,
        CURLINFO::CURLINFO_STARTTRANSFER_TIME,
        CURLINFO::CURLINFO_CONTENT_TYPE,
        CURLINFO::CURLINFO_REDIRECT_TIME,
        CURLINFO::CURLINFO_REDIRECT_COUNT,
        CURLINFO::CURLINFO_PRIVATE,
        CURLINFO::CURLINFO_HTTP_CONNECTCODE,
        CURLINFO::CURLINFO_HTTPAUTH_AVAIL,
        CURLINFO::CURLINFO_PROXYAUTH_AVAIL,
        CURLINFO::CURLINFO_OS_ERRNO,
        CURLINFO::CURLINFO_NUM_CONNECTS,
        CURLINFO::CURLINFO_SSL_ENGINES,
        CURLINFO::CURLINFO_COOKIELIST,
        CURLINFO::CURLINFO_LASTSOCKET,
        CURLINFO::CURLINFO_FTP_ENTRY_PATH,
        CURLINFO::CURLINFO_REDIRECT_URL,
        CURLINFO::CURLINFO_PRIMARY_IP,
        CURLINFO::CURLINFO_APPCONNECT_TIME,
        CURLINFO::CURLINFO_CERTINFO,
        CURLINFO::CURLINFO_CONDITION_UNMET,
        CURLINFO::CURLINFO_RTSP_SESSION_ID,
        CURLINFO::CURLINFO_RTSP_CLIENT_CSEQ,
        CURLINFO::CURLINFO_RTSP_SERVER_CSEQ,
        CURLINFO::CURLINFO_RTSP_CSEQ_RECV,
        CURLINFO::CURLINFO_PRIMARY_PORT,
        CURLINFO::CURLINFO_LOCAL_IP,
        CURLINFO::CURLINFO_LOCAL_PORT,
        CURLINFO::CURLINFO_TLS_SESSION,
        CURLINFO::CURLINFO_ACTIVESOCKET,
        CURLINFO::CURLINFO_TLS_SSL_PTR,
        CURLINFO::CURLINFO_HTTP_VERSION,
        CURLINFO::CURLINFO_PROXY_SSL_VERIFYRESULT,
        CURLINFO::CURLINFO_PROTOCOL,
        CURLINFO::CURLINFO_SCHEME,
        CURLINFO::CURLINFO_TOTAL_TIME_T,
        CURLINFO::CURLINFO_NAMELOOKUP_TIME_T,
        CURLINFO::CURLINFO_CONNECT_TIME_T,
        CURLINFO::CURLINFO_PRETRANSFER_TIME_T,
        CURLINFO::CURLINFO_STARTTRANSFER_TIME_T,
        CURLINFO::CURLINFO_REDIRECT_TIME_T,
        CURLINFO::CURLINFO_APPCONNECT_TIME_T,
        CURLINFO::CURLINFO_RETRY_AFTER,
        CURLINFO::CURLINFO_EFFECTIVE_METHOD,
        CURLINFO::CURLINFO_PROXY_ERROR,
        CURLINFO::CURLINFO_REFERER,
        CURLINFO::CURLINFO_CAINFO,
        CURLINFO::CURLINFO_CAPATH,
        CURLINFO::CURLINFO_XFER_ID,
        CURLINFO::CURLINFO_CONN_ID,
        CURLINFO::CURLINFO_QUEUE_TIME_T,
        CURLINFO::CURLINFO_USED_PROXY,
        CURLINFO::CURLINFO_POSTTRANSFER_TIME_T,
        CURLINFO::CURLINFO_EARLYDATA_SENT_T,
        CURLINFO::CURLINFO_HTTPAUTH_USED,
        CURLINFO::CURLINFO_PROXYAUTH_USED,
        CURLINFO::CURLINFO_LASTONE,
    ];

    /// The number of tokens the frozen enumeration declares.
    ///
    /// Seventy-nine, and NOT seventy: AAP 0.4.1's phrase "70 CURLINFO
    /// accessors" describes how many the getinfo implementation answers
    /// for, which is the value of `CURLINFO_LASTONE`, not the size of the
    /// enumeration. The two numbers are asserted separately below so that
    /// neither can be mistaken for the other.
    #[allow(dead_code)]
    pub(crate) const TOKEN_COUNT: usize = 79;

    /// The number of tokens written as `CURLINFO_<BASE> + n`.
    #[allow(dead_code)]
    pub(crate) const COMPOSED_COUNT: usize = 77;

    /// The C spelling of this member.
    ///
    /// An explicit match rather than `Debug`, because the spelling is ABI
    /// data that `build.rs` renders into the header, and the `Debug`
    /// representation of an enum carries no stability guarantee.
    #[allow(dead_code)]
    pub(crate) const fn c_name(self) -> &'static str {
        match self {
            CURLINFO::CURLINFO_NONE => "CURLINFO_NONE",
            CURLINFO::CURLINFO_EFFECTIVE_URL => "CURLINFO_EFFECTIVE_URL",
            CURLINFO::CURLINFO_RESPONSE_CODE => "CURLINFO_RESPONSE_CODE",
            CURLINFO::CURLINFO_TOTAL_TIME => "CURLINFO_TOTAL_TIME",
            CURLINFO::CURLINFO_NAMELOOKUP_TIME => "CURLINFO_NAMELOOKUP_TIME",
            CURLINFO::CURLINFO_CONNECT_TIME => "CURLINFO_CONNECT_TIME",
            CURLINFO::CURLINFO_PRETRANSFER_TIME => "CURLINFO_PRETRANSFER_TIME",
            CURLINFO::CURLINFO_SIZE_UPLOAD => "CURLINFO_SIZE_UPLOAD",
            CURLINFO::CURLINFO_SIZE_UPLOAD_T => "CURLINFO_SIZE_UPLOAD_T",
            CURLINFO::CURLINFO_SIZE_DOWNLOAD => "CURLINFO_SIZE_DOWNLOAD",
            CURLINFO::CURLINFO_SIZE_DOWNLOAD_T => "CURLINFO_SIZE_DOWNLOAD_T",
            CURLINFO::CURLINFO_SPEED_DOWNLOAD => "CURLINFO_SPEED_DOWNLOAD",
            CURLINFO::CURLINFO_SPEED_DOWNLOAD_T => "CURLINFO_SPEED_DOWNLOAD_T",
            CURLINFO::CURLINFO_SPEED_UPLOAD => "CURLINFO_SPEED_UPLOAD",
            CURLINFO::CURLINFO_SPEED_UPLOAD_T => "CURLINFO_SPEED_UPLOAD_T",
            CURLINFO::CURLINFO_HEADER_SIZE => "CURLINFO_HEADER_SIZE",
            CURLINFO::CURLINFO_REQUEST_SIZE => "CURLINFO_REQUEST_SIZE",
            CURLINFO::CURLINFO_SSL_VERIFYRESULT => "CURLINFO_SSL_VERIFYRESULT",
            CURLINFO::CURLINFO_FILETIME => "CURLINFO_FILETIME",
            CURLINFO::CURLINFO_FILETIME_T => "CURLINFO_FILETIME_T",
            CURLINFO::CURLINFO_CONTENT_LENGTH_DOWNLOAD => {
                "CURLINFO_CONTENT_LENGTH_DOWNLOAD"
            }
            CURLINFO::CURLINFO_CONTENT_LENGTH_DOWNLOAD_T => {
                "CURLINFO_CONTENT_LENGTH_DOWNLOAD_T"
            }
            CURLINFO::CURLINFO_CONTENT_LENGTH_UPLOAD => {
                "CURLINFO_CONTENT_LENGTH_UPLOAD"
            }
            CURLINFO::CURLINFO_CONTENT_LENGTH_UPLOAD_T => {
                "CURLINFO_CONTENT_LENGTH_UPLOAD_T"
            }
            CURLINFO::CURLINFO_STARTTRANSFER_TIME => {
                "CURLINFO_STARTTRANSFER_TIME"
            }
            CURLINFO::CURLINFO_CONTENT_TYPE => "CURLINFO_CONTENT_TYPE",
            CURLINFO::CURLINFO_REDIRECT_TIME => "CURLINFO_REDIRECT_TIME",
            CURLINFO::CURLINFO_REDIRECT_COUNT => "CURLINFO_REDIRECT_COUNT",
            CURLINFO::CURLINFO_PRIVATE => "CURLINFO_PRIVATE",
            CURLINFO::CURLINFO_HTTP_CONNECTCODE => "CURLINFO_HTTP_CONNECTCODE",
            CURLINFO::CURLINFO_HTTPAUTH_AVAIL => "CURLINFO_HTTPAUTH_AVAIL",
            CURLINFO::CURLINFO_PROXYAUTH_AVAIL => "CURLINFO_PROXYAUTH_AVAIL",
            CURLINFO::CURLINFO_OS_ERRNO => "CURLINFO_OS_ERRNO",
            CURLINFO::CURLINFO_NUM_CONNECTS => "CURLINFO_NUM_CONNECTS",
            CURLINFO::CURLINFO_SSL_ENGINES => "CURLINFO_SSL_ENGINES",
            CURLINFO::CURLINFO_COOKIELIST => "CURLINFO_COOKIELIST",
            CURLINFO::CURLINFO_LASTSOCKET => "CURLINFO_LASTSOCKET",
            CURLINFO::CURLINFO_FTP_ENTRY_PATH => "CURLINFO_FTP_ENTRY_PATH",
            CURLINFO::CURLINFO_REDIRECT_URL => "CURLINFO_REDIRECT_URL",
            CURLINFO::CURLINFO_PRIMARY_IP => "CURLINFO_PRIMARY_IP",
            CURLINFO::CURLINFO_APPCONNECT_TIME => "CURLINFO_APPCONNECT_TIME",
            CURLINFO::CURLINFO_CERTINFO => "CURLINFO_CERTINFO",
            CURLINFO::CURLINFO_CONDITION_UNMET => "CURLINFO_CONDITION_UNMET",
            CURLINFO::CURLINFO_RTSP_SESSION_ID => "CURLINFO_RTSP_SESSION_ID",
            CURLINFO::CURLINFO_RTSP_CLIENT_CSEQ => "CURLINFO_RTSP_CLIENT_CSEQ",
            CURLINFO::CURLINFO_RTSP_SERVER_CSEQ => "CURLINFO_RTSP_SERVER_CSEQ",
            CURLINFO::CURLINFO_RTSP_CSEQ_RECV => "CURLINFO_RTSP_CSEQ_RECV",
            CURLINFO::CURLINFO_PRIMARY_PORT => "CURLINFO_PRIMARY_PORT",
            CURLINFO::CURLINFO_LOCAL_IP => "CURLINFO_LOCAL_IP",
            CURLINFO::CURLINFO_LOCAL_PORT => "CURLINFO_LOCAL_PORT",
            CURLINFO::CURLINFO_TLS_SESSION => "CURLINFO_TLS_SESSION",
            CURLINFO::CURLINFO_ACTIVESOCKET => "CURLINFO_ACTIVESOCKET",
            CURLINFO::CURLINFO_TLS_SSL_PTR => "CURLINFO_TLS_SSL_PTR",
            CURLINFO::CURLINFO_HTTP_VERSION => "CURLINFO_HTTP_VERSION",
            CURLINFO::CURLINFO_PROXY_SSL_VERIFYRESULT => {
                "CURLINFO_PROXY_SSL_VERIFYRESULT"
            }
            CURLINFO::CURLINFO_PROTOCOL => "CURLINFO_PROTOCOL",
            CURLINFO::CURLINFO_SCHEME => "CURLINFO_SCHEME",
            CURLINFO::CURLINFO_TOTAL_TIME_T => "CURLINFO_TOTAL_TIME_T",
            CURLINFO::CURLINFO_NAMELOOKUP_TIME_T => {
                "CURLINFO_NAMELOOKUP_TIME_T"
            }
            CURLINFO::CURLINFO_CONNECT_TIME_T => "CURLINFO_CONNECT_TIME_T",
            CURLINFO::CURLINFO_PRETRANSFER_TIME_T => {
                "CURLINFO_PRETRANSFER_TIME_T"
            }
            CURLINFO::CURLINFO_STARTTRANSFER_TIME_T => {
                "CURLINFO_STARTTRANSFER_TIME_T"
            }
            CURLINFO::CURLINFO_REDIRECT_TIME_T => "CURLINFO_REDIRECT_TIME_T",
            CURLINFO::CURLINFO_APPCONNECT_TIME_T => {
                "CURLINFO_APPCONNECT_TIME_T"
            }
            CURLINFO::CURLINFO_RETRY_AFTER => "CURLINFO_RETRY_AFTER",
            CURLINFO::CURLINFO_EFFECTIVE_METHOD => "CURLINFO_EFFECTIVE_METHOD",
            CURLINFO::CURLINFO_PROXY_ERROR => "CURLINFO_PROXY_ERROR",
            CURLINFO::CURLINFO_REFERER => "CURLINFO_REFERER",
            CURLINFO::CURLINFO_CAINFO => "CURLINFO_CAINFO",
            CURLINFO::CURLINFO_CAPATH => "CURLINFO_CAPATH",
            CURLINFO::CURLINFO_XFER_ID => "CURLINFO_XFER_ID",
            CURLINFO::CURLINFO_CONN_ID => "CURLINFO_CONN_ID",
            CURLINFO::CURLINFO_QUEUE_TIME_T => "CURLINFO_QUEUE_TIME_T",
            CURLINFO::CURLINFO_USED_PROXY => "CURLINFO_USED_PROXY",
            CURLINFO::CURLINFO_POSTTRANSFER_TIME_T => {
                "CURLINFO_POSTTRANSFER_TIME_T"
            }
            CURLINFO::CURLINFO_EARLYDATA_SENT_T => "CURLINFO_EARLYDATA_SENT_T",
            CURLINFO::CURLINFO_HTTPAUTH_USED => "CURLINFO_HTTPAUTH_USED",
            CURLINFO::CURLINFO_PROXYAUTH_USED => "CURLINFO_PROXYAUTH_USED",
            CURLINFO::CURLINFO_LASTONE => "CURLINFO_LASTONE",
        }
    }

    /// The pinned integer, as it crosses the C boundary.
    #[allow(dead_code)]
    pub(crate) const fn as_c_int(self) -> c_int {
        self as c_int
    }

    /// Recover a member from the integer a C caller passed.
    ///
    /// `None` for anything the enumeration does not declare. A caller that
    /// maps `None` onto `CURLE_UNKNOWN_OPTION` reproduces curl's behaviour
    /// for an unrecognised request.
    #[allow(dead_code)]
    pub(crate) fn from_c_int(value: c_int) -> Option<CURLINFO> {
        CURLINFO::ABI_VARIANTS
            .iter()
            .copied()
            .find(|candidate| candidate.as_c_int() == value)
    }

    /// The base this member was composed from, as a SPELLING.
    ///
    /// `None` for the two members that are not composed. Read from
    /// [`INFO_COMPOSITION`] rather than derived, because `CURLINFO_PTR` and
    /// `CURLINFO_SLIST` are one integer and the spelling cannot be
    /// recovered from it.
    #[allow(dead_code)]
    pub(crate) fn base(self) -> Option<InfoBase> {
        INFO_COMPOSITION
            .iter()
            .find(|(info, _, _)| *info == self)
            .map(|(_, base, _)| *base)
    }

    /// The ordinal this member was composed with -- the `n` in
    /// `CURLINFO_<BASE> + n`. `None` for the two uncomposed members.
    #[allow(dead_code)]
    pub(crate) fn ordinal(self) -> Option<c_int> {
        INFO_COMPOSITION
            .iter()
            .find(|(info, _, _)| *info == self)
            .map(|(_, _, ordinal)| *ordinal)
    }

    /// The pointer type `curl_easy_getinfo` must read for this member.
    ///
    /// Masks the value exactly as `lib/getinfo.c:636` does, so a member
    /// whose base is `CURLINFO_PTR` reports [`InfoValueKind::Slist`] and
    /// the two uncomposed members report `None`.
    #[allow(dead_code)]
    pub(crate) const fn value_kind(self) -> Option<InfoValueKind> {
        info_value_kind(self.as_c_int())
    }
}

/// The `(member, base spelling, ordinal)` triple for each composed member.
///
/// 77 rows -- every member except `CURLINFO_NONE` and `CURLINFO_LASTONE`.
/// The base and the ordinal are INDEPENDENT axes, and they have to be: the
/// ordinal is reused across bases (`n = 7` is both
/// `CURLINFO_SIZE_UPLOAD` on `CURLINFO_DOUBLE` and
/// `CURLINFO_SIZE_UPLOAD_T` on `CURLINFO_OFF_T`), so `(base, ordinal)` is
/// the unique key and the ordinal alone never is. This is the data
/// `build.rs` renders back into the header's `= CURLINFO_<BASE> + n` form;
/// a table holding only the composed integer could not produce it.
#[allow(dead_code)]
pub(crate) const INFO_COMPOSITION: &[(CURLINFO, InfoBase, c_int)] = &[
    (CURLINFO::CURLINFO_EFFECTIVE_URL, InfoBase::String, 1),
    (CURLINFO::CURLINFO_RESPONSE_CODE, InfoBase::Long, 2),
    (CURLINFO::CURLINFO_TOTAL_TIME, InfoBase::Double, 3),
    (CURLINFO::CURLINFO_NAMELOOKUP_TIME, InfoBase::Double, 4),
    (CURLINFO::CURLINFO_CONNECT_TIME, InfoBase::Double, 5),
    (CURLINFO::CURLINFO_PRETRANSFER_TIME, InfoBase::Double, 6),
    (CURLINFO::CURLINFO_SIZE_UPLOAD, InfoBase::Double, 7),
    (CURLINFO::CURLINFO_SIZE_UPLOAD_T, InfoBase::OffT, 7),
    (CURLINFO::CURLINFO_SIZE_DOWNLOAD, InfoBase::Double, 8),
    (CURLINFO::CURLINFO_SIZE_DOWNLOAD_T, InfoBase::OffT, 8),
    (CURLINFO::CURLINFO_SPEED_DOWNLOAD, InfoBase::Double, 9),
    (CURLINFO::CURLINFO_SPEED_DOWNLOAD_T, InfoBase::OffT, 9),
    (CURLINFO::CURLINFO_SPEED_UPLOAD, InfoBase::Double, 10),
    (CURLINFO::CURLINFO_SPEED_UPLOAD_T, InfoBase::OffT, 10),
    (CURLINFO::CURLINFO_HEADER_SIZE, InfoBase::Long, 11),
    (CURLINFO::CURLINFO_REQUEST_SIZE, InfoBase::Long, 12),
    (CURLINFO::CURLINFO_SSL_VERIFYRESULT, InfoBase::Long, 13),
    (CURLINFO::CURLINFO_FILETIME, InfoBase::Long, 14),
    (CURLINFO::CURLINFO_FILETIME_T, InfoBase::OffT, 14),
    (
        CURLINFO::CURLINFO_CONTENT_LENGTH_DOWNLOAD,
        InfoBase::Double,
        15,
    ),
    (
        CURLINFO::CURLINFO_CONTENT_LENGTH_DOWNLOAD_T,
        InfoBase::OffT,
        15,
    ),
    (
        CURLINFO::CURLINFO_CONTENT_LENGTH_UPLOAD,
        InfoBase::Double,
        16,
    ),
    (
        CURLINFO::CURLINFO_CONTENT_LENGTH_UPLOAD_T,
        InfoBase::OffT,
        16,
    ),
    (CURLINFO::CURLINFO_STARTTRANSFER_TIME, InfoBase::Double, 17),
    (CURLINFO::CURLINFO_CONTENT_TYPE, InfoBase::String, 18),
    (CURLINFO::CURLINFO_REDIRECT_TIME, InfoBase::Double, 19),
    (CURLINFO::CURLINFO_REDIRECT_COUNT, InfoBase::Long, 20),
    (CURLINFO::CURLINFO_PRIVATE, InfoBase::String, 21),
    (CURLINFO::CURLINFO_HTTP_CONNECTCODE, InfoBase::Long, 22),
    (CURLINFO::CURLINFO_HTTPAUTH_AVAIL, InfoBase::Long, 23),
    (CURLINFO::CURLINFO_PROXYAUTH_AVAIL, InfoBase::Long, 24),
    (CURLINFO::CURLINFO_OS_ERRNO, InfoBase::Long, 25),
    (CURLINFO::CURLINFO_NUM_CONNECTS, InfoBase::Long, 26),
    (CURLINFO::CURLINFO_SSL_ENGINES, InfoBase::Slist, 27),
    (CURLINFO::CURLINFO_COOKIELIST, InfoBase::Slist, 28),
    (CURLINFO::CURLINFO_LASTSOCKET, InfoBase::Long, 29),
    (CURLINFO::CURLINFO_FTP_ENTRY_PATH, InfoBase::String, 30),
    (CURLINFO::CURLINFO_REDIRECT_URL, InfoBase::String, 31),
    (CURLINFO::CURLINFO_PRIMARY_IP, InfoBase::String, 32),
    (CURLINFO::CURLINFO_APPCONNECT_TIME, InfoBase::Double, 33),
    (CURLINFO::CURLINFO_CERTINFO, InfoBase::Ptr, 34),
    (CURLINFO::CURLINFO_CONDITION_UNMET, InfoBase::Long, 35),
    (CURLINFO::CURLINFO_RTSP_SESSION_ID, InfoBase::String, 36),
    (CURLINFO::CURLINFO_RTSP_CLIENT_CSEQ, InfoBase::Long, 37),
    (CURLINFO::CURLINFO_RTSP_SERVER_CSEQ, InfoBase::Long, 38),
    (CURLINFO::CURLINFO_RTSP_CSEQ_RECV, InfoBase::Long, 39),
    (CURLINFO::CURLINFO_PRIMARY_PORT, InfoBase::Long, 40),
    (CURLINFO::CURLINFO_LOCAL_IP, InfoBase::String, 41),
    (CURLINFO::CURLINFO_LOCAL_PORT, InfoBase::Long, 42),
    (CURLINFO::CURLINFO_TLS_SESSION, InfoBase::Ptr, 43),
    (CURLINFO::CURLINFO_ACTIVESOCKET, InfoBase::Socket, 44),
    (CURLINFO::CURLINFO_TLS_SSL_PTR, InfoBase::Ptr, 45),
    (CURLINFO::CURLINFO_HTTP_VERSION, InfoBase::Long, 46),
    (
        CURLINFO::CURLINFO_PROXY_SSL_VERIFYRESULT,
        InfoBase::Long,
        47,
    ),
    (CURLINFO::CURLINFO_PROTOCOL, InfoBase::Long, 48),
    (CURLINFO::CURLINFO_SCHEME, InfoBase::String, 49),
    (CURLINFO::CURLINFO_TOTAL_TIME_T, InfoBase::OffT, 50),
    (CURLINFO::CURLINFO_NAMELOOKUP_TIME_T, InfoBase::OffT, 51),
    (CURLINFO::CURLINFO_CONNECT_TIME_T, InfoBase::OffT, 52),
    (CURLINFO::CURLINFO_PRETRANSFER_TIME_T, InfoBase::OffT, 53),
    (CURLINFO::CURLINFO_STARTTRANSFER_TIME_T, InfoBase::OffT, 54),
    (CURLINFO::CURLINFO_REDIRECT_TIME_T, InfoBase::OffT, 55),
    (CURLINFO::CURLINFO_APPCONNECT_TIME_T, InfoBase::OffT, 56),
    (CURLINFO::CURLINFO_RETRY_AFTER, InfoBase::OffT, 57),
    (CURLINFO::CURLINFO_EFFECTIVE_METHOD, InfoBase::String, 58),
    (CURLINFO::CURLINFO_PROXY_ERROR, InfoBase::Long, 59),
    (CURLINFO::CURLINFO_REFERER, InfoBase::String, 60),
    (CURLINFO::CURLINFO_CAINFO, InfoBase::String, 61),
    (CURLINFO::CURLINFO_CAPATH, InfoBase::String, 62),
    (CURLINFO::CURLINFO_XFER_ID, InfoBase::OffT, 63),
    (CURLINFO::CURLINFO_CONN_ID, InfoBase::OffT, 64),
    (CURLINFO::CURLINFO_QUEUE_TIME_T, InfoBase::OffT, 65),
    (CURLINFO::CURLINFO_USED_PROXY, InfoBase::Long, 66),
    (CURLINFO::CURLINFO_POSTTRANSFER_TIME_T, InfoBase::OffT, 67),
    (CURLINFO::CURLINFO_EARLYDATA_SENT_T, InfoBase::OffT, 68),
    (CURLINFO::CURLINFO_HTTPAUTH_USED, InfoBase::Long, 69),
    (CURLINFO::CURLINFO_PROXYAUTH_USED, InfoBase::Long, 70),
];

/// One `CURL_DEPRECATED(version, message)` attribute from the frozen header.
///
/// Held in Rust because cbindgen cannot express the attribute in any of the
/// four positions the headers use it in, so the affected declarations are
/// carried verbatim; this table is what lets a test assert that the
/// verbatim text still covers exactly the members it covered in curl
/// 8.19.0-DEV. Deprecated is not removed: AAP 0.8.2 keeps every one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct Deprecation<T> {
    /// The enumerator the attribute is written on.
    pub(crate) member: T,
    /// The version token, UNQUOTED in the frozen header.
    pub(crate) since: &'static str,
    /// The advisory message, empty for the members that have no successor.
    pub(crate) message: &'static str,
}

/// The nine deprecated `CURLINFO` members (curl.h:2908-2971).
///
/// All nine carry the attribute in the position between the member name and
/// its `=`, which is one of the four positions cbindgen cannot write.
#[allow(dead_code)]
pub(crate) const INFO_DEPRECATIONS: &[Deprecation<CURLINFO>] = &[
    Deprecation {
        member: CURLINFO::CURLINFO_SIZE_UPLOAD,
        since: "7.55.0",
        message: "Use CURLINFO_SIZE_UPLOAD_T",
    },
    Deprecation {
        member: CURLINFO::CURLINFO_SIZE_DOWNLOAD,
        since: "7.55.0",
        message: "Use CURLINFO_SIZE_DOWNLOAD_T",
    },
    Deprecation {
        member: CURLINFO::CURLINFO_SPEED_DOWNLOAD,
        since: "7.55.0",
        message: "Use CURLINFO_SPEED_DOWNLOAD_T",
    },
    Deprecation {
        member: CURLINFO::CURLINFO_SPEED_UPLOAD,
        since: "7.55.0",
        message: "Use CURLINFO_SPEED_UPLOAD_T",
    },
    Deprecation {
        member: CURLINFO::CURLINFO_CONTENT_LENGTH_DOWNLOAD,
        since: "7.55.0",
        message: "Use CURLINFO_CONTENT_LENGTH_DOWNLOAD_T",
    },
    Deprecation {
        member: CURLINFO::CURLINFO_CONTENT_LENGTH_UPLOAD,
        since: "7.55.0",
        message: "Use CURLINFO_CONTENT_LENGTH_UPLOAD_T",
    },
    Deprecation {
        member: CURLINFO::CURLINFO_LASTSOCKET,
        since: "7.45.0",
        message: "Use CURLINFO_ACTIVESOCKET",
    },
    Deprecation {
        member: CURLINFO::CURLINFO_TLS_SESSION,
        since: "7.48.0",
        message: "Use CURLINFO_TLS_SSL_PTR",
    },
    Deprecation {
        member: CURLINFO::CURLINFO_PROTOCOL,
        since: "7.85.0",
        message: "Use CURLINFO_SCHEME",
    },
];

/// `#define CURLINFO_HTTP_CODE CURLINFO_RESPONSE_CODE` (curl.h:3000).
///
/// The one preprocessor alias in the information space, and the only reason
/// it is a `pub(crate) const` of enum type rather than an integer is that
/// the alias expands to an IDENTIFIER in the frozen header: it resolves
/// THROUGH the enumeration, so it cannot drift from it. `build.rs` carries
/// the `#define` verbatim, which is why this is not `pub`.
#[allow(dead_code)]
pub(crate) const CURLINFO_HTTP_CODE: CURLINFO =
    CURLINFO::CURLINFO_RESPONSE_CODE;

// ---------------------------------------------------------------------------
// CURLformoption: the legacy form-post option space.
// ---------------------------------------------------------------------------

// Unlike the two spaces above, these members are plain declaration
// ordinals: `include/curl/curl.h:2555-2584` composes nothing. They live
// here anyway, and not in `ffi/codes.rs`, because they are the argument
// VALUES `curl_formadd` reads out of its variadic argument list -- option
// identity for the retired form API, exactly as `CURLoption` is option
// identity for the easy API. `CURLFORMcode`, which is a RESULT and not an
// argument, is `ffi/codes.rs`'s; note also the spelling difference, a
// lowercase `f` here against `CURLFORMcode`'s uppercase.
//
// CORRECTION 12. Exactly EIGHTEEN of the 22 members carry
// `CURL_DEPRECATED(7.56.0, ...)`, not 21. The four without it are
// `CURLFORM_OBSOLETE` (:2566), `CURLFORM_END` (:2576),
// `CURLFORM_OBSOLETE2` (:2577) and `CURLFORM_LASTENTRY` (:2583); the first,
// third and fourth are retired or sentinel slots with nothing to advise,
// and `CURLFORM_END` cannot be deprecated because a caller has no way to
// stop passing it. Measured by brace-and-paren-balanced scanning of the
// enumeration body; a per-line regex under-counts, which is how the 21
// figure arises.
//
// CORRECTION 20. `CURLFORM_CONTENTLEN` puts the attribute in a FOURTH
// position -- the member name and its trailing comment on :2580, the
// attribute alone on :2581. Across the twelve public headers the positions
// are: post-name pre-`=` (`curl_sslbackend`, `CURLINFO`), an attribute line
// BEFORE the name (five prototypes), post-name (`CURLformoption`,
// `CURLFORMcode`), and post-name-post-comment-on-the-next-line (here).
// cbindgen can express none of the four, which is why all of them are
// carried verbatim by `build.rs` and asserted against
// [`FORM_DEPRECATIONS`].

/// Every `CURLFORM_*` identifier, with its ordinal pinned.
///
/// 22 members, values 0 through 21, none written explicitly in the frozen
/// header. They are written explicitly here so that inserting a member in
/// the middle cannot silently renumber its successors -- the same discipline
/// AAP 0.6.1 requires of `CURLcode`, and for the same reason: a caller
/// compiled against curl 8.19.0-DEV holds the number, not the name.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)]
// Frozen C ABI name: `include/curl/curl.h:2584` spells it with a lowercase
// `f`, and AAP 0.8.1 forbids changing a public typedef.
#[allow(clippy::enum_variant_names)]
pub enum CURLformoption {
    /// The first one is unused.
    ///
    /// `CURL_DEPRECATED(7.56.0, "")` in the frozen header. Kept, because AAP
    /// 0.8.2 forbids removing a deprecated public name.
    CURLFORM_NOTHING = 0,
    /// Name of the part, copied.
    ///
    /// `CURL_DEPRECATED(7.56.0, "Use curl_mime_name()")` in the frozen header.
    /// Kept, because AAP 0.8.2 forbids removing a deprecated public name.
    CURLFORM_COPYNAME = 1,
    /// Name of the part, by pointer.
    ///
    /// `CURL_DEPRECATED(7.56.0, "Use curl_mime_name()")` in the frozen header.
    /// Kept, because AAP 0.8.2 forbids removing a deprecated public name.
    CURLFORM_PTRNAME = 2,
    /// Length of a name that is not NUL terminated.
    ///
    /// `CURL_DEPRECATED(7.56.0, "")` in the frozen header. Kept, because AAP
    /// 0.8.2 forbids removing a deprecated public name.
    CURLFORM_NAMELENGTH = 3,
    /// Contents of the part, copied.
    ///
    /// `CURL_DEPRECATED(7.56.0, "Use curl_mime_data()")` in the frozen header.
    /// Kept, because AAP 0.8.2 forbids removing a deprecated public name.
    CURLFORM_COPYCONTENTS = 4,
    /// Contents of the part, by pointer.
    ///
    /// `CURL_DEPRECATED(7.56.0, "Use curl_mime_data()")` in the frozen header.
    /// Kept, because AAP 0.8.2 forbids removing a deprecated public name.
    CURLFORM_PTRCONTENTS = 5,
    /// Length of the contents, as a long.
    ///
    /// `CURL_DEPRECATED(7.56.0, "Use curl_mime_data()")` in the frozen header.
    /// Kept, because AAP 0.8.2 forbids removing a deprecated public name.
    CURLFORM_CONTENTSLENGTH = 6,
    /// Read the contents from a named file.
    ///
    /// `CURL_DEPRECATED(7.56.0, "Use curl_mime_data_cb()")` in the frozen
    /// header. Kept, because AAP 0.8.2 forbids removing a deprecated public
    /// name.
    CURLFORM_FILECONTENT = 7,
    /// Continue reading options from a `curl_forms` array.
    ///
    /// `CURL_DEPRECATED(7.56.0, "")` in the frozen header. Kept, because AAP
    /// 0.8.2 forbids removing a deprecated public name.
    CURLFORM_ARRAY = 8,
    /// Retired slot, held so the successors keep their ordinals.
    CURLFORM_OBSOLETE = 9,
    /// Upload the named file as this part.
    ///
    /// `CURL_DEPRECATED(7.56.0, "Use curl_mime_filedata()")` in the frozen
    /// header. Kept, because AAP 0.8.2 forbids removing a deprecated public
    /// name.
    CURLFORM_FILE = 10,
    /// Set the remote file name for a buffer upload.
    ///
    /// `CURL_DEPRECATED(7.56.0, "Use curl_mime_filename()")` in the frozen
    /// header. Kept, because AAP 0.8.2 forbids removing a deprecated public
    /// name.
    CURLFORM_BUFFER = 11,
    /// Contents of a buffer upload.
    ///
    /// `CURL_DEPRECATED(7.56.0, "Use curl_mime_data()")` in the frozen header.
    /// Kept, because AAP 0.8.2 forbids removing a deprecated public name.
    CURLFORM_BUFFERPTR = 12,
    /// Length of a buffer upload.
    ///
    /// `CURL_DEPRECATED(7.56.0, "Use curl_mime_data()")` in the frozen header.
    /// Kept, because AAP 0.8.2 forbids removing a deprecated public name.
    CURLFORM_BUFFERLENGTH = 13,
    /// Content-Type of the part.
    ///
    /// `CURL_DEPRECATED(7.56.0, "Use curl_mime_type()")` in the frozen header.
    /// Kept, because AAP 0.8.2 forbids removing a deprecated public name.
    CURLFORM_CONTENTTYPE = 14,
    /// Extra headers for the part.
    ///
    /// `CURL_DEPRECATED(7.56.0, "Use curl_mime_headers()")` in the frozen
    /// header. Kept, because AAP 0.8.2 forbids removing a deprecated public
    /// name.
    CURLFORM_CONTENTHEADER = 15,
    /// Remote file name of the part.
    ///
    /// `CURL_DEPRECATED(7.56.0, "Use curl_mime_filename()")` in the frozen
    /// header. Kept, because AAP 0.8.2 forbids removing a deprecated public
    /// name.
    CURLFORM_FILENAME = 16,
    /// Terminates the option list. Never deprecated: a caller cannot stop
    /// passing it.
    CURLFORM_END = 17,
    /// Second retired slot, held for the same reason as the first.
    CURLFORM_OBSOLETE2 = 18,
    /// Read the contents through the read callback.
    ///
    /// `CURL_DEPRECATED(7.56.0, "Use curl_mime_data_cb()")` in the frozen
    /// header. Kept, because AAP 0.8.2 forbids removing a deprecated public
    /// name.
    CURLFORM_STREAM = 19,
    /// Length of the contents, as a `curl_off_t`. Added in 7.46.0.
    ///
    /// `CURL_DEPRECATED(7.56.0, "Use curl_mime_data()")` in the frozen header.
    /// Kept, because AAP 0.8.2 forbids removing a deprecated public name.
    CURLFORM_CONTENTLEN = 20,
    /// The last unused.
    CURLFORM_LASTENTRY = 21,
}

impl CURLformoption {
    /// Every variant, in the frozen header's declaration order.
    #[allow(dead_code)]
    pub(crate) const ABI_VARIANTS: &'static [CURLformoption] = &[
        CURLformoption::CURLFORM_NOTHING,
        CURLformoption::CURLFORM_COPYNAME,
        CURLformoption::CURLFORM_PTRNAME,
        CURLformoption::CURLFORM_NAMELENGTH,
        CURLformoption::CURLFORM_COPYCONTENTS,
        CURLformoption::CURLFORM_PTRCONTENTS,
        CURLformoption::CURLFORM_CONTENTSLENGTH,
        CURLformoption::CURLFORM_FILECONTENT,
        CURLformoption::CURLFORM_ARRAY,
        CURLformoption::CURLFORM_OBSOLETE,
        CURLformoption::CURLFORM_FILE,
        CURLformoption::CURLFORM_BUFFER,
        CURLformoption::CURLFORM_BUFFERPTR,
        CURLformoption::CURLFORM_BUFFERLENGTH,
        CURLformoption::CURLFORM_CONTENTTYPE,
        CURLformoption::CURLFORM_CONTENTHEADER,
        CURLformoption::CURLFORM_FILENAME,
        CURLformoption::CURLFORM_END,
        CURLformoption::CURLFORM_OBSOLETE2,
        CURLformoption::CURLFORM_STREAM,
        CURLformoption::CURLFORM_CONTENTLEN,
        CURLformoption::CURLFORM_LASTENTRY,
    ];

    /// The number of tokens the frozen enumeration declares.
    #[allow(dead_code)]
    pub(crate) const TOKEN_COUNT: usize = 22;

    /// The C spelling of this member.
    #[allow(dead_code)]
    pub(crate) const fn c_name(self) -> &'static str {
        match self {
            CURLformoption::CURLFORM_NOTHING => "CURLFORM_NOTHING",
            CURLformoption::CURLFORM_COPYNAME => "CURLFORM_COPYNAME",
            CURLformoption::CURLFORM_PTRNAME => "CURLFORM_PTRNAME",
            CURLformoption::CURLFORM_NAMELENGTH => "CURLFORM_NAMELENGTH",
            CURLformoption::CURLFORM_COPYCONTENTS => "CURLFORM_COPYCONTENTS",
            CURLformoption::CURLFORM_PTRCONTENTS => "CURLFORM_PTRCONTENTS",
            CURLformoption::CURLFORM_CONTENTSLENGTH => {
                "CURLFORM_CONTENTSLENGTH"
            }
            CURLformoption::CURLFORM_FILECONTENT => "CURLFORM_FILECONTENT",
            CURLformoption::CURLFORM_ARRAY => "CURLFORM_ARRAY",
            CURLformoption::CURLFORM_OBSOLETE => "CURLFORM_OBSOLETE",
            CURLformoption::CURLFORM_FILE => "CURLFORM_FILE",
            CURLformoption::CURLFORM_BUFFER => "CURLFORM_BUFFER",
            CURLformoption::CURLFORM_BUFFERPTR => "CURLFORM_BUFFERPTR",
            CURLformoption::CURLFORM_BUFFERLENGTH => "CURLFORM_BUFFERLENGTH",
            CURLformoption::CURLFORM_CONTENTTYPE => "CURLFORM_CONTENTTYPE",
            CURLformoption::CURLFORM_CONTENTHEADER => "CURLFORM_CONTENTHEADER",
            CURLformoption::CURLFORM_FILENAME => "CURLFORM_FILENAME",
            CURLformoption::CURLFORM_END => "CURLFORM_END",
            CURLformoption::CURLFORM_OBSOLETE2 => "CURLFORM_OBSOLETE2",
            CURLformoption::CURLFORM_STREAM => "CURLFORM_STREAM",
            CURLformoption::CURLFORM_CONTENTLEN => "CURLFORM_CONTENTLEN",
            CURLformoption::CURLFORM_LASTENTRY => "CURLFORM_LASTENTRY",
        }
    }

    /// The pinned integer, as it crosses the C boundary.
    #[allow(dead_code)]
    pub(crate) const fn as_c_int(self) -> c_int {
        self as c_int
    }

    /// Recover a member from the integer a C caller passed.
    ///
    /// `None` for anything outside 0..=21. `curl_formadd` returns
    /// `CURL_FORMADD_UNKNOWN_OPTION` for such a value.
    #[allow(dead_code)]
    pub(crate) fn from_c_int(value: c_int) -> Option<CURLformoption> {
        CURLformoption::ABI_VARIANTS
            .iter()
            .copied()
            .find(|candidate| candidate.as_c_int() == value)
    }
}

/// The eighteen deprecated `CURLformoption` members (curl.h:2557-2581).
#[allow(dead_code)]
pub(crate) const FORM_DEPRECATIONS: &[Deprecation<CURLformoption>] = &[
    Deprecation {
        member: CURLformoption::CURLFORM_NOTHING,
        since: "7.56.0",
        message: "",
    },
    Deprecation {
        member: CURLformoption::CURLFORM_COPYNAME,
        since: "7.56.0",
        message: "Use curl_mime_name()",
    },
    Deprecation {
        member: CURLformoption::CURLFORM_PTRNAME,
        since: "7.56.0",
        message: "Use curl_mime_name()",
    },
    Deprecation {
        member: CURLformoption::CURLFORM_NAMELENGTH,
        since: "7.56.0",
        message: "",
    },
    Deprecation {
        member: CURLformoption::CURLFORM_COPYCONTENTS,
        since: "7.56.0",
        message: "Use curl_mime_data()",
    },
    Deprecation {
        member: CURLformoption::CURLFORM_PTRCONTENTS,
        since: "7.56.0",
        message: "Use curl_mime_data()",
    },
    Deprecation {
        member: CURLformoption::CURLFORM_CONTENTSLENGTH,
        since: "7.56.0",
        message: "Use curl_mime_data()",
    },
    Deprecation {
        member: CURLformoption::CURLFORM_FILECONTENT,
        since: "7.56.0",
        message: "Use curl_mime_data_cb()",
    },
    Deprecation {
        member: CURLformoption::CURLFORM_ARRAY,
        since: "7.56.0",
        message: "",
    },
    Deprecation {
        member: CURLformoption::CURLFORM_FILE,
        since: "7.56.0",
        message: "Use curl_mime_filedata()",
    },
    Deprecation {
        member: CURLformoption::CURLFORM_BUFFER,
        since: "7.56.0",
        message: "Use curl_mime_filename()",
    },
    Deprecation {
        member: CURLformoption::CURLFORM_BUFFERPTR,
        since: "7.56.0",
        message: "Use curl_mime_data()",
    },
    Deprecation {
        member: CURLformoption::CURLFORM_BUFFERLENGTH,
        since: "7.56.0",
        message: "Use curl_mime_data()",
    },
    Deprecation {
        member: CURLformoption::CURLFORM_CONTENTTYPE,
        since: "7.56.0",
        message: "Use curl_mime_type()",
    },
    Deprecation {
        member: CURLformoption::CURLFORM_CONTENTHEADER,
        since: "7.56.0",
        message: "Use curl_mime_headers()",
    },
    Deprecation {
        member: CURLformoption::CURLFORM_FILENAME,
        since: "7.56.0",
        message: "Use curl_mime_filename()",
    },
    Deprecation {
        member: CURLformoption::CURLFORM_STREAM,
        since: "7.56.0",
        message: "Use curl_mime_data_cb()",
    },
    Deprecation {
        member: CURLformoption::CURLFORM_CONTENTLEN,
        since: "7.56.0",
        message: "Use curl_mime_data()",
    },
];

// ---------------------------------------------------------------------------
// CURLOPT_WS_OPTIONS argument bits.
// ---------------------------------------------------------------------------

// These two are `setopt` ARGUMENT VALUES, which is why they are here and
// not with the websocket frame flags: a caller passes them to
// `curl_easy_setopt(h, CURLOPT_WS_OPTIONS, ...)`, so they belong to option
// identity. `ffi/ws.rs` owns the seven `CURLWS_*` FRAME flags, which are a
// different space that happens to share a prefix.
//
// The type is `c_long`, and that is an ABI distinction rather than a
// preference. `include/curl/websockets.h:89-90` writes these two as
// `(1L << 0)` and `(1L << 1)` while the frame flags at :40-60 are written
// `(1 << n)`. The `L` matters because these values are passed through a
// variadic argument list, where the default promotions apply and
// `curl_easy_setopt`'s `CURLOPTTYPE_LONG` slot is read as a `long`: an
// `int` argument on LP64 would leave the upper half of the slot
// unspecified. The frame flags are passed as a declared `unsigned int`
// parameter instead, so they need no suffix.
//
// `pub(crate)` because `build.rs:1231` carries both `#define` lines
// verbatim.

/// `CURLWS_RAW_MODE`, bit 0 of `CURLOPT_WS_OPTIONS`.
#[allow(dead_code)]
pub(crate) const CURLWS_RAW_MODE: c_long = 1 << 0;

/// `CURLWS_NOAUTOPONG`, bit 1 of `CURLOPT_WS_OPTIONS`.
#[allow(dead_code)]
pub(crate) const CURLWS_NOAUTOPONG: c_long = 1 << 1;

// ---------------------------------------------------------------------------
// The introspection contract this table has to satisfy.
// ---------------------------------------------------------------------------

// `curl_easy_option_by_name`, `_by_id` and `_next` are exported from
// `ffi/easy.rs`, and they read [`EASY_OPTIONS`] directly rather than a
// projection of it, so there is one population and no lookup logic here to
// drift from theirs. What follows is the behaviour `lib/easygetopt.c:31-76`
// defines, recorded at the authority so that a future re-implementation has
// no room to guess. Every clause is asserted over the table by this
// module's tests.
//
//   * By NAME the comparison is `curl_strequal(o->name, name)`, so it is
//     case-insensitive over ASCII, and alias rows are INCLUDED -- there is
//     no flag test in that branch.
//   * By ID the branch is `(o->id == id) && !(o->flags &
//     CURLOT_FLAG_ALIAS)`, carrying the in-source comment "do not match
//     alias options". An id shared by a retired spelling and its preferred
//     option therefore always resolves to the preferred one.
//   * `by_name` is `lookup(name, CURLOPT_LASTENTRY)` with the comment "when
//     name is used, the id argument is ignored".
//   * The walk is `do { ... o++; } while(o->name);`, so the NULL-name
//     sentinel terminates it and is never compared against. It has to be a
//     real, addressable element, which is why it is the 324th row of the
//     table rather than an absence.
//   * `_next(NULL)` yields the first row, `_next(row)` the following one,
//     and `_next` of the last real row yields NULL. Iteration INCLUDES the
//     15 alias rows.
//
// CORRECTION 3, and it contradicts a sibling requirement note. Rows store
// the name WITHOUT its `CURLOPT_` prefix and the lookup does no prefix
// handling, so:
//
//     by_name("ENCODING")         -> the CURLOPT_ACCEPT_ENCODING alias row
//     by_name("encoding")         -> the same row, case-insensitively
//     by_name("CURLOPT_ENCODING") -> NULL
//
// A validation item of the form `by_name("CURLOPT_X")->id == CURLOPT_X` is
// therefore wrong, and both the positive and the negative case are asserted
// below so the wrong reading cannot be reintroduced.
//
// `lib/easygetopt.c` wraps the whole API in `#ifndef
// CURL_DISABLE_GETOPTIONS` and returns NULL from every entry point when it
// is defined. That symbol is not among the capabilities this workspace
// makes configurable, so the enabled behaviour is the only behaviour.

#[cfg(test)]
mod tests {
    use super::*;

    /// Values transcribed BY HAND from the frozen
    /// `include/curl/curl.h`, independently of the generator that wrote
    /// the enumeration. A generator defect and a later hand-edit both
    /// have to survive this table, and neither can.
    const ANCHORS: &[(CURLoption, i32)] = &[
        (CURLoption::CURLOPT_ACCEPT_ENCODING, 10102),
        (CURLoption::CURLOPT_APPEND, 50),
        (CURLoption::CURLOPT_CAINFO, 10065),
        (CURLoption::CURLOPT_DIRLISTONLY, 48),
        (CURLoption::CURLOPT_FAILONERROR, 45),
        (CURLoption::CURLOPT_FOLLOWLOCATION, 52),
        (CURLoption::CURLOPT_HEADER, 42),
        (CURLoption::CURLOPT_HEADERDATA, 10029),
        (CURLoption::CURLOPT_HTTPHEADER, 10023),
        (CURLoption::CURLOPT_HTTPPOST, 10024),
        (CURLoption::CURLOPT_INFILESIZE, 14),
        (CURLoption::CURLOPT_INFILESIZE_LARGE, 30115),
        (CURLoption::CURLOPT_KEYPASSWD, 10026),
        (CURLoption::CURLOPT_MAIL_RCPT_ALLOWFAILS, 290),
        (CURLoption::CURLOPT_MAXFILESIZE_LARGE, 30117),
        (CURLoption::CURLOPT_MAXREDIRS, 68),
        (CURLoption::CURLOPT_NOBODY, 44),
        (CURLoption::CURLOPT_NOPROGRESS, 43),
        (CURLoption::CURLOPT_PORT, 3),
        (CURLoption::CURLOPT_POST, 47),
        (CURLoption::CURLOPT_POSTFIELDS, 10015),
        (CURLoption::CURLOPT_POSTREDIR, 161),
        (CURLoption::CURLOPT_PROXY, 10004),
        (CURLoption::CURLOPT_PUT, 54),
        (CURLoption::CURLOPT_READDATA, 10009),
        (CURLoption::CURLOPT_READFUNCTION, 20012),
        (CURLoption::CURLOPT_RESUME_FROM_LARGE, 30116),
        (CURLoption::CURLOPT_SERVER_RESPONSE_TIMEOUT, 112),
        (CURLoption::CURLOPT_SSLCERT_BLOB, 40291),
        (CURLoption::CURLOPT_SSLKEY_BLOB, 40292),
        (CURLoption::CURLOPT_SSL_SIGNATURE_ALGORITHMS, 10328),
        (CURLoption::CURLOPT_SSL_VERIFYPEER, 64),
        (CURLoption::CURLOPT_TIMEOUT, 13),
        (CURLoption::CURLOPT_UPLOAD, 46),
        (CURLoption::CURLOPT_URL, 10002),
        (CURLoption::CURLOPT_USERPWD, 10005),
        (CURLoption::CURLOPT_USE_SSL, 119),
        (CURLoption::CURLOPT_VERBOSE, 41),
        (CURLoption::CURLOPT_WRITEDATA, 10001),
        (CURLoption::CURLOPT_WRITEFUNCTION, 20011),
        (CURLoption::CURLOPT_XFERINFODATA, 10057),
    ];

    #[test]
    fn anchors_hold() {
        for &(option, expected) in ANCHORS {
            assert_eq!(
                option.as_c_int(),
                expected,
                "{} must be {} to stay ABI compatible with curl \
                 8.19.0-DEV",
                option.c_name(),
                expected
            );
        }
    }

    #[test]
    fn variant_counts_match_the_reconciliation() {
        assert_eq!(CURLoption::REAL_COUNT, 308);
        assert_eq!(
            CURLoption::ABI_VARIANTS.len(),
            CURLoption::REAL_COUNT + 1,
            "ABI_VARIANTS must hold every real option plus \
             CURLOPT_LASTENTRY"
        );
        assert_eq!(
            *CURLoption::ABI_VARIANTS.last().unwrap(),
            CURLoption::CURLOPT_LASTENTRY
        );
    }

    #[test]
    fn values_and_names_are_unique() {
        let mut values: Vec<i32> = CURLoption::ABI_VARIANTS
            .iter()
            .map(|o| o.as_c_int())
            .collect();
        let total = values.len();
        values.sort_unstable();
        values.dedup();
        assert_eq!(values.len(), total, "duplicate CURLoption value");

        let mut names: Vec<&str> = CURLoption::ABI_VARIANTS
            .iter()
            .map(|o| o.c_name())
            .collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), total, "duplicate CURLoption name");
    }

    #[test]
    fn every_value_is_a_base_plus_an_ordinal() {
        let bases = [
            CURLOPTTYPE_LONG,
            CURLOPTTYPE_OBJECTPOINT,
            CURLOPTTYPE_FUNCTIONPOINT,
            CURLOPTTYPE_OFF_T,
            CURLOPTTYPE_BLOB,
        ];
        for &option in CURLoption::ABI_VARIANTS {
            let base = option.type_base();
            let ordinal = option.type_ordinal();
            assert!(
                bases.contains(&base),
                "{} has base {}, which is not a CURLOPTTYPE_* value",
                option.c_name(),
                base
            );
            assert!(
                ordinal > 0,
                "{} has ordinal {}; the CURLOPT macro numbers from 1",
                option.c_name(),
                ordinal
            );
            assert_eq!(base + ordinal, option.as_c_int());
        }
    }

    #[test]
    fn lastentry_is_one_past_the_last_declared_option() {
        let last = CURLoption::CURLOPT_SSL_SIGNATURE_ALGORITHMS;
        assert_eq!(last.as_c_int(), 10328);
        assert_eq!(
            CURLoption::CURLOPT_LASTENTRY.as_c_int(),
            last.as_c_int() + 1
        );
        assert_eq!(CURLoption::CURLOPT_LASTENTRY.as_c_int(), 10329);
        // CORRECTION 1. 328 is the highest `nu` index, NOT the sentinel's
        // value, and the two differ by 10001.
        assert_ne!(CURLoption::CURLOPT_LASTENTRY.as_c_int(), 328);
        assert_eq!(
            CURLoption::CURLOPT_LASTENTRY.as_c_int() - 328,
            10001,
            "the exact size of the mistake CORRECTION 1 names"
        );
        // `Curl_easyopts_check` (lib/easyoptions.c:388) reports an ERROR
        // when this differs from 328 + 1, so a correct table satisfies the
        // EQUALITY. The `% 10000` in the C is only needed because the
        // sentinel is neither 328 nor 329.
        assert_eq!(CURLoption::CURLOPT_LASTENTRY.type_ordinal(), 328 + 1);
        assert_eq!(CURLoption::CURLOPT_LASTENTRY.as_c_int() % 10000, 329);
    }

    /// CORRECTION 1's twin, asserted ACROSS the module boundary.
    ///
    /// `CURLMoption` is declared in `ffi/types.rs`, but the identical trap
    /// lives there, so the guard belongs wherever someone reads about it.
    /// If that enumeration is ever "corrected" to 20 this fails here.
    #[test]
    fn the_multi_sentinel_carries_the_same_trap() {
        use crate::ffi::types::CURLMoption;

        assert_eq!(CURLMoption::CURLMOPT_NOTIFYDATA as i64, 10019);
        assert_eq!(CURLMoption::CURLMOPT_LASTENTRY as i64, 10020);
        assert_ne!(CURLMoption::CURLMOPT_LASTENTRY as i64, 20);
        // An ordinal follow-on from an OBJECTPOINT member, exactly like
        // CURLOPT_LASTENTRY follows a STRINGPOINT one.
        assert_eq!(
            CURLMoption::CURLMOPT_LASTENTRY as i64,
            CURLMoption::CURLMOPT_NOTIFYDATA as i64 + 1
        );
    }

    #[test]
    fn integers_round_trip_through_the_c_boundary() {
        for &option in CURLoption::ABI_VARIANTS {
            assert_eq!(
                CURLoption::from_c_int(option.as_c_int()),
                Some(option),
                "{} did not round trip",
                option.c_name()
            );
        }
        assert_eq!(CURLoption::from_c_int(-1), None);
        assert_eq!(CURLoption::from_c_int(0), None);
        assert_eq!(CURLoption::from_c_int(9999), None);
        assert_eq!(CURLoption::from_c_int(i32::MAX), None);
    }

    #[test]
    fn metadata_table_shape_matches_optiontable_pl() {
        assert_eq!(EASY_OPTIONS.len(), 324);
        assert_eq!(EASY_OPTIONS.len(), EASY_OPTION_ROWS);
        let sentinels =
            EASY_OPTIONS.iter().filter(|r| r.name.is_none()).count();
        assert_eq!(sentinels, 1, "exactly one terminating sentinel");
        let real = EASY_OPTIONS.iter().filter(|r| r.name.is_some()).count();
        assert_eq!(real, EASY_OPTION_REAL_ROWS);
        assert_eq!(real, EASY_OPTION_ROWS - 1);
        let aliases = EASY_OPTIONS.iter().filter(|r| r.is_alias()).count();
        assert_eq!(aliases, EASY_OPTION_ALIAS_ROWS);
        let truths = EASY_OPTIONS.iter().filter(|r| r.is_true_option());
        assert_eq!(truths.count(), EASY_OPTION_TRUE_ROWS);
        assert_eq!(
            EASY_OPTION_ALIAS_ROWS + EASY_OPTION_TRUE_ROWS,
            EASY_OPTION_REAL_ROWS
        );
    }

    /// The cross-population bridge. The enumeration comes from the frozen
    /// header; the table comes from `lib/optiontable.pl`. Neither is
    /// derived from the other, so agreement is evidence rather than
    /// tautology.
    #[test]
    fn true_rows_cover_the_enumeration_exactly() {
        assert_eq!(EASY_OPTION_TRUE_ROWS, CURLoption::REAL_COUNT);
        for &option in CURLoption::ABI_VARIANTS {
            if option == CURLoption::CURLOPT_LASTENTRY {
                continue;
            }
            let hits = EASY_OPTIONS
                .iter()
                .filter(|r| r.is_true_option() && r.id == option)
                .count();
            assert_eq!(
                hits,
                1,
                "{} has {} true metadata rows, expected exactly 1",
                option.c_name(),
                hits
            );
        }
        for row in EASY_OPTIONS.iter().filter(|r| r.is_true_option()) {
            let stripped = row.id.c_name().strip_prefix("CURLOPT_");
            assert_eq!(
                row.name_str(),
                stripped,
                "true row name must be its id minus the CURLOPT_ prefix"
            );
        }
    }

    /// AAP 0.6.1 requires the aliases to "resolve to identical
    /// integers". This is that assertion.
    #[test]
    fn aliases_resolve_to_identical_integers() {
        assert_eq!(OPTION_ALIASES.len(), 19);
        for alias in OPTION_ALIASES {
            match alias.resolves_to {
                Some(option) => assert_eq!(
                    option.as_c_int(),
                    alias.value,
                    "{} must equal {}",
                    alias.alias,
                    alias.target
                ),
                None => assert_eq!(
                    alias.value, 9999,
                    "{} expands to a bare integer, which upstream only \
                     ever uses for the two retired 9999 slots",
                    alias.alias
                ),
            }
            assert!(alias.alias.starts_with("CURLOPT_"));
        }
        let mut names: Vec<&str> =
            OPTION_ALIASES.iter().map(|a| a.alias).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), OPTION_ALIASES.len());
    }

    /// build.rs:2028-2037 derives the 15 alias ROWS from the 19 alias
    /// `#define`s as 19 - 2 - 2. This proves that arithmetic against the
    /// data rather than trusting the comment.
    #[test]
    fn alias_row_count_follows_from_the_define_count() {
        // A target is either a bare integer, or an identifier. Only the
        // former makes an alias `#define` invisible to the metadata
        // table; an alias pointing AT a bare-integer define is invisible
        // for a second, independent reason. Counting them together is
        // what makes the 19 - 2 - 2 arithmetic come out at 15.
        let bare = OPTION_ALIASES
            .iter()
            .filter(|a| {
                !a.target.is_empty()
                    && a.target.bytes().all(|b| b.is_ascii_digit())
            })
            .count();
        assert_eq!(bare, 2, "the retired 9999 slots");
        let onto_bare = OPTION_ALIASES
            .iter()
            .filter(|a| {
                a.resolves_to.is_none() && a.target.starts_with("CURLOPT_")
            })
            .count();
        assert_eq!(
            onto_bare, 2,
            "the aliases that point at a retired slot rather than at an \
             option"
        );
        assert_eq!(
            OPTION_ALIASES.len() - bare - onto_bare,
            EASY_OPTION_ALIAS_ROWS
        );
        let unresolved =
            OPTION_ALIASES.iter().filter(|a| a.resolves_to.is_none());
        for alias in unresolved {
            assert_eq!(
                alias.value, 9999,
                "{} resolves to no option, so it must carry the retired \
                 9999 value",
                alias.alias
            );
        }
    }

    #[test]
    fn alias_rows_spell_the_retired_name_and_point_at_the_preferred_one() {
        for row in EASY_OPTIONS.iter().filter(|r| r.is_alias()) {
            let spelled = row.name_str().expect("alias rows are named");
            let retired = format!("CURLOPT_{spelled}");
            let entry = OPTION_ALIASES
                .iter()
                .find(|a| a.alias == retired)
                .unwrap_or_else(|| {
                    panic!("alias row {retired} has no #define")
                });
            assert_eq!(
                entry.value,
                row.id.as_c_int(),
                "{} must resolve to {}",
                retired,
                row.id.c_name()
            );
            assert_ne!(
                row.name_str(),
                row.id.c_name().strip_prefix("CURLOPT_"),
                "an alias row names the RETIRED spelling, not its target"
            );
        }
    }

    #[test]
    fn table_is_sorted_by_stripped_name_with_the_sentinel_last() {
        let names: Vec<&str> =
            EASY_OPTIONS.iter().filter_map(|r| r.name_str()).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(
            names, sorted,
            "curl_easy_option_next walks this array in order and a \
             consumer may rely on it"
        );
        let last = EASY_OPTIONS.last().expect("non-empty");
        assert!(last.name.is_none(), "the sentinel must come last");
        assert_eq!(last.id, CURLoption::CURLOPT_LASTENTRY);
        assert_eq!(last.flags, 0);
    }

    /// The reason the table has to carry `curl_easytype` per row instead
    /// of recovering it from the identifier. If this ever stopped being
    /// true the table could be simplified; while it holds, it cannot.
    #[test]
    fn easy_type_is_not_recoverable_from_the_base() {
        let mut seen: Vec<curl_easytype> = EASY_OPTIONS
            .iter()
            .filter(|r| r.is_true_option())
            .filter(|r| r.id.type_base() == CURLOPTTYPE_OBJECTPOINT)
            .map(|r| r.value_type)
            .collect();
        seen.sort_unstable();
        seen.dedup();
        assert!(
            seen.len() > 1,
            "base {} carries {} distinct curl_easytype values",
            CURLOPTTYPE_OBJECTPOINT,
            seen.len()
        );
        assert_eq!(CURLOPTTYPE_STRINGPOINT, CURLOPTTYPE_OBJECTPOINT);
        assert_eq!(CURLOPTTYPE_SLISTPOINT, CURLOPTTYPE_OBJECTPOINT);
        assert_eq!(CURLOPTTYPE_CBPOINT, CURLOPTTYPE_OBJECTPOINT);
        assert_eq!(CURLOPTTYPE_VALUES, CURLOPTTYPE_LONG);
    }

    #[test]
    fn every_real_option_has_a_declared_value_type() {
        for &option in CURLoption::ABI_VARIANTS {
            if option == CURLoption::CURLOPT_LASTENTRY {
                assert_eq!(option.easy_type(), None);
                continue;
            }
            assert!(
                option.easy_type().is_some(),
                "{} has no metadata row",
                option.c_name()
            );
        }
    }

    #[test]
    fn curl_easytype_values_are_declaration_ordinals() {
        let declared = [
            (curl_easytype::CURLOT_LONG, 0),
            (curl_easytype::CURLOT_VALUES, 1),
            (curl_easytype::CURLOT_OFF_T, 2),
            (curl_easytype::CURLOT_OBJECT, 3),
            (curl_easytype::CURLOT_STRING, 4),
            (curl_easytype::CURLOT_SLIST, 5),
            (curl_easytype::CURLOT_CBPTR, 6),
            (curl_easytype::CURLOT_BLOB, 7),
            (curl_easytype::CURLOT_FUNCTION, 8),
        ];
        assert_eq!(declared.len(), 9);
        for (index, &(value_type, expected)) in declared.iter().enumerate() {
            assert_eq!(value_type as i32, expected);
            assert_eq!(
                value_type as i32, index as i32,
                "curl_easytype members are implicit in the frozen \
                 header, so each must equal its position"
            );
        }
    }

    #[test]
    fn flag_alias_is_bit_zero_and_the_only_flag() {
        assert_eq!(CURLOT_FLAG_ALIAS, 1);
        for row in EASY_OPTIONS {
            assert_eq!(
                row.flags & !CURLOT_FLAG_ALIAS,
                0,
                "no flag bit other than CURLOT_FLAG_ALIAS is defined"
            );
        }
    }

    #[test]
    fn type_bases_match_the_frozen_header() {
        assert_eq!(CURLOPTTYPE_LONG, 0);
        assert_eq!(CURLOPTTYPE_OBJECTPOINT, 10000);
        assert_eq!(CURLOPTTYPE_FUNCTIONPOINT, 20000);
        assert_eq!(CURLOPTTYPE_OFF_T, 30000);
        assert_eq!(CURLOPTTYPE_BLOB, 40000);
    }

    // -- CURLINFO ---------------------------------------------------------

    /// Values transcribed BY HAND from the frozen `include/curl/curl.h`,
    /// independently of the script that wrote the enumeration. Chosen to
    /// cover all seven base spellings, both uncomposed members, the reused
    /// ordinal and the highest ordinal in use.
    const INFO_ANCHORS: &[(CURLINFO, c_int)] = &[
        (CURLINFO::CURLINFO_NONE, 0),
        (CURLINFO::CURLINFO_EFFECTIVE_URL, 0x100001),
        (CURLINFO::CURLINFO_RESPONSE_CODE, 0x200002),
        (CURLINFO::CURLINFO_TOTAL_TIME, 0x300003),
        (CURLINFO::CURLINFO_SIZE_UPLOAD, 0x300007),
        (CURLINFO::CURLINFO_SIZE_UPLOAD_T, 0x600007),
        (CURLINFO::CURLINFO_SSL_ENGINES, 0x40001b),
        (CURLINFO::CURLINFO_CERTINFO, 0x400022),
        (CURLINFO::CURLINFO_TLS_SESSION, 0x40002b),
        (CURLINFO::CURLINFO_ACTIVESOCKET, 0x50002c),
        (CURLINFO::CURLINFO_TLS_SSL_PTR, 0x40002d),
        (CURLINFO::CURLINFO_PROXYAUTH_USED, 0x200046),
        (CURLINFO::CURLINFO_LASTONE, 70),
    ];

    #[test]
    fn info_anchors_hold() {
        for &(info, expected) in INFO_ANCHORS {
            assert_eq!(
                info.as_c_int(),
                expected,
                "{} must be 0x{:06x}",
                info.c_name(),
                expected
            );
        }
    }

    #[test]
    fn info_token_count_is_seventy_nine_and_lastone_is_seventy() {
        assert_eq!(CURLINFO::ABI_VARIANTS.len(), CURLINFO::TOKEN_COUNT);
        assert_eq!(CURLINFO::TOKEN_COUNT, 79);
        // The two numbers AAP 0.4.1's prose conflates. `CURLINFO_LASTONE`
        // is the highest ordinal in use, written as a bare 70 at
        // curl.h:2995; 79 is how many tokens the enumeration declares.
        assert_eq!(CURLINFO::CURLINFO_LASTONE.as_c_int(), 70);
        assert_eq!(CURLINFO::CURLINFO_NONE.as_c_int(), 0);
        assert_ne!(CURLINFO::CURLINFO_LASTONE.as_c_int(), 79);
    }

    #[test]
    fn info_bases_match_the_frozen_header() {
        assert_eq!(CURLINFO_STRING, 0x100000);
        assert_eq!(CURLINFO_LONG, 0x200000);
        assert_eq!(CURLINFO_DOUBLE, 0x300000);
        assert_eq!(CURLINFO_SLIST, 0x400000);
        assert_eq!(CURLINFO_SOCKET, 0x500000);
        assert_eq!(CURLINFO_OFF_T, 0x600000);
        assert_eq!(CURLINFO_MASK, 0x0fffff);
        assert_eq!(CURLINFO_TYPEMASK, 0xf00000);
        // Deliberately identical, per curl.h:2894's `/* same as SLIST */`.
        // Asserted, not corrected.
        assert_eq!(CURLINFO_PTR, CURLINFO_SLIST);
        // Every base is a distinct nibble in the type field, so the mask
        // and the type mask partition a composed value exactly.
        assert_eq!(CURLINFO_MASK & CURLINFO_TYPEMASK, 0);
        assert_eq!(CURLINFO_MASK | CURLINFO_TYPEMASK, 0xffffff);
        // Seven spellings, six values: the collision is the whole reason
        // `InfoBase` carries a spelling rather than an integer.
        assert_eq!(InfoBase::ALL.len(), 7);
        let mut values: Vec<c_int> =
            InfoBase::ALL.iter().map(|b| b.value()).collect();
        values.sort_unstable();
        values.dedup();
        assert_eq!(values.len(), 6);
        let mut names: Vec<&str> =
            InfoBase::ALL.iter().map(|b| b.name()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), 7);
    }

    #[test]
    fn every_info_value_is_a_base_plus_an_ordinal() {
        assert_eq!(INFO_COMPOSITION.len(), CURLINFO::COMPOSED_COUNT);
        assert_eq!(CURLINFO::COMPOSED_COUNT, 77);
        for &(info, base, ordinal) in INFO_COMPOSITION {
            assert_eq!(
                info.as_c_int(),
                base.value() + ordinal,
                "{} must be {} + {}",
                info.c_name(),
                base.name(),
                ordinal
            );
            assert_eq!(info.as_c_int() & CURLINFO_TYPEMASK, base.value());
            assert_eq!(info.as_c_int() & CURLINFO_MASK, ordinal);
            assert_eq!(info.base(), Some(base));
            assert_eq!(info.ordinal(), Some(ordinal));
        }
        // The two members the composition table deliberately omits, and
        // there are exactly two.
        let composed: Vec<CURLINFO> =
            INFO_COMPOSITION.iter().map(|(i, _, _)| *i).collect();
        let missing: Vec<CURLINFO> = CURLINFO::ABI_VARIANTS
            .iter()
            .copied()
            .filter(|i| !composed.contains(i))
            .collect();
        assert_eq!(
            missing,
            vec![CURLINFO::CURLINFO_NONE, CURLINFO::CURLINFO_LASTONE]
        );
        for info in missing {
            assert_eq!(info.base(), None);
            assert_eq!(info.ordinal(), None);
        }
    }

    #[test]
    fn info_base_and_ordinal_pairs_are_unique_but_ordinals_are_not() {
        let mut pairs: Vec<(&str, c_int)> = INFO_COMPOSITION
            .iter()
            .map(|(_, base, ordinal)| (base.name(), *ordinal))
            .collect();
        let total = pairs.len();
        pairs.sort_unstable();
        pairs.dedup();
        assert_eq!(pairs.len(), total, "(base, ordinal) must be unique");

        // The ordinal ALONE is not a key, and this is the case that proves
        // it: 7 is both CURLINFO_SIZE_UPLOAD on DOUBLE and
        // CURLINFO_SIZE_UPLOAD_T on OFF_T.
        let sevens: Vec<&str> = INFO_COMPOSITION
            .iter()
            .filter(|(_, _, ordinal)| *ordinal == 7)
            .map(|(info, _, _)| info.c_name())
            .collect();
        assert_eq!(
            sevens,
            vec!["CURLINFO_SIZE_UPLOAD", "CURLINFO_SIZE_UPLOAD_T"]
        );
        let mut ordinals: Vec<c_int> =
            INFO_COMPOSITION.iter().map(|(_, _, n)| *n).collect();
        ordinals.sort_unstable();
        ordinals.dedup();
        assert!(
            ordinals.len() < total,
            "at least one ordinal is reused across bases"
        );
    }

    #[test]
    fn info_values_and_names_are_unique() {
        let mut values: Vec<c_int> = CURLINFO::ABI_VARIANTS
            .iter()
            .map(|i| i.as_c_int())
            .collect();
        let count = values.len();
        values.sort_unstable();
        values.dedup();
        assert_eq!(values.len(), count, "two members share an integer");

        let mut names: Vec<&str> =
            CURLINFO::ABI_VARIANTS.iter().map(|i| i.c_name()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count, "two members share a spelling");
        for info in CURLINFO::ABI_VARIANTS {
            assert!(
                info.c_name().starts_with("CURLINFO_"),
                "{} is not a CURLINFO_ spelling",
                info.c_name()
            );
        }
    }

    #[test]
    fn info_base_distribution_matches_the_measurement() {
        // Measured over include/curl/curl.h:2900-2996 by brace-balanced
        // scanning of the enumeration body.
        let expected = [
            ("CURLINFO_STRING", 13),
            ("CURLINFO_LONG", 25),
            ("CURLINFO_DOUBLE", 13),
            ("CURLINFO_SLIST", 2),
            ("CURLINFO_PTR", 3),
            ("CURLINFO_SOCKET", 1),
            ("CURLINFO_OFF_T", 20),
        ];
        let mut total = 0;
        for (name, count) in expected {
            let seen = INFO_COMPOSITION
                .iter()
                .filter(|(_, base, _)| base.name() == name)
                .count();
            assert_eq!(seen, count, "{name} carries {seen} members");
            total += count;
        }
        assert_eq!(total, CURLINFO::COMPOSED_COUNT);
    }

    #[test]
    fn info_integers_round_trip_through_the_c_boundary() {
        for &info in CURLINFO::ABI_VARIANTS {
            assert_eq!(CURLINFO::from_c_int(info.as_c_int()), Some(info));
        }
        // A C caller may pass any int. None of these is declared, and
        // mapping None onto CURLE_UNKNOWN_OPTION is what curl does.
        for stranger in [-1, 1, 69, 71, 0x0fffff, 0x700000, i32::MAX] {
            assert_eq!(CURLINFO::from_c_int(stranger), None);
        }
    }

    #[test]
    fn info_value_kind_reproduces_the_getinfo_switch() {
        for &(info, base, _) in INFO_COMPOSITION {
            assert_eq!(
                info.value_kind(),
                Some(base.kind()),
                "{} classifies wrongly",
                info.c_name()
            );
        }
        // The collapse, stated as a test: a CURLINFO_PTR member is read as
        // a slist pointer, because the two bases are one integer and
        // lib/getinfo.c:637 has no PTR arm.
        assert_eq!(InfoBase::Ptr.kind(), InfoValueKind::Slist);
        assert_eq!(
            CURLINFO::CURLINFO_CERTINFO.value_kind(),
            Some(InfoValueKind::Slist)
        );
        assert_eq!(
            CURLINFO::CURLINFO_TLS_SSL_PTR.value_kind(),
            Some(InfoValueKind::Slist)
        );
        // The two uncomposed members have no type bits, so they reach the
        // `default:` arm.
        assert_eq!(CURLINFO::CURLINFO_NONE.value_kind(), None);
        assert_eq!(CURLINFO::CURLINFO_LASTONE.value_kind(), None);
        // Classification is by MASK and happens BEFORE validation, exactly
        // as the C does it: an undeclared id whose type bits are valid
        // still names a pointer type, and only the per-type getter then
        // rejects it.
        assert_eq!(CURLINFO::from_c_int(CURLINFO_LONG + 999), None);
        assert_eq!(
            info_value_kind(CURLINFO_LONG + 999),
            Some(InfoValueKind::Long)
        );
        // 0x700000 and 0x000000 are the two type-mask values no base uses.
        assert_eq!(info_value_kind(0x700000), None);
        assert_eq!(info_value_kind(0), None);
    }

    #[test]
    fn info_http_code_is_response_code() {
        assert_eq!(CURLINFO_HTTP_CODE, CURLINFO::CURLINFO_RESPONSE_CODE);
        assert_eq!(CURLINFO_HTTP_CODE.as_c_int(), 0x200002);
    }

    #[test]
    fn the_nine_deprecated_info_members_are_all_present() {
        let expected = [
            "CURLINFO_SIZE_UPLOAD",
            "CURLINFO_SIZE_DOWNLOAD",
            "CURLINFO_SPEED_DOWNLOAD",
            "CURLINFO_SPEED_UPLOAD",
            "CURLINFO_CONTENT_LENGTH_DOWNLOAD",
            "CURLINFO_CONTENT_LENGTH_UPLOAD",
            "CURLINFO_LASTSOCKET",
            "CURLINFO_TLS_SESSION",
            "CURLINFO_PROTOCOL",
        ];
        assert_eq!(INFO_DEPRECATIONS.len(), 9);
        let seen: Vec<&str> = INFO_DEPRECATIONS
            .iter()
            .map(|d| d.member.c_name())
            .collect();
        assert_eq!(seen, expected);
        for entry in INFO_DEPRECATIONS {
            // Deprecated is not removed. AAP 0.8.2.
            assert!(CURLINFO::ABI_VARIANTS.contains(&entry.member));
            assert!(!entry.since.is_empty());
            assert!(
                entry.message.starts_with("Use CURLINFO_"),
                "{} advises {:?}",
                entry.member.c_name(),
                entry.message
            );
        }
        let mut versions: Vec<&str> =
            INFO_DEPRECATIONS.iter().map(|d| d.since).collect();
        versions.sort_unstable();
        versions.dedup();
        assert_eq!(versions, vec!["7.45.0", "7.48.0", "7.55.0", "7.85.0"]);
    }

    // -- CURLformoption ---------------------------------------------------

    #[test]
    fn form_options_are_twenty_two_declaration_ordinals() {
        assert_eq!(
            CURLformoption::ABI_VARIANTS.len(),
            CURLformoption::TOKEN_COUNT
        );
        assert_eq!(CURLformoption::TOKEN_COUNT, 22);
        for (index, &option) in CURLformoption::ABI_VARIANTS.iter().enumerate()
        {
            assert_eq!(
                option.as_c_int(),
                index as c_int,
                "{} must be {index}",
                option.c_name()
            );
            assert!(option.c_name().starts_with("CURLFORM_"));
        }
        assert_eq!(CURLformoption::CURLFORM_NOTHING.as_c_int(), 0);
        assert_eq!(CURLformoption::CURLFORM_OBSOLETE.as_c_int(), 9);
        assert_eq!(CURLformoption::CURLFORM_END.as_c_int(), 17);
        assert_eq!(CURLformoption::CURLFORM_OBSOLETE2.as_c_int(), 18);
        assert_eq!(CURLformoption::CURLFORM_CONTENTLEN.as_c_int(), 20);
        assert_eq!(CURLformoption::CURLFORM_LASTENTRY.as_c_int(), 21);
    }

    #[test]
    fn eighteen_form_options_are_deprecated_not_twenty_one() {
        // CORRECTION 12. A per-line regex over the header under-counts and
        // yields 21 for the wrong reason; brace-balanced scanning of the
        // enumeration body yields 18, and these are the four without the
        // attribute.
        assert_eq!(FORM_DEPRECATIONS.len(), 18);
        let undeprecated: Vec<&str> = CURLformoption::ABI_VARIANTS
            .iter()
            .filter(|option| {
                !FORM_DEPRECATIONS.iter().any(|d| d.member == **option)
            })
            .map(|option| option.c_name())
            .collect();
        assert_eq!(
            undeprecated,
            vec![
                "CURLFORM_OBSOLETE",
                "CURLFORM_END",
                "CURLFORM_OBSOLETE2",
                "CURLFORM_LASTENTRY",
            ]
        );
        assert_eq!(
            FORM_DEPRECATIONS.len() + undeprecated.len(),
            CURLformoption::TOKEN_COUNT
        );
        for entry in FORM_DEPRECATIONS {
            // One version for the whole family, unlike CURLINFO's four.
            assert_eq!(entry.since, "7.56.0");
            assert!(CURLformoption::ABI_VARIANTS.contains(&entry.member));
        }
        // Three of the eighteen carry an EMPTY message in the frozen
        // header, which is why `Deprecation::message` may not be asserted
        // non-empty the way `since` may.
        let silent: Vec<&str> = FORM_DEPRECATIONS
            .iter()
            .filter(|d| d.message.is_empty())
            .map(|d| d.member.c_name())
            .collect();
        assert_eq!(
            silent,
            vec!["CURLFORM_NOTHING", "CURLFORM_NAMELENGTH", "CURLFORM_ARRAY",]
        );
    }

    #[test]
    fn form_options_round_trip_through_the_c_boundary() {
        for &option in CURLformoption::ABI_VARIANTS {
            assert_eq!(
                CURLformoption::from_c_int(option.as_c_int()),
                Some(option)
            );
        }
        for stranger in [-1, 22, 23, i32::MAX] {
            assert_eq!(CURLformoption::from_c_int(stranger), None);
        }
    }

    // -- CURLOPT_WS_OPTIONS argument bits ---------------------------------

    #[test]
    fn ws_option_bits_are_bit_zero_and_bit_one_and_long_typed() {
        assert_eq!(CURLWS_RAW_MODE, 1);
        assert_eq!(CURLWS_NOAUTOPONG, 2);
        assert_eq!(CURLWS_RAW_MODE & CURLWS_NOAUTOPONG, 0);
        // The `1L` in websockets.h:89-90 is an ABI distinction and not a
        // typo: these two are read out of a variadic argument list through
        // CURLOPT_WS_OPTIONS's CURLOPTTYPE_LONG slot, so the argument has
        // to be a `long`. The frame flags in `ffi/ws.rs` are written
        // `1 <<` because they are passed as a declared `unsigned int`
        // parameter instead.
        assert_eq!(
            core::mem::size_of_val(&CURLWS_RAW_MODE),
            core::mem::size_of::<c_long>()
        );
    }

    // -- the introspection contract ---------------------------------------

    /// `lookup(name, CURLOPT_LASTENTRY)` from `lib/easygetopt.c:31`.
    ///
    /// Case-insensitive over ASCII, which is what `curl_strequal` is;
    /// alias rows are INCLUDED, because that branch tests no flag; and the
    /// walk stops at the NULL-name sentinel without comparing against it,
    /// which is what the C's `do { ... } while(o->name)` does.
    fn lookup_by_name(name: &str) -> Option<&'static EasyOptionRow> {
        for row in EASY_OPTIONS {
            let Some(candidate) = row.name_str() else {
                break;
            };
            if candidate.eq_ignore_ascii_case(name) {
                return Some(row);
            }
        }
        None
    }

    /// `lookup(NULL, id)`. Skips alias rows -- "do not match alias
    /// options", `lib/easygetopt.c:44`.
    fn lookup_by_id(id: CURLoption) -> Option<&'static EasyOptionRow> {
        for row in EASY_OPTIONS {
            if row.name.is_none() {
                break;
            }
            if row.id == id && !row.is_alias() {
                return Some(row);
            }
        }
        None
    }

    /// `curl_easy_option_next` walked to exhaustion from NULL.
    fn walk_all() -> Vec<&'static EasyOptionRow> {
        let mut out = Vec::new();
        let mut index = 0;
        while EASY_OPTIONS[index].name.is_some() {
            out.push(&EASY_OPTIONS[index]);
            index += 1;
        }
        out
    }

    #[test]
    fn by_name_takes_the_stripped_name_case_insensitively() {
        // CORRECTION 3. Rows store the name WITHOUT its CURLOPT_ prefix and
        // the lookup does no prefix handling, so the prefixed spelling
        // MISSES. A validation item of the form
        // `by_name("CURLOPT_X")->id == CURLOPT_X` is wrong.
        let hit = lookup_by_name("ENCODING").expect("ENCODING is a row");
        assert_eq!(hit.name_str(), Some("ENCODING"));
        assert_eq!(hit.id, CURLoption::CURLOPT_ACCEPT_ENCODING);
        assert_eq!(hit.value_type, curl_easytype::CURLOT_STRING);
        assert_eq!(hit.flags, CURLOT_FLAG_ALIAS);

        // Case-insensitive, and it is the same row.
        let lower = lookup_by_name("encoding").expect("case-insensitive");
        assert_eq!(lower.name_str(), hit.name_str());
        assert_eq!(lower.id, hit.id);

        // The negative half of CORRECTION 3.
        assert!(lookup_by_name("CURLOPT_ENCODING").is_none());
        assert!(lookup_by_name("curlopt_encoding").is_none());
        // No trimming either.
        assert!(lookup_by_name("ENCODING ").is_none());
        assert!(lookup_by_name("").is_none());
        // A preferred spelling resolves to its own, non-alias row.
        let preferred =
            lookup_by_name("ACCEPT_ENCODING").expect("preferred row");
        assert_eq!(preferred.flags, 0);
        assert_eq!(preferred.id, CURLoption::CURLOPT_ACCEPT_ENCODING);
    }

    #[test]
    fn by_id_skips_alias_rows_and_by_name_does_not() {
        // CURLOPT_SERVER_RESPONSE_TIMEOUT is reachable under two spellings.
        // By id it must always be the preferred one.
        let by_id = lookup_by_id(CURLoption::CURLOPT_SERVER_RESPONSE_TIMEOUT)
            .expect("a preferred row exists");
        assert_eq!(by_id.name_str(), Some("SERVER_RESPONSE_TIMEOUT"));
        assert_eq!(by_id.flags, 0);

        // By name the retired spelling still resolves, to its own row.
        let by_name = lookup_by_name("FTP_RESPONSE_TIMEOUT")
            .expect("the retired spelling still resolves");
        assert_eq!(by_name.id, CURLoption::CURLOPT_SERVER_RESPONSE_TIMEOUT);
        assert_eq!(by_name.flags, CURLOT_FLAG_ALIAS);

        // Every alias row's id resolves by id to a NON-alias row carrying
        // the same id, so the two lookups never disagree about the option.
        for row in EASY_OPTIONS.iter().filter(|r| r.is_alias()) {
            let preferred = lookup_by_id(row.id).unwrap_or_else(|| {
                panic!("{:?} has no preferred row", row.name_str())
            });
            assert_eq!(preferred.id, row.id);
            assert!(!preferred.is_alias());
        }

        // The sentinel is never entered into the loop body, so the one id
        // only it carries is unreachable by id. Measured behaviour of the
        // C, not an accident of this transcription.
        assert!(lookup_by_id(CURLoption::CURLOPT_LASTENTRY).is_none());
    }

    #[test]
    fn the_walk_covers_every_real_row_and_stops_at_the_sentinel() {
        let walked = walk_all();
        assert_eq!(walked.len(), EASY_OPTION_REAL_ROWS);
        assert_eq!(walked.len(), 323);
        assert_eq!(
            walked.first().map(|r| r.name_str()),
            Some(Some("ABSTRACT_UNIX_SOCKET"))
        );
        assert_eq!(
            walked.last().map(|r| r.name_str()),
            Some(Some("XOAUTH2_BEARER"))
        );
        // Iteration INCLUDES alias rows.
        let aliases = walked.iter().filter(|r| r.is_alias()).count();
        assert_eq!(aliases, EASY_OPTION_ALIAS_ROWS);
        assert_eq!(aliases, 15);
        // And it stops before the sentinel, which is a real element.
        assert_eq!(EASY_OPTIONS.len(), walked.len() + 1);
        assert!(EASY_OPTIONS[walked.len()].name.is_none());
        assert_eq!(
            EASY_OPTIONS[walked.len()].id,
            CURLoption::CURLOPT_LASTENTRY
        );
        assert_eq!(
            EASY_OPTIONS[walked.len()].value_type,
            curl_easytype::CURLOT_LONG
        );
        assert_eq!(EASY_OPTIONS[walked.len()].flags, 0);
    }

    #[test]
    fn the_fifteen_alias_rows_are_the_ones_optiontable_pl_emits() {
        // Name, preferred option and declared type for each surviving
        // alias, transcribed from `perl lib/optiontable.pl <
        // include/curl/curl.h`. Five of them are the counter-examples that
        // make CORRECTION 2 concrete: the type is NOT the one `id / 10000`
        // would suggest.
        let expected: &[(&str, CURLoption, curl_easytype)] = &[
            (
                "ENCODING",
                CURLoption::CURLOPT_ACCEPT_ENCODING,
                curl_easytype::CURLOT_STRING,
            ),
            (
                "FILE",
                CURLoption::CURLOPT_WRITEDATA,
                curl_easytype::CURLOT_CBPTR,
            ),
            (
                "FTPAPPEND",
                CURLoption::CURLOPT_APPEND,
                curl_easytype::CURLOT_LONG,
            ),
            (
                "FTPLISTONLY",
                CURLoption::CURLOPT_DIRLISTONLY,
                curl_easytype::CURLOT_LONG,
            ),
            (
                "FTP_RESPONSE_TIMEOUT",
                CURLoption::CURLOPT_SERVER_RESPONSE_TIMEOUT,
                curl_easytype::CURLOT_LONG,
            ),
            (
                "FTP_SSL",
                CURLoption::CURLOPT_USE_SSL,
                curl_easytype::CURLOT_VALUES,
            ),
            (
                "INFILE",
                CURLoption::CURLOPT_READDATA,
                curl_easytype::CURLOT_CBPTR,
            ),
            (
                "KRB4LEVEL",
                CURLoption::CURLOPT_KRBLEVEL,
                curl_easytype::CURLOT_STRING,
            ),
            (
                "MAIL_RCPT_ALLLOWFAILS",
                CURLoption::CURLOPT_MAIL_RCPT_ALLOWFAILS,
                curl_easytype::CURLOT_LONG,
            ),
            (
                "POST301",
                CURLoption::CURLOPT_POSTREDIR,
                curl_easytype::CURLOT_VALUES,
            ),
            (
                "PROGRESSDATA",
                CURLoption::CURLOPT_XFERINFODATA,
                curl_easytype::CURLOT_CBPTR,
            ),
            (
                "RTSPHEADER",
                CURLoption::CURLOPT_HTTPHEADER,
                curl_easytype::CURLOT_SLIST,
            ),
            (
                "SSLCERTPASSWD",
                CURLoption::CURLOPT_KEYPASSWD,
                curl_easytype::CURLOT_STRING,
            ),
            (
                "SSLKEYPASSWD",
                CURLoption::CURLOPT_KEYPASSWD,
                curl_easytype::CURLOT_STRING,
            ),
            (
                "WRITEHEADER",
                CURLoption::CURLOPT_HEADERDATA,
                curl_easytype::CURLOT_CBPTR,
            ),
        ];
        let seen: Vec<&str> = EASY_OPTIONS
            .iter()
            .filter(|r| r.is_alias())
            .map(|r| r.name_str().expect("an alias row has a name"))
            .collect();
        let want: Vec<&str> = expected.iter().map(|(n, _, _)| *n).collect();
        assert_eq!(seen, want);
        for (name, id, value_type) in expected {
            let row =
                lookup_by_name(name).expect("every alias row is reachable");
            assert_eq!(row.id, *id, "{name} points at the wrong option");
            assert_eq!(
                row.value_type, *value_type,
                "{name} has the wrong type"
            );
            assert_eq!(row.flags, CURLOT_FLAG_ALIAS);
        }
        // The two aliases `lib/optiontable.pl` SKIPS, because their target
        // is an obsolete slot rather than an option: 17 true aliases less
        // these two is 15.
        assert!(lookup_by_name("WRITEINFO").is_none());
        assert!(lookup_by_name("CLOSEPOLICY").is_none());
    }

    #[test]
    fn the_per_type_row_distribution_matches_optiontable_pl() {
        // Measured over the generator's output, counting DATA rows only.
        // The widely quoted "LONG 120" counts the sentinel, which is a
        // CURLOT_LONG row; over the 323 data rows the figure is 119. Both
        // are asserted, in their own frames, so neither can be mistaken
        // for the other.
        let expected = [
            (curl_easytype::CURLOT_LONG, 119),
            (curl_easytype::CURLOT_STRING, 96),
            (curl_easytype::CURLOT_FUNCTION, 26),
            (curl_easytype::CURLOT_CBPTR, 25),
            (curl_easytype::CURLOT_VALUES, 20),
            (curl_easytype::CURLOT_SLIST, 11),
            (curl_easytype::CURLOT_OBJECT, 11),
            (curl_easytype::CURLOT_BLOB, 8),
            (curl_easytype::CURLOT_OFF_T, 7),
        ];
        let mut total = 0;
        for (value_type, count) in expected {
            let seen = EASY_OPTIONS
                .iter()
                .filter(|r| r.name.is_some())
                .filter(|r| r.value_type == value_type)
                .count();
            assert_eq!(seen, count, "{value_type:?} covers {seen} data rows");
            total += count;
        }
        assert_eq!(total, EASY_OPTION_REAL_ROWS);
        assert_eq!(total, 323);
        let with_sentinel = EASY_OPTIONS
            .iter()
            .filter(|r| r.value_type == curl_easytype::CURLOT_LONG)
            .count();
        assert_eq!(with_sentinel, 120);
        assert_eq!(EASY_OPTIONS.len(), 324);
    }

    #[test]
    fn the_projected_struct_has_the_layout_a_consumer_reads() {
        // `ffi/easy.rs` projects the rows above into
        // `ffi/types.rs`'s `curl_easyoption` and hands a POINTER to a C
        // caller, which then reads the fields and reaches the next row with
        // `prev++`. The layout is therefore directly observable, and it is
        // asserted here -- at the authority for the data -- rather than
        // only where the type happens to be declared.
        //
        // The numbers are LP64. All four targets AAP 0.8.3 mandates are
        // 64-bit, and AAP 0.6.2 records that 32-bit is deliberately
        // forfeited, so a target where these fail is a target this
        // workspace does not claim.
        use crate::ffi::types::curl_easyoption;
        use core::{mem, ptr};

        assert_eq!(mem::size_of::<curl_easyoption>(), 24);
        assert_eq!(mem::align_of::<curl_easyoption>(), 8);
        let probe = curl_easyoption {
            name: ptr::null(),
            id: 0,
            r#type: 0,
            flags: 0,
        };
        let base = ptr::addr_of!(probe) as usize;
        let name = ptr::addr_of!(probe.name) as usize - base;
        let id = ptr::addr_of!(probe.id) as usize - base;
        let value_type = ptr::addr_of!(probe.r#type) as usize - base;
        let flags = ptr::addr_of!(probe.flags) as usize - base;
        assert_eq!(name, 0);
        assert_eq!(id, 8);
        assert_eq!(value_type, 12);
        assert_eq!(flags, 16);
        // The field ORDER the frozen `struct curl_easyoption`
        // (include/curl/options.h:51-56) declares: name, id, type, flags.
        // Asserted separately from the offsets so that the intent survives
        // even on a hypothetical target with different padding.
        assert!(name < id);
        assert!(id < value_type);
        assert!(value_type < flags);
    }
}
