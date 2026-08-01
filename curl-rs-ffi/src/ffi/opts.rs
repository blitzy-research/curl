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
//! # The `dead_code` allowances
//!
//! Several items below carry `#[allow(dead_code)]`. Every one of them is
//! exercised by this module's tests, but the plain `lib` target compiles
//! without `#[cfg(test)]` code, and the exported functions that will read
//! this data -- `curl_easy_setopt`, `curl_easy_option_by_name`,
//! `curl_easy_option_by_id` and `curl_easy_option_next` -- are not landed
//! yet. The allowances are per ITEM rather than a blanket
//! `#![allow(dead_code)]` on the module, so each one disappears on its
//! own as its consumer arrives and none of them can mask an unrelated
//! unused item in the meantime.

use core::ffi::c_uint;

// ----------------------------------------------------------------------
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
// ----------------------------------------------------------------------
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

// ----------------------------------------------------------------------
// Metadata types, emitted into `include/curl/options.h`.
// ----------------------------------------------------------------------

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

// ----------------------------------------------------------------------
// The option enumeration, emitted into `include/curl/curl.h`.
//
// `cbindgen.toml:898` lists `CURLoption` under `[export] exclude`. AAP
// 0.1.2 overrides that, and `curl_h_export_exclusions` (build.rs:3101)
// lifts the one exclusion for the umbrella pass. The lift is recorded in
// `CURL_H_GENERATED_DESPITE_EXCLUSION` (build.rs:3144) so the divergence
// from the checked-in cbindgen configuration is deliberate and traceable
// rather than looking like a configuration bug.
// ----------------------------------------------------------------------

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
    /// One past the last real option. The frozen header leaves it implicit
    /// after `CURLOPT_SSL_SIGNATURE_ALGORITHMS`, so its value is 10329.
    /// `lib/optiontable.pl` asserts `10329 % 10000 != (328 + 1)` as its own
    /// guard against a stale table, which is the check this value has to
    /// satisfy.
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

// ----------------------------------------------------------------------
// The 19 `#define CURLOPT_*` aliases.
//
// Held here so the parity assertion AAP 0.1.2 requires has something to
// assert against, and NOT exported: the emitted form has to keep its
// `#ifndef CURL_NO_OLDIES` guards, which cbindgen cannot produce, so the
// guarded blocks are carried verbatim. See the module documentation.
// ----------------------------------------------------------------------

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

// ----------------------------------------------------------------------
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
// ----------------------------------------------------------------------

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
    #[allow(dead_code)]
    pub(crate) fn is_alias(&self) -> bool {
        self.flags & CURLOT_FLAG_ALIAS != 0
    }

    /// True for a real, preferred option row -- neither an alias nor the
    /// sentinel.
    #[allow(dead_code)]
    pub(crate) fn is_true_option(&self) -> bool {
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

/// Rows in the table, including the sentinel. Measured against
/// `lib/optiontable.pl` output.
#[allow(dead_code)]
pub(crate) const EASY_OPTION_ROWS: usize = 324;

/// Rows excluding the sentinel.
#[allow(dead_code)]
pub(crate) const EASY_OPTION_REAL_ROWS: usize = 323;

/// Rows flagged `CURLOT_FLAG_ALIAS`.
#[allow(dead_code)]
pub(crate) const EASY_OPTION_ALIAS_ROWS: usize = 15;

/// Rows describing a real, preferred option. Equals
/// [`CURLoption::REAL_COUNT`].
#[allow(dead_code)]
pub(crate) const EASY_OPTION_TRUE_ROWS: usize = 308;

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
        // lib/optiontable.pl guards its own output with exactly this.
        assert_eq!(CURLoption::CURLOPT_LASTENTRY.type_ordinal(), 328 + 1);
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
}
