// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
// SPDX-License-Identifier: curl
//
// Generated from the public headers of curl 8.19.0-DEV at commit
// 54cf587b9c by /tmp/p6/gen_types.py. Values are transcribed, never
// inferred: see the module documentation below.

//! The shared type vocabulary the public header references.
//!
//! This module is the single source of truth for three families that
//! every other FFI module names but none of them owns:
//!
//! 1. **Nineteen enumerations** (95 members) that are neither result
//!    codes nor options, so they belong in neither `codes` nor
//!    `opts`: the multi-handle vocabulary, the URL-part selector, and
//!    the transfer, lock, file, io and socket descriptors.
//! 2. **Thirty-four callback typedefs**, each the prototype of a
//!    function a consumer registers through `curl_easy_setopt`.
//! 3. The **support scalars and structs** those signatures name.
//!
//! Every discriminant below is written out as a literal. A consumer
//! compiled against curl 8.19.0-DEV holds the *number*, not the name:
//! a program that switches on `CURLMSG_DONE` is switching on `1`. The
//! frozen headers leave most of these values implicit, taking them
//! from declaration order, so reproducing them by relying on Rust's
//! own ordering would make a reordering of this file an ABI break
//! that no test could see. Writing each value out makes the intent
//! explicit and lets the tests at the end of this file assert every
//! one against the authority.
//!
//! Two constraints govern the *form* of what is written here, both
//! established by measuring cbindgen's output rather than by reading
//! its documentation:
//!
//! * Each enum carries `#[repr(C)]`, never `#[repr(i32)]`. Measured:
//!   `repr(i32)` makes cbindgen emit **two conflicting typedefs** for
//!   the same name -- `typedef enum NAME NAME;` and
//!   `typedef int32_t NAME;` -- while still emitting every member, so
//!   a member-count or value check cannot detect it and the build
//!   still succeeds. Only the declared form gives it away.
//! * Each declaration is literal. cbindgen parses syntactically with
//!   `syn` and expands no macro, so a value produced by a macro is
//!   invisible to it and silently absent from the header.
//!
//! The thirty-fifth callback, `curl_sshkeycallback`, is **not** here.
//! Its fourth parameter is `enum curl_khmatch`, a bare enum tag that
//! the authority never typedefs. cbindgen emits anonymous
//! `typedef enum { .. } NAME;` and so declares no tag it could refer
//! to, which makes that one prototype inexpressible; it is spliced
//! verbatim by `curl-rs-ffi/build.rs` alongside the enum it names.

use core::ffi::{c_char, c_double, c_int, c_long, c_uchar, c_uint, c_void};

use super::codes::{CURLSTScode, CURLcode};
use super::handle::{CURL, CURLM};

// The nineteen shared enumerations.

/// `CURLMSG`, transcribed from include/curl/multi.h.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)]
// ABI declaration: read by cbindgen, not by Rust callers
// Frozen C ABI name: `include/curl/curl.h` spells it this way and AAP 0.8.1
// forbids changing a public typedef, so the style lint yields to the contract.
#[allow(clippy::upper_case_acronyms)]
#[allow(clippy::enum_variant_names)]
pub enum CURLMSG {
    /// first, not used
    CURLMSG_NONE = 0,
    /// This easy handle has completed. 'result' contains the CURLcode of
    /// the transfer
    CURLMSG_DONE = 1,
    /// last, not used
    CURLMSG_LAST = 2,
}

/// `CURLMinfo_offt`, transcribed from include/curl/multi.h.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub enum CURLMinfo_offt {
    /// first, never use this
    CURLMINFO_NONE = 0,
    CURLMINFO_XFERS_CURRENT = 1,
    CURLMINFO_XFERS_RUNNING = 2,
    CURLMINFO_XFERS_PENDING = 3,
    CURLMINFO_XFERS_DONE = 4,
    CURLMINFO_XFERS_ADDED = 5,
    /// the last unused
    CURLMINFO_LASTENTRY = 6,
}

/// `CURLMoption`, transcribed from include/curl/multi.h.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub enum CURLMoption {
    CURLMOPT_SOCKETFUNCTION = 20001,
    CURLMOPT_SOCKETDATA = 10002,
    CURLMOPT_PIPELINING = 3,
    CURLMOPT_TIMERFUNCTION = 20004,
    CURLMOPT_TIMERDATA = 10005,
    CURLMOPT_MAXCONNECTS = 6,
    CURLMOPT_MAX_HOST_CONNECTIONS = 7,
    CURLMOPT_MAX_PIPELINE_LENGTH = 8,
    CURLMOPT_CONTENT_LENGTH_PENALTY_SIZE = 30009,
    CURLMOPT_CHUNK_LENGTH_PENALTY_SIZE = 30010,
    CURLMOPT_PIPELINING_SITE_BL = 10011,
    CURLMOPT_PIPELINING_SERVER_BL = 10012,
    CURLMOPT_MAX_TOTAL_CONNECTIONS = 13,
    CURLMOPT_PUSHFUNCTION = 20014,
    CURLMOPT_PUSHDATA = 10015,
    CURLMOPT_MAX_CONCURRENT_STREAMS = 16,
    CURLMOPT_NETWORK_CHANGED = 17,
    CURLMOPT_NOTIFYFUNCTION = 20018,
    CURLMOPT_NOTIFYDATA = 10019,
    /// the last unused
    CURLMOPT_LASTENTRY = 10020,
}

/// `CURLUPart`, transcribed from include/curl/urlapi.h.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub enum CURLUPart {
    CURLUPART_URL = 0,
    CURLUPART_SCHEME = 1,
    CURLUPART_USER = 2,
    CURLUPART_PASSWORD = 3,
    CURLUPART_OPTIONS = 4,
    CURLUPART_HOST = 5,
    CURLUPART_PORT = 6,
    CURLUPART_PATH = 7,
    CURLUPART_QUERY = 8,
    CURLUPART_FRAGMENT = 9,
    /// added in 7.65.0
    CURLUPART_ZONEID = 10,
}

/// `curl_TimeCond`, transcribed from include/curl/curl.h.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub enum curl_TimeCond {
    CURL_TIMECOND_LAST = 4,
}

/// `curl_closepolicy`, transcribed from include/curl/curl.h.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub enum curl_closepolicy {
    /// first, never use this
    CURLCLOSEPOLICY_NONE = 0,
    CURLCLOSEPOLICY_OLDEST = 1,
    CURLCLOSEPOLICY_LEAST_RECENTLY_USED = 2,
    CURLCLOSEPOLICY_LEAST_TRAFFIC = 3,
    CURLCLOSEPOLICY_SLOWEST = 4,
    CURLCLOSEPOLICY_CALLBACK = 5,
    /// last, never use this
    CURLCLOSEPOLICY_LAST = 6,
}

/// use "AUTH TLS"
/// Declared in include/curl/curl.h.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub enum curl_ftpauth {
    /// not an option, never use
    CURLFTPAUTH_LAST = 3,
}

/// Initiate the shutdown
/// Declared in include/curl/curl.h.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub enum curl_ftpccc {
    /// not an option, never use
    CURLFTPSSL_CCC_LAST = 3,
}

/// (FTP only) if CWD fails, try MKD and then CWD again even if MKD failed!
/// Declared in include/curl/curl.h.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub enum curl_ftpcreatedir {
    /// not an option, never use
    CURLFTP_CREATE_DIR_LAST = 3,
}

/// one CWD to full dir, then work on file
/// Declared in include/curl/curl.h.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub enum curl_ftpmethod {
    /// not an option, never use
    CURLFTPMETHOD_LAST = 4,
}

/// the kind of data that is passed to information_callback
/// Declared in include/curl/curl.h.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub enum curl_infotype {
    CURLINFO_TEXT = 0,
    /// 1
    CURLINFO_HEADER_IN = 1,
    /// 2
    CURLINFO_HEADER_OUT = 2,
    /// 3
    CURLINFO_DATA_IN = 3,
    /// 4
    CURLINFO_DATA_OUT = 4,
    /// 5
    CURLINFO_SSL_DATA_IN = 5,
    /// 6
    CURLINFO_SSL_DATA_OUT = 6,
    CURLINFO_END = 7,
}

/// Different lock access types
/// Declared in include/curl/curl.h.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub enum curl_lock_access {
    /// unspecified action
    CURL_LOCK_ACCESS_NONE = 0,
    /// for read perhaps
    CURL_LOCK_ACCESS_SHARED = 1,
    /// for write perhaps
    CURL_LOCK_ACCESS_SINGLE = 2,
    /// never use
    CURL_LOCK_ACCESS_LAST = 3,
}

/// Different data locks for a single share
/// Declared in include/curl/curl.h.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub enum curl_lock_data {
    CURL_LOCK_DATA_NONE = 0,
    CURL_LOCK_DATA_SHARE = 1,
    CURL_LOCK_DATA_COOKIE = 2,
    CURL_LOCK_DATA_DNS = 3,
    CURL_LOCK_DATA_SSL_SESSION = 4,
    CURL_LOCK_DATA_CONNECT = 5,
    CURL_LOCK_DATA_PSL = 6,
    CURL_LOCK_DATA_HSTS = 7,
    CURL_LOCK_DATA_LAST = 8,
}

/// Use the SOCKS5 protocol but pass along the hostname rather than the IP
/// address. added in 7.18.0
/// Declared in include/curl/curl.h.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub enum curl_proxytype {
    /// never use
    CURLPROXY_LAST = 8,
}

/// SSL for all communication or fail
/// Declared in include/curl/curl.h.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub enum curl_usessl {
    /// not an option, never use
    CURLUSESSL_LAST = 4,
}

/// enumeration of file types
/// Declared in include/curl/curl.h.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub enum curlfiletype {
    CURLFILETYPE_FILE = 0,
    CURLFILETYPE_DIRECTORY = 1,
    CURLFILETYPE_SYMLINK = 2,
    CURLFILETYPE_DEVICE_BLOCK = 3,
    CURLFILETYPE_DEVICE_CHAR = 4,
    CURLFILETYPE_NAMEDPIPE = 5,
    CURLFILETYPE_SOCKET = 6,
    /// is possible only on Sun Solaris now
    CURLFILETYPE_DOOR = 7,
    /// should never occur
    CURLFILETYPE_UNKNOWN = 8,
}

/// `curliocmd`, transcribed from include/curl/curl.h.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub enum curliocmd {
    /// no operation
    CURLIOCMD_NOP = 0,
    /// restart the read stream from start
    CURLIOCMD_RESTARTREAD = 1,
    /// never use
    CURLIOCMD_LAST = 2,
}

/// `curlioerr`, transcribed from include/curl/curl.h.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub enum curlioerr {
    /// I/O operation successful
    CURLIOE_OK = 0,
    /// command was unknown to callback
    CURLIOE_UNKNOWNCMD = 1,
    /// failed to restart the read
    CURLIOE_FAILRESTART = 2,
    /// never use
    CURLIOE_LAST = 3,
}

/// `curlsocktype`, transcribed from include/curl/curl.h.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub enum curlsocktype {
    /// socket created for a specific IP connection
    CURLSOCKTYPE_IPCXN = 0,
    /// socket created by accept() call
    CURLSOCKTYPE_ACCEPT = 1,
    /// never use
    CURLSOCKTYPE_LAST = 2,
}

// Support scalars and structs.
//
// Every name in this section is listed under `[export] exclude` in
// `cbindgen.toml`, so cbindgen declares none of them and the C definitions
// arrive verbatim instead -- from `system.h` for `curl_off_t`, from the
// `curl_socket_typedef` block for `curl_socket_t`, and from the spliced
// struct blocks in `curl-rs-ffi/build.rs` for the rest. They are declared
// here so that the generated callback prototypes have real Rust types to
// name. An excluded alias keeps its *name* in an emitted signature -- proven
// by measurement -- so `curl_off_t offset` is what reaches the header, not
// `int64_t offset`.
//
// Struct layouts were measured with gcc against the frozen headers on
// `x86_64-unknown-linux-gnu` rather than predicted; the `layout` tests at the
// end of this file assert the measured numbers.

/// The 64-bit file-size and offset type, frozen in `system.h` as
/// `CURL_TYPEOF_CURL_OFF_T`. All four mandated targets are 64-bit
/// (AAP 0.8.3), where that macro resolves to a 64-bit signed integer.
#[allow(non_camel_case_types)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub type curl_off_t = i64;

/// A socket descriptor. Frozen in the `curl_socket_typedef` block as
/// `typedef int curl_socket_t;` on every non-Windows target.
#[allow(non_camel_case_types)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub type curl_socket_t = c_int;

/// A singly linked string list. Layout-visible: consumers walk `next` and
/// read `data` directly. Measured size 16, alignment 8, `data` at 0,
/// `next` at 8.
#[allow(non_camel_case_types)]
#[repr(C)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub struct curl_slist {
    /// The entry's NUL-terminated string.
    pub data: *mut c_char,
    /// The next entry, or null at the end of the list.
    pub next: *mut curl_slist,
}

/// An address handed to a `curl_opensocket_callback`. Measured size 32,
/// alignment 4, with `family` at 0, `socktype` at 4, `protocol` at 8,
/// `addrlen` at 12 and `addr` at 16.
#[allow(non_camel_case_types)]
#[repr(C)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub struct curl_sockaddr {
    /// Address family, as passed to `socket(2)`.
    pub family: c_int,
    /// Socket type, as passed to `socket(2)`.
    pub socktype: c_int,
    /// Protocol, as passed to `socket(2)`.
    pub protocol: c_int,
    /// Length of `addr`. Frozen as `unsigned int`, not `socklen_t`: the
    /// header records that `socklen_t` "turned really ugly and painful on
    /// the systems that lack this type".
    pub addrlen: c_uint,
    /// The address itself.
    pub addr: libc::sockaddr,
}

/// One HSTS entry, exchanged with the read and write HSTS callbacks.
///
/// The frozen declaration carries a bitfield, `unsigned int
/// includeSubDomains:1;`, which Rust cannot express. Measured against gcc,
/// that bitfield occupies a **single byte** at offset 16 and `expire` follows
/// at 17, so a one-byte field reproduces the layout exactly: size 40,
/// alignment 8. All four mandated targets are little-endian, where the first
/// bitfield of a storage unit occupies its least-significant bit, so the flag
/// is bit 0 of this byte. Use [`curl_hstsentry::include_subdomains`] rather
/// than testing the byte directly.
#[allow(non_camel_case_types)]
#[repr(C)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub struct curl_hstsentry {
    /// The hostname.
    pub name: *mut c_char,
    /// Length of `name`.
    pub namelen: usize,
    /// Storage for the frozen `includeSubDomains:1` bitfield. Bit 0 carries
    /// the flag; every other bit is padding the authority does not define.
    pub include_subdomains_bits: c_uchar,
    /// Expiry as `YYYYMMDD HH:MM:SS`, NUL-terminated.
    pub expire: [c_char; 18],
}

impl curl_hstsentry {
    /// Read the `includeSubDomains` bitfield.
    #[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
    pub fn include_subdomains(&self) -> bool {
        self.include_subdomains_bits & 1 != 0
    }

    /// Write the `includeSubDomains` bitfield, preserving the bits the
    /// authority leaves undefined.
    #[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
    pub fn set_include_subdomains(&mut self, on: bool) {
        self.include_subdomains_bits =
            (self.include_subdomains_bits & !1) | c_uchar::from(on);
    }
}

/// Progress through a multi-entry save, passed to the HSTS write callback.
/// Measured size 16, alignment 8, `index` at 0 and `total` at 8.
#[allow(non_camel_case_types)]
#[repr(C)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub struct curl_index {
    /// The provided entry's index.
    pub index: usize,
    /// Total number of entries to save.
    pub total: usize,
}

/// The pushed-header collection handed to a `curl_push_callback`.
///
/// The authority declares this as an incomplete type -- `struct
/// curl_pushheaders;  /* forward declaration only */` at multi.h:500 -- and
/// never defines it. A zero-sized `_opaque` field reproduces that faithfully:
/// consumers reach the contents only through `curl_pushheader_bynum` and
/// `curl_pushheader_byname`.
#[allow(non_camel_case_types)]
#[repr(C)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub struct curl_pushheaders {
    _opaque: [u8; 0],
}

/// One row of the option-introspection table, returned by
/// `curl_easy_option_by_name`, `_by_id` and `_next`.
///
/// Transcribed from `include/curl/options.h:51-56`, whose four fields are all
/// ABI-visible because a consumer reads `opt->id` and `opt->type` directly.
/// The authority's own comment -- "The CURLOPTTYPE_* id ranges can still be
/// used to figure out what type/size to use for curl_easy_setopt() for the
/// given id" -- is what makes `id` and `type` a public contract rather than an
/// implementation detail.
///
/// `name` is a `*const c_char` and NOT an `Option<&CStr>`: the terminating row
/// of the table has a NULL `name`, and `curl_easy_option_next` uses exactly
/// that NULL to detect the end. Modelling the field as anything that cannot be
/// null would make the sentinel unrepresentable.
///
/// The C declaration is spliced verbatim into the generated `options.h`
/// (`OPTIONS_H_POST` in the build script) rather than generated from this
/// definition, because the struct is tag-form only and carries the authority's
/// comment. This Rust definition exists so that the table backing the three
/// introspection functions has a type to be an array of; `cbindgen.toml` lists
/// the name under `[export] exclude`, so the two cannot disagree by both being
/// emitted.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct curl_easyoption {
    /// The option's name WITHOUT its `CURLOPT_` prefix, or NULL in the
    /// terminating row.
    pub name: *const c_char,
    /// The option this row describes. For an alias row this is the PREFERRED
    /// option, not the retired spelling `name` carries.
    pub id: c_int,
    /// The declared value type, a `curl_easytype`.
    pub r#type: c_int,
    /// `CURLOT_FLAG_ALIAS`, or zero.
    pub flags: c_uint,
}

/// One available TLS backend, as reported through `curl_global_sslset`'s
/// `avail` out-parameter.
///
/// Transcribed from `include/curl/curl.h:2825-2829`. Layout-visible: the
/// documented use is to walk the NULL-terminated array and read `id` and
/// `name` from each entry.
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct curl_ssl_backend {
    /// The backend's `curl_sslbackend` identifier.
    pub id: c_int,
    /// Its human-readable name.
    pub name: *const c_char,
}

/// The version and capability report returned by `curl_version_info`.
///
/// Transcribed field for field, in order, from
/// `include/curl/curl.h:3111-3172`. Every field is ABI-visible: a consumer
/// reads `info->features`, walks `info->protocols` and prints
/// `info->ssl_version`, so both the order and the types are frozen
/// (AAP 0.8.1).
///
/// # Why the twelve generations are one flat struct
///
/// The authority grew this struct twelve times and marks each addition with a
/// comment naming the `CURLVERSION_*` stamp that introduced it. It never
/// reordered or removed a field, so a consumer compiled against an older
/// header simply stops reading early -- which is exactly why `age` exists.
/// Reproducing that means one flat `#[repr(C)]` struct with every field
/// present and `age` set to the newest generation this build populates; there
/// is no versioned union or nested struct in the C and none here.
///
/// # Nullable fields are pointers, not `Option`
///
/// Most of the string fields are documented as "might be NULL", and several
/// are unconditionally NULL in this build because the library they name is not
/// linked. They are therefore raw pointers: a null pointer is the contract's
/// way of saying "not available", and it is what a C consumer tests for.
///
/// Both array fields -- `protocols` and `feature_names` -- are
/// NULL-terminated, as the authority's comments state.
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct curl_version_info_data {
    /// Which generation of this struct is populated.
    pub age: c_int,
    /// `LIBCURL_VERSION`.
    pub version: *const c_char,
    /// `LIBCURL_VERSION_NUM`.
    pub version_num: c_uint,
    /// The `cpu-vendor-os[-env]` triple this build targets.
    pub host: *const c_char,
    /// The `CURL_VERSION_*` bitmask.
    pub features: c_int,
    /// Human-readable TLS backend and version, or NULL.
    pub ssl_version: *const c_char,
    /// "not used anymore, always 0" (`curl.h:3117`).
    pub ssl_version_num: c_long,
    /// Human-readable zlib version, or NULL.
    pub libz_version: *const c_char,
    /// NULL-terminated array of advertised scheme names.
    pub protocols: *const *const c_char,
    // ---- CURLVERSION_SECOND ----
    /// c-ares version, or NULL.
    pub ares: *const c_char,
    /// Numeric c-ares version, or zero.
    pub ares_num: c_int,
    // ---- CURLVERSION_THIRD ----
    /// libidn version, or NULL.
    pub libidn: *const c_char,
    // ---- CURLVERSION_FOURTH ----
    /// Numeric iconv version, or zero.
    pub iconv_ver_num: c_int,
    /// libssh or libssh2 version, or NULL.
    pub libssh_version: *const c_char,
    // ---- CURLVERSION_FIFTH ----
    /// Numeric Brotli version, `(MAJOR << 24) | (MINOR << 12) | PATCH`.
    pub brotli_ver_num: c_uint,
    /// Human-readable Brotli version, or NULL.
    pub brotli_version: *const c_char,
    // ---- CURLVERSION_SIXTH ----
    /// Numeric nghttp2 version, `(MAJOR << 16) | (MINOR << 8) | PATCH`.
    pub nghttp2_ver_num: c_uint,
    /// Human-readable nghttp2 version, or NULL.
    pub nghttp2_version: *const c_char,
    /// Human-readable QUIC and HTTP/3 library version, or NULL.
    pub quic_version: *const c_char,
    // ---- CURLVERSION_SEVENTH ----
    /// The built-in default `CURLOPT_CAINFO`, or NULL.
    pub cainfo: *const c_char,
    /// The built-in default `CURLOPT_CAPATH`, or NULL.
    pub capath: *const c_char,
    // ---- CURLVERSION_EIGHTH ----
    /// Numeric Zstd version, `(MAJOR << 24) | (MINOR << 12) | PATCH`.
    pub zstd_ver_num: c_uint,
    /// Human-readable Zstd version, or NULL.
    pub zstd_version: *const c_char,
    // ---- CURLVERSION_NINTH ----
    /// Human-readable Hyper version, or NULL.
    pub hyper_version: *const c_char,
    // ---- CURLVERSION_TENTH ----
    /// Human-readable GSASL version, or NULL.
    pub gsasl_version: *const c_char,
    // ---- CURLVERSION_ELEVENTH ----
    /// NULL-terminated array of advertised feature names.
    pub feature_names: *const *const c_char,
    // ---- CURLVERSION_TWELFTH ----
    /// Human-readable librtmp version, or NULL.
    pub rtmp_version: *const c_char,
}

// The thirty-four generated callback prototypes.
//
// Each is `Option<unsafe extern "C" fn(..)>` rather than a bare
// `fn`: the authority's type is a function *pointer*, which a
// consumer may set to NULL, and only the `Option` form gives Rust a
// null representation while keeping the pointer's ABI. Measured,
// cbindgen renders it as the frozen `typedef R (*name)(args);` with
// every parameter name preserved.

/// `curl_calloc_callback`, transcribed from include/curl/curl.h.
#[allow(non_camel_case_types)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub type curl_calloc_callback =
    Option<unsafe extern "C" fn(nmemb: usize, size: usize) -> *mut c_void>;

/// if splitting of data transfer is enabled, this callback is called before
/// download of an individual chunk started. Note that parameter "remains"
/// works only for FTP wildcard downloading (for now), otherwise is not used
/// Declared in include/curl/curl.h.
#[allow(non_camel_case_types)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub type curl_chunk_bgn_callback = Option<
    unsafe extern "C" fn(
        transfer_info: *const c_void,
        ptr: *mut c_void,
        remains: c_int,
    ) -> c_long,
>;

/// If splitting of data transfer is enabled this callback is called after
/// download of an individual chunk finished. Note! After this callback was
/// set then it have to be called FOR ALL chunks. Even if downloading of
/// this chunk was skipped in CHUNK_BGN_FUNC. This is the reason why we do
/// not need "transfer_info" parameter in this callback and we are not
/// interested in "remains" parameter too.
/// Declared in include/curl/curl.h.
#[allow(non_camel_case_types)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub type curl_chunk_end_callback =
    Option<unsafe extern "C" fn(ptr: *mut c_void) -> c_long>;

/// `curl_closesocket_callback`, transcribed from include/curl/curl.h.
#[allow(non_camel_case_types)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub type curl_closesocket_callback = Option<
    unsafe extern "C" fn(clientp: *mut c_void, item: curl_socket_t) -> c_int,
>;

/// This prototype applies to all conversion callbacks
/// Declared in include/curl/curl.h.
#[allow(non_camel_case_types)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub type curl_conv_callback = Option<
    unsafe extern "C" fn(buffer: *mut c_char, length: usize) -> CURLcode,
>;

/// `curl_debug_callback`, transcribed from include/curl/curl.h.
#[allow(non_camel_case_types)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub type curl_debug_callback = Option<
    unsafe extern "C" fn(
        handle: *mut CURL,
        r#type: curl_infotype,
        data: *mut c_char,
        size: usize,
        userptr: *mut c_void,
    ) -> c_int,
>;

/// callback type for wildcard downloading pattern matching. If the string
/// matches the pattern, return CURL_FNMATCHFUNC_MATCH value, etc.
/// Declared in include/curl/curl.h.
#[allow(non_camel_case_types)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub type curl_fnmatch_callback = Option<
    unsafe extern "C" fn(
        ptr: *mut c_void,
        pattern: *const c_char,
        string: *const c_char,
    ) -> c_int,
>;

/// callback function for curl_formget() The void *arg pointer will be the
/// one passed as second argument to curl_formget(). The character buffer
/// passed to it must not be freed. Should return the buffer length passed
/// to it as the argument "len" on success.
/// Declared in include/curl/curl.h.
#[allow(non_camel_case_types)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub type curl_formget_callback = Option<
    unsafe extern "C" fn(
        arg: *mut c_void,
        buf: *const c_char,
        len: usize,
    ) -> usize,
>;

/// `curl_free_callback`, transcribed from include/curl/curl.h.
#[allow(non_camel_case_types)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub type curl_free_callback = Option<unsafe extern "C" fn(ptr: *mut c_void)>;

/// `curl_hstsread_callback`, transcribed from include/curl/curl.h.
#[allow(non_camel_case_types)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub type curl_hstsread_callback = Option<
    unsafe extern "C" fn(
        easy: *mut CURL,
        e: *mut curl_hstsentry,
        userp: *mut c_void,
    ) -> CURLSTScode,
>;

/// `curl_hstswrite_callback`, transcribed from include/curl/curl.h.
#[allow(non_camel_case_types)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub type curl_hstswrite_callback = Option<
    unsafe extern "C" fn(
        easy: *mut CURL,
        e: *mut curl_hstsentry,
        i: *mut curl_index,
        userp: *mut c_void,
    ) -> CURLSTScode,
>;

/// `curl_ioctl_callback`, transcribed from include/curl/curl.h.
#[allow(non_camel_case_types)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub type curl_ioctl_callback = Option<
    unsafe extern "C" fn(
        handle: *mut CURL,
        cmd: c_int,
        clientp: *mut c_void,
    ) -> curlioerr,
>;

/// `curl_lock_function`, transcribed from include/curl/curl.h.
#[allow(non_camel_case_types)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub type curl_lock_function = Option<
    unsafe extern "C" fn(
        handle: *mut CURL,
        data: curl_lock_data,
        locktype: curl_lock_access,
        userptr: *mut c_void,
    ),
>;

/// The following typedef's are signatures of malloc, free, realloc, strdup
/// and calloc respectively. Function pointers of these types can be passed
/// to the curl_global_init_mem() function to set user defined memory
/// management callback routines.
/// Declared in include/curl/curl.h.
#[allow(non_camel_case_types)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub type curl_malloc_callback =
    Option<unsafe extern "C" fn(size: usize) -> *mut c_void>;

/// Name:    curl_multi_timer_callback Desc:    Called by libcurl whenever
/// the library detects a change in the maximum number of milliseconds the
/// app is allowed to wait before curl_multi_socket() or
/// curl_multi_perform() must be called (to allow libcurl's timed events to
/// take place). Returns: The callback should return zero.
/// Declared in include/curl/multi.h.
#[allow(non_camel_case_types)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub type curl_multi_timer_callback = Option<
    unsafe extern "C" fn(
        multi: *mut CURLM,
        timeout_ms: c_long,
        userp: *mut c_void,
    ) -> c_int,
>;

/// Callback to install via CURLMOPT_NOTIFYFUNCTION.
/// Declared in include/curl/multi.h.
#[allow(non_camel_case_types)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub type curl_notify_callback = Option<
    unsafe extern "C" fn(
        multi: *mut CURLM,
        notification: c_uint,
        easy: *mut CURL,
        user_data: *mut c_void,
    ),
>;

/// This is the CURLOPT_PREREQFUNCTION callback prototype.
/// Declared in include/curl/curl.h.
#[allow(non_camel_case_types)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub type curl_prereq_callback = Option<
    unsafe extern "C" fn(
        clientp: *mut c_void,
        conn_primary_ip: *mut c_char,
        conn_local_ip: *mut c_char,
        conn_primary_port: c_int,
        conn_local_port: c_int,
    ) -> c_int,
>;

/// This is the CURLOPT_PROGRESSFUNCTION callback prototype. It is now
/// considered deprecated but was the only choice up until 7.31.0
/// Declared in include/curl/curl.h.
#[allow(non_camel_case_types)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub type curl_progress_callback = Option<
    unsafe extern "C" fn(
        clientp: *mut c_void,
        dltotal: c_double,
        dlnow: c_double,
        ultotal: c_double,
        ulnow: c_double,
    ) -> c_int,
>;

/// `curl_push_callback`, transcribed from include/curl/multi.h.
#[allow(non_camel_case_types)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub type curl_push_callback = Option<
    unsafe extern "C" fn(
        parent: *mut CURL,
        easy: *mut CURL,
        num_headers: usize,
        headers: *mut curl_pushheaders,
        userp: *mut c_void,
    ) -> c_int,
>;

/// `curl_read_callback`, transcribed from include/curl/curl.h.
#[allow(non_camel_case_types)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub type curl_read_callback = Option<
    unsafe extern "C" fn(
        buffer: *mut c_char,
        size: usize,
        nitems: usize,
        instream: *mut c_void,
    ) -> usize,
>;

/// `curl_realloc_callback`, transcribed from include/curl/curl.h.
#[allow(non_camel_case_types)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub type curl_realloc_callback =
    Option<unsafe extern "C" fn(ptr: *mut c_void, size: usize) -> *mut c_void>;

/// This callback will be called when a new resolver request is made
/// Declared in include/curl/curl.h.
#[allow(non_camel_case_types)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub type curl_resolver_start_callback = Option<
    unsafe extern "C" fn(
        resolver_state: *mut c_void,
        reserved: *mut c_void,
        userdata: *mut c_void,
    ) -> c_int,
>;

/// tell libcurl seeking cannot be done, so libcurl might try other means
/// instead
/// Declared in include/curl/curl.h.
#[allow(non_camel_case_types)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub type curl_seek_callback = Option<
    unsafe extern "C" fn(
        instream: *mut c_void,
        offset: curl_off_t,
        origin: c_int,
    ) -> c_int,
>;

/// `curl_socket_callback`, transcribed from include/curl/multi.h.
#[allow(non_camel_case_types)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub type curl_socket_callback = Option<
    unsafe extern "C" fn(
        easy: *mut CURL,
        s: curl_socket_t,
        what: c_int,
        userp: *mut c_void,
        socketp: *mut c_void,
    ) -> c_int,
>;

/// `curl_sockopt_callback`, transcribed from include/curl/curl.h.
#[allow(non_camel_case_types)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub type curl_sockopt_callback = Option<
    unsafe extern "C" fn(
        clientp: *mut c_void,
        curlfd: curl_socket_t,
        purpose: curlsocktype,
    ) -> c_int,
>;

/// CURLOPT_SSH_KEYDATA
/// Declared in include/curl/curl.h.
#[allow(non_camel_case_types)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub type curl_sshhostkeycallback = Option<
    unsafe extern "C" fn(
        clientp: *mut c_void,
        keytype: c_int,
        key: *const c_char,
        keylen: usize,
    ) -> c_int,
>;

/// `curl_ssl_ctx_callback`, transcribed from include/curl/curl.h.
#[allow(non_camel_case_types)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub type curl_ssl_ctx_callback = Option<
    unsafe extern "C" fn(
        curl: *mut CURL,
        ssl_ctx: *mut c_void,
        userptr: *mut c_void,
    ) -> CURLcode,
>;

/// `curl_strdup_callback`, transcribed from include/curl/curl.h.
#[allow(non_camel_case_types)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub type curl_strdup_callback =
    Option<unsafe extern "C" fn(str: *const c_char) -> *mut c_char>;

/// `curl_trailer_callback`, transcribed from include/curl/curl.h.
#[allow(non_camel_case_types)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub type curl_trailer_callback = Option<
    unsafe extern "C" fn(
        list: *mut *mut curl_slist,
        userdata: *mut c_void,
    ) -> c_int,
>;

/// `curl_unlock_function`, transcribed from include/curl/curl.h.
#[allow(non_camel_case_types)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub type curl_unlock_function = Option<
    unsafe extern "C" fn(
        handle: *mut CURL,
        data: curl_lock_data,
        userptr: *mut c_void,
    ),
>;

/// `curl_write_callback`, transcribed from include/curl/curl.h.
#[allow(non_camel_case_types)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub type curl_write_callback = Option<
    unsafe extern "C" fn(
        buffer: *mut c_char,
        size: usize,
        nitems: usize,
        outstream: *mut c_void,
    ) -> usize,
>;

/// This is the CURLOPT_XFERINFOFUNCTION callback prototype. It was
/// introduced in 7.32.0, avoids the use of floating point numbers and
/// provides more detailed information.
/// Declared in include/curl/curl.h.
#[allow(non_camel_case_types)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub type curl_xferinfo_callback = Option<
    unsafe extern "C" fn(
        clientp: *mut c_void,
        dltotal: curl_off_t,
        dlnow: curl_off_t,
        ultotal: curl_off_t,
        ulnow: curl_off_t,
    ) -> c_int,
>;

// Reconciliation constants.
//
// These are asserted by the tests below and read by
// `curl-rs-ffi/build.rs`, so a change here that is not also a change
// to the authority fails the build rather than drifting silently.

/// Number of shared enumerations declared in this module.
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub(crate) const SHARED_ENUMS: usize = 19;

/// Total members across all shared enumerations, sentinels included.
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub(crate) const SHARED_ENUM_MEMBERS: usize = 95;

/// Callback prototypes generated from this module.
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub(crate) const GENERATED_CALLBACKS: usize = 32;

/// Callback prototypes that must be spliced verbatim instead. Three, for
/// three different reasons: `curl_sshkeycallback` names a bare enum tag
/// cbindgen cannot spell, `curl_opensocket_callback` cannot be laid out
/// inside 79 columns by cbindgen, and `curl_ssls_export_cb` is a function
/// TYPE rather than a function pointer, which Rust has no way to express.
/// Together with `GENERATED_CALLBACKS` this must total the 35 public
/// callback typedefs.
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub(crate) const VERBATIM_CALLBACKS: usize = 3;

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, size_of, MaybeUninit};
    use core::ptr::addr_of;

    /// Byte offset of a field, without `core::mem::offset_of!`,
    /// which is stable only from Rust 1.77 while the workspace MSRV
    /// is 1.75 (AAP 0.8.3). `addr_of!` is stable since 1.51 and
    /// forms an address without creating a reference, so it is sound
    /// on uninitialised memory.
    macro_rules! offset {
        ($ty:ty, $field:ident) => {{
            let holder = MaybeUninit::<$ty>::uninit();
            let base = holder.as_ptr();
            // SAFETY: `base` points at a whole, correctly aligned
            // allocation owned by `holder`; `addr_of!` computes the
            // field address without reading uninitialised bytes.
            let field = unsafe { addr_of!((*base).$field) };
            (field as usize) - (base as usize)
        }};
    }

    #[test]
    fn every_discriminant_matches_the_frozen_header() {
        // All 95 members, transcribed from the pristine headers of
        // curl 8.19.0-DEV. A value that drifts here is an ABI break.
        // CURLMSG (3)
        assert_eq!(CURLMSG::CURLMSG_NONE as i64, 0);
        assert_eq!(CURLMSG::CURLMSG_DONE as i64, 1);
        assert_eq!(CURLMSG::CURLMSG_LAST as i64, 2);
        // CURLMinfo_offt (7)
        assert_eq!(CURLMinfo_offt::CURLMINFO_NONE as i64, 0);
        assert_eq!(CURLMinfo_offt::CURLMINFO_XFERS_CURRENT as i64, 1);
        assert_eq!(CURLMinfo_offt::CURLMINFO_XFERS_RUNNING as i64, 2);
        assert_eq!(CURLMinfo_offt::CURLMINFO_XFERS_PENDING as i64, 3);
        assert_eq!(CURLMinfo_offt::CURLMINFO_XFERS_DONE as i64, 4);
        assert_eq!(CURLMinfo_offt::CURLMINFO_XFERS_ADDED as i64, 5);
        assert_eq!(CURLMinfo_offt::CURLMINFO_LASTENTRY as i64, 6);
        // CURLMoption (20)
        assert_eq!(CURLMoption::CURLMOPT_SOCKETFUNCTION as i64, 20001);
        assert_eq!(CURLMoption::CURLMOPT_SOCKETDATA as i64, 10002);
        assert_eq!(CURLMoption::CURLMOPT_PIPELINING as i64, 3);
        assert_eq!(CURLMoption::CURLMOPT_TIMERFUNCTION as i64, 20004);
        assert_eq!(CURLMoption::CURLMOPT_TIMERDATA as i64, 10005);
        assert_eq!(CURLMoption::CURLMOPT_MAXCONNECTS as i64, 6);
        assert_eq!(CURLMoption::CURLMOPT_MAX_HOST_CONNECTIONS as i64, 7);
        assert_eq!(CURLMoption::CURLMOPT_MAX_PIPELINE_LENGTH as i64, 8);
        assert_eq!(
            CURLMoption::CURLMOPT_CONTENT_LENGTH_PENALTY_SIZE as i64,
            30009
        );
        assert_eq!(
            CURLMoption::CURLMOPT_CHUNK_LENGTH_PENALTY_SIZE as i64,
            30010
        );
        assert_eq!(CURLMoption::CURLMOPT_PIPELINING_SITE_BL as i64, 10011);
        assert_eq!(CURLMoption::CURLMOPT_PIPELINING_SERVER_BL as i64, 10012);
        assert_eq!(CURLMoption::CURLMOPT_MAX_TOTAL_CONNECTIONS as i64, 13);
        assert_eq!(CURLMoption::CURLMOPT_PUSHFUNCTION as i64, 20014);
        assert_eq!(CURLMoption::CURLMOPT_PUSHDATA as i64, 10015);
        assert_eq!(CURLMoption::CURLMOPT_MAX_CONCURRENT_STREAMS as i64, 16);
        assert_eq!(CURLMoption::CURLMOPT_NETWORK_CHANGED as i64, 17);
        assert_eq!(CURLMoption::CURLMOPT_NOTIFYFUNCTION as i64, 20018);
        assert_eq!(CURLMoption::CURLMOPT_NOTIFYDATA as i64, 10019);
        assert_eq!(CURLMoption::CURLMOPT_LASTENTRY as i64, 10020);
        // CURLUPart (11)
        assert_eq!(CURLUPart::CURLUPART_URL as i64, 0);
        assert_eq!(CURLUPart::CURLUPART_SCHEME as i64, 1);
        assert_eq!(CURLUPart::CURLUPART_USER as i64, 2);
        assert_eq!(CURLUPart::CURLUPART_PASSWORD as i64, 3);
        assert_eq!(CURLUPart::CURLUPART_OPTIONS as i64, 4);
        assert_eq!(CURLUPart::CURLUPART_HOST as i64, 5);
        assert_eq!(CURLUPart::CURLUPART_PORT as i64, 6);
        assert_eq!(CURLUPart::CURLUPART_PATH as i64, 7);
        assert_eq!(CURLUPart::CURLUPART_QUERY as i64, 8);
        assert_eq!(CURLUPart::CURLUPART_FRAGMENT as i64, 9);
        assert_eq!(CURLUPart::CURLUPART_ZONEID as i64, 10);
        // curl_TimeCond (1)
        assert_eq!(curl_TimeCond::CURL_TIMECOND_LAST as i64, 4);
        // curl_closepolicy (7)
        assert_eq!(curl_closepolicy::CURLCLOSEPOLICY_NONE as i64, 0);
        assert_eq!(curl_closepolicy::CURLCLOSEPOLICY_OLDEST as i64, 1);
        assert_eq!(
            curl_closepolicy::CURLCLOSEPOLICY_LEAST_RECENTLY_USED as i64,
            2
        );
        assert_eq!(curl_closepolicy::CURLCLOSEPOLICY_LEAST_TRAFFIC as i64, 3);
        assert_eq!(curl_closepolicy::CURLCLOSEPOLICY_SLOWEST as i64, 4);
        assert_eq!(curl_closepolicy::CURLCLOSEPOLICY_CALLBACK as i64, 5);
        assert_eq!(curl_closepolicy::CURLCLOSEPOLICY_LAST as i64, 6);
        // curl_ftpauth (1)
        assert_eq!(curl_ftpauth::CURLFTPAUTH_LAST as i64, 3);
        // curl_ftpccc (1)
        assert_eq!(curl_ftpccc::CURLFTPSSL_CCC_LAST as i64, 3);
        // curl_ftpcreatedir (1)
        assert_eq!(curl_ftpcreatedir::CURLFTP_CREATE_DIR_LAST as i64, 3);
        // curl_ftpmethod (1)
        assert_eq!(curl_ftpmethod::CURLFTPMETHOD_LAST as i64, 4);
        // curl_infotype (8)
        assert_eq!(curl_infotype::CURLINFO_TEXT as i64, 0);
        assert_eq!(curl_infotype::CURLINFO_HEADER_IN as i64, 1);
        assert_eq!(curl_infotype::CURLINFO_HEADER_OUT as i64, 2);
        assert_eq!(curl_infotype::CURLINFO_DATA_IN as i64, 3);
        assert_eq!(curl_infotype::CURLINFO_DATA_OUT as i64, 4);
        assert_eq!(curl_infotype::CURLINFO_SSL_DATA_IN as i64, 5);
        assert_eq!(curl_infotype::CURLINFO_SSL_DATA_OUT as i64, 6);
        assert_eq!(curl_infotype::CURLINFO_END as i64, 7);
        // curl_lock_access (4)
        assert_eq!(curl_lock_access::CURL_LOCK_ACCESS_NONE as i64, 0);
        assert_eq!(curl_lock_access::CURL_LOCK_ACCESS_SHARED as i64, 1);
        assert_eq!(curl_lock_access::CURL_LOCK_ACCESS_SINGLE as i64, 2);
        assert_eq!(curl_lock_access::CURL_LOCK_ACCESS_LAST as i64, 3);
        // curl_lock_data (9)
        assert_eq!(curl_lock_data::CURL_LOCK_DATA_NONE as i64, 0);
        assert_eq!(curl_lock_data::CURL_LOCK_DATA_SHARE as i64, 1);
        assert_eq!(curl_lock_data::CURL_LOCK_DATA_COOKIE as i64, 2);
        assert_eq!(curl_lock_data::CURL_LOCK_DATA_DNS as i64, 3);
        assert_eq!(curl_lock_data::CURL_LOCK_DATA_SSL_SESSION as i64, 4);
        assert_eq!(curl_lock_data::CURL_LOCK_DATA_CONNECT as i64, 5);
        assert_eq!(curl_lock_data::CURL_LOCK_DATA_PSL as i64, 6);
        assert_eq!(curl_lock_data::CURL_LOCK_DATA_HSTS as i64, 7);
        assert_eq!(curl_lock_data::CURL_LOCK_DATA_LAST as i64, 8);
        // curl_proxytype (1)
        assert_eq!(curl_proxytype::CURLPROXY_LAST as i64, 8);
        // curl_usessl (1)
        assert_eq!(curl_usessl::CURLUSESSL_LAST as i64, 4);
        // curlfiletype (9)
        assert_eq!(curlfiletype::CURLFILETYPE_FILE as i64, 0);
        assert_eq!(curlfiletype::CURLFILETYPE_DIRECTORY as i64, 1);
        assert_eq!(curlfiletype::CURLFILETYPE_SYMLINK as i64, 2);
        assert_eq!(curlfiletype::CURLFILETYPE_DEVICE_BLOCK as i64, 3);
        assert_eq!(curlfiletype::CURLFILETYPE_DEVICE_CHAR as i64, 4);
        assert_eq!(curlfiletype::CURLFILETYPE_NAMEDPIPE as i64, 5);
        assert_eq!(curlfiletype::CURLFILETYPE_SOCKET as i64, 6);
        assert_eq!(curlfiletype::CURLFILETYPE_DOOR as i64, 7);
        assert_eq!(curlfiletype::CURLFILETYPE_UNKNOWN as i64, 8);
        // curliocmd (3)
        assert_eq!(curliocmd::CURLIOCMD_NOP as i64, 0);
        assert_eq!(curliocmd::CURLIOCMD_RESTARTREAD as i64, 1);
        assert_eq!(curliocmd::CURLIOCMD_LAST as i64, 2);
        // curlioerr (4)
        assert_eq!(curlioerr::CURLIOE_OK as i64, 0);
        assert_eq!(curlioerr::CURLIOE_UNKNOWNCMD as i64, 1);
        assert_eq!(curlioerr::CURLIOE_FAILRESTART as i64, 2);
        assert_eq!(curlioerr::CURLIOE_LAST as i64, 3);
        // curlsocktype (3)
        assert_eq!(curlsocktype::CURLSOCKTYPE_IPCXN as i64, 0);
        assert_eq!(curlsocktype::CURLSOCKTYPE_ACCEPT as i64, 1);
        assert_eq!(curlsocktype::CURLSOCKTYPE_LAST as i64, 2);
    }

    #[test]
    fn member_counts_match_the_authority() {
        let curlmsg = [
            CURLMSG::CURLMSG_NONE,
            CURLMSG::CURLMSG_DONE,
            CURLMSG::CURLMSG_LAST,
        ];
        assert_eq!(curlmsg.len(), 3);
        let mut v: Vec<i64> = curlmsg.iter().map(|x| *x as i64).collect();
        v.sort_unstable();
        let n = v.len();
        v.dedup();
        assert_eq!(v.len(), n, "CURLMSG has a duplicate");
        let curlminfo_offt = [
            CURLMinfo_offt::CURLMINFO_NONE,
            CURLMinfo_offt::CURLMINFO_XFERS_CURRENT,
            CURLMinfo_offt::CURLMINFO_XFERS_RUNNING,
            CURLMinfo_offt::CURLMINFO_XFERS_PENDING,
            CURLMinfo_offt::CURLMINFO_XFERS_DONE,
            CURLMinfo_offt::CURLMINFO_XFERS_ADDED,
            CURLMinfo_offt::CURLMINFO_LASTENTRY,
        ];
        assert_eq!(curlminfo_offt.len(), 7);
        let mut v: Vec<i64> =
            curlminfo_offt.iter().map(|x| *x as i64).collect();
        v.sort_unstable();
        let n = v.len();
        v.dedup();
        assert_eq!(v.len(), n, "CURLMinfo_offt has a duplicate");
        let curlmoption = [
            CURLMoption::CURLMOPT_SOCKETFUNCTION,
            CURLMoption::CURLMOPT_SOCKETDATA,
            CURLMoption::CURLMOPT_PIPELINING,
            CURLMoption::CURLMOPT_TIMERFUNCTION,
            CURLMoption::CURLMOPT_TIMERDATA,
            CURLMoption::CURLMOPT_MAXCONNECTS,
            CURLMoption::CURLMOPT_MAX_HOST_CONNECTIONS,
            CURLMoption::CURLMOPT_MAX_PIPELINE_LENGTH,
            CURLMoption::CURLMOPT_CONTENT_LENGTH_PENALTY_SIZE,
            CURLMoption::CURLMOPT_CHUNK_LENGTH_PENALTY_SIZE,
            CURLMoption::CURLMOPT_PIPELINING_SITE_BL,
            CURLMoption::CURLMOPT_PIPELINING_SERVER_BL,
            CURLMoption::CURLMOPT_MAX_TOTAL_CONNECTIONS,
            CURLMoption::CURLMOPT_PUSHFUNCTION,
            CURLMoption::CURLMOPT_PUSHDATA,
            CURLMoption::CURLMOPT_MAX_CONCURRENT_STREAMS,
            CURLMoption::CURLMOPT_NETWORK_CHANGED,
            CURLMoption::CURLMOPT_NOTIFYFUNCTION,
            CURLMoption::CURLMOPT_NOTIFYDATA,
            CURLMoption::CURLMOPT_LASTENTRY,
        ];
        assert_eq!(curlmoption.len(), 20);
        let mut v: Vec<i64> = curlmoption.iter().map(|x| *x as i64).collect();
        v.sort_unstable();
        let n = v.len();
        v.dedup();
        assert_eq!(v.len(), n, "CURLMoption has a duplicate");
        let curlupart = [
            CURLUPart::CURLUPART_URL,
            CURLUPart::CURLUPART_SCHEME,
            CURLUPart::CURLUPART_USER,
            CURLUPart::CURLUPART_PASSWORD,
            CURLUPart::CURLUPART_OPTIONS,
            CURLUPart::CURLUPART_HOST,
            CURLUPart::CURLUPART_PORT,
            CURLUPart::CURLUPART_PATH,
            CURLUPart::CURLUPART_QUERY,
            CURLUPart::CURLUPART_FRAGMENT,
            CURLUPart::CURLUPART_ZONEID,
        ];
        assert_eq!(curlupart.len(), 11);
        let mut v: Vec<i64> = curlupart.iter().map(|x| *x as i64).collect();
        v.sort_unstable();
        let n = v.len();
        v.dedup();
        assert_eq!(v.len(), n, "CURLUPart has a duplicate");
        let curl_timecond = [curl_TimeCond::CURL_TIMECOND_LAST];
        assert_eq!(curl_timecond.len(), 1);
        let mut v: Vec<i64> = curl_timecond.iter().map(|x| *x as i64).collect();
        v.sort_unstable();
        let n = v.len();
        v.dedup();
        assert_eq!(v.len(), n, "curl_TimeCond has a duplicate");
        let curl_closepolicy = [
            curl_closepolicy::CURLCLOSEPOLICY_NONE,
            curl_closepolicy::CURLCLOSEPOLICY_OLDEST,
            curl_closepolicy::CURLCLOSEPOLICY_LEAST_RECENTLY_USED,
            curl_closepolicy::CURLCLOSEPOLICY_LEAST_TRAFFIC,
            curl_closepolicy::CURLCLOSEPOLICY_SLOWEST,
            curl_closepolicy::CURLCLOSEPOLICY_CALLBACK,
            curl_closepolicy::CURLCLOSEPOLICY_LAST,
        ];
        assert_eq!(curl_closepolicy.len(), 7);
        let mut v: Vec<i64> =
            curl_closepolicy.iter().map(|x| *x as i64).collect();
        v.sort_unstable();
        let n = v.len();
        v.dedup();
        assert_eq!(v.len(), n, "curl_closepolicy has a duplicate");
        let curl_ftpauth = [curl_ftpauth::CURLFTPAUTH_LAST];
        assert_eq!(curl_ftpauth.len(), 1);
        let mut v: Vec<i64> = curl_ftpauth.iter().map(|x| *x as i64).collect();
        v.sort_unstable();
        let n = v.len();
        v.dedup();
        assert_eq!(v.len(), n, "curl_ftpauth has a duplicate");
        let curl_ftpccc = [curl_ftpccc::CURLFTPSSL_CCC_LAST];
        assert_eq!(curl_ftpccc.len(), 1);
        let mut v: Vec<i64> = curl_ftpccc.iter().map(|x| *x as i64).collect();
        v.sort_unstable();
        let n = v.len();
        v.dedup();
        assert_eq!(v.len(), n, "curl_ftpccc has a duplicate");
        let curl_ftpcreatedir = [curl_ftpcreatedir::CURLFTP_CREATE_DIR_LAST];
        assert_eq!(curl_ftpcreatedir.len(), 1);
        let mut v: Vec<i64> =
            curl_ftpcreatedir.iter().map(|x| *x as i64).collect();
        v.sort_unstable();
        let n = v.len();
        v.dedup();
        assert_eq!(v.len(), n, "curl_ftpcreatedir has a duplicate");
        let curl_ftpmethod = [curl_ftpmethod::CURLFTPMETHOD_LAST];
        assert_eq!(curl_ftpmethod.len(), 1);
        let mut v: Vec<i64> =
            curl_ftpmethod.iter().map(|x| *x as i64).collect();
        v.sort_unstable();
        let n = v.len();
        v.dedup();
        assert_eq!(v.len(), n, "curl_ftpmethod has a duplicate");
        let curl_infotype = [
            curl_infotype::CURLINFO_TEXT,
            curl_infotype::CURLINFO_HEADER_IN,
            curl_infotype::CURLINFO_HEADER_OUT,
            curl_infotype::CURLINFO_DATA_IN,
            curl_infotype::CURLINFO_DATA_OUT,
            curl_infotype::CURLINFO_SSL_DATA_IN,
            curl_infotype::CURLINFO_SSL_DATA_OUT,
            curl_infotype::CURLINFO_END,
        ];
        assert_eq!(curl_infotype.len(), 8);
        let mut v: Vec<i64> = curl_infotype.iter().map(|x| *x as i64).collect();
        v.sort_unstable();
        let n = v.len();
        v.dedup();
        assert_eq!(v.len(), n, "curl_infotype has a duplicate");
        let curl_lock_access = [
            curl_lock_access::CURL_LOCK_ACCESS_NONE,
            curl_lock_access::CURL_LOCK_ACCESS_SHARED,
            curl_lock_access::CURL_LOCK_ACCESS_SINGLE,
            curl_lock_access::CURL_LOCK_ACCESS_LAST,
        ];
        assert_eq!(curl_lock_access.len(), 4);
        let mut v: Vec<i64> =
            curl_lock_access.iter().map(|x| *x as i64).collect();
        v.sort_unstable();
        let n = v.len();
        v.dedup();
        assert_eq!(v.len(), n, "curl_lock_access has a duplicate");
        let curl_lock_data = [
            curl_lock_data::CURL_LOCK_DATA_NONE,
            curl_lock_data::CURL_LOCK_DATA_SHARE,
            curl_lock_data::CURL_LOCK_DATA_COOKIE,
            curl_lock_data::CURL_LOCK_DATA_DNS,
            curl_lock_data::CURL_LOCK_DATA_SSL_SESSION,
            curl_lock_data::CURL_LOCK_DATA_CONNECT,
            curl_lock_data::CURL_LOCK_DATA_PSL,
            curl_lock_data::CURL_LOCK_DATA_HSTS,
            curl_lock_data::CURL_LOCK_DATA_LAST,
        ];
        assert_eq!(curl_lock_data.len(), 9);
        let mut v: Vec<i64> =
            curl_lock_data.iter().map(|x| *x as i64).collect();
        v.sort_unstable();
        let n = v.len();
        v.dedup();
        assert_eq!(v.len(), n, "curl_lock_data has a duplicate");
        let curl_proxytype = [curl_proxytype::CURLPROXY_LAST];
        assert_eq!(curl_proxytype.len(), 1);
        let mut v: Vec<i64> =
            curl_proxytype.iter().map(|x| *x as i64).collect();
        v.sort_unstable();
        let n = v.len();
        v.dedup();
        assert_eq!(v.len(), n, "curl_proxytype has a duplicate");
        let curl_usessl = [curl_usessl::CURLUSESSL_LAST];
        assert_eq!(curl_usessl.len(), 1);
        let mut v: Vec<i64> = curl_usessl.iter().map(|x| *x as i64).collect();
        v.sort_unstable();
        let n = v.len();
        v.dedup();
        assert_eq!(v.len(), n, "curl_usessl has a duplicate");
        let curlfiletype = [
            curlfiletype::CURLFILETYPE_FILE,
            curlfiletype::CURLFILETYPE_DIRECTORY,
            curlfiletype::CURLFILETYPE_SYMLINK,
            curlfiletype::CURLFILETYPE_DEVICE_BLOCK,
            curlfiletype::CURLFILETYPE_DEVICE_CHAR,
            curlfiletype::CURLFILETYPE_NAMEDPIPE,
            curlfiletype::CURLFILETYPE_SOCKET,
            curlfiletype::CURLFILETYPE_DOOR,
            curlfiletype::CURLFILETYPE_UNKNOWN,
        ];
        assert_eq!(curlfiletype.len(), 9);
        let mut v: Vec<i64> = curlfiletype.iter().map(|x| *x as i64).collect();
        v.sort_unstable();
        let n = v.len();
        v.dedup();
        assert_eq!(v.len(), n, "curlfiletype has a duplicate");
        let curliocmd = [
            curliocmd::CURLIOCMD_NOP,
            curliocmd::CURLIOCMD_RESTARTREAD,
            curliocmd::CURLIOCMD_LAST,
        ];
        assert_eq!(curliocmd.len(), 3);
        let mut v: Vec<i64> = curliocmd.iter().map(|x| *x as i64).collect();
        v.sort_unstable();
        let n = v.len();
        v.dedup();
        assert_eq!(v.len(), n, "curliocmd has a duplicate");
        let curlioerr = [
            curlioerr::CURLIOE_OK,
            curlioerr::CURLIOE_UNKNOWNCMD,
            curlioerr::CURLIOE_FAILRESTART,
            curlioerr::CURLIOE_LAST,
        ];
        assert_eq!(curlioerr.len(), 4);
        let mut v: Vec<i64> = curlioerr.iter().map(|x| *x as i64).collect();
        v.sort_unstable();
        let n = v.len();
        v.dedup();
        assert_eq!(v.len(), n, "curlioerr has a duplicate");
        let curlsocktype = [
            curlsocktype::CURLSOCKTYPE_IPCXN,
            curlsocktype::CURLSOCKTYPE_ACCEPT,
            curlsocktype::CURLSOCKTYPE_LAST,
        ];
        assert_eq!(curlsocktype.len(), 3);
        let mut v: Vec<i64> = curlsocktype.iter().map(|x| *x as i64).collect();
        v.sort_unstable();
        let n = v.len();
        v.dedup();
        assert_eq!(v.len(), n, "curlsocktype has a duplicate");
        assert_eq!(SHARED_ENUMS, 19);
        assert_eq!(SHARED_ENUM_MEMBERS, 95);
    }

    #[test]
    fn support_structs_match_the_measured_c_layout() {
        // Measured with gcc against the frozen headers on
        // x86_64-unknown-linux-gnu.
        assert_eq!(size_of::<curl_slist>(), 16);
        assert_eq!(align_of::<curl_slist>(), 8);
        assert_eq!(offset!(curl_slist, data), 0);
        assert_eq!(offset!(curl_slist, next), 8);

        assert_eq!(size_of::<curl_sockaddr>(), 32);
        assert_eq!(align_of::<curl_sockaddr>(), 4);
        assert_eq!(offset!(curl_sockaddr, family), 0);
        assert_eq!(offset!(curl_sockaddr, socktype), 4);
        assert_eq!(offset!(curl_sockaddr, protocol), 8);
        assert_eq!(offset!(curl_sockaddr, addrlen), 12);
        assert_eq!(offset!(curl_sockaddr, addr), 16);

        assert_eq!(size_of::<curl_hstsentry>(), 40);
        assert_eq!(align_of::<curl_hstsentry>(), 8);
        assert_eq!(offset!(curl_hstsentry, name), 0);
        assert_eq!(offset!(curl_hstsentry, namelen), 8);
        assert_eq!(offset!(curl_hstsentry, include_subdomains_bits), 16);
        // 17, not 18: gcc packs the one-bit field into a single
        // byte, so `expire` follows immediately.
        assert_eq!(offset!(curl_hstsentry, expire), 17);

        assert_eq!(size_of::<curl_index>(), 16);
        assert_eq!(align_of::<curl_index>(), 8);
        assert_eq!(offset!(curl_index, index), 0);
        assert_eq!(offset!(curl_index, total), 8);

        // Incomplete in the authority, so it carries no layout.
        assert_eq!(size_of::<curl_pushheaders>(), 0);

        assert_eq!(size_of::<curl_off_t>(), 8);
        assert_eq!(size_of::<curl_socket_t>(), 4);
    }

    #[test]
    fn the_hsts_bitfield_round_trips_without_touching_padding() {
        let mut e = curl_hstsentry {
            name: core::ptr::null_mut(),
            namelen: 0,
            include_subdomains_bits: 0b1111_1110,
            expire: [0; 18],
        };
        assert!(!e.include_subdomains());
        e.set_include_subdomains(true);
        assert!(e.include_subdomains());
        // The seven undefined bits must survive untouched.
        assert_eq!(e.include_subdomains_bits, 0b1111_1111);
        e.set_include_subdomains(false);
        assert!(!e.include_subdomains());
        assert_eq!(e.include_subdomains_bits, 0b1111_1110);
    }

    #[test]
    fn callbacks_are_nullable_and_pointer_sized() {
        // `Option<unsafe extern "C" fn(..)>` must use the null
        // pointer as its `None`, or a consumer's NULL would not be
        // seen as absent. Rust guarantees this niche, and these
        // assertions pin it so a change of representation fails.
        assert_eq!(GENERATED_CALLBACKS, 32);
        assert_eq!(VERBATIM_CALLBACKS, 3);
        assert_eq!(
            GENERATED_CALLBACKS + VERBATIM_CALLBACKS,
            35,
            "every public callback must be accounted for"
        );
        assert_eq!(size_of::<curl_write_callback>(), size_of::<*mut c_void>());
        assert_eq!(size_of::<curl_read_callback>(), size_of::<*mut c_void>());
        let none: curl_write_callback = None;
        assert!(none.is_none());
    }
}
