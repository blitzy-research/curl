// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl
//
// Derived from include/curl/curl.h, multi.h, easy.h, header.h,
// websockets.h, urlapi.h and system.h of curl 8.19.0-DEV at commit
// 54cf587b9c, and from lib/vtls/vtls_int.h for the one field-ordering
// constraint the C states in-source.

//! The handle typedefs, the layout-visible ABI structs, and the ownership
//! transfer that happens where Rust meets C.
//!
//! This module exports **zero** symbols. It carries no `#[no_mangle]` and no
//! `extern "C"` function; the twelve symbol-family modules do that. What lives
//! here is the vocabulary they all need and the one mechanism none of them may
//! reimplement:
//!
//! 1. Every `#[repr(C)]` type that crosses the boundary, in the exact shape
//!    the frozen headers declare, with size, alignment and every field offset
//!    asserted against a measurement in the `layout` tests.
//! 2. The RAII pattern at the boundary -- `Box::into_raw` on the way out,
//!    `Box::from_raw` on the way back -- so that ownership transfer is
//!    explicit and confined to [`into_raw`], [`from_raw`] and [`drop_raw`]
//!    rather than scattered across sixteen files.
//! 3. The canonical result a null handle produces, one per return-type family,
//!    so no symbol module invents its own fallback.
//!
//! # The seven handle typedefs are not uniform
//!
//! Treating them uniformly breaks consumers, so each is reproduced in the
//! shape its own declaration has:
//!
//! | Frozen declaration | Location | Rust form |
//! |---|---|---|
//! | `typedef void CURL;` | curl.h:109 | [`CURL`] = `c_void` |
//! | `typedef void CURLSH;` | curl.h:110 | [`CURLSH`] = `c_void` |
//! | `typedef void CURLM;` | multi.h:57 | [`CURLM`] = `c_void` |
//! | `typedef struct Curl_URL CURLU;` | urlapi.h:107 | opaque [`Curl_URL`] |
//! | `typedef struct CURLMsg CURLMsg;` | multi.h:105 | layout-visible |
//! | `typedef struct curl_mime curl_mime;` | curl.h:2428 | opaque, self-named |
//! | `typedef struct curl_mimepart curl_mimepart;` | curl.h:2429 | ditto |
//!
//! The first three are `void`, **not** opaque structs. cbindgen's natural
//! output for an opaque Rust type is `typedef struct X X;`, which diverges
//! from all three and changes the type of every handle-passing call: a
//! consumer that assigns a `CURL *` to a `void *` -- a widespread idiom,
//! present throughout `docs/examples/` -- would begin emitting diagnostics.
//! `CURLU` diverges differently: its struct tag `Curl_URL` is not its typedef
//! name, so cbindgen would emit `typedef struct CURLU CURLU;` and declare a
//! tag no other translation unit knows. `curl_mime` and `curl_mimepart` are
//! the self-named case, where tag and typedef agree.
//!
//! Every name here is listed under `[export] exclude` in `cbindgen.toml`, and
//! `[export] item_types` deliberately omits `"opaque"` so that no accident of
//! visibility can produce those lines. The C declarations are spliced verbatim
//! by `curl-rs-ffi/build.rs` instead. The Rust declarations exist so the rest
//! of the FFI tree has real types to name and so their layout can be asserted;
//! they are never the source of the emitted C.
//!
//! ## Three names this module deals in are deliberately not on that list
//!
//! Measured against `cbindgen.toml`, twenty-eight of the thirty-one names in
//! this module's vocabulary appear in `[export] exclude`. The three that do
//! not are exactly the three with no counterpart in the frozen ABI to exclude
//! *by*: [`CURLMsg_data`] and [`curl_fileinfo_strings`] are Rust names for a C
//! unnamed union type and a C anonymous struct, and [`curl_socklen_t`]'s C
//! declaration lives in `system.h` (`:390`), which `build.rs` ships as-is
//! rather than generating.
//!
//! That is safe as configured, and the reason is worth writing down because it
//! is not the exclude list: `[export] include` is a non-empty sixty-two-entry
//! whitelist, so cbindgen emits an item only if that list names it or an
//! exported signature needs it. None of the three is named, and the only route
//! to the first two is through [`CURLMsg`] and [`curl_fileinfo`], both of
//! which are excluded and spliced verbatim. `curl_socklen_t` is referenced by
//! no public prototype at all -- `system.h` is its sole declaration site in
//! all twelve headers.
//!
//! So if header generation resumes and any of the three appears in the output,
//! that is a regression rather than a cosmetic difference: each would be a
//! declaration curl 8.19.0-DEV does not have, and `curl_socklen_t` would be a
//! second typedef of a name `curl.h` already receives by including
//! `system.h`.
//!
//! # Five declarations cbindgen cannot express at all
//!
//! For these the header text is authoritative and `build.rs` splices it. The
//! Rust forms below are layout stand-ins, and each says so at its
//! declaration:
//!
//! * [`curl_httppost`] -- eight `#define`s sit **inside** the struct body
//!   (curl.h:204-220, between `long flags;` and `char *showfilename;`).
//!   cbindgen emits no preprocessor directives, let alone interleaved ones.
//! * [`curl_fileinfo`] -- embeds a nested **anonymous** struct named
//!   `strings` (curl.h:326-333). cbindgen would hoist it to a named
//!   top-level type, changing the ABI-visible spelling `finfo->strings.time`.
//! * `curl_hstsentry` -- carries the ABI's only bit-field. cbindgen cannot
//!   express a bit-field.
//! * [`CURLMsg`] -- a C89 named member `data` of an **unnamed union type**,
//!   not a C11 anonymous union. Rust has no anonymous unions either, so the
//!   union is named [`CURLMsg_data`] here; naming it changes no offset.
//! * `curl_pushheaders` -- a forward declaration with no body anywhere
//!   (multi.h:500). An opaque `typedef` would be wrong: every use site spells
//!   it `struct curl_pushheaders *`.
//!
//! # Where the eighteen declarations live, and why not all of them are here
//!
//! The twelve public headers declare nineteen structs: eighteen with bodies
//! plus one forward declaration. Seventeen bodies and the forward declaration
//! belong to this module's inventory; the nineteenth, `struct curl_easyoption`
//! (options.h:51-56), deliberately does not, because it is the row type of the
//! option-introspection table and belongs with the table.
//!
//! Of this module's eighteen, eleven are **declared here** -- the ten below
//! plus [`CURLMsg`] -- and seven are declared by [`super::types`], which needed
//! them first because the generated callback prototypes name them. That
//! division is not cosmetic and it is not negotiable: a second
//! `#[repr(C)] struct curl_slist` in this module would be a *different Rust
//! type* with the same name, and `super::slist`, `super::global` and
//! `super::misc` -- which already name the `types` ones -- would stop
//! type-checking against it. So there is exactly one definition of each. Three
//! of the seven are re-exported here, because structs declared below name them
//! in their own fields; the other four, plus `curl_version_info_data` and the
//! `curl_pushheaders` forward declaration, are reached at their own path.
//! The `layout` tests assert all seventeen bodies regardless of which module
//! declares them, which is where the obligation actually bites.
//!
//! # Thirty-two bits are not supported and the limitation is not hidden
//!
//! [`curl_off_t`] is 64-bit on all four mandated targets, and the varargs
//! design the setters use holds an `off_t` in one register-width slot only
//! where `off_t` fits a register. Thirty-two-bit portability is deliberately
//! forfeited and is not claimed anywhere.

use core::ffi::{c_char, c_int, c_long, c_short, c_uint, c_void};
use core::ptr;

use super::codes::{
    curl_khtype, curl_sslbackend, CURLHcode, CURLMcode, CURLSHcode, CURLUcode,
    CURLcode,
};
use super::opts::CURLformoption;
use super::types::{curlfiletype, CURLMSG};

// Three of the seven declarations `super::types` owns, re-exported because the
// structs below name them in their own fields: a handle-shaped reading of the
// ABI needs `handle::curl_off_t` and `handle::curl_socket_t` to resolve, and
// `curl_slist` appears inside two structs declared here. The remaining four --
// `curl_hstsentry`, `curl_index`, `curl_sockaddr` and `curl_ssl_backend` --
// plus `curl_version_info_data` and the `curl_pushheaders` forward declaration
// are NOT re-exported: `super::slist`, `super::global` and `super::misc`
// already name them through `super::types`, and a second path that nothing
// travels would have to be excused from `unused_imports` to compile. They are
// nevertheless part of this module's inventory and [`layout`] asserts every
// one of them, which is where the obligation actually bites.
pub(crate) use super::types::{curl_off_t, curl_slist, curl_socket_t};

// ---------------------------------------------------------------------------
// The seven handle typedefs.
// ---------------------------------------------------------------------------

/// An easy handle. Frozen as `typedef void CURL;` (curl.h:109), so the alias
/// resolves to `c_void` and `*mut CURL` is spelled `CURL *` in C.
#[allow(non_camel_case_types)]
#[allow(dead_code)]
// ABI declaration: read by cbindgen, not by Rust callers
// Frozen C ABI name: `include/curl/curl.h` spells it this way and AAP 0.8.1
// forbids changing a public typedef, so the style lint yields to the contract.
#[allow(clippy::upper_case_acronyms)]
pub type CURL = c_void;

/// A multi handle. Frozen as `typedef void CURLM;` (multi.h:57).
#[allow(non_camel_case_types)]
#[allow(dead_code)]
// ABI declaration: read by cbindgen, not by Rust callers
// Frozen C ABI name: `include/curl/curl.h` spells it this way and AAP 0.8.1
// forbids changing a public typedef, so the style lint yields to the contract.
#[allow(clippy::upper_case_acronyms)]
pub type CURLM = c_void;

/// A share handle. Frozen as `typedef void CURLSH;` (curl.h:110).
#[allow(non_camel_case_types)]
#[allow(dead_code)]
// ABI declaration: read by cbindgen, not by Rust callers
// Frozen C ABI name: `include/curl/curl.h` spells it this way and AAP 0.8.1
// forbids changing a public typedef, so the style lint yields to the contract.
#[allow(clippy::upper_case_acronyms)]
pub type CURLSH = c_void;

/// The URL handle's underlying struct, frozen as an incomplete type: the
/// header declares `typedef struct Curl_URL CURLU;` (urlapi.h:107) and never
/// defines `struct Curl_URL`, so consumers can only hold it behind a pointer.
/// A zero-sized `_opaque` field reproduces that: it makes the type
/// un-constructible by a consumer without inventing a layout the authority
/// does not specify.
#[allow(non_camel_case_types)]
#[repr(C)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub struct Curl_URL {
    _opaque: [u8; 0],
}

/// A URL handle. Frozen as `typedef struct Curl_URL CURLU;` (urlapi.h:107).
#[allow(non_camel_case_types)]
#[allow(dead_code)]
// ABI declaration: read by cbindgen, not by Rust callers
// Frozen C ABI name: `include/curl/curl.h` spells it this way and AAP 0.8.1
// forbids changing a public typedef, so the style lint yields to the contract.
#[allow(clippy::upper_case_acronyms)]
pub type CURLU = Curl_URL;

/// A mime context, frozen as `typedef struct curl_mime curl_mime;`
/// (curl.h:2428, whose comment reads "Mime context.").
///
/// Self-named: the struct tag and the typedef name are the same word, unlike
/// `struct Curl_URL` and its typedef `CURLU`. That distinction is the reason
/// the handle inventory is SEVEN entries rather than the five the two `void`
/// aliases and `CURLU` and `CURLMsg` would suggest -- this type and
/// [`curl_mimepart`] are the argument and return types of all twelve
/// `curl_mime_*` symbols, so they are as ABI-visible as `CURLU` is.
///
/// Opaque, like `Curl_URL`: the authority never defines a body.
#[allow(non_camel_case_types)]
#[repr(C)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub struct curl_mime {
    _opaque: [u8; 0],
}

/// A mime part context, frozen as
/// `typedef struct curl_mimepart curl_mimepart;` (curl.h:2429, whose comment
/// reads "Mime part context."). Self-named and opaque, exactly as
/// [`curl_mime`] is.
#[allow(non_camel_case_types)]
#[repr(C)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub struct curl_mimepart {
    _opaque: [u8; 0],
}

/// The message payload union of [`CURLMsg`].
///
/// The frozen declaration nests an *unnamed union type* under the named member
/// `data` (multi.h:100-103). That is the C89 form, not a C11 anonymous union,
/// and it is why `data` appears in consumer code as `msg->data.result`. Rust
/// has no unnamed union types, so it is named here; the name never reaches C,
/// because both this type and `CURLMsg` are listed under `[export] exclude`
/// and the C struct is spliced verbatim. Naming it changes no offset: an
/// unnamed union type and a named one with identical members have identical
/// size and alignment.
#[allow(non_camel_case_types)]
#[repr(C)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub union CURLMsg_data {
    /// Message-specific data. Frozen as `void *whatever;`.
    pub whatever: *mut c_void,
    /// The transfer's result code. Frozen as `CURLcode result;`.
    pub result: CURLcode,
}

/// A completed-transfer message, as returned by `curl_multi_info_read`
/// (multi.h:97-105).
///
/// Layout-visible: consumers read every field directly, and
/// `docs/examples/multi-*.c` write `msg->data.result` verbatim. Measured
/// against the frozen headers with gcc: size 24, alignment 8, with `msg` at 0,
/// `easy_handle` at 8 and `data` at 16, identical on `x86_64-unknown-linux-gnu`
/// and `aarch64-unknown-linux-gnu`. The `layout` tests assert exactly those
/// numbers.
#[allow(non_camel_case_types)]
#[repr(C)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub struct CURLMsg {
    /// What this message means.
    pub msg: CURLMSG,
    /// The handle it concerns.
    pub easy_handle: *mut CURL,
    /// The message-specific payload, discriminated by `msg`.
    pub data: CURLMsg_data,
}

// ---------------------------------------------------------------------------
// The scalar typedefs.
//
// `curl_off_t` and `curl_socket_t` are re-exported above from
// `super::types`; the two declarations below complete the set.
// ---------------------------------------------------------------------------

/// The invalid-socket sentinel, frozen as `#define CURL_SOCKET_BAD (-1)`
/// (curl.h:145) on every non-Windows target.
///
/// The header's other arm is `INVALID_SOCKET`, reached only under `_WIN32`
/// (curl.h:140-142). Windows is outside the four mandated targets, all of
/// which are Unix-like, so no second arm is invented here: writing one would
/// claim support that nothing in this tree builds or tests.
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub const CURL_SOCKET_BAD: curl_socket_t = -1;

/// The socket-length type, frozen in `system.h` as
/// `CURL_TYPEOF_CURL_SOCKLEN_T`.
///
/// `system.h` is shipped as-is rather than generated, so this alias has to
/// agree with what that header computes rather than define it. On every
/// mandated target the macro resolves to the platform's `socklen_t`, which is
/// what `libc` names per target; measured 4 bytes, alignment 4.
///
/// Note that `struct curl_sockaddr` does **not** use this type: curl.h:431-433
/// records in-source that `socklen_t` "turned really ugly and painful on the
/// systems that lack this type", so that field is a plain `unsigned int`.
#[allow(non_camel_case_types)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub type curl_socklen_t = libc::socklen_t;

// Two properties of the scalars that the compiler can settle outright, so it
// does rather than a test doing it later. `curl_off_t` carries file sizes and
// resume offsets, both of which the API expresses as negative sentinels, and an
// unsigned alias would make `-1` unrepresentable while still compiling
// everywhere it is assigned. Eight bytes is the other half: `system.h` computes
// a 64-bit type on every mandated target, and the varargs slot the setters read
// holds an `off_t` only where one fits a register -- which is why 32-bit
// support is forfeited rather than claimed.
const _: () = assert!(curl_off_t::MIN < 0);
const _: () = assert!(core::mem::size_of::<curl_off_t>() == 8);

// ---------------------------------------------------------------------------
// `struct curl_httppost` (curl.h:188-230) and the eight flag bits that the
// authority interleaves INSIDE its body.
// ---------------------------------------------------------------------------

/// The legacy form-post node, frozen at curl.h:188-230.
///
/// Fourteen fields, in the authority's order. Measured size 112, alignment 8,
/// with every field at a multiple of eight because `long` and `curl_off_t` are
/// both 64-bit on the mandated targets.
///
/// # Why the header text is authoritative for this one
///
/// The eight `CURL_HTTPPOST_*` `#define`s are not written after the struct;
/// they are written **inside its body**, at curl.h:204-220, between
/// `long flags;` and `char *showfilename;`. cbindgen emits no preprocessor
/// directives at all, so it cannot reproduce a `#define` block at a position
/// inside a braced declaration. `curl-rs-ffi/build.rs` therefore splices the
/// whole declaration verbatim, `#define`s in place, and this Rust form exists
/// for layout and for `super::form`'s use of the type. The eight constants are
/// declared below as ordinary Rust items for the same reason.
///
/// The type is deprecated in favour of the mime API but still exported through
/// `curl_formadd`, `curl_formfree` and `curl_formget`, so it stays.
#[allow(non_camel_case_types)]
#[repr(C)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub struct curl_httppost {
    /// Next entry in the list.
    pub next: *mut curl_httppost,
    /// Pointer to allocated name.
    pub name: *mut c_char,
    /// Length of name.
    pub namelength: c_long,
    /// Pointer to allocated data contents.
    pub contents: *mut c_char,
    /// Length of the contents field. See also [`CURL_HTTPPOST_LARGE`].
    pub contentslength: c_long,
    /// Pointer to allocated buffer contents.
    pub buffer: *mut c_char,
    /// Length of the buffer field.
    pub bufferlength: c_long,
    /// `Content-Type`.
    pub contenttype: *mut c_char,
    /// List of extra headers for this form.
    pub contentheader: *mut curl_slist,
    /// If one field name has more than one file, this link should link to the
    /// following files.
    pub more: *mut curl_httppost,
    /// The `CURL_HTTPPOST_*` bits. `long` in the authority, so `c_long` here:
    /// a narrower type would misplace every field after it.
    pub flags: c_long,
    /// The filename to show. If not set, the actual filename is used, when
    /// this is a file part.
    pub showfilename: *mut c_char,
    /// Custom pointer used for [`CURL_HTTPPOST_CALLBACK`] posts.
    pub userp: *mut c_void,
    /// Alternative length of the contents field, used when
    /// [`CURL_HTTPPOST_LARGE`] is set.
    pub contentlen: curl_off_t,
}

/// Specified content is a filename (curl.h:205).
///
/// Typed `c_long` because [`curl_httppost::flags`] is a `long`: the bits are
/// combined into that field, and a `c_int` constant would be the wrong width
/// for the comparison on a 64-bit target.
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub const CURL_HTTPPOST_FILENAME: c_long = 1 << 0;
/// Specified content is a filename (curl.h:207).
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub const CURL_HTTPPOST_READFILE: c_long = 1 << 1;
/// Name is only a stored pointer; do not free it in `curl_formfree`
/// (curl.h:209).
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub const CURL_HTTPPOST_PTRNAME: c_long = 1 << 2;
/// Contents is only a stored pointer; do not free it in `curl_formfree`
/// (curl.h:211).
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub const CURL_HTTPPOST_PTRCONTENTS: c_long = 1 << 3;
/// Upload file from buffer (curl.h:213).
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub const CURL_HTTPPOST_BUFFER: c_long = 1 << 4;
/// Upload file from pointer contents (curl.h:215).
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub const CURL_HTTPPOST_PTRBUFFER: c_long = 1 << 5;
/// Upload file contents by using the regular read callback to get the data,
/// passing the given pointer as the custom pointer (curl.h:218).
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub const CURL_HTTPPOST_CALLBACK: c_long = 1 << 6;
/// Use the size in [`curl_httppost::contentlen`] (curl.h:220).
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub const CURL_HTTPPOST_LARGE: c_long = 1 << 7;

// ---------------------------------------------------------------------------
// `struct curl_fileinfo` (curl.h:316-342), its nested anonymous struct, and
// the eight `CURLFINFOFLAG_KNOWN_*` bits that say which fields were parsed.
// ---------------------------------------------------------------------------

/// The nested `strings` sub-struct of [`curl_fileinfo`], frozen at
/// curl.h:326-333.
///
/// # Why this type has a name in Rust and must not have one in C
///
/// The authority declares it **anonymously**: `struct { ... } strings;`. Rust
/// has no anonymous struct types, so it is named here -- and the name must not
/// reach the header, because cbindgen would hoist an anonymous member into a
/// named top-level type and the ABI-visible spelling `finfo->strings.time`
/// would change to something else. `curl-rs-ffi/build.rs` splices
/// `curl_fileinfo` verbatim for exactly this reason, so the C keeps the
/// anonymous form while Rust gets a nameable one. Naming it changes no offset:
/// measured, `strings` begins at 56 and its five members follow at 56, 64, 72,
/// 80 and 88, which is what five pointers laid end to end give.
///
/// The authority's own comment applies to every member: "If some of these
/// fields is not NULL, it is a pointer to `b_data`." They are views into the
/// private buffer, not separate allocations.
#[allow(non_camel_case_types)]
#[repr(C)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub struct curl_fileinfo_strings {
    /// The timestamp as the server rendered it.
    pub time: *mut c_char,
    /// The permission bits as the server rendered them.
    pub perm: *mut c_char,
    /// The owning user's name.
    pub user: *mut c_char,
    /// The owning group's name.
    pub group: *mut c_char,
    /// Pointer to the target filename of a symlink.
    pub target: *mut c_char,
}

/// Information about a single file, used when doing FTP wildcard matching
/// (curl.h:316-342).
///
/// Measured size 128, alignment 8. Field offsets: `filename` 0, `filetype` 8,
/// `time` 16, `perm` 24, `uid` 28, `gid` 32, `size` 40, `hardlinks` 48,
/// `strings` 56, `flags` 96, `b_data` 104, `b_size` 112, `b_used` 120.
///
/// Reached by a `curl_chunk_bgn_callback`, which receives it as
/// `const void *transfer_info` and casts it, so every offset is observable
/// from consumer code.
#[allow(non_camel_case_types)]
#[repr(C)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub struct curl_fileinfo {
    /// The entry's name within the listed directory.
    pub filename: *mut c_char,
    /// What kind of directory entry this is.
    pub filetype: curlfiletype,
    /// Frozen with the authority's own comment: "always zero!" The field
    /// exists and occupies its slot regardless, because removing it would move
    /// every field after it.
    pub time: libc::time_t,
    /// The permission bits.
    pub perm: c_uint,
    /// Owning user id.
    pub uid: c_int,
    /// Owning group id.
    pub gid: c_int,
    /// Size in bytes.
    pub size: curl_off_t,
    /// Hard-link count. Spelled `long int` in the authority, which is the same
    /// type as `long`; `c_long` is the faithful transcription.
    pub hardlinks: c_long,
    /// The rendered forms of the fields above, as the server sent them.
    pub strings: curl_fileinfo_strings,
    /// Which of the fields above were actually parsed: a mask of the
    /// `CURLFINFOFLAG_KNOWN_*` bits.
    pub flags: c_uint,
    /// Private to libcurl. The authority's comment is explicit -- "These are
    /// libcurl private struct fields. Previously used by libcurl, so they must
    /// never be interfered with." They are reproduced because they occupy real
    /// bytes that a consumer's `sizeof` and `offsetof` both see.
    pub b_data: *mut c_char,
    /// Private to libcurl; see [`curl_fileinfo::b_data`].
    pub b_size: usize,
    /// Private to libcurl; see [`curl_fileinfo::b_data`].
    pub b_used: usize,
}

/// [`curl_fileinfo::filename`] was parsed (curl.h:306).
///
/// Typed `c_uint` because [`curl_fileinfo::flags`] is an `unsigned int` and
/// the documented use is `finfo->flags & CURLFINFOFLAG_KNOWN_FILENAME`.
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub const CURLFINFOFLAG_KNOWN_FILENAME: c_uint = 1 << 0;
/// [`curl_fileinfo::filetype`] was parsed (curl.h:307).
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub const CURLFINFOFLAG_KNOWN_FILETYPE: c_uint = 1 << 1;
/// [`curl_fileinfo::time`] was parsed (curl.h:308).
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub const CURLFINFOFLAG_KNOWN_TIME: c_uint = 1 << 2;
/// [`curl_fileinfo::perm`] was parsed (curl.h:309).
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub const CURLFINFOFLAG_KNOWN_PERM: c_uint = 1 << 3;
/// [`curl_fileinfo::uid`] was parsed (curl.h:310).
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub const CURLFINFOFLAG_KNOWN_UID: c_uint = 1 << 4;
/// [`curl_fileinfo::gid`] was parsed (curl.h:311).
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub const CURLFINFOFLAG_KNOWN_GID: c_uint = 1 << 5;
/// [`curl_fileinfo::size`] was parsed (curl.h:312).
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub const CURLFINFOFLAG_KNOWN_SIZE: c_uint = 1 << 6;
/// [`curl_fileinfo::hardlinks`] was parsed (curl.h:313).
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub const CURLFINFOFLAG_KNOWN_HLINKCOUNT: c_uint = 1 << 7;

// ---------------------------------------------------------------------------
// The remaining layout-visible structs, in header order.
// ---------------------------------------------------------------------------

/// A host key, handed to a `curl_sshkeycallback` (curl.h:876-881).
///
/// Measured size 24, alignment 8, with `key` at 0, `len` at 8 and `keytype`
/// at 16.
///
/// The third field is spelled with the `enum` **keyword** in the authority --
/// `enum curl_khtype keytype;` -- because `curl_khtype` is one of the few
/// public enums declared in tag form rather than as an anonymous
/// `typedef enum`. `super::codes` owns that enum; the generated header must
/// keep the `enum ` spelling at this use site, which is one more reason this
/// declaration is spliced rather than rendered.
#[allow(non_camel_case_types)]
#[repr(C)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub struct curl_khkey {
    /// Points to a NUL-terminated string encoded with base64 when `len` is
    /// zero, otherwise to the raw data.
    pub key: *const c_char,
    /// Length of the raw data, or zero when `key` is base64.
    pub len: usize,
    /// Which key algorithm this is.
    pub keytype: curl_khtype,
}

/// One row of a `CURLFORM_ARRAY`, frozen at curl.h:2587-2590.
///
/// Measured size 16, alignment 8, with `option` at 0 and `value` at 8. The
/// four bytes between them are padding the C compiler inserts, not a field.
///
/// `super::opts` owns [`CURLformoption`]; importing it rather than restating it
/// is what keeps the two from drifting, since a form option's integer is as
/// frozen as an easy option's.
#[allow(non_camel_case_types)]
#[repr(C)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub struct curl_forms {
    /// Which form option this row supplies.
    pub option: CURLformoption,
    /// The option's value.
    pub value: *const c_char,
}

/// The certificate chain reported by `CURLINFO_CERTINFO` (curl.h:2874-2880).
///
/// Measured size 16, alignment 8, with `num_of_certs` at 0 and `certinfo` at 8.
#[allow(non_camel_case_types)]
#[repr(C)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub struct curl_certinfo {
    /// Number of certificates with information.
    pub num_of_certs: c_int,
    /// For each index in this array there is a linked list with textual
    /// information for one certificate, in the form `name:content` -- for
    /// example `Subject:foo` or `Issuer:bar`.
    pub certinfo: *mut *mut curl_slist,
}

/// The TLS library and its internal handle, reported by
/// `CURLINFO_TLS_SSL_PTR` and `CURLINFO_TLS_SESSION` (curl.h:2885-2888).
///
/// Measured size 16, alignment 8, with `backend` at 0 and `internals` at 8.
///
/// `internals` is null in this implementation and that is the truthful answer,
/// not an omission: the field's contract is to expose the backend's own session
/// object, and rustls exposes no C-representable handle to hand over. A
/// consumer that tests it for null -- which is what the documented use
/// requires -- sees a correct answer.
#[allow(non_camel_case_types)]
#[repr(C)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub struct curl_tlssessioninfo {
    /// Which backend produced the session.
    pub backend: curl_sslbackend,
    /// The backend's internal session object, or null when it has none to
    /// expose.
    pub internals: *mut c_void,
}

/// A blob argument, frozen at easy.h:34-39.
///
/// Measured size 24, alignment 8, with `data` at 0, `len` at 8 and `flags`
/// at 16.
///
/// Consumers construct this **on the stack** and pass `&blob` to every
/// `CURLOPTTYPE_BLOB` option, so its layout is directly observable rather than
/// merely referenced. That is why the offsets are asserted rather than
/// assumed.
#[allow(non_camel_case_types)]
#[repr(C)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub struct curl_blob {
    /// The bytes themselves.
    pub data: *mut c_void,
    /// How many bytes `data` addresses.
    pub len: usize,
    /// [`CURL_BLOB_COPY`] or [`CURL_BLOB_NOCOPY`]. The authority's comment
    /// spans two lines: "bit 0 is defined, the rest are reserved and should be
    /// left zeroes".
    pub flags: c_uint,
}

/// Tell libcurl to copy the data (easy.h:31).
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub const CURL_BLOB_COPY: c_uint = 1;
/// Tell libcurl NOT to copy the data (easy.h:32).
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub const CURL_BLOB_NOCOPY: c_uint = 0;

/// One header, as returned by `curl_easy_header` and `curl_easy_nextheader`
/// (header.h:31-38).
///
/// Six fields. Measured size 48, alignment 8, with `name` at 0, `value` at 8,
/// `amount` at 16, `index` at 24, `origin` at 32 and `anchor` at 40.
///
/// `anchor` is documented as "handle privately used by libcurl" and is last,
/// but it is reproduced and occupies its slot: a consumer's `sizeof` sees it,
/// and libcurl itself allocates the struct, so dropping it would make the two
/// sides disagree about how much memory a header record needs.
///
/// The five `CURLH_*` bits that `origin` carries live in `super::codes`; they
/// are imported where a symbol module needs them rather than restated here.
#[allow(non_camel_case_types)]
#[repr(C)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub struct curl_header {
    /// The header's name. The authority warns that this "might not use the
    /// same case" as the wire form.
    pub name: *mut c_char,
    /// The header's value.
    pub value: *mut c_char,
    /// Number of headers using this name.
    pub amount: usize,
    /// Which instance this is, zero or higher.
    pub index: usize,
    /// Where the header came from: a mask of the `CURLH_*` bits.
    pub origin: c_uint,
    /// Handle privately used by libcurl.
    pub anchor: *mut c_void,
}

/// One entry of a `curl_multi_wait` or `curl_multi_poll` descriptor array
/// (multi.h:114-118).
///
/// Measured size 8, alignment 4, with `fd` at 0, `events` at 4 and `revents`
/// at 6.
///
/// The two event fields are **`short`, not `int`**. Getting that wrong is not a
/// compile error anywhere; it silently doubles the stride of an array that
/// `curl_multi_wait`, `curl_multi_poll` and `curl_multi_waitfds` all index, and
/// the first two declare their parameter with an array declarator
/// (`struct curl_waitfd extra_fds[]`, multi.h:172-176 and :186-190), so the
/// caller's array and the callee's view would disagree from the second element
/// onwards. The authority's comment explains why the type exists at all: it is
/// "Based on poll(2) structure and values. We do not use pollfd and POLL*
/// constants explicitly to cover platforms without poll()."
///
/// The three `CURL_WAIT_POLL*` bits belong with the multi symbols, not here.
#[allow(non_camel_case_types)]
#[repr(C)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub struct curl_waitfd {
    /// The descriptor to wait on.
    pub fd: curl_socket_t,
    /// Which events to wait for.
    pub events: c_short,
    /// Which events occurred.
    pub revents: c_short,
}

/// Metadata for one received WebSocket frame (websockets.h:31-37).
///
/// Five fields. Measured size 32, alignment 8, with `age` at 0, `flags` at 4,
/// `offset` at 8, `bytesleft` at 16 and `len` at 24.
///
/// `age` is the struct-version field and is deliberately first, exactly as
/// [`super::types::curl_version_info_data`]'s `age` is. Removing or reordering
/// it would break every consumer's `offsetof`, and its documented value is
/// zero.
///
/// # A deliberate asymmetry that must not be tidied away
///
/// `flags` is `int` **here** while the same conceptual value is
/// `unsigned int` as `curl_ws_send`'s last parameter (websockets.h:73). That
/// asymmetry is present in the authority and is part of the frozen signature
/// set, so it is reproduced rather than harmonised: widening this field would
/// change the struct's declared type where a consumer compares against a
/// signed value, and narrowing the parameter would change a prototype.
#[allow(non_camel_case_types)]
#[repr(C)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub struct curl_ws_frame {
    /// The struct's generation. Frozen with the authority's comment: "zero".
    pub age: c_int,
    /// The `CURLWS_*` bits describing this frame. `int`, not `unsigned int` --
    /// see the type's documentation.
    pub flags: c_int,
    /// The offset of this data into the frame.
    pub offset: curl_off_t,
    /// Number of pending bytes left of the payload.
    pub bytesleft: curl_off_t,
    /// Size of the current data chunk.
    pub len: usize,
}

// ---------------------------------------------------------------------------
// The canonical result a null handle produces, one per return-type family.
//
// The C implementation answers a null handle differently depending on what the
// function returns, and every one of these was read off the authority rather
// than chosen. They are constants here so that no symbol module invents its
// own fallback: sixteen files each picking "the obvious error" is how a family
// ends up with two different answers for the same mistake.
// ---------------------------------------------------------------------------

/// What a `CURLcode`-returning entry point answers for a null easy handle:
/// `CURLE_BAD_FUNCTION_ARGUMENT`, which is 43.
#[allow(dead_code)] // used as symbol families land; see the module docs
pub(crate) const BAD_EASY_HANDLE: CURLcode =
    CURLcode::CURLE_BAD_FUNCTION_ARGUMENT;

/// What a `CURLMcode`-returning entry point answers for a null multi handle:
/// `CURLM_BAD_HANDLE`, which is 1. The authority's own comment names the case
/// exactly -- "the passed-in handle is not a valid CURLM handle" (multi.h:63).
#[allow(dead_code)] // used as symbol families land; see the module docs
pub(crate) const BAD_MULTI_HANDLE: CURLMcode = CURLMcode::CURLM_BAD_HANDLE;

/// What a `CURLSHcode`-returning entry point answers for a null share handle:
/// `CURLSHE_INVALID`, which is 3.
#[allow(dead_code)] // used as symbol families land; see the module docs
pub(crate) const BAD_SHARE_HANDLE: CURLSHcode = CURLSHcode::CURLSHE_INVALID;

/// What a `CURLUcode`-returning entry point answers for a null URL handle:
/// `CURLUE_BAD_HANDLE`, which is 1.
#[allow(dead_code)] // used as symbol families land; see the module docs
pub(crate) const BAD_URL_HANDLE: CURLUcode = CURLUcode::CURLUE_BAD_HANDLE;

/// What a `CURLHcode`-returning entry point answers for a null argument:
/// `CURLHE_BAD_ARGUMENT`, which is 6.
///
/// The header API has no dedicated bad-handle code; `CURLHE_BAD_ARGUMENT` is
/// the one the authority defines for "a function argument was not okay"
/// (header.h:54), and a null handle is exactly that.
#[allow(dead_code)] // used as symbol families land; see the module docs
pub(crate) const BAD_HEADER_ARGUMENT: CURLHcode =
    CURLHcode::CURLHE_BAD_ARGUMENT;

/// What an `int`-returning entry point answers for a null handle.
///
/// The `int`-returning members of the export set signal failure with a
/// negative value rather than with a code from an enumeration, so there is one
/// sentinel rather than a family of them. A pointer-returning entry point
/// answers null and a `void`-returning one returns silently; neither needs a
/// constant, and both are exercised in the `behaviour` tests.
#[allow(dead_code)] // used as symbol families land; see the module docs
pub(crate) const BAD_HANDLE_INT: c_int = -1;

// The one property of that sentinel a caller relies on -- that it is negative,
// so a `< 0` test distinguishes failure from every success value -- settled by
// the compiler rather than by a test.
const _: () = assert!(BAD_HANDLE_INT < 0);

// ---------------------------------------------------------------------------
// RAII at the boundary.
// ---------------------------------------------------------------------------

/// Hand ownership of an engine object to C, yielding an opaque handle.
///
/// This is the "out" half of the boundary's ownership transfer:
/// `curl_easy_init`, `curl_multi_init`, `curl_share_init`, `curl_url`,
/// `curl_mime_init` and `curl_easy_duphandle` all end here. The allocation
/// outlives this call and is owned by the caller of the C function until it is
/// passed back to [`from_raw`] or [`drop_raw`].
///
/// # Why one generic function rather than six family-specific ones
///
/// The families differ in exactly one respect -- the pointee type their
/// pointer names, which is `c_void` for `CURL`, `CURLM` and `CURLSH` and a
/// distinct opaque type for `CURLU`, `curl_mime` and `curl_mimepart`. The body
/// is `Box::into_raw` followed by a cast in every case, so six copies would be
/// six identical bodies differing only in a type that the signature already
/// parameterises. `H` is that pointee type and `T` is the engine object; a
/// call site writes `let h: *mut CURLM = handle::into_raw(engine);` and
/// inference supplies both.
///
/// Nothing about the returned pointer is ABI-visible beyond its width: a
/// generational key or a slab index in the engine's own representation stays
/// on the engine's side of the boundary, because `CURL *` is `void *` and
/// cannot carry a second word.
#[allow(dead_code)] // used as symbol families land; see the module docs
pub(crate) fn into_raw<H, T>(value: T) -> *mut H {
    Box::into_raw(Box::new(value)).cast::<H>()
}

/// Take ownership back from C, yielding the engine object.
///
/// This is the "in" half, and the only place besides [`drop_raw`] that ever
/// calls `Box::from_raw`. A null pointer yields `None` rather than a panic,
/// because a null handle is a caller error that C reports through a return
/// value.
///
/// # Safety
///
/// `ptr` must be either null or a pointer that
///
/// * was produced by [`into_raw`] in this crate with the same `T`,
/// * has not already been passed to this function or to [`drop_raw`], and
/// * is not borrowed through [`borrow`] or [`borrow_mut`] for the duration of
///   this call.
///
/// Calling this twice on the same non-null pointer is a double free, and the
/// pointer must not be used afterwards.
#[allow(dead_code)] // used as symbol families land; see the module docs
pub(crate) unsafe fn from_raw<H, T>(ptr: *mut H) -> Option<Box<T>> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: the pointer is non-null by the check above, and the caller
    // guarantees it came from `into_raw` with this same `T` and has not been
    // reclaimed since. `into_raw` produced it by `Box::into_raw` on a
    // `Box<T>`, so reconstituting a `Box<T>` restores exactly the ownership
    // that was given away, which is `Box::from_raw`'s whole precondition.
    Some(unsafe { Box::from_raw(ptr.cast::<T>()) })
}

/// Release an engine object owned by C.
///
/// This is what a `void`-returning cleanup entry point calls:
/// `curl_easy_cleanup`, `curl_multi_cleanup`, `curl_share_cleanup`,
/// `curl_url_cleanup` and `curl_mime_free`. A null pointer returns silently,
/// which is the documented C behaviour rather than a convenience -- calling
/// `curl_easy_cleanup(NULL)` is a defined no-op, so answering it with a panic
/// or an abort would be a behaviour change.
///
/// # Safety
///
/// The same contract as [`from_raw`], of which this is the discarding form.
#[allow(dead_code)] // used as symbol families land; see the module docs
pub(crate) unsafe fn drop_raw<H, T>(ptr: *mut H) {
    // SAFETY: delegated wholesale to `from_raw`, whose contract this
    // function's own contract repeats: null is handled there, and a non-null
    // pointer is one `into_raw` produced and nobody has reclaimed. Dropping
    // the returned `Box` is what frees it.
    let owned = unsafe { from_raw::<H, T>(ptr) };
    drop(owned);
}

/// Borrow an engine object for the duration of one call, without taking
/// ownership.
///
/// This is the path every entry point other than init and cleanup uses, and it
/// must never be `from_raw`: reconstituting a `Box` here and letting it drop at
/// the end of the call would free a handle the caller still holds. A null
/// pointer yields `None` so the caller can answer with the family-correct
/// constant above.
///
/// # Safety
///
/// `ptr` must be either null or a pointer that
///
/// * was produced by [`into_raw`] in this crate with the same `T`,
/// * has not been passed to [`from_raw`] or [`drop_raw`], and
/// * is not simultaneously borrowed mutably through [`borrow_mut`].
///
/// The returned reference must not outlive the allocation. `'a` is unbounded,
/// so the caller is responsible for confining it to one entry point's body.
#[allow(dead_code)] // used as symbol families land; see the module docs
pub(crate) unsafe fn borrow<'a, H, T>(ptr: *mut H) -> Option<&'a T> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: non-null by the check above, and by contract the pointer
    // addresses a live, initialised `T` that `into_raw` allocated and that no
    // mutable borrow is aliasing for the duration of `'a`. No ownership is
    // taken, so the allocation is untouched when the reference dies.
    Some(unsafe { &*ptr.cast::<T>() })
}

/// Borrow an engine object mutably for the duration of one call, without
/// taking ownership.
///
/// The counterpart of [`borrow`] for the entry points that mutate a handle --
/// `curl_easy_setopt` and its siblings. A null pointer yields `None`.
///
/// # Safety
///
/// `ptr` must be either null or a pointer that
///
/// * was produced by [`into_raw`] in this crate with the same `T`,
/// * has not been passed to [`from_raw`] or [`drop_raw`], and
/// * is not borrowed at all -- shared or mutable -- anywhere else for the
///   duration of `'a`, since a `&mut T` must be unique.
///
/// The returned reference must not outlive the allocation.
#[allow(dead_code)] // used as symbol families land; see the module docs
pub(crate) unsafe fn borrow_mut<'a, H, T>(ptr: *mut H) -> Option<&'a mut T> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: non-null by the check above, and by contract the pointer
    // addresses a live, initialised `T` that `into_raw` allocated and that
    // nothing else borrows for the duration of `'a`, which is what makes the
    // exclusive reference sound. No ownership is taken.
    Some(unsafe { &mut *ptr.cast::<T>() })
}

// ---------------------------------------------------------------------------
// The one direction of `curl_slist` conversion that belongs here.
// ---------------------------------------------------------------------------

/// Walk a C string list into owned Rust byte strings.
///
/// `curl_slist` keeps its C shape only at the boundary; inside the engine a
/// list of strings is a `Vec`. This is that conversion, and it is the direction
/// nothing else in the crate provides: a symbol module that receives a
/// `struct curl_slist *` through `curl_easy_setopt` needs the contents as
/// owned data, because the caller may free the chain the moment the setter
/// returns.
///
/// The bytes are copied, NUL exclusive. A node whose `data` is null
/// contributes an empty entry rather than being skipped, so the returned
/// length always equals the chain's node count and an index into it matches
/// the caller's position in the chain.
///
/// # Why the opposite direction is not here
///
/// Building and freeing a C chain are `super::slist`'s `curl_slist_append` and
/// `curl_slist_free_all`, and they must stay there because they allocate
/// through [`super::memory`] -- libcurl's five replaceable allocator hooks. A
/// `Box`-based builder in this module would hand out nodes that a consumer's
/// `curl_slist_free_all` would then pass to `free`, mixing two allocators over
/// one allocation. That is not a style preference; it is the difference between
/// working and undefined.
///
/// # Safety
///
/// `list` must be either null or the head of a well-formed `curl_slist` chain
/// whose every `data` is either null or a NUL-terminated string, and whose
/// `next` chain terminates. The chain must not be mutated for the duration of
/// the call.
#[allow(dead_code)] // used as symbol families land; see the module docs
pub(crate) unsafe fn slist_to_vec(list: *const curl_slist) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut node = list;
    while !node.is_null() {
        // SAFETY: `node` is non-null by the loop condition and, by contract,
        // addresses a live node of a well-formed chain, so both fields are
        // initialised. The borrow ends within this iteration and nothing
        // mutates the chain meanwhile.
        let (data, next) = unsafe { ((*node).data, (*node).next) };
        if data.is_null() {
            out.push(Vec::new());
        } else {
            // SAFETY: by contract a non-null `data` addresses a
            // NUL-terminated string, which is `CStr::from_ptr`'s precondition.
            // `to_bytes` excludes the terminator and the bytes are copied
            // before the borrow ends.
            let bytes = unsafe { core::ffi::CStr::from_ptr(data) }.to_bytes();
            out.push(bytes.to_vec());
        }
        node = next;
    }
    out
}

/// How many nodes a C string list holds.
///
/// The companion of [`slist_to_vec`] for the callers that need only the count,
/// which is what `CURLINFO_CERTINFO` reports through
/// [`curl_certinfo::num_of_certs`]. Counting without copying keeps that path
/// allocation-free.
///
/// # Safety
///
/// The same contract as [`slist_to_vec`]: `list` must be null or the head of a
/// well-formed, terminating chain that is not mutated during the call.
#[allow(dead_code)] // used as symbol families land; see the module docs
pub(crate) unsafe fn slist_len(list: *const curl_slist) -> usize {
    let mut count = 0usize;
    let mut node = list;
    while !node.is_null() {
        // SAFETY: `node` is non-null by the loop condition and by contract
        // addresses a live node whose `next` is initialised.
        node = unsafe { (*node).next };
        count += 1;
    }
    count
}

/// The null pointer, spelled once, for the entry points whose answer to a null
/// handle is a null return.
///
/// A pointer-returning entry point has no error code to give, so it answers
/// null -- `curl_easy_init` on allocation failure, `curl_url_dup` on a null
/// input, `curl_slist_append` on either. Naming it alongside the five code
/// constants keeps the whole family table in one place rather than leaving one
/// row of it implicit.
#[allow(dead_code)] // used as symbol families land; see the module docs
pub(crate) fn bad_handle_ptr<H>() -> *mut H {
    ptr::null_mut()
}

#[cfg(test)]
mod layout {
    use super::*;
    use core::mem::{align_of, size_of, MaybeUninit};
    use core::ptr::addr_of;

    // The six declarations this module's inventory covers but does not declare
    // and does not re-export, named here so their layout is asserted alongside
    // the eleven that are declared above. `curl_easyoption` is deliberately
    // absent from both lists: it is the option-introspection table's row type
    // and belongs with the table, not with the handles.
    use super::super::codes::CURLversion;
    use super::super::types::{
        curl_hstsentry, curl_index, curl_pushheaders, curl_sockaddr,
        curl_ssl_backend, curl_version_info_data,
    };

    /// Byte offset of a field within a struct.
    ///
    /// `core::mem::offset_of!` is stable only from Rust 1.77 and the workspace
    /// MSRV is 1.75, so the offset is taken through `addr_of!`, stable since
    /// 1.51. It forms the address without creating a reference, so it is sound
    /// on uninitialised memory -- which is what lets a struct full of raw
    /// pointers be measured without inventing values for them. No crate is
    /// added for this: `memoffset` would be a new dependency, and the
    /// dependency set is fixed.
    macro_rules! offset {
        ($ty:ty, $($field:tt).+) => {{
            let holder = MaybeUninit::<$ty>::uninit();
            let base = holder.as_ptr();
            // SAFETY: `base` points at a whole, correctly aligned allocation
            // of `$ty` owned by `holder`. `addr_of!` only computes the field's
            // address and never reads the uninitialised bytes, so no invalid
            // value is ever materialised.
            let field = unsafe { addr_of!((*base).$($field).+) };
            (field as usize) - (base as usize)
        }};
    }

    /// Assert one type's size and alignment against the measurement.
    macro_rules! shape {
        ($ty:ty, $size:expr, $align:expr) => {{
            assert_eq!(size_of::<$ty>(), $size, "size of {}", stringify!($ty));
            assert_eq!(
                align_of::<$ty>(),
                $align,
                "alignment of {}",
                stringify!($ty)
            );
        }};
    }

    // Every number below was MEASURED, not predicted: a C program including
    // the frozen headers printed `sizeof`, `_Alignof` and `offsetof` for all
    // seventeen structs, and the resulting 164 assertions were then compiled
    // as `_Static_assert`s by both `gcc` and `aarch64-linux-gnu-gcc` under
    // `-Wall -Werror`. Both accepted them, so the two Linux targets agree.
    // The two Darwin targets cannot be measured in this environment; the only
    // platform-variant member anywhere in the set is `struct sockaddr`, which
    // is reached through `libc::sockaddr` and is therefore per-target correct
    // by construction rather than by transcription.

    #[test]
    fn curl_httppost_matches_the_measured_c_layout() {
        shape!(curl_httppost, 112, 8);
        assert_eq!(offset!(curl_httppost, next), 0);
        assert_eq!(offset!(curl_httppost, name), 8);
        assert_eq!(offset!(curl_httppost, namelength), 16);
        assert_eq!(offset!(curl_httppost, contents), 24);
        assert_eq!(offset!(curl_httppost, contentslength), 32);
        assert_eq!(offset!(curl_httppost, buffer), 40);
        assert_eq!(offset!(curl_httppost, bufferlength), 48);
        assert_eq!(offset!(curl_httppost, contenttype), 56);
        assert_eq!(offset!(curl_httppost, contentheader), 64);
        assert_eq!(offset!(curl_httppost, more), 72);
        assert_eq!(offset!(curl_httppost, flags), 80);
        assert_eq!(offset!(curl_httppost, showfilename), 88);
        assert_eq!(offset!(curl_httppost, userp), 96);
        assert_eq!(offset!(curl_httppost, contentlen), 104);
    }

    #[test]
    fn the_httppost_flag_bits_match_the_authority() {
        // Declared `c_long` because `flags` is a `long`. Asserting the type as
        // well as the value is the point: a `c_int` constant would compare
        // equal here and still be the wrong width at the use site.
        let bits: [(c_long, c_long); 8] = [
            (CURL_HTTPPOST_FILENAME, 1),
            (CURL_HTTPPOST_READFILE, 2),
            (CURL_HTTPPOST_PTRNAME, 4),
            (CURL_HTTPPOST_PTRCONTENTS, 8),
            (CURL_HTTPPOST_BUFFER, 16),
            (CURL_HTTPPOST_PTRBUFFER, 32),
            (CURL_HTTPPOST_CALLBACK, 64),
            (CURL_HTTPPOST_LARGE, 128),
        ];
        for (got, want) in bits {
            assert_eq!(got, want);
        }
    }

    #[test]
    fn curl_fileinfo_matches_the_measured_c_layout() {
        shape!(curl_fileinfo, 128, 8);
        assert_eq!(offset!(curl_fileinfo, filename), 0);
        assert_eq!(offset!(curl_fileinfo, filetype), 8);
        assert_eq!(offset!(curl_fileinfo, time), 16);
        assert_eq!(offset!(curl_fileinfo, perm), 24);
        assert_eq!(offset!(curl_fileinfo, uid), 28);
        assert_eq!(offset!(curl_fileinfo, gid), 32);
        assert_eq!(offset!(curl_fileinfo, size), 40);
        assert_eq!(offset!(curl_fileinfo, hardlinks), 48);
        assert_eq!(offset!(curl_fileinfo, strings), 56);
        assert_eq!(offset!(curl_fileinfo, flags), 96);
        assert_eq!(offset!(curl_fileinfo, b_data), 104);
        assert_eq!(offset!(curl_fileinfo, b_size), 112);
        assert_eq!(offset!(curl_fileinfo, b_used), 120);
    }

    #[test]
    fn the_nested_strings_struct_lies_where_the_anonymous_one_does() {
        // Naming the anonymous member changes no offset, and this is the
        // assertion that proves it: the five pointers are measured through the
        // OUTER type, so they are compared against the offsets a C consumer
        // reaches by writing `finfo->strings.time`.
        shape!(curl_fileinfo_strings, 40, 8);
        assert_eq!(offset!(curl_fileinfo, strings.time), 56);
        assert_eq!(offset!(curl_fileinfo, strings.perm), 64);
        assert_eq!(offset!(curl_fileinfo, strings.user), 72);
        assert_eq!(offset!(curl_fileinfo, strings.group), 80);
        assert_eq!(offset!(curl_fileinfo, strings.target), 88);
    }

    #[test]
    fn the_fileinfo_known_bits_match_the_authority() {
        let bits: [(c_uint, c_uint); 8] = [
            (CURLFINFOFLAG_KNOWN_FILENAME, 1),
            (CURLFINFOFLAG_KNOWN_FILETYPE, 2),
            (CURLFINFOFLAG_KNOWN_TIME, 4),
            (CURLFINFOFLAG_KNOWN_PERM, 8),
            (CURLFINFOFLAG_KNOWN_UID, 16),
            (CURLFINFOFLAG_KNOWN_GID, 32),
            (CURLFINFOFLAG_KNOWN_SIZE, 64),
            (CURLFINFOFLAG_KNOWN_HLINKCOUNT, 128),
        ];
        for (got, want) in bits {
            assert_eq!(got, want);
        }
    }

    #[test]
    fn curl_sockaddr_matches_the_measured_c_layout() {
        // Alignment 4, not 8: the four leading `int`s set it and
        // `struct sockaddr` is only two-byte aligned, so nothing raises it.
        shape!(curl_sockaddr, 32, 4);
        assert_eq!(offset!(curl_sockaddr, family), 0);
        assert_eq!(offset!(curl_sockaddr, socktype), 4);
        assert_eq!(offset!(curl_sockaddr, protocol), 8);
        assert_eq!(offset!(curl_sockaddr, addrlen), 12);
        assert_eq!(offset!(curl_sockaddr, addr), 16);
        // The trailing member is a real `struct sockaddr` BY VALUE, which is
        // what makes the outer size 32 rather than 24.
        assert_eq!(size_of::<libc::sockaddr>(), 16);
    }

    #[test]
    fn curl_khkey_matches_the_measured_c_layout() {
        shape!(curl_khkey, 24, 8);
        assert_eq!(offset!(curl_khkey, key), 0);
        assert_eq!(offset!(curl_khkey, len), 8);
        assert_eq!(offset!(curl_khkey, keytype), 16);
        // `enum curl_khtype` is a C enum, four bytes, so the eight trailing
        // bytes of the struct are half padding.
        assert_eq!(size_of::<curl_khtype>(), 4);
    }

    #[test]
    fn curl_hstsentry_matches_the_measured_c_layout() {
        // The ABI's only bit-field and its only fixed-size array, both in this
        // one struct. Rust cannot express `unsigned int includeSubDomains:1;`,
        // so `super::super::types` represents it as a single byte -- which is
        // exactly what gcc allocates for it, measured: the bit-field occupies
        // byte 16 and `expire` follows at 17, an ODD offset that only the
        // one-byte representation reproduces. The Rust form is a layout stand-
        // in, not a semantic mirror; read the flag through
        // `include_subdomains()` rather than testing the byte.
        shape!(curl_hstsentry, 40, 8);
        assert_eq!(offset!(curl_hstsentry, name), 0);
        assert_eq!(offset!(curl_hstsentry, namelen), 8);
        assert_eq!(offset!(curl_hstsentry, include_subdomains_bits), 16);
        assert_eq!(offset!(curl_hstsentry, expire), 17);
        assert_eq!(size_of::<[c_char; 18]>(), 18, "expire is 18 bytes");
    }

    #[test]
    fn curl_index_matches_the_measured_c_layout() {
        shape!(curl_index, 16, 8);
        assert_eq!(offset!(curl_index, index), 0);
        assert_eq!(offset!(curl_index, total), 8);
    }

    #[test]
    fn curl_forms_matches_the_measured_c_layout() {
        shape!(curl_forms, 16, 8);
        assert_eq!(offset!(curl_forms, option), 0);
        assert_eq!(offset!(curl_forms, value), 8);
        assert_eq!(size_of::<CURLformoption>(), 4);
    }

    #[test]
    fn curl_slist_matches_the_measured_c_layout() {
        shape!(curl_slist, 16, 8);
        assert_eq!(offset!(curl_slist, data), 0);
        assert_eq!(offset!(curl_slist, next), 8);
    }

    #[test]
    fn curl_ssl_backend_keeps_id_first() {
        // `lib/vtls/vtls_int.h:142-145` states the reason in-source: the
        // ordering exists "to allow returning the list of available backends
        // in curl_global_sslset()", because `struct Curl_ssl` embeds this type
        // as its own first member and the two are read through one pointer.
        shape!(curl_ssl_backend, 16, 8);
        assert_eq!(offset!(curl_ssl_backend, id), 0, "id MUST be first");
        assert_eq!(offset!(curl_ssl_backend, name), 8);
    }

    #[test]
    fn curl_certinfo_matches_the_measured_c_layout() {
        shape!(curl_certinfo, 16, 8);
        assert_eq!(offset!(curl_certinfo, num_of_certs), 0);
        assert_eq!(offset!(curl_certinfo, certinfo), 8);
    }

    #[test]
    fn curl_tlssessioninfo_matches_the_measured_c_layout() {
        shape!(curl_tlssessioninfo, 16, 8);
        assert_eq!(offset!(curl_tlssessioninfo, backend), 0);
        assert_eq!(offset!(curl_tlssessioninfo, internals), 8);
        assert_eq!(size_of::<curl_sslbackend>(), 4);
    }

    #[test]
    fn curl_version_info_data_matches_the_measured_c_layout() {
        // Twenty-seven fields grown across twelve CURLVERSION_* generations,
        // never reordered and never removed, which is precisely why `age`
        // exists and is first: a consumer compiled against an older header
        // stops reading early. Asserting every offset is what makes an
        // accidental reordering a test failure rather than a silent ABI break.
        shape!(curl_version_info_data, 216, 8);
        assert_eq!(
            offset!(curl_version_info_data, age),
            0,
            "age MUST be first"
        );
        assert_eq!(offset!(curl_version_info_data, version), 8);
        assert_eq!(offset!(curl_version_info_data, version_num), 16);
        assert_eq!(offset!(curl_version_info_data, host), 24);
        assert_eq!(offset!(curl_version_info_data, features), 32);
        assert_eq!(offset!(curl_version_info_data, ssl_version), 40);
        assert_eq!(offset!(curl_version_info_data, ssl_version_num), 48);
        assert_eq!(offset!(curl_version_info_data, libz_version), 56);
        assert_eq!(offset!(curl_version_info_data, protocols), 64);
        assert_eq!(offset!(curl_version_info_data, ares), 72);
        assert_eq!(offset!(curl_version_info_data, ares_num), 80);
        assert_eq!(offset!(curl_version_info_data, libidn), 88);
        assert_eq!(offset!(curl_version_info_data, iconv_ver_num), 96);
        assert_eq!(offset!(curl_version_info_data, libssh_version), 104);
        assert_eq!(offset!(curl_version_info_data, brotli_ver_num), 112);
        assert_eq!(offset!(curl_version_info_data, brotli_version), 120);
        assert_eq!(offset!(curl_version_info_data, nghttp2_ver_num), 128);
        assert_eq!(offset!(curl_version_info_data, nghttp2_version), 136);
        assert_eq!(offset!(curl_version_info_data, quic_version), 144);
        assert_eq!(offset!(curl_version_info_data, cainfo), 152);
        assert_eq!(offset!(curl_version_info_data, capath), 160);
        assert_eq!(offset!(curl_version_info_data, zstd_ver_num), 168);
        assert_eq!(offset!(curl_version_info_data, zstd_version), 176);
        assert_eq!(offset!(curl_version_info_data, hyper_version), 184);
        assert_eq!(offset!(curl_version_info_data, gsasl_version), 192);
        assert_eq!(offset!(curl_version_info_data, feature_names), 200);
        assert_eq!(offset!(curl_version_info_data, rtmp_version), 208);
        // The two double-const members, `const char * const *`, are pointers
        // to pointers on the Rust side too; the second `const` is a property
        // of the emitted C text rather than of the layout, and `build.rs`
        // carries the declaration verbatim so it survives.
        assert_eq!(
            size_of::<*const *const c_char>(),
            size_of::<*const c_char>()
        );
        assert_eq!(size_of::<CURLversion>(), 4);
    }

    #[test]
    fn curl_blob_matches_the_measured_c_layout() {
        shape!(curl_blob, 24, 8);
        assert_eq!(offset!(curl_blob, data), 0);
        assert_eq!(offset!(curl_blob, len), 8);
        assert_eq!(offset!(curl_blob, flags), 16);
        assert_eq!(CURL_BLOB_COPY, 1);
        assert_eq!(CURL_BLOB_NOCOPY, 0);
    }

    #[test]
    fn curl_header_matches_the_measured_c_layout() {
        shape!(curl_header, 48, 8);
        assert_eq!(offset!(curl_header, name), 0);
        assert_eq!(offset!(curl_header, value), 8);
        assert_eq!(offset!(curl_header, amount), 16);
        assert_eq!(offset!(curl_header, index), 24);
        assert_eq!(offset!(curl_header, origin), 32);
        // Private to libcurl, last, and still occupying its slot: the size
        // above is 48 rather than 40 only because it is present.
        assert_eq!(offset!(curl_header, anchor), 40);
    }

    #[test]
    fn curlmsg_matches_the_measured_c_layout() {
        shape!(CURLMsg, 24, 8);
        assert_eq!(offset!(CURLMsg, msg), 0);
        assert_eq!(offset!(CURLMsg, easy_handle), 8);
        assert_eq!(offset!(CURLMsg, data), 16);
        // Both arms of the union start where the union does, which is what
        // makes `msg->data.result` and `msg->data.whatever` the same address.
        assert_eq!(offset!(CURLMsg, data.whatever), 16);
        assert_eq!(offset!(CURLMsg, data.result), 16);
    }

    #[test]
    fn curlmsg_field_widths_match_the_frozen_types() {
        assert_eq!(size_of::<CURLMSG>(), 4, "CURLMSG width");
        assert_eq!(align_of::<CURLMSG>(), 4, "CURLMSG alignment");
        assert_eq!(size_of::<CURLcode>(), 4, "CURLcode width");
        assert_eq!(size_of::<*mut CURL>(), 8, "CURL * width");
        shape!(CURLMsg_data, 8, 8);
        // The union is at least as wide as its widest member, which is the
        // pointer rather than the four-byte code.
        assert!(
            size_of::<CURLMsg_data>()
                >= core::cmp::max(
                    size_of::<*mut c_void>(),
                    size_of::<CURLcode>()
                )
        );
    }

    #[test]
    fn curl_waitfd_matches_the_measured_c_layout() {
        // Size 8 and alignment 4 are the whole point: `short` fields put
        // `revents` at 6, whereas `int` fields would put it at 8 and make the
        // struct 12 bytes, silently changing the stride of every array
        // `curl_multi_wait` and `curl_multi_poll` index.
        shape!(curl_waitfd, 8, 4);
        assert_eq!(offset!(curl_waitfd, fd), 0);
        assert_eq!(offset!(curl_waitfd, events), 4);
        assert_eq!(offset!(curl_waitfd, revents), 6);
        assert_eq!(size_of::<c_short>(), 2, "events and revents are short");
    }

    #[test]
    fn curl_ws_frame_matches_the_measured_c_layout() {
        shape!(curl_ws_frame, 32, 8);
        assert_eq!(offset!(curl_ws_frame, age), 0, "age MUST be first");
        assert_eq!(offset!(curl_ws_frame, flags), 4);
        assert_eq!(offset!(curl_ws_frame, offset), 8);
        assert_eq!(offset!(curl_ws_frame, bytesleft), 16);
        assert_eq!(offset!(curl_ws_frame, len), 24);
    }

    #[test]
    fn the_ws_frame_flags_asymmetry_is_preserved_not_harmonised() {
        // `flags` is `int` in the struct (websockets.h:33) and
        // `unsigned int` as `curl_ws_send`'s parameter (websockets.h:73). The
        // asymmetry is the authority's, so the field's type must be the SIGNED
        // one; a signed field can hold -1 and an unsigned one cannot, which is
        // the observable difference and therefore the check.
        let frame = curl_ws_frame {
            age: 0,
            flags: -1,
            offset: 0,
            bytesleft: 0,
            len: 0,
        };
        assert_eq!(frame.flags, -1, "the field must be signed");
        assert_eq!(size_of::<c_int>(), size_of::<c_uint>());
    }

    #[test]
    fn the_void_handles_are_void_and_not_opaque_structs() {
        // The frozen headers declare all three as `typedef void`, so each
        // alias must be zero-sized `c_void` rather than a sized placeholder.
        // A pointer to any of them is therefore interchangeable with `void *`,
        // which is what the example corpus relies on.
        assert_eq!(size_of::<*mut CURL>(), size_of::<*mut c_void>());
        assert_eq!(size_of::<*mut CURLM>(), size_of::<*mut c_void>());
        assert_eq!(size_of::<*mut CURLSH>(), size_of::<*mut c_void>());
    }

    #[test]
    fn the_opaque_handles_carry_no_layout_of_their_own() {
        // `struct Curl_URL`, `struct curl_mime`, `struct curl_mimepart` and
        // `struct curl_pushheaders` are never defined by the authority, so
        // none may invent a layout. Zero-sized is the faithful reproduction of
        // an incomplete type.
        assert_eq!(size_of::<Curl_URL>(), 0, "Curl_URL must be zero-sized");
        assert_eq!(size_of::<CURLU>(), size_of::<Curl_URL>());
        assert_eq!(size_of::<curl_mime>(), 0, "curl_mime must be zero-sized");
        assert_eq!(size_of::<curl_mimepart>(), 0);
        assert_eq!(size_of::<curl_pushheaders>(), 0);
        // And a pointer to an incomplete type is still one machine word, which
        // is all a consumer ever holds.
        assert_eq!(size_of::<*mut CURLU>(), size_of::<*mut c_void>());
        assert_eq!(size_of::<*mut curl_mime>(), size_of::<*mut c_void>());
    }

    #[test]
    fn the_scalar_typedefs_agree_with_system_h() {
        // `system.h` is shipped as-is rather than generated, so these aliases
        // have to agree with what it computes on each mandated target. All
        // four are 64-bit, where `CURL_TYPEOF_CURL_OFF_T` is a 64-bit signed
        // integer; 32-bit portability is deliberately forfeited and is not
        // claimed here or anywhere else.
        // Width and signedness are settled at compile time beside the
        // declaration itself, so what is left to check here is the rest of the
        // set.
        assert_eq!(size_of::<curl_off_t>(), 8, "curl_off_t MUST be 64-bit");
        assert_eq!(size_of::<curl_socket_t>(), 4);
        assert_eq!(size_of::<curl_socklen_t>(), 4);
        assert_eq!(CURL_SOCKET_BAD, -1);
        // `curl_fileinfo.time` is a `time_t`, which is the one field in the
        // set whose width comes from the platform rather than from curl.
        assert_eq!(size_of::<libc::time_t>(), 8);
    }
}

#[cfg(test)]
mod behaviour {
    use super::*;
    use std::ffi::CString;
    use std::rc::Rc;

    /// A stand-in for an engine object.
    ///
    /// The RAII helpers are generic precisely because they know nothing about
    /// the payload, so a local type exercises them exactly as `curl-rs-lib`'s
    /// easy handle will. `Rc` is the load-bearing part: a clone kept outside
    /// the boundary lets the test observe whether the allocation was dropped,
    /// which is the property under test and is otherwise invisible.
    struct Engine {
        label: String,
        alive: Rc<()>,
    }

    impl Engine {
        /// How many witnesses still observe this object.
        ///
        /// The test's proxy for "has the allocation been released": a borrow
        /// must leave the count alone and a cleanup must drop it to one. Asking
        /// the object itself, rather than the outer clone, also proves the
        /// reference really addresses the object that was handed over.
        fn witnesses(&self) -> usize {
            Rc::strong_count(&self.alive)
        }
    }

    fn engine(label: &str) -> (Engine, Rc<()>) {
        let alive = Rc::new(());
        let witness = Rc::clone(&alive);
        (
            Engine {
                label: label.to_owned(),
                alive,
            },
            witness,
        )
    }

    #[test]
    fn into_raw_then_from_raw_returns_the_same_object() {
        let (value, witness) = engine("easy");
        let handle: *mut CURL = into_raw(value);
        assert!(!handle.is_null(), "a handle must never be null on success");
        assert_eq!(Rc::strong_count(&witness), 2, "the object is still alive");

        // SAFETY: `handle` came from `into_raw` with this same payload type on
        // the line above, has not been reclaimed, and is not borrowed.
        let owned = unsafe { from_raw::<CURL, Engine>(handle) }
            .expect("a non-null handle must yield its object");
        assert_eq!(
            owned.label, "easy",
            "the object must survive the round trip"
        );

        drop(owned);
        assert_eq!(Rc::strong_count(&witness), 1, "and then be released");
    }

    #[test]
    fn drop_raw_releases_the_object() {
        let (value, witness) = engine("multi");
        let handle: *mut CURLM = into_raw(value);
        assert_eq!(Rc::strong_count(&witness), 2);

        // SAFETY: `handle` came from `into_raw` with this payload type, has not
        // been reclaimed, and is not borrowed.
        unsafe { drop_raw::<CURLM, Engine>(handle) };
        assert_eq!(Rc::strong_count(&witness), 1, "cleanup must free it");
    }

    #[test]
    fn a_borrow_does_not_take_ownership() {
        let (value, witness) = engine("share");
        let handle: *mut CURLSH = into_raw(value);

        for _ in 0..3 {
            // SAFETY: `handle` is live, came from `into_raw` with this payload
            // type, and no mutable borrow exists. The reference dies at the end
            // of the iteration.
            let seen = unsafe { borrow::<CURLSH, Engine>(handle) }
                .expect("a non-null handle must borrow");
            assert_eq!(seen.label, "share");
            // Borrowing repeatedly must not free anything: the whole point of
            // the borrow path is that it never calls `from_raw`.
            assert_eq!(seen.witnesses(), 2, "asked through the borrow itself");
            assert_eq!(Rc::strong_count(&witness), 2);
        }

        // SAFETY: as above; this is the one call that reclaims.
        unsafe { drop_raw::<CURLSH, Engine>(handle) };
        assert_eq!(Rc::strong_count(&witness), 1);
    }

    #[test]
    fn a_mutable_borrow_writes_through_to_the_owned_object() {
        let (value, _witness) = engine("url");
        let handle: *mut CURLU = into_raw(value);

        // SAFETY: `handle` is live, came from `into_raw` with this payload
        // type, and nothing else borrows it for the duration.
        let seen = unsafe { borrow_mut::<CURLU, Engine>(handle) }
            .expect("a non-null handle must borrow mutably");
        seen.label.push_str("-mutated");

        // SAFETY: the mutable borrow above has ended, so a shared one is sound.
        let after = unsafe { borrow::<CURLU, Engine>(handle) }
            .expect("still borrowable");
        assert_eq!(after.label, "url-mutated");

        // SAFETY: no borrow is outstanding; this reclaims.
        unsafe { drop_raw::<CURLU, Engine>(handle) };
    }

    #[test]
    fn the_opaque_families_use_the_same_mechanism() {
        // `curl_mime` and `curl_mimepart` are distinct pointee types, so this
        // is the check that one generic mechanism really does serve every
        // family rather than only the three `void` ones.
        let (value, witness) = engine("mime");
        let handle: *mut curl_mime = into_raw(value);
        // SAFETY: produced by `into_raw` with this payload type; live and
        // unborrowed.
        let seen = unsafe { borrow::<curl_mime, Engine>(handle) }
            .expect("a mime handle borrows like any other");
        assert_eq!(seen.label, "mime");
        // SAFETY: the borrow above has ended; this reclaims.
        unsafe { drop_raw::<curl_mime, Engine>(handle) };
        assert_eq!(Rc::strong_count(&witness), 1);

        let (part, part_witness) = engine("part");
        let handle: *mut curl_mimepart = into_raw(part);
        // SAFETY: produced by `into_raw` with this payload type; live and
        // unborrowed.
        unsafe { drop_raw::<curl_mimepart, Engine>(handle) };
        assert_eq!(Rc::strong_count(&part_witness), 1);
    }

    #[test]
    fn a_null_handle_yields_none_from_every_borrow_and_never_panics() {
        // The requirement is precise: a null pointer must produce the
        // family-correct error, NOT a panic and NOT an unchecked dereference.
        // `None` is what lets the caller supply that error, and reaching these
        // assertions at all is the proof that nothing panicked.
        // SAFETY: a null pointer is explicitly permitted by each contract, and
        // each function checks for it before doing anything else.
        unsafe {
            assert!(borrow::<CURL, Engine>(ptr::null_mut()).is_none());
            assert!(borrow_mut::<CURL, Engine>(ptr::null_mut()).is_none());
            assert!(from_raw::<CURL, Engine>(ptr::null_mut()).is_none());
            assert!(borrow::<CURLM, Engine>(ptr::null_mut()).is_none());
            assert!(borrow::<CURLSH, Engine>(ptr::null_mut()).is_none());
            assert!(borrow::<CURLU, Engine>(ptr::null_mut()).is_none());
            assert!(borrow::<curl_mime, Engine>(ptr::null_mut()).is_none());
            assert!(borrow::<curl_mimepart, Engine>(ptr::null_mut()).is_none());
        }
    }

    #[test]
    fn a_null_cleanup_is_a_silent_no_op_and_repeating_it_stays_silent() {
        // `curl_easy_cleanup(NULL)` is a documented no-op in C, so answering a
        // null with a panic or an abort would be a behaviour change. Calling it
        // twice is the double-free shape a real consumer produces, and on null
        // it must remain harmless.
        // SAFETY: null is explicitly permitted, and `drop_raw` checks for it
        // through `from_raw` before touching anything.
        unsafe {
            drop_raw::<CURL, Engine>(ptr::null_mut());
            drop_raw::<CURL, Engine>(ptr::null_mut());
            drop_raw::<CURLM, Engine>(ptr::null_mut());
            drop_raw::<CURLSH, Engine>(ptr::null_mut());
            drop_raw::<CURLU, Engine>(ptr::null_mut());
            drop_raw::<curl_mime, Engine>(ptr::null_mut());
        }
    }

    #[test]
    fn the_family_correct_errors_are_the_measured_integers() {
        // A consumer compiled against curl 8.19.0-DEV holds the NUMBER, not the
        // name, so the numbers are what get asserted. Each was read off the
        // authority: curl.h's CURLcode, multi.h:63, curl.h's CURLSHcode,
        // urlapi.h's CURLUcode and header.h:54.
        assert_eq!(BAD_EASY_HANDLE as i32, 43);
        assert_eq!(BAD_MULTI_HANDLE as i32, 1);
        assert_eq!(BAD_SHARE_HANDLE as i32, 3);
        assert_eq!(BAD_URL_HANDLE as i32, 1);
        assert_eq!(BAD_HEADER_ARGUMENT as i32, 6);
        assert_eq!(BAD_HANDLE_INT, -1);
        assert!(bad_handle_ptr::<CURL>().is_null());
        assert!(bad_handle_ptr::<curl_httppost>().is_null());
    }

    /// Build a chain the way a consumer does, from storage the test owns.
    ///
    /// Deliberately NOT through `curl_slist_append`: that allocates from
    /// libcurl's replaceable hooks, and the point here is that
    /// [`slist_to_vec`] reads any well-formed chain regardless of who
    /// allocated it. The `CString`s and nodes are kept alive by the caller.
    fn chain(nodes: &mut [curl_slist], owners: &[CString]) {
        for index in 0..nodes.len() {
            nodes[index].data = owners[index].as_ptr().cast_mut();
            nodes[index].next = ptr::null_mut();
        }
        for index in (1..nodes.len()).rev() {
            let tail: *mut curl_slist = &mut nodes[index];
            nodes[index - 1].next = tail;
        }
    }

    #[test]
    fn slist_to_vec_walks_a_chain_into_owned_bytes() {
        let owners = [
            CString::new("Accept: */*").expect("no interior NUL"),
            CString::new("X-Second: 2").expect("no interior NUL"),
            CString::new("X-Third: 3").expect("no interior NUL"),
        ];
        let mut nodes = [
            curl_slist {
                data: ptr::null_mut(),
                next: ptr::null_mut(),
            },
            curl_slist {
                data: ptr::null_mut(),
                next: ptr::null_mut(),
            },
            curl_slist {
                data: ptr::null_mut(),
                next: ptr::null_mut(),
            },
        ];
        chain(&mut nodes, &owners);
        let head: *const curl_slist = &nodes[0];

        // SAFETY: `head` addresses a well-formed chain built above whose three
        // `data` pointers address NUL-terminated strings that outlive the call,
        // and nothing mutates it meanwhile.
        let seen = unsafe { slist_to_vec(head) };
        assert_eq!(
            seen,
            vec![
                b"Accept: */*".to_vec(),
                b"X-Second: 2".to_vec(),
                b"X-Third: 3".to_vec(),
            ],
            "order must be preserved and the NUL excluded"
        );
        // SAFETY: same chain, same contract.
        assert_eq!(unsafe { slist_len(head) }, 3);
    }

    #[test]
    fn slist_helpers_accept_a_null_chain_and_a_null_entry() {
        // SAFETY: null is explicitly permitted by both contracts.
        unsafe {
            assert!(slist_to_vec(ptr::null()).is_empty());
            assert_eq!(slist_len(ptr::null()), 0);
        }

        // A node whose `data` is null contributes an EMPTY entry rather than
        // being skipped, so the returned length keeps matching the node count
        // and an index into it still matches a position in the chain.
        let mut second = curl_slist {
            data: ptr::null_mut(),
            next: ptr::null_mut(),
        };
        let kept = CString::new("second").expect("no interior NUL");
        second.data = kept.as_ptr().cast_mut();
        let first = curl_slist {
            data: ptr::null_mut(),
            next: &mut second,
        };
        let head: *const curl_slist = &first;

        // SAFETY: `head` addresses a two-node chain whose first `data` is null
        // -- which the contract permits -- and whose second addresses a
        // NUL-terminated string that outlives the call.
        let seen = unsafe { slist_to_vec(head) };
        assert_eq!(seen, vec![Vec::new(), b"second".to_vec()]);
        // SAFETY: same chain, same contract.
        assert_eq!(unsafe { slist_len(head) }, 2);
    }

    #[test]
    fn the_message_union_reads_back_what_was_written() {
        let msg = CURLMsg {
            msg: CURLMSG::CURLMSG_DONE,
            easy_handle: ptr::null_mut(),
            data: CURLMsg_data {
                result: CURLcode::CURLE_COULDNT_CONNECT,
            },
        };
        assert_eq!(msg.msg, CURLMSG::CURLMSG_DONE);
        // SAFETY: `data` was initialised through the `result` arm on the line
        // above and has not been written since, so reading that same arm
        // observes a valid `CURLcode`.
        let got = unsafe { msg.data.result };
        assert_eq!(got, CURLcode::CURLE_COULDNT_CONNECT);

        // And the other arm, because both member names are ABI-visible:
        // `docs/examples/multi-*.c` read `data.result`, while a pushed-header
        // consumer reads `data.whatever`.
        let carried = CURLMsg {
            msg: CURLMSG::CURLMSG_NONE,
            easy_handle: ptr::null_mut(),
            data: CURLMsg_data {
                whatever: ptr::null_mut(),
            },
        };
        // SAFETY: `data` was initialised through the `whatever` arm and not
        // written since, so reading that arm observes the pointer just stored.
        assert!(unsafe { carried.data.whatever }.is_null());
    }
}
