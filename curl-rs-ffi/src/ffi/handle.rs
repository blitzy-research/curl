// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
// SPDX-License-Identifier: curl
//
// Derived from include/curl/curl.h, include/curl/multi.h and
// include/curl/urlapi.h of curl 8.19.0-DEV at commit 54cf587b9c.

//! The public handle types, in their C ABI shape.
//!
//! Four handles and one layout-visible message struct reach C consumers. They
//! are **not uniform**, and treating them uniformly breaks consumers, so each
//! is reproduced here in the exact shape the frozen headers declare:
//!
//! | Frozen declaration | Location | Rust form here |
//! |---|---|---|
//! | `typedef void CURL;` | curl.h:109 | `pub type CURL = c_void` |
//! | `typedef void CURLSH;` | curl.h:110 | `pub type CURLSH = c_void` |
//! | `typedef void CURLM;` | multi.h:57 | `pub type CURLM = c_void` |
//! | `typedef struct Curl_URL CURLU;` | urlapi.h:107 | opaque struct |
//! | `typedef struct CURLMsg CURLMsg;` | multi.h:105 | `#[repr(C)]` struct |
//!
//! The first three are `void`, **not** opaque structs. cbindgen's natural
//! output for an opaque Rust type is `typedef struct X X;`, which diverges
//! from all three and changes the type of every handle-passing call: a
//! consumer that assigns a `CURL *` to a `void *` -- a widespread idiom,
//! present throughout `docs/examples/` -- would begin emitting diagnostics.
//! Every name in this module is therefore listed under `[export] exclude` in
//! `cbindgen.toml`, and the C declarations are spliced verbatim by
//! `curl-rs-ffi/build.rs` instead. The Rust declarations here exist so that
//! the rest of the FFI tree has real types to name; they are never the source
//! of the emitted C.
//!
//! `CURLMsg` is the exception that must be exact in Rust as well, because it
//! is **layout-visible**: consumers read `msg`, `easy_handle` and
//! `data.result` directly out of a struct this library writes. AAP section
//! 0.6.3 requires its layout to be asserted by test, and the constants those
//! tests check were measured with the C compiler against the frozen headers
//! rather than predicted -- see the `layout` test module.

use core::ffi::c_void;

use super::codes::CURLcode;
use super::types::CURLMSG;

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

/// The message payload union of [`CURLMsg`].
///
/// The frozen declaration nests an *anonymous* union in the struct. Rust has
/// no anonymous unions, so it is named here; the name never reaches C, because
/// both this type and `CURLMsg` are listed under `[export] exclude` and the C
/// struct is spliced verbatim. Naming it changes no offset: an anonymous union
/// and a named one of identical members have identical size and alignment.
#[allow(non_camel_case_types)]
#[repr(C)]
#[allow(dead_code)] // ABI declaration: read by cbindgen, not by Rust callers
pub union CURLMsg_data {
    /// Message-specific data. Frozen as `void *whatever;`.
    pub whatever: *mut c_void,
    /// The transfer's result code. Frozen as `CURLcode result;`.
    pub result: CURLcode,
}

/// A completed-transfer message, as returned by `curl_multi_info_read`.
///
/// Layout-visible: consumers read every field directly. Measured against the
/// frozen headers with gcc on `x86_64-unknown-linux-gnu`: size 24, alignment
/// 8, with `msg` at 0, `easy_handle` at 8 and `data` at 16. The `layout`
/// tests assert exactly those numbers.
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

#[cfg(test)]
mod layout {
    use super::*;
    use core::mem::{align_of, size_of, MaybeUninit};
    use core::ptr::addr_of;

    /// Byte offset of a field within `CURLMsg`.
    ///
    /// `core::mem::offset_of!` is stable only from Rust 1.77 and the workspace
    /// MSRV is 1.75 (AAP section 0.8.3), so the offset is taken through
    /// `addr_of!`, stable since 1.51. It forms the address without creating a
    /// reference, so it is sound on uninitialised memory.
    macro_rules! offset {
        ($field:ident) => {{
            let holder = MaybeUninit::<CURLMsg>::uninit();
            let base = holder.as_ptr();
            // SAFETY: `base` points at a whole, correctly aligned `CURLMsg`
            // allocation owned by `holder`. `addr_of!` only computes the
            // field's address and never reads the uninitialised bytes, so no
            // invalid value is ever materialised.
            let field = unsafe { addr_of!((*base).$field) };
            (field as usize) - (base as usize)
        }};
    }

    #[test]
    fn curlmsg_matches_the_measured_c_layout() {
        assert_eq!(size_of::<CURLMsg>(), 24, "CURLMsg size");
        assert_eq!(align_of::<CURLMsg>(), 8, "CURLMsg alignment");
        assert_eq!(offset!(msg), 0, "CURLMsg.msg offset");
        assert_eq!(offset!(easy_handle), 8, "CURLMsg.easy_handle offset");
        assert_eq!(offset!(data), 16, "CURLMsg.data offset");
    }

    #[test]
    fn curlmsg_field_widths_match_the_frozen_types() {
        assert_eq!(size_of::<CURLMSG>(), 4, "CURLMSG width");
        assert_eq!(align_of::<CURLMSG>(), 4, "CURLMSG alignment");
        assert_eq!(size_of::<CURLcode>(), 4, "CURLcode width");
        assert_eq!(size_of::<*mut CURL>(), 8, "CURL * width");
        assert_eq!(size_of::<CURLMsg_data>(), 8, "CURLMsg.data width");
        assert_eq!(align_of::<CURLMsg_data>(), 8, "CURLMsg.data alignment");
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
    fn the_url_handle_is_an_incomplete_type() {
        // `struct Curl_URL` is never defined by the authority, so it must
        // carry no layout of its own.
        assert_eq!(size_of::<Curl_URL>(), 0, "Curl_URL must be zero-sized");
        assert_eq!(size_of::<CURLU>(), size_of::<Curl_URL>());
    }

    #[test]
    fn the_message_union_reads_back_what_was_written() {
        let msg = CURLMsg {
            msg: CURLMSG::CURLMSG_DONE,
            easy_handle: core::ptr::null_mut(),
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
    }
}
