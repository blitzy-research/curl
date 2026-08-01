//***************************************************************************
//                                  _   _ ____  _
//  Project                     ___| | | |  _ \| |
//                             / __| | | | |_) | |
//                            | (__| |_| |  _ <| |___
//                             \___|\___/|_| \_\_____|
//
// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// This software is licensed as described in the file COPYING, which
// you should have received as part of this distribution. The terms
// are also available at https://curl.se/docs/copyright.html.
//
// You may opt to use, copy, modify, merge, publish, distribute and/or sell
// copies of the Software, and permit persons to whom the Software is
// furnished to do so, under the terms of the COPYING file.
//
// This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
// KIND, either express or implied.
//
// SPDX-License-Identifier: curl
//
//***************************************************************************

//! The optional GSS-API binding: Negotiate, SPNEGO and Kerberos 5 support.
//!
//! This module supersedes `lib/curl_gssapi.c` (448 lines) and
//! `lib/curl_gssapi.h` (71 lines). It is the smaller of the **two** files in
//! `curl-rs-lib` permitted to contain `unsafe` -- the other being
//! `src/ffi/sys.rs` -- and it is the only one that binds a C security library.
//!
//! # Why this file is allowed to exist at all
//!
//! The requirements contain an absolute prohibition -- no C TLS library at any
//! configuration, "not as a default, not behind a feature flag, not as a
//! fallback" -- and, in the same breath, mandate "Negotiate where OS Kerberos
//! is available". Those two clauses are reconciled by one observation:
//!
//! > GSS-API is neither libcurl, nor libssl, nor a TLS library -- it is an
//! > authentication mechanism. Negotiate sits behind a non-default
//! > `negotiate` feature with the binding confined to
//! > `curl-rs-lib/src/ffi/gss.rs`, so the default build links no C security
//! > library at all.
//!
//! That is why the first attribute below is `#![cfg(feature =
//! "negotiate")]`. It is deliberately belt-and-braces: `src/ffi/mod.rs`
//! declares this module as `#[cfg(feature = "negotiate")] pub(crate) mod
//! gss;`, and the inner attribute makes the guarantee hold *from this file
//! alone*. With the feature off -- which is the default, since
//! `curl-rs-lib/Cargo.toml` lists `negotiate` outside `default` alongside
//! `hickory-dns` and `memdebug` -- this file contributes nothing whatsoever:
//! no item, no `#[link]` directive, no linker input, no symbol. The negative
//! proof is mechanical: `ldd` on a default build finds no `libgssapi_krb5`,
//! and `nm` finds no undefined `gss_*`.
//!
//! # The two consumers, and nothing else
//!
//! The public surface here was sized for exactly two callers. Neither exists at
//! this commit; both are `negotiate`-gated when they land, and the surface
//! below is deliberately no wider than what they need:
//!
//! * `curl-rs-lib/src/auth/negotiate.rs`, to supersede
//!   `lib/vauth/krb5_gssapi.c`, `lib/vauth/spnego_gssapi.c` and
//!   `lib/http_negotiate.c`.
//! * `curl-rs-lib/src/proxy/socks_gss.rs`, to supersede
//!   `lib/socks_gssapi.c` (RFC 1961 SOCKS5 GSS-API).
//!
//! Every entry point added here permanently enlarges the surface that has to
//! be audited by hand, so the binding covers the ten GSS-API functions the C
//! files listed above demonstrably call and not one more. In particular
//! `gss_seal()` and `gss_unseal()` are **not** bound: a search of the C tree
//! finds them only inside RFC 1961 explanatory comments
//! (`lib/socks_gssapi.c:343`, `:366-367`) and in the excluded VMS shim
//! (`lib/setup-vms.h:363-364`). There is no call site anywhere.
//!
//! # What is transcribed from where
//!
//! Every constant and every argument order below comes from the C tree,
//! cross-checked against the installed GSS-API headers:
//!
//! | Item | C source |
//! |------|----------|
//! | The two mechanism OIDs, byte for byte | `lib/curl_gssapi.c:63-68` |
//! | `CURL_ALIGN8` on those descriptors | `lib/curl_gssapi.c:52-56` |
//! | `req_flags` composition and the `gss_init_sec_context` call | `lib/curl_gssapi.c:313-371` |
//! | Context teardown | `lib/curl_gssapi.c:373-385` |
//! | The 1024-byte error-text assembler | `lib/curl_gssapi.c:387-442` |
//! | `GSSAUTH_P_NONE` / `_INTEGRITY` / `_PRIVACY` | `lib/curl_gssapi.h:65-67` |
//! | The Apple deprecation pragma | `lib/curl_gssapi.c:58-61`, `:444-446` |
//! | `CURLGSSAPI_DELEGATION_*` bit values | `include/curl/curl.h:861-863` |
//!
//! # `CURL_GSS_STUB` is deliberately absent
//!
//! `lib/curl_gssapi.c:32-50` and `:70-311` implement a fake GSS-API
//! (`stub_gss_init_sec_context`, `stub_gss_delete_sec_context`) so that the
//! test suite can exercise Negotiate without a KDC. It is not reproduced
//! here, and the omission is deliberate:
//!
//! 1. The whole block is `#ifdef DEBUGBUILD` (`:32`, `:50`).
//! 2. It activates only when `CURL_STUB_GSS_CREDS` is set in the environment
//!    (`:135`, `:342`, `:378`).
//! 3. Exactly two fixtures in the 1,914-file corpus use it --
//!    `tests/data/test2056` (`CURL_STUB_GSS_CREDS="KRB5_Alice"`) and
//!    `tests/data/test2057` (`="NTLM_Alice"`).
//! 4. **Both** gate on `<features>` `GSS-API` *and* `Debug`. `Debug` is
//!    deliberately withheld from the version banner, so both fixtures skip
//!    whether or not the stub exists.
//!
//! # Diagnostics are injected, not reached for
//!
//! In C, `Curl_gss_log_error()` takes a `struct Curl_easy *data` and calls
//! `infof()` on it (`lib/curl_gssapi.c:429-441`). The Rust equivalent of that
//! session handle belongs in `src/easy/`, which does not exist yet and which
//! this module must not depend on when it does:
//! `src/ffi/` is a leaf, and keeping it a leaf is exactly what makes it
//! testable under Miri without a live library. The `data` parameter is
//! therefore modelled as the [`Diagnostics`] trait, which the caller
//! implements over its own trace sink. The text this module hands to it is
//! byte-identical to what C's `infof(data, "%s%s", prefix, buf)` would emit,
//! including the 1024-byte bound and the `". "` separators.
//!
//! One consequence: C compiles the whole logger away under `#ifdef
//! CURLVERBOSE` (`lib/curl_gssapi.h:50-62`). There is no verbosity feature in
//! this workspace, so the real implementation is always present. That is
//! intentional, not an oversight.
//!
//! # The truthfulness coupling with `src/version.rs`
//!
//! `src/version.rs` is to emit `GSS-API`, `SPNEGO` and `Kerberos` in the
//! `Features:` line of `curl --version` only under `negotiate` and only when
//! the capability is genuinely usable. `tests/runtests.pl` parses that line
//! against a fixed 52-name vocabulary and uses it to decide which fixtures to
//! run, and the asymmetry is decisive: **under-reporting a capability makes a
//! fixture skip; over-reporting makes it run and fail.** A compile-time
//! `cfg!` is therefore not enough, because a binary can be *built* with
//! `negotiate` on a host where the runtime library is unusable. [`available`]
//! exists to answer that question at run time. This module supplies only the
//! predicate; the three banner spellings belong to `src/version.rs`, which
//! gates them on `cfg!(feature = "negotiate")` alone at this commit and still
//! owes the call to [`available`].
//!
//! # The safety seam
//!
//! The audit surface is thirteen `unsafe` sites in three places, enumerated
//! here so that it is exact rather than approximately described:
//!
//! - `impl GssProvider for SystemGss` -- nine blocks, one per bound GSS-API
//!   function except `gss_release_buffer`. This is where the handshake, the
//!   per-message wrapping, the name and context lifecycle and the status
//!   rendering all cross into C.
//! - `LibraryBuffer` -- two blocks: `to_owned_vec` forms a read-only slice over
//!   library-allocated memory, and `Drop` makes the tenth and last foreign
//!   call, `gss_release_buffer`. So not quite every `extern "C"` call sits in
//!   the provider `impl`; this one deliberately does not, because putting the
//!   release in `Drop` is what makes it unskippable.
//! - `GssOidDesc` -- two sites: `as_bytes` forms a slice from the
//!   `elements`/`length` pair of a `'static` OID descriptor, which is a
//!   raw-pointer operation but not a foreign call, and
//!   `unsafe impl Sync for GssOidDesc` asserts a thread-safety property the
//!   compiler cannot derive because the type holds a raw pointer.
//!
//! Everything else is ordinary safe Rust parameterised over the trait, which is
//! what lets the flag composition, the error-text assembly, the handshake
//! stepping and the availability probe all be exercised by a pure-Rust double
//! under `cargo miri test`.
//!
//! Buffer, name and context lifetimes are enforced by `Drop` rather than by
//! hand-placed release calls, so no added `?` can skip one -- but "enforced by
//! `Drop`" is not the same as "released only by `Drop`". Two of the three
//! `release_name` call sites and one of the two `delete_sec_context` call sites
//! are explicit rather than RAII, for reasons documented at each; the
//! at-most-once property comes from a consume-and-discard convention plus a
//! null-handle short-circuit, not from `Drop` being the sole releaser.

#![cfg(feature = "negotiate")]

use crate::error::CURLcode;
use core::ffi::{c_int, c_void};
// Reached from exactly one place -- the cache inside [`available`] -- and that
// cache exists only on the `#[cfg(not(miri))]` arm, because under Miri the
// predicate answers `false` without probing and so has nothing to remember.
// The import carries the same gate as its only consumer rather than being left
// unconditional, so `cargo miri test` reports no unused import.
#[cfg(not(miri))]
use std::sync::OnceLock;

// Protection levels

/// No per-message protection. `GSSAUTH_P_NONE` -- `lib/curl_gssapi.h:65`.
///
/// This family is the RFC 4752 section 3.1 **SASL security-layer bitmask**,
/// which is a different encoding from the RFC 1961 SOCKS5 protection *level*;
/// see [`SOCKS5_PROTECTION_NONE`] for the latter, and do not substitute one
/// for the other. `lib/vauth/krb5_gssapi.c:234` rejects a server offer that
/// does not include this bit and then masks the octet down to it at `:239`,
/// because curl implements no security layer.
pub(crate) const GSSAUTH_P_NONE: u8 = 1;

/// Integrity protection. `GSSAUTH_P_INTEGRITY` -- `lib/curl_gssapi.h:66`.
///
/// Declared by the C header and carried here for completeness of the RFC 4752
/// bitmask; curl never requests a security layer, so it only ever appears as a
/// bit a server offered.
pub(crate) const GSSAUTH_P_INTEGRITY: u8 = 2;

/// Confidentiality protection. `GSSAUTH_P_PRIVACY` -- `lib/curl_gssapi.h:67`.
pub(crate) const GSSAUTH_P_PRIVACY: u8 = 4;

/// The warning C emits when the platform GSS-API lacks
/// `GSS_C_DELEG_POLICY_FLAG`, reproduced verbatim from
/// `lib/curl_gssapi.c:333-334`.
///
/// C spells it as two adjoining string literals; the value below is the
/// concatenation the compiler produces, which is what `infof()` actually
/// receives. It is public to the crate so `src/auth/negotiate.rs`, once it
/// lands, can emit it through the same trace path as every other `infof()`
/// message.
pub(crate) const DELEGATION_POLICY_UNSUPPORTED_WARNING: &str =
    "WARNING: support for CURLGSSAPI_DELEGATION_POLICY_FLAG not compiled in";

/// `GSS_LOG_BUFFER_LEN` -- `lib/curl_gssapi.c:388`.
///
/// C declares `char buf[GSS_LOG_BUFFER_LEN]` and bounds every append against
/// it. The bound is reproduced exactly, including its off-by-design `+ 3`
/// slack, because the assembled text is user-visible output.
#[allow(dead_code)]
const GSS_LOG_BUFFER_LEN: usize = 1024;

// GSS-API scalar types and constants
//
// Measured against the installed MIT Kerberos headers
// (`/usr/include/mit-krb5/gssapi/gssapi.h`) by compiling and running a probe
// rather than by reading: `sizeof(OM_uint32) == 4`, and every flag, status
// and status-type value below was printed by that probe.

/// `OM_uint32`, the width of every GSS-API status and flag word.
///
/// MIT defines it as `gss_uint32`, which is `uint32_t` on all four mandated
/// targets; the probe confirmed `sizeof(OM_uint32) == 4`.
type OmUint32 = u32;

/// `gss_qop_t`, a `typedef` of `OM_uint32`.
#[allow(dead_code)]
type GssQop = OmUint32;

/// `GSS_C_DELEG_FLAG` = 1. Requested for `CURLGSSAPI_DELEGATION_FLAG`.
const GSS_C_DELEG_FLAG: OmUint32 = 1;

/// `GSS_C_MUTUAL_FLAG` = 2. Requested when the caller asks for mutual auth.
const GSS_C_MUTUAL_FLAG: OmUint32 = 2;

/// `GSS_C_REPLAY_FLAG` = 4.
///
/// This is the seed value of `req_flags`, not zero -- see
/// [`request_flags`]. Starting from zero would silently change the
/// negotiated context.
const GSS_C_REPLAY_FLAG: OmUint32 = 4;

/// `GSS_C_CONF_FLAG` = 16. Inspected by SOCKS5 to pick confidentiality.
#[allow(dead_code)]
const GSS_C_CONF_FLAG: OmUint32 = 16;

/// `GSS_C_INTEG_FLAG` = 32. Inspected by SOCKS5 to pick integrity.
#[allow(dead_code)]
const GSS_C_INTEG_FLAG: OmUint32 = 32;

/// `GSS_C_DELEG_POLICY_FLAG` = 32768.
///
/// MIT Kerberos 1.8 and later define this, as does Apple's GSS.framework, so
/// all four mandated targets have it; the probe measured 32768. It is absent
/// from GNU GSS, which is what the `#else` branch at `lib/curl_gssapi.c:332-335`
/// exists for. That branch is still modelled here -- see
/// [`DELEGATION_POLICY_UNSUPPORTED_WARNING`] and the
/// `policy_flag_supported` parameter of [`request_flags`] -- so the behaviour
/// is reproduced.
const GSS_C_DELEG_POLICY_FLAG: OmUint32 = 32768;

/// `GSS_C_GSS_CODE` = 1: render a *major* status through `gss_display_status`.
#[allow(dead_code)]
const GSS_C_GSS_CODE: c_int = 1;

/// `GSS_C_MECH_CODE` = 2: render a *minor* status.
#[allow(dead_code)]
const GSS_C_MECH_CODE: c_int = 2;

/// `GSS_C_QOP_DEFAULT` = 0.
#[allow(dead_code)]
const GSS_C_QOP_DEFAULT: GssQop = 0;

/// `GSS_S_COMPLETE` = 0.
const GSS_S_COMPLETE: OmUint32 = 0;

/// `GSS_S_CONTINUE_NEEDED` = 1, i.e. `1 << GSS_C_SUPPLEMENTARY_OFFSET`.
#[allow(dead_code)]
const GSS_S_CONTINUE_NEEDED: OmUint32 = 1;

/// `GSS_S_FAILURE` = `13 << GSS_C_ROUTINE_ERROR_OFFSET` = 851968.
///
/// `Curl_gss_log_error()` suppresses the major-status text for exactly this
/// value (`lib/curl_gssapi.c:435`), because "General failure" carries no
/// information the minor status does not carry better.
#[allow(dead_code)]
const GSS_S_FAILURE: OmUint32 = 13 << 16;

/// The bit mask behind the `GSS_ERROR()` macro.
///
/// MIT expands it to
/// `(x) & ((GSS_C_CALLING_ERROR_MASK << 24) | (GSS_C_ROUTINE_ERROR_MASK << 16))`
/// with both masks `0377` octal, i.e. `0xff`. The probe printed
/// `0xffff0000`.
const GSS_ERROR_MASK: OmUint32 = 0xffff_0000;

/// The `GSS_ERROR()` macro, as a function.
///
/// A macro cannot be bound across the FFI boundary, so it is reimplemented.
/// Non-zero means the calling-error or routine-error field is set;
/// supplementary bits such as `GSS_S_CONTINUE_NEEDED` deliberately do **not**
/// count as errors, which is precisely why the mask excludes the low 16 bits.
const fn gss_error(major: OmUint32) -> OmUint32 {
    major & GSS_ERROR_MASK
}

// C layout types
//
// Sizes, offsets and alignments below are not inferred; they were printed by
// a compiled `offsetof`/`sizeof`/`_Alignof` probe against the installed
// headers and are asserted again by the unit tests at the foot of this file.

/// `gss_buffer_desc` -- `{ size_t length; void *value; }`.
///
/// Measured: 16 bytes, `length` at offset 0, `value` at offset 8, alignment 8.
///
/// Note that `length` is `size_t`, **not** `OM_uint32`. Getting that wrong
/// would misread every token the library hands back on a 64-bit target, so it
/// is called out here and pinned by a test.
#[repr(C)]
struct GssBufferDesc {
    length: usize,
    value: *mut c_void,
}

impl GssBufferDesc {
    /// `GSS_C_EMPTY_BUFFER`, which MIT spells `{0, NULL}`.
    #[allow(dead_code)]
    const EMPTY: Self = Self {
        length: 0,
        value: core::ptr::null_mut(),
    };

    /// A descriptor borrowing `bytes` for the duration of one call.
    ///
    /// GSS-API declares input buffers as the non-const `gss_buffer_t` for
    /// purely historical reasons and never writes through them; C curl asserts
    /// the same thing with its `CURL_UNCONST` macro. The `*const -> *mut` cast
    /// therefore happens here, at the boundary, while the Rust side of the
    /// data stays genuinely immutable.
    fn borrowing(bytes: &[u8]) -> Self {
        Self {
            length: bytes.len(),
            value: bytes.as_ptr().cast::<c_void>().cast_mut(),
        }
    }
}

/// `gss_OID_desc` -- `{ OM_uint32 length; void *elements; }`.
///
/// Measured: 16 bytes, `length` at offset 0, `elements` at offset 8,
/// alignment 8.
///
/// `align(8)` reproduces `CURL_ALIGN8`, which `lib/curl_gssapi.c:52-56`
/// expands to `__attribute__((aligned(8)))` and applies to both mechanism
/// descriptors at `:63` and `:66`. On a 64-bit target the natural alignment
/// is already 8, but stating it is not cosmetic: the descriptor is passed *by
/// pointer* into the C library, and an under-aligned pointer is undefined
/// behaviour that Miri flags and that some platforms fault on. Keeping the
/// attribute means the guarantee survives any future change to the field
/// types.
#[repr(C, align(8))]
struct GssOidDesc {
    length: OmUint32,
    elements: *const u8,
}

impl GssOidDesc {
    /// Wrap a `'static` DER-encoded OID body.
    ///
    /// `bytes` must be the OID *contents* octets only -- no ASN.1 tag and no
    /// length prefix -- which is exactly the shape of the string literals at
    /// `lib/curl_gssapi.c:64` and `:67`.
    const fn new(bytes: &'static [u8]) -> Self {
        // A DER OID body is a handful of octets; `as` cannot lose information
        // here, and every construction site below is a fixed-size literal
        // array whose length is checked by a unit test.
        Self {
            length: bytes.len() as OmUint32,
            elements: bytes.as_ptr(),
        }
    }

    /// The OID body, for assertions and diagnostics.
    #[allow(dead_code)]
    fn as_bytes(&self) -> &[u8] {
        if self.elements.is_null() || self.length == 0 {
            return &[];
        }
        // SAFETY: `elements` and `length` are only ever set by `new()` from a
        // `&'static [u8]`, whose pointer is non-null, properly aligned for
        // `u8`, and valid for exactly `length` initialised bytes for the
        // whole program. Every one of the three constructions in this file
        // passes a `static` array, so the referent outlives `&self` and is
        // never mutated -- no other code in the crate can reach these static
        // items, and `GssOidDesc` exposes no way to overwrite the fields.
        unsafe {
            core::slice::from_raw_parts(self.elements, self.length as usize)
        }
    }
}

// SAFETY: `GssOidDesc` is `Sync` because it is deeply immutable. The only
// constructor, `new()`, takes a `&'static [u8]`; the struct has no method that
// mutates either field and no interior mutability; and the three `static`
// instances below are the only values ever placed in shared storage. Sharing a
// `&GssOidDesc` across threads therefore only ever exposes a `'static`,
// read-only byte array, which is exactly what C relies on when it declares
// `Curl_spnego_mech_oid` and `Curl_krb5_mech_oid` at file scope
// (`lib/curl_gssapi.c:63-68`) and hands their addresses to a library that may
// be driven from several threads.
unsafe impl Sync for GssOidDesc {}

/// `struct gss_channel_bindings_struct`, the referent of
/// `gss_channel_bindings_t`.
///
/// Measured: 64 bytes, alignment 8, with `initiator_addrtype` at 0,
/// `initiator_address` at 8, `acceptor_addrtype` at 24, `acceptor_address` at
/// 32 and `application_data` at 48.
///
/// `lib/vauth/spnego_gssapi.c:152-159` fills `application_data` alone, leaving
/// everything else zeroed by `memset`, and only when
/// `GSS_C_CHANNEL_BOUND_FLAG` is available. [`channel_bindings`] reproduces
/// that exactly.
#[repr(C)]
#[allow(dead_code)]
struct GssChannelBindings {
    initiator_addrtype: OmUint32,
    initiator_address: GssBufferDesc,
    acceptor_addrtype: OmUint32,
    acceptor_address: GssBufferDesc,
    application_data: GssBufferDesc,
}

/// Build the channel-bindings structure `lib/vauth/spnego_gssapi.c:152-159`
/// builds: everything zeroed except `application_data`.
#[allow(dead_code)]
fn channel_bindings(data: &[u8]) -> GssChannelBindings {
    GssChannelBindings {
        initiator_addrtype: 0,
        initiator_address: GssBufferDesc::EMPTY,
        acceptor_addrtype: 0,
        acceptor_address: GssBufferDesc::EMPTY,
        application_data: GssBufferDesc::borrowing(data),
    }
}

/// `gss_ctx_id_t`, an opaque handle owned by the library.
///
/// A distinct newtype rather than a bare pointer so that a context, a name
/// and a credential can never be passed where another was meant. Never
/// dereferenced by this crate -- it is only ever handed straight back to
/// GSS-API.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RawContext(*mut c_void);

impl RawContext {
    /// `GSS_C_NO_CONTEXT`, which MIT spells `((gss_ctx_id_t) 0)`.
    const NONE: Self = Self(core::ptr::null_mut());

    fn is_none(self) -> bool {
        self.0.is_null()
    }
}

/// `gss_name_t`, an opaque handle owned by the library.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RawName(*mut c_void);

impl RawName {
    /// `GSS_C_NO_NAME`, which MIT spells `((gss_name_t) 0)`.
    const NONE: Self = Self(core::ptr::null_mut());

    fn is_none(self) -> bool {
        self.0.is_null()
    }
}

/// `gss_cred_id_t`, an opaque handle.
///
/// Only ever the null variant: `Curl_gss_init_sec_context()` passes
/// `GSS_C_NO_CREDENTIAL` unconditionally (`lib/curl_gssapi.c:359`), meaning
/// "use the default credential", and nothing in curl acquires one explicitly.
#[repr(transparent)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
struct RawCredential(*mut c_void);

impl RawCredential {
    /// `GSS_C_NO_CREDENTIAL`.
    #[allow(dead_code)]
    const NONE: Self = Self(core::ptr::null_mut());
}

// The mechanism and name-type object identifiers

/// SPNEGO, OID 1.3.6.1.5.5.2.
///
/// Transcribed octet by octet from `lib/curl_gssapi.c:64`, which writes
/// `CURL_UNCONST("\x2b\x06\x01\x05\x05\x02")` with an explicit length of 6.
#[allow(dead_code)]
static SPNEGO_MECH_OID_BYTES: [u8; 6] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];

/// Kerberos 5, OID 1.2.840.113554.1.2.2.
///
/// Transcribed octet by octet from `lib/curl_gssapi.c:67`, which writes
/// `CURL_UNCONST("\x2a\x86\x48\x86\xf7\x12\x01\x02\x02")` with an explicit
/// length of 9.
#[allow(dead_code)]
static KRB5_MECH_OID_BYTES: [u8; 9] =
    [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];

/// `GSS_C_NT_HOSTBASED_SERVICE`, OID 1.2.840.113554.1.2.1.4.
///
/// C reaches for the library's exported `gss_OID` *variable*
/// (`lib/vauth/spnego_gssapi.c:118`, `lib/vauth/krb5_gssapi.c:110`,
/// `lib/socks_gssapi.c:156`). This binding carries the octets instead, for
/// three reasons: GSS-API selects a name type by comparing the OID *value*,
/// so the two are behaviourally identical; MIT exports the variable under a
/// versioned symbol (`GSS_C_NT_HOSTBASED_SERVICE@@gssapi_krb5_2_MIT`), and
/// declaring a versioned `extern static` from Rust is avoidable risk; and
/// Apple's GSS.framework exports it differently again, so hard-coding keeps
/// all four mandated targets on one code path.
///
/// The octets were not derived on paper -- they were printed from
/// `libgssapi_krb5.so.2` at run time, which reported length 10 and exactly
/// this sequence.
static HOSTBASED_SERVICE_OID_BYTES: [u8; 10] =
    [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x01, 0x04];

/// `Curl_spnego_mech_oid` -- `lib/curl_gssapi.c:63-65`.
#[allow(dead_code)]
static SPNEGO_MECH_OID: GssOidDesc = GssOidDesc::new(&SPNEGO_MECH_OID_BYTES);

/// `Curl_krb5_mech_oid` -- `lib/curl_gssapi.c:66-68`.
#[allow(dead_code)]
static KRB5_MECH_OID: GssOidDesc = GssOidDesc::new(&KRB5_MECH_OID_BYTES);

/// The descriptor passed as `input_name_type` to `gss_import_name`.
static HOSTBASED_SERVICE_OID: GssOidDesc =
    GssOidDesc::new(&HOSTBASED_SERVICE_OID_BYTES);

/// Which security mechanism a handshake step should negotiate.
///
/// Replaces C's habit of passing `&Curl_spnego_mech_oid` or
/// `&Curl_krb5_mech_oid` directly, so no caller outside this module ever holds
/// a `gss_OID`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Mechanism {
    /// SPNEGO (RFC 4178), used for HTTP Negotiate -- `lib/vauth/spnego_gssapi.c:166`.
    #[allow(dead_code)]
    Spnego,
    /// Kerberos 5, used for SASL GSSAPI and SOCKS5 --
    /// `lib/vauth/krb5_gssapi.c:136`, `lib/socks_gssapi.c:178`.
    #[allow(dead_code)]
    Krb5,
}

impl Mechanism {
    /// The DER body of this mechanism's OID.
    #[allow(dead_code)]
    pub(crate) fn oid_bytes(self) -> &'static [u8] {
        self.descriptor().as_bytes()
    }

    /// The `gss_OID_desc` to hand to the library.
    #[allow(dead_code)]
    fn descriptor(self) -> &'static GssOidDesc {
        match self {
            Self::Spnego => &SPNEGO_MECH_OID,
            Self::Krb5 => &KRB5_MECH_OID,
        }
    }
}

/// How the library should interpret the bytes given to [`TargetName::import`].
///
/// Both variants are load-bearing. `lib/socks_gssapi.c:136-157` chooses
/// between them on whether the configured proxy service name contains a `/`:
/// a fully qualified principal is imported with `GSS_C_NULL_OID`, while a bare
/// service is imported as a host-based service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NameType {
    /// `GSS_C_NT_HOSTBASED_SERVICE`, i.e. `service@host`.
    HostBasedService,
    /// `GSS_C_NULL_OID`: let the mechanism guess. C passes this for a name
    /// that already contains a `/`.
    #[allow(dead_code)]
    Unspecified,
}

impl NameType {
    /// The `input_name_type` descriptor, or `None` for `GSS_C_NULL_OID`.
    fn descriptor(self) -> Option<&'static GssOidDesc> {
        match self {
            Self::HostBasedService => Some(&HOSTBASED_SERVICE_OID),
            Self::Unspecified => None,
        }
    }
}

// The ten GSS-API entry points
//
// Hand-written because there is no GSS-API crate in this workspace's
// dependency set and `curl-rs-lib` declares no build script, so neither
// `bindgen` nor a build-time link directive is available. Every signature was
// transcribed from the installed prototypes:
//
//   gss_init_sec_context    gssapi.h:438-451
//   gss_delete_sec_context  gssapi.h:475-478
//   gss_wrap                gssapi.h:509-515
//   gss_unwrap              gssapi.h:521-527
//   gss_display_status      gssapi.h:531-537
//   gss_display_name        gssapi.h:555-559
//   gss_import_name         gssapi.h:563-567
//   gss_release_name        gssapi.h:570-572
//   gss_release_buffer      gssapi.h:575-577
//   gss_inquire_context     gssapi.h:595-604
//
// Linkage follows the platform, never a Cargo feature: `negotiate` gates the
// *capability*, and which library provides it is a separate axis expressed
// with `target_os`. On Linux, MIT Kerberos ships `libgssapi_krb5`
// (`krb5-config --libs gssapi` reports `-lgssapi_krb5 -lkrb5 -lk5crypto
// -lcom_err`, and the transitive three arrive through the shared object's own
// DT_NEEDED entries). On macOS, Apple ships GSS.framework. No Windows arm
// exists by design: the SSPI variants -- `lib/vauth/krb5_sspi.c`,
// `spnego_sspi.c`, `digest_sspi.c`, `ntlm_sspi.c`, `lib/curl_sspi.c` and
// `lib/socks_sspi.c` -- are all out of scope.
//
// A note on the deprecation pragma that wraps the whole C file
// (`lib/curl_gssapi.c:58-61`, `:444-446`): it suppresses
// `-Wdeprecated-declarations` under `__GNUC__ && __APPLE__` because Apple's
// GSS.framework headers mark these entry points deprecated. Rust cannot
// inherit that, because it does not read the C headers -- the declarations
// below are this file's own and carry no `#[deprecated]`. There is therefore
// no deprecation lint to silence on either Darwin target, and adding an
// `#[allow(deprecated)]` "to match C" would be noise rather than parity. This
// was verified by building for both Apple triples.

/// The four mandated targets are `x86_64-unknown-linux-gnu`,
/// `aarch64-unknown-linux-gnu`, `x86_64-apple-darwin` and
/// `aarch64-apple-darwin`. Anything else has no vetted GSS-API provider here,
/// and failing loudly at compile time is better than failing obscurely at
/// link time.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!(
    "the `negotiate` feature binds GSS-API and is supported only on the four mandated \
     targets (x86_64/aarch64 unknown-linux-gnu and x86_64/aarch64 apple-darwin); build \
     without `--features negotiate` on this target"
);

#[cfg_attr(target_os = "linux", link(name = "gssapi_krb5"))]
#[cfg_attr(target_os = "macos", link(name = "GSS", kind = "framework"))]
extern "C" {
    /// Drive one step of the context establishment handshake.
    ///
    /// Thirteen parameters, in the order the C prototype declares them; the
    /// wide signature is the library's, not a design choice here.
    #[allow(clippy::too_many_arguments)]
    #[allow(dead_code)]
    fn gss_init_sec_context(
        minor_status: *mut OmUint32,
        claimant_cred_handle: RawCredential,
        context_handle: *mut RawContext,
        target_name: RawName,
        mech_type: *const GssOidDesc,
        req_flags: OmUint32,
        time_req: OmUint32,
        input_chan_bindings: *const GssChannelBindings,
        input_token: *const GssBufferDesc,
        actual_mech_type: *mut *mut GssOidDesc,
        output_token: *mut GssBufferDesc,
        ret_flags: *mut OmUint32,
        time_rec: *mut OmUint32,
    ) -> OmUint32;

    /// Discard a security context. Sets `*context_handle` to
    /// `GSS_C_NO_CONTEXT`.
    fn gss_delete_sec_context(
        minor_status: *mut OmUint32,
        context_handle: *mut RawContext,
        output_token: *mut GssBufferDesc,
    ) -> OmUint32;

    /// Apply per-message protection.
    #[allow(dead_code)]
    fn gss_wrap(
        minor_status: *mut OmUint32,
        context_handle: RawContext,
        conf_req_flag: c_int,
        qop_req: GssQop,
        input_message_buffer: *const GssBufferDesc,
        conf_state: *mut c_int,
        output_message_buffer: *mut GssBufferDesc,
    ) -> OmUint32;

    /// Remove per-message protection.
    #[allow(dead_code)]
    fn gss_unwrap(
        minor_status: *mut OmUint32,
        context_handle: RawContext,
        input_message_buffer: *const GssBufferDesc,
        output_message_buffer: *mut GssBufferDesc,
        conf_state: *mut c_int,
        qop_state: *mut GssQop,
    ) -> OmUint32;

    /// Render one part of a status value as text. Multi-part messages are
    /// walked with the `message_context` cursor.
    #[allow(dead_code)]
    fn gss_display_status(
        minor_status: *mut OmUint32,
        status_value: OmUint32,
        status_type: c_int,
        mech_type: *const GssOidDesc,
        message_context: *mut OmUint32,
        status_string: *mut GssBufferDesc,
    ) -> OmUint32;

    /// Render an internal name as text.
    #[allow(dead_code)]
    fn gss_display_name(
        minor_status: *mut OmUint32,
        input_name: RawName,
        output_name_buffer: *mut GssBufferDesc,
        output_name_type: *mut *mut GssOidDesc,
    ) -> OmUint32;

    /// Convert a textual name into an internal name.
    fn gss_import_name(
        minor_status: *mut OmUint32,
        input_name_buffer: *const GssBufferDesc,
        input_name_type: *const GssOidDesc,
        output_name: *mut RawName,
    ) -> OmUint32;

    /// Release an internal name. Sets `*input_name` to `GSS_C_NO_NAME`.
    fn gss_release_name(
        minor_status: *mut OmUint32,
        input_name: *mut RawName,
    ) -> OmUint32;

    /// Release a buffer the library allocated. Sets the descriptor to
    /// `GSS_C_EMPTY_BUFFER`.
    #[allow(dead_code)]
    fn gss_release_buffer(
        minor_status: *mut OmUint32,
        buffer: *mut GssBufferDesc,
    ) -> OmUint32;

    /// Interrogate an established context. Nine parameters; curl asks only for
    /// `src_name` and passes `NULL` for the other seven
    /// (`lib/socks_gssapi.c:296-298`).
    #[allow(clippy::too_many_arguments)]
    #[allow(dead_code)]
    fn gss_inquire_context(
        minor_status: *mut OmUint32,
        context_handle: RawContext,
        src_name: *mut RawName,
        targ_name: *mut RawName,
        lifetime_rec: *mut OmUint32,
        mech_type: *mut *mut GssOidDesc,
        ctx_flags: *mut OmUint32,
        locally_initiated: *mut c_int,
        open: *mut c_int,
    ) -> OmUint32;
}

// Status, flags and delegation: the safe vocabulary the consumers see

/// A GSS-API major/minor status pair.
///
/// The fields are private on purpose: no `OM_uint32` may escape this
/// directory. What callers need is the *classification*, and every question
/// curl asks of a status is answerable through a method here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GssStatus {
    major: OmUint32,
    minor: OmUint32,
}

impl GssStatus {
    /// The pair a call that has not happened yet reports.
    pub(crate) const COMPLETE: Self = Self {
        major: GSS_S_COMPLETE,
        minor: 0,
    };

    fn new(major: OmUint32, minor: OmUint32) -> Self {
        Self { major, minor }
    }

    /// `GSS_ERROR(major)` -- a calling error or a routine error is set.
    pub(crate) fn is_error(self) -> bool {
        gss_error(self.major) != 0
    }

    /// The handshake position this status reports, or `None` if it is an
    /// error.
    ///
    /// Replaces the raw comparisons at `lib/http_negotiate.c:237-238`
    /// (`status == GSS_S_COMPLETE || status == GSS_S_CONTINUE_NEEDED`) and the
    /// loop exit at `lib/socks_gssapi.c:227` (`major != GSS_S_CONTINUE_NEEDED`).
    #[allow(dead_code)]
    pub(crate) fn state(self) -> Option<HandshakeState> {
        if self.is_error() {
            return None;
        }
        if self.major & GSS_S_CONTINUE_NEEDED != 0 {
            Some(HandshakeState::ContinueNeeded)
        } else {
            Some(HandshakeState::Complete)
        }
    }

    /// Whether the context is fully established.
    #[allow(dead_code)]
    pub(crate) fn is_complete(self) -> bool {
        self.state() == Some(HandshakeState::Complete)
    }

    /// Whether another token must be exchanged.
    #[allow(dead_code)]
    pub(crate) fn is_continue_needed(self) -> bool {
        self.state() == Some(HandshakeState::ContinueNeeded)
    }
}

/// Where a handshake has got to.
///
/// An enum rather than a status integer so that a caller cannot forget a case:
/// `match` is exhaustive, whereas `if(status == GSS_S_COMPLETE)` silently
/// falls through.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HandshakeState {
    /// `GSS_S_COMPLETE`: the context is established.
    #[allow(dead_code)]
    Complete,
    /// `GSS_S_CONTINUE_NEEDED`: send the returned token and call again.
    #[allow(dead_code)]
    ContinueNeeded,
}

/// The `ret_flags` word `gss_init_sec_context` reports.
///
/// Wrapped so the `GSS_C_*` bit constants stay inside this file.
/// `lib/socks_gssapi.c:329-335` tests exactly the two protection bits below.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ContextFlags(OmUint32);

impl ContextFlags {
    /// `GSS_C_CONF_FLAG`: the context can protect confidentiality, which is
    /// SOCKS5's first choice -- `lib/socks_gssapi.c:331-332`.
    #[allow(dead_code)]
    pub(crate) fn has_confidentiality(self) -> bool {
        self.0 & GSS_C_CONF_FLAG != 0
    }

    /// `GSS_C_INTEG_FLAG`: the context can protect integrity, which is
    /// SOCKS5's fallback -- `lib/socks_gssapi.c:334-335`.
    #[allow(dead_code)]
    pub(crate) fn has_integrity(self) -> bool {
        self.0 & GSS_C_INTEG_FLAG != 0
    }

    /// `GSS_C_MUTUAL_FLAG`: the peer authenticated itself in turn.
    #[allow(dead_code)]
    pub(crate) fn has_mutual_auth(self) -> bool {
        self.0 & GSS_C_MUTUAL_FLAG != 0
    }

    /// `GSS_C_DELEG_FLAG`: credentials were delegated.
    #[allow(dead_code)]
    pub(crate) fn has_delegation(self) -> bool {
        self.0 & GSS_C_DELEG_FLAG != 0
    }

    /// `GSS_C_REPLAY_FLAG`: replay detection is active.
    #[allow(dead_code)]
    pub(crate) fn has_replay_detection(self) -> bool {
        self.0 & GSS_C_REPLAY_FLAG != 0
    }

    /// The RFC 1961 protection level this context supports, selected exactly
    /// as `lib/socks_gssapi.c:330-335` selects it.
    ///
    /// The returned value is the **RFC 1961 wire octet**, not a
    /// [`GSSAUTH_P_NONE`]-family constant: C computes `gss_enc = 0` for no
    /// protection, `2` for confidentiality and `1` for integrity, and writes
    /// that octet into the protection-level message. The two families happen
    /// to be different encodings of the same idea, and confusing them would
    /// put the wrong byte on the wire -- so this returns C's, byte for byte.
    #[allow(dead_code)]
    pub(crate) fn socks5_protection_level(self) -> u8 {
        if self.has_confidentiality() {
            SOCKS5_PROTECTION_CONFIDENTIALITY
        } else if self.has_integrity() {
            SOCKS5_PROTECTION_INTEGRITY
        } else {
            SOCKS5_PROTECTION_NONE
        }
    }
}

/// RFC 1961 protection level "no data protection" -- `lib/socks_gssapi.c:330`.
pub(crate) const SOCKS5_PROTECTION_NONE: u8 = 0;

/// RFC 1961 protection level "integrity" -- `lib/socks_gssapi.c:335`.
pub(crate) const SOCKS5_PROTECTION_INTEGRITY: u8 = 1;

/// RFC 1961 protection level "confidentiality" -- `lib/socks_gssapi.c:332`.
pub(crate) const SOCKS5_PROTECTION_CONFIDENTIALITY: u8 = 2;

/// The value of `CURLOPT_GSSAPI_DELEGATION`, as a type rather than a `long`.
///
/// `include/curl/curl.h:861-863` declares the option's three constants:
/// `CURLGSSAPI_DELEGATION_NONE` is `0L`,
/// `CURLGSSAPI_DELEGATION_POLICY_FLAG` is `(1L << 0)` and
/// `CURLGSSAPI_DELEGATION_FLAG` is `(1L << 1)`. They are a bitmask, and
/// `lib/curl_gssapi.c:329` and `:338` test them independently, so both may be
/// set at once.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Delegation(i64);

impl Delegation {
    /// `CURLGSSAPI_DELEGATION_NONE` -- the default.
    #[allow(dead_code)]
    pub(crate) const NONE: Self = Self(0);

    /// `CURLGSSAPI_DELEGATION_POLICY_FLAG` = `1 << 0`.
    const POLICY_BIT: i64 = 1 << 0;

    /// `CURLGSSAPI_DELEGATION_FLAG` = `1 << 1`.
    const ALWAYS_BIT: i64 = 1 << 1;

    /// Adopt the raw option value the easy handle holds.
    ///
    /// The parameter is `i64` rather than `libc::c_long` deliberately: no
    /// `libc` type may appear in this module's crate-visible surface, and all
    /// four mandated targets are LP64, so `c_long` and `i64` are the same
    /// integer there. Unknown bits are preserved rather than rejected, exactly
    /// as C preserves them -- it only ever tests the two it knows.
    #[allow(dead_code)]
    pub(crate) const fn from_option_value(value: i64) -> Self {
        Self(value)
    }

    /// Whether delegation is permitted when policy allows it.
    pub(crate) const fn policy(self) -> bool {
        self.0 & Self::POLICY_BIT != 0
    }

    /// Whether delegation is requested unconditionally.
    pub(crate) const fn always(self) -> bool {
        self.0 & Self::ALWAYS_BIT != 0
    }
}

/// Whether the platform GSS-API defines `GSS_C_DELEG_POLICY_FLAG`.
///
/// True on every mandated target -- MIT Kerberos has had it since 1.8 and
/// Apple's GSS.framework defines it too -- which is why [`request_flags`] is
/// normally called with this value. The constant exists so the value has a
/// single home rather than being written `true` at the call site, and so the
/// `false` path stays reachable and unit-tested rather than rotting.
#[allow(dead_code)]
const DELEGATION_POLICY_FLAG_SUPPORTED: bool = true;

/// What `Curl_gss_init_sec_context()` computes before it calls into the
/// library.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RequestedFlags {
    flags: OmUint32,
    warning: Option<&'static str>,
}

impl RequestedFlags {
    /// The diagnostic C emits through `infof()` when the delegation-policy
    /// flag was asked for but the platform cannot express it, or `None` when
    /// there is nothing to report.
    ///
    /// Callers must forward this to their trace sink. C emits it inline at
    /// `lib/curl_gssapi.c:333-334`; here the caller owns the sink, so the text
    /// travels back with the flags rather than being printed from inside the
    /// binding.
    #[allow(dead_code)]
    pub(crate) fn warning(self) -> Option<&'static str> {
        self.warning
    }

    /// The flags, as [`ContextFlags`] so the bit constants stay private.
    ///
    /// Chiefly useful for asserting the composition; the value is passed to
    /// the library through [`SecurityContext::step`] without the caller ever
    /// handling it.
    #[allow(dead_code)]
    pub(crate) fn as_context_flags(self) -> ContextFlags {
        ContextFlags(self.flags)
    }
}

/// Compose `req_flags` exactly as `lib/curl_gssapi.c:324-339` composes it.
///
/// This is the single highest-risk computation in the file, because the flags
/// change the bytes on the wire, so it is a pure function of its inputs and is
/// exhaustively unit-tested rather than being folded into the FFI call.
///
/// Order and seed are both load-bearing:
///
/// 1. `req_flags` starts at `GSS_C_REPLAY_FLAG`, **not** zero (`:324`).
///    Seeding from zero silently changes the negotiated context.
/// 2. `GSS_C_MUTUAL_FLAG` is added when the caller asks for mutual
///    authentication (`:326-327`).
/// 3. `GSS_C_DELEG_POLICY_FLAG` is added when the delegation mask carries
///    `CURLGSSAPI_DELEGATION_POLICY_FLAG` *and* the platform defines the flag;
///    otherwise the verbatim warning is reported instead, and the flag is
///    **not** silently dropped (`:329-336`).
/// 4. `GSS_C_DELEG_FLAG` is added when the mask carries
///    `CURLGSSAPI_DELEGATION_FLAG` (`:338-339`).
///
/// `policy_flag_supported` is a parameter rather than a `cfg!` so that the
/// GNU-GSS branch is reachable from a test on a host where MIT is installed.
pub(crate) fn request_flags(
    mutual_auth: bool,
    delegation: Delegation,
    policy_flag_supported: bool,
) -> RequestedFlags {
    let mut flags = GSS_C_REPLAY_FLAG;
    let mut warning = None;

    if mutual_auth {
        flags |= GSS_C_MUTUAL_FLAG;
    }

    if delegation.policy() {
        if policy_flag_supported {
            flags |= GSS_C_DELEG_POLICY_FLAG;
        } else {
            warning = Some(DELEGATION_POLICY_UNSUPPORTED_WARNING);
        }
    }

    if delegation.always() {
        flags |= GSS_C_DELEG_FLAG;
    }

    RequestedFlags { flags, warning }
}

// Diagnostics: C's `struct Curl_easy *data`, inverted

/// Where this module sends the text `Curl_gss_log_error()` would have logged.
///
/// C threads a `struct Curl_easy *data` through every function that might need
/// to talk (`lib/curl_gssapi.c:313`, `:429`) and calls `infof()` on it. The
/// Rust session handle belongs in `src/easy/`, and `src/ffi/` must not depend
/// upward on it, so the sink is injected instead. The caller -- either
/// `src/auth/negotiate.rs` or `src/proxy/socks_gss.rs`, neither of which exists
/// yet -- is to implement this over its own handle and route the message
/// through the crate's trace machinery, so that `--verbose` and `--trace`
/// behave exactly as they do for every other `infof()` message.
pub(crate) trait Diagnostics {
    /// Emit one informational line. The message carries no trailing newline,
    /// matching `infof()`.
    #[allow(dead_code)]
    fn infof(&mut self, message: &str);
}

/// A sink that throws messages away.
///
/// For call sites that genuinely have nothing to log to -- the availability
/// probe, and the tests.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct DiscardDiagnostics;

impl Diagnostics for DiscardDiagnostics {
    fn infof(&mut self, _message: &str) {}
}

// A `&mut` to a sink is itself a sink, which keeps `&mut dyn Diagnostics`
// usable wherever a generic sink is expected without the caller re-borrowing
// by hand.
impl<T: Diagnostics + ?Sized> Diagnostics for &mut T {
    fn infof(&mut self, message: &str) {
        (**self).infof(message);
    }
}

// The substitutable seam
//
// Everything below the `SystemGss` implementation of this trait is ordinary
// safe Rust. That is what makes the flag composition, the error-text
// assembler, the handshake stepping and the availability probe all runnable
// under `cargo miri test`, which cannot call into a real GSS-API library.
//
// Three deliberate shapes make the seam safe rather than merely indirect:
//
//   * every method is a SAFE `fn`, so no caller needs an `unsafe` block; the
//     implementation upholds the library's preconditions internally,
//   * every method returns OWNED data (`Vec<u8>`), never a view into
//     library-allocated memory. Release-exactly-once is therefore an
//     invariant of the implementation rather than an obligation on callers,
//     enforced by `Drop` on a guard, and
//   * every method that HANDS BACK A HANDLE returns it outside a `Result`, so
//     that no `?` can sit between the library call and the caller's adoption of
//     what it produced. That rule covers exactly three methods --
//     `import_name`, `init_sec_context` and `source_name` -- and it is what
//     makes leaking a handle, or deleting one the library already destroyed,
//     unreachable rather than merely unlikely. A new method returning a handle
//     must follow it; a fallible part belongs *inside* the outcome, as
//     `StepOutcome::token` shows. The three methods that do return a `Result`
//     (`display_name`, `wrap` and `unwrap`) hand back nothing but bytes, whose
//     backing buffer a guard releases on drop, so an early return there costs
//     at most a diagnostic; `display_status` swallows its own failures rather
//     than returning one, and likewise hands back only bytes.

/// The GSS-API operations this crate needs, as a substitutable interface.
///
/// Private to this file: `RawContext`, `RawName` and `c_int` appear in these
/// signatures, and none of them may become crate-visible.
trait GssProvider {
    /// `gss_import_name`.
    fn import_name(&self, name: &[u8], kind: NameType) -> NameOutcome;

    /// `gss_release_name`. Total: a `GSS_C_NO_NAME` handle is ignored.
    fn release_name(&self, name: RawName);

    /// `gss_delete_sec_context` with a `GSS_C_NO_BUFFER` output token, which
    /// is how every curl call site invokes it. Total: `GSS_C_NO_CONTEXT` is
    /// ignored.
    fn delete_sec_context(&self, context: RawContext);

    /// `gss_init_sec_context`.
    ///
    /// Returns the possibly-replaced context handle, because the C parameter
    /// is in/out and the library may hand back a different one on any call.
    ///
    /// Infallible on purpose: the handle must reach the caller even when the
    /// step failed, so the fallible part lives in [`StepOutcome::token`]. See
    /// that type for why.
    #[allow(dead_code)]
    fn init_sec_context(
        &self,
        context: RawContext,
        request: &StepRequest<'_>,
    ) -> StepOutcome;

    /// One `gss_display_status` iteration, advancing `message_context`.
    #[allow(dead_code)]
    fn display_status(
        &self,
        status: OmUint32,
        status_type: c_int,
        message_context: &mut OmUint32,
    ) -> StatusText;

    /// `gss_display_name`.
    #[allow(dead_code)]
    fn display_name(&self, name: RawName) -> Result<TokenOutcome, CURLcode>;

    /// `gss_inquire_context`, asking only for `src_name` and passing `NULL`
    /// for the other seven out-parameters, as `lib/socks_gssapi.c:296-298`
    /// does.
    #[allow(dead_code)]
    fn source_name(&self, context: RawContext) -> NameOutcome;

    /// `gss_wrap` with `GSS_C_QOP_DEFAULT`.
    #[allow(dead_code)]
    fn wrap(
        &self,
        context: RawContext,
        confidentiality: bool,
        plain: &[u8],
    ) -> Result<WrapOutcome, CURLcode>;

    /// `gss_unwrap`, discarding `conf_state` and `qop_state` exactly as
    /// `lib/socks_gssapi.c:477-479` does.
    #[allow(dead_code)]
    fn unwrap(
        &self,
        context: RawContext,
        sealed: &[u8],
    ) -> Result<TokenOutcome, CURLcode>;
}

impl<T: GssProvider + ?Sized> GssProvider for &T {
    fn import_name(&self, name: &[u8], kind: NameType) -> NameOutcome {
        (**self).import_name(name, kind)
    }

    fn release_name(&self, name: RawName) {
        (**self).release_name(name);
    }

    fn delete_sec_context(&self, context: RawContext) {
        (**self).delete_sec_context(context);
    }

    fn init_sec_context(
        &self,
        context: RawContext,
        request: &StepRequest<'_>,
    ) -> StepOutcome {
        (**self).init_sec_context(context, request)
    }

    fn display_status(
        &self,
        status: OmUint32,
        status_type: c_int,
        message_context: &mut OmUint32,
    ) -> StatusText {
        (**self).display_status(status, status_type, message_context)
    }

    fn display_name(&self, name: RawName) -> Result<TokenOutcome, CURLcode> {
        (**self).display_name(name)
    }

    fn source_name(&self, context: RawContext) -> NameOutcome {
        (**self).source_name(context)
    }

    fn wrap(
        &self,
        context: RawContext,
        confidentiality: bool,
        plain: &[u8],
    ) -> Result<WrapOutcome, CURLcode> {
        (**self).wrap(context, confidentiality, plain)
    }

    fn unwrap(
        &self,
        context: RawContext,
        sealed: &[u8],
    ) -> Result<TokenOutcome, CURLcode> {
        (**self).unwrap(context, sealed)
    }
}

/// What one handshake step needs, gathered so the thirteen-parameter C call is
/// assembled in one place.
#[allow(dead_code)]
struct StepRequest<'a> {
    target_name: RawName,
    mechanism: Mechanism,
    flags: OmUint32,
    channel_binding_data: Option<&'a [u8]>,
    input_token: Option<&'a [u8]>,
    want_return_flags: bool,
}

/// The result of `gss_import_name` or `gss_inquire_context`.
struct NameOutcome {
    status: GssStatus,
    name: RawName,
}

/// The result of `gss_init_sec_context`.
///
/// Deliberately *not* wrapped in a `Result`. The library's `context_handle`
/// parameter is in/out: by the time the call returns, the handle the caller
/// passed in may already have been destroyed and replaced, so the returned
/// handle is not a result to be discarded on failure -- it is an ownership
/// transfer the caller has no choice but to accept. C cannot get this wrong,
/// because it passes `&nego->context` and the library writes the caller's
/// storage directly (`lib/vauth/spnego_gssapi.c:164`,
/// `lib/socks_gssapi.c:176`). Modelling the same call as
/// `Result<StepOutcome, CURLcode>` reintroduces the hazard, because a single `?`
/// then drops the replacement on the floor: the new handle leaks and the caller
/// goes on to delete a handle the library has already freed.
///
/// So the only fallible part -- copying the output token into owned storage --
/// is carried *inside* the outcome instead of in place of it. That makes the
/// error impossible to observe before the handle has been adopted, and it is a
/// property of the type rather than of the call sites: there is no `?` for a
/// later edit to add, because there is no `Result` to apply one to.
#[allow(dead_code)]
struct StepOutcome {
    status: GssStatus,
    context: RawContext,
    /// The output token, or the reason it could not be copied.
    ///
    /// Copying happens after the library has already replaced the handle and
    /// reported a status, so a failure here says nothing about either of them
    /// and must not suppress them.
    token: Result<Vec<u8>, CURLcode>,
    flags: ContextFlags,
}

/// The result of a call that produces one library buffer.
#[allow(dead_code)]
struct TokenOutcome {
    status: GssStatus,
    token: Vec<u8>,
}

/// The result of `gss_wrap`, which additionally reports whether
/// confidentiality was actually applied.
#[allow(dead_code)]
struct WrapOutcome {
    status: GssStatus,
    token: Vec<u8>,
    confidential: bool,
}

/// One part of a rendered status message.
#[allow(dead_code)]
struct StatusText {
    status: GssStatus,
    text: Vec<u8>,
}

// From here to the end of `impl GssProvider for SystemGss` is eleven of the
// file's thirteen `unsafe` sites: two in `LibraryBuffer` below and nine in the
// provider `impl`. The other two are `GssOidDesc::as_bytes` and
// `unsafe impl Sync for GssOidDesc`, above. Every site in all three places
// carries a `// SAFETY:` comment stating the precondition it upholds and why it
// holds at that site.

/// An output buffer the library allocated and that must be released with
/// exactly one `gss_release_buffer`.
///
/// The release lives in `Drop` rather than at call sites on purpose. C spreads
/// 31 `gss_release_buffer()` calls over four files -- 17 in
/// `lib/socks_gssapi.c`, 6 in `lib/vauth/spnego_gssapi.c`, 5 in
/// `lib/vauth/krb5_gssapi.c` and 3 in `lib/curl_gssapi.c` -- precisely because
/// every early return needs its own, and each one is a leak waiting to happen.
/// Here an added `?` cannot skip one.
#[allow(dead_code)]
struct LibraryBuffer {
    descriptor: GssBufferDesc,
}

impl LibraryBuffer {
    /// A descriptor for the library to fill, initialised to
    /// `GSS_C_EMPTY_BUFFER`.
    #[allow(dead_code)]
    const fn empty() -> Self {
        Self {
            descriptor: GssBufferDesc::EMPTY,
        }
    }

    /// A raw pointer for use as an out-parameter.
    #[allow(dead_code)]
    fn as_out_ptr(&mut self) -> *mut GssBufferDesc {
        &mut self.descriptor
    }

    /// Copy the contents into owned storage.
    ///
    /// Returns an owned `Vec` so nothing outside this module ever holds a view
    /// into library memory. An absurd length -- which only a broken or hostile
    /// mechanism could report -- yields `CURLE_OUT_OF_MEMORY` rather than an
    /// allocation abort, keeping every wrapper total.
    ///
    /// "Total" is the operative word, and it is why the copy reserves before it
    /// writes. `[u8]::to_vec` and `Vec::extend_from_slice` allocate
    /// *infallibly*: when the allocator refuses they call
    /// `alloc::alloc::handle_alloc_error`, which aborts the process. A
    /// mechanism reporting a token larger than the address space can satisfy --
    /// a broken one, or one fed by a hostile peer -- would therefore take the
    /// entire application down instead of failing one authentication. libcurl
    /// has a code for that condition and every other allocation on this path
    /// already reports it, so aborting would be both a denial of service and a
    /// departure from the surrounding contract.
    #[allow(dead_code)]
    fn to_owned_vec(&self) -> Result<Vec<u8>, CURLcode> {
        if self.descriptor.value.is_null() || self.descriptor.length == 0 {
            return Ok(Vec::new());
        }
        // A slice may not exceed `isize::MAX` bytes, and neither may a Rust
        // allocation. Checking here converts a would-be abort into an error
        // the caller can report.
        if self.descriptor.length > isize::MAX as usize {
            return Err(CURLcode::OutOfMemory);
        }
        let length = self.descriptor.length;
        // Reserve first, and fallibly: this is the only allocation the copy
        // performs, and it is the one that can fail. `try_reserve_exact`
        // guarantees spare capacity of at least `length`, and `reserve` -- which
        // `extend_from_slice` calls internally -- is documented to do nothing
        // when the capacity is already sufficient, so the write below cannot
        // reach the allocator a second time.
        let mut owned: Vec<u8> = Vec::new();
        owned
            .try_reserve_exact(length)
            .map_err(|_| CURLcode::OutOfMemory)?;
        let start = self.descriptor.value.cast::<u8>();
        // SAFETY: `descriptor` was zeroed by `empty()` and is only ever written
        // by a GSS-API call that returned. Validity here rests on the NON-NULL
        // `value` tested above, NOT on a successful major status, and the
        // distinction matters because this function is called before `major` is
        // examined -- `init_sec_context` copies the output token out before it
        // decides what the status means. RFC 2744 obliges the library to set
        // `value` and `length` together for ANY buffer it returns: a success
        // token, a `GSS_S_CONTINUE_NEEDED` continuation token, and an error
        // token emitted alongside a failing status are all allocations owned by
        // the library. A failing call may therefore leave a populated
        // descriptor, which is exactly why curl's C releases it on the error
        // path (`lib/vauth/spnego_gssapi.c:177-180` and
        // `lib/vauth/krb5_gssapi.c:142-145` both release `output_token` under
        // an `if(GSS_ERROR(major))` guard whenever its `value` is non-null).
        // A call that returns nothing leaves the descriptor `EMPTY`, and the
        // null test above turns that into an empty `Vec` without forming a
        // slice. Given a non-null `value`, `length` is the count of initialised
        // bytes at it. The pointer is byte-aligned, which is the only alignment
        // `u8` needs; `length` is at most `isize::MAX`, checked above; the
        // referent is live because `self` still owns it and `Drop` has not run;
        // and the slice is read-only and dropped before this function returns,
        // so it cannot outlive the allocation or alias the release in `Drop`.
        let bytes = unsafe { core::slice::from_raw_parts(start, length) };
        owned.extend_from_slice(bytes);
        Ok(owned)
    }
}

impl Drop for LibraryBuffer {
    fn drop(&mut self) {
        if self.descriptor.value.is_null() {
            // `GSS_C_EMPTY_BUFFER`: nothing was ever allocated. C guards the
            // same way, e.g. `lib/vauth/spnego_gssapi.c:178`.
            return;
        }
        let mut minor: OmUint32 = 0;
        // SAFETY: `gss_release_buffer` requires a writable pointer to a
        // descriptor the library itself filled, and requires that it be
        // released at most once. Both hold: `descriptor` is an owned field of
        // `self`, so the pointer is non-null, aligned and uniquely borrowed
        // for the call; the non-null `value` proves the library allocated it;
        // and `Drop` runs at most once per value, after which `descriptor` is
        // reset to `EMPTY` so that even a `mem::forget`-then-reconstruct
        // sequence could not release it twice. `minor` is a live local the
        // library may write.
        unsafe {
            gss_release_buffer(&mut minor, &mut self.descriptor);
        }
        // RFC 2744 says the library resets the descriptor; do not rely on it.
        self.descriptor = GssBufferDesc::EMPTY;
    }
}

/// The platform GSS-API: MIT Kerberos `libgssapi_krb5` on Linux, Apple's
/// GSS.framework on macOS.
#[derive(Clone, Copy, Debug, Default)]
struct SystemGss;

impl GssProvider for SystemGss {
    fn import_name(&self, name: &[u8], kind: NameType) -> NameOutcome {
        let input = GssBufferDesc::borrowing(name);
        let name_type = kind
            .descriptor()
            .map_or(core::ptr::null(), |oid| oid as *const GssOidDesc);
        let mut output = RawName::NONE;
        let mut minor: OmUint32 = 0;

        // SAFETY: every pointer passed is either null where GSS-API documents
        // null as meaningful, or points at a live, correctly typed local.
        // `minor` and `output` are uniquely borrowed locals the library may
        // write. `input` is a `#[repr(C)]` descriptor over `name`, which
        // outlives the call and which `gss_import_name` only reads -- the
        // parameter is the historically non-const `gss_buffer_t`, the same
        // situation C papers over with `CURL_UNCONST`. `name_type` is either
        // `GSS_C_NULL_OID` or the address of a `'static` descriptor whose OID
        // body is immutable for the life of the process.
        let major = unsafe {
            gss_import_name(&mut minor, &input, name_type, &mut output)
        };

        NameOutcome {
            status: GssStatus::new(major, minor),
            name: output,
        }
    }

    fn release_name(&self, name: RawName) {
        if name.is_none() {
            // `GSS_C_NO_NAME`; C guards identically at
            // `lib/vauth/spnego_gssapi.c:278`.
            return;
        }
        let mut handle = name;
        let mut minor: OmUint32 = 0;
        // SAFETY: `gss_release_name` requires a writable pointer to a name
        // handle the library produced, released at most once. `handle` is a
        // local copy of a handle that came from `gss_import_name` or
        // `gss_inquire_context`.
        //
        // At-most-once is upheld by a CONSUME-AND-DISCARD protocol rather than
        // by a single caller, because there are three callers and each one
        // gives up its handle at the call:
        //
        //   `NameGuard::drop`         the owning release; assigns
        //                             `RawName::NONE` straight afterwards, so
        //                             the field cannot be released again even
        //                             through a later refactor.
        //   `NameGuard::import`       the error path, where `import_name`
        //                             returned a failing status. No guard was
        //                             ever constructed, so nothing else can
        //                             ever see that handle, and releasing it
        //                             here is the only way it does not leak.
        //   `available_with`          the availability probe, which releases
        //                             unconditionally and then inspects only
        //                             the status, never the handle.
        //
        // In all three the caller's `RawName` is dead at the point of call, so
        // no live copy survives to be released a second time. `RawName` is
        // `Copy`, which is what makes passing by value the right shape here:
        // there is no move to observe, only a convention the three sites keep.
        // The `GSS_C_NO_NAME` short-circuit above also makes a double release
        // harmless rather than merely unreachable, since a poisoned handle
        // returns before touching the library. Writing through `&mut handle`
        // affects only the local, which is correct: the caller's copy is
        // already being discarded.
        unsafe {
            gss_release_name(&mut minor, &mut handle);
        }
    }

    fn delete_sec_context(&self, context: RawContext) {
        if context.is_none() {
            // `GSS_C_NO_CONTEXT`; C guards identically at
            // `lib/vauth/spnego_gssapi.c:264`.
            return;
        }
        let mut handle = context;
        let mut minor: OmUint32 = 0;
        // SAFETY: `gss_delete_sec_context` requires a writable pointer to a
        // context handle the library produced and that has not already been
        // deleted, plus either a writable output-token descriptor or
        // `GSS_C_NO_BUFFER`. `handle` is a local copy of a handle only ever
        // obtained from `gss_init_sec_context`.
        //
        // There are two callers, not one, and they cannot double-delete:
        //
        //   `ContextGuard::drop`      the owning release, run once per value.
        //   `ContextGuard::reset`     the explicit restart path, the
        //                             counterpart of
        //                             `Curl_auth_cleanup_spnego()`, for a
        //                             caller that must begin a new handshake
        //                             on a guard it keeps.
        //
        // Both assign `RawContext::NONE` immediately after the call, so a
        // `reset` followed by the eventual `drop` hits the `GSS_C_NO_CONTEXT`
        // short-circuit above and never reaches the library a second time. That
        // ordering -- delete, then poison, with no fallible step between -- is
        // the invariant to preserve if either function is ever edited.
        //
        // Null is passed for the output token, exactly as the C call sites do
        // (for example `lib/socks_gssapi.c:196`), so no buffer can be leaked
        // here.
        unsafe {
            gss_delete_sec_context(
                &mut minor,
                &mut handle,
                core::ptr::null_mut(),
            );
        }
    }

    fn init_sec_context(
        &self,
        context: RawContext,
        request: &StepRequest<'_>,
    ) -> StepOutcome {
        // Bindings and input token are materialised as locals so that they
        // outlive the call; taking `&` of a temporary inside the argument list
        // would be equally sound but far harder to audit.
        let bindings = request.channel_binding_data.map(channel_bindings);
        let bindings_ptr =
            bindings.as_ref().map_or(core::ptr::null(), |value| {
                value as *const GssChannelBindings
            });

        let input = request.input_token.map(GssBufferDesc::borrowing);
        let input_ptr = input
            .as_ref()
            .map_or(core::ptr::null(), |value| value as *const GssBufferDesc);

        let mut output = LibraryBuffer::empty();
        let mut returned_flags: OmUint32 = 0;
        let returned_flags_ptr = if request.want_return_flags {
            &mut returned_flags as *mut OmUint32
        } else {
            // C passes NULL when the caller does not want them, e.g.
            // `lib/vauth/spnego_gssapi.c:171`.
            core::ptr::null_mut()
        };
        let mut minor: OmUint32 = 0;

        // `context_handle` is an in/out parameter: the library may hand back a
        // different handle on any call, including the first, and the caller
        // must adopt it. Holding it in a named local rather than a temporary
        // is what makes the write-back observable. Whatever the library leaves
        // here is returned unconditionally -- this function has no early
        // return and no `?` -- so the value cannot be stranded.
        let mut handle = context;

        // SAFETY: the argument list reproduces `lib/curl_gssapi.c:358-370`
        // exactly, including the three deliberate constants
        // (`GSS_C_NO_CREDENTIAL`, `time_req = 0`, and null for both
        // `actual_mech_type` and `time_rec`).
        //
        // Preconditions upheld:
        //   * `minor`, `context_handle` and `output` are uniquely borrowed
        //     live locals; `context_handle` is in/out, and the value written
        //     back is captured below and stored, so the previous handle is
        //     never reused.
        //   * `target_name` is a handle owned by a live `NameGuard` that the
        //     borrow checker keeps alive for the whole call, via the `&`
        //     borrow inside `StepRequest`.
        //   * `mech_type` addresses a `'static` immutable descriptor.
        //   * `input_chan_bindings` and `input_token` are either null, which
        //     GSS-API documents as `GSS_C_NO_CHANNEL_BINDINGS` and
        //     `GSS_C_NO_BUFFER`, or address locals that outlive the call and
        //     borrow slices the caller keeps alive; the library only reads
        //     them.
        //   * `ret_flags` is either null or a live local.
        //   * `output` starts as `GSS_C_EMPTY_BUFFER` and is owned by a
        //     `LibraryBuffer`, so whatever the library allocates is released
        //     exactly once when that guard drops -- including when
        //     `to_owned_vec()` below cannot copy it.
        let major = unsafe {
            gss_init_sec_context(
                &mut minor,
                RawCredential::NONE,
                &mut handle,
                request.target_name,
                request.mechanism.descriptor(),
                request.flags,
                0,
                bindings_ptr,
                input_ptr,
                core::ptr::null_mut(),
                output.as_out_ptr(),
                returned_flags_ptr,
                core::ptr::null_mut(),
            )
        };

        // Note the absence of `?`: the copy's outcome is carried, not
        // propagated, so the handle and the status the library just reported
        // reach the caller whether or not the token could be copied.
        StepOutcome {
            status: GssStatus::new(major, minor),
            context: handle,
            token: output.to_owned_vec(),
            flags: ContextFlags(returned_flags),
        }
    }

    fn display_status(
        &self,
        status: OmUint32,
        status_type: c_int,
        message_context: &mut OmUint32,
    ) -> StatusText {
        let mut rendered = LibraryBuffer::empty();
        let mut minor: OmUint32 = 0;

        // SAFETY: `minor`, `message_context` and `rendered` are live and
        // uniquely borrowed for the call. `mech_type` is null, which GSS-API
        // documents as `GSS_C_NO_OID` ("use the default mechanism"), matching
        // `lib/curl_gssapi.c:401`. `message_context` is the library's cursor
        // and must be zero on the first call and carried unchanged between
        // calls; `assemble_status_text` initialises it to zero and never
        // touches it in between, so that contract holds. `rendered` owns
        // whatever the library allocates and releases it exactly once when it
        // drops at the end of this function -- which is what reproduces C's
        // per-iteration `gss_release_buffer` at `lib/curl_gssapi.c:411`.
        let major = unsafe {
            gss_display_status(
                &mut minor,
                status,
                status_type,
                core::ptr::null(),
                message_context,
                rendered.as_out_ptr(),
            )
        };

        StatusText {
            status: GssStatus::new(major, minor),
            // An oversized or unreadable buffer degrades to no text, which is
            // exactly what C's length-bound check at `:405` does with it.
            text: rendered.to_owned_vec().unwrap_or_default(),
        }
    }

    fn display_name(&self, name: RawName) -> Result<TokenOutcome, CURLcode> {
        let mut rendered = LibraryBuffer::empty();
        let mut minor: OmUint32 = 0;

        // SAFETY: `minor` and `rendered` are live, uniquely borrowed locals.
        // `name` is a handle owned by a live `NameGuard` -- the `&self` borrow
        // in the caller keeps it alive across this call -- and
        // `gss_display_name` only reads it. Null is passed for
        // `output_name_type`, which GSS-API permits and which
        // `lib/socks_gssapi.c:305` also does, so no OID is allocated for us to
        // leak. `rendered` releases the produced buffer exactly once on drop.
        let major = unsafe {
            gss_display_name(
                &mut minor,
                name,
                rendered.as_out_ptr(),
                core::ptr::null_mut(),
            )
        };

        Ok(TokenOutcome {
            status: GssStatus::new(major, minor),
            token: rendered.to_owned_vec()?,
        })
    }

    fn source_name(&self, context: RawContext) -> NameOutcome {
        let mut source = RawName::NONE;
        let mut minor: OmUint32 = 0;

        // SAFETY: `minor` and `source` are live, uniquely borrowed locals.
        // `context` is a handle owned by a live `ContextGuard` and is only
        // read. The remaining seven out-parameters are null, which GSS-API
        // documents as "not requested"; that both matches
        // `lib/socks_gssapi.c:296-298` and means nothing besides `src_name`
        // is allocated, so `src_name` is the only handle to release -- which
        // the `NameGuard` built from it in `SecurityContext::source_name`
        // then does.
        let major = unsafe {
            gss_inquire_context(
                &mut minor,
                context,
                &mut source,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };

        NameOutcome {
            status: GssStatus::new(major, minor),
            name: source,
        }
    }

    fn wrap(
        &self,
        context: RawContext,
        confidentiality: bool,
        plain: &[u8],
    ) -> Result<WrapOutcome, CURLcode> {
        let input = GssBufferDesc::borrowing(plain);
        let mut sealed = LibraryBuffer::empty();
        let mut conf_state: c_int = 0;
        let mut minor: OmUint32 = 0;

        // SAFETY: `minor`, `conf_state` and `sealed` are live, uniquely
        // borrowed locals the library may write. `context` is owned by a live
        // `ContextGuard` and only read. `input` is a descriptor over `plain`,
        // which outlives the call and which `gss_wrap` only reads.
        // `GSS_C_QOP_DEFAULT` is the quality of protection every curl call
        // site requests (`lib/socks_gssapi.c:384`,
        // `lib/vauth/krb5_gssapi.c:275`). `sealed` releases the produced
        // buffer exactly once on drop, including on the `?` below.
        let major = unsafe {
            gss_wrap(
                &mut minor,
                context,
                c_int::from(confidentiality),
                GSS_C_QOP_DEFAULT,
                &input,
                &mut conf_state,
                sealed.as_out_ptr(),
            )
        };

        Ok(WrapOutcome {
            status: GssStatus::new(major, minor),
            token: sealed.to_owned_vec()?,
            confidential: conf_state != 0,
        })
    }

    fn unwrap(
        &self,
        context: RawContext,
        sealed: &[u8],
    ) -> Result<TokenOutcome, CURLcode> {
        let input = GssBufferDesc::borrowing(sealed);
        let mut plain = LibraryBuffer::empty();
        let mut minor: OmUint32 = 0;

        // SAFETY: `minor` and `plain` are live, uniquely borrowed locals.
        // `context` is owned by a live `ContextGuard` and only read. `input`
        // is a descriptor over `sealed`, which outlives the call and is only
        // read. Null is passed for both `conf_state` and `qop_state`, which
        // GSS-API documents as "not requested"; that is also what
        // `lib/socks_gssapi.c:477-479` passes, since `GSS_C_QOP_DEFAULT` is
        // zero and is being used there as a null pointer. `plain` releases
        // the produced buffer exactly once on drop.
        let major = unsafe {
            gss_unwrap(
                &mut minor,
                context,
                &input,
                plain.as_out_ptr(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };

        Ok(TokenOutcome {
            status: GssStatus::new(major, minor),
            token: plain.to_owned_vec()?,
        })
    }
}

// Ownership guards.
//
// From here down there is no `unsafe` and no raw-pointer OPERATION: every call
// goes through the `GssProvider` trait, which is what lets the tests -- and
// Miri -- drive it with a pure-Rust double. The guards do STORE raw pointers,
// because `RawName` and `RawContext` are `#[repr(transparent)]` newtypes over
// `*mut c_void`; what they never do is dereference one. That is the line worth
// keeping: a handle may be held, copied and compared against its null value
// here, and may only be dereferenced behind the trait.
//
// The guards are generic over the provider so the double can own them, and are
// private for the same reason: a `pub(crate)` item may not name the private
// `GssProvider` trait. The crate-visible types below are thin newtypes over
// the `SystemGss` instantiation.

/// An owned `gss_name_t`, released exactly once.
///
/// C leaves this to discipline and pays for it with 15 scattered
/// `gss_release_name()` calls.
struct NameGuard<P: GssProvider> {
    provider: P,
    handle: RawName,
}

impl<P: GssProvider> NameGuard<P> {
    /// `gss_import_name`, mirroring `lib/vauth/spnego_gssapi.c:117-127`.
    ///
    /// An empty `name` is rejected before the library sees it. C cannot reach
    /// that state -- `Curl_auth_build_spn()` either returns a non-empty string
    /// or `NULL`, and `NULL` is turned into `CURLE_OUT_OF_MEMORY` at
    /// `:110` -- so rejecting it here preserves the invariant the C call site
    /// relies on instead of handing a mechanism a degenerate name.
    #[allow(dead_code)]
    fn import(
        provider: P,
        name: &[u8],
        kind: NameType,
        diagnostics: &mut dyn Diagnostics,
    ) -> Result<Self, CURLcode> {
        if name.is_empty() {
            diagnostics.infof("gss_import_name() failed: empty service name");
            return Err(CURLcode::AuthError);
        }

        let outcome = provider.import_name(name, kind);
        if outcome.status.is_error() {
            // Release first if the mechanism handed something back anyway, so
            // the diagnostic cannot leak it.
            provider.release_name(outcome.name);
            diagnostics.infof(&describe(
                &provider,
                "gss_import_name() failed: ",
                outcome.status,
            ));
            return Err(CURLcode::AuthError);
        }

        Ok(Self {
            provider,
            handle: outcome.name,
        })
    }

    /// Adopt a handle the library produced through some other call, such as
    /// `gss_inquire_context`'s `src_name`.
    #[allow(dead_code)]
    fn adopt(provider: P, handle: RawName) -> Self {
        Self { provider, handle }
    }

    /// `gss_display_name`, mirroring `lib/socks_gssapi.c:304-314`.
    #[allow(dead_code)]
    fn display(
        &self,
        diagnostics: &mut dyn Diagnostics,
    ) -> Result<Vec<u8>, CURLcode> {
        let outcome = self.provider.display_name(self.handle)?;
        if outcome.status.is_error() {
            diagnostics.infof(&describe(
                &self.provider,
                "gss_display_name() failed: ",
                outcome.status,
            ));
            return Err(CURLcode::AuthError);
        }
        Ok(outcome.token)
    }
}

impl<P: GssProvider> Drop for NameGuard<P> {
    fn drop(&mut self) {
        self.provider.release_name(self.handle);
        // Poison the handle so that even a future refactor that resurrected
        // the value could not release it twice.
        self.handle = RawName::NONE;
    }
}

/// An owned `gss_ctx_id_t`, deleted exactly once.
///
/// The handle is in/out on every `gss_init_sec_context` call, so it is stored
/// in one place and overwritten wholesale by [`Self::step`]. A stale handle is
/// therefore unreachable rather than merely discouraged.
struct ContextGuard<P: GssProvider> {
    provider: P,
    handle: RawContext,
    #[allow(dead_code)]
    status: GssStatus,
}

impl<P: GssProvider> ContextGuard<P> {
    /// A fresh, empty context: `GSS_C_NO_CONTEXT`.
    fn new(provider: P) -> Self {
        Self {
            provider,
            handle: RawContext::NONE,
            status: GssStatus::COMPLETE,
        }
    }

    /// Whether the library has handed back a context handle at all.
    #[allow(dead_code)]
    fn exists(&self) -> bool {
        !self.handle.is_none()
    }

    /// Whether the handshake has finished successfully.
    ///
    /// This is the `nego->context && nego->status == GSS_S_COMPLETE` test at
    /// `lib/vauth/spnego_gssapi.c:96`, which curl uses to detect a server that
    /// rejected an authentication the client considered finished.
    #[allow(dead_code)]
    fn is_established(&self) -> bool {
        self.exists() && self.status.is_complete()
    }

    /// The status of the most recent step.
    ///
    /// C stores this as `nego->status` (`lib/vauth/spnego_gssapi.c:176`) --
    /// *before* the error check, so it is meaningful even when the step failed
    /// -- and `lib/http_negotiate.c:237-238` reads it back later. Keeping it on
    /// the context reproduces that without leaking an `OM_uint32`.
    #[allow(dead_code)]
    fn status(&self) -> GssStatus {
        self.status
    }

    /// One `Curl_gss_init_sec_context()` step -- `lib/curl_gssapi.c:313-371`.
    #[allow(dead_code)]
    fn step(
        &mut self,
        request: &HandshakeRequest<'_, P>,
        diagnostics: &mut dyn Diagnostics,
    ) -> Result<HandshakeOutcome, CURLcode> {
        let requested = request_flags(
            request.mutual_auth,
            request.delegation,
            DELEGATION_POLICY_FLAG_SUPPORTED,
        );
        if let Some(warning) = requested.warning() {
            // C emits this inline through `infof()` at
            // `lib/curl_gssapi.c:333-334`; the sink is injected here, but the
            // text and the timing -- before the library call -- are the same.
            diagnostics.infof(warning);
        }

        let outcome = self.provider.init_sec_context(
            self.handle,
            &StepRequest {
                target_name: request.target.handle,
                mechanism: request.mechanism,
                flags: requested.flags,
                channel_binding_data: request.channel_binding_data,
                input_token: request.input_token,
                want_return_flags: request.want_return_flags,
            },
        );

        // Adopt the handle unconditionally, exactly as C does by passing
        // `&context`: a failed call can still have created a partial context,
        // and `lib/socks_gssapi.c:196` deletes it on the error path for that
        // reason. Storing it here means `Drop` does the same. Adopting it also
        // *retires* the handle that was here before, which is the half that
        // matters most -- if the library replaced it, the old value is already
        // freed and deleting it again would be a double free.
        //
        // `init_sec_context` returns no `Result`, so nothing can run between the
        // call and these two lines. The status is recorded here for the same
        // reason C assigns `nego->status` before its own error check
        // (`lib/vauth/spnego_gssapi.c:175`): `lib/http_negotiate.c:237-238`
        // reads it back after a failure, so it has to survive one.
        self.handle = outcome.context;
        self.status = outcome.status;

        if outcome.status.is_error() {
            diagnostics.infof(&describe(
                &self.provider,
                "gss_init_sec_context() failed: ",
                outcome.status,
            ));
            return Err(CURLcode::AuthError);
        }

        // Only now may the token's own failure propagate. The library error
        // takes precedence when both occurred, because it is the one C reports
        // and the one that explains the handshake.
        let token = outcome.token?;

        Ok(HandshakeOutcome {
            state: outcome.status.state().unwrap_or(HandshakeState::Complete),
            token,
            flags: outcome.flags,
        })
    }

    /// `gss_inquire_context`'s `src_name` -- `lib/socks_gssapi.c:296-303`.
    #[allow(dead_code)]
    fn source_name(
        &self,
        diagnostics: &mut dyn Diagnostics,
    ) -> Result<NameGuard<P>, CURLcode>
    where
        P: Clone,
    {
        let outcome = self.provider.source_name(self.handle);
        // Adopt before checking, so a handle produced alongside an error is
        // still released. C does the reverse order at `:293-295` and has to
        // call `gss_release_name()` by hand on that path.
        let name = NameGuard::adopt(self.provider.clone(), outcome.name);
        if outcome.status.is_error() {
            diagnostics.infof(&describe(
                &self.provider,
                "gss_inquire_context() failed: ",
                outcome.status,
            ));
            return Err(CURLcode::AuthError);
        }
        Ok(name)
    }

    /// `gss_wrap` -- `lib/socks_gssapi.c:383-385`,
    /// `lib/vauth/krb5_gssapi.c:274-276`.
    #[allow(dead_code)]
    fn wrap(
        &self,
        confidentiality: bool,
        plain: &[u8],
        diagnostics: &mut dyn Diagnostics,
    ) -> Result<SealedMessage, CURLcode> {
        let outcome =
            self.provider.wrap(self.handle, confidentiality, plain)?;
        if outcome.status.is_error() {
            diagnostics.infof(&describe(
                &self.provider,
                "gss_wrap() failed: ",
                outcome.status,
            ));
            return Err(CURLcode::AuthError);
        }
        Ok(SealedMessage {
            token: outcome.token,
            confidential: outcome.confidential,
        })
    }

    /// `gss_unwrap` -- `lib/socks_gssapi.c:477-479`,
    /// `lib/vauth/krb5_gssapi.c:209-210`.
    ///
    /// An empty input is rejected before the library sees it, mapping to
    /// `CURLE_BAD_CONTENT_ENCODING` exactly as
    /// `lib/vauth/krb5_gssapi.c:199-202` maps an empty security message.
    #[allow(dead_code)]
    fn unwrap(
        &self,
        sealed: &[u8],
        diagnostics: &mut dyn Diagnostics,
    ) -> Result<Vec<u8>, CURLcode> {
        if sealed.is_empty() {
            diagnostics
                .infof("GSSAPI handshake failure (empty security message)");
            return Err(CURLcode::BadContentEncoding);
        }
        let outcome = self.provider.unwrap(self.handle, sealed)?;
        if outcome.status.is_error() {
            diagnostics.infof(&describe(
                &self.provider,
                "gss_unwrap() failed: ",
                outcome.status,
            ));
            return Err(CURLcode::BadContentEncoding);
        }
        Ok(outcome.token)
    }

    /// Delete the context and return to the pre-handshake state.
    ///
    /// The explicit counterpart of `Curl_auth_cleanup_spnego()`
    /// (`lib/vauth/spnego_gssapi.c:259-289`), for callers that must restart a
    /// handshake on a handle they keep.
    #[allow(dead_code)]
    fn reset(&mut self) {
        self.provider.delete_sec_context(self.handle);
        self.handle = RawContext::NONE;
        self.status = GssStatus::COMPLETE;
    }
}

impl<P: GssProvider> Drop for ContextGuard<P> {
    fn drop(&mut self) {
        self.provider.delete_sec_context(self.handle);
        self.handle = RawContext::NONE;
    }
}

/// Everything one handshake step needs from its caller.
///
/// Generic over the provider only because it borrows a [`NameGuard`]. Callers
/// outside this module fill the crate-visible [`StepOptions`] instead, which
/// [`SecurityContext::step`] converts into this.
#[allow(dead_code)]
struct HandshakeRequest<'a, P: GssProvider> {
    target: &'a NameGuard<P>,
    mechanism: Mechanism,
    mutual_auth: bool,
    delegation: Delegation,
    channel_binding_data: Option<&'a [u8]>,
    input_token: Option<&'a [u8]>,
    want_return_flags: bool,
}

/// What one successful handshake step produced.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HandshakeOutcome {
    /// Whether to send another token after this one.
    pub(crate) state: HandshakeState,
    /// The token to send, owned. May be empty: `lib/vauth/krb5_gssapi.c:154-157`
    /// treats an empty final token as legitimate under mutual authentication.
    pub(crate) token: Vec<u8>,
    /// The flags the library actually granted, meaningful only when the caller
    /// asked for them.
    pub(crate) flags: ContextFlags,
}

/// What `gss_wrap` produced.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SealedMessage {
    /// The wrapped token, owned.
    pub(crate) token: Vec<u8>,
    /// The `conf_state` the library reported: whether confidentiality was
    /// actually applied. `lib/socks_gssapi.c:385` collects this;
    /// `lib/vauth/krb5_gssapi.c:275` passes `NULL` and ignores it.
    pub(crate) confidential: bool,
}

// The error-text assembler
//
// `display_gss_error()` and `Curl_gss_log_error()` -- `lib/curl_gssapi.c:387-442`
// -- reproduced byte for byte. Generic over the provider so a multi-part
// status source can be faked in a test.

/// Append every part of one status value to `buffer`, mirroring
/// `display_gss_error()` at `lib/curl_gssapi.c:389-415`.
///
/// The loop is a `do`/`while`, so at least one call always happens, and it
/// continues `while(!GSS_ERROR(maj_stat) && msg_ctx)`: GSS-API returns
/// multi-part messages through the `msg_ctx` cursor, and a single call is not
/// enough.
#[allow(dead_code)]
fn append_status_parts<P: GssProvider>(
    provider: &P,
    status: GssStatusValue,
    status_type: c_int,
    buffer: &mut Vec<u8>,
) {
    let mut message_context: OmUint32 = 0;
    loop {
        let part = provider.display_status(
            status.0,
            status_type,
            &mut message_context,
        );

        if part.status.major == GSS_S_COMPLETE && !part.text.is_empty() {
            // `if(GSS_LOG_BUFFER_LEN > len + status_string.length + 3)`
            // (`:405`). The `+ 3` covers the two characters appended after the
            // text plus C's terminating NUL, so it is reproduced literally
            // rather than tightened.
            if GSS_LOG_BUFFER_LEN > buffer.len() + part.text.len() + 3 {
                // `"%.*s. "` (`:407`): the text, a period, a space. `%.*s`
                // stops at the first NUL as well as at the precision, so a
                // buffer with an embedded NUL is truncated there -- reproduced
                // so the assembled text matches C byte for byte even in that
                // pathological case.
                let end = part
                    .text
                    .iter()
                    .position(|&byte| byte == 0)
                    .unwrap_or(part.text.len());
                buffer.extend_from_slice(&part.text[..end]);
                buffer.extend_from_slice(b". ");
            }
        }

        // The library buffer for this part was already released by the
        // provider, which is what reproduces C's in-loop
        // `gss_release_buffer()` at `:411` rather than a single release after
        // the loop.
        if gss_error(part.status.major) != 0 || message_context == 0 {
            break;
        }
    }
}

/// A bare status value, so `append_status_parts` cannot be handed a major
/// where a minor was meant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
struct GssStatusValue(OmUint32);

/// `Curl_gss_log_error()` -- `lib/curl_gssapi.c:429-441`.
///
/// Returns the string C passes to `infof(data, "%s%s", prefix, buf)` rather
/// than logging it, because the sink is the caller's (see [`Diagnostics`]).
///
/// Two details are easy to get backwards and are therefore spelled out:
///
/// * the **major** status is rendered only when it is not `GSS_S_FAILURE`
///   (`:435`), because "General failure" adds nothing the minor status does
///   not say better;
/// * the **minor** status is rendered unconditionally (`:438`), with
///   `GSS_C_MECH_CODE` rather than `GSS_C_GSS_CODE`.
///
/// C's buffer is `char buf[1024] = ""`, so when neither status renders any text
/// the result is the bare prefix. That is reproduced.
#[allow(dead_code)]
fn describe<P: GssProvider>(
    provider: &P,
    prefix: &str,
    status: GssStatus,
) -> String {
    let mut buffer: Vec<u8> = Vec::new();

    if status.major != GSS_S_FAILURE {
        append_status_parts(
            provider,
            GssStatusValue(status.major),
            GSS_C_GSS_CODE,
            &mut buffer,
        );
    }

    append_status_parts(
        provider,
        GssStatusValue(status.minor),
        GSS_C_MECH_CODE,
        &mut buffer,
    );

    // GSS-API status strings are ASCII by RFC 2743, but a mechanism is not
    // obliged to prove it. Lossy conversion keeps this total -- a panic here
    // could unwind towards a C caller through `curl-rs-ffi`.
    let mut message = String::with_capacity(prefix.len() + buffer.len());
    message.push_str(prefix);
    message.push_str(&String::from_utf8_lossy(&buffer));
    message
}

// The crate-visible surface
//
// Thin newtypes over the `SystemGss` instantiation of the guards above. They
// exist so that no crate-visible item names the private `GssProvider` trait,
// and so that no crate-visible signature mentions a raw pointer, an
// `OM_uint32`, a `gss_*` handle, a `libc` type or an `unsafe fn`.

/// An imported GSS-API name: the service principal a handshake targets, or the
/// client principal an established context reports.
///
/// Supersedes the `gss_name_t` fields C keeps in `struct negotiatedata` and
/// `struct kerberos5data`, together with their hand-placed
/// `gss_release_name()` calls.
#[allow(dead_code)]
pub(crate) struct TargetName(NameGuard<SystemGss>);

impl TargetName {
    /// `gss_import_name` -- `lib/vauth/spnego_gssapi.c:117-127`,
    /// `lib/vauth/krb5_gssapi.c:109-118`, `lib/socks_gssapi.c:142-157`.
    ///
    /// `name` is the service principal in the mechanism's textual form; for
    /// [`NameType::HostBasedService`] that is `service@host`, which is what
    /// `Curl_auth_build_spn()` produces.
    ///
    /// # Errors
    ///
    /// [`CURLcode::AuthError`] if the name is empty or the mechanism rejects
    /// it. The library's own diagnosis goes to `diagnostics` first, under the
    /// same `"gss_import_name() failed: "` prefix C uses.
    #[allow(dead_code)]
    pub(crate) fn import(
        name: &[u8],
        kind: NameType,
        diagnostics: &mut dyn Diagnostics,
    ) -> Result<Self, CURLcode> {
        NameGuard::import(SystemGss, name, kind, diagnostics).map(Self)
    }

    /// `gss_display_name` -- `lib/socks_gssapi.c:304-314`.
    ///
    /// Returns the mechanism's textual rendering, owned. SOCKS5 logs it as the
    /// authenticated username.
    ///
    /// # Errors
    ///
    /// [`CURLcode::AuthError`] if the mechanism cannot render the name, or
    /// [`CURLcode::OutOfMemory`] if it reports a rendering larger than the
    /// address space can represent.
    #[allow(dead_code)]
    pub(crate) fn display(
        &self,
        diagnostics: &mut dyn Diagnostics,
    ) -> Result<Vec<u8>, CURLcode> {
        self.0.display(diagnostics)
    }
}

/// Everything [`SecurityContext::step`] needs, as named fields rather than a
/// thirteen-argument call.
///
/// The default is the shape SPNEGO uses: mutual authentication on, no
/// delegation, no channel bindings, no returned flags -- matching
/// `lib/vauth/spnego_gssapi.c:162-171`, which passes `TRUE` for `mutual_auth`
/// and `NULL` for `ret_flags`.
pub(crate) struct StepOptions<'a> {
    /// The imported service principal.
    #[allow(dead_code)]
    pub(crate) target: &'a TargetName,
    /// Which mechanism OID to negotiate.
    #[allow(dead_code)]
    pub(crate) mechanism: Mechanism,
    /// `GSS_C_MUTUAL_FLAG`. SPNEGO and SOCKS5 both pass `TRUE`
    /// (`lib/vauth/spnego_gssapi.c:170`, `lib/socks_gssapi.c:182`); SASL
    /// GSSAPI passes the caller's choice (`lib/vauth/krb5_gssapi.c:143`).
    #[allow(dead_code)]
    pub(crate) mutual_auth: bool,
    /// The `CURLOPT_GSSAPI_DELEGATION` mask.
    #[allow(dead_code)]
    pub(crate) delegation: Delegation,
    /// RFC 5929 channel-binding application data, or `None` for
    /// `GSS_C_NO_CHANNEL_BINDINGS`. Only SPNEGO supplies it, and only when the
    /// platform exposes `GSS_C_CHANNEL_BOUND_FLAG`
    /// (`lib/vauth/spnego_gssapi.c:152-159`).
    #[allow(dead_code)]
    pub(crate) channel_binding_data: Option<&'a [u8]>,
    /// The peer's token, or `None` for the first step. C leaves the descriptor
    /// as `GSS_C_EMPTY_BUFFER` in that case
    /// (`lib/vauth/spnego_gssapi.c:132-149`).
    #[allow(dead_code)]
    pub(crate) input_token: Option<&'a [u8]>,
    /// Whether to ask for `ret_flags`. Only SOCKS5 does, because it needs the
    /// protection bits (`lib/socks_gssapi.c:183`).
    #[allow(dead_code)]
    pub(crate) want_return_flags: bool,
}

impl<'a> StepOptions<'a> {
    /// The SPNEGO shape: mutual authentication, no delegation, no bindings, no
    /// returned flags.
    #[allow(dead_code)]
    pub(crate) fn new(target: &'a TargetName, mechanism: Mechanism) -> Self {
        Self {
            target,
            mechanism,
            mutual_auth: true,
            delegation: Delegation::NONE,
            channel_binding_data: None,
            input_token: None,
            want_return_flags: false,
        }
    }
}

/// An owned GSS-API security context, deleted exactly once.
///
/// Supersedes the `gss_ctx_id_t` C stores in `struct negotiatedata` and
/// `struct kerberos5data`, plus `Curl_gss_init_sec_context()` and
/// `Curl_gss_delete_sec_context()` (`lib/curl_gssapi.c:313-385`).
///
/// The whole lifecycle is here: a fresh value is `GSS_C_NO_CONTEXT`,
/// [`Self::step`] drives the handshake and adopts whatever handle the library
/// returns, and `Drop` deletes it. There is no way to observe a handle the
/// library has replaced, and no path -- early return, `?`, or panic -- that
/// leaks one or deletes one twice.
///
/// That last sentence is load-bearing rather than decorative, so the shape that
/// enforces it is worth naming: the provider's `init_sec_context` returns a
/// [`StepOutcome`] and *not* a `Result`, which leaves no expression between the
/// library call and the adoption for a `?` to occupy. The one fallible step --
/// copying the output token -- is carried inside that outcome and is unwrapped
/// only after the handle and the status have been stored.
#[allow(dead_code)]
pub(crate) struct SecurityContext(ContextGuard<SystemGss>);

impl SecurityContext {
    /// A context that has not been established yet: `GSS_C_NO_CONTEXT`.
    pub(crate) fn new() -> Self {
        Self(ContextGuard::new(SystemGss))
    }

    /// Whether the library has handed back a context handle.
    ///
    /// The `nego->context` half of the re-entry test at
    /// `lib/vauth/spnego_gssapi.c:96`.
    #[allow(dead_code)]
    pub(crate) fn exists(&self) -> bool {
        self.0.exists()
    }

    /// Whether a handshake completed successfully on this context.
    ///
    /// Both halves of `lib/vauth/spnego_gssapi.c:96`. A caller that sees this
    /// return `true` on a *fresh* challenge is in the situation C answers with
    /// `CURLE_LOGIN_DENIED` at `:101` -- the server rejected an authentication
    /// the client considered finished -- and that mapping stays with the caller,
    /// because only it knows a new challenge arrived.
    #[allow(dead_code)]
    pub(crate) fn is_established(&self) -> bool {
        self.0.is_established()
    }

    /// The status of the most recent step, meaningful even after a failure.
    ///
    /// This is `nego->status`, which `lib/vauth/spnego_gssapi.c:176` assigns
    /// before the error check and `lib/http_negotiate.c:237-238` reads back.
    #[allow(dead_code)]
    pub(crate) fn status(&self) -> GssStatus {
        self.0.status()
    }

    /// One handshake step -- `Curl_gss_init_sec_context()`,
    /// `lib/curl_gssapi.c:313-371`.
    ///
    /// # Errors
    ///
    /// [`CURLcode::AuthError`] when the library reports `GSS_ERROR`, having
    /// first sent the rendered major and minor statuses to `diagnostics` under
    /// the `"gss_init_sec_context() failed: "` prefix; or
    /// [`CURLcode::OutOfMemory`] if the output token cannot be copied into owned
    /// storage. The library error wins when both happen, since it is the one
    /// that explains the handshake. Consumers needing a different code map it --
    /// `lib/socks_gssapi.c:197` answers the same failure with
    /// `CURLE_COULDNT_CONNECT`.
    ///
    /// On every one of those paths the context handle the library returned has
    /// already been adopted and [`Self::status`] already updated, so both remain
    /// readable and `Drop` still deletes exactly the handle that is current.
    #[allow(dead_code)]
    pub(crate) fn step(
        &mut self,
        options: &StepOptions<'_>,
        diagnostics: &mut dyn Diagnostics,
    ) -> Result<HandshakeOutcome, CURLcode> {
        self.0.step(
            &HandshakeRequest {
                target: &options.target.0,
                mechanism: options.mechanism,
                mutual_auth: options.mutual_auth,
                delegation: options.delegation,
                channel_binding_data: options.channel_binding_data,
                input_token: options.input_token,
                want_return_flags: options.want_return_flags,
            },
            diagnostics,
        )
    }

    /// The client principal this context authenticated --
    /// `lib/socks_gssapi.c:296-303`.
    ///
    /// # Errors
    ///
    /// [`CURLcode::AuthError`] if the mechanism cannot report it.
    #[allow(dead_code)]
    pub(crate) fn source_name(
        &self,
        diagnostics: &mut dyn Diagnostics,
    ) -> Result<TargetName, CURLcode> {
        self.0.source_name(diagnostics).map(TargetName)
    }

    /// `gss_wrap` with `GSS_C_QOP_DEFAULT` -- `lib/socks_gssapi.c:383-385`,
    /// `lib/vauth/krb5_gssapi.c:274-276`.
    ///
    /// `confidentiality` is C's `conf_req_flag`, which both call sites pass as
    /// `0`; the parameter exists because the value is observable in
    /// [`SealedMessage::confidential`] and forcing it to `false` here would
    /// hide a capability the ABI exposes.
    ///
    /// # Errors
    ///
    /// [`CURLcode::AuthError`] if the mechanism refuses, or
    /// [`CURLcode::OutOfMemory`] if the sealed token is unrepresentable.
    #[allow(dead_code)]
    pub(crate) fn wrap(
        &self,
        confidentiality: bool,
        plain: &[u8],
        diagnostics: &mut dyn Diagnostics,
    ) -> Result<SealedMessage, CURLcode> {
        self.0.wrap(confidentiality, plain, diagnostics)
    }

    /// `gss_unwrap` -- `lib/socks_gssapi.c:477-479`,
    /// `lib/vauth/krb5_gssapi.c:209-210`.
    ///
    /// # Errors
    ///
    /// [`CURLcode::BadContentEncoding`] for an empty input or a token the
    /// mechanism rejects, matching `lib/vauth/krb5_gssapi.c:201` and `:214`;
    /// or [`CURLcode::OutOfMemory`] if the plaintext is unrepresentable.
    #[allow(dead_code)]
    pub(crate) fn unwrap(
        &self,
        sealed: &[u8],
        diagnostics: &mut dyn Diagnostics,
    ) -> Result<Vec<u8>, CURLcode> {
        self.0.unwrap(sealed, diagnostics)
    }

    /// Delete the context and return to the pre-handshake state --
    /// `Curl_auth_cleanup_spnego()`, `lib/vauth/spnego_gssapi.c:262-268`.
    #[allow(dead_code)]
    pub(crate) fn reset(&mut self) {
        self.0.reset();
    }
}

impl Default for SecurityContext {
    fn default() -> Self {
        Self::new()
    }
}

// The runtime availability predicate

/// The name the availability probe imports.
///
/// A host-based service name is the cheapest thing that still exercises the
/// mechanism glue: `gss_import_name` performs no I/O, touches no credential
/// cache and contacts no KDC, so calling it has no observable effect beyond a
/// transient allocation.
const AVAILABILITY_PROBE_NAME: &[u8] = b"host@localhost";

/// Whether GSS-API is genuinely usable in this process, right now.
///
/// This is the predicate `src/version.rs` must consult before it puts
/// `GSS-API`, `SPNEGO` or `Kerberos` in the `Features:` line of
/// `curl --version`. It does not consult it yet: at this commit those three
/// entries are gated on `cfg!(feature = "negotiate")` alone, which is the
/// weaker test. A compile-time `cfg!` does not suffice, because a binary can be
/// *built* with the feature on a host where the runtime library is present but
/// unusable -- no mechanism configured, a broken `/etc/gss` or `gss_mech`
/// setup -- and over-reporting in that state turns a clean fixture skip into a
/// hard failure. `tests/runtests.pl` believes the banner, so the banner must
/// be true.
///
/// Total by construction: it returns a `bool`, never panics, never propagates
/// an error, and performs no I/O. The answer is computed once and cached, so
/// repeated calls -- the banner is assembled more than once -- cost nothing and
/// cannot disagree with each other.
/// # Under Miri
///
/// Answers `false` without probing. Miri interprets rather than links, so
/// calling `gss_import_name` there is an unsupported operation that aborts the
/// run -- and that is not a defect to be worked around but the literal truth
/// about the environment: no GSS-API mechanism is reachable from a Miri
/// execution, so "unavailable" is the accurate answer as well as the
/// conservative one.
///
/// The alternative would have been to mark every test that transitively reaches
/// this predicate as `#[cfg_attr(miri, ignore)]`. That was rejected: `version.rs`
/// consults it while assembling the whole capability banner, so `features_bitmask`
/// and `feature_names` reach it, and ignoring their tests would surrender Miri
/// coverage of 32 unrelated rows to shield one. Deciding here costs nothing --
/// [`available_with`] is fully covered under Miri through `FakeGss`, so the logic
/// this shortcut skips is tested, only the linkage is not.
pub(crate) fn available() -> bool {
    #[cfg(miri)]
    {
        false
    }

    #[cfg(not(miri))]
    {
        static AVAILABLE: OnceLock<bool> = OnceLock::new();
        *AVAILABLE.get_or_init(|| available_with(&SystemGss))
    }
}

/// The provider-parameterised body of [`available`], so the predicate itself
/// can be tested -- including under Miri, which cannot call into a real
/// GSS-API library.
fn available_with<P: GssProvider>(provider: &P) -> bool {
    let outcome = provider
        .import_name(AVAILABILITY_PROBE_NAME, NameType::HostBasedService);
    // Release whatever came back before judging it. RFC 2744 says a failed
    // call leaves `GSS_C_NO_NAME`, but a mechanism that breaks that promise
    // must not be allowed to leak, and `release_name` ignores the null case.
    provider.release_name(outcome.name);
    !outcome.status.is_error()
}

// Tests
//
// `tests/unit/*.c` and `tests/libtest/*.c` link a debug static libcurl and
// call internal `Curl_*` symbols. A Rust static library does not export
// `pub(crate)` items -- they are genuinely absent from the symbol table, not
// merely hidden -- so no quality of implementation makes those programs link,
// and their coverage is relocated here instead.
//
// Everything below runs against `FakeGss`, a pure-Rust double, which is why it
// all runs under `cargo miri test` as well: Miri cannot call into a real
// GSS-API library, so a seam that only *looked* substitutable would show up
// here as an untestable gap.

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    // ---- the double -------------------------------------------------------

    /// One scripted `gss_display_status` response.
    #[derive(Clone)]
    struct StatusPart {
        text: Vec<u8>,
        /// The cursor the library should leave behind. Non-zero means "another
        /// part follows", which is what drives C's `while(... && msg_ctx)`.
        next_context: OmUint32,
        major: OmUint32,
    }

    impl StatusPart {
        fn last(text: &str) -> Self {
            Self {
                text: text.as_bytes().to_vec(),
                next_context: 0,
                major: GSS_S_COMPLETE,
            }
        }

        fn more(text: &str) -> Self {
            Self {
                text: text.as_bytes().to_vec(),
                next_context: 1,
                major: GSS_S_COMPLETE,
            }
        }
    }

    #[derive(Default)]
    struct Journal {
        imported: Vec<(Vec<u8>, NameType)>,
        names_released: usize,
        contexts_deleted: usize,
        /// *Which* handles were deleted, in order.
        ///
        /// The count above answers "how many times", which is enough to catch a
        /// leak or a double delete of the same value. It cannot distinguish
        /// deleting the handle that is current from deleting one the library
        /// already destroyed and replaced -- both are exactly one deletion. That
        /// is the question the ownership tests below ask, so the identity is
        /// recorded too.
        deleted: Vec<RawContext>,
        display_status_calls: Vec<(OmUint32, c_int)>,
        wrapped: Vec<(bool, Vec<u8>)>,
        unwrapped: Vec<Vec<u8>>,
        step_flags: Vec<OmUint32>,
        /// The handle each step was *given*, before any substitution.
        stepped_from: Vec<RawContext>,
    }

    /// A pure-Rust `GssProvider`. Handles are opaque integers cast to
    /// pointers; nothing is ever dereferenced, so Miri is satisfied.
    struct FakeGss {
        journal: RefCell<Journal>,
        import_major: OmUint32,
        import_returns_handle: bool,
        step_major: OmUint32,
        step_token: Vec<u8>,
        step_flags: OmUint32,
        /// `Some(n)` replaces the context handle with `n` on each step, which
        /// is how the in/out parameter is exercised.
        ///
        /// A `Cell` so a test can change the answer *between* steps: proving
        /// that a failing step retires the handle a previous successful step
        /// installed requires the two steps to return different handles.
        step_handle: Cell<Option<usize>>,
        /// Fails only the step's token copy, leaving the status and the handle
        /// substitution intact.
        ///
        /// Distinct from `oversize`, which fails every buffer copy in the
        /// double, and a `Cell` for the same reason as `step_handle`: the
        /// interesting case is a step that fails *after* an earlier one
        /// succeeded.
        token_copy_fails: Cell<bool>,
        display_status_parts: Vec<StatusPart>,
        display_name_major: OmUint32,
        display_name_text: Vec<u8>,
        source_name_major: OmUint32,
        wrap_major: OmUint32,
        wrap_token: Vec<u8>,
        wrap_confidential: bool,
        unwrap_major: OmUint32,
        unwrap_token: Vec<u8>,
        /// Forces the oversize-token path that maps to `CURLE_OUT_OF_MEMORY`.
        oversize: bool,
    }

    impl Default for FakeGss {
        fn default() -> Self {
            Self {
                journal: RefCell::new(Journal::default()),
                import_major: GSS_S_COMPLETE,
                import_returns_handle: true,
                step_major: GSS_S_COMPLETE,
                step_token: b"token".to_vec(),
                step_flags: 0,
                step_handle: Cell::new(Some(STEPPED_CONTEXT_SLOT)),
                token_copy_fails: Cell::new(false),
                display_status_parts: vec![StatusPart::last(
                    "Unspecified GSS failure",
                )],
                display_name_major: GSS_S_COMPLETE,
                display_name_text: b"alice@EXAMPLE.COM".to_vec(),
                source_name_major: GSS_S_COMPLETE,
                wrap_major: GSS_S_COMPLETE,
                wrap_token: b"sealed".to_vec(),
                wrap_confidential: false,
                unwrap_major: GSS_S_COMPLETE,
                unwrap_token: b"plain".to_vec(),
                oversize: false,
            }
        }
    }

    /// Distinct stand-ins for the opaque handles a real mechanism would return.
    ///
    /// Backed by a genuine static rather than produced by an integer-to-pointer
    /// cast, so the double carries real pointer provenance and
    /// `cargo miri test -Zmiri-strict-provenance` accepts it. (A cast such as
    /// `1usize as *mut c_void` is accepted by default Miri but rejected under
    /// strict provenance, and `ptr::without_provenance_mut` only stabilised
    /// after MSRV 1.75.) Nothing ever dereferences these; the guards only ever
    /// compare them against null and hand them back to the double.
    static HANDLE_SLOTS: [u8; 4] = [0, 1, 2, 3];

    /// The slot the double reports from `import_name`.
    const IMPORTED_NAME_SLOT: usize = 1;
    /// The slot the double reports from `source_name`.
    const SOURCE_NAME_SLOT: usize = 2;
    /// The slot the double substitutes into the in/out context handle.
    const STEPPED_CONTEXT_SLOT: usize = 3;
    /// The slot the double substitutes on the *first* of two steps, so that a
    /// test can tell a replaced handle apart from the one it replaced. Uses the
    /// otherwise spare slot 0.
    const FIRST_CONTEXT_SLOT: usize = 0;

    fn handle(slot: usize) -> *mut c_void {
        // `cast_mut` rather than an `as` cast so the intent is explicit; the
        // pointer is never written through, and never read through either.
        let byte: *const u8 = &HANDLE_SLOTS[slot];
        byte.cast_mut().cast::<c_void>()
    }

    impl FakeGss {
        fn oversize_guard(&self) -> Result<(), CURLcode> {
            if self.oversize {
                Err(CURLcode::OutOfMemory)
            } else {
                Ok(())
            }
        }
    }

    impl GssProvider for FakeGss {
        fn import_name(&self, name: &[u8], kind: NameType) -> NameOutcome {
            self.journal
                .borrow_mut()
                .imported
                .push((name.to_vec(), kind));
            NameOutcome {
                status: GssStatus::new(self.import_major, 7),
                name: if self.import_returns_handle {
                    RawName(handle(IMPORTED_NAME_SLOT))
                } else {
                    RawName::NONE
                },
            }
        }

        fn release_name(&self, name: RawName) {
            if name.is_none() {
                return;
            }
            self.journal.borrow_mut().names_released += 1;
        }

        fn delete_sec_context(&self, context: RawContext) {
            if context.is_none() {
                return;
            }
            let mut journal = self.journal.borrow_mut();
            journal.contexts_deleted += 1;
            journal.deleted.push(context);
        }

        fn init_sec_context(
            &self,
            context: RawContext,
            request: &StepRequest<'_>,
        ) -> StepOutcome {
            {
                let mut journal = self.journal.borrow_mut();
                journal.step_flags.push(request.flags);
                journal.stepped_from.push(context);
            }
            let copy_fails = self.oversize || self.token_copy_fails.get();
            StepOutcome {
                status: GssStatus::new(self.step_major, 9),
                // The substitution happens whether or not the token can be
                // copied, because that is the order the real library imposes:
                // `gss_init_sec_context` writes `context_handle` before it
                // returns, and copying its output buffer is something this side
                // does afterwards. A double that failed *before* substituting --
                // as this one previously did -- cannot catch a caller that
                // forgets to adopt the replacement, which is why the ownership
                // defect survived the original test suite.
                context: self
                    .step_handle
                    .get()
                    .map_or(context, |value| RawContext(handle(value))),
                token: if copy_fails {
                    Err(CURLcode::OutOfMemory)
                } else {
                    Ok(self.step_token.clone())
                },
                flags: ContextFlags(self.step_flags),
            }
        }

        fn display_status(
            &self,
            status: OmUint32,
            status_type: c_int,
            message_context: &mut OmUint32,
        ) -> StatusText {
            let index = *message_context as usize;
            self.journal
                .borrow_mut()
                .display_status_calls
                .push((status, status_type));
            match self.display_status_parts.get(index) {
                Some(part) => {
                    *message_context = part.next_context;
                    StatusText {
                        status: GssStatus::new(part.major, 0),
                        text: part.text.clone(),
                    }
                }
                None => {
                    *message_context = 0;
                    StatusText {
                        status: GssStatus::new(GSS_S_FAILURE, 0),
                        text: Vec::new(),
                    }
                }
            }
        }

        fn display_name(
            &self,
            _name: RawName,
        ) -> Result<TokenOutcome, CURLcode> {
            self.oversize_guard()?;
            Ok(TokenOutcome {
                status: GssStatus::new(self.display_name_major, 0),
                token: self.display_name_text.clone(),
            })
        }

        fn source_name(&self, _context: RawContext) -> NameOutcome {
            NameOutcome {
                status: GssStatus::new(self.source_name_major, 0),
                name: RawName(handle(SOURCE_NAME_SLOT)),
            }
        }

        fn wrap(
            &self,
            _context: RawContext,
            confidentiality: bool,
            plain: &[u8],
        ) -> Result<WrapOutcome, CURLcode> {
            self.oversize_guard()?;
            self.journal
                .borrow_mut()
                .wrapped
                .push((confidentiality, plain.to_vec()));
            Ok(WrapOutcome {
                status: GssStatus::new(self.wrap_major, 0),
                token: self.wrap_token.clone(),
                confidential: self.wrap_confidential,
            })
        }

        fn unwrap(
            &self,
            _context: RawContext,
            sealed: &[u8],
        ) -> Result<TokenOutcome, CURLcode> {
            self.oversize_guard()?;
            self.journal.borrow_mut().unwrapped.push(sealed.to_vec());
            Ok(TokenOutcome {
                status: GssStatus::new(self.unwrap_major, 0),
                token: self.unwrap_token.clone(),
            })
        }
    }

    /// A sink that keeps what it was told, so the exact `infof()` text can be
    /// asserted.
    #[derive(Default)]
    struct Recorder {
        lines: Vec<String>,
    }

    impl Diagnostics for Recorder {
        fn infof(&mut self, message: &str) {
            self.lines.push(message.to_owned());
        }
    }

    // ---- the mechanism OIDs ----------------------------------------------

    #[test]
    fn spnego_oid_is_byte_exact() {
        // lib/curl_gssapi.c:64 -- { 6, "\x2b\x06\x01\x05\x05\x02" }
        assert_eq!(
            SPNEGO_MECH_OID_BYTES,
            [0x2b, 0x06, 0x01, 0x05, 0x05, 0x02],
            "SPNEGO mechanism OID 1.3.6.1.5.5.2"
        );
        assert_eq!(SPNEGO_MECH_OID.length, 6, "the declared length is 6");
        assert_eq!(SPNEGO_MECH_OID.as_bytes(), &SPNEGO_MECH_OID_BYTES[..]);
        assert_eq!(Mechanism::Spnego.oid_bytes(), &SPNEGO_MECH_OID_BYTES[..]);
    }

    #[test]
    fn krb5_oid_is_byte_exact() {
        // lib/curl_gssapi.c:67 -- { 9, "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02" }
        assert_eq!(
            KRB5_MECH_OID_BYTES,
            [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02],
            "Kerberos 5 mechanism OID 1.2.840.113554.1.2.2"
        );
        assert_eq!(KRB5_MECH_OID.length, 9, "the declared length is 9");
        assert_eq!(KRB5_MECH_OID.as_bytes(), &KRB5_MECH_OID_BYTES[..]);
        assert_eq!(Mechanism::Krb5.oid_bytes(), &KRB5_MECH_OID_BYTES[..]);
    }

    #[test]
    fn hostbased_service_oid_is_byte_exact() {
        // Printed from libgssapi_krb5.so.2 at run time: length 10, OID
        // 1.2.840.113554.1.2.1.4.
        assert_eq!(
            HOSTBASED_SERVICE_OID_BYTES,
            [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x01, 0x04]
        );
        assert_eq!(HOSTBASED_SERVICE_OID.length, 10);
        assert!(NameType::HostBasedService.descriptor().is_some());
        assert!(
            NameType::Unspecified.descriptor().is_none(),
            "GSS_C_NULL_OID is a null pointer, not a descriptor"
        );
    }

    #[test]
    fn oid_descriptors_are_eight_byte_aligned() {
        // `CURL_ALIGN8` -- lib/curl_gssapi.c:52-56. The descriptors are passed
        // by pointer into C, so an under-aligned one is undefined behaviour.
        for (name, descriptor) in [
            ("SPNEGO", &SPNEGO_MECH_OID),
            ("Kerberos 5", &KRB5_MECH_OID),
            ("hostbased-service", &HOSTBASED_SERVICE_OID),
        ] {
            let address = descriptor as *const GssOidDesc as usize;
            assert_eq!(
                address % 8,
                0,
                "{name} descriptor must be 8-byte aligned"
            );
        }
        assert_eq!(core::mem::align_of::<GssOidDesc>(), 8);
    }

    // ---- C layout --------------------------------------------------------

    #[test]
    fn c_layouts_match_the_measured_headers() {
        // Values printed by a compiled sizeof/offsetof probe against
        // /usr/include/mit-krb5/gssapi/gssapi.h.
        assert_eq!(core::mem::size_of::<OmUint32>(), 4, "OM_uint32 is 32 bits");
        assert_eq!(core::mem::size_of::<GssBufferDesc>(), 16);
        assert_eq!(core::mem::align_of::<GssBufferDesc>(), 8);
        assert_eq!(core::mem::size_of::<GssOidDesc>(), 16);
        assert_eq!(core::mem::size_of::<GssChannelBindings>(), 64);
        assert_eq!(core::mem::align_of::<GssChannelBindings>(), 8);
        // The opaque handles must be exactly pointer-shaped, or passing them
        // by value across the ABI would be wrong.
        assert_eq!(
            core::mem::size_of::<RawContext>(),
            core::mem::size_of::<*mut c_void>()
        );
        assert_eq!(
            core::mem::size_of::<RawName>(),
            core::mem::size_of::<*mut c_void>()
        );
        assert_eq!(
            core::mem::size_of::<RawCredential>(),
            core::mem::size_of::<*mut c_void>()
        );
    }

    #[test]
    fn empty_and_borrowing_buffers_are_built_correctly() {
        let empty = GssBufferDesc::EMPTY;
        assert_eq!(empty.length, 0);
        assert!(empty.value.is_null(), "GSS_C_EMPTY_BUFFER is {{0, NULL}}");

        let payload = b"abc";
        let borrowed = GssBufferDesc::borrowing(payload);
        assert_eq!(borrowed.length, 3);
        assert_eq!(borrowed.value.cast::<u8>().cast_const(), payload.as_ptr());

        // A zero-length slice still yields a non-null, dangling-but-aligned
        // pointer, which GSS-API never reads because the length is zero.
        let none = GssBufferDesc::borrowing(&[]);
        assert_eq!(none.length, 0);
    }

    /// Neutralise a hand-built descriptor before it can drop.
    ///
    /// `LibraryBuffer::drop` hands a non-null `value` to the real
    /// `gss_release_buffer`. These tests build descriptors that point at static
    /// storage rather than at a library allocation, so they must be reset to
    /// `GSS_C_EMPTY_BUFFER` -- which `drop` ignores -- before going out of
    /// scope. Resetting rather than `mem::forget` keeps the guard's own
    /// early-return path on the tested path.
    fn defuse(buffer: &mut LibraryBuffer) {
        buffer.descriptor = GssBufferDesc::EMPTY;
    }

    #[test]
    fn an_absent_or_zero_length_buffer_copies_to_an_empty_vec() {
        static ONE_BYTE: u8 = 0xa5;

        // GSS_C_EMPTY_BUFFER: nothing was ever allocated.
        //
        // The expected value is spelled `Vec::<u8>::new()` rather than `&[]`
        // because a bare empty slice literal leaves its element type to
        // inference, and inference fails outright in any dependency graph
        // carrying a second `PartialEq<_> for u8` implementation. Naming the
        // type keeps this assertion compiling for every consumer instead of
        // only for the graphs that happen to have one candidate.
        let absent = LibraryBuffer::empty();
        assert_eq!(
            absent.to_owned_vec().expect("no buffer is not an error"),
            Vec::<u8>::new()
        );

        // A non-null pointer with a zero length, which a mechanism may report
        // for an empty final token: `lib/vauth/krb5_gssapi.c:154-157` treats one
        // as legitimate.
        let mut zero_length = LibraryBuffer::empty();
        zero_length.descriptor.value =
            core::ptr::addr_of!(ONE_BYTE).cast_mut().cast::<c_void>();
        assert_eq!(
            zero_length
                .to_owned_vec()
                .expect("a zero length is not an error"),
            Vec::<u8>::new()
        );
        defuse(&mut zero_length);
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "Miri raises 'resource exhaustion' as an interpreter error \
                  instead of returning AllocError, so the branch under test is \
                  unreachable there; native execution covers it"
    )]
    fn a_token_the_allocator_cannot_serve_is_reported_not_aborted() {
        // The whole point of the fallible reservation. `[u8]::to_vec` and
        // `Vec::extend_from_slice` allocate infallibly: on refusal they call
        // `handle_alloc_error`, which aborts the process -- so a mechanism
        // reporting an impossible length would kill the application instead of
        // failing one authentication. Both branches must report instead.
        static ONE_BYTE: u8 = 0xa5;
        let pointer = core::ptr::addr_of!(ONE_BYTE).cast_mut().cast::<c_void>();

        // Above `isize::MAX`: rejected before anything is attempted.
        let mut unrepresentable = LibraryBuffer::empty();
        unrepresentable.descriptor.value = pointer;
        unrepresentable.descriptor.length = (isize::MAX as usize) + 1;
        assert_eq!(
            unrepresentable
                .to_owned_vec()
                .expect_err("a length no slice could describe is refused"),
            CURLcode::OutOfMemory
        );
        defuse(&mut unrepresentable);

        // Representable but unallocatable: this is the case the reservation
        // catches, and it is caught *before* the raw slice is formed, so no
        // slice spanning unmapped memory is ever constructed.
        let mut unallocatable = LibraryBuffer::empty();
        unallocatable.descriptor.value = pointer;
        unallocatable.descriptor.length = (isize::MAX as usize) - 4096;
        assert_eq!(
            unallocatable
                .to_owned_vec()
                .expect_err("a length the allocator cannot serve is refused"),
            CURLcode::OutOfMemory
        );
        defuse(&mut unallocatable);
    }

    #[test]
    fn channel_bindings_zero_everything_but_application_data() {
        // lib/vauth/spnego_gssapi.c:154-157 memsets the struct and fills only
        // application_data.
        let data = b"tls-server-end-point:xyz";
        let bindings = channel_bindings(data);
        assert_eq!(bindings.initiator_addrtype, 0);
        assert_eq!(bindings.acceptor_addrtype, 0);
        assert_eq!(bindings.initiator_address.length, 0);
        assert!(bindings.initiator_address.value.is_null());
        assert_eq!(bindings.acceptor_address.length, 0);
        assert!(bindings.acceptor_address.value.is_null());
        assert_eq!(bindings.application_data.length, data.len());
    }

    #[test]
    fn null_handles_are_the_gss_c_no_constants() {
        assert!(RawContext::NONE.is_none());
        assert!(RawName::NONE.is_none());
        assert!(RawCredential::NONE.0.is_null());
        assert!(!RawName(handle(1)).is_none());
        assert!(!RawContext(handle(1)).is_none());
    }

    // ---- protection levels ------------------------------------------------

    #[test]
    fn protection_level_constants_match_the_c_header() {
        // lib/curl_gssapi.h:65-67
        assert_eq!(GSSAUTH_P_NONE, 1);
        assert_eq!(GSSAUTH_P_INTEGRITY, 2);
        assert_eq!(GSSAUTH_P_PRIVACY, 4);
        // lib/socks_gssapi.c:330-335 -- a different encoding of the same idea.
        assert_eq!(SOCKS5_PROTECTION_NONE, 0);
        assert_eq!(SOCKS5_PROTECTION_INTEGRITY, 1);
        assert_eq!(SOCKS5_PROTECTION_CONFIDENTIALITY, 2);
    }

    #[test]
    fn socks5_protection_level_prefers_confidentiality() {
        assert_eq!(
            ContextFlags(GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG)
                .socks5_protection_level(),
            SOCKS5_PROTECTION_CONFIDENTIALITY
        );
        assert_eq!(
            ContextFlags(GSS_C_INTEG_FLAG).socks5_protection_level(),
            SOCKS5_PROTECTION_INTEGRITY
        );
        assert_eq!(
            ContextFlags(0).socks5_protection_level(),
            SOCKS5_PROTECTION_NONE
        );
    }

    #[test]
    fn context_flag_accessors_read_the_right_bits() {
        let all = ContextFlags(
            GSS_C_DELEG_FLAG
                | GSS_C_MUTUAL_FLAG
                | GSS_C_REPLAY_FLAG
                | GSS_C_CONF_FLAG
                | GSS_C_INTEG_FLAG,
        );
        assert!(all.has_delegation());
        assert!(all.has_mutual_auth());
        assert!(all.has_replay_detection());
        assert!(all.has_confidentiality());
        assert!(all.has_integrity());

        let none = ContextFlags::default();
        assert!(!none.has_delegation());
        assert!(!none.has_mutual_auth());
        assert!(!none.has_replay_detection());
        assert!(!none.has_confidentiality());
        assert!(!none.has_integrity());
    }

    // ---- GSS_ERROR and status classification ------------------------------

    #[test]
    fn gss_error_masks_only_the_calling_and_routine_fields() {
        assert_eq!(GSS_ERROR_MASK, 0xffff_0000);
        assert_eq!(gss_error(GSS_S_COMPLETE), 0);
        assert_eq!(
            gss_error(GSS_S_CONTINUE_NEEDED),
            0,
            "GSS_S_CONTINUE_NEEDED is supplementary, not an error"
        );
        assert_ne!(gss_error(GSS_S_FAILURE), 0);
        // GSS_S_FAILURE is 13 << GSS_C_ROUTINE_ERROR_OFFSET; the probe printed
        // 851968.
        assert_eq!(GSS_S_FAILURE, 851_968);
        // A calling error in the top octet also counts.
        assert_ne!(gss_error(1 << 24), 0);
    }

    #[test]
    fn status_classification_matches_the_c_comparisons() {
        let complete = GssStatus::new(GSS_S_COMPLETE, 0);
        assert!(!complete.is_error());
        assert_eq!(complete.state(), Some(HandshakeState::Complete));
        assert!(complete.is_complete());
        assert!(!complete.is_continue_needed());

        let more = GssStatus::new(GSS_S_CONTINUE_NEEDED, 0);
        assert!(!more.is_error());
        assert_eq!(more.state(), Some(HandshakeState::ContinueNeeded));
        assert!(more.is_continue_needed());
        assert!(!more.is_complete());

        let failed = GssStatus::new(GSS_S_FAILURE, 42);
        assert!(failed.is_error());
        assert_eq!(failed.state(), None, "an error has no handshake position");
        assert!(!failed.is_complete());
        assert!(!failed.is_continue_needed());

        assert_eq!(GssStatus::COMPLETE, complete);
    }

    // ---- the request-flag composition ------------------------------------

    #[test]
    fn request_flags_seed_is_replay_not_zero() {
        // lib/curl_gssapi.c:324 -- OM_uint32 req_flags = GSS_C_REPLAY_FLAG;
        let flags = request_flags(false, Delegation::NONE, true);
        assert_eq!(flags.flags, GSS_C_REPLAY_FLAG);
        assert_ne!(flags.flags, 0, "seeding from zero changes the context");
        assert!(flags.warning().is_none());
        assert!(flags.as_context_flags().has_replay_detection());
    }

    #[test]
    fn request_flags_covers_every_combination() {
        let policy = Delegation::from_option_value(1);
        let always = Delegation::from_option_value(2);
        let both = Delegation::from_option_value(3);

        // (mutual_auth, delegation) across all four shapes, with the
        // delegation-policy flag available.
        assert_eq!(
            request_flags(false, Delegation::NONE, true).flags,
            GSS_C_REPLAY_FLAG
        );
        assert_eq!(
            request_flags(true, Delegation::NONE, true).flags,
            GSS_C_REPLAY_FLAG | GSS_C_MUTUAL_FLAG
        );
        assert_eq!(
            request_flags(false, policy, true).flags,
            GSS_C_REPLAY_FLAG | GSS_C_DELEG_POLICY_FLAG
        );
        assert_eq!(
            request_flags(true, policy, true).flags,
            GSS_C_REPLAY_FLAG | GSS_C_MUTUAL_FLAG | GSS_C_DELEG_POLICY_FLAG
        );
        assert_eq!(
            request_flags(false, always, true).flags,
            GSS_C_REPLAY_FLAG | GSS_C_DELEG_FLAG
        );
        assert_eq!(
            request_flags(true, both, true).flags,
            GSS_C_REPLAY_FLAG
                | GSS_C_MUTUAL_FLAG
                | GSS_C_DELEG_POLICY_FLAG
                | GSS_C_DELEG_FLAG
        );
    }

    #[test]
    fn request_flags_reports_the_verbatim_warning_when_policy_is_unsupported() {
        // lib/curl_gssapi.c:332-335 -- the GNU GSS branch.
        let flags =
            request_flags(false, Delegation::from_option_value(1), false);
        assert_eq!(
            flags.flags, GSS_C_REPLAY_FLAG,
            "the policy flag must not be set when the platform lacks it"
        );
        assert_eq!(
            flags.warning(),
            Some("WARNING: support for CURLGSSAPI_DELEGATION_POLICY_FLAG not compiled in")
        );
        assert_eq!(
            flags.warning(),
            Some(DELEGATION_POLICY_UNSUPPORTED_WARNING)
        );

        // The unconditional flag is still honoured on the same platform.
        let both =
            request_flags(false, Delegation::from_option_value(3), false);
        assert_eq!(both.flags, GSS_C_REPLAY_FLAG | GSS_C_DELEG_FLAG);
        assert!(both.warning().is_some());

        // No warning when policy delegation was not asked for.
        assert!(request_flags(true, Delegation::from_option_value(2), false)
            .warning()
            .is_none());
    }

    #[test]
    fn delegation_bits_match_the_public_header() {
        // include/curl/curl.h:861-863
        assert_eq!(Delegation::NONE, Delegation::from_option_value(0));
        assert!(!Delegation::NONE.policy());
        assert!(!Delegation::NONE.always());
        assert!(Delegation::from_option_value(1).policy());
        assert!(!Delegation::from_option_value(1).always());
        assert!(Delegation::from_option_value(2).always());
        assert!(!Delegation::from_option_value(2).policy());
        assert!(Delegation::from_option_value(3).policy());
        assert!(Delegation::from_option_value(3).always());
        // Unknown bits are preserved, not rejected, exactly as C ignores them.
        assert!(!Delegation::from_option_value(4).policy());
        assert!(!Delegation::from_option_value(4).always());
        assert_eq!(Delegation::default(), Delegation::NONE);
        // `DELEGATION_POLICY_FLAG_SUPPORTED` is asserted through its effect
        // rather than directly: a bare assertion on a `const bool` is a
        // tautology. Every mandated target defines GSS_C_DELEG_POLICY_FLAG
        // (MIT Kerberos 1.8+ and Apple's GSS.framework both do), so composing
        // with the real constant must set the flag and emit no warning.
        let composed = request_flags(
            false,
            Delegation::from_option_value(1),
            DELEGATION_POLICY_FLAG_SUPPORTED,
        );
        assert_eq!(composed.flags, GSS_C_REPLAY_FLAG | GSS_C_DELEG_POLICY_FLAG);
        assert!(composed.warning().is_none());
        assert_eq!(GSS_C_DELEG_POLICY_FLAG, 32_768);
    }

    // ---- the error-text assembler ----------------------------------------

    #[test]
    fn describe_joins_parts_with_period_space() {
        // lib/curl_gssapi.c:407 -- "%.*s. "
        let fake = FakeGss {
            display_status_parts: vec![StatusPart::last(
                "Unspecified GSS failure",
            )],
            ..FakeGss::default()
        };
        let text = describe(
            &fake,
            "gss_init_sec_context() failed: ",
            GssStatus::new(0, 0),
        );
        assert_eq!(
            text,
            "gss_init_sec_context() failed: Unspecified GSS failure. \
             Unspecified GSS failure. ",
            "the major and the minor status are both rendered"
        );
    }

    #[test]
    fn describe_walks_the_multipart_message_context_cursor() {
        // lib/curl_gssapi.c:412 -- while(!GSS_ERROR(maj_stat) && msg_ctx)
        let fake = FakeGss {
            display_status_parts: vec![
                StatusPart::more("first part"),
                StatusPart::last("second part"),
            ],
            ..FakeGss::default()
        };
        let text = describe(&fake, "", GssStatus::new(GSS_S_FAILURE, 0));
        // GSS_S_FAILURE suppresses the major (`:435`), so only the minor is
        // rendered -- and it is rendered in two parts.
        assert_eq!(text, "first part. second part. ");
        let calls = fake.journal.borrow().display_status_calls.clone();
        assert_eq!(calls.len(), 2);
        assert!(
            calls.iter().all(|&(_, kind)| kind == GSS_C_MECH_CODE),
            "a suppressed major means every call is GSS_C_MECH_CODE"
        );
    }

    #[test]
    fn describe_suppresses_the_major_only_for_gss_s_failure() {
        let fake = FakeGss::default();
        describe(&fake, "", GssStatus::new(GSS_S_FAILURE, 5));
        assert_eq!(
            fake.journal.borrow().display_status_calls,
            vec![(5, GSS_C_MECH_CODE)],
            "GSS_S_FAILURE renders the minor alone"
        );

        let other = FakeGss::default();
        let major = 1 << 16; // GSS_S_BAD_MECH
        describe(&other, "", GssStatus::new(major, 5));
        assert_eq!(
            other.journal.borrow().display_status_calls,
            vec![(major, GSS_C_GSS_CODE), (5, GSS_C_MECH_CODE)],
            "any other major renders first, with GSS_C_GSS_CODE"
        );
    }

    #[test]
    fn describe_respects_the_1024_byte_bound() {
        // lib/curl_gssapi.c:405 -- if(GSS_LOG_BUFFER_LEN > len + length + 3)
        assert_eq!(GSS_LOG_BUFFER_LEN, 1024);
        let long = "x".repeat(600);
        let fake = FakeGss {
            display_status_parts: vec![
                StatusPart::more(&long),
                StatusPart::last(&long),
            ],
            ..FakeGss::default()
        };
        let text = describe(&fake, "", GssStatus::new(GSS_S_FAILURE, 1));
        // 600 + 2 fits; a second 600 would not, so it is dropped whole rather
        // than truncated mid-way -- which is exactly what C's guard does.
        assert_eq!(text.len(), 602);
        assert!(text.ends_with("x. "));
    }

    #[test]
    fn describe_drops_a_part_that_alone_exceeds_the_bound() {
        let huge = "y".repeat(GSS_LOG_BUFFER_LEN + 10);
        let fake = FakeGss {
            display_status_parts: vec![StatusPart::last(&huge)],
            ..FakeGss::default()
        };
        assert_eq!(
            describe(&fake, "prefix: ", GssStatus::new(GSS_S_FAILURE, 1)),
            "prefix: ",
            "an oversized part is skipped, leaving the bare prefix"
        );
    }

    #[test]
    fn describe_truncates_at_an_embedded_nul_like_the_c_precision_conversion() {
        // "%.*s" stops at the first NUL as well as at the precision.
        let fake = FakeGss {
            display_status_parts: vec![StatusPart {
                text: b"visible\0hidden".to_vec(),
                next_context: 0,
                major: GSS_S_COMPLETE,
            }],
            ..FakeGss::default()
        };
        assert_eq!(
            describe(&fake, "", GssStatus::new(GSS_S_FAILURE, 1)),
            "visible. "
        );
    }

    #[test]
    fn describe_yields_the_bare_prefix_when_nothing_renders() {
        // C's `char buf[GSS_LOG_BUFFER_LEN] = ""` (`:432`).
        let fake = FakeGss {
            display_status_parts: Vec::new(),
            ..FakeGss::default()
        };
        assert_eq!(
            describe(
                &fake,
                "gss_wrap() failed: ",
                GssStatus::new(GSS_S_FAILURE, 1)
            ),
            "gss_wrap() failed: "
        );
    }

    #[test]
    fn describe_is_total_for_non_utf8_status_text() {
        let fake = FakeGss {
            display_status_parts: vec![StatusPart {
                text: vec![0xff, 0xfe, b'!'],
                next_context: 0,
                major: GSS_S_COMPLETE,
            }],
            ..FakeGss::default()
        };
        // Lossy rather than a panic: an unwind here could cross the C ABI.
        let text = describe(&fake, "", GssStatus::new(GSS_S_FAILURE, 1));
        assert!(text.contains('\u{fffd}'));
        assert!(text.ends_with("!. "));
    }

    #[test]
    fn describe_stops_when_display_status_itself_errors() {
        // The loop condition is `!GSS_ERROR(maj_stat) && msg_ctx`, so an error
        // from gss_display_status ends the walk even with the cursor set.
        let fake = FakeGss {
            display_status_parts: vec![
                StatusPart {
                    text: b"partial".to_vec(),
                    next_context: 1,
                    major: GSS_S_FAILURE,
                },
                StatusPart::last("never reached"),
            ],
            ..FakeGss::default()
        };
        let text = describe(&fake, "", GssStatus::new(GSS_S_FAILURE, 1));
        assert_eq!(
            text, "",
            "a failed render contributes no text and terminates the loop"
        );
        assert_eq!(fake.journal.borrow().display_status_calls.len(), 1);
    }

    // ---- name ownership --------------------------------------------------

    #[test]
    fn importing_a_name_releases_it_exactly_once_on_drop() {
        let fake = FakeGss::default();
        {
            let mut sink = Recorder::default();
            let name = NameGuard::import(
                &fake,
                b"HTTP@example.com",
                NameType::HostBasedService,
                &mut sink,
            )
            .expect("the double reports success");
            assert!(sink.lines.is_empty(), "success is silent");
            assert_eq!(fake.journal.borrow().names_released, 0);
            drop(name);
        }
        assert_eq!(
            fake.journal.borrow().names_released,
            1,
            "gss_release_name exactly once"
        );
        let imported = fake.journal.borrow().imported.clone();
        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].0, b"HTTP@example.com".to_vec());
        assert_eq!(imported[0].1, NameType::HostBasedService);
    }

    #[test]
    fn importing_an_empty_name_is_rejected_without_calling_the_library() {
        let fake = FakeGss::default();
        let mut sink = Recorder::default();
        assert_eq!(
            NameGuard::import(
                &fake,
                b"",
                NameType::HostBasedService,
                &mut sink
            )
            .err()
            .expect("an empty service name cannot be imported"),
            CURLcode::AuthError
        );
        assert!(
            fake.journal.borrow().imported.is_empty(),
            "the degenerate name never reaches the mechanism"
        );
        assert_eq!(sink.lines.len(), 1);
        assert!(sink.lines[0].starts_with("gss_import_name() failed: "));
    }

    #[test]
    fn a_failed_import_logs_and_releases_any_handle_it_was_given() {
        let fake = FakeGss {
            import_major: GSS_S_FAILURE,
            // A mechanism that breaks RFC 2744 by returning a handle anyway.
            import_returns_handle: true,
            display_status_parts: vec![StatusPart::last("Unknown host")],
            ..FakeGss::default()
        };
        let mut sink = Recorder::default();
        assert_eq!(
            NameGuard::import(
                &fake,
                b"HTTP@nowhere",
                NameType::Unspecified,
                &mut sink
            )
            .err()
            .expect("the double reports GSS_S_FAILURE"),
            CURLcode::AuthError
        );
        assert_eq!(
            fake.journal.borrow().names_released,
            1,
            "the stray handle must not leak"
        );
        assert_eq!(
            sink.lines,
            vec!["gss_import_name() failed: Unknown host. "]
        );
    }

    #[test]
    fn display_name_returns_owned_text_and_reports_failure() {
        let fake = FakeGss::default();
        let mut sink = Recorder::default();
        let name = NameGuard::import(
            &fake,
            b"host@h",
            NameType::HostBasedService,
            &mut sink,
        )
        .expect("import succeeds");
        assert_eq!(
            name.display(&mut sink).expect("display succeeds"),
            b"alice@EXAMPLE.COM".to_vec()
        );

        let broken = FakeGss {
            display_name_major: GSS_S_FAILURE,
            display_status_parts: vec![StatusPart::last("Bad name")],
            ..FakeGss::default()
        };
        let mut other = Recorder::default();
        let broken_name = NameGuard::import(
            &broken,
            b"host@h",
            NameType::HostBasedService,
            &mut other,
        )
        .expect("import succeeds");
        assert_eq!(
            broken_name.display(&mut other).expect_err("display fails"),
            CURLcode::AuthError
        );
        assert_eq!(other.lines, vec!["gss_display_name() failed: Bad name. "]);
    }

    #[test]
    fn an_oversized_rendering_maps_to_out_of_memory() {
        let fake = FakeGss {
            oversize: true,
            ..FakeGss::default()
        };
        let mut sink = Recorder::default();
        let name = NameGuard::import(
            &fake,
            b"host@h",
            NameType::HostBasedService,
            &mut sink,
        )
        .expect("import does not go through the oversize guard");
        assert_eq!(
            name.display(&mut sink).expect_err("oversize is refused"),
            CURLcode::OutOfMemory
        );
    }

    // ---- context ownership and the handshake ------------------------------

    #[test]
    fn a_fresh_context_is_gss_c_no_context_and_needs_no_teardown() {
        let fake = FakeGss::default();
        {
            let context = ContextGuard::new(&fake);
            assert!(!context.exists());
            assert!(!context.is_established());
            assert_eq!(context.status(), GssStatus::COMPLETE);
        }
        assert_eq!(
            fake.journal.borrow().contexts_deleted,
            0,
            "GSS_C_NO_CONTEXT must not be handed to gss_delete_sec_context"
        );
    }

    #[test]
    fn a_step_adopts_the_returned_handle_and_deletes_it_once() {
        let fake = FakeGss::default();
        let mut sink = Recorder::default();
        let target = NameGuard::import(
            &fake,
            b"HTTP@example.com",
            NameType::HostBasedService,
            &mut sink,
        )
        .expect("import succeeds");
        {
            let mut context = ContextGuard::new(&fake);
            let outcome = context
                .step(
                    &HandshakeRequest {
                        target: &target,
                        mechanism: Mechanism::Spnego,
                        mutual_auth: true,
                        delegation: Delegation::NONE,
                        channel_binding_data: None,
                        input_token: None,
                        want_return_flags: false,
                    },
                    &mut sink,
                )
                .expect("the double reports GSS_S_COMPLETE");
            assert_eq!(outcome.state, HandshakeState::Complete);
            assert_eq!(outcome.token, b"token".to_vec());
            assert!(context.exists(), "the in/out handle was adopted");
            assert!(context.is_established());
            // The flags actually requested were composed by `request_flags`.
            assert_eq!(
                fake.journal.borrow().step_flags,
                vec![GSS_C_REPLAY_FLAG | GSS_C_MUTUAL_FLAG]
            );
        }
        assert_eq!(fake.journal.borrow().contexts_deleted, 1);
    }

    #[test]
    fn continue_needed_is_reported_as_a_state_not_an_error() {
        let fake = FakeGss {
            step_major: GSS_S_CONTINUE_NEEDED,
            ..FakeGss::default()
        };
        let mut sink = Recorder::default();
        let target = NameGuard::import(
            &fake,
            b"rcmd@proxy",
            NameType::HostBasedService,
            &mut sink,
        )
        .expect("import succeeds");
        let mut context = ContextGuard::new(&fake);
        let outcome = context
            .step(
                &HandshakeRequest {
                    target: &target,
                    mechanism: Mechanism::Krb5,
                    mutual_auth: true,
                    delegation: Delegation::NONE,
                    channel_binding_data: Some(b"cb"),
                    input_token: Some(b"peer"),
                    want_return_flags: true,
                },
                &mut sink,
            )
            .expect("CONTINUE_NEEDED is success");
        assert_eq!(outcome.state, HandshakeState::ContinueNeeded);
        assert!(context.status().is_continue_needed());
        assert!(sink.lines.is_empty());
    }

    #[test]
    fn a_failed_step_still_records_the_status_and_deletes_the_partial_context()
    {
        // lib/vauth/spnego_gssapi.c:176 assigns nego->status BEFORE the error
        // check, and lib/socks_gssapi.c:196 deletes the context on that path.
        let fake = FakeGss {
            step_major: GSS_S_FAILURE,
            display_status_parts: vec![StatusPart::last(
                "No credentials cache found",
            )],
            ..FakeGss::default()
        };
        let mut sink = Recorder::default();
        let target = NameGuard::import(
            &fake,
            b"HTTP@example.com",
            NameType::HostBasedService,
            &mut sink,
        )
        .expect("import succeeds");
        {
            let mut context = ContextGuard::new(&fake);
            assert_eq!(
                context
                    .step(
                        &HandshakeRequest {
                            target: &target,
                            mechanism: Mechanism::Spnego,
                            mutual_auth: true,
                            delegation: Delegation::NONE,
                            channel_binding_data: None,
                            input_token: None,
                            want_return_flags: false,
                        },
                        &mut sink,
                    )
                    .expect_err("GSS_S_FAILURE is an error"),
                CURLcode::AuthError
            );
            assert!(
                context.status().is_error(),
                "the status survives the failure"
            );
            assert!(!context.is_established());
            assert_eq!(
                sink.lines,
                vec!["gss_init_sec_context() failed: No credentials cache found. "]
            );
        }
        assert_eq!(
            fake.journal.borrow().contexts_deleted,
            1,
            "a partially created context is still deleted"
        );
    }

    #[test]
    fn the_delegation_policy_warning_is_emitted_before_the_library_call() {
        // The composition inside `step` uses DELEGATION_POLICY_FLAG_SUPPORTED,
        // which is true on every mandated target, so no warning is expected
        // here; the unsupported branch is covered by
        // `request_flags_reports_the_verbatim_warning_when_policy_is_unsupported`.
        let fake = FakeGss::default();
        let mut sink = Recorder::default();
        let target = NameGuard::import(
            &fake,
            b"HTTP@example.com",
            NameType::HostBasedService,
            &mut sink,
        )
        .expect("import succeeds");
        let mut context = ContextGuard::new(&fake);
        context
            .step(
                &HandshakeRequest {
                    target: &target,
                    mechanism: Mechanism::Spnego,
                    mutual_auth: false,
                    delegation: Delegation::from_option_value(3),
                    channel_binding_data: None,
                    input_token: None,
                    want_return_flags: false,
                },
                &mut sink,
            )
            .expect("step succeeds");
        assert!(sink.lines.is_empty());
        assert_eq!(
            fake.journal.borrow().step_flags,
            vec![
                GSS_C_REPLAY_FLAG | GSS_C_DELEG_POLICY_FLAG | GSS_C_DELEG_FLAG
            ]
        );
    }

    #[test]
    fn reset_deletes_the_context_and_returns_to_the_initial_state() {
        let fake = FakeGss::default();
        let mut sink = Recorder::default();
        let target = NameGuard::import(
            &fake,
            b"HTTP@example.com",
            NameType::HostBasedService,
            &mut sink,
        )
        .expect("import succeeds");
        let mut context = ContextGuard::new(&fake);
        context
            .step(
                &HandshakeRequest {
                    target: &target,
                    mechanism: Mechanism::Spnego,
                    mutual_auth: true,
                    delegation: Delegation::NONE,
                    channel_binding_data: None,
                    input_token: None,
                    want_return_flags: false,
                },
                &mut sink,
            )
            .expect("step succeeds");
        context.reset();
        assert!(!context.exists());
        assert_eq!(context.status(), GssStatus::COMPLETE);
        assert_eq!(fake.journal.borrow().contexts_deleted, 1);
        drop(context);
        assert_eq!(
            fake.journal.borrow().contexts_deleted,
            1,
            "Drop after reset must not delete a second time"
        );
    }

    #[test]
    fn source_name_is_adopted_even_when_inquire_context_fails() {
        let good = FakeGss::default();
        {
            let mut sink = Recorder::default();
            let context = ContextGuard::new(&good);
            let source =
                context.source_name(&mut sink).expect("inquire succeeds");
            drop(source);
        }
        assert_eq!(good.journal.borrow().names_released, 1);

        let bad = FakeGss {
            source_name_major: GSS_S_FAILURE,
            display_status_parts: vec![StatusPart::last("Context is invalid")],
            ..FakeGss::default()
        };
        let mut sink = Recorder::default();
        let context = ContextGuard::new(&bad);
        assert_eq!(
            context.source_name(&mut sink).err().expect("inquire fails"),
            CURLcode::AuthError
        );
        assert_eq!(
            bad.journal.borrow().names_released,
            1,
            "a handle produced alongside an error is still released"
        );
        assert_eq!(
            sink.lines,
            vec!["gss_inquire_context() failed: Context is invalid. "]
        );
    }

    // ---- per-message protection ------------------------------------------

    #[test]
    fn wrap_passes_the_confidentiality_request_and_reports_conf_state() {
        let fake = FakeGss {
            wrap_confidential: true,
            ..FakeGss::default()
        };
        let mut sink = Recorder::default();
        let context = ContextGuard::new(&fake);
        let sealed = context
            .wrap(false, b"\x01\x00\x00\x00", &mut sink)
            .expect("wrap succeeds");
        assert_eq!(sealed.token, b"sealed".to_vec());
        assert!(sealed.confidential);
        assert_eq!(
            fake.journal.borrow().wrapped,
            vec![(false, b"\x01\x00\x00\x00".to_vec())]
        );
    }

    #[test]
    fn a_failed_wrap_maps_to_auth_error() {
        let fake = FakeGss {
            wrap_major: GSS_S_FAILURE,
            display_status_parts: vec![StatusPart::last("Wrong QOP")],
            ..FakeGss::default()
        };
        let mut sink = Recorder::default();
        let context = ContextGuard::new(&fake);
        assert_eq!(
            context.wrap(true, b"x", &mut sink).expect_err("wrap fails"),
            CURLcode::AuthError
        );
        assert_eq!(sink.lines, vec!["gss_wrap() failed: Wrong QOP. "]);
    }

    #[test]
    fn unwrap_returns_the_plaintext_and_rejects_an_empty_token() {
        let fake = FakeGss::default();
        let mut sink = Recorder::default();
        let context = ContextGuard::new(&fake);
        assert_eq!(
            context
                .unwrap(b"sealed", &mut sink)
                .expect("unwrap succeeds"),
            b"plain".to_vec()
        );
        assert_eq!(fake.journal.borrow().unwrapped, vec![b"sealed".to_vec()]);

        // lib/vauth/krb5_gssapi.c:199-202
        assert_eq!(
            context
                .unwrap(&[], &mut sink)
                .expect_err("an empty security message is rejected"),
            CURLcode::BadContentEncoding
        );
        assert_eq!(
            sink.lines,
            vec!["GSSAPI handshake failure (empty security message)"]
        );
        assert_eq!(
            fake.journal.borrow().unwrapped.len(),
            1,
            "the empty token never reaches the mechanism"
        );
    }

    #[test]
    fn a_failed_unwrap_maps_to_bad_content_encoding() {
        // lib/vauth/krb5_gssapi.c:211-215
        let fake = FakeGss {
            unwrap_major: GSS_S_FAILURE,
            display_status_parts: vec![StatusPart::last("Token is malformed")],
            ..FakeGss::default()
        };
        let mut sink = Recorder::default();
        let context = ContextGuard::new(&fake);
        assert_eq!(
            context
                .unwrap(b"garbage", &mut sink)
                .expect_err("unwrap fails"),
            CURLcode::BadContentEncoding
        );
        assert_eq!(
            sink.lines,
            vec!["gss_unwrap() failed: Token is malformed. "]
        );
    }

    #[test]
    fn an_oversized_step_or_message_maps_to_out_of_memory() {
        let fake = FakeGss {
            oversize: true,
            ..FakeGss::default()
        };
        let mut sink = Recorder::default();
        let context = ContextGuard::new(&fake);
        assert_eq!(
            context.wrap(false, b"x", &mut sink).expect_err("refused"),
            CURLcode::OutOfMemory
        );
        assert_eq!(
            context.unwrap(b"x", &mut sink).expect_err("refused"),
            CURLcode::OutOfMemory
        );
    }

    // ---- the token copy must never strand the context ---------------------
    //
    // `gss_init_sec_context` writes `context_handle` before it returns, so by
    // the time this side tries to copy the output token the caller's previous
    // handle may already be freed and a replacement installed. The copy is the
    // one fallible step on that path, and these tests pin down that failing it
    // neither leaks the replacement nor deletes the value it superseded.

    #[test]
    fn a_failed_token_copy_still_adopts_the_handle_and_the_status() {
        let fake = FakeGss {
            oversize: true,
            ..FakeGss::default()
        };
        let mut sink = Recorder::default();
        let target = NameGuard::import(
            &fake,
            b"HTTP@example.com",
            NameType::HostBasedService,
            &mut sink,
        )
        .expect("import succeeds");
        {
            let mut context = ContextGuard::new(&fake);
            assert_eq!(
                context
                    .step(
                        &HandshakeRequest {
                            target: &target,
                            mechanism: Mechanism::Spnego,
                            mutual_auth: true,
                            delegation: Delegation::NONE,
                            channel_binding_data: None,
                            input_token: None,
                            want_return_flags: false,
                        },
                        &mut sink,
                    )
                    .expect_err("an uncopyable token is refused"),
                CURLcode::OutOfMemory
            );
            assert!(
                context.exists(),
                "the handle the library installed must be adopted even though \
                 the token could not be copied"
            );
            assert_eq!(
                context.status(),
                GssStatus::new(GSS_S_COMPLETE, 9),
                "the status the library reported must survive the copy failure, \
                 exactly as lib/vauth/spnego_gssapi.c:175 assigns nego->status \
                 before its own error check"
            );
            assert!(
                sink.lines.is_empty(),
                "the library did not fail, so no gss_init_sec_context() \
                 diagnostic is due"
            );
        }
        assert_eq!(
            fake.journal.borrow().deleted,
            vec![RawContext(handle(STEPPED_CONTEXT_SLOT))],
            "Drop must delete the replacement exactly once; a stranded handle \
             would leave this empty"
        );
    }

    #[test]
    fn a_failed_token_copy_retires_the_handle_it_replaced() {
        let fake = FakeGss {
            step_handle: Cell::new(Some(FIRST_CONTEXT_SLOT)),
            ..FakeGss::default()
        };
        let mut sink = Recorder::default();
        let target = NameGuard::import(
            &fake,
            b"HTTP@example.com",
            NameType::HostBasedService,
            &mut sink,
        )
        .expect("import succeeds");
        let request = HandshakeRequest {
            target: &target,
            mechanism: Mechanism::Spnego,
            mutual_auth: true,
            delegation: Delegation::NONE,
            channel_binding_data: None,
            input_token: None,
            want_return_flags: false,
        };
        {
            let mut context = ContextGuard::new(&fake);
            context
                .step(&request, &mut sink)
                .expect("the first step succeeds");

            // A second step whose copy fails, and which the library answers
            // with a *different* handle: the first one is destroyed by
            // `gss_init_sec_context` itself, so deleting it again would be a
            // double free.
            fake.step_handle.set(Some(STEPPED_CONTEXT_SLOT));
            fake.token_copy_fails.set(true);
            assert_eq!(
                context
                    .step(&request, &mut sink)
                    .expect_err("an uncopyable token is refused"),
                CURLcode::OutOfMemory
            );
            assert_eq!(
                fake.journal.borrow().stepped_from,
                vec![RawContext::NONE, RawContext(handle(FIRST_CONTEXT_SLOT))],
                "the second step must be handed the handle the first one \
                 installed"
            );
        }
        assert_eq!(
            fake.journal.borrow().deleted,
            vec![RawContext(handle(STEPPED_CONTEXT_SLOT))],
            "only the current handle may be deleted: the superseded one was \
             already destroyed by the library"
        );
    }

    #[test]
    fn a_library_error_outranks_a_failed_token_copy() {
        // Both go wrong at once. C reports the GSS-API failure -- it is the one
        // that explains the handshake -- so `AuthError` must win over
        // `OutOfMemory`, and the diagnostic must still be emitted.
        let fake = FakeGss {
            step_major: GSS_S_FAILURE,
            oversize: true,
            display_status_parts: vec![StatusPart::last(
                "No credentials cache found",
            )],
            ..FakeGss::default()
        };
        let mut sink = Recorder::default();
        let target = NameGuard::import(
            &fake,
            b"HTTP@example.com",
            NameType::HostBasedService,
            &mut sink,
        )
        .expect("import succeeds");
        {
            let mut context = ContextGuard::new(&fake);
            assert_eq!(
                context
                    .step(
                        &HandshakeRequest {
                            target: &target,
                            mechanism: Mechanism::Spnego,
                            mutual_auth: true,
                            delegation: Delegation::NONE,
                            channel_binding_data: None,
                            input_token: None,
                            want_return_flags: false,
                        },
                        &mut sink,
                    )
                    .expect_err("the library failed"),
                CURLcode::AuthError
            );
            assert_eq!(
                sink.lines,
                vec!["gss_init_sec_context() failed: No credentials cache found. "]
            );
            assert!(context.status().is_error());
        }
        assert_eq!(
            fake.journal.borrow().deleted,
            vec![RawContext(handle(STEPPED_CONTEXT_SLOT))],
            "a partial context is deleted once even when both failures coincide"
        );
    }

    #[test]
    fn a_failed_token_copy_leaves_a_context_that_reset_can_still_clear() {
        // The recovery path a caller takes after `CURLE_OUT_OF_MEMORY`: the
        // context is real, so `reset` must delete it and leave a value that
        // `Drop` will not delete again.
        let fake = FakeGss {
            oversize: true,
            ..FakeGss::default()
        };
        let mut sink = Recorder::default();
        let target = NameGuard::import(
            &fake,
            b"HTTP@example.com",
            NameType::HostBasedService,
            &mut sink,
        )
        .expect("import succeeds");
        {
            let mut context = ContextGuard::new(&fake);
            context
                .step(
                    &HandshakeRequest {
                        target: &target,
                        mechanism: Mechanism::Spnego,
                        mutual_auth: true,
                        delegation: Delegation::NONE,
                        channel_binding_data: None,
                        input_token: None,
                        want_return_flags: false,
                    },
                    &mut sink,
                )
                .expect_err("an uncopyable token is refused");
            context.reset();
            assert!(!context.exists());
            assert_eq!(context.status(), GssStatus::COMPLETE);
            assert_eq!(fake.journal.borrow().contexts_deleted, 1);
        }
        assert_eq!(
            fake.journal.borrow().contexts_deleted,
            1,
            "Drop after reset must not delete a second time"
        );
    }

    // ---- the availability predicate ---------------------------------------

    #[test]
    fn available_is_true_when_the_mechanism_glue_answers() {
        let fake = FakeGss::default();
        assert!(available_with(&fake));
        assert_eq!(
            fake.journal.borrow().imported,
            vec![(b"host@localhost".to_vec(), NameType::HostBasedService)],
            "the probe imports a host-based service name and nothing else"
        );
        assert_eq!(
            fake.journal.borrow().names_released,
            1,
            "the probe leaves nothing behind"
        );
    }

    #[test]
    fn available_is_false_when_the_library_is_unusable_and_never_panics() {
        for (major, returns_handle) in [
            (GSS_S_FAILURE, false),
            (GSS_S_FAILURE, true),
            (1 << 16, false), // GSS_S_BAD_MECH: no mechanism configured
            (1 << 24, false), // a calling error
        ] {
            let fake = FakeGss {
                import_major: major,
                import_returns_handle: returns_handle,
                ..FakeGss::default()
            };
            assert!(
                !available_with(&fake),
                "major {major:#x} must read as unavailable"
            );
            assert_eq!(
                fake.journal.borrow().names_released,
                usize::from(returns_handle),
                "any handle returned alongside a failure is still released"
            );
        }
    }

    #[test]
    fn available_is_idempotent() {
        let fake = FakeGss::default();
        let first = available_with(&fake);
        let second = available_with(&fake);
        assert_eq!(first, second);
        assert!(first);
    }

    /// The cached, real-library predicate.
    ///
    /// Ignored under Miri because it calls `gss_import_name` for real, and Miri
    /// interprets rather than links -- an FFI call is an unsupported operation
    /// there. The logic it delegates to is covered by `available_with` above,
    /// which is Miri-clean; this test exists to prove the wiring and the
    /// caching, and to prove the predicate is total against whatever GSS-API
    /// the host actually has.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn the_system_predicate_is_total_and_cached() {
        let first = available();
        let second = available();
        assert_eq!(first, second, "OnceLock must not produce two answers");
    }

    // ---- the crate-visible surface ----------------------------------------

    /// Exercises the crate-visible `SystemGss` newtypes' construction and
    /// teardown -- the only part of the real-provider surface reachable without
    /// a live mechanism, and Miri-clean because `release_name` and
    /// `delete_sec_context` short-circuit on the null handle before any
    /// `unsafe` block, so no FFI call is made.
    #[test]
    fn the_real_provider_newtypes_construct_and_drop_without_calling_the_library(
    ) {
        let context = SecurityContext::default();
        assert!(!context.exists());
        assert!(!context.is_established());
        assert_eq!(context.status(), GssStatus::COMPLETE);
        drop(context);

        let mut reused = SecurityContext::new();
        reused.reset();
        assert!(!reused.exists());
        assert_eq!(reused.status(), GssStatus::COMPLETE);
        drop(reused);

        // A `GSS_C_NO_NAME` guard is likewise inert on drop.
        let name = TargetName(NameGuard::adopt(SystemGss, RawName::NONE));
        drop(name);
    }

    #[test]
    fn step_options_default_to_the_spnego_shape() {
        // A `GSS_C_NO_NAME` target is enough: the field defaults are what is
        // under test, and nothing here reaches the library.
        let target = TargetName(NameGuard::adopt(SystemGss, RawName::NONE));
        let options = StepOptions::new(&target, Mechanism::Spnego);
        assert_eq!(options.mechanism, Mechanism::Spnego);
        assert!(
            options.mutual_auth,
            "lib/vauth/spnego_gssapi.c:170 passes TRUE"
        );
        assert_eq!(options.delegation, Delegation::NONE);
        assert!(options.channel_binding_data.is_none());
        assert!(options.input_token.is_none());
        assert!(
            !options.want_return_flags,
            "lib/vauth/spnego_gssapi.c:171 passes NULL for ret_flags"
        );

        let krb5 = StepOptions::new(&target, Mechanism::Krb5);
        assert_eq!(krb5.mechanism, Mechanism::Krb5);
    }

    #[test]
    fn a_borrowed_sink_is_itself_a_sink() {
        // The guards take `&mut dyn Diagnostics`, and the blanket
        // `impl<T: Diagnostics + ?Sized> Diagnostics for &mut T` is what lets a
        // caller forward its own borrow. Exercised through a generic so the
        // blanket impl is the one selected rather than inherent method
        // resolution on `Recorder`.
        fn log_via<D: Diagnostics>(mut sink: D, message: &str) {
            sink.infof(message);
        }

        let mut recorder = Recorder::default();
        log_via(&mut recorder, "kept");
        assert_eq!(recorder.lines, vec!["kept"]);

        // The null sink accepts and discards, which is what a caller with no
        // `struct Curl_easy *data` equivalent uses.
        log_via(DiscardDiagnostics, "dropped");
        let mut discard = DiscardDiagnostics;
        discard.infof("also dropped");
        assert_eq!(recorder.lines.len(), 1, "the null sink kept nothing");
    }
}
