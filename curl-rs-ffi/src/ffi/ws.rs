// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl
//
// Derived from include/curl/websockets.h, lib/ws.c and lib/libcurl.def of
// curl 8.19.0-DEV at commit 54cf587b9c.

//! The WebSocket API: four of the 100 exported symbols.
//!
//! | Symbol | Declared | Returns | Authority |
//! |---|---|---|---|
//! | [`curl_ws_recv`] | `websockets.h:55-57` | `CURLcode` | `lib/ws.c:1530` |
//! | [`curl_ws_send`] | `websockets.h:70-73` | `CURLcode` | `lib/ws.c:1763` |
//! | [`curl_ws_start_frame`] | `websockets.h:84-86` | `CURLcode` | `:1866` |
//! | [`curl_ws_meta`] | `websockets.h:92` | `const curl_ws_frame *` | `:1851` |
//!
//! `include/curl/websockets.h` declares exactly these four and nothing else,
//! and they are the last four names of `lib/libcurl.def` in its alphabetical
//! order: `curl_ws_meta` at `:98`, `curl_ws_recv` at `:99`, `curl_ws_send` at
//! `:100` and `curl_ws_start_frame` at `:101`, which is the hundredth and
//! final line of the file. Each has exactly ONE
//! `#[no_mangle] pub extern "C"` definition here; a duplicate anywhere in the
//! crate is a link error and nothing builds.
//!
//! **`curl_ws_recv`'s fourth parameter is literally named `recv`**
//! (`websockets.h:56`), shadowing POSIX `recv()`. The name is ABI-visible
//! through the manual-page synopses that `.github/scripts/verify-synopsis.pl`
//! compiles against the generated header, so it is reproduced exactly rather
//! than renamed to something a Rust author would prefer. The C's own
//! definition calls the same parameter `nread` (`lib/ws.c:1531`); the HEADER
//! is the authority for a name a consumer can see.
//!
//! # Declaration order is ABI-visible, and `curl_ws_meta` is LAST
//!
//! `cbindgen.toml` sets `sort_by = "None"`, so the Rust source's declaration
//! order is the generated header's declaration order. `websockets.h` does not
//! group its functions the way an author would: `curl_ws_meta` is declared
//! LAST, at `:92`, AFTER the two `CURLOPT_WS_OPTIONS` bits at `:89-90`. The
//! order below is therefore `curl_ws_recv`, `curl_ws_send`,
//! `curl_ws_start_frame`, `curl_ws_meta`, and it is neither alphabetised nor
//! regrouped by return type. `rustfmt`'s `reorder_imports` sorts `use`
//! statements and not item declarations, so the formatter cannot disturb it --
//! which is why the crate root's note about `reorder_modules` applies to
//! `ffi/mod.rs` and not to this file.
//!
//! # `websockets.h` has no `#include` at all
//!
//! Measured: the header contains zero `#include` lines, yet it names `CURL`,
//! `CURLcode`, `curl_off_t`, `size_t` and `CURL_EXTERN`. It is compilable only
//! after `curl.h`, which includes it as one of the seven umbrella includes at
//! `curl.h:3314-3320` -- after `curl.h` has closed its own `extern "C"` at
//! `:3308-3310`. The Rust consequence is an ordering one: `ffi/codes.rs` and
//! `ffi/handle.rs` supply every type named below, so both precede this module
//! in `ffi/mod.rs`. Its closing brace at `:95` is a BARE `}` with no
//! `/* end of extern "C" */` comment, unlike most of its siblings;
//! `build.rs` reproduces that asymmetry rather than tidying it.
//!
//! # Two flag spaces that share a prefix
//!
//! Nine `CURLWS_*` bits exist and they are not one set:
//!
//! * The **seven frame flags** -- `CURLWS_TEXT` through `CURLWS_OFFSET` at
//!   `:40-45`, plus `CURLWS_PONG` at `:60` -- are written `(1 << n)` and are
//!   `unsigned int`: they occupy `struct curl_ws_frame`'s `flags` field and
//!   the declared `flags` parameter of [`curl_ws_send`] and
//!   [`curl_ws_start_frame`]. **This module owns them**, as `c_uint`.
//! * The **two option bits** -- `CURLWS_RAW_MODE` and `CURLWS_NOAUTOPONG` at
//!   `:89-90` -- are written `(1L << n)` and are `long`: they are argument
//!   values for `curl_easy_setopt(h, CURLOPT_WS_OPTIONS, ...)`, where the
//!   default argument promotions make the width load-bearing. `ffi/opts.rs`
//!   owns them, as `c_long`, and nothing here declares or redeclares them.
//!
//! The `L` suffix is an ABI distinction and not a typo, so the two spaces are
//! not harmonised even though `CURLWS_TEXT` and `CURLWS_RAW_MODE` are both
//! bit 0. Both option bits nevertheless change what the functions below DO --
//! raw mode bypasses framing entirely and `CURLWS_NOAUTOPONG` suppresses the
//! automatic PONG reply -- and every one of those effects belongs to
//! `curl-rs-lib/src/protocols/ws.rs`, which reads them off the transfer.
//!
//! **`CURLWS_PONG` is declared MID-FILE**, between [`curl_ws_recv`] and
//! [`curl_ws_send`] under the C's own comment `/* flags for curl_ws_send() */`,
//! and is reproduced in that position below rather than consolidated with its
//! six siblings.
//!
//! # `struct curl_ws_frame` is imported, never redeclared
//!
//! [`super::handle::curl_ws_frame`] carries the frozen shape of
//! `websockets.h:31-37`: `age` first, then `flags`, `offset`, `bytesleft` and
//! `len`. Two properties of it are easy to lose and both are deliberate.
//! `age` is the struct's VERSION field -- the C's comment is literally
//! `/* zero */` -- so it must stay first and stay zero, or every consumer's
//! `offsetof` moves. And `flags` is `int` INSIDE the struct while it is
//! `unsigned int` as a PARAMETER of the two senders (`:33` against `:73` and
//! `:85`); the asymmetry is in the authority and is not tidied. `handle.rs`
//! asserts the layout with its own `#[cfg(test)] mod layout`, computing offsets
//! by pointer arithmetic because `offset_of!` is Rust 1.77 and the declared
//! minimum is 1.75, so none of that machinery is repeated here.
//!
//! # [`curl_ws_meta`] hands back a BORROWED pointer
//!
//! The C returns `&ws->recvframe` (`lib/ws.c:1861`) -- the address of the
//! connection's own metadata block, not a copy -- and `curl_ws_recv` stores
//! the same address through `*metap` (`:1611`). **The caller must not free
//! it**, and it stays valid until the next transfer operation on that handle.
//! So no `Box::into_raw` appears in this file: the boundary's RAII pattern
//! applies to the handles that `curl_easy_init` and its siblings mint, and
//! applying it here would hand the application a pointer it would then be
//! obliged to release. Nor may either route ever return the address of a Rust
//! temporary, which would be dangling the instant the call returned. The
//! metadata has to live in the transfer's own state in `curl-rs-lib`, and the
//! two functions that would publish it do so only from there.
//!
//! # No protocol logic lives here
//!
//! Frame headers, masking, fragmentation boundaries, PING and PONG handling
//! and close negotiation are `curl-rs-lib/src/protocols/ws.rs`'s, which
//! supersedes the whole of `lib/ws.c`. That division is the facade discipline
//! the crate root describes, and it is load-bearing here rather than
//! decorative: WebSocket framing is wire behaviour, wire behaviour is frozen,
//! and the fixture corpus compares whole request bytes as one string with no
//! normalisation and no reordering. A second frame encoder in this crate would
//! be a second place for those bytes to be decided.
//!
//! # What this build can answer, and why
//!
//! `lib/ws.c` defines these four symbols TWICE. `:1530-1916` is the built-in
//! branch; `:1938-1980`, reached through `#else` when
//! `CURL_DISABLE_WEBSOCKETS` is defined, defines all four again as
//! `CURLE_NOT_BUILT_IN` for the three `CURLcode` functions and `NULL` for
//! `curl_ws_meta`, with every parameter cast to void. A build is one branch or
//! the other, and [`WEBSOCKETS_ARE_BUILT_IN`] selects which one this build
//! reproduces -- DERIVED from the engine's own marker rather than hand-set, so
//! that it changes on its own when the capability lands.
//!
//! Two facts about the export set, kept apart because conflating them is how
//! an ABI regression gets rationalised. The four symbols are exported
//! UNCONDITIONALLY: no `#[cfg(feature = "websockets")]` appears below, and
//! `--no-default-features` still exports all four, because a disabled
//! capability answers an error rather than removing a symbol a consumer links
//! against. What the feature does change is the ANSWER, which is exactly what
//! the C's two branches do.
//!
//! None of the four is variadic and none takes a `va_list`, so the
//! single-trailing-pointer design the option setters use, and the Apple arm64
//! argument-passing escalation that comes with it, do not touch this file.

use core::convert::Infallible;
use core::ffi::{c_uint, c_void};
use core::ptr;

use super::codes::CURLcode;
use super::handle::{curl_off_t, curl_ws_frame, BAD_EASY_HANDLE, CURL};
use super::panic_boundary::{guard, guard_const_ptr};

// The seven CURLWS_* FRAME flags (websockets.h:40-45 and :60).
//
// WHY THEY ARE DECLARED AT ALL, given that the generated header does not come
// from them. `build.rs`'s `WEBSOCKETS_H_DECLS` splices all nine `CURLWS_*`
// bits into the header VERBATIM from the frozen source, because cbindgen was
// measured to drop the `L` suffix -- turning the two option bits' `long` into
// an `int` and changing the varargs type of `CURLOPT_WS_OPTIONS` -- as well as
// rewriting hex as decimal. So these seven exist for the two reasons a Rust
// declaration is still needed: this crate has a typed value to compare a
// caller's `flags` against, and the tests below pin the integers so that a
// transcription error in the verbatim block cannot pass unnoticed.
//
// They are `pub(crate)`, which additionally makes them invisible to cbindgen,
// so there is no route by which a second declaration of any of them could
// reach the header beside the verbatim one.
//
// Each carries its own `#[allow(dead_code)]` rather than the module carrying
// one: an ABI declaration with no Rust consumer is legitimate, but a NEW
// unreferenced item must still warn, and a module-wide allowance would hide
// the next one.

/// `CURLWS_TEXT (1 << 0)` (`include/curl/websockets.h:40`).
#[allow(dead_code)] // ABI declaration: pinned by test, spliced by build.rs
pub(crate) const CURLWS_TEXT: c_uint = 1 << 0;

/// `CURLWS_BINARY (1 << 1)` (`include/curl/websockets.h:41`).
#[allow(dead_code)] // ABI declaration: pinned by test, spliced by build.rs
pub(crate) const CURLWS_BINARY: c_uint = 1 << 1;

/// `CURLWS_CONT (1 << 2)` (`include/curl/websockets.h:42`).
#[allow(dead_code)] // ABI declaration: pinned by test, spliced by build.rs
pub(crate) const CURLWS_CONT: c_uint = 1 << 2;

/// `CURLWS_CLOSE (1 << 3)` (`include/curl/websockets.h:43`).
#[allow(dead_code)] // ABI declaration: pinned by test, spliced by build.rs
pub(crate) const CURLWS_CLOSE: c_uint = 1 << 3;

/// `CURLWS_PING (1 << 4)` (`include/curl/websockets.h:44`).
#[allow(dead_code)] // ABI declaration: pinned by test, spliced by build.rs
pub(crate) const CURLWS_PING: c_uint = 1 << 4;

/// `CURLWS_OFFSET (1 << 5)` (`include/curl/websockets.h:45`).
#[allow(dead_code)] // ABI declaration: pinned by test, spliced by build.rs
pub(crate) const CURLWS_OFFSET: c_uint = 1 << 5;

/// Whether the WebSocket surface is built in, in the sense `lib/ws.c` means.
///
/// This is not a question about which symbols exist -- all four exist
/// unconditionally -- but about which of the C's two definitions of them a
/// build carries. `lib/ws.c:28` guards the whole implementation with
/// `#ifndef CURL_DISABLE_WEBSOCKETS` and the `#else` at `:1938-1980` supplies
/// a second, complete definition of all four entry points for builds where
/// that condition is false.
///
/// This build is the second one, and the answer is DERIVED from
/// [`curl_rs_lib::version::supports_websockets`] rather than written down
/// here. That function conjoins the `websockets` Cargo feature -- this
/// crate's own feature forwards to it, so `--no-default-features` is exactly
/// C's `CURL_DISABLE_WEBSOCKETS` -- with
/// [`curl_rs_lib::version::ENGINE_PROTOCOLS`], which is `Engine::inert`: the
/// scheme table and the WebSocket codec are both written and tested, and no
/// executor reaches them. Deriving it is the whole point: when the transfer
/// core wires the protocol layer, this constant becomes `true` and the four
/// entry points switch branches with no edit in this file, whereas a hand-set
/// `false` would have to be remembered.
///
/// The engine records the same contract on its own side as
/// `protocols::ws::NOT_BUILT_IN`, and notes there that the four disabled-build
/// stubs belong to this file because that module does not exist in a build
/// without the feature.
const WEBSOCKETS_ARE_BUILT_IN: bool =
    curl_rs_lib::version::supports_websockets();

/// The WebSocket transfer that `easy` names, or `None` for a handle this
/// library did not issue.
///
/// This is C's `GOOD_EASY_HANDLE` limb (`lib/urldata.h:218-223`), which tests
/// `(x) && ((x)->magic == CURLEASY_MAGIC_NUMBER)` -- a null test AND a
/// magic-number test, so a stale or foreign pointer answers false rather than
/// being followed.
///
/// **This build issues no easy handle at all, and that is measured rather than
/// assumed.** `curl-rs-lib/src/easy/` holds only `mod.rs` and `options.rs`;
/// there is no engine easy-handle object, and `curl_easy_init` is one of the
/// exports `build.rs`'s `undefined_abi_exports` still reports as missing. So
/// no `CURL *` a caller can present was issued by this library, and a pointer
/// this library did not issue cannot be interpreted: reading a magic number
/// through it on the strength of a type name would be undefined behaviour,
/// not a shortcut. `easy` is therefore not dereferenced below.
///
/// A second layer is missing independently of that one, and it is recorded
/// here because it is the reason this seam cannot simply be filled in.
/// `curl-rs-lib` declares `pub(crate) mod protocols`, and its only crate-root
/// re-export from that subtree is `scheme_registry`. The engine's four
/// WebSocket entry points -- `ws_recv`, `ws_send`, `ws_start_frame` and
/// `ws_meta` -- together with `WebSocket`, `WsCtx` and `WsFrameMeta` are
/// `pub(crate)` and are therefore unreachable from this crate, even though
/// each is annotated as awaiting this file as its consumer. Widening them
/// wholesale is not this file's to do: re-exporting internals is what the
/// encapsulation exists to prevent, and a private path cannot be named across
/// a crate boundary at all. The gap is reported rather than worked around.
///
/// [`Infallible`] as the payload is a deliberate choice and not a placeholder.
/// It is the type-level statement that no such transfer can be produced in
/// this build, which lets each entry point's engine arm be discharged by
/// `match transfer {}` -- a proof accepted by the compiler -- instead of by an
/// invented return value or an `unreachable!()` that the panic boundary would
/// have to contain. When the two layers land, this becomes a real transfer
/// type and every `match transfer {}` below becomes the call that acts on it;
/// nothing else in this file changes shape.
///
/// # Safety
///
/// `easy` must be either null or an easy handle this crate issued and has not
/// released, and the returned value must not outlive one entry point's body.
unsafe fn ws_transfer(easy: *mut CURL) -> Option<Infallible> {
    let _ = easy;
    None
}

/// Clear [`curl_ws_recv`]'s two out-parameters, as `lib/ws.c:1539-1540` does
/// before it validates anything.
///
/// ```c
/// *nread = 0;
/// *metap = NULL;
/// ```
///
/// Split out of the entry point for one reason: it holds the only two writes
/// through a caller-supplied pointer in this file, and a private function can
/// be called by a test where an inline statement behind
/// [`WEBSOCKETS_ARE_BUILT_IN`] cannot. That is what puts these two stores under
/// Miri today rather than when the marker flips.
///
/// **The null tests are this side's one widening of the C's pair.** The C
/// writes through both unconditionally, so a null `recv` or `metap` faults
/// there rather than returning a code; reproducing a crash is not reproducing a
/// contract. A caller that passes the pointers the prototype asks for observes
/// no difference at all.
///
/// # Safety
///
/// Each pointer must be either null or a writable, suitably aligned slot of
/// its declared type, not aliased by another thread for the duration of the
/// call.
unsafe fn clear_receive_out_params(
    recv: *mut usize,
    metap: *mut *const curl_ws_frame,
) {
    if !recv.is_null() {
        // SAFETY: non-null by the test above and, by this function's contract,
        // a writable aligned `size_t` slot the caller owns. The write is a
        // plain scalar store and nothing is read back.
        unsafe { recv.write(0) };
    }
    if !metap.is_null() {
        // SAFETY: non-null by the test above and, by this function's contract,
        // a writable aligned `const struct curl_ws_frame *` slot. The value
        // stored is a null pointer, so this write asserts nothing about any
        // pointee's lifetime. The success path stores `&ws->recvframe` instead
        // (`lib/ws.c:1611`), which outlives the call because it addresses the
        // transfer's own metadata rather than anything owned by this frame --
        // and that path is unreachable in this build; see `ws_transfer`.
        unsafe { metap.write(ptr::null()) };
    }
}

// 1 of 4: curl_ws_recv

/// Receives data from the WebSocket connection.
///
/// Supersedes `curl_ws_recv` (`lib/ws.c:1530-1625`), whose prototype is frozen
/// at `include/curl/websockets.h:55-57`. On success `buffer` holds up to
/// `buflen` payload bytes, `*recv` is how many arrived, and `*metap` addresses
/// the frame's metadata -- **borrowed** from the transfer's own state, so the
/// caller must not free it and must not use it after the next operation on
/// this handle.
///
/// The header states the precondition twice, at `:52-53`: use it after a
/// successful `curl_easy_perform` with `CURLOPT_CONNECT_ONLY`. The C enforces
/// that only where it bites -- `:1544-1557` demands the option just when the
/// transfer has already released its connection -- so a call from inside a
/// write callback, which two fixtures make, needs no option at all.
///
/// # Errors
///
/// `CURLE_BAD_FUNCTION_ARGUMENT` for a handle this library did not issue and
/// for a null `buffer` with a non-zero `buflen`; `CURLE_UNSUPPORTED_PROTOCOL`
/// when the transfer has no connection and `CURLOPT_CONNECT_ONLY` was not set;
/// `CURLE_GOT_NOTHING` when the peer closed; and `CURLE_AGAIN` when the
/// transport has nothing to hand over yet. `CURLE_AGAIN` is a NORMAL answer in
/// non-blocking use and is passed through exactly as the C reports it, never
/// smoothed into `CURLE_OK` or into a retry loop this side.
///
/// `CURLE_NOT_BUILT_IN` in a build without WebSocket support, which is the
/// whole of `lib/ws.c:1940-1950`.
///
/// # Safety
///
/// `curl` must be either null or an easy handle this library issued and that
/// has not been released. `buffer` must be either null or writable for
/// `buflen` bytes. `recv` and `metap` must each be either null or a writable,
/// suitably aligned slot of their declared type. None of the four pointers may
/// be used from another thread for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn curl_ws_recv(
    curl: *mut CURL,
    buffer: *mut c_void,
    buflen: usize,
    recv: *mut usize,
    metap: *mut *const curl_ws_frame,
) -> CURLcode {
    guard(CURLcode::CURLE_FAILED_INIT, || {
        if !WEBSOCKETS_ARE_BUILT_IN {
            // `lib/ws.c:1940-1950` verbatim: all five parameters are cast to
            // void and `CURLE_NOT_BUILT_IN` is returned. NEITHER
            // out-parameter is written, which is why that branch needs no null
            // test -- and why this one performs no write before returning.
            return CURLcode::CURLE_NOT_BUILT_IN;
        }

        // `:1539-1540`, in the C's order: both out-parameters are cleared
        // BEFORE anything is validated, so a caller that ignores the return
        // code still reads a zero count and a null metadata pointer. The one
        // widening of that pair, and the reason it is a separate function, are
        // both recorded at `clear_receive_out_params`.
        //
        // SAFETY: forwarded verbatim from this function's own contract, which
        // is what `clear_receive_out_params` requires of its caller.
        unsafe { clear_receive_out_params(recv, metap) };

        // `:1541-1542` is ONE condition with two limbs answering one code:
        // `!GOOD_EASY_HANDLE(data) || (buflen && !buffer)`. Their relative
        // order is therefore unobservable, and neither limb has a side
        // effect, so the buffer limb is spelled here and the handle limb is
        // the `None` arm below.
        //
        // Note the shape that is NOT an error, because the limb is
        // `buflen && !buffer` and not `!buffer`: a `buflen` of zero with a
        // null `buffer` passes validation.
        if buflen != 0 && buffer.is_null() {
            return BAD_EASY_HANDLE;
        }

        // SAFETY: forwarded verbatim from this function's own contract, which
        // is what `ws_transfer` requires of its caller.
        match unsafe { ws_transfer(curl) } {
            // Where the C's remaining 80 lines go: the connection lookup at
            // `:1544-1562`, the slurp-and-decode loop at `:1570-1606` -- which
            // keeps reading rather than returning an auto-answered PING -- the
            // metadata update at `:1608-1612` and the pending-control flush at
            // `:1617-1623`. Discharged by an uninhabited match rather than by
            // a stand-in value: `ws_transfer` records why no transfer can
            // exist here and what replaces this arm.
            Some(transfer) => match transfer {},
            // The `GOOD_EASY_HANDLE` limb of the condition above, false for
            // every pointer this build can be handed. The code is the C's own
            // for that limb and not a substitute for one.
            None => BAD_EASY_HANDLE,
        }
    })
}

/// `CURLWS_PONG (1 << 6)` (`include/curl/websockets.h:60`).
///
/// **Declared here, mid-file, on purpose.** The frozen header puts this bit
/// between `curl_ws_recv` and `curl_ws_send` under the comment
/// `/* flags for curl_ws_send() */`, apart from its six siblings at `:40-45`,
/// and `sort_by = "None"` makes source order header order. Consolidating the
/// seven into one block would reorder the public contract, so the position is
/// reproduced rather than tidied.
#[allow(dead_code)] // ABI declaration: pinned by test, spliced by build.rs
pub(crate) const CURLWS_PONG: c_uint = 1 << 6;

// 2 of 4: curl_ws_send

/// Sends data over the WebSocket connection.
///
/// Supersedes `curl_ws_send` (`lib/ws.c:1763-1838`), whose prototype is frozen
/// at `include/curl/websockets.h:70-73`. `flags` selects the frame type from
/// the seven `CURLWS_*` frame bits and carries `CURLWS_OFFSET`'s meaning for a
/// continued frame; `fragsize` declares the total payload of a fragmented
/// send. `*sent` receives the number of bytes accepted, and **a short send is
/// reported rather than retried internally**, exactly as the C reports what
/// `ws_enc_send` accepted.
///
/// Two argument shapes are easy to assume wrong, so both are stated as
/// measured. A null `sent` is TOLERATED outside raw mode -- `:1773`
/// substitutes a local dummy, `size_t *pnsent = sent ? sent : &ndummy;` -- and
/// only the raw-mode arm at `:1817-1820` rejects it. And raw mode, selected by
/// `CURLWS_RAW_MODE` on `CURLOPT_WS_OPTIONS`, additionally rejects a null
/// `buffer` and any non-zero `fragsize` or `flags` (`:1813-1824`), because
/// there is no frame for them to describe.
///
/// # Errors
///
/// `CURLE_BAD_FUNCTION_ARGUMENT` for a handle this library did not issue, for
/// a null `buffer` with a non-zero `buflen`, and for the three raw-mode
/// argument rejections above; `CURLE_SEND_ERROR` when the transfer has no
/// connection or is not a WebSocket transfer; `CURLE_AGAIN` when the transport
/// cannot accept more, which is a normal non-blocking answer and is passed
/// through unchanged.
///
/// `CURLE_NOT_BUILT_IN` in a build without WebSocket support
/// (`lib/ws.c:1952-1964`).
///
/// # Safety
///
/// `curl` must be either null or an easy handle this library issued and that
/// has not been released. `buffer` must be either null or readable for
/// `buflen` bytes, and `sent` must be either null or a writable, suitably
/// aligned `size_t` slot. Neither pointer may be used from another thread for
/// the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn curl_ws_send(
    curl: *mut CURL,
    buffer: *const c_void,
    buflen: usize,
    sent: *mut usize,
    fragsize: curl_off_t,
    flags: c_uint,
) -> CURLcode {
    guard(CURLcode::CURLE_FAILED_INIT, || {
        if !WEBSOCKETS_ARE_BUILT_IN {
            // `lib/ws.c:1952-1964` verbatim: all six parameters cast to void,
            // `CURLE_NOT_BUILT_IN` returned, `sent` not written.
            return CURLcode::CURLE_NOT_BUILT_IN;
        }

        // Named for the frozen header and unread on this path, which is the C's
        // arrangement and not an omission. `:1775-1776` tests the handle FIRST
        // and returns before `*pnsent = 0` at `:1781`, so a rejected handle
        // leaves `sent` untouched -- an observable ordering, kept. Everything
        // that reads these five -- the zeroing, the `!buffer && buflen` limb at
        // `:1783-1787`, the connection attach at `:1789-1804`, the raw-mode arm
        // at `:1806-1827` and `ws_enc_send` at `:1830` -- sits behind that
        // test, on the transfer path. The C's own disabled branch casts the
        // same parameters to void at `:1957-1962`.
        let _ = buffer;
        let _ = buflen;
        let _ = sent;
        let _ = fragsize;
        let _ = flags;

        // SAFETY: forwarded verbatim from this function's own contract, which
        // is what `ws_transfer` requires of its caller.
        match unsafe { ws_transfer(curl) } {
            // Where `:1781-1830` goes, with the transfer it acts on.
            Some(transfer) => match transfer {},
            // `:1775-1776`, whose `GOOD_EASY_HANDLE` is false for every
            // pointer this build can be handed.
            None => BAD_EASY_HANDLE,
        }
    })
}

// 3 of 4: curl_ws_start_frame

/// Buffers a WebSocket frame header of the given flags and length.
///
/// Supersedes `curl_ws_start_frame` (`lib/ws.c:1866-1916`), whose prototype is
/// frozen at `include/curl/websockets.h:84-86`. It begins a streaming send:
/// the header for a frame of `frame_len` payload bytes is queued, and the
/// payload follows through [`curl_ws_send`]. The C's own comment at `:80-82`
/// names the error case -- a previous frame whose payload is not yet complete.
///
/// # Errors
///
/// `CURLE_BAD_FUNCTION_ARGUMENT` for a handle this library did not issue.
///
/// **`CURLE_FAILED_INIT` when `CURLWS_RAW_MODE` is set** (`:1876-1879`), and
/// that code is measured rather than inferred: raw mode has no frames to
/// start. The second raw-mode test at `:1896-1900` answers `CURLE_SEND_ERROR`
/// instead, but it is unreachable -- the first test has already returned -- so
/// `CURLE_FAILED_INIT` is the only code a caller can observe for that
/// condition and it is the one reproduced.
///
/// `CURLE_SEND_ERROR` when the transfer has no connection, is not a WebSocket
/// transfer, or still owes payload for a previous frame (`:1884-1906`).
///
/// `CURLE_NOT_BUILT_IN` in a build without WebSocket support
/// (`lib/ws.c:1972-1980`).
///
/// # Safety
///
/// `curl` must be either null or an easy handle this library issued and that
/// has not been released, and must not be used from another thread for the
/// duration of the call. `flags` and `frame_len` are plain scalars.
#[no_mangle]
pub unsafe extern "C" fn curl_ws_start_frame(
    curl: *mut CURL,
    flags: c_uint,
    frame_len: curl_off_t,
) -> CURLcode {
    guard(CURLcode::CURLE_FAILED_INIT, || {
        if !WEBSOCKETS_ARE_BUILT_IN {
            // `lib/ws.c:1972-1980` verbatim: all three parameters cast to void
            // and `CURLE_NOT_BUILT_IN` returned.
            return CURLcode::CURLE_NOT_BUILT_IN;
        }

        // Named for the frozen header and unread on this path. `:1874-1875`
        // tests the handle first, and every use of these two -- the raw-mode
        // rejection at `:1876`, the unfinished-frame test at `:1902` and
        // `ws_enc_write_head` at `:1908` -- is behind it, on the transfer path.
        // The C's disabled branch casts both to void at `:1976-1978`.
        let _ = flags;
        let _ = frame_len;

        // SAFETY: forwarded verbatim from this function's own contract, which
        // is what `ws_transfer` requires of its caller.
        match unsafe { ws_transfer(curl) } {
            // Where `:1876-1913` goes, with the transfer it acts on.
            Some(transfer) => match transfer {},
            // `:1874-1875`, whose `GOOD_EASY_HANDLE` is false for every
            // pointer this build can be handed.
            None => BAD_EASY_HANDLE,
        }
    })
}

// 4 of 4: curl_ws_meta -- declared LAST because websockets.h:92 declares it
// last, after the two CURLOPT_WS_OPTIONS bits at :89-90. See the module
// documentation: `sort_by = "None"` makes this order the header's order.

/// The metadata of the frame currently being received, or NULL.
///
/// Supersedes `curl_ws_meta` (`lib/ws.c:1851-1864`), whose prototype is frozen
/// at `include/curl/websockets.h:92`. The C's comment above it says what the
/// four-part conjunction below it enforces: it answers something only for a
/// WebSocket transfer, called from inside the callback, when not using raw
/// mode. Anything else -- a handle that is not one, a call from outside a
/// callback, a transfer with no connection, `CURLWS_RAW_MODE` set, or a
/// connection with no WebSocket state -- is NULL, and NULL is the only failure
/// channel this signature has.
///
/// **The returned pointer is BORROWED and must not be freed.** It addresses
/// `&ws->recvframe` (`:1861`), the transfer's own metadata block, and stays
/// valid until the next operation on that handle -- which is also why
/// [`curl_ws_recv`] can store the same address through `*metap` and why
/// neither route may ever return the address of a Rust temporary. There is
/// deliberately no `Box::into_raw` here: the boundary's ownership transfer
/// belongs to the handle constructors, and using it for this return would
/// invent a caller-frees contract the frozen API does not have.
///
/// `age` is zero in whatever this eventually returns, as
/// [`super::handle::curl_ws_frame`] records: it is the struct's version field,
/// the C's comment for it is literally `/* zero */`, and a handle that has
/// received no frame yet answers a wholly zeroed block, which is what `calloc`
/// leaves behind in the C.
///
/// # Safety
///
/// `curl` must be either null or an easy handle this library issued and that
/// has not been released, and must not be used from another thread for the
/// duration of the call. The caller must not free the returned pointer and
/// must not retain it across another operation on the same handle.
#[no_mangle]
pub unsafe extern "C" fn curl_ws_meta(curl: *mut CURL) -> *const curl_ws_frame {
    guard_const_ptr(|| {
        if !WEBSOCKETS_ARE_BUILT_IN {
            // `lib/ws.c:1966-1970` verbatim: the parameter is cast to void and
            // NULL is returned.
            return ptr::null();
        }

        // SAFETY: forwarded verbatim from this function's own contract, which
        // is what `ws_transfer` requires of its caller.
        match unsafe { ws_transfer(curl) } {
            // Where the rest of `:1856-1862` goes: the in-callback and
            // raw-mode conjuncts and the WebSocket-state lookup, all three of
            // which read the transfer, followed by the borrow of its own
            // metadata block. Nothing here may become a pointer to a Rust
            // temporary; see this function's documentation.
            Some(transfer) => match transfer {},
            // The `GOOD_EASY_HANDLE` conjunct of `:1856`, false for every
            // pointer this build can be handed. NULL is the C's answer for it
            // and the whole of this signature's error channel.
            None => ptr::null(),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ffi::c_int;
    // `size_of_val` reached the prelude in Rust 1.80 and the declared minimum
    // is 1.75, so it is imported rather than named bare -- measured by
    // `cargo +1.75.0 check`, which rejected the bare form outright.
    use core::mem::{size_of, size_of_val};

    /// The seven frame bits as `(C identifier, value)`, in HEADER order rather
    /// than in value order -- which for this group happens to coincide, and is
    /// asserted below so that a future insertion cannot quietly break it.
    ///
    /// Kept inside the tests rather than beside the constants for two reasons:
    /// a table with no runtime consumer would need its own `dead_code`
    /// allowance, and placing one between `curl_ws_recv` and `curl_ws_send`
    /// would put a non-declaration item exactly where the header's
    /// `CURLWS_PONG` has to sit.
    const FRAME_FLAGS: [(&str, c_uint); 7] = [
        ("CURLWS_TEXT", CURLWS_TEXT),
        ("CURLWS_BINARY", CURLWS_BINARY),
        ("CURLWS_CONT", CURLWS_CONT),
        ("CURLWS_CLOSE", CURLWS_CLOSE),
        ("CURLWS_PING", CURLWS_PING),
        ("CURLWS_OFFSET", CURLWS_OFFSET),
        ("CURLWS_PONG", CURLWS_PONG),
    ];

    /// A non-null pointer that is deliberately not a handle, and which nothing
    /// in this module dereferences. `misc.rs` uses the same address for the
    /// same purpose: a driver linked against a stock libcurl 8.14.1 and handed
    /// it faults, so answering a code for it is a widening this shim makes on
    /// purpose and the tests have to be able to present the input.
    fn foreign_handle() -> *mut CURL {
        0x1000_usize as *mut CURL
    }

    /// Which of `lib/ws.c`'s two branches this build is, asserted rather than
    /// assumed, because every expectation below follows from it.
    #[test]
    fn this_build_is_the_disabled_branch_of_lib_ws_c() {
        // Asserted through the engine's own marker rather than on the constant,
        // for the reason `misc.rs` records: `assert!` on a `const` operand is a
        // constant expression that `clippy::assertions_on_constants` rejects
        // under `-D warnings`, and -- more to the point -- asserting the
        // DERIVATION is what lets the constant flip on its own when the layer
        // lands instead of having to be remembered.
        assert!(
            !curl_rs_lib::version::supports_websockets(),
            "no executor reaches the WebSocket codec, so lib/ws.c:1938-1980 \
             is the branch this build reproduces"
        );
        assert_eq!(
            WEBSOCKETS_ARE_BUILT_IN,
            curl_rs_lib::version::supports_websockets(),
            "the branch marker must be derived, never hand-set"
        );

        // An INERT capability, not an unwritten one, and the distinction
        // matters: `curl-rs-lib/src/protocols/ws.rs` supersedes the whole of
        // `lib/ws.c` and is tested there. What is missing is the wiring.
        assert!(curl_rs_lib::version::ENGINE_PROTOCOLS.is_written());
        assert!(!curl_rs_lib::version::ENGINE_PROTOCOLS.is_present());
    }

    /// The three codes this file answers with, pinned to their frozen
    /// integers. A C program compiled against curl 8.19.0-DEV holds these
    /// numbers, not their names.
    #[test]
    fn the_codes_this_file_answers_with_are_the_frozen_integers() {
        assert_eq!(CURLcode::CURLE_NOT_BUILT_IN as i32, 4);
        assert_eq!(BAD_EASY_HANDLE as i32, 43);
        assert_eq!(
            BAD_EASY_HANDLE,
            CURLcode::CURLE_BAD_FUNCTION_ARGUMENT,
            "the built-in branch's answer for a handle it did not issue"
        );
        // The panic-boundary fallback for this return-type family, which the
        // crate root documents and which every entry point below supplies.
        assert_eq!(CURLcode::CURLE_FAILED_INIT as i32, 2);
        // `CURLE_AGAIN` is not answered by this shim, but it IS a normal
        // return of the built-in branch that no caller may treat as an error,
        // so its integer is pinned where the contract is described.
        assert_eq!(CURLcode::CURLE_AGAIN as i32, 81);
    }

    #[test]
    fn the_seven_frame_flags_are_the_frozen_bits() {
        assert_eq!(CURLWS_TEXT, 1);
        assert_eq!(CURLWS_BINARY, 2);
        assert_eq!(CURLWS_CONT, 4);
        assert_eq!(CURLWS_CLOSE, 8);
        assert_eq!(CURLWS_PING, 16);
        assert_eq!(CURLWS_OFFSET, 32);
        assert_eq!(CURLWS_PONG, 64);

        // Each is a single bit, at the ordinal the header gives it, and the
        // seven are pairwise disjoint -- which is what makes `flags` a mask.
        for (index, (name, value)) in FRAME_FLAGS.iter().enumerate() {
            assert_eq!(
                *value,
                1 << index,
                "{name} must be bit {index}, as (1 << {index})"
            );
            assert_eq!(value.count_ones(), 1, "{name} must be one bit");
        }
        let union = FRAME_FLAGS
            .iter()
            .fold(0_u32, |acc, (_, value)| acc | *value);
        assert_eq!(union, 0x7f, "the seven bits occupy 0..=6 and no more");
        assert_eq!(
            union.count_ones() as usize,
            FRAME_FLAGS.len(),
            "a repeated bit would make two flags indistinguishable"
        );
    }

    /// The frame flags and the `CURLOPT_WS_OPTIONS` bits are different spaces
    /// that share a prefix, and the difference is an ABI one.
    #[test]
    fn the_frame_flags_are_not_the_option_bits() {
        // The two spaces OVERLAP numerically, which is precisely why they must
        // not be merged: `CURLWS_TEXT` and `CURLWS_RAW_MODE` are both bit 0,
        // and `CURLWS_BINARY` and `CURLWS_NOAUTOPONG` are both bit 1.
        assert_eq!(
            i64::from(CURLWS_TEXT),
            super::super::opts::CURLWS_RAW_MODE,
            "both are bit 0 of unrelated masks"
        );
        assert_eq!(
            i64::from(CURLWS_BINARY),
            super::super::opts::CURLWS_NOAUTOPONG,
            "both are bit 1 of unrelated masks"
        );

        // And they differ in width, which is what the `L` suffix in
        // `(1L << 0)` at `websockets.h:89` is there to say: the option bits
        // travel through `curl_easy_setopt`'s varargs as a `long`, while the
        // frame flags travel as a declared `unsigned int` parameter.
        assert_eq!(size_of::<c_uint>(), 4);
        assert_eq!(
            size_of_val(&super::super::opts::CURLWS_RAW_MODE),
            8,
            "c_long is 64-bit on all four mandated targets"
        );
    }

    /// The frozen signatures, proved by the compiler rather than described.
    ///
    /// Each coercion below fails to compile if a parameter type, its order,
    /// its `const` qualification or the return type drifts from
    /// `include/curl/websockets.h`. It is the cheapest available check on the
    /// three asymmetries that are easiest to "tidy": `curl_ws_recv`'s `buffer`
    /// is `void *` while `curl_ws_send`'s is `const void *`, `metap` is
    /// `const struct curl_ws_frame **`, and `flags` is `unsigned int` as a
    /// parameter while `struct curl_ws_frame`'s own field is `int`.
    #[test]
    fn the_four_declared_signatures_are_the_frozen_ones() {
        type Recv = unsafe extern "C" fn(
            *mut CURL,
            *mut c_void,
            usize,
            *mut usize,
            *mut *const curl_ws_frame,
        ) -> CURLcode;
        type Send = unsafe extern "C" fn(
            *mut CURL,
            *const c_void,
            usize,
            *mut usize,
            curl_off_t,
            c_uint,
        ) -> CURLcode;
        type StartFrame =
            unsafe extern "C" fn(*mut CURL, c_uint, curl_off_t) -> CURLcode;
        type Meta = unsafe extern "C" fn(*mut CURL) -> *const curl_ws_frame;

        let recv: Recv = curl_ws_recv;
        let send: Send = curl_ws_send;
        let start_frame: StartFrame = curl_ws_start_frame;
        let meta: Meta = curl_ws_meta;

        // Non-vacuity, and it deliberately does NOT compare the pointers:
        // `std::ptr::fn_addr_eq` is Rust 1.85 and the declared minimum is
        // 1.75, while `==` on function pointers is rejected outright by
        // `-D warnings`. Each is CALLED through its coerced pointer instead,
        // which is what a consumer resolving these symbols does, and which
        // proves the signature is callable and not merely nameable.
        //
        // SAFETY: every handle is null and no pointer argument is
        // dereferenced on the disabled branch these four take.
        unsafe {
            let want = CURLcode::CURLE_NOT_BUILT_IN;
            assert_eq!(
                recv(
                    ptr::null_mut(),
                    ptr::null_mut(),
                    0,
                    ptr::null_mut(),
                    ptr::null_mut()
                ),
                want
            );
            assert_eq!(
                send(ptr::null_mut(), ptr::null(), 0, ptr::null_mut(), 0, 0),
                want
            );
            assert_eq!(start_frame(ptr::null_mut(), 0, 0), want);
            assert!(meta(ptr::null_mut()).is_null());
        }
    }

    /// `lib/ws.c:1940-1980` answers every input the same way, having cast every
    /// parameter to void. Reproduced argument for argument, including the ones
    /// the built-in branch would reject differently.
    #[test]
    fn the_disabled_branch_answers_every_input_the_same_way() {
        let want = CURLcode::CURLE_NOT_BUILT_IN;
        let mut payload = [0_u8; 8];
        let buffer = payload.as_mut_ptr().cast::<c_void>();

        for (label, handle) in [
            ("a null handle", ptr::null_mut::<CURL>()),
            ("a handle this library did not issue", foreign_handle()),
        ] {
            let mut count = usize::MAX;
            let mut meta: *const curl_ws_frame = ptr::null();

            // SAFETY: `handle` is null or a bogus address that nothing
            // dereferences, `buffer` addresses eight live writable bytes, and
            // `count` and `meta` are live writable slots of the declared
            // types.
            let code = unsafe {
                curl_ws_recv(
                    handle,
                    buffer,
                    payload.len(),
                    &mut count,
                    &mut meta,
                )
            };
            assert_eq!(code, want, "curl_ws_recv: {label}");

            // SAFETY: as above, with `buffer` read rather than written.
            let code = unsafe {
                curl_ws_send(
                    handle,
                    buffer.cast::<c_void>(),
                    payload.len(),
                    &mut count,
                    0,
                    CURLWS_BINARY,
                )
            };
            assert_eq!(code, want, "curl_ws_send: {label}");

            // SAFETY: `handle` is null or a bogus address that nothing
            // dereferences; both remaining arguments are scalars.
            let code = unsafe { curl_ws_start_frame(handle, CURLWS_TEXT, 4) };
            assert_eq!(code, want, "curl_ws_start_frame: {label}");

            // SAFETY: as above; the pointer returned is only compared.
            let frame = unsafe { curl_ws_meta(handle) };
            assert!(frame.is_null(), "curl_ws_meta: {label}");
        }
    }

    /// The disabled branch writes NO out-parameter, which is measurable rather
    /// than merely stated: `lib/ws.c:1940-1950` casts `nread` and `metap` to
    /// void without storing through either.
    #[test]
    fn the_disabled_branch_leaves_both_out_parameters_untouched() {
        let mut byte = 0_u8;
        let buffer = (&mut byte as *mut u8).cast::<c_void>();
        let sentinel_count = 0xdead_usize;
        let sentinel_meta = 0x1_usize as *const curl_ws_frame;
        let mut count = sentinel_count;
        let mut meta = sentinel_meta;

        // SAFETY: `buffer` addresses one live writable byte and both out-slots
        // are live and writable; the handle is a bogus address that nothing
        // dereferences.
        let code = unsafe {
            curl_ws_recv(foreign_handle(), buffer, 1, &mut count, &mut meta)
        };
        assert_eq!(code, CURLcode::CURLE_NOT_BUILT_IN);
        assert_eq!(count, sentinel_count, "*recv must not be written");
        assert_eq!(meta, sentinel_meta, "*metap must not be written");

        let mut sent = sentinel_count;
        // SAFETY: as above, with `buffer` read rather than written.
        let code = unsafe {
            curl_ws_send(foreign_handle(), buffer, 1, &mut sent, 0, CURLWS_TEXT)
        };
        assert_eq!(code, CURLcode::CURLE_NOT_BUILT_IN);
        assert_eq!(sent, sentinel_count, "*sent must not be written");
    }

    /// A null out-parameter is never dereferenced, and a null `buffer` with a
    /// zero `buflen` is not an error -- the C's limb is `buflen && !buffer`
    /// (`lib/ws.c:1541`), not `!buffer`. A null `sent` is likewise tolerated
    /// outside raw mode, because `:1773` substitutes a local dummy.
    #[test]
    fn null_pointers_the_c_accepts_are_accepted_here_too() {
        let want = CURLcode::CURLE_NOT_BUILT_IN;

        // SAFETY: every pointer is null and none is dereferenced on this path.
        let code = unsafe {
            curl_ws_recv(
                foreign_handle(),
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        assert_eq!(code, want, "a zero-length receive with null everything");

        // SAFETY: `buffer` and `sent` are both null and neither is
        // dereferenced on this path.
        let code = unsafe {
            curl_ws_send(
                foreign_handle(),
                ptr::null(),
                0,
                ptr::null_mut(),
                0,
                CURLWS_CLOSE,
            )
        };
        assert_eq!(code, want, "a zero-length send with a null sent");
    }

    /// `curl_ws_meta` answers NULL for every handle this build can be handed,
    /// and the pointer it eventually answers is BORROWED: never the address of
    /// a Rust temporary, and never freed by the caller.
    #[test]
    fn curl_ws_meta_answers_null_and_never_a_temporary() {
        for handle in [ptr::null_mut::<CURL>(), foreign_handle()] {
            // SAFETY: the handle is null or a bogus address that nothing
            // dereferences; the result is only tested for nullity.
            let first = unsafe { curl_ws_meta(handle) };
            // SAFETY: as above. Called twice on purpose: the C answers from
            // the transfer's own storage, so two calls with no intervening
            // transfer must agree rather than each producing a fresh
            // allocation.
            let second = unsafe { curl_ws_meta(handle) };
            assert!(first.is_null());
            assert_eq!(first, second, "the answer is state, not an allocation");
        }
    }

    /// The two writes of `lib/ws.c:1539-1540`, exercised directly.
    ///
    /// They are the only stores through a caller-supplied pointer in this file
    /// and they sit on the built-in branch, which [`WEBSOCKETS_ARE_BUILT_IN`]
    /// does not select today -- so calling the entry point cannot reach them.
    /// Calling the helper can, which is what puts them under Miri now rather
    /// than when the marker flips.
    #[test]
    fn the_receive_out_parameters_are_cleared_and_null_ones_skipped() {
        let mut count = usize::MAX;
        let mut meta = 0x1_usize as *const curl_ws_frame;

        // SAFETY: both are live, writable, correctly aligned slots of the
        // declared types and nothing else aliases them here.
        unsafe { clear_receive_out_params(&mut count, &mut meta) };
        assert_eq!(count, 0, "*recv is cleared to zero");
        assert!(meta.is_null(), "*metap is cleared to NULL");

        // The widening: a null slot is skipped rather than written, where the C
        // would fault. Reaching this line at all is the assertion.
        // SAFETY: both pointers are null, and the helper's contract admits
        // null explicitly.
        unsafe { clear_receive_out_params(ptr::null_mut(), ptr::null_mut()) };

        // One of each, so neither test can be satisfied by the other's branch.
        let mut only_count = usize::MAX;
        // SAFETY: `only_count` is a live writable slot; the metadata slot is
        // null, which the contract admits.
        unsafe { clear_receive_out_params(&mut only_count, ptr::null_mut()) };
        assert_eq!(only_count, 0);
        let mut only_meta = 0x1_usize as *const curl_ws_frame;
        // SAFETY: `only_meta` is a live writable slot; the count slot is null.
        unsafe { clear_receive_out_params(ptr::null_mut(), &mut only_meta) };
        assert!(only_meta.is_null());
    }

    /// `age` is `struct curl_ws_frame`'s version field: first, and zero.
    ///
    /// The five field offsets are asserted field by field in `handle.rs`'s own
    /// `layout` tests, which compute them by pointer arithmetic because
    /// `offset_of!` is Rust 1.77 and the declared minimum is 1.75. That
    /// machinery is not repeated here; what is asserted is the one property
    /// this file's contract turns on.
    #[test]
    fn the_frame_metadata_begins_with_a_zero_age() {
        let frame = curl_ws_frame {
            age: 0,
            flags: 0,
            offset: 0,
            bytesleft: 0,
            len: 0,
        };
        assert_eq!(frame.age, 0, "the version field is zero");
        assert_eq!(
            ptr::addr_of!(frame.age),
            ptr::addr_of!(frame).cast::<c_int>(),
            "`age` must be the first member, or every offsetof moves"
        );
        // The asymmetry the module documentation names, held by the compiler:
        // the struct's field is `int` while the `flags` PARAMETER of the two
        // senders is `unsigned int`. A negative literal in the field is what
        // proves it -- the same initialiser against a `c_uint` field would not
        // compile -- and the two are the same width, so the asymmetry is about
        // signedness alone.
        assert_eq!(size_of::<c_int>(), size_of::<c_uint>());
        let signed = curl_ws_frame {
            age: 0,
            flags: -1,
            offset: 0,
            bytesleft: 0,
            len: 0,
        };
        assert_eq!(signed.flags, -1, "`flags` is `int` inside the struct");
    }
}
