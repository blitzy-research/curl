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

// THE LICENCE BANNER ABOVE -- 23 lines, byte-identical to `util/mod.rs:1-23`.
//
// That file records why it is spelled this way and why the licence tag is
// never written a second time in prose: `reuse` parses every line carrying
// the tag's colon form as a licence expression, so a prose mention becomes a
// parse error rather than prose. The tag appears exactly once here, on line
// 21, and nowhere else in this file. The reasoning is not repeated -- see
// `util/mod.rs:25-61`.
//
// `dead_code` IS NOT ALLOWED for this file as a whole, and no attribute below
// grants it at module scope. Every item carries its own
// `#[allow(dead_code)]`, so the suppression reads as an inventory: each one is
// load-bearing, deleting any one restores a warning, and an item added later
// with no consumer is still reported. This is not merely a convention --
// `mod source_policy` in `curl-rs-lib/src/lib.rs` walks the workspace at test
// time and fails on a `dead_code` level set on any crate root or module root,
// this file included.
//
// The allowances here are expected to be short-lived, and the reason is
// structural rather than incidental: `util` is the BASE of this crate's module
// graph, so its consumers are the last code to exist. The C call sites this
// module serves live in `lib/vauth/`, `lib/http_ntlm.c`, `lib/formdata.c` and
// `lib/url.c`, which become `crate::auth`, `crate::mime` and `crate::url` --
// none of them written yet. Each allowance is deleted when its consumer lands.
//
// No level for the `unsafe_code` lint is set here, at any level. `src/lib.rs`
// carries `#![deny(unsafe_code)]` and grants exactly ONE exemption, on
// `mod ffi`. This file contains no block bearing that keyword and no
// `#[allow(unsafe_code)]`, which matters especially here: the C original is
// built entirely out of a raw pointer, a length and a function pointer to
// free with, and reproducing it safely is this module's whole reason to
// exist.

//! The generic buffer reference -- supersedes `lib/bufref.c` (138 lines) and
//! `lib/bufref.h` (52).
//!
//! `struct bufref` is curl's hand-rolled answer to "a byte buffer that may be
//! borrowed or owned, and knows how to release itself". It carries a
//! destructor so that a caller can hand over either a `malloc`ed buffer or a
//! static one without the receiver having to know which. Rust has that type in
//! its standard library, so the target representation is [`Cow`] over a byte
//! slice, aliased here as [`BufRef`]. The transformation is a genuine
//! simplification and the specification sanctions it directly (AAP 0.6.9,
//! which names untyped contexts and hand-rolled ownership discriminators as
//! the constructs a standard-library type replaces outright).
//!
//! # The C type, measured
//!
//! ```text
//! struct bufref {                 /* lib/bufref.h:30-37 */
//!   void (*dtor)(void *);         /* Associated destructor. */
//!   const unsigned char *ptr;     /* Referenced data buffer. */
//!   size_t len;                   /* The data size in bytes. */
//! #ifdef DEBUGBUILD
//!   int signature;                /* Detect API use mistakes. */
//! #endif
//! };
//! ```
//!
//! # Three C constructs vanish
//!
//! Listing them is the point of this section: each one exists only because C
//! cannot express what `Cow` expresses, so none has a Rust successor and none
//! is reintroduced under another name.
//!
//! 1. **The `dtor` function pointer.** `Curl_bufref_set`
//!    (`lib/bufref.c:72-82`) takes a destructor precisely so that the
//!    reference can own either a heap buffer -- callers pass `curl_free` -- or
//!    a borrowed and static one, for which they pass `NULL`. That single
//!    pointer is the owned-versus-borrowed discriminator, checked at run time
//!    on every release: `if(br->ptr && br->dtor) br->dtor(...)`
//!    (`lib/bufref.c:60-61`). [`Cow::Owned`] and [`Cow::Borrowed`] encode the
//!    same distinction in the type, and `Drop` runs the correct cleanup with
//!    no field to set, no branch to take and nothing to forget.
//!
//! 2. **The `signature` field, `0x5c48e9b2`** (`lib/bufref.c:31`, "Random
//!    pattern"). A `DEBUGBUILD`-only detector for a reference that was never
//!    initialised or has been overwritten, asserted by every one of the six
//!    accessors. The constant is written out here so that a reader grepping
//!    the C tree for it lands on this paragraph, and it is then deleted: a
//!    `Cow` cannot be in that state, because there is no way to obtain one
//!    without initialising it.
//!
//! 3. **The `ptr || !len` invariant.** Also asserted by every accessor -- a
//!    null pointer implies a zero length. It is structural in Rust rather than
//!    checked: an empty slice has length zero and a pointer that is valid to
//!    compare and to offset by nothing, so the two halves cannot disagree.
//!
//! # The API map
//!
//! Seven functions plus one macro, each with a counterpart or a documented
//! subsumption. Where the Rust column reads as a plain expression, no wrapper
//! is written: a function that only forwards is noise, and the specification's
//! minimal-change mandate rules it out (AAP 0.8.2).
//!
//! | C entry point | Measured at | Rust |
//! |---|---|---|
//! | `Curl_bufref_init` | `bufref.c:37-47` | [`empty`] |
//! | `Curl_bufref_free` | `bufref.c:54-66` | `Drop`, or assignment |
//! | `Curl_bufref_set` | `bufref.c:72-82` | [`borrowed`], [`owned`] |
//! | `Curl_bufref_ptr` | `bufref.c:99-106` | `&*br` |
//! | `Curl_bufref_uptr` | `bufref.c:87-94` | `&*br` -- the same slice |
//! | `Curl_bufref_len` | `bufref.c:111-118` | `br.len()`, `br.is_empty()` |
//! | `Curl_bufref_memdup0` | `bufref.c:120-138` | [`memdup0`] |
//! | `Curl_bufref_dup` | `bufref.h:49` | [`dup`] -- see the divergence |
//!
//! Two of those rows deserve their reasoning stated rather than implied.
//!
//! `Curl_bufref_ptr` and `Curl_bufref_uptr` differ only in returning
//! `const char *` versus `const unsigned char *`; the bodies are the same
//! field read through a different cast. Rust has one byte type, so the two
//! collapse into one expression, and because [`BufRef`] dereferences to
//! `[u8]`, that expression needs no function: `&*br` and `br.as_ref()` both
//! yield the slice, and every method on `[u8]` is already reachable.
//!
//! `Curl_bufref_free` has no successor because releasing is what `Drop` is.
//! The C comment on it (`lib/bufref.c:49-52`) is worth carrying over --
//! "it does not touch the 'signature' field and thus this buffer reference can
//! be reused" -- because reuse is exactly what Rust assignment gives: writing
//! `br = bufref::owned(next)` drops the previous value first, which is the
//! same ordering `Curl_bufref_set` spells out by calling `Curl_bufref_free`
//! before it assigns (`lib/bufref.c:69-70, 78`).
//!
//! # No `clear` helper, and the measurement that settled it
//!
//! An explicit mid-life release looked worth a helper until the 16 C call
//! sites were counted. Twelve are end-of-scope or struct teardown, which
//! `Drop` subsumes entirely: `lib/url.c:175-176` and `:265`,
//! `lib/formdata.c:158-161`, `lib/curl_sasl.c:585`, `:812` and `:831`,
//! `lib/http_ntlm.c:81` and `:249`. Four are genuine mid-life clears --
//! `lib/setopt.c:2218`, `lib/url.c:1741`, `lib/http.c:1147` and
//! `lib/curl_sasl.c:573` -- and three of those four clear a field back to the
//! *unset* state that other code then tests for, which the next section shows
//! is a state a `BufRef` deliberately cannot represent. In Rust those three
//! are `*field = None` on an `Option`, so a `clear` taking `&mut BufRef`
//! would be the wrong tool at exactly the sites that appeared to want it, and
//! a quietly wrong one. It is therefore not provided.
//!
//! # Unset versus empty: a distinction that survives, elsewhere
//!
//! `Curl_bufref_ptr` returns `NULL` for a reference that was never set, and
//! callers test it. The obvious translation -- an empty slice -- would fold
//! "no buffer" and "a buffer of length zero" together, so whether any caller
//! actually distinguishes them had to be measured rather than assumed. **One
//! does, and it changes bytes on the wire** (`lib/curl_sasl.c:253-256`):
//!
//! ```text
//! if(!Curl_bufref_ptr(msg))          /* Empty message.           */
//!   Curl_bufref_set(msg, "", 0, NULL);
//! else if(!Curl_bufref_len(msg))     /* Explicit empty response. */
//!   Curl_bufref_set(msg, "=", 1, NULL);
//! else
//!   ... base64-encode ...
//! ```
//!
//! Three states, and the middle one emits `=` where the first emits nothing.
//! Fifteen further null tests read the same way -- "was this field ever
//! set?": `lib/easy.c:1014`, `:1018`, `:1021` and `:1025`, which copy the URL
//! and referer into a duplicated handle only when they were set;
//! `lib/formdata.c:281`, `:374`, `:398`, `:437`, `:513` and `:557`;
//! `lib/http.c:2935`; `lib/rtsp.c:468`; `lib/url.c:3264`; and
//! `lib/curl_sasl.c:253` and `:567`.
//!
//! Nullability is nevertheless NOT reintroduced here. [`BufRef`] always
//! denotes a buffer; a field that additionally needs "no buffer at all" is
//! `Option<BufRef<'_>>` at ITS OWN declaration, where `None` is the C's
//! `NULL` and the compiler forces every reader to handle it. Those
//! declarations belong to `crate::easy`, `crate::url`, `crate::mime`,
//! `crate::protocols::http1` and `crate::auth` -- none of them this file.
//! Recording the finding here is what stops each of them rediscovering it,
//! and preserving that three-way branch is required: SASL message framing is
//! wire behaviour, which is frozen (AAP 0.8.1).
//!
//! # The one deliberate divergence: `dup` does not truncate
//!
//! `Curl_bufref_dup` is a macro, not a function (`lib/bufref.h:48-49`):
//!
//! ```text
//! /* return a strdup() version of the buffer */
//! #define Curl_bufref_dup(x) curlx_strdup(Curl_bufref_ptr(x))
//! ```
//!
//! It reaches the buffer through `Curl_bufref_ptr` and then calls `strdup`,
//! which stops at the first NUL byte. The length the reference is carrying is
//! discarded. For a buffer holding an interior zero -- a binary
//! authentication token, say -- the macro therefore returns a TRUNCATED copy,
//! silently. [`dup`] copies every byte, so the two disagree on exactly that
//! input, and the disagreement is flagged rather than absorbed because the
//! minimal-change mandate requires a behavioural difference to be visible
//! (AAP 0.8.2).
//!
//! No call site depends on the truncation, and that was checked rather than
//! hoped for. All eight duplicate URL or referer text: `lib/multi.c:1972`,
//! `lib/http.c:593`, `:607`, `:893` and `:4101`, `lib/easy.c:1016` and
//! `:1023`, and `lib/transfer.c:664`. None can contain an interior NUL, so
//! the divergent input is unreachable from the C tree as it stands -- the
//! difference is latent, which is precisely why it is written down.
//!
//! # `memdup0` keeps the C's length, not the C's terminator
//!
//! `curlx_memdup0` (`lib/curlx/strdup.c:85-96`) allocates `length + 1`,
//! copies `length` bytes and writes `buf[length] = 0`, so the buffer can also
//! be read as a C string -- while `Curl_bufref_memdup0` records the length
//! WITHOUT the terminator. [`memdup0`] does not store the terminator at all,
//! which makes `len()` equal the C's `len` exactly. The decision is recorded
//! because the name is otherwise misleading in a Rust port: the trailing `0`
//! now refers to the C function it supersedes and not to anything in the
//! bytes. A caller that genuinely needs C-string semantics adds the
//! terminator at that boundary, and inside this crate none does -- the need
//! survives only where a `*const c_char` is handed to C, which `curl-rs-ffi`
//! owns.
//!
//! # Layering
//!
//! `util` is the base of this crate's module graph and depends on nothing
//! except [`crate::error`]. This file honours that with two imports and no
//! more. Its C original opens with `#include "urldata.h"`
//! (`lib/bufref.c:26`), which grants blanket access to the god-struct, and
//! the only thing it actually needs from there is one constant -- so that
//! constant is reproduced below as a measured literal rather than fetched by
//! reaching into a sibling module (AAP 0.4.2).
//!
//! # Scope
//!
//! Deliberately thin. `dynbuf` owns growable accumulation and `bufq` owns
//! chunked queueing; three modules with overlapping buffer abstractions would
//! be a defect rather than thoroughness. Nothing here is reachable from
//! `curl-rs-ffi` either -- `lib/libcurl.def` exports no `curl_bufref_*`
//! symbol among its 100 names -- so every item is `pub(crate)` and none is
//! widened to `pub`.

use std::borrow::Cow;

use crate::error::CURLcode;

/// The upper bound the C asserts on a buffer length, as a measured literal.
///
/// `CURL_MAX_INPUT_LENGTH` is `8000000`, defined at **`lib/urldata.h:131`**
/// under the comment "Max string input length is a precaution against abuse
/// and to detect junk input easier and better" (`:129-130`). Both mutators
/// assert against it: `Curl_bufref_set` at `lib/bufref.c:76` and
/// `Curl_bufref_memdup0` at `:128`.
///
/// Written out here rather than reached for, and the reason is layering
/// rather than taste. The C obtains it by including the god-struct header
/// (`#include "urldata.h"`, `lib/bufref.c:26`), and `util` depends on nothing
/// beyond [`crate::error`], so a blanket include becomes a measured literal
/// (AAP 0.4.2).
///
/// PRIVATE to this file, on purpose. The bound is curl-wide in C -- the
/// option setters in `lib/setopt.c` assert against it too -- so it will
/// eventually want one shared home, and choosing that home belongs to the
/// unit of work that brings the second consumer. Publishing it now would
/// settle that question early and widen the crate's surface with nothing
/// asking for it.
const MAX_INPUT_LENGTH: usize = 8_000_000;

/// A byte buffer that is either borrowed or owned -- supersedes
/// `struct bufref` (`lib/bufref.h:30-37`).
///
/// A plain alias over [`Cow`], deliberately, rather than a newtype. A wrapper
/// would have to forward `len`, `is_empty`, indexing, iteration, `PartialEq`,
/// `Clone` and every other slice operation its callers use, and would earn
/// nothing in exchange: once the destructor and the signature are gone the C
/// type has no invariant left to protect. The alias keeps
/// `Deref<Target = [u8]>`, so `&*br` is the C's `Curl_bufref_ptr` and
/// `br.len()` is `Curl_bufref_len`, at no cost and with no new API to learn.
///
/// The lifetime parameter is what replaces the `dtor` field. A
/// `BufRef<'static>` from [`owned`] or [`memdup0`] carries its own allocation
/// and releases it on drop, exactly as a C reference holding `curl_free`
/// does; one from [`borrowed`] cannot outlive the bytes it points at, which
/// is the rule a C reference holding a `NULL` destructor could only state in
/// a comment.
#[allow(dead_code)]
pub(crate) type BufRef<'a> = Cow<'a, [u8]>;

/// An empty reference owning nothing -- supersedes `Curl_bufref_init`
/// (`lib/bufref.c:37-47`).
///
/// The C zeroes all three fields and stamps the signature. Here there is
/// nothing to zero, so this is the value that the zeroed struct denotes: a
/// buffer of no bytes, borrowed from a slice literal that is promoted to
/// `'static`, and therefore free of any allocation.
///
/// [`Cow::Borrowed`] rather than [`Cow::Owned`] with an empty [`Vec`], and
/// rather than `Cow::default()` -- which yields the owned form -- because the
/// borrowed form is what the C's `dtor = NULL` means: there is nothing to
/// release. Neither allocates, so the choice is about faithfulness rather
/// than cost.
///
/// It has a second, exact call shape in the C. `lib/curl_sasl.c:254` writes
/// `Curl_bufref_set(msg, "", 0, NULL)` -- a borrowed, zero-length, ownerless
/// buffer -- which is this function.
///
/// Note what this is NOT: the C's `NULL` pointer, meaning "never set". That
/// state is `None` on an `Option<BufRef<'_>>` at the field that needs it; see
/// the module documentation for the measurement showing the difference is
/// observable on the wire.
#[allow(dead_code)]
pub(crate) fn empty() -> BufRef<'static> {
    Cow::Borrowed(&[])
}

/// Borrows `bytes` without copying -- one half of `Curl_bufref_set`
/// (`lib/bufref.c:72-82`), the half whose callers pass no destructor.
///
/// `Curl_bufref_set(out, value, strlen(value), NULL)`
/// (`lib/vauth/cleartext.c:91`) is the canonical C shape: the reference
/// points at storage somebody else owns, and releasing it is somebody else's
/// business. The lifetime enforces here what that `NULL` only documented
/// there.
///
/// The C's "previously referenced buffer is released before assignment"
/// (`lib/bufref.c:69-70`) needs no counterpart in this function, because the
/// release belongs to the assignment rather than to the constructor: writing
/// `br = bufref::borrowed(next)` drops whatever `br` held first, in that
/// order, whether it owned an allocation or not.
///
/// # Panics
///
/// In a debug build only, panics when `bytes` is longer than
/// [`MAX_INPUT_LENGTH`], reproducing `DEBUGASSERT(len <=
/// CURL_MAX_INPUT_LENGTH)` at `lib/bufref.c:76`. A release build, like the C,
/// does not check.
#[allow(dead_code)]
pub(crate) fn borrowed(bytes: &[u8]) -> BufRef<'_> {
    debug_assert!(
        bytes.len() <= MAX_INPUT_LENGTH,
        "Curl_bufref_set contract: {} bytes exceeds \
         CURL_MAX_INPUT_LENGTH ({MAX_INPUT_LENGTH})",
        bytes.len()
    );

    Cow::Borrowed(bytes)
}

/// Takes ownership of `bytes` -- the other half of `Curl_bufref_set`
/// (`lib/bufref.c:72-82`), the half whose callers pass `curl_free`.
///
/// `Curl_bufref_set(out, auth, len, curl_free)`
/// (`lib/vauth/cleartext.c:72`) and `Curl_bufref_set(out, ntlmbuf, size,
/// curl_free)` (`lib/vauth/ntlm.c:524`) are the C shapes. There is no
/// destructor argument because there is nothing left for one to decide:
/// [`Vec`] frees its own allocation, and it does so on the path the C could
/// only reach by remembering to store the right function pointer.
///
/// Prefer this over [`memdup0`] whenever the caller already owns the bytes.
/// The two differ by exactly one copy, and this one does not make it.
///
/// # Panics
///
/// In a debug build only, panics when `bytes` is longer than
/// [`MAX_INPUT_LENGTH`], reproducing `DEBUGASSERT(len <=
/// CURL_MAX_INPUT_LENGTH)` at `lib/bufref.c:76`. A release build, like the C,
/// does not check.
#[allow(dead_code)]
pub(crate) fn owned(bytes: Vec<u8>) -> BufRef<'static> {
    debug_assert!(
        bytes.len() <= MAX_INPUT_LENGTH,
        "Curl_bufref_set contract: {} bytes exceeds \
         CURL_MAX_INPUT_LENGTH ({MAX_INPUT_LENGTH})",
        bytes.len()
    );

    Cow::Owned(bytes)
}

/// Copies `bytes` into a new owned reference -- supersedes
/// `Curl_bufref_memdup0` (`lib/bufref.c:120-138`).
///
/// The C copies through `curlx_memdup0` (`lib/curlx/strdup.c:85-96`), which
/// allocates `length + 1` bytes, copies `length` of them and writes
/// `buf[length] = 0`, then installs `curl_free` as the destructor. Its guard
/// `(length < SIZE_MAX)` has nothing to guard here: a Rust slice can never be
/// that long, since its length is bounded by `isize::MAX`.
///
/// **The terminator is not stored.** `Curl_bufref_memdup0` records the length
/// WITHOUT it, so omitting it is what makes `len()` agree with the C exactly;
/// see the module documentation for why the name keeps its trailing `0`
/// regardless. A caller needing C-string semantics appends the terminator at
/// that boundary, which is `curl-rs-ffi`'s job and not this module's.
///
/// # Errors
///
/// [`CURLcode::OutOfMemory`], which is `CURLE_OUT_OF_MEMORY = 27` and is
/// exactly what the C returns when its allocation fails
/// (`lib/bufref.c:132-133`).
///
/// That branch is reachable, and making it so was a decision. `bytes.to_vec()`
/// would be shorter and would ABORT the process on allocation failure, which
/// is a behavioural change from the C's graceful return -- and curl's own
/// torture testing injects precisely that failure. [`Vec::try_reserve_exact`]
/// keeps the C's failure mode, costs one line, and is stable well inside the
/// 1.75 minimum supported version. Faithfulness wins over brevity here
/// because performance is an explicit non-goal (AAP 0.1.1).
///
/// # Panics
///
/// In a debug build only, panics when `bytes` is longer than
/// [`MAX_INPUT_LENGTH`], reproducing `DEBUGASSERT(len <=
/// CURL_MAX_INPUT_LENGTH)` at `lib/bufref.c:128`. The check precedes the copy,
/// as it does in the C, so an over-long buffer is reported rather than
/// duplicated first.
#[allow(dead_code)]
pub(crate) fn memdup0(bytes: &[u8]) -> Result<BufRef<'static>, CURLcode> {
    debug_assert!(
        bytes.len() <= MAX_INPUT_LENGTH,
        "Curl_bufref_memdup0 contract: {} bytes exceeds \
         CURL_MAX_INPUT_LENGTH ({MAX_INPUT_LENGTH})",
        bytes.len()
    );

    let mut copy = Vec::new();
    copy.try_reserve_exact(bytes.len())
        .map_err(|_| CURLcode::OutOfMemory)?;
    copy.extend_from_slice(bytes);

    Ok(owned(copy))
}

/// Duplicates the referenced bytes -- supersedes the `Curl_bufref_dup` macro
/// (`lib/bufref.h:48-49`).
///
/// Takes `&[u8]` rather than `&BufRef<'_>` so that a caller writes
/// `bufref::dup(&br)` and reads exactly like the C's `Curl_bufref_dup(&br)`:
/// [`BufRef`] dereferences to the slice, so the coercion is silent. The slice
/// form is also the honest signature, since the macro reaches the bytes
/// through `Curl_bufref_ptr` and never looks at the reference again.
///
/// The body is `bytes.to_vec()`, and a caller who prefers to write that
/// directly loses nothing. This function exists to give the macro's eight
/// call sites a named successor and to put the divergence below next to code
/// rather than only in prose.
///
/// # Divergence from the C -- the only one in this module
///
/// The macro expands to `curlx_strdup(Curl_bufref_ptr(x))`, so it STOPS AT
/// THE FIRST NUL BYTE and discards the length the reference was carrying. On
/// a buffer holding an interior zero it returns a silently truncated copy.
/// This copies every byte. The two therefore disagree on exactly that input,
/// and the difference is recorded rather than absorbed, because a behavioural
/// change has to be visible (AAP 0.8.2).
///
/// No existing call site can reach the divergent input: all eight duplicate
/// URL or referer text -- `lib/multi.c:1972`, `lib/http.c:593`, `:607`,
/// `:893` and `:4101`, `lib/easy.c:1016` and `:1023`, and
/// `lib/transfer.c:664`. The difference is latent, which is why it is written
/// down instead of assumed harmless.
#[allow(dead_code)]
pub(crate) fn dup(bytes: &[u8]) -> Vec<u8> {
    bytes.to_vec()
}

// The coverage `tests/unit/*.c` would have carried, relocated here.
//
// Those C programs link a debug static libcurl and call internal `Curl_*`
// symbols; a Rust static library genuinely does not export `pub(crate)` items,
// so no quality of implementation makes them link. Relocating the assertions
// into the module is the documented resolution (AAP 0.8.7), and re-exporting
// internals to satisfy the C harness instead would defeat the encapsulation
// that the zero-keyword safety guarantee rests on.
//
// Miri is the gate that matters for this module rather than an extra: every
// behaviour here is about ownership, which is exactly what Miri inspects. It
// reports a leak at the end of a test as a failure, so a reassignment that
// failed to release its predecessor would be caught by
// `reassignment_releases_the_previous_owned_buffer` even though no ordinary
// assertion can observe a `Vec` being freed.
#[cfg(test)]
mod tests {
    use super::*;

    /// A borrowed reference copies nothing and reports the same bytes.
    ///
    /// The C equivalent is `Curl_bufref_set(br, value, len, NULL)` -- a
    /// destructor of `NULL`, meaning "not mine to free". The
    /// [`Cow::Borrowed`] match arm is the assertion that no allocation
    /// happened: an owned value could not match it.
    #[test]
    fn a_borrowed_reference_shares_its_bytes() {
        // Shaped like the Digest challenge a `bufref` actually carries in
        // `lib/vauth/digest.c`, with a self-evidently synthetic value: the
        // test needs only SOME bytes, so nothing here should read as though
        // it were ever a real credential.
        static CHALLENGE: &[u8] =
            b"realm=example.test, nonce=PLACEHOLDER-NOT-A-SECRET";

        let br = borrowed(CHALLENGE);

        assert!(matches!(br, Cow::Borrowed(_)), "borrowing must not copy");
        assert_eq!(&*br, CHALLENGE, "Curl_bufref_ptr yields the same bytes");
        assert_eq!(br.len(), CHALLENGE.len(), "Curl_bufref_len agrees");
        assert!(!br.is_empty());

        // The C's two accessors differ only in their cast, so both spellings
        // of the slice must be the one slice.
        assert_eq!(br.as_ref(), &*br);
    }

    /// `memdup0` copies every byte and stores NO terminator.
    ///
    /// This is the decision the module documentation records. `curlx_memdup0`
    /// allocates `len + 1` and writes `buf[len] = 0`, while
    /// `Curl_bufref_memdup0` records `len`; not storing the terminator is what
    /// makes `len()` agree with the C exactly, so the assertion on the final
    /// byte is the substantive one rather than decoration.
    #[test]
    fn memdup0_copies_the_bytes_and_appends_no_terminator() {
        let source = b"TlRMTVNTUAACAAAA";

        let br = memdup0(source).expect("a 16-byte copy cannot fail");

        assert!(matches!(br, Cow::Owned(_)), "memdup0 must own its copy");
        assert_eq!(&*br, source);
        assert_eq!(br.len(), source.len(), "the C's len excludes the NUL");
        assert_eq!(
            br.last(),
            Some(&b'A'),
            "the last byte is the source's last byte, not a terminator"
        );
        assert!(!br.contains(&0), "no NUL is stored anywhere");
    }

    /// `memdup0` of nothing succeeds and yields a zero-length reference.
    ///
    /// The C reaches this through `if(ptr)` being false
    /// (`lib/bufref.c:130`), which skips the copy and sets a null reference
    /// with the given -- necessarily zero -- length, returning `CURLE_OK`.
    /// Passing a non-null pointer with a zero length instead makes
    /// `curlx_memdup0` allocate one byte for the terminator; either way the
    /// recorded length is zero and no error is returned, which is what this
    /// asserts.
    #[test]
    fn memdup0_of_an_empty_slice_succeeds() {
        let br = memdup0(&[]).expect("an empty copy cannot fail");

        assert!(br.is_empty());
        assert_eq!(br.len(), 0);
        assert_eq!(&*br, b"");
    }

    /// An empty reference reads as an empty slice, never as a null pointer.
    ///
    /// `Curl_bufref_ptr` returns `NULL` here and callers test it; the Rust
    /// equivalent is `&[]`. The module documentation carries the measurement
    /// showing that one C call site distinguishes the two, and
    /// [`unset_is_an_option_not_a_null_pointer`] encodes the resolution.
    #[test]
    fn an_empty_reference_yields_an_empty_slice() {
        let br = empty();

        assert!(
            matches!(br, Cow::Borrowed(_)),
            "the C's dtor is NULL here, so nothing is owned"
        );
        assert_eq!(&*br, b"");
        assert_eq!(br.len(), 0);
        assert!(br.is_empty());

        // `Curl_bufref_init` leaves the same value `Curl_bufref_free` leaves,
        // which is why the C can reuse a freed reference without re-stamping
        // the signature.
        assert_eq!(empty(), borrowed(b""));
    }

    /// "Never set" is `None`, and it is not the same value as "set to
    /// nothing".
    ///
    /// The distinction is measured in `lib/curl_sasl.c:253-256`, where a null
    /// pointer emits nothing and a non-null zero-length buffer emits `=`.
    /// Nullability is not reintroduced into [`BufRef`]; a field that needs the
    /// third state wraps it, and this test is the executable form of that
    /// resolution so the two states cannot be conflated later by accident.
    #[test]
    fn unset_is_an_option_not_a_null_pointer() {
        let unset: Option<BufRef<'_>> = None;
        let set_to_nothing: Option<BufRef<'_>> = Some(empty());

        assert_ne!(unset, set_to_nothing);
        assert!(unset.is_none(), "the C's NULL ptr");
        assert_eq!(
            set_to_nothing.as_deref(),
            Some(&b""[..]),
            "the C's non-NULL ptr with len 0"
        );
    }

    /// `dup` keeps every byte where the C macro would have truncated.
    ///
    /// The module's ONE divergence, asserted rather than described.
    /// `Curl_bufref_dup` expands to `curlx_strdup(Curl_bufref_ptr(x))`, so it
    /// would have stopped at the interior NUL below and returned four bytes.
    /// The `strlen`-shaped prefix is computed here to show what the C would
    /// have produced, so the comparison is against a measured value rather
    /// than an asserted one.
    #[test]
    fn dup_does_not_truncate_at_an_interior_nul() {
        let token: &[u8] = b"NTLM\0\x01\x02binary";
        let br = owned(token.to_vec());

        let copied = dup(&br);

        assert_eq!(copied, token, "every byte survives");
        assert_eq!(copied.len(), token.len());

        let what_strdup_would_have_returned =
            &token[..token.iter().position(|byte| *byte == 0).unwrap()];
        assert_eq!(what_strdup_would_have_returned, b"NTLM");
        assert!(
            copied.len() > what_strdup_would_have_returned.len(),
            "the divergence is real: the C macro would have lost {} bytes",
            token.len() - what_strdup_would_have_returned.len()
        );

        // Text with no interior NUL is where all eight C call sites live, and
        // there the two agree exactly.
        let referer: &[u8] = b"https://example.com/index.html";
        assert_eq!(dup(referer), referer.to_vec());
    }

    /// Reassignment releases the previous buffer before installing the next.
    ///
    /// `Curl_bufref_set` states the ordering explicitly and implements it by
    /// calling `Curl_bufref_free` first (`lib/bufref.c:69-70, 78`). Rust
    /// assignment does the same thing without a line of code, and Miri is the
    /// oracle: no ordinary assertion can watch a `Vec` being freed, but a
    /// missed release is a leak and a premature one is a use-after-free, and
    /// Miri fails the test for either.
    #[test]
    fn reassignment_releases_the_previous_owned_buffer() {
        let mut br = owned(b"first response".to_vec());
        assert_eq!(&*br, b"first response");

        // Owned over owned: the first allocation must go.
        br = owned(b"second response".to_vec());
        assert_eq!(&*br, b"second response");

        // Owned over borrowed: the allocation goes and a borrow replaces it.
        br = borrowed(b"borrowed third");
        assert_eq!(&*br, b"borrowed third");
        assert!(matches!(br, Cow::Borrowed(_)));

        // Through the copying constructor as well, which is the C's
        // `Curl_bufref_memdup0` over a live reference.
        br = memdup0(b"fourth").expect("a six-byte copy cannot fail");
        assert_eq!(&*br, b"fourth");

        // And back to the empty state, the C's mid-life `Curl_bufref_free`.
        br = empty();
        assert!(br.is_empty());
    }

    /// A borrowed reference promotes to an owned one with the same bytes.
    ///
    /// This is the transition the C cannot express: it would have to allocate,
    /// copy and then remember to store `curl_free` in the `dtor` field. Here
    /// it is one call, and the borrowed input is left untouched.
    #[test]
    fn a_borrowed_reference_round_trips_through_into_owned() {
        let source: &[u8] = b"user:password";
        let br = borrowed(source);

        let promoted: Vec<u8> = br.into_owned();

        assert_eq!(promoted, source);
        assert_eq!(source, b"user:password", "the borrow is unchanged");

        // The reverse direction costs nothing, because an owned value is
        // already what `into_owned` returns.
        let already_owned = owned(promoted.clone());
        assert_eq!(already_owned.into_owned(), promoted);
    }

    /// The reproduced bound is the measured one.
    ///
    /// `CURL_MAX_INPUT_LENGTH` is `8000000` at `lib/urldata.h:131`. This
    /// module carries the value as a literal because `util` may not include
    /// the god-struct header, so an assertion on the number is the only thing
    /// standing between a transcription error and a silently wrong contract.
    #[test]
    fn the_input_bound_matches_the_c_definition() {
        assert_eq!(MAX_INPUT_LENGTH, 8_000_000);
    }

    /// The bound is enforced, in a debug build, exactly as the C enforces it.
    ///
    /// `#[cfg(debug_assertions)]` rather than a runtime check on the same
    /// flag: in a release build the assertion is compiled out, as
    /// `DEBUGASSERT` is, so the test would fail for the correct reason and
    /// should simply not exist there. Ignored under Miri only because the
    /// eight-megabyte buffer is slow to interpret; there is no pointer
    /// behaviour here for Miri to inspect.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "CURL_MAX_INPUT_LENGTH")]
    #[cfg_attr(miri, ignore = "8 MB is slow to interpret and proves nothing")]
    fn a_buffer_over_the_input_bound_trips_the_contract() {
        let oversized = vec![0u8; MAX_INPUT_LENGTH + 1];

        let _ = borrowed(&oversized);
    }

    /// The copying constructor enforces the same bound before it copies.
    ///
    /// Separate from the borrowing case because the C asserts it separately,
    /// at `lib/bufref.c:128`, and because the ordering is observable: the
    /// check has to precede the copy so an over-long buffer is reported rather
    /// than duplicated first.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "Curl_bufref_memdup0 contract")]
    #[cfg_attr(miri, ignore = "8 MB is slow to interpret and proves nothing")]
    fn memdup0_enforces_the_input_bound_before_copying() {
        let oversized = vec![0u8; MAX_INPUT_LENGTH + 1];

        let _ = memdup0(&oversized);
    }

    /// The whole point of the module, in one assertion: ownership is a type.
    ///
    /// The C needed a `void (*dtor)(void *)` field to tell these two apart at
    /// run time, and a `0x5c48e9b2` signature to notice when the struct had
    /// never been initialised. Both distinctions are made here by the
    /// compiler, and neither field exists.
    #[test]
    fn ownership_is_encoded_in_the_type_rather_than_a_function_pointer() {
        let borrows = borrowed(b"=");
        let owns = owned(b"=".to_vec());

        assert!(matches!(borrows, Cow::Borrowed(_)));
        assert!(matches!(owns, Cow::Owned(_)));

        // Different provenance, same value: the C's `dtor` was never part of
        // what the buffer MEANT, which is why dropping the field loses
        // nothing.
        assert_eq!(borrows, owns);
        assert_eq!(&*borrows, &*owns);
    }
}
