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

// THE LICENCE BANNER ABOVE, byte-identical to `util/mod.rs`'s.

//! The generic buffer reference -- supersedes `lib/bufref.c` and
//! `lib/bufref.h`.
//!
//! `struct bufref` is curl's hand-rolled answer to "a byte buffer that may be
//! borrowed or owned, and knows how to release itself". It carries a
//! destructor so that a caller can hand over either a `malloc`ed buffer or a
//! static one without the receiver having to know which. Rust has that type in
//! its standard library, so the target representation is [`Cow`] over a byte
//! slice, aliased here as [`BufRef`]. The transformation is a genuine
//! simplification and the specification sanctions it directly.
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
//! # The one deliberate divergence: `dup` does not truncate
//!
//! `Curl_bufref_dup` is a macro, not a function (`lib/bufref.h:48-49`):
//!
//! ```text
//! /* return a strdup() version of the buffer */
//! #define Curl_bufref_dup(x) curlx_strdup(Curl_bufref_ptr(x))
//! ```
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
#[allow(dead_code)]
pub(crate) type BufRef<'a> = Cow<'a, [u8]>;

/// An empty reference owning nothing -- supersedes `Curl_bufref_init`
/// (`lib/bufref.c:37-47`).
///
/// It has a second, exact call shape in the C. `lib/curl_sasl.c:254` writes
/// `Curl_bufref_set(msg, "", 0, NULL)` -- a borrowed, zero-length, ownerless
/// buffer -- which is this function.
#[allow(dead_code)]
pub(crate) fn empty() -> BufRef<'static> {
    Cow::Borrowed(&[])
}

/// Borrows `bytes` without copying -- one half of `Curl_bufref_set`
/// (`lib/bufref.c:72-82`), the half whose callers pass no destructor.
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
/// because performance is an explicit non-goal.
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
/// # Divergence from the C -- the only one in this module
///
/// The macro expands to `curlx_strdup(Curl_bufref_ptr(x))`, so it STOPS AT THE
/// FIRST NUL BYTE and discards the length the reference was carrying. On a
/// buffer holding an interior zero it returns a silently truncated copy. This
/// copies every byte. The two therefore disagree on exactly that input, and the
/// difference is recorded rather than absorbed, because a behavioural change has
/// to be visible.
///
/// No existing call site can reach the divergent input: all eight duplicate URL
/// or referer text -- `lib/multi.c:1972`, `lib/http.c:593`, `:607`, `:893` and
/// `:4101`, `lib/easy.c:1016` and `:1023`, and `lib/transfer.c:664`. The
/// difference is latent, which is why it is written down instead of assumed
/// harmless.
#[allow(dead_code)]
pub(crate) fn dup(bytes: &[u8]) -> Vec<u8> {
    bytes.to_vec()
}

// The coverage `tests/unit/*.c` would have carried, relocated here.
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
