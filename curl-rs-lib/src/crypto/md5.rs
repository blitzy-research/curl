// /***************************************************************************
//  *                                  _   _ ____  _
//  *  Project                     ___| | | |  _ \| |
//  *                             / __| | | | |_) | |
//  *                            | (__| |_| |  _ <| |___
//  *                             \___|\___/|_| \_\_____|
//  *
//  * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//  *
//  * This software is licensed as described in the file COPYING, which
//  * you should have received as part of this distribution. The terms
//  * are also available at https://curl.se/docs/copyright.html.
//  *
//  * You may opt to use, copy, modify, merge, publish, distribute and/or sell
//  * copies of the Software, and permit persons to whom the Software is
//  * furnished to do so, under the terms of the COPYING file.
//  *
//  * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
//  * KIND, either express or implied.
//  *
//  * SPDX-License-Identifier: curl
//  *
//  ***************************************************************************/
//! MD5, RFC 1321. Supersedes `lib/md5.c` and `lib/curl_md5.h`.
//!
//! The primitive itself comes from the **`md-5 0.10.6`** crate, pinned exactly
//! in the workspace manifest's `[workspace.dependencies]` and inherited here
//! with `{ workspace = true }`. The crate is published as `md-5` while its
//! library target is `md5`, so `use ::md5::Md5` is correct despite the hyphen.
//! Nothing in this file implements a compression function.
//!
//! # The parameter values are contractual, not chosen
//!
//! `lib/md5.c:528-535` fixes the keyed table `Curl_HMAC_MD5` at a 64-byte
//! maximum key length (`lib/md5.c:533`) and a 16-byte result
//! (`lib/md5.c:534`). `lib/md5.c:537-543` fixes the unkeyed `Curl_DIGEST_MD5`
//! result at 16 bytes (`lib/md5.c:542`), agreeing with `MD5_DIGEST_LEN` at
//! `lib/curl_md5.h:32`. [`crate::crypto`] re-exports [`DIGEST_LEN`] and
//! [`BLOCK_LEN`] under prefixed names and pins both with `const` assertions,
//! so changing either value fails the build beside the citation that explains
//! why it cannot change.
//!
//! # Scope, and where rendering belongs
//!
//! MD5 is present only because curl's wire formats specify it: HTTP Digest
//! (`lib/vauth/digest.c`) and the NTLMv2 response, whose three HMAC-MD5 call
//! sites are `lib/curl_ntlm_core.c:524`, `:610` and `:653`. It is never a
//! security primitive chosen by this implementation.
//!
//! Turning a digest into text is not this module's job. Every digest curl puts
//! on the wire is written with `"%02x"` and is therefore **lowercase** --
//! `lib/vauth/digest.c:139`, and again at `:417`, `:440` and `:470` -- which
//! [`crate::crypto::hex_lower`] owns. `Curl_hexbyte` at `lib/escape.c:218-225`
//! is the uppercase renderer and must never be used for a digest.

use ::md5::{Digest, Md5 as Md5Hasher};

/// Length of an MD5 digest in bytes.
///
/// `MD5_DIGEST_LEN` (`lib/curl_md5.h:32`), and the result size both C
/// parameter tables declare (`lib/md5.c:534` and `:542`).
pub(crate) const DIGEST_LEN: usize = 16;

/// MD5's HMAC block size in bytes: the maximum key length `Curl_HMAC_MD5`
/// declares at `lib/md5.c:533`.
///
/// The allowance is required by the MSRV floor and is not redundant, however
/// much it looks it on a current toolchain. This constant's only consumer is
/// the `const _: () = assert!(MD5_BLOCK_LEN == 64);` contract in
/// [`crate::crypto`], and rustc 1.75 does not count a reference from inside a
/// `const _` item as a use, so 1.75 reports it unused where 1.97 does not.
/// Measured on both. The sibling modules carry the attribute on the same two
/// item kinds for the same reason. Delete it only alongside the attribute on
/// [`md5`], and only once a real caller exists.
#[allow(dead_code)]
pub(crate) const BLOCK_LEN: usize = 64;

/// The `digest` marker type for MD5.
pub(crate) type Md5 = Md5Hasher;

/// Digest a whole message: `Curl_md5it` (`lib/md5.c:549-561`).
///
/// The signature is infallible, which narrows the C one deliberately.
/// `Curl_md5it` returns `CURLcode` only because the pluggable backend's `init`
/// could fail (`lib/md5.c:555`); with a single infallible backend there is no
/// error left to report, so a `Result` would be a lie the caller must still
/// handle. Returning the array also retires C's output pointer: out-parameters
/// do not survive the port.
#[allow(dead_code)]
pub(crate) fn md5(input: &[u8]) -> [u8; DIGEST_LEN] {
    let mut hasher = Md5Hasher::new();
    hasher.update(input);
    hasher.finalize().into()
}

/// The incremental form: `Curl_MD5_init` / `Curl_MD5_update` /
/// `Curl_MD5_final` (`lib/curl_md5.h:59-63`, implemented at
/// `lib/md5.c:563-589`, `:591-597` and `:599-607`).
///
/// Finishing consumes the context, which is stricter than the C it replaces.
/// `Curl_MD5_final` frees the context it is handed (`lib/md5.c:603-604`) and
/// leaves the caller holding a dangling pointer, so calling it twice is a
/// use-after-free there. Here it does not compile.
#[derive(Clone, Default)]
pub(crate) struct Md5Context {
    #[allow(dead_code)]
    hasher: Md5Hasher,
}

impl Md5Context {
    /// A fresh context: `Curl_MD5_init` (`lib/md5.c:563-589`).
    #[allow(dead_code)]
    pub(crate) fn new() -> Self {
        Self {
            hasher: Md5Hasher::new(),
        }
    }

    /// Feed the next chunk: `Curl_MD5_update` (`lib/md5.c:591-597`).
    ///
    /// C narrowed `size_t` to `unsigned int` through `curlx_uztoui` to reach
    /// this call (`lib/md5.c:557`). The Rust length is a `usize` end to end,
    /// and that narrowing is deliberately not reintroduced.
    #[allow(dead_code)]
    pub(crate) fn update(&mut self, input: &[u8]) {
        self.hasher.update(input);
    }

    /// Finish and return the digest: `Curl_MD5_final` (`lib/md5.c:599-607`).
    #[allow(dead_code)]
    pub(crate) fn finalize(self) -> [u8; DIGEST_LEN] {
        self.hasher.finalize().into()
    }

    /// [`Md5Context::finalize`] under the name the sibling contexts use.
    #[allow(dead_code)]
    pub(crate) fn finish(self) -> [u8; DIGEST_LEN] {
        self.finalize()
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::{md5, Digest, Md5, Md5Context, BLOCK_LEN, DIGEST_LEN};

    /// The seven vectors of RFC 1321 appendix A.5, with the digests written
    /// the way the specification prints them: lowercase hex.
    ///
    /// Lowercase is not a presentation choice here. `"%02x"` at
    /// `lib/vauth/digest.c:139` is what puts these bytes on the wire, so
    /// comparing through [`crate::crypto::hex_lower`] asserts the digest and
    /// the casing curl actually emits in one step. The uppercase renderer,
    /// `Curl_hexbyte` at `lib/escape.c:218-225`, would fail this table.
    #[rustfmt::skip]
    const RFC_1321: &[(&[u8], &str)] = &[
        (b"", "d41d8cd98f00b204e9800998ecf8427e"),
        (b"a", "0cc175b9c0f1b6a831c399e269772661"),
        (b"abc", "900150983cd24fb0d6963f7d28e17f72"),
        (b"message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
        (b"abcdefghijklmnopqrstuvwxyz",
         "c3fcd3d76192e4007dfb496cca67e13b"),
        (b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
         "d174ab98d277d9f5a5611c2c9f419d9f"),
        // "1234567890" eight times over: 80 bytes, which crosses the 64-byte
        // block boundary and so exercises the padded second block.
        (b"12345678901234567890123456789012345678901234567890\
           123456789012345678901234567890",
         "57edf4a22be3c955ac49da2e2107b67a"),
    ];

    #[test]
    fn one_shot_matches_the_rfc_1321_test_suite() {
        for &(message, expected) in RFC_1321 {
            assert_eq!(
                crate::crypto::hex_lower(&md5(message)),
                expected,
                "RFC 1321 vector of {} bytes",
                message.len()
            );
        }
    }

    /// `tests/unit/unit1601.c:40-48`, relocated.
    #[rustfmt::skip]
    #[test]
    fn one_shot_matches_the_relocated_unit1601_vectors() {
        assert_eq!(
            md5(b"1"),
            [0xc4, 0xca, 0x42, 0x38, 0xa0, 0xb9, 0x23, 0x82,
             0x0d, 0xcc, 0x50, 0x9a, 0x6f, 0x75, 0x84, 0x9b]
        );
        assert_eq!(
            md5(b"hello-you-fool"),
            [0x88, 0x67, 0x0b, 0x6d, 0x5d, 0x74, 0x2f, 0xad,
             0xa5, 0xcd, 0xf9, 0xb6, 0x82, 0x87, 0x5f, 0x22]
        );
    }

    /// The specific pattern HTTP Digest depends on, and the reason a
    /// one-shot-only surface would not serve it.
    #[test]
    fn incremental_feeds_a_one_byte_separator_like_http_digest() {
        let mut ctx = Md5Context::new();
        ctx.update(b"a");
        ctx.update(b":");
        ctx.update(b"b");
        assert_eq!(ctx.finalize(), md5(b"a:b"));
    }

    /// `lib/vauth/digest.c:402-413` feeds the *digest* of the first context
    /// into the second as input, then a separator, then more text.
    ///
    /// Nothing renders it to hex first at that point -- the hex conversion
    /// happens afterwards at `lib/vauth/digest.c:416-417` -- so the context
    /// must accept 16 arbitrary bytes, including any that are not valid text.
    #[test]
    fn incremental_accepts_a_digest_fed_back_as_input() {
        // The three fields C feeds in that order, named after the parameters
        // at `lib/vauth/digest.c:392-399` so that nothing here reads as a
        // credential. Any bytes would do; these document the shape.
        let ha1 = md5(b"userp:realm:passwdp");

        let mut ctx = Md5Context::new();
        ctx.update(&ha1);
        ctx.update(b":");
        ctx.update(b"nonce");
        ctx.update(b":");
        ctx.update(b"cnonce");

        let mut concatenated = Vec::new();
        concatenated.extend_from_slice(&ha1);
        concatenated.extend_from_slice(b":nonce:cnonce");

        assert_eq!(ctx.finalize(), md5(&concatenated));
    }

    /// A streamed digest must equal the one-shot digest of the same bytes at
    /// every split, or the four contexts in `lib/vauth/digest.c` could
    /// disagree with each other depending only on how the input arrived.
    ///
    /// The splits bracket the 64-byte block boundary deliberately, since that
    /// is where a buffered implementation goes wrong.
    #[test]
    fn incremental_agrees_with_one_shot_across_chunk_boundaries() {
        let message: Vec<u8> = (0u8..=255).collect();
        for split in
            [0usize, 1, 63, BLOCK_LEN, BLOCK_LEN + 1, 200, message.len()]
        {
            let mut ctx = Md5Context::new();
            ctx.update(&message[..split]);
            ctx.update(&message[split..]);
            assert_eq!(ctx.finalize(), md5(&message), "split at {split}");
        }
    }

    /// A context that is never fed, and one fed only empty slices, must both
    /// produce the digest of the empty message.
    ///
    /// [`Default`] is derived rather than written, so it is asserted to agree
    /// with [`Md5Context::new`] rather than assumed to.
    #[test]
    fn a_context_with_no_input_digests_the_empty_message() {
        let empty = md5(b"");
        assert_eq!(Md5Context::new().finalize(), empty);
        assert_eq!(Md5Context::default().finalize(), empty);

        let mut ctx = Md5Context::new();
        ctx.update(b"");
        ctx.update(b"");
        assert_eq!(ctx.finalize(), empty);
    }

    /// The two spellings of finishing are the same operation.
    ///
    /// `finish` exists for shape parity with the sibling contexts, so it must
    /// never drift from `finalize`.
    #[test]
    fn finish_and_finalize_produce_the_same_digest() {
        let mut by_finalize = Md5Context::new();
        by_finalize.update(b"curl");

        let mut by_finish = Md5Context::new();
        by_finish.update(b"curl");

        assert_eq!(by_finalize.finalize(), by_finish.finish());
        assert_eq!(Md5Context::new().finish(), md5(b""));
    }

    /// The published marker type must be the `md-5` crate's own type.
    #[test]
    fn the_published_marker_type_agrees_with_the_one_shot_form() {
        let mut hasher = Md5::new();
        hasher.update(b"abc");
        let digest: [u8; DIGEST_LEN] = hasher.finalize().into();
        assert_eq!(digest, md5(b"abc"));
    }

    /// The two numbers the C parameter tables fix, asserted by value.
    ///
    /// `MD5_DIGEST_LEN` at `lib/curl_md5.h:32` and `Curl_HMAC_MD5`'s maximum
    /// key length at `lib/md5.c:533`. [`crate::crypto`] pins the same pair
    /// with `const` assertions; these restate them at test time so that the
    /// failure names this module when a value is changed here.
    #[test]
    fn the_contracted_constants_hold() {
        assert_eq!(DIGEST_LEN, 16);
        assert_eq!(BLOCK_LEN, 64);

        // And the published surface really does produce that many bytes.
        assert_eq!(md5(b"anything").len(), DIGEST_LEN);
        assert_eq!(Md5Context::new().finalize().len(), DIGEST_LEN);

        // The hex rendering HTTP Digest writes is two characters per byte;
        // `lib/vauth/digest.c:134-135` sizes its buffer 16 in, 33 out, the
        // extra byte being C's NUL terminator.
        assert_eq!(crate::crypto::hex_lower(&md5(b"")).len(), DIGEST_LEN * 2);
    }
}
