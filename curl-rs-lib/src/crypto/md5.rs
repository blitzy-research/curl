// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! MD5, RFC 1321. Supersedes `lib/md5.c` and `lib/curl_md5.h`.
//!
//! Two shapes, because the C tree needs both. `lib/curl_md5.h:40` declares the
//! one-shot `Curl_md5it`, and `lib/curl_md5.h:59-63` declares the incremental
//! `Curl_MD5_init` / `Curl_MD5_update` / `Curl_MD5_final` trio that
//! `lib/vauth/digest.c:388`, `:402`, `:425` and `:443` feed in pieces while
//! composing a Digest response.
//!
//! The parameter values are contractual rather than chosen.
//! `lib/md5.c:528-535` fixes the keyed parameter table at a 64-byte block and
//! a 16-byte result, and `lib/md5.c:537-543` fixes the unkeyed result at 16
//! bytes. [`crate::crypto`] asserts both at compile time next to those
//! citations.
//!
//! MD5 is used here only where curl's wire protocols demand it -- HTTP Digest
//! (`lib/vauth/digest.c`) and the NTLM session response
//! (`lib/curl_ntlm_core.c`) -- and never as a security primitive of this
//! implementation's own choosing.

use ::md5::{Digest, Md5 as Md5Hasher};

/// Length of an MD5 digest in bytes (`lib/curl_md5.h:32`, `MD5_DIGEST_LEN`).
pub(crate) const DIGEST_LEN: usize = 16;

/// MD5's compression block size in bytes (`lib/md5.c:530`).
#[allow(dead_code)]
pub(crate) const BLOCK_LEN: usize = 64;

/// The `digest` marker type for MD5, re-exported so that
/// [`crate::crypto::hmac`] can instantiate `Hmac<Md5>` without importing the
/// `md-5` crate a second time.
///
/// Named `Md5` rather than re-exported under the module's own name because
/// `Hmac<D>` takes the hasher type, and a caller writing
/// `crypto::md5::Md5` reads as the algorithm it is.
#[allow(dead_code)]
pub(crate) type Md5 = Md5Hasher;

/// Digest a whole message: `Curl_md5it` (`lib/md5.c:537-543`).
///
/// Returns the 16 raw bytes. Rendering to ASCII is
/// [`crate::crypto::hex_lower`]'s job, and it is lowercase because every
/// digest curl puts on the wire is written with `"%02x"`.
#[allow(dead_code)]
pub(crate) fn md5(input: &[u8]) -> [u8; DIGEST_LEN] {
    let mut hasher = Md5Hasher::new();
    hasher.update(input);
    hasher.finalize().into()
}

/// The incremental form: `Curl_MD5_init` / `_update` / `_final`
/// (`lib/curl_md5.h:59-63`).
///
/// C exposed this over a vtable (`MD5_params`, `lib/curl_md5.h:41-43`) because
/// the backend was selected at build time. There is one implementation here,
/// so the indirection is gone while the call sequence is preserved: construct,
/// feed any number of times, finish once.
///
/// `finish` consumes the context, which is stricter than C's `Curl_MD5_final`
/// -- that function frees the context and leaves the caller holding a dangling
/// pointer if it is called twice. Consuming makes the second call a compile
/// error.
#[derive(Clone, Default)]
pub(crate) struct Md5Context {
    #[allow(dead_code)]
    hasher: Md5Hasher,
}

impl Md5Context {
    /// A fresh context, equivalent to `Curl_MD5_init` (`lib/md5.c:481-501`).
    #[allow(dead_code)]
    pub(crate) fn new() -> Self {
        Self {
            hasher: Md5Hasher::new(),
        }
    }

    /// Feed the next chunk: `Curl_MD5_update` (`lib/md5.c:503-513`).
    #[allow(dead_code)]
    pub(crate) fn update(&mut self, input: &[u8]) {
        self.hasher.update(input);
    }

    /// Finish and return the digest: `Curl_MD5_final` (`lib/md5.c:515-526`).
    #[allow(dead_code)]
    pub(crate) fn finish(self) -> [u8; DIGEST_LEN] {
        self.hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::{md5, Md5Context, BLOCK_LEN, DIGEST_LEN};

    /// RFC 1321 appendix A.5, and the same vectors `tests/unit/unit1601.c`
    /// asserts against `Curl_md5it`.
    #[test]
    fn one_shot_matches_the_rfc_1321_test_suite() {
        assert_eq!(
            md5(b""),
            [
                0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80,
                0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e
            ]
        );
        assert_eq!(
            md5(b"abc"),
            [
                0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96,
                0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72
            ]
        );
        assert_eq!(
            md5(b"message digest"),
            [
                0xf9, 0x6b, 0x69, 0x7d, 0x7c, 0xb7, 0x93, 0x8d, 0x52, 0x5a,
                0x2f, 0x31, 0xaa, 0xf1, 0x61, 0xd0
            ]
        );
    }

    /// A streamed digest must equal the one-shot digest of the same bytes, or
    /// the two call sites in `lib/vauth/digest.c` would disagree with each
    /// other.
    #[test]
    fn incremental_agrees_with_one_shot_across_chunk_boundaries() {
        let message: Vec<u8> = (0u8..=255).collect();
        for split in
            [0usize, 1, 63, BLOCK_LEN, BLOCK_LEN + 1, 200, message.len()]
        {
            let mut ctx = Md5Context::new();
            ctx.update(&message[..split]);
            ctx.update(&message[split..]);
            assert_eq!(ctx.finish(), md5(&message), "split at {split}");
        }
    }

    #[test]
    fn digest_length_is_the_contracted_sixteen() {
        assert_eq!(md5(b"anything").len(), DIGEST_LEN);
        assert_eq!(Md5Context::new().finish().len(), DIGEST_LEN);
    }
}
