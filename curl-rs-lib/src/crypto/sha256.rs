// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! SHA-256, FIPS 180-4. Supersedes `lib/sha256.c` and `lib/curl_sha256.h`.
//!
//! Consumed by the `SHA-256` and `SHA-256-sess` HTTP Digest algorithms
//! (`lib/vauth/digest.c`), by AWS SigV4 request signing
//! (`lib/http_aws_sigv4.c`, which also keys it through HMAC) and by public-key
//! pinning (`lib/vtls/vtls.c`).
//!
//! `lib/curl_sha256.h:40` declares only the one-shot `Curl_sha256it`. The
//! incremental [`Sha256Context`] below has no direct C counterpart and exists
//! so that a caller which must feed data in pieces has one shape for both
//! digest families; the bytes a streamed digest produces are the bytes the
//! one-shot form produces, so it changes nothing observable.
//!
//! `lib/sha256.c:468-475` fixes the keyed parameter table at a 64-byte block
//! and a 32-byte result. Those two values are asserted at compile time in
//! [`crate::crypto`], and the 64 is the value that must not be confused with
//! SHA-512/256's 128.

use ::sha2::{Digest, Sha256};

/// Length of a SHA-256 digest in bytes (`lib/curl_sha256.h`,
/// `CURL_SHA256_DIGEST_LENGTH`).
pub(crate) const DIGEST_LEN: usize = 32;

/// SHA-256's compression block size in bytes (`lib/sha256.c:470`).
#[allow(dead_code)]
pub(crate) const BLOCK_LEN: usize = 64;

/// Digest a whole message: `Curl_sha256it` (`lib/sha256.c`).
#[allow(dead_code)]
pub(crate) fn sha256(input: &[u8]) -> [u8; DIGEST_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().into()
}

/// The incremental form, for callers that cannot present the message at once.
///
/// `finish` consumes the context so that a second finish is a compile error
/// rather than a use-after-free, which is the class of defect the C vtable
/// form invited.
#[derive(Clone, Default)]
pub(crate) struct Sha256Context {
    #[allow(dead_code)]
    hasher: Sha256,
}

impl Sha256Context {
    /// A fresh context.
    #[allow(dead_code)]
    pub(crate) fn new() -> Self {
        Self {
            hasher: Sha256::new(),
        }
    }

    /// Feed the next chunk.
    #[allow(dead_code)]
    pub(crate) fn update(&mut self, input: &[u8]) {
        self.hasher.update(input);
    }

    /// Finish and return the digest.
    #[allow(dead_code)]
    pub(crate) fn finish(self) -> [u8; DIGEST_LEN] {
        self.hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::{sha256, Sha256Context, BLOCK_LEN, DIGEST_LEN};

    /// FIPS 180-4 examples, and the vectors `tests/unit/unit1610.c` asserts
    /// against `Curl_sha256it`.
    #[test]
    fn one_shot_matches_the_fips_180_4_examples() {
        assert_eq!(
            sha256(b""),
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb,
                0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4,
                0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
                0xb8, 0x55
            ]
        );
        assert_eq!(
            sha256(b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41,
                0x40, 0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3,
                0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
                0x15, 0xad
            ]
        );
    }

    #[test]
    fn incremental_agrees_with_one_shot_across_chunk_boundaries() {
        let message: Vec<u8> = (0u8..=255).collect();
        for split in
            [0usize, 1, 63, BLOCK_LEN, BLOCK_LEN + 1, 200, message.len()]
        {
            let mut ctx = Sha256Context::new();
            ctx.update(&message[..split]);
            ctx.update(&message[split..]);
            assert_eq!(ctx.finish(), sha256(&message), "split at {split}");
        }
    }

    #[test]
    fn digest_length_is_the_contracted_thirty_two() {
        assert_eq!(sha256(b"anything").len(), DIGEST_LEN);
        assert_eq!(Sha256Context::new().finish().len(), DIGEST_LEN);
    }
}
