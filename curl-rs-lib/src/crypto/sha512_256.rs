// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! SHA-512/256, FIPS 180-4 section 6.7. Supersedes `lib/curl_sha512_256.c` and
//! `lib/curl_sha512_256.h`.
//!
//! SHA-512 with a distinct truncated initial state, which is why the block is
//! **128** bytes and not 64: `lib/curl_sha512_256.c:83` defines
//! `CURL_SHA512_256_BLOCK_SIZE 128` while the digest is still 32 bytes, and
//! `:788-804` fixes the keyed parameter table at exactly those two values.
//! Conflating that block length with SHA-256's silently corrupts a keyed
//! digest, so [`crate::crypto`] asserts the doubling relationship rather than
//! only the value.
//!
//! One consumer: the `SHA-512-256` HTTP Digest algorithm
//! (`lib/vauth/digest.c`), which curl added because RFC 7616 names it.
//! `lib/curl_sha512_256.h:34` declares the one-shot form; the incremental
//! context below carries the module's own name rather than the obvious
//! `Sha512_256Context`, because that spelling trips
//! `clippy::non_camel_case_types` and the build gate admits no warnings.

use ::sha2::{Digest, Sha512_256};

/// Length of a SHA-512/256 digest in bytes
/// (`lib/curl_sha512_256.h`, `CURL_SHA512_256_DIGEST_LENGTH`).
pub(crate) const DIGEST_LEN: usize = 32;

/// SHA-512/256's compression block size in bytes
/// (`lib/curl_sha512_256.c:83`). Twice SHA-256's, despite the identical digest
/// length.
#[allow(dead_code)]
pub(crate) const BLOCK_LEN: usize = 128;

/// The `digest` marker type, re-exported so [`crate::crypto::hmac`] can
/// instantiate the keyed form without importing `sha2` again.
#[allow(dead_code)]
pub(crate) type Sha512Trunc256 = Sha512_256;

/// Whether this build provides the digest: the authority for
/// `CURL_HAVE_SHA512_256`.
///
/// `lib/curl_sha512_256.h:28-32` defines that macro under
/// `!defined(CURL_DISABLE_DIGEST_AUTH) && !defined(CURL_DISABLE_SHA512_256)`,
/// and `src/curlinfo.c:204-209` prints the `sha512-256: ` row from it. Neither
/// switch has a counterpart among this workspace's fifteen Cargo features, so no
/// build configuration can remove the digest -- and there is nothing else to
/// condition the answer on, because this module is a plain, non-optional part of
/// the crate with no `#[cfg]` on any item and no fallible initialization:
/// `sha2` is a non-optional dependency and [`sha512_256`] is a pure function.
///
/// It is a function rather than a `const` so that the single public accessor,
/// [`crate::version::has_sha512_256`], delegates to the module that owns the
/// implementation instead of restating the conclusion. If the digest ever
/// becomes conditional, this is the one expression that changes and the
/// diagnostic follows automatically.
///
/// Deliberately **not** exposed as a `--version` feature token: C publishes no
/// such token, and `curl_version_info()->feature_names` must keep exactly the
/// names it has always held.
pub(crate) fn available() -> bool {
    true
}

/// Digest a whole message: `Curl_sha512_256it` (`lib/curl_sha512_256.c`).
#[allow(dead_code)]
pub(crate) fn sha512_256(input: &[u8]) -> [u8; DIGEST_LEN] {
    let mut hasher = Sha512_256::new();
    hasher.update(input);
    hasher.finalize().into()
}

/// The incremental form.
///
/// Named for the algorithm rather than spelled `Sha512_256Context`: the
/// underscore-and-digit form is not upper camel case and the lint that says so
/// is on. Callers reach it as `crypto::sha512_256::Sha512Trunc256Context`,
/// which is why [`crate::crypto`] deliberately does not re-export it.
#[derive(Clone, Default)]
#[allow(dead_code)]
pub(crate) struct Sha512Trunc256Context {
    hasher: Sha512_256,
}

impl Sha512Trunc256Context {
    /// A fresh context.
    #[allow(dead_code)]
    pub(crate) fn new() -> Self {
        Self {
            hasher: Sha512_256::new(),
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
    use super::{sha512_256, Sha512Trunc256Context, BLOCK_LEN, DIGEST_LEN};

    /// The vectors `tests/unit/unit1615.c` asserts against
    /// `Curl_sha512_256it`. Note that these differ from SHA-256's for the same
    /// input, which is the whole point of the truncated initial state.
    #[test]
    fn one_shot_matches_the_fips_180_4_examples() {
        assert_eq!(
            sha512_256(b""),
            [
                0xc6, 0x72, 0xb8, 0xd1, 0xef, 0x56, 0xed, 0x28, 0xab, 0x87,
                0xc3, 0x62, 0x2c, 0x51, 0x14, 0x06, 0x9b, 0xdd, 0x3a, 0xd7,
                0xb8, 0xf9, 0x73, 0x74, 0x98, 0xd0, 0xc0, 0x1e, 0xce, 0xf0,
                0x96, 0x7a
            ]
        );
        assert_eq!(
            sha512_256(b"abc"),
            [
                0x53, 0x04, 0x8e, 0x26, 0x81, 0x94, 0x1e, 0xf9, 0x9b, 0x2e,
                0x29, 0xb7, 0x6b, 0x4c, 0x7d, 0xab, 0xe4, 0xc2, 0xd0, 0xc6,
                0x34, 0xfc, 0x6d, 0x46, 0xe0, 0xe2, 0xf1, 0x31, 0x07, 0xe7,
                0xaf, 0x23
            ]
        );
    }

    #[test]
    fn incremental_agrees_with_one_shot_across_chunk_boundaries() {
        let message: Vec<u8> = (0u8..=255).collect();
        for split in [0usize, 1, 127, BLOCK_LEN, BLOCK_LEN + 1, message.len()] {
            let mut ctx = Sha512Trunc256Context::new();
            ctx.update(&message[..split]);
            ctx.update(&message[split..]);
            assert_eq!(ctx.finish(), sha512_256(&message), "split at {split}");
        }
    }

    #[test]
    fn the_block_is_twice_sha_256s_while_the_digest_is_the_same_size() {
        assert_eq!(BLOCK_LEN, 128);
        assert_eq!(DIGEST_LEN, 32);
        assert_eq!(sha512_256(b"anything").len(), DIGEST_LEN);
    }
}
