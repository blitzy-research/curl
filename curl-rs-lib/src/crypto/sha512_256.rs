// /***************************************************************************
//  *                                  _   _ ____  _
//  *  Project                     ___| | | |  _ \| |
//  *                             / __| | | | |_) | |
//  *                            | (__| |_| |  _ <| |___
//  *                             \___|\___/|_| \_\_____|
//  *
//  * Copyright (C) Evgeny Grin (Karlson2k), <k2k@narod.ru>.
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
//! SHA-512/256, FIPS 180-4. Supersedes `lib/curl_sha512_256.c` and
//! `lib/curl_sha512_256.h` over `sha2 0.10.9`'s `Sha512_256`.
//!
//! # The whole C contract, in four declarations
//!
//! ```text
//!   lib/curl_sha512_256.h:32  #define CURL_HAVE_SHA512_256
//!   lib/curl_sha512_256.h:34  extern const struct HMAC_params
//!                               Curl_HMAC_SHA512_256[1];
//!   lib/curl_sha512_256.h:36  #define CURL_SHA512_256_DIGEST_LENGTH 32
//!   lib/curl_sha512_256.h:38  CURLcode Curl_sha512_256it(
//!                               unsigned char *output,
//!                               const unsigned char *input,
//!                               size_t input_size);
//! ```
//!
//! Two oddities in those four lines are recorded so that nobody hunts for
//! something that is not missing. `Curl_HMAC_SHA512_256` is declared as an
//! **array of one** rather than as a scalar, which is a C declaration habit
//! with no Rust consequence: the keyed form here is `Hmac<Sha512Trunc256>` over
//! a type, and there is no table to find. And `lib/curl_sha512_256.h:43` closes
//! the include guard with the comment `/* HEADER_CURL_SHA256_H */`, naming a
//! different header -- a copy-paste artefact in the C that is deliberately not
//! propagated.
//!
//! # The licence banner names one author, and it is not the usual one
//!
//! The twenty-three lines above reproduce `lib/curl_sha512_256.c:1-23`
//! verbatim, and `lib/curl_sha512_256.h:3-25` carries the same banner. It has
//! exactly **one** copyright line, `lib/curl_sha512_256.c:8`, naming Karlson2k
//! -- with a trailing full stop the other files in this directory do not have,
//! and with **no second copyright line of any kind**. Every other file under
//! `curl-rs-lib/src/crypto/` names the project's principal author; this one
//! does not, which makes it the most divergent banner in the directory and the
//! one thing here that must not be copied from a sibling. Doing so would assert
//! an attribution the C original does not make.
//!
//! Attribution is not boilerplate to be normalised. `reuse lint`
//! (`.github/workflows/hygiene.yml:47-50`) reads what is actually in the file,
//! and `REUSE.toml` annotates no path under `curl-rs-lib/src/`, so this header
//! is the only record there is. [`crate::crypto`] tabulates every banner in
//! this directory for the same reason, and the precedent is one directory over:
//! `util/inet.rs` alone carries an ISC/BIND banner because its C originals are
//! ISC-licensed.

use ::sha2::{Digest, Sha512_256};

/// Length of a SHA-512/256 digest in bytes.
pub(crate) const DIGEST_LEN: usize = 32;

/// SHA-512/256's compression block size in bytes -- **128, not 64**.
#[allow(dead_code)]
pub(crate) const BLOCK_LEN: usize = 128;

/// The `digest` marker type for SHA-512/256, published so that
/// [`crate::crypto::hmac`] can instantiate `Hmac<Sha512Trunc256>` without
/// naming the `sha2` crate a second time.
#[allow(dead_code)]
pub(crate) type Sha512Trunc256 = Sha512_256;

/// Whether this build provides the digest: the authority for
/// `CURL_HAVE_SHA512_256`.
///
/// Deliberately **not** exposed as a `--version` feature token: C publishes no
/// such token, and `curl_version_info()->feature_names` must keep exactly the
/// names it has always held.
pub(crate) fn available() -> bool {
    true
}

/// Digest a whole message: `Curl_sha512_256it`
/// (`lib/curl_sha512_256.c:750-768`).
#[allow(dead_code)]
pub(crate) fn sha512_256(input: &[u8]) -> [u8; DIGEST_LEN] {
    let mut hasher = Sha512_256::new();
    hasher.update(input);
    hasher.finalize().into()
}

/// The incremental form: construct, feed any number of times, finish once.
#[derive(Clone, Default)]
#[allow(dead_code)]
pub(crate) struct Sha512Trunc256Context {
    hasher: Sha512_256,
}

impl Sha512Trunc256Context {
    /// A fresh context: `Curl_sha512_256_init`
    /// (`lib/curl_sha512_256.c:103`, and `:396` in the bundled arm, where the
    /// FIPS 180-4 initial state of `:405-415` is written out by hand).
    #[allow(dead_code)]
    pub(crate) fn new() -> Self {
        Self {
            hasher: Sha512_256::new(),
        }
    }

    /// Feed the next chunk: `Curl_sha512_256_update`, wrapped for the parameter
    /// table at `lib/curl_sha512_256.c:771-777`.
    #[allow(dead_code)]
    pub(crate) fn update(&mut self, input: &[u8]) {
        self.hasher.update(input);
    }

    /// Finish and return the digest: `Curl_sha512_256_finish`, wrapped at
    /// `lib/curl_sha512_256.c:780-784`.
    ///
    /// Consuming `self` is stricter than the C sequence, where nothing stopped
    /// a caller from finalising the same context twice. Here a second call does
    /// not compile.
    #[allow(dead_code)]
    pub(crate) fn finalize(self) -> [u8; DIGEST_LEN] {
        self.hasher.finalize().into()
    }

    /// [`Sha512Trunc256Context::finalize`] under the name the incremental MD5
    /// context publishes.
    #[allow(dead_code)]
    pub(crate) fn finish(self) -> [u8; DIGEST_LEN] {
        self.finalize()
    }
}

// Tests -- where the coverage of tests/unit/unit1615.c now lives
//
// `tests/unit/unit1615.c` is the C unit test for this digest, and
// `tests/data/test1615` is named "SHA-512/256 unit tests" and gates on
// `<features>unittest</features>` together with the `sha512-256` label. This
// binary does not advertise `unittest`, so that fixture skips -- and it could
// not run in any case, because it links a debug static library and calls the
// internal `Curl_sha512_256it` symbol, which a Rust static library genuinely
// does not place in its symbol table.

#[cfg(test)]
mod tests {
    use super::{
        available, sha512_256, Sha512Trunc256, Sha512Trunc256Context,
        BLOCK_LEN, DIGEST_LEN,
    };
    use crate::crypto::{hex_lower, SHA256_HEX_BUF_LEN};
    use ::hmac::{Hmac, Mac};
    use ::sha2::digest::core_api::BlockSizeUser;
    use ::sha2::digest::typenum::Unsigned;

    /// `tests/unit/unit1615.c:35`.
    const TEST_STR1: &[u8] = b"1";

    /// `tests/unit/unit1615.c:36-40`.
    #[rustfmt::skip]
    const PRECOMP_HASH1: [u8; DIGEST_LEN] = [
        0x18, 0xd2, 0x75, 0x66, 0xbd, 0x1a, 0xc6, 0x6b, 0x23, 0x32, 0xd8,
        0xc5, 0x4a, 0xd4, 0x3f, 0x7b, 0xb2, 0x20, 0x79, 0xc9, 0x06, 0xd0,
        0x5f, 0x49, 0x1f, 0x3f, 0x07, 0xa2, 0x8d, 0x5c, 0x69, 0x90,
    ];

    /// `tests/unit/unit1615.c:41`.
    const TEST_STR2: &[u8] = b"hello-you-fool";

    /// `tests/unit/unit1615.c:42-46`.
    #[rustfmt::skip]
    const PRECOMP_HASH2: [u8; DIGEST_LEN] = [
        0xaf, 0x6f, 0xb4, 0xb0, 0x13, 0x9b, 0xee, 0x13, 0xd1, 0x95, 0x3c,
        0xb8, 0xc7, 0xcd, 0x5b, 0x19, 0xf9, 0xcd, 0xcd, 0x21, 0xef, 0xdf,
        0xa7, 0x42, 0x5c, 0x07, 0x13, 0xea, 0xcc, 0x1a, 0x39, 0x76,
    ];

    /// `tests/unit/unit1615.c:47`.
    const TEST_STR3: &[u8] = b"abc";

    /// `tests/unit/unit1615.c:48-52` -- THE TRAP DETECTOR.
    #[rustfmt::skip]
    const PRECOMP_HASH3: [u8; DIGEST_LEN] = [
        0x53, 0x04, 0x8E, 0x26, 0x81, 0x94, 0x1E, 0xF9, 0x9B, 0x2E, 0x29,
        0xB7, 0x6B, 0x4C, 0x7D, 0xAB, 0xE4, 0xC2, 0xD0, 0xC6, 0x34, 0xFC,
        0x6D, 0x46, 0xE0, 0xE2, 0xF1, 0x31, 0x07, 0xE7, 0xAF, 0x23,
    ];

    /// `tests/unit/unit1615.c:53` -- empty, zero size input.
    const TEST_STR4: &[u8] = b"";

    /// `tests/unit/unit1615.c:54-58`.
    #[rustfmt::skip]
    const PRECOMP_HASH4: [u8; DIGEST_LEN] = [
        0xc6, 0x72, 0xb8, 0xd1, 0xef, 0x56, 0xed, 0x28, 0xab, 0x87, 0xc3,
        0x62, 0x2c, 0x51, 0x14, 0x06, 0x9b, 0xdd, 0x3a, 0xd7, 0xb8, 0xf9,
        0x73, 0x74, 0x98, 0xd0, 0xc0, 0x1e, 0xce, 0xf0, 0x96, 0x7a,
    ];

    /// `tests/unit/unit1615.c:59-61` -- one 52-character run of mixed case,
    /// written twice, so 104 bytes: long enough to fill the first 128-byte
    /// block without spilling into a second.
    const TEST_STR5: &[u8] =
        b"abcdefghijklmnopqrstuvwxyzzyxwvutsrqponMLKJIHGFEDCBA\
          abcdefghijklmnopqrstuvwxyzzyxwvutsrqponMLKJIHGFEDCBA";

    /// `tests/unit/unit1615.c:62-66`.
    #[rustfmt::skip]
    const PRECOMP_HASH5: [u8; DIGEST_LEN] = [
        0xad, 0xe9, 0x5d, 0x55, 0x3b, 0x9e, 0x45, 0x69, 0xdb, 0x53, 0xa4,
        0x04, 0x92, 0xe7, 0x87, 0x94, 0xff, 0xc9, 0x98, 0x5f, 0x93, 0x03,
        0x86, 0x45, 0xe1, 0x97, 0x17, 0x72, 0x7c, 0xbc, 0x31, 0x15,
    ];

    /// `tests/unit/unit1615.c:67-74` -- the long path, 378 bytes, spanning
    /// three 128-byte blocks with the final one partly filled.
    const TEST_STR6: &[u8] =
        b"/long/long/long/long/long/long/long/long/long/long/long\
          /long/long/long/long/long/long/long/long/long/long/long\
          /long/long/long/long/long/long/long/long/long/long/long\
          /long/long/long/long/long/long/long/long/long/long/long\
          /long/long/long/long/long/long/long/long/long/long/long\
          /long/long/long/long/long/long/long/long/long/long/long\
          /long/long/long/long/path?with%20some=parameters";

    /// `tests/unit/unit1615.c:75-79`.
    #[rustfmt::skip]
    const PRECOMP_HASH6: [u8; DIGEST_LEN] = [
        0xbc, 0xab, 0xc6, 0x2c, 0x0a, 0x22, 0xd5, 0xcb, 0xac, 0xac, 0xe9,
        0x25, 0xcf, 0xce, 0xaa, 0xaf, 0x0e, 0xa1, 0xed, 0x42, 0x46, 0x8a,
        0xe2, 0x01, 0xee, 0x2f, 0xdb, 0x39, 0x75, 0x47, 0x73, 0xf1,
    ];

    /// `tests/unit/unit1615.c:80`.
    const TEST_STR7: &[u8] = b"Simple string.";

    /// `tests/unit/unit1615.c:81-85`.
    #[rustfmt::skip]
    const PRECOMP_HASH7: [u8; DIGEST_LEN] = [
        0xde, 0xcb, 0x3c, 0x81, 0x65, 0x4b, 0xa0, 0xf5, 0xf0, 0x45, 0x6b,
        0x7e, 0x61, 0xf5, 0x0d, 0xf5, 0x38, 0xa4, 0xfc, 0xb1, 0x8a, 0x95,
        0xff, 0x59, 0xbc, 0x04, 0x82, 0xcf, 0x23, 0xb2, 0x32, 0x56,
    ];

    /// `tests/unit/unit1615.c:86-104` -- the `255..1` sequence, 255 bytes.
    fn test_seq8() -> Vec<u8> {
        (1u8..=255).rev().collect()
    }

    /// `tests/unit/unit1615.c:105-109`.
    #[rustfmt::skip]
    const PRECOMP_HASH8: [u8; DIGEST_LEN] = [
        0x22, 0x31, 0xf2, 0xa1, 0xb4, 0x89, 0xb2, 0x44, 0xf7, 0x66, 0xa0,
        0xb8, 0x31, 0xed, 0xb7, 0x73, 0x8a, 0x34, 0xdc, 0x11, 0xc8, 0x2c,
        0xf2, 0xb5, 0x88, 0x60, 0x39, 0x6b, 0x5c, 0x06, 0x70, 0x37,
    ];

    /// The two constructed inputs really are the lengths the C literals have.
    ///
    /// Asserted before anything is hashed, and separately from the digests, so
    /// that a mistake in a line continuation or in the sequence bounds reports
    /// itself as a length rather than as an unexplained mismatch.
    #[test]
    fn the_constructed_inputs_have_the_lengths_the_c_literals_have() {
        // 52 characters written twice: tests/unit/unit1615.c:59-61.
        assert_eq!(TEST_STR5.len(), 104);
        assert_eq!(&TEST_STR5[..52], &TEST_STR5[52..]);

        // Six 55-character runs plus a 48-character tail:
        // tests/unit/unit1615.c:67-74.
        assert_eq!(TEST_STR6.len(), 6 * 55 + 48);
        assert_eq!(TEST_STR6.len(), 378);
        assert!(TEST_STR6.starts_with(b"/long/long"));
        assert!(TEST_STR6.ends_with(b"/path?with%20some=parameters"));

        // 255 values, descending, never reaching zero:
        // tests/unit/unit1615.c:86-104.
        let seq = test_seq8();
        assert_eq!(seq.len(), 255);
        assert_eq!(seq.first(), Some(&255u8));
        assert_eq!(seq.last(), Some(&1u8));
        assert!(!seq.contains(&0u8));
        assert!(seq.windows(2).all(|pair| pair[0] == pair[1] + 1));
    }

    /// All eight vectors of `tests/unit/unit1615.c`, in its order.
    #[test]
    fn one_shot_reproduces_every_unit1615_vector() {
        assert_eq!(sha512_256(TEST_STR1), PRECOMP_HASH1);
        assert_eq!(sha512_256(TEST_STR2), PRECOMP_HASH2);
        assert_eq!(sha512_256(TEST_STR3), PRECOMP_HASH3);
        assert_eq!(sha512_256(TEST_STR4), PRECOMP_HASH4);
        assert_eq!(sha512_256(TEST_STR5), PRECOMP_HASH5);
        assert_eq!(sha512_256(TEST_STR6), PRECOMP_HASH6);
        assert_eq!(sha512_256(TEST_STR7), PRECOMP_HASH7);
        assert_eq!(sha512_256(&test_seq8()), PRECOMP_HASH8);
    }

    /// The published FIPS 180-4 example, asserted a second time in the form it
    /// would travel in.
    #[test]
    fn the_published_abc_vector_is_the_one_the_standard_publishes() {
        let rendered = hex_lower(&sha512_256(TEST_STR3));
        assert_eq!(
            rendered,
            "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"
        );

        // The wrong-primitive answer, spelled out so that a failure of the
        // assertion above can be recognised on sight.
        assert_ne!(
            rendered,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    /// The concrete guard against the confusion this module documents.
    ///
    /// Both algorithms answer `"abc"` with 32 bytes, so length proves nothing
    /// and only the values separate them. Asserted at the digest, at the block
    /// length, and at the rendered form, because each is a place where the
    /// wrong choice would go unnoticed.
    #[test]
    fn the_digest_is_not_the_other_thirty_two_byte_digests() {
        let ours = sha512_256(TEST_STR3);
        let sibling = crate::crypto::sha256::sha256(TEST_STR3);

        assert_eq!(ours.len(), sibling.len());
        assert_ne!(ours, sibling);
        assert_ne!(hex_lower(&ours), hex_lower(&sibling));

        // And across every one of the eight inputs, not only the published
        // one, so the inequality cannot hold by coincidence on a single value.
        let inputs: [&[u8]; 7] = [
            TEST_STR1, TEST_STR2, TEST_STR3, TEST_STR4, TEST_STR5, TEST_STR6,
            TEST_STR7,
        ];
        for input in inputs {
            assert_ne!(
                sha512_256(input),
                crate::crypto::sha256::sha256(input),
                "the two 32-byte digests agreed on a {}-byte input",
                input.len()
            );
        }
        assert_ne!(
            sha512_256(&test_seq8()),
            crate::crypto::sha256::sha256(&test_seq8())
        );
    }

    /// The lengths the C parameter table fixes, and the one that must not be
    /// the sibling's.
    #[test]
    fn the_block_length_is_twice_the_siblings_while_the_digest_matches_it() {
        assert_eq!(DIGEST_LEN, 32);
        assert_eq!(BLOCK_LEN, 128);

        let sibling_block = crate::crypto::sha256::BLOCK_LEN;
        assert_eq!(sibling_block, 64);
        assert_ne!(BLOCK_LEN, sibling_block);
        assert_eq!(BLOCK_LEN, sibling_block * 2);
        assert_eq!(DIGEST_LEN, crate::crypto::sha256::DIGEST_LEN);

        assert_eq!(sha512_256(b"anything").len(), DIGEST_LEN);
        assert_eq!(Sha512Trunc256Context::new().finalize().len(), DIGEST_LEN);
        assert_eq!(Sha512Trunc256Context::default().finish().len(), DIGEST_LEN);
    }

    /// The hasher itself reports a 128-byte block, which no configuration of
    /// the sibling could.
    #[test]
    fn the_hashers_own_block_size_is_the_one_the_c_table_records() {
        let from_the_type = <Sha512Trunc256 as BlockSizeUser>::BlockSize::USIZE;
        assert_eq!(from_the_type, 128);
        assert_eq!(from_the_type, BLOCK_LEN);
        assert_eq!(
            from_the_type,
            <Sha512Trunc256 as BlockSizeUser>::block_size()
        );
        assert_ne!(from_the_type, crate::crypto::sha256::BLOCK_LEN);
    }

    /// A streamed digest must equal the one-shot digest of the same bytes.
    #[test]
    fn incremental_agrees_with_one_shot_across_chunk_boundaries() {
        let message = test_seq8();
        assert!(message.len() > BLOCK_LEN);

        for split in [
            0usize,
            1,
            BLOCK_LEN - 1,
            BLOCK_LEN,
            BLOCK_LEN + 1,
            message.len(),
        ] {
            let mut ctx = Sha512Trunc256Context::new();
            ctx.update(&message[..split]);
            ctx.update(&message[split..]);
            assert_eq!(
                ctx.finalize(),
                sha512_256(&message),
                "split at {split}"
            );
        }

        // Byte at a time over the longest vector, which crosses the block
        // boundary twice and finishes on a partly filled block.
        let mut ctx = Sha512Trunc256Context::new();
        for byte in TEST_STR6 {
            ctx.update(&[*byte]);
        }
        assert_eq!(ctx.finish(), PRECOMP_HASH6);

        // Nothing fed at all is the empty-input vector, which is the case a
        // context that primed itself lazily would get wrong.
        assert_eq!(Sha512Trunc256Context::new().finalize(), PRECOMP_HASH4);
    }

    /// A cloned context continues independently of its origin.
    ///
    /// `Clone` is derived, so this asserts the property the derive is there
    /// for: a caller digesting several messages that share a prefix primes one
    /// context and clones it, rather than re-feeding the prefix.
    #[test]
    fn a_cloned_context_diverges_from_its_origin() {
        let mut prefix = Sha512Trunc256Context::new();
        prefix.update(b"shared-prefix:");

        let mut first = prefix.clone();
        first.update(b"one");
        let mut second = prefix;
        second.update(b"two");

        assert_eq!(first.finalize(), sha512_256(b"shared-prefix:one"));
        assert_eq!(second.finalize(), sha512_256(b"shared-prefix:two"));
    }

    /// Thirty-two bytes render as sixty-four lowercase characters.
    #[test]
    fn the_wire_rendering_is_sixty_four_lowercase_hex_characters() {
        let rendered = hex_lower(&sha512_256(TEST_STR1));
        assert_eq!(rendered.len(), 64);
        assert_eq!(rendered.len(), DIGEST_LEN * 2);
        assert_eq!(rendered.len(), SHA256_HEX_BUF_LEN - 1);
        assert!(!rendered.chars().any(|c| c.is_ascii_uppercase()));
        assert!(rendered.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(
            rendered,
            "18d27566bd1ac66b2332d8c54ad43f7bb22079c906d05f491f3f07a28d5c6990"
        );

        // Every one of the eight vectors renders to the same width, which is
        // what lets one 65-byte C buffer serve all of them.
        for digest in [
            PRECOMP_HASH1,
            PRECOMP_HASH2,
            PRECOMP_HASH3,
            PRECOMP_HASH4,
            PRECOMP_HASH5,
            PRECOMP_HASH6,
            PRECOMP_HASH7,
            PRECOMP_HASH8,
        ] {
            let hex = hex_lower(&digest);
            assert_eq!(hex.len(), SHA256_HEX_BUF_LEN - 1);
            assert!(!hex.chars().any(|c| c.is_ascii_uppercase()));
        }
    }

    /// The coherence assertion the marker type exists for.
    #[test]
    fn the_marker_type_keys_the_same_hash_as_the_keyed_module() {
        let key = b"Jefe";
        let message = b"what do ya want for nothing?";

        let mut mac = Hmac::<Sha512Trunc256>::new_from_slice(key)
            .expect("the keyed construction accepts a key of any length");
        mac.update(message);
        let tag: [u8; DIGEST_LEN] = mac.finalize().into_bytes().into();

        assert_eq!(tag.len(), DIGEST_LEN);
        assert_eq!(tag, crate::crypto::hmac_sha512_256(key, message));

        // A key longer than the block is replaced by its own digest
        // (lib/hmac.c:65-74), so the 128 rather than 64 is observable in the
        // tag: a key of exactly 128 bytes is used as given, and one byte more
        // is not.
        let at_the_block = vec![0xaau8; BLOCK_LEN];
        let past_the_block = vec![0xaau8; BLOCK_LEN + 1];
        assert_ne!(
            crate::crypto::hmac_sha512_256(&at_the_block, message),
            crate::crypto::hmac_sha512_256(&past_the_block, message)
        );
    }

    /// The alias must be reachable under the path a sibling module spells, not
    /// only under the `super::` path this test module happens to use.
    #[test]
    fn the_marker_type_is_reachable_by_fully_qualified_path() {
        const _: Option<crate::crypto::sha512_256::Sha512Trunc256> = None;
        let mut mac =
            Hmac::<crate::crypto::sha512_256::Sha512Trunc256>::new_from_slice(
                b"any key at all",
            )
            .expect("the keyed construction accepts a key of any length");
        mac.update(b"any message");
        assert_eq!(mac.finalize().into_bytes().len(), DIGEST_LEN);
    }

    /// The capability predicate answers, and answers unconditionally.
    #[test]
    fn the_capability_predicate_reports_the_digest_as_present() {
        assert!(available());

        // And the thing it claims to be present really answers, which is what
        // keeps the claim substantive rather than a bare boolean.
        assert_eq!(sha512_256(TEST_STR3), PRECOMP_HASH3);
    }
}
