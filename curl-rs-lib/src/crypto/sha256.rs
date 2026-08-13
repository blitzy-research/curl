// /***************************************************************************
//  *                                  _   _ ____  _
//  *  Project                     ___| | | |  _ \| |
//  *                             / __| | | | |_) | |
//  *                            | (__| |_| |  _ <| |___
//  *                             \___|\___/|_| \_\_____|
//  *
//  * Copyright (C) Florin Petriuc, <petriuc.florin@gmail.com>
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
//! SHA-256, FIPS 180-4. Supersedes `lib/sha256.c` and `lib/curl_sha256.h` over
//! `sha2 0.10.9`'s `Sha256`.
//!
//! # The rendering is lowercase, and the trap is one function away
//!
//! `lib/vauth/digest.c:142-150` declares
//! `auth_digest_sha256_to_ascii(const unsigned char *source /* 32 bytes */,
//! unsigned char *dest /* 65 bytes */)` and fills it with
//! `curl_msnprintf((char *)&dest[i * 2], 3, "%02x", source[i])` for `i < 32`.
//! Thirty-two bytes in, sixty-four **lowercase** characters plus a terminator
//! out -- the same 65 that `lib/http_aws_sigv4.c:56` computes.
//!
//! `lib/escape.c:218-227` is the near neighbour that must not be used here:
//! `Curl_hexbyte` emits an UPPERCASE pair. Rendering belongs to
//! [`crate::crypto::hex_lower`], which goes through `hex 0.4.3` and is
//! lowercase by definition; this module returns raw bytes and never a string,
//! so it cannot get the case wrong on its own.
//!
//! # The licence banner above is longer than its siblings'
//!
//! Twenty-four lines and two attribution lines, reproducing `lib/sha256.c:1-24`
//! verbatim -- one line more than `md5.rs`, `md4.rs`, `rand.rs` and
//! `crypto/mod.rs` carry. `lib/curl_sha256.h:3-26` carries the same pair, so
//! both C sources agree. It is not boilerplate to be normalised: the extra
//! line is the attribution of the person who contributed this digest, and
//! `reuse lint` (`.github/workflows/hygiene.yml:52`) reads what is actually in
//! the file. `REUSE.toml` annotates only three `.txt` oracle files and nothing
//! under `curl-rs-lib/src/`, so the header here is the only record there is.
//! [`crate::crypto`] tabulates the banner of every file in this directory for
//! the same reason.

use ::sha2::{Digest, Sha256 as Sha256Hasher};

/// Length of a SHA-256 digest in bytes.
pub(crate) const DIGEST_LEN: usize = 32;

/// SHA-256's compression block size in bytes.
#[allow(dead_code)]
pub(crate) const BLOCK_LEN: usize = 64;

/// The `digest` marker type for SHA-256, published so that
/// [`crate::crypto::hmac`] can instantiate `Hmac<Sha256>` without naming the
/// `sha2` crate a second time.
#[allow(dead_code)]
pub(crate) type Sha256 = Sha256Hasher;

/// Digest a whole message: `Curl_sha256it` (`lib/sha256.c:441-466`).
#[allow(dead_code)]
pub(crate) fn sha256(input: &[u8]) -> [u8; DIGEST_LEN] {
    let mut hasher = Sha256Hasher::new();
    hasher.update(input);
    hasher.finalize().into()
}

/// The incremental form: construct, feed any number of times, finish once.
///
/// This has no direct C counterpart. `lib/curl_sha256.h:40-41` declares only
/// the one-shot entry point, and `lib/sha256.c:454-466` runs its own
/// init / update / final sequence over a stack context that no caller ever
/// sees. It exists because two consumers genuinely assemble a message in
/// pieces and would otherwise have to concatenate it first:
///
/// * AWS SigV4 builds a canonical request from a method, a path, a sorted query
///   string, sorted headers, a signed-header list and a payload hash before
///   digesting the result (`lib/http_aws_sigv4.c:1034`).
/// * The TLS session cache digests a composite key
///   (`lib/vtls/vtls_scache.c:114`).
#[derive(Clone, Default)]
pub(crate) struct Sha256Context {
    #[allow(dead_code)]
    hasher: Sha256Hasher,
}

impl Sha256Context {
    /// A fresh context: `my_sha256_init` (`lib/sha256.c:460`).
    ///
    /// [`Default`] is derived alongside this and produces the same value, so a
    /// caller in a generic position is not forced through the inherent
    /// constructor.
    #[allow(dead_code)]
    pub(crate) fn new() -> Self {
        Self {
            hasher: Sha256Hasher::new(),
        }
    }

    /// Feed the next chunk: `my_sha256_update` (`lib/sha256.c:462`).
    #[allow(dead_code)]
    pub(crate) fn update(&mut self, input: &[u8]) {
        self.hasher.update(input);
    }

    /// Finish and return the digest: `my_sha256_final` (`lib/sha256.c:463`).
    ///
    /// Consuming `self` is stricter than the C sequence, where nothing stops a
    /// caller from finalising the same context twice. Here a second call does
    /// not compile.
    #[allow(dead_code)]
    pub(crate) fn finalize(self) -> [u8; DIGEST_LEN] {
        self.hasher.finalize().into()
    }

    /// [`Sha256Context::finalize`] under the name the incremental MD5 context
    /// publishes.
    #[allow(dead_code)]
    pub(crate) fn finish(self) -> [u8; DIGEST_LEN] {
        self.finalize()
    }
}

// Tests -- where the coverage of tests/unit/unit1610.c now lives
//
// `tests/unit/unit1610.c` is the C unit test for this digest, and
// `tests/data/test1610` is named "SHA256 unit tests" and gates on
// `<features>unittest</features>`. This binary does not advertise `unittest`,
// so that fixture skips -- and it could not run in any case, because it links
// a debug static library and calls the internal `Curl_sha256it` symbol, which
// a Rust static library genuinely does not place in its symbol table.

#[cfg(test)]
mod tests {
    use super::{sha256, Sha256, Sha256Context, BLOCK_LEN, DIGEST_LEN};
    use crate::crypto::{hex_lower, SHA256_HEX_BUF_LEN};
    use ::hmac::{Hmac, Mac};

    /// `sha256("")` in the wire form, reused below as the payload-hash
    /// component of an AWS SigV4 canonical request.
    const EMPTY_HEX: &str =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /// `sha256("1")`, exactly the 32 bytes `tests/unit/unit1610.c:49-53` hands
    /// to `verify_memory`.
    #[rustfmt::skip]
    const UNIT1610_DIGIT_ONE: [u8; DIGEST_LEN] = [
        0x6b, 0x86, 0xb2, 0x73, 0xff, 0x34, 0xfc, 0xe1,
        0x9d, 0x6b, 0x80, 0x4e, 0xff, 0x5a, 0x3f, 0x57,
        0x47, 0xad, 0xa4, 0xea, 0xa2, 0x2f, 0x1d, 0x49,
        0xc0, 0x1e, 0x52, 0xdd, 0xb7, 0x87, 0x5b, 0x4b,
    ];

    /// `sha256("hello-you-fool")`, from `tests/unit/unit1610.c:57-61`.
    #[rustfmt::skip]
    const UNIT1610_HELLO_YOU_FOOL: [u8; DIGEST_LEN] = [
        0xcb, 0xb1, 0x6a, 0x8a, 0xb9, 0xcb, 0xb9, 0x35,
        0xa8, 0xcb, 0xa0, 0x2e, 0x28, 0xc0, 0x26, 0x30,
        0xd1, 0x19, 0x9c, 0x1f, 0x02, 0x17, 0xf4, 0x7c,
        0x96, 0x20, 0xf3, 0xef, 0xe8, 0x27, 0x15, 0xae,
    ];

    /// The short published FIPS 180-4 examples, as `(input, wire form)`.
    #[rustfmt::skip]
    const FIPS_180_4: [(&[u8], &str); 4] = [
        (
            b"",
            EMPTY_HEX,
        ),
        (
            b"abc",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
        (
            b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn\
              hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
        ),
    ];

    /// The two vectors the C unit test asserts, byte for byte.
    #[test]
    fn one_shot_reproduces_the_unit1610_vectors() {
        assert_eq!(sha256(b"1"), UNIT1610_DIGIT_ONE);
        assert_eq!(sha256(b"hello-you-fool"), UNIT1610_HELLO_YOU_FOOL);
    }

    #[test]
    fn one_shot_reproduces_the_short_fips_180_4_examples() {
        for (input, expected) in FIPS_180_4 {
            // The length is bound here rather than passed as a trailing
            // message argument. A trailing argument is evaluated only on the
            // failing path, so while the test passes that expression is never
            // executed -- a coverage artefact rather than an untested branch.
            // Binding it keeps the failure message and leaves no unexecuted
            // line behind.
            let len = input.len();
            let digest = sha256(input);
            assert_eq!(digest.len(), DIGEST_LEN);
            assert_eq!(hex_lower(&digest), expected, "input of {len} bytes");
        }

        // The lengths the table is chosen for, asserted so that an edit which
        // shortens a literal cannot quietly remove the two-block case.
        let lengths: Vec<usize> =
            FIPS_180_4.iter().map(|(input, _)| input.len()).collect();
        assert_eq!(lengths, vec![0, 3, 56, 112]);
    }

    /// The long published vector: one million `'a'` characters.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "a million bytes through the interpreter proves nothing new"
    )]
    fn one_shot_reproduces_the_long_fips_180_4_example() {
        let input = vec![b'a'; 1_000_000];
        assert_eq!(
            hex_lower(&sha256(&input)),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    /// A streamed digest must equal the one-shot digest of the same bytes, or
    /// the AWS SigV4 canonical-request hash and the payload hash would disagree
    /// with each other.
    #[test]
    fn incremental_agrees_with_one_shot_across_chunk_boundaries() {
        let message: Vec<u8> = (0u8..=255).collect();
        for split in [
            0usize,
            1,
            BLOCK_LEN - 1,
            BLOCK_LEN,
            BLOCK_LEN + 1,
            200,
            message.len(),
        ] {
            let mut ctx = Sha256Context::new();
            ctx.update(&message[..split]);
            ctx.update(&message[split..]);
            assert_eq!(ctx.finalize(), sha256(&message), "split at {split}");
        }
    }

    /// Many small chunks, in the shape `lib/http_aws_sigv4.c:1034` digests.
    #[test]
    fn many_chunks_agree_with_the_concatenated_one_shot() {
        let parts: [&[u8]; 6] = [
            b"GET\n",
            b"/\n",
            b"a=1&b=2\n",
            b"host:example.com\nx-amz-date:20240102T030405Z\n\n",
            b"host;x-amz-date\n",
            EMPTY_HEX.as_bytes(),
        ];

        let mut joined: Vec<u8> = Vec::new();
        let mut streamed = Sha256Context::new();
        let mut aliased = Sha256Context::default();
        for part in parts {
            joined.extend_from_slice(part);
            streamed.update(part);
            aliased.update(part);
        }

        let expected = sha256(&joined);
        assert_eq!(streamed.finalize(), expected);
        assert_eq!(aliased.finish(), expected);
    }

    #[test]
    fn the_lengths_are_the_ones_the_c_parameter_table_fixes() {
        assert_eq!(DIGEST_LEN, 32);
        assert_eq!(BLOCK_LEN, 64);
        assert_eq!(sha256(b"anything").len(), DIGEST_LEN);
        assert_eq!(Sha256Context::new().finalize().len(), DIGEST_LEN);
        assert_eq!(Sha256Context::default().finish().len(), DIGEST_LEN);
    }

    /// The concrete guard against the one confusion that silently corrupts a
    /// keyed digest.
    #[test]
    fn the_block_length_is_not_the_sha512_256_block_length() {
        let sibling = crate::crypto::sha512_256::BLOCK_LEN;
        assert_eq!(BLOCK_LEN, 64);
        assert_eq!(sibling, 128);
        assert_ne!(BLOCK_LEN, sibling);
        assert_eq!(sibling, BLOCK_LEN * 2);
        assert_eq!(DIGEST_LEN, crate::crypto::sha512_256::DIGEST_LEN);
    }

    /// Thirty-two bytes render as sixty-four lowercase characters.
    #[test]
    fn the_wire_rendering_is_sixty_four_lowercase_hex_characters() {
        let rendered = hex_lower(&sha256(b"1"));
        assert_eq!(rendered.len(), 64);
        assert_eq!(rendered.len(), DIGEST_LEN * 2);
        assert_eq!(rendered.len(), SHA256_HEX_BUF_LEN - 1);
        assert!(!rendered.chars().any(|c| c.is_ascii_uppercase()));
        assert!(rendered.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(
            rendered,
            "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b"
        );
    }

    /// The coherence assertion the marker type exists for.
    #[test]
    fn the_marker_type_keys_the_same_hash_as_the_keyed_module() {
        let key = b"Jefe";
        let message = b"what do ya want for nothing?";

        let mut mac = Hmac::<Sha256>::new_from_slice(key)
            .expect("the keyed construction accepts a key of any length");
        mac.update(message);
        let tag: [u8; DIGEST_LEN] = mac.finalize().into_bytes().into();

        assert_eq!(tag.len(), DIGEST_LEN);
        assert_eq!(tag, crate::crypto::hmac_sha256(key, message));
    }

    /// The alias must be reachable under the path a sibling module would spell,
    /// not only under the `super::` path this test module happens to use.
    #[test]
    fn the_marker_type_is_reachable_by_fully_qualified_path() {
        const _: Option<crate::crypto::sha256::Sha256> = None;
        let mut mac = Hmac::<crate::crypto::sha256::Sha256>::new_from_slice(
            b"any key at all",
        )
        .expect("the keyed construction accepts a key of any length");
        mac.update(b"any message");
        assert_eq!(mac.finalize().into_bytes().len(), DIGEST_LEN);
    }

    /// A cloned context continues independently of its origin.
    ///
    /// `Clone` is derived, so this asserts the property the derive is there
    /// for: the TLS session cache digests several keys that share a common
    /// prefix, and cloning a primed context is how that is done without
    /// re-feeding the prefix.
    #[test]
    fn a_cloned_context_diverges_from_its_origin() {
        let mut prefix = Sha256Context::new();
        prefix.update(b"shared-prefix:");

        let mut first = prefix.clone();
        first.update(b"one");
        let mut second = prefix;
        second.update(b"two");

        assert_eq!(first.finalize(), sha256(b"shared-prefix:one"));
        assert_eq!(second.finalize(), sha256(b"shared-prefix:two"));
    }
}
