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
//! MD4, RFC 1320. Supersedes `lib/md4.c` and `lib/curl_md4.h` over the `md4
//! 0.10.2` crate.
//!
//! # What belongs to the NTLM module and not to this one
//!
//! The NT hash is three steps and only the middle one is MD4. Measured from
//! `Curl_ntlm_core_mk_nt_hash` (`lib/curl_ntlm_core.c:410-431`):
//!
//! 1. `ascii_to_unicode_le` (`:395-403`) widens the password to UTF-16LE,
//!    writing `dest[2 * i] = src[i]` and `dest[2 * i + 1] = '\0'`.
//! 2. `Curl_md4it(ntbuffer, pw, 2 * len)` (`:425`) digests all `2 * len`
//!    widened bytes.
//! 3. `memset(ntbuffer + 16, 0, 21 - 16)` (`:427`) zeroes the tail of a
//!    twenty-one byte buffer, sized for the three seven-byte DES key
//!    schedules that follow it.
//!
//! Steps 1 and 3 are NTLM's, not MD4's, and `lib/curl_ntlm_core.c` maps to
//! `auth/ntlm.rs`. This module accordingly takes an opaque `&[u8]` and neither
//! knows nor cares that the bytes are UTF-16LE, and it returns exactly sixteen
//! bytes rather than twenty-one. Two consequences are worth stating because
//! getting either wrong is silent:
//!
//! * **The input is bytes, not text.** A UTF-16LE password is half NUL bytes,
//!   so any length-free reading of it would truncate after the first
//!   character. `Curl_md4it` takes an explicit `len` for exactly that reason,
//!   and a Rust slice carries the same information in its type. The test
//!   module below asserts it rather than assuming it.
//! * **DES is not this directory's business.** `lib/curl_ntlm_core.c:59-90`
//!   obtains `DES_set_key_unchecked` and `DES_ecb_encrypt` from the linked TLS
//!   backend, and every C TLS backend is dropped, so `des 0.8.1` is consumed
//!   directly by `auth/ntlm.rs`. There is no DES module in this directory and
//!   there must not be one.
//!
//! # Where the C unit test went
//!
//! `tests/unit/unit1611.c` is the MD4 unit test, and `tests/data/test1611` --
//! named "MD4 unit tests" -- gates on the `unittest` feature. This binary does
//! not advertise `unittest`, so that fixture skips; and the C program could
//! not link in any case, because it calls the internal `Curl_md4it` and a Rust
//! static library genuinely does not place `pub(crate)` items in its symbol
//! table. Re-exporting internals to make it link would destroy the
//! encapsulation this crate's safety guarantee rests on, so it is not done.
//! Its two assertions live in this file's `tests` module instead, beside the
//! seven published RFC 1320 vectors and a cross-check of the NT hash shape.

use ::md4::{Digest, Md4};

/// Length of an MD4 digest in bytes: `MD4_DIGEST_LENGTH`
/// (`lib/curl_md4.h:30`).
pub(crate) const DIGEST_LEN: usize = 16;

/// Digest a whole message: `Curl_md4it` (`lib/md4.c:425-440`).
///
/// The input is an opaque byte slice. This function does not know, and must
/// not know, that its sole production caller passes a UTF-16LE-widened
/// password -- that widening belongs to `auth/ntlm.rs`, as does the
/// twenty-one byte buffer whose tail the caller zeroes afterwards.
#[allow(dead_code)]
pub(crate) fn md4(input: &[u8]) -> [u8; DIGEST_LEN] {
    let mut hasher = Md4::new();
    hasher.update(input);
    hasher.finalize().into()
}

// Tests
//
// Three sources feed this module, and the distinction between them matters
// because they carry different authority:
//
//   * RFC 1320 appendix A.5 -- the seven published vectors of the standard
//     itself. These are the algorithm's definition.
//   * `tests/unit/unit1611.c:38-50` -- the two vectors curl asserted against
//     `Curl_md4it`. These are what this migration must not regress, and the
//     C program that held them cannot link against a Rust static library, so
//     this is now the only place they run.
//   * The NTLM cross-check -- the published NT hash of a known password,
//     which pins the digest and the byte-widening convention together before
//     `auth/ntlm.rs` exists to pin them itself.

#[cfg(test)]
mod tests {
    use super::{md4, DIGEST_LEN};
    use crate::crypto::hex_lower;

    /// RFC 1320 appendix A.5, in the order the standard lists them.
    ///
    /// `rustfmt::skip` keeps one vector per row with the expected digest as
    /// the published 32-character hex string, so a reader can compare a row
    /// against the RFC directly instead of re-chunking sixteen numbers.
    #[rustfmt::skip]
    const RFC_1320_VECTORS: [(&[u8], &str); 7] = [
        (b"",               "31d6cfe0d16ae931b73c59d7e0c089c0"),
        (b"a",              "bde52cb31de33e46245e05fbdbd6fb24"),
        (b"abc",            "a448017aaf21d8525fc10ae87aa6729d"),
        (b"message digest", "d9130a8164549fe818874806e1c7014b"),
        (
            b"abcdefghijklmnopqrstuvwxyz",
            "d79e1c308aa5bbcdeea8ed63df412da9",
        ),
        (
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
              abcdefghijklmnopqrstuvwxyz\
              0123456789",
            "043f8582f241db351ce627e153e7f0e4",
        ),
        (
            b"1234567890123456789012345678901234567890\
              1234567890123456789012345678901234567890",
            "e33b4ddc9c38f2199c3e7b164fcc0536",
        ),
    ];

    /// The two vectors `tests/unit/unit1611.c` asserts against `Curl_md4it`,
    /// transcribed from the `\x`-escaped literals at `:40-43` and `:47-50`.
    #[rustfmt::skip]
    const UNIT1611_VECTORS: [(&[u8], &str); 2] = [
        (b"1",              "8be1ec697b14ad3a53b371436120641d"),
        (b"hello-you-fool", "a7161cad7ebedbbcf8c723102d2ce20b"),
    ];

    /// The UTF-16LE encoding of the password `"password"`, written out as the
    /// literal bytes rather than produced by a helper.
    #[rustfmt::skip]
    const PASSWORD_UTF16LE: [u8; 16] = [
        0x70, 0x00, 0x61, 0x00, 0x73, 0x00, 0x73, 0x00,
        0x77, 0x00, 0x6f, 0x00, 0x72, 0x00, 0x64, 0x00,
    ];

    /// The published NT hash of `"password"`, i.e. MD4 over the bytes above.
    const PASSWORD_NT_HASH: &str = "8846f7eaee8fb117ad06bdd830b7586c";

    #[test]
    fn matches_every_rfc_1320_appendix_a5_vector() {
        for (input, expected) in RFC_1320_VECTORS {
            assert_eq!(
                hex_lower(&md4(input)),
                expected,
                "RFC 1320 vector of {} bytes",
                input.len()
            );
        }
    }

    /// The seven rows must really be seven distinct inputs of the lengths RFC
    /// 1320 specifies. A table that had silently lost a row, or whose
    /// line-continued literals had absorbed their indentation, would still
    /// pass the loop above while testing less than it claims.
    #[test]
    fn the_rfc_1320_table_is_the_published_one_and_is_complete() {
        let lengths: Vec<usize> = RFC_1320_VECTORS
            .iter()
            .map(|(input, _)| input.len())
            .collect();
        assert_eq!(lengths, [0, 1, 3, 14, 26, 62, 80]);

        // Two of those lengths are the ones that exercise MD4's padding rule,
        // which appends a 0x80 byte, pads to 56 bytes modulo 64 and then
        // appends a 64-bit little-endian bit count. 62 forces a second block
        // for the length alone; 80 spans two blocks outright.
        assert!(lengths.contains(&62));
        assert!(lengths.contains(&80));
    }

    /// `tests/unit/unit1611.c`, relocated. This is the migration's regression
    /// guard, not a restatement of the standard.
    #[test]
    fn matches_the_two_vectors_of_the_c_unit_test() {
        for (input, expected) in UNIT1611_VECTORS {
            assert_eq!(
                hex_lower(&md4(input)),
                expected,
                "unit1611.c vector {:?}",
                core::str::from_utf8(input).expect("ASCII test input")
            );
        }
    }

    /// The contracted width, asserted three ways: the constant itself, the
    /// length of a returned digest, and the length of its hex rendering.
    #[test]
    fn digest_length_is_the_contracted_sixteen() {
        assert_eq!(DIGEST_LEN, 16);
        assert_eq!(md4(b"anything").len(), DIGEST_LEN);
        assert_eq!(hex_lower(&md4(b"anything")).len(), DIGEST_LEN * 2);
    }

    /// The NT hash, end to end at this module's level.
    ///
    /// This is the one test that ties the primitive to its only real consumer.
    /// It proves the digest and the byte-widening convention agree before
    /// `auth/ntlm.rs` exists to depend on both, and it is a published value,
    /// so a wrong answer here means a wrong NTLM type-3 message on the wire.
    #[test]
    fn digests_the_utf_16le_password_to_the_published_nt_hash() {
        assert_eq!(hex_lower(&md4(&PASSWORD_UTF16LE)), PASSWORD_NT_HASH);

        // The C caller passes `2 * len` bytes, so the slice really is twice
        // the eight-character password. Asserted so that a table edited to
        // the wrong width could not pass the comparison above by accident.
        assert_eq!(PASSWORD_UTF16LE.len(), 2 * "password".len());
    }

    /// Interior NUL bytes are message content, not terminators.
    ///
    /// This is the failure mode a length-free reading of the input would
    /// produce, and it is not hypothetical: every second byte of a UTF-16LE
    /// password is NUL, so truncating at the first one would digest a single
    /// character and still return a plausible-looking sixteen bytes.
    /// `Curl_md4it` takes an explicit `len` for precisely this reason.
    #[test]
    fn hashes_interior_nul_bytes_instead_of_stopping_at_them() {
        // Truncating `PASSWORD_UTF16LE` at its first NUL would leave b"p".
        assert_ne!(md4(&PASSWORD_UTF16LE), md4(b"p"));

        // And the trailing NUL is content too: dropping it changes the
        // digest, which is what distinguishes a length-carrying slice from a
        // C string.
        let without_final_nul = &PASSWORD_UTF16LE[..PASSWORD_UTF16LE.len() - 1];
        assert_ne!(md4(without_final_nul), md4(&PASSWORD_UTF16LE));

        // A message that is nothing but NUL bytes still has a length-dependent
        // digest, so no prefix of it collides with another.
        let all_nuls = [0u8; 8];
        for split in 0..all_nuls.len() {
            assert_ne!(
                md4(&all_nuls[..split]),
                md4(&all_nuls),
                "NUL run of {split} bytes"
            );
        }
    }

    /// A pure function of its input: repeated calls agree, and a fresh hasher
    /// is used each time rather than shared state being carried between
    /// calls. `Curl_md4it` guaranteed the same by declaring its context on
    /// the stack (`lib/md4.c:428`).
    #[test]
    fn is_a_pure_function_of_its_input() {
        let message: Vec<u8> = (0u8..=255).collect();
        let first = md4(&message);
        for _ in 0..4 {
            assert_eq!(md4(&message), first);
        }

        // Interleaving other inputs must not disturb the result either, which
        // is what a leaked or reused context would break.
        assert_eq!(md4(b""), md4(b""));
        let _ = md4(b"interleaved");
        assert_eq!(md4(&message), first);
    }

    /// Every input length from nothing through 137 bytes -- two full 64-byte
    /// blocks plus a tail, which pads out to three blocks -- yields a
    /// full-width digest, and no two lengths of the same filler byte collide.
    #[test]
    fn every_length_through_three_padded_blocks_has_its_own_digest() {
        let mut seen: Vec<[u8; DIGEST_LEN]> = Vec::new();
        for len in 0..=137usize {
            let input = vec![0x5au8; len];
            let digest = md4(&input);
            assert_eq!(digest.len(), DIGEST_LEN, "length {len}");
            assert!(
                !seen.contains(&digest),
                "length {len} collided with a shorter input"
            );
            seen.push(digest);
        }
        assert_eq!(seen.len(), 138, "the sweep must really have run 0..=137");
    }

    /// A single flipped input bit changes the digest. Weak as cryptography,
    /// but it is the assertion that catches a wiring mistake in which the
    /// input never reaches the hasher at all.
    #[test]
    fn one_flipped_input_bit_changes_the_digest() {
        let base = [0x00u8; DIGEST_LEN];
        let baseline = md4(&base);
        for byte in 0..DIGEST_LEN {
            for bit in 0..8u32 {
                let mut mutated = base;
                mutated[byte] ^= 1u8 << bit;
                assert_ne!(
                    md4(&mutated),
                    baseline,
                    "byte {byte} bit {bit} did not reach the digest"
                );
            }
        }
    }

    /// The empty message has the well-known non-zero digest of RFC 1320's
    /// initial state, so an implementation that returned a zeroed buffer
    /// without hashing anything would be caught.
    #[test]
    fn the_empty_message_digest_is_not_a_zeroed_buffer() {
        let empty = md4(b"");
        assert_ne!(empty, [0u8; DIGEST_LEN]);
        assert_eq!(hex_lower(&empty), "31d6cfe0d16ae931b73c59d7e0c089c0");
    }
}
