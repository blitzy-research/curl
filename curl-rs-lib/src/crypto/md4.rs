// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! MD4, RFC 1320. Supersedes `lib/md4.c` and `lib/curl_md4.h`.
//!
//! One consumer, one shape. `lib/curl_ntlm_core.c:425` calls
//! `Curl_md4it(ntbuffer, pw, 2 * len)` to derive the NTLM password hash from
//! the UTF-16LE password, and that is the only place curl uses MD4 at all.
//! curl never streams MD4 and never keys it, so this module publishes neither
//! an incremental context nor a block length -- there is no HMAC parameter
//! table to reproduce, and inventing one would be surface with no call site.
//!
//! MD4 is cryptographically broken and is present solely because the NTLM
//! wire format specifies it. AAP section 0.8.1 freezes that wire format, so
//! the algorithm cannot be substituted.

use ::md4::{Digest, Md4};

/// Length of an MD4 digest in bytes (`lib/curl_md4.h:32`, `MD4_DIGEST_LENGTH`).
#[allow(dead_code)]
pub(crate) const DIGEST_LEN: usize = 16;

/// Digest a whole message: `Curl_md4it` (`lib/md4.c`).
///
/// Returns the 16 raw bytes, which is what `lib/curl_ntlm_core.c` feeds
/// straight into the DES key schedule without rendering them as text.
#[allow(dead_code)]
pub(crate) fn md4(input: &[u8]) -> [u8; DIGEST_LEN] {
    let mut hasher = Md4::new();
    hasher.update(input);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::{md4, DIGEST_LEN};

    /// RFC 1320 appendix A.5, and the vectors `tests/unit/unit1611.c` asserts
    /// against `Curl_md4it`.
    #[test]
    fn matches_the_rfc_1320_test_suite() {
        assert_eq!(
            md4(b""),
            [
                0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7, 0x3c,
                0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0
            ]
        );
        assert_eq!(
            md4(b"abc"),
            [
                0xa4, 0x48, 0x01, 0x7a, 0xaf, 0x21, 0xd8, 0x52, 0x5f, 0xc1,
                0x0a, 0xe8, 0x7a, 0xa6, 0x72, 0x9d
            ]
        );
        assert_eq!(
            md4(b"message digest"),
            [
                0xd9, 0x13, 0x0a, 0x81, 0x64, 0x54, 0x9f, 0xe8, 0x18, 0x87,
                0x48, 0x06, 0xe1, 0xc7, 0x01, 0x4b
            ]
        );
    }

    #[test]
    fn digest_length_is_the_contracted_sixteen() {
        assert_eq!(md4(b"anything").len(), DIGEST_LEN);
    }
}
