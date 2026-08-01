// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! HMAC, RFC 2104. Supersedes `lib/hmac.c` and `lib/curl_hmac.h`.
//!
//! `lib/hmac.c:40-41` fixes the inner and outer pads at `0x36` and `0x5C`, and
//! the C implementation was generic over a parameter table
//! (`struct HMAC_params`, `lib/curl_hmac.h:36-49`) carrying a block size, a
//! result size and three function pointers. The Rust replacement is generic
//! over the `digest` traits instead, which is precisely why a single `digest`
//! generation across the whole dependency graph is a hard requirement: with
//! `digest 0.10` and `digest 0.11` both resolved, the bounds below would not
//! unify and `Hmac<Md5>` would fail to compile.
//!
//! Three concrete instantiations are published because the C tree provided
//! exactly three parameter tables: `Curl_HMAC_MD5` (`lib/md5.c:528-535`),
//! `Curl_HMAC_SHA256` (`lib/sha256.c:468-475`) and `Curl_HMAC_SHA512_256`
//! (`lib/curl_sha512_256.c:788-804`). The generic [`hmac`] and [`HmacContext`]
//! stay reachable as `crypto::hmac::hmac::<D>` and
//! `crypto::hmac::HmacContext<D>` and are deliberately not re-exported by
//! [`crate::crypto`], whose documentation explains why.
//!
//! # The bound is written out rather than abbreviated
//!
//! `hmac 0.12.1` expresses "an eager, fixed-output block hash" through five
//! separate `digest` core traits plus two type-level comparisons
//! (`hmac-0.12.1/src/optim.rs:20-31`), and it publishes no trait alias for the
//! combination. Emulating one with a blanket-implemented local trait would add
//! a layer whose elaboration rules are subtler than the clause it replaces, so
//! the clause is repeated verbatim at each of the three sites that need it.
//! Verbosity here is preferable to a construct a reader has to reason about.
//!
//! # No key length is rejected
//!
//! RFC 2104 section 3 and `lib/hmac.c:98-118` both prescribe hashing a key
//! longer than the block and zero-padding a shorter one.
//! `Hmac::new_from_slice` does both, so it cannot reject a byte string; the
//! `expect` below documents an unreachable arm rather than swallowing a real
//! error.

use ::hmac::digest::block_buffer::Eager;
use ::hmac::digest::core_api::{
    BlockSizeUser, BufferKindUser, CoreProxy, FixedOutputCore, OutputSizeUser,
    UpdateCore,
};
use ::hmac::digest::generic_array::typenum::{IsLess, Le, NonZero, U256};
use ::hmac::digest::{HashMarker, Output};
use ::hmac::{Hmac, Mac};

use super::md5::Md5;
use super::sha512_256::Sha512Trunc256;

/// Key a whole message in one call.
///
/// The C `Curl_HMAC_init` / `_update` / `_final` sequence collapsed, which is
/// how every call site in the C tree actually uses it.
#[allow(dead_code)]
pub(crate) fn hmac<D>(key: &[u8], message: &[u8]) -> Output<Hmac<D>>
where
    D: CoreProxy,
    D::Core: HashMarker
        + UpdateCore
        + FixedOutputCore
        + BufferKindUser<BufferKind = Eager>
        + Default
        + Clone,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    let mut ctx = HmacContext::<D>::new(key);
    ctx.update(message);
    ctx.finish()
}

/// The incremental form: `Curl_HMAC_init`, `Curl_HMAC_update` and
/// `Curl_HMAC_final` (`lib/curl_hmac.h:51-57`).
///
/// AWS SigV4 is the caller that needs it, because it keys a canonical request
/// it assembles in pieces.
pub(crate) struct HmacContext<D>
where
    D: CoreProxy,
    D::Core: HashMarker
        + UpdateCore
        + FixedOutputCore
        + BufferKindUser<BufferKind = Eager>
        + Default
        + Clone,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    #[allow(dead_code)]
    mac: Hmac<D>,
}

impl<D> HmacContext<D>
where
    D: CoreProxy,
    D::Core: HashMarker
        + UpdateCore
        + FixedOutputCore
        + BufferKindUser<BufferKind = Eager>
        + Default
        + Clone,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    /// Start a keyed digest over any key length.
    #[allow(dead_code)]
    pub(crate) fn new(key: &[u8]) -> Self {
        Self {
            mac: <Hmac<D> as Mac>::new_from_slice(key)
                .expect("HMAC accepts every key length: RFC 2104 section 3"),
        }
    }

    /// Feed the next chunk of the message.
    #[allow(dead_code)]
    pub(crate) fn update(&mut self, message: &[u8]) {
        Mac::update(&mut self.mac, message);
    }

    /// Finish and return the keyed digest.
    #[allow(dead_code)]
    pub(crate) fn finish(self) -> Output<Hmac<D>> {
        self.mac.finalize().into_bytes()
    }

    /// Length in bytes of the keyed digest this instantiation produces.
    ///
    /// Derived from the type rather than from a constant, so a caller sizing a
    /// buffer cannot pick a different algorithm's length by mistake -- the
    /// mistake that makes SHA-512/256 and SHA-256 dangerous to conflate.
    #[allow(dead_code)]
    pub(crate) fn output_len() -> usize {
        <Hmac<D> as OutputSizeUser>::output_size()
    }
}

/// `Curl_HMAC_MD5` (`lib/md5.c:528-535`): a 64-byte block, a 16-byte result.
///
/// Consumed by HTTP Digest's `-sess` variants and by the NTLMv2 response.
#[allow(dead_code)]
pub(crate) fn hmac_md5(
    key: &[u8],
    message: &[u8],
) -> [u8; super::md5::DIGEST_LEN] {
    hmac::<Md5>(key, message).into()
}

/// `Curl_HMAC_SHA256` (`lib/sha256.c:468-475`): a 64-byte block, a 32-byte
/// result.
///
/// Consumed by HTTP Digest's SHA-256 variants and by AWS SigV4's signing-key
/// derivation chain.
#[allow(dead_code)]
pub(crate) fn hmac_sha256(
    key: &[u8],
    message: &[u8],
) -> [u8; super::sha256::DIGEST_LEN] {
    hmac::<::sha2::Sha256>(key, message).into()
}

/// `Curl_HMAC_SHA512_256` (`lib/curl_sha512_256.c:788-804`): a **128**-byte
/// block and a 32-byte result.
///
/// The block length is the trap. It is twice SHA-256's while the digest length
/// is identical, so a table that reused 64 here would produce a wrong keyed
/// digest that shows up only as a failed authentication exchange.
#[allow(dead_code)]
pub(crate) fn hmac_sha512_256(
    key: &[u8],
    message: &[u8],
) -> [u8; super::sha512_256::DIGEST_LEN] {
    hmac::<Sha512Trunc256>(key, message).into()
}

#[cfg(test)]
mod tests {
    use super::{hmac_md5, hmac_sha256, hmac_sha512_256, HmacContext};
    use crate::crypto::md5::Md5;

    /// RFC 2202 test case 1 for HMAC-MD5, which is also what
    /// `tests/unit/unit1612.c` asserts against `Curl_HMAC_MD5`.
    #[test]
    fn hmac_md5_matches_rfc_2202_case_1() {
        assert_eq!(
            hmac_md5(&[0x0b; 16], b"Hi There"),
            [
                0x92, 0x94, 0x72, 0x7a, 0x36, 0x38, 0xbb, 0x1c, 0x13, 0xf4,
                0x8e, 0xf8, 0x15, 0x8b, 0xfc, 0x9d
            ]
        );
    }

    /// RFC 2202 test case 2, whose key is shorter than the block and must be
    /// zero-padded rather than rejected.
    #[test]
    fn hmac_md5_zero_pads_a_short_key() {
        assert_eq!(
            hmac_md5(b"Jefe", b"what do ya want for nothing?"),
            [
                0x75, 0x0c, 0x78, 0x3e, 0x6a, 0xb0, 0xb5, 0x03, 0xea, 0xa8,
                0x6e, 0x31, 0x0a, 0x5d, 0xb7, 0x38
            ]
        );
    }

    /// RFC 4231 test case 2 for HMAC-SHA-256.
    #[test]
    fn hmac_sha256_matches_rfc_4231_case_2() {
        assert_eq!(
            hmac_sha256(b"Jefe", b"what do ya want for nothing?"),
            [
                0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04,
                0x24, 0x26, 0x08, 0x95, 0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08,
                0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec,
                0x38, 0x43
            ]
        );
    }

    /// A key longer than the block must be hashed down, not truncated. RFC
    /// 4231 test case 6 uses a 131-byte key against SHA-256's 64-byte block.
    #[test]
    fn hmac_sha256_hashes_an_oversized_key() {
        assert_eq!(
            hmac_sha256(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            ),
            [
                0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f, 0x0d, 0x8a,
                0x26, 0xaa, 0xcb, 0xf5, 0xb7, 0x7f, 0x8e, 0x0b, 0xc6, 0x21,
                0x37, 0x28, 0xc5, 0x14, 0x05, 0x46, 0x04, 0x0f, 0x0e, 0xe3,
                0x7f, 0x54
            ]
        );
    }

    /// The three published instantiations must produce the contracted result
    /// lengths, and SHA-512/256 must not silently share SHA-256's block.
    #[test]
    fn the_three_instantiations_produce_the_contracted_lengths() {
        assert_eq!(hmac_md5(b"k", b"m").len(), 16);
        assert_eq!(hmac_sha256(b"k", b"m").len(), 32);
        assert_eq!(hmac_sha512_256(b"k", b"m").len(), 32);
        assert_ne!(
            hmac_sha256(b"k", b"m").as_slice(),
            hmac_sha512_256(b"k", b"m").as_slice()
        );
    }

    #[test]
    fn incremental_agrees_with_one_shot() {
        let mut ctx = HmacContext::<Md5>::new(&[0x0b; 16]);
        ctx.update(b"Hi ");
        ctx.update(b"There");
        assert_eq!(ctx.finish().as_slice(), hmac_md5(&[0x0b; 16], b"Hi There"));
        assert_eq!(HmacContext::<Md5>::output_len(), 16);
    }
}
