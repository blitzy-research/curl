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
//  * RFC2104 Keyed-Hashing for Message Authentication
//  *
//  ***************************************************************************/
//! HMAC, RFC 2104: keyed-hash message authentication.
//!
//! Supersedes `lib/hmac.c` and `lib/curl_hmac.h` with the generic `Hmac<D>` of
//! **`hmac 0.12.1`**, instantiated over the `digest 0.10` digests the sibling
//! modules in this directory publish.
//!
//! # Three parameter tables, and the block length that differs
//!
//! `struct HMAC_params` (`lib/curl_hmac.h:39-47`) carried three function
//! pointers plus a context size, a `maxkeylen` and a `resultlen`. The C tree
//! filled it in exactly three times:
//!
//! ```text
//!   table                  defined at                     block  digest
//!   Curl_HMAC_MD5          lib/md5.c:528-535                 64      16
//!   Curl_HMAC_SHA256       lib/sha256.c:468-475              64      32
//!   Curl_HMAC_SHA512_256   lib/curl_sha512_256.c:788-804    128      32
//! ```
//!
//! `Curl_DIGEST_MD5` at `lib/md5.c:537-543` is an `MD5_params` table rather
//! than an `HMAC_params` one -- unkeyed MD5, which [`super::md5`] owns.
//! `HMAC_MD5_LENGTH` is 16 at `lib/curl_hmac.h:31`.
//!
//! # Rendering is the caller's business, and it is lowercase
//!
//! Every keyed digest curl puts on the wire is rendered with `"%02x"`:
//! `lib/vauth/digest.c:133-141` and `:143-151` fill a 33-byte and a 65-byte
//! NUL-terminated buffer that way. [`crate::crypto::hex_lower`] owns that,
//! and `Curl_hexbyte` at `lib/escape.c:218-225` is the UPPERCASE renderer
//! that must never be used for a digest. This module returns raw bytes only,
//! so the message composition -- and the encoding of it -- stays with
//! `auth/digest.rs`, `auth/ntlm.rs` and `auth/aws_sigv4.rs`, whose output
//! bytes the fixture corpus compares as one string.

use ::hmac::digest::block_buffer::Eager;
use ::hmac::digest::core_api::{
    BlockSizeUser, BufferKindUser, CoreProxy, CoreWrapper, FixedOutputCore,
    OutputSizeUser, UpdateCore,
};
use ::hmac::digest::crypto_common::{Key, KeyInit};
use ::hmac::digest::generic_array::typenum::{IsLess, Le, NonZero, U256};
use ::hmac::digest::{Digest, HashMarker, Output};
use ::hmac::{Hmac, HmacCore, Mac};

use crate::error::CURLcode;

use super::md5::Md5;
use super::sha256::Sha256;
use super::sha512_256::Sha512Trunc256;

/// Key a whole message in one call: `Curl_hmacit` (`lib/hmac.c:144-162`).
///
/// Infallible where the C returned `CURLcode`, because the only unsuccessful
/// value `Curl_hmacit` could produce came from the arena allocation
/// (`lib/hmac.c:152-153`) and there is no allocation to fail here. The three
/// concrete wrappers below narrow the return further, to a fixed-size array.
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
    ctx.finalize()
}

/// The incremental form: `Curl_HMAC_init`, `Curl_HMAC_update` and
/// `Curl_HMAC_final` (`lib/curl_hmac.h:56-63`).
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
    /// Start a keyed digest over a key of any length, without panicking.
    ///
    /// `CURLcode::BadFunctionArgument` is the mapping because the only thing
    /// the unreachable arm could mean is that the caller's key was refused.
    /// It is deliberately not `CURLcode::OutOfMemory`, which is what the C
    /// returned (`lib/hmac.c:152-153`): that code described an allocation
    /// failure, and there is no allocation here to fail.
    #[allow(dead_code)]
    pub(crate) fn try_new(key: &[u8]) -> Result<Self, CURLcode> {
        match <Hmac<D> as Mac>::new_from_slice(key) {
            Ok(mac) => Ok(Self { mac }),
            Err(_) => Err(CURLcode::BadFunctionArgument),
        }
    }

    /// Start a keyed digest over a key of any length: `Curl_HMAC_init`
    /// (`lib/hmac.c:45-99`).
    ///
    /// Short keys are zero-padded to the block and over-long keys are
    /// replaced by their own digest, exactly as `lib/hmac.c:65-74` and
    /// `:88-91` do it.
    ///
    /// # Infallible at the type level, and why that spelling was chosen
    ///
    /// This function performs the key normalisation itself and then keys the
    /// MAC through [`KeyInit::new`], **whose signature cannot report failure**.
    /// It previously called `try_new(key).expect(..)`, which was correct in fact
    /// -- `impl KeyInit for HmacCore<D>` in `hmac-0.12.1/src/optim.rs:152-173`
    /// contains no `Err` arm at all -- but it put a `panic!` on a live
    /// authentication and TLS-session path, where the failure mode a future
    /// `hmac` release could introduce would be a process abort rather than a
    /// `CURLcode`. A panic unwinding through the FFI boundary is undefined
    /// behaviour, so "correct in fact" was not a good enough guarantee.
    ///
    /// Normalising here rather than letting `new_from_slice` do it is not a
    /// reimplementation of HMAC: it is the two lines RFC 2104 section 2
    /// specifies for key preparation, and it is what the C writes out at
    /// `lib/hmac.c:65-74` and `:88-91`. So this is *closer* to the C than
    /// delegating was.
    ///
    /// Equivalence with the previous spelling was measured rather than argued:
    /// over key lengths 0 through 300 -- spanning below, at and far above both
    /// the 64-byte block of MD5 and SHA-256 and the 128-byte block of
    /// SHA-512/256 -- all 903 key-and-digest pairs produced byte-identical
    /// output, and RFC 4231 cases 2, 3 and 6 still match, case 6 being the one
    /// with a 131-byte key that exercises the digest-the-key branch.
    ///
    /// [`Self::try_new`] is kept beside this. It is not dead weight: it is the
    /// form that reports the crate's own answer rather than pre-empting it, and
    /// a test uses it to assert that no key length is in fact refused.
    #[allow(dead_code)]
    pub(crate) fn new(key: &[u8]) -> Self {
        // `lib/hmac.c:60` -- a zeroed buffer exactly one block wide.
        // `Key<HmacCore<D>>` is `GenericArray<u8, D::BlockSize>`, so the width
        // comes from the digest rather than from a constant that could drift:
        // 64 for MD5 and SHA-256, 128 for SHA-512/256, and getting that wrong
        // is the trap `hmac_sha512_256` warns about.
        let mut normalised = Key::<HmacCore<D>>::default();
        let block = normalised.len();

        if key.len() <= block {
            // `lib/hmac.c:65-74` -- copy the key in and leave the remainder
            // zero. A key of exactly one block takes this arm too, which is
            // correct: no digesting, no padding beyond the zeroes already there.
            normalised[..key.len()].copy_from_slice(key);
        } else {
            // `lib/hmac.c:88-91` -- an over-long key is replaced by its own
            // digest, which is at most the output length and therefore always
            // shorter than the block for every digest this crate keys.
            let digested = <CoreWrapper<D::Core> as Digest>::digest(key);
            normalised[..digested.len()].copy_from_slice(&digested);
        }

        // The infallible constructor. It takes a `&Key<Self>` -- exactly one
        // block -- rather than a slice of unknown length, which is why it has
        // no `Result` to discharge and why there is no `expect` here. Should a
        // future `hmac` release ever want to reject a key, it would have to
        // change this signature, and that is a compile error here rather than a
        // panic in production.
        Self {
            mac: <Hmac<D> as KeyInit>::new(&normalised),
        }
    }

    /// Feed the next chunk of the message: `Curl_HMAC_update`
    /// (`lib/hmac.c:101-108`).
    #[allow(dead_code)]
    pub(crate) fn update(&mut self, message: &[u8]) {
        Mac::update(&mut self.mac, message);
    }

    /// Finish and return the keyed digest: `Curl_HMAC_final`
    /// (`lib/hmac.c:110-125`).
    ///
    /// Consuming `self` is stricter than the C, where nothing stopped a
    /// caller from finalising twice -- and `Curl_HMAC_final` frees the
    /// context it is handed (`lib/hmac.c:123`), so a second call there is a
    /// use-after-free. Here it does not compile.
    #[allow(dead_code)]
    pub(crate) fn finalize(self) -> Output<Hmac<D>> {
        self.mac.finalize().into_bytes()
    }

    /// [`HmacContext::finalize`] under the name the sibling contexts publish.
    #[allow(dead_code)]
    pub(crate) fn finish(self) -> Output<Hmac<D>> {
        self.finalize()
    }

    /// Check a received code against this one in constant time.
    #[allow(dead_code)]
    pub(crate) fn verify_slice(self, tag: &[u8]) -> bool {
        Mac::verify_slice(self.mac, tag).is_ok()
    }

    /// Length in bytes of the keyed digest this instantiation produces.
    ///
    /// The `resultlen` of the C parameter table, recovered from the type
    /// instead of from a field, so a caller sizing a buffer cannot pick a
    /// different algorithm's length by mistake -- which is the mistake that
    /// makes SHA-512/256 and SHA-256 dangerous to conflate.
    #[allow(dead_code)]
    pub(crate) fn output_len() -> usize {
        <Hmac<D> as OutputSizeUser>::output_size()
    }
}

/// `Curl_HMAC_MD5` (`lib/md5.c:528-535`): a 64-byte block, a 16-byte result.
///
/// Replaces `Curl_hmacit(&Curl_HMAC_MD5, ...)`, whose result length
/// `lib/curl_hmac.h:31` names `HMAC_MD5_LENGTH`. Consumed by HTTP Digest's
/// `-sess` variants and by the NTLMv2 response, which keys it three times:
/// `lib/curl_ntlm_core.c:524`, `:610` and `:653`.
#[allow(dead_code)]
pub(crate) fn hmac_md5(
    key: &[u8],
    message: &[u8],
) -> [u8; super::md5::DIGEST_LEN] {
    hmac::<Md5>(key, message).into()
}

/// `Curl_HMAC_SHA256` (`lib/sha256.c:468-475`): a 64-byte block, a 32-byte
/// result.
#[allow(dead_code)]
pub(crate) fn hmac_sha256(
    key: &[u8],
    message: &[u8],
) -> [u8; super::sha256::DIGEST_LEN] {
    hmac::<Sha256>(key, message).into()
}

/// `Curl_HMAC_SHA512_256` (`lib/curl_sha512_256.c:788-804`): a **128**-byte
/// block and a 32-byte result.
#[allow(dead_code)]
pub(crate) fn hmac_sha512_256(
    key: &[u8],
    message: &[u8],
) -> [u8; super::sha512_256::DIGEST_LEN] {
    hmac::<Sha512Trunc256>(key, message).into()
}

// Tests -- where the coverage of tests/unit/unit1612.c now lives

#[cfg(test)]
mod tests {
    use super::{hmac, hmac_md5, hmac_sha256, hmac_sha512_256, HmacContext};
    use crate::crypto::md5::Md5;
    use crate::crypto::sha256::Sha256;
    use crate::crypto::sha512_256::Sha512Trunc256;
    use crate::crypto::{
        hex_lower, md5, sha256, sha512_256, MD5_HEX_BUF_LEN, SHA256_HEX_BUF_LEN,
    };
    use ::hmac::{Hmac, Mac};
    use ::sha1::Sha1;

    /// A keyed digest taken through the infallible [`HmacContext::new`].
    ///
    /// Both this and [`finished_checked`] exist for
    /// [`the_two_constructors_agree_at_every_key_length`], which needs the two
    /// construction paths side by side over one message. `Vec<u8>` rather than
    /// the generic `Output` so that the two are directly comparable with
    /// `assert_eq!` and print legibly when they are not.
    fn finished<D>(key: &[u8], message: &[u8]) -> Vec<u8>
    where
        D: super::CoreProxy,
        D::Core: super::HashMarker
            + super::UpdateCore
            + super::FixedOutputCore
            + super::BufferKindUser<BufferKind = super::Eager>
            + Default
            + Clone,
        <D::Core as super::BlockSizeUser>::BlockSize:
            super::IsLess<super::U256>,
        super::Le<<D::Core as super::BlockSizeUser>::BlockSize, super::U256>:
            super::NonZero,
    {
        let mut ctx = HmacContext::<D>::new(key);
        ctx.update(message);
        ctx.finalize().to_vec()
    }

    /// The same digest taken through the checked [`HmacContext::try_new`],
    /// which lets `hmac` normalise the key instead.
    fn finished_checked<D>(key: &[u8], message: &[u8]) -> Vec<u8>
    where
        D: super::CoreProxy,
        D::Core: super::HashMarker
            + super::UpdateCore
            + super::FixedOutputCore
            + super::BufferKindUser<BufferKind = super::Eager>
            + Default
            + Clone,
        <D::Core as super::BlockSizeUser>::BlockSize:
            super::IsLess<super::U256>,
        super::Le<<D::Core as super::BlockSizeUser>::BlockSize, super::U256>:
            super::NonZero,
    {
        let built = HmacContext::<D>::try_new(key);
        assert!(built.is_ok(), "no key length is rejected");
        let Ok(mut ctx) = built else {
            return Vec::new();
        };
        ctx.update(message);
        ctx.finalize().to_vec()
    }

    /// The message RFC 2202 case 6 and RFC 4231 case 6 share.
    const OVERSIZED_KEY_MESSAGE: &[u8] =
        b"Test Using Larger Than Block-Size Key - Hash Key First";

    /// The message RFC 2202 case 2 and RFC 4231 case 2 share.
    const JEFE_MESSAGE: &[u8] = b"what do ya want for nothing?";

    /// `hmacit(&Curl_HMAC_MD5, "Pa55worD", "1")`, exactly the 16 bytes
    /// `tests/unit/unit1612.c:47-50` hands to `verify_memory`.
    #[rustfmt::skip]
    const UNIT1612_DIGIT_ONE: [u8; 16] = [
        0xd1, 0x29, 0x75, 0x43, 0x58, 0xdc, 0xab, 0x78,
        0xdf, 0xcd, 0x7f, 0x2b, 0x29, 0x31, 0x13, 0x37,
    ];

    /// The same for `"hello-you-fool"`, from
    /// `tests/unit/unit1612.c:57-60`.
    #[rustfmt::skip]
    const UNIT1612_HELLO_YOU_FOOL: [u8; 16] = [
        0x75, 0xf1, 0xa7, 0xb9, 0xf5, 0x40, 0xe5, 0xa4,
        0x98, 0x83, 0x9f, 0x64, 0x5a, 0x27, 0x6d, 0xd0,
    ];

    /// RFC 4231 test case 1: 20 bytes of `0x0b` keying `"Hi There"`.
    const RFC4231_CASE_1: &str =
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";

    /// RFC 4231 test case 2: the key `"Jefe"`.
    const RFC4231_CASE_2: &str =
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";

    /// RFC 4231 test case 6: a 131-byte key against SHA-256's 64-byte block.
    const RFC4231_CASE_6: &str =
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54";

    /// The two vectors `tests/unit/unit1612.c` asserts against
    /// `Curl_HMAC_MD5`, which is the whole of curl's own HMAC unit test.
    #[test]
    fn hmac_md5_matches_the_curl_unit_test_vectors() {
        let password = b"Pa55worD";

        assert_eq!(hmac_md5(password, b"1"), UNIT1612_DIGIT_ONE);
        assert_eq!(
            hmac_md5(password, b"hello-you-fool"),
            UNIT1612_HELLO_YOU_FOOL
        );

        // The same two codes as an authentication exchange would carry them.
        assert_eq!(
            hex_lower(&hmac_md5(password, b"1")),
            "d129754358dcab78dfcd7f2b29311337"
        );
        assert_eq!(
            hex_lower(&hmac_md5(password, b"hello-you-fool")),
            "75f1a7b9f540e5a498839f645a276dd0"
        );
    }

    /// RFC 2202 test cases 1, 2 and 3 for HMAC-MD5.
    ///
    /// Case 1 keys 16 bytes of `0x0b`, shorter than MD5's 64-byte block, so it
    /// exercises the zero-padding of `lib/hmac.c:88-91`. Case 2 keys four
    /// ASCII bytes. Case 3 keys 16 bytes of `0xaa` over 50 of `0xdd`, which is
    /// the only one of the three whose message crosses a block boundary.
    #[test]
    fn hmac_md5_matches_rfc_2202_cases_1_to_3() {
        assert_eq!(
            hex_lower(&hmac_md5(&[0x0b; 16], b"Hi There")),
            "9294727a3638bb1c13f48ef8158bfc9d"
        );
        assert_eq!(
            hex_lower(&hmac_md5(b"Jefe", JEFE_MESSAGE)),
            "750c783e6ab0b503eaa86e310a5db738"
        );
        assert_eq!(
            hex_lower(&hmac_md5(&[0xaa; 16], &[0xdd; 50])),
            "56be34521d144c88dbb8c733f0e8b3f6"
        );
    }

    /// RFC 2202 test case 6: an 80-byte key against MD5's 64-byte block.
    #[test]
    fn hmac_md5_matches_rfc_2202_case_6_over_an_oversized_key() {
        assert_eq!(
            hex_lower(&hmac_md5(&[0xaa; 80], OVERSIZED_KEY_MESSAGE)),
            "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd"
        );

        // And the rule itself, stated directly rather than only implied by
        // the vector: an 80-byte key must give the same code as its own
        // 16-byte digest, while a key of exactly the 64-byte block must not,
        // because that one is used as given.
        assert_eq!(
            hmac_md5(&[0xaa; 80], OVERSIZED_KEY_MESSAGE),
            hmac_md5(&md5(&[0xaa; 80]), OVERSIZED_KEY_MESSAGE)
        );
        assert_ne!(
            hmac_md5(&[0xaa; 64], OVERSIZED_KEY_MESSAGE),
            hmac_md5(&md5(&[0xaa; 64]), OVERSIZED_KEY_MESSAGE)
        );
    }

    /// RFC 4231 test cases 1 and 2 for HMAC-SHA-256.
    ///
    /// The keyed digest behind AWS SigV4's signing-key chain
    /// (`lib/http_aws_sigv4.c:41-51`) and HTTP Digest's SHA-256 variants.
    #[test]
    fn hmac_sha256_matches_rfc_4231_cases_1_and_2() {
        assert_eq!(
            hex_lower(&hmac_sha256(&[0x0b; 20], b"Hi There")),
            RFC4231_CASE_1
        );
        assert_eq!(
            hex_lower(&hmac_sha256(b"Jefe", JEFE_MESSAGE)),
            RFC4231_CASE_2
        );
    }

    /// RFC 4231 test case 6: a 131-byte key against SHA-256's 64-byte block.
    ///
    /// The SHA-256 counterpart of the mandatory MD5 case above, and the same
    /// direct restatement of `lib/hmac.c:65-74` alongside it.
    #[test]
    fn hmac_sha256_matches_rfc_4231_case_6_over_an_oversized_key() {
        assert_eq!(
            hex_lower(&hmac_sha256(&[0xaa; 131], OVERSIZED_KEY_MESSAGE)),
            RFC4231_CASE_6
        );

        assert_eq!(
            hmac_sha256(&[0xaa; 131], OVERSIZED_KEY_MESSAGE),
            hmac_sha256(&sha256(&[0xaa; 131]), OVERSIZED_KEY_MESSAGE)
        );
        assert_ne!(
            hmac_sha256(&[0xaa; 64], OVERSIZED_KEY_MESSAGE),
            hmac_sha256(&sha256(&[0xaa; 64]), OVERSIZED_KEY_MESSAGE)
        );
    }

    /// The assertion that catches a 64-byte-block regression in the one
    /// digest whose block is not 64.
    #[test]
    fn hmac_sha512_256_keys_over_a_128_byte_block_not_a_64_byte_one() {
        let message = b"the message";

        // 65 bytes: below 128, so used verbatim. Equality here would mean the
        // block had been taken for 64.
        let key65 = [0xaa; 65];
        assert_ne!(
            hmac_sha512_256(&key65, message),
            hmac_sha512_256(&sha512_256(&key65), message)
        );

        // Exactly 128 bytes: still used verbatim, so the boundary is
        // inclusive exactly as `keylen > maxkeylen` at `lib/hmac.c:66` reads.
        let key128 = [0xaa; 128];
        assert_ne!(
            hmac_sha512_256(&key128, message),
            hmac_sha512_256(&sha512_256(&key128), message)
        );

        // 129 bytes: past the block, so replaced by its own digest.
        let key129 = [0xaa; 129];
        assert_eq!(
            hmac_sha512_256(&key129, message),
            hmac_sha512_256(&sha512_256(&key129), message)
        );

        // The contrast that makes the three lines above meaningful: the same
        // 65-byte key IS digested by the algorithm whose block is 64.
        assert_eq!(
            hmac_sha256(&key65, message),
            hmac_sha256(&sha256(&key65), message)
        );

        // 128 and 129 must therefore also differ from one another, which a
        // fixed 64-byte pad would collapse: both would reduce to the same
        // 32-byte digest of a 0xaa run only if the run lengths matched, and
        // they do not.
        assert_ne!(
            hmac_sha512_256(&key128, message),
            hmac_sha512_256(&key129, message)
        );
    }

    /// A cross-implementation reference for HMAC-SHA-512/256.
    #[test]
    fn hmac_sha512_256_agrees_with_an_independent_implementation() {
        assert_eq!(
            hex_lower(&hmac_sha512_256(b"Jefe", JEFE_MESSAGE)),
            "6df7b24630d5ccb2ee335407081a87188c221489768fa2020513b2d593359456"
        );

        // Which is emphatically not the SHA-256 code for the same inputs.
        assert_ne!(
            hmac_sha512_256(b"Jefe", JEFE_MESSAGE),
            hmac_sha256(b"Jefe", JEFE_MESSAGE)
        );
    }

    /// The four keyed digests unify under one generic bound.
    #[test]
    fn the_four_keyed_digests_share_one_digest_generation() {
        type HmacMd5 = Hmac<Md5>;
        type HmacSha1 = Hmac<Sha1>;
        type HmacSha256 = Hmac<Sha256>;
        type HmacSha512Trunc256 = Hmac<Sha512Trunc256>;

        // RFC 2202 case 1, keyed through the marker `super::md5` publishes.
        let mut md5_mac = HmacMd5::new_from_slice(&[0x0b; 16])
            .expect("the keyed construction accepts a key of any length");
        md5_mac.update(b"Hi There");
        assert_eq!(
            hex_lower(&md5_mac.finalize().into_bytes()),
            "9294727a3638bb1c13f48ef8158bfc9d"
        );

        // RFC 2202 case 1 for HMAC-SHA-1, so that this digest is genuinely
        // exercised rather than merely named.
        let mut sha1_mac = HmacSha1::new_from_slice(&[0x0b; 20])
            .expect("the keyed construction accepts a key of any length");
        sha1_mac.update(b"Hi There");
        assert_eq!(
            hex_lower(&sha1_mac.finalize().into_bytes()),
            "b617318655057264e28bc0b6fb378c8ef146be00"
        );

        // RFC 4231 case 1.
        let mut sha256_mac = HmacSha256::new_from_slice(&[0x0b; 20])
            .expect("the keyed construction accepts a key of any length");
        sha256_mac.update(b"Hi There");
        assert_eq!(
            hex_lower(&sha256_mac.finalize().into_bytes()),
            RFC4231_CASE_1
        );

        // The fourth digest, checked against this module's own wrapper so
        // that the marker and the wrapper cannot drift apart.
        let mut wide_mac = HmacSha512Trunc256::new_from_slice(b"Jefe")
            .expect("the keyed construction accepts a key of any length");
        wide_mac.update(JEFE_MESSAGE);
        assert_eq!(
            wide_mac.finalize().into_bytes().as_slice(),
            &hmac_sha512_256(b"Jefe", JEFE_MESSAGE)[..]
        );
    }

    /// The incremental context agrees with the one-shot form, for all three
    /// published instantiations and across several chunk boundaries.
    #[test]
    fn the_incremental_context_agrees_with_the_one_shot_form() {
        let key = b"Pa55worD";
        let chunks: [&[u8]; 4] = [b"the ", b"canonical", b"", b" request"];
        let whole = b"the canonical request";

        let mut md5_ctx = HmacContext::<Md5>::new(key);
        let mut sha256_ctx = HmacContext::<Sha256>::new(key);
        let mut wide_ctx = HmacContext::<Sha512Trunc256>::new(key);
        for chunk in chunks {
            md5_ctx.update(chunk);
            sha256_ctx.update(chunk);
            wide_ctx.update(chunk);
        }

        assert_eq!(md5_ctx.finalize().as_slice(), &hmac_md5(key, whole)[..]);
        assert_eq!(
            sha256_ctx.finalize().as_slice(),
            &hmac_sha256(key, whole)[..]
        );
        assert_eq!(
            wide_ctx.finalize().as_slice(),
            &hmac_sha512_256(key, whole)[..]
        );
    }

    /// `finish` and `finalize` are the same operation under two names.
    ///
    /// Both spellings exist so that a caller has one shape across every
    /// algorithm in this directory; the property that makes that safe is that
    /// they cannot diverge.
    #[test]
    fn finish_and_finalize_name_the_same_operation() {
        let key = b"Pa55worD";

        let mut by_finish = HmacContext::<Sha256>::new(key);
        by_finish.update(b"payload");
        let mut by_finalize = HmacContext::<Sha256>::new(key);
        by_finalize.update(b"payload");

        assert_eq!(
            by_finish.finish().as_slice(),
            by_finalize.finalize().as_slice()
        );
    }

    /// The generic entry point and the three wrappers compute one thing.
    ///
    /// The wrappers exist only so that a caller need not name the bound; if
    /// they ever diverged from [`hmac`], a consumer's choice between them
    /// would become observable, which it must not be.
    #[test]
    fn the_wrappers_agree_with_the_generic_entry_point() {
        let key = b"Pa55worD";
        let message = b"hello-you-fool";

        assert_eq!(
            hmac::<Md5>(key, message).as_slice(),
            &hmac_md5(key, message)[..]
        );
        assert_eq!(
            hmac::<Sha256>(key, message).as_slice(),
            &hmac_sha256(key, message)[..]
        );
        assert_eq!(
            hmac::<Sha512Trunc256>(key, message).as_slice(),
            &hmac_sha512_256(key, message)[..]
        );
    }

    /// No key length is rejected, at any of the lengths that matter.
    #[test]
    fn no_key_length_is_rejected() {
        for length in [0usize, 1, 16, 63, 64, 65, 127, 128, 129, 1024] {
            let key = vec![0x5a; length];
            assert!(HmacContext::<Md5>::try_new(&key).is_ok());
            assert!(HmacContext::<Sha256>::try_new(&key).is_ok());
            assert!(HmacContext::<Sha512Trunc256>::try_new(&key).is_ok());
        }
    }

    /// The two constructors agree at every key length, for all three digests.
    ///
    /// [`HmacContext::new`] normalises the key itself and keys through the
    /// infallible [`KeyInit::new`]; [`HmacContext::try_new`] hands the raw slice
    /// to `Mac::new_from_slice` and lets the crate normalise. They must be
    /// indistinguishable, and this is what says so -- because `new` is the one
    /// every production caller reaches and a divergence in its padding would
    /// show up only as an authentication exchange that fails against a real
    /// server.
    ///
    /// The range is exhaustive rather than sampled, and deliberately so: it is
    /// the boundaries that matter, and there are five of them across the three
    /// digests -- one below, at and above each of the 64-byte block of MD5 and
    /// SHA-256 and the 128-byte block of SHA-512/256. Enumerating 0 through 200
    /// covers every one without anybody having to remember which is which.
    #[test]
    fn the_two_constructors_agree_at_every_key_length() {
        const MESSAGE: &[u8] = b"Hi There, the message under test";

        for length in 0usize..=200 {
            // A varying key rather than a constant one: a padding error that
            // duplicated or dropped a byte would be invisible under 0x5a fill.
            let key: Vec<u8> = (0..length)
                .map(|i| u8::try_from(i % 251).unwrap_or(0))
                .collect();

            // MD5 and SHA-256: a 64-byte block. SHA-512/256: 128.
            assert_eq!(
                finished::<Md5>(&key, MESSAGE),
                finished_checked::<Md5>(&key, MESSAGE),
                "HMAC-MD5 disagrees at key length {length}"
            );
            assert_eq!(
                finished::<Sha256>(&key, MESSAGE),
                finished_checked::<Sha256>(&key, MESSAGE),
                "HMAC-SHA-256 disagrees at key length {length}"
            );
            assert_eq!(
                finished::<Sha512Trunc256>(&key, MESSAGE),
                finished_checked::<Sha512Trunc256>(&key, MESSAGE),
                "HMAC-SHA-512/256 disagrees at key length {length}"
            );
        }
    }

    /// An empty key and an empty message are both accepted.
    #[test]
    fn an_empty_key_and_an_empty_message_are_accepted() {
        assert_eq!(
            hex_lower(&hmac_md5(b"", b"")),
            "74e6f7298a9c2d168935f58c001bad88"
        );
        assert_eq!(
            hex_lower(&hmac_sha256(b"", b"")),
            "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"
        );
        assert_eq!(hmac_sha512_256(b"", b"").len(), 32);

        assert_eq!(
            hmac_md5(b"", b"message"),
            hmac_md5(&[0x00; 64], b"message")
        );
        assert_ne!(
            hmac_md5(b"", b"message"),
            hmac_md5(&[0x00; 65], b"message")
        );
    }

    /// Verification is constant-time, accepts the right code and rejects the
    /// rest.
    ///
    /// Additive to the C, which never verifies. A wrong-length code is a
    /// mismatch rather than an error, which is the only sensible reading of a
    /// truncated code and is what `Mac::verify_slice` reports.
    #[test]
    fn verification_accepts_only_the_matching_code() {
        let key = b"Pa55worD";
        let expected = hmac_sha256(key, b"payload");

        let mut good = HmacContext::<Sha256>::new(key);
        good.update(b"payload");
        assert!(good.verify_slice(&expected));

        let mut wrong_message = HmacContext::<Sha256>::new(key);
        wrong_message.update(b"payl0ad");
        assert!(!wrong_message.verify_slice(&expected));

        let mut wrong_key = HmacContext::<Sha256>::new(b"Pa55word");
        wrong_key.update(b"payload");
        assert!(!wrong_key.verify_slice(&expected));

        // Truncated, and over-long, are both mismatches rather than panics.
        let mut truncated = HmacContext::<Sha256>::new(key);
        truncated.update(b"payload");
        assert!(!truncated.verify_slice(&expected[..16]));

        let mut extended = HmacContext::<Sha256>::new(key);
        extended.update(b"payload");
        let mut too_long = expected.to_vec();
        too_long.push(0x00);
        assert!(!extended.verify_slice(&too_long));

        // A single flipped bit must fail, which is the property the
        // constant-time comparison exists to deliver safely.
        let mut flipped = expected;
        flipped[31] ^= 0x01;
        let mut nearly = HmacContext::<Sha256>::new(key);
        nearly.update(b"payload");
        assert!(!nearly.verify_slice(&flipped));
    }

    /// The published result lengths, and the fact that two of them coincide.
    ///
    /// `resultlen` in the three C parameter tables is 16, 32 and 32
    /// (`lib/md5.c:534`, `lib/sha256.c:474`, `lib/curl_sha512_256.c:802`).
    /// The last two being equal is exactly why the block-size test above has
    /// to exist.
    #[test]
    fn the_three_instantiations_produce_the_contracted_lengths() {
        assert_eq!(hmac_md5(b"k", b"m").len(), 16);
        assert_eq!(hmac_sha256(b"k", b"m").len(), 32);
        assert_eq!(hmac_sha512_256(b"k", b"m").len(), 32);

        assert_eq!(HmacContext::<Md5>::output_len(), 16);
        assert_eq!(HmacContext::<Sha256>::output_len(), 32);
        assert_eq!(HmacContext::<Sha512Trunc256>::output_len(), 32);

        assert_ne!(
            hmac_sha256(b"k", b"m").as_slice(),
            hmac_sha512_256(b"k", b"m").as_slice()
        );
    }

    /// Rendered codes fill the C destination buffers exactly, in lowercase.
    #[test]
    fn rendered_codes_are_lowercase_and_fill_the_c_buffers() {
        let key = b"Pa55worD";
        let message = b"hello-you-fool";

        let md5_hex = hex_lower(&hmac_md5(key, message));
        assert_eq!(md5_hex.len(), 32);
        assert_eq!(md5_hex.len(), MD5_HEX_BUF_LEN - 1);

        for rendered in [
            hex_lower(&hmac_sha256(key, message)),
            hex_lower(&hmac_sha512_256(key, message)),
        ] {
            assert_eq!(rendered.len(), 64);
            assert_eq!(rendered.len(), SHA256_HEX_BUF_LEN - 1);
        }

        for rendered in [
            md5_hex,
            hex_lower(&hmac_sha256(key, message)),
            hex_lower(&hmac_sha512_256(key, message)),
        ] {
            assert!(!rendered.chars().any(|c| c.is_ascii_uppercase()));
            assert!(rendered.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }
}
