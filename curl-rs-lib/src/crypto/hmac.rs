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
//! Supersedes `lib/hmac.c` (164 lines) and `lib/curl_hmac.h` (72 lines) with
//! the generic `Hmac<D>` of **`hmac 0.12.1`**, instantiated over the
//! `digest 0.10` digests the sibling modules in this directory publish.
//!
//! Every claim below carries a `path:line` citation, because the behaviour
//! being preserved is defined by those files and not by this description.
//!
//! # The C is textbook RFC 2104, which is what makes the swap byte-exact
//!
//! `lib/hmac.c:42-99` is the entire algorithm, and reading it end to end
//! shows no curl-specific deviation of any kind:
//!
//! * `lib/hmac.c:42-43` fixes the inner and outer pads at `0x36` and `0x5C`.
//! * `lib/hmac.c:65-74` replaces a key longer than the parameter table's
//!   `maxkeylen` by its own digest -- RFC 2104 section 2's over-long-key rule.
//! * `lib/hmac.c:81-86` primes the two hash contexts with `key[i] ^ 0x36` and
//!   `key[i] ^ 0x5C`, one byte per call.
//! * `lib/hmac.c:88-91` feeds the bare pad byte for the remainder of the
//!   block, which is how a key shorter than the block is zero-padded.
//! * `lib/hmac.c:110-125` finalises the inner context, feeds that digest to
//!   the outer one, and finalises that.
//!
//! `hmac 0.12.1` performs those same five steps, and the correspondence is
//! checkable rather than assumed: `hmac-0.12.1/src/lib.rs:105-106` declares
//! `IPAD = 0x36` and `OPAD = 0x5C`, and its `get_der_key` copies a key of at
//! most one block verbatim into a zeroed block while replacing a longer one
//! by `D::digest(key)` -- `lib/hmac.c:65-74` and `:88-91` in one function.
//! The conclusion is therefore evidenced and not merely hoped for: the crate
//! is a byte-exact drop-in. The pads appear in this file only as
//! documentation. **The crate owns the padding; nothing here reimplements
//! it.**
//!
//! # Who needs HMAC, from the C's own compile guard
//!
//! `lib/hmac.c:28-30` guards the whole translation unit on
//! `(USE_CURL_NTLM_CORE && !USE_WINDOWS_SSPI) || !CURL_DISABLE_AWS ||
//! !CURL_DISABLE_DIGEST_AUTH || USE_SSL`, so the consumer set is NTLM, AWS
//! SigV4, HTTP Digest and TLS. (`lib/curl_hmac.h:27-29` repeats the guard
//! with `USE_LIBSSH2` added, for the SSH transport.) The call sites are
//! concrete: `lib/curl_ntlm_core.c:524`, `:610` and `:653` key MD5 for the
//! NTLMv2 response; `lib/http_aws_sigv4.c:41-51` wraps
//! `Curl_hmacit(&Curl_HMAC_SHA256, ...)` in an `HMAC_SHA256` macro that drives
//! the whole signing-key derivation chain; and `lib/vtls/vtls_scache.c:656`,
//! `:1009` and `:1048` key SHA-256 for the TLS session cache, which is what
//! the guard's `USE_SSL` arm is there for.
//!
//! That guard is deliberately NOT reproduced as a Cargo feature. HMAC is
//! compiled unconditionally, and no `#[cfg]` appears anywhere in this file --
//! a `cfg` naming a feature this workspace does not declare would compile
//! authentication away in silence.
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
//! That 64-against-128 divergence is why `Hmac<D>` has to be generic rather
//! than hard-coded, and it is the one mistake in this area that is invisible:
//! the two digest lengths are identical, so an implementation with a fixed
//! 64-byte pad would produce a well-formed but wrong HMAC-SHA-512/256 and
//! surface only as a failed authentication exchange.
//! `CURL_SHA512_256_BLOCK_SIZE` is 128 at `lib/curl_sha512_256.c:83`, and
//! `hmac 0.12.1` derives the length from `D::BlockSize`, so no site in this
//! file names a block length at all.
//!
//! `Curl_DIGEST_MD5` at `lib/md5.c:537-543` is an `MD5_params` table rather
//! than an `HMAC_params` one -- unkeyed MD5, which [`super::md5`] owns.
//! `HMAC_MD5_LENGTH` is 16 at `lib/curl_hmac.h:31`.
//!
//! # The vtable is dropped; generics replace it
//!
//! `struct HMAC_params` and `struct HMAC_context` (`lib/curl_hmac.h:49-54`)
//! exist to make the hash pluggable across seven TLS backends through
//! untyped `void *` contexts. Rust expresses the same intent with
//! compile-time dispatch, so neither struct survives and no untyped context
//! pointer remains. `Curl_HMAC_init` / `_update` / `_final`
//! (`lib/curl_hmac.h:56-63`) become [`HmacContext`], and `Curl_hmacit`
//! (`lib/hmac.c:144-162`) becomes [`hmac`] with three concrete wrappers over
//! it -- one per surviving parameter table.
//!
//! Three C artefacts are deliberately not reproduced, because buffer
//! management is the type system's responsibility here and performance is an
//! explicit non-goal: the single-allocation arena at `lib/hmac.c:55-63`,
//! which laid two hash contexts and a digest scratch out inside one `malloc`
//! and then indexed into it by pointer arithmetic; the
//! one-byte-per-call `hupdate` loop; and the `curlx_free` at
//! `lib/hmac.c:123`. `Curl_HMAC_update` and `Curl_HMAC_final` return `int`
//! only because their signatures had to match a function pointer -- both
//! unconditionally return 0 (`lib/hmac.c:107`, `:124`) -- so the Rust
//! equivalents are infallible and return nothing to check.
//!
//! # `digest 0.10` coherence is proven here
//!
//! `Hmac<D>` is the only construct in this workspace that must unify several
//! different digest types under one generic bound, which makes this file the
//! concrete site of the coherence requirement the manifests describe. The
//! newest-release set would have put `digest 0.10` and `digest 0.11` in one
//! graph, and `Hmac<Sha1>` would then not compile, because `Mac` and `Digest`
//! would come from different crates. Three things hold the line: the
//! workspace manifest pins the whole RustCrypto family to one generation,
//! `deny.toml` denies `digest >= 0.11.0` outright, and the test module below
//! instantiates `Hmac<Md5>`, `Hmac<Sha1>`, `Hmac<Sha256>` and
//! `Hmac<Sha512Trunc256>` in a single scope so that the compiler holds the
//! same guarantee. `hmac 0.13.0` must not be used: it declares a minimum
//! supported Rust version of 1.85 against this workspace's floor of 1.75, and
//! it is bound to `digest 0.11`.
//!
//! # The bound is written out rather than abbreviated
//!
//! `hmac 0.12.1` expresses "an eager, fixed-output block hash" through five
//! separate `digest` core traits plus two type-level comparisons
//! (`hmac-0.12.1/src/optim.rs:20-31`), and it publishes no trait alias for
//! the combination. Emulating one with a blanket-implemented local trait
//! would add a layer whose elaboration rules are subtler than the clause it
//! replaces, so the clause is repeated verbatim at each of the three sites
//! that need it. Verbosity here is preferable to a construct a reader has to
//! reason about.
//!
//! # No key length is rejected
//!
//! `Mac::new_from_slice` returns a `Result`, and for `Hmac<D>` the error arm
//! is structurally unreachable: `impl KeyInit for HmacCore<D>` in
//! `hmac-0.12.1/src/optim.rs` ends in `Ok(..)` and has no other return. The C
//! could not reject a key length either -- `Curl_HMAC_init`'s only failure
//! was the arena allocation at `lib/hmac.c:56-59`, which `Curl_hmacit`
//! reported as `CURLE_OUT_OF_MEMORY` at `lib/hmac.c:152-153`, and that
//! failure mode does not survive the port. Both spellings are therefore
//! published: [`HmacContext::try_new`] is total and maps the unreachable arm
//! to `CURLcode::BadFunctionArgument`, and [`HmacContext::new`] is
//! infallible.
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
//!
//! # Gates
//!
//! Each pattern carries a character class on its first letter so that these
//! comment lines cannot match themselves and the gates stay runnable against
//! this file.
//!
//! ```sh
//! # The pads and the padding loop belong to the crate. Every hit must be a
//! # comment, never a reimplementation.
//! grep -n '0x36\|0x5C\|[i]pad\|[o]pad' curl-rs-lib/src/crypto/hmac.rs
//!
//! # The 25-line banner, whose 23rd line is the algorithm credit that the
//! # 23-line sibling banners do not carry. Must print 1; a 0 means a
//! # sibling's banner was copied.
//! grep -c 'RFC2104 Keyed-Hashing for Message Authent[i]cation' \
//!   curl-rs-lib/src/crypto/hmac.rs
//!
//! # One copyright holder, and not the ones that belong to sha256.rs and
//! # sha512_256.rs. Must print 1, then 0.
//! grep -c 'Daniel Sten[b]erg' curl-rs-lib/src/crypto/hmac.rs
//! grep -c 'Florin Petri[u]c\|Evgeny Gr[i]n' curl-rs-lib/src/crypto/hmac.rs
//!
//! # There is no production SHA-1 wrapper anywhere in this workspace: curl
//! # has no SHA-1 module at all. Every hit must sit under #[cfg(test)].
//! grep -n '[s]ha1' curl-rs-lib/src/crypto/hmac.rs
//!
//! # This file adds no exemption to the crate-root safety attribute, and
//! # names no C scalar width. Both must print nothing.
//! grep -nE '[u]nsafe' curl-rs-lib/src/crypto/hmac.rs
//! grep -nE '[c]_int|[c]_uint|[c]_long' curl-rs-lib/src/crypto/hmac.rs
//! ```

use ::hmac::digest::block_buffer::Eager;
use ::hmac::digest::core_api::{
    BlockSizeUser, BufferKindUser, CoreProxy, FixedOutputCore, OutputSizeUser,
    UpdateCore,
};
use ::hmac::digest::generic_array::typenum::{IsLess, Le, NonZero, U256};
use ::hmac::digest::{HashMarker, Output};
use ::hmac::{Hmac, Mac};

use crate::error::CURLcode;

use super::md5::Md5;
use super::sha256::Sha256;
use super::sha512_256::Sha512Trunc256;

/// Key a whole message in one call: `Curl_hmacit` (`lib/hmac.c:144-162`).
///
/// The C `Curl_HMAC_init` / `_update` / `_final` sequence collapsed, which is
/// how nearly every call site in the C tree actually used it. Of the header's
/// four entry points this is the one with in-scope callers:
/// `lib/http_aws_sigv4.c`, `lib/curl_ntlm_core.c` and `lib/vtls/vtls_scache.c`
/// all reach for it, and the incremental trio has exactly one caller anywhere
/// in the tree -- `lib/vauth/cram.c:59-71`, which is out of scope because
/// CRAM-MD5 serves the stubbed mail protocols. [`HmacContext`] is nonetheless
/// published, for the reasons recorded on it.
///
/// Infallible where the C returned `CURLcode`, because the only unsuccessful
/// value `Curl_hmacit` could produce came from the arena allocation
/// (`lib/hmac.c:152-153`) and there is no allocation to fail here. The three
/// concrete wrappers below narrow the return further, to a fixed-size array.
///
/// The allowance below is an inventory entry rather than a suppression: the
/// consumers are `auth/digest.rs`, `auth/ntlm.rs` and `auth/aws_sigv4.rs`,
/// none of which has landed. It is deleted when the first one calls this.
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
///
/// AWS SigV4 is the caller that needs it, because it keys a canonical request
/// it assembles in pieces rather than a message it already holds whole. It
/// also completes the pair that [`super::md5::Md5Context`] and
/// [`super::sha256::Sha256Context`] publish, so that a caller streaming a
/// digest has one shape whether or not the digest is keyed.
///
/// One field replaces the whole of `struct HMAC_context`
/// (`lib/curl_hmac.h:49-54`), whose three members were a pointer to the
/// parameter table and two untyped hash contexts. The table is the type
/// parameter now, and both hash states live inside `Hmac<D>`: an inner hasher
/// primed with the inner pad and an outer one primed with the outer pad,
/// exactly the pair `lib/hmac.c:81-91` builds. Routing the message to the
/// inner one and the inner digest to the outer one is the crate's business,
/// so nothing here has to remember which of the two to feed -- which is what
/// the untyped `void *` members of the C struct existed to let it do by hand.
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
    /// The total form, and the one a caller that must not panic should reach
    /// for. It cannot actually report a failure -- see [`HmacContext::new`] --
    /// but it discharges the `Result` that `Mac::new_from_slice` returns
    /// without discarding it, and it does so in the crate's own error
    /// vocabulary rather than leaking `hmac`'s `InvalidLength`.
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
    /// `:88-91` do it. The crate performs both; nothing here does.
    #[allow(dead_code)]
    pub(crate) fn new(key: &[u8]) -> Self {
        // The arm resolved here cannot be taken, and the claim is checkable
        // rather than asserted: `impl KeyInit for HmacCore<D>` in
        // hmac-0.12.1/src/optim.rs ends in `Ok(..)` and has no other return,
        // and `lib/hmac.c:56-70` likewise contains no path that rejects a key
        // -- its sole failure was the arena allocation, which does not
        // survive the port.
        //
        // Resolving it by keying with anything else would silently produce a
        // wrong authentication code should it ever become reachable, which
        // for a security primitive is strictly worse than stopping. So this
        // stops, loudly, and `try_new` above is the total form for a caller
        // that wants one.
        Self::try_new(key).expect("no key length is rejected: lib/hmac.c:56-70")
    }

    /// Feed the next chunk of the message: `Curl_HMAC_update`
    /// (`lib/hmac.c:101-108`).
    ///
    /// Any number of calls in any chunking; the code depends only on the
    /// concatenation of everything fed. The C narrowed a `size_t` to an
    /// `unsigned int` to reach this call (`lib/hmac.c:156`); the Rust length
    /// is a `usize` end to end and that narrowing is not reintroduced.
    ///
    /// The C returned `int` here purely so its signature matched a function
    /// pointer, and it returned 0 unconditionally (`lib/hmac.c:107`), so
    /// there is nothing for a caller to check.
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
    ///
    /// Both spellings exist deliberately, and all three incremental contexts
    /// in this directory carry the pair: `finalize` is what the `digest`
    /// traits call the operation, and [`super::md5::Md5Context`] and
    /// [`super::sha256::Sha256Context`] both also answer to `finish`. The
    /// promise that a caller has one shape for every algorithm holds only if
    /// the terminal method answers to the same name everywhere, so rather
    /// than break one of the two contracts both names do the same work.
    #[allow(dead_code)]
    pub(crate) fn finish(self) -> Output<Hmac<D>> {
        self.finalize()
    }

    /// Check a received code against this one in constant time.
    ///
    /// Additive: the C has no verification path at all. `lib/hmac.c` only
    /// ever generates, and every call site compares the result itself --
    /// which for HTTP Digest is a server-side operation curl never performs.
    /// The operation is published anyway, and the non-constant-time
    /// alternative deliberately is not, so that a consumer which does need to
    /// compare codes cannot reach for `==` on two digests and leak timing.
    ///
    /// `true` means the codes match. A `tag` of the wrong length is a
    /// mismatch rather than an error, which is what `Mac::verify_slice`
    /// reports and the only sensible reading of a truncated code.
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
///
/// Replaces `Curl_hmacit(&Curl_HMAC_SHA256, ...)`, which is exactly what the
/// `HMAC_SHA256` macro at `lib/http_aws_sigv4.c:41-51` wraps. It is therefore
/// the single primitive behind the whole SigV4 signing-key chain -- HMAC
/// applied successively over the date, the region, the service and
/// `aws4_request` -- whose final signature reaches the wire as lowercase hex.
/// Also consumed by HTTP Digest's SHA-256 variants.
#[allow(dead_code)]
pub(crate) fn hmac_sha256(
    key: &[u8],
    message: &[u8],
) -> [u8; super::sha256::DIGEST_LEN] {
    hmac::<Sha256>(key, message).into()
}

/// `Curl_HMAC_SHA512_256` (`lib/curl_sha512_256.c:788-804`): a **128**-byte
/// block and a 32-byte result.
///
/// Replaces `Curl_hmacit(&Curl_HMAC_SHA512_256, ...)` for HTTP Digest's
/// `algorithm=SHA-512-256-SESS`.
///
/// The block length is the trap. It is twice SHA-256's while the digest
/// length is identical, so a table that reused 64 here would produce a wrong
/// keyed digest that shows up only as a failed authentication exchange. The
/// generic parameter carries it: `Sha512Trunc256` is SHA-512 with a truncated
/// initial state, not a variant of SHA-256, so `D::BlockSize` is 128 and
/// `hmac 0.12.1` reads it from there.
#[allow(dead_code)]
pub(crate) fn hmac_sha512_256(
    key: &[u8],
    message: &[u8],
) -> [u8; super::sha512_256::DIGEST_LEN] {
    hmac::<Sha512Trunc256>(key, message).into()
}

// Tests -- where the coverage of tests/unit/unit1612.c now lives
//
// `tests/unit/unit1612.c` (64 lines) is the C unit test for this code, and
// `tests/data/test1612` ("HMAC unit tests") gates it on
// `<features>unittest</features>`. This binary does not advertise `unittest`,
// so that fixture skips and its two assertions live here instead. That is a
// recorded consequence of the port rather than a defect: the C program calls
// internal `Curl_*` symbols, and a Rust static library genuinely does not
// place `pub(crate)` items in its symbol table, so re-exporting internals to
// make it link would destroy the encapsulation the crate depends on.
//
// The published vectors come from RFC 2202 (HMAC-MD5 and HMAC-SHA-1) and
// RFC 4231 (HMAC-SHA-256). Byte tables carry `#[rustfmt::skip]` so the
// formatter cannot regroup the literals into rows that no longer line up with
// the specification or with the C source they were transcribed from.

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
    ///
    /// The one case that cannot be omitted. Every other HMAC-MD5 vector here
    /// keys at most one block, so a truncating implementation and a digesting
    /// one agree on all of them; this is the only vector that exercises
    /// `lib/hmac.c:65-74`, where a key longer than `maxkeylen` is replaced by
    /// its own digest, and therefore the only one that proves that path
    /// matches curl's.
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
    ///
    /// `Curl_HMAC_SHA512_256` declares `CURL_SHA512_256_BLOCK_SIZE`, which is
    /// 128 (`lib/curl_sha512_256.c:83` and `:788-804`), while its result
    /// length is 32 -- identical to SHA-256's. Nothing about the output
    /// betrays a wrong block size, so it has to be observed through the
    /// over-long-key rule, which is the only behaviour that depends on it.
    ///
    /// A key of 65 bytes is the discriminating case. Under a 128-byte block it
    /// is used exactly as given, so it must NOT agree with its own digest;
    /// under a mistaken 64-byte block it would be replaced by that digest and
    /// the two would agree. The 129-byte key then confirms the rule really is
    /// in force at the correct boundary, and the SHA-256 line beneath shows
    /// the same key being treated the other way by the algorithm whose block
    /// genuinely is 64.
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
    ///
    /// Provenance stated honestly, because it matters: no NIST or RFC vector
    /// for HMAC-SHA-512/256 is being cited here, and none is claimed. The
    /// expected code below was computed with an independent implementation --
    /// OpenSSL, reached through Python's `hashlib` -- over the RFC 4231 case 2
    /// inputs. It earns its place by catching the failure the self-consistent
    /// assertions above cannot: keying the wrong member of the SHA-2 family.
    /// `Sha512Trunc256` and `Sha256` both emit 32 bytes, so a mixed-up type
    /// parameter would satisfy every length and self-agreement check in this
    /// module and only differ here.
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
    ///
    /// This is the compile-time guard the manifests describe, and it is the
    /// reason `sha1 0.10.7` is a workspace dependency at all. `Hmac<D>` bounds
    /// `D` on the `digest 0.10` core traits, so a `digest 0.11` crate entering
    /// the graph would put `Mac` and `Digest` in different crates and this
    /// function would stop compiling -- which is the whole point: a failure to
    /// COMPILE here means the coherence has been lost, before any test runs.
    ///
    /// SHA-1 appears only in this module, and only for that purpose. curl has
    /// no SHA-1 module: `ls lib/sha1*` and `ls lib/curl_sha1*` both find
    /// nothing, `grep -rn 'Curl_sha1' lib/` is empty, and `lib/ws.c:1359-1363`
    /// merely comments on what the *server* does with the WebSocket GUID. So
    /// there is no C source to supersede, no production wrapper exists, and
    /// none is to be created; should one ever be needed it belongs in
    /// `crypto/mod.rs` rather than in a new module file here.
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
    ///
    /// `Curl_HMAC_update` accepts any chunking (`lib/hmac.c:101-108`), so the
    /// code must depend only on the concatenation of what was fed. AWS SigV4
    /// is the caller that relies on this, because it keys a canonical request
    /// it assembles in pieces.
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
    ///
    /// `Mac::new_from_slice` returns a `Result` whose error arm is
    /// unreachable, and [`HmacContext::try_new`] discharges it without
    /// panicking. The lengths chosen straddle both block sizes in play -- 63,
    /// 64 and 65 around SHA-256's and MD5's, and 127, 128 and 129 around
    /// SHA-512/256's -- plus the empty key that `lib/hmac.c:81-86` handles by
    /// skipping its loop entirely.
    #[test]
    fn no_key_length_is_rejected() {
        for length in [0usize, 1, 16, 63, 64, 65, 127, 128, 129, 1024] {
            let key = vec![0x5a; length];
            assert!(HmacContext::<Md5>::try_new(&key).is_ok());
            assert!(HmacContext::<Sha256>::try_new(&key).is_ok());
            assert!(HmacContext::<Sha512Trunc256>::try_new(&key).is_ok());
        }
    }

    /// An empty key and an empty message are both accepted.
    ///
    /// `lib/hmac.c` accepts both: a `keylen` of zero skips the XOR loop at
    /// `:81-86` and pads the whole block at `:88-91`, and a message of zero
    /// length is simply an `hupdate` that copies nothing. The consequence is
    /// checked as well as the acceptance -- an empty key is exactly a key of
    /// one block of zeros, and is exactly NOT a key of one block plus one.
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
    ///
    /// `lib/vauth/digest.c:133-141` writes 16 bytes into 33 and `:143-151`
    /// writes 32 into 65, both with `"%02x"`, so the rendered length is one
    /// less than the buffer size and no character is uppercase. An uppercase
    /// digit would mean `Curl_hexbyte` (`lib/escape.c:218-225`) had been
    /// reached for instead of [`crate::crypto::hex_lower`].
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
