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
//! SHA-256, FIPS 180-4. Supersedes `lib/sha256.c` (477 lines) and
//! `lib/curl_sha256.h` (45 lines) over `sha2 0.10.9`'s `Sha256`.
//!
//! Every claim below carries a `path:line` citation into the C tree, because
//! the behaviour being reproduced is defined by those files and not by this
//! description.
//!
//! # What was superseded, and by what
//!
//! `lib/sha256.c` is not one implementation but six, selected by the
//! preprocessor. `lib/sha256.c:40-50` records the required order of the
//! branches -- OpenSSL, GnuTLS, mbedTLS, CommonCrypto, then Windows'
//! CryptoAPI -- and `lib/sha256.c:215` opens a sixth, bundled arm for the case
//! where no cryptographic library is linked at all. All six are replaced here
//! by `sha2 0.10.9`, the RustCrypto implementation on the `digest 0.10`
//! generation the rest of this directory already resolves to. The selection
//! machinery disappears with them: there is exactly one implementation now, so
//! there is nothing to select between.
//!
//! Two C declarations are the whole contract this module reproduces:
//!
//! ```text
//!   lib/curl_sha256.h:36-38  CURL_SHA256_DIGEST_LENGTH 32  /* fixed size */
//!   lib/curl_sha256.h:40-41  CURLcode Curl_sha256it(unsigned char *output,
//!                                                   const unsigned char *in,
//!                                                   const size_t len);
//!   lib/sha256.c:468-475     const struct HMAC_params Curl_HMAC_SHA256 = {
//!                              ..., 64 /* max key */, 32 /* result */ };
//! ```
//!
//! `lib/curl_sha256.h:29-30` wraps all of it in
//! `#if !defined(CURL_DISABLE_AWS) || !defined(CURL_DISABLE_DIGEST_AUTH) ||
//! defined(USE_LIBSSH2) || defined(USE_SSL)`. That guard is deliberately NOT
//! reproduced as a Cargo `cfg`. None of the workspace's fifteen features
//! corresponds to any of those four switches, so a `cfg` naming one would be
//! false and would compile this module away in silence. SHA-256 is
//! unconditionally available here.
//!
//! # The three consumers, and why the bytes matter
//!
//! Two of the three put this digest's output on the wire, where it is compared
//! byte for byte against a recorded expectation rather than parsed:
//!
//! * **HTTP Digest, `SHA-256` and `SHA-256-SESS`.**
//!   `lib/vauth/digest.c:983-1015` selects the digest for an algorithm at or
//!   below `ALGO_SHA256SESS` and pairs it with `auth_digest_sha256_to_ascii`.
//!   The rendered hash lands inside an `Authorization` header.
//! * **AWS SigV4.** `lib/http_aws_sigv4.c:600` digests the request payload and
//!   `:1034` digests the assembled canonical request; `:41-50` defines the
//!   `HMAC_SHA256` macro over `Curl_hmacit(&Curl_HMAC_SHA256, ...)` that drives
//!   the whole signing-key derivation chain at `:1071-1077`. The surrounding
//!   constants show how tightly the 32 is wired in: `:53` fixes
//!   `TIMESTAMP_SIZE 17`, `:56` derives `SHA256_HEX_LENGTH` as
//!   `2 * CURL_SHA256_DIGEST_LENGTH + 1`, and `:58` caps
//!   `MAX_QUERY_COMPONENTS` at 128.
//! * **The TLS session cache**, which is not wire-visible but must be
//!   self-consistent for the lifetime of a process:
//!   `lib/vtls/vtls_scache.c:114` digests a session-cache key, and `:656`,
//!   `:1009` and `:1048` key the same digest through `Curl_HMAC_SHA256`.
//!
//! Composing those messages belongs to `auth/` and `tls/`. This module owes
//! them one thing: a digest that is byte-identical to the C one, plus the
//! [`Sha256`] marker type so the keyed form names the same hash.
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
//! # 64 here, 128 in the sibling
//!
//! SHA-512/256 produces the same 32-byte digest from a **128**-byte block
//! (`lib/curl_sha512_256.c:83`), where SHA-256's block is 64
//! (`lib/sha256.c:473`). The identical output length is exactly what makes the
//! two easy to conflate, and a keyed digest built on the wrong block length is
//! wrong in a way that surfaces only as a rejected authentication exchange.
//! [`crate::crypto`] therefore asserts both values and the doubling
//! relationship between them, and the test module below asserts that
//! [`BLOCK_LEN`] and the sibling's are not equal.
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
//!
//! # One in-body attribution is deliberately not carried forward
//!
//! `lib/sha256.c:219-220` reads "This is based on the SHA256 implementation in
//! LibTomCrypt that was released / into public domain." -- the note ends at
//! `lib/sha256.c:220`. It attributes the bundled fallback that
//! `lib/sha256.c:215` opens, and that fallback is **not** ported: `sha2 0.10.9`
//! supplies the primitive instead, so none of the attributed code is present
//! and reproducing its notice would credit code that is not here. Recorded
//! rather than dropped in silence, because a reader comparing the two files
//! will find the note and needs to know where it went. Three siblings carry
//! in-body attributions that DO travel with their code, for contrast:
//! `lib/md5.c:237-273`, `lib/md4.c:160-196` and `lib/curl_sha512_256.c:48`.
//!
//! # What this module deliberately does not contain
//!
//! * **No parameter table.** `struct HMAC_params` (`lib/sha256.c:468-475`)
//!   existed to make the digest pluggable across seven TLS backends by carrying
//!   three function pointers, a context size, a block length and a result
//!   length. There is one implementation now, and `hmac 0.12.1` recovers the
//!   two lengths from the type itself, so the table has no job left.
//! * **No `sha256sum` shim and no certificate-pinning helper.** curl's own
//!   rustls backend advertises neither: `lib/vtls/rustls.c:1397-1426` sets
//!   exactly seven `SSLSUPP_*` flags and `SSLSUPP_PINNEDPUBKEY` is not among
//!   them, while `lib/vtls/rustls.c:1423` leaves the `sha256sum` vtable slot
//!   `NULL`. `lib/vtls/mbedtls.c:1501` does populate it, but that backend is
//!   dropped. Building the capability in here would let `tls/` advertise
//!   something that is not implemented, and under-reporting is safe where
//!   over-reporting is not.
//! * **No availability predicate.** `sha512_256.rs` publishes one because
//!   `lib/curl_sha512_256.h:28-32` defines `CURL_HAVE_SHA512_256` and
//!   `src/curlinfo.c` prints a row from it. SHA-256 has no such macro and no
//!   such row, so there is nothing to answer.
//! * **No local error type.** Nothing here is fallible, so no error type is
//!   defined or imported; see the note on [`sha256`]. Were that to change, the
//!   answer is `crate::error::CURLcode`, never a type declared in this file.
//!
//! # The version pin is load-bearing
//!
//! `sha2` is pinned at `=0.10.9` once, in the workspace manifest's
//! `[workspace.dependencies]`, and inherited by `curl-rs-lib/Cargo.toml` with
//! `{ workspace = true }`. Do not restate the version here and do not advance
//! it. `sha2 0.11.0` declares a minimum supported Rust version of 1.85 against
//! this project's floor of 1.75, and it moves to `digest 0.11`, which would put
//! two `digest` generations in one graph and stop `Hmac<Sha256>` from
//! compiling at all -- a build break, not a preference. `deny.toml` bans
//! `digest:>=0.11.0` outright so that even a whole-graph migration, which would
//! leave no duplicate for its `multiple-versions` policy to catch, still fails.
//!
//! Nothing here enables a `sha2` feature. `asm` in particular is left off:
//! speed is not a goal of this work, and where a choice exists between a faster
//! design and a more faithful one the faithful one wins. No feature enabled
//! from this file may union a second cryptographic provider into the graph
//! either; `ring` is pinned explicitly at the root and `aws-lc-rs` is banned by
//! name.
//!
//! # Gates
//!
//! Each pattern below carries a character class on its first letter so the
//! pattern cannot match the line it is written on, which keeps every gate
//! runnable against this file itself. The convention, and the reason for it,
//! are recorded in [`crate::crypto`].
//!
//! ```sh
//! # The attribution assertion that matters most for this file: exactly one
//! # line names the contributor, and exactly two lines are notices. Prints 1
//! # then two lines.
//! grep -c '[F]lorin Petriuc' curl-rs-lib/src/crypto/sha256.rs
//! grep -n '[C]opyright'      curl-rs-lib/src/crypto/sha256.rs
//!
//! # Exactly one licence identifier line. Prints 1.
//! grep -c 'SPDX-License-Ident[i]fier: curl' \
//!   curl-rs-lib/src/crypto/sha256.rs
//!
//! # This file adds no exemption to the crate-root safety attribute, and
//! # names no keyword that would need one. Must print nothing.
//! grep -n '[u]nsafe' curl-rs-lib/src/crypto/sha256.rs
//!
//! # There is no `tls` feature; a cfg naming one compiles the code away in
//! # silence. Must print nothing.
//! grep -nE 'feature *= *"[t]ls"' curl-rs-lib/src/crypto/sha256.rs
//!
//! # The pin, and the single digest generation it exists to preserve.
//! cargo tree -p curl-rs-lib -i sha2    # sha2 v0.10.9
//! cargo tree -p curl-rs-lib -i digest  # digest v0.10.x, once
//! ```

use ::sha2::{Digest, Sha256 as Sha256Hasher};

/// Length of a SHA-256 digest in bytes.
///
/// `lib/curl_sha256.h:36-38` defines `CURL_SHA256_DIGEST_LENGTH 32` and
/// comments it "fixed size"; `lib/sha256.c:474` repeats the 32 as the result
/// size of the keyed parameter table. It is contractual rather than chosen: two
/// independent C call sites size a buffer from it -- `lib/vauth/digest.c:144`
/// takes 32 bytes in and writes 65 out, and `lib/http_aws_sigv4.c:56` derives
/// its own `SHA256_HEX_LENGTH` as `2 * CURL_SHA256_DIGEST_LENGTH + 1`.
pub(crate) const DIGEST_LEN: usize = 32;

/// SHA-256's compression block size in bytes.
///
/// `lib/sha256.c:473` gives it as the maximum-key-length field of
/// `Curl_HMAC_SHA256` (`lib/sha256.c:468-475`), which is where the C tree
/// recorded a block size. The two are the same number for a reason:
/// `lib/hmac.c:98-118` hashes a key longer than the block down to a digest and
/// zero-pads a shorter one, so the block length *is* the largest key length
/// that carries any information.
///
/// Nothing in this crate computes with this constant. `hmac 0.12.1` reads the
/// same number off `Sha256::BlockSize` for itself, so the value exists here to
/// be documented and asserted: [`crate::crypto`] pins it at 64, pins
/// SHA-512/256's at 128, and asserts the doubling relationship between them
/// because the two digests share a 32-byte output while their blocks differ.
#[allow(dead_code)]
pub(crate) const BLOCK_LEN: usize = 64;

/// The `digest` marker type for SHA-256, published so that
/// [`crate::crypto::hmac`] can instantiate `Hmac<Sha256>` without naming the
/// `sha2` crate a second time.
///
/// Both keyed siblings publish the same shape -- `md5`'s `Md5` and
/// `sha512_256`'s `Sha512Trunc256` -- so the keyed module imports one marker
/// per algorithm rather than a crate per algorithm. The alias is named for the
/// algorithm rather than for this module so that it reads correctly at the use
/// site: `Hmac<Sha256>`.
///
/// It also stands in for the coherence the whole directory depends on.
/// `Hmac<D>` bounds `D` on the `digest 0.10` core traits, so an `Hmac<Sha256>`
/// that compiles is the compiler's own proof that `sha2` and `hmac` resolved to
/// one `digest` generation. The test module asserts exactly that, and asserts
/// in addition that keying through this alias agrees with
/// `crate::crypto::hmac_sha256`. That wrapper keys through this very alias --
/// `crypto/hmac.rs:222` imports it and `:451` keys with it -- so what the
/// second comparison pins is that the wrapper has not been pointed at a
/// different SHA-2 member: `Sha512Trunc256` emits the same 32 bytes, so no
/// length or self-agreement check in the keyed module would notice, and this
/// one would.
#[allow(dead_code)]
pub(crate) type Sha256 = Sha256Hasher;

/// Digest a whole message: `Curl_sha256it` (`lib/sha256.c:441-466`).
///
/// Returns the 32 raw bytes. Rendering to ASCII is
/// [`crate::crypto::hex_lower`]'s job, and it is lowercase because every digest
/// curl puts on the wire is written with `"%02x"`.
///
/// # Why this cannot fail
///
/// The C function returns a `CURLcode` (`lib/curl_sha256.h:40-41`), and the
/// only unsuccessful value it can produce comes from `my_sha256_init`
/// (`lib/sha256.c:460`) -- a different function in each of the six branches
/// `lib/sha256.c:40-50` orders, and one that genuinely can fail in some of
/// them. The Windows arm is the clearest case: `lib/sha256.c:175-189` acquires
/// a provider from the operating system and returns `CURLE_OUT_OF_MEMORY` if
/// that is refused, then creates a hash object and returns `CURLE_FAILED_INIT`
/// if that is.
///
/// There is one implementation here. It allocates nothing, asks the operating
/// system for nothing and has no initialisation step that can be refused, so
/// there is no failure to report. An infallible signature is the honest one; a
/// `Result` that is always successful would oblige every call site to handle a
/// case that cannot arise, and would invite the reflex of discarding it.
///
/// # The shape is shared with the other two Digest hashes
///
/// `lib/vauth/digest.c:983-1015` chooses between `Curl_md5it`,
/// `Curl_sha256it` and `Curl_sha512_256it` through a function pointer, so the
/// three must stay interchangeable. `md5`, this function and `sha512_256`
/// therefore all take `&[u8]` and return a fixed-size array, which lets
/// `auth/digest.rs` dispatch over them without special-casing one.
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
///
/// Streaming changes nothing observable: the bytes a streamed digest produces
/// are the bytes the one-shot form produces, which the test module asserts
/// across every chunk boundary that could plausibly differ.
///
/// The hasher is held in a named field rather than a positional one, and the
/// method sequence matches the incremental MD5 context, so that a caller
/// feeding a digest in pieces writes the same code whichever algorithm it
/// holds. [`crate::crypto`] records that property as this type's reason for
/// existing.
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
    ///
    /// Any number of calls in any chunking; the digest depends only on the
    /// concatenation of everything fed. The C call narrowed its `size_t` length
    /// to an `unsigned int` through `curlx_uztoui` first
    /// (`lib/sha256.c:462`). Nothing narrows here -- the slice carries its own
    /// `usize` length the whole way down -- so a message longer than `u32::MAX`
    /// cannot be silently truncated.
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
    ///
    /// Both spellings exist deliberately. `finalize` is the name this module's
    /// specification fixes, and it is what the `digest` traits call the
    /// operation. `finish` is what `Md5Context` publishes, and
    /// [`crate::crypto`] states that this type exists to give a caller "one
    /// shape for both algorithms" -- which holds only if the terminal method
    /// answers to the same name in both. Rather than break one of the two
    /// contracts, both names resolve to the same work.
    #[allow(dead_code)]
    pub(crate) fn finish(self) -> [u8; DIGEST_LEN] {
        self.finalize()
    }
}

// Tests -- where the coverage of tests/unit/unit1610.c now lives
//
// `tests/unit/unit1610.c` (65 lines) is the C unit test for this digest, and
// `tests/data/test1610` is named "SHA256 unit tests" and gates on
// `<features>unittest</features>`. This binary does not advertise `unittest`,
// so that fixture skips -- and it could not run in any case, because it links a
// debug static library and calls the internal `Curl_sha256it` symbol, which a
// Rust static library genuinely does not place in its symbol table. Relocating
// the assertions here is the recorded response to that, and re-exporting
// internals to make the C program link instead is not, because it would destroy
// the encapsulation this crate depends on.
//
// The vector tables carry `#[rustfmt::skip]` so the formatter cannot regroup
// the literals: the byte arrays are laid out eight per line to match how a
// digest is read off a reference, and the hex strings are one per line to keep
// them diffable against a published table.

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
    ///
    /// Written as the lowercase hex a Digest or SigV4 exchange would actually
    /// carry rather than as byte arrays, so each row asserts the digest and its
    /// rendering together. The four inputs are chosen for their lengths: 0 and
    /// 3 bytes stay inside one block, 56 bytes is the largest input whose
    /// padding still fits the first block, and 112 bytes spans two.
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
    ///
    /// Compared as raw arrays rather than through the hex helper, because that
    /// is the form `verify_memory` compares at `tests/unit/unit1610.c:49` and
    /// `:57` and this test is the relocation of those two assertions.
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
    ///
    /// The standard check that the message-length counter and the final padding
    /// block stay right across many compression rounds, which no short input
    /// reaches. Ignored under Miri, where a million bytes through the
    /// interpreter costs minutes and proves nothing the shorter vectors have
    /// not already proved; the same treatment the source-policy tests in
    /// `crate` give their own slow cases.
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
    ///
    /// The splits are the ones that can plausibly differ: nothing fed, one
    /// byte, one byte short of a block, exactly a block, one byte past a block,
    /// a point in the middle, and everything at once.
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
    ///
    /// The canonical request is a method, a path, a sorted query string, sorted
    /// headers, a signed-header list and a payload hash, joined by newlines --
    /// six pieces that the C tree assembles into one buffer before hashing and
    /// that a streaming context can absorb one at a time. Both terminal method
    /// names are exercised here, since they must agree.
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
    ///
    /// `Curl_HMAC_SHA256`'s maximum key length is 64 (`lib/sha256.c:473`) while
    /// `Curl_HMAC_SHA512_256`'s is `CURL_SHA512_256_BLOCK_SIZE`, which
    /// `lib/curl_sha512_256.c:83` defines as 128. The digest lengths are
    /// identical, which is exactly what makes the two easy to conflate, so the
    /// difference is asserted rather than assumed.
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
    ///
    /// `lib/vauth/digest.c:145` sizes its destination at 65 and
    /// `lib/http_aws_sigv4.c:56` computes the same 65, both counting a
    /// terminator a Rust string does not carry -- hence the `- 1`.
    /// `lib/escape.c:218-227` is the uppercase renderer and must not be the one
    /// reproduced, so every character is checked rather than sampled.
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
    ///
    /// Two independent things are proved here. First, `Hmac<D>` bounds `D` on
    /// the `digest 0.10` core traits, so this test would not compile at all if
    /// `sha2` and `hmac` ever resolved to different `digest` generations --
    /// which is the build break `sha2 0.11.0` would cause. Second, keying
    /// through the alias this module publishes must produce exactly what
    /// `crate::crypto::hmac_sha256` produces, and that function names its hash
    /// independently; if the two ever drifted apart, the tags would differ.
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
    ///
    /// `crypto/hmac.rs` reaches its other two markers as `super::md5::Md5` and
    /// `super::sha512_256::Sha512Trunc256`, which resolve to the fully
    /// qualified paths below. Naming this one the same way makes the visibility
    /// a compile-time obligation of this file rather than something a reader
    /// has to take on trust: drop the `pub(crate)` from the alias and this line
    /// stops compiling.
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
