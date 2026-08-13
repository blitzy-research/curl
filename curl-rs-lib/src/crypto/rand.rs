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
//! Randomness. Supersedes `lib/rand.c` and `lib/rand.h` over **`rand 0.8.7`**.
//!
//! # The source is injected, never reached for
//!
//! Every entry point here takes its randomness as a parameter. That mirrors
//! the C exactly: each `Curl_rand*` function takes `struct Curl_easy *data` as
//! its first argument precisely so that `randit` (`lib/rand.c:135-170`) can
//! reach the TLS backend's generator through the handle (`lib/rand.c:165-166`,
//! `Curl_ssl_random`).
//!
//! Injection is not decoration. A line-coverage gate of at least 80
//! percent over `src/protocols/` and `src/transfer/`, and the paths that
//! compose a MIME boundary, a Digest challenge response and a WebSocket
//! handshake all run through this file. A test cannot assert on the bytes
//! those paths produce unless it can substitute the generator, so a
//! generator that cannot be substituted makes the gate unreachable. Hence
//! [`TestRng`], which is `pub(crate)` and **not** `#[cfg(test)]`, so that any
//! module's tests can inject it -- `mime/`, `protocols/ws.rs`,
//! `auth/digest.rs` and `util/fopen.rs` each need it, and a `#[cfg(test)]`
//! item here would be invisible to all four.
//!
//! # No global generator, at any level
//!
//! No `static` generator, none in a `thread_local!`, and no
//! `OnceLock<Box<dyn Rng>>` singleton that a test could install: a
//! process-global override defeats P12 and lets two tests influence one
//! another through the order they happen to run in. This file declares no
//! mutable global state of any kind -- only the five named `const` items
//! that transcribe `lib/rand.c`'s alphabet and bounds, and the anonymous
//! `const` assertions that check them.
//!
//! HOW TO CHECK THE CLAIM, because it is the kind of invariant that decays
//! silently:
//!
//! Each pattern below that must print nothing is written so that it cannot
//! match its own comment line -- either anchored past the `//!` that starts
//! every line here, or with a character class on its first letter, the
//! convention `crypto/mod.rs` established for the same reason.
//!
//! ```sh
//! # The whole-of-crate gate. Every match must be in this file.
//! grep -rn 'thread_rng\|rand::random\|OsRng\|from_entropy' \
//!   curl-rs-lib/src/ --include='*.rs'
//!
//! # No mutable global and no installable singleton -- every item here is a
//! # const, a type, a trait or a function. Must print nothing.
//! grep -nE '^ *(pub\S* )?static |^ *[t]hread_local!|Once(Lock|Cell)::new' \
//!   curl-rs-lib/src/crypto/rand.rs
//!
//! # curl's own rejection sampling, not the crate's. Must print nothing.
//! grep -nE '[g]en_range|\.choose\(|[U]niform' \
//!   curl-rs-lib/src/crypto/rand.rs
//!
//! # No numeric cast: narrowing goes through `to_le_bytes`. Must print
//! # nothing.
//! grep -nE ' as (u8|u32|usize|i32)' curl-rs-lib/src/crypto/rand.rs
//! ```
//!
//! The environment is read nowhere on a production path. `CURL_ENTROPY` is a
//! `DEBUGBUILD`-only facility in the C (`lib/rand.c:138-159`); here it
//! becomes an explicitly constructed [`TestRng::from_entropy_string`], so
//! the name appears in this file only in prose and in the test module.
//!
//! # What is deliberately not ported
//!
//! It exists only under `#ifndef USE_SSL`, offering `arc4random` where the
//! platform has it and otherwise the linear congruential fallback `randseed *
//! 1103515245 + 12345` announced by `infof(data, "WARNING: using weak random
//! seed")`. TLS is unconditional in this workspace, so the branch is
//! unreachable and there is no "weak mode" here to reach for.
//!
//! The `DEBUGBUILD`-only `allow_env_override` parameter of
//! `Curl_rand_bytes` (`lib/rand.h:26-30`) is gone too, along with the
//! asymmetry it created -- `Curl_rand_alnum` always passed `TRUE`
//! (`lib/rand.c:273`) while `Curl_rand_bytes` propagated its caller's choice.
//! Once the source itself is the parameter, there is nothing left for the
//! flag to select.
//!
//! # Version pinning
//!
//! `rand` is held at **0.8.7** and must not be advanced, for two independent
//! reasons. The version is declared once, in the workspace root's
//! `[workspace.dependencies]`, and inherited here.

use ::rand::rngs::{OsRng, StdRng};
use ::rand::{RngCore, SeedableRng};

use crate::error::{CURLcode, CodeResult};
use crate::util::fallible;

/// The alphabet `Curl_rand_alnum` draws from, transcribed character for
/// character from `alnum[]` at `lib/rand.c:258-259`.
#[rustfmt::skip]
const ALNUM: &[u8; 62] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// [`ALNUM`]'s length as the [`u32`] the reduction needs -- `alnumspace` at
/// `lib/rand.c:265`, which the C computes as `sizeof(alnum) - 1`.
const ALNUM_SPACE: u32 = 62;

/// The largest draw [`rand_alnum`] will accept, exclusive.
const ALNUM_LIMIT: u32 = u32::MAX - u32::MAX % ALNUM_SPACE;

/// The scratch buffer `Curl_rand_hex` declares (`unsigned char buffer[128]`
/// at `lib/rand.c:228`), and therefore the bound its size check enforces.
const HEX_SCRATCH: usize = 128;

/// The number of bytes one draw contributes, `sizeof(unsigned int)` at
/// `lib/rand.c:202`.
const DRAW_BYTES: usize = 4;

/// The crate's source of randomness, injected rather than reached for.
///
/// # Object safety
///
/// Neither method is generic and neither carries a `Self: Sized` bound, so
/// `&mut dyn Rng` and `Box<dyn Rng>` both work. That is deliberate:
/// `util/fopen.rs` needs random temporary filenames but must not import this
/// directory, so it accepts the generator from its caller; a connection
/// filter chain holds heterogeneous state and needs the trait-object form;
/// and a unit test is happier with a concrete [`TestRng`].
#[allow(dead_code)]
pub(crate) trait Rng {
    /// One draw -- the successor of `randit(data, &r, ...)`.
    ///
    /// Distributed uniformly over the whole of [`u32`], including the four
    /// values [`rand_alnum`] discards.
    fn next_u32(&mut self) -> u32;

    /// Fill `dest` completely, in the byte order `lib/rand.c:200-214`
    /// produces.
    fn fill_bytes(&mut self, dest: &mut [u8]);
}

/// The production [`Rng`]: a cryptographically secure generator seeded from
/// the operating system.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct SystemRng {
    /// ChaCha12, seeded once from the operating system by [`Self::new`].
    inner: StdRng,
}

impl SystemRng {
    /// A generator seeded from the operating system's entropy source.
    ///
    /// # Errors
    ///
    /// [`CURLcode::FailedInit`] when the platform cannot supply entropy --
    /// the code `Curl_win32_random` returns for the same condition
    /// (`lib/rand.c:61`).
    #[allow(dead_code)]
    pub(crate) fn new() -> CodeResult<Self> {
        // `Seed` is `[u8; 32]` for ChaCha12, but it is named through the
        // trait so that the size follows the algorithm rather than a literal
        // written here.
        let mut seed = <StdRng as SeedableRng>::Seed::default();
        OsRng
            .try_fill_bytes(seed.as_mut())
            .map_err(|_| CURLcode::FailedInit)?;
        Ok(Self {
            inner: StdRng::from_seed(seed),
        })
    }
}

impl Rng for SystemRng {
    fn next_u32(&mut self) -> u32 {
        // `RngCore::next_u32` on the seeded ChaCha, not on `OsRng`: the
        // operating system is read once, in the constructor.
        self.inner.next_u32()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        fill_from_draws(self, dest);
    }
}

/// A deterministic [`Rng`] reproducing the C's `CURL_ENTROPY` generator
/// exactly (`lib/rand.c:138-159`).
///
/// # The generator being reproduced
///
/// ```c
/// if(!seeded) { ... randseed = ntohl(seed); seeded = TRUE; }
/// else randseed++;
/// *rnd = randseed;
/// ```
///
/// Three properties follow, and all three are load-bearing:
///
/// * the **first** draw is the seed itself, not the seed plus one;
/// * each later draw is a plain increment -- not a step of any generator;
/// * the increment wraps, because `randseed` is an `unsigned int`.
///
/// # Example
///
/// ```text
/// let mut rng = TestRng::from_entropy_string("12345678");
/// let mut out = [0_u8; 16];
/// rand_bytes(&mut rng, &mut out);
/// assert_eq!(&out, b"4321532163217321");
/// ```
///
/// That is `tests/data/test2300`, whose expected `Sec-WebSocket-Key` header
/// is the base64 form of exactly those bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct TestRng {
    /// The value the next draw returns -- `randseed` in the C.
    next: u32,
}

impl TestRng {
    /// The generator `CURL_ENTROPY=<text>` selects.
    #[allow(dead_code)]
    pub(crate) fn from_entropy_string(text: &str) -> Self {
        let mut seed = [0_u8; DRAW_BYTES];
        for (slot, byte) in seed.iter_mut().zip(text.as_bytes()) {
            *slot = *byte;
        }
        Self::from_seed(u32::from_be_bytes(seed))
    }

    /// The same generator, seeded with a value directly.
    ///
    /// For the cases where the interesting seed is a number rather than a
    /// string -- the four draws [`rand_alnum`] discards, for instance, which
    /// no short ASCII string lands on.
    #[allow(dead_code)]
    pub(crate) fn from_seed(seed: u32) -> Self {
        Self { next: seed }
    }
}

impl Rng for TestRng {
    fn next_u32(&mut self) -> u32 {
        let drawn = self.next;
        // `randseed++` at `lib/rand.c:155`, wrapping because the C counter
        // is an `unsigned int`. Written as `wrapping_add` so that a debug
        // build agrees with a release one instead of panicking at the wrap.
        self.next = self.next.wrapping_add(1);
        drawn
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        fill_from_draws(self, dest);
    }
}

/// Fill `out` with random bytes: `Curl_rand_bytes` (`lib/rand.c:187-216`),
/// reached in the C through the `Curl_rand` macro (`lib/rand.h:32-36`).
///
/// # The byte order is the contract
///
/// ```c
/// while(left) {
///   *rnd++ = (unsigned char)(r & 0xFF);
///   r >>= 8;
///   --num; --left;
/// }
/// ```
///
/// Four bytes per draw, **low byte first**, with the last group truncated to
/// whatever remains. This is the ordering that makes the `CURL_ENTROPY`
/// sequence come out as it does, and the ordering a fixture sees in a
/// `Sec-WebSocket-Key` header, so it is reproduced rather than delegated: the
/// draws are driven here, and `Rng::fill_bytes` is never called, because an
/// implementation living outside this file could order its bulk fill
/// differently and the difference would land on the wire.
#[allow(dead_code)]
pub(crate) fn rand_bytes(rng: &mut dyn Rng, out: &mut [u8]) {
    debug_assert!(
        !out.is_empty(),
        "a zero-length draw is the DEBUGASSERT(num) of lib/rand.c:198"
    );
    fill_from_draws(rng, out);
}

/// The fill loop of `lib/rand.c:200-214`, in one place.
///
/// Private and shared by [`rand_bytes`] and by both [`Rng::fill_bytes`]
/// implementations, so that the ordering exists exactly once and the three
/// cannot drift apart.
fn fill_from_draws(rng: &mut dyn Rng, out: &mut [u8]) {
    for group in out.chunks_mut(DRAW_BYTES) {
        // `to_le_bytes` IS the C's `r & 0xFF` followed by `r >>= 8`,
        // repeated: element 0 is the low byte. It is also the narrowing the
        // C spells `(unsigned char)`, expressed without a cast that could
        // truncate something else by accident.
        let drawn = rng.next_u32().to_le_bytes();
        // `left = num < sizeof(unsigned int) ? num : sizeof(unsigned int)`
        // at `lib/rand.c:202`: the final group takes only as many bytes as
        // remain, and the rest of the draw is discarded. `chunks_mut` yields
        // exactly that short final slice, so the length is never above four.
        group.copy_from_slice(&drawn[..group.len()]);
    }
}

/// `num - 1` **lowercase** hexadecimal characters: `Curl_rand_hex`
/// (`lib/rand.c:225-251`).
///
/// # Lowercase, not upper
///
/// The C renders through `Curl_hexencode`, documented at `lib/escape.c:197`
/// as producing "lowercase hex-encoded ASCII" from the `Curl_ldigits` table.
/// One function further on, `Curl_hexbyte` (`lib/escape.c:220`) emits
/// **UPPERCASE** from `Curl_udigits`; it is the wrong one here, and a Digest
/// exchange built on it would fail against a real server. This goes through
/// the directory's single rendering policy, `crypto::hex_lower`, which is
/// `hex 0.4.3`'s lowercase `encode`.
///
/// # Errors
///
/// [`CURLcode::BadFunctionArgument`], for each of the three conditions the C
/// rejects with the same code:
///
/// * `num` is even -- `!(num & 1)` at `lib/rand.c:237`. The implementation
///   renders whole bytes, so an even size cannot be filled exactly.
/// * `num / 2` reaches the 128-byte scratch buffer -- `lib/rand.c:237`
///   again. The check is on the size as passed, before the decrement, so the
///   largest accepted odd `num` is 255.
/// * `num` is below 2 -- `DEBUGASSERT(num > 1)` at `lib/rand.c:229`. The C
///   reaches the same code by a longer route: `num == 1` passes both
///   explicit checks, then asks `Curl_rand_bytes` for zero bytes, which
///   returns the `CURLE_BAD_FUNCTION_ARGUMENT` its `result` was initialised
///   to at `lib/rand.c:193` and never overwrote.
#[allow(dead_code)]
pub(crate) fn rand_hex(rng: &mut dyn Rng, num: usize) -> CodeResult<String> {
    // `DEBUGASSERT(num > 1)` at `:229`, as a returned error rather than an
    // assertion, because the C returns an error here too.
    if num < 2 {
        return Err(CURLcode::BadFunctionArgument);
    }
    // The two halves of `:237`, in the C's own order.
    if num / 2 >= HEX_SCRATCH || num % 2 == 0 {
        return Err(CURLcode::BadFunctionArgument);
    }

    // `num--` at `:243`, then `num / 2` bytes at `:245`. `num` is odd and at
    // least 3 here, so the subtraction cannot wrap and the count is at least
    // one.
    let characters = num - 1;
    let mut bytes = vec![0_u8; characters / 2];
    rand_bytes(rng, &mut bytes);

    // `Curl_hexencode(buffer, num / 2, rnd, num + 1)` at `:249`. Two
    // characters per byte, so the result is `characters` long by
    // construction.
    Ok(super::hex_lower(&bytes))
}

/// `num - 1` alphanumeric characters: `Curl_rand_alnum`
/// (`lib/rand.c:258-284`).
///
/// # Rejection sampling, reproduced rather than replaced
///
/// ```c
/// do {
///   result = randit(data, &r, TRUE);
/// } while(r >= (UINT_MAX - UINT_MAX % alnumspace));
/// *rnd++ = (unsigned char)alnum[r % alnumspace];
/// ```
///
/// The loop discards the top four values of [`u32`] -- see [`ALNUM_LIMIT`]
/// -- so that the reduction is unbiased. It is written out here rather than
/// delegated to a range-sampling helper from the `rand` crate on purpose:
/// such a helper rejects on its own schedule, which would discard different
/// draws and therefore emit different characters for the same seed, breaking
/// both the deterministic tests and the `CURL_ENTROPY` reproduction.
///
/// # Errors
///
/// [`CURLcode::BadFunctionArgument`] when `num` is zero, which is the one
/// input `DEBUGASSERT(num > 1)` (`lib/rand.c:267`) forbids and the C's
/// unchecked `num--` would answer by wrapping to `SIZE_MAX` and running off
/// the end of the caller's buffer. Expressing the decrement as a checked
/// subtraction turns that into an error and leaves every other input
/// behaving exactly as the C does -- `num == 1` included, which yields an
/// empty string.
///
/// [`CURLcode::OutOfMemory`] when the output cannot be allocated. `num` is a
/// size the CALLER declared -- in the C it is the size of the caller's own
/// buffer, and here it is the length of the string produced -- so this is one
/// of the externally sized allocations [`crate::util::fallible`] exists for.
/// The C has no such code here because the caller owns the storage; reporting
/// it is what replaces that, and it is strictly better than aborting the
/// process on a `num` the caller mis-derived.
#[allow(dead_code)]
pub(crate) fn rand_alnum(rng: &mut dyn Rng, num: usize) -> CodeResult<String> {
    // `num--` at `:269`. Checked, because the C's version is what
    // `DEBUGASSERT(num > 1)` at `:267` is guarding against.
    let characters = num.checked_sub(1).ok_or(CURLcode::BadFunctionArgument)?;

    let mut text =
        fallible::string_with_capacity(characters).map_err(fallible::oom)?;
    for _ in 0..characters {
        let mut drawn = rng.next_u32();
        // The `do { } while(r >= limit)` of `:272-276`: draw first, then
        // test, so a draw at or above the threshold is replaced rather than
        // reduced.
        while drawn >= ALNUM_LIMIT {
            drawn = rng.next_u32();
        }

        // `alnum[r % alnumspace]` at `:278`. The remainder is below 62, so
        // its little-endian low byte IS its value -- which is the C's
        // `(unsigned char)` narrowing, written without a cast -- and the
        // index is inside the array by construction.
        let index = usize::from((drawn % ALNUM_SPACE).to_le_bytes()[0]);
        text.push(char::from(ALNUM[index]));
    }

    Ok(text)
}

// Value contracts, discharged at compile time.
//
// These pin what `lib/rand.c` fixes, next to the citation that explains why
// it cannot change. They are `const` items, so they are evaluated during
// compilation, allocate nothing and are inert under Miri.

// `ALNUM_SPACE` is the `u32` spelling of the alphabet's length, and this is
// what stops the two from disagreeing: edit the string and the array type
// rejects it, edit the array type and this rejects it.
const _: () = assert!(ALNUM.len() == 62);

// `UINT_MAX % 62 == 3`, so the threshold sits three below `UINT_MAX` and the
// four discarded draws are 4_294_967_292 through 4_294_967_295. Asserting the
// measured value means a mistyped derivation cannot pass.
const _: () = assert!(ALNUM_LIMIT == 4_294_967_292);
const _: () = assert!(u32::MAX - ALNUM_LIMIT == 3);

// `sizeof(unsigned int)` on every platform curl supports, and the group size
// of the fill loop.
const _: () = assert!(DRAW_BYTES == 4);

// `sizeof(buffer)` at `lib/rand.c:228`.
const _: () = assert!(HEX_SCRATCH == 128);

#[cfg(test)]
mod tests {
    use super::{
        rand_alnum, rand_bytes, rand_hex, Rng, SystemRng, TestRng, ALNUM,
        ALNUM_LIMIT, ALNUM_SPACE, DRAW_BYTES, HEX_SCRATCH,
    };
    use crate::error::CURLcode;

    /// The bytes `CURL_ENTROPY=12345678` makes the sixteen-byte draw of
    /// `lib/ws.c:1278` produce.
    ///
    /// `tests/data/test2300` sets that variable and expects
    /// `Sec-WebSocket-Key: NDMyMTUzMjE2MzIxNzMyMQ==`, which is the base64
    /// form of exactly this.
    const TEST2300_KEY_BYTES: &[u8; 16] = b"4321532163217321";

    /// The header value `tests/data/test2300` expects, transcribed from the
    /// fixture.
    const TEST2300_KEY_BASE64: &str = "NDMyMTUzMjE2MzIxNzMyMQ==";

    /// The alphabet, transcribed a second time and independently, so that a
    /// single careless edit cannot pass both copies.
    #[rustfmt::skip]
    const C_ALPHABET: &str =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    /// The highest-value test in this file: the seed derivation, the
    /// increment rule and the low-byte-first ordering, all at once.
    #[test]
    fn the_entropy_vector_of_test2300_is_reproduced() {
        let mut rng = TestRng::from_entropy_string("12345678");
        let mut out = [0_u8; 16];
        rand_bytes(&mut rng, &mut out);
        assert_eq!(&out, TEST2300_KEY_BYTES);
    }

    /// The same draw, carried all the way to the header value the fixture
    /// compares against.
    ///
    /// `lib/ws.c:1278-1281` draws 16 bytes and base64-encodes them, so this
    /// asserts the whole path from generator to wire rather than only the
    /// generator.
    #[test]
    fn the_websocket_key_of_test2300_is_reproduced() {
        let mut rng = TestRng::from_entropy_string("12345678");
        let mut out = [0_u8; 16];
        rand_bytes(&mut rng, &mut out);
        let encoded = crate::util::base64::encode(&out)
            .expect("base64 encoding of 16 bytes cannot fail");
        assert_eq!(encoded, TEST2300_KEY_BASE64);
    }

    /// Only the first four characters of the entropy text are read, so the
    /// eight-character fixture value and its first half are one generator.
    #[test]
    fn only_the_first_four_entropy_characters_are_read() {
        let mut long = TestRng::from_entropy_string("12345678");
        let mut short = TestRng::from_entropy_string("1234");
        assert_eq!(long, short);
        assert_eq!(long.next_u32(), 0x3132_3334);
        assert_eq!(short.next_u32(), 0x3132_3334);
    }

    /// Shorter text is zero-padded on the right, matching a partial
    /// `memcpy` into a zero-initialised seed at `lib/rand.c:146`.
    #[test]
    fn shorter_entropy_text_is_padded_on_the_right() {
        assert_eq!(TestRng::from_entropy_string("1").next_u32(), 0x3100_0000);
        assert_eq!(TestRng::from_entropy_string("12").next_u32(), 0x3132_0000);
        assert_eq!(TestRng::from_entropy_string("").next_u32(), 0);
    }

    /// The first draw is the seed itself and each later draw is a plain
    /// increment -- `lib/rand.c:145-156`, where the `else randseed++` branch
    /// is reached only from the second call onwards.
    #[test]
    fn the_first_draw_is_the_seed_and_the_rest_increment_by_one() {
        let mut rng = TestRng::from_seed(7);
        assert_eq!(rng.next_u32(), 7);
        assert_eq!(rng.next_u32(), 8);
        assert_eq!(rng.next_u32(), 9);
    }

    /// The counter wraps, because the C's `randseed` is an `unsigned int`.
    #[test]
    fn the_counter_wraps_at_the_top_of_the_range() {
        let mut rng = TestRng::from_seed(u32::MAX);
        assert_eq!(rng.next_u32(), u32::MAX);
        assert_eq!(rng.next_u32(), 0);
        assert_eq!(rng.next_u32(), 1);
    }

    /// Each draw contributes its four bytes low-end first
    /// (`lib/rand.c:209-210`), asserted on its own rather than only through
    /// the fixture vector.
    #[test]
    fn each_draw_emits_its_low_byte_first() {
        let mut rng = TestRng::from_seed(0x0102_0304);
        let mut out = [0_u8; DRAW_BYTES];
        rand_bytes(&mut rng, &mut out);
        assert_eq!(out, [0x04, 0x03, 0x02, 0x01]);
        assert_eq!(out, 0x0102_0304_u32.to_le_bytes());
    }

    /// The final group takes only the bytes that remain and discards the
    /// rest of the draw -- `left = num < sizeof(unsigned int) ? ...` at
    /// `lib/rand.c:202`.
    ///
    /// Six bytes: the first draw contributes four, the second only its low
    /// two.
    #[test]
    fn the_final_group_is_truncated_to_what_remains() {
        let mut rng = TestRng::from_seed(0x0102_0304);
        let mut out = [0_u8; 6];
        rand_bytes(&mut rng, &mut out);
        assert_eq!(out, [0x04, 0x03, 0x02, 0x01, 0x05, 0x03]);

        // The third and fourth bytes of the second draw were dropped, not
        // carried into a later position: the next draw is the third one.
        assert_eq!(rng.next_u32(), 0x0102_0306);
    }

    /// `Rng::fill_bytes` and [`rand_bytes`] are the same fill, which is why
    /// both delegate to one private helper.
    #[test]
    fn the_trait_fill_matches_the_free_function() {
        let mut left = TestRng::from_entropy_string("12345678");
        let mut right = TestRng::from_entropy_string("12345678");
        let mut through_function = [0_u8; 23];
        let mut through_trait = [0_u8; 23];
        rand_bytes(&mut left, &mut through_function);
        right.fill_bytes(&mut through_trait);
        assert_eq!(through_function, through_trait);
    }

    /// The alphabet is `lib/rand.c:258-259`, character for character, and
    /// `alnumspace` is 62 (`lib/rand.c:265`).
    #[test]
    fn the_alphabet_is_the_c_alphabet() {
        assert_eq!(ALNUM.len(), 62);
        assert_eq!(ALNUM_SPACE, 62);
        assert_eq!(ALNUM.as_slice(), C_ALPHABET.as_bytes());

        // Upper case, then lower case, then digits -- the order that fixes
        // which draw maps to which character.
        assert_eq!(&ALNUM[..26], b"ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        assert_eq!(&ALNUM[26..52], b"abcdefghijklmnopqrstuvwxyz");
        assert_eq!(&ALNUM[52..], b"0123456789");
    }

    /// The alphabet here and the one `util/fopen.rs` transcribes for its own
    /// temporary-name check are the same 62 bytes.
    #[test]
    #[cfg(any(feature = "cookies", feature = "altsvc", feature = "hsts"))]
    fn the_alphabet_matches_the_sibling_transcription() {
        assert_eq!(
            ALNUM.as_slice(),
            crate::util::fopen::RAND_ALPHABET.as_slice()
        );
    }

    /// The rejection threshold is the C's: `UINT_MAX - UINT_MAX % 62`
    /// (`lib/rand.c:276`).
    #[test]
    fn the_rejection_threshold_is_the_c_threshold() {
        assert_eq!(ALNUM_LIMIT, 4_294_967_292);
        assert_eq!(u32::MAX % ALNUM_SPACE, 3);
        assert_eq!(ALNUM_LIMIT % ALNUM_SPACE, 0);
        assert_eq!(u32::MAX - ALNUM_LIMIT, 3);
    }

    /// A draw at or above the threshold is discarded and replaced, not
    /// reduced.
    ///
    /// Seeded exactly at the threshold, the counter offers four unusable
    /// draws, wraps to zero and is accepted, so the single character
    /// produced is `ALNUM[0]`.
    #[test]
    fn draws_at_or_above_the_threshold_are_redrawn() {
        let mut rng = TestRng::from_seed(ALNUM_LIMIT);
        let text = rand_alnum(&mut rng, 2).expect("num of 2 is valid");
        assert_eq!(text, "A");

        // Five draws were consumed: the four discarded ones and the zero
        // that was accepted.
        assert_eq!(rng.next_u32(), 1);
    }

    /// A draw below the threshold is reduced, and the reduction is the C's
    /// `alnum[r % 62]`.
    #[test]
    fn an_accepted_draw_indexes_the_alphabet_by_its_remainder() {
        for seed in [0_u32, 1, 25, 26, 51, 52, 61, 62, 63, 123] {
            let mut rng = TestRng::from_seed(seed);
            let text = rand_alnum(&mut rng, 2).expect("num of 2 is valid");
            let index = usize::try_from(seed % ALNUM_SPACE)
                .expect("a value below 62 fits a usize");
            assert_eq!(text.as_bytes(), &[ALNUM[index]]);
        }
    }

    /// Every character produced is a member of the alphabet, over a run long
    /// enough to exercise the whole of it.
    #[test]
    fn every_generated_character_is_in_the_alphabet() {
        let mut rng = TestRng::from_entropy_string("seed");
        let text = rand_alnum(&mut rng, 513).expect("num of 513 is valid");
        assert_eq!(text.len(), 512);
        assert!(text.bytes().all(|byte| ALNUM.contains(&byte)));
        assert!(text.is_ascii());
    }

    /// One byte of the caller's buffer is the terminator, so the string is
    /// `num - 1` characters -- `lib/rand.c:269`.
    ///
    /// The two sizes are the live C call sites: 41 for a temporary filename
    /// (`lib/curl_fopen.c:89`, `:109`) and 23 for a MIME boundary
    /// (`lib/mime.c:1191-1194` with `MIME_RAND_BOUNDARY_CHARS` of 22).
    #[test]
    fn rand_alnum_spends_one_byte_of_num_on_the_terminator() {
        let mut rng = TestRng::from_entropy_string("temp");

        let temp_name = rand_alnum(&mut rng, 41).expect("41 is valid");
        assert_eq!(temp_name.len(), 40, "lib/curl_fopen.c:89 is 41 bytes");

        let boundary = rand_alnum(&mut rng, 23).expect("23 is valid");
        assert_eq!(boundary.len(), 22, "MIME_RAND_BOUNDARY_CHARS is 22");

        // A MIME boundary is 24 dashes and then those 22 characters, which
        // `lib/mime.h:97` sums to MIME_BOUNDARY_LEN.
        assert_eq!(24 + boundary.len(), 46);
    }

    /// The degenerate sizes behave as the C's do: `num == 1` yields an empty
    /// string, and only `num == 0` -- the case `DEBUGASSERT(num > 1)`
    /// forbids and the C's `num--` would answer by wrapping -- is an error.
    #[test]
    fn rand_alnum_handles_the_degenerate_sizes_as_the_c_does() {
        let mut rng = TestRng::from_seed(1);
        assert_eq!(rand_alnum(&mut rng, 1), Ok(String::new()));
        assert_eq!(rand_alnum(&mut rng, 0), Err(CURLcode::BadFunctionArgument));
        // The rejected call consumed no draw.
        assert_eq!(rng.next_u32(), 1);
    }

    /// A `num` the allocator cannot serve is REPORTED, not fatal.
    ///
    /// `num` is a size the caller declared, so it is one of the externally
    /// sized allocations `crate::util::fallible` exists for. The figure is one
    /// past the largest expressible `std::alloc::Layout`, which fails inside
    /// `Layout::array` **without calling the allocator** -- deterministic on
    /// every target and, unlike a request the allocator merely declines, safe
    /// under Miri, whose interpreter answers a genuine over-allocation with a
    /// hard `resource exhaustion` error that no `Result` can carry.
    #[test]
    fn a_num_the_allocator_cannot_serve_is_reported_not_fatal() {
        let mut rng = TestRng::from_seed(1);
        // `characters` is `num - 1`, so add two to stay past the limit.
        let unservable = (isize::MAX as usize) + 2;
        assert_eq!(
            rand_alnum(&mut rng, unservable),
            Err(CURLcode::OutOfMemory),
            "an unservable size is a code, not an abort"
        );
        // And the refusal happened before any draw was spent.
        assert_eq!(rng.next_u32(), 1);
    }

    /// An even size is rejected, because the implementation renders whole
    /// bytes -- `!(num & 1)` at `lib/rand.c:237`.
    #[test]
    fn rand_hex_rejects_an_even_size() {
        let mut rng = TestRng::from_seed(1);
        for num in [0_usize, 2, 4, 32, 64, 254] {
            assert_eq!(
                rand_hex(&mut rng, num),
                Err(CURLcode::BadFunctionArgument),
                "an even num of {num} must be rejected"
            );
        }
    }

    /// A size below two is rejected -- `DEBUGASSERT(num > 1)` at
    /// `lib/rand.c:229`, which the C answers with the same code by asking
    /// `Curl_rand_bytes` for zero bytes.
    #[test]
    fn rand_hex_rejects_a_size_below_two() {
        let mut rng = TestRng::from_seed(1);
        assert_eq!(rand_hex(&mut rng, 0), Err(CURLcode::BadFunctionArgument));
        assert_eq!(rand_hex(&mut rng, 1), Err(CURLcode::BadFunctionArgument));
    }

    /// The 128-byte scratch bound of `lib/rand.c:228` is enforced on the
    /// size as passed, so 255 is the largest accepted odd size and 257 is
    /// the first rejected one.
    #[test]
    fn rand_hex_enforces_the_scratch_buffer_bound() {
        let mut rng = TestRng::from_seed(2);
        assert_eq!(HEX_SCRATCH, 128);

        let widest = rand_hex(&mut rng, 255).expect("255 is odd and in range");
        assert_eq!(widest.len(), 254);

        assert_eq!(
            rand_hex(&mut rng, 257),
            Err(CURLcode::BadFunctionArgument),
            "257 / 2 reaches the 128-byte scratch buffer"
        );
    }

    /// The output is lowercase and exactly `num - 1` characters --
    /// `Curl_hexencode` via `Curl_ldigits` (`lib/escape.c:197`), after the
    /// `num--` of `lib/rand.c:243`.
    ///
    /// 33 is `lib/vauth/digest.c:352`'s `char cnonce[33]`, whose value is 32
    /// characters wide.
    #[test]
    fn rand_hex_is_lowercase_and_num_minus_one_characters() {
        let mut rng = TestRng::from_entropy_string("hex!");
        for num in [3_usize, 9, 33, 65, 255] {
            let text = rand_hex(&mut rng, num).expect("odd and in range");
            assert_eq!(text.len(), num - 1);
            assert!(text.bytes().all(|byte| byte.is_ascii_hexdigit()));
            assert!(!text.bytes().any(|byte| byte.is_ascii_uppercase()));
        }
    }

    /// The hex is the rendering of the bytes the draws produce, tied to the
    /// same fixture vector so that the two cannot drift.
    ///
    /// `CURL_ENTROPY=12345678` gives the sixteen bytes `4321532163217321`,
    /// whose lowercase rendering is the ASCII of those digits.
    #[test]
    fn rand_hex_renders_the_bytes_the_draws_produce() {
        let mut rng = TestRng::from_entropy_string("12345678");
        let text = rand_hex(&mut rng, 33).expect("33 is odd and in range");
        assert_eq!(text.len(), 32);
        assert_eq!(text, "34333231353332313633323137333231");

        // Which is exactly the rendering of the vector's own bytes: the
        // literal above is the independent check, and this is the statement
        // of why it reads as it does.
        assert_eq!(text, super::super::hex_lower(TEST2300_KEY_BYTES));
    }

    /// The sizes the remaining C call sites draw, each asserted so that a
    /// consumer transcribing one cannot be silently short-changed.
    #[test]
    fn the_consumer_draw_sizes_are_filled_completely() {
        // `lib/ws.c:903` -- the frame mask, `sizeof(enc->mask)`.
        let mut mask = [0_u8; 4];
        // `lib/vauth/ntlm.c:617` -- the NTLM client entropy.
        let mut ntlm = [0_u8; 8];
        // `lib/vauth/digest.c:711-718` -- `char cnoncebuf[12]`, base64-encoded
        // into a 16-character cnonce.
        let mut cnonce = [0_u8; 12];
        // `lib/ws.c:1278` -- the Sec-WebSocket-Key nonce.
        let mut key = [0_u8; 16];

        let mut rng = TestRng::from_entropy_string("size");
        rand_bytes(&mut rng, &mut mask);
        rand_bytes(&mut rng, &mut ntlm);
        rand_bytes(&mut rng, &mut cnonce);
        rand_bytes(&mut rng, &mut key);

        // Filled, not left at the zeroes they were initialised with: this
        // counter never produces four consecutive zero bytes from these
        // seeds.
        assert!(mask.iter().any(|byte| *byte != 0));
        assert!(ntlm.iter().any(|byte| *byte != 0));
        assert!(cnonce.iter().any(|byte| *byte != 0));
        assert!(key.iter().any(|byte| *byte != 0));

        // The base64 form of a 12-byte cnonce is 16 characters, which is
        // what `lib/vauth/digest.c:718` produces.
        let encoded = crate::util::base64::encode(&cnonce)
            .expect("base64 encoding of 12 bytes cannot fail");
        assert_eq!(encoded.len(), 16);
    }

    /// Two generators built from the same entropy text agree completely,
    /// which is the property a test asserting on exact bytes depends on.
    #[test]
    fn a_test_generator_is_reproducible() {
        let mut left = TestRng::from_entropy_string("12345678");
        let mut right = TestRng::from_entropy_string("12345678");
        let mut first = [0_u8; 64];
        let mut second = [0_u8; 64];
        rand_bytes(&mut left, &mut first);
        rand_bytes(&mut right, &mut second);
        assert_eq!(first, second);

        let mut alnum_left = TestRng::from_entropy_string("abcd");
        let mut alnum_right = TestRng::from_entropy_string("abcd");
        assert_eq!(
            rand_alnum(&mut alnum_left, 41),
            rand_alnum(&mut alnum_right, 41)
        );
    }

    /// The generator is usable behind a trait object, which is what lets
    /// `util/fopen.rs` take one without importing this directory and what
    /// lets a filter chain hold one.
    #[test]
    fn the_trait_is_object_safe_in_both_forms() {
        let mut boxed: Box<dyn Rng> =
            Box::new(TestRng::from_entropy_string("12345678"));
        let mut out = [0_u8; 16];
        rand_bytes(boxed.as_mut(), &mut out);
        assert_eq!(&out, TEST2300_KEY_BYTES);

        let mut owned = TestRng::from_entropy_string("12345678");
        let borrowed: &mut dyn Rng = &mut owned;
        let text = rand_alnum(borrowed, 23).expect("23 is valid");
        assert_eq!(text.len(), 22);
    }

    /// The production generator satisfies the same trait as the
    /// deterministic one and really produces randomness.
    #[test]
    fn the_system_generator_is_interchangeable_and_random() {
        let mut first = SystemRng::new().expect("OS entropy is available");
        let mut second = SystemRng::new().expect("OS entropy is available");

        let mut left = [0_u8; 32];
        let mut right = [0_u8; 32];
        rand_bytes(&mut first, &mut left);
        rand_bytes(&mut second, &mut right);

        // Two independently seeded generators agreeing on 32 bytes has
        // probability 2^-256, so this is a real check rather than a
        // probabilistic guess -- as is a 32-byte draw of all zeroes.
        assert_ne!(left, right);
        assert_ne!(left, [0_u8; 32]);
        assert_ne!(right, [0_u8; 32]);

        // Successive draws from one generator differ too, so it is not
        // returning a fixed block.
        let mut again = [0_u8; 32];
        rand_bytes(&mut first, &mut again);
        assert_ne!(left, again);

        // And it drives the same entry points, through the same trait
        // object, as the deterministic one.
        let erased: &mut dyn Rng = &mut first;
        let hex = rand_hex(&mut *erased, 33).expect("33 is odd and in range");
        assert_eq!(hex.len(), 32);
        assert!(hex.bytes().all(|byte| byte.is_ascii_hexdigit()));
        let text = rand_alnum(&mut *erased, 41).expect("41 is valid");
        assert_eq!(text.len(), 40);
        assert!(text.bytes().all(|byte| ALNUM.contains(&byte)));
    }
}
