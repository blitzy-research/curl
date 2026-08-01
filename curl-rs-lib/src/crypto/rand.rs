// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! Randomness. Supersedes `lib/rand.c` and `lib/rand.h` over `rand 0.8.7`.
//!
//! The `rand` version is pinned rather than advanced: `russh 0.54.5` requires
//! `rand ^0.8`, and one generation across the graph is what keeps a single
//! `getrandom` and a single `rand_core` resolved.
//!
//! # Why the source is a trait rather than a free function
//!
//! `Rng` is object-safe on purpose. `util/fopen.rs` needs random temporary
//! filenames but must not import this directory, so it accepts a
//! `&mut dyn Rng` from its caller instead. [`TestRng`] is deliberately *not*
//! behind `#[cfg(test)]` for the same reason: a sibling module or an
//! integration test needs a deterministic source without a test-only build.
//!
//! # The two acceptance rules that are contractual
//!
//! `lib/rand.c:236-241` rejects, with `CURLE_BAD_FUNCTION_ARGUMENT`, an odd
//! requested length and a request larger than the 128-byte scratch buffer.
//! Both are reproduced by [`rand_hex`], because a caller that relied on the
//! rejection would otherwise silently receive a short or truncated string.
//! `lib/rand.c:250` renders the bytes as **lowercase** hex through
//! `Curl_hexencode`, which is why [`crate::crypto::hex_lower`] and not an
//! uppercase form is used here.

use ::rand::rngs::OsRng;
use ::rand::{RngCore, SeedableRng};

use crate::error::CURLcode;

/// The scratch buffer `lib/rand.c:229` declares, and therefore the largest
/// number of hex characters `Curl_rand_hex` can be asked for.
#[allow(dead_code)]
const RANDIT_BUFFER: usize = 128;

/// The alphabet `lib/rand.c:262-266` draws from for `Curl_rand_alnum`:
/// digits, upper case, lower case, in that order. Its length, 62, is the
/// modulus the C code divides by, so the order is not cosmetic -- it is what
/// makes a given random byte map to a given character.
#[allow(dead_code)]
const ALNUM: &[u8; 62] =
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// A source of random bytes, object-safe so that callers can take it by
/// injection.
///
/// One method, because that is all curl ever needs: `lib/rand.c` fills a byte
/// buffer and derives everything else from it.
pub(crate) trait Rng {
    /// Fill `out` completely with random bytes.
    fn fill(&mut self, out: &mut [u8]);
}

/// The operating system's entropy source: `Curl_rand`'s default path
/// (`lib/rand.c:126-160`, which prefers the TLS backend's CSPRNG and falls
/// back to the platform).
///
/// rustls draws from the same platform source through `getrandom`, so there is
/// no second-best fallback to reproduce here and no `srand`-seeded weak path
/// of the kind `lib/rand.c:162-187` keeps for builds without one.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SystemRng;

impl Rng for SystemRng {
    fn fill(&mut self, out: &mut [u8]) {
        OsRng.fill_bytes(out);
    }
}

/// A deterministic source, seeded explicitly.
///
/// Exists so that a test can assert on an exact output and so that a caller
/// which must be reproducible has one. It is a real PRNG rather than a counter
/// because a counter would produce byte patterns no plausible entropy source
/// emits, and a test written against those would prove nothing.
#[derive(Clone, Debug)]
pub(crate) struct TestRng {
    inner: ::rand::rngs::StdRng,
}

impl TestRng {
    /// A source that yields the same sequence for the same `seed`.
    #[allow(dead_code)]
    pub(crate) fn from_seed(seed: u64) -> Self {
        Self {
            inner: ::rand::rngs::StdRng::seed_from_u64(seed),
        }
    }
}

impl Rng for TestRng {
    fn fill(&mut self, out: &mut [u8]) {
        self.inner.fill_bytes(out);
    }
}

/// Fill `out` with random bytes: `Curl_rand` (`lib/rand.c:189-215`).
///
/// C returned `CURLE_OK` or a failure from the backend. There is no failure
/// path here: `getrandom` either succeeds or the platform is unable to provide
/// entropy at all, which `OsRng` treats as unrecoverable, exactly as
/// `lib/rand.c:205` treats a backend that cannot deliver.
#[allow(dead_code)]
pub(crate) fn rand_bytes(rng: &mut dyn Rng, out: &mut [u8]) {
    rng.fill(out);
}

/// Write `len` **lowercase** hex characters: `Curl_rand_hex`
/// (`lib/rand.c:225-256`).
///
/// The two rejections are the C ones, in the C order:
///
/// * `:236-238` -- an odd `len` is `CURLE_BAD_FUNCTION_ARGUMENT`, because the
///   implementation renders whole bytes.
/// * `:239-241` -- `len` larger than the 128-byte scratch buffer is the same
///   error.
///
/// C wrote into a caller-supplied buffer of `len + 1` bytes and terminated it;
/// a Rust `String` carries its own length, so the terminator is absent and the
/// returned string is exactly `len` characters.
#[allow(dead_code)]
pub(crate) fn rand_hex(
    rng: &mut dyn Rng,
    len: usize,
) -> Result<String, CURLcode> {
    if len % 2 != 0 {
        return Err(CURLcode::BadFunctionArgument);
    }
    if len > RANDIT_BUFFER {
        return Err(CURLcode::BadFunctionArgument);
    }

    let mut bytes = vec![0u8; len / 2];
    rng.fill(&mut bytes);
    Ok(super::hex_lower(&bytes))
}

/// Write `len` alphanumeric characters: `Curl_rand_alnum`
/// (`lib/rand.c:258-280`).
///
/// C drew one byte at a time and reduced it modulo 62. The modulo introduces a
/// small bias, and it is reproduced rather than corrected: the values are used
/// for MIME boundaries and temporary filenames, where the C behaviour is the
/// documented behaviour, and AAP section 0.8.1 freezes it.
///
/// The only rejection is the buffer bound, matching `:266-267`.
#[allow(dead_code)]
pub(crate) fn rand_alnum(
    rng: &mut dyn Rng,
    len: usize,
) -> Result<String, CURLcode> {
    if len > RANDIT_BUFFER {
        return Err(CURLcode::BadFunctionArgument);
    }

    let mut bytes = vec![0u8; len];
    rng.fill(&mut bytes);

    let modulus = ALNUM.len();
    let text: Vec<u8> = bytes
        .iter()
        .map(|byte| ALNUM[usize::from(*byte) % modulus])
        .collect();

    // Every byte of `text` is drawn from ALNUM, which is ASCII, so the
    // conversion cannot fail. Constructing through `String::from_utf8` rather
    // than an unchecked call keeps this module free of `unsafe`.
    String::from_utf8(text).map_err(|_| CURLcode::BadFunctionArgument)
}

#[cfg(test)]
mod tests {
    use super::{
        rand_alnum, rand_bytes, rand_hex, Rng, SystemRng, TestRng, ALNUM,
        RANDIT_BUFFER,
    };
    use crate::error::CURLcode;

    #[test]
    fn the_scratch_bound_and_alphabet_match_lib_rand_c() {
        assert_eq!(RANDIT_BUFFER, 128);
        assert_eq!(ALNUM.len(), 62);
        assert!(ALNUM.starts_with(b"0123456789"));
        assert!(ALNUM.ends_with(b"xyz"));
    }

    #[test]
    fn rand_hex_rejects_an_odd_length() {
        let mut rng = TestRng::from_seed(1);
        assert_eq!(rand_hex(&mut rng, 1), Err(CURLcode::BadFunctionArgument));
        assert_eq!(rand_hex(&mut rng, 33), Err(CURLcode::BadFunctionArgument));
    }

    #[test]
    fn rand_hex_rejects_more_than_the_scratch_buffer() {
        let mut rng = TestRng::from_seed(2);
        assert!(rand_hex(&mut rng, RANDIT_BUFFER).is_ok());
        assert_eq!(
            rand_hex(&mut rng, RANDIT_BUFFER + 2),
            Err(CURLcode::BadFunctionArgument)
        );
    }

    #[test]
    fn rand_hex_is_lowercase_and_exactly_the_requested_length() {
        let mut rng = TestRng::from_seed(3);
        for len in [0usize, 2, 8, 32, RANDIT_BUFFER] {
            let text = rand_hex(&mut rng, len).expect("even and within bounds");
            assert_eq!(text.len(), len);
            assert!(text.chars().all(|c| c.is_ascii_hexdigit()));
            assert!(!text.chars().any(|c| c.is_ascii_uppercase()));
        }
    }

    #[test]
    fn rand_alnum_stays_inside_the_alphabet() {
        let mut rng = TestRng::from_seed(4);
        let text = rand_alnum(&mut rng, 64).expect("within bounds");
        assert_eq!(text.len(), 64);
        assert!(text.bytes().all(|b| ALNUM.contains(&b)));
        assert_eq!(
            rand_alnum(&mut rng, RANDIT_BUFFER + 1),
            Err(CURLcode::BadFunctionArgument)
        );
    }

    #[test]
    fn a_seeded_source_repeats_and_the_system_source_fills() {
        let mut a = TestRng::from_seed(7);
        let mut b = TestRng::from_seed(7);
        let mut left = [0u8; 32];
        let mut right = [0u8; 32];
        rand_bytes(&mut a, &mut left);
        rand_bytes(&mut b, &mut right);
        assert_eq!(left, right);

        // The system source must actually write something. A 32-byte draw of
        // all zeroes has probability 2^-256, so this is a real check that the
        // buffer was touched rather than a probabilistic guess.
        let mut system = SystemRng;
        let mut filled = [0u8; 32];
        system.fill(&mut filled);
        assert_ne!(filled, [0u8; 32]);
    }
}
