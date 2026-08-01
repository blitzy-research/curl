// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! Percent-encoding and percent-decoding -- supersedes `lib/escape.c`.
//!
//! # Why this module is `pub`
//!
//! [`super`] is `pub` and so is this module, because four of the 100 symbols
//! `lib/libcurl.def` exports are backed from here: `curl_easy_escape` and
//! `curl_easy_unescape`, together with the two ABI-compatibility forwarders
//! `curl_escape` and `curl_unescape` that `lib/escape.c:36-45` defines as
//! nothing but calls into them. `curl-rs-ffi` reaches [`escape`] and
//! [`unescape`] through `crate::url::escape`, so no crate-root name is added
//! for them.
//!
//! # The transformation this module owns, and the marshalling it does not
//!
//! The division of labour is deliberate and is the reason the signatures below
//! take `&[u8]` rather than a pointer and a length.
//!
//! This module owns every *transformation* decision: which bytes survive
//! unencoded, the case of the hex digits, the exact conditions under which a
//! `%` introduces an escape rather than standing for itself, and which decoded
//! bytes are acceptable. Those are the parts a caller can observe in the
//! output, and they are frozen by AAP section 0.8.1.
//!
//! The adapter in `curl-rs-ffi` owns the *marshalling*: turning
//! `(*const c_char, c_int)` into the slice passed here. That split is not an
//! aesthetic preference -- it is forced by the C contract. `lib/escape.c:59`
//! resolves the byte count as
//!
//! ```text
//! length = (inlength ? (size_t)inlength : strlen(string))
//! ```
//!
//! so a non-zero `inlength` is trusted **absolutely**: the C reads that many
//! bytes whether or not a NUL appears first, and whether or not the object is
//! that long. Two consequences are directly observable, and both are asserted
//! against the C oracle below:
//!
//! ```text
//! curl_easy_escape(NULL, "",   1)  ->  "%00"      /* escapes the terminator */
//! curl_easy_escape(NULL, "ab", 3)  ->  "ab%00"    /* same, one byte further */
//! ```
//!
//! "Read `n` bytes from a pointer" is exactly what
//! `core::slice::from_raw_parts` expresses and exactly what this crate may not
//! write: `crate` is `#![deny(unsafe_code)]` outside [`crate::ffi`], and the
//! obligation being discharged is the *caller's* promise about the object it
//! passed, which only the C boundary is in a position to state. So the shim
//! resolves the length, forms the slice under one `// SAFETY:` comment, and
//! this module receives a slice whose bounds are already someone else's
//! guarantee. Every row of the oracle is reproduced by that single rule --
//! resolve, slice, transform -- with no special case for the terminator-reading
//! rows above, which is the strongest evidence available that the boundary is
//! drawn in the right place.
//!
//! # `escape`: the unreserved set and the case of the hex digits
//!
//! `lib/escape.c:72` keeps a byte verbatim when `ISUNRESERVED(in)` holds and
//! otherwise emits `%` followed by two hex digits. `lib/curl_ctype.h:49`
//! defines that predicate as `ISALNUM(x) || ISURLPUNTCS(x)`, where
//! `ISURLPUNTCS` covers `-`, `.`, `_` and `~`. curl's `ISALNUM` is its own
//! ASCII-only table rather than `<ctype.h>`, so it is locale-independent and no
//! byte at or above `0x80` is ever alphanumeric. The resulting set is exactly
//! the 66 bytes [`is_unreserved`] accepts, and the oracle pins all 256
//! single-byte answers, so the table cannot drift.
//!
//! The digits are **uppercase**. `lib/escape.c:80` calls `Curl_hexbyte`, which
//! `lib/escape.c:222-227` implements over `Curl_udigits`; the lowercase table
//! `Curl_ldigits` belongs to `Curl_hexencode`, a different function with
//! different callers. Emitting lowercase would produce output that is
//! semantically equivalent and textually wrong, which AAP section 0.8.2 rules
//! out: a difference that is arguably as good has still failed.
//!
//! # `unescape`: the decode walk, and the strictness of `alloc > 2`
//!
//! `Curl_urldecode` (`lib/escape.c:105-154`) walks the input with a counter the
//! C calls `alloc`, holding the number of bytes still to be consumed. A `%` is
//! treated as an escape only when **all three** of these hold:
//!
//! ```text
//! alloc > 2  &&  ISXDIGIT(string[1])  &&  ISXDIGIT(string[2])
//! ```
//!
//! and otherwise the `%` is copied through as an ordinary byte. The comparison
//! is strictly greater, not `>=`, and the difference is observable rather than
//! theoretical -- decoding `"%41"` with an explicit length of 2 yields the two
//! literal bytes `%4`, because two remaining bytes are not more than two. The
//! oracle pins that row (`len_past_pct`) precisely so a `>=` typo fails.
//!
//! Because `alloc` counts down from the resolved length and the two lookahead
//! bytes are read only once `alloc > 2` is known, the C never reads past the
//! byte count it was given. The Rust below preserves that ordering, so the
//! indexing cannot panic; a test drives the boundary from both sides.
//!
//! `curl_easy_unescape` passes `REJECT_NADA` (`lib/escape.c:170-171`), which
//! accepts every decoded byte -- control characters and NUL included. That is
//! why the decoded output is a byte string rather than a C string, why the
//! function reports its length through an out-parameter, and why
//! `unescape("a%00b")` is three bytes long with a NUL in the middle.
//!
//! # What this module deliberately does not contain
//!
//! Three omissions, each recorded because its absence could otherwise be read
//! as an oversight.
//!
//! `REJECT_CTRL` and `REJECT_ZERO`, the other two modes of the `urlreject`
//! enumeration, have no caller here: `lib/escape.c:170` shows the exported
//! entry point using `REJECT_NADA` unconditionally, and the strict modes exist
//! for `lib/urlapi.c`, which is a separate module with its own findings. Adding
//! them now would land an item no code calls. When the URL API arrives, this is
//! the file it extends, and [`unescape`]'s walk is the function it
//! parameterises -- the rejection test belongs immediately after the byte is
//! decoded, at `lib/escape.c:139-143`.
//!
//! The C's `length > SIZE_MAX / 16` guard (`lib/escape.c:63-64`) has no Rust
//! counterpart, because there is no value of `input.len()` that can satisfy it.
//! A slice's length never exceeds `isize::MAX`, which is `usize::MAX / 2`
//! rounded down and therefore far below `usize::MAX / 16` multiplied out; the
//! guard is not merely unreachable on the four 64-bit targets of AAP section
//! 0.8.3 but unrepresentable for any valid slice. Writing the branch anyway
//! would add a condition that provably never holds, and it would have to
//! propagate a failure case through both signatures to report something that
//! cannot happen.
//!
//! The C's out-of-memory returns (`lib/escape.c:75`, `:82`, `:119`) likewise
//! have no counterpart: `Vec` aborts rather than reporting a failed growth, so
//! there is no `NULL` for this module to produce. Both functions are therefore
//! total, and the only `NULL` results in the oracle come from the argument
//! checks the shim performs before calling in.

/// Uppercase hex digits, matching `Curl_udigits`.
///
/// Named for the C table it stands in for so the choice of case is traceable
/// to `lib/escape.c:225-226` rather than looking like a free decision. The
/// lowercase counterpart `Curl_ldigits` is deliberately absent: nothing this
/// module implements uses it.
const UDIGITS: &[u8; 16] = b"0123456789ABCDEF";

/// Reproduces `ISUNRESERVED` from `lib/curl_ctype.h:49`.
///
/// `ISALNUM(x) || ISURLPUNTCS(x)`, spelled out over byte ranges because curl's
/// character classes are its own ASCII tables rather than `<ctype.h>` and are
/// therefore locale-independent by construction. The four punctuation bytes are
/// the ones RFC 3986 calls unreserved alongside the alphanumerics.
///
/// `const` so it can be used to build a lookup table in a test that checks all
/// 256 values against the oracle without depending on this function's own
/// control flow.
const fn is_unreserved(byte: u8) -> bool {
    matches!(byte,
        b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' | b'-' | b'.' | b'_' | b'~')
}

/// Reproduces `ISXDIGIT` combined with `curlx_hexval`.
///
/// Returns the numeric value of a single hexadecimal digit, or `None` when the
/// byte is not one. Folding the classification and the conversion into one
/// function mirrors how the decode walk uses them -- `lib/escape.c:127` tests
/// both digits before `:129-130` converts either -- and makes it impossible to
/// convert a byte that was never classified.
const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Percent-encodes `input`, reproducing `curl_easy_escape`.
///
/// Every byte of `input` is either copied verbatim, when [`is_unreserved`]
/// accepts it, or replaced by `%` and two **uppercase** hex digits. The result
/// is always valid ASCII and can never contain a NUL, so the caller may hand it
/// to C as a string without loss -- which is what makes
/// `curl_easy_escape`'s `char *` return sufficient where
/// `curl_easy_unescape` needs an explicit length.
///
/// `input` is the already-resolved byte range: this function has no view of a
/// terminator and applies no length convention of its own. See the module
/// documentation for why that resolution belongs to the caller.
///
/// An empty `input` yields an empty `Vec`, matching `lib/escape.c:60-61`, which
/// returns a duplicate of `""` rather than `NULL`. The distinction reaches the
/// application, so it is preserved deliberately.
///
/// # Examples
///
/// ```
/// use curl_rs_lib::url::escape::escape;
///
/// assert_eq!(escape(b"a b~c"), b"a%20b~c".to_vec());
/// // Uppercase hex, and no byte at or above 0x80 is ever unreserved.
/// assert_eq!(escape("é".as_bytes()), b"%C3%A9".to_vec());
/// // An interior NUL is escaped like any other reserved byte.
/// assert_eq!(escape(b"a\0b"), b"a%00b".to_vec());
/// ```
pub fn escape(input: &[u8]) -> Vec<u8> {
    // A lower bound on the result, not the C's `length * 3 + 1`. Reserving the
    // exact worst case would have to guard its own multiplication -- which is
    // what `lib/escape.c:63` is really doing -- whereas reserving the input
    // length is always allocatable, because the input already exists, and lets
    // `Vec` grow for the escaped remainder. The output is identical either
    // way; only the number of reallocations differs, and AAP section 0.1.1
    // makes performance a non-goal.
    let mut out = Vec::with_capacity(input.len());

    for &byte in input {
        if is_unreserved(byte) {
            out.push(byte);
        } else {
            out.push(b'%');
            out.push(UDIGITS[usize::from(byte >> 4)]);
            out.push(UDIGITS[usize::from(byte & 0x0F)]);
        }
    }

    out
}

/// Percent-decodes `input`, reproducing `curl_easy_unescape`.
///
/// A `%` is treated as introducing an escape only when at least three bytes
/// remain and the two that follow are both hexadecimal digits; in every other
/// case it is copied through literally, which is what makes `"abc%"`,
/// `"abc%4"` and `"%%41"` decode to `"abc%"`, `"abc%4"` and `"%A"` rather than
/// failing. Hex digits are accepted in either case.
///
/// This is `REJECT_NADA` behaviour (`lib/escape.c:170-171`): every decoded
/// byte is accepted, so the result can contain NUL and control bytes and is
/// therefore returned as a byte vector whose length is authoritative. The
/// function is total -- there is no input for which the C's
/// `CURLE_URL_MALFORMAT` path can be reached through this entry point, because
/// that path is guarded by the two reject modes this module does not
/// implement.
///
/// `input` is the already-resolved byte range, exactly as for [`escape`].
///
/// # Examples
///
/// ```
/// use curl_rs_lib::url::escape::unescape;
///
/// assert_eq!(unescape(b"%41%42%43"), b"ABC".to_vec());
/// // Either hex case decodes.
/// assert_eq!(unescape(b"%4a%4B"), b"JK".to_vec());
/// // A '%' that does not introduce two hex digits stands for itself.
/// assert_eq!(unescape(b"abc%4G"), b"abc%4G".to_vec());
/// // '+' is not a space: this is URL escaping, not form encoding.
/// assert_eq!(unescape(b"a+b"), b"a+b".to_vec());
/// // NUL survives, which is why the length is the return value's own.
/// assert_eq!(unescape(b"a%00b"), vec![b'a', 0, b'b']);
/// ```
pub fn unescape(input: &[u8]) -> Vec<u8> {
    // The result is never longer than the input, and is shorter by two bytes
    // for every escape decoded, so this reservation is an exact upper bound.
    let mut out = Vec::with_capacity(input.len());
    let mut index = 0usize;

    while index < input.len() {
        // The C's `alloc`: bytes still to be consumed, counted down from the
        // resolved length. Testing it BEFORE the two lookaheads is what keeps
        // the indexing below in bounds, and it is the order `lib/escape.c:126`
        // uses for the same reason.
        let remaining = input.len() - index;
        let byte = input[index];

        if byte == b'%' && remaining > 2 {
            if let (Some(high), Some(low)) =
                (hex_value(input[index + 1]), hex_value(input[index + 2]))
            {
                out.push((high << 4) | low);
                index += 3;
                continue;
            }
        }

        out.push(byte);
        index += 1;
    }

    out
}

#[cfg(test)]
mod tests {
    use super::{escape, hex_value, is_unreserved, unescape};

    /// Every row measured from the frozen `libcurl.so.4.8.0`.
    ///
    /// Self-describing by construction: each row carries the input object's
    /// bytes -- including its NUL terminator -- and the exact `inlength`
    /// argument, so the call is reconstructed rather than transcribed. That
    /// matters more than it sounds: several rows deliberately pass a length
    /// that reaches the terminator, and a hand-written input would have to
    /// encode that intent correctly to be testing anything at all.
    const ORACLE: &str = include_str!("escape_oracle.txt");

    /// Decodes one hex field of the oracle into bytes.
    fn from_hex(field: &str) -> Vec<u8> {
        assert!(
            field.len() % 2 == 0,
            "oracle hex field has an odd length: {field:?}"
        );
        (0..field.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&field[i..i + 2], 16)
                    .unwrap_or_else(|e| panic!("bad oracle hex {field:?}: {e}"))
            })
            .collect()
    }

    /// One parsed oracle row.
    struct Row<'a> {
        tag: &'a str,
        name: &'a str,
        /// The input object's bytes, or `None` when the C pointer was NULL.
        object: Option<Vec<u8>>,
        /// The `inlength` / `length` argument exactly as passed.
        arg_len: i32,
        /// The expected output bytes, or `None` when the C returned NULL.
        output: Option<Vec<u8>>,
        /// The `*olen` the C wrote, when the row reports one.
        olen: Option<i32>,
    }

    fn rows() -> Vec<Row<'static>> {
        ORACLE
            .lines()
            .filter(|line| !line.is_empty())
            .map(|line| {
                let f: Vec<&str> = line.split('\t').collect();
                assert!(
                    f.len() == 5 || f.len() == 6,
                    "unexpected oracle row shape: {line:?}"
                );
                Row {
                    tag: f[0],
                    name: f[1],
                    object: if f[2] == "NULL" {
                        None
                    } else {
                        Some(from_hex(f[2]))
                    },
                    arg_len: f[3].parse().expect("oracle arg_len"),
                    output: if f[4] == "NULL" {
                        None
                    } else {
                        Some(from_hex(f[4]))
                    },
                    olen: f.get(5).map(|s| {
                        s.strip_prefix("olen=")
                            .expect("oracle olen field")
                            .parse()
                            .expect("oracle olen value")
                    }),
                }
            })
            .collect()
    }

    /// Applies the C's length convention and returns the slice the engine sees.
    ///
    /// This is the marshalling rule `curl-rs-ffi` performs, reproduced here so
    /// the differential exercises the same composition the shipped code does.
    /// `None` means the C returned NULL before any transformation ran, which is
    /// the argument check rather than a transformation result.
    fn resolve(row: &Row<'_>) -> Option<Vec<u8>> {
        let object = row.object.as_ref()?;
        if row.arg_len < 0 {
            return None;
        }
        // `lib/escape.c:59` and `:115`: zero means "measure it", anything else
        // is taken at face value. The object carries its terminator, so its
        // strlen is one less than its length.
        let resolved = if row.arg_len == 0 {
            object.len() - 1
        } else {
            row.arg_len as usize
        };
        assert!(
            resolved <= object.len(),
            "oracle row {:?} would read outside its object; the oracle, not \
             the engine, is wrong",
            row.name
        );
        Some(object[..resolved].to_vec())
    }

    #[test]
    fn the_oracle_parses_and_covers_what_it_claims() {
        let rows = rows();
        assert_eq!(rows.len(), 815, "oracle row count changed");

        let count = |tag: &str| rows.iter().filter(|r| r.tag == tag).count();
        // 256 single-byte escapes + 11 escape edge cases.
        assert_eq!(count("ESC"), 267);
        assert_eq!(count("ESCL"), 3);
        // 512 exhaustive %XX rows (both hex cases) + 28 edge cases.
        assert_eq!(count("UNESC"), 540);
        assert_eq!(count("UNESCN"), 2);
        assert_eq!(count("UNESCL"), 3);

        // Every row that reports a length agrees with the bytes it reports,
        // which is the oracle checking itself before it is used as authority.
        for row in &rows {
            if let (Some(olen), Some(output)) = (row.olen, row.output.as_ref())
            {
                assert_eq!(
                    usize::try_from(olen).expect("non-negative olen"),
                    output.len(),
                    "oracle row {:?} disagrees with its own olen",
                    row.name
                );
            }
        }
    }

    #[test]
    fn escape_matches_the_c_oracle_on_every_row() {
        let mut checked = 0usize;
        for row in &rows() {
            if row.tag != "ESC" && row.tag != "ESCL" {
                continue;
            }
            match (resolve(row), row.output.as_ref()) {
                // The argument check rejected the call, so there is nothing
                // for this module to have produced. `resolve` reaching `None`
                // exactly when the C returned NULL is itself the assertion.
                (None, None) => {}
                (Some(input), Some(expected)) => {
                    assert_eq!(
                        &escape(&input),
                        expected,
                        "escape mismatch on row {:?} (input {input:02X?})",
                        row.name
                    );
                }
                (resolved, expected) => panic!(
                    "row {:?}: the argument check and the C disagree \
                     (resolved={:?}, expected={:?})",
                    row.name,
                    resolved.is_some(),
                    expected.is_some()
                ),
            }
            checked += 1;
        }
        assert_eq!(checked, 270, "escape rows checked");
    }

    #[test]
    fn unescape_matches_the_c_oracle_on_every_row() {
        let mut checked = 0usize;
        for row in &rows() {
            if !matches!(row.tag, "UNESC" | "UNESCN" | "UNESCL") {
                continue;
            }
            match (resolve(row), row.output.as_ref()) {
                (None, None) => {}
                (Some(input), Some(expected)) => {
                    let produced = unescape(&input);
                    // `UNESC` rows carry `*olen`, so their output field is the
                    // whole result. The other two tags do not: `UNESCN` passes
                    // `olen == NULL` and `UNESCL` is `curl_unescape`, which has
                    // no length parameter at all, so the only thing a C caller
                    // can measure is `strlen` -- and that is exactly what the
                    // oracle recorded. Comparing the NUL-truncated view for
                    // those two is therefore not a weakened assertion; it is
                    // the precise one, modelling what the C consumer observes.
                    // The full result is still pinned, for the same bytes, by
                    // the `UNESC` rows that decode NUL.
                    let comparable: &[u8] = if row.tag == "UNESC" {
                        &produced
                    } else {
                        let visible = produced
                            .iter()
                            .position(|&b| b == 0)
                            .unwrap_or(produced.len());
                        &produced[..visible]
                    };
                    assert_eq!(
                        comparable,
                        expected.as_slice(),
                        "unescape mismatch on row {:?} (input {input:02X?})",
                        row.name
                    );
                    // For the rows that carry one, the C's `*olen` is the
                    // authority on the result's length, and it is the only
                    // way the NUL-carrying rows are distinguishable at all.
                    if let Some(olen) = row.olen {
                        assert_eq!(
                            i32::try_from(produced.len()).expect("fits"),
                            olen,
                            "unescape length mismatch on row {:?}",
                            row.name
                        );
                    }
                }
                (resolved, expected) => panic!(
                    "row {:?}: the argument check and the C disagree \
                     (resolved={:?}, expected={:?})",
                    row.name,
                    resolved.is_some(),
                    expected.is_some()
                ),
            }
            checked += 1;
        }
        assert_eq!(checked, 545, "unescape rows checked");
    }

    #[test]
    fn the_unreserved_set_is_exactly_the_sixty_six_bytes_c_keeps() {
        // Derived from the oracle rather than restated: a `byteNN` row whose
        // output is the single input byte is a byte C left alone.
        let mut from_oracle = [false; 256];
        let mut seen = 0usize;
        for row in &rows() {
            let Some(rest) = row.name.strip_prefix("byte") else {
                continue;
            };
            let byte = u8::from_str_radix(rest, 16).expect("byte row name");
            let output = row.output.as_ref().expect("byte row has output");
            from_oracle[usize::from(byte)] = output.as_slice() == [byte];
            seen += 1;
        }
        assert_eq!(seen, 256, "the oracle covers every byte value");

        for byte in 0..=255u8 {
            assert_eq!(
                is_unreserved(byte),
                from_oracle[usize::from(byte)],
                "is_unreserved disagrees with C on byte {byte:#04X}"
            );
        }
        assert_eq!(
            (0..=255u8).filter(|&b| is_unreserved(b)).count(),
            66,
            "62 alphanumerics plus the four of ISURLPUNTCS"
        );
        // Named individually because a range typo would keep the count.
        for byte in *b"-._~" {
            assert!(is_unreserved(byte), "ISURLPUNTCS byte {byte:?}");
        }
        for byte in [b'+', b'/', b' ', b'%', b'*', b'!', 0x7F, 0x80, 0xFF] {
            assert!(!is_unreserved(byte), "byte {byte:#04X} must be escaped");
        }
    }

    #[test]
    fn the_hex_digits_are_uppercase_and_both_cases_decode() {
        // Encoding is one-way: only the uppercase spelling is ever produced.
        assert_eq!(escape(&[0xAB]), b"%AB".to_vec());
        assert_eq!(escape(&[0xef]), b"%EF".to_vec());
        assert!(
            !escape(&[0xAB, 0xCD, 0xEF])
                .iter()
                .any(|b| b.is_ascii_lowercase()),
            "escape must never emit a lowercase hex digit"
        );

        // Decoding accepts either, and the two must agree byte for byte.
        for byte in 0..=255u8 {
            let upper = format!("%{byte:02X}");
            let lower = format!("%{byte:02x}");
            assert_eq!(unescape(upper.as_bytes()), vec![byte]);
            assert_eq!(unescape(lower.as_bytes()), vec![byte]);
        }

        // The classifier accepts exactly the 22 hex digits and nothing else.
        let accepted: Vec<u8> =
            (0..=255u8).filter(|&b| hex_value(b).is_some()).collect();
        assert_eq!(accepted.len(), 22);
        for (byte, value) in [
            (b'0', 0u8),
            (b'9', 9),
            (b'a', 10),
            (b'f', 15),
            (b'A', 10),
            (b'F', 15),
        ] {
            assert_eq!(hex_value(byte), Some(value));
        }
        for byte in [b'g', b'G', b'%', b' ', 0x00, 0xFF] {
            assert_eq!(hex_value(byte), None, "byte {byte:#04X} is not hex");
        }
    }

    #[test]
    fn the_escape_test_is_strictly_greater_than_two() {
        // The boundary from both sides. Three bytes remaining is an escape;
        // two is not, and a `>=` typo would decode the second row.
        assert_eq!(unescape(b"%41"), vec![0x41]);
        assert_eq!(unescape(b"%4"), b"%4".to_vec());
        assert_eq!(unescape(b"%"), b"%".to_vec());
        assert_eq!(unescape(b""), Vec::<u8>::new());
        // And the same boundary reached by exhausting a longer input, which is
        // the case the counting -- rather than the initial length -- decides.
        assert_eq!(unescape(b"ab%41"), b"abA".to_vec());
        assert_eq!(unescape(b"ab%4"), b"ab%4".to_vec());
    }

    #[test]
    fn escape_and_unescape_round_trip_over_every_byte() {
        // Not a property the C documents, but one it has: the escaped form of
        // any byte string decodes back to it, because every byte is either
        // unreserved -- and so not a '%' -- or emitted as a full triple.
        let all: Vec<u8> = (0..=255u8).collect();
        assert_eq!(unescape(&escape(&all)), all);

        // Including the sequences most likely to confuse the walk.
        for probe in [
            b"%".as_slice(),
            b"%%",
            b"%41",
            b"100%",
            b"a+b",
            b"\0\0",
            b"%%%%",
        ] {
            assert_eq!(
                unescape(&escape(probe)),
                probe.to_vec(),
                "round trip failed for {probe:02X?}"
            );
        }
    }

    #[test]
    fn an_empty_input_escapes_to_an_empty_result_not_a_failure() {
        // `lib/escape.c:60-61` returns a duplicate of "" rather than NULL, and
        // the difference is visible to the application: one is a pointer it
        // must free, the other is an error. The oracle's `empty_len0` row
        // reports an empty output, not NULL.
        assert_eq!(escape(b""), Vec::<u8>::new());
        assert_eq!(unescape(b""), Vec::<u8>::new());

        let row = rows()
            .into_iter()
            .find(|r| r.tag == "ESC" && r.name == "empty_len0")
            .expect("the oracle carries the empty-input row");
        assert_eq!(row.output, Some(Vec::new()), "C returned \"\", not NULL");
    }

    #[test]
    fn the_strlen_reported_rows_hide_a_nul_that_is_still_pinned_elsewhere() {
        // Guards the one place the differential above compares a truncated
        // view. `nolen_basic` decodes to three bytes, but the oracle could only
        // record the one byte before the NUL, so a decode that dropped the tail
        // entirely would match that row. It does not go unchecked: the full
        // three-byte result is asserted here, and the identical byte sequence
        // is pinned losslessly by the `embedded_nul` row, which carries `olen`.
        assert_eq!(unescape(b"%41%00%42"), vec![0x41, 0x00, 0x42]);

        let rows = rows();
        let nolen = rows
            .iter()
            .find(|r| r.tag == "UNESCN" && r.name == "nolen_basic")
            .expect("the oracle carries the strlen-reported row");
        assert_eq!(
            nolen.output.as_deref(),
            Some([0x41].as_slice()),
            "the oracle recorded only the pre-NUL prefix, as strlen forces"
        );
        assert!(
            nolen.olen.is_none(),
            "a UNESCN row must not claim a length; that is what makes it lossy"
        );

        let embedded = rows
            .iter()
            .find(|r| r.tag == "UNESC" && r.name == "embedded_nul")
            .expect("the oracle carries the lossless counterpart");
        assert_eq!(embedded.olen, Some(3), "olen counts the NUL");
        assert_eq!(
            embedded.output.as_deref(),
            Some([0x61, 0x00, 0x62].as_slice())
        );
    }

    #[test]
    fn reject_nada_accepts_nul_and_control_bytes() {
        // The mode `curl_easy_unescape` passes accepts everything, which is
        // why the result is a byte string. If the strict modes were ever wired
        // in by default, these would start failing rather than silently
        // truncating.
        assert_eq!(unescape(b"a%00b"), vec![b'a', 0x00, b'b']);
        assert_eq!(unescape(b"%00%00"), vec![0x00, 0x00]);
        assert_eq!(unescape(b"%01%1F%7F"), vec![0x01, 0x1F, 0x7F]);
        for byte in 0..0x20u8 {
            assert_eq!(unescape(format!("%{byte:02X}").as_bytes()), vec![byte]);
        }
    }
}
