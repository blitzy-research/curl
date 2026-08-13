//***************************************************************************
//                                  _   _ ____  _
//  Project                     ___| | | |  _ \| |
//                             / __| | | | |_) | |
//                            | (__| |_| |  _ <| |___
//                             \___|\___/|_| \_\_____|
//
// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// This software is licensed as described in the file COPYING, which
// you should have received as part of this distribution. The terms
// are also available at https://curl.se/docs/copyright.html.
//
// You may opt to use, copy, modify, merge, publish, distribute and/or sell
// copies of the Software, and permit persons to whom the Software is
// furnished to do so, under the terms of the COPYING file.
//
// This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
// KIND, either express or implied.
//
// SPDX-License-Identifier: curl
//
//***************************************************************************

//! `NO_PROXY` and `--noproxy` host matching -- supersedes `lib/noproxy.c` and
//! `lib/noproxy.h`.
//!
//! # What this module is
//!
//! A pure predicate, and nothing else. It answers one question -- "does this
//! host name appear in this no-proxy list?" -- from its two arguments alone,
//! touching no connection, no socket, no clock and no shared state. It
//! therefore implements NO connection filter and registers nothing in the
//! chain that [`crate::conn`] owns: every other module in this directory is
//! a filter, and this one deliberately is not.
//!
//! It is consulted BEFORE the proxy filters are inserted. That ordering is
//! the whole point of the module: a match means the filters are never built,
//! so a matching host reaches its origin directly. `tests/data/test1212`
//! is the corpus statement of exactly that -- `--noproxy %HOSTIP` given
//! alongside `--socks5 non-existing-host.haxx.se:1080`, with a `<protocol>`
//! block that expects an ordinary direct `GET`. The SOCKS proxy named on the
//! command line is deliberately unresolvable, so the fixture passes only if
//! this predicate suppressed it.
//!
//! # Why the matching rules are transcribed rather than reimplemented
//!
//! `NO_PROXY` has no specification. What circulates instead is a convention,
//! described in blog posts and implemented slightly differently by every tool
//! that reads the variable, and curl's behaviour is not that convention.
//! These rules are CLI-visible and frozen, so each of the following is
//! preserved exactly as `lib/noproxy.c` has it, and none of them is a bug to
//! be fixed here:
//!
//! * A bare `*` overrides everything, but ONLY as the entire value
//!   (`:201-202`). As one token among several it is an ordinary name that
//!   matches nothing.
//! * `/0` means EXACT equality rather than "match everything" (`:60`, `:74`),
//!   while an IPv6 `/0` is promoted to `/128` and reaches exactness by the
//!   other route (`:87-88`).
//! * A token of 128 bytes or more can never match an address (`:153-156`).
//! * A prefix length above 128 is refused by the PARSER (`:166`) and one
//!   above 32 by the IPv4 matcher (`:51`), so the two refusals happen in
//!   different places.
//! * One trailing dot is ignored on a token (`:123-125`) and one on a host
//!   name (`:215-217`), and one LEADING dot is ignored on a token
//!   (`:127-131`) -- but `*` is not a wildcard inside one.
//! * A tail match must land on a label boundary, so `nonexample.com` misses
//!   `example.com` (`:141-142`).
//! * Anything other than a comma between two tokens ENDS the scan
//!   (`:247-249`), while any number of consecutive commas is skipped, so
//!   empty tokens are tolerated (`:250-252`).
//! * Blanks are space and tab only -- a newline is not a blank
//!   (`lib/curl_ctype.h:45`).
//!
//! # Bytes, not `str`
//!
//! Both arguments are `&[u8]`. `NO_PROXY` arrives from the environment and
//! `--noproxy` from the command line, and neither is guaranteed to be UTF-8;
//! the C reads both as byte strings and compares them byte by byte, so a
//! `&str` signature would have to reject input that curl accepts. The
//! comparison the C reaches for is `curl_strnequal`, which folds only the 26
//! ASCII letter pairs, so [`crate::util::strcase::ncasecompare`] is used
//! rather than [`str::to_lowercase`] -- which allocates and applies Unicode
//! folding that curl does not do.

use crate::util::inet;
use crate::util::strcase;
use crate::util::strparse;

/// How the name under test was classified -- `enum nametype`,
/// `lib/noproxy.c:112-116`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NameType {
    /// Not parseable as an address, so treated as a host name. `TYPE_HOST`.
    Host,
    /// A dotted quad. `TYPE_IPV4`.
    Ipv4,
    /// An IPv6 literal. `TYPE_IPV6`.
    Ipv6,
}

/// The prefix of `bytes` up to its first zero, or all of it when it has none.
fn cstr(bytes: &[u8]) -> &[u8] {
    match bytes.iter().position(|&byte| byte == 0) {
        Some(end) => &bytes[..end],
        None => bytes,
    }
}

/// True when `ipv4` lies inside the CIDR range `network`/`bits`.
#[must_use]
fn cidr4_match(ipv4: &[u8], network: &[u8], bits: u32) -> bool {
    // `if(bits > 32) return FALSE;` with the C's comment: "strange input".
    if bits > 32 {
        return false;
    }

    // `if(curlx_inet_pton(AF_INET, ipv4, &address) != 1) return FALSE;`
    let address = match inet::pton4(ipv4) {
        Some(address) => u32::from_be_bytes(address),
        None => return false,
    };
    // `if(curlx_inet_pton(AF_INET, network, &check) != 1) return FALSE;`
    let check = match inet::pton4(network) {
        Some(check) => u32::from_be_bytes(check),
        None => return false,
    };

    // `if(bits && (bits != 32))`
    if bits != 0 && bits != 32 {
        // `unsigned int mask = 0xffffffff << (32 - bits);`
        //
        // The literal is the C's, digit for digit, and the shift distance is
        // in 1..=31 for the reason the documentation above sets out.
        let mask: u32 = 0xffffffff << (32 - bits);

        // `if((haddr ^ hcheck) & mask) return FALSE; return TRUE;`
        //
        // The C computes `haddr` and `hcheck` with `htonl` here; both are
        // already host-order above. The XOR-then-mask shape is kept rather
        // than rewritten as two masked comparisons so that this line reads
        // as its original does.
        return (address ^ check) & mask == 0;
    }

    // `return address == check;` -- reached by BOTH `bits == 0` and
    // `bits == 32`.
    address == check
}

/// True when `ipv6` lies inside the CIDR range `network`/`bits`.
#[must_use]
fn cidr6_match(ipv6: &[u8], network: &[u8], bits: u32) -> bool {
    // `if(!bits) bits = 128;`
    let bits = if bits == 0 { 128 } else { bits };

    // `bytes = bits / 8; rest = bits & 0x07;`
    let bytes = bits / 8;
    let rest = bits & 0x07;

    // `if((bytes > 16) || ((bytes == 16) && rest)) return FALSE;`
    if bytes > 16 || (bytes == 16 && rest != 0) {
        return false;
    }
    // Lossless: the test above bounds `bytes` at 16, and every target of this
    // workspace is 64-bit, so the value fits a `usize` with room to spare.
    let bytes = bytes as usize;

    // `if(curlx_inet_pton(AF_INET6, ipv6, address) != 1) return FALSE;`
    let address = match inet::pton6(ipv6) {
        Some(address) => address,
        None => return false,
    };
    // `if(curlx_inet_pton(AF_INET6, network, check) != 1) return FALSE;`
    let check = match inet::pton6(network) {
        Some(check) => check,
        None => return false,
    };

    // `if(bytes && memcmp(address, check, bytes)) return FALSE;`
    //
    // The `bytes &&` guard is redundant in Rust -- two empty slices compare
    // equal -- and is kept so that the line still reads as the C's.
    if bytes != 0 && address[..bytes] != check[..bytes] {
        return false;
    }

    // `if(rest && ((address[bytes] ^ check[bytes]) & (0xff << (8 - rest))))`
    if rest != 0 {
        debug_assert!(
            bytes < inet::IN6ADDRSZ,
            "the bytes == 16 && rest refusal above bounds bytes at 15 here"
        );

        // The C shifts an `int`, so `0xff << (8 - rest)` can carry bits above
        // the eighth -- 0x7f80 when `rest` is 1. They are then masked against
        // a value that came from an `unsigned char` XOR, so only the low
        // eight ever contribute. A `u8` shift drops them instead of carrying
        // them, which is the same mask with the dead high bits removed.
        let mask: u8 = 0xff << (8 - rest);
        if (address[bytes] ^ check[bytes]) & mask != 0 {
            return false;
        }
    }

    // `return TRUE;`
    true
}

/// True when the host name `name` matches the no-proxy token `token`.
///
/// # Token normalisation, in the C's order
///
/// A note for anyone diffing this against the original: the C's trailing-dot
/// test at `:124` is `if(token[tokenlen - 1] == '.')` with NO guard on
/// `tokenlen`, while the leading-dot test at `:127` does guard. The
/// asymmetry is harmless there because the only caller dispatches a token
/// only when `tokenlen` is non-zero (`:234`), so the read is always in
/// bounds. Here the emptiness test is written out, the caller's guarantee is
/// asserted, and the behaviour is identical.
///
/// # The three cases, labelled as the C labels them
///
/// The comment block at `:132-135` names them, and its own worked example is
/// the one that matters most:
///
/// ```text
/// A: example.com matches 'example.com'
/// B: www.example.com matches 'example.com'
/// C: nonexample.com DOES NOT match 'example.com'
/// ```
#[must_use]
fn match_host(token: &[u8], name: &[u8]) -> bool {
    debug_assert!(
        !token.is_empty(),
        "the tokenizer dispatches a token only when it has bytes"
    );

    let mut token = token;

    // `if(token[tokenlen - 1] == '.') tokenlen--;` -- ignore trailing dots in
    // the token to check.
    if token.last() == Some(&b'.') {
        token = &token[..token.len() - 1];
    }

    // `if(tokenlen && (*token == '.')) { token++; tokenlen--; }` -- ignore
    // leading token dot as well. The token can be empty by now: a token of
    // exactly `.` loses its only byte above.
    if token.first() == Some(&b'.') {
        token = &token[1..];
    }

    if token.len() == name.len() {
        // Case A, exact match. `curl_strnequal(token, name, namelen)`.
        strcase::ncasecompare(token, name, name.len())
    } else if token.len() < name.len() {
        // Case B, tail match against a domain.
        let offset = name.len() - token.len();
        name[offset - 1] == b'.'
            && strcase::ncasecompare(token, &name[offset..], token.len())
    } else {
        // Case C passes through, not a match. A token longer than the name
        // cannot be a tail of it.
        false
    }
}

/// The size of the C's fixed `checkip` buffer -- `char checkip[128]`,
/// `lib/noproxy.c:153`.
const CHECKIP_LEN: usize = 128;

/// The largest prefix length the `/bits` parser will accept --
/// `curlx_str_number(&p, &value, 128)`, `lib/noproxy.c:166`.
const MAX_PREFIX: i64 = 128;

/// True when the address `name` matches the no-proxy token `token`, which may
/// carry a `/bits` CIDR suffix.
///
/// # The `/bits` parse is strict at both ends
///
/// `if(curlx_str_number(&p, &value, 128) || *p) return FALSE;` is two
/// refusals written as one line, and both are observable:
///
/// * The parse itself must succeed. At least one decimal digit must follow
///   the slash, so `192.168.0.0/a16` fails, and the value must not exceed
///   [`MAX_PREFIX`], so `::1/129` fails. Leading zeros are accepted, because
///   `curlx_str_number` accepts them -- `/008` is `/8`.
/// * Nothing may follow the digits. `*p` is the C's terminator test, so
///   `192.168.0.0/16a` fails.
#[must_use]
fn match_ip(kind: NameType, token: &[u8], name: &[u8]) -> bool {
    // `if(tokenlen >= sizeof(checkip)) return FALSE;` -- "this cannot match".
    if token.len() >= CHECKIP_LEN {
        return false;
    }

    // `unsigned int bits = 0;` and, in place of the copy into `checkip`, the
    // token itself: `memcpy(checkip, token, tokenlen); checkip[tokenlen] = 0;`
    // produces a string holding exactly these bytes.
    let mut bits: u32 = 0;
    let mut network = token;

    // `slash = strchr(checkip, '/'); if(slash) { ... }`
    if let Some(slash) = token.iter().position(|&byte| byte == b'/') {
        // `const char *p = &slash[1];`
        let mut cursor = &token[slash + 1..];

        // `if(curlx_str_number(&p, &value, 128) || *p) return FALSE;`
        let value = match strparse::str_number(&mut cursor, MAX_PREFIX) {
            Ok(value) => value,
            Err(_) => return false,
        };
        if !cursor.is_empty() {
            return false;
        }

        // `bits = (unsigned int)value;`
        //
        // In range by construction: the parser accepts no sign and was given
        // a ceiling of 128, so the value is in 0..=128.
        debug_assert!(
            (0..=MAX_PREFIX).contains(&value),
            "str_number bounds the value at MAX_PREFIX and rejects a sign"
        );
        bits = value as u32;

        // `*slash = 0;` -- null-terminate there.
        network = &token[..slash];
    }

    match kind {
        // `if(type == TYPE_IPV6) return Curl_cidr6_match(name, checkip, bits);`
        NameType::Ipv6 => cidr6_match(name, network, bits),
        // `else return Curl_cidr4_match(name, checkip, bits);`
        //
        // The C's `else` covers `TYPE_IPV4` and, unreachably, `TYPE_HOST`:
        // [`check_noproxy`] sends a host name to [`match_host`] instead. The
        // arm is written out rather than left to a wildcard so that adding a
        // fourth classification would be a compile error here.
        NameType::Ipv4 | NameType::Host => cidr4_match(name, network, bits),
    }
}

/// True when `name` appears in the no-proxy list `no_proxy`, and therefore
/// **the proxy must NOT be used** for it.
#[allow(dead_code)] // proxy selection calls it.
#[must_use]
pub(crate) fn check_noproxy(name: &[u8], no_proxy: &[u8]) -> bool {
    // C string semantics, applied once. See `cstr` for why.
    let name = cstr(name);
    let no_proxy = cstr(no_proxy);

    // `if(!name || name[0] == '\0') return FALSE;`
    if name.is_empty() {
        return false;
    }

    // `if(no_proxy && no_proxy[0]) {` -- the whole remaining body is inside
    // this test, so an absent or empty list falls through to FALSE.
    if no_proxy.is_empty() {
        return false;
    }

    // `if(!strcmp("*", no_proxy)) return TRUE;`
    if no_proxy == b"*" {
        return true;
    }

    // "NO_PROXY was specified and it was not just an asterisk"
    let (kind, subject) = if inet::pton4(name).is_some() {
        // `if(curlx_inet_pton(AF_INET, name, &address) == 1) type = TYPE_IPV4;`
        (NameType::Ipv4, name)
    } else if inet::pton6(name).is_some() {
        // `else if(curlx_inet_pton(AF_INET6, name, &address) == 1)
        //    type = TYPE_IPV6;`
        (NameType::Ipv6, name)
    } else {
        // `else { if(name[namelen - 1] == '.') namelen--; }` -- ignore
        // trailing dots in the hostname. The index is in bounds because the
        // emptiness test above proved the name has at least one byte, and the
        // result may be empty: a name of exactly `.` trims to nothing, which
        // [`match_host`] handles in its case A.
        let namelen = if name[name.len() - 1] == b'.' {
            name.len() - 1
        } else {
            name.len()
        };
        (NameType::Host, &name[..namelen])
    };

    // `const char *p = no_proxy;` and `while(*p) {`
    let mut cursor = no_proxy;
    while !cursor.is_empty() {
        // `curlx_str_passblanks(&p);` -- pass blanks.
        strparse::str_passblanks(&mut cursor);

        // `token = p; while(*p && !ISBLANK(*p) && (*p != ',')) { p++;
        //  tokenlen++; }` -- pass over the pattern.
        let end = cursor
            .iter()
            .position(|&byte| strparse::is_blank(byte) || byte == b',')
            .unwrap_or(cursor.len());
        let (token, rest) = cursor.split_at(end);
        cursor = rest;

        // `if(tokenlen) { ... if(match) return TRUE; }`
        if !token.is_empty() {
            let matched = match kind {
                // `if(type == TYPE_HOST) match = match_host(...);`
                NameType::Host => match_host(token, subject),
                // `else match = match_ip(type, token, name);`
                NameType::Ipv4 | NameType::Ipv6 => {
                    match_ip(kind, token, subject)
                }
            };
            if matched {
                return true;
            }
        }

        // `curlx_str_passblanks(&p);` -- pass blanks after pattern.
        strparse::str_passblanks(&mut cursor);

        // `if(*p != ',') break;` -- if not a comma, this ends the loop. The
        // end of the value is not a comma either, so this is also how a
        // well-formed list finishes.
        if cursor.first() != Some(&b',') {
            break;
        }

        // `while(*p == ',') p++;` -- pass any number of commas.
        while cursor.first() == Some(&b',') {
            cursor = &cursor[1..];
        }
    }

    // `return FALSE;`
    false
}

// The C unit test builds three tables and walks them, counting mismatches.
// Its rows are transcribed here row for row, in the C's own order, so that a
// row added upstream can be added here by reading a diff. The C guards its
// IPv6 rows with `#ifdef USE_IPV6` and its whole body with
// `#if defined(DEBUGBUILD) && !defined(CURL_DISABLE_PROXY)`; none of those
// three conditions has an analogue in this crate, so every row runs
// unconditionally.
#[cfg(test)]
mod tests {
    use super::{
        check_noproxy, cidr4_match, cidr6_match, cstr, match_host, NameType,
    };

    /// [`check_noproxy`] over text, which is what every row of the C's table
    /// holds.
    fn check(name: &str, no_proxy: &str) -> bool {
        check_noproxy(name.as_bytes(), no_proxy.as_bytes())
    }

    /// [`cidr4_match`] over text.
    fn cidr4(ipv4: &str, network: &str, bits: u32) -> bool {
        cidr4_match(ipv4.as_bytes(), network.as_bytes(), bits)
    }

    /// [`cidr6_match`] over text.
    fn cidr6(ipv6: &str, network: &str, bits: u32) -> bool {
        cidr6_match(ipv6.as_bytes(), network.as_bytes(), bits)
    }

    /// `unit1614.c:43-54`, the `list4[]` table, without its NULL end marker.
    ///
    /// Twelve rows of `(address, network, bits, matches)`. The first three are
    /// the ones worth reading twice: `/33` never matches, `/32` is exact, and
    /// `/0` is ALSO exact -- which is why the tenth through twelfth rows,
    /// which pair two different addresses, are false at 8, 32 and 0 alike.
    const CIDR4_ROWS: &[(&str, &str, u32, bool)] = &[
        ("192.160.0.1", "192.160.0.1", 33, false),
        ("192.160.0.1", "192.160.0.1", 32, true),
        ("192.160.0.1", "192.160.0.1", 0, true),
        ("192.160.0.1", "192.160.0.1", 24, true),
        ("192.160.0.1", "192.160.0.1", 26, true),
        ("192.160.0.1", "192.160.0.1", 20, true),
        ("192.160.0.1", "192.160.0.1", 18, true),
        ("192.160.0.1", "192.160.0.1", 12, true),
        ("192.160.0.1", "192.160.0.1", 8, true),
        ("192.160.0.1", "10.0.0.1", 8, false),
        ("192.160.0.1", "10.0.0.1", 32, false),
        ("192.160.0.1", "10.0.0.1", 0, false),
    ];

    /// `unit1614.c:59-63`, the `list6[]` table, without its NULL end marker.
    ///
    /// Five rows. `0:0::1` is the same address as `::1` written the long way,
    /// which is what makes the third and fourth rows a test of the parser as
    /// much as of the mask, and `/129` is refused for the reason
    /// [`cidr6_match`] documents.
    const CIDR6_ROWS: &[(&str, &str, u32, bool)] = &[
        ("::1", "::1", 0, true),
        ("::1", "::1", 128, true),
        ("::1", "0:0::1", 128, true),
        ("::1", "0:0::1", 129, false),
        (
            "fe80::ab47:4396:55c9:8474",
            "fe80::ab47:4396:55c9:8474",
            64,
            true,
        ),
    ];

    /// The 128-byte token of `unit1614.c:90-92`, which cannot match because
    /// it does not fit the C's `checkip` buffer.
    const TOKEN_128: &str = concat!(
        "localhost,127.0.0.1.127.0.0.1.127.0.0.1.127.0.0.1.",
        "127.0.0.1.127.0.0.1.127.0.0.1.127.0.0.1.127.0.0.1.127.0.0.1.127.",
        "0.0.1.127.0.0.1.127.0.0.",
    );

    /// The 127-byte token of `unit1614.c:93-95`, one byte shorter, which
    /// FITS the buffer and then fails for the ordinary reason that it is not
    /// an address.
    const TOKEN_127: &str = concat!(
        "localhost,127.0.0.1.127.0.0.1.127.0.0.1.127.0.0.1.",
        "127.0.0.1.127.0.0.1.127.0.0.1.127.0.0.1.127.0.0.1.127.0.0.1.127.",
        "0.0.1.127.0.0.1.127.0.0",
    );

    /// The six `no_proxy` values the C's table repeats, named so that every
    /// row below fits one line.
    const BLANK_SEPARATED: &str = "localhost .example.com .example.de";
    /// `:74`: both domain tokens carry a leading dot.
    const LEADING_DOTS: &str = "localhost,.example.com,.example.de";
    /// `:78`: a token with dots at BOTH ends.
    const DOTS_BOTH_ENDS: &str = "localhost,.example.com.,.example.de";
    /// `:79`: a fully qualified token with a trailing dot.
    const TRAILING_DOT: &str = "localhost,www.example.com.,.example.de";
    /// `:80`: the domain token has NO leading dot, which is what makes
    /// the tail match rather than the leading-dot rule do the work.
    const NO_LEADING_DOT: &str = "localhost,example.com,.example.de";
    /// `:151`: a run of five commas and a long run of blanks.
    const COMMA_RUN: &str = "foo,,,,,              bar, ::1/64";
    /// `:154`: a near miss -- `www2` rather than `www`, and a different
    /// top-level domain on the second token.
    const NEAR_MISS: &str = "www2.example.com, .example.net";

    /// `unit1614.c:73-156`, the `list[]` table, without its NULL end marker.
    ///
    /// Rows of `(name, no_proxy, matches)`. The C's IPv6 block is inlined in
    /// place rather than lifted out, so the order matches the original.
    const NOPROXY_ROWS: &[(&str, &str, bool)] = &[
        ("www.example.com", BLANK_SEPARATED, false),
        ("www.example.com", LEADING_DOTS, true),
        ("www.example.com.", LEADING_DOTS, true),
        ("example.com", LEADING_DOTS, true),
        ("example.com.", LEADING_DOTS, true),
        ("www.example.com", DOTS_BOTH_ENDS, true),
        ("www.example.com", TRAILING_DOT, true),
        ("example.com", NO_LEADING_DOT, true),
        ("example.com.", NO_LEADING_DOT, true),
        ("nexample.com", NO_LEADING_DOT, false),
        ("www.example.com", NO_LEADING_DOT, true),
        ("127.0.0.1", "127.0.0.1,localhost", true),
        ("127.0.0.1", "127.0.0.1,localhost,", true),
        ("127.0.0.1", "127.0.0.1/8,localhost,", true),
        ("127.0.0.1", "127.0.0.1/28,localhost,", true),
        ("127.0.0.1", "127.0.0.1/31,localhost,", true),
        ("127.0.0.1", "localhost,127.0.0.1", true),
        ("127.0.0.1", TOKEN_128, false),
        ("127.0.0.1", TOKEN_127, false),
        ("localhost", "localhost,127.0.0.1", true),
        ("localhost", "127.0.0.1,localhost", true),
        ("foobar", "barfoo", false),
        ("foobar", "foobar", true),
        ("192.168.0.1", "foobar", false),
        ("192.168.0.1", "192.168.0.0/16", true),
        ("192.168.0.1", "192.168.0.0/16a", false),
        ("192.168.0.1", "192.168.0.0/16 ", true),
        ("192.168.0.1", "192.168.0.0/a16", false),
        ("192.168.0.1", "192.168.0.0/ 16", false),
        ("192.168.0.1", "192.168.0.0/24", true),
        ("192.168.0.1", "192.168.0.0/32", false),
        ("192.168.0.1", "192.168.0.1/32", true),
        ("192.168.0.1", "192.168.0.1/33", false),
        ("192.168.0.1", "192.168.0.0", false),
        ("192.168.1.1", "192.168.0.0/24", false),
        ("192.168.1.1", "192.168.0.0/33", false),
        ("192.168.1.1", "foo, bar, 192.168.0.0/24", false),
        ("192.168.1.1", "foo, bar, 192.168.0.0/16", true),
        ("::1", "foo, bar, 192.168.0.0/16", false),
        ("::1", "foo, bar, ::1/64", true),
        ("::1", "::1/64", true),
        ("::1", "::1/96", true),
        ("::1", "::1/129", false),
        ("::1", "::1/128", true),
        ("::1", "::1/127", true),
        ("::1", "::1/a127", false),
        ("::1", "::1/127a", false),
        ("::1", "::1/ 127", false),
        ("::1", "::1/127 ", true),
        ("::1", "::1/126", true),
        ("::1", "::1/125", true),
        ("::1", "::1/124", true),
        ("::1", "::1/123", true),
        ("::1", "::1/122", true),
        ("2001:db8:8000::1", "2001:db8::/65", false),
        ("2001:db8:8000::1", "2001:db8::/66", false),
        ("2001:db8:8000::1", "2001:db8::/67", false),
        ("2001:db8:8000::1", "2001:db8::/68", false),
        ("2001:db8:8000::1", "2001:db8::/69", false),
        ("2001:db8:8000::1", "2001:db8::/70", false),
        ("2001:db8:8000::1", "2001:db8::/71", false),
        ("2001:db8:8000::1", "2001:db8::/72", false),
        ("2001:db8::1", "2001:db8::/65", true),
        ("2001:db8::1", "2001:db8::/66", true),
        ("2001:db8::1", "2001:db8::/67", true),
        ("2001:db8::1", "2001:db8::/68", true),
        ("2001:db8::1", "2001:db8::/69", true),
        ("2001:db8::1", "2001:db8::/70", true),
        ("2001:db8::1", "2001:db8::/71", true),
        ("2001:db8::1", "2001:db8::/72", true),
        ("::1", "::1/129", false),
        ("bar", "foo, bar, ::1/64", true),
        ("BAr", "foo, bar, ::1/64", true),
        ("BAr", COMMA_RUN, true),
        ("www.example.com", "foo, .example.com", true),
        ("www.example.com", NEAR_MISS, false),
        ("example.com", ".example.com, .example.net", true),
        ("nonexample.com", ".example.com, .example.net", false),
    ];

    /// The `list4[]` walk of `unit1614.c:159-167`.
    #[test]
    fn the_unit1614_cidr4_table_passes() {
        for &(address, network, bits, expected) in CIDR4_ROWS {
            assert_eq!(
                cidr4(address, network, bits),
                expected,
                "{address} in {network}/{bits}"
            );
        }
        assert_eq!(CIDR4_ROWS.len(), 12, "the table must not silently shrink");
    }

    /// The `list6[]` walk of `unit1614.c:169-177`.
    #[test]
    fn the_unit1614_cidr6_table_passes() {
        for &(address, network, bits, expected) in CIDR6_ROWS {
            assert_eq!(
                cidr6(address, network, bits),
                expected,
                "{address} in {network}/{bits}"
            );
        }
        assert_eq!(CIDR6_ROWS.len(), 5, "the table must not silently shrink");
    }

    /// The `list[]` walk of `unit1614.c:179-187`.
    #[test]
    fn the_unit1614_noproxy_table_passes() {
        for &(name, no_proxy, expected) in NOPROXY_ROWS {
            assert_eq!(check(name, no_proxy), expected, "{name} in {no_proxy}");
        }
        assert_eq!(
            NOPROXY_ROWS.len(),
            78,
            "the table must not silently shrink"
        );
    }

    /// The two long rows are the lengths the C's comments claim, which is the
    /// only thing that makes them a test of the `checkip` bound rather than
    /// of nothing in particular.
    #[test]
    fn the_two_long_unit1614_tokens_are_128_and_127_bytes() {
        let boundary = "localhost,".len();
        assert_eq!(TOKEN_128.len() - boundary, 128);
        assert_eq!(TOKEN_127.len() - boundary, 127);
    }

    // The entry point's two refusals and the asterisk.

    /// `if(!name || name[0] == '\0') return FALSE;` -- and it is tested
    /// against `*`, because the emptiness test comes FIRST. A FILE transfer
    /// has no host to interrogate the list with, and must not be treated as
    /// matching everything.
    #[test]
    fn an_empty_name_never_matches() {
        assert!(!check("", "example.com"));
        assert!(!check("", "*"));
        assert!(!check("", ""));
        // A name that ends at an interior zero is empty for the same reason.
        assert!(!check_noproxy(b"\0example.com", b"*"));
    }

    /// The C wraps its whole body in `if(no_proxy && no_proxy[0])`, so an
    /// absent or empty list matches nothing. This is what lets a user pass
    /// `--noproxy ""` to override a `NO_PROXY` inherited from the
    /// environment, which `docs/cmdline-opts/noproxy.md` documents.
    #[test]
    fn an_empty_no_proxy_list_never_matches() {
        assert!(!check("example.com", ""));
        assert!(!check("127.0.0.1", ""));
        assert!(!check("::1", ""));
    }

    /// `if(!strcmp("*", no_proxy)) return TRUE;` -- a whole-value test.
    #[test]
    fn a_lone_asterisk_overrides_only_as_the_entire_value() {
        assert!(check("example.com", "*"));
        assert!(check("127.0.0.1", "*"));
        assert!(check("::1", "*"));

        assert!(!check("bar", "foo,*"));
        assert!(!check("example.com", "*,foo"));
        assert!(!check("example.com", " * "));
        assert!(!check("127.0.0.1", "foo,*"));

        assert!(!check("www.example.com", "*.example.com"));
        assert!(!check("example.com", "*.example.com"));
    }

    // Host matching: cases A, B and C.

    /// Case A, and the fold is ASCII-only and case-insensitive in both
    /// directions.
    #[test]
    fn a_host_name_matches_exactly_and_case_insensitively() {
        assert!(check("EXAMPLE.com", "example.COM"));
        assert!(check("example.com", "EXAMPLE.COM"));
        assert!(check("ExAmPlE.CoM", "eXaMpLe.cOm"));
        assert!(!check("example.org", "example.com"));
    }

    /// Case B: a shorter token tail-matches, and the byte before the tail
    /// must be the label separator.
    #[test]
    fn a_shorter_token_tail_matches_at_a_label_boundary() {
        assert!(check("www.example.com", "example.com"));
        assert!(check("a.b.c.example.com", "example.com"));
        assert!(check("WWW.EXAMPLE.COM", "example.com"));
    }

    /// Case C, with the C's own worked example. `example.com` IS a suffix of
    /// `nonexample.com`, so a plain suffix test would match it; the byte
    /// before the tail is `n` rather than `.`, so this does not.
    #[test]
    fn a_tail_match_off_a_label_boundary_is_refused() {
        assert!(!check("nonexample.com", "example.com"));
        assert!(!check("nexample.com", "example.com"));
        assert!(!check("myexample.com", ".example.com"));
    }

    /// One leading dot on the token is dropped, which is why `.example.com`
    /// matches the domain itself as well as its subdomains.
    #[test]
    fn a_leading_dot_on_a_token_is_ignored() {
        assert!(check("www.example.com", ".example.com"));
        assert!(check("example.com", ".example.com"));
        assert!(!check("notexample.com", ".example.com"));
    }

    /// One trailing dot on the token is dropped, and it is dropped BEFORE the
    /// leading one -- which is the only reason `.example.com.` normalises all
    /// the way to `example.com`.
    #[test]
    fn a_trailing_dot_on_a_token_is_ignored() {
        assert!(check("example.com", "example.com."));
        assert!(check("www.example.com", "example.com."));
        assert!(check("www.example.com", ".example.com."));
        assert!(check("example.com", ".example.com."));
    }

    /// One trailing dot on the NAME is dropped too, in the host branch only.
    #[test]
    fn a_trailing_dot_on_the_name_is_ignored() {
        assert!(check("example.com.", "example.com"));
        assert!(check("www.example.com.", ".example.com"));
        assert!(check("example.com.", "example.com."));
    }

    /// `if` rather than `while`, at all four sites: a second dot survives and
    /// stops the match.
    #[test]
    fn only_one_dot_is_removed_at_each_end() {
        assert!(!check("www.example.com", "..example.com"));
        assert!(!check("example.com", "example.com.."));
        assert!(!check("example.com..", "example.com"));
    }

    /// Case C again, from the other side: `tokenlen > namelen`.
    #[test]
    fn a_token_longer_than_the_name_cannot_match() {
        assert!(!check("example.com", "www.example.com"));
        assert!(!check("com", "example.com"));
        assert!(!check("a", "ab"));
    }

    /// A token, and a name, that normalise to nothing at all.
    #[test]
    fn a_token_of_one_dot_normalises_to_nothing() {
        assert!(match_host(b".", b""));
        assert!(!match_host(b".", b"example.com"));
        assert!(!match_host(b"..", b"example.com"));
        assert!(check(".", "."));
        assert!(!check(".", "example.com"));
        assert!(!check("example.com", "."));
    }

    // Address matching.

    /// An address with no prefix at all means that one address.
    #[test]
    fn an_ipv4_literal_matches_itself_exactly() {
        assert!(check("10.1.2.3", "10.1.2.3"));
        assert!(!check("10.1.2.3", "10.1.2.4"));
        assert!(!check("10.1.2.3", "10.1.2.0"));
    }

    /// A prefix narrows the comparison to its leading bits.
    #[test]
    fn an_ipv4_cidr_range_matches_by_prefix() {
        assert!(check("10.1.2.3", "10.0.0.0/8"));
        assert!(!check("10.1.2.3", "10.2.0.0/16"));
        assert!(check("10.1.2.3", "10.1.0.0/16"));
        assert!(check("10.1.2.3", "10.1.2.0/24"));
        assert!(!check("10.1.2.3", "10.1.3.0/24"));
        // /12 spans 10.0.0.0 through 10.15.255.255, and /13 does not reach
        // 10.16.0.0 -- one bit of difference, checked in both directions.
        assert!(check("10.16.0.1", "10.16.0.0/12"));
        assert!(!check("10.16.0.1", "10.0.0.0/13"));
    }

    /// `/32` is exact, and so is `/0` -- which conventionally would match
    /// every address in the space. curl's behaviour is asserted here, not the
    /// convention, because changing it would silently disable the proxy for
    /// the entire internet on any value carrying a `/0`.
    #[test]
    fn an_ipv4_prefix_of_32_and_of_0_both_mean_exact_equality() {
        assert!(check("10.1.2.3", "10.1.2.3/32"));
        assert!(!check("10.1.2.3", "10.1.2.4/32"));

        assert!(check("10.1.2.3", "10.1.2.3/0"));
        assert!(!check("10.1.2.3", "0.0.0.0/0"));
        assert!(!check("10.1.2.3", "10.0.0.0/0"));

        // And directly, where the argument is a number rather than text.
        assert!(cidr4("10.1.2.3", "10.1.2.3", 0));
        assert!(!cidr4("10.1.2.3", "0.0.0.0", 0));
    }

    /// `if(bits > 32) return FALSE;` -- refused by the MATCHER, after the
    /// parser accepted the value, for every prefix from 33 to 128.
    #[test]
    fn an_ipv4_prefix_above_32_never_matches() {
        assert!(!check("10.1.2.3", "10.1.2.3/33"));
        assert!(!check("10.1.2.3", "10.0.0.0/33"));
        assert!(!check("10.1.2.3", "10.1.2.3/128"));
        for bits in 33..=128 {
            assert!(!cidr4("10.1.2.3", "10.1.2.3", bits), "/{bits}");
        }
    }

    /// The long and short spellings of one address are the same sixteen
    /// bytes, and so are the upper- and lower-case spellings -- normalised by
    /// the parser rather than folded by a comparison, which is why nothing
    /// here lowercases an address literal.
    #[test]
    fn an_ipv6_literal_is_normalised_rather_than_case_folded() {
        assert!(check("::1", "0:0:0:0:0:0:0:1"));
        assert!(check("0:0::1", "::1"));
        assert!(check("::AB", "::ab"));
        assert!(check("FE80::1", "fe80::1"));
        assert!(check("fe80::1", "FE80::1"));
        assert!(!check("::1", "::2"));
    }

    /// A prefix that is not a whole number of bytes exercises the remainder
    /// mask, which is the one piece of arithmetic in [`cidr6_match`] that the
    /// byte comparison cannot reach.
    #[test]
    fn an_ipv6_prefix_that_is_not_byte_aligned_uses_the_remainder_mask() {
        assert!(check("2001:db8:0:f::1", "2001:db8::/60"));
        assert!(!check("2001:db8:0:f::1", "2001:db8::/61"));
        assert!(check("2001:db8:0:7::1", "2001:db8::/61"));
        assert!(check("2001:db8::1", "2001:db8::/64"));
        assert!(!check("2001:db8:1::1", "2001:db8::/64"));

        // Directly, so that the numeric argument is exercised too.
        assert!(cidr6("2001:db8:0:f::1", "2001:db8::", 60));
        assert!(!cidr6("2001:db8:0:f::1", "2001:db8::", 61));
    }

    /// `/128` is the full width and matches exactly; `/129` and above are
    /// refused. Through the text path the refusal is the PARSER's, because
    /// the ceiling is 128; through the numeric path it is the matcher's
    /// `bytes > 16` and `bytes == 16 && rest` test, which is the only thing
    /// that can refuse 129 through 135.
    #[test]
    fn an_ipv6_prefix_above_128_never_matches() {
        assert!(check("::1", "::1/128"));
        assert!(!check("::1", "::1/129"));
        assert!(!check("::1", "::1/200"));

        for bits in 129..=200 {
            assert!(!cidr6("::1", "::1", bits), "/{bits}");
        }
        // The seven values that reach the `bytes == 16 && rest` clause.
        for bits in 129..=135 {
            assert_eq!(bits / 8, 16, "these are the bytes == 16 cases");
            assert!(!cidr6("::1", "::1", bits), "/{bits}");
        }
    }

    /// `if(curlx_str_number(&p, &value, 128) || *p) return FALSE;` -- both
    /// halves of the line, and the blank that is NOT garbage because the
    /// tokenizer never puts it inside a token.
    #[test]
    fn the_prefix_parse_is_strict_at_both_ends() {
        // A digit is required.
        assert!(!check("10.1.2.3", "10.0.0.0/"));
        assert!(!check("10.1.2.3", "10.0.0.0/a8"));
        assert!(!check("10.1.2.3", "10.0.0.0/-8"));
        assert!(!check("10.1.2.3", "10.0.0.0/+8"));
        assert!(!check("10.1.2.3", "10.0.0.0/ 8"));

        // Nothing may follow the digits.
        assert!(!check("10.1.2.3", "10.0.0.0/8x"));
        assert!(!check("10.1.2.3", "10.0.0.0/8."));
        assert!(!check("10.1.2.3", "10.0.0.0/8/9"));

        // A trailing blank ends the TOKEN, so it never reaches the parser.
        assert!(check("10.1.2.3", "10.0.0.0/8 "));
        assert!(check("10.1.2.3", "10.0.0.0/8\t"));
        assert!(check("10.1.2.3", "10.0.0.0/8 ,foo"));

        // Leading zeros are accepted, because `str_number` accepts them.
        assert!(check("10.1.2.3", "10.0.0.0/008"));
        assert!(check("::1", "::1/0128"));

        // The ceiling refuses anything above 128, however long the run of
        // digits, and nothing overflows on the way.
        assert!(!check("10.1.2.3", "10.0.0.0/129"));
        assert!(!check("10.1.2.3", "10.0.0.0/99999999999999999999999"));
    }

    /// `if(tokenlen >= sizeof(checkip)) return FALSE;` -- the bound is 128
    /// bytes, and 127 is admitted.
    #[test]
    fn a_token_of_128_bytes_or_more_cannot_match_an_address() {
        let mut token = String::from("10.1.2.3/8");
        while token.len() < 128 {
            token.push('0');
        }
        assert_eq!(token.len(), 128);
        assert!(!check("10.1.2.3", &token));

        // A padded token one byte shorter is admitted and then fails on its
        // own merits, which is the C's behaviour for the same input.
        let shorter = &token[..127];
        assert_eq!(shorter.len(), 127);
        assert!(!check("10.1.2.3", shorter));

        // A real 127-byte value that DOES match, so the bound is shown to
        // refuse on length rather than on padding: a valid network followed
        // by a comment-free run of commas, which the tokenizer skips.
        let mut padded = String::from("10.0.0.0/8");
        while padded.len() < 127 {
            padded.push(',');
        }
        assert_eq!(padded.len(), 127);
        assert!(check("10.1.2.3", &padded));
    }

    /// The C's `else` arm covers `TYPE_IPV4` and, unreachably, `TYPE_HOST`.
    /// Reached directly, because [`check_noproxy`] never dispatches a host
    /// name here.
    #[test]
    fn match_ip_selects_the_matcher_from_the_classification() {
        assert!(super::match_ip(NameType::Ipv6, b"::1/64", b"::1"));
        assert!(!super::match_ip(NameType::Ipv6, b"10.0.0.0/8", b"::1"));
        assert!(super::match_ip(NameType::Ipv4, b"10.0.0.0/8", b"10.1.2.3"));
        assert!(super::match_ip(NameType::Host, b"10.0.0.0/8", b"10.1.2.3"));
    }

    /// Neither matcher trusts its text: an unparseable address on either side
    /// is a non-match rather than an error.
    #[test]
    fn the_cidr_matchers_refuse_text_that_is_not_an_address() {
        assert!(!cidr4("example.com", "10.0.0.0", 8));
        assert!(!cidr4("10.1.2.3", "example.com", 8));
        assert!(!cidr4("", "10.0.0.0", 8));
        assert!(!cidr4("10.1.2.3", "", 8));
        assert!(!cidr4("10.1.2.3.4", "10.0.0.0", 8));
        assert!(!cidr4("010.1.2.3", "10.0.0.0", 8));
        assert!(!cidr4("10.1.2", "10.0.0.0", 8));
        assert!(!cidr4("::1", "10.0.0.0", 8));

        assert!(!cidr6("example.com", "::", 8));
        assert!(!cidr6("::1", "example.com", 8));
        assert!(!cidr6("", "::", 8));
        assert!(!cidr6("::1", "", 8));
        assert!(!cidr6("10.1.2.3", "::", 8));
        assert!(!cidr6("fe80::1%eth0", "fe80::", 16));
    }

    // Classification, and the trailing-dot asymmetry it creates.

    /// Classification happens BEFORE any trailing dot is stripped, so a name
    /// with a trailing dot is never an address literal.
    #[test]
    fn an_address_literal_never_loses_a_trailing_dot() {
        assert!(check("127.0.0.1", "127.0.0.0/8"));
        assert!(!check("127.0.0.1.", "127.0.0.0/8"));
        assert!(check("127.0.0.1.", "127.0.0.1"));

        assert!(check("::1", "::0/64"));
        assert!(!check("::1.", "::0/64"));
    }

    // The tokenizer.

    /// Blanks around tokens, tabs as separators, runs of commas, and a comma
    /// at either end. Blank means space and tab only.
    #[test]
    fn the_tokenizer_skips_blanks_and_runs_of_commas() {
        assert!(check("bar", "foo, bar"));
        assert!(check("bar", "foo ,bar"));
        assert!(check("bar", " foo , bar "));
        assert!(check("bar", "foo,\tbar"));
        assert!(check("bar", "foo\t,\tbar"));
        assert!(check("bar", "a,,,b,,,bar"));
        assert!(check("bar", ",bar"));
        assert!(check("bar", ",,,,,bar"));
        assert!(check("bar", "bar,"));
        assert!(check("bar", "bar,,,,,"));
        assert!(check("bar", ",,,bar,,,"));
        assert!(check("bar", "foo,,,,,              bar"));
        assert!(!check("bar", "foo,,,,,"));
        assert!(!check("bar", ",,,,,"));
    }

    /// `if(*p != ',') break;` -- anything else ends the whole scan, so a
    /// blank-separated list is not a list.
    #[test]
    fn anything_other_than_a_comma_between_tokens_ends_the_scan() {
        assert!(check("localhost", "localhost .example.com"));
        assert!(!check("www.example.com", "localhost .example.com"));
        assert!(!check("www.example.com", "localhost\t.example.com"));
        assert!(!check("bar", "foo bar"));
        assert!(!check("bar", "foo;bar"));
        assert!(!check("bar", "foo:bar"));

        // A newline joins the token rather than separating it.
        assert!(!check("bar", "foo\nbar"));
        assert!(check("foo\nbar", "foo\nbar"));
        assert!(!check("bar", "foo,bar\nbaz"));
        assert!(check("bar\nbaz", "foo,bar\nbaz"));
    }

    /// A match on the last token of a mixed list is found, whichever kind of
    /// name is under test.
    #[test]
    fn a_match_on_the_last_token_of_a_mixed_list_is_found() {
        assert!(check("example.com", "a.com, 10.0.0.0/8, ::1, example.com"));
        assert!(check("10.1.2.3", "a.com, ::1/64, 10.0.0.0/8"));
        assert!(check("::1", "a.com, 10.0.0.0/8, ::1/64"));
        assert!(!check("other.com", "a.com, 10.0.0.0/8, ::1, example.com"));
    }

    /// `tests/data/test1212` in miniature: the fixture passes `--noproxy`
    /// with the same address the server listens on, alongside a deliberately
    /// unresolvable `--socks5` host, and expects a direct transfer. Its
    /// `%HOSTIP` is the loopback address.
    #[test]
    fn the_test1212_shape_suppresses_the_proxy() {
        assert!(check("127.0.0.1", "127.0.0.1"));
        assert!(!check("127.0.0.2", "127.0.0.1"));
    }

    // Byte-string behaviour the C's `const char *` cannot express.

    /// Both arguments are bytes, so a value that is not valid UTF-8 is
    /// matched rather than rejected, and nothing panics on the way.
    #[test]
    fn bytes_that_are_not_utf8_are_matched_as_bytes() {
        assert!(check_noproxy(b"ex\xffample.com", b"ex\xffample.com"));
        assert!(check_noproxy(b"www.ex\xffample.com", b".ex\xffample.com"));
        assert!(!check_noproxy(b"ex\xffample.com", b"ex\xfeample.com"));
        assert!(check_noproxy(b"\xff\xfe", b"foo,\xff\xfe,bar"));
        assert!(!check_noproxy(b"\xff\xfe", b"foo,\xff\xff,bar"));

        // High bytes are not folded: the fold covers the 26 ASCII letter
        // pairs and nothing else, so 0xe0 and 0xc0 stay distinct even though
        // they are a case pair in Latin-1.
        assert!(!check_noproxy(b"\xe0", b"\xc0"));

        // A whole sweep of single-byte names against themselves, which
        // reaches every value including the ones no `&str` could carry.
        const NOT_A_TOKEN: [u8; 4] = [0x00, b'\t', b' ', b','];
        let mut matched = 0_usize;
        for byte in 1..=u8::MAX {
            if NOT_A_TOKEN.contains(&byte) {
                continue;
            }
            let name = [byte];
            assert!(check_noproxy(&name, &name), "{byte:#04x}");
            matched += 1;
        }
        assert_eq!(matched, 252, "the sweep must not silently shrink");

        for byte in NOT_A_TOKEN {
            let name = [byte];
            assert!(!check_noproxy(&name, &name), "{byte:#04x}");
        }
    }

    /// A zero ends the string, exactly as it does in the C -- where every
    /// length comes from `strlen` or a `while(*p)`.
    #[test]
    fn an_interior_zero_ends_the_string() {
        assert_eq!(cstr(b"example.com\0junk"), b"example.com");
        assert_eq!(cstr(b"\0"), b"");
        assert_eq!(cstr(b""), b"");
        assert_eq!(cstr(b"example.com"), b"example.com");

        // The name stops there, so the junk beyond is not compared.
        assert!(check_noproxy(b"example.com\0junk", b"example.com"));
        // And so does the list, so a token beyond the zero is never seen.
        assert!(!check_noproxy(b"example.com", b"nomatch\0,example.com"));
        assert!(check_noproxy(b"nomatch", b"nomatch\0,example.com"));
    }

    // Differential sweeps against an independent prefix comparison.

    /// Do the first `bits` bits of two addresses agree?
    fn prefix_bits_agree(left: &[u8], right: &[u8], bits: u32) -> bool {
        (0..bits as usize).all(|bit| {
            let byte = bit / 8;
            let mask = 0x80_u8 >> (bit % 8);
            (left[byte] & mask) == (right[byte] & mask)
        })
    }

    /// Every prefix from 1 to 32 over six address pairs, against
    /// [`prefix_bits_agree`].
    #[test]
    fn the_ipv4_mask_agrees_with_a_bitwise_reference() {
        const PAIRS: [(&str, &str); 6] = [
            ("192.160.0.1", "192.160.0.1"),
            ("192.168.0.1", "192.168.0.0"),
            ("10.1.2.3", "10.0.0.0"),
            ("255.255.255.255", "0.0.0.0"),
            ("1.2.3.4", "1.2.3.5"),
            ("0.0.0.0", "0.0.0.0"),
        ];

        let mut compared = 0_usize;
        for (address, network) in PAIRS {
            let left = octets4(address);
            let right = octets4(network);
            for bits in 1..=32 {
                assert_eq!(
                    cidr4(address, network, bits),
                    prefix_bits_agree(&left, &right, bits),
                    "{address} in {network}/{bits}"
                );
                compared += 1;
            }
        }
        assert_eq!(compared, 192, "the sweep must not silently shrink");
    }

    /// Every prefix from 1 to 128 over five address pairs, plus the zero the
    /// matcher promotes to 128.
    #[test]
    fn the_ipv6_mask_agrees_with_a_bitwise_reference() {
        const PAIRS: [(&str, &str); 5] = [
            ("::1", "::1"),
            ("2001:db8:8000::1", "2001:db8::"),
            ("2001:db8::1", "2001:db8::"),
            ("fe80::ab47:4396:55c9:8474", "fe80::"),
            ("::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
        ];

        let mut compared = 0_usize;
        for (address, network) in PAIRS {
            let left = octets6(address);
            let right = octets6(network);
            for bits in 1..=128 {
                assert_eq!(
                    cidr6(address, network, bits),
                    prefix_bits_agree(&left, &right, bits),
                    "{address} in {network}/{bits}"
                );
                compared += 1;
            }
            // `if(!bits) bits = 128;` -- the promotion, checked against the
            // full-width answer rather than against a special case.
            assert_eq!(
                cidr6(address, network, 0),
                prefix_bits_agree(&left, &right, 128),
                "{address} in {network}/0"
            );
            compared += 1;
        }
        assert_eq!(compared, 645, "the sweep must not silently shrink");
    }

    /// The four bytes of a dotted quad, parsed by the standard library rather
    /// than by the parser under test, so that the sweeps above compare two
    /// independent readings of the same text.
    fn octets4(text: &str) -> [u8; 4] {
        text.parse::<std::net::Ipv4Addr>()
            .expect("the sweep's addresses are valid")
            .octets()
    }

    /// The sixteen bytes of an IPv6 literal, parsed by the standard library.
    fn octets6(text: &str) -> [u8; 16] {
        text.parse::<std::net::Ipv6Addr>()
            .expect("the sweep's addresses are valid")
            .octets()
    }
}
