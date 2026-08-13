// This is from the BIND 4.9.4 release, modified to compile by itself
//
// Copyright (C) 1996-2022  Internet Software Consortium.
// Copyright (c) Internet Software Consortium.
//
// Permission to use, copy, modify, and distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
// DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
// INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
// INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
// FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
// NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
// WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
//
// SPDX-License-Identifier: ISC

// THE LICENCE BANNER ABOVE IS NOT THE ONE EVERY OTHER FILE IN THIS
// DIRECTORY CARRIES, and the difference is deliberate. Read this before
// "fixing" it to match its neighbours.
//
// WHAT IS REPRODUCED, AND FROM WHICH FILE. This module merges two
// translation units, so it carries the provenance of both:
//
//   * line 1 is `lib/curlx/inet_pton.c:1` verbatim -- the BIND 4.9.4
//     provenance note, which appears only on that file;
//   * line 3 is `lib/curlx/inet_ntop.c:2`, whose copyright carries the
//     1996-2022 range;
//   * line 4 is `lib/curlx/inet_pton.c:3`, whose copyright carries NO year
//     range and spells the mark in lower case. Both lines are kept rather
//     than merged into one, because they are two distinct notices and the
//     ISC terms above require that "the above copyright notice ... appear in
//     all copies";
//   * the permission grant and the disclaimer are `inet_ntop.c:4-15`, whose
//     line breaks follow the canonical ISC text. `inet_pton.c:5-16` carries
//     the same words reflowed to a different width, so quoting one covers
//     both;
//   * the SPDX identifier is `inet_ntop.c:17` and `inet_pton.c:18`, which
//     agree.

//! Address presentation and parsing -- supersedes `lib/curlx/inet_ntop.c` and
//! `lib/curlx/inet_pton.c`, together with their two thin headers.
//!
//! Four functions in the C, wearing two names. `curlx_inet_ntop` turns four
//! or sixteen network-order bytes into the text a human reads, and
//! `curlx_inet_pton` turns that text back into bytes. Each dispatches on an
//! address family to one of two static workers -- `inet_ntop4`,
//! `inet_ntop6`, `inet_pton4`, `inet_pton6` -- and those four names are kept
//! here, without the `inet_` prefix that the enclosing module already
//! supplies.
//!
//! # Visibility, layering and inputs
//!
//! Two sibling modules are imported and nothing else: `super`'s [`ultouc`]
//! for the one narrowing the C writes as a cast, and
//! [`strparse`](crate::util::strparse) for byte classification and
//! hexadecimal decoding. Both are inside this layer, so the rule `super`
//! states for the whole directory -- `util` depends on nothing in this crate
//! except `crate::error`, and not even that here -- holds.
//!
//! Text arrives as `&[u8]`, not `&str`. The C parses a NUL-terminated
//! `char *`; a slice carries its own length instead, so a caller with a
//! [`str`] passes `s.as_bytes()` and no wrapper is offered for a conversion
//! that short. One consequence is worth stating because it is a real
//! difference: a slice is **exactly** its bytes, so an interior NUL is an
//! unaccepted character and yields [`None`], where the C would have stopped
//! there and parsed the prefix. That makes these parsers strictly less
//! permissive than the C, never more, so no address the C rejects can be
//! accepted here -- and it is tested rather than argued.
//!
//! # Conventions
//!
//! No `unsafe` anywhere: the crate root denies the lint and grants its one
//! exemption to `mod ffi`, which this module is not. Every index below is
//! either bounded by a mask or proved in range at the site.
//!
//! No panic on hostile input, which is not a stylistic preference: these
//! strings arrive from URLs, DNS answers, `Alt-Svc` response headers and
//! SOCKS replies. Nothing below indexes with a value derived from input
//! length, and nothing unwraps a fallible lookup.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::util::strparse;
use crate::util::ultouc;

/// The width of an IPv6 address in bytes -- `IN6ADDRSZ`.
///
/// `inet_ntop.c:37` and `inet_pton.c:37`, which agree.
pub(crate) const IN6ADDRSZ: usize = 16;

/// The width of an IPv4 address in bytes -- `INADDRSZ`.
pub(crate) const INADDRSZ: usize = 4;

/// The width of one IPv6 group in bytes -- `INT16SZ`.
///
/// `inet_ntop.c:39` and `inet_pton.c:39`. It appears in the C in two roles,
/// and both survive below: as the divisor in `IN6ADDRSZ / INT16SZ`, the group
/// count, and as the step in the bound `tp + INT16SZ > endp`.
pub(crate) const INT16SZ: usize = 2;

/// The number of 16-bit groups in an IPv6 address -- the C's
/// `IN6ADDRSZ / INT16SZ`, which it recomputes at every use.
///
/// Named once here rather than eight times below. The value is 8.
const GROUPS: usize = IN6ADDRSZ / INT16SZ;

/// The group index at which an embedded IPv4 address begins.
///
/// The C writes the literal `6` in its embedded-address test
/// (`inet_ntop.c:155`). Named, not renumbered: groups 0 through 5 are the
/// prefix and groups 6 and 7 are the four bytes rendered as a dotted quad.
const EMBEDDED_V4_GROUP: usize = 6;

/// The byte offset of an embedded IPv4 address -- the C's `src + 12`
/// (`inet_ntop.c:157`).
const EMBEDDED_V4_OFFSET: usize = IN6ADDRSZ - INADDRSZ;

/// The lower-case hexadecimal digits, as an explicit table.
const LDIGITS: [u8; 16] = *b"0123456789abcdef";

/// The longest string [`ntop4`] can return.
const NTOP4_MAX_LEN: usize = "255.255.255.255".len();

/// The longest string [`ntop6`] can return.
const NTOP6_MAX_LEN: usize =
    "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255".len();

/// A run of zero groups: the C's anonymous `struct { int base; int len; }`
/// (`inet_ntop.c:99-102`), which it instantiates twice as `best` and `cur`.
#[derive(Clone, Copy)]
struct Run {
    /// The index of the first zero group in the run, or [`None`] for the C's
    /// `base == -1`, meaning "no run".
    base: Option<usize>,
    /// The number of consecutive zero groups. Meaningless when `base` is
    /// [`None`], exactly as in the C, where `cur.len` is left stale by
    /// `cur.base = -1`.
    len: usize,
}

impl Run {
    /// The C's initial state: `best.base = -1; cur.base = -1; best.len = 0;
    /// cur.len = 0;` (`inet_ntop.c:114-117`).
    const NONE: Self = Self { base: None, len: 0 };
}

/// Formats four network-order bytes as a dotted quad.
#[allow(dead_code)] // Callers: `dns`, `conn` and `url`.
#[must_use]
pub(crate) fn ntop4(addr: &[u8; INADDRSZ]) -> String {
    // `SNPRINTF(tmp, sizeof(tmp), "%d.%d.%d.%d", src[0] & 0xff, ...)`. The
    // C's `& 0xff` on each argument is the identity for a value already read
    // through an `unsigned char *`; it is there because the arguments are
    // widened to `int` for the variadic call.
    let text = format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3]);

    // `DEBUGASSERT(size >= 16)` restated as the property it was protecting.
    // The C asserts that the caller's buffer is wide enough; with no caller
    // buffer, what is left worth checking is that the answer really does fit
    // the width the C promised, which is what every consumer sizing a
    // fixed-width field relies on.
    debug_assert!(
        text.len() <= NTOP4_MAX_LEN,
        "inet_ntop4 contract: {} characters exceeds the {}-character maximum",
        text.len(),
        NTOP4_MAX_LEN
    );

    text
}

/// Formats sixteen network-order bytes as an IPv6 address.
///
/// Supersedes `inet_ntop6` (`inet_ntop.c:88-197`). Every branch of the C is
/// transcribed, and the three that are easy to get wrong each carry their own
/// test at the foot of this file:
///
/// * a **single** zero group is never compressed, because the C discards a
///   run shorter than two at `:136-137`, so `1:0:2:3:4:5:6:7` keeps its
///   `0`;
/// * on a tie the **first** longest run wins, because `cur.len > best.len` at
///   `:129` and `:134` is strict, so `1:0:0:1:0:0:1:1` compresses the first
///   pair and renders as `1::1:0:0:1:1`;
/// * a run reaching the end of the address gains a **second** colon at
///   `:182-183`, which is what makes the all-zero address `"::"` rather than
///   `":"`.
#[allow(dead_code)] // Callers: `dns`, `conn` and `url`.
#[must_use]
pub(crate) fn ntop6(addr: &[u8; IN6ADDRSZ]) -> String {
    let words = groups_of(addr);
    let best = longest_zero_run(&words);

    // `tp = tmp;` -- the C's cursor into a 46-byte scratch buffer. Reserving
    // the same width here means the string never reallocates, which is not a
    // performance claim: it is what lets the assertion at the end check the
    // C's `sizeof(tmp)` bound against a number that came from the same place.
    let mut out = String::with_capacity(NTOP6_MAX_LEN);

    // `for(i = 0; i < (IN6ADDRSZ / INT16SZ); i++)`
    for index in 0..GROUPS {
        // `if(best.base != -1 && i >= best.base && i < (best.base +
        // best.len)) { if(i == best.base) *tp++ = ':'; continue; }`
        if let Some(base) = best.base {
            if index >= base && index < base + best.len {
                if index == base {
                    out.push(':');
                }
                continue;
            }
        }

        // `if(i) *tp++ = ':';`
        if index != 0 {
            out.push(':');
        }

        // `if(i == 6 && best.base == 0 && (best.len == 6 || (best.len == 5 &&
        // words[5] == 0xffff)))`
        if index == EMBEDDED_V4_GROUP
            && best.base == Some(0)
            && (best.len == 6 || (best.len == 5 && words[5] == 0xffff))
        {
            // `if(!inet_ntop4(src + 12, tp, sizeof(tmp) - (tp - tmp)))
            //    return NULL;`
            //
            // Indexing is proved in range by the array type: the offsets are
            // 12 through 15 of a `&[u8; 16]`, all constants.
            let quad = [
                addr[EMBEDDED_V4_OFFSET],
                addr[EMBEDDED_V4_OFFSET + 1],
                addr[EMBEDDED_V4_OFFSET + 2],
                addr[EMBEDDED_V4_OFFSET + 3],
            ];
            out.push_str(&ntop4(&quad));

            // `tp += strlen(tp); break;`
            break;
        }

        // `else { ... }` -- the ordinary case, one group in hexadecimal.
        push_group_hex(&mut out, words[index]);
    }

    // `if(best.base != -1 && (best.base + best.len) == (IN6ADDRSZ /
    // INT16SZ)) *tp++ = ':';`
    if let Some(base) = best.base {
        if base + best.len == GROUPS {
            out.push(':');
        }
    }

    // `if((size_t)(tp - tmp) >= size) { errno = ENOSPC; return NULL; }`
    // restated as the property it was protecting, exactly as in [`ntop4`].
    debug_assert!(
        out.len() <= NTOP6_MAX_LEN,
        "inet_ntop6 contract: {} characters exceeds the {}-character maximum",
        out.len(),
        NTOP6_MAX_LEN
    );

    out
}

/// Formats an address of either family -- supersedes `curlx_inet_ntop`
/// (`inet_ntop.c:210-221`).
#[allow(dead_code)] // Callers: `dns` and `conn`.
#[must_use]
pub(crate) fn ntop(addr: IpAddr) -> String {
    match addr {
        // `case AF_INET: return inet_ntop4(src, buf, size);`
        IpAddr::V4(v4) => ntop4(&v4.octets()),
        // `case AF_INET6: return inet_ntop6(src, buf, size);`
        IpAddr::V6(v6) => ntop6(&v6.octets()),
    }
}

/// Appends one group as lower-case hexadecimal with leading zeros suppressed.
///
/// Transcribes `inet_ntop.c:163-177`, whose suppression is performed by **four
/// masked tests** rather than by a formatter:
///
/// ```c
/// static const unsigned char ldigits[] = "0123456789abcdef";
/// unsigned int w = words[i];
/// if(w & 0xf000) *tp++ = ldigits[(w & 0xf000) >> 12];
/// if(w & 0xff00) *tp++ = ldigits[(w & 0x0f00) >>  8];
/// if(w & 0xfff0) *tp++ = ldigits[(w & 0x00f0) >>  4];
/// *tp++ = ldigits[(w & 0x000f)];
/// ```
fn push_group_hex(out: &mut String, word: u16) {
    if (word & 0xf000) != 0 {
        out.push(char::from(LDIGITS[usize::from((word & 0xf000) >> 12)]));
    }
    if (word & 0xff00) != 0 {
        out.push(char::from(LDIGITS[usize::from((word & 0x0f00) >> 8)]));
    }
    if (word & 0xfff0) != 0 {
        out.push(char::from(LDIGITS[usize::from((word & 0x00f0) >> 4)]));
    }
    out.push(char::from(LDIGITS[usize::from(word & 0x000f)]));
}

/// Splits sixteen bytes into eight big-endian groups.
///
/// The C fills its word array with a shift-and-or over every byte
/// (`inet_ntop.c:110-112`):
///
/// ```c
/// memset(words, '\0', sizeof(words));
/// for(i = 0; i < IN6ADDRSZ; i++)
///   words[i / 2] |= ((unsigned int)src[i] << ((1 - (i % 2)) << 3));
/// ```
fn groups_of(addr: &[u8; IN6ADDRSZ]) -> [u16; GROUPS] {
    let mut words = [0u16; GROUPS];

    for (index, word) in words.iter_mut().enumerate() {
        // `index` is below `GROUPS`, so `at + 1` is at most 15 -- in range
        // for a `&[u8; 16]`, and the compiler can see it.
        let at = index * INT16SZ;
        *word = u16::from_be_bytes([addr[at], addr[at + 1]]);
    }

    words
}

/// Finds the run of zero groups that `::` will replace.
///
/// Transcribes `inet_ntop.c:114-137`. Three properties of that loop are
/// load-bearing and each is preserved literally:
///
/// * **the comparison is strict.** `cur.len > best.len` at `:129` and `:134`
///   means an equal-length later run does NOT displace an earlier one, so the
///   first of several longest runs is the one compressed;
/// * **a trailing run is considered after the loop** (`:134-135`), because a
///   run that reaches the last group never meets the non-zero group that
///   would otherwise have committed it;
/// * **a run of one is discarded** (`:136-137`). Replacing a single zero group
///   with `::` would save no characters and is not curl's rendering.
fn longest_zero_run(words: &[u16; GROUPS]) -> Run {
    // `best.base = -1; cur.base = -1; best.len = 0; cur.len = 0;`
    let mut best = Run::NONE;
    let mut cur = Run::NONE;

    for (index, &word) in words.iter().enumerate() {
        if word == 0 {
            // `if(cur.base == -1) { cur.base = i; cur.len = 1; } else
            // cur.len++;`
            if cur.base.is_none() {
                cur.base = Some(index);
                cur.len = 1;
            } else {
                cur.len += 1;
            }
        } else if cur.base.is_some() {
            // `if(best.base == -1 || cur.len > best.len) best = cur;` --
            // STRICT, so the first longest run wins a tie.
            if best.base.is_none() || cur.len > best.len {
                best = cur;
            }
            // `cur.base = -1;` and, as in the C, `cur.len` is left as it is.
            cur.base = None;
        }
    }

    // `if((cur.base != -1) && (best.base == -1 || cur.len > best.len))
    //    best = cur;`
    if cur.base.is_some() && (best.base.is_none() || cur.len > best.len) {
        best = cur;
    }

    // `if(best.base != -1 && best.len < 2) best.base = -1;`
    if best.base.is_some() && best.len < 2 {
        best.base = None;
    }

    best
}

/// Parses a dotted quad into four network-order bytes.
///
/// # Leading zeros are rejected, and the mechanism is worth reading
///
/// `if(saw_digit && *tp == 0) return 0;` (`:77-78`) tests the **accumulator**,
/// not the digit. Trace the three cases the distinction turns on:
///
/// | Input | What happens |
/// |---|---|
/// | `0` | the first digit leaves the accumulator at 0 with `saw_digit` set, and nothing follows, so it is accepted |
/// | `01` | the second digit finds `saw_digit` set and the accumulator still 0, so it is rejected |
/// | `10` | the second digit finds the accumulator at 1, so it is accepted |
#[allow(dead_code)] // Callers: `dns`, `conn` and `proxy`.
#[must_use]
pub(crate) fn pton4(src: &[u8]) -> Option<[u8; INADDRSZ]> {
    // `saw_digit = 0; octets = 0; tp = tmp; *tp = 0;`
    let mut tmp = [0u8; INADDRSZ];
    let mut saw_digit = false;
    let mut octets = 0usize;

    // The C's `*tp`: the octet under construction. Held in a local rather
    // than read back out of `tmp` through a walking pointer, which is what
    // lets every write below be indexed by `octets - 1` -- a value provably
    // in `0..4` -- instead of by a cursor that has to be argued about.
    let mut acc: u8 = 0;

    // `while((ch = *src++) != '\0')`. The slice IS the string: it carries its
    // own length, so there is no terminator to look for and an interior NUL
    // falls to the rejecting arm below rather than ending the scan. That is
    // stricter than the C and never more permissive, as the module
    // documentation records.
    for &ch in src {
        if strparse::is_digit(ch) {
            // `unsigned int val = (*tp * 10) + (ch - '0');`
            let val = acc
                .checked_mul(10)
                .and_then(|scaled| scaled.checked_add(ch - b'0'));

            // `if(saw_digit && *tp == 0) return 0;` -- the leading zero.
            if saw_digit && acc == 0 {
                return None;
            }

            // `if(val > 255) return 0;`
            let val = val?;

            // `*tp = (unsigned char)val;`
            acc = val;

            // `if(!saw_digit) { if(++octets > 4) return 0; saw_digit = 1; }`
            if !saw_digit {
                octets += 1;
                if octets > INADDRSZ {
                    return None;
                }
                saw_digit = true;
            }

            // The store the C performs through `*tp` at `:81`, which happens
            // there BEFORE the `octets` bookkeeping above. Moving it after is
            // what lets `octets` name the slot, so that no walking cursor has
            // to be trusted, and it is exact rather than approximately right:
            //
            //   * the C's cursor and the octet count satisfy
            //     `tp == &tmp[octets - 1]` whenever `saw_digit` holds, because
            //     the count rises on the first digit of an octet and the
            //     cursor advances on the dot before it;
            //   * so for a continuing octet, where the count does not change,
            //     the two name the same slot outright;
            //   * and for a new octet the count has just risen by one, which
            //     is precisely the difference between the C's pre-increment
            //     cursor and this index. The first digit of the address writes
            //     slot 0 either way, and the first digit after a dot writes
            //     the slot the C's `*++tp` had just stepped onto.
            tmp[octets - 1] = acc;
        } else if ch == b'.' && saw_digit {
            // `if(octets == 4) return 0;`
            if octets == INADDRSZ {
                return None;
            }

            // `*++tp = 0; saw_digit = 0;` -- the C advances its cursor and
            // clears the slot it now points at. Here the accumulator is
            // cleared and the slot is chosen by `octets` when the next digit
            // arrives, so the two steps become one.
            acc = 0;
            saw_digit = false;
        } else {
            // The C's bare `else return 0;` -- anything that is neither a
            // digit nor a dot following a digit. That covers a leading dot, a
            // doubled dot, a sign, a space, a hexadecimal marker and a NUL.
            return None;
        }
    }

    // `if(octets < 4) return 0;`
    if octets < INADDRSZ {
        return None;
    }

    // `memcpy(dst, tmp, INADDRSZ); return 1;`
    Some(tmp)
}

/// Parses an IPv6 address into sixteen network-order bytes.
///
/// The accepted grammar is the C's, transcribed statement by statement:
///
/// * up to eight groups of **at most four** hexadecimal digits
///   (`if(++saw_xdigit > 4) return 0` at `:136-137`), separated by colons;
/// * **at most one** `::` (`if(colonp) return 0` at `:143-144`), standing for
///   any number of zero groups;
/// * a **leading single colon is invalid** unless a second follows it
///   immediately (`:126-128`), so `:1::` is rejected while `::1` is not;
/// * an **embedded dotted quad** as the tail, attempted only when four bytes
///   of room remain (`:156-157`), which is what admits `::ffff:1.2.3.4` and
///   `::1.2.3.4` while rejecting a quad anywhere but at the end;
/// * the result must be **exactly** sixteen bytes (`if(tp != endp) return 0`
///   at `:186-187`).
#[allow(dead_code)] // Callers: `dns`, `url` and `proxy`.
#[must_use]
pub(crate) fn pton6(src: &[u8]) -> Option<[u8; IN6ADDRSZ]> {
    // `memset((tp = tmp), 0, IN6ADDRSZ); endp = tp + IN6ADDRSZ;
    //  colonp = NULL;`
    let mut tmp = [0u8; IN6ADDRSZ];
    let mut tp = 0usize;
    let endp = IN6ADDRSZ;
    let mut colonp: Option<usize> = None;

    // `if(*src == ':') if(*++src != ':') return 0;`
    //
    // A leading colon is only ever the first half of `::`. The cursor
    // advances onto the second colon and the loop below consumes it, which is
    // what leaves `colonp` recording position zero.
    let mut at = 0usize;
    if src.first() == Some(&b':') {
        at = 1;
        if src.get(at) != Some(&b':') {
            return None;
        }
    }

    // `curtok = src; saw_xdigit = 0; val = 0;`
    //
    // `curtok` marks the start of the token being read, so that the embedded
    // dotted quad can be re-parsed from its beginning. The C keeps it as a
    // pointer; here it is an index, and it never exceeds `src.len()` because
    // it is only ever assigned the cursor.
    let mut curtok = at;
    let mut saw_xdigit = 0usize;

    // `size_t val` -- the group being accumulated. Four nibbles fit sixteen
    // bits, but the fifth is shifted in BEFORE the count is checked, so the
    // accumulator has to be wider than the group it holds. Thirty-two bits is
    // ample: the check fires at five nibbles, twenty bits.
    let mut val = 0u32;

    // `while((ch = *src++) != '\0')`. As in [`pton4`], the slice is the whole
    // string and a NUL inside it is simply not an accepted character.
    while at < src.len() {
        let ch = src[at];
        at += 1;

        // `if(ISXDIGIT(ch)) { val <<= 4; val |= curlx_hexval(ch);
        //                     if(++saw_xdigit > 4) return 0; continue; }`
        if let Some(digit) = strparse::hexval(ch) {
            val = (val << 4) | u32::from(digit);
            saw_xdigit += 1;
            if saw_xdigit > 4 {
                return None;
            }
            continue;
        }

        if ch == b':' {
            // `curtok = src;` -- already past the colon, since the cursor
            // advanced when the character was read.
            curtok = at;

            if saw_xdigit == 0 {
                // `if(colonp) return 0; colonp = tp; continue;`
                //
                // A colon with no digits before it is the second half of
                // `::`. Only one such run is allowed, because two would leave
                // the number of elided groups ambiguous.
                if colonp.is_some() {
                    return None;
                }
                colonp = Some(tp);
                continue;
            }

            // `if(tp + INT16SZ > endp) return 0;`
            if tp + INT16SZ > endp {
                return None;
            }

            // `*tp++ = (unsigned char)((val >> 8) & 0xff);
            //  *tp++ = (unsigned char)(val & 0xff);`
            tmp[tp] = ultouc(u64::from((val >> 8) & 0xff));
            tmp[tp + 1] = ultouc(u64::from(val & 0xff));
            tp += INT16SZ;

            // `saw_xdigit = 0; val = 0; continue;`
            saw_xdigit = 0;
            val = 0;
            continue;
        }

        // `if(ch == '.' && ((tp + INADDRSZ) <= endp) &&
        //     inet_pton4(curtok, tp) > 0) {
        //   tp += INADDRSZ; saw_xdigit = 0; break; }`
        //
        // A failure of any of the three conjuncts falls through to the
        // rejection below, exactly as the C's bare `return 0;` does.
        if ch == b'.' && (tp + INADDRSZ) <= endp {
            if let Some(quad) = pton4(&src[curtok..]) {
                tmp[tp..tp + INADDRSZ].copy_from_slice(&quad);
                tp += INADDRSZ;
                saw_xdigit = 0;
                break;
            }
        }

        // `return 0;`
        return None;
    }

    // `if(saw_xdigit) { if(tp + INT16SZ > endp) return 0;
    //   *tp++ = (val >> 8) & 0xff; *tp++ = val & 0xff; }`
    //
    // The final group, which had no trailing colon to flush it.
    if saw_xdigit != 0 {
        if tp + INT16SZ > endp {
            return None;
        }
        tmp[tp] = ultouc(u64::from((val >> 8) & 0xff));
        tmp[tp + 1] = ultouc(u64::from(val & 0xff));
        tp += INT16SZ;
    }

    // `if(colonp) { ... }`
    if let Some(colon_at) = colonp {
        // `if(tp == endp) return 0;`
        //
        // THE STALE COMMENT LIVES HERE. `inet_pton.c:109` claims a `::` in a
        // full address is silently ignored; this line rejects it. The code is
        // what ships, so the code is what is transcribed.
        if tp == endp {
            return None;
        }

        close_up_double_colon(&mut tmp, colon_at, tp);

        // `tp = endp;`
        tp = endp;
    }

    // `if(tp != endp) return 0;`
    //
    // Everything above accumulates; this is the only place the total is
    // required to be exactly an address. It is what rejects `1:2:3:4:5:6:7`
    // -- seven groups and no `::` to stand for the eighth.
    if tp != endp {
        return None;
    }

    // `memcpy(dst, tmp, IN6ADDRSZ); return 1;`
    Some(tmp)
}

/// Slides the groups written after a `::` to the end of the address and zeros
/// the gap they leave.
///
/// ```c
/// const ssize_t n = tp - colonp;
/// for(i = 1; i <= n; i++) {
///   *(endp - i) = *(colonp + n - i);
///   *(colonp + n - i) = 0;
/// }
/// ```
///
/// # Preconditions
///
/// `colon_at <= tp` and `tp < IN6ADDRSZ`. Both hold at the single call site:
/// `colon_at` is a value `tp` had earlier and so cannot exceed it, and the
/// caller has already returned for `tp == endp`. Together they give
/// `colon_at + n < IN6ADDRSZ`, hence `colon_at < IN6ADDRSZ - n`, which is what
/// makes both ranges below well formed.
fn close_up_double_colon(
    tmp: &mut [u8; IN6ADDRSZ],
    colon_at: usize,
    tp: usize,
) {
    debug_assert!(
        colon_at <= tp && tp < IN6ADDRSZ,
        "inet_pton6 close-up contract: colon at {colon_at}, cursor at {tp}"
    );

    // `const ssize_t n = tp - colonp;`
    let n = tp - colon_at;

    // The slide: `*(endp - i) = *(colonp + n - i)` for `i` in `1..=n`.
    tmp.copy_within(colon_at..tp, IN6ADDRSZ - n);

    // The zero-fill: `*(colonp + n - i) = 0`, less whatever the slide
    // reclaimed. See the note above for why the upper bound is a minimum.
    let gap_end = tp.min(IN6ADDRSZ - n);
    tmp[colon_at..gap_end].fill(0);
}

/// Parses an address of either family -- the successor of `curlx_inet_pton`
/// (`inet_pton.c:207-219`).
#[allow(dead_code)] // Callers: `dns` and `proxy::noproxy`.
#[must_use]
pub(crate) fn pton(src: &[u8]) -> Option<IpAddr> {
    // `case AF_INET: return inet_pton4(src, dst);`
    if let Some(quad) = pton4(src) {
        return Some(IpAddr::V4(Ipv4Addr::from(quad)));
    }

    // `case AF_INET6: return inet_pton6(src, dst);`
    pton6(src).map(|bytes| IpAddr::V6(Ipv6Addr::from(bytes)))
}

#[cfg(test)]
mod tests {
    use super::{
        close_up_double_colon, groups_of, ntop, ntop4, ntop6, pton, pton4,
        pton6, push_group_hex, GROUPS, IN6ADDRSZ, INADDRSZ, INT16SZ,
        NTOP6_MAX_LEN,
    };
    use crate::util::strparse;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    /// Builds a sixteen-byte address from eight groups.
    fn address(groups: [u16; GROUPS]) -> [u8; IN6ADDRSZ] {
        let mut bytes = [0u8; IN6ADDRSZ];
        for (index, group) in groups.iter().enumerate() {
            let pair = group.to_be_bytes();
            bytes[index * INT16SZ] = pair[0];
            bytes[index * INT16SZ + 1] = pair[1];
        }
        bytes
    }

    // ---- ntop4 -------------------------------------------------------------

    /// The four anchors the specification names, including the widest and the
    /// narrowest answer the function can give.
    #[test]
    fn ntop4_renders_the_documented_anchors() {
        assert_eq!(ntop4(&[0, 0, 0, 0]), "0.0.0.0");
        assert_eq!(ntop4(&[255, 255, 255, 255]), "255.255.255.255");
        assert_eq!(ntop4(&[192, 168, 0, 1]), "192.168.0.1");
        assert_eq!(ntop4(&[1, 2, 3, 4]), "1.2.3.4");
    }

    /// `%d`, not `%03d`: every octet is one to three digits with no padding
    /// and no leading zero, checked for all 256 values.
    #[test]
    fn ntop4_renders_every_byte_value_without_padding() {
        for byte in 0..=u8::MAX {
            let rendered = ntop4(&[byte, 0, 0, 0]);
            let first = rendered
                .split('.')
                .next()
                .expect("a dotted quad has a first field");

            assert!(
                first.bytes().all(strparse::is_digit),
                "{byte} rendered {first}, which is not all decimal digits"
            );
            assert_eq!(
                first.parse::<u8>().ok(),
                Some(byte),
                "{byte} rendered {first}, which does not read back"
            );

            let expected_width = if byte >= 100 {
                3
            } else if byte >= 10 {
                2
            } else {
                1
            };
            assert_eq!(
                first.len(),
                expected_width,
                "{byte} rendered {first}, which is padded or truncated"
            );
            assert!(
                byte == 0 || !first.starts_with('0'),
                "{byte} rendered {first} with a leading zero"
            );
        }
    }

    // ---- ntop6, the three rules that are easy to get wrong ------------------

    /// The all-zero address is `"::"`, and the second colon has a specific
    /// origin worth pinning: the loop emits one colon at the start of the run
    /// and skips every remaining group, so the trailing-run rule at
    /// `inet_ntop.c:182-183` supplies the other. Without that rule the answer
    /// would be `":"`.
    #[test]
    fn ntop6_renders_the_all_zero_address_as_two_colons() {
        assert_eq!(ntop6(&[0; IN6ADDRSZ]), "::");
    }

    /// The loopback address takes the other path through the same code: the
    /// run covers groups 0 through 6, so `base + len` is 7 rather than 8 and
    /// no trailing colon is appended -- group 7 supplies its own leading one.
    #[test]
    fn ntop6_renders_the_loopback_address() {
        assert_eq!(ntop6(&address([0, 0, 0, 0, 0, 0, 0, 1])), "::1");
    }

    /// No compressible run at all: lower-case hexadecimal, no leading zeros,
    /// eight groups and seven colons.
    #[test]
    fn ntop6_renders_a_fully_populated_address() {
        assert_eq!(
            ntop6(&address([0x2001, 0x0db8, 1, 2, 3, 4, 5, 6])),
            "2001:db8:1:2:3:4:5:6"
        );
        assert_eq!(
            ntop6(&address([
                0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff
            ])),
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
        );
        assert_eq!(
            ntop6(&address([0xABCD, 0xEF01, 0, 0, 0, 0, 0xBEEF, 0xDEAD])),
            "abcd:ef01::beef:dead",
            "the digits above `9` must come out in lower case"
        );
    }

    /// **A single zero group is NOT compressed.** `inet_ntop.c:136-137`
    /// discards any run shorter than two, because `::` in place of one group
    /// saves no characters.
    ///
    /// This is the rule most often got wrong, so it is tested at three
    /// positions -- the middle, the front and the back -- rather than once.
    #[test]
    fn ntop6_does_not_compress_a_single_zero_group() {
        assert_eq!(
            ntop6(&address([1, 0, 2, 3, 4, 5, 6, 7])),
            "1:0:2:3:4:5:6:7"
        );
        assert_eq!(
            ntop6(&address([0, 1, 2, 3, 4, 5, 6, 7])),
            "0:1:2:3:4:5:6:7"
        );
        assert_eq!(
            ntop6(&address([1, 2, 3, 4, 5, 6, 7, 0])),
            "1:2:3:4:5:6:7:0"
        );
    }

    /// **On a tie the FIRST longest run wins**, because `cur.len > best.len`
    /// at `inet_ntop.c:129` and `:134` is strict rather than
    /// greater-or-equal.
    #[test]
    fn ntop6_compresses_the_first_of_two_equal_longest_runs() {
        assert_eq!(ntop6(&address([1, 0, 0, 1, 0, 0, 1, 1])), "1::1:0:0:1:1");
    }

    /// A longer LATER run does displace an earlier one -- the strictness is
    /// about ties only. Without this case the test above would also pass an
    /// implementation that simply kept the first run it found.
    #[test]
    fn ntop6_prefers_a_longer_later_run() {
        assert_eq!(ntop6(&address([1, 0, 0, 1, 0, 0, 0, 1])), "1:0:0:1::1");
    }

    /// A run reaching the last group gains a second colon
    /// (`inet_ntop.c:182-183`), because there is no following group to supply
    /// its closing one.
    #[test]
    fn ntop6_appends_a_second_colon_for_a_trailing_run() {
        assert_eq!(ntop6(&address([1, 0, 0, 0, 0, 0, 0, 0])), "1::");
        assert_eq!(ntop6(&address([1, 2, 0, 0, 0, 0, 0, 0])), "1:2::");
    }

    // ---- ntop6, the embedded IPv4 forms ------------------------------------

    /// IPv4-mapped: the zero run is five groups and group 5 holds the `ffff`
    /// marker, which is the second arm of the condition at
    /// `inet_ntop.c:155-156`.
    #[test]
    fn ntop6_renders_an_ipv4_mapped_address_as_a_dotted_quad() {
        let mut bytes = [0u8; IN6ADDRSZ];
        bytes[10] = 0xff;
        bytes[11] = 0xff;
        bytes[12] = 192;
        bytes[13] = 168;
        bytes[14] = 0;
        bytes[15] = 1;
        assert_eq!(ntop6(&bytes), "::ffff:192.168.0.1");

        // Rust agrees on this form, so both are asserted: agreement is worth
        // recording as deliberately as divergence.
        assert_eq!(
            Ipv6Addr::from(bytes).to_string(),
            "::ffff:192.168.0.1",
            "the mapped form is the one std::net also special-cases"
        );
    }

    /// IPv4-**compatible**: the first six groups are zero and group 6 is not,
    /// which is the `best.len == 6` arm. The deprecated form is rendered as a
    /// dotted quad exactly as the mapped form is.
    #[test]
    fn ntop6_renders_an_ipv4_compatible_address_as_a_dotted_quad() {
        let mut bytes = [0u8; IN6ADDRSZ];
        bytes[12] = 192;
        bytes[13] = 168;
        bytes[14] = 0;
        bytes[15] = 1;

        assert_eq!(ntop6(&bytes), "::192.168.0.1", "curl's rendering");
        assert_eq!(
            Ipv6Addr::from(bytes).to_string(),
            "::c0a8:1",
            "std::net's rendering -- the divergence this test exists to pin"
        );

        // The widest compatible address, where the difference is starkest.
        let widest = address([0, 0, 0, 0, 0, 0, 0xffff, 0xffff]);
        assert_eq!(ntop6(&widest), "::255.255.255.255");
        assert_eq!(Ipv6Addr::from(widest).to_string(), "::ffff:ffff");
    }

    /// The other side of the same equality, where the two agree again.
    #[test]
    fn ntop6_prefers_hexadecimal_when_the_seventh_group_is_zero() {
        let bytes = address([0, 0, 0, 0, 0, 0, 0, 0x0100]);

        assert_eq!(ntop6(&bytes), "::100", "curl's rendering");
        assert_eq!(
            Ipv6Addr::from(bytes).to_string(),
            "::100",
            "measured: std::net agrees here, unlike the case above"
        );
    }

    // ---- ntop6, the transcriptions proved against their originals -----------

    /// The four masked tests and `{:x}` are the same function, for all 65,536
    /// group values.
    ///
    /// # Why this one is `#[cfg_attr(miri, ignore)]`d
    ///
    /// Nothing is hidden by the exclusion, and the reasoning is specific
    /// rather than a shrug. Miri looks for undefined behaviour -- aliasing,
    /// out-of-bounds access, uninitialised reads -- and this body contains
    /// integer masking, a sixteen-entry table lookup at a nibble index and
    /// [`String::push`], none of which can exhibit any of those. The
    /// operations in this module that Miri genuinely has something to say
    /// about are the slice work in [`close_up_double_colon`], and
    /// `close_up_matches_the_c_hand_shift_for_every_position` exercises those
    /// **exhaustively** and does run under Miri. The assertion below still
    /// runs in full under `cargo test --workspace`, which is the gate that
    /// owns it, and
    /// [`the_masked_tests_agree_at_every_nibble_boundary`] keeps
    /// [`push_group_hex`] covered under Miri as well.
    #[test]
    #[cfg_attr(miri, ignore = "65,536 passes through core::fmt; see the note")]
    fn the_four_masked_tests_agree_with_lower_hex_for_every_group() {
        let mut rendered = String::with_capacity(4);
        for word in 0..=u16::MAX {
            rendered.clear();
            push_group_hex(&mut rendered, word);
            assert_eq!(
                rendered,
                format!("{word:x}"),
                "the masked tests and lower-hex disagree on {word:#06x}"
            );
        }
    }

    /// The same equivalence at every value where the masks can change their
    /// answer, so that [`push_group_hex`] stays covered under the Miri gate
    /// that the exhaustive sweep above steps out of.
    #[test]
    fn the_masked_tests_agree_at_every_nibble_boundary() {
        const BOUNDARIES: [u16; 20] = [
            0x0000, 0x0001, 0x000f, 0x0010, 0x0011, 0x001f, 0x00f0, 0x00ff,
            0x0100, 0x0101, 0x010f, 0x0110, 0x0f00, 0x0fff, 0x1000, 0x1001,
            0x100f, 0x1010, 0xf000, 0xffff,
        ];

        let mut rendered = String::with_capacity(4);
        for word in BOUNDARIES {
            rendered.clear();
            push_group_hex(&mut rendered, word);
            assert_eq!(
                rendered,
                format!("{word:x}"),
                "the masked tests and lower-hex disagree on {word:#06x}"
            );
        }

        // The two the module documentation names, spelled out so that a
        // reader of this test sees the claim rather than having to evaluate
        // the table above.
        rendered.clear();
        push_group_hex(&mut rendered, 0x0100);
        assert_eq!(rendered, "100", "the wider second mask earns its width");
        rendered.clear();
        push_group_hex(&mut rendered, 0);
        assert_eq!(rendered, "0", "the low nibble is unconditional");
    }

    /// [`groups_of`] and the C's shift-and-or expression agree.
    ///
    /// Its whole purpose is to be comparable with the C, not to be good Rust.
    #[test]
    fn group_decomposition_matches_the_c_shift() {
        /// `words[i / 2] |= ((unsigned int)src[i] << ((1 - (i % 2)) << 3));`
        fn by_the_c_shift(addr: &[u8; IN6ADDRSZ]) -> [u16; GROUPS] {
            let mut words = [0u16; GROUPS];
            for index in 0..IN6ADDRSZ {
                let shift = (1 - (index % 2)) << 3;
                words[index / 2] |= u16::from(addr[index]) << shift;
            }
            words
        }

        let cases: [[u8; IN6ADDRSZ]; 5] = [
            [0; IN6ADDRSZ],
            [0xff; IN6ADDRSZ],
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            [
                0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0, 0xff, 0xff, 0x7f, 0x80,
                192, 168, 0, 1,
            ],
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        ];

        for addr in cases {
            assert_eq!(
                groups_of(&addr),
                by_the_c_shift(&addr),
                "decomposition of {addr:?} disagrees with the C expression"
            );
        }
    }

    /// The `::` close-up and the C's hand-written shift agree, for **every**
    /// position the function can be called with.
    ///
    /// The fixture deliberately fills the bytes beyond `tp` with a non-zero
    /// pattern, even though the real caller always leaves them zero. That is
    /// what makes the test check the implementation's own bound rather than a
    /// coincidence: a fill of `colon_at..tp` instead of
    /// `colon_at..min(tp, 16 - n)` passes with a zero tail and fails here.
    #[test]
    fn close_up_matches_the_c_hand_shift_for_every_position() {
        /// `for(i = 1; i <= n; i++) { *(endp - i) = *(colonp + n - i);
        ///                            *(colonp + n - i) = 0; }`
        fn by_hand(tmp: &mut [u8; IN6ADDRSZ], colon_at: usize, tp: usize) {
            let n = tp - colon_at;
            for i in 1..=n {
                tmp[IN6ADDRSZ - i] = tmp[colon_at + n - i];
                tmp[colon_at + n - i] = 0;
            }
        }

        for colon_at in 0..IN6ADDRSZ {
            for tp in colon_at..IN6ADDRSZ {
                // A distinctive, entirely non-zero pattern, so that a byte
                // left in the wrong place is visible rather than
                // indistinguishable from the fill.
                let mut mine = [0u8; IN6ADDRSZ];
                for (index, slot) in mine.iter_mut().enumerate() {
                    *slot = 0x10 + u8::try_from(index).unwrap_or(0);
                }
                let mut theirs = mine;

                close_up_double_colon(&mut mine, colon_at, tp);
                by_hand(&mut theirs, colon_at, tp);

                assert_eq!(
                    mine, theirs,
                    "close-up disagrees for colon at {colon_at}, cursor {tp}"
                );
            }
        }
    }

    /// The width promise behind `char tmp[46]` (`inet_ntop.c:97`) holds.
    #[test]
    fn ntop6_stays_within_the_width_the_c_promises() {
        let widest = ntop6(&[0xff; IN6ADDRSZ]);
        assert_eq!(widest.len(), 39);
        assert!(widest.len() <= NTOP6_MAX_LEN);
        assert_eq!(NTOP6_MAX_LEN, 45, "the C's sizeof(tmp) less its NUL");
    }

    // ---- the contract this module borrows from strparse ---------------------

    /// [`hexval`](strparse::hexval) answers for exactly the bytes
    /// [`is_xdigit`](strparse::is_xdigit) admits.
    #[test]
    fn hexval_and_is_xdigit_admit_the_same_bytes() {
        for byte in 0..=u8::MAX {
            assert_eq!(
                strparse::hexval(byte).is_some(),
                strparse::is_xdigit(byte),
                "the two disagree about {byte:#04x}"
            );
        }
    }

    // ---- pton4 -------------------------------------------------------------

    /// The forms the specification names, including both extremes.
    #[test]
    fn pton4_accepts_the_documented_forms() {
        assert_eq!(pton4(b"0.0.0.0"), Some([0, 0, 0, 0]));
        assert_eq!(pton4(b"255.255.255.255"), Some([255, 255, 255, 255]));
        assert_eq!(pton4(b"1.2.3.4"), Some([1, 2, 3, 4]));
        assert_eq!(pton4(b"10.0.0.1"), Some([10, 0, 0, 1]));
        assert_eq!(pton4(b"192.168.0.1"), Some([192, 168, 0, 1]));
    }

    /// **A leading zero is rejected, but a bare zero is not.** The three cases
    /// the distinction turns on, traced through
    /// `if(saw_digit && *tp == 0) return 0;` (`inet_pton.c:77-78`), which tests
    /// the accumulator rather than the digit.
    #[test]
    fn pton4_rejects_a_leading_zero_but_accepts_a_bare_zero() {
        // `0` -- the first digit leaves the accumulator at zero with
        // `saw_digit` set, and nothing follows.
        assert_eq!(pton4(b"0.1.2.3"), Some([0, 1, 2, 3]));
        // `01` -- the second digit finds `saw_digit` set and the accumulator
        // still zero.
        assert_eq!(pton4(b"01.2.3.4"), None);
        // `10` -- the second digit finds the accumulator at one.
        assert_eq!(pton4(b"10.2.3.4"), Some([10, 2, 3, 4]));

        // The rejection applies at every octet, not only the first, and `00`
        // is rejected for the same reason `01` is.
        assert_eq!(pton4(b"1.02.3.4"), None);
        assert_eq!(pton4(b"1.2.3.04"), None);
        assert_eq!(pton4(b"00.1.2.3"), None);
        assert_eq!(pton4(b"1.2.3.000"), None);
    }

    /// Every rejection the specification names, each with the C's own reason.
    #[test]
    fn pton4_rejects_the_documented_forms() {
        // Too few octets: `if(octets < 4) return 0;` (`:97-98`).
        assert_eq!(pton4(b"1.2.3"), None);
        assert_eq!(pton4(b"1.2"), None);
        assert_eq!(pton4(b"1"), None);
        // Too many, and a trailing dot, both via `if(octets == 4) return 0;`
        // in the dot arm (`:89-90`).
        assert_eq!(pton4(b"1.2.3.4.5"), None);
        assert_eq!(pton4(b"1.2.3.4."), None);
        // Out of range: `if(val > 255) return 0;` (`:79-80`).
        assert_eq!(pton4(b"256.1.1.1"), None);
        assert_eq!(pton4(b"1.1.1.256"), None);
        assert_eq!(pton4(b"999.999.999.999"), None);
        // Not a digit and not a dot after a digit: the bare `else return 0;`.
        assert_eq!(pton4(b"1.2.3.-4"), None);
        assert_eq!(pton4(b"0x1.2.3.4"), None);
        assert_eq!(pton4(b"1.2.3.4 "), None, "a trailing space is a character");
        assert_eq!(pton4(b" 1.2.3.4"), None, "and so is a leading one");
        assert_eq!(pton4(b".1.2.3"), None, "a leading dot has no digit before");
        assert_eq!(pton4(b"1..2.3"), None, "nor does a doubled dot");
        assert_eq!(pton4(b""), None);
        // No hexadecimal and no octal, however plausible the spelling.
        assert_eq!(pton4(b"a.b.c.d"), None);
        assert_eq!(pton4(b"1.2.3.4a"), None);
    }

    // ---- pton6 -------------------------------------------------------------

    /// The forms the specification names, checked against the bytes rather
    /// than against a rendering, so that a formatter fault cannot mask a
    /// parser fault.
    #[test]
    fn pton6_accepts_the_documented_forms() {
        assert_eq!(pton6(b"::"), Some([0; IN6ADDRSZ]));
        assert_eq!(pton6(b"::1"), Some(address([0, 0, 0, 0, 0, 0, 0, 1])));
        assert_eq!(
            pton6(b"2001:db8::1"),
            Some(address([0x2001, 0x0db8, 0, 0, 0, 0, 0, 1]))
        );
        assert_eq!(
            pton6(b"1:2:3:4:5:6:7:8"),
            Some(address([1, 2, 3, 4, 5, 6, 7, 8])),
            "a complete address with no elision at all"
        );
        assert_eq!(
            pton6(b"::ffff:1.2.3.4"),
            Some(address([0, 0, 0, 0, 0, 0xffff, 0x0102, 0x0304])),
            "the IPv4-mapped form"
        );
        assert_eq!(
            pton6(b"::1.2.3.4"),
            Some(address([0, 0, 0, 0, 0, 0, 0x0102, 0x0304])),
            "the IPv4-compatible form"
        );
        assert_eq!(
            pton6(b"1:2:3:4:5:6:1.2.3.4"),
            Some(address([1, 2, 3, 4, 5, 6, 0x0102, 0x0304])),
            "six groups then a quad -- exactly sixteen bytes"
        );
        // Case is not significant going in, though it is coming out.
        assert_eq!(pton6(b"ABCD::EF"), pton6(b"abcd::ef"));
    }

    /// At most four hexadecimal digits per group
    /// (`if(++saw_xdigit > 4) return 0;`, `inet_pton.c:136-137`).
    #[test]
    fn pton6_accepts_at_most_four_hex_digits_per_group() {
        assert_eq!(
            pton6(b"ffff::"),
            Some(address([0xffff, 0, 0, 0, 0, 0, 0, 0]))
        );
        assert_eq!(pton6(b"12345::"), None);
        assert_eq!(pton6(b"::00000"), None);
        assert_eq!(
            pton6(b"::0000"),
            Some([0; IN6ADDRSZ]),
            "four zeros is a legitimate way to write a zero group"
        );
    }

    /// **A complete address that also carries `::` is rejected**, contradicting
    /// the C's own doc comment.
    #[test]
    fn pton6_rejects_a_full_address_that_also_carries_a_double_colon() {
        assert_eq!(pton6(b"1:2:3:4:5:6:7:8::"), None);
        assert_eq!(pton6(b"::1:2:3:4:5:6:7:8"), None);
        assert_eq!(
            pton6(b"1:2:3:4:5:6::1.2.3.4"),
            None,
            "six groups plus a quad already fills the address"
        );
    }

    /// A zone identifier is not handled here, and that is the C's behaviour
    /// too: `%` reaches the rejecting arm.
    #[test]
    fn pton6_rejects_a_zone_identifier() {
        assert_eq!(pton6(b"fe80::1%eth0"), None);
        assert_eq!(pton6(b"fe80::1%25eth0"), None, "nor percent-encoded");
        assert_eq!(pton6(b"fe80::1%1"), None);
    }

    /// Every remaining rejection the specification names.
    #[test]
    fn pton6_rejects_the_documented_forms() {
        // A leading single colon is only ever half of `::` (`:126-128`).
        assert_eq!(pton6(b":1::"), None);
        assert_eq!(pton6(b":1"), None);
        assert_eq!(pton6(b":"), None);
        // At most one `::` (`if(colonp) return 0;`, `:143-144`).
        assert_eq!(pton6(b"1:::2"), None);
        assert_eq!(pton6(b"::1::2"), None);
        assert_eq!(pton6(b":::"), None);
        // Too many groups: the room test in the colon arm (`:148-149`) or the
        // one guarding the final flush (`:165-166`).
        assert_eq!(pton6(b"1:2:3:4:5:6:7:8:9"), None);
        // Too few, with nothing to stand for the rest (`:186-187`).
        assert_eq!(pton6(b"1:2:3:4:5:6:7"), None);
        assert_eq!(pton6(b"1:2"), None);
        assert_eq!(pton6(b"1"), None);
        // A dotted quad on its own is not an IPv6 address: the quad arm writes
        // four bytes and the length check then rejects the other twelve.
        assert_eq!(pton6(b"1.2.3.4"), None);
        // A quad anywhere but at the end, and one with no room left.
        assert_eq!(pton6(b"1.2.3.4::1"), None);
        assert_eq!(pton6(b"1:2:3:4:5:6:7:1.2.3.4"), None);
        // A quad that is itself invalid takes the whole address down with it.
        assert_eq!(pton6(b"::ffff:1.2.3"), None);
        assert_eq!(pton6(b"::ffff:01.2.3.4"), None);
        assert_eq!(pton6(b"::ffff:256.1.1.1"), None);
        // Not a hexadecimal digit, a colon or a dot.
        assert_eq!(pton6(b"g::1"), None);
        assert_eq!(pton6(b"::1 "), None);
        assert_eq!(pton6(b" ::1"), None);
        assert_eq!(pton6(b"::-1"), None);
        assert_eq!(pton6(b""), None);
    }

    /// **A trailing colon is accepted, where Rust's own parser rejects it.**
    #[test]
    fn pton6_accepts_a_trailing_colon_where_rust_does_not() {
        use std::str::FromStr;

        for (text, expected) in [
            ("1::2:", address([1, 0, 0, 0, 0, 0, 0, 2])),
            ("::1:", address([0, 0, 0, 0, 0, 0, 0, 1])),
            ("1::2:3:", address([1, 0, 0, 0, 0, 0, 2, 3])),
            ("1:2:3:4:5:6:7:8:", address([1, 2, 3, 4, 5, 6, 7, 8])),
        ] {
            assert_eq!(
                pton6(text.as_bytes()),
                Some(expected),
                "curl accepts {text}"
            );
            assert!(
                Ipv6Addr::from_str(text).is_err(),
                "std::net rejects {text} -- the divergence being pinned"
            );
        }

        // A trailing colon does not repair an otherwise short address: seven
        // groups and a colon is fourteen bytes with no `::`, so the final
        // length check still rejects it.
        assert_eq!(pton6(b"1:2:3:4:5:6:7:"), None);
    }

    // ---- the byte-slice contract -------------------------------------------

    /// An interior NUL is a character, not a terminator.
    #[test]
    fn an_interior_nul_is_rejected_rather_than_treated_as_a_terminator() {
        assert_eq!(pton4(b"1.2.3.4\0"), None);
        assert_eq!(pton4(b"1.2.3.4\0garbage"), None);
        assert_eq!(pton6(b"::1\0"), None);
        assert_eq!(pton6(b"::ffff:1.2.3.4\0"), None);
        assert_eq!(pton6(b"\0"), None);
    }

    /// A rejected address yields no bytes at all.
    ///
    /// The C promises to leave `dst` untouched unless it returns 1, and
    /// enforces that by copying only on its last line. Returning [`Option`]
    /// makes it a property of the type: there is nothing to inspect until
    /// there is an answer. Asserted anyway, for the record.
    #[test]
    fn a_rejected_address_yields_nothing_at_all() {
        assert!(pton4(b"not an address").is_none());
        assert!(pton6(b"not an address").is_none());
        assert!(pton(b"not an address").is_none());
    }

    // ---- round trips -------------------------------------------------------

    /// Text to bytes to text, for IPv4.
    #[test]
    fn pton4_and_ntop4_round_trip() {
        for text in [
            "0.0.0.0",
            "1.2.3.4",
            "10.0.0.1",
            "127.0.0.1",
            "192.168.0.1",
            "255.255.255.255",
        ] {
            let bytes = pton4(text.as_bytes())
                .unwrap_or_else(|| panic!("{text} should parse"));
            assert_eq!(ntop4(&bytes), text, "{text} did not survive");
            assert_eq!(
                pton4(ntop4(&bytes).as_bytes()),
                Some(bytes),
                "{text} did not survive the return trip"
            );
        }
    }

    /// Text to bytes to text, for IPv6 -- including both embedded-IPv4 forms
    /// and a fully populated address, which the specification names as the
    /// priority cases.
    #[test]
    fn pton6_and_ntop6_round_trip() {
        for (text, canonical) in [
            ("::", "::"),
            ("::1", "::1"),
            ("1::", "1::"),
            ("2001:db8::1", "2001:db8::1"),
            ("1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8"),
            ("::ffff:192.168.0.1", "::ffff:192.168.0.1"),
            ("::192.168.0.1", "::192.168.0.1"),
            ("::1.2.3.4", "::1.2.3.4"),
            ("1:0:2:3:4:5:6:7", "1:0:2:3:4:5:6:7"),
            ("0000:0000::0001", "::1"),
            ("ABCD::EF", "abcd::ef"),
            ("1:2:3:4:5:6:1.2.3.4", "1:2:3:4:5:6:102:304"),
        ] {
            let bytes = pton6(text.as_bytes())
                .unwrap_or_else(|| panic!("{text} should parse"));
            let rendered = ntop6(&bytes);
            assert_eq!(rendered, canonical, "{text} rendered unexpectedly");
            assert_eq!(
                pton6(rendered.as_bytes()),
                Some(bytes),
                "{canonical} did not parse back to the same bytes"
            );
        }
    }

    // ---- the dispatchers ---------------------------------------------------

    /// [`ntop`] is the C's `switch(af)` with the family carried by the type.
    #[test]
    fn ntop_dispatches_on_the_address_family() {
        assert_eq!(
            ntop(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))),
            "192.168.0.1"
        );
        assert_eq!(ntop(IpAddr::V6(Ipv6Addr::LOCALHOST)), "::1");
        assert_eq!(ntop(IpAddr::V6(Ipv6Addr::UNSPECIFIED)), "::");

        // And it agrees with the two workers it delegates to.
        let quad = [10, 0, 0, 1];
        assert_eq!(ntop(IpAddr::V4(Ipv4Addr::from(quad))), ntop4(&quad));
        let bytes = address([0x2001, 0x0db8, 0, 0, 0, 0, 0, 1]);
        assert_eq!(ntop(IpAddr::V6(Ipv6Addr::from(bytes))), ntop6(&bytes));
    }

    /// [`pton`] answers with the family that parsed, and the two accept sets
    /// really are disjoint -- which is what makes the ordering a matter of
    /// work done rather than of answer given.
    #[test]
    fn pton_answers_with_the_family_that_parsed() {
        assert_eq!(
            pton(b"192.168.0.1"),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)))
        );
        assert_eq!(pton(b"::1"), Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert_eq!(
            pton(b"::ffff:1.2.3.4"),
            Some(IpAddr::V6(Ipv6Addr::from(address([
                0, 0, 0, 0, 0, 0xffff, 0x0102, 0x0304
            ]))))
        );
        assert_eq!(pton(b"example.com"), None);

        // Disjointness, stated as the property the ordering argument rests on.
        for text in [
            "1.2.3.4",
            "0.0.0.0",
            "255.255.255.255",
            "::",
            "::1",
            "1:2:3:4:5:6:7:8",
            "::ffff:1.2.3.4",
        ] {
            let both = pton4(text.as_bytes()).is_some()
                && pton6(text.as_bytes()).is_some();
            assert!(!both, "{text} parses as both families");
        }
    }

    /// Where curl and [`std::net`] agree, both are asserted, so that agreement
    /// is on the record as deliberately as the two divergences are.
    #[test]
    fn curl_and_std_net_agree_outside_the_measured_divergences() {
        use std::str::FromStr;

        for text in [
            "::",
            "::1",
            "1::",
            "2001:db8::1",
            "1:2:3:4:5:6:7:8",
            "::ffff:192.168.0.1",
            "1:0:2:3:4:5:6:7",
            "abcd::ef",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        ] {
            let mine = pton6(text.as_bytes())
                .unwrap_or_else(|| panic!("{text} should parse"));
            let theirs = Ipv6Addr::from_str(text)
                .unwrap_or_else(|_| panic!("{text} should parse for std too"));
            assert_eq!(
                mine,
                theirs.octets(),
                "the parsers disagree about {text}"
            );
            assert_eq!(
                ntop6(&mine),
                theirs.to_string(),
                "the formatters disagree about {text}"
            );
        }

        for text in ["0.0.0.0", "1.2.3.4", "10.0.0.1", "255.255.255.255"] {
            let mine = pton4(text.as_bytes())
                .unwrap_or_else(|| panic!("{text} should parse"));
            let theirs = Ipv4Addr::from_str(text)
                .unwrap_or_else(|_| panic!("{text} should parse for std too"));
            assert_eq!(mine, theirs.octets());
            assert_eq!(ntop4(&mine), theirs.to_string());
        }
    }

    /// The three width constants say what the C's `#define`s say.
    #[test]
    fn the_transcribed_widths_match_the_c_defines() {
        assert_eq!(IN6ADDRSZ, 16);
        assert_eq!(INADDRSZ, 4);
        assert_eq!(INT16SZ, 2);
        assert_eq!(GROUPS, 8, "IN6ADDRSZ / INT16SZ");
    }
}
