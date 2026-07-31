// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! The exact parameter acceptance rules of curl 8.19.0-DEV.
//!
//! Port of `src/tool_paramhlp.c` (733 lines) and `src/tool_paramhlp.h`. AAP
//! section 0.4.1 assigns this module "numeric, protocol, and list parameter
//! parsing with curl's exact acceptance rules".
//!
//! This module is the arbiter of what curl accepts and what curl rejects, so
//! its behaviour is frozen by AAP section 0.8.1: a value curl rejects must be
//! rejected, a value curl accepts must be accepted, and the reported error
//! must be the same one. It also owns the two password prompts, which
//! `curl-rs/src/terminal.rs` explicitly disclaims in the documentation of
//! `getpass_r`.
//!
//! NO USER-SPECIFIED RULES EXIST FOR THIS PROJECT. `review_rules` returns the
//! single line "No user rules provided." -- checked with the default window
//! and again with an explicit full-document range, both returning that
//! identical line, which corroborates AAP section 0.7. Nothing here is
//! therefore attributed to a rule. Every constraint cited below is an AAP
//! requirement drawn from the user's request (AAP section 0.8): binding, but a
//! requirement rather than a rule. Where no requirement speaks,
//! enterprise-standard best practice governs; the absence of rules is not
//! permission to lower the bar.
//!
//! # The primitive that defines "exact"
//!
//! Every numeric parser here delegates to `curlx_str_number`,
//! `curlx_str_octal` or `curlx_str_single`, so [`str_num_base`] is translated
//! first and the parsers are built on it. Its acceptance rules, measured at
//! `lib/curlx/strparse.c:157-192`, are: no leading blanks, no `+`, no `-`
//! (a single minus is handled once, by [`str2num`] alone), leading zeroes
//! accepted, digits consumed greedily with the first non-digit merely ending
//! the scan rather than failing it, and overflow relative to `max` reported
//! separately from "no number at all". Rejecting trailing garbage is a second,
//! explicit step -- `curlx_str_single(&str, '\0')` -- and three functions here
//! deliberately omit it.
//!
//! # Translation differences, each with the C anchor it derives from
//!
//! 1. **`outnum` becomes an owned counter.** `src/tool_paramhlp.c:40` declares
//!    `static int outnum = 0;` inside `new_getout`, making it a process-global
//!    monotonic counter shared across every configuration set rather than a
//!    per-config index. The crate root's blanket safety `forbid` attribute on
//!    `curl-rs/src/main.rs` covers this module, so a mutable `static` cannot
//!    compile at all, and a `static` atomic would be a global singleton that
//!    also destroys test isolation.
//!    AAP section 0.1.2 replaces the C tree's shared mutable state with
//!    "per-module structs and explicit ownership", so the counter is
//!    [`GetOutSeq`], owned by whoever owns the URL list and threaded in by
//!    `&mut`.
//!
//! 2. **`CURLE_TOO_LARGE` is reported as "out of memory", on purpose.**
//!    `lib/curlx/dynbuf.c:82-84` returns `CURLE_TOO_LARGE` -- not
//!    `CURLE_OUT_OF_MEMORY` -- when an append would exceed the buffer's
//!    `toobig` cap. Every caller in this file maps any non-zero result to
//!    `PARAM_NO_MEM`, so an over-large input file really does report "out of
//!    memory" (`src/tool_helpers.c:57`). That is preserved exactly; a truer
//!    error would be a behaviour change, which AAP section 0.8.2 rules out.
//!
//! 3. **`"-0"` is accepted by [`str2unum`].** `src/tool_paramhlp.c:252-260`
//!    calls `str2num` and then rejects only `*val < 0`. A leading minus
//!    applied to zero yields zero, and zero is not negative, so the
//!    "ONLY ACCEPTS POSITIVE NUMBERS" contract at `:245` admits `"-0"`.
//!
//! 4. **[`secs2ms`] performs no trailing-garbage check.**
//!    `src/tool_paramhlp.c:297-336` never calls `curlx_str_single(&str, '\0')`,
//!    so `"1abc"` is 1000 ms and `"1.5xyz"` is 1500 ms. It is also asymmetric
//!    in its errors: an over-large whole part is `PARAM_BAD_NUMERIC` (`:312`)
//!    while a malformed fraction is `PARAM_NUMBER_TOO_LARGE` (`:318-319`),
//!    because that arm maps every failure -- including "no number" -- to the
//!    latter.
//!
//! 5. **[`oct2nummax`]'s negative test is unreachable and kept anyway.**
//!    `src/tool_paramhlp.c:236-237` tests `num < 0`, but `str_num_base`
//!    accumulates only non-negative values and rejects anything above `max`,
//!    so no negative value can reach it. The branch is retained because
//!    removing a guard the oracle contains would be a change to the code being
//!    preserved, and it is expressed as an ordinary comparison so the compiler
//!    does not fold it away.
//!
//! 6. **Interned-pointer equality becomes content equality.**
//!    `src/tool_paramhlp.c:339-350` compares protocol tokens with `==` on
//!    `const char *`, relying on `proto_token()` returning the engine's own
//!    entry. `curl-rs/src/cli/libinfo.rs` documents that comparing the
//!    returned `&'static str` values by content is identical, because the
//!    engine's list holds no duplicates. Content equality is therefore used,
//!    with a `debug_assert!` standing in for the C `DEBUGASSERT(proto ==
//!    proto_token(proto))` at `:343`. Nothing here compares addresses or
//!    takes one.
//!
//! 7. **The login-option separator is hidden without mutation.**
//!    `src/tool_paramhlp.c:578-588` overwrites the caller's string in place --
//!    `*osep = '\0'` before prompting, `*osep = ';'` after -- so that the
//!    prompt shows the user name alone while the composed result keeps the
//!    options. Here the prompt is built from a borrowed prefix and the result
//!    from the untouched original, which is observably identical with no
//!    mutation, no interior mutability and no escape from the safety rules.
//!
//! # Gaps, reported rather than worked around
//!
//! GAP #4: the URL list and the `OperationConfig` aggregate are owned by
//! `curl-rs/src/config/mod.rs`; needed by `src/tool_paramhlp.c:35-55`.
//! `new_getout` cannot append the node itself because AAP section 0.6.9
//! replaces the intrusive `struct getout *next` chain with an owned `Vec`, and
//! in Rust the push belongs to the owner of that `Vec`. [`new_getout`]
//! therefore computes and returns exactly the two fields the C function
//! assigns (`:51-52`) plus the sequence number, and the owner performs the
//! push. Reported rather than worked around: reaching into another module's
//! aggregate would rebuild the god-struct coupling AAP section 0.4.2 removes.
//!
//! GAP #5: `curl-rs/src/terminal.rs`'s `getpass_r` takes its prompt as `&str`;
//! needed by `src/tool_paramhlp.c:575-586`. A user name that is not valid
//! UTF-8 is therefore rendered with replacement characters in the prompt text.
//! The divergence is confined to that one display string: the composed
//! credential is assembled from the original bytes and is byte-exact, which is
//! the part AAP section 0.8.1 freezes because Basic authentication encodes
//! precisely those bytes. Reported rather than worked around: rendering the
//! credential lossily to make the prompt lossless would corrupt what goes on
//! the wire.
//!
//! Gap 1 and Gap 2 are `curl-rs/src/terminal.rs`'s, and GAP #3 is
//! `curl-rs/src/util.rs`'s. Nothing here attempts to compensate for Gap 2:
//! no newline is added after the prompt, no re-prompt is issued and no
//! terminal control is attempted.
//!
//! # What this module does not do
//!
//! It emits no error text. Every fallible entry point returns a
//! [`ParameterError`] variant and `curl-rs/src/cli/args.rs` renders it through
//! its port of `param2text` (`src/tool_helpers.c:35-75`). It writes nothing to
//! standard error directly either: the three warnings it can raise go through
//! `curl-rs/src/output/msgs.rs`, which owns the `Warning: ` prefix and the
//! `--silent` gate. And it never logs, traces or `Debug`-prints a password;
//! [`OperationArgs`] deliberately derives no `Debug` for that reason.

use std::io::{self, Read, Seek, SeekFrom, Write};

use curl_rs_lib::error::CURLcode;

use super::args::ParameterError;
use super::libinfo::LibInfo;
use crate::output::msgs::{warnf, warnf_bytes, MsgConfig};
use crate::terminal::getpass_r;
use crate::util::struplocompare4sort;

// ===========================================================================
// Constants -- every one measured in this tree, none invented
// ===========================================================================

/// `LONG_MAX`, the bound `str2num` and `secs2ms` apply.
///
/// `long` is 64 bits on all four targets AAP section 0.1.1 goal G8 mandates
/// (`x86_64`/`aarch64` on `unknown-linux-gnu` and `apple-darwin`, all LP64),
/// so `i64` is the faithful width. AAP section 0.2.2 excludes 32-bit targets
/// explicitly, calling the narrower `long` "a deliberate forfeit rather than
/// an oversight".
const LONG_MAX: i64 = i64::MAX;

/// `CURL_OFF_T_MAX`. `curl_off_t` is 64 bits on every mandated target.
const CURL_OFF_T_MAX: i64 = i64::MAX;

/// `MAX_FILE2MEMORY` -- `src/tool_paramhlp.h:32-36`.
///
/// The C header selects `16LL * 1024 * 1024 * 1024` when `SIZEOF_SIZE_T > 4`
/// and `INT_MAX` otherwise. Both arms are reproduced: the wide one is what all
/// four mandated targets use, and keeping the narrow one means this module
/// still compiles, with the cap the C code would have chosen, on a 32-bit host
/// rather than overflowing its own constant.
#[cfg(target_pointer_width = "64")]
const MAX_FILE2MEMORY: usize = 16 * 1024 * 1024 * 1024;

/// `MAX_FILE2MEMORY` on a target whose `size_t` is at most 32 bits:
/// `INT_MAX`, per the `#else` arm of `src/tool_paramhlp.h:34-36`.
#[cfg(not(target_pointer_width = "64"))]
const MAX_FILE2MEMORY: usize = i32::MAX as usize;

/// `MAX_FILE2STRING` -- `src/tool_paramhlp.c:84` aliases `MAX_FILE2MEMORY`.
const MAX_FILE2STRING: usize = MAX_FILE2MEMORY;

/// `MAX_USERPWDLENGTH` -- `src/tool_paramhlp.c:547`, `100 * 1024`.
const MAX_USERPWDLENGTH: usize = 100 * 1024;

/// `MAX_PROTOS` -- `src/tool_paramhlp.c:391`.
const MAX_PROTOS: usize = 34;

/// `MAX_PROTOSTRING` -- `src/tool_paramhlp.c:392`, `MAX_PROTOS * 11`, with the
/// C comment "Room for MAX_PROTOS number of 10-chars proto names."
const MAX_PROTOSTRING: usize = MAX_PROTOS * 11;

/// `sizeof(passwd)` for the `char passwd[2048]` of
/// `src/tool_paramhlp.c:567`, passed on to `getpass_r` at `:586`.
///
/// AAP section 0.8.2 forbids widening it: the password is truncated at this
/// bound exactly as C truncates it.
const PASSWORD_BUFFER_SIZE: usize = 2048;

/// `sizeof(buffer)` for the two `char buffer[4096]` read buffers of
/// `src/tool_paramhlp.c:92` and `:143`.
///
/// The size is behaviourally visible, not an implementation detail: the
/// stripping loop in [`file2string`] and the range arithmetic in
/// [`file2memory_range`] both step chunk by chunk, so the reader below refills
/// this many bytes per pass exactly as `fread` does.
const READ_CHUNK: usize = 4096;

/// `sizeof(buffer) - 1` for the `char buffer[32]` of
/// `src/tool_paramhlp.c:463`, which `curl_msnprintf` fills with at most 31
/// bytes plus a terminator.
///
/// A longer protocol token is silently truncated to this length before
/// `proto_token()` ever sees it, so the truncation is part of the acceptance
/// rule rather than a buffer detail.
const PROTO_TOKEN_MAX: usize = 31;

/// `CURLFTPMETHOD_MULTICWD` -- `include/curl/curl.h:1018`.
const CURLFTPMETHOD_MULTICWD: i64 = 1;

/// `CURLFTPMETHOD_NOCWD` -- `include/curl/curl.h:1020`.
const CURLFTPMETHOD_NOCWD: i64 = 2;

/// `CURLFTPMETHOD_SINGLECWD` -- `include/curl/curl.h:1021`.
const CURLFTPMETHOD_SINGLECWD: i64 = 3;

/// `CURLFTPSSL_CCC_PASSIVE` -- `include/curl/curl.h:988`.
///
/// The group also holds `CURLFTPSSL_CCC_NONE = 0`
/// (`include/curl/curl.h:987`), which `ftpcccmethod` never selects because its
/// fallback is the passive mode; it is recorded here rather than declared so
/// that no constant in this file is unused.
const CURLFTPSSL_CCC_PASSIVE: i64 = 1;

/// `CURLFTPSSL_CCC_ACTIVE` -- `include/curl/curl.h:989`.
const CURLFTPSSL_CCC_ACTIVE: i64 = 2;

/// `CURLGSSAPI_DELEGATION_NONE` -- `include/curl/curl.h:861`.
const CURLGSSAPI_DELEGATION_NONE: i64 = 0;

/// `CURLGSSAPI_DELEGATION_POLICY_FLAG` -- `include/curl/curl.h:862`.
///
/// The C spelling is `(1L << 0)`; written as the literal `1` here because
/// `clippy::identity_op` rejects a shift by zero and the value is what the ABI
/// pins, not the expression.
const CURLGSSAPI_DELEGATION_POLICY_FLAG: i64 = 1;

/// `CURLGSSAPI_DELEGATION_FLAG` -- `include/curl/curl.h:863`, `(1L << 1)`.
const CURLGSSAPI_DELEGATION_FLAG: i64 = 1 << 1;

// ===========================================================================
// The acceptance-rule primitive: lib/curlx/strparse.c, translated first
// ===========================================================================

/// The subset of `STRE_*` (`lib/curlx/strparse.h:28-36`) this module can
/// observe.
///
/// `STRE_OK` is absent because success is `Result::Ok`. The distinction
/// between `STRE_OVERFLOW` (7) and everything else is observable exactly once,
/// in [`oct2nummax`], which is the only caller that maps overflow to a
/// different `ParameterError` than a malformed number
/// (`src/tool_paramhlp.c:229-233`). Keeping the variants separate is what
/// makes that difference expressible rather than accidental.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StrError {
    /// `STRE_BYTE` (5) -- `curlx_str_single` found a different byte
    /// (`lib/curlx/strparse.c:126-133`).
    Byte,

    /// `STRE_OVERFLOW` (7) -- the accumulated value would exceed `max`.
    Overflow,

    /// `STRE_NO_NUM` (8) -- the first byte is not a digit in the given base.
    NoNum,
}

/// `curlx_hexasciitable` -- `lib/curlx/strparse.c:148-154`, verbatim.
///
/// Indexed by `byte - b'0'`, which is why the entry for `'0'` is 16 rather
/// than 0: the C comment at `:145-147` records that the non-zero value exists
/// so `valid_digit()` can use the same table as the value lookup. The value is
/// recovered by masking with `0x0f` (`lib/curlx/strparse.h:111`), so 16 masks
/// back to 0.
///
/// 55 entries span `'0'` (0x30) through `'f'` (0x66) inclusive, which is why
/// [`hex_ascii_table`] bounds-checks rather than indexing blindly: C relies on
/// `valid_digit`'s `byte <= m` test to stay inside the array, and `m` is never
/// above `'f'`.
const HEX_ASCII_TABLE: [u8; 55] = [
    // 0x30: '0' - '9'
    16, 1, 2, 3, 4, 5, 6, 7, 8, 9, //
    // 0x3a - 0x40
    0, 0, 0, 0, 0, 0, 0, //
    // 0x41: 'A' - 'F'
    10, 11, 12, 13, 14, 15, //
    // 0x47 - 0x60
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, //
    // 0x61: 'a' - 'f'
    10, 11, 12, 13, 14, 15,
];

/// `curlx_hexasciitable[byte - '0']`, with C's implicit precondition made
/// explicit.
///
/// Returns 0 -- the table's "not a digit" value -- for any byte outside the
/// table, which is the answer `valid_digit` needs and which keeps the lookup
/// free of a panicking index.
fn hex_ascii_table(byte: u8) -> u8 {
    match byte.checked_sub(b'0') {
        Some(index) => match HEX_ASCII_TABLE.get(usize::from(index)) {
            Some(value) => *value,
            None => 0,
        },
        None => 0,
    }
}

/// `curlx_hexval(x)` -- `lib/curlx/strparse.h:111`, the table entry masked to
/// its low nibble.
fn hexval(byte: u8) -> u8 {
    hex_ascii_table(byte) & 0x0f
}

/// `valid_digit(x, m)` -- `lib/curlx/strparse.c:142-143`.
///
/// All three conjuncts are kept in order: at or above `'0'`, at or below the
/// largest digit the base permits, and a non-zero table entry. The third is
/// what excludes the seven punctuation bytes between `'9'` and `'A'` for
/// base 16.
fn valid_digit(byte: u8, largest: u8) -> bool {
    byte >= b'0' && byte <= largest && hex_ascii_table(byte) != 0
}

/// A read cursor over a parameter string.
///
/// C advances a `const char **` and reads `*p`, relying on the NUL terminator
/// to end the scan. This holds a byte slice and an index instead: no raw
/// pointer, no arithmetic that can run off the end, and [`Cursor::peek`]
/// yields 0 past the last byte so that every `'\0'` test in the C code
/// translates literally.
///
/// A NUL byte embedded in the input therefore behaves exactly as it does in C,
/// where it would have terminated the string: the digit scan stops there and
/// the end-of-string test succeeds.
struct Cursor<'a> {
    /// The bytes being scanned.
    bytes: &'a [u8],

    /// Index of the next byte to read; may equal `bytes.len()`, and may pass
    /// it once, mirroring C's `(*linep)++` over the terminator.
    pos: usize,
}

impl<'a> Cursor<'a> {
    /// Starts a scan at the first byte of `input`.
    fn new(input: &'a str) -> Self {
        Self {
            bytes: input.as_bytes(),
            pos: 0,
        }
    }

    /// C's `**linep`: the byte under the cursor, or 0 at or past the end.
    fn peek(&self) -> u8 {
        match self.bytes.get(self.pos) {
            Some(byte) => *byte,
            None => 0,
        }
    }

    /// C's `(*linep)++`.
    ///
    /// Saturating so the index cannot wrap; the value is only ever compared
    /// against the slice length, so saturation is unobservable.
    fn bump(&mut self) {
        self.pos = self.pos.saturating_add(1);
    }

    /// The number of bytes consumed so far.
    ///
    /// `secs2ms` needs this to count the digits of the fractional part, which
    /// C obtains as the pointer difference `str - s`
    /// (`src/tool_paramhlp.c:321`).
    fn offset(&self) -> usize {
        self.pos
    }
}

/// `str_num_base` -- `lib/curlx/strparse.c:157-192`.
///
/// No `0x` prefix, no leading blanks, no sign. Both overflow arms are
/// reproduced, including the C code's reason for having two: when `max` is
/// below the base, a pre-multiplication check cannot be expressed, so the
/// value is accumulated first and tested afterwards.
///
/// The C function zeroes `*nump` before the digit test, so a failed parse
/// leaves zero behind. That is unobservable here because failure yields
/// `Err` and no value at all.
fn str_num_base(
    cursor: &mut Cursor<'_>,
    max: i64,
    base: i64,
) -> Result<i64, StrError> {
    // `:161-162` -- the largest digit the base admits.
    let largest = if base == 10 {
        b'9'
    } else if base == 16 {
        b'f'
    } else {
        b'7'
    };

    // `:164-166` -- the three C DEBUGASSERTs, kept as debug assertions
    // because they document caller obligations rather than input validation.
    debug_assert!(base == 8 || base == 10 || base == 16);
    debug_assert!(max >= 0, "SIZE_MAX-style maxima are rejected upstream");

    let mut num: i64 = 0;

    // `:169-170` -- a first byte that is not a digit is "no number".
    if !valid_digit(cursor.peek(), largest) {
        return Err(StrError::NoNum);
    }

    if max < base {
        // `:171-178` -- the special-cased low maximum: accumulate, then test.
        loop {
            let digit = i64::from(hexval(cursor.peek()));
            cursor.bump();
            // Cannot overflow: on entry `num <= max < base <= 16`, so the
            // product is at most 256. Checked anyway so that no arithmetic
            // here can panic in a debug build, and reported as overflow --
            // which is the outcome the very next line would produce.
            num = match num.checked_mul(base).and_then(|v| v.checked_add(digit))
            {
                Some(value) => value,
                None => return Err(StrError::Overflow),
            };
            if num > max {
                return Err(StrError::Overflow);
            }
            if !valid_digit(cursor.peek(), largest) {
                break;
            }
        }
    } else {
        // `:180-187` -- the ordinary arm: test before multiplying.
        loop {
            let digit = i64::from(hexval(cursor.peek()));
            cursor.bump();
            // `max >= base > digit`, so the subtraction is non-negative and
            // the division is well defined.
            if num > (max - digit) / base {
                return Err(StrError::Overflow);
            }
            // Cannot overflow: the guard above gives `num * base <= max -
            // digit`, hence `num * base + digit <= max <= i64::MAX`. Checked
            // for the same no-panic reason as the other arm.
            num = match num.checked_mul(base).and_then(|v| v.checked_add(digit))
            {
                Some(value) => value,
                None => return Err(StrError::Overflow),
            };
            if !valid_digit(cursor.peek(), largest) {
                break;
            }
        }
    }

    // `:189-191`
    Ok(num)
}

/// `curlx_str_number` -- `lib/curlx/strparse.c:196-199`, base 10.
fn str_number(cursor: &mut Cursor<'_>, max: i64) -> Result<i64, StrError> {
    str_num_base(cursor, max, 10)
}

/// `curlx_str_octal` -- `lib/curlx/strparse.c:210-213`, base 8.
///
/// Because the largest digit is `'7'`, `'8'` and `'9'` are not digits at all:
/// `"08"` parses as 0, stops at the `'8'`, and is then rejected by the
/// trailing-garbage test rather than by the number scan.
fn str_octal(cursor: &mut Cursor<'_>, max: i64) -> Result<i64, StrError> {
    str_num_base(cursor, max, 8)
}

/// `curlx_str_single` -- `lib/curlx/strparse.c:126-133`.
///
/// Called with 0 it is the "must be exactly at the end of the string" test
/// that rejects trailing garbage, trailing blanks included.
fn str_single(cursor: &mut Cursor<'_>, byte: u8) -> Result<(), StrError> {
    if cursor.peek() != byte {
        return Err(StrError::Byte);
    }
    cursor.bump();
    Ok(())
}

// ===========================================================================
// Numeric parameters
// ===========================================================================

/// `str2num` -- `src/tool_paramhlp.c:206-221`.
///
/// Accepts an optional single leading `'-'`, then an unsigned decimal number
/// bounded by [`LONG_MAX`], then end of string. Everything else is
/// `PARAM_BAD_NUMERIC`, which is what makes both "not a number" and "too
/// large" indistinguishable here -- unlike in [`oct2nummax`].
///
/// Three consequences of the exact order of operations, each asserted in the
/// tests:
///
/// - `"--5"` is rejected: the minus is consumed once, and the second one is
///   not a digit.
/// - `"+1"`, `" 1"` and `"1 "` are rejected: the primitive accepts no sign and
///   no blanks, and the trailing test accepts nothing but the end.
/// - `LONG_MIN` is not representable. The bound is applied to the magnitude
///   *before* negation, so `"-9223372036854775808"` overflows and is rejected.
///
/// The C function's `DEBUGASSERT(str)` at `:210` is expressed in the type: the
/// callers that can pass NULL are `secs2ms`, `str2tls_max` and
/// `check_protocol`, and only those three take an `Option`.
pub(crate) fn str2num(text: &str) -> Result<i64, ParameterError> {
    let mut cursor = Cursor::new(text);

    // `:211-212` -- one optional minus, and only one.
    let is_neg = str_single(&mut cursor, b'-').is_ok();

    // `:213-215` -- both failures collapse to one error here.
    let num = match str_number(&mut cursor, LONG_MAX) {
        Ok(value) => value,
        Err(_) => return Err(ParameterError::BadNumeric),
    };
    if str_single(&mut cursor, 0).is_err() {
        return Err(ParameterError::BadNumeric);
    }

    // `:217-219`. Negating a value in `0..=LONG_MAX` cannot overflow, which is
    // precisely why `LONG_MIN` cannot be reached.
    Ok(if is_neg { -num } else { num })
}

/// `oct2nummax` -- `src/tool_paramhlp.c:223-241`.
///
/// The only function in this module that distinguishes overflow:
/// `STRE_OVERFLOW`
/// becomes `PARAM_NUMBER_TOO_LARGE` (`:230-231`) while every other failure
/// becomes `PARAM_BAD_NUMERIC` (`:232`).
///
/// No sign is accepted at all, and because the octal scan stops at `'8'`, the
/// inputs `"08"`, `"0644x"` and `"777 "` all fail the trailing-garbage test at
/// `:234-235` rather than the number scan.
///
/// The sole caller passes `0777` (`src/tool_getparam.c:2415`, the
/// `--create-file-mode` option).
pub(crate) fn oct2nummax(text: &str, max: i64) -> Result<i64, ParameterError> {
    let mut cursor = Cursor::new(text);

    // `:228-233`
    let num = match str_octal(&mut cursor, max) {
        Ok(value) => value,
        Err(StrError::Overflow) => return Err(ParameterError::NumberTooLarge),
        Err(_) => return Err(ParameterError::BadNumeric),
    };

    // `:234-235`
    if str_single(&mut cursor, 0).is_err() {
        return Err(ParameterError::BadNumeric);
    }

    // `:236-237`. Unreachable: `str_num_base` accumulates only non-negative
    // values and rejects anything above `max`. Translation difference 5 in the
    // module documentation explains why it is kept: it is a guard the oracle
    // contains, and it is written as an ordinary comparison on the parsed value
    // so that it stays in the compiled code rather than being folded away.
    if num < 0 {
        return Err(ParameterError::NegativeNumeric);
    }

    // `:238`
    Ok(num)
}

/// `str2unum` -- `src/tool_paramhlp.c:252-261`.
///
/// [`str2num`] followed by a single rejection of negative results, which is
/// why `"-0"` is **accepted**: the minus yields zero and zero is not negative.
/// Translation difference 3 in the module documentation records the anchor.
pub(crate) fn str2unum(text: &str) -> Result<i64, ParameterError> {
    // `:254-256`
    let value = str2num(text)?;

    // `:257-258`
    if value < 0 {
        return Err(ParameterError::NegativeNumeric);
    }

    Ok(value)
}

/// `str2unummax` -- `src/tool_paramhlp.c:273-282`.
///
/// [`str2unum`] plus an inclusive upper bound: `max` itself is accepted and
/// anything above it is `PARAM_NUMBER_TOO_LARGE`.
pub(crate) fn str2unummax(text: &str, max: i64) -> Result<i64, ParameterError> {
    // `:275-277`
    let value = str2unum(text)?;

    // `:278-279`
    if value > max {
        return Err(ParameterError::NumberTooLarge);
    }

    Ok(value)
}

/// `secs2ms` -- `src/tool_paramhlp.c:297-331`.
///
/// Parses seconds with an optional decimal fraction and yields milliseconds.
/// The subtlest function in the file, in four ways that are all asserted in the
/// tests:
///
/// 1. **No trailing-garbage check at all.** `"1abc"` is 1000 and `"1.5xyz"` is
///    1500. Translation difference 4 in the module documentation records this.
/// 2. **Asymmetric errors.** An absent argument or an over-large whole part is
///    `PARAM_BAD_NUMERIC` (`:312-313`); a malformed fraction such as `"1."` is
///    `PARAM_NUMBER_TOO_LARGE`, because `:318-319` maps every failure of the
///    fraction scan -- "no number" included -- to that variant.
/// 3. **Trailing zeroes in the fraction matter to the arithmetic but not to the
///    result.** The divisor is chosen by the digit *count*: `"1.5"` divides by
///    1, `"1.50"` by 10 and `"1.500"` by 100, so all three are 1500.
/// 4. **The whole part is bounded by `LONG_MAX / 1000 - 1`**, which is what
///    makes the final `secs * 1000 + ms` unable to overflow.
pub(crate) fn secs2ms(text: Option<&str>) -> Result<i64, ParameterError> {
    /// `digs[]` -- `src/tool_paramhlp.c:301-311`, nine entries.
    ///
    /// `CURL_ARRAYSIZE(digs)` is 9 and the loop below tests `len > 9` rather
    /// than `>=`, so the index `len - 1` stays within `0..=8`.
    const DIGS: [u32; 9] = [
        1,
        10,
        100,
        1_000,
        10_000,
        100_000,
        1_000_000,
        10_000_000,
        100_000_000,
    ];

    // `:312-313` -- the NULL test and the whole-seconds scan share one error.
    let text = match text {
        Some(value) => value,
        None => return Err(ParameterError::BadNumeric),
    };
    let mut cursor = Cursor::new(text);
    let secs = match str_number(&mut cursor, LONG_MAX / 1000 - 1) {
        Ok(value) => value,
        Err(_) => return Err(ParameterError::BadNumeric),
    };

    let mut ms: i64 = 0;

    // `:314` -- a fraction is present only if the next byte is a full stop.
    if str_single(&mut cursor, b'.').is_ok() {
        // `:316` -- C remembers the pointer so it can measure the digit count.
        let start = cursor.offset();

        // `:318-319` -- every failure here is NUMBER_TOO_LARGE, including
        // STRE_NO_NUM for an input such as "1.".
        let mut fracs = match str_number(&mut cursor, CURL_OFF_T_MAX) {
            Ok(value) => value,
            Err(_) => return Err(ParameterError::NumberTooLarge),
        };

        // `:321` -- `len = (str - s)`. The cursor only ever advances, so the
        // subtraction cannot go negative.
        let mut len = cursor.offset().saturating_sub(start);
        debug_assert!(
            len >= 1,
            "a successful scan consumed at least one digit"
        );

        // `:322-325`. This terminates with `len` in `1..=9`: a scan of `len`
        // digits yields `fracs < 10^len`, each pass preserves that invariant,
        // and at `len == 1` the value is at most 9, which is far below
        // `LONG_MAX / 100`. The saturating decrement therefore never
        // saturates; it is written that way so the arithmetic cannot panic.
        while len > DIGS.len() || fracs > LONG_MAX / 100 {
            fracs /= 10;
            len = len.saturating_sub(1);
        }

        // `:326` -- `digs[len - 1]`.
        let scale = match DIGS.get(len.saturating_sub(1)) {
            Some(value) => i64::from(*value),
            // Unreachable by the argument above. Reported rather than indexed
            // blindly, so that no slice access in this module can panic.
            None => return Err(ParameterError::NumberTooLarge),
        };

        // `fracs <= LONG_MAX / 100` is the loop's exit condition, so the
        // multiplication cannot overflow; `scale` is a power of ten and never
        // zero, so the division is well defined. The result is below 1000
        // because `fracs < 10^len` and `scale == 10^(len - 1)`.
        ms = fracs.saturating_mul(100) / scale;
    }

    // `:329`. `secs <= LONG_MAX / 1000 - 1` and `ms <= 999`, so the sum is at
    // most `LONG_MAX - 1`.
    Ok(secs.saturating_mul(1000).saturating_add(ms))
}

/// `str2offset` -- `src/tool_paramhlp.c:539-545`.
///
/// An unsigned `curl_off_t`: no sign, no trailing garbage, bounded by
/// [`CURL_OFF_T_MAX`]. The C documentation at `:533` states the contract in
/// capitals -- "The offset CANNOT be negative!" -- and the absence of a minus
/// arm is what enforces it.
pub(crate) fn str2offset(text: &str) -> Result<i64, ParameterError> {
    let mut cursor = Cursor::new(text);

    // `:541-543` -- one scan, then the end-of-string test, and a single error
    // for either failure.
    let value = match str_number(&mut cursor, CURL_OFF_T_MAX) {
        Ok(value) => value,
        Err(_) => return Err(ParameterError::BadNumeric),
    };
    if str_single(&mut cursor, 0).is_err() {
        return Err(ParameterError::BadNumeric);
    }

    Ok(value)
}

/// `str2tls_max` -- `src/tool_paramhlp.c:710-732`.
///
/// The one string table in this module that is **case-sensitive**: `:726` uses
/// `strcmp`, not `curl_strequal`, so `"DEFAULT"` is rejected while `"default"`
/// is accepted. Preserved deliberately.
///
/// An absent argument is `PARAM_REQUIRES_PARAMETER` (`:723-724`) and an
/// unrecognised one is `PARAM_BAD_USE` (`:731`).
pub(crate) fn str2tls_max(text: Option<&str>) -> Result<u8, ParameterError> {
    /// `tls_max_array[]` -- `src/tool_paramhlp.c:715-721`. The comment on the
    /// first entry reads "lets the library decide".
    const TLS_MAX_ARRAY: [(&str, u8); 5] = [
        ("default", 0),
        ("1.0", 1),
        ("1.1", 2),
        ("1.2", 3),
        ("1.3", 4),
    ];

    // `:723-724`
    let text = match text {
        Some(value) => value,
        None => return Err(ParameterError::RequiresParameter),
    };

    // `:725-730` -- `strcmp`, hence `==` on the whole string and not
    // `eq_ignore_ascii_case`.
    for (name, value) in TLS_MAX_ARRAY {
        if text == name {
            return Ok(value);
        }
    }

    // `:731`
    Err(ParameterError::BadUse)
}

// ===========================================================================
// File readers
// ===========================================================================

/// The two capabilities `file2memory_range` asks of a `FILE *`.
///
/// `src/tool_paramhlp.c:130` branches on `file != stdin` to decide whether it
/// may seek, and `:136` explains the alternative: "we cannot seek stdin, read
/// 'starto' bytes and throw them away". `src/var.c:443-446` confirms those are
/// the only two things the one caller passes -- `stdin`, or the result of
/// `curlx_fopen`.
///
/// That branch is a property of the source, not of the algorithm, so it is
/// expressed as a trait with two implementations rather than as a runtime
/// comparison against a global. AAP section 0.3.3 pattern P12 injects such
/// capabilities precisely so the behaviour can be exercised without the real
/// resource; both arms are covered by the tests below using in-memory sources.
pub(crate) trait ByteSource {
    /// One `fread` of up to `buffer.len()` bytes.
    ///
    /// Returns short only at end of input, exactly as `fread` does, so that
    /// chunk boundaries match the C code even though `Read::read` is permitted
    /// to return early.
    fn read_block(&mut self, buffer: &mut [u8]) -> io::Result<usize>;

    /// `curlx_fseek(file, offset, SEEK_SET)`, or `None` when the source cannot
    /// seek -- the `file == stdin` arm of `src/tool_paramhlp.c:130-137`.
    fn seek_start(&mut self, offset: u64) -> Option<io::Result<()>>;
}

/// A seekable source: the `file != stdin` arm.
pub(crate) struct SeekSource<T> {
    /// The underlying reader.
    inner: T,
}

impl<T: Read + Seek> SeekSource<T> {
    /// Wraps a reader that supports seeking, such as a `std::fs::File`.
    pub(crate) fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl<T: Read + Seek> ByteSource for SeekSource<T> {
    fn read_block(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        fread(&mut self.inner, buffer)
    }

    fn seek_start(&mut self, offset: u64) -> Option<io::Result<()>> {
        Some(self.inner.seek(SeekFrom::Start(offset)).map(|_| ()))
    }
}

/// A non-seekable source: the `file == stdin` arm.
pub(crate) struct StreamSource<R> {
    /// The underlying reader.
    inner: R,
}

impl<R: Read> StreamSource<R> {
    /// Wraps a reader that cannot seek, such as standard input.
    pub(crate) fn new(inner: R) -> Self {
        Self { inner }
    }
}

impl<R: Read> ByteSource for StreamSource<R> {
    fn read_block(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        fread(&mut self.inner, buffer)
    }

    fn seek_start(&mut self, _offset: u64) -> Option<io::Result<()>> {
        // `:135-137` -- seeking is impossible, so the caller drains instead.
        None
    }
}

/// `fread(buffer, 1, sizeof(buffer), file)`.
///
/// `Read::read` may return fewer bytes than requested for reasons that have
/// nothing to do with end of input, while `fread` returns short only at end of
/// input or on error. The distinction is behaviourally visible here because
/// both readers below process the buffer chunk by chunk, so the loop reproduces
/// `fread` rather than exposing `read`'s weaker guarantee.
///
/// `ErrorKind::Interrupted` is retried, which is what the C library does for
/// `EINTR`. Any other error is propagated, and every caller turns it into
/// `PARAM_READ_ERROR` -- the C `ferror(file)` test at
/// `src/tool_paramhlp.c:95` and `:147`, which likewise discards whatever had
/// already been read.
fn fread(reader: &mut dyn Read, buffer: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0usize;
    while filled < buffer.len() {
        let rest = match buffer.get_mut(filled..) {
            Some(slice) => slice,
            // Unreachable: `filled < buffer.len()` is the loop condition.
            None => break,
        };
        match reader.read(rest) {
            Ok(0) => break,
            Ok(count) => filled = filled.saturating_add(count),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
            Err(error) => return Err(error),
        }
    }
    Ok(filled)
}

/// `ISCRLF(x)` -- `src/tool_paramhlp.c:57`.
///
/// A NUL byte counts as a line terminator alongside CR and LF, which matters
/// because [`file2string`] uses it to end a piece.
fn is_crlf(byte: u8) -> bool {
    byte == b'\r' || byte == b'\n' || byte == 0
}

/// `memcrlf` -- `src/tool_paramhlp.c:69-82`.
///
/// Two modes, selected by the C exclusive-or test `if(countcrlf ^ crlf)` at
/// `:78`, which for two truth values is inequality:
///
/// - `countcrlf == false`: the number of leading bytes that are **not** CR, LF
///   or NUL.
/// - `countcrlf == true`: the number of leading bytes that **are**.
///
/// With no delimiter found it returns the whole length, which is C's
/// `return total;` at `:81`.
fn memcrlf(mem: &[u8], countcrlf: bool) -> usize {
    for (index, byte) in mem.iter().enumerate() {
        // `:77-79`
        if countcrlf != is_crlf(*byte) {
            return index;
        }
    }
    mem.len()
}

/// `curlx_dyn_addn` reduced to the one outcome this module can observe.
///
/// `lib/curlx/dynbuf.c:72` computes `fit = len + idx + 1` -- the new bytes,
/// the bytes already held, and the terminator C always reserves -- and
/// `:82-84` rejects `fit > toobig` with `CURLE_TOO_LARGE`. Every caller here
/// maps any non-zero result to `PARAM_NO_MEM`, so that is what this returns;
/// translation difference 2 in the module documentation records why the less
/// accurate error is the faithful one.
///
/// The terminator is counted even though a `Vec<u8>` needs none, because the
/// cap is an observable acceptance boundary rather than an allocation detail.
fn dyn_addn(
    out: &mut Vec<u8>,
    mem: &[u8],
    toobig: usize,
) -> Result<(), ParameterError> {
    let fit = mem.len().saturating_add(out.len()).saturating_add(1);
    if fit > toobig {
        return Err(ParameterError::NoMem);
    }
    out.extend_from_slice(mem);
    Ok(())
}

/// A byte count as a `curl_off_t`.
///
/// Every length converted here is at most [`READ_CHUNK`], so the conversion is
/// exact. The saturating fallback exists only so that no conversion in this
/// module can panic.
fn as_off(len: usize) -> i64 {
    // `unwrap_or` is total -- it is the infallible combinator, not the
    // panicking accessor the prohibitions rule out.
    i64::try_from(len).unwrap_or(i64::MAX)
}

/// `file2string` -- `src/tool_paramhlp.c:86-118`.
///
/// Reads the whole source and removes **every** run of CR, LF or NUL,
/// concatenating what is left with nothing in between: `"a\r\n\r\nb"` becomes
/// `"ab"` and `"\n\n"` becomes the empty string. The inner loop at `:101-113`
/// alternates the two modes of [`memcrlf`] to do it.
///
/// An absent source yields an empty result and success, because the whole body
/// of the C function sits inside `if(file)` at `:90`.
///
/// The result is bytes rather than a string: the C function returns a
/// `char *` that callers hand to libcurl unchanged, and the sources it reads --
/// `--data`, `--header` and friends from a file -- are not required to be
/// UTF-8. Re-encoding them would change bytes that AAP section 0.8.1 freezes.
pub(crate) fn file2string(
    file: Option<&mut dyn Read>,
) -> Result<Vec<u8>, ParameterError> {
    let mut out: Vec<u8> = Vec::new();

    // `:90`
    if let Some(reader) = file {
        let mut buffer = [0u8; READ_CHUNK];
        loop {
            // `:94-99` -- read, and on error discard everything.
            let nread = match fread(reader, &mut buffer) {
                Ok(count) => count,
                Err(_) => return Err(ParameterError::ReadError),
            };
            let mut rest: &[u8] = match buffer.get(..nread) {
                Some(slice) => slice,
                // Unreachable: `fread` never reports more than it was given.
                None => &[],
            };

            // `:101-113`
            while !rest.is_empty() {
                // `:102-104` -- the piece up to the next terminator.
                let keep = memcrlf(rest, false);
                let head = match rest.get(..keep) {
                    Some(slice) => slice,
                    // Unreachable: `memcrlf` never exceeds the slice length.
                    None => rest,
                };
                dyn_addn(&mut out, head, MAX_FILE2STRING)?;
                rest = match rest.get(keep..) {
                    Some(slice) => slice,
                    None => &[],
                };

                // `:107-112` -- then the run of terminators, dropped.
                if !rest.is_empty() {
                    let skip = memcrlf(rest, true);
                    rest = match rest.get(skip..) {
                        Some(slice) => slice,
                        None => &[],
                    };
                }
            }

            // `:114` -- `while(!feof(file))`. Because `fread` returns short
            // only at end of input, a short read is exactly end of file.
            if nread < READ_CHUNK {
                break;
            }
        }
    }

    // `:116-117`
    Ok(out)
}

/// `file2memory_range` -- `src/tool_paramhlp.c:120-191`.
///
/// Reads the byte range `starto..=endo` -- **`endo` is inclusive**, which is
/// what the `+ 1` in the clamp at `:172` encodes, so `starto == endo == 0`
/// yields exactly one byte. Unlike [`file2string`] nothing is stripped.
///
/// A seekable source is positioned with `curlx_fseek` (`:131`); a source that
/// cannot seek has `starto` bytes read and discarded instead (`:135-137`).
/// An absent source yields an empty result and success (`:186-189`).
///
/// This is the entry point `curl-rs/src/cli/vars.rs` needs for
/// `--variable @file[N-M]`; `src/var.c:455` is the C call site.
///
/// An inverted range is `PARAM_NO_MEM`, which deserves its reasoning written
/// down because C reaches it by accident. `:171-172` computes
/// `n_add = (size_t)(endo - offset + 1)`, and when `offset > endo` that cast
/// turns a negative value into one far above the cap, so `curlx_dyn_addn`
/// rejects it with `CURLE_TOO_LARGE` and `:175` reports `PARAM_NO_MEM`. That
/// outcome is deterministic: an append happens only when `endo - offset + 1`
/// is at least 1, and `:178-179` leaves the loop as soon as `offset` passes
/// `endo`, so `offset <= endo` holds at every later pass and the negative
/// clamp can only be reached before anything has been appended. With bytes
/// already buffered the C addition would wrap and copy about 2^64 bytes, which
/// is undefined behaviour rather than behaviour to reproduce -- and it is
/// unreachable.
pub(crate) fn file2memory_range(
    file: Option<&mut dyn ByteSource>,
    starto: i64,
    endo: i64,
) -> Result<Vec<u8>, ParameterError> {
    // `:123`, with `:186-189` as the else arm.
    let reader = match file {
        Some(source) => source,
        None => return Ok(Vec::new()),
    };

    let mut out: Vec<u8> = Vec::new();
    let mut offset: i64 = 0;
    let mut throwaway: i64 = 0;

    // `:129-138`
    if starto != 0 {
        // A negative start is not reachable from the one caller -- `src/var.c`
        // parses an unsigned range -- and C has no defined behaviour for it:
        // `curlx_fseek` rejects a negative `SEEK_SET` offset, while the stdin
        // arm would index `&buffer[throwaway]` with a negative subscript. The
        // defined half of that pair is reported.
        let start = match u64::try_from(starto) {
            Ok(value) => value,
            Err(_) => return Err(ParameterError::ReadError),
        };
        match reader.seek_start(start) {
            // `:131-133`
            Some(Ok(())) => offset = starto,
            Some(Err(_)) => return Err(ParameterError::ReadError),
            // `:135-137`
            None => throwaway = starto,
        }
    }

    let mut buffer = [0u8; READ_CHUNK];
    loop {
        // `:146-152` -- read, and on error discard everything.
        let nread = match reader.read_block(&mut buffer) {
            Ok(count) => count,
            Err(_) => return Err(ParameterError::ReadError),
        };
        let chunk: &[u8] = match buffer.get(..nread) {
            Some(slice) => slice,
            // Unreachable: `read_block` never reports more than it was given.
            None => &[],
        };

        // `:153-154`
        let mut n_add = as_off(nread);
        let mut ptr_add: &[u8] = chunk;

        // `:155`
        if nread != 0 {
            // `:156-169` -- drain the leading bytes the caller asked to skip.
            if throwaway != 0 {
                if throwaway >= as_off(nread) {
                    // `:157-161` -- the whole chunk is skipped.
                    throwaway = throwaway.saturating_sub(as_off(nread));
                    offset = offset.saturating_add(as_off(nread));
                    n_add = 0;
                } else {
                    // `:162-168` -- keep only the trailing piece.
                    n_add = as_off(nread).saturating_sub(throwaway);
                    let skip = match usize::try_from(throwaway) {
                        Ok(value) => value,
                        // Unreachable: `throwaway < nread <= READ_CHUNK`.
                        Err(_) => chunk.len(),
                    };
                    ptr_add = match chunk.get(skip..) {
                        Some(slice) => slice,
                        None => &[],
                    };
                    offset = offset.saturating_add(throwaway);
                    throwaway = 0;
                }
            }

            // `:170-180`
            if n_add != 0 {
                // `:171-172` -- clamp to the inclusive end of the range.
                if n_add.saturating_add(offset) > endo {
                    let want = endo.saturating_sub(offset).saturating_add(1);
                    if want <= 0 {
                        // The inverted-range case argued in this function's
                        // documentation. Nothing has been appended yet, so C
                        // reports CURLE_TOO_LARGE here, which `:175` turns
                        // into PARAM_NO_MEM.
                        return Err(ParameterError::NoMem);
                    }
                    n_add = want;
                }

                // The clamp only ever lowers `n_add`, so it cannot exceed the
                // piece; the conversion and the bound below keep that provable
                // rather than assumed.
                let take = match usize::try_from(n_add) {
                    Ok(value) => value,
                    // Unreachable: `n_add <= nread <= READ_CHUNK`.
                    Err(_) => ptr_add.len(),
                };
                let piece = match ptr_add.get(..take) {
                    Some(slice) => slice,
                    // Unreachable for the same reason.
                    None => ptr_add,
                };

                // `:174-175`
                dyn_addn(&mut out, piece, MAX_FILE2MEMORY)?;

                // `:177-179`
                offset = offset.saturating_add(n_add);
                if offset > endo {
                    break;
                }
            }
        }

        // `:182` -- `while(!feof(file))`, as in `file2string`.
        if nread < READ_CHUNK {
            break;
        }
    }

    // `:183-184`. The C function also reports the length through `*size`;
    // a `Vec` carries its own, so that out-parameter disappears.
    Ok(out)
}

/// `file2memory` -- `src/tool_paramhlp.c:193-196`.
///
/// Exactly `file2memory_range(bufp, size, file, 0, CURL_OFF_T_MAX)`: the whole
/// source, with no range restriction and no seek.
pub(crate) fn file2memory(
    file: Option<&mut dyn ByteSource>,
) -> Result<Vec<u8>, ParameterError> {
    file2memory_range(file, 0, CURL_OFF_T_MAX)
}

// ===========================================================================
// Protocol sets
// ===========================================================================

/// `enum e_action` -- `src/tool_paramhlp.c:420`.
///
/// The modifier a `--proto` token carries: `+` or nothing allows, `-` denies,
/// `=` replaces the whole set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    /// `allow` -- add to the set.
    Allow,

    /// `deny` -- remove from the set.
    Deny,

    /// `set` -- empty the set, then add.
    Set,
}

/// `protoset_index` -- `src/tool_paramhlp.c:339-349`.
///
/// The position of `proto` in the set, or the set's cardinality when it is
/// absent -- which is how C signals "not found", because the slot at that index
/// holds the NULL terminator.
///
/// C compares interned addresses; this compares content. Translation
/// difference 6 in the module documentation records why the two are identical
/// and keeps the C `DEBUGASSERT` at `:343` as a debug assertion.
///
/// The C entry point could also be called with NULL to obtain the cardinality
/// (`:337-338`). That use disappears: a slice carries its own length.
fn protoset_index(
    info: &LibInfo,
    protoset: &[&'static str],
    proto: &str,
) -> usize {
    // `:343` -- "Ensure it is tokenized."
    debug_assert!(
        info.proto_token(Some(proto)) == Some(proto),
        "protocol tokens must come from proto_token()"
    );

    // `:345-348`
    for (index, entry) in protoset.iter().enumerate() {
        if *entry == proto {
            return index;
        }
    }
    protoset.len()
}

/// `protoset_set` -- `src/tool_paramhlp.c:352-363`.
///
/// Adds the token unless it is already present. The C `DEBUGASSERT(n <
/// proto_count)` at `:358` is kept: the set can never hold more entries than
/// the engine advertises.
///
/// C's guard is `if(!protoset[n])`, meaning the index returned was the
/// terminator's, i.e. not found. An index equal to the length says the same
/// thing here.
fn protoset_set(
    info: &LibInfo,
    protoset: &mut Vec<&'static str>,
    proto: &'static str,
) {
    let index = protoset_index(info, protoset, proto);

    // `:357`
    if protoset.get(index).is_none() {
        // `:358`
        debug_assert!(index < info.proto_count());
        // `:359-360` -- append and re-terminate; a `Vec` needs no terminator.
        protoset.push(proto);
    }
}

/// `protoset_clear` -- `src/tool_paramhlp.c:366-378`.
///
/// Removes the token by moving the last entry into its place -- `:372-375` --
/// which destroys the ordering. That is exactly why `proto2num` sorts before
/// emitting, and it is reproduced rather than replaced by an order-preserving
/// removal so that no intermediate ordering difference can hide a sorting
/// mistake.
fn protoset_clear(
    info: &LibInfo,
    protoset: &mut Vec<&'static str>,
    proto: &'static str,
) {
    let index = protoset_index(info, protoset, proto);

    // `:371` -- present only if the index is a real slot.
    if protoset.get(index).is_some() {
        // `:372-375`. `swap_remove` is the same operation, and the guard above
        // proves the index is in bounds.
        let _ = protoset.swap_remove(index);
    }
}

/// `proto2num` -- `src/tool_paramhlp.c:395-511`.
///
/// Builds the comma-separated protocol string that `--proto` and
/// `--proto-redir` hand to libcurl. `preset` is C's `val`: either
/// `built_in_protos` for `--proto` (`src/tool_getparam.c:2538`) or the literal
/// array `redir_protos[] = { "http", "https", "ftp", "ftps", NULL }` for
/// `--proto-redir` (`:2349-2355`, used at `:2542`). Because the second is
/// literals rather than interned tokens, `:411` re-interns every entry through
/// `proto_token()` and silently drops anything the engine does not advertise.
///
/// The grammar, from `:417-493`:
///
/// - Tokens are separated by commas and an empty token is skipped rather than
///   rejected (`:423-426`), so `"http,,https"` is accepted.
/// - A leading `=`, `-` or `+` selects the [`Action`]; anything else means
///   allow, and `:445-446` puts the byte back and lengthens the token to
///   compensate for the `- 1` the length was computed with at `:427` and
///   `:430`.
/// - The token `all`, matched without regard to case, means every built-in
///   protocol: denied it empties the set, allowed or set it replaces the set
///   wholesale (`:450-460`).
/// - An unrecognised token warns, and if the modifier was `=` it first empties
///   the set, because -- in the words of the C comment at `:482-483` -- "If
///   they have specified only this protocol, we say treat it as if no
///   protocols are allowed".
///
/// Two details that look incidental and are not. The C code renders each token
/// through a `char buffer[32]` at `:463-465`, so a token longer than 31 bytes
/// is **truncated before lookup**; and `:495-497` sorts the result with
/// `struplocompare4sort` under the comment "We need the protocols in alphabetic
/// order for CI tests requirements." Both are reproduced: the sort uses
/// `curl-rs/src/util.rs`'s comparator, never a plain `sort`, because a
/// case-sensitive ordering would emit a different string.
///
/// An empty result is `PARAM_BAD_USE` (`:504-507`), which is what `"-all"` with
/// nothing added produces.
pub(crate) fn proto2num(
    info: &LibInfo,
    preset: &[&str],
    text: &str,
    sink: &mut dyn Write,
    msgcfg: &MsgConfig,
) -> Result<String, ParameterError> {
    // `:402-404` -- the assertion and the "in case of surprises" guard.
    debug_assert!(info.proto_count() <= MAX_PROTOS);
    if info.proto_count() > MAX_PROTOS {
        return Err(ParameterError::NoMem);
    }

    // `:400`, `:409` -- a fixed `const char *protoset[MAX_PROTOS + 1]` starting
    // empty. The capacity is reserved for the same bound; the NUL terminator
    // has no counterpart.
    let mut protoset: Vec<&'static str> = Vec::with_capacity(MAX_PROTOS);

    // `:410-415` -- preset the set, interning each entry and skipping unknowns.
    for entry in preset {
        if let Some(token) = info.proto_token(Some(entry)) {
            protoset_set(info, &mut protoset, token);
        }
    }

    // `:417` -- `while(*str)`
    let mut rest = text;
    while !rest.is_empty() {
        // `:418`
        let next = rest.find(',');

        // `:422-430`. The `- 1` pre-compensates for the modifier byte the
        // switch below consumes.
        let plen = match next {
            Some(0) => {
                // `:423-426` -- an empty token is skipped, not an error. The
                // default of `&str` is `""`, and the index cannot be out of
                // range because the loop condition proved `rest` non-empty.
                rest = rest.get(1..).unwrap_or_default();
                continue;
            }
            Some(position) => position.saturating_sub(1),
            None => rest.len().saturating_sub(1),
        };

        // `:433-448` -- the modifier.
        let first = match rest.as_bytes().first() {
            Some(byte) => *byte,
            // Unreachable: the loop condition proved `rest` is not empty.
            None => 0,
        };
        let (action, body, plen) = match first {
            b'=' => (Action::Set, rest.get(1..), plen),
            b'-' => (Action::Deny, rest.get(1..), plen),
            b'+' => (Action::Allow, rest.get(1..), plen),
            // `:443-447` -- no modifier: put the byte back and restore the
            // length.
            _ => (Action::Allow, Some(rest), plen.saturating_add(1)),
        };
        // Unreachable fallback: index 1 follows a one-byte ASCII modifier.
        let body: &str = body.unwrap_or_default();

        // `:450` -- `(plen == 3) && curl_strnequal(str, "all", 3)`, an
        // ASCII-only case-insensitive comparison of exactly three bytes.
        let is_all = plen == 3
            && match body.as_bytes().get(..3) {
                Some(head) => head.eq_ignore_ascii_case(b"all"),
                None => false,
            };

        if is_all {
            match action {
                // `:452-454`
                Action::Deny => protoset.clear(),
                // `:455-459` -- replace the set with every built-in protocol.
                // C copies `proto_count + 1` entries, the extra one being its
                // NUL terminator.
                Action::Allow | Action::Set => {
                    protoset.clear();
                    protoset.extend_from_slice(info.built_in_protos());
                }
            }
        } else {
            // `:463-465` -- `char buffer[32]` truncates the token before
            // lookup. Sliced as bytes, so a token that is not ASCII is cut
            // exactly where C cuts it instead of at a character boundary.
            let take = if plen < PROTO_TOKEN_MAX {
                plen
            } else {
                PROTO_TOKEN_MAX
            };
            let token: &[u8] = match body.as_bytes().get(..take) {
                Some(slice) => slice,
                // Unreachable: `take <= plen <= body.len()`.
                None => body.as_bytes(),
            };

            // `:467` -- `proto_token(buffer)`. A token that is not valid UTF-8
            // cannot equal any scheme name, which is the same answer C's
            // case-insensitive comparison gives for the same bytes.
            let found = match std::str::from_utf8(token) {
                Ok(name) => info.proto_token(Some(name)),
                Err(_) => None,
            };

            match found {
                Some(name) => match action {
                    // `:471-473`
                    Action::Deny => {
                        protoset_clear(info, &mut protoset, name);
                    }
                    // `:474-476` -- empty the set, then FALLTHROUGH to allow.
                    Action::Set => {
                        protoset.clear();
                        protoset_set(info, &mut protoset, name);
                    }
                    // `:477-479`
                    Action::Allow => {
                        protoset_set(info, &mut protoset, name);
                    }
                },
                None => {
                    // `:481-487` -- unknown protocol.
                    if action == Action::Set {
                        protoset.clear();
                    }
                    // `:486`. Emitted through `warnf_bytes` so the token
                    // reaches the terminal as the bytes C would have printed,
                    // even when the 31-byte truncation split a multi-byte
                    // sequence.
                    let mut message =
                        Vec::with_capacity(token.len().saturating_add(24));
                    message.extend_from_slice(b"unrecognized protocol '");
                    message.extend_from_slice(token);
                    message.push(b'\'');
                    warnf_bytes(sink, msgcfg, &message);
                }
            }
        }

        // `:489-492`. `next` is an index into the string as it stood before
        // the modifier was consumed, exactly as C's `next` is a pointer that
        // `str++` does not move.
        match next {
            Some(position) => {
                rest =
                    rest.get(position.saturating_add(1)..).unwrap_or_default();
            }
            None => break,
        }
    }

    // `:495-497` -- "We need the protocols in alphabetic order for CI tests
    // requirements." `struplocompare4sort` is ASCII-only case-insensitive; a
    // plain `sort` would be case-sensitive and would emit a different string.
    // C uses `qsort`, which is unstable, but the set holds no duplicates so a
    // stable sort yields the identical order.
    protoset.sort_by(struplocompare4sort);

    // `:499-501` -- comma-joined with no spaces, under the MAX_PROTOSTRING cap.
    let mut obuf = String::new();
    for entry in &protoset {
        let separator = if obuf.is_empty() { "" } else { "," };
        // One `curlx_dyn_addf` of the rendered "%s%s", so one cap test over
        // both pieces (`lib/curlx/dynbuf.c:82-84`).
        let fit = obuf
            .len()
            .saturating_add(separator.len())
            .saturating_add(entry.len())
            .saturating_add(1);
        if fit > MAX_PROTOSTRING {
            // `:502-503`
            return Err(ParameterError::NoMem);
        }
        obuf.push_str(separator);
        obuf.push_str(entry);
    }

    // `:504-507`
    if obuf.is_empty() {
        return Err(ParameterError::BadUse);
    }

    // `:508-510`. C frees the previous string and stores the new one; the
    // caller assigns the returned value instead.
    Ok(obuf)
}

/// `check_protocol` -- `src/tool_paramhlp.c:521-529`.
///
/// Reports whether the engine advertises the named scheme. The C
/// documentation at `:513-519` lists all three outcomes.
///
/// `"ipfs"` is correctly unsupported: `src/tool_libinfo.c:47-50` declares
/// `proto_ipfs` and `proto_ipns` as hard-coded literals that are never part of
/// `built_in_protos`, so `proto_token()` cannot return them.
pub(crate) fn check_protocol(
    info: &LibInfo,
    text: Option<&str>,
) -> Result<(), ParameterError> {
    // `:523-524`
    let text = match text {
        Some(value) => value,
        None => return Err(ParameterError::RequiresParameter),
    };

    // `:526-528`
    if info.proto_token(Some(text)).is_some() {
        Ok(())
    } else {
        Err(ParameterError::LibcurlUnsupportedProtocol)
    }
}

// ===========================================================================
// Keyword tables: src/tool_paramhlp.c:612-650
//
// All three share one shape. They match with `curl_strequal`, which
// `lib/strequal.c:76` implements as an ASCII-only case-insensitive compare, so
// the Rust equivalent is `eq_ignore_ascii_case` -- never the Unicode-aware
// fold, which would accept spellings curl rejects. All three
// fall back to a default and emit a frozen warning; **none of them can fail**,
// which is why they return a value rather than a `Result`.
// ===========================================================================

/// `ftpfilemethod` -- `src/tool_paramhlp.c:612-624`.
///
/// Accepts `singlecwd`, `nocwd` and `multicwd` in any ASCII case. Anything
/// else warns and yields `CURLFTPMETHOD_MULTICWD`, matching `:622`.
///
/// The `--ftp-method` call site is `src/tool_getparam.c:2495`.
pub(crate) fn ftpfilemethod(
    text: &str,
    sink: &mut dyn Write,
    msgcfg: &MsgConfig,
) -> i64 {
    // `:614-619` -- the C order is singlecwd, nocwd, multicwd. Order is not
    // observable here because the three keywords are distinct, but it is kept
    // so the translation reads against the original line by line.
    if text.eq_ignore_ascii_case("singlecwd") {
        return CURLFTPMETHOD_SINGLECWD;
    }
    if text.eq_ignore_ascii_case("nocwd") {
        return CURLFTPMETHOD_NOCWD;
    }
    if text.eq_ignore_ascii_case("multicwd") {
        return CURLFTPMETHOD_MULTICWD;
    }

    // `:620-621` -- frozen text.
    warnf(
        sink,
        msgcfg,
        format_args!("unrecognized ftp file method '{text}', using default"),
    );
    CURLFTPMETHOD_MULTICWD
}

/// `ftpcccmethod` -- `src/tool_paramhlp.c:626-636`.
///
/// Accepts `passive` and `active` in any ASCII case. Anything else warns and
/// yields `CURLFTPSSL_CCC_PASSIVE`, matching `:634`.
///
/// The `--ftp-ssl-ccc-mode` call site is `src/tool_getparam.c:2799`.
pub(crate) fn ftpcccmethod(
    text: &str,
    sink: &mut dyn Write,
    msgcfg: &MsgConfig,
) -> i64 {
    // `:628-631`
    if text.eq_ignore_ascii_case("passive") {
        return CURLFTPSSL_CCC_PASSIVE;
    }
    if text.eq_ignore_ascii_case("active") {
        return CURLFTPSSL_CCC_ACTIVE;
    }

    // `:632-633` -- frozen text. Note the capitalised `CCC`, which differs
    // from the wording of the other two warnings.
    warnf(
        sink,
        msgcfg,
        format_args!("unrecognized ftp CCC method '{text}', using default"),
    );
    CURLFTPSSL_CCC_PASSIVE
}

/// `delegation` -- `src/tool_paramhlp.c:638-650`.
///
/// Accepts `none`, `policy` and `always` in any ASCII case. Anything else
/// warns and yields `CURLGSSAPI_DELEGATION_NONE`, matching `:648`.
///
/// The `--delegation` call site is `src/tool_getparam.c:2549`.
pub(crate) fn delegation(
    text: &str,
    sink: &mut dyn Write,
    msgcfg: &MsgConfig,
) -> i64 {
    // `:640-645`
    if text.eq_ignore_ascii_case("none") {
        return CURLGSSAPI_DELEGATION_NONE;
    }
    if text.eq_ignore_ascii_case("policy") {
        return CURLGSSAPI_DELEGATION_POLICY_FLAG;
    }
    if text.eq_ignore_ascii_case("always") {
        return CURLGSSAPI_DELEGATION_FLAG;
    }

    // `:646-647` -- frozen text. This one ends `using none`, not
    // `using default`.
    warnf(
        sink,
        msgcfg,
        format_args!("unrecognized delegation method '{text}', using none"),
    );
    CURLGSSAPI_DELEGATION_NONE
}

// ===========================================================================
// String lists: src/tool_paramhlp.c:601-610, :652-671
// ===========================================================================

/// `add2list` -- `src/tool_paramhlp.c:601-610`.
///
/// The C body is `curl_slist_append`, which returns `NULL` only when
/// allocation fails; the caller maps that to `PARAM_NO_MEM` at `:607`.
///
/// AAP section 0.6.9 replaces the intrusive `curl_slist` with an owned
/// collection internally -- "`curl_slist` retains its C shape only at the ABI
/// boundary" -- so `Vec::push` cannot report failure and the error arm is
/// unreachable. The fallible signature is kept regardless, because thirteen C
/// call sites across `src/tool_getparam.c` and `src/tool_operate.c` propagate
/// the `ParameterError` and changing the shape would ripple into every one of
/// them.
pub(crate) fn add2list(
    list: &mut Vec<String>,
    ptr: &str,
) -> Result<(), ParameterError> {
    list.push(ptr.to_owned());
    Ok(())
}

/// `isheadersep` -- `src/tool_paramhlp.c:652`.
///
/// The byte that must follow a header name for `inlist` to call it a match.
/// `';'` counts because `-H` accepts `Name;` as the "send an empty header"
/// form.
const fn is_header_sep(byte: u8) -> bool {
    byte == b':' || byte == b';'
}

/// `inlist` -- `src/tool_paramhlp.c:658-671`.
///
/// True when some entry of `head` begins with `checkfor`, compared
/// case-insensitively over exactly `checkfor.len()` bytes, **and** the byte
/// immediately after that prefix is a header separator.
///
/// Both boundary cases follow `curl_strnequal`'s definition at
/// `lib/strequal.c:53-64` rather than being invented here:
///
/// * An entry shorter than `checkfor` does not match, because `ncasecompare`
///   stops at the entry's NUL and then compares that NUL against a non-NUL
///   byte of `checkfor`.
/// * An entry exactly as long as `checkfor` does not match either, because the
///   byte after the prefix is the NUL, and NUL is not a header separator.
///
/// The two `DEBUGASSERT`s at `:661-662` are preserved as `debug_assert!`:
/// `checkfor` must be non-empty and must not already carry the `':'`.
fn inlist(head: &[String], checkfor: &str) -> bool {
    let needle = checkfor.as_bytes();
    // `:661-662`
    debug_assert!(!needle.is_empty());
    debug_assert!(needle.last() != Some(&b':'));

    for entry in head {
        let bytes = entry.as_bytes();
        // `:665` -- curl_strnequal over strlen(checkfor) bytes.
        let prefix_matches = match bytes.get(..needle.len()) {
            Some(prefix) => prefix.eq_ignore_ascii_case(needle),
            None => false,
        };
        // `:666` -- and the following byte must separate name from value. An
        // absent byte stands for the C string's NUL, which is not a
        // separator.
        let follower = match bytes.get(needle.len()) {
            Some(byte) => *byte,
            None => 0,
        };
        if prefix_matches && is_header_sep(follower) {
            return true;
        }
    }
    false
}

// ===========================================================================
// Credentials: src/tool_paramhlp.c:547-599, :673-706
// ===========================================================================

/// The password prompt, injected so the frozen text can be asserted.
///
/// [`get_args`] supplies [`crate::terminal::getpass_r`]; the tests supply a
/// recorder. The two arguments are the prompt and the maximum password length,
/// matching `getpass_r`'s own contract at `src/tool_getpass.h:35`.
type PromptFn<'a> = &'a mut dyn FnMut(&str, usize) -> Vec<u8>;

/// `checkpasswd` -- `src/tool_paramhlp.c:548-599`.
///
/// Prompts for the password half of a `user:password` pair when, and only
/// when, the user did not supply one, then rewrites `userpwd` as
/// `user:password`.
///
/// # The two frozen prompts
///
/// `:580-587` builds one of exactly two strings, and both are frozen ABI-level
/// output under AAP section 0.8.1 -- no trailing space, no trailing newline,
/// the colon inside the literal:
///
/// * `Enter {kind} password for user '{user}':` when `i == 0` **and** `last`
/// * `Enter {kind} password for user '{user}' on URL #{i + 1}:` otherwise
///
/// The index is **one-based**: `:583` passes `i + 1` to `%zu`. `kind` is the
/// literal `"host"` or `"proxy"` chosen by [`get_args`].
///
/// # When no prompt happens
///
/// `:565` prompts only when there is no `':'` anywhere in the value and the
/// value does not begin with `';'`. A value that already carries a password is
/// therefore left byte-for-byte alone, and so is one that opens with login
/// options.
///
/// # Hiding the login options without mutating the caller's string
///
/// Translation difference 7 in the module documentation: C truncates in place
/// at `:578` (`*osep = '\0'`) so the prompt shows only the user name, then
/// restores the `';'` at `:588` **before** composing the result at `:590`. The
/// login options are consequently absent from the prompt but present in the
/// credential. This translation slices for the prompt and composes from the
/// untouched original, which is the same observable behaviour with no
/// mutation, no interior mutability and no escape from the safety rules.
///
/// # Caps
///
/// The password buffer is [`PASSWORD_BUFFER_SIZE`] (`char passwd[2048]` at
/// `:570`) and the composed result is capped at [`MAX_USERPWDLENGTH`] by the
/// dynbuf initialised at `:574`. Exceeding the latter returns
/// `CURLE_OUT_OF_MEMORY`, because `:590-591` maps any `curlx_dyn_addf` failure
/// to it -- the same `CURLE_TOO_LARGE` collapse recorded as translation
/// difference 2.
fn checkpasswd(
    kind: &str,
    i: usize,
    last: bool,
    userpwd: &mut Option<Vec<u8>>,
    prompt: PromptFn<'_>,
) -> CURLcode {
    // `:556-557` -- nothing to do when the option was never given.
    let current: &[u8] = match userpwd.as_deref() {
        Some(value) => value,
        None => return CURLcode::Ok,
    };

    // `:560` and `:563`
    let psep = current.iter().position(|byte| *byte == b':');
    let osep = current.iter().position(|byte| *byte == b';');

    // `:565` -- "no password present, prompt for one", but only when the value
    // does not start with the login-options separator.
    if psep.is_some() || current.first() == Some(&b';') {
        return CURLcode::Ok;
    }

    // `:578` -- the prompt shows the user name alone. Slicing replaces the
    // in-place NUL; see the note above.
    let shown_bytes = match osep {
        Some(index) => match current.get(..index) {
            Some(head) => head,
            None => current,
        },
        None => current,
    };
    // GAP #5: `getpass_r` takes `&str`, so a user name that is not UTF-8 is
    // rendered lossily *in the prompt only*. The credential composed below is
    // built from the original bytes and is never re-encoded.
    let shown = String::from_utf8_lossy(shown_bytes);

    // `:580-587` -- the two frozen prompts. `i + 1` is the one-based URL
    // number that `%zu` receives at `:583`.
    let urlnum = i.saturating_add(1);
    let prompt_text = if i == 0 && last {
        format!("Enter {kind} password for user '{shown}':")
    } else {
        format!("Enter {kind} password for user '{shown}' on URL #{urlnum}:")
    };

    // `:589` -- getpass_r(prompt, passwd, sizeof(passwd)).
    let passwd = prompt(&prompt_text, PASSWORD_BUFFER_SIZE);

    // `:590` -- curlx_dyn_addf(&dyn, "%s:%s", *userpwd, passwd), where
    // `*userpwd` has had its `';'` restored at `:588`, so the login options are
    // part of the credential.
    let mut formatted =
        Vec::with_capacity(current.len().saturating_add(1) + passwd.len());
    formatted.extend_from_slice(current);
    formatted.push(b':');
    formatted.extend_from_slice(&passwd);

    // One `dyn_nappend` of the whole formatted string into an empty buffer,
    // exactly as `curlx_dyn_addf` performs it; the cap is MAX_USERPWDLENGTH.
    let mut composed = Vec::new();
    if dyn_addn(&mut composed, &formatted, MAX_USERPWDLENGTH).is_err() {
        // `:591`
        return CURLcode::OutOfMemory;
    }

    // `:593-594` -- free the old value and adopt the new one.
    *userpwd = Some(composed);
    CURLcode::Ok
}

/// The fields of `struct OperationConfig` that [`get_args`] reads.
///
/// `OperationConfig` lives in `curl-rs/src/config/mod.rs` and is not among
/// this file's dependencies, so the borrow is explicit rather than reached for.
/// The C field names are kept so the mapping needs no lookup:
/// `src/tool_cfgable.h:274` (`jsoned`), `:149` (`headers`), `:85` (`userpwd`),
/// `:93` (`proxyuserpwd`), `:164` (`oauth_bearer`) and `:172` (`next`).
///
/// This type deliberately derives **no** `Debug`: obligation O5 forbids any
/// route by which a password could be logged, traced or printed, and
/// `userpwd`/`proxyuserpwd` hold exactly that once [`checkpasswd`] has run.
pub(crate) struct OperationArgs<'a> {
    /// `config->jsoned` -- set by `--json`.
    pub(crate) jsoned: bool,
    /// `config->headers` -- the `-H` list, which `--json` must not duplicate.
    pub(crate) headers: &'a mut Vec<String>,
    /// `config->userpwd` -- `-u`, as bytes so the credential stays exact.
    pub(crate) userpwd: &'a mut Option<Vec<u8>>,
    /// `config->proxyuserpwd` -- `-U`.
    pub(crate) proxyuserpwd: &'a mut Option<Vec<u8>>,
    /// `config->oauth_bearer` -- when set, the host password is not prompted
    /// for.
    pub(crate) oauth_bearer: Option<&'a str>,
    /// `config->next == NULL` at `src/tool_paramhlp.c:676`: true for the final
    /// operation in the chain. The caller computes it because the chain lives
    /// in `config/mod.rs`.
    pub(crate) last: bool,
}

/// `get_args` -- `src/tool_paramhlp.c:673-706`.
///
/// Applies the two implications of `--json` and then prompts for any missing
/// passwords. Returns a `CURLcode`, not a `ParameterError`, because the sole C
/// call site in `src/tool_operate.c` propagates a `CURLcode`.
///
/// # The two frozen `--json` headers
///
/// `:679-687`, whose C comment reads "--json also implies json Content-Type:
/// and Accept: headers - if they are not set with -H". Both literals are
/// frozen, and `Content-Type` is added first:
///
/// * `Content-Type: application/json`
/// * `Accept: application/json`
///
/// Each is added only when [`inlist`] does not already find that header among
/// the `-H` values, so an explicit `-H 'Content-Type: text/plain'` wins.
///
/// # Password prompts
///
/// `:691-696`: the host password is skipped entirely when `oauth_bearer` is
/// set, and the proxy password is attempted only if the host attempt
/// succeeded.
pub(crate) fn get_args(args: OperationArgs<'_>, i: usize) -> CURLcode {
    let mut prompt: fn(&str, usize) -> Vec<u8> = getpass_r;
    get_args_with(args, i, &mut prompt)
}

/// [`get_args`] with the password prompt injected.
///
/// Exists so the two frozen prompt strings can be asserted without a terminal;
/// `get_args` is the only production entry point.
fn get_args_with(
    args: OperationArgs<'_>,
    i: usize,
    prompt: PromptFn<'_>,
) -> CURLcode {
    let OperationArgs {
        jsoned,
        headers,
        userpwd,
        proxyuserpwd,
        oauth_bearer,
        last,
    } = args;

    // `:678-688`
    if jsoned {
        let mut err = Ok(());
        if !inlist(headers, "Content-Type") {
            err = add2list(headers, "Content-Type: application/json");
        }
        if err.is_ok() && !inlist(headers, "Accept") {
            err = add2list(headers, "Accept: application/json");
        }
        if err.is_err() {
            // `:686`
            return CURLcode::OutOfMemory;
        }
    }

    // `:691-692` -- a bearer token replaces the password entirely.
    let mut result = CURLcode::Ok;
    if userpwd.is_some() && oauth_bearer.is_none() {
        result = checkpasswd("host", i, last, userpwd, prompt);
    }

    // `:695-696` -- `!result` in C is "still CURLE_OK".
    if result == CURLcode::Ok && proxyuserpwd.is_some() {
        result = checkpasswd("proxy", i, last, proxyuserpwd, prompt);
    }

    result
}

// ===========================================================================
// URL list nodes: src/tool_paramhlp.c:35-55
// ===========================================================================

/// The counter behind `struct getout`'s `num` field.
///
/// Translation difference 1 in the module documentation. `:40` declares
/// `static int outnum = 0;` **inside** `new_getout`, so it is a
/// process-global monotonic counter shared by every config set, not a
/// per-config index. AAP section 0.1.2 replaces the C tree's shared mutable
/// state with "per-module structs and explicit ownership", and a mutable
/// `static` is forbidden outright, so the counter becomes a field owned by
/// whichever
/// aggregate owns the URL list -- `curl-rs/src/config/mod.rs` -- and is
/// threaded in by `&mut`. A `static AtomicU32` would preserve the C shape but
/// reintroduce a global singleton and destroy test isolation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct GetOutSeq {
    /// The value the next node will receive; `outnum` before the `++`.
    next: i32,
}

impl GetOutSeq {
    /// A counter positioned where `:40` starts, at zero.
    pub(crate) const fn new() -> Self {
        Self { next: 0 }
    }
}

/// The two fields `new_getout` sets on a freshly appended node.
///
/// `struct getout` is declared at `src/tool_sdecls.h:85-99` and owned by
/// `curl-rs/src/config/mod.rs`; everything else on it is left at its default,
/// exactly as `:47`'s `calloc` leaves it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NewGetOut {
    /// `node->num` -- `:52`. `curl_off_t` in C even though `outnum` is `int`
    /// (`src/tool_sdecls.h:90`), so the widening is part of the original.
    pub(crate) num: i64,
    /// `node->useremote = config->remote_name_all` -- `:51`.
    pub(crate) useremote: bool,
}

/// `new_getout` -- `src/tool_paramhlp.c:35-55`.
///
/// GAP #4: the URL list itself (`config->url_list` / `config->url_last`,
/// `src/tool_cfgable.h:102-103`) lives in `curl-rs/src/config/mod.rs`, which
/// is not among this file's dependencies. This function therefore computes the
/// node's contents and advances the sequence; the owner performs the push.
/// AAP section 0.6.9 turns the intrusive `next` chain into an owned
/// `Vec<GetOut>`, so appending is the owner's operation in any case. Reported
/// rather than worked around: nothing here reaches into `config/mod.rs`.
///
/// The C function returns `NULL` when `calloc` fails and every caller treats
/// that as out of memory (`:44-45`). `Vec::push` cannot fail that way, so the
/// `NULL` branch disappears and this function is infallible.
pub(crate) fn new_getout(
    seq: &mut GetOutSeq,
    remote_name_all: bool,
) -> NewGetOut {
    // `:52` -- `node->num = outnum++`, i.e. the pre-increment value.
    let num = i64::from(seq.next);
    // `int` overflow is undefined in C and unreachable in practice (it would
    // need more than two billion URLs on one command line); saturating keeps
    // this panic-free without pretending to a behaviour C does not define.
    seq.next = seq.next.saturating_add(1);
    NewGetOut {
        num,
        // `:51`
        useremote: remote_name_all,
    }
}

// ===========================================================================
// Cross-checks
//
// AAP section 0.8.7 relocates the coverage of `tests/unit` into the crates,
// because a Rust static library does not export `pub(crate)` items and the C
// unit tests therefore cannot link whatever the quality of the translation.
// These are that coverage for this module: every acceptance rule, every frozen
// literal and every preserved quirk, asserted against the C original by line.
//
// Two conventions keep the assertions free of the constructs the prohibitions
// forbid, the panicking result accessors and the abort macros among them:
//
// * a successful result is compared through `.ok()`, which needs `Debug` and
//   `PartialEq` only on the *value*;
// * a failing result is matched with `matches!`, which needs no derives at all.
//
// The second convention matters beyond style. `ParameterError` is owned by
// `cli/args.rs`, which is deliberately not one of this file's dependencies, so
// nothing here may assume which traits it derives.
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::libinfo::get_libcurl_info;
    use crate::output::msgs::WARN_PREFIX;
    use curl_rs_lib::error::Error;
    use std::io::Cursor as IoCursor;

    /// A configuration that lets warnings through.
    ///
    /// `warnf` is gated on `!silent` (`src/tool_msgs.h`), so a silent
    /// configuration would make every warning assertion below vacuously true.
    fn loud() -> MsgConfig {
        MsgConfig::new(false, true, false)
    }

    /// The message a warning carried, with `voutf`'s line wrapping undone.
    ///
    /// `src/tool_msgs.c:37-73` re-emits the prefix once per wrapped line and
    /// keeps the blank it cut at, so concatenating the unprefixed segments
    /// restores the message byte for byte. Undoing the wrap here makes the
    /// assertions independent of `$COLUMNS`, which
    /// `crate::terminal::get_terminal_columns` reads and which no test may
    /// assume.
    fn warning_text(raw: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for line in raw.split(|byte| *byte == b'\n') {
            if line.is_empty() {
                continue;
            }
            match line.strip_prefix(WARN_PREFIX.as_bytes()) {
                Some(rest) => out.extend_from_slice(rest),
                None => out.extend_from_slice(line),
            }
        }
        out
    }

    /// A reader that always fails, for the `PARAM_READ_ERROR` paths.
    ///
    /// Stands in for C's `ferror(file)` at `src/tool_paramhlp.c:95` and `:147`.
    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("read failed"))
        }
    }

    /// A seekable source over owned bytes, like a `curlx_fopen`ed file.
    fn seekable(bytes: &[u8]) -> SeekSource<IoCursor<Vec<u8>>> {
        SeekSource::new(IoCursor::new(bytes.to_vec()))
    }

    /// A non-seekable source, like `stdin`.
    fn streaming(bytes: &[u8]) -> StreamSource<IoCursor<Vec<u8>>> {
        StreamSource::new(IoCursor::new(bytes.to_vec()))
    }

    // -- 1. str2num, src/tool_paramhlp.c:206-221 ---------------------------

    #[test]
    fn str2num_accepts_what_curl_accepts() {
        assert_eq!(str2num("0").ok(), Some(0));
        assert_eq!(str2num("42").ok(), Some(42));
        // Leading zeros are digits: `valid_digit` at
        // `lib/curlx/strparse.c:142-143` admits '0' because
        // `curlx_hexasciitable[0]` is 16, not 0.
        assert_eq!(str2num("007").ok(), Some(7));
        // One optional '-', consumed by `curlx_str_single` at `:212`.
        assert_eq!(str2num("-5").ok(), Some(-5));
        // The magnitude bound is LONG_MAX and negation happens after, so the
        // largest positive value is representable.
        assert_eq!(str2num("9223372036854775807").ok(), Some(i64::MAX));
    }

    #[test]
    fn str2num_rejects_what_curl_rejects() {
        // No digits at all -- STRE_NO_NUM.
        assert!(matches!(str2num(""), Err(ParameterError::BadNumeric)));
        // No leading whitespace: `curlx_str_numblanks` exists for that and is
        // deliberately not used here.
        assert!(matches!(str2num(" 1"), Err(ParameterError::BadNumeric)));
        assert!(matches!(str2num("\t1"), Err(ParameterError::BadNumeric)));
        // No '+' sign anywhere in the primitive.
        assert!(matches!(str2num("+1"), Err(ParameterError::BadNumeric)));
        // Trailing garbage, including trailing whitespace, fails the
        // `curlx_str_single(&str, '\0')` test at `:213`.
        assert!(matches!(str2num("1 "), Err(ParameterError::BadNumeric)));
        assert!(matches!(str2num("1x"), Err(ParameterError::BadNumeric)));
        // Exactly one '-' is consumed, so the second is garbage.
        assert!(matches!(str2num("--5"), Err(ParameterError::BadNumeric)));
        // Overflow relative to LONG_MAX maps to BAD_NUMERIC here, not to
        // NUMBER_TOO_LARGE: `:213` collapses every `curlx_str_number` failure.
        assert!(matches!(
            str2num("9223372036854775808"),
            Err(ParameterError::BadNumeric)
        ));
        // LONG_MIN is NOT representable, because the bound is applied to the
        // magnitude before the negation at `:219`.
        assert!(matches!(
            str2num("-9223372036854775808"),
            Err(ParameterError::BadNumeric)
        ));
    }

    // -- 2. str2unum, src/tool_paramhlp.c:252-260 --------------------------

    #[test]
    fn str2unum_rejects_negatives_but_accepts_minus_zero() {
        assert_eq!(str2unum("0").ok(), Some(0));
        assert_eq!(str2unum("12345").ok(), Some(12345));
        assert!(matches!(
            str2unum("-1"),
            Err(ParameterError::NegativeNumeric)
        ));

        // The quirk of `:259`, preserved deliberately: "-0" parses to 0 through
        // `str2num`, and 0 is not `< 0`, so the guard never fires.
        assert_eq!(str2unum("-0").ok(), Some(0));
        assert_eq!(str2unum("-000").ok(), Some(0));

        // A malformed value still reports the numeric error, not the sign one.
        assert!(matches!(str2unum("x"), Err(ParameterError::BadNumeric)));
    }

    // -- 3. str2unummax, src/tool_paramhlp.c:273-281 -----------------------

    #[test]
    fn str2unummax_bound_is_inclusive() {
        assert_eq!(str2unummax("10", 10).ok(), Some(10));
        assert_eq!(str2unummax("9", 10).ok(), Some(9));
        assert!(matches!(
            str2unummax("11", 10),
            Err(ParameterError::NumberTooLarge)
        ));
        // The sign check of `str2unum` runs first.
        assert!(matches!(
            str2unummax("-1", 10),
            Err(ParameterError::NegativeNumeric)
        ));
    }

    // -- 4. oct2nummax, src/tool_paramhlp.c:223-240 ------------------------

    #[test]
    fn oct2nummax_reads_octal_only() {
        // The one call site is `--create-file-mode`, max 0777
        // (`src/tool_getparam.c:2415`).
        assert_eq!(oct2nummax("0644", 0o777).ok(), Some(0o644));
        assert_eq!(oct2nummax("777", 0o777).ok(), Some(0o777));
        assert_eq!(oct2nummax("0", 0o777).ok(), Some(0));
    }

    #[test]
    fn oct2nummax_rejects_non_octal_digits_and_garbage() {
        // Base 8 makes `m` == '7', so '8' is not a digit: the scan stops with
        // 0 consumed-as-value and the trailing test then rejects the '8'.
        assert!(matches!(
            oct2nummax("08", 0o777),
            Err(ParameterError::BadNumeric)
        ));
        assert!(matches!(
            oct2nummax("09", 0o777),
            Err(ParameterError::BadNumeric)
        ));
        assert!(matches!(
            oct2nummax("0644x", 0o777),
            Err(ParameterError::BadNumeric)
        ));
        // Trailing whitespace is garbage.
        assert!(matches!(
            oct2nummax("777 ", 0o777),
            Err(ParameterError::BadNumeric)
        ));
        assert!(matches!(
            oct2nummax("", 0o777),
            Err(ParameterError::BadNumeric)
        ));
        // No sign is accepted at all -- there is no `curlx_str_single(&str,
        // '-')` here, unlike `str2num`.
        assert!(matches!(
            oct2nummax("-1", 0o777),
            Err(ParameterError::BadNumeric)
        ));
    }

    #[test]
    fn oct2nummax_is_the_only_site_that_reports_overflow() {
        // `:234-235` distinguishes STRE_OVERFLOW from every other failure.
        // 0o1000 exceeds 0o777.
        assert!(matches!(
            oct2nummax("1000", 0o777),
            Err(ParameterError::NumberTooLarge)
        ));
        // The `max < base` arm of `str_num_base` (`lib/curlx/strparse.c:166`)
        // is reachable only with a bound below 8; it reports the same overflow.
        assert!(matches!(
            oct2nummax("7", 3),
            Err(ParameterError::NumberTooLarge)
        ));
    }

    // -- 5. secs2ms, src/tool_paramhlp.c:297-331 ---------------------------

    #[test]
    fn secs2ms_scales_whole_seconds() {
        assert_eq!(secs2ms(Some("0")).ok(), Some(0));
        assert_eq!(secs2ms(Some("1")).ok(), Some(1000));
        assert_eq!(secs2ms(Some("30")).ok(), Some(30_000));
    }

    #[test]
    fn secs2ms_fraction_depends_on_digits_consumed() {
        // `len` counts the digits actually scanned, so trailing zeros change
        // the divisor and not the result: `:321-326`.
        assert_eq!(secs2ms(Some("1.5")).ok(), Some(1500));
        assert_eq!(secs2ms(Some("1.50")).ok(), Some(1500));
        assert_eq!(secs2ms(Some("1.500")).ok(), Some(1500));
        assert_eq!(secs2ms(Some("0.001")).ok(), Some(1));
        // Below a millisecond the integer division truncates to zero.
        assert_eq!(secs2ms(Some("0.0001")).ok(), Some(0));
        // Nine fraction digits is the largest `digs` covers; a tenth forces the
        // divide-down loop at `:322-325`.
        assert_eq!(secs2ms(Some("1.123456789")).ok(), Some(1123));
        assert_eq!(secs2ms(Some("1.1234567891")).ok(), Some(1123));
    }

    #[test]
    fn secs2ms_does_not_check_for_trailing_garbage() {
        // The preserved quirk of `:297-331`: no `curlx_str_single(&str, '\0')`
        // anywhere in the function.
        assert_eq!(secs2ms(Some("1abc")).ok(), Some(1000));
        assert_eq!(secs2ms(Some("1.5xyz")).ok(), Some(1500));
        assert_eq!(secs2ms(Some("1 ")).ok(), Some(1000));
    }

    #[test]
    fn secs2ms_error_asymmetry_is_preserved() {
        // An absent argument and a value with no digits both report
        // BAD_NUMERIC, from `:312-313`.
        assert!(matches!(secs2ms(None), Err(ParameterError::BadNumeric)));
        assert!(matches!(secs2ms(Some("")), Err(ParameterError::BadNumeric)));
        assert!(matches!(
            secs2ms(Some(" 1")),
            Err(ParameterError::BadNumeric)
        ));
        assert!(matches!(
            secs2ms(Some("-1")),
            Err(ParameterError::BadNumeric)
        ));

        // The whole-seconds bound is LONG_MAX/1000 - 1 == 9223372036854774,
        // and exceeding it is BAD_NUMERIC rather than NUMBER_TOO_LARGE.
        assert_eq!(
            secs2ms(Some("9223372036854774")).ok(),
            Some(9_223_372_036_854_774_000)
        );
        assert!(matches!(
            secs2ms(Some("9223372036854775")),
            Err(ParameterError::BadNumeric)
        ));

        // A malformed *fraction* reports NUMBER_TOO_LARGE instead, because
        // `:317-318` maps every failure of the second scan to it -- including
        // STRE_NO_NUM.
        assert!(matches!(
            secs2ms(Some("1.")),
            Err(ParameterError::NumberTooLarge)
        ));
        assert!(matches!(
            secs2ms(Some("1.x")),
            Err(ParameterError::NumberTooLarge)
        ));
    }

    // -- 6. str2offset, src/tool_paramhlp.c:539-545 ------------------------

    #[test]
    fn str2offset_is_unsigned_and_strict() {
        assert_eq!(str2offset("0").ok(), Some(0));
        assert_eq!(str2offset("9223372036854775807").ok(), Some(i64::MAX));
        // "The offset CANNOT be negative!" -- `:535`. There is no sign scan.
        assert!(matches!(str2offset("-1"), Err(ParameterError::BadNumeric)));
        assert!(matches!(str2offset("1 "), Err(ParameterError::BadNumeric)));
        assert!(matches!(str2offset(""), Err(ParameterError::BadNumeric)));
        assert!(matches!(
            str2offset("9223372036854775808"),
            Err(ParameterError::BadNumeric)
        ));
    }

    // -- 7. str2tls_max, src/tool_paramhlp.c:710-731 -----------------------

    #[test]
    fn str2tls_max_is_case_sensitive() {
        assert_eq!(str2tls_max(Some("default")).ok(), Some(0));
        assert_eq!(str2tls_max(Some("1.0")).ok(), Some(1));
        assert_eq!(str2tls_max(Some("1.1")).ok(), Some(2));
        assert_eq!(str2tls_max(Some("1.2")).ok(), Some(3));
        assert_eq!(str2tls_max(Some("1.3")).ok(), Some(4));

        // `:727` compares with `strcmp`, not `curl_strequal`: this is the one
        // table in the file that rejects a different case.
        assert!(matches!(
            str2tls_max(Some("DEFAULT")),
            Err(ParameterError::BadUse)
        ));
        assert!(matches!(
            str2tls_max(Some("Default")),
            Err(ParameterError::BadUse)
        ));
        assert!(matches!(
            str2tls_max(Some("1.4")),
            Err(ParameterError::BadUse)
        ));
        assert!(matches!(str2tls_max(Some("")), Err(ParameterError::BadUse)));
        assert!(matches!(
            str2tls_max(None),
            Err(ParameterError::RequiresParameter)
        ));
    }

    // -- 8. ftpfilemethod, src/tool_paramhlp.c:612-624 ---------------------

    #[test]
    fn ftpfilemethod_matches_without_regard_to_ascii_case() {
        let mut sink = Vec::new();
        assert_eq!(ftpfilemethod("SingleCWD", &mut sink, &loud()), 3);
        assert_eq!(ftpfilemethod("NOCWD", &mut sink, &loud()), 2);
        assert_eq!(ftpfilemethod("multicwd", &mut sink, &loud()), 1);
        assert_eq!(ftpfilemethod("MultiCWD", &mut sink, &loud()), 1);
        // Nothing recognised warns.
        assert!(sink.is_empty());
    }

    #[test]
    fn ftpfilemethod_warns_with_frozen_text_and_defaults() {
        let mut sink = Vec::new();
        assert_eq!(ftpfilemethod("bogus", &mut sink, &loud()), 1);
        assert_eq!(
            warning_text(&sink),
            b"unrecognized ftp file method 'bogus', using default".to_vec()
        );

        // Silence suppresses the warning but not the fallback.
        let mut quiet = Vec::new();
        let silent = MsgConfig::new(true, false, false);
        assert_eq!(ftpfilemethod("bogus", &mut quiet, &silent), 1);
        assert!(quiet.is_empty());
    }

    // -- 9. ftpcccmethod, src/tool_paramhlp.c:626-636 ----------------------

    #[test]
    fn ftpcccmethod_matches_and_warns() {
        let mut sink = Vec::new();
        assert_eq!(ftpcccmethod("PASSIVE", &mut sink, &loud()), 1);
        assert_eq!(ftpcccmethod("Active", &mut sink, &loud()), 2);
        assert!(sink.is_empty());

        assert_eq!(ftpcccmethod("nope", &mut sink, &loud()), 1);
        assert_eq!(
            warning_text(&sink),
            b"unrecognized ftp CCC method 'nope', using default".to_vec()
        );
    }

    // -- 10. delegation, src/tool_paramhlp.c:638-650 -----------------------

    #[test]
    fn delegation_matches_and_warns() {
        let mut sink = Vec::new();
        assert_eq!(delegation("None", &mut sink, &loud()), 0);
        assert_eq!(delegation("POLICY", &mut sink, &loud()), 1);
        assert_eq!(delegation("always", &mut sink, &loud()), 2);
        assert!(sink.is_empty());

        assert_eq!(delegation("maybe", &mut sink, &loud()), 0);
        assert_eq!(
            warning_text(&sink),
            b"unrecognized delegation method 'maybe', using none".to_vec()
        );
    }

    // -- memcrlf, src/tool_paramhlp.c:69-82 --------------------------------

    #[test]
    fn memcrlf_counts_in_both_directions() {
        // `countcrlf == false`: bytes that are not CR, LF or NUL.
        assert_eq!(memcrlf(b"abc\r\ndef", false), 3);
        assert_eq!(memcrlf(b"\r\nabc", false), 0);
        // `countcrlf == true`: bytes that are.
        assert_eq!(memcrlf(b"\r\n\r\nabc", true), 4);
        assert_eq!(memcrlf(b"abc", true), 0);
        // No delimiter found returns the whole length -- `:81`.
        assert_eq!(memcrlf(b"abc", false), 3);
        assert_eq!(memcrlf(b"\r\r\r", true), 3);
        assert_eq!(memcrlf(b"", false), 0);
        // NUL counts as a terminator, per `ISCRLF` at `:57`.
        assert_eq!(memcrlf(b"ab\0cd", false), 2);
        assert_eq!(memcrlf(b"\0\0ab", true), 2);
    }

    // -- dyn_addn, the cap that becomes PARAM_NO_MEM -----------------------

    #[test]
    fn dyn_addn_reserves_the_terminator_c_always_counts() {
        // `lib/curlx/dynbuf.c:72` computes `fit = len + idx + 1`, so a cap of 4
        // admits three bytes and refuses four.
        let mut out = Vec::new();
        assert!(dyn_addn(&mut out, b"abc", 4).is_ok());
        assert_eq!(out, b"abc".to_vec());
        assert!(matches!(
            dyn_addn(&mut out, b"d", 4),
            Err(ParameterError::NoMem)
        ));
        // And the bytes already held count towards the cap.
        let mut fresh = Vec::new();
        assert!(matches!(
            dyn_addn(&mut fresh, b"abcd", 4),
            Err(ParameterError::NoMem)
        ));

        // The 16 GiB caps of `MAX_FILE2STRING` and `MAX_FILE2MEMORY`
        // (`src/tool_paramhlp.h:32-36`) cannot be exercised in memory, so this
        // is where the `CURLE_TOO_LARGE` to `PARAM_NO_MEM` collapse recorded as
        // translation difference 2 is pinned: every capped append in this
        // module goes through here.
        //
        // The two caps alias each other at `src/tool_paramhlp.c:84`, which is
        // checkable on any target; the 16 GiB value itself is only the 64-bit
        // arm, so it is asserted under the same `cfg` that selects it.
        assert_eq!(MAX_FILE2STRING, MAX_FILE2MEMORY);
        #[cfg(target_pointer_width = "64")]
        assert_eq!(MAX_FILE2MEMORY, 17_179_869_184);
        assert_eq!(MAX_USERPWDLENGTH, 102_400);
        assert_eq!(MAX_PROTOS, 34);
        assert_eq!(MAX_PROTOSTRING, 374);
        assert_eq!(PASSWORD_BUFFER_SIZE, 2048);
        assert_eq!(READ_CHUNK, 4096);
        assert_eq!(PROTO_TOKEN_MAX, 31);
    }

    // -- 11. file2string, src/tool_paramhlp.c:86-118 -----------------------

    #[test]
    fn file2string_strips_every_terminator_run() {
        let mut input = IoCursor::new(b"a\r\n\r\nb".to_vec());
        assert_eq!(
            file2string(Some(&mut input)).ok().as_deref(),
            Some(&b"ab"[..])
        );

        let mut only = IoCursor::new(b"\n\n".to_vec());
        assert_eq!(
            file2string(Some(&mut only)).ok().as_deref(),
            Some(&b""[..])
        );

        // A NUL is a terminator too, so it joins the pieces rather than
        // ending the value.
        let mut nul = IoCursor::new(b"a\0b".to_vec());
        assert_eq!(
            file2string(Some(&mut nul)).ok().as_deref(),
            Some(&b"ab"[..])
        );

        // Leading and trailing runs vanish entirely.
        let mut edges = IoCursor::new(b"\r\nabc\r\n".to_vec());
        assert_eq!(
            file2string(Some(&mut edges)).ok().as_deref(),
            Some(&b"abc"[..])
        );

        // An absent source is success with an empty value -- the whole C body
        // sits inside `if(file)` at `:90`.
        assert_eq!(file2string(None).ok().as_deref(), Some(&b""[..]));
    }

    #[test]
    fn file2string_is_chunk_boundary_invariant() {
        // A terminator run split across two 4,096-byte reads must give the same
        // answer as an unsplit one. The first read ends on the CR; the second
        // opens on the LF, which drives `memcrlf(FALSE)` to return 0 -- the
        // zero-length-append path of `:104`.
        let mut bytes = vec![b'a'; READ_CHUNK - 1];
        bytes.extend_from_slice(b"\r\nb");
        let mut split = IoCursor::new(bytes);

        let mut expected = vec![b'a'; READ_CHUNK - 1];
        expected.push(b'b');
        assert_eq!(
            file2string(Some(&mut split)).ok().as_deref(),
            Some(expected.as_slice())
        );
    }

    #[test]
    fn file2string_reports_a_read_error() {
        let mut failing = FailingReader;
        assert!(matches!(
            file2string(Some(&mut failing)),
            Err(ParameterError::ReadError)
        ));
    }

    // -- 12. file2memory_range, src/tool_paramhlp.c:120-191 ----------------

    #[test]
    fn file2memory_range_end_is_inclusive() {
        // `starto == endo == 0` yields exactly one byte: the `+ 1` at `:172`.
        let mut one = seekable(b"abcdef");
        assert_eq!(
            file2memory_range(Some(&mut one), 0, 0).ok().as_deref(),
            Some(&b"a"[..])
        );

        let mut three = seekable(b"abcdef");
        assert_eq!(
            file2memory_range(Some(&mut three), 0, 2).ok().as_deref(),
            Some(&b"abc"[..])
        );

        // A range that starts partway through.
        let mut middle = seekable(b"abcdef");
        assert_eq!(
            file2memory_range(Some(&mut middle), 2, 3).ok().as_deref(),
            Some(&b"cd"[..])
        );

        // An end beyond the last byte yields the rest of the source.
        let mut past = seekable(b"abcdef");
        assert_eq!(
            file2memory_range(Some(&mut past), 0, 999).ok().as_deref(),
            Some(&b"abcdef"[..])
        );

        // An absent source is success with an empty value -- `:186-189`.
        assert_eq!(
            file2memory_range(None, 0, 0).ok().as_deref(),
            Some(&b""[..])
        );
    }

    #[test]
    fn file2memory_range_drains_a_source_that_cannot_seek() {
        // `:135-137`: "we cannot seek stdin, read 'starto' bytes and throw them
        // away". The visible result must match the seekable path exactly.
        let mut stream = streaming(b"abcdef");
        assert_eq!(
            file2memory_range(Some(&mut stream), 2, 3).ok().as_deref(),
            Some(&b"cd"[..])
        );

        // A drain longer than the first read block still lands on the right
        // byte, which is the case the `throwaway >= nread` arm of `:155-163`
        // exists for.
        let mut long: Vec<u8> = vec![b'x'; READ_CHUNK + 10];
        long.extend_from_slice(b"TAIL");
        let total = long.len();
        let mut source = streaming(&long);
        let start = as_off(total.saturating_sub(4));
        assert_eq!(
            file2memory_range(Some(&mut source), start, CURL_OFF_T_MAX)
                .ok()
                .as_deref(),
            Some(&b"TAIL"[..])
        );
    }

    #[test]
    fn file2memory_reads_everything() {
        // `:193-196` is `file2memory_range(..., 0, CURL_OFF_T_MAX)`.
        let mut source = seekable(b"abcdef");
        assert_eq!(
            file2memory(Some(&mut source)).ok().as_deref(),
            Some(&b"abcdef"[..])
        );

        // Nothing is stripped here, unlike `file2string`.
        let mut raw = seekable(b"a\r\n\0b");
        assert_eq!(
            file2memory(Some(&mut raw)).ok().as_deref(),
            Some(&b"a\r\n\0b"[..])
        );

        assert_eq!(file2memory(None).ok().as_deref(), Some(&b""[..]));
    }

    // -- 13. read errors ---------------------------------------------------

    #[test]
    fn file2memory_range_reports_a_read_error() {
        let mut failing = StreamSource::new(FailingReader);
        assert!(matches!(
            file2memory_range(Some(&mut failing), 0, CURL_OFF_T_MAX),
            Err(ParameterError::ReadError)
        ));

        // A failure while seeking is the same error -- `:132-133`.
        let mut seek_failing = SeekSource::new(FailingSeek);
        assert!(matches!(
            file2memory_range(Some(&mut seek_failing), 4, CURL_OFF_T_MAX),
            Err(ParameterError::ReadError)
        ));
    }

    /// A seekable source whose seek fails, for `:132-133`.
    struct FailingSeek;

    impl Read for FailingSeek {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }
    }

    impl Seek for FailingSeek {
        fn seek(&mut self, _pos: SeekFrom) -> io::Result<u64> {
            Err(io::Error::other("seek failed"))
        }
    }

    // -- 14-18. the protocol set, src/tool_paramhlp.c:395-510 --------------

    #[test]
    fn proto2num_selects_and_orders() -> Result<(), Error> {
        let info = get_libcurl_info()?;
        let mut sink = Vec::new();

        // Named protocols with no modifier are allowed into an empty set.
        assert_eq!(
            proto2num(&info, &[], "http,https", &mut sink, &loud())
                .ok()
                .as_deref(),
            Some("http,https")
        );

        // `=` replaces the whole set, so only the named one survives even when
        // the preset held everything.
        assert_eq!(
            proto2num(
                &info,
                info.built_in_protos(),
                "=http",
                &mut sink,
                &loud()
            )
            .ok()
            .as_deref(),
            Some("http")
        );

        // Nothing above warned.
        assert!(sink.is_empty());
        Ok(())
    }

    #[test]
    fn proto2num_denies_and_re_allows() -> Result<(), Error> {
        let info = get_libcurl_info()?;
        let mut sink = Vec::new();
        let all = info.built_in_protos();

        // `file` is advertised unconditionally by the engine, so it is the one
        // token available whatever the Cargo feature selection.
        let mut without: Vec<&str> =
            all.iter().copied().filter(|name| *name != "file").collect();
        without.sort_by(struplocompare4sort);
        let expected = without.join(",");

        assert_eq!(
            proto2num(&info, all, "-file", &mut sink, &loud())
                .ok()
                .as_deref(),
            Some(expected.as_str())
        );

        // `+` puts it back; the result is the full set again.
        let mut everything: Vec<&str> = all.to_vec();
        everything.sort_by(struplocompare4sort);
        let full = everything.join(",");
        assert_eq!(
            proto2num(&info, all, "-file,+file", &mut sink, &loud())
                .ok()
                .as_deref(),
            Some(full.as_str())
        );

        // The same two steps written with the `ftp` token of the prompt's
        // example, when this build advertises it.
        if info.proto_token(Some("ftp")).is_some() {
            let mut no_ftp: Vec<&str> =
                all.iter().copied().filter(|name| *name != "ftp").collect();
            no_ftp.sort_by(struplocompare4sort);
            assert_eq!(
                proto2num(&info, all, "-ftp", &mut sink, &loud())
                    .ok()
                    .as_deref(),
                Some(no_ftp.join(",").as_str())
            );
            assert_eq!(
                proto2num(&info, all, "-ftp,+ftp", &mut sink, &loud())
                    .ok()
                    .as_deref(),
                Some(full.as_str())
            );
        }

        assert!(sink.is_empty());
        Ok(())
    }

    #[test]
    fn proto2num_handles_all_and_an_emptied_set() -> Result<(), Error> {
        let info = get_libcurl_info()?;
        let mut sink = Vec::new();
        let mut everything: Vec<&str> = info.built_in_protos().to_vec();
        everything.sort_by(struplocompare4sort);
        let full = everything.join(",");

        // `all` restores every built-in from an empty start -- `:455-459`.
        assert_eq!(
            proto2num(&info, &[], "all", &mut sink, &loud())
                .ok()
                .as_deref(),
            Some(full.as_str())
        );
        // Case-insensitively, because `:450` uses `curl_strnequal`.
        assert_eq!(
            proto2num(&info, &[], "ALL", &mut sink, &loud())
                .ok()
                .as_deref(),
            Some(full.as_str())
        );
        // `=all` does the same, through the shared arm.
        assert_eq!(
            proto2num(&info, &[], "=all", &mut sink, &loud())
                .ok()
                .as_deref(),
            Some(full.as_str())
        );

        // `-all` empties the set, and an empty set is PARAM_BAD_USE at
        // `:504-507`.
        assert!(matches!(
            proto2num(
                &info,
                info.built_in_protos(),
                "-all",
                &mut sink,
                &loud()
            ),
            Err(ParameterError::BadUse)
        ));

        assert!(sink.is_empty());
        Ok(())
    }

    #[test]
    fn proto2num_output_is_sorted_and_comma_joined() -> Result<(), Error> {
        let info = get_libcurl_info()?;
        let mut sink = Vec::new();

        // The tokens come back from `proto_token` in the engine's own
        // spelling, so a case-mixed *argument* still yields the canonical
        // names; ordering is then `struplocompare4sort`'s, which is the
        // comparator `:497` names. A plain `sort` would agree on an
        // all-lowercase set, so this pins the specification rather than
        // distinguishing the two -- the ordering oracle is built with the
        // required comparator either way.
        assert_eq!(
            proto2num(&info, &[], "HTTPS,HTTP,File", &mut sink, &loud())
                .ok()
                .as_deref(),
            Some("file,http,https")
        );
        assert!(sink.is_empty());

        // No spaces anywhere, and no trailing separator.
        let joined =
            proto2num(&info, info.built_in_protos(), "all", &mut sink, &loud());
        let text = joined.ok();
        let text: &str = text.as_deref().unwrap_or_default();
        assert!(!text.contains(' '));
        assert!(!text.ends_with(','));
        assert!(!text.starts_with(','));
        assert!(text.len() < MAX_PROTOSTRING);
        Ok(())
    }

    #[test]
    fn proto2num_skips_empty_tokens() -> Result<(), Error> {
        let info = get_libcurl_info()?;
        let mut sink = Vec::new();

        // `:423-426` -- `if(str == next) { str++; continue; }`.
        assert_eq!(
            proto2num(&info, &[], "http,,https", &mut sink, &loud())
                .ok()
                .as_deref(),
            Some("http,https")
        );
        assert_eq!(
            proto2num(&info, &[], ",http", &mut sink, &loud())
                .ok()
                .as_deref(),
            Some("http")
        );
        assert_eq!(
            proto2num(&info, &[], "http,", &mut sink, &loud())
                .ok()
                .as_deref(),
            Some("http")
        );
        assert!(sink.is_empty());
        Ok(())
    }

    #[test]
    fn proto2num_warns_about_an_unknown_protocol() -> Result<(), Error> {
        let info = get_libcurl_info()?;

        // `:486` -- frozen text, and the set is otherwise untouched.
        let mut sink = Vec::new();
        assert_eq!(
            proto2num(&info, &["http"], "bogus", &mut sink, &loud())
                .ok()
                .as_deref(),
            Some("http")
        );
        assert_eq!(
            warning_text(&sink),
            b"unrecognized protocol 'bogus'".to_vec()
        );

        // With `=`, `:482-484` clears the set first -- "if they have specified
        // only this protocol, we say treat it as if no protocols are allowed"
        // -- so the result is empty and PARAM_BAD_USE.
        let mut cleared = Vec::new();
        assert!(matches!(
            proto2num(
                &info,
                info.built_in_protos(),
                "=bogus",
                &mut cleared,
                &loud()
            ),
            Err(ParameterError::BadUse)
        ));
        assert_eq!(
            warning_text(&cleared),
            b"unrecognized protocol 'bogus'".to_vec()
        );

        // A stubbed scheme is legitimately unknown (AAP 0.6.5): the engine does
        // not advertise it, so `--proto smtp` warns here while the 283 fixtures
        // that target it skip on the `Protocols:` line instead.
        let mut stub = Vec::new();
        assert!(info.proto_token(Some("smtp")).is_none());
        assert!(matches!(
            proto2num(&info, &[], "smtp", &mut stub, &loud()),
            Err(ParameterError::BadUse)
        ));
        assert_eq!(
            warning_text(&stub),
            b"unrecognized protocol 'smtp'".to_vec()
        );
        Ok(())
    }

    #[test]
    fn proto2num_truncates_an_over_long_token() -> Result<(), Error> {
        let info = get_libcurl_info()?;
        let mut sink = Vec::new();

        // `char buffer[32]` at `:463` holds 31 bytes and a NUL, so a longer
        // token is cut before `proto_token` ever sees it and the warning
        // reports the cut form.
        let long = "a".repeat(40);
        assert!(matches!(
            proto2num(&info, &[], &long, &mut sink, &loud()),
            Err(ParameterError::BadUse)
        ));
        let mut expected = b"unrecognized protocol '".to_vec();
        expected.extend_from_slice("a".repeat(PROTO_TOKEN_MAX).as_bytes());
        expected.push(b'\'');
        assert_eq!(warning_text(&sink), expected);

        // Exactly 31 bytes is not truncated.
        let edge = "b".repeat(PROTO_TOKEN_MAX);
        let mut edge_sink = Vec::new();
        assert!(matches!(
            proto2num(&info, &[], &edge, &mut edge_sink, &loud()),
            Err(ParameterError::BadUse)
        ));
        let mut edge_expected = b"unrecognized protocol '".to_vec();
        edge_expected.extend_from_slice(edge.as_bytes());
        edge_expected.push(b'\'');
        assert_eq!(warning_text(&edge_sink), edge_expected);
        Ok(())
    }

    #[test]
    fn proto2num_ignores_an_unknown_preset_entry() -> Result<(), Error> {
        let info = get_libcurl_info()?;
        let mut sink = Vec::new();

        // `:410-415` skips a preset name the engine does not know, silently --
        // there is no warning on that path. `--proto-redir`'s preset
        // (`src/tool_getparam.c:2349-2355`) names ftp and ftps, which a build
        // without the `ftp` feature does not advertise, so this path is live.
        let preset = ["http", "https", "ftp", "ftps"];
        let text = proto2num(&info, &preset, "", &mut sink, &loud());
        let text = text.ok();
        let text: &str = text.as_deref().unwrap_or_default();
        assert!(text.contains("http"));
        assert!(sink.is_empty());
        Ok(())
    }

    // -- 19. check_protocol, src/tool_paramhlp.c:521-529 -------------------

    #[test]
    fn check_protocol_reports_what_the_engine_advertises() -> Result<(), Error>
    {
        let info = get_libcurl_info()?;

        assert!(check_protocol(&info, Some("http")).is_ok());
        assert!(check_protocol(&info, Some("HTTP")).is_ok());
        assert!(check_protocol(&info, Some("file")).is_ok());

        // `ipfs` and `ipns` are hard-coded literals in
        // `src/tool_libinfo.c:47-50` that are never part of
        // `built_in_protos`, so they are correctly
        // unsupported here even though the tool has flags mentioning them.
        assert!(matches!(
            check_protocol(&info, Some("ipfs")),
            Err(ParameterError::LibcurlUnsupportedProtocol)
        ));
        assert!(matches!(
            check_protocol(&info, Some("smtp")),
            Err(ParameterError::LibcurlUnsupportedProtocol)
        ));
        assert!(matches!(
            check_protocol(&info, None),
            Err(ParameterError::RequiresParameter)
        ));
        Ok(())
    }

    // -- add2list and inlist, src/tool_paramhlp.c:601-610, :652-671 --------

    #[test]
    fn add2list_appends_in_order() {
        let mut list: Vec<String> = Vec::new();
        assert!(add2list(&mut list, "first").is_ok());
        assert!(add2list(&mut list, "second").is_ok());
        assert_eq!(list, vec!["first".to_owned(), "second".to_owned()]);
    }

    #[test]
    fn inlist_needs_a_header_separator_after_the_name() {
        let list = vec![
            "content-type: text/plain".to_owned(),
            "X-Thing;".to_owned(),
            "Acceptable: no".to_owned(),
        ];

        // Case-insensitive over exactly the name's length, then `:` or `;`.
        assert!(inlist(&list, "Content-Type"));
        assert!(inlist(&list, "CONTENT-TYPE"));
        assert!(inlist(&list, "X-Thing"));

        // "Accept" is a prefix of "Acceptable", but the following byte is 'a',
        // not a separator, so it does not match -- `:666`.
        assert!(!inlist(&list, "Accept"));

        // An entry shorter than the name cannot match, and one exactly as long
        // has no separator after it.
        assert!(!inlist(&["Con".to_owned()], "Content-Type"));
        assert!(!inlist(&["Accept".to_owned()], "Accept"));
        assert!(!inlist(&[], "Accept"));
    }

    #[test]
    fn is_header_sep_is_colon_or_semicolon() {
        assert!(is_header_sep(b':'));
        assert!(is_header_sep(b';'));
        assert!(!is_header_sep(b' '));
        assert!(!is_header_sep(0));
        assert!(!is_header_sep(b'a'));
    }

    // -- 20-23. checkpasswd, src/tool_paramhlp.c:548-599 -------------------

    #[test]
    fn checkpasswd_short_prompt_only_for_the_first_and_last_url() {
        let mut asked: Vec<String> = Vec::new();
        let mut userpwd = Some(b"bob".to_vec());
        {
            let mut prompt = |text: &str, max_len: usize| {
                assert_eq!(max_len, PASSWORD_BUFFER_SIZE);
                asked.push(text.to_owned());
                b"secret".to_vec()
            };
            assert_eq!(
                checkpasswd("host", 0, true, &mut userpwd, &mut prompt),
                CURLcode::Ok
            );
        }
        assert_eq!(
            asked.first().map(String::as_str),
            Some("Enter host password for user 'bob':")
        );
        assert_eq!(userpwd.as_deref(), Some(&b"bob:secret"[..]));
    }

    #[test]
    fn checkpasswd_long_prompt_carries_a_one_based_url_number() {
        // Not last, so the long form even at index 0 -- `:580-587`.
        let mut asked: Vec<String> = Vec::new();
        let mut first = Some(b"bob".to_vec());
        {
            let mut prompt = |text: &str, _max: usize| {
                asked.push(text.to_owned());
                b"pw".to_vec()
            };
            assert_eq!(
                checkpasswd("host", 0, false, &mut first, &mut prompt),
                CURLcode::Ok
            );
        }
        assert_eq!(
            asked.first().map(String::as_str),
            Some("Enter host password for user 'bob' on URL #1:")
        );

        // Index 2 is URL #3: the `i + 1` of `:583`.
        let mut later_asked: Vec<String> = Vec::new();
        let mut third = Some(b"bob".to_vec());
        {
            let mut prompt = |text: &str, _max: usize| {
                later_asked.push(text.to_owned());
                b"pw".to_vec()
            };
            assert_eq!(
                checkpasswd("host", 2, true, &mut third, &mut prompt),
                CURLcode::Ok
            );
        }
        assert_eq!(
            later_asked.first().map(String::as_str),
            Some("Enter host password for user 'bob' on URL #3:")
        );
    }

    #[test]
    fn checkpasswd_kind_is_the_literal_the_caller_passes() {
        let mut asked: Vec<String> = Vec::new();
        let mut proxy = Some(b"joe".to_vec());
        {
            let mut prompt = |text: &str, _max: usize| {
                asked.push(text.to_owned());
                b"pw".to_vec()
            };
            assert_eq!(
                checkpasswd("proxy", 1, true, &mut proxy, &mut prompt),
                CURLcode::Ok
            );
        }
        assert_eq!(
            asked.first().map(String::as_str),
            Some("Enter proxy password for user 'joe' on URL #2:")
        );
    }

    #[test]
    fn checkpasswd_leaves_a_complete_or_options_only_value_alone() {
        // `:565` -- a ':' anywhere means the password is already there.
        let mut asked = 0_usize;
        let mut complete = Some(b"bob:hunter2".to_vec());
        {
            let mut prompt = |_text: &str, _max: usize| {
                asked += 1;
                b"pw".to_vec()
            };
            assert_eq!(
                checkpasswd("host", 0, true, &mut complete, &mut prompt),
                CURLcode::Ok
            );
        }
        assert_eq!(asked, 0);
        assert_eq!(complete.as_deref(), Some(&b"bob:hunter2"[..]));

        // Even an empty password counts as present.
        let mut empty_pw = Some(b"bob:".to_vec());
        {
            let mut prompt = |_text: &str, _max: usize| b"pw".to_vec();
            assert_eq!(
                checkpasswd("host", 0, true, &mut empty_pw, &mut prompt),
                CURLcode::Ok
            );
        }
        assert_eq!(empty_pw.as_deref(), Some(&b"bob:"[..]));

        // A value that opens with the login-options separator is left alone.
        let mut options_only = Some(b";auth=NTLM".to_vec());
        {
            let mut prompt = |_text: &str, _max: usize| b"pw".to_vec();
            assert_eq!(
                checkpasswd("host", 0, true, &mut options_only, &mut prompt),
                CURLcode::Ok
            );
        }
        assert_eq!(options_only.as_deref(), Some(&b";auth=NTLM"[..]));

        // No option at all is nothing to do.
        let mut absent: Option<Vec<u8>> = None;
        {
            let mut prompt = |_text: &str, _max: usize| b"pw".to_vec();
            assert_eq!(
                checkpasswd("host", 0, true, &mut absent, &mut prompt),
                CURLcode::Ok
            );
        }
        assert_eq!(absent, None);
    }

    #[test]
    fn checkpasswd_hides_login_options_from_the_prompt_but_keeps_them() {
        let mut asked: Vec<String> = Vec::new();
        let mut userpwd = Some(b"bob;auth=NTLM".to_vec());
        {
            let mut prompt = |text: &str, _max: usize| {
                asked.push(text.to_owned());
                b"pw".to_vec()
            };
            assert_eq!(
                checkpasswd("host", 0, true, &mut userpwd, &mut prompt),
                CURLcode::Ok
            );
        }
        // `:578` truncates for the prompt...
        assert_eq!(
            asked.first().map(String::as_str),
            Some("Enter host password for user 'bob':")
        );
        // ...and `:588` restores before `:590` composes, so the options are in
        // the credential.
        assert_eq!(userpwd.as_deref(), Some(&b"bob;auth=NTLM:pw"[..]));
    }

    #[test]
    fn checkpasswd_composes_bytes_without_re_encoding_them() {
        // A user name that is not UTF-8 is rendered lossily in the prompt --
        // GAP #5 -- but reaches the credential unchanged.
        let mut asked: Vec<String> = Vec::new();
        let mut userpwd = Some(vec![0xffu8, 0xfe, b'x']);
        {
            let mut prompt = |text: &str, _max: usize| {
                asked.push(text.to_owned());
                b"pw".to_vec()
            };
            assert_eq!(
                checkpasswd("host", 0, true, &mut userpwd, &mut prompt),
                CURLcode::Ok
            );
        }
        assert_eq!(asked.len(), 1);
        assert_eq!(
            userpwd.as_deref(),
            Some(&[0xffu8, 0xfe, b'x', b':', b'p', b'w'][..])
        );
    }

    #[test]
    fn checkpasswd_enforces_the_composed_length_cap() {
        // `:574` caps the result at MAX_USERPWDLENGTH, and `:590-591` reports
        // any failure as CURLE_OUT_OF_MEMORY. "bob" plus ':' plus the password
        // plus dynbuf's reserved terminator must not exceed 102,400.
        let fits = MAX_USERPWDLENGTH - 3 - 1 - 1;

        let mut ok_value = Some(b"bob".to_vec());
        {
            let mut prompt = |_text: &str, _max: usize| vec![b'p'; fits];
            assert_eq!(
                checkpasswd("host", 0, true, &mut ok_value, &mut prompt),
                CURLcode::Ok
            );
        }
        assert_eq!(
            ok_value.as_deref().map(<[u8]>::len),
            Some(MAX_USERPWDLENGTH - 1)
        );

        let mut too_big = Some(b"bob".to_vec());
        {
            let mut prompt = |_text: &str, _max: usize| vec![b'p'; fits + 1];
            assert_eq!(
                checkpasswd("host", 0, true, &mut too_big, &mut prompt),
                CURLcode::OutOfMemory
            );
        }
        // The value is left as it was when the cap refused the composition.
        assert_eq!(too_big.as_deref(), Some(&b"bob"[..]));
    }

    // -- 24-25. get_args, src/tool_paramhlp.c:673-706 ----------------------

    /// [`get_args_with`] over freshly owned state, returning what it produced.
    fn run_get_args(
        jsoned: bool,
        headers: Vec<String>,
        userpwd: Option<Vec<u8>>,
        proxyuserpwd: Option<Vec<u8>>,
        oauth_bearer: Option<&str>,
        i: usize,
        last: bool,
    ) -> (
        CURLcode,
        Vec<String>,
        Vec<String>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
    ) {
        let mut headers = headers;
        let mut userpwd = userpwd;
        let mut proxyuserpwd = proxyuserpwd;
        let mut asked: Vec<String> = Vec::new();
        let code = {
            let mut prompt = |text: &str, _max: usize| {
                asked.push(text.to_owned());
                b"pw".to_vec()
            };
            let args = OperationArgs {
                jsoned,
                headers: &mut headers,
                userpwd: &mut userpwd,
                proxyuserpwd: &mut proxyuserpwd,
                oauth_bearer,
                last,
            };
            get_args_with(args, i, &mut prompt)
        };
        (code, headers, asked, userpwd, proxyuserpwd)
    }

    #[test]
    fn get_args_adds_both_json_headers_in_order() {
        let (code, headers, asked, _, _) =
            run_get_args(true, Vec::new(), None, None, None, 0, true);
        assert_eq!(code, CURLcode::Ok);
        assert_eq!(
            headers,
            vec![
                "Content-Type: application/json".to_owned(),
                "Accept: application/json".to_owned(),
            ]
        );
        assert!(asked.is_empty());
    }

    #[test]
    fn get_args_does_not_duplicate_a_header_given_with_dash_h() {
        // An explicit Content-Type wins, case-insensitively.
        let (_, headers, _, _, _) = run_get_args(
            true,
            vec!["content-type: text/plain".to_owned()],
            None,
            None,
            None,
            0,
            true,
        );
        assert_eq!(
            headers,
            vec![
                "content-type: text/plain".to_owned(),
                "Accept: application/json".to_owned(),
            ]
        );

        // The `-H 'Name;'` form counts as supplied too.
        let (_, semi, _, _, _) = run_get_args(
            true,
            vec!["Accept;".to_owned()],
            None,
            None,
            None,
            0,
            true,
        );
        assert_eq!(
            semi,
            vec![
                "Accept;".to_owned(),
                "Content-Type: application/json".to_owned(),
            ]
        );

        // Both supplied: nothing is added.
        let (_, both, _, _, _) = run_get_args(
            true,
            vec!["Content-Type: a".to_owned(), "Accept: b".to_owned()],
            None,
            None,
            None,
            0,
            true,
        );
        assert_eq!(both.len(), 2);

        // A name that merely starts the same is not a match.
        let (_, prefixed, _, _, _) = run_get_args(
            true,
            vec!["Acceptable: no".to_owned()],
            None,
            None,
            None,
            0,
            true,
        );
        assert_eq!(prefixed.len(), 3);
    }

    #[test]
    fn get_args_leaves_headers_alone_without_json() {
        let (code, headers, _, _, _) = run_get_args(
            false,
            vec!["X: y".to_owned()],
            None,
            None,
            None,
            0,
            true,
        );
        assert_eq!(code, CURLcode::Ok);
        assert_eq!(headers, vec!["X: y".to_owned()]);
    }

    #[test]
    fn get_args_prompts_for_both_kinds() {
        let (code, _, asked, userpwd, proxyuserpwd) = run_get_args(
            false,
            Vec::new(),
            Some(b"bob".to_vec()),
            Some(b"joe".to_vec()),
            None,
            0,
            true,
        );
        assert_eq!(code, CURLcode::Ok);
        assert_eq!(
            asked,
            vec![
                "Enter host password for user 'bob':".to_owned(),
                "Enter proxy password for user 'joe':".to_owned(),
            ]
        );
        assert_eq!(userpwd.as_deref(), Some(&b"bob:pw"[..]));
        assert_eq!(proxyuserpwd.as_deref(), Some(&b"joe:pw"[..]));
    }

    #[test]
    fn get_args_skips_the_host_prompt_for_a_bearer_token() {
        // `:691` -- `config->userpwd && !config->oauth_bearer`.
        let (code, _, asked, userpwd, proxyuserpwd) = run_get_args(
            false,
            Vec::new(),
            Some(b"bob".to_vec()),
            Some(b"joe".to_vec()),
            Some("t0ken"),
            0,
            true,
        );
        assert_eq!(code, CURLcode::Ok);
        // Only the proxy is asked about; the host value is untouched.
        assert_eq!(
            asked,
            vec!["Enter proxy password for user 'joe':".to_owned()]
        );
        assert_eq!(userpwd.as_deref(), Some(&b"bob"[..]));
        assert_eq!(proxyuserpwd.as_deref(), Some(&b"joe:pw"[..]));
    }

    // -- new_getout, src/tool_paramhlp.c:35-55 -----------------------------

    #[test]
    fn new_getout_numbers_nodes_and_carries_remote_name_all() {
        let mut seq = GetOutSeq::new();
        assert_eq!(
            new_getout(&mut seq, true),
            NewGetOut {
                num: 0,
                useremote: true
            }
        );
        assert_eq!(
            new_getout(&mut seq, false),
            NewGetOut {
                num: 1,
                useremote: false
            }
        );
        assert_eq!(
            new_getout(&mut seq, false),
            NewGetOut {
                num: 2,
                useremote: false
            }
        );

        // The counter is owned, not global: a fresh one restarts at zero.
        // Translation difference 1 -- C's `static int outnum` at `:40` could
        // not do this, and neither could a `static AtomicU32`.
        let mut fresh = GetOutSeq::new();
        assert_eq!(
            new_getout(&mut fresh, false),
            NewGetOut {
                num: 0,
                useremote: false
            }
        );
        assert_eq!(GetOutSeq::default(), GetOutSeq::new());
    }

    // -- the strparse primitive, lib/curlx/strparse.c ----------------------

    #[test]
    fn hexascii_table_admits_zero_as_a_digit() {
        // `curlx_hexasciitable[0]` is 16, not 0, which is why `valid_digit`
        // accepts '0' at all (`lib/curlx/strparse.c:142-154`). Getting this
        // wrong would reject every leading zero.
        assert_eq!(hex_ascii_table(b'0'), 16);
        assert_eq!(hexval(b'0'), 0);
        assert_eq!(hexval(b'9'), 9);
        assert!(valid_digit(b'0', b'9'));
        assert!(valid_digit(b'7', b'7'));
        // Base 8 stops at '7'.
        assert!(!valid_digit(b'8', b'7'));
        assert!(!valid_digit(b'9', b'7'));
        // Outside the table's range entirely.
        assert!(!valid_digit(b'/', b'9'));
        assert!(!valid_digit(b'a', b'9'));
    }

    #[test]
    fn str_single_is_the_trailing_garbage_test() {
        let mut cursor = Cursor::new("-1");
        assert!(str_single(&mut cursor, b'-').is_ok());
        assert!(matches!(str_single(&mut cursor, b'-'), Err(StrError::Byte)));
        // A NUL match means "exactly at the end", because the cursor reports 0
        // past the last byte.
        assert!(str_number(&mut cursor, LONG_MAX).is_ok());
        assert!(str_single(&mut cursor, 0).is_ok());
    }

    #[test]
    fn str_num_base_leaves_zero_behind_on_failure() {
        // `lib/curlx/strparse.c:161` zeroes `*nump` before the digit test.
        let mut cursor = Cursor::new("x");
        assert!(matches!(
            str_number(&mut cursor, LONG_MAX),
            Err(StrError::NoNum)
        ));
        // And the cursor did not move, so the caller can still see the byte.
        assert_eq!(cursor.offset(), 0);
        assert_eq!(cursor.peek(), b'x');
    }
}
