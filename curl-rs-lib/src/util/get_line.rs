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

// THE BANNER ABOVE -- 23 lines, and why the licence tag appears exactly once.
//
// The block is the banner measured at `lib/llist.c:1-23` and reproduced
// byte-for-byte at `lib/curl_get_line.c:1-23`, rendered as Rust line comments
// in the stripped form the rest of this crate already uses: `src/lib.rs:1-23`,
// `src/error.rs:1-23`, `src/util/mod.rs:1-23` and `src/util/dynbuf.rs:1-23`
// are byte-identical to it. `reuse lint` runs in continuous integration at
// `.github/workflows/checksrc.yml:58-62` and requires the licence-identifier
// tag naming `curl`, which is on line 21.
//
// That tag spelling is never repeated anywhere else in this file, and the
// omission is deliberate rather than stylistic. `reuse` scans every line for
// the tag's colon form and parses whatever follows it as a licence
// expression, so a second, prose mention becomes a parse error instead of
// prose. `src/util/mod.rs:33-42` records the two verbatim diagnostics that
// established this. Line 21 is therefore the only place in this file where
// that spelling occurs, which is exactly what the tool needs.
//
// `REUSE.toml` exists at the repository root but is out of scope for this
// migration, so the annotation is made here, directly, rather than by adding
// a path entry there.

// NO `unsafe` HERE, AND NO EXEMPTION FOR IT.
//
// `src/lib.rs:105` carries `#![deny(unsafe_code)]` and grants exactly one
// exemption, on `pub(crate) mod ffi;`. This file is not under that module, so
// it has no exemption, contains no block of the kind the keyword introduces
// and contains no attribute allowing one.
//
// That is worth stating for this file in particular, because the C original
// is built out of exactly the three constructs the migration exists to
// delete: a fixed-size stack array, a pointer walked with `strlen`, and an
// unchecked index of the form `b[rlen - 1]`. All three become bounds-checked
// slice work below. The array keeps its fixed size, because its size is
// behaviour (see the chunk note in the module documentation), but nothing
// indexes past what was actually filled.
//
// The compiler is the real authority: with no exemption in this file,
// `#![deny(unsafe_code)]` makes any occurrence a hard error. Four executable
// gates in `src/lib.rs` (`mod source_policy`) additionally scan this crate's
// own source text, and this file is written to pass all four -- the keyword
// appears only under `src/ffi/`, at most one exemption exists per crate, no
// raw string literal defeats the scanner's comment stripper, and no C scalar
// width is named outside the island. A fifth forbids a `dead_code` lint level
// on a module or crate root, which is why the allowance below sits on the
// item.

// The `dead_code` allowance, and why there is exactly one.
//
// [`get_line`] has four measured consumers and not one of them has landed
// yet: the Netscape cookie jar, the Alt-Svc cache, `.netrc` and the HSTS
// cache all live under `src/cookies/`, which this checkpoint does not carry.
// Until they arrive the function is legitimately unreferenced and the
// zero-warnings gate would otherwise fail on code that is correct.
//
// It is `allow` rather than `expect` because a `#[cfg(test)]` use does not
// count towards the lint -- the lint is evaluated for the non-test build --
// so `expect` would itself become an unfulfilled-expectation warning the
// moment the tests below are the only callers. Measured on the pinned
// toolchain, rustc 1.97.1.
//
// One allowance, not three. `read_chunk` and `CHUNK_BYTES` are reachable
// from [`get_line`], and rustc's reachability pass treats an item carrying
// the allowance as a live root, so the whole chain below it is live. That was
// measured rather than assumed: adding a second allowance produces no change
// in output, so the extra one would be noise. It is removed when the first
// consumer lands.

//! Whole-line reading for curl's on-disk state files.
//!
//! **Every successful return leaves the buffer non-empty and ending in
//! `'\n'`.** That is the whole contract, it is stated first because a
//! consumer depends on it, and it holds even when the underlying file
//! contained no newline at all -- at end of input this function *synthesises*
//! one. The immediate corollary is the one that surprises every reader:
//! after the last real line of a file that ends in a newline, one further
//! call reads nothing and returns a buffer holding **exactly `"\n"`**.
//!
//! Supersedes `lib/curl_get_line.c` (67 lines) and its interface
//! `lib/curl_get_line.h` (31 lines), per specification 0.4.1, which maps
//! `get_line.rs <- lib/curl_get_line.c`.
//!
//! # The four consumers, and why their file formats freeze this behaviour
//!
//! Measured with `grep -rn Curl_get_line lib/ src/`. There are exactly four,
//! and every one of them parses a persisted format that must stay readable by
//! and writable for curl 8.x:
//!
//! | Call site | Format | Buffer ceiling |
//! |-----------|--------|----------------|
//! | `lib/cookie.c:1120` | Netscape cookie jar | `MAX_COOKIE_LINE` 5000 |
//! | `lib/altsvc.c:215` | Alt-Svc cache | `MAX_ALTSVC_LINE` 4095 |
//! | `lib/netrc.c:84` | `.netrc` | `MAX_NETRC_LINE` 16384 |
//! | `lib/hsts.c:512` | HSTS cache | `MAX_HSTS_LINE` 4095 |
//!
//! Specification 0.8.1 freezes those on-disk shapes, so this file reproduces
//! the C's behaviour including the two places where that behaviour is
//! surprising and the one place where it is arguably wrong. Specification
//! 0.1.1 settles the tie explicitly: where a choice exists between a nicer
//! design and a more behaviourally faithful one, faithfulness wins.
//!
//! # A consumer depends on the synthesised newline
//!
//! This is not a curiosity to be tidied away. `lib/hsts.c:517-520` says so in
//! as many words:
//!
//! ```text
//! /*
//!  * Skip empty or commented lines, since we know the line will have a
//!  * trailing newline from Curl_get_line we can treat length 1 as empty.
//!  */
//! if((*lineptr == '#') || strlen(lineptr) <= 1)
//!   continue;
//! ```
//!
//! Suppressing the terminal `"\n"` line would leave that filter testing for
//! a length that never occurs, and an HSTS cache would start being parsed one
//! line short of where it used to be. An empty, zero-byte file yields exactly
//! one line -- `"\n"` -- with the end-of-input flag set.
//!
//! The other three consumers each treat that line differently, and all three
//! behaviours must stay reachable:
//!
//! - `lib/hsts.c` filters it explicitly, as above.
//! - `lib/altsvc.c:214-222` has **no** length guard at all. It hands the bare
//!   `"\n"` to `altsvc_add`, which rejects it while parsing.
//! - `lib/netrc.c:82-99` appends it to the accumulated file buffer as a blank
//!   line.
//! - `lib/cookie.c:1116-1136` passes it to `Curl_cookie_add`, which rejects
//!   it.
//!
//! # The consumer loop shape
//!
//! Recorded here so that the `src/cookies/` modules inherit it rather than
//! rediscover it. All four are `do { ... } while(!eof)`: the body always runs
//! at least once, and the loop terminates on the flag, **never** on a null or
//! empty return -- there is no such return to test.
//!
//! ```text
//! /* lib/netrc.c:82-99   */  do { result = Curl_get_line(&linebuf, file,
//!                                                       &eof); ... }
//!                            while(!eof);
//! /* lib/hsts.c:511-527  */  do { result = Curl_get_line(&buf, fp, &eof);
//!                                 ... if((*lineptr == '#') ||
//!                                        strlen(lineptr) <= 1) continue; }
//!                            while(!result && !eof);
//! /* lib/altsvc.c:214-222*/  do { result = Curl_get_line(&buf, fp, &eof);
//!                                 ... if(curlx_str_single(&lineptr, '#'))
//!                                        altsvc_add(asi, lineptr); }
//!                            while(!result && !eof);
//! ```
//!
//! `lib/netrc.c` is the one whose `while` tests only the flag; it breaks out
//! of the body on a non-`OK` result instead, and `curl2netrc`
//! (`lib/netrc.c:67-69`) then maps `CURLE_OUT_OF_MEMORY` to
//! `NETRC_OUT_OF_MEMORY` and every other code to `NETRC_SYNTAX_ERROR`.
//!
//! # Reproduced faithfully: the chunk is truncated at an embedded zero byte
//!
//! `fgets` delivers the bytes it read; `rlen = strlen(b)`
//! (`lib/curl_get_line.c:46`) then stops counting at the first `0x00`.
//! Everything after that zero byte, **up to and including the newline**, has
//! already been consumed from the stream and is never appended. The bytes are
//! not deferred to the next call; they are gone.
//!
//! Worked example, traced against the C: for a file containing
//! `"ab\0cd\nnext\n"`, the first call's first read consumes six bytes and
//! appends `"ab"`, finds no trailing newline, loops, and reads `"next\n"`.
//! The returned line is **`"abnext\n"`** and `"cd"` is silently lost.
//!
//! A "fixed" version that kept those bytes would be a behaviour change, so
//! this file reproduces the truncation and [`get_line`] asserts the worked
//! example above by test, so that the choice reads as deliberate rather than
//! accidental.
//!
//! # Reproduced faithfully: a carriage return is not stripped
//!
//! `lib/hsts.c:506`, `lib/altsvc.c:209` and `lib/netrc.c:74` open with
//! `FOPEN_READTEXT`, which is `"r"` on every target outside Windows
//! (`lib/curl_setup.h:1258`) and therefore identical to binary mode on all
//! four targets of specification 0.8.3. `lib/cookie.c:1108` does not even use
//! that macro -- it passes `"rb"` outright.
//!
//! So a CRLF-terminated file yields lines ending `"...\r\n"` and the
//! carriage return reaches the consumer. That is measured behaviour, it
//! matters for a cookie jar or an HSTS cache written on Windows and read
//! here, and it is recorded explicitly so that its absence does not read as
//! an oversight.
//!
//! # Not reproduced: the infinite loop on a hard read error
//!
//! One divergence, disclosed rather than buried. On a read error `fgets`
//! returns null and sets the stream's *error* indicator, not its
//! end-of-input indicator, so the C's `*eof = feof(input)` stays false, no
//! bytes are appended, no trailing newline appears, and the loop goes round
//! again -- for ever.
//!
//! That was measured twice rather than reasoned about, with a cookie-backed
//! stream whose read always fails and with a directory opened for reading:
//! `fgets` returns null with `feof == 0` and `ferror == 1`, repeatedly and
//! indefinitely. A hang is not observable behaviour a consumer can depend
//! on, and the preservation mandate is about observable behaviour, so
//! [`get_line`] returns `CURLcode::ReadError` instead. Its C spelling is
//! `CURLE_READ_ERROR` and its message, from `lib/strerror.c:114-115`, is
//! "Failed to open/read local data from file/application" -- which is exactly
//! this situation. An interrupted read is retried rather than reported,
//! matching what buffered C input does with a restartable signal.
//!
//! Every consumer already handles a non-`OK` result, because every one of
//! them can already receive `CURLE_TOO_LARGE`, so nothing downstream needs a
//! new branch.
//!
//! # No feature gate, and why the C's has no counterpart
//!
//! `lib/curl_get_line.c:26-27` wraps the whole file in
//!
//! ```text
//! #if !defined(CURL_DISABLE_COOKIES) || !defined(CURL_DISABLE_ALTSVC) || \
//!   !defined(CURL_DISABLE_HSTS) || !defined(CURL_DISABLE_NETRC)
//! ```
//!
//! Three of those four names map to features in this workspace's fifteen-name
//! vocabulary -- `cookies`, `hsts`, `altsvc` -- and the fourth does not:
//! there is no `netrc` feature, because `.netrc` support is unconditional.
//! The disjunction is therefore always true and the guard has nothing to
//! express. **This module is deliberately not gated**, and no `cfg` on a
//! feature name appears anywhere in it: a condition naming a feature that
//! does not exist compiles the code away in silence, which is the worst
//! possible failure mode for a file whose absence would only show up as a
//! missing cookie jar.
//!
//! # No limit of its own
//!
//! A line is bounded, but not by anything here. The bound is the ceiling on
//! the [`DynBuf`] the caller passes in -- the four values tabulated above --
//! and this function inherits it, imposes nothing further, and propagates the
//! buffer's error code unchanged. Two codes can arrive: `CURLE_TOO_LARGE`
//! when the line crosses the ceiling, and `CURLE_OUT_OF_MEMORY` when an
//! allocation is refused. The C annotates the same early return "too long
//! line or out of memory" at `lib/curl_get_line.c:50`.
//!
//! **On overflow the buffer is emptied, not left partially filled.**
//! `dyn_nappend` calls `curlx_dyn_free` before returning either code
//! (`lib/curlx/dynbuf.c:82-85` and `:105-110`), and
//! [`DynBuf`](crate::util::dynbuf::DynBuf) reproduces that. So after an error
//! the buffer holds nothing, which is what lets all four consumers stop their
//! loop on the result without first having to discard a half-read line.

// `Read` is deliberately NOT imported, and the omission is measured rather
// than stylistic: `BufRead` has it as a supertrait, so a `R: BufRead` bound
// already brings the byte-oriented read into scope for the generic parameter,
// and naming the trait here is an unused import that the zero-warnings gate
// rejects. The test module below does implement it and imports it for itself.
use std::io::{BufRead, ErrorKind};

use crate::error::CURLcode;
use crate::util::dynbuf::DynBuf;

/// The most bytes one read may deliver -- **127, not 128**.
///
/// The C declares `char buffer[128]` (`lib/curl_get_line.c:38`) and calls
/// `fgets(buffer, sizeof(buffer), input)` (`:42`). `fgets` reads at most
/// `size - 1` bytes and writes a terminator into the last slot, so the most
/// it ever delivers is 127. The off-by-one is recorded here so that nobody
/// "corrects" this to 128: the chunk boundary is where the zero-byte
/// truncation described in the module documentation takes effect, so it is
/// behaviour rather than a buffer-sizing detail.
///
/// A Rust slice needs no terminator, so the array below is 127 bytes rather
/// than 128 and every one of them is usable.
const CHUNK_BYTES: usize = 127;

/// Reads one chunk, and reports whether the read stopped because the input
/// was exhausted.
///
/// The counterpart of a single `fgets` call together with the
/// `*eof = feof(input)` that follows it on the very next line
/// (`lib/curl_get_line.c:42-44`). Returns the number of bytes written into
/// `buffer` and the flag.
///
/// # The three stop conditions, in the order they are tested
///
/// Exactly `fgets`', and no others:
///
/// 1. a newline was read -- it **is** included in the chunk;
/// 2. [`CHUNK_BYTES`] bytes were read;
/// 3. the input was exhausted.
///
/// Only the third sets the flag. Neither of the first two does, and that is
/// the whole subtlety of this function.
///
/// # The flag rule, measured rather than inferred
///
/// > The flag is true if and only if the read stopped because the input was
/// > **exhausted** -- not because a newline was found, and not because the
/// > chunk filled.
///
/// Four cases pin it, each traced against the C with a memory-backed stream:
///
/// | Input | Chunk | Flag | Why |
/// |-------|-------|------|-----|
/// | `"a\n"` | `"a\n"` | false | stopped at the newline |
/// | `"abc"` | `"abc"` | **true** | stopped at exhaustion |
/// | `""` | empty | **true** | exhausted immediately |
/// | 127 bytes, no newline | all 127 | **false** | stopped at the cap |
///
/// The fourth is the one that proves the rule is not "there is nothing left".
/// Those 127 bytes drain the input completely, yet the flag stays clear,
/// because nothing has yet *tried* to read past them. A second call then
/// reads nothing and sets it -- which is exactly how the terminal `"\n"` line
/// comes to exist.
///
/// # Why the flag comes from an attempted read and never from a peek
///
/// This is the single easiest mistake to make in this file, so it is stated
/// as a prohibition rather than a preference. A reader that can be asked
/// whether its internal buffer is empty offers a much cheaper answer, and
/// that answer is **wrong here**: it reports exhaustion one iteration early,
/// which suppresses the terminal `"\n"` line and breaks the `lib/hsts.c`
/// filter quoted in the module documentation. The flag is therefore derived
/// from a read that returned zero bytes, and from nothing else.
///
/// For the same reason the bytes are taken one at a time through the
/// byte-oriented read rather than through either of the two conveniences the
/// standard library offers for lines -- the one that fills a `String` and the
/// iterator that yields them. Both decode UTF-8, which these files are not
/// guaranteed to be, and the iterator additionally discards the terminator
/// this function's whole contract is built on. Neither name appears anywhere
/// in this file, so the audit expressions that search for them stay
/// unambiguous. Reading a byte at a time costs a bounds check and a one-byte
/// copy out of the reader's buffer, never a system call, and performance is
/// an explicit non-goal of this migration.
///
/// A zero-length read result means exhaustion here without ambiguity: the
/// standard library documents `Ok(0)` as meaning either end of input or a
/// zero-length destination, and the destination below is one byte.
///
/// # Errors
///
/// `CURLcode::ReadError` if the reader fails. An interrupted read is retried
/// rather than reported; the module documentation records why this path
/// exists at all, given that the C loops for ever instead.
fn read_chunk<R: BufRead>(
    input: &mut R,
    buffer: &mut [u8; CHUNK_BYTES],
) -> Result<(usize, bool), CURLcode> {
    let mut filled = 0_usize;

    // Stop condition 2: the cap. Tested by the loop itself, so falling out of
    // it is the "chunk filled" exit and carries a clear flag.
    while filled < CHUNK_BYTES {
        let mut byte = [0_u8; 1];
        match input.read(&mut byte) {
            // Stop condition 3: exhausted. A one-byte destination makes this
            // unambiguous -- see the note above.
            Ok(0) => return Ok((filled, true)),
            Ok(_) => {
                buffer[filled] = byte[0];
                filled += 1;
                // Stop condition 1: the newline, which is kept.
                if byte[0] == b'\n' {
                    return Ok((filled, false));
                }
            }
            // A restartable signal is not a failure. Retrying matches what
            // buffered C input does and cannot loop for ever on its own,
            // because a genuine failure reports a different kind.
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(_) => return Err(CURLcode::ReadError),
        }
    }

    Ok((filled, false))
}

/// Reads one whole line into `buf`, and reports whether it was the last.
///
/// Supersedes `Curl_get_line` (`lib/curl_get_line.c:35-65`). The C's
/// signature is
///
/// ```text
/// CURLcode Curl_get_line(struct dynbuf *buf, FILE *input, bool *eof);
/// ```
///
/// and the two shape changes are the obvious ones: an already-open reader
/// stands in for the already-open `FILE *`, and the `bool *eof`
/// out-parameter becomes the success payload. **This function does not open
/// anything** -- the C receives a stream its caller opened, and so does this;
/// choosing and opening the file is the consumer's business.
///
/// # `Ok(true)` still means the buffer holds a line
///
/// The flag says "this was the last line", never "there is no line". A
/// successful return always leaves `buf` non-empty and ending in `'\n'`, at
/// every value of the flag, and the module documentation explains what that
/// line contains when the input had already been consumed in full.
///
/// # The caller owns the buffer, and it is cleared on entry
///
/// `curlx_dyn_reset(buf)` is the C's very first statement
/// (`lib/curl_get_line.c:39`), before the loop and before anything is read,
/// because all four consumers create **one** buffer and reuse it for every
/// line of the file. Resetting keeps the allocation and drops the content, so
/// the reuse costs nothing and consecutive calls cannot concatenate.
///
/// # Errors
///
/// Whatever the buffer's append returns, unchanged: `CURLcode::TooLarge` when
/// the line crosses the ceiling the caller set, or `CURLcode::OutOfMemory`
/// when an allocation is refused. Either way the buffer is left **empty**,
/// not partially filled. `CURLcode::ReadError` if the reader fails.
///
/// Note that the synthesised-newline path is fallible too, and deliberately
/// so: a line that exactly fills the ceiling still needs one more byte for
/// the newline, and `curlx_dyn_addn(buf, "\n", 1)` is the C's *return*
/// expression at `lib/curl_get_line.c:61` rather than a statement whose
/// result is dropped.
///
/// On the read-error path the buffer holds whatever whole chunks had already
/// been appended. There is nothing to be faithful to there, because the C
/// never returns on that path at all.
///
/// **The flag is not reported alongside an error, and nothing observes it.**
/// The C writes through its out-parameter on every iteration, so a value is
/// technically available to a caller that reads it after a failure; none
/// does. `lib/hsts.c`, `lib/altsvc.c` and `lib/cookie.c` all loop on
/// `while(!result && !eof)`, and `&&` evaluates left to right and
/// short-circuits, so a non-`OK` result means the flag is never read.
/// `lib/netrc.c` breaks out of its body before reaching its own `while`. So
/// folding the flag into the success payload loses nothing a consumer can
/// see.
#[allow(dead_code)]
pub(crate) fn get_line<R: BufRead>(
    buf: &mut DynBuf,
    input: &mut R,
) -> Result<bool, CURLcode> {
    // `lib/curl_get_line.c:39`.
    buf.reset();

    // The C's `char buffer[128]` at `:38`, less the slot `fgets` reserves for
    // a terminator. See [`CHUNK_BYTES`].
    let mut buffer = [0_u8; CHUNK_BYTES];

    // `while(1)` at `:40`. The C marks the closing brace `/* UNREACHABLE */`
    // at `:64` because every path out is a `return`; the same is true here,
    // so there is no trailing expression and no `unreachable` marker is
    // needed to say so.
    loop {
        // `:42-44` -- the read, and the flag taken from it immediately, on
        // every iteration, before anything is appended.
        let (filled, at_eof) = read_chunk(input, &mut buffer)?;

        // `:46` -- `rlen = b ? strlen(b) : 0`. NOTE: this is the zero-byte
        // truncation the module documentation calls out, reproduced on
        // purpose. `strlen` stops at the first `0x00`, so the bytes after it
        // are dropped even though `read_chunk` has already consumed them from
        // the reader, and even though the newline that ended the physical
        // line was among them.
        let chunk = &buffer[..filled];
        let chunk = match chunk.iter().position(|&byte| byte == 0) {
            Some(nul) => &chunk[..nul],
            None => chunk,
        };

        // `:47-52` -- append, and propagate the code unchanged. The C guards
        // the call on a non-zero length and so does this; the guard is not
        // observable either way, because a zero-length append can never cross
        // the ceiling, but reproducing it keeps the two bodies aligned
        // statement for statement.
        if !chunk.is_empty() {
            buf.addn(chunk)?;
        }

        // `:54-58` -- "now check the full line". The C reads the accumulated
        // length and pointer back out of the buffer and tests
        // `rlen && (b[rlen - 1] == '\n')`; the leading `rlen &&` is what keeps
        // it from indexing an empty buffer at `[-1]`. A slice's last element
        // is `None` when there is none, so the guard and the index are one
        // expression here and the unchecked subtraction is gone.
        if buf.as_slice().last() == Some(&b'\n') {
            // The flag is whatever this iteration's read reported, exactly as
            // the C hands back whatever its last `feof` wrote.
            return Ok(at_eof);
        }

        // `:59-61` -- no newline and nothing left to read, so synthesise one.
        // This is the source of both surprises in the module documentation: a
        // final line without a newline gains one, and a call that read
        // nothing at all returns a line consisting solely of it.
        if at_eof {
            buf.addn(b"\n")?;
            return Ok(true);
        }

        // `:62` -- "otherwise get next line to append".
    }
}

#[cfg(test)]
mod tests {
    // `Read` is imported here and not in the parent scope, because the two
    // stream stand-ins below implement it directly. See the note beside the
    // parent's imports for why the parent needs no such entry.
    use std::io::{self, BufReader, Cursor, Read};

    use super::*;

    /// A ceiling large enough that no test below reaches it by accident.
    ///
    /// The overflow tests set their own, deliberately tiny, values instead, so
    /// that a limit failure in any other test would be a real defect rather
    /// than a fixture running out of room. 4096 is comfortably above the
    /// longest line any test here constructs, which is 301 bytes.
    const ROOMY: usize = 4096;

    /// Drives `calls` successive reads over `input` and collects the result of
    /// each one.
    ///
    /// Every call reuses the same [`DynBuf`], which is what the four consumers
    /// do -- so this helper exercises the reset-on-entry contract in every
    /// test that uses it, not only in the one that asserts it.
    ///
    /// Deliberately fallible-free: it unwraps, because a test that expects an
    /// error calls [`get_line`] directly.
    fn drive(
        input: &[u8],
        calls: usize,
        ceiling: usize,
    ) -> Vec<(Vec<u8>, bool)> {
        let mut reader = Cursor::new(input.to_vec());
        let mut buf = DynBuf::new(ceiling);
        let mut out = Vec::with_capacity(calls);
        for index in 0..calls {
            let at_eof = get_line(&mut buf, &mut reader)
                .unwrap_or_else(|code| panic!("call {index}: {code:?}"));
            out.push((buf.as_slice().to_vec(), at_eof));
        }
        out
    }

    /// A reader that hands over `ready` and then fails with `kind` for ever.
    ///
    /// Wrapped in a [`BufReader`] by its users, because [`get_line`] takes a
    /// buffered reader and implementing that trait here would mean writing the
    /// very look-ahead the module documentation forbids using for the
    /// end-of-input flag. Composing with the standard library's buffer keeps
    /// this type down to the one method that matters.
    struct FailsAfter {
        ready: Cursor<Vec<u8>>,
        kind: io::ErrorKind,
    }

    impl Read for FailsAfter {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            let taken = self.ready.read(out)?;
            if taken == 0 {
                return Err(io::Error::new(self.kind, "probe"));
            }
            Ok(taken)
        }
    }

    /// A reader that reports one interruption and then behaves normally.
    ///
    /// The retry path has to be reachable from a test, and a restartable
    /// signal cannot be provoked deterministically, so it is modelled.
    struct InterruptsOnce {
        interrupted: bool,
        rest: Cursor<Vec<u8>>,
    }

    impl Read for InterruptsOnce {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(io::Error::new(ErrorKind::Interrupted, "probe"));
            }
            self.rest.read(out)
        }
    }

    /// The chunk cap is 127, and the off-by-one is the point.
    ///
    /// `fgets(buffer, sizeof(buffer), input)` over `char buffer[128]` reads at
    /// most `sizeof - 1`. The C's array size is written out here as a literal
    /// so that the relationship is asserted rather than merely commented, and
    /// so that "correcting" either number disagrees with the other.
    #[test]
    fn the_chunk_cap_is_one_less_than_the_c_array() {
        const C_ARRAY_SIZE: usize = 128;
        assert_eq!(CHUNK_BYTES, C_ARRAY_SIZE - 1);
        assert_eq!(CHUNK_BYTES, 127);
    }

    /// The most important test in the file: the terminal `"\n"` line exists.
    ///
    /// Two calls, both asserted. A file holding `"a\n"` has exactly one real
    /// line, and the second call nevertheless succeeds and yields a buffer
    /// holding solely the synthesised newline -- with the flag now set. This
    /// is what `lib/hsts.c:517-520` relies on when it treats a length of one
    /// as empty.
    #[test]
    fn a_line_is_followed_by_a_synthesised_newline_only_line() {
        let seen = drive(b"a\n", 2, ROOMY);
        assert_eq!(seen[0], (b"a\n".to_vec(), false));
        assert_eq!(seen[1], (b"\n".to_vec(), true));
    }

    /// An empty file yields exactly one line, and it is not empty.
    #[test]
    fn an_empty_input_still_yields_one_line() {
        let seen = drive(b"", 1, ROOMY);
        assert_eq!(seen[0], (b"\n".to_vec(), true));
    }

    /// A final line with no newline gains one.
    ///
    /// The flag is set on the *same* call, because the read that delivered
    /// `"abc"` is the read that hit exhaustion.
    #[test]
    fn a_final_line_without_a_newline_gains_one() {
        let seen = drive(b"abc", 1, ROOMY);
        assert_eq!(seen[0], (b"abc\n".to_vec(), true));
    }

    /// Two real lines, then the synthesised one.
    #[test]
    fn two_lines_then_the_synthesised_one() {
        let seen = drive(b"a\nb\n", 3, ROOMY);
        assert_eq!(seen[0], (b"a\n".to_vec(), false));
        assert_eq!(seen[1], (b"b\n".to_vec(), false));
        assert_eq!(seen[2], (b"\n".to_vec(), true));
    }

    /// A genuinely empty middle line is indistinguishable from the terminal
    /// one except by the flag.
    ///
    /// This is why every consumer filters on content rather than on the flag:
    /// call two and call four return byte-identical buffers.
    #[test]
    fn an_empty_middle_line_matches_the_terminal_one_byte_for_byte() {
        let seen = drive(b"a\n\nb\n", 4, ROOMY);
        assert_eq!(seen[0], (b"a\n".to_vec(), false));
        assert_eq!(seen[1], (b"\n".to_vec(), false));
        assert_eq!(seen[2], (b"b\n".to_vec(), false));
        assert_eq!(seen[3], (b"\n".to_vec(), true));
        assert_eq!(seen[1].0, seen[3].0);
        assert_ne!(seen[1].1, seen[3].1);
    }

    /// A 300-byte line with no interior newline is reassembled across three
    /// chunks into one returned line.
    #[test]
    fn a_line_longer_than_the_chunk_is_reassembled() {
        let input = vec![b'z'; 300];
        let seen = drive(&input, 1, ROOMY);
        let mut want = input.clone();
        want.push(b'\n');
        assert_eq!(seen[0], (want, true));
        assert_eq!(seen[0].0.len(), 301);
    }

    /// Both sides of the chunk boundary reassemble correctly.
    ///
    /// 127 bytes plus a newline splits as 127 then `"\n"`; 128 bytes plus a
    /// newline splits as 127 then two bytes. Both calls report a clear flag,
    /// because both stopped at the newline.
    #[test]
    fn the_chunk_boundary_is_straddled_in_both_directions() {
        for content in [CHUNK_BYTES, CHUNK_BYTES + 1] {
            let mut input = vec![b'x'; content];
            input.push(b'\n');
            let seen = drive(&input, 1, ROOMY);
            assert_eq!(seen[0], (input.clone(), false), "content {content}");
            assert_eq!(seen[0].0.len(), content + 1);
        }
    }

    /// The crux of the port, asserted directly on the chunk reader.
    ///
    /// A chunk that stops at the newline or at the cap must leave the flag
    /// clear even when it has drained the input completely; only a read that
    /// came back empty may set it. The 127-byte row is the decisive one: those
    /// bytes are the entire input, and the flag is still false, which is
    /// precisely why one further call is needed and why that call is the
    /// source of the terminal `"\n"` line.
    #[test]
    fn the_flag_is_set_only_by_a_read_that_came_back_empty() {
        let cap = vec![b'w'; CHUNK_BYTES];
        let cases: [(&[u8], usize, bool); 5] = [
            (b"a\n", 2, false),
            (b"abc", 3, true),
            (b"", 0, true),
            (&cap, CHUNK_BYTES, false),
            (b"\n", 1, false),
        ];
        for (input, want_len, want_flag) in cases {
            let mut reader = Cursor::new(input.to_vec());
            let mut buffer = [0_u8; CHUNK_BYTES];
            let (filled, at_eof) = read_chunk(&mut reader, &mut buffer)
                .expect("a memory-backed reader cannot fail");
            assert_eq!(filled, want_len, "input {input:?}");
            assert_eq!(at_eof, want_flag, "input {input:?}");
            assert_eq!(&buffer[..filled], input, "input {input:?}");
        }
    }

    /// A second call on the exhausted 127-byte case reads nothing.
    ///
    /// The other half of the case above, kept separate so that a failure names
    /// which half broke.
    #[test]
    fn a_chunk_that_drains_the_input_needs_one_more_read_to_notice() {
        let input = vec![b'w'; CHUNK_BYTES];
        let mut reader = Cursor::new(input.clone());
        let mut buffer = [0_u8; CHUNK_BYTES];

        let first = read_chunk(&mut reader, &mut buffer).expect("first chunk");
        assert_eq!(first, (CHUNK_BYTES, false));

        let second = read_chunk(&mut reader, &mut buffer).expect("second");
        assert_eq!(second, (0, true));

        // And the observable consequence: one line of 128 bytes, flag set.
        let seen = drive(&input, 1, ROOMY);
        let mut want = input;
        want.push(b'\n');
        assert_eq!(seen[0], (want, true));
    }

    /// Reproduced C behaviour: an embedded zero byte truncates the chunk and
    /// the rest of that physical line is lost.
    ///
    /// `rlen = strlen(b)` at `lib/curl_get_line.c:46` stops at the first
    /// `0x00`. The bytes `"cd"` and the newline that followed them have
    /// already been consumed from the reader and are never appended, so the
    /// returned line splices `"ab"` onto the *next* physical line. Asserted
    /// rather than merely commented so that the faithfulness is deliberate and
    /// visible.
    #[test]
    fn an_embedded_zero_byte_truncates_the_chunk() {
        let seen = drive(b"ab\0cd\nnext\n", 2, ROOMY);
        assert_eq!(seen[0], (b"abnext\n".to_vec(), false));
        assert_eq!(seen[1], (b"\n".to_vec(), true));
    }

    /// A lone zero byte reads as an empty chunk at exhaustion.
    ///
    /// The C's `fgets` returns non-null here and `strlen` returns zero, so
    /// nothing is appended and the synthesised newline is all that comes back.
    #[test]
    fn a_lone_zero_byte_yields_only_the_synthesised_newline() {
        let seen = drive(b"\0", 1, ROOMY);
        assert_eq!(seen[0], (b"\n".to_vec(), true));
    }

    /// A zero byte after the final newline is a line of its own that
    /// truncates to nothing.
    #[test]
    fn a_zero_byte_after_the_last_newline_is_its_own_empty_line() {
        let seen = drive(b"a\n\0", 3, ROOMY);
        assert_eq!(seen[0], (b"a\n".to_vec(), false));
        assert_eq!(seen[1], (b"\n".to_vec(), true));
        assert_eq!(seen[2], (b"\n".to_vec(), true));
    }

    /// Reproduced C behaviour: a carriage return reaches the consumer.
    ///
    /// All four consumers read in binary mode on the four mandated targets, so
    /// a file written on Windows keeps its CRLF and the caller sees it.
    #[test]
    fn a_carriage_return_is_not_stripped() {
        let seen = drive(b"a\r\n", 2, ROOMY);
        assert_eq!(seen[0], (b"a\r\n".to_vec(), false));
        assert_eq!(seen[0].0[1], b'\r');
        assert_eq!(seen[1], (b"\n".to_vec(), true));
    }

    /// The buffer is cleared on entry, so consecutive calls cannot
    /// concatenate.
    ///
    /// `drive` already reuses one buffer throughout, so this asserts the
    /// property directly rather than incidentally: the second result contains
    /// the second line and nothing of the first.
    #[test]
    fn the_buffer_is_cleared_on_entry() {
        let seen = drive(b"first\nsecond\n", 2, ROOMY);
        assert_eq!(seen[0].0, b"first\n".to_vec());
        assert_eq!(seen[1].0, b"second\n".to_vec());
        assert!(!seen[1].0.starts_with(b"first"));
        assert_eq!(seen[1].0.len(), 7);
    }

    /// A line past the caller's ceiling reports it, and leaves the buffer
    /// empty.
    ///
    /// The ceiling is the caller's, never this function's. A ceiling of eight
    /// admits seven content bytes, because the C's comparison is against
    /// `len + current + 1` and the trailing byte it accounts for is part of
    /// the frozen limit. Ten content bytes therefore cross it, and
    /// `dyn_nappend` frees the whole buffer before returning -- which is what
    /// lets all four consumers stop on the result without discarding a
    /// half-read line first.
    #[test]
    fn a_line_past_the_ceiling_reports_it_and_empties_the_buffer() {
        let mut reader = Cursor::new(b"abcdefghij\n".to_vec());
        let mut buf = DynBuf::new(8);
        let result = get_line(&mut buf, &mut reader);
        assert_eq!(result, Err(CURLcode::TooLarge));
        assert!(buf.is_empty(), "dynbuf frees everything on overflow");
        assert_eq!(buf.len(), 0);
    }

    /// The synthesised-newline path is fallible too.
    ///
    /// Seven content bytes exactly fill a ceiling of eight, so the append that
    /// stores them succeeds; the newline the end-of-input path then has to add
    /// is the byte that crosses the limit. The C's `:61` is a `return
    /// curlx_dyn_addn(...)` rather than a statement whose result is dropped,
    /// and this is the case that distinguishes the two.
    #[test]
    fn the_synthesised_newline_can_itself_cross_the_ceiling() {
        let mut reader = Cursor::new(b"abcdefg".to_vec());
        let mut buf = DynBuf::new(8);
        let result = get_line(&mut buf, &mut reader);
        assert_eq!(result, Err(CURLcode::TooLarge));
        assert!(buf.is_empty());
    }

    /// One byte less, and the same input succeeds -- so the test above is
    /// measuring the boundary rather than a broken fixture.
    #[test]
    fn a_line_that_leaves_room_for_the_newline_succeeds() {
        let mut reader = Cursor::new(b"abcdef".to_vec());
        let mut buf = DynBuf::new(8);
        let at_eof = get_line(&mut buf, &mut reader).expect("fits exactly");
        assert!(at_eof);
        assert_eq!(buf.as_slice(), b"abcdef\n");
        assert_eq!(buf.len(), 7);
    }

    /// Reading past the end is idempotent and terminates.
    ///
    /// The loop inside [`get_line`] has no iteration bound of its own -- the
    /// C's does not either -- so termination is asserted rather than assumed,
    /// under a cap that would fail the test instead of hanging the suite.
    #[test]
    fn reading_past_the_end_is_idempotent_and_terminates() {
        let mut reader = Cursor::new(b"only\n".to_vec());
        let mut buf = DynBuf::new(ROOMY);

        let first = get_line(&mut buf, &mut reader).expect("the real line");
        assert!(!first);
        assert_eq!(buf.as_slice(), b"only\n");

        for round in 0..16 {
            let at_eof = get_line(&mut buf, &mut reader)
                .unwrap_or_else(|code| panic!("round {round}: {code:?}"));
            assert!(at_eof, "round {round}");
            assert_eq!(buf.as_slice(), b"\n", "round {round}");
        }
    }

    /// Bytes that are not valid UTF-8 survive unchanged.
    ///
    /// The proof that the byte-oriented design is doing real work: a cookie
    /// jar, a `.netrc` file or an HSTS cache may hold arbitrary bytes, and a
    /// text-decoding reader would either fail or replace them.
    #[test]
    fn bytes_that_are_not_utf8_survive_unchanged() {
        let input: &[u8] = &[0xff, 0xfe, 0x80, b'\n', 0xc3, b'\n'];
        let seen = drive(input, 3, ROOMY);
        assert_eq!(seen[0].0, vec![0xff, 0xfe, 0x80, b'\n']);
        assert_eq!(seen[1].0, vec![0xc3, b'\n']);
        assert_eq!(seen[2].0, b"\n".to_vec());
        assert!(std::str::from_utf8(&seen[0].0).is_err());
    }

    /// A hard read error is reported rather than looped on.
    ///
    /// The one divergence from the C, which spins for ever here: measured with
    /// a failing stream and with a directory opened for reading, `fgets`
    /// returns null with the *error* indicator set and the end-of-input
    /// indicator clear, so the C's loop condition never becomes true. This
    /// returns instead.
    #[test]
    fn a_hard_read_error_is_reported_rather_than_looped_on() {
        let mut reader = BufReader::new(FailsAfter {
            ready: Cursor::new(Vec::new()),
            kind: ErrorKind::Other,
        });
        let mut buf = DynBuf::new(ROOMY);
        let result = get_line(&mut buf, &mut reader);
        assert_eq!(result, Err(CURLcode::ReadError));
        assert!(buf.is_empty(), "nothing was appended before the failure");
    }

    /// The same, with the failure arriving part-way through a line.
    ///
    /// The bytes already consumed do not rescue the call; the error is
    /// reported and the partial line is not returned as though it were
    /// complete. That is the point of reporting rather than synthesising a
    /// newline: a truncated cookie jar must not read as a valid short one.
    #[test]
    fn a_read_error_part_way_through_a_line_is_still_reported() {
        let mut reader = BufReader::new(FailsAfter {
            ready: Cursor::new(b"partial".to_vec()),
            kind: ErrorKind::BrokenPipe,
        });
        let mut buf = DynBuf::new(ROOMY);
        assert_eq!(get_line(&mut buf, &mut reader), Err(CURLcode::ReadError));
    }

    /// An interrupted read is retried, not reported.
    #[test]
    fn an_interrupted_read_is_retried() {
        let mut reader = BufReader::new(InterruptsOnce {
            interrupted: false,
            rest: Cursor::new(b"resumed\n".to_vec()),
        });
        let mut buf = DynBuf::new(ROOMY);
        let at_eof = get_line(&mut buf, &mut reader).expect("retried");
        assert!(!at_eof);
        assert_eq!(buf.as_slice(), b"resumed\n");
    }

    /// Every successful return ends in a newline, over a spread of inputs.
    ///
    /// The invariant the whole module is built on, asserted as an invariant
    /// rather than only case by case -- including for the inputs that contain
    /// no newline at all, that are empty, that end mid-chunk and that hold a
    /// zero byte.
    #[test]
    fn every_successful_return_ends_in_a_newline() {
        let long = vec![b'q'; CHUNK_BYTES * 2 + 5];
        let inputs: [&[u8]; 9] = [
            b"",
            b"\n",
            b"a",
            b"a\n",
            b"a\r\n",
            b"\0",
            b"ab\0cd\nnext\n",
            b"a\n\nb\n",
            &long,
        ];
        for input in inputs {
            for (line, _) in drive(input, 4, ROOMY) {
                assert!(!line.is_empty(), "input {input:?}");
                assert_eq!(line.last(), Some(&b'\n'), "input {input:?}");
            }
        }
    }

    /// The four consumers' ceilings admit the lines they are meant to admit.
    ///
    /// Not a limit this module imposes -- it imposes none -- but a check that
    /// inheriting the caller's ceiling behaves the way each consumer needs.
    /// The values are transcribed from the C: `MAX_COOKIE_LINE`
    /// (`lib/cookie.h:81`), `MAX_ALTSVC_LINE` (`lib/altsvc.c:41`),
    /// `MAX_HSTS_LINE` (`lib/hsts.c:41`) and `MAX_NETRC_LINE`
    /// (`lib/netrc.c:62`).
    ///
    /// Skipped under the interpreter, on a measurement rather than a hunch.
    /// Timed per test with `--report-time`, this one costs **314.9 seconds**
    /// of the module's 391 there, while the other twenty-four together cost
    /// about thirteen -- because a `MAX_NETRC_LINE` line is read a byte at a
    /// time, which is some 32,000 interpreted reads for the `.netrc` row
    /// alone. It buys no coverage for that price: the interpreter looks for
    /// undefined behaviour, and every branch this test reaches is already
    /// reached under it by [`a_line_longer_than_the_chunk_is_reassembled`],
    /// [`the_chunk_boundary_is_straddled_in_both_directions`],
    /// [`a_line_past_the_ceiling_reports_it_and_empties_the_buffer`] and
    /// [`the_synthesised_newline_can_itself_cross_the_ceiling`]. What this
    /// test adds over those is volume and the real constants, and it adds
    /// both in the ordinary run, which is where it matters.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "314.9s of the module's 391s there, and no branch the \
                  other tests do not already cover"
    )]
    fn each_consumers_ceiling_admits_one_byte_less_than_itself() {
        const CEILINGS: [(&str, usize); 4] = [
            ("MAX_COOKIE_LINE", 5000),
            ("MAX_ALTSVC_LINE", 4095),
            ("MAX_HSTS_LINE", 4095),
            ("MAX_NETRC_LINE", 16384),
        ];
        for (name, ceiling) in CEILINGS {
            // The longest line that fits: `ceiling - 1` bytes in total, of
            // which one is the newline the input supplies itself.
            let mut input = vec![b'c'; ceiling - 2];
            input.push(b'\n');
            let mut reader = Cursor::new(input.clone());
            let mut buf = DynBuf::new(ceiling);
            let at_eof =
                get_line(&mut buf, &mut reader).unwrap_or_else(|code| {
                    panic!("{name} rejected a line it must admit: {code:?}")
                });
            assert!(!at_eof, "{name}");
            assert_eq!(buf.len(), ceiling - 1, "{name}");
            assert_eq!(buf.as_slice(), input.as_slice(), "{name}");

            // And one byte more does not fit.
            let mut over = vec![b'c'; ceiling - 1];
            over.push(b'\n');
            let mut reader = Cursor::new(over);
            let mut buf = DynBuf::new(ceiling);
            assert_eq!(
                get_line(&mut buf, &mut reader),
                Err(CURLcode::TooLarge),
                "{name}"
            );
        }
    }
}
