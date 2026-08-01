// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! Terminal detection and password prompting for the `curl` command-line tool.
//!
//! This module supersedes two C translation units, `src/terminal.c`
//! (87 lines) and `src/tool_getpass.c` (197 lines), and it
//! provides exactly the two capabilities they provided -- report the terminal
//! width, and read a password from the controlling terminal:
//!
//! * `get_terminal_columns` -- from `src/terminal.c:38-86`, declared in C as
//!   `unsigned int get_terminal_columns(void);` at `src/terminal.h:28`.
//! * `getpass_r` -- from `src/tool_getpass.c:164-193`, whose header contract at
//!   `src/tool_getpass.h:32-35` reads "Returning NULL will abort the continued
//!   operation!". The POSIX implementation never returns `NULL`, so the abort
//!   outcome is made unrepresentable here rather than merely unused.
//!
//! Only ~70 of `src/tool_getpass.c`'s 197 lines are in scope. The `__VMS` arm
//! (`:54-86`), the `_WIN32` `_getch` arm with its backspace handling
//! (`:88-114`), the `__AMIGA__` adjustment (`:26-28`) and the legacy System-V
//! `HAVE_TERMIO_H` `ioctl(TCGETA/TCSETA)` arm all fall outside the
//! four-target matrix (Linux and macOS on x86_64 and aarch64), and none of
//! them is reproduced.
//!
//! # Who depends on the width
//!
//! Three call sites consume `get_terminal_columns`, and all three are frozen
//! output surfaces -- migration targets, not design decisions:
//!
//! * `src/tool_help.c:227` -- `--help` text wrapping.
//! * `src/tool_cb_prg.c:112`, inside `update_width()` -- the progress-bar
//!   width. That function clamps to `MAX_BARLENGTH` 400 / `MIN_BARLENGTH` 20
//!   (`src/tool_cb_prg.c:31-32`); the clamping belongs to the progress
//!   callback, not here, but it is why a wrong width is not merely cosmetic.
//! * `src/tool_msgs.c:42`, inside `voutf()` -- warning and error wrapping.
//!
//! `getpass_r` has exactly one consumer: `src/tool_paramhlp.c:586`. The two
//! prompt strings it builds at `src/tool_paramhlp.c:575-583` are frozen CLI
//! output and belong to `curl-rs/src/cli/paramhlp.rs`, **not** to this module --
//! including the 1-based `i + 1` URL index in the second form. This module
//! therefore accepts an arbitrary prompt and never composes one.
//!
//! The prompt is taken as **bytes**, not as a `&str`. C holds it in a
//! `char prompt[256]` and emits it with `fputs` (`src/tool_getpass.c:176`),
//! and its `%s` conversion at `src/tool_paramhlp.c:582` renders a username
//! that need not be valid UTF-8 -- an operating-system credential is a byte
//! string. Accepting `&str` would force the caller to convert lossily and put
//! U+FFFD on the terminal where C puts the user's own bytes, which the
//! preservation mandate rules out. Nothing is decoded here: the bytes given
//! are the bytes written.
//!
//! # Both operating-system capabilities, reached without `unsafe`
//!
//! `#![forbid(unsafe_code)]` on `curl-rs/src/main.rs` covers this module, and
//! this crate has no `mod ffi`, so it carries no `#[allow(unsafe_code)]`
//! anywhere; `src/bin/curlinfo.rs` and `build.rs` carry the same literal
//! `forbid`. Two branches of the C originals need raw libc calls, and both
//! arrive here through the narrow safe facade `curl-rs-lib` re-exports at its
//! crate root -- the surface reserved for genuine operating-system residue.
//! No `unsafe` appears in this crate, no dependency was added, and neither
//! capability is approximated.
//!
//! ## Terminal width -- [`curl_rs_lib::terminal_columns`]
//!
//! `src/terminal.c:54-82` probes the kernel with
//! `ioctl(STDIN_FILENO, TIOCGSIZE|TIOCGWINSZ, &ts)` at `:59`/`:63`. The engine
//! wrapper performs exactly that call, on exactly that descriptor, and returns
//! the raw `ws_col` or `None`. Everything C does with the answer -- the
//! `cols < 10000` acceptance test at `:80` and the 79 fallback at `:83-84` --
//! stays here in [`columns_from_parts`], because it is CLI policy rather than
//! an operating-system detail.
//!
//! Two details of C's control flow are easy to get wrong and are reproduced
//! deliberately. The probe sits inside `if(!width)` at `:54`, so a usable
//! `COLUMNS` short-circuits it and the kernel is never asked. The probe
//! path carries **no** `> 20` lower bound; that gate belongs to the `COLUMNS`
//! path alone, so a terminal genuinely five columns wide reports five.
//!
//! The descriptor is **`STDIN_FILENO`**, not stdout or stderr, which is why
//! this is invisible under `tests/runtests.pl`: the harness invokes curl
//! non-interactively with stdin redirected, so the `ioctl` fails in the C build
//! too and both implementations fall to 79. Confirmed against the real curl
//! 8.19.0-DEV binary -- stdin from `/dev/null`, `COLUMNS` unset, `--help`
//! wrapping at 79.
//!
//! ## Password echo suppression -- [`curl_rs_lib::disable_echo`]
//!
//! `ttyecho()` at `src/tool_getpass.c:126-162` clears the `ECHO` bit with
//! `tcgetattr`/`tcsetattr`, with the asymmetry `TCSANOW` when disabling
//! (`:139`) against `TCSAFLUSH` when restoring (`:155`). The engine wrapper
//! preserves that asymmetry and hands back an RAII guard, so the restore runs
//! on the normal path, on an early return and on an unwind alike.
//!
//! Two observable details ride on that guard rather than on this module.
//! `EchoGuard::echo_disabled` reports `true` unconditionally, because
//! `src/tool_getpass.c:148` returns `TRUE` once it has taken the
//! `HAVE_TERMIOS_H` branch, having discarded the result of both `tcgetattr` and
//! `tcsetattr` -- so the extra newline at `:185` is emitted even when standard
//! input is redirected and `tcgetattr` fails, which is precisely the case
//! `tests/runtests.pl` produces. The guard is then restored explicitly after
//! the newline is written, not left to fall out of scope, because `:183-186`
//! fixes that order.
//!
//! Two further details of the port are easy to get wrong and are therefore
//! explicit:
//!
//! * **The restore writes back only what was successfully saved.** C would
//!   write an all-zero `struct termios` when the save had failed, because
//!   `:129-130` are zero-initialised function static variables; that is
//!   harmless upstream only because a failed save implies a descriptor the
//!   restore also fails on. `SavedTerminal` represents "nothing was captured"
//!   explicitly and skips the restore, which is identical on every input
//!   where C's behaviour is defined and avoids a destructive terminal reset
//!   where it is not.
//! * **"Echo is reported disabled" and "attributes were saved" are two
//!   questions.** `EchoGuard::echo_disabled` answers the first
//!   unconditionally, as C does; `SavedTerminal::is_restorable` answers the
//!   second, and it is the one the restore keys off.
//!
//! The `__VMS`, `_WIN32` and legacy System-V `HAVE_TERMIO_H` arms remain
//! excluded by the four-target matrix, as does the `#else` arm at `:145-149`
//! where neither header exists; neither mandated target selects it.
//!
//! That newline is also unobservable to the fixture corpus, which is worth
//! recording so nobody looks for it there: 21 fixtures pass a colon-less
//! `-u`/`-U`, and not one of them carries a `<stderr>` block, so nothing the
//! prompt path writes is compared.

use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::AsFd;

/// Width reported when nothing better is known: `src/terminal.c:83-84`.
///
/// `src/terminal.c:85` comments the return value as "79 for unknown, might also
/// be tiny or enormous", so no clamping beyond C's own is applied anywhere in
/// this module.
const FALLBACK_COLUMNS: u32 = 79;

/// Upper bound handed to `curlx_str_number` at `src/terminal.c:49`.
///
/// The parser rejects any value that would exceed it, so 10000 is accepted and
/// 10001 is not.
const COLUMNS_MAX: u32 = 10_000;

/// Exclusive lower bound from the `(num > 20)` test at `src/terminal.c:49`.
///
/// Combined with `COLUMNS_MAX` the accepted range is 21..=10000 inclusive;
/// exactly 20 is rejected.
///
/// It gates the `COLUMNS` path **only**. The `ioctl` path has no lower bound
/// at all -- see [`IOCTL_COLUMNS_MAX_EXCLUSIVE`].
const COLUMNS_MIN_EXCLUSIVE: u32 = 20;

/// Exclusive upper bound from the `(cols < 10000)` test at `src/terminal.c:80`.
///
/// The same number as [`COLUMNS_MAX`], written separately because C writes it
/// separately and the two bounds are **not** the same test:
///
/// * `COLUMNS_MAX` is the `max` argument of `curlx_str_number` at `:49`, which
///   is INCLUSIVE, so `COLUMNS=10000` yields a width of 10000.
/// * This one is the `cols < 10000` half of `:80`, which is EXCLUSIVE, so an
///   `ioctl` reporting exactly 10000 is rejected and the width falls to 79.
///
/// The asymmetry is C's and is preserved rather than tidied away. The `cols >=
/// 0` half of `:80` has no counterpart here: `ws_col` is an `unsigned short`
/// widened to `int`, so it can never be negative, as the engine wrapper's own
/// documentation records.
const IOCTL_COLUMNS_MAX_EXCLUSIVE: u32 = 10_000;

/// The environment variable consulted at `src/terminal.c:45`.
const COLUMNS_ENV: &str = "COLUMNS";

/// Radix used by `curlx_str_number`, which is `str_num_base(..., 10)`.
const NUMBER_BASE: u32 = 10;

/// Terminal opened by `getpass_r` at `src/tool_getpass.c:170`.
#[allow(dead_code)]
const TTY_PATH: &str = "/dev/tty";

/// Value of an ASCII decimal digit, or `None` for every other byte.
///
/// This is `valid_digit(x, '9')` from `lib/curlx/strparse.c:142-143` combined
/// with `curlx_hexval` from `lib/curlx/strparse.h:111`. The C macro is
/// `((x) >= '0') && ((x) <= '9') && curlx_hexasciitable[(x) - '0']`, and the
/// table at `lib/curlx/strparse.c:148-154` is non-zero for every one of
/// `'0'..='9'`, so the C predicate reduces exactly to "is an ASCII decimal
/// digit".
///
/// The reduction holds for all 256 byte values, including those above 0x7f.
/// `char` is signed on all four targets in the matrix, so a byte such as 0xff
/// is read as a negative value, fails `(x) >= '0'`, and is rejected -- the same
/// answer `u8::is_ascii_digit` gives. Verified by measurement: with
/// `COLUMNS` set to the bytes `\xff`, C yields the 79 fallback.
fn decimal_digit_value(byte: u8) -> Option<u32> {
    if byte.is_ascii_digit() {
        Some(u32::from(byte - b'0'))
    } else {
        None
    }
}

/// Parses a leading run of ASCII decimal digits, bounded by `COLUMNS_MAX`.
///
/// Faithful port of `str_num_base` from `lib/curlx/strparse.c`, which
/// `curlx_str_number` calls with base 10 and which `src/terminal.c:49` calls
/// with `max` 10000. Three properties of the C function are load-bearing and
/// are reproduced exactly:
///
/// 1. The **first** byte must be a digit. If it is not, C returns `STRE_NO_NUM`
///    before entering its loop, so a leading sign, leading whitespace or an
///    empty value is rejected. `+80` and `" 80"` both fall back to 79.
/// 2. Trailing non-digit bytes are **accepted, not rejected**. C stops at the
///    first non-digit, stores the accumulated value, advances the caller's
///    pointer and returns `STRE_OK`; there is no end-of-string check anywhere
///    in the function. `80x` therefore parses as 80.
/// 3. The overflow guard `num > ((max - n) / base)` is evaluated **before** the
///    accumulation, which both matches C's rejection point and makes the
///    accumulator provably unable to exceed `max` or to wrap.
///
/// Property 2 deserves emphasis because it is easy to assume the opposite. It
/// was verified three independent ways: by reading `str_num_base`, by running a
/// verbatim C transcription of it, and by running the real curl 8.19.0-DEV
/// binary, whose `--help` output wraps identically at 80 for `COLUMNS=80` and
/// for `COLUMNS=80x` while falling back to 79 for a genuinely rejected value
/// such as `+80`. Rust's `str::parse::<u64>()` matches C on neither point: it
/// rejects `80x` and it accepts a leading `+`. It is deliberately not used.
///
/// Returns the parsed value on C's `STRE_OK`, or `None` for C's `STRE_NO_NUM`
/// and `STRE_OVERFLOW`, which `src/terminal.c:49` treats identically.
fn parse_columns_digit_prefix(bytes: &[u8]) -> Option<u32> {
    let mut num: u32 = 0;
    let mut digits: usize = 0;

    for &byte in bytes {
        let digit = match decimal_digit_value(byte) {
            Some(digit) => digit,
            // C leaves its `do {} while(valid_digit(...))` loop here. Having
            // consumed at least one digit it reports STRE_OK and ignores the
            // rest of the string; having consumed none it reported STRE_NO_NUM
            // before the loop, which the `digits == 0` check below reproduces.
            None => break,
        };

        // `if(num > ((max - n) / base)) return STRE_OVERFLOW;`
        // `COLUMNS_MAX` is 10000 and `digit` is at most 9, so the subtraction
        // cannot underflow, and the guard bounds `num` by `COLUMNS_MAX`, so the
        // multiply-add below cannot overflow a u32.
        if num > (COLUMNS_MAX - digit) / NUMBER_BASE {
            return None;
        }
        num = num * NUMBER_BASE + digit;
        digits += 1;
    }

    if digits == 0 {
        return None;
    }
    Some(num)
}

/// Resolves the terminal width from a `COLUMNS` value and an `ioctl` result.
///
/// Split out from `get_terminal_columns` so that both inputs are injectable:
/// the caller supplies the raw environment bytes, or `None` when the variable
/// is unset, and the probed column count, or `None` when the probe failed.
/// Every width case can then be tested without mutating process-global state
/// or owning a terminal, neither of which a parallel test runner can offer.
///
/// `value` carries **raw bytes** rather than a `&str` deliberately. C reads the
/// variable with `curl_getenv` (`src/terminal.c:45`) and parses whatever bytes
/// come back, so a value that is not valid UTF-8 still yields a width whenever
/// it begins with digits: measured, `COLUMNS` set to the bytes `80\xff` gives 80
/// in C. `std::env::var` cannot express that, because it fails outright on
/// non-UTF-8; `std::env::var_os` can, and it also removes any possibility of a
/// panic on such a value.
///
/// The three stages are C's three stages, in C's order, including the detail
/// that the second is reached **only** when the first produced nothing.
fn columns_from_parts(value: Option<&[u8]>, probe: Option<u32>) -> u32 {
    // Stage 1 -- `src/terminal.c:44-52`. A value is used only if it parses and
    // is strictly greater than 20.
    let mut width: u32 = match value.and_then(parse_columns_digit_prefix) {
        Some(num) if num > COLUMNS_MIN_EXCLUSIVE => num,
        _ => 0,
    };

    // Stage 2 -- `src/terminal.c:54-82`, the `ioctl(STDIN_FILENO, TIOCGWINSZ)`
    // probe, reached through the engine's safe wrapper.
    //
    // THE GUARD IS PART OF THE CONTRACT. `:54` is `if(!width) {`, so a usable
    // `COLUMNS` short-circuits the probe entirely and the kernel is never
    // asked. Running the probe unconditionally would let a real terminal
    // override an explicit `COLUMNS`, which is a behaviour change in the one
    // direction users notice.
    if width == 0 {
        // `int cols = 0;` at `:55`. A failed `ioctl` leaves the initialiser in
        // place, which is why the failure collapses to zero here rather than
        // skipping the test below: C evaluates `:80` either way.
        let cols = probe.unwrap_or(0);

        // `if(cols >= 0 && cols < 10000) width = (unsigned int)cols;` at
        // `:80-81`. Note what is NOT here: the `> 20` gate of stage 1. A
        // terminal genuinely 5 columns wide reports 5, and C honours it.
        // Zero satisfies the test too and assigns a `width` that is already
        // zero, so stage 3 still supplies the fallback.
        if cols < IOCTL_COLUMNS_MAX_EXCLUSIVE {
            width = cols;
        }
    }

    // Stage 3 -- `src/terminal.c:83-84`. Any failure above lands here.
    if width == 0 {
        width = FALLBACK_COLUMNS;
    }
    width
}

/// Returns the number of columns in the current terminal.
///
/// Port of `get_terminal_columns` (`src/terminal.c:38-86`), declared at
/// `src/terminal.h:28`. The C doc comment at `src/terminal.c:39-40` states the
/// contract this preserves: "get_terminal_columns() returns the number of
/// columns in the current terminal. It will return 79 on failure. Also, the
/// number can be big."
///
/// The result is `u32` to match C's `unsigned int`. This function cannot fail
/// and cannot panic, so it returns a plain value rather than a `Result` --
/// C has no failure channel here either.
///
/// Both of C's sources are consulted, in C's order: `COLUMNS` first, and the
/// `ioctl(STDIN_FILENO, TIOCGWINSZ)` probe only if that yielded nothing. The
/// probe arrives through [`curl_rs_lib::terminal_columns`], the engine's safe
/// wrapper; the `< 10000` acceptance test and the 79 fallback stay here,
/// because they are CLI policy rather than an operating-system detail.
pub(crate) fn get_terminal_columns() -> u32 {
    let value = std::env::var_os(COLUMNS_ENV);
    columns_from_parts(
        value.as_deref().map(OsStr::as_encoded_bytes),
        curl_rs_lib::terminal_columns(),
    )
}

/// Prompts on `err_sink`, then reads one password from `input`.
///
/// Port of the body of `getpass_r` (`src/tool_getpass.c:176-187`), with the
/// descriptor, the error stream and the echo state injected so that every branch
/// is testable. The steps map one-to-one onto the C:
///
/// * `:176` `fputs(prompt, tool_stderr)` -- the prompt goes to the **error**
///   stream, never to stdout, and carries no newline of its own. It is written
///   as raw bytes, matching `fputs`, and then flushed so it is visible before
///   the read blocks.
/// * `:177` `nread = read(fd, buffer, buflen)` -- a **single** read of at most
///   `max_len` bytes. Not a read-to-end and not a line read: C performs exactly
///   one `read(2)`, and reproducing that is what keeps the amount consumed from
///   the descriptor faithful.
/// * `:179` `buffer[--nread] = '\0'` -- the **last byte read is discarded**, on
///   the assumption it is the newline. This is reproduced exactly, including the
///   case where the read filled the buffer and no newline was present: C
///   discards the final byte there too. Stripping only a genuine newline would
///   be a behaviour change, which the preservation mandate forbids.
/// * `:181` `buffer[0] = '\0'` -- a read of zero bytes, or a failed read, yields
///   the empty password. C ignores the distinction between end-of-input and
///   error because both leave `nread <= 0`, so a read error maps to empty here
///   rather than propagating.
/// * `:183-187` -- the extra newline is emitted **only** when echo was actually
///   disabled. That guard is the single most important conditional in the
///   function, and it is the one place the echo state is observable in output.
///
/// `echo_disabled` is a parameter rather than a value derived here so that both
/// arms of the `:183` guard exist and are verified by the tests below.
/// It also keeps this function free of any platform call, which is what lets
/// the tests drive it over an in-memory reader and writer.
/// [`getpass_r`] supplies it from `EchoGuard::echo_disabled`, which reports
/// `true` on both mandated platforms for the reason recorded in the module
/// documentation. This function reproduces only the newline half of
/// `:183-187`; the restore half, `ttyecho(TRUE, fd)` at `:186`, belongs to the
/// guard and is invoked by [`getpass_r`] immediately after this returns, which
/// is what keeps the two in C's order.
///
/// `prompt` is **raw bytes**, matching `fputs(prompt, tool_stderr)` on a
/// `const char *`. It is not a `&str` because the sole composer,
/// `src/tool_paramhlp.c:580-587`, interpolates a username taken from the
/// command line with `%s`, and an argument is an arbitrary byte string on the
/// mandated targets. Rendering it through [`String::from_utf8_lossy`] would
/// substitute U+FFFD and change the bytes the terminal receives, which AAP
/// section 0.8.1 does not permit.
///
/// Returns the password as raw bytes. `Vec<u8>` rather than `String` because C
/// stores raw bytes in a `char` buffer, so a password that is not valid UTF-8
/// must round-trip without panicking. Callers convert as they need. One C-side
/// consequence worth recording for `cli/paramhlp.rs`: the C caller formats the
/// result with `"%s"` (`src/tool_paramhlp.c:590`), which truncates at an
/// embedded NUL byte. That truncation is a property of the caller's C string
/// formatting, not of `getpass_r`, which returns every byte it kept.
#[allow(dead_code)]
fn read_password_into(
    prompt: &[u8],
    max_len: usize,
    input: &mut dyn Read,
    err_sink: &mut dyn Write,
    echo_disabled: bool,
) -> Vec<u8> {
    // `:176`. C ignores whether `fputs` succeeded, so write errors are dropped
    // rather than reported; a failure to render the prompt must not prevent the
    // read, and there is no channel on which to report it.
    let _ = err_sink.write_all(prompt);
    let _ = err_sink.flush();

    // `:177`. One read, at most `max_len` bytes.
    //
    // `max_len == 0` is the one place this module declines to mirror C. There,
    // `read(fd, buffer, 0)` returns 0 and `:181` writes `buffer[0] = '\0'` into
    // a zero-length buffer, which is undefined behaviour. The sole caller never
    // does it -- `src/tool_paramhlp.c:567` declares `char passwd[2048]` -- and
    // undefined behaviour is not an observable behaviour worth preserving, so
    // an empty password is returned instead.
    let mut buffer = vec![0u8; max_len];
    // C's `read` returns -1 on error, which fails the `nread > 0` test at `:178`
    // and lands in the `else` at `:180-181`. Collapsing a failed read to zero
    // bytes read is exactly that behaviour, so the error is intentionally
    // discarded rather than propagated.
    let nread = input.read(&mut buffer).unwrap_or_default();

    if nread > 0 {
        // `:179` -- drop the last byte read.
        buffer.truncate(nread - 1);
    } else {
        // `:181` -- got nothing.
        buffer.clear();
    }

    // `:183-185` -- only if echo really was disabled.
    if echo_disabled {
        let _ = err_sink.write_all(b"\n");
        let _ = err_sink.flush();
    }

    buffer
}

/// Reads a password from the controlling terminal without displaying it.
///
/// Port of `getpass_r` (`src/tool_getpass.c:164-193`). `prompt` is written to
/// standard error and `max_len` bounds the read exactly as C's `buflen` does;
/// the sole C caller passes `sizeof(passwd)` for a `char passwd[2048]`
/// (`src/tool_paramhlp.c:567`, `:586`), so 2048 is the bound in practice. The
/// password is truncated at that bound rather than grown without limit.
///
/// The prompt is a parameter, is taken as bytes and is never composed here.
/// The two strings the C caller builds at `src/tool_paramhlp.c:575-583` are
/// frozen CLI output and belong to `curl-rs/src/cli/paramhlp.rs`; one of them
/// interpolates a username that need not be valid UTF-8, which is why the
/// parameter is `&[u8]`. That includes their 256-byte buffer bound: the
/// truncation is the composer's, not this function's.
///
/// Returns the password as raw bytes, always. C's contract at
/// `src/tool_getpass.h:32-35` warns that "Returning NULL will abort the
/// continued operation!", and the POSIX implementation at `:192` returns the
/// buffer on every path, so there is no abort outcome to represent: this
/// signature makes that outcome unrepresentable rather than merely unused. An
/// unreadable terminal, a failed read and an immediate end-of-input all yield an
/// empty password, matching `:181`.
///
/// Echo is suppressed for the duration of the read through
/// [`curl_rs_lib::disable_echo`], whose guard restores the saved terminal
/// attributes on the normal path, on an early return and on an unwind.
///
/// # The order of the last three steps is C's order
///
/// `src/tool_getpass.c:183-186` writes the newline **before** re-enabling echo:
///
/// ```text
/// if(disabled) {
///   fputs("\n", tool_stderr);
///   (void)ttyecho(TRUE, fd);
/// }
/// ```
///
/// [`read_password_into`] writes that newline, so the guard is restored
/// explicitly after it returns rather than being left to fall out of scope.
/// `Drop` remains the unwind safety net and does nothing a second time.
pub(crate) fn getpass_r(prompt: &[u8], max_len: usize) -> Vec<u8> {
    let mut err_sink = io::stderr();

    // `:170-172` -- open the terminal read-only, and on any failure fall back to
    // standard input. The error is deliberately not propagated: C only checks
    // for `-1` and substitutes `STDIN_FILENO`.
    match File::open(TTY_PATH) {
        Ok(tty) => {
            // `:174` -- `disabled = ttyecho(FALSE, fd);` on the SAME descriptor
            // the password is then read from, which is why the guard is taken
            // here rather than once outside the match.
            let guard = curl_rs_lib::disable_echo(tty.as_fd());
            let echo_disabled = guard.echo_disabled();

            // `impl Read for &File` lets the read borrow the file immutably, so
            // it coexists with the immutable borrow `as_fd()` already handed to
            // the guard. Taking `&mut tty` instead would conflict with it, and
            // the alternative -- rebuilding the descriptor with
            // `File::from_raw_fd` -- is `unsafe` and unavailable in this crate.
            let mut reader = &tty;
            let password = read_password_into(
                prompt,
                max_len,
                &mut reader,
                &mut err_sink,
                echo_disabled,
            );

            // `:186`, after the newline `read_password_into` has just written.
            guard.restore();

            // The `File` is dropped when this arm ends, closing the descriptor.
            // That is `:189-190`, `if(STDIN_FILENO != fd) curlx_close(fd);`.
            // It is dropped after the guard has restored, so the attributes are
            // written while the descriptor is still open.
            password
        }
        Err(_) => {
            // The stdin branch of `:189` closes nothing, and `StdinLock` upholds
            // that structurally: dropping it never closes descriptor 0, so the
            // guard C needs cannot be forgotten here.
            //
            // One honest consequence of using `std` only: `io::stdin` is
            // buffered, whereas C reads descriptor 0 unbuffered. A single read
            // may therefore pull more bytes out of the operating system into
            // std's buffer than C would. Reading descriptor 0 unbuffered needs
            // `File::from_raw_fd`, which is `unsafe` and so unavailable here.
            // The effect is confined to the case where `/dev/tty` cannot be
            // opened *and* standard input is also a data source, and even then
            // the surplus bytes are not lost: they stay reachable through
            // `io::stdin` for the rest of this process.
            let stdin = io::stdin();

            // `:174` again, now on `STDIN_FILENO` -- the descriptor C
            // substituted at `:172`. `Stdin::lock` borrows `&self` and yields a
            // `StdinLock<'static>`, so it coexists with the `as_fd()` borrow.
            let guard = curl_rs_lib::disable_echo(stdin.as_fd());
            let echo_disabled = guard.echo_disabled();

            let mut locked = stdin.lock();
            let password = read_password_into(
                prompt,
                max_len,
                &mut locked,
                &mut err_sink,
                echo_disabled,
            );

            guard.restore();
            password
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bound the sole C caller passes: `char passwd[2048]`
    /// (`src/tool_paramhlp.c:567`, `:586`).
    const CALLER_MAX_LEN: usize = 2048;

    /// A reader whose every read fails, exercising C's `read` returning -1.
    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("simulated read failure"))
        }
    }

    /// A writer whose every write fails, proving the prompt path tolerates a
    /// broken error stream exactly as C tolerates a failing `fputs`.
    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "simulated write failure",
            ))
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "simulated flush failure",
            ))
        }
    }

    /// Drives the injectable core over a byte slice, returning the password and
    /// everything written to the captured error stream.
    fn run_password(
        prompt: &[u8],
        max_len: usize,
        input: &[u8],
        echo_disabled: bool,
    ) -> (Vec<u8>, Vec<u8>) {
        let mut reader = input;
        let mut sink: Vec<u8> = Vec::new();
        let password = read_password_into(
            prompt,
            max_len,
            &mut reader,
            &mut sink,
            echo_disabled,
        );
        (password, sink)
    }

    /// Convenience wrapper for the width seam.
    ///
    /// The probe is `None` -- a failed `ioctl`, which is what
    /// `tests/runtests.pl` produces by redirecting standard input -- so every
    /// case reached through this helper isolates the `COLUMNS` path. The probe
    /// path has its own tests below.
    fn width(value: &[u8]) -> u32 {
        columns_from_parts(Some(value), None)
    }

    #[test]
    fn columns_accepts_the_documented_range() {
        // The accepted range is 21..=10000 inclusive: `curlx_str_number` caps at
        // 10000 and `src/terminal.c:49` additionally demands `num > 20`.
        assert_eq!(width(b"80"), 80);
        assert_eq!(width(b"21"), 21);
        assert_eq!(width(b"10000"), 10_000);
        assert_eq!(width(b"9999"), 9999);
    }

    #[test]
    fn columns_rejects_out_of_range_values() {
        // Exactly 20 fails `num > 20`; 0 fails it too; 10001 overflows the cap.
        assert_eq!(width(b"20"), FALLBACK_COLUMNS);
        assert_eq!(width(b"0"), FALLBACK_COLUMNS);
        assert_eq!(width(b"10001"), FALLBACK_COLUMNS);
        // Far beyond any integer bound: C returns STRE_OVERFLOW and the guard
        // here returns None, so nothing wraps and nothing panics.
        assert_eq!(width(b"9999999999999999999999"), FALLBACK_COLUMNS);
    }

    #[test]
    fn columns_falls_back_when_absent_or_empty() {
        assert_eq!(columns_from_parts(None, None), FALLBACK_COLUMNS);
        assert_eq!(width(b""), FALLBACK_COLUMNS);
    }

    #[test]
    fn columns_accepts_a_digit_prefix_and_ignores_trailing_bytes() {
        // `str_num_base` has no end-of-string check: it stops at the first
        // non-digit, stores what it accumulated and returns STRE_OK. Verified
        // against the real curl 8.19.0-DEV binary, whose --help wraps at 80 for
        // COLUMNS=80x exactly as it does for COLUMNS=80.
        assert_eq!(width(b"80x"), 80);
        assert_eq!(width(b"80 "), 80);
        assert_eq!(width(b"3.14"), FALLBACK_COLUMNS); // 3 parses, 3 is not > 20
        assert_eq!(width(b"1e3"), FALLBACK_COLUMNS); // 1 parses, 1 is not > 20
        assert_eq!(width(b"8_0"), FALLBACK_COLUMNS); // 8 parses, 8 is not > 20
        assert_eq!(width(b"20x"), FALLBACK_COLUMNS); // 20 parses, not > 20
    }

    #[test]
    fn columns_requires_the_first_byte_to_be_a_digit() {
        // A leading sign or space is not a digit, so C returns STRE_NO_NUM
        // before its loop. Rust's `str::parse::<u64>()` would accept `+80`,
        // which is precisely why it is not used here.
        assert_eq!(width(b"+80"), FALLBACK_COLUMNS);
        assert_eq!(width(b"-5"), FALLBACK_COLUMNS);
        assert_eq!(width(b"  80"), FALLBACK_COLUMNS);
        assert_eq!(width(b"\t80"), FALLBACK_COLUMNS);
    }

    #[test]
    fn columns_accepts_leading_zeros() {
        assert_eq!(width(b"0080"), 80);
        assert_eq!(width(b"00000021"), 21);
    }

    #[test]
    fn columns_handles_non_utf8_without_panicking() {
        // Raw bytes are parsed, so a digit prefix still counts even when the
        // value as a whole is not valid UTF-8. Measured against the C parser:
        // `80\xff` yields 80 and `\xff80` yields the fallback, because `char` is
        // signed on every target in the matrix so 0xff fails `(x) >= '0'`.
        assert_eq!(width(b"80\xff"), 80);
        assert_eq!(width(b"\xff80"), FALLBACK_COLUMNS);
        assert_eq!(width(b"\xff"), FALLBACK_COLUMNS);
        assert_eq!(width(&[0xff, 0xfe, 0x00, 0x38, 0x30]), FALLBACK_COLUMNS);
    }

    #[test]
    fn columns_never_panics_and_always_returns_a_usable_width() {
        // Every single byte value, then a spread of awkward multi-byte values.
        for byte in 0u8..=255 {
            let got = columns_from_parts(Some(&[byte]), None);
            assert!(
                got == FALLBACK_COLUMNS || (21..=10_000).contains(&got),
                "byte {byte:#04x} produced an out-of-contract width {got}"
            );
        }

        let awkward: [&[u8]; 12] = [
            b"",
            b"\0",
            b"99\0999",
            b"000000000000000000000000000000",
            b"2147483648",
            b"4294967296",
            b"18446744073709551616",
            b"10000000000000000000000000000000",
            b"21\n",
            b"\n21",
            b"0000000000000000000000000000021",
            &[0x80, 0x81, 0x82, 0x83],
        ];
        for value in awkward {
            let got = columns_from_parts(Some(value), None);
            assert!(
                got == FALLBACK_COLUMNS || (21..=10_000).contains(&got),
                "value {value:?} produced an out-of-contract width {got}"
            );
        }
    }

    #[test]
    fn columns_boundary_of_the_overflow_guard() {
        // 10000 is the largest accepted value and every longer digit run above
        // it is rejected, which pins the `num > ((max - n) / base)` guard.
        assert_eq!(width(b"10000"), 10_000);
        assert_eq!(width(b"10001"), FALLBACK_COLUMNS);
        assert_eq!(width(b"100000"), FALLBACK_COLUMNS);
        assert_eq!(parse_columns_digit_prefix(b"10000"), Some(10_000));
        assert_eq!(parse_columns_digit_prefix(b"10001"), None);
        assert_eq!(parse_columns_digit_prefix(b"0"), Some(0));
        assert_eq!(parse_columns_digit_prefix(b""), None);
    }

    /// `src/terminal.c:54` guards the probe with `if(!width)`, so a usable
    /// `COLUMNS` must win outright and the kernel must not be consulted.
    #[test]
    fn a_usable_columns_short_circuits_the_probe() {
        assert_eq!(columns_from_parts(Some(b"80"), Some(120)), 80);
        assert_eq!(columns_from_parts(Some(b"21"), Some(9999)), 21);
        // A trailing-garbage value is still usable, so it still short-circuits.
        assert_eq!(columns_from_parts(Some(b"80x"), Some(120)), 80);
    }

    /// When `COLUMNS` yields nothing the probe supplies the width, which is the
    /// whole point of `src/terminal.c:54-82`.
    #[test]
    fn the_probe_supplies_the_width_when_columns_does_not() {
        for value in [None, Some(&b""[..]), Some(&b"20"[..]), Some(&b"x"[..])] {
            assert_eq!(
                columns_from_parts(value, Some(120)),
                120,
                "an unusable COLUMNS {value:?} must defer to the probe"
            );
        }
    }

    /// The probe path carries NO lower bound. `src/terminal.c:80` tests only
    /// `cols >= 0 && cols < 10000`; the `> 20` gate at `:49` belongs to the
    /// `COLUMNS` path alone, so a genuinely narrow terminal is honoured.
    #[test]
    fn the_probe_path_has_no_lower_bound() {
        assert_eq!(columns_from_parts(None, Some(5)), 5);
        assert_eq!(columns_from_parts(None, Some(1)), 1);
        assert_eq!(columns_from_parts(None, Some(20)), 20);
        // Which is exactly what COLUMNS may not do.
        assert_eq!(columns_from_parts(Some(b"20"), None), FALLBACK_COLUMNS);
    }

    /// The two 10000s are different tests, and the asymmetry is C's.
    #[test]
    fn the_two_ten_thousand_bounds_are_asymmetric() {
        // `curlx_str_number`'s max at `:49` is INCLUSIVE.
        assert_eq!(columns_from_parts(Some(b"10000"), None), 10_000);
        // `cols < 10000` at `:80` is EXCLUSIVE.
        assert_eq!(columns_from_parts(None, Some(10_000)), FALLBACK_COLUMNS);
        assert_eq!(columns_from_parts(None, Some(9999)), 9999);
        assert_eq!(columns_from_parts(None, Some(u32::MAX)), FALLBACK_COLUMNS);
    }

    /// A failed probe and a zero-width probe are indistinguishable, because
    /// `int cols = 0;` at `:55` is what a failed `ioctl` leaves behind, and
    /// `:80` then assigns that zero to a `width` already zero.
    #[test]
    fn a_failed_or_zero_probe_reaches_the_fallback() {
        assert_eq!(columns_from_parts(None, None), FALLBACK_COLUMNS);
        assert_eq!(columns_from_parts(None, Some(0)), FALLBACK_COLUMNS);
    }

    #[test]
    fn public_width_entry_point_is_in_contract() {
        // Reads the real environment and probes the real descriptor, so it
        // asserts the contract rather than a specific number: mutating COLUMNS
        // here would race other tests, and whether standard input is a terminal
        // is not this test's to decide.
        //
        // The contract is 1..=10000, wider than the `COLUMNS` path's
        // 21..=10000, because the probe path has no lower bound. Zero is
        // unreachable: stage three turns it into 79.
        let got = get_terminal_columns();
        assert!(
            (1..=10_000).contains(&got),
            "get_terminal_columns returned an out-of-contract width {got}"
        );
    }

    #[test]
    fn password_drops_the_trailing_newline() {
        let (password, _) =
            run_password(b"Password:", CALLER_MAX_LEN, b"secret\n", false);
        assert_eq!(password, b"secret");
    }

    #[test]
    fn password_full_buffer_without_newline_still_loses_its_last_byte() {
        // `buffer[--nread] = '\0'` at `src/tool_getpass.c:179` overwrites the
        // last byte read whatever it is. Eight bytes into an eight-byte buffer
        // with no newline present must therefore yield seven.
        let (password, _) = run_password(b"Password:", 8, b"abcdefgh", false);
        assert_eq!(password, b"abcdefg");
        assert_eq!(password.len(), 7);
    }

    #[test]
    fn password_is_empty_on_end_of_input() {
        let (password, _) =
            run_password(b"Password:", CALLER_MAX_LEN, b"", false);
        assert!(password.is_empty());
    }

    #[test]
    fn password_is_empty_on_read_error() {
        // C cannot distinguish -1 from 0: both fail `nread > 0`.
        let mut reader = FailingReader;
        let mut sink: Vec<u8> = Vec::new();
        let password = read_password_into(
            b"Password:",
            CALLER_MAX_LEN,
            &mut reader,
            &mut sink,
            false,
        );
        assert!(password.is_empty());
        // The prompt was still written before the failing read.
        assert_eq!(sink, b"Password:");
    }

    #[test]
    fn password_survives_non_utf8_bytes() {
        let (password, _) =
            run_password(b"Password:", CALLER_MAX_LEN, b"p\xffw\n", false);
        assert_eq!(password, b"p\xffw");

        // A lone continuation byte and an embedded NUL must also round-trip.
        let (password, _) =
            run_password(b"Password:", CALLER_MAX_LEN, b"a\x80\0b\n", false);
        assert_eq!(password, b"a\x80\0b");
    }

    #[test]
    fn password_prompt_goes_to_the_error_stream_with_no_newline_of_its_own() {
        // Asserting equality, not containment, proves three things at once: the
        // prompt reached the error sink, it gained no trailing newline, and no
        // extra newline was appended.
        let (_, sink) =
            run_password(b"prompt-sample:", CALLER_MAX_LEN, b"pw\n", false);
        assert_eq!(sink, b"prompt-sample:");
    }

    #[test]
    fn password_suppresses_the_extra_newline_when_echo_was_not_disabled() {
        // The `if(disabled)` guard at `src/tool_getpass.c:183`. Reachable in
        // production only through the `#else` arm at `:145-149`, which upstream
        // itself compiles when there is no `termios`; on the four mandated
        // targets `EchoGuard::echo_disabled` always reports `true`, so this
        // covers the conditional's other direction rather than a live path.
        let (_, sink) = run_password(b"P:", CALLER_MAX_LEN, b"pw\n", false);
        assert_eq!(sink, b"P:");
        assert!(!sink.ends_with(b"\n"));
    }

    #[test]
    fn password_emits_the_extra_newline_when_echo_was_disabled() {
        // The other arm of the same guard, so both directions are verified and
        // a future echo-suppression guard inherits a proven conditional.
        let (_, sink) = run_password(b"P:", CALLER_MAX_LEN, b"pw\n", true);
        assert_eq!(sink, b"P:\n");
    }

    #[test]
    fn password_tolerates_a_broken_error_stream() {
        // C ignores whether `fputs` succeeded; a failing prompt must not stop
        // the read and must not panic.
        let mut reader: &[u8] = b"secret\n";
        let mut sink = FailingWriter;
        let password = read_password_into(
            b"Password:",
            CALLER_MAX_LEN,
            &mut reader,
            &mut sink,
            true,
        );
        assert_eq!(password, b"secret");
    }

    #[test]
    fn password_handles_a_zero_length_bound() {
        // C would write `buffer[0]` into a zero-length buffer here, which is
        // undefined behaviour; an empty password is returned instead. The sole
        // caller never does this.
        let (password, sink) = run_password(b"P:", 0, b"secret\n", false);
        assert!(password.is_empty());
        assert_eq!(sink, b"P:");
    }

    #[test]
    fn password_reads_at_most_the_requested_bound() {
        // A single read of at most `max_len`, then the last byte dropped.
        let (password, _) = run_password(b"P:", 4, b"abcdefgh", false);
        assert_eq!(password, b"abc");
    }

    #[test]
    fn password_of_exactly_one_byte_becomes_empty() {
        // A bare newline is one byte read, and dropping it leaves nothing.
        let (password, _) = run_password(b"P:", CALLER_MAX_LEN, b"\n", false);
        assert!(password.is_empty());
    }

    #[test]
    fn password_accepts_an_arbitrary_prompt() {
        // This module never composes a prompt, so the sample below is
        // deliberately synthetic rather than a copy of curl's wording. The two
        // real strings at `src/tool_paramhlp.c:575-583` are frozen CLI output
        // owned by `cli/paramhlp.rs`, and reproducing either here -- even as
        // test data -- would create a second place for them to drift.
        //
        // What is verified is only that an arbitrary prompt is passed through
        // verbatim, so the sample still exercises the character classes the real
        // prompts contain: spaces, an apostrophe, a `#` and a trailing colon.
        let prompt = b"sample 'quoted' prompt #7:";
        let (password, sink) =
            run_password(prompt, CALLER_MAX_LEN, b"pw\n", false);
        assert_eq!(sink, prompt);
        assert_eq!(password, b"pw");
    }

    #[test]
    fn password_prompt_bytes_are_written_without_re_encoding() {
        // `src/tool_getpass.c:176` is `fputs(prompt, tool_stderr)` over a
        // `char prompt[256]` that `src/tool_paramhlp.c:582` filled with `%s`
        // from a username. A credential is a byte string, so an invalid UTF-8
        // sequence must reach the terminal unchanged rather than as U+FFFD.
        // The bytes below are a lone continuation byte, a bare 0xFF -- neither
        // is a valid UTF-8 sequence -- and a NUL, which `fputs` would stop at
        // but which is unreachable from the composing caller.
        let prompt = b"user '\x80\xffz':";
        let (password, sink) =
            run_password(prompt, CALLER_MAX_LEN, b"pw\n", false);
        assert_eq!(sink, prompt);
        assert_eq!(password, b"pw");

        let embedded_nul = b"a\0b:";
        let (_, sink) =
            run_password(embedded_nul, CALLER_MAX_LEN, b"pw\n", false);
        assert_eq!(sink, embedded_nul);
    }

    /// Open the multiplexer side of a pseudo-terminal.
    ///
    /// A plain `File::open` of `/dev/ptmx` yields a descriptor that `isatty`
    /// accepts and whose attributes `tcgetattr` reports, which is all the
    /// engine's guard requires. Returning `None` rather than panicking keeps a
    /// host without `/dev/ptmx` from turning into a spurious failure.
    fn open_pty_master() -> Option<File> {
        File::open("/dev/ptmx").ok()
    }

    #[test]
    fn the_engine_guard_this_module_relies_on_works_on_a_real_terminal() {
        // `getpass_r` takes the guard on the descriptor it then reads, and it
        // cannot be removed without a compile error, because `echo_disabled`
        // is bound from it. What a test can still add is evidence that the
        // engine call behaves on a descriptor that IS a terminal -- every
        // other test here drives `read_password_into` over a byte slice, where
        // no terminal exists.
        //
        // A pseudo-terminal master is used rather than `/dev/tty`, which is
        // absent in a container, and the restore is invoked explicitly so the
        // ordered path of `src/tool_getpass.c:183-186` is exercised rather
        // than only `Drop`.
        let Some(pty) = open_pty_master() else {
            return;
        };

        let guard = curl_rs_lib::disable_echo(pty.as_fd());
        assert!(
            guard.echo_disabled(),
            "src/tool_getpass.c:148 reports TRUE once the termios branch is \
             taken, which gates the newline at :185"
        );
        guard.restore();
    }
}
