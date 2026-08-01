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

// THE SAFETY INVARIANT for this crate.
//
// `forbid`, not `deny`, and the difference is deliberate. `curl-rs-lib` cannot
// use `forbid` because it owns the workspace's one sanctioned `unsafe` island
// and `#![forbid(unsafe_code)]` with a `#[allow(unsafe_code)]` anywhere beneath
// it is a hard compile error -- `error[E0453]: allow(unsafe_code) incompatible
// with previous forbid`, measured on the pinned toolchain. This crate has no
// such island: it declares no `mod ffi`, needs no exemption, and therefore
// takes the stronger form, which no inner scope can override.
//
// That is what the modules beneath rely on when they say `unsafe` is
// unavailable to them -- `curl-rs/src/output/xattr.rs` names this attribute by
// file and line when it explains why the extended-attribute syscall is reached
// through the engine rather than called directly.
//
// The audit is one command, and it must be anchored past indentation only,
// because several files in this crate legitimately DISCUSS the attribute in
// prose and an unanchored search matches the discussion:
//
//   grep -rnE '^[[:space:]]*#!?\[allow\(unsafe_code\)\]' --include='*.rs' \
//     curl-rs/src
//
// must print nothing at all. Unlike the engine's, this crate's expected count
// is zero rather than one, so the check needs no allow-list and no exception.
#![forbid(unsafe_code)]

//! `curl` -- the command-line tool, in safe Rust.
//!
//! Comments throughout this crate cite `AAP <section>` -- the frozen
//! migration specification that this implementation is measured against.
//! Its section numbers are stable, and a citation marks a decision the
//! specification fixes rather than one this code is free to change.
//!
//! This is the crate root of the `curl-rs` binary and the Rust counterpart of
//! `src/tool_main.c`. It supersedes the 22,399 lines of C under `src/`, and it
//! is a *thin* adapter: every byte that goes on the wire is decided by
//! `curl-rs-lib`, and nothing in this crate carries protocol knowledge.
//!
//! ```text
//!     curl-rs-ffi  ->  curl-rs-lib  <-  curl-rs
//!     (C ABI)          (the engine)     (this crate)
//! ```
//!
//! # What is frozen here
//!
//! AAP section 0.8.1 freezes the command-line surface: option names, aliases,
//! argument arity, argument type and default value, for all 282 rows of the
//! `aliases[]` table (`src/tool_getparam.c:80`) together with the
//! `--no-<flag>` negations that the `ARG_NO`-flagged rows generate. It also
//! freezes every byte this crate prints. That is not a stylistic preference:
//! 1,914 fixtures under `tests/data/` drive this binary through documented
//! flags, `tests/getpart.pm` compares each expected section against the actual
//! one as a **single joined string** with no per-line matching and no
//! normalization, and `tests/runtests.pl:640-730` parses the `Protocols:` and
//! `Features:` lines of `--version` to decide which fixtures may run at all.
//!
//! # The process exit status is an observable contract
//!
//! `src/tool_main.c:204` ends with `return (int)result;` -- the exit status is
//! the `CURLcode` numerically, and fixtures assert on it. [`main`] therefore
//! converts the code rather than mapping it: `CURLE_OK` is 0,
//! `CURLE_FAILED_INIT` is 2, and every other value is whatever
//! `include/curl/curl.h` pins it to. Nothing here collapses a failure to a
//! generic 1.
//!
//! # Startup order follows the C, because the C order is load-bearing
//!
//! `tool_init_stderr()` (`src/tool_stderr.c:31-35`) runs at
//! `src/tool_main.c:148`, *before* anything that can fail, so that the first
//! diagnostic the tool can emit -- `out of file descriptors` at
//! `src/tool_main.c:170` -- already has a channel to emit on. [`main`] builds
//! [`output::msgs::MessageSink`] first for exactly that reason.
//!
//! # The runtime shape is prescribed
//!
//! AAP section 0.8.3 specifies a **current-thread** Tokio runtime for the
//! command-line tool and a multi-thread runtime for the multi handle. That
//! pairing is unusual enough to be worth restating: a single sequential
//! transfer must not pay for a thread pool, and `--parallel` gets the
//! multi-thread runtime from the module that drives it
//! (`curl-rs/src/operate/parallel.rs` in the target design), not from here.
//! [`main`] builds the current-thread runtime and drives the whole invocation
//! inside it.
//!
//! # Modules
//!
//! One module per unit of the C tool, following AAP sections 0.3.1 and 0.4.1:
//!
//! - [`cli`] -- `src/tool_getparam.c`, `src/tool_help.c`,
//!   `src/tool_paramhlp.c`, `src/tool_libinfo.c`, `src/var.c`,
//!   `src/tool_ipfs.c`: the option surface and everything that validates it.
//! - [`output`] -- `src/tool_msgs.c`, `src/tool_progress.c`,
//!   `src/tool_writeout.c`, `src/tool_formparse.c`, `src/tool_dirhie.c`,
//!   `src/tool_filetime.c`, `src/tool_xattr.c`: every byte the tool emits and
//!   everything it does to a file it has saved.
//! - [`callbacks`] -- the seven `src/tool_cb_*.c` units the tool installs on
//!   the easy handle.
//! - [`terminal`] -- `src/terminal.c` and `src/tool_getpass.c`.
//! - [`util`] -- `src/tool_util.c` and `src/toolx/tool_time.c`.
//! - [`ca_embed`] -- `src/tool_ca_embed.c`, a build artifact rather than a
//!   committed source, produced by `build.rs`.

mod ca_embed;
mod callbacks;
mod cli;
mod output;
mod terminal;
mod util;

use std::io::Write;
use std::process::ExitCode;

use curl_rs_lib::CURLcode;

use crate::output::msgs::{self, DiagnosticSink, MessageSink, MsgConfig};

/// Entry point: the Rust counterpart of `main()` at `src/tool_main.c:143-205`.
///
/// # What is reproduced, and what is deliberately absent
///
/// The C body has eleven statements, and six of them do not survive the
/// migration for reasons that are structural rather than incidental:
///
/// * `:153-160` `--dump-module-paths` and `:162-168` `win32_init()` are
///   Windows-only. Windows is outside the four-target matrix, so this crate
///   carries no code path for it -- not even a `#[cfg(windows)]` arm.
/// * `:170-172` `main_checkfds()` reopens descriptors 0, 1 and 2 if the shell
///   handed the process a closed standard stream. It is a raw `fcntl`/`open`
///   loop with no safe expression, and `#![forbid(unsafe_code)]` above closes
///   the only route to one from this crate. Rust's standard streams are
///   nonetheless safe against the hazard C is defending from: writing to a
///   closed descriptor returns an `io::Error` rather than corrupting an
///   unrelated file, and every emitter in [`output::msgs`] already discards a
///   write error exactly as C's unchecked `fputs` does.
/// * `:176-181` `signal(SIGPIPE, SIG_IGN)` is unnecessary: Rust's runtime
///   already ignores `SIGPIPE` at process start, which is why a broken pipe
///   surfaces as `ErrorKind::BrokenPipe` here instead of killing the process.
/// * `:184` `memory_tracking_init()` is the `CURL_MEMDEBUG` hook. It belongs
///   to the engine, which owns the counting allocator behind the default-off
///   `memdebug` feature; a `GlobalAlloc` is registered at the root of the
///   crate that defines it and cannot be installed from here.
/// * `:196-199` `fflush(NULL)` is Windows-only, and `vms_special_exit` is
///   VMS-only.
///
/// What remains is the order that matters: the diagnostic channel first, then
/// the runtime, then the invocation, then the exit status.
fn main() -> ExitCode {
    // `src/tool_main.c:148` -- `tool_init_stderr()`, before anything that can
    // fail. Held by value here so that `--stderr <file>` can redirect it later
    // without any global state.
    let mut sink = MessageSink::init();

    // `src/tool_main.c:182` -- `memory_tracking_init()`, which C places after
    // `tool_init_stderr()` at `:148` and `main_checkfds()` at `:169` and before
    // it reaches `operate()`. This is that call, at that point in the order.
    //
    // Why it is worth making even though the cap already works: the engine's
    // allocator arms itself from `CURL_MEMLIMIT` on its first use, so the limit
    // is enforced whether or not this runs. What only an explicit early call can
    // fix is WHERE THE COUNTING STARTS. `tests/data/test1` asserts
    // `Allocations: 135` as a ceiling, and `tests/memanalyzer.pm` counts from the
    // first record in the log, so arming lazily on first use would attribute the
    // allocations made before that point to nobody and shift every subsequent
    // number. Calling here makes the numbering begin where C's begins.
    //
    // Behind the feature because the whole mechanism is: `curl-rs`'s `memdebug`
    // forwards to `curl-rs-lib/memdebug`, and with it off the engine does not
    // export this name at all, exactly as C compiles `memory_tracking_init` to
    // `tool_nop_stmt` at `src/tool_main.c:128` without `CURL_MEMDEBUG`.
    #[cfg(feature = "memdebug")]
    curl_rs_lib::memdebug_init_from_env();

    let result = match runtime() {
        Ok(runtime) => runtime.block_on(operate(&mut sink)),
        Err(error) => {
            // No `curl` counterpart, because C has no runtime to build. The
            // shape follows `src/tool_main.c:166` -- the one place C reports a
            // failed platform initialization -- which uses `errorf` and returns
            // the code rather than panicking. A panic here would produce a
            // Rust backtrace on standard error and an exit status of 101,
            // neither of which any fixture expects.
            msgs::errorf(
                &mut sink,
                &MsgConfig::new(false, false, false),
                format_args!("failed to start the async runtime: {error}"),
            );
            CURLcode::FailedInit
        }
    };

    // `src/tool_main.c:204` -- `return (int)result;`. The stream is flushed
    // first because `ExitCode` returns through the runtime's exit path, and a
    // buffered diagnostic that is dropped instead of written is a silent
    // change to the emitted bytes.
    let _ = sink.flush();

    // Every `CURLcode` is in `0..=102` (`CURL_LAST` is 102), so the conversion
    // is exact and cannot wrap. The cast is written with an explicit clamp
    // rather than `as u8` so that it stays exact by construction instead of by
    // assumption.
    let status = u8::try_from(result.as_i32()).unwrap_or(u8::MAX);
    ExitCode::from(status)
}

/// The current-thread Tokio runtime that AAP section 0.8.3 prescribes for the
/// command-line tool.
///
/// `enable_all()` turns on both the I/O and the time drivers. Both are needed
/// by the transfer path: sockets are I/O, and `--limit-rate`, `--retry-delay`,
/// `--speed-time` and the progress-meter interval are all time. They are
/// enabled here, at the one place the runtime is built, rather than by each
/// consumer, because a driver that is missing surfaces as a runtime panic
/// inside an unrelated module.
fn runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}

/// The Rust counterpart of `operate()` (`src/tool_operate.c:2260-2340`), driven
/// inside the current-thread runtime.
///
/// # The no-arguments path is complete
///
/// `src/tool_operate.c:2283-2287` is reproduced exactly. When the process is
/// invoked with no arguments and `.curlrc` supplied no URL, C calls
/// `helpf(NULL)` and returns `CURLE_FAILED_INIT`, which is exit status 2.
/// `helpf(NULL)` emits the try-line and nothing else
/// (`src/tool_msgs.c:109-123`): the `curl: ` prefix, then
/// `try 'curl --help' or 'curl --manual' for more information`, then a
/// newline. [`output::msgs::helpf`] owns those bytes, and passing `None` is
/// what selects the message-free form.
///
/// The `.curlrc` half of the same condition belongs to
/// `curl-rs/src/config/parseconfig.rs` in the target design
/// (`src/tool_parsecfg.c`). Until a configuration file can contribute a URL,
/// `argc == 1` is unconditionally the no-URL case, which is the same answer C
/// gives for an absent or URL-free `.curlrc`.
///
/// # Any other invocation
///
/// Every other invocation requires the option surface -- `parse_args()` at
/// `src/tool_operate.c:2293`, which this workspace places in
/// `curl-rs/src/cli/args.rs`. That module is not part of this crate, so no
/// option can be honoured, and the code returned says exactly that:
/// `CURLE_NOT_BUILT_IN` is documented as "a requested feature, protocol or
/// option was not found built-in in this libcurl due to a build-time
/// decision", which is a truthful description of this configuration.
///
/// Reporting it is deliberately *not* silent, and deliberately not a panic.
/// The diagnostic goes through [`output::msgs::errorf`] with the same
/// `curl: ` prefix and wrapping every other error uses, followed by the
/// try-line, so a caller sees the standard shape rather than a Rust backtrace.
///
/// # The mandatory insecure warning is reached here
///
/// [`output::msgs::warn_insecure_flags`] is called on the pre-transfer path,
/// which is where `src/config2setopts.c:378-393` switches verification off. It
/// is placed in the driver rather than left to the option layer so that the
/// door is *executed* on every invocation: AAP section 0.8.4's gate 10 asks for
/// a warning that cannot fail to appear, and a call site that only exists in a
/// module nothing reaches would not deliver that. With no option parser every
/// flag is clear and it emits nothing, exactly as C does with all three bits
/// clear.
async fn operate(sink: &mut dyn DiagnosticSink) -> CURLcode {
    // `src/tool_operate.c:2270-2272` -- the `#ifdef HAVE_SETLOCALE` pair
    // `setlocale(LC_ALL, ""); setlocale(LC_NUMERIC, "C");`, commented there
    // "Override locale for number parsing (only)". C makes it the first
    // statement of `operate()` after reading `argv[1]`, ahead of `parseconfig`
    // at `:2280`, and this is the same position.
    //
    // The order inside the engine call is the load-bearing part and is why this
    // is one call rather than two: `LC_ALL` adopts the user's environment so
    // that `%time{}` renders month and day names in their locale
    // (`src/tool_writeout.c:581-588`), and `LC_NUMERIC` is then put BACK to `C`
    // so that decimal points in parsed numbers and in `--write-out` stay `.`
    // regardless of it. Applying them in the other order would leave a comma
    // decimal separator in the emitted bytes for a locale like `de_DE`, which
    // AAP section 0.8.1 does not permit.
    //
    // It is called here, in the tool, and not from the library or the FFI shim:
    // `setlocale` mutates process-global state, and an embedding application
    // that links libcurl has its own locale policy. C has the same split --
    // nothing under `lib/` calls `setlocale` -- and the engine's facade
    // documents it as the tool's call to make.
    //
    // The return value says whether the platform honoured it. Nothing branches
    // on that: C ignores both return values too, and a locale that could not be
    // set leaves the `C` default, which is the one every fixture expects.
    let _ = curl_rs_lib::set_locale_from_environment();

    // C reads `argc`; the Rust equivalent counts the arguments *after* the
    // program name, so `argc == 1` is `args.is_empty()`.
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();

    if args.is_empty() {
        // `src/tool_operate.c:2284` -- `helpf(NULL)`, the try-line alone.
        msgs::helpf(sink, None);
        // `src/tool_operate.c:2285`.
        return CURLcode::FailedInit;
    }

    // The gates below are the ones C would have derived from the parsed
    // options. With no parser, none of `--silent`, `--show-error` or a trace
    // mode can have been requested, so the honest configuration is the default
    // one -- and it is the configuration under which an error IS reported.
    let config = MsgConfig::new(false, false, false);

    // `src/config2setopts.c:378-393` is the point at which certificate
    // verification is switched off, and therefore -- per AAP section 0.1.1
    // goal G4, section 0.8.1 and validation gate 10 of section 0.8.4 -- the
    // point at which the mandatory warning must be emitted. It sits here, on
    // the pre-transfer path, so that the door is reached on every invocation
    // rather than depending on a future caller remembering it.
    //
    // The three booleans come from exactly where `config` above comes from:
    // no option can be honoured by this build, so no `--insecure`,
    // `--doh-insecure` or `--proxy-insecure` can have been accepted, and all
    // three bits of `src/tool_cfgable.h:258-261` are clear. C emits nothing
    // when they are clear -- its three `if` statements are simply not taken --
    // and neither does this, so the emitted bytes are unchanged. The moment
    // the option table can set a bit, the warning appears with no further
    // wiring, because `warn_insecure_flags` is the only place the three flag
    // names exist.
    msgs::warn_insecure_flags(sink, false, false, false);

    msgs::errorf(
        sink,
        &config,
        format_args!(
            "option parsing is not built in; no command-line option can be \
             honoured by this build"
        ),
    );
    msgs::helpf(sink, None);

    CURLcode::NotBuiltIn
}

#[cfg(test)]
mod tests {
    use super::{operate, runtime};
    use curl_rs_lib::CURLcode;

    #[test]
    fn the_current_thread_runtime_builds_with_both_drivers() {
        let runtime = runtime().expect("the current-thread runtime must build");

        // Both drivers must be live, because the transfer path needs both: a
        // missing time driver panics on the first sleep and a missing I/O
        // driver panics on the first socket registration. `sleep` proves the
        // timer, and the worker count proves the shape AAP section 0.8.3
        // prescribes.
        runtime.block_on(async {
            tokio::time::sleep(std::time::Duration::from_millis(0)).await;
        });

        assert_eq!(runtime.metrics().num_workers(), 1);
    }

    #[test]
    fn every_invocation_emits_the_try_line_and_a_specific_code() {
        // `operate` reads the real process arguments, which a test cannot set,
        // so both of its branches are admissible here: `cargo test` may pass
        // arguments to the test binary or none at all. Both return a specific
        // non-zero `CURLcode` and both emit the try-line, and that pair is what
        // is asserted -- so the test is meaningful whichever way it runs, and
        // it exercises the production body rather than a copy of it.
        let runtime = runtime().expect("the current-thread runtime must build");
        let mut sink: Vec<u8> = Vec::new();
        let code = runtime.block_on(operate(&mut sink));

        assert!(
            code == CURLcode::FailedInit || code == CURLcode::NotBuiltIn,
            "expected CURLE_FAILED_INIT or CURLE_NOT_BUILT_IN, got {code:?}"
        );

        // Neither code may be zero: a tool that honoured nothing must not
        // report success. This is the property the process exit status carries.
        assert!(!code.is_ok());

        // The try-line of `src/tool_msgs.c:118-122` is emitted from `helpf` on
        // both paths, with the `curl: ` prefix of `:113`.
        let text = String::from_utf8(sink).expect("diagnostics are UTF-8 here");
        let expected =
            "curl: try 'curl --help' or 'curl --manual' for more information\n";
        assert!(
            text.ends_with(expected),
            "the try-line must be emitted verbatim, got {text:?}"
        );
    }
}

/// The mandatory-warning door is reached, and reached unconditionally.
///
/// AAP section 0.1.1 goal G4 requires that `--insecure` "must emit a stderr
/// warning before proceeding", and section 0.8.4's gate 10 makes it a merge
/// gate. [`output::msgs::warn_insecure`] already makes *suppression*
/// unrepresentable by taking no configuration argument at all, but that
/// guarantee is worthless if nothing calls it: an unreachable warning is
/// indistinguishable from an absent one.
///
/// A behavioural test cannot establish the call site. With no option parser all
/// three flags are clear, C emits nothing in that state, and section 0.8.1
/// freezes that -- so the correct behaviour today is silence, and silence is
/// exactly what deleting the call would also produce. The property therefore has
/// to be asserted structurally, and this module does it the way the workspace
/// already does elsewhere (`curl-rs-ffi/src/lib.rs`'s unsafe-boundary gate and
/// `curl-rs-lib/src/lib.rs`'s source policy): by reading its own source through
/// [`include_str!`] and asserting on the code, with comments and string literals
/// stripped so that the prose above -- which names the function twice -- cannot
/// satisfy the gate on its own.
#[cfg(test)]
mod mandatory_warning_gate {
    /// This file's own text. `include_str!` resolves relative to this file, so
    /// the gate reads the source it is compiled from and cannot drift.
    const SOURCE: &str = include_str!("main.rs");

    /// The call the gate insists on, spelled as it appears in code.
    const DOOR: &str = "msgs::warn_insecure_flags(";

    /// `line` with its trailing `//` comment and every string literal removed.
    ///
    /// A literal collapses to a single space rather than to nothing, so a string
    /// standing between two identifiers cannot fuse them into one token. The one
    /// limitation is that a `//` sequence inside a raw string literal would
    /// truncate the line early, which [`the_gate_sees_no_raw_strings`] rules out
    /// for this file specifically rather than assuming.
    fn code_only(line: &str) -> String {
        let without_comment = line.split("//").next().unwrap_or("");
        let mut out = String::with_capacity(without_comment.len());
        let mut in_string = false;
        let mut escaped = false;

        for ch in without_comment.chars() {
            if in_string {
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == '"' {
                    in_string = false;
                }
                continue;
            }
            if ch == '"' {
                in_string = true;
                out.push(' ');
                continue;
            }
            out.push(ch);
        }

        out
    }

    /// Every line of [`SOURCE`], reduced to code, paired with its 1-based
    /// number.
    fn code_lines() -> Vec<(usize, String)> {
        SOURCE
            .lines()
            .enumerate()
            .map(|(index, line)| (index + 1, code_only(line)))
            .collect()
    }

    /// The 1-based line on which `needle` first appears as code, if at all.
    fn first_code_line(needle: &str) -> Option<usize> {
        code_lines()
            .into_iter()
            .find(|(_, code)| code.contains(needle))
            .map(|(number, _)| number)
    }

    /// The 1-based line on which `needle` first appears as code strictly
    /// between `after` and `before`.
    ///
    /// Needed because several of these names appear more than once in the file
    /// -- `main` reports a runtime-construction failure through the same
    /// `errorf` that `operate` uses -- so an unbounded search would answer about
    /// the wrong function and make an ordering assertion meaningless. That
    /// happened while this gate was being written, which is why the bound is
    /// explicit rather than implied.
    fn first_code_line_within(
        needle: &str,
        after: usize,
        before: usize,
    ) -> Option<usize> {
        code_lines()
            .into_iter()
            .find(|(number, code)| {
                *number > after && *number < before && code.contains(needle)
            })
            .map(|(number, _)| number)
    }

    /// The line range of `operate`'s body: its signature, and the module that
    /// follows it.
    fn operate_bounds() -> (usize, usize) {
        let operate = first_code_line("async fn operate(")
            .expect("`operate` must be declared");
        let tests = first_code_line("mod tests")
            .expect("the test module must follow `operate`");

        assert!(operate < tests, "`operate` must precede the test module");

        (operate, tests)
    }

    #[test]
    fn the_gate_sees_no_raw_strings() {
        // `code_only` cannot reason about raw string literals, so the gate is
        // only sound while this file has none. Asserted rather than assumed,
        // because a future edit could introduce one and would then weaken the
        // gate silently instead of failing here.
        //
        // The scan covers comments too, not only code -- it has to, since
        // deciding where a comment ends is exactly the thing that needs
        // raw-string awareness. The practical consequence is that this file's
        // own prose may not spell the sigil, and it does not: writing it out
        // in a comment is what made this assertion fire twice while the gate
        // was being written, which is the gate proving itself.
        for (number, line) in SOURCE.lines().enumerate() {
            let bytes = line.as_bytes();

            for (index, _) in line.match_indices('r') {
                let preceded_by_identifier = index > 0
                    && (bytes[index - 1].is_ascii_alphanumeric()
                        || bytes[index - 1] == b'_');
                if preceded_by_identifier {
                    continue;
                }

                let rest = &line[index + 1..];
                let opens = rest.starts_with('"')
                    || (rest.starts_with('#')
                        && rest.trim_start_matches('#').starts_with('"'));

                assert!(
                    !opens,
                    "line {} opens a raw string, which this gate cannot \
                     strip: {line:?}",
                    number + 1
                );
            }
        }
    }

    #[test]
    fn the_door_is_called_exactly_once_as_code() {
        let calls = code_lines()
            .into_iter()
            .filter(|(_, code)| code.contains(DOOR))
            .count();

        assert_eq!(
            calls, 1,
            "`{DOOR}` must appear exactly once as code in this file: zero \
             means the mandatory warning of AAP section 0.1.1 goal G4 is \
             unreachable, and more than one means two driver paths could \
             disagree about what was warned"
        );
    }

    #[test]
    fn the_door_is_unconditional_and_inside_operate() {
        let door =
            first_code_line(DOOR).expect("the door must be called as code");
        let (operate, tests) = operate_bounds();

        assert!(
            operate < door && door < tests,
            "the call must sit in `operate`'s body (lines {operate}..{tests}), \
             not in `main`, not in a helper and not in a test"
        );

        // Unconditional: the statement stands at `operate`'s own statement
        // level, four spaces in. A call nested inside an `if`, a `match` arm or
        // a loop would be indented further and could be skipped, which is
        // exactly the shape gate 10 forbids.
        let line = SOURCE
            .lines()
            .nth(door - 1)
            .expect("the line just located must exist");
        let indent = line.len() - line.trim_start().len();

        assert_eq!(
            indent, 4,
            "the call must be an unconditional statement of `operate`, but \
             line {door} is indented {indent} spaces: {line:?}"
        );
    }

    #[test]
    fn the_door_precedes_every_other_diagnostic_on_that_path() {
        // "Before proceeding" is the requirement, and on this path the only
        // things that follow are the error and the try-line. Asserting the
        // ordering against `errorf` keeps the property checkable now and
        // remains correct when a transfer is added after it, because anything
        // added later can only move `errorf` further down.
        let door =
            first_code_line(DOOR).expect("the door must be called as code");
        let (operate, tests) = operate_bounds();
        let errorf = first_code_line_within("msgs::errorf(", operate, tests)
            .expect("`operate` must report the build-time refusal");

        assert!(
            door < errorf,
            "the warning must be emitted before the path proceeds, but the \
             call is on line {door} and `errorf` on line {errorf}"
        );
    }

    // Start-up initialisers.
    //
    // Two engine facades exist for the tool to call once, early, and both were
    // reported as having no production consumer at all. A gate of the same shape
    // as the one above is the right guard because the failure mode is identical:
    // the code compiles, runs and reports nothing whatever wrong, and only a
    // reader comparing against `src/tool_main.c` would notice the call missing.
    // An ordinary behavioural test cannot see it either -- `setlocale` succeeds
    // silently and the allocation cap arms itself lazily -- so the call site
    // itself is the thing to assert on.

    /// The locale call, spelled as it appears in code.
    const LOCALE_DOOR: &str = "curl_rs_lib::set_locale_from_environment(";

    /// The allocation-accounting call, spelled as it appears in code.
    ///
    /// Gated for the same reason as the two tests that read it: without the
    /// feature the engine does not export the name, there is no call to find, and
    /// an ungated constant would be dead code -- a warning, and AAP section
    /// 0.8.4's first gate is a zero-warning build.
    #[cfg(feature = "memdebug")]
    const MEMDEBUG_DOOR: &str = "curl_rs_lib::memdebug_init_from_env(";

    #[test]
    fn the_locale_initialiser_has_a_production_call_site() {
        // `src/tool_operate.c:2270-2272`. The facade requires one call before
        // runtime or thread creation, and without this gate nothing keeps that
        // call present.
        let door = first_code_line(LOCALE_DOOR)
            .expect("`operate` must call the engine's locale facade");
        let (operate, tests) = operate_bounds();

        assert!(
            door > operate && door < tests,
            "the call must be inside `operate`, but it is on line {door} and \
             `operate` spans {operate}..{tests}"
        );

        let line = SOURCE
            .lines()
            .nth(door - 1)
            .expect("the line just located must exist");
        let indent = line.len() - line.trim_start().len();
        assert_eq!(
            indent, 4,
            "the call must be an unconditional statement of `operate`, not \
             nested in a branch, but line {door} is indented {indent} spaces"
        );
    }

    #[test]
    fn the_locale_is_set_before_anything_reads_a_configuration() {
        // C's ordering, and the reason it is the ordering: `setlocale` at
        // `src/tool_operate.c:2271` precedes `parseconfig` at `:2280`, so every
        // number this process parses is parsed under `LC_NUMERIC=C`. A call
        // placed after the first parse would leave the earliest-parsed numbers
        // reading a decimal comma in a locale like `de_DE`.
        //
        // `args_os` is the first thing on this path that a configuration could
        // come from, so it stands in for `parseconfig` until the parser exists,
        // and the assertion stays correct when the parser arrives because a
        // parser can only appear after the arguments are collected.
        let door = first_code_line(LOCALE_DOOR)
            .expect("`operate` must call the engine's locale facade");
        let (operate, tests) = operate_bounds();
        let first_input = first_code_line_within("args_os(", operate, tests)
            .expect("`operate` must read its arguments");

        assert!(
            door < first_input,
            "the locale must be set before the first configuration input, but \
             the call is on line {door} and `args_os` on line {first_input}"
        );
    }

    #[test]
    #[cfg(feature = "memdebug")]
    fn the_allocation_accounting_initialiser_has_a_production_call_site() {
        // `src/tool_main.c:182`. Left unwired, the facade shifts allocation
        // numbering before lazy activation.
        //
        // Gated on the feature for the same reason the call is: without it the
        // engine does not export the name, so a gate that ran unconditionally
        // would demand a call that could not compile.
        let door = first_code_line(MEMDEBUG_DOOR)
            .expect("`main` must call the engine's allocation-cap facade");

        assert!(
            door < first_code_line("fn operate(").unwrap_or(usize::MAX),
            "the call must be in `main`, ahead of `operate`, but it is on \
             line {door}"
        );
    }

    #[test]
    #[cfg(feature = "memdebug")]
    fn allocation_accounting_is_armed_before_the_runtime_is_built() {
        // The whole point of calling it explicitly rather than letting the
        // allocator arm itself lazily: the runtime allocates. If the cap is
        // armed after `runtime()`, those allocations fall outside the count and
        // every number `tests/memanalyzer.pm` reports shifts relative to C's.
        let door = first_code_line(MEMDEBUG_DOOR)
            .expect("`main` must call the engine's allocation-cap facade");
        let runtime = first_code_line("match runtime()")
            .expect("`main` must build the runtime");

        assert!(
            door < runtime,
            "the cap must be armed before the runtime allocates, but the call \
             is on line {door} and the runtime is built on line {runtime}"
        );
    }
}

/// Every output `build.rs` writes must have a consumer that includes it.
///
/// Three generated outputs can sit in `OUT_DIR` with no module including them:
/// the manual and both completion scripts. Including them is the fix, but an
/// inclusion added once can be removed again, and
/// a NEW artifact added to the generator can be orphaned on the day it is
/// written. So the finding also asks for "tests that fail when an output has no
/// consumer", and this module is that test.
///
/// # Why it reads two sources rather than asserting a list
///
/// A hand-written list of expected artifacts is only as current as the last
/// person to edit it. This gate instead derives the expectation from the two
/// places that cannot be wrong:
///
/// * `build.rs`'s own `const OUT_*` declarations say what the generator is FOR.
///   Adding an artifact means adding one of those, so the gate sees it
///   immediately.
/// * `OUT_DIR` says what the generator actually WROTE on this build.
///
/// It then requires the two to agree, and requires every file in them to be
/// named inside an inclusion macro. An orphan fails on the third check; a
/// generator that silently stopped writing something fails on the second.
#[cfg(test)]
mod generated_artifact_gate {
    use std::fs;
    use std::path::{Path, PathBuf};

    /// The generator's own text, so the expectation cannot drift from it.
    const BUILD_SCRIPT: &str = include_str!("../build.rs");

    /// Where this build's artifacts landed.
    ///
    /// Available because the build script ran for this crate; `env!` resolves it
    /// at compile time, so the test reads the same directory the `include!`
    /// invocations resolved against rather than guessing at a path.
    const OUT_DIR: &str = env!("OUT_DIR");

    /// The three macros that make an artifact reachable from Rust.
    ///
    /// `include!` splices Rust source, `include_str!` embeds text and
    /// `include_bytes!` embeds bytes. There is no fourth way to consume a file
    /// from `OUT_DIR` at compile time, and a runtime read would be wrong for all
    /// five of these because `OUT_DIR` does not exist for an installed binary.
    const INCLUSION_MACROS: &[&str] =
        &["include!", "include_str!", "include_bytes!"];

    /// Every `const OUT_*: &str = "..."` value the generator declares.
    ///
    /// Parsed rather than listed for the reason in the module documentation. The
    /// prefix is the generator's own naming convention for exactly this set, and
    /// it is uniform: `OUT_HUGEHELP`, `OUT_CA_EMBED_RS`, `OUT_CA_EMBED_BIN`,
    /// `OUT_COMPLETIONS_DIR`, `OUT_ZSH`, `OUT_FISH`.
    fn declared_names() -> Vec<String> {
        let mut names = Vec::new();

        for line in BUILD_SCRIPT.lines() {
            let trimmed = line.trim_start();
            let Some(rest) = trimmed.strip_prefix("const OUT_") else {
                continue;
            };
            // `<NAME>: &str = "<value>";` -- take what is between the quotes.
            let Some(open) = rest.find('"') else { continue };
            let Some(close) = rest[open + 1..].find('"') else {
                continue;
            };
            names.push(rest[open + 1..open + 1 + close].to_owned());
        }

        names
    }

    /// Every file `OUT_DIR` holds, as a path relative to it.
    ///
    /// Recursive because the completion scripts live one level down, in the
    /// directory `OUT_COMPLETIONS_DIR` names.
    fn artifacts_on_disk() -> Vec<PathBuf> {
        fn walk(dir: &Path, base: &Path, into: &mut Vec<PathBuf>) {
            let Ok(entries) = fs::read_dir(dir) else {
                return;
            };

            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, base, into);
                } else if let Ok(relative) = path.strip_prefix(base) {
                    into.push(relative.to_owned());
                }
            }
        }

        let base = Path::new(OUT_DIR);
        let mut found = Vec::new();
        walk(base, base, &mut found);
        found.sort();
        found
    }

    /// Every committed source file of this crate, with its text.
    ///
    /// Read from disk rather than `include_str!`ed one by one so that a new
    /// module cannot be added without the gate seeing it -- which is the same
    /// drift the gate exists to catch, one level up.
    fn crate_sources() -> Vec<(PathBuf, String)> {
        fn walk(dir: &Path, into: &mut Vec<(PathBuf, String)>) {
            let Ok(entries) = fs::read_dir(dir) else {
                return;
            };

            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, into);
                } else if path.extension().is_some_and(|ext| ext == "rs") {
                    if let Ok(text) = fs::read_to_string(&path) {
                        into.push((path, text));
                    }
                }
            }
        }

        // `CARGO_MANIFEST_DIR` is the crate root, so `src` is beside `build.rs`.
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut sources = Vec::new();
        walk(&root, &mut sources);
        sources.sort_by(|left, right| left.0.cmp(&right.0));
        sources
    }

    /// Whether `text` names `artifact` inside an inclusion macro's own argument
    /// list.
    ///
    /// The extent is the macro's parentheses, found by counting depth from the
    /// first `(` until it returns to zero, rather than a fixed number of bytes
    /// after the macro name. A byte window was tried first and
    /// [`the_window_scan_does_not_answer_from_a_mere_mention`] rejected it: with
    /// a 120-byte window, a comment on the line AFTER a short inclusion fell
    /// inside it, so a module that merely mentioned an artifact would have
    /// counted as its consumer and an orphan could have passed. Paren depth has
    /// no such slack -- the extent is exactly the argument list, whatever its
    /// length.
    fn includes(text: &str, artifact: &str) -> bool {
        for macro_name in INCLUSION_MACROS {
            let mut from = 0;
            while let Some(offset) = text[from..].find(macro_name) {
                let start = from + offset;
                from = start + macro_name.len();

                let Some(arguments) = argument_list(text, from) else {
                    continue;
                };
                if arguments.contains(artifact) {
                    return true;
                }
            }
        }

        false
    }

    /// The text between the `(` at or after `from` and its matching `)`.
    ///
    /// Returns `None` when no `(` follows immediately -- which is what
    /// `INCLUSION_MACROS` names appearing inside prose do, since a comment writes
    /// `include_str!` without invoking it -- or when the parentheses are
    /// unbalanced, which cannot happen in a file that compiles.
    ///
    /// Quoting is tracked so that a `(` or `)` inside a string literal does not
    /// move the depth. None of this crate's inclusions contain one, but a gate
    /// that would miscount if they did is a gate whose result cannot be trusted
    /// after the next edit.
    fn argument_list(text: &str, from: usize) -> Option<&str> {
        let bytes = text.as_bytes();
        let mut index = from;

        // Only whitespace may sit between the `!` and the `(`.
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if bytes.get(index) != Some(&b'(') {
            return None;
        }

        let open = index;
        let mut depth = 0_usize;
        let mut in_string = false;
        let mut escaped = false;

        while index < bytes.len() {
            let byte = bytes[index];

            if in_string {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    in_string = false;
                }
            } else {
                match byte {
                    b'"' => in_string = true,
                    b'(' => depth += 1,
                    b')' => {
                        depth -= 1;
                        if depth == 0 {
                            return text.get(open + 1..index);
                        }
                    }
                    _ => {}
                }
            }

            index += 1;
        }

        None
    }

    /// The consumer of `artifact`, named by file, if one exists.
    ///
    /// `OUT_DIR` is searched as well as the committed sources because one
    /// artifact is consumed by another: `ca_embed.bin` is included by the
    /// GENERATED `ca_embed.rs`, which `build.rs` writes with an `include_bytes!`
    /// of its own (`curl-rs/build.rs:1838-1842`). That is a real consumer, and
    /// the only place it can be observed is the generated file itself.
    fn consumer_of(artifact: &str) -> Option<PathBuf> {
        for (path, text) in crate_sources() {
            if includes(&text, artifact) {
                return Some(path);
            }
        }

        for relative in artifacts_on_disk() {
            let path = Path::new(OUT_DIR).join(&relative);
            if path.extension().is_some_and(|ext| ext == "rs") {
                if let Ok(text) = fs::read_to_string(&path) {
                    // An artifact cannot consume itself.
                    if relative.file_name().is_some_and(|name| name != artifact)
                        && includes(&text, artifact)
                    {
                        return Some(path);
                    }
                }
            }
        }

        None
    }

    #[test]
    fn the_generator_declares_the_artifacts_this_gate_expects() {
        // Establishes that the parse above works before anything is concluded
        // from it. Without this, a `const OUT_*` renaming would empty the list
        // and every assertion below would pass vacuously.
        let declared = declared_names();

        assert_eq!(
            declared.len(),
            6,
            "expected six OUT_* declarations in build.rs -- four files, one \
             directory and one more file inside it -- but parsed {declared:?}"
        );
        for expected in [
            "hugehelp.rs",
            "ca_embed.rs",
            "ca_embed.bin",
            "completions",
            "_curl",
            "curl.fish",
        ] {
            assert!(
                declared.iter().any(|name| name == expected),
                "build.rs no longer declares {expected:?}; parsed {declared:?}"
            );
        }
    }

    #[test]
    fn every_declared_artifact_was_actually_written() {
        // The second of the two failures this module guards: a generator that
        // stopped writing something. That is invisible to a build unless the
        // artifact is `include!`d, and two of these are not Rust source.
        let on_disk = artifacts_on_disk();
        let names: Vec<String> = on_disk
            .iter()
            .filter_map(|path| path.file_name())
            .map(|name| name.to_string_lossy().into_owned())
            .collect();

        for declared in declared_names() {
            // The directory name is not itself a file; its presence is proven by
            // the two files inside it.
            if declared == "completions" {
                assert!(
                    on_disk.iter().any(|path| path.starts_with("completions")),
                    "build.rs declares a completions directory but OUT_DIR \
                     holds {on_disk:?}"
                );
                continue;
            }

            assert!(
                names.contains(&declared),
                "build.rs declares {declared:?} but it is not in OUT_DIR, \
                 which holds {names:?}"
            );
        }
    }

    #[test]
    fn no_generated_artifact_is_orphaned() {
        // In one assertion: every file the generator wrote
        // must be named inside an `include!`, `include_str!` or `include_bytes!`
        // somewhere that compiles into this crate.
        let mut orphans = Vec::new();

        for relative in artifacts_on_disk() {
            let Some(name) =
                relative.file_name().and_then(|name| name.to_str())
            else {
                continue;
            };

            if consumer_of(name).is_none() {
                orphans.push(relative);
            }
        }

        // The scan is over what is ON DISK rather than over what `build.rs`
        // declares, which is deliberate: an artifact written from a literal path
        // with no `const OUT_*` beside it is exactly the kind that gets
        // orphaned, and only the disk knows about it. The cost is that a file the
        // generator USED to write lingers in `OUT_DIR` after the generator stops,
        // and reports here as an orphan until `cargo clean`. That is named in the
        // message rather than papered over, because the alternative -- trusting
        // the declarations -- cannot see the undeclared case this probe was built
        // to catch.
        assert!(
            orphans.is_empty(),
            "these generated outputs have no consumer, so build.rs writes them \
             and nothing reads them: {orphans:?}. Either include the file from a \
             module, or stop generating it -- or, if generation has ALREADY \
             stopped and this is a leftover from an earlier build, run \
             `cargo clean -p curl-rs`"
        );
    }

    #[test]
    fn both_completions_are_staged_where_an_installer_can_find_them() {
        // The other half: packaging must install them. Including a completion
        // makes it reachable from Rust, which does
        // not put it where a shell will look. `build.rs` therefore also writes
        // each one into `$OUT_DIR/staging/<install-relative path>`, following the
        // convention `curl-rs-ffi/build.rs` uses for `curl-config` and
        // `libcurl.pc` and that `.github/workflows/rust-abi.yml` already asserts.
        //
        // The install-relative paths stand in for `@ZSH_FUNCTIONS_DIR@` and
        // `@FISH_FUNCTIONS_DIR@` (`scripts/Makefile.am:54-62`), which are
        // configure substitutions with no Cargo equivalent.
        let out = Path::new(OUT_DIR);

        for (staged, product) in [
            ("share/zsh/site-functions/_curl", "completions/_curl"),
            (
                "share/fish/vendor_completions.d/curl.fish",
                "completions/curl.fish",
            ),
        ] {
            let staged = out.join("staging").join(staged);
            let product = out.join(product);

            let staged_bytes = fs::read(&staged).unwrap_or_else(|err| {
                panic!(
                    "no staged completion at {}: {err}. build.rs must write the \
                     install copy as well as the one the crate includes",
                    staged.display()
                )
            });
            let product_bytes = fs::read(&product).unwrap_or_else(|err| {
                panic!("no completion at {}: {err}", product.display())
            });

            // Byte-identical rather than merely present: a staged copy that
            // drifted from the included one would install a completion the
            // binary's own tests never checked.
            assert_eq!(
                staged_bytes,
                product_bytes,
                "the staged copy of {} differs from the one the crate includes",
                product.display()
            );
        }
    }

    #[test]
    fn nothing_is_staged_outside_the_build_directory_by_default() {
        // `CURL_RS_STAGING_DIR` is opt-in precisely so that a default build
        // cannot write into the source tree, and AAP section 0.8.4's first gate
        // asserts a clean tree. If the variable leaked into the environment of an
        // ordinary build, the staged copies would land somewhere `cargo clean`
        // does not reach and `git status` might.
        //
        // The assertion is on this test process rather than on the build script's
        // environment, which is the closest observable proxy: Cargo passes its own
        // environment through to build scripts, so a value visible here would have
        // been visible there.
        assert!(
            std::env::var_os("CURL_RS_STAGING_DIR").is_none(),
            "CURL_RS_STAGING_DIR is set in this environment, so the build \
             script staged files outside target/. That is supported, but it \
             must be deliberate: unset it for ordinary builds"
        );
    }

    #[test]
    fn each_artifact_is_consumed_where_it_is_meant_to_be() {
        // The stronger form: not merely "somebody includes it" but "the module
        // that owns it includes it". An inclusion moved into the wrong module
        // would still leave the artifact reachable, and would still be a defect,
        // because the ownership is what `cli/mod.rs` documents.
        for (artifact, expected_owner) in [
            ("hugehelp.rs", "cli/hugehelp.rs"),
            ("_curl", "cli/completions.rs"),
            ("curl.fish", "cli/completions.rs"),
            ("ca_embed.rs", "ca_embed.rs"),
            // The generated file, not a committed one -- see `consumer_of`.
            ("ca_embed.bin", "ca_embed.rs"),
        ] {
            let consumer = consumer_of(artifact)
                .unwrap_or_else(|| panic!("{artifact} has no consumer at all"));
            let shown = consumer.to_string_lossy().replace('\\', "/");

            assert!(
                shown.ends_with(expected_owner),
                "{artifact} should be included by {expected_owner}, but its \
                 consumer is {shown}"
            );
        }
    }

    #[test]
    fn the_window_scan_does_not_answer_from_a_mere_mention() {
        // This gate's own correctness. `includes` must key off an inclusion
        // macro's argument list, not off the artifact's name appearing anywhere
        // in the file -- otherwise a module that merely documents an artifact
        // would look like its consumer, and the orphan test would pass while the
        // orphan remained. Every case below is one this gate answered wrongly at
        // some point while it was being written.
        assert!(
            !includes("// hugehelp.rs is generated by build.rs", "hugehelp.rs"),
            "a comment naming an artifact must not count as including it"
        );
        assert!(
            !includes(
                "include!(concat!(env!(\"OUT_DIR\"), \"/other.rs\"));\n\
                 // and separately, hugehelp.rs exists",
                "hugehelp.rs"
            ),
            "a mention after the macro's closing paren must not count -- this is \
             the case a fixed byte window got wrong"
        );
        assert!(
            !includes(
                "/// Consumed through include_str! by cli/completions.rs\n\
                 const NAME: &str = \"_curl\";",
                "_curl"
            ),
            "a macro NAME in prose is not an invocation, so what follows it is \
             not an argument list"
        );
        assert!(
            includes(
                "include!(concat!(env!(\"OUT_DIR\"), \"/hugehelp.rs\"));",
                "hugehelp.rs"
            ),
            "a real inclusion must count"
        );
        assert!(
            includes(
                "const ZSH: &str = include_str!(\n    concat!(env!(\"OUT_DIR\"), \
                 \"/completions/_curl\"),\n);",
                "_curl"
            ),
            "an inclusion split across lines must count, because that is how \
             rustfmt writes the longer ones"
        );

        // And that a parenthesis inside the path cannot end the argument list
        // early, which is the one way the depth counter could under-read.
        assert!(
            includes("include_bytes!(concat!(\"a(b\", \"/x.bin\"));", "x.bin"),
            "a paren inside a string literal must not close the argument list"
        );
    }
}

/// Checks that what the test and CI documentation says about this checkout is
/// true of this checkout.
///
/// Documentation drifts from the checkout in two ways: `docs/tests/CI.md` can
/// describe committed workflow files as though they were absent, and the test
/// documentation can refer to test paths that do not match the manifests.
/// Correcting such prose does not keep it correct, so the claims are validated
/// automatically here rather than merely fixed once.
///
/// The two classes of claim are checked in opposite ways, deliberately.
///
/// A workflow file that the documentation names is checked for existence, and
/// that direction is safe because naming a workflow is a statement that it is
/// committed. Deleting a workflow while a page still discusses it is the same
/// defect in reverse.
///
/// A path that the documentation says is *absent* is checked in **both**
/// directions, and this matters more than it appears. `tests-rs/` is specified
/// by AAP section 0.3.1 and is expected to arrive; a gate that simply asserted
/// its absence would turn the delivery of specified work into a test failure,
/// which would make the gate an obstacle to the plan it is supposed to serve.
/// What is asserted instead is agreement: if the tree is absent the pages must
/// say so, and if it is present they must no longer say so. Either state passes,
/// and only a page that disagrees with the disk fails.
#[cfg(test)]
mod documentation_gate {
    use std::fs;
    use std::path::{Path, PathBuf};

    /// The repository root, two levels up from this crate's `src`.
    ///
    /// `CARGO_MANIFEST_DIR` is `<root>/curl-rs`, so one `parent()` reaches the
    /// workspace root. Derived rather than assumed from the working directory,
    /// because `cargo test` may be invoked from anywhere in the tree.
    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("this crate's directory has a parent, the repository root")
            .to_path_buf()
    }

    fn read(relative: &str) -> String {
        let path = repo_root().join(relative);
        fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
    }

    /// Every distinct name ending in `.yml` that this page prints inside
    /// backticks.
    ///
    /// Parsed from the prose rather than listed here on purpose. A list in this
    /// file would be a second copy of the documentation's own claim, and the two
    /// copies would then be free to disagree -- which is the shape of the defect
    /// this module exists to catch, not a way to catch it.
    fn yml_names(page: &str) -> Vec<String> {
        let mut found: Vec<String> = Vec::new();
        for fragment in page.split('`').skip(1).step_by(2) {
            if !fragment.ends_with(".yml") {
                continue;
            }
            // Backticked spans in these pages are single tokens; anything with
            // whitespace is prose that happens to end in the suffix, not a path.
            if fragment.split_whitespace().count() != 1 {
                continue;
            }
            if !found.iter().any(|f| f == fragment) {
                found.push(fragment.to_string());
            }
        }
        found
    }

    /// Every workflow file the CI page names has to exist.
    ///
    /// A name resolves either under `.github/workflows/` or, for the two
    /// third-party services, at the repository root: `appveyor.yml` and
    /// `.circleci/config.yml` are configuration for AppVeyor and Circle CI and
    /// have never lived in the GitHub Actions directory. Accepting both
    /// locations keeps the check general instead of special-casing those two by
    /// name, and a name that is in neither place fails.
    #[test]
    fn every_workflow_the_ci_page_names_exists() {
        let page = read("docs/tests/CI.md");
        let names = yml_names(&page);
        assert!(
            names.len() >= 10,
            "only {} workflow names parsed out of docs/tests/CI.md -- the \
             parser has stopped matching the page and the gate would be \
             vacuous",
            names.len()
        );

        let root = repo_root();
        let mut missing = Vec::new();
        for name in &names {
            let in_workflows = root.join(".github/workflows").join(name);
            let at_root = root.join(name);
            if !in_workflows.is_file() && !at_root.is_file() {
                missing.push(name.clone());
            }
        }
        assert!(
            missing.is_empty(),
            "docs/tests/CI.md names {} workflow file(s) that are not in this \
             checkout: {missing:?}. Either the file was removed and the page \
             still discusses it, or the page names it wrongly: documentation \
             and checkout disagree about which workflows exist",
            missing.len()
        );
    }

    /// The numbered gate list has to be a complete, duplicate-free 1..=N and
    /// every entry has to name a committed workflow.
    ///
    /// The list is the page's most specific claim -- it assigns each gate a
    /// number and a file -- so it is checked as a structure rather than only for
    /// the existence its entries imply. A hole or a repeat means the list was
    /// edited without being re-read.
    #[test]
    fn the_numbered_gate_list_is_complete_and_backed_by_files() {
        let page = read("docs/tests/CI.md");
        let root = repo_root();

        let mut gates: Vec<(usize, String)> = Vec::new();
        for line in page.lines() {
            // The form the page uses is: - `x.yml` (gate N) ...
            let Some(rest) = line.strip_prefix("- `") else {
                continue;
            };
            let Some((file, after)) = rest.split_once('`') else {
                continue;
            };
            let Some(tail) = after.trim_start().strip_prefix("(gate ") else {
                continue;
            };
            let Some((number, _)) = tail.split_once(')') else {
                continue;
            };
            let number: usize = number
                .trim()
                .parse()
                .unwrap_or_else(|e| panic!("gate number {number:?} in docs/tests/CI.md does not parse: {e}"));
            gates.push((number, file.to_string()));
        }

        assert!(
            !gates.is_empty(),
            "no `- `x.yml` (gate N)` entries parsed out of docs/tests/CI.md -- \
             the page's list format changed and this gate would be vacuous"
        );

        // The numbering has to cover 1..=len exactly once each.
        let mut numbers: Vec<usize> = gates.iter().map(|(n, _)| *n).collect();
        numbers.sort_unstable();
        let expected: Vec<usize> = (1..=gates.len()).collect();
        assert_eq!(
            numbers,
            expected,
            "the gate numbers in docs/tests/CI.md are not a complete \
             duplicate-free run: parsed {numbers:?} from {} entries",
            gates.len()
        );

        for (number, file) in &gates {
            let path = root.join(".github/workflows").join(file);
            assert!(
                path.is_file(),
                "docs/tests/CI.md lists {file} as gate {number}, but \
                 {} is not in this checkout",
                path.display()
            );
        }

        // The page states the count in words as well as listing it. Both have to
        // agree, because a reader who trusts the sentence never counts the list.
        let counted = gates.len();
        let word = match counted {
            9 => "nine",
            10 => "ten",
            11 => "eleven",
            other => panic!(
                "{other} gates are listed in docs/tests/CI.md, which this check \
                 has no spelling for -- add it here and to the page together"
            ),
        };
        assert!(
            page.contains(&format!("All {word} gates below are present")),
            "docs/tests/CI.md lists {counted} numbered gates, so it should say \
             \"All {word} gates below are present\", and it does not. The \
             sentence and the list have drifted apart"
        );
    }

    /// `hygiene.yml` is committed and is not one of the numbered gates.
    ///
    /// The page makes this exact claim, and it is the one workflow whose status
    /// is easy to state wrongly: it reaches the Rust sources, so it looks like a
    /// gate, but it is not one of the specified ones. Both halves are checked
    /// because the claim is only useful if both are true.
    #[test]
    fn the_hygiene_workflow_is_committed_and_is_not_a_numbered_gate() {
        let page = read("docs/tests/CI.md");
        let path = repo_root().join(".github/workflows/hygiene.yml");
        assert!(
            path.is_file(),
            "docs/tests/CI.md describes hygiene.yml as committed, but {} does \
             not exist",
            path.display()
        );
        for line in page.lines() {
            if line.starts_with("- `hygiene.yml`") && line.contains("(gate ") {
                panic!(
                    "docs/tests/CI.md says hygiene.yml is not one of the \
                     specified gates, yet lists it as a numbered gate: {line}"
                );
            }
        }
    }

    /// The pages and the manifest have to agree with the disk about `tests-rs/`.
    ///
    /// Checked in both directions, for the reason given in the module
    /// documentation: this tree is specified work that is expected to arrive, so
    /// its arrival must not break the gate. What fails is disagreement.
    #[test]
    fn the_tests_rs_claims_match_the_checkout() {
        let root = repo_root();
        let present = root.join("tests-rs").is_dir();

        let suite = read("docs/tests/TEST-SUITE.md");
        let manifest = read("curl-rs/Cargo.toml");

        // The two statements each page makes about the tree being absent.
        let suite_says_absent = suite.contains("not part of this checkout");
        let manifest_says_absent =
            manifest.contains("No such file or directory");

        if present {
            assert!(
                !suite_says_absent,
                "tests-rs/ is in this checkout, but docs/tests/TEST-SUITE.md \
                 still says it is \"not part of this checkout\". The specified \
                 tree has landed and the page needs updating"
            );
            assert!(
                !manifest_says_absent,
                "tests-rs/ is in this checkout, but curl-rs/Cargo.toml still \
                 records `ls tests-rs` as failing. Its [[test]] declarations \
                 should now be live rather than commented out"
            );
        } else {
            assert!(
                suite_says_absent,
                "tests-rs/ is absent, but docs/tests/TEST-SUITE.md does not say \
                 so where it refers to tests-rs/integration/. A reader would \
                 take the reference for a path they can open"
            );
            assert!(
                manifest_says_absent,
                "tests-rs/ is absent, but curl-rs/Cargo.toml does not record \
                 that measurement beside its commented-out [[test]] targets"
            );
            // With the tree absent, a live [[test]] target pointing into it
            // would fail the build outright, so the declarations must stay
            // commented out. Checked at line starts: the commented form is
            // `# [[test]]`, which does not begin with the bracket.
            for (index, line) in manifest.lines().enumerate() {
                assert!(
                    line.trim_start() != "[[test]]",
                    "curl-rs/Cargo.toml:{} declares a live [[test]] target \
                     while tests-rs/ is absent -- `cargo test` cannot resolve \
                     its path",
                    index + 1
                );
            }
        }
    }

    /// The parser and the two-direction check are exercised on inputs of both
    /// shapes, so a change that made either stop matching would be caught here
    /// rather than by silently passing over real pages.
    #[test]
    fn the_parsers_reject_what_they_should() {
        // Backticked names are picked up; prose ending in the suffix is not.
        let names = yml_names("see `a.yml` and `b.yml`, not `some file.yml`");
        assert_eq!(
            names,
            vec!["a.yml".to_string(), "b.yml".to_string()],
            "the parser should take backticked single tokens only"
        );

        // A repeated name is reported once, so a page that mentions a workflow
        // twice does not inflate the vacuity floor.
        assert_eq!(
            yml_names("`a.yml` again `a.yml`").len(),
            1,
            "duplicates must collapse"
        );

        // Unbackticked text yields nothing, which is why the existence test
        // asserts a floor on the parsed count rather than trusting it.
        assert!(
            yml_names("rust-build.yml with no backticks").is_empty(),
            "only backticked spans count"
        );
    }
}
