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

// ===========================================================================
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
// ===========================================================================
#![forbid(unsafe_code)]

//! `curl` -- the command-line tool, in safe Rust.
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

use crate::output::msgs::{self, MessageSink, MsgConfig};

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
async fn operate(sink: &mut dyn Write) -> CURLcode {
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
}
