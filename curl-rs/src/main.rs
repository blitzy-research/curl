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
//! [`output::msgs::SinkHandle`] over that sink first for exactly that reason.
//!
//! # What an invocation reaches, and what it does not
//!
//! [`operate`] drives the whole of `src/tool_operate.c:2260-2330`: the
//! no-arguments path, the 282-row option parser through
//! [`cli::args::parse_args`], the mandatory `--insecure` warning, and the
//! outcome dispatch in [`outcome_for`]. Of C's five "requested" outcomes,
//! `--manual` and `--dump-ca-embed` are served in full because their renderers
//! are part of this checkout; `--help`, `--version` and `--engine list` render
//! through `src/tool_help.c`, whose counterpart `curl-rs/src/cli/help.rs` is
//! not, and each reports that rather than returning a successful exit for
//! output nobody produced.
//!
//! What no invocation reaches is a transfer. A command line that parses cleanly
//! ends with a diagnostic naming the driver and `CURLE_NOT_BUILT_IN`, which is
//! documented as "a requested feature, protocol or option was not found built-in
//! in this libcurl due to a build-time decision".
//!
//! Thirteen of the files AAP section 0.3.1 assigns to this crate have no
//! implementation at this commit, enumerated here rather than gestured at
//! because every one of them is a separate planned unit of work and a reader
//! needs to know which:
//!
//! * the three-module operation driver, `operate/{mod,single,parallel}.rs`
//! * the option-to-`setopt` mapping, `config/to_setopts.rs`
//! * the remaining configuration stage, `config/ssls.rs`
//! * the seven transfer callbacks under [`callbacks`] --
//!   `{write,read,header,debug,seek,progress,socket}.rs`. That module is
//!   declared and declares none of them, which is why a parsed command line has
//!   nothing to hand a transfer.
//! * the `--libcurl` emitter, `libcurl_src.rs`
//!
//! Three that this list used to carry have landed:
//!
//! * `cli/help.rs`, the `--help` renderer and built-in-manual scanner. The
//!   renderer exists; wiring the `--help`, `--version` and `--engine list`
//!   dispatch arms to it belongs to the operation driver above.
//! * `cli/ipfs.rs`, the IPFS and IPNS gateway rewriting of `src/tool_ipfs.c`.
//!   The eighteen fixtures that exercise it still need an HTTP executor in the
//!   engine before they can run, because the rewrite sets `CURLUPART_SCHEME`
//!   and that setter requires a runnable scheme.
//! * `config/parseconfig.rs`, the `.curlrc` and `-K` reader. Its reader is
//!   complete and tested, but nothing reaches it yet: `ParseHost::parse_config`
//!   does not take the `&mut GlobalConfig` the re-entry needs, so no
//!   configuration file is loaded at run time. That is a signature gap in a
//!   delivered file rather than an absent file.
//!
//! That list is CHECKED, not merely written: `absent_target_gate` in
//! `src/bin/curlinfo.rs` holds the same thirteen paths together with the
//! seventeen `curl-rs-lib` and two `curl-rs-ffi` targets, and fails naming
//! any that has since landed. When it fails, this paragraph is what needs
//! updating.
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
//! - [`config`] -- `src/tool_cfgable.c` and `src/slist_wc.c`: the
//!   `GlobalConfig` and `OperationConfig` model, and the init and teardown
//!   lifecycle that `src/tool_main.c:186` and `:192` drive. This is where the
//!   file-scope `struct GlobalConfig *global` of `src/tool_cfgable.c:33-34`
//!   does *not* go: the value is constructed here and threaded down by
//!   reference, so nothing can reach it without being handed it.
//! - [`callbacks`] -- the seven `src/tool_cb_*.c` units the tool installs on
//!   the easy handle.
//! - [`terminal`] -- `src/terminal.c` and `src/tool_getpass.c`.
//! - [`util`] -- `src/tool_util.c` and `src/toolx/tool_time.c`.
//! - [`ca_embed`] -- `src/tool_ca_embed.c`, a build artifact rather than a
//!   committed source, produced by `build.rs`.
//! - [`urlglob`] -- `src/tool_urlglob.c`: the `{a,b}` / `[1-100]` expansion that
//!   turns one command-line URL into many transfers, and the `#1` substitution
//!   an `-o` file name uses to follow it.

mod ca_embed;
mod callbacks;
mod cli;
mod config;
mod output;
mod terminal;
mod urlglob;
mod util;

use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process::ExitCode;

use curl_rs_lib::{CURLcode, TraceConfig};

use crate::cli::args::{ParameterError, ParseHost};
use crate::cli::paramhlp::ByteSource;
use crate::cli::vars::{OsVarHost, VarHost};
use crate::config::{GlobalConfig, TraceType};
use crate::output::formparse::{ProcessStdin, StdinAccess};
use crate::output::msgs::{self, DiagnosticSink, MsgConfig, SinkHandle};

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
/// the allocation accounting, then the configuration, then the runtime, then
/// the invocation, then the exit status.
fn main() -> ExitCode {
    // `src/tool_main.c:148` -- `tool_init_stderr()`, before anything that can
    // fail.
    //
    // A [`SinkHandle`] rather than a bare `MessageSink` because `--stderr
    // <file>` is honoured from *inside* the option parser
    // (`src/tool_getparam.c:2312`), which needs the concrete sink at a moment
    // when the parser already holds it for emitting. C solves that with the
    // file-scope `FILE *tool_stderr` of `src/tool_stderr.c:29`; the handle is
    // the narrowest replacement for that global -- shared ownership of one
    // value, reachable from the two places that need it and from nowhere else.
    let mut sink = SinkHandle::init();

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

    // The verbosity nothing has yet been able to change: C's `global` is
    // zero-initialised until the option parser runs, so warnings and errors are
    // emitted and notes are not (`src/tool_msgs.c:81`, `:95`, `:130`).
    let boot = MsgConfig::new(false, false, false);

    // `src/tool_main.c:186` -- `result = globalconf_init();`, and `:187`'s
    // `if(!result)` guard on everything that follows. C returns the code
    // without calling `operate()` when it fails, and `globalconf_free()` at
    // `:192` runs only on the success path; here the value's own `Drop`
    // (`curl-rs/src/config/mod.rs:1993`) is that call, so the coupling C spells
    // out with an `if` is expressed by ownership and cannot be forgotten.
    let result = match GlobalConfig::init(&mut sink, &boot) {
        Err(code) => code,
        Ok(mut global) => match runtime() {
            Ok(runtime) => {
                // The production [`ParseHost`]: the six effects the parser
                // cannot perform itself (`curl-rs/src/cli/args.rs`'s
                // "Injected capabilities"). It shares the diagnostic channel
                // with `sink` above rather than owning a second one.
                let mut host = OsParseHost::new(sink.handle());

                // C's `main` receives `argv` and hands it to `operate(argc,
                // argv)` at `:189`; the command line is collected here for the
                // same reason -- `operate` is then a function of its arguments
                // and can be driven with any command line, which is what makes
                // the outcome mapping below testable without a subprocess.
                //
                // `args_os` rather than `args`: an argument is arbitrary bytes on
                // the four mandated targets and `std::env::args` panics on one
                // that is not valid Unicode, which curl accepts.
                let args: Vec<OsString> = std::env::args_os().collect();

                // C's `puts` and `curl_mprintf` write to the `stdout` global.
                // It is passed in rather than reached for so that `--manual` and
                // `--dump-ca-embed` can be exercised against a buffer, which is
                // the only way to assert their bytes without a subprocess
                // (AAP section 0.3.3's pattern P12).
                let mut out = io::stdout();

                runtime.block_on(operate(
                    &args,
                    &mut out,
                    &mut sink,
                    &mut host,
                    &mut global,
                ))
            }
            Err(error) => {
                // No `curl` counterpart, because C has no runtime to build. The
                // shape follows `src/tool_main.c:166` -- the one place C reports
                // a failed platform initialization -- which uses `errorf` and
                // returns the code rather than panicking. A panic here would
                // produce a Rust backtrace on standard error and an exit status
                // of 101, neither of which any fixture expects.
                msgs::errorf(
                    &mut sink,
                    &boot,
                    format_args!("failed to start the async runtime: {error}"),
                );
                CURLcode::FailedInit
            }
        },
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

/// The production [`ParseHost`]: the real filesystem, the real environment, the
/// real standard input and the real diagnostic channel.
///
/// `curl-rs/src/cli/args.rs` keeps the 282-row option parser a pure function of
/// its inputs by injecting the effects it cannot perform itself (AAP section
/// 0.3.3's pattern P12). Until this type existed the only implementation was the
/// `FakeHost` of that module's own tests, which is why no option could be
/// honoured: `parse_args` had nothing to run against outside a test binary.
///
/// # What each capability resolves to, and the two that cannot yet
///
/// | [`ParseHost`] method | C original | Resolved by |
/// |---|---|---|
/// | `exists` | `curlx_stat` in `existingfile`, `src/tool_getparam.c:2212` | [`std::fs::metadata`] |
/// | `file_time` | `getfiletime`, `:1636` | [`crate::output::filetime::getfiletime`] |
/// | `set_trace` | `curl_global_trace(config)`, `:790` | [`TraceConfig::apply_code`] |
/// | `set_stderr_file` | `tool_set_stderr_file`, `:2312` | [`SinkHandle::redirect`] |
/// | `help` | `tool_help(category)`, `:3003` | **absent** -- see below |
/// | `parse_config` | `parseconfig(...)`, `:2252` | **partly absent** -- see below |
///
/// GAP #4 and GAP #5 stand, and both are recorded on the trait rather than
/// worked around here. `curl-rs/src/cli/help.rs` and
/// `curl-rs/src/config/parseconfig.rs` are specified by AAP section 0.3.1 and
/// are not part of this checkout, and neither capability can be reproduced
/// without them:
///
/// * `tool_help` renders a 273-row table, 25 categories and a per-option scan of
///   the built-in manual (`src/tool_help.c:222-296`). Emitting an
///   approximation of it here would put a second printer in the tree, and the
///   two would then be free to disagree about bytes AAP section 0.8.1 freezes.
/// * `parseconfig` re-enters the parser for every line of the file
///   (`src/tool_parsecfg.c`), so it belongs with the module that owns that
///   re-entry. The half that *is* reproducible is reproduced: an unreadable
///   file yields exactly C's `cannot read config from '%s'` and
///   `PARAM_READ_ERROR` (`:267-270`).
///
/// Both therefore report their own absence through the diagnostic channel
/// rather than returning quietly, so that no caller can mistake "nothing was
/// printed" for "the request was served".
struct OsParseHost {
    /// The shared diagnostic channel, so that `--stderr` redirects the same
    /// sink the parser is emitting through.
    sink: SinkHandle,

    /// The live process environment and the real filesystem, for
    /// `--variable`'s `%name` and `@path` forms (`src/var.c:408`, `:446`).
    vars: OsVarHost,

    /// The process's standard input, for `-F name=@-` and `--variable name@-`
    /// (`src/tool_formparse.c:121-244`, `src/var.c:444`).
    stdin: ProcessStdin,

    /// `curl_global_trace`'s process-global token state
    /// (`lib/curl_trc.c:600-636`), held as a value.
    ///
    /// GAP #2 narrows rather than closes. Applying the tokens is what validates
    /// them, and that is what `set_trace`'s boolean reports, so `--trace-config`
    /// now behaves exactly as C's `curl_global_trace` does at the option
    /// boundary. What no consumer reads yet is the resulting configuration: the
    /// trace emitters live in `curl-rs-lib`, whose `trace` module is
    /// `pub(crate)` by design -- only [`TraceConfig`] itself crosses the crate
    /// boundary (`curl-rs-lib/src/lib.rs:1303`) -- so the value is owned here
    /// and handed on when the engine grows the sink that consumes it.
    trace: TraceConfig,
}

impl OsParseHost {
    /// Binds the real operating system to a shared diagnostic channel.
    fn new(sink: SinkHandle) -> Self {
        Self {
            sink,
            vars: OsVarHost,
            stdin: ProcessStdin::new(),
            trace: TraceConfig::new(),
        }
    }
}

/// Forwarded to [`OsVarHost`], which is `src/var.c`'s three reaches for the
/// operating system.
impl VarHost for OsParseHost {
    fn getenv(&self, name: &[u8]) -> Option<Vec<u8>> {
        self.vars.getenv(name)
    }

    fn open(&mut self, path: &[u8]) -> io::Result<Box<dyn ByteSource>> {
        self.vars.open(path)
    }

    fn stdin(&mut self) -> Box<dyn ByteSource> {
        self.vars.stdin()
    }
}

/// Forwarded to [`ProcessStdin`], which is what `src/tool_formparse.c` does
/// with the `stdin` global.
impl StdinAccess for OsParseHost {
    fn regular_extent(&mut self) -> Option<(i64, i64)> {
        self.stdin.regular_extent()
    }

    fn read_all(&mut self, out: &mut Vec<u8>) -> io::Result<()> {
        self.stdin.read_all(out)
    }

    fn read_chunk(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.stdin.read_chunk(buffer)
    }

    fn seek_to(&mut self, offset: i64) -> io::Result<()> {
        self.stdin.seek_to(offset)
    }
}

impl ParseHost for OsParseHost {
    /// `existingfile(filename)` -- `src/tool_getparam.c:2206-2216`.
    ///
    /// C inspects only whether `curlx_stat` succeeded, and `curlx_stat` is
    /// `stat()` rather than `lstat()` on the four mandated targets, so
    /// [`std::fs::metadata`] -- which follows symbolic links -- is the same
    /// question. A dangling link reports `false` in both.
    fn exists(&mut self, path: &[u8]) -> bool {
        std::fs::metadata(Path::new(OsStr::from_bytes(path))).is_ok()
    }

    /// `getfiletime(nextarg, &value)` -- `src/tool_getparam.c:1636`.
    ///
    /// The whole of the behaviour, including the frozen
    /// `Failed to get filetime: %s` warning of `src/tool_filetime.c:78-79`,
    /// belongs to [`crate::output::filetime::getfiletime`]; this only supplies
    /// it the channel and the verbosity, and turns its two-valued return into
    /// the [`Option`] the parser wants. `stamp` is read only on success, as
    /// `:1637`'s `if(!rc)` requires.
    fn file_time(
        &mut self,
        path: &[u8],
        sink: &mut dyn DiagnosticSink,
        msgs: &MsgConfig,
    ) -> Option<i64> {
        let mut stamp = 0_i64;
        let outcome = crate::output::filetime::getfiletime(
            sink,
            msgs,
            Path::new(OsStr::from_bytes(path)),
            &mut stamp,
        );

        if outcome == crate::output::filetime::FILETIME_SUCCESS {
            Some(stamp)
        } else {
            None
        }
    }

    /// `curl_global_trace(config)` -- `src/tool_getparam.c:790`, `:792`, `:806`.
    ///
    /// C tests the returned `CURLcode` for truth and turns a non-`CURLE_OK`
    /// answer into `PARAM_NO_MEM`, which is what the boolean here reports. The
    /// token grammar -- the `+`/`-` prefixes, the four keywords, the `doh`
    /// alias, the 32-byte token cap and the empty-token stop -- is
    /// [`TraceConfig::apply`]'s, so nothing about `--trace-config`'s acceptance
    /// is decided in this crate.
    ///
    /// The bytes are handed through undecoded, because `curl_global_trace` takes
    /// a `const char *` and `trc_opt()` never decodes it.
    fn set_trace(&mut self, config: &str) -> bool {
        self.trace.apply_code(Some(config.as_bytes())) == CURLcode::Ok
    }

    /// `tool_set_stderr_file(nextarg)` -- `src/tool_getparam.c:2312`.
    ///
    /// The redirection lands on the sink the parser is emitting through, so the
    /// very next diagnostic goes to the new destination -- which is what C's
    /// file-scope `tool_stderr` achieves and what the shared handle is for.
    fn set_stderr_file(&mut self, path: &[u8], msgs: &MsgConfig) {
        self.sink.redirect(msgs, Some(OsStr::from_bytes(path)));
    }

    /// `tool_help(category)` -- `src/tool_getparam.c:3003`.
    ///
    /// GAP #4: the renderer is `curl-rs/src/cli/help.rs`, which is not part of
    /// this checkout. Reporting that is the whole of this body, and it is
    /// reported rather than passed over in silence because the caller turns
    /// `PARAM_HELP_REQUESTED` into a *successful* exit in C
    /// (`src/tool_operate.c:2303-2305`): a silent return would claim that help
    /// had been printed.
    fn help(
        &mut self,
        category: Option<&str>,
        sink: &mut dyn DiagnosticSink,
        msgs: &MsgConfig,
    ) {
        match category {
            Some(category) => msgs::errorf(
                sink,
                msgs,
                format_args!(
                    "--help {category} is not built in: the help text is \
                     rendered by tool_help (src/tool_help.c:222), which this \
                     build does not carry"
                ),
            ),
            None => msgs::errorf(
                sink,
                msgs,
                format_args!(
                    "--help is not built in: the help text is rendered by \
                     tool_help (src/tool_help.c:222), which this build does \
                     not carry"
                ),
            ),
        }
    }

    /// `parseconfig(filename, max_recursive, NULL)` --
    /// `src/tool_getparam.c:2252`.
    ///
    /// The unreadable-file half is C's, byte for byte: `src/tool_parsecfg.c:267`
    /// sets `PARAM_READ_ERROR` when the file cannot be opened and `:269-270`
    /// then emits `cannot read config from '%s'` through `errorf`. Measured
    /// against the oracle binary: `curl -K /nonexistent/config/file` prints that
    /// line, then `option -K: error encountered when reading a file`, then the
    /// try-line, and exits **26** -- `CURLE_READ_ERROR`.
    ///
    /// GAP #5 covers the other half. A file that *can* be read has to be parsed
    /// line by line back through [`crate::cli::args`]'s `getparameter`, and
    /// that re-entry belongs to `curl-rs/src/config/parseconfig.rs`, which is
    /// not part of this checkout. `PARAM_LIBCURL_DOESNT_SUPPORT` is the closest
    /// truthful answer in C's frozen vocabulary -- "the installed libcurl
    /// version does not support this", and `src/tool_operate.c:2329` maps it to
    /// `CURLE_FAILED_INIT` -- and the diagnostic above it names exactly what is
    /// owed, so the outcome cannot be mistaken for a file that parsed to
    /// nothing.
    fn parse_config(
        &mut self,
        filename: &[u8],
        max_recursive: i32,
        sink: &mut dyn DiagnosticSink,
        msgs: &MsgConfig,
    ) -> ParameterError {
        // The budget is C's and is already decremented by the caller
        // (`src/tool_getparam.c:2246`). Nothing here can recurse, so nothing
        // here can spend it; it is named rather than dropped so that the
        // signature stays the one `parseconfig` needs when it lands.
        let _ = max_recursive;
        let path = Path::new(OsStr::from_bytes(filename));
        let shown = path.display();

        // `src/tool_parsecfg.c:265-270` -- "could not open the file", then the
        // frozen message. `File::open` answers the same question
        // `fopen(filename, FOPEN_READTEXT)` answers at `:114`.
        if std::fs::File::open(path).is_err() {
            msgs::errorf(
                sink,
                msgs,
                format_args!("cannot read config from '{shown}'"),
            );
            return ParameterError::ReadError;
        }

        msgs::errorf(
            sink,
            msgs,
            format_args!(
                "cannot read config from '{shown}': configuration files are \
                 parsed by curl-rs/src/config/parseconfig.rs \
                 (src/tool_parsecfg.c), which this build does not carry"
            ),
        );
        ParameterError::LibcurlDoesntSupport
    }
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
/// gives for an absent or URL-free `.curlrc` -- and the answer the oracle binary
/// gives under `env -i`, measured: exit 2 and the try-line alone.
///
/// The same absence removes C's implicit `.curlrc` read for *every* other
/// invocation (`:2280`, taken unless the first argument begins `-q` or is
/// `--disable`), and removes the `Read config file from '%s'` note at `:2296`
/// with it. Both arrive with that module; nothing here approximates them,
/// because a partial configuration reader would apply some of a user's defaults
/// and silently drop the rest.
///
/// # Any other invocation goes through the option parser
///
/// `parse_args()` (`src/tool_operate.c:2293`) is
/// [`crate::cli::args::parse_args`], and it is called here with the production
/// [`OsParseHost`]. Its outcome is dispatched by [`outcome_for`], which
/// reproduces `src/tool_operate.c:2297-2330` arm for arm.
///
/// Two of C's five "requested" outcomes are served in full, because their
/// renderers are part of this checkout: `--manual` writes the built-in manual
/// through [`crate::cli::hugehelp::hugehelp`], and `--dump-ca-embed` writes
/// [`crate::ca_embed::bundle`] -- or nothing at all, and still succeeds, when no
/// bundle was embedded, exactly as C's `#ifdef CURL_CA_EMBED` does. Every parse
/// *failure* is served in full too: the code, the `option <opt>: <reason>`
/// composition and the try-line are all C's.
///
/// What is not served is named where it is missing rather than blanketed over
/// the whole command line, which is the substantive change from the previous
/// revision of this function: it returned `CURLE_NOT_BUILT_IN` for *every*
/// non-empty invocation, so `curl --bogus` could not report an unknown option
/// and `curl --manual` could not print the manual.
///
/// # The mandatory insecure warning is reached here
///
/// [`crate::output::msgs::warn_insecure_flags`] is called on the pre-transfer
/// path, which is where `src/config2setopts.c:378-393` switches verification
/// off. It is placed in the driver rather than left to the option layer so that
/// the door is *executed* on every invocation: AAP section 0.8.4's gate 10 asks
/// for a warning that cannot fail to appear, and a call site that only exists in
/// a module nothing reaches would not deliver that.
///
/// The three flags now come from the parsed configuration chain, through
/// [`insecure_flags`], rather than from three literals. See that function for
/// why the chain is reduced to one call rather than warning per operation.
async fn operate<H: ParseHost>(
    args: &[OsString],
    out: &mut dyn Write,
    sink: &mut dyn DiagnosticSink,
    host: &mut H,
    global: &mut GlobalConfig,
) -> CURLcode {
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

    // `src/tool_operate.c:2283` -- `argc == 1`. `args` holds the whole command
    // line, `argv[0]` included, because `crate::cli::args::parse_args` starts its
    // walk at index 1 exactly as `src/tool_getparam.c:3060` does, so `argc == 1`
    // is `args.len() < 2`.
    if args.len() < 2 {
        // `src/tool_operate.c:2284` -- `helpf(NULL)`, the try-line alone.
        msgs::helpf(sink, None);
        // `src/tool_operate.c:2285`.
        return CURLcode::FailedInit;
    }

    // `src/tool_operate.c:2293` -- `ParameterError err = parse_args(argc,
    // argv);`. The 282-row inventory, the `--` terminator, the bare-URL form,
    // `--next`, the `option <opt>: <reason>` reporting and the try-line are all
    // this call's; nothing about the surface is decided here.
    let parsed = cli::args::parse_args(args, global, host, sink);

    // The gates C reads from `global` once the parser has filled it in
    // (`src/tool_msgs.c:81`, `:95`, `:130`). C computes them at each emission
    // site; this is the same three predicates, taken after the parse so that
    // `--silent`, `--show-error` and `--verbose` are in force for everything
    // below -- which is exactly what `src/tool_operate.c:2295-2297`'s comment
    // "After parse_args so notef knows the verbosity" is about.
    let config = MsgConfig::new(
        global.silent,
        global.showerror,
        global.tracetype != TraceType::None,
    );

    // `src/config2setopts.c:378-393` is the point at which certificate
    // verification is switched off, and therefore -- per AAP section 0.1.1
    // goal G4, section 0.8.1 and validation gate 10 of section 0.8.4 -- the
    // point at which the mandatory warning must be emitted. It sits here, on
    // the pre-transfer path, so that the door is reached on every invocation
    // rather than depending on a future caller remembering it.
    //
    // The three bits are the PARSED ones, reduced over the whole `--next` chain
    // by `insecure_flags`, and they reach the warning through the typed
    // `InsecureRequest` seam rather than as three positional literals. Both
    // halves matter. The call used to read `warn_insecure_flags(sink, false,
    // false, false)`, and the literals were the defect: they would have gone on
    // reporting "nothing insecure was requested" after the option parser
    // landed, after `--insecure` began to be honoured and after certificate
    // verification began to be switched off, and they would have kept compiling
    // the whole way. `crate::config::OperationConfig` implements the same trait
    // by reading the three bits of `src/tool_cfgable.h:258-261`, so there is no
    // longer a spelling of this call that passes an anonymous boolean.
    //
    // The bits are read even when the parse FAILED, deliberately: `curl -k
    // --bogus` accepted `-k` before it rejected `--bogus`, so verification was
    // asked to be switched off and saying so is the point of the requirement.
    let (insecure, doh_insecure, proxy_insecure) = insecure_flags(global);
    let requested = msgs::RequestedInsecurely {
        insecure,
        doh_insecure,
        proxy_insecure,
    };

    msgs::warn_insecure_flags(sink, &requested);

    match parsed {
        // `src/tool_operate.c:2333-2340` and beyond -- `easysrc_init()` when
        // `--libcurl` was given, then `run_all_transfers`. Neither is part of
        // this checkout: the emitter is `curl-rs/src/libcurl_src.rs` and the
        // driver is `curl-rs/src/operate/`, both specified by AAP section 0.3.1.
        //
        // Every option on the command line has been parsed, validated and
        // recorded in `global` by this point, so what is missing is the transfer
        // itself and the code says exactly that. `CURLE_NOT_BUILT_IN` is
        // documented as "a requested feature, protocol or option was not found
        // built-in in this libcurl due to a build-time decision", which is a
        // truthful description of this configuration -- and it is now reached
        // only here, rather than for every invocation.
        Ok(()) => {
            msgs::errorf(
                sink,
                &config,
                format_args!(
                    "no transfer was performed: the operation driver \
                     (curl-rs/src/operate/, src/tool_operate.c) is not part of \
                     this build"
                ),
            );
            CURLcode::NotBuiltIn
        }
        Err(error) => outcome_for(error, out, sink, &config),
    }
}

/// The three verification-off flags, reduced over the whole `--next` chain.
///
/// # Why a reduction rather than one warning per operation
///
/// C's three `if` statements live in `config2setopts` (`:379`, `:385`, `:390`),
/// which runs once per operation, so a chain of two `--insecure` transfers would
/// reach them twice. That says nothing about how many *warnings* to emit,
/// because -- measured against the oracle binary --
/// `curl --insecure http://127.0.0.1:1/a --next --insecure http://127.0.0.1:1/b`
/// emits **no warning at all**: `src/config2setopts.c:379-393` contains three
/// bare `my_setopt_long` blocks and no `warnf`. The warning is an AAP
/// requirement (section 0.1.1 goal G4, section 0.8.4 gate 10) with no C
/// behaviour to imitate, which `crate::output::msgs::warn_insecure` documents at
/// length.
///
/// So the requirement is read as it is written -- a warning must be emitted
/// before proceeding, per flag that was asked for -- and one reduction over the
/// chain delivers that with the single unconditional call site that gate 10 is
/// about. Warning once per operation would repeat an identical line for a
/// repeated flag while adding nothing a reader could act on.
///
/// The chain is walked by index rather than by iterator because
/// `crate::config::ConfigChain` deliberately exposes no iterator: it owns its
/// elements to replace C's intrusive `next`/`prev` pointers, and `get` plus
/// `len` is the accessor pair it offers.
fn insecure_flags(global: &GlobalConfig) -> (bool, bool, bool) {
    let mut origin = false;
    let mut doh = false;
    let mut proxy = false;

    for at in 0..global.chain.len() {
        if let Some(config) = global.chain.get(at) {
            // `src/tool_cfgable.h:258-261` -- the three bits, in declaration
            // order, which is also the order `warn_insecure_flags` emits in.
            origin |= config.insecure_ok;
            doh |= config.doh_insecure_ok;
            proxy |= config.proxy_insecure_ok;
        }
    }

    (origin, doh, proxy)
}

/// `src/tool_operate.c:2297-2330`: what a non-`PARAM_OK` parse outcome means.
///
/// C sets `result = CURLE_OK` first (`:2298`) and then either produces output or
/// overrides the code, so five of the outcomes are *requests* rather than
/// failures. The arms below are C's, in C's order, with two of the five served in
/// full and three reporting an absent renderer.
///
/// # The three that cannot be served, and why they do not return `CURLE_OK`
///
/// `tool_help`, `tool_version_info` and `tool_list_engines` are all defined in
/// `src/tool_help.c` (`:222`, `:311`, `:389`), whose Rust counterpart
/// `curl-rs/src/cli/help.rs` is specified by AAP section 0.3.1 and is not part of
/// this checkout. C's own precedent for an output capability that was configured
/// out is `--manual` without `USE_MANUAL` at `:2308-2311`: warn, and keep
/// `CURLE_OK`. That precedent is deliberately *not* followed, for one reason --
/// it describes a supported build configuration, whereas this describes work that
/// has not landed. Returning zero would report success for output nobody
/// produced, which is precisely the inert-entry-point defect this workspace is
/// under review for. Each of the three therefore emits a diagnostic naming the
/// missing renderer and yields `CURLE_NOT_BUILT_IN`, and when
/// `curl-rs/src/cli/help.rs` lands these three arms become C's exactly by
/// calling it.
fn outcome_for(
    error: ParameterError,
    mut out: &mut dyn Write,
    sink: &mut dyn DiagnosticSink,
    config: &MsgConfig,
) -> CURLcode {
    match error {
        // `:2303-2305` -- "already done": `getparameter` calls `tool_help`
        // before returning this. `OsParseHost::help` is what ran, and it has
        // already reported that the renderer is absent, so nothing is said twice
        // here.
        ParameterError::HelpRequested => CURLcode::NotBuiltIn,

        // `:2307-2312` -- `hugehelp()`, served in full.
        //
        // The manual goes to standard output, because C emits it with `puts`
        // (`src/mkhelp.pl:231-236`). The write result is discarded for the same
        // reason C discards `puts`'s: see
        // `crate::cli::hugehelp::hugehelp`.
        ParameterError::ManualRequested => {
            // `&mut out` rather than `out`: `hugehelp` is generic over a `Sized`
            // writer, and `&mut &mut dyn Write` satisfies that through
            // `impl<W: Write + ?Sized> Write for &mut W`. Reborrowing here keeps
            // that generic bound as narrow as the module wrote it.
            let _ = cli::hugehelp::hugehelp(&mut out);
            let _ = out.flush();
            CURLcode::Ok
        }

        // `:2314-2315` -- `tool_version_info()`.
        ParameterError::VersionInfoRequested => {
            msgs::errorf(
                sink,
                config,
                format_args!(
                    "--version is not built in: the banner is rendered by \
                     tool_version_info (src/tool_help.c:311), which this build \
                     does not carry"
                ),
            );
            CURLcode::NotBuiltIn
        }

        // `:2317-2318` -- `tool_list_engines()`.
        ParameterError::EnginesRequested => {
            msgs::errorf(
                sink,
                config,
                format_args!(
                    "--engine list is not built in: the list is rendered by \
                     tool_list_engines (src/tool_help.c:389), which this build \
                     does not carry"
                ),
            );
            CURLcode::NotBuiltIn
        }

        // `:2320-2324` -- `curl_mprintf("%s", curl_ca_embed)` inside
        // `#ifdef CURL_CA_EMBED`, served in full.
        //
        // Standard output, no trailing newline, and *nothing at all* when no
        // bundle was embedded -- which still succeeds, because C's `#ifdef`
        // simply compiles the statement away. Measured against the oracle
        // binary: `curl --dump-ca-embed` on a build without one prints nothing
        // and exits 0.
        ParameterError::CaEmbedRequested => {
            if let Some(bundle) = ca_embed::bundle() {
                let _ = out.write_all(bundle);
                let _ = out.flush();
            }
            CURLcode::Ok
        }

        // `:2325-2326`
        ParameterError::LibcurlUnsupportedProtocol => {
            CURLcode::UnsupportedProtocol
        }

        // `:2327-2328`
        ParameterError::ReadError => CURLcode::ReadError,

        // `:2329-2330` -- C's `else`. Every remaining outcome, listed rather
        // than wildcarded so that a new variant cannot join this arm without
        // someone choosing to put it here. `Ok` and `NextOperation` cannot
        // arrive: the first is not an error and the second never escapes
        // `parse_args` (`src/tool_getparam.c:3087-3110`).
        ParameterError::Ok
        | ParameterError::OptionUnknown
        | ParameterError::ConfigOptionUnknown
        | ParameterError::RequiresParameter
        | ParameterError::BadUse
        | ParameterError::GotExtraParameter
        | ParameterError::BadNumeric
        | ParameterError::NegativeNumeric
        | ParameterError::LibcurlDoesntSupport
        | ParameterError::NoMem
        | ParameterError::NextOperation
        | ParameterError::NoPrefix
        | ParameterError::NumberTooLarge
        | ParameterError::ContdispResumeFrom
        | ParameterError::ExpandError
        | ParameterError::BlankString
        | ParameterError::VarSyntax
        | ParameterError::Recursion => CURLcode::FailedInit,
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs;
    use std::io::{self, Write};
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};

    use curl_rs_lib::CURLcode;

    use super::{insecure_flags, operate, outcome_for, runtime, OsParseHost};
    use crate::cli::args::{ParameterError, ParseHost};
    use crate::cli::paramhlp::{ByteSource, SeekSource};
    use crate::cli::vars::VarHost;
    use crate::config::{GlobalConfig, OperationConfig};
    use crate::output::formparse::StdinAccess;
    use crate::output::msgs::{self, DiagnosticSink, MsgConfig, SinkHandle};

    /// The try-line of `src/tool_msgs.c:118-122`, with the `curl: ` prefix of
    /// `:113`. Measured byte for byte against the oracle binary `/usr/bin/curl`.
    const TRY_LINE: &str =
        "curl: try 'curl --help' or 'curl --manual' for more information\n";

    /// The default verbosity: C's zero-initialised `global`.
    fn boot() -> MsgConfig {
        MsgConfig::new(false, false, false)
    }

    /// Everything one `operate` call produced.
    struct Run {
        /// The `CURLcode` `main` would turn into the process exit status.
        code: CURLcode,
        /// Everything written to the diagnostic channel, as text.
        diagnostics: String,
        /// Everything written to standard output.
        stdout: Vec<u8>,
        /// Every `--help` category the parser forwarded to the host.
        helped: Vec<Option<String>>,
    }

    /// Drives one whole invocation over a synthetic command line.
    ///
    /// `operate` takes its arguments and both output streams rather than reading
    /// the process's, exactly as C's `operate(argc, argv)` takes its own, so an
    /// invocation is driven here with no subprocess, no terminal and no
    /// filesystem writes. `argv[0]` is supplied because the parser skips index
    /// 0, as `src/tool_getparam.c:3060` does.
    fn run(arguments: &[&str]) -> Run {
        let mut argv: Vec<OsString> = vec![OsString::from("curl")];
        argv.extend(arguments.iter().map(OsString::from));

        let runtime = runtime().expect("the current-thread runtime must build");
        let mut sink: Vec<u8> = Vec::new();
        let mut stdout: Vec<u8> = Vec::new();
        let mut global = GlobalConfig::init(&mut sink, &boot())
            .expect("globalconf_init must succeed on this platform");
        let mut host = TestHost::default();

        let code = runtime.block_on(operate(
            &argv,
            &mut stdout,
            &mut sink,
            &mut host,
            &mut global,
        ));

        Run {
            code,
            diagnostics: String::from_utf8(sink)
                .expect("diagnostics are UTF-8 here"),
            stdout,
            helped: host.helped,
        }
    }

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

    // -- the invocation paths, against the oracle binary's measured answers --

    #[test]
    fn no_arguments_emits_the_try_line_alone_and_fails_init() {
        // `src/tool_operate.c:2283-2287`, and the oracle: bare `curl` writes the
        // try-line and nothing else, and exits 2.
        let run = run(&[]);

        assert_eq!(run.code, CURLcode::FailedInit);
        assert_eq!(run.code.as_i32(), 2);
        assert_eq!(run.diagnostics, TRY_LINE);
        assert!(run.stdout.is_empty());
    }

    #[test]
    fn an_unknown_option_is_reported_by_the_parser_and_fails_init() {
        // THE ASSERTION THIS PHASE EXISTS FOR. Before `parse_args` was wired in,
        // this invocation returned `CURLE_NOT_BUILT_IN` with a message about
        // option parsing being absent -- for every option, valid or not. The
        // oracle's answer is exit 2, `curl: option --bogus: is unknown`, then the
        // try-line, and that is now what comes out.
        let run = run(&["--bogus"]);

        assert_eq!(run.code, CURLcode::FailedInit);
        assert_eq!(
            run.diagnostics,
            format!("curl: option --bogus: is unknown\n{TRY_LINE}")
        );
    }

    #[test]
    fn a_missing_argument_is_reported_by_the_parser() {
        // The oracle: `curl --stderr` prints
        // `curl: option --stderr: requires parameter` and exits 2.
        let run = run(&["--stderr"]);

        assert_eq!(run.code, CURLcode::FailedInit);
        assert_eq!(
            run.diagnostics,
            format!("curl: option --stderr: requires parameter\n{TRY_LINE}")
        );
    }

    #[test]
    fn next_without_a_url_reports_both_frozen_lines() {
        // Measured against the oracle: `curl --next` emits
        // `curl: missing URL before --next` (`src/tool_getparam.c:3106-3109`),
        // then `curl: option --next: is badly used here` (`:3141-3144`), then the
        // try-line, and exits 2. All three come from the parser; this asserts
        // that the wiring neither swallows nor reorders them.
        let run = run(&["--next"]);

        assert_eq!(run.code, CURLcode::FailedInit);
        assert_eq!(
            run.diagnostics,
            format!(
                "curl: missing URL before --next\ncurl: option --next: is \
                 badly used here\n{TRY_LINE}"
            )
        );
    }

    #[test]
    fn a_url_parses_and_then_reports_the_absent_transfer_driver() {
        // A well-formed command line now reaches the end of the parse, so the
        // only thing left to report is the missing driver. That distinction is
        // the point: the code names what is actually absent instead of refusing
        // every option.
        let run = run(&["http://example.invalid/"]);

        assert_eq!(run.code, CURLcode::NotBuiltIn);
        assert_eq!(run.code.as_i32(), 4);
        assert!(
            run.diagnostics.contains("no transfer was performed"),
            "expected the driver report, got {:?}",
            run.diagnostics
        );
        // The parse succeeded, so no try-line: `helpf` is reached only from a
        // failing outcome (`src/tool_getparam.c:3133-3145`).
        assert!(
            !run.diagnostics.contains("try 'curl --help'"),
            "a successful parse must not emit the try-line, got {:?}",
            run.diagnostics
        );
    }

    // -- F7-05: the three flags come from the parsed chain --------------------

    #[test]
    fn insecure_is_taken_from_the_parsed_chain_and_warns_per_flag() {
        // The three arguments used to be literal `false`s, so no invocation
        // could ever warn. Each flag now produces its own warning, in
        // `src/config2setopts.c`'s order: origin (`:379`), DoH (`:385`), proxy
        // (`:390`).
        let one = run(&["--insecure", "http://example.invalid/"]);
        assert!(
            one.diagnostics
                .contains("using --insecure makes the transfer insecure"),
            "expected the mandatory warning, got {:?}",
            one.diagnostics
        );

        // `--insecure` and `--proxy-insecure` are plain `ARG_BOOL` rows
        // (`src/tool_getparam.c:179`, `:256`), so both are reachable from the
        // command line today. `--doh-insecure` is not, and that is asserted in
        // its own test below rather than glossed over here.
        let pair =
            run(&["--insecure", "--proxy-insecure", "http://example.invalid/"]);
        let origin = pair
            .diagnostics
            .find("--insecure makes")
            .expect("the origin warning must be emitted");
        let proxy = pair
            .diagnostics
            .find("--proxy-insecure makes")
            .expect("the proxy warning must be emitted");
        assert!(
            origin < proxy,
            "the warnings must follow src/config2setopts.c's order, got {:?}",
            pair.diagnostics
        );
    }

    #[test]
    fn doh_insecure_is_refused_while_tls_is_not_advertised() {
        // MEASURED, and the reason the test above uses `--proxy-insecure`
        // instead: `src/tool_getparam.c:126` marks `--doh-insecure`
        // `ARG_BOOL|ARG_TLS`, and the gate at `:2991-2994` turns every `ARG_TLS`
        // row into `PARAM_LIBCURL_DOESNT_SUPPORT` when `feature_ssl` is false.
        // `curl-rs-lib/src/version.rs` derives that feature from
        // `ENGINE_TLS.is_present()`, which is currently false, so the option is
        // refused -- exactly as it is by a C curl built without TLS. Truthful
        // advertisement is what produces this, and AAP section 0.6.5 requires
        // it, so the refusal is correct rather than a defect to route around.
        let run = run(&["--doh-insecure", "http://example.invalid/"]);

        assert_eq!(run.code, CURLcode::FailedInit);
        assert_eq!(
            run.diagnostics,
            format!(
                "curl: option --doh-insecure: the installed libcurl version \
                 does not support this\n{TRY_LINE}"
            )
        );
    }

    #[test]
    fn the_reduction_covers_all_three_bits_and_the_whole_chain() {
        // `insecure_flags` reduces the three bits over every operation, and the
        // DoH bit is exercised here because the command line cannot reach it
        // while TLS is unadvertised. Setting the fields directly is what makes
        // the reduction itself testable rather than the parser.
        let mut sink: Vec<u8> = Vec::new();
        let mut global = GlobalConfig::init(&mut sink, &boot())
            .expect("globalconf_init must succeed on this platform");

        assert_eq!(insecure_flags(&global), (false, false, false));

        // The first operation carries the origin bit.
        global
            .chain
            .first_mut()
            .expect("globalconf_init allocates one operation")
            .insecure_ok = true;
        assert_eq!(insecure_flags(&global), (true, false, false));

        // A second and a third operation carry one bit each, so a reduction
        // that only read `current()` or `first()` would miss them.
        let at = global
            .chain
            .append(OperationConfig::new())
            .expect("appending an operation must succeed");
        global
            .chain
            .get_mut(at)
            .expect("the operation just appended must be there")
            .doh_insecure_ok = true;

        let at = global
            .chain
            .append(OperationConfig::new())
            .expect("appending an operation must succeed");
        global
            .chain
            .get_mut(at)
            .expect("the operation just appended must be there")
            .proxy_insecure_ok = true;

        assert_eq!(global.chain.len(), 3);
        assert_eq!(insecure_flags(&global), (true, true, true));
    }

    #[test]
    fn nothing_is_warned_when_no_flag_was_given() {
        // C's behaviour with all three bits clear: its three `if` statements are
        // simply not taken. The requirement is a warning when verification is
        // switched off, not a warning on every run.
        let run = run(&["http://example.invalid/"]);

        assert!(
            !run.diagnostics.contains("makes the transfer insecure"),
            "no flag was given, so nothing may be warned: {:?}",
            run.diagnostics
        );
    }

    #[test]
    fn a_flag_on_a_later_operation_still_warns() {
        // `insecure_flags` reduces over the whole `--next` chain, so a flag that
        // only the second operation carries is still reported. Reading only
        // `chain.current()` would miss it.
        let run = run(&[
            "http://example.invalid/a",
            "--next",
            "--insecure",
            "http://example.invalid/b",
        ]);

        assert!(
            run.diagnostics
                .contains("using --insecure makes the transfer insecure"),
            "expected the warning for the second operation, got {:?}",
            run.diagnostics
        );
    }

    #[test]
    fn a_flag_accepted_before_a_parse_failure_still_warns() {
        // `curl -k --bogus` accepted `-k` before it rejected `--bogus`, so
        // verification WAS asked to be switched off. The warning is emitted from
        // `operate`'s own statement level, ahead of the outcome dispatch, so it
        // does not depend on the parse having succeeded.
        let run = run(&["-k", "--bogus"]);

        assert_eq!(run.code, CURLcode::FailedInit);
        assert!(
            run.diagnostics
                .contains("using --insecure makes the transfer insecure"),
            "expected the warning before the failure report, got {:?}",
            run.diagnostics
        );
        assert!(
            run.diagnostics.contains("option --bogus: is unknown"),
            "the failure must still be reported, got {:?}",
            run.diagnostics
        );
    }

    // -- the five "requested" outcomes ---------------------------------------

    #[test]
    fn the_manual_is_served_in_full_and_succeeds() {
        // `src/tool_operate.c:2307-2311` -- `hugehelp()`, which C emits with
        // `puts` (`src/mkhelp.pl:231-236`): every element followed by exactly
        // one line feed, to standard output, with nothing on the diagnostic
        // channel.
        let mut out: Vec<u8> = Vec::new();
        let mut sink: Vec<u8> = Vec::new();
        let code = outcome_for(
            ParameterError::ManualRequested,
            &mut out,
            &mut sink,
            &boot(),
        );

        assert_eq!(code, CURLcode::Ok);
        assert!(sink.is_empty(), "the manual is not a diagnostic");

        // Byte-identical to what the module itself writes, rather than a
        // restatement of its line arithmetic: `crate::cli::hugehelp` already owns
        // and tests the folded-blank rendering, and a second copy of that
        // reasoning here would be free to disagree with it.
        let mut expected: Vec<u8> = Vec::new();
        let _ = crate::cli::hugehelp::hugehelp(&mut expected);
        assert_eq!(out, expected);

        // And it is a real manual rather than an empty artifact. The first
        // element is the first line of the five-line ASCII logo
        // `src/mkhelp.pl:20-27` prepends, which carries that script's leading
        // tab -- so this also pins the START of what was written, which is the
        // part a truncating write would corrupt first.
        assert!(crate::cli::hugehelp::manual_lines() > 1000);
        assert!(out.starts_with(b"\t"));
    }

    #[test]
    fn dump_ca_embed_writes_exactly_the_bundle_and_succeeds() {
        // `src/tool_operate.c:2320-2324`: the statement sits inside
        // `#ifdef CURL_CA_EMBED`, so an unconfigured build prints nothing and
        // still exits 0 -- measured against the oracle binary, which has no
        // embedded bundle. A configured build writes the payload with no
        // trailing newline, because C uses `curl_mprintf("%s", ...)`.
        let mut out: Vec<u8> = Vec::new();
        let mut sink: Vec<u8> = Vec::new();
        let code = outcome_for(
            ParameterError::CaEmbedRequested,
            &mut out,
            &mut sink,
            &boot(),
        );

        assert_eq!(code, CURLcode::Ok);
        assert!(sink.is_empty());
        match crate::ca_embed::bundle() {
            Some(bundle) => assert_eq!(out, bundle),
            None => assert!(out.is_empty()),
        }
    }

    #[test]
    fn the_three_absent_renderers_report_themselves_and_do_not_claim_success() {
        // `tool_help`, `tool_version_info` and `tool_list_engines` are all in
        // `src/tool_help.c`, whose counterpart `curl-rs/src/cli/help.rs` is not
        // part of this checkout. None of them may return `CURLE_OK`: that would
        // report success for output nobody produced.
        for error in [
            ParameterError::HelpRequested,
            ParameterError::VersionInfoRequested,
            ParameterError::EnginesRequested,
        ] {
            let mut out: Vec<u8> = Vec::new();
            let mut sink: Vec<u8> = Vec::new();
            let code = outcome_for(error, &mut out, &mut sink, &boot());

            assert_eq!(code, CURLcode::NotBuiltIn, "{error:?} claimed success");
            assert!(out.is_empty(), "{error:?} produced output it cannot");
        }

        // `--version` and `--engine list` name their renderer on the diagnostic
        // channel; `--help` is reported by the host, before the outcome is
        // returned, which the parser-level test below covers.
        let version = run(&["--version"]);
        assert_eq!(version.code, CURLcode::NotBuiltIn);
        assert!(version.diagnostics.contains("tool_version_info"));

        // `--engine` is an `ARG_TLS` row (`src/tool_getparam.c:132`), so the
        // command line cannot reach `PARAM_ENGINES_REQUESTED` while TLS is
        // unadvertised -- see `doh_insecure_is_refused_while_tls_is_not_advertised`
        // for the gate. The mapping is asserted above, on the outcome itself.
        let engines = run(&["--engine", "list"]);
        assert_eq!(engines.code, CURLcode::FailedInit);
        assert_eq!(
            engines.diagnostics,
            format!(
                "curl: option --engine: the installed libcurl version does \
                 not support this\n{TRY_LINE}"
            )
        );
    }

    #[test]
    fn help_reaches_the_host_before_the_outcome_is_returned() {
        // `src/tool_getparam.c:3001-3005` -- "--help is special": the output is
        // produced inside `getparameter`, before `PARAM_HELP_REQUESTED` is
        // returned. This asserts the category reached the host, which is the
        // only observable that the call happened at all.
        assert_eq!(run(&["--help"]).helped, vec![None]);
        assert_eq!(
            run(&["--help", "http"]).helped,
            vec![Some("http".to_owned())]
        );
    }

    #[test]
    fn the_outcome_map_agrees_with_tool_operate_arm_for_arm() {
        // `src/tool_operate.c:2297-2330`. `outcome_for` matches exhaustively
        // with no wildcard, so the compiler already enforces coverage; this
        // checks the codes.
        let mut out: Vec<u8> = Vec::new();
        let mut sink: Vec<u8> = Vec::new();

        for (error, expected) in [
            (ParameterError::HelpRequested, CURLcode::NotBuiltIn),
            (ParameterError::ManualRequested, CURLcode::Ok),
            (ParameterError::VersionInfoRequested, CURLcode::NotBuiltIn),
            (ParameterError::EnginesRequested, CURLcode::NotBuiltIn),
            (ParameterError::CaEmbedRequested, CURLcode::Ok),
            (
                ParameterError::LibcurlUnsupportedProtocol,
                CURLcode::UnsupportedProtocol,
            ),
            (ParameterError::ReadError, CURLcode::ReadError),
            (ParameterError::Ok, CURLcode::FailedInit),
            (ParameterError::OptionUnknown, CURLcode::FailedInit),
            (ParameterError::ConfigOptionUnknown, CURLcode::FailedInit),
            (ParameterError::RequiresParameter, CURLcode::FailedInit),
            (ParameterError::BadUse, CURLcode::FailedInit),
            (ParameterError::GotExtraParameter, CURLcode::FailedInit),
            (ParameterError::BadNumeric, CURLcode::FailedInit),
            (ParameterError::NegativeNumeric, CURLcode::FailedInit),
            (ParameterError::LibcurlDoesntSupport, CURLcode::FailedInit),
            (ParameterError::NoMem, CURLcode::FailedInit),
            (ParameterError::NextOperation, CURLcode::FailedInit),
            (ParameterError::NoPrefix, CURLcode::FailedInit),
            (ParameterError::NumberTooLarge, CURLcode::FailedInit),
            (ParameterError::ContdispResumeFrom, CURLcode::FailedInit),
            (ParameterError::ExpandError, CURLcode::FailedInit),
            (ParameterError::BlankString, CURLcode::FailedInit),
            (ParameterError::VarSyntax, CURLcode::FailedInit),
            (ParameterError::Recursion, CURLcode::FailedInit),
        ] {
            assert_eq!(
                outcome_for(error, &mut out, &mut sink, &boot()),
                expected,
                "{error:?} maps to the wrong CURLcode"
            );
        }

        // Every variant was listed, so the table is a complete function of the
        // enumeration rather than a sample of it.
        assert_eq!(ParameterError::COUNT, 25);

        // The two codes C singles out are observable as exit statuses.
        assert_eq!(CURLcode::UnsupportedProtocol.as_i32(), 1);
        assert_eq!(CURLcode::ReadError.as_i32(), 26);
        assert_eq!(CURLcode::NotBuiltIn.as_i32(), 4);
    }

    // -- the production host -------------------------------------------------

    /// This crate's own manifest: a path that certainly exists.
    fn manifest() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")
    }

    /// A path that certainly does not.
    const ABSENT: &str = "/nonexistent/blitzy/curl-rs/probe";

    fn production_host() -> OsParseHost {
        OsParseHost::new(SinkHandle::init())
    }

    #[test]
    fn the_production_host_answers_existence_from_the_real_filesystem() {
        // `existingfile` -- `src/tool_getparam.c:2206-2216`, whose `curlx_stat`
        // is `stat()` and therefore follows symbolic links.
        let mut host = production_host();
        let path = manifest();

        assert!(host.exists(path.as_os_str().as_bytes()));
        assert!(!host.exists(ABSENT.as_bytes()));
    }

    #[test]
    fn the_production_host_reads_a_real_modification_time() {
        // `getfiletime(nextarg, &value)` -- `src/tool_getparam.c:1636`. Success
        // yields a stamp; failure yields `None` *and* the frozen
        // `Failed to get filetime: %s` warning of `src/tool_filetime.c:78-79`,
        // which is the half that used to be missing entirely.
        let mut host = production_host();
        let mut sink: Vec<u8> = Vec::new();
        let path = manifest();

        assert!(host
            .file_time(path.as_os_str().as_bytes(), &mut sink, &boot())
            .is_some());
        assert!(sink.is_empty(), "success is silent");

        assert!(host
            .file_time(ABSENT.as_bytes(), &mut sink, &boot())
            .is_none());
        let text = String::from_utf8(sink).expect("UTF-8 here");
        assert!(
            text.contains("Failed to get filetime:"),
            "the frozen warning must be emitted, got {text:?}"
        );
        // The message carries no filename -- the asymmetry with `setfiletime` is
        // C's and is preserved (`src/tool_filetime.c:78`).
        assert!(!text.contains(ABSENT));
    }

    #[test]
    fn the_production_host_silences_the_filetime_warning_under_silent() {
        // The reason `file_time` is handed the verbosity rather than assuming
        // one: `warnf`'s gate is `!global->silent` (`src/tool_msgs.c:95`).
        let mut host = production_host();
        let mut sink: Vec<u8> = Vec::new();

        assert!(host
            .file_time(
                ABSENT.as_bytes(),
                &mut sink,
                &MsgConfig::new(true, false, false)
            )
            .is_none());
        assert!(sink.is_empty(), "--silent must suppress the warning");
    }

    #[test]
    fn the_production_host_applies_a_trace_configuration() {
        // `curl_global_trace(config)` -- `src/tool_getparam.c:790`. C turns a
        // non-`CURLE_OK` answer into `PARAM_NO_MEM`; `TraceConfig::apply` can
        // only produce `CURLE_OK`, exactly as `Curl_trc_opt()` can, so every
        // token list -- including a malformed one, which C also accepts -- is
        // reported as applied.
        let mut host = production_host();

        assert!(host.set_trace("all"));
        assert!(host.set_trace("multi,-dns"));
        assert!(host.set_trace(",dns"));
        assert!(host.set_trace(""));
    }

    #[test]
    fn the_production_host_redirects_the_shared_diagnostic_channel() {
        // THE PROPERTY THE SHARED HANDLE EXISTS FOR. `--stderr <file>` is
        // honoured from inside the parser (`src/tool_getparam.c:2312`), so a
        // diagnostic written *after* it must land in the file. The two owners --
        // the host and the emitting sink -- are separate values over one
        // `MessageSink`, which is what C's file-scope `tool_stderr` achieves.
        let target = Path::new(env!("OUT_DIR")).join("blitzy_stderr_probe");
        let _ = fs::remove_file(&target);

        let shared = SinkHandle::init();
        let mut emitter = shared.handle();
        let mut host = OsParseHost::new(shared.handle());

        host.set_stderr_file(target.as_os_str().as_bytes(), &boot());
        msgs::errorf(&mut emitter, &boot(), format_args!("after the redirect"));
        let _ = emitter.flush();

        let written = fs::read_to_string(&target).expect("the file must exist");
        assert_eq!(written, "curl: after the redirect\n");
        let _ = fs::remove_file(&target);
    }

    #[test]
    fn an_unopenable_stderr_target_warns_and_leaves_the_channel_alone() {
        // `src/tool_stderr.c:49-56`, including the doubled prefix `:53` produces
        // because the literal already carries one. Measured against the oracle:
        // `curl --stderr /nonexistent/dir/x --bogus` writes
        // `Warning: Warning: Failed to open /nonexistent/dir/x` and then still
        // reports the unknown option on the ORIGINAL channel.
        //
        // The first redirect is what makes this observable: it points the shared
        // sink at a file, so the second -- which must fail -- writes its warning
        // where the test can read it, and the fact that it lands there at all is
        // the proof that the channel was left unchanged.
        let target = Path::new(env!("OUT_DIR")).join("blitzy_stderr_keep");
        let _ = fs::remove_file(&target);

        let shared = SinkHandle::init();
        let mut emitter = shared.handle();
        let mut host = OsParseHost::new(shared.handle());

        host.set_stderr_file(target.as_os_str().as_bytes(), &boot());
        host.set_stderr_file(b"/nonexistent/blitzy/dir/x", &boot());
        msgs::errorf(&mut emitter, &boot(), format_args!("still here"));
        let _ = emitter.flush();

        let written = fs::read_to_string(&target).expect("the file must exist");
        assert_eq!(
            written,
            "Warning: Warning: Failed to open /nonexistent/blitzy/dir/x\n\
             curl: still here\n"
        );
        let _ = fs::remove_file(&target);
    }

    #[test]
    fn the_production_host_reproduces_the_unreadable_config_message() {
        // `src/tool_parsecfg.c:267-270`, and the oracle: `curl -K <absent>`
        // prints `curl: cannot read config from '<f>'` and ultimately exits 26.
        let mut host = production_host();
        let mut sink: Vec<u8> = Vec::new();

        let outcome =
            host.parse_config(ABSENT.as_bytes(), 4, &mut sink, &boot());

        assert_eq!(outcome, ParameterError::ReadError);
        assert_eq!(
            String::from_utf8(sink).expect("UTF-8 here"),
            format!("curl: cannot read config from '{ABSENT}'\n")
        );
    }

    #[test]
    fn the_production_host_names_the_absent_config_reader() {
        // GAP #5. A file that CAN be read has to be parsed back through
        // `getparameter`, and that re-entry belongs to
        // `curl-rs/src/config/parseconfig.rs`. The answer must not be silence
        // and must not be success.
        let mut host = production_host();
        let mut sink: Vec<u8> = Vec::new();
        let path = manifest();

        let outcome = host.parse_config(
            path.as_os_str().as_bytes(),
            4,
            &mut sink,
            &boot(),
        );

        assert_eq!(outcome, ParameterError::LibcurlDoesntSupport);
        let text = String::from_utf8(sink).expect("UTF-8 here");
        assert!(
            text.contains("parseconfig.rs"),
            "the absent module must be named, got {text:?}"
        );
    }

    #[test]
    fn the_unreadable_config_path_is_reached_through_a_whole_invocation() {
        // The end-to-end form of the two tests above, with the production host,
        // so the mapping `PARAM_READ_ERROR -> CURLE_READ_ERROR`
        // (`src/tool_operate.c:2327`) is exercised rather than asserted.
        let runtime = runtime().expect("the current-thread runtime must build");
        let mut sink: Vec<u8> = Vec::new();
        let mut stdout: Vec<u8> = Vec::new();
        let mut global = GlobalConfig::init(&mut sink, &boot())
            .expect("globalconf_init must succeed on this platform");
        let mut host = production_host();
        let argv: Vec<OsString> = ["curl", "-K", ABSENT, "http://a.invalid/"]
            .iter()
            .map(OsString::from)
            .collect();

        let code = runtime.block_on(operate(
            &argv,
            &mut stdout,
            &mut sink,
            &mut host,
            &mut global,
        ));

        assert_eq!(code, CURLcode::ReadError);
        assert_eq!(code.as_i32(), 26);
        assert_eq!(
            String::from_utf8(sink).expect("UTF-8 here"),
            format!(
                "curl: cannot read config from '{ABSENT}'\ncurl: option -K: \
                 error encountered when reading a file\n{TRY_LINE}"
            )
        );
    }

    /// A [`ParseHost`] that touches nothing outside itself.
    ///
    /// [`OsParseHost`] is the production one and reaches the real filesystem,
    /// the real environment and the real standard input; the invocation-level
    /// tests above must not. Every member answers the "nothing is there" case,
    /// which is what makes those tests independent of the machine they run on.
    #[derive(Debug, Default)]
    struct TestHost {
        /// Every `--help` category the parser forwarded.
        helped: Vec<Option<String>>,
    }

    impl VarHost for TestHost {
        fn getenv(&self, _name: &[u8]) -> Option<Vec<u8>> {
            None
        }

        fn open(&mut self, _path: &[u8]) -> io::Result<Box<dyn ByteSource>> {
            Err(io::Error::other("no filesystem in this test"))
        }

        fn stdin(&mut self) -> Box<dyn ByteSource> {
            Box::new(SeekSource::new(io::Cursor::new(Vec::new())))
        }
    }

    impl StdinAccess for TestHost {
        fn regular_extent(&mut self) -> Option<(i64, i64)> {
            None
        }

        fn read_all(&mut self, _out: &mut Vec<u8>) -> io::Result<()> {
            Ok(())
        }

        fn read_chunk(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }

        fn seek_to(&mut self, _offset: i64) -> io::Result<()> {
            Ok(())
        }
    }

    impl ParseHost for TestHost {
        fn exists(&mut self, _path: &[u8]) -> bool {
            false
        }

        fn file_time(
            &mut self,
            _path: &[u8],
            _sink: &mut dyn DiagnosticSink,
            _msgs: &MsgConfig,
        ) -> Option<i64> {
            None
        }

        fn set_trace(&mut self, _config: &str) -> bool {
            true
        }

        fn set_stderr_file(&mut self, _path: &[u8], _msgs: &MsgConfig) {}

        fn help(
            &mut self,
            category: Option<&str>,
            _sink: &mut dyn DiagnosticSink,
            _msgs: &MsgConfig,
        ) {
            self.helped.push(category.map(str::to_owned));
        }

        fn parse_config(
            &mut self,
            _filename: &[u8],
            _max_recursive: i32,
            _sink: &mut dyn DiagnosticSink,
            _msgs: &MsgConfig,
        ) -> ParameterError {
            ParameterError::ReadError
        }
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
/// The behavioural tests in [`mod tests`](self) now cover the emission itself --
/// `--insecure` and `--proxy-insecure` each produce their warning, and an
/// invocation with neither produces none. What they cannot cover is the *shape*
/// of the call site, and the shape is what gate 10 is about: a warning moved
/// inside an `if`, or moved after the point at which the path proceeds, would
/// still pass every one of those tests on the inputs they use while leaving some
/// other input silent. So the shape is asserted structurally here, the way the
/// workspace already does elsewhere (`curl-rs-ffi/src/lib.rs`'s unsafe-boundary
/// gate and `curl-rs-lib/src/lib.rs`'s source policy): by reading its own source
/// through [`include_str!`] and asserting on the code, with comments and string
/// literals stripped so that the prose above -- which names the function twice --
/// cannot satisfy the gate on its own.
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
    ///
    /// The needle omits the opening parenthesis on purpose: `operate` is generic
    /// over its [`crate::cli::args::ParseHost`], so the declaration reads
    /// `async fn operate<H: ParseHost>(` and a needle ending in `(` would find
    /// nothing and make every assertion below vacuous.
    fn operate_bounds() -> (usize, usize) {
        let operate = first_code_line("async fn operate")
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
        // The option parser is the first thing on this path that parses a
        // number, so it is what the locale has to precede. It stands in for
        // `parseconfig` too, which re-enters it for every line of a
        // configuration file.
        //
        // The needle used to be `args_os(`, which moved to `main` when `operate`
        // became a function of its arguments -- as C's `operate(argc, argv)` is.
        // Merely collecting `argv` parses nothing, and C reads `argv[1]` at
        // `:2267` before it calls `setlocale` at `:2271`, so the ordering C
        // actually guarantees is the one asserted here.
        let door = first_code_line(LOCALE_DOOR)
            .expect("`operate` must call the engine's locale facade");
        let (operate, tests) = operate_bounds();
        let first_input =
            first_code_line_within("cli::args::parse_args(", operate, tests)
                .expect("`operate` must call the option parser");

        assert!(
            door < first_input,
            "the locale must be set before the first configuration input, but \
             the call is on line {door} and `parse_args` on line {first_input}"
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

        // `"fn operate"` and not `"fn operate("`: the declaration is generic, so
        // a needle ending in `(` would match nothing and `unwrap_or(usize::MAX)`
        // would make the assertion pass vacuously.
        let operate =
            first_code_line("fn operate").expect("`operate` must be declared");
        assert!(
            door < operate,
            "the call must be in `main`, ahead of `operate`, but it is on \
             line {door} and `operate` is declared on line {operate}"
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
