// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! Build script for `curl-rs-ffi`, the crate that presents libcurl's C ABI.
//!
//! It has exactly three responsibilities, and replaces `lib/optiontable.pl`
//! and `lib/Makefile.soname`:
//!
//! 1. Drive cbindgen over this crate's Rust source to regenerate
//!    `include/curl/curl.h` and its seven generated siblings.
//! 2. Stamp the shared library's soname, `libcurl.so.4` on Linux and the
//!    matching install name on Apple targets.
//! 3. Render `curl-config` and `libcurl.pc` from the repository's own
//!    `curl-config.in` and `libcurl.pc.in` templates, which Autotools and
//!    CMake used to render and which nothing else renders once the C build
//!    is gone. Third-party build systems query both, so they have to keep
//!    reporting the correct version, feature set and link line.
//!
//! ## Trap 2: the soname belongs here, not in `.cargo/config.toml`
//!
//! `[target.<triple>] rustflags` are not artifact-scoped. Measured with a
//! crate that builds both a cdylib and a binary: putting
//! `-C link-arg=-Wl,--soname=libcurl.so.4` in `.cargo/config.toml` stamped
//! `Library soname: [libcurl.so.4]` onto the *executable* as well. That is
//! a real packaging defect, because RPM, dpkg and `ldconfig` all read
//! `DT_SONAME`. `cargo:rustc-link-arg-cdylib=` applies only to the cdylib
//! artifact of this crate, so this file is the authoritative emitter.
//!
//! ## Trap 3: the flag spelling is platform-specific and wrong is fatal
//!
//! Measured: `gcc -shared -Wl,-install_name,...` gives
//! `/usr/bin/ld: unrecognised option: -install_name` and exit status 1.
//! Emission is therefore gated on `CARGO_CFG_TARGET_OS`, which describes
//! the *target*. A build script is compiled for the *host*, so `cfg!` and
//! `#[cfg(target_os = ...)]` would report the host and break the
//! cross-compiled `aarch64-unknown-linux-gnu` leg.
//!
//! # What is deliberately absent
//!
//! * No export-HIDING script, and no versioned symbol names. Both were
//!   measured to be unreachable this way: a user-supplied `--version-script`
//!   handed through `-C link-arg` cannot *remove* a Rust export, because
//!   rustc's own script already lists it in `global:` and a symbol listed
//!   global in any script stays global -- so names of the form
//!   `name@@CURL_OPENSSL_4` are unreachable through a link argument. That is a
//!   documented deviation, exactly equivalent to curl's own supported
//!   `--disable-versioned-symbols` build mode. Hiding is unnecessary besides:
//!   a cdylib exporting only its `#[no_mangle] pub extern "C"` items measured
//!   total=2, curl_*=2, leaked=0.
//!
//!   **ADDING an export through a second version script is a different
//!   question, and the answer is different.** It works, it is measured on both
//!   Linux targets and at the MSRV floor, and `promote_assembled_exports`
//!   below does exactly that for the six symbols `global_asm!` defines --
//!   which rustc cannot see and therefore localises. The one thing that route
//!   needs is that the linker be LLD, selected explicitly from the invoking
//!   toolchain's own sysroot rather than left to whatever `cc` defaults to;
//!   GNU ld refuses a second anonymous version tag outright. So export parity
//!   comes from declaration discipline for the fifty-three Rust items, and
//!   from one measured, ELF-only link argument for the six that cannot be
//!   Rust items at this MSRV.
//! * No claim of 32-bit support, anywhere. The four supported targets are
//!   all 64-bit, and the C ABI shim's single-trailing-pointer setters hold
//!   an `off_t` in one register-width slot only where `off_t` fits a
//!   register. 32-bit portability is therefore deliberately forfeited, and
//!   neither the rendered `curl-config` nor the rendered `libcurl.pc` may
//!   imply otherwise. Concretely: nothing this
//!   file writes advertises a word size, `@SUPPORT_FEATURES@` carries
//!   `Largefile` only because `curl_off_t` is 64-bit here, and
//!   `@CONFIGURE_OPTIONS@` reports the actual `TARGET` triple rather than a
//!   portability claim. `emit_link_args` warns on any target OS outside the
//!   supported four rather than guessing a convention for it.
//! * No reimplementation of `lib/optiontable.pl`, and no parsing of
//!   `include/curl/curl.h`. The direction of generation inverts relative
//!   to the C build: there the public header was the source of truth and
//!   the option table was derived from it, whereas here Rust source is the
//!   source of truth and the header is an output. Reading the header back
//!   would close that loop and reintroduce the drift the single-source
//!   rule exists to prevent. The `OPTION_TABLE_*` constants below hold the
//!   measured output of that generator, and `option_table_ground_truth`
//!   checks `src/ffi/opts.rs` against them on every build. Reading the
//!   hand-authored Rust authority is not the forbidden loop; reading the
//!   GENERATED header back in would be.
//! * No profile settings. `[profile.*]` is honoured only in the workspace
//!   root; a member profile is ignored *and* warns, which would break the
//!   zero-warnings build gate. `panic = "abort"` is prohibited outright
//!   because unwinding across the C ABI boundary has to be contained, and
//!   this crate catches panics at the boundary rather than aborting the
//!   host process. Nothing here tries to influence panic strategy.
//! * No network access, no timestamps, no hostname, no absolute paths and
//!   no unordered iteration in anything emitted. Builds are reproducible,
//!   so two runs from a clean tree produce byte-identical output.
//! * No `unsafe`. A build script is an ordinary host-side program, so
//!   `#![forbid(unsafe_code)]` would be clutter, but the file contains no
//!   `unsafe` block either.

use std::env;
use std::error::Error;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, Once};

// Parity constants

/// Major version of the shared library, and therefore its soname suffix.
///
/// Derived, never chosen. `lib/Makefile.soname:27-29` gives
/// `VERSIONCHANGE=12`, `VERSIONADD=0` and `VERSIONDEL=8`, which
/// `lib/Makefile.soname:32` turns into libtool `-version-info 12:0:8`.
/// libtool's rule is that the soname major is `current - age`, so
/// `12 - 8 = 4`. Corroborated twice more in the C tree:
///
/// * `configure.ac:2824` sets `CURL_LIBCURL_VERSIONED_SYMBOLS_SONAME` to
///   `"4"` and comments "Keep in sync with VERSIONCHANGE - VERSIONDEL in
///   lib/Makefile.soname".
/// * `lib/CMakeLists.txt:285` computes
///   `math(EXPR _cmakesoname "${VERSIONCHANGE} - ${VERSIONDEL}")` and
///   `:286` derives `VERSION 4.8.0` from it, applied at `:291`.
const SONAME_MAJOR: u32 = 12 - 8;

/// Basename of the ELF shared object. `lib/Makefile.am:35` declares
/// `lib_LTLIBRARIES = libcurl.la` and `lib/CMakeLists.txt:156` sets
/// `PREFIX "" OUTPUT_NAME "${LIBCURL_OUTPUT_NAME}"`, so the artifact is
/// `libcurl.so` and this is the name `ldconfig` must see.
fn linux_soname() -> String {
    format!("libcurl.so.{SONAME_MAJOR}")
}

/// Mach-O install name. CMake's `SOVERSION 4` produces `libcurl.4.dylib`
/// on Apple platforms, and `@rpath` keeps the artifact relocatable.
///
/// Verified rather than assumed, which matters because the alternative was
/// to ship an unverified flag. Built a cdylib for both mandated Apple
/// targets through `cargo zigbuild` and read the load command back with
/// `llvm-objdump --macho --dylib-id`:
///
/// ```text
/// x86_64-apple-darwin  -> @rpath/libcurl.4.dylib
/// aarch64-apple-darwin -> @rpath/libcurl.4.dylib
/// ```
fn apple_install_name() -> String {
    format!("@rpath/libcurl.{SONAME_MAJOR}.dylib")
}

/// Default installation prefix, matching Autotools' own default.
const DEFAULT_PREFIX: &str = "/usr/local";

/// Environment variables this script reads that Cargo does not already
/// fingerprint for us. Each one gets a `rerun-if-env-changed` line, so a
/// change to any of them re-renders the artifacts that embed it.
///
/// `CARGO_FEATURE_*`, `CARGO_CFG_TARGET_OS` and `CARGO_CFG_TARGET_ARCH`
/// are deliberately absent: the feature set, target and profile are part
/// of the unit's fingerprint, so Cargo already re-runs the script when any
/// of them changes. Listing them would be noise, not safety.
/// `PREFIX` is deliberately ABSENT: [`install_prefix`] no longer reads it, and
/// declaring a variable the script does not consult would make Cargo re-run
/// this build for a change that cannot affect its output. `CC_<target>` and
/// `CC_<target_with_underscores>` cannot be spelled here because they depend
/// on `TARGET`, so [`tracked_env_keys`] appends them at run time.
/// `A4_DECISION_ENV` is here because the refusal in [`check_variadic_abi`]
/// reads it: a cargo that had not been told this build depends on it would
/// not re-evaluate the refusal on the day the decision is recorded.
/// `STRICT_ABI_ENV` is here for the same reason and the mirror image of it --
/// setting it must turn the incomplete-export warning into a failure on the
/// NEXT build rather than whenever something else happens to dirty this script.
const TRACKED_ENV: [&str; 7] = [
    "CURL_RS_PREFIX",
    "CC",
    "TARGET_CC",
    "CURL_CA_BUNDLE",
    "CURL_RS_STAGING_DIR",
    A4_DECISION_ENV,
    STRICT_ABI_ENV,
];

/// Every environment variable this script reads, including the two whose
/// names are derived from `TARGET`.
fn tracked_env_keys() -> Vec<String> {
    let mut keys: Vec<String> =
        TRACKED_ENV.iter().map(|k| (*k).to_string()).collect();

    let target = env::var("TARGET").unwrap_or_default();
    if !target.is_empty() {
        let underscored: String = target
            .chars()
            .map(|c| if c == '-' || c == '.' { '_' } else { c })
            .collect();
        keys.push(format!("CC_{target}"));
        if underscored != target {
            keys.push(format!("CC_{underscored}"));
        }
    }

    keys
}

// Section 1b: the variadic ABI gate (open ambiguity A4)
//
// The four option-identifier functions -- curl_easy_setopt, curl_easy_getinfo,
// curl_multi_setopt and curl_share_setopt -- are reached by a NON-variadic Rust
// callee taking one trailing pointer, which is sound because the option value
// already encodes its argument's type class. That was proven end to end on
// x86_64 System V. On AAPCS64, which Linux aarch64 follows, variadic arguments
// are also passed in registers, so the same design holds. **Apple's arm64 ABI
// passes them on the stack**, so on aarch64-apple-darwin the callee reads
// register x2, which the caller never populated. Reading an uninitialised
// register as a user-supplied option value is memory-unsafe, not merely wrong,
// and the failure is silent: nothing in a Linux test run can surface it.
//
// `src/ffi/printf.rs` now does exactly that for ten of the eleven, and
// `src/ffi/form.rs` for the eleventh, so all eleven are implemented and
// ABI-correct by construction rather than open. Two honest qualifications, both
// stated rather than buried:
//
//  * The Apple legs are cross-assembled and disassembled here, never executed,
//    because no Apple host is available. That residual gap is why A4 is
//    narrowed and not closed.
//  * Six of the eleven -- the five plain `curl_m*printf` forms and
//    `curl_formadd` -- reach the STATIC library and not the shared one, for the
//    reason set out under "Trap 3" below, which is Rust's cdylib export model
//    and has nothing to do with the prologues.
//
// MEASUREMENT THAT OVERTOOK AN EARLIER CLAIM HERE. This paragraph used to read
// that `curl_formadd` was "untouched" because its "`CURLFORM_*` sequence carries
// no type encoding to recover the argument shapes from, so `va_start` alone does
// not help: the problem there is semantic, not mechanical". That is wrong, and
// the correction is worth keeping visible because it is the reason the eleventh
// symbol exists at all. `lib/formdata.c:346-347` reads the option with
// `va_arg(params, int)` and its switch then reads exactly one argument of a type
// that option names -- `char *`, `long`, `curl_off_t`, `struct curl_slist *`,
// `struct curl_forms *`, or nothing. That IS a type encoding: per-option instead
// of arithmetic. Every one of those shapes occupies a single general-purpose slot
// of at most eight bytes on all four required targets and none is a
// floating-point type, so one cursor over the general-purpose slots decodes the
// whole list, and `va_start` is precisely what was missing.

/// Turns the incomplete-export diagnostic from a warning into a build failure.
///
/// # Why a gate rather than a change of default
///
/// The export surface is incomplete while the migration is in progress, and the
/// guard that reports it is a `cargo:warning` so that the workspace stays
/// buildable -- the reasoning is set out in full where the guard fires. That is
/// the right default for a developer and the WRONG one for a release gate,
/// because `-D warnings` reaches rustc and clippy diagnostics and does not reach
/// a build script's, so AAP section 0.8.4's zero-warning build gate would sign
/// off a known ABI failure. That is exactly the hole this variable closes.
///
/// Setting it to anything non-empty makes an incomplete export surface a hard
/// error. `.github/workflows/rust-abi.yml` and `rust-build.yml` set it, so the
/// two legs whose job is to certify the artifact cannot pass while symbols are
/// missing, while an ordinary `cargo build` still works.
///
/// Named alongside [`A4_DECISION_ENV`] and read the same way, so a reader who
/// has met one has met both.
const STRICT_ABI_ENV: &str = "CURL_RS_REQUIRE_COMPLETE_EXPORTS";

/// Records the A4 decision, which is a user's to make and not this file's.
const A4_DECISION_ENV: &str = "CURL_RS_A4_VARIADIC_DECISION";

/// The only accepted value, spelled so it cannot be set by accident.
///
/// It names the decision it records rather than reading like a switch that
/// silences a nuisance. Setting it is an assertion that the consequence below
/// is understood and accepted:
///
/// * `curl_easy_setopt`, `curl_easy_getinfo`, `curl_multi_setopt` and
///   `curl_share_setopt` are NOT ABI-correct on aarch64-apple-darwin. A C
///   caller reaches them through the variadic prototype in the generated
///   header and the callee reads a register the caller did not write.
/// * None of the eleven exports in [`VARIADIC_UNIMPLEMENTABLE`] is unimplemented
///   any longer. `src/ffi/printf.rs` implements ten of them and
///   `src/ffi/form.rs` the eleventh, each with a per-target `va_start` written
///   in `global_asm!`, which needs neither a newer toolchain nor a C compiler.
///   What acceptance concedes for them is narrower and is stated on
///   [`check_printf_trampolines`] and [`check_formadd_trampoline`] -- their
///   Apple prologues are cross-assembled and disassembled rather than executed,
///   no Apple host being available, and six of the eleven reach the static
///   library but not the shared one, for the separate reason recorded under
///   "Trap 3".
const A4_ACCEPTED: &str = "accept-unsupported-varargs";

/// The eleven exports with no ABI-correct expression **as a Rust function** at
/// the declared minimum.
///
/// The qualification is load-bearing and was added after measurement. Every one
/// of the eleven is inexpressible as a Rust `extern "C" fn` at MSRV 1.75 --
/// `extern "C" fn f(x: T, ...)` is `error[E0658]`, and there is no stable way to
/// walk a `va_list` -- and that is what this list records. It does not follow
/// that they cannot be *exported*: ten of them are, from
/// `src/ffi/printf.rs`, by writing the target's `va_start` in `global_asm!` and
/// calling a `va_list` sibling that is an ordinary Rust function. The list
/// therefore stays at eleven because the Rust-level constraint is unchanged,
/// while [`VARIADIC_IMPLEMENTATION_FILES`] no longer vetoes the printf module
/// and [`check_printf_trampolines`] enforces the arrangement per symbol
/// instead.
///
/// Single source of truth, and asserted against the verbatim header text by
/// [`self_check_variadic_inventory`] so the list cannot drift from what the
/// headers actually declare. Searching for the literal `...);` finds only four
/// of these, because `include/curl/mprintf.h` puts a `CURL_TEMP_PRINTF`
/// attribute after the closing parenthesis -- which is exactly the trap that
/// makes a hand-maintained count unreliable and this assertion necessary.
const VARIADIC_UNIMPLEMENTABLE: [&str; 11] = [
    // `...`, driven by a format string rather than by an option identifier,
    // so `va_start` is unavoidable (include/curl/mprintf.h).
    "curl_mprintf",
    "curl_mfprintf",
    "curl_msprintf",
    "curl_msnprintf",
    "curl_maprintf",
    // `va_list` PARAMETERS. The layout is target-specific -- a pointer to a
    // four-field record on x86-64 System V, to a five-field record on AAPCS64,
    // and a plain `char *` on Apple arm64 -- so walking one needs hand-written
    // per-target unsafe (include/curl/mprintf.h).
    "curl_mvprintf",
    "curl_mvfprintf",
    "curl_mvsprintf",
    "curl_mvsnprintf",
    "curl_mvaprintf",
    // A genuinely open-ended CURLFORM_* sequence with no type-class encoding
    // to recover it from (include/curl/curl.h:2632-2635).
    "curl_formadd",
];

/// The four that the trailing-pointer design does solve, on three of the four
/// targets.
const VARIADIC_TRAILING_POINTER: [&str; 4] = [
    "curl_easy_setopt",
    "curl_easy_getinfo",
    "curl_multi_setopt",
    "curl_share_setopt",
];

/// The modules that would ship an argument-passing shape nobody has verified,
/// relative to the manifest.
///
/// Empty, because a per-file veto cannot tell a correct variadic
/// implementation from an incorrect one -- it only counts files, and an
/// environment variable silences it. Every variadic export is instead held to
/// a per-symbol obligation that nothing can silence:
/// [`check_printf_trampolines`] for the five plain-variadic printf forms and
/// [`check_formadd_trampoline`] for `curl_formadd`, each requiring an
/// assembled `va_start` prologue per ABI rather than a plain Rust
/// `extern "C" fn` reached through a variadic prototype.
const VARIADIC_IMPLEMENTATION_FILES: [&str; 0] = [];

// The four headers that must never be written

/// Public headers cbindgen cannot express, carried verbatim in the tree.
///
/// [`guard_write_target`] checks this list immediately before every write.
/// The check exists because a safety property that depends on nobody making
/// a mistake is not a safety property: it is a hope.
const NEVER_GENERATED: [&str; 4] =
    ["curlver.h", "stdcheaders.h", "system.h", "typecheck-gcc.h"];

// The per-header partition

/// One generated public header.
///
/// `cbindgen.toml` holds the shared configuration plus the umbrella
/// `curl.h` prologue and epilogue, and delegates the split to this file:
/// for each header we clone that one configuration and override the
/// prologue, the epilogue and the export partition. Nothing from
/// `cbindgen.toml` is restated here, so the two cannot disagree.
struct HeaderSpec {
    /// File name inside `include/curl/`.
    file: &'static str,
    /// Include-guard macro. `CURLINC_` plus the upper-cased stem.
    guard: &'static str,
    /// Verbatim text between the boxed banner and the `extern "C"` block:
    /// the header's own commentary and its `#include` directives. Empty
    /// where the header has neither.
    preamble: &'static str,
    /// Verbatim text after the generated declarations and before the
    /// `extern "C"` close. Only `mprintf.h` needs one.
    postamble: &'static str,
    /// Spelling of the `extern "C"` close. Measured across the tree: seven
    /// headers use `} /* end of extern "C" */` and `websockets.h:95` uses a
    /// bare `}`. Reproducing the wrong one is an unrequested change to a
    /// frozen file.
    extern_c_close: &'static str,
    /// Whether a blank line separates the `__cplusplus` `#endif` from the
    /// guard close. True for six of the seven siblings; measured false for
    /// `options.h`, which closes both `#endif` lines back to back. This
    /// asymmetry is easy to miss and shows up as a one-line diff.
    blank_before_guard_close: bool,
    /// Whether the guard close names the macro in a trailing comment.
    /// Measured: `easy.h` and `multi.h` end with a bare `#endif`; the other
    /// ten headers use `#endif /* CURLINC_<NAME>_H */`.
    named_guard_close: bool,
    /// Items this header owns. Drives both sides of the partition: forced
    /// emission for this header, and suppression in every other pass.
    items: &'static [&'static str],
    /// Names this header's own verbatim text declares and which therefore
    /// must be suppressed in EVERY pass, this one included.
    ///
    /// `cbindgen.toml`'s `[export] exclude` already covers the names it
    /// carries verbatim itself. This field covers the few that only the
    /// per-header text above declares, so that a name is never both
    /// generated and written out by hand. Empty for six of the seven.
    verbatim: &'static [&'static str],
}

/// Items owned by `curl.h`.
///
/// Derived by measurement, not by intuition: for every name the tree
/// declares, the owning header is the one whose text declares it. The
/// script that produced this list matched each of the 100 names in
/// `lib/libcurl.def` to the header carrying its `CURL_EXTERN` prototype,
/// and separately collected every callback typedef, anonymous-enum typedef
/// and struct per header. Names already listed under `[export] exclude` in
/// `cbindgen.toml` are omitted throughout, because those are emitted
/// verbatim and no pass may generate them.
const CURL_H_ITEMS: &[&str] = &[
    // Enumerations. Every one also appears in `cbindgen.toml`'s
    // `[export] include`, because several are referenced only by the
    // prototypes that list excludes, and cbindgen emits a type only when
    // it is reachable. An enum that vanishes is an ABI regression that
    // compiles cleanly right up until a consumer names one of its members.
    "CURLcode",
    "CURLproxycode",
    "CURLSHcode",
    "CURLSHoption",
    "CURLsslset",
    "CURLSTScode",
    "CURLversion",
    "curl_closepolicy",
    "curl_ftpauth",
    "curl_ftpccc",
    "curl_ftpcreatedir",
    "curl_ftpmethod",
    "curl_infotype",
    "curl_lock_access",
    "curl_lock_data",
    "curl_proxytype",
    "curl_TimeCond",
    "curl_usessl",
    "curlfiletype",
    "curliocmd",
    "curlioerr",
    "curlsocktype",
    // Callback function-pointer typedefs. The largest category cbindgen
    // genuinely renders well.
    "curl_calloc_callback",
    "curl_chunk_bgn_callback",
    "curl_chunk_end_callback",
    "curl_closesocket_callback",
    "curl_conv_callback",
    "curl_debug_callback",
    "curl_fnmatch_callback",
    "curl_formget_callback",
    "curl_free_callback",
    "curl_hstsread_callback",
    "curl_hstswrite_callback",
    "curl_ioctl_callback",
    "curl_lock_function",
    "curl_malloc_callback",
    // curl_opensocket_callback is deliberately NOT here, for a layout
    // reason rather than a type one. Its third parameter is
    // `struct curl_sockaddr *address`, and cbindgen aligns continuation
    // arguments under the opening parenthesis of
    // `typedef curl_socket_t (*curl_opensocket_callback)(` -- an indent of 49
    // columns -- which puts that parameter at 81 columns and trips the
    // 79-column guard. The frozen header avoids this by placing the return
    // type on its own line, a layout cbindgen has no setting for. It is
    // written verbatim instead, in the authority's own formatting.
    "curl_prereq_callback",
    "curl_progress_callback",
    "curl_read_callback",
    "curl_realloc_callback",
    "curl_resolver_start_callback",
    "curl_seek_callback",
    "curl_sockopt_callback",
    "curl_sshhostkeycallback",
    // curl_sshkeycallback is deliberately NOT here. It is the one public
    // callback typedef that cannot be generated -- its fourth parameter is
    // `enum curl_khmatch`, a bare enum tag cbindgen never declares -- so it
    // is written verbatim and named in CURL_H_VERBATIM_NAMES instead.
    // Claiming it here would assert that cbindgen generates it, which the
    // disjoint-name guard below correctly rejects as a lie.
    "curl_ssl_ctx_callback",
    // curl_ssls_export_cb is deliberately NOT here. The authority declares a
    // function TYPE, not a function pointer:
    //     typedef CURLcode curl_ssls_export_cb(CURL *handle, ..);
    // and its only use site spells `curl_ssls_export_cb *export_fn`, i.e. a
    // pointer TO that function type. Rust has no type that maps to a bare C
    // function type -- `extern "C" fn(..)` is already a pointer -- so
    // generating it produced `typedef CURLcode (*curl_ssls_export_cb)(..)`,
    // which silently turns every consumer's `curl_ssls_export_cb *` into a
    // pointer to a function pointer. Written verbatim instead.
    "curl_strdup_callback",
    "curl_trailer_callback",
    "curl_unlock_function",
    "curl_write_callback",
    "curl_xferinfo_callback",
    // Functions. 37 of the 100, the remainder of curl.h's share being the
    // verbatim `curl_share_setopt` and the deprecated `curl_form*` trio.
    "curl_easy_escape",
    "curl_easy_pause",
    "curl_easy_ssls_export",
    "curl_easy_ssls_import",
    "curl_easy_unescape",
    "curl_escape",
    "curl_free",
    "curl_getenv",
    "curl_global_cleanup",
    "curl_global_trace",
    "curl_mime_addpart",
    "curl_mime_data",
    "curl_mime_data_cb",
    "curl_mime_encoder",
    "curl_mime_filedata",
    "curl_mime_filename",
    "curl_mime_free",
    "curl_mime_headers",
    "curl_mime_init",
    "curl_mime_name",
    "curl_mime_subparts",
    "curl_mime_type",
    "curl_share_cleanup",
    "curl_share_init",
    "curl_slist_append",
    "curl_slist_free_all",
    "curl_strequal",
    "curl_strnequal",
    "curl_unescape",
    "curl_version",
];

/// Items owned by `easy.h`: eight functions and no types.
///
/// `curl_easy_setopt` and `curl_easy_getinfo` are declared here too but are
/// excluded globally, because both are C-variadic and their prototypes are
/// carried verbatim.
const EASY_H_ITEMS: &[&str] = &[
    "curl_easy_cleanup",
    "curl_easy_duphandle",
    "curl_easy_init",
    "curl_easy_perform",
    "curl_easy_recv",
    "curl_easy_reset",
    "curl_easy_send",
    "curl_easy_upkeep",
];

/// Items owned by `multi.h`: four enums, four callback typedefs and 21
/// functions. `curl_multi_setopt` is variadic and `curl_multi_socket` and
/// `curl_multi_socket_all` are deprecated, so all three are verbatim; the
/// deprecated pair stays exported and declared, because removing a
/// deprecated exported symbol is prohibited.
const MULTI_H_ITEMS: &[&str] = &[
    "CURLMcode",
    "CURLMinfo_offt",
    "CURLMoption",
    "CURLMSG",
    "curl_multi_timer_callback",
    "curl_notify_callback",
    "curl_push_callback",
    "curl_socket_callback",
    "curl_multi_add_handle",
    "curl_multi_assign",
    "curl_multi_cleanup",
    "curl_multi_fdset",
    "curl_multi_get_handles",
    "curl_multi_get_offt",
    "curl_multi_info_read",
    "curl_multi_init",
    "curl_multi_notify_disable",
    "curl_multi_notify_enable",
    "curl_multi_perform",
    "curl_multi_poll",
    "curl_multi_remove_handle",
    "curl_multi_socket_action",
    "curl_multi_timeout",
    "curl_multi_wait",
    "curl_multi_waitfds",
    "curl_multi_wakeup",
    "curl_pushheader_byname",
    "curl_pushheader_bynum",
    // Constants. Measured: every `^#define` in multi.h other than the
    // include guard and the CURL_ALLOW_OLD_MULTI_SOCKET compatibility macro
    // at multi.h:332, which is function-like and therefore outside what
    // cbindgen emits at all.
];

/// Items owned by `urlapi.h`: none.
///
/// MEASURED, by rendering this header with the five names owned and diffing
/// against `include/curl/urlapi.h`. Seven divergences, in four families:
///
/// 1. ORDER. The frozen file interleaves generated and verbatim material:
///    `CURLUcode` and `CURLUPart` (`:34-82`), then the 16 `CURLU_*` flag bits
///    (`:84-105`), then `typedef struct Curl_URL CURLU;` (`:107`), then the
///    six prototypes. A cbindgen pass emits ONE contiguous generated region
///    between `after_includes` and the trailer, so no preamble/postamble split
///    can place the flag bits and the handle typedef BETWEEN the enums and the
///    prototypes. Owning the enums hoisted the typedef and the flags above
///    them, which reorders the public contract.
/// 2. TRAILING COMMENTS. `CURLUcode`'s 31 ordinal comments -- `/* 1 */`
///    through `/* 31 */`, the C tree's own drift guard against an accidental
///    insertion -- and `CURLUPART_ZONEID`'s `/* added in 7.65.0 */` become
///    multi-line blocks ABOVE each member, and every member acquires an
///    explicit `= N`. Exactly what was measured for `CURLHcode`; cbindgen has
///    no trailing-comment form. `cbindgen.toml`'s hope that "those comments
///    survive because `documentation` is on" was measured FALSE.
/// 3. PROTOTYPE SPELLING. `curl_url`, `curl_url_cleanup` and `curl_url_dup`
///    acquire `CURL_EXTERN` on a line of its own plus their whole Rust doc
///    comment -- `# Safety` headings, markdown emphasis and
///    `super::panic_boundary::guard_tx` intra-doc links -- where the frozen
///    header carries a four-line C comment per prototype that
///    `docs/libcurl/curl_url*.md` cross-references.
/// 4. PARAMETER NAME. `urlapi.h:126` spells it `curl_url_dup(const CURLU *in)`
///    and `in` is a RUST KEYWORD, so the Rust definition must name the
///    parameter something else and cbindgen renders whatever it is named.
///
/// `CURLU` was already verbatim before this measurement, because `urlapi.h:107`
/// spells it `typedef struct Curl_URL CURLU;`, where the struct tag differs
/// from the typedef name and cbindgen would emit `typedef struct CURLU CURLU;`
/// -- valid C that introduces a DIFFERENT incomplete type from the one
/// libcurl's own translation units define.
const URLAPI_H_ITEMS: &[&str] = &[
    // The two enums, the 16 CURLU_* flag bits and the handle typedef are in
    // URLAPI_H_DECLS; the six prototypes are in URLAPI_H_POST.
];

/// Items owned by `options.h`: `curl_easytype` and the three introspection
/// functions. `struct curl_easyoption` is verbatim, being layout-visible.
const OPTIONS_H_ITEMS: &[&str] = &[
    "curl_easytype",
    // options.h:47, and the only flag bit the API defines.
    "CURLOT_FLAG_ALIAS",
];

/// Items owned by `header.h`: none.
///
/// The second empty partition, alongside [`MPRINTF_H_ITEMS`], and empty for
/// the same kind of reason: every construct the header declares is one
/// cbindgen cannot render to the frozen bytes. `struct curl_header` is
/// layout-visible, the five `origin` bits are `pub(crate)` and so invisible
/// to cbindgen at all, `CURLHcode`'s eight frozen trailing comments become
/// eight multi-line blocks above the members, and both prototypes acquire
/// their whole Rust doc comment plus a line break after `CURL_EXTERN`.
/// [`HEADER_H_DECLS`] carries all four, and each of the three names that
/// would otherwise be generated is listed in this header's
/// [`HeaderSpec::verbatim`] so no pass -- including `curl.h`'s -- emits a
/// second declaration.
const HEADER_H_ITEMS: &[&str] = &[];

/// Items owned by `websockets.h`: none.
///
/// The fourth empty partition -- [`URLAPI_H_ITEMS`], [`HEADER_H_ITEMS`] and
/// [`MPRINTF_H_ITEMS`] are the others -- and empty for both of the reasons
/// they are, measured on this tree rather than anticipated:
///
///   1. INTERLEAVING. The frozen file does not put its constants in one
///      block and its prototypes in another. `CURLWS_PONG (1 << 6)`
///      (websockets.h:60) sits BETWEEN `curl_ws_recv` (:55-57) and
///      `curl_ws_send` (:70-73) under its own `/* flags for
///      curl_ws_send() */` comment, and the two `CURLOPT_WS_OPTIONS` bits
///      (:88-90) sit between `curl_ws_start_frame` (:84-86) and
///      `curl_ws_meta` (:92). cbindgen emits ONE contiguous generated
///      region, so no partition of this header can express that order --
///      the same limit that put `urlapi.h`'s three remaining constructors
///      in [`URLAPI_H_ITEMS`]'s verbatim list, where the flag bits and the
///      handle typedef likewise interleave with the prototypes. A
///      generator that groups the constants would move `CURLWS_PONG` and
///      produce a large diff in a frozen, reviewed file.
///   2. THE `struct` KEYWORD. `curl_ws_recv`'s `metap` parameter and
///      `curl_ws_meta`'s return type both name `struct curl_ws_frame`,
///      which websockets.h:31-37 declares in TAG form with no typedef.
///      With `style = "type"` cbindgen spells a struct by its bare name,
///      so generating either prototype emits `const curl_ws_frame **` --
///      `error: unknown type name 'curl_ws_frame'`, exactly the invalid C
///      that `cbindgen.toml`'s `[export.rename]` note records for
///      `curl_header`, and exactly what `docs/examples/websocket.c` and
///      `websocket-cb.c` would have failed to compile. Carrying the
///      prototypes verbatim removes the referent instead of renaming it,
///      which is the reason that same note gives for `curl_khkey` needing
///      no entry.
///
/// Both are settled by [`WEBSOCKETS_H_DECLS`], which carries the whole
/// interior, and by this header's [`HeaderSpec::verbatim`], which keeps
/// every one of the four names out of every pass -- the umbrella included.
const WEBSOCKETS_H_ITEMS: &[&str] = &[];

/// Items owned by `mprintf.h`: none.
///
/// All ten `curl_m*printf` prototypes carry a `CURL_TEMP_PRINTF(n, m)`
/// attribute that cbindgen has no way to express, so all ten are excluded
/// globally and the whole body is verbatim below. This header is generated
/// in the sense that this script writes it, but every byte of it is
/// prologue and epilogue.
const MPRINTF_H_ITEMS: &[&str] = &[];

/// The eight partitions, in the order the headers are written.
///
/// One table, read by the self-checks, by the partition builder and by the
/// generator, so a header can never be added to one and forgotten in
/// another.
const PARTITIONS: [(&str, &[&str]); 8] = [
    ("curl.h", CURL_H_ITEMS),
    ("easy.h", EASY_H_ITEMS),
    ("multi.h", MULTI_H_ITEMS),
    ("urlapi.h", URLAPI_H_ITEMS),
    ("options.h", OPTIONS_H_ITEMS),
    ("header.h", HEADER_H_ITEMS),
    ("websockets.h", WEBSOCKETS_H_ITEMS),
    ("mprintf.h", MPRINTF_H_ITEMS),
];

/// Every block of verbatim header text, grouped by the header it lands in.
///
/// Exists so the disjoint-name rule below can be DERIVED from the text that is
/// actually emitted rather than from a hand-maintained list of names. A
/// hand-maintained list is what allowed 53 constant macros to be carried
/// verbatim while still being claimed as generated items: the existing guard
/// only consulted `CURL_H_VERBATIM_NAMES`, so a name carried verbatim in a
/// SIBLING header was never checked at all.
const VERBATIM_CARRIERS: [(&str, &[&str]); 8] = [
    (
        "curl.h",
        &[
            CURL_H_FORWARD,
            CURL_H_VERBATIM,
            CURL_H_CONSTS,
            CURL_H_OLDIES,
        ],
    ),
    ("easy.h", &[EASY_H_DECLS, EASY_H_POST]),
    ("multi.h", &[MULTI_H_INCLUDES, MULTI_H_DECLS, MULTI_H_POST]),
    (
        "urlapi.h",
        &[URLAPI_H_INCLUDES, URLAPI_H_DECLS, URLAPI_H_POST],
    ),
    ("options.h", &[OPTIONS_H_DECLS, OPTIONS_H_POST]),
    ("header.h", &[HEADER_H_DECLS]),
    ("websockets.h", &[WEBSOCKETS_H_DECLS]),
    ("mprintf.h", &[MPRINTF_H_INCLUDES, MPRINTF_H_DECLS]),
];

/// The macro names a block of verbatim text `#define`s.
fn verbatim_defines(text: &str) -> Vec<&str> {
    let mut names = Vec::new();
    let mut in_comment = false;
    for line in text.lines() {
        let trimmed = line.trim_start();
        if !in_comment {
            if let Some(rest) = trimmed.strip_prefix("#define") {
                let name = rest
                    .trim_start()
                    .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                    .next()
                    .unwrap_or_default();
                if !name.is_empty() {
                    names.push(name);
                }
            }
        }
        // Track /* */ nesting-free state across lines. A line may both open
        // and close a comment, so scan it rather than testing its ends.
        let bytes = line.as_bytes();
        let mut i = 0;
        while i + 1 < bytes.len() {
            if !in_comment && bytes[i] == b'/' && bytes[i + 1] == b'*' {
                in_comment = true;
                i += 2;
            } else if in_comment && bytes[i] == b'*' && bytes[i + 1] == b'/' {
                in_comment = false;
                i += 2;
            } else {
                i += 1;
            }
        }
    }
    names
}

// Section 4: the verbatim per-header text
//
// A prologue and an epilogue can place text before and after the generated
// block. They cannot interleave text *within* it. `cbindgen.toml` states
// where the excluded declarations are put back: ":968-975" assigns this
// script the per-header split and says in so many words that it is "also
// where the verbatim blocks excluded above are spliced back in".
//
// Three groups needed splicing INSIDE a header's declarations rather than
// at a boundary, and each is placed at the nearest boundary instead:
//
//   * `curl_easy_setopt` (easy.h:42) and `curl_easy_getinfo` (easy.h:59)
//     sit among easy.h's other prototypes. Both move to its epilogue.
//   * `curl_multi_setopt` (multi.h:429) and the deprecated
//     `curl_multi_socket` (multi.h:317) and `curl_multi_socket_all`
//     (multi.h:325) sit among multi.h's. All three move to its epilogue.
//   * curl.h's twelve tag-form structs and five tag-form enums are spread
//     through 3,000 lines. They move to `CURL_H_FORWARD` when something
//     generated names them by value, and to `CURL_H_VERBATIM` otherwise.

/// The `extern "C"` opening block, identical in all eight headers.
///
/// Written out rather than delegated to cbindgen's `cpp_compat`, which was
/// measured to emit `}  // extern "C"` on the closing side. That is a `//`
/// comment, and `scripts/checksrc.pl:162` defines `CPPCOMMENTS` as a
/// finding, checked at `:666`, so the generated header would fail the live
/// style gate.
const CPP_OPEN: &str = "#ifdef __cplusplus\nextern \"C\" {\n#endif\n";

/// `easy.h`, after the `extern "C"` open.
///
/// `struct curl_blob` is layout-visible: consumers allocate one and fill in
/// its three fields, so cbindgen's opaque rendering would be wrong and the
/// declaration is verbatim. The two flag values keep the column alignment
/// of `easy.h:31-32`.
const EASY_H_DECLS: &str = r#"
/* Flag bits in the curl_blob struct: */
#define CURL_BLOB_COPY   1 /* tell libcurl to copy the data */
#define CURL_BLOB_NOCOPY 0 /* tell libcurl to NOT copy the data */

struct curl_blob {
  void *data;
  size_t len;
  unsigned int flags; /* bit 0 is defined, the rest are reserved and should be
                         left zeroes */
};
"#;

/// `easy.h`, after the generated block: the two C-variadic prototypes.
///
/// Both are listed under `[export] exclude` in `cbindgen.toml` because a
/// Rust `extern "C" fn` cannot be C-variadic under MSRV 1.75 (measured:
/// `error[E0658]`, tracking issue 44930), so the Rust definitions take a
/// single trailing pointer while the header must keep the `...` the C ABI
/// declares. Being excluded, they cannot arrive by source order, and
/// `cbindgen.toml`'s partitioning note assigns their splice to this script.
const EASY_H_POST: &str = r#"
CURL_EXTERN CURLcode curl_easy_setopt(CURL *curl, CURLoption option, ...);

/*
 * NAME curl_easy_getinfo()
 *
 * DESCRIPTION
 *
 * Request internal information from the curl session with this function.
 * The third argument MUST be pointing to the specific type of the used option
 * which is documented in each man page of the option. The data pointed to
 * will be filled in accordingly and can be relied upon only if the function
 * returns CURLE_OK. This function is intended to get used *AFTER* a performed
 * transfer, all results from this function are undefined until the transfer
 * is completed.
 */
CURL_EXTERN CURLcode curl_easy_getinfo(CURL *curl, CURLINFO info, ...);
"#;

/// `multi.h`, before the `extern "C"` open: its two block comments and the
/// `#include "curl.h"` they explain. Reproduced verbatim, including the
/// second comment's admission that the include should never have been added
/// and is kept only so that existing applications keep compiling.
const MULTI_H_INCLUDES: &str = r#"
/*
  This is an "external" header file. Do not give away any internals here!

  GOALS

  o Enable a "pull" interface. The application that uses libcurl decides where
    and when to ask libcurl to get/send data.

  o Enable multiple simultaneous transfers in the same thread without making it
    complicated for the application.

  o Enable the application to select() on its own file descriptors and curl's
    file descriptors simultaneous easily.

*/

/*
 * This header file should not really need to include "curl.h" since curl.h
 * itself includes this file and we expect user applications to do #include
 * <curl/curl.h> without the need for especially including multi.h.
 *
 * For some reason we added this include here at one point, and rather than to
 * break existing (wrongly written) libcurl applications, we leave it as-is
 * but with this warning attached.
 */
#include "curl.h"
"#;

/// `multi.h`, after the `extern "C"` open.
///
/// `typedef void CURLM;` is the whole point of the verbatim treatment.
/// cbindgen renders an opaque Rust type as `typedef struct CURLM CURLM;`,
/// which is a different type from `void` and changes the type of every
/// handle-passing call. Consumers assigning a `CURLM *` to a `void *` is a
/// widespread idiom, present in `docs/examples/`, so the wrong spelling
/// turns 129 compilation units into warnings or errors.
///
/// `CURLMsg` is split across the prologue and the epilogue, and the reason
/// is a rule of C rather than a preference. `struct CURLMsg` (multi.h:97)
/// has a `CURLMSG msg` member, so it cannot be declared before the
/// `CURLMSG` enum, which is generated. But `curl_multi_info_read`
/// (multi.h:342) returns `CURLMsg *`, and a typedef -- unlike a struct tag --
/// cannot be forward declared, so the typedef must exist before that
/// prototype. The only arrangement satisfying both is a tag forward
/// declaration plus the typedef here, and the full definition after the
/// generated block. Both halves are legal C89 and the resulting type is
/// identical; only the position of the definition differs from the C
/// header.
///
/// `struct curl_pushheaders` (multi.h:500) is an opaque handle the library
/// never defines publicly. It is excluded in `cbindgen.toml`, so it cannot
/// arrive by source order, and it must precede everything that names it:
/// `curl_pushheader_bynum` (:502), `curl_pushheader_byname` (:504) and
/// `curl_push_callback` (:507) are all generated, so the declaration belongs
/// in the prologue even though the C header places it at `:500`. The
/// trailing comment is reproduced because it is part of the frozen file.
const MULTI_H_DECLS: &str = r#"
typedef void CURLM;

struct CURLMsg;
typedef struct CURLMsg CURLMsg;

struct curl_waitfd {
  curl_socket_t fd;
  short events;
  short revents;
};

struct curl_pushheaders;  /* forward declaration only */

/* ---- verbatim from multi.h, not generated ---- */
/* cbindgen cannot carry these faithfully, measured on all three
   forms: it DROPS an `L` suffix (`2L` becomes `2`, changing the
   varargs type of a long option), rewrites hex as decimal, and
   cannot express a #define whose value is another identifier.
   multi.h's twenty-three constants, in seven families are therefore
   spliced from the frozen header exactly as written. */
/* just to make code nicer when using curl_multi_socket() you can now check
   for CURLM_CALL_MULTI_SOCKET too in the same style it works for
   curl_multi_perform() and CURLM_CALL_MULTI_PERFORM */
#define CURLM_CALL_MULTI_SOCKET CURLM_CALL_MULTI_PERFORM

/* bitmask bits for CURLMOPT_PIPELINING */
#define CURLPIPE_NOTHING   0L
#define CURLPIPE_HTTP1     1L
#define CURLPIPE_MULTIPLEX 2L

/* Based on poll(2) structure and values.
 * We do not use pollfd and POLL* constants explicitly
 * to cover platforms without poll(). */
#define CURL_WAIT_POLLIN    0x0001
#define CURL_WAIT_POLLPRI   0x0002
#define CURL_WAIT_POLLOUT   0x0004

#define CURL_POLL_NONE   0
#define CURL_POLL_IN     1
#define CURL_POLL_OUT    2
#define CURL_POLL_INOUT  3
#define CURL_POLL_REMOVE 4

#define CURL_SOCKET_TIMEOUT CURL_SOCKET_BAD

#define CURL_CSELECT_IN   0x01
#define CURL_CSELECT_OUT  0x02
#define CURL_CSELECT_ERR  0x04

/* Definition of bits for the CURLMOPT_NETWORK_CHANGED argument: */

/* - CURLMNWC_CLEAR_CONNS tells libcurl to prevent further reuse of existing
   connections. Connections that are idle will be closed. Ongoing transfers
   will continue with the connection they have. */
#define CURLMNWC_CLEAR_CONNS (1L << 0)

/* - CURLMNWC_CLEAR_DNS tells libcurl to prevent further reuse of existing
   connections. Connections that are idle will be closed. Ongoing transfers
   will continue with the connection they have. */
#define CURLMNWC_CLEAR_DNS (1L << 0)

#define CURL_PUSH_OK       0
#define CURL_PUSH_DENY     1
#define CURL_PUSH_ERROROUT 2 /* added in 7.72.0 */

#define CURLMNOTIFY_INFO_READ    0
#define CURLMNOTIFY_EASY_DONE    1

"#;

/// `multi.h`, after the generated block: the definition whose forward
/// declaration is above, then the three excluded prototypes.
///
/// `curl_multi_socket` (multi.h:317) and `curl_multi_socket_all` (:325) are
/// deprecated in the headers and still exported -- both are in the
/// 100-symbol parity set, and a deprecated exported symbol may not be
/// removed. They are excluded from generation because cbindgen
/// renders `deprecated_with_note` through
/// `format.replace("{}", &format!("{note:?}"))`
/// (`annotation.rs:70-100`), which Debug-quotes the note and therefore
/// cannot produce `CURL_DEPRECATED(7.19.5, "...")` with an unquoted version
/// token. The attribute placement here -- after the return type, on its own
/// line, with the function name beginning the next -- is `multi.h`'s own.
const MULTI_H_POST: &str = r#"
struct CURLMsg {
  CURLMSG msg;       /* what this message means */
  CURL *easy_handle; /* the handle it concerns */
  union {
    void *whatever;    /* message-specific data */
    CURLcode result;   /* return code for transfer */
  } data;
};

CURL_EXTERN CURLMcode CURL_DEPRECATED(7.19.5, "Use curl_multi_socket_action()")
curl_multi_socket(CURLM *multi_handle, curl_socket_t s, int *running_handles);

CURL_EXTERN CURLMcode CURL_DEPRECATED(7.19.5, "Use curl_multi_socket_action()")
curl_multi_socket_all(CURLM *multi_handle, int *running_handles);

#ifndef CURL_ALLOW_OLD_MULTI_SOCKET
/* This macro below was added in 7.16.3 to push users who recompile to use
 * the new curl_multi_socket_action() instead of the old curl_multi_socket()
 */
#define curl_multi_socket(x,y,z) curl_multi_socket_action(x,y,0,z)
#endif

/*
 * Name:    curl_multi_setopt()
 *
 * Desc:    Sets options for the multi handle.
 *
 * Returns: CURLM error code.
 */
CURL_EXTERN CURLMcode curl_multi_setopt(CURLM *multi_handle,
                                        CURLMoption option, ...);

/*
 * Name:    curl_multi_strerror
 *
 * Desc:    Turns a CURLMcode into a human readable error string.
 *
 * Carried verbatim rather than generated: the parameter is a CURLMcode and the
 * Rust definition must take a c_int. See cbindgen.toml, "Group 5e".
 */
CURL_EXTERN const char *curl_multi_strerror(CURLMcode);
"#;

/// `header.h`, after the `extern "C"` open: `header.h:31-68` verbatim, which
/// is every declaration the header carries.
///
/// `struct curl_header` is LAYOUT-VISIBLE -- consumers read all six fields
/// off the pointer the two functions hand back -- so cbindgen's opaque
/// rendering would be wrong and the definition is spliced. Placing it first
/// also gives the two prototypes below, which take
/// `struct curl_header **` and return `struct curl_header *`, a complete
/// type to refer to.
///
/// `CURLHcode` is spliced for the reason that governs every comment in this
/// file's output: cbindgen renders `documentation = true` faithfully, and
/// `ffi::codes::CURLHcode` carries a Rust doc comment per member. Generated,
/// the enumeration came out with each comment lifted into its own multi-line
/// `/* .. */` block ABOVE the member, carrying Rust intra-doc links
/// (`` [`engine::CURLHcode`] ``), backticks and markdown emphasis into a C
/// header -- 42 lines where the authority has 10, and not one of the frozen
/// trailing comments left in place. Turning `documentation` off is not the
/// remedy: it is a GLOBAL key in `cbindgen.toml` and the other seven headers
/// depend on it. So this header owns its enumeration, exactly as
/// `mprintf.h` owns all ten of its prototypes.
const HEADER_H_DECLS: &str = r#"
struct curl_header {
  char *name;    /* this might not use the same case */
  char *value;
  size_t amount; /* number of headers using this name  */
  size_t index;  /* ... of this instance, 0 or higher */
  unsigned int origin; /* see bits below */
  void *anchor; /* handle privately used by libcurl */
};

/* 'origin' bits */
#define CURLH_HEADER    (1 << 0) /* plain server header */
#define CURLH_TRAILER   (1 << 1) /* trailers */
#define CURLH_CONNECT   (1 << 2) /* CONNECT headers */
#define CURLH_1XX       (1 << 3) /* 1xx headers */
#define CURLH_PSEUDO    (1 << 4) /* pseudo headers */

typedef enum {
  CURLHE_OK,
  CURLHE_BADINDEX,      /* header exists but not with this index */
  CURLHE_MISSING,       /* no such header exists */
  CURLHE_NOHEADERS,     /* no headers at all exist (yet) */
  CURLHE_NOREQUEST,     /* no request with this number was used */
  CURLHE_OUT_OF_MEMORY, /* out of memory while processing */
  CURLHE_BAD_ARGUMENT,  /* a function argument was not okay */
  CURLHE_NOT_BUILT_IN   /* if API was disabled in the build */
} CURLHcode;

CURL_EXTERN CURLHcode curl_easy_header(CURL *easy,
                                       const char *name,
                                       size_t index,
                                       unsigned int origin,
                                       int request,
                                       struct curl_header **hout);

CURL_EXTERN struct curl_header *curl_easy_nextheader(CURL *easy,
                                                     unsigned int origin,
                                                     int request,
                                                     struct curl_header *prev);
"#;

/// `options.h`, after the `extern "C"` open: a tag forward declaration.
///
/// Same rule as `CURLMsg`, for the same reason. `struct curl_easyoption`
/// (options.h:51) has a `curl_easytype type` member and so cannot precede
/// the generated `curl_easytype` enum, while all three introspection
/// functions take or return `const struct curl_easyoption *`. Forward
/// declaring the tag at file scope here makes those prototypes
/// order-independent: without it, whichever prototype mentioned the tag
/// first inside a parameter list would scope it to that prototype, and gcc
/// would report `-Wvisibility`, which the `-Werror` that
/// `docs/examples/Makefile.am:54-55` may add through
/// `CFLAGS += @CURL_CFLAG_EXTRAS@` turns into a failure of all 129 example
/// compilations.
const OPTIONS_H_DECLS: &str = "\nstruct curl_easyoption;\n";

/// `options.h`, after the generated block: the definition itself, with the
/// comment `options.h:49-50` carries.
const OPTIONS_H_POST: &str = r#"
/* The CURLOPTTYPE_* id ranges can still be used to figure out what type/size
   to use for curl_easy_setopt() for the given id */
struct curl_easyoption {
  const char *name;
  CURLoption id;
  curl_easytype type;
  unsigned int flags;
};

/* The three prototypes below are carried verbatim. `struct curl_easyoption` is
   tag-form only, so cbindgen renders it `const curl_easyoption *` -- not a
   valid C type name without the `struct` keyword, and gcc rejects it. The
   `by_id` parameter is additionally a CURLoption where the Rust definition
   must take a c_int. See cbindgen.toml, "Group 5e". */

CURL_EXTERN const struct curl_easyoption *
curl_easy_option_by_name(const char *name);

CURL_EXTERN const struct curl_easyoption *
curl_easy_option_by_id(CURLoption id);

CURL_EXTERN const struct curl_easyoption *
curl_easy_option_next(const struct curl_easyoption *prev);
"#;

/// `urlapi.h`, before the `extern "C"` open.
///
/// TWO leading newlines, not one, and the difference is a line of the public
/// header. `sibling_prologue` appends this straight onto the banner, whose last
/// line is unterminated, so the first newline ends `***/` and only the second
/// produces the blank line that `include/curl/urlapi.h:26` carries between the
/// banner and the include. Measured: with one newline the render was
/// byte-identical to the frozen header except for that missing blank line.
/// `MPRINTF_H_INCLUDES` has two for the same reason; `MULTI_H_INCLUDES`
/// deliberately has one, because `include/curl/multi.h:25-26` runs `***/`
/// straight into its `/*` comment with no blank line at all.
const URLAPI_H_INCLUDES: &str = "\n\n#include \"curl.h\"\n";

/// `urlapi.h`, after the generated block: all six prototypes, each preceded by
/// the frozen C comment the header carries for it.
///
/// SIX rather than three since [`URLAPI_H_ITEMS`] emptied. The three that
/// joined -- `curl_url`, `curl_url_cleanup` and `curl_url_dup` -- are here for
/// the measured reason recorded there: cbindgen writes a prototype with
/// `CURL_EXTERN` on a line of its own and prefixes it with its ENTIRE Rust doc
/// comment, so the frozen four-line C comment that
/// `docs/libcurl/curl_url*.md` cross-references would be replaced by
/// Rust-internal prose -- `# Safety` headings, markdown emphasis and
/// `super::panic_boundary::guard_tx` intra-doc links -- in a shipped public C
/// header. Identical in kind to what was measured for `header.h`'s two
/// prototypes; see [`VERBATIM_FUNCTIONS`].
///
/// The rule they share, and why it is a rule rather than three coincidences: a
/// C caller may pass any value of an enum parameter's compatible integer type,
/// and libcurl ANSWERS an out-of-range one -- `curl_url_strerror` with
/// `"CURLUcode unknown"` (`lib/strerror.c:524`), and `curl_url_get` and
/// `curl_url_set` with `CURLUE_UNKNOWN_PART` (`lib/urlapi.c:1626-1628`,
/// `:1773-1774`, `:1873-1874`). A Rust `#[repr(C)]` enum parameter would make
/// each of those DEFINED inputs an invalid Rust value, which is undefined
/// behaviour before the callee runs. So the Rust signature takes a `c_int` and
/// the header's spelling is preserved here, exactly as it is for
/// `curl_version_info(CURLversion)` in `curl.h` and
/// `curl_easy_option_by_id(CURLoption)` in `options.h`.
const URLAPI_H_POST: &str = r#"
/*
 * curl_url() creates a new CURLU handle and returns a pointer to it.
 * Must be freed with curl_url_cleanup().
 */
CURL_EXTERN CURLU *curl_url(void);

/*
 * curl_url_cleanup() frees the CURLU handle and related resources used for
 * the URL parsing. It will not free strings previously returned with the URL
 * API.
 */
CURL_EXTERN void curl_url_cleanup(CURLU *handle);

/*
 * curl_url_dup() duplicates a CURLU handle and returns a new copy. The new
 * handle must also be freed with curl_url_cleanup().
 */
CURL_EXTERN CURLU *curl_url_dup(const CURLU *in);

/*
 * curl_url_get() extracts a specific part of the URL from a CURLU
 * handle. Returns error code. The returned pointer MUST be freed with
 * curl_free() afterwards.
 */
CURL_EXTERN CURLUcode curl_url_get(const CURLU *handle, CURLUPart what,
                                   char **part, unsigned int flags);

/*
 * curl_url_set() sets a specific part of the URL in a CURLU handle. Returns
 * error code. The passed in string will be copied. Passing a NULL instead of
 * a part string, clears that part.
 */
CURL_EXTERN CURLUcode curl_url_set(CURLU *handle, CURLUPart what,
                                   const char *part, unsigned int flags);

/*
 * curl_url_strerror() turns a CURLUcode value into the equivalent human
 * readable error string. This is useful for printing meaningful error
 * messages.
 */
CURL_EXTERN const char *curl_url_strerror(CURLUcode);
"#;

/// `urlapi.h`, after the `extern "C"` open: the two URL-API enums, the 16
/// `CURLU_*` flag bits and the handle typedef, in the frozen order.
///
/// Every byte below is `include/curl/urlapi.h:33-107`, character for
/// character. Four measured reasons none of it can be generated, each
/// recorded at [`URLAPI_H_ITEMS`]:
///
/// * ORDER. The flag bits and the handle typedef sit BETWEEN the enums and the
///   prototypes. A cbindgen pass emits one contiguous generated region, so no
///   preamble/postamble split can place verbatim text there.
/// * TRAILING COMMENTS. `CURLUcode`'s `/* 1 */` through `/* 31 */` -- the C
///   tree's own drift guard against an accidental insertion -- and
///   `CURLUPART_ZONEID`'s `/* added in 7.65.0 */` are TRAILING comments.
///   cbindgen has no trailing-comment form: it writes a block ABOVE the member
///   and adds an explicit `= N`.
/// * THE HANDLE TYPEDEF, the subtler of the two handle mis-renderings.
///   `urlapi.h:107` spells it `typedef struct Curl_URL CURLU;`, where the
///   struct tag differs from the typedef name. cbindgen would emit
///   `typedef struct CURLU CURLU;`, which compiles and is still wrong, because
///   it introduces a DIFFERENT incomplete type from the one libcurl's own
///   translation units define. This is also the one header whose handle is a
///   genuine opaque struct rather than `void`, so it must stay incomplete and
///   must never be flattened to `typedef void CURLU;` for uniformity with
///   `CURL`, `CURLM` and `CURLSH`.
/// * THE FLAG BITS, for the reason the block's own comment gives: cbindgen
///   DROPS an `L` suffix, rewrites hex as decimal, and cannot express a
///   `#define` whose value is another identifier.
const URLAPI_H_DECLS: &str = r#"
/* the error codes for the URL API */
typedef enum {
  CURLUE_OK,
  CURLUE_BAD_HANDLE,          /* 1 */
  CURLUE_BAD_PARTPOINTER,     /* 2 */
  CURLUE_MALFORMED_INPUT,     /* 3 */
  CURLUE_BAD_PORT_NUMBER,     /* 4 */
  CURLUE_UNSUPPORTED_SCHEME,  /* 5 */
  CURLUE_URLDECODE,           /* 6 */
  CURLUE_OUT_OF_MEMORY,       /* 7 */
  CURLUE_USER_NOT_ALLOWED,    /* 8 */
  CURLUE_UNKNOWN_PART,        /* 9 */
  CURLUE_NO_SCHEME,           /* 10 */
  CURLUE_NO_USER,             /* 11 */
  CURLUE_NO_PASSWORD,         /* 12 */
  CURLUE_NO_OPTIONS,          /* 13 */
  CURLUE_NO_HOST,             /* 14 */
  CURLUE_NO_PORT,             /* 15 */
  CURLUE_NO_QUERY,            /* 16 */
  CURLUE_NO_FRAGMENT,         /* 17 */
  CURLUE_NO_ZONEID,           /* 18 */
  CURLUE_BAD_FILE_URL,        /* 19 */
  CURLUE_BAD_FRAGMENT,        /* 20 */
  CURLUE_BAD_HOSTNAME,        /* 21 */
  CURLUE_BAD_IPV6,            /* 22 */
  CURLUE_BAD_LOGIN,           /* 23 */
  CURLUE_BAD_PASSWORD,        /* 24 */
  CURLUE_BAD_PATH,            /* 25 */
  CURLUE_BAD_QUERY,           /* 26 */
  CURLUE_BAD_SCHEME,          /* 27 */
  CURLUE_BAD_SLASHES,         /* 28 */
  CURLUE_BAD_USER,            /* 29 */
  CURLUE_LACKS_IDN,           /* 30 */
  CURLUE_TOO_LARGE,           /* 31 */
  CURLUE_LAST
} CURLUcode;

typedef enum {
  CURLUPART_URL,
  CURLUPART_SCHEME,
  CURLUPART_USER,
  CURLUPART_PASSWORD,
  CURLUPART_OPTIONS,
  CURLUPART_HOST,
  CURLUPART_PORT,
  CURLUPART_PATH,
  CURLUPART_QUERY,
  CURLUPART_FRAGMENT,
  CURLUPART_ZONEID /* added in 7.65.0 */
} CURLUPart;

#define CURLU_DEFAULT_PORT (1 << 0)       /* return default port number */
#define CURLU_NO_DEFAULT_PORT (1 << 1)    /* act as if no port number was set,
                                             if the port number matches the
                                             default for the scheme */
#define CURLU_DEFAULT_SCHEME (1 << 2)     /* return default scheme if
                                             missing */
#define CURLU_NON_SUPPORT_SCHEME (1 << 3) /* allow non-supported scheme */
#define CURLU_PATH_AS_IS (1 << 4)         /* leave dot sequences */
#define CURLU_DISALLOW_USER (1 << 5)      /* no user+password allowed */
#define CURLU_URLDECODE (1 << 6)          /* URL decode on get */
#define CURLU_URLENCODE (1 << 7)          /* URL encode on set */
#define CURLU_APPENDQUERY (1 << 8)        /* append a form style part */
#define CURLU_GUESS_SCHEME (1 << 9)       /* legacy curl-style guessing */
#define CURLU_NO_AUTHORITY (1 << 10)      /* Allow empty authority when the
                                             scheme is unknown. */
#define CURLU_ALLOW_SPACE (1 << 11)       /* Allow spaces in the URL */
#define CURLU_PUNYCODE (1 << 12)          /* get the hostname in punycode */
#define CURLU_PUNY2IDN (1 << 13)          /* punycode => IDN conversion */
#define CURLU_GET_EMPTY (1 << 14)         /* allow empty queries and fragments
                                             when extracting the URL or the
                                             components */
#define CURLU_NO_GUESS_SCHEME (1 << 15)   /* for get, do not accept a guess */

typedef struct Curl_URL CURLU;
"#;

/// `websockets.h`, after the `extern "C"` open: the WHOLE interior of the
/// frozen header, `websockets.h:31-92` byte for byte.
///
/// Every construct in it is one cbindgen cannot render to the frozen bytes,
/// which is why nothing is left for it to generate and
/// [`WEBSOCKETS_H_ITEMS`] is empty. Four independent measurements, each
/// naming what the generated alternative produced:
///
///   1. ORDER. The nine `CURLWS_*` bits are not contiguous with each other
///      and not contiguous with the prototypes: six precede
///      `curl_ws_recv`, `CURLWS_PONG` follows it, and the two option bits
///      follow `curl_ws_start_frame`. cbindgen writes one generated region,
///      so this interleaving is unreachable through a partition -- and
///      `cbindgen.toml`'s `[const]` note commits to reproducing the
///      placement, which only this block can honour.
///   2. THE `L` SUFFIX. cbindgen was measured to DROP it -- `1L` comes out
///      as `1` -- which would change `CURLOPT_WS_OPTIONS`'s varargs type
///      from `long` to `int`. `CURLWS_RAW_MODE` and `CURLWS_NOAUTOPONG`
///      are passed through `curl_easy_setopt`, so the suffix is ABI.
///   3. THE `struct` KEYWORD. `struct curl_ws_frame` is tag-form with no
///      typedef, and `style = "type"` spells a struct by its bare name, so
///      a generated `curl_ws_recv` or `curl_ws_meta` emits C that does not
///      compile. See [`WEBSOCKETS_H_ITEMS`].
///   4. THE PROTOTYPE COMMENTS AND WRAPPING. The four `/* NAME
///      curl_ws_*() */` blocks are the frozen file's own, whereas
///      `documentation_length = "full"` would emit each function's entire
///      Rust doc comment -- `# Errors` and `# Safety` headings and all --
///      and re-wrap the parameter lists to `line_length`. `docs/libcurl/`'s
///      `curl_ws_*` pages are cross-checked against these declarations, so
///      both the prose and the hand-wrapping are part of what is frozen.
///
/// `struct curl_ws_frame` would be verbatim regardless of the above, being
/// layout-visible: consumers read all five of its fields off the pointer
/// `curl_ws_recv` stores through `metap` and the one `curl_ws_meta`
/// returns. `age` is a struct-version field and stays FIRST -- moving it
/// would change every consumer's `offsetof`. Its `int flags` is signed
/// while `curl_ws_send`'s `unsigned int flags` parameter is not; that
/// asymmetry is in the frozen file and harmonising it would change the ABI
/// of both.
const WEBSOCKETS_H_DECLS: &str = r#"
struct curl_ws_frame {
  int age;              /* zero */
  int flags;            /* See the CURLWS_* defines */
  curl_off_t offset;    /* the offset of this data into the frame */
  curl_off_t bytesleft; /* number of pending bytes left of the payload */
  size_t len;           /* size of the current data chunk */
};

/* flag bits */
#define CURLWS_TEXT       (1 << 0)
#define CURLWS_BINARY     (1 << 1)
#define CURLWS_CONT       (1 << 2)
#define CURLWS_CLOSE      (1 << 3)
#define CURLWS_PING       (1 << 4)
#define CURLWS_OFFSET     (1 << 5)

/*
 * NAME curl_ws_recv()
 *
 * DESCRIPTION
 *
 * Receives data from the websocket connection. Use after successful
 * curl_easy_perform() with CURLOPT_CONNECT_ONLY option.
 */
CURL_EXTERN CURLcode curl_ws_recv(CURL *curl, void *buffer, size_t buflen,
                                  size_t *recv,
                                  const struct curl_ws_frame **metap);

/* flags for curl_ws_send() */
#define CURLWS_PONG       (1 << 6)

/*
 * NAME curl_ws_send()
 *
 * DESCRIPTION
 *
 * Sends data over the websocket connection. Use after successful
 * curl_easy_perform() with CURLOPT_CONNECT_ONLY option.
 */
CURL_EXTERN CURLcode curl_ws_send(CURL *curl, const void *buffer,
                                  size_t buflen, size_t *sent,
                                  curl_off_t fragsize,
                                  unsigned int flags);

/*
 * NAME curl_ws_start_frame()
 *
 * DESCRIPTION
 *
 * Buffers a websocket frame header with the given flags and length.
 * Errors when a previous frame is not complete, e.g. not all its
 * payload has been added.
 */
CURL_EXTERN CURLcode curl_ws_start_frame(CURL *curl,
                                         unsigned int flags,
                                         curl_off_t frame_len);

/* bits for the CURLOPT_WS_OPTIONS bitmask: */
#define CURLWS_RAW_MODE   (1L << 0)
#define CURLWS_NOAUTOPONG (1L << 1)

CURL_EXTERN const struct curl_ws_frame *curl_ws_meta(CURL *curl);
"#;

/// `mprintf.h`, before the `extern "C"` open.
const MPRINTF_H_INCLUDES: &str = r#"

#include <stdarg.h>
#include <stdio.h> /* needed for FILE */
#include "curl.h"  /* for CURL_EXTERN */
"#;

/// `mprintf.h`, after the `extern "C"` open: the `CURL_TEMP_PRINTF`
/// cascade. It resolves to a `__attribute__((format(printf, n, m)))` on
/// compilers that support it, to the mingw-w64 variant on MinGW and to
/// nothing elsewhere. cbindgen's `[fn] postfix` is global and same-line, so
/// it could express none of that: the attribute differs per function, sits
/// on the following line with a two-space indent, and depends on a
/// preprocessor cascade.
const MPRINTF_H_DECLS: &str = r#"
#ifndef CURL_TEMP_PRINTF
#if (defined(__GNUC__) || defined(__clang__) ||                         \
  defined(__IAR_SYSTEMS_ICC__)) &&                                      \
  defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L) &&         \
  !defined(CURL_NO_FMT_CHECKS)
#if defined(__MINGW32__) && !defined(__clang__)
#ifdef __MINGW_PRINTF_FORMAT  /* mingw-w64 3.0.0+. Needs stdio.h. */
#define CURL_TEMP_PRINTF(fmt, arg) \
  __attribute__((format(__MINGW_PRINTF_FORMAT, fmt, arg)))
#else
#define CURL_TEMP_PRINTF(fmt, arg)
#endif
#else
#define CURL_TEMP_PRINTF(fmt, arg) \
  __attribute__((format(printf, fmt, arg)))
#endif
#else
#define CURL_TEMP_PRINTF(fmt, arg)
#endif
#endif

CURL_EXTERN int curl_mprintf(const char *format, ...)
  CURL_TEMP_PRINTF(1, 2);
CURL_EXTERN int curl_mfprintf(FILE *fd, const char *format, ...)
  CURL_TEMP_PRINTF(2, 3);
CURL_EXTERN int curl_msprintf(char *buffer, const char *format, ...)
  CURL_TEMP_PRINTF(2, 3);
CURL_EXTERN int curl_msnprintf(char *buffer, size_t maxlength,
                               const char *format, ...)
  CURL_TEMP_PRINTF(3, 4);
CURL_EXTERN int curl_mvprintf(const char *format, va_list args)
  CURL_TEMP_PRINTF(1, 0);
CURL_EXTERN int curl_mvfprintf(FILE *fd, const char *format, va_list args)
  CURL_TEMP_PRINTF(2, 0);
CURL_EXTERN int curl_mvsprintf(char *buffer, const char *format, va_list args)
  CURL_TEMP_PRINTF(2, 0);
CURL_EXTERN int curl_mvsnprintf(char *buffer, size_t maxlength,
                                const char *format, va_list args)
  CURL_TEMP_PRINTF(3, 0);
CURL_EXTERN char *curl_maprintf(const char *format, ...)
  CURL_TEMP_PRINTF(1, 2);
CURL_EXTERN char *curl_mvaprintf(const char *format, va_list args)
  CURL_TEMP_PRINTF(1, 0);

#undef CURL_TEMP_PRINTF
"#;

/// The seven generated siblings of `curl.h`.
///
/// `curl.h` is absent on purpose: its prologue and epilogue already live in
/// `cbindgen.toml`, which is the single configuration, so its pass uses
/// that file's `header` and `trailer` untouched and overrides only the
/// export partition. Restating them here would be the duplication the
/// single-configuration rule exists to prevent.
const SIBLING_HEADERS: [HeaderSpec; 7] = [
    HeaderSpec {
        file: "easy.h",
        guard: "CURLINC_EASY_H",
        preamble: EASY_H_DECLS,
        postamble: EASY_H_POST,
        extern_c_close: EXTERN_C_CLOSE_COMMENTED,
        blank_before_guard_close: true,
        named_guard_close: false,
        items: EASY_H_ITEMS,
        // The two flag bits are carried with the struct they document,
        // because the C header groups them under one comment and splitting
        // them would gain nothing. They are the only names this file
        // suppresses that `cbindgen.toml` does not.
        verbatim: &["CURL_BLOB_COPY", "CURL_BLOB_NOCOPY"],
    },
    HeaderSpec {
        file: "multi.h",
        guard: "CURLINC_MULTI_H",
        preamble: MULTI_H_DECLS,
        postamble: MULTI_H_POST,
        extern_c_close: EXTERN_C_CLOSE_COMMENTED,
        blank_before_guard_close: true,
        named_guard_close: false,
        items: MULTI_H_ITEMS,
        verbatim: &[],
    },
    HeaderSpec {
        file: "urlapi.h",
        guard: "CURLINC_URLAPI_H",
        preamble: URLAPI_H_DECLS,
        postamble: URLAPI_H_POST,
        extern_c_close: EXTERN_C_CLOSE_COMMENTED,
        blank_before_guard_close: true,
        named_guard_close: true,
        items: URLAPI_H_ITEMS,
        // All five are declared by URLAPI_H_DECLS and URLAPI_H_POST, so every
        // pass must suppress them -- this one included, or they would be
        // declared twice in the same file. Naming them here is what keeps them
        // out of the UMBRELLA as well: `curl.h`'s suppression list is built
        // from `observed` intersected with the sibling ITEM lists, so a name
        // dropped from `URLAPI_H_ITEMS` without being added here would migrate
        // into `curl.h` instead of disappearing. Same arrangement as
        // `header.h`'s three.
        verbatim: &[
            "CURLUcode",
            "CURLUPart",
            "curl_url",
            "curl_url_cleanup",
            "curl_url_dup",
        ],
    },
    HeaderSpec {
        file: "options.h",
        guard: "CURLINC_OPTIONS_H",
        preamble: OPTIONS_H_DECLS,
        postamble: OPTIONS_H_POST,
        extern_c_close: EXTERN_C_CLOSE_COMMENTED,
        // Measured false, and the only header for which it is: options.h
        // closes the __cplusplus #endif and the guard #endif back to back
        // with no blank line between them.
        blank_before_guard_close: false,
        named_guard_close: true,
        items: OPTIONS_H_ITEMS,
        verbatim: &[],
    },
    HeaderSpec {
        file: "header.h",
        guard: "CURLINC_HEADER_H",
        preamble: HEADER_H_DECLS,
        postamble: "",
        extern_c_close: EXTERN_C_CLOSE_COMMENTED,
        blank_before_guard_close: true,
        named_guard_close: true,
        items: HEADER_H_ITEMS,
        // All three are declared by HEADER_H_DECLS, so every pass must
        // suppress them -- this one included, or they would be declared
        // twice in the same file. `CURLHcode` additionally has to be named
        // here because it is listed under `[export] include` in
        // cbindgen.toml: that list is replaced per pass by
        // `apply_partition`, so the entry is inert, but the exclusion is
        // what actually keeps the enumeration out of the umbrella.
        verbatim: &["CURLHcode", "curl_easy_header", "curl_easy_nextheader"],
    },
    HeaderSpec {
        file: "websockets.h",
        guard: "CURLINC_WEBSOCKETS_H",
        preamble: WEBSOCKETS_H_DECLS,
        postamble: "",
        // The one header that closes with a bare brace.
        extern_c_close: EXTERN_C_CLOSE_BARE,
        blank_before_guard_close: true,
        named_guard_close: true,
        items: WEBSOCKETS_H_ITEMS,
        // All four are declared by WEBSOCKETS_H_DECLS, so every pass must
        // suppress them -- this one included, or they would be declared
        // twice in the same file. Naming them here is also what keeps them
        // out of the UMBRELLA: `curl.h`'s suppression list is built from
        // `verbatim` plus `observed` intersected with the sibling ITEM
        // lists, and this header's item list is now empty, so without these
        // four entries the prototypes would migrate into `curl.h` -- in
        // cbindgen's own order and wrapping, and spelling
        // `struct curl_ws_frame` without its keyword. Same arrangement as
        // `header.h`'s three and `urlapi.h`'s five.
        verbatim: &[
            "curl_ws_meta",
            "curl_ws_recv",
            "curl_ws_send",
            "curl_ws_start_frame",
        ],
    },
    HeaderSpec {
        file: "mprintf.h",
        guard: "CURLINC_MPRINTF_H",
        preamble: MPRINTF_H_DECLS,
        postamble: "",
        extern_c_close: EXTERN_C_CLOSE_COMMENTED,
        blank_before_guard_close: true,
        named_guard_close: true,
        items: MPRINTF_H_ITEMS,
        verbatim: &[],
    },
];

/// Text placed before the `extern "C"` open, per header. Kept beside
/// [`SIBLING_HEADERS`] rather than inside it so that the struct holds only
/// scalars and slices and stays readable.
fn before_extern_c(file: &str) -> &'static str {
    match file {
        "multi.h" => MULTI_H_INCLUDES,
        "urlapi.h" => URLAPI_H_INCLUDES,
        "mprintf.h" => MPRINTF_H_INCLUDES,
        // easy.h, options.h, header.h and websockets.h carry no #include at
        // all. Measured across include/curl/: only curl.h, multi.h,
        // urlapi.h, mprintf.h and stdcheaders.h contain one. The four that
        // do not depend entirely on curl.h having already defined CURL,
        // CURLcode, CURLoption, CURL_EXTERN and size_t, which is why the
        // umbrella include order in curl.h's trailer is a compile-order
        // dependency and not a style choice.
        _ => "",
    }
}

// Section 4b: curl.h's own verbatim text
//
// WHY EACH BLOCK IS HERE RATHER THAN GENERATED. Two independent reasons,
// both measured:
//
//   1. TAG FORM. `cbindgen.toml` sets `style = "type"` (":272"), so cbindgen
//      writes `typedef struct { ... } Name;` -- an anonymous tag. curl.h
//      declares twelve structs and five enums in TAG form, and code in the
//      tree names them that way: `struct curl_khkey` has a member declared
//      `enum curl_khtype keytype;`, and `include/curl/typecheck-gcc.h` names
//      `struct curl_slist`, `struct curl_httppost` and others. A typedef of
//      an anonymous tag cannot satisfy `struct X` or `enum X`. Measured
//      across all eight headers: every one of the seventeen tag-form STRUCTS
//      is already in `[export] exclude`; the five tag-form ENUMS
//      (`curl_khtype`, `curl_khstat`, `curl_khmatch`, `CURL_NETRC_OPTION`,
//      `CURL_TLSAUTH`) are not, so this script suppresses them itself
//      through `CURL_H_VERBATIM_NAMES`.
//   2. DEPRECATION SPELLING. cbindgen renders a deprecation note through
//      `format.replace("{}", &format!("{note:?}"))` (`annotation.rs:70-100`),
//      which always Debug-quotes it. curl.h needs
//      `CURL_DEPRECATED(8.3.0, "")` with an UNQUOTED version token, and the
//      format string is global while curl.h uses seven different versions.
//      `curl_sslbackend`, `CURLformoption`, `CURLFORMcode`, `CURLINFO` and
//      the `curl_form*` trio all carry such attributes.
//
// * `CURLoption` (curl.h:1138-2262) and its 17 `#define` aliases. Splicing
//   1,125 lines of enumeration here would create a second population, and two
//   populations drift silently. `cbindgen.toml` lists `CURLoption` under
//   `[export] exclude`; `curl_h_export_exclusions` lifts that one exclusion
//   for the umbrella pass so the enumeration is generated from `opts.rs`
//   instead. The generator macros it expands ARE here, which is what
//   `cbindgen.toml`'s "deliberately not here" note asks for.
//   * `include/curl/curl.h`'s own text is never READ by this script. The
//     header is an OUTPUT of this build, so parsing it would close a cycle
//     (header <- build.rs <- header) and reintroduce exactly that drift.
//     `include/curl/curlver.h` is read, and only because it is in
//     `NEVER_GENERATED` and therefore an input.

/// `curl.h`'s backward-compatibility `#define` blocks, carried verbatim.
///
/// These cannot be generated. cbindgen emits no preprocessor conditionals at
/// all, and the frozen header wraps most of these aliases in `#ifndef
/// CURL_NO_OLDIES` guards (include/curl/curl.h:650-736 and:2264-2295) with
/// `#undef CURLOPT_DNS_USE_GLOBAL_CACHE` in the `#else` branch.
///
/// Placement. Everything here is a `#define`, so it is valid anywhere the
/// preprocessor sees it before use; it goes after the generated body because
/// two of the blocks name generated enumerators and one of them
/// (`CURLOPT_PROGRESSDATA`, frozen at curl.h:1341) sits INSIDE the
/// `typedef enum` in the original, which is a position cbindgen cannot write
/// into. `CURLOPT_RTSPHEADER` (curl.h:2306) is unguarded in the frozen header
/// and stays unguarded here.
const CURL_H_OLDIES: &str = r#"#ifndef CURL_NO_OLDIES /* define this to test if your app builds with all
                          the obsolete stuff removed! */

/* removed in 7.53.0 */
#define CURLE_FUNCTION_NOT_FOUND CURLE_OBSOLETE41

/* removed in 7.56.0 */
#define CURLE_HTTP_POST_ERROR CURLE_OBSOLETE34

/* Previously obsolete error code reused in 7.38.0 */
#define CURLE_OBSOLETE16 CURLE_HTTP2

/* Previously obsolete error codes reused in 7.24.0 */
#define CURLE_OBSOLETE10 CURLE_FTP_ACCEPT_FAILED
#define CURLE_OBSOLETE12 CURLE_FTP_ACCEPT_TIMEOUT

/*  compatibility with older names */
#define CURLOPT_ENCODING CURLOPT_ACCEPT_ENCODING
#define CURLE_FTP_WEIRD_SERVER_REPLY CURLE_WEIRD_SERVER_REPLY

/* The following were added in 7.62.0 */
#define CURLE_SSL_CACERT CURLE_PEER_FAILED_VERIFICATION

/* The following were added in 7.21.5, April 2011 */
#define CURLE_UNKNOWN_TELNET_OPTION CURLE_UNKNOWN_OPTION

/* Added for 7.78.0 */
#define CURLE_TELNET_OPTION_SYNTAX CURLE_SETOPT_OPTION_SYNTAX

/* The following were added in 7.17.1 */
/* These are scheduled to disappear by 2009 */
#define CURLE_SSL_PEER_CERTIFICATE CURLE_PEER_FAILED_VERIFICATION

/* The following were added in 7.17.0 */
/* These are scheduled to disappear by 2009 */
#define CURLE_OBSOLETE CURLE_OBSOLETE50 /* no one should be using this! */
#define CURLE_BAD_PASSWORD_ENTERED CURLE_OBSOLETE46
#define CURLE_BAD_CALLING_ORDER CURLE_OBSOLETE44
#define CURLE_FTP_USER_PASSWORD_INCORRECT CURLE_OBSOLETE10
#define CURLE_FTP_CANT_RECONNECT CURLE_OBSOLETE16
#define CURLE_FTP_COULDNT_GET_SIZE CURLE_OBSOLETE32
#define CURLE_FTP_COULDNT_SET_ASCII CURLE_OBSOLETE29
#define CURLE_FTP_WEIRD_USER_REPLY CURLE_OBSOLETE12
#define CURLE_FTP_WRITE_ERROR CURLE_OBSOLETE20
#define CURLE_LIBRARY_NOT_FOUND CURLE_OBSOLETE40
#define CURLE_MALFORMAT_USER CURLE_OBSOLETE24
#define CURLE_SHARE_IN_USE CURLE_OBSOLETE57
#define CURLE_URL_MALFORMAT_USER CURLE_NOT_BUILT_IN

#define CURLE_FTP_ACCESS_DENIED CURLE_REMOTE_ACCESS_DENIED
#define CURLE_FTP_COULDNT_SET_BINARY CURLE_FTP_COULDNT_SET_TYPE
#define CURLE_FTP_QUOTE_ERROR CURLE_QUOTE_ERROR
#define CURLE_TFTP_DISKFULL CURLE_REMOTE_DISK_FULL
#define CURLE_TFTP_EXISTS CURLE_REMOTE_FILE_EXISTS
#define CURLE_HTTP_RANGE_ERROR CURLE_RANGE_ERROR
#define CURLE_FTP_SSL_FAILED CURLE_USE_SSL_FAILED

/* The following were added earlier */

#define CURLE_OPERATION_TIMEOUTED CURLE_OPERATION_TIMEDOUT
#define CURLE_HTTP_NOT_FOUND CURLE_HTTP_RETURNED_ERROR
#define CURLE_HTTP_PORT_FAILED CURLE_INTERFACE_FAILED
#define CURLE_FTP_COULDNT_STOR_FILE CURLE_UPLOAD_FAILED
#define CURLE_FTP_PARTIAL_FILE CURLE_PARTIAL_FILE
#define CURLE_FTP_BAD_DOWNLOAD_RESUME CURLE_BAD_DOWNLOAD_RESUME
#define CURLE_LDAP_INVALID_URL CURLE_OBSOLETE62
#define CURLE_CONV_REQD CURLE_OBSOLETE76
#define CURLE_CONV_FAILED CURLE_OBSOLETE75

/* This was the error code 50 in 7.7.3 and a few earlier versions, this
   is no longer used by libcurl but is instead #defined here only to not
   make programs break */
#define CURLE_ALREADY_COMPLETE 99999

/* Provide defines for really old option names */
#define CURLOPT_FILE CURLOPT_WRITEDATA /* name changed in 7.9.7 */
#define CURLOPT_INFILE CURLOPT_READDATA /* name changed in 7.9.7 */
#define CURLOPT_WRITEHEADER CURLOPT_HEADERDATA

/* Since long deprecated options with no code in the lib that does anything
   with them. */
#define CURLOPT_WRITEINFO CURLOPT_OBSOLETE40
#define CURLOPT_CLOSEPOLICY CURLOPT_OBSOLETE72
#define CURLOPT_OBSOLETE72 9999
#define CURLOPT_OBSOLETE40 9999

#endif /* !CURL_NO_OLDIES */

#ifndef CURL_NO_OLDIES /* define this to test if your app builds with all
                          the obsolete stuff removed! */

/* Backwards compatibility with older names */
/* These are scheduled to disappear by 2011 */

/* This was added in version 7.19.1 */
#define CURLOPT_POST301 CURLOPT_POSTREDIR

/* These are scheduled to disappear by 2009 */

/* The following were added in 7.17.0 */
#define CURLOPT_SSLKEYPASSWD CURLOPT_KEYPASSWD
#define CURLOPT_FTPAPPEND CURLOPT_APPEND
#define CURLOPT_FTPLISTONLY CURLOPT_DIRLISTONLY
#define CURLOPT_FTP_SSL CURLOPT_USE_SSL

/* The following were added earlier */

#define CURLOPT_SSLCERTPASSWD CURLOPT_KEYPASSWD
#define CURLOPT_KRB4LEVEL CURLOPT_KRBLEVEL

/* */
#define CURLOPT_FTP_RESPONSE_TIMEOUT CURLOPT_SERVER_RESPONSE_TIMEOUT

/* Added in 8.2.0 */
#define CURLOPT_MAIL_RCPT_ALLLOWFAILS CURLOPT_MAIL_RCPT_ALLOWFAILS

#else
/* This is set if CURL_NO_OLDIES is defined at compile-time */
#undef CURLOPT_DNS_USE_GLOBAL_CACHE /* soon obsolete */
#endif

#define CURLOPT_PROGRESSDATA CURLOPT_XFERINFODATA
  /* Convenient "aliases" */
#define CURLOPT_RTSPHEADER CURLOPT_HTTPHEADER
"#;

/// `curl.h`, between its `#include` block and the generated declarations.
///
/// Goes into cbindgen's `after_includes`. Two measured facts make that the
/// only workable slot: `cbindgen.toml`'s `header` already opens
/// `extern "C" {` and its `trailer` closes it, so text placed here lands
/// inside the block; and with `no_includes = true` and empty include lists
/// cbindgen's include section early-returns unless `after_includes` is
/// `Some`, so setting it is also what makes the section emit at all.
const CURL_H_FORWARD: &str = r#"
/* Tag forward declarations. These twelve are the only synthetic lines in
   any generated header: curl.h itself has no need of them, because it
   defines each struct before the first prototype that names it. Here the
   generated block sits between the two, so without a file-scope tag
   declaration the tag would be scoped to a parameter list and gcc reports
   -Wvisibility -- which becomes 129 failed compilations wherever
   docs/examples/Makefile.am:54-55 adds -Werror. Adding a tag declaration
   cannot change the ABI: no member, no size, no alignment. */
struct curl_httppost;
struct curl_fileinfo;
struct curl_sockaddr;
struct curl_khkey;
struct curl_hstsentry;
struct curl_index;
struct curl_forms;
struct curl_slist;
struct curl_certinfo;
struct curl_tlssessioninfo;
struct curl_version_info_data;
typedef struct curl_version_info_data curl_version_info_data;

/* enum for the different supported SSL backends */
typedef enum {
  CURLSSLBACKEND_NONE = 0,
  CURLSSLBACKEND_OPENSSL = 1,
  CURLSSLBACKEND_GNUTLS = 2,
  CURLSSLBACKEND_NSS                    CURL_DEPRECATED(8.3.0, "") = 3,
  CURLSSLBACKEND_OBSOLETE4 = 4,  /* Was QSOSSL. */
  CURLSSLBACKEND_GSKIT                  CURL_DEPRECATED(8.3.0, "") = 5,
  CURLSSLBACKEND_POLARSSL               CURL_DEPRECATED(7.69.0, "") = 6,
  CURLSSLBACKEND_WOLFSSL = 7,
  CURLSSLBACKEND_SCHANNEL = 8,
  CURLSSLBACKEND_SECURETRANSPORT        CURL_DEPRECATED(8.15.0, "") = 9,
  CURLSSLBACKEND_AXTLS                  CURL_DEPRECATED(7.61.0, "") = 10,
  CURLSSLBACKEND_MBEDTLS = 11,
  CURLSSLBACKEND_MESALINK               CURL_DEPRECATED(7.82.0, "") = 12,
  CURLSSLBACKEND_BEARSSL                CURL_DEPRECATED(8.15.0, "") = 13,
  CURLSSLBACKEND_RUSTLS = 14
} curl_sslbackend;

enum curl_khtype {
  CURLKHTYPE_UNKNOWN,
  CURLKHTYPE_RSA1,
  CURLKHTYPE_RSA,
  CURLKHTYPE_DSS,
  CURLKHTYPE_ECDSA,
  CURLKHTYPE_ED25519
};

/* this is the set of return values expected from the curl_sshkeycallback
   callback */
enum curl_khstat {
  CURLKHSTAT_FINE_ADD_TO_FILE,
  CURLKHSTAT_FINE,
  CURLKHSTAT_REJECT, /* reject the connection, return an error */
  CURLKHSTAT_DEFER,  /* do not accept it, but we cannot answer right now.
                        Causes a CURLE_PEER_FAILED_VERIFICATION error but the
                        connection will be left intact etc */
  CURLKHSTAT_FINE_REPLACE, /* accept and replace the wrong key */
  CURLKHSTAT_LAST    /* not for use, only a marker for last-in-list */
};

/* this is the set of status codes pass in to the callback */
enum curl_khmatch {
  CURLKHMATCH_OK,       /* match */
  CURLKHMATCH_MISMATCH, /* host found, key mismatch! */
  CURLKHMATCH_MISSING,  /* no matching host/key found */
  CURLKHMATCH_LAST      /* not for use, only a marker for last-in-list */
};

typedef int
  (*curl_sshkeycallback) (CURL *easy,     /* easy handle */
                          const struct curl_khkey *knownkey, /* known */
                          const struct curl_khkey *foundkey, /* found */
                          enum curl_khmatch, /* libcurl's view on the keys */
                          void *clientp); /* custom pointer passed with */
                                          /* CURLOPT_SSH_KEYDATA */

/* Mime/form handling support. */
typedef struct curl_mime      curl_mime;      /* Mime context. */
typedef struct curl_mimepart  curl_mimepart;  /* Mime part context. */

struct curl_ssl_backend {
  curl_sslbackend id;
  const char *name;
};
typedef struct curl_ssl_backend curl_ssl_backend;

/* long may be 32 or 64 bits, but we should never depend on anything else
   but 32 */
#define CURLOPTTYPE_LONG          0
#define CURLOPTTYPE_OBJECTPOINT   10000
#define CURLOPTTYPE_FUNCTIONPOINT 20000
#define CURLOPTTYPE_OFF_T         30000
#define CURLOPTTYPE_BLOB          40000

/* *STRINGPOINT is an alias for OBJECTPOINT to allow tools to extract the
   string options from the header file */

#define CURLOPT(na, t, nu) na = ((t) + (nu))
#define CURLOPTDEPRECATED(na, t, nu, v, m) na CURL_DEPRECATED(v, m) \
  = ((t) + (nu))

/* CURLOPT aliases that make no runtime difference */

/* 'char *' argument to a string with a trailing zero */
#define CURLOPTTYPE_STRINGPOINT CURLOPTTYPE_OBJECTPOINT

/* 'struct curl_slist *' argument */
#define CURLOPTTYPE_SLISTPOINT  CURLOPTTYPE_OBJECTPOINT

/* 'void *' argument passed untouched to callback */
#define CURLOPTTYPE_CBPOINT     CURLOPTTYPE_OBJECTPOINT

/* 'long' argument with a set of values/bitmask */
#define CURLOPTTYPE_VALUES      CURLOPTTYPE_LONG
"#;

/// Names `CURL_H_FORWARD` and `CURL_H_VERBATIM` declare which
/// `cbindgen.toml`'s `[export] exclude` does NOT already cover.
///
/// Measured, not guessed: every tag-form struct across all eight public
/// headers is already excluded, and exactly these five tag-form enums are
/// not. Without suppressing them here each would be declared twice -- once
/// verbatim in tag form and once generated as a typedef of an anonymous tag
/// -- which is a hard C error, not a warning.
///
/// Three callback typedefs join them, each for a different reason, and every
/// one was found by COMPILING the emitted C rather than by reading cbindgen's
/// documentation -- the Rust built, every count matched and the column guard
/// passed in all three cases:
///
/// * `curl_sshkeycallback` -- TYPE. Its fourth parameter is
///   `enum curl_khmatch`, and cbindgen emits only anonymous
///   `typedef enum { .. } NAME;`, so it never declares a tag to name there.
/// * `curl_opensocket_callback` -- LAYOUT. cbindgen aligns continuation
///   arguments under the opening parenthesis (indent 49), putting
///   `struct curl_sockaddr *address);` at 81 columns. The authority puts the
///   return type on its own line; cbindgen has no setting for that.
/// * `curl_ssls_export_cb` -- ABI. The authority declares a function TYPE,
///   `typedef CURLcode curl_ssls_export_cb(..);`, whose use site reads
///   `curl_ssls_export_cb *export_fn`. Rust has no type for a bare C function
///   type, so generating it turned that into a pointer to a function pointer.
const CURL_H_VERBATIM_NAMES: &[&str] = &[
    "CURL_NETRC_OPTION",
    "CURL_TLSAUTH",
    "curl_khmatch",
    "curl_khstat",
    "curl_khtype",
    "curl_opensocket_callback",
    "curl_sshkeycallback",
    "curl_ssls_export_cb",
];

/// `curl.h`, after the generated declarations and before the `extern "C"`
/// close.
///
/// Prepended to `cbindgen.toml`'s `trailer`, which closes the block and then
/// includes the seven siblings and `typecheck-gcc.h`. Ordering inside this
/// constant follows curl.h's own line order, so relative order is faithful
/// even though the generated body now sits above all of it.
const CURL_H_VERBATIM: &str = r#"struct curl_httppost {
  struct curl_httppost *next;       /* next entry in the list */
  char *name;                       /* pointer to allocated name */
  long namelength;                  /* length of name length */
  char *contents;                   /* pointer to allocated data contents */
  long contentslength;              /* length of contents field, see also
                                       CURL_HTTPPOST_LARGE */
  char *buffer;                     /* pointer to allocated buffer contents */
  long bufferlength;                /* length of buffer field */
  char *contenttype;                /* Content-Type */
  struct curl_slist *contentheader; /* list of extra headers for this form */
  struct curl_httppost *more;       /* if one field name has more than one
                                       file, this link should link to following
                                       files */
  long flags;                       /* as defined below */

/* specified content is a filename */
#define CURL_HTTPPOST_FILENAME (1 << 0)
/* specified content is a filename */
#define CURL_HTTPPOST_READFILE (1 << 1)
/* name is only stored pointer do not free in formfree */
#define CURL_HTTPPOST_PTRNAME (1 << 2)
/* contents is only stored pointer do not free in formfree */
#define CURL_HTTPPOST_PTRCONTENTS (1 << 3)
/* upload file from buffer */
#define CURL_HTTPPOST_BUFFER (1 << 4)
/* upload file from pointer contents */
#define CURL_HTTPPOST_PTRBUFFER (1 << 5)
/* upload file contents by using the regular read callback to get the data and
   pass the given pointer as custom pointer */
#define CURL_HTTPPOST_CALLBACK (1 << 6)
/* use size in 'contentlen', added in 7.46.0 */
#define CURL_HTTPPOST_LARGE (1 << 7)

  char *showfilename;               /* The filename to show. If not set, the
                                       actual filename will be used (if this
                                       is a file part) */
  void *userp;                      /* custom pointer used for
                                       HTTPPOST_CALLBACK posts */
  curl_off_t contentlen;            /* alternative length of contents
                                       field. Used if CURL_HTTPPOST_LARGE is
                                       set. Added in 7.46.0 */
};

/* Information about a single file, used when doing FTP wildcard matching */
struct curl_fileinfo {
  char *filename;
  curlfiletype filetype;
  time_t time; /* always zero! */
  unsigned int perm;
  int uid;
  int gid;
  curl_off_t size;
  long int hardlinks;

  struct {
    /* If some of these fields is not NULL, it is a pointer to b_data. */
    char *time;
    char *perm;
    char *user;
    char *group;
    char *target; /* pointer to the target filename of a symlink */
  } strings;

  unsigned int flags;

  /* These are libcurl private struct fields. Previously used by libcurl, so
     they must never be interfered with. */
  char *b_data;
  size_t b_size;
  size_t b_used;
};

struct curl_sockaddr {
  int family;
  int socktype;
  int protocol;
  unsigned int addrlen; /* addrlen was a socklen_t type before 7.18.0 but it
                           turned really ugly and painful on the systems that
                           lack this type */
  struct sockaddr addr;
};

typedef curl_socket_t
(*curl_opensocket_callback)(void *clientp,
                            curlsocktype purpose,
                            struct curl_sockaddr *address);

/* This is the curl_ssls_export_cb callback prototype. It
 * is passed to curl_easy_ssls_export() to extract SSL sessions/tickets. */
typedef CURLcode curl_ssls_export_cb(CURL *handle,
                                     void *userptr,
                                     const char *session_key,
                                     const unsigned char *shmac,
                                     size_t shmac_len,
                                     const unsigned char *sdata,
                                     size_t sdata_len,
                                     curl_off_t valid_until,
                                     int ietf_tls_id,
                                     const char *alpn,
                                     size_t earlydata_max);

struct curl_khkey {
  const char *key; /* points to a null-terminated string encoded with base64
                      if len is zero, otherwise to the "raw" data */
  size_t len;
  enum curl_khtype keytype;
};

struct curl_hstsentry {
  char *name;
  size_t namelen;
  unsigned int includeSubDomains:1;
  char expire[18]; /* YYYYMMDD HH:MM:SS [null-terminated] */
};

struct curl_index {
  size_t index; /* the provided entry's "index" or count */
  size_t total; /* total number of entries to save */
};

enum CURL_NETRC_OPTION {
  /* we set a single member here, just to make sure we still provide the enum,
     but the values to use are defined above with L suffixes */
  CURL_NETRC_LAST = 3
};

enum CURL_TLSAUTH {
  /* we set a single member here, just to make sure we still provide the enum,
     but the values to use are defined above with L suffixes */
  CURL_TLSAUTH_LAST = 2
};

typedef enum {
  /********* the first one is unused ************/
  CURLFORM_NOTHING         CURL_DEPRECATED(7.56.0, ""),
  CURLFORM_COPYNAME        CURL_DEPRECATED(7.56.0, "Use curl_mime_name()"),
  CURLFORM_PTRNAME         CURL_DEPRECATED(7.56.0, "Use curl_mime_name()"),
  CURLFORM_NAMELENGTH      CURL_DEPRECATED(7.56.0, ""),
  CURLFORM_COPYCONTENTS    CURL_DEPRECATED(7.56.0, "Use curl_mime_data()"),
  CURLFORM_PTRCONTENTS     CURL_DEPRECATED(7.56.0, "Use curl_mime_data()"),
  CURLFORM_CONTENTSLENGTH  CURL_DEPRECATED(7.56.0, "Use curl_mime_data()"),
  CURLFORM_FILECONTENT     CURL_DEPRECATED(7.56.0, "Use curl_mime_data_cb()"),
  CURLFORM_ARRAY           CURL_DEPRECATED(7.56.0, ""),
  CURLFORM_OBSOLETE,
  CURLFORM_FILE            CURL_DEPRECATED(7.56.0, "Use curl_mime_filedata()"),

  CURLFORM_BUFFER          CURL_DEPRECATED(7.56.0, "Use curl_mime_filename()"),
  CURLFORM_BUFFERPTR       CURL_DEPRECATED(7.56.0, "Use curl_mime_data()"),
  CURLFORM_BUFFERLENGTH    CURL_DEPRECATED(7.56.0, "Use curl_mime_data()"),

  CURLFORM_CONTENTTYPE     CURL_DEPRECATED(7.56.0, "Use curl_mime_type()"),
  CURLFORM_CONTENTHEADER   CURL_DEPRECATED(7.56.0, "Use curl_mime_headers()"),
  CURLFORM_FILENAME        CURL_DEPRECATED(7.56.0, "Use curl_mime_filename()"),
  CURLFORM_END,
  CURLFORM_OBSOLETE2,

  CURLFORM_STREAM          CURL_DEPRECATED(7.56.0, "Use curl_mime_data_cb()"),
  CURLFORM_CONTENTLEN  /* added in 7.46.0, provide a curl_off_t length */
                           CURL_DEPRECATED(7.56.0, "Use curl_mime_data()"),

  CURLFORM_LASTENTRY /* the last unused */
} CURLformoption;

/* structure to be used as parameter for CURLFORM_ARRAY */
struct curl_forms {
  CURLformoption option;
  const char     *value;
};

/* use this for multipart formpost building */
/* Returns code for curl_formadd()
 *
 * Returns:
 * CURL_FORMADD_OK             on success
 * CURL_FORMADD_MEMORY         if the FormInfo allocation fails
 * CURL_FORMADD_OPTION_TWICE   if one option is given twice for one Form
 * CURL_FORMADD_NULL           if a null pointer was given for a char
 * CURL_FORMADD_MEMORY         if the allocation of a FormInfo struct failed
 * CURL_FORMADD_UNKNOWN_OPTION if an unknown option was used
 * CURL_FORMADD_INCOMPLETE     if the some FormInfo is not complete (or error)
 * CURL_FORMADD_MEMORY         if a curl_httppost struct cannot be allocated
 * CURL_FORMADD_MEMORY         if some allocation for string copying failed.
 * CURL_FORMADD_ILLEGAL_ARRAY  if an illegal option is used in an array
 *
 ***************************************************************************/
typedef enum {
  CURL_FORMADD_OK             CURL_DEPRECATED(7.56.0, ""), /* 1st, no error */

  CURL_FORMADD_MEMORY         CURL_DEPRECATED(7.56.0, ""),
  CURL_FORMADD_OPTION_TWICE   CURL_DEPRECATED(7.56.0, ""),
  CURL_FORMADD_NULL           CURL_DEPRECATED(7.56.0, ""),
  CURL_FORMADD_UNKNOWN_OPTION CURL_DEPRECATED(7.56.0, ""),
  CURL_FORMADD_INCOMPLETE     CURL_DEPRECATED(7.56.0, ""),
  CURL_FORMADD_ILLEGAL_ARRAY  CURL_DEPRECATED(7.56.0, ""),
  /* libcurl was built with form api disabled */
  CURL_FORMADD_DISABLED       CURL_DEPRECATED(7.56.0, ""),

  CURL_FORMADD_LAST /* last */
} CURLFORMcode;

/*
 * NAME curl_formadd()
 *
 * DESCRIPTION
 *
 * Pretty advanced function for building multi-part formposts. Each invoke
 * adds one part that together construct a full post. Then use
 * CURLOPT_HTTPPOST to send it off to libcurl.
 */
CURL_EXTERN CURLFORMcode CURL_DEPRECATED(7.56.0, "Use curl_mime_init()")
curl_formadd(struct curl_httppost **httppost,
             struct curl_httppost **last_post,
             ...);

/*
 * NAME curl_formget()
 *
 * DESCRIPTION
 *
 * Serialize a curl_httppost struct built with curl_formadd().
 * Accepts a void pointer as second argument which will be passed to
 * the curl_formget_callback function.
 * Returns 0 on success.
 */
CURL_EXTERN int CURL_DEPRECATED(7.56.0, "")
curl_formget(struct curl_httppost *form, void *arg,
             curl_formget_callback append);
/*
 * NAME curl_formfree()
 *
 * DESCRIPTION
 *
 * Free a multipart formpost previously built with curl_formadd().
 */
CURL_EXTERN void CURL_DEPRECATED(7.56.0, "Use curl_mime_free()")
curl_formfree(struct curl_httppost *form);

/* linked-list structure for the CURLOPT_QUOTE option (and other) */
struct curl_slist {
  char *data;
  struct curl_slist *next;
};

/* info about the certificate chain, for SSL backends that support it. Asked
   for with CURLOPT_CERTINFO / CURLINFO_CERTINFO */
struct curl_certinfo {
  int num_of_certs;             /* number of certificates with information */
  struct curl_slist **certinfo; /* for each index in this array, there is a
                                   linked list with textual information for a
                                   certificate in the format "name:content".
                                   eg "Subject:foo", "Issuer:bar", etc. */
};

/* Information about the SSL library used and the respective internal SSL
   handle, which can be used to obtain further information regarding the
   connection. Asked for with CURLINFO_TLS_SSL_PTR or CURLINFO_TLS_SESSION. */
struct curl_tlssessioninfo {
  curl_sslbackend backend;
  void *internals;
};

#define CURLINFO_STRING   0x100000
#define CURLINFO_LONG     0x200000
#define CURLINFO_DOUBLE   0x300000
#define CURLINFO_SLIST    0x400000
#define CURLINFO_PTR      0x400000 /* same as SLIST */
#define CURLINFO_SOCKET   0x500000
#define CURLINFO_OFF_T    0x600000
#define CURLINFO_MASK     0x0fffff
#define CURLINFO_TYPEMASK 0xf00000

typedef enum {
  CURLINFO_NONE, /* first, never use this */
  CURLINFO_EFFECTIVE_URL    = CURLINFO_STRING + 1,
  CURLINFO_RESPONSE_CODE    = CURLINFO_LONG   + 2,
  CURLINFO_TOTAL_TIME       = CURLINFO_DOUBLE + 3,
  CURLINFO_NAMELOOKUP_TIME  = CURLINFO_DOUBLE + 4,
  CURLINFO_CONNECT_TIME     = CURLINFO_DOUBLE + 5,
  CURLINFO_PRETRANSFER_TIME = CURLINFO_DOUBLE + 6,
  CURLINFO_SIZE_UPLOAD CURL_DEPRECATED(7.55.0, "Use CURLINFO_SIZE_UPLOAD_T")
                            = CURLINFO_DOUBLE + 7,
  CURLINFO_SIZE_UPLOAD_T    = CURLINFO_OFF_T  + 7,
  CURLINFO_SIZE_DOWNLOAD
                       CURL_DEPRECATED(7.55.0, "Use CURLINFO_SIZE_DOWNLOAD_T")
                            = CURLINFO_DOUBLE + 8,
  CURLINFO_SIZE_DOWNLOAD_T  = CURLINFO_OFF_T  + 8,
  CURLINFO_SPEED_DOWNLOAD
                       CURL_DEPRECATED(7.55.0, "Use CURLINFO_SPEED_DOWNLOAD_T")
                            = CURLINFO_DOUBLE + 9,
  CURLINFO_SPEED_DOWNLOAD_T = CURLINFO_OFF_T  + 9,
  CURLINFO_SPEED_UPLOAD
                       CURL_DEPRECATED(7.55.0, "Use CURLINFO_SPEED_UPLOAD_T")
                            = CURLINFO_DOUBLE + 10,
  CURLINFO_SPEED_UPLOAD_T   = CURLINFO_OFF_T  + 10,
  CURLINFO_HEADER_SIZE      = CURLINFO_LONG   + 11,
  CURLINFO_REQUEST_SIZE     = CURLINFO_LONG   + 12,
  CURLINFO_SSL_VERIFYRESULT = CURLINFO_LONG   + 13,
  CURLINFO_FILETIME         = CURLINFO_LONG   + 14,
  CURLINFO_FILETIME_T       = CURLINFO_OFF_T  + 14,
  CURLINFO_CONTENT_LENGTH_DOWNLOAD
                       CURL_DEPRECATED(7.55.0,
                                      "Use CURLINFO_CONTENT_LENGTH_DOWNLOAD_T")
                            = CURLINFO_DOUBLE + 15,
  CURLINFO_CONTENT_LENGTH_DOWNLOAD_T = CURLINFO_OFF_T  + 15,
  CURLINFO_CONTENT_LENGTH_UPLOAD
                       CURL_DEPRECATED(7.55.0,
                                       "Use CURLINFO_CONTENT_LENGTH_UPLOAD_T")
                            = CURLINFO_DOUBLE + 16,
  CURLINFO_CONTENT_LENGTH_UPLOAD_T   = CURLINFO_OFF_T  + 16,
  CURLINFO_STARTTRANSFER_TIME = CURLINFO_DOUBLE + 17,
  CURLINFO_CONTENT_TYPE     = CURLINFO_STRING + 18,
  CURLINFO_REDIRECT_TIME    = CURLINFO_DOUBLE + 19,
  CURLINFO_REDIRECT_COUNT   = CURLINFO_LONG   + 20,
  CURLINFO_PRIVATE          = CURLINFO_STRING + 21,
  CURLINFO_HTTP_CONNECTCODE = CURLINFO_LONG   + 22,
  CURLINFO_HTTPAUTH_AVAIL   = CURLINFO_LONG   + 23,
  CURLINFO_PROXYAUTH_AVAIL  = CURLINFO_LONG   + 24,
  CURLINFO_OS_ERRNO         = CURLINFO_LONG   + 25,
  CURLINFO_NUM_CONNECTS     = CURLINFO_LONG   + 26,
  CURLINFO_SSL_ENGINES      = CURLINFO_SLIST  + 27,
  CURLINFO_COOKIELIST       = CURLINFO_SLIST  + 28,
  CURLINFO_LASTSOCKET  CURL_DEPRECATED(7.45.0, "Use CURLINFO_ACTIVESOCKET")
                            = CURLINFO_LONG   + 29,
  CURLINFO_FTP_ENTRY_PATH   = CURLINFO_STRING + 30,
  CURLINFO_REDIRECT_URL     = CURLINFO_STRING + 31,
  CURLINFO_PRIMARY_IP       = CURLINFO_STRING + 32,
  CURLINFO_APPCONNECT_TIME  = CURLINFO_DOUBLE + 33,
  CURLINFO_CERTINFO         = CURLINFO_PTR    + 34,
  CURLINFO_CONDITION_UNMET  = CURLINFO_LONG   + 35,
  CURLINFO_RTSP_SESSION_ID  = CURLINFO_STRING + 36,
  CURLINFO_RTSP_CLIENT_CSEQ = CURLINFO_LONG   + 37,
  CURLINFO_RTSP_SERVER_CSEQ = CURLINFO_LONG   + 38,
  CURLINFO_RTSP_CSEQ_RECV   = CURLINFO_LONG   + 39,
  CURLINFO_PRIMARY_PORT     = CURLINFO_LONG   + 40,
  CURLINFO_LOCAL_IP         = CURLINFO_STRING + 41,
  CURLINFO_LOCAL_PORT       = CURLINFO_LONG   + 42,
  CURLINFO_TLS_SESSION CURL_DEPRECATED(7.48.0, "Use CURLINFO_TLS_SSL_PTR")
                            = CURLINFO_PTR    + 43,
  CURLINFO_ACTIVESOCKET     = CURLINFO_SOCKET + 44,
  CURLINFO_TLS_SSL_PTR      = CURLINFO_PTR    + 45,
  CURLINFO_HTTP_VERSION     = CURLINFO_LONG   + 46,
  CURLINFO_PROXY_SSL_VERIFYRESULT = CURLINFO_LONG + 47,
  CURLINFO_PROTOCOL    CURL_DEPRECATED(7.85.0, "Use CURLINFO_SCHEME")
                            = CURLINFO_LONG   + 48,
  CURLINFO_SCHEME           = CURLINFO_STRING + 49,
  CURLINFO_TOTAL_TIME_T     = CURLINFO_OFF_T + 50,
  CURLINFO_NAMELOOKUP_TIME_T = CURLINFO_OFF_T + 51,
  CURLINFO_CONNECT_TIME_T   = CURLINFO_OFF_T + 52,
  CURLINFO_PRETRANSFER_TIME_T = CURLINFO_OFF_T + 53,
  CURLINFO_STARTTRANSFER_TIME_T = CURLINFO_OFF_T + 54,
  CURLINFO_REDIRECT_TIME_T  = CURLINFO_OFF_T + 55,
  CURLINFO_APPCONNECT_TIME_T = CURLINFO_OFF_T + 56,
  CURLINFO_RETRY_AFTER      = CURLINFO_OFF_T + 57,
  CURLINFO_EFFECTIVE_METHOD = CURLINFO_STRING + 58,
  CURLINFO_PROXY_ERROR      = CURLINFO_LONG + 59,
  CURLINFO_REFERER          = CURLINFO_STRING + 60,
  CURLINFO_CAINFO           = CURLINFO_STRING + 61,
  CURLINFO_CAPATH           = CURLINFO_STRING + 62,
  CURLINFO_XFER_ID          = CURLINFO_OFF_T + 63,
  CURLINFO_CONN_ID          = CURLINFO_OFF_T + 64,
  CURLINFO_QUEUE_TIME_T     = CURLINFO_OFF_T + 65,
  CURLINFO_USED_PROXY       = CURLINFO_LONG + 66,
  CURLINFO_POSTTRANSFER_TIME_T = CURLINFO_OFF_T + 67,
  CURLINFO_EARLYDATA_SENT_T = CURLINFO_OFF_T + 68,
  CURLINFO_HTTPAUTH_USED    = CURLINFO_LONG + 69,
  CURLINFO_PROXYAUTH_USED   = CURLINFO_LONG + 70,
  CURLINFO_LASTONE          = 70
} CURLINFO;

CURL_EXTERN CURLSHcode curl_share_setopt(CURLSH *share, CURLSHoption option,
                                         ...);

struct curl_version_info_data {
  CURLversion age;          /* age of the returned struct */
  const char *version;      /* LIBCURL_VERSION */
  unsigned int version_num; /* LIBCURL_VERSION_NUM */
  const char *host;         /* OS/host/cpu/machine when configured */
  int features;             /* bitmask, see defines below */
  const char *ssl_version;  /* human readable string */
  long ssl_version_num;     /* not used anymore, always 0 */
  const char *libz_version; /* human readable string */
  /* protocols is terminated by an entry with a NULL protoname */
  const char * const *protocols;

  /* The fields below this were added in CURLVERSION_SECOND */
  const char *ares;
  int ares_num;

  /* This field was added in CURLVERSION_THIRD */
  const char *libidn;

  /* These field were added in CURLVERSION_FOURTH */

  /* Same as '_libiconv_version' if built with HAVE_ICONV */
  int iconv_ver_num;

  const char *libssh_version; /* human readable string */

  /* These fields were added in CURLVERSION_FIFTH */
  unsigned int brotli_ver_num; /* Numeric Brotli version
                                  (MAJOR << 24) | (MINOR << 12) | PATCH */
  const char *brotli_version; /* human readable string. */

  /* These fields were added in CURLVERSION_SIXTH */
  unsigned int nghttp2_ver_num; /* Numeric nghttp2 version
                                   (MAJOR << 16) | (MINOR << 8) | PATCH */
  const char *nghttp2_version; /* human readable string. */
  const char *quic_version;    /* human readable quic (+ HTTP/3) library +
                                  version or NULL */

  /* These fields were added in CURLVERSION_SEVENTH */
  const char *cainfo;          /* the built-in default CURLOPT_CAINFO, might
                                  be NULL */
  const char *capath;          /* the built-in default CURLOPT_CAPATH, might
                                  be NULL */

  /* These fields were added in CURLVERSION_EIGHTH */
  unsigned int zstd_ver_num; /* Numeric Zstd version
                                  (MAJOR << 24) | (MINOR << 12) | PATCH */
  const char *zstd_version; /* human readable string. */

  /* These fields were added in CURLVERSION_NINTH */
  const char *hyper_version; /* human readable string. */

  /* These fields were added in CURLVERSION_TENTH */
  const char *gsasl_version; /* human readable string. */

  /* These fields were added in CURLVERSION_ELEVENTH */
  /* feature_names is terminated by an entry with a NULL feature name */
  const char * const *feature_names;

  /* These fields were added in CURLVERSION_TWELFTH */
  const char *rtmp_version; /* human readable string. */
};

/* The seven prototypes below are carried verbatim, not generated. Every one
   names a type in its signature that cbindgen cannot be asked to produce from
   this crate's Rust spelling -- an enum where the Rust parameter must be a
   plain integer, or `time_t` where the engine's type is `i64`. The measured
   reasons are recorded in cbindgen.toml under "Group 5e". Placement is after
   `curl_version_info_data` above and after the generated enums and memory
   callbacks, so every type each one references is already declared. */

/* NAME curl_global_init -- curl.h:2748 */
CURL_EXTERN CURLcode curl_global_init(long flags);

/* NAME curl_global_init_mem -- curl.h:2763-2768 */
CURL_EXTERN CURLcode curl_global_init_mem(long flags,
                                          curl_malloc_callback m,
                                          curl_free_callback f,
                                          curl_realloc_callback r,
                                          curl_strdup_callback s,
                                          curl_calloc_callback c);

/* NAME curl_global_sslset -- curl.h:2838-2839 */
CURL_EXTERN CURLsslset curl_global_sslset(curl_sslbackend id, const char *name,
                                          const curl_ssl_backend ***avail);

/* NAME curl_getdate -- curl.h:2870 */
CURL_EXTERN time_t curl_getdate(const char *p, const time_t *unused);

/* NAME curl_version_info -- curl.h:3221 */
CURL_EXTERN curl_version_info_data *curl_version_info(CURLversion);

/* NAME curl_easy_strerror -- curl.h:3232 */
CURL_EXTERN const char *curl_easy_strerror(CURLcode);

/* NAME curl_share_strerror -- curl.h:3243 */
CURL_EXTERN const char *curl_share_strerror(CURLSHcode);
"#;

/// `curl.h`'s object-like and function-like constant macros, carried verbatim.
///
/// These 258 `#define` directives are reproduced from the frozen
/// `include/curl/curl.h` byte-for-byte, in the authority's own order and
/// formatting, rather than generated from Rust constants. cbindgen provably
/// cannot carry them faithfully, and every one of the following forms appears
/// in the set:
///
/// * A C cast inside the macro body -- `CURLAUTH_BASIC` is
///   `(((unsigned long)1) << 0)` and `CURL_ZERO_TERMINATED` is `((size_t)-1)`.
///   cbindgen emits a typed Rust constant, not a cast expression.
/// * A backslash line continuation -- `CURLAUTH_ANY`, `CURLAUTH_ANYSAFE` and
///   `CURL_REDIR_POST_ALL` span two physical lines.
/// * Arithmetic -- `CURL_MAX_READ_SIZE` is `(10*1024*1024)`.
/// * A reference to another macro or to a generated enumerator --
///   `CURL_GLOBAL_ALL` is `(CURL_GLOBAL_SSL | CURL_GLOBAL_WIN32)` and
///   `CURL_SSLVERSION_MAX_TLSv1_2` is `(CURL_SSLVERSION_TLSv1_2 << 16)`.
/// * An `L` integer suffix -- 81 of the 258 carry one. cbindgen DROPS it,
///   which changes the varargs type of a `long` option on LP64 and is
///   therefore an ABI break, not a cosmetic difference.
/// * A macro with no replacement list at all --
///   `CURL_DID_MEMORY_FUNC_TYPEDEFS` is a bare `#define` used as a guard.
///
/// The six local `#ifndef` guards the authority wraps around some of these are
/// preserved: three let a consumer override a buffer-size ceiling before
/// including the header, one guards a typedef block, and two are
/// `CURL_NO_OLDIES` blocks. The file-level `#ifndef CURLINC_CURL_H` include
/// guard is deliberately NOT reproduced -- cbindgen emits it, and a second
/// copy would be skipped because the macro is already defined by this point,
/// which would silently drop every constant below it.
const CURL_H_CONSTS: &str = r#"/* aliases for library clones and renames */
#define CURLSSLBACKEND_AWSLC CURLSSLBACKEND_OPENSSL
#define CURLSSLBACKEND_BORINGSSL CURLSSLBACKEND_OPENSSL
#define CURLSSLBACKEND_LIBRESSL CURLSSLBACKEND_OPENSSL

/* deprecated names: */
#define CURLSSLBACKEND_CYASSL CURLSSLBACKEND_WOLFSSL
#define CURLSSLBACKEND_DARWINSSL CURLSSLBACKEND_SECURETRANSPORT

/* bits for the CURLOPT_FOLLOWLOCATION option */
#define CURLFOLLOW_ALL       1L /* generic follow redirects */

/* Do not use the custom method in the follow-up request if the HTTP code
   instructs so (301, 302, 303). */
#define CURLFOLLOW_OBEYCODE  2L

/* Only use the custom method in the first request, always reset in the next */
#define CURLFOLLOW_FIRSTONLY 3L

/* This is a return code for the progress callback that, when returned, will
   signal libcurl to continue executing the default progress function */
#define CURL_PROGRESSFUNC_CONTINUE 0x10000001

#ifndef CURL_MAX_READ_SIZE
  /* The maximum receive buffer size configurable via CURLOPT_BUFFERSIZE. */
#define CURL_MAX_READ_SIZE (10*1024*1024)
#endif

#ifndef CURL_MAX_WRITE_SIZE
  /* Tests have proven that 20K is a bad buffer size for uploads on Windows,
     while 16K for some odd reason performed a lot better. We do the ifndef
     check to allow this value to easier be changed at build time for those
     who feel adventurous. The practical minimum is about 400 bytes since
     libcurl uses a buffer of this size as a scratch area (unrelated to
     network send operations). */
#define CURL_MAX_WRITE_SIZE 16384
#endif

#ifndef CURL_MAX_HTTP_HEADER
/* The only reason to have a max limit for this is to avoid the risk of a bad
   server feeding libcurl with a never-ending header that will cause reallocs
   infinitely */
#define CURL_MAX_HTTP_HEADER (100*1024)
#endif

/* This is a magic return code for the write callback that, when returned,
   will signal libcurl to pause receiving on the current transfer. */
#define CURL_WRITEFUNC_PAUSE 0x10000001

/* This is a magic return code for the write callback that, when returned,
   will signal an error from the callback. */
#define CURL_WRITEFUNC_ERROR 0xFFFFFFFF

#define CURLFINFOFLAG_KNOWN_FILENAME    (1 << 0)
#define CURLFINFOFLAG_KNOWN_FILETYPE    (1 << 1)
#define CURLFINFOFLAG_KNOWN_TIME        (1 << 2)
#define CURLFINFOFLAG_KNOWN_PERM        (1 << 3)
#define CURLFINFOFLAG_KNOWN_UID         (1 << 4)
#define CURLFINFOFLAG_KNOWN_GID         (1 << 5)
#define CURLFINFOFLAG_KNOWN_SIZE        (1 << 6)
#define CURLFINFOFLAG_KNOWN_HLINKCOUNT  (1 << 7)

/* return codes for CURLOPT_CHUNK_BGN_FUNCTION */
#define CURL_CHUNK_BGN_FUNC_OK      0
#define CURL_CHUNK_BGN_FUNC_FAIL    1 /* tell the lib to end the task */
#define CURL_CHUNK_BGN_FUNC_SKIP    2 /* skip this chunk over */

/* return codes for CURLOPT_CHUNK_END_FUNCTION */
#define CURL_CHUNK_END_FUNC_OK      0
#define CURL_CHUNK_END_FUNC_FAIL    1 /* tell the lib to end the task */

/* return codes for FNMATCHFUNCTION */
#define CURL_FNMATCHFUNC_MATCH    0 /* string corresponds to the pattern */
#define CURL_FNMATCHFUNC_NOMATCH  1 /* pattern does not match the string */
#define CURL_FNMATCHFUNC_FAIL     2 /* an error occurred */

/* These are the return codes for the seek callbacks */
#define CURL_SEEKFUNC_OK       0
#define CURL_SEEKFUNC_FAIL     1 /* fail the entire transfer */
#define CURL_SEEKFUNC_CANTSEEK 2 /* tell libcurl seeking cannot be done, so
                                    libcurl might try other means instead */

/* This is a return code for the read callback that, when returned, will
   signal libcurl to immediately abort the current transfer. */
#define CURL_READFUNC_ABORT 0x10000000
/* This is a return code for the read callback that, when returned, will
   signal libcurl to pause sending data on the current transfer. */
#define CURL_READFUNC_PAUSE 0x10000001

/* Return code for when the trailing headers' callback has terminated
   without any errors */
#define CURL_TRAILERFUNC_OK 0
/* Return code for when was an error in the trailing header's list and we
  want to abort the request */
#define CURL_TRAILERFUNC_ABORT 1

/* The return code from the sockopt_callback can signal information back
   to libcurl: */
#define CURL_SOCKOPT_OK 0
#define CURL_SOCKOPT_ERROR 1 /* causes libcurl to abort and return
                                CURLE_ABORTED_BY_CALLBACK */
#define CURL_SOCKOPT_ALREADY_CONNECTED 2

#ifndef CURL_DID_MEMORY_FUNC_TYPEDEFS

#define CURL_DID_MEMORY_FUNC_TYPEDEFS
#endif

/* Return code for when the pre-request callback has terminated without
   any errors */
#define CURL_PREREQFUNC_OK 0
/* Return code for when the pre-request callback wants to abort the
   request */
#define CURL_PREREQFUNC_ABORT 1

#define CURLPROXY_HTTP            0L /* added in 7.10, new in 7.19.4 default is
                                        to use CONNECT HTTP/1.1 */
#define CURLPROXY_HTTP_1_0        1L /* force to use CONNECT HTTP/1.0
                                        added in 7.19.4 */
#define CURLPROXY_HTTPS           2L /* HTTPS but stick to HTTP/1
                                        added in 7.52.0 */
#define CURLPROXY_HTTPS2          3L /* HTTPS and attempt HTTP/2
                                        added in 8.2.0 */
#define CURLPROXY_SOCKS4          4L /* support added in 7.15.2, enum existed
                                        already in 7.10 */
#define CURLPROXY_SOCKS5          5L /* added in 7.10 */
#define CURLPROXY_SOCKS4A         6L /* added in 7.18.0 */
#define CURLPROXY_SOCKS5_HOSTNAME 7L /* Use the SOCKS5 protocol but pass along
                                        the hostname rather than the IP
                                        address. added in 7.18.0 */

#define CURLAUTH_NONE         ((unsigned long)0)
#define CURLAUTH_BASIC        (((unsigned long)1) << 0)
#define CURLAUTH_DIGEST       (((unsigned long)1) << 1)
#define CURLAUTH_NEGOTIATE    (((unsigned long)1) << 2)
/* Deprecated since the advent of CURLAUTH_NEGOTIATE */
#define CURLAUTH_GSSNEGOTIATE CURLAUTH_NEGOTIATE
/* Used for CURLOPT_SOCKS5_AUTH to stay terminologically correct */
#define CURLAUTH_GSSAPI CURLAUTH_NEGOTIATE
#define CURLAUTH_NTLM         (((unsigned long)1) << 3)
#define CURLAUTH_DIGEST_IE    (((unsigned long)1) << 4)
#ifndef CURL_NO_OLDIES
  /* functionality removed since 8.8.0 */
#define CURLAUTH_NTLM_WB      (((unsigned long)1) << 5)
#endif
#define CURLAUTH_BEARER       (((unsigned long)1) << 6)
#define CURLAUTH_AWS_SIGV4    (((unsigned long)1) << 7)
#define CURLAUTH_ONLY         (((unsigned long)1) << 31)
#define CURLAUTH_ANY          ((~CURLAUTH_DIGEST_IE) & \
                               ((unsigned long)0xffffffff))
#define CURLAUTH_ANYSAFE      ((~(CURLAUTH_BASIC | CURLAUTH_DIGEST_IE)) & \
                               ((unsigned long)0xffffffff))

/* all types supported by server */
#define CURLSSH_AUTH_ANY       ((unsigned long)0xffffffff)
#define CURLSSH_AUTH_NONE      0L        /* none allowed, silly but complete */
#define CURLSSH_AUTH_PUBLICKEY (1L << 0) /* public/private key files */
#define CURLSSH_AUTH_PASSWORD  (1L << 1) /* password */
#define CURLSSH_AUTH_HOST      (1L << 2) /* host key files */
#define CURLSSH_AUTH_KEYBOARD  (1L << 3) /* keyboard interactive */
#define CURLSSH_AUTH_AGENT     (1L << 4) /* agent (ssh-agent, pageant...) */
#define CURLSSH_AUTH_GSSAPI    (1L << 5) /* gssapi (kerberos, ...) */
#define CURLSSH_AUTH_DEFAULT   CURLSSH_AUTH_ANY

#define CURLGSSAPI_DELEGATION_NONE        0L      /* no delegation (default) */
#define CURLGSSAPI_DELEGATION_POLICY_FLAG (1L<<0) /* if permitted by policy */
#define CURLGSSAPI_DELEGATION_FLAG        (1L<<1) /* delegate always */

#define CURL_ERROR_SIZE 256

/* parameter for the CURLOPT_USE_SSL option */
#define CURLUSESSL_NONE    0L /* do not attempt to use SSL */
#define CURLUSESSL_TRY     1L /* try using SSL, proceed anyway otherwise */
#define CURLUSESSL_CONTROL 2L /* SSL for the control connection or fail */
#define CURLUSESSL_ALL     3L /* SSL for all communication or fail */

/* - ALLOW_BEAST tells libcurl to allow the BEAST SSL vulnerability in the
   name of improving interoperability with older servers. Some SSL libraries
   have introduced work-arounds for this flaw but those work-arounds sometimes
   make the SSL communication fail. To regain functionality with those broken
   servers, a user can this way allow the vulnerability back. */
#define CURLSSLOPT_ALLOW_BEAST (1L << 0)

/* - NO_REVOKE tells libcurl to disable certificate revocation checks for those
   SSL backends where such behavior is present. */
#define CURLSSLOPT_NO_REVOKE (1L << 1)

/* - NO_PARTIALCHAIN tells libcurl to *NOT* accept a partial certificate chain
   if possible. The OpenSSL backend has this ability. */
#define CURLSSLOPT_NO_PARTIALCHAIN (1L << 2)

/* - REVOKE_BEST_EFFORT tells libcurl to ignore certificate revocation offline
   checks and ignore missing revocation list for those SSL backends where such
   behavior is present. */
#define CURLSSLOPT_REVOKE_BEST_EFFORT (1L << 3)

/* - CURLSSLOPT_NATIVE_CA tells libcurl to use standard certificate store of
   operating system. Currently implemented under MS-Windows. */
#define CURLSSLOPT_NATIVE_CA (1L << 4)

/* - CURLSSLOPT_AUTO_CLIENT_CERT tells libcurl to automatically locate and use
   a client certificate for authentication. (Schannel) */
#define CURLSSLOPT_AUTO_CLIENT_CERT (1L << 5)

/* If possible, send data using TLS 1.3 early data */
#define CURLSSLOPT_EARLYDATA (1L << 6)

/* The default connection attempt delay in milliseconds for happy eyeballs.
   CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS.3 and happy-eyeballs-timeout-ms.d document
   this value, keep them in sync. */
#define CURL_HET_DEFAULT 200L

/* The default connection upkeep interval in milliseconds. */
#define CURL_UPKEEP_INTERVAL_DEFAULT 60000L

#ifndef CURL_NO_OLDIES /* define this to test if your app builds with all
                          the obsolete stuff removed! */

#define CURLFTPSSL_NONE CURLUSESSL_NONE
#define CURLFTPSSL_TRY CURLUSESSL_TRY
#define CURLFTPSSL_CONTROL CURLUSESSL_CONTROL
#define CURLFTPSSL_ALL CURLUSESSL_ALL
#define CURLFTPSSL_LAST CURLUSESSL_LAST
#define curl_ftpssl curl_usessl
#endif /* !CURL_NO_OLDIES */

/* parameter for the CURLOPT_FTP_SSL_CCC option */
#define CURLFTPSSL_CCC_NONE    0L /* do not send CCC */
#define CURLFTPSSL_CCC_PASSIVE 1L /* Let the server initiate the shutdown */
#define CURLFTPSSL_CCC_ACTIVE  2L /* Initiate the shutdown */

/* parameter for the CURLOPT_FTPSSLAUTH option */
#define CURLFTPAUTH_DEFAULT 0L /* let libcurl decide */
#define CURLFTPAUTH_SSL     1L /* use "AUTH SSL" */
#define CURLFTPAUTH_TLS     2L /* use "AUTH TLS" */

/* parameter for the CURLOPT_FTP_CREATE_MISSING_DIRS option */
#define CURLFTP_CREATE_DIR_NONE  0L /* do NOT create missing dirs! */
#define CURLFTP_CREATE_DIR       1L /* (FTP/SFTP) if CWD fails, try MKD and
                                       then CWD again if MKD succeeded, for
                                       SFTP this does similar magic */
#define CURLFTP_CREATE_DIR_RETRY 2L /* (FTP only) if CWD fails, try MKD and
                                       then CWD again even if MKD failed! */

/* parameter for the CURLOPT_FTP_FILEMETHOD option */
#define CURLFTPMETHOD_DEFAULT   0L /* let libcurl pick */
#define CURLFTPMETHOD_MULTICWD  1L /* single CWD operation for each path
                                      part */
#define CURLFTPMETHOD_NOCWD     2L /* no CWD at all */
#define CURLFTPMETHOD_SINGLECWD 3L /* one CWD to full dir, then work on file */

/* bitmask defines for CURLOPT_HEADEROPT */
#define CURLHEADER_UNIFIED  0L
#define CURLHEADER_SEPARATE (1L << 0)

/* CURLALTSVC_* are bits for the CURLOPT_ALTSVC_CTRL option */
#define CURLALTSVC_READONLYFILE (1L << 2)
#define CURLALTSVC_H1           (1L << 3)
#define CURLALTSVC_H2           (1L << 4)
#define CURLALTSVC_H3           (1L << 5)

/* bitmask values for CURLOPT_UPLOAD_FLAGS */
#define CURLULFLAG_ANSWERED (1L << 0)
#define CURLULFLAG_DELETED  (1L << 1)
#define CURLULFLAG_DRAFT    (1L << 2)
#define CURLULFLAG_FLAGGED  (1L << 3)
#define CURLULFLAG_SEEN     (1L << 4)

/* CURLHSTS_* are bits for the CURLOPT_HSTS option */
#define CURLHSTS_ENABLE       (1L << 0)
#define CURLHSTS_READONLYFILE (1L << 1)

/* The CURLPROTO_ defines below are for the **deprecated** CURLOPT_*PROTOCOLS
   options. Do not use. */
#define CURLPROTO_HTTP    (1L << 0)
#define CURLPROTO_HTTPS   (1L << 1)
#define CURLPROTO_FTP     (1L << 2)
#define CURLPROTO_FTPS    (1L << 3)
#define CURLPROTO_SCP     (1L << 4)
#define CURLPROTO_SFTP    (1L << 5)
#define CURLPROTO_TELNET  (1L << 6)
#define CURLPROTO_LDAP    (1L << 7)
#define CURLPROTO_LDAPS   (1L << 8)
#define CURLPROTO_DICT    (1L << 9)
#define CURLPROTO_FILE    (1L << 10)
#define CURLPROTO_TFTP    (1L << 11)
#define CURLPROTO_IMAP    (1L << 12)
#define CURLPROTO_IMAPS   (1L << 13)
#define CURLPROTO_POP3    (1L << 14)
#define CURLPROTO_POP3S   (1L << 15)
#define CURLPROTO_SMTP    (1L << 16)
#define CURLPROTO_SMTPS   (1L << 17)
#define CURLPROTO_RTSP    (1L << 18)
#define CURLPROTO_RTMP    (1L << 19)
#define CURLPROTO_RTMPT   (1L << 20)
#define CURLPROTO_RTMPE   (1L << 21)
#define CURLPROTO_RTMPTE  (1L << 22)
#define CURLPROTO_RTMPS   (1L << 23)
#define CURLPROTO_RTMPTS  (1L << 24)
#define CURLPROTO_GOPHER  (1L << 25)
#define CURLPROTO_SMB     (1L << 26)
#define CURLPROTO_SMBS    (1L << 27)
#define CURLPROTO_MQTT    (1L << 28)
#define CURLPROTO_GOPHERS (1L << 29)
#define CURLPROTO_MQTTS   (1L << 30)
#define CURLPROTO_ALL     ((unsigned long)0xffffffff) /* enable everything */

/* Below here follows defines for the CURLOPT_IPRESOLVE option. If a host
   name resolves addresses using more than one IP protocol version, this
   option might be handy to force libcurl to use a specific IP version. */
#define CURL_IPRESOLVE_WHATEVER 0L /* default, uses addresses to all IP
                                     versions that your system allows */
#define CURL_IPRESOLVE_V4       1L /* uses only IPv4 addresses/connections */
#define CURL_IPRESOLVE_V6       2L /* uses only IPv6 addresses/connections */

/* These constants are for use with the CURLOPT_HTTP_VERSION option. */
#define CURL_HTTP_VERSION_NONE  0L /* setting this means we do not care, and
                                      that we would like the library to choose
                                      the best possible for us! */
#define CURL_HTTP_VERSION_1_0   1L /* please use HTTP 1.0 in the request */
#define CURL_HTTP_VERSION_1_1   2L /* please use HTTP 1.1 in the request */
#define CURL_HTTP_VERSION_2_0   3L /* please use HTTP 2 in the request */
#define CURL_HTTP_VERSION_2TLS  4L /* use version 2 for HTTPS, version 1.1 for
                                      HTTP */
#define CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE 5L /* please use HTTP 2 without
                                                  HTTP/1.1 Upgrade */
#define CURL_HTTP_VERSION_3     30L /* Use HTTP/3, fallback to HTTP/2 or
                                       HTTP/1 if needed. For HTTPS only. For
                                       HTTP, this option makes libcurl
                                       return error. */
#define CURL_HTTP_VERSION_3ONLY 31L /* Use HTTP/3 without fallback. For
                                       HTTPS only. For HTTP, this makes
                                       libcurl return error. */
#define CURL_HTTP_VERSION_LAST  32L /* *ILLEGAL* http version */

/* Convenience definition simple because the name of the version is HTTP/2 and
   not 2.0. The 2_0 version of the enum name was set while the version was
   still planned to be 2.0 and we stick to it for compatibility. */
#define CURL_HTTP_VERSION_2 CURL_HTTP_VERSION_2_0

#define CURL_RTSPREQ_NONE          0L
#define CURL_RTSPREQ_OPTIONS       1L
#define CURL_RTSPREQ_DESCRIBE      2L
#define CURL_RTSPREQ_ANNOUNCE      3L
#define CURL_RTSPREQ_SETUP         4L
#define CURL_RTSPREQ_PLAY          5L
#define CURL_RTSPREQ_PAUSE         6L
#define CURL_RTSPREQ_TEARDOWN      7L
#define CURL_RTSPREQ_GET_PARAMETER 8L
#define CURL_RTSPREQ_SET_PARAMETER 9L
#define CURL_RTSPREQ_RECORD        10L
#define CURL_RTSPREQ_RECEIVE       11L
#define CURL_RTSPREQ_LAST          12L /* not used */

  /* These enums are for use with the CURLOPT_NETRC option. */
#define CURL_NETRC_IGNORED  0L /* The .netrc will never be read.
                                  This is the default. */
#define CURL_NETRC_OPTIONAL 1L /* A user:password in the URL will be preferred
                                  to one in the .netrc. */
#define CURL_NETRC_REQUIRED 2L /* A user:password in the URL will be ignored.
                                  Unless one is set programmatically, the
                                  .netrc will be queried. */

#define CURL_SSLVERSION_DEFAULT 0L
#define CURL_SSLVERSION_TLSv1   1L /* TLS 1.x */
#define CURL_SSLVERSION_SSLv2   2L
#define CURL_SSLVERSION_SSLv3   3L
#define CURL_SSLVERSION_TLSv1_0 4L
#define CURL_SSLVERSION_TLSv1_1 5L
#define CURL_SSLVERSION_TLSv1_2 6L
#define CURL_SSLVERSION_TLSv1_3 7L

#define CURL_SSLVERSION_LAST    8L /* never use, keep last */

#define CURL_SSLVERSION_MAX_NONE 0L
#define CURL_SSLVERSION_MAX_DEFAULT (CURL_SSLVERSION_TLSv1   << 16)
#define CURL_SSLVERSION_MAX_TLSv1_0 (CURL_SSLVERSION_TLSv1_0 << 16)
#define CURL_SSLVERSION_MAX_TLSv1_1 (CURL_SSLVERSION_TLSv1_1 << 16)
#define CURL_SSLVERSION_MAX_TLSv1_2 (CURL_SSLVERSION_TLSv1_2 << 16)
#define CURL_SSLVERSION_MAX_TLSv1_3 (CURL_SSLVERSION_TLSv1_3 << 16)

/* never use, keep last */
#define CURL_SSLVERSION_MAX_LAST    (CURL_SSLVERSION_LAST    << 16)

#define CURL_TLSAUTH_NONE 0L
#define CURL_TLSAUTH_SRP  1L

#define CURL_REDIR_GET_ALL  0L
#define CURL_REDIR_POST_301 1L
#define CURL_REDIR_POST_302 2L
#define CURL_REDIR_POST_303 4L
#define CURL_REDIR_POST_ALL \
  (CURL_REDIR_POST_301 | CURL_REDIR_POST_302 | CURL_REDIR_POST_303)

#define CURL_TIMECOND_NONE         0L
#define CURL_TIMECOND_IFMODSINCE   1L
#define CURL_TIMECOND_IFUNMODSINCE 2L
#define CURL_TIMECOND_LASTMOD      3L

/* Special size_t value signaling a null-terminated string. */
#define CURL_ZERO_TERMINATED ((size_t)-1)

/* CURLMIMEOPT_ defines are for the CURLOPT_MIME_OPTIONS option. */
#define CURLMIMEOPT_FORMESCAPE (1L << 0) /* Use backslash-escaping for forms */

/* CURLINFO_RESPONSE_CODE is the new name for the option previously known as
   CURLINFO_HTTP_CODE */
#define CURLINFO_HTTP_CODE CURLINFO_RESPONSE_CODE

#define CURL_GLOBAL_SSL (1 << 0) /* no purpose since 7.57.0 */
#define CURL_GLOBAL_WIN32 (1 << 1)
#define CURL_GLOBAL_ALL (CURL_GLOBAL_SSL | CURL_GLOBAL_WIN32)
#define CURL_GLOBAL_NOTHING 0
#define CURL_GLOBAL_DEFAULT CURL_GLOBAL_ALL
#define CURL_GLOBAL_ACK_EINTR (1 << 2)

/* The 'CURLVERSION_NOW' is the symbolic name meant to be used by
   basically all programs ever that want to get version information. It is
   meant to be a built-in version number for what kind of struct the caller
   expects. If the struct ever changes, we redefine the NOW to another enum
   from above. */
#define CURLVERSION_NOW CURLVERSION_TWELFTH

#define CURL_VERSION_IPV6         (1<<0)  /* IPv6-enabled */
#define CURL_VERSION_KERBEROS4    (1<<1)  /* Kerberos V4 auth is supported
                                             (deprecated) */
#define CURL_VERSION_SSL          (1<<2)  /* SSL options are present */
#define CURL_VERSION_LIBZ         (1<<3)  /* libz features are present */
#define CURL_VERSION_NTLM         (1<<4)  /* NTLM auth is supported */
#define CURL_VERSION_GSSNEGOTIATE (1<<5)  /* Negotiate auth is supported
                                             (deprecated) */
#define CURL_VERSION_DEBUG        (1<<6)  /* Built with debug capabilities */
#define CURL_VERSION_ASYNCHDNS    (1<<7)  /* Asynchronous DNS resolves */
#define CURL_VERSION_SPNEGO       (1<<8)  /* SPNEGO auth is supported */
#define CURL_VERSION_LARGEFILE    (1<<9)  /* Supports files larger than 2GB */
#define CURL_VERSION_IDN          (1<<10) /* Internationized Domain Names are
                                             supported */
#define CURL_VERSION_SSPI         (1<<11) /* Built against Windows SSPI */
#define CURL_VERSION_CONV         (1<<12) /* Character conversions supported */
#define CURL_VERSION_CURLDEBUG    (1<<13) /* Debug memory tracking supported
                                             (deprecated) */
#define CURL_VERSION_TLSAUTH_SRP  (1<<14) /* TLS-SRP auth is supported */
#define CURL_VERSION_NTLM_WB      (1<<15) /* NTLM delegation to winbind helper
                                             is supported */
#define CURL_VERSION_HTTP2        (1<<16) /* HTTP2 support built-in */
#define CURL_VERSION_GSSAPI       (1<<17) /* Built against a GSS-API library */
#define CURL_VERSION_KERBEROS5    (1<<18) /* Kerberos V5 auth is supported */
#define CURL_VERSION_UNIX_SOCKETS (1<<19) /* Unix domain sockets support */
#define CURL_VERSION_PSL          (1<<20) /* Mozilla's Public Suffix List, used
                                             for cookie domain verification */
#define CURL_VERSION_HTTPS_PROXY  (1<<21) /* HTTPS-proxy support built-in */
#define CURL_VERSION_MULTI_SSL    (1<<22) /* Multiple SSL backends available */
#define CURL_VERSION_BROTLI       (1<<23) /* Brotli features are present. */
#define CURL_VERSION_ALTSVC       (1<<24) /* Alt-Svc handling built-in */
#define CURL_VERSION_HTTP3        (1<<25) /* HTTP3 support built-in */
#define CURL_VERSION_ZSTD         (1<<26) /* zstd features are present */
#define CURL_VERSION_UNICODE      (1<<27) /* Unicode support on Windows */
#define CURL_VERSION_HSTS         (1<<28) /* HSTS is supported */
#define CURL_VERSION_GSASL        (1<<29) /* libgsasl is supported */
#define CURL_VERSION_THREADSAFE   (1<<30) /* libcurl API is thread-safe */

#define CURLPAUSE_RECV      (1 << 0)
#define CURLPAUSE_RECV_CONT (0)

#define CURLPAUSE_SEND      (1 << 2)
#define CURLPAUSE_SEND_CONT (0)

#define CURLPAUSE_ALL       (CURLPAUSE_RECV | CURLPAUSE_SEND)
#define CURLPAUSE_CONT      (CURLPAUSE_RECV_CONT | CURLPAUSE_SEND_CONT)
"#;

/// Seven headers close the block this way.
const EXTERN_C_CLOSE_COMMENTED: &str = "} /* end of extern \"C\" */";

/// `websockets.h:95` closes it this way.
const EXTERN_C_CLOSE_BARE: &str = "}";

// What this build honestly supports
//
// The asymmetry that makes truthfulness the optimal strategy rather than
// merely the decent one: `tests/runtests.pl` parses the `Features:` and
// `Protocols:` lines of `curl --version` and uses them to decide which of
// the 1,914 fixtures to run. 874 of them gate on `<features>`.
// UNDER-REPORTING A CAPABILITY MAKES A FIXTURE SKIP; OVER-REPORTING MAKES
// IT RUN AND FAIL. So there is no advantage anywhere in claiming more than
// is built, and a real cost to it.
//
// AND THEY CANNOT DISAGREE WITH THE RUNTIME BANNER EITHER, because the feature
// tokens are no longer written down here at all: they are DERIVED from
// `curl-rs-lib/src/version.rs`, which is the
// authority for the feature and protocol banner. A local 23-row table here,
// beside a note that the two "cannot be unified in code" and that "the peer is
// named so the correspondence is checkable", is not equivalent: the check does
// not exist, and the two lists drift. Measured, they drifted in five places at
// once -- this file claiming `asyn-rr`, `HTTPSRR`, `Debug` and a non-standard
// standalone `TrackMemory` that the engine withholds, while omitting the
// `HTTPS-proxy` the engine advertises. Two hand-maintained lists of the same
// facts always end that way.
//
// A build script cannot depend on the crate it is packaging, so the engine's
// table is read as a SOURCE AUTHORITY -- the same way this file already reads
// `lib/libcurl.def` and the frozen headers -- and interpreted through a CLOSED
// grammar. Any construct the grammar does not recognise is a hard error naming
// the row, so a new gate shape cannot be silently misread as something it is
// not. See `runtime_feature_rows`.

/// The shell of `compiled_in:` expressions this build script can evaluate.
///
/// Closed on purpose. Adding a row to the engine's table with a gate outside
/// this set fails the build with the expression quoted, which is the only safe
/// response: guessing would either over-report a capability or silently drop
/// one, and both directions corrupt the metadata consumers read.
#[derive(Debug, PartialEq, Eq)]
enum Gate {
    /// `true` -- unconditional in this implementation.
    Always,
    /// `false` -- the row exists for ABI completeness but is withheld.
    Never,
    /// `cfg!(feature = "x")` -- gated on a Cargo feature.
    Feature(String),
    /// `cfg!(unix)` -- gated on the target family.
    Unix,
    /// `CURL_OFF_T_SIZE > 4` -- gated on the width of `curl_off_t`.
    LargeFile,
    /// `ENGINE_X.is_present()` -- gated on whether the engine that owns the
    /// capability can actually EXECUTE it, which is not the same question as
    /// whether its module has been written. Resolved at parse time by reading
    /// the `Engine::working`/`inert`/`unwritten` constructor of the named
    /// constant in the engine's version module, so the answer is a constant
    /// here exactly as it is a `const fn` there.
    Engine(bool),
    /// Two or more of the above joined by `&&`. Every conjunct must hold.
    All(Vec<Gate>),
}

/// What a row's `present:` field resolves to.
#[derive(Debug, PartialEq, Eq)]
enum Probe {
    /// `None` -- C's NULL: present whenever compiled in.
    Absent,
    /// `Some(f)` where `f`'s whole body is a boolean literal, so the answer is
    /// fixed for a given build and this script can evaluate it.
    Constant(bool),
    /// `Some(f)` where `f` is genuinely dynamic. The named function decides at
    /// RUN TIME, so no build-time answer exists and the token is withheld from
    /// static metadata.
    Dynamic(String),
}

/// One row read from the engine's feature table.
struct RuntimeFeature {
    /// The token exactly as the harness's 52-name vocabulary spells it.
    /// Case matters: the map is keyed on these strings.
    token: String,
    /// The compile-time half of the row's predicate.
    gate: Gate,
    /// The runtime half of the row's predicate.
    probe: Probe,
}

/// One row read from the engine's protocol table.
struct RuntimeProtocol {
    /// The scheme name, LOWER case, exactly as the engine spells it.
    token: String,
    /// The compile-time gate on serving the scheme.
    gate: Gate,
}

/// Where the engine's capability tables live, relative to this crate.
///
/// Reading it here rather than mirroring it is what makes the generated
/// consumer metadata and the runtime banner two projections of one list.
const ENGINE_VERSION_RS: &str = "../curl-rs-lib/src/version.rs";

/// Where the "headers not regenerated" notice is written inside `OUT_DIR`.
///
/// A fixed name so a workflow or a reader can find the live export-surface
/// figure at a derivable path. It replaces two `cargo:warning=` lines that
/// specification 0.8.4's zero-warning gate could not accommodate, and it is
/// not warning-class: the condition it reports is unwritten work, not a fault.
/// Removed when the surface completes, so it can never describe a state that
/// has passed.
const HEADER_NOTICE: &str = "include-curl-not-regenerated.txt";

/// Read the engine module that owns the capability tables.
fn engine_authority() -> Result<String, Box<dyn Error>> {
    fs::read_to_string(ENGINE_VERSION_RS).map_err(|e| {
        format!(
            "cannot read the engine capability tables at \
             {ENGINE_VERSION_RS}: {e}. They are the authority for the \
             advertised feature and protocol sets, so the metadata cannot be \
             generated without them."
        )
        .into()
    })
}

/// The body of one `pub const NAME: &[Type] = &[ ... \n];` table.
///
/// Located by its literal declaration rather than by a permissive pattern, so
/// a renamed or reshaped table fails loudly instead of yielding a partial
/// read. The terminator is anchored to a line-initial `];` because a row's own
/// text may contain a bracket.
fn engine_table<'a>(
    source: &'a str,
    open: &str,
) -> Result<&'a str, Box<dyn Error>> {
    let start = source.find(open).ok_or_else(|| {
        format!(
            "{ENGINE_VERSION_RS} no longer declares `{open}`. Either the \
             authority moved or its shape changed; this script reads it \
             literally and must be updated deliberately."
        )
    })? + open.len();
    let len = source[start..].find("\n];").ok_or_else(|| {
        format!("the `{open}` table in {ENGINE_VERSION_RS} is unterminated")
    })?;
    Ok(&source[start..start + len])
}

/// Read and interpret every row of the engine's `FEATURES` table.
///
/// The engine's table is the single authority for what this build advertises
///. This reads it rather than mirroring it, so the static
/// consumer metadata and the runtime `--version` banner are two projections of
/// one list and cannot describe different products.
fn runtime_feature_rows() -> Result<Vec<RuntimeFeature>, Box<dyn Error>> {
    let source = engine_authority()?;
    let table = engine_table(&source, "pub const FEATURES: &[Feature] = &[")?;

    let mut rows: Vec<RuntimeFeature> = Vec::new();
    let mut seen: Vec<String> = Vec::new();

    // Rows are matched field-by-field in declaration order rather than with one
    // permissive pattern, so a reordered or extra field fails to match and is
    // reported as an unparsable row instead of being read incorrectly.
    for chunk in table.split("Feature {").skip(1) {
        let token = row_token(chunk, "Feature")?;

        if seen.contains(&token) {
            return Err(format!(
                "{token} appears twice in the engine feature table; the \
                 advertised set would then depend on iteration order"
            )
            .into());
        }
        seen.push(token.clone());

        let gate = classify_gate(
            &field(chunk, "compiled_in:", "Feature")?,
            &token,
            &source,
        )?;
        let probe = classify_probe(
            &field(chunk, "present:", "Feature")?,
            &source,
            &token,
        )?;
        rows.push(RuntimeFeature { token, gate, probe });
    }

    if rows.is_empty() {
        return Err(format!(
            "no rows parsed out of the FEATURES table in \
             {ENGINE_VERSION_RS}. An empty result would silently advertise \
             nothing at all, so it is rejected rather than accepted."
        )
        .into());
    }

    Ok(rows)
}

/// The text of one `name: value,` field of a struct literal.
///
/// `ctor` names the struct being read purely so a failure says which table it
/// came from; both capability tables live in one file.
fn field(chunk: &str, key: &str, ctor: &str) -> Result<String, Box<dyn Error>> {
    let at = chunk.find(key).ok_or_else(|| {
        format!("a `{ctor}` row is missing its `{key}` field")
    })?;
    let rest = &chunk[at + key.len()..];
    let end = rest.find(",\n").ok_or_else(|| {
        format!("the `{key}` field of a `{ctor}` row is unterminated")
    })?;
    Ok(rest[..end].trim().to_string())
}

/// A row's `name:` field, which must be a string literal in both tables.
fn row_token(chunk: &str, ctor: &str) -> Result<String, Box<dyn Error>> {
    let raw = field(chunk, "name:", ctor)?;
    Ok(raw
        .strip_prefix('"')
        .and_then(|t| t.strip_suffix('"'))
        .ok_or_else(|| format!("a `{ctor}` row has a non-literal name: {raw}"))?
        .to_string())
}

/// Read and interpret every row of the engine's `PROTOCOLS` table.
fn runtime_protocol_rows() -> Result<Vec<RuntimeProtocol>, Box<dyn Error>> {
    let source = engine_authority()?;
    let table = engine_table(&source, "pub const PROTOCOLS: &[Protocol] = &[")?;

    let mut rows: Vec<RuntimeProtocol> = Vec::new();
    let mut seen: Vec<String> = Vec::new();

    for chunk in table.split("Protocol {").skip(1) {
        let token = row_token(chunk, "Protocol")?;

        if token.is_empty() || token != token.to_lowercase() {
            return Err(format!(
                "the engine protocol table spells a scheme as {token:?}, but \
                 the banner spells schemes in lower case and this script \
                 upper-cases them for `curl-config`. A differently cased name \
                 would be transformed blindly, so it is rejected."
            )
            .into());
        }
        if seen.contains(&token) {
            return Err(format!(
                "{token} appears twice in the engine protocol table; the \
                 advertised set would then depend on iteration order"
            )
            .into());
        }
        seen.push(token.clone());

        let gate = classify_gate(
            &field(chunk, "compiled_in:", "Protocol")?,
            &token,
            &source,
        )?;
        rows.push(RuntimeProtocol { token, gate });
    }

    if rows.is_empty() {
        return Err(format!(
            "no rows parsed out of the PROTOCOLS table in \
             {ENGINE_VERSION_RS}. An empty result would advertise no scheme \
             at all, making every fixture ineligible, so it is rejected."
        )
        .into());
    }

    Ok(rows)
}

/// Interpret a `compiled_in:` expression against the closed [`Gate`] grammar.
fn classify_gate(
    expr: &str,
    token: &str,
    source: &str,
) -> Result<Gate, Box<dyn Error>> {
    classify_gate_at_depth(expr, token, source, 0)
}

/// The maximum number of `supports_*()` indirections this script will follow.
const MAX_PREDICATE_DEPTH: usize = 4;

/// [`classify_gate`] plus the indirection counter.
fn classify_gate_at_depth(
    expr: &str,
    token: &str,
    source: &str,
    depth: usize,
) -> Result<Gate, Box<dyn Error>> {
    // A `compiled_in:` expression may be written across several lines by
    // rustfmt, so collapse the whitespace before matching any shape.
    let flat = expr.split_whitespace().collect::<Vec<_>>().join(" ");

    // `&&` is the only operator the grammar admits, and it binds every
    // conjunct: a row is compiled in only when all of them hold.
    let parts: Vec<&str> = flat.split("&&").map(str::trim).collect();
    if parts.len() > 1 {
        let mut gates = Vec::with_capacity(parts.len());
        for part in parts {
            gates.push(classify_conjunct(part, token, source, depth)?);
        }
        return Ok(Gate::All(gates));
    }

    classify_conjunct(&flat, token, source, depth)
}

/// One `&&`-free term of a `compiled_in:` expression.
///
/// The grammar is closed deliberately -- guessing would either invent a
/// capability or drop a real one -- so an unrecognised shape is an error and
/// never a default.
fn classify_conjunct(
    expr: &str,
    token: &str,
    source: &str,
    depth: usize,
) -> Result<Gate, Box<dyn Error>> {
    if expr == "true" {
        return Ok(Gate::Always);
    }
    if expr == "false" {
        return Ok(Gate::Never);
    }
    if expr == "cfg!(unix)" {
        return Ok(Gate::Unix);
    }
    if expr == "CURL_OFF_T_SIZE > 4" {
        return Ok(Gate::LargeFile);
    }
    if let Some(rest) = expr.strip_prefix("cfg!(feature = \"") {
        if let Some(name) = rest.strip_suffix("\")") {
            if !CRATE_FEATURES.contains(&name) {
                return Err(format!(
                    "{token} is gated on the Cargo feature {name:?}, which \
                     this crate does not declare, so its state cannot be read \
                     here. Forward the feature in curl-rs-ffi/Cargo.toml and \
                     add it to CRATE_FEATURES, or the metadata will silently \
                     withhold the capability."
                )
                .into());
            }
            return Ok(Gate::Feature(name.to_string()));
        }
    }
    if let Some(name) = expr
        .strip_prefix("ENGINE_")
        .and_then(|rest| rest.strip_suffix(".is_present()"))
    {
        let konst = format!("ENGINE_{name}");
        return Ok(Gate::Engine(engine_is_present(&konst, source, token)?));
    }
    // `supports_x()` -- one of the engine's public capability predicates.
    //
    // Resolved by FOLLOWING it rather than by tabulating it here. The engine
    // introduced these so that a capability is spelled once and consumed by the
    // `Features:` table, the version banner and the `curl_version_info`
    // payload alike; a build script that carried its own copy of what
    // `supports_brotli()` means would recreate exactly the duplication those
    // predicates removed, and this file's own history (a 23-row table that
    // drifted from the engine's in five places) is the argument against that.
    if let Some(name) = expr
        .strip_prefix("supports_")
        .and_then(|rest| rest.strip_suffix("()"))
    {
        let predicate = format!("supports_{name}");

        if depth >= MAX_PREDICATE_DEPTH {
            return Err(format!(
                "{token} is gated on `{predicate}`, but following the \
                 capability predicates exceeded {MAX_PREDICATE_DEPTH} levels \
                 of indirection. That means a predicate in \
                 {ENGINE_VERSION_RS} refers to itself, directly or through \
                 another, and no fixed answer exists to read."
            )
            .into());
        }

        let body = predicate_body(&predicate, source, token)?;

        return classify_gate_at_depth(&body, token, source, depth + 1);
    }
    Err(format!(
        "{token} has a `compiled_in:` expression this build script does not \
         recognise: `{expr}`. The grammar is closed deliberately -- guessing \
         would either invent a capability or drop a real one -- so extend \
         `classify_gate` with the new shape and its evaluation."
    )
    .into())
}

/// Extract the body expression of a `pub const fn supports_x() -> bool`.
fn predicate_body(
    predicate: &str,
    source: &str,
    token: &str,
) -> Result<String, Box<dyn Error>> {
    let decl = format!("pub const fn {predicate}() -> bool {{");
    let at = source.find(&decl).ok_or_else(|| {
        // Naming the non-const spelling separately turns the most likely
        // mistake into a one-line diagnosis instead of a hunt.
        let non_const = format!("pub fn {predicate}() -> bool {{");
        if source.contains(&non_const) {
            format!(
                "{token} is gated on `{predicate}`, which exists in \
                 {ENGINE_VERSION_RS} but is not `const fn`. This script reads \
                 the body as data and cannot evaluate a runtime predicate; \
                 make it `const fn`, or express the row's gate directly."
            )
        } else {
            format!(
                "{token} is gated on `{predicate}`, but no \
                 `pub const fn {predicate}() -> bool` was found in \
                 {ENGINE_VERSION_RS}. Either the predicate was renamed \
                 without updating the table, or the gate is a typo."
            )
        }
    })?;

    let open = at + decl.len() - 1;
    let mut depth = 0usize;
    let mut close = None;

    for (offset, byte) in source.as_bytes()[open..].iter().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(open + offset);
                    break;
                }
            }
            _ => {}
        }
    }

    let close = close.ok_or_else(|| {
        format!(
            "{token} is gated on `{predicate}`, whose body in \
             {ENGINE_VERSION_RS} is not brace-balanced"
        )
    })?;

    let body = source[open + 1..close].trim().to_string();

    if body.is_empty() {
        return Err(format!(
            "{token} is gated on `{predicate}`, whose body is empty"
        )
        .into());
    }
    if body.contains(';') || body.contains("return") {
        return Err(format!(
            "{token} is gated on `{predicate}`, whose body is a statement \
             block rather than a single expression: `{body}`. This script \
             reads the body as data, so keep the predicate a single \
             expression or express the row's gate directly."
        )
        .into());
    }

    Ok(body)
}

/// Read whether an `ENGINE_*` constant in the engine's version module was
/// declared present.
///
/// The constants are written with one of THREE constructors, so the state is a
/// literal in the source and this script resolves it without executing the
/// engine:
///
/// * `Engine::working("path")` -- the module exists and the work executes.
///   Present.
/// * `Engine::inert("path")` -- the module exists but nothing calls it. NOT
///   present.
/// * `Engine::unwritten("path")` -- the module is not in the tree. NOT present.
///
/// Only the first advertises. The other two are distinguished in the engine so
/// that "what would clear this row" is recorded correctly -- write a file, or
/// wire one that already exists -- and that distinction is deliberately
/// FLATTENED here, because a consumer reading `curl-config --protocols` cares
/// only whether the capability works. Both therefore map to `false`, and mapping
/// either to `true` would be the over-report AAP 0.6.5 measures as fatal.
///
/// An unknown constructor is an error rather than a guess, for the same reason
/// the gate grammar is closed: silently reading an engine as present would
/// advertise a capability that does not exist, and the harness would then run
/// fixtures against it. That is also why the check is `starts_with` on each
/// exact constructor rather than a negative test for `working`: a future
/// `Engine::partial(..)` would fail loudly here instead of being read as absent
/// by default and then quietly as present by some later edit.
fn engine_is_present(
    konst: &str,
    source: &str,
    token: &str,
) -> Result<bool, Box<dyn Error>> {
    let decl = format!("pub const {konst}: Engine =");
    let at = source.find(&decl).ok_or_else(|| {
        format!(
            "{token} is gated on `{konst}.is_present()`, but no \
             `pub const {konst}: Engine =` declaration was found in \
             {ENGINE_VERSION_RS}, so the capability cannot be resolved"
        )
    })?;
    let rest = &source[at + decl.len()..];
    let body =
        rest.find(';')
            .map(|end| rest[..end].trim())
            .ok_or_else(|| {
                format!(
                "{konst} in {ENGINE_VERSION_RS} has no terminated initialiser"
            )
            })?;
    if body.starts_with("Engine::working(") {
        return Ok(true);
    }
    if body.starts_with("Engine::inert(")
        || body.starts_with("Engine::unwritten(")
    {
        return Ok(false);
    }
    Err(format!(
        "{konst} in {ENGINE_VERSION_RS} is initialised with `{body}`, which is \
         none of `Engine::working(..)`, `Engine::inert(..)` or \
         `Engine::unwritten(..)`; {token}'s capability cannot be resolved \
         without executing the engine"
    )
    .into())
}

/// Read the engine module source that owns a qualified `present:` path.
///
/// `crate::url::idn::available` resolves to `curl-rs-lib/src/url/idn.rs`, or to
/// `.../idn/mod.rs` when the module is a directory. An unresolvable path is an
/// error rather than a silent `Dynamic`, because a probe this script cannot
/// read is a capability it cannot honestly describe.
fn engine_module_source(
    path: &str,
    token: &str,
) -> Result<String, Box<dyn Error>> {
    let mut parts: Vec<&str> = path.split("::").collect();
    parts.pop();
    if parts.first() == Some(&"crate") {
        parts.remove(0);
    }
    if parts.is_empty() {
        return Err(format!(
            "{token}'s `present:` path `{path}` names no module"
        )
        .into());
    }
    let stem = format!("../curl-rs-lib/src/{}", parts.join("/"));
    for candidate in [format!("{stem}.rs"), format!("{stem}/mod.rs")] {
        if let Ok(text) = fs::read_to_string(&candidate) {
            println!("cargo:rerun-if-changed={candidate}");
            return Ok(text);
        }
    }
    Err(format!(
        "{token}'s `present:` path `{path}` points at no readable module: \
         neither {stem}.rs nor {stem}/mod.rs exists"
    )
    .into())
}

/// Resolve a `present:` field, reading the named function's body when there is
/// one so that a constant probe can be evaluated at build time.
fn classify_probe(
    expr: &str,
    source: &str,
    token: &str,
) -> Result<Probe, Box<dyn Error>> {
    if expr == "None" {
        return Ok(Probe::Absent);
    }
    let name = expr
        .strip_prefix("Some(")
        .and_then(|r| r.strip_suffix(')'))
        .ok_or_else(|| {
            format!(
                "{token} has a `present:` field that is neither `None` nor \
                 `Some(function)`: `{expr}`"
            )
        })?;

    // The probe may name a function in this module or a path into another
    // engine module -- the IDN row consumes `crate::url::idn::available`
    // directly rather than keeping a duplicate predicate here. A path is
    // resolved by reading the module that owns it, so a single source of truth
    // in the engine stays a single source of truth for this script too.
    let (owner, name) = if name.contains("::") {
        let owned = engine_module_source(name, token)?;
        let leaf = name.rsplit("::").next().unwrap_or(name).to_string();
        (owned, leaf)
    } else {
        (source.to_string(), name.to_string())
    };
    let name = name.as_str();

    // A constant probe is a whole body of exactly `true` or `false`. Anything
    // else -- a call, a cfg, arithmetic -- is dynamic by definition, because
    // this script cannot evaluate it without executing the engine.
    let signature = format!("fn {name}() -> bool {{");
    let body = owner
        .find(&signature)
        .map(|at| &owner[at + signature.len()..])
        .and_then(|rest| rest.find('}').map(|end| rest[..end].trim()))
        .ok_or_else(|| {
            format!(
                "{token}'s `present:` names `{name}`, but no \
                 `fn {name}() -> bool` with a braced body was found in the \
                 module that owns it, so its value cannot be established"
            )
        })?;

    match body {
        "true" => Ok(Probe::Constant(true)),
        "false" => Ok(Probe::Constant(false)),
        _ => Ok(Probe::Dynamic(name.to_string())),
    }
}

/// Evaluate a row's compile-time gate for the target being built.
fn gate_holds(gate: &Gate) -> Result<bool, Box<dyn Error>> {
    match gate {
        Gate::Always => Ok(true),
        Gate::Never => Ok(false),
        Gate::Feature(name) => Ok(feature_enabled(name)),
        // Resolved at parse time from the engine's own constant, so there is
        // nothing target-specific left to decide here.
        Gate::Engine(present) => Ok(*present),
        Gate::All(gates) => {
            for gate in gates {
                if !gate_holds(gate)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        // From CARGO_CFG_*, never `cfg!`: a build script is compiled for the
        // HOST, so its own `cfg!` describes the wrong machine.
        Gate::Unix => Ok(env::var("CARGO_CFG_TARGET_FAMILY")
            .unwrap_or_default()
            .split(',')
            .any(|family| family == "unix")),
        Gate::LargeFile => {
            let width =
                env::var("CARGO_CFG_TARGET_POINTER_WIDTH").unwrap_or_default();
            // All four mandated targets are 64-bit, and the engine derives
            // this row from the width of curl_off_t. A narrower target would
            // need the engine consulted rather than assumed, so it is rejected
            // instead of guessed.
            match width.as_str() {
                "64" => Ok(true),
                "" => Err("CARGO_CFG_TARGET_POINTER_WIDTH is unset, so the \
                           Largefile capability cannot be decided"
                    .into()),
                other => Err(format!(
                    "target pointer width {other} is outside the four 64-bit \
                     targets specification 0.8.3 mandates; the Largefile \
                     capability would have to be re-derived for it"
                )
                .into()),
            }
        }
    }
}

/// Tokens from the harness's vocabulary that this build must never
/// advertise, each with the reason. Checked at build time by
/// [`run_self_checks`] against what [`advertised_features`] actually derives,
/// so a token cannot reappear through a careless edit to the engine's table.
const WITHHELD: [(&str, &str); 17] = [
    // ---- The cross-artifact contract with curl-rs-lib/src/version.rs -------
    //
    // 1. THE GATE COULD NEVER TAKE EFFECT WHERE IT MATTERS.
    //    `tests/runtests.pl` reads capabilities from `curl --version`, which
    //    is produced by `FEATURES` in `curl-rs-lib/src/version.rs` -- and that
    //    table hard-codes the `Debug` row to `compiled_in: false`, a literal
    //    rather than a `cfg!`. So with `--features memdebug` the banner still
    //    withheld `Debug` while `curl-config --feature` and `libcurl.pc`
    //    announced it: two artifacts of one build contradicting each other,
    //    with the announcement coming from the artifact the harness does not
    //    read. Withholding here makes the two agree by construction.
    //
    // 2. `TrackMemory` IS NOT A curl FEATURE TOKEN AT ALL.
    //    curl never emits it. Measured across the whole C tree: it appears in
    //    `tests/runtests.pl`, `tests/runner.pm` and `tests/data/test558` and
    //    nowhere in `lib/`, `src/`, `include/`, `curl-config.in` or
    //    `CMakeLists.txt`. The harness DERIVES it -- `tests/runtests.pl:660`,
    //    `$feature{"TrackMemory"} = $feat =~ /Debug/i;` -- from the `Debug`
    //    token. Advertising it invented a token with no C counterpart, which
    //    is why it has no row in `version.rs`'s 32 either. (`Debug` by
    //    contrast is genuine: `CMakeLists.txt:2032`,
    //    `curl_add_if("Debug" ENABLE_DEBUG)`.)
    //
    // The `memdebug` feature is NOT made inert by this. It supplies the
    // counting `GlobalAlloc` that reproduces `lib/memdebug.c`'s log format and
    // honours `CURL_MEMLIMIT`, which is useful on its own and is exercised by
    // its own tests. What it must not do is claim a capability whose full
    // semantics -- the internal behaviour changes a C DEBUGBUILD also makes,
    // which the 98 `Debug`-gated fixtures exercise -- do not exist. That is
    // exactly the recorded A5 resolution, and the cost is
    // stated rather than buried: 98 fixtures skip, the 28 `<limits>` fixtures
    // go inert, and `make torture-test` is inapplicable because it dies
    // without `TrackMemory` (`tests/runtests.pl:847-849`).
    (
        "Debug",
        "a C DEBUGBUILD also changes internal behaviour that the 98 \
         Debug-gated fixtures exercise, and only the allocation log exists \
         here; curl-rs-lib/src/version.rs withholds it unconditionally too",
    ),
    (
        "TrackMemory",
        "curl never emits this token -- tests/runtests.pl:660 derives it from \
         Debug -- so advertising it would invent a capability name with no C \
         counterpart",
    ),
    // ---- Everything else ---------------------------------------------------
    (
        "MultiSSL",
        "rustls is the only backend; there is no second one",
    ),
    ("OpenSSL", "no C TLS library is linked"),
    ("GnuTLS", "no C TLS library is linked"),
    ("mbedtls", "no C TLS library is linked"),
    ("wolfssl", "no C TLS library is linked"),
    (
        "Schannel",
        "no C TLS library is linked, and Windows is not a target",
    ),
    ("SSPI", "Windows-only, and Windows is not a mandated target"),
    ("TLS-SRP", "not implemented; rustls exposes no SRP suite"),
    (
        "NTLM_WB",
        "the retired external NTLM helper has no equivalent",
    ),
    (
        "WinIDN",
        "the idna crate provides IDN; Windows is not a target",
    ),
    ("AppleIDN", "the idna crate provides IDN on every target"),
    ("libssh", "russh replaces both C SSH libraries"),
    ("libssh2", "russh replaces both C SSH libraries"),
    (
        "c-ares",
        "the system resolver is used in every configuration; the reserved \
         hickory-dns feature has no implementation",
    ),
    (
        "gsasl",
        "dropped with the SASL protocols, which are out of scope",
    ),
];

/// The sole TLS backend, as `curl-config --ssl-backends` reports it.
const SSL_BACKENDS: &str = "rustls";

// Measured ground truth for the option table.
//
// `curl-rs-ffi/src/ffi/opts.rs` is the sole source of truth for the
// CURLoption identifiers AND for the `curl_easyoption` metadata array that
// backs `curl_easy_option_by_name`, `curl_easy_option_by_id` and
// `curl_easy_option_next` (note that last spelling: it is
// `curl_easy_option_next`, not `_by_next`, confirmed in `lib/libcurl.def`).
// That module is on disk, and cbindgen renders both from it.

/// Rows the C generator emits, including the terminating sentinel
/// `{ NULL, CURLOPT_LASTENTRY, CURLOT_LONG, 0 }`. Measured: 324.
///
/// Re-measured by running `perl lib/optiontable.pl < include/curl/curl.h`
/// and counting `{...}` groups with brace-balanced scanning, bounded to the
/// `Curl_easyopts[]` initialiser so that the braces of the functions the
/// generator emits after the array are not counted. Two counting mistakes
/// are worth naming, because one of them is what this constant previously
/// recorded:
///
///   * Scanning to end-of-file instead of to the array's closing `};` yields
///     325 and reports two sentinel rows, the second being the
///     `CURLOPT_LASTENTRY` reference inside the lookup function the
///     generator emits below the table.
///   * A per-line regex yields 301, because the longer rows wrap onto a
///     second line.
const OPTION_TABLE_ROWS: usize = 324;

/// Rows flagged `CURLOT_FLAG_ALIAS`. Measured: 15.
const OPTION_TABLE_ALIAS_ROWS: usize = 15;

/// Rows describing something, excluding the sentinel. Measured: 323.
///
/// "Real" here means non-sentinel, NOT non-alias: 15 of these rows are
/// backward-compatibility aliases. The count of rows describing a PREFERRED
/// option is [`OPTION_TABLE_TRUE_OPTIONS`].
const OPTION_TABLE_REAL_ROWS: usize = OPTION_TABLE_ROWS - 1;

/// Rows describing a preferred option -- neither an alias nor the sentinel.
/// Measured: 308.
const OPTION_TABLE_TRUE_OPTIONS: usize =
    OPTION_TABLE_REAL_ROWS - OPTION_TABLE_ALIAS_ROWS;

/// The last real option's ordinal -- the third argument to its `CURLOPT`
/// macro. Measured: 328, on `CURLOPT_SSL_SIGNATURE_ALGORITHMS`.
///
/// Not `CURLOPT_LASTENTRY`'s own value, which is 10329 and whose ordinal is
/// 329. The distinction matters because `lib/optiontable.pl` guards its
/// output with `return (CURLOPT_LASTENTRY % 10000) != (328 + 1);`, so the
/// number appearing in that check is this ordinal and not the sentinel's.
const OPTION_LASTENTRY_INDEX: usize = 328;

/// Symbols `lib/libcurl.def` exports: `EXPORTS` on line 1 then exactly 100
/// names on lines 2-101, `curl_easy_cleanup` first and
/// `curl_ws_start_frame` last. Every one is a function; measured zero data
/// symbols, which is why `cbindgen.toml` omits `globals` from
/// `item_types`.
const EXPORTED_SYMBOLS: usize = 100;

/// Of those 100, the number carried verbatim rather than generated: the
/// four C-variadic setters, the five deprecated prototypes, the ten
/// `curl_m*printf` functions, the twelve whose frozen signature names a type
/// this crate's Rust spelling cannot ask cbindgen to produce
/// (`cbindgen.toml`, "Group 5e"), the two whose parameter names a public enum,
/// the two the header API declares, the three remaining URL-API
/// constructors and the four WebSocket entry points.
/// 4 + 5 + 10 + 12 + 2 + 2 + 3 + 4 = 42.
///
/// The next two are `curl_easy_header` and `curl_easy_nextheader`. They were
/// generated until the render of `include/curl/header.h` was measured against
/// the frozen file: cbindgen emitted `CURL_EXTERN` on a line of its own,
/// re-indenting every continuation line, and prefixed each prototype with its
/// whole Rust doc comment -- 40 and 29 lines of `# Safety` headings, markdown
/// and `lib/headers.c` internals in a header that carries no prototype
/// comment at all. See [`HEADER_H_DECLS`].
///
/// The last three are `curl_url`, `curl_url_cleanup` and `curl_url_dup`, and
/// they joined for exactly that measured reason plus two more that are specific
/// to `urlapi.h`: the frozen file interleaves the flag bits and the handle
/// typedef BETWEEN the enums and the prototypes, which one contiguous generated
/// region cannot express, and `curl_url_dup`'s frozen parameter name `in`
/// (`urlapi.h:126`) is a Rust keyword. [`URLAPI_H_ITEMS`] records the full
/// measurement.
///
/// The last four are `curl_ws_recv`, `curl_ws_send`, `curl_ws_start_frame`
/// and `curl_ws_meta`, and they joined for BOTH of `urlapi.h`'s reasons at
/// once. `websockets.h` interleaves three constant blocks between its four
/// prototypes -- `CURLWS_PONG` between the first and the second, the two
/// `CURLOPT_WS_OPTIONS` bits between the third and the fourth -- which one
/// contiguous generated region cannot express; and two of the four name
/// `struct curl_ws_frame`, a tag-form struct with no typedef, which
/// `style = "type"` renders as a bare `curl_ws_frame` that does not compile.
/// [`WEBSOCKETS_H_ITEMS`] records the full measurement.
const VERBATIM_FUNCTIONS: usize = 42;

// Three further facts about the option metadata, recorded as comments
// because they are shape rather than count:
//
//   * Names are stored WITHOUT the `CURLOPT_` prefix. The generator emits
//     `{ "ENCODING", CURLOPT_ACCEPT_ENCODING, CURLOT_STRING,
//     CURLOT_FLAG_ALIAS }`, and `curl_easy_option_by_name` matches
//     case-insensitively.
//   * `curl_easytype` CANNOT be derived from `id / 10000`.
//     `CURLOPTTYPE_STRINGPOINT`, `CURLOPTTYPE_SLISTPOINT` and
//     `CURLOPTTYPE_CBPOINT` all alias `CURLOPTTYPE_OBJECTPOINT`, and
//     `CURLOPTTYPE_VALUES` aliases `CURLOPTTYPE_LONG`, so `CURLOT_VALUES`,
//     `CURLOT_STRING`, `CURLOT_SLIST`, `CURLOT_CBPTR`, `CURLOT_OBJECT` and
//     `CURLOT_FUNCTION` share bases with other types. The type must be
//     carried explicitly per row. (The division DOES recover the argument's
//     size class, which is what makes the single-trailing-pointer setters
//     sound; it just does not recover `curl_easytype`.)
//   * `CURLOT_FLAG_ALIAS (1 << 0)` (include/curl/options.h:47) is the only
//     flag bit defined.

// Entry point

/// WHY THIS IS NOT `fn main() -> Result<(), Box<dyn Error>>`.
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

/// Everything the build script does, with failure returned rather than printed.
fn run() -> Result<(), Box<dyn Error>> {
    // Invariants first. A build script that renders the wrong thing quickly
    // is worse than one that refuses to render at all.
    run_self_checks()?;

    let manifest = PathBuf::from(env_var("CARGO_MANIFEST_DIR")?);

    // CARGO_MANIFEST_DIR is <root>/curl-rs-ffi, so the repository root is
    // its parent. Never an absolute literal: hard-coding one would break
    // both reproducibility and every CI checkout path.
    let root = manifest
        .parent()
        .ok_or_else(|| {
            format!(
                "CARGO_MANIFEST_DIR has no parent, so the repository root \
                 cannot be located: {}",
                manifest.display()
            )
        })?
        .to_path_buf();

    emit_rerun_directives(&manifest)?;

    // Deliberately after the rerun directives and before anything is
    // rendered. After, so that cargo has already been told this build depends
    // on CURL_RS_A4_VARIADIC_DECISION -- a refusal that cargo would not
    // re-evaluate when the decision is recorded would be a trap. Before, so
    // that a configuration whose variadic ABI is known-wrong never gets as far
    // as writing a public header that advertises symbols it cannot honour.
    check_variadic_abi(&manifest)?;

    // Every environment-derived substitution, checked against every grammar it
    // reaches, before a single artifact is written. See Section 14b.
    validate_environment_substitutions()?;

    emit_link_args(&manifest)?;

    // Needs the repository root, so it cannot live in run_self_checks. Runs
    // before any render: a symbol the headers would not declare is a defect in
    // the partition, not in the output.
    check_export_coverage(&root)?;

    // Needs the manifest directory, so likewise cannot live in
    // run_self_checks. The measured option-table facts above describe
    // `src/ffi/opts.rs`; this is what makes that description enforceable
    // instead of merely asserted.
    option_table_ground_truth(&manifest)?;

    // Needs the repository root for the same reason. Runs before any render
    // because `curl-config --cc` is one of the things about to be rendered.
    check_cross_toolchain_agreement(&root)?;

    // Likewise root-relative, and likewise before any render: the blocked-gate
    // declarations describe the dependency graph this artifact was built from,
    // so they must be current before anything describes that artifact.
    check_blocked_aap_gates(&root)?;

    let facts = VersionFacts::read(&root)?;

    generate_headers(&manifest, &root)?;
    render_curl_config(&root, &facts)?;
    render_libcurl_pc(&root, &facts)?;

    Ok(())
}

/// Read an environment variable Cargo is contractually required to set,
/// failing with a message that names it rather than with a bare `None`.
fn env_var(key: &str) -> Result<String, Box<dyn Error>> {
    env::var(key).map_err(|e| {
        format!("cargo did not provide {key} to the build script: {e}").into()
    })
}

// Build-time invariants

/// Assert the internal consistency of the tables above.
fn run_self_checks() -> Result<(), Box<dyn Error>> {
    // The partition must be disjoint. Two headers declaring the same item
    // is a duplicate C declaration, which is a hard compile error in the
    // 129 example programs and would be found late and confusingly.
    for (i, (name_a, items_a)) in PARTITIONS.iter().enumerate() {
        for (name_b, items_b) in PARTITIONS.iter().skip(i + 1) {
            for item in items_a.iter() {
                if items_b.contains(item) {
                    return Err(format!(
                        "header partition is not disjoint: {item} is \
                         claimed by both {name_a} and {name_b}. Each item \
                         must belong to exactly one header, or it will be \
                         declared twice."
                    )
                    .into());
                }
            }
        }
        // A name may not be both partitioned and globally verbatim. If it
        // were, the verbatim declaration and a generated one would both
        // appear, or the exclude would silently win and the partition entry
        // would be a lie.
        for item in items_a.iter() {
            if NEVER_GENERATED.contains(item) {
                return Err(format!(
                    "{item} is listed as an item of {name_a} but names a \
                     header that is never generated"
                )
                .into());
            }
            if CURL_H_VERBATIM_NAMES.contains(item) {
                return Err(format!(
                    "{item} is listed as an item of {name_a} and is also \
                     written verbatim into curl.h. It would be declared \
                     twice, which is a hard C error."
                )
                .into());
            }
            // The same rule, derived from the verbatim text itself, so a
            // constant macro carried verbatim in ANY header cannot also be
            // claimed as a generated item of one.
            for (header, carriers) in VERBATIM_CARRIERS.iter() {
                for carrier in carriers.iter() {
                    if verbatim_defines(carrier).contains(item) {
                        return Err(format!(
                            "{item} is listed as an item of {name_a}, so \
                             this script asks cbindgen to generate it, yet \
                             it is also `#define`d in the verbatim text of \
                             {header}. Either it is declared twice, or -- \
                             because a constant macro is not a Rust item \
                             cbindgen can emit -- the partition entry is a \
                             lie that hides a missing declaration. Carry it \
                             verbatim and drop it from the item list."
                        )
                        .into());
                    }
                }
            }
        }
    }

    // The name whose exclusion is lifted must be owned by curl.h and by
    // nothing else, or lifting it would publish it from two headers.
    for lifted in CURL_H_GENERATED_DESPITE_EXCLUSION {
        if let Some(owner) = sibling_owner_of(lifted) {
            return Err(format!(
                "{lifted}'s cbindgen.toml exclusion is lifted for the curl.h \
                 pass, but {owner} claims it. Lifting it would declare it in \
                 both headers."
            )
            .into());
        }
        if CURL_H_VERBATIM_NAMES.contains(lifted) {
            return Err(format!(
                "{lifted}'s exclusion is lifted so cbindgen generates it, \
                 yet curl.h also suppresses it as verbatim. Pick one."
            )
            .into());
        }
    }

    // The two curl.h verbatim blocks must not declare the same name twice,
    // and neither may be empty: an empty `after_includes` would make
    // cbindgen skip the section entirely (measured: with `no_includes = true`
    // the include block early-returns unless `after_includes` is `Some`),
    // and an empty trailer prefix would silently drop 19 declarations.
    if CURL_H_FORWARD.trim().is_empty() || CURL_H_VERBATIM.trim().is_empty() {
        return Err("curl.h's verbatim blocks must not be empty".into());
    }
    for name in CURL_H_VERBATIM_NAMES {
        let tag_struct = format!("struct {name} {{");
        let tag_enum = format!("enum {name} {{");
        // The third shape a verbatim name can take: a function-pointer
        // typedef, spelled `typedef R (*name)(args);`. curl_sshkeycallback is
        // the only one, and without this arm the check below would report it
        // as absent even though it is present -- a false failure that would
        // have been read as a real one.
        let tag_fnptr = format!("(*{name})");
        // And a fourth: a plain function typedef, `typedef R name(args);`.
        // curl_ssls_export_cb is the only one. Anchored with a leading space
        // so a longer name ending in this one cannot match.
        let tag_fn = format!(" {name}(");
        let defines = |block: &str| {
            block.contains(&tag_struct)
                || block.contains(&tag_enum)
                || block.contains(&tag_fnptr)
                || block.contains(&tag_fn)
        };
        let in_forward = defines(CURL_H_FORWARD);
        let in_verbatim = defines(CURL_H_VERBATIM);
        if in_forward && in_verbatim {
            return Err(format!(
                "{name} is defined in both of curl.h's verbatim blocks; it \
                 would be declared twice."
            )
            .into());
        }
        if !in_forward && !in_verbatim {
            return Err(format!(
                "{name} is suppressed as verbatim but neither curl.h verbatim \
                 block defines it, so it would be absent from the ABI."
            )
            .into());
        }
    }

    // Every generated header must have a distinct file name and a guard
    // derived from it, and none may name a header we must not write.
    for spec in SIBLING_HEADERS.iter() {
        guard_write_target(Path::new(spec.file));
        let expected = format!(
            "CURLINC_{}_H",
            spec.file.trim_end_matches(".h").to_uppercase()
        );
        if spec.guard != expected {
            return Err(format!(
                "include guard for {} is {}, expected {}",
                spec.file, spec.guard, expected
            )
            .into());
        }
    }

    // No capability may be both advertised and withheld. This is the check
    // that stops `Debug` or `OpenSSL` reappearing through a careless edit.
    let advertised = advertised_features()?;
    for token in advertised.split_whitespace() {
        if let Some((name, reason)) = WITHHELD.iter().find(|(t, _)| *t == token)
        {
            return Err(format!(
                "{name} is advertised by the engine feature table but is \
                 withheld because {reason}. One of the two is wrong; the \
                 engine's table is the authority, so fix whichever states \
                 the capability incorrectly."
            )
            .into());
        }
    }

    // Two tokens must never appear, for reasons that outlive any single row.
    //
    // `TrackMemory` is not a curl feature token at all: the harness DERIVES it
    // from `/Debug/i`, so emitting it standalone would advertise a vocabulary
    // curl does not have. Both were emitted by the previous hand-maintained
    // table; asserting their absence keeps them from returning.
    for forbidden in ["Debug", "TrackMemory"] {
        if advertised.split_whitespace().any(|t| t == forbidden) {
            return Err(format!(
                "{forbidden} must never appear in generated metadata \
                 (specification 0.6.6); the harness derives TrackMemory from \
                 /Debug/i and gates all memory checking on it"
            )
            .into());
        }
    }

    // Every arm of the static-metadata probe decision, asserted directly.
    //
    // Two of the three are unreachable in a default build -- no row of the
    // engine's table currently resolves to `Constant(false)` or reaches a
    // `Dynamic` probe with its gate holding -- so nothing would notice if an
    // arm were inverted. That is exactly how the `Dynamic` arm came to discard
    // the compile-time GSS fact: the code path had no witness. It has one now.
    for (probe, permitted, why) in [
        (
            Probe::Absent,
            true,
            "C's NULL is present whenever compiled in",
        ),
        (
            Probe::Constant(true),
            true,
            "a probe fixed true for this build has the same static answer",
        ),
        (
            Probe::Constant(false),
            false,
            "the engine withholds it at run time, so metadata claiming it \
             would describe a different product",
        ),
        (
            Probe::Dynamic("gss_present".to_string()),
            true,
            "curl-config --features and libcurl.pc report what the build was \
             built to do; C answers the same question from HAVE_GSSAPI at \
             configure time (configure.ac:5175-5200) and never re-examines \
             the host",
        ),
    ] {
        if probe_permits_static_metadata(&probe) != permitted {
            return Err(format!(
                "probe_permits_static_metadata({probe:?}) must be \
                 {permitted}: {why}"
            )
            .into());
        }
    }

    // The three GSS tokens are advertised exactly when their gate holds, and
    // never on the strength of the probe alone. Asserted as an equivalence in
    // both directions so that neither the previous defect (compile-time fact
    // discarded) nor its opposite (token emitted with the feature off) can
    // pass.
    {
        let advertised_now = advertised_features()?;
        for row in runtime_feature_rows()? {
            if !["GSS-API", "SPNEGO", "Kerberos"].contains(&row.token.as_str())
            {
                continue;
            }
            let gate = gate_holds(&row.gate)?;
            let named =
                advertised_now.split_whitespace().any(|t| t == row.token);
            if gate != named {
                return Err(format!(
                    "{} is {} static metadata while its compile-time gate is \
                     {gate}. The two must agree: the gate is the whole of the \
                     question these files answer, and the runtime probe \
                     belongs to the live banner alone.",
                    row.token,
                    if named { "named in" } else { "absent from" }
                )
                .into());
            }
        }
    }

    // The target-compiler table describes the four mandated targets and
    // invents nothing.
    //
    // The row that matters most is the one that cannot be observed on a Linux
    // runner: an Apple entry derived as `<triple>-gcc` names a driver that has
    // never existed, and `curl-config --cc` is consumed by a consumer that
    // will run it. So the shape is asserted rather than trusted.
    {
        let mandated = [
            "x86_64-unknown-linux-gnu",
            "aarch64-unknown-linux-gnu",
            "x86_64-apple-darwin",
            "aarch64-apple-darwin",
        ];
        for triple in mandated {
            let command = target_compiler(triple).ok_or_else(|| {
                format!(
                    "{triple} is mandated by specification 0.8.3 but has no \
                     TARGET_COMPILERS row, so curl-config --cc would have to \
                     invent one"
                )
            })?;
            if command.trim().is_empty() {
                return Err(format!(
                    "{triple}'s compiler command is empty; a consumer \
                     substituting it would run its next argument as a program"
                )
                .into());
            }
            if command.starts_with(triple) {
                return Err(format!(
                    "{triple}'s compiler command {command:?} is derived from \
                     the Rust triple. That is the defect this table replaces: \
                     GNU drops the vendor field and Apple has no \
                     triple-prefixed driver at all."
                )
                .into());
            }
        }
        for (triple, _) in TARGET_COMPILERS {
            if !mandated.contains(&triple) {
                return Err(format!(
                    "TARGET_COMPILERS carries {triple}, which is outside the \
                     four targets specification 0.8.3 mandates"
                )
                .into());
            }
        }
    }

    // The option-table facts have to agree with each other. Prose cannot be
    // checked; arithmetic can.
    if OPTION_TABLE_REAL_ROWS + 1 != OPTION_TABLE_ROWS {
        return Err("option table row arithmetic is inconsistent".into());
    }
    if OPTION_TABLE_ALIAS_ROWS >= OPTION_TABLE_REAL_ROWS {
        return Err("alias rows cannot outnumber real option rows".into());
    }
    if OPTION_TABLE_TRUE_OPTIONS != 308 {
        return Err(format!(
            "the metadata table describes {OPTION_TABLE_TRUE_OPTIONS} \
             preferred options; curl 8.19.0-DEV has 308 (291 CURLOPT plus 17 \
             CURLOPTDEPRECATED). ffi/opts.rs and this table disagree."
        )
        .into());
    }
    // The generator's own guard is `(CURLOPT_LASTENTRY % 10000) != (328 + 1)`,
    // so the sentinel's ordinal must be one past the last real option's.
    if OPTION_LASTENTRY_INDEX + 1 != 329 {
        return Err("CURLOPT_LASTENTRY's ordinal must be 329".into());
    }

    // The verbatim alias blocks must be intact. A truncated block still
    // produces a header that compiles, so nothing downstream would notice:
    // the aliases simply stop existing, and only an application still using a
    // retired spelling would find out. Counting them here is what turns that
    // silent loss into a build failure.
    {
        let defines = CURL_H_OLDIES
            .lines()
            .filter(|line| line.starts_with("#define "))
            .count();
        let option_aliases = CURL_H_OLDIES
            .lines()
            .filter(|line| line.starts_with("#define CURLOPT_"))
            .count();
        let code_aliases = CURL_H_OLDIES
            .lines()
            .filter(|line| line.starts_with("#define CURLE_"))
            .count();
        if defines != 59 || option_aliases != 19 || code_aliases != 40 {
            return Err(format!(
                "curl.h's alias blocks hold {defines} defines \
                 ({option_aliases} CURLOPT_, {code_aliases} CURLE_); \
                 curl 8.19.0-DEV has 59 (19 and 40)."
            )
            .into());
        }
        // Guards have to balance, or the `#ifndef` would swallow the rest of
        // the header. Two guarded regions, one of which has an `#else`.
        let opens = CURL_H_OLDIES.matches("#ifndef CURL_NO_OLDIES").count();
        let closes = CURL_H_OLDIES
            .lines()
            .filter(|line| line.starts_with("#endif"))
            .count();
        let alternates = CURL_H_OLDIES
            .lines()
            .filter(|line| line.trim_end() == "#else")
            .count();
        if opens != 2 || closes != 2 || alternates != 1 {
            return Err(format!(
                "curl.h's alias blocks have {opens} CURL_NO_OLDIES guards, \
                 {closes} #endif and {alternates} #else; expected 2, 2 and 1."
            )
            .into());
        }
        if !CURL_H_OLDIES.contains("#undef CURLOPT_DNS_USE_GLOBAL_CACHE") {
            return Err("the CURL_NO_OLDIES #else branch must still \
                        #undef CURLOPT_DNS_USE_GLOBAL_CACHE"
                .into());
        }
    }
    if OPTION_LASTENTRY_INDEX < OPTION_TABLE_REAL_ROWS {
        return Err(format!(
            "CURLOPT_LASTENTRY index {OPTION_LASTENTRY_INDEX} is below the \
             {OPTION_TABLE_REAL_ROWS} real option rows"
        )
        .into());
    }

    // The per-header function partition has to account for every exported
    // symbol exactly once. 100 symbols, 42 of them verbatim, so the eight
    // partitions must contribute 58 function names between them. Counting
    // them directly would require distinguishing functions from types, so
    // the weaker but still useful invariant is asserted: the partition
    // cannot contain more names than the header set can possibly declare.
    let partitioned: usize = PARTITIONS.iter().map(|(_, v)| v.len()).sum();
    let generated_functions = EXPORTED_SYMBOLS - VERBATIM_FUNCTIONS;
    if partitioned < generated_functions {
        return Err(format!(
            "the header partition names {partitioned} items, fewer than the \
             {generated_functions} functions that must be generated \
             ({EXPORTED_SYMBOLS} exported minus {VERBATIM_FUNCTIONS} \
             carried verbatim), so at least one is unassigned and would be \
             suppressed in every pass"
        )
        .into());
    }

    self_check_variadic_inventory()?;
    self_check_substitution_encoders()?;

    Ok(())
}

/// Exercise the two encoders and the two validators on adversarial input.
fn self_check_substitution_encoders() -> Result<(), Box<dyn Error>> {
    // The shell encoder. The payload is the one that demonstrably executed
    // `id -u` when substituted raw into `echo '...'`.
    let cases = [
        ("/opt/curl", "/opt/curl"),
        ("/opt/my curl", "/opt/my curl"),
        // Inert inside single quotes, so deliberately NOT touched. Encoding
        // them would corrupt a legitimate path.
        ("/opt/a#b", "/opt/a#b"),
        ("/opt/$(id -u)", "/opt/$(id -u)"),
        ("/opt/a\\b", "/opt/a\\b"),
        ("/opt/a\"b", "/opt/a\"b"),
        // The one character that is special, and the injection it enables.
        ("/opt/a'b", "/opt/a'\\''b"),
        ("x'; id -u; echo 'y", "x'\\''; id -u; echo '\\''y"),
    ];
    for (input, expected) in cases {
        let got = shell_single_quoted_body(input);
        if got != expected {
            return Err(format!(
                "the shell encoder turned {input:?} into {got:?}, expected \
                 {expected:?}"
            )
            .into());
        }
    }

    // The pkg-config encoder: five characters refused, everything else
    // returned unchanged. `#` is refused rather than escaped, which is a
    // change from the first form of this check and was decided by
    // measurement against pkgconf 1.8.1: `prefix=/opt/a\#b` does round-trip
    // through `pkg-config --variable=prefix` (`/opt/a#b`), but
    // `pkg-config --cflags` then emits `-I/opt/a\#b/include` with the
    // backslash intact, so a consumer that does not pass the flags through a
    // shell gets a different include path. An escape that is correct for one
    // query and wrong for another is not an escape.
    if pkg_config_variable_body("probe", "/opt/a#b").is_ok() {
        return Err(
            "the pkg-config encoder must refuse #, not escape it".into()
        );
    }
    if pkg_config_variable_body("probe", "/opt/my curl")? != "/opt/my curl" {
        return Err("the pkg-config encoder must leave a space alone".into());
    }
    for refused in [
        "/opt/${libdir}",
        "/opt/$x",
        "/opt/a'b",
        "/opt/a\"b",
        "/opt/a`b",
    ] {
        if pkg_config_variable_body("probe", refused).is_ok() {
            return Err(format!(
                "the pkg-config encoder accepted {refused:?}, which pkg-config \
                 either interpolates or silently fails on"
            )
            .into());
        }
    }

    // Control characters, including the NUL that nothing else can reach.
    for refused in ["a\0b", "a\nb", "a\rb", "a\tb", "a\x1bb", "a\x7fb"] {
        if reject_control_characters("probe", refused).is_ok() {
            return Err(format!(
                "a control character in {refused:?} was accepted; a newline \
                 forges a pkg-config key and a line of shell, and a NUL \
                 truncates the value in every C consumer"
            )
            .into());
        }
    }
    for accepted in [
        "/opt/curl",
        "/opt/my curl",
        "/opt/a#b",
        "/opt/\u{e9}t\u{e9}",
    ] {
        reject_control_characters("probe", accepted)?;
    }

    // The unquoted arms.
    reject_unquoted_shell_metacharacters(
        "probe",
        "--target=x86_64-unknown-linux-gnu --features=ftp,http2",
    )?;
    for refused in [
        "a;b", "a$b", "a`b", "a*b", "a'b", "a\"b", "a|b", "a&b", "a(b",
    ] {
        if reject_unquoted_shell_metacharacters("probe", refused).is_ok() {
            return Err(format!(
                "{refused:?} was accepted for an arm the shell word-splits and \
                 glob-expands"
            )
            .into());
        }
    }

    Ok(())
}

/// Assert that the variadic partition matches the headers this script writes.
///
/// The A4 gate is only as good as the two lists it reasons about, and both are
/// hand-written, so both can drift. Three things are checked, and each has
/// already been a live trap rather than a hypothetical one:
///
/// 1. **Disjoint lists.** If a name appeared in both lists, the same symbol would
///    be described as solved and as unimplementable at once, and whichever
///    message was read first would be believed.
/// 2. **Counts.** The refusal text says "the eleven" and "the four" in prose,
///    and the accept-path warning reports
///    `VARIADIC_UNIMPLEMENTABLE.len()`. A count that drifted from the array
///    would make the diagnostic lie about its own subject.
/// 3. **Presence in the verbatim header text.** Every one of the fifteen must
///    actually be declared by a header this script emits. This is the check
///    that catches a typo -- a misspelt entry would simply never match any
///    target, and the gate would look satisfied while protecting nothing. It
///    also catches the reverse drift: renaming a prototype in the verbatim
///    text without updating these lists.
///
/// The prototypes live across four verbatim constants rather than one, because
/// the C headers put them there: the ten `curl_m*printf` forms in `mprintf.h`,
/// `curl_easy_setopt` and `curl_easy_getinfo` in `easy.h`, `curl_multi_setopt`
/// in `multi.h`, and `curl_formadd` and `curl_share_setopt` in `curl.h`. All
/// four are searched together, since which header declares a symbol is
/// irrelevant to whether the symbol exists.
fn self_check_variadic_inventory() -> Result<(), Box<dyn Error>> {
    if VARIADIC_UNIMPLEMENTABLE.len() != 11 {
        return Err(format!(
            "VARIADIC_UNIMPLEMENTABLE holds {} names, but the A4 diagnostics \
             and specification 0.8.6 both say eleven",
            VARIADIC_UNIMPLEMENTABLE.len()
        )
        .into());
    }
    if VARIADIC_TRAILING_POINTER.len() != 4 {
        return Err(format!(
            "VARIADIC_TRAILING_POINTER holds {} names, but the four \
             option-identifier functions are exactly the set that \
             include/curl/curl.h defines three-argument enforcement macros \
             for",
            VARIADIC_TRAILING_POINTER.len()
        )
        .into());
    }

    for solved in VARIADIC_TRAILING_POINTER {
        if VARIADIC_UNIMPLEMENTABLE.contains(&solved) {
            return Err(format!(
                "{solved} is listed both as solved by the trailing-pointer \
                 design and as having no ABI-correct expression. The two \
                 lists must be disjoint, or the A4 gate describes the same \
                 symbol two contradictory ways."
            )
            .into());
        }
    }

    // Only the verbatim text is searched.
    let declared =
        [MPRINTF_H_DECLS, EASY_H_POST, MULTI_H_POST, CURL_H_VERBATIM].concat();

    for name in VARIADIC_UNIMPLEMENTABLE
        .iter()
        .chain(VARIADIC_TRAILING_POINTER.iter())
    {
        // Match the name followed by its opening parenthesis, so that a
        // mention inside a comment -- `curl_formadd()` appears in three of
        // them -- cannot stand in for a prototype. Both spellings occur in the
        // real text: `curl_mprintf(const char *format, ...)` on one line, and
        // `curl_formadd(struct curl_httppost **httppost,` after a
        // CURL_DEPRECATED attribute broke the line.
        if !declared.contains(&format!("{name}(")[..]) {
            return Err(format!(
                "{name} is named by the A4 variadic inventory but is not \
                 declared anywhere in the verbatim header text. Either it is \
                 misspelt -- in which case the gate that cites it protects \
                 nothing -- or a prototype was renamed without updating the \
                 inventory."
            )
            .into());
        }
    }

    Ok(())
}

/// Check the measured option-table facts against the canonical Rust data.
///
/// # What a failure means
///
/// Either a row was added to or removed from `opts.rs` without re-running the
/// C generator to confirm curl agrees, or the constants above were edited
/// without the table. Both are drift, and the build stops rather than
/// rendering a `curl_easyoption` projection that disagrees with curl
/// 8.19.0-DEV about how many options exist.
fn option_table_ground_truth(manifest: &Path) -> Result<(), Box<dyn Error>> {
    let path = manifest.join("src").join("ffi").join("opts.rs");
    let text = fs::read_to_string(&path).map_err(|e| {
        format!(
            "the option metadata authority {} could not be read: {e}",
            path.display()
        )
    })?;

    // Comments first. Row constructions appear inside doc comments and inside
    // the explanatory text above the table, and counting those would inflate
    // every total.
    let source = strip_rust_comments(&text);

    // Bound the scan to the array initialiser. `EasyOptionRow` also appears in
    // the struct definition, in `impl` blocks, in the const counters and in
    // the test module.
    const OPEN: &str = "pub(crate) const EASY_OPTIONS: &[EasyOptionRow] = &[";
    let start = source.find(OPEN).ok_or_else(|| {
        format!(
            "{} no longer declares `{OPEN}`, so the option metadata array \
             cannot be located. That declaration is the authority this build \
             checks its measured counts against; if it was renamed, this \
             function has to be updated in the same commit.",
            path.display()
        )
    })?;
    let body_start = start + OPEN.len();
    let body_len = source[body_start..].find("\n];").ok_or_else(|| {
        format!(
            "the EASY_OPTIONS array in {} is not terminated by a line \
             beginning `];`, so its extent cannot be determined",
            path.display()
        )
    })?;
    let body = &source[body_start..body_start + body_len];

    let rows = body.matches("EasyOptionRow {").count();
    let aliases = body.matches("CURLOT_FLAG_ALIAS").count();
    let sentinels = body.matches("name: None").count();

    // Shape before counts: a body that parses as something other than a flat
    // list of row constructions would make all three numbers meaningless, and
    // a meaningless number that happens to match is worse than a mismatch.
    let ids = body.matches("id: CURLoption::CURLOPT_").count();
    if ids != rows {
        return Err(format!(
            "the EASY_OPTIONS array in {} holds {rows} `EasyOptionRow {{` \
             constructions but {ids} `id: CURLoption::CURLOPT_` fields, so it \
             is not the flat one-construction-per-row literal this check \
             assumes and the counts below cannot be trusted",
            path.display()
        )
        .into());
    }

    if rows != OPTION_TABLE_ROWS {
        return Err(format!(
            "option table drift: {} holds {rows} rows, but \
             `perl lib/optiontable.pl < include/curl/curl.h` emits \
             {OPTION_TABLE_ROWS} including the sentinel. Re-run the generator \
             and reconcile; do not simply edit one of the two numbers.",
            path.display()
        )
        .into());
    }
    if sentinels != 1 {
        return Err(format!(
            "option table drift: {} holds {sentinels} NULL-name sentinel \
             rows; the C generator emits exactly one, and \
             `curl_easy_option_next` stops at the first, so a second would \
             silently truncate the walk",
            path.display()
        )
        .into());
    }
    if aliases != OPTION_TABLE_ALIAS_ROWS {
        return Err(format!(
            "option table drift: {} flags {aliases} rows CURLOT_FLAG_ALIAS, \
             but the C generator emits {OPTION_TABLE_ALIAS_ROWS} (17 true \
             `#define CURLOPT_` aliases in curl.h, less the two pointing at \
             an obsolete option, which the generator skips)",
            path.display()
        )
        .into());
    }
    let true_options = rows - sentinels - aliases;
    if true_options != OPTION_TABLE_TRUE_OPTIONS {
        return Err(format!(
            "option table drift: {} describes {true_options} preferred \
             options; curl 8.19.0-DEV has {OPTION_TABLE_TRUE_OPTIONS}",
            path.display()
        )
        .into());
    }

    // The counts agree. The last thing to confirm is that they agree for the
    // right reason: `opts.rs` must still DERIVE its own four constants from
    // the table and pin them with `const` assertions. Deleting either half
    // would leave the numbers correct today and unprotected tomorrow, and it
    // is the one regression this text-level check cannot otherwise see.
    for required in [
        "pub(crate) const EASY_OPTION_ROWS: usize = EASY_OPTIONS.len();",
        "count_alias_rows(EASY_OPTIONS)",
        "count_sentinel_rows(EASY_OPTIONS)",
    ] {
        if !source.contains(required) {
            return Err(format!(
                "{} no longer derives its row counts from the table: \
                 `{required}` is absent. The counts must be computed from \
                 EASY_OPTIONS, not transcribed beside it -- a transcribed \
                 literal is what this build previously carried, and it was \
                 wrong.",
                path.display()
            )
            .into());
        }
    }
    let pins = source.matches("const _: () = assert!(").count();
    if pins < 4 {
        return Err(format!(
            "{} carries {pins} `const _: () = assert!(` oracle pins; four are \
             required, one each for the row, sentinel, alias and \
             preferred-option counts measured from lib/optiontable.pl. \
             Derivation alone lets the table and its counts drift away from \
             curl together.",
            path.display()
        )
        .into());
    }

    Ok(())
}

/// Every symbol name `lib/libcurl.def` exports.
///
/// `EXPORTS` on line 1, then one bare name per line.
fn exported_symbols(root: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let path = root.join("lib").join("libcurl.def");
    let text = fs::read_to_string(&path).map_err(|e| {
        format!(
            "cannot read the export authority {}: {e}. The 100-symbol parity \
             requirement of AAP 0.1.1 is derived from this file.",
            path.display()
        )
    })?;

    let mut names = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with(';')
            || trimmed.eq_ignore_ascii_case("EXPORTS")
        {
            continue;
        }
        // A .def entry may carry decoration after the name; take the name.
        let end = trimmed
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(trimmed.len());
        let name = &trimmed[..end];
        if !name.is_empty() {
            names.push(name.to_string());
        }
    }

    Ok(names)
}

/// C text with block comments, line comments and string literals removed.
///
/// Necessary rather than fastidious. Searching the verbatim text for a
/// prototype without this step matches inside a deprecation notice:
/// `CURL_DEPRECATED(7.19.5, "Use curl_multi_socket_action()")` reports
/// `curl_multi_socket_action` as declared and, because the real
/// `curl_multi_socket` prototype is on the same logical line, hides it. That
/// measurement cost a wrong answer once already, and it is recorded here so
/// the next reader does not repeat it.
fn strip_c_noise(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;

    while i < bytes.len() {
        let two = bytes.get(i..i + 2);
        if two == Some(b"/*") {
            i += 2;
            while i < bytes.len() && bytes.get(i..i + 2) != Some(b"*/") {
                if bytes[i] == b'\n' {
                    out.push('\n');
                }
                i += 1;
            }
            i = (i + 2).min(bytes.len());
            out.push(' ');
            continue;
        }
        if two == Some(b"//") {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if bytes[i] == b'"' {
            i += 1;
            while i < bytes.len() && bytes[i] != b'"' {
                // A backslash escapes the next byte, quote included.
                if bytes[i] == b'\\' {
                    i += 1;
                }
                i += 1;
            }
            i = (i + 1).min(bytes.len());
            out.push(' ');
            continue;
        }
        out.push(bytes[i] as char);
        i += 1;
    }

    out
}

/// Every name a block of verbatim C DECLARES as taking arguments.
///
/// WHY THIS IS DIRECTIVE-AWARE, measured rather than anticipated. A first
/// version simply searched for `name(` in the comment-stripped and
/// literal-stripped text, and it reported `curl_multi_socket_action` as both
/// generated and verbatim. The cause is that `multi.h` carries
///
/// ```c
/// #define curl_multi_socket(x,y,z) curl_multi_socket_action(x,y,0,z)
/// ```
fn verbatim_callables(text: &str) -> Vec<String> {
    let clean = strip_c_noise(text);
    let mut names = Vec::new();
    let mut in_directive = false;

    for line in clean.lines() {
        let trimmed = line.trim();
        let opens_directive = trimmed.starts_with('#');

        if opens_directive || in_directive {
            if opens_directive {
                if let Some(rest) = trimmed.strip_prefix("#define ") {
                    let rest = rest.trim_start();
                    let end = rest
                        .find(|c: char| {
                            !(c.is_ascii_alphanumeric() || c == '_')
                        })
                        .unwrap_or(rest.len());
                    // Only a function-like macro declares a callable; an
                    // object-like one defines a constant.
                    if end > 0 && rest[end..].starts_with('(') {
                        names.push(rest[..end].to_string());
                    }
                }
            }
            in_directive = trimmed.ends_with('\\');
            continue;
        }

        names.extend(callables_on(line));
    }

    names
}

/// Identifiers immediately followed by `(` on one ordinary line of C.
fn callables_on(line: &str) -> Vec<String> {
    let bytes = line.as_bytes();
    let mut names = Vec::new();
    let mut start: Option<usize> = None;

    for (index, byte) in bytes.iter().enumerate() {
        let is_ident = byte.is_ascii_alphanumeric() || *byte == b'_';
        if is_ident {
            if start.is_none() {
                start = Some(index);
            }
            continue;
        }
        if let Some(from) = start.take() {
            if *byte == b'(' {
                names.push(line[from..index].to_string());
            }
        }
    }

    names
}

/// Assert that every exported symbol is accounted for exactly once.
///
/// Exact export coverage is required from the `.def` file,
/// and this replaces the inequality `run_self_checks` could offer without
/// reading it. Each of the 100 names must be either claimed by a header
/// partition, and therefore generated, or present as a verbatim prototype,
/// and therefore hand-written -- never both and never neither.
///
/// Measured today, and CHECKED rather than dated -- `check_export_coverage`
/// below fails the build if either figure moves: 58 claimed, 42 verbatim,
/// disjoint, union 100 of 100, nothing unaccounted. These two describe how each
/// of the 100 DECLARATIONS reaches the header, and say nothing about how many
/// symbols the crate currently defines; that is
/// [`undefined_abi_exports`]'s figure, and confusing the two has misled a
/// review once. The 42 are the four C-variadic setters, the five
/// deprecated prototypes, the ten `curl_m*printf` functions, the twelve
/// whose frozen signature names a type this crate's Rust spelling cannot ask
/// cbindgen to produce (cbindgen.toml, "Group 5e"), the two `urlapi.h`
/// declares with a `CURLUPart` parameter, the two `header.h` declares, the
/// three remaining `urlapi.h` constructors and the four `websockets.h`
/// declares between its three interleaved constant blocks, which matches
/// [`VERBATIM_FUNCTIONS`] exactly.
fn check_export_coverage(root: &Path) -> Result<(), Box<dyn Error>> {
    let symbols = exported_symbols(root)?;

    if symbols.len() != EXPORTED_SYMBOLS {
        return Err(format!(
            "lib/libcurl.def lists {} symbols, and this script is written \
             against {EXPORTED_SYMBOLS}. Every partition count depends on \
             that number, so reconcile them rather than adjusting one.",
            symbols.len()
        )
        .into());
    }

    let claimed = all_partition_items();
    let carriers: Vec<String> = VERBATIM_CARRIERS
        .iter()
        .flat_map(|(_, blocks)| blocks.iter())
        .flat_map(|block| verbatim_callables(block))
        .collect();

    let mut verbatim = 0usize;
    let mut generated = 0usize;
    let mut both: Vec<&str> = Vec::new();
    let mut neither: Vec<&str> = Vec::new();

    for symbol in &symbols {
        let is_claimed = claimed.iter().any(|item| item == symbol);
        let is_verbatim = carriers.iter().any(|c| c == symbol);

        match (is_claimed, is_verbatim) {
            (true, true) => both.push(symbol),
            (true, false) => generated += 1,
            (false, true) => verbatim += 1,
            (false, false) => neither.push(symbol),
        }
    }

    if !both.is_empty() {
        return Err(format!(
            "{} exported symbol(s) are both claimed by a header partition and \
             written verbatim: {}. Each would be declared twice, and the \
             partition entry is a lie either way.",
            both.len(),
            both.join(", ")
        )
        .into());
    }

    if !neither.is_empty() {
        return Err(format!(
            "{} of the {EXPORTED_SYMBOLS} symbols in lib/libcurl.def are \
             neither claimed by a header partition nor written verbatim, so \
             the generated headers would not declare them at all: {}. A \
             consumer calling one would compile against an implicit \
             declaration and link against nothing.",
            neither.len(),
            neither.join(", ")
        )
        .into());
    }

    if verbatim != VERBATIM_FUNCTIONS {
        return Err(format!(
            "{verbatim} exported symbols are carried verbatim, and \
             VERBATIM_FUNCTIONS says {VERBATIM_FUNCTIONS}. The two are used \
             together to derive how many functions the partition must \
             generate, so a disagreement makes that derivation wrong."
        )
        .into());
    }

    let expected_generated = EXPORTED_SYMBOLS - VERBATIM_FUNCTIONS;
    if generated != expected_generated {
        return Err(format!(
            "{generated} exported symbols are claimed by a header partition, \
             and {expected_generated} are required \
             ({EXPORTED_SYMBOLS} exported minus {VERBATIM_FUNCTIONS} \
             verbatim)."
        )
        .into());
    }

    Ok(())
}

// Cargo directives

/// Declare every input this script reads.
///
/// EMITTING EVEN ONE `rerun-if-changed` DISABLES CARGO'S DEFAULT BEHAVIOUR
/// OF RE-RUNNING WHEN ANYTHING IN THE PACKAGE CHANGES. The list must
/// therefore be complete, or an edit will be silently ignored and the tree
/// will hold a stale header while the source says otherwise. Every path
/// below corresponds to something this file actually reads; adding a read
/// without adding a line here is a defect.
fn emit_rerun_directives(manifest: &Path) -> Result<(), Box<dyn Error>> {
    // The single cbindgen configuration, loaded by generate_headers.
    println!("cargo:rerun-if-changed=cbindgen.toml");
    // This script itself.
    println!("cargo:rerun-if-changed=build.rs");
    // cbindgen parses the whole crate, so any change to a symbol module,
    // to opts.rs, to codes.rs or to handle.rs changes the output. Naming
    // the directory rather than individual files is what makes a newly
    // added module count too: Cargo walks a directory target recursively.
    println!("cargo:rerun-if-changed=src");
    // The two templates rendered below.
    println!("cargo:rerun-if-changed=../curl-config.in");
    println!("cargo:rerun-if-changed=../libcurl.pc.in");
    // The provenance of the version facts. This header is one of the four
    // that must never be WRITTEN; reading it is a different matter and is
    // exactly what configure.ac:129 and :141 do.
    println!("cargo:rerun-if-changed=../include/curl/curlver.h");
    // The soname authority. Nothing is parsed out of it -- the derivation
    // is recorded in SONAME_MAJOR -- but a change to VERSIONCHANGE or
    // VERSIONDEL must force a rebuild so the mismatch is noticed.
    println!("cargo:rerun-if-changed=../lib/Makefile.soname");
    // The export authority, PARSED by check_export_coverage: every one of
    // the 100 names must be either generated or carried verbatim. Adding a
    // symbol here without assigning it to a partition has to fail the next
    // build rather than the next release, which it cannot do unless the file
    // is watched.
    println!("cargo:rerun-if-changed=../lib/libcurl.def");
    // The capability authority, PARSED by runtime_feature_rows and
    // runtime_protocol_rows. The advertised feature and protocol sets in
    // curl-config and libcurl.pc are DERIVED from this file's two tables
    // rather than mirrored beside them, so adding a row, flipping a
    // `compiled_in:` gate or changing a `present:` probe must regenerate the
    // metadata. Without this directive the derivation would go stale and
    // reintroduce exactly the drift it was built to remove. Watched under the
    // same rule as every other real authority.
    println!("cargo:rerun-if-changed={ENGINE_VERSION_RS}");
    // The manifests. Both influence the generated contracts and neither was
    // watched before. This crate's own manifest carries the feature
    // forwarding that decides which capabilities the ABI reports, and
    // `version` feeds the banner; the workspace manifest is where every
    // dependency version and the MSRV are pinned, and cbindgen's
    // `Cargo::load` reads the manifest and the lock file while resolving the
    // crate it parses.
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=../Cargo.toml");
    println!("cargo:rerun-if-changed=../Cargo.lock");
    // The cross-toolchain authority, PARSED by
    // check_cross_toolchain_agreement. It names the aarch64 Linux `linker`,
    // and `curl-config --cc` must report the same command for that triple, so
    // renaming the linker there has to fail this build rather than silently
    // leave the two ends of one toolchain disagreeing.
    println!("cargo:rerun-if-changed=../.cargo/config.toml");

    for key in tracked_env_keys() {
        println!("cargo:rerun-if-env-changed={key}");
    }

    // cbindgen.toml is an AUTHORITY, not a convenience, so its absence is
    // FATAL rather than a warning.
    //
    // It fails OPEN, which is the exact defect class this guard
    // names: a missing authority item has to stop the build, because the
    // thing this file is missing is not decoration. cbindgen.toml carries the
    // verbatim header prologue that pins `typedef void CURL;`,
    // `typedef void CURLSH;`, `typedef void CURLM;`,
    // `typedef struct Curl_URL CURLU;` and `typedef struct CURLMsg CURLMsg;`
    // exactly as the frozen headers spell them. Without
    // it cbindgen emits `typedef struct CURL CURL;` for the first three, which
    // changes the type of every handle-passing call and breaks the widespread
    // idiom of assigning a `CURL *` to a `void *` -- silently, in the
    // consumer's build rather than in ours. It also carries the `[export]`
    // exclusions and the verbatim carriers that keep 35 prototypes and 53
    // `#define`s byte-identical to the authority. A build that proceeded
    // without it would either fail with a less obvious message or, worse,
    // succeed and promote headers that no longer match.
    let config = manifest.join("cbindgen.toml");
    if !config.is_file() {
        return Err(format!(
            "{} does not exist, so the public headers cannot be generated: \
             this file carries the verbatim prologue that pins the CURL, \
             CURLSH, CURLM, CURLU and CURLMsg typedefs, the [export] \
             exclusions, and the verbatim prototype and #define carriers",
            config.display()
        )
        .into());
    }

    Ok(())
}

/// Stamp the shared library's identity.
///
/// One directive, artifact-scoped, spelled for the target platform. See the
/// module documentation for the three measurements behind each of those
/// three words.
fn emit_link_args(manifest: &Path) -> Result<(), Box<dyn Error>> {
    // CARGO_CFG_TARGET_OS, never cfg!(target_os). A build script is
    // compiled for the host, so cfg! would describe the machine doing the
    // building and would silently emit a Linux flag when cross-compiling to
    // a Darwin target, or vice versa.
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    // CARGO_CFG_TARGET_ARCH is deliberately not read here any more. It existed
    // solely to gate the aarch64-apple-darwin variadic warning this function
    // used to emit; that hazard is now enforced twice over and in neither case
    // by printing. `check_variadic_strategy` is target-independent by design,
    // so a plain non-variadic definition of one of the four cannot be landed
    // from the platform least likely to be building; `check_variadic_abi`
    // refuses the affected target outright unless the A4 decision is on
    // record. A build script refuses by returning, not by printing.

    match os.as_str() {
        "linux" => {
            // Verified: readelf -d then reports
            // "Library soname: [libcurl.so.4]", on cargo 1.75.0 and 1.97.1
            // alike.
            println!(
                "cargo:rustc-link-arg-cdylib=-Wl,--soname={}",
                linux_soname()
            );

            // The six assembled labels rustc cannot see. ELF only, and only
            // here: see Trap 3 above for the measurement, and
            // MACH_O_EXPORT_GAP for why the Darwin arm has no counterpart.
            promote_assembled_exports(manifest)?;
        }
        "macos" => {
            // Verified rather than assumed. Built a cdylib for both
            // x86_64-apple-darwin and aarch64-apple-darwin and read the
            // load command back with llvm-objdump --macho --dylib-id: both
            // report @rpath/libcurl.4.dylib. GNU ld rejects this option
            // outright ("unrecognised option: -install_name", exit 1),
            // which is why the match arm exists at all.
            println!(
                "cargo:rustc-link-arg-cdylib=-Wl,-install_name,{}",
                apple_install_name()
            );

            // THE ASYMMETRY WITH THE LINUX ARM IS DELIBERATE, and this is the
            // only place a reader will look for it. The six `global_asm!`
            // labels the Linux arm promotes stay ABSENT from a Mach-O dylib's
            // export table, so Darwin's dynamic ceiling is six lower than
            // ELF's. ld64's mechanism is `-exported_symbols_list <file>`,
            // which SETS the export list rather than extending it, so handing
            // it the six would hide the fifty-three rustc put there -- a
            // strictly worse artifact. There is no additive spelling: the
            // per-symbol form builds the same single list, and a second list
            // replaces the first. Nothing is emitted here rather than
            // something being emitted that makes it worse.
        }
        other => {
            // Silence here would be the wrong answer twice over: the
            // artifact would ship with no soname, and nobody would know.
            let named = if other.is_empty() { "<unset>" } else { other };
            println!(
                "cargo:warning=no soname convention is known for target OS \
                 '{named}', so libcurl will be built without one. The four \
                 supported targets are x86_64/aarch64 on \
                 unknown-linux-gnu and apple-darwin."
            );
        }
    }

    // The aarch64-apple-darwin variadic hazard used to be escalated from here
    // with a `cargo:warning=`. It no longer is, for two measured reasons.
    //
    // And it was inaccurate. It asserted that "the C ABI shim's setopt and
    // getinfo entry points are non-variadic and read a register", but no such
    // definition exists in this crate: all four names are carried into the
    // generated headers as verbatim prototypes and none has a Rust body. The
    // warning therefore reported a defect that was not present, which is the
    // reporting equivalent of the over-advertisement specification 0.6.5 rules
    // out -- and, unlike a missing capability, a phantom one cannot be
    // discovered and dismissed cheaply by a reader.
    //
    // The hazard itself is real and is now handled where it can be handled
    // mechanically: `check_variadic_strategy` fails the build, on EVERY target,
    // if any of the four ever gains a plain non-variadic definition without the
    // `global_asm!` trampoline that relocates the argument. That function
    // carries the disassembly from both sides of the call and the proof that
    // the trampoline builds at the declared MSRV of 1.75 without a C compiler,
    // which is why the four have a remedy rather than only a hazard.
    //
    // A4 itself stays open, and stays escalated from `check_variadic_abi`
    // below. That is not a duplicate of the check just described: the
    // trampoline makes a definition of the four sound, while none of the four
    // has a Rust body to trampoline yet. Refusing a target and requiring a
    // trampoline answer different questions; both are kept, and only one of
    // them prints.
    //
    // One clause that used to sit in this paragraph has been removed because
    // measurement contradicted it. It read that "the eleven printf and va_list
    // exports have no ABI-correct expression at the declared minimum on ANY
    // target". Ten of the eleven now have one, in `src/ffi/printf.rs`: the five
    // `va_list` forms are ordinary Rust functions over a per-target `va_list`
    // walker, and the five plain-variadic forms are `global_asm!` spill
    // prologues that hand a synthesised `va_list` to their sibling. What remains
    // true of the eleventh, `curl_formadd`, is unchanged, and what remains open
    // about the ten is narrower and is stated where it belongs: the Apple
    // prologues are cross-assembled here but have never been executed.

    Ok(())
}

/// The directory holding the invoking toolchain's own `ld.lld`, if it has one.
///
/// `<sysroot>/lib/rustlib/<HOST>/bin/gcc-ld` is where rustup lays out the
/// `rust-lld` shims that `-fuse-ld=lld` finds through `-B`. Two details are
/// load-bearing:
///
/// * The triple is the **host**, not the target. LLD cross-links, so the host
///   copy serves the `aarch64-unknown-linux-gnu` leg -- measured, producing a
///   genuine `ELF 64-bit LSB shared object, ARM aarch64`. Reaching for a
///   target-triple directory would find nothing on any cross build.
/// * The sysroot is asked of `$RUSTC`, the compiler cargo is actually invoking,
///   rather than of whatever `rustc` is first on `PATH`. Those differ whenever
///   the build is `cargo +1.75.0`, and the 1.75.0 sysroot is exactly the one
///   whose LLD makes the MSRV row of the table above work.
///
/// `None` when the toolchain ships no LLD -- a distribution rustc, or a rustup
/// toolchain installed without the `rust-lld` component. Both pinned
/// toolchains, 1.97.1 from `rust-toolchain.toml` and the 1.75.0 MSRV floor,
/// were measured to have it.
fn lld_search_dir() -> Option<PathBuf> {
    let rustc = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let sysroot = Command::new(rustc)
        .args(["--print", "sysroot"])
        .output()
        .ok()
        .filter(|out| out.status.success())?;
    let sysroot = String::from_utf8(sysroot.stdout).ok()?;
    let host = env::var("HOST").ok()?;
    let dir = PathBuf::from(sysroot.trim())
        .join("lib")
        .join("rustlib")
        .join(host)
        .join("bin")
        .join("gcc-ld");
    if dir.join("ld.lld").is_file() {
        Some(dir)
    } else {
        None
    }
}

/// Whether this build is adding the `global_asm!` labels to the cdylib's
/// dynamic export table.
///
/// Exactly [`promote_assembled_exports`]'s own precondition, factored out so
/// that [`implemented_exports`] answers about the artifact this build produces
/// rather than about the one it would have produced without LLD. Both pinned
/// toolchains ship `ld.lld` in their own sysroot, so on this project's supported
/// configurations the answer is yes and the six labels are exported.
fn assembled_exports_are_promoted() -> bool {
    lld_search_dir().is_some()
}

/// Add the `global_asm!` labels to the cdylib's dynamic export table.
///
/// rustc builds a cdylib's export list from Rust items carrying `#[no_mangle]`
/// or `#[export_name]` and hands the linker `{ global: <those>; local: *; };`.
/// An assembled `.globl` label matches nothing in `global:`, falls to the
/// wildcard and is localised -- then, being unreferenced, discarded outright.
/// Six of the hundred exported symbols are such labels, because
/// `extern "C" fn f(x: T, ...)` is `error[E0658]` at the declared MSRV, so
/// without this the shared library can never exceed 94 however much else is
/// written. See Trap 3 above for the full measurement, including the routes
/// that do not work and why.
///
/// Three arguments are emitted, all `-cdylib` scoped so that neither
/// command-line binary nor any test binary sees them:
///
/// 1. `-B<dir>` so the `cc` driver can find the toolchain's linker shims.
/// 2. `-fuse-ld=lld`, because GNU ld refuses a second version script with
///    `anonymous version tag cannot be combined with other version tags` while
///    LLD merges the two additively.
/// 3. `-Wl,--version-script=<OUT_DIR>/assembled-exports.map`.
///
/// # Emitting nothing is a supported outcome
///
/// When no LLD is available the function emits nothing and says nothing. It
/// must not emit the version script alone: that is a hard link failure, so a
/// toolchain without LLD would stop building altogether rather than build the
/// artifact it built before. And it must not warn, because a warning would
/// break the zero-warning build gate for a condition neither pinned toolchain
/// can reach. The consequence is visible where it belongs -- the export census
/// this script prints, and the ABI parity gate -- rather than invented here.
///
/// The names are read out of the source on every build rather than listed, for
/// the same reason every other count in this file is derived: a literal list
/// would be a second source of truth and would go stale the first time a
/// seventh label was added or the sixth removed.
///
/// # Errors
///
/// If the source tree cannot be scanned, or `$OUT_DIR` cannot be written.
fn promote_assembled_exports(manifest: &Path) -> Result<(), Box<dyn Error>> {
    let names = assembled_export_names(manifest)?;
    if names.is_empty() {
        // Nothing to promote. Reached only if every trampoline becomes a Rust
        // item, which is the outcome this whole mechanism exists to survive.
        return Ok(());
    }

    let Some(dir) = lld_search_dir() else {
        return Ok(());
    };

    let out = PathBuf::from(env_var("OUT_DIR")?).join("assembled-exports.map");
    let mut script = String::from(
        "/* Generated by curl-rs-ffi/build.rs. The labels below are defined \
         with\n * global_asm! and are invisible to rustc's own export list, \
         which\n * localises them. Merged additively with that list by LLD. \
         */\n{\n  global:\n",
    );
    for name in &names {
        script.push_str("    ");
        script.push_str(name);
        script.push_str(";\n");
    }
    script.push_str("};\n");
    fs::write(&out, script)
        .map_err(|e| format!("cannot write {}: {e}", out.display()))?;

    println!("cargo:rustc-link-arg-cdylib=-B{}", dir.display());
    println!("cargo:rustc-link-arg-cdylib=-fuse-ld=lld");
    println!(
        "cargo:rustc-link-arg-cdylib=-Wl,--version-script={}",
        out.display()
    );

    Ok(())
}

// MEASURED FINDING, Trap 3: the six assembled entry points ARE exportable from
// this crate's shared library, on both Linux targets and at the declared
// minimum Rust version. `promote_assembled_exports` does it. This block records
// the defect, the route, and -- at the end -- the one row whose absence made an
// earlier revision of this comment conclude the opposite.
//
// WHAT WAS OBSERVED. `src/ffi/printf.rs` defines its five plain-variadic forms
// with `global_asm!`, for the reason `check_printf_trampolines` sets out, and
// `src/ffi/form.rs` does the same for `curl_formadd`. On
// x86_64-unknown-linux-gnu, in BOTH profiles:
//
// Five, not ten, and the missing five were not merely hidden: localised and then
// unreferenced, they were discarded outright, absent from a `.symtab` of 2703
// entries. The static library was untouched. Every unit test still passed,
// because a test binary links the rlib, where the labels are plainly visible.
//
// WHY. rustc builds a cdylib's export list from Rust items carrying
// `#[no_mangle]` or `#[export_name]` and hands the linker an anonymous version
// script. Captured verbatim from rustc 1.75.0 and 1.97.1 alike, through a
// logging `-C linker=` wrapper, it reads `{ global: <those items>; local: *; };`
// -- byte-identical between the two. An assembled `.globl` label matches nothing
// in `global:`, falls to the wildcard, and is localised. Specification 0.6.4 put
// this in one sentence before any of it was measured here: export parity "comes
// from declaration discipline, not from link-time filtering."
//
// EVERY ROUTE MEASURED, against a probe cdylib holding one Rust item and three
// assembled labels, one of them in its own `.text.<name>` section:
//
// | Route                                  | GNU ld 1.75 | LLD 1.97 | aarch64 GNU ld |
// |----------------------------------------|-------------|----------|----------------|
// | baseline                               | 1 of 4      | 1 of 4   | 1 of 4         |
// | -Wl,--export-dynamic-symbol=<name>     | 1 of 4      | 1 of 4   | -              |
// | -Wl,--export-dynamic-symbol-list=<f>   | 1 of 4      | 1 of 4   | -              |
// | -Wl,--dynamic-list=<file>              | 1 of 4      | 1 of 4   | -              |
// | -Wl,-u,<name> + --export-dynamic-symbol| 1 of 4      | -        | -              |
// | -Wl,--export-dynamic                   | 1 of 4      | -        | -              |
// | a second anonymous --version-script    | LINK ERROR  | 4 of 4   | LINK ERROR     |
// | a named version tag                    | LINK ERROR  | -        | -              |
//
// The link error is `anonymous version tag cannot be combined with other version
// tags`. Every route but the second version script fails because a symbol that
// rustc's own script has already matched against `local: *` stays local: the
// dynamic-list options ADD to a set that the version script then overrides, so
// they add nothing.
//
// THE ROW THAT WAS MISSING, AND THAT CHANGES THE CONCLUSION. Every cell above
// was measured with the linker `cc` happens to select. That is GNU ld on rustc
// 1.75.0 and on the `aarch64-linux-gnu-gcc` cross driver, and LLD on rustc
// 1.9x for the x86_64 host -- which is why the table reads as though the route
// worked on one target only. The linker is not fate: both pinned toolchains
// ship LLD in their own sysroot, at
// `<sysroot>/lib/rustlib/<HOST>/bin/gcc-ld/ld.lld`, and selecting it
// explicitly with `-B<that directory> -fuse-ld=lld` makes the route work
// everywhere it is emitted. Measured here, over a probe cdylib holding two
// Rust items and three assembled labels:
//
// | Route (probe: 2 Rust + 3 assembled = 5)      | exported | leaked |
// |----------------------------------------------|----------|--------|
// | 1.75.0 x86_64, baseline                      | 2 of 5   | 0      |
// | 1.75.0 x86_64, 2nd script, default linker    | LINK ERROR        |
// | 1.75.0 x86_64, 2nd script + sysroot ld.lld   | 5 of 5   | 0      |
// | 1.97.1 x86_64, baseline                      | 2 of 5   | 0      |
// | 1.97.1 x86_64, 2nd script + sysroot ld.lld   | 5 of 5   | 0      |
// | 1.97.1 aarch64, baseline                     | 2 of 5   | 0      |
// | 1.97.1 aarch64, 2nd script, cross GNU ld     | LINK ERROR        |
// | 1.97.1 aarch64, 2nd script + sysroot ld.lld  | 5 of 5   | 0      |
//
// The aarch64 artifact is a genuine `ELF 64-bit LSB shared object, ARM
// aarch64`: LLD cross-links, so the host toolchain's copy serves the cross leg
// too. `readelf -d` reports `Library soname: [libprobe.so.4]` in every success,
// so the soname argument and the version script coexist; `readelf -V` shows no
// version DEFINITION node, so nothing invents a `CURL_...` tag. A
// `-Wall -Wextra -Werror` C driver compiled against the probe's own header,
// linked with `-lprobe` and run against the shared object, called all three
// promoted labels and got the right answers back (`one=12 two=22 three=32`).
//
// WHAT IS EMITTED, THEREFORE. `promote_assembled_exports` writes the six names
// into `$OUT_DIR/assembled-exports.map` and emits three cdylib-scoped link
// arguments. It is silent -- emitting nothing at all -- when the ELF route does
// not apply or LLD is not there to select, because a `--version-script` without
// LLD is a hard link failure and a partial artifact is worse than a documented
// gap. The Mach-O side is untouched and stays at 53: ld64 takes an
// `-exported_symbols_list` FILE that REPLACES the list rather than adding to
// it, so the same trick there would hide the fifty-three to reveal the six.
// That gap is recorded at the Darwin arm of `emit_link_args`, where the
// asymmetry is visible, and is not a silent one.
//
// THE THREE ALTERNATIVES CONSIDERED BEFORE THE ROUTE WAS FOUND, AND WHY EACH
// IS STILL WORSE THAN IT.
//
// 1. A Rust item whose body is one `asm!(..., options(noreturn))` block. The
//    symbol IS exported. But a prologue is emitted -- `push %rax` in release,
//    `push %rax` plus a store of the first argument in debug -- so the assembly
//    cannot see the true incoming stack pointer and `overflow_arg_area` would be
//    wrong by an unspecified, profile-dependent amount. `#[naked]`, which is
//    what would make it exact, is stable at 1.88 and this crate declares 1.75.
//
// 2. Declaring the register-resident variadic arguments as ordinary
//    parameters. This is ABI-correct, needs no assembly, is exported on all
//    four targets, and would even close A4's Apple hazard for these five. It
//    caps the argument count: measured, `addr_of!` of the last stack-passed
//    parameter is the caller's slot in debug and a callee-local COPY in
//    release (debug read the true 6 7 8 9, release read 6 455266533382 0 0),
//    so the overflow area is unreachable and only explicitly declared slots
//    can be consumed.
//
// 3. A `cc`-compiled C shim, which is route (b) of the ambiguity as filed. It
//    does not solve THIS problem at all. The version script governs the whole
//    link, so a C object's symbols are localised exactly as an assembled label
//    is. Route (b) answers the varargs question and is silent on the export
//    question.
//
// WHAT IS CHOSEN. Keep the trampolines -- they are ABI-exact where a Rust body
// cannot be -- and promote their labels with the measured link argument. That is
// strictly better than the three alternatives: it changes no argument-passing
// convention, caps no argument list, adds no C to the build, and leaks nothing.
// The static library carried all six before and still does; the shared library
// now carries them too on ELF.
//
// What remains open is narrower than it was, and is stated where it belongs. On
// Mach-O the six are still absent, for the additive-versus-replacing reason
// above. And ambiguity A4 is untouched by any of this: it is about the four
// option-identifier entry points reading a register an Apple arm64 variadic
// caller never writes, which no linker flag addresses. The earlier claim that
// the export obstacle "applies on every target" was measured wrong and is
// withdrawn: it applies to Mach-O, and to a build whose toolchain ships no LLD.

/// Refuses to build a configuration whose variadic ABI is known to be wrong.
///
/// Read Section 1b before changing anything here. Two independent conditions
/// are checked, and each fails the build rather than warning:
///
/// 1. **`aarch64-apple-darwin`** -- the trailing-pointer design that implements
///    the four option-identifier functions reads a register that an Apple arm64
///    variadic caller never writes. That is a memory-safety fault, silent at run
///    time, on one of the four required targets.
/// 2. **An implementation of the eleven appears** -- the exports in
///    [`VARIADIC_UNIMPLEMENTABLE`] cannot be ABI-correct at the declared minimum
///    Rust version on any target, so the existence of a module purporting to
///    implement them is itself the thing that must not ship unremarked.
///
/// **Neither is releasable from the environment.** Both used to be, through
/// `CURL_RS_A4_VARIADIC_DECISION = accept-unsupported-varargs`; that bypass
/// produced a release artifact carrying the fault described in condition 1 and
/// has been removed. Setting the variable is now itself refused, so an
/// environment that still carries it fails loudly rather than appearing to be
/// honoured. [`variadic_abi_verdict`] argues the removal in full.
fn check_variadic_abi(manifest: &Path) -> Result<(), Box<dyn Error>> {
    // CARGO_CFG_TARGET_OS and _ARCH, never cfg!(...), for the reason spelled
    // out in `emit_link_args`: a build script is compiled for the host, so
    // cfg! would describe the machine doing the building. Cross-compiling to
    // aarch64-apple-darwin from an x86-64 Linux host is exactly the case this
    // gate exists to catch, and cfg! would miss it.
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let decision = env::var(A4_DECISION_ENV).unwrap_or_default();

    // Which of the two implementation files exist is a filesystem fact, read
    // here so that the verdict itself stays pure and exhaustively testable.
    let present: Vec<&'static str> = VARIADIC_IMPLEMENTATION_FILES
        .iter()
        .copied()
        .filter(|relative| manifest.join(relative).exists())
        .collect();

    variadic_abi_verdict(&os, &arch, &decision, &present)?;
    Ok(())
}

/// The verdict itself: no environment, no filesystem, no output.
///
/// Split out from [`check_variadic_abi`] so every combination of target,
/// recorded decision and implementation state can be reasoned about directly.
/// There are exactly two outcomes, and there used to be three:
///
/// * `Err(_)` -- refuse the build. The string is the whole diagnostic.
/// * `Ok(())` -- build silently.
///
/// # Why acceptance was removed
///
/// An `Ok(Some(warning))` arm used to exist, reached when
/// `CURL_RS_A4_VARIADIC_DECISION=accept-unsupported-varargs` was set: the
/// `aarch64-apple-darwin` refusal became a `cargo:warning` and the build
/// produced the artifact. That was a **release-producing bypass of a
/// memory-safety fault**, and it is gone.
///
/// The reasoning behind it was that an opt-in makes a limitation a recorded
/// decision rather than a hidden one, which is true of a limitation. It is not
/// true of this one. What the bypass produced was a shared library whose four
/// option-identifier entry points read register `x2` for an argument that an
/// Apple arm64 variadic caller places on the stack -- an uninitialised register
/// read, interpreted as a caller-supplied option value, with no diagnostic at
/// build time and none at run time. A build-time variable cannot change an
/// argument-passing convention. It could only decide whether the unsafe
/// artifact got built, and there is no correct value for that.
///
/// So the refusal is now unconditional, and setting the variable is itself
/// refused with an explanation, so that an environment carrying it fails
/// loudly instead of appearing to be honoured. Specification 0.8.6 A4 keeps
/// exactly two available options -- raise the MSRV, or drop the triple -- and
/// both are edits to this repository, made by whoever owns the requirements.
///
/// The consequence for validation gate 1 (a warning-free build on all four
/// targets, specification 0.8.4) is unchanged in substance and simpler in
/// shape: three targets build silently and pass, and `aarch64-apple-darwin`
/// fails outright with the diagnosis. It cannot be made to pass by any
/// environment setting, which is what "escalated" is supposed to mean.
///
/// **No workflow in this repository sets `CURL_RS_A4_VARIADIC_DECISION`**,
/// measured: the only occurrences under `.github/workflows/` are comments.
/// That was already true when the variable still did something, and it now
/// matters in the other direction -- a workflow that set it would fail every
/// leg rather than quietly certifying one.
fn variadic_abi_verdict(
    os: &str,
    arch: &str,
    decision: &str,
    implementations_present: &[&str],
) -> Result<(), String> {
    let decision = decision.trim();

    // Condition 1: the target whose variadic ABI is known-wrong.
    //
    // UNCONDITIONAL. No environment variable is consulted, and that is the
    // whole point -- see the doc comment's "why acceptance was removed".
    if os == "macos" && arch == "aarch64" {
        return Err(format!(
            "aarch64-apple-darwin cannot be built: its variadic ABI is \
             known-wrong (specification 0.8.6, open ambiguity A4).\n\
             \n\
             Apple's arm64 ABI passes variadic arguments ON THE STACK. The \
             non-variadic Rust callees behind {} read register x2 (measured \
             codegen: \"mov x0, x2; ret\"), which such a caller never \
             populates. Reading an uninitialised register as a user-supplied \
             option value is memory-unsafe, not merely wrong, and it is \
             silent at run time -- no Linux or x86-64 macOS test run can \
             surface it.\n\
             \n\
             THERE IS NO OPT-IN. {A4_DECISION_ENV}={A4_ACCEPTED} used to \
             release this refusal and no longer does, because a build-time \
             variable cannot make a memory-safety fault safe: it can only \
             produce the artifact that carries it. A4 requires a decision \
             this build script cannot make, and only two of its three options \
             are decisions this repository can encode:\n\
             \x20 1. Raise the minimum supported Rust version above 1.75 and \
             implement the four with c_variadic / VaList::next_arg. That means \
             rust-toolchain.toml's channel, Cargo.toml's rust-version and \
             clippy.toml's msrv, together.\n\
             \x20 2. Drop aarch64-apple-darwin from the target matrix, which \
             means amending specification 0.1.1 goal G8 and every place the \
             four-target matrix is enumerated.\n\
             \n\
             Lifting this refusal for the right reason means demonstrating \
             option 1: a C driver on aarch64-apple-darwin that calls all four \
             through the variadic prototype in the generated header and \
             round-trips every argument class.",
            VARIADIC_TRAILING_POINTER.join(", ")
        ));
    }

    // Condition 2: the decision variable is set, on a target where it can no
    // longer change anything.
    //
    // Refused rather than ignored. A build that sets it is a build whose
    // author believes an artifact is being released that is not, and silence
    // would confirm the belief -- which is the same failure mode the typo
    // check this replaces was written for, one step earlier.
    if !decision.is_empty() {
        return Err(format!(
            "{A4_DECISION_ENV} is set to {decision:?}, and no value of it \
             does anything any more.\n\
             \n\
             It formerly released the aarch64-apple-darwin refusal above when \
             set to the exact string {A4_ACCEPTED:?}. That bypass has been \
             removed: it could emit a release artifact whose variadic entry \
             points read a register an Apple arm64 caller never writes. \
             Unset the variable. If the intent was to record A4's option 3, \
             note that option 3 was the bypass, and it is gone; the remaining \
             options are to raise the MSRV or to drop the triple, both of \
             which are edits to this repository rather than environment \
             settings."
        ));
    }

    // Condition 3: a module claiming to implement the eleven has appeared.
    if !implementations_present.is_empty() {
        return Err(format!(
            "{} present, but the variadic exports those modules own have no \
             ABI-correct expression at the declared minimum Rust version on \
             any target (specification 0.8.6, open ambiguity A4).\n\
             \n\
             The eleven are: {}.\n\
             \n\
             Five are plain `...` printf forms that need va_start; five take a \
             va_list parameter whose representation differs across the four \
             targets; and curl_formadd's CURLFORM_* sequence is open-ended, \
             with no type-class encoding to recover the argument list from. \
             None is solved by the single-trailing-pointer design that serves \
             {}, because that design works only because the option identifier \
             already encodes its argument's type class. None may be dropped \
             either: they are eleven of the 100 exported symbols, and symbol \
             parity is a whole-artifact gate.\n\
             \n\
             Raise the minimum supported Rust version and implement them. \
             There is no environment setting that records a decision to ship \
             without them: {A4_DECISION_ENV} no longer releases any refusal in \
             this script.",
            implementations_present.join(" and "),
            VARIADIC_UNIMPLEMENTABLE.join(", "),
            VARIADIC_TRAILING_POINTER.join(", ")
        ));
    }

    Ok(())
}

// Section 10: version facts, read the way configure.ac read them

/// The two version strings both rendered artifacts need.
struct VersionFacts {
    /// `LIBCURL_VERSION`, for example `8.19.0-DEV`.
    version: String,
    /// `LIBCURL_VERSION_NUM` with the `0x` removed, for example `081300`.
    vernum: String,
}

impl VersionFacts {
    /// Extract both from `include/curl/curlver.h`.
    ///
    /// This reproduces what Autotools did and what nothing does any more.
    /// `configure.ac:129` ran
    /// `sed -ne 's/^#define LIBCURL_VERSION "\(.*\)".*/\1/p'` and
    /// `configure.ac:141` ran
    /// `sed -ne 's/^#define LIBCURL_VERSION_NUM 0x\([0-9A-Fa-f]*\).*/\1/p'`.
    /// Note what the second one captures: the hex digits WITHOUT the `0x`,
    /// which is why `curl-config --vernum` prints `081300` and not
    /// `0x081300`. `--vernum` echoes the value raw, so getting this wrong
    /// silently changes what every consumer's version comparison sees.
    fn read(root: &Path) -> Result<Self, Box<dyn Error>> {
        let path = root.join("include").join("curl").join("curlver.h");
        let text = fs::read_to_string(&path).map_err(|e| {
            format!("cannot read {} for version facts: {e}", path.display())
        })?;

        let mut version = None;
        let mut vernum = None;
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("#define LIBCURL_VERSION \"")
            {
                if let Some(end) = rest.find('"') {
                    version = Some(rest[..end].to_string());
                }
            } else if let Some(rest) =
                line.strip_prefix("#define LIBCURL_VERSION_NUM 0x")
            {
                let digits: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_hexdigit())
                    .collect();
                if !digits.is_empty() {
                    vernum = Some(digits);
                }
            }
        }

        let version = version.ok_or_else(|| {
            format!(
                "no `#define LIBCURL_VERSION \"...\"` found in {}",
                path.display()
            )
        })?;
        let vernum = vernum.ok_or_else(|| {
            format!(
                "no `#define LIBCURL_VERSION_NUM 0x...` found in {}",
                path.display()
            )
        })?;

        // The version string is substituted into shell and into pkg-config
        // just as the environment-derived values are, so it is validated in
        // the same spirit -- Section 14b covers the reasoning, and this is the
        // one substitution that reaches a context single quotes do not
        // protect. `curl-config.in`'s --checkfor arm places it inside BACKTICKS
        // (`vmajor=`echo '@CURLVERSION@' | cut -d. -f1``) and its "requested
        // version" diagnostic places it inside DOUBLE quotes, where `$` and a
        // backtick are live. In `libcurl.pc` it is the `Version:` field, where
        // a `#` truncates.
        if let Some(bad) = version.chars().find(|c| {
            !(c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '+'))
        }) {
            return Err(format!(
                "LIBCURL_VERSION is {version:?}, which contains {bad:?}. Only \
                 ASCII alphanumerics and '.', '-', '_' and '+' are accepted, \
                 because this string is substituted into backticks in \
                 curl-config's --checkfor arm and into libcurl.pc's Version: \
                 field, \
                 where a shell or pkg-config metacharacter would be \
                 interpreted rather than printed."
            )
            .into());
        }

        // curl-config --checkfor splits the version on '.' and strips
        // anything after a '-' from the patch field, so a version without
        // two dots would make its arithmetic compare empty strings and the
        // `test ... -gt ...` would fail with a shell error rather than a
        // verdict. Catch it here, where the message can be useful.
        if version.split('.').count() < 3 {
            return Err(format!(
                "LIBCURL_VERSION is {version:?}, which has fewer than three \
                 dot-separated fields; curl-config --checkfor needs major, \
                 minor and patch to compare"
            )
            .into());
        }

        Ok(Self { version, vernum })
    }
}

// Writing files

/// Refuse to write any of the four headers that must be carried verbatim.
///
/// A panic rather than an `Err` is deliberate: this cannot be a recoverable
/// condition. Reaching it means the header table is wrong, and continuing
/// would corrupt a reviewed ABI contract.
fn guard_write_target(path: &Path) {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if NEVER_GENERATED.contains(&name) {
        panic!(
            "refusing to write {}: {name} is one of the four public headers \
             that cannot be generated and are carried verbatim \
             (curlver.h is all #define including two function-like macros, \
             system.h is 287 preprocessor lines against 2 declarations, \
             stdcheaders.h declares libc prototypes, and typecheck-gcc.h is \
             958 lines defining 61 curlcheck_ macros, whose name occurs 260 \
             times across 258 lines, that the 129 example programs compile \
             with active). Remove it from the header table.",
            path.display()
        );
    }
}

/// A staging sibling of a destination path, unique to one write.
///
/// Same directory as the destination, because `rename` is only atomic within
/// one filesystem. The root `.gitignore` covers `include/curl/*.new` and
/// `include/curl/*.tmp` while deliberately NOT ignoring `include/curl/*.h`,
/// since those are the reviewed ABI contract.
fn staging_path(path: &Path) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("out");
    let serial = COUNTER.fetch_add(1, Ordering::Relaxed);
    path.with_file_name(format!(".{name}.{}.{serial}.new", std::process::id()))
}

/// Write `contents` into a fresh staging file beside `path`.
///
/// `create_new` is the point of the function. A staging path that already
/// exists means the uniqueness argument above is wrong, and the only safe
/// response is to say so: silently truncating whatever is there is how a
/// concurrent build's half-written render becomes this build's output.
fn stage_contents(
    path: &Path,
    contents: &str,
) -> Result<PathBuf, Box<dyn Error>> {
    use std::io::Write as _;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }

    let staged = staging_path(path);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staged)
        .map_err(|e| {
            format!("cannot create staging file {}: {e}", staged.display())
        })?;
    file.write_all(contents.as_bytes()).map_err(|e| {
        format!("cannot write staging file {}: {e}", staged.display())
    })?;
    file.flush().map_err(|e| {
        format!("cannot flush staging file {}: {e}", staged.display())
    })?;

    Ok(staged)
}

/// One header staged on disk and not yet promoted to its destination.
struct StagedHeader {
    staged: PathBuf,
    destination: PathBuf,
}

/// An all-or-nothing set of header writes.
struct HeaderTransaction {
    pending: Vec<StagedHeader>,
}

impl HeaderTransaction {
    fn new() -> Self {
        Self {
            pending: Vec::new(),
        }
    }

    /// Validate the destination and stage `contents` for it.
    ///
    /// A destination whose content is already identical is dropped here
    /// rather than staged, which preserves [`write_if_changed`]'s
    /// mtime-stability: an unchanged header keeps its timestamp, so
    /// downstream consumers do not rebuild and `git status` stays quiet.
    fn stage(
        &mut self,
        destination: &Path,
        contents: &str,
    ) -> Result<(), Box<dyn Error>> {
        guard_write_target(destination);

        if let Ok(existing) = fs::read_to_string(destination) {
            if existing == contents {
                return Ok(());
            }
        }

        let staged = stage_contents(destination, contents)?;
        self.pending.push(StagedHeader {
            staged,
            destination: destination.to_path_buf(),
        });
        Ok(())
    }

    /// How many headers are staged and awaiting promotion.
    ///
    /// Exists so the caller can assert the set is COMPLETE before any rename
    /// happens; `promote` also returns the count, but by then the files are
    /// already in place.
    fn staged_count(&self) -> usize {
        self.pending.len()
    }

    /// Promote every staged header, and report how many destinations changed.
    fn promote(mut self) -> Result<usize, Box<dyn Error>> {
        let pending = std::mem::take(&mut self.pending);
        let count = pending.len();

        for header in pending {
            if let Err(e) = fs::rename(&header.staged, &header.destination) {
                let _ = fs::remove_file(&header.staged);
                return Err(format!(
                    "cannot promote {} to {}: {e}",
                    header.staged.display(),
                    header.destination.display()
                )
                .into());
            }
        }

        Ok(count)
    }
}

impl Drop for HeaderTransaction {
    /// Remove every staging file that was never promoted.
    fn drop(&mut self) {
        for header in self.pending.drain(..) {
            let _ = fs::remove_file(&header.staged);
        }
    }
}

/// Write `contents` to `path` only if that changes the file.
///
/// Two reasons this is not a plain `fs::write`, both of which have bitten
/// real build systems:
///
/// * An unconditional rewrite touches the mtime on every build. Every
///   consumer of the header then rebuilds, and `git status` reports
///   modifications that contain no change. Comparing first keeps an
///   unchanged file byte-identical AND mtime-identical.
/// * A crash midway through a direct write leaves a truncated public
///   header on disk -- a corrupted ABI contract in a tracked file. Writing
///   to a sibling and promoting by `rename` makes the swap atomic, so the
///   destination is only ever the old content or the new content.
fn write_if_changed(
    path: &Path,
    contents: &str,
) -> Result<bool, Box<dyn Error>> {
    guard_write_target(path);

    if let Ok(existing) = fs::read_to_string(path) {
        if existing == contents {
            return Ok(false);
        }
    }

    let staged = stage_contents(path, contents)?;

    if let Err(e) = fs::rename(&staged, path) {
        // Leave nothing behind on the failure path either.
        let _ = fs::remove_file(&staged);
        return Err(format!(
            "cannot promote {} to {}: {e}",
            staged.display(),
            path.display()
        )
        .into());
    }

    Ok(true)
}

/// Apply a POSIX mode to a file that has just been written.
///
/// Applied unconditionally rather than only after a change, because a mode
/// is cheap to set and a file that already had the wrong mode would
/// otherwise keep it forever. `chmod` updates ctime, not mtime, so this does
/// not defeat [`write_if_changed`]'s rebuild-avoidance.
#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|e| {
        format!("cannot set mode {mode:o} on {}: {e}", path.display()).into()
    })
}

/// Non-Unix hosts have no POSIX mode to set. None of the four mandated
/// targets is in this branch; it exists so the file compiles anywhere.
#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<(), Box<dyn Error>> {
    Ok(())
}

/// Mode for `curl-config`: an executable script.
/// `Makefile.am:71` declares `bin_SCRIPTS = curl-config` and its first line
/// is `#!/bin/sh`, so it is installed as a program and must be runnable.
const MODE_SCRIPT: u32 = 0o755;

/// Mode for `libcurl.pc`: data, not a script. `Makefile.am:76-77` declares
/// `pkgconfigdir = $(libdir)/pkgconfig` and `pkgconfig_DATA = libcurl.pc`.
/// Marking it executable would be wrong and some packaging linters flag it.
const MODE_DATA: u32 = 0o644;

/// Reject text that is malformed for any consumer, before it reaches disk.
fn check_text_hygiene(label: &str, text: &str) -> Result<(), Box<dyn Error>> {
    if text.is_empty() {
        return Err(format!("{label} rendered empty").into());
    }
    if !text.ends_with('\n') {
        return Err(format!("{label} has no newline at end of file").into());
    }
    if text.ends_with("\n\n") {
        return Err(
            format!("{label} has a duplicated newline at end of file").into()
        );
    }
    if let Some(index) = text.find("\n\n\n") {
        // Report the line number, not merely the fact. A build-script error
        // that names a position is fixable; one that does not is a hunt.
        let line = text[..index].lines().count() + 2;
        return Err(format!(
            "{label}:{line} is the second of two consecutive blank lines, \
             which scripts/spacecheck.pl rejects"
        )
        .into());
    }
    if text.contains('\r') {
        return Err(format!("{label} contains a carriage return").into());
    }
    Ok(())
}

/// Everything [`check_text_hygiene`] requires, plus the rules that apply to
/// C source specifically.
///
/// Kept separate on purpose. Trailing whitespace and a column cap are rules
/// for source files, not for `libcurl.pc`: substituting an empty value into
/// `Requires: @LIBCURL_PC_REQUIRES@` necessarily leaves `Requires: ` with a
/// trailing space, exactly as `configure_file` leaves it in the CMake build,
/// and the template's bytes are frozen so it must not be trimmed.
fn check_source_hygiene(
    label: &str,
    text: &str,
    max_columns: usize,
) -> Result<(), Box<dyn Error>> {
    check_text_hygiene(label, text)?;

    if text.contains('\t') {
        return Err(format!("{label} contains a tab").into());
    }
    for (i, line) in text.lines().enumerate() {
        let number = i + 1;
        if line.len() != line.trim_end().len() {
            return Err(
                format!("{label}:{number} has trailing whitespace").into()
            );
        }
        if !line.is_ascii() {
            return Err(
                format!("{label}:{number} contains a non-ASCII byte").into()
            );
        }
        // Columns are counted in characters; the text is ASCII by the check
        // above, so bytes and characters agree. A line carrying a URL is
        // exempt, exactly as checksrc.pl:588 exempts it.
        if line.chars().count() > max_columns && !line.contains("://") {
            return Err(format!(
                "{label}:{number} is {} columns, over the {max_columns} \
                 column limit: {line}",
                line.chars().count()
            )
            .into());
        }
    }
    check_no_terminal_enumerator_comma(label, text)?;
    validate_comments(label, text)?;
    Ok(())
}

/// Reject a header that closes a braced typedef on a trailing comma.
fn check_no_terminal_enumerator_comma(
    label: &str,
    text: &str,
) -> Result<(), Box<dyn Error>> {
    let lines: Vec<&str> = text.lines().collect();
    for (index, line) in lines.iter().enumerate() {
        if !line.ends_with(',') {
            continue;
        }
        // Walk past blank lines so the diagnosis survives the very layout
        // change that would defeat the rewrite.
        let mut cursor = index + 1;
        while lines.get(cursor).is_some_and(|l| l.trim().is_empty()) {
            cursor += 1;
        }
        let Some(closer) = lines.get(cursor) else {
            continue;
        };
        if !closes_braced_typedef(closer) {
            continue;
        }
        return Err(format!(
            "{label}:{} ends the enumerator list of `{}` with a comma. That \
             is legal from C99 and C++11 onward and a constraint violation in \
             C89 and C++98, where gcc reports \"comma at end of enumerator \
             list\" -- an error under the -Werror a consumer may use. The \
             frozen curl 8.19.0-DEV headers carry no such comma, so emitting \
             one would regress the public ABI surface. `normalise_generated_c` \
             strips it when the closing brace is the next non-blank line; \
             reaching this check means it no longer is.",
            index + 1,
            closer.trim_start_matches("} ").trim_end_matches(';')
        )
        .into());
    }
    Ok(())
}

/// Reject a header whose C block comments are not well formed.
///
/// Three conditions are checked, each of which makes the header invalid C:
///
/// * a `*/` with no open block -- the signature of the failure above,
/// * a `/*` opened inside an already-open block, which C does not nest and
///   which gcc warns about, and
/// * a block still open at end of file.
fn validate_comments(label: &str, text: &str) -> Result<(), Box<dyn Error>> {
    let bytes = text.as_bytes();
    let mut index = 0usize;
    let mut line = 1usize;
    let mut open_at: Option<usize> = None;

    while index < bytes.len() {
        if bytes[index] == b'\n' {
            line += 1;
            index += 1;
            continue;
        }

        let pair = bytes.get(index..index + 2);

        if pair == Some(b"/*") {
            if let Some(started) = open_at {
                return Err(format!(
                    "{label}:{line} opens a block comment inside the one \
                     opened at line {started}. C does not nest block \
                     comments, so the first `*/` closes both and the text \
                     between them changes meaning. Rewrite the doc comment \
                     on the exported item without the inner delimiter."
                )
                .into());
            }
            open_at = Some(line);
            index += 2;
            continue;
        }

        if pair == Some(b"*/") {
            if open_at.is_none() {
                return Err(format!(
                    "{label}:{line} has a block-comment close with no open \
                     block. The usual cause is a Rust doc comment on an \
                     exported item that contains a literal comment-close \
                     sequence: cbindgen transcribes it, the block ends early, \
                     and every following line becomes stray C tokens. Rewrite \
                     the prose without the delimiter."
                )
                .into());
            }
            open_at = None;
            index += 2;
            continue;
        }

        // Only skip literals in code, never inside a comment, where a lone
        // quote is just prose and has no closing partner.
        if open_at.is_none() && (bytes[index] == b'"' || bytes[index] == b'\'')
        {
            let quote = bytes[index];
            index += 1;
            while index < bytes.len() && bytes[index] != quote {
                if bytes[index] == b'\\' {
                    index += 1;
                } else if bytes[index] == b'\n' {
                    line += 1;
                }
                index += 1;
            }
            index += 1;
            continue;
        }

        index += 1;
    }

    if let Some(started) = open_at {
        return Err(format!(
            "{label} ends with the block comment opened at line {started} \
             still unclosed, so everything after it was swallowed."
        )
        .into());
    }

    Ok(())
}

// Header generation

/// Number of lines in the boxed banner, measured identical in all twelve
/// public headers.
const BANNER_LINES: usize = 23;

/// The column limit generated headers must respect.
/// `scripts/checksrc.pl:29` sets `$max_column = 79`.
const HEADER_MAX_COLUMNS: usize = 79;

/// Extract the boxed banner from `cbindgen.toml`'s prologue.
///
/// Taken from there rather than restated here so that the banner has one
/// source of truth for all eight generated headers. `cbindgen.toml`'s
/// prologue is `curl.h:1-148` verbatim, whose lines 3 to 25 are the banner;
/// the two lines before it are the include guard, which every header spells
/// with its own macro and which is therefore composed per header.
fn shared_banner(base: &cbindgen::Config) -> Result<String, Box<dyn Error>> {
    let header = base.header.as_deref().ok_or_else(|| {
        "cbindgen.toml sets no `header`, so the shared banner cannot be \
         taken from it"
            .to_string()
    })?;

    let lines: Vec<&str> = header.lines().collect();
    let start = lines
        .iter()
        .position(|l| l.starts_with("/****"))
        .ok_or_else(|| {
            "cbindgen.toml's `header` has no line opening the boxed banner"
                .to_string()
        })?;
    let offset = lines[start..]
        .iter()
        .position(|l| l.ends_with("****/"))
        .ok_or_else(|| {
            "cbindgen.toml's `header` has no line closing the boxed banner"
                .to_string()
        })?;
    let banner = &lines[start..=start + offset];

    if banner.len() != BANNER_LINES {
        return Err(format!(
            "the boxed banner in cbindgen.toml is {} lines, expected \
             {BANNER_LINES}",
            banner.len()
        )
        .into());
    }
    if !banner
        .iter()
        .any(|l| l.contains("Copyright (C) Daniel Stenberg"))
    {
        return Err("the boxed banner has no copyright line, which \
                    scripts/checksrc.pl:161 requires"
            .into());
    }
    // The licence tag is matched WITHOUT its colon on purpose. `reuse`
    // recognises the tag only when the colon follows, so spelling the full
    // form in this file a second time would make it read the rest of this
    // expression as a licence expression and report the file as invalid.
    if !banner.iter().any(|l| l.contains("SPDX-License-Identifier")) {
        return Err("the boxed banner has no licence-identifier line, which \
                    `reuse lint` requires"
            .into());
    }

    Ok(banner.join("\n"))
}

/// Compose a sibling header's prologue: guard open, banner, then whatever
/// commentary and `#include` directives the header carries.
///
/// Returned without a trailing newline. cbindgen writes `header` and then
/// calls `new_line()` itself, so a trailing newline here would produce a
/// blank line that `scripts/spacecheck.pl` counts.
fn sibling_prologue(spec: &HeaderSpec, banner: &str) -> String {
    let mut out = String::new();
    let _ = write!(out, "#ifndef {0}\n#define {0}\n", spec.guard);
    out.push_str(banner);
    out.push_str(before_extern_c(spec.file));
    while out.ends_with('\n') {
        out.pop();
    }
    out
}

/// Compose the text between the includes and the generated declarations:
/// the `extern "C"` open and this header's verbatim declarations.
///
/// This goes into cbindgen's `after_includes` rather than into `header` so
/// that the autogen warning lands between the banner and the `extern "C"`
/// block -- the same position it occupies in `curl.h`, and where a reader
/// looks first. Measured emission order in cbindgen 0.29.4
/// (`language_backend/clike.rs:342-445`): `header`, then `autogen_warning`,
/// then includes, then `after_includes`.
///
/// No leading newline. Measured, not assumed: cbindgen calls
/// `new_line_if_not_start()` before this block and that call does emit a
/// blank separator, so adding one here produced two consecutive blank lines
/// -- which `scripts/spacecheck.pl` rejects and which the hygiene check
/// caught on the first run.
fn sibling_after_includes(spec: &HeaderSpec) -> String {
    let mut out = String::new();
    out.push_str(CPP_OPEN);
    out.push_str(spec.preamble);
    while out.ends_with('\n') {
        out.pop();
    }
    out
}

/// Compose a sibling header's epilogue: this header's trailing verbatim
/// declarations, the `extern "C"` close and the guard close.
fn sibling_epilogue(spec: &HeaderSpec) -> String {
    let mut out = String::new();
    // The postamble constants open with a newline so they read naturally
    // where they are defined; the leading one is dropped here because
    // cbindgen has already supplied the separator.
    out.push_str(spec.postamble.trim_start_matches('\n'));
    if !spec.postamble.is_empty() {
        out.push('\n');
    }
    let _ =
        write!(out, "#ifdef __cplusplus\n{}\n#endif\n", spec.extern_c_close);
    if spec.blank_before_guard_close {
        out.push('\n');
    }
    if spec.named_guard_close {
        let _ = write!(out, "#endif /* {} */", spec.guard);
    } else {
        out.push_str("#endif");
    }
    out
}

/// Compose `curl.h`'s `after_includes`: its verbatim forward declarations.
///
/// Kept as a function rather than used as a bare constant so the
/// no-leading-newline and no-trailing-newline rules are applied in exactly
/// one place, the same way [`sibling_after_includes`] applies them. The
/// `extern "C"` open is NOT added here: unlike the siblings, `curl.h` gets it
/// from `cbindgen.toml`'s `header`, which was measured to contain it at
/// header-relative line 106, before `typedef void CURL;`.
fn umbrella_after_includes() -> String {
    let mut out = String::new();
    out.push_str(CURL_H_FORWARD.trim_start_matches('\n'));
    while out.ends_with('\n') {
        out.pop();
    }
    out
}

/// Compose `curl.h`'s trailer: its verbatim definitions, then its
/// backward-compatibility alias blocks, then `cbindgen.toml`'s trailer
/// untouched.
///
/// `cbindgen.toml` remains the single configuration for the guard close, the
/// `extern "C"` close, the seven sibling `#include` lines and the
/// `typecheck-gcc.h` selection. This function only prepends the definitions
/// that must precede them, so nothing from that file is restated here.
fn umbrella_epilogue(base_trailer: &str) -> String {
    let mut out = String::new();
    out.push_str(CURL_H_VERBATIM.trim_start_matches('\n'));
    while out.ends_with('\n') {
        out.pop();
    }
    // The constant macros come next, before the alias blocks: several of the
    // aliases in `CURL_H_OLDIES` expand to names defined here.
    out.push_str("\n\n");
    out.push_str(CURL_H_CONSTS.trim_start_matches('\n'));
    while out.ends_with('\n') {
        out.pop();
    }
    // The alias blocks come after the struct definitions and before
    // cbindgen.toml's trailer, because they name generated enumerators and
    // the trailer closes `extern "C"` and the include guard.
    out.push_str("\n\n");
    out.push_str(CURL_H_OLDIES.trim_start_matches('\n'));
    while out.ends_with('\n') {
        out.pop();
    }
    out.push_str("\n\n");
    out.push_str(base_trailer);
    out
}

/// Which header owns `name`, if any sibling does.
fn sibling_owner_of(name: &str) -> Option<&'static str> {
    PARTITIONS
        .iter()
        .skip(1)
        .find(|(_, items)| items.contains(&name))
        .map(|(file, _)| *file)
}

/// Every name any sibling claims.
fn all_sibling_items() -> Vec<&'static str> {
    PARTITIONS
        .iter()
        .skip(1)
        .flat_map(|(_, items)| items.iter().copied())
        .collect()
}

/// Every name a sibling declares in its own verbatim text, and which must
/// therefore be suppressed in every pass.
fn all_verbatim_names() -> Vec<&'static str> {
    SIBLING_HEADERS
        .iter()
        .flat_map(|spec| spec.verbatim.iter().copied())
        .collect()
}

/// Names declared by a block of generated C.
///
/// The recognised forms are exactly those cbindgen 0.29.4 emits for
/// `language = "C"` with `style = "type"`, so this is a scanner for one
/// known producer rather than a C parser:
///
/// * `typedef enum {` ... `} Name;` -- also `struct` and `union`
/// * `typedef Underlying Name;`
/// * `typedef Ret (*Name)(args);`
/// * `CURL_EXTERN Ret Name(args);` -- the prefix comes from `[fn] prefix`
/// * `#define Name value`
fn declared_names(body: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut inside_braced_typedef = false;
    let mut awaiting_prototype = false;

    for raw in body.lines() {
        let line = raw.trim_end();

        if inside_braced_typedef {
            if let Some(rest) = line.strip_prefix("} ") {
                if let Some(name) = rest.strip_suffix(';') {
                    push_identifier(&mut names, name);
                }
                inside_braced_typedef = false;
            }
            continue;
        }

        if line.starts_with("typedef ") && line.ends_with('{') {
            inside_braced_typedef = true;
            continue;
        }

        if let Some(rest) = line.strip_prefix("#define ") {
            let end = rest.find([' ', '(']).unwrap_or(rest.len());
            push_identifier(&mut names, &rest[..end]);
            continue;
        }

        if line.starts_with("typedef ") && line.contains("(*") {
            if let Some(open) = line.find("(*") {
                let rest = &line[open + 2..];
                let end = rest.find(')').unwrap_or(rest.len());
                push_identifier(&mut names, &rest[..end]);
            }
            continue;
        }

        if line.starts_with("typedef ") && line.ends_with(';') {
            let body = &line[..line.len() - 1];
            if let Some(name) = body.split_whitespace().last() {
                push_identifier(&mut names, name);
            }
            continue;
        }

        // A prototype whose return type and name do not fit one line is
        // emitted with the prefix alone on its own line, measured:
        //
        //     CURL_EXTERN
        //     void *curl_easy_nextheader(void *_easy,
        //                                int _origin,
        if line == "CURL_EXTERN" {
            awaiting_prototype = true;
            continue;
        }
        if awaiting_prototype {
            awaiting_prototype = false;
            if let Some(name) = function_name_on(line) {
                push_identifier(&mut names, &name);
            }
            continue;
        }

        if line.starts_with("CURL_EXTERN ") {
            match function_name_on(line) {
                Some(name) if name.starts_with("CURL_DEPRECATED") => {
                    awaiting_prototype = true;
                }
                Some(name) => push_identifier(&mut names, &name),
                None => awaiting_prototype = true,
            }
        }
    }

    names
}

/// The identifier immediately before the first `(` on a prototype line.
fn function_name_on(line: &str) -> Option<String> {
    let open = line.find('(')?;
    let head = &line[..open];
    let start = head
        .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .map_or(0, |index| index + 1);
    let name = &head[start..];
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

/// Record `candidate` if it is a plain C identifier and not already held.
fn push_identifier(names: &mut Vec<String>, candidate: &str) {
    let name = candidate.trim().trim_start_matches('*');
    if name.is_empty() {
        return;
    }
    let first_ok = name
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
    let rest_ok = name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if first_ok && rest_ok && !names.iter().any(|held| held == name) {
        names.push(name.to_string());
    }
}

/// The part of a generated header cbindgen produced, with the verbatim
/// prologue and epilogue removed.
///
/// Needed because the verbatim text declares names too, and counting those
/// as generated would make every partition check meaningless.
fn generated_region<'a>(
    text: &'a str,
    prologue: &str,
    epilogue: &str,
) -> &'a str {
    let start = text
        .find(prologue)
        .map_or(0, |index| index + prologue.len());
    let region = &text[start..];
    match region.rfind(epilogue) {
        Some(index) => &region[..index],
        None => region,
    }
}

/// Set one pass's export partition.
fn apply_partition(
    config: &mut cbindgen::Config,
    owned: &[&str],
    suppress: &[String],
) {
    config.export.include = owned.iter().map(|s| (*s).to_string()).collect();
    for name in suppress {
        if !config.export.exclude.iter().any(|held| held == name) {
            config.export.exclude.push(name.clone());
        }
    }
    // Lifting has to happen after appending, because a name may be both
    // excluded by `cbindgen.toml` and forced by `owned`. `owned` wins.
    config
        .export
        .exclude
        .retain(|name| !owned.iter().any(|held| held == name));
}

/// The one name whose exclusion this script lifts, and why.
///
/// `CURLoption` is excluded by `cbindgen.toml` so that no pass emits it by
/// accident, and re-admitted here for the one pass that owns it: `src/ffi/opts.rs`
/// is its single source of truth. That module carries the whole mechanism, so no macro
/// expansion is required of cbindgen: `#[repr(C)] pub enum CURLoption` writes
/// all 309 discriminants out as explicit integer literals (308 preferred
/// options plus `CURLOPT_LASTENTRY`), `EASY_OPTIONS` is the 324-row
/// `curl_easyoption` projection, and `OPTION_ALIASES` carries all 19
/// `#define CURLOPT_` spellings. This matters because `[parse.expand]` in
/// `cbindgen.toml` is empty on purpose -- expansion would shell out to
/// `cargo expand` -- so an enumeration that only existed as a macro
/// invocation could not be rendered at all.
const CURL_H_GENERATED_DESPITE_EXCLUSION: &[&str] = &["CURLoption"];

// Section 12a: making cbindgen's diagnostics fatal
//
// MEASURED CAUSE OF THE FAIL-OPEN THIS SECTION CLOSES. cbindgen reports
// recoverable problems -- among them `Parsing crate: can't find mod X` at
// `bindgen/parser.rs:390`, whose own comment concedes "This should be an
// error, but it's common enough to just elicit a warning" -- through the
// `log` crate. Its 36 `warn!`/`error!` sites in `src/bindgen/` are only ever
// visible when a logger is installed, and cbindgen installs one exclusively
// in its COMMAND-LINE binary (`src/main.rs:323-328`). Used as a library, as
// it is here, `log`'s default no-op logger discards every record, so
// `generate()` returns `Ok` and the caller sees a successful build that has
// silently dropped a module -- the reported failure emitted 6,672 bytes with
// neither `CURLE_OK` nor `curl_easy_init` in it and still exited 0.

/// Diagnostics cbindgen emitted during the current generation pass.
static CBINDGEN_DIAGNOSTICS: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Installs [`DIAGNOSTIC_SINK`] exactly once. `log::set_logger` fails on a
/// second call, and generation runs nine passes.
static SINK_INSTALLED: Once = Once::new();

/// A `log` sink that records rather than prints, so the caller can fail.
struct DiagnosticSink;

static DIAGNOSTIC_SINK: DiagnosticSink = DiagnosticSink;

impl log::Log for DiagnosticSink {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Warn
    }

    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        // A poisoned lock must not mask a diagnostic, so the message is
        // recovered from the poison rather than unwrapped.
        let mut sink = match CBINDGEN_DIAGNOSTICS.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        sink.push(format!("{}: {}", record.level(), record.args()));
    }

    fn flush(&self) {}
}

/// Begins a generation pass with an empty diagnostic buffer.
///
/// `set_max_level` is raised to `Warn` because `log`'s default is `Off`, at
/// which the `warn!` macros short-circuit before reaching any logger and the
/// sink would record nothing however correct it is.
fn begin_diagnostics() {
    SINK_INSTALLED.call_once(|| {
        // A failure here means something else already claimed the global
        // logger. Recording that is worthwhile: it means the diagnostics
        // this script relies on are going somewhere else.
        if log::set_logger(&DIAGNOSTIC_SINK).is_err() {
            println!(
                "cargo:warning=another logger is already installed, so \
                 cbindgen diagnostics cannot be captured"
            );
        }
        log::set_max_level(log::LevelFilter::Warn);
    });
    take_diagnostics();
}

/// Drains and returns everything recorded since [`begin_diagnostics`].
fn take_diagnostics() -> Vec<String> {
    let mut sink = match CBINDGEN_DIAGNOSTICS.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    std::mem::take(&mut *sink)
}

/// One captured cbindgen diagnostic, classified by shape.
///
/// Shape matters because a correct build here is NOT diagnostic-free, and
/// pretending otherwise would leave only two options, both wrong: fail on
/// every build, or accept every diagnostic and restore the fail-open that
/// this guard describes. Measured on a correct build, cbindgen
/// 0.29.4 emits 59 records in exactly two shapes, and both are consequences
/// of decisions this script makes on purpose. The third arm is everything
/// else, which includes the one that actually mattered:
/// `Parsing crate `curl-rs-ffi`: can't find mod ffi`.`, emitted at
/// `cbindgen-0.29.4/src/bindgen/parser.rs:390` under a comment that reads
/// "This should be an error, but it's common enough to just elicit a
/// warning".
enum Diagnostic<'a> {
    /// `Skip curl-rs-ffi::NAME - (not `pub`).`, and the `no_mangle` variant.
    ///
    /// cbindgen walks every item in the crate and says so when it declines
    /// one. Benign only when no header partition claims the name: a skipped
    /// item that a partition claims is a DROPPED DECLARATION, which is the
    /// defect this exists to catch.
    Skipped(&'a str),
    /// `Can't find NAME. This usually means that this type was incompatible
    /// or not found.`
    ///
    /// Emitted while resolving a type referenced by a declaration cbindgen
    /// IS emitting. Benign only when the name is deliberately withheld from
    /// cbindgen -- either excluded for this pass or carried verbatim -- in
    /// which case keeping the referenced name as written is precisely the
    /// behaviour this script relies on to preserve `curl_off_t`,
    /// `curl_socket_t` and the tag-only structs. A name that is neither is a
    /// genuinely unresolved type, and the signature referencing it will not
    /// compile.
    TypeNotFound(&'a str),
    /// Any other record, always fatal.
    Unrecognised,
}

/// Classify one record of the form `"{level}: {message}"`.
fn classify_diagnostic(record: &str) -> Diagnostic<'_> {
    // `Skip <crate>::<path::>NAME - (not `pub`).`
    if let Some(rest) = record.find("Skip ").map(|at| &record[at + 5..]) {
        if let Some(end) = rest.find(" - (") {
            let qualified = &rest[..end];
            let name = qualified.rsplit("::").next().unwrap_or(qualified);
            if !name.is_empty() {
                return Diagnostic::Skipped(name);
            }
        }
    }

    // `Can't find NAME. This usually means ...`
    const TAIL: &str = ". This usually means that this type was";
    if let Some(rest) = record.find("Can't find ").map(|at| &record[at + 11..])
    {
        if let Some(end) = rest.find(TAIL) {
            let name = rest[..end].trim();
            // Anchored on a bare identifier, so the superficially similar
            // `can't find mod ffi`.` cannot land here.
            if !name.is_empty()
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                return Diagnostic::TypeNotFound(name);
            }
        }
    }

    Diagnostic::Unrecognised
}

/// Fail if any module the generated headers are built from is missing.
///
/// The first requirement, and it exists because of exactly what was measured:
/// cbindgen reported `can't find mod ffi`, returned Ok, and
/// emitted a header containing neither `CURLE_OK` nor `curl_easy_init`. A
/// missing module is not a degraded render, it is the silent deletion of an
/// entire ABI surface, and it is indistinguishable in the output from a
/// module that legitimately declares nothing.
fn preflight_modules(manifest: &Path) -> Result<(), Box<dyn Error>> {
    let root = manifest.join("src").join("lib.rs");
    if !root.is_file() {
        return Err(format!(
            "{} does not exist, so there is no crate root to generate the \
             public headers from",
            root.display()
        )
        .into());
    }

    let mut checked = 0usize;
    let mut queue = vec![root.clone()];

    while let Some(file) = queue.pop() {
        let text = fs::read_to_string(&file)
            .map_err(|e| format!("cannot read {}: {e}", file.display()))?;

        // A file module's children live beside it; a directory module's live
        // in its directory.
        let dir = if file.file_name().and_then(|n| n.to_str()) == Some("mod.rs")
            || file == root
        {
            file.parent().map(Path::to_path_buf).unwrap_or_default()
        } else {
            file.with_extension("")
        };

        for name in declared_modules(&text) {
            let flat = dir.join(format!("{name}.rs"));
            let nested = dir.join(&name).join("mod.rs");
            let resolved = if flat.is_file() {
                flat
            } else if nested.is_file() {
                nested
            } else {
                return Err(format!(
                    "{} declares `mod {name};` but neither {} nor {} exists. \
                     cbindgen would report this as the warning \"can't find \
                     mod {name}\", return Ok, and emit public headers missing \
                     everything that module declares.",
                    file.display(),
                    flat.display(),
                    nested.display()
                )
                .into());
            };

            if fs::metadata(&resolved).map(|m| m.len()).unwrap_or(0) == 0 {
                return Err(format!(
                    "{} is empty, but {} declares `mod {name};`. An empty \
                     module parses without complaint and contributes no \
                     declarations, so the generated headers would be short by \
                     exactly its contents.",
                    resolved.display(),
                    file.display()
                )
                .into());
            }

            checked += 1;
            queue.push(resolved);
        }
    }

    if checked == 0 {
        return Err(format!(
            "{} declares no modules at all. The public headers are generated \
             from this crate's module tree, so an empty tree means an empty \
             ABI contract.",
            root.display()
        )
        .into());
    }

    Ok(())
}

/// The four exported functions whose C prototype is genuinely variadic and
/// whose argument count is nevertheless fixed at three.
const VARIADIC_ENTRY_POINTS: [&str; 4] = [
    "curl_easy_setopt",
    "curl_easy_getinfo",
    "curl_multi_setopt",
    "curl_share_setopt",
];

/// Refuse to build a plain non-variadic definition of a variadic entry point.
///
/// # The hazard, measured on all four targets
///
/// A C caller reaching one of [`VARIADIC_ENTRY_POINTS`] through its variadic
/// prototype does not put the third argument in the same place on every
/// target. Disassembling the call site proves it:
///
/// ```text
/// x86_64-unknown-linux-gnu    mov  %rsi,%rdx     -> RDX
/// x86_64-apple-darwin         movq %rsi,%rdx     -> RDX
/// aarch64-unknown-linux-gnu   mov  x2, x1        -> X2
/// aarch64-apple-darwin        str  x1, [sp]      -> THE STACK; x2 never written
/// ```
///
/// A plain non-variadic `extern "C" fn` callee compiles to `mov x0, x2; ret`
/// on aarch64 -- it reads x2. On the first three targets caller and callee
/// agree. On `aarch64-apple-darwin`, one of the four required targets, the
/// callee would read a register the caller never populated, and the failure is
/// silent: no crash, no diagnostic, just a wrong option value.
///
/// # The remedy, measured rather than assumed
///
/// A `core::arch::global_asm!` trampoline exported under the public symbol
/// name, relocating the argument and tail-calling the real implementation:
///
/// ```text
/// _curl_easy_setopt:
///     ldr  x2, [sp]                  ; the slot the Apple caller wrote
///     adrp x16, {impl}@PAGE
///     add  x16, x16, {impl}@PAGEOFF
///     br   x16
/// ```
///
/// # Why this is a hard check and no longer a warning
///
/// A `cargo:warning=` here would break the zero-warnings build gate, and it
/// would fire on every `aarch64-apple-darwin` build for a hazard that is not
/// yet present. A check is strictly stronger: it fails the build the moment
/// the hazard is actually introduced, it fails on every target rather than
/// only on the affected one -- so a developer on Linux cannot land it
/// unnoticed -- and it cannot be satisfied by a comment, because the token it
/// looks for is the assembly label that defines the global symbol.
fn check_variadic_strategy(manifest: &Path) -> Result<(), Box<dyn Error>> {
    let sources = rust_sources(&manifest.join("src"))?;

    for name in VARIADIC_ENTRY_POINTS {
        // A Rust-side definition, as opposed to a prototype carried verbatim
        // into the generated header. Both spellings the crate uses are
        // matched; a declaration in a string or a comment cannot, because
        // `extern "C" fn` has to precede the name directly.
        let signature = format!("extern \"C\" fn {name}(");
        let defined_in = sources.iter().find(|(_, text)| {
            strip_rust_comments(text).lines().any(|line| {
                let line = line.trim();
                // Anchored to an item declaration, so the same text appearing
                // inside a string literal -- which the stripper deliberately
                // leaves alone -- cannot be mistaken for a definition.
                line.contains(&signature)
                    && (line.starts_with("pub ")
                        || line.starts_with("extern ")
                        || line.starts_with("unsafe "))
            })
        });
        let Some((path, _)) = defined_in else {
            continue;
        };

        // The trampoline's Mach-O label. Requiring the label rather than a
        // marker comment is what makes this mechanical: the label is what
        // actually emits the global symbol, so it cannot be faked.
        let label = format!("_{name}:");
        let trampolined = sources.iter().any(|(_, text)| {
            text.contains("global_asm!") && text.contains(&label)
        });

        if !trampolined {
            return Err(format!(
                "{} defines `extern \"C\" fn {name}` with a fixed argument \
                 list, but no `global_asm!` trampoline exporting `{label}` \
                 was found. On aarch64-apple-darwin -- a required target -- \
                 Apple's arm64 ABI passes the variadic third argument on the \
                 stack (measured: `str x1, [sp]`) while a non-variadic aarch64 \
                 callee reads register x2 (measured: `mov x0, x2; ret`), so \
                 this definition would silently read an argument the caller \
                 never wrote. Add the trampoline described on \
                 check_variadic_strategy; it is proven to build at the \
                 declared MSRV of 1.75 and needs no C compiler.",
                path.display()
            )
            .into());
        }
    }

    Ok(())
}

/// The printf module, relative to the manifest.
const PRINTF_MODULE: &str = "src/ffi/printf.rs";

/// The five plain-variadic `curl_m*printf` forms, each paired with the
/// `va_list` sibling its trampoline must reach.
///
/// The pairing is the header's, and it is not guessable from the names alone --
/// `curl_maprintf` reaches `curl_mvaprintf`, which returns `char *` where the
/// other four siblings return `int`. Recording it here means a trampoline wired
/// to the wrong sibling is a build failure rather than a silent type confusion
/// across the ABI boundary.
const PRINTF_TRAMPOLINES: [(&str, &str); 5] = [
    ("curl_mprintf", "curl_mvprintf"),
    ("curl_mfprintf", "curl_mvfprintf"),
    ("curl_msprintf", "curl_mvsprintf"),
    ("curl_msnprintf", "curl_mvsnprintf"),
    ("curl_maprintf", "curl_mvaprintf"),
];

/// The two `.globl` spellings a trampoline macro must emit, and the object
/// format each one serves.
const GLOBL_SPELLINGS: [(&str, &str); 2] = [
    (r#"".globl ", $name"#, "ELF"),
    (r#"".globl _", $name"#, "Mach-O"),
];

/// Require the five plain-variadic printf forms to be trampolines, per symbol.
///
/// # Why this is stricter than a per-file veto
///
/// [`VARIADIC_IMPLEMENTATION_FILES`] can only count files, so it cannot tell a
/// correct implementation from an incorrect one, and an environment variable
/// silences it. This check cannot be silenced and looks at each symbol
/// individually. It refuses, for every one of the five:
///
/// 1. a plain Rust `extern "C" fn` definition, which is the actual A4 hazard --
///    a non-variadic callee reached through a variadic prototype reads a
///    register the Apple arm64 caller never wrote, and the failure is silent;
/// 2. the absence of a `global_asm!` trampoline naming that export;
/// 3. a trampoline wired to the wrong `va_list` sibling, or to one that does not
///    exist as a Rust export;
/// 4. a macro that emits only one object format's `.globl` spelling.
fn check_printf_trampolines(manifest: &Path) -> Result<(), Box<dyn Error>> {
    if !manifest.join(PRINTF_MODULE).exists() {
        return Ok(());
    }

    let sources = rust_sources(&manifest.join("src"))?;

    for (exported, sibling) in PRINTF_TRAMPOLINES {
        if let Some((path, _)) = find_c_definition(&sources, exported) {
            return Err(format!(
                "{} defines `extern \"C\" fn {exported}` as a Rust function, \
                 but `{exported}` is variadic in include/curl/mprintf.h and a \
                 Rust function cannot be. On aarch64-apple-darwin -- a \
                 required target -- Apple's arm64 ABI passes every variadic \
                 argument on the stack (measured: `str x1, [sp]`), so a \
                 non-variadic callee would read a register the caller never \
                 wrote and would do it silently. Emit a `global_asm!` \
                 trampoline that performs the target's own `va_start` and \
                 calls `{sibling}`; that is proven to build at the declared \
                 MSRV of 1.75 and needs no C compiler.",
                path.display()
            )
            .into());
        }

        let export_arg = format!("export = \"{exported}\",");
        let callee_arg = format!("callee = {sibling},");
        let trampolined = sources.iter().any(|(_, text)| {
            let code = strip_rust_comments(text);
            code.contains("global_asm!")
                && code.contains(&export_arg)
                && code.contains(&callee_arg)
        });
        if !trampolined {
            return Err(format!(
                "{PRINTF_MODULE} exists, so `{exported}` has to be exported, \
                 but no `global_asm!` trampoline declaring `{export_arg}` and \
                 `{callee_arg}` was found. All 100 symbols in lib/libcurl.def \
                 are compared as one set by the nm parity gate, so a missing \
                 one fails it outright.",
            )
            .into());
        }

        if find_c_definition(&sources, sibling).is_none() {
            return Err(format!(
                "a trampoline names `{sibling}` as the target of \
                 `{exported}`, but nothing defines \
                 `extern \"C\" fn {sibling}`. The trampoline would assemble \
                 and then fail to link, or worse, bind to some other \
                 translation unit's symbol of that name.",
            )
            .into());
        }
    }

    let printf = sources
        .iter()
        .find(|(path, _)| path.ends_with("printf.rs"))
        .ok_or_else(|| {
            format!("{PRINTF_MODULE} exists but was not read back")
        })?;
    let code = strip_rust_comments(&printf.1);
    for (fragment, object_format) in GLOBL_SPELLINGS {
        if !code.contains(fragment) {
            return Err(format!(
                "{} carries printf trampolines but never emits `{fragment}`, \
                 so nothing exports them on {object_format}. Mach-O decorates \
                 symbols with a leading underscore and ELF does not; a macro \
                 that emits one spelling exports nothing on the targets \
                 needing the other.",
                printf.0.display()
            )
            .into());
        }
    }

    Ok(())
}

/// The module that owns the legacy `curl_form*` trio, relative to the manifest.
const FORM_MODULE: &str = "src/ffi/form.rs";

/// `curl_formadd` and the non-exported Rust function its trampoline calls.
///
/// Kept as a pair for the same reason [`PRINTF_TRAMPOLINES`] is: recording which
/// function the trampoline must reach turns a mis-wired one into a build failure
/// rather than a silent type confusion across the ABI boundary. Unlike the printf
/// pairs the callee here is **not** itself an export -- `curl_formadd` has no
/// `va_list` sibling in `lib/libcurl.def` -- so the check below requires it to
/// exist as a Rust definition without requiring it to be exported. An exported
/// callee would be a 101st symbol and would fail the parity gate.
const FORMADD_TRAMPOLINE: (&str, &str) = ("curl_formadd", "formadd_va");

/// Require `curl_formadd` to be a trampoline, not a Rust function.
///
/// The per-symbol counterpart of [`check_printf_trampolines`], and it exists for
/// the same reason: the per-file veto that used to list [`FORM_MODULE`] in
/// [`VARIADIC_IMPLEMENTATION_FILES`] could only count files, and an environment
/// variable silenced it. This cannot be silenced and refuses four things:
///
/// 1. a plain Rust `extern "C" fn curl_formadd`, which is the actual A4 hazard --
///    a non-variadic callee reached through a variadic prototype reads a register
///    the Apple arm64 caller never wrote, and the failure is silent;
/// 2. the absence of a `global_asm!` trampoline exporting the name;
/// 3. the absence of the Rust function that trampoline calls, which would
///    assemble and then fail to link, or worse, bind to some other translation
///    unit's symbol of that name;
/// 4. only one object format's `.globl` spelling, which would leave half the
///    required targets with no exporter at all.
fn check_formadd_trampoline(manifest: &Path) -> Result<(), Box<dyn Error>> {
    if !manifest.join(FORM_MODULE).exists() {
        return Ok(());
    }

    let (exported, callee) = FORMADD_TRAMPOLINE;
    let sources = rust_sources(&manifest.join("src"))?;

    if let Some((path, _)) = find_c_definition(&sources, exported) {
        return Err(format!(
            "{} defines `extern \"C\" fn {exported}` as a Rust function, but \
             `{exported}` is variadic in include/curl/curl.h:2632-2635 and a \
             Rust function cannot be: `extern \"C\" fn f(x: T, ...)` is \
             error[E0658] at the declared MSRV of 1.75. On \
             aarch64-apple-darwin -- a required target -- Apple's arm64 ABI \
             passes every variadic argument on the stack, so a non-variadic \
             callee would read a register the caller never wrote and would do \
             it silently. Emit a `global_asm!` trampoline that performs the \
             target's own `va_start` and calls `{callee}`; that is proven to \
             build at 1.75 and needs no C compiler.",
            path.display()
        )
        .into());
    }

    let form = sources
        .iter()
        .find(|(path, _)| path.ends_with("form.rs"))
        .ok_or_else(|| format!("{FORM_MODULE} exists but was not read back"))?;
    let code = strip_rust_comments(&form.1);

    if !code.contains("global_asm!") {
        return Err(format!(
            "{FORM_MODULE} exists, so `{exported}` has to be exported, but the \
             module assembles nothing. All 100 symbols in lib/libcurl.def are \
             compared as one set by the nm parity gate, so a missing one fails \
             it outright.",
        )
        .into());
    }

    for (label, object_format) in [
        (format!(".globl {exported}"), "ELF"),
        (format!(".globl _{exported}"), "Mach-O"),
    ] {
        if !code.contains(&label) {
            return Err(format!(
                "{FORM_MODULE} assembles a trampoline but never emits \
                 `{label}`, so nothing exports `{exported}` on \
                 {object_format}. Mach-O decorates symbols with a leading \
                 underscore and ELF does not; emitting one spelling exports \
                 nothing on the targets needing the other.",
            )
            .into());
        }
    }

    if find_c_definition(&sources, callee).is_none() {
        return Err(format!(
            "{FORM_MODULE} assembles `{exported}`, but nothing defines \
             `extern \"C\" fn {callee}` for it to call. The trampoline would \
             assemble and then fail to link, or worse, bind to some other \
             translation unit's symbol of that name.",
        )
        .into());
    }

    Ok(())
}

/// Find the file defining `name` as a C-ABI Rust function, if any.
///
/// Anchored to an item declaration -- `pub `, `extern ` or `unsafe ` must begin
/// the line -- so the same text inside a string literal, which
/// [`strip_rust_comments`] deliberately leaves alone, cannot be mistaken for a
/// definition.
fn find_c_definition<'a>(
    sources: &'a [(PathBuf, String)],
    name: &str,
) -> Option<&'a (PathBuf, String)> {
    let signature = format!("extern \"C\" fn {name}(");
    sources.iter().find(|(_, text)| {
        strip_rust_comments(text).lines().any(|line| {
            let line = line.trim();
            line.contains(&signature)
                && (line.starts_with("pub ")
                    || line.starts_with("extern ")
                    || line.starts_with("unsafe "))
        })
    })
}

/// Every `.rs` file under `dir`, read, with its path.
///
/// Used by the checks that have to reason about this crate's own source
/// rather than about its output. Recursive, so a check cannot be evaded by
/// moving a definition into a subdirectory.
fn rust_sources(dir: &Path) -> Result<Vec<(PathBuf, String)>, Box<dyn Error>> {
    let mut found = Vec::new();
    let mut queue = vec![dir.to_path_buf()];

    while let Some(current) = queue.pop() {
        let entries = fs::read_dir(&current)
            .map_err(|e| format!("cannot list {}: {e}", current.display()))?;
        for entry in entries {
            let entry = entry.map_err(|e| {
                format!("cannot read an entry of {}: {e}", current.display())
            })?;
            let path = entry.path();
            if path.is_dir() {
                queue.push(path);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                let text = fs::read_to_string(&path).map_err(|e| {
                    format!("cannot read {}: {e}", path.display())
                })?;
                found.push((path, text));
            }
        }
    }

    if found.is_empty() {
        return Err(format!(
            "{} contains no Rust source at all",
            dir.display()
        )
        .into());
    }

    found.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(found)
}

/// Blank out Rust comments so a scan sees code only.
///
/// String literals are deliberately **kept**, and the reason is worth
/// recording because the first version of this function removed them and
/// thereby made [`check_variadic_strategy`] vacuous. The pattern that check
/// looks for is `extern "C" fn NAME(`, and `extern "C"` *contains a string
/// literal*. Blanking literals rewrote it to `extern     fn NAME(`, so the
/// search could never match and a deliberately injected hazard built cleanly.
/// Comments are the only noise that has to go; literals are handled instead by
/// requiring the match to begin an item declaration.
fn strip_rust_comments(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = vec![b' '; bytes.len()];
    let mut i = 0usize;

    while i < bytes.len() {
        // Line comment: to the end of the line, newline preserved.
        if bytes[i] == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        // Block comment, nesting as Rust nests them.
        if bytes[i] == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            let mut depth = 1usize;
            i += 2;
            while i < bytes.len() && depth > 0 {
                if bytes[i] == b'/'
                    && i + 1 < bytes.len()
                    && bytes[i + 1] == b'*'
                {
                    depth += 1;
                    i += 2;
                } else if bytes[i] == b'*'
                    && i + 1 < bytes.len()
                    && bytes[i + 1] == b'/'
                {
                    depth -= 1;
                    i += 2;
                } else {
                    if bytes[i] == b'\n' {
                        out[i] = b'\n';
                    }
                    i += 1;
                }
            }
            continue;
        }
        out[i] = bytes[i];
        i += 1;
    }

    String::from_utf8_lossy(&out).into_owned()
}

/// Names in `mod NAME;` declarations, ignoring inline and commented ones.
///
/// Only a declaration terminated by `;` names a separate file; `mod tests {`
/// is inline and needs none. A line inside a doc comment cannot match,
/// because the trimmed line has to begin with the keyword itself.
fn declared_modules(text: &str) -> Vec<String> {
    let mut names = Vec::new();

    for line in text.lines() {
        let trimmed = line.trim();
        let rest = trimmed
            .strip_prefix("pub(crate) mod ")
            .or_else(|| trimmed.strip_prefix("pub mod "))
            .or_else(|| trimmed.strip_prefix("mod "));
        let Some(rest) = rest else { continue };
        let Some(name) = rest.strip_suffix(';') else {
            continue;
        };
        let name = name.trim();
        if !name.is_empty()
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            names.push(name.to_string());
        }
    }

    names
}

/// Every `pub enum` in the crate's FFI tree, with the representation it
/// declares.
///
/// The authority for the declared-FORM assertion. Reproduced three times
/// during this work -- once for `CURLoption` and twice for `curl_infotype` --
/// changing a public enum's representation from `#[repr(C)]` to `#[repr(iN)]`
/// makes cbindgen emit TWO CONFLICTING TYPEDEFS for it:
///
/// ```c
/// typedef enum curl_infotype { ... } curl_infotype;   /* not emitted */
/// typedef int32_t curl_infotype;                      /* emitted instead */
/// ```
///
/// Every member keeps its name and value, so a member-count check passes, a
/// value check passes, and `declared_names` still reports the name because it
/// recognises `typedef Underlying Name;`. The Rust build stays green and every
/// unit test passes. Only the SHAPE changes -- and with it the C type of every
/// parameter declared as that enum.
fn public_enum_reprs(
    manifest: &Path,
) -> Result<Vec<(String, String)>, Box<dyn Error>> {
    let dir = manifest.join("src").join("ffi");
    let mut found = Vec::new();

    let entries = fs::read_dir(&dir)
        .map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
    let mut files: Vec<PathBuf> = Vec::new();
    for entry in entries {
        let path = entry
            .map_err(|e| format!("cannot walk {}: {e}", dir.display()))?
            .path();
        if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            files.push(path);
        }
    }
    // Deterministic, so an error message is reproducible between builds.
    files.sort();

    for file in files {
        let text = fs::read_to_string(&file)
            .map_err(|e| format!("cannot read {}: {e}", file.display()))?;
        let lines: Vec<&str> = text.lines().map(str::trim).collect();

        for (index, line) in lines.iter().enumerate() {
            let Some(rest) = line.strip_prefix("pub enum ") else {
                continue;
            };
            let end = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(rest.len());
            let name = &rest[..end];
            if name.is_empty() {
                continue;
            }

            // Walk back over the contiguous attribute, derive and doc-comment
            // lines that precede the declaration, looking for the
            // representation. Backward rather than forward so the search is
            // anchored on the declaration, which is what the name comes from.
            let mut repr = String::new();
            let mut cursor = index;
            while cursor > 0 {
                let above = lines[cursor - 1];
                if above.is_empty() {
                    break;
                }
                if let Some(inner) = above
                    .strip_prefix("#[repr(")
                    .and_then(|r| r.strip_suffix(")]"))
                {
                    repr = inner.to_string();
                    break;
                }
                if above.starts_with("#[") || above.starts_with("//") {
                    cursor -= 1;
                    continue;
                }
                break;
            }

            found.push((name.to_string(), repr));
        }
    }

    Ok(found)
}

/// How many times a block of C closes a braced typedef named `name`.
///
/// `} NAME;` is the terminator cbindgen writes for a `#[repr(C)]` enum,
/// struct or union under `style = "type"`, and it is the one form a
/// `typedef int32_t NAME;` twin cannot produce.
fn braced_typedef_terminators(body: &str, name: &str) -> usize {
    let terminator = format!("}} {name};");
    body.lines()
        .filter(|line| line.trim() == terminator)
        .count()
}

/// The scalar typedef of `name`, if the block declares one.
///
/// Matches `typedef <single-token> NAME;` -- the exact shape cbindgen
/// substitutes for a braced enum when the representation is `#[repr(iN)]`.
fn scalar_typedef_of(body: &str, name: &str) -> Option<String> {
    let suffix = format!(" {name};");
    body.lines().map(str::trim).find_map(|line| {
        let rest = line.strip_prefix("typedef ")?;
        let underlying = rest.strip_suffix(&suffix)?;
        // A single token, so `typedef enum NAME { ... } NAME;` collapsed onto
        // one line cannot be mistaken for the scalar form.
        if !underlying.is_empty()
            && underlying
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            Some(line.to_string())
        } else {
            None
        }
    })
}

/// Every name any header partition claims as generated.
fn all_partition_items() -> Vec<&'static str> {
    PARTITIONS
        .iter()
        .flat_map(|(_, items)| items.iter().copied())
        .collect()
}

/// Every name written by hand into some header's verbatim text, whether as a
/// declaration or as a `#define`.
fn all_verbatim_carried() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = all_verbatim_names();
    names.extend(CURL_H_VERBATIM_NAMES.iter().copied());
    for (_, blocks) in VERBATIM_CARRIERS.iter() {
        for block in blocks.iter() {
            names.extend(verbatim_defines(block));
        }
    }
    names
}

/// Reduce a pass's diagnostics to the ones that must fail the build.
fn fatal_diagnostics(records: &[String], excluded: &[String]) -> Vec<String> {
    let claimed = all_partition_items();
    let verbatim = all_verbatim_carried();

    records
        .iter()
        .filter_map(|record| match classify_diagnostic(record) {
            Diagnostic::Skipped(name) => {
                if claimed.contains(&name) {
                    Some(format!(
                        "{record}\n    -> FATAL: a header partition claims \
                         {name}, so skipping it drops a declaration the \
                         generated headers are asserted to contain."
                    ))
                } else {
                    None
                }
            }
            Diagnostic::TypeNotFound(name) => {
                let withheld = excluded.iter().any(|held| held == name)
                    || verbatim.contains(&name);
                if withheld {
                    None
                } else {
                    Some(format!(
                        "{record}\n    -> FATAL: {name} is neither excluded \
                         from this pass nor carried verbatim, so it is a \
                         genuinely unresolved type and any signature \
                         referencing it will not compile."
                    ))
                }
            }
            Diagnostic::Unrecognised => Some(format!(
                "{record}\n    -> FATAL: unrecognised cbindgen diagnostic. \
                 cbindgen downgrades a missing module to a warning and \
                 returns Ok, so an unclassified record is treated as a \
                 dropped declaration until it is understood."
            )),
        })
        .collect()
}

/// Run one cbindgen pass and return its text.
///
/// A pass that silently renders nothing is deliberately NOT caught here. An
/// emptiness test at this level would be wrong: `mprintf.h` owns zero partition items, so a *correct* render
/// of it legitimately contributes no generated declarations, and rejecting an
/// empty body would fail a healthy build. The condition is instead caught in
/// [`generate_headers`], where the expected item set is known -- the
/// unconditional discovery-completeness check reports every missing name, and
/// [`undefined_abi_exports`] stops the common case before any pass runs.
fn render_binding(
    manifest: &Path,
    config: cbindgen::Config,
) -> Result<String, Box<dyn Error>> {
    begin_diagnostics();

    // Captured before the config is moved into cbindgen: a name excluded for
    // THIS pass is legitimately unresolvable in it.
    let excluded = config.export.exclude.clone();

    let bindings = cbindgen::Builder::new()
        .with_config(config)
        .with_crate(manifest)
        .generate()
        .map_err(|e| {
            format!(
                "cbindgen could not parse {}: {e}. The public headers are \
                 generated from this crate's Rust source, so they cannot be \
                 written until it parses.",
                manifest.display()
            )
        })?;

    // `Ok` from cbindgen is not evidence of a complete render. It downgrades
    // a missing module to a `log::warn!` and returns Ok, and because it
    // installs a logger only in its command-line binary, every such record is
    // discarded when it is used as a library. That is the fail-open behind
    // measured: a live run warned "can't find mod ffi", exited 0, and emitted
    // 6,672 bytes containing neither CURLE_OK nor curl_easy_init.
    let fatal = fatal_diagnostics(&take_diagnostics(), &excluded);
    if !fatal.is_empty() {
        return Err(format!(
            "cbindgen reported {} fatal diagnostic(s) while parsing {}. Each \
             one can silently drop declarations from the generated public \
             headers, so nothing is written:\n  {}",
            fatal.len(),
            manifest.display(),
            fatal.join("\n  ")
        )
        .into());
    }

    let mut out: Vec<u8> = Vec::new();
    bindings.write(&mut out);
    let text = String::from_utf8(out)
        .map_err(|e| format!("cbindgen produced non-UTF-8 output: {e}"))?;

    Ok(normalise_generated_c(&text))
}

/// Rewrite the two constructs cbindgen emits that the tree's own gates
/// reject: a `//` comment closing a preprocessor conditional, and a trailing
/// comma on an enumeration's last enumerator.
///
/// # The trailing enumerator comma
///
/// Measured, and the reason this rewrite exists at all. cbindgen writes each
/// enumerator as `NAME = value,` unconditionally, so the closing `}` of every
/// generated braced typedef is preceded by a comma. That spelling is legal in
/// C99 and later and in C++11 and later, and is a CONSTRAINT VIOLATION in C89
/// and in C++98: `gcc -std=c89 -pedantic` and `g++ -std=c++98 -pedantic` both
/// report "comma at end of enumerator list", which `-Werror` turns into a
/// failure. Measured across one full generation of the eight headers: 31
/// occurrences -- 23 in `curl.h`, 4 in `multi.h`, 2 in `urlapi.h`, 1 in
/// `header.h` and 1 in `options.h` -- and it is the ONLY construct in the
/// whole generated set that C89 rejects, so removing it is sufficient as well
/// as necessary.
///
/// The rewrite is deliberately narrow, in the same spirit as the comment
/// rewrite: the comma is dropped only when the NEXT line is precisely
/// `} <identifier>;`, which is the closing line of a `style = "type"` braced
/// typedef and nothing else. A struct's or union's last member ends in `;`, so
/// no field can match; a line inside a `/* ... */` documentation block never
/// ends in a comma followed by that closing form. Should a future cbindgen
/// interpose anything between the last enumerator and the brace, this rewrite
/// silently stops applying -- which is why [`check_source_hygiene`] asserts
/// the absence of the construct independently rather than trusting it.
///
/// # The `//` comment closing a preprocessor conditional
///
/// `scripts/checksrc.pl:162` defines CPPCOMMENTS and `:666` checks it, and
/// `include/curl/Makefile.am:36` runs checksrc over exactly these files,
/// reached from the root `make checksrc` target at `Makefile.am:166-172`,
/// which `Makefile.am:174` also aliases as `make lint`. Left alone, the
/// twelve occurrences measured in one run fail a live gate. Verified by
/// running that invocation against the generated headers: exit 0, zero
/// findings. `cbindgen.toml` records the same
/// reasoning where it declines to use `cpp_compat`, which would have emitted
/// `}  // extern "C"`, so converting the comment form honours that intent
/// rather than inventing a new policy.
fn normalise_generated_c(text: &str) -> String {
    let mut out = String::with_capacity(text.len());

    let lines: Vec<&str> = text.lines().collect();
    for (index, line) in lines.iter().enumerate() {
        let rewritten = rewrite_preprocessor_comment(line);
        let next = lines.get(index + 1).copied().unwrap_or_default();
        out.push_str(strip_terminal_enumerator_comma(&rewritten, next));
        out.push('\n');
    }

    out
}

/// The trailing-comma half of [`normalise_generated_c`], applied per line with
/// its successor as the only context.
///
/// Returns a borrow of `line` unchanged in every case but the one it targets,
/// so the common path allocates nothing beyond what the caller already holds.
fn strip_terminal_enumerator_comma<'a>(line: &'a str, next: &str) -> &'a str {
    match line.strip_suffix(',') {
        Some(head) if closes_braced_typedef(next) => head,
        _ => line,
    }
}

/// Whether `line` is the closing line of a `style = "type"` braced typedef,
/// i.e. exactly `} <identifier>;` at column zero.
///
/// The identifier test is explicit rather than a "starts with `}`" shortcut:
/// cbindgen also writes `} <identifier>;` for structs and unions, whose last
/// member ends in `;` and therefore cannot reach the comma branch above, but
/// it writes bare `}` and `};` in other positions and neither of those closes
/// a typedef whose members are comma-separated.
fn closes_braced_typedef(line: &str) -> bool {
    let Some(rest) = line.strip_prefix("} ") else {
        return false;
    };
    let Some(name) = rest.strip_suffix(';') else {
        return false;
    };
    !name.is_empty()
        && name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The single-line half of [`normalise_generated_c`].
fn rewrite_preprocessor_comment(line: &str) -> String {
    if !line.starts_with('#') {
        return line.to_string();
    }
    let Some(marker) = line.find("//") else {
        return line.to_string();
    };
    // A scheme separator is never a comment.
    if marker > 0 && line.as_bytes()[marker - 1] == b':' {
        return line.to_string();
    }
    let head = line[..marker].trim_end();
    let comment = line[marker + 2..].trim();
    if comment.is_empty() {
        return head.to_string();
    }
    format!("{head} /* {comment} */")
}

/// Collect every symbol this crate actually defines as a C export.
///
/// # A Rust function
///
/// A name is counted only when `#[no_mangle]` and an `extern "C"` definition
/// appear together, because either alone produces a symbol the dynamic linker
/// will not resolve under the exported name: `#[no_mangle]` without
/// `extern "C"` keeps the Rust ABI, and `extern "C"` without `#[no_mangle]`
/// keeps the mangled name.
///
/// # An assembly trampoline
///
/// The five plain-variadic `curl_m*printf` forms cannot be Rust functions at
/// the declared MSRV -- `extern "C" fn f(x: T, ...)` is `error[E0658]` -- so
/// they are emitted by `global_asm!` instead, each declaring its own `.globl`.
/// Those symbols are every bit as real as a `#[no_mangle]` function's, and a
/// scan that could not see them would report all five as undefined forever,
/// leaving the export-surface accounting permanently wrong in the one direction
/// that matters: it would understate what ships.
///
/// Both spellings a trampoline can use are matched. A hand-written label is
/// found by its `.globl`, in either the ELF or the Mach-O form, since Mach-O
/// decorates symbols with a leading underscore. A macro-generated label is
/// found by the `export = "name"` argument that becomes it, which is necessary
/// because the label is assembled with `concat!` and so never appears literally
/// in the source. That argument is only honoured in a file that actually
/// contains `global_asm!`, so prose or a table of names cannot be mistaken for
/// an emission.
///
/// # THE TWO MECHANISMS DO NOT REACH THE SAME ARTIFACT
///
/// This is the distinction [`ExportKind`] exists for, and it is measured
/// rather than reasoned about. A `#[no_mangle] pub extern "C"` function is in
/// rustc's export list for the `cdylib`, so it lands in **both**
/// `libcurl.so` and `libcurl.a`. A `global_asm!` label is not: rustc computes
/// the `cdylib` export list from Rust items and specification 0.6.4 measured
/// that this list "takes precedence" over anything a linker script asks for, so
/// an assembled label reaches `libcurl.a` and stops there.
///
/// Measured on this tree at the commit that introduced [`ExportKind`]:
/// `nm --defined-only libcurl.a` reports 59 `curl_*` symbols while
/// `nm -D --defined-only libcurl.so` reports 53, and the six in the archive
/// alone are exactly the assembled ones -- `curl_formadd`, `curl_maprintf`,
/// `curl_mfprintf`, `curl_mprintf`, `curl_msnprintf`, `curl_msprintf`.
///
/// So "implemented" has two honest meanings and the caller must say which it
/// wants. Both are counted for accounting, because 59 really are defined and a
/// scan that could not see the assembled six would understate what ships in the
/// archive. Only the dynamic set may gate header promotion, because a header is
/// a promise about `libcurl.so`: with the assembled names counted, this scan
/// would reach 100 of 100 and regenerate the public headers while the shared
/// object still exported 94, and every one of the 129 programs under
/// `docs/examples/` that called one of the six would fail to link against a
/// header that had just declared it.
///
/// The scan is textual on purpose. A build script cannot ask the compiler for
/// this set -- the crate has not been compiled yet, and the whole point of the
/// check is to run before anything is rendered. The post-link measurement is
/// still performed, by `.github/workflows/rust-abi.yml`'s leg A, which compares
/// `nm -D` over the built `cdylib` against `lib/libcurl.def` symmetrically;
/// that leg is the authority on what actually shipped, and this function is
/// what stops a header from being promoted before that leg could ever pass.
fn implemented_exports(
    manifest: &Path,
    kind: ExportKind,
) -> Result<Vec<String>, Box<dyn Error>> {
    let src = manifest.join("src");
    let mut names = Vec::new();
    let mut queue = vec![src.clone()];
    // `Any` is every mechanism, so it always counts an assembled label.
    // `Dynamic` counts one only while `promote_assembled_exports` is actually
    // promoting it: the label reaches `libcurl.so` because that version script
    // reaches the linker, and if no LLD is available it emits nothing and the
    // label stays archive-only. Deriving the answer from the same condition the
    // promotion uses is what keeps this parser and `nm -D` from disagreeing.
    let counts_assembled =
        kind == ExportKind::Any || assembled_exports_are_promoted();

    while let Some(current) = queue.pop() {
        let entries = fs::read_dir(&current)
            .map_err(|e| format!("cannot read {}: {e}", current.display()))?;
        for entry in entries {
            let entry = entry.map_err(|e| {
                format!(
                    "cannot read a directory entry \
                     under {}: {e}",
                    current.display()
                )
            })?;
            let path = entry.path();
            if path.is_dir() {
                queue.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let text = fs::read_to_string(&path)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?;

            if counts_assembled {
                names.extend(assembled_exports(&text));
            }

            // `#[no_mangle]` may be separated from the signature by further
            // attributes and doc comments, so the flag persists until a line
            // that is neither.
            let mut no_mangle = false;
            for line in text.lines() {
                let trimmed = line.trim();
                if trimmed.contains("#[no_mangle]") {
                    no_mangle = true;
                    continue;
                }
                if let Some(rest) = trimmed
                    .strip_prefix("pub unsafe extern \"C\" fn ")
                    .or_else(|| trimmed.strip_prefix("pub extern \"C\" fn "))
                {
                    if no_mangle {
                        let name: String = rest
                            .chars()
                            .take_while(|c| {
                                c.is_ascii_alphanumeric() || *c == '_'
                            })
                            .collect();
                        if !name.is_empty() {
                            names.push(name);
                        }
                    }
                    no_mangle = false;
                    continue;
                }
                if trimmed.is_empty()
                    || trimmed.starts_with("//")
                    || trimmed.starts_with("#[")
                    || trimmed.starts_with("#!")
                {
                    continue;
                }
                no_mangle = false;
            }
        }
    }

    names.sort();
    names.dedup();
    Ok(names)
}

/// Which artifact a caller of [`implemented_exports`] is asking about.
///
/// Not a boolean, because the two answers are not "more" and "less" of one
/// thing: they describe two different files, and the whole defect this enum
/// fixes was one number being used for both.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExportKind {
    /// Every symbol the crate defines by any mechanism -- what reaches
    /// `libcurl.a`. Honest accounting; NOT eligible to gate header promotion.
    Any,
    /// What reaches `libcurl.so`, which is what a public header promises:
    /// the symbols rustc places in the `cdylib` export list, plus the
    /// `global_asm!` labels while [`promote_assembled_exports`] is adding them
    /// to it. When no LLD is available nothing is promoted and this is the
    /// smaller set again, which is the whole reason it is derived rather than
    /// assumed.
    Dynamic,
}

/// Every C export this crate establishes through `global_asm!`, tree-wide.
///
/// The union of [`assembled_exports`] over `src/`, which is the subset of
/// [`implemented_exports`] that rustc's cdylib export list cannot see.
/// [`promote_assembled_exports`] writes exactly these names into the version
/// script it hands the linker, so the two can never disagree about which
/// symbols need promoting.
///
/// Measured today: six -- `curl_formadd` from `src/ffi/form.rs` and the five
/// plain-variadic `curl_m*printf` forms from `src/ffi/printf.rs`. The figure is
/// derived on every build rather than asserted, so it follows the source.
///
/// # Errors
///
/// If the source tree cannot be read.
fn assembled_export_names(
    manifest: &Path,
) -> Result<Vec<String>, Box<dyn Error>> {
    let mut names = Vec::new();
    for (_, text) in rust_sources(&manifest.join("src"))? {
        names.extend(assembled_exports(&text));
    }
    names.sort();
    names.dedup();
    Ok(names)
}

/// The C exports one source file establishes through `global_asm!`.
///
/// Documented at length on [`implemented_exports`]. Also reached by
/// [`assembled_export_names`], which unions it over the tree.
/// Kept separate so the two mechanisms can be reasoned about -- and tested --
/// independently of each other.
fn assembled_exports(text: &str) -> Vec<String> {
    // Without this, a table of names or a paragraph of prose in any file would
    // read as an emission. The label and the macro argument only mean anything
    // in a file that actually assembles something.
    if !text.contains("global_asm!") {
        return Vec::new();
    }

    let code = strip_rust_comments(text);
    let mut names = Vec::new();

    // Both markers are scanned over the whole text rather than one being tried
    // first, because `.globl _foo` matches the shorter marker too. The
    // `curl_` requirement resolves it: the shorter marker yields `_foo`, which
    // is discarded, and the longer yields `foo`, which is kept when it is one
    // of ours.
    for marker in [".globl ", ".globl _", "export = \""] {
        let mut rest = code.as_str();
        while let Some(at) = rest.find(marker) {
            rest = &rest[at + marker.len()..];
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if name.starts_with("curl_") {
                names.push(name);
            }
        }
    }

    names
}

/// Every one of the 100 exported symbols this crate does not yet define.
///
/// This is the number every human-facing diagnostic must quote, because it is
/// the number that decides whether the artifact is a drop-in replacement.
///
/// **Do not quote a literal for it.** Every build prints the live figure as a
/// `cargo:warning`, and that is the number to read; a figure written into a doc
/// comment is correct on the day it is written and misleading afterwards, which
/// is how an earlier revision of this comment came to claim 76 while the build
/// was printing 41. The count moves with every export that lands.
///
/// No carrier subtraction. A previous version of this function filtered out
/// the verbatim carriers before filtering out the implemented names, on the
/// reasoning that a carrier's declaration is literal prologue text and so
/// cannot truncate a generated header. That reasoning is correct about
/// TRUNCATION and wrong about the gate: a header that DECLARES a function the
/// library does not EXPORT does not produce a shorter header, it produces an
/// undefined reference in every one of the 129 programs under `docs/examples/`
/// that calls it. Subtracting the carriers made the advisory report the smaller
/// [`declaration_gap`] figure in place of this one, and made this function
/// contradict the rule [`generate_headers`] documents as "while any of the 100
/// symbols in `lib/libcurl.def` is undefined in this crate, generate nothing".
/// The two differ by the number of undefined names that are carriers, which the
/// build prints alongside both.
///
/// The truncation-only subset is still worth knowing, and is
/// [`declaration_gap`].
///
/// # Why the DYNAMIC set, not every definition
///
/// [`ExportKind::Dynamic`] is deliberate and is the whole of this function's
/// correctness. A header is a promise about `libcurl.so`; asking whether a name
/// is defined *anywhere* answers a question about `libcurl.a` instead. The six
/// `global_asm!` labels are defined and do reach the archive, and counting them
/// here would let this function report 0 undefined -- and regenerate the public
/// headers -- while the shared object was still six short. That is a
/// fail-OPEN, and the symbols it would silently declare are precisely the ones
/// no `docs/examples/` program could then link against.
///
/// Those six are therefore reported as undefined until they have
/// cdylib-exportable definitions, which is not a fiction about the archive:
/// [`static_only_abi_exports`] names them separately so the two facts stay
/// distinguishable, and the advisory quotes both.
fn undefined_abi_exports(
    manifest: &Path,
    root: &Path,
) -> Result<Vec<String>, Box<dyn Error>> {
    let expected = exported_symbols(root)?;
    let implemented = implemented_exports(manifest, ExportKind::Dynamic)?;

    Ok(expected
        .into_iter()
        .filter(|name| !implemented.iter().any(|i| i == name))
        .collect())
}

/// The exported symbols this crate defines ONLY in `global_asm!`, and which
/// therefore reach `libcurl.a` but not `libcurl.so`.
///
/// The difference between the two [`ExportKind`] answers, intersected with the
/// 100 names `lib/libcurl.def` requires so that an assembled helper which is
/// not part of the ABI cannot appear here. Measured today: EMPTY, because
/// [`promote_assembled_exports`] puts all six labels in the cdylib's export
/// table. It becomes the six again on a toolchain with no `ld.lld`, which is
/// the configuration this accounting exists for.
///
/// Reported beside [`undefined_abi_exports`] rather than folded into it. The two
/// are different obligations with different remedies -- an undefined symbol
/// needs writing, whereas one of these needs a `#[no_mangle] pub extern "C"`
/// definition to replace or wrap its label -- and a reader who is told only
/// "undefined" for a name they can see in the archive will go looking for the
/// wrong thing.
fn static_only_abi_exports(
    manifest: &Path,
    root: &Path,
) -> Result<Vec<String>, Box<dyn Error>> {
    let expected = exported_symbols(root)?;
    let any = implemented_exports(manifest, ExportKind::Any)?;
    let dynamic = implemented_exports(manifest, ExportKind::Dynamic)?;

    Ok(any
        .into_iter()
        .filter(|name| !dynamic.iter().any(|d| d == name))
        .filter(|name| expected.iter().any(|e| e == name))
        .collect())
}

/// Assert that the blocked-gate declarations still describe this workspace.
///
/// `[workspace.metadata.curl-rs.blocked-aap-gates]` records, per row, a
/// requirement of the frozen specification that this build does NOT satisfy,
/// together with what it delivers instead. The value of that table depends
/// entirely on its being current, and the failure mode is silent: a pin gets
/// bumped, the row keeps describing the old one, and a reader is told a gate is
/// blocked when it has in fact been closed - or, worse, is told which version is
/// delivered and given the wrong one.
///
/// That is not a hypothetical risk in this tree. `curl-rs-lib/src/version.rs`
/// carried "the file does not exist" about `mime/mod.rs` and
/// `util/parsedate.rs` long after both had landed, and only a review caught it.
/// A prose comment cannot be checked; a `delivered` string that must appear
/// verbatim in the manifest can.
///
/// So each row's `delivered = "..."` is required to be a literal substring of
/// the workspace manifest. That is deliberately a weaker claim than parsing the
/// dependency graph and a much stronger one than a comment: it pins the row to
/// the exact text it is a statement about, so the two cannot drift apart
/// without failing this build.
///
/// # What it does NOT do
///
/// It does not re-verify that the blocked gate is still blocked - that a version
/// is still yanked, or an advisory still unpatched. Those are properties of
/// crates.io and the advisory database, and a build script has no business
/// reaching for either. `cargo deny` and `cargo audit` own that question, and
/// each row carries the exact command and output that established it so a reader
/// can re-run it.
fn check_blocked_aap_gates(root: &Path) -> Result<(), Box<dyn Error>> {
    let path = root.join("Cargo.toml");
    let manifest = fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;

    let table = "[workspace.metadata.curl-rs.blocked-aap-gates";
    if !manifest.contains(table) {
        return Err(format!(
            "{} declares no {table}] table. Every specification requirement \
             this build does not satisfy is recorded there; an empty workspace \
             would be a claim of full compliance, and if that is genuinely the \
             case the table should say so explicitly rather than be deleted.",
            path.display()
        )
        .into());
    }

    // One pass over the rows, reading only the two fields this check is about.
    // A TOML parser would be the obvious tool and is deliberately not used:
    // adding a build-dependency to assert a property of the manifest would put
    // a crate in the graph for the sake of describing the graph.
    let mut rows = 0usize;
    let mut current: Option<&str> = None;

    for line in manifest.lines() {
        let trimmed = line.trim();

        if let Some(rest) = trimmed.strip_prefix(&format!("{table}.")) {
            current = rest.strip_suffix(']');
            if current.is_some() {
                rows += 1;
            }
            continue;
        }
        // Any other table header ends the block; the rows are contiguous.
        if trimmed.starts_with('[') && !trimmed.starts_with(table) {
            current = None;
            continue;
        }

        let Some(name) = current else { continue };
        let Some(value) = trimmed.strip_prefix("delivered = ") else {
            continue;
        };

        // The value is a TOML basic string. Exactly ONE delimiter is stripped
        // from each end and only then are the escapes resolved, in that order:
        // `trim_matches('"')` would eat the closing delimiter and leave the
        // backslash of a trailing `\"` behind, turning
        // `"russh = \"=0.54.5\""` into `russh = \"=0.54.5\` -- a literal that
        // matches nothing and fails this check on a row that is perfectly
        // correct. Measured, on the first run of this function.
        let body = value.trim();
        let body = body.strip_prefix('"').unwrap_or(body);
        let body = body.strip_suffix('"').unwrap_or(body);
        let literal = body.replace("\\\"", "\"");
        if literal.is_empty() {
            return Err(format!(
                "blocked-aap-gates row {name:?} declares an empty `delivered`, \
                 so it says nothing about what this build actually ships"
            )
            .into());
        }

        // A row whose `delivered` is prose rather than a pin is legitimate --
        // mime_guess's and hickory-dns's are sentences, because what is
        // delivered in those two cases is code and a feature name rather than a
        // dependency -- so the substring test applies only to rows that quote a
        // manifest pin, identified by the `= "=` of an exact version
        // requirement. The quoted text must be a substring and NOT a whole line,
        // because a pin may carry `default-features` and `features` after its
        // version and a row should not have to restate them to stay honest about
        // the version.
        if literal.contains("= \"=") && !manifest.contains(&literal) {
            return Err(format!(
                "blocked-aap-gates row {name:?} says this build delivers \
                 `{literal}`, but that line is not in {}. The row has gone \
                 stale: either the pin moved and the row must move with it, or \
                 the gate is no longer blocked and the row must be removed.",
                path.display()
            )
            .into());
        }
    }

    if rows == 0 {
        return Err(format!(
            "{} declares the blocked-aap-gates table but no rows under it. An \
             empty table is indistinguishable from a forgotten one; state full \
             compliance explicitly if that is what is meant.",
            path.display()
        )
        .into());
    }

    Ok(())
}

/// Assert that the two [`ExportKind`] answers are still different answers.
///
/// The distinction they draw is the only thing standing between
/// [`undefined_abi_exports`] and a fail-open, and it is one condition wide:
/// `implemented_exports` skips [`assembled_exports`] under
/// [`ExportKind::Dynamic`]. A refactor that "simplified" that condition away
/// would restore the original defect exactly, and nothing would notice --
/// the build would still succeed, the headers would still be withheld today,
/// and only once the last Rust-defined export landed would the gate promote a
/// header six symbols ahead of the shared object.
///
/// So the property is asserted while it is cheap: as long as this crate
/// assembles at least one ABI label with no `#[no_mangle]` definition, the two
/// sets MUST differ. The check is self-retiring rather than a fixed count --
/// giving one of the eleven a `#[no_mangle]` wrapper legitimately moves it into
/// the dynamic set, and when the last one moves the sets coincide and this
/// check stops asserting anything, which is correct because by then there is
/// nothing left to distinguish.
fn check_export_kinds_are_distinguished(
    manifest: &Path,
    root: &Path,
) -> Result<(), Box<dyn Error>> {
    let any = implemented_exports(manifest, ExportKind::Any)?;
    let dynamic = implemented_exports(manifest, ExportKind::Dynamic)?;

    for name in &dynamic {
        if !any.contains(name) {
            return Err(format!(
                "{name} is counted as a dynamic export but not as a \
                 definition at all, which is impossible: ExportKind::Dynamic \
                 must be a subset of ExportKind::Any"
            )
            .into());
        }
    }

    let static_only = static_only_abi_exports(manifest, root)?;
    if static_only.is_empty() && any.len() == dynamic.len() {
        // Both sets agree AND no ABI name is archive-only. Either every
        // trampoline now has a Rust definition -- in which case there is
        // nothing to distinguish and this is the finished state -- or the
        // distinction has been lost. Tell them apart by looking for the
        // trampolines themselves rather than assuming.
        if crate_assembles_abi_labels(manifest)?
            && !assembled_exports_are_promoted()
        {
            return Err("this crate still assembles exported ABI labels in \
                 global_asm!, yet ExportKind::Any and ExportKind::Dynamic \
                 report the same set. A global_asm! label reaches libcurl.a \
                 and not libcurl.so, so collapsing the two would let \
                 undefined_abi_exports reach 100 of 100 and promote a public \
                 header while the shared object was still short -- the \
                 fail-open ExportKind exists to prevent. Restore the \
                 ExportKind::Any condition in implemented_exports."
                .into());
        }
    }

    Ok(())
}

/// Whether this crate assembles at least one exported ABI label.
///
/// The companion to [`check_export_kinds_are_distinguished`]: it is what
/// distinguishes "the trampolines are gone" from "the accounting stopped
/// seeing them". Scans for the labels themselves, over the same source walk
/// [`implemented_exports`] performs, so the two cannot disagree about which
/// files exist.
fn crate_assembles_abi_labels(manifest: &Path) -> Result<bool, Box<dyn Error>> {
    let mut queue = vec![manifest.join("src")];

    while let Some(current) = queue.pop() {
        let entries = fs::read_dir(&current)
            .map_err(|e| format!("cannot read {}: {e}", current.display()))?;
        for entry in entries {
            let path = entry
                .map_err(|e| {
                    format!(
                        "cannot read a directory entry under {}: {e}",
                        current.display()
                    )
                })?
                .path();
            if path.is_dir() {
                queue.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let text = fs::read_to_string(&path)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            if !assembled_exports(&text).is_empty() {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

/// Publish the ABI export inventory where a consumer can READ it, and return
/// whether the surface is complete.
///
/// # Why a printed warning is not enough
///
/// While the export surface is incomplete, [`generate_headers`] writes no
/// header and says so with `cargo:warning`. That is the right behaviour and the
/// wrong interface. A `cargo:warning` is text on a terminal: nothing downstream
/// can branch on it, so a continuous-integration job that packages a software
/// development kit, or one that asserts a header was regenerated, has no way to
/// discover that generation was WITHHELD rather than unnecessary. Both then do
/// the wrong thing confidently -- one ships frozen headers declaring 100
/// symbols beside a library defining fewer, the other fails for a reason it
/// cannot name.
///
/// So the same facts are published three ways, each for a different consumer,
/// and all three from this one computation so they cannot disagree:
///
/// 1. `$OUT_DIR/abi-inventory.txt`, a stable line-oriented format for shell and
///    for continuous integration. `cargo build --message-format=json` reports
///    `out_dir` on the `build-script-executed` record, which is how a job
///    locates it without guessing a hash directory.
/// 2. `cargo:rustc-env` values, which make the counts available to
///    `env!()` inside this crate -- see `ABI_EXPORTS_REQUIRED` and its
///    siblings in `src/lib.rs`. This is the half that a Rust consumer, and this
///    crate's own tests, can assert on at COMPILE time.
/// 3. The existing `cargo:warning` lines, kept because a human reading a build
///    log is also a consumer.
///
/// # Format
///
/// One `key=value` per line, then one `missing-export=<name>` per undefined
/// export in `lib/libcurl.def` order. Deliberately not JSON: every consumer of
/// it is a shell or an `awk` script, and a format they can read with `grep`
/// needs no parser to be trusted.
///
/// The per-name key is spelled differently from the `missing` COUNT on purpose.
/// Sharing one key made `grep -c '^missing='` return the count plus one, which
/// is the kind of off-by-one a consumer discovers late and blames on the tree.
///
/// ```text
/// required=100
/// defined=59
/// missing=41
/// declaration-gap=35
/// headers-generated=0
/// missing-family=multi 21
/// missing-family=easy 13
/// missing-family=ws 4
/// missing-family=share 3
/// missing-export=curl_easy_cleanup
/// ...
/// ```
///
/// That is the real output of this checkout, copied from
/// `$OUT_DIR/abi-inventory.txt` rather than composed here -- the first draft of
/// this block listed the families alphabetically and so contradicted the
/// ordering the paragraph below specifies.
///
/// The `missing-family` lines are a grouping of the same names by the `curl_`
/// prefix segment that follows, emitted highest count first with ties broken
/// alphabetically so the output is stable across builds. They exist because
/// "41 undefined" and "41 undefined, falling in four families whose modules are
/// three absent files plus one partly-written one" are different pieces of
/// information, and only the second says what has to happen. A name with no
/// second underscore-separated segment is grouped under its whole spelling
/// rather than dropped, so the family counts always sum to `missing` --
/// [`crate::abi_inventory`]'s siblings in `src/lib.rs` assert that.
///
/// `headers-generated` is the field the packaging and header gates turn on. It
/// is `1` only when this run promoted a complete set of headers, so it answers
/// "is this build's C surface trustworthy" rather than "did a file happen to
/// change".
///
/// # Errors
///
/// If the export list or this crate's sources cannot be read, or `$OUT_DIR`
/// cannot be written.
fn publish_abi_inventory(
    manifest: &Path,
    root: &Path,
) -> Result<bool, Box<dyn Error>> {
    let required = exported_symbols(root)?;
    let missing = undefined_abi_exports(manifest, root)?;
    let truncating = declaration_gap(&missing);
    let complete = missing.is_empty();

    let mut inventory = String::new();
    inventory.push_str(&format!("required={}\n", required.len()));
    inventory
        .push_str(&format!("defined={}\n", required.len() - missing.len()));
    inventory.push_str(&format!("missing={}\n", missing.len()));
    inventory.push_str(&format!("declaration-gap={}\n", truncating.len()));
    inventory.push_str(&format!("headers-generated={}\n", u8::from(complete)));
    for (family, count) in missing_families(&missing) {
        inventory.push_str(&format!("missing-family={family} {count}\n"));
    }
    for name in &missing {
        inventory.push_str(&format!("missing-export={name}\n"));
    }

    let out = PathBuf::from(env_var("OUT_DIR")?).join("abi-inventory.txt");
    write_if_changed(&out, &inventory)?;

    // The compile-time half. Emitted unconditionally, including when the
    // surface is complete, so that a consumer's `env!` never has to cope with
    // the variable being absent.
    println!("cargo:rustc-env=CURL_RS_ABI_REQUIRED={}", required.len());
    println!(
        "cargo:rustc-env=CURL_RS_ABI_DEFINED={}",
        required.len() - missing.len()
    );
    println!(
        "cargo:rustc-env=CURL_RS_ABI_HEADERS_GENERATED={}",
        u8::from(complete)
    );

    Ok(complete)
}

/// Group undefined export names by API family, largest family first.
///
/// The family is the segment after the `curl_` prefix -- `easy` from
/// `curl_easy_init`, `multi` from `curl_multi_socket_action`. That is the same
/// partition the target design uses to assign one module per family, which is
/// what makes the grouping actionable: a family's count is the number of entry
/// points one file has to define.
///
/// A name that does not fit the pattern is grouped under its own full spelling
/// rather than discarded, so the counts always sum to the input length. This is
/// not defensive padding -- six of the currently undefined names are
/// `curl_mprintf` and its siblings, which have no second segment at all, and an
/// implementation that dropped them would report a total that quietly
/// disagreed with `missing`.
///
/// Ordering is by descending count then ascending name, so the output is a
/// function of the input alone and does not move between builds on the same
/// tree. `write_if_changed` compares file contents, so an unstable order would
/// rewrite `$OUT_DIR` on every build and invalidate the crate's cache.
fn missing_families(undefined: &[String]) -> Vec<(String, usize)> {
    let mut families: Vec<(String, usize)> = Vec::new();

    for name in undefined {
        let family = family_of(name);
        match families.iter_mut().find(|(seen, _)| *seen == family) {
            Some((_, count)) => *count += 1,
            None => families.push((family, 1)),
        }
    }

    families.sort_by(|left, right| {
        right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0))
    });
    families
}

/// The API family an exported name belongs to.
///
/// `curl_easy_init` is `easy`; `curl_mprintf`, which has nothing after the
/// prefix to split on, is `curl_mprintf`. See [`missing_families`] for why the
/// fallback returns the whole name rather than nothing.
fn family_of(name: &str) -> String {
    name.strip_prefix("curl_")
        .and_then(|rest| rest.split_once('_'))
        .map_or_else(|| name.to_string(), |(family, _)| family.to_string())
}

/// The subset of [`undefined_abi_exports`] whose absence would make a
/// generated header SHORT, as opposed to making it declare an export that
/// does not exist.
///
/// A verbatim carrier's declaration is literal text spliced into the prologue,
/// so the header declares it whatever the crate contains; the undefined names
/// that ARE carriers are therefore not in this set. Both figures are printed by
/// every build rather than written here, for the reason
/// [`undefined_abi_exports`] gives. Reported alongside
/// the export gap rather than instead of it, because the two numbers answer
/// different questions and quoting either one alone has already misled a
/// review once.
fn declaration_gap(undefined: &[String]) -> Vec<String> {
    let carriers: Vec<String> = VERBATIM_CARRIERS
        .iter()
        .flat_map(|(_, blocks)| blocks.iter())
        .flat_map(|block| verbatim_callables(block))
        .collect();

    undefined
        .iter()
        .filter(|name| !carriers.iter().any(|c| c == *name))
        .cloned()
        .collect()
}

/// Generate `include/curl/curl.h` and its seven generated siblings.
///
/// Nine cbindgen passes: one to discover the full set of items the crate
/// exposes, then one per header. The discovery pass is what makes the
/// partition complete rather than merely plausible -- without it, the
/// exclusion lists could only name items this file happens to enumerate,
/// and anything else would be emitted into all eight headers at once.
///
/// Nothing is written until every header has been rendered AND validated, and
/// nothing is written at all while the export surface is incomplete. Four
/// checks stand between a cbindgen pass and the tracked files, in increasing
/// order of specificity:
///
/// 1. [`undefined_abi_exports`] -- while any of the 100 symbols in
///    `lib/libcurl.def` is undefined in this crate, generate nothing and leave
///    the reviewed curl 8.19.0-DEV headers exactly as they are. This subsumes
///    the case where the ABI module is absent altogether, because a crate that
///    defines no exports is missing all 100 of them.
/// 2. Discovery non-vacuity -- an empty discovery set, or an expected set that
///    intersects no public enum, is itself an error. Both are what a module
///    cbindgen could not parse produces, and both would otherwise make every
///    later check pass over a header containing nothing.
/// 3. Discovery completeness -- every expected item must actually have been
///    emitted by the discovery pass, unconditionally. Testing each item only
///    if it had already been observed would make the check vacuous in exactly
///    the case it exists to catch.
/// 4. Per-header ownership, in both directions -- no header may declare a name
///    another header owns, and no header may omit a name it owns. This one is
///    scoped to observed items on purpose: an item that was never emitted is
///    already reported by check 3, and reporting it again per header would bury
///    the cause in noise.
fn generate_headers(
    manifest: &Path,
    root: &Path,
) -> Result<(), Box<dyn Error>> {
    // PREFLIGHT FIRST, AHEAD OF THE EXPORT-SURFACE GATE BELOW.
    preflight_modules(manifest)?;
    // Likewise preflight: a variadic strategy this target's ABI cannot honour
    // must stop the build before any header advertises symbols it cannot keep.
    check_variadic_strategy(manifest)?;
    // And the same obligation, discharged per symbol, for the five
    // plain-variadic printf forms that are assembled rather than compiled.
    check_printf_trampolines(manifest)?;
    // The eleventh of the same family, whose argument list is open-ended rather
    // than format-driven but whose exported name is assembled for the same
    // reason.
    check_formadd_trampoline(manifest)?;
    // And the invariant that keeps the eleven from being counted as shared
    // exports, which is what decides whether the gate below can fail open.
    check_export_kinds_are_distinguished(manifest, root)?;

    // THE SECOND THING THIS FUNCTION DOES, AND DELIBERATELY BEFORE ANY RENDER.
    //
    // The headers under include/curl/ are the reference ABI contract: 100
    // exported symbols, the CURLcode and CURLoption integers, and the
    // declarations that all 129 programs under docs/examples/ compile
    // against. While this crate defines only part of that surface, cbindgen
    // observes only the part that exists, so every rendered header is short
    // by exactly what is missing -- and promoting it would REPLACE the
    // complete contract with a truncated one. Measured on this tree: with 24
    // of the 100 symbols defined, regeneration dropped curl_easy_init,
    // curl_easy_perform, curl_easy_cleanup and curl_easy_duphandle from
    // easy.h, among 3,289 deleted lines across eight headers.
    //
    // Erroring is not the answer either: the missing symbols are unwritten
    // work, not a defect, and a build script that fails the workspace until
    // the last of 100 exports lands would make the tree unbuildable for the
    // entire migration. So the only posture that is both honest and useful is
    // to write NOTHING and say so. `rerun-if-changed=src` means the moment
    // the surface completes, this guard stops firing and generation resumes
    // with no further intervention.
    //
    // HOW IT SAYS SO, AND WHY NOT AS A WARNING. This used to be two
    // `cargo:warning=` lines. That channel was wrong for it: specification
    // 0.8.4's first gate is a ZERO-WARNING build, and a `cargo:warning=` is a
    // warning-class diagnostic, so a normal build could not satisfy the gate
    // and the only way to call it satisfied was to allow-list these two lines
    // -- which is not a zero-warning gate, it is a zero-unapproved-warning
    // gate. The message is not a warning in any case: it reports unwritten
    // work, and nothing in the build is wrong.
    //
    // So it goes to a channel that carries state rather than fault, and both
    // halves of that are load-bearing. `eprintln!` puts it in the build log
    // where `cargo build -vv` and any failing build already show it. The
    // OUT_DIR file makes it durable and greppable at a fixed path, so a
    // workflow or a reader can consult the live figure without re-running the
    // build and without parsing cargo's output. Neither is warning-class, and
    // the gate is now something a normal build can actually pass.
    //
    // AND WHY THERE IS ALSO A HARD GATE. A build-script diagnostic on any
    // channel is text: `-D warnings` reaches rustc and clippy and does not
    // reach a build script, so nothing in the pipeline could FAIL on an
    // artifact short of the 100 names in `lib/libcurl.def`. `STRICT_ABI_ENV`
    // closes that. The legs whose job is to certify the artifact set it and
    // get a hard error naming every missing symbol; everybody else gets the
    // state report above and a working build.
    // Publish the inventory BEFORE the decision it describes, so that the
    // withholding below is a fact a consumer can read rather than a warning it
    // has to notice. See `publish_abi_inventory` for why the printed warning
    // alone left both the packaging gate and the header gate unable to tell
    // "withheld" from "unnecessary".
    let complete = publish_abi_inventory(manifest, root)?;

    let missing = undefined_abi_exports(manifest, root)?;
    debug_assert_eq!(complete, missing.is_empty());
    if !missing.is_empty() {
        let total = exported_symbols(root)?.len();
        let truncating = declaration_gap(&missing).len();
        if env::var_os(STRICT_ABI_ENV).is_some_and(|value| !value.is_empty()) {
            // The same facts as the warning below, as an error, and with the
            // whole list rather than a preview: a gate failure is read once by
            // somebody who needs to act on it, so truncating it would only
            // send them back to the build script.
            return Err(format!(
                "{STRICT_ABI_ENV} is set and the export surface is \
                 incomplete: {} of the {} symbols in lib/libcurl.def are not \
                 defined in this crate, so libcurl.so.4 cannot be a drop-in \
                 replacement and include/curl/ was not regenerated. {} of the \
                 {} are rendered from Rust items. Missing: {}",
                missing.len(),
                total,
                truncating,
                missing.len(),
                missing.join(", ")
            )
            .into());
        }
        let static_only = static_only_abi_exports(manifest, root)?;
        let preview: Vec<&str> =
            missing.iter().take(8).map(String::as_str).collect();

        let mut notice = format!(
            "include/curl/ NOT regenerated: {} of the {} exported symbols in \
             lib/libcurl.def do not yet have a definition that reaches \
             libcurl.so. {} of those {} are rendered from Rust items, so \
             every generated header would be short by exactly those; the \
             remaining {} are carried verbatim and would still be DECLARED, \
             which is worse rather than better -- a declaration without an \
             export is an undefined reference in every docs/examples program \
             that calls it. The existing headers are left untouched and \
             remain the ABI contract. Generation resumes automatically once \
             the export surface is complete.\n\
             first missing exports: {}{}\n",
            missing.len(),
            total,
            truncating,
            missing.len(),
            missing.len() - truncating,
            preview.join(", "),
            if missing.len() > preview.len() {
                format!(", and {} more", missing.len() - preview.len())
            } else {
                String::new()
            }
        );

        // Counted among the missing above, and named again here because the
        // remedy differs. These have a definition -- it just does not reach a
        // cdylib -- so a reader who found them with `nm` on libcurl.a and was
        // told only "not yet defined" would go looking for the wrong thing.
        if !static_only.is_empty() {
            notice.push_str(&format!(
                "of those, {} are defined in global_asm! and reach \
                 libcurl.a but NOT libcurl.so, because rustc computes the \
                 cdylib export list from Rust items: {}. They are counted as \
                 missing on purpose -- a header promoted on the strength of \
                 an archive-only definition would declare a symbol the \
                 shared object does not export. Each needs a \
                 #[no_mangle] pub extern \"C\" definition, or a wrapper that \
                 has one.\n",
                static_only.len(),
                static_only.join(", ")
            ));
        }

        // The log copy. Build-script stderr is not a warning class, so this
        // costs the zero-warning gate nothing.
        eprint!("{notice}");

        // The durable copy, at a path derived from OUT_DIR rather than guessed.
        let out_dir = PathBuf::from(env_var("OUT_DIR")?);
        let notice_path = out_dir.join(HEADER_NOTICE);
        fs::write(&notice_path, &notice).map_err(|e| {
            format!("cannot write {}: {e}", notice_path.display())
        })?;

        return Ok(());
    }

    // The surface is complete, so any notice from a previous build describes a
    // state that no longer holds. Removed rather than left behind: a stale file
    // saying the headers were not regenerated, sitting beside headers that were,
    // is worse than no file at all.
    {
        let out_dir = PathBuf::from(env_var("OUT_DIR")?);
        let notice_path = out_dir.join(HEADER_NOTICE);
        if notice_path.exists() {
            fs::remove_file(&notice_path).map_err(|e| {
                format!("cannot remove {}: {e}", notice_path.display())
            })?;
        }
    }

    // The source-level half of the declared-FORM assertion, and the half that
    // gives the better diagnosis, so it runs before any render: an ABI enum
    // the headers generate must carry #[repr(C)]. Deferring it until after the
    // discovery pass still caught both defect shapes, but a missing
    // representation surfaced as cbindgen's generic "Can't find <type>"
    // instead of naming the attribute to restore.
    let enum_reprs = public_enum_reprs(manifest)?;
    let public_enums: Vec<String> =
        enum_reprs.iter().map(|(name, _)| name.clone()).collect();
    let generated_names: Vec<&str> = all_partition_items()
        .into_iter()
        .chain(CURL_H_GENERATED_DESPITE_EXCLUSION.iter().copied())
        .collect();

    for (name, repr) in &enum_reprs {
        if !generated_names.iter().any(|item| item == name) {
            continue;
        }
        if repr != "C" {
            let declared = if repr.is_empty() {
                "no #[repr(...)] at all".to_string()
            } else {
                format!("#[repr({repr})]")
            };
            return Err(format!(
                "the public enum {name} is generated into the headers but \
                 declares {declared}. cbindgen emits such an enum as \
                 `typedef {} {name};` instead of a braced typedef, keeping \
                 every member name and value -- so the Rust build stays green, \
                 every unit test passes, and only the C type a consumer sees \
                 changes. AAP 0.6.1 requires the integers to be pinned by \
                 #[repr(C)] with explicit discriminants.",
                if repr.is_empty() { "int" } else { repr }
            )
            .into());
        }
    }

    let config_path = manifest.join("cbindgen.toml");
    let base = cbindgen::Config::from_file(&config_path)
        .map_err(|e| format!("cannot load {}: {e}", config_path.display()))?;

    let banner = shared_banner(&base)?;

    // Names written by hand, whether by a sibling's per-header text or by
    // `curl.h`'s own. Suppressed in every pass, this one included, so nothing
    // is both generated and written verbatim.
    let verbatim: Vec<String> = all_verbatim_names()
        .iter()
        .chain(CURL_H_VERBATIM_NAMES.iter())
        .map(|n| (*n).to_string())
        .collect();

    // Discovery. Every partition's items are forced so that enums reachable
    // only from excluded prototypes are counted too, and so is the one name
    // whose `cbindgen.toml` exclusion this script lifts.
    let mut discovery = base.clone();
    let every_item: Vec<&str> = PARTITIONS
        .iter()
        .flat_map(|(_, items)| items.iter().copied())
        .chain(CURL_H_GENERATED_DESPITE_EXCLUSION.iter().copied())
        .collect();
    apply_partition(&mut discovery, &every_item, &verbatim);
    let discovery_text = render_binding(manifest, discovery)?;
    let observed = declared_names(generated_region(
        &discovery_text,
        base.header.as_deref().unwrap_or_default(),
        base.trailer.as_deref().unwrap_or_default(),
    ));

    // The discovery set is what every downstream partition check is measured
    // against, so a check that consults it is only as strong as it is
    // populated. Before this guard existed the per-header assertion read
    // `if observed.contains(item) && !declared.contains(item)`, which is
    // VACUOUSLY TRUE for every item when `observed` is empty -- and an empty
    // `observed` is exactly what a dropped module produces. The 205-item
    // assertion that was supposed to be the oracle could therefore pass
    // over a header containing nothing at all.
    let expected: Vec<&str> = every_item
        .iter()
        .copied()
        .filter(|item| public_enums.iter().any(|name| name == item))
        .collect();

    if observed.is_empty() {
        return Err(format!(
            "the cbindgen discovery pass observed no declarations at all, \
             although the header partition claims {} items. Every per-header \
             completeness check is measured against this set, so continuing \
             would validate the headers against nothing.",
            every_item.len()
        )
        .into());
    }
    if expected.is_empty() {
        return Err(format!(
            "no partition item is a public enum, although {} of them exist in \
             {}. The discovery check derives its expected set from that \
             intersection, so an empty intersection means the check cannot \
             fail and must not be trusted.",
            public_enums.len(),
            manifest.join("src").join("ffi").display()
        )
        .into());
    }

    let undiscovered: Vec<&str> = expected
        .iter()
        .copied()
        .filter(|item| !observed.iter().any(|name| name == item))
        .collect();
    if !undiscovered.is_empty() {
        return Err(format!(
            "the cbindgen discovery pass did not observe {} of {} expected \
             public enums: {}. cbindgen reports a module it cannot parse as a \
             warning and returns Ok, so a whole file's declarations can \
             disappear without any error; the headers are not written.",
            undiscovered.len(),
            expected.len(),
            undiscovered.join(", ")
        )
        .into());
    }

    let sibling_items = all_sibling_items();
    let include_dir = root.join("include").join("curl");

    // Nothing reaches include/curl until every header below has been rendered
    // AND validated. See `HeaderTransaction` for why the set is promoted
    // together: the eight headers are one partition of one ABI contract, and a
    // mixture of old and new has never been reviewed and need not be valid C.
    let mut transaction = HeaderTransaction::new();

    // The umbrella. Its guard, banner, `extern "C"` open, `#include` block,
    // guard close and sibling includes all come from cbindgen.toml
    // untouched, because that file is the single configuration and restating
    // them here is the duplication the rule exists to prevent. What this
    // script adds is the interior verbatim text cbindgen.toml delegates to it
    // at ":968-975": the forward declarations before the generated block and
    // the definitions after it.
    let umbrella_forward = umbrella_after_includes();
    let umbrella_trailer =
        umbrella_epilogue(base.trailer.as_deref().unwrap_or_default());

    let mut umbrella = base.clone();
    umbrella.after_includes = Some(umbrella_forward.clone());
    umbrella.trailer = Some(umbrella_trailer.clone());

    let umbrella_owned: Vec<&str> = CURL_H_ITEMS
        .iter()
        .copied()
        .chain(CURL_H_GENERATED_DESPITE_EXCLUSION.iter().copied())
        .collect();
    let umbrella_suppress: Vec<String> = verbatim
        .iter()
        .cloned()
        .chain(
            observed
                .iter()
                .filter(|name| sibling_items.contains(&name.as_str()))
                .cloned(),
        )
        .collect();
    apply_partition(&mut umbrella, &umbrella_owned, &umbrella_suppress);
    let umbrella_text = render_binding(manifest, umbrella)?;
    check_source_hygiene("curl.h", &umbrella_text, HEADER_MAX_COLUMNS)?;
    // Region bounded by the verbatim blocks, not by cbindgen.toml's header
    // and trailer, for the same reason the sibling passes are: counting the
    // verbatim declarations as generated would make both partition checks
    // meaningless.
    let umbrella_body =
        generated_region(&umbrella_text, &umbrella_forward, &umbrella_trailer);
    for name in declared_names(umbrella_body) {
        if let Some(owner) = sibling_owner_of(&name) {
            return Err(format!(
                "curl.h declares {name}, which {owner} owns. The exclusion \
                 for that pass did not take effect, and the name would be \
                 declared twice."
            )
            .into());
        }
    }
    check_declared_forms(
        "curl.h",
        umbrella_body,
        &umbrella_owned,
        &public_enums,
    )?;
    transaction.stage(&include_dir.join("curl.h"), &umbrella_text)?;

    for spec in SIBLING_HEADERS.iter() {
        let prologue = sibling_prologue(spec, &banner);
        let after_includes = sibling_after_includes(spec);
        let epilogue = sibling_epilogue(spec);

        let marker = after_includes.clone();

        let mut config = base.clone();
        config.header = Some(prologue);
        config.after_includes = Some(after_includes);
        config.trailer = Some(epilogue.clone());

        let suppress: Vec<String> = verbatim
            .iter()
            .cloned()
            .chain(
                observed
                    .iter()
                    .filter(|name| !spec.items.contains(&name.as_str()))
                    .cloned(),
            )
            .collect();
        apply_partition(&mut config, spec.items, &suppress);

        let text = render_binding(manifest, config)?;
        check_source_hygiene(spec.file, &text, HEADER_MAX_COLUMNS)?;

        // Both directions of the partition, so neither a leak nor a
        // disappearance can pass unnoticed.
        //
        // The region starts after `after_includes`, not after `header`,
        // because the verbatim declarations live in the former and counting
        // them as generated would make both checks meaningless: easy.h's
        // CURL_BLOB_COPY and mprintf.h's ten prototypes would look like
        // items the header does not own.
        let body = generated_region(&text, &marker, &epilogue);
        let declared = declared_names(body);
        for name in &declared {
            if !spec.items.contains(&name.as_str()) {
                return Err(format!(
                    "{} declares {name}, which it does not own. Assign it in \
                     the header partition, or it will be declared in every \
                     header.",
                    spec.file
                )
                .into());
            }
        }
        // Unconditional. The `observed.iter().any(...)` precondition that used
        // to guard this loop is gone: it made the check answer "nothing was
        // expected" whenever discovery returned nothing, which is precisely
        // when an incomplete contract is about to be published. Check 2 above
        // has already established that every partition item was observed, so
        // an item missing here means this pass dropped it.
        for item in spec.items {
            if observed.iter().any(|name| name == item)
                && !declared.iter().any(|name| name == item)
            {
                return Err(format!(
                    "{} was expected to declare {item} and does not. \
                     Generating it now would publish an incomplete ABI \
                     contract, so nothing has been written.",
                    spec.file
                )
                .into());
            }
        }

        check_declared_forms(spec.file, body, spec.items, &public_enums)?;
        transaction.stage(&include_dir.join(spec.file), &text)?;
    }

    // Every header rendered and every check passed. Only now does anything
    // reach the tracked directory.
    let expected_files = 1 + SIBLING_HEADERS.len();
    let staged = transaction.staged_count();
    if staged != expected_files {
        return Err(format!(
            "rendered {staged} of {expected_files} public headers. Publishing \
             a partial set would leave a mixed ABI contract on disk, so \
             nothing has been written."
        )
        .into());
    }

    transaction.promote()?;

    Ok(())
}

/// Assert that every public enum is declared in the SHAPE its ABI requires.
///
/// Name presence is not enough, and this is the check that says so. A
/// `#[repr(iN)]` enum is emitted as `typedef int32_t NAME;` instead of a
/// braced typedef; `declared_names` recognises that form, so the name is
/// still reported as declared and every existing completeness check passes.
/// The C type of every parameter declared as that enum has nonetheless
/// changed, which is precisely the integer-exactness failure the pinning rule
/// exists
/// to prevent.
///
/// Two independent assertions, because either alone can be satisfied by an
/// accident: the braced terminator `} NAME;` must appear exactly once, and no
/// scalar typedef of the same name may appear at all.
fn check_declared_forms(
    file: &str,
    body: &str,
    items: &[&str],
    public_enums: &[String],
) -> Result<(), Box<dyn Error>> {
    for item in items {
        if !public_enums.iter().any(|name| name == item) {
            continue;
        }

        if let Some(line) = scalar_typedef_of(body, item) {
            return Err(format!(
                "{file} declares {item} as `{line}` rather than as a braced \
                 typedef. That is what cbindgen emits when a public enum \
                 carries #[repr(iN)] instead of #[repr(C)]: the members keep \
                 their names and values, so every count and value check still \
                 passes, but the C type of every parameter declared as {item} \
                 changes. Restore #[repr(C)] on it."
            )
            .into());
        }

        let terminators = braced_typedef_terminators(body, item);
        if terminators != 1 {
            return Err(format!(
                "{file} closes a braced typedef named {item} {terminators} \
                 time(s), and exactly one is required. {item} is a #[repr(C)] \
                 pub enum, so it must be emitted as `typedef enum {{ ... }} \
                 {item};`; any other shape changes the type a C consumer sees."
            )
            .into());
        }
    }

    Ok(())
}

// Template substitution

const CURL_CONFIG_PLACEHOLDERS: usize = 18;

/// Placeholders in `libcurl.pc.in`: 14 distinct tokens, one occurrence each.
const LIBCURL_PC_PLACEHOLDERS: usize = 14;

/// Every distinct `@TOKEN@` in a template, sorted.
///
/// Sorted so the error messages below are deterministic, which matters
/// because a build script's output is read by people diffing two builds.
fn collect_placeholders(text: &str) -> Vec<String> {
    let bytes: Vec<char> = text.chars().collect();
    let mut found: Vec<String> = Vec::new();
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] != '@' {
            index += 1;
            continue;
        }
        let mut end = index + 1;
        // A token is @ then an identifier then @. Anything else is an
        // ordinary at-sign, of which the templates have several in email
        // addresses and shell text.
        while end < bytes.len()
            && (bytes[end].is_ascii_alphanumeric() || bytes[end] == '_')
        {
            end += 1;
        }
        if end > index + 1 && end < bytes.len() && bytes[end] == '@' {
            let name: String = bytes[index + 1..end].iter().collect();
            let first_is_alpha = name
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
            if first_is_alpha && !found.contains(&name) {
                found.push(name);
            }
            index = end + 1;
        } else {
            index += 1;
        }
    }

    found.sort();
    found
}

/// Replace every `@KEY@` with its value.
fn substitute(template: &str, values: &[(&str, String)]) -> String {
    let mut out = template.to_string();
    for (key, value) in values {
        out = out.replace(&format!("@{key}@"), value);
    }
    out
}

/// Check that a template's placeholders and a value table correspond
/// exactly, in both directions, and that the expected count holds.
fn check_placeholder_coverage(
    label: &str,
    template: &str,
    values: &[(&str, String)],
    expected: usize,
) -> Result<(), Box<dyn Error>> {
    let present = collect_placeholders(template);

    if present.len() != expected {
        return Err(format!(
            "{label} has {} distinct placeholders, expected {expected}: {}",
            present.len(),
            present.join(", ")
        )
        .into());
    }
    for name in &present {
        if !values.iter().any(|(key, _)| key == name) {
            return Err(format!(
                "{label} uses @{name}@ and no value is supplied for it"
            )
            .into());
        }
    }
    for (key, _) in values {
        if !present.iter().any(|name| name == key) {
            return Err(format!(
                "a value is supplied for @{key}@, which {label} does not use"
            )
            .into());
        }
    }
    Ok(())
}

/// Fail if any `@TOKEN@` survived substitution.
///
/// A leftover token is the worst possible outcome for these two files: they
/// are consumed by third-party build systems, so an unsubstituted
/// `@SUPPORT_FEATURES@` does not crash anything, it just silently
/// misinforms every downstream configure script that reads it.
fn check_no_residual_placeholders(
    label: &str,
    rendered: &str,
) -> Result<(), Box<dyn Error>> {
    let residual = collect_placeholders(rendered);
    if residual.is_empty() {
        return Ok(());
    }
    Err(format!(
        "{label} still contains {} unsubstituted placeholder(s): {}",
        residual.len(),
        residual
            .iter()
            .map(|name| format!("@{name}@"))
            .collect::<Vec<_>>()
            .join(", ")
    )
    .into())
}

// What to report about this build

/// Every Cargo feature this crate declares, in declaration order.
///
/// Used only to render `curl-config --configure`, whose value is otherwise
/// empty in the CMake build (`CMakeLists.txt:2077`). Reporting the real
/// feature selection is strictly more informative than an empty string and
/// is the honest answer to "how was this built".
const CRATE_FEATURES: [&str; 15] = [
    "http2",
    "http3",
    "ftp",
    "ssh",
    "websockets",
    "cookies",
    "hsts",
    "altsvc",
    "doh",
    "brotli",
    "zstd",
    "gzip",
    "negotiate",
    "hickory-dns",
    "memdebug",
];

/// Whether a Cargo feature is enabled for this build.
///
/// Cargo exports `CARGO_FEATURE_<NAME>` with the name upper-cased and every
/// hyphen turned into an underscore, so `hickory-dns` arrives as
/// `CARGO_FEATURE_HICKORY_DNS`. The value is always `1`, so presence is the
/// signal.
fn feature_enabled(name: &str) -> bool {
    let key =
        format!("CARGO_FEATURE_{}", name.to_uppercase().replace('-', "_"));
    env::var_os(key).is_some()
}

/// The feature tokens this build honestly supports, space separated.
///
/// Sorted case-insensitively, matching `CMakeLists.txt:2041-2045`, which
/// sorts both the feature list and the SSL-backend list that way. Sorting at
/// all is what makes the rendered artifacts byte-identical between two
/// builds of the same configuration.
fn advertised_features() -> Result<String, Box<dyn Error>> {
    let mut tokens: Vec<String> = Vec::new();

    for row in runtime_feature_rows()? {
        if !gate_holds(&row.gate)? {
            continue;
        }
        if probe_permits_static_metadata(&row.probe) {
            tokens.push(row.token);
        }
    }

    tokens.sort_by_key(|token| token.to_lowercase());
    Ok(tokens.join(" "))
}

/// Whether a row's `present:` probe allows the token into STATIC metadata.
///
/// The compile-time half of the decision is [`gate_holds`] and is applied by
/// the caller; this answers only what the probe adds. Extracted from
/// [`advertised_features`] so [`run_self_checks`] can assert all three arms
/// directly, because two of them are unreachable in a default build and an
/// arm nothing exercises is an arm nothing protects.
fn probe_permits_static_metadata(probe: &Probe) -> bool {
    match probe {
        // C's NULL, or a probe whose answer is fixed for this build: the
        // static answer equals the runtime one, so it can be advertised.
        Probe::Absent | Probe::Constant(true) => true,
        // The engine withholds it at run time, so metadata that claimed it
        // would describe a different product.
        Probe::Constant(false) => false,
        // GENUINELY RUNTIME -- and still advertised, because the question
        // these two files answer is not the one the probe answers.
        //
        // This is the `GSS-API`, `Kerberos` and `SPNEGO` case: `negotiate`
        // may be compiled in on a host with no usable mechanism, so
        // `crate::version`'s banner conjoins a runtime probe before naming
        // the token. `curl-config --features` and `libcurl.pc`'s
        // `supported_features` are **compile-time** interfaces, and C
        // answers them from configure-time detection alone. Measured in
        // this tree: `configure.ac:5175-5177` appends `GSS-API` under
        // `test "$HAVE_GSSAPI" = "1"`, and `:5194-5200` appends `SPNEGO`
        // and `Kerberos` under that same variable conjoined with their
        // `CURL_DISABLE_` switches. `HAVE_GSSAPI` is decided when configure
        // finds the library, and nothing re-examines the host afterwards.
        // A consumer running `curl-config --features` is asking what this
        // libcurl was BUILT to do, which is exactly what the gate above
        // already decided.
        //
        // Withholding it here was the defect, not the caution. It made the
        // two interfaces incapable of ever reporting the three names at any
        // feature setting, so a build WITH `negotiate` described itself as a
        // build without it -- and the gate that would have kept the claim
        // honest, `gate_holds`, had already run and already said yes. The
        // runtime probe stays where it can actually be performed, in the
        // live banner, and nothing here weakens it.
        //
        // Specification 0.6.5's asymmetry is not violated by this, because
        // the tokens these files carry are not the tokens
        // `tests/runtests.pl` reads: the harness parses the `Features:`
        // line of `curl --version` (`:640-730`), which is rendered from the
        // engine's own predicate WITH the probe folded in, and never parses
        // `curl-config` or `libcurl.pc` at all. So no fixture can be moved
        // from skip to run-and-fail by this arm.
        Probe::Dynamic(_) => true,
    }
}

/// The protocol tokens this build honestly supports, space separated.
///
/// Sorted case-sensitively, matching `CMakeLists.txt:1990-1991`, which sorts
/// the protocol list without the case-insensitive flag. Every token is
/// upper-case, so the two orders coincide; the distinction is preserved
/// because the C build drew it.
fn advertised_protocols() -> Result<String, Box<dyn Error>> {
    let mut tokens: Vec<String> = Vec::new();

    for row in runtime_protocol_rows()? {
        if gate_holds(&row.gate)? {
            tokens.push(row.token.to_uppercase());
        }
    }

    tokens.sort_unstable();
    Ok(tokens.join(" "))
}

/// How this build was configured, in the shape a reader expects from
/// `curl-config --configure`.
fn configure_options() -> Result<String, Box<dyn Error>> {
    let mut parts: Vec<String> = Vec::new();

    let target = env::var("TARGET").unwrap_or_default();
    if !target.is_empty() {
        parts.push(format!("--target={target}"));
    }

    let mut enabled: Vec<&str> = CRATE_FEATURES
        .iter()
        .copied()
        .filter(|feature| feature_enabled(feature))
        .collect();
    enabled.sort_unstable();
    if !enabled.is_empty() {
        parts.push(format!("--features={}", enabled.join(",")));
    }

    let rendered = parts.join(" ");

    // Validated here as well as in the value loop, and deliberately through the
    // SAME authority rather than a second copy of the character class. A local
    // `SAFE_CONFIGURE_CHARS` constant holding a byte-identical string would be
    // precisely the drift shape the single-source-of-truth rule exists to
    // prevent: two policies that agree today and silently disagree after one
    // of them is edited.
    check_shell_context("CONFIGURE_OPTIONS", &rendered)?;

    Ok(rendered)
}

// Section 14a: injection safety for the two generated consumer files
//
// THE MEASUREMENT THAT DECIDES THE DESIGN. The tokens do not all sit in one
// grammar. Counted across `curl-config.in`, they appear in three distinct
// shell contexts:
//
//   single-quoted   prefix='@prefix@'                   :28
//                   echo '@CC@'                         :77
//                   echo '@CURL_CA_BUNDLE@'             :73
//   double-quoted   exec_prefix="@exec_prefix@"         :31
//                   echo "@LIBCURL_PC_CFLAGS@ -I@includedir@"  :147
//   unquoted        for feature in @SUPPORT_FEATURES@   :85
//                   echo @CONFIGURE_OPTIONS@            :178

/// Control characters rejected in every substituted value, in both files.
fn check_control_chars(
    file: &str,
    token: &str,
    value: &str,
) -> Result<(), Box<dyn Error>> {
    if let Some(bad) = value.chars().find(|c| c.is_control()) {
        let described = match bad {
            '\n' => "a line feed".to_string(),
            '\r' => "a carriage return".to_string(),
            '\0' => "a NUL".to_string(),
            other => format!("the control character U+{:04X}", other as u32),
        };
        return Err(format!(
            "the value for @{token}@ in {file} contains {described}. In a \
             shell script that ends a command and in a pkg-config file it \
             ends a field, so either way the rest of the value becomes \
             something the generated file executes or declares."
        )
        .into());
    }
    Ok(())
}

/// The `curl-config.in` tokens whose values come from the environment.
const SHELL_QUOTED_TOKENS: [&str; 3] = ["prefix", "CC", "CURL_CA_BUNDLE"];

/// The POSIX-shell quoting state a position in a line sits in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ShellQuote {
    /// Outside any quotes: word splitting, globbing and expansion all apply.
    Unquoted,
    /// Inside `'...'`: nothing is special, which is why it is the safe home for
    /// an environment-derived value.
    Single,
    /// Inside `"..."`: `$` and backticks still expand.
    Double,
}

/// The quoting state at `col` bytes into `line`.
///
/// A REAL SCANNER, NOT AN ADJACENCY TEST, and the difference is not academic.
/// An adjacency test -- checking whether a quote character sits immediately
/// before or after the token -- misclassifies the --static-libs line of
/// `curl-config.in`:
///
/// ```text
/// echo "@libdir@/libcurl.@libext@ @LIBCURL_PC_LDFLAGS_PRIVATE@ ..."
/// ```
fn quote_state_at(line: &str, col: usize) -> ShellQuote {
    let mut state = ShellQuote::Unquoted;
    let mut escaped = false;

    for (i, c) in line.char_indices() {
        if i >= col {
            break;
        }
        if escaped {
            escaped = false;
            continue;
        }
        match (state, c) {
            // A backslash escapes the next character everywhere except inside
            // single quotes, where POSIX gives it no special meaning at all.
            (ShellQuote::Single, '\\') => {}
            (_, '\\') => escaped = true,
            (ShellQuote::Unquoted, '\'') => state = ShellQuote::Single,
            (ShellQuote::Single, '\'') => state = ShellQuote::Unquoted,
            (ShellQuote::Unquoted, '"') => state = ShellQuote::Double,
            (ShellQuote::Double, '"') => state = ShellQuote::Unquoted,
            _ => {}
        }
    }

    state
}

/// Every `(line number, quoting state)` at which `token` appears.
fn token_contexts(template: &str, token: &str) -> Vec<(usize, ShellQuote)> {
    let needle = format!("@{token}@");
    let mut found = Vec::new();

    for (n, line) in template.lines().enumerate() {
        let mut from = 0;
        while let Some(offset) = line[from..].find(&needle) {
            let at = from + offset;
            found.push((n + 1, quote_state_at(line, at)));
            from = at + needle.len();
        }
    }

    found
}

/// Assert that the template still puts every value in the grammar this script
/// validated it against.
///
/// Three independent claims, each of which would otherwise be a comment:
///
/// * Every occurrence of an environment-derived token is single-quoted. This is
///   the precondition that makes [`shell_single_quoted_body`] correct. Editing
///   `curl-config.in` to double-quote `@prefix@` would turn a correct escape
///   into a literal `'\''` in the middle of a path, and nothing would notice
///   until a consumer's build broke.
/// * Each token classified as unquoted really does appear unquoted, so
///   [`check_shell_context`]'s narrow character class is guarding something.
/// * Each token classified as double-quoted really does appear double-quoted.
fn check_single_quoted_context(template: &str) -> Result<(), Box<dyn Error>> {
    for token in SHELL_QUOTED_TOKENS.iter() {
        let contexts = token_contexts(template, token);
        if contexts.is_empty() {
            return Err(format!(
                "curl-config.in no longer uses @{token}@ at all, so the \
                 escaping rule for it is dead and the value it carries is no \
                 longer reported to consumers."
            )
            .into());
        }
        for (line, state) in contexts {
            if state != ShellQuote::Single {
                return Err(format!(
                    "curl-config.in:{line} uses @{token}@ in a {state:?} \
                     context. Its value comes from the environment and is \
                     escaped for a single-quoted context, so anywhere else the \
                     escape is wrong: inside double quotes it inserts a literal \
                     backslash and quote, and unquoted it word-splits. Either \
                     restore the single quotes or give this token its own \
                     escaping rule."
                )
                .into());
            }
        }
    }

    // No token may be classified twice. The three grammars contradict each
    // other -- a value escaped for single quoting contains `'\''`, which the
    // unquoted character class rejects -- so a token in two tables would be
    // validated against rules it cannot simultaneously satisfy.
    for (a, b, label) in [
        (
            &SHELL_QUOTED_TOKENS[..],
            &SHELL_UNQUOTED_TOKENS[..],
            "unquoted",
        ),
        (
            &SHELL_QUOTED_TOKENS[..],
            &SHELL_DOUBLE_QUOTED_TOKENS[..],
            "double-quoted",
        ),
        (
            &SHELL_UNQUOTED_TOKENS[..],
            &SHELL_DOUBLE_QUOTED_TOKENS[..],
            "double-quoted",
        ),
    ] {
        for token in a {
            if b.contains(token) {
                return Err(format!(
                    "@{token}@ is classified both by an earlier table and as \
                     {label}. The grammars are mutually exclusive, so one \
                     classification must be wrong."
                )
                .into());
            }
        }
    }

    for (tokens, want) in [
        (&SHELL_UNQUOTED_TOKENS[..], ShellQuote::Unquoted),
        (&SHELL_DOUBLE_QUOTED_TOKENS[..], ShellQuote::Double),
    ] {
        for token in tokens {
            let contexts = token_contexts(template, token);

            // Restriction strength runs Unquoted > Double > Single: the
            // unquoted character class is the narrowest, double quotes only
            // rescue word splitting and globbing, and single quotes make
            // everything literal. A token validated against the weaker grammar
            // must therefore never appear in a context that demands the
            // stronger one, or the narrower rules would go unenforced at that
            // occurrence. Only the Double -> Unquoted direction is reachable
            // here; the converse is vacuous because the unquoted class is a
            // subset of what double quotes accept.
            if want == ShellQuote::Double {
                if let Some((line, _)) = contexts
                    .iter()
                    .find(|(_, state)| *state == ShellQuote::Unquoted)
                {
                    return Err(format!(
                        "curl-config.in:{line} uses @{token}@ unquoted, but \
                         this build script validates it against the \
                         double-quoted grammar, which permits characters that \
                         word-split or glob when unquoted. Quote the \
                         occurrence or reclassify the token as unquoted."
                    )
                    .into());
                }
            }

            if !contexts.iter().any(|(_, state)| *state == want) {
                let seen: Vec<String> = contexts
                    .iter()
                    .map(|(line, state)| format!("{line}:{state:?}"))
                    .collect();
                return Err(format!(
                    "curl-config.in has no {want:?} occurrence of @{token}@, \
                     but this build script classifies it that way and validates \
                     its value against that grammar. Occurrences found: {}. \
                     Either the template changed or the classification is \
                     wrong; check both before adjusting either.",
                    if seen.is_empty() {
                        "none".to_string()
                    } else {
                        seen.join(", ")
                    }
                )
                .into());
            }
        }
    }

    Ok(())
}

/// Tokens the template leaves UNQUOTED so the shell word-splits them.
///
/// These three are assembled from a static capability table rather than read
/// from the environment, so nothing hostile reaches them today. The check is
/// here because that table will grow: a capability token acquiring a `*`, a
/// `;` or a `$` would be glob-expanded, treated as a command separator, or
/// expanded as a variable in an unquoted `for` list, and the failure would
/// appear in a consumer's build rather than here.
const SHELL_UNQUOTED_TOKENS: [&str; 3] =
    ["SUPPORT_FEATURES", "SUPPORT_PROTOCOLS", "CONFIGURE_OPTIONS"];

/// Tokens the template places inside DOUBLE quotes.
const SHELL_DOUBLE_QUOTED_TOKENS: [&str; 6] = [
    "exec_prefix",
    "includedir",
    "libdir",
    "libext",
    "LIBCURL_PC_CFLAGS",
    "LIBCURL_PC_LDFLAGS_PRIVATE",
];

/// Characters permitted in a value the template leaves unquoted.
const SHELL_UNQUOTED_SAFE: &str = "-_=,./+: ";

/// Validate a value against the shell context the template puts it in.
///
/// Called for every `curl-config` value, with the context looked up rather than
/// assumed, so a token that moves between contexts is checked against the one
/// it actually lands in.
fn check_shell_context(token: &str, value: &str) -> Result<(), Box<dyn Error>> {
    if SHELL_UNQUOTED_TOKENS.contains(&token) {
        if let Some(bad) = value.chars().find(|c| {
            !(c.is_ascii_alphanumeric() || SHELL_UNQUOTED_SAFE.contains(*c))
        }) {
            return Err(format!(
                "the value for @{token}@ contains {bad:?}, which curl-config.in \
                 leaves unquoted so that the shell word-splits it. There the \
                 character would be glob-expanded, treated as a control \
                 operator, or expanded -- not printed. The template's quoting \
                 is frozen, so the value has to be safe for it."
            )
            .into());
        }
    }

    if SHELL_DOUBLE_QUOTED_TOKENS.contains(&token) {
        // `$` stays legal: `${prefix}` and `${exec_prefix}` are values this
        // script emits on purpose. Command substitution is not.
        if value.contains('`') || value.contains("$(") {
            return Err(format!(
                "the value for @{token}@ contains a command substitution, and \
                 curl-config.in places that token inside double quotes where \
                 both spellings are evaluated. Parameter expansion is \
                 deliberate here; running a command is not."
            )
            .into());
        }
    }

    Ok(())
}

/// Reject a value that would break the pkg-config grammar.
///
/// `allow_variables` exists because this file's own values legitimately use
/// the mechanism: `exec_prefix=${prefix}` and `libdir=${exec_prefix}/lib` are
/// deliberate, and the template's `Libs: -L${libdir}` depends on them.
fn check_pkgconfig_value(
    token: &str,
    value: &str,
    allow_variables: bool,
) -> Result<(), Box<dyn Error>> {
    check_control_chars("libcurl.pc", token, value)?;

    if value.contains('#') {
        return Err(format!(
            "the value for @{token}@ in libcurl.pc contains '#', which starts \
             a comment in a pkg-config file. Everything after it would be \
             discarded, so the field would be silently truncated."
        )
        .into());
    }

    if !allow_variables && value.contains('$') {
        return Err(format!(
            "the value for @{token}@ in libcurl.pc contains '$', which \
             introduces a pkg-config variable reference. An unintended one \
             either expands to the wrong text or makes pkg-config fail with \
             \"Variable not defined\" for every consumer."
        )
        .into());
    }

    Ok(())
}

// Section 14b: the native-link authority

/// Every native library a static consumer of `libcurl.a` must also link.
///
/// A Rust `staticlib` is not self-contained. It carries no reference to the
/// Rust standard library's own dependencies, so a C program linking it must
/// name them itself, and omitting one produces a wall of undefined symbols
/// that says nothing about the cause. Every entry below was MEASURED, not
/// recalled:
///
/// * The baseline is `rustc --print native-static-libs` for the real crate.
///   Both Linux triples report `-lgcc_s -lutil -lrt -lpthread -lm -ldl -lc`,
///   and both Apple triples report `-lSystem -lc -lm`. The Linux figure is
///   identical for the full crate and for a trivial one, so `ring` and the
///   rest add nothing there.
/// * The two Apple frameworks come from the dependency graph rather than from
///   that print, because `--print native-static-libs` cannot be run for a
///   Darwin target in this environment. They arrive through
///   `rustls-native-certs`, which reads the platform trust store.
/// * The `negotiate` arm follows the platform, never the feature alone. On
///   Linux MIT Kerberos provides `libgssapi_krb5`, whose own `DT_NEEDED`
///   entries pull `krb5`, `k5crypto` and `com_err`, so naming the one is
///   enough. On macOS Apple ships `GSS.framework`. This mirrors the reasoning
///   already recorded in `curl-rs-lib/src/ffi/gss.rs`.
///
/// Order matters for a traditional static linker, which resolves left to
/// right, so the dependents precede the libraries they need and `-lc` is
/// last.
fn native_link_libs(target_os: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let mut libs: Vec<String> = Vec::new();

    match target_os {
        "linux" => {
            libs.extend(
                ["-lgcc_s", "-lutil", "-lrt", "-lpthread", "-lm", "-ldl"]
                    .iter()
                    .map(|s| (*s).to_string()),
            );
            if feature_enabled("negotiate") {
                libs.push("-lgssapi_krb5".to_string());
            }
            // Last, so every library above can still resolve against it.
            libs.push("-lc".to_string());
        }
        "macos" => {
            libs.push("-lSystem".to_string());
            libs.push("-lm".to_string());
            // Reached through rustls-native-certs -> security-framework.
            libs.push("-framework Security".to_string());
            libs.push("-framework CoreFoundation".to_string());
            if feature_enabled("negotiate") {
                libs.push("-framework GSS".to_string());
            }
            libs.push("-lc".to_string());
        }
        other => {
            return Err(format!(
                "no native-link authority is recorded for target_os {other:?}. \
                 AAP 0.8.3 mandates exactly four targets, two \
                 -unknown-linux-gnu and two -apple-darwin, so a fifth \
                 platform needs its static-link inputs measured with `rustc \
                 --print native-static-libs` before its consumer metadata can \
                 be honest."
            )
            .into());
        }
    }

    Ok(libs)
}

/// The native-link authority rendered for a template field.
fn private_libs(target_os: &str) -> Result<String, Box<dyn Error>> {
    Ok(native_link_libs(target_os)?.join(" "))
}

/// The install prefix the rendered artifacts describe.
fn install_prefix() -> String {
    env::var("CURL_RS_PREFIX").unwrap_or_else(|_| DEFAULT_PREFIX.to_string())
}

/// The compiler name `curl-config --cc` reports, for the target being built.
///
/// WHY THE PRECEDENCE IS WHAT IT IS. Consumers use this value to compile
/// programs that link the artifact this build produced, so it must name the
/// compiler that can actually target it. Reading only `CC` gets that wrong in
/// exactly the case where it matters most: cross-compiling. `cargo build
/// --target aarch64-unknown-linux-gnu` with `CC` pointing at the host `gcc`
/// and `CC_aarch64_unknown_linux_gnu` pointing at the cross compiler would
/// report the host one, and a consumer following it would produce x86-64
/// objects and fail to link against an aarch64 library.
///
/// The order below mirrors `cc-rs`, which is what every `-sys` crate in the
/// dependency graph uses, so the reported compiler is the one that in fact
/// compiled this build's C (`ring`'s, for one). `cc-rs` resolves, most
/// specific first:
///
///   1. `CC_<target>` with the triple exactly as written
///   2. `CC_<target_with_underscores>`, hyphens and dots turned into `_`,
///      because many shells cannot export a name containing a hyphen
///   3. `TARGET_CC`, which applies to whatever the target happens to be
///   4. `CC`, the generic fallback
///
/// and when none is set it derives a name from the triple.
///
/// WHY THE DERIVATION IS A TABLE AND NOT A FORMAT STRING. This function used
/// to fall back to `format!("{target}-gcc")` whenever `HOST != TARGET`. For
/// the two Linux triples that happens to produce something real, and for the
/// two Apple ones it produces a compiler that has never existed on any
/// machine: `x86_64-apple-darwin-gcc`, `aarch64-apple-darwin-gcc`. A consumer
/// following `curl-config --cc` would run a command not found, which is a
/// worse outcome than reporting nothing, because it looks like a broken
/// installation rather than an unconfigured build.
///
/// The four mandated targets of specification 0.8.3 are therefore mapped
/// explicitly, and each entry is the command that can really produce objects
/// for that triple:
///
///   * `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu` -- the GNU
///     cross prefix, which is NOT the Rust triple: GNU spells it
///     `aarch64-linux-gnu-gcc`, with the `unknown` vendor field dropped. That
///     is the same command `.cargo/config.toml` names as this triple's
///     `linker`, so the two authorities cannot disagree about which toolchain
///     targets aarch64 Linux.
///   * `x86_64-apple-darwin`, `aarch64-apple-darwin` -- `clang` with the
///     architecture named. One Xcode `clang` targets both architectures, and
///     `-arch` is how it is told which; there is no `-apple-darwin-` prefixed
///     driver to name instead. The SDK needs no flag here because `clang` on
///     macOS resolves it itself, and hard-coding an `-isysroot` path would
///     pin a specific Xcode installation into a file consumers read.
///
/// A triple outside the four gets NO invented name. It is an error, because
/// this build script has no way to know what compiles for it and a guess is
/// what produced the Apple defect. `cc-rs` has a full table for that job; if
/// a fifth target is ever added, the honest fix is to add its row here or to
/// export `CC_<target>`, both of which the precedence above already supports.
///
/// Never empty, and never a name that cannot be run: a consumer substituting
/// an empty `--cc` into a command line would run its first argument as a
/// program, and one substituting a fabricated name gets `command not found`.
fn compiler() -> Result<String, Box<dyn Error>> {
    let target = env::var("TARGET").unwrap_or_default();
    let host = env::var("HOST").unwrap_or_default();

    let underscored: String = target
        .chars()
        .map(|c| if c == '-' || c == '.' { '_' } else { c })
        .collect();

    let candidates = [
        format!("CC_{target}"),
        format!("CC_{underscored}"),
        "TARGET_CC".to_string(),
        "CC".to_string(),
    ];

    for key in candidates.iter() {
        // An empty or whitespace-only value is treated as unset. Exporting
        // `CC=` is a common way to clear an inherited value, and honouring it
        // literally would report a compiler name of "".
        if let Ok(value) = env::var(key) {
            if !value.trim().is_empty() {
                return Ok(value.trim().to_string());
            }
        }
    }

    // A native build needs no table at all: the driver rustc itself invokes is
    // correct by construction, and `cc` is the name every POSIX system has.
    // Checked before the table so that a host build of a mandated triple is
    // not reported under a cross name it does not need.
    if !target.is_empty() && target == host {
        return Ok("cc".to_string());
    }

    target_compiler(&target).map(str::to_string).ok_or_else(|| {
        format!(
            "no target compiler is known for {target:?}, and inventing one is \
             what this function exists to stop: a derived `{target}-gcc` is a \
             real command for the GNU triples and a command that has never \
             existed for the Apple ones, so a consumer following \
             `curl-config --cc` would get `command not found`. Either add \
             {target:?} to TARGET_COMPILERS beside the four targets \
             specification 0.8.3 mandates, or export CC_{underscored} for \
             this build"
        )
        .into()
    })
}

/// The C compiler that produces objects for each mandated target.
///
/// Separate from [`compiler`] so the mapping is a value the tests can walk
/// rather than a branch they have to reach through the environment, and so
/// that the set is visibly the four of specification 0.8.3 and not a wildcard.
///
/// The Linux rows are cross-prefix names and are only reached when
/// `HOST != TARGET`; a native build never consults this table.
const TARGET_COMPILERS: [(&str, &str); 4] = [
    ("x86_64-unknown-linux-gnu", "x86_64-linux-gnu-gcc"),
    ("aarch64-unknown-linux-gnu", "aarch64-linux-gnu-gcc"),
    ("x86_64-apple-darwin", "clang -arch x86_64"),
    // `arm64`, not `aarch64`: `-arch` takes Apple's own architecture spelling,
    // and `clang -arch aarch64` is rejected as an unknown architecture.
    ("aarch64-apple-darwin", "clang -arch arm64"),
];

/// The [`TARGET_COMPILERS`] row for a triple, or `None` when it has no row.
fn target_compiler(target: &str) -> Option<&'static str> {
    TARGET_COMPILERS
        .iter()
        .find(|(triple, _)| *triple == target)
        .map(|(_, command)| *command)
}

/// One authority for which toolchain targets aarch64 Linux, checked against
/// the other end of it.
///
/// `.cargo/config.toml` names that triple's `linker`, and a consumer following
/// `curl-config --cc` must reach the same toolchain: objects from a different
/// cross gcc are not necessarily linkable by the one rustc will invoke. Two
/// authorities for one toolchain is precisely how a cross consumer ends up
/// compiling against the wrong architecture, so the agreement is asserted here
/// rather than maintained by hand in two files.
///
/// Deliberately a build-time check and not a `#[cfg(test)]` test, for the
/// reason [`run_self_checks`] records: `cargo test` never compiles a build
/// script's test module. Kept out of `run_self_checks` itself only because it
/// needs the repository root, which that function does not receive.
fn check_cross_toolchain_agreement(root: &Path) -> Result<(), Box<dyn Error>> {
    let config = root.join(".cargo").join("config.toml");
    let text = fs::read_to_string(&config)
        .map_err(|e| format!("cannot read {}: {e}", config.display()))?;

    // The file declares exactly one `linker`, under
    // `[target.aarch64-unknown-linux-gnu]`; the other three tables set no
    // linker at all, which the file itself explains. Finding more than one
    // would mean that layout changed and this check is reasoning about the
    // wrong row, so it is an error rather than a first-match win.
    let linkers: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter_map(|line| line.strip_prefix("linker = \""))
        .filter_map(|rest| rest.split('"').next())
        .collect();

    let linker = match linkers.as_slice() {
        [only] => *only,
        [] => {
            return Err(format!(
                "{} names no linker. The aarch64 Linux cross toolchain is \
                 named there, and curl-config --cc must agree with it.",
                config.display()
            )
            .into())
        }
        many => {
            return Err(format!(
                "{} names {} linkers ({}). This check assumes the single \
                 aarch64 Linux entry the file documents; re-derive it \
                 per-triple before adding another.",
                config.display(),
                many.len(),
                many.join(", ")
            )
            .into())
        }
    };

    let reported =
        target_compiler("aarch64-unknown-linux-gnu").unwrap_or_default();
    if reported != linker {
        return Err(format!(
            "curl-config --cc would report {reported:?} for \
             aarch64-unknown-linux-gnu while {} names {linker:?} as its \
             linker. One toolchain must have one name.",
            config.display()
        )
        .into());
    }

    // The third end of the same authority. The file's `[env]` table also names
    // a C compiler for this triple, for cc-rs's benefit, and that value takes
    // PRECEDENCE over the table above inside `compiler()` -- it arrives as
    // `CC_aarch64_unknown_linux_gnu`. So if the two disagreed, the table would
    // be silently unreachable on the one leg it exists for, and the check
    // above would be asserting something no build ever consults.
    let env_cc = text
        .lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix("CC_aarch64_unknown_linux_gnu = \""))
        .and_then(|rest| rest.split('"').next());

    if let Some(env_cc) = env_cc {
        if env_cc != reported {
            return Err(format!(
                "{} sets CC_aarch64_unknown_linux_gnu to {env_cc:?} while \
                 TARGET_COMPILERS names {reported:?}. The environment value \
                 wins inside compiler(), so the disagreement would make the \
                 table unreachable on the only leg it serves.",
                config.display()
            )
            .into());
        }
    }

    Ok(())
}

/// The CA bundle path to report, or an empty string when none is configured.
///
/// Empty is a legitimate answer: curl-config's --ca arm prints whatever it is
/// given, and this build reads trust anchors through rustls rather than from
/// a compiled-in path unless one is supplied.
fn ca_bundle() -> String {
    env::var("CURL_CA_BUNDLE").unwrap_or_default()
}

// Section 14c: where the generated consumer metadata goes

/// Every path a rendered consumer file is written to, product path first.
///
/// The paths returned, in order:
///
/// 1. `$OUT_DIR/<name>` -- the product path. `OUT_DIR` is unique per target,
///    per feature set and per profile, so the collision is structurally
///    impossible rather than merely avoided. Cargo emits
///    `cargo:rustc-env`-visible metadata from here and cleans it with `cargo
///    clean`.
/// 2. `$OUT_DIR/staging/<install-relative path>` -- the same content laid out
///    the way `make install` would place it, so packaging is a copy of one
///    directory rather than a script that has to know both names. `bin/` for
///    the executable script and `lib/pkgconfig/` for the pkg-config file,
///    matching `Makefile.am` and what every consumer's `PKG_CONFIG_PATH`
///    expects.
/// 3. `$CURL_RS_STAGING_DIR/<install-relative path>` -- present only when
///    that variable is set. OPT-IN BY DESIGN: a build writes outside its own
///    `OUT_DIR` only when explicitly told where, which keeps the default
///    build incapable of touching the source tree at all.
fn metadata_destinations(
    install_relative: &str,
) -> Result<Vec<PathBuf>, Box<dyn Error>> {
    let out_dir = PathBuf::from(env_var("OUT_DIR")?);

    let name = Path::new(install_relative)
        .file_name()
        .ok_or_else(|| format!("{install_relative:?} names no file"))?
        .to_owned();

    let mut paths = vec![
        out_dir.join(&name),
        out_dir.join("staging").join(install_relative),
    ];

    if let Some(explicit) = env::var_os("CURL_RS_STAGING_DIR") {
        let explicit = PathBuf::from(explicit);
        if explicit.as_os_str().is_empty() {
            return Err("CURL_RS_STAGING_DIR is set but empty. An empty \
                        value would resolve every staged path to a relative \
                        one under whatever directory Cargo happened to run \
                        the script in; unset it instead."
                .into());
        }
        paths.push(explicit.join(install_relative));
    }

    Ok(paths)
}

/// Write one rendered consumer file to all of its destinations.
///
/// Parent directories are created because the staging layout is nested and
/// `OUT_DIR/staging/lib/pkgconfig` does not exist on a first build. The mode
/// is applied per destination rather than once, since a copy does not inherit
/// it.
fn publish_metadata(
    install_relative: &str,
    contents: &str,
    mode: u32,
) -> Result<PathBuf, Box<dyn Error>> {
    let destinations = metadata_destinations(install_relative)?;

    for destination in destinations.iter() {
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                format!("cannot create {}: {e}", parent.display())
            })?;
        }
        write_if_changed(destination, contents)?;
        set_mode(destination, mode)?;
    }

    // The product path, which is what a caller reports.
    Ok(destinations
        .into_iter()
        .next()
        .expect("metadata_destinations always yields the product path"))
}

// Section 14b: encoding environment-derived values for their destination
//
// Three values in the two rendered artifacts come from the environment rather
// than from a table in this file: the install prefix (CURL_RS_PREFIX or
// PREFIX), the compiler name (CC) and the CA bundle path (CURL_CA_BUNDLE). A
// fourth, TARGET, reaches @CONFIGURE_OPTIONS@. None of them is under this
// script's control, and all of them are interpolated into text that another
// program then PARSES.
//
// libcurl.pc is read by pkg-config, whose grammar is unrelated. Measured
// against pkg-config 1.8.1:
//   * `#` SILENTLY TRUNCATES the value -- `/opt/a#b` reads back as `/opt/a`.
//     `\#` is honoured and reads back as `/opt/a#b`, so `#` is ENCODED.
//   * `${...}` is INTERPOLATED -- `/opt/${libdir}x` reads back as `/opt/x`.
//     `$$` is NOT an escape for it (it reads back as a literal `$$`), so there
//     is no encoding available and `$` is REFUSED.
//   * An apostrophe or a double quote makes `pkg-config --cflags` return
//     EMPTY with exit status 0 -- a silent failure at the consumer -- so both
//     are REFUSED.
//   * `$(...)` passes through `--cflags` UNESCAPED into the consumer's shell,
//     which is the same injection as above by a longer route. Refused with the
//     rest of `$`.
// Encoding what can be encoded correctly and refusing what cannot is the
// honest split. A path containing `$`, `'`, `"` or a backtick is not a path
// anyone has; a path containing `#` or a space is.
//
// Control characters are refused for BOTH destinations before either encoder
// runs, because a newline forges a new pkg-config key and a new line of shell,
// and no encoding makes an unprintable character into a working path.
// `check_text_hygiene` already rejects a carriage return in the RENDERED text,
// but it cannot distinguish a newline inside a value from the line structure
// the template intended, which is exactly why the check belongs at the source.

/// Reject NUL and every other control character in an environment-derived
/// value.
///
/// Applied before either encoder, to every value that did not come from a
/// table in this file. The message names the variable and the offending
/// character, because the alternative is a rendered artifact that is subtly
/// wrong and a consumer that fails somewhere else entirely.
/// The class is `char::is_control` -- C0 plus DEL -- exactly as in
/// [`check_control_chars`], which reaches the same policy from the other
/// direction: that one names a template token and the file it lands in, this
/// one names a prose label for a value validated before any token is chosen.
/// Both entry points are live and must stay in step.
fn reject_control_characters(
    label: &str,
    value: &str,
) -> Result<(), Box<dyn Error>> {
    if let Some((index, bad)) =
        value.char_indices().find(|(_, c)| c.is_control())
    {
        return Err(format!(
            "{label} contains the control character {bad:?} at byte {index}, \
             which cannot appear in a rendered curl-config or libcurl.pc. A \
             newline would forge a new line of shell and a new pkg-config \
             key; a NUL would truncate the value in any C consumer. No \
             encoding makes an unprintable character into a usable path, so \
             the value is refused rather than mangled."
        )
        .into());
    }
    Ok(())
}

/// Encode a value for a POSIX shell SINGLE-quoted context.
fn shell_single_quoted_body(value: &str) -> String {
    value.replace('\'', "'\\''")
}

/// Encode a value for a pkg-config variable definition, or refuse it.
///
/// See the section comment for the measurements behind each branch. Five
/// characters are refused and nothing is encoded: `$` because pkg-config
/// interpolates `${...}`, `'`, `"` and a backtick because each makes
/// `pkg-config --cflags` return empty or reach the consumer's shell, and `#`
/// because pkg-config truncates the value at an unescaped one while an
/// escaped `\#` survives into `--cflags` verbatim (both measured against
/// pkgconf 1.8.1). A value this refuses is a mistake to report, not a value
/// to accommodate -- the same posture as the rest of Section 14a.
fn pkg_config_variable_body(
    label: &str,
    value: &str,
) -> Result<String, Box<dyn Error>> {
    const REFUSED: [(char, &str); 5] = [
        (
            '$',
            "pkg-config interpolates ${...} and offers no working escape",
        ),
        (
            '\'',
            "an apostrophe makes `pkg-config --cflags` return empty",
        ),
        (
            '"',
            "a double quote makes `pkg-config --cflags` return empty",
        ),
        ('`', "a backtick would reach the consumer's shell"),
        (
            '#',
            "pkg-config truncates the value at an unescaped # and leaks the \
             backslash of an escaped one into --cflags",
        ),
    ];
    for (bad, why) in REFUSED {
        if value.contains(bad) {
            return Err(format!(
                "{label} contains {bad:?}, which cannot be represented in a \
                 libcurl.pc variable: {why}. Measured against pkg-config \
                 1.8.1. Choose a prefix without it."
            )
            .into());
        }
    }
    Ok(value.to_string())
}

/// Reject anything unsafe in a value the template leaves UNQUOTED.
fn reject_unquoted_shell_metacharacters(
    label: &str,
    value: &str,
) -> Result<(), Box<dyn Error>> {
    if let Some(bad) = value.chars().find(|c| {
        !(c.is_ascii_alphanumeric() || SHELL_UNQUOTED_SAFE.contains(*c))
    }) {
        return Err(format!(
            "the value for {label} contains {bad:?}, which is not safe to \
             leave unquoted in curl-config.in. Only ASCII alphanumerics and \
             {SHELL_UNQUOTED_SAFE:?} are permitted, because the shell word- \
             splits and glob-expands this arm."
        )
        .into());
    }
    Ok(())
}

/// Validate every environment-derived value against BOTH grammars, up front.
fn validate_environment_substitutions() -> Result<(), Box<dyn Error>> {
    let prefix = install_prefix();
    let ca_bundle = ca_bundle();
    let compiler = compiler()?;

    // Control characters first: they are refused for every destination, so
    // there is no point asking a grammar about them.
    for (label, value) in [
        ("the install prefix (CURL_RS_PREFIX)", &prefix),
        ("CURL_CA_BUNDLE", &ca_bundle),
        ("CC", &compiler),
    ] {
        reject_control_characters(label, value)?;
    }

    // The prefix must satisfy pkg-config as well as the shell. CC and the CA
    // bundle reach curl-config only, and the shell encoder accepts everything
    // that is not a control character, so they need nothing further.
    pkg_config_variable_body(
        "the install prefix (CURL_RS_PREFIX), which libcurl.pc also \
         uses",
        &prefix,
    )?;

    // TARGET, and the two feature-derived loop arms.
    configure_options()?;
    reject_unquoted_shell_metacharacters(
        "@SUPPORT_FEATURES@",
        &advertised_features()?,
    )?;
    reject_unquoted_shell_metacharacters(
        "@SUPPORT_PROTOCOLS@",
        &advertised_protocols()?,
    )?;

    Ok(())
}

/// Confirm the template really wraps a token in single quotes.
fn assert_single_quoted_context(
    template_name: &str,
    template: &str,
    token: &str,
) -> Result<(), Box<dyn Error>> {
    let needle = format!("@{token}@");
    let mut found = 0usize;
    let mut from = 0usize;
    while let Some(offset) = template[from..].find(&needle) {
        let at = from + offset;
        found += 1;
        let before = template[..at].chars().next_back();
        let after = template[at + needle.len()..].chars().next();
        if before != Some('\'') || after != Some('\'') {
            return Err(format!(
                "{template_name} does not wrap @{token}@ in single quotes \
                 (found {before:?} before and {after:?} after), but this \
                 script encodes it for a single-quoted context. One of the \
                 two must change, and the encoder cannot guess which."
            )
            .into());
        }
        from = at + needle.len();
    }
    if found == 0 {
        return Err(
            format!("{template_name} does not use @{token}@ at all").into()
        );
    }
    Ok(())
}

// Section 15: rendering curl-config and libcurl.pc
//
// Why this file renders them at all. `configure.ac:129` and `:141` extracted
// the version facts with sed and substituted these two templates; CMake did
// the same at `CMakeLists.txt:1994`, `:2048`, `:2067` and `:2078-2079`.
// UNDER CARGO NEITHER RUNS. Yet third-party build systems query both files --
// `pkg-config --cflags libcurl` and `curl-config --libs` are how most
// projects find libcurl -- so leaving them as unsubstituted templates would
// break every consumer. This script already holds the version, the soname
// and the honest capability set, so it is the right place.

/// Render `<root>/curl-config` from `<root>/curl-config.in`.
///
/// The eighteen values, in the template's own order, with the evidence for
/// each recorded beside it. Where a value is deliberately empty that is
/// stated, because an empty string and an oversight look identical in a
/// rendered file.
fn render_curl_config(
    root: &Path,
    facts: &VersionFacts,
) -> Result<(), Box<dyn Error>> {
    let template_path = root.join("curl-config.in");
    let template = fs::read_to_string(&template_path)
        .map_err(|e| format!("cannot read {}: {e}", template_path.display()))?;

    // Assert, against the template itself, that every externally derived
    // token still sits inside single quotes -- the precondition that makes
    // the escaping below the correct transform rather than a corrupting one.
    check_single_quoted_context(&template)?;

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    // The three environment-derived values, checked for control characters at
    // the source and then encoded for the ONE context this template puts them
    // in. The contexts are asserted rather than assumed, because the template
    // is frozen text this script does not own. See Section 14b.
    // Only CURL_RS_PREFIX is consulted for the prefix: a namespaced variable
    // cannot be set by accident, so the ambiguity a generic `PREFIX` carried
    // disappears rather than being managed.
    let prefix = install_prefix();
    let ca_bundle = ca_bundle();
    let compiler = compiler()?;
    for (label, value) in [
        ("the install prefix (CURL_RS_PREFIX)", &prefix),
        ("CURL_CA_BUNDLE", &ca_bundle),
        ("CC", &compiler),
    ] {
        reject_control_characters(label, value)?;
    }
    for token in ["prefix", "CURL_CA_BUNDLE", "CC"] {
        assert_single_quoted_context("curl-config.in", &template, token)?;
    }

    // Both loop arms word-split on purpose (:85 and :92), and both depend on
    // the environment through CARGO_FEATURE_*, so both are validated.
    let features = advertised_features()?;
    let protocols = advertised_protocols()?;
    reject_unquoted_shell_metacharacters("@SUPPORT_FEATURES@", &features)?;
    reject_unquoted_shell_metacharacters("@SUPPORT_PROTOCOLS@", &protocols)?;

    let values: Vec<(&str, String)> = vec![
        // Assigned at the head of the script, inside single quotes.
        ("prefix", shell_single_quoted_body(&prefix)),
        // CMakeLists.txt:2079 sets this to the literal ${prefix}, which the
        // script then expands at run time. Reproduced exactly, because
        // curl-config.in assigns it and later arms expand it.
        ("exec_prefix", "${prefix}".to_string()),
        // Assigned at the head of the script and expanded by the --cflags arm.
        ("includedir", "${prefix}/include".to_string()),
        // Used by the --libs and --static-libs arms.
        ("libdir", "${exec_prefix}/lib".to_string()),
        // Both yes: curl-rs-ffi/Cargo.toml sets
        // crate-type = ["cdylib", "staticlib"], so both artifacts exist.
        ("ENABLE_SHARED", "yes".to_string()),
        ("ENABLE_STATIC", "yes".to_string()),
        // The staticlib artifact is libcurl.a, so the extension is `a`.
        // CMakeLists.txt:2093 derives the same value by stripping the dot
        // from CMAKE_STATIC_LIBRARY_SUFFIX.
        ("libext", "a".to_string()),
        // Drives --ca. Empty unless configured, and single-quoted there.
        ("CURL_CA_BUNDLE", shell_single_quoted_body(&ca_bundle)),
        // Drives --cc, single-quoted there.
        ("CC", shell_single_quoted_body(&compiler)),
        // Drives --feature/--features, which loops over the value unquoted so
        // that it word-splits into one token per line. Validated above rather
        // than encoded, because the word splitting is wanted.
        ("SUPPORT_FEATURES", features),
        // Drives --protocols, whose loop carries a
        // `# shellcheck disable=SC2043` immediately before it.
        ("SUPPORT_PROTOCOLS", protocols),
        // include/curl/curlver.h:35. Every parity claim in this work is
        // against this exact string.
        ("CURLVERSION", facts.version.clone()),
        // curlver.h:61 with the 0x removed, exactly as configure.ac:141
        // captured it. The --vernum arm echoes it raw.
        ("VERSIONNUM", facts.vernum.clone()),
        // rustls and nothing else. Note the spelling: CMakeLists.txt:2059
        // capitalises its backend names, but the truthful token here is the
        // crate's own name, lower-case.
        ("SSL_BACKENDS", SSL_BACKENDS.to_string()),
        // Empty: consumers need no extra flags to include the public
        // headers beyond the -I the --cflags arm already prints.
        ("LIBCURL_PC_CFLAGS", String::new()),
        // Printed by --static-libs. One authority, shared with
        // libcurl.pc's Libs.private, so the two cannot disagree.
        ("LIBCURL_PC_LIBS_PRIVATE", private_libs(&target_os)?),
        // Empty: a Rust cdylib needs no extra link-time flags of its own.
        ("LIBCURL_PC_LDFLAGS_PRIVATE", String::new()),
        // Printed unquoted by --configure, hence validated.
        ("CONFIGURE_OPTIONS", configure_options()?),
    ];

    // Every value, not only the three that were escaped. Escaping made the
    // three safe inside their single quotes; a control character is unsafe in
    // any context, because `'` -> `'\''` deliberately leaves a region OUTSIDE
    // the quotes where a newline would still end the command. The computed
    // values are checked for the same reason as in libcurl.pc: the capability
    // table and the native-link authority both grow.
    for (token, value) in values.iter() {
        check_control_chars("curl-config", token, value)?;
        check_shell_context(token, value)?;
    }

    check_placeholder_coverage(
        "curl-config.in",
        &template,
        &values,
        CURL_CONFIG_PLACEHOLDERS,
    )?;

    let rendered = substitute(&template, &values);
    check_no_residual_placeholders("curl-config", &rendered)?;

    // Only the universal rules: the script is shell, not C, and its
    // frozen text is not subject to checksrc's column cap.
    check_text_hygiene("curl-config", &rendered)?;

    if !rendered.starts_with("#!/bin/sh\n") {
        return Err("rendered curl-config does not begin with #!/bin/sh, so \
                    it would not be executable as a script"
            .into());
    }

    publish_metadata("bin/curl-config", &rendered, MODE_SCRIPT)?;

    Ok(())
}

/// Render `<root>/libcurl.pc` from `<root>/libcurl.pc.in`.
///
/// Fourteen values. Two of them are empty for a reason that would otherwise
/// be invisible, so it is stated in full below.
fn render_libcurl_pc(
    root: &Path,
    facts: &VersionFacts,
) -> Result<(), Box<dyn Error>> {
    let template_path = root.join("libcurl.pc.in");
    let template = fs::read_to_string(&template_path)
        .map_err(|e| format!("cannot read {}: {e}", template_path.display()))?;

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    // pkg-config has no escaping mechanism at all -- a variable's value runs
    // to end of line -- so an unsafe value here must be REFUSED rather than
    // encoded. The prefix is the only externally derived value in this file,
    // and it is checked without the variable-reference allowance because a
    // `$` in an inherited path is never intentional.
    // The same prefix as curl-config, encoded for a DIFFERENT grammar. The two
    // artifacts share the value and must not share the escaper: pkg-config
    // truncates on `#` and interpolates `${...}`, neither of which means
    // anything to a shell inside single quotes. See Section 14b for the
    // measurements.
    let prefix = install_prefix();
    reject_control_characters("the install prefix (CURL_RS_PREFIX)", &prefix)?;
    let prefix = pkg_config_variable_body("the install prefix", &prefix)?;
    // And re-checked against the same grammar from the token's side, which is
    // where the `${...}` allowance is decided per token rather than globally.
    check_pkgconfig_value("prefix", &prefix, false)?;

    let values: Vec<(&str, String)> = vec![
        // The same four directories curl-config uses.
        ("prefix", prefix),
        ("exec_prefix", "${prefix}".to_string()),
        ("libdir", "${exec_prefix}/lib".to_string()),
        ("includedir", "${prefix}/include".to_string()),
        // :112 and :113, read back by
        // `pkg-config --variable=supported_protocols libcurl`. The same two
        // functions feed curl-config, so the two files cannot disagree.
        //
        // Routed through the pkg-config encoder even though both are joins of
        // static tokens and cannot today contain anything it would touch. Two
        // reasons, and the second is the one that matters: the template quotes
        // them (`supported_protocols="@SUPPORT_PROTOCOLS@"`, :112-113), so a
        // metacharacter would break the field rather than the file, and
        // `validate_environment_substitutions` currently guarantees they are
        // safe only by applying the STRICTER unquoted-shell rule. That
        // guarantee is real but indirect, and it would evaporate silently if
        // that rule were ever relaxed. Asking the destination's own encoder
        // makes the dependency explicit at no cost -- the output is
        // byte-identical to the input for every value these tables can produce.
        (
            "SUPPORT_PROTOCOLS",
            pkg_config_variable_body(
                "the protocol list",
                &advertised_protocols()?,
            )?,
        ),
        (
            "SUPPORT_FEATURES",
            pkg_config_variable_body(
                "the feature list",
                &advertised_features()?,
            )?,
        ),
        // The Version: field.
        ("CURLVERSION", facts.version.clone()),
        // BOTH DELIBERATELY EMPTY, and this is load-bearing. `Requires:`
        // names other pkg-config modules, and pkg-config FAILS OUTRIGHT if
        // one is missing -- `pkg-config --cflags libcurl` would error for
        // every consumer. Every C library curl used to require is now a
        // statically linked Rust crate with no .pc file at all: OpenSSL,
        // GnuTLS, mbedTLS and wolfSSL became rustls; nghttp2 became h2;
        // ngtcp2, nghttp3 and quiche became quinn, h3 and h3-quinn; libssh2
        // and libssh became russh; zlib became flate2; the C brotli and zstd
        // libraries became the brotli and zstd crates; c-ares became the
        // system resolver; libidn2 became idna; libpsl became publicsuffix;
        // libuv became tokio. Naming any of them would be a lie that breaks
        // the build of everything downstream. CMakeLists.txt:2144 and :2260
        // leave both empty too.
        ("LIBCURL_PC_REQUIRES", String::new()),
        ("LIBCURL_PC_REQUIRES_PRIVATE", String::new()),
        // :153 keeps the literal -lcurl, which is why curl-rs-ffi/Cargo.toml
        // sets [lib] name = "curl": the artifacts must really be libcurl.so
        // and libcurl.a. Nothing further is needed here.
        ("LIBCURL_PC_LIBS", String::new()),
        ("LIBCURL_PC_LDFLAGS_PRIVATE", String::new()),
        // The same authority curl-config --static-libs reads.
        ("LIBCURL_PC_LIBS_PRIVATE", private_libs(&target_os)?),
        ("LIBCURL_PC_CFLAGS", String::new()),
        // CMakeLists.txt:2255. Consumers linking the static library must
        // define this so the public headers do not mark the API
        // dllimport-style on platforms that distinguish the two.
        ("LIBCURL_PC_CFLAGS_PRIVATE", "-DCURL_STATICLIB".to_string()),
    ];

    // Validate EVERY value, not just the externally derived one. The values
    // above are computed rather than inherited, but `advertised_features` and
    // `advertised_protocols` are assembled from a capability table that will
    // grow, and `private_libs` from a native-link authority that already
    // varies per platform -- so the check belongs on the grammar, not on
    // provenance. `${...}` is allowed only for the three tokens whose values
    // ARE deliberate pkg-config variable references; `"` is rejected for the
    // two `supported_*` fields the template double-quotes, where a quote would
    // end the value early and leave the rest as stray text.
    const PKGCONFIG_VARIABLE_TOKENS: [&str; 3] =
        ["exec_prefix", "libdir", "includedir"];
    const PKGCONFIG_QUOTED_FIELDS: [&str; 2] =
        ["SUPPORT_PROTOCOLS", "SUPPORT_FEATURES"];

    for (token, value) in values.iter() {
        check_pkgconfig_value(
            token,
            value,
            PKGCONFIG_VARIABLE_TOKENS.contains(token),
        )?;
        if PKGCONFIG_QUOTED_FIELDS.contains(token) && value.contains('"') {
            return Err(format!(
                "the value for @{token}@ contains a double quote, but \
                 libcurl.pc.in encloses that field in double quotes. The \
                 value would end early and the remainder would become stray \
                 text in the field."
            )
            .into());
        }
    }

    check_placeholder_coverage(
        "libcurl.pc.in",
        &template,
        &values,
        LIBCURL_PC_PLACEHOLDERS,
    )?;

    let rendered = substitute(&template, &values);
    check_no_residual_placeholders("libcurl.pc", &rendered)?;
    check_text_hygiene("libcurl.pc", &rendered)?;

    // pkg-config reads these two keys; a missing one is a silent failure at
    // the consumer rather than here.
    for key in ["Name:", "Version:", "Libs:", "Cflags:"] {
        if !rendered.lines().any(|line| line.starts_with(key)) {
            return Err(format!(
                "rendered libcurl.pc has no {key} field, so pkg-config \
                 would not describe the library"
            )
            .into());
        }
    }

    // Data, not a script. Explicitly NOT MODE_SCRIPT.
    publish_metadata("lib/pkgconfig/libcurl.pc", &rendered, MODE_DATA)?;

    Ok(())
}
