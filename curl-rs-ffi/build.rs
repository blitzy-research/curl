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
//! # Three traps, each proven by running code rather than by reading
//!
//! ## Trap 1: emit single-colon `cargo:` directives, never `cargo::`
//!
//! The `cargo::key=value` spelling was stabilised in Cargo 1.77. This
//! workspace declares `rust-version = "1.75"`. Measured on this machine
//! with a throwaway cdylib crate:
//!
//! ```text
//! cargo +1.75.0, "cargo::rustc-link-arg-cdylib=..."
//!   -> build fails; readelf -d shows NO SONAME. Cargo 1.75 prints
//!      "Either change the directive to `cargo:key=value` syntax (note
//!      the single `:`) or upgrade your version of Rust."
//! cargo +1.75.0, "cargo:rustc-link-arg-cdylib=..."
//!   -> Library soname: [libcurl.so.4]
//! cargo 1.97.1,  "cargo:rustc-link-arg-cdylib=..."
//!   -> Library soname: [libcurl.so.4]
//! ```
//!
//! So every directive below uses one colon. A future contributor
//! "modernising" the syntax would silently produce a `libcurl.so` with no
//! `DT_SONAME`, which fails the symbol-parity gate with no diagnostic that
//! points anywhere near the cause. Do not do it. Note the distinction: the
//! *instruction* `rustc-link-arg-cdylib` has been stable since Rust 1.50;
//! only the `cargo::` *prefix syntax* is version-sensitive.
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
//! * No linker version script, and no export-hiding script. Both were
//!   measured to be pointless: a user-supplied `--version-script` handed
//!   through `-C link-arg` does not control Rust exports, because rustc's
//!   internal export list takes precedence, so symbol names of the form
//!   `name@@CURL_OPENSSL_4` are unreachable that way. That is a documented
//!   deviation, exactly equivalent to curl's own supported
//!   `--disable-versioned-symbols` build mode. Hiding is
//!   unnecessary besides: a cdylib exporting only its
//!   `#[no_mangle] pub extern "C"` items measured total=2, curl_*=2,
//!   leaked=0. Export parity comes from declaration discipline, not from
//!   link-time filtering.
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
//!   rule exists to prevent. `option_table_ground_truth` below holds the
//!   measured facts `src/ffi/opts.rs` is checked against.
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
//!
//! # Text hygiene
//!
//! `scripts/spacecheck.pl` walks `git ls-files` and rejects, for any path
//! not in one of its allow-lists, a tab, a non-LF line ending, trailing
//! whitespace, a missing or duplicated newline at EOF, two consecutive
//! blank lines and any byte in 0x80-0xff. This path matches none of those
//! allow-lists, so all of it applies, and that is why nothing below uses a
//! typographic dash, arrow or section sign. It runs in CI at
//! `.github/workflows/hygiene.yml:164-165` and from `Makefile.am:175`.

use std::env;
use std::error::Error;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
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
///
/// The literal 4 appears once, here, so the two names below cannot drift
/// apart from each other or from the C build.
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
const TRACKED_ENV: [&str; 6] = [
    "CURL_RS_PREFIX",
    "CC",
    "TARGET_CC",
    "CURL_CA_BUNDLE",
    "CURL_RS_STAGING_DIR",
    A4_DECISION_ENV,
];

/// Every environment variable this script reads, including the two whose
/// names are derived from `TARGET`.
///
/// [`compiler`] resolves `CC_<target>` and `CC_<target_with_underscores>`
/// ahead of `TARGET_CC` and `CC`, so a change to either must re-render the
/// consumer metadata. Cargo cannot be told about a variable whose name is not
/// a literal, which is why the list is assembled rather than declared.
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
// Two of this project's own requirements contradict each other, and this is
// the only place that can see the contradiction at build time. Specification
// 0.8.6 records the ambiguity as A4 and calls silent acceptance "the worst
// option"; what follows is the mechanism that makes it impossible.
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
// A further eleven of the 100 exports have no ABI-correct expression on ANY of
// the four targets at the declared minimum Rust version -- five plain printf
// variadics, five `va_list` forms and curl_formadd -- because `va_start` and
// `VaList::next_arg` are unavailable there.
//
// So the build REFUSES, in `check_variadic_abi`, which `main` calls where an
// `Err` can stop it. A `cargo:warning` -- which is what used to be here -- was
// the wrong instrument twice over: it is not a refusal, so an unsound artifact
// still shipped; and specification 0.8.4's validation gate 1 requires a
// warning-free build, so a permanent warning is a gate that is either
// suppressed or scrolled past.
//
// The refusal is released only by a recorded decision, never by a default, and
// the single warning that acceptance produces fires only where that acceptance
// actually suppressed a refusal. Both of those are policy rather than
// convenience, and both are argued in full on `variadic_abi_verdict`.
//
// A MEASURED REMEDY EXISTS FOR THE FOUR, AND IT DOES NOT CLOSE A4. A
// `global_asm!` trampoline that reloads the third argument from the stack
// (`ldr x2, [sp]`) before branching to the implementation was built on
// stable 1.97.1 AND on 1.75.0 with no C compiler, and llvm-nm shows the
// trampoline exported as a global `T` with the implementation left as a
// local `t`. `check_variadic_strategy` REQUIRES that trampoline, on every
// target, of any plain non-variadic definition of the four -- so the hazard
// cannot be introduced unnoticed from a Linux workstation, which is where it
// would otherwise be introduced. Two things the trampoline does not do, and
// they are why this section stays: it cannot make the eleven above
// implementable at the declared minimum, and it is exercised by nothing
// today, because none of the four has a Rust body -- all four are carried
// into the generated headers as verbatim prototypes. A4 remains open, and
// `check_variadic_abi` remains the instrument that says so out loud.

/// Records the A4 decision, which is a user's to make and not this file's.
const A4_DECISION_ENV: &str = "CURL_RS_A4_VARIADIC_DECISION";

/// The only accepted value, spelled so it cannot be set by accident.
///
/// It names the decision it records -- specification 0.8.6's third option,
/// "accept that one target's varargs entry points are unsupported" -- rather
/// than reading like a switch that silences a nuisance. Setting it is an
/// assertion that the consequence below is understood and accepted:
///
/// * `curl_easy_setopt`, `curl_easy_getinfo`, `curl_multi_setopt` and
///   `curl_share_setopt` are NOT ABI-correct on aarch64-apple-darwin. A C
///   caller reaches them through the variadic prototype in the generated
///   header and the callee reads a register the caller did not write.
/// * The eleven exports in [`VARIADIC_UNIMPLEMENTABLE`] remain unimplemented
///   on every target until the minimum Rust version rises or an approved C
///   shim is added.
const A4_ACCEPTED: &str = "accept-unsupported-varargs";

/// The eleven exports with no ABI-correct expression at the declared minimum.
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
///
/// Kept beside the eleven and asserted disjoint from them, because conflating
/// the two sets is the mistake that would make either gate look satisfied when
/// it is not. `include/curl/curl.h:3328-3341` corroborates the split from the
/// header's own side: it defines three-argument enforcement macros for exactly
/// these four and for none of the rest.
const VARIADIC_TRAILING_POINTER: [&str; 4] = [
    "curl_easy_setopt",
    "curl_easy_getinfo",
    "curl_multi_setopt",
    "curl_share_setopt",
];

/// The two modules that would implement the eleven, relative to the manifest.
///
/// Their absence is what keeps the second half of the gate inert today: there
/// is nothing to ship, so nothing can ship wrongly. The moment either appears,
/// the gate applies -- which is the point at which the decision genuinely has
/// to have been made.
const VARIADIC_IMPLEMENTATION_FILES: [&str; 2] =
    ["src/ffi/printf.rs", "src/ffi/form.rs"];

// The four headers that must never be written

/// Public headers cbindgen cannot express, carried verbatim in the tree.
///
/// Line counts measured in this checkout:
///
/// * `system.h` (399) is pure platform detection. It produces `curl_off_t`,
///   `CURL_FORMAT_CURL_OFF_T` and `CURL_TYPEOF_CURL_SOCKLEN_T` from a
///   cascade of compiler and OS probes; there is nothing for a generator to
///   render.
/// * `stdcheaders.h` (35) declares four libc prototypes and includes only
///   `<sys/types.h>`.
/// * `curlver.h` (78) is entirely `#define`, including the function-like
///   `CURL_VERSION_BITS(x, y, z)` and `CURL_AT_LEAST_VERSION(x, y, z)`.
/// * `typecheck-gcc.h` (958) holds the `curlcheck_` macro family that gives
///   `curl_easy_setopt`'s variadic arguments compile-time type checking. It
///   is hand-maintained and shipped verbatim beside the generated headers,
///   and it must stay correct because all 129 programs in `docs/examples/`
///   compile with it active.
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

/// Items owned by `urlapi.h`: the two URL-API enums and six functions.
/// `CURLU` itself is verbatim, because `urlapi.h:107` spells it
/// `typedef struct Curl_URL CURLU;`, where the tag differs from the typedef
/// name, and cbindgen would emit `typedef struct CURLU CURLU;`.
const URLAPI_H_ITEMS: &[&str] = &[
    "CURLUcode",
    "CURLUPart",
    "curl_url",
    "curl_url_cleanup",
    "curl_url_dup",
    "curl_url_get",
    "curl_url_set",
    // The 16 CURLU_* flag bits, urlapi.h:84-105.
];

/// Items owned by `options.h`: `curl_easytype` and the three introspection
/// functions. `struct curl_easyoption` is verbatim, being layout-visible.
const OPTIONS_H_ITEMS: &[&str] = &[
    "curl_easytype",
    // options.h:47, and the only flag bit the API defines.
    "CURLOT_FLAG_ALIAS",
];

/// Items owned by `header.h`: `CURLHcode`, the five `origin` bits and two
/// functions. `struct curl_header` is verbatim, being layout-visible.
const HEADER_H_ITEMS: &[&str] = &[
    "CURLHcode",
    // The 'origin' bits, header.h:41-45.
    "curl_easy_header",
    "curl_easy_nextheader",
];

/// Items owned by `websockets.h`: nine flag bits and four functions.
/// `struct curl_ws_frame` is verbatim, being layout-visible.
const WEBSOCKETS_H_ITEMS: &[&str] = &[
    // websockets.h:40-45, :60 and :89-90. CURLWS_PONG is separated from its
    // five siblings in the C header, which the note above records.
    "curl_ws_meta",
    "curl_ws_recv",
    "curl_ws_send",
    "curl_ws_start_frame",
];

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
///
/// Block comments are tracked so a `#define` mentioned inside an explanatory
/// comment is not mistaken for a real declaration -- without that, the guard
/// this feeds would raise a false failure that reads exactly like a real one.
/// Only a directive starting its own line counts, which is the form every
/// carrier uses.
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
// WHAT THIS SECTION CAN AND CANNOT DO.
//
// A prologue and an epilogue can place text before and after the generated
// block. They cannot interleave text *within* it. `cbindgen.toml` states
// where the excluded declarations are put back: ":968-975" assigns this
// script the per-header split and says in so many words that it is "also
// where the verbatim blocks excluded above are spliced back in".
//
// TWO MECHANISMS EXIST, AND CONFUSING THEM IS THE TRAP.
//
// The first is source order. `cbindgen.toml` sets `sort_by = "None"`, so
// cbindgen emits items in the order `curl-rs-ffi/src/ffi/*.rs` declares
// them. A name that is EXPORTED therefore lands wherever the Rust source
// puts it, and no splice is needed. `CURLWS_PONG (1 << 6)`
// (websockets.h:58) relies on exactly this: it appears *after*
// `curl_ws_recv` while its five siblings appear before it, and source order
// reproduces that for free.
//
// The second is this section. A name listed under `[export] exclude` is
// removed in `Library::remove_excluded` BEFORE dependency collection and
// before anything is written, so source order can never place it -- it is
// simply gone. Every excluded name must therefore be written out here or it
// is absent from the ABI contract. That was measured rather than reasoned
// about: compiling `#include <curl/curl.h>` reported `unknown type name`
// for the excluded declarations until they were spliced.
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
//
// A prototype's POSITION within a header is not part of the ABI: no
// consumer can observe it, and `docs/libcurl/*.md` synopses name functions,
// not line numbers. What IS observable -- the declaration's spelling, its
// parameter list, its deprecation attribute -- is reproduced byte for byte
// from the C header. The positional difference is recorded here because it is
// the one difference a reader diffing the two headers will see.
//
// A violation of the observable part is caught by compiling all 129 programs
// in `docs/examples/` against the generated headers and comparing the exported
// symbol set against `lib/libcurl.def`. That gate is the ABI leg in
// `.github/workflows/rust-abi.yml`, which is on disk and runs both legs. The
// checks in this build script are still written to fail closed rather than
// warn, because they run on every build rather than only in continuous
// integration.

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
///
/// Reproduced byte for byte from `easy.h:42` and `easy.h:46-59`, comment
/// included. The comment is part of the frozen file and
/// `.github/scripts/verify-synopsis.pl` reads the tree's documentation
/// against these declarations, so dropping it would be an unrequested
/// change.
///
/// Position differs from the C header: `curl_easy_setopt` sits at `:42`
/// between `curl_easy_init` and `curl_easy_perform`, and lands here after
/// all of easy.h's generated prototypes instead. `CURLoption` and `CURLINFO`
/// are both complete by this point -- `curl.h` includes `easy.h` from its
/// own trailer, after `CURL_H_VERBATIM` -- so the declarations compile.
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
/// `struct curl_waitfd` (multi.h:114) depends on nothing generated --
/// `curl_socket_t` comes from `curl.h` -- so it is declared here in full.
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
/// `struct CURLMsg` is placed here because it names the generated `CURLMSG`
/// enum, and a struct definition may follow every use of a pointer to it.
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
///
/// `curl_multi_setopt` (multi.h:422-430) is the third C-variadic setter, so
/// it is excluded for the same reason as easy.h's two, and its block comment
/// is reproduced with it.
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

/// `header.h`, after the `extern "C"` open. Layout-visible, so verbatim:
/// consumers read all six fields. Nothing it names is generated, so the
/// full definition sits in the prologue, exactly where `header.h:31` has
/// it, and every prototype that takes a `struct curl_header **` therefore
/// sees a complete type.
const HEADER_H_DECLS: &str = r#"
struct curl_header {
  char *name;    /* this might not use the same case */
  char *value;
  size_t amount; /* number of headers using this name  */
  size_t index;  /* ... of this instance, 0 or higher */
  unsigned int origin; /* see bits below */
  void *anchor; /* handle privately used by libcurl */
};

/* ---- verbatim from header.h, not generated ---- */
/* cbindgen cannot carry these faithfully, measured on all three
   forms: it DROPS an `L` suffix (`2L` becomes `2`, changing the
   varargs type of a long option), rewrites hex as decimal, and
   cannot express a #define whose value is another identifier.
   The five `origin` bits of `struct curl_header` are therefore
   spliced from the frozen header exactly as written. */
/* 'origin' bits */
#define CURLH_HEADER    (1 << 0) /* plain server header */
#define CURLH_TRAILER   (1 << 1) /* trailers */
#define CURLH_CONNECT   (1 << 2) /* CONNECT headers */
#define CURLH_1XX       (1 << 3) /* 1xx headers */
#define CURLH_PSEUDO    (1 << 4) /* pseudo headers */
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
const URLAPI_H_INCLUDES: &str = "\n#include \"curl.h\"\n";

/// `urlapi.h`, after the `extern "C"` open.
///
/// The subtler of the two handle mis-renderings. `urlapi.h:107` spells this
/// `typedef struct Curl_URL CURLU;`, where the struct tag differs from the
/// typedef name. cbindgen would emit `typedef struct CURLU CURLU;`, which
/// compiles and is still wrong, because it introduces a different
/// incomplete type than the one libcurl's own translation units define.
/// `urlapi.h`, after the generated block: the one prototype whose parameter is
/// a CURLUcode while the Rust definition must take a c_int. It has to follow
/// the generated block because that is where CURLUcode is declared. See
/// cbindgen.toml, "Group 5e".
const URLAPI_H_POST: &str = r#"
/*
 * curl_url_strerror turns a CURLUcode value into the equivalent human
 * readable error string. This is useful for printing meaningful error
 * messages.
 */
CURL_EXTERN const char *curl_url_strerror(CURLUcode);
"#;

const URLAPI_H_DECLS: &str = r#"
typedef struct Curl_URL CURLU;

/* ---- verbatim from urlapi.h, not generated ---- */
/* cbindgen cannot carry these faithfully, measured on all three
   forms: it DROPS an `L` suffix (`2L` becomes `2`, changing the
   varargs type of a long option), rewrites hex as decimal, and
   cannot express a #define whose value is another identifier.
   The sixteen CURLU_* flag bits are therefore
   spliced from the frozen header exactly as written. */
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
"#;

/// `websockets.h`, after the `extern "C"` open. Layout-visible, so
/// verbatim: consumers read all five fields of the frame metadata.
const WEBSOCKETS_H_DECLS: &str = r#"
struct curl_ws_frame {
  int age;              /* zero */
  int flags;            /* See the CURLWS_* defines */
  curl_off_t offset;    /* the offset of this data into the frame */
  curl_off_t bytesleft; /* number of pending bytes left of the payload */
  size_t len;           /* size of the current data chunk */
};

/* ---- verbatim from websockets.h, not generated ---- */
/* cbindgen cannot carry these faithfully, measured on all three
   forms: it DROPS an `L` suffix (`2L` becomes `2`, changing the
   varargs type of a long option), rewrites hex as decimal, and
   cannot express a #define whose value is another identifier.
   The nine CURLWS_* frame and option bits are therefore
   spliced from the frozen header exactly as written. */
/* flag bits */
#define CURLWS_TEXT       (1 << 0)
#define CURLWS_BINARY     (1 << 1)
#define CURLWS_CONT       (1 << 2)
#define CURLWS_CLOSE      (1 << 3)
#define CURLWS_PING       (1 << 4)
#define CURLWS_OFFSET     (1 << 5)

/* flags for curl_ws_send() */
#define CURLWS_PONG       (1 << 6)

/* bits for the CURLOPT_WS_OPTIONS bitmask: */
#define CURLWS_RAW_MODE   (1L << 0)
#define CURLWS_NOAUTOPONG (1L << 1)
"#;

/// `mprintf.h`, before the `extern "C"` open.
///
/// Three includes that `no_includes` suppresses, so they are verbatim.
/// The inline comments explain why each is needed and are preserved.
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
        verbatim: &[],
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
        verbatim: &[],
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
        verbatim: &[],
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
// `cbindgen.toml` supplies curl.h's `header` (148 lines) and `trailer` (37
// lines) and deliberately leaves `after_includes` empty; ":1280" records it
// as unused there precisely because this script overrides it per header.
// The two constants below fill that gap for the umbrella.
//
// Every block is reproduced BYTE FOR BYTE from `include/curl/curl.h` at
// commit 54cf587b9c, `LIBCURL_VERSION "8.19.0-DEV"`. Each carries its source
// line range so it can be checked with `sed -n 'A,Bp'`. Nothing
// here is retyped, reformatted, re-indented or re-commented: the public
// headers are frozen, and a "tidier" spelling of a frozen file is an
// unrequested change.
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
// SPLIT BETWEEN THE TWO CONSTANTS. A block goes in `CURL_H_FORWARD`, before
// the generated body, when something generated names it BY VALUE -- an
// incomplete type will not do there, and a C enum cannot be forward
// declared at all. Measured cases: `curl_global_sslset` takes
// `curl_sslbackend` and a `const curl_ssl_backend ***`; `curl_sshkeycallback`
// takes `enum curl_khmatch`; the `curl_mime_*` prototypes take `curl_mime *`
// and `curl_mimepart *`; and the generated `CURLoption` enum expands the
// `CURLOPT` macro. Everything else goes in `CURL_H_VERBATIM`, after the
// body, where it can name generated types freely.
//
// WHAT IS DELIBERATELY NOT HERE.
//
//   * `CURLoption` (curl.h:1138-2262) and its 17 `#define` aliases. Option
//     identity has one source of truth, `curl-rs-ffi/src/ffi/opts.rs`, which
//     must emit both the enumeration and the metadata array and does not
//     exist yet. Splicing 1,125 lines of enumeration here would create a
//     second population, and two populations drift silently.
//     `cbindgen.toml` lists `CURLoption` under `[export] exclude`;
//     `curl_h_export_exclusions` lifts that one exclusion for the umbrella
//     pass so the enumeration is generated from `opts.rs` instead. The
//     generator macros it expands ARE here, which is what
//     `cbindgen.toml`'s "deliberately not here" note asks for.
//   * `include/curl/curl.h`'s own text is never READ by this script. The
//     header is an OUTPUT of this build, so parsing it would close a cycle
//     (header <- build.rs <- header) and reintroduce exactly that drift.
//     `include/curl/curlver.h` is read, and only because it is in
//     `NEVER_GENERATED` and therefore an input.

/// `curl.h`'s backward-compatibility `#define` blocks, carried verbatim.
///
/// These cannot be generated. cbindgen emits no preprocessor conditionals at
/// all, and the frozen header wraps most of these aliases in `#ifndef
/// CURL_NO_OLDIES` guards (include/curl/curl.h:650-736 and :2264-2295) with
/// `#undef CURLOPT_DNS_USE_GLOBAL_CACHE` in the `#else` branch. Emitting the
/// aliases without their guards would change observable behaviour for an
/// application that defines `CURL_NO_OLDIES` -- it would keep receiving every
/// retired spelling it asked not to have -- and AAP 0.8.1 freezes the C ABI.
///
/// Carrying them verbatim does NOT create the second population AAP 0.1.2
/// warns about, and that is the whole reason this is safe: every alias here
/// expands to an IDENTIFIER, never to a literal, so each one resolves THROUGH
/// the generated `CURLcode` and `CURLoption` enumerations. Change a value in
/// `ffi/codes.rs` or `ffi/opts.rs` and every alias below follows it
/// automatically. The two exceptions are numeric by design in the frozen
/// header itself -- `CURLE_ALREADY_COMPLETE 99999` and the pair
/// `CURLOPT_OBSOLETE72`/`CURLOPT_OBSOLETE40 9999`, retired slots that no
/// longer have an enumerator to point at.
///
/// The alias -> target mapping is still held in Rust, in
/// `ffi/opts.rs`'s `OPTION_ALIASES`, where a test asserts that all 19
/// `CURLOPT_*` aliases resolve to the integers AAP 0.6.1 requires.
///
/// Placement. Everything here is a `#define`, so it is valid anywhere the
/// preprocessor sees it before use; it goes after the generated body because
/// two of the blocks name generated enumerators and one of them
/// (`CURLOPT_PROGRESSDATA`, frozen at curl.h:1341) sits INSIDE the
/// `typedef enum` in the original, which is a position cbindgen cannot write
/// into. `CURLOPT_RTSPHEADER` (curl.h:2306) is unguarded in the frozen header
/// and stays unguarded here.
///
/// NOT here, deliberately: the `CURLFTPSSL_*` block (curl.h:972-984) and the
/// `CURLAUTH_NTLM_WB` guard (curl.h:838-843). Both alias identifiers that no
/// Rust module declares yet -- `CURLUSESSL_*` and the `CURLAUTH_*` family --
/// and splicing a `#define` whose target does not exist would hand consumers
/// a macro that fails to compile on use. They arrive with the types they
/// depend on. Every target named below was verified present in the generated
/// header before this block was added.
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
///
/// No leading newline. cbindgen calls `new_line_if_not_start()` before this
/// block and that call does emit a separator, so a leading newline here
/// produces two consecutive blank lines, which `scripts/spacecheck.pl`
/// rejects.
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
///
/// The other 32 callback typedefs are generated from
/// `curl-rs-ffi/src/ffi/types.rs`. These three are spliced verbatim above, in
/// the authority's own formatting and line order, and are named here so that
/// the "nothing is both generated and written verbatim" invariant still holds.
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
///
/// Nineteen blocks, each with its curl.h line range. Reproduced byte for
/// byte; the ranges are exact so `diff <(sed -n 'A,Bp' include/curl/curl.h)`
/// against the generated header is a one-line review step.
///
/// No leading newline, and none at the end: cbindgen separates the trailer
/// with `new_line_if_not_start()` and appends exactly one newline when the
/// trailer lacks it (`language_backend/mod.rs:220-227`), which is the single
/// end-of-file newline `scripts/spacecheck.pl` wants.
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
///
/// Multi-line comments are carried whole. Several of these directives end in a
/// comment that continues onto following lines, so extracting the directive
/// line alone leaves an unterminated `/*` that swallows everything after it --
/// measured as gcc rejecting the header with `unknown type name 'network'`
/// while 12 `CURLAUTH_*`, `CURLFTPSSL_*` and `CURL_SSLVERSION_*` constants
/// silently vanished from a consumer's view.
///
/// Emitted between [`CURL_H_VERBATIM`] and [`CURL_H_OLDIES`]. Placement is
/// free: a macro body is expanded at its use site, so a constant naming an
/// enumerator or another macro does not require that name to be declared
/// first.
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
// Both renderers below read these two tables, so `curl-config --features`
// and `libcurl.pc`'s `supported_features` cannot disagree with each other.
//
// AND THEY CANNOT DISAGREE WITH THE RUNTIME BANNER EITHER, because the feature
// tokens are no longer written down here at all: they are DERIVED from
// `curl-rs-lib/src/version.rs`, which specification 0.4.1 designates as the
// authority for the feature and protocol banner. An earlier revision of this
// file carried its own 23-row table beside a note saying the two "cannot be
// unified in code here" and that "the peer is named so the correspondence is
// checkable" -- but the check was never written, and the tables drifted in five
// places at once: this file claimed `asyn-rr`, `HTTPSRR`, `Debug` and a
// non-standard standalone `TrackMemory` that the engine withholds, and omitted
// the `HTTPS-proxy` the engine advertises. Two hand-maintained lists of the
// same facts always end that way.
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
    /// `ENGINE_X.is_present()` -- gated on whether the engine module that owns
    /// the capability has actually been written. Resolved at parse time by
    /// reading the `Engine::present`/`Engine::absent` constructor of the named
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
///
/// A `Protocol` row is a strict subset of a `Feature` row: it carries a name
/// and a `compiled_in:` gate but no `present:` probe, because a scheme this
/// build serves is served unconditionally once compiled in. There is
/// therefore no [`Probe`] field to resolve, and no runtime-only case to
/// withhold.
struct RuntimeProtocol {
    /// The scheme name, LOWER case, exactly as the engine spells it.
    token: String,
    /// The compile-time gate on serving the scheme.
    gate: Gate,
}

/// Where the engine's capability tables live, relative to this crate.
///
/// One file owns both the feature table and the protocol table, because
/// specification 0.4.1 makes `version.rs` the authority for the whole
/// `curl --version` banner. Reading it here rather than mirroring it is what
/// makes the generated consumer metadata and the runtime banner two
/// projections of one list.
const ENGINE_VERSION_RS: &str = "../curl-rs-lib/src/version.rs";

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
/// (specification 0.4.1). This reads it rather than mirroring it, so the static
/// consumer metadata and the runtime `--version` banner are two projections of
/// one list and cannot describe different products.
///
/// Everything is checked rather than assumed. An unreadable file, a missing
/// table, an empty table, a duplicate token, an unrecognised gate and an
/// unresolvable probe are each a hard error that names what it found. The one
/// thing this must never do is guess: a misread gate either invents a capability
/// or drops a real one.
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
///
/// Derived from the same authority as the feature set, for the same reason: a
/// hand-mirrored copy here and a live table in the engine are two statements
/// that can disagree, and a consumer reading the generated metadata would then
/// be told about a different product than `curl --version` describes. The two
/// copies happened to agree when this derivation replaced the mirror, which is
/// exactly why the mirror had to go before they drifted.
///
/// Every scheme name is asserted to be lower case, because the metadata this
/// feeds is upper case and the transformation between them must be a checked
/// rule rather than an assumption -- see [`advertised_protocols`].
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
    // A `compiled_in:` expression may be written across several lines by
    // rustfmt, so collapse the whitespace before matching any shape.
    let flat = expr.split_whitespace().collect::<Vec<_>>().join(" ");

    // `&&` is the only operator the grammar admits, and it binds every
    // conjunct: a row is compiled in only when all of them hold.
    let parts: Vec<&str> = flat.split("&&").map(str::trim).collect();
    if parts.len() > 1 {
        let mut gates = Vec::with_capacity(parts.len());
        for part in parts {
            gates.push(classify_conjunct(part, token, source)?);
        }
        return Ok(Gate::All(gates));
    }

    classify_conjunct(&flat, token, source)
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
    Err(format!(
        "{token} has a `compiled_in:` expression this build script does not \
         recognise: `{expr}`. The grammar is closed deliberately -- guessing \
         would either invent a capability or drop a real one -- so extend \
         `classify_gate` with the new shape and its evaluation."
    )
    .into())
}

/// Read whether an `ENGINE_*` constant in the engine's version module was
/// declared present.
///
/// The constants are written `Engine::present("path")` or
/// `Engine::absent("path")`, so the state is a literal in the source and this
/// script resolves it without executing the engine. An unknown constructor is
/// an error rather than a guess, for the same reason the gate grammar is
/// closed: silently reading an engine as present would advertise a capability
/// that does not exist, and the harness would then run fixtures against it.
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
    if body.starts_with("Engine::present(") {
        return Ok(true);
    }
    if body.starts_with("Engine::absent(") {
        return Ok(false);
    }
    Err(format!(
        "{konst} in {ENGINE_VERSION_RS} is initialised with `{body}`, which is \
         neither `Engine::present(..)` nor `Engine::absent(..)`; {token}'s \
         capability cannot be resolved without executing the engine"
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
            // All four mandated targets are 64-bit (specification 0.8.3), and
            // the engine derives this row from the width of curl_off_t. A
            // narrower target would need the engine consulted rather than
            // assumed, so it is rejected instead of guessed.
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
///
/// `rustls` is absent from this list because it IS advertised, and that
/// deserves its own note, resolved in favour of accuracy. The harness sets
/// `$feature{"rustls"}` from a
/// `rustls-ffi` token in the banner (tests/runtests.pl:585-586), not from
/// the word `rustls`. Emitting `rustls-ffi` would unlock the rustls-gated
/// fixtures but would misdescribe the implementation, which uses rustls
/// natively rather than through its C FFI, and `deny.toml` bans the
/// `rustls-ffi` crate outright for exactly that reason. So the truthful
/// token is emitted and the resulting skips are accepted, consistent with
/// under-reporting being the safe direction.
const WITHHELD: [(&str, &str); 17] = [
    // ---- The cross-artifact contract with curl-rs-lib/src/version.rs -------
    //
    // BOTH ARE WITHHELD UNCONDITIONALLY, NOT GATED ON `memdebug`. They were
    // gated once, on the reasoning that leaving the tokens unreachable would
    // make the `memdebug` feature inert. That reasoning was wrong on two
    // independent counts, and gating them created a disagreement between the
    // two artifacts this workspace ships.
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
    // exactly specification 0.8.6 ambiguity A5's resolution, and the cost is
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
///
/// Lower case, matching how libcurl names a backend at run time. Noted for
/// the record: `CMakeLists.txt:2059` spells the CMake-side label `Rustls`,
/// so the two differ in case; the lower-case spelling is the required one
/// here. `CURLSSLBACKEND_RUSTLS = 14` already exists in `curl_sslbackend`
/// (curl.h:166), so `curl_global_sslset` reports a rustls backend without
/// inventing an enumerant.
const SSL_BACKENDS: &str = "rustls";

// Measured ground truth for the option table.
//
// This script deliberately does NOT reimplement `lib/optiontable.pl`, and
// deliberately does NOT parse `include/curl/curl.h`. In the C build the
// public header was the source of truth and `lib/Makefile.am:179-180`
// derived the option table from it; here the arrow reverses, Rust source is
// the source of truth and the header is an output. Reading the header back
// in would close the loop and reintroduce the drift that the
// single-source rule exists to prevent, and the drift would stay invisible
// until a consumer asked for an option by name and got the wrong id.
//
// `curl-rs-ffi/src/ffi/opts.rs` is the sole source of truth for the
// CURLoption identifiers AND for the `curl_easyoption` metadata array that
// backs `curl_easy_option_by_name`, `curl_easy_option_by_id` and
// `curl_easy_option_next` (note that last spelling: it is
// `curl_easy_option_next`, not `_by_next`, confirmed in `lib/libcurl.def`).
// That module is on disk, and cbindgen renders both from it.
//
// The facts below come from RUNNING the C generator,
// `perl lib/optiontable.pl < include/curl/curl.h`, so that `opts.rs` can be
// checked against them without re-deriving anything. They are constants
// rather than prose because [`run_self_checks`] asserts the relationships
// between them, which prose cannot do.

/// Rows the C generator emits, including the terminating sentinel
/// `{ NULL, CURLOPT_LASTENTRY, CURLOT_LONG, 0 }`. Measured: 324.
///
/// Re-measured by running `perl lib/optiontable.pl < include/curl/curl.h`
/// and counting with brace-balanced scanning rather than a line regex. A
/// per-line regex undercounts, because the longer rows wrap onto a second
/// line; that is how this constant previously came to read 323, which is the
/// count EXCLUDING the sentinel and so contradicted its own documentation.
const OPTION_TABLE_ROWS: usize = 324;

/// Rows flagged `CURLOT_FLAG_ALIAS`. Measured: 15.
///
/// Not 17, and the arithmetic is worth spelling out because the discrepancy
/// looks like an error until it is traced. `include/curl/curl.h` has 19
/// `#define CURLOPT_` lines. Two are numeric rather than aliases
/// (`CURLOPT_OBSOLETE72 9999` at `:733` and `CURLOPT_OBSOLETE40 9999` at
/// `:734`), leaving 17 true aliases. Of those, two point at an obsolete
/// option (`CURLOPT_WRITEINFO` to `CURLOPT_OBSOLETE40` at `:731` and
/// `CURLOPT_CLOSEPOLICY` to `CURLOPT_OBSOLETE72` at `:732`) and the
/// generator skips them. 17 - 2 = 15.
const OPTION_TABLE_ALIAS_ROWS: usize = 15;

/// Rows describing something, excluding the sentinel. Measured: 323.
///
/// "Real" here means non-sentinel, NOT non-alias: 15 of these rows are
/// backward-compatibility aliases. The count of rows describing a PREFERRED
/// option is [`OPTION_TABLE_TRUE_OPTIONS`].
const OPTION_TABLE_REAL_ROWS: usize = OPTION_TABLE_ROWS - 1;

/// Rows describing a preferred option -- neither an alias nor the sentinel.
/// Measured: 308.
///
/// This is the number that has to agree with the enumeration, and AAP 0.6.1
/// reconciles it independently as 291 `CURLOPT(...)` invocations plus 17
/// `CURLOPTDEPRECATED(...)` invocations. Two populations, one number: the
/// enumeration comes from the frozen header and the table comes from
/// `lib/optiontable.pl`, so their agreement is evidence rather than
/// restatement. `ffi/opts.rs` asserts the same equality on the data itself.
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
/// four C-variadic setters, the five deprecated prototypes and the ten
/// `curl_m*printf` functions.
const VERBATIM_FUNCTIONS: usize = 31;

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
//
// And one compile-order fact that looks like style but is not:
// `include/curl/options.h` contains NO `#include` at all and depends on
// `curl.h` having already defined `CURLoption` and `CURL_EXTERN`. Measured
// across the tree, the same is true of `easy.h`, `header.h` and
// `websockets.h`. That is why the umbrella include order in `curl.h`'s
// trailer is load-bearing.

// Entry point

fn main() -> Result<(), Box<dyn Error>> {
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

    emit_link_args();

    // Needs the repository root, so it cannot live in run_self_checks. Runs
    // before any render: a symbol the headers would not declare is a defect in
    // the partition, not in the output.
    check_export_coverage(&root)?;

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
///
/// These run on every build rather than living in a `#[cfg(test)]` module,
/// and that is deliberate. `cargo test` does not compile or execute tests
/// declared inside a build script, so a test module here would be dead
/// weight that never caught anything. Checking at build time is the only
/// way to make these machine-enforced rather than review-enforced.
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
    //
    // Now asked of what is ACTUALLY ADVERTISED, derived from the engine's table,
    // rather than of a local list of what might be. That closes the hole the
    // previous form left open: a token could be absent from the local table --
    // and so pass this check trivially -- while the engine advertised it anyway.
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
    // `Debug` gates ALL memory checking in the harness (tests/runtests.pl:1759
    // via :660), and specification 0.6.6 records the deliberate decision to
    // withhold it so the 28 `<limits>` fixtures go inert rather than fail.
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

    // The option-table facts have to agree with each other. Prose cannot be
    // checked; arithmetic can.
    if OPTION_TABLE_REAL_ROWS + 1 != OPTION_TABLE_ROWS {
        return Err("option table row arithmetic is inconsistent".into());
    }
    if OPTION_TABLE_ALIAS_ROWS >= OPTION_TABLE_REAL_ROWS {
        return Err("alias rows cannot outnumber real option rows".into());
    }
    // 291 CURLOPT(...) + 17 CURLOPTDEPRECATED(...) per AAP 0.6.1, arrived at
    // from the other direction: 324 rows - 1 sentinel - 15 alias rows.
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
    // symbol exactly once. 100 symbols, 31 of them verbatim, so the eight
    // partitions must contribute 69 function names between them. Counting
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
///
/// Every branch below has a real destination behind it, and the values are the
/// ones that were actually measured against `sh` and `pkg-config 1.8.1` rather
/// than invented. Running on every build rather than under `cargo test` is not
/// a compromise here: `cargo test` never compiles a build script, so a test
/// module would be the coverage that never runs, and NUL in particular cannot
/// be exercised any other way -- a POSIX environment variable cannot contain
/// one, so no child process can carry it in. This is the only place that path
/// is reachable at all.
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

    // Only the verbatim text is searched. The generated portion of each header
    // is produced by cbindgen from source that does not exist yet for these
    // symbols, so searching it would assert nothing today and would silently
    // start passing for the wrong reason later.
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

/// Every symbol name `lib/libcurl.def` exports.
///
/// `EXPORTS` on line 1, then one bare name per line. The file is read rather
/// than trusted to a constant because it is the AUTHORITY: AAP 0.1.1 settles
/// the export count from it ("The binding requirement is 100, not 52"), and
/// AAP 0.8.4 gate 7 compares `nm` output against it.
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
///
/// whose REPLACEMENT LIST mentions `curl_multi_socket_action` as a USE. A use
/// is not a declaration, and counting it as one made a correct partition look
/// like a double declaration -- a false failure indistinguishable from a real
/// one. Stripping comments and string literals is therefore necessary but not
/// sufficient: a macro body is a third source of a name that declares nothing.
///
/// So a preprocessor logical line contributes exactly the name being defined,
/// and nothing else on it counts. Backslash continuations are tracked, because
/// `curl.h`'s `CURLAUTH_ANY` proves the carriers use them.
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
/// Review finding N-03 asks for exact export coverage from the `.def` file,
/// and this replaces the inequality `run_self_checks` could offer without
/// reading it. Each of the 100 names must be either claimed by a header
/// partition, and therefore generated, or present as a verbatim prototype,
/// and therefore hand-written -- never both and never neither.
///
/// Measured today: 69 claimed, 31 verbatim, disjoint, union 100 of 100,
/// nothing unaccounted. The 31 are the four C-variadic setters, the five
/// deprecated prototypes, the ten `curl_m*printf` functions and the twelve
/// whose frozen signature names a type this crate's Rust spelling cannot ask
/// cbindgen to produce (cbindgen.toml, "Group 5e"), which matches
/// [`VERBATIM_FUNCTIONS`] exactly.
///
/// This is a declaration-coverage check, not an export check: it asserts the
/// public headers will DECLARE all 100. Whether the library EXPORTS all 100 is
/// AAP 0.8.4 gate 7's job, asserted by `nm` in
/// `.github/workflows/rust-abi.yml`, because a build script cannot inspect a
/// binary it has not yet produced.
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
    // is watched. Review finding N-03.
    println!("cargo:rerun-if-changed=../lib/libcurl.def");
    // The capability authority, PARSED by runtime_feature_rows and
    // runtime_protocol_rows. The advertised feature and protocol sets in
    // curl-config and libcurl.pc are DERIVED from this file's two tables
    // rather than mirrored beside them, so adding a row, flipping a
    // `compiled_in:` gate or changing a `present:` probe must regenerate the
    // metadata. Without this directive the derivation would go stale and
    // reintroduce exactly the drift it was built to remove -- review finding
    // M-22, watched under the N-03 rule that every real authority is watched.
    println!("cargo:rerun-if-changed={ENGINE_VERSION_RS}");
    // The manifests. Both influence the generated contracts and neither was
    // watched before. This crate's own manifest carries the feature
    // forwarding that decides which capabilities the ABI reports, and
    // `version` feeds the banner; the workspace manifest is where every
    // dependency version and the MSRV are pinned, and cbindgen's
    // `Cargo::load` reads the manifest and the lock file while resolving the
    // crate it parses. Review finding N-03.
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=../Cargo.toml");
    println!("cargo:rerun-if-changed=../Cargo.lock");

    for key in tracked_env_keys() {
        println!("cargo:rerun-if-env-changed={key}");
    }

    // cbindgen.toml is an AUTHORITY, not a convenience, so its absence is
    // FATAL rather than a warning.
    //
    // It was a `cargo:warning=` that said "header generation will fail" and
    // then let the build carry on regardless. That was wrong twice over.
    //
    // It fails OPEN, which is the exact defect class review finding C-04
    // names: a missing authority item has to stop the build, because the
    // thing this file is missing is not decoration. cbindgen.toml carries the
    // verbatim header prologue that pins `typedef void CURL;`,
    // `typedef void CURLSH;`, `typedef void CURLM;`,
    // `typedef struct Curl_URL CURLU;` and `typedef struct CURLMsg CURLMsg;`
    // exactly as the frozen headers spell them (AAP section 0.6.3). Without
    // it cbindgen emits `typedef struct CURL CURL;` for the first three, which
    // changes the type of every handle-passing call and breaks the widespread
    // idiom of assigning a `CURL *` to a `void *` -- silently, in the
    // consumer's build rather than in ours. It also carries the `[export]`
    // exclusions and the verbatim carriers that keep 31 prototypes and 53
    // `#define`s byte-identical to the authority. A build that proceeded
    // without it would either fail with a less obvious message or, worse,
    // succeed and promote headers that no longer match.
    //
    // And it emits a WARNING, which breaks validation gate 1 -- a build with
    // zero warnings on all four targets (AAP section 0.8.4). A diagnostic that
    // announces a fatal condition while returning success is over-reporting in
    // one direction and under-reporting in the other.
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
fn emit_link_args() {
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
    // The warning broke specification 0.8.4 gate 1, which requires a build with
    // ZERO warnings on all four targets -- so on the very target it was warning
    // about, it was itself the gate failure.
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
    // trampoline makes a definition of the four sound, while the eleven
    // printf and va_list exports have no ABI-correct expression at the
    // declared minimum on ANY target, and none of the four has a Rust body
    // to trampoline yet. Refusing a target and requiring a trampoline answer
    // different questions; both are kept, and only one of them prints.
}

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
/// Both are released by the same recorded decision, `CURL_RS_A4_VARIADIC_DECISION
/// = accept-unsupported-varargs`, because both are the same ambiguity. Nothing
/// here chooses for the user: an unset variable produces a refusal that states
/// the three options, and the only value accepted is the one that names which
/// option was taken.
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

    match variadic_abi_verdict(&os, &arch, &decision, &present)? {
        Some(warning) => {
            println!("cargo:warning={warning}");
            Ok(())
        }
        None => Ok(()),
    }
}

/// The verdict itself: no environment, no filesystem, no output.
///
/// Split out from [`check_variadic_abi`] so every combination of target,
/// recorded decision and implementation state can be asserted directly. The
/// three outcomes are distinct on purpose:
///
/// * `Err(_)` -- refuse the build. The string is the whole diagnostic.
/// * `Ok(Some(_))` -- build, but emit this as a `cargo:warning`.
/// * `Ok(None)` -- build silently.
///
/// A warning is produced **only when the recorded decision actually suppressed
/// a refusal**, and this is the one subtle part of the policy, so it is worth
/// stating why. Validation gate 1 of specification 0.8.4 requires a
/// warning-free build on all four targets, and every workflow that builds this
/// crate sets `CURL_RS_A4_VARIADIC_DECISION` so the decision is visible in the
/// repository rather than implicit. If acceptance warned unconditionally, that
/// combination would break gate 1 on all four targets at once -- including the
/// three whose variadic ABI is entirely sound -- which would be noise, and
/// noise is how a real signal gets filtered out.
///
/// Warning only when acceptance is load-bearing gives the honest result
/// instead: the three sound targets stay silent and pass gate 1, and
/// `aarch64-apple-darwin` cannot pass gate 1 by either route -- unset, the
/// build fails; accepted, it warns. That is not a defect in this gate. It is
/// open ambiguity A4 being undisguisable, which is the entire point of
/// escalating it rather than picking a side.
fn variadic_abi_verdict(
    os: &str,
    arch: &str,
    decision: &str,
    implementations_present: &[&str],
) -> Result<Option<String>, String> {
    let decision = decision.trim();
    let accepted = decision == A4_ACCEPTED;

    // A misspelling must not read as consent. Silently treating an
    // unrecognised value as "not accepted" would be defensible, but it would
    // also mean a workflow that sets `accept_unsupported_varargs` (underscores)
    // fails with the long A4 refusal below and sends the reader looking for a
    // target problem that does not exist.
    if !accepted && !decision.is_empty() {
        return Err(format!(
            "{A4_DECISION_ENV} is set to {decision:?}, which is not a \
             recognised A4 decision. The only accepted value is the exact \
             string {A4_ACCEPTED:?}. An unrecognised value is refused rather \
             than ignored, so that a typo cannot read as consent."
        ));
    }

    // Condition 1: the target whose variadic ABI is known-wrong.
    if !accepted && os == "macos" && arch == "aarch64" {
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
             A4 requires a decision this build script cannot make:\n\
             \x20 1. Raise the minimum supported Rust version above 1.75 and \
             implement the four with c_variadic / VaList::next_arg.\n\
             \x20 2. Drop aarch64-apple-darwin from the target matrix.\n\
             \x20 3. Accept that this target's varargs entry points are \
             unsupported, by setting {A4_DECISION_ENV}={A4_ACCEPTED}.\n\
             \n\
             Option 3 is a recorded limitation, not a fix. Lifting this \
             refusal for the right reason means demonstrating option 1: a C \
             driver on aarch64-apple-darwin that calls all four through the \
             variadic prototype in the generated header and round-trips every \
             argument class.",
            VARIADIC_TRAILING_POINTER.join(", ")
        ));
    }

    // Condition 2: a module claiming to implement the eleven has appeared.
    if !accepted && !implementations_present.is_empty() {
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
             Either raise the minimum supported Rust version and implement \
             them, or record the decision to ship without them by setting \
             {A4_DECISION_ENV}={A4_ACCEPTED}.",
            implementations_present.join(" and "),
            VARIADIC_UNIMPLEMENTABLE.join(", "),
            VARIADIC_TRAILING_POINTER.join(", ")
        ));
    }

    // Acceptance warns only where it is load-bearing. See the doc comment.
    let suppressed_a_refusal = accepted
        && ((os == "macos" && arch == "aarch64")
            || !implementations_present.is_empty());
    if suppressed_a_refusal {
        return Ok(Some(format!(
            "A4 decision on record ({A4_DECISION_ENV}={A4_ACCEPTED}): this \
             artifact is NOT a drop-in replacement for {} of the 100 exported \
             symbols. {} are unimplemented; on aarch64-apple-darwin {} are \
             additionally not ABI-correct. Specification 0.8.6 records this as \
             an accepted limitation, not as a fix.",
            VARIADIC_UNIMPLEMENTABLE.len(),
            VARIADIC_UNIMPLEMENTABLE.join(", "),
            VARIADIC_TRAILING_POINTER.join(", ")
        )));
    }

    Ok(None)
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
    ///
    /// Reading this header is not the prohibited round trip. The
    /// prohibition is on parsing `include/curl/curl.h`, which this script
    /// generates; `curlver.h` is never generated, so there is no loop.
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
        // protect. `curl-config.in:110`, `:111` and `:114` place it inside
        // BACKTICKS (`vmajor=`echo '@CURLVERSION@' | cut -d. -f1``) and `:130`
        // places it inside DOUBLE quotes, where `$` and a backtick are live.
        // libcurl.pc:35 makes it the `Version:` field, where a `#` truncates.
        //
        // The set below admits every version curl has ever carried --
        // `8.19.0-DEV`, `8.4.0`, a `-rc1` suffix -- and excludes every
        // metacharacter of both grammars. The provenance is a tracked header
        // rather than the environment, which lowers the likelihood but not the
        // consequence, and the check costs nothing.
        if let Some(bad) = version.chars().find(|c| {
            !(c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '+'))
        }) {
            return Err(format!(
                "LIBCURL_VERSION is {version:?}, which contains {bad:?}. Only \
                 ASCII alphanumerics and '.', '-', '_' and '+' are accepted, \
                 because this string is substituted into backticks at \
                 curl-config.in:110 and into libcurl.pc's Version: field, \
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
/// This is the "machine-enforced, not review-enforced" principle applied to
/// file output. A comment saying "do not generate system.h" is a hope; a
/// check that aborts the build is a guarantee. It runs immediately before
/// every write and also once at start-up over the whole header table, so a
/// mistake is caught before any file is touched rather than after some have
/// been.
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
///
/// WHY THE NAME CARRIES A PID AND A SERIAL rather than being the fixed
/// `foo.h.new` this function used to return. Cargo runs one build script per
/// target, and the four targets AAP 0.8.3 mandates are routinely built from
/// one checkout -- `.github/workflows/rust-build.yml` does exactly that.
/// Every one of those processes computes the same `include/curl` destination,
/// because that path comes from the repository root and not from `OUT_DIR`.
/// With a fixed staging name they would all write the same
/// `include/curl/curl.h.new`: two processes interleaving there produce a file
/// that is half of one render and half of another, and `rename` then
/// publishes it atomically, so the corruption arrives in the tracked header
/// looking like a successful write. The PID separates processes and the
/// serial separates writes within a process, which together make a collision
/// impossible rather than unlikely.
///
/// The leading dot keeps the artifact out of the way of a `*.h` glob, and the
/// `.new` suffix is retained so the existing `.gitignore` entry still covers
/// it. Verified by measurement rather than assumed: `git status --porcelain`
/// reports nothing for a file of this shape.
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
///
/// WHY THE HEADERS ARE PROMOTED AS A SET. The eight generated headers are
/// not eight independent files; they are one partition of one ABI contract,
/// and `curl.h` `#include`s the other seven. Promoting them one at a time --
/// which is what this script used to do, calling `write_if_changed` from
/// inside the generation loop -- means a validation failure on the sixth
/// sibling leaves five new headers and three old ones on disk. That mixture
/// has never been reviewed and need not even be valid C: a name moved from
/// `curl.h` to `easy.h` between two runs would be declared twice, or not at
/// all, in exactly the window a consumer might compile in. Review finding
/// M-06 names this, and C-04 requires that nothing be promoted "unless every
/// header passes".
///
/// Staging every header first and renaming only after the last validation has
/// passed makes the failure mode leave the tracked headers BYTE-UNCHANGED,
/// which is the property the discrimination probes assert.
///
/// The promotion loop itself is not atomic across files -- POSIX offers no
/// such primitive for eight renames -- but each individual `rename` is, and
/// by the time the loop runs every byte has already been written and
/// validated. What remains is a sequence of metadata operations that can only
/// fail for reasons unrelated to content (a vanished directory, a full inode
/// table), and that residual case is reported rather than swallowed.
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
    ///
    /// This is the half of the transaction that runs on the failure path.
    /// `generate_headers` returns `Err` from a dozen places after the first
    /// header has been staged, and every one of those early returns drops
    /// this value; without the cleanup each failed build would leave another
    /// `.curl.h.<pid>.<n>.new` behind in a tracked directory. Errors are
    /// deliberately ignored: this runs while another error is already
    /// propagating, and masking that error with a cleanup failure would hide
    /// the diagnosis the developer actually needs.
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
///
/// Returns whether the destination changed.
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
///
/// These four rules hold for every artifact this script writes, generated C
/// and rendered template alike: a file must not be empty, must end with
/// exactly one newline, must not contain a carriage return, and must not
/// contain two consecutive blank lines. `scripts/spacecheck.pl`, which runs
/// at `.github/workflows/hygiene.yml:164-165` and from `Makefile.am:175`,
/// enforces all four on the tree, and its allow-lists name nothing here.
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
///
/// `scripts/checksrc.pl:29` sets the cap at 79 columns and `:588` exempts a
/// line carrying a URL; `:176` is the LONGLINE message.
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
    validate_comments(label, text)?;
    Ok(())
}

/// Reject a header whose C block comments are not well formed.
///
/// This closes a failure mode that is invisible to every other check here, and
/// it was a live defect before it was added rather than a hypothetical one.
///
/// `documentation = true` in `cbindgen.toml` transcribes each exported item's
/// Rust doc comment into the generated header inside a `/* ... */` block. A
/// doc comment is ordinary Rust prose, so nothing stops it containing a
/// literal comment-close sequence -- and quoting a C preprocessor line such as
/// the `#else` arm of a conditional is a natural way to end up with one. When
/// that happens the emitted block ends early and every following line of prose
/// becomes stray C tokens.
///
/// Measured: a doc comment on `curl_global_sslset` that quoted `#else` together
/// with its trailing comment produced a `curl.h` that gcc rejected with
/// `error: stray '`' in program` followed by `error: unknown type name
/// 'answer'`. The build itself still succeeded, because a build script does not
/// compile the header it writes, so the breakage would have reached a consumer.
///
/// Three conditions are checked, each of which makes the header invalid C:
///
/// * a `*/` with no open block -- the signature of the failure above,
/// * a `/*` opened inside an already-open block, which C does not nest and
///   which gcc warns about, and
/// * a block still open at end of file.
///
/// A `//` line comment is not considered: `documentation_style = "c"` never
/// emits one, and `scripts/checksrc.pl:162` (CPPCOMMENTS) already forbids it.
/// String and character literals are skipped, so a `"*/"` inside a literal --
/// which is legal C -- is not mistaken for a delimiter.
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
///
/// The banner is load-bearing beyond decoration. It carries the
/// `Copyright (C) Daniel Stenberg` line that `scripts/checksrc.pl:161`
/// requires, and the licence-identifier line that `reuse lint` reads in the
/// `REUSE check` step of `.github/workflows/hygiene.yml:49-52`. Both are
/// asserted here, because a silently banner-less header would fail two live
/// gates far from the cause.
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
///
/// Also returned without a trailing newline, for the reason above.
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
///
/// No leading newline, for the same measured reason as
/// [`sibling_after_includes`]: cbindgen's `new_line_if_not_start()` before
/// the trailer already separates it from the last declaration.
/// Ends without a newline: cbindgen adds exactly one when the trailer lacks
/// it (`language_backend/mod.rs:220-227`), which is what
/// `scripts/spacecheck.pl` wants -- one newline at end of file, not two.
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
///
/// Used to build the partition and then to check it. It is defence in depth,
/// not the authority: the authority is compiling the 129 `docs/examples/`
/// programs, where a duplicated or missing declaration is a hard error from
/// the C compiler across every one of them. That gate is the ABI leg in
/// `.github/workflows/rust-abi.yml`. This check runs on every build rather
/// than only in continuous integration, so it is applied unconditionally
/// rather than only when discovery found something.
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
        //
        // so the name has to be taken from the following line. The C tree
        // does the same thing wherever CURL_DEPRECATED intervenes, which is
        // why the guard below also skips that macro.
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
///
/// `[export] include` is ADDITIVE: cbindgen only writes a type reachable
/// from an exported signature, and this list forces the rest. `[export]
/// exclude` is the blacklist, applied in `Library::remove_excluded` BEFORE
/// dependency collection, so an excluded item cannot be pulled back in by a
/// signature that mentions it. The partition therefore has to be expressed
/// as an exclusion of everything the header does not own.
///
/// `curl.h` is the DEFAULT OWNER, and that asymmetry is the point: it is
/// excluded from writing only what a sibling claims, so an item nobody
/// claimed still appears exactly once, in `curl.h`. Making `curl.h` a
/// whitelist instead would silently drop every unclaimed item, and silent
/// dropping of a public declaration is the failure mode this whole file
/// exists to prevent.
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
/// `cbindgen.toml` lists `CURLoption` under `[export] exclude`, and this
/// script overrides that for the umbrella pass. Option identity has exactly
/// one source of truth, `curl-rs-ffi/src/ffi/opts.rs`, which must emit both
/// the enumeration and the `curl_easyoption` metadata array; it does not exist
/// yet. The enumeration is therefore GENERATED from that module rather than
/// spliced verbatim.
///
/// That resolves `cbindgen.toml`'s intent rather than contradicting it: the
/// file delegates the per-header export partition to this script, and deciding
/// which pass owns `CURLoption` is part of the partition. The alternative --
/// splicing curl.h:1138-2262 verbatim -- would put the 308 option identifiers
/// in two places, and two populations drift silently. The first symptom is a
/// consumer asking for an option by name and getting the wrong id.
///
/// The generator macros `CURLoption` expands (`CURLOPT`, `CURLOPTDEPRECATED`,
/// the five `CURLOPTTYPE_*` bases and their four aliases) remain verbatim in
/// [`CURL_H_FORWARD`], which is what `cbindgen.toml`'s "deliberately not here"
/// note asks for. The integers must be asserted against curl 8.19.0-DEV so
/// that generation is checked rather than trusted;
/// `tests-rs/abi/enum_values.rs` is where that assertion belongs, and it does
/// not exist yet either.
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
//
// Installing a collecting logger converts every such diagnostic into a build
// failure. This is the whole mechanism: no subprocess, no stderr redirection
// and no `unsafe`.

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
/// review finding C-04 describes. Measured on a correct build, cbindgen
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
    /// defect C-04 exists to catch.
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
/// This is C-04's first requirement, and it exists because of exactly what
/// C-04 measured: cbindgen reported `can't find mod ffi`, returned Ok, and
/// emitted a header containing neither `CURLE_OK` nor `curl_easy_init`. A
/// missing module is not a degraded render, it is the silent deletion of an
/// entire ABI surface, and it is indistinguishable in the output from a
/// module that legitimately declares nothing.
///
/// Checking here rather than relying on cbindgen has two advantages. The
/// error names the file that is missing and the declaration that asked for
/// it, which a cbindgen warning does not; and it runs BEFORE any pass, so
/// there is no window in which a truncated render exists at all.
///
/// A `#[cfg(...)]`-gated declaration is deliberately still required to have a
/// file. cbindgen follows `mod` declarations while parsing and does not
/// evaluate this crate's feature resolution, so a gated module whose file is
/// absent produces the same warning as an ungated one.
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
///
/// `include/curl/curl.h:3328-3341` corroborates the membership of this list
/// from the other side: it defines three-argument enforcement macros for
/// exactly these four and for none of the other eleven variadic or `va_list`
/// symbols, because only these four take a fixed argument count. That is what
/// makes the trailing-pointer design possible for them and impossible for the
/// rest.
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
/// agree. On `aarch64-apple-darwin`, which specification 0.8.3 requires, the
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
/// `bl` does not modify `sp`, so `[sp]` on entry is exactly the slot the
/// caller stored to. This was compiled and disassembled on stable 1.97.1 **and
/// on 1.75.0**, and needs neither a newer toolchain nor a C compiler, so it
/// costs none of the three trade-offs specification 0.8.6 lists under open
/// ambiguity A4. `llvm-nm` shows the trampoline as a global `T` and the
/// implementation as a local `t`, so the private symbol does not join the
/// export set.
///
/// # Why this is a hard check and no longer a warning
///
/// This function replaces a `cargo:warning=` that fired on every
/// `aarch64-apple-darwin` build. That warning had two faults. It broke
/// specification 0.8.4 gate 1, which requires a build with zero warnings on
/// all four targets. And it was inaccurate: it described a mismatch in
/// entry-point definitions that do not exist yet, so it reported a defect
/// that was not present -- the reporting equivalent of the over-advertisement
/// specification 0.6.5 rules out.
///
/// A check is strictly stronger than a warning here. It fails the build the
/// moment the hazard is actually introduced, it fails on every target rather
/// than only on the affected one -- so a developer on Linux cannot land it
/// unnoticed -- and it cannot be satisfied by a comment, because the token it
/// looks for is the assembly label that defines the global symbol.
///
/// It is one half of the policy, not the whole of it. This check makes a
/// DEFINITION of one of the four sound wherever it appears;
/// [`check_variadic_abi`] escalates open ambiguity A4 itself, which outlives
/// the trampoline because the eleven printf and `va_list` exports have no
/// ABI-correct expression at the declared minimum on any target and because
/// none of the four has a Rust body to trampoline yet.
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
/// Without this, prose naming a function -- and this crate's documentation
/// names all four variadic entry points repeatedly -- would read as a
/// definition. Replacing rather than deleting keeps byte offsets stable, which
/// matters for any caller that reports a position.
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
/// The authority for C-04's declared-FORM assertion. Reproduced three times
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
///
/// WHY THE REPRESENTATION IS RETURNED RATHER THAN FILTERED ON. The first
/// version of this function returned only the `#[repr(C)]` enums, and the
/// discrimination probe for the defect above did not fire. The reason is worth
/// recording, because it is the same vacuity C-04 is about: deriving the
/// expected set from the attribute means the injection REMOVES the name from
/// the set it is checked against, so the check skips exactly the enum that
/// broke. A gate whose authority is the thing under test cannot fail. The set
/// is therefore keyed on `pub enum`, which does not move when the
/// representation changes, and the representation is checked as data.
///
/// Scanned from source rather than listed by hand so that adding an enum
/// cannot forget to add it here.
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
///
/// Each benign shape is CHECKED against this script's own tables rather than
/// allow-listed by text, which is the difference between a gate and a
/// rubber stamp: the allowance for a skipped item is conditional on no
/// partition claiming it, and the allowance for an unresolved type is
/// conditional on that type being withheld on purpose. Change the partition
/// so that a skipped name becomes owned, and this starts failing without
/// anyone having to remember to update it.
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
/// The `?` below catches a parse failure, and that is the only failure mode it
/// catches. It is specifically NOT sufficient on its own, and the reason is
/// worth stating because trusting it was a real defect: when a module named by
/// `mod` cannot be resolved, cbindgen writes "can't find mod ffi" to stderr,
/// returns `Ok`, and yields a body containing no declarations. The pass looks
/// like a success and produces a structurally valid, nearly empty header.
///
/// That case is not handled here, deliberately. An emptiness test at this level
/// would be wrong: `mprintf.h` owns zero partition items, so a *correct* render
/// of it legitimately contributes no generated declarations, and rejecting an
/// empty body would fail a healthy build. The condition is instead caught in
/// [`generate_headers`], where the expected item set is known -- the
/// unconditional discovery-completeness check reports every missing name, and
/// [`missing_abi_exports`] stops the common case before any pass runs.
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
    // C-04, where a live run warned "can't find mod ffi", exited 0, and
    // emitted 6,672 bytes containing neither CURLE_OK nor curl_easy_init.
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

/// Rewrite the one construct cbindgen emits that the tree's own style gate
/// rejects: a `//` comment closing a preprocessor conditional.
///
/// Measured, with the cause traced rather than guessed. cbindgen writes
/// `#endif // __STDC_VERSION__ >= 202311L` at
/// `ir/enumeration.rs:798`, and it takes that path for every enum carrying an
/// explicit `#[repr(iN)]` -- which is EVERY public enum here, because
/// integer-exact ABI parity is implemented by pinning the representation.
/// The construct is therefore unavoidable, not incidental.
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
///
/// The rewrite is deliberately narrow: only a line whose first character is
/// `#`, and only a `//` that is not part of a `://` scheme separator, so a
/// URL in a doc comment cannot be mangled. Everything else is passed
/// through untouched.
fn normalise_generated_c(text: &str) -> String {
    let mut out = String::with_capacity(text.len());

    for line in text.lines() {
        let rewritten = rewrite_preprocessor_comment(line);
        out.push_str(&rewritten);
        out.push('\n');
    }

    out
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
/// A name is counted only when `#[no_mangle]` and an `extern "C"` definition
/// appear together, because either alone produces a symbol the dynamic linker
/// will not resolve under the exported name: `#[no_mangle]` without
/// `extern "C"` keeps the Rust ABI, and `extern "C"` without `#[no_mangle]`
/// keeps the mangled name.
///
/// The scan is textual on purpose. A build script cannot ask the compiler for
/// this set -- the crate has not been compiled yet, and the whole point of the
/// check is to run before anything is rendered.
fn implemented_exports(manifest: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let src = manifest.join("src");
    let mut names = Vec::new();
    let mut queue = vec![src.clone()];

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

/// The exported symbols the headers would be expected to declare but which
/// this crate does not yet define.
///
/// Verbatim carriers are excluded because their declarations are literal text
/// in the prologue rather than rendered from Rust items: the header declares
/// them whatever the crate contains, so their absence cannot truncate a
/// generated header.
fn missing_abi_exports(
    manifest: &Path,
    root: &Path,
) -> Result<Vec<String>, Box<dyn Error>> {
    let expected = exported_symbols(root)?;
    let implemented = implemented_exports(manifest)?;
    let carriers: Vec<String> = VERBATIM_CARRIERS
        .iter()
        .flat_map(|(_, blocks)| blocks.iter())
        .flat_map(|block| verbatim_callables(block))
        .collect();

    Ok(expected
        .into_iter()
        .filter(|name| !carriers.iter().any(|c| c == name))
        .filter(|name| !implemented.iter().any(|i| i == name))
        .collect())
}

/// Generate `include/curl/curl.h` and its seven generated siblings.
///
/// Nine cbindgen passes: one to discover the full set of items the crate
/// exposes, then one per header. The discovery pass is what makes the
/// partition complete rather than merely plausible -- without it, the
/// exclusion lists could only name items this file happens to enumerate,
/// and anything else would be emitted into all eight headers at once.
///
/// The four headers under [`NEVER_GENERATED`] are not passes and cannot
/// become passes: [`guard_write_target`] runs before every write.
///
/// Nothing is written until every header has been rendered AND validated, and
/// nothing is written at all while the export surface is incomplete. Four
/// checks stand between a cbindgen pass and the tracked files, in increasing
/// order of specificity:
///
/// 1. [`missing_abi_exports`] -- while any of the 100 symbols in
///    `lib/libcurl.def` is undefined in this crate, generate nothing and leave
///    the reviewed curl 8.19.0-DEV headers exactly as they are. This subsumes
///    the case where the ABI module is absent altogether, because a crate that
///    defines no exports is missing all 100 of them.
/// 2. Discovery non-vacuity -- an empty discovery set, or an expected set that
///    intersects no public enum, is itself an error. Both are what a module
///    cbindgen could not parse produces, and both would otherwise make every
///    later check pass over a header containing nothing.
/// 3. Discovery completeness -- every expected item must actually have been
///    emitted by the discovery pass, unconditionally. An earlier revision
///    tested each item only if it had already been observed, which made the
///    check vacuous in exactly the case it needed to catch.
/// 4. Per-header ownership, in both directions -- no header may declare a name
///    another header owns, and no header may omit a name it owns. This one is
///    scoped to observed items on purpose: an item that was never emitted is
///    already reported by check 3, and reporting it again per header would bury
///    the cause in noise.
///
/// Only then does the transaction promote the complete set.
fn generate_headers(
    manifest: &Path,
    root: &Path,
) -> Result<(), Box<dyn Error>> {
    // THE FIRST THING THIS FUNCTION DOES, AND DELIBERATELY SO.
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
    let missing = missing_abi_exports(manifest, root)?;
    if !missing.is_empty() {
        let total = exported_symbols(root)?.len();
        println!(
            "cargo:warning=include/curl/ NOT regenerated: {} of the {} \
             exported symbols in lib/libcurl.def are not yet defined in this \
             crate, so every generated header would be short by exactly what \
             is missing. The existing headers are left untouched and remain \
             the ABI contract. Generation resumes automatically once the \
             export surface is complete.",
            missing.len(),
            total
        );
        let preview: Vec<&str> =
            missing.iter().take(8).map(String::as_str).collect();
        println!(
            "cargo:warning=include/curl/ first missing exports: {}{}",
            preview.join(", "),
            if missing.len() > preview.len() {
                format!(", and {} more", missing.len() - preview.len())
            } else {
                String::new()
            }
        );
        return Ok(());
    }

    // Before anything is rendered, let alone written. A missing module is the
    // measured cause of C-04, and the only place to catch it cheaply is here.
    preflight_modules(manifest)?;
    // Both are preflight: a hazard in this crate's own source must stop the
    // build before any header is rendered, not after.
    check_variadic_strategy(manifest)?;

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
    // assertion that was supposed to be C-04's oracle could therefore pass
    // over a header containing nothing at all.
    //
    // The expected set is DERIVED rather than listed: every `#[repr(C)] pub
    // enum` in the FFI tree that some partition also claims. Measured today
    // that is 30 of the 32 such enums, the two exceptions being
    // `curl_sslbackend` and `CURLoption`, which are emitted but claimed by no
    // partition -- so listing all 32 would false-fire. The derivation is
    // non-vacuous in the way that matters: a module that fails to parse drops
    // all 30 at once.
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
    //
    // The staged count is asserted BEFORE promotion rather than after, because
    // publishing a partial set would leave a mixed ABI contract on disk -- some
    // headers describing the new surface and the rest the old one -- and a
    // check that ran after the renames could not undo them. On this path the
    // transaction's `Drop` discards every staging file instead.
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
/// changed, which is precisely the integer-exactness failure AAP 0.6.1 exists
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

/// Placeholders in `curl-config.in`, measured with `grep -o`: 18 distinct
/// tokens across 30 occurrences.
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
///
/// GLOBAL, not first-match, and that is not a stylistic choice. Measured in
/// `curl-config.in`, counting occurrences rather than lines because a single
/// line can carry the same token twice: `@CURLVERSION@` occurs five times
/// (`:98`, `:110`, `:111`, `:114`, `:130`), `@includedir@` three times
/// (`:33`, `:144`, `:147`) and `@libdir@` four times across three lines
/// (twice on `:152`, then `:153` and `:170`). A first-match substitution
/// would leave live placeholders in the `--checkfor` arithmetic, where they
/// would produce shell errors rather than a verdict.
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
        match row.probe {
            // C's NULL, or a probe whose answer is fixed for this build: the
            // static answer equals the runtime one, so it can be advertised.
            Probe::Absent | Probe::Constant(true) => {
                tokens.push(row.token);
            }
            // The engine withholds it at run time, so metadata that claimed it
            // would describe a different product.
            Probe::Constant(false) => {}
            // GENUINELY RUNTIME, therefore WITHHELD from static metadata.
            //
            // A file written at build time cannot know whether a library that
            // resolves at run time will be there -- this is the `GSS-API`,
            // `Kerberos` and `SPNEGO` case, where `negotiate` may be compiled
            // in on a host with no usable mechanism. Specification 0.6.5 makes
            // the choice for us: under-reporting only causes a fixture to skip,
            // while over-reporting makes it run and fail. So the token is
            // omitted here and left to `curl --version`, which can ask.
            Probe::Dynamic(_) => {}
        }
    }

    tokens.sort_by_key(|token| token.to_lowercase());
    Ok(tokens.join(" "))
}

/// The protocol tokens this build honestly supports, space separated.
///
/// Sorted case-sensitively, matching `CMakeLists.txt:1990-1991`, which sorts
/// the protocol list without the case-insensitive flag. Every token is
/// upper-case, so the two orders coincide; the distinction is preserved
/// because the C build drew it.
///
/// The 24 registered-but-unimplemented schemes are absent, and that is the
/// whole point. `tests/runtests.pl` reads this list to decide which fixtures
/// are eligible, so the 283 fixtures targeting those schemes skip cleanly
/// instead of running and failing. They are absent here because they are
/// absent from the engine's table, not because a second list omits them.
///
/// THE CASE CHANGE IS DELIBERATE AND AUTHORITY-BACKED. The engine stores
/// scheme names in lower case, because that is how `curl --version` spells its
/// `Protocols:` line. `curl-config --protocols` spells them in UPPER case:
/// `configure.ac:5327` appends `HTTP`, `FTP`, `FILE` and the rest upper-cased
/// into `SUPPORT_PROTOCOLS`, and `CMakeLists.txt:1994` builds the same variable
/// from upper-case items -- deriving a *separate* lower-case variable at
/// :1995 purely for its status message, which is what proves the upper-case
/// spelling is the one consumers get. So one list serves both surfaces and
/// this function applies the documented transformation, having first asserted
/// in [`runtime_protocol_rows`] that the input really is lower case.
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
    // SAME authority rather than a second copy of the character class. An
    // earlier revision of this file carried its own `SAFE_CONFIGURE_CHARS`
    // constant holding a byte-identical string, which is precisely the drift
    // shape the single-source-of-truth rule exists to prevent: two policies
    // that agree today and silently disagree after one of them is edited.
    //
    // `reject_unquoted_shell_metacharacters`, which guards the same three
    // unquoted arms from Section 14b's side, reads that one constant too, for
    // exactly this reason: two entry points, one character class.
    //
    // The early call is kept because `TARGET` is externally supplied, and
    // failing at the point of construction names the value's origin instead of
    // reporting it from a generic loop several hundred lines away.
    check_shell_context("CONFIGURE_OPTIONS", &rendered)?;

    Ok(rendered)
}

// Section 14a: injection safety for the two generated consumer files
//
// WHY THIS SECTION EXISTS, and why it validates in one place and escapes in
// another rather than doing one thing everywhere. `curl-config` is an
// executable POSIX shell script and `libcurl.pc` is a pkg-config file; both
// are produced by substituting `@TOKEN@` placeholders, and three of those
// values come from the environment. Substituted raw, a single quote in a
// prefix closes the shell string it lands in and everything after it is
// executed by every consumer that runs `curl-config --libs`. Review finding
// M-19.
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
//
// and SOME TOKENS APPEAR IN MORE THAN ONE: `@includedir@` is double-quoted at
// :33, :144 and :147, `@CURLVERSION@` is single-quoted at :98 and :110 but
// double-quoted at :130. A single escaping transform therefore cannot be
// correct for every token -- `'` -> `'\''` is right inside single quotes and
// produces four literal characters inside double quotes -- and the template
// text is frozen by AAP 0.8.1, so the quoting cannot be normalised either.
//
// What makes the problem tractable is a second measurement: each of the THREE
// EXTERNALLY-DERIVED tokens appears EXACTLY ONCE, and always inside single
// quotes. So POSIX single-quote escaping is provably correct for exactly those
// three, and [`check_single_quoted_context`] asserts that precondition against
// the template on every build rather than trusting this comment.
//
// Everything else is validated instead of escaped, which is the right posture
// for a build script: a prefix containing a newline is a mistake to report,
// not a value to accommodate.

/// Control characters rejected in every substituted value, in both files.
///
/// M-19 names CR, LF and NUL explicitly, and the reason differs per file. In
/// `curl-config` a newline ends a shell command, so a value carrying one adds
/// a line of script. In `libcurl.pc` a newline ends a field, so a value
/// carrying one adds a metadata field -- a `prefix` of
/// `/tmp\nLibs: -L/tmp/evil -lcurl` rewrites the link line of every consumer.
/// NUL truncates for any reader that uses C strings, which pkg-config does.
///
/// The whole C0 range plus DEL is rejected rather than only those three: none
/// of them is legitimate in a path, a compiler name or a flag, and rejecting
/// the class removes the need to argue about each member.
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
///
/// Each is measured to appear exactly once, inside single quotes, which is
/// what makes [`shell_single_quoted_body`] the correct transform for it and only
/// it. `@SUPPORT_FEATURES@`, `@SUPPORT_PROTOCOLS@` and `@CONFIGURE_OPTIONS@`
/// are also externally influenced but are deliberately UNQUOTED in the
/// template so they word-split, so they are validated character-by-character
/// instead.
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
/// The first attempt at this checked whether a quote character sat immediately
/// before or after the token, and it misclassified `curl-config.in:170`:
///
/// ```text
/// echo "@libdir@/libcurl.@libext@ @LIBCURL_PC_LDFLAGS_PRIVATE@ ..."
/// ```
///
/// where `@libext@` is genuinely inside double quotes but has a `.` before it
/// and a space after it. Quoting is a property of the enclosing string, so it
/// has to be computed by scanning from the start of the line.
///
/// Only what this template needs is modelled: the two quote forms and a
/// backslash escape outside single quotes. Neither `$'...'` nor a here-document
/// appears in `curl-config.in`, and a value never spans a line because
/// [`check_control_chars`] has already rejected every line break.
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
///
/// A table that drifts into describing a template that no longer exists is the
/// same class of silent mismatch as an unescaped value: the check still runs,
/// against the wrong grammar.
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
/// `curl-config.in:85` and `:92` are `for feature in @SUPPORT_FEATURES@ ''` and
/// `for protocol in @SUPPORT_PROTOCOLS@`, which depend on word splitting to
/// print one token per line, and `:178` is `echo @CONFIGURE_OPTIONS@`. Their
/// values cannot be quoted without changing what the script does, so they are
/// validated character by character instead -- the same treatment
/// `@CONFIGURE_OPTIONS@` already had, extended to the two that lacked it.
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
///
/// `curl-config.in:31`, `:33`, `:147`, `:153`, `:158` and `:170`. A
/// double-quoted string in POSIX shell still expands `$` and backticks, and
/// that is DELIBERATE for these: `exec_prefix="${prefix}"` and
/// `libdir="${exec_prefix}/lib"` are meant to be expanded when the script runs,
/// which is why `$` cannot simply be banned here. A backtick and a `$(` cannot
/// be deliberate -- neither appears in any value this script produces -- so
/// those are refused, closing the command-substitution route while leaving
/// parameter expansion intact.
const SHELL_DOUBLE_QUOTED_TOKENS: [&str; 6] = [
    "exec_prefix",
    "includedir",
    "libdir",
    "libext",
    "LIBCURL_PC_CFLAGS",
    "LIBCURL_PC_LDFLAGS_PRIVATE",
];

/// Characters permitted in a value the template leaves unquoted.
///
/// Deliberately narrow: alphanumerics plus the punctuation that appears in a
/// path, a compiler flag or a capability token. Everything else -- `*` `?` `[`
/// `;` `&` `|` `$` `` ` `` `(` `)` `<` `>` `\` `'` `"` `{` `}` `~` `!` `#` --
/// is either a glob character, a control operator or an expansion introducer in
/// an unquoted word.
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
/// pkg-config has no escaping mechanism for a variable definition: the value
/// runs to the end of the line. Two characters therefore have to be refused
/// rather than encoded. `#` starts a comment, so everything after it is
/// discarded and the field silently loses its tail. `$` begins a variable
/// reference, so an unintended one either expands to something else or makes
/// `pkg-config` fail with "Variable not defined", which surfaces at the
/// consumer as an unexplained build failure.
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
/// ONE AUTHORITY, feeding both `curl-config --static-libs` and
/// `libcurl.pc`'s `Libs.private`. Review finding M-21 recorded that the two
/// under-reported their inputs; having them read the same function is what
/// stops them from disagreeing again.
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
///   Darwin target in this environment. `cargo tree --target
///   aarch64-apple-darwin` shows `security-framework 3.6.0` and
///   `core-foundation 0.10.1` present, and their `-sys` crates declare
///   `#[link(name = "Security", kind = "framework")]` and
///   `#[link(name = "CoreFoundation", kind = "framework")]`. They arrive
///   through `rustls-native-certs`, which reads the platform trust store.
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
///
/// Only `CURL_RS_PREFIX` is consulted, then the same `/usr/local` default
/// Autotools used.
///
/// WHY THE BARE `PREFIX` FALLBACK WAS REMOVED. `PREFIX` is not a Cargo
/// variable and carries no agreement about what it means. It is set for
/// unrelated reasons by Homebrew, by pkgsrc, by many `Makefile`s that export
/// their own `PREFIX` into a recursive `$(MAKE)`, and by developers who
/// exported it once for something else. Inheriting it means a build in such
/// an environment silently reports install paths that libcurl was never
/// installed to, and every consumer that runs `curl-config --prefix` is
/// misdirected -- with no diagnostic, because an inherited value is
/// indistinguishable from an intended one. Review finding M-19 named the
/// generic inherited fallback specifically; a namespaced variable cannot be
/// set by accident, so the ambiguity disappears rather than being managed.
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
/// objects and fail to link against an aarch64 library. Review finding M-07.
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
/// and when none is set it derives a name from the triple. The derivation
/// here is deliberately narrower than `cc-rs`'s full table: `<triple>-gcc`
/// when cross-compiling, plain `cc` when `HOST == TARGET`. That is right for
/// the four mandated targets -- `aarch64-linux-gnu-gcc` is what the installed
/// cross toolchain is called -- and any other triple gets a name a reader can
/// recognise as derived rather than a silently wrong host compiler.
///
/// Never empty: a consumer substituting an empty `--cc` into a command line
/// would run its first argument as a program.
fn compiler() -> String {
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
                return value;
            }
        }
    }

    if !target.is_empty() && !host.is_empty() && target != host {
        format!("{target}-gcc")
    } else {
        "cc".to_string()
    }
}

/// The CA bundle path to report, or an empty string when none is configured.
///
/// Empty is a legitimate answer: `curl-config.in:72` prints whatever it is
/// given, and this build reads trust anchors through rustls rather than from
/// a compiled-in path unless one is supplied.
fn ca_bundle() -> String {
    env::var("CURL_CA_BUNDLE").unwrap_or_default()
}

// Section 14c: where the generated consumer metadata goes

/// Every path a rendered consumer file is written to, product path first.
///
/// WHY NOT THE SOURCE ROOT, WHICH IS WHERE THESE USED TO GO. Both files are
/// target-specific and feature-specific: `curl-config --cc` names the target's
/// compiler, `--static-libs` and `Libs.private` name that platform's native
/// libraries, and `--features` names the selected Cargo features. There is
/// exactly ONE `curl-config` path in the source root, so the four-target
/// matrix of AAP 0.8.3 had four builds writing four different files to one
/// name. Whichever finished last won; the other three were destroyed. On a
/// parallel matrix they also raced, so a consumer could read a half-written
/// script. Review finding M-15.
///
/// The concealment made it worse rather than better. `.gitignore` listed both
/// names, so `git status --porcelain` stayed empty while the build wrote into
/// a tracked directory -- the clean-tree assertions of AAP 0.8.4 gate 1 could
/// pass over exactly the writes they exist to catch. Those two `.gitignore`
/// lines are removed, so an accidental source-root write is now VISIBLE.
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
// THE TWO DESTINATIONS ARE DIFFERENT LANGUAGES AND MUST NOT SHARE ONE
// ESCAPER. That is not a stylistic claim; both halves were measured here.
//
// curl-config is a POSIX shell script, and every environment-derived value
// lands inside SINGLE quotes: `prefix='@prefix@'` (:28),
// `echo '@CURL_CA_BUNDLE@'` (:73), `echo '@CC@'` (:77). Inside single quotes
// `$`, a backtick and `"` are inert -- verified by running them -- so the
// apostrophe is the ONLY character that needs encoding, and `'\''` is the
// POSIX way to encode it. Measured, with `id -u` as the payload: the raw value
// `x'; id -u; echo 'y` substituted into `echo '...'` EXECUTES, printing `0`;
// the same value encoded prints the literal `x'; id -u; echo 'y` and executes
// nothing. Every later use of the prefix is a `"$prefix"` expansion, which a
// POSIX shell does not re-parse, so encoding it once at :28 is sufficient.
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
///
/// The template supplies the surrounding quotes, so this returns the body
/// only. `'` becomes `'\''` -- close the literal, emit an escaped apostrophe,
/// reopen it -- which is the sole POSIX-portable way to place an apostrophe
/// inside single quotes. Nothing else is touched, because nothing else is
/// special there -- not `$`, not a backtick, not a backslash -- which is
/// precisely why the frozen template's choice of single quotes is worth
/// preserving rather than replacing with double quotes.
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
///
/// `curl-config.in:178` is `echo @CONFIGURE_OPTIONS@` and `:85` and `:92` loop
/// over `@SUPPORT_FEATURES@` and `@SUPPORT_PROTOCOLS@` without quotes, on
/// purpose, so that each word becomes one token. Word splitting is the
/// feature; glob expansion and command substitution are not, and there is no
/// encoding that keeps the first while removing the others. So these values
/// are validated rather than encoded, and the allowed set is deliberately
/// small.
///
/// This is the single definition of that rule. It began as an inline check on
/// `@CONFIGURE_OPTIONS@` alone, which left the two loop arms trusting values
/// that also depend on the environment through `CARGO_FEATURE_*`.
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
///
/// The prefix is the only value that reaches both artifacts, and the two
/// grammars do not accept the same set. Validating inside each renderer would
/// therefore write a perfectly good `curl-config` and only then refuse
/// `libcurl.pc`, leaving a half-rendered pair on disk after a failed build.
/// Measured: with an apostrophe in the prefix, `curl-config` was written with
/// the apostrophe correctly encoded before `libcurl.pc` refused. So the whole
/// environment is checked against the whole set of destinations before
/// anything is written at all.
///
/// The renderers still encode -- they must, since the encodings differ -- but
/// by then nothing can be refused.
fn validate_environment_substitutions() -> Result<(), Box<dyn Error>> {
    let prefix = install_prefix();
    let ca_bundle = ca_bundle();
    let compiler = compiler();

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
///
/// The shell encoder above is correct only for a single-quoted context, so the
/// context is asserted rather than assumed. `curl-config.in` is frozen text
/// that this script does not own; if a future edit changed `echo '@CC@'` to
/// `echo @CC@`, the encoding would become both wrong and dangerous, and
/// nothing else would notice.
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
//
// One shared rule governs both: SUBSTITUTE ONLY `@...@` TOKENS AND CHANGE
// NOTHING ELSE. The shell logic of curl-config and the field structure of
// libcurl.pc are frozen; every line between the tokens is reproduced exactly
// as the template has it.

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
    // disappears rather than being managed. Review finding M-19.
    let prefix = install_prefix();
    let ca_bundle = ca_bundle();
    let compiler = compiler();
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
        // curl-config.in:28, inside single quotes.
        ("prefix", shell_single_quoted_body(&prefix)),
        // CMakeLists.txt:2079 sets this to the literal ${prefix}, which the
        // script then expands at run time. Reproduced exactly, because
        // curl-config.in:31 assigns it and later arms expand it.
        ("exec_prefix", "${prefix}".to_string()),
        // curl-config.in:33, expanded by the --cflags arm at :144.
        ("includedir", "${prefix}/include".to_string()),
        // Used by --libs (:152) and --static-libs (:170).
        ("libdir", "${exec_prefix}/lib".to_string()),
        // Both yes: curl-rs-ffi/Cargo.toml sets
        // crate-type = ["cdylib", "staticlib"], so both artifacts exist.
        ("ENABLE_SHARED", "yes".to_string()),
        ("ENABLE_STATIC", "yes".to_string()),
        // The staticlib artifact is libcurl.a, so the extension is `a`.
        // CMakeLists.txt:2093 derives the same value by stripping the dot
        // from CMAKE_STATIC_LIBRARY_SUFFIX.
        ("libext", "a".to_string()),
        // Drives --ca (:72). Empty unless configured. Single-quoted at :73.
        ("CURL_CA_BUNDLE", shell_single_quoted_body(&ca_bundle)),
        // Drives --cc (:76). Single-quoted at :77.
        ("CC", shell_single_quoted_body(&compiler)),
        // Drives --feature/--features (:84-89), which loops over the value
        // unquoted so that it word-splits into one token per line. Validated
        // above rather than encoded, because the word splitting is wanted.
        ("SUPPORT_FEATURES", features),
        // Drives --protocols (:90-96). curl-config.in:91 carries a
        // `# shellcheck disable=SC2043` immediately before the loop.
        ("SUPPORT_PROTOCOLS", protocols),
        // include/curl/curlver.h:35. Every parity claim in this work is
        // against this exact string.
        ("CURLVERSION", facts.version.clone()),
        // curlver.h:61 with the 0x removed, exactly as configure.ac:141
        // captured it. --vernum (:134) echoes it raw.
        ("VERSIONNUM", facts.vernum.clone()),
        // rustls and nothing else. Note the spelling: CMakeLists.txt:2059
        // capitalises its backend names, but the truthful token here is the
        // crate's own name, lower-case.
        ("SSL_BACKENDS", SSL_BACKENDS.to_string()),
        // Empty: consumers need no extra flags to include the public
        // headers beyond the -I the --cflags arm already prints.
        ("LIBCURL_PC_CFLAGS", String::new()),
        // Printed by --static-libs (:170). One authority, shared with
        // libcurl.pc's Libs.private, so the two cannot disagree.
        ("LIBCURL_PC_LIBS_PRIVATE", private_libs(&target_os)?),
        // Empty: a Rust cdylib needs no extra link-time flags of its own.
        ("LIBCURL_PC_LDFLAGS_PRIVATE", String::new()),
        // Printed unquoted by --configure (:178), hence validated.
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
    // `$` in an inherited path is never intentional. Review finding M-19.
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
        // libcurl.pc.in:25-28, the same four directories curl-config uses.
        ("prefix", prefix),
        ("exec_prefix", "${prefix}".to_string()),
        ("libdir", "${exec_prefix}/lib".to_string()),
        ("includedir", "${prefix}/include".to_string()),
        // :29 and :30, read back by
        // `pkg-config --variable=supported_protocols libcurl`. The same two
        // functions feed curl-config, so the two files cannot disagree.
        //
        // Routed through the pkg-config encoder even though both are joins of
        // static tokens and cannot today contain anything it would touch. Two
        // reasons, and the second is the one that matters: the template quotes
        // them (`supported_protocols="@SUPPORT_PROTOCOLS@"`, :29-30), so a
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
        // :38 keeps the literal -lcurl, which is why curl-rs-ffi/Cargo.toml
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
    // two fields the template double-quotes (`libcurl.pc.in:29-30`), where a
    // quote would end the value early and leave the rest as stray text.
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
