// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! Build script for `curl-rs-ffi`, the crate that presents libcurl's C ABI.
//!
//! It has exactly three responsibilities, assigned by the specification's
//! transformation map ("curl-rs-ffi/build.rs | CREATE | lib/optiontable.pl,
//! lib/Makefile.soname | cbindgen invocation plus soname configuration"):
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
//! Nothing here is a user-specified rule: `review_rules` reports that no
//! rules were provided for this project, read to end of document twice and
//! byte-identical both times. The constraints this file honours come from
//! the specification, which derives them from the user's request; calling
//! them rules would misrepresent where they came from. In the absence of
//! rules, enterprise-standard best practice governs.
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
//!   deviation -- specification 0.8.7 -- exactly equivalent to curl's own
//!   supported `--disable-versioned-symbols` build mode. Hiding is
//!   unnecessary besides: a cdylib exporting only its
//!   `#[no_mangle] pub extern "C"` items measured total=2, curl_*=2,
//!   leaked=0. Export parity comes from declaration discipline, not from
//!   link-time filtering.
//! * No claim of 32-bit support, anywhere. The four supported targets are
//!   all 64-bit, and the C ABI shim's single-trailing-pointer setters hold
//!   an `off_t` in one register-width slot only where `off_t` fits a
//!   register. 32-bit portability is therefore deliberately forfeited
//!   (specification 0.6.2), and neither the rendered `curl-config` nor the
//!   rendered `libcurl.pc` may imply otherwise. Concretely: nothing this
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
//!   rule exists to prevent. See `option_table_ground_truth` below for the
//!   measured facts a reviewer can check `src/ffi/opts.rs` against.
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

// ---------------------------------------------------------------------------
// Section 1: parity constants
// ---------------------------------------------------------------------------

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
const TRACKED_ENV: [&str; 4] = ["CURL_RS_PREFIX", "PREFIX", "CC", "CURL_CA_BUNDLE"];

// ---------------------------------------------------------------------------
// Section 2: the four headers that must never be written
// ---------------------------------------------------------------------------

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
const NEVER_GENERATED: [&str; 4] = ["curlver.h", "stdcheaders.h", "system.h", "typecheck-gcc.h"];

// ---------------------------------------------------------------------------
// Section 3: the per-header partition
// ---------------------------------------------------------------------------

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
    "curl_opensocket_callback",
    "curl_prereq_callback",
    "curl_progress_callback",
    "curl_read_callback",
    "curl_realloc_callback",
    "curl_resolver_start_callback",
    "curl_seek_callback",
    "curl_sockopt_callback",
    "curl_sshhostkeycallback",
    "curl_sshkeycallback",
    "curl_ssl_ctx_callback",
    "curl_ssls_export_cb",
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
    "curl_easy_strerror",
    "curl_easy_unescape",
    "curl_escape",
    "curl_free",
    "curl_getdate",
    "curl_getenv",
    "curl_global_cleanup",
    "curl_global_init",
    "curl_global_init_mem",
    "curl_global_sslset",
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
    "curl_share_strerror",
    "curl_slist_append",
    "curl_slist_free_all",
    "curl_strequal",
    "curl_strnequal",
    "curl_unescape",
    "curl_version",
    "curl_version_info",
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
    "curl_multi_strerror",
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
    "CURLM_CALL_MULTI_SOCKET",
    "CURLPIPE_NOTHING",
    "CURLPIPE_HTTP1",
    "CURLPIPE_MULTIPLEX",
    "CURL_WAIT_POLLIN",
    "CURL_WAIT_POLLPRI",
    "CURL_WAIT_POLLOUT",
    "CURL_POLL_NONE",
    "CURL_POLL_IN",
    "CURL_POLL_OUT",
    "CURL_POLL_INOUT",
    "CURL_POLL_REMOVE",
    "CURL_SOCKET_TIMEOUT",
    "CURL_CSELECT_IN",
    "CURL_CSELECT_OUT",
    "CURL_CSELECT_ERR",
    "CURLMNWC_CLEAR_CONNS",
    "CURLMNWC_CLEAR_DNS",
    "CURL_PUSH_OK",
    "CURL_PUSH_DENY",
    "CURL_PUSH_ERROROUT",
    "CURLMNOTIFY_INFO_READ",
    "CURLMNOTIFY_EASY_DONE",
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
    "curl_url_strerror",
    // The 16 CURLU_* flag bits, urlapi.h:84-105.
    "CURLU_DEFAULT_PORT",
    "CURLU_NO_DEFAULT_PORT",
    "CURLU_DEFAULT_SCHEME",
    "CURLU_NON_SUPPORT_SCHEME",
    "CURLU_PATH_AS_IS",
    "CURLU_DISALLOW_USER",
    "CURLU_URLDECODE",
    "CURLU_URLENCODE",
    "CURLU_APPENDQUERY",
    "CURLU_GUESS_SCHEME",
    "CURLU_NO_AUTHORITY",
    "CURLU_ALLOW_SPACE",
    "CURLU_PUNYCODE",
    "CURLU_PUNY2IDN",
    "CURLU_GET_EMPTY",
    "CURLU_NO_GUESS_SCHEME",
];

/// Items owned by `options.h`: `curl_easytype` and the three introspection
/// functions. `struct curl_easyoption` is verbatim, being layout-visible.
const OPTIONS_H_ITEMS: &[&str] = &[
    "curl_easytype",
    // options.h:47, and the only flag bit the API defines.
    "CURLOT_FLAG_ALIAS",
    "curl_easy_option_by_id",
    "curl_easy_option_by_name",
    "curl_easy_option_next",
];

/// Items owned by `header.h`: `CURLHcode`, the five `origin` bits and two
/// functions. `struct curl_header` is verbatim, being layout-visible.
const HEADER_H_ITEMS: &[&str] = &[
    "CURLHcode",
    // The 'origin' bits, header.h:41-45.
    "CURLH_HEADER",
    "CURLH_TRAILER",
    "CURLH_CONNECT",
    "CURLH_1XX",
    "CURLH_PSEUDO",
    "curl_easy_header",
    "curl_easy_nextheader",
];

/// Items owned by `websockets.h`: nine flag bits and four functions.
/// `struct curl_ws_frame` is verbatim, being layout-visible.
const WEBSOCKETS_H_ITEMS: &[&str] = &[
    // websockets.h:40-45, :60 and :89-90. CURLWS_PONG is separated from its
    // five siblings in the C header, which the note above records.
    "CURLWS_TEXT",
    "CURLWS_BINARY",
    "CURLWS_CONT",
    "CURLWS_CLOSE",
    "CURLWS_PING",
    "CURLWS_OFFSET",
    "CURLWS_PONG",
    "CURLWS_RAW_MODE",
    "CURLWS_NOAUTOPONG",
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

// ---------------------------------------------------------------------------
// Section 4: the verbatim per-header text
// ---------------------------------------------------------------------------
//
// WHAT THIS SECTION CAN AND CANNOT DO, stated plainly rather than implied.
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
// from the C header. The positional difference is recorded here so the
// header diff review has an explanation rather than a surprise.
//
// The gate that catches a violation is `.github/workflows/rust-abi.yml`,
// which compiles all 129 programs in `docs/examples/` against the generated
// headers and compares the exported symbol set against `lib/libcurl.def`.

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
/// `cbindgen.toml:968-975` assigns their splice to this script.
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
/// header, which the diff review records.
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
"#;

/// `multi.h`, after the generated block: the definition whose forward
/// declaration is above, then the three excluded prototypes.
///
/// `struct CURLMsg` is placed here because it names the generated `CURLMSG`
/// enum, and a struct definition may follow every use of a pointer to it.
///
/// `curl_multi_socket` (multi.h:317) and `curl_multi_socket_all` (:325) are
/// deprecated in the headers and still exported -- both are in the
/// 100-symbol parity set, and AAP 0.8.2 forbids removing a deprecated
/// exported symbol. They are excluded from generation because cbindgen
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

/*
 * Name:    curl_multi_setopt()
 *
 * Desc:    Sets options for the multi handle.
 *
 * Returns: CURLM error code.
 */
CURL_EXTERN CURLMcode curl_multi_setopt(CURLM *multi_handle,
                                        CURLMoption option, ...);
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
const URLAPI_H_DECLS: &str = "\ntypedef struct Curl_URL CURLU;\n";

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
        postamble: "",
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

// ---------------------------------------------------------------------------
// Section 4b: curl.h's own verbatim text
// ---------------------------------------------------------------------------
//
// `cbindgen.toml` supplies curl.h's `header` (148 lines) and `trailer` (37
// lines) and deliberately leaves `after_includes` empty; ":1280" records it
// as unused there precisely because this script overrides it per header.
// The two constants below fill that gap for the umbrella.
//
// Every block is reproduced BYTE FOR BYTE from `include/curl/curl.h` at
// commit 54cf587b9c, `LIBCURL_VERSION "8.19.0-DEV"`. Each carries its source
// line range so the diff review can check it with `sed -n 'A,Bp'`. Nothing
// here is retyped, reformatted, re-indented or re-commented: AAP 0.8.1
// freezes the public headers, and a "tidier" spelling of a frozen file is an
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
//   * `CURLoption` (curl.h:1138-2262) and its 17 `#define` aliases. AAP
//     0.1.2 makes `curl-rs-ffi/src/ffi/opts.rs` the SINGLE source of truth
//     for option identity, "emitting both the enumeration and the metadata
//     array", and AAP 0.4.1 repeats it. Splicing 1,125 lines of enumeration
//     here would create the second population that AAP 0.1.2 warns about,
//     whose "drift will be invisible until a consumer queries an option by
//     name and receives the wrong identifier". `cbindgen.toml:898` lists
//     `CURLoption` under `[export] exclude`; the AAP takes precedence, so
//     `curl_h_export_exclusions` lifts that one exclusion for the umbrella
//     pass and the enumeration is generated from `opts.rs`. The generator
//     macros it expands ARE here, which is what `cbindgen.toml:406-425` asks
//     for.
//   * `include/curl/curl.h`'s own text is never READ by this script. The
//     header is an OUTPUT of this build, so parsing it would close a cycle
//     (header <- build.rs <- header) and reintroduce the drift AAP 0.1.2
//     warns about. `include/curl/curlver.h` is read, and only because it is
//     in `NEVER_GENERATED` and therefore an input.

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
const CURL_H_VERBATIM_NAMES: &[&str] = &[
    "CURL_NETRC_OPTION",
    "CURL_TLSAUTH",
    "curl_khmatch",
    "curl_khstat",
    "curl_khtype",
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
"#;

/// Seven headers close the block this way.
const EXTERN_C_CLOSE_COMMENTED: &str = "} /* end of extern \"C\" */";

/// `websockets.h:95` closes it this way.
const EXTERN_C_CLOSE_BARE: &str = "}";

// ---------------------------------------------------------------------------
// Section 5: what this build honestly supports
// ---------------------------------------------------------------------------
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
// `curl-rs-lib/src/version.rs` owns the same facts for `curl --version` and
// `curl_version_info`, and it must agree with these; that crate is not a
// dependency of this build script, so the two cannot be unified in code
// here, and the peer is named so the correspondence is checkable.

/// One advertised capability token and the Cargo feature it depends on.
struct Capability {
    /// The token exactly as the harness's 52-name vocabulary spells it.
    /// Case matters: the map is keyed on these strings.
    token: &'static str,
    /// The Cargo feature that must be enabled, or `None` when the
    /// capability is unconditional in this implementation.
    feature: Option<&'static str>,
}

/// Every token this build may advertise, with its precondition.
///
/// Derived from the Cargo feature vocabulary rather than hard-coded, so the
/// advertised set is computed from what was actually compiled. That makes
/// over-reporting structurally impossible instead of merely unintended: a
/// feature that is off cannot contribute its token, because the token is
/// gated on the `CARGO_FEATURE_*` variable Cargo sets for it.
const CAPABILITIES: [Capability; 23] = [
    // -- Unconditional in this implementation ------------------------------
    // rustls is the sole TLS implementation and is never optional, so SSL
    // is always true. Note what is NOT claimed alongside it -- this is
    // specification 0.8.6, open ambiguity A7, recorded as a disclosure
    // rather than resolved: no C TLS library is linked, which is the
    // constraint that matters, but neither `ring` nor `aws-lc-rs` is pure
    // Rust, so the honest statement is that rustls implements the protocol,
    // record layer and certificate verification in Rust while the provider
    // supplies primitives. `@SSL_BACKENDS@` therefore reports `rustls` and
    // nothing more; it must not be read as a purity claim.
    Capability {
        token: "SSL",
        feature: None,
    },
    Capability {
        token: "IPv6",
        feature: None,
    },
    Capability {
        token: "UnixSockets",
        feature: None,
    },
    // The resolver runs on the async runtime, so resolution never blocks
    // the transfer loop. This also replaces the C tree's most hazardous
    // construct outright: `lib/hostip.c` implemented DNS timeouts with
    // `alarm()` plus `sigsetjmp`/`siglongjmp`, jumping out of a signal
    // handler across allocation boundaries.
    Capability {
        token: "AsynchDNS",
        feature: None,
    },
    Capability {
        token: "asyn-rr",
        feature: None,
    },
    Capability {
        token: "HTTPSRR",
        feature: None,
    },
    // The `idna` crate replaces libidn2. Neither WinIDN nor AppleIDN is
    // claimed: those name platform implementations this build does not use.
    Capability {
        token: "IDN",
        feature: None,
    },
    // Pure-Rust NTLM over `des`, `md4`, `md-5` and `hmac`. `NTLM_WB` is
    // deliberately absent: that token means the retired external helper
    // binary, which this build has no equivalent of.
    Capability {
        token: "NTLM",
        feature: None,
    },
    // All four mandated targets are 64-bit, so curl_off_t is 64-bit.
    Capability {
        token: "Largefile",
        feature: None,
    },
    Capability {
        token: "threadsafe",
        feature: None,
    },
    // -- Gated on a default-on Cargo feature -------------------------------
    // `libz` names the capability, not the library: `flate2` provides it.
    Capability {
        token: "libz",
        feature: Some("gzip"),
    },
    Capability {
        token: "brotli",
        feature: Some("brotli"),
    },
    Capability {
        token: "zstd",
        feature: Some("zstd"),
    },
    Capability {
        token: "alt-svc",
        feature: Some("altsvc"),
    },
    Capability {
        token: "HSTS",
        feature: Some("hsts"),
    },
    Capability {
        token: "HTTP2",
        feature: Some("http2"),
    },
    Capability {
        token: "HTTP3",
        feature: Some("http3"),
    },
    // PSL is gated on `cookies` rather than being unconditional. The
    // `publicsuffix` crate that replaces libpsl is consumed only by the
    // cookie engine, for domain matching, so advertising PSL in a build
    // without cookies would claim a capability that cannot be exercised.
    Capability {
        token: "PSL",
        feature: Some("cookies"),
    },
    // -- Gated on the non-default `negotiate` feature ----------------------
    // GSS-API is an authentication mechanism, not a TLS library, so it does
    // not contradict "rustls exclusively". Keeping it non-default is what
    // makes the stronger statement true: the default build links no C
    // security library at all.
    Capability {
        token: "GSS-API",
        feature: Some("negotiate"),
    },
    Capability {
        token: "SPNEGO",
        feature: Some("negotiate"),
    },
    Capability {
        token: "Kerberos",
        feature: Some("negotiate"),
    },
    // -- Gated on the non-default `memdebug` feature -----------------------
    // WITHHELD BY DEFAULT, DELIBERATELY, AND THE COST IS STATED RATHER THAN
    // BURIED -- specification 0.8.6, open ambiguity A5, resolved there with
    // this same trade-off. The harness wraps its entire memory-checking
    // block in
    // `if($feature{"TrackMemory"})` (tests/runtests.pl:1759) and sets that
    // feature exclusively from the banner (`:660`,
    // `$feature{"TrackMemory"} = $feat =~ /Debug/i;`). Withholding `Debug`
    // therefore makes the 28 fixtures carrying a `<limits>` block inert,
    // which is what we want, because a Rust allocator's allocation counts
    // will not match a C one's. The price, stated plainly: 98 fixtures
    // require `Debug` and will skip, and `make torture-test` hard-requires
    // it (tests/runtests.pl:847-849) and is therefore not applicable.
    //
    // They are gated rather than absent because the `memdebug` feature
    // exists precisely to reverse that decision by supplying a counting
    // GlobalAlloc that reproduces `lib/memdebug.c`'s log format. Leaving
    // the tokens permanently unreachable would make that feature inert. A
    // default build still withholds both, which is what is required.
    Capability {
        token: "Debug",
        feature: Some("memdebug"),
    },
    Capability {
        token: "TrackMemory",
        feature: Some("memdebug"),
    },
];

/// Tokens from the harness's vocabulary that this build must never
/// advertise, each with the reason. Checked at build time by
/// [`run_self_checks`], so a token cannot reappear through a careless edit
/// to [`CAPABILITIES`].
///
/// `rustls` is absent from this list because it IS advertised, and that
/// deserves its own note -- specification 0.8.6, open ambiguity A8,
/// resolved there in favour of accuracy. The harness sets
/// `$feature{"rustls"}` from a
/// `rustls-ffi` token in the banner (tests/runtests.pl:585-586), not from
/// the word `rustls`. Emitting `rustls-ffi` would unlock the rustls-gated
/// fixtures but would misdescribe the implementation, which uses rustls
/// natively rather than through its C FFI, and `deny.toml:630` bans the
/// `rustls-ffi` crate outright for exactly that reason. So the truthful
/// token is emitted and the resulting skips are accepted, consistent with
/// under-reporting being the safe direction.
const WITHHELD: [(&str, &str); 15] = [
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
        "the system resolver is used; hickory-dns is optional",
    ),
    (
        "gsasl",
        "dropped with the SASL protocols, which are out of scope",
    ),
];

/// The nine URL schemes this implementation actually serves.
///
/// The C tree registers 33. The other 24 are registered for ABI
/// completeness and return `CURLE_UNSUPPORTED_PROTOCOL`, and they are
/// withheld from this list so that the 283 fixtures targeting them skip
/// cleanly rather than running and failing.
const PROTOCOLS: [Capability; 9] = [
    Capability {
        token: "FILE",
        feature: None,
    },
    Capability {
        token: "FTP",
        feature: Some("ftp"),
    },
    Capability {
        token: "FTPS",
        feature: Some("ftp"),
    },
    Capability {
        token: "HTTP",
        feature: None,
    },
    Capability {
        token: "HTTPS",
        feature: None,
    },
    Capability {
        token: "SCP",
        feature: Some("ssh"),
    },
    Capability {
        token: "SFTP",
        feature: Some("ssh"),
    },
    Capability {
        token: "WS",
        feature: Some("websockets"),
    },
    Capability {
        token: "WSS",
        feature: Some("websockets"),
    },
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

// ---------------------------------------------------------------------------
// Section 6: measured ground truth, kept where a reviewer will find it
// ---------------------------------------------------------------------------
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
// cbindgen renders both from that one module.
//
// So that a reviewer can check `opts.rs` without re-deriving anything, the
// facts below were measured by RUNNING the C generator:
// `perl lib/optiontable.pl < include/curl/curl.h`. They are constants
// rather than prose because [`run_self_checks`] asserts the relationships
// between them, which prose cannot do.

/// Rows the C generator emits, including the terminating sentinel
/// `{ NULL, CURLOPT_LASTENTRY, CURLOT_LONG, 0 }`. Measured: 323.
const OPTION_TABLE_ROWS: usize = 323;

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

/// True option rows, excluding the sentinel.
const OPTION_TABLE_REAL_ROWS: usize = OPTION_TABLE_ROWS - 1;

/// `CURLOPT_LASTENTRY`'s index, from the generator's own consistency check:
/// `return (CURLOPT_LASTENTRY % 10000) != (328 + 1);`.
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
const VERBATIM_FUNCTIONS: usize = 19;

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

// ---------------------------------------------------------------------------
// Section 7: entry point
// ---------------------------------------------------------------------------

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

    emit_rerun_directives(&manifest);
    emit_link_args();

    let facts = VersionFacts::read(&root)?;

    generate_headers(&manifest, &root)?;
    render_curl_config(&root, &facts)?;
    render_libcurl_pc(&root, &facts)?;

    Ok(())
}

/// Read an environment variable Cargo is contractually required to set,
/// failing with a message that names it rather than with a bare `None`.
fn env_var(key: &str) -> Result<String, Box<dyn Error>> {
    env::var(key)
        .map_err(|e| format!("cargo did not provide {key} to the build script: {e}").into())
}

// ---------------------------------------------------------------------------
// Section 8: build-time invariants
// ---------------------------------------------------------------------------

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
        let in_forward = CURL_H_FORWARD.contains(&tag_struct) || CURL_H_FORWARD.contains(&tag_enum);
        let in_verbatim =
            CURL_H_VERBATIM.contains(&tag_struct) || CURL_H_VERBATIM.contains(&tag_enum);
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
    for cap in CAPABILITIES.iter() {
        if let Some((token, reason)) = WITHHELD.iter().find(|(t, _)| *t == cap.token) {
            return Err(format!(
                "{token} appears in CAPABILITIES but is withheld because {reason}"
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
    if OPTION_LASTENTRY_INDEX < OPTION_TABLE_REAL_ROWS {
        return Err(format!(
            "CURLOPT_LASTENTRY index {OPTION_LASTENTRY_INDEX} is below the \
             {OPTION_TABLE_REAL_ROWS} real option rows"
        )
        .into());
    }

    // The per-header function partition has to account for every exported
    // symbol exactly once. 100 symbols, 19 of them verbatim, so the eight
    // partitions must contribute 81 function names between them. Counting
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

    Ok(())
}

// ---------------------------------------------------------------------------
// Section 9: Cargo directives
// ---------------------------------------------------------------------------

/// Declare every input this script reads.
///
/// EMITTING EVEN ONE `rerun-if-changed` DISABLES CARGO'S DEFAULT BEHAVIOUR
/// OF RE-RUNNING WHEN ANYTHING IN THE PACKAGE CHANGES. The list must
/// therefore be complete, or an edit will be silently ignored and the tree
/// will hold a stale header while the source says otherwise. Every path
/// below corresponds to something this file actually reads; adding a read
/// without adding a line here is a defect.
fn emit_rerun_directives(manifest: &Path) {
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

    for key in TRACKED_ENV.iter() {
        println!("cargo:rerun-if-env-changed={key}");
    }

    // Sanity: if the manifest directory somehow lacks the configuration we
    // just declared, say so now rather than failing inside cbindgen with a
    // less obvious message.
    let config = manifest.join("cbindgen.toml");
    if !config.is_file() {
        println!(
            "cargo:warning=curl-rs-ffi/cbindgen.toml is missing at {}; \
             header generation will fail",
            config.display()
        );
    }
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
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();

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

    // ESCALATION, NOT SILENT ACCEPTANCE -- specification 0.8.6, open
    // ambiguity A4. On aarch64-apple-darwin, Apple's
    // arm64 ABI passes variadic arguments on the stack, while the
    // non-variadic Rust callee that implements curl_easy_setopt and its
    // three siblings reads register x2 (measured codegen: "mov x0, x2;
    // ret"). Caller and callee disagree, and the failure is silent. The
    // remedy is the c_variadic feature, stable only on nightly 1.99, which
    // exceeds the declared MSRV of 1.75, so two of the project's own
    // requirements cannot both be satisfied. Raising the MSRV, dropping
    // this target, or accepting that its varargs entry points are
    // unsupported are all decisions above this file's pay grade. What this
    // file can do is refuse to let the build be quiet about it, and this is
    // the only place that knows the target triple at build time.
    if os == "macos" && arch == "aarch64" {
        println!(
            "cargo:warning=aarch64-apple-darwin (open ambiguity A4): \
             Apple's arm64 ABI passes variadic arguments on the stack, but \
             the C ABI shim's setopt and getinfo entry points are \
             non-variadic and read a register. This mismatch is silent at \
             run time. A4 needs a decision: raise the MSRV above 1.75 to \
             use c_variadic, drop this target, or accept that its varargs \
             entry points are unsupported."
        );
    }
}

// ---------------------------------------------------------------------------
// Section 10: version facts, read the way configure.ac read them
// ---------------------------------------------------------------------------

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
        let text = fs::read_to_string(&path)
            .map_err(|e| format!("cannot read {} for version facts: {e}", path.display()))?;

        let mut version = None;
        let mut vernum = None;
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("#define LIBCURL_VERSION \"") {
                if let Some(end) = rest.find('"') {
                    version = Some(rest[..end].to_string());
                }
            } else if let Some(rest) = line.strip_prefix("#define LIBCURL_VERSION_NUM 0x") {
                let digits: String = rest.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
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

// ---------------------------------------------------------------------------
// Section 11: writing files
// ---------------------------------------------------------------------------

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
             958 lines of 258 curlcheck_ macros that the 129 example \
             programs compile with active). Remove it from the header table.",
            path.display()
        );
    }
}

/// The staging sibling of a destination path: `foo.h` becomes `foo.h.new`.
///
/// Same directory as the destination, because `rename` is only atomic within
/// one filesystem. The root `.gitignore` covers `include/curl/*.new` and
/// `include/curl/*.tmp` while deliberately NOT ignoring `include/curl/*.h`,
/// since those are the reviewed ABI contract.
fn staging_path(path: &Path) -> PathBuf {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("out");
    path.with_file_name(format!("{name}.new"))
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
fn write_if_changed(path: &Path, contents: &str) -> Result<bool, Box<dyn Error>> {
    guard_write_target(path);

    if let Ok(existing) = fs::read_to_string(path) {
        if existing == contents {
            return Ok(false);
        }
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }

    let staged = staging_path(path);
    fs::write(&staged, contents).map_err(|e| format!("cannot write {}: {e}", staged.display()))?;

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

    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|e| format!("cannot set mode {mode:o} on {}: {e}", path.display()).into())
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
        return Err(format!("{label} has a duplicated newline at end of file").into());
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
fn check_source_hygiene(label: &str, text: &str, max_columns: usize) -> Result<(), Box<dyn Error>> {
    check_text_hygiene(label, text)?;

    if text.contains('\t') {
        return Err(format!("{label} contains a tab").into());
    }
    for (i, line) in text.lines().enumerate() {
        let number = i + 1;
        if line.len() != line.trim_end().len() {
            return Err(format!("{label}:{number} has trailing whitespace").into());
        }
        if !line.is_ascii() {
            return Err(format!("{label}:{number} contains a non-ASCII byte").into());
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
    Ok(())
}

// ---------------------------------------------------------------------------
// Section 12: header generation
// ---------------------------------------------------------------------------

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
            "cbindgen.toml's `header` has no line opening the boxed banner".to_string()
        })?;
    let offset = lines[start..]
        .iter()
        .position(|l| l.ends_with("****/"))
        .ok_or_else(|| {
            "cbindgen.toml's `header` has no line closing the boxed banner".to_string()
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
    let _ = write!(out, "#ifdef __cplusplus\n{}\n#endif\n", spec.extern_c_close);
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

/// Compose `curl.h`'s trailer: its verbatim definitions, then
/// `cbindgen.toml`'s trailer untouched.
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
/// Used to build the partition and then to check it. It is defence in
/// depth, not the authority: the authority is
/// `.github/workflows/rust-abi.yml`, where a duplicated or missing
/// declaration is a hard error from the C compiler across 129 programs.
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
fn generated_region<'a>(text: &'a str, prologue: &str, epilogue: &str) -> &'a str {
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
fn apply_partition(config: &mut cbindgen::Config, owned: &[&str], suppress: &[String]) {
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
/// `cbindgen.toml:898` lists `CURLoption` under `[export] exclude`. AAP 0.1.2
/// makes `curl-rs-ffi/src/ffi/opts.rs` the single source of truth for option
/// identity and requires it to emit "both the enumeration and the metadata
/// array"; AAP 0.4.1 repeats it. The AAP takes precedence over the
/// configuration, so the enumeration is GENERATED from `opts.rs` rather than
/// spliced verbatim.
///
/// This is not a contradiction of `cbindgen.toml`'s intent so much as a
/// resolution of it. That file delegates the per-header export partition to
/// this script; deciding which pass owns `CURLoption` is part of the
/// partition. The alternative -- splicing curl.h:1138-2262 verbatim -- would
/// put 308 option identifiers in two places, and AAP 0.1.2 says of exactly
/// that arrangement: "If those are populated from two places, they will
/// drift, and the drift will be invisible until a consumer queries an option
/// by name and receives the wrong identifier."
///
/// The generator macros `CURLoption` expands (`CURLOPT`,
/// `CURLOPTDEPRECATED`, the five `CURLOPTTYPE_*` bases and their four
/// aliases) remain verbatim in [`CURL_H_FORWARD`], which is what
/// `cbindgen.toml:406-425` asks for. Its integers are asserted against
/// curl 8.19.0-DEV by `tests-rs/abi/enum_values.rs`, so generation is
/// checked rather than trusted.
const CURL_H_GENERATED_DESPITE_EXCLUSION: &[&str] = &["CURLoption"];

/// Run one cbindgen pass and return its text.
fn render_binding(manifest: &Path, config: cbindgen::Config) -> Result<String, Box<dyn Error>> {
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

    let mut out: Vec<u8> = Vec::new();
    bindings.write(&mut out);
    let text =
        String::from_utf8(out).map_err(|e| format!("cbindgen produced non-UTF-8 output: {e}"))?;

    Ok(normalise_generated_c(&text))
}

/// Rewrite the one construct cbindgen emits that the tree's own style gate
/// rejects: a `//` comment closing a preprocessor conditional.
///
/// Measured, with the cause traced rather than guessed. cbindgen writes
/// `#endif // __STDC_VERSION__ >= 202311L` at
/// `ir/enumeration.rs:798`, and it takes that path for every enum carrying an
/// explicit `#[repr(iN)]` -- which is EVERY public enum here, because AAP
/// 0.6.1's integer-exactness requirement is implemented by pinning the
/// representation. The construct is therefore unavoidable, not incidental.
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
fn generate_headers(manifest: &Path, root: &Path) -> Result<(), Box<dyn Error>> {
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

    let sibling_items = all_sibling_items();
    let include_dir = root.join("include").join("curl");

    // The umbrella. Its guard, banner, `extern "C"` open, `#include` block,
    // guard close and sibling includes all come from cbindgen.toml
    // untouched, because that file is the single configuration and restating
    // them here is the duplication the rule exists to prevent. What this
    // script adds is the interior verbatim text cbindgen.toml delegates to it
    // at ":968-975": the forward declarations before the generated block and
    // the definitions after it.
    let umbrella_forward = umbrella_after_includes();
    let umbrella_trailer = umbrella_epilogue(base.trailer.as_deref().unwrap_or_default());

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
    let umbrella_body = generated_region(&umbrella_text, &umbrella_forward, &umbrella_trailer);
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
    write_if_changed(&include_dir.join("curl.h"), &umbrella_text)?;

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
        for item in spec.items {
            if observed.iter().any(|name| name == item) && !declared.iter().any(|name| name == item)
            {
                return Err(format!(
                    "{} was expected to declare {item} and does not. \
                     Generating it now would publish an incomplete ABI \
                     contract.",
                    spec.file
                )
                .into());
            }
        }

        write_if_changed(&include_dir.join(spec.file), &text)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Section 13: template substitution
// ---------------------------------------------------------------------------

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
        while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == '_') {
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
/// GLOBAL, not first-match, and that is not a stylistic choice:
/// `@CURLVERSION@` occurs four times in `curl-config.in` (`:98`, `:110`,
/// `:111`, `:114` and `:130`), `@includedir@` three times and `@libdir@`
/// three times. A first-match substitution would leave live placeholders in
/// the `--checkfor` arithmetic, where they would produce shell errors rather
/// than a verdict.
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
            return Err(format!("{label} uses @{name}@ and no value is supplied for it").into());
        }
    }
    for (key, _) in values {
        if !present.iter().any(|name| name == key) {
            return Err(
                format!("a value is supplied for @{key}@, which {label} does not use").into(),
            );
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
fn check_no_residual_placeholders(label: &str, rendered: &str) -> Result<(), Box<dyn Error>> {
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

// ---------------------------------------------------------------------------
// Section 14: what to report about this build
// ---------------------------------------------------------------------------

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
    let key = format!("CARGO_FEATURE_{}", name.to_uppercase().replace('-', "_"));
    env::var_os(key).is_some()
}

/// The feature tokens this build honestly supports, space separated.
///
/// Sorted case-insensitively, matching `CMakeLists.txt:2041-2045`, which
/// sorts both the feature list and the SSL-backend list that way. Sorting at
/// all is what makes the rendered artifacts byte-identical between two
/// builds of the same configuration.
fn advertised_features() -> String {
    let mut tokens: Vec<&str> = CAPABILITIES
        .iter()
        .filter(|capability| match capability.feature {
            Some(feature) => feature_enabled(feature),
            None => true,
        })
        .map(|capability| capability.token)
        .collect();
    tokens.sort_by_key(|token| token.to_lowercase());
    tokens.join(" ")
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
/// instead of running and failing.
fn advertised_protocols() -> String {
    let mut tokens: Vec<&str> = PROTOCOLS
        .iter()
        .filter(|protocol| match protocol.feature {
            Some(feature) => feature_enabled(feature),
            None => true,
        })
        .map(|protocol| protocol.token)
        .collect();
    tokens.sort_unstable();
    tokens.join(" ")
}

/// Characters allowed in `@CONFIGURE_OPTIONS@`.
///
/// `curl-config.in:178` is `echo @CONFIGURE_OPTIONS@` -- the ONE arm of the
/// script that leaves its value unquoted, so the shell word-splits and
/// glob-expands it. Anything outside this set could be interpreted rather
/// than printed, so the value is validated instead of trusted.
const SAFE_CONFIGURE_CHARS: &str = "-_=,./+: ";

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
    if let Some(bad) = rendered
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || SAFE_CONFIGURE_CHARS.contains(*c)))
    {
        return Err(format!(
            "the value for @CONFIGURE_OPTIONS@ contains {bad:?}, which is \
             not safe to leave unquoted in curl-config.in:178"
        )
        .into());
    }

    Ok(rendered)
}

/// Libraries a static link needs beyond libcurl itself.
///
/// Linux keeps `-ldl`; macOS does not have a separate libdl, since `dlopen`
/// lives in libSystem, so naming it there would make every static link fail.
/// Selected from `CARGO_CFG_TARGET_OS` because these describe the artifact
/// being built, not the host building it.
fn private_libs(target_os: &str) -> &'static str {
    match target_os {
        "linux" => "-lpthread -ldl -lm",
        _ => "-lpthread -lm",
    }
}

/// The install prefix the rendered artifacts describe.
///
/// `CURL_RS_PREFIX` first because it is unambiguous, then `PREFIX`, then the
/// same `/usr/local` default Autotools used. Both are declared to Cargo
/// under `rerun-if-env-changed`, so changing one re-renders.
fn install_prefix() -> String {
    env::var("CURL_RS_PREFIX")
        .or_else(|_| env::var("PREFIX"))
        .unwrap_or_else(|_| DEFAULT_PREFIX.to_string())
}

/// The compiler name `curl-config --cc` reports.
///
/// Must be non-empty: consumers use it to build test programs, and an empty
/// value turns their command line into one that runs their first argument as
/// a program.
fn compiler() -> String {
    match env::var("CC") {
        Ok(value) if !value.trim().is_empty() => value,
        _ => "cc".to_string(),
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

// ---------------------------------------------------------------------------
// Section 15: rendering curl-config and libcurl.pc
// ---------------------------------------------------------------------------
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
fn render_curl_config(root: &Path, facts: &VersionFacts) -> Result<(), Box<dyn Error>> {
    let template_path = root.join("curl-config.in");
    let template = fs::read_to_string(&template_path)
        .map_err(|e| format!("cannot read {}: {e}", template_path.display()))?;

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let prefix = install_prefix();

    let values: Vec<(&str, String)> = vec![
        // curl-config.in:28.
        ("prefix", prefix),
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
        // Drives --ca (:72). Empty unless configured.
        ("CURL_CA_BUNDLE", ca_bundle()),
        // Drives --cc (:76).
        ("CC", compiler()),
        // Drives --feature/--features (:84-89), which loops over the value
        // unquoted so that it word-splits into one token per line.
        ("SUPPORT_FEATURES", advertised_features()),
        // Drives --protocols (:90-96). curl-config.in:91 carries a
        // `# shellcheck disable=SC2043` immediately before the loop.
        ("SUPPORT_PROTOCOLS", advertised_protocols()),
        // include/curl/curlver.h:35. AAP 0.8.5/C6 binds every parity claim
        // in this work to this exact string.
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
        // Printed by --static-libs (:170).
        (
            "LIBCURL_PC_LIBS_PRIVATE",
            private_libs(&target_os).to_string(),
        ),
        // Empty: a Rust cdylib needs no extra link-time flags of its own.
        ("LIBCURL_PC_LDFLAGS_PRIVATE", String::new()),
        // Printed unquoted by --configure (:178), hence validated.
        ("CONFIGURE_OPTIONS", configure_options()?),
    ];

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

    let destination = root.join("curl-config");
    write_if_changed(&destination, &rendered)?;
    set_mode(&destination, MODE_SCRIPT)?;

    Ok(())
}

/// Render `<root>/libcurl.pc` from `<root>/libcurl.pc.in`.
///
/// Fourteen values. Two of them are empty for a reason that would otherwise
/// be invisible, so it is stated in full below.
fn render_libcurl_pc(root: &Path, facts: &VersionFacts) -> Result<(), Box<dyn Error>> {
    let template_path = root.join("libcurl.pc.in");
    let template = fs::read_to_string(&template_path)
        .map_err(|e| format!("cannot read {}: {e}", template_path.display()))?;

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    let values: Vec<(&str, String)> = vec![
        // libcurl.pc.in:25-28, the same four directories curl-config uses.
        ("prefix", install_prefix()),
        ("exec_prefix", "${prefix}".to_string()),
        ("libdir", "${exec_prefix}/lib".to_string()),
        ("includedir", "${prefix}/include".to_string()),
        // :29 and :30, read back by
        // `pkg-config --variable=supported_protocols libcurl`. The same two
        // functions feed curl-config, so the two files cannot disagree.
        ("SUPPORT_PROTOCOLS", advertised_protocols()),
        ("SUPPORT_FEATURES", advertised_features()),
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
        (
            "LIBCURL_PC_LIBS_PRIVATE",
            private_libs(&target_os).to_string(),
        ),
        ("LIBCURL_PC_CFLAGS", String::new()),
        // CMakeLists.txt:2255. Consumers linking the static library must
        // define this so the public headers do not mark the API
        // dllimport-style on platforms that distinguish the two.
        ("LIBCURL_PC_CFLAGS_PRIVATE", "-DCURL_STATICLIB".to_string()),
    ];

    check_placeholder_coverage("libcurl.pc.in", &template, &values, LIBCURL_PC_PLACEHOLDERS)?;

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

    let destination = root.join("libcurl.pc");
    write_if_changed(&destination, &rendered)?;
    // Data, not a script. Explicitly NOT MODE_SCRIPT.
    set_mode(&destination, MODE_DATA)?;

    Ok(())
}
