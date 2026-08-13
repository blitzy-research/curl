// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

// The safety invariant, asserted mechanically rather than by review. A build
// script is a separate compilation unit with its own crate root, so an
// attribute written in `src/main.rs` would not reach it and the invariant is
// restated here rather than inherited. `forbid` rather than `deny`, because
// this crate has no `mod ffi` and so nothing to exempt: unlike the engine
// crate, which must leave one `#[allow(unsafe_code)]` reachable, nothing here
// may re-enable the keyword from an inner scope.
#![forbid(unsafe_code)]

//! Build script for the curl command-line tool: three Perl generators,
//! reimplemented in Rust, all writing into `OUT_DIR`.
//!
//! This script replaces three Perl generators -- `src/mkhelp.pl`,
//! `src/mk-file-embed.pl` and `scripts/completion.pl` -- and writes their
//! output into `OUT_DIR`. Section 0.2.1 makes reproducing them mandatory and
//! gives the reason: their outputs are build artifacts rather than committed
//! source, so hand-writing the outputs would guarantee drift. Section 0.3.3
//! pattern P11 puts it as a rule: generated code stays generated.
//!
//! The three generators and the artifact each one produces are the embedded
//! manual from `src/mkhelp.pl` into `hugehelp.rs`, the embedded CA bundle
//! from `src/mk-file-embed.pl` into `ca_embed.rs` plus `ca_embed.bin`, and
//! the zsh and fish shell completions from `scripts/completion.pl` into
//! `completions/_curl` and `completions/curl.fish`. Every one of the four
//! artifacts is written on EVERY run, as a valid stub when its optional input
//! is absent, so the consuming modules can include them unconditionally.
//! `curl-rs/src/output/msgs.rs` already depends on exactly that: it records
//! that this script "generates `$OUT_DIR`/hugehelp.rs unconditionally, so the
//! built-in manual is always present", and that `USE_MANUAL` "is not, and must
//! not become, a Cargo feature".
//!
//! The dominant constraint on this file is reproducibility. Every byte emitted
//! here is a pure function of the repository contents: no clock is read, no
//! host or user name is consulted, no absolute path reaches generated code,
//! no network is touched, and no directory-iteration order is trusted --
//! every file list is sorted explicitly before use.

use std::env;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

// Measured corpus constants
//
// These are counted, not quoted. Every figure below was produced by listing
// the directory in this checkout, and the derivation is written out so a
// future reader can re-run it rather than trust it.
//
//   ls docs/cmdline-opts/*.md   | wc -l  ->  293   every curldown page
//   ls docs/cmdline-opts/_*.md  | wc -l  ->   19   the SUPPORT meta pages
//   MANPAGE.md                           ->    1   documentation ABOUT the
//                                                  format, not an option
//   293 - 19 - 1                         ->  273   option pages
//
// 273 is cross-checked three independent ways:
//
//   * docs/cmdline-opts/Makefile.inc declares SUPPORT at :26 with 19 `.md`
//     entries and DPAGES at :47 with 273.
//   * src/tool_listhelp.c's helptext[] holds 273 real entries followed by
//     `{ NULL, NULL, 0 }` at :863. A naive count of lines beginning "  {"
//     therefore yields 274 -- the sentinel is not an option.
//   * scripts/completion.pl:89 selects exactly this set: `*.md`,
//     case-insensitive, a regular file, not `^_`-prefixed, and not
//     `MANPAGE.md`, whose exclusion its own comment calls out as an edge
//     case. Running it here emits 273 completion entries.
//
// The count is asserted at build time and a mismatch FAILS the build. That is
// a deliberate reversal of an earlier design in this file, which reported
// drift through `cargo:warning=` on the reasoning that divergence is "worth
// shouting about, but not a reason to refuse to build". Three things make the
// warning the weaker choice:
//
//   * It does not actually keep the build green. AAP section 0.8.4 gate 1
//     requires `cargo build --release --workspace` to complete with ZERO
//     warnings on all four targets, and a `cargo:warning=` line is a warning
//     in that output. So drift already broke the build -- just at a distance
//     from its cause, in a gate whose message says nothing about
//     documentation pages.
//   * The artifacts are generated FROM this corpus. A page count that no
//     longer matches means the embedded manual and the shell completions
//     describe a different command-line surface than the one being built, and
//     AAP section 0.8.1 freezes that surface. Emitting the artifacts anyway
//     ships the disagreement.
//   * A warning is discardable. `cargo build` prints it once and a cached
//     rebuild does not print it again, so the signal disappears while the
//     wrong artifact stays.
//
// Failing here costs a developer who is deliberately adding or removing an
// option exactly one edit -- this constant -- and that edit is the record that
// the surface moved.
//
// WHAT A COUNT CANNOT SEE, and why that is not a gap. A cardinality check is
// blind to any change that preserves the total, the obvious case being a page
// renamed rather than added. That was measured rather than reasoned about:
// renaming `verbose.md` to `verbose-renamed.md` leaves the corpus at 273 and
// the check passes -- and it SHOULD, because the three artifacts came out
// byte-identical. Every generated byte derives from the front matter's `Long:`
// and `Short:` fields, so a file name is only the handle used to find a page,
// never data. There is no drift to catch.
//
// The change that would be drift -- editing the front matter itself -- is
// caught, by the generators rather than by arithmetic. Rewriting
// `Long: verbose` to an invented name makes `scripts/managen` exit 2 with
// "head.md:17:1:WARN: see-also a non-existing option: verbose", and this script
// now treats a managen failure as fatal. Removing the front matter entirely is
// caught by `generate_completions`, which refuses every unparsable page. So the
// three checks compose to cover the whole space: arithmetic catches a page
// appearing or vanishing, managen catches a cross-reference that no longer
// resolves, and the page parser catches malformed front matter. Adding a parser
// for `Makefile.inc`'s DPAGES list on top would add a fourth authority to keep
// in step while catching nothing the other three miss.
const OPTION_PAGE_COUNT: usize = 273;

/// Count of `_`-prefixed SUPPORT pages -- `Makefile.inc:26`, `mainpage.idx`.
const SUPPORT_PAGE_COUNT: usize = 19;

/// Count of every `*.md` page under `docs/cmdline-opts`, derived not quoted.
///
/// The `+ 1` is `MANPAGE.md`. Writing the total as the sum keeps the three
/// figures from ever disagreeing with one another.
const TOTAL_PAGE_COUNT: usize = OPTION_PAGE_COUNT + SUPPORT_PAGE_COUNT + 1;

/// The one `*.md` page that is neither an option page nor a SUPPORT page.
///
/// `scripts/completion.pl:89` excludes it by exact, case-sensitive name.
const MANPAGE_DOC: &str = "MANPAGE.md";

// Paths, relative to the repository root
//
// Held as `&str` with forward slashes and joined component-wise, so nothing
// absolute is ever written down. Reproducibility rules out a hard-coded
// absolute path outright, and the root is derived at run time from
// CARGO_MANIFEST_DIR instead.

/// `docs/cmdline-opts` -- the curldown corpus.
const OPTS_DIR: [&str; 2] = ["docs", "cmdline-opts"];

/// `scripts/managen` -- the renderer this script drives.
///
/// It stays in scope: the documentation tooling -- `scripts/managen`,
/// `docs/libcurl/symbols.pl`, `docs/libcurl/mksymbolsmanpage.pl` and
/// `scripts/mk-ca-bundle.pl` -- remains in scope for continued operation
/// against the new tree." It is driven, never reimplemented; reimplementing
/// curldown rendering would be a second source of truth for the manual and
/// would drift from the manual page.
const MANAGEN: [&str; 2] = ["scripts", "managen"];

/// `include` -- what `managen -I` points at.
const INCLUDE_DIR: [&str; 1] = ["include"];

/// `include/curl/curlver.h` -- where `managen` reads the version from.
///
/// `scripts/managen:1367-1374` opens `$include/curl/curlver.h` and takes
/// `$version` from the first `#define LIBCURL_VERSION "..."` line, unless
/// CURL_MAKETGZ_VERSION overrides it at :1365. That makes this header a
/// genuine input to the rendered manual, which is why it appears in the
/// rerun set below. Upstream's own CMake dependency list
/// (`docs/cmdline-opts/CMakeLists.txt:32-35`) omits it; this script does not.
const CURLVER_H: [&str; 3] = ["include", "curl", "curlver.h"];

/// `docs/cmdline-opts/mainpage.idx` -- fixes the manual's section order.
///
/// `scripts/managen:1226-1227` opens it and dies without it. It lists the 19
/// `_*.md` SUPPORT pages plus the `%options` placeholder that expands to the
/// option section.
const MAINPAGE_IDX: &str = "mainpage.idx";

/// `docs/cmdline-opts/Makefile.inc` -- the shared SUPPORT/DPAGES lists.
///
/// A dependency of the ASCII manual in both C build systems:
/// `docs/cmdline-opts/Makefile.am:57` and
/// `docs/cmdline-opts/CMakeLists.txt:33`.
const OPTS_MAKEFILE_INC: &str = "Makefile.inc";

/// `docs/cmdline-opts/curl.txt` -- the pre-rendered ASCII manual.
///
/// A transient artifact, never committed: `docs/cmdline-opts/Makefile.am:47`
/// puts it in CLEANFILES and `docs/cmdline-opts/.gitignore:5` ignores it. It
/// is absent in a fresh checkout, which was confirmed in this one.
///
/// This script does NOT read it opportunistically. Because its presence says
/// nothing about its age, picking it up silently could embed a `--manual` that
/// disagrees with the corpus being compiled; the reasoning is recorded in full
/// at `obtain_ascii_manual`. The name survives here because that function's
/// diagnostic points at it as the file to name in `CURL_ASCIIPAGE` when Perl
/// is unavailable.
const ASCIIPAGE_FILE: &str = "curl.txt";

// Environment variables read -- every one also appears in the rerun set

/// Overrides the Perl interpreter. Defaults to `perl` on `PATH`.
const ENV_PERL: &str = "PERL";

/// Points at a pre-rendered ASCII manual, bypassing `managen`.
///
/// The name matches the C build's own variable so nothing new is invented:
/// `CMakeLists.txt:1912` sets
/// `CURL_ASCIIPAGE "${PROJECT_BINARY_DIR}/docs/cmdline-opts/curl.txt"` and
/// `src/CMakeLists.txt:39` feeds it to `mkhelp.pl` on stdin.
const ENV_ASCIIPAGE: &str = "CURL_ASCIIPAGE";

/// Points at the CA bundle to embed. Unset means embed nothing.
///
/// The name matches the C build exactly, so anyone who already sets it needs
/// no change: `configure.ac:2127`
/// `AM_CONDITIONAL(CURL_CA_EMBED_SET, test -n "$CURL_CA_EMBED")`,
/// `CMakeLists.txt:1375` declaring the cache variable, and
/// `src/Makefile.am:194-195` consuming it.
const ENV_CA_EMBED: &str = "CURL_CA_EMBED";

/// Overrides the version `managen` substitutes for `%VERSION`.
///
/// `scripts/managen:1365-1366`. This one genuinely changes the manual --
/// measured: setting it to 9.9.9 rewrites both "This man page describes curl
/// 8.19.0" and the `curl/8.19.0` user-agent example, and the output hash
/// changes with it. It is therefore a real input, not a curiosity.
const ENV_MAKETGZ_VERSION: &str = "CURL_MAKETGZ_VERSION";

/// The reproducible-builds clock override, honoured by `managen`.
///
/// `scripts/managen:55-56` uses it in place of `localtime`. Measured here,
/// the ASCII manual does NOT depend on it: rendering with SOURCE_DATE_EPOCH
/// unset, 0 and 1700000000 produced three byte-identical outputs. The reason
/// is that `$date` reaches output only through the nroff `.TH` line at
/// `:1256`, which the `ascii` mode does not emit, and through the `%DATE`
/// substitution at `:457`, whose only user is `MANPAGE.md` -- the one page
/// excluded from the option set. The manual is reproducible as a result, and
/// this variable is still declared below because `managen` reads it and a
/// complete rerun set is the point.
const ENV_SOURCE_DATE_EPOCH: &str = "SOURCE_DATE_EPOCH";

/// An additional, explicit install-staging root for the completion scripts.
///
/// Same name and same opt-in semantics as `curl-rs-ffi/build.rs` uses for
/// `curl-config` and `libcurl.pc`, so a packaging step sets one variable and
/// collects every installable artifact of the workspace from one tree. Unset by
/// default, which is what keeps a default build structurally incapable of writing
/// anywhere but its own `OUT_DIR`.
const ENV_STAGING_DIR: &str = "CURL_RS_STAGING_DIR";

/// Every environment variable this script's behaviour depends on.
///
/// ONE list, read by both the `rerun-if-env-changed` emitter and the self-check
/// that validates the keys, because two lists are how a key comes to be read
/// without being tracked. That is not hypothetical: `CURL_RS_STAGING_DIR` was
/// read by `stage_completion` and named in neither list, so a build that had
/// already run would NOT re-run when the variable was set, changed or cleared --
/// cargo would serve the cached script output and the new staging root would
/// simply never be written. A packaging step that set the variable and then
/// found an empty tree had no way to tell that from a build script that had
/// silently declined.
///
/// Emitting even one `rerun-if-changed`/`rerun-if-env-changed` directive
/// disables cargo's default "re-run on any change in the package" behaviour, so
/// an incomplete list here does not degrade tracking, it removes it. That is why
/// the list is a single constant rather than a literal repeated at each use.
const TRACKED_ENV_KEYS: [&str; 6] = [
    ENV_PERL,
    ENV_ASCIIPAGE,
    ENV_CA_EMBED,
    ENV_MAKETGZ_VERSION,
    ENV_SOURCE_DATE_EPOCH,
    ENV_STAGING_DIR,
];

// Artifact names inside OUT_DIR -- the contract with the consuming modules
//
// Written down here because other files include these by name, and a
// producer that leaves its output shape undocumented is a producer nobody
// can consume safely.
//
//   $OUT_DIR/hugehelp.rs            pub(crate) const MANUAL: &[&str]
//   $OUT_DIR/ca_embed.rs            pub(crate) const CA_EMBED_CONFIGURED: bool
//                                   pub(crate) const CA_EMBED: &[u8]
//   $OUT_DIR/ca_embed.bin           raw bundle bytes behind CA_EMBED
//   $OUT_DIR/completions/_curl      zsh completion, `#compdef curl`
//   $OUT_DIR/completions/curl.fish  fish completion, `complete -c curl`
//
// And the install-staging copies of the two completions, laid out the way
// `make install` places them, per `scripts/Makefile.am:54-62`:
//
//   $OUT_DIR/staging/share/zsh/site-functions/_curl
//   $OUT_DIR/staging/share/fish/vendor_completions.d/curl.fish

/// To be included by `curl-rs/src/cli/hugehelp.rs`.
const OUT_HUGEHELP: &str = "hugehelp.rs";

/// Included by `curl-rs/src/ca_embed.rs`.
const OUT_CA_EMBED_RS: &str = "ca_embed.rs";

/// Read by `OUT_CA_EMBED_RS` through `include_bytes!`.
const OUT_CA_EMBED_BIN: &str = "ca_embed.bin";

/// Directory holding both completion scripts.
const OUT_COMPLETIONS_DIR: &str = "completions";

/// zsh completion function file name, as `scripts/Makefile.am:34` names it.
const OUT_ZSH: &str = "_curl";

/// fish completion file name, as `scripts/Makefile.am:37` names it.
const OUT_FISH: &str = "curl.fish";

// Entry point
//
// The split between `main` and `run` exists so that the only two failure
// modes this script may have -- a missing REQUIRED input and an unwritable
// OUT_DIR -- surface as one readable line instead of a Debug-formatted
// panic. Everything optional degrades instead of failing; see
// `generate_manual` and `generate_ca_embed`.

fn main() {
    if let Err(err) = run() {
        // Encoded on the way out as well. This stream is stderr, which Cargo
        // does NOT read directives from, so no forgery is possible here --
        // but the message interpolates the same untrusted paths and child
        // diagnostics that `warn` handles, and Cargo shows a failing build
        // script's stderr verbatim. Encoding it makes the property total and
        // easy to state: no control byte from untrusted data reaches ANY
        // output stream, whichever one it is.
        eprintln!(
            "curl-rs/build.rs: {}",
            encode_directive_value(&format!("{err}"))
        );
        // Every failure path in this script ends here, and none of them
        // degrades into a partial artifact.
        //
        // The distinction that matters is between an input being ABSENT and an
        // input being UNUSABLE. Absence can be a legitimate configuration: no
        // `CURL_CA_EMBED` means no embedded bundle, exactly as the C build's
        // `test -n "$CURL_CA_EMBED"` at configure.ac:2127 decides it, and that
        // path emits a real, empty-by-design artifact.
        //
        // Unusable is never legitimate. A configured variable that points at
        // something unreadable, a generator that cannot run, a page that will
        // not parse, or a corpus whose size no longer matches the surface being
        // built are all situations where the only artifact this script could
        // produce is one that misdescribes the binary. Because AAP section
        // 0.8.1 freezes the command-line surface, `--manual` output and the
        // help text, shipping a silently empty or partial version of any of
        // them is a behavioural change smuggled in as a warning. So each of
        // those conditions arrives here instead.
        //
        // Which inputs are which is not left to the reader, and the list is
        // shorter than it once was because this script no longer degrades:
        //
        //   ABSENT AND LEGITIMATE -- exactly one input, `CURL_CA_EMBED`. Not
        //   setting it means "do not embed a bundle", which is a real
        //   configuration rather than a missing one, so it produces the
        //   empty-by-design artifact with NO diagnostic at all.
        //
        //   REQUIRED -- everything else. The curldown corpus, OUT_DIR and
        //   CARGO_MANIFEST_DIR have no substitute. Neither does the manual:
        //   Perl and `scripts/managen` are required rather than optional,
        //   because the only alternative would be embedding a stale or empty
        //   `--manual`, and `obtain_ascii_manual` records in full why reaching
        //   for `docs/cmdline-opts/curl.txt` was rejected as that alternative.
        //   `CURL_ASCIIPAGE` REPLACES the generator rather than standing in for
        //   it: unset it renders from the corpus, set it is authoritative, and
        //   set-but-unusable is fatal instead of falling through to something
        //   nobody asked for.
        //
        // The whole file therefore holds a single `warn` call, and it does not
        // excuse a missing artifact: it names a corpus page whose file name
        // cannot be a curldown page, and `Corpus::verify_counts` then fails the
        // build because the surviving page count no longer matches the surface.
        std::process::exit(1);
    }
}

fn run() -> io::Result<()> {
    // Before anything is read or written. These assert the properties the
    // rest of the file relies on and that no `#[cfg(test)]` module could
    // ever check, because `cargo test` never compiles a build script -- the
    // only way a self-check here can run is by running on every build.
    run_self_checks()?;

    // The repository root is the parent of this crate's manifest directory.
    // Deriving it rather than hard-coding it is what keeps the script
    // relocatable and keeps absolute paths out of every artifact.
    let manifest_dir = required_env_path("CARGO_MANIFEST_DIR")?;
    let repo_root = manifest_dir
        .parent()
        .ok_or_else(|| {
            io::Error::other(format!(
                "CARGO_MANIFEST_DIR ({}) has no parent directory, so the \
                 repository root cannot be derived",
                manifest_dir.display()
            ))
        })?
        .to_path_buf();
    let out_dir = required_env_path("OUT_DIR")?;

    let opts_dir = join(&repo_root, &OPTS_DIR);
    let corpus = Corpus::collect(&opts_dir)?;

    // Both are validated at this boundary rather than at the point of use, so
    // that a hostile value cannot reach any directive-emitting code path at
    // all. See `check_directive_safe`.
    let ca_bundle = optional_env_path(ENV_CA_EMBED)?;
    let ascii_override = optional_env_path(ENV_ASCIIPAGE)?;

    // Emitted before any generator runs, so that a build which fails in a
    // generator still leaves a complete dependency record behind and therefore
    // re-runs when the input that caused the failure is corrected.
    emit_rerun_directives(
        &repo_root,
        &opts_dir,
        &corpus,
        ca_bundle.as_deref(),
        ascii_override.as_deref(),
    )?;
    corpus.verify_counts()?;

    generate_manual(
        &repo_root,
        &opts_dir,
        &corpus,
        ascii_override.as_deref(),
        &out_dir,
    )?;
    generate_ca_embed(ca_bundle.as_deref(), &out_dir)?;
    generate_completions(&corpus, &out_dir)?;

    Ok(())
}

// Environment and path helpers

/// Reads a variable Cargo always sets, failing loudly when it is absent.
///
/// Both callers name variables documented as part of the build script
/// protocol, so their absence means the script is not being run by Cargo at
/// all, and no amount of degradation would produce a useful artifact.
fn required_env_path(key: &str) -> io::Result<PathBuf> {
    match env::var_os(key) {
        Some(value) if !value.is_empty() => Ok(PathBuf::from(value)),
        _ => Err(io::Error::other(format!(
            "{key} is not set; this file must be run as a Cargo build script"
        ))),
    }
}

/// Reads an optional variable, treating empty exactly as unset.
///
/// Empty-means-unset matches the C build's own test:
/// `configure.ac:2127` uses `test -n "$CURL_CA_EMBED"`, so `CURL_CA_EMBED=`
/// disables embedding there and disables it here too.
///
/// The value is validated here, at the boundary where it enters the script,
/// rather than at each of the places it is later used. Both variables this is
/// called for are named in `cargo:rerun-if-changed=` directives, and Cargo's
/// build-script protocol is line-oriented: it reads one directive per line of
/// standard output. A value carrying a line break would therefore end the
/// directive early and let the remainder of the value be parsed as a FURTHER
/// instruction to Cargo -- `rustc-link-lib`, `rustc-link-search`,
/// `rustc-cfg`, `rustc-env` -- from whatever set that variable. Rejecting the
/// value once, on entry, means no later caller has to remember.
fn optional_env_path(key: &str) -> io::Result<Option<PathBuf>> {
    match env::var_os(key) {
        Some(value) if !value.is_empty() => {
            let path = PathBuf::from(value);
            check_directive_safe(key, &path)?;
            Ok(Some(path))
        }
        _ => Ok(None),
    }
}

/// Rejects a path that could not appear in a Cargo directive verbatim.
///
/// Three classes are refused, and the reason differs for each:
///
///   * A line break, `\n` or `\r`, would terminate the directive line. This is
///     the injection vector: everything after the break becomes a new line on
///     standard output, and Cargo interprets any line beginning `cargo:` or
///     `cargo::` as an instruction. Refusing the value is the only safe
///     response, because there is no escape sequence for a newline in a
///     protocol that has none.
///   * A NUL byte cannot survive the round trip. The path would be truncated
///     at the NUL by any system call that takes a C string, so the file
///     recorded as a dependency would not be the file that was read.
///
///     Reported honestly rather than claimed as a closed hole: this class is
///     UNREACHABLE through the environment, by construction rather than by
///     luck. A POSIX `environ` entry is itself a NUL-terminated C string, so
///     the kernel copies only up to the first NUL and the child never receives
///     the remainder. Measured directly with an `execve` carrying
///     `CURL_CA_EMBED=/path\0/etc/passwd`: the child observed a 20-character
///     value ending at the NUL. The check is kept because it costs one
///     comparison and because the two live classes above are reachable, so a
///     reader who finds only those two would reasonably wonder whether the
///     third had been considered.
///   * A path that is not valid UTF-8 cannot be written to standard output as
///     text at all. `Path::display` would substitute replacement characters
///     and name a file that does not exist, so the dependency record would be
///     silently wrong rather than loudly absent.
fn check_directive_safe(key: &str, path: &Path) -> io::Result<()> {
    let Some(text) = path.to_str() else {
        return Err(io::Error::other(format!(
            "{key} is not valid UTF-8. Its value has to be written verbatim \
             into a cargo:rerun-if-changed= directive, which is UTF-8 text, so \
             a lossy conversion would record a dependency on a file that does \
             not exist"
        )));
    };
    for (offset, character) in text.char_indices() {
        let label = match character {
            '\n' => "a line feed",
            '\r' => "a carriage return",
            '\0' => "a NUL byte",
            _ => continue,
        };
        return Err(io::Error::other(format!(
            "{key} contains {label} at byte {offset}. Cargo reads one \
             directive per line of build-script output, so this value would \
             end the cargo:rerun-if-changed= line early and let the rest of it \
             be interpreted as a further instruction to Cargo. Remove the \
             control character from the path"
        )));
    }
    Ok(())
}

/// Joins path components onto a base without ever writing a separator.
///
/// Keeping the components as `&str` arrays and joining here means the
/// constants stay platform-neutral and no literal contains a separator.
fn join(base: &Path, parts: &[&str]) -> PathBuf {
    let mut path = base.to_path_buf();
    for part in parts {
        path.push(part);
    }
    path
}

/// Emits one Cargo directive, refusing any value that would break the line.
///
/// EVERY line this script writes to standard output goes through here. That is
/// the point: Cargo's build-script protocol treats standard output as a
/// sequence of directives, one per line, so a single `println!` elsewhere in
/// the file that interpolated an external value would reopen the injection
/// hole this function exists to close. Centralising the write means the
/// validation cannot be forgotten at a call site, because there are no other
/// call sites.
///
/// `key` is the directive name without its `cargo:` prefix, such as
/// `rerun-if-changed`. `value` is checked, not escaped: the protocol provides
/// no escape sequence for a line break, so a value containing one has no
/// faithful encoding and is refused instead of mangled.
///
/// Two companions, and they are not alternatives to this function. [`warn`]
/// ENCODES its message and then emits it through here, because a diagnostic
/// that refused to print itself on account of its own content would report
/// nothing at all; the refusal below is therefore unreachable for that
/// caller rather than bypassed by it. [`checked_directive_value`] applies the
/// identical rule EARLIER, where a caller wants to fail at the point the
/// value is derived instead of at the point it is written.
fn emit_directive(key: &str, value: &str) -> io::Result<()> {
    for (offset, character) in value.char_indices() {
        let label = match character {
            '\n' => "a line feed",
            '\r' => "a carriage return",
            '\0' => "a NUL byte",
            _ => continue,
        };
        return Err(io::Error::other(format!(
            "refusing to emit cargo:{key}= with {label} at byte {offset} of \
             its value. Cargo parses one directive per line, so the remainder \
             would be read as a separate instruction"
        )));
    }
    println!("cargo:{key}={value}");
    Ok(())
}

// The Cargo directive channel
//
// EVERY dynamic value that reaches a `cargo:` directive passes through one of
// the two functions below, which is what makes the property auditable:
//
//     grep -cE 'println!\("cargo' curl-rs/build.rs   ==  1
//
// and that one line is inside [`emit_directive`], which every other writer
// goes through: `warn` after encoding, `rerun_if_changed` and the
// `rerun-if-env-changed` loop after `checked_directive_value` has already
// refused anything unrepresentable. One write point and two ways of reaching
// it is a stronger invariant than four write points that each remember to
// validate, because the reminder cannot be forgotten where there is nothing
// to remember.
//
// WHY THIS EXISTS. Cargo reads a build script's stdout LINE BY LINE, so a
// newline embedded in a directive VALUE does not truncate the directive: it
// ENDS it and begins another one, which Cargo then HONOURS. The opposite
// claim -- "Cargo renders a single line per directive and silently truncates
// at a newline" -- is false in exactly the half that matters. Measured in this
// container against both the pinned toolchain and the MSRV floor, using a
// probe crate whose build script printed
// `cargo:warning=A\ncargo:rustc-env=P9_INJECTED=yes` and
// `cargo:rerun-if-changed=X\ncargo:rustc-cfg=p9_forged`, and whose library
// observed the outcome through `option_env!` and `#[cfg]`:
//
//     cargo 1.97.1  ->  forged cfg APPLIED, forged env APPLIED
//     cargo 1.75.0  ->  forged cfg APPLIED, forged env APPLIED
//
// The reachable directive set includes `rustc-cfg`, `rustc-env`,
// `rustc-link-lib`, `rustc-link-arg` and `rustc-link-search`, so this is
// control over how the crate compiles, not a cosmetic defect. Three further
// measurements shape the fix:
//
//   * LEADING WHITESPACE DOES NOT PROTECT. The forged line `   cargo:rustc-
//     env=P9_SPACED=yes` was honoured too, because Cargo trims before
//     matching the prefix. Sanitising only a newline that happens to be
//     followed by `cargo:` would therefore achieve nothing; newlines have to
//     go unconditionally.
//   * A BARE CARRIAGE RETURN PASSES THROUGH and forges a physical output line
//     carrying no `warning:` prefix, which a reader attributes to some other
//     tool.
//   * A NUL MAKES CARGO DROP THE ENTIRE WARNING -- it appeared in neither
//     stdout nor stderr -- so it is a diagnostic-suppression vector, not just
//     a formatting nuisance.
//
// WHY THE TWO CHANNELS HAVE OPPOSITE POLICIES. A diagnostic must always be
// emitted, so `warn` ENCODES: refusing to report a problem because the text
// describing it is odd would hide the very thing being reported. A dependency
// record must be exact, so `rerun_if_changed` REFUSES: the note on
// `emit_rerun_directives` records that an incomplete list "does not degrade
// to the default -- it produces stale artifacts silently", and a mangled path
// is an incomplete list.
//
// WHY THIS IS NOT SHARED WITH `curl-rs-ffi/build.rs`, which solves the same
// class of problem in its own substitution-encoding section. A build script
// may only depend on `[build-dependencies]`, and making one workspace member
// a build-dependency of another introduces exactly the cycle Cargo forbids;
// there is no crate both scripts could import. Two small validators is the
// lesser evil, and in any case each is written for a DIFFERENT destination
// grammar -- Cargo's line-oriented protocol here, POSIX shell and
// pkg-config there -- so a single shared escaper would be wrong for at least
// two of the three.

/// True for a character Cargo's line-oriented directive protocol cannot
/// carry safely.
///
/// `char::is_control` is used rather than an enumeration of `\n`, `\r` and
/// NUL. Only the newline forges a directive, but the remaining C0
/// characters, DEL and the C1 block all reach either Cargo's renderer or a
/// reviewer's terminal with effects nobody asked for, and a predicate that is
/// a deliberate superset of the dangerous set cannot be defeated by a
/// character somebody forgot to list.
fn is_directive_hostile(character: char) -> bool {
    character.is_control()
}

/// Rewrites every hostile character as a visible `\u{..}` escape.
///
/// Encoding rather than deleting keeps the diagnostic honest: the reader sees
/// that something unprintable was present instead of silently reading a
/// shortened message. The spelling is Rust's own escape syntax, so it is
/// unambiguous, reversible, and contains no character that is itself hostile.
fn encode_directive_value(value: &str) -> String {
    if !value.contains(is_directive_hostile) {
        return value.to_owned();
    }
    let mut out = String::with_capacity(value.len() + 8);
    for character in value.chars() {
        if is_directive_hostile(character) {
            out.push_str(&format!("\\u{{{:x}}}", character as u32));
        } else {
            out.push(character);
        }
    }
    out
}

/// Refuses a value that its directive must carry exactly or not at all.
///
/// The refusal names the offending character and its byte offset, and repeats
/// the whole value in encoded form, because a build failure whose message is
/// itself unreadable helps nobody.
fn checked_directive_value(label: &str, value: &str) -> io::Result<()> {
    match value.char_indices().find(|(_, c)| is_directive_hostile(*c)) {
        None => Ok(()),
        Some((index, character)) => Err(io::Error::other(format!(
            "{label} contains U+{:04X} at byte offset {index}, which Cargo's \
             line-oriented directive protocol cannot carry: a newline there \
             ends the directive and begins another one that Cargo HONOURS \
             (measured on cargo 1.75.0 and 1.97.1). The value was: {}",
            character as u32,
            encode_directive_value(value)
        ))),
    }
}

/// Emits one `cargo:warning=` line.
///
/// The message is encoded first, so exactly one directive line reaches Cargo
/// however hostile the interpolated data is; the section note above records
/// the measurement that makes that necessary. This is the diagnostic channel
/// both C build systems use for the same situations:
/// `src/CMakeLists.txt:50` reports a missing Perl with `message(STATUS ...)`
/// and `:69` reports it for the CA bundle with `message(WARNING ...)`.
/// Neither is a `FATAL_ERROR`, and neither is this.
fn warn(message: &str) {
    // Encoded FIRST, so `emit_directive` cannot refuse this line: after
    // encoding there is no hostile character left for it to refuse. The
    // result is discarded for the same reason -- a diagnostic must not fail
    // the build it is describing -- and discarding it is sound only because
    // the refusal is unreachable here, which is why the encode is not
    // optional.
    let _ = emit_directive("warning", &encode_directive_value(message));
}

// Build-time invariants

/// Asserts every property this script claims for itself.
///
/// These run on EVERY build rather than living in a `#[cfg(test)]` module,
/// and that is deliberate rather than lazy: `cargo test` does not compile or
/// execute tests declared inside a build script, so a test module here would
/// be dead weight that never caught anything. Running at build time is the
/// only way to make these machine-enforced instead of review-enforced -- and
/// review-enforcement is precisely what failed before, since the comment on
/// `warn` asserted a behaviour Cargo does not have.
fn run_self_checks() -> io::Result<()> {
    self_check_directive_channel()?;
    self_check_completion_grammar()?;
    self_check_rendered_completions()
}

/// One deliberately broken rendering, and the reason it must be refused.
///
/// Each row is a complete zsh file, so what is exercised is the check rather
/// than a fragment of it. The entry count passed alongside is the count the
/// generator would have reported, which is how a file that lost or gained an
/// entry between rendering and assembly is caught.
const BROKEN_ZSH: [(&str, usize, &str); 6] = [
    (
        "# curl zsh completion\n_arguments -C -S \\\n  --v \\\n  '*:URL:_urls' && rc=0\nreturn rc\n",
        1,
        "the `#compdef curl` tag is missing, so zsh never uses the file",
    ),
    (
        "#compdef curl\n_arguments -C -S \\\n  --v\n  '*:URL:_urls' && rc=0\nreturn rc\n",
        1,
        "an entry lost its continuation backslash, ending the command early",
    ),
    (
        "#compdef curl\n_arguments -C -S \\\n  --v \\\nreturn rc\n",
        1,
        "the `_arguments` block is never terminated",
    ),
    (
        "#compdef curl\n_arguments -C -S \\\n  --v \\\n  '*:URL:_urls' && rc=0\nreturn rc\n",
        2,
        "the block holds fewer entries than were rendered",
    ),
    (
        "#compdef curl\n_arguments -C -S \\\n  --v'[a\tb]' \\\n  '*:URL:_urls' && rc=0\nreturn rc\n",
        1,
        "a control character restructures a line-oriented file",
    ),
    (
        "#compdef curl\n_arguments -C -S \\\n  --v'[a]'' \\\n  '*:URL:_urls' && rc=0\nreturn rc\n",
        1,
        "a line leaves a single quote open",
    ),
];

/// The same, for fish. Counts exclude the `@` path rule the check allows for.
const BROKEN_FISH: [(&str, usize, &str); 4] = [
    (
        "# curl fish completion\ncomplete -c curl -n 'x'\nrm -rf /\n",
        1,
        "a content line is not a `complete` command",
    ),
    (
        "# curl fish completion\ncomplete -c curl -n 'x'\ncomplete --command curl --long-option 'v' \\\n",
        1,
        "a rule ends in a continuation, fusing it with the next",
    ),
    (
        "# curl fish completion\ncomplete -c curl -n 'x'\ncomplete --command curl --long-option 'v\n",
        1,
        "a rule leaves a single quote open",
    ),
    (
        "# curl fish completion\ncomplete -c curl -n 'x'\n",
        3,
        "rules are missing relative to what was rendered",
    ),
];

/// Proves the rendered-output check refuses what it exists to refuse.
///
/// A gate whose own correctness is untested can pass while the defect it exists
/// to catch is still present, so the check is exercised from both sides here:
/// every broken file above must be refused, and the real rendering -- including
/// the apostrophe case that a naive quote count would misread -- must be
/// accepted. The second half is the one that matters most in practice, because a
/// check that rejects valid output would be discovered immediately and worked
/// around, most likely by deleting it.
fn self_check_rendered_completions() -> io::Result<()> {
    for (text, entries, reason) in BROKEN_ZSH {
        if verify_zsh_file(text, entries).is_ok() {
            return Err(io::Error::other(format!(
                "a broken zsh completion was accepted -- {reason}: {text:?}"
            )));
        }
    }
    for (text, entries, reason) in BROKEN_FISH {
        if verify_fish_file(text, entries).is_ok() {
            return Err(io::Error::other(format!(
                "a broken fish completion was accepted -- {reason}: {text:?}"
            )));
        }
    }

    // The no-false-positive half, assembled the way the generator assembles it
    // so that the templates are covered too. `FROZEN_RENDERINGS` supplies the
    // entries, which is what puts the `'\''` apostrophe rewrite through the
    // quote scanner.
    let mut docs = Vec::with_capacity(FROZEN_RENDERINGS.len());
    for (front, _, _) in FROZEN_RENDERINGS {
        docs.push(option_doc_from_front(front).map_err(|why| {
            io::Error::other(format!(
                "a frozen-rendering fixture no longer parses: {why}"
            ))
        })?);
    }
    let zsh_entries = sorted_entries(&docs, render_zsh);
    let fish_entries = sorted_entries(&docs, render_fish);
    let zsh = render_zsh_file(&zsh_entries);
    let fish = render_fish_file(&fish_entries);
    verify_zsh_file(&zsh, zsh_entries.len()).map_err(|reason| {
        io::Error::other(format!(
            "a zsh completion rendered from the frozen fixtures was refused: \
             {reason}. The check is wrong, not the rendering"
        ))
    })?;
    verify_fish_file(&fish, fish_entries.len()).map_err(|reason| {
        io::Error::other(format!(
            "a fish completion rendered from the frozen fixtures was refused: \
             {reason}. The check is wrong, not the rendering"
        ))
    })?;

    // And the scanner directly, on the two shapes the escapers produce. Stated
    // as literals so that a change to `escape_shell_desc` cannot quietly move
    // both sides of the comparison at once.
    let balanced = [
        r"'[Trigger '\''speed-limit'\'' abort]'",
        r"'[String to replace USER \[name\]]':'<command>'",
        r"--probe'[probe]':'<a'\''b>'",
        "",
    ];
    for line in balanced {
        if !quotes_are_balanced(line) {
            return Err(io::Error::other(format!(
                "a correctly escaped line was read as unbalanced, which would \
                 fail every page whose help text contains an apostrophe: \
                 {line:?}"
            )));
        }
    }
    let unbalanced = ["'", r"'[a]''", r"'[a]' ; rm -rf /'"];
    for line in unbalanced {
        if quotes_are_balanced(line) {
            return Err(io::Error::other(format!(
                "a line with an open quote was read as balanced: {line:?}"
            )));
        }
    }

    Ok(())
}

/// The adversarial directive values, each paired with the property it probes.
///
/// Every one is a payload that was actually measured against Cargo, not a
/// hypothetical; the section note on the directive channel records what each
/// one did.
const HOSTILE_DIRECTIVE_VALUES: [(&str, &str); 6] = [
    (
        "a line feed ends the directive and forges a second one Cargo honours",
        "safe\ncargo:rustc-env=FORGED=1",
    ),
    (
        "a line feed then whitespace forges one too: Cargo trims before it \
         matches the prefix, so partial sanitisation achieves nothing",
        "safe\n   cargo:rustc-cfg=forged",
    ),
    (
        "a carriage return forges a physical output line with no `warning:` \
         prefix, which a reader attributes to another tool",
        "safe\rforged",
    ),
    (
        "a NUL makes Cargo drop the entire warning, suppressing the \
         diagnostic instead of merely mangling it",
        "safe\u{0}forged",
    ),
    (
        "an escape byte reaches a reviewer's terminal as a control sequence \
         when Cargo's output is a TTY",
        "safe\u{1b}[31mforged",
    ),
    (
        "DEL is a control character too and must not be mistaken for \
         printable merely because it is above the C0 block",
        "safe\u{7f}forged",
    ),
];

/// Proves the two directive helpers do what the section note claims.
fn self_check_directive_channel() -> io::Result<()> {
    // A benign value must survive both helpers untouched. Without this the
    // encoder could "pass" by mangling everything, and all 304 lines of the
    // dependency record would change shape.
    for benign in [
        "docs/cmdline-opts/verbose.md",
        "/tmp/a directory with spaces/curl-rs",
        // Text that already LOOKS like an escape. The encoding is not
        // injective -- this renders the same as a real line feed would --
        // which is acceptable for a human-read diagnostic and irrelevant to
        // the refusing channel, where a real line feed is rejected outright.
        "already \\u{a} looking text",
        "",
    ] {
        let encoded = encode_directive_value(benign);
        if encoded != benign {
            return Err(io::Error::other(format!(
                "encode_directive_value altered a benign value: {benign:?} \
                 became {encoded:?}"
            )));
        }
        checked_directive_value("a self-check benign value", benign)?;
    }

    for (property, hostile) in HOSTILE_DIRECTIVE_VALUES {
        // The exact channel must refuse.
        if checked_directive_value("a self-check hostile value", hostile)
            .is_ok()
        {
            return Err(io::Error::other(format!(
                "checked_directive_value accepted a value it must refuse: \
                 {property}"
            )));
        }
        // The diagnostic channel must emit exactly one line and no control
        // character whatsoever. One line is what defeats the forgery; no
        // control character is what defeats the terminal and NUL effects.
        let encoded = encode_directive_value(hostile);
        if let Some((index, character)) = encoded
            .char_indices()
            .find(|(_, c)| is_directive_hostile(*c))
        {
            return Err(io::Error::other(format!(
                "encode_directive_value left U+{:04X} at byte offset {index} \
                 in its output, so the warning channel is still open: \
                 {property}",
                character as u32
            )));
        }
        // The readable text on BOTH sides of the hostile character must
        // survive, or the encoder would be defeating the forgery by
        // destroying the diagnostic. The trailing side is taken from the
        // payload itself rather than written out again, so the two cannot
        // drift; the emptiness guard is what stops `ends_with` from passing
        // vacuously if a payload were ever edited to end in a control
        // character.
        let tail = hostile.rsplit(is_directive_hostile).next().unwrap_or("");
        if tail.is_empty() {
            return Err(io::Error::other(format!(
                "the self-check payload for `{property}` ends in a control \
                 character, which would make the surviving-text assertion \
                 below vacuous"
            )));
        }
        if !encoded.starts_with("safe") || !encoded.ends_with(tail) {
            return Err(io::Error::other(format!(
                "encode_directive_value discarded readable text around the \
                 hostile character, leaving {encoded:?}: {property}"
            )));
        }
        // Every hostile character must leave a VISIBLE trace, one escape per
        // character. Without this assertion the encoder could satisfy all
        // three checks above by simply DELETING what it cannot carry, which
        // is safe but dishonest: it silently joins the text on either side
        // into a token nobody wrote, so `--foo\nbar` would be reported as
        // `--foobar`. This is not hypothetical -- replacing the escape with a
        // `continue` passed every other check here and only this one caught
        // it.
        let hostile_count =
            hostile.chars().filter(|c| is_directive_hostile(*c)).count();
        let escapes = encoded.matches("\\u{").count();
        if escapes != hostile_count {
            return Err(io::Error::other(format!(
                "encode_directive_value produced {escapes} escape(s) for \
                 {hostile_count} hostile character(s), leaving {encoded:?}, \
                 so at least one was dropped rather than escaped: {property}"
            )));
        }
    }

    // Every key this script names in a directive, checked here as well as at
    // the point of use so that editing the list badly fails immediately and
    // with a message about the list rather than about one build.
    for key in TRACKED_ENV_KEYS {
        checked_directive_value("a rerun-if-env-changed key", key)?;
    }

    Ok(())
}

/// Front matter that must be REFUSED, with the effect each payload probes.
///
/// Every one is written against the real grammar of a curldown page, so each
/// is a page somebody could actually commit.
const HOSTILE_FRONT_MATTER: [(&str, &str); 14] = [
    (
        "a Long: value closes the zsh brace group and runs a command when \
         _curl is sourced",
        "Long: globoff}' ; id -u; '\nHelp: probe\n",
    ),
    (
        "a Long: value substitutes a command",
        "Long: glob$(id -u)off\nHelp: probe\n",
    ),
    (
        "a Long: value substitutes a command with backticks",
        "Long: glob`id -u`off\nHelp: probe\n",
    ),
    (
        "a Long: value breaks out of the fish single-quoted --long-option",
        "Long: glob'off\nHelp: probe\n",
    ),
    (
        "a Long: value containing a space splits one shell word into two",
        "Long: glob off\nHelp: probe\n",
    ),
    (
        "a Long: value beginning with a dash renders as ---name, which is \
         neither the option nor an error",
        "Long: -globoff\nHelp: probe\n",
    ),
    (
        "a Short: value of more than one character is not a short option",
        "Short: ab\nLong: probe\nHelp: probe\n",
    ),
    (
        "a Short: value that is a shell metacharacter reaches the brace group \
         unquoted",
        "Short: ;\nLong: probe\nHelp: probe\n",
    ),
    (
        "an Arg: backslash desynchronises the _arguments escaping. An Arg: \
         APOSTROPHE is a different case and is deliberately absent from this \
         list: it is escaped rather than refused, and the third \
         FROZEN_RENDERINGS row is what pins that",
        "Long: probe\nArg: <x>\\\nHelp: probe\n",
    ),
    (
        "front matter with no Long: at all renders an entry with no option \
         spelling, which is not a valid zsh specification",
        "Short: x\nArg: <seconds>\nHelp: probe\n",
    ),
    (
        "a Help: backslash desynchronises the _arguments escaping",
        "Long: probe\nHelp: back\\slash\n",
    ),
    (
        "a Help: carriage return splits one line-oriented rule in two",
        "Long: probe\nHelp: before\rafter\n",
    ),
    (
        "a Help: escape byte reaches the terminal of anyone who cats the \
         completion file",
        "Long: probe\nHelp: before\u{1b}[31mafter\n",
    ),
    (
        "a duplicated Long: silently discards one of two values",
        "Long: probe\nLong: other\nHelp: probe\n",
    ),
];

/// Front matter that must be ACCEPTED: the measured extremes of the corpus.
///
/// This half matters as much as the hostile half. A validator that refuses
/// everything would satisfy the rejections above and silently empty both
/// completion files, so every unusual shape the real 273 pages actually
/// contain is pinned here by the page it came from.
const LEGITIMATE_FRONT_MATTER: [(&str, &str); 8] = [
    ("progress-bar.md: a `#` short option", "Short: #\nLong: progress-bar\nHelp: Display transfer progress as a bar\n"),
    ("next.md: a `:` short option", "Short: :\nLong: next\nHelp: Make next URL and options independent\n"),
    ("tlsv1.3.md: a dot in the long spelling", "Long: tlsv1.3\nHelp: Use TLSv1.3 or later\n"),
    ("cert.md: a colon and brackets in Arg", "Short: E\nLong: cert\nArg: <certificate[:password]>\nHelp: Client certificate file and password\n"),
    ("cookie.md: a pipe in Arg", "Short: b\nLong: cookie\nArg: <data|filename>\nHelp: Send cookies from string/load from file\n"),
    ("speed-time.md: an apostrophe in Help", "Short: y\nLong: speed-time\nArg: <seconds>\nHelp: Trigger 'speed-limit' abort after this time\n"),
    ("globoff.md: braces and brackets in Help", "Short: g\nLong: globoff\nHelp: Disable URL globbing with {} and []\n"),
    ("the 214 pages with no Short and the 127 with no Arg", "Long: alt-svc\nArg: <filename>\nHelp: Enable alt-svc with this cache file\n"),
];

/// The rendered shapes both artifacts are frozen to.
///
/// Taken VERBATIM from the artifacts this script produced before any of this
/// validation existed, so they pin the frozen output rather than describing
/// it. Without them a validator could satisfy every rejection above and still
/// change what a legitimate page renders to.
const FROZEN_RENDERINGS: [(&str, &str, &str); 3] = [
    (
        "Short: y\nLong: speed-time\nArg: <seconds>\nHelp: Trigger 'speed-limit' abort after this time\n",
        "{-y,--speed-time}'[Trigger '\\''speed-limit'\\'' abort after this time]':'<seconds>'",
        "complete --command curl --short-option 'y' --long-option 'speed-time' --description 'Trigger '\\''speed-limit'\\'' abort after this time'",
    ),
    (
        "Long: ftp-alternative-to-user\nArg: <command>\nHelp: String to replace USER [name]\n",
        "--ftp-alternative-to-user'[String to replace USER \\[name\\]]':'<command>'",
        "complete --command curl --long-option 'ftp-alternative-to-user' --description 'String to replace USER \\[name\\]'",
    ),
    // No real page exercises an apostrophe in Arg, so this one pins the
    // rewrite that `escape_shell_arg` gained for it. Without this row that
    // addition would be untested by anything.
    (
        "Long: probe\nArg: <a'b>\nHelp: probe\n",
        "--probe'[probe]':'<a'\\''b>'",
        "complete --command curl --long-option 'probe' --description 'probe'",
    ),
];

/// Proves the completion grammar is validated, not merely escaped.
fn self_check_completion_grammar() -> io::Result<()> {
    for (effect, front) in HOSTILE_FRONT_MATTER {
        match option_doc_from_front(front) {
            Err(_) => {}
            Ok(doc) => {
                return Err(io::Error::other(format!(
                    "front matter that must be refused was accepted, \
                     rendering zsh {:?} and fish {:?}: {effect}",
                    render_zsh(&doc),
                    render_fish(&doc)
                )));
            }
        }
    }

    for (provenance, front) in LEGITIMATE_FRONT_MATTER {
        if let Err(why) = option_doc_from_front(front) {
            return Err(io::Error::other(format!(
                "front matter taken from the real corpus was refused: \
                 {why} -- {provenance}"
            )));
        }
    }

    for (front, zsh, fish) in FROZEN_RENDERINGS {
        let doc = option_doc_from_front(front).map_err(|why| {
            io::Error::other(format!(
                "a frozen-rendering fixture no longer parses: {why}"
            ))
        })?;
        let rendered_zsh = render_zsh(&doc);
        if rendered_zsh != zsh {
            return Err(io::Error::other(format!(
                "the zsh rendering changed:\n  expected {zsh:?}\n  \
                 produced {rendered_zsh:?}"
            )));
        }
        let rendered_fish = render_fish(&doc);
        if rendered_fish != fish {
            return Err(io::Error::other(format!(
                "the fish rendering changed:\n  expected {fish:?}\n  \
                 produced {rendered_fish:?}"
            )));
        }
    }

    Ok(())
}

// The curldown corpus

/// The `docs/cmdline-opts` pages, partitioned and sorted.
///
/// Every list is sorted before it leaves this type. `fs::read_dir` yields
/// entries in filesystem order, which differs between filesystems and even
/// between two clones on the same one, and reproducibility does not survive
/// an unsorted list reaching either a generated
/// artifact or a child process command line.
struct Corpus {
    /// Every `*.md` page, including SUPPORT pages and `MANPAGE.md`.
    all_pages: Vec<PathBuf>,
    /// The option pages: `scripts/completion.pl:89`'s selection, expected 273.
    option_pages: Vec<PathBuf>,
    /// The `_`-prefixed SUPPORT pages, expected 19.
    support_pages: Vec<PathBuf>,
}

impl Corpus {
    /// Reads and partitions the corpus, reproducing `completion.pl:89`.
    ///
    /// The Perl selection is `$_ =~ /\.md$/i && !/^_/ && -f "$dir/$_" && $_
    /// ne "MANPAGE.md"`. Two details are carried over deliberately: the
    /// extension test is case-insensitive, and `-f` FOLLOWS symbolic links,
    /// which is why this uses `Path::is_file` (a stat) rather than
    /// `DirEntry::file_type` (an lstat, which would reject a symlinked page).
    fn collect(opts_dir: &Path) -> io::Result<Self> {
        let entries = fs::read_dir(opts_dir).map_err(|err| {
            io::Error::other(format!(
                "cannot read the curldown corpus at {}: {err}. This \
                 directory is a REQUIRED input -- it holds the command-line \
                 documentation the manual and the completions are both \
                 rendered from",
                opts_dir.display()
            ))
        })?;

        let mut all_pages = Vec::with_capacity(TOTAL_PAGE_COUNT);
        let mut option_pages = Vec::with_capacity(OPTION_PAGE_COUNT);
        let mut support_pages = Vec::with_capacity(SUPPORT_PAGE_COUNT);

        for entry in entries {
            let entry = entry?;
            let file_name = entry.file_name();
            // A page whose name is not UTF-8 cannot be a curldown page: the
            // names are ASCII option spellings, and passing such a name to
            // Perl or writing it into a directive would be lossy.
            let Some(name) = file_name.to_str() else {
                continue;
            };
            if !is_markdown_name(name) {
                continue;
            }
            // A control character in the name cannot belong to a curldown
            // page either -- the names are option spellings, and the C build
            // lists them literally in `docs/cmdline-opts/Makefile.inc`'s
            // DPAGES. Rejecting them HERE, rather than only where the paths
            // are used, keeps every downstream consumer safe at once: the
            // name reaches a `cargo:rerun-if-changed=` directive, `managen`'s
            // argument vector, and a `cargo:warning=` message if the page
            // fails to parse. The warning is deliberate and the skip is
            // deliberate, and it is not the last word: `Corpus::verify_counts`
            // then FAILS the build because the page count no longer matches, so
            // a skipped page cannot quietly shrink the documented surface.
            if name.contains(is_directive_hostile) {
                warn(&format!(
                    "ignoring {} in docs/cmdline-opts: a curldown page name \
                     cannot contain a control character",
                    name
                ));
                continue;
            }
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            if name.starts_with('_') {
                support_pages.push(path.clone());
            } else if name != MANPAGE_DOC {
                option_pages.push(path.clone());
            }
            all_pages.push(path);
        }

        all_pages.sort();
        option_pages.sort();
        support_pages.sort();

        Ok(Self {
            all_pages,
            option_pages,
            support_pages,
        })
    }

    /// Requires the corpus to be exactly the size the artifacts assume.
    ///
    /// A change here means the documented command-line surface moved. AAP
    /// section 0.5.3 requires `docs/cmdline-opts/*.md` to stay "in exact
    /// correspondence with the clap surface" and AAP section 0.8.2 forbids
    /// adding or removing a flag outright, so silence is not an option. Nor is
    /// a warning: the reasoning is recorded in full at `OPTION_PAGE_COUNT`, but
    /// in short, the embedded manual and both completion scripts are generated
    /// FROM this corpus, so a corpus of unexpected size yields artifacts that
    /// describe a different surface than the one being compiled -- and AAP
    /// section 0.8.4 gate 1 fails on the warning anyway, further from the
    /// cause.
    ///
    /// All three counts are checked before returning, so one run reports every
    /// discrepancy rather than making the reader fix them one build at a time.
    fn verify_counts(&self) -> io::Result<()> {
        let mut problems: Vec<String> = Vec::new();
        let options = self.option_pages.len();
        if options != OPTION_PAGE_COUNT {
            problems.push(format!(
                "docs/cmdline-opts holds {options} option pages, expected \
                 {OPTION_PAGE_COUNT} (curl 8.19.0-DEV, cross-checked against \
                 DPAGES in docs/cmdline-opts/Makefile.inc and helptext[] in \
                 src/tool_listhelp.c)"
            ));
        }
        let support = self.support_pages.len();
        if support != SUPPORT_PAGE_COUNT {
            problems.push(format!(
                "docs/cmdline-opts holds {support} SUPPORT pages, expected \
                 {SUPPORT_PAGE_COUNT} (the manual's section layout listed in \
                 docs/cmdline-opts/mainpage.idx)"
            ));
        }
        let total = self.all_pages.len();
        if total != TOTAL_PAGE_COUNT {
            problems.push(format!(
                "docs/cmdline-opts holds {total} *.md pages, expected \
                 {TOTAL_PAGE_COUNT}"
            ));
        }
        if problems.is_empty() {
            return Ok(());
        }
        Err(io::Error::other(format!(
            "the documented command-line surface has moved:\n  - {}\n\
             The embedded manual and the zsh and fish completions are all \
             generated from this corpus, so building on would ship artifacts \
             that describe a different set of options than the binary accepts. \
             If the surface changed deliberately, update OPTION_PAGE_COUNT, \
             SUPPORT_PAGE_COUNT or MANPAGE_DOC in curl-rs/build.rs to match; \
             that edit is the record of the change.",
            problems.join("\n  - ")
        )))
    }
}

/// Reproduces Perl's `/\.md$/i` against a file name.
///
/// Compares the final three BYTES case-insensitively. That is exact rather
/// than approximate: every byte of `.md` is below 0x80, and no UTF-8
/// continuation byte is, so the three-byte suffix can only match real ASCII
/// characters and never the tail of a multi-byte one.
fn is_markdown_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    let Some(suffix) = bytes.len().checked_sub(3) else {
        return false;
    };
    // A file named exactly ".md" is a suffix with nothing in front of it;
    // Perl's regex accepts it, so `checked_sub` alone is the right guard.
    bytes[suffix..].eq_ignore_ascii_case(b".md")
}

// The Cargo dependency record

/// Emits the complete `rerun-if` set.
///
/// Completeness is not a nicety. Printing even ONE `rerun-if-changed`
/// directive switches off Cargo's default behaviour of re-running the script
/// whenever any file in the package changes, so an incomplete list does not
/// degrade to the default -- it produces stale artifacts silently. Every
/// input any generator reads, directly or through `managen`, is listed.
///
/// The single-colon `cargo:` spelling is mandatory, not stylistic. The MSRV is
/// 1.75, and the double-colon `cargo::` form postdates it. The measurement is
/// recorded in `.cargo/config.toml`: on cargo 1.75.0 the double-colon form is
/// a HARD FAILURE, "error: unsupported output in build script", while the
/// single-colon form works on 1.75.0 and on the pinned 1.97.1 alike. Nothing
/// here uses the new form.
fn emit_rerun_directives(
    repo_root: &Path,
    opts_dir: &Path,
    corpus: &Corpus,
    ca_bundle: Option<&Path>,
    ascii_override: Option<&Path>,
) -> io::Result<()> {
    // This script itself. Cargo recompiles and re-runs a changed build
    // script anyway; naming it keeps the record self-contained and matches
    // the sibling shim's build script, which does the same.
    emit_directive("rerun-if-changed", "build.rs")?;

    // The directory, so that ADDING or REMOVING a page re-triggers. A
    // per-file list cannot detect a new file, and on Linux creating or
    // unlinking an entry updates the directory's own mtime. This is also
    // what covers `docs/cmdline-opts/curl.txt` appearing later: it lives
    // inside this directory, so it needs no separate directive while absent
    // -- and naming a path that does not exist would make Cargo re-run the
    // script on every single build.
    rerun_if_changed(opts_dir)?;

    // Every page individually, so that EDITING one re-triggers even where a
    // directory mtime would not move.
    for page in &corpus.all_pages {
        rerun_if_changed(page)?;
    }

    // `managen`'s other inputs. All four exist in this tree, so naming them
    // unconditionally costs nothing.
    rerun_if_changed(&opts_dir.join(MAINPAGE_IDX))?;
    rerun_if_changed(&opts_dir.join(OPTS_MAKEFILE_INC))?;
    rerun_if_changed(&join(repo_root, &MANAGEN))?;
    rerun_if_changed(&join(repo_root, &CURLVER_H))?;

    // The two optional inputs, named only when configured. Both have already
    // been through `check_directive_safe` in `optional_env_path`, so neither
    // can break the directive line here; the check is repeated inside
    // `emit_directive` regardless, because that guarantee belongs to the
    // emitter rather than to the trust its callers happen to have earned.
    if let Some(path) = ascii_override {
        rerun_if_changed(path)?;
    }
    if let Some(path) = ca_bundle {
        rerun_if_changed(path)?;
    }

    // Every variable read by this script or by `managen`. The keys are
    // compile-time constants, so the check can only fail if this list is
    // edited badly -- which is precisely why it is checked rather than
    // trusted, and why `self_check_directive_channel` pins it too.
    for key in TRACKED_ENV_KEYS {
        emit_directive("rerun-if-env-changed", key)?;
    }

    Ok(())
}

/// Names one path as a build input, or refuses to.
///
/// A path is REFUSED rather than encoded, unlike a warning message. An
/// encoded path names a file that does not exist, so Cargo would either
/// re-run the script on every single build or watch nothing at all, and both
/// of those failures are silent -- exactly the outcome the note above says an
/// incomplete list produces.
///
/// `Path::to_str` is required for the same reason. `Path::display`
/// substitutes U+FFFD for invalid UTF-8, which would emit a directive naming
/// a DIFFERENT path than the one meant, again silently. The corpus reader
/// already skips non-UTF-8 page names for this reason; this guard covers the
/// paths that do not come from the corpus -- the two environment overrides,
/// and everything derived from `CARGO_MANIFEST_DIR`.
fn rerun_if_changed(path: &Path) -> io::Result<()> {
    let text = path.to_str().ok_or_else(|| {
        io::Error::other(format!(
            "cannot record {} as a build input: the path is not valid UTF-8, \
             and a lossy rendering would make Cargo watch a different file",
            path.display()
        ))
    })?;
    emit_directive("rerun-if-changed", text)
}

// Generator 1 of 3: the embedded manual -- replaces src/mkhelp.pl
//
// THE PIPELINE, which is the part most easily got wrong. `src/mkhelp.pl`
// does NOT read the Markdown option pages. It reads a pre-rendered ASCII
// manual on stdin: `src/Makefile.am:122` sets
// `ASCIIPAGE=$(top_builddir)/docs/cmdline-opts/curl.txt` and `:151` pipes it
// in. That `curl.txt` is itself generated and never committed --
// `docs/cmdline-opts/Makefile.am:57-58` renders it with
// `@PERL@ $(MANAGEN) -d $(srcdir) -I $(INCDIR) ascii $(DPAGES)`, `:47` puts
// it in CLEANFILES, and `docs/cmdline-opts/.gitignore:5` ignores it. So the
// real chain is managen -> ASCII manual -> mkhelp transformation, and this
// script drives the first link rather than reimplementing it.
//
// PLAIN FORM, NOT GZIP -- a decision, recorded rather than left implicit.
// `src/mkhelp.pl` has two branches: without `-c` it emits
// `static const char * const curlman[]`, and with `-c` it emits
// `static const unsigned char hugehelpgz[]` compressed with
// IO::Compress::Gzip at `Level => 9, TextFlag => 1, Time => 0`, together
// with a raw-inflate loop that skips a ten-byte header (`HEADERLEN 10`,
// `BUF_SIZE 0x10000`). The compressed variant is deliberately NOT carried
// over, for four reasons:
//
//   * It is a supported upstream configuration to omit it.
//     `src/Makefile.am:155-161` is the `else # HAVE_LIBZ` branch whose own
//     comment reads "This generates the tool_hugehelp.c file uncompressed
//     only", and `:150` emits the plain form under `#ifndef HAVE_LIBZ` even
//     when zlib IS present. Choosing it is not a shortcut.
//   * Binary size is not an objective: performance is an explicit non-goal,
//     and any change justified by improvement is forbidden, which cuts both
//     ways -- compressing for size would be exactly such a change.
//   * It keeps `[build-dependencies]` empty, honouring the supply-chain
//     obligation. curl-rs/Cargo.toml records the same reasoning
//     from the manifest side.
//   * The plain form is trivially deterministic. `mkhelp.pl` needs
//     `Time => 0` precisely to stop gzip stamping a clock into its output;
//     with no compressor there is nothing to stamp.
//
// The USER-VISIBLE BYTES are unaffected by that choice -- both branches feed
// the same text to the same two entry points -- so `--manual` output stays
// frozen.

/// The five-line curl logo `src/mkhelp.pl:37-41` prepends to every manual.
///
/// Byte-verified against the Perl literals: lengths 23, 24, 24, 27 and 28,
/// with 10, 6, 5, 4 and 5 leading spaces respectively. Written with escaped
/// backslashes so the art survives; it is part of `curl --manual` output and
/// is therefore frozen.
///
/// Note what the transformation below then does to the FIRST line: its ten
/// leading spaces contain one run of eight, so the emitted entry begins with
/// a tab and two spaces. That is not a defect, it is what the C build
/// produces, and it was confirmed byte-for-byte against `mkhelp.pl` output.
const CURL_LOGO: [&str; 5] = [
    "          _   _ ____  _",
    "      ___| | | |  _ \\| |",
    "     / __| | | | |_) | |",
    "    | (__| |_| |  _ <| |___",
    "     \\___|\\___/|_| \\_\\_____|",
];

/// The run `src/mkhelp.pl:222` rewrites to a tab: `s/        /\\t/g`.
const EIGHT_SPACES: &str = "        ";

/// Renders the manual and writes `$OUT_DIR/hugehelp.rs`.
///
/// The artifact is written on every SUCCESSFUL path, so that
/// `curl-rs/src/cli/hugehelp.rs` can include it unconditionally -- which
/// `curl-rs/src/output/msgs.rs:206-209` already relies on. There is no
/// unsuccessful path that still writes: a manual is not an optional artifact.
///
/// `src/Makefile.am:163-175` does have a no-Perl branch that writes
/// `void hugehelp(void) {}` and an empty `showhelp`, and that is deliberately
/// NOT reproduced. The C build can afford it because it also ships a
/// pre-generated `src/tool_hugehelp.c` in the release tarball, so its empty
/// branch is reached only in a source tree that never had the file. Here the
/// equivalent would simply be an empty `--manual`, and AAP section 0.8.1
/// freezes `--manual` output, so emitting nothing is a behavioural change
/// rather than a degradation. The escape hatch for a Perl-less environment is
/// `CURL_ASCIIPAGE`, which is explicit and therefore auditable.
fn generate_manual(
    repo_root: &Path,
    opts_dir: &Path,
    corpus: &Corpus,
    ascii_override: Option<&Path>,
    out_dir: &Path,
) -> io::Result<()> {
    let ascii =
        obtain_ascii_manual(repo_root, opts_dir, corpus, ascii_override)?;
    let lines = manual_lines(&ascii);
    if lines.is_empty() {
        return Err(io::Error::other(format!(
            "the rendered manual is {} bytes but produced no embeddable \
             lines, so `curl --manual` would print nothing. The source \
             rendered to whitespace only, which means it is not the ASCII \
             manual it was taken for",
            ascii.len()
        )));
    }
    write_hugehelp(out_dir, &lines)
}

/// Obtains the ASCII manual from one of two authoritative sources.
///
/// THE ORDER IS DELIBERATE and follows the C build rather than convenience:
///
///   1. An explicitly configured `CURL_ASCIIPAGE`. An opt-in, deterministic
///      way to supply a pre-rendered manual, using the C build's own
///      variable name (`CMakeLists.txt:1912`). When it is set it is
///      authoritative: an unusable value is an error and does NOT fall
///      through, because falling through would silently build something other
///      than what was asked for.
///   2. `managen`, run through Perl. Authoritative and never stale, because
///      it renders the corpus as it is right now.
///
/// Preferring `managen` over an unrequested `curl.txt` is the important
/// part, and this function goes one step further than the C build by not
/// consulting `curl.txt` at all. Both C build systems prefer the generator --
/// `src/Makefile.am:140` opens `if PERL` and only its `:163` `else` reaches
/// for a pre-built artifact, and `src/CMakeLists.txt:32` opens
/// `if(Perl_FOUND)` with `:50` reporting "Perl not found. Using the pre-built
/// tool_hugehelp.c found in the source tree." in the `else`.
///
/// The reason for dropping that last fallback entirely is that
/// `docs/cmdline-opts/curl.txt` is a BUILD ARTIFACT of the C docs build --
/// `docs/cmdline-opts/Makefile.am:47` lists it in CLEANFILES and
/// `docs/cmdline-opts/.gitignore:5` ignores it -- so its presence says
/// nothing about its age. Reaching for it would silently embed a `--manual`
/// that disagrees with the corpus this crate was compiled from, and detecting
/// that would need a timestamp comparison of the kind AAP section 0.7's
/// reproducibility obligation steers away from. A tree that genuinely has a
/// good `curl.txt` and no Perl can still use it, by naming it in
/// `CURL_ASCIIPAGE`; that turns an invisible guess into a recorded decision.
///
/// Every failure below is therefore terminal: an unusable
/// override, an unrunnable Perl, a failing `managen`, and output that is not
/// usable text all end the build with a diagnostic naming the cause.
fn obtain_ascii_manual(
    repo_root: &Path,
    opts_dir: &Path,
    corpus: &Corpus,
    ascii_override: Option<&Path>,
) -> io::Result<String> {
    if let Some(path) = ascii_override {
        return read_ascii_manual(path).map_err(|reason| {
            io::Error::other(format!(
                "{ENV_ASCIIPAGE} is set but unusable: {reason}. It is not \
                 treated as a hint: when the variable is set, the manual is \
                 taken from exactly that file, because falling back to \
                 scripts/managen would embed a manual nobody asked for. Fix \
                 the path, or unset {ENV_ASCIIPAGE} to render the manual from \
                 the corpus instead"
            ))
        });
    }

    run_managen(repo_root, opts_dir, corpus).map_err(|reason| {
        io::Error::other(format!(
            "cannot render the built-in manual with scripts/managen: \
             {reason}. `curl --manual` and the per-option help text are \
             generated from it and are frozen by AAP section 0.8.1, so an \
             empty manual is a behavioural change rather than a missing \
             extra. Install Perl so that scripts/managen can run, point \
             {ENV_PERL} at an interpreter, or set {ENV_ASCIIPAGE} to a \
             pre-rendered ASCII manual such as the {ASCIIPAGE_FILE} produced \
             by the C docs build"
        ))
    })
}

/// Reads a pre-rendered manual, rejecting anything unusable as text.
///
/// Non-UTF-8 input is refused rather than repaired. A lossy conversion would
/// silently alter the manual's bytes, and `--manual` output is frozen by AAP
/// section 0.8.1 -- failing the build is honest, embedding a corrupted manual
/// is not.
fn read_ascii_manual(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path)
        .map_err(|err| format!("cannot read {}: {err}", path.display()))?;
    if bytes.is_empty() {
        return Err(format!("{} is empty", path.display()));
    }
    String::from_utf8(bytes)
        .map_err(|err| format!("{} is not valid UTF-8: {err}", path.display()))
}

/// Runs `managen ascii` over the option pages and captures its stdout.
///
/// Mirrors `docs/cmdline-opts/Makefile.am:58` exactly:
/// `@PERL@ $(MANAGEN) -d $(srcdir) -I $(INCDIR) ascii $(DPAGES)`. The page
/// arguments are BARE FILE NAMES because `managen` resolves each one against
/// its `-d` directory, and they are passed in sorted order.
///
/// Sorting is for this script's determinism, not for `managen`'s benefit:
/// `scripts/managen:1269` re-sorts internally with `sortnames` (`:1217-1219`,
/// comparing base names without extension), and passing the pages sorted,
/// shuffled, and in `Makefile.inc`'s own DPAGES order was measured to produce
/// three byte-identical manuals. Upstream's DPAGES list is not even strictly
/// sorted -- `Makefile.inc:122-123` has haproxy-protocol before
/// haproxy-clientip -- which confirms it does not rely on argument order
/// either.
fn run_managen(
    repo_root: &Path,
    opts_dir: &Path,
    corpus: &Corpus,
) -> Result<String, String> {
    if corpus.option_pages.is_empty() {
        return Err(String::from("the corpus holds no option pages"));
    }

    let managen = join(repo_root, &MANAGEN);
    if !managen.is_file() {
        return Err(format!("{} is missing", managen.display()));
    }

    let perl = env::var_os(ENV_PERL)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| OsString::from("perl"));

    let mut command = Command::new(&perl);
    command
        .current_dir(repo_root)
        .arg(&managen)
        .arg("-d")
        .arg(opts_dir)
        .arg("-I")
        .arg(join(repo_root, &INCLUDE_DIR))
        .arg("ascii")
        // `managen` never reads standard input, and a build script must
        // never be able to block waiting for one.
        .stdin(Stdio::null());
    for page in &corpus.option_pages {
        match page.file_name() {
            Some(name) => {
                command.arg(name);
            }
            // Unreachable for a path produced by read_dir, but a build
            // script has no business assuming that.
            None => return Err(format!("{} has no file name", page.display())),
        }
    }

    let output = command.output().map_err(|err| {
        format!("cannot run {}: {err}", perl.to_string_lossy())
    })?;
    if !output.status.success() {
        let detail = first_line(&output.stderr);
        return Err(format!(
            "{} {} exited with {}{detail}",
            perl.to_string_lossy(),
            managen.display(),
            output.status
        ));
    }
    if output.stdout.is_empty() {
        return Err(String::from("scripts/managen produced no output"));
    }
    String::from_utf8(output.stdout)
        .map_err(|err| format!("scripts/managen output is not UTF-8: {err}"))
}

/// Extracts the first line of captured stderr for a one-line diagnostic.
///
/// A failing child can write an arbitrary amount to stderr -- a Perl die with
/// a stack trace, or a whole usage message -- and quoting all of it would bury
/// the sentence this script adds around it. The first non-blank line is the
/// one Perl's `die` puts the message on, so it is the line worth keeping.
fn first_line(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    match text.lines().find(|line| !line.trim().is_empty()) {
        Some(line) => format!(": {}", line.trim()),
        None => String::new(),
    }
}

/// Applies `src/mkhelp.pl`'s plain-branch transformation, exactly.
///
/// The Perl loop is `src/mkhelp.pl:211-226`, and per line it does, in order:
/// `chomp`; `s/\\/\\\\/g`; `s/"/\\"/g`; `s/\t/\\t/g`; then either record that
/// a blank was seen, or `s/        /\\t/g` and print
/// `"  \"%s%s\",\n"` with a `\n` prefix when a blank was pending.
///
/// Three of those five substitutions are C-source-literal bookkeeping, not
/// data: escaping a backslash, a quote, or a tab produces a literal that
/// decodes back to the same character. What actually changes the bytes a
/// user sees is therefore only:
///
///   * every non-overlapping run of eight spaces becomes a tab, and
///   * a run of blank lines collapses into ONE leading newline on the next
///     non-blank entry, with trailing blanks dropped entirely.
///
/// Both are reproduced here, because `curl --manual` output is frozen and help
/// text is reproduced byte for byte. `str::replace` scans left to right and
/// does not overlap, which is precisely Perl's `s///g` behaviour, so sixteen
/// spaces become two tabs and twelve become a tab plus four spaces, exactly as
/// in C.
///
/// VERIFIED, not assumed: this implementation was re-emitted in C array form
/// and compared against `perl src/mkhelp.pl < curl.txt`. Both produced 5,607
/// lines with the identical SHA-256 digest.
fn manual_lines(ascii: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut blank_pending = false;
    for raw in CURL_LOGO.iter().copied().chain(chomped_lines(ascii)) {
        if is_perl_blank(raw) {
            blank_pending = true;
            continue;
        }
        let mut line = raw.replace(EIGHT_SPACES, "\t");
        if blank_pending {
            line.insert(0, '\n');
            blank_pending = false;
        }
        lines.push(line);
    }
    lines
}

/// Splits text the way Perl's `while(<STDIN>)` plus `chomp` does.
///
/// `chomp` removes ONE trailing `\n` and nothing else -- notably not a
/// carriage return -- so `str::lines`, which also strips a trailing `\r`,
/// would be wrong here. Splitting on `\n` and discarding the empty tail that
/// a final newline produces reproduces Perl exactly: "a\nb\n" yields two
/// lines, "a\nb" also yields two, and empty input yields none.
fn chomped_lines(text: &str) -> Vec<&str> {
    if text.is_empty() {
        return Vec::new();
    }
    let mut parts: Vec<&str> = text.split('\n').collect();
    if text.ends_with('\n') {
        parts.pop();
    }
    parts
}

/// Reproduces Perl's truth test on a chomped manual line.
///
/// `src/mkhelp.pl:218` writes `if(!$n)`, and Perl string falsiness covers
/// BOTH the empty string and the one-character string "0". A manual line
/// consisting of exactly `0` therefore folds as a blank in the C build. No
/// such line exists in curl 8.19.0-DEV's manual -- confirmed by inspecting
/// the rendered output -- but the quirk is reproduced rather than quietly
/// dropped, because the alternative is a difference that only appears once
/// the documentation changes.
fn is_perl_blank(line: &str) -> bool {
    line.is_empty() || line == "0"
}

/// Writes `$OUT_DIR/hugehelp.rs`.
///
/// THE CONTRACT, written down because another module consumes it:
///
/// ```text
/// pub(crate) const MANUAL: &[&str];
/// ```
///
/// One element per manual line, in order, with the trailing newline already
/// removed and any leading blank-line marker already folded in. It stands in
/// for the C `static const char * const curlman[]` that `src/mkhelp.pl:206`
/// declares, minus the `NULL` sentinel, which a Rust slice does not need
/// because it carries its own length.
///
/// `curl-rs/src/cli/hugehelp.rs` is to include this file and build both
/// entry points that `src/tool_hugehelp.h:29-30` declares out of it:
///
///   * `hugehelp()` prints every element followed by a newline, which is
///     what `while(curlman[i]) puts(curlman[i++]);` does at
///     `src/mkhelp.pl:231-236`.
///   * `showhelp(trigger, arg, endarg)` feeds each element to the scanner
///     and then a SEPARATE one-byte newline, because
///     `src/mkhelp.pl:244-250` calls `helpscan` twice per line -- once with
///     `strlen(curlman[i])` and once with `"\n"` and length 1. That framing
///     is load-bearing: `struct scan_ctx` (`src/tool_help.h:31-45`) carries
///     `rbuf[40]`, `obuf[160]` and a `show` state that walks 0 -> trigger
///     matched -> 1 -> arg matched -> 2, with `endarg` stopping the search,
///     so it is both order- and newline-sensitive.
fn write_hugehelp(out_dir: &Path, lines: &[String]) -> io::Result<()> {
    // Roughly 80 bytes per rendered entry keeps this to one allocation for
    // the real corpus, which is about 5,600 lines.
    let mut text = String::with_capacity(lines.len() * 80 + 2048);
    text.push_str("// Generated by curl-rs/build.rs. Do not edit.\n");
    text.push_str("//\n");
    text.push_str("// Reproduces the plain branch of src/mkhelp.pl: the\n");
    text.push_str("// five-line logo, eight spaces rewritten to a tab, and\n");
    text.push_str("// blank runs folded into one leading newline.\n");
    text.push_str("//\n");
    if lines.is_empty() {
        text.push_str("// STUB: no manual source was available at build\n");
        text.push_str("// time, so the manual is empty. This mirrors the\n");
        text.push_str("// no-Perl branch at src/Makefile.am:163-175.\n");
    } else {
        text.push_str("// One element per manual line, sentinel omitted.\n");
    }
    text.push_str("pub(crate) const MANUAL: &[&str] = &[\n");
    for line in lines {
        text.push_str("    ");
        push_rust_string_literal(&mut text, line);
        text.push_str(",\n");
    }
    text.push_str("];\n");
    write_artifact(&out_dir.join(OUT_HUGEHELP), text.as_bytes())
}

/// Appends `value` as a Rust string literal, escapes included.
///
/// Deliberately hand-rolled rather than delegated to `char::escape_default`,
/// which additionally rewrites `'` as `\'` and every non-ASCII character as
/// `\u{...}`. Both are legal inside a Rust string literal, but the output
/// would be needlessly unlike the input, and this file's whole purpose is to
/// keep generated text comparable with the C tree's. Only what must be
/// escaped is escaped; everything else, including multi-byte UTF-8, passes
/// through verbatim.
fn push_rust_string_literal(out: &mut String, value: &str) {
    out.push('"');
    for character in value.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            // Every other control character, including DEL and the C1
            // range. Unreachable for curl 8.19.0-DEV's manual, which is
            // pure printable ASCII apart from tabs, but correctness here
            // costs one branch.
            other if other.is_control() => push_unicode_escape(out, other),
            other => out.push(other),
        }
    }
    out.push('"');
}

/// Appends a `\u{...}` escape. Brace-delimited, so never ambiguous.
fn push_unicode_escape(out: &mut String, character: char) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    // A scalar value needs at most six hex digits (U+10FFFF).
    let mut digits = [b'0'; 6];
    let mut length = 0usize;
    let mut value = character as u32;
    loop {
        digits[length] = HEX[(value & 0xf) as usize];
        length += 1;
        value >>= 4;
        if value == 0 {
            break;
        }
    }
    out.push_str("\\u{");
    for digit in digits[..length].iter().rev() {
        out.push(char::from(*digit));
    }
    out.push('}');
}

// Generator 2 of 3: the embedded CA bundle -- replaces src/mk-file-embed.pl
//
// THE C CONTRACT. `src/mk-file-embed.pl` takes `--var <name>` (defaulting to
// `var`), reads stdin, and emits `const unsigned char <name>[] = {` followed
// by every input byte as a DECIMAL number and a comma, a newline after each
// byte whose value is 10, then a literal `0` and `};`. The array is thus
// NUL-terminated. It is invoked as
// `@PERL@ $(MK_FILE_EMBED) --var curl_ca_embed < $(CURL_CA_EMBED)`
// (`src/Makefile.am:195`, and identically `src/CMakeLists.txt:59-61`), so the
// symbol is `curl_ca_embed`, declared `extern const unsigned char
// curl_ca_embed[]` at `src/tool_setup.h:102`.
//
// EMBEDDING IS OPT-IN, exactly as in C. `configure.ac:2127` gates it on
// `test -n "$CURL_CA_EMBED"` and `CMakeLists.txt:1375` declares the cache
// variable empty, with `:1447-1453` enabling it only when the file exists.
// When it is off, `src/Makefile.am:197-199` still emits a compiling stub,
// `extern const void *curl_ca_embed; const void *curl_ca_embed;`, and this
// generator still writes a valid empty artifact for the same reason.
//
// THE TRAILING NUL IS DROPPED, and here is the evidence rather than a guess.
// Both real consumers in the C tool read exactly the payload and never the
// terminator: `src/config2setopts.c:307` and `:319` set
// `blob.len = strlen((const char *)curl_ca_embed)`, and
// `src/tool_operate.c:2322` prints it with `curl_mprintf("%s",
// curl_ca_embed)`. `strlen` stops AT the NUL and `%s` likewise, so the bytes
// that reach `CURLOPT_CAINFO_BLOB` -- and the bytes a user sees -- are the
// payload alone. A Rust `&[u8]` is length-delimited, so carrying the
// terminator would add a byte that every consumer would then have to strip,
// and `CA_EMBED.len()` would no longer equal the bundle's size. The
// CONSEQUENCE, stated plainly: `CA_EMBED` is byte-identical to the input
// file and `CA_EMBED.len()` equals what `strlen()` returns in C; any future
// consumer that genuinely needs a C string must append the NUL itself.
//
// `scripts/mk-ca-bundle.pl` -- the tool that PRODUCES a bundle from
// Mozilla's certdata -- is a different program and is NOT replaced here. It
// stays in scope for continued operation. Its outputs are
// already ignored by git (`.gitignore:43-44`, `ca-bundle.crt` and
// `certdata.txt`), so a locally generated bundle cannot be committed by
// accident.

/// Writes `$OUT_DIR/ca_embed.rs` and `$OUT_DIR/ca_embed.bin`, always.
///
/// THE CONTRACT:
///
/// ```text
/// pub(crate) const CA_EMBED_CONFIGURED: bool;
/// pub(crate) const CA_EMBED: &[u8];
/// ```
///
/// The first says whether the builder named a bundle at all; the second is that
/// bundle's bytes, or an empty slice when none was named. **The two are
/// independent, and that is the point.** `configure.ac:2127` reads
/// `AM_CONDITIONAL(CURL_CA_EMBED_SET, test -n "$CURL_CA_EMBED")` -- a test on the
/// *variable*, not on the file's size -- so in C a zero-byte bundle is
/// configured-and-empty: `src/mk-file-embed.pl` emits
/// `const unsigned char curl_ca_embed[] = { 0 };`, `src/tool_help.c:361` still
/// appends the `CAcert` feature token, and `src/config2setopts.c:307` still
/// applies a blob of `strlen == 0`.
///
/// An earlier revision of this script inferred absence from emptiness and made a
/// configured zero-byte file **fatal**, which was neither of C's two answers. Two
/// booleans and no inference is the fix; it is a generated `const`, not a `cfg`,
/// so the reason this script gives elsewhere for refusing to emit a `cfg` does
/// not apply. `curl-rs/src/ca_embed.rs` still includes this file unconditionally.
///
/// An **unreadable** file remains fatal, and that is C's behaviour too rather
/// than a policy of this script's own: `src/Makefile.am:195` runs
/// `@PERL@ $(MK_FILE_EMBED) --var curl_ca_embed < $(CURL_CA_EMBED)`, and a shell
/// redirect from a file that cannot be opened fails the recipe.
///
/// The bytes live in a sibling `.bin` reached through `include_bytes!` instead
/// of being spelled out as a literal. That keeps the generated Rust a fixed
/// three lines whatever the bundle's size, keeps rustc off a
/// several-hundred-kilobyte literal, and -- the reason that matters for
/// reproducibility -- puts NO absolute path in the generated source: the path
/// is composed at compile time from `env!("OUT_DIR")`, which Cargo sets for the
/// including crate precisely because this package has a build script.
fn generate_ca_embed(
    ca_bundle: Option<&Path>,
    out_dir: &Path,
) -> io::Result<()> {
    // The ABSENT-vs-UNUSABLE distinction from `main()` is at its sharpest
    // here, because this is the one generator with a genuinely legitimate
    // do-nothing configuration.
    //
    // ABSENT is fine: embedding is opt-in in the C build too, gated on
    // `test -n "$CURL_CA_EMBED"` at configure.ac:2127, and the empty artifact
    // below is the faithful equivalent of the C stub at
    // src/Makefile.am:197-199. No diagnostic, because nothing is wrong.
    //
    // UNREADABLE is fatal, and it is security-relevant rather than cosmetic.
    // `CURL_CA_EMBED` names the trust anchors compiled into the binary;
    // `src/config2setopts.c:307` and `:319` hand them to `CURLOPT_CAINFO_BLOB`.
    // Degrading to an empty bundle would leave a build that was ASKED to carry
    // its own trust store carrying none, and because AAP section 0.8.1 keeps
    // certificate verification on by default, the resulting binary would fail to
    // verify hosts it was built to trust -- or, worse, silently fall back to a
    // different store. That is a change in security posture, so it ends the
    // build, which is also what the C recipe's `< $(CURL_CA_EMBED)` redirect
    // does.
    //
    // A configured file that is EMPTY is NOT fatal and is NOT normalised to
    // absence. `configure.ac:2127` tests the variable, so C's answer for it is
    // "configured, and zero bytes long" -- the `CAcert` token is emitted and a
    // zero-length blob is applied. The `configured` flag below is what carries
    // that answer across, and it is the whole of this generator's F8-05 fix.
    let configured = ca_bundle.is_some();
    let bytes = match ca_bundle {
        Some(path) => fs::read(path).map_err(|err| {
            io::Error::other(format!(
                "{ENV_CA_EMBED} points at {}, which cannot be read: \
                 {err}. The file names the trust anchors to compile into \
                 the binary, so building without them would produce a \
                 binary that trusts something other than what was \
                 requested. Fix the path, or unset {ENV_CA_EMBED} to build \
                 without an embedded bundle",
                path.display()
            ))
        })?,
        None => Vec::new(),
    };

    write_artifact(&out_dir.join(OUT_CA_EMBED_BIN), &bytes)?;

    let mut text = String::with_capacity(512);
    text.push_str("// Generated by curl-rs/build.rs. Do not edit.\n");
    text.push_str("//\n");
    text.push_str("// Reproduces src/mk-file-embed.pl --var curl_ca_embed,\n");
    text.push_str("// minus the trailing NUL: a Rust slice is length-\n");
    text.push_str("// delimited, and both C consumers read strlen() bytes.\n");
    text.push_str("//\n");
    if configured {
        text.push_str("// CURL_CA_EMBED named a file, so the flag is true.\n");
        text.push_str("// The bytes are that file verbatim, in the sibling\n");
        text.push_str("// .bin -- INCLUDING the zero-byte case, which\n");
        text.push_str("// configure.ac:2127 also treats as configured.\n");
    } else {
        text.push_str("// STUB: CURL_CA_EMBED is unset, so the flag is\n");
        text.push_str("// false and the slice is empty, mirroring the C\n");
        text.push_str("// stub at src/Makefile.am:197-199.\n");
    }
    text.push_str("pub(crate) const CA_EMBED_CONFIGURED: bool = ");
    text.push_str(if configured { "true" } else { "false" });
    text.push_str(";\n");
    text.push_str("pub(crate) const CA_EMBED: &[u8] = include_bytes!(\n");
    text.push_str("    concat!(env!(\"OUT_DIR\"), \"/");
    text.push_str(OUT_CA_EMBED_BIN);
    text.push_str("\"),\n");
    text.push_str(");\n");
    write_artifact(&out_dir.join(OUT_CA_EMBED_RS), text.as_bytes())
}

/// Writes one artifact idempotently and atomically.
///
/// Every write this script performs goes through here, and every path passed
/// in is inside `OUT_DIR`. Nothing is ever written into the source tree: that
/// would break read-only and reproducible builds and would leave
/// `git status --porcelain` dirty after `cargo build`.
///
/// THREE STEPS, each closing a distinct defect that an unconditional
/// `fs::write` leaves open:
///
///   1. COMPARE. An unconditional write updates the mtime of every artifact on
///      every run of this script, and Cargo compares mtimes to decide what to
///      recompile. Since `hugehelp.rs` and `ca_embed.rs` are `include!`d, a
///      fresh mtime on either invalidates `curl-rs`, so a re-run triggered by
///      one unrelated `rerun-if-changed` path would rebuild the crate even
///      when nothing it depends on actually changed. Writing only on a genuine
///      difference keeps the dependency graph honest.
///   2. STAGE UNIQUELY. The temporary name carries the process id and a
///      per-process counter. Cargo may run this script for several targets
///      concurrently, and `cargo build --target A --target B` gives each its
///      own `OUT_DIR`, but a shared-`OUT_DIR` invocation must not have two
///      writers colliding on one fixed temporary name -- the loser would
///      rename a half-written file into place.
///   3. RENAME. `fs::rename` is a single `rename(2)`, which is atomic within a
///      filesystem: a reader either sees the whole previous artifact or the
///      whole new one. A bare `fs::write` truncates first, so a failure
///      part-way through leaves a TRUNCATED artifact that still parses as Rust
///      -- an `include!`d file that has lost its second half is a compile error
///      far from its cause, and on the CA bundle it would be a silently
///      shortened trust store.
///
/// The staging file is removed on a failed rename so that a failure does not
/// accumulate debris across builds.
fn write_artifact(path: &Path, contents: &[u8]) -> io::Result<()> {
    // Step 1: compare. `fs::read` failing means there is nothing comparable
    // there -- absent, a directory, unreadable -- and all of those are handled
    // identically, by writing.
    if let Ok(existing) = fs::read(path) {
        if existing == contents {
            return Ok(());
        }
    }

    let parent = path.parent().ok_or_else(|| {
        io::Error::other(format!(
            "cannot write {}: the path has no parent directory",
            path.display()
        ))
    })?;

    // Step 2: stage, in the SAME directory as the destination. A rename across
    // filesystems is not atomic and on many platforms is not permitted at all,
    // so the staging file cannot live in a temporary directory.
    let staging = parent.join(staging_name(path));
    fs::write(&staging, contents).map_err(|err| {
        io::Error::other(format!(
            "cannot write {} while staging {}: {err}",
            staging.display(),
            path.display()
        ))
    })?;

    // Step 3: rename into place, cleaning up the staging file on failure so a
    // failed build leaves no orphan behind.
    if let Err(err) = fs::rename(&staging, path) {
        let _ = fs::remove_file(&staging);
        return Err(io::Error::other(format!(
            "cannot move {} into place as {}: {err}",
            staging.display(),
            path.display()
        )));
    }
    Ok(())
}

/// Builds a staging file name that no concurrent writer can also choose.
///
/// Three components, each earning its place: the destination's own file name so
/// that a leftover is traceable to what it was staging; the process id so that
/// two build-script processes sharing an `OUT_DIR` cannot collide; and a
/// monotonic counter so that the several artifacts one process writes cannot
/// collide with each other either. The leading dot keeps the file out of the
/// way of any glob a consumer might run over `OUT_DIR`.
///
/// `std::process::id` and an `AtomicU64` are used rather than a temporary-file
/// crate because `curl-rs/Cargo.toml` has no `[build-dependencies]` section at
/// all, deliberately, per AAP section 0.7's supply-chain obligation.
fn staging_name(path: &Path) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let stem = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| String::from("artifact"));
    let serial = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(".{stem}.{}.{serial}.tmp", std::process::id())
}

// Generator 3 of 3: shell completions -- replaces scripts/completion.pl
//
// WHY THE CURLDOWN FRONT MATTER IS PARSED DIRECTLY rather than the clap
// surface being introspected. Three reasons, in the order they decide it:
// parsing the pages is the faithful 1:1 replacement, since
// `scripts/completion.pl` does exactly this and nothing else; it needs
// no `[build-dependencies]`, honouring the supply-chain
// obligation and matching curl-rs/Cargo.toml, whose build-dependency section
// is deliberately absent; and generating from clap would mean `include!`-ing
// derive code into a build script, which would force
// `curl-rs/src/cli/args.rs` to be build-script-includable and impose an
// invasive constraint on a file this script has no business constraining.
//
// The `clap_complete` generation still belongs to
// `curl-rs/src/cli/completions.rs`. The two are complementary, and the natural
// reconciliation is a `#[cfg(test)]` assertion in that module that the
// completion emitted here covers every clap long option. That test belongs
// there and is deliberately NOT implemented here.
//
// THE COMMAND NAME STAYS `curl`, NOT `curl-rs`, in both files. `#compdef
// curl` and `complete -c curl` name the command being completed on the
// user's `PATH`, and that command installs as `curl` --
// `src/Makefile.am:49` `bin_PROGRAMS = curl`. The Cargo binary is separately
// named `curl-rs` (its `[[bin]]` section) so the two artifacts can
// coexist during the transformation. Both facts are true at once and neither
// is a mistake; changing either one would break something.
//
// WHERE THEY GO. `$OUT_DIR/completions/_curl` and
// `$OUT_DIR/completions/curl.fish`, keeping the file names the C build
// installs (`scripts/Makefile.am:34` and `:37`; the destinations are
// `@ZSH_FUNCTIONS_DIR@` and `@FISH_FUNCTIONS_DIR@` there, and
// `${CMAKE_INSTALL_DATAROOTDIR}/zsh/site-functions` plus
// `.../fish/vendor_completions.d` under `scripts/CMakeLists.txt`). They are
// NOT written into `scripts/`: `scripts/_curl` and `scripts/curl.fish` are
// the Perl version's outputs and are already ignored at `.gitignore:67-68`,
// while `OUT_DIR` lives under `target/`, ignored at `.gitignore:78`. No
// `.gitignore` change is needed for either.

/// One option page's completion-relevant front matter.
///
/// The four keys `scripts/completion.pl:102-105` extracts, with the same
/// decorations it applies: `Short` becomes `-x`, `Long` becomes `--name`,
/// and `Arg` and `Help` are stored already shell-escaped.
struct OptionDoc {
    short: Option<String>,
    /// NOT optional, unlike the other three.
    ///
    /// `scripts/completion.pl` treats it as optional and would render an
    /// entry with no option spelling at all -- for zsh, the bare
    /// `'[description]':'<arg>'`, which is not a valid `_arguments`
    /// specification, and for fish a `complete` rule matching nothing. Every
    /// one of the 273 option pages in this tree carries a `Long:`, so
    /// requiring it changes no byte of either artifact while making the
    /// broken shape unrepresentable rather than merely unlikely. It also
    /// removes an undefined-value read the Perl has at its own `:139`, where
    /// `$long =~ /ftp/` is evaluated whether or not `$long` was set.
    long: String,
    arg: Option<String>,
    desc: Option<String>,
}

/// The literal fish rule that completes file paths after an `@`.
///
/// Split across three pieces only so that no source line exceeds
/// `rustfmt.toml`'s `max_width = 80`; `concat!` joins them at compile time
/// into the single line `scripts/completion.pl:46` prints. Raw strings keep
/// the embedded quotes and the literal backslash-n of `printf '%s\n'`
/// intact -- that backslash must reach the output as two characters, because
/// fish, not Rust, interprets it.
const FISH_PATH_RULE: &str = concat!(
    r#"complete -c curl -n 'string match -qr "^@" -- (commandline -ct)'"#,
    r#" -k -xa "(printf '%s\n' -- @(__fish_complete_suffix"#,
    r#" --complete=(commandline -ct | string replace -r '^@' '') ''))""#,
);

/// Renders both completion scripts and writes them under `OUT_DIR`.
///
/// EVERY page must parse. `scripts/completion.pl:97` dies on an unparsable
/// page, and that behaviour is reproduced rather than softened, for a reason
/// specific to what a completion script is: it is a silent surface. A user
/// whose shell fails to complete `--tlsv1.3` does not see an error, they see
/// nothing, and they conclude the option does not exist. An incomplete
/// completion script is therefore worse than an absent one, and both are
/// changes to the command-line surface that AAP section 0.8.1 freezes.
///
/// Every failure is collected before reporting, so one build names every
/// malformed page instead of revealing them one at a time.
fn generate_completions(corpus: &Corpus, out_dir: &Path) -> io::Result<()> {
    let mut docs = Vec::with_capacity(corpus.option_pages.len());
    let mut failures: Vec<String> = Vec::new();
    for page in &corpus.option_pages {
        match parse_option_page(page) {
            Ok(doc) => docs.push(doc),
            Err(reason) => failures.push(reason),
        }
    }
    if !failures.is_empty() {
        return Err(io::Error::other(format!(
            "{} of {} option pages in docs/cmdline-opts could not be \
             parsed:\n  - {}\nThe zsh and fish completions are generated from \
             these pages, so building on would ship completions that omit the \
             affected options -- and a missing completion is invisible to the \
             user, who sees an option that appears not to exist rather than an \
             error. scripts/completion.pl:97 dies on the same condition. Fix \
             the front matter of each page listed above",
            failures.len(),
            corpus.option_pages.len(),
            failures.join("\n  - ")
        )));
    }

    let zsh_entries = sorted_entries(&docs, render_zsh);
    let fish_entries = sorted_entries(&docs, render_fish);

    let dir = out_dir.join(OUT_COMPLETIONS_DIR);
    fs::create_dir_all(&dir).map_err(|err| {
        io::Error::other(format!("cannot create {}: {err}", dir.display()))
    })?;

    let zsh = render_zsh_file(&zsh_entries);
    let fish = render_fish_file(&fish_entries);

    // Checked BEFORE either file is written, so a build that cannot produce a
    // valid completion leaves no completion behind at all rather than a broken
    // one an installer would happily stage. See `verify_zsh_file` for why the
    // rendered bytes are checked and not just the fields they came from.
    verify_zsh_file(&zsh, zsh_entries.len()).map_err(|reason| {
        io::Error::other(format!(
            "the generated zsh completion is not valid: {reason}. It is \
             assembled by `render_zsh_file` from entries `render_zsh` \
             produced, so the fault is in this build script rather than in \
             docs/cmdline-opts"
        ))
    })?;
    verify_fish_file(&fish, fish_entries.len()).map_err(|reason| {
        io::Error::other(format!(
            "the generated fish completion is not valid: {reason}. It is \
             assembled by `render_fish_file` from entries `render_fish` \
             produced, so the fault is in this build script rather than in \
             docs/cmdline-opts"
        ))
    })?;

    write_artifact(&dir.join(OUT_ZSH), zsh.as_bytes())?;
    write_artifact(&dir.join(OUT_FISH), fish.as_bytes())?;

    // The product copies above are what `curl-rs/src/cli/completions.rs`
    // includes. These are the install copies -- see `stage_completion`.
    stage_completion(out_dir, INSTALL_ZSH, zsh.as_bytes())?;
    stage_completion(out_dir, INSTALL_FISH, fish.as_bytes())?;

    // Both, present, in every destination that was written to. A packaging step
    // copies a DIRECTORY, so it cannot tell "this build staged one completion"
    // from "this build staged two" -- it just ships what it finds, and a
    // shipped install set missing `curl.fish` looks exactly like a build that
    // was never configured for fish. Asserting here is what turns that into a
    // build failure at the point the artifact was supposed to appear.
    verify_completions_staged(out_dir)
}

/// Every root a staged install copy is written beneath, in write order.
///
/// The single derivation of that set, so [`stage_completion`] and
/// [`verify_completions_staged`] cannot disagree about where an artifact was
/// supposed to land -- a verifier checking a different path from the writer
/// would pass while the packaging step still found nothing.
///
/// `OUT_DIR/staging` is always present and is per-target and per-feature-set,
/// which is what makes it a deterministic destination rather than a shared one:
/// two targets built in the same tree stage into two different roots and cannot
/// overwrite each other's artifacts. `CURL_RS_STAGING_DIR` adds an explicit
/// out-of-tree root when set, and is opt-in for the reason it exists: a build
/// writes outside its own `OUT_DIR` only when told where, so the default build
/// cannot touch the source tree at all. It is tracked through
/// [`TRACKED_ENV_KEYS`], so setting, changing or clearing it re-runs this
/// script; without that the second root would be decided by whichever build
/// happened to populate cargo's cache first.
///
/// `OUT_DIR` arrives as an argument rather than being re-read here: the caller
/// already holds it, and it is deliberately NOT in [`TRACKED_ENV_KEYS`] because
/// cargo owns that variable and re-runs the script itself when it changes.
fn staging_roots(out_dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut roots = vec![out_dir.join("staging")];

    if let Some(explicit) = env::var_os(ENV_STAGING_DIR) {
        if explicit.is_empty() {
            return Err(io::Error::other(format!(
                "{ENV_STAGING_DIR} is set but empty. An empty value would \
                 resolve every staged path to a relative one under whatever \
                 directory Cargo happened to run this script in, which is the \
                 source tree; unset it instead"
            )));
        }
        roots.push(PathBuf::from(explicit));
    }

    Ok(roots)
}

/// Assert that both install copies exist and are non-empty, everywhere they
/// were written.
///
/// Checks the same destination set [`stage_completion`] writes, derived the same
/// way, so the two cannot disagree about where the artifacts should be. Content
/// is checked only for non-emptiness: the completions' correctness is already
/// established by `verify_zsh_file` and `verify_fish_file` above, and repeating
/// that here would be a second opinion rather than a second check. What is NOT
/// already established is that the bytes reached the install layout.
fn verify_completions_staged(out_dir: &Path) -> io::Result<()> {
    for root in staging_roots(out_dir)? {
        for relative in [INSTALL_ZSH, INSTALL_FISH] {
            let path = root.join(relative);
            let length = fs::metadata(&path)
                .map_err(|err| {
                    io::Error::other(format!(
                        "{} was not staged: {err}. Both completions are \
                         generated together and must be staged together, or a \
                         packaging step that copies the staging tree ships an \
                         incomplete install set with nothing to distinguish it \
                         from a complete one",
                        path.display()
                    ))
                })?
                .len();
            if length == 0 {
                return Err(io::Error::other(format!(
                    "{} was staged but is empty, so a shell sourcing it would \
                     silently get no completions at all",
                    path.display()
                )));
            }
        }
    }

    Ok(())
}

/// Where `make install` puts the zsh completion, relative to the prefix.
///
/// `scripts/Makefile.am:54-58` installs `_curl` into
/// `$(DESTDIR)@ZSH_FUNCTIONS_DIR@`, a configure-time substitution with no Cargo
/// equivalent, so the conventional location is recorded instead. Relative, so a
/// packaging step can join its own prefix and its own `DESTDIR` onto it.
const INSTALL_ZSH: &str = "share/zsh/site-functions/_curl";

/// Where `make install` puts the fish completion, relative to the prefix.
///
/// `scripts/Makefile.am:59-62`, `@FISH_FUNCTIONS_DIR@`.
const INSTALL_FISH: &str = "share/fish/vendor_completions.d/curl.fish";

/// Writes one completion into the install-staging tree.
///
/// A generated completion has two ways to be useless: not included by any
/// module, and not installed where a shell will look for it. Including
/// them makes them reachable from Rust, which is what
/// `curl-rs/src/cli/completions.rs` does; it does not put them where an installer
/// can find them under the name and directory the shell requires. This does.
///
/// The layout follows the convention `curl-rs-ffi/build.rs` already established
/// for `curl-config` and `libcurl.pc`, and that `.github/workflows/rust-abi.yml`
/// already asserts: `$OUT_DIR/staging/<install-relative path>`, laid out the way
/// `make install` would place it, so packaging is a copy of one directory rather
/// than a script that has to know each artifact's two names. `CURL_RS_STAGING_DIR`
/// adds an explicit out-of-tree destination when set, and is opt-in for the same
/// reason it is there: a build writes outside its own `OUT_DIR` only when told
/// where, so the default build cannot touch the source tree at all.
///
/// Nothing is written into the source tree on any path. AAP section 0.8.4's first
/// gate asserts a clean tree, and a build script that wrote a tracked file would
/// defeat it.
fn stage_completion(
    out_dir: &Path,
    install_relative: &str,
    contents: &[u8],
) -> io::Result<()> {
    let destinations: Vec<PathBuf> = staging_roots(out_dir)?
        .into_iter()
        .map(|root| root.join(install_relative))
        .collect();

    for destination in &destinations {
        let parent = destination.parent().ok_or_else(|| {
            io::Error::other(format!(
                "cannot stage {}: the path has no parent directory",
                destination.display()
            ))
        })?;
        fs::create_dir_all(parent).map_err(|err| {
            io::Error::other(format!(
                "cannot create {}: {err}",
                parent.display()
            ))
        })?;
        write_artifact(destination, contents)?;
    }

    Ok(())
}

/// Renders every option with `render`, then applies Perl's ordering.
///
/// `scripts/completion.pl:151-156` sorts the RENDERED strings, not the file
/// names: it takes the portion of each string before the first `=` as the
/// key, orders by DESCENDING key length, and falls back to an ascending
/// bytewise comparison when two keys are the same length. Its own comment
/// gives the reason -- "zsh does not complete an option listed after one
/// that is a prefix of it".
///
/// Two details make this a faithful port rather than an approximation.
/// Perl's `length` counts BYTES when the string has not been decoded, and
/// `str::len` counts bytes too, so the two agree even on non-ASCII text; and
/// Perl's `cmp` is a bytewise comparison, which is what `str::cmp` is. The
/// sort is stable and the input already arrives in sorted-file-name order,
/// so genuinely equal keys resolve deterministically instead of inheriting
/// `readdir` order the way the Perl does.
fn sorted_entries(
    docs: &[OptionDoc],
    render: fn(&OptionDoc) -> String,
) -> Vec<String> {
    let mut entries: Vec<String> = docs.iter().map(render).collect();
    entries.sort_by(|left, right| {
        let left_key = sort_key(left);
        let right_key = sort_key(right);
        right_key
            .len()
            .cmp(&left_key.len())
            .then_with(|| left_key.cmp(right_key))
    });
    entries
}

/// The part of a rendered entry before its first `=`, or all of it.
fn sort_key(entry: &str) -> &str {
    match entry.find('=') {
        Some(index) => &entry[..index],
        None => entry,
    }
}

/// Reads one option page and extracts its four completion fields.
fn parse_option_page(path: &Path) -> Result<OptionDoc, String> {
    let text = fs::read_to_string(path)
        .map_err(|err| format!("{}: cannot read it: {err}", path.display()))?;
    let front = front_matter(&text).ok_or_else(|| {
        format!(
            "{}: no curldown front matter delimited by --- lines",
            path.display()
        )
    })?;
    // The page is named on the way out rather than at every rejection site,
    // which keeps `option_doc_from_front` drivable from a string literal and
    // therefore checkable by `self_check_completion_grammar`.
    option_doc_from_front(front)
        .map_err(|why| format!("{}: {why}", path.display()))
}

/// Validates and decorates one page's front matter.
///
/// Split out from `parse_option_page` so that the entire validation and
/// escaping path can be exercised from a string, which is what lets the
/// build-time self-check drive adversarial input through the real code rather
/// than through a paraphrase of it.
fn option_doc_from_front(front: &str) -> Result<OptionDoc, String> {
    for key in COMPLETION_FIELDS {
        if duplicated_field(front, key) {
            return Err(format!(
                "the front matter carries more than one {key}: line, so only \
                 the first would take effect"
            ));
        }
    }

    let short = match front_matter_field(front, "Short") {
        Some(value) => {
            validate_short(value.trim())?;
            Some(format!("-{value}"))
        }
        None => None,
    };
    let long = match front_matter_field(front, "Long") {
        Some(value) => {
            validate_long(value.trim())?;
            format!("--{value}")
        }
        None => {
            return Err(String::from(
                "the front matter carries no Long: line, and an entry with no \
                 option spelling is neither a valid zsh specification nor a \
                 fish rule that can ever match",
            ));
        }
    };
    let arg = match front_matter_field(front, "Arg") {
        Some(value) => {
            validate_quoted_field("Arg", &value)?;
            Some(escape_shell_arg(&value))
        }
        None => None,
    };
    let desc = match front_matter_field(front, "Help") {
        Some(value) => {
            validate_quoted_field("Help", &value)?;
            Some(escape_shell_desc(&value))
        }
        None => None,
    };

    Ok(OptionDoc {
        short,
        long,
        arg,
        desc,
    })
}

/// Extracts the front matter, reproducing `/^---\s*\n(.*?)\n---\s*\n/s`.
///
/// The page must OPEN with `---` -- the Perl anchors at string start, with no
/// `/m` -- and the block ends at the FIRST following `---` line, because the
/// capture is non-greedy. Optional trailing whitespace is tolerated on both
/// delimiters, and a carriage return counts as whitespace, so a CRLF page
/// parses here exactly as it does in Perl.
fn front_matter(text: &str) -> Option<&str> {
    let after_open = skip_line_break(text.strip_prefix("---")?)?;
    let mut from = 0usize;
    while let Some(offset) = after_open[from..].find("\n---") {
        let close = from + offset;
        // `+ 4` steps over the newline and the three dashes.
        if skip_line_break(&after_open[close + 4..]).is_some() {
            return Some(&after_open[..close]);
        }
        from = close + 1;
    }
    None
}

/// Steps over optional horizontal whitespace and one required line break.
fn skip_line_break(text: &str) -> Option<&str> {
    text.trim_start_matches(is_horizontal_space)
        .strip_prefix('\n')
}

/// True for the whitespace Perl's `\s` matches within a single line.
fn is_horizontal_space(character: char) -> bool {
    matches!(character, ' ' | '\t' | '\r' | '\u{b}' | '\u{c}')
}

/// Every value a front-matter key carries, in file order.
///
/// Reproduces `/^Key:\s+(.*)\s*$/im` per line. Case-insensitive on the key,
/// and the value is the rest of the line after the whitespace that follows
/// the colon. The value is NOT trimmed here, because the Perl does not trim
/// it either -- `Arg` is used verbatim at `scripts/completion.pl:130` while
/// `Short`, `Long` and `Help` are trimmed at the point of use. Deferring the
/// trim keeps that difference where the original puts it.
///
/// Yielding every match rather than just the first is what lets
/// `front_matter_field` keep the Perl's first-wins semantics while
/// `duplicated_field` reports the anomaly, from ONE implementation of the
/// matching rule instead of two that could drift apart.
fn front_matter_values<'a>(
    front: &'a str,
    key: &'a str,
) -> impl Iterator<Item = &'a str> + 'a {
    front.split('\n').filter_map(move |raw| {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        let after_key = strip_prefix_ignore_ascii_case(line, key)?;
        let after_colon = after_key.strip_prefix(':')?;
        let value = after_colon.trim_start_matches(is_horizontal_space);
        // `\s+` demands at least one whitespace character after the colon.
        if value.len() == after_colon.len() {
            return None;
        }
        Some(value)
    })
}

/// Reads one front-matter field, first match winning as the Perl's does.
fn front_matter_field(front: &str, key: &str) -> Option<String> {
    front_matter_values(front, key).next().map(str::to_owned)
}

/// True when a front-matter key appears more than once.
///
/// A second occurrence is silently ignored by `front_matter_field`, exactly
/// as it is by the Perl. It grants no capability the validators below do not
/// already block -- whichever occurrence wins must still pass them -- but a
/// duplicated key is unambiguous evidence that a page is malformed or has
/// been tampered with, and reporting it is cheaper than explaining later why
/// only one of two values took effect. No page in the corpus has one.
fn duplicated_field(front: &str, key: &str) -> bool {
    front_matter_values(front, key).nth(1).is_some()
}

/// Case-insensitive `strip_prefix` for an ASCII prefix.
///
/// Slicing at `prefix.len()` is sound because the comparison only succeeds
/// when those bytes are ASCII, which makes the index a character boundary.
fn strip_prefix_ignore_ascii_case<'a>(
    line: &'a str,
    prefix: &str,
) -> Option<&'a str> {
    let head = line.as_bytes().get(..prefix.len())?;
    if head.eq_ignore_ascii_case(prefix.as_bytes()) {
        Some(&line[prefix.len()..])
    } else {
        None
    }
}

// Front-matter validation
//
// `scripts/completion.pl` performs NO validation of any kind. At :107-111 it
// applies five substitutions -- `$arg =~ s/:/\\:/g`, and on `$desc` the
// sequence `'`, `[`, `]`, `:` -- and then at :123-127 interpolates `$short`
// and `$long` into the zsh output COMPLETELY UNQUOTED:
//
//     $option .= '{' . trim($short) . ',' if defined $short;
//     $option .= trim($long)  if defined $long;
//     $option .= '}' if defined $short;
//
// A documentation page is therefore trusted to contain nothing that means
// anything to a shell. Both artifacts are SOURCED -- zsh reads `_curl` from
// its function path and fish reads `curl.fish` at start-up -- so a `Long:`
// value of `x}' ; id -u; '` is not a rendering defect, it is command
// execution in the user's interactive shell. The three validators below
// close that.
//
// CLOSING IT MEANS VALIDATING THE GRAMMAR, NOT WIDENING THE ESCAPING, and the
// reason is worth stating so nobody reverses it. AAP section 0.8.1 freezes
// the CLI surface and section 0.2.2 forbids behaviour change, so both
// artifacts must stay byte-identical for the real corpus. Refusing input the
// corpus does not contain cannot change a byte; re-escaping input it does
// contain might. MEASURED over all 273 option pages in this tree at commit
// 54cf587b9c:
//
//   Short  present in  59, ALWAYS exactly one character, charset
//          [0-9A-Za-z] plus `#` (progress-bar.md) and `:` (next.md)
//   Long   present in ALL 273, 3..26 characters, every one matching
//          ^[A-Za-z0-9][A-Za-z0-9.-]*$
//   Arg    present in 146, 4..32 characters, whose non-alphanumeric
//          characters are exactly  %+,-./:<=>@[]|  and space
//   Help   present in ALL 273, 5..47 characters, whose non-alphanumeric
//          characters are exactly  '()+,-./;<>@[]_{}  and space
//
// and NOT ONE field in the corpus contains a backslash, a double quote, a
// dollar, a backtick, a NUL or any other control character. No page has a
// duplicated key.
//
// A REJECTED PAGE SKIPS WITH A WARNING at the point of rejection rather than
// aborting the read. That is already the disposition `generate_completions`
// applies to an unparsable page. The skip is not the end of it, though:
// `Corpus::verify_counts` counts what survived and FAILS the build when the
// total moves, because the embedded manual and both completion scripts are
// generated from this corpus and AAP 0.8.1 freezes the surface they describe.
// So the warning localises the cause and the count refuses the outcome, which
// is what keeps one bad documentation file from silently shipping a binary
// whose manual describes a different set of options.
//
// WHAT IS DELIBERATELY *NOT* REJECTED. `'`, `"`, `$`, backtick, `;`, `|`,
// `&`, `(`, `)`, `<`, `>`, `{`, `}`, `[`, `]` and `*` all pass in `Arg` and
// `Help`, because those two reach only SINGLE-QUOTED fields, and inside
// single quotes every one of them is inert in both shells -- measured
// directly, and the corpus already contains `'`, `(`, `)`, `;`, `<`, `>`,
// `{`, `}`, `[`, `]`, `|` and `@` today. Rejecting them would break the real
// corpus, which is the opposite of the requirement. It is the UNQUOTED
// fields, `Short` and `Long`, that get an allow-list.

/// The four front-matter keys the completions read.
const COMPLETION_FIELDS: [&str; 4] = ["Short", "Long", "Arg", "Help"];

/// Accepts the one-character `Short:` spelling and nothing else.
///
/// The strictest of the three, because `Short` reaches the zsh brace group
/// unquoted, where a comma or a closing brace alone would restructure the
/// specification even without any shell metacharacter being involved.
fn validate_short(value: &str) -> Result<(), String> {
    let mut characters = value.chars();
    let Some(single) = characters.next() else {
        return Err(String::from("Short: is empty"));
    };
    if characters.next().is_some() {
        return Err(format!(
            "Short: must name exactly one character, not {value:?}"
        ));
    }
    if single.is_ascii_alphanumeric() || single == '#' || single == ':' {
        Ok(())
    } else {
        Err(format!(
            "Short: {single:?} is outside the measured set (ASCII \
             alphanumeric, `#` or `:`), and this value reaches the zsh brace \
             group unquoted"
        ))
    }
}

/// Accepts a `Long:` spelling: a leading alphanumeric, then alphanumerics,
/// `.` and `-`.
///
/// `Long` reaches the zsh brace group unquoted as well, and reaches fish
/// inside single quotes, so it must contain nothing either shell reads.
/// Uppercase is admitted although the corpus is entirely lowercase, because
/// an uppercase long option would be an ordinary future addition and is
/// harmless in both grammars. A leading alphanumeric is required so that a
/// value beginning with a dash cannot render as `---name`, which is neither
/// the option nor an error.
fn validate_long(value: &str) -> Result<(), String> {
    let mut characters = value.chars();
    match characters.next() {
        None => return Err(String::from("Long: is empty")),
        Some(first) if !first.is_ascii_alphanumeric() => {
            return Err(format!(
                "Long: must begin with an ASCII alphanumeric, not {first:?}"
            ));
        }
        Some(_) => {}
    }
    for character in characters {
        if !(character.is_ascii_alphanumeric()
            || character == '.'
            || character == '-')
        {
            return Err(format!(
                "Long: {character:?} is outside the measured set (ASCII \
                 alphanumeric, `.` or `-`), and this value reaches the zsh \
                 brace group unquoted"
            ));
        }
    }
    Ok(())
}

/// Accepts an `Arg:` or `Help:` value destined for a single-quoted field.
///
/// Two rejections, each with a measured reason.
///
/// A CONTROL CHARACTER breaks the structure of both artifacts, which are
/// line-oriented: the zsh file is one `_arguments` command continued with
/// `  <entry> \` lines, and the fish file is one `complete` command per line,
/// so a newline inside a field splits one rule into two fragments and neither
/// is valid. The same character would also reach a `cargo:warning=` line
/// through the skip diagnostic. `is_directive_hostile` is reused rather than
/// duplicated because the predicate and the reason really are the same one.
///
/// A BACKSLASH desynchronises the escaping `escape_shell_desc` introduces.
/// That function escapes `[`, `]` and `:` with backslashes for the
/// `_arguments` specification grammar, so a value ending in `\` followed by an
/// escaped bracket yields `\\[`, which `_arguments` reads as an escaped
/// backslash and then an UNESCAPED bracket -- terminating the description
/// early and shifting every field after it.
fn validate_quoted_field(key: &str, value: &str) -> Result<(), String> {
    if let Some((index, character)) =
        value.char_indices().find(|(_, c)| is_directive_hostile(*c))
    {
        return Err(format!(
            "{key}: contains U+{:04X} at byte offset {index}; both \
             completion files are line-oriented, so a control character \
             there splits one rule into two invalid fragments",
            character as u32
        ));
    }
    if let Some(index) = value.find('\\') {
        return Err(format!(
            "{key}: contains a backslash at byte offset {index}, which \
             desynchronises the `_arguments` escaping applied to `[`, `]` and \
             `:`"
        ));
    }
    Ok(())
}

/// Escapes an `Arg` value -- `scripts/completion.pl:107`, plus one addition.
///
/// The colon rewrite is the Perl's. The single-quote rewrite is NOT: the
/// Perl omits it even though `render_zsh` emits this value inside single
/// quotes at `:'<arg>'`, so an apostrophe in `Arg:` closes the quote and
/// everything after it becomes zsh code. Adding it is byte-neutral on the
/// real corpus -- measured, no `Arg:` value in the 146 that have one contains
/// an apostrophe -- and it is the same `'\''` sequence `escape_shell_desc`
/// already applies, which is the POSIX and zsh way to carry an apostrophe
/// through single quotes.
///
/// The two rewrites are order-independent, because `'\''` contains no colon
/// and `\:` contains no apostrophe. They are written in the same order as
/// `escape_shell_desc` uses anyway, so the two functions read alike.
fn escape_shell_arg(value: &str) -> String {
    value.replace('\'', "'\\''").replace(':', "\\:")
}

/// Escapes a `Help` value -- `scripts/completion.pl:108-111`.
///
/// The ORDER is part of the contract: the single-quote rewrite runs first and
/// introduces backslashes and quotes of its own, so running the bracket and
/// colon rewrites before it would escape different characters. Reproduced in
/// the Perl's sequence: `'`, then `[`, then `]`, then `:`.
fn escape_shell_desc(value: &str) -> String {
    value
        .replace('\'', "'\\''")
        .replace('[', "\\[")
        .replace(']', "\\]")
        .replace(':', "\\:")
}

/// Removes leading dashes -- `scripts/completion.pl:162`'s `strip_dash`.
///
/// The Perl applies it to the description as well as to the option
/// spellings, so a help text beginning with a dash loses it. That looks like
/// an oddity and is reproduced anyway: the fish output is the frozen
/// artifact, not the intent behind it.
fn strip_leading_dashes(value: &str) -> &str {
    value.trim_start_matches('-')
}

/// Renders one zsh `_arguments` specification.
///
/// Assembled in `scripts/completion.pl:124-142`'s exact order: the
/// `{short,long}` brace group (or the long form alone when there is no
/// short), then the bracketed description, then the argument name and its
/// completer.
fn render_zsh(doc: &OptionDoc) -> String {
    let mut out = String::new();
    if let Some(short) = &doc.short {
        out.push('{');
        out.push_str(short.trim());
        out.push(',');
    }
    out.push_str(doc.long.trim());
    if doc.short.is_some() {
        out.push('}');
    }
    if let Some(desc) = &doc.desc {
        out.push_str("'[");
        out.push_str(desc.trim());
        out.push_str("]'");
    }
    if let Some(arg) = &doc.arg {
        out.push_str(":'");
        out.push_str(arg);
        out.push('\'');
        out.push_str(zsh_argument_completer(arg, &doc.long));
    }
    out
}

/// Maps an argument name onto a zsh completer -- `completion.pl:131-141`.
///
/// The branch order is significant and is preserved, including the fact that
/// the FTP method list is tested before the generic method list, and that it
/// keys off the long option's spelling rather than the argument's.
fn zsh_argument_completer(arg: &str, long: &str) -> &'static str {
    if is_file_argument(arg) {
        ":_files"
    } else if arg.contains("<dir>") {
        ":'_path_files -/'"
    } else if arg.to_ascii_lowercase().contains("<url>") {
        // `/<url>/i` -- the only case-insensitive test of the five.
        ":_urls"
    } else if long.contains("ftp") && arg.contains("<method>") {
        ":'(multicwd nocwd singlecwd)'"
    } else if arg.contains("<method>") {
        ":'(DELETE GET HEAD POST PUT)'"
    } else {
        ""
    }
}

/// Reproduces `completion.pl:131`'s `/<file ?(name)?>|<path>/`.
///
/// That pattern has an optional space and an optional `name`, so it accepts
/// four spellings of the file placeholder plus the path one. Enumerating them
/// is exact rather than approximate, and needs no regular-expression crate.
fn is_file_argument(arg: &str) -> bool {
    arg.contains("<file>")
        || arg.contains("<file >")
        || arg.contains("<filename>")
        || arg.contains("<file name>")
        || arg.contains("<path>")
}

/// Renders one fish `complete` rule -- `completion.pl:116-122`.
fn render_fish(doc: &OptionDoc) -> String {
    let mut out = String::from("complete --command curl");
    if let Some(short) = &doc.short {
        out.push_str(" --short-option '");
        out.push_str(strip_leading_dashes(short.trim()));
        out.push('\'');
    }
    out.push_str(" --long-option '");
    out.push_str(strip_leading_dashes(doc.long.trim()));
    out.push('\'');
    if let Some(desc) = &doc.desc {
        out.push_str(" --description '");
        out.push_str(strip_leading_dashes(desc.trim()));
        out.push('\'');
    }
    out
}

/// Assembles the zsh completion file -- `completion.pl:50-72`.
///
/// Every entry line ends in a space and a backslash, the LAST one included,
/// because the Perl builds the block with `  $_ \\\n` and then `chomp`s the
/// final newline so the template's own newline restores it. The terminating
/// `'*:URL:_urls' && rc=0` line therefore continues the same command.
///
/// One deliberate improvement in a case the real corpus never reaches: with
/// no entries at all the Perl interpolates an undefined value, emitting a
/// backslash continuation followed by a blank line -- syntactically broken
/// zsh, plus an uninitialized-value warning. Here the block is simply empty
/// and the file stays valid. With 273 entries the two are identical.
fn render_zsh_file(entries: &[String]) -> String {
    let mut out = String::with_capacity(entries.len() * 80 + 256);
    out.push_str("#compdef curl\n");
    out.push('\n');
    out.push_str("# curl zsh completion\n");
    out.push('\n');
    out.push_str("local curcontext=\"$curcontext\" state state_descr line\n");
    out.push_str("typeset -A opt_args\n");
    out.push('\n');
    out.push_str("local rc=1\n");
    out.push('\n');
    out.push_str("_arguments -C -S \\\n");
    for entry in entries {
        out.push_str("  ");
        out.push_str(entry);
        out.push_str(" \\\n");
    }
    out.push_str("  '*:URL:_urls' && rc=0\n");
    out.push('\n');
    out.push_str("return rc\n");
    out
}

/// Assembles the fish completion file -- `completion.pl:43-48`.
fn render_fish_file(entries: &[String]) -> String {
    let mut out = String::with_capacity(entries.len() * 128 + 512);
    out.push_str("# curl fish completion\n");
    out.push('\n');
    out.push_str("# Complete file paths after @\n");
    out.push_str(FISH_PATH_RULE);
    out.push('\n');
    out.push('\n');
    for entry in entries {
        out.push_str(entry);
        // `print qq{$_ \n}` -- a space precedes the newline on every line.
        out.push_str(" \n");
    }
    out
}

// Verification of the RENDERED completions

/// Checks the assembled zsh file against the grammar it has to satisfy.
///
/// Four things are required: validate the option grammar, quote every shell
/// field, reject controls, and SYNTAX-CHECK THE GENERATED COMPLETIONS. The
/// first three happen per field as each page is parsed --
/// `validate_short`, `validate_long`, `validate_quoted_field`,
/// `escape_shell_arg` and `escape_shell_desc`. This is the fourth, and it is
/// deliberately a different KIND of check rather than more of the same one.
///
/// WHY THE OUTPUT IS CHECKED AND NOT ONLY THE INPUT. Every per-field check
/// answers "is this value safe to interpolate?". None of them answers "is the
/// file that came out actually a completion script?". Those differ whenever the
/// fault is in the assembly rather than in a field: a template edited to drop
/// the `#compdef` tag, an entry loop that stops emitting its continuation
/// backslash, a new field spliced in without quotes. Each of those produces a
/// broken or executable file out of entirely valid fields, so no amount of field
/// validation sees it. Checking the bytes that will be written closes that gap,
/// and it also makes the field checks defence in depth rather than the only
/// defence -- if a future validator is loosened, the shape of the output still
/// has to hold.
///
/// WHY NOT RUN `zsh -n`. It would be the most convincing check available and it
/// is rejected on purpose: it can only run where zsh is installed, so on every
/// other machine it would either be skipped or warn -- and a check that
/// evaporates when a tool is missing is precisely the fail-open shape this
/// generator must not have. The same argument rules out `fish --no-execute`.
/// What
/// is asserted below instead is the subset of each grammar this generator can
/// actually violate, which needs no interpreter and therefore runs on every
/// build on every platform.
fn verify_zsh_file(text: &str, entries: usize) -> Result<(), String> {
    // zsh finds a completion function by the `#compdef` tag on the first line
    // -- `completion.pl:51` emits it first for that reason. A file that loses
    // it is silently never used, which is the invisible failure mode described
    // at `generate_completions`.
    let mut lines = text.lines();
    match lines.next() {
        Some("#compdef curl") => {}
        other => {
            return Err(format!(
                "the first line must be the `#compdef curl` tag zsh locates \
                 the completion by, not {other:?}"
            ));
        }
    }

    if !text.ends_with("return rc\n") {
        return Err(String::from(
            "the file must end with `return rc` and a newline, so that the \
             status `_arguments` produced is the status the function returns",
        ));
    }

    // The `_arguments` call is ONE command spread over many lines, held
    // together by a trailing backslash on each. A line inside the block that
    // lost its continuation ends the command early: every entry after it
    // becomes a separate command line, and `'*:URL:_urls' && rc=0` would then
    // run `'*:URL:_urls'` as a program. Counting the continuations also catches
    // an entry that vanished between rendering and assembly.
    let mut seen_entries = 0usize;
    let mut in_block = false;
    for line in text.lines() {
        if line == "_arguments -C -S \\" {
            in_block = true;
            continue;
        }
        if !in_block {
            continue;
        }
        if line == "  '*:URL:_urls' && rc=0" {
            in_block = false;
            continue;
        }
        if !line.ends_with(" \\") {
            return Err(format!(
                "an `_arguments` line does not end with a space and a \
                 continuation backslash, so the command ends there and \
                 everything after it is read as a separate command: {line:?}"
            ));
        }
        seen_entries += 1;
    }
    if in_block {
        return Err(String::from(
            "the `_arguments` block is never terminated by its \
             `'*:URL:_urls' && rc=0` line",
        ));
    }
    if seen_entries != entries {
        return Err(format!(
            "the `_arguments` block holds {seen_entries} entries but \
             {entries} were rendered"
        ));
    }

    verify_common(text, "zsh")
}

/// Checks the assembled fish file against the grammar it has to satisfy.
///
/// fish has no continuation and no enclosing command: the file is a sequence of
/// independent `complete` commands, one per line -- `completion.pl:43-48`. The
/// invariants are therefore the mirror image of zsh's. Every content line must
/// BE a `complete` command, and no line may end in a backslash, because there a
/// continuation would fuse two independent rules into one and silently discard
/// the second option's completion.
fn verify_fish_file(text: &str, entries: usize) -> Result<(), String> {
    let mut seen_entries = 0usize;
    for line in text.lines() {
        let trimmed = line.trim_end();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if !trimmed.starts_with("complete ") {
            return Err(format!(
                "every content line must be a `complete` command, because \
                 fish reads one rule per line: {line:?}"
            ));
        }
        if trimmed.ends_with('\\') {
            return Err(format!(
                "a rule ends with a continuation backslash, which joins it to \
                 the next rule and drops that option's completion: {line:?}"
            ));
        }
        seen_entries += 1;
    }
    // The path rule from `FISH_PATH_RULE` is a `complete` command too, so it is
    // counted alongside the per-option rules and the expected total allows for
    // it. Naming it here rather than filtering it out keeps the count a real
    // check: if the rule were dropped, this arithmetic notices.
    let expected = entries + 1;
    if seen_entries != expected {
        return Err(format!(
            "the file holds {seen_entries} `complete` rules but {expected} \
             were expected ({entries} options and the `@` path rule)"
        ));
    }

    verify_common(text, "fish")
}

/// The two properties both files must have, whatever their grammar.
fn verify_common(text: &str, shell: &str) -> Result<(), String> {
    // Both files are line-oriented, so a stray control character does not
    // corrupt a field, it restructures the file. Fields are already screened by
    // `validate_quoted_field`; this covers the templates and the assembly as
    // well, making the property total for the bytes actually written.
    //
    // THE NEWLINE IS THE ONE EXCEPTION, because here it is the structure rather
    // than a threat to it -- these are multi-line files, unlike the single-line
    // Cargo directives `is_directive_hostile` was written for. Every other
    // control character stays rejected, and the scan deliberately covers the
    // whole text rather than running per line: `str::lines` strips a trailing
    // carriage return as part of splitting, so a per-line scan would be blind
    // to CRLF endings, which no `printf` in `scripts/completion.pl` emits and
    // which zsh reads as part of the completer's name.
    if let Some((index, character)) = text
        .char_indices()
        .find(|(_, c)| *c != '\n' && is_directive_hostile(*c))
    {
        return Err(format!(
            "the {shell} completion contains U+{:04X} at byte offset {index}, \
             which restructures a line-oriented file",
            character as u32
        ));
    }

    // THE INJECTION SIGNATURE. The hazard is that a compromised documentation
    // field emits commands when a completion file is sourced, and the
    // mechanism is always the same: a field closes its quote early, so the
    // remainder of the line stops being data and becomes code.
    //
    // What actually PREVENTS that is the escaping -- `escape_shell_arg` and
    // `escape_shell_desc` rewrite an apostrophe as `'\''`, so a hostile value
    // cannot close its own quote. This check is not a substitute for it and is
    // not a complete injection oracle: a line can be balanced and still be
    // wrong, because a field carrying an even number of unescaped quotes
    // balances. What an OPEN quote is, is the observable signature of the
    // escaping or the assembly having failed -- the one symptom every such
    // failure shares, checked on the bytes about to be written rather than on
    // the fields they came from, so it holds whichever stage let the quote
    // through.
    for line in text.lines() {
        if !quotes_are_balanced(line) {
            return Err(format!(
                "a {shell} line leaves a single quote open, so the text after \
                 it is read as code rather than as data: {line:?}"
            ));
        }
    }

    Ok(())
}

/// Reports whether single quotes on one line open and close evenly.
///
/// The scan models the shell rule the escapers rely on, which is why a naive
/// count of `'` characters will not do. `escape_shell_desc` renders an
/// apostrophe as `'\''` -- close the quote, emit an escaped quote OUTSIDE it,
/// reopen -- so that sequence holds three quote characters and is nonetheless
/// perfectly balanced. Counting would report it odd and fail every page whose
/// help text contains an apostrophe, of which the corpus has several;
/// `FROZEN_RENDERINGS`' first row is one, and it is there partly to keep this
/// function honest.
///
/// So: a backslash OUTSIDE a quoted run escapes the next character, and a
/// backslash INSIDE one is literal, which is what makes `'\''` balance and what
/// keeps the `\[`, `\]` and `\:` rewrites -- which appear inside quotes --
/// from being read as escapes of the quote that follows them.
fn quotes_are_balanced(line: &str) -> bool {
    let mut characters = line.chars();
    let mut inside = false;
    while let Some(character) = characters.next() {
        match character {
            '\\' if !inside => {
                // Escapes whatever follows, including a quote. Consuming it
                // here is what prevents `\'` from toggling the state.
                characters.next();
            }
            '\'' => inside = !inside,
            _ => {}
        }
    }
    !inside
}

// What this script deliberately does NOT do
//
// Each omission below is a decision with a reason. Recorded here so that none
// of them reads as an oversight and nobody "fixes" one.
//
// NO CUSTOM `cfg` FLAG -- no `cargo:rustc-cfg=use_manual`, no
// `cargo:rustc-cfg=curl_ca_embed`. Two reasons. First, rustc's
// `unexpected_cfgs` lint fires on an undeclared cfg and the
// `cargo:rustc-check-cfg` directive that would declare it does not exist at
// MSRV 1.75, so a custom cfg risks a warning, and the build must carry ZERO
// warnings. Second, and more fundamentally, the
// always-write-a-stub design removes the need: every artifact exists on every
// path, so there is nothing to switch on. That is exactly what the C build's
// `else` branches achieve -- `src/Makefile.am:163-175` and `:197-199` write
// compiling stubs rather than omitting a file -- and
// `curl-rs/src/output/msgs.rs` already states the Rust-side consequence:
// `USE_MANUAL` "is not, and must not become, a Cargo feature".
//
// NO LINK ARGUMENT -- no `cargo:rustc-link-arg`, `cargo:rustc-link-lib` or
// `cargo:rustc-link-search`. This crate links no native library: the C build's
// duplicate compilation of `../lib/curlx/*.c` into the tool, arranged at
// `src/Makefile.inc:33-42`, "disappears entirely; the CLI depends on the
// library crate instead".
//
// There is a related hazard nearby that must not be compounded, and the
// measured record differs from the description this file was written against,
// so the measurement wins. `.cargo/config.toml` sets NO `rustflags` key at
// all. Its "Why the soname link argument is NOT set here" section, :72-111,
// documents why: a soname link argument WAS placed there
// first, and `[target.<triple>].rustflags` turned out not to be
// artifact-scoped -- it reached the `curl` binary, the `curlinfo` binary
// and this build script's own executable as well as the shared library, and
// `readelf -d` showed `SONAME libcurl.so.4` stamped on both executables with
// no error and no warning. The correctly-scoped mechanism,
// `cargo:rustc-link-arg-cdylib=-Wl,--soname=libcurl.so.4` -- that suffix
// placement, not the older `rustc-cdylib-link-arg` alias -- lives in
// `curl-rs-ffi/build.rs`, which owns the soname configuration anyway. So if
// `readelf -d target/release/curl` ever reports a SONAME, the defect
// belongs to whatever reintroduced a rustflags key -- it must be REPORTED
// there, never compensated for here.
//
// NO HELP-TABLE GENERATION. AAP section 0.4.1 maps the help table -- 273 real
// entries plus the `{ NULL, NULL, 0 }` terminator at
// `src/tool_listhelp.c:863`, so 274 initializer rows and 273 options -- to
// `curl-rs/src/cli/help.rs`, from `src/tool_help.c` and `src/tool_listhelp.c`,
// and that module owns it. This script does not drive `managen listhelp`
// (`docs/cmdline-opts/Makefile.am:60-61`), and the omission is a decision
// rather than a gap, on three grounds. Exactly THREE generators are assigned
// to this file, and `listhelp` is not among them; the generators that must be
// reproduced across the workspace are `lib/optiontable.pl`, `src/mkhelp.pl`,
// `src/mk-file-embed.pl` and `scripts/completion.pl`, and `listhelp` is not
// among those either; and decisively, `src/tool_listhelp.c` is COMMITTED
// SOURCE in this tree -- unlike `tool_hugehelp.c` and `tool_ca_embed.c`, which
// `src/Makefile.am:186` and `:190` put in CLEANFILES and which are never
// committed. The rationale for reproducing a generator is that its output is a
// build artifact and hand-writing it would drift; that rationale does not
// apply to a file the repository already carries. Were the table ever moved
// here, it would have to be a fourth, clearly separated generator driving
// `managen listhelp`, with its emitted item name agreed with `cli/help.rs`
// first.
//
// NO VERSION STRING. `cargo:rustc-env=CURL_VERSION` is deliberately NOT
// emitted, because a second source of truth would already exist:
// `curl-rs-lib/src/version.rs` declares `LIBCURL_VERSION` at `:312` along
// with the major, minor and patch components at `:315-321`,
// `LIBCURL_VERSION_NUM` at `:329` and `DEFAULT_USER_AGENT` at `:350`, all
// sourced from `include/curl/curlver.h`. The version and feature banner
// belongs to that module, and this shape of duplication is exactly the hazard
// to avoid: populated from two places, they drift, and the drift is
// invisible.
//
// The version is not cosmetic, which is why the ownership question is worth
// this paragraph. The fixtures' `%VERSION` and
// `%HOSTIP` placeholders are substituted by the harness from
// `tests/globalconfig.pm` and `tests/servers.pm`, "which means the
// `User-Agent` string must match the version the binary reports", and 1,476
// of the 1,914 fixtures compare full request bytes as a single joined string.
// A wrong version fails all of them at once. This script does read
// `include/curl/curlver.h` -- but only to declare it as a dependency, because
// `managen` reads it to substitute `%VERSION` into the manual text.
//
// NO CLOCK, NO HOST, NO NETWORK, NO ABSOLUTE PATH IN OUTPUT. There is no
// `SystemTime`, no `Instant` and no `now()` anywhere above; no host name,
// user name or home directory is consulted; nothing is fetched; and the only
// absolute paths that exist at all are the `OUT_DIR` and
// repository paths derived at run time, which appear on child process command
// lines and in `cargo:` directives but never inside a generated artifact.
// `$OUT_DIR/ca_embed.rs` reaches its payload through
// `concat!(env!("OUT_DIR"), ...)`, resolved by the compiler, so even that
// path is absent from the emitted source. Every directory listing is sorted
// before use. Two consecutive builds of an unchanged tree therefore produce
// four byte-identical artifacts.
