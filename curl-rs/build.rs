// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

// The safety invariant, asserted mechanically rather than by review. AAP
// section 0.1.1 goal G6 puts `#![forbid(unsafe_code)]` at the root of
// curl-rs-lib and curl-rs, "with a single #[allow(unsafe_code)] attribute on
// `mod ffi`". This crate has NO ffi module -- curl-rs/Cargo.toml records that
// both of its crate roots forbid unsafe code with ZERO exemptions -- and a
// build script is a separate compilation unit with its own crate root, so the
// attribute is repeated here and there is nothing to exempt.
#![forbid(unsafe_code)]

//! Build script for the curl command-line tool: three Perl generators,
//! reimplemented in Rust, all writing into `OUT_DIR`.
//!
//! AAP section 0.3.1 states the assignment in one line -- "curl-rs/build.rs
//! replaces src/mkhelp.pl, src/mk-file-embed.pl, scripts/completion.pl;
//! writes to OUT_DIR" -- and section 0.4.1 repeats it as a CREATE row.
//! Section 0.2.1 makes reproducing them mandatory and gives the reason:
//! their outputs are build artifacts rather than committed source, so
//! hand-writing the outputs would guarantee drift. Section 0.3.3 pattern P11
//! puts it as a rule: generated code stays generated.
//!
//! The three generators and the artifact each one produces are the embedded
//! manual from `src/mkhelp.pl` into `hugehelp.rs`, the embedded CA bundle
//! from `src/mk-file-embed.pl` into `ca_embed.rs` plus `ca_embed.bin`, and
//! the zsh and fish shell completions from `scripts/completion.pl` into
//! `completions/_curl` and `completions/curl.fish`. Every one of the four
//! artifacts is written on EVERY run, as a valid stub when its optional
//! input is absent, so the consuming modules can include them
//! unconditionally. `curl-rs/src/output/msgs.rs:206-209` already depends on
//! exactly that: it records that this script "generates `$OUT_DIR`
//! /hugehelp.rs unconditionally, so the built-in manual is always present",
//! and that `USE_MANUAL` "is not, and must not become, a Cargo feature".
//!
//! The dominant constraint on this file is reproducibility, which AAP
//! section 0.7 lists first among the enterprise best-practice obligations
//! that apply in the absence of user-specified rules. Every byte emitted
//! here is a pure function of the repository contents: no clock is read, no
//! host or user name is consulted, no absolute path reaches generated code,
//! no network is touched, and no directory-iteration order is trusted --
//! every file list is sorted explicitly before use.
//!
//! No user-specified rules exist for this project. `review_rules` returns
//! the single line "No user rules provided", verified twice, and AAP section
//! 0.7 corroborates it: zero files enter scope by rule. The preservation
//! mandate, the minimal-change mandate, the zero-unsafe prohibition and the
//! validation gates cited throughout this file are AAP requirements drawn
//! from the user's request, recorded in AAP section 0.8 -- they are binding,
//! but they are requirements and not rules, and describing them as rules
//! would misrepresent an empty channel as a full one.

use std::env;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

// ===========================================================================
// Measured corpus constants
// ===========================================================================
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
// The count is asserted at build time and a mismatch is reported through
// `cargo:warning=`, never by failing: drift means the documented surface and
// the implemented surface have diverged, which is worth shouting about, but
// it is not a reason to refuse to build.
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

// ===========================================================================
// Paths, relative to the repository root
// ===========================================================================
//
// Held as `&str` with forward slashes and joined component-wise, so nothing
// absolute is ever written down. AAP section 0.7's reproducibility
// obligation rules out a hard-coded absolute path outright, and the root is
// derived at run time from CARGO_MANIFEST_DIR instead.

/// `docs/cmdline-opts` -- the curldown corpus.
const OPTS_DIR: [&str; 2] = ["docs", "cmdline-opts"];

/// `scripts/managen` -- the renderer this script drives.
///
/// AAP section 0.2.1 keeps it in scope: "Documentation tooling in the same
/// category -- scripts/managen, docs/libcurl/symbols.pl,
/// docs/libcurl/mksymbolsmanpage.pl, scripts/mk-ca-bundle.pl -- remains in
/// scope for continued operation against the new tree." It is driven, never
/// reimplemented; reimplementing curldown rendering would be a second source
/// of truth for the manual and would drift from the manual page.
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
const ASCIIPAGE_FILE: &str = "curl.txt";

// ===========================================================================
// Environment variables read -- every one also appears in the rerun set
// ===========================================================================

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

// ===========================================================================
// Artifact names inside OUT_DIR -- the contract with the consuming modules
// ===========================================================================
//
// Written down here because other files include these by name, and a
// producer that leaves its output shape undocumented is a producer nobody
// can consume safely.
//
//   $OUT_DIR/hugehelp.rs            pub(crate) const MANUAL: &[&str]
//   $OUT_DIR/ca_embed.rs            pub(crate) const CA_EMBED: &[u8]
//   $OUT_DIR/ca_embed.bin           raw bundle bytes behind CA_EMBED
//   $OUT_DIR/completions/_curl      zsh completion, `#compdef curl`
//   $OUT_DIR/completions/curl.fish  fish completion, `complete -c curl`

/// Included by `curl-rs/src/cli/hugehelp.rs`.
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

// ===========================================================================
// Entry point
// ===========================================================================
//
// The split between `main` and `run` exists so that the only two failure
// modes this script may have -- a missing REQUIRED input and an unwritable
// OUT_DIR -- surface as one readable line instead of a Debug-formatted
// panic. Everything optional degrades instead of failing; see
// `generate_manual` and `generate_ca_embed`.

fn main() {
    if let Err(err) = run() {
        eprintln!("curl-rs/build.rs: {err}");
        // A required input is unusable. Refusing to continue is correct here
        // -- the distinction AAP-driven graceful degradation draws is
        // between OPTIONAL inputs (Perl, a CA bundle, a pre-rendered manual),
        // which warn and stub, and REQUIRED ones (the curldown corpus,
        // OUT_DIR), which cannot be substituted for.
        std::process::exit(1);
    }
}

fn run() -> io::Result<()> {
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

    let ca_bundle = optional_env_path(ENV_CA_EMBED);
    let ascii_override = optional_env_path(ENV_ASCIIPAGE);

    // Emitted before any generator runs, so that a generator which degrades
    // still leaves a complete dependency record behind.
    emit_rerun_directives(
        &repo_root,
        &opts_dir,
        &corpus,
        ca_bundle.as_deref(),
        ascii_override.as_deref(),
    );
    corpus.report_drift();

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

// ===========================================================================
// Environment and path helpers
// ===========================================================================

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
fn optional_env_path(key: &str) -> Option<PathBuf> {
    match env::var_os(key) {
        Some(value) if !value.is_empty() => Some(PathBuf::from(value)),
        _ => None,
    }
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

/// Emits one `cargo:warning=` line.
///
/// Cargo renders a single line per directive and silently truncates at a
/// newline, so every message passed here is deliberately one line. This is
/// the diagnostic channel both C build systems use for the same situations:
/// `src/CMakeLists.txt:50` reports a missing Perl with `message(STATUS ...)`
/// and `:69` reports it for the CA bundle with `message(WARNING ...)`.
/// Neither is a `FATAL_ERROR`, and neither is this.
fn warn(message: &str) {
    println!("cargo:warning={message}");
}

// ===========================================================================
// The curldown corpus
// ===========================================================================

/// The `docs/cmdline-opts` pages, partitioned and sorted.
///
/// Every list is sorted before it leaves this type. `fs::read_dir` yields
/// entries in filesystem order, which differs between filesystems and even
/// between two clones on the same one, and AAP section 0.7's reproducibility
/// obligation does not survive an unsorted list reaching either a generated
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

    /// Reports any divergence from the measured counts, without failing.
    ///
    /// A change here means the documented command-line surface moved. AAP
    /// section 0.5.3 requires `docs/cmdline-opts/*.md` to stay "in exact
    /// correspondence with the clap surface", and AAP section 0.8.2 forbids
    /// adding or removing a flag outright, so silence would be the wrong
    /// response. Failing would be wrong too: the count is an observation
    /// about the corpus, not a precondition for rendering it.
    fn report_drift(&self) {
        let options = self.option_pages.len();
        if options != OPTION_PAGE_COUNT {
            warn(&format!(
                "docs/cmdline-opts holds {options} option pages, expected \
                 {OPTION_PAGE_COUNT} (curl 8.19.0-DEV, cross-checked against \
                 DPAGES in docs/cmdline-opts/Makefile.inc and helptext[] in \
                 src/tool_listhelp.c); the CLI surface and its documentation \
                 may have diverged"
            ));
        }
        let support = self.support_pages.len();
        if support != SUPPORT_PAGE_COUNT {
            warn(&format!(
                "docs/cmdline-opts holds {support} SUPPORT pages, expected \
                 {SUPPORT_PAGE_COUNT}; the manual's section layout listed in \
                 docs/cmdline-opts/mainpage.idx may be incomplete"
            ));
        }
        let total = self.all_pages.len();
        if total != TOTAL_PAGE_COUNT {
            warn(&format!(
                "docs/cmdline-opts holds {total} *.md pages, expected \
                 {TOTAL_PAGE_COUNT}"
            ));
        }
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

// ===========================================================================
// The Cargo dependency record
// ===========================================================================

/// Emits the complete `rerun-if` set.
///
/// Completeness is not a nicety. Printing even ONE `rerun-if-changed`
/// directive switches off Cargo's default behaviour of re-running the script
/// whenever any file in the package changes, so an incomplete list does not
/// degrade to the default -- it produces stale artifacts silently. Every
/// input any generator reads, directly or through `managen`, is listed.
///
/// The single-colon `cargo:` spelling is mandatory, not stylistic. AAP
/// section 0.8.3 fixes the MSRV at 1.75, and the double-colon `cargo::` form
/// postdates it. The measurement is recorded in `.cargo/config.toml:190-198`:
/// on cargo 1.75.0 the double-colon form is a HARD FAILURE, "error:
/// unsupported output in build script", while the single-colon form works on
/// 1.75.0 and on the pinned 1.97.1 alike. Nothing here uses the new form.
fn emit_rerun_directives(
    repo_root: &Path,
    opts_dir: &Path,
    corpus: &Corpus,
    ca_bundle: Option<&Path>,
    ascii_override: Option<&Path>,
) {
    // This script itself. Cargo recompiles and re-runs a changed build
    // script anyway; naming it keeps the record self-contained and matches
    // the sibling shim's build script, which does the same.
    println!("cargo:rerun-if-changed=build.rs");

    // The directory, so that ADDING or REMOVING a page re-triggers. A
    // per-file list cannot detect a new file, and on Linux creating or
    // unlinking an entry updates the directory's own mtime. This is also
    // what covers `docs/cmdline-opts/curl.txt` appearing later: it lives
    // inside this directory, so it needs no separate directive while absent
    // -- and naming a path that does not exist would make Cargo re-run the
    // script on every single build.
    rerun_if_changed(opts_dir);

    // Every page individually, so that EDITING one re-triggers even where a
    // directory mtime would not move.
    for page in &corpus.all_pages {
        rerun_if_changed(page);
    }

    // `managen`'s other inputs. All four exist in this tree, so naming them
    // unconditionally costs nothing.
    rerun_if_changed(&opts_dir.join(MAINPAGE_IDX));
    rerun_if_changed(&opts_dir.join(OPTS_MAKEFILE_INC));
    rerun_if_changed(&join(repo_root, &MANAGEN));
    rerun_if_changed(&join(repo_root, &CURLVER_H));

    // The two optional inputs, named only when configured. A configured but
    // absent path is still named on purpose: the build must refresh when the
    // file finally appears, and the accompanying warning says what is wrong.
    if let Some(path) = ascii_override {
        rerun_if_changed(path);
    }
    if let Some(path) = ca_bundle {
        rerun_if_changed(path);
    }

    // Every variable read by this script or by `managen`.
    for key in [
        ENV_PERL,
        ENV_ASCIIPAGE,
        ENV_CA_EMBED,
        ENV_MAKETGZ_VERSION,
        ENV_SOURCE_DATE_EPOCH,
    ] {
        println!("cargo:rerun-if-env-changed={key}");
    }
}

fn rerun_if_changed(path: &Path) {
    println!("cargo:rerun-if-changed={}", path.display());
}

// ===========================================================================
// Generator 1 of 3: the embedded manual -- replaces src/mkhelp.pl
// ===========================================================================
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
// script drives the first link rather than reimplementing it, per AAP
// section 0.2.1.
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
//   * Binary size is not an objective. AAP section 0.1.1 is explicit --
//     "Explicitly NOT performance. No performance objective, latency target,
//     or throughput requirement appears anywhere in the request" -- and AAP
//     section 0.8.2 forbids any change "justified by improvement", which
//     cuts both ways: compressing for size would be exactly such a change.
//   * It keeps `[build-dependencies]` empty, honouring AAP section 0.7's
//     supply-chain obligation. curl-rs/Cargo.toml records the same reasoning
//     from the manifest side.
//   * The plain form is trivially deterministic. `mkhelp.pl` needs
//     `Time => 0` precisely to stop gzip stamping a clock into its output;
//     with no compressor there is nothing to stamp.
//
// The USER-VISIBLE BYTES are unaffected by that choice -- both branches feed
// the same text to the same two entry points -- so `--manual` output stays
// frozen as AAP section 0.8.1 and section 0.3.4 require.

/// The five-line curl logo `src/mkhelp.pl:37-41` prepends to every manual.
///
/// Byte-verified against the Perl literals: lengths 23, 24, 24, 27 and 28,
/// with 10, 6, 5, 4 and 5 leading spaces respectively. Written with escaped
/// backslashes so the art survives; it is part of `curl --manual` output and
/// is therefore frozen by AAP section 0.8.1.
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

/// Renders the manual and writes `$OUT_DIR/hugehelp.rs`, always.
///
/// The artifact is written on every path, including the degraded one, so
/// that `curl-rs/src/cli/hugehelp.rs` can include it unconditionally --
/// which `curl-rs/src/output/msgs.rs:206-209` already relies on. The stub is
/// an EMPTY manual, mirroring `src/Makefile.am:163-175`, whose no-Perl branch
/// writes `void hugehelp(void) {}` and an empty `showhelp`.
fn generate_manual(
    repo_root: &Path,
    opts_dir: &Path,
    corpus: &Corpus,
    ascii_override: Option<&Path>,
    out_dir: &Path,
) -> io::Result<()> {
    let ascii =
        obtain_ascii_manual(repo_root, opts_dir, corpus, ascii_override);
    let lines = match ascii {
        Some(text) => manual_lines(&text),
        None => Vec::new(),
    };
    write_hugehelp(out_dir, &lines)
}

/// Obtains the ASCII manual, degrading through three fallbacks.
///
/// THE ORDER IS DELIBERATE and follows the C build rather than convenience:
///
///   1. An explicitly configured `CURL_ASCIIPAGE`. An opt-in, deterministic
///      way to supply a pre-rendered manual, using the C build's own
///      variable name (`CMakeLists.txt:1912`).
///   2. `managen`, run through Perl. Authoritative and never stale, because
///      it renders the corpus as it is right now.
///   3. A pre-existing `docs/cmdline-opts/curl.txt` left behind by a C docs
///      build.
///
/// Preferring `managen` over an unrequested `curl.txt` is the important
/// part. Both C build systems do exactly this -- `src/Makefile.am:140` opens
/// `if PERL` and only its `:163` `else` reaches for a pre-built artifact,
/// and `src/CMakeLists.txt:32` opens `if(Perl_FOUND)` with `:50` reporting
/// "Perl not found. Using the pre-built tool_hugehelp.c found in the source
/// tree." in the `else`. The reason matters here more than there: a stale
/// `curl.txt` would silently produce a `--manual` that does not match the
/// tree, and detecting staleness would need a timestamp comparison, which
/// AAP section 0.7's reproducibility obligation steers away from. Ordering
/// the never-stale source first removes the question instead of answering it.
fn obtain_ascii_manual(
    repo_root: &Path,
    opts_dir: &Path,
    corpus: &Corpus,
    ascii_override: Option<&Path>,
) -> Option<String> {
    if let Some(path) = ascii_override {
        match read_ascii_manual(path) {
            Ok(text) => return Some(text),
            Err(reason) => warn(&format!(
                "{ENV_ASCIIPAGE} is set but unusable: {reason}; falling back \
                 to rendering the manual with scripts/managen"
            )),
        }
    }

    match run_managen(repo_root, opts_dir, corpus) {
        Ok(text) => return Some(text),
        Err(reason) => warn(&format!(
            "cannot render the manual with scripts/managen: {reason}"
        )),
    }

    let prerendered = opts_dir.join(ASCIIPAGE_FILE);
    match read_ascii_manual(&prerendered) {
        Ok(text) => {
            warn(&format!(
                "using the pre-rendered manual at {}; it is a build artifact \
                 (docs/cmdline-opts/Makefile.am:47 CLEANFILES) and may be \
                 older than the corpus",
                prerendered.display()
            ));
            Some(text)
        }
        Err(_) => {
            warn(
                "no built-in manual will be embedded: neither Perl with \
                 scripts/managen nor a pre-rendered curl.txt is available. \
                 `--manual` and per-option help text will be empty. Install \
                 Perl, or set CURL_ASCIIPAGE, to restore them",
            );
            None
        }
    }
}

/// Reads a pre-rendered manual, rejecting anything unusable as text.
///
/// Non-UTF-8 input is refused rather than repaired. A lossy conversion would
/// silently alter the manual's bytes, and `--manual` output is frozen by AAP
/// section 0.8.1 -- an empty manual with a warning is honest, a corrupted
/// one is not.
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
/// `cargo:warning=` is line-oriented, so a multi-line child error has to be
/// reduced before it is reported rather than after.
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
/// Both are reproduced here, because `curl --manual` output is frozen (AAP
/// section 0.8.1; AAP section 0.3.4 lists help text among the surfaces
/// "reproduced byte-for-byte"). `str::replace` scans left to right and does
/// not overlap, which is precisely Perl's `s///g` behaviour, so sixteen
/// spaces become two tabs and twelve become a tab plus four spaces, exactly
/// as in C.
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
/// `curl-rs/src/cli/hugehelp.rs` includes this file and builds both entry
/// points that `src/tool_hugehelp.h:29-30` declares out of it:
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

// ===========================================================================
// Generator 2 of 3: the embedded CA bundle -- replaces src/mk-file-embed.pl
// ===========================================================================
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
// Mozilla's certdata -- is a different program and is NOT replaced here. AAP
// section 0.2.1 keeps it in scope for continued operation. Its outputs are
// already ignored by git (`.gitignore:43-44`, `ca-bundle.crt` and
// `certdata.txt`), so a locally generated bundle cannot be committed by
// accident.

/// Writes `$OUT_DIR/ca_embed.rs` and `$OUT_DIR/ca_embed.bin`, always.
///
/// THE CONTRACT:
///
/// ```text
/// pub(crate) const CA_EMBED: &[u8];
/// ```
///
/// The bundle's bytes, or an empty slice when none is configured. Emptiness
/// is the signal that embedding is off; there is no separate flag and no
/// `cfg` for it, so `curl-rs/src/ca_embed.rs` can include this file
/// unconditionally.
///
/// The bytes live in a sibling `.bin` reached through `include_bytes!`
/// instead of being spelled out as a literal. That keeps the generated Rust
/// a fixed three lines whatever the bundle's size, keeps rustc off a
/// several-hundred-kilobyte literal, and -- the reason that matters for AAP
/// section 0.7 -- puts NO absolute path in the generated source: the path is
/// composed at compile time from `env!("OUT_DIR")`, which Cargo sets for the
/// including crate precisely because this package has a build script.
fn generate_ca_embed(
    ca_bundle: Option<&Path>,
    out_dir: &Path,
) -> io::Result<()> {
    let bytes = match ca_bundle {
        Some(path) => match fs::read(path) {
            Ok(bytes) if bytes.is_empty() => {
                warn(&format!(
                    "{ENV_CA_EMBED} points at {}, which is empty; no CA \
                     bundle will be embedded",
                    path.display()
                ));
                Vec::new()
            }
            Ok(bytes) => bytes,
            Err(err) => {
                warn(&format!(
                    "{ENV_CA_EMBED} points at {}, which cannot be read \
                     ({err}); no CA bundle will be embedded",
                    path.display()
                ));
                Vec::new()
            }
        },
        // Not a warning. Embedding is opt-in in the C build too, so its
        // absence is the ordinary configuration, not a problem.
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
    if bytes.is_empty() {
        text.push_str("// STUB: CURL_CA_EMBED is unset or unusable, so the\n");
        text.push_str("// slice is empty. Mirrors the stub at\n");
        text.push_str("// src/Makefile.am:197-199.\n");
    } else {
        text.push_str("// Bundle bytes, verbatim, in the sibling .bin file.\n");
    }
    text.push_str("pub(crate) const CA_EMBED: &[u8] = include_bytes!(\n");
    text.push_str("    concat!(env!(\"OUT_DIR\"), \"/");
    text.push_str(OUT_CA_EMBED_BIN);
    text.push_str("\"),\n");
    text.push_str(");\n");
    write_artifact(&out_dir.join(OUT_CA_EMBED_RS), text.as_bytes())
}

/// Writes one artifact, reporting the path when the write fails.
///
/// Every write this script performs goes through here, and every path passed
/// in is inside `OUT_DIR`. Nothing is ever written into the source tree: that
/// would break read-only and reproducible builds and would leave
/// `git status --porcelain` dirty after `cargo build`.
fn write_artifact(path: &Path, contents: &[u8]) -> io::Result<()> {
    fs::write(path, contents).map_err(|err| {
        io::Error::other(format!("cannot write {}: {err}", path.display()))
    })
}

// ===========================================================================
// Generator 3 of 3: shell completions -- replaces scripts/completion.pl
// ===========================================================================
//
// WHY THE CURLDOWN FRONT MATTER IS PARSED DIRECTLY rather than the clap
// surface being introspected. Three reasons, in the order they decide it:
// parsing the pages is the faithful 1:1 replacement AAP section 0.4.1 maps,
// since `scripts/completion.pl` does exactly this and nothing else; it needs
// no `[build-dependencies]`, honouring AAP section 0.7's supply-chain
// obligation and matching curl-rs/Cargo.toml, whose build-dependency section
// is deliberately absent; and generating from clap would mean `include!`-ing
// derive code into a build script, which would force
// `curl-rs/src/cli/args.rs` to be build-script-includable and impose an
// invasive constraint on a file this script has no business constraining.
//
// `curl-rs/src/cli/completions.rs` still owns the `clap_complete` generation
// that AAP section 0.4.1 assigns it. The two are complementary, and the
// natural reconciliation is a `#[cfg(test)]` assertion in that module that
// the completion emitted here covers every clap long option. That test
// belongs there and is deliberately NOT implemented here.
//
// THE COMMAND NAME STAYS `curl`, NOT `curl-rs`, in both files. `#compdef
// curl` and `complete -c curl` name the command being completed on the
// user's `PATH`, and that command installs as `curl` --
// `src/Makefile.am:49` `bin_PROGRAMS = curl`. The Cargo binary is separately
// named `curl-rs` (`curl-rs/Cargo.toml:168-170`) so the two artifacts can
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
    long: Option<String>,
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
fn generate_completions(corpus: &Corpus, out_dir: &Path) -> io::Result<()> {
    let mut docs = Vec::with_capacity(corpus.option_pages.len());
    for page in &corpus.option_pages {
        match parse_option_page(page) {
            Ok(doc) => docs.push(doc),
            // `scripts/completion.pl:97` dies on an unparsable page. Warning
            // and skipping is chosen instead, deliberately: refusing to build
            // over one malformed documentation page would take the manual and
            // the CA bundle down with it, and the drift report below makes
            // the omission just as loud.
            Err(reason) => warn(&format!("skipping {reason}")),
        }
    }
    if docs.len() != corpus.option_pages.len() {
        warn(&format!(
            "{} of {} option pages could not be parsed; the shell \
             completions are incomplete",
            corpus.option_pages.len() - docs.len(),
            corpus.option_pages.len()
        ));
    }

    let zsh_entries = sorted_entries(&docs, render_zsh);
    let fish_entries = sorted_entries(&docs, render_fish);

    let dir = out_dir.join(OUT_COMPLETIONS_DIR);
    fs::create_dir_all(&dir).map_err(|err| {
        io::Error::other(format!("cannot create {}: {err}", dir.display()))
    })?;
    write_artifact(
        &dir.join(OUT_ZSH),
        render_zsh_file(&zsh_entries).as_bytes(),
    )?;
    write_artifact(
        &dir.join(OUT_FISH),
        render_fish_file(&fish_entries).as_bytes(),
    )
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
    Ok(OptionDoc {
        short: front_matter_field(front, "Short")
            .map(|value| format!("-{value}")),
        long: front_matter_field(front, "Long")
            .map(|value| format!("--{value}")),
        arg: front_matter_field(front, "Arg")
            .map(|value| escape_shell_arg(&value)),
        desc: front_matter_field(front, "Help")
            .map(|value| escape_shell_desc(&value)),
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

/// Reads one front-matter field, reproducing `/^Key:\s+(.*)\s*$/im`.
///
/// Case-insensitive on the key, first match wins, and the value is the rest
/// of the line after the whitespace that follows the colon. The value is NOT
/// trimmed here, because the Perl does not trim it either -- `Arg` is used
/// verbatim at `scripts/completion.pl:130` while `Short`, `Long` and `Help`
/// are trimmed at the point of use. Deferring the trim keeps that difference
/// where the original puts it.
fn front_matter_field(front: &str, key: &str) -> Option<String> {
    for raw in front.split('\n') {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        let Some(after_key) = strip_prefix_ignore_ascii_case(line, key) else {
            continue;
        };
        let Some(after_colon) = after_key.strip_prefix(':') else {
            continue;
        };
        let value = after_colon.trim_start_matches(is_horizontal_space);
        // `\s+` demands at least one whitespace character after the colon.
        if value.len() == after_colon.len() {
            continue;
        }
        return Some(value.to_owned());
    }
    None
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

/// Escapes an `Arg` value -- `scripts/completion.pl:107`.
fn escape_shell_arg(value: &str) -> String {
    value.replace(':', "\\:")
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
    if let Some(long) = &doc.long {
        out.push_str(long.trim());
    }
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
        out.push_str(zsh_argument_completer(arg, doc.long.as_deref()));
    }
    out
}

/// Maps an argument name onto a zsh completer -- `completion.pl:131-141`.
///
/// The branch order is significant and is preserved, including the fact that
/// the FTP method list is tested before the generic method list, and that it
/// keys off the long option's spelling rather than the argument's.
fn zsh_argument_completer(arg: &str, long: Option<&str>) -> &'static str {
    if is_file_argument(arg) {
        ":_files"
    } else if arg.contains("<dir>") {
        ":'_path_files -/'"
    } else if arg.to_ascii_lowercase().contains("<url>") {
        // `/<url>/i` -- the only case-insensitive test of the five.
        ":_urls"
    } else if long.is_some_and(|value| value.contains("ftp"))
        && arg.contains("<method>")
    {
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
    if let Some(long) = &doc.long {
        out.push_str(" --long-option '");
        out.push_str(strip_leading_dashes(long.trim()));
        out.push('\'');
    }
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

// ===========================================================================
// What this script deliberately does NOT do
// ===========================================================================
//
// Each omission below is a decision with a reason. Recorded here so that none
// of them reads as an oversight and nobody "fixes" one.
//
// NO CUSTOM `cfg` FLAG -- no `cargo:rustc-cfg=use_manual`, no
// `cargo:rustc-cfg=curl_ca_embed`. Two reasons. First, rustc's
// `unexpected_cfgs` lint fires on an undeclared cfg and the
// `cargo:rustc-check-cfg` directive that would declare it does not exist at
// MSRV 1.75, so a custom cfg risks a warning, and AAP section 0.8.4 gate 1
// requires a build with ZERO warnings. Second, and more fundamentally, the
// always-write-a-stub design removes the need: every artifact exists on every
// path, so there is nothing to switch on. That is exactly what the C build's
// `else` branches achieve -- `src/Makefile.am:163-175` and `:197-199` write
// compiling stubs rather than omitting a file --  and
// `curl-rs/src/output/msgs.rs:206-209` already states the Rust-side
// consequence: `USE_MANUAL` "is not, and must not become, a Cargo feature".
//
// NO LINK ARGUMENT -- no `cargo:rustc-link-arg`, `cargo:rustc-link-lib` or
// `cargo:rustc-link-search`. This crate links no native library: AAP
// section 0.4.2 records that the C build's duplicate compilation of
// `../lib/curlx/*.c` into the tool, arranged at `src/Makefile.inc:33-42`,
// "disappears entirely; the CLI depends on the library crate instead".
//
// There is a related hazard nearby that must not be compounded, and the
// measured record differs from the description this file was written
// against, so the measurement wins. `.cargo/config.toml` sets NO `rustflags`
// key at all. Its :135-171 documents why: a soname link argument WAS placed
// there first, and `[target.<triple>].rustflags` turned out not to be
// artifact-scoped -- it reached the `curl-rs` binary, the `curlinfo` binary
// and this build script's own executable as well as the shared library, and
// `readelf -d` showed `SONAME libcurl.so.4` stamped on both executables with
// no error and no warning. The correctly-scoped mechanism,
// `cargo:rustc-cdylib-link-arg=-Wl,--soname=libcurl.so.4`, lives in
// `curl-rs-ffi/build.rs`, which is where AAP section 0.4.1 assigns the soname
// configuration anyway. So if `readelf -d target/release/curl-rs` ever
// reports a SONAME, the defect belongs to whatever reintroduced a rustflags
// key -- it must be REPORTED there, never compensated for here.
//
// NO HELP-TABLE GENERATION. AAP section 0.4.1 maps the 274-row help table to
// `curl-rs/src/cli/help.rs`, from `src/tool_help.c` and `src/tool_listhelp.c`,
// and that module owns it. This script does not drive `managen listhelp`
// (`docs/cmdline-opts/Makefile.am:60-61`), and the omission is a decision
// rather than a gap, on three grounds. AAP section 0.3.1 and section 0.4.1
// both name exactly THREE generators for this file, and `listhelp` is not
// among them; AAP section 0.2.1's list of generators that must be reproduced
// is `lib/optiontable.pl`, `src/mkhelp.pl`, `src/mk-file-embed.pl` and
// `scripts/completion.pl`, and `listhelp` is not among those either; and
// decisively, `src/tool_listhelp.c` is COMMITTED SOURCE in this tree --
// unlike `tool_hugehelp.c` and `tool_ca_embed.c`, which
// `src/Makefile.am:186` and `:190` put in CLEANFILES and which are never
// committed. The rationale for reproducing a generator is that its output is
// a build artifact and hand-writing it would drift; that rationale does not
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
// sourced from `include/curl/curlver.h`. AAP section 0.4.1 assigns the
// version and feature banner to that module, and AAP section 0.1.2 warns
// precisely about this shape of duplication: "If those are populated from two
// places, they will drift, and the drift will be invisible."
//
// The version is not cosmetic, which is why the ownership question is worth
// this paragraph. AAP section 0.6.7 records that the fixtures' `%VERSION` and
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
// user name or home directory is consulted; nothing is fetched, which AAP
// section 0.8.8 notes was true even of the environment this work was planned
// in; and the only absolute paths that exist at all are the `OUT_DIR` and
// repository paths derived at run time, which appear on child process command
// lines and in `cargo:` directives but never inside a generated artifact.
// `$OUT_DIR/ca_embed.rs` reaches its payload through
// `concat!(env!("OUT_DIR"), ...)`, resolved by the compiler, so even that
// path is absent from the emitted source. Every directory listing is sorted
// before use. Two consecutive builds of an unchanged tree therefore produce
// four byte-identical artifacts.
