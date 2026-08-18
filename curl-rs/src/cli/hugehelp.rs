// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! The built-in manual -- `src/tool_hugehelp.c`, which is a build artifact.
//!
//! `ls src/tool_hugehelp.c` finds a file only because a build has run;
//! `src/.gitignore:7` lists `tool_hugehelp.c`, so it is generated, never
//! committed. `src/mkhelp.pl` writes it from the rendered ASCII page, which
//! `docs/cmdline-opts/Makefile.am:57-58` in turn builds with
//! `managen -d $(srcdir) -I $(INCDIR) ascii $(DPAGES)`. AAP 0.2.1 makes
//! reproducing that generator mandatory rather than optional: hand-writing its
//! output would guarantee eventual drift from the 273 option pages `DPAGES`
//! lists -- 293 files sit in that directory, the remaining twenty being the
//! nineteen `_*.md` support pages and `MANPAGE.md`. `scripts/managen` itself
//! stays in scope and authoritative, so it is not reimplemented here or in
//! `build.rs`.
//!
//! This module is the Rust half of that arrangement. `curl-rs/build.rs`
//! reproduces the generator and writes `$OUT_DIR/hugehelp.rs`; this file is the
//! consumer named in that script's own artifact contract, and it does nothing
//! except include the result and present it the way C presents it.
//!
//! # Which of `mkhelp.pl`'s two branches this is, and why
//!
//! `src/mkhelp.pl` emits one of two shapes, and the difference is not
//! cosmetic:
//!
//! * **The compressed branch** (`src/mkhelp.pl:70-203`, taken when
//!   `HAVE_LIBZ`) writes the manual as a gzip stream in a
//!   `static const unsigned char hugehelpgz[]` and inflates it at run time.
//! * **The plain branch** (`src/mkhelp.pl:204-251`) writes a
//!   `NULL`-terminated `static const char * const curlman[]` and walks it:
//!
//!   ```c
//!   void hugehelp(void)
//!   {
//!     int i = 0;
//!     while(curlman[i])
//!       puts(curlman[i++]);
//!   }
//!   ```
//!
//! `build.rs` reproduces the **plain** branch, which is why the generated
//! artifact declares `pub(crate) const MANUAL: &[&str]` with, in its own
//! header comment, "one element per manual line, sentinel omitted". The
//! sentinel is dropped because a Rust slice carries its own length: C needs
//! the `NULL` to know where to stop, and reproducing it would put an element
//! in the slice that [`hugehelp`] would then have to special-case.
//!
//! Four facts settle the choice of the plain branch, and none of them is
//! "it was easier":
//!
//! 1. **The plain form is a supported upstream configuration, not a degraded
//!    mode.** `src/Makefile.am:155-161` is the `else # HAVE_LIBZ` arm, whose
//!    own comment reads "This generates the tool_hugehelp.c file uncompressed
//!    only", and `src/CMakeLists.txt:38-42` mirrors the same
//!    `#ifndef HAVE_LIBZ` / `#else` / `#endif` selection. A curl built
//!    without zlib ships exactly this shape.
//! 2. **Binary size is not an objective.** The compressed form buys size and
//!    nothing else. AAP 0.1.1 records performance -- and by extension size --
//!    as an explicit non-goal, and AAP 0.8.2 forbids a change justified by
//!    improvement.
//! 3. **The compressed branch is the one construct in this subtree that could
//!    not be written within the crate-level memory-safety lint asserted at
//!    `curl-rs/src/main.rs:49`.** It hands raw `voidpf` allocator callbacks to
//!    zlib (`src/mkhelp.pl:104-114`), sniffs a header byte as
//!    `hugehelpgz[3] & 0xfe` (`:126`), does pointer arithmetic as
//!    `hugehelpgz + HEADERLEN` (`:132-133`) and drives a raw-deflate stream
//!    through `inflateInit2(&z, -MAX_WBITS)` (`:135`). Every one of the four
//!    needs a raw pointer or a foreign call. Choosing plain satisfies that
//!    lint by construction rather than by argument, and needs no decompressor
//!    crate -- so it adds nothing to the dependency graph `cargo audit` and
//!    `cargo deny` police. This crate has no `mod ffi` and grants no
//!    exemption to the lint anywhere beneath it.
//! 4. **The observable output is identical.** Both branches put the same
//!    manual text on standard output, one line at a time. Choosing plain
//!    therefore changes no byte, which is what the preservation mandate of
//!    AAP 0.8.1 requires.
//!
//! # Why the artifact is included with no `cfg` guard
//!
//! The C build has three arms for `tool_hugehelp.c`, and every one of them
//! leaves a compilable file behind:
//!
//! * `src/Makefile.am:141-154` -- Perl present: `mkhelp.pl` output, both
//!   shapes, selected by `#ifndef HAVE_LIBZ`.
//! * `src/Makefile.am:163-175` -- **no Perl**: a stub, `void hugehelp(void)
//!   {}` at `:169` followed by an empty `showhelp` whose three parameters are
//!   `(void)`-cast.
//! * `src/Makefile.am:177-181` -- `USE_MANUAL` off: a file holding only
//!   `#include "tool_hugehelp.h"` at `:181`.
//!
//! `build.rs` reaches the same end by a deliberately different route, and the
//! difference is worth stating because it is easy to assume the stub arm was
//! carried over. It was not. `curl-rs/build.rs:1514-1529` records the
//! decision: the artifact is written on every **successful** path, and there
//! is no unsuccessful path that still writes one. `generate_manual` fails the
//! build outright rather than emit an empty `MANUAL`
//! (`curl-rs/build.rs:1540-1548`), and every way of failing to obtain the
//! ASCII page is terminal too (`:1587-1618`). C can afford its stub only
//! because a release tarball also ships a pre-generated
//! `src/tool_hugehelp.c`; here the equivalent would be a silently empty
//! `--manual`, and AAP 0.8.1 freezes that output, so an empty manual is a
//! behaviour change rather than a degraded build. A Perl-less tree names a
//! pre-rendered page in `CURL_ASCIIPAGE` instead, which turns an invisible
//! guess into a recorded decision.
//!
//! Either way the conclusion for this module is the same, and stronger than
//! the C reading alone would give: **there is no build in which this file
//! compiles and the artifact is absent.** A successful build wrote one; an
//! unsuccessful build produced no `curl-rs` at all. So the inclusion below
//! needs no `cfg`, no `option_env!` and no `Path::exists` probe -- and none of
//! those could help in any case, since a missing artifact is a build failure
//! and not a configuration to select against.
//!
//! [`write_lines`] and [`feed_lines`] are nonetheless total over an empty
//! slice, and the `tests` module drives both with one. That is not dead
//! defensiveness: it is the behaviour of C's own stub arm, whose `hugehelp`
//! body is literally `{}`, and holding to it means the emptiness of the
//! manual is never a precondition either function relies on.
//!
//! # The two transformations that are visible in the bytes
//!
//! `build.rs` owns the transformation and this module must not reproduce it.
//! Two of its steps are visible in `MANUAL`'s contents, and both must survive
//! untouched -- so neither function may trim, normalise or re-wrap an
//! element:
//!
//! * **Eight consecutive spaces become a TAB.** `src/mkhelp.pl:222` applies
//!   `s/        /\t/g` to every non-blank line, left to right, after `:216`
//!   has already turned pre-existing TABs into the same escape. The ten-space
//!   first line of the logo is the visible consequence: it arrives as a TAB
//!   followed by two spaces, and no element anywhere in the artifact still
//!   holds a run of eight spaces.
//! * **Blank lines are dropped and folded into one leading newline.**
//!   `src/mkhelp.pl:218-220` counts a blank rather than emitting it, and
//!   `:223` prefixes the next non-blank line with `$blank ? "\n" : ""` -- a
//!   truthiness test rather than a count, so a run of any length contributes
//!   exactly one newline. An element may therefore begin with a newline of
//!   its own, which [`hugehelp`] reproduces verbatim and which is what lets
//!   the scanner's `"\nFILES"` and `"\n    -"` terminators match at all.
//!
//! # `USE_MANUAL` is a feature *name*, never a Cargo feature
//!
//! In C it is a preprocessor symbol, set by `curl_CPPFLAGS += -DUSE_MANUAL`
//! (`src/Makefile.am:135`) and by
//! `list(APPEND _curl_definitions "USE_MANUAL")` (`src/CMakeLists.txt:54`).
//! It appears in no header: `src/tool_setup.h` never mentions it. Both C
//! functions sit inside `#ifdef USE_MANUAL` (`src/tool_hugehelp.h:28-31`),
//! and `src/tool_operate.c:2306-2311` has an `#else` arm warning "built-in
//! manual was disabled at build-time".
//!
//! It is **not** reproduced as a Cargo feature. The canonical set is exactly
//! fifteen names -- `http2`, `http3`, `ftp`, `ssh`, `websockets`, `cookies`,
//! `hsts`, `altsvc`, `doh`, `brotli`, `zstd` and `gzip` on by default, plus
//! `negotiate`, `hickory-dns` and `memdebug` off by default -- and inventing
//! a sixteenth for the manual would make `--manual` configurable, which
//! `build.rs`'s unconditional artifact deliberately prevents. What is
//! narrowed is C's build matrix, not its behaviour: a curl built with
//! `USE_MANUAL` behaves exactly as this does, and `--manual` is documented
//! without qualification in `docs/cmdline-opts/manual.md`.
//!
//! What `USE_MANUAL` maps to instead is a *harness* feature name, and the
//! mechanism is worth stating precisely because it is easy to assume it is
//! read off the `--version` banner. It is not. `tests/runtests.pl:818-827`
//! runs `curl -M` -- the short form of `--manual`, letter `M` at
//! `src/tool_getparam.c:208` -- and inspects only the first line of its
//! output: a match for `built-in manual was disabled at build-time` sets
//! `$feature{"manual"} = 0` at `:821`, and any other first line sets it to
//! `1` at `:824`. Those two lines are the only assignments to that feature in
//! the whole harness, and `manual` appears nowhere in the `Features:`
//! vocabulary the banner is parsed for.
//!
//! So this module's first emitted byte is what answers the probe. Because
//! `MANUAL` is the real manual, that first line is the logo, and the harness
//! records `manual = 1` truthfully with nothing to advertise anywhere --
//! which is what the seven fixtures gating on the feature need. Measured by
//! running that probe against a build of this crate: `manual = 1`.
//!
//! The probe has a third state worth naming, because it is what makes the
//! arrangement safe rather than merely correct. Were the manual empty, `-M`
//! would write no lines at all, the `while` at `:819` would never enter its
//! body, and `$feature{"manual"}` would be left unset -- which Perl reads as
//! false, exactly as an explicit `0` would be. So every way of not having a
//! manual makes the seven fixtures *skip*, and none makes them run and fail.
//! That is the direction AAP 0.6.5 identifies as the safe one, and it holds
//! without this module advertising anything. The disabled-message text itself
//! belongs to the `--manual` dispatch, not here.

// GAP #1: `hugehelp` here is `hugehelp<W: Write>(&mut W) -> io::Result<()>`,
// whereas `src/tool_hugehelp.h:30` declares `void hugehelp(void)`. The writer
// is a parameter because three call sites already written against that shape
// depend on it -- `curl-rs/src/main.rs:914` serves `--manual` through it,
// `main.rs:1361` compares against it, and this module's own tests capture its
// bytes without a terminal. C reaches standard output through a global
// `FILE *`, which is not a seam a test can substitute; a parameter is. The
// stream is unchanged: `main.rs` passes the process's standard output, so
// `--manual` writes exactly where `puts` writes. Reported rather than worked
// around, because "worked around" would mean either a second entry point or
// an edit to `main.rs`, and both cost more than the divergence does.
//
// GAP #2 -- retracted on measurement, recorded so the retraction is visible.
// This module was to note that the repository's root `.gitignore` lacked a
// `target/` entry. It does not lack one: `.gitignore:76` holds `/target`, and
// `:79-81` hold `curl-rs-lib/target/`, `curl-rs/target/` and
// `curl-rs-ffi/target/`. There is nothing to report and nothing to fix, and
// no `.gitignore` is created or edited from here in any case.
//
// GAP #3: this module was specified against a `build.rs` that "always writes a
// valid `$OUT_DIR/hugehelp.rs`, even when its input is unavailable", so that
// the include could be verified by pointing the generator at absent input and
// watching the build still succeed. The `build.rs` that exists resolves the
// same requirement the other way round: `curl-rs/build.rs:1514-1529` states
// that no unsuccessful path writes an artifact, `:1540-1548` fails the build
// rather than emit an empty `MANUAL`, and `:1587-1618` makes every way of
// failing to obtain the ASCII page terminal. So the emitted item's name and
// type are exactly as specified -- `pub(crate) const MANUAL: &[&str]` -- and
// only the emptiness guarantee differs, in the safer direction.
//
// `build.rs` is matched rather than argued with, which is why nothing here is
// conditional. The verification it displaces is replaced rather than dropped:
// `an_empty_manual_writes_nothing_and_does_not_panic` and
// `an_empty_manual_feeds_nothing_and_does_not_panic` assert the same property
// the stub build was meant to establish -- that neither loop relies on the
// manual being non-empty -- by driving the shipped loops with an empty slice.
// Reported rather than worked around: making `build.rs` write a stub would
// mean editing another file to weaken a deliberate, documented decision.

use crate::cli::help;
use std::io::{self, Write};

// Brings `pub(crate) const MANUAL: &[&str]` into scope -- one element per line
// of the rendered manual, with no terminating sentinel.
//
// Included rather than declared so that the manual cannot be edited in place:
// the only way to change it is to change `docs/cmdline-opts/*.md` and let
// `build.rs` regenerate, which is the same discipline the C build enforces by
// gitignoring its output (`src/.gitignore:7` lists `tool_hugehelp.c`, and
// `docs/cmdline-opts/.gitignore:5` lists the `curl.txt` it is rendered from).
//
// Unconditional, for the reason the module documentation sets out above: all
// three C arms leave a compilable file behind, so `build.rs` always writes
// one, so there is nothing for a `cfg` to select between.
//
// A `//` comment rather than `///`: rustdoc emits nothing for a macro
// invocation, so a doc comment here is `unused_doc_comments` -- a warning, and
// AAP 0.8.4's first gate is a zero-warning build.
include!(concat!(env!("OUT_DIR"), "/hugehelp.rs"));

/// Writes the whole built-in manual, reproducing `hugehelp()`.
///
/// C is `while(curlman[i]) puts(curlman[i++]);` (`src/mkhelp.pl:231-236`), and
/// `puts` appends exactly one `\n` to each string. So the emitted bytes are each
/// element followed by a single line feed, in order, and nothing else -- no
/// leading blank, no trailing extra, no separator between elements beyond the one
/// newline `puts` supplies.
///
/// # Errors
///
/// Returns the first write error, and **keeps going after it**, which is the
/// combination C's `puts` loop produces.
///
/// The earlier revision of this function used `?` and stopped at the first
/// failure. That is a behaviour change of exactly the kind AAP section 0.8.2
/// forbids: `src/mkhelp.pl:231-236` is `while(curlman[i]) puts(curlman[i++]);`,
/// and `puts` reports failure through its return value, which the loop never
/// reads. C therefore attempts **every** line whatever happens, and a transient
/// failure -- an interrupted write, a full pipe buffer that later drains --
/// costs C one line where it would have cost this function the entire
/// remainder of the manual.
///
/// So the loop is unconditional and the *first* error is remembered and returned
/// at the end. That gives a caller strictly more than C has, without changing
/// what reaches the stream: `crate::outcome_for` discards the result, exactly as
/// C's `--manual` arm at `src/tool_operate.c:2309` does, and a caller that wants
/// to know can look.
pub(crate) fn hugehelp<W: Write>(sink: &mut W) -> io::Result<()> {
    write_lines(MANUAL, sink)
}

/// The `puts` loop of `src/mkhelp.pl:231-236`, over an arbitrary slice.
///
/// [`hugehelp`] is this applied to `MANUAL`. The slice is a parameter for one
/// reason only: it lets the `tests` module drive the empty case -- the
/// behaviour of C's no-Perl stub at `src/Makefile.am:163-175`, whose
/// `hugehelp` body is `{}` -- without pretending `MANUAL` is something it is
/// not. There is exactly one definition of the loop, so the tested path and
/// the shipped path cannot drift apart.
fn write_lines<W: Write>(lines: &[&str], sink: &mut W) -> io::Result<()> {
    let mut first_failure: Option<io::Error> = None;

    for line in lines {
        // `write_all` rather than `write`, because a short write is not a
        // failure and C's `puts` writes the whole string. `writeln!` is not
        // used because it would format, and these bytes are already final.
        //
        // Two calls rather than one concatenation: `puts` is itself one call
        // per element that appends its own terminator, so a failure on the
        // line does not suppress the newline.
        let line_result = sink.write_all(line.as_bytes());
        let newline_result = sink.write_all(b"\n");

        for outcome in [line_result, newline_result] {
            if let Err(error) = outcome {
                if first_failure.is_none() {
                    first_failure = Some(error);
                }
            }
        }
    }

    match first_failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// The frozen feeding protocol of `src/mkhelp.pl:244-250`, over an arbitrary
/// slice and an arbitrary consumer.
///
/// ```c
/// while(curlman[i]) {
///   size_t len = strlen(curlman[i]);
///   if(!helpscan((const unsigned char *)curlman[i], len, &ctx) ||
///      !helpscan((const unsigned char *)"\n", 1, &ctx))
///     break;
///   i++;
/// }
/// ```
///
/// This is the **single** definition of that loop. [`showhelp`] supplies
/// `crate::cli::help::helpscan` as `feed`; the `tests` module supplies a
/// recorder, which is the only way to assert mechanically that the three
/// properties below survived. Writing the loop twice -- once to ship and once
/// to test -- would let the copies disagree, which is precisely the drift this
/// arrangement exists to prevent.
///
/// The three properties, each of which is easy to lose and none of which is
/// negotiable:
///
/// 1. **Each element is fed as its own piece, and the separating newline as a
///    second piece of exactly one byte.** The elements carry no terminator
///    (`chomp` at `src/mkhelp.pl:213`), and the matcher recognises a line
///    boundary only by seeing a `\n` byte go past. The manual's own
///    `"\nALL OPTIONS"` element is the proof that this matters: the trigger
///    `crate::cli::help` uses is `"\nALL OPTIONS\n"`, which no single element
///    contains, so it can *only* match across the seam between the two feeds.
/// 2. **The `||` short-circuits.** When the line says stop, the newline is
///    never fed. Concatenating the two pieces would emit the same bytes but
///    make one call where C makes two, and the return value is checked after
///    each.
/// 3. **Either `false` breaks.** A `false` means the matcher has reached its
///    terminator or overflowed its 160-byte line buffer, and in both cases C
///    stops feeding immediately.
fn feed_lines<F>(lines: &[&str], mut feed: F)
where
    F: FnMut(&[u8]) -> bool,
{
    for line in lines {
        if !feed(line.as_bytes()) || !feed(b"\n") {
            break;
        }
    }
}

/// `showhelp(trigger, arg, endarg)` -- `src/mkhelp.pl:238-251`, declared at
/// `src/tool_hugehelp.h:29`, carrying the generator's comment "Show the help
/// text for the 'arg' curl argument on stdout".
///
/// ```c
/// void showhelp(const char *trigger, const char *arg, const char *endarg)
/// {
///   int i = 0;
///   struct scan_ctx ctx;
///   inithelpscan(&ctx, trigger, arg, endarg);
///   while(curlman[i]) {
///     size_t len = strlen(curlman[i]);
///     if(!helpscan((const unsigned char *)curlman[i], len, &ctx) ||
///        !helpscan((const unsigned char *)"\n", 1, &ctx))
///       break;
///     i++;
///   }
/// }
/// ```
///
/// Like `hugehelp` above, this function is *generated* in C -- it is emitted by
/// `src/mkhelp.pl` alongside the `curlman[]` array, because it is the one place
/// that array is walked other than `hugehelp()` itself. It lives here for the
/// same reason: this module owns the manual, and
/// `crate::cli::help` owns the matcher it feeds.
///
/// # The framing is load-bearing
///
/// The loop itself lives in [`feed_lines`], which documents the three
/// properties that must survive -- one piece per element plus a separate
/// one-byte newline, a short-circuiting `||`, and a break on either `false`.
/// It is factored out rather than written inline so that the `tests` module can
/// assert those properties against the same loop this function ships, instead
/// of against a second copy of it.
///
/// `inithelpscan` is called **once**, before the loop, exactly as
/// `src/mkhelp.pl:243` does: the matcher's rolling window and its stage carry
/// across every element, so re-initialising per line would reset the search.
///
/// Standard output is locked once for the whole scan rather than per line. C
/// gets the same effect implicitly, because its `puts` writes through one
/// line-buffered `FILE *`.
pub(crate) fn showhelp(trigger: &str, arg: &str, endarg: &str) {
    let stdout = io::stdout();
    let mut out = stdout.lock();

    let mut ctx = help::inithelpscan(trigger, arg, endarg);

    feed_lines(MANUAL, |piece| help::helpscan(piece, &mut ctx, &mut out));

    let _ = out.flush();
}

/// How many lines the built-in manual has.
///
/// Exposed because it is the cheapest way for a test -- or a caller sizing a
/// buffer -- to establish that the artifact is present and non-trivial without
/// materialising the whole thing.
// Every caller is under `#[cfg(test)]` -- `main.rs:1369` and `help.rs:3388`,
// `:3646`, `:3863` -- so a release build sees no use and would warn without
// this. Placed on the function rather than the module so nothing else is
// exempted.
#[allow(dead_code)]
pub(crate) fn manual_lines() -> usize {
    MANUAL.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    // The three needles `crate::cli::help` builds for a per-option lookup.
    // Reproduced as literals rather than imported because they are private to
    // that module; each carries the citation that fixes it.

    /// `MANUAL_TRIGGER` -- `src/tool_help.c:286`, `curl-rs/src/cli/help.rs:2202`.
    const TRIGGER: &str = "\nALL OPTIONS\n";

    /// The heading `--help --xattr` looks for. `src/tool_help.c:283` builds it
    /// as `"\n    %s"` from the option text, for an option with no short letter.
    const XATTR: &str = "\n    --xattr";

    /// `--xattr` is the last option in the manual, so its section is terminated
    /// by the next top-level heading rather than by the next option --
    /// `src/tool_help.c:284-286`, which special-cases `C_XATTR` for exactly
    /// this reason.
    const FILES: &str = "\nFILES";

    /// Element `index`, or the empty string past the end.
    ///
    /// Non-panicking, because a panicking index is forbidden here and because a
    /// test asserting on an absent element should fail on its own assertion,
    /// with its own message, rather than on the index.
    fn element(index: usize) -> &'static str {
        MANUAL.get(index).copied().unwrap_or_default()
    }

    /// The whole manual as [`hugehelp`] writes it.
    fn rendered() -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        assert!(
            hugehelp(&mut out).is_ok(),
            "a `Vec` sink has no failure mode"
        );
        out
    }

    /// Runs the scan [`showhelp`] runs, into a buffer instead of standard
    /// output.
    ///
    /// [`showhelp`] itself cannot be called from a test: it writes to the
    /// process's standard output, which a test cannot capture. This drives
    /// [`feed_lines`] -- the same and only definition of the feeding protocol
    /// -- with the same `crate::cli::help::helpscan`, differing from
    /// [`showhelp`] in nothing but the sink. So what it observes is what
    /// [`showhelp`] does.
    fn scan(lines: &[&str], trigger: &str, arg: &str, endarg: &str) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        let mut ctx = help::inithelpscan(trigger, arg, endarg);
        feed_lines(lines, |piece| help::helpscan(piece, &mut ctx, &mut out));
        out
    }

    /// Every piece [`feed_lines`] offers, in order.
    fn recorded_feeds(lines: &[&str]) -> Vec<Vec<u8>> {
        let mut seen: Vec<Vec<u8>> = Vec::new();
        feed_lines(lines, |piece| {
            seen.push(piece.to_vec());
            true
        });
        seen
    }

    /// How many elements begin with the folded-blank marker.
    ///
    /// Its own function because several tests need the same count and because
    /// naming it is what makes the newline arithmetic below legible.
    fn folded_blank_elements() -> usize {
        MANUAL.iter().filter(|line| line.starts_with('\n')).count()
    }

    // -- the artifact is the real manual --------------------------------------

    #[test]
    fn the_generated_artifact_is_present_and_substantial() {
        // The failure this catches is a generated output with no consumer. If
        // `build.rs` stopped writing the manual the inclusion above would fail
        // to compile, so reaching this assertion at all proves the artifact
        // exists; the bound proves it is the manual rather than the empty stub
        // `src/Makefile.am:163-175` produces when Perl is absent.
        //
        // `src/tool_hugehelp.c` runs to several thousand array elements in this
        // tree, so a thousand is the right order of magnitude. The bound is
        // deliberately loose: it must not fail merely because an option page
        // gained or lost a paragraph.
        assert!(
            manual_lines() > 1000,
            "the built-in manual has only {} lines, which is too few to be the \
             rendered manual",
            manual_lines()
        );
        assert!(!MANUAL.is_empty(), "the manual must not be empty");
    }

    #[test]
    fn the_first_element_is_the_first_logo_line_byte_for_byte() {
        // `src/mkhelp.pl:37` pushes `"          _   _ ____  _\n"` -- ten
        // leading spaces -- onto the output BEFORE reading standard input, so
        // it is element zero. `:222` then rewrites the first eight of those
        // spaces as a TAB, leaving two behind.
        //
        // Byte-exact rather than a `starts_with`, because this single assertion
        // pins both transformations of `src/mkhelp.pl` at once: the TAB proves
        // the eight-space substitution ran, and the absence of a trailing
        // newline proves the `chomp` at `:213` ran.
        assert_eq!(
            element(0),
            "\t  _   _ ____  _",
            "element zero must be the first logo line with its leading eight \
             spaces rewritten as a TAB"
        );
    }

    #[test]
    fn all_five_logo_lines_lead_the_manual_in_order() {
        // `src/mkhelp.pl:37-41`. The leading-space counts are 10, 6, 5, 4, 5,
        // and only the first reaches eight, so only the first carries a TAB
        // after `:222`. Asserting all five in order pins the START of the
        // artifact, which is the part a truncating generator bug corrupts
        // first, and it is also what makes `curl -M`'s first line -- the
        // harness's `manual` probe at `tests/runtests.pl:818-827` -- what it
        // is.
        let logo = [
            "\t  _   _ ____  _",
            "      ___| | | |  _ \\| |",
            "     / __| | | | |_) | |",
            "    | (__| |_| |  _ <| |___",
            "     \\___|\\___/|_| \\_\\_____|",
        ];

        for (index, expected) in logo.iter().enumerate() {
            assert_eq!(
                element(index),
                *expected,
                "logo line {index} must be reproduced verbatim"
            );
        }

        // And the TAB is the first line's alone.
        assert!(
            element(0).contains('\t'),
            "only the ten-space logo line reaches eight spaces, so it alone \
             carries a TAB"
        );
        for index in 1..logo.len() {
            assert!(
                !element(index).contains('\t'),
                "logo line {index} has fewer than eight leading spaces, so it \
                 must carry no TAB"
            );
        }
    }

    // -- the transformations of src/mkhelp.pl:211-226 survived ----------------

    #[test]
    fn no_element_carries_a_trailing_newline() {
        // `chomp $n` at `src/mkhelp.pl:213`. The terminator is `puts`'s to
        // supply (`:235`), so an element that carried one would be printed with
        // two -- and, in `showhelp`, would feed the matcher a line boundary
        // that the separate one-byte feed then duplicates.
        for (index, line) in MANUAL.iter().enumerate() {
            assert!(
                !line.ends_with('\n'),
                "element {index} ends with a newline, so `chomp` did not run: \
                 {line:?}"
            );
        }
    }

    #[test]
    fn blank_runs_are_folded_into_exactly_one_leading_newline() {
        // `src/mkhelp.pl:218-223`:
        //
        //   if(!$n) { $blank++; }
        //   else { printf("  \"%s%s\",\n", $blank ? "\\n" : "", $n);
        //          $blank = 0; }
        //
        // Three properties of that one loop, asserted together because they are
        // one loop:
        //
        // 1. A blank input line never becomes an element -- it only increments
        //    `$blank`. So no element is empty and none is newline-only.
        // 2. A blank RUN of any length contributes `$blank ? "\n" : ""`, which
        //    is ONE newline however many blanks preceded it, because `$blank`
        //    is read as a truth value and not as a count. So no element begins
        //    with two.
        // 3. `chomp` removes the trailing newline and input is read a line at a
        //    time, so the optional leading marker is the ONLY newline an
        //    element can contain.
        //
        // An earlier form of this test asserted `!line.contains('\n')` and
        // failed on element 6, `"\n    curl - transfer a URL"`. That was the
        // test being wrong rather than the generator: the leading marker is C's
        // own output. The invariant below is strictly stronger than the false
        // one it replaced, because it also pins properties 1 and 2.
        for (index, line) in MANUAL.iter().enumerate() {
            let body = line.strip_prefix('\n').unwrap_or(line);

            assert!(
                !body.contains('\n'),
                "element {index} carries a newline after its first character, \
                 so the generator did not split on lines: {line:?}"
            );
            assert!(
                !body.is_empty(),
                "element {index} is blank, but `mkhelp.pl` folds blank lines \
                 into the next element rather than emitting them: {line:?}"
            );
        }

        // And that the marker is genuinely in use, so the loop above is not
        // vacuously true against an artifact that lost its blank folding.
        assert!(
            folded_blank_elements() > 100,
            "only {} of {} elements carry the folded-blank marker, which is \
             too few for a rendered manual",
            folded_blank_elements(),
            MANUAL.len()
        );
    }

    #[test]
    fn eight_spaces_became_tabs_everywhere_they_occurred() {
        // `s/        /\t/g` at `src/mkhelp.pl:222`, applied globally and left
        // to right. Two halves, and the second is the one that would catch a
        // partial substitution: the TAB must be present somewhere, AND no run
        // of eight spaces may remain anywhere.
        assert!(
            MANUAL.iter().any(|line| line.contains('\t')),
            "no element contains a TAB, so the eight-space substitution never \
             ran"
        );

        for (index, line) in MANUAL.iter().enumerate() {
            assert!(
                !line.contains("        "),
                "element {index} still holds a run of eight spaces, so the \
                 substitution was not global: {line:?}"
            );
        }
    }

    // -- hugehelp() reproduces `puts` per element -----------------------------

    #[test]
    fn the_writer_emits_every_element_followed_by_one_newline() {
        // `while(curlman[i]) puts(curlman[i++]);` -- `src/mkhelp.pl:231-236`.
        // The strongest available statement of it: the whole output, byte for
        // byte, against the whole input. This is what "exactly `MANUAL.len()`
        // newline-terminated lines and nothing else" means, and it forecloses
        // a missing separator, a doubled one, a reordering, a dropped element
        // and a stray prologue or epilogue in one comparison.
        let mut expected: Vec<u8> = Vec::new();
        for line in MANUAL {
            expected.extend_from_slice(line.as_bytes());
            expected.push(b'\n');
        }

        assert_eq!(
            rendered(),
            expected,
            "the manual must be every element followed by exactly one newline"
        );
    }

    #[test]
    fn the_writer_emits_one_newline_per_element_plus_the_folded_blanks() {
        // The same property counted rather than compared, which localises a
        // failure: a mismatch here says how many newlines are wrong, where the
        // byte comparison above only says that they are.
        //
        // The total is `puts`'s one-per-element PLUS the leading markers the
        // elements already carry, because `puts` appends to whatever the string
        // holds rather than replacing it. C emits the same two sources of line
        // feed for the same reason.
        let out = rendered();

        assert_eq!(
            out.iter().filter(|byte| **byte == b'\n').count(),
            MANUAL.len() + folded_blank_elements(),
            "one newline per element from `puts`, plus the {} folded-blank \
             markers already inside the elements",
            folded_blank_elements()
        );
        assert!(
            out.ends_with(b"\n"),
            "the last line is terminated like every other"
        );
    }

    #[test]
    fn a_folded_blank_renders_as_a_blank_line_ahead_of_its_text() {
        // The positive form of the folding invariant, on real bytes: an element
        // that begins with the marker must appear in the output as an empty
        // line and then its text, which is what
        // `puts("\n    curl - transfer a URL")` writes. Without this, the
        // counting test alone could not distinguish a marker that survived from
        // one the writer had stripped.
        let folded = MANUAL
            .iter()
            .find(|line| line.starts_with('\n'))
            .copied()
            .unwrap_or_default();
        assert!(
            !folded.is_empty(),
            "the manual must contain a folded blank for this to mean anything"
        );

        let text = folded.trim_start_matches('\n');
        let mut needle: Vec<u8> = Vec::new();
        needle.push(b'\n');
        needle.push(b'\n');
        needle.extend_from_slice(text.as_bytes());
        needle.push(b'\n');

        let out = rendered();
        assert!(
            out.windows(needle.len()).any(|window| window == needle),
            "a folded blank must render as an empty line before {text:?}"
        );
    }

    #[test]
    fn the_manual_contains_the_section_heading_the_scanner_triggers_on() {
        // `crate::cli::help` searches for `"\nALL OPTIONS\n"`
        // (`src/tool_help.c:286`). If the rendered manual did not contain that
        // heading, every per-option lookup would silently produce nothing, and
        // no other test here would notice.
        let out = rendered();
        let needle = b"ALL OPTIONS";
        assert!(
            out.windows(needle.len()).any(|window| window == needle),
            "the manual must contain the `ALL OPTIONS` heading that the \
             per-option help triggers on"
        );
    }

    // -- the feeding protocol of src/mkhelp.pl:244-250 ------------------------

    #[test]
    fn each_line_is_followed_by_a_separate_one_byte_newline_feed() {
        // Property 1 of `feed_lines`, on synthetic input so the expectation can
        // be written out in full. `helpscan`'s line handling keys on seeing a
        // `\n` byte go past, and the elements carry none, so this framing is
        // the only thing that gives the matcher line boundaries at all.
        let seen = recorded_feeds(&["alpha", "beta"]);
        let expected: Vec<Vec<u8>> = vec![
            b"alpha".to_vec(),
            b"\n".to_vec(),
            b"beta".to_vec(),
            b"\n".to_vec(),
        ];

        assert_eq!(
            seen, expected,
            "each line must be fed on its own, then a newline of exactly one \
             byte"
        );
    }

    #[test]
    fn the_real_corpus_is_fed_as_alternating_line_and_newline_pieces() {
        // The same property against the artifact that actually ships, which is
        // what makes it a statement about this build rather than about a
        // two-element fixture.
        let seen = recorded_feeds(MANUAL);

        assert_eq!(
            seen.len(),
            MANUAL.len() * 2,
            "two feeds per element -- the line, then its newline"
        );

        for (index, line) in MANUAL.iter().enumerate() {
            let fed_line =
                seen.get(index * 2).map(Vec::as_slice).unwrap_or_default();
            let fed_newline = seen
                .get(index * 2 + 1)
                .map(Vec::as_slice)
                .unwrap_or_default();

            assert_eq!(
                fed_line,
                line.as_bytes(),
                "feed {} must be element {index} verbatim, with no newline of \
                 its own",
                index * 2
            );
            assert_eq!(
                fed_newline,
                b"\n",
                "feed {} must be the separating newline, one byte exactly",
                index * 2 + 1
            );
        }
    }

    #[test]
    fn a_stop_on_a_line_suppresses_that_line_s_newline_feed() {
        // Property 2 -- the `||` short-circuits. C writes
        //
        //   if(!helpscan(curlman[i], len, &ctx) || !helpscan("\n", 1, &ctx))
        //     break;
        //
        // so a `false` from the line feed means the newline feed never happens
        // and the loop ends. Two unconditional calls would emit the same bytes
        // and behave differently, which is why this is asserted rather than
        // assumed.
        let mut seen: Vec<Vec<u8>> = Vec::new();
        feed_lines(&["alpha", "beta", "gamma"], |piece| {
            seen.push(piece.to_vec());
            piece != b"beta"
        });

        let expected: Vec<Vec<u8>> =
            vec![b"alpha".to_vec(), b"\n".to_vec(), b"beta".to_vec()];
        assert_eq!(
            seen, expected,
            "the newline after a refused line must not be fed, and no later \
             line may be reached"
        );
    }

    #[test]
    fn a_stop_on_a_newline_ends_the_loop_before_the_next_line() {
        // Property 3, from the other operand: a `false` from the newline feed
        // also breaks, so the following element is never offered.
        let mut seen: Vec<Vec<u8>> = Vec::new();
        feed_lines(&["alpha", "beta"], |piece| {
            seen.push(piece.to_vec());
            piece != b"\n"
        });

        let expected: Vec<Vec<u8>> = vec![b"alpha".to_vec(), b"\n".to_vec()];
        assert_eq!(
            seen, expected,
            "a refusal on the newline must end the loop before the next line"
        );
    }

    // -- showhelp() over the real manual --------------------------------------

    #[test]
    fn a_per_option_lookup_emits_the_heading_then_its_section() {
        // The whole point of the module, end to end: the needles
        // `crate::cli::help` builds for `--help --xattr`, fed through the same
        // loop `showhelp` uses, must produce that option's documentation.
        //
        // The output begins at `&arg[1]` rather than at `arg`, because
        // `src/tool_help.c:194` is `fputs(&ctx->arg[1], stdout)` -- the heading
        // without the blank line that preceded it.
        let out = scan(MANUAL, TRIGGER, XATTR, FILES);

        assert!(
            !out.is_empty(),
            "the `--xattr` section must not come back empty"
        );

        let heading = XATTR.as_bytes().get(1..).unwrap_or_default();
        assert!(
            out.starts_with(heading),
            "the section must open with the heading minus its leading \
             newline, {:?}",
            String::from_utf8_lossy(heading)
        );

        // And the terminator's own text never reaches the output: the endarg
        // test at `src/tool_help.c:202-203` runs BEFORE the byte is
        // accumulated, and the partial line held when it fires is discarded
        // unflushed.
        let files = b"FILES";
        assert!(
            !out.windows(files.len()).any(|window| window == files),
            "the `FILES` heading terminates the section and must not appear \
             inside it"
        );
    }

    #[test]
    fn a_trigger_that_never_matches_emits_nothing() {
        // `helpscan` stays in its first stage until the trigger goes past
        // (`src/tool_help.c:180-187`), and only the third stage writes. So an
        // absent trigger is silence, not an error and not a panic.
        let out = scan(MANUAL, "\nNO SUCH SECTION\n", XATTR, FILES);

        assert!(
            out.is_empty(),
            "an unmatched trigger must emit nothing, got {} bytes",
            out.len()
        );
    }

    #[test]
    fn an_option_that_never_matches_emits_nothing() {
        // The same for the second stage: the trigger matches, the heading does
        // not, and nothing is ever shown.
        let out = scan(MANUAL, TRIGGER, "\n    --no-such-option-exists", FILES);

        assert!(
            out.is_empty(),
            "an unmatched option heading must emit nothing, got {} bytes",
            out.len()
        );
    }

    #[test]
    fn the_scan_stops_feeding_as_soon_as_the_matcher_says_stop() {
        // `break` on `false` -- `src/mkhelp.pl:245-248`. Measured directly by
        // counting the feeds the loop actually makes: a scan that ran to the
        // end of the manual would make two per element, and one that stopped at
        // its terminator makes fewer. This is the only assertion here that
        // distinguishes "stopped" from "kept feeding and happened to write
        // nothing more".
        let mut out: Vec<u8> = Vec::new();
        let mut ctx = help::inithelpscan(TRIGGER, XATTR, FILES);
        let mut feeds = 0usize;

        feed_lines(MANUAL, |piece| {
            feeds += 1;
            help::helpscan(piece, &mut ctx, &mut out)
        });

        assert!(
            !out.is_empty(),
            "the section must have been found for the stop to mean anything"
        );
        assert!(
            feeds < MANUAL.len() * 2,
            "the scan must stop at its terminator, but it made all {feeds} \
             feeds of a possible {}",
            MANUAL.len() * 2
        );
    }

    #[test]
    fn the_section_is_byte_identical_to_the_same_region_of_the_whole_manual() {
        // `hugehelp` and `showhelp` walk one array with one framing, so the
        // text they put on the overlapping region must agree byte for byte. If
        // it did not, one of them would be reformatting, and the folded-blank
        // marker is exactly where that would happen.
        //
        // Anchored rather than searched: the whole manual holds
        // `"\n    --xattr" + "\n"`, so the section -- which begins one byte
        // later, at `&arg[1]` -- must be a prefix of what follows that anchor.
        // A shorter section is still a prefix, which is the right outcome if
        // the matcher's 160-byte line buffer ever cuts the scan short.
        let section = scan(MANUAL, TRIGGER, XATTR, FILES);
        assert!(!section.is_empty(), "the section must not be empty");

        let whole = rendered();
        let mut anchor: Vec<u8> = Vec::new();
        anchor.extend_from_slice(XATTR.as_bytes());
        anchor.push(b'\n');

        let at = whole
            .windows(anchor.len())
            .position(|window| window == anchor);
        assert!(
            at.is_some(),
            "the whole manual must contain {:?}",
            String::from_utf8_lossy(&anchor)
        );

        // `+ 1` skips the anchor's own leading newline, because the section
        // begins at `&arg[1]`. Resolved through `and_then` rather than an
        // index: the assertion above is what reports an absent anchor, and a
        // `None` here then yields an empty slice that the assertion below
        // rejects with its own message.
        let after = at.and_then(|at| whole.get(at + 1..)).unwrap_or_default();
        assert!(
            after.starts_with(&section),
            "the scanned section must match the whole manual's own rendering \
             of the same region"
        );
    }

    // -- the empty artifact, which is a supported build ----------------------

    #[test]
    fn an_empty_manual_writes_nothing_and_does_not_panic() {
        // C's no-Perl arm at `src/Makefile.am:163-175` has a `hugehelp` whose
        // body is literally `{}`, so an empty manual is a shape C ships.
        // `build.rs` never emits one -- it fails the build instead
        // (`curl-rs/build.rs:1540-1548`) -- but that is `build.rs`'s policy,
        // not an invariant this loop may lean on. Driving the shipped loop
        // with an empty slice keeps the emptiness of `MANUAL` out of its
        // preconditions.
        let mut out: Vec<u8> = Vec::new();
        assert!(
            write_lines(&[], &mut out).is_ok(),
            "writing no lines cannot fail"
        );
        assert!(out.is_empty(), "an empty manual writes no bytes");
    }

    #[test]
    fn an_empty_manual_feeds_nothing_and_does_not_panic() {
        // The same for `showhelp`'s half: C's stub `showhelp` casts its three
        // parameters to `(void)` and returns, and an empty slice reaches the
        // matcher with nothing at all.
        assert!(
            recorded_feeds(&[]).is_empty(),
            "an empty manual offers no pieces"
        );
        assert!(
            scan(&[], TRIGGER, XATTR, FILES).is_empty(),
            "an empty manual can match no trigger"
        );
    }

    // -- write failures follow C rather than Rust convention ------------------

    #[test]
    fn a_write_failure_is_reported_rather_than_swallowed() {
        struct Closed;

        impl Write for Closed {
            fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
                Err(io::Error::other("closed"))
            }

            fn flush(&mut self) -> io::Result<()> {
                Err(io::Error::other("closed"))
            }
        }

        assert!(
            hugehelp(&mut Closed).is_err(),
            "the manual must not truncate silently"
        );
    }

    #[test]
    fn a_transient_failure_does_not_abandon_the_remainder() {
        // THE PARITY PROPERTY. `src/mkhelp.pl:231-236` never reads `puts`'s
        // return value, so a failure costs C one line and nothing more. This
        // sink fails once and then works, and every element after the failure
        // must still arrive -- which a `?`-based loop would not deliver.
        struct FailsOnce {
            failed: bool,
            written: Vec<u8>,
        }

        impl Write for FailsOnce {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                if !self.failed {
                    self.failed = true;
                    return Err(io::Error::other("transient"));
                }
                self.written.extend_from_slice(buf);
                Ok(buf.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let mut sink = FailsOnce {
            failed: false,
            written: Vec::new(),
        };
        let outcome = hugehelp(&mut sink);

        // The failure is still reported, because a caller that wants to know
        // can look.
        assert!(outcome.is_err(), "the first failure must be remembered");

        // And the manual is all there except the one element that failed.
        let lost = element(0).len();
        assert_eq!(
            sink.written.len(),
            rendered().len() - lost,
            "exactly the failed element must be missing, and nothing else"
        );
        assert!(
            sink.written.starts_with(b"\n"),
            "the newline that followed the failed element must still be \
             written, as a second `puts` call would write it"
        );
    }
}
