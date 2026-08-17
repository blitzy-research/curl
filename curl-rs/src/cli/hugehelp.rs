// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! The built-in manual -- `src/tool_hugehelp.c`, which is a build artifact.
//!
//! `ls src/tool_hugehelp.c` finds a file only because a build has run;
//! `src/.gitignore:7` lists `tool_hugehelp.c`, so it is generated, never
//! committed. `src/mkhelp.pl` writes it from `docs/cmdline-opts/*.md` at build
//! time, and AAP section 0.2.1 makes reproducing that generator mandatory rather
//! than optional: hand-writing its output would guarantee eventual drift from
//! the 293 option pages it is derived from.
//!
//! This module is the Rust half of that arrangement. `curl-rs/build.rs`
//! reproduces the generator and writes `$OUT_DIR/hugehelp.rs`; this file is the
//! consumer named in that script's own artifact contract, and it does nothing
//! except include the result and present it the way C presents it.
//!
//! # Which of `mkhelp.pl`'s two branches this is
//!
//! `src/mkhelp.pl` emits one of two shapes, and the difference is not cosmetic:
//!
//! * **The compressed branch** (`:81-224`, taken when `HAVE_LIBZ`) writes the
//!   manual as a gzip stream in a `static const unsigned char hugehelpgz[]` and
//!   inflates it at run time through `inflateInit2(&z, -MAX_WBITS)`.
//! * **The plain branch** (`:228-236`) writes a `NULL`-terminated
//!   `static const char * const curlman[]` and walks it:
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
//! artifact declares `pub(crate) const MANUAL: &[&str]` with, in its own header
//! comment, "one element per manual line, sentinel omitted". The sentinel is
//! dropped because a Rust slice carries its own length: C needs the `NULL` to
//! know where to stop, and reproducing it would put an element in the slice that
//! [`hugehelp`] would then have to special-case.
//!
//! Choosing the plain branch is a deliberate consequence of AAP section 0.5.1
//! rather than a shortcut. Compressing at build time and inflating at run time
//! would make the manual depend on `flate2` from the *tool* crate, and the
//! emitted bytes are identical either way -- `puts` per line in both branches --
//! so the compressed form buys only binary size, which is not an objective
//! anywhere in the request. Section 0.1.1 records that performance, and by
//! extension size, is explicitly a non-goal.
//!
//! # `USE_MANUAL` is a real switch in C and is not reproduced as one
//!
//! Both C functions sit inside `#ifdef USE_MANUAL` (`src/tool_hugehelp.h:28-31`),
//! and `src/tool_operate.c:2306-2311` has an `#else` arm that warns "built-in
//! manual was disabled at build-time". Here the manual is unconditional: `build.rs`
//! generates the artifact on every build, so there is no configuration in which
//! it is absent and no arm for the warning to be emitted from. That is a
//! narrowing of C's build matrix, not of its behaviour -- a curl built with
//! `USE_MANUAL` behaves exactly as this does, and `--manual` is documented
//! without qualification in `docs/cmdline-opts/manual.md`.

use crate::cli::help;
use std::io::{self, Write};

// Brings `pub(crate) const MANUAL: &[&str]` into scope -- one element per line of
// the rendered manual, with no terminating sentinel.
//
// Included rather than declared so that the manual cannot be edited in place: the
// only way to change it is to change `docs/cmdline-opts/*.md` and let `build.rs`
// regenerate, which is the same discipline the C build enforces by gitignoring its
// output.
//
// A `//` comment rather than `///`: rustdoc emits nothing for a macro invocation,
// so a doc comment here is `unused_doc_comments` -- a warning, and AAP section
// 0.8.4's first gate is a zero-warning build.
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
/// costs C one line and cost this function the entire remainder of the manual.
///
/// So the loop is unconditional and the *first* error is remembered and returned
/// at the end. That gives a caller strictly more than C has, without changing
/// what reaches the stream: `crate::outcome_for` discards the result, exactly as
/// C's `--manual` arm at `src/tool_operate.c:2309` does, and a caller that wants
/// to know can look.
pub(crate) fn hugehelp<W: Write>(sink: &mut W) -> io::Result<()> {
    let mut first_failure: Option<io::Error> = None;

    for line in MANUAL {
        // One `write_all` per element plus one for the newline would double the
        // syscall count on an unbuffered sink, so the newline goes out with the
        // line. `writeln!` is not used because it would format, and these bytes
        // are already final.
        //
        // `write_all` is used rather than `write` because a short write is not a
        // failure and C's `puts` writes the whole string; the two calls are
        // sequenced so a failure on the line does not suppress the newline, which
        // is what `puts` -- one call per element -- would also do.
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
/// Each manual line is fed **as its own piece**, and the separating newline is
/// fed **as a second, one-byte piece**. C does that because the array elements
/// carry no line terminator, and the matcher recognises line boundaries only by
/// seeing a `\n` byte go past. Concatenating the two would produce the same
/// bytes on the wire but a different number of `helpscan` calls, and the return
/// value is checked after each one -- so the concatenated form would fail to
/// stop between a line and its newline. The two calls are therefore kept
/// separate, and the short-circuit `||` is preserved: the newline is fed only
/// when the line itself said "keep going".
///
/// Standard output is locked once for the whole scan rather than per line. C
/// gets the same effect implicitly, because its `puts` writes through one
/// line-buffered `FILE *`.
pub(crate) fn showhelp(trigger: &str, arg: &str, endarg: &str) {
    let stdout = io::stdout();
    let mut out = stdout.lock();

    let mut ctx = help::inithelpscan(trigger, arg, endarg);

    for line in MANUAL {
        if !help::helpscan(line.as_bytes(), &mut ctx, &mut out)
            || !help::helpscan(b"\n", &mut ctx, &mut out)
        {
            break;
        }
    }

    let _ = out.flush();
}

/// How many lines the built-in manual has.
///
/// Exposed because it is the cheapest way for a test -- or a caller sizing a
/// buffer -- to establish that the artifact is present and non-trivial without
/// materialising the whole thing.
#[allow(dead_code)]
pub(crate) fn manual_lines() -> usize {
    MANUAL.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_generated_artifact_is_present_and_substantial() {
        // The failure this catches is a generated output with no consumer.
        // If `build.rs` stopped writing
        // `hugehelp.rs` the `include!` above would fail to compile, so reaching
        // this assertion at all proves the artifact exists; the bound proves it
        // is the manual rather than an empty placeholder.
        //
        // `src/tool_hugehelp.c` runs to over 4,600 array elements in this tree,
        // so several thousand is the right order of magnitude. The bound is
        // deliberately loose: it must not fail merely because an option page
        // gained or lost a paragraph.
        assert!(
            manual_lines() > 1000,
            "the built-in manual has only {} lines, which is too few to be the \
             rendered manual",
            manual_lines()
        );
    }

    #[test]
    fn the_logo_is_the_first_thing_the_manual_emits() {
        // `src/mkhelp.pl:20-27` prepends a five-line ASCII logo, and the first
        // of those lines carries the leading tab the script writes. Asserting on
        // it pins the *start* of the artifact, which is the part a truncating
        // generator bug would corrupt first.
        let first = MANUAL.first().expect("the manual must not be empty");
        assert!(
            first.starts_with('\t'),
            "the first manual line must carry mkhelp.pl's leading tab, got {first:?}"
        );
    }

    /// How many elements begin with the folded-blank marker.
    ///
    /// Its own function because two tests need the same count and because
    /// naming it is what makes the newline arithmetic below legible.
    fn folded_blank_elements() -> usize {
        MANUAL.iter().filter(|line| line.starts_with('\n')).count()
    }

    #[test]
    fn each_element_carries_at_most_the_one_folded_blank_marker() {
        // The three properties of `src/mkhelp.pl:210-227` that together make
        // `hugehelp` a faithful `puts` reproduction. All three concern the SAME
        // loop, which is why they are asserted together:
        //
        //   if(!$n) { $blank++; }
        //   else { printf("  \"%s%s\",\n", $blank ? "\\n" : "", $n); $blank = 0; }
        //
        // 1. A blank input line never becomes an element -- it only increments
        //    `$blank`. So no element is empty, and none is newline-only.
        // 2. A blank RUN of any length contributes `$blank ? "\n" : ""`, which is
        //    one newline however many blanks preceded. So no element begins with
        //    two.
        // 3. `chomp` removes the trailing newline and the input is read a line at
        //    a time, so the optional leading marker is the ONLY newline an
        //    element can contain.
        //
        // The first version of this test asserted `!line.contains('\n')` and
        // failed on element 6, `"\n    curl - transfer a URL"`. That was the test
        // being wrong rather than the generator: the leading marker is C's own
        // output, measured at 2261 of 5771 elements. The correct invariant is
        // "at most one, and only in front", which is strictly stronger than the
        // false one it replaces because it also pins properties 1 and 2.
        for (index, line) in MANUAL.iter().enumerate() {
            let body = line.strip_prefix('\n').unwrap_or(line);

            assert!(
                !body.contains('\n'),
                "manual element {index} carries a newline after its first \
                 character, so the generator did not split on lines: {line:?}"
            );
            assert!(
                !body.is_empty(),
                "manual element {index} is blank, but mkhelp.pl folds blank \
                 lines into the next element rather than emitting them: {line:?}"
            );
        }

        // And that the marker is genuinely in use, so the loop above is not
        // vacuously true against an artifact that lost its blank folding.
        assert!(
            folded_blank_elements() > 100,
            "only {} of {} elements carry the folded-blank marker, which is too \
             few for a rendered manual",
            folded_blank_elements(),
            MANUAL.len()
        );
    }

    #[test]
    fn the_writer_emits_one_newline_per_element_plus_the_folded_blanks() {
        // Reproduces `puts` per element and nothing more. Counting newlines is
        // the whole assertion: it catches both a missing separator and a doubled
        // one, which are the two ways a `puts` reproduction goes wrong.
        //
        // The total is `puts`'s one-per-element PLUS the leading markers the
        // elements already carry, because `puts` appends to whatever the string
        // holds rather than replacing it. C emits exactly the same two sources of
        // line feed for exactly the same reason.
        let mut out: Vec<u8> = Vec::new();
        hugehelp(&mut out).expect("a Vec sink cannot fail");

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

        // And the bytes themselves, for the first element, so the assertion is
        // not purely structural.
        let mut expected = MANUAL[0].as_bytes().to_vec();
        expected.push(b'\n');
        assert!(
            out.starts_with(&expected),
            "the first emitted line must be the first manual element"
        );
    }

    #[test]
    fn a_folded_blank_renders_as_a_blank_line_ahead_of_its_text() {
        // The positive form of the invariant above, on real bytes: an element
        // that begins with the marker must appear in the output as an empty line
        // and then its text, which is what `puts("\n    curl - ...")` writes.
        // Without this, the counting test alone could not distinguish a marker
        // that survived from one the writer had stripped.
        let folded = MANUAL
            .iter()
            .find(|line| line.starts_with('\n'))
            .expect("the manual must contain a folded blank");

        let mut out: Vec<u8> = Vec::new();
        hugehelp(&mut out).expect("a Vec sink cannot fail");
        let rendered = String::from_utf8(out).expect("the manual is UTF-8");

        let expected = format!("\n{}\n", folded.trim_start_matches('\n'));
        assert!(
            rendered.contains(&format!("\n{expected}")),
            "a folded blank must render as an empty line before {:?}",
            folded.trim_start_matches('\n')
        );
    }

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
        // must still arrive -- which the earlier `?`-based loop did not deliver.
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

        // The failure is still reported, because a caller that wants to know can.
        assert!(outcome.is_err(), "the first failure must be remembered");

        // And the manual is all there except the one element that failed.
        let mut whole: Vec<u8> = Vec::new();
        hugehelp(&mut whole).expect("a Vec sink cannot fail");
        let first = MANUAL.first().expect("the manual must not be empty");
        let lost = first.len();
        assert_eq!(
            sink.written.len(),
            whole.len() - lost,
            "exactly the failed element must be missing, and nothing else"
        );
        assert!(
            sink.written.starts_with(b"\n"),
            "the newline that followed the failed element must still be written, \
             as a second `puts` call would write it"
        );
    }
}
