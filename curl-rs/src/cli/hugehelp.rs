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
/// Returns the first write error. C discards `puts`'s return value, so an error
/// is invisible there; it is surfaced here because the caller is `--manual`
/// handling, which can report it, and because silently truncating the manual
/// halfway is worse than saying so. A caller that wants C's exact
/// indifference can discard the result.
///
/// `#[allow(dead_code)]` for the same reason `cli::args` and `cli::libinfo` carry
/// it: the `--manual` arm that calls this lives in `cli::help`, which
/// `cli/mod.rs` records as specified-but-not-yet-declared. The attribute is on the
/// function rather than the module so that it lapses the moment a caller appears.
#[allow(dead_code)]
pub(crate) fn hugehelp<W: Write>(sink: &mut W) -> io::Result<()> {
    for line in MANUAL {
        // One `write_all` per element plus one for the newline would double the
        // syscall count on an unbuffered sink, so the newline goes out with the
        // line. `writeln!` is not used because it would format, and these bytes
        // are already final.
        sink.write_all(line.as_bytes())?;
        sink.write_all(b"\n")?;
    }

    Ok(())
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
}
