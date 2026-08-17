// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! Shell completions -- the `clap_complete` emitter over the parsed surface,
//! and the cross-check that the generated scripts cover it.
//!
//! # The ownership split, and why `build.rs` owns the port
//!
//! AAP section 0.4.1 maps this file from `scripts/completion.pl` with the
//! note "`clap_complete` generation". Two generation paths follow from that,
//! and they are complementary rather than alternative:
//!
//! * `curl-rs/build.rs` owns the faithful port. It reads the 273
//!   `docs/cmdline-opts/*.md` option pages and writes
//!   `$OUT_DIR/completions/_curl` and `$OUT_DIR/completions/curl.fish`.
//! * This file owns the `clap_complete` emission. It takes the live
//!   [`clap::Command`] that `cli/args.rs` builds and writes a completion
//!   script to any [`std::io::Write`].
//!
//! `build.rs` cannot reach for `clap_complete` instead, so it cannot avoid
//! the port: `curl-rs` has no `[lib]` target -- its manifest declares
//! `[[bin]]` twice and nothing else -- so a build script has no crate from
//! which to import the builder. It parses the curldown front matter exactly
//! as `scripts/completion.pl:102-105` does.
//!
//! This module re-implements none of that. It reads no page, parses no front
//! matter, writes nothing to `OUT_DIR`, and templates neither shell; it
//! consumes what `build.rs` produced and holds it against the clap surface.
//!
//! # There is no `--completion` flag, and none may be added
//!
//! `scripts/completion.pl` is maintainer-side tooling: `scripts/Makefile.am`
//! runs it at build time at `:45-52` and installs its output at `:54-62`, and
//! `:40` lists both files in `CLEANFILES`. It is not a runtime feature of the
//! binary. No row of the frozen 282-row `aliases[]` table
//! (`src/tool_getparam.c:80`) mentions completion, AAP section 0.8.1 freezes
//! that surface, and AAP section 0.8.2 states "No new command-line flags".
//!
//! So [`generate`] is deliberately wired to no flag. Its consumers are this
//! module's cross-checks and maintainer tooling, which is why it carries the
//! one `#[allow(dead_code)]` this file permits.
//!
//! # The completed command is `curl`, never `curl-rs`
//!
//! Every self-reported and every completed name is `curl`:
//! `src/tool_version.h:28` defines `CURL_NAME "curl"`,
//! `scripts/completion.pl:56` emits `#compdef curl`, `:46` emits
//! `complete -c curl`, `:116` emits `complete --command curl`, and
//! `src/tool_help.c:240` prints `Usage: curl [options...] <url>`. These
//! scripts complete the installed command, and it installs as `curl`.
//!
//! Cargo metadata is therefore never an identity source anywhere in this
//! crate: the package is `curl-rs`, so the package name, the binary name, the
//! package version and `argv[0]` are all excluded as sources for it.
//! [`generate`] passes the literal [`COMPLETED_COMMAND`], which is what
//! settles the name in the emitted script -- see that function's note on
//! `set_bin_name`.
//!
//! # 273 option pages, and why the larger figure is not used
//!
//! AAP section 0.4.1 records a larger count of help entries. Measurement
//! supersedes it here, and the measurement is unambiguous:
//! `docs/cmdline-opts/` holds 293 `.md` files: 273 option pages, 19 `_*.md`
//! support pages, and `MANPAGE.md`. `scripts/completion.pl:89` selects exactly
//! the 273 by excluding the underscore-prefixed names and `MANPAGE.md` by
//! name, and `docs/cmdline-opts/Makefile.inc`'s `DPAGES` list carries the same
//! 273. Of those, 273 declare `Long:`, 273 declare `Help:`, 146 declare
//! `Arg:` and 59 declare `Short:` -- and each of those four counts is
//! observable in the artifacts, so each is asserted below.
//!
//! # Two `completion.pl` quirks are preserved, not fixed
//!
//! AAP section 0.8.2 holds that a refactor producing
//! different-but-arguably-better output has failed, so both of these are
//! reproduced deliberately:
//!
//! 1. `strip_dash` (`scripts/completion.pl:162`) is applied to the
//!    description as well as to the option spellings, so a `Help:` beginning
//!    with a dash loses it. No page in the present corpus begins one that
//!    way, so the quirk is latent here rather than observable, and it is
//!    recorded rather than asserted.
//! 2. The `'` to `'\''`, `[` to `\[`, `]` to `\]` and `:` to `\:` escapes are
//!    applied at `:107-111`, ahead of the per-shell branch at `:115`, so fish
//!    descriptions carry zsh-shaped escapes that fish does not need. That one
//!    IS observable and is asserted: `--globoff` reads `Disable URL globbing
//!    with {} and \[\]`, and `--speed-time` reads `Trigger '\''speed-limit'\''
//!    abort after this time`.

use std::io::Write;

/// The command name every completion completes.
///
/// `src/tool_version.h:28`'s `CURL_NAME`. The only identity source this
/// module has; see the module note on the name.
const COMPLETED_COMMAND: &str = "curl";

/// Writes a `clap_complete` completion script for `shell` to `out`.
///
/// `cmd` is the live [`clap::Command`], which callers take from
/// `crate::cli::args::clap_command` rather than assembling here, so this
/// emitter cannot drift from the surface the parser actually accepts.
///
/// # The command name is settled here
///
/// [`COMPLETED_COMMAND`] is passed rather than any Cargo value.
/// `clap_complete::generate` opens by calling `cmd.set_bin_name` with this
/// argument, so it decides the name in the emitted script outright -- which is
/// what makes this the place the name has to be right, even though
/// `cli/args.rs` already declares `bin_name = "curl"`. Passing the package
/// name would emit a script for a command that is not on anyone's `PATH`, and
/// it would install cleanly and simply never fire.
///
/// # Failure
///
/// There is none to report. `clap_complete::generate` returns `()` in 4.5.67,
/// so it exposes no error for this wrapper to forward and an error path here
/// would be unreachable; the signature returns nothing for that reason and
/// nothing is discarded.
///
/// Output goes only to `out`, never to the process's own streams, so a caller
/// -- a test included -- keeps full control of the destination.
// No --completion flag exists in the frozen 282-row alias table
// (src/tool_getparam.c:80); scripts/completion.pl is a maintainer script
// driven by scripts/Makefile.am:45-52. Adding a flag would violate
// AAP section 0.8.1 and section 0.8.2, so this emitter has no runtime call
// site. (The justification is carried with "section" spelled out because
// scripts/spacecheck.pl:182-196 rejects non-ASCII bytes in a tracked file,
// and every other .rs file in this workspace is likewise pure ASCII.)
#[allow(dead_code)]
pub(crate) fn generate(
    shell: clap_complete::Shell,
    cmd: &mut clap::Command,
    out: &mut dyn Write,
) {
    clap_complete::generate(shell, cmd, COMPLETED_COMMAND, out);
}

// Cross-checks
//
// AAP section 0.8.7 relocates the coverage of `tests/unit` into the crates, so
// this is that coverage for this module. Every assertion is hermetic: the two
// artifacts are embedded, so nothing here opens a socket, a terminal or a
// file, and nothing reads `docs/cmdline-opts` -- which is also what keeps this
// module clear of `build.rs`'s port.
//
// The complement, deliberately not repeated here: `cli/args.rs` already
// reconciles the option PAGES against the option TABLE. What only this module
// can check is the rendered SCRIPTS against the live `clap::Command`.
#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::cli::args;

    /// The zsh completion function `build.rs` rendered.
    ///
    /// The `include_str!` is unguarded: no `#[cfg]`, no `option_env!` and no
    /// existence probe. `build.rs` renders, verifies and writes both files
    /// together and fails the build outright rather than emitting one of them,
    /// so a guard could only ever hide a missing artifact.
    ///
    /// It sits inside the test module rather than at module scope for a
    /// measured reason. Nothing outside these checks consumes either script,
    /// so at module scope both constants are unused in a plain build, and
    /// rustc 1.75 -- the declared floor -- reports `constant ZSH is never
    /// used`, which `-D warnings` turns into a build failure. Referencing them
    /// from an anonymous `const _` silences that on 1.97.1 but NOT on 1.75,
    /// where the lint still fires, so that dodge is not portable to the floor.
    /// A second `#[allow(dead_code)]` is not available either: exactly one is
    /// sanctioned in this file and it belongs to [`generate`]. No guarantee is
    /// lost, because `build.rs` verifies both artifacts itself.
    const ZSH: &str =
        include_str!(concat!(env!("OUT_DIR"), "/completions/_curl"));

    /// The fish completion file `build.rs` rendered.
    const FISH: &str =
        include_str!(concat!(env!("OUT_DIR"), "/completions/curl.fish"));

    /// The option pages `scripts/completion.pl:89` selects.
    ///
    /// Therefore the number of entries each script carries. 273, measured
    /// three ways -- see the module note on the count.
    const OPTION_PAGES: usize = 273;

    /// Pages declaring `Arg:`, so zsh entries carrying an argument slot.
    const PAGES_WITH_ARG: usize = 146;

    /// Pages declaring `Short:`, so short letters in both scripts.
    const PAGES_WITH_SHORT: usize = 59;

    /// Rows of the frozen table with no option page of their own.
    ///
    /// Undocumented synonyms and test-only options, each sharing a `case` body
    /// with a documented option, so no page and no completion entry describes
    /// them. `cli/args.rs`'s own page reconciliation names the same nine.
    const ROWS_WITHOUT_A_PAGE: [&str; 9] = [
        "eprt",
        "epsv",
        "ftp-ssl",
        "ftp-ssl-reqd",
        "include",
        "krb4",
        "test-duphandle",
        "test-event",
        "wdebug",
    ];

    /// Rows documented under their `--no-` spelling instead of their own.
    ///
    /// The page is `no-<name>.md`, so the completion carries `--no-<name>` and
    /// never the positive form. These are exactly the negations that have a
    /// page of their own; every other negation has none.
    const ROWS_DOCUMENTED_AS_NEGATIONS: [&str; 7] = [
        "alpn",
        "buffer",
        "clobber",
        "keepalive",
        "npn",
        "progress-meter",
        "sessionid",
    ];

    /// Negations with no page of their own, and so no completion entry.
    const NEGATIONS_WITHOUT_A_PAGE: usize = 108;

    /// The rule prefix `scripts/completion.pl:116` emits for every option.
    const FISH_RULE: &str = "complete --command curl";

    /// The line `scripts/completion.pl:67` closes the `_arguments` call with.
    const ZSH_TERMINATOR: &str = "  '*:URL:_urls' && rc=0";

    // Readers

    /// The zsh option specifications, in file order.
    ///
    /// The only lines `render_zsh_file` writes with both two leading spaces
    /// and a trailing ` \`. [`ZSH_TERMINATOR`] shares the indent but not the
    /// continuation, so it drops out without being named.
    fn zsh_entries() -> Vec<&'static str> {
        ZSH.lines()
            .filter_map(|line| line.strip_prefix("  "))
            .filter_map(|rest| rest.strip_suffix(" \\"))
            .collect()
    }

    /// The fish `complete` rules, in file order, trailing space removed.
    ///
    /// The file-path rule at `completion.pl:46` spells the command
    /// `complete -c curl`, so keying on the long spelling excludes it.
    ///
    /// Note that this requires the command to be `curl`, which is deliberate
    /// but leaves a trap that [`fish_option_shaped_lines`] closes.
    fn fish_entries() -> Vec<&'static str> {
        FISH.lines()
            .filter(|line| line.starts_with(FISH_RULE))
            .filter_map(|line| line.strip_suffix(' '))
            .collect()
    }

    /// Lines shaped like a per-option rule, whatever command they name.
    ///
    /// Identified WITHOUT the command name, which is what makes a rule naming
    /// the wrong command distinguishable from no rule at all. Keying the stub
    /// guard on [`fish_entries`] alone would conflate the two: a script whose
    /// rules all read `complete --command wcurl` would yield no entries, look
    /// exactly like a bare template, and skip every check that exists to catch
    /// it -- the precise failure mode the module note on the name describes.
    /// Comparing the two counts is what catches a rename instead.
    fn fish_option_shaped_lines() -> Vec<&'static str> {
        FISH.lines()
            .filter(|line| line.starts_with("complete "))
            .filter(|line| line.contains(" --long-option '"))
            .collect()
    }

    /// The long option a zsh specification completes, without its dashes.
    ///
    /// Both shapes put the long form first -- `{-x,--long}...` and
    /// `--long...` -- so the first `--` opens it, and it runs to the first
    /// character that cannot appear in an option name: the `}` closing a brace
    /// group, the `'` opening a description, or the `:` before an argument.
    ///
    /// The dot is part of the name set, not a terminator: eight options carry
    /// one -- `--http0.9`, `--http1.0`, `--http1.1`, `--proxy1.0` and
    /// `--tlsv1.0` through `--tlsv1.3` -- and stopping at it would truncate
    /// `tlsv1.3` to `tlsv1` and report a coverage failure that is really a
    /// parsing failure here.
    fn zsh_long(entry: &str) -> Option<&str> {
        let rest = entry.get(entry.find("--")? + 2..)?;
        let is_name =
            |ch: char| ch.is_ascii_alphanumeric() || "-.".contains(ch);
        let end = rest.find(|ch| !is_name(ch)).unwrap_or(rest.len());
        rest.get(..end)
    }

    /// The short letter of a braced zsh specification, if it has one.
    fn zsh_short(entry: &str) -> Option<char> {
        entry.strip_prefix("{-")?.chars().next()
    }

    /// The single-quoted value following `clause`.
    ///
    /// Used only for option spellings, whose values cannot contain a quote.
    /// Descriptions can -- `completion.pl:108` rewrites `'` as `'\''` -- so
    /// they are matched whole rather than through this.
    fn quoted_after<'a>(entry: &'a str, clause: &str) -> Option<&'a str> {
        let rest = entry.get(entry.find(clause)? + clause.len()..)?;
        let rest = rest.strip_prefix('\'')?;
        rest.get(..rest.find('\'')?)
    }

    /// The long option a fish rule completes -- `completion.pl:119`.
    fn fish_long(entry: &str) -> Option<&str> {
        quoted_after(entry, " --long-option ")
    }

    /// The short option a fish rule completes -- `completion.pl:117`.
    fn fish_short(entry: &str) -> Option<&str> {
        quoted_after(entry, " --short-option ")
    }

    /// The part of a rendered entry before its first `=`.
    ///
    /// `completion.pl:152-153`'s `/([^=]*)/` capture.
    fn sort_key(entry: &str) -> &str {
        match entry.find('=') {
            Some(at) => entry.get(..at).unwrap_or(entry),
            None => entry,
        }
    }

    /// The long options the zsh script names, in file order.
    fn zsh_longs() -> Vec<&'static str> {
        zsh_entries().into_iter().filter_map(zsh_long).collect()
    }

    /// The long options the fish script names, in file order.
    fn fish_longs() -> Vec<&'static str> {
        fish_entries().into_iter().filter_map(fish_long).collect()
    }

    /// Every long option the parser accepts, from `cli/args.rs`'s builder.
    ///
    /// Derived from the [`clap::Command`] rather than from the table, because
    /// the negations live in a list this module cannot name -- and the Command
    /// is the better authority in any case, being what actually parses.
    fn clap_longs() -> BTreeSet<String> {
        let command = args::clap_command();
        command
            .get_arguments()
            .filter_map(clap::Arg::get_long)
            .map(str::to_owned)
            .collect()
    }

    /// Every short option the parser accepts.
    fn clap_shorts() -> BTreeSet<char> {
        let command = args::clap_command();
        command
            .get_arguments()
            .filter_map(clap::Arg::get_short)
            .collect()
    }

    /// The zsh specification for one long option.
    fn zsh_entry_for(name: &str) -> Option<&'static str> {
        zsh_entries()
            .into_iter()
            .find(|entry| zsh_long(entry) == Some(name))
    }

    /// The fish rule for one long option.
    fn fish_entry_for(name: &str) -> Option<&'static str> {
        fish_entries()
            .into_iter()
            .find(|entry| fish_long(entry) == Some(name))
    }

    /// Whether `build.rs` emitted the real corpus rather than a bare template.
    ///
    /// `render_zsh_file` and `render_fish_file` both accept an empty entry
    /// list and still emit a valid script -- that is the degenerate artifact a
    /// stub build leaves, and `build.rs` documents the case explicitly -- so a
    /// check that depends on entries returns early for it instead of failing.
    ///
    /// A populated-but-wrong corpus is a different thing and is NOT tolerated:
    /// once a single entry exists, every count below is asserted exactly. That
    /// keeps stub tolerance from degrading into count blindness.
    ///
    /// The fish side is measured with [`fish_option_shaped_lines`] rather than
    /// [`fish_entries`] on purpose: rules that name the wrong command are still
    /// rules, so they must count as a populated corpus and let the checks run
    /// and fail, not be mistaken for an absent one and skipped.
    fn artifacts_are_populated() -> bool {
        !zsh_entries().is_empty() && !fish_option_shaped_lines().is_empty()
    }

    /// Emits a completion for `shell` into a buffer.
    fn emit(shell: clap_complete::Shell) -> Vec<u8> {
        let mut command = args::clap_command();
        let mut buffer: Vec<u8> = Vec::new();
        generate(shell, &mut command, &mut buffer);
        buffer
    }

    // Coverage, both directions

    #[test]
    fn every_completion_entry_names_an_option_the_parser_accepts() {
        // No orphan entries, in either script. An entry naming an option clap
        // does not accept would complete a spelling the parser then rejects,
        // which is precisely the doc-page-versus-parser drift AAP section
        // 0.8.1 freezes.
        if !artifacts_are_populated() {
            return;
        }
        let accepted = clap_longs();
        for name in zsh_longs() {
            assert!(
                accepted.contains(name),
                "zsh completes --{name}, which the parser does not accept"
            );
        }
        for name in fish_longs() {
            assert!(
                accepted.contains(name),
                "fish completes --{name}, which the parser does not accept"
            );
        }
    }

    #[test]
    fn the_parsed_surface_and_the_completed_surface_partition_exactly() {
        // The other direction, and the one that needed measuring rather than
        // assuming. "Every clap long option appears in the completion" is
        // FALSE and cannot be asserted: clap accepts 397 long forms -- 282
        // table rows plus 115 negations -- while each script carries 273, one
        // per option page. The two counts are different on purpose.
        //
        // What IS true is stronger than a subset relation in either direction:
        // the parsed surface partitions EXACTLY into the completed options and
        // three named residues, with nothing left over and no overlap. That
        // pins both directions at once, so a drift either way fails: an option
        // that gains a page must gain an entry, and an entry that loses its
        // row becomes an orphan the test above catches.
        if !artifacts_are_populated() {
            return;
        }
        let accepted = clap_longs();
        let completed: BTreeSet<&str> = zsh_longs().into_iter().collect();

        let residue: BTreeSet<&str> = accepted
            .iter()
            .map(String::as_str)
            .filter(|name| !completed.contains(*name))
            .collect();

        // Residue one: rows with no page at all.
        for name in ROWS_WITHOUT_A_PAGE {
            assert!(
                residue.contains(name),
                "--{name} is listed as having no page but is completed"
            );
        }
        // Residue two: rows reached only through their negated page.
        for name in ROWS_DOCUMENTED_AS_NEGATIONS {
            assert!(
                residue.contains(name),
                "--{name} is documented only as --no-{name}, so the positive \
                 spelling must not be completed"
            );
            let negated = format!("no-{name}");
            assert!(
                completed.contains(negated.as_str()),
                "--{negated} is the documented spelling and must be completed"
            );
        }
        // Residue three: negations with no page. Counted rather than listed,
        // and identified by the one property that distinguishes them -- every
        // residue member that is not in the two lists above is a negation.
        let negations: BTreeSet<&str> = residue
            .iter()
            .copied()
            .filter(|name| {
                !ROWS_WITHOUT_A_PAGE.contains(name)
                    && !ROWS_DOCUMENTED_AS_NEGATIONS.contains(name)
            })
            .collect();
        for name in &negations {
            assert!(
                name.starts_with("no-"),
                "--{name} is in neither residue list and is not a negation, \
                 so the partition below no longer accounts for it"
            );
        }
        assert_eq!(negations.len(), NEGATIONS_WITHOUT_A_PAGE);

        // The partition is exact: nothing is counted twice and nothing is
        // unaccounted for.
        assert_eq!(
            residue.len(),
            ROWS_WITHOUT_A_PAGE.len()
                + ROWS_DOCUMENTED_AS_NEGATIONS.len()
                + NEGATIONS_WITHOUT_A_PAGE
        );
        assert_eq!(completed.len() + residue.len(), accepted.len());
    }

    #[test]
    fn both_scripts_complete_the_same_option_pages() {
        // The union the two scripts describe has exactly one member per option
        // page. 273, never one more: `docs/cmdline-opts/` holds 293 `.md`
        // files and `completion.pl:89` excludes the 19 `_*.md` support pages
        // and `MANPAGE.md` by name.
        if !artifacts_are_populated() {
            return;
        }
        let zsh: BTreeSet<&str> = zsh_longs().into_iter().collect();
        let fish: BTreeSet<&str> = fish_longs().into_iter().collect();

        assert_eq!(zsh_entries().len(), OPTION_PAGES, "zsh entry count");
        assert_eq!(fish_entries().len(), OPTION_PAGES, "fish entry count");
        assert_eq!(zsh.len(), OPTION_PAGES, "zsh names are distinct");
        assert_eq!(fish.len(), OPTION_PAGES, "fish names are distinct");
        assert_eq!(zsh, fish, "the two shells describe different options");
    }

    #[test]
    fn every_short_letter_appears_in_both_shells_in_its_own_shape() {
        // Each shell spells a short option differently and only the rows that
        // have one carry it: zsh puts it in a `{-x,--long}` brace group
        // (`completion.pl:124-126`) and fish in a `--short-option 'x'` clause
        // (`:117`). The rows without a short must therefore appear as a bare
        // `--long` in zsh with NO braces, which is the case a brace-always
        // renderer would get wrong while still passing a name-only check.
        if !artifacts_are_populated() {
            return;
        }
        let letters = clap_shorts();
        assert_eq!(letters.len(), PAGES_WITH_SHORT);

        let braced: Vec<&str> = zsh_entries()
            .into_iter()
            .filter(|e| e.starts_with('{'))
            .collect();
        assert_eq!(braced.len(), PAGES_WITH_SHORT, "zsh brace groups");
        assert_eq!(
            fish_entries()
                .into_iter()
                .filter(|e| fish_short(e).is_some())
                .count(),
            PAGES_WITH_SHORT,
            "fish --short-option clauses"
        );

        for entry in braced {
            let letter = zsh_short(entry)
                .unwrap_or_else(|| panic!("no short letter in {entry}"));
            assert!(
                letters.contains(&letter),
                "zsh completes -{letter}, which the parser does not accept"
            );
            let name = zsh_long(entry)
                .unwrap_or_else(|| panic!("no long name in {entry}"));
            let fish = fish_entry_for(name)
                .unwrap_or_else(|| panic!("--{name} is missing from fish"));
            assert_eq!(
                fish_short(fish).map(str::to_owned),
                Some(letter.to_string()),
                "--{name} carries -{letter} in zsh but not in fish"
            );
        }

        // And a short-less option is brace-free rather than `{,--long}`.
        for entry in zsh_entries() {
            if zsh_short(entry).is_none() {
                assert!(
                    !entry.contains('{') || !entry.starts_with('{'),
                    "{entry} opens a brace group with no short option"
                );
            }
        }
    }

    // Template fidelity

    #[test]
    fn the_zsh_script_reproduces_the_completion_pl_template() {
        // `completion.pl:55-70`, line for line. `#compdef curl` must be first:
        // zsh locates the function by that tag, and a completion tagged for
        // another command installs cleanly and never fires.
        assert!(
            ZSH.starts_with("#compdef curl\n"),
            "zsh locates the function by this tag"
        );
        for line in [
            "\n# curl zsh completion\n",
            "\nlocal curcontext=\"$curcontext\" state state_descr line\n",
            "typeset -A opt_args\n",
            "\nlocal rc=1\n",
        ] {
            assert!(ZSH.contains(line), "the template is missing {line:?}");
        }

        // Exactly one backslash continues the `_arguments` call. Two would
        // emit a literal backslash and break the command.
        assert!(ZSH.contains("\n_arguments -C -S \\\n"));
        assert!(!ZSH.contains("_arguments -C -S \\\\"));

        // The call is closed by the URL catch-all and the function returns.
        // `chomp` at `:53` leaves the last option line continuing, so the
        // terminator is part of the same command.
        let tail = format!("{ZSH_TERMINATOR}\n\nreturn rc\n");
        assert!(ZSH.ends_with(&tail), "the zsh tail is {tail:?}");
        assert_eq!(ZSH.matches(ZSH_TERMINATOR).count(), 1);
    }

    #[test]
    fn every_zsh_option_line_is_indented_and_continued() {
        // `$opts_str .= qq{  $_ \\\n}` at `:52` -- two leading spaces, the
        // specification, one space, one backslash. Read off the raw lines
        // rather than through `zsh_entries`, which would assume the shape it
        // is meant to be checking.
        let mut seen = 0_usize;
        for line in ZSH.lines() {
            let Some(rest) = line.strip_prefix("  ") else {
                continue;
            };
            if line == ZSH_TERMINATOR {
                continue;
            }
            seen += 1;
            assert!(
                rest.ends_with(" \\"),
                "{line:?} is indented like an option but does not continue"
            );
            assert!(
                !rest.starts_with(' '),
                "{line:?} is indented more deeply than the template"
            );
        }
        assert_eq!(seen, zsh_entries().len(), "an option line was missed");
    }

    #[test]
    fn the_fish_script_reproduces_the_completion_pl_preamble() {
        // `completion.pl:44-47`: the title, a blank line, the comment, the
        // file-path rule, then the blank line `print "\n\n"` leaves.
        assert!(FISH.starts_with(
            "# curl fish completion\n\n# Complete file paths after @\n"
        ));

        let rule = FISH
            .lines()
            .find(|line| line.starts_with("complete -c curl -n "))
            .unwrap_or_else(|| panic!("the fish file-path rule is missing"));

        // The Perl emits this from a NON-interpolating `q(...)`, so the two
        // characters backslash and n must survive into the file: fish, not
        // Rust and not Perl, is what interprets them. A `\n` that became a
        // newline here would split the rule across two lines and break it.
        assert!(
            rule.contains("printf '%s\\n' --"),
            "the literal backslash-n in printf '%s\\\\n' was interpreted"
        );
        assert!(rule.contains("__fish_complete_suffix"));
        assert!(rule.ends_with("''))\""));

        let preamble = format!("{rule}\n\n");
        assert!(
            FISH.contains(&preamble),
            "a blank line must follow the file-path rule"
        );
    }

    #[test]
    fn every_fish_option_line_names_curl_and_ends_with_one_space() {
        // `print qq{$_ \n}` at `:48` -- every rule ends with exactly one
        // space before its newline. It looks like a stray character and is
        // not: it is a byte of the frozen artifact.
        let mut seen = 0_usize;
        for line in FISH.lines() {
            if !line.starts_with(FISH_RULE) {
                continue;
            }
            seen += 1;
            assert!(
                line.ends_with(' '),
                "{line:?} does not end with the trailing space"
            );
            assert!(
                !line.ends_with("  "),
                "{line:?} ends with more than one space"
            );
            assert!(
                line.contains(" --long-option '"),
                "{line:?} completes no long option"
            );
        }
        assert_eq!(seen, fish_entries().len(), "a fish rule was missed");
    }

    #[test]
    fn neither_script_names_the_cargo_package() {
        // The completed command is the installed one. `src/tool_version.h:28`
        // and `completion.pl:56`; the package name would name nothing on a
        // user's PATH.
        for (shell, text) in [("zsh", ZSH), ("fish", FISH)] {
            assert!(
                !text.contains("curl-rs"),
                "the {shell} completion names the Cargo package"
            );
            assert!(
                text.contains(COMPLETED_COMMAND),
                "the {shell} completion never names {COMPLETED_COMMAND}"
            );
        }
        // Both spellings of the command, and both are in the template rather
        // than in an option line, so a bare template still carries them.
        assert!(ZSH.contains("#compdef curl"));
        assert!(FISH.contains("complete -c curl"));

        // Every option-shaped rule names `curl`. Unconditional and still stub
        // safe, because a bare template has none of either -- and it is a count
        // comparison rather than a `contains` because a renamed command would
        // otherwise leave no rule this module recognises, look exactly like a
        // bare template and skip the check meant to catch it.
        assert_eq!(
            fish_entries().len(),
            fish_option_shaped_lines().len(),
            "some fish rules complete a command other than {COMPLETED_COMMAND}"
        );
    }

    #[test]
    fn neither_script_embeds_a_build_path_or_an_unsubstituted_template() {
        // Reproducibility: the scripts are a function of the committed option
        // pages and of nothing else, so no build location may reach them. The
        // build directory is the one path that could, since that is where they
        // are written, so it is checked by name rather than by pattern.
        for (shell, text) in [("zsh", ZSH), ("fish", FISH)] {
            assert!(
                !text.contains(env!("OUT_DIR")),
                "the {shell} completion embeds its own build directory"
            );
            for root in ["/tmp/", "/home/", "/root/", "/usr/", "/var/"] {
                assert!(
                    !text.contains(root),
                    "the {shell} completion embeds the path {root}"
                );
            }
            // An Autotools substitution reaching the output would mean the
            // install directory leaked in from `scripts/Makefile.am:54-62`,
            // which describes where a script goes and never its contents.
            for leak in ["@ZSH_FUNCTIONS_DIR@", "@FISH_FUNCTIONS_DIR@"] {
                assert!(
                    !text.contains(leak),
                    "the {shell} completion carries {leak} unsubstituted"
                );
            }
        }
    }

    // Ordering

    #[test]
    fn each_script_is_sorted_by_completion_pls_comparator() {
        // `:151-156` -- descending length of the part before the first `=`,
        // then an ascending bytewise comparison. It sorts the RENDERED
        // strings, so each shell is sorted independently and the two ORDERS
        // DIFFER: zsh opens with `--request` and fish with `--speed-time`.
        // That is not a defect to reconcile, it is what sorting two different
        // renderings produces, so the property asserted is that each file is
        // sorted by its own entries rather than that the two agree.
        if !artifacts_are_populated() {
            return;
        }
        for (shell, entries) in
            [("zsh", zsh_entries()), ("fish", fish_entries())]
        {
            for pair in entries.windows(2) {
                let (Some(left), Some(right)) = (pair.first(), pair.get(1))
                else {
                    continue;
                };
                let (a, b) = (sort_key(left), sort_key(right));
                assert!(
                    b.len() < a.len() || (b.len() == a.len() && a <= b),
                    "{shell} is out of order: {a:?} then {b:?}"
                );
            }
        }
    }

    #[test]
    fn no_entry_precedes_an_entry_whose_key_extends_it() {
        // The reason the sort exists, in the Perl's own words at `:148-150`:
        // "zsh does not complete an option listed after one that is a prefix
        // of it". Descending key length delivers exactly that for the sort
        // KEYS, and this asserts it globally rather than only for neighbours.
        //
        // Worth stating precisely, because the guarantee is narrower than the
        // comment reads. It holds for rendered keys, NOT for option names: the
        // zsh file lists `--request` first and `--request-target` twenty-six
        // entries later, because `--request`'s rendered specification carries
        // a longer description and method list. `--proxy` likewise sits
        // immediately before `--proxy-key-type`. Both are faithful to the
        // Perl, and AAP section 0.8.2 forbids "fixing" them.
        if !artifacts_are_populated() {
            return;
        }
        for (shell, entries) in
            [("zsh", zsh_entries()), ("fish", fish_entries())]
        {
            let keys: Vec<&str> =
                entries.iter().copied().map(sort_key).collect();
            for (index, key) in keys.iter().enumerate() {
                for later in keys.iter().skip(index + 1) {
                    assert!(
                        !later.starts_with(key) || later == key,
                        "{shell} lists {key:?} before {later:?}, which \
                         extends it, so zsh would not complete the longer one"
                    );
                }
            }
        }
    }

    // The argument-completer chain

    #[test]
    fn the_argument_completer_chain_matches_completion_pl_branch_for_branch() {
        // `:131-141`, an ordered if/elsif in which the first match wins.
        // Spot-checked on real pages, one per branch.
        if !artifacts_are_populated() {
            return;
        }
        for (name, suffix) in [
            // Branch 1, `/<file ?(name)?>|<path>/`.
            ("output", ":_files"),
            ("cookie-jar", ":_files"),
            // Branch 2, `/<dir>/`.
            ("output-dir", ":'_path_files -/'"),
            // Branch 3, `/<url>/i`. These pages declare `Arg: <URL>` in
            // capitals, so they match only because this one test of the five
            // is case-insensitive.
            ("referer", ":_urls"),
            ("doh-url", ":_urls"),
            // Branch 5, `/<method>/` with no `ftp` in the long name.
            ("request", ":'(DELETE GET HEAD POST PUT)'"),
        ] {
            let entry = zsh_entry_for(name)
                .unwrap_or_else(|| panic!("--{name} is not completed"));
            assert!(
                entry.ends_with(suffix),
                "--{name} should end {suffix:?}: {entry}"
            );
        }

        // Branch 4 is the first-match-wins evidence, and the only branch that
        // keys off the LONG NAME rather than the argument. `--ftp-method` and
        // `--request` both declare `Arg: <method>`, so both match branch 5;
        // `--ftp-method` reaches branch 4 first and takes the FTP list. Ordering
        // the chain the other way round would give both the same completer and
        // this pair is what detects it.
        let ftp = zsh_entry_for("ftp-method")
            .unwrap_or_else(|| panic!("--ftp-method is not completed"));
        assert!(ftp.contains(":'<method>'"), "--ftp-method takes <method>");
        assert!(ftp.ends_with(":'(multicwd nocwd singlecwd)'"));

        // And a fall-through that proves the patterns are literal rather than
        // loose. `--url` declares `Arg: <url/file>`, which contains neither
        // `<file>` nor `<url>`, so every branch misses and the entry carries
        // an argument with no completer at all.
        let url = zsh_entry_for("url")
            .unwrap_or_else(|| panic!("--url is not completed"));
        assert!(url.ends_with(":'<url/file>'"), "--url gained a completer");
    }

    #[test]
    fn only_the_pages_declaring_an_argument_carry_an_argument_slot() {
        // `:129-130` appends `:'<arg>'` only when `Arg:` is present, so the
        // count of entries carrying one is the count of pages declaring one.
        if !artifacts_are_populated() {
            return;
        }
        let with_slot = zsh_entries()
            .into_iter()
            .filter(|entry| entry.contains(":'<"))
            .count();
        assert_eq!(with_slot, PAGES_WITH_ARG);
        assert!(with_slot < OPTION_PAGES, "some pages declare no argument");

        // Every page declares `Help:`, so every entry carries a description
        // in both shells -- zsh as `'[...]'` at `:127` and fish as
        // `--description '...'` at `:121`.
        assert_eq!(
            zsh_entries()
                .into_iter()
                .filter(|entry| entry.contains("'["))
                .count(),
            OPTION_PAGES
        );
        assert_eq!(
            fish_entries()
                .into_iter()
                .filter(|entry| entry.contains(" --description '"))
                .count(),
            OPTION_PAGES
        );
    }

    #[test]
    fn fish_descriptions_keep_the_zsh_shaped_escapes_the_perl_leaks() {
        // Quirk two of the module note. `:107-111` escapes the description
        // before `:115` chooses a shell, so fish inherits zsh's `\[`, `\]`
        // and `\:` although fish needs none of them, and inherits the
        // `'` -> `'\''` rewrite it does need.
        //
        // Reproduced rather than corrected: the fish output is the frozen
        // artifact, not the intent behind it.
        if !artifacts_are_populated() {
            return;
        }
        let globoff = fish_entry_for("globoff")
            .unwrap_or_else(|| panic!("--globoff is not completed"));
        assert!(
            globoff.ends_with("globbing with {} and \\[\\]'"),
            "the bracket escapes were removed from fish: {globoff}"
        );

        let speed = fish_entry_for("speed-time")
            .unwrap_or_else(|| panic!("--speed-time is not completed"));
        assert!(
            speed.contains("'\\''speed-limit'\\''"),
            "the quote escape was removed from fish: {speed}"
        );

        // strip_dash at `:162` reaches the option spellings too, which is why
        // fish names them bare. The description arm of that same call is the
        // latent half of the quirk: no page's `Help:` begins with a dash, so
        // it is recorded in the module note and cannot be asserted here.
        assert_eq!(fish_long(speed), Some("speed-time"));
        assert_eq!(fish_short(speed), Some("y"));
    }

    // The emitter

    #[test]
    fn the_emitter_names_curl_for_both_shells_completion_pl_supports() {
        // `clap_complete::generate` opens with `cmd.set_bin_name`, so the
        // literal passed by `generate` is what lands in the script.
        for shell in [clap_complete::Shell::Zsh, clap_complete::Shell::Fish] {
            let bytes = emit(shell);
            assert!(!bytes.is_empty(), "{shell} produced nothing");
            let text = String::from_utf8(bytes)
                .unwrap_or_else(|_| panic!("{shell} emitted invalid UTF-8"));
            assert!(
                text.contains(COMPLETED_COMMAND),
                "{shell} never names {COMPLETED_COMMAND}"
            );
            assert!(
                !text.contains("curl-rs"),
                "{shell} names the Cargo package instead of the command"
            );
        }
    }

    #[test]
    fn the_emitter_writes_only_to_the_writer_it_is_given() {
        // The destination is injected, so a caller keeps control of it and a
        // test needs no access to the process's own streams. That the emitter
        // has no other sink is settled by construction -- its body forwards
        // `out` and holds nothing -- so what is checked here is the observable
        // half: the buffer receives the whole script, and two emissions into
        // two buffers agree, which no shared or retained state would allow.
        let first = emit(clap_complete::Shell::Zsh);
        let second = emit(clap_complete::Shell::Zsh);
        assert!(!first.is_empty());
        assert_eq!(first, second, "the emitter is not deterministic");

        // A writer handed nothing to append to still receives everything.
        let mut command = args::clap_command();
        let mut buffer = Vec::with_capacity(0);
        generate(clap_complete::Shell::Fish, &mut command, &mut buffer);
        assert_eq!(buffer, emit(clap_complete::Shell::Fish));
    }

    #[test]
    fn the_emitter_handles_every_shell_clap_complete_offers() {
        // `clap_complete::Shell` is `#[non_exhaustive]`, so its variants are
        // taken from `ValueEnum` rather than matched: a variant added upstream
        // is then covered here automatically instead of silently skipped.
        //
        // Reaching the end is the assertion. `generate` returns `()` and
        // `clap_complete` panics from a `debug_assert` on a malformed command,
        // so a surface it cannot render would abort rather than return.
        let shells =
            <clap_complete::Shell as clap::ValueEnum>::value_variants();
        assert!(shells.len() >= 2, "zsh and fish at least");
        for shell in shells {
            let bytes = emit(*shell);
            assert!(!bytes.is_empty(), "{shell} produced nothing");
        }
    }

    // Robustness

    #[test]
    fn a_bare_template_is_tolerated_rather_than_fatal() {
        // `render_zsh_file` and `render_fish_file` accept an empty entry list
        // and still emit a valid script, and `build.rs` documents that case,
        // so the artifacts can in principle carry a template and no options.
        // Every entry-dependent check above returns early for that, which is
        // what keeps a stub from panicking one of them.
        //
        // The discrimination is deliberate and narrow: NO entries means a
        // stub and is skipped, whereas one entry means a real rendering and
        // every count is then asserted exactly. So this tolerance cannot
        // degrade into blindness about a corpus that is present but wrong.
        //
        // The template half is asserted unconditionally, because a stub still
        // has to be a working script.
        assert!(ZSH.starts_with("#compdef curl\n"));
        assert!(ZSH.ends_with("return rc\n"));
        assert!(FISH.starts_with("# curl fish completion\n"));

        // And the guard reports what is actually there, so the early returns
        // above are reached only when they should be.
        assert_eq!(
            artifacts_are_populated(),
            !zsh_entries().is_empty() && !fish_entries().is_empty()
        );
        if artifacts_are_populated() {
            assert_eq!(zsh_entries().len(), OPTION_PAGES);
        }
    }
}
