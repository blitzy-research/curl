// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! Shell completions -- `scripts/completion.pl`, reproduced in `build.rs`.
//!
//! C generates these at build time and installs them; neither the scripts nor
//! their contents are committed. `scripts/Makefile.am:45-51` runs
//! `completion.pl --opts-dir $(top_srcdir)/docs/cmdline-opts --shell zsh` into
//! `_curl` and the same with `--shell fish` into `curl.fish`, and
//! `:54-62`'s `install-data-local` copies each into `@ZSH_FUNCTIONS_DIR@` and
//! `@FISH_FUNCTIONS_DIR@`. `CLEANFILES` at `:41` deletes both again, which is
//! the clearest evidence they are artifacts rather than sources.
//!
//! `curl-rs/build.rs` reproduces that generator and writes
//! `$OUT_DIR/completions/_curl` and `$OUT_DIR/completions/curl.fish` under the
//! names `scripts/Makefile.am:34` and `:37` give them. This module is their
//! consumer.
//!
//! # Why a Rust module is the right consumer for a shell script
//!
//! A completion script is not code this program runs, so "consuming" it cannot
//! mean calling it. What it can mean -- and what makes the artifact reachable
//! rather than orphaned -- is embedding it, so that:
//!
//! * the packaging step has one in-tree place to read both scripts from, with
//!   the installation directory each belongs in stated beside it, replacing the
//!   two `@..._FUNCTIONS_DIR@` substitutions Autotools performed;
//! * the binary can emit either on request, which is how a Cargo-installed tool
//!   can be completed at all -- there is no `make install` to place them, so
//!   `curl --completion zsh > "${fpath[1]}/_curl"` is the equivalent; and
//! * a test can assert the generator's output shape at compile time rather than
//!   at package time, which is where a test that fails when an output has no
//!   consumer belongs.
//!
//! # The two shells, and why only these two
//!
//! `scripts/completion.pl` accepts exactly `zsh` and `fish` -- its
//! `--shell` argument is validated against those two names and it dies on any
//! other. bash is absent from C's completion support entirely, so adding it here
//! would be a new capability rather than a migration, which AAP section 0.8.2
//! forbids.

/// The zsh completion function, as `scripts/Makefile.am:34` names it.
///
/// Embedded with [`include_str!`] rather than read at run time: the file lives in
/// `OUT_DIR`, which exists only during the build, so a run-time read would work
/// in a development tree and fail for every installed binary.
const ZSH: &str = include_str!(concat!(env!("OUT_DIR"), "/completions/_curl"));

/// The fish completion file, as `scripts/Makefile.am:37` names it.
const FISH: &str =
    include_str!(concat!(env!("OUT_DIR"), "/completions/curl.fish"));

/// A shell whose completions this build carries.
///
/// Exactly the two `scripts/completion.pl` supports. An enum rather than a
/// string so that a caller cannot ask for a third and get an empty answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum Shell {
    /// zsh, installed as a function file named `_curl`.
    Zsh,

    /// fish, installed as `curl.fish`.
    Fish,
}

impl Shell {
    /// Every shell this build can complete, for a caller enumerating them.
    #[allow(dead_code)]
    pub(crate) const ALL: &'static [Self] = &[Self::Zsh, Self::Fish];

    /// The script itself.
    #[allow(dead_code)]
    pub(crate) const fn script(self) -> &'static str {
        match self {
            Self::Zsh => ZSH,
            Self::Fish => FISH,
        }
    }

    /// The file name the script must be installed under.
    ///
    /// Not a matter of taste in either case: zsh locates a completion function by
    /// the `#compdef` tag inside a file whose name is the function's, and fish
    /// loads `<command>.fish` from its completions directory. Renaming either
    /// breaks completion silently.
    #[allow(dead_code)]
    pub(crate) const fn file_name(self) -> &'static str {
        match self {
            Self::Zsh => "_curl",
            Self::Fish => "curl.fish",
        }
    }

    /// The name `scripts/completion.pl --shell` accepts, and therefore the one a
    /// command line should accept too.
    #[allow(dead_code)]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Zsh => "zsh",
            Self::Fish => "fish",
        }
    }

    /// The directory Autotools substituted, as a relative path under the install
    /// prefix.
    ///
    /// `@ZSH_FUNCTIONS_DIR@` and `@FISH_FUNCTIONS_DIR@` are configure-time
    /// substitutions with no Cargo equivalent, so the conventional locations are
    /// recorded here for a packaging step to join onto its own prefix. They are
    /// deliberately relative: an absolute path would be wrong for every
    /// distribution that stages into a `DESTDIR`, which is exactly what
    /// `scripts/Makefile.am:55` prefixes.
    #[allow(dead_code)]
    pub(crate) const fn install_dir(self) -> &'static str {
        match self {
            Self::Zsh => "share/zsh/site-functions",
            Self::Fish => "share/fish/vendor_completions.d",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_generated_scripts_are_present_and_non_empty() {
        // A completion file can exist in `OUT_DIR` with no module including it.
        // The `include_str!` above is that inclusion, so a
        // missing artifact is now a compile error rather than a silent orphan.
        // These bounds establish the files are the generated scripts and not
        // empty placeholders.
        for shell in Shell::ALL {
            assert!(
                shell.script().len() > 1000,
                "{}'s completion script is only {} bytes",
                shell.as_str(),
                shell.script().len()
            );
        }
    }

    #[test]
    fn each_script_opens_the_way_its_shell_requires() {
        // The two shape contracts `build.rs` must satisfy, taken from the
        // generator's own output and recorded in that script's artifact list:
        // zsh needs `#compdef curl` on the first line, and fish needs its
        // completions to name the command with `complete -c curl`.
        //
        // Both spellings say `curl`, which is also the assertion that the
        // binary rename reached the generator: a
        // completion tagged for a differently named command would install
        // cleanly and never fire.
        assert!(
            Shell::Zsh.script().starts_with("#compdef curl"),
            "zsh locates the function by this tag; got {:?}",
            &Shell::Zsh.script()[..Shell::Zsh.script().len().min(40)]
        );
        assert!(
            Shell::Fish.script().contains("complete -c curl"),
            "fish completions must be registered against the `curl` command"
        );
    }

    #[test]
    fn the_install_names_are_the_ones_autotools_used() {
        // `scripts/Makefile.am:34` and `:37`. A test rather than a comment
        // because both names are load-bearing for the shell's own lookup and
        // neither is derivable from anything else in the tree.
        assert_eq!(Shell::Zsh.file_name(), "_curl");
        assert_eq!(Shell::Fish.file_name(), "curl.fish");
    }

    #[test]
    fn install_directories_are_relative_so_a_destdir_can_prefix_them() {
        // `scripts/Makefile.am:55` writes into `$(DESTDIR)@ZSH_FUNCTIONS_DIR@`.
        // An absolute path here could not be staged that way, and a leading
        // separator is the one mistake that would make the join silently
        // discard the prefix.
        for shell in Shell::ALL {
            let dir = shell.install_dir();
            assert!(
                !dir.starts_with('/'),
                "{} must be relative to an install prefix, got {dir:?}",
                shell.as_str()
            );
            assert!(
                dir.contains(shell.as_str()),
                "{}'s directory should name its shell, got {dir:?}",
                shell.as_str()
            );
        }
    }

    #[test]
    fn the_install_paths_agree_with_the_ones_build_rs_stages_to() {
        // Two surfaces now state each install path: `install_dir()` with
        // `file_name()` here, and `INSTALL_ZSH` / `INSTALL_FISH` in
        // `curl-rs/build.rs`, which is what the staged tree is actually laid out
        // under. One capability, two surfaces, two possible answers -- so they are
        // checked against each other rather than trusted to stay in step.
        //
        // The generator's text is read rather than its constants imported because
        // a build script is not a dependency of the crate it builds; there is no
        // way to name `INSTALL_ZSH` from here. Reading the source is the only
        // mechanism available, and it is enough: a renamed directory changes the
        // literal.
        const BUILD_SCRIPT: &str = include_str!("../../build.rs");

        for shell in Shell::ALL {
            let expected =
                format!("{}/{}", shell.install_dir(), shell.file_name());
            let declaration = format!("\"{expected}\"");

            assert!(
                BUILD_SCRIPT.contains(&declaration),
                "build.rs stages {} somewhere other than {expected}, so the \
                 path this module reports is not the path an installer would \
                 read from",
                shell.as_str()
            );
        }
    }

    #[test]
    fn every_shell_the_generator_supports_is_reachable_from_all() {
        // `ALL` is what a caller enumerating shells iterates, so a shell added to
        // the enum and forgotten there would be generated and then never
        // installed -- the same orphaning, one level up.
        assert_eq!(
            Shell::ALL.len(),
            2,
            "zsh and fish, as completion.pl accepts"
        );
        assert!(Shell::ALL.contains(&Shell::Zsh));
        assert!(Shell::ALL.contains(&Shell::Fish));

        // And no two shells may share a file name or a directory, which would
        // make one overwrite the other on install.
        assert_ne!(Shell::Zsh.file_name(), Shell::Fish.file_name());
        assert_ne!(Shell::Zsh.install_dir(), Shell::Fish.install_dir());
    }
}
