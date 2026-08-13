// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! Output surfaces of the command-line tool: diagnostics, progress, formatted
//! results, and everything the tool does to a file it has saved.
//!
//! Seven modules, each superseding one C translation unit of the tool or a
//! pair of them. The fixtures in `tests/data/test*` compare emitted bytes
//! against literal expectations, so a layout that merely reads better is a
//! test failure rather than an improvement.
//!
//! # Two of these are machine-read, not human-read
//!
//! [`writeout`] and [`msgs`] are consumed by the test harness, so their
//! output is a contract with a program rather than with a reader.
//! `--write-out` substitutions appear directly in fixture expectations, and
//! diagnostics land in the `<stderr>` sections that `tests/getpart.pm`
//! compares as a single joined string -- there is no per-line matching and no
//! normalisation, so wording, punctuation and line breaks are all
//! significant.
//!
//! The diagnostic wrap width is worth stating precisely, because it is easy to
//! mistake for a fixed column and it is not one. `src/tool_msgs.c:42-44`
//! computes it as the terminal width minus the width of the prefix, and
//! `src/terminal.c:84-85` supplies 79 when the terminal width is unknown. It
//! is therefore 70 behind `Warning: ` and 73 behind `curl: ` by default, and
//! it moves with the terminal.
//!
//! # Declarations only
//!
//! This root holds no logic and publishes no re-export surface. A convenience
//! re-export here would rebuild exactly the coupling this migration removes,
//! and would blur which module owns which frozen surface -- and that ownership
//! is what keeps the frozen bytes in one place.

/// `--create-dirs` -- supersedes `src/tool_dirhie.c`.
pub(crate) mod dirhie;

/// `-R` / `--remote-time` and the `-z` / `--time-cond` file reader --
/// supersedes `src/tool_filetime.c`.
pub(crate) mod filetime;

/// `-F` / `--form` parsing -- supersedes `src/tool_formparse.c`.
pub(crate) mod formparse;

/// Diagnostics on standard error -- supersedes `src/tool_msgs.c` and
/// `src/tool_stderr.c`.
pub(crate) mod msgs;

/// The parallel-transfer progress meter -- supersedes `src/tool_progress.c`.
/// The single-transfer progress bar is a separate surface and is not here: it
/// belongs to `callbacks/progress.rs`, over `src/tool_cb_prg.c`.
pub(crate) mod progress;

/// `--write-out`, including its JSON form -- supersedes `src/tool_writeout.c`
/// and `src/tool_writeout_json.c`.
pub(crate) mod writeout;

/// `--xattr` -- supersedes `src/tool_xattr.c`.
pub(crate) mod xattr;
