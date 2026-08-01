// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! Output surfaces of the command-line tool: diagnostics, progress, formatted
//! results, and everything the tool does to a file it has saved.
//!
//! Seven modules, one per translation unit of the C tool. Each is frozen
//! output rather than a presentation choice, and that distinction governs every
//! decision under this directory: `tests/data/test*` compares emitted bytes
//! against literal expectations, and the harness parses several of these
//! surfaces to decide what to run, so a "nicer" layout is a test failure.
//!
//! | Module | Supersedes | What is frozen |
//! |--------|------------|----------------|
//! | [`msgs`] | `src/tool_msgs.c`, `src/tool_stderr.c` | The `curl: `, `Warning: ` and `Note: ` prefixes, the 78-column wrap, and the word-boundary rule |
//! | [`progress`] | `src/tool_progress.c` | The progress-bar and progress-meter column layout |
//! | [`writeout`] | `src/tool_writeout.c`, `src/tool_writeout_json.c` | The `--write-out` variable vocabulary and the JSON form |
//! | [`formparse`] | `src/tool_formparse.c` | `-F` acceptance: what parses, what is rejected, and with which message |
//! | [`dirhie`] | `src/tool_dirhie.c` | `--create-dirs` path construction and its failure text |
//! | [`filetime`] | `src/tool_filetime.c` | `-R` timestamp preservation |
//! | [`xattr`] | `src/tool_xattr.c` | The extended-attribute names written to a saved file, and their order |
//!
//! # Two of these are machine-read, not human-read
//!
//! [`writeout`] and [`msgs`] are consumed by the test harness, so their output
//! is a contract with a program rather than with a reader. `--write-out`
//! substitutions appear directly in fixture expectations, and diagnostics land
//! in the `<stderr>` sections that `tests/getpart.pm` compares as a single
//! joined string -- there is no per-line matching and no normalization, so
//! wording, punctuation and line breaks are all significant.
//!
//! # Declarations only
//!
//! This root holds no logic and publishes no re-export surface. A caller names
//! the owning module directly, as in `crate::output::msgs`, which is the "one
//! import per type actually used" rule of AAP section 0.4.2 in place of the C
//! tree's blanket `#include`. A convenience re-export here would rebuild
//! exactly the coupling this migration removes.

/// `--create-dirs` -- supersedes `src/tool_dirhie.c`.
pub(crate) mod dirhie;

/// `-R` / `--remote-time` -- supersedes `src/tool_filetime.c`.
pub(crate) mod filetime;

/// `-F` / `--form` parsing -- supersedes `src/tool_formparse.c`.
pub(crate) mod formparse;

/// Diagnostics on standard error -- supersedes `src/tool_msgs.c` and
/// `src/tool_stderr.c`.
pub(crate) mod msgs;

/// The progress meter and progress bar -- supersedes `src/tool_progress.c`.
pub(crate) mod progress;

/// `--write-out`, including its JSON form -- supersedes `src/tool_writeout.c`
/// and `src/tool_writeout_json.c`.
pub(crate) mod writeout;

/// `--xattr` -- supersedes `src/tool_xattr.c`.
pub(crate) mod xattr;
