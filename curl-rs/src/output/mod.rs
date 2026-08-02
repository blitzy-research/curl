// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! Output surfaces of the command-line tool: diagnostics, progress, formatted
//! results, and everything the tool does to a file it has saved.
//!
//! Seven modules, each superseding one C translation unit of the tool or a
//! pair of them. Every one of them is frozen output rather than a
//! presentation choice, and that distinction governs each decision under this
//! directory: AAP section 0.3.4 records these surfaces as "migration targets,
//! not design decisions", and AAP section 0.8.1 freezes them. The fixtures in
//! `tests/data/test*` compare emitted bytes against literal expectations, so a
//! layout that merely reads better is a test failure rather than an
//! improvement.
//!
//! # What each module owns
//!
//! * [`dirhie`] -- `--create-dirs`, from `src/tool_dirhie.c`: the path
//!   hierarchy built behind an output template, and its failure text.
//! * [`filetime`] -- from `src/tool_filetime.c`: the `-R, --remote-time`
//!   writer and the `-z, --time-cond` local-file reader. Both functions of
//!   that unit live there, not just the writer.
//! * [`formparse`] -- `-F, --form`, from `src/tool_formparse.c`: what parses,
//!   what is rejected, and with which message.
//! * [`msgs`] -- from `src/tool_msgs.c` and `src/tool_stderr.c`: the
//!   `curl: `, `Warning: ` and `Note: ` prefixes
//!   (`src/tool_msgs.c:30-32`), the line wrap, and its word-boundary rule.
//! * [`progress`] -- the *parallel-transfer* meter only, from
//!   `src/tool_progress.c`: its column layout. The single-transfer bar is a
//!   separate surface; see the boundary notes below.
//! * [`writeout`] -- from `src/tool_writeout.c` and
//!   `src/tool_writeout_json.c`: the `--write-out` variable vocabulary and
//!   the JSON form.
//! * [`xattr`] -- from `src/tool_xattr.c`: the extended-attribute names
//!   written alongside a saved download, and their order
//!   (`src/tool_xattr.c:38-39`).
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
//! # Boundaries -- four surfaces that deliberately live elsewhere
//!
//! Recorded here so that no later reader adds them to this directory:
//!
//! * The **single-transfer** progress bar is not here. It is a second,
//!   distinct `CURLOPT_XFERINFOFUNCTION` -- the one carrying
//!   `MAX_BARLENGTH 400` and `MIN_BARLENGTH 20`
//!   (`src/tool_cb_prg.c:31-32`) and `update_width()` (`:110-119`) --
//!   whereas [`progress`] holds the parallel-mode callback
//!   (`src/tool_progress.c:64`). AAP section 0.4.1 assigns
//!   `src/tool_cb_prg.c` to `curl-rs/src/callbacks/progress.rs`. Neither
//!   callback is duplicated here.
//! * The `--trace` and `--trace-ascii` formats are not here. AAP section
//!   0.4.1 assigns `src/tool_cb_dbg.c` to
//!   `curl-rs/src/callbacks/debug.rs`.
//! * Terminal width and the timing helpers are not here.
//!   `get_terminal_columns()` (declared at `src/terminal.h:28`) belongs to
//!   `crate::terminal`, and the `src/tool_util.c` helpers to `crate::util`.
//!   Modules in this tree *use* those; they do not re-derive them.
//! * `--libcurl` emission is not here. AAP section 0.4.1 assigns
//!   `src/tool_easysrc.c` to `curl-rs/src/libcurl_src.rs`, a sibling of this
//!   directory rather than a member of it -- even though its
//!   `Failed to open %s to write libcurl code` warning
//!   (`src/tool_easysrc.c:185`) is emitted *through* [`msgs`].
//!
//! # Declarations only
//!
//! This root holds no logic and publishes no re-export surface. A caller
//! names the owning module directly, as in `crate::output::msgs`, which is the
//! "one import per type actually used" rule of AAP section 0.4.2 in place of
//! the C tree's blanket `#include`. A convenience re-export here would rebuild
//! exactly the coupling this migration removes, and would blur which module
//! owns which frozen surface -- and that ownership is what keeps the frozen
//! bytes in one place.

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
/// The single-transfer progress bar is not here; see the boundary notes above.
pub(crate) mod progress;

/// `--write-out`, including its JSON form -- supersedes `src/tool_writeout.c`
/// and `src/tool_writeout_json.c`.
pub(crate) mod writeout;

/// `--xattr` -- supersedes `src/tool_xattr.c`.
pub(crate) mod xattr;
