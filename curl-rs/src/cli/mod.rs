// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! Command-line surface of the `curl-rs` binary.
//!
//! This subtree carries the argument-parsing, help and parameter-validation
//! half of the C command-line tool. Its surface is frozen by AAP section
//! 0.8.1: option names, aliases, argument arity, argument type and default
//! value are fixed for all 282 rows of the `aliases[]` table
//! (`src/tool_getparam.c:80`), and the `--version` banner is a machine-read
//! contract that `tests/runtests.pl:640-730` parses to decide which fixtures
//! may run. Under-reporting a capability there makes a fixture skip, while
//! over-reporting makes it run and fail (AAP section 0.6.5).
//!
//! Each module stands in for exactly one unit of the C tool:
//!
//! - `args` -- `src/tool_getparam.c` plus `src/tool_helpers.c`: the 282-row
//!   `aliases[]` table as a `clap` 4.x derive surface.
//! - `completions` -- `scripts/completion.pl`: shell-completion emission.
//! - `help` -- `src/tool_help.c` plus `src/tool_listhelp.c`: the help table,
//!   the 26-bit category mask spanning `CURLHELP_AUTH` through
//!   `CURLHELP_VERBOSE` (`src/tool_help.h:62-87`), and the `--version`
//!   printer.
//! - `hugehelp` -- `src/tool_hugehelp.c`, a generated artifact rather than a
//!   committed source, which is why `src/Makefile.inc` omits it from
//!   `CURL_CFILES`; includes the manual that `build.rs` emits.
//! - `ipfs` -- `src/tool_ipfs.c`: IPFS gateway URL translation.
//! - `libinfo` -- `src/tool_libinfo.c`: the protocol and feature data model
//!   behind the banner described above.
//! - `paramhlp` -- `src/tool_paramhlp.c`: the exact numeric, protocol and
//!   list acceptance rules of curl 8.19.0-DEV.
//! - `vars` -- `src/var.c`: `--variable` expansion.
//!
//! This root declares those modules and nothing else. Callers name the
//! owning module directly, as in `crate::cli::args`, because AAP section
//! 0.4.2 replaces the C tree's blanket `#include "urldata.h"` with "one
//! import per type actually used". A convenience re-export here would
//! rebuild exactly the god-header coupling that this migration removes.

pub(crate) mod args;
pub(crate) mod completions;
pub(crate) mod help;
pub(crate) mod hugehelp;
pub(crate) mod ipfs;
pub(crate) mod libinfo;
pub(crate) mod paramhlp;
pub(crate) mod vars;
