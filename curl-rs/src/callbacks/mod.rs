// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! Transfer callbacks the command-line tool installs on the engine.
//!
//! One module per translation unit of the C tool's `tool_cb_*.c` set, which
//! `src/Makefile.inc:82-88` lists as exactly seven files. Each module holds
//! the Rust counterpart of one callback, and the configuration layer installs
//! them on the easy handle before every transfer just as
//! `src/config2setopts.c:656-704` does, one module per C unit.
//!
//! Declarations only. This file holds no logic and publishes no re-export
//! surface, so every callback is reached through its own module path.
//!
//! # The seven callbacks -- SPECIFIED TARGET DESIGN, NOT DECLARED
//!
//! **No callback module exists in this checkout.** All seven are assigned to
//! later units of work, and a `mod` line without its file is `E0583` -- a hard
//! error that no `#[allow]` can reach, because module resolution never gets far
//! enough to produce a lint. Declaring them here would therefore not merely be
//! an unverified claim; it would stop the crate compiling.
//!
//! They are recorded instead, in the order `src/Makefile.inc:82-88` lists them,
//! with the `CURLOPT_*` each one serves and the `src/config2setopts.c` line that
//! installs it. Each `mod` line arrives WITH its file in the unit of work that
//! creates it. Visibility is part of the specification: every one is
//! `pub(crate)`, because a callback is installed by this crate's configuration
//! layer and named by nothing outside it.
//!
//! | Module | C original | Option and install site |
//! |---|---|---|
//! | `debug` | `src/tool_cb_dbg.c` | `CURLOPT_DEBUGFUNCTION` -- trace output (`src/config2setopts.c:659`) |
//! | `header` | `src/tool_cb_hdr.c` | `CURLOPT_HEADERFUNCTION` -- response headers (`:702`) |
//! | `progress` | `src/tool_cb_prg.c` | `CURLOPT_XFERINFOFUNCTION` -- the single-transfer progress bar (`:691`) |
//! | `read` | `src/tool_cb_rea.c` | `CURLOPT_READFUNCTION` -- request body (`:680`), plus the `CURLOPT_XFERINFOFUNCTION` that unpauses a busy read (`:698`) |
//! | `seek` | `src/tool_cb_see.c` | `CURLOPT_SEEKFUNCTION` -- rewind before a resend (`:685`) |
//! | `socket` | `src/tool_cb_soc.c` | `CURLOPT_OPENSOCKETFUNCTION` -- socket creation (`:607`) |
//! | `write` | `src/tool_cb_wrt.c` | `CURLOPT_WRITEFUNCTION` -- response body (`:676`) |
//!
//! Nothing else belongs in this file. When the modules land, the table above is
//! replaced by the seven declarations it describes, one for one.
//!
//! When they do, each is reached through its own module path and nothing is
//! re-exported from here -- the "one import per type actually used" rule of
//! AAP section 0.4.2, rather than the blanket `#include` the C tree relies
//! on.
