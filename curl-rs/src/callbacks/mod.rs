// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! Transfer callbacks the command-line tool installs on the engine.
//!
//! One module per translation unit of the C tool's `tool_cb_*.c` set, which
//! `src/Makefile.inc:82-88` lists as exactly seven files. Each module holds
//! the Rust counterpart of one callback, and the configuration layer installs
//! them on the easy handle before every transfer just as
//! `src/config2setopts.c:656-704` does. AAP sections 0.3.1 and 0.4.1 assign
//! one module per unit.
//!
//! Declarations only. This file holds no logic and publishes no re-export
//! surface, so every callback is reached through its own module path.

/// `CURLOPT_DEBUGFUNCTION` -- trace output (`src/config2setopts.c:659`).
pub(crate) mod debug;

/// `CURLOPT_HEADERFUNCTION` -- response headers (`src/config2setopts.c:702`).
pub(crate) mod header;

/// `CURLOPT_XFERINFOFUNCTION` -- the single-transfer progress bar
/// (`src/config2setopts.c:691`).
pub(crate) mod progress;

/// `CURLOPT_READFUNCTION` -- request body (`src/config2setopts.c:680`), plus
/// the `CURLOPT_XFERINFOFUNCTION` that unpauses a busy read
/// (`src/config2setopts.c:698`).
pub(crate) mod read;

/// `CURLOPT_SEEKFUNCTION` -- rewind before a resend
/// (`src/config2setopts.c:685`).
pub(crate) mod seek;

/// `CURLOPT_OPENSOCKETFUNCTION` -- socket creation
/// (`src/config2setopts.c:607`).
pub(crate) mod socket;

/// `CURLOPT_WRITEFUNCTION` -- response body (`src/config2setopts.c:676`).
pub(crate) mod write;
