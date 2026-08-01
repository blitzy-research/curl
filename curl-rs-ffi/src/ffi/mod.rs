// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! The sanctioned FFI tree: the one place in this crate where `unsafe` lives.
//!
//! The crate root declares this module with the single `#[allow(unsafe_code)]`
//! that the whole crate contains, so everything beneath this directory -- and
//! nothing outside it -- may write `unsafe`. Every `unsafe` block carries a
//! `// SAFETY:` comment stating the precondition the caller must have met.
//!
//! # Why the boundary is one directory and one attribute
//!
//! The requirement is that `unsafe` be impossible anywhere except under a single
//! FFI tree, and that exactly one attribute grant the exemption. Two facts,
//! both measured on the pinned toolchain rather than assumed, fix the spelling:
//!
//! * `#![forbid(unsafe_code)]` at the crate root with `#[allow(unsafe_code)]` on
//!   this declaration does **not** compile: `error[E0453]: allow(unsafe_code)
//!   incompatible with previous forbid`. `forbid` is by definition
//!   un-overridable from an inner scope, so no placement of the `allow` rescues
//!   it.
//! * `#![deny(unsafe_code)]` with one `#[allow(unsafe_code)]` on this
//!   declaration compiles, and the same `unsafe` block moved anywhere outside
//!   this directory is a hard error.
//!
//! `deny` leaves one gap that `forbid` would not: a module outside this
//! directory could write its own `#[allow(unsafe_code)]` and compile. The
//! compiler therefore enforces the invariant against accident but not against a
//! second deliberate exemption, which is why the crate root also carries an
//! executable test that walks `src/` and asserts the count of exemptions and the
//! absence of the keyword outside this directory. That test is the gate; this
//! comment records why it is load-bearing rather than decorative.
//!
//! # What lives here
//!
//! Two support modules, both consumed by every exported entry point:
//!
//! - [`panic_boundary`] -- containment for panics that would otherwise unwind
//!   across the C ABI, where unwinding is undefined behaviour.
//! - [`memory`] -- libcurl's five replaceable allocator hooks, the counterpart
//!   of `Curl_cmalloc` and its four siblings (`lib/easy.c:106-110`), backing
//!   `curl_global_init_mem`.
//!
//! The 100 exported entry points themselves are partitioned across the twelve
//! symbol-family modules the crate documentation tabulates -- `easy`, `multi`,
//! `share`, `global`, `slist`, `mime`, `form`, `url`, `ws`, `printf`,
//! `strerror` and `misc` -- together with the three type-and-metadata modules
//! `opts`, `codes` and `handle`. That partition is disjoint and exhaustive
//! against `lib/libcurl.def`: each of the 100 names has exactly one
//! `#[no_mangle] pub extern "C"` definition, because a duplicate is a link
//! error and nothing builds.
//!
//! Export parity comes from declaration discipline, not from link-time
//! filtering. A Rust `cdylib` was built and inspected: it exported exactly the
//! two symbols declared `#[no_mangle] pub extern "C"` and leaked nothing from
//! the standard library, so no linker version script is needed -- and a
//! user-supplied one was separately measured not to control a Rust `cdylib`'s
//! exports at all.

pub(crate) mod codes;
pub(crate) mod handle;
pub(crate) mod memory;
pub(crate) mod opts;
pub(crate) mod panic_boundary;
pub(crate) mod types;

// The symbol-family modules. Each owns a disjoint slice of the 100 names in
// `lib/libcurl.def`, and `build.rs`'s `check_export_coverage` asserts that the
// partition stays disjoint and exhaustive as families land.
pub(crate) mod easy;
pub(crate) mod escape;
pub(crate) mod global;
pub(crate) mod misc;
pub(crate) mod slist;
pub(crate) mod strerror;
