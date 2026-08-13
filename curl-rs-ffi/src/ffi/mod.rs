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
//! The 100 exported entry points are TO BE partitioned across the twelve
//! symbol-family modules the crate documentation tabulates -- `easy`, `multi`,
//! `share`, `global`, `slist`, `mime`, `form`, `url`, `ws`, `printf`,
//! `strerror` and `misc` -- together with the three type-and-metadata modules
//! `opts`, `codes` and `handle`. That is the target partition, and the
//! distinction between it and what exists today is load-bearing rather than
//! pedantic, so both are stated:
//!
//! * MEASURED, at the commit that completed `form`: 59 of the 100
//!   are defined, 41 are not, and 0 extra symbols are exported. Two
//!   independent measurements
//!   agree on the export set -- `nm --defined-only` over the built staticlib,
//!   and `build.rs`'s `undefined_abi_exports` computed from `lib/libcurl.def` --
//!   and `build.rs` prints the live figure as a `cargo:warning` on every build,
//!   which is the authority to consult rather than this sentence. The
//!   declarations below are therefore TEN symbol-family modules, not twelve:
//!   `easy`, `escape`, `form`, `global`, `mime`, `misc`, `printf`, `slist`,
//!   `strerror` and `url` -- `printf` declared apart from the other nine, for
//!   the two reasons recorded at its declaration, but a family all the same.
//!   `escape` does
//!   not appear in the twelve-name list above because it is not a family of its
//!   own -- it now holds only `curl_easy_escape` and `curl_easy_unescape`, which
//!   the target partition assigns to `easy`; the two legacy names `curl_escape`
//!   and `curl_unescape` have moved to `misc`, which the same partition assigns
//!   them to, and they forward into `escape` exactly as `lib/escape.c:36-45`
//!   forwards.
//! * The 41 that are absent are exactly `curl_easy_*` (13), all of
//!   `curl_multi_*` (21), `curl_share_*` (3) and `curl_ws_*` (4) -- computed by
//!   differencing `lib/libcurl.def` against `nm` over the staticlib, which is
//!   also how the four family figures were obtained rather than by subtracting
//!   from the previous value of this sentence. Two earlier figures here are
//!   corrected by that measurement and not merely restated: `curl_easy_*` is 13
//!   short, not 15, and NO `curl_global_*` name is missing at all. Neither
//!   `curl_mime_*` nor `curl_url*` nor the legacy `curl_form*` trio is among
//!   them any longer: `mime` carries all 12 of the first, `url` all of the
//!   second and `form` all three of the third.
//!   They are unwritten work,
//!   not a defect: the modules that back them are assigned to units of work
//!   beyond this checkpoint, and `include/curl/` is deliberately NOT
//!   regenerated while any of them is missing, so the reviewed curl 8.19.0-DEV
//!   headers remain the ABI contract rather than being replaced by a truncated
//!   one.
//! * One caveat that belongs with the export figure rather than buried in it,
//!   and it is now CLOSED on ELF and open only on Mach-O. Six symbols -- the
//!   five plain-variadic `curl_m*printf` forms in `printf` and `curl_formadd`
//!   in `form` -- are defined by `core::arch::global_asm!`, because
//!   `extern "C" fn f(x: T, ...)` is `error[E0658]` on stable at the declared
//!   minimum. A `global_asm!` symbol reaches the STATICLIB unaided but not the
//!   CDYLIB, because rustc's cdylib export list covers only the
//!   `#[no_mangle] pub extern` items it knows of and hands the linker a version
//!   script that localises everything else. Measured, that made
//!   `build.rs`'s source-scanning count read 59 where `nm -D --defined-only`
//!   over the shared object read 53, the difference being exactly those six.
//!   `build.rs`'s `promote_assembled_exports` closes it on ELF by merging a
//!   second version script naming the six, with LLD selected explicitly from
//!   the invoking toolchain's own sysroot; measured after the change, both
//!   artifacts export the identical 59 and nothing leaks, at the 1.75 floor and
//!   on the aarch64 cross leg alike. On Mach-O the six are still absent,
//!   because ld64's export list is replaced rather than extended. What that
//!   leaves for escalation A4 is only the four option-identifier setters on
//!   Apple arm64, which is an argument-passing question and not an export one;
//!   `printf` and `form` each record their half at their own site.
//!
//! What holds unconditionally, now and at completion, is the partition's SHAPE:
//! it is disjoint, and every name defined has exactly one `#[no_mangle] pub
//! extern "C"` definition, because a duplicate is a link error and nothing
//! builds. `build.rs`'s `check_export_coverage` asserts that the families are
//! disjoint and exhaustive against `lib/libcurl.def` as they land, so the claim
//! becomes true by enforcement rather than by editing this comment.
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

// The symbol-family modules that EXIST at this commit -- nine of the twelve
// the target partition names. Each owns a disjoint slice of the 100 names in
// `lib/libcurl.def`, and `build.rs`'s `check_export_coverage` asserts that the
// partition stays disjoint and exhaustive as families land. `multi`, `share` and
// `ws` are not yet declared because they are not yet written.
//
// The counts below were measured over the built artifacts, not accumulated from
// the previous value of this sentence. The nine carry 49 definitions between
// them; with `printf`'s ten that is the 59 `build.rs` scans from source, and on
// ELF all 59 reach the cdylib as well, because `promote_assembled_exports`
// merges a second version script naming the six symbols `global_asm!` defines.
// On Mach-O those six are still absent and the cdylib carries 53; the module
// documentation above records the measurement and why ld64 differs.
//
// `form` is the newest of the nine and the smallest: three names, all deprecated
// in the headers since 7.56.0 and all still exported, because the symbol-parity
// gate compares the whole set and dropping a deprecated export would fail it.
// One of the three, `curl_formadd`, is the only assembled symbol outside
// `printf`. `mime` carries the whole `curl_mime_*` family -- all 12 of its names
// -- and `url` the URL API's exported entry points; none of either family's
// names lives anywhere else, and in particular the modern `curl_mime_*` surface
// and the legacy `curl_form*` trio do not overlap.
pub(crate) mod easy;
pub(crate) mod escape;
pub(crate) mod form;
pub(crate) mod global;
pub(crate) mod mime;
pub(crate) mod misc;
pub(crate) mod slist;
pub(crate) mod strerror;
pub(crate) mod url;

// The `curl_m*printf` family, declared apart from the six above because it is
// unlike every other family in this crate in two ways.
//
// It needs nothing from `curl-rs-lib`. Specification 0.4.1 maps it from
// `include/curl/mprintf.h` and `lib/mprintf.c` alone and assigns it no library
// module, so curl's formatter lives inside it rather than being adapted from
// somewhere else. That is not a breach of the facade discipline the other
// families follow: a `printf` implementation is not protocol logic, and there is
// no protocol logic here to move.
//
// And five of its ten symbols are not Rust functions at all. `extern "C" fn
// f(x: T, ...)` is `error[E0658]` on stable, so the plain-variadic forms are
// emitted by `global_asm!` -- one prologue per ABI, performing exactly what a C
// compiler's `va_start` performs -- and only the five `va_list` forms behind
// them are ordinary `#[no_mangle]` definitions. `build.rs`'s
// `check_printf_trampolines` enforces that arrangement per symbol.
pub(crate) mod printf;
