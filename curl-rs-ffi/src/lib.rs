// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

// THE CRATE-ROOT SAFETY GATE. Read before adding an `#[allow(unsafe_code)]`
// anywhere in this crate.
//
// `deny`, not `forbid`, and the reason is measured rather than preferred.
// `curl-rs-lib/src/lib.rs:34-48` records the experiment: `forbid` at the root
// with `#[allow(unsafe_code)]` on a module is rejected outright with
// `error[E0453]: allow(unsafe_code) incompatible with previous forbid`,
// while `deny` plus a scoped `allow` compiles. This crate cannot do without
// the scoped allows -- all 100 entry points receive raw pointers from C, so
// `unsafe` is its subject matter and not an escape hatch -- so `forbid` is
// unavailable and `deny` is the strongest level that can actually be set.
//
// What this changes. Before it, the `#[allow(unsafe_code)]` attribute below
// enforced NOTHING: the `unsafe_code` lint is `allow` by default, so it was
// documentary. A new module could use `unsafe` freely and silently. With the
// root at `deny`, `unsafe` anywhere in this crate is a compile error unless
// that module carries an explicitly audited allow, which is the property
// specification 0.1.1 goal G6 asks for and which review alone cannot give.
//
// THE AUDITED ALLOWANCE, singular, and why it is unavoidable:
//
//   `mod ffi`  -- the exported entry points, over raw C pointers received from
//                 a caller this crate cannot inspect. Every one is
//                 `#[no_mangle] pub extern "C"`, so `unsafe` is this module's
//                 subject matter rather than an escape hatch.
//
// It is ONE and not three. An earlier revision of this comment listed
// `mod memory` and `mod tests` alongside `mod ffi`, and that was true of an
// earlier layout: both now live INSIDE `src/ffi/`, so the single allowance on
// the `mod ffi` declaration already covers them. `memory` holds libcurl's five
// replaceable allocator hooks, whose C typedefs
// (`include/curl/curl.h:469-473`) are `unsafe extern "C" fn`, and the tests
// that exercise them must construct real `unsafe extern "C" fn` hooks rather
// than safe stand-ins with a different signature. Neither needs its own
// exemption any more, and neither may have one: two exemptions would mean two
// places to audit and would leave the root able to grant a third.
//
// `deny` is defeatable by an inner allow, exactly as it is in `curl-rs-lib`,
// so the level is paired with an invariant a reviewer can check mechanically.
// The pattern is ANCHORED to column zero, because an unanchored one also
// matches the prose above and would report several:
//
//     grep -cE '^#\[allow\(unsafe_code\)\]$' curl-rs-ffi/src/lib.rs   ==  1
//     grep -rhE '^ *#!?\[allow\(unsafe_code\)\]' curl-rs-ffi/src/ffi/ ==  nothing
//
// A second allowance anywhere in this crate is a finding and not a
// convenience. `the_audited_unsafe_allowance_is_exactly_one` asserts the count
// over EVERY source file in the crate -- not merely this one, because `deny`
// unlike `forbid` can be overridden from an inner scope -- and it reads them
// from disk rather than trusting this comment. The other half of the discipline
// is unchanged and is not replaceable by a lint: EVERY `unsafe` block carries a
// `// SAFETY:` comment naming the precondition it relies on and why it holds.
#![deny(unsafe_code)]

//! libcurl's C ABI, expressed in Rust.
//!
//! This crate is the ABI facade that presents curl 8.19.0-DEV's exported C
//! surface over the safe engine in `curl-rs-lib`. It marshals; it does not
//! decide. Every protocol, transport, TLS, DNS and authentication decision
//! belongs to `curl-rs-lib`, which is what keeps the shim small enough to
//! audit against the public header in isolation. There is deliberately no
//! protocol logic anywhere in this crate.
//!
//! The build products are `libcurl.so` (a `cdylib`) and `libcurl.a` (a
//! `staticlib`), named by `[lib] name = "curl"` in the manifest so the
//! `-lcurl` link line published by `libcurl.pc.in` and `curl-config.in`
//! keeps resolving. `curl-rs-ffi/build.rs` stamps the shared object's
//! `SONAME` as `libcurl.so.4`, derived from `lib/Makefile.soname:27-29`
//! (`VERSIONCHANGE=12`, `VERSIONADD=0`, `VERSIONDEL=8`, so 12 - 8 = 4).
//! Nothing in this file influences linking, and nothing here may: see the
//! version-script finding under "Open items" below.
//!
//! # The export contract: exactly 100 symbols
//!
//! `lib/libcurl.def` is the authority. It is 101 lines -- `EXPORTS`
//! followed by exactly 100 `curl_*` names on lines 2 to 101, in
//! alphabetical order. That set, neither a subset nor a superset, is what
//! a drop-in replacement must export. `docs/libcurl/symbols-in-versions`
//! is a 1,164-entry historical record that includes symbols curl has since
//! removed, and it is **not** the export list.
//!
//! Parity comes from declaration discipline rather than from link-time
//! filtering. rustc emits from a `cdylib` only what is declared
//! `#[no_mangle] pub extern "C"`, so the entry points are exported
//! irrespective of the privacy of the module holding them, and nothing
//! internal leaks alongside them. That is why `mod ffi` is private, and
//! why there is no `pub use ffi::*` re-export: a second path to every item
//! would buy nothing -- the crate has no `rlib` target and therefore no
//! Rust consumer -- while inviting duplicate-definition confusion.
//!
//! Each of the 100 names must have exactly **one**
//! `#[no_mangle] pub extern "C"` definition; a duplicate is a link error
//! and nothing builds. The partition below is therefore both disjoint and
//! exhaustive, and it is the contract the `ffi/` modules must satisfy.
//!
//! **The partition is PARTLY REALISED at this commit, and the table below is
//! the target rather than an inventory.** The measured state, which every
//! claim here is to be read against:
//!
//! * `curl-rs-ffi/src/ffi/` holds twenty-one entries: the twelve symbol-family
//!   modules `easy`, `escape`, `form`, `global`, `mime`, `misc`, `printf`,
//!   `share`, `slist`, `strerror`, `url` and `ws`; the type-and-metadata
//!   modules `codes`, `handle`, `opts` and `types`; the support modules
//!   `memory` and `panic_boundary`; `mod.rs`; and two oracle fixtures. `multi`
//!   is the one family still a target.
//! * **66 of the 100 symbols are defined, 34 are not, and 0 extra symbols
//!   leak.** `build.rs` prints the live figure as a `cargo:warning` on every
//!   build, so that -- not this sentence -- is the number to consult. Two
//!   independent measurements now AGREE on both the export set and the count:
//!   `nm -D --defined-only` over the built `cdylib`, and `build.rs`'s
//!   `undefined_abi_exports`, which parses `lib/libcurl.def` and this crate's
//!   `#[no_mangle]` and `global_asm!` declarations. They used to differ by the
//!   assembled labels, which reached `libcurl.a` and not
//!   `libcurl.so`; `promote_assembled_exports` closed that, so the shared
//!   library and the static library now export the identical set. The crate
//!   therefore exports something, but it is **not** a drop-in replacement yet,
//!   and nothing here should be read as claiming otherwise: 34 of the 100 have
//!   no definition at all.
//! * **The 34 fall in two families, and the split is published rather than
//!   only written here**: `curl_multi_*` 21 and `curl_easy_*` 13.
//!   `build.rs` emits them as `missing-family=<name> <count>`
//!   lines in `$OUT_DIR/abi-inventory.txt` beside the 34 names, and
//!   [`abi_inventory`]'s tests assert the counts sum to `missing` and that no
//!   family is invented. The split is the actionable form of the total: one
//!   of the two families is the one module `ffi/` does not hold, and the
//!   other is `ffi/easy.rs`, which exists and defines only its three
//!   option-introspection entry points. `curl_share_*` left this list when
//!   `ffi/share.rs` landed: it carries three of that family's four names, and
//!   `ffi/strerror.rs` has always carried the fourth. `curl_ws_*` left it
//!   whole when `ffi/ws.rs` landed, carrying all four of its names.
//! * Because the header is generated FROM this crate, an incomplete surface
//!   would generate an incomplete header. `build.rs` refuses: while any of the
//!   100 is undefined it writes no header at all and says so, leaving the
//!   reviewed curl 8.19.0-DEV headers in place as the ABI contract. So the
//!   partial state cannot silently degrade the contract - see
//!   `generate_headers`.
//! * That refusal is an advisory, and an advisory cannot fail a build: a
//!   `cargo:warning` leaves the exit status at zero, and `-D warnings` reaches
//!   rustc lints only. Setting `CURL_RS_REQUIRE_COMPLETE_EXPORTS` turns the
//!   same condition into a hard error naming every missing symbol, and
//!   `.github/workflows/rust-abi.yml` arms it so that the incomplete surface
//!   cannot pass a gate unremarked. Until it is complete, that workflow is red
//!   on purpose.
//!
//! | Module | Count | Derivation |
//! |---|---|---|
//! | `ffi/easy.rs` | 16 | 21 `curl_easy_*` less the 5 moved out |
//! | `ffi/escape.rs` | 2 | `curl_easy_escape`, `curl_easy_unescape` |
//! | `ffi/multi.rs` | 21 | 22 `curl_multi_*` less `curl_multi_strerror` |
//! | `ffi/share.rs` | 3 | 4 `curl_share_*` less `curl_share_strerror` |
//! | `ffi/global.rs` | 5 | init, cleanup, init_mem, sslset, trace |
//! | `ffi/slist.rs` | 2 | `curl_slist_append`, `curl_slist_free_all` |
//! | `ffi/mime.rs` | 12 | the whole `curl_mime_*` family |
//! | `ffi/form.rs` | 3 | `curl_formadd`, `curl_formfree`, `curl_formget` |
//! | `ffi/url.rs` | 5 | 6 `curl_url*` less `curl_url_strerror` |
//! | `ffi/ws.rs` | 4 | the whole `curl_ws_*` family |
//! | `ffi/printf.rs` | 10 | the `curl_m*printf` family |
//! | `ffi/strerror.rs` | 4 | the four strerror functions |
//! | `ffi/misc.rs` | 13 | 11 standalone plus the 2 header-API functions |
//! | `codes`, `handle`, `memory`, `mod`, `opts`, `panic_boundary`, `types`, and this file | 0 | types and support only |
//!
//! Sum: 16 + 2 + 21 + 3 + 5 + 2 + 12 + 3 + 5 + 4 + 10 + 4 + 13 = **100**.
//!
//! The five moved out of `ffi/easy.rs` are `curl_easy_strerror` (to
//! `ffi/strerror.rs`), `curl_easy_header` and `curl_easy_nextheader` (to
//! `ffi/misc.rs`, which is where their declaring header points), and
//! `curl_easy_escape` and `curl_easy_unescape` (to `ffi/escape.rs`). That
//! last pair is why `ffi/escape.rs` carries a row of its own: it holds two
//! symbols of the `curl_easy_*` family without being the `easy` module, and
//! folding them back into the `easy` row would make the row disagree with the
//! file. The split is load-bearing for the arithmetic above -- 16 rather than
//! 18 -- and it reconciles against measurement: `ffi/easy.rs` defines three of
//! its sixteen today (the `curl_easy_option_*` introspection trio), and
//! 16 - 3 is exactly the 13 undefined `curl_easy_*` symbols reported above.
//!
//! Two ways of counting the same file set disagree unless the double
//! counting is made explicit, so it is recorded here rather than
//! rediscovered. Tallying `lib/libcurl.def` by name prefix gives
//! `curl_easy_*` 21, `curl_multi_*` 22, `curl_share_*` 4,
//! `curl_global_*` 5, `curl_slist_*` 2, `curl_mime_*` 12, `curl_form*` 3,
//! `curl_url*` 6, `curl_ws_*` 4 and `curl_m*printf` 10, which is 89, plus
//! 11 names that match no family: `curl_escape`, `curl_free`,
//! `curl_getdate`, `curl_getenv`, `curl_pushheader_byname`,
//! `curl_pushheader_bynum`, `curl_strequal`, `curl_strnequal`,
//! `curl_unescape`, `curl_version` and `curl_version_info`. Adding the
//! per-module counts naively instead yields 106, because the four
//! strerror functions are also inside the `easy`, `multi`, `share` and
//! `url` prefix families, and because `curl_easy_header` and
//! `curl_easy_nextheader` are also inside the `curl_easy_*` family:
//! 106 - 6 = 100. The partition resolves it by giving `ffi/strerror.rs`
//! genuine ownership of its four, which mirrors the C tree, where
//! `lib/strerror.c` houses all four in one translation unit
//! (`curl_easy_strerror` at `:34`, `curl_multi_strerror` at `:326`,
//! `curl_share_strerror` at `:385`, `curl_url_strerror` at `:420`).
//!
//! # Module declaration order is ABI-visible
//!
//! `curl-rs-ffi/cbindgen.toml` sets `sort_by = "None"` on purpose, so the
//! generated header's declaration order is the Rust source's declaration
//! order. That order is load-bearing in two measured places.
//! `include/curl/curl.h:3312-3313` says so in curl's own words -- the
//! `easy.h` and `multi.h` include files need the option and info
//! definitions before they can be included -- and the `extern "C"` block
//! duly closes at `:3308-3310`, ahead of the seven umbrella includes at
//! `:3314-3320`. Independently, `include/curl/multi.h:347-408` builds
//! `CURLMoption` out of the `CURLOPT(na, t, nu)` macro defined at
//! `include/curl/curl.h:1120`, so the `CURLOPTTYPE_*` bases must already
//! exist. `ffi/codes.rs` and `ffi/opts.rs` therefore precede the symbol
//! modules. The order `ffi/mod.rs` should declare is: `codes`, `opts`,
//! `handle`, `global`, `easy`, `multi`, `share`, `slist`, `mime`, `form`,
//! `url`, `ws`, `printf`, `strerror`, `misc`.
//!
//! There is a trap here that fails silently, and it was found by running
//! the formatter rather than by reading it. The workspace `rustfmt.toml`
//! sets `reorder_modules = true`, and `rustfmt` does alphabetise a
//! contiguous run of body-less `mod` declarations: a probe file declaring
//! `mod zulu; mod alpha; mod mike;` came back ordered `alpha`, `mike`,
//! `zulu`. Left alone, `cargo fmt` would therefore sort `ffi/mod.rs`
//! alphabetically and move `opts` behind `misc`, breaking the generated
//! header with no diagnostic anywhere. The remedy is measured too: a
//! comment line between two `mod` declarations ends the run, and the same
//! probe with an interleaved comment preserved source order. `ffi/mod.rs`
//! must therefore separate its declarations with comments. This file's
//! single `mod ffi;` is unaffected, because one declaration cannot be
//! reordered.
//!
//! # Panic containment
//!
//! An unwind that crosses the C boundary is undefined behaviour, so no
//! panic may escape any entry point -- the rule covers all 100 names and is
//! obeyed by every one defined today. The containment
//! mechanism is code, not a build setting: `panic = "abort"` is prohibited
//! in the release profile -- the workspace root sets `panic = "unwind"`
//! explicitly -- because aborting would terminate the host application,
//! which is precisely the outcome the boundary exists to prevent. A member
//! manifest could not change it in any case, since Cargo honours
//! `[profile.*]` only at the workspace root and warns about it elsewhere,
//! and a warning is itself a build failure here.
//!
//! `panic_boundary` is that mechanism, and it exists exactly once. Every
//! entry point wraps its body and supplies the fallback its return type
//! demands:
//!
//! | Return type | Fallback |
//! |---|---|
//! | `CURLcode` | `CURLE_FAILED_INIT`, which is 2 |
//! | `CURLMcode` | `CURLM_INTERNAL_ERROR` (`multi.h:66`) |
//! | `CURLSHcode` | `CURLSHE_INVALID` (`curl.h:3062`) |
//! | `CURLUcode` | `CURLUE_BAD_HANDLE` (`urlapi.h:36`) |
//! | `CURLHcode` | `CURLHE_BAD_ARGUMENT` (`header.h:54`) |
//! | `CURLsslset` | `CURLSSLSET_UNKNOWN_BACKEND` (`curl.h:2833`) |
//! | `CURLFORMcode` | `CURL_FORMADD_MEMORY` (`curl.h:2611`) |
//! | any pointer | null, via `panic_boundary::guard_ptr` |
//! | `int` | a negative value, as C `printf` signals failure |
//! | `void` | return quietly, via `panic_boundary::guard_void` |
//!
//! `CURLE_FAILED_INIT` is chosen for the `CURLcode` family rather than
//! `CURLE_RECURSIVE_API_CALL`, which names a specific misuse by the
//! application, or `CURLE_OUT_OF_MEMORY`, which would misattribute the
//! fault to the caller's environment. `CURLM_INTERNAL_ERROR` needs no
//! justification beyond the comment curl itself attaches to it at
//! `include/curl/multi.h:66`, "this is a libcurl bug", which is precisely
//! what a contained panic is.
//!
//! One asymmetry is easy to miss by reasoning from `curl_global_init`:
//! `curl_global_cleanup` returns `void`, measured at
//! `include/curl/curl.h:2778`. It has no error channel whatsoever, so a
//! panic there can only be swallowed. The same holds for `curl_free`,
//! `curl_slist_free_all`, `curl_mime_free`, `curl_formfree` and
//! `curl_url_cleanup`.
//!
//! ## The diagnostic the default hook would print, and why it is replaced
//!
//! Nothing in `panic_boundary` writes to standard error, but Rust's
//! *default* hook does, before unwinding begins and therefore before
//! `catch_unwind` can intervene -- measured by driving these entry points
//! from a C program and observing the stream, not assumed. What it prints
//! is `thread '<unnamed>' panicked at <file>:<line>:<col>:` followed by the
//! payload, and, under `RUST_BACKTRACE`, a full backtrace with absolute
//! paths and symbol names.
//!
//! So a hook *is* installed, and the two objections that argued against
//! one are both answered rather than overridden:
//!
//! * **It does not replace the application's hook.** The hook that was in
//!   place is captured with `take_hook` and is called verbatim for every
//!   panic that did not arise inside this boundary. An application that
//!   installed its own hook keeps it for its own panics.
//! * **The defect is not hidden.** A boundary panic emits one constant,
//!   payload-free, path-free line naming it as a libcurl bug, and
//!   `contained()` counts it so a test can assert both that the net works
//!   and that a clean run absorbed nothing. `CURL_RS_PANIC_VERBOSE`
//!   restores the unredacted default output for a debugging session, which
//!   is the right way to make that output available: opt in, never by
//!   default.
//!
//! # `unsafe` in this crate
//!
//! `curl-rs-lib` and `curl-rs` deny `unsafe_code` at their roots. This
//! crate cannot: all 100 entry points receive raw pointers from C, so
//! `unsafe` is its subject matter rather than an escape hatch. The
//! `#[allow(unsafe_code)]` attributes below are honest about what they
//! achieve -- the `unsafe_code` lint is `allow` by default, so they are
//! documentary and they future-proof the crate against a workspace lint
//! table being added later; they enforce nothing today. The half that
//! carries the weight is the discipline that **every `unsafe` block
//! carries a `// SAFETY:` comment** naming the precondition it relies on
//! and why that precondition holds. That is a review obligation, and it
//! applies to every file under `ffi/` as much as to this one.
//!
//! # Memory: `curl_global_init_mem`, and a deviation stated plainly
//!
//! curl lets an application replace libcurl's allocator wholesale.
//! `lib/easy.c:106-110` holds five global function pointers --
//! `Curl_cmalloc`, `Curl_cfree`, `Curl_crealloc`, `Curl_cstrdup` and
//! `Curl_ccalloc` -- initialised to `malloc`, `free`, `realloc`, `strdup`
//! and `calloc`; `curl_global_init_mem` overwrites them at `:236-240`, and
//! `global_init` restores the defaults at `:129-133`. Two further details
//! were measured rather than inferred, because both are observable:
//! `lib/easy.c:220-221` rejects a null callback with
//! `CURLE_FAILED_INIT`, and `:222-232` leaves the pointers untouched and
//! returns `CURLE_OK` when libcurl is already initialised. The public
//! contract is `include/curl/curl.h:2763-2768`, over the five typedefs at
//! `:469-473`.
//!
//! **The deviation.** This crate installs no `#[global_allocator]`, so
//! Rust's own `Vec`, `Box` and `String` allocations do not pass through
//! the callbacks. The user-visible consequence is concrete and is not
//! buried: a leak-checking or accounting wrapper installed through
//! `curl_global_init_mem` observes every allocation that crosses the
//! boundary, and does not observe the engine's internal allocations. Two
//! independent findings force this, and each was established by
//! measurement:
//!
//! 1. **The slot is already occupied, and there is only one.** A
//!    `#[global_allocator]` may be declared once per artifact, and
//!    `curl-rs-lib` already declares one under its `memdebug` feature --
//!    the counting allocator that reproduces `lib/memdebug.c`'s record
//!    format for `tests/memanalyzer.pm`. `curl-rs-ffi`'s own `memdebug`
//!    feature forwards to it. A probe built to settle the question --
//!    an `rlib` with a `#[global_allocator]` plus a dependent `cdylib`
//!    with its own -- fails to compile with "the `#[global_allocator]` in
//!    this crate conflicts with global allocator in", so declaring one
//!    here would break `--features memdebug` outright.
//! 2. **A runtime allocator switch cannot be made sound.**
//!    `GlobalAlloc::dealloc` receives a pointer and a `Layout` and no
//!    provenance whatsoever, so it cannot tell which allocator produced
//!    the block. Any allocation made before `curl_global_init_mem`
//!    installs the callbacks would then be released through the
//!    application's `free`, which is heap corruption rather than a
//!    diagnosable error. curl has the same exposure -- it is why
//!    `include/curl/curl.h:2743-2745` requires `curl_global_init` to
//!    precede "any call of other libcurl functions", and why
//!    `lib/easy.c:102-105` notes the pointers must be set before anything
//!    that allocates -- but C's allocations are explicit and short-lived
//!    where a Rust runtime's are neither. Trading a documented reporting
//!    gap for a silent memory-corruption class is the right way round.
//!
//! Thread safety is a live contract rather than a formality:
//! `include/curl/curl.h:2744-2745` and `:2788-2789` document
//! `curl_global_init` and `curl_global_trace` as thread-safe when
//! `CURL_VERSION_THREADSAFE` is advertised, and `curl-rs-lib`'s version
//! banner does advertise it. Every item of shared state introduced here is
//! therefore genuinely synchronised.
//!
//! # Where the error enumerations live, and why they are declared twice
//!
//! `curl-rs-lib/src/error.rs` owns `CURLcode`, `CURLMcode`, `CURLUcode`,
//! `CURLSHcode` and `CURLHcode` for the engine, and `ffi/codes.rs`
//! declares them again for the ABI. That is deliberate:
//! `cbindgen.toml` sets `parse_deps = false` and excludes `curl-rs-lib`,
//! so cbindgen reads only this crate and the enumerations that must appear
//! in the generated header have to be declared inside it. Drift is
//! prevented by conversions that are total and infallible in both
//! directions, plus a `#[cfg(test)]` module in `ffi/codes.rs` asserting
//! every discriminant against its `curl_rs_lib::error` counterpart. A
//! fallible or partial conversion would let a newly added variant slip
//! through unnoticed, so neither is acceptable. `CURLINFO` and
//! `CURLoption` are not error codes and are not in either place: they
//! belong to `ffi/opts.rs`, which is their sole source of truth.
//!
//! # Open items
//!
//! These are unresolved, or resolved at a cost, and the crate root is where
//! a reader looks for crate-wide caveats. None may be discovered by surprise
//! later.
//!
//! **A4: OPEN AND ESCALATED, with the fourth option now ADOPTED for one of
//! the four names.** Four exported functions -- `curl_easy_setopt`,
//! `curl_easy_getinfo`, `curl_multi_setopt` and `curl_share_setopt` -- are
//! C-variadic in the header, and the design reaches them with a non-variadic
//! Rust function taking one trailing pointer, which works because the option
//! identifier already encodes its argument's type class (integer division by
//! 10,000 recovers the `CURLOPTTYPE_*` base -- for three of the four;
//! `CURLSHoption` is ordinal instead, so `ffi/share.rs` dispatches on the
//! value itself and says so).
//!
//! The hazard is real and was measured on both sides of the call, on all
//! four targets. A C caller does not put the third argument in the same
//! place everywhere:
//!
//! ```text
//! x86_64-unknown-linux-gnu    mov  %rsi,%rdx     -> RDX
//! x86_64-apple-darwin         movq %rsi,%rdx     -> RDX
//! aarch64-unknown-linux-gnu   mov  x2, x1        -> X2
//! aarch64-apple-darwin        str  x1, [sp]      -> THE STACK; x2 unwritten
//! ```
//!
//! A plain non-variadic aarch64 callee compiles to `mov x0, x2; ret` -- it
//! reads `x2`. Standard AAPCS64, which Linux aarch64 follows, passes
//! variadic arguments in registers, so caller and callee agree there.
//! **Apple's arm64 ABI passes them on the stack**, so on
//! `aarch64-apple-darwin` the callee would read a register the caller never
//! populated, silently and without a diagnostic.
//!
//! A fourth is technically available and costs none of those three, and it is
//! described below because a reader is entitled to know it exists. A
//! `core::arch::global_asm!` trampoline exported under the public symbol name
//! would relocate the argument and tail-call the implementation:
//!
//! ```text
//! _curl_easy_setopt:
//!     ldr  x2, [sp]                  ; the slot the Apple caller wrote
//!     adrp x16, {impl}@PAGE
//!     add  x16, x16, {impl}@PAGEOFF
//!     br   x16
//! ```
//!
//! `bl` does not modify `sp`, so `[sp]` on entry is exactly the slot the
//! caller stored to. This was compiled and disassembled on stable 1.97.1
//! **and on 1.75.0**: `llvm-nm` reports the trampoline as a global `T` and
//! the implementation as a local `t`, so the private symbol does not join
//! the export set, and `llvm-objdump` shows precisely the four instructions
//! above. No newer toolchain, no C compiler, no dropped target.
//!
//! ONE OF THE FOUR NOW USES IT. `ffi/share.rs` defines `curl_share_setopt`
//! with exactly this mechanism -- four `global_asm!` prologues, one per ABI
//! flavour, three of them a bare tail call because the argument is already in
//! the register the callee reads, and the Apple arm64 one `ldr x2, [sp]`
//! followed by `b` -- tail-calling a private `share_setopt_slot` that is not
//! `#[no_mangle]` and so does not join the export set. The other three have no
//! Rust body yet and so no trampoline either. That split is a fact about the
//! current state, not a reason to rely on remembering it:
//! `curl-rs-ffi/build.rs`'s `check_variadic_strategy` fails the build, **on
//! every target**, if any of the four ever gains a plain non-variadic
//! definition without a `global_asm!` trampoline exporting its label. It
//! checks for the assembly label rather than a marker comment, so it cannot
//! be satisfied by prose, and it is target-independent so the failure cannot
//! be confined to the one platform least likely to be building. This
//! replaces a `cargo:warning=` that fired on every macOS arm64 build, which
//! both broke specification 0.8.4 gate 1 -- zero warnings on all four
//! targets -- and described a defect that was not present.
//!
//! **The escalation is enforced, not merely recorded here, and it can no
//! longer be waived.** A caveat in a doc comment is exactly the "silent
//! acceptance" the specification calls the worst option, so `build.rs`'s
//! `check_variadic_abi` makes it impossible: building for
//! `aarch64-apple-darwin` **fails, unconditionally**. It formerly succeeded
//! when `CURL_RS_A4_VARIADIC_DECISION=accept-unsupported-varargs` was set,
//! and that bypass has been removed -- it could emit a release artifact whose
//! four option-identifier entry points read a register an Apple arm64
//! variadic caller never writes, and no build-time variable makes an
//! uninitialised register read safe. Setting the variable is now itself
//! refused, with a message that says so, so an environment still carrying it
//! fails loudly instead of appearing to be honoured. Specification 0.8.6 A4
//! keeps two available options, both edits to this repository rather than
//! environment settings: raise the MSRV above 1.75 and implement the four
//! with `c_variadic`, or drop the triple from the matrix. `src/ffi/printf.rs`
//! was once vetoed by file existence and no longer is, because a stricter
//! per-symbol check replaced the per-file veto for it; the next-but-one
//! paragraph gives the measurement that made that possible. The two lists the
//! gate reasons about are asserted against the verbatim header text this
//! crate emits, and the eleven named in the next paragraph are asserted
//! equal to the gate's own list by the `#[cfg(test)]` function
//! `the_variadic_inventory_matches_the_build_gate` in this file, so this
//! documentation and that enforcement cannot drift apart. (Named in prose
//! rather than as an intra-doc link: a `#[cfg(test)]` item is absent from the
//! documented crate, so a link to it resolves to nothing and rustdoc rejects
//! it under `-D warnings`.)
//!
//! **Fifteen of the 100 symbols, not four, have an argument shape stable
//! Rust cannot express at the declared minimum.** Searching for the
//! literal `...);` finds only four, because in `include/curl/mprintf.h`
//! the closing parenthesis is followed by a newline and then a
//! `CURL_TEMP_PRINTF` attribute. Scanning for `...` anywhere finds ten
//! variadic prototypes: the four option-identifier functions above, plus
//! `curl_formadd` (`curl.h:2632-2635`), whose `CURLFORM_*` sequence is
//! genuinely open-ended, plus `curl_mprintf`, `curl_mfprintf`,
//! `curl_msprintf`, `curl_msnprintf` and `curl_maprintf`, which are driven
//! by a format string. Five more take a `va_list` *parameter*:
//! `curl_mvprintf`, `curl_mvfprintf`, `curl_mvsprintf`, `curl_mvsnprintf`
//! and `curl_mvaprintf`. Only the first four are solved by the trailing
//! pointer; the other eleven are not. The header corroborates the split
//! itself: `include/curl/curl.h:3328-3341` defines three-argument
//! enforcement macros for exactly those four and for none of the rest,
//! because only those four take a fixed argument count. A `va_list`'s
//! layout is target-specific -- a pointer to a four-field record on x86-64
//! System V, a pointer to a five-field record on AAPCS64, and a plain
//! `char *` on Apple arm64 -- so walking one from Rust needs hand-written
//! per-target `unsafe`, while the plain forms need `va_start`, which is
//! unavailable at the declared minimum.
//!
//! **The candidate trampoline would not reach these eleven even if it were
//! adopted, and the difference is worth stating precisely so the paragraph
//! above is not over-read.** That trampoline relocates exactly one argument
//! from a known
//! stack slot into a known register, which is sufficient because those four
//! functions take a fixed three arguments. A format-driven function takes an
//! unknown number of arguments of unknown types, so reaching them needs the
//! whole of what `va_start` does: spilling the general-purpose and
//! floating-point argument registers into a target-specific record and
//! synthesising the `va_list` that indexes it. That is expressible in
//! `global_asm!` in principle, but it is a separate per-target
//! implementation for each of the three `va_list` layouts above rather than
//! a four-instruction thunk. Raising the minimum, adding a C shim that
//! captures the `va_list` and delegates -- which would add a build-time C
//! compiler dependency the manifest does not currently permit -- and
//! hand-writing the spill prologue are the ABI-exact routes. Dropping the
//! symbols is not an option, because they are eleven of the 100.
//!
//! **The third of those routes has since been taken for ten of the eleven, and
//! the paragraph above is left standing because its reasoning is still the
//! reason it was needed.** The one claim in it that measurement overtook is
//! "none of it is written". The spill prologue is now written, once per ABI, in
//! `src/ffi/printf.rs`: x86-64 System V and AAPCS64 each save their argument
//! registers into a frame and synthesise the record their ABI defines, while
//! Apple arm64 needs two instructions because its `va_list` *is* the entry
//! stack pointer. Each was compared against the prologue the target's own C
//! compiler emits, field by field, and the five `va_list` siblings the
//! trampolines call are ordinary Rust functions with no `unsafe` beyond what a
//! documented `// SAFETY:` comment covers. So `curl_mprintf`, `curl_mfprintf`,
//! `curl_msprintf`, `curl_msnprintf`, `curl_maprintf`, `curl_mvprintf`,
//! `curl_mvfprintf`, `curl_mvsprintf`, `curl_mvsnprintf` and `curl_mvaprintf`
//! are all implemented and correct at the declared minimum, with no new
//! dependency, and all ten are exported from the **static** library. Five of
//! them are not exported from the shared library, for a reason that is nothing
//! to do with the prologues and is set out two paragraphs below.
//!
//! **`curl_formadd`, the eleventh, is implemented by the same route, and the
//! claim that stood here -- that its obstacle was "different in kind" because a
//! `CURLFORM_*` sequence "carries no type encoding to recover the argument shapes
//! from" -- was overtaken by measurement.** It does carry one: `lib/formdata.c`
//! reads the option itself with `va_arg(params, int)` and its switch then reads
//! exactly one argument of the type that option names -- `char *`, `long`,
//! `curl_off_t`, `struct curl_slist *`, `struct curl_forms *`, or nothing at all.
//! The encoding is per-option rather than arithmetic, every one of those shapes
//! is a single general-purpose slot of at most eight bytes on all four required
//! targets, and none is a floating-point type, so one cursor decodes the whole
//! list and `va_start` was the only thing missing. `src/ffi/form.rs` supplies it
//! with the same four per-ABI prologues, calls a non-exported Rust function with
//! the synthesised list, and shares `src/ffi/printf.rs`'s cursor rather than
//! keeping a second copy of the slot arithmetic. It inherits the same shared-library
//! gap: `curl_formadd` is a `T` in `libcurl.a` and absent from `libcurl.so`,
//! which makes six such symbols rather than five. `curl_formget` and
//! `curl_formfree` are ordinary Rust items and are exported from both.
//!
//! **What remains open for those ten, stated rather than glossed.** The Apple
//! prologues are cross-assembled and disassembled in this environment, never
//! executed, because no Apple host is available -- so their correctness rests on
//! a reading of Apple's ABI plus a disassembly, not on a passing test. That is a
//! narrower open item than the one it replaced, and it is enforced rather than
//! merely noted: `build.rs`'s `check_printf_trampolines` refuses a plain Rust
//! definition of any of the five variadic forms, requires a trampoline naming
//! each export and its correct `va_list` sibling, and requires both the ELF and
//! the Mach-O `.globl` spelling, so no required target can be left without an
//! exporter. Unlike the per-file veto it replaced, no environment variable
//! silences it.
//!
//! Eight linker routes were measured; seven have no effect at all
//! (`--export-dynamic-symbol`, `--export-dynamic-symbol-list`, `--dynamic-list`,
//! `-u`, `--export-dynamic`, and combinations of them). The eighth, a second
//! anonymous `--version-script` naming the five, works under LLD -- which is why
//! it appeared to work at first, since rustc passes `-fuse-ld=lld` for
//! x86_64-unknown-linux-gnu -- and **fails the link** under GNU ld with
//! `anonymous version tag cannot be combined with other version tags`, which is
//! three of the four required targets and the 1.75 floor among them. It was
//! implemented, verified where it works, and removed; `build.rs` carries the full
//! matrix under "Trap 3". Two further findings belong with it. The C-shim route
//! this section describes above would not have helped either, because the version
//! script governs the whole link and a C object's symbols are localised exactly
//! as an assembled label is -- that route answers the variadic question and is
//! silent on the export question. And the one design that *would* export all ten,
//! declaring the register-resident variadic arguments as ordinary parameters,
//! caps the argument count: `addr_of!` of the last stack-passed parameter was
//! measured to be the caller's slot in debug and a callee-local copy in release,
//! putting the overflow area out of reach.
//!
//! **32-bit support is forfeited deliberately and must not be claimed.** A
//! single register-width argument slot holds a `curl_off_t` only where
//! `curl_off_t` fits a register. All four required targets are 64-bit, so
//! the width question is settled for the required matrix and for nothing
//! wider.
//!
//! **A disclosure rather than a defect.** Neither cryptographic
//! provider available to rustls is pure Rust; both contain C and assembly.
//! What the no-C-TLS requirement actually secures is satisfied: no C *TLS
//! library* is linked, because rustls implements the protocol, the record
//! layer and certificate verification in Rust, and the provider supplies
//! only primitives. `ring` is selected as the more portable of the two and
//! avoids the vendored C and assembly toolchain the alternative needs,
//! which would likely break the cross-compiled aarch64 Linux target. This
//! reaches the ABI at exactly one point: `ffi/global.rs` reports
//! `CURLSSLBACKEND_RUSTLS`, whose value 14 already exists in
//! `curl_sslbackend`, so `curl_global_sslset` invents nothing.
//!
//! **The version-banner token, resolved in favour of accuracy.**
//! `tests/runtests.pl:585-586` sets its `rustls` feature from a `rustls-ffi`
//! token in the version banner, not from the word `rustls`. Emitting
//! `rustls-ffi` would unlock the fixtures gated on that feature while
//! misdescribing an implementation that uses rustls natively rather than
//! through its C FFI, so the truthful token is emitted and the skips are
//! accepted. The asymmetry makes this the safe direction as well as the honest
//! one: under-reporting a capability makes a fixture skip, whereas
//! over-reporting makes it run and fail.
//!
//! **Versioned symbol names are not reproducible, and nothing here should
//! try.** Passing a linker version script through `-C link-arg` was
//! measured not to control a Rust `cdylib`'s exports: the script is read,
//! and `.gnu.version_d` gains the expected node, but rustc's own export
//! list takes precedence and the symbols stay unversioned. An unversioned
//! export set is exactly what curl produces when built with
//! `--disable-versioned-symbols`, which is a supported upstream
//! configuration, so the artifact remains legitimate. Setting the
//! `SONAME`, by contrast, does work, and `build.rs` owns it.
//!
//! **Every re-export `ffi/misc.rs` needs now exists.** `curl_getdate`
//! needs the date parser, which lives under `curl-rs-lib`'s `util`
//! module; `util` is `pub(crate)`, so a private path could not be named
//! from here. `curl-rs-lib`'s crate root now re-exports exactly one name
//! from that tree -- `curl_rs_lib::getdate`, backed by
//! `curl-rs-lib/src/util/parsedate.rs`. That gap was closed by widening the
//! ENGINE rather than by duplicating the parser here, because a copy would
//! put engine logic in
//! a crate whose job is the C ABI and nothing else; this crate's
//! `curl_getdate` is left with a `*const c_char` to `&str` conversion and
//! an `Option` to `time_t` mapping. The internal `Curl_getdate_capped`
//! stays `pub(crate)` in the engine, since it is not one of the 100
//! exported symbols. The equivalent needs for the other two ABI
//! obligations were already met -- the TLS backend identity is public in
//! `curl-rs-lib`'s `version` module, and every code enumeration exposes a
//! message accessor.

//!
//! # Provenance of the constraints above
//!
//! Every constraint stated in this documentation is measured against the C tree
//! this crate replaces: curl/libcurl 8.19.0-DEV, `LIBCURL_VERSION_NUM
//! 0x081300`. `lib/libcurl.def` is the export list, `include/curl/*.h` is the
//! declaration authority, and `docs/examples/*.c` is the conformance suite that
//! compiles against the generated header.

// The exported entry points, the two support modules every one of them routes
// through, and the ABI types the generated header is built from.
//
// `#![deny(unsafe_code)]` is at the head of this file, and exactly ONE
// `#[allow(unsafe_code)]` exists in the whole crate: on the `mod ffi`
// declaration at the foot of this file. Both spellings were compiled before
// either was chosen.
//
// `#![forbid(unsafe_code)]` with `#[allow(unsafe_code)]` on `mod ffi` DOES NOT
// COMPILE. Measured on the pinned toolchain, verbatim:
//
//     error[E0453]: allow(unsafe_code) incompatible with previous forbid
//       |
//     1 | #![forbid(unsafe_code)]
//       |           ----------- `forbid` level set here
//     2 |
//     3 | #[allow(unsafe_code)]
//       |         ^^^^^^^^^^^ overruled by previous forbid
//
// `forbid` is by definition un-overridable from an inner scope, so no placement
// of the `allow` rescues it, and this crate cannot do without one: an
// `extern "C"` entry point that dereferences a caller-supplied pointer is
// `unsafe` by construction. `#![deny(unsafe_code)]` with the one `allow`
// compiles, and the same `unsafe` block moved outside `src/ffi/` is a hard
// error.
//
// One gap remains and is stated rather than glossed over: `deny`, unlike
// `forbid`, CAN be overridden from an inner scope, so a second deliberate
// `#[allow(unsafe_code)]` elsewhere in this crate would compile. That is what
// `mod unsafe_boundary` at the foot of this file closes -- it walks `src/` at
// test time and asserts that exactly one exemption exists, that it is on
// `mod ffi`, and that the keyword appears nowhere outside `src/ffi/`. The check
// is executable, so weakening the boundary fails `cargo test --workspace`
// rather than merely contradicting a comment.
//
// NEVER add `#![allow(unsafe_code)]` at crate level, and NEVER add a second
// `#[allow(unsafe_code)]` anywhere. Either one converts a checked invariant
// back into a review obligation.
// THE ABI EXPORT INVENTORY, AS COMPILE-TIME CONSTANTS.
//
// `build.rs` computes how much of `lib/libcurl.def` this crate actually defines
// and, from the same computation, publishes it three ways: a line-oriented file
// at `$OUT_DIR/abi-inventory.txt` for shell and continuous integration, the
// `cargo:warning` lines a human reads, and the `cargo:rustc-env` values these
// three constants read. See `publish_abi_inventory` for why the printed warning
// alone was not enough - a `cargo:warning` cannot be branched on, so a job that
// packaged a development kit or asserted a header had been regenerated could
// not tell "generation was WITHHELD" from "generation was unnecessary", and
// both then did the wrong thing confidently.
//
// These are `pub` although the `ffi` module is not, and that is the point: they
// are the one part of this crate a Rust consumer is meant to read, because the
// question they answer - is this build's C surface trustworthy yet - has to be
// answerable before anything is shipped. They are constants, so a consumer can
// assert on them at compile time.
//
// They are not a substitute for the `nm` parity gate. `nm` measures the built
// artifact; these measure this crate's source. Both are needed, and the gate in
// `.github/workflows/rust-abi.yml` reads both.

/// How many symbols the ABI contract requires: every name in `lib/libcurl.def`.
pub const ABI_EXPORTS_REQUIRED: u32 = konst(env!("CURL_RS_ABI_REQUIRED"));

/// How many of those this crate defines today.
///
/// Equal to [`ABI_EXPORTS_REQUIRED`] exactly when the surface is complete.
pub const ABI_EXPORTS_DEFINED: u32 = konst(env!("CURL_RS_ABI_DEFINED"));

/// Whether this build promoted a complete set of generated public headers.
///
/// `false` while any required export is undefined, because a header rendered
/// from a partial crate would be short by exactly what is missing, and a header
/// that declares an export nothing provides is an undefined reference in every
/// program that calls it. While this is `false` the reviewed curl 8.19.0-DEV
/// headers in `include/curl/` are untouched and remain the ABI contract.
pub const ABI_HEADERS_GENERATED: bool =
    konst(env!("CURL_RS_ABI_HEADERS_GENERATED")) != 0;

/// Parse a build-script-supplied decimal in a `const` context.
///
/// `u32::from_str_radix` is not `const`, and `str::parse` is not either, so the
/// digits are walked by hand. A non-digit panics at COMPILE time, which is the
/// behaviour wanted: the value comes from this workspace's own build script, so
/// a malformed one is a defect here and not input to be tolerated.
const fn konst(text: &str) -> u32 {
    let bytes = text.as_bytes();
    assert!(!bytes.is_empty(), "the build script emitted an empty count");

    let mut value: u32 = 0;
    let mut i = 0;
    while i < bytes.len() {
        let digit = bytes[i];
        assert!(
            digit >= b'0' && digit <= b'9',
            "the build script emitted a non-decimal count"
        );
        value = value * 10 + (digit - b'0') as u32;
        i += 1;
    }
    value
}

// The exported entry points -- the two support modules every one of them routes
// through, and the ABI types the generated header is built from. How many are
// defined at this commit is not restated here: it is
// [`ABI_EXPORTS_DEFINED`] out of [`ABI_EXPORTS_REQUIRED`], measured by the
// build script on every build, which is what stops a hand-written count from
// going stale.
//
// The module is private on purpose: a `cdylib` exports what is declared
// `#[no_mangle] pub extern "C"` regardless of the privacy of the module holding
// it, this crate has no `rlib` target and therefore no Rust consumer, and so
// `pub` would widen the surface without widening what any caller can reach. For
// the same reason there is no `pub use ffi::*`.
#[allow(unsafe_code)]
mod ffi;

// The executable half of the safety gate.

#[cfg(test)]
mod unsafe_boundary {
    use std::fs;
    use std::path::{Path, PathBuf};

    /// Every `.rs` file under `src/`, relative to the crate directory.
    fn sources() -> Vec<PathBuf> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut found = Vec::new();
        walk(&root, &mut found);
        assert!(
            !found.is_empty(),
            "the walk must find this crate's own sources, or the gate is vacuous"
        );
        found.sort();
        found
    }

    fn walk(dir: &Path, found: &mut Vec<PathBuf>) {
        let entries = fs::read_dir(dir).unwrap_or_else(|error| {
            panic!("cannot read {}: {error}", dir.display())
        });
        for entry in entries {
            let path = entry.expect("a readable directory entry").path();
            if path.is_dir() {
                walk(&path, found);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                found.push(path);
            }
        }
    }

    /// True when `line` *is* an `allow(unsafe_code)` attribute rather than prose
    /// mentioning one.
    ///
    /// The anchoring is what makes the check usable: this file legitimately
    /// discusses the attribute many times over, and an unanchored search matches
    /// the discussion and reports a false failure. Skipping leading whitespace
    /// and then requiring `#[` or `#![` means a comment can never match, because
    /// a comment begins with a slash.
    fn is_allow_attribute(line: &str) -> bool {
        let trimmed = line.trim_start();
        trimmed.starts_with("#[allow(unsafe_code)]")
            || trimmed.starts_with("#![allow(unsafe_code)]")
    }

    /// `line` with its comment tail and every string literal removed, leaving
    /// only the code that the compiler would see as identifiers and punctuation.
    fn code_only(line: &str) -> String {
        let without_comment = line.split("//").next().unwrap_or("");
        let mut out = String::with_capacity(without_comment.len());
        let mut in_string = false;
        let mut escaped = false;
        for ch in without_comment.chars() {
            if in_string {
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == '"' {
                    in_string = false;
                }
                continue;
            }
            if ch == '"' {
                in_string = true;
                // A space keeps the surrounding tokens apart, so a literal
                // between two identifiers cannot fuse them into one word.
                out.push(' ');
                continue;
            }
            out.push(ch);
        }
        out
    }

    /// True when `line` uses the `unsafe` keyword as code.
    fn uses_unsafe_keyword(line: &str) -> bool {
        code_only(line)
            .split(|c: char| !c.is_alphanumeric() && c != '_')
            .any(|word| word == "unsafe")
    }

    /// Does `code` open a raw string literal?
    fn starts_a_raw_string(code: &str) -> bool {
        let bytes = code.as_bytes();
        for (i, _) in code.match_indices('r') {
            if i > 0 {
                let prev = bytes[i - 1];
                if prev.is_ascii_alphanumeric() || prev == b'_' {
                    continue;
                }
            }
            let mut j = i + 1;
            while j < bytes.len() && bytes[j] == b'#' {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'"' {
                return true;
            }
        }
        false
    }

    #[test]
    fn the_raw_string_detector_discriminates() {
        // Real raw strings, which must be caught.
        assert!(starts_a_raw_string("let a = r\"x\";"));
        assert!(starts_a_raw_string("let a = r#\"x\"#;"));
        assert!(starts_a_raw_string("let a = r###\"x\"###;"));
        assert!(starts_a_raw_string("r\"at the start\""));
        assert!(starts_a_raw_string("(r\"after a paren\")"));
        // Not raw strings. The first is the case that actually fired: an
        // ordinary literal whose last word ends in `r`.
        assert!(!starts_a_raw_string("\"every callback accounted for\""));
        assert!(!starts_a_raw_string("\"a user\", \"a doctor\""));
        assert!(!starts_a_raw_string("let r = 1;"));
        assert!(!starts_a_raw_string("foo(bar\")"));
        assert!(!starts_a_raw_string("let x: r#type = 1;"));
        assert!(!starts_a_raw_string(""));
    }

    #[test]
    fn the_gate_sees_no_raw_string_literals() {
        // [`code_only`] does not understand `r"..."` or `r#"..."#`. Rather than
        // implement a lexer, the gate asserts the simplification holds: no
        // source under `src/` uses a raw string. If one is ever introduced, this
        // test fails and says so, instead of the two checks below silently
        // losing coverage.
        let mut offenders = Vec::new();
        for path in sources() {
            let text =
                fs::read_to_string(&path).expect("a readable source file");
            for (index, line) in text.lines().enumerate() {
                let code = line.split("//").next().unwrap_or("");
                if starts_a_raw_string(code) {
                    offenders.push(format!("{}:{}", path.display(), index + 1));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "code_only does not lex raw strings; found {offenders:?}"
        );
    }

    #[test]
    fn exactly_one_exemption_exists_and_it_is_on_mod_ffi() {
        let mut sites = Vec::new();
        for path in sources() {
            let text =
                fs::read_to_string(&path).expect("a readable source file");
            let lines: Vec<&str> = text.lines().collect();
            for (index, line) in lines.iter().enumerate() {
                if is_allow_attribute(line) {
                    // The declaration the attribute applies to is the next line
                    // that is neither blank nor another attribute.
                    let target = lines[index + 1..]
                        .iter()
                        .find(|next| {
                            let t = next.trim_start();
                            !t.is_empty() && !t.starts_with('#')
                        })
                        .copied()
                        .unwrap_or("");
                    sites.push((
                        path.clone(),
                        index + 1,
                        target.trim().to_string(),
                    ));
                }
            }
        }

        assert_eq!(
            sites.len(),
            1,
            "exactly one allow(unsafe_code) may exist in this crate; found {sites:?}"
        );
        let (path, _line, target) = &sites[0];
        assert!(
            path.ends_with("src/lib.rs"),
            "the one exemption must live in the crate root, not {}",
            path.display()
        );
        assert_eq!(
            target, "mod ffi;",
            "the one exemption must apply to `mod ffi`, not to {target:?}"
        );
    }

    #[test]
    fn the_unsafe_keyword_appears_only_under_src_ffi() {
        let mut outside = Vec::new();
        let mut inside = 0usize;
        for path in sources() {
            let under_ffi = path
                .components()
                .any(|component| component.as_os_str() == "ffi");
            let text =
                fs::read_to_string(&path).expect("a readable source file");
            for (index, line) in text.lines().enumerate() {
                if uses_unsafe_keyword(line) {
                    if under_ffi {
                        inside += 1;
                    } else {
                        outside.push(format!(
                            "{}:{}",
                            path.display(),
                            index + 1
                        ));
                    }
                }
            }
        }

        assert!(
            outside.is_empty(),
            "`unsafe` may appear only under src/ffi/; found {outside:?}"
        );
        // Discriminating rather than vacuous: the FFI tree really does use the
        // keyword, so an expression that matched nothing would be caught here.
        assert!(
            inside > 0,
            "the gate found no `unsafe` under src/ffi/, so it is not testing \
             anything"
        );
    }

    #[test]
    fn every_unsafe_block_under_src_ffi_is_covered_by_a_safety_comment() {
        // "Immediately preceded by a `// SAFETY:` line" is the natural phrasing
        // and is measurably wrong: the justifications here run to several lines,
        // so the line directly above an `unsafe` is the LAST line of the block,
        // not its opener. The check walks back over blank lines and attributes,
        // then over the contiguous run of `//` comment lines, and requires that
        // run to contain a line beginning `// SAFETY:`.
        //
        // Only `unsafe` *blocks* and `unsafe` *impl*s need a justification. An
        // `unsafe fn` declaration and an `unsafe extern "C" fn` definition state
        // their contract in their doc comment instead, which is where a caller
        // reads it.
        let mut uncovered = Vec::new();
        let mut covered = 0usize;
        for path in sources() {
            if !path.components().any(|c| c.as_os_str() == "ffi") {
                continue;
            }
            let text =
                fs::read_to_string(&path).expect("a readable source file");
            let lines: Vec<&str> = text.lines().collect();
            for (index, line) in lines.iter().enumerate() {
                let stripped = code_only(line);
                let code = stripped.trim();
                let is_block = code == "unsafe {"
                    || code.ends_with(" unsafe {")
                    || code.starts_with("unsafe impl ");
                if !is_block {
                    continue;
                }
                let mut cursor = index;
                let mut found = false;
                while cursor > 0 {
                    cursor -= 1;
                    let above = lines[cursor].trim_start();
                    if above.is_empty() || above.starts_with('#') {
                        continue;
                    }
                    if above.starts_with("//") {
                        if above.starts_with("// SAFETY:") {
                            found = true;
                            break;
                        }
                        continue;
                    }
                    break;
                }
                if found {
                    covered += 1;
                } else {
                    uncovered.push(format!("{}:{}", path.display(), index + 1));
                }
            }
        }

        assert!(
            uncovered.is_empty(),
            "every unsafe block under src/ffi/ needs a `// SAFETY:` comment; \
             uncovered: {uncovered:?}"
        );
        assert!(covered > 0, "the gate found no unsafe blocks to check");
    }
}

// The executable half of the capability-truthfulness contract.
//
// THE ASSERTION IS ASYMMETRIC, ON PURPOSE. Specification 0.6.5 measured that
// `tests/runtests.pl` uses the advertised sets to decide fixture eligibility:
// under-reporting a capability makes a fixture SKIP, while over-reporting makes
// it RUN AND FAIL. So the contract is containment, not equality --
// static must be a SUBSET of runtime. That is what lets the static metadata
// legitimately withhold `GSS-API`, `Kerberos` and `SPNEGO`, whose availability
// only a running process can establish.

#[cfg(test)]
mod capability_truthfulness {
    /// The generated pkg-config metadata, baked in at compile time.
    ///
    /// `include_str!` rather than a runtime read: it guarantees the gate sees
    /// exactly the artifact this build produced, and makes a missing file a
    /// compile error instead of a silently skipped assertion.
    const LIBCURL_PC: &str =
        include_str!(concat!(env!("OUT_DIR"), "/libcurl.pc"));

    /// The value of one `key="value"` line of the generated metadata.
    fn pc_variable(key: &str) -> Vec<String> {
        let prefix = format!("{key}=");
        let line = LIBCURL_PC
            .lines()
            .find(|line| line.starts_with(&prefix))
            .unwrap_or_else(|| {
                panic!(
                    "the generated libcurl.pc declares no `{key}`; the gate \
                     cannot confirm the advertised set without it"
                )
            });
        line[prefix.len()..]
            .trim()
            .trim_matches('"')
            .split_whitespace()
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn static_metadata_never_advertises_a_feature_the_engine_withholds() {
        let advertised = pc_variable("supported_features");
        let runtime = curl_rs_lib::version::feature_names();

        assert!(
            !advertised.is_empty(),
            "the generated metadata advertises no feature at all, which would \
             make the derivation vacuous"
        );

        let over: Vec<&String> = advertised
            .iter()
            .filter(|token| !runtime.contains(&token.as_str()))
            .collect();
        assert!(
            over.is_empty(),
            "the generated metadata advertises {over:?}, which the engine's \
             own banner does not. Over-reporting makes a gated fixture run and \
             fail (specification 0.6.5), so the two surfaces must not diverge \
             in this direction. Advertised: {advertised:?}; runtime: {runtime:?}"
        );
    }

    #[test]
    fn debug_and_trackmemory_never_appear_in_generated_metadata() {
        let advertised = pc_variable("supported_features");
        for forbidden in ["Debug", "TrackMemory"] {
            assert!(
                !advertised.iter().any(|token| token == forbidden),
                "{forbidden} must never be advertised (specification 0.6.6); \
                 found it in {advertised:?}"
            );
        }
    }

    #[test]
    fn the_two_protocol_surfaces_agree_under_the_documented_case_rule() {
        // The engine spells schemes lower case, as `curl --version` does;
        // `curl-config --protocols` and pkg-config spell them upper case, as
        // configure.ac:5327 and CMakeLists.txt:1994 do. One list serves both,
        // so the only permitted difference is that case change.
        let advertised = pc_variable("supported_protocols");
        let runtime: Vec<String> = curl_rs_lib::version::protocols()
            .iter()
            .map(|scheme| scheme.to_uppercase())
            .collect();

        // NOT asserted non-empty, and the reason is the same honesty rule the
        // rest of this module turns on. Requiring a scheme here would demand
        // that the metadata claim one -- over-reporting, which makes a gated
        // fixture run and fail, where under-reporting only makes it skip. What
        // IS asserted is that the two surfaces agree, in either direction: one
        // going non-empty while the other stays empty is exactly the
        // divergence this test exists to catch, and it fails the comparison
        // below.
        let mut expected = runtime;
        expected.sort_unstable();
        let mut found = advertised;
        found.sort_unstable();
        assert_eq!(
            found, expected,
            "the generated protocol list and the engine's banner disagree. \
             They are derived from one table, so a difference here means the \
             derivation or the case rule is wrong."
        );
    }
}

// The executable half of the cross-crate seam.
//
// `curl_getdate` is one of the 100 exported symbols and
// needs a date parser, which lives in `curl-rs-lib`'s `pub(crate) mod util`.
// A private path cannot be named across a crate boundary, so before the fix
// this crate had exactly two options -- reimplement `lib/parsedate.c` here, or
// widen the engine. It was closed by widening the engine, because a copy would
// put protocol-adjacent logic in a crate whose entire job is the C ABI.
//
// The test below asserts the SEAM, not the parser: that the one re-exported
// name is reachable from here, that it answers correctly, and that the two
// quirks of `curl_getdate`'s contract are already applied on the engine side so
// the eventual `extern "C"` shim contains nothing but marshalling. The parser
// itself is verified against the real `libcurl.so.4` in
// `curl-rs-lib/src/util/parsedate.rs`, which is where that evidence belongs.

#[cfg(test)]
mod engine_seam {
    // The boundary's own module, named rather than glob-imported so every use
    // below reads `panic_boundary::...` and stays attributable to it. The
    // process types are needed because the hook writes to the real standard
    // error, which only a child process can observe -- see
    // [`spawn_panic_child`].
    use crate::ffi::panic_boundary;
    use std::process::{Command, Output, Stdio};

    /// The engine's date parser is reachable and correct from this crate.
    #[test]
    fn the_date_parser_is_reachable_through_the_crate_root() {
        // Named through the ROOT re-export. `curl_rs_lib::util::parsedate::...`
        // would not compile, and that is the point: the engine exposes one
        // name, not a module.
        assert_eq!(
            curl_rs_lib::getdate("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some(784_111_777)
        );
        // Failure is out of band, so the shim maps `None` to `-1` and needs no
        // knowledge of why the parse failed.
        assert_eq!(curl_rs_lib::getdate("not a date"), None);
    }

    #[test]
    fn the_minus_one_quirk_is_already_applied_on_the_engine_side() {
        // `curl_getdate` cannot return -1 for a SUCCESSFUL parse, because -1
        // is its failure sentinel; C increments that one instant to 0. If the
        // engine did not do this, the shim would have to, and the finding
        // would only have moved rather than been resolved.
        assert_eq!(
            curl_rs_lib::getdate("Wed, 31 Dec 1969 23:59:59 GMT"),
            Some(0)
        );
        // Which means no successful parse ever yields the sentinel, so
        // `unwrap_or(-1)` in the shim is unambiguous.
        for input in [
            "Wed, 31 Dec 1969 23:59:59 GMT",
            "Thu, 01 Jan 1970 00:00:00 GMT",
            "Wed, 31 Dec 1969 23:59:58 GMT",
            "Sun, 06 Nov 1994 08:49:37 GMT",
        ] {
            assert_ne!(
                curl_rs_lib::getdate(input),
                Some(-1),
                "{input:?} must not collide with the failure sentinel"
            );
        }
    }

    #[test]
    fn the_internal_capped_variant_is_not_reachable_from_here() {
        // `Curl_getdate_capped` is NOT one of the 100 exported symbols, so the
        // engine keeps it `pub(crate)`. This test documents that boundary; the
        // compiler enforces it. Uncommenting the line below is a compile error
        // (E0603, module `util` is private), which is the desired state:
        //
        //     curl_rs_lib::util::parsedate::getdate_capped("20011231");
        assert!(curl_rs_lib::getdate("20011231").is_some());
    }

    // -- The crate-root safety gate ---------------------------

    #[test]
    fn the_audited_unsafe_allowance_is_exactly_one() {
        // The invariant the crate-root gate names, asserted rather than
        // described. `#![deny(unsafe_code)]` is defeatable by an inner allow,
        // so the count is the second half of the enforcement: a fourth
        // allowance is a finding, and this is where it is caught.
        //
        // Read from disk so the assertion is about the files rather than
        // about a copy of the list kept in the test, and read EVERY source in
        // the crate rather than this one, because the gap the gate names is an
        // allowance "elsewhere in this crate": `deny`, unlike `forbid`, can be
        // overridden from an inner scope, so counting only this file would
        // leave the one placement that defeats it unmeasured. The pattern is
        // anchored to column zero, exactly as the comment on the gate
        // specifies, because an unanchored one also matches the prose.
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
        let mut sources = Vec::new();
        let mut pending = vec![std::path::PathBuf::from(root)];
        while let Some(directory) = pending.pop() {
            let Ok(entries) = std::fs::read_dir(&directory) else {
                // Reachable when this crate is compiled outside the workspace
                // layout; the assertion would then be about the harness.
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    pending.push(path);
                } else if path.extension().is_some_and(|ext| ext == "rs") {
                    sources.push(path);
                }
            }
        }
        assert!(
            sources.len() >= 2,
            "the crate has more than one source file; found {sources:?}"
        );

        let mut carriers = Vec::new();
        for path in &sources {
            let text = std::fs::read_to_string(path).expect("a readable file");
            let count = text
                .lines()
                .filter(|line| *line == "#[allow(unsafe_code)]")
                .count();
            for _ in 0..count {
                carriers.push(path.clone());
            }
        }
        assert_eq!(
            carriers.len(),
            1,
            "exactly ONE `#[allow(unsafe_code)]` may exist in this crate -- on \
             the `mod ffi` declaration at the foot of the crate root. A second \
             one compiles, which is why it is counted here. Found: {carriers:?}"
        );
        assert!(
            carriers[0].ends_with("lib.rs"),
            "the single allowance must sit on the `mod ffi` declaration in the \
             crate root, not in a module that the root cannot audit; found \
             {carriers:?}"
        );

        // And the crate root really is at `deny`, not merely documented as
        // such. Measured, because a lint level that is only in a comment
        // enforces nothing -- which was the whole of the finding. This half
        // reads the root through `include_str!`, which cannot fail, so the
        // level is asserted even where the directory walk above bailed out.
        let source = include_str!("lib.rs");
        assert!(
            source.lines().any(|line| line == "#![deny(unsafe_code)]"),
            "the crate root must deny unsafe_code"
        );
        assert!(
            !source.lines().any(|line| line == "#![allow(unsafe_code)]"),
            "a crate-level allow would silently undo the gate"
        );
    }

    // -- The variadic inventory, bound to the build gate ------

    /// The eleven names in this test, read out of the build script.
    ///
    /// Parsing rather than duplicating, because a duplicate is a third place
    /// to keep in step and the whole point of the assertion is that there are
    /// only two.
    fn build_script_inventory() -> Vec<String> {
        let script = include_str!("../build.rs");
        let start = script
            .find("const VARIADIC_UNIMPLEMENTABLE:")
            .expect("build.rs must declare VARIADIC_UNIMPLEMENTABLE");
        let body = &script[start..];
        let end = body.find("\n];").expect("the array must be terminated");
        body[..end]
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                line.strip_prefix('"')
                    .and_then(|rest| rest.split('"').next())
                    .map(str::to_owned)
            })
            .collect()
    }

    #[test]
    fn the_variadic_inventory_matches_the_build_gate() {
        // Finding 20 asked for three things: establish exactly which exports
        // have no ABI-correct implementation, make that state impossible to
        // ship silently, and document the decision it needs. The first and
        // third live in the crate documentation above; the second lives in
        // build.rs. This test is what stops the two from diverging, because a
        // documented caveat that no longer matches the enforcement is worse
        // than no caveat -- a reader would trust it.
        let inventory = build_script_inventory();
        assert_eq!(
            inventory.len(),
            11,
            "the build gate must name exactly eleven exports, found {inventory:?}"
        );

        let doc = include_str!("lib.rs");
        // The caveat section ALONE, not the whole crate documentation. Scoping
        // this correctly is the difference between an assertion and a
        // formality, and it was measured: with the whole documentation
        // searched, deleting `curl_maprintf` from the caveat still passed,
        // because the name also appears in the module table and in the memory
        // section. Neither of those tells a reader the symbol is
        // unimplemented, which is the only claim this test is about.
        // Anchored with its surrounding newlines so the search cannot
        // match this literal itself: in the documentation the heading is a
        // line of its own, while here it sits inside a string on a line of
        // code. Without the anchors `find` returns this offset instead,
        // and the section then appears to have no following heading.
        let heading = "\n//! # Open items\n";
        let start = doc
            .find(heading)
            .expect("the crate documentation must carry an open-items section");
        let body = &doc[start + heading.len()..];
        let end = body.find("\n//! # ").expect(
            "the open-items section must be followed by another heading",
        );
        let caveats = &body[..end];
        assert!(
            caveats.len() > 3_000,
            "the open-items section did not parse out; got {} bytes",
            caveats.len()
        );
        for name in &inventory {
            assert!(
                caveats.contains(name.as_str()),
                "{name} is refused by the build gate but is not named among \
                 the crate's open items, so a reader has no way to learn it \
                 is unimplemented. Naming it elsewhere does not count: the \
                 module table lists it as a symbol this crate exports, which \
                 is the opposite claim."
            );
        }

        // The spellings the diagnostics quote. A message that names the wrong
        // variable sends a reader to change something that does not exist, and
        // the two constants are what the messages are built from.
        let script = include_str!("../build.rs");
        for (constant, quoted) in [
            ("A4_DECISION_ENV", "CURL_RS_A4_VARIADIC_DECISION"),
            ("A4_ACCEPTED", "accept-unsupported-varargs"),
        ] {
            assert!(
                script.contains(&format!(
                    "const {constant}: &str = \"{quoted}\";"
                )),
                "build.rs must define {constant} as {quoted:?}"
            );
            assert!(
                caveats.contains(quoted),
                "the open-items section must quote {quoted:?} verbatim"
            );
        }

        // And the gate must REFUSE, unconditionally, which is the stronger
        // form of the original finding. Asserted on the shape of the code,
        // because a gate that returns `Ok(Some(..))` on the Apple arm64 path
        // is a warning wearing a refusal's name -- and one that consults an
        // environment variable first is a bypass wearing one.
        let arm = script
            .find("if os == \"macos\" && arch == \"aarch64\" {")
            .expect("build.rs must guard the Apple arm64 configuration");
        let tail = &script[arm..];
        let body = &tail[..tail.find("\n    }").unwrap_or(tail.len())];
        assert!(
            body.contains("return Err("),
            "the aarch64-apple-darwin arm must fail the build, not warn"
        );

        // The bypass must be structurally absent rather than merely unused. An
        // `accepted` binding is how it was spelled, so its reappearance
        // anywhere in the script is the regression this asserts against.
        assert!(
            !script.contains("let accepted = decision =="),
            "build.rs must not derive an acceptance flag from \
             {A4_DECISION_ENV_NAME}: the Apple arm64 refusal is unconditional \
             and no environment value may release it"
        );
        assert!(
            !body.contains("accepted"),
            "the aarch64-apple-darwin arm must not consult any acceptance \
             state; found: {body}"
        );

        // And the variable must still be DIAGNOSED, not ignored. A build that
        // sets it believes an artifact is being released that is not, and
        // silence would confirm the belief.
        assert!(
            script
                .contains("and no value of it \\\n             does anything")
                || script.contains("no value of it does anything"),
            "build.rs must refuse a set {A4_DECISION_ENV_NAME} with an \
             explanation rather than ignoring it"
        );
    }

    /// The environment variable name, for the assertions above.
    ///
    /// Spelled once here rather than three times inline, and deliberately not
    /// read from `build.rs`: an assertion that quoted the script's own value
    /// back at it would pass however the script was edited.
    const A4_DECISION_ENV_NAME: &str = "CURL_RS_A4_VARIADIC_DECISION";

    /// The module partition in the crate documentation must still partition the
    /// authority: its Count column must sum to the number of names in
    /// `lib/libcurl.def`, and the prose sum must agree with the column.
    ///
    /// WHY THIS EXISTS. The table is a hand-maintained partition of a
    /// hand-maintained authority, and it drifted: a row read `ffi/easy.rs | 18`
    /// after two of those eighteen symbols had moved into `ffi/escape.rs`, so
    /// the column summed to 100 only because the moved pair was counted in a
    /// row that no longer held it. Nothing failed. A partition that is wrong in
    /// two places that cancel is the hardest kind to notice by reading, and the
    /// arithmetic is exactly what a machine should check instead.
    ///
    /// The three numbers are read from three independent places -- the table
    /// column, the prose sum, and `lib/libcurl.def` -- so agreement is
    /// meaningful. Splitting a module, moving a symbol between modules or
    /// mis-transcribing the authority all break it.
    #[test]
    fn the_module_partition_sums_to_the_authority() {
        // The authority itself, not a constant transcribed from it. `EXPORTS`
        // and any blank or comment line are not symbols.
        let authority = include_str!("../../lib/libcurl.def")
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with("curl_"))
            .count();
        assert_eq!(
            authority, 100,
            "lib/libcurl.def must list the 100 names specification 0.1.1 \
             derives from it; found {authority}"
        );

        let doc = include_str!("lib.rs");

        // The Count column. A row is `//! | `ffi/x.rs` | <n> | <derivation> |`,
        // and the header and separator rows carry no number in that position,
        // so parsing the cell rather than matching a pattern is enough to skip
        // them. The `| 0 |` row for the type-only modules participates
        // correctly: it adds nothing and asserts nothing is owed.
        let mut column = 0usize;
        let mut rows = 0usize;
        for line in doc.lines() {
            let Some(row) = line.strip_prefix("//! |") else {
                continue;
            };
            let cells: Vec<&str> = row.split('|').map(str::trim).collect();
            // Module, Count, Derivation, and the empty cell after the trailing
            // pipe. Anything else is not one of these rows.
            if cells.len() != 4 {
                continue;
            }
            if let Ok(count) = cells[1].parse::<usize>() {
                column += count;
                rows += 1;
            }
        }
        assert!(
            rows >= 13,
            "the module table did not parse out; found {rows} counted row(s)"
        );
        assert_eq!(
            column, authority,
            "the Count column of the module table sums to {column}, but \
             lib/libcurl.def lists {authority} names. The table is a partition \
             of that authority, so every name must be owed to exactly one \
             module: a mismatch means a symbol is unowned or double-owned."
        );

        // The prose sum, which a reader checks by eye and therefore must agree
        // with the column rather than merely with 100. Both directions matter:
        // the addends must total the authority AND there must be one addend per
        // counted row, so moving a symbol between two rows cannot leave the
        // prose looking right.
        let marker = "//! Sum: ";
        let line = doc
            .lines()
            .find(|line| line.starts_with(marker))
            .expect("the crate documentation must carry the partition sum");
        let addends: Vec<usize> = line[marker.len()..]
            .split('=')
            .next()
            .unwrap_or_default()
            .split('+')
            .filter_map(|term| term.trim().parse::<usize>().ok())
            .collect();
        assert_eq!(
            addends.iter().sum::<usize>(),
            authority,
            "the documented sum {addends:?} does not total the {authority} \
             names in lib/libcurl.def"
        );
        assert_eq!(
            addends.len(),
            rows - 1,
            "the documented sum has {} addends for {rows} counted table rows. \
             One row -- the type-only modules, which own no symbol -- is \
             deliberately absent from the sum; any other difference means the \
             prose and the table disagree about how many modules there are.",
            addends.len()
        );

        // THE PART THAT CATCHES WHAT THE ARITHMETIC CANNOT. The historical
        // defect balanced: two symbols moved out of `ffi/easy.rs` into a new
        // `ffi/escape.rs` while the `easy` row kept counting them, so the column
        // still summed to 100 and every check above would have passed. What was
        // actually wrong is that a file existed which no row named. So the table
        // is required to be a complete inventory of `src/ffi/`: every module
        // there must appear somewhere in it, including the ones that own no
        // symbol and are named collectively in the last row. A new module then
        // cannot be added without deciding, in the table, what it owns.
        let table_start = doc
            .find("//! | Module | Count | Derivation |")
            .expect("the crate documentation must carry the module table");
        let table_end = table_start
            + doc[table_start..]
                .find("\n//! Sum: ")
                .expect("the module table must be followed by its sum");
        let table = &doc[table_start..table_end];

        let ffi =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/ffi");
        let mut modules: Vec<String> = std::fs::read_dir(&ffi)
            .unwrap_or_else(|error| {
                panic!("cannot read {}: {error}", ffi.display())
            })
            .filter_map(|entry| {
                let path = entry.ok()?.path();
                if path.extension()? != "rs" {
                    return None;
                }
                Some(path.file_stem()?.to_str()?.to_owned())
            })
            .collect();
        modules.sort();
        assert!(
            modules.len() >= 17,
            "the ffi directory did not enumerate; found {modules:?}"
        );
        for module in &modules {
            assert!(
                table.contains(module.as_str()),
                "src/ffi/{module}.rs exists but no row of the module table \
                 names it, so the table is not the complete partition it is \
                 documented to be. Whatever that module owns is currently \
                 either unowned or counted against a module that does not hold \
                 it -- the exact drift that let two curl_easy_* symbols be \
                 counted in the easy row after they moved to escape.rs. Give it \
                 a row, or add it to the row for the modules that own nothing."
            );
        }
    }

    // -- Redaction and poisoning at the boundary --------------

    #[test]
    fn the_redacted_line_carries_no_payload_and_no_path() {
        // What the hook is permitted to write, asserted byte by byte. The
        // point of the constant is that nothing derived from the caller's data
        // or from the build machine can reach standard error, so the assertion
        // is that the line is free of every ingredient the default hook would
        // have included.
        let line = panic_boundary::REDACTED_PANIC_LINE;
        assert!(line.ends_with('\n'), "one line, terminated");
        assert_eq!(line.lines().count(), 1, "exactly one line");
        assert!(line.contains("libcurl bug"), "it must name the fault class");

        for leak in [
            "panicked at", // the default hook's own wording
            ".rs",         // any source filename
            "/",           // any path separator, absolute or relative
            "curl-rs",     // any crate directory
            "src",         // the source directory
        ] {
            assert!(
                !line.contains(leak),
                "the redacted line must not contain {leak:?}"
            );
        }
        assert!(
            line.is_ascii() && !line.trim_end().contains('\n'),
            "no embedded newline could forge a second line"
        );
    }

    #[test]
    fn redaction_applies_inside_the_boundary_and_nowhere_else() {
        // The whole of the hook's decision, and the reason it is factored out
        // of the hook: a `PanicHookInfo` cannot be constructed by a test.
        assert!(
            !panic_boundary::would_redact(),
            "a panic outside the boundary belongs to the application"
        );

        let inside = panic_boundary::guard(false, panic_boundary::would_redact);
        assert!(inside, "a panic raised inside the boundary is ours");

        // And the depth is released again, unwind or not. Asserted after a
        // guard that *did* panic, because that is the path where a plain
        // decrement rather than a drop guard would leak the count and redact
        // every later panic in the process.
        let _: i32 =
            panic_boundary::guard(0, || panic!("contained on purpose"));
        assert!(
            !panic_boundary::would_redact(),
            "the depth must be released on the unwinding path too"
        );
    }

    #[test]
    fn a_healthy_handle_runs_its_body_and_stays_usable() {
        let poison = panic_boundary::Poison::new();
        assert!(!poison.is_poisoned());
        let observed = panic_boundary::guard_tx(&poison, -1, || 41 + 1);
        assert_eq!(observed, 42);
        assert!(
            !poison.is_poisoned(),
            "a completed mutation must not poison"
        );
    }

    #[test]
    fn a_panic_before_a_mutation_poisons_the_handle() {
        // Half one of what the finding asks to be tested. `catch_unwind`
        // reports only that the body did not finish, so a panic that never
        // reached the first write is treated exactly like one that did --
        // conservative on purpose, and asserted so the conservatism is a
        // property rather than an accident.
        let poison = panic_boundary::Poison::new();
        let mut mutated = false;
        let observed = panic_boundary::guard_tx(&poison, -1, || {
            panic!("contained on purpose");
            #[allow(unreachable_code)]
            {
                mutated = true;
                0
            }
        });
        assert_eq!(observed, -1, "the caller sees the documented fallback");
        assert!(!mutated, "nothing was written");
        assert!(poison.is_poisoned(), "and the handle is still poisoned");
    }

    #[test]
    fn a_panic_after_a_mutation_poisons_the_handle() {
        // Half two. The mutation really happened, so the handle is observably
        // half-updated -- which is exactly the state the poison flag exists to
        // stop anyone reading.
        let poison = panic_boundary::Poison::new();
        let mut staged = 0u32;
        let observed = panic_boundary::guard_tx(&poison, -1, || {
            staged = 7;
            panic!("contained on purpose")
        });
        assert_eq!(observed, -1);
        assert_eq!(staged, 7, "the half-applied write is real");
        assert!(poison.is_poisoned());
    }

    #[test]
    fn a_poisoned_handle_never_runs_another_body() {
        // The property that makes poisoning worth anything: the half-mutated
        // state is not merely flagged, it is never read again. A short-circuit
        // that still ran the body would leave the flag as decoration.
        let poison = panic_boundary::Poison::new();
        poison.poison();

        let mut ran = false;
        let observed = panic_boundary::guard_tx(&poison, -1, || {
            ran = true;
            0
        });
        assert_eq!(observed, -1);
        assert!(!ran, "the body of a poisoned handle must not run");
    }

    #[test]
    fn poisoning_is_idempotent_and_one_way() {
        // There is deliberately no `unpoison`, so the only assertion available
        // is that repetition changes nothing. Recorded as a test because the
        // absence of an escape hatch is a design decision that a later edit
        // could quietly reverse.
        let poison = panic_boundary::Poison::new();
        poison.poison();
        poison.poison();
        assert!(poison.is_poisoned());
        // `Default` and `new` must agree: a handle built either way starts
        // healthy, so neither constructor can become the one that forgets.
        assert!(!panic_boundary::Poison::default().is_poisoned());
    }

    #[test]
    fn a_contained_panic_in_a_transaction_is_still_counted() {
        // `guard_tx` composes with `guard` rather than reimplementing it, so
        // the panic must reach the same counter. If it stopped doing so, a
        // whole family of entry points would become invisible to the only
        // health signal this boundary publishes.
        let before = panic_boundary::contained();
        let poison = panic_boundary::Poison::new();
        let _: i32 =
            panic_boundary::guard_tx(&poison, -1, || panic!("on purpose"));
        assert!(panic_boundary::contained() > before);
    }

    /// The libtest name of a test in this module, for re-execution.
    ///
    /// Derived from `module_path!()` with the crate segment dropped, so the
    /// same code addresses the test whether this file is compiled as the
    /// `curl` library or included by an out-of-tree type-check harness under a
    /// different crate name.
    fn child_test_path(function: &str) -> String {
        let module = module_path!();
        let inner = match module.find("::") {
            Some(at) => &module[at + 2..],
            None => "",
        };
        if inner.is_empty() {
            function.to_string()
        } else {
            format!("{inner}::{function}")
        }
    }

    /// The payload the redaction tests look for. Deliberately distinctive.
    const SENSITIVE_PAYLOAD: &str = "blitzy-secret-payload-9f3c";

    /// Set in the child to select the panic, so a plain run costs nothing.
    const PANIC_CHILD_VAR: &str = "BLITZY_FFI_PANIC_CHILD";

    /// Re-executes `function` in a child, returning its captured output.
    ///
    /// The hook writes to the process's real standard error, which cannot be
    /// redirected in-process without `dup2`. A child is therefore the only way
    /// to observe what a C application would actually see, and observing that
    /// -- rather than the decision that leads to it -- is the whole point.
    fn spawn_panic_child(function: &str, verbose: bool) -> Option<Output> {
        let executable = std::env::current_exe().ok()?;
        let mut command = Command::new(executable);
        command
            .arg("--exact")
            .arg(child_test_path(function))
            .arg("--nocapture")
            .env(PANIC_CHILD_VAR, "1")
            .stdin(Stdio::null());
        if verbose {
            command.env(panic_boundary::VERBOSE_ENV, "1");
        } else {
            command.env_remove(panic_boundary::VERBOSE_ENV);
        }
        command.output().ok()
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "re-executes the test binary; current_exe needs readlink, which \
                  Miri's isolation refuses"
    )]
    fn a_boundary_panic_reaches_stderr_redacted() {
        let Some(output) =
            spawn_panic_child("panic_child_raises_in_guard", false)
        else {
            // A host that cannot spawn is not a host on which this property can
            // be observed at all, so skipping is the honest answer rather than
            // asserting something weaker.
            return;
        };
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            stderr.contains(panic_boundary::REDACTED_PANIC_LINE.trim_end()),
            "the constant line must reach stderr, got: {stderr:?}"
        );
        assert!(
            !stderr.contains(SENSITIVE_PAYLOAD),
            "the payload must never reach stderr, got: {stderr:?}"
        );
        assert!(
            !stderr.contains("panicked at"),
            "the default hook's wording must not appear, got: {stderr:?}"
        );
        assert!(
            output.status.success(),
            "the panic is contained, so the child still passes"
        );
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "re-executes the test binary; current_exe needs readlink, which \
                  Miri's isolation refuses"
    )]
    fn the_verbose_opt_in_restores_the_unredacted_diagnostic() {
        // The other side of the same mechanism, and the proof that the hook is
        // what suppresses rather than something else swallowing the output. If
        // this passed while the test above also passed for the wrong reason --
        // stderr simply never receiving anything -- the payload could not
        // appear here.
        let Some(output) =
            spawn_panic_child("panic_child_raises_in_guard", true)
        else {
            return;
        };
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            stderr.contains(SENSITIVE_PAYLOAD),
            "CURL_RS_PANIC_VERBOSE must restore the payload, got: {stderr:?}"
        );
        assert!(
            !stderr.contains(panic_boundary::REDACTED_PANIC_LINE.trim_end()),
            "and must not also emit the redacted line, got: {stderr:?}"
        );
    }

    #[test]
    fn panic_child_raises_in_guard() {
        // Returns immediately unless a parent selected it, so an ordinary run
        // of the suite pays nothing for it.
        if std::env::var_os(PANIC_CHILD_VAR).is_none() {
            return;
        }
        let observed: i32 =
            panic_boundary::guard(2, || panic!("{SENSITIVE_PAYLOAD}"));
        assert_eq!(observed, 2, "the panic must be contained, not propagated");
    }

    #[test]
    fn the_verbose_variable_is_named_as_documented() {
        // The opt-in is part of the contract, so its spelling is pinned. A
        // rename would silently remove the only route back to an unredacted
        // diagnostic, and nothing else in the tree would notice.
        assert_eq!(panic_boundary::VERBOSE_ENV, "CURL_RS_PANIC_VERBOSE");
    }
}

/// The three published forms of the ABI export inventory must agree.
///
/// `build.rs` computes the inventory once and publishes it as a file, as
/// `cargo:rustc-env` values, and as warning text. One computation cannot
/// disagree with itself, but the three FORMATTINGS can drift apart under
/// editing, and a consumer that reads the file while a gate reads the constants
/// would then be told two different things about whether the C surface can be
/// trusted. So the file and the constants are compared here.
///
/// `include_str!` rather than a runtime read, for the reason the pkg-config gate
/// above gives: it guarantees the assertion sees exactly the artifact this build
/// produced, and a missing file becomes a compile error instead of a silently
/// skipped test.
#[cfg(test)]
mod abi_inventory {
    use super::{
        ABI_EXPORTS_DEFINED, ABI_EXPORTS_REQUIRED, ABI_HEADERS_GENERATED,
    };

    /// The published inventory, baked in at compile time.
    const INVENTORY: &str =
        include_str!(concat!(env!("OUT_DIR"), "/abi-inventory.txt"));

    /// The value of one `key=value` line.
    fn field(key: &str) -> &'static str {
        let prefix = format!("{key}=");
        INVENTORY
            .lines()
            .find(|line| line.starts_with(&prefix))
            .map(|line| &line[prefix.len()..])
            .unwrap_or_else(|| {
                panic!("the published inventory declares no `{key}`")
            })
    }

    fn number(key: &str) -> u32 {
        field(key)
            .parse()
            .unwrap_or_else(|e| panic!("`{key}` is not a number: {e}"))
    }

    #[test]
    fn the_file_and_the_constants_agree() {
        assert_eq!(number("required"), ABI_EXPORTS_REQUIRED);
        assert_eq!(number("defined"), ABI_EXPORTS_DEFINED);
        assert_eq!(
            field("headers-generated") == "1",
            ABI_HEADERS_GENERATED,
            "the file and the constant disagree about whether this build \
             promoted a complete set of headers"
        );
    }

    #[test]
    fn the_inventory_is_internally_consistent() {
        // The count and the enumeration are written from the same vector, so a
        // disagreement means one of the two loops was edited without the other.
        let named = INVENTORY
            .lines()
            .filter(|line| line.starts_with("missing-export="))
            .count();
        assert_eq!(number("missing") as usize, named);

        assert_eq!(
            ABI_EXPORTS_REQUIRED - ABI_EXPORTS_DEFINED,
            number("missing"),
            "required minus defined must be the missing count"
        );

        // The truncation-only subset cannot exceed the whole gap. Both figures
        // answer different questions and quoting either alone has misled a
        // review once, which is why both are published.
        assert!(number("declaration-gap") <= number("missing"));
    }

    #[test]
    fn headers_are_generated_exactly_when_the_surface_is_complete() {
        // The rule `generate_headers` documents, asserted from the published
        // side: no partial header set, ever. This is the field the packaging
        // gate and the header gate both turn on, so an inversion here would let
        // a build ship frozen headers beside a library that does not match
        // them - which is the defect the inventory exists to make detectable.
        assert_eq!(
            ABI_HEADERS_GENERATED,
            ABI_EXPORTS_DEFINED == ABI_EXPORTS_REQUIRED
        );

        // Non-vacuity: the requirement is the 100 names of lib/libcurl.def, so
        // a zero here would mean the export list was not read at all and every
        // assertion above would hold trivially.
        //
        // Read through the published file rather than the constants, because
        // `assert!` on two `const` operands is a constant expression and
        // `clippy::assertions_on_constants` rejects it under `-D warnings`. The
        // file values are equal to the constants -- `the_file_and_the_constants_
        // agree` is what establishes that -- so this asserts the same property
        // without the lint, and it additionally covers the case where the
        // constants were somehow correct and the file was not.
        assert!(number("required") > 0);
        assert!(number("defined") <= number("required"));
    }

    /// Every `missing-family=<name> <count>` line, in published order.
    fn families() -> Vec<(&'static str, usize)> {
        INVENTORY
            .lines()
            .filter_map(|line| line.strip_prefix("missing-family="))
            .map(|body| {
                let (name, count) = body.split_once(' ').unwrap_or_else(|| {
                    panic!("malformed family line: `{body}`")
                });
                let count = count.parse().unwrap_or_else(|e| {
                    panic!("family `{name}` has a bad count: {e}")
                });
                (name, count)
            })
            .collect()
    }

    /// The family grouping accounts for every missing name, once each.
    ///
    /// This is what makes the grouping usable as a work inventory rather than a
    /// summary: if the counts did not sum to `missing`, a reader could not tell
    /// whether a family had been omitted or a name double-counted. The
    /// `curl_m*printf` names have no family segment and are grouped under their
    /// own spelling for exactly this reason.
    #[test]
    fn the_family_counts_account_for_every_missing_name() {
        let families = families();
        let summed: usize = families.iter().map(|(_, count)| count).sum();
        assert_eq!(
            summed,
            number("missing") as usize,
            "the family counts must sum to the missing count: {families:?}"
        );

        let mut names: Vec<&str> =
            families.iter().map(|(name, _)| *name).collect();
        let before = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(before, names.len(), "a family is listed twice");

        // Every family that appears must be derivable from a name that appears,
        // so the grouping cannot invent one.
        let missing_names: Vec<&str> = INVENTORY
            .lines()
            .filter_map(|line| line.strip_prefix("missing-export="))
            .collect();
        for (family, _) in &families {
            assert!(
                missing_names.iter().any(|name| {
                    name.strip_prefix("curl_")
                        .and_then(|rest| rest.split_once('_'))
                        .map_or(name == family, |(seg, _)| seg == *family)
                }),
                "family `{family}` matches no missing export"
            );
        }
    }

    /// Published largest-first with alphabetical ties, so the file is a function
    /// of the tree alone.
    ///
    /// An unstable order would rewrite `$OUT_DIR` on every build --
    /// `write_if_changed` compares contents -- and invalidate this crate's cache
    /// for no reason.
    #[test]
    fn the_family_order_is_deterministic() {
        let families = families();
        for pair in families.windows(2) {
            let (left, right) = (&pair[0], &pair[1]);
            assert!(
                left.1 > right.1 || (left.1 == right.1 && left.0 < right.0),
                "{left:?} must not precede {right:?}"
            );
        }

        // Non-vacuity: a single-element or empty list would satisfy the loop
        // trivially. While the surface is incomplete there is more than one
        // family; when it is complete there are none, and the sum assertion
        // above covers that case.
        if number("missing") > 0 {
            assert!(!families.is_empty(), "names but no families");
        } else {
            assert!(families.is_empty(), "families but no names");
        }
    }
}
