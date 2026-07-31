// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! libcurl's C ABI, expressed in Rust.
//!
//! This crate is the ABI facade -- pattern P10 of the migration plan --
//! that presents curl 8.19.0-DEV's exported C surface over the safe engine
//! in `curl-rs-lib`. It marshals; it does not decide. Every protocol,
//! transport, TLS, DNS and authentication decision belongs to
//! `curl-rs-lib`, which is what keeps the shim small enough to audit
//! against the public header in isolation. There is deliberately no
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
//! exhaustive, and it is the contract the `ffi/` modules satisfy.
//!
//! | Module | Count | Derivation |
//! |---|---|---|
//! | `ffi/easy.rs` | 18 | 21 `curl_easy_*` less the 3 moved out |
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
//! | `codes`, `opts`, `handle`, `mod`, and this file | 0 | types only |
//!
//! Sum: 18 + 21 + 3 + 5 + 2 + 12 + 3 + 5 + 4 + 10 + 4 + 13 = **100**.
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
//! Where a symbol is *declared* is not where it is *defined*, and the two
//! must not be conflated. `include/curl/options.h` declares the three
//! `curl_easy_option_*` functions that `ffi/easy.rs` defines;
//! `include/curl/header.h` declares the two header-API functions that
//! `ffi/misc.rs` defines; `include/curl/multi.h` declares
//! `curl_pushheader_byname` and `curl_pushheader_bynum`, which also belong
//! to `ffi/misc.rs`. A definition is never moved to match a declaration's
//! header.
//!
//! Spellings that are easy to get subtly wrong, each confirmed against the
//! `.def` file: `curl_easy_option_next` (not `curl_easy_option_by_next`),
//! `curl_multi_get_offt`, `curl_easy_ssls_export`, `curl_easy_ssls_import`,
//! `curl_multi_notify_enable`, `curl_multi_notify_disable`,
//! `curl_multi_get_handles`, `curl_multi_waitfds` and
//! `curl_ws_start_frame`.
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
//! panic may escape any of the 100 entry points. The containment
//! mechanism is code, not a build setting: `panic = "abort"` is prohibited
//! in the release profile -- the workspace root sets `panic = "unwind"`
//! explicitly -- because aborting would terminate the host application,
//! which is the very outcome the boundary exists to prevent. A member
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
//! Containment is a safety net, never an error-handling strategy. A panic
//! that reaches the boundary is always a defect in this crate, and the
//! correct response is to fix the defect rather than to lean on the
//! fallback. `panic_boundary::contained` counts the panics absorbed so
//! far, so that a test can prove the net works and so that a clean run can
//! be asserted to have absorbed none.
//!
//! No panic hook is installed here, and that is a decision rather than an
//! omission. Two things are true at once, and only the first is under this
//! crate's control. Nothing in `panic_boundary` writes to standard error.
//! Rust's *default* hook, however, does print a `thread '<unnamed>'
//! panicked at ...` line before unwinding begins -- measured, by driving
//! these entry points from a C program and observing the stream, not
//! assumed. Suppressing it with `std::panic::set_hook` was considered and
//! rejected for two reasons. The hook is process-global, and this crate
//! ships as a library loaded into an application that did not write it;
//! replacing that application's own hook is a far more invasive side
//! effect than a diagnostic line. And the diagnostic is wanted: since a
//! panic here is by definition a defect, silencing it would hide the very
//! thing that most needs to be seen. The residual risk is narrow and worth
//! naming -- `tests/data` fixtures compare emitted bytes literally, so
//! such a line could turn a passing fixture into a failing one -- but it
//! can only arise when a defect is already present, and in that situation
//! a loud failure is the correct outcome rather than something to be
//! engineered away.
//!
//! # Argument validation at the boundary
//!
//! Every raw pointer arriving from C is null-checked before use, and a
//! violation returns the family-correct `CURLE_*`, `CURLM_*`, `CURLSH_*`,
//! `CURLU_*` or `CURLH_*` error exactly as the C implementation does.
//! Never a panic, and never a dereference of an unchecked pointer. This
//! binds all 16 modules under `ffi/`, which is why it is stated here.
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
//! `memory` is the Rust counterpart of those five pointers. It stores
//! them as a group so no caller can observe a half-installed set, and it
//! routes through them every buffer this crate hands across the C
//! boundary. That last property is the one that matters to applications:
//! a pointer returned by `curl_easy_escape`, `curl_maprintf` or
//! `curl_getenv` is produced by the caller's own `malloc` and released by
//! the caller's own `free`, with no header, no offset and no hidden
//! bookkeeping, so `curl_free` behaves exactly as it does against C
//! libcurl -- and so does a plain `free`, which real applications do rely
//! on even though the documentation asks for `curl_free`.
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
//! What is emphatically *not* done is to accept the callbacks and discard
//! them. `curl_global_init_mem` must keep working, its null-argument
//! rejection must keep returning `CURLE_FAILED_INIT`, and the callbacks
//! must be genuinely used; silent acceptance would be the worst of the
//! available options.
//!
//! The flag word `curl_global_init_mem` shares with `curl_global_init` is
//! `include/curl/curl.h:3014-3019`: `CURL_GLOBAL_SSL` is `1 << 0` and has
//! had "no purpose since 7.57.0", `CURL_GLOBAL_WIN32` is `1 << 1`,
//! `CURL_GLOBAL_ALL` is the two together, `CURL_GLOBAL_NOTHING` is 0,
//! `CURL_GLOBAL_DEFAULT` aliases `CURL_GLOBAL_ALL`, and
//! `CURL_GLOBAL_ACK_EINTR` is `1 << 2`. All six must be accepted.
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
//! declares them again for the ABI. That is deliberate, not an oversight:
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
//! # Open items, recorded rather than quietly accepted
//!
//! These are unresolved or resolved-with-a-cost, and the crate root is
//! where a reader looks for crate-wide caveats. None may be discovered by
//! surprise later.
//!
//! **A4: the minimum supported Rust version conflicts with one of the four
//! required targets, and this needs a decision that is not the agent's to
//! make.** Four exported functions -- `curl_easy_setopt`,
//! `curl_easy_getinfo`, `curl_multi_setopt` and `curl_share_setopt` -- are
//! C-variadic in the header, and the design reaches them with a
//! non-variadic Rust function taking one trailing pointer, which works
//! because the option identifier already encodes its argument's type class
//! (integer division by 10,000 recovers the `CURLOPTTYPE_*` base). The
//! generated aarch64 code reads that argument from register `x2`. Standard
//! AAPCS64, which Linux aarch64 follows, passes variadic arguments in
//! registers, so caller and callee agree. **Apple's arm64 ABI passes
//! variadic arguments on the stack**, so on `aarch64-apple-darwin` the
//! callee would read a register the caller never populated. The failure is
//! silent and would not show up in a Linux test run. The remedy is
//! `VaList` with `ap.next_arg`, whose `VaArgSafe` bound is sealed and is
//! not implemented for raw pointers -- they must be read as `usize` and
//! cast -- and which is stable only on a toolchain far newer than the
//! declared minimum. Raising the minimum, dropping the target, or
//! accepting that one target's variadic entry points are unsupported are
//! the three options, and choosing between them is a user decision.
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
//! unavailable at the declared minimum. Raising the minimum, or adding a
//! small C shim that captures the `va_list` and delegates to a Rust
//! function, are the only ABI-exact routes; a shim would add a build-time
//! C compiler dependency the manifest does not currently permit. Dropping
//! the symbols is not an option, because they are eleven of the 100.
//!
//! **32-bit support is forfeited deliberately and must not be claimed.** A
//! single register-width argument slot holds a `curl_off_t` only where
//! `curl_off_t` fits a register. All four required targets are 64-bit, so
//! the design is sound for the required matrix and for nothing wider.
//!
//! **A7, a disclosure rather than a defect.** Neither cryptographic
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
//! **A8, resolved in favour of accuracy.** `tests/runtests.pl:585-586`
//! sets its `rustls` feature from a `rustls-ffi` token in the version
//! banner, not from the word `rustls`. Emitting `rustls-ffi` would unlock
//! the fixtures gated on that feature while misdescribing an
//! implementation that uses rustls natively rather than through its C FFI,
//! so the truthful token is emitted and the skips are accepted. The
//! asymmetry makes this the safe direction as well as the honest one:
//! under-reporting a capability makes a fixture skip, whereas
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
//! **One re-export that `ffi/misc.rs` will need does not exist yet.**
//! `curl_getdate` needs the date parser, which lives under
//! `curl-rs-lib`'s `util` module; `util` is `pub(crate)` and the crate
//! root re-exports nothing from it. `curl-rs-lib`'s public surface must
//! grow that re-export. It is reported here rather than worked around:
//! duplicating the parser in this crate would put engine logic in the
//! facade, and reaching for a private path is not possible. The
//! equivalent needs for the other two ABI obligations are already met --
//! the TLS backend identity is public in `curl-rs-lib`'s `version` module,
//! and every code enumeration exposes a message accessor.
//!
//! # Provenance of the constraints above
//!
//! No user-specified rules were provided for this project: the rules
//! channel is empty, which was confirmed by reading it to end of document
//! more than once. Nothing in this file derives from a rule, and no rule
//! is cited anywhere in it, because there is none to cite. Every
//! constraint recorded here comes from one of exactly two places: the
//! migration plan's own requirements, which restate the user's request,
//! or a fact measured in this repository and given with its path and line
//! so it can be rechecked. Neither is a rule, and neither should be
//! described as one. Where a claim could not be settled by reading, it was
//! settled by building and running the thing in question, and it says so.

// Every consumer of the two helper modules below lives under `ffi/`, which
// is a separate unit of work, so until those 16 files land each helper here
// is legitimately unreferenced. `dead_code` is therefore allowed for these
// modules specifically and with a stated reason rather than as a
// convenience, which is the same situation and the same remedy as
// `curl-rs-lib/src/ffi/sys.rs:131-135`. It is deliberately not allowed at
// the crate root, so that genuinely dead code under `ffi/` still warns.

/// Containment for panics that would otherwise unwind into C.
///
/// Every one of the 100 exported entry points routes its body through
/// exactly one of the four functions here. See the crate-level
/// documentation for the fallback each return type takes and for why
/// containment is a safety net rather than an error-handling strategy.
#[allow(dead_code)]
pub(crate) mod panic_boundary {
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::panic::{self, AssertUnwindSafe};

    /// Panics absorbed since the library was loaded.
    static CONTAINED: AtomicUsize = AtomicUsize::new(0);

    /// How many panics this boundary has absorbed.
    ///
    /// A healthy process reports zero, and a non-zero result is a defect
    /// report rather than a statistic. It exists so a test can prove the
    /// net works without the crate having to write to a stream the test
    /// fixtures compare byte for byte.
    pub(crate) fn contained() -> usize {
        CONTAINED.load(Ordering::Relaxed)
    }

    /// Runs `body`, returning `fallback` if it panics.
    ///
    /// `fallback` is evaluated by the caller, so it must be a plain value
    /// and not itself able to fail. That is deliberate: the recovery path
    /// has to be incapable of the fault it is recovering from.
    pub(crate) fn guard<T, F>(fallback: T, body: F) -> T
    where
        F: FnOnce() -> T,
    {
        // `AssertUnwindSafe` is unavoidable and is sound here for a reason
        // worth stating rather than waving through: the closures this
        // wraps capture raw pointers handed over by C, and a raw pointer
        // is never `UnwindSafe`. The lint exists to stop a caller
        // observing a Rust value left half-updated by an unwind, but C
        // owns the memory behind these pointers and inspects it after the
        // call in either outcome. The boundary is itself where the
        // invariant is restored, by returning a documented failure value.
        match panic::catch_unwind(AssertUnwindSafe(body)) {
            Ok(value) => value,
            Err(payload) => {
                CONTAINED.fetch_add(1, Ordering::Relaxed);
                // Releasing the payload runs the caller's own `Drop` when
                // the panic came from `panic_any` with a type of their
                // choosing, so the release is contained too. A panic
                // raised while already unwinding aborts by Rust's own
                // rules, and that is the single case no library can
                // intercept.
                let _ = panic::catch_unwind(AssertUnwindSafe(move || {
                    drop(payload);
                }));
                fallback
            }
        }
    }

    /// Runs `body`, returning a null pointer if it panics.
    ///
    /// Covers every entry point declared to return `char *`, `CURL *`,
    /// `CURLM *`, `CURLSH *`, `CURLU *`, `CURL **`, `struct curl_slist *`,
    /// `curl_mime *`, `curl_mimepart *` or `struct curl_header *`.
    pub(crate) fn guard_ptr<T, F>(body: F) -> *mut T
    where
        F: FnOnce() -> *mut T,
    {
        guard(core::ptr::null_mut(), body)
    }

    /// Runs `body`, returning a null `const` pointer if it panics.
    ///
    /// Covers the entry points declared to return `const char *` or
    /// `const struct curl_ws_frame *`.
    pub(crate) fn guard_const_ptr<T, F>(body: F) -> *const T
    where
        F: FnOnce() -> *const T,
    {
        guard(core::ptr::null(), body)
    }

    /// Runs `body` and returns quietly if it panics.
    ///
    /// Covers the six entry points with no error channel at all:
    /// `curl_global_cleanup`, `curl_free`, `curl_slist_free_all`,
    /// `curl_mime_free`, `curl_formfree` and `curl_url_cleanup`.
    pub(crate) fn guard_void<F>(body: F)
    where
        F: FnOnce(),
    {
        guard((), body);
    }
}

/// libcurl's five replaceable allocator hooks.
///
/// This is the Rust counterpart of `Curl_cmalloc`, `Curl_cfree`,
/// `Curl_crealloc`, `Curl_cstrdup` and `Curl_ccalloc`
/// (`lib/easy.c:106-110`), and it backs `curl_global_init_mem`. Read the
/// crate-level documentation for the scope of what these hooks observe:
/// every buffer this crate hands to C passes through them, and the
/// engine's internal Rust allocations do not, which is a deviation stated
/// there in full along with the two measurements that force it.
///
/// The hook types below mirror the five typedefs at
/// `include/curl/curl.h:469-473`. They are private and are given names
/// distinct from the C typedefs on purpose: the ABI typedefs belong to the
/// verbatim header text that `cbindgen.toml` and `ffi/handle.rs` own, and
/// nothing here should be mistaken for them or collide with them. The
/// `[export] include` allow-list in `cbindgen.toml` independently keeps
/// them out of the generated header.
#[allow(dead_code)]
#[allow(unsafe_code)]
pub(crate) mod memory {
    use core::ffi::{c_char, c_void};
    use core::ptr;
    use std::ffi::CStr;
    use std::sync::Mutex;

    /// Mirrors `curl_malloc_callback` (`include/curl/curl.h:469`).
    type MallocFn = unsafe extern "C" fn(usize) -> *mut c_void;
    /// Mirrors `curl_free_callback` (`include/curl/curl.h:470`).
    type FreeFn = unsafe extern "C" fn(*mut c_void);
    /// Mirrors `curl_realloc_callback` (`include/curl/curl.h:471`).
    type ReallocFn = unsafe extern "C" fn(*mut c_void, usize) -> *mut c_void;
    /// Mirrors `curl_strdup_callback` (`include/curl/curl.h:472`).
    type StrdupFn = unsafe extern "C" fn(*const c_char) -> *mut c_char;
    /// Mirrors `curl_calloc_callback` (`include/curl/curl.h:473`).
    type CallocFn = unsafe extern "C" fn(usize, usize) -> *mut c_void;

    /// All five hooks, stored and replaced as a single value.
    ///
    /// Grouping them is not a convenience. `curl_global_init_mem` takes
    /// all five together, and a set that were installed one at a time
    /// could be observed half-replaced by another thread, which would
    /// pair one allocator's `malloc` with another's `free`. A tuple is
    /// used rather than a named struct so that this module declares no
    /// type that could be confused with an ABI type.
    type Hooks = (MallocFn, FreeFn, ReallocFn, StrdupFn, CallocFn);

    /// `None` means the C library defaults are in force.
    ///
    /// A `Mutex` rather than a set of atomics, for two reasons. It makes
    /// the five-at-once replacement above trivially correct, and it needs
    /// no transmute between a function pointer and an integer, so this
    /// module stores no address it has to reconstitute. `Mutex::new` is a
    /// `const` constructor, so there is no lazy initialisation and no
    /// start-up ordering problem. These paths run when a buffer crosses
    /// the C boundary, not in any hot loop, so the lock is not on a
    /// critical path.
    static HOOKS: Mutex<Option<Hooks>> = Mutex::new(None);

    /// Copies the installed hooks out, if any are installed.
    ///
    /// The copy is taken so that the lock is released before any hook
    /// runs. A callback that re-entered libcurl while the lock was held
    /// would deadlock, and function pointers are `Copy`, so avoiding it
    /// costs nothing. Poisoning is absorbed rather than propagated: the
    /// protected value is five function pointers with no invariant a
    /// panic could break, and refusing to release memory because an
    /// unrelated thread panicked would be strictly worse than proceeding.
    fn snapshot() -> Option<Hooks> {
        *HOOKS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Installs a complete hook set, as `curl_global_init_mem` does.
    ///
    /// Returns `false`, and installs nothing, when any hook is null. That
    /// is exactly what `lib/easy.c:220-221` tests before returning
    /// `CURLE_FAILED_INIT`. Choosing that `CURLcode` is the caller's job,
    /// which is what keeps this module free of ABI enumerations.
    ///
    /// The replacement is legal only before any other libcurl call, per
    /// `include/curl/curl.h:2743-2745`, because a block must be released
    /// by the allocator that produced it. Nothing here can enforce that
    /// ordering, and pretending otherwise would be worse than saying so.
    pub(crate) fn install(
        malloc: Option<MallocFn>,
        free: Option<FreeFn>,
        realloc: Option<ReallocFn>,
        strdup: Option<StrdupFn>,
        calloc: Option<CallocFn>,
    ) -> bool {
        let (Some(m), Some(f), Some(r), Some(s), Some(c)) =
            (malloc, free, realloc, strdup, calloc)
        else {
            return false;
        };
        *HOOKS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
            Some((m, f, r, s, c));
        true
    }

    /// Restores the C library defaults, as `lib/easy.c:129-133` does.
    pub(crate) fn reset() {
        *HOOKS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    }

    /// Whether application-supplied hooks are currently in force.
    pub(crate) fn is_installed() -> bool {
        snapshot().is_some()
    }

    /// Allocates `size` bytes for the C caller to own.
    ///
    /// Returns null on failure, as C `malloc` does. A `size` of zero is
    /// forwarded unchanged, so the result is whatever the active allocator
    /// returns for it, which is the same latitude C libcurl allows.
    pub(crate) fn malloc(size: usize) -> *mut c_void {
        match snapshot() {
            Some((hook, ..)) => {
                // SAFETY: `hook` reached `install` as a
                // `curl_malloc_callback`, whose contract at
                // `include/curl/curl.h:2763-2768` is that it behaves as
                // `malloc`; `install` rejected null. No value of `size`
                // can make the call itself unsound.
                unsafe { hook(size) }
            }
            None => {
                // SAFETY: `libc::malloc` has no precondition beyond a
                // valid `size_t`, and every `usize` is one on all four
                // supported targets, which are all 64-bit Unix.
                unsafe { libc::malloc(size) }
            }
        }
    }

    /// Allocates `nmemb * size` zeroed bytes for the C caller to own.
    pub(crate) fn calloc(nmemb: usize, size: usize) -> *mut c_void {
        match snapshot() {
            Some((_, _, _, _, hook)) => {
                // SAFETY: `hook` reached `install` as a
                // `curl_calloc_callback` and is non-null. Overflow of
                // `nmemb * size` is the allocator's to detect and report
                // by returning null, exactly as C `calloc` must.
                unsafe { hook(nmemb, size) }
            }
            None => {
                // SAFETY: `libc::calloc` has no precondition beyond two
                // valid `size_t` arguments and reports overflow by
                // returning null.
                unsafe { libc::calloc(nmemb, size) }
            }
        }
    }

    /// Resizes a block obtained from this module.
    ///
    /// # Safety
    ///
    /// `ptr` must be null, or a live block previously returned by this
    /// module while the *same* hook set was in force. Passing null is
    /// well defined and allocates, as C `realloc` requires.
    pub(crate) unsafe fn realloc(ptr: *mut c_void, size: usize) -> *mut c_void {
        match snapshot() {
            Some((_, _, hook, _, _)) => {
                // SAFETY: `hook` reached `install` as a
                // `curl_realloc_callback` and is non-null, and this
                // function's own contract has already obliged the caller
                // to pass a pointer that hook set produced.
                unsafe { hook(ptr, size) }
            }
            None => {
                // SAFETY: this function's contract obliges the caller to
                // pass null or a live block from the same default path,
                // which is `libc::realloc`'s only precondition.
                unsafe { libc::realloc(ptr, size) }
            }
        }
    }

    /// Releases a block obtained from this module.
    ///
    /// Null is forwarded to the hook rather than filtered out, because C
    /// `free` defines it as a no-op and libcurl does pass it -- the
    /// `Curl_safefree` idiom releases unconditionally -- so filtering
    /// would hide calls an accounting hook legitimately expects to see.
    ///
    /// # Safety
    ///
    /// `ptr` must be null, or a live block previously returned by this
    /// module while the *same* hook set was in force, and must not have
    /// been released already. Releasing across a hook replacement is the
    /// mismatch the crate-level documentation describes, which is why
    /// `curl_global_init_mem` may only be called before anything else.
    pub(crate) unsafe fn free(ptr: *mut c_void) {
        match snapshot() {
            Some((_, hook, _, _, _)) => {
                // SAFETY: `hook` reached `install` as a
                // `curl_free_callback` and is non-null, and this
                // function's contract has already obliged the caller to
                // pass a pointer that hook set produced, or null.
                unsafe { hook(ptr) }
            }
            None => {
                // SAFETY: this function's contract obliges the caller to
                // pass null or a live block from the same default path,
                // which is `libc::free`'s only precondition.
                unsafe { libc::free(ptr) }
            }
        }
    }

    /// Duplicates a C string into caller-owned memory.
    ///
    /// A null input yields null instead of undefined behaviour. That is a
    /// deliberate and stated divergence: the default hook is the C
    /// library's `strdup` (`lib/curl_setup.h:1450` defines
    /// `CURLX_STRDUP_LOW` as `strdup`), which has no defined behaviour on
    /// null, and libcurl simply never passes it one. Guarding costs a
    /// branch, is indistinguishable to every conforming caller, and turns
    /// a latent undefined behaviour into a null return.
    ///
    /// When no hook is installed the copy is made through this module's own
    /// `malloc` rather than by calling the C library's `strdup`. The two
    /// are indistinguishable to a caller -- curl's own default reaches
    /// `malloc` through `strdup` anyway -- and routing through `malloc`
    /// buys two things. The duplicate provably comes from the same
    /// allocator as everything else here, so releasing it with `free` is
    /// symmetric by construction rather than by coincidence; and it keeps
    /// the module executable under Miri, which shims `malloc`, `calloc`,
    /// `realloc`, `free` and `strlen` but rejects `strdup` outright with
    /// "unsupported operation: can't call foreign function `strdup`". That
    /// was measured, not assumed, and it would otherwise have made the
    /// crate's own tests unrunnable under a required gate.
    ///
    /// # Safety
    ///
    /// `s` must be null, or a pointer to a NUL-terminated C string that
    /// stays valid and unmodified for the duration of the call.
    pub(crate) unsafe fn strdup(s: *const c_char) -> *mut c_char {
        if s.is_null() {
            return ptr::null_mut();
        }
        if let Some((_, _, _, hook, _)) = snapshot() {
            // SAFETY: `hook` reached `install` as a
            // `curl_strdup_callback` and is non-null; `s` is non-null and
            // NUL-terminated by this function's own contract, which is
            // all `strdup` requires.
            return unsafe { hook(s) };
        }
        // SAFETY: `s` is non-null and points to a NUL-terminated string
        // that stays valid for the call, by this function's contract, so
        // the borrow ends before anything can invalidate it. The bytes it
        // yields exclude the terminator, which `copy_to_c_string` adds
        // back.
        let bytes = unsafe { CStr::from_ptr(s) }.to_bytes();
        copy_to_c_string(bytes)
    }

    /// Copies `bytes` into caller-owned C memory and appends a NUL.
    ///
    /// This is the primitive behind every entry point that returns a
    /// string the application later releases with `curl_free`, such as
    /// `curl_escape`, `curl_easy_escape`, `curl_maprintf` and
    /// `curl_getenv`. Going through it rather than through
    /// `CString::into_raw` is what makes those buffers the application's
    /// own allocator's, so that `curl_free` -- and a plain `free`, which
    /// applications do use -- behave exactly as against C libcurl.
    ///
    /// Returns null if the allocation fails or if the length plus its
    /// terminator would overflow. `bytes` is copied verbatim, so an
    /// interior NUL is preserved in the buffer and simply terminates the
    /// string early as far as C is concerned; callers that must reject
    /// that case check before calling, which is where the knowledge of
    /// whether it matters lives.
    pub(crate) fn copy_to_c_string(bytes: &[u8]) -> *mut c_char {
        let Some(total) = bytes.len().checked_add(1) else {
            return ptr::null_mut();
        };
        let block = malloc(total);
        if block.is_null() {
            return ptr::null_mut();
        }
        let out = block.cast::<u8>();
        // SAFETY: `malloc` returned a non-null block of `total` bytes,
        // and `total` is `bytes.len() + 1`, so the copy of `bytes.len()`
        // bytes at offset 0 and the single terminator at offset
        // `bytes.len()` both land inside it. `bytes` is a live borrowed
        // slice, so it cannot overlap a block allocated after it, which
        // is what `copy_nonoverlapping` requires. The destination is a
        // fresh byte allocation, so it has no alignment requirement
        // beyond one.
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len());
            out.add(bytes.len()).write(0);
        }
        out.cast::<c_char>()
    }
}

// The 100 exported entry points, and the ABI types the generated header is
// built from. The module is private on purpose: a `cdylib` exports what is
// declared `#[no_mangle] pub extern "C"` regardless of the privacy of the
// module holding it, this crate has no `rlib` target and therefore no Rust
// consumer, and so `pub` would widen the surface without widening what any
// caller can reach. For the same reason there is no `pub use ffi::*`.
//
// `#[allow(unsafe_code)]` sits here, on the declaration, rather than at the
// crate root. That mirrors how `curl-rs-lib` and `curl-rs` are written, and
// it keeps the sanctioned `unsafe` visibly scoped to the two places that
// need it -- this module and `mod memory` above -- instead of blanketing
// the crate.
#[allow(unsafe_code)]
mod ffi;

#[cfg(test)]
mod tests {
    use super::{memory, panic_boundary};
    use core::ffi::{c_char, c_void};
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::ffi::CStr;
    use std::sync::{Mutex, MutexGuard};

    /// Serialises the tests that touch the process-wide hook registry.
    ///
    /// `memory`'s state is global by necessity, and the test harness runs
    /// tests on concurrent threads, so anything that installs or resets
    /// hooks has to take this first. Poisoning is absorbed for the same
    /// reason the registry absorbs it: a failure in one test must not turn
    /// every later test into a spurious failure.
    static REGISTRY: Mutex<()> = Mutex::new(());

    fn registry_lock() -> MutexGuard<'static, ()> {
        REGISTRY
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Invocation counters for the test hooks below.
    static MALLOC_CALLS: AtomicUsize = AtomicUsize::new(0);
    static FREE_CALLS: AtomicUsize = AtomicUsize::new(0);
    static REALLOC_CALLS: AtomicUsize = AtomicUsize::new(0);
    static STRDUP_CALLS: AtomicUsize = AtomicUsize::new(0);
    static CALLOC_CALLS: AtomicUsize = AtomicUsize::new(0);

    // The five hooks an application would pass to `curl_global_init_mem`.
    // Each records that it ran and then delegates to the C library, so a
    // block they produce is releasable by the matching hook and the test
    // observes routing without changing allocation behaviour.

    unsafe extern "C" fn test_malloc(size: usize) -> *mut c_void {
        MALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: `libc::malloc` requires only a valid `size_t`.
        unsafe { libc::malloc(size) }
    }

    unsafe extern "C" fn test_free(ptr: *mut c_void) {
        FREE_CALLS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: this hook is only ever reached through `memory::free`,
        // whose contract obliges the caller to pass null or a live block
        // that `test_malloc`, `test_calloc` or `test_realloc` produced,
        // all of which allocate through `libc`.
        unsafe { libc::free(ptr) }
    }

    unsafe extern "C" fn test_realloc(
        ptr: *mut c_void,
        size: usize,
    ) -> *mut c_void {
        REALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: reached only through `memory::realloc`, whose contract
        // obliges the caller to pass null or a live block from this same
        // hook set, which allocates through `libc`.
        unsafe { libc::realloc(ptr, size) }
    }

    /// Duplicates through `memory::copy_to_c_string`, which reaches
    /// `memory::malloc` and therefore `test_malloc`. That is intentional:
    /// it makes this test assert composition -- a hooked `strdup` whose
    /// storage comes from the hooked `malloc` -- rather than merely
    /// assert that one hook fired. It also keeps the test free of
    /// `libc::strdup`, which Miri refuses to call.
    unsafe extern "C" fn test_strdup(s: *const c_char) -> *mut c_char {
        STRDUP_CALLS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: reached only through `memory::strdup`, which has already
        // rejected null and whose contract obliges the caller to pass a
        // NUL-terminated string valid for the call, so the borrow ends
        // before anything can invalidate it.
        let bytes = unsafe { CStr::from_ptr(s) }.to_bytes();
        memory::copy_to_c_string(bytes)
    }

    unsafe extern "C" fn test_calloc(nmemb: usize, size: usize) -> *mut c_void {
        CALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: `libc::calloc` requires only two valid `size_t` values.
        unsafe { libc::calloc(nmemb, size) }
    }

    fn install_test_hooks() -> bool {
        memory::install(
            Some(test_malloc),
            Some(test_free),
            Some(test_realloc),
            Some(test_strdup),
            Some(test_calloc),
        )
    }

    #[test]
    fn guard_returns_the_body_value_when_nothing_panics() {
        assert_eq!(panic_boundary::guard(-1_i32, || 42_i32), 42);
        assert_eq!(panic_boundary::guard(0_usize, || 7_usize), 7);
    }

    #[test]
    fn guard_returns_the_fallback_and_counts_a_contained_panic() {
        let before = panic_boundary::contained();
        // 2 stands in for `CURLE_FAILED_INIT`, the documented fallback for
        // the `CURLcode` family. The enumeration itself belongs to
        // `ffi/codes.rs`, so the assertion is on the integer.
        let observed: i32 =
            panic_boundary::guard(2, || panic!("contained on purpose"));
        assert_eq!(observed, 2);
        assert!(panic_boundary::contained() > before);
    }

    #[test]
    fn guard_ptr_yields_null_on_panic_and_the_pointer_otherwise() {
        let mut value = 5_u8;
        let live: *mut u8 = &mut value;
        assert_eq!(panic_boundary::guard_ptr(|| live), live);
        let fallback: *mut u8 =
            panic_boundary::guard_ptr(|| panic!("contained"));
        assert!(fallback.is_null());
    }

    #[test]
    fn guard_const_ptr_yields_null_on_panic() {
        let fallback: *const c_char =
            panic_boundary::guard_const_ptr(|| panic!("contained"));
        assert!(fallback.is_null());
    }

    #[test]
    fn guard_void_swallows_a_panic_and_returns_normally() {
        let before = panic_boundary::contained();
        panic_boundary::guard_void(|| panic!("no error channel exists"));
        assert!(panic_boundary::contained() > before);
    }

    #[test]
    fn guard_contains_a_panic_whose_payload_drop_also_panics() {
        // The nastiest shape the boundary has to survive: releasing the
        // payload runs the caller's `Drop`, and that `Drop` panics too.
        // Both unwinds must stop inside `guard`.
        struct Hostile;
        impl Drop for Hostile {
            fn drop(&mut self) {
                panic!("the payload's own drop panicked too");
            }
        }
        let observed: i32 =
            panic_boundary::guard(2, || std::panic::panic_any(Hostile));
        assert_eq!(observed, 2);
    }

    #[test]
    fn install_rejects_an_incomplete_hook_set() {
        let _guard = registry_lock();
        // Each of the five positions is exercised as the missing one,
        // because `lib/easy.c:220-221` rejects on any of them.
        assert!(!memory::install(
            None,
            Some(test_free),
            Some(test_realloc),
            Some(test_strdup),
            Some(test_calloc),
        ));
        assert!(!memory::install(
            Some(test_malloc),
            None,
            Some(test_realloc),
            Some(test_strdup),
            Some(test_calloc),
        ));
        assert!(!memory::install(
            Some(test_malloc),
            Some(test_free),
            None,
            Some(test_strdup),
            Some(test_calloc),
        ));
        assert!(!memory::install(
            Some(test_malloc),
            Some(test_free),
            Some(test_realloc),
            None,
            Some(test_calloc),
        ));
        assert!(!memory::install(
            Some(test_malloc),
            Some(test_free),
            Some(test_realloc),
            Some(test_strdup),
            None,
        ));
        // A rejected set must leave the previous state untouched.
        assert!(!memory::is_installed());
    }

    #[test]
    fn the_default_path_round_trips_an_allocation() {
        let _guard = registry_lock();
        memory::reset();
        let block = memory::malloc(32);
        assert!(!block.is_null());
        // SAFETY: `malloc` returned a live 32-byte block, so writing one
        // byte at offset 0 is in bounds, and a fresh byte allocation has
        // no alignment requirement beyond one.
        unsafe { block.cast::<u8>().write(0xAB) };
        // SAFETY: `block` came from `memory::malloc` under the same hook
        // set, which is still the default one, and is released once.
        unsafe { memory::free(block) };

        let zeroed = memory::calloc(4, 8);
        assert!(!zeroed.is_null());
        let start = zeroed.cast::<u8>();
        // SAFETY: `calloc` returned a live 32-byte block, so a 32-byte read
        // from its start is in bounds, and `calloc` guarantees it is zeroed.
        let bytes = unsafe { core::slice::from_raw_parts(start, 32) };
        assert!(bytes.iter().all(|byte| *byte == 0));
        // SAFETY: as above, released exactly once.
        unsafe { memory::free(zeroed) };
    }

    #[test]
    fn installed_hooks_receive_every_boundary_allocation() {
        let _guard = registry_lock();
        let malloc_before = MALLOC_CALLS.load(Ordering::Relaxed);
        let free_before = FREE_CALLS.load(Ordering::Relaxed);
        let calloc_before = CALLOC_CALLS.load(Ordering::Relaxed);
        let realloc_before = REALLOC_CALLS.load(Ordering::Relaxed);
        let strdup_before = STRDUP_CALLS.load(Ordering::Relaxed);

        assert!(install_test_hooks());
        assert!(memory::is_installed());

        let block = memory::malloc(16);
        assert!(!block.is_null());
        // SAFETY: `block` is a live 16-byte block from the hook set that
        // is still installed, and 32 bytes is a valid new size.
        let grown = unsafe { memory::realloc(block, 32) };
        assert!(!grown.is_null());
        // SAFETY: `grown` is the live block that `realloc` returned under
        // the still-installed hook set, released exactly once. `block` is
        // not released: `realloc` already consumed it.
        unsafe { memory::free(grown) };

        let zeroed = memory::calloc(2, 8);
        assert!(!zeroed.is_null());
        // SAFETY: live block from the installed hooks, released once.
        unsafe { memory::free(zeroed) };

        let source = CStr::from_bytes_with_nul(b"curl\0").unwrap();
        let malloc_pre_strdup = MALLOC_CALLS.load(Ordering::Relaxed);
        // SAFETY: `CStr::as_ptr` yields a NUL-terminated string that
        // outlives the call, which is `strdup`'s only precondition.
        let copy = unsafe { memory::strdup(source.as_ptr()) };
        assert!(!copy.is_null());
        // SAFETY: `copy` is NUL-terminated because `strdup` copies through
        // the terminator, and it stays valid until released below.
        assert_eq!(unsafe { CStr::from_ptr(copy) }, source);
        // Composition, not just dispatch: `test_strdup` obtains its
        // storage from `memory::malloc`, so the hooked `malloc` must have
        // fired again while servicing the hooked `strdup`. A hook set that
        // dispatched `strdup` but bypassed `malloc` would pass every other
        // assertion in this test and fail this one.
        assert!(MALLOC_CALLS.load(Ordering::Relaxed) > malloc_pre_strdup);
        // SAFETY: live block from the installed hooks, released once.
        unsafe { memory::free(copy.cast::<c_void>()) };

        assert!(MALLOC_CALLS.load(Ordering::Relaxed) > malloc_before);
        assert!(REALLOC_CALLS.load(Ordering::Relaxed) > realloc_before);
        assert!(CALLOC_CALLS.load(Ordering::Relaxed) > calloc_before);
        assert!(STRDUP_CALLS.load(Ordering::Relaxed) > strdup_before);
        assert!(FREE_CALLS.load(Ordering::Relaxed) > free_before);

        memory::reset();
        assert!(!memory::is_installed());
    }

    #[test]
    fn strdup_maps_null_to_null_rather_than_to_undefined_behaviour() {
        let _guard = registry_lock();
        memory::reset();
        // SAFETY: null is explicitly permitted by `strdup`'s contract and
        // is the case under test.
        let copy = unsafe { memory::strdup(core::ptr::null()) };
        assert!(copy.is_null());
    }

    #[test]
    fn copy_to_c_string_nul_terminates_and_is_caller_freeable() {
        let _guard = registry_lock();
        memory::reset();
        let buffer = memory::copy_to_c_string(b"https://curl.se/");
        assert!(!buffer.is_null());
        // SAFETY: `copy_to_c_string` wrote a NUL after the payload, so the
        // block is a valid C string that stays live until released.
        let seen = unsafe { CStr::from_ptr(buffer) };
        assert_eq!(seen.to_bytes(), b"https://curl.se/");
        // SAFETY: the block came from `copy_to_c_string` under the default
        // hook set, which is still in force, and is released once.
        unsafe { memory::free(buffer.cast::<c_void>()) };

        // The empty case must still produce a one-byte NUL-terminated
        // buffer rather than null, because a caller cannot distinguish
        // "empty" from "failed" otherwise.
        let empty = memory::copy_to_c_string(b"");
        assert!(!empty.is_null());
        // SAFETY: as above; the single byte written is the terminator.
        assert_eq!(unsafe { CStr::from_ptr(empty) }.to_bytes(), b"");
        // SAFETY: as above, released exactly once.
        unsafe { memory::free(empty.cast::<c_void>()) };
    }

    #[test]
    fn the_registry_tolerates_concurrent_readers() {
        let _guard = registry_lock();
        memory::reset();
        // `curl_global_init` and `curl_global_trace` are documented
        // thread-safe at `include/curl/curl.h:2744-2745` and `:2788-2789`,
        // so the state behind them must be too. Several threads allocate
        // and release through the registry at once; the test passes if it
        // neither deadlocks nor observes a torn hook set.
        let threads: Vec<_> = (0..8)
            .map(|_| {
                std::thread::spawn(|| {
                    for _ in 0..64 {
                        let block = memory::malloc(8);
                        assert!(!block.is_null());
                        // SAFETY: a live block from the hook set in force
                        // for this iteration, released exactly once.
                        unsafe { memory::free(block) };
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().expect("registry access must not panic");
        }
    }
}
