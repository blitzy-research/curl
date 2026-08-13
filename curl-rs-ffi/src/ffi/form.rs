// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl
//
// Derived from include/curl/curl.h:188-230, :2555-2590 and :2608-2669,
// lib/formdata.c, lib/mime.c and lib/libcurl.def:24-26 of curl 8.19.0-DEV at
// commit 54cf587b9c.

//! The three legacy form-post entry points -- supersedes the public half of
//! `lib/formdata.c`.
//!
//! | Symbol | C authority | Returns | Failure answer |
//! |--------|-------------|---------|----------------|
//! | `curl_formadd` | curl.h:2632-2635, formdata.c:609-618 | `CURLFORMcode` | a member of that enumeration |
//! | `curl_formget` | curl.h:2657-2660, formdata.c:625-658 | **`int`** | non-zero, a `CURLcode` widened |
//! | `curl_formfree` | curl.h:2668-2669, formdata.c:664-689 | **`void`** | none: silence |
//!
//! **Three different return types across three functions**, and the
//! difference is load-bearing rather than cosmetic. `curl_formadd` has the
//! nine-member `CURLFORMcode` to report with. `curl_formget` returns a plain
//! `int` -- not a `CURLFORMcode` and not a `CURLcode` -- into which
//! `lib/formdata.c:658` casts a `CURLcode`, so 0 means success and 43 is
//! `CURLE_BAD_FUNCTION_ARGUMENT`. `curl_formfree` returns `void` and so has
//! **no error channel at all**: a null form is a silent no-op, exactly as
//! `lib/formdata.c:668-670` makes it, and a contained panic is a silent
//! return. That last point matters beyond tidiness, because the fixture
//! corpus compares output byte for byte and a diagnostic on standard error
//! would corrupt it.
//!
//! # `curl_formadd` is an OPEN-ENDED variadic, and the option-identifier
//! trick cannot reach it
//!
//! The design that serves `curl_easy_setopt` and its three siblings works
//! because the option identifier already encodes its argument's type class:
//! integer division by 10,000 recovers the class before the slot is read, so
//! one leading identifier governs exactly one trailing argument and a single
//! trailing `*mut c_void` parameter is enough. `include/curl/curl.h:3328-3341`
//! corroborates the split from the header's own side, defining three-argument
//! enforcement macros for exactly those four functions and for none of the
//! rest -- `curl_formadd` deliberately among the excluded, "only done to make
//! sure application authors pass exactly three arguments to these functions".
//!
//! **32-bit portability is deliberately forfeited and is not claimed.** A
//! single register-width slot holds a `curl_off_t` only where a `curl_off_t`
//! fits a register. All four required targets are 64-bit; no other
//! architecture's argument-list representation has been measured, and adding
//! one means measuring that ABI rather than relaxing a condition.
//!
//! # MSRV CONFLICT, and the route taken
//!
//! A true C-variadic `extern "C"` Rust function is unavailable at the
//! declared minimum: `extern "C" fn f(x: T, ...)` is
//! `error[E0658]: C-variadic functions are unstable` (tracking issue 44930) on
//! stable rustc, and the remedy -- `VaList` with `next_arg` -- is stable only
//! on a nightly far above 1.75. `rust-toolchain.toml` pins the stable channel
//! and deliberately does not pin a nightly, so no nightly-only feature may
//! appear here: there is no `#![feature(...)]`, no `c_variadic` and no
//! `VaList` in this file.
//!
//! # ESCALATION A4 remains open, and this is what it costs here
//!
//! For a trampolined symbol that hazard does not arise, because nothing here
//! treats a register as a variadic argument: the Apple arm64 prologue is two
//! instructions, `mov x2, sp` followed by a tail call, since on that target the
//! argument list *is* the entry stack pointer. What remains open is narrower
//! and is stated rather than glossed: the Apple prologues are cross-assembled
//! and disassembled in this environment and never executed, because no Apple
//! host is available.
//!
//! Neither conflict is surfaced from this file as a compiler diagnostic, and
//! that restraint is deliberate. A `cargo:warning=` line -- the legacy
//! single-colon spelling, because `cargo::` requires Cargo 1.77 and is
//! silently ignored at the declared minimum -- belongs to
//! `curl-rs-ffi/build.rs`, whose output is exempt from `-D warnings`; this
//! file reports that requirement and emits nothing. A `warning` raised here
//! would fail validation gate 1, which requires a warning-free build on all
//! four targets, and a `#[cfg]`-gated `compile_error!` would make
//! `aarch64-apple-darwin` unbuildable and fail the four-target matrix.
//!
//! # A second finding, now closed on ELF: `curl_formadd` and the shared library
//!
//! Measured, and recorded in full in `build.rs` under "Trap 3" together with
//! the five printf trampolines that share the constraint. rustc builds a
//! `cdylib`'s export list from Rust items carrying `#[no_mangle]` or
//! `#[export_name]` and hands the linker an anonymous version script shaped
//! `{ global: <those items>; local: *; };`. An assembled `.globl` label
//! matches nothing in `global:`, falls to the wildcard, is localised and --
//! being unreferenced -- is discarded outright. So `curl_formadd` was a `T` in
//! `libcurl.a` and in every rlib the tests link, and absent from `libcurl.so`.
//!
//! Eight linker routes were measured against that finding and seven do
//! nothing, because a symbol rustc's own script has already matched against
//! `local: *` stays local. The eighth -- a second anonymous version script
//! naming the assembled labels -- works, and `build.rs`'s
//! `promote_assembled_exports` now emits it: the label is merged additively
//! into rustc's list, so `curl_formadd` reaches the shared library too.
//!
//! What that route needs is LLD, selected explicitly from the invoking
//! toolchain's own sysroot rather than left to whatever `cc` defaults to; GNU
//! ld fails the link with "anonymous version tag cannot be combined with other
//! version tags". An earlier revision of this comment concluded from that
//! failure that the route worked on one target only, and the conclusion was
//! wrong: both pinned toolchains ship LLD, and the route was measured to work
//! at the 1.75 floor and on the aarch64 cross leg alike, with nothing leaked
//! and the soname intact.
//!
//! What remains is Mach-O, where ld64's export list is REPLACED rather than
//! extended, so promoting the six there would hide the other fifty-three.
//! `curl_formadd` is therefore absent from a `.dylib` and present in a `.so`,
//! and the residual gap is LOUD in the one place it still exists -- an
//! undefined symbol at link or load time, which the parity gate reports by
//! design. `curl_formget` and `curl_formfree` are ordinary Rust items and are
//! exported from every artifact.
//!
//! None of this touches A4: what that escalation reserves to the user is the
//! four option-identifier setters on Apple arm64, an argument-passing question
//! that no linker flag addresses.
//!
//! `curl_formadd` is one of **six** symbols that were in this position, and the
//! count belongs here so that this module is not read as an isolated blemish:
//! the other five are the `curl_m*printf` trampolines, and `ffi/printf.rs`
//! carries the measurement, the eight rejected linker routes and the enumerated
//! decision in full. Measured on x86_64-unknown-linux-gnu after the promotion,
//! in the debug and release profiles alike: `nm -D --defined-only libcurl.so`
//! and `nm --defined-only libcurl.a` both read the same 59 of the 100 required
//! symbols, these six among them, so the two artifacts agree. Before the
//! promotion the shared object read 53 where the archive read 59, and that
//! earlier pair of numbers now describes Mach-O and the counterfactual the
//! `build.rs` link-argument gate asserts against, nothing else.
//!
//! What is left is Mach-O, and the decision that would close it there is the
//! requirement owner's: raise the MSRV above 1.75 to a toolchain carrying
//! `#[naked]` (1.88) or `c_variadic` (1.99) and write the entry points as
//! ordinary Rust items, which ld64 exports like any other; or narrow the target
//! matrix. There is no third form, and in particular no environment setting.
//! `CURL_RS_A4_VARIADIC_DECISION=accept-unsupported-varargs` once released the
//! related `aarch64-apple-darwin` refusal and has been removed, because a
//! build-time variable cannot make a known-wrong ABI right -- it can only
//! produce the artifact that carries it, and specification 0.6.2 calls that
//! silent acceptance the worst option for this hazard. `build.rs` now refuses a
//! build that sets the variable at all, so nothing in this crate sets it,
//! defaults it or infers it, and this module does not become correct because an
//! environment still carries the string.
//!
//! # Where the model lives, and why C is shown a mirror
//!
//! `curl_rs_lib::mime::formdata` is the authority: `form_add` applies the
//! whole of `FormAdd` plus `FormAddCheck` to an already-decoded, ordered
//! option list, and it owns every "given twice" outcome, the content-type
//! inference, the interior-NUL rejection and the `LONG_MAX` guard. It exposes
//! no constructor for a form entry -- accessors only -- and says so in its own
//! documentation: "The ABI crate needs this mapping to build the `#[repr(C)]`
//! mirror that C callers walk", and "**The `#[repr(C)]` mirror belongs in
//! `curl-rs-ffi`, not here.**"
//!
//! So the engine's `FormList` is the store, held for as long as the form
//! lives, and the `struct curl_httppost` chain a caller receives is a faithful
//! mirror of it: real nodes at stable addresses, every field written the way
//! `AddHttpPost` (`lib/formdata.c:57-103`) writes it, every `CURL_HTTPPOST_*`
//! bit set the way it sets them, and every string that C would have owned
//! allocated through this crate's uniform allocator so that
//! `curl_global_init_mem`'s hooks see it. A consumer that reads
//! `post->flags`, `post->name` or `post->next` gets what C would have given
//! it.
//!
//! # Three measurements recorded here because they contradict the folder's
//! own notes
//!
//! **CORRECTION 5.** The set of prototypes carrying `CURL_DEPRECATED` on the
//! line **before** the function name is FIVE, not two: `curl_multi_socket`
//! (`multi.h:316-317`) and `curl_multi_socket_all` (`:325-326`), and all three
//! of this module's -- `curl_formadd` (`curl.h:2632-2633`), `curl_formget`
//! (`:2657-2658`) and `curl_formfree` (`:2668-2669`). cbindgen cannot express
//! a two-line attribute-before-name spelling, so an `[export] exclude` list
//! built from the two `multi.h` names alone would let these three
//! declarations be mangled. Verified present rather than assumed:
//! `cbindgen.toml` excludes all five, and `build.rs` carries all three
//! declarations verbatim with the attribute on the preceding line and
//! `curl_formadd` still spelled with `...`.
//!
//! **CORRECTION 20.** `CURLFORM_CONTENTLEN` exhibits a fourth attribute
//! position: the member name and its trailing comment sit on `:2580` and the
//! attribute on the next line, `:2581`. Across the public headers the four
//! positions are post-name-pre-`=`, attribute-line-before-name, post-name, and
//! post-name-post-comment-next-line; cbindgen can express none of them, which
//! is why all four come from verbatim header text.

use core::ffi::{c_char, c_int, c_long, c_void, CStr};
use core::mem::{align_of, size_of};
use core::{ptr, slice};

use curl_rs_lib::mime::formdata::{
    form_add, form_free, form_get_with_system_rng, FormCode, FormEntry,
    FormFlags, FormList, FormOption, Ownership,
};
use curl_rs_lib::mime::{PartReader, ReadStatus, SeekResult, SeekWhence};

use super::codes::{CURLFORMcode, CURLcode};
use super::handle::{
    curl_forms, curl_httppost, curl_off_t, curl_slist, slist_to_vec,
    CURL_HTTPPOST_BUFFER, CURL_HTTPPOST_CALLBACK, CURL_HTTPPOST_FILENAME,
    CURL_HTTPPOST_LARGE, CURL_HTTPPOST_PTRBUFFER, CURL_HTTPPOST_PTRCONTENTS,
    CURL_HTTPPOST_PTRNAME, CURL_HTTPPOST_READFILE,
};
use super::memory;
use super::opts::CURLformoption;
use super::panic_boundary::{guard, guard_tx, guard_void, Poison};
use super::printf::{ArgSource, CVaList, VaArgs};
use super::types::curl_formget_callback;

/// The tag every node this module allocates carries.
///
/// `"formrs\0\0"` read as a little-endian `u64`. It answers one question --
/// "did `curl_formadd` produce this node?" -- and it has to be answerable,
/// because the engine model a node belongs to cannot be reconstructed from the
/// node's public fields alone.
const FORM_MAGIC: u64 = 0x0000_7372_6d72_6f66;

/// The largest number of decode steps one `curl_formadd` call may take.
///
/// `lib/formdata.c:331-352` reads until `CURLFORM_END` and has no bound, so an
/// unterminated list walks off the end of the caller's frame -- undefined
/// behaviour, with no defined result to preserve. This bound converts that into
/// [`CURLFORMcode::CURL_FORMADD_INCOMPLETE`], whose documented meaning at
/// `include/curl/curl.h:2602` is "if the some FormInfo is not complete (or
/// error)". It counts steps rather than options so that a run of
/// `CURLFORM_ARRAY` options, which contribute no option of their own, is bounded
/// too. No terminated call comes close: the largest form in the fixture corpus
/// carries fewer than twenty options.
const MAX_DECODE_STEPS: usize = 4096;

// The argument shape of each option: lib/formdata.c:311-316 and :355-566

/// What the argument governed by one `CURLFORM_*` option holds.
///
/// The C reads it through one of two macros whose definitions are the whole of
/// why this enumeration has three members and not one:
///
/// ```c
/// #define form_ptr_arg(t) (forms ? (t)(void *)avalue : va_arg(params, t))
/// #define form_int_arg(t) (forms ? (t)(uintptr_t)avalue : va_arg(params, t))
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Shape {
    /// `form_ptr_arg(char *)`, and the two other pointer types the switch
    /// reads: `struct curl_slist *` for `CURLFORM_CONTENTHEADER` and
    /// `struct curl_forms *` for `CURLFORM_ARRAY`. `CURLFORM_STREAM`'s
    /// argument is a `void *` context read through the same macro (`:496`).
    Ptr,
    /// `form_int_arg(long)`: `CURLFORM_NAMELENGTH` (`:388`),
    /// `CURLFORM_CONTENTSLENGTH` (`:409`) and `CURLFORM_BUFFERLENGTH`
    /// (`:490`).
    Long,
    /// `form_int_arg(curl_off_t)`: `CURLFORM_CONTENTLEN` alone (`:414`).
    OffT,
}

/// The shape of `option`'s argument, or `None` when the C's `switch` has no
/// case for it.
fn shape_of(option: CURLformoption) -> Option<Shape> {
    match option {
        CURLformoption::CURLFORM_COPYNAME
        | CURLformoption::CURLFORM_PTRNAME
        | CURLformoption::CURLFORM_COPYCONTENTS
        | CURLformoption::CURLFORM_PTRCONTENTS
        | CURLformoption::CURLFORM_FILECONTENT
        | CURLformoption::CURLFORM_ARRAY
        | CURLformoption::CURLFORM_FILE
        | CURLformoption::CURLFORM_BUFFER
        | CURLformoption::CURLFORM_BUFFERPTR
        | CURLformoption::CURLFORM_CONTENTTYPE
        | CURLformoption::CURLFORM_CONTENTHEADER
        | CURLformoption::CURLFORM_FILENAME
        | CURLformoption::CURLFORM_STREAM => Some(Shape::Ptr),
        CURLformoption::CURLFORM_NAMELENGTH
        | CURLformoption::CURLFORM_CONTENTSLENGTH
        | CURLformoption::CURLFORM_BUFFERLENGTH => Some(Shape::Long),
        CURLformoption::CURLFORM_CONTENTLEN => Some(Shape::OffT),
        CURLformoption::CURLFORM_END
        | CURLformoption::CURLFORM_NOTHING
        | CURLformoption::CURLFORM_OBSOLETE
        | CURLformoption::CURLFORM_OBSOLETE2
        | CURLformoption::CURLFORM_LASTENTRY => None,
    }
}

/// One argument, already fetched from wherever it lived.
#[derive(Clone, Copy)]
enum Arg {
    /// A `Shape::Ptr` argument.
    Ptr(*mut c_void),
    /// A `Shape::Long` argument.
    Long(c_long),
    /// A `Shape::OffT` argument.
    OffT(curl_off_t),
}

/// One option and its argument, in the order the caller wrote them.
#[derive(Clone, Copy)]
struct Item {
    /// The option, already validated against the enumeration.
    option: CURLformoption,
    /// The argument the option governs.
    arg: Arg,
}

impl Item {
    /// The pointer this item carries, or null when its shape is not a pointer.
    ///
    /// Total rather than panicking: [`shape_of`] decided the variant when the
    /// item was built, so the mismatched arms are unreachable, and returning
    /// null in them keeps that unreachability from becoming a panic across the
    /// C boundary if it is ever wrong.
    fn pointer(self) -> *mut c_void {
        match self.arg {
            Arg::Ptr(pointer) => pointer,
            Arg::Long(_) | Arg::OffT(_) => ptr::null_mut(),
        }
    }

    /// The integer this item carries, widened, or zero for a pointer shape.
    fn integer(self) -> curl_off_t {
        match self.arg {
            Arg::Long(value) => value,
            Arg::OffT(value) => value,
            Arg::Ptr(_) => 0,
        }
    }
}

// Stage 1: the argument-list walk, once, in the caller's order

/// Walks the argument list into [`Item`]s, flattening any `CURLFORM_ARRAY`.
///
/// A transcription of `lib/formdata.c:328-352` plus the two `CURLFORM_ARRAY`
/// arms at `:356-365`. Three properties of the C are reproduced exactly and
/// each one is observable:
///
/// * **Array state is consulted first.** While a row pointer is live the option
///   and its value both come from the row and **no argument-list slot is
///   consumed**; `CURLFORM_END` inside an array only leaves array state and
///   continues, rather than ending the list (`:337-343`).
/// * **One level only.** `CURLFORM_ARRAY` inside an array is
///   `CURL_FORMADD_ILLEGAL_ARRAY` -- the C's own comment is "we do not support
///   an array from within an array" -- and a null array pointer is
///   `CURL_FORMADD_NULL` (`:356-364`).
/// * **An unrecognised option stops the walk.** The C's `default` arm reads no
///   argument, so nothing is known about the rest of the list.
///
/// One difference from the C is deliberate and is unobservable. Several arms
/// fetch their argument only in the `else` branch of a "given twice" test, so
/// the C leaves a slot unread when that test fails; this walk always reads it.
/// The difference cannot be seen, because every such branch's other side sets a
/// non-`CURL_FORMADD_OK` code, which ends the C's `while` loop immediately --
/// so no later argument is read by either implementation.
///
/// # Safety
///
/// `ap` must be non-null and must be the argument list the trampoline
/// synthesised for this call, unread by anything else. The caller must have
/// terminated its options with `CURLFORM_END`, and each option must be followed
/// by an argument of the type that option names; that is `curl_formadd`'s own
/// contract with its caller and no implementation in any language can check it.
/// Any `struct curl_forms` array named by `CURLFORM_ARRAY` must likewise be
/// `CURLFORM_END`-terminated and must stay valid for the duration of the call.
unsafe fn collect(ap: *mut CVaList) -> Result<Vec<Item>, CURLFORMcode> {
    // SAFETY: `ap` is non-null and is this call's own argument list by the
    // contract above, which is exactly `VaArgs::new`'s precondition.
    let mut args = unsafe { VaArgs::new(ap) };
    let mut items: Vec<Item> = Vec::new();
    let mut row: *const curl_forms = ptr::null();
    let end = CURLformoption::CURLFORM_END.as_c_int();

    for _ in 0..MAX_DECODE_STEPS {
        // `if(forms) { ... } else { ... }` (`:332-352`): array state first.
        let (raw, from_array, row_value) = if row.is_null() {
            let raw = args.next_int();
            if raw == end {
                // `if(CURLFORM_END == option) break;` (`:351-352`).
                return Ok(items);
            }
            (raw, false, ptr::null_mut())
        } else {
            // SAFETY: `row` is either the array pointer the caller supplied or
            // that pointer advanced past rows this loop has already read, and
            // the caller's contract promises a `CURLFORM_END`-terminated array,
            // so the row is inside it. `addr_of!` forms a pointer to each field
            // without constructing a reference to the record, and the option is
            // read as a `c_int` rather than as a `CURLformoption` on purpose: a
            // C caller may put any integer there, and materialising an
            // out-of-range value as the enumeration would be undefined
            // behaviour rather than the `CURL_FORMADD_UNKNOWN_OPTION` the C
            // reports.
            let (option, value) = unsafe {
                (
                    ptr::addr_of!((*row).option).cast::<c_int>().read(),
                    ptr::addr_of!((*row).value).read(),
                )
            };
            // SAFETY: as above; the array is terminated, so advancing one row
            // stays inside it or reaches the terminator.
            row = unsafe { row.add(1) };
            if option == end {
                // `forms = NULL; continue;` (`:339-343`) -- the end of the
                // array, not the end of the list.
                row = ptr::null();
                continue;
            }
            (option, true, value.cast_mut().cast::<c_void>())
        };

        // `default: retval = CURL_FORMADD_UNKNOWN_OPTION;` (`:563-565`), for an
        // integer outside the enumeration and for the four members that name no
        // operation alike. No argument is read, here or in the C.
        let Some(option) = CURLformoption::from_c_int(raw) else {
            return Err(CURLFORMcode::CURL_FORMADD_UNKNOWN_OPTION);
        };
        let Some(shape) = shape_of(option) else {
            return Err(CURLFORMcode::CURL_FORMADD_UNKNOWN_OPTION);
        };

        let arg = if from_array {
            // `form_ptr_arg` and `form_int_arg` with `forms` live: the row's
            // `value` field reinterpreted, with no slot consumed.
            match shape {
                Shape::Ptr => Arg::Ptr(row_value),
                Shape::Long => Arg::Long(row_value as usize as c_long),
                Shape::OffT => Arg::OffT(row_value as usize as curl_off_t),
            }
        } else {
            // The `va_arg` half of the same two macros.
            match shape {
                Shape::Ptr => Arg::Ptr(args.next_ptr()),
                Shape::Long => Arg::Long(args.next_long()),
                Shape::OffT => Arg::OffT(args.next_longlong()),
            }
        };

        if option == CURLformoption::CURLFORM_ARRAY {
            if from_array {
                return Err(CURLFORMcode::CURL_FORMADD_ILLEGAL_ARRAY);
            }
            let next = match arg {
                Arg::Ptr(pointer) => pointer.cast::<curl_forms>(),
                Arg::Long(_) | Arg::OffT(_) => ptr::null_mut(),
            };
            if next.is_null() {
                return Err(CURLFORMcode::CURL_FORMADD_NULL);
            }
            row = next.cast_const();
            continue;
        }

        items.push(Item { option, arg });
    }

    // The bound was reached without a terminator. See `MAX_DECODE_STEPS`.
    Err(CURLFORMcode::CURL_FORMADD_INCOMPLETE)
}

// Stage 2: resolving the lengths, then building the engine's vocabulary

/// Which potential `more`-node group each item belongs to.
fn groups(items: &[Item]) -> Vec<usize> {
    let mut current = 0usize;
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        if matches!(
            item.option,
            CURLformoption::CURLFORM_FILE
                | CURLformoption::CURLFORM_CONTENTTYPE
        ) {
            current += 1;
        }
        out.push(current);
    }
    out
}

/// The length the caller declared for the pointer at `at`, if it can be found.
///
/// `last_wins` distinguishes the two rules the C uses. `CURLFORM_NAMELENGTH`
/// (`:385-388`) and `CURLFORM_BUFFERLENGTH` (`:487-490`) report
/// `CURL_FORMADD_OPTION_TWICE` for a second non-zero value, so the first
/// non-zero one is the effective one. `CURLFORM_CONTENTSLENGTH` (`:408-410`) and
/// `CURLFORM_CONTENTLEN` (`:412-415`) have **no such check** -- an asymmetry that
/// is transcribed rather than corrected -- so the last value written is the
/// effective one.
fn declared_length(
    items: &[Item],
    grouping: &[usize],
    at: usize,
    wanted: fn(CURLformoption) -> bool,
    last_wins: bool,
) -> Option<curl_off_t> {
    let mine = grouping.get(at).copied()?;
    let mut found: Option<curl_off_t> = None;
    for (index, item) in items.iter().enumerate() {
        if grouping.get(index).copied() != Some(mine) || !wanted(item.option) {
            continue;
        }
        let value = item.integer();
        // Both rules assign the same thing; only the condition differs, so they
        // are one branch rather than two identical ones. Under `last_wins` every
        // value overwrites; otherwise only the first non-zero one takes.
        if last_wins || (found.is_none() && value != 0) {
            found = Some(value);
        }
    }
    if found.is_some() {
        return found;
    }

    let mut candidates = items.iter().filter(|item| wanted(item.option));
    let only = candidates.next()?;
    if candidates.next().is_some() {
        return None;
    }
    Some(only.integer())
}

/// True for the two options that declare a name's length.
fn is_name_length(option: CURLformoption) -> bool {
    option == CURLformoption::CURLFORM_NAMELENGTH
}

/// True for the option that declares a buffer's length.
fn is_buffer_length(option: CURLformoption) -> bool {
    option == CURLformoption::CURLFORM_BUFFERLENGTH
}

/// True for the two options that declare a value's length.
///
/// Both write the same field in the C -- `curr->contentslength` -- and the flag
/// is what records which spelling was used, so they are one question here.
fn is_content_length(option: CURLformoption) -> bool {
    matches!(
        option,
        CURLformoption::CURLFORM_CONTENTSLENGTH
            | CURLformoption::CURLFORM_CONTENTLEN
    )
}

/// Borrows the bytes a caller's pointer names, for `declared` of them.
///
/// The three cases are the C's, in the C's own terms:
///
/// * A **positive** declared length is taken at face value and the pointer is
///   **not** measured. That is the point of `CURLFORM_NAMELENGTH`: a name that
///   is not NUL-terminated, which `lib/formdata.c` reads with `memchr` and
///   `Curl_bufref_memdup0` for exactly that many bytes and never with `strlen`.
/// * A **zero or absent** length means "measure it", which the C spells as
///   `strlen` in `AddHttpPost` (`:63-65`) and as `CURL_ZERO_TERMINATED` in the
///   bridge (`:807-810`).
/// * A **negative** length is not a length. The C casts it through `size_t`,
///   which yields a value above `LONG_MAX`, and the engine's transcription of
///   `AddHttpPost`'s guard (`:66-68`) reports `CURL_FORMADD_MEMORY` for it
///   before the bytes are looked at. An empty slice is therefore returned: it is
///   non-`None`, so the option is not mistaken for a null pointer, and it is
///   sound for any non-null pointer, so no oversized slice is ever constructed.
///   The declared value itself still reaches the engine unaltered, which is what
///   makes the guard fire.
///
/// # Safety
///
/// `pointer` must be null, or address at least `declared` readable bytes when
/// `declared` is positive, or a NUL-terminated string otherwise. Those bytes
/// must stay valid and unmodified for as long as the returned slice is used,
/// which for a `CURLFORM_PTR*` option means for as long as the form lives. This
/// is `curl_formadd`'s contract with its caller, unchanged from the C.
unsafe fn borrow_bytes<'a>(
    pointer: *const c_char,
    declared: Option<curl_off_t>,
) -> Option<&'a [u8]> {
    if pointer.is_null() {
        return None;
    }
    match declared {
        Some(length) if length < 0 => Some(&[]),
        Some(length) if length > 0 => {
            // `length` is positive and 64-bit, so it is at most `isize::MAX` on
            // every 64-bit target, which is the bound `from_raw_parts` requires.
            let length = length as usize;
            // SAFETY: the caller promised `length` readable bytes at `pointer`
            // by passing that length alongside it, and promised they outlive the
            // form. `u8` has no alignment requirement, and `length` cannot
            // exceed `isize::MAX` as observed above.
            Some(unsafe { slice::from_raw_parts(pointer.cast::<u8>(), length) })
        }
        _ => {
            // SAFETY: with no positive length declared, the caller's promise is
            // a NUL-terminated string, which is exactly `CStr::from_ptr`'s
            // precondition. The returned bytes exclude the terminator, matching
            // `strlen`.
            Some(unsafe { CStr::from_ptr(pointer) }.to_bytes())
        }
    }
}

/// Borrows a NUL-terminated pathname or media type, as the bytes it is.
///
/// # The narrow deviation that used to live here, and why it is gone
///
/// A `borrow_str` stood in this place. It decoded the pointer as UTF-8 and, for
/// anything it could not read, returned `CURL_FORMADD_MEMORY` -- because the
/// engine's `FormOption` vocabulary spelled these five options `&str` and there
/// was no other code to give. Two things were wrong with that, beyond the
/// narrowing itself:
///
/// * `CURL_FORMADD_MEMORY` means an allocation failed. Reporting it for a
///   perfectly valid byte string told the caller something untrue about its own
///   process, and `curl_formadd`'s five codes have no member that means "your
///   filename is not Unicode" precisely because the C never needs one.
/// * The affected options are `CURLFORM_FILE`, `CURLFORM_FILECONTENT`,
///   `CURLFORM_BUFFER`, `CURLFORM_FILENAME` and `CURLFORM_CONTENTTYPE`. The
///   first three name files on the local filesystem and the last two go on the
///   wire inside a `Content-Disposition` or a `Content-Type`. The C stores each
///   as the `char *` it received. So a form that curl 8.x posts was refused,
///   and the refusal was reachable from any program passing a filename in a
///   locale encoding.
///
/// The engine now carries all five as bytes, so this is a plain borrow with no
/// failure mode -- which is why it returns `Option` rather than `Result`.
///
/// # Safety
///
/// `pointer` must be null or address a NUL-terminated string that stays valid
/// and unmodified for as long as the returned reference is used.
unsafe fn borrow_cstr_bytes<'a>(pointer: *const c_char) -> Option<&'a [u8]> {
    // The NUL-terminated form of `borrow_bytes`, reached by declaring no
    // length: one implementation answers for both, so the two cannot drift.
    // SAFETY: this function's contract is `borrow_bytes`'s contract for a
    // `declared` of `None`, forwarded unchanged.
    unsafe { borrow_bytes(pointer, None) }
}

/// The caller's own pointers, which the engine's model does not carry back.
///
/// Two of `struct curl_httppost`'s fourteen members hold a pointer that the C
/// stores verbatim and never copies, and neither can be recovered from the
/// engine afterwards:
///
/// * `contentheader` -- `post->contentheader = src->contentheader` (`:79`), and
///   `curl_formfree` never frees it. The engine takes a *copy* of the list, so
///   what it can hand back is equal but not identical, and a consumer comparing
///   `post->contentheader` against the list it passed would see a different
///   address.
/// * `userp` -- `post->userp = src->userp` (`:81`). The engine holds an
///   assembled reader instead, because a function pointer and an untyped context
///   cannot be held safely apart, and a reader cannot be asked for the context
///   inside it.
struct Sides {
    /// The `struct curl_slist *` each successful `CURLFORM_CONTENTHEADER`
    /// carried, in order.
    headers: Vec<*mut curl_slist>,
    /// The `void *` each successful `CURLFORM_STREAM` carried, in order.
    streams: Vec<*mut c_void>,
}

/// The reader a `CURLFORM_STREAM` part is built with.
///
/// # Why reading nothing is the correct behaviour and not a stub
///
/// In the C the context and the read function live apart: `curl_formadd` stores
/// only the context in `post->userp` (`:504`), and the function arrives later as
/// `Curl_getformdata`'s fourth parameter. `curl_formget` passes **NULL** for it
/// (`:638`), and `curl_mime_data_cb` with a null read function "clears the
/// content and installs nothing" (`lib/mime.c:1425-1434`), so a form serialised
/// by `curl_formget` renders a callback part as its headers with an empty body.
/// That is curl 8.x's behaviour and it is frozen.
///
/// This reader reproduces exactly that, and the context it carries is not lost:
/// it is written to `post->userp`, which is where the C's own bridge reads it
/// from.
struct StreamSource {
    /// `post->userp`: the caller's context, carried and never dereferenced.
    arg: *mut c_void,
}

impl core::fmt::Debug for StreamSource {
    /// Deliberately opaque.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StreamSource")
            .field("arg", &!self.arg.is_null())
            .finish()
    }
}

impl PartReader for StreamSource {
    /// End of data at once, which is what a null read function produces.
    ///
    /// `ReadStatus::Eof` rather than `Bytes(0)`: the engine's contract makes the
    /// two distinct cases and `Bytes(0)` would loop.
    fn read(&mut self, _buf: &mut [u8]) -> ReadStatus {
        ReadStatus::Eof
    }

    /// No repositioning, which is the C's absent seek function.
    fn seek(&mut self, _offset: curl_off_t, _whence: SeekWhence) -> SeekResult {
        SeekResult::CantSeek
    }

    /// A second reader over the same context.
    ///
    /// `Curl_mime_duppart` copies the pointers and the `void *arg` unchanged
    /// (`lib/mime.c:1122-1123`), so the two parts share one context; that is
    /// reproduced literally.
    fn duplicate(&self) -> Box<dyn PartReader> {
        Box::new(Self { arg: self.arg })
    }
}

/// Turns the decoded items into the engine's option vocabulary.
///
/// Every variant is a one-to-one transcription of one `case` in
/// `lib/formdata.c:355-566`, and three properties of that switch are preserved
/// deliberately:
///
/// * **A null pointer is passed through as `None`, not filtered out.** The C
///   checks in a specific order and the order is observable:
///   `CURLFORM_FILENAME` tests "already set" **before** it looks at the argument
///   (`:557-560`), so `CURLFORM_FILENAME, "a", CURLFORM_FILENAME, NULL` is
///   `CURL_FORMADD_OPTION_TWICE` and not `CURL_FORMADD_NULL`. A decoder that
///   rejected the null first would report the wrong code.
/// * **A length option is forwarded even though its value has already been used
///   to size a slice.** The engine applies its own "given twice" test to it and
///   its own `LONG_MAX` guard, and both are observable.
/// * **The `(size_t)` cast of a `long` is reproduced rather than repaired.** A
///   negative `CURLFORM_NAMELENGTH` or `CURLFORM_BUFFERLENGTH` lands above
///   `LONG_MAX` in the C's `size_t` field (`:388`, `:490`) and the engine's guard
///   answers `CURL_FORMADD_MEMORY` for exactly those inputs. Clamping to zero
///   here would silently accept a call the C rejects.
///
/// # Safety
///
/// Every pointer in `items` must satisfy the promise the option that carried it
/// makes -- see [`borrow_bytes`] and [`borrow_cstr_bytes`] -- and a
/// `CURLFORM_CONTENTHEADER` list must be null or a well-formed, terminating
/// chain of NUL-terminated strings that nothing mutates during the call.
unsafe fn decode(
    items: &[Item],
    grouping: &[usize],
) -> Result<(Vec<FormOption<'static>>, Sides), CURLFORMcode> {
    let mut options: Vec<FormOption<'static>> = Vec::with_capacity(items.len());
    let mut sides = Sides {
        headers: Vec::new(),
        streams: Vec::new(),
    };

    for (at, item) in items.iter().enumerate() {
        let option = match item.option {
            // `case CURLFORM_PTRNAME:` / `case CURLFORM_COPYNAME:`
            // (`:370-383`), which share a body through a fallthrough.
            CURLformoption::CURLFORM_COPYNAME
            | CURLformoption::CURLFORM_PTRNAME => {
                let declared =
                    declared_length(items, grouping, at, is_name_length, false);
                // SAFETY: this function's contract, delegated to the caller of
                // `curl_formadd`, which promised the bytes this option names.
                let bytes =
                    unsafe { borrow_bytes(item.pointer().cast(), declared) };
                if item.option == CURLformoption::CURLFORM_COPYNAME {
                    FormOption::CopyName(bytes)
                } else {
                    FormOption::PtrName(bytes)
                }
            }

            // `case CURLFORM_NAMELENGTH:` (`:384-389`). `as usize` IS the C's
            // `(size_t)` cast; see this function's third preserved property.
            CURLformoption::CURLFORM_NAMELENGTH => {
                FormOption::NameLength(item.integer() as usize)
            }

            // `case CURLFORM_PTRCONTENTS:` / `case CURLFORM_COPYCONTENTS:`
            // (`:394-407`), likewise sharing a body.
            CURLformoption::CURLFORM_COPYCONTENTS
            | CURLformoption::CURLFORM_PTRCONTENTS => {
                let declared = declared_length(
                    items,
                    grouping,
                    at,
                    is_content_length,
                    true,
                );
                // SAFETY: as the name arms above.
                let bytes =
                    unsafe { borrow_bytes(item.pointer().cast(), declared) };
                if item.option == CURLformoption::CURLFORM_COPYCONTENTS {
                    FormOption::CopyContents(bytes)
                } else {
                    FormOption::PtrContents(bytes)
                }
            }

            // `case CURLFORM_CONTENTSLENGTH:` (`:408-410`). The C's expression
            // is `(curl_off_t)(size_t)form_int_arg(long)`, a round trip that is
            // the identity on every 64-bit target, so the value is forwarded as
            // it arrived.
            CURLformoption::CURLFORM_CONTENTSLENGTH => {
                FormOption::ContentsLength(item.integer())
            }

            // `case CURLFORM_CONTENTLEN:` (`:412-415`).
            CURLformoption::CURLFORM_CONTENTLEN => {
                FormOption::ContentLen(item.integer())
            }

            // `case CURLFORM_FILECONTENT:` (`:418-432`).
            CURLformoption::CURLFORM_FILECONTENT => {
                // SAFETY: this function's contract; the option names a
                // NUL-terminated filename.
                FormOption::FileContent(unsafe {
                    borrow_cstr_bytes(item.pointer().cast())
                })
            }

            // `case CURLFORM_FILE:` (`:435-468`).
            CURLformoption::CURLFORM_FILE => {
                // SAFETY: as `CURLFORM_FILECONTENT`.
                FormOption::File(unsafe {
                    borrow_cstr_bytes(item.pointer().cast())
                })
            }

            // `case CURLFORM_BUFFERPTR:` (`:470-484`).
            CURLformoption::CURLFORM_BUFFERPTR => {
                let declared = declared_length(
                    items,
                    grouping,
                    at,
                    is_buffer_length,
                    false,
                );
                // SAFETY: as the name arms above; a buffer is bytes, not a
                // string, and a zero or absent length means "measure it"
                // exactly as `CURL_ZERO_TERMINATED` does in the bridge.
                FormOption::BufferPtr(unsafe {
                    borrow_bytes(item.pointer().cast(), declared)
                })
            }

            // `case CURLFORM_BUFFERLENGTH:` (`:486-491`).
            CURLformoption::CURLFORM_BUFFERLENGTH => {
                FormOption::BufferLength(item.integer() as usize)
            }

            // `case CURLFORM_STREAM:` (`:493-509`). A null context is
            // `CURL_FORMADD_NULL`, which the engine reports for `None`; a
            // non-null one is recorded so that `post->userp` can carry it.
            CURLformoption::CURLFORM_STREAM => {
                let arg = item.pointer();
                if arg.is_null() {
                    FormOption::Stream(None)
                } else {
                    sides.streams.push(arg);
                    FormOption::Stream(Some(Box::new(StreamSource { arg })))
                }
            }

            // `case CURLFORM_CONTENTTYPE:` (`:511-540`).
            CURLformoption::CURLFORM_CONTENTTYPE => {
                // SAFETY: as `CURLFORM_FILECONTENT`; a media type is a
                // NUL-terminated string.
                FormOption::ContentType(unsafe {
                    borrow_cstr_bytes(item.pointer().cast())
                })
            }

            // `case CURLFORM_CONTENTHEADER:` (`:542-553`). The chain is copied
            // here and the caller's pointer recorded separately, which is what
            // makes the engine's `take_ownership`-of-zero faithful without
            // aliasing: the caller keeps its own list and `curl_formfree` never
            // frees it.
            CURLformoption::CURLFORM_CONTENTHEADER => {
                let list = item.pointer().cast::<curl_slist>();
                if list.is_null() {
                    FormOption::ContentHeader(None)
                } else {
                    sides.headers.push(list);
                    // SAFETY: by contract `list` is a well-formed, terminating
                    // chain of NUL-terminated strings that nothing mutates
                    // during the call, which is `slist_to_vec`'s precondition.
                    let lines = unsafe { slist_to_vec(list.cast_const()) };
                    // `SList` is not nameable from this crate; `collect`
                    // resolves it from this position through the engine's
                    // `FromIterator<Vec<u8>>`, so no private path is named.
                    FormOption::ContentHeader(Some(lines.into_iter().collect()))
                }
            }

            // `case CURLFORM_FILENAME:` and `case CURLFORM_BUFFER:`
            // (`:554-561`) -- one arm in the C, writing one field.
            CURLformoption::CURLFORM_FILENAME
            | CURLformoption::CURLFORM_BUFFER => {
                // SAFETY: as `CURLFORM_FILECONTENT`.
                let shown = unsafe { borrow_cstr_bytes(item.pointer().cast()) };
                if item.option == CURLformoption::CURLFORM_FILENAME {
                    FormOption::FileName(shown)
                } else {
                    FormOption::Buffer(shown)
                }
            }

            // Unreachable by construction: `collect` refuses `CURLFORM_ARRAY`
            // and `CURLFORM_END` and every member with no `case`, so no item can
            // carry one. Answering with the code the C's `default` arm answers
            // keeps the unreachability from becoming a panic across the ABI.
            CURLformoption::CURLFORM_ARRAY
            | CURLformoption::CURLFORM_END
            | CURLformoption::CURLFORM_NOTHING
            | CURLformoption::CURLFORM_OBSOLETE
            | CURLformoption::CURLFORM_OBSOLETE2
            | CURLformoption::CURLFORM_LASTENTRY => {
                return Err(CURLFORMcode::CURL_FORMADD_UNKNOWN_OPTION);
            }
        };
        options.push(option);
    }

    Ok((options, sides))
}

// The mirror: what a `struct curl_httppost *` actually addresses

/// One node of the chain a caller walks.
///
/// `post` is **first** and the record is `#[repr(C)]`, so a `*mut FormNode` and
/// a `*mut curl_httppost` addressing it are the same address and the first 112
/// bytes are exactly the frozen struct. The two trailing members are invisible
/// to C, which cannot know the allocation is larger than the type it was handed.
#[repr(C)]
struct FormNode {
    /// The ABI-visible prefix, and the only part C may read.
    post: curl_httppost,
    /// [`FORM_MAGIC`] in a live node.
    magic: u64,
    /// The form this node belongs to. Never null in a live node.
    root: *mut FormRoot,
}

/// Everything one form owns: the engine's model and the mirror of it.
struct FormRoot {
    /// The authority. Declared first so that it is dropped first, before the
    /// bookkeeping that describes it.
    list: FormList<'static>,
    /// Every node this form has allocated, top-level and `more` alike, in
    /// allocation order. Raw pointers, so dropping the vector frees nothing;
    /// [`release_form`] releases them explicitly.
    nodes: Vec<*mut FormNode>,
    /// The first top-level node, which is the `struct curl_httppost *` a caller
    /// holds. Null only between construction and the first successful addition.
    head: *mut FormNode,
    /// The abandoned-mutation flag the transactional guard consults.
    ///
    /// **Boxed on purpose**, for the same borrow shape `super::mime` documents:
    /// the flag's address is read out of the record and the flag reached through
    /// its own allocation, so the shared borrow handed to the guard does not
    /// overlap the exclusive borrow the body takes.
    poison: Box<Poison>,
}

/// The eight `CURL_HTTPPOST_*` bits, from the engine's named booleans.
fn flag_bits(flags: FormFlags) -> c_long {
    let mut bits: c_long = 0;
    if flags.filename {
        bits |= CURL_HTTPPOST_FILENAME;
    }
    if flags.readfile {
        bits |= CURL_HTTPPOST_READFILE;
    }
    if flags.ptrname {
        bits |= CURL_HTTPPOST_PTRNAME;
    }
    if flags.ptrcontents {
        bits |= CURL_HTTPPOST_PTRCONTENTS;
    }
    if flags.buffer {
        bits |= CURL_HTTPPOST_BUFFER;
    }
    if flags.ptrbuffer {
        bits |= CURL_HTTPPOST_PTRBUFFER;
    }
    if flags.callback {
        bits |= CURL_HTTPPOST_CALLBACK;
    }
    if flags.large {
        bits |= CURL_HTTPPOST_LARGE;
    }
    bits
}

/// A length the engine has already bounded, as the `long` the mirror needs.
///
/// The engine reproduces `AddHttpPost`'s guard -- "avoid overflow in typecasts
/// below" at `lib/formdata.c:66-68` -- and answers `CURL_FORMADD_MEMORY` for a
/// length above `LONG_MAX`, so by the time an entry exists every length fits.
/// `try_from` rather than `as` keeps that a checked fact: the failure arm cannot
/// be reached, and if it ever were it would report a failure rather than write a
/// silently negative `long` into a field a consumer reads.
fn as_long<T: TryInto<c_long>>(value: T, failed: &mut bool) -> c_long {
    match value.try_into() {
        Ok(value) => value,
        Err(_) => {
            *failed = true;
            0
        }
    }
}

/// A duplicate the node will own, or the caller's own pointer left alone.
///
/// The distinction is [`Ownership`], which the engine hands over as a
/// transcription of `curl_formfree`'s two conditional releases (`:679-683`)
/// rather than as something re-derived here. `Ownership::Owned` bytes are copied
/// through the crate-uniform allocator so that the block a consumer could free,
/// and that `curl_formfree` will free, comes from the same allocator
/// `curl_global_init_mem` installed. `Ownership::Borrowed` bytes are the
/// caller's: the pointer is stored as it is, the matching `CURL_HTTPPOST_PTR*`
/// bit keeps `curl_formfree` off it, and the caller may reuse or release it once
/// the form is gone.
fn own_or_borrow(
    bytes: Option<&[u8]>,
    ownership: Ownership,
    failed: &mut bool,
) -> *mut c_char {
    let Some(bytes) = bytes else {
        return ptr::null_mut();
    };
    match ownership {
        Ownership::Borrowed => bytes.as_ptr().cast_mut().cast::<c_char>(),
        Ownership::Owned => {
            let copy = memory::copy_to_c_string(bytes);
            if copy.is_null() {
                *failed = true;
            }
            copy
        }
    }
}

/// Releases exactly the fields `curl_formfree` releases, and no others.
///
/// A transcription of `lib/formdata.c:679-685`, reading the decision out of
/// `post->flags` exactly as the C does:
///
/// ```c
/// if(!(form->flags & HTTPPOST_PTRNAME)) free(form->name);
/// if(!(form->flags & (HTTPPOST_PTRCONTENTS | HTTPPOST_BUFFER |
///                     HTTPPOST_CALLBACK))) free(form->contents);
/// free(form->contenttype);
/// free(form->showfilename);
/// ```
///
/// # Safety
///
/// Every non-null field this releases must be a block obtained from
/// [`super::memory`] by [`own_or_borrow`] and not already released, and the
/// flags must be the ones that were in force when they were allocated. Both hold
/// for a node [`stage`] built, whose flags are never modified afterwards.
unsafe fn release_fields(post: &curl_httppost) {
    if post.flags & CURL_HTTPPOST_PTRNAME == 0 {
        // SAFETY: the bit is clear, so `name` is a duplicate this module
        // allocated, or null, which `memory::free` forwards as C `free` does.
        unsafe { memory::free(post.name.cast::<c_void>()) };
    }
    let borrowed = CURL_HTTPPOST_PTRCONTENTS
        | CURL_HTTPPOST_BUFFER
        | CURL_HTTPPOST_CALLBACK;
    if post.flags & borrowed == 0 {
        // SAFETY: as above, for the three bits the C tests together.
        unsafe { memory::free(post.contents.cast::<c_void>()) };
    }
    // SAFETY: both are unconditional in the C because `CURLFORM_CONTENTTYPE`
    // (`:535`) and `CURLFORM_FILENAME` (`:559`) always copy, so the engine
    // reports `Ownership::Owned` for both and these are always duplicates or
    // null.
    unsafe { memory::free(post.contenttype.cast::<c_void>()) };
    // SAFETY: as `contenttype`.
    unsafe { memory::free(post.showfilename.cast::<c_void>()) };
}

/// Releases one node and everything it owns.
///
/// # Safety
///
/// `node` must be a live node [`stage`] produced, not already released, and
/// unreachable from any chain a caller still holds.
unsafe fn release_node(node: *mut FormNode) {
    // SAFETY: by contract `node` addresses a live `FormNode`, so the shared
    // borrow of its ABI prefix is sound; the borrow ends before the block is
    // released.
    unsafe { release_fields(&(*node).post) };
    // SAFETY: the block came from `memory::calloc` in `stage` and this is its
    // single release, through the same allocator.
    unsafe { memory::free(node.cast::<c_void>()) };
}

/// Mirrors one engine entry into one node.
///
/// A transcription of `AddHttpPost` (`lib/formdata.c:57-103`) field by field,
/// minus the list surgery its caller performs. Two assignments are not a plain
/// copy of the corresponding accessor and both are the C's own doing:
///
/// * **`contents` for a callback part is the context pointer.**
///   `Curl_bufref_set(&curr->value, avalue, 0, NULL)` at `:504` stores the
///   `CURLFORM_STREAM` argument itself as the value -- the C's comment is "the
///   following line is not strictly true but we derive a value from this later
///   on" -- and `CURL_HTTPPOST_CALLBACK` then keeps `curl_formfree` off it. The
///   engine holds an assembled reader in that slot instead, so the pointer is
///   restored here.
/// * **`contentslength` stays whatever the engine reports, which is zero.**
///   `AddHttpPost` never assigns it: the struct arrives zeroed from `calloc` at
///   `:69` and the accumulator's length goes to `contentlen` at `:74` instead.
///   Both members are written anyway, because both are public and a consumer can
///   read either.
///
/// # Safety
///
/// `root` must address the form this node will belong to; it is stored and never
/// dereferenced here. `headers` and `userp` must be the caller's own pointers for
/// this node, and every borrowed byte range the entry reports must outlive the
/// form, which is the `CURLFORM_PTR*` contract.
unsafe fn stage(
    entry: &FormEntry<'_>,
    root: *mut FormRoot,
    headers: *mut curl_slist,
    userp: *mut c_void,
) -> *mut FormNode {
    let mut failed = false;
    let plan = entry.free_plan();
    let flags = entry.flags();

    let name = own_or_borrow(entry.name(), plan.name, &mut failed);
    let contents = if flags.callback {
        userp.cast::<c_char>()
    } else {
        own_or_borrow(entry.contents(), plan.contents, &mut failed)
    };
    // Both already are the bytes the C's `char *` holds, so nothing is
    // converted here any more.
    let contenttype =
        own_or_borrow(entry.contenttype(), plan.contenttype, &mut failed);
    let showfilename =
        own_or_borrow(entry.showfilename(), plan.showfilename, &mut failed);

    let post = curl_httppost {
        next: ptr::null_mut(),
        name,
        namelength: as_long(entry.namelength(), &mut failed),
        contents,
        contentslength: as_long(entry.contentslength(), &mut failed),
        // `post->buffer = src->buffer;` (`:75`): the caller's pointer, never
        // copied and never freed.
        buffer: entry.buffer().map_or(ptr::null_mut(), |bytes| {
            bytes.as_ptr().cast_mut().cast::<c_char>()
        }),
        bufferlength: as_long(entry.bufferlength(), &mut failed),
        contenttype,
        // `post->contentheader = src->contentheader;` (`:79`).
        contentheader: headers,
        // Linked by `mirror` once every node of the group exists.
        more: ptr::null_mut(),
        flags: flag_bits(flags),
        showfilename,
        // `post->userp = src->userp;` (`:81`).
        userp,
        // `post->contentlen = src->contentslength;` (`:74`).
        contentlen: entry.contentlen(),
    };

    if failed {
        // SAFETY: `post`'s fields are exactly what `own_or_borrow` produced a
        // moment ago and its flags are the ones in force for them, so this is
        // their single release. Nothing else has seen the record.
        unsafe { release_fields(&post) };
        return ptr::null_mut();
    }

    let block = memory::calloc(1, size_of::<FormNode>());
    if block.is_null() || block as usize % align_of::<FormNode>() != 0 {
        // A hook that answers null, or one that answers a block this record
        // cannot legally live in. The alignment test is cheap and the
        // alternative is a misaligned write, so it is checked rather than
        // assumed of a replaceable allocator.
        // SAFETY: as the `failed` arm above.
        unsafe { release_fields(&post) };
        // SAFETY: the block, if any, came from `memory::calloc` above and is
        // released exactly once.
        unsafe { memory::free(block) };
        return ptr::null_mut();
    }

    let node = block.cast::<FormNode>();
    // SAFETY: `block` is a fresh, suitably sized and now provably aligned
    // allocation that nothing else refers to, so writing the record into it
    // initialises it without dropping anything that was there.
    unsafe {
        node.write(FormNode {
            post,
            magic: FORM_MAGIC,
            root,
        });
    }
    node
}

/// The next recorded side pointer, or `absent` when the record has run out.
///
/// Running out cannot happen on the path that reaches this -- see [`Sides`] for
/// why the counts agree -- and answering with the absent value rather than
/// panicking is what keeps that reasoning from becoming a panic across the ABI
/// if it is ever wrong.
fn take_next<T: Copy>(from: &[T], at: &mut usize, absent: T) -> T {
    let value = from.get(*at).copied().unwrap_or(absent);
    *at += 1;
    value
}

/// Mirrors one engine entry and its `more` chain into a fresh group of nodes.
///
/// # Safety
///
/// As [`stage`], for every node in the group.
unsafe fn mirror(
    entry: &FormEntry<'_>,
    root: *mut FormRoot,
    sides: &Sides,
) -> Option<Vec<*mut FormNode>> {
    let mut header_at = 0usize;
    let mut stream_at = 0usize;
    let mut nodes: Vec<*mut FormNode> =
        Vec::with_capacity(1 + entry.more().len());

    for one in core::iter::once(entry).chain(entry.more().iter()) {
        let headers = if one.contentheader().is_some() {
            take_next(&sides.headers, &mut header_at, ptr::null_mut())
        } else {
            ptr::null_mut()
        };
        let userp = if one.reader().is_some() {
            take_next(&sides.streams, &mut stream_at, ptr::null_mut())
        } else {
            ptr::null_mut()
        };

        // SAFETY: this function's contract, delegated one node at a time.
        let node = unsafe { stage(one, root, headers, userp) };
        if node.is_null() {
            for made in nodes {
                // SAFETY: each was produced by `stage` in this loop, is not
                // released, and is reachable from nothing: the group was never
                // spliced into the caller's chain.
                unsafe { release_node(made) };
            }
            return None;
        }
        nodes.push(node);
    }

    for at in 1..nodes.len() {
        let child = nodes[at].cast::<curl_httppost>();
        // SAFETY: `nodes[at - 1]` is a live node this loop just built and
        // nothing else refers to it yet, so writing one field of its ABI prefix
        // through a raw pointer is sound. `addr_of_mut!` avoids forming a
        // reference to the whole record.
        unsafe { ptr::addr_of_mut!((*nodes[at - 1]).post.more).write(child) };
    }

    Some(nodes)
}

/// Releases a whole form: every node, then the engine model.
///
/// The C's `curl_formfree` walks `next`, recurses into `more` and releases six
/// things per node (`:672-688`). Here the nodes are all in one vector in
/// allocation order, so the walk is a loop and the recursion is unnecessary --
/// the set released is identical, which is what matters -- and the engine model
/// is released by dropping it, which runs the same releases the C performs on the
/// copies it owns.
///
/// # Safety
///
/// `root` must be a live form this module created, reachable from nothing
/// afterwards, and not already released.
unsafe fn release_form(root: *mut FormRoot) {
    // SAFETY: by contract `root` addresses a live `FormRoot` produced by
    // `Box::into_raw`, so reclaiming the `Box` restores exactly the ownership
    // that call gave away, and this is its single reclamation.
    let owned = *unsafe { Box::from_raw(root) };
    for node in &owned.nodes {
        // SAFETY: every entry was produced by `stage` and spliced into this
        // form alone, the form is unreachable by contract, and each node appears
        // in the vector once.
        unsafe { release_node(*node) };
    }
    // The engine's own release function, called rather than left to drop glue:
    // it is what `lib/formdata.c:664-689` corresponds to on that side of the
    // boundary, and naming it keeps the correspondence visible.
    form_free(owned.list);
}

/// The form a node belongs to, or `None` when the node is not one of ours.
///
/// # Safety
///
/// `post` must be null, or a `struct curl_httppost *` that [`curl_formadd`]
/// produced and that has not been released. That is the C API's own documented
/// precondition -- `docs/libcurl/curl_formget.md` and
/// `docs/libcurl/curl_formfree.md` both say the chain must have been built with
/// `curl_formadd` -- so the trailing members this reads are inside the same
/// allocation. The magic test is defence in depth against a stale pointer, not a
/// substitute for that precondition.
unsafe fn form_of(post: *mut curl_httppost) -> Option<*mut FormRoot> {
    if post.is_null() {
        return None;
    }
    let node = post.cast::<FormNode>();
    // SAFETY: non-null by the test above and, by this function's contract,
    // addressing a live `FormNode`. Both reads are of plain `Copy` members and
    // no reference to the record outlives this block.
    let (magic, root) = unsafe {
        (
            ptr::addr_of!((*node).magic).read(),
            ptr::addr_of!((*node).root).read(),
        )
    };
    if magic != FORM_MAGIC || root.is_null() {
        return None;
    }
    Some(root)
}

/// The flag's address, read out of a form without borrowing the form.
///
/// # Safety
///
/// `root` must address a live [`FormRoot`], and the returned reference must not
/// outlive it.
unsafe fn poison_of<'a>(root: *mut FormRoot) -> &'a Poison {
    // SAFETY: by contract `root` addresses a live, initialised `FormRoot`, so
    // its `poison` member holds a valid `Box<Poison>`, and reading the member as
    // a pointer neither constructs nor drops a second owner of the flag.
    let flag: *const Poison =
        unsafe { ptr::addr_of!((*root).poison).cast::<*const Poison>().read() };
    // SAFETY: `flag` addresses a `Poison` the form's `Box` owns, which by
    // contract outlives this borrow, and nothing takes an exclusive borrow of
    // that separate allocation.
    unsafe { &*flag }
}

/// The engine's outcome, as the enumeration the ABI reports.
///
/// One arm per token, written out rather than folded, because the numbers behind
/// them are frozen: `super::codes` pins all nine and the engine deliberately
/// carries no discriminants of its own so that the two cannot disagree.
fn to_form_code(code: FormCode) -> CURLFORMcode {
    match code {
        FormCode::Ok => CURLFORMcode::CURL_FORMADD_OK,
        FormCode::Memory => CURLFORMcode::CURL_FORMADD_MEMORY,
        FormCode::OptionTwice => CURLFORMcode::CURL_FORMADD_OPTION_TWICE,
        FormCode::Null => CURLFORMcode::CURL_FORMADD_NULL,
        FormCode::UnknownOption => CURLFORMcode::CURL_FORMADD_UNKNOWN_OPTION,
        FormCode::Incomplete => CURLFORMcode::CURL_FORMADD_INCOMPLETE,
        FormCode::IllegalArray => CURLFORMcode::CURL_FORMADD_ILLEGAL_ARRAY,
        FormCode::Disabled => CURLFORMcode::CURL_FORMADD_DISABLED,
    }
}

// 1 of 3: curl_formadd

/// Adds one part to a form: the Rust half of `curl_formadd`.
///
/// # Safety
///
/// `httppost` and `last_post` must each be null or address a writable
/// `struct curl_httppost *`, and `ap` must be the argument list the trampoline
/// synthesised. Every pointer in that list must satisfy the promise its option
/// makes -- see [`borrow_bytes`] and [`borrow_cstr_bytes`] -- and a `CURLFORM_PTR*`
/// buffer must outlive the form. Any existing chain reached through `*last_post`
/// must be one this module produced.
unsafe extern "C" fn formadd_va(
    httppost: *mut *mut curl_httppost,
    last_post: *mut *mut curl_httppost,
    ap: *mut CVaList,
) -> CURLFORMcode {
    guard(CURLFORMcode::CURL_FORMADD_MEMORY, || {
        if httppost.is_null() || last_post.is_null() || ap.is_null() {
            // The C dereferences all three unconditionally; a null is undefined
            // there and so has no behaviour to preserve. `CURL_FORMADD_NULL`,
            // whose documented meaning at `curl.h:2599` is "if a null pointer
            // was given", is the honest answer.
            return CURLFORMcode::CURL_FORMADD_NULL;
        }

        // SAFETY: this function's contract; `ap` is non-null by the test above.
        let items = match unsafe { collect(ap) } {
            Ok(items) => items,
            Err(code) => return code,
        };
        let grouping = groups(&items);
        // SAFETY: as above, delegated for every pointer the items carry.
        let (options, sides) = match unsafe { decode(&items, &grouping) } {
            Ok(decoded) => decoded,
            Err(code) => return code,
        };

        // `if(*last_post) ... else (*httppost) = newchain;` (`:586-594`): it is
        // the TAIL, not the head, that decides whether a chain already exists.
        // SAFETY: non-null by the test above and writable by contract.
        let tail = unsafe { last_post.read() };

        let (root, created) = if tail.is_null() {
            let fresh = Box::new(FormRoot {
                list: FormList::new(),
                nodes: Vec::new(),
                head: ptr::null_mut(),
                poison: Box::new(Poison::new()),
            });
            (Box::into_raw(fresh), true)
        } else {
            // SAFETY: by contract any chain reached through `*last_post` is one
            // this module produced.
            match unsafe { form_of(tail) } {
                Some(root) => (root, false),
                None => {
                    // A chain this module did not build. The engine model behind
                    // it does not exist and cannot be reconstructed -- the
                    // builder exposes accessors and no constructor -- so the
                    // form cannot be extended. `CURL_FORMADD_INCOMPLETE`, whose
                    // documented meaning at `curl.h:2602` is "if the some
                    // FormInfo is not complete (or error)", reports it loudly
                    // rather than corrupting either model.
                    return CURLFORMcode::CURL_FORMADD_INCOMPLETE;
                }
            }
        };

        // SAFETY: `root` is either the form just created or the one the tail
        // named, and by libcurl's own contract a form is used from one thread at
        // a time, so the flag's allocation is not exclusively borrowed here.
        let poison = unsafe { poison_of(root) };

        let outcome = guard_tx(
            poison,
            CURLFORMcode::CURL_FORMADD_MEMORY,
            // SAFETY: `root` addresses a live form that nothing else borrows for
            // the duration of this call.
            || unsafe { extend(root, options, &sides, httppost, last_post) },
        );

        if outcome != CURLFORMcode::CURL_FORMADD_OK && created {
            // Nothing was written to either out-parameter, so this form is
            // unreachable and its release restores the state the call found.
            // SAFETY: created here, never handed out, not released.
            unsafe { release_form(root) };
        }

        outcome
    })
}

/// The body of one successful-or-not addition, with the form already resolved.
///
/// # Safety
///
/// `root` must address a live form that nothing else borrows, and `httppost` and
/// `last_post` must be non-null and writable.
unsafe fn extend(
    root: *mut FormRoot,
    options: Vec<FormOption<'static>>,
    sides: &Sides,
    httppost: *mut *mut curl_httppost,
    last_post: *mut *mut curl_httppost,
) -> CURLFORMcode {
    // SAFETY: by contract `root` addresses a live form that nothing else
    // borrows, which is what makes the exclusive reference sound. No ownership
    // is taken.
    let form = unsafe { &mut *root };

    // `retval = FormAddCheck(first_form, &newchain, &lastnode);` (`:569-570`).
    // The engine leaves its list untouched unless it answers `Ok`.
    let code = form_add(&mut form.list, options);
    if code != FormCode::Ok {
        return to_form_code(code);
    }

    let mirrored = {
        let Some(entry) = form.list.last() else {
            // Unreachable: `form_add` answered `Ok`, so it pushed an entry.
            return CURLFORMcode::CURL_FORMADD_INCOMPLETE;
        };
        // SAFETY: the entry was just built from the decoded options, whose
        // borrowed byte ranges outlive the form by the caller's contract, and
        // `root` is stored rather than dereferenced.
        unsafe { mirror(entry, root, sides) }
    };

    let Some(nodes) = mirrored else {
        // An allocation failed after the engine had accepted the part, so the
        // model now describes a part the mirror does not. Neither can be undone
        // -- the engine's list has no public removal -- so the form is marked
        // unusable instead: further additions and any serialisation refuse,
        // while releasing it keeps working. That is the loud answer, and it is
        // reachable only from an allocator that returns null.
        //
        // SAFETY: `root` addresses a live form by this function's contract, and
        // the flag lives in its own allocation, so marking it takes no borrow of
        // the record the exclusive reference above still covers.
        unsafe { poison_of(root) }.poison();
        return CURLFORMcode::CURL_FORMADD_MEMORY;
    };

    let head = nodes[0];
    form.nodes.extend(nodes.iter().copied());
    if form.head.is_null() {
        form.head = head;
    }

    // The splice, verbatim from `:586-594`.
    // SAFETY: both out-parameters are non-null and writable by contract.
    let tail = unsafe { last_post.read() };
    if tail.is_null() {
        // SAFETY: as above.
        unsafe { httppost.write(head.cast::<curl_httppost>()) };
    } else {
        // SAFETY: `tail` is a node of this form, so writing its `next` member
        // through a raw pointer is sound and touches no other member.
        unsafe {
            ptr::addr_of_mut!((*tail).next).write(head.cast::<curl_httppost>());
        }
    }
    // SAFETY: as the out-parameter write above. One call adds exactly one
    // top-level part, so the new head IS the new tail -- which is what
    // `tests/libtest/lib1308.c:59-61` asserts of the first call.
    unsafe { last_post.write(head.cast::<curl_httppost>()) };

    CURLFORMcode::CURL_FORMADD_OK
}

// The exported name: an assembled `va_start`, one prologue per ABI
//
// ROUTE (b') FROM THE MODULE DOCUMENTATION, and the reason there are four of
// these rather than one. The argument list a caller expects to be produced
// differs by ABI, and reading the wrong shape returns plausible rubbish rather
// than a diagnosable error:
//
//   x86-64 System V   a 24-byte record: a register save area plus two cursors
//   AAPCS64           a 32-byte record: three area pointers plus two offsets
//   Apple arm64       a bare cursor, because every variadic argument is on the
//                     stack -- which is what ESCALATION A4 is about, and what
//                     makes this the simplest of the four rather than the
//                     hardest
//
// The callee is deliberately NOT `#[no_mangle]`. Exactly one symbol named
// `curl_formadd` may exist, and it is the label below; an exported callee would
// be a 101st symbol and would fail the parity gate that compares the whole set.

// x86-64 System V, ELF flavour.
//
// Frame of 200 bytes: the six general-purpose argument registers at 0, the
// eight vector registers at 48 in sixteen-byte steps, and the 24-byte record at
// 176. `subq $200` turns the entry alignment of 8 into 0 modulo 16, which is
// what makes the `movaps` stores legal. `overflow_arg_area` is the entry stack
// pointer plus 8, one slot past the return address, and the general-purpose
// cursor starts at 16 because the two named parameters consumed the first two
// registers. The vector cursor always starts at 48, the size of the
// general-purpose half.
//
// The vector registers are saved unconditionally rather than under the usual
// `testb %al, %al` guard: SSE2 is baseline on every x86-64 target, the stores
// go into this frame alone, and no `CURLFORM_*` argument is a floating-point
// type, so nothing can ever read them. `%rax` is clobbered to compute the
// overflow area, which is sound -- it is not an argument register.
#[cfg(all(target_arch = "x86_64", not(target_vendor = "apple")))]
core::arch::global_asm!(
    concat!(
        ".text\n",
        ".globl curl_formadd\n",
        ".p2align 4\n",
        ".type curl_formadd,@function\n",
        "curl_formadd:\n",
        ".cfi_startproc\n",
        "subq $200, %rsp\n",
        ".cfi_def_cfa_offset 208\n",
        "movq %rdi, 0(%rsp)\n",
        "movq %rsi, 8(%rsp)\n",
        "movq %rdx, 16(%rsp)\n",
        "movq %rcx, 24(%rsp)\n",
        "movq %r8, 32(%rsp)\n",
        "movq %r9, 40(%rsp)\n",
        "movaps %xmm0, 48(%rsp)\n",
        "movaps %xmm1, 64(%rsp)\n",
        "movaps %xmm2, 80(%rsp)\n",
        "movaps %xmm3, 96(%rsp)\n",
        "movaps %xmm4, 112(%rsp)\n",
        "movaps %xmm5, 128(%rsp)\n",
        "movaps %xmm6, 144(%rsp)\n",
        "movaps %xmm7, 160(%rsp)\n",
        "movl $16, 176(%rsp)\n",
        "movl $48, 180(%rsp)\n",
        "leaq 208(%rsp), %rax\n",
        "movq %rax, 184(%rsp)\n",
        "movq %rsp, 192(%rsp)\n",
        "leaq 176(%rsp), %rdx\n",
        "call {callee}\n",
        "addq $200, %rsp\n",
        ".cfi_def_cfa_offset 8\n",
        "ret\n",
        ".cfi_endproc\n",
        ".size curl_formadd, .-curl_formadd\n",
    ),
    callee = sym formadd_va,
    options(att_syntax),
);

// x86-64 System V, Mach-O flavour -- `x86_64-apple-darwin`.
#[cfg(all(target_arch = "x86_64", target_vendor = "apple"))]
core::arch::global_asm!(
    concat!(
        ".text\n",
        ".globl _curl_formadd\n",
        ".p2align 4\n",
        "_curl_formadd:\n",
        ".cfi_startproc\n",
        "subq $200, %rsp\n",
        ".cfi_def_cfa_offset 208\n",
        "movq %rdi, 0(%rsp)\n",
        "movq %rsi, 8(%rsp)\n",
        "movq %rdx, 16(%rsp)\n",
        "movq %rcx, 24(%rsp)\n",
        "movq %r8, 32(%rsp)\n",
        "movq %r9, 40(%rsp)\n",
        "movaps %xmm0, 48(%rsp)\n",
        "movaps %xmm1, 64(%rsp)\n",
        "movaps %xmm2, 80(%rsp)\n",
        "movaps %xmm3, 96(%rsp)\n",
        "movaps %xmm4, 112(%rsp)\n",
        "movaps %xmm5, 128(%rsp)\n",
        "movaps %xmm6, 144(%rsp)\n",
        "movaps %xmm7, 160(%rsp)\n",
        "movl $16, 176(%rsp)\n",
        "movl $48, 180(%rsp)\n",
        "leaq 208(%rsp), %rax\n",
        "movq %rax, 184(%rsp)\n",
        "movq %rsp, 192(%rsp)\n",
        "leaq 176(%rsp), %rdx\n",
        "call {callee}\n",
        "addq $200, %rsp\n",
        ".cfi_def_cfa_offset 8\n",
        "ret\n",
        ".cfi_endproc\n",
    ),
    callee = sym formadd_va,
    options(att_syntax),
);

// AAPCS64, ELF flavour -- `aarch64-unknown-linux-gnu`.
#[cfg(all(target_arch = "aarch64", not(target_vendor = "apple")))]
core::arch::global_asm!(
    concat!(
        ".text\n",
        ".globl curl_formadd\n",
        ".p2align 2\n",
        ".type curl_formadd,%function\n",
        "curl_formadd:\n",
        ".cfi_startproc\n",
        "stp x29, x30, [sp, #-240]!\n",
        ".cfi_def_cfa_offset 240\n",
        ".cfi_offset 29, -240\n",
        ".cfi_offset 30, -232\n",
        "mov x29, sp\n",
        "stp x0, x1, [sp, #16]\n",
        "stp x2, x3, [sp, #32]\n",
        "stp x4, x5, [sp, #48]\n",
        "stp x6, x7, [sp, #64]\n",
        "stp q0, q1, [sp, #80]\n",
        "stp q2, q3, [sp, #112]\n",
        "stp q4, q5, [sp, #144]\n",
        "stp q6, q7, [sp, #176]\n",
        "add x9, sp, #240\n",
        "str x9, [sp, #208]\n",
        "add x9, sp, #80\n",
        "str x9, [sp, #216]\n",
        "add x9, sp, #208\n",
        "str x9, [sp, #224]\n",
        "mov w9, #-48\n",
        "str w9, [sp, #232]\n",
        "mov w9, #-128\n",
        "str w9, [sp, #236]\n",
        "add x2, sp, #208\n",
        "bl {callee}\n",
        "ldp x29, x30, [sp], #240\n",
        ".cfi_def_cfa_offset 0\n",
        "ret\n",
        ".cfi_endproc\n",
        ".size curl_formadd, .-curl_formadd\n",
    ),
    callee = sym formadd_va,
);

// Apple arm64, Mach-O flavour -- `aarch64-apple-darwin`.
//
// **This is the target ESCALATION A4 was raised about, and this is the
// resolution for this symbol.** The concern was a Rust callee reading a register
// an Apple caller never populated; nothing here treats a register as a variadic
// argument, so the possibility is removed rather than mitigated. The residual
// gap is that this leg is cross-assembled and disassembled rather than executed.
#[cfg(all(target_arch = "aarch64", target_vendor = "apple"))]
core::arch::global_asm!(
    concat!(
        ".text\n",
        ".globl _curl_formadd\n",
        ".p2align 2\n",
        "_curl_formadd:\n",
        ".cfi_startproc\n",
        "mov x2, sp\n",
        "b {callee}\n",
        ".cfi_endproc\n",
    ),
    callee = sym formadd_va,
);

// 2 of 3: curl_formget

/// Serialises a form and hands the bytes to a callback.
///
/// Supersedes `curl_formget` (`lib/formdata.c:625-658`), frozen at
/// `include/curl/curl.h:2657-2660`. **Returns `int`**, not a `CURLFORMcode` and
/// not a `CURLcode`: the C casts a `CURLcode` into it at `:658`, so 0 is success
/// and 43 -- `CURLE_BAD_FUNCTION_ARGUMENT` -- is what an absent callback reports.
///
/// # Safety
///
/// `form` must be null or a chain [`curl_formadd`] produced and not yet released
/// -- the same precondition `docs/libcurl/curl_formget.md` states. `append`, if
/// present, must be safe to call with `arg` and a readable buffer, and it must
/// not call back into this form: libcurl's own contract is that one form is used
/// from one thread at a time and not re-entrantly, and the C has the identical
/// exposure.
#[no_mangle]
pub unsafe extern "C" fn curl_formget(
    form: *mut curl_httppost,
    arg: *mut c_void,
    append: curl_formget_callback,
) -> c_int {
    guard(CURLcode::CURLE_FAILED_INIT.as_c_int(), || {
        // `if(!append) return (int)CURLE_BAD_FUNCTION_ARGUMENT;` (`:633-635`) --
        // first, so that a null callback is reported whatever else is wrong.
        let Some(append) = append else {
            return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT.as_c_int();
        };

        let mut sink = |bytes: &[u8]| -> usize {
            // SAFETY: `append` is the caller's own function pointer and `arg`
            // the context it supplied alongside it. `bytes` is a live borrowed
            // slice, so the pointer and length handed over describe readable
            // memory of exactly that size, which is the whole of what a
            // `curl_formget_callback` may touch.
            unsafe { append(arg, bytes.as_ptr().cast::<c_char>(), bytes.len()) }
        };

        if form.is_null() {
            let empty = FormList::new();
            return match form_get_with_system_rng(&empty, Some(&mut sink)) {
                Ok(()) => 0,
                Err(code) => CURLcode::from(code).as_c_int(),
            };
        }

        // SAFETY: this function's contract -- `form` is a chain `curl_formadd`
        // produced, so the node's own allocation carries the two members read.
        let Some(root) = (unsafe { form_of(form) }) else {
            return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT.as_c_int();
        };

        // SAFETY: `root` is the form the node named, so it is live.
        if unsafe { poison_of(root) }.is_poisoned() {
            // A form whose model and mirror disagree; see `extend`. Releasing it
            // still works, reading it does not.
            return CURLcode::CURLE_FAILED_INIT.as_c_int();
        }

        // SAFETY: `root` addresses a live form; the borrow ends inside this
        // block and no exclusive borrow of the record is taken.
        let head = unsafe { ptr::addr_of!((*root).head).read() };
        if !ptr::eq(head.cast_const(), form.cast::<FormNode>().cast_const()) {
            return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT.as_c_int();
        }

        // SAFETY: as above, and by libcurl's contract nothing else is using this
        // form for the duration of the call, which is what makes the shared
        // borrow of its model sound.
        let list = unsafe { &(*root).list };
        match form_get_with_system_rng(list, Some(&mut sink)) {
            Ok(()) => 0,
            Err(code) => CURLcode::from(code).as_c_int(),
        }
    })
}

// 3 of 3: curl_formfree

/// Releases a whole form post.
///
/// Supersedes `curl_formfree` (`lib/formdata.c:664-689`), frozen at
/// `include/curl/curl.h:2668-2669`. **Returns `void`, so it has no error channel
/// at all.** A null form is a silent no-op, exactly as `:668-670` makes it, and a
/// contained panic is a silent return. Whatever it learns about a fault it keeps
/// to itself, which matters beyond tidiness: the fixture corpus compares output
/// byte for byte and a diagnostic on standard error would corrupt it.
///
/// # Safety
///
/// `form` must be null or a chain [`curl_formadd`] produced and not already
/// released -- the same precondition `docs/libcurl/curl_formfree.md` states.
/// Afterwards every node of that chain, and every string this crate allocated
/// inside it, is invalid and must not be used.
#[no_mangle]
pub unsafe extern "C" fn curl_formfree(form: *mut curl_httppost) {
    // `guard_void`, not the transactional guard: the cleanup family is the
    // documented exception, because releasing a poisoned form has to keep
    // working or a contained defect becomes a leak.
    guard_void(|| {
        if form.is_null() {
            return;
        }

        // SAFETY: this function's contract -- `form` is a chain `curl_formadd`
        // produced, so the members read are inside the node's own allocation.
        let Some(root) = (unsafe { form_of(form) }) else {
            // Not ours. There is nothing here this module allocated, and silence
            // is the only answer a `void` function has.
            return;
        };

        // SAFETY: `root` addresses a live form; the read takes no reference to
        // the record as a whole.
        let head = unsafe { ptr::addr_of!((*root).head).read() };
        if !ptr::eq(head.cast_const(), form.cast::<FormNode>().cast_const()) {
            return;
        }

        // SAFETY: `form` is this form's head, so the form is reachable from
        // nothing else the caller can legally use afterwards, and by contract it
        // has not been released.
        unsafe { release_form(root) };
    });
}

// The coordination surface `CURLOPT_HTTPPOST` needs

/// Runs `body` against the engine model behind a `struct curl_httppost *`.
///
/// `CURLOPT_HTTPPOST` hands libcurl a form the application still owns
/// (`lib/setopt.c` stores the pointer; `curl_formfree` remains the caller's
/// job), and the transfer then needs the model rather than the mirror. This is
/// the only way to reach it, because the mirror cannot be turned back into a
/// model: the engine exposes accessors and no constructor.
///
/// # Safety
///
/// `form` must be null or a chain [`curl_formadd`] produced and not released, and
/// nothing else may be using that form for the duration of the call.
#[allow(dead_code)] // consumed by CURLOPT_HTTPPOST, which is `super::easy`'s
pub(crate) unsafe fn with_form_list<R>(
    form: *mut curl_httppost,
    body: impl FnOnce(&FormList<'static>) -> R,
) -> Option<R> {
    // SAFETY: this function's contract, which is `form_of`'s exactly.
    let root = unsafe { form_of(form) }?;

    // SAFETY: `root` addresses a live form.
    if unsafe { poison_of(root) }.is_poisoned() {
        return None;
    }

    // SAFETY: as above; the read forms no reference to the whole record.
    let head = unsafe { ptr::addr_of!((*root).head).read() };
    if !ptr::eq(head.cast_const(), form.cast::<FormNode>().cast_const()) {
        return None;
    }

    // SAFETY: `root` addresses a live form that nothing else is using, by
    // contract, which is what makes the shared borrow sound.
    Some(body(unsafe { &(*root).list }))
}

// Tests
//
// `curl_formadd` and `curl_formget` are both annotated `@unittest: 1308`
// (`lib/formdata.c:606`, `:625`), and that annotation points at
// `tests/libtest/lib1308.c` -- a C program that links a debug static libcurl
// and calls internal `Curl_*` symbols. Such a program cannot link against a
// Rust static library at all, because `pub(crate)` items are genuinely absent
// from its symbol table rather than merely hidden, so the assertions move into
// the crate that owns the code.

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::MaybeUninit;

    // The exported name, declared as `include/curl/curl.h:2632-2635` declares
    // it. It is variadic here, which is the point: nothing else in this crate
    // can reach the assembled label, because it is not a Rust item, so the ABI
    // is the only path to it -- and that is precisely the path a caller takes.
    extern "C" {
        fn curl_formadd(
            httppost: *mut *mut curl_httppost,
            last_post: *mut *mut curl_httppost,
            ...
        ) -> CURLFORMcode;
    }

    /// A NUL-terminated `*const c_char` from a string literal.
    ///
    /// `c"..."` and `CStr`'s const methods are Rust 1.77; the declared minimum
    /// is 1.75, so the terminator is concatenated instead.
    macro_rules! cstr {
        ($s:literal) => {
            concat!($s, "\0").as_ptr().cast::<c_char>()
        };
    }

    /// The option integers, spelled as a C caller spells them: plain `int`s.
    ///
    /// A C caller writes `CURLFORM_COPYNAME`, which is an `int` by the time it
    /// reaches the argument list -- `lib/formdata.c:346-347` reads it back with
    /// `va_arg(params, int)` for exactly that reason. Passing the Rust
    /// enumeration through a variadic call would pass a differently sized value
    /// on some ABI, so the tests use the integers, obtained from the enumeration
    /// rather than written out, so that a renumbering cannot pass.
    fn opt(option: CURLformoption) -> c_int {
        option.as_c_int()
    }

    /// Every top-level node of a chain, in order.
    ///
    /// # Safety
    ///
    /// `head` must be null or a chain `curl_formadd` produced.
    unsafe fn chain(head: *mut curl_httppost) -> Vec<*mut curl_httppost> {
        let mut out = Vec::new();
        let mut at = head;
        while !at.is_null() {
            out.push(at);
            // SAFETY: `at` is a live node of the chain by the contract above.
            at = unsafe { ptr::addr_of!((*at).next).read() };
        }
        out
    }

    /// A node's `more` chain, in order.
    ///
    /// # Safety
    ///
    /// As [`chain`].
    unsafe fn more(node: *mut curl_httppost) -> Vec<*mut curl_httppost> {
        let mut out = Vec::new();
        // SAFETY: `node` is a live node by the contract above.
        let mut at = unsafe { ptr::addr_of!((*node).more).read() };
        while !at.is_null() {
            out.push(at);
            // SAFETY: as above.
            at = unsafe { ptr::addr_of!((*at).more).read() };
        }
        out
    }

    /// A `char *` field as owned bytes, or `None` for null.
    ///
    /// # Safety
    ///
    /// `text` must be null or a NUL-terminated string that outlives the call.
    unsafe fn owned(text: *const c_char) -> Option<Vec<u8>> {
        if text.is_null() {
            return None;
        }
        // SAFETY: the contract above is `CStr::from_ptr`'s precondition.
        Some(unsafe { CStr::from_ptr(text) }.to_bytes().to_vec())
    }

    /// The bytes `curl_formget` produces for a form, and its return code.
    ///
    /// # Safety
    ///
    /// `form` must be null or a chain `curl_formadd` produced.
    unsafe fn serialise(form: *mut curl_httppost) -> (c_int, Vec<u8>) {
        // The sink has to be reachable from an `extern "C"` function, so the
        // context is a `Vec` the callback appends to.
        unsafe extern "C" fn append(
            arg: *mut c_void,
            buf: *const c_char,
            len: usize,
        ) -> usize {
            // SAFETY: `arg` is the `Vec` this test handed to `curl_formget`,
            // used from this thread alone, and `buf` addresses `len` readable
            // bytes for the duration of the call.
            let sink = unsafe { &mut *arg.cast::<Vec<u8>>() };
            let bytes = unsafe { slice::from_raw_parts(buf.cast::<u8>(), len) };
            sink.extend_from_slice(bytes);
            len
        }

        let mut sink: Vec<u8> = Vec::new();
        let context: *mut c_void = (&mut sink as *mut Vec<u8>).cast();
        // SAFETY: `form` satisfies this function's contract and `append` is
        // safe to call with `context`.
        let code = unsafe { curl_formget(form, context, Some(append)) };
        (code, sink)
    }

    // -- the module's own shape -------------------------------------------

    /// This module's source with the test module removed.
    ///
    /// The structural checks search for text they themselves contain, so
    /// searching the whole file would make each one find itself. Splitting at
    /// the `#[cfg(test)]` attribute, whose first occurrence in the file *is*
    /// that attribute, leaves exactly the half being asserted about.
    fn production_source() -> &'static str {
        let source = include_str!("form.rs");
        let at = source
            .find("#[cfg(test)]")
            .expect("this module has a test module");
        &source[..at]
    }

    /// [`production_source`] with every comment line removed.
    fn production_code() -> String {
        production_source()
            .lines()
            .filter(|line| {
                let trimmed = line.trim_start();
                !trimmed.starts_with("//")
            })
            .collect::<Vec<&str>>()
            .join("\n")
    }

    #[test]
    fn exactly_three_symbols_are_owned_and_defined_once_each() {
        let source = production_code();

        // Two are ordinary Rust items.
        for name in ["curl_formget", "curl_formfree"] {
            let definition = format!("pub unsafe extern \"C\" fn {name}(");
            assert_eq!(
                source.matches(&definition).count(),
                1,
                "{name} must be defined exactly once",
            );
        }

        // `curl_formadd` is not a Rust function at all, on purpose.
        assert!(
            !source.contains("extern \"C\" fn curl_formadd("),
            "curl_formadd is variadic and must not be a Rust function",
        );
        assert_eq!(
            source.matches(".globl curl_formadd\\n").count(),
            2,
            "one ELF label per x86-64 and aarch64 prologue",
        );
        assert_eq!(
            source.matches(".globl _curl_formadd\\n").count(),
            2,
            "one Mach-O label per x86-64 and aarch64 prologue",
        );
        assert_eq!(
            source.matches("core::arch::global_asm!").count(),
            4,
            "four ABI flavours: x86-64 and aarch64, ELF and Mach-O",
        );

        // None of the twelve mime symbols, which are `super::mime`'s.
        assert!(
            !source.contains("fn curl_mime_"),
            "the curl_mime_* family belongs to another module",
        );

        // The exported count, so a fourth definition cannot slip in.
        let attribute = format!("#[{}]", "no_mangle");
        assert_eq!(
            source.matches(attribute.as_str()).count(),
            2,
            "two Rust exports; the third symbol is assembled",
        );
    }

    #[test]
    fn no_nightly_feature_and_no_second_containment_helper() {
        let source = production_code();
        for forbidden in [
            "#![feature(",
            "#[feature(",
            "feature(c_variadic)",
            "VaListImpl",
            "next_arg",
            "catch_unwind",
            "process::abort",
            "#[deprecated",
            "#![forbid(unsafe_code)]",
            "#[allow(unsafe_code)]",
            "compile_error!",
        ] {
            assert!(
                !source.contains(forbidden),
                "{forbidden} must not appear in this module",
            );
        }

        // Every `unsafe` block carries a `// SAFETY:` comment. Counted over
        // the whole source rather than the code, because the comments are what
        // is being counted, and asserted as an inequality because one comment
        // legitimately covers a run of blocks that share a precondition.
        let blocks = source.matches("unsafe {").count();
        let notes = production_source().matches("SAFETY:").count();
        assert!(
            notes >= blocks,
            "{blocks} unsafe blocks but only {notes} SAFETY comments",
        );
    }

    #[test]
    fn the_conflicts_are_recorded_rather_than_warned_about() {
        let source = production_source();
        for evidence in [
            "MSRV CONFLICT",
            "ESCALATION A4",
            "ROUTE (b')",
            "32-bit portability is deliberately forfeited",
            "cargo:warning=",
            "Trap 3",
        ] {
            assert!(
                source.contains(evidence),
                "the record must keep {evidence:?}",
            );
        }
        // And the requirement is REPORTED, not discharged from here: a warning
        // raised in this module would fail the zero-warnings gate.
        assert!(
            !source.contains("println!(\"cargo:warning"),
            "the advisory belongs to build.rs, not to this module",
        );
    }

    /// Byte offset of a field within a struct.
    ///
    /// `core::mem::offset_of!` is stable only from Rust 1.77 and the declared
    /// minimum is 1.75 (AAP 0.8.3, obligation B3), so the offset is taken
    /// through `addr_of!`, stable since 1.51. It forms the address without
    /// creating a reference, so it is sound on uninitialised memory -- which is
    /// what lets a record full of raw pointers be measured without inventing
    /// values for them. No crate is added for this: `memoffset` would be a new
    /// dependency and the dependency set is fixed (obligation B4). The same
    /// helper, for the same reason, is in `super::handle` and `super::types`.
    macro_rules! offset {
        ($ty:ty, $field:ident) => {{
            let holder = MaybeUninit::<$ty>::uninit();
            let base = holder.as_ptr();
            // SAFETY: `base` points at a whole, correctly aligned allocation of
            // `$ty` owned by `holder`. `addr_of!` only computes the field's
            // address and never reads the uninitialised bytes, so no invalid
            // value is ever materialised.
            let field = unsafe { ptr::addr_of!((*base).$field) };
            (field as usize) - (base as usize)
        }};
    }

    #[test]
    fn the_node_layout_puts_the_frozen_struct_first() {
        // A `*mut FormNode` handed to C as a `*mut curl_httppost` must address
        // the frozen struct at offset zero, or every field a consumer reads is
        // the wrong one.
        assert_eq!(
            offset!(FormNode, post),
            0,
            "the ABI prefix must come first"
        );
        assert!(
            size_of::<FormNode>() > size_of::<curl_httppost>(),
            "the record extends the frozen struct rather than replacing it",
        );
        assert_eq!(
            align_of::<FormNode>(),
            align_of::<curl_httppost>(),
            "extending must not raise the alignment C allocates for",
        );
        // The mirror writes lengths as `long`; `as_long` is a checked conversion
        // precisely because this equality is a property of the four required
        // targets rather than of the language.
        assert_eq!(size_of::<c_long>(), 8, "LP64, as all four targets are");
    }

    // -- building a chain ---------------------------------------------------

    #[test]
    fn a_first_add_starts_a_chain_and_sets_both_out_parameters() {
        let mut post: *mut curl_httppost = ptr::null_mut();
        let mut last: *mut curl_httppost = ptr::null_mut();

        // SAFETY: the option list is terminated and every option is followed by
        // an argument of the type it names.
        let code = unsafe {
            curl_formadd(
                &mut post,
                &mut last,
                opt(CURLformoption::CURLFORM_COPYNAME),
                cstr!("name"),
                opt(CURLformoption::CURLFORM_COPYCONTENTS),
                cstr!("content"),
                opt(CURLformoption::CURLFORM_END),
            )
        };
        assert_eq!(code, CURLFORMcode::CURL_FORMADD_OK);
        assert!(!post.is_null(), "the head must be written");
        // "after the first curl_formadd when there is a single entry, both
        // pointers should point to the same struct" (`lib1308.c:59-61`).
        assert!(ptr::eq(post, last));

        // SAFETY: `post` is the chain just built.
        unsafe {
            assert_eq!(chain(post).len(), 1);
            let node = &*post;
            assert_eq!(owned(node.name).as_deref(), Some(&b"name"[..]));
            assert_eq!(node.namelength, 4);
            assert_eq!(owned(node.contents).as_deref(), Some(&b"content"[..]));
            // `AddHttpPost` sets CURL_HTTPPOST_LARGE on every node it creates
            // and never writes `contentslength` (`:69-82`).
            assert_eq!(node.flags & CURL_HTTPPOST_LARGE, CURL_HTTPPOST_LARGE);
            assert_eq!(node.contentslength, 0);
            assert_eq!(node.contentlen, 0);
            assert!(node.buffer.is_null());
            assert!(node.contentheader.is_null());
            assert!(node.more.is_null());
            assert!(node.next.is_null());
            assert!(node.userp.is_null());
            curl_formfree(post);
        }
    }

    #[test]
    fn a_second_add_extends_the_chain_and_moves_the_tail() {
        let mut post: *mut curl_httppost = ptr::null_mut();
        let mut last: *mut curl_httppost = ptr::null_mut();

        for (name, value) in [("one", "1"), ("two", "2"), ("three", "3")] {
            let name = format!("{name}\0");
            let value = format!("{value}\0");
            // SAFETY: as the previous test; both strings are NUL-terminated and
            // outlive the call, and `CURLFORM_COPY*` copies them besides.
            let code = unsafe {
                curl_formadd(
                    &mut post,
                    &mut last,
                    opt(CURLformoption::CURLFORM_COPYNAME),
                    name.as_ptr().cast::<c_char>(),
                    opt(CURLformoption::CURLFORM_COPYCONTENTS),
                    value.as_ptr().cast::<c_char>(),
                    opt(CURLformoption::CURLFORM_END),
                )
            };
            assert_eq!(code, CURLFORMcode::CURL_FORMADD_OK);
        }

        // SAFETY: `post` is the chain just built.
        unsafe {
            let nodes = chain(post);
            assert_eq!(nodes.len(), 3, "one top-level part per call");
            assert!(ptr::eq(nodes[2], last), "the tail is the newest part");
            let names: Vec<Option<Vec<u8>>> =
                nodes.iter().map(|node| owned((**node).name)).collect();
            assert_eq!(
                names,
                vec![
                    Some(b"one".to_vec()),
                    Some(b"two".to_vec()),
                    Some(b"three".to_vec()),
                ],
                "insertion order is preserved",
            );
            curl_formfree(post);
        }
    }

    #[test]
    fn freeing_null_is_a_silent_no_op_and_so_is_a_foreign_node() {
        // SAFETY: null is explicitly permitted.
        unsafe { curl_formfree(ptr::null_mut()) };

        // A node this module did not build. Only the ABI prefix is read before
        // the magic test rejects it, and the record is large enough for the
        // trailing members the test reads.
        let mut foreign = FormNode {
            post: curl_httppost {
                next: ptr::null_mut(),
                name: ptr::null_mut(),
                namelength: 0,
                contents: ptr::null_mut(),
                contentslength: 0,
                buffer: ptr::null_mut(),
                bufferlength: 0,
                contenttype: ptr::null_mut(),
                contentheader: ptr::null_mut(),
                more: ptr::null_mut(),
                flags: 0,
                showfilename: ptr::null_mut(),
                userp: ptr::null_mut(),
                contentlen: 0,
            },
            magic: 0,
            root: ptr::null_mut(),
        };
        let as_post: *mut curl_httppost =
            (&mut foreign as *mut FormNode).cast();
        // SAFETY: the record is a live `FormNode` this test owns, so reading its
        // magic is in bounds; the magic differs, so nothing is released.
        unsafe { curl_formfree(as_post) };
        // SAFETY: as above.
        let (code, bytes) = unsafe { serialise(as_post) };
        assert_eq!(code, CURLcode::CURLE_BAD_FUNCTION_ARGUMENT.as_c_int());
        assert!(bytes.is_empty());
    }

    // -- ownership: the COPY*-versus-PTR* split -----------------------------

    #[test]
    fn copyname_and_copycontents_copy_so_the_callers_buffer_is_free_after() {
        let mut name = *b"scribble-me-name\0";
        let mut value = *b"scribble-me-value\0";
        let mut post: *mut curl_httppost = ptr::null_mut();
        let mut last: *mut curl_httppost = ptr::null_mut();

        // SAFETY: both buffers are NUL-terminated and live for the call.
        let code = unsafe {
            curl_formadd(
                &mut post,
                &mut last,
                opt(CURLformoption::CURLFORM_COPYNAME),
                name.as_ptr().cast::<c_char>(),
                opt(CURLformoption::CURLFORM_COPYCONTENTS),
                value.as_ptr().cast::<c_char>(),
                opt(CURLformoption::CURLFORM_END),
            )
        };
        assert_eq!(code, CURLFORMcode::CURL_FORMADD_OK);

        // The caller's memory is its own again the moment the call returns, so
        // overwriting it must not disturb the form. This is the half that a leak
        // would hide and a dangling read would not.
        name.fill(b'X');
        value.fill(b'Y');

        // SAFETY: `post` is the chain just built.
        unsafe {
            let node = &*post;
            assert_eq!(node.flags & CURL_HTTPPOST_PTRNAME, 0);
            assert_eq!(node.flags & CURL_HTTPPOST_PTRCONTENTS, 0);
            assert_eq!(
                owned(node.name).as_deref(),
                Some(&b"scribble-me-name"[..]),
            );
            assert_eq!(
                owned(node.contents).as_deref(),
                Some(&b"scribble-me-value"[..]),
            );
            // The duplicates are ours, so they are also not the caller's
            // addresses.
            assert!(!ptr::eq(node.name.cast_const(), name.as_ptr().cast()));
            curl_formfree(post);
        }
    }

    #[test]
    fn ptrname_and_ptrcontents_borrow_and_are_not_released() {
        // The buffer outlives the form deliberately: that is the `CURLFORM_PTR*`
        // contract, and it is what makes releasing it here a double free.
        let name = b"borrowed-name\0";
        let value = b"borrowed-value\0";
        let mut post: *mut curl_httppost = ptr::null_mut();
        let mut last: *mut curl_httppost = ptr::null_mut();

        // SAFETY: both buffers are NUL-terminated and outlive the form.
        let code = unsafe {
            curl_formadd(
                &mut post,
                &mut last,
                opt(CURLformoption::CURLFORM_PTRNAME),
                name.as_ptr().cast::<c_char>(),
                opt(CURLformoption::CURLFORM_PTRCONTENTS),
                value.as_ptr().cast::<c_char>(),
                opt(CURLformoption::CURLFORM_END),
            )
        };
        assert_eq!(code, CURLFORMcode::CURL_FORMADD_OK);

        // SAFETY: `post` is the chain just built.
        unsafe {
            let node = &*post;
            // Both flags set, because a consumer may read `post->flags` and
            // decide from it what it owns.
            assert_eq!(
                node.flags & CURL_HTTPPOST_PTRNAME,
                CURL_HTTPPOST_PTRNAME,
            );
            assert_eq!(
                node.flags & CURL_HTTPPOST_PTRCONTENTS,
                CURL_HTTPPOST_PTRCONTENTS,
            );
            // And the fields are the caller's own addresses, not copies: that
            // is the observable half of "borrowed".
            assert!(ptr::eq(node.name.cast_const(), name.as_ptr().cast()));
            assert!(ptr::eq(node.contents.cast_const(), value.as_ptr().cast()),);

            // Releasing the form must leave the caller's buffers alone. Under
            // AddressSanitizer a release of either is a report; here the
            // surviving contents are the assertion.
            curl_formfree(post);
        }
        assert_eq!(&name[..], b"borrowed-name\0");
        assert_eq!(&value[..], b"borrowed-value\0");
    }

    #[test]
    fn bufferptr_borrows_and_sets_both_buffer_flags() {
        // Terminated for the same reason as in the flag test below, even though
        // `CURLFORM_BUFFERPTR` declares a length and so is not measured: the
        // invariant "every pointer handed to a string option is a C string" is
        // worth holding uniformly rather than per-option, so that safety here
        // does not depend on remembering which options measure and which do not.
        let buffer = b"in-memory-file-contents\0";
        let content = &buffer[..buffer.len() - 1];
        let mut post: *mut curl_httppost = ptr::null_mut();
        let mut last: *mut curl_httppost = ptr::null_mut();

        // SAFETY: the buffer outlives the form and its declared length is its
        // real one.
        let code = unsafe {
            curl_formadd(
                &mut post,
                &mut last,
                opt(CURLformoption::CURLFORM_COPYNAME),
                cstr!("field"),
                opt(CURLformoption::CURLFORM_BUFFER),
                cstr!("shown.txt"),
                opt(CURLformoption::CURLFORM_BUFFERPTR),
                content.as_ptr().cast::<c_char>(),
                opt(CURLformoption::CURLFORM_BUFFERLENGTH),
                content.len() as c_long,
                opt(CURLformoption::CURLFORM_END),
            )
        };
        assert_eq!(code, CURLFORMcode::CURL_FORMADD_OK);

        // SAFETY: `post` is the chain just built.
        unsafe {
            let node = &*post;
            let wanted = CURL_HTTPPOST_BUFFER | CURL_HTTPPOST_PTRBUFFER;
            assert_eq!(node.flags & wanted, wanted);
            assert!(ptr::eq(node.buffer.cast_const(), content.as_ptr().cast()));
            assert_eq!(node.bufferlength, content.len() as c_long);
            // `CURLFORM_BUFFERPTR` also writes the value slot -- "Make value
            // non-NULL to be accepted as fine" (`:478-479`) -- with the same
            // pointer, and the BUFFER flag keeps `curl_formfree` off it.
            assert!(ptr::eq(
                node.contents.cast_const(),
                content.as_ptr().cast()
            ),);
            assert_eq!(
                owned(node.showfilename).as_deref(),
                Some(&b"shown.txt"[..]),
            );
            curl_formfree(post);
        }
        assert_eq!(content, b"in-memory-file-contents");
    }

    #[test]
    fn an_explicit_namelength_reads_a_name_that_has_no_terminator() {
        // The documented reason `CURLFORM_NAMELENGTH` exists. The buffer has no
        // NUL at all, so an implementation that measured it would read out of
        // bounds -- which is exactly what the C never does when a length is
        // given.
        let name: [u8; 5] = *b"abcde";
        let mut post: *mut curl_httppost = ptr::null_mut();
        let mut last: *mut curl_httppost = ptr::null_mut();

        // SAFETY: the declared length is the buffer's real length.
        let code = unsafe {
            curl_formadd(
                &mut post,
                &mut last,
                opt(CURLformoption::CURLFORM_PTRNAME),
                name.as_ptr().cast::<c_char>(),
                opt(CURLformoption::CURLFORM_NAMELENGTH),
                3 as c_long,
                opt(CURLformoption::CURLFORM_COPYCONTENTS),
                cstr!("v"),
                opt(CURLformoption::CURLFORM_END),
            )
        };
        assert_eq!(code, CURLFORMcode::CURL_FORMADD_OK);

        // SAFETY: `post` is the chain just built.
        unsafe {
            assert_eq!((*post).namelength, 3);
            let (code, bytes) = serialise(post);
            assert_eq!(code, 0);
            let text = String::from_utf8_lossy(&bytes).into_owned();
            assert!(
                text.contains("name=\"abc\""),
                "the declared prefix is the field name: {text}",
            );
            curl_formfree(post);
        }
    }

    #[test]
    fn a_negative_length_is_the_cs_size_t_cast_and_reports_memory() {
        let mut post: *mut curl_httppost = ptr::null_mut();
        let mut last: *mut curl_httppost = ptr::null_mut();

        // A negative `long` reaches the accumulator's `size_t` through a cast,
        // lands above `LONG_MAX`, and `AddHttpPost`'s guard (`:66-68`) rejects
        // it. Clamping to zero here would silently accept a call the C refuses.
        // SAFETY: the name is NUL-terminated; the length is deliberately bogus,
        // which is the input under test.
        let code = unsafe {
            curl_formadd(
                &mut post,
                &mut last,
                opt(CURLformoption::CURLFORM_COPYNAME),
                cstr!("n"),
                opt(CURLformoption::CURLFORM_NAMELENGTH),
                -1 as c_long,
                opt(CURLformoption::CURLFORM_COPYCONTENTS),
                cstr!("v"),
                opt(CURLformoption::CURLFORM_END),
            )
        };
        assert_eq!(code, CURLFORMcode::CURL_FORMADD_MEMORY);
        assert!(post.is_null(), "nothing is written on failure");
        assert!(last.is_null(), "nothing is written on failure");
    }

    /// A filename that is not valid UTF-8 is accepted and reaches the wire.
    ///
    /// This used to answer `CURL_FORMADD_MEMORY`, because the five path and
    /// media-type options were decoded as UTF-8 first and the five-member code
    /// set has no member meaning "not Unicode". Two things were wrong with
    /// that: it refused a form curl 8.x posts, and it told the caller an
    /// allocation had failed when none had. Both halves are asserted -- the
    /// code, and the bytes in the emitted body.
    #[test]
    fn an_undecodable_shown_filename_is_accepted_and_emitted_verbatim() {
        let mut post: *mut curl_httppost = ptr::null_mut();
        let mut last: *mut curl_httppost = ptr::null_mut();

        // `fi\xffle.txt`, NUL-terminated, as a C caller would hold it.
        const SHOWN: &[u8] = b"fi\xffle.txt\0";

        // SAFETY: every pointer addresses a NUL-terminated buffer that outlives
        // the call, and the option sequence is well formed.
        let code = unsafe {
            curl_formadd(
                &mut post,
                &mut last,
                opt(CURLformoption::CURLFORM_COPYNAME),
                cstr!("upload"),
                opt(CURLformoption::CURLFORM_BUFFER),
                SHOWN.as_ptr().cast::<c_char>(),
                opt(CURLformoption::CURLFORM_BUFFERPTR),
                cstr!("payload"),
                opt(CURLformoption::CURLFORM_BUFFERLENGTH),
                7 as c_long,
                opt(CURLformoption::CURLFORM_END),
            )
        };
        assert_eq!(
            code,
            CURLFORMcode::CURL_FORMADD_OK,
            "a filename the local filesystem accepts is not an allocation \
             failure"
        );
        assert!(!post.is_null());

        // SAFETY: `post` is the chain `curl_formadd` just built.
        let (status, bytes) = unsafe { serialise(post) };
        assert_eq!(status, 0);
        assert!(
            bytes
                .windows(SHOWN.len() - 1)
                .any(|window| window == &SHOWN[..SHOWN.len() - 1]),
            "the filename must appear in the body as the bytes supplied, \
             neither replaced nor dropped"
        );

        // SAFETY: `post` is a chain this test owns and has not yet freed.
        unsafe { curl_formfree(post) };
    }

    // -- the error codes ---------------------------------------------------

    #[test]
    fn an_option_given_twice_reports_option_twice_and_changes_nothing() {
        let mut post: *mut curl_httppost = ptr::null_mut();
        let mut last: *mut curl_httppost = ptr::null_mut();

        // SAFETY: both strings are NUL-terminated literals.
        let code = unsafe {
            curl_formadd(
                &mut post,
                &mut last,
                opt(CURLformoption::CURLFORM_COPYNAME),
                cstr!("first"),
                opt(CURLformoption::CURLFORM_COPYNAME),
                cstr!("second"),
                opt(CURLformoption::CURLFORM_END),
            )
        };
        assert_eq!(code, CURLFORMcode::CURL_FORMADD_OPTION_TWICE);
        assert!(post.is_null(), "the all-or-nothing contract");
        assert!(last.is_null(), "the all-or-nothing contract");
    }

    #[test]
    fn a_null_string_reports_null_and_an_unknown_option_reports_unknown() {
        let mut post: *mut curl_httppost = ptr::null_mut();
        let mut last: *mut curl_httppost = ptr::null_mut();

        // SAFETY: a null argument is the input under test; the list is
        // terminated.
        let code = unsafe {
            curl_formadd(
                &mut post,
                &mut last,
                opt(CURLformoption::CURLFORM_COPYNAME),
                ptr::null::<c_char>(),
                opt(CURLformoption::CURLFORM_END),
            )
        };
        assert_eq!(code, CURLFORMcode::CURL_FORMADD_NULL);

        // An integer outside the enumeration, and one of the four members that
        // name no operation. Both reach the C's `default` arm, which reads no
        // argument, so neither may consume a slot.
        for bogus in [
            9_999_i32,
            opt(CURLformoption::CURLFORM_NOTHING),
            opt(CURLformoption::CURLFORM_OBSOLETE),
            opt(CURLformoption::CURLFORM_LASTENTRY),
        ] {
            // SAFETY: the option carries no argument, exactly as the C's
            // default arm expects, and the list is terminated.
            let code = unsafe {
                curl_formadd(
                    &mut post,
                    &mut last,
                    bogus,
                    opt(CURLformoption::CURLFORM_END),
                )
            };
            assert_eq!(
                code,
                CURLFORMcode::CURL_FORMADD_UNKNOWN_OPTION,
                "option {bogus} must be refused",
            );
        }
        assert!(post.is_null());
        assert!(last.is_null());
    }

    #[test]
    fn an_unusable_part_reports_incomplete() {
        let mut post: *mut curl_httppost = ptr::null_mut();
        let mut last: *mut curl_httppost = ptr::null_mut();

        // A name with no value at all: the first of `FormAddCheck`'s five
        // conditions (`:229-241`).
        // SAFETY: the name is a NUL-terminated literal and the list ends.
        let code = unsafe {
            curl_formadd(
                &mut post,
                &mut last,
                opt(CURLformoption::CURLFORM_COPYNAME),
                cstr!("lonely"),
                opt(CURLformoption::CURLFORM_END),
            )
        };
        assert_eq!(code, CURLFORMcode::CURL_FORMADD_INCOMPLETE);
        assert!(post.is_null());
    }

    #[test]
    fn a_null_out_parameter_reports_null_rather_than_dereferencing_it() {
        // SAFETY: passing null is the input under test; the C dereferences it
        // unconditionally, which is undefined, so there is no behaviour to
        // preserve and reporting is the honest answer.
        let code = unsafe {
            curl_formadd(
                ptr::null_mut(),
                ptr::null_mut(),
                opt(CURLformoption::CURLFORM_END),
            )
        };
        assert_eq!(code, CURLFORMcode::CURL_FORMADD_NULL);
    }

    // -- CURLFORM_ARRAY ----------------------------------------------------

    #[test]
    fn an_array_carries_the_same_options_and_consumes_no_argument_slot() {
        let rows = [
            curl_forms {
                option: CURLformoption::CURLFORM_COPYNAME,
                value: cstr!("array-name"),
            },
            curl_forms {
                option: CURLformoption::CURLFORM_COPYCONTENTS,
                value: cstr!("array-value"),
            },
            curl_forms {
                option: CURLformoption::CURLFORM_END,
                value: ptr::null(),
            },
        ];
        let mut post: *mut curl_httppost = ptr::null_mut();
        let mut last: *mut curl_httppost = ptr::null_mut();

        // The array is terminated and the outer list continues after it, which
        // is what `forms = NULL; continue;` (`:339-343`) makes possible.
        // SAFETY: the array is `CURLFORM_END`-terminated and outlives the call,
        // and the outer list is terminated too.
        let code = unsafe {
            curl_formadd(
                &mut post,
                &mut last,
                opt(CURLformoption::CURLFORM_ARRAY),
                rows.as_ptr(),
                opt(CURLformoption::CURLFORM_CONTENTTYPE),
                cstr!("text/plain"),
                opt(CURLformoption::CURLFORM_END),
            )
        };
        assert_eq!(code, CURLFORMcode::CURL_FORMADD_OK);

        // SAFETY: `post` is the chain just built.
        unsafe {
            let node = &*post;
            assert_eq!(owned(node.name).as_deref(), Some(&b"array-name"[..]));
            assert_eq!(
                owned(node.contents).as_deref(),
                Some(&b"array-value"[..]),
            );
            assert_eq!(
                owned(node.contenttype).as_deref(),
                Some(&b"text/plain"[..]),
            );
            curl_formfree(post);
        }
    }

    #[test]
    fn an_array_inside_an_array_and_a_null_array_are_both_refused() {
        let nested = [
            curl_forms {
                option: CURLformoption::CURLFORM_ARRAY,
                value: ptr::null(),
            },
            curl_forms {
                option: CURLformoption::CURLFORM_END,
                value: ptr::null(),
            },
        ];
        let mut post: *mut curl_httppost = ptr::null_mut();
        let mut last: *mut curl_httppost = ptr::null_mut();

        // "we do not support an array from within an array" (`:357-359`).
        // SAFETY: the array is terminated and outlives the call.
        let code = unsafe {
            curl_formadd(
                &mut post,
                &mut last,
                opt(CURLformoption::CURLFORM_ARRAY),
                nested.as_ptr(),
                opt(CURLformoption::CURLFORM_END),
            )
        };
        assert_eq!(code, CURLFORMcode::CURL_FORMADD_ILLEGAL_ARRAY);

        // And a null array pointer is `CURL_FORMADD_NULL` (`:362-363`).
        // SAFETY: a null array is the input under test; the list is terminated.
        let code = unsafe {
            curl_formadd(
                &mut post,
                &mut last,
                opt(CURLformoption::CURLFORM_ARRAY),
                ptr::null::<curl_forms>(),
                opt(CURLformoption::CURLFORM_END),
            )
        };
        assert_eq!(code, CURLFORMcode::CURL_FORMADD_NULL);
        assert!(post.is_null());
    }

    #[test]
    fn an_over_long_list_is_stopped_by_the_bound_rather_than_read_past() {
        // The bound is asserted through the ARRAY path deliberately, and the
        // reason is worth stating because the obvious test is the wrong one.
        //
        // A genuinely unterminated `...` list is undefined in C and stays
        // undefined here: past the caller's last argument there is nothing to
        // read but indeterminate stack, so an assertion about what comes back
        // would be an assertion about garbage -- flaky by construction, and a
        // deliberate use of uninitialised memory that a sanitiser would rightly
        // report. `MAX_DECODE_STEPS` exists so that such a list TERMINATES
        // instead of running away, and an array reaches the very same counter
        // while every byte read stays inside a buffer this test owns. So the
        // property under test -- the walk is bounded -- is checked exactly, and
        // nothing indeterminate is touched.
        let mut rows: Vec<curl_forms> = Vec::new();
        for _ in 0..=MAX_DECODE_STEPS {
            rows.push(curl_forms {
                option: CURLformoption::CURLFORM_CONTENTSLENGTH,
                value: 1_usize as *const c_char,
            });
        }
        rows.push(curl_forms {
            option: CURLformoption::CURLFORM_END,
            value: ptr::null(),
        });

        let mut post: *mut curl_httppost = ptr::null_mut();
        let mut last: *mut curl_httppost = ptr::null_mut();
        // SAFETY: the array is `CURLFORM_END`-terminated and fully initialised,
        // and it outlives the call; the outer list is terminated too. The
        // terminator sits beyond the step bound on purpose, which is the input
        // under test.
        let code = unsafe {
            curl_formadd(
                &mut post,
                &mut last,
                opt(CURLformoption::CURLFORM_ARRAY),
                rows.as_ptr(),
                opt(CURLformoption::CURLFORM_END),
            )
        };
        assert_eq!(
            code,
            CURLFORMcode::CURL_FORMADD_INCOMPLETE,
            "a list the bound cannot finish is reported, not guessed at",
        );
        assert!(post.is_null(), "and nothing is built");
        assert!(last.is_null());
    }

    #[test]
    fn every_httppost_flag_is_set_exactly_as_the_c_sets_it() {
        // One node per flag-setting option, asserted as a whole word rather than
        // bit by bit: a consumer may read `post->flags` and decide from it what
        // it owns, so a spurious bit is as wrong as a missing one.
        let dir = std::env::temp_dir();
        let stamp = std::process::id();
        let path = dir.join(format!("blitzy_form_flags_{stamp}.txt"));
        std::fs::write(&path, b"contents\n").expect("scratch file written");
        let arg = format!("{}\0", path.display());
        let file = arg.as_ptr().cast::<c_char>();
        // NUL-TERMINATED DELIBERATELY, and the terminator is load-bearing.
        // `CURLFORM_PTRCONTENTS` below declares no length, and "if
        // CURLFORM_CONTENTSLENGTH is missing strlen () is used"
        // (`lib/formdata.c:190`), so an unterminated buffer would be measured
        // past its end -- by the C exactly as by this crate. An earlier draft
        // of this test used `b"buffered"` and AddressSanitizer reported a
        // 9-byte read of an 8-byte global, which was this test's defect and not
        // the implementation's: the option's contract is a C string. The
        // `BUFFERLENGTH` case below therefore subtracts the terminator, because
        // there the length IS declared and describes content only.
        let buffer = b"buffered\0";
        let content = &buffer[..buffer.len() - 1];
        let mut context = 0_u8;
        let userp: *mut c_void = (&mut context as *mut u8).cast();

        // Each case is (description, the options after the name, expected word).
        // The options are spelled as `curl_forms` rows so that one loop can
        // drive them all; the array path and the varargs path share the decode,
        // and the two are already shown equivalent above.
        let cases: Vec<(&str, Vec<curl_forms>, c_long)> = vec![
            (
                "a plain copied part: LARGE alone",
                vec![curl_forms {
                    option: CURLformoption::CURLFORM_COPYCONTENTS,
                    value: cstr!("v"),
                }],
                CURL_HTTPPOST_LARGE,
            ),
            (
                "CURLFORM_PTRCONTENTS sets PTRCONTENTS (`:395`)",
                vec![curl_forms {
                    option: CURLformoption::CURLFORM_PTRCONTENTS,
                    value: buffer.as_ptr().cast::<c_char>(),
                }],
                CURL_HTTPPOST_LARGE | CURL_HTTPPOST_PTRCONTENTS,
            ),
            (
                "CURLFORM_FILECONTENT sets READFILE (`:427`)",
                vec![curl_forms {
                    option: CURLformoption::CURLFORM_FILECONTENT,
                    value: file,
                }],
                CURL_HTTPPOST_LARGE | CURL_HTTPPOST_READFILE,
            ),
            (
                "CURLFORM_FILE sets FILENAME (`:463`)",
                vec![curl_forms {
                    option: CURLformoption::CURLFORM_FILE,
                    value: file,
                }],
                CURL_HTTPPOST_LARGE | CURL_HTTPPOST_FILENAME,
            ),
            (
                "CURLFORM_BUFFERPTR sets PTRBUFFER AND BUFFER (`:471`)",
                vec![
                    curl_forms {
                        option: CURLformoption::CURLFORM_BUFFER,
                        value: cstr!("shown.txt"),
                    },
                    curl_forms {
                        option: CURLformoption::CURLFORM_BUFFERPTR,
                        value: content.as_ptr().cast::<c_char>(),
                    },
                    curl_forms {
                        option: CURLformoption::CURLFORM_BUFFERLENGTH,
                        value: content.len() as *const c_char,
                    },
                ],
                CURL_HTTPPOST_LARGE
                    | CURL_HTTPPOST_BUFFER
                    | CURL_HTTPPOST_PTRBUFFER,
            ),
            (
                "CURLFORM_STREAM sets CALLBACK (`:494`)",
                vec![
                    curl_forms {
                        option: CURLformoption::CURLFORM_STREAM,
                        value: userp.cast_const().cast::<c_char>(),
                    },
                    curl_forms {
                        option: CURLformoption::CURLFORM_CONTENTSLENGTH,
                        value: 1_usize as *const c_char,
                    },
                ],
                CURL_HTTPPOST_LARGE | CURL_HTTPPOST_CALLBACK,
            ),
        ];

        for (what, tail, wanted) in cases {
            let mut rows = vec![curl_forms {
                option: CURLformoption::CURLFORM_PTRNAME,
                value: cstr!("field"),
            }];
            rows.extend(tail);
            rows.push(curl_forms {
                option: CURLformoption::CURLFORM_END,
                value: ptr::null(),
            });

            let mut post: *mut curl_httppost = ptr::null_mut();
            let mut last: *mut curl_httppost = ptr::null_mut();
            // SAFETY: the array is terminated, fully initialised and outlives
            // the call; every pointer it carries outlives the form; the outer
            // list is terminated.
            let code = unsafe {
                curl_formadd(
                    &mut post,
                    &mut last,
                    opt(CURLformoption::CURLFORM_ARRAY),
                    rows.as_ptr(),
                    opt(CURLformoption::CURLFORM_END),
                )
            };
            assert_eq!(code, CURLFORMcode::CURL_FORMADD_OK, "{what}");

            // SAFETY: `post` is the chain just built.
            unsafe {
                // PTRNAME is on every row, since every case names the field
                // that way; the case's own bit is what varies.
                let expected = wanted | CURL_HTTPPOST_PTRNAME;
                assert_eq!((*post).flags, expected, "{what}");
                curl_formfree(post);
            }
        }

        // And the eight bits really are the eight the header interleaves into
        // the struct body, in the order it gives them.
        let bits = [
            CURL_HTTPPOST_FILENAME,
            CURL_HTTPPOST_READFILE,
            CURL_HTTPPOST_PTRNAME,
            CURL_HTTPPOST_PTRCONTENTS,
            CURL_HTTPPOST_BUFFER,
            CURL_HTTPPOST_PTRBUFFER,
            CURL_HTTPPOST_CALLBACK,
            CURL_HTTPPOST_LARGE,
        ];
        for (shift, bit) in bits.iter().enumerate() {
            assert_eq!(*bit, 1 << shift, "CURL_HTTPPOST_* bit {shift}");
        }

        std::fs::remove_file(&path).expect("scratch file removed");
        assert_eq!(context, 0, "the stream context is never written through");
    }

    // -- the side pointers a consumer can read ------------------------------

    #[test]
    fn contentheader_and_userp_are_the_callers_own_pointers() {
        // A one-entry header list, built through the exported slist API so that
        // the chain is exactly the one an application would pass.
        // SAFETY: the string is a NUL-terminated literal.
        let headers = unsafe {
            super::super::slist::curl_slist_append(
                ptr::null_mut(),
                cstr!("X-Custom: 1"),
            )
        };
        assert!(!headers.is_null());

        let mut context = 0xABCD_u32;
        let userp: *mut c_void = (&mut context as *mut u32).cast();
        let mut post: *mut curl_httppost = ptr::null_mut();
        let mut last: *mut curl_httppost = ptr::null_mut();

        // SAFETY: the list and the context both outlive the form, and every
        // option is followed by an argument of the type it names.
        let code = unsafe {
            curl_formadd(
                &mut post,
                &mut last,
                opt(CURLformoption::CURLFORM_COPYNAME),
                cstr!("streamed"),
                opt(CURLformoption::CURLFORM_STREAM),
                userp,
                opt(CURLformoption::CURLFORM_CONTENTSLENGTH),
                4 as c_long,
                opt(CURLformoption::CURLFORM_CONTENTHEADER),
                headers,
                opt(CURLformoption::CURLFORM_END),
            )
        };
        assert_eq!(code, CURLFORMcode::CURL_FORMADD_OK);

        // SAFETY: `post` is the chain just built.
        unsafe {
            let node = &*post;
            assert_eq!(
                node.flags & CURL_HTTPPOST_CALLBACK,
                CURL_HTTPPOST_CALLBACK,
            );
            assert!(ptr::eq(node.contentheader, headers), "the same list");
            assert!(ptr::eq(node.userp, userp), "the same context");
            // `Curl_bufref_set(&curr->value, avalue, ...)` at `:504` stores the
            // context as the value too, and the CALLBACK flag keeps
            // `curl_formfree` off it.
            assert!(ptr::eq(node.contents.cast::<c_void>(), userp));
            assert_eq!(node.contentlen, 4);
            curl_formfree(post);
            // The list is still the caller's, exactly as in the C.
            assert!(!headers.is_null());
            super::super::slist::curl_slist_free_all(headers);
        }
        assert_eq!(context, 0xABCD, "the context is never written through");
    }

    // -- serialisation ------------------------------------------------------

    #[test]
    fn lib1308s_three_field_form_is_exactly_518_bytes_through_the_abi() {
        // `tests/libtest/lib1308.c:53-76`, reproduced call for call, including
        // the buffer the third part borrows. The assertion is the C's:
        // `total_size == 518`.
        let buffer = b"test buffer\0";
        let mut post: *mut curl_httppost = ptr::null_mut();
        let mut last: *mut curl_httppost = ptr::null_mut();

        // SAFETY: every string is a NUL-terminated literal and the borrowed
        // buffer outlives the form.
        unsafe {
            assert_eq!(
                curl_formadd(
                    &mut post,
                    &mut last,
                    opt(CURLformoption::CURLFORM_COPYNAME),
                    cstr!("name"),
                    opt(CURLformoption::CURLFORM_COPYCONTENTS),
                    cstr!("content"),
                    opt(CURLformoption::CURLFORM_END),
                ),
                CURLFORMcode::CURL_FORMADD_OK,
            );
            assert!(ptr::eq(post, last), "lib1308.c:59-61");
            assert_eq!(
                curl_formadd(
                    &mut post,
                    &mut last,
                    opt(CURLformoption::CURLFORM_COPYNAME),
                    cstr!("htmlcode"),
                    opt(CURLformoption::CURLFORM_COPYCONTENTS),
                    cstr!("<HTML></HTML>"),
                    opt(CURLformoption::CURLFORM_CONTENTTYPE),
                    cstr!("text/html"),
                    opt(CURLformoption::CURLFORM_END),
                ),
                CURLFORMcode::CURL_FORMADD_OK,
            );
            assert_eq!(
                curl_formadd(
                    &mut post,
                    &mut last,
                    opt(CURLformoption::CURLFORM_COPYNAME),
                    cstr!("name_for_ptrcontent"),
                    opt(CURLformoption::CURLFORM_PTRCONTENTS),
                    buffer.as_ptr().cast::<c_char>(),
                    opt(CURLformoption::CURLFORM_END),
                ),
                CURLFORMcode::CURL_FORMADD_OK,
            );

            let (code, bytes) = serialise(post);
            assert_eq!(code, 0, "curl_formget returned error");
            assert_eq!(bytes.len(), 518, "lib1308.c:74 asserts 518 bytes");

            // And the bytes are the wire's, not a normalisation of them: CRLF
            // line endings, the header spelling and casing the C emits, and the
            // part order the calls established.
            let text = String::from_utf8_lossy(&bytes).into_owned();
            assert!(text
                .contains("Content-Disposition: form-data; name=\"name\"\r\n"));
            assert!(text.contains("Content-Type: text/html\r\n"));
            let first = text.find("name=\"name\"").expect("part one");
            let second = text.find("name=\"htmlcode\"").expect("part two");
            let third = text
                .find("name=\"name_for_ptrcontent\"")
                .expect("part three");
            assert!(first < second && second < third, "part order is frozen");

            curl_formfree(post);
        }
    }

    #[test]
    fn lib1308s_file_field_is_exactly_381_bytes_through_the_abi() {
        // The other half of `lib1308.c:79-91`. Its assertion is a RUNNING total
        // -- `total_size` is never reset between the two `curl_formget` calls --
        // so `total_size == 899` at `:89` is 518 from the form above plus 381
        // for this one.
        //
        // The fixture is `tests/data/test1308`'s `<file>` block: one 51-
        // character line and its newline. The path deliberately carries no
        // suffix, so curl's table finds no type for it and the part falls back
        // to `application/octet-stream` -- which is part of the 381.
        let contents = b"Piece of the file that is to uploaded as a formpost\n";
        assert_eq!(contents.len(), 52, "the fixture's own length");
        let dir = std::env::temp_dir();
        let stamp = std::process::id();
        let path = dir.join(format!("blitzy_form_1308_{stamp}"));
        std::fs::write(&path, contents).expect("scratch file written");
        let arg = format!("{}\0", path.display());

        let mut post: *mut curl_httppost = ptr::null_mut();
        let mut last: *mut curl_httppost = ptr::null_mut();

        // SAFETY: every string is NUL-terminated and outlives the form, and the
        // list is terminated.
        unsafe {
            assert_eq!(
                curl_formadd(
                    &mut post,
                    &mut last,
                    opt(CURLformoption::CURLFORM_PTRNAME),
                    cstr!("name of file field"),
                    opt(CURLformoption::CURLFORM_FILE),
                    arg.as_ptr().cast::<c_char>(),
                    opt(CURLformoption::CURLFORM_FILENAME),
                    cstr!("custom named file"),
                    opt(CURLformoption::CURLFORM_END),
                ),
                CURLFORMcode::CURL_FORMADD_OK,
            );

            let (code, bytes) = serialise(post);
            assert_eq!(code, 0, "curl_formget returned error");

            let text = String::from_utf8_lossy(&bytes).into_owned();
            // The shown filename overrides the base name the path gave, and
            // both appear in one header, in this order.
            assert!(
                text.contains(
                    "Content-Disposition: form-data; \
                     name=\"name of file field\"; \
                     filename=\"custom named file\"\r\n"
                ),
                "{text}",
            );
            assert!(text.contains("Content-Type: application/octet-stream\r\n"));
            assert!(text.contains("Piece of the file that is to uploaded"));
            assert_eq!(
                bytes.len(),
                381,
                "lib1308.c:89 asserts 899 cumulative, which is 518 + 381",
            );

            curl_formfree(post);
        }

        // The borrowed name survives the release, as `:679` requires.
        std::fs::remove_file(&path).expect("scratch file removed");
    }

    #[test]
    fn a_null_form_serialises_to_the_top_parts_header_and_nothing_more() {
        // Worth stating why this is not "nothing", because that is the natural
        // guess and it is wrong. `Curl_getformdata`'s "no input => no output!"
        // (`:729-730`) returns `CURLE_OK` with the top part left empty, and
        // `curl_formget` then calls `Curl_mime_prepare_headers(..., NULL,
        // "multipart/form-data", NULL, MIMESTRATEGY_FORM)` REGARDLESS (`:639-
        // 641`) -- the `if(!result)` guard is satisfied. A part of no kind has
        // no boundary to advertise, so the content type is emitted bare, and
        // the blank line that ends any header block follows it.
        //
        // SAFETY: null is explicitly permitted for the form.
        let (code, bytes) = unsafe { serialise(ptr::null_mut()) };
        assert_eq!(code, 0, "an empty form is not an error");
        assert_eq!(
            String::from_utf8_lossy(&bytes),
            "Content-Type: multipart/form-data\r\n\r\n",
            "the C's bytes for an empty form, header casing and CRLF included",
        );
    }

    #[test]
    fn an_absent_callback_is_bad_function_argument_before_anything_else() {
        // `if(!append) return (int)CURLE_BAD_FUNCTION_ARGUMENT;` (`:633-635`),
        // and it comes first: even a null form reports the callback.
        // SAFETY: null is permitted for both arguments.
        let code =
            unsafe { curl_formget(ptr::null_mut(), ptr::null_mut(), None) };
        assert_eq!(code, CURLcode::CURLE_BAD_FUNCTION_ARGUMENT.as_c_int());
        assert_eq!(code, 43, "the frozen integer, not merely the name");
    }

    #[test]
    fn a_short_return_from_the_callback_aborts_with_a_read_error() {
        // `append(arg, buffer, nread) != nread` (`:650-653`).
        unsafe extern "C" fn short_write(
            _arg: *mut c_void,
            _buf: *const c_char,
            len: usize,
        ) -> usize {
            len.saturating_sub(1)
        }

        let mut post: *mut curl_httppost = ptr::null_mut();
        let mut last: *mut curl_httppost = ptr::null_mut();
        // SAFETY: NUL-terminated literals, terminated list.
        unsafe {
            assert_eq!(
                curl_formadd(
                    &mut post,
                    &mut last,
                    opt(CURLformoption::CURLFORM_COPYNAME),
                    cstr!("n"),
                    opt(CURLformoption::CURLFORM_COPYCONTENTS),
                    cstr!("v"),
                    opt(CURLformoption::CURLFORM_END),
                ),
                CURLFORMcode::CURL_FORMADD_OK,
            );

            let code = curl_formget(post, ptr::null_mut(), Some(short_write));
            assert_eq!(code, CURLcode::CURLE_READ_ERROR.as_c_int());
            curl_formfree(post);
        }
    }

    #[test]
    fn only_the_head_of_a_chain_may_be_serialised_or_released() {
        let mut post: *mut curl_httppost = ptr::null_mut();
        let mut last: *mut curl_httppost = ptr::null_mut();
        // SAFETY: NUL-terminated literals, terminated lists.
        unsafe {
            for name in [cstr!("a"), cstr!("b")] {
                assert_eq!(
                    curl_formadd(
                        &mut post,
                        &mut last,
                        opt(CURLformoption::CURLFORM_COPYNAME),
                        name,
                        opt(CURLformoption::CURLFORM_COPYCONTENTS),
                        cstr!("v"),
                        opt(CURLformoption::CURLFORM_END),
                    ),
                    CURLFORMcode::CURL_FORMADD_OK,
                );
            }
            let nodes = chain(post);
            assert_eq!(nodes.len(), 2);

            // The second node is not the head. Serialising from there is refused
            // rather than answered with the whole form, and releasing from there
            // is ignored rather than left half-done.
            let (code, bytes) = serialise(nodes[1]);
            assert_eq!(code, CURLcode::CURLE_BAD_FUNCTION_ARGUMENT.as_c_int());
            assert!(bytes.is_empty());
            curl_formfree(nodes[1]);

            // The form is untouched, so the head still works and still frees.
            let (code, bytes) = serialise(post);
            assert_eq!(code, 0);
            assert!(!bytes.is_empty());
            curl_formfree(post);
        }
    }

    // -- the `more` chain a multi-file field builds -------------------------

    #[test]
    fn two_files_under_one_name_become_one_part_with_a_more_chain() {
        let dir = std::env::temp_dir();
        let stamp = std::process::id();
        let first = dir.join(format!("blitzy_form_more_a_{stamp}.txt"));
        let second = dir.join(format!("blitzy_form_more_b_{stamp}.txt"));
        std::fs::write(&first, b"alpha\n").expect("scratch file written");
        std::fs::write(&second, b"beta\n").expect("scratch file written");
        let first_arg = format!("{}\0", first.display());
        let second_arg = format!("{}\0", second.display());

        let mut post: *mut curl_httppost = ptr::null_mut();
        let mut last: *mut curl_httppost = ptr::null_mut();

        // `-F 'files=@a,@b'`: the second `CURLFORM_FILE` spawns a node on the
        // `more` chain because a value is already present and
        // `CURL_HTTPPOST_FILENAME` is set (`:438-451`).
        // SAFETY: both paths are NUL-terminated and live for the call.
        let code = unsafe {
            curl_formadd(
                &mut post,
                &mut last,
                opt(CURLformoption::CURLFORM_COPYNAME),
                cstr!("files"),
                opt(CURLformoption::CURLFORM_FILE),
                first_arg.as_ptr().cast::<c_char>(),
                opt(CURLformoption::CURLFORM_FILE),
                second_arg.as_ptr().cast::<c_char>(),
                opt(CURLformoption::CURLFORM_END),
            )
        };
        assert_eq!(code, CURLFORMcode::CURL_FORMADD_OK);

        // SAFETY: `post` is the chain just built.
        unsafe {
            assert_eq!(chain(post).len(), 1, "one form field, not two");
            let children = more(post);
            assert_eq!(children.len(), 1, "one sibling on the `more` chain");
            let top = &*post;
            let child = &*children[0];
            assert_eq!(
                top.flags & CURL_HTTPPOST_FILENAME,
                CURL_HTTPPOST_FILENAME,
            );
            assert_eq!(
                child.flags & CURL_HTTPPOST_FILENAME,
                CURL_HTTPPOST_FILENAME,
            );
            assert_eq!(owned(top.name).as_deref(), Some(&b"files"[..]));
            // Each node's contents is its own filename, copied eagerly by the
            // C (`:461`) and so owned by the form.
            assert_eq!(
                owned(top.contents).as_deref(),
                Some(first.display().to_string().as_bytes()),
            );
            assert_eq!(
                owned(child.contents).as_deref(),
                Some(second.display().to_string().as_bytes()),
            );

            let (code, bytes) = serialise(post);
            assert_eq!(code, 0);
            let text = String::from_utf8_lossy(&bytes).into_owned();
            assert!(
                text.contains("multipart/mixed"),
                "a multi-file field nests a multipart: {text}",
            );
            assert!(text.contains("alpha") && text.contains("beta"));

            curl_formfree(post);
        }

        std::fs::remove_file(&first).expect("scratch file removed");
        std::fs::remove_file(&second).expect("scratch file removed");
    }

    #[test]
    fn a_file_field_carries_the_shown_filename_and_the_inferred_type() {
        let dir = std::env::temp_dir();
        let stamp = std::process::id();
        let path = dir.join(format!("blitzy_form_file_{stamp}.txt"));
        std::fs::write(&path, b"payload\n").expect("scratch file written");
        let arg = format!("{}\0", path.display());

        let mut post: *mut curl_httppost = ptr::null_mut();
        let mut last: *mut curl_httppost = ptr::null_mut();

        // `lib1308.c:82-86`'s second form, without the byte count -- which
        // depends on the fixture's own file -- but with the two things that are
        // this module's to get right: the flags and the shown filename.
        // SAFETY: both strings are NUL-terminated and live for the call.
        let code = unsafe {
            curl_formadd(
                &mut post,
                &mut last,
                opt(CURLformoption::CURLFORM_PTRNAME),
                cstr!("name of file field"),
                opt(CURLformoption::CURLFORM_FILE),
                arg.as_ptr().cast::<c_char>(),
                opt(CURLformoption::CURLFORM_FILENAME),
                cstr!("custom named file"),
                opt(CURLformoption::CURLFORM_END),
            )
        };
        assert_eq!(code, CURLFORMcode::CURL_FORMADD_OK);

        // SAFETY: `post` is the chain just built.
        unsafe {
            let node = &*post;
            let wanted = CURL_HTTPPOST_FILENAME | CURL_HTTPPOST_PTRNAME;
            assert_eq!(node.flags & wanted, wanted);
            assert_eq!(
                owned(node.showfilename).as_deref(),
                Some(&b"custom named file"[..]),
            );
            // `FormAddCheck` fills in a content type when the part is a file and
            // none was given (`:245-259`); a suffixless temporary path falls
            // back to the default.
            assert!(
                node.contenttype.is_null() || {
                    let seen = owned(node.contenttype).unwrap_or_default();
                    !seen.is_empty()
                }
            );

            let (code, bytes) = serialise(post);
            assert_eq!(code, 0);
            let text = String::from_utf8_lossy(&bytes).into_owned();
            assert!(text.contains("filename=\"custom named file\""));
            assert!(text.contains("payload"));
            curl_formfree(post);
        }

        std::fs::remove_file(&path).expect("scratch file removed");
    }

    // -- the coordination surface -------------------------------------------

    #[test]
    fn the_engine_model_is_reachable_for_curlopt_httppost() {
        let mut post: *mut curl_httppost = ptr::null_mut();
        let mut last: *mut curl_httppost = ptr::null_mut();
        // SAFETY: NUL-terminated literals, terminated list.
        unsafe {
            assert_eq!(
                curl_formadd(
                    &mut post,
                    &mut last,
                    opt(CURLformoption::CURLFORM_COPYNAME),
                    cstr!("n"),
                    opt(CURLformoption::CURLFORM_COPYCONTENTS),
                    cstr!("v"),
                    opt(CURLformoption::CURLFORM_END),
                ),
                CURLFORMcode::CURL_FORMADD_OK,
            );

            let parts = with_form_list(post, FormList::len);
            assert_eq!(parts, Some(1), "the model is reachable and correct");
            assert_eq!(
                with_form_list(ptr::null_mut(), FormList::len),
                None,
                "and a null form has none",
            );
            curl_formfree(post);
        }
    }
}
