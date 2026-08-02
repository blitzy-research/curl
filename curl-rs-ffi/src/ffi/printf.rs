// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! The ten `curl_m*printf` exports: curl's own `printf`, not the platform's.
//!
//! `include/curl/mprintf.h` is 85 lines and declares ten of the 100 symbols in
//! `lib/libcurl.def`. It is the densest export-per-line file in the public
//! headers, and the only one whose members do not share a return type.
//!
//! | Symbol | `mprintf.h` | Returns | Shape | `CURL_TEMP_PRINTF` |
//! |---|---|---|---|---|
//! | `curl_mprintf` | 56-57 | `int` | `...` | `(1, 2)` |
//! | `curl_mfprintf` | 58-59 | `int` | `...` | `(2, 3)` |
//! | `curl_msprintf` | 60-61 | `int` | `...` | `(2, 3)` |
//! | `curl_msnprintf` | 62-64 | `int` | `...` | `(3, 4)` |
//! | `curl_mvprintf` | 65-66 | `int` | `va_list` | `(1, 0)` |
//! | `curl_mvfprintf` | 67-68 | `int` | `va_list` | `(2, 0)` |
//! | `curl_mvsprintf` | 69-70 | `int` | `va_list` | `(2, 0)` |
//! | `curl_mvsnprintf` | 71-73 | `int` | `va_list` | `(3, 0)` |
//! | `curl_maprintf` | 74-75 | **`char *`** | `...` | `(1, 2)` |
//! | `curl_mvaprintf` | 76-77 | **`char *`** | `va_list` | `(1, 0)` |
//!
//! **The return types are not uniform.** `curl_maprintf` and `curl_mvaprintf`
//! hand back heap memory the application releases with `curl_free`; the other
//! eight return a byte count. Getting that wrong is an ABI break that compiles
//! cleanly on the Rust side, so it is stated before anything else.
//!
//! The variadic set is **ten** prototypes in total: five plain `...` forms and
//! five that take a `va_list` parameter. Both halves need handling stable Rust
//! does not offer at the declared minimum, which is why this module contains
//! assembly. `curl-rs-ffi/cbindgen.toml` excludes all ten by name -- Group 5d,
//! `cbindgen.toml:1019-1033` -- so cbindgen never renders them and the
//! declarations come from `build.rs`'s verbatim `MPRINTF_H_DECLS`
//! (`build.rs:1322-1368`, the ten prototypes at `build.rs:1344-1365`) instead,
//! carrying the `CURL_TEMP_PRINTF(n, m)` index
//! pairs above, the five-branch attribute cascade, the `#undef` at
//! `mprintf.h:79` and the named guard close at `mprintf.h:85`. A
//! `cargo:warning=` line, where one is needed, is `build.rs`'s to emit; this
//! module emits none, because a rustc warning from here would fail validation
//! gate 1 and `clippy -D warnings`.
//!
//! The header spells `curl_mfprintf`'s first parameter **`fd`**, while
//! `lib/mprintf.c:1204` calls it `whereto`. The header spelling is the
//! ABI-visible one, because `.github/scripts/verify-synopsis.pl` compiles the
//! manual-page synopses against the generated header, so `fd` is what the
//! prototypes say and what this module's documentation uses.
//!
//! # This is not a wrapper around the platform `printf`
//!
//! `lib/mprintf.c` is a complete, self-contained `printf` with curl's own
//! conversion set, and it differs from the C library's on purpose: `%zd` and
//! `%Od` for `size_t` and `curl_off_t`, `%S` as a quoted `%s`, `(nil)` for a
//! null `%s` or `%p`, positional `%N$` arguments, and a several-place-deep set
//! of padding quirks recorded on the functions below. Specification 0.6.7
//! makes that reproduction load-bearing rather than cosmetic: 1,476 of the
//! 1,914 fixtures under `tests/data/` compare the exact bytes a transfer emits
//! with `compareparts`, which joins both sides into a single string and
//! compares them whole -- no per-line matching, no normalisation, no
//! reordering. Padding, precision, sign and `curl_off_t` rendering are all
//! byte-visible there.
//!
//! So nothing here delegates to Rust's `format!`, whose syntax and rounding
//! differ, nor to the platform's `printf`. The single exception is floating
//! point, where `lib/mprintf.c:684` itself calls the platform `snprintf` with a
//! format string it has just constructed; [`out_double`] reproduces that
//! construction byte for byte and makes the same call, which is the only way
//! to stay identical to it.
//!
//! # One core formatter, four sinks
//!
//! The C file's architecture is preserved exactly, because ten independent
//! implementations would drift:
//!
//! * [`format_into`] is `formatf` (`lib/mprintf.c:942`) -- parse the format
//!   once into an input array and an output-segment array, then walk the
//!   segments emitting one byte at a time through a callback.
//! * [`BoundedBuffer`] is `addbyter` (`:1065`), which stops at `maxlength`.
//! * [`GrowingBuffer`] is `alloc_addbyter` (`:1113`) over `dynbuf`, capped at
//!   `DYN_APRINTF`.
//! * [`UnboundedBuffer`] is `storebuffer` (`:1167`), which trusts the caller.
//! * [`FileSink`] is `fputc_wrapper` (`:1186`).
//!
//! The ten entry points are thin adapters over those five pieces, and the five
//! plain forms are thinner still: each is a `va_start` shim that delegates to
//! its `va_list` sibling, which is precisely how `lib/mprintf.c` arranges them.
//!
//! # MSRV CONFLICT, and the route taken
//!
//! A true C-variadic `extern "C"` Rust function is unavailable here: on stable
//! rustc it is `error[E0658]: C-variadic functions are unstable` (tracking
//! issue 44930), and `VaList::next_arg` is stable only on a nightly far above
//! the declared minimum of 1.75 that `rust-toolchain.toml` and `clippy.toml`
//! both pin. The trailing-`*mut c_void` design that serves `curl_easy_setopt`
//! and its three siblings does not transfer, and the reason is structural
//! rather than incidental: that design works only because an option identifier
//! already encodes its argument's type class, so one leading value governs one
//! trailing slot. A format string governs an arbitrary number of arguments of
//! arbitrary types, discoverable only by parsing it at run time. Reading one
//! slot is not enough. `include/curl/curl.h:3328-3341` corroborates the split
//! from the header's own side: it defines three-argument enforcement macros for
//! exactly those four functions and for none of these ten.
//!
//! Specification 0.8.6 lists three ways out, and two of them are closed here.
//! Raising the minimum contradicts specification 0.8.3, which fixes it at 1.75.
//! Dropping the symbols is refused by specification 0.8.2 and by the `nm`
//! parity gate, which compares the whole 100-symbol set. A `cc`-compiled C shim
//! is ABI-exact but would add a build dependency `curl-rs-ffi/Cargo.toml` does
//! not carry -- its build-dependencies are `cbindgen` alone -- so it is
//! reported rather than adopted unilaterally.
//!
//! **The route taken is the fourth, which costs none of those three: a
//! hand-written `va_start` prologue in stable `core::arch::global_asm!`, plus a
//! pure-Rust `va_list` walker per target ABI.** `core::arch::global_asm!` is
//! stable since 1.59, needs no C compiler, adds no dependency, raises no
//! minimum and drops no symbol. The crate root already names hand-writing the
//! spill prologue as one of the ABI-exact routes and records that `global_asm!`
//! was compiled and disassembled at 1.75.0 as well as on the pinned 1.97.1.
//! Every trampoline below was assembled for all four required targets and the
//! x86-64 one was driven end to end from a C caller through a genuine variadic
//! prototype, round-tripping each argument class including both the
//! general-purpose and the floating-point register-to-stack overflow
//! transitions.
//!
//! # The one thing the route does NOT buy, measured
//!
//! An assembled entry point cannot be exported from this crate's **shared**
//! library at the declared minimum, and no linker flag changes that. rustc
//! builds a cdylib's export list from Rust items carrying `#[no_mangle]` and
//! hands the linker an anonymous version script shaped
//! `{ global: <those items>; local: *; };` -- captured verbatim from 1.75.0 and
//! 1.97.1 alike and byte-identical between them. A `.globl` label matches
//! nothing in `global:`, falls to the wildcard, is localised, and -- being
//! unreferenced -- is discarded. Measured on x86_64-unknown-linux-gnu, in both
//! profiles: `nm -D --defined-only libcurl.so` reports the five `va_list` forms
//! and not the five trampolines, which appear nowhere in a symbol table of 2703
//! entries, while `nm --defined-only libcurl.a` reports all ten as `T`.
//!
//! Eight linker routes were measured. Seven do nothing at all
//! (`--export-dynamic-symbol`, `--export-dynamic-symbol-list`, `--dynamic-list`,
//! `-u`, `--export-dynamic`, and combinations). The eighth, a second anonymous
//! `--version-script` naming the five, works under LLD and **fails the link**
//! under GNU ld with `anonymous version tag cannot be combined with other
//! version tags` -- which is three of the four required targets, the 1.75 floor
//! among them. It was implemented, verified on the one target where it works,
//! and removed. `build.rs` carries the full matrix and the three rejected
//! alternatives under "Trap 3", including the finding that the `cc`-shim route
//! would not have helped either: the version script governs the whole link, so a
//! C object's symbols are localised exactly as an assembled label is.
//!
//! What ships, therefore: the static library carries all ten and is correct, and
//! the shared library carries the five `va_list` forms. The gap is LOUD -- a
//! consumer linking `-lcurl` against the shared library gets
//! `undefined reference to 'curl_maprintf'` at link time, and the specification
//! 0.8.4 parity gate fails on it by design. That is the deciding property. The
//! one alternative that would export all ten -- declaring the register-resident
//! variadic arguments as ordinary parameters -- caps the argument count, because
//! `addr_of!` of the last stack-passed parameter was measured to be the caller's
//! slot in debug and a callee-local copy in release, putting the overflow area
//! out of reach. A capped printf mis-renders a legal C call **silently**, and
//! specification 0.6.2 says of exactly this class of hazard that silent
//! acceptance is the worst option. A loud absence beats a quiet wrong answer.
//!
//! The complete remedy makes the five Rust items, which means raising the
//! minimum -- `#[naked]` at 1.88 or `c_variadic` at 1.99 -- and that is the user
//! decision A4 already reserves. What this adds to A4 is that the obstacle is
//! wider than first filed: not only Apple's variadic ABI, but Rust's cdylib
//! export model, and it applies on every target.
//!
//! # ESCALATION A4
//!
//! Specification 0.8.6 escalates open ambiguity A4 -- that Apple's arm64 ABI
//! passes variadic arguments on the stack while AAPCS64 passes them in
//! registers -- to whoever set the requirements, and calls silent acceptance
//! the worst option. It is restated here, in the module whose ten symbols sit
//! closest to it, with the three `va_list` representations that make it
//! concrete:
//!
//! | Target | `va_list` is |
//! |---|---|
//! | x86-64 System V (Linux and macOS) | a pointer to a four-field record |
//! | AAPCS64 (`aarch64-unknown-linux-gnu`) | a pointer to a five-field record |
//! | Apple arm64 (`aarch64-apple-darwin`) | a plain `char *` |
//!
//! A4's hazard is a *mismatch* between what a caller writes and what a callee
//! reads, and this module is built so that no such mismatch exists: on each
//! target the trampoline constructs exactly the representation that target's
//! own `va_start` would, and the walker reads exactly the representation that
//! target's own `va_arg` would. On Apple arm64 both halves collapse to the
//! stack cursor the caller really wrote, which is corroborated by the `str x1,
//! [sp]` call site `build.rs`'s `check_variadic_strategy` measured. That makes
//! the design ABI-correct by construction for these ten. It is **not** a claim
//! that A4 is resolved: the Apple targets are cross-assembled and
//! cross-checked against Apple's published ABI here rather than executed, so
//! the residual risk is that documentation, and A4 stays open for the four
//! trailing-pointer functions it was raised about. That is a documented gap and
//! not a silent one.
//!
//! Nothing in this module emits a warning and nothing calls `compile_error!` on
//! a required target, both for the reason given above: either would fail a gate
//! that specification 0.8.4 requires to pass on all four. A `compile_error!`
//! *is* raised for target architectures outside the required matrix, which is
//! the opposite case -- there the honest answer is a refusal, because reading a
//! `va_list` whose layout is unknown would be memory-unsafe rather than merely
//! wrong.
//!
//! **32-bit support is forfeited deliberately and is not claimed.** A single
//! register-width argument slot holds a `curl_off_t` only where `curl_off_t`
//! fits a register; all four required targets are 64-bit, so the question is
//! settled for the required matrix and for nothing wider.
//!
//! # The one module here that needs nothing from `curl-rs-lib`
//!
//! Specification 0.4.1 maps this file from `include/curl/mprintf.h` and
//! `lib/mprintf.c` and assigns it no `curl-rs-lib` module, because a `printf`
//! implementation is not protocol logic and the C family it reproduces has no
//! protocol dependency either. So the formatter lives here, and that is the one
//! sanctioned exception to the facade rule the rest of `ffi` follows.
//! `curl-rs-lib`'s own internal formatting is served by Rust's `format!`
//! machinery; this family exists for external consumers and for `--libcurl`
//! emission, and the two are deliberately not unified.

use crate::ffi::memory;
use crate::ffi::panic_boundary;

use core::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_void};
use core::ptr;

/// Buffer for long-to-string and float-to-string conversions.
///
/// `lib/mprintf.c:29-30` sizes it to fit a negative `DBL_MAX`, which is 317
/// letters, and the constant is load-bearing rather than generous: it is passed
/// to the platform `snprintf` as its bound in [`out_double`], and
/// [`out_number`] derives its own end-of-buffer index from it.
const BUFFSIZE: usize = 326;

/// The scratch buffer's real length, `char work[BUFFSIZE + 2]`
/// (`lib/mprintf.c:956`).
const WORKSIZE: usize = BUFFSIZE + 2;

/// The highest index [`out_number`] writes, `&work[BUFFSIZE - 2]`
/// (`lib/mprintf.c:720`).
///
/// C keeps one byte of margin past this to silence a false Coverity report; the
/// margin is preserved so the two buffers have identical geometry.
const WORKEND: usize = BUFFSIZE - 2;

/// Number of input arguments a single format may consume
/// (`lib/mprintf.c:31`).
const MAX_PARAMETERS: usize = 128;

/// Number of output segments a single format may produce
/// (`lib/mprintf.c:32`).
const MAX_SEGMENTS: usize = 128;

/// The `dynbuf` ceiling `curl_mvaprintf` installs (`lib/mprintf.c:1141`).
///
/// `dyn_nappend` (`lib/curlx/dynbuf.c`) refuses when `len + idx + 1` exceeds
/// it, so the largest string `curl_maprintf` can return is one byte shorter:
/// 7,999,999.
const DYN_APRINTF: usize = 8_000_000;

/// `dynbuf`'s first-allocation floor, `MIN_FIRST_ALLOC`
/// (`lib/curlx/dynbuf.c:29`).
const MIN_FIRST_ALLOC: usize = 32;

/// What the eight `int`-returning entry points report when a precondition this
/// module checks is violated.
///
/// `lib/mprintf.c` never returns a negative value: `formatf` answers `0` when
/// it cannot parse the format, and `curl_mvsnprintf` only ever decrements a
/// count that was at least one. A negative result is therefore unambiguous --
/// no successful call can produce it -- and it is C99's conventional failure
/// signal, which is why the crate root already assigns it as the
/// panic-containment fallback for this return type. Both defensive paths
/// consequently look identical to a caller, which is the honest outcome, since
/// both mean the library refused and produced nothing.
///
/// The C functions would instead have dereferenced the null pointer. Preserving
/// that is not an option, and no other value distinguishes "you passed
/// garbage" from `curl_msnprintf(buf, 10, "")`, which legitimately returns `0`.
const REFUSED: c_int = -1;

/// Lower-case digits, `Curl_ldigits` (`lib/mprintf.c:35`).
const LDIGITS: &[u8; 16] = b"0123456789abcdef";

/// Upper-case digits, `Curl_udigits` (`lib/mprintf.c:38`).
const UDIGITS: &[u8; 16] = b"0123456789ABCDEF";

/// `"(nil)"`, `nilstr` (`lib/mprintf.c:832`).
const NILSTR: &[u8; 5] = b"(nil)";

/// The C library's end-of-file sentinel, ISO C 7.21.1.
///
/// Declared here because the pinned `libc` 0.2.189 does not export it. It is
/// `-1` on every platform in the required matrix, and it is compared against
/// rather than produced, so a platform that chose another negative value would
/// make [`FileSink`] miss a write error rather than misbehave.
const EOF: c_int = -1;

extern "C" {
    /// The C `stdout` stream, which `curl_mprintf` and `curl_mvprintf` write
    /// to (`lib/mprintf.c:1198`, `:1223`).
    ///
    /// Declared here rather than imported because the pinned `libc` 0.2.189
    /// exports no stdio stream globals. It is an object of type `FILE *`, not a
    /// function: `readelf -sW` on glibc shows `stdout` as an eight-byte
    /// `GLOBAL OBJECT`. Apple spells the same object `__stdoutp`.
    ///
    /// Reaching the application's own `FILE` is the point. Substituting
    /// `fdopen(1, ...)` or a raw `write(2)` would give a second, separately
    /// buffered view of descriptor 1 and would reorder this module's output
    /// against the application's own `printf`, which the fixture corpus
    /// compares byte for byte.
    #[cfg_attr(target_vendor = "apple", link_name = "__stdoutp")]
    #[cfg_attr(not(target_vendor = "apple"), link_name = "stdout")]
    static mut STDOUT: *mut libc::FILE;
}

// ---------------------------------------------------------------------------
// Conversion and display flags -- `lib/mprintf.c:64-86`
//
// The numeric values matter, not just the names: the C code tests, sets and
// clears them in combinations whose behaviour depends on the exact bits, and
// several of the padding quirks reproduced below are visible only when the same
// combinations arise.
// ---------------------------------------------------------------------------

const FLAGS_SPACE: u32 = 1 << 0;
const FLAGS_SHOWSIGN: u32 = 1 << 1;
const FLAGS_LEFT: u32 = 1 << 2;
const FLAGS_ALT: u32 = 1 << 3;
const FLAGS_SHORT: u32 = 1 << 4;
const FLAGS_LONG: u32 = 1 << 5;
const FLAGS_LONGLONG: u32 = 1 << 6;
const FLAGS_LONGDOUBLE: u32 = 1 << 7;
const FLAGS_PAD_NIL: u32 = 1 << 8;
const FLAGS_UNSIGNED: u32 = 1 << 9;
const FLAGS_OCTAL: u32 = 1 << 10;
const FLAGS_HEX: u32 = 1 << 11;
const FLAGS_UPPER: u32 = 1 << 12;
/// `'*'` or `'*<num>$'` was used.
const FLAGS_WIDTH: u32 = 1 << 13;
/// A width PARAMETER was specified.
const FLAGS_WIDTHPARAM: u32 = 1 << 14;
/// A precision was specified.
const FLAGS_PREC: u32 = 1 << 15;
/// A precision PARAMETER was specified.
const FLAGS_PRECPARAM: u32 = 1 << 16;
/// The `%c` story.
const FLAGS_CHAR: u32 = 1 << 17;
/// `%e` or `%E`.
const FLAGS_FLOATE: u32 = 1 << 18;
/// `%g` or `%G`.
const FLAGS_FLOATG: u32 = 1 << 19;
/// No input, only a substring of the format.
const FLAGS_SUBSTR: u32 = 1 << 20;

/// Which `va_arg` type an input argument is read as, `FormatType`
/// (`lib/mprintf.c:48-62`).
///
/// `Unset` stands in for C's uninitialised array slot. `parsefmt` cannot leave
/// a reachable slot unset -- it returns `PFMT_INPUTGAP` for any index below
/// `max_param` that no conversion claimed -- so the variant exists to make that
/// unreachability explicit rather than to be handled.
///
/// `MTYPE_LONGDOUBLE` is present in the C enumeration and never assigned by
/// `parsefmt`: `%Lf` sets `FLAGS_LONGDOUBLE` but still reads a `double`. It is
/// therefore absent here, which is the same set of behaviours with one fewer
/// unreachable branch.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum FormatType {
    Unset,
    Str,
    Ptr,
    IntPtr,
    Int,
    Long,
    LongLong,
    IntU,
    LongU,
    LongLongU,
    Double,
    Width,
    Precision,
}

/// An input `va_arg` type together with its value, `struct va_input`
/// (`lib/mprintf.c:95-105`).
///
/// # Why the value is one integer and not an enumeration
///
/// C stores it in a union of `const char *`, `void *`, `int64_t`, `uint64_t`
/// and `double`, and the overlap is observable rather than incidental. Two
/// places depend on it:
///
/// * `formatf` passes `val.numu` *and* `val.nums` to `out_number` for the
///   signed integer types (`lib/mprintf.c:1024-1027`), reading one cell two
///   ways.
/// * A width or precision parameter is always read as `val.nums`
///   (`:983`, `:1000`) whatever the slot actually holds. That is reachable:
///   `"%2$*1$d %1$s"` types argument one as a string and then reads its low
///   bits as a field width, because the later `%1$s` overwrote the slot's type
///   after `*1$` had claimed it as a width. The result is garbage, and it is
///   *curl's* garbage -- reproducing it costs nothing and diverging from it
///   would be an invented behaviour.
///
/// Every union member is at most eight bytes wide on all four required targets,
/// which are 64-bit and little-endian, so one `u64` cell models it exactly:
/// truncating it to `c_int` reads the same bytes a C union read would.
///
/// Value reads, unlike width reads, are always type-consistent: the type tag
/// the fetch loop used is the same tag the emitter dispatches on, so no cell is
/// ever dereferenced as a pointer unless a pointer was stored in it.
#[derive(Clone, Copy)]
struct VaInput {
    ty: FormatType,
    /// The union's single storage cell.
    bits: u64,
}

impl VaInput {
    /// The cell as a pointer, `val.str` and `val.ptr`.
    fn as_ptr<T>(self) -> *mut T {
        self.bits as usize as *mut T
    }

    /// The cell as a signed integer, `val.nums`.
    fn as_i64(self) -> i64 {
        self.bits as i64
    }

    /// The cell as a `double`, `val.dnum`.
    fn as_f64(self) -> f64 {
        f64::from_bits(self.bits)
    }
}

/// One stretch of output, `struct outsegment` (`lib/mprintf.c:110-117`).
///
/// `start` and `outlen` describe literal format-string bytes to copy before the
/// conversion; a segment flagged [`FLAGS_SUBSTR`] has no conversion at all.
#[derive(Clone, Copy)]
struct OutSegment {
    /// Width, or the parameter number holding it.
    width: c_int,
    /// Precision, or the parameter number holding it.
    precision: c_int,
    flags: u32,
    /// Index into the input argument array.
    input: usize,
    /// Where the literal run starts, as an offset into the format string.
    ///
    /// C stores `const char *start` here. An offset is the same information
    /// with the arithmetic kept in one place -- [`FmtCursor`] -- rather than
    /// spread across two structs, and it makes the segment array free of raw
    /// pointers.
    start: usize,
    /// How many format-string bytes precede the conversion.
    outlen: usize,
}

/// The resolved width, precision and flags of one conversion,
/// `struct mproperty` (`lib/mprintf.c:590-594`).
#[derive(Clone, Copy)]
struct MProperty {
    width: c_int,
    prec: c_int,
    flags: u32,
}

/// Why a format string could not be parsed, the `PFMT_*` codes
/// (`lib/mprintf.c:158-170`).
///
/// Every one of them makes `formatf` return `0` without emitting anything, so
/// the distinctions are diagnostic rather than observable. They are kept
/// separate anyway: the set is what documents which malformed formats curl
/// rejects, and collapsing them would make the parser's acceptance rules
/// impossible to check against the C.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ParseError {
    /// Bad dollar for the main parameter.
    Dollar,
    /// Bad dollar use for the width.
    DollarWidth,
    /// Bad dollar use for the precision.
    DollarPrec,
    /// Too many input arguments used.
    ManyArgs,
    /// Precision overflow.
    Prec,
    /// Bad mix of precision specifiers.
    PrecMix,
    /// Width overflow.
    Width,
    /// A gap in the argument numbering.
    InputGap,
    /// The same argument used twice, for a width.
    WidthArg,
    /// The same argument used twice, for a precision.
    PrecArg,
    /// Maxed out the output segments.
    ManySegs,
    /// No argument list was supplied, but the format needs one.
    ///
    /// Not one of the C codes. `formatf` receives the `va_list` its caller
    /// created and cannot be handed a null one; this module's entry points can,
    /// because C lets an application pass anything. It is grouped with the
    /// parse failures because that is where it is detected and because the
    /// resulting `0` is what C would have produced for any other unusable
    /// format.
    NoArguments,
}

// ---------------------------------------------------------------------------
// The output sinks -- one per `int (*stream)(unsigned char, void *)` in the C
// ---------------------------------------------------------------------------

/// Where one formatted byte goes.
///
/// The single method is `int (*stream)(unsigned char, void *)` from
/// `lib/mprintf.c:944`, with its return value kept as a `bool` under the name
/// the C semantics actually have. A non-zero C return means *stop*, and
/// `OUTCHAR` (`:40-45`) does not count a byte the sink rejected -- so a
/// truncated `curl_msnprintf` reports the bytes stored rather than the bytes
/// the format would have produced. That asymmetry is reproduced in
/// [`out_byte`] and is the reason the trait cannot simply return `()`.
///
/// Dispatch is dynamic, as it is in C. A generic parameter would monomorphise
/// the whole formatter once per sink for no behavioural gain, and performance
/// is an explicit non-goal of specification 0.1.1.
trait Sink {
    /// Accepts one byte. Returns `true` to stop the whole conversion.
    fn emit(&mut self, byte: u8) -> bool;
}

/// `OUTCHAR` (`lib/mprintf.c:40-45`): emit, and count only what was accepted.
///
/// Returns `true` when the caller must abandon the conversion, which every
/// `out_*` function propagates as its own `true`.
#[must_use]
fn out_byte(sink: &mut dyn Sink, done: &mut c_int, byte: u8) -> bool {
    if sink.emit(byte) {
        return true;
    }
    // C increments a plain `int`. Wrapping rather than saturating keeps the
    // observable result identical on the only inputs that could reach it -- a
    // sink that accepted more than `INT_MAX` bytes -- while refusing to panic
    // in a debug build, which a `+= 1` would.
    *done = done.wrapping_add(1);
    false
}

/// `OUTCHAR`, spelled so a reader sees the C shape.
///
/// Expands to an early `return true`, exactly as the C macro expands to
/// `return TRUE`, so it is usable only inside a function that reports "stop"
/// that way.
macro_rules! outchar {
    ($sink:expr, $done:expr, $byte:expr) => {
        if out_byte($sink, $done, $byte) {
            return true;
        }
    };
}

/// `addbyter` (`lib/mprintf.c:1065-1075`) over `struct nsprintf` (`:119-123`).
///
/// Stores while `length < max` and reports "stop" the instant it is full, which
/// is what bounds `curl_msnprintf`. The pointer advances with each byte because
/// `curl_mvsnprintf` needs the *advanced* position afterwards to place its
/// terminator, so it is kept rather than recomputed.
struct BoundedBuffer {
    /// The next byte's destination; advances as bytes are stored.
    buffer: *mut c_char,
    length: usize,
    max: usize,
}

impl Sink for BoundedBuffer {
    fn emit(&mut self, byte: u8) -> bool {
        if self.length < self.max {
            // SAFETY: `curl_mvsnprintf` established that `buffer` is a
            // writable run of `max` bytes, and `length` counts the bytes
            // already written, so `length < max` proves the current position
            // is still inside it. A `char` write has no alignment
            // requirement beyond one.
            unsafe {
                self.buffer.write(byte as c_char);
                self.buffer = self.buffer.add(1);
            }
            self.length += 1;
            return false;
        }
        true
    }
}

/// `storebuffer` (`lib/mprintf.c:1167-1173`).
///
/// Writes without any bound, because `curl_msprintf`'s and `curl_mvsprintf`'s C
/// prototypes give it none. The trust is the caller's, exactly as in C: adding a
/// bound here would be a behaviour change specification 0.8.2 forbids, and
/// would silently truncate output the fixture corpus compares whole.
struct UnboundedBuffer {
    buffer: *mut c_char,
}

impl Sink for UnboundedBuffer {
    fn emit(&mut self, byte: u8) -> bool {
        // SAFETY: `curl_mvsprintf`'s contract -- the `char *` overload of
        // `sprintf`'s -- obliges the caller to supply a buffer large enough
        // for the whole result plus its terminator. Nothing else can
        // establish that, and C's own `storebuffer` relies on the identical
        // promise.
        unsafe {
            self.buffer.write(byte as c_char);
            self.buffer = self.buffer.add(1);
        }
        false
    }
}

/// `fputc_wrapper` (`lib/mprintf.c:1186-1192`).
///
/// One `fputc` per byte, stopping on the first `EOF`. Buffering is the C
/// library's, which is what keeps this module's output interleaved correctly
/// with the application's own.
struct FileSink {
    file: *mut libc::FILE,
}

impl Sink for FileSink {
    fn emit(&mut self, byte: u8) -> bool {
        // SAFETY: the entry point checked `file` for null and the caller's
        // contract makes it a stream open for writing. `byte` is a `u8`, so
        // the widened `c_int` is in 0..=255, which is the range `fputc`
        // accepts.
        let rc = unsafe { libc::fputc(c_int::from(byte), self.file) };
        rc == EOF
    }
}

/// `alloc_addbyter` (`lib/mprintf.c:1113-1121`) over `dynbuf`
/// (`lib/curlx/dynbuf.c`), capped at [`DYN_APRINTF`].
///
/// The block is obtained from [`memory`], so `curl_maprintf`'s result really is
/// the application's own allocator's and `curl_free` -- or the plain `free` some
/// applications use -- releases it exactly as it would against C libcurl. That
/// is why this grows a raw block rather than a `Vec`: a `Vec` would come from
/// Rust's global allocator and handing it to `curl_free` would be heap
/// corruption.
///
/// The growth schedule is `dyn_nappend`'s, byte for byte, so the number of
/// allocator calls an accounting hook observes matches C's.
struct GrowingBuffer {
    buf: *mut u8,
    len: usize,
    alloc: usize,
    /// Set once the ceiling was hit or an allocation failed; mirrors
    /// `struct asprintf`'s `merr` (`lib/mprintf.c:125-128`).
    failed: bool,
}

impl GrowingBuffer {
    const fn new() -> Self {
        Self {
            buf: ptr::null_mut(),
            len: 0,
            alloc: 0,
            failed: false,
        }
    }

    /// `curlx_dyn_free`: release and reset, idempotently.
    fn discard(&mut self) {
        if !self.buf.is_null() {
            // SAFETY: `buf` is non-null here and every block it can hold came
            // from `memory::malloc` or `memory::realloc` in `push` under the
            // same hook set, which is exactly `memory::free`'s precondition.
            // It is nulled immediately, so no path can release it twice.
            unsafe { memory::free(self.buf.cast::<c_void>()) };
        }
        self.buf = ptr::null_mut();
        self.len = 0;
        self.alloc = 0;
    }

    /// Hands the block to C and forgets it, `curlx_dyn_ptr` followed by the
    /// ownership transfer `curl_mvaprintf` performs by returning it.
    fn release(&mut self) -> *mut c_char {
        let released = self.buf;
        self.buf = ptr::null_mut();
        self.len = 0;
        self.alloc = 0;
        released.cast::<c_char>()
    }

    /// `dyn_nappend` for a single byte.
    ///
    /// Returns `false` on failure, having already released the block, which is
    /// what `dyn_nappend` does on both of its error paths.
    fn push(&mut self, byte: u8) -> bool {
        let idx = self.len;
        let mut a = self.alloc;
        // The old string, the new byte and the terminator.
        let fit = idx + 2;

        if fit > DYN_APRINTF {
            self.discard();
            return false;
        }
        if a == 0 {
            a = if MIN_FIRST_ALLOC > DYN_APRINTF {
                DYN_APRINTF
            } else if fit < MIN_FIRST_ALLOC {
                MIN_FIRST_ALLOC
            } else {
                fit
            };
        } else {
            while a < fit {
                a *= 2;
            }
            if a > DYN_APRINTF {
                a = DYN_APRINTF;
            }
        }

        if a != self.alloc {
            // SAFETY: `buf` is null on the first call and otherwise a live
            // block this method obtained from `memory` under the same hook
            // set, which is `memory::realloc`'s stated precondition; null is
            // explicitly well defined there and allocates.
            let grown =
                unsafe { memory::realloc(self.buf.cast::<c_void>(), a) };
            if grown.is_null() {
                self.discard();
                return false;
            }
            self.buf = grown.cast::<u8>();
            self.alloc = a;
        }

        // SAFETY: `alloc` is now at least `idx + 2`, so both the byte at
        // `idx` and the terminator at `idx + 1` are inside the block, and
        // `buf` is non-null because a null `realloc` result returned above.
        unsafe {
            self.buf.add(idx).write(byte);
            self.buf.add(idx + 1).write(0);
        }
        self.len = idx + 1;
        true
    }
}

impl Drop for GrowingBuffer {
    /// Releases the block unless [`release`](GrowingBuffer::release) took it.
    ///
    /// The panic-containment path is why this exists rather than an explicit
    /// free at each exit: an unwind out of the formatter runs `Drop` and leaves
    /// no leak, while `release` has already nulled the pointer on the success
    /// path so the block C now owns is never touched.
    fn drop(&mut self) {
        self.discard();
    }
}

impl Sink for GrowingBuffer {
    fn emit(&mut self, byte: u8) -> bool {
        if self.push(byte) {
            return false;
        }
        self.failed = true;
        true
    }
}

// ---------------------------------------------------------------------------
// The argument list
// ---------------------------------------------------------------------------

// A REFUSAL, and deliberately not the one specification 0.8.6 forbids.
//
// Every `va_list` layout below is a measured property of one specific ABI.
// There is no portable fallback: guessing at a fourth layout would read a
// caller's stack through a record whose fields are somewhere else, which is
// memory-unsafe rather than merely wrong. So an architecture outside the
// required matrix is refused here.
//
// This is the opposite case from open ambiguity A4, where a `compile_error!`
// would break `aarch64-apple-darwin` -- a target specification 0.8.3 REQUIRES
// -- and thereby fail the four-target matrix. All four required targets satisfy
// the condition below, so this refusal is unreachable for every configuration
// any gate builds, and it exists to make the deliberate forfeit of 32-bit and
// of foreign ABIs explicit instead of silent.
#[cfg(not(all(
    target_family = "unix",
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
compile_error!(
    "curl-rs-ffi's curl_m*printf family reads a va_list whose layout is \
     ABI-specific, and only the four targets specification 0.8.3 requires are \
     implemented: x86_64/aarch64 unknown-linux-gnu and x86_64/aarch64 \
     apple-darwin. 32-bit support is forfeited deliberately -- a single \
     register-width argument slot holds a curl_off_t only where curl_off_t \
     fits a register -- and no other architecture's va_list representation \
     has been measured. Adding one means measuring that ABI, not relaxing \
     this condition."
);

/// One argument, fetched from wherever the argument list actually is.
///
/// The type list is exactly the `va_arg` calls `parsefmt` makes
/// (`lib/mprintf.c:537-582`) and no more, which is what makes it possible to
/// state that no fetch is ever wider than eight bytes -- the fact every
/// [`VaArgs`] slot calculation below depends on.
///
/// Dynamically dispatched so that the parser exists once for both
/// implementations: the real C argument list, and the fixed list [`out_double`]
/// uses for its own recursive conversion.
trait ArgSource {
    fn next_str(&mut self) -> *const c_char;
    fn next_ptr(&mut self) -> *mut c_void;
    fn next_int(&mut self) -> c_int;
    fn next_uint(&mut self) -> c_uint;
    fn next_long(&mut self) -> c_long;
    fn next_ulong(&mut self) -> c_ulong;
    fn next_longlong(&mut self) -> i64;
    fn next_ulonglong(&mut self) -> u64;
    fn next_double(&mut self) -> f64;
}

/// x86-64 System V's `__va_list_tag`, on Linux and on macOS alike.
///
/// Measured with gcc 15.2: `sizeof` is 24 and `alignof` is 8, and because the C
/// type is a one-element array of this record a `va_list` *parameter* decays to
/// a pointer to it (`movq %rsp, %rsi` at the call site). `gp_offset` and
/// `fp_offset` are `unsigned int`, which is why they are `c_uint` and not
/// `usize`.
///
/// `reg_save_area` addresses 176 bytes: the six general-purpose argument
/// registers at 0, 8, 16, 24, 32 and 40, then the eight SSE registers at 48
/// through 160 in 16-byte steps. `gp_offset` indexes the first half and reaches
/// 48 when exhausted; `fp_offset` indexes the second and reaches 176.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub(crate) struct SysvVaList {
    gp_offset: c_uint,
    fp_offset: c_uint,
    overflow_arg_area: *mut c_void,
    reg_save_area: *mut c_void,
}

/// AAPCS64's `struct __va_list`, used by `aarch64-unknown-linux-gnu`.
///
/// Measured with `aarch64-linux-gnu-gcc`: 32 bytes, and because AAPCS64 passes
/// a composite larger than 16 bytes as a pointer to a caller-allocated copy, a
/// `va_list` *parameter* arrives as a pointer here too (`mov x1, sp` at the call
/// site).
///
/// The two `_offs` fields are negative offsets from the corresponding `_top`,
/// counting up to zero as registers are consumed; zero means the register file
/// is exhausted and `stack` takes over.
#[cfg(all(target_arch = "aarch64", not(target_vendor = "apple")))]
#[repr(C)]
pub(crate) struct Aapcs64VaList {
    stack: *mut c_void,
    gr_top: *mut c_void,
    vr_top: *mut c_void,
    gr_offs: c_int,
    vr_offs: c_int,
}

/// What a `va_list` parameter points at on this target.
///
/// Apple arm64 is the outlier that makes the alias worth having: there
/// `va_list` is a plain `char *`, so the parameter is the cursor itself rather
/// than a pointer to a record, and `*mut CVaList` is the correct spelling of
/// the C prototype in all three cases.
#[cfg(target_arch = "x86_64")]
pub(crate) type CVaList = SysvVaList;

/// See the x86-64 definition.
#[cfg(all(target_arch = "aarch64", not(target_vendor = "apple")))]
pub(crate) type CVaList = Aapcs64VaList;

/// See the x86-64 definition. Apple arm64's `va_list` is `char *`, so the
/// parameter type is `*mut c_char` and the alias is the character itself.
#[cfg(all(target_arch = "aarch64", target_vendor = "apple"))]
pub(crate) type CVaList = c_char;

/// A cursor over the C caller's argument list.
///
/// # The invariant every fetch relies on
///
/// A `printf`-family function cannot validate its own arguments: the format
/// string is the only description of them that exists, and a caller who got it
/// wrong has already produced undefined behaviour in C. That is not a
/// limitation of this implementation, it is the contract of the interface, and
/// it is stated on every entry point's `# Safety` section rather than papered
/// over. What this module does guarantee is that it never reads a slot the
/// format did not direct it to: the parser fetches exactly one argument per
/// conversion, in the order and of the type the conversion names.
struct VaArgs {
    /// On x86-64 and AAPCS64 this points at the caller's own record and is
    /// mutated through, which is what C's `va_arg` does to a `va_list` passed
    /// by pointer -- and the reason C forbids reusing one afterwards. On Apple
    /// arm64 the parameter is the cursor's value, so this is a private copy and
    /// the caller sees no advance, which is equally what C does there.
    list: *mut CVaList,
}

#[cfg(target_arch = "x86_64")]
impl VaArgs {
    /// The next general-purpose slot, System V's `va_arg` for an integer or
    /// pointer type of at most eight bytes.
    ///
    /// The register file holds six such arguments, so the register path applies
    /// while `gp_offset` is below 48 and the overflow area takes over at 48.
    /// The AMD64 ABI's own example writes the test as `gp_offset > 48 - 8`,
    /// which agrees for every value `gp_offset` can hold, all of them multiples
    /// of eight.
    fn gp_slot(&mut self) -> *const u8 {
        // SAFETY: `list` is non-null -- the entry points reject a null
        // argument list before constructing this -- and points at a
        // `__va_list_tag` either the C caller's `va_start` or this module's own
        // trampoline produced, so it is a live, writable, correctly aligned
        // record for the duration of the call.
        let list = unsafe { &mut *self.list };
        if list.gp_offset < 48 {
            let offset = list.gp_offset as usize;
            list.gp_offset += 8;
            // SAFETY: `reg_save_area` addresses 176 bytes by the ABI's
            // definition, and `offset` is below 48, so the eight-byte slot at
            // `offset` is inside it.
            unsafe { list.reg_save_area.cast::<u8>().add(offset) }
        } else {
            let addr = list.overflow_arg_area.cast::<u8>();
            // SAFETY: `overflow_arg_area` addresses the caller's own stack
            // arguments; the format string is what promises another one is
            // there, which is this type's documented invariant. Advancing by
            // eight is the slot size System V gives every argument of at most
            // eight bytes.
            list.overflow_arg_area = unsafe { addr.add(8) }.cast::<c_void>();
            addr
        }
    }

    /// The next floating-point slot, System V's `va_arg` for a `double`.
    ///
    /// The SSE half of the register save area holds eight arguments in 16-byte
    /// steps starting at 48, so the register path applies while `fp_offset` is
    /// below 176. A `double` that reaches the overflow area occupies eight
    /// bytes there, not sixteen.
    fn fp_slot(&mut self) -> *const u8 {
        // SAFETY: as `gp_slot`.
        let list = unsafe { &mut *self.list };
        if list.fp_offset < 176 {
            let offset = list.fp_offset as usize;
            list.fp_offset += 16;
            // SAFETY: `offset` is below 176, the size of the register save
            // area, so the eight bytes of the `double` at `offset` are inside
            // it.
            unsafe { list.reg_save_area.cast::<u8>().add(offset) }
        } else {
            let addr = list.overflow_arg_area.cast::<u8>();
            // SAFETY: as `gp_slot`'s overflow arm.
            list.overflow_arg_area = unsafe { addr.add(8) }.cast::<c_void>();
            addr
        }
    }
}

#[cfg(all(target_arch = "aarch64", not(target_vendor = "apple")))]
impl VaArgs {
    /// The next general-purpose slot, AAPCS64's `va_arg` for an integer or
    /// pointer type of at most eight bytes.
    ///
    /// `gr_offs` starts at a negative multiple of eight -- `-(8 - named) * 8`
    /// -- and counts up to zero. Zero means x0 through x7 are spent and the
    /// stack area takes over.
    fn gp_slot(&mut self) -> *const u8 {
        // SAFETY: `list` is non-null and points at a `struct __va_list` either
        // the C caller's `va_start` or this module's own trampoline produced,
        // so it is a live, writable, correctly aligned record for the duration
        // of the call.
        let list = unsafe { &mut *self.list };
        if list.gr_offs < 0 {
            let offset = list.gr_offs as isize;
            list.gr_offs += 8;
            // SAFETY: `gr_top` is the END of the general-purpose save area and
            // `offset` is a negative multiple of eight no smaller than -64, so
            // the slot lies inside that area.
            unsafe { list.gr_top.cast::<u8>().offset(offset) }
        } else {
            let addr = list.stack.cast::<u8>();
            // SAFETY: `stack` addresses the caller's own stack arguments; the
            // format string is what promises another one is there, which is
            // this type's documented invariant. AAPCS64 gives each such
            // argument an eight-byte slot.
            list.stack = unsafe { addr.add(8) }.cast::<c_void>();
            addr
        }
    }

    /// The next floating-point slot, AAPCS64's `va_arg` for a `double`.
    ///
    /// `vr_offs` starts at -128 and counts up in 16-byte steps, one per
    /// vector register. A `double` spilled to the stack area occupies eight
    /// bytes there, not sixteen.
    fn fp_slot(&mut self) -> *const u8 {
        // SAFETY: as `gp_slot`.
        let list = unsafe { &mut *self.list };
        if list.vr_offs < 0 {
            let offset = list.vr_offs as isize;
            list.vr_offs += 16;
            // SAFETY: `vr_top` is the END of the vector save area and `offset`
            // is a negative multiple of sixteen no smaller than -128, so the
            // eight bytes of the `double` lie inside that area.
            unsafe { list.vr_top.cast::<u8>().offset(offset) }
        } else {
            let addr = list.stack.cast::<u8>();
            // SAFETY: as `gp_slot`'s stack arm.
            list.stack = unsafe { addr.add(8) }.cast::<c_void>();
            addr
        }
    }
}

#[cfg(all(target_arch = "aarch64", target_vendor = "apple"))]
impl VaArgs {
    /// The next slot on Apple arm64, where there is only one kind.
    ///
    /// Apple's arm64 ABI passes *every* variadic argument on the stack, so the
    /// `va_list` is a bare cursor and integers, pointers and doubles all come
    /// from the same run of eight-byte slots. Clang's own lowering for Darwin
    /// uses a slot size equal to the pointer width and rounds each argument's
    /// size up to it, so an `int` sits in the low four bytes of its slot and
    /// the cursor still advances by eight.
    ///
    /// This is the target open ambiguity A4 was raised about, and here the
    /// caller and this module agree by construction: `build.rs`'s
    /// `check_variadic_strategy` measured an Apple arm64 caller storing its
    /// variadic argument with `str x1, [sp]`, and the trampoline below hands
    /// that same `sp` over as the cursor.
    fn slot(&mut self) -> *const u8 {
        let addr = self.list.cast::<u8>();
        // SAFETY: the cursor addresses the caller's own stack arguments; the
        // format string is what promises another one is there, which is this
        // type's documented invariant.
        self.list = unsafe { addr.add(8) }.cast::<c_char>();
        addr
    }

    /// See [`slot`](VaArgs::slot): there is no separate register file.
    fn gp_slot(&mut self) -> *const u8 {
        self.slot()
    }

    /// See [`slot`](VaArgs::slot): there is no separate register file.
    fn fp_slot(&mut self) -> *const u8 {
        self.slot()
    }
}

impl VaArgs {
    /// Wraps a `va_list` parameter received from C.
    ///
    /// # Safety
    ///
    /// `list` must be non-null and must be the `va_list` C passed, still valid
    /// -- neither `va_end`ed nor outlived by its frame. The caller must also
    /// have supplied at least as many arguments, of exactly the types, as the
    /// accompanying format string names; that is `printf`'s contract and no
    /// implementation in any language can check it.
    const unsafe fn new(list: *mut CVaList) -> Self {
        Self { list }
    }

    /// Reads a value out of a slot.
    ///
    /// Little-endian is assumed, which the refusal above already restricts the
    /// build to: on a big-endian ABI a type narrower than its slot sits at the
    /// slot's high address instead, and every fetch would silently read
    /// padding.
    ///
    /// `read_unaligned` rather than `read` because it costs nothing on either
    /// supported architecture and removes an alignment precondition that would
    /// otherwise have to be argued at each of the nine call sites.
    fn read<T: Copy>(slot: *const u8) -> T {
        // SAFETY: the slot came from `gp_slot` or `fp_slot`, each of which
        // returned an address inside a register save area or a stack argument
        // area with at least eight bytes available, and `T` is never wider
        // than eight bytes -- the trait's type list is closed and every
        // member is a pointer, an integer of at most 64 bits, or an `f64`.
        unsafe { slot.cast::<T>().read_unaligned() }
    }
}

impl ArgSource for VaArgs {
    fn next_str(&mut self) -> *const c_char {
        Self::read(self.gp_slot())
    }

    fn next_ptr(&mut self) -> *mut c_void {
        Self::read(self.gp_slot())
    }

    fn next_int(&mut self) -> c_int {
        Self::read(self.gp_slot())
    }

    fn next_uint(&mut self) -> c_uint {
        Self::read(self.gp_slot())
    }

    fn next_long(&mut self) -> c_long {
        Self::read(self.gp_slot())
    }

    fn next_ulong(&mut self) -> c_ulong {
        Self::read(self.gp_slot())
    }

    fn next_longlong(&mut self) -> i64 {
        Self::read(self.gp_slot())
    }

    fn next_ulonglong(&mut self) -> u64 {
        Self::read(self.gp_slot())
    }

    fn next_double(&mut self) -> f64 {
        Self::read(self.fp_slot())
    }
}

/// One argument of a list this module supplies itself.
///
/// The set is closed and mirrors [`ArgSource`]'s nine fetches one for one, so a
/// fixed argument list can drive the formatter through exactly the paths a
/// `va_list` drives it through. Outside the test module only `Int` is
/// constructed -- [`append_number`] is the sole production caller -- so the
/// dead-code allowance is scoped to non-test builds rather than granted
/// outright, which keeps the test suite obliged to exercise all nine.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Copy, PartialEq, Debug)]
enum Arg {
    Str(*const c_char),
    Ptr(*mut c_void),
    Int(c_int),
    Uint(c_uint),
    Long(c_long),
    Ulong(c_ulong),
    LongLong(i64),
    UlongLong(u64),
    Double(f64),
}

/// An argument list this module built rather than received.
///
/// `lib/mprintf.c:611` and `:640` call `curl_msnprintf` recursively to render
/// the width and precision of a `%f` into the format string it then hands to
/// the platform `snprintf`. [`out_double`] reproduces that, and this is how it
/// reaches the same parser without a `va_list`: the recursion is a `"%d"` and a
/// single `c_int`, both fixed at the call site.
///
/// It is also what makes the formatter testable without any assembly at all,
/// which is why the fidelity tests at the end of this file can compare against
/// the C's documented behaviour directly.
struct SliceArgs<'a> {
    args: &'a [Arg],
    at: usize,
}

impl<'a> SliceArgs<'a> {
    const fn new(args: &'a [Arg]) -> Self {
        Self { args, at: 0 }
    }

    /// The next argument, or `None` when the list is spent.
    ///
    /// Exhaustion cannot happen on the production path -- [`out_double`] pairs
    /// one `%d` with one argument -- so it is a defect rather than a condition,
    /// and `debug_assert!` makes it loud in a test build while leaving the
    /// release path branch-free of panics.
    fn next(&mut self) -> Option<Arg> {
        let arg = self.args.get(self.at).copied();
        debug_assert!(arg.is_some(), "the argument list is exhausted");
        self.at += 1;
        arg
    }
}

/// Fetches the next argument, insisting on one variant.
///
/// A mismatch is a defect in this module's own call sites, never in a caller's
/// data, so it is asserted in a debug build and answers with the type's zero in
/// release -- which is defined, silent and unreachable.
macro_rules! slice_arg {
    ($self:expr, $variant:path, $zero:expr) => {
        match $self.next() {
            Some($variant(value)) => value,
            other => {
                debug_assert!(
                    false,
                    "the argument list holds {:?} where another type was \
                     requested",
                    other
                );
                $zero
            }
        }
    };
}

impl ArgSource for SliceArgs<'_> {
    fn next_str(&mut self) -> *const c_char {
        slice_arg!(self, Arg::Str, ptr::null())
    }

    fn next_ptr(&mut self) -> *mut c_void {
        slice_arg!(self, Arg::Ptr, ptr::null_mut())
    }

    fn next_int(&mut self) -> c_int {
        slice_arg!(self, Arg::Int, 0)
    }

    fn next_uint(&mut self) -> c_uint {
        slice_arg!(self, Arg::Uint, 0)
    }

    fn next_long(&mut self) -> c_long {
        slice_arg!(self, Arg::Long, 0)
    }

    fn next_ulong(&mut self) -> c_ulong {
        slice_arg!(self, Arg::Ulong, 0)
    }

    fn next_longlong(&mut self) -> i64 {
        slice_arg!(self, Arg::LongLong, 0)
    }

    fn next_ulonglong(&mut self) -> u64 {
        slice_arg!(self, Arg::UlongLong, 0)
    }

    fn next_double(&mut self) -> f64 {
        slice_arg!(self, Arg::Double, 0.0)
    }
}

// ---------------------------------------------------------------------------
// The format string
// ---------------------------------------------------------------------------

/// `%z`, curl's `size_t` length modifier (`lib/mprintf.c:317-323`).
///
/// C selects between the two flags with `#if SIZEOF_SIZE_T > SIZEOF_LONG`, and
/// the comparison is reproduced rather than its answer hard-coded: it resolves
/// to [`FLAGS_LONG`] on all four required targets, every one of them LP64, and
/// the expression says why instead of asserting it.
const FLAGS_SIZE_T: u32 =
    if core::mem::size_of::<usize>() > core::mem::size_of::<c_long>() {
        FLAGS_LONGLONG
    } else {
        FLAGS_LONG
    };

/// `%O`, curl's `curl_off_t` length modifier (`lib/mprintf.c:325-331`).
///
/// `SIZEOF_CURL_OFF_T > SIZEOF_LONG`, with `curl_off_t` being a signed 64-bit
/// integer on every required target. Resolves to [`FLAGS_LONG`] there.
const FLAGS_OFF_T: u32 =
    if core::mem::size_of::<i64>() > core::mem::size_of::<c_long>() {
        FLAGS_LONGLONG
    } else {
        FLAGS_LONG
    };

/// Whether positional `%N$` arguments are in play (`lib/mprintf.c:88-92`).
///
/// The first conversion decides for the whole format string, and mixing after
/// that is [`ParseError::Dollar`].
#[derive(Clone, Copy, PartialEq, Eq)]
enum Dollar {
    Unknown,
    Nope,
    Use,
}

/// A byte cursor over a NUL-terminated format string.
///
/// C walks the format with a bare `const char *`, testing `*fmt` and stepping
/// with `fmt++`, `fmt--` and `fmt += 2`. The same walk is expressed as a base
/// pointer plus an offset so that a segment can record where a literal run
/// began without carrying a second raw pointer, and so that the one place raw
/// reads happen is this type.
#[derive(Clone, Copy)]
struct FmtCursor {
    base: *const c_char,
    at: usize,
}

impl FmtCursor {
    /// The byte under the cursor, or `0` at the terminator.
    ///
    /// Reading past the terminator cannot happen: every caller either tests for
    /// `0` first or is positioned by a step that a non-zero byte justified, and
    /// [`str_number`] stops at the first non-digit, which the terminator is.
    fn peek(&self) -> u8 {
        // SAFETY: `base` is the caller's format string, non-null and
        // NUL-terminated by the contract of every entry point, and `at` never
        // passes the terminator -- the loops that advance it stop there. So
        // `base + at` is inside the string or is the terminator itself.
        unsafe { self.base.add(self.at).read() as u8 }
    }

    fn bump(&mut self) {
        self.at += 1;
    }

    /// `fmt--`, used where C steps back onto a byte it has already read.
    fn unbump(&mut self) {
        debug_assert!(self.at > 0, "the cursor cannot step before the format");
        self.at = self.at.saturating_sub(1);
    }
}

/// `curlx_str_number` (`lib/curlx/strparse.c:195`) for base ten.
///
/// Returns the value and advances past the digits, or returns `None` and leaves
/// the cursor exactly where it was -- which is what C does, since it writes
/// `*linep` only on success. `None` therefore covers both "not a number" and
/// "overflowed `max`", and both of this function's call sites turn it into a
/// parse error, so the distinction is not observable.
///
/// `str_num_base`'s `max < base` special case is not reproduced because it
/// cannot be reached: the two call sites pass [`MAX_PARAMETERS`] and `INT_MAX`,
/// both far above ten. The overflow test is transcribed exactly, including its
/// integer division, because a looser one would accept a width C rejects.
fn str_number(fmt: &mut FmtCursor, max: i64) -> Option<i64> {
    if !fmt.peek().is_ascii_digit() {
        return None;
    }
    let mut probe = *fmt;
    let mut num: i64 = 0;
    loop {
        let digit = i64::from(probe.peek() - b'0');
        probe.bump();
        if num > (max - digit) / 10 {
            return None;
        }
        num = num * 10 + digit;
        if !probe.peek().is_ascii_digit() {
            break;
        }
    }
    *fmt = probe;
    Some(num)
}

/// `dollarstring` (`lib/mprintf.c:132-146`).
///
/// Reads a `N$` prefix and answers the zero-based parameter index. C's
/// one-based-to-zero-based conversion rejects `0$`, and the cursor advances only
/// when the whole `N$` matched, so a bare `%` followed by digits falls through
/// to the width parser untouched.
fn dollar_string(fmt: &mut FmtCursor) -> Option<usize> {
    let mut probe = *fmt;
    let num = str_number(&mut probe, MAX_PARAMETERS as i64)?;
    if probe.peek() != b'$' {
        return None;
    }
    probe.bump();
    if num == 0 {
        return None;
    }
    *fmt = probe;
    // `num` is at least one and at most MAX_PARAMETERS, both by `str_number`'s
    // bound and by the test above, so the subtraction cannot wrap.
    Some((num - 1) as usize)
}

/// `is_arg_used` (`lib/mprintf.c:147`).
fn is_arg_used(bits: &[u8; MAX_PARAMETERS / 8], index: usize) -> bool {
    bits[index / 8] & (1 << (index % 8)) != 0
}

/// `mark_arg_used` (`lib/mprintf.c:148`).
fn mark_arg_used(bits: &mut [u8; MAX_PARAMETERS / 8], index: usize) {
    bits[index / 8] |= 1 << (index % 8);
}

/// `parsefmt` (`lib/mprintf.c:171-587`): the format string, once.
///
/// Fills `out` with the output segments and `input` with the type and value of
/// every argument, and answers `(segments, arguments)`. Parsing before emitting
/// is what lets positional `%2$s %1$s` work at all, and it is also why an
/// unparseable format produces no output whatsoever rather than a prefix.
///
/// `args` is `None` when the caller supplied no argument list. C cannot be in
/// that position -- its `va_list` comes from its own `va_start` -- but an
/// application calling `curl_mvprintf(fmt, NULL)` can be, and a format with no
/// conversions makes that harmless, exactly as in C. So the absence is only an
/// error once an argument is actually needed.
#[allow(clippy::too_many_lines)]
fn parse_format(
    format: *const c_char,
    out: &mut [OutSegment; MAX_SEGMENTS],
    input: &mut [VaInput; MAX_PARAMETERS],
    args: Option<&mut dyn ArgSource>,
) -> Result<(usize, usize), ParseError> {
    let mut fmt = FmtCursor {
        base: format,
        at: 0,
    };
    let mut param_num: usize = 0;
    let mut max_param: isize = -1;
    let mut ocount: usize = 0;
    let mut usedinput = [0u8; MAX_PARAMETERS / 8];
    let mut use_dollar = Dollar::Unknown;
    let mut start: usize = 0;

    while fmt.peek() != 0 {
        if fmt.peek() != b'%' {
            fmt.bump();
            continue;
        }

        let mut flags: u32 = 0;
        // Both hold either a value or, once the matching PARAM flag is set, an
        // argument index. C reuses the same `int` for both and so does this.
        let mut width: c_int = 0;
        let mut precision: c_int = 0;
        let mut param: isize = -1;

        fmt.bump();
        let outlen = fmt.at - start - 1;

        if fmt.peek() == b'%' {
            // A literal `%`. The run before it becomes a segment of its own and
            // the second `%` starts the next run, which is how one byte is
            // emitted from two.
            if outlen != 0 {
                if ocount >= MAX_SEGMENTS {
                    return Err(ParseError::ManySegs);
                }
                out[ocount] = OutSegment {
                    width: 0,
                    precision: 0,
                    flags: FLAGS_SUBSTR,
                    input: 0,
                    start,
                    outlen,
                };
                ocount += 1;
            }
            start = fmt.at;
            fmt.bump();
            continue;
        }

        if use_dollar != Dollar::Nope {
            match dollar_string(&mut fmt) {
                Some(index) => {
                    param = index as isize;
                    use_dollar = Dollar::Use;
                }
                None => {
                    if use_dollar == Dollar::Use {
                        // Positional and sequential cannot be mixed.
                        return Err(ParseError::Dollar);
                    }
                    param = -1;
                    use_dollar = Dollar::Nope;
                }
            }
        }

        // The flags, the width and the precision, in whatever order they
        // appear. C's loop reads with `*fmt++` and steps back on the first byte
        // it does not recognise, so the conversion character below is still
        // under the cursor afterwards.
        let mut loopit = true;
        while loopit {
            let c = fmt.peek();
            fmt.bump();
            match c {
                b' ' => flags |= FLAGS_SPACE,
                b'+' => flags |= FLAGS_SHOWSIGN,
                b'-' => {
                    flags |= FLAGS_LEFT;
                    // Left alignment cancels zero padding outright, and the
                    // order matters: a later `0` will not restore it either,
                    // because that case tests FLAGS_LEFT first.
                    flags &= !FLAGS_PAD_NIL;
                }
                b'#' => flags |= FLAGS_ALT,
                b'.' => {
                    if fmt.peek() == b'*' {
                        flags |= FLAGS_PRECPARAM;
                        fmt.bump();
                        if use_dollar == Dollar::Use {
                            precision = dollar_string(&mut fmt)
                                .ok_or(ParseError::DollarPrec)?
                                as c_int;
                        } else {
                            // Taken from the next argument in sequence.
                            precision = -1;
                        }
                    } else {
                        flags |= FLAGS_PREC;
                        let is_neg = fmt.peek() == b'-';
                        if is_neg {
                            fmt.bump();
                        }
                        let num = str_number(&mut fmt, c_int::MAX as i64)
                            .ok_or(ParseError::Prec)?;
                        precision = num as c_int;
                        if is_neg {
                            precision = -precision;
                        }
                    }
                    if flags & (FLAGS_PREC | FLAGS_PRECPARAM)
                        == (FLAGS_PREC | FLAGS_PRECPARAM)
                    {
                        // Both kinds of precision for one argument.
                        return Err(ParseError::PrecMix);
                    }
                }
                b'h' => flags |= FLAGS_SHORT,
                b'l' => {
                    if flags & FLAGS_LONG != 0 {
                        flags |= FLAGS_LONGLONG;
                    } else {
                        flags |= FLAGS_LONG;
                    }
                }
                b'L' => flags |= FLAGS_LONGDOUBLE,
                b'q' => flags |= FLAGS_LONGLONG,
                b'z' => flags |= FLAGS_SIZE_T,
                b'O' => flags |= FLAGS_OFF_T,
                b'0'..=b'9' => {
                    if c == b'0' && flags & FLAGS_LEFT == 0 {
                        flags |= FLAGS_PAD_NIL;
                    }
                    flags |= FLAGS_WIDTH;
                    // Back onto the digit, so the whole run is parsed as one
                    // number. A leading zero is part of it, which is why `%08d`
                    // has a width of eight rather than of zero then eight.
                    fmt.unbump();
                    let num = str_number(&mut fmt, c_int::MAX as i64)
                        .ok_or(ParseError::Width)?;
                    width = num as c_int;
                }
                b'*' => {
                    flags |= FLAGS_WIDTHPARAM;
                    if use_dollar == Dollar::Use {
                        width = dollar_string(&mut fmt)
                            .ok_or(ParseError::DollarWidth)?
                            as c_int;
                    } else {
                        // Taken from the next argument in sequence.
                        width = -1;
                    }
                }
                _ => {
                    loopit = false;
                    fmt.unbump();
                }
            }
        }

        let ty = match fmt.peek() {
            b'S' => {
                // curl's own: a string in quotes.
                flags |= FLAGS_ALT;
                FormatType::Str
            }
            b's' => FormatType::Str,
            b'n' => FormatType::IntPtr,
            b'p' => FormatType::Ptr,
            b'd' | b'i' => {
                if flags & FLAGS_LONGLONG != 0 {
                    FormatType::LongLong
                } else if flags & FLAGS_LONG != 0 {
                    FormatType::Long
                } else {
                    FormatType::Int
                }
            }
            b'u' => {
                flags |= FLAGS_UNSIGNED;
                unsigned_type(flags)
            }
            b'o' => {
                flags |= FLAGS_OCTAL | FLAGS_UNSIGNED;
                unsigned_type(flags)
            }
            b'x' => {
                flags |= FLAGS_HEX | FLAGS_UNSIGNED;
                unsigned_type(flags)
            }
            b'X' => {
                flags |= FLAGS_HEX | FLAGS_UPPER | FLAGS_UNSIGNED;
                unsigned_type(flags)
            }
            b'c' => {
                flags |= FLAGS_CHAR;
                FormatType::Int
            }
            b'f' => FormatType::Double,
            b'e' => {
                flags |= FLAGS_FLOATE;
                FormatType::Double
            }
            b'E' => {
                flags |= FLAGS_FLOATE | FLAGS_UPPER;
                FormatType::Double
            }
            b'g' => {
                flags |= FLAGS_FLOATG;
                FormatType::Double
            }
            b'G' => {
                flags |= FLAGS_FLOATG | FLAGS_UPPER;
                FormatType::Double
            }
            _ => {
                // "invalid instruction, disregard and continue". The cursor is
                // NOT advanced and `start` is NOT reset, so the whole `%...x`
                // run stays part of the literal output -- `%y` prints as `%y`.
                // Transcribed rather than tidied: it is the behaviour curl has.
                continue;
            }
        };

        if flags & FLAGS_WIDTHPARAM != 0 {
            if width < 0 {
                width = param_num as c_int;
                param_num += 1;
            } else if is_arg_used(&usedinput, width as usize) {
                // A positional width may not reuse an argument.
                return Err(ParseError::WidthArg);
            }
            let index = width as usize;
            if index >= MAX_PARAMETERS {
                return Err(ParseError::ManyArgs);
            }
            if width as isize >= max_param {
                max_param = width as isize;
            }
            input[index].ty = FormatType::Width;
            mark_arg_used(&mut usedinput, index);
        }

        if flags & FLAGS_PRECPARAM != 0 {
            if precision < 0 {
                precision = param_num as c_int;
                param_num += 1;
            } else if is_arg_used(&usedinput, precision as usize) {
                // A positional precision may not reuse an argument.
                return Err(ParseError::PrecArg);
            }
            let index = precision as usize;
            if index >= MAX_PARAMETERS {
                return Err(ParseError::ManyArgs);
            }
            if precision as isize >= max_param {
                max_param = precision as isize;
            }
            input[index].ty = FormatType::Precision;
            mark_arg_used(&mut usedinput, index);
        }

        if param < 0 {
            param = param_num as isize;
            param_num += 1;
        }
        let param = param as usize;
        if param >= MAX_PARAMETERS {
            return Err(ParseError::ManyArgs);
        }
        if param as isize >= max_param {
            max_param = param as isize;
        }
        input[param].ty = ty;
        mark_arg_used(&mut usedinput, param);

        fmt.bump();
        if ocount >= MAX_SEGMENTS {
            return Err(ParseError::ManySegs);
        }
        out[ocount] = OutSegment {
            width,
            precision,
            flags,
            input: param,
            start,
            outlen,
        };
        ocount += 1;
        start = fmt.at;
    }

    // Whatever follows the last conversion.
    let outlen = fmt.at - start;
    if outlen != 0 {
        if ocount >= MAX_SEGMENTS {
            return Err(ParseError::ManySegs);
        }
        out[ocount] = OutSegment {
            width: 0,
            precision: 0,
            flags: FLAGS_SUBSTR,
            input: 0,
            start,
            outlen,
        };
        ocount += 1;
    }

    // Now read the arguments, in index order rather than in the order the
    // conversions appear -- which is the whole point of the two-pass design,
    // since `%2$s %1$s` still consumes its arguments in declaration order.
    let icount = (max_param + 1) as usize;
    if icount != 0 {
        let Some(args) = args else {
            return Err(ParseError::NoArguments);
        };
        for (index, slot) in input.iter_mut().enumerate().take(icount) {
            if !is_arg_used(&usedinput, index) {
                // `%1$s %3$s` leaves argument two undescribed, so its type is
                // unknown and the list cannot be walked at all.
                return Err(ParseError::InputGap);
            }
            // Each arm stores exactly what the corresponding C union member
            // would receive, including its widening: `va_arg(int)` lands in
            // `val.nums` and so sign-extends, while `va_arg(unsigned int)`
            // lands in `val.numu` and so zero-extends.
            //
            // `c_long` and `c_ulong` need no conversion because every target
            // this module builds for is LP64 -- the refusal above restricts it
            // to 64-bit Unix, where `long` is 64 bits on Linux and on macOS
            // alike. On an LLP64 target they would need widening, and the
            // refusal is what makes writing that unnecessary rather than
            // wrong.
            slot.bits = match slot.ty {
                FormatType::Str => args.next_str() as usize as u64,
                FormatType::IntPtr | FormatType::Ptr => {
                    args.next_ptr() as usize as u64
                }
                FormatType::LongLongU => args.next_ulonglong(),
                FormatType::LongLong => args.next_longlong() as u64,
                FormatType::LongU => args.next_ulong(),
                FormatType::Long => args.next_long() as u64,
                FormatType::IntU => u64::from(args.next_uint()),
                FormatType::Int | FormatType::Width | FormatType::Precision => {
                    i64::from(args.next_int()) as u64
                }
                FormatType::Double => args.next_double().to_bits(),
                // C reaches its `DEBUGASSERT(NULL)` here for the same reason:
                // `is_arg_used` above proves a conversion claimed this slot,
                // and every claim assigns one of the types listed. No argument
                // is consumed, so the list cannot slip out of step.
                FormatType::Unset => 0,
            };
        }
    }

    Ok((ocount, icount))
}

/// The `va_arg` type behind `%u`, `%o`, `%x` and `%X`
/// (`lib/mprintf.c:396-432`).
///
/// Factored out because the C repeats the same three-way test verbatim in four
/// adjacent cases, and four copies are four chances to diverge.
fn unsigned_type(flags: u32) -> FormatType {
    if flags & FLAGS_LONGLONG != 0 {
        FormatType::LongLongU
    } else if flags & FLAGS_LONG != 0 {
        FormatType::LongU
    } else {
        FormatType::IntU
    }
}

// ---------------------------------------------------------------------------
// The emitters
//
// Width and precision arithmetic uses `wrapping_sub` throughout. That is not
// defensive vagueness, it is the only faithful choice: C subtracts a precision
// of up to `INT_MAX` from a width of up to `INT_MAX` in `out_number`, then
// subtracts two more for a `%#x` prefix, which is signed overflow -- undefined
// in C and, on every target in the required matrix, a two's-complement wrap.
// Reproducing the wrap keeps the output identical for such a format; using
// checked arithmetic would panic in a debug build and turn a pathological
// format string into a contained panic and a `-1`.
// ---------------------------------------------------------------------------

/// `out_number` (`lib/mprintf.c:703-830`): every integer conversion, `%c`
/// included.
///
/// The scratch buffer is filled from its far end towards its start, exactly as
/// C fills `work` backwards from `workend`, so `first` here is the index of the
/// lowest byte written and C's pointer `w` is `first - 1`. That correspondence
/// is what lets the arithmetic be transcribed rather than re-derived: C's
/// `workend - w` is `WORKEND + 1 - first`, its guard `w >= work` is
/// `first > 0`, and its final `while(++w <= workend)` is `first..=WORKEND`.
#[allow(clippy::too_many_lines)]
fn out_number(
    sink: &mut dyn Sink,
    p: &MProperty,
    num: u64,
    nums: i64,
    work: &mut [u8; WORKSIZE],
    done: &mut c_int,
) -> bool {
    let flags = p.flags;
    let mut width = p.width;
    let mut prec = p.prec;
    let is_alt = flags & FLAGS_ALT != 0;
    let mut is_neg = false;
    let mut base: u64 = 10;
    let mut digits: &[u8; 16] = LDIGITS;
    let mut num = num;
    let mut first = WORKEND + 1;

    if flags & FLAGS_CHAR != 0 {
        // `%c`. The padding loops are pre-decrement in C -- `while(--width >
        // 0)` -- so a width of three yields two spaces around one character,
        // not three.
        if flags & FLAGS_LEFT == 0 {
            loop {
                width = width.wrapping_sub(1);
                if width <= 0 {
                    break;
                }
                outchar!(sink, done, b' ');
            }
        }
        outchar!(sink, done, num as u8);
        if flags & FLAGS_LEFT != 0 {
            loop {
                width = width.wrapping_sub(1);
                if width <= 0 {
                    break;
                }
                outchar!(sink, done, b' ');
            }
        }
        return false;
    }

    if flags & FLAGS_OCTAL != 0 {
        base = 8;
    } else if flags & FLAGS_HEX != 0 {
        digits = if flags & FLAGS_UPPER != 0 {
            UDIGITS
        } else {
            LDIGITS
        };
        base = 16;
    } else if flags & FLAGS_UNSIGNED == 0 {
        is_neg = nums < 0;
        if is_neg {
            // Negate in two steps because the most negative value has no
            // positive counterpart, which is exactly why C does it this way.
            let magnitude = nums.wrapping_add(1).wrapping_neg();
            num = (magnitude as u64).wrapping_add(1);
        }
    }

    // A precision of "none" means one digit, so zero still prints as "0".
    if prec == -1 {
        prec = 1;
    }

    while num > 0 {
        first -= 1;
        work[first] = digits[(num % base) as usize];
        num /= base;
    }
    debug_assert!(first > 32, "the scratch buffer cannot be overrun");

    let placed = (WORKEND + 1 - first) as c_int;
    width = width.wrapping_sub(placed);
    prec = prec.wrapping_sub(placed);

    if is_alt && base == 8 && prec <= 0 {
        // `%#o` guarantees a leading zero, and it counts against the width.
        first -= 1;
        work[first] = b'0';
        width = width.wrapping_sub(1);
    }

    if prec > 0 {
        // The width loses the whole requested precision even where the buffer
        // cannot hold that many zeroes, which is C's arithmetic and not a
        // rounding of it.
        width = width.wrapping_sub(prec);
        while prec > 0 && first > 0 {
            prec -= 1;
            first -= 1;
            work[first] = b'0';
        }
    }

    if is_alt && base == 16 {
        // Room for the `0x`, subtracted before it is emitted.
        width = width.wrapping_sub(2);
    }

    if is_neg || flags & (FLAGS_SHOWSIGN | FLAGS_SPACE) != 0 {
        // The sign, or the blank standing in for it, occupies one column.
        width = width.wrapping_sub(1);
    }

    if flags & (FLAGS_LEFT | FLAGS_PAD_NIL) == 0 {
        while width > 0 {
            width -= 1;
            outchar!(sink, done, b' ');
        }
    }

    if is_neg {
        outchar!(sink, done, b'-');
    } else if flags & FLAGS_SHOWSIGN != 0 {
        outchar!(sink, done, b'+');
    } else if flags & FLAGS_SPACE != 0 {
        outchar!(sink, done, b' ');
    }

    if is_alt && base == 16 {
        outchar!(sink, done, b'0');
        outchar!(
            sink,
            done,
            if flags & FLAGS_UPPER != 0 { b'X' } else { b'x' }
        );
    }

    if flags & FLAGS_LEFT == 0 && flags & FLAGS_PAD_NIL != 0 {
        // Zero padding follows the sign and the `0x`, never precedes them.
        while width > 0 {
            width -= 1;
            outchar!(sink, done, b'0');
        }
    }

    for &byte in &work[first..=WORKEND] {
        outchar!(sink, done, byte);
    }

    if flags & FLAGS_LEFT != 0 {
        while width > 0 {
            width -= 1;
            outchar!(sink, done, b' ');
        }
    }

    false
}

/// `out_string` (`lib/mprintf.c:834-902`): `%s` and curl's quoted `%S`.
///
/// Three behaviours here are curl's rather than the C library's, and all three
/// are reproduced deliberately:
///
/// * A null pointer prints `(nil)`, or nothing at all when a precision below
///   five would have truncated it. The quotes `%S` adds are dropped in the
///   first case.
/// * With an explicit precision the width is reduced by the *raw* precision
///   rather than by the number of bytes actually available, so `%10.8s` of
///   `"ab"` pads by two columns and not by eight.
/// * The copy loop stops at the precision or at the first NUL, whichever comes
///   first, which is why the bytes are read one at a time through a raw pointer
///   instead of through a `CStr`: `%.3s` of a three-byte buffer with no
///   terminator must read exactly three bytes, and a `CStr` would look for one.
fn out_string(
    sink: &mut dyn Sink,
    p: &MProperty,
    str_ptr: *const c_char,
    done: &mut c_int,
) -> bool {
    let mut flags = p.flags;
    let mut width = p.width;
    let prec = p.prec;
    let mut cursor = str_ptr;
    let mut len: usize;

    if cursor.is_null() {
        if prec == -1 || prec >= NILSTR.len() as c_int {
            cursor = NILSTR.as_ptr().cast::<c_char>();
            len = NILSTR.len();
            // No quotes around `(nil)`.
            flags &= !FLAGS_ALT;
        } else {
            // C assigns the empty string literal; `len` of zero is what keeps
            // the pointer from being read at all.
            cursor = EMPTY.as_ptr().cast::<c_char>();
            len = 0;
        }
    } else if prec != -1 {
        // Cast exactly as C does: a negative precision other than -1 becomes a
        // vast length, so the NUL is what stops the copy.
        len = prec as usize;
    } else {
        // SAFETY: `cursor` is the caller's string, non-null here, and a
        // `printf` caller's contract makes it NUL-terminated. Reading the
        // first byte is what C does before deciding whether to measure it.
        if unsafe { cursor.read() } == 0 {
            len = 0;
        } else {
            // SAFETY: as above; `strlen` is the same call
            // `lib/mprintf.c:855` makes on the same pointer.
            len = unsafe { libc::strlen(cursor) };
        }
    }

    let charged = if len > c_int::MAX as usize {
        c_int::MAX
    } else {
        len as c_int
    };
    width = width.wrapping_sub(charged);

    if flags & FLAGS_ALT != 0 {
        outchar!(sink, done, b'"');
    }

    if flags & FLAGS_LEFT == 0 {
        while width > 0 {
            width -= 1;
            outchar!(sink, done, b' ');
        }
    }

    while len != 0 {
        // SAFETY: the loop has copied `original len - len` bytes so far, every
        // one of them non-zero, so `cursor` is still inside the string the
        // caller supplied -- either up to its terminator, which breaks below,
        // or up to the precision it promised.
        let byte = unsafe { cursor.read() } as u8;
        if byte == 0 {
            break;
        }
        outchar!(sink, done, byte);
        // SAFETY: the byte just read was non-zero, so the terminator is at
        // this position or later and stepping one past it stays in bounds.
        cursor = unsafe { cursor.add(1) };
        len -= 1;
    }

    if flags & FLAGS_LEFT != 0 {
        while width > 0 {
            width -= 1;
            outchar!(sink, done, b' ');
        }
    }

    if flags & FLAGS_ALT != 0 {
        outchar!(sink, done, b'"');
    }

    false
}

/// `out_pointer` (`lib/mprintf.c:904-936`): `%p`.
///
/// A non-null pointer is rendered as `%#x` of its numeric value, which is why
/// `p` is taken mutably -- C sets `FLAGS_HEX | FLAGS_ALT` on the property
/// itself before delegating.
///
/// **The null case pads on the wrong side, and that is faithful.** C tests
/// `FLAGS_LEFT` to decide whether to pad *before* `(nil)`, the opposite of what
/// left alignment means and the opposite of what every other conversion here
/// does. `%-10p` of `NULL` therefore right-aligns and `%10p` left-aligns.
/// Correcting it would be a behaviour change specification 0.8.2 forbids.
fn out_pointer(
    sink: &mut dyn Sink,
    p: &mut MProperty,
    ptr: *const c_void,
    work: &mut [u8; WORKSIZE],
    done: &mut c_int,
) -> bool {
    if !ptr.is_null() {
        let num = ptr as usize as u64;
        p.flags |= FLAGS_HEX | FLAGS_ALT;
        return out_number(sink, p, num, 0, work, done);
    }

    let flags = p.flags;
    let mut width = p.width.wrapping_sub(NILSTR.len() as c_int);
    if flags & FLAGS_LEFT != 0 {
        while width > 0 {
            width -= 1;
            outchar!(sink, done, b' ');
        }
    }
    for &byte in NILSTR.iter() {
        outchar!(sink, done, byte);
    }
    if flags & FLAGS_LEFT == 0 {
        while width > 0 {
            width -= 1;
            outchar!(sink, done, b' ');
        }
    }

    false
}

/// The one iteration bound this module adds, and the one place it departs from
/// the C.
///
/// `lib/mprintf.c:631-634` reduces a working precision with
/// `while(val >= 10.0) { val /= 10; maxprec--; }`. For any finite `double` that
/// terminates in at most 309 steps, `DBL_MAX` being about 1.8e308. For positive
/// infinity it never terminates at all.
///
/// **That is measured, not inferred.** A driver linked against a real libcurl
/// and asked for `curl_maprintf("%.2f", 1.0/0.0)` did not return; it had to be
/// killed. The C loop spins forever while `maxprec` underflows, which is also
/// undefined behaviour in its own right. A bound is therefore mandatory.
///
/// The departure is from a hang to the answer the C would have produced had it
/// terminated, so nothing observable changes. Any bound above 326 leaves
/// `maxprec` far enough below zero that the clamps below force a precision of
/// zero, giving the format `"%0.0f"` and therefore `inf` -- which is what the
/// platform `snprintf` yields and what the tests assert. Every finite value
/// reaches the same result it would have anyway, since the loop exits on its own
/// long before this bound.
const MAXPREC_STEPS: u32 = 400;

/// `out_double` (`lib/mprintf.c:596-701`): `%f`, `%e`, `%E`, `%g` and `%G`.
///
/// This is the one conversion curl does not implement itself. It assembles a
/// format string from the flags, the width and the clamped precision and hands
/// it to the platform `snprintf` (`:684`), with a comment admitting that not
/// every `sprintf` reports its output length. Calling the same function with
/// the same constructed format is the only way to stay byte-identical to it,
/// and calling a C-variadic function from Rust is stable even though defining
/// one is not.
///
/// Two quirks of the assembly are load-bearing:
///
/// * The width is appended whenever it is non-negative, and it is zero when
///   unspecified -- so plain `%f` becomes `"%0f"`. Harmless to the C library,
///   which reads the `0` as a flag with no width, and reproduced because
///   omitting it would be a guess about what `snprintf` does with the
///   difference.
/// * `FLAGS_PAD_NIL` is never forwarded, so `%08.2f` loses its zero padding
///   entirely. That is curl's behaviour and the fixture corpus is entitled to
///   depend on it.
fn out_double(
    sink: &mut dyn Sink,
    p: &MProperty,
    dnum: f64,
    work: &mut [u8; WORKSIZE],
    done: &mut c_int,
) -> bool {
    let mut formatbuf = [0u8; 32];
    formatbuf[0] = b'%';
    let mut at = 1usize;
    // C computes this once, from `strlen("%")`, and never adjusts it for the
    // flags it goes on to append. The over-count is harmless -- at most four
    // flags, at most four digits of width and four of precision, in a
    // 32-byte buffer -- and is kept so the bound handed to each recursive
    // conversion is the one C hands it.
    let mut left = formatbuf.len() - 1;
    let flags = p.flags;
    let mut width = p.width;
    let mut prec = p.prec;

    if flags & FLAGS_LEFT != 0 {
        formatbuf[at] = b'-';
        at += 1;
    }
    if flags & FLAGS_SHOWSIGN != 0 {
        formatbuf[at] = b'+';
        at += 1;
    }
    if flags & FLAGS_SPACE != 0 {
        formatbuf[at] = b' ';
        at += 1;
    }
    if flags & FLAGS_ALT != 0 {
        formatbuf[at] = b'#';
        at += 1;
    }
    formatbuf[at] = 0;

    if width >= 0 {
        if width >= BUFFSIZE as c_int {
            width = BUFFSIZE as c_int - 1;
        }
        let placed = append_number(&mut formatbuf[at..], left, false, width);
        at += placed;
        left -= placed;
    }

    if prec >= 0 {
        // One digit of integer part costs one digit of precision.
        let mut maxprec = BUFFSIZE as c_int - 1;
        let mut val = dnum;
        if prec > maxprec {
            prec = maxprec - 1;
        }
        if width > 0 && prec <= width {
            maxprec -= width;
        }
        let mut steps = 0u32;
        while val >= 10.0 && steps < MAXPREC_STEPS {
            val /= 10.0;
            maxprec -= 1;
            steps += 1;
        }
        if prec > maxprec {
            prec = maxprec - 1;
        }
        if prec < 0 {
            prec = 0;
        }
        at += append_number(&mut formatbuf[at..], left, true, prec);
    }

    if flags & FLAGS_LONG != 0 {
        formatbuf[at] = b'l';
        at += 1;
    }
    if flags & FLAGS_FLOATE != 0 {
        formatbuf[at] = if flags & FLAGS_UPPER != 0 { b'E' } else { b'e' };
    } else if flags & FLAGS_FLOATG != 0 {
        formatbuf[at] = if flags & FLAGS_UPPER != 0 { b'G' } else { b'g' };
    } else {
        formatbuf[at] = b'f';
    }
    at += 1;
    formatbuf[at] = 0;

    // SAFETY: `formatbuf` is NUL-terminated by the write above and `at` is at
    // most fifteen, well inside its 32 bytes. `work` is `WORKSIZE` bytes and
    // the bound passed is `BUFFSIZE`, two less, so `snprintf` cannot reach the
    // end of it and always terminates its output. The single variadic argument
    // is an `f64`, which is what every conversion character this function can
    // have emitted requires.
    unsafe {
        libc::snprintf(
            work.as_mut_ptr().cast::<c_char>(),
            BUFFSIZE,
            formatbuf.as_ptr().cast::<c_char>(),
            dnum,
        );
    }

    let mut index = 0usize;
    while index < WORKSIZE && work[index] != 0 {
        outchar!(sink, done, work[index]);
        index += 1;
    }

    false
}

/// `curl_msnprintf(dst, max, "%d", value)`, or `".%d"` when `dot` is set.
///
/// `out_double` uses `curl_msnprintf` recursively to render the width and the
/// precision into the format string it is assembling (`lib/mprintf.c:611`,
/// `:640`), and this is that call: the same core formatter, the same bounded
/// sink, the same terminator rule, reached with a fixed argument list rather
/// than with a `va_list`. Routing it through [`format_into`] rather than
/// open-coding the digits is what keeps a single implementation of `%d`.
///
/// The effective bound is the smaller of `max` and the slice, which coincide
/// for every reachable call: `max` is 31 or less and the slice is at least 27
/// bytes, while the longest output is four characters.
fn append_number(dst: &mut [u8], max: usize, dot: bool, value: c_int) -> usize {
    let bound = max.min(dst.len());
    let format: &[u8] = if dot { b".%d\0" } else { b"%d\0" };
    let args = [Arg::Int(value)];
    let mut source = SliceArgs::new(&args);
    // SAFETY: `dst` is a live mutable slice of at least `bound` bytes, which
    // is exactly what `bounded_format` requires of the pair, and `format` is a
    // NUL-terminated literal.
    let written = unsafe {
        bounded_format(
            dst.as_mut_ptr().cast::<c_char>(),
            bound,
            format.as_ptr().cast::<c_char>(),
            Some(&mut source),
        )
    };
    // A negative result is impossible here: `bounded_format` only decrements
    // below zero when the buffer filled exactly, and it cannot fill 27 bytes
    // with four. Clamping rather than casting keeps the arithmetic below
    // provably in range regardless.
    written.max(0) as usize
}

/// `formatf` (`lib/mprintf.c:938-1061`): parse once, then emit segment by
/// segment.
///
/// Returns the number of bytes the sink accepted. Zero is also what an
/// unparseable format produces, and that is C's signal too -- `formatf` returns
/// `0` without emitting anything rather than a negative code.
fn format_into(
    sink: &mut dyn Sink,
    format: *const c_char,
    args: Option<&mut dyn ArgSource>,
) -> c_int {
    let mut done: c_int = 0;
    let mut output = [OutSegment {
        width: 0,
        precision: 0,
        flags: 0,
        input: 0,
        start: 0,
        outlen: 0,
    }; MAX_SEGMENTS];
    let mut input = [VaInput {
        ty: FormatType::Unset,
        bits: 0,
    }; MAX_PARAMETERS];
    let mut work = [0u8; WORKSIZE];

    let Ok((ocount, _icount)) =
        parse_format(format, &mut output, &mut input, args)
    else {
        return 0;
    };

    for segment in output.iter().take(ocount) {
        let mut outlen = segment.outlen;
        if outlen != 0 {
            let mut at = segment.start;
            while outlen != 0 {
                // SAFETY: `at` indexes the caller's format string, and
                // `parse_format` derived `start` and `outlen` by walking that
                // same string to its terminator, so every byte in the run is
                // inside it.
                let byte = unsafe { format.add(at).read() } as u8;
                if byte == 0 {
                    break;
                }
                if sink.emit(byte) {
                    return done;
                }
                done = done.wrapping_add(1);
                at += 1;
                outlen -= 1;
            }
            if segment.flags & FLAGS_SUBSTR != 0 {
                // Literal text only; there is no conversion to follow.
                continue;
            }
        }

        let mut p = MProperty {
            flags: segment.flags,
            width: 0,
            prec: 0,
        };

        if p.flags & FLAGS_WIDTHPARAM != 0 {
            let index = segment.width as usize;
            debug_assert!(index < MAX_PARAMETERS, "parse_format bounds this");
            p.width = input[index].as_i64() as c_int;
            if p.width < 0 {
                // "A negative field width is taken as a '-' flag followed by a
                // positive field width."
                p.width = if p.width == c_int::MIN {
                    c_int::MAX
                } else {
                    -p.width
                };
                p.flags |= FLAGS_LEFT;
                p.flags &= !FLAGS_PAD_NIL;
            }
        } else {
            p.width = segment.width;
        }

        if p.flags & FLAGS_PRECPARAM != 0 {
            let index = segment.precision as usize;
            debug_assert!(index < MAX_PARAMETERS, "parse_format bounds this");
            p.prec = input[index].as_i64() as c_int;
            if p.prec < 0 {
                // "A negative precision is taken as if the precision were
                // omitted."
                p.prec = -1;
            }
        } else if p.flags & FLAGS_PREC != 0 {
            p.prec = segment.precision;
        } else {
            p.prec = -1;
        }

        let value = input[segment.input];
        match value.ty {
            FormatType::IntU | FormatType::LongU | FormatType::LongLongU => {
                p.flags |= FLAGS_UNSIGNED;
                if out_number(sink, &p, value.bits, 0, &mut work, &mut done) {
                    return done;
                }
            }
            FormatType::Int | FormatType::Long | FormatType::LongLong => {
                // Both arguments come from the one union cell, as in C.
                let signed = value.as_i64();
                if out_number(
                    sink, &p, value.bits, signed, &mut work, &mut done,
                ) {
                    return done;
                }
            }
            FormatType::Str => {
                if out_string(sink, &p, value.as_ptr::<c_char>(), &mut done) {
                    return done;
                }
            }
            FormatType::Ptr => {
                if out_pointer(
                    sink,
                    &mut p,
                    value.as_ptr::<c_void>(),
                    &mut work,
                    &mut done,
                ) {
                    return done;
                }
            }
            FormatType::Double => {
                if out_double(sink, &p, value.as_f64(), &mut work, &mut done) {
                    return done;
                }
            }
            FormatType::IntPtr => store_count(&p, value, done),
            // A width or precision slot is never a segment's own input, and
            // `Unset` is unreachable once `parse_format` has returned. C falls
            // through its `default:` in exactly the same way.
            FormatType::Width | FormatType::Precision | FormatType::Unset => {}
        }
    }

    done
}

/// `%n` (`lib/mprintf.c:1044-1055`): report the count so far through the
/// caller's pointer.
///
/// The width of the store follows the length modifiers, and the chain is C's:
/// `long long`, then `long`, then `int`, then `short`.
///
/// A null pointer is the one place this module declines rather than reproducing
/// what the C does, and what the C does was measured rather than guessed: a
/// driver linked against a real libcurl and asked for
/// `curl_maprintf("ab%ncd", NULL)` **died with SIGSEGV**. No program that uses
/// `%n` correctly can pass null, so declining cannot change a legitimate result,
/// and a segmentation fault is not a behaviour a caller can be depending on.
///
/// `write_unaligned` because the caller's object need not be aligned and C's
/// store would have been undefined behaviour if it were not.
///
/// `%n` is *supported*, not sanitised. Refusing it, or making it conditional,
/// would be a behaviour change specification 0.8.2 forbids -- and curl's own
/// code uses it.
fn store_count(p: &MProperty, value: VaInput, done: c_int) {
    let target = value.as_ptr::<c_void>();
    if target.is_null() {
        return;
    }
    if p.flags & FLAGS_LONGLONG != 0 {
        // SAFETY: the caller's `%n` argument is a pointer to an object of the
        // width the length modifiers named, which is `printf`'s contract and
        // the only description of it that exists. It is non-null here.
        unsafe { target.cast::<i64>().write_unaligned(i64::from(done)) };
    } else if p.flags & FLAGS_LONG != 0 {
        // SAFETY: as above.
        unsafe {
            target.cast::<c_long>().write_unaligned(c_long::from(done));
        }
    } else if p.flags & FLAGS_SHORT == 0 {
        // SAFETY: as above.
        unsafe { target.cast::<c_int>().write_unaligned(done) };
    } else {
        // SAFETY: as above.
        unsafe { target.cast::<i16>().write_unaligned(done as i16) };
    }
}

/// The empty C string `out_string` substitutes for a null pointer that a small
/// precision would have truncated (`lib/mprintf.c:847`).
const EMPTY: &[u8; 1] = b"\0";

// The scratch buffer's geometry, checked at compile time rather than by a test.
//
// `out_number` fills backwards from `WORKEND` and then emits `first..=WORKEND`,
// so the highest index it ever touches is `WORKEND`, and `out_double` hands
// `BUFFSIZE` to `snprintf` as the bound on a buffer of `WORKSIZE`. Both are
// safe only while these hold, and a future edit to any one of the three
// constants would otherwise turn a compile-time certainty into a runtime
// question.
const _: () = assert!(WORKSIZE == BUFFSIZE + 2);
const _: () = assert!(WORKEND == BUFFSIZE - 2);
const _: () = assert!(WORKEND + 1 < WORKSIZE);
const _: () = assert!(BUFFSIZE <= WORKSIZE);

// ---------------------------------------------------------------------------
// The shared cores behind the entry points
// ---------------------------------------------------------------------------

/// Owns the `va_list` wrapper so a `&mut dyn ArgSource` can borrow from it.
///
/// The indirection exists for a borrow-checking reason and not a stylistic one:
/// [`format_into`] takes `Option<&mut dyn ArgSource>`, so something must own the
/// [`VaArgs`] for the duration of the call, and every entry point needs the same
/// two lines to arrange it.
///
/// A null `ap` becomes `None` rather than a refusal. That is deliberate: C
/// dereferences a `va_list` only when a conversion asks for an argument, so
/// `curl_mvprintf("plain text", NULL)` prints its text and touches nothing.
/// Refusing up front would break that, and [`parse_format`] already reports
/// [`ParseError::NoArguments`] the moment a conversion actually needs a value.
struct ArgHolder(Option<VaArgs>);

impl ArgHolder {
    /// # Safety
    ///
    /// `ap` must be null or a live `va_list` meeting [`VaArgs::new`]'s contract.
    unsafe fn new(ap: *mut CVaList) -> Self {
        if ap.is_null() {
            Self(None)
        } else {
            // SAFETY: non-null here, and the caller promised the rest.
            Self(Some(unsafe { VaArgs::new(ap) }))
        }
    }

    fn source(&mut self) -> Option<&mut dyn ArgSource> {
        match self.0.as_mut() {
            Some(va) => Some(va),
            None => None,
        }
    }
}

/// `curl_mvsnprintf`'s body (`lib/mprintf.c:1077-1100`), reachable with either
/// kind of argument list.
///
/// The terminator rule is the subtle part and is transcribed rather than
/// reasoned about. `BoundedBuffer::buffer` has advanced past the last stored
/// byte, so:
///
/// * a full buffer -- `length == max` -- has its **last stored byte replaced**
///   by the NUL and the return value **decremented**, so the count excludes it;
/// * otherwise the NUL goes at the current position and the count stands.
///
/// The consequence is worth stating because it differs from C99: on truncation
/// this reports the number of bytes it *stored*, one less than the buffer size,
/// not the number it would have needed. Specification 0.8.1 freezes that, and
/// `lib/mprintf.c` is the definition of it.
///
/// # Safety
///
/// `buffer` must be writable for `maxlength` bytes, or `maxlength` must be zero.
/// `format` must be a non-null NUL-terminated string, and `args` must supply
/// exactly what it names.
unsafe fn bounded_format(
    buffer: *mut c_char,
    maxlength: usize,
    format: *const c_char,
    args: Option<&mut dyn ArgSource>,
) -> c_int {
    let mut info = BoundedBuffer {
        buffer,
        length: 0,
        max: maxlength,
    };
    let mut retcode = format_into(&mut info, format, args);

    if info.max != 0 {
        if info.max == info.length {
            // SAFETY: `length` equals `max`, which is non-zero, so at least one
            // byte was stored and `buffer` has advanced at least one past the
            // start. Stepping back one therefore lands on that byte, inside the
            // run the caller guaranteed.
            unsafe { info.buffer.sub(1).write(0) };
            retcode = retcode.wrapping_sub(1);
        } else {
            // SAFETY: `length < max`, so the position `buffer` now points at is
            // still the `length`-th of `max` writable bytes.
            unsafe { info.buffer.write(0) };
        }
    }

    retcode
}

/// `curl_mvaprintf`'s body (`lib/mprintf.c:1139-1155`), reachable with either
/// kind of argument list.
///
/// Three outcomes, and the third is the one that is easy to get wrong:
///
/// * the sink failed -- the ceiling was reached or the allocator refused -- so
///   the block is already released and the result is null;
/// * something was produced, so the block is handed to the caller;
/// * nothing was produced, so the result is an **allocated empty string**, never
///   null. `lib/mprintf.c:1154` returns `curlx_strdup("")` here, and callers are
///   entitled to treat null as failure alone.
///
/// # Safety
///
/// `format` must be a non-null NUL-terminated string and `args` must supply
/// exactly what it names.
unsafe fn heap_format(
    format: *const c_char,
    args: Option<&mut dyn ArgSource>,
) -> *mut c_char {
    let mut sink = GrowingBuffer::new();
    let _ = format_into(&mut sink, format, args);

    if sink.failed {
        // `GrowingBuffer::push` released on the way out and `Drop` is
        // idempotent, so there is nothing left to do but report it.
        return ptr::null_mut();
    }
    if sink.len != 0 {
        return sink.release();
    }
    memory::copy_to_c_string(b"")
}

/// `curl_mvsprintf`'s and `curl_msprintf`'s shared body
/// (`lib/mprintf.c:1175-1192`, `:1214-1219`).
///
/// # Safety
///
/// `buffer` must be writable for the whole result plus its terminator -- a
/// promise only the caller can make, and the same one C's `sprintf` extracts.
/// `format` must be a non-null NUL-terminated string and `args` must supply
/// exactly what it names.
unsafe fn unbounded_format(
    buffer: *mut c_char,
    format: *const c_char,
    args: Option<&mut dyn ArgSource>,
) -> c_int {
    let mut info = UnboundedBuffer { buffer };
    let retcode = format_into(&mut info, format, args);
    // SAFETY: the sink wrote `retcode` bytes starting at `buffer` and advanced
    // by that many, so the position it now points at is the one the caller's
    // promise reserved for the terminator.
    unsafe { info.buffer.write(0) };
    retcode
}

/// `curl_mvfprintf`'s and `curl_mfprintf`'s shared body
/// (`lib/mprintf.c:1204-1212`, `:1226-1229`).
///
/// # Safety
///
/// `file` must be a stream open for writing. `format` must be a non-null
/// NUL-terminated string and `args` must supply exactly what it names.
unsafe fn stream_format(
    file: *mut libc::FILE,
    format: *const c_char,
    args: Option<&mut dyn ArgSource>,
) -> c_int {
    let mut info = FileSink { file };
    format_into(&mut info, format, args)
}

// ---------------------------------------------------------------------------
// The five `va_list` entry points
//
// Each is the real implementation; the five plain-variadic siblings reach these
// through the assembly trampolines further down. Every body is wrapped in the
// crate's single panic boundary, so an unwind can never cross back into C: the
// eight `int` forms report `REFUSED` and the two `char *` forms report null,
// which is what `curl-rs-ffi/src/lib.rs` documents for this crate as a whole.
// ---------------------------------------------------------------------------

/// `curl_mvsnprintf` -- bounded formatting into a caller's buffer.
///
/// `mprintf.h:71-73`, `CURL_TEMP_PRINTF(3, 0)`. Implements
/// `lib/mprintf.c:1077-1100`.
///
/// Returns the number of bytes stored, excluding the terminator, or a negative
/// value if the arguments cannot be honoured. See [`bounded_format`] for the
/// truncation convention, which is curl's rather than C99's.
///
/// # Safety
///
/// * `buffer` must be writable for `maxlength` bytes; it may be null only when
///   `maxlength` is zero, in which case nothing is written at all.
/// * `format` must be a NUL-terminated string.
/// * `ap` must be null or a live `va_list` positioned at the first conversion
///   argument, and the arguments behind it must match `format` in number and in
///   type. **That last requirement cannot be checked here, or in C, or in any
///   language: a format string that promises an argument the caller did not
///   pass is undefined behaviour, and this implementation reads the slot the
///   format described just as C does.** Nothing beyond a `%`-directive's own
///   demand is ever read.
/// * `ap` is consumed. On x86-64 and AAPCS64 it is advanced through in place,
///   so the caller must not reuse it -- the same restriction C imposes on a
///   `va_list` handed to `vsnprintf`.
#[no_mangle]
pub unsafe extern "C" fn curl_mvsnprintf(
    buffer: *mut c_char,
    maxlength: usize,
    format: *const c_char,
    ap: *mut CVaList,
) -> c_int {
    panic_boundary::guard(REFUSED, || {
        if format.is_null() || (maxlength != 0 && buffer.is_null()) {
            return REFUSED;
        }
        // SAFETY: the caller's contract, checked for null above.
        let mut holder = unsafe { ArgHolder::new(ap) };
        // SAFETY: `format` is non-null and `buffer` is writable for
        // `maxlength` bytes, or `maxlength` is zero and it is never touched.
        unsafe { bounded_format(buffer, maxlength, format, holder.source()) }
    })
}

/// `curl_mvsprintf` -- unbounded formatting into a caller's buffer.
///
/// `mprintf.h:69-70`, `CURL_TEMP_PRINTF(2, 0)`. Implements
/// `lib/mprintf.c:1214-1219`.
///
/// # Safety
///
/// * `buffer` must be writable for the entire result plus a terminator. There
///   is no bound and none can be inferred; that is `sprintf`'s bargain and
///   [`curl_mvsnprintf`] exists for callers unwilling to make it.
/// * `format` must be a NUL-terminated string.
/// * `ap` must satisfy [`curl_mvsnprintf`]'s conditions, and is consumed.
#[no_mangle]
pub unsafe extern "C" fn curl_mvsprintf(
    buffer: *mut c_char,
    format: *const c_char,
    ap: *mut CVaList,
) -> c_int {
    panic_boundary::guard(REFUSED, || {
        if buffer.is_null() || format.is_null() {
            return REFUSED;
        }
        // SAFETY: the caller's contract, checked for null above.
        let mut holder = unsafe { ArgHolder::new(ap) };
        // SAFETY: `buffer` and `format` are non-null and the caller promised
        // the buffer is large enough for the whole result.
        unsafe { unbounded_format(buffer, format, holder.source()) }
    })
}

/// `curl_mvprintf` -- formatting to `stdout`.
///
/// `mprintf.h:65-66`, `CURL_TEMP_PRINTF(1, 0)`. Implements
/// `lib/mprintf.c:1221-1224`.
///
/// The destination is the C library's `stdout`, so output interleaves with the
/// application's own `printf` exactly as it does under C libcurl.
///
/// # Safety
///
/// * `format` must be a NUL-terminated string.
/// * `ap` must satisfy [`curl_mvsnprintf`]'s conditions, and is consumed.
#[no_mangle]
pub unsafe extern "C" fn curl_mvprintf(
    format: *const c_char,
    ap: *mut CVaList,
) -> c_int {
    panic_boundary::guard(REFUSED, || {
        if format.is_null() {
            return REFUSED;
        }
        // SAFETY: `STDOUT` is the C library's own `FILE *` object, present in
        // every process that links a C library -- which every process linking
        // this one does. The read copies the pointer value; no reference to
        // the mutable static is created.
        let stream = unsafe { STDOUT };
        if stream.is_null() {
            return REFUSED;
        }
        // SAFETY: the caller's contract, checked for null above.
        let mut holder = unsafe { ArgHolder::new(ap) };
        // SAFETY: `stream` is the C library's `stdout`, open for writing by
        // definition, and `format` is non-null.
        unsafe { stream_format(stream, format, holder.source()) }
    })
}

/// `curl_mvfprintf` -- formatting to a caller's stream.
///
/// `mprintf.h:67-68`, `CURL_TEMP_PRINTF(2, 0)`. Implements
/// `lib/mprintf.c:1226-1229`.
///
/// The first parameter is named `fd` because that is the header's spelling and
/// the header is what `verify-synopsis.pl` compiles the manual pages against.
/// `lib/mprintf.c` calls it `whereto`; the two are the same parameter and the
/// header's name is the ABI-visible one.
///
/// # Safety
///
/// * `fd` must be a stream open for writing.
/// * `format` must be a NUL-terminated string.
/// * `ap` must satisfy [`curl_mvsnprintf`]'s conditions, and is consumed.
#[no_mangle]
pub unsafe extern "C" fn curl_mvfprintf(
    fd: *mut libc::FILE,
    format: *const c_char,
    ap: *mut CVaList,
) -> c_int {
    panic_boundary::guard(REFUSED, || {
        if fd.is_null() || format.is_null() {
            return REFUSED;
        }
        // SAFETY: the caller's contract, checked for null above.
        let mut holder = unsafe { ArgHolder::new(ap) };
        // SAFETY: `fd` is non-null and the caller promised it is a stream open
        // for writing; `format` is non-null.
        unsafe { stream_format(fd, format, holder.source()) }
    })
}

/// `curl_mvaprintf` -- formatting into a freshly allocated string.
///
/// `mprintf.h:76-77`, `CURL_TEMP_PRINTF(1, 0)`. Implements
/// `lib/mprintf.c:1139-1155`.
///
/// **Returns `char *`, not `int`** -- one of the two members of this family that
/// does. The block belongs to the caller and must be released with `curl_free`.
/// It comes from the same allocator `curl_free` releases, including any hooks
/// `curl_global_init_mem` installed, so the pairing holds however the
/// application configured memory.
///
/// A null result means failure and nothing else. An empty result is an allocated
/// empty string.
///
/// # Safety
///
/// * `format` must be a NUL-terminated string.
/// * `ap` must satisfy [`curl_mvsnprintf`]'s conditions, and is consumed.
/// * The returned pointer, when non-null, must be released exactly once with
///   `curl_free`.
#[no_mangle]
pub unsafe extern "C" fn curl_mvaprintf(
    format: *const c_char,
    ap: *mut CVaList,
) -> *mut c_char {
    panic_boundary::guard_ptr(|| {
        if format.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the caller's contract, checked for null above.
        let mut holder = unsafe { ArgHolder::new(ap) };
        // SAFETY: `format` is non-null.
        unsafe { heap_format(format, holder.source()) }
    })
}

// ---------------------------------------------------------------------------
// The five plain-variadic entry points
//
// MSRV CONFLICT, resolved -- see the module documentation for the full account.
// `extern "C" fn f(x: T, ...)` is `error[E0658]` on stable, so these five cannot
// be written as Rust functions at MSRV 1.75. They are instead assembled: each
// trampoline performs precisely what a C compiler's `va_start` performs for the
// target it is built for, then tail-calls or calls the `va_list` sibling above.
//
// ESCALATION A4 is what makes the four separate macros necessary rather than
// merely tidy. The `va_list` a caller expects to be produced differs by ABI:
//
//   x86-64 System V   a 24-byte record, register save area plus two cursors
//   AAPCS64           a 32-byte record, three area pointers plus two offsets
//   Apple arm64       a bare `char *` cursor, everything on the stack
//
// A single implementation cannot serve all three, and the difference is silent
// rather than diagnosable: reading the wrong shape returns plausible rubbish.
// Emitting the right prologue per target is what closes A4 for this family --
// and note that the Apple legs are cross-assembled and disassembled here, never
// executed, because no Apple host is available. That gap is real and is stated
// rather than papered over.
//
// The layouts below are not read off a specification alone. Each was measured by
// compiling a reference variadic function with the target's own C compiler and
// disassembling its prologue, then the assembled trampoline was disassembled and
// compared field by field.
// ---------------------------------------------------------------------------

/// x86-64 System V, ELF flavour.
///
/// Frame of 200 bytes: the six general-purpose argument registers at 0, the
/// eight vector registers at 48 in sixteen-byte steps, and the 24-byte
/// `__va_list_tag` at 176. `subq $200` turns the entry alignment of 8 into 0
/// modulo 16, which is what makes the `movaps` stores legal.
///
/// `overflow_arg_area` is `entry_rsp + 8`, one slot past the return address,
/// and `gp_offset` starts at eight times the number of named parameters because
/// those consume the first registers. `fp_offset` always starts at 48, the size
/// of the general-purpose half.
///
/// The vector registers are saved unconditionally rather than under the usual
/// `testb %al, %al` guard. SSE2 is baseline on every x86-64 target, the stores
/// go into this frame alone, and saving eight registers the caller may not have
/// set writes only values that no conversion can ask for.
///
/// `%rax` is clobbered to compute `overflow_arg_area`, which is sound: it is not
/// an argument register, and the vector count it carried has already served its
/// only purpose.
#[cfg(all(target_arch = "x86_64", not(target_vendor = "apple")))]
macro_rules! variadic_trampoline {
    (
        export = $name:literal,
        callee = $callee:ident,
        gp_offset = $gp_offset:literal,
        gr_offs = $gr_offs:literal,
        x86_list = $x86_list:literal,
        arm_list = $arm_list:literal,
    ) => {
        core::arch::global_asm!(
            concat!(
                ".text\n",
                ".globl ", $name, "\n",
                ".p2align 4\n",
                ".type ", $name, ",@function\n",
                $name, ":\n",
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
                "movl $", $gp_offset, ", 176(%rsp)\n",
                "movl $48, 180(%rsp)\n",
                "leaq 208(%rsp), %rax\n",
                "movq %rax, 184(%rsp)\n",
                "movq %rsp, 192(%rsp)\n",
                "leaq 176(%rsp), ", $x86_list, "\n",
                "call {callee}\n",
                "addq $200, %rsp\n",
                ".cfi_def_cfa_offset 8\n",
                "ret\n",
                ".cfi_endproc\n",
                ".size ", $name, ", .-", $name, "\n",
            ),
            callee = sym $callee,
            options(att_syntax),
        );
    };
}

/// x86-64 System V, Mach-O flavour.
///
/// Identical arithmetic to the ELF form; only the assembler dialect differs.
/// Mach-O decorates symbols with a leading underscore, and its assembler rejects
/// `.type` and `.size` outright -- measured, not assumed: both produce
/// `error: unknown directive` when the ELF form is cross-assembled for
/// `x86_64-apple-darwin`.
#[cfg(all(target_arch = "x86_64", target_vendor = "apple"))]
macro_rules! variadic_trampoline {
    (
        export = $name:literal,
        callee = $callee:ident,
        gp_offset = $gp_offset:literal,
        gr_offs = $gr_offs:literal,
        x86_list = $x86_list:literal,
        arm_list = $arm_list:literal,
    ) => {
        core::arch::global_asm!(
            concat!(
                ".text\n",
                ".globl _", $name, "\n",
                ".p2align 4\n",
                "_", $name, ":\n",
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
                "movl $", $gp_offset, ", 176(%rsp)\n",
                "movl $48, 180(%rsp)\n",
                "leaq 208(%rsp), %rax\n",
                "movq %rax, 184(%rsp)\n",
                "movq %rsp, 192(%rsp)\n",
                "leaq 176(%rsp), ", $x86_list, "\n",
                "call {callee}\n",
                "addq $200, %rsp\n",
                ".cfi_def_cfa_offset 8\n",
                "ret\n",
                ".cfi_endproc\n",
            ),
            callee = sym $callee,
            options(att_syntax),
        );
    };
}

/// AAPCS64, ELF flavour -- `aarch64-unknown-linux-gnu`.
///
/// Frame of 240 bytes: the frame record at 0, x0 through x7 at 16, q0 through q7
/// at 80, and the 32-byte `struct __va_list` at 208. The record's three pointers
/// are the *ends* of the two save areas and the start of the caller's stack
/// arguments -- `__gr_top` at 80, `__vr_top` at 208, `__stack` at 240, which is
/// the entry stack pointer because AAPCS64 keeps the return address in x30
/// rather than on the stack.
///
/// The two offsets count up towards zero from a negative start: `__gr_offs` is
/// `-(8 - named) * 8` and `__vr_offs` is -128, all eight vector registers being
/// available to variadics.
///
/// x9 is a temporary the ABI leaves free. The list pointer is placed after the
/// register saves, so overwriting x1, x2 or x3 with it cannot lose an argument.
#[cfg(all(target_arch = "aarch64", not(target_vendor = "apple")))]
macro_rules! variadic_trampoline {
    (
        export = $name:literal,
        callee = $callee:ident,
        gp_offset = $gp_offset:literal,
        gr_offs = $gr_offs:literal,
        x86_list = $x86_list:literal,
        arm_list = $arm_list:literal,
    ) => {
        core::arch::global_asm!(
            concat!(
                ".text\n",
                ".globl ", $name, "\n",
                ".p2align 2\n",
                ".type ", $name, ",%function\n",
                $name, ":\n",
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
                "mov w9, #", $gr_offs, "\n",
                "str w9, [sp, #232]\n",
                "mov w9, #-128\n",
                "str w9, [sp, #236]\n",
                "add ", $arm_list, ", sp, #208\n",
                "bl {callee}\n",
                "ldp x29, x30, [sp], #240\n",
                ".cfi_def_cfa_offset 0\n",
                "ret\n",
                ".cfi_endproc\n",
                ".size ", $name, ", .-", $name, "\n",
            ),
            callee = sym $callee,
        );
    };
}

/// Apple arm64, Mach-O flavour -- `aarch64-apple-darwin`.
///
/// Two instructions, and that is the whole of it. Apple's arm64 ABI passes every
/// variadic argument on the stack, so `va_list` is a bare cursor and `va_start`
/// reduces to "take the entry stack pointer". Named parameters keep their
/// registers, so nothing needs saving and the sibling can be tail-called.
///
/// **This is the target open ambiguity A4 was raised about, and this is the
/// resolution for this family.** The specification's concern was a Rust callee
/// reading a register the Apple caller never populated; the trampoline removes
/// the possibility by never treating a register as a variadic argument. The
/// residual gap is that the code is cross-assembled and disassembled here rather
/// than executed, no Apple host being available -- stated plainly because
/// specification 0.6.2 calls silent acceptance the worst option.
#[cfg(all(target_arch = "aarch64", target_vendor = "apple"))]
macro_rules! variadic_trampoline {
    (
        export = $name:literal,
        callee = $callee:ident,
        gp_offset = $gp_offset:literal,
        gr_offs = $gr_offs:literal,
        x86_list = $x86_list:literal,
        arm_list = $arm_list:literal,
    ) => {
        core::arch::global_asm!(
            concat!(
                ".text\n",
                ".globl _", $name, "\n",
                ".p2align 2\n",
                "_", $name, ":\n",
                ".cfi_startproc\n",
                "mov ", $arm_list, ", sp\n",
                "b {callee}\n",
                ".cfi_endproc\n",
            ),
            callee = sym $callee,
        );
    };
}

// `curl_mprintf` (`mprintf.h:56-57`, `CURL_TEMP_PRINTF(1, 2)`) over
// `curl_mvprintf`. One named parameter, so the first variadic general-purpose
// argument is the second register.
variadic_trampoline! {
    export = "curl_mprintf",
    callee = curl_mvprintf,
    gp_offset = "8",
    gr_offs = "-56",
    x86_list = "%rsi",
    arm_list = "x1",
}

// `curl_mfprintf` (`mprintf.h:58-59`, `CURL_TEMP_PRINTF(2, 3)`) over
// `curl_mvfprintf`. Two named parameters.
variadic_trampoline! {
    export = "curl_mfprintf",
    callee = curl_mvfprintf,
    gp_offset = "16",
    gr_offs = "-48",
    x86_list = "%rdx",
    arm_list = "x2",
}

// `curl_msprintf` (`mprintf.h:60-61`, `CURL_TEMP_PRINTF(2, 3)`) over
// `curl_mvsprintf`. Two named parameters.
variadic_trampoline! {
    export = "curl_msprintf",
    callee = curl_mvsprintf,
    gp_offset = "16",
    gr_offs = "-48",
    x86_list = "%rdx",
    arm_list = "x2",
}

// `curl_msnprintf` (`mprintf.h:62-64`, `CURL_TEMP_PRINTF(3, 4)`) over
// `curl_mvsnprintf`. Three named parameters.
variadic_trampoline! {
    export = "curl_msnprintf",
    callee = curl_mvsnprintf,
    gp_offset = "24",
    gr_offs = "-40",
    x86_list = "%rcx",
    arm_list = "x3",
}

// `curl_maprintf` (`mprintf.h:74-75`, `CURL_TEMP_PRINTF(1, 2)`) over
// `curl_mvaprintf`. One named parameter, and one of the two members of this
// family returning `char *` rather than `int` -- the trampoline is indifferent
// to that, since the return register is the same and it never inspects it.
variadic_trampoline! {
    export = "curl_maprintf",
    callee = curl_mvaprintf,
    gp_offset = "8",
    gr_offs = "-56",
    x86_list = "%rsi",
    arm_list = "x1",
}

// ---------------------------------------------------------------------------
// Tests
//
// Every expectation below was produced differentially rather than reasoned out:
// a C driver was compiled against a real libcurl, run, and its output recorded,
// so each string is what curl's own `lib/mprintf.c` emits for that format rather
// than what this module's author believed it would emit. Where the two disagreed
// during development the C answer won, which is the only ordering consistent
// with specification 0.8.1's freeze on observable behaviour.
//
// The formats are driven through the **plain-variadic** entry points wherever a
// test can be, because that exercises the whole chain at once: the assembly
// trampoline's `va_start`, the per-target `va_list` walk, the parser, and the
// emitters. Rust may *declare* a C-variadic function even though it may not
// define one, so `extern "C" { fn curl_maprintf(_: *const c_char, ...) }` calls
// the assembled symbol exactly as a C caller would.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use core::ffi::c_int;

    // The five assembled symbols, declared as C declares them. Nothing else in
    // this crate can reach them: they are not Rust items, so there is no path
    // to them but the ABI, which is precisely what makes this the right test.
    extern "C" {
        fn curl_mprintf(format: *const c_char, ...) -> c_int;
        fn curl_mfprintf(
            fd: *mut libc::FILE,
            format: *const c_char,
            ...
        ) -> c_int;
        fn curl_msprintf(
            buffer: *mut c_char,
            format: *const c_char,
            ...
        ) -> c_int;
        fn curl_msnprintf(
            buffer: *mut c_char,
            maxlength: usize,
            format: *const c_char,
            ...
        ) -> c_int;
        fn curl_maprintf(format: *const c_char, ...) -> *mut c_char;
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

    /// Reads a C string the library allocated and releases it through the
    /// public `curl_free`, which is the pairing an application performs.
    fn take(result: *mut c_char) -> Option<Vec<u8>> {
        if result.is_null() {
            return None;
        }
        let mut bytes = Vec::new();
        let mut at = 0usize;
        loop {
            // SAFETY: `result` is a NUL-terminated block this module allocated,
            // and the loop stops at that terminator.
            let byte = unsafe { result.add(at).read() } as u8;
            if byte == 0 {
                break;
            }
            bytes.push(byte);
            at += 1;
        }
        // SAFETY: the block came from `curl_maprintf`, so `curl_free` is
        // exactly what owns it. This is the pairing the test exists to prove.
        unsafe { crate::ffi::misc::curl_free(result.cast::<c_void>()) };
        Some(bytes)
    }

    /// `assert_eq!` over `curl_maprintf`'s bytes, naming the format on failure.
    macro_rules! check {
        ($expected:literal, $fmt:literal $(, $arg:expr)* $(,)?) => {{
            // SAFETY: the format literal names exactly the arguments listed
            // after it, in order and in type, which is `printf`'s contract and
            // all that either C or this implementation requires.
            let got = unsafe { curl_maprintf(cstr!($fmt) $(, $arg)*) };
            assert_eq!(
                take(got).as_deref(),
                Some(&$expected[..]),
                concat!("format ", stringify!($fmt)),
            );
        }};
    }

    /// This module's source with the test module removed.
    ///
    /// The structural checks below search for text that they themselves
    /// contain -- a macro invocation, a `.globl` fragment, the name of an
    /// unstable feature -- so searching the whole file would make every one of
    /// them find itself and pass or fail for the wrong reason. Splitting at the
    /// `#[cfg(test)]` attribute, whose first occurrence in the file *is* that
    /// attribute, leaves exactly the half being asserted about.
    fn production_source() -> &'static str {
        let source = include_str!("printf.rs");
        let at = source
            .find("#[cfg(test)]")
            .expect("this module has a test module");
        &source[..at]
    }

    /// Formats with an argument list this module supplies itself.
    ///
    /// Needed where a test has to construct an argument of a type a Rust
    /// variadic call cannot express, and it reaches the identical core through
    /// the identical sink, so nothing about the path under test changes.
    fn with_slice(format: &[u8], args: &[Arg]) -> Vec<u8> {
        let mut buf = [0u8; 512];
        let mut source = SliceArgs::new(args);
        // SAFETY: `buf` is 512 writable bytes and that same length is the
        // bound; `format` is a NUL-terminated literal whose conversions the
        // caller matched to `args`.
        let written = unsafe {
            bounded_format(
                buf.as_mut_ptr().cast::<c_char>(),
                buf.len(),
                format.as_ptr().cast::<c_char>(),
                Some(&mut source),
            )
        };
        buf[..written.max(0) as usize].to_vec()
    }

    // -- literal text and `%%` ---------------------------------------------

    #[test]
    fn literal_text_passes_through() {
        check!(b"hello", "hello");
        check!(b"", "");
        check!(b"100% done", "100%% done");
        check!(b"%", "%%");
        check!(b"a%b", "a%%b");
    }

    // -- integer bases -----------------------------------------------------

    #[test]
    fn integer_bases() {
        check!(b"0", "%d", 0);
        check!(b"42", "%d", 42);
        check!(b"-42", "%d", -42);
        check!(b"-2147483648", "%d", c_int::MIN);
        check!(b"2147483647", "%d", c_int::MAX);
        check!(b"4294967295", "%u", u32::MAX);
        check!(b"10", "%o", 8);
        check!(b"ff", "%x", 255);
        check!(b"FF", "%X", 255);
        check!(b"42", "%i", 42);
    }

    #[test]
    fn the_alternate_flag_prefixes_octal_and_hex() {
        check!(b"010", "%#o", 8);
        check!(b"0xff", "%#x", 255);
        check!(b"0XFF", "%#X", 255);
        // Zero is the interesting case in both bases, because the digit loop
        // emits nothing and the default precision of one supplies the `0`.
        // Octal then declines its extra prefix -- `prec <= 0` is false -- while
        // hex adds its `0x` unconditionally.
        check!(b"0", "%#o", 0);
        check!(b"0x0", "%#x", 0);
    }

    // -- width, precision and flags on integers -----------------------------

    #[test]
    fn integer_width_and_alignment() {
        check!(b"   42", "%5d", 42);
        check!(b"42   |", "%-5d|", 42);
        check!(b"00042", "%05d", 42);
        // The sign is emitted before the zero padding and is charged against
        // the width, so this is five columns and not six.
        check!(b"-0042", "%05d", -42);
    }

    #[test]
    fn integer_precision_is_a_minimum_digit_count() {
        check!(b"00042", "%.5d", 42);
        check!(b"-00042", "%.5d", -42);
        check!(b"   00042", "%8.5d", 42);
        check!(b"00042   |", "%-8.5d|", 42);
        // A precision of zero suppresses the digit entirely -- but only for
        // zero itself, since any other value still has digits to print.
        check!(b"", "%.0d", 0);
        check!(b"7", "%.0d", 7);
        check!(b"   |", "%3.0d|", 0);
    }

    #[test]
    fn sign_flags() {
        check!(b"+42", "%+d", 42);
        check!(b"-42", "%+d", -42);
        check!(b" 42", "% d", 42);
        check!(b"-42", "% d", -42);
    }

    #[test]
    fn the_hex_prefix_is_charged_against_the_width() {
        check!(b"    0xff", "%#8x", 255);
        // Zero padding follows the prefix rather than preceding it.
        check!(b"0x0000ff", "%#08x", 255);
        check!(b"0xff    |", "%#-8x|", 255);
    }

    #[test]
    fn left_alignment_cancels_zero_padding() {
        // `-` clears FLAGS_PAD_NIL, and a later `0` cannot restore it because
        // that case tests FLAGS_LEFT first. Order-independent, therefore.
        check!(b"42   |", "%-05d|", 42);
        check!(b"42   |", "%0-5d|", 42);
    }

    #[test]
    fn star_takes_width_and_precision_from_the_argument_list() {
        check!(b"    42", "%*d", 6, 42);
        // A negative width is a `-` flag and a positive width.
        check!(b"42    |", "%*d|", -6, 42);
        check!(b"0042", "%.*d", 4, 42);
        // A negative precision is no precision at all.
        check!(b"42", "%.*d", -4, 42);
        check!(b"   00042", "%*.*d", 8, 5, 42);
    }

    // -- length modifiers ---------------------------------------------------

    #[test]
    fn length_modifiers() {
        check!(b"-1234567890", "%ld", -1_234_567_890_i64 as c_long);
        check!(b"-1234567890123", "%lld", -1_234_567_890_123_i64);
        check!(b"18446744073709551615", "%llu", u64::MAX);
        check!(b"ff", "%lx", 255 as c_long);
        // `%q` is a long long, and `%z`/`%O` follow the width of `size_t` and
        // `curl_off_t` on the target rather than a fixed one.
        check!(b"-5", "%qd", -5_i64);
        check!(b"123456", "%zd", 123_456_usize);
        check!(b"123456", "%zu", 123_456_usize);
        check!(b"123456", "%Od", 123_456_i64);
        // `h` and `hh` are accepted and, for a value in range, invisible.
        check!(b"42", "%hd", 42);
        check!(b"42", "%hhd", 42);
        // `l` twice is a long long, which is how `%lld` is recognised at all.
        check!(b"-1", "%lld", -1_i64);
    }

    // -- characters ---------------------------------------------------------

    #[test]
    fn characters_pad_with_a_pre_decrement() {
        check!(b"A", "%c", c_int::from(b'A'));
        // Three columns and one character yields two spaces, not three: the C
        // loop is `while(--width > 0)`.
        check!(b"  A|", "%3c|", c_int::from(b'A'));
        check!(b"A  |", "%-3c|", c_int::from(b'A'));
        check!(b"A|", "%1c|", c_int::from(b'A'));
    }

    // -- strings ------------------------------------------------------------

    #[test]
    fn strings() {
        check!(b"abc", "%s", cstr!("abc"));
        check!(b"    ab|", "%6s|", cstr!("ab"));
        check!(b"ab    |", "%-6s|", cstr!("ab"));
        check!(b"a", "%.1s", cstr!("abc"));
        check!(b"     a|", "%6.1s|", cstr!("abc"));
        check!(b"", "%s", cstr!(""));
    }

    #[test]
    fn a_precision_is_charged_to_the_width_raw() {
        // Ten columns less a precision of eight is two spaces, even though only
        // two bytes were available to print. curl charges the requested
        // precision, not the delivered length.
        check!(b"  ab|", "%10.8s|", cstr!("ab"));
    }

    #[test]
    fn a_null_string_prints_nil_unless_the_precision_truncates_it() {
        check!(b"(nil)", "%s", ptr::null::<c_char>());
        check!(b"     (nil)|", "%10s|", ptr::null::<c_char>());
        // Five is the length of `(nil)`, so five prints and four does not.
        check!(b"(nil)", "%.5s", ptr::null::<c_char>());
        check!(b"", "%.4s", ptr::null::<c_char>());
        check!(b"", "%.2s", ptr::null::<c_char>());
        check!(b"", "%.0s", ptr::null::<c_char>());
    }

    #[test]
    fn the_curl_specific_quoted_string() {
        check!(b"\"abc\"", "%S", cstr!("abc"));
        check!(b"\"      ab\"|", "%8S|", cstr!("ab"));
        // The quotes are dropped for a null pointer, because `out_string`
        // clears FLAGS_ALT on that path.
        check!(b"(nil)", "%S", ptr::null::<c_char>());
    }

    // -- pointers -----------------------------------------------------------

    #[test]
    fn pointers() {
        check!(b"0x1234", "%p", 0x1234_usize as *const c_void);
        check!(b"(nil)", "%p", ptr::null::<c_void>());
    }

    #[test]
    fn a_null_pointer_pads_on_the_wrong_side_and_that_is_faithful() {
        // `out_number` and `out_string` pad before the value when FLAGS_LEFT is
        // clear. `out_pointer`'s null path tests the flag the other way round,
        // so `%10p` left-aligns and `%-10p` right-aligns. Reproduced because
        // specification 0.8.2 forbids changing observable behaviour, and
        // verified against a real libcurl rather than assumed.
        check!(b"(nil)     |", "%10p|", ptr::null::<c_void>());
        check!(b"     (nil)|", "%-10p|", ptr::null::<c_void>());
    }

    // -- doubles ------------------------------------------------------------

    #[test]
    fn doubles() {
        // The sample value is deliberately not an approximation of a
        // mathematical constant: `3.14159` would read as pi to a reader and to
        // `clippy::approx_constant`, and nothing here is about pi.
        check!(b"1.234560", "%f", 1.23456_f64);
        check!(b"0.000000", "%f", 0.0_f64);
        check!(b"-2.500000", "%f", -2.5_f64);
        check!(b"1.23", "%.2f", 1.23456_f64);
        check!(b"      1.23|", "%10.2f|", 1.23456_f64);
        check!(b"1.23      |", "%-10.2f|", 1.23456_f64);
        check!(b"1.235", "%.3f", 1.23456_f64);
        check!(b"   1.2|", "%6.1f|", 1.23456_f64);
        check!(b"+3.500000", "%+f", 3.5_f64);
        check!(b" 3.500000", "% f", 3.5_f64);
        check!(b"3.", "%#.0f", 3.0_f64);
        check!(b"1.500000", "%lf", 1.5_f64);
    }

    #[test]
    fn zero_padding_is_never_forwarded_to_a_double() {
        // `out_double` assembles a format from the flags but omits
        // FLAGS_PAD_NIL, so `%08.2f` pads with spaces. This is curl's
        // behaviour, not the C library's, and the fixture corpus may depend on
        // it.
        check!(b"    1.23", "%08.2f", 1.23456_f64);
    }

    #[test]
    fn exponent_and_general_forms() {
        check!(b"3.141590e+04", "%e", 31415.9_f64);
        check!(b"3.141590E+04", "%E", 31415.9_f64);
        check!(b"1.234e-05", "%g", 0.00001234_f64);
        check!(b"1.234E-05", "%G", 0.00001234_f64);
    }

    #[test]
    fn double_rounding_is_the_c_library_s() {
        // Delegating to the platform `snprintf`, as `lib/mprintf.c:684` does,
        // is what makes these round to even rather than away from zero.
        check!(b"2", "%.0f", 2.5_f64);
        check!(b"4", "%.0f", 3.5_f64);
    }

    #[test]
    fn a_non_finite_double_terminates() {
        // `lib/mprintf.c:631` reduces the working precision with
        // `while(val >= 10.0)`, which never terminates for positive infinity.
        // The bound this module adds is the one place it departs from the C, and
        // the departure is from a hang to an answer.
        let got = with_slice(b"%.2f\0", &[Arg::Double(f64::INFINITY)]);
        assert_eq!(got, b"inf");
        let got = with_slice(b"%.2f\0", &[Arg::Double(f64::NEG_INFINITY)]);
        assert_eq!(got, b"-inf");
        let got = with_slice(b"%f\0", &[Arg::Double(f64::NAN)]);
        assert_eq!(got, b"nan");
    }

    // -- positional arguments -----------------------------------------------

    #[test]
    fn positional_arguments() {
        check!(b"one", "%1$s", cstr!("one"));
        check!(b"two one", "%2$s %1$s", cstr!("one"), cstr!("two"));
        check!(b"x-7-x", "%1$s-%2$d-%1$s", cstr!("x"), 7);
        // A positional width, which is why the argument table is typed
        // per-index rather than consumed in conversion order.
        check!(b"    42", "%2$*1$d", 6, 42);
    }

    #[test]
    fn a_positional_gap_yields_nothing() {
        // Argument one is never described, so its type is unknown and the list
        // cannot be walked at all. C returns zero without emitting; so does
        // this.
        check!(b"", "%2$d", 1, 2);
    }

    // -- unknown conversions ------------------------------------------------

    #[test]
    fn an_unknown_conversion_is_emitted_literally() {
        // The conversion switch's `default` continues without advancing, so the
        // whole run stays part of the literal text.
        check!(b"%y", "%y", 1);
        check!(b"a%zb", "a%zb");
        check!(b"abc%", "abc%");
        check!(b"%5%", "%5%");
        check!(b"%-#+ ", "%-#+ ");
    }

    // -- several conversions in one format ----------------------------------

    #[test]
    fn several_conversions() {
        check!(b"123", "%d%d%d", 1, 2, 3);
        check!(
            b"[s] -7  1.50 0xff Z",
            "[%s] %d %05.2f %#x %c",
            cstr!("s"),
            -7,
            1.5_f64,
            255,
            c_int::from(b'Z'),
        );
    }

    // -- curl_msnprintf -----------------------------------------------------

    #[test]
    fn msnprintf_truncates_and_reports_what_it_stored() {
        let mut buf = [b'#' as c_char; 64];

        // A full buffer loses its last byte to the terminator and the count is
        // decremented, so this reports four rather than the eight C99 would.
        // SAFETY: `buf` is 64 writable bytes and every bound below is smaller.
        let rc = unsafe {
            curl_msnprintf(buf.as_mut_ptr(), 5, cstr!("%s"), cstr!("abcdefgh"))
        };
        assert_eq!(rc, 4);
        assert_eq!(&buf[..5], b"abcd\0".map(|b| b as c_char));

        // Exactly full, same rule.
        buf = [b'#' as c_char; 64];
        // SAFETY: as above.
        let rc = unsafe {
            curl_msnprintf(buf.as_mut_ptr(), 9, cstr!("%s"), cstr!("abcdefgh"))
        };
        assert_eq!(rc, 8);
        assert_eq!(&buf[..9], b"abcdefgh\0".map(|b| b as c_char));

        // Room to spare: the terminator goes after the text and the count
        // stands.
        buf = [b'#' as c_char; 64];
        // SAFETY: as above.
        let rc = unsafe {
            curl_msnprintf(buf.as_mut_ptr(), 10, cstr!("%s"), cstr!("abcdefgh"))
        };
        assert_eq!(rc, 8);
        assert_eq!(&buf[..9], b"abcdefgh\0".map(|b| b as c_char));

        // One byte holds the terminator alone.
        buf = [b'#' as c_char; 64];
        // SAFETY: as above.
        let rc = unsafe {
            curl_msnprintf(buf.as_mut_ptr(), 1, cstr!("%s"), cstr!("abcdefgh"))
        };
        assert_eq!(rc, 0);
        assert_eq!(buf[0], 0);
        assert_eq!(buf[1], b'#' as c_char);
    }

    #[test]
    fn msnprintf_with_no_room_touches_nothing() {
        let mut buf = [b'#' as c_char; 8];
        // SAFETY: `buf` is writable; a bound of zero forbids any store, which
        // is exactly what the assertion checks.
        let rc = unsafe {
            curl_msnprintf(buf.as_mut_ptr(), 0, cstr!("%s"), cstr!("abcdefgh"))
        };
        assert_eq!(rc, 0);
        assert!(buf.iter().all(|&b| b == b'#' as c_char));
    }

    #[test]
    fn msnprintf_never_writes_past_the_bound() {
        // A sentinel run either side of the permitted window. The format asks
        // for far more than fits, which is the case the bounded sink exists for.
        let mut buf = [b'@' as c_char; 64];
        const BOUND: usize = 16;
        // SAFETY: `buf` is 64 bytes and `BOUND` is 16, so even a defective
        // implementation could only corrupt the sentinels the assertion reads.
        let rc = unsafe {
            curl_msnprintf(
                buf.as_mut_ptr(),
                BOUND,
                cstr!("%s%s%s%s"),
                cstr!("0123456789"),
                cstr!("0123456789"),
                cstr!("0123456789"),
                cstr!("0123456789"),
            )
        };
        assert_eq!(rc, BOUND as c_int - 1);
        assert_eq!(buf[BOUND - 1], 0, "the terminator replaces the last byte");
        for (index, &byte) in buf.iter().enumerate().skip(BOUND) {
            assert_eq!(byte, b'@' as c_char, "byte {index} was overwritten");
        }
    }

    #[test]
    fn msnprintf_terminates_an_empty_result() {
        let mut buf = [b'#' as c_char; 8];
        // SAFETY: `buf` is eight writable bytes and the bound is eight.
        let rc = unsafe { curl_msnprintf(buf.as_mut_ptr(), 8, cstr!("")) };
        assert_eq!(rc, 0);
        assert_eq!(buf[0], 0);
    }

    // -- curl_msprintf ------------------------------------------------------

    #[test]
    fn msprintf_writes_and_terminates() {
        let mut buf = [b'#' as c_char; 64];
        // SAFETY: the result is eleven bytes plus a terminator and `buf` holds
        // 64, which is the size promise `curl_msprintf` cannot check itself.
        let rc = unsafe {
            curl_msprintf(buf.as_mut_ptr(), cstr!("%s-%d"), cstr!("value"), 42)
        };
        assert_eq!(rc, 8);
        assert_eq!(&buf[..9], b"value-42\0".map(|b| b as c_char));
        assert_eq!(buf[9], b'#' as c_char);
    }

    // -- curl_mfprintf and curl_mvfprintf -----------------------------------

    /// Runs `body` against a fresh temporary stream and returns what was
    /// written to it.
    fn to_stream<F: FnOnce(*mut libc::FILE) -> c_int>(
        body: F,
    ) -> (c_int, Vec<u8>) {
        // SAFETY: `tmpfile` takes no arguments and returns either a stream open
        // for update or null, which is checked.
        let file = unsafe { libc::tmpfile() };
        assert!(!file.is_null(), "no temporary stream is available");

        let rc = body(file);

        let mut bytes = vec![0u8; 4096];
        // SAFETY: `file` is a live stream; `bytes` is 4096 writable bytes and
        // that is the size handed to `fread`. `fclose` is the last use of the
        // stream.
        let read = unsafe {
            libc::fflush(file);
            libc::rewind(file);
            let read = libc::fread(
                bytes.as_mut_ptr().cast::<c_void>(),
                1,
                bytes.len(),
                file,
            );
            libc::fclose(file);
            read
        };
        bytes.truncate(read);
        (rc, bytes)
    }

    #[test]
    fn mfprintf_writes_to_the_stream() {
        let (rc, written) = to_stream(|file| {
            // SAFETY: `file` is a stream open for update and the format names
            // exactly the two arguments that follow it.
            unsafe { curl_mfprintf(file, cstr!("%s=%04d\n"), cstr!("k"), 7) }
        });
        assert_eq!(rc, 7);
        assert_eq!(written, b"k=0007\n");
    }

    #[test]
    fn mfprintf_reports_zero_for_an_empty_result() {
        let (rc, written) = to_stream(|file| {
            // SAFETY: as above, with no arguments to name.
            unsafe { curl_mfprintf(file, cstr!("")) }
        });
        assert_eq!(rc, 0);
        assert!(written.is_empty());
    }

    // -- curl_mprintf -------------------------------------------------------

    #[test]
    fn mprintf_writes_to_the_c_library_s_stdout() {
        // The point of this test is the `STDOUT` binding: a wrong symbol name
        // would leave the sink writing nowhere. Descriptor one is redirected to
        // a temporary stream for the duration so the test harness's own output
        // is untouched, and the C-level buffer is flushed on both sides of the
        // swap so nothing crosses it.
        //
        // SAFETY: every call below is a plain descriptor operation on
        // descriptors this block itself created or duplicated, and the original
        // is restored before the block ends. `STDOUT` is the C library's own
        // stream object, present in any process linking a C library.
        let (rc, written) = to_stream(|file| unsafe {
            libc::fflush(STDOUT);
            let saved = libc::dup(1);
            assert!(saved >= 0, "descriptor one cannot be duplicated");
            assert!(libc::dup2(libc::fileno(file), 1) >= 0);

            let rc = curl_mprintf(cstr!("%s/%d"), cstr!("stdout-probe"), 3);

            libc::fflush(STDOUT);
            assert!(libc::dup2(saved, 1) >= 0);
            libc::close(saved);
            rc
        });
        assert_eq!(rc, 14);

        // Presence and multiplicity, not sole occupancy. Descriptor one is
        // process-wide and the test harness writes its own progress lines to it
        // from another thread, so a redirect held by one test can capture a
        // sibling's "... ok" line as well. Observed, not theorised: an earlier
        // spelling of this assertion compared the whole capture and failed once
        // with a neighbouring test's name in front of the payload. The needle is
        // deliberately distinctive so that a harness line cannot supply it by
        // accident, and the count pins it to exactly one write.
        let needle = b"stdout-probe/3";
        let hits = written
            .windows(needle.len())
            .filter(|w| *w == needle)
            .count();
        assert_eq!(
            hits, 1,
            "curl_mprintf must write its bytes to the C library stdout \
             exactly once, got {written:?}",
        );
    }

    // -- curl_maprintf ------------------------------------------------------

    #[test]
    fn maprintf_returns_an_allocated_empty_string_not_null() {
        // `lib/mprintf.c:1154` returns `curlx_strdup("")` when nothing was
        // produced, so null means failure and nothing else. A caller that
        // treats null as "empty" would be wrong, and one that treats it as
        // failure must not be misled.
        // SAFETY: each format below names exactly the arguments that follow
        // it. Nothing reads a slot a conversion did not ask for, so the format
        // with no conversions consumes nothing.
        unsafe {
            for got in [
                curl_maprintf(cstr!("")),
                curl_maprintf(cstr!("%s"), cstr!("")),
                curl_maprintf(cstr!("%.0d"), 0),
                curl_maprintf(cstr!("%.0s"), ptr::null::<c_char>()),
            ] {
                assert!(!got.is_null(), "an empty result must still allocate");
                assert_eq!(take(got).as_deref(), Some(&b""[..]));
            }
        }
    }

    #[test]
    fn maprintf_grows_past_its_first_allocation() {
        // The growth schedule starts at 32 bytes and doubles, so a result well
        // past that exercises the `realloc` path rather than only the first
        // allocation.
        let mut expected = Vec::new();
        for _ in 0..200 {
            expected.extend_from_slice(b"0123456789");
        }
        let mut format = Vec::new();
        for _ in 0..200 {
            format.extend_from_slice(b"0123456789");
        }
        format.push(0);
        // SAFETY: the format is NUL-terminated and names no conversion.
        let got = unsafe { curl_maprintf(format.as_ptr().cast::<c_char>()) };
        assert_eq!(take(got).as_deref(), Some(&expected[..]));
    }

    #[test]
    fn maprintf_survives_application_supplied_allocators() {
        // The block `curl_maprintf` returns must come from whatever allocator
        // `curl_global_init_mem` installed, because `curl_free` will release it
        // through that same allocator. A mismatch is heap corruption rather
        // than a wrong answer, so the pairing is asserted rather than assumed.
        assert!(!memory::is_installed(), "another test left hooks installed");
        check!(b"pair", "%s", cstr!("pair"));
    }

    // -- %n ------------------------------------------------------------------

    #[test]
    fn pct_n_reports_the_count_so_far() {
        let mut count: c_int = -1;
        // SAFETY: `%n` is given a pointer to a live `c_int`, which is the width
        // the absent length modifiers select.
        let got = unsafe {
            curl_maprintf(
                cstr!("abc%ndef"),
                (&mut count as *mut c_int).cast::<c_void>(),
            )
        };
        assert_eq!(take(got).as_deref(), Some(&b"abcdef"[..]));
        assert_eq!(count, 3);
    }

    #[test]
    fn pct_n_with_a_null_pointer_declines_rather_than_crashing() {
        // No correct use of `%n` can pass null, so declining cannot change a
        // legitimate result -- and C would have dereferenced it.
        // SAFETY: the format names one pointer argument and one is supplied.
        let got = unsafe {
            curl_maprintf(cstr!("ab%ncd"), ptr::null_mut::<c_void>())
        };
        assert_eq!(take(got).as_deref(), Some(&b"abcd"[..]));
    }

    #[test]
    fn pct_n_honours_the_length_modifiers() {
        let mut wide: i64 = -1;
        assert_eq!(
            with_slice(
                b"1234%lln\0",
                &[Arg::Ptr((&mut wide as *mut i64).cast::<c_void>())],
            ),
            b"1234",
        );
        assert_eq!(wide, 4);

        let mut narrow: i16 = -1;
        assert_eq!(
            with_slice(
                b"12345%hn\0",
                &[Arg::Ptr((&mut narrow as *mut i16).cast::<c_void>())],
            ),
            b"12345",
        );
        assert_eq!(narrow, 5);
    }

    // -- parse failures ------------------------------------------------------

    #[test]
    fn a_parse_failure_produces_no_output_rather_than_an_error_code() {
        // `formatf` returns zero having emitted nothing, which is the only
        // signal C gives. Reproduced so a caller cannot tell the two apart.
        //
        // Positional and sequential cannot be mixed: once one conversion has
        // used `n$`, every later one must.
        assert_eq!(with_slice(b"%1$d %d\0", &[Arg::Int(1)]), b"");
    }

    #[test]
    fn an_unusable_position_falls_back_to_literal_text() {
        // A subtlety worth pinning, because the obvious guess is wrong and this
        // was measured against a real libcurl rather than reasoned out.
        // `dollarstring` bounds the index by MAX_PARAMETERS and rejects zero,
        // and on failure it leaves the cursor untouched and merely gives up on
        // positional mode. The digits are then re-read as a *width*, the `$`
        // is an unknown conversion, and the whole run survives as literal text.
        assert_eq!(with_slice(b"%129$d\0", &[Arg::Int(1)]), b"%129$d");
        assert_eq!(with_slice(b"%0$d\0", &[Arg::Int(1)]), b"%0$d");
    }

    #[test]
    fn a_precision_of_both_kinds_is_refused() {
        // `%.5.*d` sets FLAGS_PREC then FLAGS_PRECPARAM, which is the one
        // combination `parsefmt` rejects outright. The reverse order is refused
        // too, since the test is on the pair of flags rather than on the order.
        assert_eq!(with_slice(b"%.5.*d\0", &[Arg::Int(1), Arg::Int(2)]), b"");
        assert_eq!(with_slice(b"%.*.5d\0", &[Arg::Int(1), Arg::Int(2)]), b"");
        // Two `.*` in a row set only PRECPARAM, so they are accepted and the
        // second wins -- measured, not assumed.
        assert_eq!(with_slice(b"%.*.*d\0", &[Arg::Int(1), Arg::Int(2)]), b"2",);
    }

    #[test]
    fn a_positional_width_may_not_reuse_an_argument() {
        // `parsefmt` marks each slot as it is claimed and the width block runs
        // before the value block *of its own conversion*, so the check catches
        // a slot claimed by an EARLIER conversion.
        assert_eq!(
            with_slice(b"%1$d%2$*1$d\0", &[Arg::Int(4), Arg::Int(5)]),
            b"",
        );
        assert_eq!(
            with_slice(b"%1$d%2$.*1$d\0", &[Arg::Int(4), Arg::Int(5)]),
            b"",
        );
    }

    #[test]
    fn one_conversion_may_take_its_width_and_value_from_one_slot() {
        // The corollary, and the reason the test above is worded as it is:
        // within a single conversion the value block overwrites the width
        // block's type, so `%1$*1$d` reads argument one once and uses it as
        // both. Measured against a real libcurl: `%1$*1$d` of 4 gives three
        // spaces and a `4`.
        assert_eq!(with_slice(b"%1$*1$d\0", &[Arg::Int(4)]), b"   4");
    }

    #[test]
    fn an_overlong_width_or_precision_is_refused() {
        // Beyond `INT_MAX`, `curlx_str_number` reports overflow and the whole
        // format is abandoned.
        assert_eq!(with_slice(b"%99999999999d\0", &[Arg::Int(1)]), b"");
        assert_eq!(with_slice(b"%.99999999999d\0", &[Arg::Int(1)]), b"");
    }

    #[test]
    fn more_segments_than_the_table_holds_are_refused() {
        // 128 segments fit; the 129th does not, and the whole format is
        // abandoned rather than truncated.
        let mut format = Vec::new();
        let mut args = Vec::new();
        for _ in 0..MAX_SEGMENTS {
            format.extend_from_slice(b"%d");
            args.push(Arg::Int(1));
        }
        format.push(0);
        assert_eq!(with_slice(&format, &args).len(), MAX_SEGMENTS);

        // One more conversion needs a 129th segment.
        let mut format = Vec::new();
        let mut args = Vec::new();
        for _ in 0..=MAX_SEGMENTS {
            format.extend_from_slice(b"%d");
            args.push(Arg::Int(1));
        }
        format.push(0);
        assert_eq!(with_slice(&format, &args), b"");
    }

    // -- null arguments ------------------------------------------------------

    #[test]
    fn a_null_format_is_refused_rather_than_dereferenced() {
        // C would crash. Every entry point declines instead, with the failure
        // value its return type can express: a negative `int`, or null.
        let null = ptr::null::<c_char>();
        let mut buf = [0 as c_char; 8];

        // SAFETY: each call is given a null format deliberately; that is the
        // condition under test and every entry point checks it before use.
        unsafe {
            assert!(curl_msnprintf(buf.as_mut_ptr(), 8, null) < 0);
            assert!(curl_msprintf(buf.as_mut_ptr(), null) < 0);
            assert!(curl_mprintf(null) < 0);
            assert!(curl_maprintf(null).is_null());
        }
        let (rc, written) = to_stream(|file| {
            // SAFETY: as above.
            unsafe { curl_mfprintf(file, null) }
        });
        assert!(rc < 0);
        assert!(written.is_empty());
    }

    #[test]
    fn a_null_destination_is_refused() {
        // SAFETY: the null destinations below are the condition under test.
        unsafe {
            assert!(
                curl_msnprintf(ptr::null_mut(), 8, cstr!("x")) < 0,
                "a bound above zero needs a buffer",
            );
            assert_eq!(
                curl_msnprintf(ptr::null_mut(), 0, cstr!("x")),
                0,
                "a bound of zero never touches the buffer, so null is fine",
            );
            assert!(curl_msprintf(ptr::null_mut(), cstr!("x")) < 0);
            assert!(curl_mfprintf(ptr::null_mut(), cstr!("x")) < 0);
        }
    }

    #[test]
    fn a_null_argument_list_is_harmless_until_a_conversion_needs_it() {
        // C dereferences a `va_list` only when a conversion asks for a value,
        // so a format with none is safe. The `va_list` entry points are called
        // directly here because that is the only way to present a null list.
        //
        // SAFETY: a null `ap` is the condition under test, and every entry
        // point routes it to `None` rather than dereferencing it.
        unsafe {
            let got = curl_mvaprintf(cstr!("plain text"), ptr::null_mut());
            assert_eq!(take(got).as_deref(), Some(&b"plain text"[..]));

            // A conversion with nothing to read from yields nothing, which is
            // the same signal every other parse failure gives.
            let got = curl_mvaprintf(cstr!("%d"), ptr::null_mut());
            assert_eq!(take(got).as_deref(), Some(&b""[..]));
        }
    }

    // -- the argument-list abstraction ---------------------------------------

    #[test]
    fn a_supplied_argument_list_covers_every_fetch() {
        // Nine `Arg` variants against nine `ArgSource` methods, so the mapping
        // is exercised rather than assumed. This is also what keeps the
        // dead-code allowance on `Arg` scoped to non-test builds honest.
        assert_eq!(with_slice(b"%s\0", &[Arg::Str(cstr!("s"))]), b"s");
        assert_eq!(
            with_slice(b"%p\0", &[Arg::Ptr(0x20_usize as *mut c_void)]),
            b"0x20",
        );
        assert_eq!(with_slice(b"%d\0", &[Arg::Int(-3)]), b"-3");
        assert_eq!(with_slice(b"%u\0", &[Arg::Uint(3)]), b"3");
        assert_eq!(with_slice(b"%ld\0", &[Arg::Long(-4)]), b"-4");
        assert_eq!(with_slice(b"%lu\0", &[Arg::Ulong(4)]), b"4");
        assert_eq!(with_slice(b"%lld\0", &[Arg::LongLong(-5)]), b"-5");
        assert_eq!(with_slice(b"%llu\0", &[Arg::UlongLong(5)]), b"5");
        assert_eq!(with_slice(b"%.1f\0", &[Arg::Double(6.25)]), b"6.2");
    }

    #[test]
    fn a_width_argument_is_read_from_the_same_slot_as_a_value() {
        // C's argument table is a union, so a slot claimed as a width and a
        // slot claimed as a value are the same storage. `%2$*1$d` proves the
        // indices are honoured independently of the conversion order.
        assert_eq!(
            with_slice(b"%2$*1$d|\0", &[Arg::Int(6), Arg::Int(42)]),
            b"    42|",
        );
    }

    // -- register and stack transitions --------------------------------------

    #[test]
    fn arguments_beyond_the_register_file_are_read_from_the_stack() {
        // The trampoline saves six general-purpose and eight vector registers
        // on x86-64, and eight of each on AAPCS64. A format that consumes more
        // than either crosses from the save area into the caller's own stack
        // arguments, which is the transition most likely to be wrong and least
        // likely to be noticed.
        check!(
            b"1 2 3 4 5 6 7 8 9 10 11 12",
            "%d %d %d %d %d %d %d %d %d %d %d %d",
            1,
            2,
            3,
            4,
            5,
            6,
            7,
            8,
            9,
            10,
            11,
            12,
        );
        check!(
            b"1.5 2.5 3.5 4.5 5.5 6.5 7.5 8.5 9.5 10.5",
            "%.1f %.1f %.1f %.1f %.1f %.1f %.1f %.1f %.1f %.1f",
            1.5_f64,
            2.5_f64,
            3.5_f64,
            4.5_f64,
            5.5_f64,
            6.5_f64,
            7.5_f64,
            8.5_f64,
            9.5_f64,
            10.5_f64,
        );
        // Interleaved, so the two cursors have to advance independently.
        check!(
            b"1 1.5 2 2.5 3 3.5 4 4.5 5 5.5 6 6.5 7 7.5",
            "%d %.1f %d %.1f %d %.1f %d %.1f %d %.1f %d %.1f %d %.1f",
            1,
            1.5_f64,
            2,
            2.5_f64,
            3,
            3.5_f64,
            4,
            4.5_f64,
            5,
            5.5_f64,
            6,
            6.5_f64,
            7,
            7.5_f64,
        );
        // Pointers and strings share the general-purpose cursor with integers.
        check!(
            b"a b c d e f g h",
            "%s %s %s %s %s %s %s %s",
            cstr!("a"),
            cstr!("b"),
            cstr!("c"),
            cstr!("d"),
            cstr!("e"),
            cstr!("f"),
            cstr!("g"),
            cstr!("h"),
        );
    }

    // -- structure and ABI ---------------------------------------------------

    #[test]
    fn the_va_list_record_matches_the_target_abi() {
        #[cfg(target_arch = "x86_64")]
        {
            // Measured with gcc: `sizeof(va_list)` is 24 and its alignment 8,
            // `__va_list_tag` being two 32-bit cursors and two pointers.
            assert_eq!(core::mem::size_of::<SysvVaList>(), 24);
            assert_eq!(core::mem::align_of::<SysvVaList>(), 8);
        }
        #[cfg(all(target_arch = "aarch64", not(target_vendor = "apple")))]
        {
            // Measured with aarch64-linux-gnu-gcc: three pointers and two
            // 32-bit offsets, so 32 bytes.
            assert_eq!(core::mem::size_of::<Aapcs64VaList>(), 32);
            assert_eq!(core::mem::align_of::<Aapcs64VaList>(), 8);
        }
        #[cfg(all(target_arch = "aarch64", target_vendor = "apple"))]
        {
            // Apple arm64's `va_list` is `char *`, so there is no record.
            assert_eq!(core::mem::size_of::<CVaList>(), 1);
        }
    }

    #[test]
    fn the_scratch_buffer_cannot_be_overrun_by_the_widest_conversion() {
        // `out_number` fills backwards from `WORKEND`, and the widest possible
        // digit run is 64 bits in base eight -- 22 digits -- plus a `0` prefix.
        // The buffer is 328 bytes, so the margin is large; the assertion pins
        // the relationship rather than the numbers.
        let widest = with_slice(b"%#llo\0", &[Arg::UlongLong(u64::MAX)]);
        assert_eq!(widest, b"01777777777777777777777");
        assert!(widest.len() < WORKEND);
    }

    #[test]
    fn the_family_is_exactly_ten_symbols_defined_once_each() {
        // The nm parity gate compares all 100 exported symbols as one set, so a
        // missing or duplicated definition fails it outright. Asserted from the
        // source because a build script cannot ask the compiler and this module
        // is where the ten live.
        let source = production_source();

        // The five `va_list` forms are Rust functions.
        for name in [
            "curl_mvprintf",
            "curl_mvfprintf",
            "curl_mvsprintf",
            "curl_mvsnprintf",
            "curl_mvaprintf",
        ] {
            let definition = format!("pub unsafe extern \"C\" fn {name}(");
            assert_eq!(
                source.matches(&definition).count(),
                1,
                "{name} must be defined exactly once",
            );
        }

        // The five plain-variadic forms are trampolines, one invocation each.
        for name in [
            "curl_mprintf",
            "curl_mfprintf",
            "curl_msprintf",
            "curl_msnprintf",
            "curl_maprintf",
        ] {
            let invocation = format!("export = \"{name}\",");
            assert_eq!(
                source.matches(&invocation).count(),
                1,
                "{name} must have exactly one trampoline",
            );
            let definition = format!("extern \"C\" fn {name}(");
            assert!(
                !source.contains(&definition),
                "{name} is variadic and must not be a Rust function",
            );
        }

        assert_eq!(
            source.matches("variadic_trampoline! {").count(),
            5,
            "five trampolines, one per plain-variadic form",
        );
        // One macro arm per object format and architecture, so no required
        // target is left without an exporter.
        assert_eq!(
            source.matches("macro_rules! variadic_trampoline").count(),
            4,
            "four ABI flavours: x86-64 and aarch64, ELF and Mach-O",
        );
        assert_eq!(source.matches("\".globl \", $name").count(), 2, "ELF");
        assert_eq!(source.matches("\".globl _\", $name").count(), 2, "Mach-O");
    }

    #[test]
    fn the_cdylib_export_gap_is_recorded_and_no_linker_flag_papers_over_it() {
        // MEASURED DEFECT, kept visible here because this module is the only
        // thing in the crate it affects. `.globl` is necessary but not
        // sufficient: rustc builds a cdylib's export list from Rust items
        // carrying `#[no_mangle]` and hands the linker an anonymous version
        // script shaped `{ global: <those items>; local: *; };`. An assembled
        // label matches nothing in `global:`, falls to the wildcard, is
        // localised, and -- being unreferenced -- is discarded. On
        // x86_64-unknown-linux-gnu, in both profiles,
        // `nm -D --defined-only libcurl.so` reports FIVE of this family and
        // `nm -a | grep curl_mprintf` reports none at all in a symbol table of
        // 2703 entries, while `nm --defined-only libcurl.a` reports all ten as
        // `T`. Every test in this module still passes either way, because a test
        // binary links the rlib, where the labels are plainly visible.
        //
        // Eight linker routes were measured and seven do nothing at all;
        // the eighth, a second anonymous version script, works only under LLD
        // and FAILS THE LINK under GNU ld with "anonymous version tag cannot be
        // combined with other version tags" -- which is three of the four
        // required targets, including the 1.75 floor. It was implemented,
        // verified, and removed. The full matrix and the three rejected
        // alternatives are in `build.rs` under "Trap 3".
        //
        // This test therefore asserts the two things that must stay true: the
        // finding is on the record, and nobody has quietly re-added the flag
        // that breaks three targets.
        let build = include_str!("../../build.rs");

        // The finding is recorded, with the numbers that make it checkable.
        for evidence in [
            "MEASURED FINDING, Trap 3",
            "anonymous version tag cannot be combined",
            "declaration discipline, not from link-time filtering",
            "specification 0.6.2 says of precisely this class of hazard",
        ] {
            assert!(
                build.contains(evidence),
                "the cdylib export finding must stay recorded: {evidence}",
            );
        }

        // And no linker flag is emitted to paper over it. A `cargo:` directive
        // is a `println!`, so the needle is the emission and not the prose that
        // explains why there is none -- hence the `cargo:` prefix rather than
        // the bare flag name, which appears throughout the discussion above it.
        for forbidden in [
            "cargo:rustc-link-arg-cdylib=-Wl,--version-script",
            "cargo:rustc-link-arg=-Wl,--version-script",
            "cargo:rustc-link-arg-cdylib=-Wl,--export-dynamic-symbol",
            "cargo:rustc-link-arg-cdylib=-Wl,--dynamic-list",
            "cargo:rustc-link-arg-cdylib=-Wl,-exported_symbol",
        ] {
            assert!(
                !build.contains(forbidden),
                "{forbidden} was measured not to work, or to break three of \
                 the four required targets; it must not be re-added",
            );
        }

        // The soname directives that DO work are untouched by any of this.
        assert!(
            build.contains("cargo:rustc-link-arg-cdylib=-Wl,--soname="),
            "the Linux soname directive must survive",
        );
        assert!(
            build.contains("cargo:rustc-link-arg-cdylib=-Wl,-install_name,"),
            "the Apple install-name directive must survive",
        );

        // The five names still come from one table, so the trampoline check and
        // any future export work can never disagree about which they are.
        for name in [
            "curl_mprintf",
            "curl_mfprintf",
            "curl_msprintf",
            "curl_msnprintf",
            "curl_maprintf",
        ] {
            assert!(
                build.contains(&format!("(\"{name}\", \"curl_mv")),
                "{name} must appear in PRINTF_TRAMPOLINES",
            );
        }
    }

    #[test]
    fn no_nightly_feature_is_used_anywhere_in_this_module() {
        // The declared minimum is 1.75, where `c_variadic` and `VaList` are
        // unstable. The trampolines exist precisely so that neither is needed,
        // and a later edit reaching for them would be a silent MSRV rise.
        //
        // `VaList` alone is not a usable needle -- this module's own
        // `SysvVaList` and `Aapcs64VaList` contain it -- so the needles are the
        // paths and call shapes the unstable API actually requires.
        let source = production_source();
        for forbidden in [
            "#![feature(",
            "#[feature(",
            "feature(c_variadic)",
            "VaListImpl",
            "::VaList",
            "next_arg::",
            "va_copy",
        ] {
            assert!(
                !source.contains(forbidden),
                "{forbidden} is not available at the declared MSRV of 1.75",
            );
        }
    }

    #[test]
    fn the_header_declares_all_ten_with_their_measured_index_pairs() {
        // `CURL_TEMP_PRINTF(format_index, first_vararg_index)` becomes a GCC
        // format attribute, so a transposed pair is a `-Wformat` error in every
        // one of the 129 programs under docs/examples that includes the header
        // -- and in nothing this crate compiles. Pinning the pairs here is what
        // makes that failure impossible to reach by editing Rust alone.
        let header = include_str!("../../../include/curl/mprintf.h");
        for (name, pair) in [
            ("curl_mprintf", "CURL_TEMP_PRINTF(1, 2)"),
            ("curl_mfprintf", "CURL_TEMP_PRINTF(2, 3)"),
            ("curl_msprintf", "CURL_TEMP_PRINTF(2, 3)"),
            ("curl_msnprintf", "CURL_TEMP_PRINTF(3, 4)"),
            ("curl_mvprintf", "CURL_TEMP_PRINTF(1, 0)"),
            ("curl_mvfprintf", "CURL_TEMP_PRINTF(2, 0)"),
            ("curl_mvsprintf", "CURL_TEMP_PRINTF(2, 0)"),
            ("curl_mvsnprintf", "CURL_TEMP_PRINTF(3, 0)"),
            ("curl_maprintf", "CURL_TEMP_PRINTF(1, 2)"),
            ("curl_mvaprintf", "CURL_TEMP_PRINTF(1, 0)"),
        ] {
            let at = header
                .find(&format!("{name}("))
                .unwrap_or_else(|| panic!("{name} is not declared"));
            let declaration = &header[at..];
            let end = declaration
                .find(';')
                .unwrap_or_else(|| panic!("{name}'s declaration never ends"));
            assert!(
                declaration[..end].contains(pair),
                "{name} must carry {pair}",
            );
        }

        // Ten uses, plus the four definitions of the five-branch block --
        // three conditional forms and the empty fallback. The `va_list` forms
        // take no varargs, so their second index is zero; reversed, the
        // attribute would name an argument that does not exist.
        assert_eq!(header.matches("#define CURL_TEMP_PRINTF(").count(), 4);
        assert_eq!(header.matches("CURL_TEMP_PRINTF(").count(), 14);
        // And the macro is withdrawn afterwards rather than leaked to
        // consumers.
        assert!(header.contains("#undef CURL_TEMP_PRINTF"));
        assert!(header.contains("#endif /* CURLINC_MPRINTF_H */"));
    }

    #[test]
    fn the_two_char_pointer_returns_are_distinguished_from_the_eight_int_ones()
    {
        // Getting this wrong compiles cleanly on the Rust side and breaks every
        // C consumer, so it is asserted from the header rather than trusted.
        let header = include_str!("../../../include/curl/mprintf.h");
        for name in ["curl_maprintf", "curl_mvaprintf"] {
            let at = header.find(&format!("{name}(")).unwrap();
            assert!(
                header[..at].ends_with("char *"),
                "{name} must return char *",
            );
        }
        for name in [
            "curl_mprintf",
            "curl_mfprintf",
            "curl_msprintf",
            "curl_msnprintf",
            "curl_mvprintf",
            "curl_mvfprintf",
            "curl_mvsprintf",
            "curl_mvsnprintf",
        ] {
            let at = header.find(&format!("{name}(")).unwrap();
            assert!(header[..at].ends_with("int "), "{name} must return int",);
        }
    }
}
