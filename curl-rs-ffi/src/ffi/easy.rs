// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! The `curl_easy_*` option-introspection exports.
//!
//! Supersedes `lib/easygetopt.c`.
//!
//! Three of the twenty-one `curl_easy_*` symbols in `lib/libcurl.def` describe
//! the option table rather than operating on an easy handle:
//!
//! - `curl_easy_option_by_name`
//! - `curl_easy_option_by_id`
//! - `curl_easy_option_next`
//!
//! They are implementable today because their entire backing store is the
//! option metadata table, which this crate already owns as the sole source of
//! truth for option identity (AAP section 0.1.2). The remaining eighteen
//! `curl_easy_*` symbols operate on an easy handle and a transfer engine, and
//! neither layer exists yet; they are therefore absent rather than stubbed, so
//! that a consumer linking against them gets a link error naming the symbol
//! instead of a runtime answer that is silently wrong.
//!
//! # One table, projected twice, searched once
//!
//! [`super::opts::EASY_OPTIONS`] is the authority. It is a pure-Rust table with
//! no raw pointers, which is what lets `opts.rs` stay free of `unsafe`. Two
//! consumers need it in a shape it is not already in, so this module holds two
//! `const fn`-derived projections of that single authority and no table of its
//! own:
//!
//! - [`TABLE`] -- the C form. An array of [`curl_easyoption`] with a
//!   `*const c_char` name and a NULL-named terminating row, built by
//!   [`project`]. This is the memory whose addresses the three exports hand
//!   out, so it must exist in exactly the layout a C caller reads.
//! - [`ENGINE_VIEW`] -- the engine form. An array of
//!   [`curl_rs_lib::easy::options::EasyOption`], built by [`project_engine`].
//!   This is what the *search* runs over.
//!
//! Neither is a second table:
//!
//! - Both are `const fn`-derived from `EASY_OPTIONS`, so a row cannot be added,
//!   removed, reordered or edited on one side only. Verified at MSRV 1.75.
//! - The names in both are the same `&'static [u8]` literals `opts.rs`
//!   declares, NUL included; each projection takes their address rather than
//!   copying them.
//! - The two `const` assertions below pin both lengths to the authority's, and
//!   the tests walk all three in lockstep.
//!
//! # Where the lookup algorithm lives, and why it is not here
//!
//! `lib/easygetopt.c` is a library file, not a tool file, so its algorithm
//! belongs to the engine: `curl_rs_lib::easy::options` owns
//! [`by_name`](curl_rs_lib::easy::options::by_name),
//! [`by_id`](curl_rs_lib::easy::options::by_id),
//! [`next`](curl_rs_lib::easy::options::next) and the
//! [`lookup`](curl_rs_lib::easy::options::lookup) they share. Each of the three
//! exports below therefore does exactly three things -- validate the pointer or
//! integer a C caller supplied, call the engine over [`ENGINE_VIEW`], and turn
//! the row the engine chose back into an address in [`TABLE`]. No comparison,
//! no `break` on the sentinel, and no index arithmetic that decides *which* row
//! is the answer appears in this file any more.
//!
//! That direction is required rather than tidy. This crate is a leaf adapter
//! (AAP section 0.1.1 G1); a search written here would be a second
//! implementation of a library algorithm, free to disagree with the engine's
//! about case folding, about whether an alias row is a candidate, and about
//! where a walk stops -- and nothing would have caught the disagreement,
//! because the engine's version had no consumer to disagree with.
//!
//! The engine also owns the check that its own three entry points agree about
//! every row of a table it is handed,
//! [`first_inconsistent_row`](curl_rs_lib::easy::options::first_inconsistent_row).
//! Its documentation says the crate that owns the table is the one that must
//! run it, because the acyclicity rule keeps the table out of reach from the
//! engine's own tests. This crate owns the table, so this module runs it.
//!
//! # Row order is part of the contract
//!
//! `curl_easy_option_next` hands out consecutive elements of this array, so a
//! consumer enumerating options observes the array's order. `lib/optiontable.pl`
//! emits rows sorted alphabetically by the stripped name with the sentinel last,
//! `opts.rs` preserves that order, and the oracle test in this module asserts all
//! 323 real rows against the order the frozen `libcurl.so.4` actually produces.
//!
//! # Why the two lookup parameters are `c_int`
//!
//! The frozen header declares `curl_easy_option_by_id(CURLoption id)`. Measured
//! against `libcurl.so.4.8.0`, the C accepts and answers for values that are not
//! `CURLoption` variants at all -- `0`, `1`, `2`, `-1`, `99999`, `30005`,
//! `40025`, `10329` and `INT_MAX` all return NULL rather than misbehaving. A C
//! caller may therefore legally pass any `int`. Materialising such a value in a
//! Rust `#[repr(C)]` enum parameter would be undefined behaviour, so the Rust
//! parameter is `c_int` and the variant is recovered by comparison instead of by
//! transmutation. The declaration a consumer compiles against is unchanged; only
//! this side's spelling differs, and it differs in the direction that is sound.

use core::ffi::{c_char, c_int, CStr};

use curl_rs_lib::easy::options::{
    self as options, EasyOption, EasyType, OptionFlags, OptionId,
};

use super::opts::{EasyOptionRow, EASY_OPTIONS, EASY_OPTION_ROWS};
use super::panic_boundary::guard_const_ptr;
use super::types::curl_easyoption;

/// The number of rows in the C projection, including the terminating sentinel.
///
/// Taken from the authority rather than restated, so the two cannot drift.
const ROWS: usize = EASY_OPTION_ROWS;

// Asserts at compile time that the constant above really does describe
// `EASY_OPTIONS`. `EASY_OPTION_ROWS` is now DERIVED from that table --
// `EASY_OPTIONS.len()` -- and pinned in `opts.rs` by a `const` assertion
// against `lib/optiontable.pl`'s measured 324 rows, so this assertion can no
// longer fail. It is retained deliberately rather than deleted: it is what
// makes the array length below provably the table length AT THIS USE SITE,
// and it is the check that would fire first if the authority were ever
// reverted to a transcribed literal. The binding is anonymous so that the
// assertion needs no reference to keep it alive.
const _: () = assert!(EASY_OPTIONS.len() == ROWS);

/// The value every field of an unwritten projection slot holds before
/// [`project`] fills it in.
///
/// A repeat-expression array needs a seed. Using an all-zero row rather than a
/// copy of a real one means that a projection bug which skipped a slot would
/// leave a NULL-named row behind, which the walk treats as the end of the table
/// and the oracle test then catches as a short row count -- a loud failure
/// rather than a duplicated entry.
const UNWRITTEN: curl_easyoption = curl_easyoption {
    name: core::ptr::null(),
    id: 0,
    r#type: 0,
    flags: 0,
};

/// Projects one authority row into its C form.
///
/// `name` becomes a pointer into the row's own `&'static [u8]` literal, which
/// already carries the terminating NUL, so no allocation or copy occurs and the
/// pointer is valid for the life of the process. The sentinel's `None` becomes
/// the NULL that a consumer's loop condition tests.
const fn project_row(row: &EasyOptionRow) -> curl_easyoption {
    let name = match row.name {
        Some(bytes) => bytes.as_ptr() as *const c_char,
        None => core::ptr::null(),
    };
    curl_easyoption {
        name,
        id: row.id as c_int,
        r#type: row.value_type as c_int,
        flags: row.flags,
    }
}

/// Builds the whole projection during const evaluation.
const fn project() -> [curl_easyoption; ROWS] {
    let mut out = [UNWRITTEN; ROWS];
    let mut index = 0;
    while index < ROWS {
        out[index] = project_row(&EASY_OPTIONS[index]);
        index += 1;
    }
    out
}

/// Wrapper that lets the projection be a `static`.
///
/// [`curl_easyoption`] holds a raw pointer and so is not `Sync`, which a
/// `static` requires. The wrapper carries the assertion rather than the ABI
/// struct, so the ABI struct keeps the auto-trait behaviour a raw pointer
/// implies and only this immutable table opts out.
#[repr(transparent)]
struct OptionTable([curl_easyoption; ROWS]);

// SAFETY: `OptionTable` is immutable for the life of the program -- it is a
// `static` with no interior mutability and nothing in this crate takes a
// `&mut` to it. Its only non-`Sync` component is each row's `name`, which
// points into a `&'static [u8]` literal in `opts.rs`: read-only, always valid,
// and never freed. Sharing it across threads therefore permits nothing beyond
// concurrent reads of immortal constants.
unsafe impl Sync for OptionTable {}

/// The C-layout option table. Derived, never hand-maintained.
static TABLE: OptionTable = OptionTable(project());

/// The first element's address, which every returned pointer is an offset from.
fn base() -> *const curl_easyoption {
    TABLE.0.as_ptr()
}

/// Projects one authority row into the engine's normalized row.
///
/// The three conversions are each a narrowing that would otherwise have to be
/// trusted, and each is checked here during const evaluation, so a malformed
/// row is a compile error rather than a wrong answer at run time:
///
/// * The name becomes a `&'static CStr` through
///   [`CStr::from_bytes_with_nul`], which is `const` from Rust 1.72 and so is
///   available at MSRV 1.75. It rejects a name with no terminator or with an
///   interior NUL. The previous hand-written search reached the same value with
///   `.ok()` and silently treated a malformed name as the table's terminator,
///   which would have truncated the walk.
/// * The type integer becomes an [`EasyType`] through its own total
///   constructor. A value outside the nine `CURLOT_*` members cannot be
///   projected at all.
/// * `id` and `flags` are the same integers, in the engine's newtypes.
///
/// The `&'static [u8]` the name points into is `opts.rs`'s own literal, so this
/// borrows rather than copies and the two projections name the same bytes.
const fn project_engine_row(row: &EasyOptionRow) -> EasyOption {
    let name = match row.name {
        Some(bytes) => match CStr::from_bytes_with_nul(bytes) {
            Ok(text) => Some(text),
            Err(_) => panic!(
                "an option name must end in exactly one NUL and contain no \
                 other"
            ),
        },
        None => None,
    };
    let value_type = match EasyType::from_i32(row.value_type as i32) {
        Some(kind) => kind,
        None => panic!("an option row carries a type outside CURLOT_*"),
    };

    EasyOption {
        name,
        id: OptionId(row.id as i32),
        value_type,
        flags: OptionFlags(row.flags),
    }
}

/// Builds the engine projection during const evaluation.
const fn project_engine() -> [EasyOption; ROWS] {
    // The seed is the sentinel's own shape for the same reason [`UNWRITTEN`] is
    // all-zero: a projection bug that skipped a slot leaves a name-less row,
    // which the engine's walk treats as the end of the table and the
    // consistency check below then reports.
    let mut out = [EasyOption {
        name: None,
        id: OptionId(0),
        value_type: EasyType::Long,
        flags: OptionFlags::NONE,
    }; ROWS];
    let mut index = 0;
    while index < ROWS {
        out[index] = project_engine_row(&EASY_OPTIONS[index]);
        index += 1;
    }
    out
}

/// The engine-layout option table. Derived, never hand-maintained.
///
/// Needs no `Sync` wrapper: every field of [`EasyOption`] is a shared reference
/// to immortal data or a plain integer, so the array is `Sync` on its own terms
/// and this `static` asserts nothing. That is the difference the two
/// projections make plain -- only the C form has to carry a raw pointer, and
/// only the C form has to opt out of the auto trait.
static ENGINE_VIEW: [EasyOption; ROWS] = project_engine();

// NO `const` LENGTH ASSERTION ON `ENGINE_VIEW`, and the absence is reasoned
// rather than an omission -- the guarantee exists twice over without one, and
// the assertion could not be written portably anyway.
//
// It cannot be written: `const _: () = assert!(ENGINE_VIEW.len() == ROWS);`
// compiles on the pinned 1.97.1 and is `error[E0013]: constants cannot refer to
// statics` on the 1.75.0 floor. Measured -- it took `cargo +1.75.0 build
// --workspace` down on its own, which is precisely what the MSRV gate is for.
//
// It is not needed:
//
//   * the `static`'s own type annotation is `[EasyOption; ROWS]`, so a
//     projection of any other length does not type-check at all; and
//   * `project_engine` indexes `EASY_OPTIONS[index]` for every `index < ROWS`,
//     so an authority shorter than `ROWS` is an out-of-bounds index during
//     const evaluation -- a compile error, not a short table.
//
// `EASY_OPTIONS.len() == ROWS` is asserted above, over a `const`, which is
// legal on both toolchains; and `the_engine_projection_mirrors_the_authority_row_for_row`
// asserts the two lengths agree at run time as well.

/// The identifier C's `by_name` searches for when it is handed a NULL name.
///
/// `lib/easygetopt.c:55` spells this `CURLOPT_LASTENTRY`, and reaching it is
/// not an accident of the C: `curl_easy_option_by_name` is
/// `lookup(name, CURLOPT_LASTENTRY)`, so a NULL name falls into the id branch
/// with that identifier. Only the never-examined sentinel carries it, so the
/// search finds nothing. Named here so the NULL case can take that route
/// literally rather than short-circuiting past it.
const LASTENTRY: OptionId =
    OptionId(super::opts::CURLoption::CURLOPT_LASTENTRY as i32);

/// The index in [`ENGINE_VIEW`] of a row the engine returned.
///
/// Found by identity rather than by arithmetic. Every row the engine hands back
/// is an element of the slice it was given, so a subtraction of addresses would
/// also be correct -- but a scan comparing addresses *proves* that, where the
/// subtraction would assume it, and an option-introspection lookup is not a hot
/// path (AAP section 0.1.1 makes performance an explicit non-goal). The row is
/// never dereferenced through a raw pointer, so no `unsafe` is involved.
///
/// [`ENGINE_VIEW`] and [`TABLE`] are projections of one authority in one order,
/// so the index is equally an index into the C form.
fn engine_index(row: &EasyOption) -> Option<usize> {
    ENGINE_VIEW
        .iter()
        .position(|candidate| core::ptr::eq(candidate, row))
}

/// The address in [`TABLE`] of the row the engine chose, or NULL.
fn c_row(chosen: Option<&EasyOption>) -> *const curl_easyoption {
    let Some(index) = chosen.and_then(engine_index) else {
        return core::ptr::null();
    };
    // SAFETY: `index` came from `ENGINE_VIEW.iter().position`, so it is below
    // `ENGINE_VIEW.len()`, which the `const` assertion above pins to `ROWS` --
    // the length of `TABLE.0`. The offset therefore lands on an element of
    // `TABLE`, and nothing is dereferenced here.
    unsafe { base().add(index) }
}

/// Resolves a caller-supplied row pointer back to its index in [`TABLE`].
///
/// The C reaches the next row with `prev++`, which is defined only when `prev`
/// points into `Curl_easyopts[]`; for any other pointer the C reads memory it
/// does not own. Rather than reproduce that, this converts the pointer to an
/// index and rejects anything that is not an exact element boundary inside the
/// table. Every pointer this API can hand out resolves, so the behaviour is
/// identical for all defined inputs, and an undefined input yields NULL instead
/// of a wild read. The comparison is pure integer arithmetic on the addresses --
/// the foreign pointer is never dereferenced.
fn index_of(row: *const curl_easyoption) -> Option<usize> {
    let stride = core::mem::size_of::<curl_easyoption>();
    let offset = (row as usize).wrapping_sub(base() as usize);
    if offset % stride != 0 {
        return None;
    }
    let index = offset / stride;
    if index < ROWS {
        Some(index)
    } else {
        None
    }
}

/// Looks up an option by name, case-insensitively.
///
/// Reproduces `lookup(name, CURLOPT_LASTENTRY)` from `lib/easygetopt.c:31`.
/// Three details of that function are behaviour a consumer can observe, and all
/// three are measured against `libcurl.so.4.8.0` in this module's tests:
///
/// - The comparison is `curl_strequal`, so it is case-insensitive over ASCII.
///   It reaches that authority through the engine's own search, which folds with
///   `crate::util::strcase::casecompare` -- the function the exported
///   `curl_strequal` is itself a thin wrapper over -- so there is one
///   case-folding authority rather than two.
/// - Alias rows are **included**. `by_name("ENCODING")` returns the retired
///   spelling's own row -- id `CURLOPT_ACCEPT_ENCODING`, flags
///   `CURLOT_FLAG_ALIAS` -- and not the preferred row.
/// - Names are stored without their `CURLOPT_` prefix and are not trimmed, so
///   `"CURLOPT_URL"`, `"URL "` and `""` all miss.
///
/// A NULL `name` yields NULL. In the C this happens by a longer route: `lookup`
/// falls into its id branch and searches for `CURLOPT_LASTENTRY`, which only the
/// untested sentinel carries. The answer is the same, and measured.
///
/// # Safety
///
/// `name` must be NULL or a pointer to a NUL-terminated C string that stays
/// valid and unmodified for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_option_by_name(
    name: *const c_char,
) -> *const curl_easyoption {
    guard_const_ptr(|| {
        if name.is_null() {
            // C's own route, not a short-circuit: `lookup` with no name and
            // `CURLOPT_LASTENTRY` searches the id branch for an identifier only
            // the never-examined sentinel carries, and so answers NULL.
            return c_row(options::lookup(&ENGINE_VIEW, None, LASTENTRY));
        }
        // SAFETY: the caller guarantees a valid NUL-terminated string, and the
        // NULL case returned above. The borrow does not outlive this call, and
        // the engine's search compares its bytes without retaining it.
        let wanted = unsafe { CStr::from_ptr(name) };

        c_row(options::by_name(&ENGINE_VIEW, wanted))
    })
}

/// Looks up an option by its identifier, skipping alias rows.
///
/// Reproduces `lookup(NULL, id)`. Two details matter and both are measured:
///
/// - Rows flagged `CURLOT_FLAG_ALIAS` are skipped, so an id shared by a retired
///   spelling and its preferred option always resolves to the preferred one.
///   `by_id(112)` is `SERVER_RESPONSE_TIMEOUT`, never `FTP_RESPONSE_TIMEOUT`;
///   `by_id(10001)` is `WRITEDATA`, never `FILE`.
/// - `id == 0` yields NULL without a search, because the C guards the whole
///   lookup with `if(name || id)` and a NULL name with a zero id fails it. No
///   row carries id 0 -- option numbering starts at 1 -- so the guard and the
///   search agree. The engine reproduces it explicitly, in
///   [`by_id`](curl_rs_lib::easy::options::by_id), rather than leaving it to
///   coincide; this side does not restate it.
///
/// Any id with no matching non-alias row yields NULL.
#[no_mangle]
pub extern "C" fn curl_easy_option_by_id(id: c_int) -> *const curl_easyoption {
    guard_const_ptr(|| c_row(options::by_id(&ENGINE_VIEW, OptionId(id))))
}

/// Walks the option table.
///
/// Reproduces `curl_easy_option_next` from `lib/easygetopt.c:65`:
///
/// - `NULL` yields the first row, `ABSTRACT_UNIX_SOCKET`.
/// - A real row yields the row after it, or NULL once that would be the
///   sentinel. So the walk ends after `XOAUTH2_BEARER`, the 323rd row.
/// - The sentinel itself yields NULL, matching the C's `prev && prev->name`
///   test failing.
/// - Any pointer that is not a row of this table yields NULL. See
///   [`index_of`]: the C would perform a wild read here.
///
/// The loop a consumer writes is `while((o = curl_easy_option_next(o)))`, so
/// these four cases are the whole contract.
#[no_mangle]
pub extern "C" fn curl_easy_option_next(
    prev: *const curl_easyoption,
) -> *const curl_easyoption {
    guard_const_ptr(|| {
        // The one decision that is genuinely this side's: turning the foreign
        // pointer into a row of the table, or refusing it. Everything after it
        // -- the sentinel test, where the walk stops, which row comes next --
        // is the engine's.
        let here = if prev.is_null() {
            None
        } else {
            let Some(index) = index_of(prev) else {
                return core::ptr::null();
            };
            Some(&ENGINE_VIEW[index])
        };

        c_row(options::next(&ENGINE_VIEW, here))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ffi::c_uint;
    use std::collections::HashMap;
    use std::ffi::CString;

    /// The alias flag, read here so the tests compare against the same constant
    /// the table is built from rather than a literal `1`.
    const ALIAS: c_uint = super::super::opts::CURLOT_FLAG_ALIAS;

    /// The recorded behaviour of the frozen `libcurl.so.4.8.0`, produced by
    /// `/tmp/p11/oracle/eo.c` and committed beside this module. Every
    /// expectation below is read from it rather than hand-written, so a
    /// transcription slip cannot make a test agree with a wrong implementation.
    const ORACLE: &str = include_str!("easy_option_oracle.txt");

    /// One oracle record: the fields a `curl_easyoption` carries.
    #[derive(Debug, Eq, PartialEq)]
    struct Record {
        name: String,
        id: c_int,
        value_type: c_int,
        flags: c_uint,
    }

    fn parse(fields: &[&str]) -> Record {
        Record {
            name: fields[0].to_string(),
            id: fields[1].parse().expect("an integer id"),
            value_type: fields[2].parse().expect("an integer type"),
            flags: fields[3].parse().expect("an integer flag word"),
        }
    }

    /// Reads a returned row back into a `Record` for comparison.
    fn read(row: *const curl_easyoption) -> Option<Record> {
        if row.is_null() {
            return None;
        }
        // SAFETY: every non-NULL pointer these functions return is an element
        // of `TABLE`, which is a live `static`, and its `name` points into a
        // `&'static [u8]` literal.
        let row = unsafe { &*row };
        let name = unsafe { CStr::from_ptr(row.name) }
            .to_str()
            .expect("an ASCII option name")
            .to_string();
        Some(Record {
            name,
            id: row.id,
            value_type: row.r#type,
            flags: row.flags,
        })
    }

    fn oracle_rows() -> Vec<Record> {
        ORACLE
            .lines()
            .filter_map(|line| {
                let fields: Vec<&str> = line.split('\t').collect();
                (fields[0] == "ROW").then(|| parse(&fields[2..]))
            })
            .collect()
    }

    /// Walking with `curl_easy_option_next` must reproduce the frozen library's
    /// enumeration exactly: same rows, same order, same four field values.
    ///
    /// This is the strongest assertion in the module. 323 rows times four
    /// fields is 1,292 independent facts, none of them written by hand.
    #[test]
    fn the_walk_reproduces_the_c_enumeration_exactly() {
        let expected = oracle_rows();
        assert_eq!(
            expected.len(),
            323,
            "the oracle should carry every real row"
        );

        let mut observed = Vec::new();
        let mut cursor = curl_easy_option_next(core::ptr::null());
        while let Some(record) = read(cursor) {
            observed.push(record);
            cursor = curl_easy_option_next(cursor);
        }

        assert_eq!(
            observed.len(),
            expected.len(),
            "the walk must visit exactly the rows the C visits"
        );
        for (index, (got, want)) in
            observed.iter().zip(expected.iter()).enumerate()
        {
            assert_eq!(
                got, want,
                "row {index} differs from the frozen library"
            );
        }
    }

    /// The oracle's declared row count must agree with the walk, so a truncated
    /// oracle file cannot quietly weaken the test above.
    #[test]
    fn the_oracle_declares_the_row_count_it_carries() {
        let declared: usize = ORACLE
            .lines()
            .find_map(|line| line.strip_prefix("ROWCOUNT\t"))
            .expect("a ROWCOUNT record")
            .parse()
            .expect("an integer count");
        assert_eq!(declared, oracle_rows().len());
        assert_eq!(
            declared + 1,
            ROWS,
            "the projection carries one sentinel beyond the real rows"
        );
    }

    /// Every `BYNAME` record the oracle holds, replayed. Covers the
    /// case-insensitivity, the alias inclusion, the absent `CURLOPT_` prefix,
    /// the untrimmed spaces, the empty string and the misses.
    #[test]
    fn by_name_matches_the_c_for_every_probed_name() {
        let mut checked = 0usize;
        for line in ORACLE.lines() {
            let fields: Vec<&str> = line.split('\t').collect();
            if fields[0] != "BYNAME" {
                continue;
            }
            let probe = fields[1];
            if probe == "<NULL>" {
                // SAFETY: a NULL name is one of the two shapes the contract
                // admits, and the function returns before reading it.
                let answer =
                    unsafe { curl_easy_option_by_name(core::ptr::null()) };
                assert!(answer.is_null(), "a NULL name must yield NULL");
                checked += 1;
                continue;
            }
            let subject = CString::new(probe).expect("a NUL-free probe");
            // SAFETY: `subject` is a live NUL-terminated string for the call.
            let got =
                read(unsafe { curl_easy_option_by_name(subject.as_ptr()) });
            if fields[2] == "NULL" {
                assert_eq!(got, None, "{probe:?} must not resolve");
            } else {
                assert_eq!(
                    got.as_ref(),
                    Some(&parse(&fields[2..])),
                    "{probe:?} resolved differently from the C"
                );
            }
            checked += 1;
        }
        assert!(checked >= 30, "expected the full probe set, got {checked}");
    }

    /// Every `BYID` record the oracle holds, replayed. Covers the alias skip,
    /// the zero guard, negative ids, `CURLOPT_LASTENTRY` and `INT_MAX`.
    #[test]
    fn by_id_matches_the_c_for_every_probed_id() {
        let mut checked = 0usize;
        for line in ORACLE.lines() {
            let fields: Vec<&str> = line.split('\t').collect();
            if fields[0] != "BYID" {
                continue;
            }
            let probe: c_int = fields[1].parse().expect("an integer id");
            let got = read(curl_easy_option_by_id(probe));
            if fields[2] == "NULL" {
                assert_eq!(got, None, "id {probe} must not resolve");
            } else {
                assert_eq!(
                    got.as_ref(),
                    Some(&parse(&fields[2..])),
                    "id {probe} resolved differently from the C"
                );
            }
            checked += 1;
        }
        assert!(checked >= 18, "expected the full probe set, got {checked}");
    }

    /// The four walk boundaries the oracle records by name.
    #[test]
    fn the_walk_boundaries_match_the_c() {
        let field = |key: &str| -> String {
            ORACLE
                .lines()
                .find_map(|line| {
                    line.strip_prefix(&format!("{key}\t")).map(str::to_string)
                })
                .unwrap_or_else(|| panic!("a {key} record"))
        };

        let first = read(curl_easy_option_next(core::ptr::null()))
            .expect("a first row");
        assert_eq!(first.name, field("FIRST"));

        let mut last = core::ptr::null();
        let mut cursor = curl_easy_option_next(core::ptr::null());
        while !cursor.is_null() {
            last = cursor;
            cursor = curl_easy_option_next(cursor);
        }
        assert_eq!(read(last).expect("a last row").name, field("LAST"));
        assert_eq!(field("AFTERLAST"), "NULL");
        assert!(curl_easy_option_next(last).is_null());

        // The sentinel, reached the way the C reaches it.
        assert_eq!(field("SENTINEL_NAME_NULL"), "1");
        assert_eq!(field("NEXT_OF_SENTINEL"), "NULL");
        // SAFETY: `last` is the final real row of `TABLE`, so `add(1)` lands on
        // the sentinel, still inside the same object.
        let sentinel = unsafe { last.add(1) };
        assert!(
            // SAFETY: as above; the sentinel is a live element of `TABLE`.
            unsafe { (*sentinel).name }.is_null(),
            "the row after the last real one is the sentinel"
        );
        assert!(curl_easy_option_next(sentinel).is_null());
    }

    /// The projection must be element-for-element identical to the authority,
    /// including the sentinel. This is what makes "one table, projected" a fact
    /// rather than an intention.
    #[test]
    fn the_projection_mirrors_the_authority_row_for_row() {
        assert_eq!(TABLE.0.len(), EASY_OPTIONS.len());
        for (index, authority) in EASY_OPTIONS.iter().enumerate() {
            let projected = &TABLE.0[index];
            assert_eq!(projected.id, authority.id as c_int, "row {index} id");
            assert_eq!(
                projected.r#type, authority.value_type as c_int,
                "row {index} type"
            );
            assert_eq!(projected.flags, authority.flags, "row {index} flags");
            match authority.name {
                None => assert!(
                    projected.name.is_null(),
                    "row {index} should be the sentinel"
                ),
                Some(bytes) => {
                    assert!(!projected.name.is_null(), "row {index} name");
                    // SAFETY: the projection's `name` points into `bytes`,
                    // which is a `&'static [u8]` ending in NUL.
                    let seen = unsafe { CStr::from_ptr(projected.name) };
                    assert_eq!(
                        seen.to_bytes_with_nul(),
                        bytes,
                        "row {index} name must be the authority's own literal"
                    );
                    // The ADDRESS is deliberately not compared, and the reason
                    // is worth recording so it is not read as a weakening.
                    // `project_row` cannot copy: `bytes.as_ptr()` is the only
                    // operation it performs on a name, and a `const fn` has no
                    // allocator to copy into. Whether the pointer the const
                    // evaluator interns is the SAME allocation the runtime
                    // static occupies is a codegen property that moves with the
                    // compiler, and it does. Measured: equal on the pinned
                    // 1.97.1, and distinct-but-byte-identical on the 1.75.0
                    // floor, where a pointer-equality assertion fails though
                    // nothing about the projection has changed -- it took
                    // `cargo +1.75.0 test --workspace` down on its own. Byte
                    // equality is what the contract actually needs: it is what
                    // makes a row impossible to add, remove, reorder or edit on
                    // one side only, which is the claim this module makes.
                }
            }
        }
    }

    /// The engine projection must mirror the authority row for row too.
    ///
    /// The C projection has the same assertion above. Both are needed and for
    /// the same reason: the exports look a row up in `ENGINE_VIEW` and hand back
    /// the address of the row at that index in `TABLE`, so the two projections
    /// agreeing with the authority is what makes that index mean the same thing
    /// on both sides. A single reordered row would make every answer point at
    /// its neighbour.
    #[test]
    fn the_engine_projection_mirrors_the_authority_row_for_row() {
        assert_eq!(ENGINE_VIEW.len(), EASY_OPTIONS.len());
        for (index, authority) in EASY_OPTIONS.iter().enumerate() {
            let projected = &ENGINE_VIEW[index];
            assert_eq!(
                projected.id,
                OptionId(authority.id as c_int),
                "row {index} id"
            );
            assert_eq!(
                projected.value_type.as_i32(),
                authority.value_type as c_int,
                "row {index} type"
            );
            assert_eq!(
                projected.flags,
                OptionFlags(authority.flags),
                "row {index} flags"
            );
            match authority.name {
                None => assert!(
                    projected.is_sentinel(),
                    "row {index} should be the sentinel"
                ),
                Some(bytes) => assert_eq!(
                    projected.name.map(CStr::to_bytes_with_nul),
                    Some(bytes),
                    "row {index} name must be the authority's own literal"
                ),
            }
        }
    }

    /// The two projections agree about every row, index for index.
    ///
    /// Stated directly rather than left to follow from the two assertions above,
    /// because it is the property [`c_row`] relies on: an index found in one
    /// array is used to address the other.
    #[test]
    fn the_two_projections_agree_index_for_index() {
        assert_eq!(TABLE.0.len(), ENGINE_VIEW.len());
        for (index, engine) in ENGINE_VIEW.iter().enumerate() {
            let c = &TABLE.0[index];
            assert_eq!(c.id, engine.id.0, "row {index} id");
            assert_eq!(
                c.r#type,
                engine.value_type.as_i32(),
                "row {index} type"
            );
            assert_eq!(c.flags, engine.flags.0, "row {index} flags");
            assert_eq!(
                c.name.is_null(),
                engine.is_sentinel(),
                "row {index} sentinel-ness"
            );
        }
    }

    /// The engine's three entry points agree about every row of this table.
    ///
    /// `first_inconsistent_row`'s own documentation says the crate that owns the
    /// table has to be the one to run it, because the acyclicity rule keeps the
    /// table out of reach from the engine's tests. This is that call, and it is
    /// the anti-duplication check in the literal sense: it holds only if
    /// `by_name`, `by_id` and `next` are consistent over these exact rows, which
    /// is a property a second, drifting table would lose.
    ///
    /// The check is stronger than "each row is findable". For a preferred row it
    /// requires `by_id` to return *that very row*, compared by address, which
    /// holds only when no two preferred rows share an identifier -- and it
    /// requires every alias row's identifier to resolve to a non-alias row.
    #[test]
    fn the_engine_finds_every_row_of_this_table_consistently() {
        let inconsistent = options::first_inconsistent_row(&ENGINE_VIEW);

        assert!(
            inconsistent.is_none(),
            "the engine's entry points disagree about {:?}",
            inconsistent.and_then(|row| row.name_str())
        );
    }

    /// The metadata table and the option enumeration are in step.
    ///
    /// `lib/easyoptions.c`'s `Curl_easyopts_check()` is
    /// `(CURLOPT_LASTENTRY % 10000) != (328 + 1)`; the engine owns that
    /// arithmetic as `easyopts_in_sync`, and this crate owns the identifier it
    /// is asked about. C evaluates it per lookup in a debug build; running it
    /// once, here, over the identifier this table's sentinel carries is the same
    /// guarantee without the per-call cost.
    #[test]
    fn the_table_is_in_step_with_the_option_enumeration() {
        assert!(options::easyopts_in_sync(LASTENTRY));

        // Discriminating rather than vacuous: a different identifier fails.
        assert!(!options::easyopts_in_sync(OptionId(LASTENTRY.0 + 1)));

        // And the sentinel really is the row that carries it.
        let sentinel =
            ENGINE_VIEW.last().expect("the table has a terminating row");
        assert!(sentinel.is_sentinel());
        assert_eq!(sentinel.id, LASTENTRY);
    }

    /// No slot may keep its seed value. A skipped slot would look like a
    /// sentinel and silently truncate the walk.
    #[test]
    fn no_projection_slot_was_left_unwritten() {
        for (index, row) in TABLE.0.iter().enumerate() {
            let is_seed = row.name.is_null()
                && row.id == 0
                && row.r#type == 0
                && row.flags == 0;
            assert!(
                !is_seed || index == ROWS - 1,
                "row {index} still holds the seed value"
            );
        }
        let sentinel = &TABLE.0[ROWS - 1];
        assert!(sentinel.name.is_null());
        assert_eq!(
            sentinel.id, 10329,
            "the sentinel carries CURLOPT_LASTENTRY"
        );
    }

    /// `by_id` must never answer with an alias row, and `by_name` must be the
    /// only way to reach one. Asserted over the whole table rather than over
    /// the sampled ids, so a newly added alias cannot escape.
    #[test]
    fn by_id_never_answers_with_an_alias_and_by_name_can() {
        let mut aliases = 0usize;
        for row in EASY_OPTIONS.iter().filter(|r| r.name.is_some()) {
            let id = row.id as c_int;
            let answer = read(curl_easy_option_by_id(id))
                .unwrap_or_else(|| panic!("id {id} must resolve"));
            assert_eq!(
                answer.flags & ALIAS,
                0,
                "id {id} answered with an alias"
            );
            assert_eq!(answer.id, id);

            let name = row.name_str().expect("a real row");
            let subject = CString::new(name).expect("a NUL-free name");
            // SAFETY: `subject` is live for the call.
            let by_name =
                read(unsafe { curl_easy_option_by_name(subject.as_ptr()) })
                    .unwrap_or_else(|| panic!("{name} must resolve by name"));
            assert_eq!(
                by_name.name, name,
                "by_name must return the row spelling it was given"
            );
            if row.is_alias() {
                aliases += 1;
                assert_eq!(
                    by_name.flags & ALIAS,
                    ALIAS,
                    "{name} is an alias row and by_name must return it"
                );
                assert_ne!(
                    by_name.name, answer.name,
                    "{name} must differ from what its id resolves to"
                );
            }
        }
        assert_eq!(aliases, 15, "the table carries fifteen alias rows");
    }

    /// Case folding must be ASCII-only and total: every real row resolves from
    /// its lower-case, upper-case and alternating spellings alike.
    #[test]
    fn by_name_folds_case_for_every_row() {
        for row in EASY_OPTIONS.iter().filter(|r| r.name.is_some()) {
            let name = row.name_str().expect("a real row");
            let variants = [
                name.to_ascii_lowercase(),
                name.to_ascii_uppercase(),
                name.chars()
                    .enumerate()
                    .map(|(i, c)| {
                        if i % 2 == 0 {
                            c.to_ascii_lowercase()
                        } else {
                            c.to_ascii_uppercase()
                        }
                    })
                    .collect(),
            ];
            for variant in variants {
                let subject = CString::new(variant.clone()).expect("NUL-free");
                // SAFETY: `subject` is live for the call.
                let got =
                    read(unsafe { curl_easy_option_by_name(subject.as_ptr()) });
                assert_eq!(
                    got.map(|r| r.name),
                    Some(name.to_string()),
                    "{variant:?} should resolve to {name}"
                );
            }
        }
    }

    /// A pointer that is not a row of the table yields NULL rather than a wild
    /// read. The C is undefined here; this is the documented divergence.
    #[test]
    fn a_foreign_row_pointer_yields_null() {
        let stranger = curl_easyoption {
            name: core::ptr::null(),
            id: 3,
            r#type: 0,
            flags: 0,
        };
        assert!(curl_easy_option_next(&stranger).is_null());

        // Inside the table but not on an element boundary.
        let stride = core::mem::size_of::<curl_easyoption>();
        assert!(stride > 1, "a misaligned probe needs a wide element");
        let skewed = (base() as usize + 1) as *const curl_easyoption;
        assert!(curl_easy_option_next(skewed).is_null());

        // One element past the sentinel.
        // SAFETY: address arithmetic only; the pointer is never dereferenced by
        // `curl_easy_option_next`, which resolves it to an index first.
        let past = unsafe { base().add(ROWS) };
        assert!(curl_easy_option_next(past).is_null());
    }

    /// Every returned pointer must be an element of `TABLE`, so a consumer may
    /// feed any of them straight back into `curl_easy_option_next`.
    #[test]
    fn every_answer_points_into_the_table() {
        let inside = |p: *const curl_easyoption| index_of(p).is_some();
        let mut cursor = curl_easy_option_next(core::ptr::null());
        let mut seen = 0usize;
        while !cursor.is_null() {
            assert!(inside(cursor), "the walk left the table");
            seen += 1;
            cursor = curl_easy_option_next(cursor);
        }
        assert_eq!(seen, 323);

        for row in EASY_OPTIONS.iter().filter(|r| r.name.is_some()) {
            assert!(inside(curl_easy_option_by_id(row.id as c_int)));
            let subject =
                CString::new(row.name_str().expect("real")).expect("NUL-free");
            // SAFETY: `subject` is live for the call.
            assert!(inside(unsafe {
                curl_easy_option_by_name(subject.as_ptr())
            }));
        }
    }

    /// Ids are not unique across the table, so `by_id` has to pick, and the
    /// shape of the sharing is measured rather than assumed.
    ///
    /// Fifteen alias rows spread over **fourteen** distinct ids, not fifteen:
    /// `CURLOPT_KEYPASSWD` (10026) carries two retired spellings,
    /// `SSLCERTPASSWD` and `SSLKEYPASSWD`, so thirteen ids appear twice and one
    /// appears three times. 13 + 2 = 15 reconciles the alias count.
    ///
    /// The skip is load-bearing rather than decorative: in eight of the fourteen
    /// groups the alias sorts *before* the preferred row --
    /// `FTP_RESPONSE_TIMEOUT` before `SERVER_RESPONSE_TIMEOUT` (112), `FTP_SSL`
    /// before `USE_SSL` (119), `POST301` before `POSTREDIR` (161),
    /// `MAIL_RCPT_ALLLOWFAILS` before `MAIL_RCPT_ALLOWFAILS` (290), `FILE`
    /// before `WRITEDATA` (10001), `INFILE` before `READDATA` (10009),
    /// `PROGRESSDATA` before `XFERINFODATA` (10057), and `KRB4LEVEL` before
    /// `KRBLEVEL` (10063). A first-match-wins lookup without the alias skip
    /// would answer with the retired spelling for all eight, and the oracle
    /// confirms the C answers with the preferred row for every one of them.
    #[test]
    fn shared_ids_resolve_to_the_preferred_row() {
        let mut by_id: HashMap<c_int, Vec<&EasyOptionRow>> = HashMap::new();
        for row in EASY_OPTIONS.iter().filter(|r| r.name.is_some()) {
            by_id.entry(row.id as c_int).or_default().push(row);
        }
        let mut shared: Vec<_> =
            by_id.iter().filter(|(_, v)| v.len() > 1).collect();
        shared.sort_by_key(|(id, _)| **id);

        assert_eq!(shared.len(), 14, "fourteen ids are shared");
        let pairs = shared.iter().filter(|(_, v)| v.len() == 2).count();
        let triples = shared.iter().filter(|(_, v)| v.len() == 3).count();
        assert_eq!((pairs, triples), (13, 1), "thirteen pairs and one triple");
        assert_eq!(
            shared.iter().map(|(_, v)| v.len() - 1).sum::<usize>(),
            15,
            "the shared groups must account for all fifteen alias rows"
        );

        let mut alias_first = 0usize;
        for (id, rows) in shared {
            assert_eq!(
                rows.iter().filter(|r| !r.is_alias()).count(),
                1,
                "id {id} must have exactly one preferred row"
            );
            let preferred = rows
                .iter()
                .find(|r| !r.is_alias())
                .and_then(|r| r.name_str())
                .expect("a preferred row");
            let answer = read(curl_easy_option_by_id(*id))
                .unwrap_or_else(|| panic!("id {id} must resolve"));
            assert_eq!(
                answer.name, preferred,
                "id {id} must resolve to its preferred row"
            );
            assert_eq!(answer.flags & ALIAS, 0);
            if rows[0].is_alias() {
                alias_first += 1;
            }
        }
        assert_eq!(
            alias_first, 8,
            "eight groups list an alias first, which is what makes the skip \
             observable rather than decorative"
        );
    }

    /// A name that is not in the table must miss, including near-misses that a
    /// sloppy comparison would accept.
    #[test]
    fn near_miss_names_do_not_resolve() {
        for probe in [
            "CURLOPT_URL",
            "URL ",
            " URL",
            "URLL",
            "UR",
            "",
            "NOSUCHOPTION",
            "url\t",
            "WRITEDATA ",
        ] {
            let subject = CString::new(probe).expect("NUL-free");
            // SAFETY: `subject` is live for the call.
            let got = unsafe { curl_easy_option_by_name(subject.as_ptr()) };
            assert!(got.is_null(), "{probe:?} must not resolve");
        }
    }
}
