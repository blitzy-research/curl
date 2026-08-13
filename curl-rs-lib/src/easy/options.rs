//***************************************************************************
//                                  _   _ ____  _
//  Project                     ___| | | |  _ \| |
//                             / __| | | | |_) | |
//                            | (__| |_| |  _ <| |___
//                             \___|\___/|_| \_\_____|
//
// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// This software is licensed as described in the file COPYING, which
// you should have received as part of this distribution. The terms
// are also available at https://curl.se/docs/copyright.html.
//
// You may opt to use, copy, modify, merge, publish, distribute and/or sell
// copies of the Software, and permit persons to whom the Software is
// furnished to do so, under the terms of the COPYING file.
//
// This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
// KIND, either express or implied.
//
// SPDX-License-Identifier: curl
//
//***************************************************************************

//! Option identity, *consumed* -- supersedes `lib/easygetopt.c`.
//!
//! This module is the runtime lookup behind the three exported symbols
//! `curl_easy_option_by_name`, `curl_easy_option_by_id` and
//! `curl_easy_option_next`, and it is the option-identity vocabulary the
//! rest of the engine dispatches on. It reproduces:
//!
//! * `lib/easygetopt.c:31-51` -- the `lookup()` search, whose two branches
//!   behave differently in a way a consumer can observe.
//! * `lib/easygetopt.c:53-57`, `:59-62`, `:65-76` -- the three entry
//!   points built on it.
//! * `include/curl/options.h:31-65` -- the public contract: the nine
//!   `curl_easytype` members, the single `CURLOT_FLAG_ALIAS` bit, the
//!   four fields of `struct curl_easyoption`, and the three prototypes.
//! * `lib/easyoptions.c`'s `Curl_easyopts_check()` tripwire, as
//!   [`easyopts_in_sync`].
//!
//! # THE TABLE IS NOT HERE, AND PUTTING IT HERE IS A DEFECT
//!
//! `lib/easyoptions.c` is generated C: `optiontable.pl` reads
//! `include/curl/curl.h` and emits 324 rows, which `lib/easyoptions.h`
//! publishes as `extern const struct curl_easyoption Curl_easyopts[]`.
//! Under cbindgen the generation arrow **reverses** -- Rust becomes the
//! source of truth and `include/curl/curl.h` is generated from it -- so
//! the table moves to the crate that owns the enumeration it is keyed by.
//!
//! That crate is `curl-rs-ffi`, and `curl-rs-ffi/src/ffi/opts.rs` is the sole
//! source of truth for the 308 `CURLoption` identifiers, their
//! backward-compatibility aliases and the `curl_easyoption` metadata array.
//! **This module restates none of it: not one option name, not one option
//! integer, not one metadata row, and not even as a test fixture.** The reason
//! is worth stating rather than asserting, because the failure mode is
//! invisible: two populations of option metadata drift, and the drift shows up
//! only when a consumer asks for an option by name and is handed the wrong
//! identifier. Nothing crashes and no test fails until one is written for that
//! exact pair.
//!
//! # How the algorithm reaches the table without a dependency cycle
//!
//! The crate graph is `curl-rs-ffi -> curl-rs-lib <- curl-rs` and it is
//! acyclic. This crate may never name `curl_rs_ffi`, so it cannot reach for
//! the table -- the table is **handed in**. Every entry point here takes
//! `table: &'static [EasyOption]` as its first argument, and the ABI crate
//! calls in with its own array and turns the returned reference back into the
//! `const struct curl_easyoption *` a C caller expects. The direction stays
//! `ffi -> lib`, and exactly one table exists in the workspace.
//!
//! `&'static` rather than a borrowed lifetime is deliberate: the C returns
//! a pointer into an array of static storage duration and a consumer may
//! hold it for the life of the process, so a table with any shorter
//! lifetime could not honour the contract.
//!
//! # Two conventions the caller owes this module
//!
//! **The rows are sentinel-terminated, or they are not.** C's table ends
//! with `{ NULL, CURLOPT_LASTENTRY, CURLOT_LONG, 0 }` and
//! `lib/easygetopt.c:48` uses exactly that NULL `name` to stop; the ABI
//! crate keeps the sentinel, so its slice is 324 rows for 323 real ones.
//! The search here stops at the first sentinel **or** at the end of the
//! slice, whichever comes first, so a slice that omits the sentinel
//! behaves identically. Rows after a sentinel are unreachable, exactly as
//! in C.
//!
//! **The row order is observable ABI.** `lib/optiontable.pl` emits rows
//! sorted alphabetically by the name with its `CURLOPT_` prefix stripped
//! -- `ABSTRACT_UNIX_SOCKET`, `ACCEPTTIMEOUT_MS`, `ACCEPT_ENCODING` and so
//! on -- and [`next`] hands out consecutive elements, so an application
//! that enumerates options sees that sequence. Nothing here sorts,
//! filters or re-orders: the slice is consumed as given, and supplying it
//! in `optiontable.pl`'s order is the ABI crate's obligation.

use std::ffi::CStr;

/// The type of value an option takes, as reported through the
/// introspection API.
#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum EasyType {
    /// `CURLOT_LONG` -- "long (a range of values)".
    Long = 0,
    /// `CURLOT_VALUES` -- a long from "a defined set or bitmask".
    Values = 1,
    /// `CURLOT_OFF_T` -- "curl_off_t (a range of values)".
    OffT = 2,
    /// `CURLOT_OBJECT` -- "pointer (void *)".
    Object = 3,
    /// `CURLOT_STRING` -- "char * to null-terminated buffer".
    String = 4,
    /// `CURLOT_SLIST` -- "struct curl_slist *".
    Slist = 5,
    /// `CURLOT_CBPTR` -- "void * passed as-is to a callback".
    Cbptr = 6,
    /// `CURLOT_BLOB` -- "blob (struct curl_blob *)".
    Blob = 7,
    /// `CURLOT_FUNCTION` -- "function pointer".
    Function = 8,
}

impl EasyType {
    /// Every member, in the declaration order of
    /// `include/curl/options.h:31-41`.
    ///
    /// Iterated by this module's tests to assert the discriminants against
    /// their measured values, and available to any consumer that needs to
    /// enumerate the vocabulary rather than hard-code it.
    pub const ALL: [Self; 9] = [
        Self::Long,
        Self::Values,
        Self::OffT,
        Self::Object,
        Self::String,
        Self::Slist,
        Self::Cbptr,
        Self::Blob,
        Self::Function,
    ];

    /// The integer a C caller reads out of `curl_easyoption::type`.
    ///
    /// # Examples
    ///
    /// ```
    /// use curl_rs_lib::easy::options::EasyType;
    /// assert_eq!(EasyType::Long.as_i32(), 0);
    /// assert_eq!(EasyType::Function.as_i32(), 8);
    /// ```
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
    }

    /// The member with this integer, or `None` for a value the
    /// enumeration does not define.
    ///
    /// # Examples
    ///
    /// ```
    /// use curl_rs_lib::easy::options::EasyType;
    /// assert_eq!(EasyType::from_i32(5), Some(EasyType::Slist));
    /// assert_eq!(EasyType::from_i32(9), None);
    /// assert_eq!(EasyType::from_i32(-1), None);
    /// ```
    #[must_use]
    pub const fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::Long),
            1 => Some(Self::Values),
            2 => Some(Self::OffT),
            3 => Some(Self::Object),
            4 => Some(Self::String),
            5 => Some(Self::Slist),
            6 => Some(Self::Cbptr),
            7 => Some(Self::Blob),
            8 => Some(Self::Function),
            _ => None,
        }
    }
}

/// The one flag bit `struct curl_easyoption::flags` can carry.
///
/// Exposed as a bare integer as well as through [`OptionFlags`] because
/// the ABI crate has to place the same value into a C `unsigned int`, and
/// a consumer testing `opt->flags & CURLOT_FLAG_ALIAS` is doing arithmetic
/// on it.
pub const CURLOT_FLAG_ALIAS: u32 = 1 << 0;

/// The `flags` word of a metadata row.
///
/// A newtype rather than a bare `u32` so that the only defined bit is
/// reachable through a named predicate instead of by open-coding the mask
/// at each site. `#[repr(transparent)]` keeps it laid out exactly as the
/// `unsigned int` of `include/curl/options.h:55`.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OptionFlags(pub u32);

impl OptionFlags {
    /// No flag set: an ordinary, preferred option row.
    pub const NONE: Self = Self(0);

    /// [`CURLOT_FLAG_ALIAS`] set: a row that exists only so that programs
    /// written against a retired spelling keep working.
    pub const ALIAS: Self = Self(CURLOT_FLAG_ALIAS);

    /// Whether this row is an alias.
    ///
    /// # Examples
    ///
    /// ```
    /// use curl_rs_lib::easy::options::OptionFlags;
    /// assert!(OptionFlags::ALIAS.is_alias());
    /// assert!(!OptionFlags::NONE.is_alias());
    /// ```
    #[must_use]
    pub const fn is_alias(self) -> bool {
        self.0 & CURLOT_FLAG_ALIAS != 0
    }

    /// The integer a C caller reads out of `curl_easyoption::flags`.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

/// One of the five arithmetic bases a `CURLOPT_*` identifier is composed
/// from.
///
/// `include/curl/curl.h:1120` composes every identifier as `#define
/// CURLOPT(na, t, nu) na = ((t) + (nu))`, where `t` is one of the five bases
/// of `:1111-1115` and `nu` is an ordinal well below 10000. The composition
/// looks like a historical curiosity and is in fact what makes the ABI's
/// variadic setters type-safe: the identifier alone tells the callee which of
/// `long`, pointer, function pointer, `curl_off_t` or blob pointer occupies
/// the argument slot, *before* anything reads that slot.
#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum OptionTypeBase {
    /// `CURLOPTTYPE_LONG`, 0. Also `CURLOPTTYPE_VALUES`.
    Long = 0,
    /// `CURLOPTTYPE_OBJECTPOINT`, 10000. Also `CURLOPTTYPE_STRINGPOINT`,
    /// `CURLOPTTYPE_SLISTPOINT` and `CURLOPTTYPE_CBPOINT`.
    ObjectPoint = 10_000,
    /// `CURLOPTTYPE_FUNCTIONPOINT`, 20000.
    FunctionPoint = 20_000,
    /// `CURLOPTTYPE_OFF_T`, 30000.
    OffT = 30_000,
    /// `CURLOPTTYPE_BLOB`, 40000.
    Blob = 40_000,
}

impl OptionTypeBase {
    /// The five bases, in ascending order.
    pub const ALL: [Self; 5] = [
        Self::Long,
        Self::ObjectPoint,
        Self::FunctionPoint,
        Self::OffT,
        Self::Blob,
    ];

    /// The width of one band: the divisor of `CURLOPT(na, t, nu)`.
    ///
    /// Named rather than repeated as a literal, because the same 10000
    /// appears in `Curl_easyopts_check`'s `% 10000`
    /// ([`easyopts_in_sync`]) and in every band decode below.
    pub const STRIDE: i32 = 10_000;

    /// This base's integer -- the `CURLOPTTYPE_*` value itself.
    ///
    /// # Examples
    ///
    /// ```
    /// use curl_rs_lib::easy::options::OptionTypeBase;
    /// assert_eq!(OptionTypeBase::Long.base(), 0);
    /// assert_eq!(OptionTypeBase::Blob.base(), 40_000);
    /// ```
    #[must_use]
    pub const fn base(self) -> i32 {
        self as i32
    }
}

/// A `CURLOption` identifier, as an integer.
///
/// The engine dispatches on this rather than on an enumeration, and that
/// is a deliberate consequence of the acyclicity rule: the `CURLoption`
/// enumeration lives in `curl-rs-ffi`, which depends on this crate, so
/// this crate cannot name it. A transparent newtype over `i32` carries
/// the same information -- the composed integer *is* the identity -- while
/// keeping the single source of truth on the other side of the boundary.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OptionId(pub i32);

impl OptionId {
    /// The absent identifier.
    pub const UNSET: Self = Self(0);

    /// The identifier as the `int` that crosses the C boundary.
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self.0
    }

    /// The `CURLOPTTYPE_*` base this identifier was composed from.
    ///
    /// # Examples
    ///
    /// ```
    /// use curl_rs_lib::easy::options::OptionId;
    /// assert_eq!(OptionId(0).type_base(), 0);
    /// assert_eq!(OptionId(9_999).type_base(), 0);
    /// assert_eq!(OptionId(10_000).type_base(), 10_000);
    /// assert_eq!(OptionId(40_025).type_base(), 40_000);
    /// ```
    #[must_use]
    pub const fn type_base(self) -> i32 {
        self.0 - self.type_ordinal()
    }

    /// The ordinal this identifier was composed with -- the third argument
    /// to `CURLOPT(na, t, nu)`.
    ///
    /// # Examples
    ///
    /// ```
    /// use curl_rs_lib::easy::options::OptionId;
    /// assert_eq!(OptionId(10_328).type_ordinal(), 328);
    /// assert_eq!(OptionId(7).type_ordinal(), 7);
    /// ```
    #[must_use]
    pub const fn type_ordinal(self) -> i32 {
        self.0 % OptionTypeBase::STRIDE
    }

    /// Which of the five bands this identifier falls in, or `None` when it
    /// falls in none of them.
    ///
    /// # Examples
    ///
    /// ```
    /// use curl_rs_lib::easy::options::{OptionId, OptionTypeBase};
    /// assert_eq!(OptionId(13).type_band(), Some(OptionTypeBase::Long));
    /// assert_eq!(
    ///     OptionId(30_005).type_band(),
    ///     Some(OptionTypeBase::OffT)
    /// );
    /// assert_eq!(OptionId(50_000).type_band(), None);
    /// assert_eq!(OptionId(-1).type_band(), None);
    /// ```
    #[must_use]
    pub const fn type_band(self) -> Option<OptionTypeBase> {
        if self.0 < 0 {
            return None;
        }
        match self.type_base() {
            0 => Some(OptionTypeBase::Long),
            10_000 => Some(OptionTypeBase::ObjectPoint),
            20_000 => Some(OptionTypeBase::FunctionPoint),
            30_000 => Some(OptionTypeBase::OffT),
            40_000 => Some(OptionTypeBase::Blob),
            _ => None,
        }
    }
}

/// One row of the option metadata table.
///
/// # This is not the C ABI struct, and saying otherwise would be false
///
/// The C-ABI-exact declaration is `curl_easyoption` in
/// `curl-rs-ffi/src/ffi/types.rs`, whose `name` is a `*const c_char`. `name`
/// here is an `Option<&'static CStr>`, which is a *wide* pointer: measured,
/// this struct is 32 bytes where the C struct is 24. This crate carries
/// `#![deny(unsafe_code)]` with a single exemption for its `ffi` module, so a
/// raw `const char *` here would be a field nothing in this crate could read;
/// `Option<&CStr>` is readable, guarantees the terminator, and keeps the NULL
/// sentinel representable -- which a plain `&CStr` would not. Turning a row
/// into a pointer, and a pointer back into a row, is the ABI crate's job and
/// is done exactly where `unsafe` is permitted.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EasyOption {
    /// The option's name with its `CURLOPT_` prefix stripped, or `None` in
    /// the terminating row.
    ///
    /// Stored NUL-terminated so the ABI crate can hand out a
    /// `const char *` without allocating or copying, and so the comparison
    /// in [`by_name`] is over exactly the bytes a C caller supplies.
    pub name: Option<&'static CStr>,
    /// The option this row describes.
    ///
    /// For an alias row this is the **preferred** option, not the retired
    /// spelling `name` carries -- which is why an alias row and its
    /// canonical row share one id, and why [`by_id`] has to skip aliases
    /// to give a stable answer.
    pub id: OptionId,
    /// The declared value type.
    ///
    /// C spells this field `type`, which is a Rust keyword. The name is
    /// widened rather than escaped, matching the ABI crate's own
    /// engine-side row type; the C spelling is restored in the
    /// `#[repr(C)]` struct that crosses the boundary.
    pub value_type: EasyType,
    /// [`OptionFlags::ALIAS`], or [`OptionFlags::NONE`].
    pub flags: OptionFlags,
}

impl EasyOption {
    /// Whether this row is the table's terminator.
    ///
    /// Exactly C's `!o->name` test.
    #[must_use]
    pub const fn is_sentinel(&self) -> bool {
        self.name.is_none()
    }

    /// Whether this row exists only for backward compatibility.
    #[must_use]
    pub const fn is_alias(&self) -> bool {
        self.flags.is_alias()
    }

    /// Whether this row is a real, preferred option -- neither the
    /// sentinel nor an alias.
    ///
    /// The predicate [`by_id`] searches on.
    #[must_use]
    pub const fn is_preferred(&self) -> bool {
        !self.is_sentinel() && !self.is_alias()
    }

    /// The name without its terminating NUL, or `None` for the sentinel.
    #[must_use]
    pub fn name_bytes(&self) -> Option<&'static [u8]> {
        Some(self.name?.to_bytes())
    }

    /// The name as UTF-8, or `None` for the sentinel or for a name that is
    /// not valid UTF-8.
    #[must_use]
    pub fn name_str(&self) -> Option<&'static str> {
        std::str::from_utf8(self.name_bytes()?).ok()
    }
}

/// The ordinal `CURLOPT_LASTENTRY` must carry for the metadata table to be
/// in step with the option enumeration.
///
/// Written as `328 + 1` because that is literally how `lib/easyoptions.c`
/// writes it:
///
/// ```c
/// int Curl_easyopts_check(void)
/// {
///   return (CURLOPT_LASTENTRY % 10000) != (328 + 1);
/// }
/// ```
pub const EASYOPTS_LASTENTRY_ORDINAL: i32 = 328 + 1;

/// Whether the option enumeration and the metadata table were regenerated
/// together.
///
/// Supersedes `Curl_easyopts_check()`, which `lib/easyoptions.c` compiles
/// only under `#ifdef DEBUGBUILD` and which `lib/easygetopt.c:34` asserts
/// on every single lookup. Two things change in the translation, and both
/// are improvements rather than losses:
///
/// * The sense is inverted. The C returns **non-zero on failure**, so its
///   caller reads `DEBUGASSERT(!Curl_easyopts_check())`. A predicate named
///   for what it checks is read correctly at a glance, so this returns
///   `true` when the two *are* in sync.
/// * It is not asserted per lookup. In C the operand is a compile-time
///   constant compared at run time, once per call, in debug builds only.
///   Here the operand is a `const` in the crate that owns it, so the same
///   guarantee is available as a `const` assertion with no run-time cost
///   at all -- and `curl-rs-ffi/src/ffi/opts.rs` already pins the concrete
///   value that way. This function is the algorithm those assertions run.
///
/// # Examples
///
/// ```
/// use curl_rs_lib::easy::options::{
///     easyopts_in_sync, OptionId, EASYOPTS_LASTENTRY_ORDINAL,
/// };
/// assert_eq!(EASYOPTS_LASTENTRY_ORDINAL, 329);
/// // The bound sits in the object-pointer band, so the `% 10000` in the
/// // C is doing real work: the value is neither 328 nor 329.
/// assert!(easyopts_in_sync(OptionId(10_000 + 329)));
/// assert!(!easyopts_in_sync(OptionId(10_000 + 328)));
/// ```
#[must_use]
pub const fn easyopts_in_sync(last_entry: OptionId) -> bool {
    last_entry.type_ordinal() == EASYOPTS_LASTENTRY_ORDINAL
}

/// The rows a search may examine: everything before the first sentinel.
fn rows(
    table: &'static [EasyOption],
) -> impl Iterator<Item = &'static EasyOption> {
    table.iter().take_while(|row| !row.is_sentinel())
}

/// The name search, over raw bytes.
fn search_by_name(
    table: &'static [EasyOption],
    wanted: &[u8],
) -> Option<&'static EasyOption> {
    rows(table).find(|row| {
        row.name.is_some_and(|name| {
            crate::util::strcase::casecompare(name.to_bytes(), wanted)
        })
    })
}

/// The two-branch search of `lib/easygetopt.c:31-51`.
///
/// C keeps this function `static`; it is public here because the ABI crate
/// needs the name-and-id pair to reproduce one documented edge case --
/// `curl_easy_option_by_name(NULL)` -- without writing a second search.
/// See [`by_name`] for what that case does.
///
/// The two branches are **not** symmetric, and the asymmetry is contract:
///
/// * With a name, only the name is compared, so alias rows match.
/// * Without a name, the id must match **and** the row must not be an
///   alias. C's own comment on the test is `/* do not match alias
///   options */` (`lib/easygetopt.c:44`).
///
/// # Arguments
///
/// * `table` -- the metadata rows, supplied by the crate that owns them.
/// * `name` -- the name to find, or `None` to search by id. `None` models
///   C's NULL `name` argument.
/// * `id` -- the identifier to find. **Ignored when `name` is `Some`**,
///   exactly as C ignores it (`lib/easygetopt.c:55`).
///
/// # Panics
///
/// Never. The `debug_assert!` reproduces C's
/// `DEBUGASSERT(name || id)` (`lib/easygetopt.c:33`) so that a caller
/// supplying neither is caught while testing; in release builds, and in
/// any build for a caller that does supply one, it is not evaluated. C's
/// second assertion, `DEBUGASSERT(!Curl_easyopts_check())`, is not
/// reproduced here: its operand is a constant, so it belongs in a `const`
/// assertion rather than on every lookup. [`easyopts_in_sync`] is that
/// check, and this module's tests exercise it.
#[must_use]
pub fn lookup(
    table: &'static [EasyOption],
    name: Option<&CStr>,
    id: OptionId,
) -> Option<&'static EasyOption> {
    debug_assert!(
        name.is_some() || id != OptionId::UNSET,
        "lookup needs a name or an id (lib/easygetopt.c:33)"
    );

    if let Some(name) = name {
        return search_by_name(table, name.to_bytes());
    }

    // C guards the whole search with `if(name || id)`, so a NULL name and
    // a zero id find nothing without looking. No row can carry zero --
    // option numbering starts at 1 -- so the guard and the search agree,
    // and it is reproduced explicitly rather than left to coincide.
    if id == OptionId::UNSET {
        return None;
    }

    rows(table).find(|row| row.id == id && row.is_preferred())
}

/// Looks an option up by name, case-insensitively.
///
/// # The NULL-name case belongs to the caller
///
/// C accepts a NULL `name` and answers NULL, by a longer route: `lookup`
/// falls into its id branch and searches for `CURLOPT_LASTENTRY`, an
/// identifier only the never-examined sentinel carries. A Rust caller
/// cannot express NULL in a `&CStr`, so the ABI crate handles the null
/// pointer. It may short-circuit, or it may reproduce the C's route
/// literally through [`lookup`] with `None` and that identifier; both
/// yield `None` for a well-formed table.
#[must_use]
pub fn by_name(
    table: &'static [EasyOption],
    name: &CStr,
) -> Option<&'static EasyOption> {
    lookup(table, Some(name), OptionId::UNSET)
}

/// [`by_name`] for a caller that holds a Rust string.
///
/// # Examples
///
/// ```
/// use std::ffi::CStr;
/// use curl_rs_lib::easy::options::{
///     by_name_str, EasyOption, EasyType, OptionFlags, OptionId,
/// };
///
/// const EXAMPLE: &CStr =
///     match CStr::from_bytes_with_nul(b"EXAMPLE_OPTION\0") {
///         Ok(text) => text,
///         Err(_) => panic!("the literal ends in a NUL"),
///     };
///
/// // A synthetic table: the real one lives in `curl-rs-ffi`. The
/// // identifier's ordinal (4321) is far past the last real one, so this
/// // row cannot be mistaken for a restatement of curl's own table.
/// static TABLE: [EasyOption; 2] = [
///     EasyOption {
///         name: Some(EXAMPLE),
///         id: OptionId(14_321),
///         value_type: EasyType::String,
///         flags: OptionFlags::NONE,
///     },
///     EasyOption {
///         name: None,
///         id: OptionId(0),
///         value_type: EasyType::Long,
///         flags: OptionFlags::NONE,
///     },
/// ];
///
/// // Case-insensitive, and the prefix is already stripped in the table.
/// assert!(by_name_str(&TABLE, "example_option").is_some());
/// assert!(by_name_str(&TABLE, "Example_Option").is_some());
/// assert!(by_name_str(&TABLE, "CURLOPT_EXAMPLE_OPTION").is_none());
/// ```
#[must_use]
pub fn by_name_str(
    table: &'static [EasyOption],
    name: &str,
) -> Option<&'static EasyOption> {
    search_by_name(table, name.as_bytes())
}

/// Looks an option up by its identifier, skipping alias rows.
///
/// Supersedes `curl_easy_option_by_id` (`lib/easygetopt.c:59-62`), which
/// is `lookup(NULL, id)`. Two consequences are contract:
///
/// * **An alias row is never returned.** An identifier shared by a retired
///   spelling and its preferred option therefore always resolves to the
///   preferred one, whichever comes first in the table.
/// * [`OptionId::UNSET`] finds nothing, because C's `if(name || id)`
///   rejects a NULL name with a zero id before searching.
#[must_use]
pub fn by_id(
    table: &'static [EasyOption],
    id: OptionId,
) -> Option<&'static EasyOption> {
    if id == OptionId::UNSET {
        return None;
    }
    lookup(table, None, id)
}

/// Walks the table, one row at a time.
///
/// Supersedes `curl_easy_option_next` (`lib/easygetopt.c:65-76`). The loop
/// a consumer writes is `while((o = curl_easy_option_next(o)))`, so the
/// whole contract is four cases:
///
/// * `None` yields the first row.
/// * A real row yields the row after it, or `None` once that would be the
///   sentinel -- so the walk ends after the last real row.
/// * The sentinel yields `None`, matching C's `prev && prev->name` test
///   failing on a NULL name.
/// * A row that is not an element of `table` yields `None`. See below.
///
/// # One deliberate hardening for a table that cannot exist
///
/// C returns `&Curl_easyopts[0]` for a NULL `prev` *unconditionally*, so
/// for a sentinel-only table it would hand back the terminator itself and
/// the consumer's loop would dereference a NULL `name`; for an empty table
/// it would read past the end. Both are refused here. Neither can arise
/// for the workspace's 324-row table, whose first row is real, so the two
/// implementations agree on every input the ABI can actually produce.
#[must_use]
pub fn next(
    table: &'static [EasyOption],
    prev: Option<&EasyOption>,
) -> Option<&'static EasyOption> {
    let Some(prev) = prev else {
        return table.first().filter(|row| !row.is_sentinel());
    };

    let (at, row) = table
        .iter()
        .enumerate()
        .find(|(_, candidate)| std::ptr::eq(*candidate, prev))?;

    if row.is_sentinel() {
        return None;
    }

    table
        .get(at + 1)
        .filter(|following| !following.is_sentinel())
}

/// The first row of `table` whose metadata the three entry points do not
/// agree about, or `None` when they all agree about every row.
///
/// This is the anti-duplication check, and it is public for a reason that
/// follows from the acyclicity rule rather than from taste. The real
/// 324-row table can never be reachable from this crate -- that is the
/// whole point of handing it in -- so the check that the algorithm and the
/// authority agree cannot live in a test *here*. It lives here as a
/// function, and the crate that owns the table runs it:
///
/// ```text
/// // in curl-rs-ffi, over its own rows:
/// assert!(first_inconsistent_row(TABLE).is_none());
/// ```
///
/// # What agreement means
///
/// Walking with [`next`] from `None` must visit exactly the rows before
/// the first sentinel, in order, and for each visited row:
///
/// * [`by_name`] must find a row whose name equals this row's name
///   case-insensitively. Alias rows are included, because the name branch
///   does not filter them.
/// * A **preferred** row must be the row [`by_id`] returns for its own
///   identifier -- the very same row, compared by address. That is
///   stronger than "some row with that id", and deliberately so: it holds
///   only when no two preferred rows share an identifier, which is a
///   property the authority table has and a duplicated table would lose.
/// * An **alias** row's identifier must resolve through [`by_id`] to a row
///   that is not an alias. Every alias names a preferred option, so the
///   preferred row exists; verified against `lib/easyoptions.c`, whose 13
///   flagged rows all point at an unflagged one.
#[must_use]
pub fn first_inconsistent_row(
    table: &'static [EasyOption],
) -> Option<&'static EasyOption> {
    let mut cursor = next(table, None);
    let mut expected = 0usize;

    while let Some(row) = cursor {
        // The walk must be in table order, so the row it produced has to
        // be the one at the index reached so far.
        if !table.get(expected).is_some_and(|at| std::ptr::eq(at, row)) {
            return Some(row);
        }

        let Some(name) = row.name else {
            // `next` never yields a sentinel, so reaching this is itself
            // the inconsistency.
            return Some(row);
        };
        let found_by_name = by_name(table, name);
        let name_agrees = found_by_name.is_some_and(|other| {
            other.name.is_some_and(|other_name| {
                crate::util::strcase::casecompare(
                    other_name.to_bytes(),
                    name.to_bytes(),
                )
            })
        });
        if !name_agrees {
            return Some(row);
        }

        let found_by_id = by_id(table, row.id);
        let id_agrees = if row.is_alias() {
            found_by_id.is_some_and(|other| !other.is_alias())
        } else {
            found_by_id.is_some_and(|other| std::ptr::eq(other, row))
        };
        if !id_agrees {
            return Some(row);
        }

        expected += 1;
        cursor = next(table, Some(row));
    }

    // The walk stopped. It must have stopped exactly at the first sentinel
    // or at the end of the slice, and nowhere earlier.
    let reachable = rows(table).count();
    if expected == reachable {
        None
    } else {
        table.get(expected)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        by_id, by_name, by_name_str, easyopts_in_sync, first_inconsistent_row,
        lookup, next, EasyOption, EasyType, OptionFlags, OptionId,
        OptionTypeBase, CURLOT_FLAG_ALIAS, EASYOPTS_LASTENTRY_ORDINAL,
    };
    use std::ffi::CStr;

    // EVERY ROW BELOW IS SYNTHETIC.

    /// A NUL-terminated name, checked at compile time.
    const fn name(bytes: &'static [u8]) -> &'static CStr {
        match CStr::from_bytes_with_nul(bytes) {
            Ok(text) => text,
            Err(_) => panic!("a synthetic row name must end in one NUL"),
        }
    }

    const ALPHA: &CStr = name(b"ALPHA_ONE\0");
    const BETA: &CStr = name(b"BETA_TWO\0");
    const OLD_BETA: &CStr = name(b"OLD_BETA\0");
    const GAMMA: &CStr = name(b"GAMMA_THREE\0");
    const ABSENT: &CStr = name(b"IN_NO_TABLE_AT_ALL\0");

    const ALPHA_ID: OptionId = OptionId(4_321);
    const BETA_ID: OptionId = OptionId(14_321);
    const GAMMA_ID: OptionId = OptionId(24_321);
    const ABSENT_ID: OptionId = OptionId(34_321);

    /// One synthetic row.
    const fn row(
        name: Option<&'static CStr>,
        id: OptionId,
        value_type: EasyType,
        flags: OptionFlags,
    ) -> EasyOption {
        EasyOption {
            name,
            id,
            value_type,
            flags,
        }
    }

    /// The terminator: C's `{ NULL, CURLOPT_LASTENTRY, CURLOT_LONG, 0 }`,
    /// with the identifier left unset because the row is never examined.
    const SENTINEL: EasyOption =
        row(None, OptionId::UNSET, EasyType::Long, OptionFlags::NONE);

    // The tables are `static`, never `const`. `next` resolves a row by
    // ADDRESS, and only a `static` guarantees one address for one row; a
    // `const` is a value that each use site may materialise separately.

    /// Canonical shape: three preferred rows, one alias sharing
    /// [`BETA_ID`], then the sentinel.
    static TABLE: [EasyOption; 5] = [
        row(Some(ALPHA), ALPHA_ID, EasyType::Long, OptionFlags::NONE),
        row(Some(BETA), BETA_ID, EasyType::String, OptionFlags::NONE),
        row(
            Some(OLD_BETA),
            BETA_ID,
            EasyType::String,
            OptionFlags::ALIAS,
        ),
        row(Some(GAMMA), GAMMA_ID, EasyType::Function, OptionFlags::NONE),
        SENTINEL,
    ];

    /// The same rows with the alias placed FIRST, so that "an alias is
    /// skipped" cannot be satisfied by mere ordering.
    static ALIAS_FIRST: [EasyOption; 3] = [
        row(
            Some(OLD_BETA),
            BETA_ID,
            EasyType::String,
            OptionFlags::ALIAS,
        ),
        row(Some(BETA), BETA_ID, EasyType::String, OptionFlags::NONE),
        SENTINEL,
    ];

    /// A table with no terminator at all.
    static NO_SENTINEL: [EasyOption; 2] = [
        row(Some(ALPHA), ALPHA_ID, EasyType::Long, OptionFlags::NONE),
        row(Some(BETA), BETA_ID, EasyType::String, OptionFlags::NONE),
    ];

    /// A row hidden behind the terminator, which must be unreachable.
    static AFTER_SENTINEL: [EasyOption; 3] = [
        row(Some(ALPHA), ALPHA_ID, EasyType::Long, OptionFlags::NONE),
        SENTINEL,
        row(Some(GAMMA), GAMMA_ID, EasyType::Function, OptionFlags::NONE),
    ];

    /// Degenerate tables. Neither can arise for the authority table, and
    /// neither may panic or index out of bounds.
    static SENTINEL_ONLY: [EasyOption; 1] = [SENTINEL];
    static EMPTY: [EasyOption; 0] = [];

    /// A different table, for the foreign-row case of [`next`].
    static FOREIGN: [EasyOption; 2] = [
        row(Some(ALPHA), ALPHA_ID, EasyType::Long, OptionFlags::NONE),
        SENTINEL,
    ];

    /// The names the walk visits, for order assertions.
    fn walk(table: &'static [EasyOption]) -> Vec<&'static str> {
        let mut visited = Vec::new();
        let mut cursor = next(table, None);
        while let Some(row) = cursor {
            visited.push(row.name_str().expect("a walked row has a name"));
            cursor = next(table, Some(row));
        }
        visited
    }

    // The public vocabulary: pinned integers.

    #[test]
    fn easy_type_members_are_the_measured_ordinals() {
        // include/curl/options.h:31-41, in the header's order. Asserted
        // against the position rather than against a transcribed list, so
        // a member inserted in the middle fails here rather than silently
        // renumbering its successors.
        assert_eq!(EasyType::ALL.len(), 9);
        for (ordinal, member) in EasyType::ALL.iter().enumerate() {
            let expected = i32::try_from(ordinal).expect("0..9 fits");
            assert_eq!(
                member.as_i32(),
                expected,
                "{member:?} must carry {expected}"
            );
        }
    }

    #[test]
    fn easy_type_members_are_in_the_headers_order() {
        assert_eq!(
            EasyType::ALL,
            [
                EasyType::Long,
                EasyType::Values,
                EasyType::OffT,
                EasyType::Object,
                EasyType::String,
                EasyType::Slist,
                EasyType::Cbptr,
                EasyType::Blob,
                EasyType::Function,
            ]
        );
    }

    #[test]
    fn easy_type_round_trips_through_its_integer() {
        for member in EasyType::ALL {
            assert_eq!(EasyType::from_i32(member.as_i32()), Some(member));
        }
        // Outside the enumeration, and therefore not a member. A C caller
        // can produce these, so they are answered rather than assumed away.
        assert_eq!(EasyType::from_i32(-1), None);
        assert_eq!(EasyType::from_i32(9), None);
        assert_eq!(EasyType::from_i32(i32::MAX), None);
    }

    #[test]
    fn the_alias_flag_is_bit_zero_and_the_only_bit() {
        // include/curl/options.h:47 -- `#define CURLOT_FLAG_ALIAS (1 << 0)`.
        assert_eq!(CURLOT_FLAG_ALIAS, 1);
        assert_eq!(OptionFlags::ALIAS.as_u32(), CURLOT_FLAG_ALIAS);
        assert_eq!(OptionFlags::NONE.as_u32(), 0);
        assert!(OptionFlags::ALIAS.is_alias());
        assert!(!OptionFlags::NONE.is_alias());
        assert_eq!(OptionFlags::default(), OptionFlags::NONE);
        // The predicate reads the bit, it does not compare the word, so a
        // row carrying an unknown bit alongside it is still an alias and a
        // row carrying only an unknown bit is not.
        assert!(OptionFlags(0b11).is_alias());
        assert!(!OptionFlags(0b10).is_alias());
    }

    #[test]
    fn option_type_bases_are_the_five_measured_values() {
        // include/curl/curl.h:1111-1115.
        let bases: Vec<i32> =
            OptionTypeBase::ALL.iter().map(|base| base.base()).collect();
        assert_eq!(bases, vec![0, 10_000, 20_000, 30_000, 40_000]);
        assert_eq!(OptionTypeBase::STRIDE, 10_000);
    }

    #[test]
    fn option_id_decodes_its_band_at_every_boundary() {
        for (index, base) in OptionTypeBase::ALL.iter().enumerate() {
            let low = base.base();
            let high = low + OptionTypeBase::STRIDE - 1;
            assert_eq!(
                OptionId(low).type_band(),
                Some(*base),
                "the first identifier of the band"
            );
            assert_eq!(
                OptionId(high).type_band(),
                Some(*base),
                "the largest identifier of the band"
            );
            assert_eq!(OptionId(low).type_base(), low);
            assert_eq!(OptionId(high).type_base(), low);
            assert_eq!(OptionId(low).type_ordinal(), 0);
            assert_eq!(
                OptionId(high).type_ordinal(),
                OptionTypeBase::STRIDE - 1
            );
            // The bands are contiguous: one past the top of a band is the
            // bottom of the next, so no identifier falls between two.
            let next_band = OptionTypeBase::ALL.get(index + 1);
            assert_eq!(
                OptionId(high + 1).type_band(),
                next_band.copied(),
                "the identifier just past the band"
            );
        }
    }

    #[test]
    fn option_id_outside_the_bands_decodes_to_nothing() {
        // Past the last band.
        assert_eq!(OptionId(50_000).type_band(), None);
        assert_eq!(OptionId(i32::MAX).type_band(), None);
        // Negative. This needs its own guard rather than falling out of
        // the arithmetic: `%` truncates toward zero, so OptionId(-1) has
        // ordinal -1 and therefore base 0, which would otherwise read as
        // the `Long` band.
        assert_eq!(OptionId(-1).type_ordinal(), -1);
        assert_eq!(OptionId(-1).type_base(), 0);
        assert_eq!(OptionId(-1).type_band(), None);
        assert_eq!(OptionId(-10_001).type_band(), None);
        assert_eq!(OptionId(i32::MIN).type_band(), None);
    }

    #[test]
    fn option_id_band_decode_matches_truncating_division() {
        // `type_base` is written as a subtraction of the remainder. The
        // ABI crate writes the same decode as `value / 10000 * 10000`, and
        // the two must agree for every input, not just for the table's.
        //
        // The probes are written relative to the stride -- "the boundary",
        // "one before it", "one past it" -- rather than as bare integers.
        // That is deliberate: it states that these are arithmetic edge
        // cases and not option identifiers quoted from curl's table, which
        // this module is forbidden to restate.
        const S: i32 = OptionTypeBase::STRIDE;
        for probe in [
            0,
            1,
            S - 1,
            S,
            S + 1,
            3 * S - 1,
            4 * S,
            5 * S - 1,
            i32::MAX,
            -1,
            -(S - 1),
            -S,
            i32::MIN + 1,
        ] {
            assert_eq!(
                OptionId(probe).type_base(),
                probe / OptionTypeBase::STRIDE * OptionTypeBase::STRIDE,
                "the two spellings of the band decode must agree for \
                 {probe}"
            );
        }
    }

    #[test]
    fn the_unset_identifier_is_zero() {
        // C's `if(name || id)` treats a zero id as absent, which costs it
        // nothing because option numbering starts at 1.
        assert_eq!(OptionId::UNSET, OptionId(0));
        assert_eq!(OptionId::UNSET.as_i32(), 0);
    }

    // The tripwire from lib/easyoptions.c.

    #[test]
    fn the_lastentry_tripwire_is_the_c_expression() {
        // `return (CURLOPT_LASTENTRY % 10000) != (328 + 1);`
        assert_eq!(EASYOPTS_LASTENTRY_ORDINAL, 329);

        // The check is `% 10000 == 329`, so it holds for the bound in
        // whichever band it sits in -- and the `% 10000` is doing real
        // work, because the bound is neither 328 nor 329.
        for base in OptionTypeBase::ALL {
            let bound = OptionId(base.base() + EASYOPTS_LASTENTRY_ORDINAL);
            assert!(
                easyopts_in_sync(bound),
                "the bound in band {} must satisfy the check",
                base.base()
            );
        }

        // Off by one in either direction is exactly what the tripwire
        // exists to catch: an option added to the enumeration without
        // regenerating the table, or removed without it.
        let object = OptionTypeBase::ObjectPoint.base();
        assert!(!easyopts_in_sync(OptionId(
            object + EASYOPTS_LASTENTRY_ORDINAL - 1
        )));
        assert!(!easyopts_in_sync(OptionId(
            object + EASYOPTS_LASTENTRY_ORDINAL + 1
        )));
        assert!(!easyopts_in_sync(OptionId::UNSET));
    }

    // The anti-duplication check: the algorithm and the table agree.

    #[test]
    fn the_three_entry_points_agree_about_every_row() {
        // The mandatory anti-duplication assertion of the mission brief,
        // run here over synthetic tables. The authority table cannot be
        // reached from this crate by construction, so the same walk is
        // published as `first_inconsistent_row` for the crate that owns
        // it to run over the real 324 rows.
        for table in [
            &TABLE[..],
            &ALIAS_FIRST[..],
            &NO_SENTINEL[..],
            &AFTER_SENTINEL[..],
            &SENTINEL_ONLY[..],
            &EMPTY[..],
        ] {
            assert_eq!(
                first_inconsistent_row(table),
                None,
                "the entry points disagree about a row"
            );
        }
    }

    #[test]
    fn the_consistency_check_detects_a_duplicated_identifier() {
        // Non-vacuity for the check above. Two PREFERRED rows sharing one
        // identifier is precisely the shape a second, drifted table
        // produces, and `by_id` can then only ever answer with the first
        // of them -- so the second row fails the walk.
        static DUPLICATED: [EasyOption; 3] = [
            row(Some(ALPHA), BETA_ID, EasyType::Long, OptionFlags::NONE),
            row(Some(BETA), BETA_ID, EasyType::String, OptionFlags::NONE),
            SENTINEL,
        ];
        let defect =
            first_inconsistent_row(&DUPLICATED).expect("a defect is found");
        assert_eq!(defect.name, Some(BETA));
    }

    #[test]
    fn the_consistency_check_detects_a_dangling_alias() {
        // An alias whose identifier no preferred row carries. Every one of
        // `lib/easyoptions.c`'s 13 flagged rows points at an unflagged
        // one, so this shape is a defect and is reported as one.
        static DANGLING: [EasyOption; 2] = [
            row(
                Some(OLD_BETA),
                BETA_ID,
                EasyType::String,
                OptionFlags::ALIAS,
            ),
            SENTINEL,
        ];
        let defect =
            first_inconsistent_row(&DANGLING).expect("a defect is found");
        assert_eq!(defect.name, Some(OLD_BETA));
    }

    // by_name: lib/easygetopt.c:38-41 and :53-57.

    #[test]
    fn by_name_is_case_insensitive() {
        // `curl_strequal` folds ASCII, so every spelling of one name finds
        // one row -- and it is the SAME row, by address.
        let canonical =
            by_name(&TABLE, ALPHA).expect("the exact spelling is found");
        for spelling in ["alpha_one", "ALPHA_ONE", "AlPhA_oNe"] {
            let found = by_name_str(&TABLE, spelling)
                .unwrap_or_else(|| panic!("{spelling} must be found"));
            assert!(std::ptr::eq(found, canonical));
        }
    }

    #[test]
    fn by_name_matches_alias_rows() {
        // The name branch tests nothing but the name, so a retired
        // spelling returns ITS OWN row -- flagged, and carrying the
        // preferred identifier -- rather than the preferred row.
        let found = by_name(&TABLE, OLD_BETA).expect("the alias is found");
        assert_eq!(found.name, Some(OLD_BETA));
        assert!(found.is_alias());
        assert_eq!(found.id, BETA_ID);
        assert!(!std::ptr::eq(
            found,
            by_name(&TABLE, BETA).expect("the preferred row is found")
        ));
    }

    #[test]
    fn by_name_matches_the_whole_name_untrimmed_and_unprefixed() {
        // The table stores names with `CURLOPT_` already stripped, and
        // nothing here trims. All three of these miss.
        assert!(by_name_str(&TABLE, "CURLOPT_ALPHA_ONE").is_none());
        assert!(by_name_str(&TABLE, "ALPHA_ONE ").is_none());
        assert!(by_name_str(&TABLE, "ALPHA").is_none());
        assert!(by_name_str(&TABLE, "").is_none());
    }

    #[test]
    fn by_name_str_agrees_with_by_name() {
        for row in super::rows(&TABLE) {
            let name = row.name_str().expect("a real row has a name");
            let through_cstr =
                by_name(&TABLE, row.name.expect("a real row has a name"));
            let through_str = by_name_str(&TABLE, name);
            match (through_cstr, through_str) {
                (Some(left), Some(right)) => {
                    assert!(std::ptr::eq(left, right));
                }
                (left, right) => {
                    panic!("the two spellings disagree: {left:?} {right:?}")
                }
            }
        }
    }

    #[test]
    fn by_name_str_cannot_match_a_name_holding_an_interior_nul() {
        // A `&str` can hold a NUL where a C string cannot. A stored name
        // comes from a `CStr` and holds none, so the byte sequences can
        // never be equal and no special case is needed.
        assert!(by_name_str(&TABLE, "ALPHA_ONE\0").is_none());
        assert!(by_name_str(&TABLE, "ALPHA\0ONE").is_none());
    }

    #[test]
    fn an_unknown_name_yields_nothing() {
        assert!(by_name(&TABLE, ABSENT).is_none());
        assert!(by_name_str(&TABLE, "IN_NO_TABLE_AT_ALL").is_none());
    }

    // by_id: lib/easygetopt.c:42-46 and :59-62.

    #[test]
    fn by_id_never_returns_an_alias() {
        // The C comment is `/* do not match alias options */`. Asserted
        // with the alias BOTH after and before the preferred row, so the
        // answer cannot be an accident of ordering.
        for table in [&TABLE[..], &ALIAS_FIRST[..]] {
            let found =
                by_id(table, BETA_ID).expect("the preferred row is found");
            assert!(!found.is_alias());
            assert_eq!(found.name, Some(BETA));
            assert_eq!(found.id, BETA_ID);
        }
    }

    #[test]
    fn by_id_returns_the_row_bearing_the_identifier() {
        for row in super::rows(&TABLE).filter(|row| row.is_preferred()) {
            let found = by_id(&TABLE, row.id).expect("a preferred row");
            assert!(std::ptr::eq(found, row));
        }
    }

    #[test]
    fn an_unknown_identifier_yields_nothing() {
        assert!(by_id(&TABLE, ABSENT_ID).is_none());
        assert!(by_id(&TABLE, OptionId(i32::MAX)).is_none());
        assert!(by_id(&TABLE, OptionId(-1)).is_none());
    }

    #[test]
    fn the_unset_identifier_yields_nothing_without_searching() {
        // C's own `by_id(0)` trips `DEBUGASSERT(name || id)` in a debug
        // build and returns NULL in a release one. The guard is hoisted
        // into `by_id` so that every build gives the release answer: a
        // development-only assertion must not turn a defined release
        // behaviour into a panic.
        assert!(by_id(&TABLE, OptionId::UNSET).is_none());
        // Including for a table whose sentinel carries that very value.
        assert!(by_id(&SENTINEL_ONLY, OptionId::UNSET).is_none());
    }

    // lookup: the two branches, and the ignored argument.

    #[test]
    fn lookup_ignores_the_identifier_when_a_name_is_given() {
        // "when name is used, the id argument is ignored"
        // (lib/easygetopt.c:55). Every identifier gives the same answer.
        let canonical = by_name(&TABLE, GAMMA).expect("found by name");
        for id in [
            OptionId::UNSET,
            ALPHA_ID,
            BETA_ID,
            ABSENT_ID,
            OptionId(i32::MAX),
            OptionId(i32::MIN),
        ] {
            let found = lookup(&TABLE, Some(GAMMA), id)
                .expect("the name decides the answer");
            assert!(std::ptr::eq(found, canonical));
        }
    }

    #[test]
    fn lookup_without_a_name_is_the_identifier_branch() {
        let by_lookup =
            lookup(&TABLE, None, BETA_ID).expect("the preferred row");
        let by_entry = by_id(&TABLE, BETA_ID).expect("the preferred row");
        assert!(std::ptr::eq(by_lookup, by_entry));
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "lookup needs a name or an id")]
    fn lookup_with_neither_a_name_nor_an_identifier_is_a_caller_defect() {
        // Reproduces `DEBUGASSERT(name || id)` (lib/easygetopt.c:33). Only
        // meaningful where debug assertions are compiled in, hence the
        // `cfg`: in a release build the guard below returns `None`
        // instead, which is what the C release build does.
        let _ = lookup(&TABLE, None, OptionId::UNSET);
    }

    // next: lib/easygetopt.c:65-76.

    #[test]
    fn next_from_nothing_yields_the_first_row() {
        let first = next(&TABLE, None).expect("the table has a first row");
        assert!(std::ptr::eq(first, &TABLE[0]));
        assert_eq!(first.name, Some(ALPHA));
    }

    #[test]
    fn next_walks_the_table_in_its_own_order_and_stops_at_the_sentinel() {
        // Order is `lib/optiontable.pl`'s and is observable ABI, so the
        // walk is asserted as a sequence rather than as a set.
        assert_eq!(
            walk(&TABLE),
            vec!["ALPHA_ONE", "BETA_TWO", "OLD_BETA", "GAMMA_THREE"]
        );
        // The alias is walked: `next` filters nothing.
        assert_eq!(walk(&TABLE).len(), super::rows(&TABLE).count());
    }

    #[test]
    fn next_from_the_last_real_row_yields_nothing() {
        let last = &TABLE[3];
        assert!(last.is_preferred());
        assert!(next(&TABLE, Some(last)).is_none());
    }

    #[test]
    fn next_from_the_sentinel_yields_nothing() {
        // C's `prev && prev->name` test fails on a NULL name.
        let sentinel = &TABLE[4];
        assert!(sentinel.is_sentinel());
        assert!(next(&TABLE, Some(sentinel)).is_none());
    }

    #[test]
    fn next_from_a_row_of_another_table_yields_nothing() {
        // C would do `prev++` and read memory it does not own. Every row a
        // consumer can obtain comes from the table it was walking, so no
        // defined input reaches this path.
        assert!(next(&TABLE, Some(&FOREIGN[0])).is_none());
        // Equal CONTENTS are not enough: identity is by address.
        assert_eq!(FOREIGN[0], TABLE[0]);
        assert!(next(&TABLE, Some(&FOREIGN[0])).is_none());
    }

    #[test]
    fn next_walks_a_table_that_has_no_sentinel() {
        // The search stops at the first sentinel or at the end of the
        // slice, so a caller may omit the terminator entirely.
        assert_eq!(walk(&NO_SENTINEL), vec!["ALPHA_ONE", "BETA_TWO"]);
        assert!(next(&NO_SENTINEL, Some(&NO_SENTINEL[1])).is_none());
    }

    #[test]
    fn rows_after_a_sentinel_are_unreachable() {
        // Exactly as in C, where the sentinel ends the loop.
        assert_eq!(walk(&AFTER_SENTINEL), vec!["ALPHA_ONE"]);
        assert!(by_name(&AFTER_SENTINEL, GAMMA).is_none());
        assert!(by_id(&AFTER_SENTINEL, GAMMA_ID).is_none());
        // Handed the hidden row directly, `next` still refuses to
        // continue past the sentinel that precedes it.
        assert!(next(&AFTER_SENTINEL, Some(&AFTER_SENTINEL[2])).is_none());
    }

    // Degenerate tables: no panic, no out-of-bounds index.

    #[test]
    fn a_sentinel_only_table_answers_nothing_everywhere() {
        assert!(by_name(&SENTINEL_ONLY, ALPHA).is_none());
        assert!(by_name_str(&SENTINEL_ONLY, "ALPHA_ONE").is_none());
        assert!(by_id(&SENTINEL_ONLY, ALPHA_ID).is_none());
        assert!(next(&SENTINEL_ONLY, None).is_none());
        assert!(next(&SENTINEL_ONLY, Some(&SENTINEL_ONLY[0])).is_none());
        assert!(walk(&SENTINEL_ONLY).is_empty());
    }

    #[test]
    fn an_empty_table_answers_nothing_everywhere() {
        assert!(by_name(&EMPTY, ALPHA).is_none());
        assert!(by_name_str(&EMPTY, "ALPHA_ONE").is_none());
        assert!(by_id(&EMPTY, ALPHA_ID).is_none());
        assert!(next(&EMPTY, None).is_none());
        assert!(next(&EMPTY, Some(&TABLE[0])).is_none());
        assert!(walk(&EMPTY).is_empty());
    }

    // The row view type.

    #[test]
    fn the_row_predicates_partition_the_table() {
        let alpha = &TABLE[0];
        assert!(!alpha.is_sentinel());
        assert!(!alpha.is_alias());
        assert!(alpha.is_preferred());

        let alias = &TABLE[2];
        assert!(!alias.is_sentinel());
        assert!(alias.is_alias());
        assert!(!alias.is_preferred());

        let sentinel = &TABLE[4];
        assert!(sentinel.is_sentinel());
        assert!(!sentinel.is_alias());
        assert!(!sentinel.is_preferred());
    }

    #[test]
    fn the_row_name_accessors_drop_the_terminator() {
        let alpha = &TABLE[0];
        assert_eq!(alpha.name_bytes(), Some(&b"ALPHA_ONE"[..]));
        assert_eq!(alpha.name_str(), Some("ALPHA_ONE"));
        // No NUL survives into either view.
        assert!(!alpha
            .name_bytes()
            .expect("a real row has a name")
            .contains(&0));

        let sentinel = &TABLE[4];
        assert_eq!(sentinel.name_bytes(), None);
        assert_eq!(sentinel.name_str(), None);
    }

    #[test]
    fn the_row_fields_are_in_the_headers_order() {
        // struct curl_easyoption is `{ name, id, type, flags }`
        // (include/curl/options.h:51-56). Field order is not observable
        // from Rust, so what is asserted here is that the row carries
        // exactly those four values and that each is readable -- the
        // projection into the C struct, which IS order-sensitive, lives in
        // the ABI crate and is asserted there.
        let beta = &TABLE[1];
        assert_eq!(beta.name, Some(BETA));
        assert_eq!(beta.id, BETA_ID);
        assert_eq!(beta.value_type, EasyType::String);
        assert_eq!(beta.flags, OptionFlags::NONE);
    }

    #[test]
    fn the_value_type_is_read_from_the_row_and_never_from_the_identifier() {
        // Both of these rows sit in the object-pointer band, and they
        // carry DIFFERENT types. Deriving the type from `id / 10000` would
        // make them indistinguishable, which is why the metadata table
        // exists at all (include/curl/curl.h:1127-1136).
        static SHARED_BAND: [EasyOption; 3] = [
            row(
                Some(ALPHA),
                OptionId(14_320),
                EasyType::String,
                OptionFlags::NONE,
            ),
            row(
                Some(BETA),
                OptionId(14_321),
                EasyType::Slist,
                OptionFlags::NONE,
            ),
            SENTINEL,
        ];
        let first = by_name(&SHARED_BAND, ALPHA).expect("the first row");
        let second = by_name(&SHARED_BAND, BETA).expect("the second row");
        assert_eq!(first.id.type_band(), second.id.type_band());
        assert_ne!(first.value_type, second.value_type);
        assert_eq!(first.value_type, EasyType::String);
        assert_eq!(second.value_type, EasyType::Slist);
    }
}
