// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! The two modern percent-encoding entry points.
//!
//! | Symbol | Authority | Engine backing |
//! |--------|-----------|----------------|
//! | `curl_easy_escape`   | `lib/escape.c:50-87`   | `curl_rs_lib::url::escape::escape` |
//! | `curl_easy_unescape` | `lib/escape.c:163-184` | `curl_rs_lib::url::escape::unescape` |
//!
//! Neither decides what a byte encodes to. The unreserved set, the case of the
//! hex digits, and the exact conditions under which a `%` introduces an escape
//! all live in the engine module, which asserts them against an oracle measured
//! from the frozen library. This file marshals, and marshalling is the whole of
//! its job (specification 0.3.3, pattern P10).
//!
//! # Where the two legacy names went, and why they are not here
//!
//! `curl_escape` and `curl_unescape` predate the `curl_easy_` spelling and are
//! kept for ABI compatibility. `lib/escape.c:36-45` implements each as a single
//! call into its modern counterpart with `NULL` for the handle, and that forward
//! is reproduced literally -- but in [`super::misc`], not here, because the
//! target partition assigns the two legacy names to `ffi/misc.rs` and the two
//! modern ones to `ffi/easy.rs`. The forward direction is what matters and it is
//! unchanged: `misc` calls the pair below rather than repeating the
//! marshalling, so the length convention has exactly one implementation.
//!
//! # The handle argument is accepted and ignored
//!
//! `curl_easy_escape` and `curl_easy_unescape` each take a `CURL *` that has
//! been unused since 7.82.0; the C says so explicitly at `lib/escape.c:48` and
//! `:161` and discards it with `(void)data`. The parameter cannot be removed --
//! it is in the frozen signature (specification 0.8.1) and callers pass it --
//! so it is accepted, named as the header names it, and ignored. That it is
//! ignored is load-bearing rather than incidental: it is why these four
//! functions need no easy handle to exist, and therefore why they can be
//! exported before the handle layer is built.
//!
//! # Ownership: every non-null return is the caller's to free
//!
//! All four hand back a buffer the application releases with `curl_free`.
//! Allocation goes through [`super::memory`] rather than `CString::into_raw`
//! so that an application which replaced the allocator through
//! `curl_global_init_mem` frees with the same one that allocated -- and so that
//! a plain `free`, which applications do use against libcurl, behaves as it
//! does against the C library.
//!
//! # Why `curl_easy_unescape` needs an out-parameter at all
//!
//! Decoded output can contain NUL: `curl_easy_unescape` decodes with
//! `REJECT_NADA` (`lib/escape.c:170-171`), which accepts every byte, so
//! `"a%00b"` decodes to three bytes with a NUL in the middle. `strlen` would
//! report one. That is the entire reason for `outlength`, and it is why the
//! engine returns a byte vector rather than a string.
//!
//! The write order matters and is preserved. The C allocates first
//! (`lib/escape.c:116`) and stores the length afterwards (`:149-151`), so a
//! failed allocation leaves `*outlength` untouched. The same holds here: the
//! buffer is produced, checked, and only then is the length written. A caller
//! that initialises its own variable and tests the return value therefore sees
//! exactly what it sees against C libcurl.

use core::ffi::{c_char, c_int};
use core::ptr;
use core::slice;
use std::ffi::CStr;

use curl_rs_lib::url::escape::{escape, unescape};

use super::handle::CURL;
use super::memory;
use super::panic_boundary::guard_ptr;

/// Applies the C length convention and hands the resulting bytes to `body`.
///
/// This is the whole of the marshalling the four entry points share, and the
/// only place in the module that dereferences the caller's pointer.
///
/// Returns `None` for exactly the two argument shapes the C rejects before
/// doing any work -- a null string, or a negative length -- which are the
/// conditions at `lib/escape.c:56` and `:167`. Note that the second is spelled
/// as a positive test in the C (`length >= 0`) for the unescape side and as a
/// negative one (`inlength < 0`) for the escape side; they are the same
/// condition and are implemented once.
///
/// The length rule itself is `lib/escape.c:59` and `:115`: zero means "measure
/// the string", and any other value is trusted **absolutely**, so the C reads
/// that many bytes whether or not a NUL appears first. Both behaviours are
/// observable -- `curl_easy_escape(NULL, "", 1)` returns `"%00"` because it
/// escapes the terminator -- and both are pinned by the engine's oracle, so
/// this function reproduces the rule rather than improving on it.
///
/// # Safety
///
/// `string` must either be null or address at least the number of bytes the
/// length rule above resolves to. When `length` is zero that means a
/// NUL-terminated string; when it is positive it means `length` readable bytes,
/// which is the caller's promise and not something this crate can check. The
/// bytes must not be mutated for the duration of the call.
unsafe fn with_input<R>(
    string: *const c_char,
    length: c_int,
    body: impl FnOnce(&[u8]) -> R,
) -> Option<R> {
    if string.is_null() || length < 0 {
        return None;
    }

    let resolved = if length == 0 {
        // SAFETY: `string` is non-null, and a zero `length` is precisely the
        // caller's assertion that it is NUL-terminated -- that is what makes
        // the C's `strlen` at `lib/escape.c:59` legitimate. The borrow ends
        // before this statement does, so nothing can invalidate it.
        unsafe { CStr::from_ptr(string) }.to_bytes().len()
    } else {
        // `length` is positive here. `try_from` cannot fail on any target whose
        // `usize` is at least as wide as `c_int`, which covers all four of the
        // 64-bit targets specification 0.8.3 mandates. The fallback declines
        // rather than panics, so a hypothetical narrower target degrades to the
        // C's null return instead of unwinding across the boundary.
        match usize::try_from(length) {
            Ok(explicit) => explicit,
            Err(_) => return None,
        }
    };

    // SAFETY: `string` is non-null and, by this function's documented safety
    // contract, addresses at least `resolved` readable bytes that stay
    // unmutated for the call. `c_char` and `u8` have the same size and
    // alignment, and `u8` has an alignment of one, so the cast cannot
    // misalign. `resolved` derives either from `CStr` -- which measured a real
    // object -- or from the caller's own length, so it cannot exceed
    // `isize::MAX`. The slice is consumed by `body` and does not escape.
    let bytes = unsafe { slice::from_raw_parts(string.cast::<u8>(), resolved) };
    Some(body(bytes))
}

/// Percent-encodes a string.
///
/// Supersedes `curl_easy_escape` (`lib/escape.c:50-87`). Returns a
/// NUL-terminated, caller-owned string that must be released with `curl_free`,
/// or null when `string` is null or `length` is negative.
///
/// `handle` is ignored, as it has been since 7.82.0.
///
/// A zero `length` means the string is measured with `strlen`; any other value
/// is used as given. An empty result is an empty string, not null:
/// `lib/escape.c:60-61` returns a duplicate of `""`, and the difference reaches
/// the application, which must free one and not the other.
///
/// # Safety
///
/// `string` must satisfy the contract described on [`with_input`].
#[no_mangle]
pub unsafe extern "C" fn curl_easy_escape(
    handle: *mut CURL,
    string: *const c_char,
    length: c_int,
) -> *mut c_char {
    guard_ptr(|| {
        // Accepted and discarded, exactly as `(void)data` at
        // `lib/escape.c:54`. Bound rather than left unnamed so the signature
        // keeps the parameter name the frozen header uses.
        let _ = handle;

        // SAFETY: forwarded verbatim from this function's own safety contract,
        // which is what `with_input` requires of its caller.
        let escaped = unsafe { with_input(string, length, escape) };
        // Bound before destructuring because a `let ... else` initialiser may
        // not end in a block expression, and because it keeps the SAFETY
        // comment above directly against the `unsafe` it justifies.
        let Some(escaped) = escaped else {
            return ptr::null_mut();
        };
        // The engine reports a refused allocation -- the output is three times
        // the caller's own length -- and `lib/escape.c:75` and `:82` answer that
        // with the same null this returns. Two routes to one observable
        // outcome, which is what the C has too.
        let Ok(escaped) = escaped else {
            return ptr::null_mut();
        };
        memory::copy_to_c_string(&escaped)
    })
}

/// Percent-decodes a string.
///
/// Supersedes `curl_easy_unescape` (`lib/escape.c:163-184`). Returns a
/// caller-owned buffer that must be released with `curl_free`, or null when
/// `string` is null or `length` is negative.
///
/// When `outlength` is non-null the decoded length is stored through it, and
/// that length is authoritative: the decode accepts NUL, so the buffer may
/// contain interior NUL bytes that `strlen` would not count. The buffer is
/// still NUL-terminated, so a caller that ignores `outlength` sees a valid C
/// string, which is what makes the parameter optional.
///
/// `*outlength` is written only once the buffer exists, so a failed allocation
/// leaves the caller's variable untouched -- as does an argument rejection.
///
/// `handle` is ignored, as it has been since 7.82.0.
///
/// # Safety
///
/// `string` must satisfy the contract described on [`with_input`].
/// `outlength`, when non-null, must be a writable, aligned `int`.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_unescape(
    handle: *mut CURL,
    string: *const c_char,
    length: c_int,
    outlength: *mut c_int,
) -> *mut c_char {
    guard_ptr(|| {
        let _ = handle;

        // SAFETY: forwarded verbatim from this function's own safety contract.
        let decoded = unsafe { with_input(string, length, unescape) };
        let Some(decoded) = decoded else {
            return ptr::null_mut();
        };
        // As in `curl_easy_escape`: a refused output buffer is
        // `lib/escape.c:117-118`'s null, not an abort.
        let Ok(decoded) = decoded else {
            return ptr::null_mut();
        };

        // `lib/escape.c:176-180`: a result too large to express as an `int` is
        // not reported, and the C frees the buffer and returns null rather than
        // truncating the length. Unreachable in practice -- it needs more than
        // two gibibytes of output -- but the branch is what makes the `int`
        // out-parameter sound, so it is reproduced instead of assumed away.
        let Ok(decoded_len) = c_int::try_from(decoded.len()) else {
            return ptr::null_mut();
        };

        // Allocate BEFORE storing the length, matching `lib/escape.c:116` and
        // `:149-151`, so that a failed allocation leaves `*outlength` as the
        // caller left it.
        let buffer = memory::copy_to_c_string(&decoded);
        if buffer.is_null() {
            return ptr::null_mut();
        }

        if !outlength.is_null() {
            // SAFETY: `outlength` is non-null and, by this function's safety
            // contract, is a writable aligned `c_int` for the duration of the
            // call. The write is a single scalar store to memory the caller
            // owns.
            unsafe { outlength.write(decoded_len) };
        }

        buffer
    })
}

#[cfg(test)]
mod tests {
    use super::{curl_easy_escape, curl_easy_unescape};
    use crate::ffi::memory;
    // The two legacy names live in `ffi/misc.rs`, which the target partition
    // assigns them to, and they forward here. The equivalence test below reaches
    // across that boundary on purpose: it is the forward itself that is under
    // test, so testing it from either side alone would leave the seam unchecked.
    use crate::ffi::misc::{curl_escape, curl_unescape};

    use core::ffi::c_int;
    use core::ptr;
    use std::ffi::CStr;

    /// Calls an escape-style entry point and returns the result as bytes.
    ///
    /// The result is always a C string here because escaped output can never
    /// contain a NUL -- every NUL becomes `%00` -- so `CStr` is lossless.
    fn escaped(input: &str, length: c_int) -> Option<Vec<u8>> {
        let c = std::ffi::CString::new(input)
            .expect("no interior NUL in the literal");
        // SAFETY: `c` owns a NUL-terminated buffer that outlives the call, and
        // `length` never exceeds its length plus the terminator in these tests.
        let raw =
            unsafe { curl_easy_escape(ptr::null_mut(), c.as_ptr(), length) };
        if raw.is_null() {
            return None;
        }
        // SAFETY: a non-null return is a NUL-terminated buffer owned by this
        // caller, by the function's documented contract.
        let bytes = unsafe { CStr::from_ptr(raw) }.to_bytes().to_vec();
        // SAFETY: `raw` came from `memory::copy_to_c_string` and is released
        // exactly once, here.
        unsafe { memory::free(raw.cast()) };
        Some(bytes)
    }

    /// Calls `curl_easy_unescape` and returns the buffer plus the stored length.
    fn unescaped(input: &str, length: c_int) -> Option<(Vec<u8>, c_int)> {
        let c = std::ffi::CString::new(input)
            .expect("no interior NUL in the literal");
        let mut olen: c_int = -12345;
        // SAFETY: as above, plus `olen` is a live writable `c_int`.
        let raw = unsafe {
            curl_easy_unescape(
                ptr::null_mut(),
                c.as_ptr(),
                length,
                &mut olen as *mut c_int,
            )
        };
        if raw.is_null() {
            // The contract says the length is untouched on failure, which the
            // caller checks against this sentinel.
            return None;
        }
        let len = usize::try_from(olen).expect("non-negative length");
        // SAFETY: the buffer holds at least `len` initialised bytes followed by
        // a terminator, by the function's contract.
        let bytes =
            unsafe { std::slice::from_raw_parts(raw.cast::<u8>(), len) }
                .to_vec();
        // SAFETY: released exactly once.
        unsafe { memory::free(raw.cast()) };
        Some((bytes, olen))
    }

    #[test]
    fn escape_marshals_the_length_convention() {
        // Zero measures the string.
        assert_eq!(escaped("a b~c", 0).as_deref(), Some(b"a%20b~c".as_slice()));
        // A non-zero length is trusted as given, and stops short.
        assert_eq!(escaped("a b~c", 3).as_deref(), Some(b"a%20b".as_slice()));
        // The two argument rejections.
        assert_eq!(escaped("abc", -1), None);
        // SAFETY: a null string is exactly the case under test.
        assert!(unsafe { curl_easy_escape(ptr::null_mut(), ptr::null(), 5) }
            .is_null());
    }

    #[test]
    fn escape_reads_the_terminator_when_told_to() {
        // The behaviour that proves the length is trusted absolutely rather
        // than clamped to the string: `lib/escape.c:59` takes a non-zero
        // `inlength` at face value, so the NUL is escaped like any other
        // reserved byte. Clamping would return "" and "ab" instead.
        assert_eq!(escaped("", 1).as_deref(), Some(b"%00".as_slice()));
        assert_eq!(escaped("ab", 3).as_deref(), Some(b"ab%00".as_slice()));
    }

    #[test]
    fn an_empty_escape_is_an_empty_string_not_null() {
        // `lib/escape.c:60-61` duplicates "" rather than failing, and the
        // application must free the result, so null would be a leak-shaped bug
        // in the opposite direction.
        assert_eq!(escaped("", 0).as_deref(), Some(b"".as_slice()));
    }

    #[test]
    fn unescape_stores_the_length_and_keeps_interior_nul() {
        assert_eq!(unescaped("%41%42%43", 0), Some((b"ABC".to_vec(), 3)));
        // The reason `outlength` exists: strlen would report 1 here.
        assert_eq!(
            unescaped("a%00b", 0),
            Some((vec![b'a', 0x00, b'b'], 3)),
            "REJECT_NADA accepts NUL, so the stored length is authoritative"
        );
        // Either hex case, and a lone '%' passes through.
        assert_eq!(unescaped("%4a%4B", 0), Some((b"JK".to_vec(), 2)));
        assert_eq!(unescaped("abc%", 0), Some((b"abc%".to_vec(), 4)));
    }

    #[test]
    fn unescape_leaves_the_out_parameter_untouched_on_rejection() {
        // The contract the C expresses by returning before `:149`: a caller
        // that pre-sets its variable can distinguish "failed" from "decoded to
        // nothing", and both are reachable.
        let mut olen: c_int = -12345;
        let c = std::ffi::CString::new("abc").expect("literal");
        // SAFETY: a negative length is the rejection under test; `olen` is live.
        let raw = unsafe {
            curl_easy_unescape(
                ptr::null_mut(),
                c.as_ptr(),
                -1,
                &mut olen as *mut c_int,
            )
        };
        assert!(raw.is_null(), "a negative length is rejected");
        assert_eq!(olen, -12345, "the out-parameter must not be written");

        // SAFETY: a null string with a live out-parameter.
        let raw = unsafe {
            curl_easy_unescape(
                ptr::null_mut(),
                ptr::null(),
                3,
                &mut olen as *mut c_int,
            )
        };
        assert!(raw.is_null(), "a null string is rejected");
        assert_eq!(olen, -12345, "the out-parameter must not be written");

        // And an empty decode DOES write, with zero.
        assert_eq!(unescaped("", 0), Some((Vec::new(), 0)));
    }

    #[test]
    fn the_buffer_is_allocated_before_the_length_is_stored() {
        // The write ORDER is part of the contract: `lib/escape.c` allocates at
        // `:116` and stores the length at `:149-151`, so a failed allocation
        // leaves `*outlength` untouched. That difference is only observable when
        // the allocator fails, and the only way to induce that here would be to
        // install a failing malloc hook -- which is process-wide, and this
        // module has no way to serialise against the other test modules that
        // touch the hook registry, so doing so would make unrelated tests flaky.
        //
        // Asserting the order in the source is therefore the honest way to pin
        // it: deterministic, and it fails if the two statements are ever
        // swapped. The technique is the one `crate::unsafe_boundary` already
        // uses to police this crate from inside it.
        let source = include_str!("escape.rs");
        let body = source
            .split("pub unsafe extern \"C\" fn curl_easy_unescape")
            .nth(1)
            .expect("the function this test is about must exist");
        // Bound the search to the function body: an unbounded scan would answer
        // about some other function, which is a trap this project has hit before.
        // `curl_easy_unescape` is now the last item in the module -- the two
        // legacy names that used to follow it moved to `ffi/misc.rs` -- so the
        // test module's own attribute is what delimits the body.
        let body = &body[..body
            .find("\n#[cfg(test)]")
            .expect("the next item delimits the body")];

        let alloc = body
            .find("memory::copy_to_c_string")
            .expect("the buffer must be allocated in this function");
        let store = body
            .find("outlength.write(")
            .expect("the length must be stored in this function");
        assert!(
            alloc < store,
            "curl_easy_unescape must allocate ({alloc}) before storing the \
             length ({store}), so a failed allocation leaves *outlength as the \
             caller left it"
        );
        // And the null check on the out-parameter must guard the store, which is
        // what makes the parameter optional at all (`lib/escape.c:175`).
        let guard = body
            .find("if !outlength.is_null()")
            .expect("the store must be guarded");
        assert!(guard < store, "the store must sit inside the null guard");
    }

    #[test]
    fn a_null_out_parameter_is_accepted() {
        // `lib/escape.c:175` guards the store, so the length is genuinely
        // optional and the buffer is still a valid C string without it.
        let c = std::ffi::CString::new("%41%42").expect("literal");
        // SAFETY: a null out-parameter is the case under test.
        let raw = unsafe {
            curl_easy_unescape(ptr::null_mut(), c.as_ptr(), 0, ptr::null_mut())
        };
        assert!(!raw.is_null());
        // SAFETY: non-null returns are NUL-terminated.
        let s = unsafe { CStr::from_ptr(raw) }.to_bytes().to_vec();
        // SAFETY: released exactly once.
        unsafe { memory::free(raw.cast()) };
        assert_eq!(s, b"AB".to_vec());
    }

    #[test]
    fn the_legacy_names_agree_with_the_modern_ones() {
        // `lib/escape.c:36-45` makes these pure forwarders, so any divergence
        // would mean the marshalling had been duplicated and drifted.
        for (input, length) in [("a b~c", 0), ("a b~c", 3), ("", 0), ("", 1)] {
            let c = std::ffi::CString::new(input).expect("literal");
            // SAFETY: both calls take the same live NUL-terminated buffer.
            let (legacy, modern) = unsafe {
                (
                    curl_escape(c.as_ptr(), length),
                    curl_easy_escape(ptr::null_mut(), c.as_ptr(), length),
                )
            };
            assert!(
                !legacy.is_null() && !modern.is_null(),
                "{input:?}/{length}"
            );
            // SAFETY: both are NUL-terminated buffers owned here.
            let (a, b) = unsafe {
                (
                    CStr::from_ptr(legacy).to_bytes().to_vec(),
                    CStr::from_ptr(modern).to_bytes().to_vec(),
                )
            };
            // SAFETY: each released exactly once.
            unsafe {
                memory::free(legacy.cast());
                memory::free(modern.cast());
            }
            assert_eq!(a, b, "curl_escape disagrees for {input:?}/{length}");
        }

        // The unescape pair, where the legacy name additionally discards the
        // length -- so the comparison is over the C-visible string.
        let c = std::ffi::CString::new("%41%42").expect("literal");
        // SAFETY: a live NUL-terminated buffer.
        let legacy = unsafe { curl_unescape(c.as_ptr(), 0) };
        assert!(!legacy.is_null());
        // SAFETY: NUL-terminated by contract.
        let bytes = unsafe { CStr::from_ptr(legacy) }.to_bytes().to_vec();
        // SAFETY: released exactly once.
        unsafe { memory::free(legacy.cast()) };
        assert_eq!(bytes, b"AB".to_vec());

        // Both legacy names reject what the modern ones reject.
        // SAFETY: the argument rejections under test; no dereference occurs.
        unsafe {
            assert!(curl_escape(ptr::null(), 0).is_null());
            assert!(curl_escape(c.as_ptr(), -1).is_null());
            assert!(curl_unescape(ptr::null(), 0).is_null());
            assert!(curl_unescape(c.as_ptr(), -1).is_null());
        }
    }

    #[test]
    fn the_handle_argument_is_ignored_rather_than_dereferenced() {
        // `(void)data` at `lib/escape.c:54` and `:166`. A non-null, deliberately
        // invalid handle must be as harmless as a null one, because that is what
        // "ignored since 7.82.0" means and callers do still pass real handles.
        let c = std::ffi::CString::new("a b").expect("literal");
        let bogus = 0xDEAD_BEEF_usize as *mut super::CURL;
        // SAFETY: the handle is never dereferenced by either function -- which
        // is the property under test -- and the string is live and terminated.
        let (with_null, with_bogus) = unsafe {
            (
                curl_easy_escape(ptr::null_mut(), c.as_ptr(), 0),
                curl_easy_escape(bogus, c.as_ptr(), 0),
            )
        };
        assert!(!with_null.is_null() && !with_bogus.is_null());
        // SAFETY: both are NUL-terminated buffers owned here.
        let (a, b) = unsafe {
            (
                CStr::from_ptr(with_null).to_bytes().to_vec(),
                CStr::from_ptr(with_bogus).to_bytes().to_vec(),
            )
        };
        // SAFETY: each released exactly once.
        unsafe {
            memory::free(with_null.cast());
            memory::free(with_bogus.cast());
        }
        assert_eq!(a, b"a%20b".to_vec());
        assert_eq!(a, b);
    }

    #[test]
    fn every_return_is_releasable_through_curl_free() {
        // The ownership half of the contract. `copy_to_c_string` is the only
        // allocator used, so `curl_free` -- and a replaced allocator's free --
        // matches. Exercised over a mix that includes the empty result, which
        // is still a one-byte allocation the caller must release.
        for input in ["", "a b~c", "%41%00%42", "100%"] {
            let c = std::ffi::CString::new(input).expect("literal");
            // SAFETY: a live NUL-terminated buffer; both results are owned here.
            let (e, u) = unsafe {
                (
                    curl_easy_escape(ptr::null_mut(), c.as_ptr(), 0),
                    curl_easy_unescape(
                        ptr::null_mut(),
                        c.as_ptr(),
                        0,
                        ptr::null_mut(),
                    ),
                )
            };
            assert!(!e.is_null() && !u.is_null(), "{input:?}");
            // SAFETY: each pointer came from `copy_to_c_string` and is passed
            // to the matching free exactly once. `curl_free` is the documented
            // release for both.
            unsafe {
                crate::ffi::misc::curl_free(e.cast());
                crate::ffi::misc::curl_free(u.cast());
            }
        }
    }
}
