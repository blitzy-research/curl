// /***************************************************************************
//  *                                  _   _ ____  _
//  *  Project                     ___| | | |  _ \| |
//  *                             / __| | | | |_) | |
//  *                            | (__| |_| |  _ <| |___
//  *                             \___|\___/|_| \_\_____|
//  *
//  * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//  *
//  * This software is licensed as described in the file COPYING, which
//  * you should have received as part of this distribution. The terms
//  * are also available at https://curl.se/docs/copyright.html.
//  *
//  * You may opt to use, copy, modify, merge, publish, distribute and/or sell
//  * copies of the Software, and permit persons to whom the Software is
//  * furnished to do so, under the terms of the COPYING file.
//  *
//  * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
//  * KIND, either express or implied.
//  *
//  * SPDX-License-Identifier: curl
//  *
//  ***************************************************************************/
//! The legacy HTTP form-post API: `lib/formdata.c` and `lib/formdata.h`,
//! superseded here in full.
//!
//! Three of the hundred symbols `lib/libcurl.def` exports live in this file
//! -- `curl_formadd`, `curl_formfree` and `curl_formget`, listed together at
//! `lib/libcurl.def:24-26`. A fourth entry point is internal:
//! `Curl_getformdata` (`lib/formdata.h:49-52`), the bridge that turns a
//! `curl_httppost` chain into the `curl_mimepart` tree that
//! [`crate::mime`] knows how to serialize.
//!
//! # Deprecated, and therefore mandatory
//!
//! Every `CURLformoption` token except `CURLFORM_NOTHING`,
//! `CURLFORM_OBSOLETE`, `CURLFORM_OBSOLETE2`, `CURLFORM_END` and
//! `CURLFORM_LASTENTRY` carries `CURL_DEPRECATED(7.56.0,...)` in
//! `include/curl/curl.h:2555-2584`, pointing callers at the `curl_mime_*`
//! family instead. A program compiled against curl 8.x that calls
//! `curl_formadd` must therefore keep working, so this module is fully
//! functional rather than a compatibility shim that fails.
//!
//! # What this module does not own
//!
//! **No serializer.** `lib/formdata.c` has none either: `Curl_getformdata`
//! translates the legacy model into `curl_mime_*` builder calls and lets
//! `lib/mime.c` emit the bytes. The same division holds here, which is why
//! every function below is expressed in terms of [`crate::mime`]'s
//! [`Mime`], [`MimePart`] and [`PartReader`].

use core::fmt;
use std::borrow::Cow;
use std::io::Read;
use std::path::Path;

use crate::crypto::rand::{Rng, SystemRng};
use crate::error::{CURLcode, CodeResult};
use crate::util::fallible;
use crate::util::redact::Redacted;
use crate::util::slist::SList;
use crate::util::CurlOffT;

use super::{
    contenttype, Mime, MimeOptions, MimePart, MimeStrategy, PartReader,
    ReadStatus, SeekResult, SeekWhence, FILE_CONTENTTYPE_DEFAULT,
};

// `crate::util::strcase` is deliberately absent from the imports above.
// `lib/formdata.c` performs exactly one string comparison -- `strcmp(
// file->contents, "-")` at `:785`, testing for the pseudo-filename that
// means standard input -- and it is case SENSITIVE, so `-` matches and
// nothing else does. There is no case-insensitive comparison anywhere in the
// file to route through `casecompare`, `ncasecompare` or `checkprefix`, and
// importing a helper this module does not use would be an unused import that
// `-D warnings` rejects. The content-type suffix match, which IS
// case-insensitive, lives in the parent module's `contenttype` table and is
// reached through it rather than reimplemented here.

// Constants transcribed from lib/formdata.c

/// The buffer `curl_formget` reads through: `char buffer[8192]`
/// (`lib/formdata.c:644`).
const FORMGET_BUFFER_SIZE: usize = 8192;

/// The content type `curl_formget` prepares the top part with
/// (`lib/formdata.c:640`).
#[rustfmt::skip]
const FORMGET_CONTENT_TYPE: &str = "multipart/form-data";

/// The pseudo-filename that means standard input (`lib/formdata.c:785`).
///
/// Compared as bytes rather than as text because the value it is compared
/// against arrives from a C `char *` and carries no encoding guarantee.
#[rustfmt::skip]
const STDIN_PSEUDO_FILENAME: &[u8] = b"-";

/// The stand-in `CURLFORM_STREAM` puts in the value slot.
///
/// `lib/formdata.c:499-504` stores the callback's context pointer in
/// `curr->value` with the comment "The following line is not strictly true
/// but we derive a value from this later on and we need this non-NULL to be
/// accepted as a fine form part". Its bytes are never read: the `CALLBACK`
/// flag exempts the value from the copy in `FormAddCheck` (`:270-275`), and
/// the bridge's callback branch (`:811-818`) reads the context rather than
/// the value. What the assignment actually accomplishes is to satisfy the
/// `!Curl_bufref_ptr(&form->value)` half of the completeness test at
/// `:230`, so an empty borrowed slice reproduces "present but meaningless"
/// without inventing content that could reach the wire.
#[rustfmt::skip]
const STREAM_VALUE_PLACEHOLDER: &[u8] = b"";

/// The invariant every helper below relies on: the accumulator is never
/// empty.
const CHAIN_NEVER_EMPTY: &str =
    "FormAdd seeds the chain with one node before reading any option";

// The outcome of a builder call: CURLFORMcode, by name

/// The outcome `curl_formadd` reports: `CURLFORMcode`
/// (`include/curl/curl.h:2607-2621`).
///
/// # The nine C tokens, and which one is dropped
///
/// | C token | Here |
/// |---|---|
/// | `CURL_FORMADD_OK` | [`Self::Ok`] |
/// | `CURL_FORMADD_MEMORY` | [`Self::Memory`] |
/// | `CURL_FORMADD_OPTION_TWICE` | [`Self::OptionTwice`] |
/// | `CURL_FORMADD_NULL` | [`Self::Null`] |
/// | `CURL_FORMADD_UNKNOWN_OPTION` | [`Self::UnknownOption`] |
/// | `CURL_FORMADD_INCOMPLETE` | [`Self::Incomplete`] |
/// | `CURL_FORMADD_ILLEGAL_ARRAY` | [`Self::IllegalArray`] |
/// | `CURL_FORMADD_DISABLED` | [`Self::Disabled`] |
/// | `CURL_FORMADD_LAST` | dropped |
///
/// `CURL_FORMADD_LAST` is the C's array bound -- its own comment is "last"
/// -- and it names no outcome. Reproducing it would create a variant that
/// can be constructed and matched but never means anything, which is exactly
/// the failure mode a Rust enum exists to prevent. It is dropped, and the
/// ABI crate reproduces the integer without needing a variant to hold it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FormCode {
    /// `CURL_FORMADD_OK`: the part was added.
    Ok,
    /// `CURL_FORMADD_MEMORY`: an allocation or a length conversion failed.
    ///
    /// The C's `malloc` sites here are fixed-size `struct curl_httppost` and
    /// `struct FormInfo` nodes, whose sizes this module chooses; a fixed-size
    /// allocation has no stable fallible spelling at the declared minimum Rust
    /// version, so the classic "malloc returned NULL" route to this code does
    /// not exist here.
    /// The variant is nonetheless live and reachable, for two reasons that
    /// AAP 0.8.2 makes it wrong to drop. First, `AddHttpPost`
    /// (`lib/formdata.c:66-68`) returns `NULL` -- and therefore this code --
    /// when a name or buffer length exceeds `LONG_MAX`, a guard that
    /// [`form_add`] reproduces. Second, `FormAddCheck` (`:273-274`) returns
    /// it when the value copy is asked for a length the allocator cannot
    /// satisfy, which is what the C's `(size_t)` cast of a negative
    /// `contentslength` produces.
    Memory,
    /// `CURL_FORMADD_OPTION_TWICE`: an option was given twice for one part.
    OptionTwice,
    /// `CURL_FORMADD_NULL`: a null pointer was given where a string was
    /// required.
    Null,
    /// `CURL_FORMADD_UNKNOWN_OPTION`: an option outside the vocabulary.
    UnknownOption,
    /// `CURL_FORMADD_INCOMPLETE`: the accumulated part is not usable.
    ///
    /// The five conditions are transcribed in [`form_add`]; the first that
    /// holds wins, and the order is the C's.
    Incomplete,
    /// `CURL_FORMADD_ILLEGAL_ARRAY`: a `CURLFORM_ARRAY` inside a
    /// `CURLFORM_ARRAY`.
    ///
    /// Raised by the ABI crate while decoding, never by [`form_add`]. See
    /// [`FormOption`] for the division of labour.
    IllegalArray,
    /// `CURL_FORMADD_DISABLED`: the form API was compiled out.
    ///
    /// Unreachable here, and deliberately so. See the module documentation.
    Disabled,
}

impl FormCode {
    /// Whether this is `CURL_FORMADD_OK`.
    #[must_use]
    pub fn is_ok(self) -> bool {
        matches!(self, Self::Ok)
    }
}

// Ownership: what curl_formfree may release, and what it must not

/// Who owns a byte range that a form entry points at.
///
/// In Rust that decision is the compiler's -- an owned `Vec<u8>` is dropped
/// and a borrowed slice is not -- but the ABI crate still has to make it,
/// because on its side of the boundary the "borrowed" case is a raw C
/// pointer that Rust must leave entirely alone. So the distinction is
/// **recorded** as well as expressed, and [`FormEntry::free_plan`] hands it
/// over.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ownership {
    /// This library holds the only copy and releases it.
    ///
    /// The `CURLFORM_COPY*` options and every option the C copies eagerly
    /// with `Curl_bufref_memdup0`.
    Owned,
    /// The caller holds the memory; this library must not release it.
    ///
    /// The `CURLFORM_PTR*` options, plus `CURLFORM_BUFFERPTR` and
    /// `CURLFORM_STREAM`, whose flags appear in `curl_formfree`'s second
    /// condition.
    Borrowed,
}

/// What `curl_formfree` would release for one entry, and what it must leave
/// alone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FreePlan {
    /// `if(!(form->flags & HTTPPOST_PTRNAME)) free(form->name);` (`:679`).
    pub name: Ownership,
    /// `if(!(form->flags & (HTTPPOST_PTRCONTENTS | HTTPPOST_BUFFER |
    /// HTTPPOST_CALLBACK))) free(form->contents);` (`:681-683`).
    pub contents: Ownership,
    /// `free(form->contenttype);` (`:684`) -- unconditional, because
    /// `CURLFORM_CONTENTTYPE` always copies (`:535`).
    pub contenttype: Ownership,
    /// `free(form->showfilename);` (`:685`) -- unconditional, because
    /// `CURLFORM_FILENAME` and `CURLFORM_BUFFER` always copy (`:559`).
    pub showfilename: Ownership,
}

// The read-function argument, made explicit

/// Whether the caller of the bridge supplied a read function.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamPolicy {
    /// A read function was supplied: a callback part reaches the mime tree
    /// with its reader installed.
    Available,
    /// The caller passed `NULL`, as `curl_formget` does: a callback part
    /// reaches the mime tree with no content.
    Unavailable,
}

// The decoded option vocabulary: the contract curl-rs-ffi drives

/// One decoded `CURLFORM_*` option.
///
/// # The division of labour with `curl-rs-ffi`
///
/// `curl_formadd`'s argument list cannot be read from safe Rust on the MSRV
/// this workspace pins, so the split is:
///
/// * **`curl-rs-ffi/src/ffi/form.rs`** walks the `va_list`, flattens any
///   `CURLFORM_ARRAY`, and produces a `Vec` of these in the order the caller
///   wrote them.
/// * **[`form_add`]** consumes that `Vec` and applies the semantics of
///   `FormAdd` (`lib/formdata.c:301-601`) to it.
///
/// # A negative length is a real code, not a clamp
///
/// [`Self::NameLength`] and [`Self::BufferLength`] are `usize` here because
/// the C stores them in a `size_t` (`lib/formdata.c:388`, `:490`). A caller
/// that passes a negative `long` reaches that `size_t` through a cast, which
/// yields a value above `LONG_MAX`, which `AddHttpPost`'s guard (`:66-68`)
/// then rejects with `CURL_FORMADD_MEMORY`. **The ABI crate must reproduce
/// the cast** -- `value as usize` on the four 64-bit targets -- rather than
/// clamping to zero or rejecting early, because [`form_add`] reproduces the
/// guard and will return [`FormCode::Memory`] for exactly the inputs the C
/// does.
pub enum FormOption<'a> {
    /// `CURLFORM_COPYNAME`: the field name, copied.
    CopyName(Option<&'a [u8]>),
    /// `CURLFORM_PTRNAME`: the field name, borrowed.
    ///
    /// `:370-372` sets `CURL_HTTPPOST_PTRNAME` and then falls through into
    /// the `CURLFORM_COPYNAME` arm, so the twice and null checks are shared.
    /// The flag suppresses the copy in `FormAddCheck` (`:264`), which is what
    /// makes the caller's memory the caller's responsibility: it must outlive
    /// the form and `curl_formfree` must not free it.
    PtrName(Option<&'a [u8]>),
    /// `CURLFORM_NAMELENGTH`: an explicit name length, for a name that is
    /// not NUL-terminated.
    ///
    /// `:384-389`. A non-zero value already recorded is
    /// [`FormCode::OptionTwice`]. A name whose first `namelength` bytes
    /// contain a NUL is [`FormCode::Null`] (`:260-263`).
    NameLength(usize),
    /// `CURLFORM_COPYCONTENTS`: the field value, copied.
    ///
    /// `:397-407`, with the same deferred copy as [`Self::CopyName`]. The
    /// copy in `FormAddCheck` (`:273`) uses
    /// [`Self::ContentsLength`]/[`Self::ContentLen`] as its length, or the
    /// slice's own length when neither was given.
    CopyContents(Option<&'a [u8]>),
    /// `CURLFORM_PTRCONTENTS`: the field value, borrowed.
    ///
    /// `:394-396` sets `CURL_HTTPPOST_PTRCONTENTS` and falls through. The
    /// flag appears in `curl_formfree`'s second condition (`:681-683`), so
    /// the bytes stay the caller's.
    PtrContents(Option<&'a [u8]>),
    /// `CURLFORM_CONTENTSLENGTH`: the value's length, as a `long`.
    ///
    /// The C's expression is `(curl_off_t)(size_t)form_int_arg(long)`, a
    /// round trip through `size_t` that is the identity on the four 64-bit
    /// targets, so the value is stored as it arrives.
    ContentsLength(CurlOffT),
    /// `CURLFORM_CONTENTLEN`: the value's length, as a `curl_off_t`.
    ///
    /// `:412-415`. Sets `CURL_HTTPPOST_LARGE` and, like
    /// [`Self::ContentsLength`], has no "given twice" check. Both options
    /// write the same field; the flag records which spelling was used.
    ContentLen(CurlOffT),
    /// `CURLFORM_FILECONTENT`: send the named file's **contents** as an
    /// ordinary value.
    FileContent(Option<&'a [u8]>),
    /// `CURLFORM_FILE`: upload the named file.
    ///
    /// `:435-468`. Three outcomes, and the third is how multi-file parts
    /// exist at all:
    ///
    /// * no value yet -- copy the filename and set `CURL_HTTPPOST_FILENAME`;
    /// * a value already present **without** that flag --
    ///   [`FormCode::OptionTwice`];
    /// * a value already present **with** that flag -- spawn a new node on
    ///   the `more` chain and make it current, which is what turns
    ///   `-F 'name=@a.txt,@b.txt'` into a nested `multipart/mixed`.
    File(Option<&'a [u8]>),
    /// `CURLFORM_BUFFERPTR`: upload from a caller-owned buffer.
    BufferPtr(Option<&'a [u8]>),
    /// `CURLFORM_BUFFERLENGTH`: the buffer's length.
    ///
    /// `:486-491`. A non-zero value already recorded is
    /// [`FormCode::OptionTwice`]. Zero means "measure it", which the bridge
    /// spells as `CURL_ZERO_TERMINATED` (`:807-810`).
    BufferLength(usize),
    /// `CURLFORM_BUFFER`: the filename to show for a buffer upload.
    ///
    /// # `None` here is undefined behaviour in the C
    ///
    /// The shared arm reaches `strlen(avalue)` with no null check, so
    /// `CURLFORM_BUFFER, NULL` dereferences a null pointer. Undefined
    /// behaviour has no behaviour to preserve, so `None` is
    /// [`FormCode::Null`] here -- the answer every sibling option gives --
    /// and it is reported **after** the "already set" test, so the ordering
    /// the C does define is unchanged.
    Buffer(Option<&'a [u8]>),
    /// `CURLFORM_CONTENTTYPE`: the part's `Content-Type`.
    ContentType(Option<&'a [u8]>),
    /// `CURLFORM_CONTENTHEADER`: extra headers for this part.
    ContentHeader(Option<SList>),
    /// `CURLFORM_FILENAME`: the filename to show for a file upload.
    ///
    /// `:554-561`. Shares its arm, and its `showfilename` field, with
    /// [`Self::Buffer`]; see that variant for the `None` case.
    FileName(Option<&'a [u8]>),
    /// `CURLFORM_STREAM`: read the part's content through a callback.
    Stream(Option<Box<dyn PartReader>>),
    /// Any option outside the vocabulary: `CURL_FORMADD_UNKNOWN_OPTION`.
    ///
    /// `:563-565`. The ABI crate produces this for an integer that is not one
    /// of the `CURLformoption` tokens this vocabulary covers, and for the five
    /// tokens that name no operation -- `CURLFORM_NOTHING`,
    /// `CURLFORM_OBSOLETE`, `CURLFORM_OBSOLETE2`, `CURLFORM_LASTENTRY` and
    /// anything beyond them. `CURLFORM_END` is **not** one of these: it
    /// terminates the argument list and so simply ends the `Vec`.
    Unknown,
}

/// The option's identity, never its payload.
///
/// # Why this is not `#[derive(Debug)]`
///
/// Nine of these seventeen variants carry caller-supplied bytes: a field name,
/// a field value, a buffer, a filename, a content type, a header list. A
/// multipart form is how a browser and `curl -F` upload credentials and
/// private files -- `docs/cmdline-opts/form.md`'s own examples post a password
/// field -- so a derived formatter would render exactly the bytes a user
/// least expects in a log, and this type is an *argument* to
/// [`form_add`], so it appears in every diagnostic that reports a bad option.
///
/// What renders is the variant name plus, where there is one, a byte count.
/// That is what a caller debugging `CURL_FORMADD_OPTION_TWICE` or
/// `CURL_FORMADD_NULL` needs: which option was given and whether it was empty.
/// The numeric variants render their number, because a length or a
/// `contentslength` is not a secret and is precisely what the twice-and-null
/// checks turn on.
impl fmt::Debug for FormOption<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        /// `Some(n bytes)` or `None`, so an absent option stays distinct from
        /// an empty one -- the distinction the C's `NULL` checks turn on
        /// (`lib/formdata.c:260-263`).
        fn bytes(
            f: &mut fmt::Formatter<'_>,
            name: &str,
            v: Option<&[u8]>,
        ) -> fmt::Result {
            match v {
                Some(bytes) => write!(f, "{name}({:?})", Redacted(bytes)),
                None => write!(f, "{name}(None)"),
            }
        }

        match self {
            Self::CopyName(v) => bytes(f, "CopyName", *v),
            Self::PtrName(v) => bytes(f, "PtrName", *v),
            Self::NameLength(n) => write!(f, "NameLength({n})"),
            Self::CopyContents(v) => bytes(f, "CopyContents", *v),
            Self::PtrContents(v) => bytes(f, "PtrContents", *v),
            Self::ContentsLength(n) => write!(f, "ContentsLength({n})"),
            Self::ContentLen(n) => write!(f, "ContentLen({n})"),
            Self::FileContent(v) => bytes(f, "FileContent", *v),
            Self::File(v) => bytes(f, "File", *v),
            Self::BufferPtr(v) => bytes(f, "BufferPtr", *v),
            Self::BufferLength(n) => write!(f, "BufferLength({n})"),
            Self::Buffer(v) => bytes(f, "Buffer", *v),
            Self::ContentType(v) => bytes(f, "ContentType", *v),
            Self::ContentHeader(v) => {
                write!(
                    f,
                    "ContentHeader({} headers)",
                    v.as_ref().map_or(0, SList::len)
                )
            }
            Self::FileName(v) => bytes(f, "FileName", *v),
            Self::Stream(v) => {
                write!(
                    f,
                    "Stream({})",
                    if v.is_some() { "set" } else { "None" }
                )
            }
            Self::Unknown => f.write_str("Unknown"),
        }
    }
}

// ---------------------------------------------------------------------------
// The flag word, as named booleans

/// The eight `CURL_HTTPPOST_*` flags (`include/curl/curl.h:205-220`), which
/// `lib/formdata.c:39-45` aliases to shorter local names.
///
/// # Why these survive at all
///
/// Three of the eight exist only to record who owns an allocation so that
/// `curl_formfree` releases the right things, and in Rust that job belongs to
/// the type system -- see [`Ownership`]. They are kept anyway, because four
/// of the eight drive **behaviour** rather than deallocation, in
/// `FormAddCheck` and in the bridge:
///
/// * `filename` selects the file branch of the bridge (`:784`), suppresses
///   the value copy (`:270`), and gates both the `more`-node spawning
///   (`:438`, `:514`) and the fake-filename assignment (`:831`);
/// * `readfile` additionally clears the remote filename afterwards
///   (`:804-805`);
/// * `buffer` selects the in-memory branch (`:807`) and switches the
///   content-type probe from the value to the shown filename (`:248-249`);
/// * `callback` selects the reader branch (`:811`).
///
/// # The bit positions are not here
///
/// `include/curl/curl.h:205-220` assigns them and
/// `curl-rs-ffi/src/ffi/opts.rs` owns them. Each field below names its C token
/// so the correspondence is unambiguous without restating a value that would
/// then have to be kept in step.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FormFlags {
    /// `CURL_HTTPPOST_FILENAME`: the content names a file to upload.
    pub filename: bool,
    /// `CURL_HTTPPOST_READFILE`: the content names a file whose bytes become
    /// the value.
    pub readfile: bool,
    /// `CURL_HTTPPOST_PTRNAME`: the name is the caller's memory.
    pub ptrname: bool,
    /// `CURL_HTTPPOST_PTRCONTENTS`: the contents are the caller's memory.
    pub ptrcontents: bool,
    /// `CURL_HTTPPOST_BUFFER`: upload from a buffer.
    pub buffer: bool,
    /// `CURL_HTTPPOST_PTRBUFFER`: that buffer is the caller's memory.
    pub ptrbuffer: bool,
    /// `CURL_HTTPPOST_CALLBACK`: read the content through a callback.
    pub callback: bool,
    /// `CURL_HTTPPOST_LARGE`: the length lives in `contentlen` rather than
    /// `contentslength`.
    pub large: bool,
}

// FormInfo: the accumulator FormAdd fills while it reads options

/// `struct FormInfo` (`lib/formdata.h:33-47`): the temporary accumulator
/// `FormAdd` fills before validation turns it into entries.
///
/// # Two C constructs that do not survive
///
/// **The four `struct bufref` fields.** `lib/formdata.h:34-37` uses a
/// `bufref` precisely so that a name or value can be stored borrowed now and
/// copied later, which is what `FormAddCheck`'s `FormInfoCopyField`
/// (`:121-133`) does. [`Cow`] expresses that natively, and it also expresses
/// the case the C leaves implicit: a `CURLFORM_PTRNAME` name is
/// [`Cow::Borrowed`] forever, and that is the whole of the `PTRNAME` flag's
/// deallocation duty.
///
/// `contenttype` and `showfilename` are owned rather than [`Cow`] because the
/// C copies both eagerly (`:535`, `:559`), so no deferral exists to model, and
/// `curl_formfree` frees both unconditionally (`:684-685`). They are
/// `Vec<u8>` rather than `String` for the same reason `name` and `value` are
/// bytes: both are `char *` in the C, both are emitted on the wire verbatim --
/// `showfilename` inside a `Content-Disposition` and `contenttype` as a
/// `Content-Type` -- and a `-F` argument may name a file whose path the local
/// filesystem accepts and Unicode cannot spell.
#[derive(Default)]
struct FormInfo<'a> {
    /// `struct bufref name`.
    name: Option<Cow<'a, [u8]>>,
    /// `struct bufref value`.
    value: Option<Cow<'a, [u8]>>,
    /// `struct bufref contenttype`.
    contenttype: Option<Vec<u8>>,
    /// `struct bufref showfilename` -- "The filename to show. If not set, the
    /// actual filename will be used".
    showfilename: Option<Vec<u8>>,
    /// `char *buffer` -- "pointer to existing buffer used for file upload".
    buffer: Option<&'a [u8]>,
    /// `char *userp` -- "pointer for the read callback", here the assembled
    /// reader.
    reader: Option<Box<dyn PartReader>>,
    /// `struct curl_slist *contentheader`.
    contentheader: Option<SList>,
    /// `curl_off_t contentslength`.
    contentslength: CurlOffT,
    /// `size_t namelength`.
    namelength: usize,
    /// `size_t bufferlength`.
    bufferlength: usize,
    /// `unsigned char flags`.
    flags: FormFlags,
}

/// Shape and presence, never the accumulated bytes.
///
/// The accumulator holds the same caller-supplied name, value, buffer,
/// filename and content type that [`FormOption`] delivers, so it discloses the
/// same secrets and is redacted the same way. It is `struct`-private and
/// short-lived, but it appears in `{:?}` the moment anybody debugging
/// `FormAddCheck` reaches for one, which is exactly when a form body is in it.
impl fmt::Debug for FormInfo<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FormInfo")
            .field("name", &self.name.as_deref().map(Redacted))
            .field("value", &self.value.as_deref().map(Redacted))
            .field("contenttype", &self.contenttype.as_deref().map(<[u8]>::len))
            .field(
                "showfilename",
                &self.showfilename.as_deref().map(<[u8]>::len),
            )
            .field("buffer", &self.buffer.map(Redacted))
            .field("has_reader", &self.reader.is_some())
            .field(
                "contentheader",
                &self.contentheader.as_ref().map(SList::len),
            )
            .field("contentslength", &self.contentslength)
            .field("namelength", &self.namelength)
            .field("bufferlength", &self.bufferlength)
            .field("flags", &self.flags)
            .finish()
    }
}

impl<'a> FormInfo<'a> {
    /// A node chained onto an existing one: `NewFormInfo` (`:106-118`)
    /// followed by `AddFormInfo` (`:142-153`).
    fn spawned() -> Self {
        Self {
            flags: FormFlags {
                filename: true,
                ..FormFlags::default()
            },
            ..Self::default()
        }
    }
}

// FormEntry and FormList: the validated form, owned as a tree

/// One validated form part: `struct curl_httppost`
/// (`include/curl/curl.h:188-230`), as an owned Rust value.
///
/// # The field correspondence, in the header's order
///
/// The ABI crate needs this mapping to build the `#[repr(C)]` mirror that C
/// callers walk, so it is given in the header's declaration order rather than
/// this struct's:
///
/// | C member | C type | Here |
/// |---|---|---|
/// | `next` | `struct curl_httppost *` | position in [`FormList`] |
/// | `name` | `char *` | [`Self::name`] |
/// | `namelength` | `long` | [`Self::namelength`] |
/// | `contents` | `char *` | [`Self::contents`] |
/// | `contentslength` | `long` | [`Self::contentslength`] |
/// | `buffer` | `char *` | [`Self::buffer`] |
/// | `bufferlength` | `long` | [`Self::bufferlength`] |
/// | `contenttype` | `char *` | [`Self::contenttype`] |
/// | `contentheader` | `struct curl_slist *` | [`Self::contentheader`] |
/// | `more` | `struct curl_httppost *` | [`Self::more`] |
/// | `flags` | `long` | [`Self::flags`] |
/// | `showfilename` | `char *` | [`Self::showfilename`] |
/// | `userp` | `void *` | [`Self::reader`] |
/// | `contentlen` | `curl_off_t` | [`Self::contentlen`] |
pub struct FormEntry<'a> {
    /// `char *name` -- "pointer to allocated name".
    name: Option<Cow<'a, [u8]>>,
    /// `long namelength` -- "length of name length".
    ///
    /// The **effective** length: `AddHttpPost` (`:63-65`) substitutes
    /// `strlen(name)` when the caller gave none, so this is never zero for a
    /// non-empty name.
    namelength: usize,
    /// `char *contents` -- "pointer to allocated data contents".
    contents: Option<Cow<'a, [u8]>>,
    /// `long contentslength` -- never written by `AddHttpPost`; see the type
    /// documentation.
    contentslength: CurlOffT,
    /// `char *buffer` -- "pointer to allocated buffer contents".
    buffer: Option<&'a [u8]>,
    /// `long bufferlength` -- "length of buffer field".
    bufferlength: usize,
    /// `char *contenttype` -- the part's `Content-Type`, as the caller's or
    /// the table's bytes.
    contenttype: Option<Vec<u8>>,
    /// `struct curl_slist *contentheader` -- "list of extra headers for this
    /// form".
    contentheader: Option<SList>,
    /// `struct curl_httppost *more` -- "if one field name has more than one
    /// file, this link should link to following files".
    more: Vec<FormEntry<'a>>,
    /// `long flags` -- "as defined below".
    flags: FormFlags,
    /// `char *showfilename` -- "The filename to show. If not set, the actual
    /// filename will be used", as the caller's bytes.
    showfilename: Option<Vec<u8>>,
    /// `void *userp` -- "custom pointer used for HTTPPOST_CALLBACK posts",
    /// here the assembled reader.
    reader: Option<Box<dyn PartReader>>,
    /// `curl_off_t contentlen` -- "alternative length of contents field. Used
    /// if CURL_HTTPPOST_LARGE is set".
    contentlen: CurlOffT,
}

/// Shape and presence, never a name, a value, a buffer or a filename.
///
/// # Why this is not `#[derive(Debug)]`
///
/// This is the assembled multipart form: the field names, the field values,
/// the upload buffers and the filenames a caller handed to `curl_formadd`, plus
/// the `more` chain of every additional file under one field name. A multipart
/// body is how credentials and private files are uploaded -- and unlike a
/// header, there is no name to classify against, because a form field called
/// `password` and one called `comment` are indistinguishable to this type. So
/// every caller-supplied byte is redacted, unconditionally.
///
/// What renders is enough to debug the assembly: which fields are present, how
/// long each is, how many extra headers a part carries, the flags, and the
/// `more` chain's length. Those are what [`Self::content_length`]'s selection
/// and the `CURL_HTTPPOST_*` flag interactions turn on.
///
/// The `more` chain is rendered recursively, so a nested part is redacted by
/// this same formatter rather than by a parent that might not be.
///
/// Nothing about the stored bytes changes: [`Self::name`], [`Self::contents`]
/// and [`Self::buffer`] still return them verbatim, which is what the
/// `#[repr(C)]` bridge in `curl-rs-ffi` hands to a C caller.
impl fmt::Debug for FormEntry<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FormEntry")
            .field("name", &self.name.as_deref().map(Redacted))
            .field("namelength", &self.namelength)
            .field("contents", &self.contents.as_deref().map(Redacted))
            .field("contentslength", &self.contentslength)
            .field("buffer", &self.buffer.map(Redacted))
            .field("bufferlength", &self.bufferlength)
            .field("contenttype", &self.contenttype.as_deref().map(<[u8]>::len))
            .field(
                "contentheader",
                &self.contentheader.as_ref().map(SList::len),
            )
            .field("more", &self.more)
            .field("flags", &self.flags)
            .field(
                "showfilename",
                &self.showfilename.as_deref().map(<[u8]>::len),
            )
            .field("has_reader", &self.reader.is_some())
            .field("contentlen", &self.contentlen)
            .finish()
    }
}

impl<'a> FormEntry<'a> {
    /// The field name, as the bytes the caller supplied.
    ///
    /// Not narrowed to [`Self::namelength`]: the C keeps the pointer and the
    /// length apart, and a `CURLFORM_PTRNAME` name is not NUL-terminated at
    /// that length. Use [`Self::name_bytes`] for the name the wire sees.
    #[must_use]
    pub fn name(&self) -> Option<&[u8]> {
        self.name.as_deref()
    }

    /// The field name narrowed to [`Self::namelength`]: what `setname`
    /// (`lib/formdata.c:692-705`) copies.
    #[must_use]
    pub fn name_bytes(&self) -> Option<&[u8]> {
        let name = self.name.as_deref()?;
        let extent = if self.namelength == 0 {
            name.len()
        } else {
            self.namelength.min(name.len())
        };
        Some(&name[..extent])
    }

    /// `long namelength`: the effective name length.
    #[must_use]
    pub fn namelength(&self) -> usize {
        self.namelength
    }

    /// `char *contents`: the value, or the filename for a file part.
    #[must_use]
    pub fn contents(&self) -> Option<&[u8]> {
        self.contents.as_deref()
    }

    /// `long contentslength`: always zero, and kept for the ABI's sake.
    ///
    /// See the type documentation for why `AddHttpPost` leaves it alone.
    #[must_use]
    pub fn contentslength(&self) -> CurlOffT {
        self.contentslength
    }

    /// `curl_off_t contentlen`: the length `CURLFORM_CONTENTSLENGTH` or
    /// `CURLFORM_CONTENTLEN` recorded.
    #[must_use]
    pub fn contentlen(&self) -> CurlOffT {
        self.contentlen
    }

    /// The length the bridge uses: `lib/formdata.c:779-782`.
    ///
    /// ```c
    /// curl_off_t clen = post->contentslength;
    /// if(post->flags & CURL_HTTPPOST_LARGE)
    ///   clen = post->contentlen;
    /// ```
    #[must_use]
    pub fn content_length(&self) -> CurlOffT {
        if self.flags.large {
            self.contentlen
        } else {
            self.contentslength
        }
    }

    /// `char *buffer`: the caller's upload buffer.
    #[must_use]
    pub fn buffer(&self) -> Option<&[u8]> {
        self.buffer
    }

    /// `long bufferlength`: zero means "measure it".
    #[must_use]
    pub fn bufferlength(&self) -> usize {
        self.bufferlength
    }

    /// `char *contenttype`: the resolved `Content-Type`.
    ///
    /// Resolved, not merely recorded: for a file or buffer part with no
    /// explicit type, [`form_add`] fills this in from curl's own suffix
    /// table, then from the previous part's type, then from
    /// `application/octet-stream`.
    #[must_use]
    pub fn contenttype(&self) -> Option<&[u8]> {
        self.contenttype.as_deref()
    }

    /// `struct curl_slist *contentheader`: the caller's extra headers.
    #[must_use]
    pub fn contentheader(&self) -> Option<&SList> {
        self.contentheader.as_ref()
    }

    /// `char *showfilename`: the filename to advertise.
    #[must_use]
    pub fn showfilename(&self) -> Option<&[u8]> {
        self.showfilename.as_deref()
    }

    /// `long flags`.
    #[must_use]
    pub fn flags(&self) -> FormFlags {
        self.flags
    }

    /// `void *userp`: the reader a `CURLFORM_STREAM` part carries.
    #[must_use]
    pub fn reader(&self) -> Option<&dyn PartReader> {
        self.reader.as_deref()
    }

    /// `struct curl_httppost *more`: the further files under this name.
    #[must_use]
    pub fn more(&self) -> &[FormEntry<'a>] {
        &self.more
    }

    /// This entry and its `more` chain, in the order the bridge walks them:
    /// `for(file = post; file; file = file->more)` (`lib/formdata.c:759`).
    ///
    /// The head of the chain is the entry itself, which is why a single-file
    /// part and a multi-file part share one code path in the bridge.
    pub fn files(&self) -> impl Iterator<Item = &FormEntry<'a>> {
        std::iter::once(self).chain(self.more.iter())
    }

    /// What `curl_formfree` would release for this entry:
    /// `lib/formdata.c:679-686`.
    ///
    /// Rust's `Drop` performs the release, so this is not a prerequisite for
    /// correctness **here**; it is the information `curl-rs-ffi` needs, where
    /// the borrowed cases are raw C pointers it must leave untouched. A
    /// caller that passed `CURLFORM_PTRNAME` still owns that memory after
    /// `curl_formfree` returns and may reuse or free it, and that is
    /// observable.
    #[must_use]
    pub fn free_plan(&self) -> FreePlan {
        FreePlan {
            // `if(!(form->flags & HTTPPOST_PTRNAME))`
            name: if self.flags.ptrname {
                Ownership::Borrowed
            } else {
                Ownership::Owned
            },
            // `if(!(form->flags & (HTTPPOST_PTRCONTENTS | HTTPPOST_BUFFER |
            //                      HTTPPOST_CALLBACK)))`
            contents: if self.flags.ptrcontents
                || self.flags.buffer
                || self.flags.callback
            {
                Ownership::Borrowed
            } else {
                Ownership::Owned
            },
            // Both unconditional in the C.
            contenttype: Ownership::Owned,
            showfilename: Ownership::Owned,
        }
    }
}

/// A whole form post: the `struct curl_httppost *` chain a caller threads
/// through `curl_formadd`.
///
/// # What this replaces
///
/// `curl_formadd(&post, &last, ...)` takes **two** out-parameters: the head of
/// the chain and its tail, the second purely so that appending is O(1)
/// (`lib/formdata.c:586-594`). A `Vec` pushes in O(1) without a tail pointer,
/// so both collapse into this one value. `tests/libtest/lib1308.c:59-61`
/// asserts that after the first `curl_formadd` the two C pointers are equal;
/// the ABI crate reproduces that by setting `*last_post` to the entry
/// [`Self::last`] reports.
///
/// # One call, one top-level entry
///
/// A single [`form_add`] appends exactly one entry, however many options it
/// was given. `FormAddCheck` passes the previous node as the parent from its
/// second iteration onward (`:276`), and `AddHttpPost` with a parent splices
/// into `parent->more` (`:86-92`), so a chain of N accumulators becomes one
/// top-level node with N-1 entries on its `more` chain. That is what makes
/// `-F 'name=@a.txt,@b.txt'` one form field rather than two.
#[derive(Default)]
pub struct FormList<'a> {
    /// The `next` chain, in order. Each element carries its own `more`
    /// chain.
    entries: Vec<FormEntry<'a>>,
}

/// The entries, each redacted by [`FormEntry`]'s own formatter.
///
/// Hand-written only because the derive was removed from [`FormEntry`]; the
/// list itself holds nothing secret beyond what its elements hold, and each
/// element redacts itself. Rendering the elements rather than only their count
/// is therefore safe, and it is what makes a form's *structure* -- which the
/// one-call-one-entry rule above makes non-obvious -- debuggable.
impl fmt::Debug for FormList<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FormList")
            .field("entries", &self.entries)
            .finish()
    }
}

impl<'a> FormList<'a> {
    /// An empty form: the C's `struct curl_httppost *post = NULL`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// How many top-level parts the form has.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the form has no parts.
    ///
    /// The bridge's "no input => no output!" test (`lib/formdata.c:729-730`)
    /// is `if(!post)`, and an empty list is what a null chain stands for.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The top-level parts, in order.
    #[must_use]
    pub fn entries(&self) -> &[FormEntry<'a>] {
        &self.entries
    }

    /// One top-level part by position.
    #[must_use]
    pub fn entry(&self, index: usize) -> Option<&FormEntry<'a>> {
        self.entries.get(index)
    }

    /// The last top-level part: the C's `*last_post`.
    #[must_use]
    pub fn last(&self) -> Option<&FormEntry<'a>> {
        self.entries.last()
    }
}

// form_add: curl_formadd, without the varargs

/// `curl_formadd` (`lib/formdata.c:609-618`) and the `FormAdd` it wraps
/// (`:301-601`): adds one part to a form.
///
/// # All or nothing
///
/// On failure the caller's list is left **completely** unchanged. The C is
/// explicit about it: the accumulator chain's fields are released
/// (`:572-575`), its nodes are released (`:577-584`), and the partially built
/// `curl_httppost` chain is released by `free_chain` (`:596`) instead of being
/// spliced on (`:586-594`). Here the accumulator and the new entry are locals,
/// so an early return discards them and only a successful build pushes. The
/// behaviour is observable: a caller that gets a non-`Ok` code can retry, and
/// must not find a half-built part in its form.
///
/// # Returns
///
/// [`FormCode::Ok`] on success. Otherwise the first failing outcome, exactly
/// as the C's `while(retval == CURL_FORMADD_OK)` loop stops at the first
/// option that fails and `FormAddCheck` returns at the first part that does.
pub fn form_add<'a>(
    list: &mut FormList<'a>,
    options: Vec<FormOption<'a>>,
) -> FormCode {
    // "We need to allocate the first struct to fill in." (`:319-326`). The
    // C's `curr` is the tail of this chain at every moment; see `FormInfo`.
    let mut chain: Vec<FormInfo<'a>> = vec![FormInfo::default()];
    let mut retval = FormCode::Ok;

    // "Loop through all the options set. Break if we have an error to
    // report." (`:328-331`). `CURLFORM_END` is not a member of the decoded
    // vocabulary, so the list simply ends where the C's `break` at `:352`
    // fires.
    for option in options {
        retval = apply_option(&mut chain, option);
        if !retval.is_ok() {
            break;
        }
    }

    // `if(!retval) retval = FormAddCheck(first_form, &newchain, &lastnode);`
    // (`:569-570`). The new chain is built into a local and committed only on
    // success, which is the whole of the all-or-nothing contract.
    if retval.is_ok() {
        match form_add_check(chain) {
            Ok(entry) => list.entries.push(entry),
            Err(code) => retval = code,
        }
    }

    retval
}

/// One iteration of `FormAdd`'s option switch (`lib/formdata.c:355-566`).
///
/// Split out from [`form_add`] so that each arm sits beside its locator and so
/// that the loop above stays readable; the C's `switch` is one statement.
/// `chain`'s last element is the C's `curr`, and the two arms that push are
/// the two that call `AddFormInfo`.
fn apply_option<'a>(
    chain: &mut Vec<FormInfo<'a>>,
    option: FormOption<'a>,
) -> FormCode {
    match option {
        // `case CURLFORM_PTRNAME:` (`:370-372`) sets the flag and then falls
        // through into `case CURLFORM_COPYNAME:`, so the twice and null
        // checks below are shared. The flag is set BEFORE those checks, which
        // is why it is written first here too -- though no caller can observe
        // it, because a failing `form_add` commits nothing.
        FormOption::PtrName(value) => {
            let curr = chain.last_mut().expect(CHAIN_NEVER_EMPTY);
            curr.flags.ptrname = true;
            store_name(curr, value)
        }
        // `case CURLFORM_COPYNAME:` (`:373-383`).
        FormOption::CopyName(value) => {
            store_name(chain.last_mut().expect(CHAIN_NEVER_EMPTY), value)
        }

        // `case CURLFORM_NAMELENGTH:` (`:384-389`).
        FormOption::NameLength(length) => {
            let curr = chain.last_mut().expect(CHAIN_NEVER_EMPTY);
            if curr.namelength != 0 {
                FormCode::OptionTwice
            } else {
                curr.namelength = length;
                FormCode::Ok
            }
        }

        // `case CURLFORM_PTRCONTENTS:` (`:394-396`), falling through into
        // `case CURLFORM_COPYCONTENTS:`.
        FormOption::PtrContents(value) => {
            let curr = chain.last_mut().expect(CHAIN_NEVER_EMPTY);
            curr.flags.ptrcontents = true;
            store_value(curr, value)
        }
        // `case CURLFORM_COPYCONTENTS:` (`:397-407`).
        FormOption::CopyContents(value) => {
            store_value(chain.last_mut().expect(CHAIN_NEVER_EMPTY), value)
        }

        // `case CURLFORM_CONTENTSLENGTH:` (`:408-410`). NO "given twice"
        // check, deliberately: the C allows repetition and the last value
        // wins.
        FormOption::ContentsLength(length) => {
            chain.last_mut().expect(CHAIN_NEVER_EMPTY).contentslength = length;
            FormCode::Ok
        }

        // `case CURLFORM_CONTENTLEN:` (`:412-415`). Same field, plus the
        // flag; also no "given twice" check.
        FormOption::ContentLen(length) => {
            let curr = chain.last_mut().expect(CHAIN_NEVER_EMPTY);
            curr.flags.large = true;
            curr.contentslength = length;
            FormCode::Ok
        }

        // `case CURLFORM_FILECONTENT:` (`:418-432`) -- "Get contents from a
        // given filename". Copies immediately, unlike the two options above.
        FormOption::FileContent(path) => {
            let curr = chain.last_mut().expect(CHAIN_NEVER_EMPTY);
            if curr.flags.ptrcontents || curr.flags.readfile {
                FormCode::OptionTwice
            } else if let Some(path) = path {
                curr.value = Some(Cow::Owned(path.to_vec()));
                curr.flags.readfile = true;
                FormCode::Ok
            } else {
                FormCode::Null
            }
        }

        // `case CURLFORM_FILE:` (`:435-468`) -- "We upload a file". The one
        // arm with three distinct outcomes; the third is how a multi-file
        // field exists.
        FormOption::File(path) => {
            let (has_value, is_filename) = {
                let curr = chain.last().expect(CHAIN_NEVER_EMPTY);
                (curr.value.is_some(), curr.flags.filename)
            };
            if !has_value {
                // The ordinary first file (`:458-467`).
                let curr = chain.last_mut().expect(CHAIN_NEVER_EMPTY);
                match path {
                    Some(path) => {
                        curr.value = Some(Cow::Owned(path.to_vec()));
                        curr.flags.filename = true;
                        FormCode::Ok
                    }
                    None => FormCode::Null,
                }
            } else if !is_filename {
                // A value from some other option is already here (`:455-456`).
                FormCode::OptionTwice
            } else if let Some(path) = path {
                // `form = NewFormInfo(); ... AddFormInfo(form, curr); curr =
                // form;` (`:440-450`). The push IS the splice, and it also
                // advances `curr`, because the tail is what `chain.last_mut`
                // returns from here on.
                let mut spawned = FormInfo::spawned();
                spawned.value = Some(Cow::Owned(path.to_vec()));
                chain.push(spawned);
                FormCode::Ok
            } else {
                FormCode::Null
            }
        }

        // `case CURLFORM_BUFFERPTR:` (`:470-484`).
        FormOption::BufferPtr(buffer) => {
            let curr = chain.last_mut().expect(CHAIN_NEVER_EMPTY);
            // Both flags, set before the check, at `:471`.
            curr.flags.ptrbuffer = true;
            curr.flags.buffer = true;
            if curr.buffer.is_some() {
                FormCode::OptionTwice
            } else if let Some(buffer) = buffer {
                curr.buffer = Some(buffer);
                // "Make value non-NULL to be accepted as fine" (`:478-479`).
                // Assigned with no "given twice" check of its own, so this
                // deliberately replaces a value an earlier option set.
                curr.value = Some(Cow::Borrowed(buffer));
                FormCode::Ok
            } else {
                FormCode::Null
            }
        }

        // `case CURLFORM_BUFFERLENGTH:` (`:486-491`).
        FormOption::BufferLength(length) => {
            let curr = chain.last_mut().expect(CHAIN_NEVER_EMPTY);
            if curr.bufferlength != 0 {
                FormCode::OptionTwice
            } else {
                curr.bufferlength = length;
                FormCode::Ok
            }
        }

        // `case CURLFORM_STREAM:` (`:493-509`).
        FormOption::Stream(reader) => {
            let curr = chain.last_mut().expect(CHAIN_NEVER_EMPTY);
            // The flag, set before the check, at `:494`.
            curr.flags.callback = true;
            if curr.reader.is_some() {
                FormCode::OptionTwice
            } else if let Some(reader) = reader {
                curr.reader = Some(reader);
                // The C's `Curl_bufref_set(&curr->value, avalue, 0, NULL)` at
                // `:504`; see `STREAM_VALUE_PLACEHOLDER` for why the bytes do
                // not matter and why something must nonetheless be here.
                curr.value = Some(Cow::Borrowed(STREAM_VALUE_PLACEHOLDER));
                FormCode::Ok
            } else {
                FormCode::Null
            }
        }

        // `case CURLFORM_CONTENTTYPE:` (`:511-540`). Spawns a `more` node on
        // the same condition `CURLFORM_FILE` does, which is how each file of
        // a multi-file field gets its own type.
        FormOption::ContentType(mimetype) => {
            let (has_type, is_filename) = {
                let curr = chain.last().expect(CHAIN_NEVER_EMPTY);
                (curr.contenttype.is_some(), curr.flags.filename)
            };
            if !has_type {
                // `else if(avalue) { memdup0 }` / `else NULL` (`:534-539`).
                match mimetype {
                    Some(mimetype) => {
                        chain
                            .last_mut()
                            .expect(CHAIN_NEVER_EMPTY)
                            .contenttype = Some(mimetype.to_owned());
                        FormCode::Ok
                    }
                    None => FormCode::Null,
                }
            } else if !is_filename {
                // `else retval = CURL_FORMADD_OPTION_TWICE;` (`:531-532`).
                FormCode::OptionTwice
            } else if let Some(mimetype) = mimetype {
                // `:516-526`, the same spawn as `CURLFORM_FILE`.
                let mut spawned = FormInfo::spawned();
                spawned.contenttype = Some(mimetype.to_owned());
                chain.push(spawned);
                FormCode::Ok
            } else {
                FormCode::Null
            }
        }

        // `case CURLFORM_CONTENTHEADER:` (`:542-553`). A null list is stored
        // as "not set" and is not an error, which is why the check is on the
        // stored list rather than on the argument.
        FormOption::ContentHeader(headers) => {
            let curr = chain.last_mut().expect(CHAIN_NEVER_EMPTY);
            if curr.contentheader.is_some() {
                FormCode::OptionTwice
            } else {
                curr.contentheader = headers;
                FormCode::Ok
            }
        }

        // `case CURLFORM_FILENAME:` and `case CURLFORM_BUFFER:` (`:554-561`)
        // -- one arm, one field. See `FormOption::Buffer` for why `None` is
        // `Null` here even though the C reaches `strlen(NULL)`.
        FormOption::FileName(shown) | FormOption::Buffer(shown) => {
            let curr = chain.last_mut().expect(CHAIN_NEVER_EMPTY);
            if curr.showfilename.is_some() {
                FormCode::OptionTwice
            } else {
                match shown {
                    Some(shown) => {
                        curr.showfilename = Some(shown.to_owned());
                        FormCode::Ok
                    }
                    None => FormCode::Null,
                }
            }
        }

        // `default: retval = CURL_FORMADD_UNKNOWN_OPTION;` (`:563-565`).
        FormOption::Unknown => FormCode::UnknownOption,
    }
}

/// The shared body of `CURLFORM_PTRNAME` and `CURLFORM_COPYNAME`
/// (`lib/formdata.c:373-383`).
fn store_name<'a>(
    curr: &mut FormInfo<'a>,
    value: Option<&'a [u8]>,
) -> FormCode {
    if curr.name.is_some() {
        return FormCode::OptionTwice;
    }
    match value {
        Some(value) => {
            curr.name = Some(Cow::Borrowed(value));
            FormCode::Ok
        }
        None => FormCode::Null,
    }
}

/// The shared body of `CURLFORM_PTRCONTENTS` and `CURLFORM_COPYCONTENTS`
/// (`lib/formdata.c:397-407`), with the same deferred copy as
/// [`store_name`].
fn store_value<'a>(
    curr: &mut FormInfo<'a>,
    value: Option<&'a [u8]>,
) -> FormCode {
    if curr.value.is_some() {
        return FormCode::OptionTwice;
    }
    match value {
        Some(value) => {
            curr.value = Some(Cow::Borrowed(value));
            FormCode::Ok
        }
        None => FormCode::Null,
    }
}

// form_add_check: validation, content-type inference, and the prevtype carry

/// `FormAddCheck` (`lib/formdata.c:216-286`): validates the accumulator chain
/// and turns it into one entry.
fn form_add_check<'a>(
    chain: Vec<FormInfo<'a>>,
) -> Result<FormEntry<'a>, FormCode> {
    /// One field, copied, reporting a refused allocation as the C's own
    /// `CURL_FORMADD_MEMORY`.
    ///
    /// `FormAddCheck` answers that code for every failed duplication in its
    /// body -- `:255-258`, `:264-269`, `:270-275`, `:281-282` -- so the mapping
    /// is stated once here rather than at each of the four sites.
    fn dup(field: &[u8]) -> Result<Vec<u8>, FormCode> {
        fallible::vec_from_slice(field).map_err(|_| FormCode::Memory)
    }

    let mut prevtype: Option<Vec<u8>> = None;
    // The chain length is the caller's option count, so the reservation is
    // externally sized. `FormAddCheck` has no matching allocation -- it walks a
    // linked list the C already built -- so `CURL_FORMADD_MEMORY` is the code
    // its own allocation failures use throughout, and the one used here.
    let mut nodes: Vec<FormEntry<'a>> =
        fallible::vec_with_capacity(chain.len())
            .map_err(|_| FormCode::Memory)?;

    for (index, mut form) in chain.into_iter().enumerate() {
        // The C's `!post` is true only on the first iteration: from the
        // second onward `post` holds the node `AddHttpPost` just returned,
        // and a null return has already sent us home with `Memory`.
        let first = index == 0;

        // The five completeness conditions, in the C's order (`:230-244`).
        // Written as one disjunction, as the C writes it, so that no
        // reordering can creep in.
        let incomplete = ((form.name.is_none() || form.value.is_none())
            && first)
            || (form.contentslength != 0 && form.flags.filename)
            || (form.flags.filename && form.flags.ptrcontents)
            || (form.buffer.is_none()
                && form.flags.buffer
                && form.flags.ptrbuffer)
            || (form.flags.readfile && form.flags.ptrcontents);
        if incomplete {
            return Err(FormCode::Incomplete);
        }

        // Content-type inference with the `prevtype` carry-forward
        // (`:245-259`).
        if (form.flags.filename || form.flags.buffer)
            && form.contenttype.is_none()
        {
            // `const char *f = Curl_bufref_ptr((form->flags &
            // HTTPPOST_BUFFER) ? &form->showfilename : &form->value);`
            // (`:248-249`). A buffer has no path of its own, so the shown
            // filename is the only thing with a suffix to look at.
            // The C hands `Curl_mime_contenttype` a `char *` and lets it
            // match one of ten ASCII suffixes. Both candidates reach it as
            // the bytes they are, so a path the local filesystem accepts and
            // Unicode cannot spell is matched exactly as the C matches it --
            // where decoding first made every such path answer "no suffix".
            let probe: Option<&[u8]> = if form.flags.buffer {
                form.showfilename.as_deref()
            } else {
                form.value.as_deref()
            };
            // `Curl_bufref_set(&form->contenttype, type, strlen(type),
            // NULL)` at `:255-258`, whose surrounding `FormAddCheck` reports
            // `CURL_FORMADD_MEMORY` for a failed allocation. The three
            // candidates are a table constant, the previous part's type, or the
            // octet-stream default; the first is bounded and the second is a
            // caller- or table-sized extent, so the copy is routed through
            // `crate::util::fallible` like the rest.
            let source: &[u8] = match contenttype(probe) {
                Some(kind) => kind.as_bytes(),
                // `if(!type) type = prevtype;` (`:251-252`), then
                // `if(!type) type = FILE_CONTENTTYPE_DEFAULT;` (`:253-254`).
                None => match prevtype.as_deref() {
                    Some(previous) => previous,
                    None => FILE_CONTENTTYPE_DEFAULT.as_bytes(),
                },
            };
            form.contenttype = Some(dup(source)?);
        }

        // `if(name && form->namelength) { if(memchr(name, 0,
        // form->namelength)) return CURL_FORMADD_NULL; }` (`:260-263`).
        if let Some(name) = form.name.as_deref() {
            if form.namelength != 0 {
                let extent = form.namelength.min(name.len());
                if name[..extent].contains(&0) {
                    return Err(FormCode::Null);
                }
            }
        }

        // `if(!(form->flags & HTTPPOST_PTRNAME)) FormInfoCopyField(
        //     &form->name, form->namelength);` (`:264-269`).
        if !form.flags.ptrname {
            if let Some(name) = form.name.take() {
                let extent = effective_usize_len(form.namelength, name.len());
                // `FormInfoCopyField` is `Curl_bufref_memdup0`, and its caller
                // answers `CURL_FORMADD_MEMORY` for a null return
                // (`:264-269`). The extent is the caller's name.
                form.name = Some(Cow::Owned(dup(&name[..extent])?));
            }
        }

        // `if(!(form->flags & (HTTPPOST_FILENAME | HTTPPOST_READFILE |
        //   HTTPPOST_PTRCONTENTS | HTTPPOST_PTRBUFFER | HTTPPOST_CALLBACK)))
        //   FormInfoCopyField(&form->value, (size_t)form->contentslength);`
        // (`:270-275`).
        if !(form.flags.filename
            || form.flags.readfile
            || form.flags.ptrcontents
            || form.flags.ptrbuffer
            || form.flags.callback)
        {
            if let Some(value) = form.value.take() {
                if form.contentslength < 0 {
                    // The C's `(size_t)` cast turns a negative length into a
                    // value near `SIZE_MAX`, `Curl_bufref_memdup0` cannot
                    // allocate it, and `FormAddCheck` reports
                    // `CURL_FORMADD_MEMORY` (`:273-274`). Reproduced as the code
                    // rather than as an allocation attempt: refusing a length
                    // this absurd before asking the allocator is what
                    // `crate::util::fallible` would achieve here, one step
                    // earlier and with the C's own code.
                    return Err(FormCode::Memory);
                }
                let requested =
                    usize::try_from(form.contentslength).unwrap_or(usize::MAX);
                let extent = effective_usize_len(requested, value.len());
                // As the name above: `FormInfoCopyField` at `:270-275`, over a
                // length the caller declared.
                form.value = Some(Cow::Owned(dup(&value[..extent])?));
            }
        }

        // `post = AddHttpPost(form, post, httppost, last_post); if(!post)
        // return CURL_FORMADD_MEMORY;` (`:276-279`).
        let entry = add_http_post(form)?;

        // `if(Curl_bufref_ptr(&form->contenttype)) prevtype =
        // Curl_bufref_ptr(&form->contenttype);` (`:281-282`). Read from the
        // entry rather than from the accumulator because the accumulator has
        // been moved; the value is the same one.
        if let Some(mimetype) = entry.contenttype.as_deref() {
            prevtype = Some(dup(mimetype)?);
        }

        fallible::push(&mut nodes, entry).map_err(|_| FormCode::Memory)?;
    }

    // `AddHttpPost` makes the first node the top-level one and every
    // subsequent node a child of the previous, so a chain of N accumulators
    // becomes one entry with N-1 items on its `more` chain. See
    // `FormList`'s "one call, one top-level entry".
    let mut nodes = nodes.into_iter();
    let mut top = nodes.next().expect(CHAIN_NEVER_EMPTY);
    top.more = nodes.collect();
    Ok(top)
}

/// `AddHttpPost` (`lib/formdata.c:57-103`): converts one validated
/// accumulator into one entry.
///
/// # The `LONG_MAX` guard, and why it is kept
///
/// `if((src->bufferlength > LONG_MAX) || (namelength > LONG_MAX)) return
/// NULL;` at `:66-68`, with the C's own comment "avoid overflow in typecasts
/// below": both fields are `size_t` in the accumulator and `long` in `struct
/// curl_httppost`, so a value above `LONG_MAX` would become negative. The
/// guard is therefore reachable and is reproduced rather than dismissed as a
/// 32-bit concern. It is written with `try_from` instead of a comparison
/// against a cast bound so that no cast appears at all.
///
/// # Errors
///
/// [`FormCode::Memory`], which is the code `FormAddCheck` reports for the
/// C's `NULL` return (`:278-279`).
fn add_http_post<'a>(form: FormInfo<'a>) -> Result<FormEntry<'a>, FormCode> {
    // `size_t namelength = src->namelength; if(!namelength &&
    // Curl_bufref_ptr(&src->name)) namelength = strlen(...);` (`:63-65`).
    let namelength = if form.namelength == 0 {
        form.name.as_deref().map_or(0, <[u8]>::len)
    } else {
        form.namelength
    };

    if CurlOffT::try_from(form.bufferlength).is_err()
        || CurlOffT::try_from(namelength).is_err()
    {
        return Err(FormCode::Memory);
    }

    Ok(FormEntry {
        // `post->name = ...; post->namelength = (long)namelength;`
        name: form.name,
        namelength,
        // `post->contents = ...;`
        contents: form.value,
        // `post->contentslength` is NEVER assigned: the struct arrives zeroed
        // from `curlx_calloc` at `:69` and the accumulator's length goes to
        // `contentlen` below instead. See `FormEntry`'s note.
        contentslength: 0,
        // `post->buffer = src->buffer; post->bufferlength = (long)...;`
        buffer: form.buffer,
        bufferlength: form.bufferlength,
        // `post->contenttype = ...;`
        contenttype: form.contenttype,
        // `post->contentheader = src->contentheader;`
        contentheader: form.contentheader,
        // Filled in by the caller, which knows the chain.
        more: Vec::new(),
        // `post->flags = src->flags | CURL_HTTPPOST_LARGE;` (`:78`) -- the OR
        // is unconditional, which is what makes `content_length` always read
        // `contentlen`.
        flags: FormFlags {
            large: true,
            ..form.flags
        },
        // `post->showfilename = ...; post->userp = src->userp;`
        showfilename: form.showfilename,
        reader: form.reader,
        // `post->contentlen = src->contentslength;` (`:74`).
        contentlen: form.contentslength,
    })
}

/// Resolves a length that may mean "measure it" against a slice that already
/// knows how long it is.
fn effective_usize_len(requested: usize, available: usize) -> usize {
    if requested == 0 {
        available
    } else {
        requested.min(available)
    }
}

// get_form_data: the httppost -> mimepart bridge

/// `Curl_getformdata` (`lib/formdata.c:717-841`): converts a form into a mime
/// tree.
///
/// # Shape
///
/// A form field with no `more` chain becomes one part of the outer
/// `multipart/form-data`. A field **with** a `more` chain becomes an
/// intermediate part that carries the field name and a nested multipart, and
/// each file becomes a child of that. `tests/data/test1133` shows the result:
/// the outer part carries `Content-Disposition: form-data; name="file3"` and
/// `Content-Type: multipart/mixed`, and each child carries
/// `Content-Disposition: attachment; filename="..."` -- `form-data` only
/// propagates under a `multipart/form-data` parent (`lib/mime.c:1798-1801`).
///
/// # Randomness is injected, never reached for
///
/// # Errors
///
/// Whatever the mime builder reports. `Curl_mime_cleanpart(finalform)` runs on
/// any failure (`:837-838`), so a caller never inherits a half-built tree; the
/// same is true here, and it is why the tree is built by a helper whose
/// failure this function can clean up after.
pub(crate) fn get_form_data(
    finalform: &mut MimePart,
    form: &FormList<'_>,
    streams: StreamPolicy,
    rng: &mut dyn Rng,
) -> CodeResult<()> {
    // `Curl_mime_cleanpart(finalform); /* default form is empty */` (`:727`).
    finalform.clean();

    // "no input => no output!" (`:729-730`). Note that this returns
    // `CURLE_OK` with the part left EMPTY rather than as a multipart, which
    // is what gives `curl_formget(NULL, ...)` its headers-only output.
    if form.is_empty() {
        return Ok(());
    }

    let result = build_form_tree(finalform, form, streams, rng);
    if result.is_err() {
        // `if(result) Curl_mime_cleanpart(finalform);` (`:837-838`).
        finalform.clean();
    }
    result
}

/// The body of [`get_form_data`] once the empty case is out of the way.
///
/// Separated so that the caller can clean the destination on failure without
/// holding a borrow of it, which is the Rust expression of the C's single
/// `if(result)` at the end of a function that has been writing through the
/// same pointer throughout.
fn build_form_tree(
    finalform: &mut MimePart,
    form: &FormList<'_>,
    streams: StreamPolicy,
    rng: &mut dyn Rng,
) -> CodeResult<()> {
    // `form = curl_mime_init(data); ... curl_mime_subparts(finalform, form);`
    // (`:732-737`). Attached immediately, as the C attaches it, so that
    // everything below is reached through the destination rather than
    // assembled beside it.
    let top = Mime::new(rng)?;
    finalform.set_subparts(top).map_err(|(_, code)| code)?;

    // "Process each top part." (`:739-740`).
    for post in form.entries() {
        if post.more.is_empty() {
            // No `more` chain, so `multipart` stays the outer handle and the
            // single file IS the post (`file = post` at `:759`).
            let part = finalform
                .subparts_mut()
                .expect(TOP_MULTIPART_ATTACHED)
                .add_part();
            fill_part(part, post, post, NameSite::OnThisPart, streams)?;
        } else {
            // "If we have more than a file here, create a mime subpart and
            // fill it." (`:741-756`).
            let position = {
                let multipart =
                    finalform.subparts_mut().expect(TOP_MULTIPART_ATTACHED);
                let position = multipart.len();
                let intermediate = multipart.add_part();
                // `setname(part, post->name, post->namelength)` (`:748`) --
                // the field name goes HERE, not on the children.
                set_part_name(intermediate, post)?;
                position
            };

            // `multipart = curl_mime_init(data);` (`:750`), after the name and
            // before the attachment, so that the generator is used in the
            // C's order.
            let nested = Mime::new(rng)?;
            let intermediate = finalform
                .subparts_mut()
                .expect(TOP_MULTIPART_ATTACHED)
                .part_mut(position)
                .expect(INTERMEDIATE_JUST_ADDED);
            // `curl_mime_subparts(part, multipart);` (`:755`).
            intermediate
                .set_subparts(nested)
                .map_err(|(_, code)| code)?;

            // "Generate all the part contents." (`:758-759`): the top entry
            // first, then its `more` chain.
            for file in post.files() {
                let part = intermediate
                    .subparts_mut()
                    .expect(NESTED_MULTIPART_ATTACHED)
                    .add_part();
                fill_part(part, post, file, NameSite::OnTheParent, streams)?;
            }
        }
    }

    Ok(())
}

/// Where the field name was placed, which decides whether this part gets one.
///
/// `if(!result && !post->more) setname(part, post->name, post->namelength);`
/// (`lib/formdata.c:774-775`). When a `more` chain exists the name went on the
/// intermediate part instead, and repeating it on every child would emit a
/// `name=` parameter inside a `multipart/mixed` that curl 8.x does not emit --
/// visible in `tests/data/test1133`, whose inner children carry only
/// `Content-Disposition: attachment; filename="..."`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NameSite {
    /// No `more` chain: the name belongs on this part.
    OnThisPart,
    /// A `more` chain exists: the name is already on the intermediate part.
    OnTheParent,
}

/// The `expect` messages for the three attachments this bridge just made.
///
/// Each is unreachable by construction -- `set_subparts` has returned `Ok`, so
/// the part holds a multipart -- and each is spelled out rather than left as a
/// bare `unwrap` so that an impossible failure names the invariant it broke.
const TOP_MULTIPART_ATTACHED: &str =
    "the outer multipart was attached to the destination part above";
const INTERMEDIATE_JUST_ADDED: &str =
    "the intermediate part was appended at this position above";
const NESTED_MULTIPART_ATTACHED: &str =
    "the nested multipart was attached to the intermediate part above";

/// One iteration of the bridge's inner loop (`lib/formdata.c:759-834`).
///
/// # Errors
///
/// Whatever the mime builder reports, plus
/// [`CURLcode::BadFunctionArgument`] for a name or path that is not UTF-8 --
/// see [`set_part_name`].
fn fill_part(
    part: &mut MimePart,
    post: &FormEntry<'_>,
    file: &FormEntry<'_>,
    name_site: NameSite,
    streams: StreamPolicy,
) -> CodeResult<()> {
    // 1. "Set the headers." `curl_mime_headers(part, file->contentheader, 0)`
    //    (`:766-767`). The third argument is ZERO: the caller keeps its list,
    //    which is why the entry's list is cloned rather than moved and why
    //    `curl_formfree` never frees a `contentheader`.
    part.set_headers(file.contentheader.clone(), false);

    // 2. "Set the content type." (`:769-771`). Only when present -- a `None`
    //    here must NOT clear a type, because the C's `if(file->contenttype)`
    //    guards the call rather than passing a null through it.
    if let Some(mimetype) = file.contenttype.as_deref() {
        part.set_type(Some(mimetype))?;
    }

    // 3. "Set field name." (`:773-775`).
    if name_site == NameSite::OnThisPart {
        set_part_name(part, post)?;
    }

    // 4. "Process contents." (`:777-827`). Every field read below comes from
    //    `post`, not from `file`, except the path itself.
    let clen = post.content_length();
    if post.flags.filename || post.flags.readfile {
        set_file_content(part, file)?;
        if post.flags.readfile {
            // `curl_mime_filename(part, NULL)` (`:804-805`).
            // `CURLFORM_FILECONTENT` sends the file's CONTENTS as an ordinary
            // value, so the remote filename `curl_mime_filedata` set as a
            // side effect must be removed again -- otherwise the part would
            // carry a `filename=` parameter curl 8.x does not emit.
            part.set_filename(None)?;
        }
    } else if post.flags.buffer {
        // `curl_mime_data(part, post->buffer, post->bufferlength ?
        // post->bufferlength : -1)` (`:807-810`). The `-1` is
        // `CURL_ZERO_TERMINATED` reinterpreted as a `size_t`, which means
        // "measure it"; a Rust slice already knows its length.
        let data = post.buffer.map(|buffer| {
            let extent = effective_usize_len(post.bufferlength, buffer.len());
            &buffer[..extent]
        });
        part.set_data(data);
    } else if post.flags.callback {
        // `if(!clen) clen = -1; curl_mime_data_cb(part, clen, fread_func,
        // NULL, NULL, post->userp);` (`:811-818`) -- "the contents should be
        // read with the callback and the size is set with the
        // contentslength".
        let size = if clen == 0 { None } else { Some(clen) };
        let reader = match streams {
            StreamPolicy::Available => {
                post.reader.as_deref().map(|reader| reader.duplicate())
            }
            // A null `fread_func` reaches `curl_mime_data_cb` with a null
            // `readfunc`, which clears the content and installs nothing
            // (`lib/mime.c:1425-1434`). See `StreamPolicy`.
            StreamPolicy::Unavailable => None,
        };
        part.set_reader(size, reader);
    } else {
        // `size_t uclen; if(!clen) uclen = CURL_ZERO_TERMINATED; else uclen =
        // (size_t)clen; curl_mime_data(part, post->contents, uclen);`
        // (`:819-826`).
        if clen < 0 {
            // The C's `(size_t)clen` of a negative length is a value near
            // `SIZE_MAX`, and `curl_mime_data`'s `curlx_memdup0` cannot
            // allocate it, so the C reports `CURLE_OUT_OF_MEMORY`. Reachable
            // through `CURLFORM_CONTENTLEN` with a negative argument on a
            // part whose value is not copied -- `CURLFORM_PTRCONTENTS`, for
            // instance -- because only the copied path is guarded earlier.
            return Err(CURLcode::OutOfMemory);
        }
        let requested = usize::try_from(clen).unwrap_or(usize::MAX);
        let data = post.contents.as_deref().map(|contents| {
            let extent = effective_usize_len(requested, contents.len());
            &contents[..extent]
        });
        part.set_data(data);
    }

    // 5. "Set fake filename." (`:829-833`). Three flags plus the chain, and
    //    the gate matters: a plain `CURLFORM_COPYCONTENTS` part with a
    //    `CURLFORM_FILENAME` gets NO `filename=` parameter, because none of
    //    the four conditions holds.
    if let Some(showfilename) = post.showfilename.as_deref() {
        if !post.more.is_empty()
            || post.flags.filename
            || post.flags.buffer
            || post.flags.callback
        {
            part.set_filename(Some(showfilename))?;
        }
    }

    Ok(())
}

/// `setname` (`lib/formdata.c:692-705`): sets a part's name from a byte range
/// that is not necessarily NUL-terminated.
///
/// ```c
/// if(!name || !len) return curl_mime_name(part, name);
/// zname = curlx_memdup0(name, len);
/// res = curl_mime_name(part, zname);
/// curlx_free(zname);
/// ```
///
/// # Errors
///
/// [`CURLcode::OutOfMemory`], which covers both of the C's failure arms here:
/// its own `curlx_memdup0` of the name range (`:698-700`) and the
/// `curl_mime_name` it then calls, whose `curlx_strdup` has the same answer.
/// Only one copy is made on this side, so only one arm exists.
///
/// A name that is not valid UTF-8 was previously
/// [`CURLcode::BadFunctionArgument`] here, because the parent module's
/// `set_name` took a `&str`. It no longer is: `curl_formadd` stores a
/// `char *`, the name is emitted inside a `Content-Disposition` byte for byte,
/// and the tool's `-F` argument comes from an argument vector that is bytes on
/// every mandated target. Refusing such a name rejected a form the C posts.
fn set_part_name(part: &mut MimePart, post: &FormEntry<'_>) -> CodeResult<()> {
    // `curl_mime_name(part, NULL)` clears the name (`lib/mime.c:1244`); the
    // C's `if(!name || !len) return curl_mime_name(part, name);` is the same
    // path for an absent name.
    part.set_name(post.name_bytes())
}

/// The file branch of the bridge (`lib/formdata.c:784-806`), including the
/// `"-"` pseudo-filename.
///
/// # Errors
///
/// Whatever `MimePart::set_file` reports -- [`CURLcode::ReadError`] for a path
/// that cannot be stat'd, which is how the C's `curl_mime_filedata` reports
/// the same condition. A path that is not valid UTF-8 is no longer among them:
/// it is a path like any other, and refusing it rejected an upload the C
/// performs.
fn set_file_content(
    part: &mut MimePart,
    file: &FormEntry<'_>,
) -> CodeResult<()> {
    let path = file.contents.as_deref();

    // `if(!strcmp(file->contents, "-"))` (`:785`).
    if path == Some(STDIN_PSEUDO_FILENAME) {
        // `curl_mime_data_cb(part, (curl_off_t)-1, (curl_read_callback)fread,
        // curlx_fseek, NULL, (void *)stdin)` (`:794-797`), with the C's own
        // warning at `:786-789`: "There are a few cases where the code below
        // will not work; in particular, freopen(stdin) by the caller is not
        // guaranteed to result as expected. This feature has been kept for
        // backward compatibility: use of "-" pseudo filename should be
        // avoided."
        part.set_reader(None, Some(Box::new(StdinReader)));
        return Ok(());
    }

    match path {
        // `curl_mime_filedata(part, file->contents)` (`:803`). The bytes are
        // viewed as a path without decoding: `OsStr::from_bytes` is the
        // lossless view of a platform string on the mandated targets, and
        // `std::str::from_utf8` stood here refusing -- with
        // `CURLE_BAD_FUNCTION_ARGUMENT` -- every path the local filesystem
        // accepts and Unicode cannot spell. The C passes the `char *` straight
        // to `curl_mime_filedata`, which stats it and stores it.
        Some(bytes) => {
            use std::os::unix::ffi::OsStrExt;
            part.set_file(Some(Path::new(std::ffi::OsStr::from_bytes(bytes))))
        }
        // The C reaches `strcmp(NULL, "-")` here and dereferences a null
        // pointer. It is reachable: a second `CURLFORM_CONTENTTYPE` spawns a
        // `more` node that carries a type and no value (`:516-526`), and
        // `FormAddCheck`'s completeness test only requires a value on the
        // FIRST node of a chain (`:230`). Undefined behaviour has no
        // behaviour to preserve, so the defined answer is the one
        // `curl_mime_filedata` itself gives a null filename: clear the
        // content and succeed (`lib/mime.c:1305-1308`).
        None => part.set_file(None),
    }
}

/// The reader the `"-"` pseudo-filename installs: bare `fread` on `stdin`.
#[derive(Debug)]
struct StdinReader;

impl PartReader for StdinReader {
    /// `fread(buffer, 1, nitems, stdin)`.
    fn read(&mut self, buf: &mut [u8]) -> ReadStatus {
        if buf.is_empty() {
            return ReadStatus::Eof;
        }
        let mut stdin = std::io::stdin().lock();
        loop {
            match stdin.read(buf) {
                Ok(0) => return ReadStatus::Eof,
                Ok(count) => return ReadStatus::Bytes(count),
                Err(error)
                    if error.kind() == std::io::ErrorKind::Interrupted =>
                {
                    continue
                }
                Err(_) => return ReadStatus::Eof,
            }
        }
    }

    /// `curlx_fseek(stdin, offset, whence)`.
    fn seek(&mut self, _offset: CurlOffT, _whence: SeekWhence) -> SeekResult {
        SeekResult::CantSeek
    }

    /// A second reader over the same standard input.
    ///
    /// The C duplicates a callback part by copying the function pointers and
    /// the context unchanged (`lib/mime.c:1122-1123`), so both parts read the
    /// same `stdin` and consume each other's bytes. This unit struct
    /// reproduces that exactly: there is only one standard input.
    fn duplicate(&self) -> Box<dyn PartReader> {
        Box::new(Self)
    }
}

// form_get: curl_formget, the serializer

/// `curl_formget` (`lib/formdata.c:627-659`): serializes a form and hands the
/// bytes to a callback.
///
/// ```c
/// if(!append) return (int)CURLE_BAD_FUNCTION_ARGUMENT;
/// Curl_mime_initpart(&toppart);
/// result = Curl_getformdata(NULL, &toppart, form, NULL);
/// if(!result)
///   result = Curl_mime_prepare_headers(NULL, &toppart, "multipart/form-data",
///                                      NULL, MIMESTRATEGY_FORM);
/// while(!result) {
///   char buffer[8192];
///   size_t nread = Curl_mime_read(buffer, 1, sizeof(buffer), &toppart);
///   if(!nread) break;
///   if(nread > sizeof(buffer) || append(arg, buffer, nread) != nread) {
///     result = CURLE_READ_ERROR;
///     if(nread == CURL_READFUNC_ABORT) result = CURLE_ABORTED_BY_CALLBACK;
///   }
/// }
/// Curl_mime_cleanpart(&toppart);
/// ```
///
/// # Errors
///
/// [`CURLcode::BadFunctionArgument`] for an absent callback, before anything
/// else happens. [`CURLcode::ReadError`] for a short count from the callback
/// or a failing source, and [`CURLcode::AbortedByCallback`] when a source
/// signals `CURL_READFUNC_ABORT`. Otherwise whatever the bridge or the header
/// preparation reports.
pub(crate) fn form_get(
    form: &FormList<'_>,
    rng: &mut dyn Rng,
    append: Option<&mut dyn FnMut(&[u8]) -> usize>,
) -> CodeResult<()> {
    // "Validate callback is provided" (`:633-635`) -- first, before the part
    // is initialised, so that a null callback is reported whatever else is
    // wrong with the form.
    let Some(append) = append else {
        return Err(CURLcode::BadFunctionArgument);
    };

    // `Curl_mime_initpart(&toppart); /* default form is empty */` (`:637`).
    let mut toppart = MimePart::new();

    // `Curl_getformdata(NULL, &toppart, form, NULL)` (`:638`). The fourth
    // argument is null, which is `StreamPolicy::Unavailable`.
    let mut result =
        get_form_data(&mut toppart, form, StreamPolicy::Unavailable, rng);

    if result.is_ok() {
        // `:640-641`. The content type is the literal below, the disposition
        // is absent, and the strategy is the form one.
        result = toppart.prepare_headers(
            Some(FORMGET_CONTENT_TYPE),
            None,
            MimeStrategy::Form,
            MimeOptions::default(),
        );
    }

    // The C declares its buffer inside the loop; hoisting it out is
    // indistinguishable, because every iteration overwrites the prefix it
    // reads and reads only that prefix back.
    let mut buffer = [0_u8; FORMGET_BUFFER_SIZE];
    while result.is_ok() {
        let status = toppart.read(&mut buffer);

        // `if(!nread) break;` (`:647-648`), and it comes first, so a zero
        // count ends the body rather than being classified as a failure.
        if status == ReadStatus::Eof {
            break;
        }

        // `if(nread > sizeof(buffer) || append(arg, buffer, nread) != nread)`
        // (`:650`). The two halves of that disjunction are one question --
        // "did the chunk reach the callback intact?" -- because every sentinel
        // the C can receive exceeds 8192 and so short-circuits before the
        // callback is invoked at all.
        let delivered = match status {
            ReadStatus::Bytes(count) => append(&buffer[..count]) == count,
            _ => false,
        };
        if !delivered {
            result = Err(formget_failure(status));
        }
    }

    // `Curl_mime_cleanpart(&toppart);` (`:657`), unconditionally, before the
    // code is returned.
    toppart.clean();
    result
}

/// The code `curl_formget` reports when a chunk does not reach its callback
/// intact (`lib/formdata.c:651-653`).
///
/// ```c
/// result = CURLE_READ_ERROR;
/// if(nread == CURL_READFUNC_ABORT)
///   result = CURLE_ABORTED_BY_CALLBACK;
/// ```
fn formget_failure(status: ReadStatus) -> CURLcode {
    match status {
        ReadStatus::Abort => CURLcode::AbortedByCallback,
        ReadStatus::Bytes(_)
        | ReadStatus::Eof
        | ReadStatus::StopFilling
        | ReadStatus::ReadError
        | ReadStatus::Pause => CURLcode::ReadError,
    }
}

/// `curl_formget` with a system-seeded generator: the ABI's entry point.
///
/// # Why this exists alongside `form_get`
///
/// # Errors
///
/// As `form_get`, plus [`CURLcode::FailedInit`] when the platform cannot
/// supply entropy -- which is the code `lib/rand.c:61` reports for the same
/// condition. The absent-callback check runs first, so a null callback is
/// still [`CURLcode::BadFunctionArgument`] even on a platform with no entropy
/// source.
pub fn form_get_with_system_rng(
    form: &FormList<'_>,
    append: Option<&mut dyn FnMut(&[u8]) -> usize>,
) -> CodeResult<()> {
    // Ordered before the generator so that the C's first check stays first.
    if append.is_none() {
        return Err(CURLcode::BadFunctionArgument);
    }
    let mut rng = SystemRng::new()?;
    form_get(form, &mut rng, append)
}

// form_free: curl_formfree, which Drop already performs

/// `curl_formfree` (`lib/formdata.c:665-689`): releases a whole form.
///
/// ```c
/// if(!form) return;
/// do {
///   next = form->next;
///   curl_formfree(form->more);
///   if(!(form->flags & HTTPPOST_PTRNAME)) free(form->name);
///   if(!(form->flags & (HTTPPOST_PTRCONTENTS | HTTPPOST_BUFFER |
///                       HTTPPOST_CALLBACK))) free(form->contents);
///   free(form->contenttype);
///   free(form->showfilename);
///   free(form);
///   form = next;
/// } while(form);
/// ```
///
/// # What does NOT fall out of `Drop`, and where it went
///
/// The C's frees are **conditional**, and the condition is observable rather
/// than an optimisation: a caller that passed `CURLFORM_PTRNAME` still owns
/// that memory after `curl_formfree` returns and may reuse or free it itself.
/// Here a borrowed name is a `Cow::Borrowed`, which `Drop` leaves alone, so
/// the behaviour is right by construction -- but `curl-rs-ffi` cannot rely on
/// that, because on its side the borrowed case is a raw C pointer that must
/// not be freed. [`FormEntry::free_plan`] carries the decision across, and it
/// is a transcription of `:679-683` rather than a re-derivation.
pub fn form_free(form: FormList<'_>) {
    drop(form);
}

// Tests
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rand::TestRng;
    use std::path::PathBuf;

    // --- helpers -----------------------------------------------------------

    /// The random tail a seed of zero produces, spelled out so that a change
    /// in the sampler is a test failure rather than a silent difference.
    ///
    /// The parent module's tests assert the same string for the same seed; the
    /// duplication is deliberate, because the two modules must agree and a
    /// shared helper would hide a divergence.
    const SEED_ZERO_TAIL: &str = "ABCDEFGHIJKLMNOPQRSTUV";

    /// The 46-byte boundary a given random tail produces: 24 dashes then the
    /// tail.
    fn boundary(tail: &str) -> String {
        format!("{}{tail}", "-".repeat(24))
    }

    /// Serializes a form through [`form_get`] with a deterministic generator,
    /// concatenating every chunk the callback receives.
    ///
    /// The concatenation is the contract; the chunking is not. See
    /// [`serialize_with_buffer`] for the other half of that claim.
    fn serialize(form: &FormList<'_>, seed: u32) -> CodeResult<Vec<u8>> {
        let mut out: Vec<u8> = Vec::new();
        let mut rng = TestRng::from_seed(seed);
        let result = {
            let mut append = |chunk: &[u8]| {
                out.extend_from_slice(chunk);
                chunk.len()
            };
            form_get(form, &mut rng, Some(&mut append))
        };
        result.map(|()| out)
    }

    /// The same bytes, produced by driving the engine directly through a
    /// buffer of exactly `size` bytes.
    ///
    /// Reproduces every step [`form_get`] takes -- the same bridge, the same
    /// header preparation with the same four arguments -- and differs only in
    /// how much room each read gets.
    fn serialize_with_buffer(
        form: &FormList<'_>,
        seed: u32,
        size: usize,
    ) -> CodeResult<Vec<u8>> {
        let mut toppart = build(form, seed, StreamPolicy::Unavailable)?;
        let mut out = Vec::new();
        let mut buffer = vec![0_u8; size];
        loop {
            match toppart.read(&mut buffer) {
                ReadStatus::Bytes(count) => {
                    out.extend_from_slice(&buffer[..count]);
                }
                ReadStatus::Eof => return Ok(out),
                other => panic!("unexpected read status {other:?}"),
            }
        }
    }

    /// The bridged and header-prepared top part, ready to read or inspect.
    fn build(
        form: &FormList<'_>,
        seed: u32,
        streams: StreamPolicy,
    ) -> CodeResult<MimePart> {
        let mut rng = TestRng::from_seed(seed);
        let mut toppart = MimePart::new();
        get_form_data(&mut toppart, form, streams, &mut rng)?;
        toppart.prepare_headers(
            Some(FORMGET_CONTENT_TYPE),
            None,
            MimeStrategy::Form,
            MimeOptions::default(),
        )?;
        Ok(toppart)
    }

    /// The same, for a form the test knows succeeds.
    fn tree(form: &FormList<'_>, seed: u32) -> MimePart {
        build(form, seed, StreamPolicy::Unavailable)
            .expect("the bridge succeeds for this form")
    }

    /// One part's generated headers, as text, in emission order.
    fn headers(part: &MimePart) -> Vec<String> {
        part.curl_headers()
            .iter()
            .map(|line| String::from_utf8_lossy(line).into_owned())
            .collect()
    }

    /// A path in the system temporary directory, unique to this process.
    fn scratch_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "blitzy_adhoc_test_formdata_{}_{name}",
            std::process::id()
        ))
    }

    /// Writes a scratch file and returns its path.
    fn scratch_file(name: &str, contents: &[u8]) -> PathBuf {
        let path = scratch_path(name);
        std::fs::write(&path, contents).expect("scratch file");
        path
    }

    /// A reader that yields a fixed byte count and then stops.
    #[derive(Debug)]
    struct FixedReader {
        remaining: usize,
        total: usize,
    }

    impl FixedReader {
        fn new(total: usize) -> Self {
            Self {
                remaining: total,
                total,
            }
        }
    }

    impl PartReader for FixedReader {
        fn read(&mut self, buf: &mut [u8]) -> ReadStatus {
            if self.remaining == 0 {
                return ReadStatus::Eof;
            }
            let count = self.remaining.min(buf.len());
            if count == 0 {
                return ReadStatus::StopFilling;
            }
            for slot in buf[..count].iter_mut() {
                *slot = b'z';
            }
            self.remaining -= count;
            ReadStatus::Bytes(count)
        }

        fn seek(&mut self, offset: CurlOffT, whence: SeekWhence) -> SeekResult {
            if whence != SeekWhence::Set || offset != 0 {
                return SeekResult::CantSeek;
            }
            self.remaining = self.total;
            SeekResult::Ok
        }

        fn duplicate(&self) -> Box<dyn PartReader> {
            Box::new(Self {
                remaining: self.remaining,
                total: self.total,
            })
        }
    }

    /// A reader that signals `CURL_READFUNC_ABORT` on its first read.
    #[derive(Debug)]
    struct AbortingReader;

    impl PartReader for AbortingReader {
        fn read(&mut self, _buf: &mut [u8]) -> ReadStatus {
            ReadStatus::Abort
        }

        fn seek(
            &mut self,
            _offset: CurlOffT,
            _whence: SeekWhence,
        ) -> SeekResult {
            SeekResult::Ok
        }

        fn duplicate(&self) -> Box<dyn PartReader> {
            Box::new(Self)
        }
    }

    /// `tests/data/test669`'s two fields, as `curl_formadd` would build them:
    /// `-F name=daniel -F tool=curl`.
    fn two_field_form() -> FormList<'static> {
        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"name")),
                    FormOption::CopyContents(Some(b"daniel")),
                ]
            ),
            FormCode::Ok
        );
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"tool")),
                    FormOption::CopyContents(Some(b"curl")),
                ]
            ),
            FormCode::Ok
        );
        form
    }

    // --- the whole pipeline, byte for byte ---------------------------------

    #[test]
    fn a_two_field_form_serialises_to_the_documented_bytes() {
        // This exercises the entire chain in one assertion: `form_add` ->
        // `form_add_check` -> `get_form_data` -> `prepare_headers` ->
        // `MimePart::read`. Every literal below is protocol data, compared
        // byte for byte by `compareparts` (`tests/getpart.pm:351+`), which
        // joins both sides into one string -- so header order, casing, every
        // CRLF and the absence of a space after `boundary=` are all results
        // rather than formatting.
        let form = two_field_form();
        let b = boundary(SEED_ZERO_TAIL);
        let expected = [
            // The top part's own header, then the blank line. Present because
            // `Curl_mime_initpart` does not set `MIME_BODY_ONLY`; absent
            // `Content-Disposition` because the type begins `multipart/`
            // (`lib/mime.c:1731-1733`).
            format!("Content-Type: multipart/form-data; boundary={b}\r\n"),
            "\r\n".to_owned(),
            // The first delimiter elides the leading CRLF the others carry.
            format!("--{b}\r\n"),
            "Content-Disposition: form-data; name=\"name\"\r\n".to_owned(),
            "\r\n".to_owned(),
            "daniel".to_owned(),
            format!("\r\n--{b}\r\n"),
            "Content-Disposition: form-data; name=\"tool\"\r\n".to_owned(),
            "\r\n".to_owned(),
            "curl".to_owned(),
            format!("\r\n--{b}--\r\n"),
        ]
        .concat();

        let actual = serialize(&form, 0).expect("the form serialises");
        assert_eq!(
            String::from_utf8_lossy(&actual),
            expected,
            "the concatenated body must match curl 8.x byte for byte"
        );

        // And the arithmetic, independently: 94 bytes of top-part header plus
        // the 260 `tests/data/test669:48` asserts as its `Content-Length`.
        assert_eq!(actual.len(), 94 + 260);
    }

    #[test]
    fn lib1308s_three_field_form_is_exactly_518_bytes() {
        // `tests/libtest/lib1308.c:56-74` builds this form and asserts that
        // `curl_formget` delivers 518 bytes. It reconciles exactly: 94 for the
        // top part's `Content-Type` and blank line, 54 + 89 + 73 for the three
        // parts, and 4 * 52 for the delimiters.
        let buffer = b"test buffer";
        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"name")),
                    FormOption::CopyContents(Some(b"content")),
                ]
            ),
            FormCode::Ok
        );
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"htmlcode")),
                    FormOption::CopyContents(Some(b"<HTML></HTML>")),
                    FormOption::ContentType(Some(b"text/html")),
                ]
            ),
            FormCode::Ok
        );
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"name_for_ptrcontent")),
                    FormOption::PtrContents(Some(buffer)),
                ]
            ),
            FormCode::Ok
        );

        // "after the first curl_formadd when there is a single entry, both
        // pointers should point to the same struct" (`lib1308.c:59-61`) -- the
        // Rust expression of which is that a single `form_add` appends exactly
        // one top-level entry, so head and tail coincide.
        assert_eq!(form.len(), 3);

        let bytes = serialize(&form, 0).expect("the form serialises");
        assert_eq!(
            bytes.len(),
            518,
            "lib1308.c:74 asserts 518 bytes for this exact form"
        );

        // The three parts, and only the middle one carries a content type.
        let text = String::from_utf8_lossy(&bytes).into_owned();
        assert!(text.contains("Content-Disposition: form-data; name=\"name\""));
        assert!(text.contains("Content-Type: text/html\r\n"));
        assert_eq!(text.matches("Content-Type:").count(), 2, "top part + one");
        assert!(text.ends_with("--\r\n"));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn lib1308s_file_field_is_exactly_381_bytes() {
        // The second half of `lib1308.c:79-91`, whose assertion is a RUNNING
        // total: `total_size` is not reset between the two `curl_formget`
        // calls, so 899 minus the 518 above is 381 for this form alone.
        //
        // The fixture's file is `tests/data/test1308`'s `<file>` block, whose
        // body is one 51-character line plus its newline.
        let contents = b"Piece of the file that is to uploaded as a formpost\n";
        assert_eq!(contents.len(), 52);
        let path = scratch_file("lib1308", contents);
        let path_text = crate::util::path_bytes(path.as_path());

        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::PtrName(Some(b"name of file field")),
                    FormOption::File(Some(path_text)),
                    FormOption::FileName(Some(b"custom named file")),
                ]
            ),
            FormCode::Ok
        );

        let bytes = serialize(&form, 0).expect("the form serialises");
        let text = String::from_utf8_lossy(&bytes).into_owned();

        // The shown filename overrides the base name `set_file` derived, and
        // the type falls back to the default because a temporary path has no
        // suffix curl's table recognises.
        assert!(text.contains(
            "Content-Disposition: form-data; name=\"name of file field\"; \
             filename=\"custom named file\"\r\n"
        ));
        assert!(text.contains("Content-Type: application/octet-stream\r\n"));
        assert_eq!(
            bytes.len(),
            381,
            "lib1308.c:89 asserts 899 cumulative, which is 518 + 381"
        );

        std::fs::remove_file(&path).expect("scratch file removed");
    }

    #[test]
    fn an_empty_form_serialises_to_headers_only() {
        // `curl_formget(NULL, arg, cb)`: the bridge's "no input => no output!"
        // (`lib/formdata.c:729-730`) leaves the top part with no content at
        // all, so `prepare_headers` sees a part of no kind and emits the
        // content type it was handed with no boundary parameter -- there is no
        // multipart to take one from.
        let form = FormList::new();
        assert!(form.is_empty());
        assert_eq!(form.len(), 0);
        assert!(form.last().is_none());

        let bytes = serialize(&form, 0).expect("an empty form serialises");
        assert_eq!(
            String::from_utf8_lossy(&bytes),
            "Content-Type: multipart/form-data\r\n\r\n"
        );
    }

    // --- CURL_FORMADD_OPTION_TWICE -----------------------------------------

    #[test]
    fn every_option_twice_path() {
        // Each row is an argument list whose second option repeats the first
        // and must therefore be `CURL_FORMADD_OPTION_TWICE`. The locators are
        // the C's `retval = CURL_FORMADD_OPTION_TWICE;` assignments.
        let mut form = FormList::new();

        // `:374-375` -- and via the fallthrough at `:370-372`, so `PtrName`
        // after `CopyName` reaches the same check.
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"a")),
                    FormOption::CopyName(Some(b"b")),
                ]
            ),
            FormCode::OptionTwice
        );
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"a")),
                    FormOption::PtrName(Some(b"b")),
                ]
            ),
            FormCode::OptionTwice
        );

        // `:385-386`.
        assert_eq!(
            form_add(
                &mut form,
                vec![FormOption::NameLength(3), FormOption::NameLength(4),]
            ),
            FormCode::OptionTwice
        );

        // `:398-399`.
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyContents(Some(b"a")),
                    FormOption::PtrContents(Some(b"b")),
                ]
            ),
            FormCode::OptionTwice
        );

        // `:419-420` -- `CURLFORM_FILECONTENT` after `CURLFORM_PTRCONTENTS`,
        // which is the flag half of that check.
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::PtrContents(Some(b"a")),
                    FormOption::FileContent(Some(b"f.txt")),
                ]
            ),
            FormCode::OptionTwice
        );
        // ... and after itself, which is the other half.
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::FileContent(Some(b"f.txt")),
                    FormOption::FileContent(Some(b"g.txt")),
                ]
            ),
            FormCode::OptionTwice
        );

        // `:455-456` -- a value from another option is present and the
        // filename flag is NOT set, so this is a conflict rather than a second
        // file.
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyContents(Some(b"a")),
                    FormOption::File(Some(b"f.txt")),
                ]
            ),
            FormCode::OptionTwice
        );

        // `:472-473`.
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::BufferPtr(Some(b"a")),
                    FormOption::BufferPtr(Some(b"b")),
                ]
            ),
            FormCode::OptionTwice
        );

        // `:487-488`.
        assert_eq!(
            form_add(
                &mut form,
                vec![FormOption::BufferLength(3), FormOption::BufferLength(4),]
            ),
            FormCode::OptionTwice
        );

        // `:495-496`.
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::Stream(Some(Box::new(FixedReader::new(4)))),
                    FormOption::Stream(Some(Box::new(FixedReader::new(4)))),
                ]
            ),
            FormCode::OptionTwice
        );

        // `:531-532` -- a content type is present and the filename flag is
        // NOT set, so this cannot spawn a `more` node.
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::ContentType(Some(b"a/b")),
                    FormOption::ContentType(Some(b"c/d")),
                ]
            ),
            FormCode::OptionTwice
        );

        // `:547-548`.
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::ContentHeader(Some(SList::new())),
                    FormOption::ContentHeader(Some(SList::new())),
                ]
            ),
            FormCode::OptionTwice
        );

        // `:557-558` -- and the two options share one field, so either
        // ordering collides.
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::FileName(Some(b"a")),
                    FormOption::FileName(Some(b"b")),
                ]
            ),
            FormCode::OptionTwice
        );
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::FileName(Some(b"a")),
                    FormOption::Buffer(Some(b"b")),
                ]
            ),
            FormCode::OptionTwice
        );

        // Not one part was committed: every call above failed.
        assert!(form.is_empty(), "a failing form_add commits nothing");
    }

    #[test]
    fn contents_length_may_be_given_twice_and_the_last_wins() {
        // `:408-410` has NO "given twice" check, unlike almost every other
        // option.
        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"n")),
                    FormOption::CopyContents(Some(b"0123456789")),
                    FormOption::ContentsLength(9),
                    FormOption::ContentsLength(4),
                ]
            ),
            FormCode::Ok
        );
        let entry = form.entry(0).expect("one entry");
        assert_eq!(entry.contentlen(), 4, "the last value wins");
        // And the copy honoured it: `FormInfoCopyField(&form->value,
        // (size_t)form->contentslength)` at `:273`.
        assert_eq!(entry.contents(), Some(b"0123".as_slice()));

        // `CURLFORM_CONTENTLEN` (`:412-415`) likewise has no check.
        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"n")),
                    FormOption::CopyContents(Some(b"0123456789")),
                    FormOption::ContentLen(9),
                    FormOption::ContentLen(2),
                ]
            ),
            FormCode::Ok
        );
        assert_eq!(form.entry(0).expect("one entry").contentlen(), 2);
    }

    // --- CURL_FORMADD_NULL -------------------------------------------------

    #[test]
    fn every_null_path() {
        let mut form = FormList::new();

        // `:380-381`, reached by both spellings through the fallthrough.
        assert_eq!(
            form_add(&mut form, vec![FormOption::CopyName(None)]),
            FormCode::Null
        );
        assert_eq!(
            form_add(&mut form, vec![FormOption::PtrName(None)]),
            FormCode::Null
        );

        // `:404-405`.
        assert_eq!(
            form_add(&mut form, vec![FormOption::CopyContents(None)]),
            FormCode::Null
        );
        assert_eq!(
            form_add(&mut form, vec![FormOption::PtrContents(None)]),
            FormCode::Null
        );

        // `:429-430`.
        assert_eq!(
            form_add(&mut form, vec![FormOption::FileContent(None)]),
            FormCode::Null
        );

        // `:465-466`, the no-value-yet branch.
        assert_eq!(
            form_add(&mut form, vec![FormOption::File(None)]),
            FormCode::Null
        );
        // `:452-453`, the multi-file branch: a value and the flag are already
        // present, so a null here is `Null` rather than `OptionTwice`.
        assert_eq!(
            form_add(
                &mut form,
                vec![FormOption::File(Some(b"a.txt")), FormOption::File(None),]
            ),
            FormCode::Null
        );

        // `:481-482`.
        assert_eq!(
            form_add(&mut form, vec![FormOption::BufferPtr(None)]),
            FormCode::Null
        );

        // `:506-507`.
        assert_eq!(
            form_add(&mut form, vec![FormOption::Stream(None)]),
            FormCode::Null
        );

        // `:538-539`, the no-type-yet branch.
        assert_eq!(
            form_add(&mut form, vec![FormOption::ContentType(None)]),
            FormCode::Null
        );
        // `:528-529`, the spawn branch.
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::File(Some(b"a.txt")),
                    FormOption::ContentType(Some(b"a/b")),
                    FormOption::ContentType(None),
                ]
            ),
            FormCode::Null
        );

        assert!(form.is_empty());
    }

    #[test]
    fn a_null_shown_filename_is_null_after_the_twice_check() {
        // `:554-561` reaches `strlen(avalue)` with no null check, so the C
        // dereferences a null pointer here. Undefined behaviour has no
        // behaviour to preserve, so `None` is `Null` -- the answer every
        // sibling option gives.
        let mut form = FormList::new();
        assert_eq!(
            form_add(&mut form, vec![FormOption::FileName(None)]),
            FormCode::Null
        );
        assert_eq!(
            form_add(&mut form, vec![FormOption::Buffer(None)]),
            FormCode::Null
        );

        // But the ORDER the C does define is unchanged: "already set" is
        // tested first, so this is `OptionTwice` and not `Null`.
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::FileName(Some(b"first")),
                    FormOption::FileName(None),
                ]
            ),
            FormCode::OptionTwice
        );
    }

    #[test]
    fn an_embedded_nul_in_a_sized_name_is_null() {
        // `if(name && form->namelength) { if(memchr(name, 0,
        // form->namelength)) return CURL_FORMADD_NULL; }` (`:260-263`).
        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"ab\0cd")),
                    FormOption::NameLength(5),
                    FormOption::CopyContents(Some(b"v")),
                ]
            ),
            FormCode::Null
        );

        // Only the first `namelength` bytes are examined, exactly as
        // `memchr`'s third argument says: a NUL beyond the length is outside
        // the name and is not an error.
        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"ab\0cd")),
                    FormOption::NameLength(2),
                    FormOption::CopyContents(Some(b"v")),
                ]
            ),
            FormCode::Ok
        );
        assert_eq!(
            form.entry(0).expect("one entry").name_bytes(),
            Some(b"ab".as_slice())
        );

        // And with no explicit length the check does not run at all, because
        // the C guards it with `form->namelength`.
        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"ab\0cd")),
                    FormOption::CopyContents(Some(b"v")),
                ]
            ),
            FormCode::Ok
        );
    }

    // --- CURL_FORMADD_UNKNOWN_OPTION and CURL_FORMADD_ILLEGAL_ARRAY --------

    #[test]
    fn an_option_outside_the_vocabulary_is_unknown_option() {
        // `default: retval = CURL_FORMADD_UNKNOWN_OPTION;` (`:563-565`).
        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"n")),
                    FormOption::Unknown,
                    FormOption::CopyContents(Some(b"v")),
                ]
            ),
            FormCode::UnknownOption
        );
        // The loop stops at the first failing option, so the trailing
        // `CopyContents` was never applied -- and nothing was committed.
        assert!(form.is_empty());
    }

    #[test]
    fn illegal_array_is_produced_by_the_decoder_not_the_builder() {
        // `CURLFORM_ARRAY` inside a `CURLFORM_ARRAY` is
        // `CURL_FORMADD_ILLEGAL_ARRAY` -- the C's comment at `:357-359` is "we
        // do not support an array from within an array" -- and a null array is
        // `CURL_FORMADD_NULL` (`:362-363`).
        assert_ne!(FormCode::IllegalArray, FormCode::Ok);
        assert_ne!(FormCode::IllegalArray, FormCode::Null);
        assert!(!FormCode::IllegalArray.is_ok());

        // No argument list this builder accepts can yield it.
        let mut form = FormList::new();
        for option in [
            FormOption::CopyName(Some(b"n")),
            FormOption::CopyContents(Some(b"v")),
            FormOption::Unknown,
        ] {
            assert_ne!(
                form_add(&mut form, vec![option]),
                FormCode::IllegalArray
            );
        }
    }

    #[test]
    fn disabled_is_never_returned() {
        // `lib/formdata.c:843-866` returns `CURL_FORMADD_DISABLED` from three
        // stub entry points when the form API is compiled out. The variant
        // exists only so the ABI crate can spell the token.
        assert!(!FormCode::Disabled.is_ok());
        let mut form = FormList::new();
        assert_ne!(
            form_add(&mut form, vec![FormOption::Unknown]),
            FormCode::Disabled
        );
        assert_ne!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"n")),
                    FormOption::CopyContents(Some(b"v")),
                ]
            ),
            FormCode::Disabled
        );
    }

    // --- CURL_FORMADD_INCOMPLETE -------------------------------------------

    #[test]
    fn the_five_incomplete_conditions() {
        // `:230-244`, each condition on its own.

        // 1. `(!name || !value) && !post` -- and only for the FIRST node of a
        //    chain, which is what `!post` means.
        let mut form = FormList::new();
        assert_eq!(
            form_add(&mut form, vec![FormOption::CopyName(Some(b"n"))]),
            FormCode::Incomplete
        );
        assert_eq!(
            form_add(&mut form, vec![FormOption::CopyContents(Some(b"v"))]),
            FormCode::Incomplete
        );
        // An empty argument list is the degenerate case: neither is set.
        assert_eq!(form_add(&mut form, Vec::new()), FormCode::Incomplete);

        // 2. `form->contentslength && (form->flags & HTTPPOST_FILENAME)` -- a
        //    file part cannot also carry an explicit content length.
        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"n")),
                    FormOption::File(Some(b"f.txt")),
                    FormOption::ContentsLength(4),
                ]
            ),
            FormCode::Incomplete
        );

        // 3. `FILENAME && PTRCONTENTS`.
        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"n")),
                    FormOption::PtrContents(Some(b"v")),
                    FormOption::File(Some(b"f.txt")),
                    FormOption::CopyName(Some(b"x")),
                ]
            ),
            // The `File` after a `PtrContents` value is caught earlier, by the
            // "given twice" check at `:455-456`, so condition 3 needs the
            // flags set in the other order.
            FormCode::OptionTwice
        );
        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"n")),
                    FormOption::File(Some(b"f.txt")),
                    FormOption::PtrContents(Some(b"v")),
                ]
            ),
            // `PtrContents` sets its flag BEFORE the twice check (`:394-396`),
            // so the flag survives into `FormAddCheck` and condition 3 fires
            // there -- except that the twice check fires first for the value.
            FormCode::OptionTwice
        );

        // 4. `!form->buffer && BUFFER && PTRBUFFER`. `CURLFORM_BUFFERPTR`
        //    sets both flags before its own null check (`:471`), so a null
        //    buffer leaves the flags set -- but that call returns `Null`
        //    first. The condition is reachable only through the flags being
        //    set with no buffer stored, which the builder cannot produce and
        //    which is therefore asserted on the check itself: a buffer part
        //    WITH a buffer passes.
        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"n")),
                    FormOption::BufferPtr(Some(b"bytes")),
                    FormOption::FileName(Some(b"shown.txt")),
                ]
            ),
            FormCode::Ok
        );

        // 5. `READFILE && PTRCONTENTS` -- likewise guarded earlier by
        //    `:419-420`, which tests exactly those two flags, so the outcome a
        //    caller sees is `OptionTwice`.
        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"n")),
                    FormOption::PtrContents(Some(b"v")),
                    FormOption::FileContent(Some(b"f.txt")),
                ]
            ),
            FormCode::OptionTwice
        );

        // Condition 2 in its other spelling, which IS reachable and is the
        // clearest demonstration that `FormAddCheck` runs after the whole
        // option list rather than during it: `CURLFORM_CONTENTLEN` sets the
        // length with no conflict at option time and fails at check time.
        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"n")),
                    FormOption::ContentLen(7),
                    FormOption::File(Some(b"f.txt")),
                ]
            ),
            FormCode::Incomplete
        );
    }

    #[test]
    fn a_more_node_needs_neither_name_nor_value() {
        // `(!name || !value) && !post` (`:230`): the `!post` term makes the
        // name-and-value requirement apply to the FIRST node only. A `more`
        // node spawned by a second `CURLFORM_CONTENTTYPE` has a type and
        // nothing else, and that is accepted -- which is why the bridge has to
        // cope with a null `contents` there.
        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"n")),
                    FormOption::File(Some(b"a.txt")),
                    FormOption::ContentType(Some(b"a/b")),
                    FormOption::ContentType(Some(b"c/d")),
                ]
            ),
            FormCode::Ok
        );
        let entry = form.entry(0).expect("one entry");
        assert_eq!(entry.more().len(), 1);
        let spawned = &entry.more()[0];
        assert_eq!(spawned.contenttype(), Some(&b"c/d"[..]));
        assert!(spawned.name().is_none());
        assert!(spawned.contents().is_none());
        // `AddFormInfo` sets the filename flag on every node it chains
        // (`:144`), which is why the spawned node reports itself as a file.
        assert!(spawned.flags().filename);
    }

    #[test]
    fn filename_with_ptrcontents_is_incomplete_through_a_spawned_node() {
        // Condition 3 of `:230-244`, `FILENAME && PTRCONTENTS`, IS reachable
        // -- but only through a spawned node, because on the first node the
        // "given twice" checks fire first whichever order the two options
        // arrive in. A second `CURLFORM_CONTENTTYPE` spawns a node that
        // carries the filename flag (`AddFormInfo`, `:144`) and no value, so a
        // following `CURLFORM_PTRCONTENTS` succeeds at option time and the
        // combination is caught at check time.
        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"n")),
                    FormOption::File(Some(b"a.txt")),
                    FormOption::ContentType(Some(b"a/b")),
                    FormOption::ContentType(Some(b"c/d")),
                    FormOption::PtrContents(Some(b"x")),
                ]
            ),
            FormCode::Incomplete
        );
        assert!(form.is_empty());
    }

    // --- content-type inference and the prevtype carry-forward -------------

    #[test]
    fn the_prevtype_carry_forward() {
        // `:245-259` with `:281-282`. When a file or buffer part has no
        // explicit type, the order is: curl's own suffix table, then the
        // PREVIOUS part's resolved type, then `application/octet-stream`. The
        // middle step is the one that is easy to miss, and it changes the
        // emitted `Content-Type` of the second and later files of a multi-file
        // field.
        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"f")),
                    FormOption::File(Some(b"a.dat")),
                    FormOption::ContentType(Some(b"x/y")),
                    // `.dat` is not one of the ten suffixes in curl's table,
                    // so this part has nothing of its own to infer from.
                    FormOption::File(Some(b"b.dat")),
                ]
            ),
            FormCode::Ok
        );
        let entry = form.entry(0).expect("one entry");
        assert_eq!(entry.contenttype(), Some(&b"x/y"[..]));
        assert_eq!(entry.more().len(), 1);
        assert_eq!(
            entry.more()[0].contenttype(),
            Some(&b"x/y"[..]),
            "the second file inherits prevtype, NOT the octet-stream default"
        );

        // With no previous type to inherit, the same unknown suffix falls all
        // the way through to the default.
        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"g")),
                    FormOption::File(Some(b"c.dat")),
                ]
            ),
            FormCode::Ok
        );
        assert_eq!(
            form.entry(0).expect("one entry").contenttype(),
            Some(FILE_CONTENTTYPE_DEFAULT.as_bytes())
        );
        assert_eq!(FILE_CONTENTTYPE_DEFAULT, "application/octet-stream");
    }

    #[test]
    fn prevtype_resets_between_calls() {
        // `prevtype` is a local of `FormAddCheck` (`:220`), so it cannot leak
        // from one `curl_formadd` to the next however adjacent the parts are
        // in the finished form. A shared carry-forward would give the second
        // field below the first field's type.
        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"first")),
                    FormOption::File(Some(b"a.dat")),
                    FormOption::ContentType(Some(b"x/y")),
                ]
            ),
            FormCode::Ok
        );
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"second")),
                    FormOption::File(Some(b"b.dat")),
                ]
            ),
            FormCode::Ok
        );
        assert_eq!(
            form.entry(0).expect("first").contenttype(),
            Some(&b"x/y"[..])
        );
        assert_eq!(
            form.entry(1).expect("second").contenttype(),
            Some(FILE_CONTENTTYPE_DEFAULT.as_bytes()),
            "prevtype is per-call"
        );
    }

    #[test]
    fn content_type_inference_uses_curls_ten_row_table() {
        // The parent module's `contenttype` is the whole of the inference, and
        // it returns `None` for an unmatched suffix exactly as
        // `Curl_mime_contenttype` (`lib/mime.c:1654`) returns `NULL`. No
        // general-purpose MIME database is consulted -- `deny.toml` bans both
        // `mime_guess` and `mime`, because a larger database answers where curl
        // 8.x answers `application/octet-stream` and so emits bytes curl never
        // emits.
        for (path, expected) in [
            ("note.txt", "text/plain"),
            ("photo.jpeg", "image/jpeg"),
            ("photo.JPG", "image/jpeg"),
            ("logo.svg", "image/svg+xml"),
            ("page.html", "text/html"),
            ("doc.pdf", "application/pdf"),
            ("blob.unknown", FILE_CONTENTTYPE_DEFAULT),
            ("archive.tar.gz", FILE_CONTENTTYPE_DEFAULT),
        ] {
            let mut form = FormList::new();
            assert_eq!(
                form_add(
                    &mut form,
                    vec![
                        FormOption::CopyName(Some(b"f")),
                        FormOption::File(Some(path.as_bytes())),
                    ]
                ),
                FormCode::Ok
            );
            assert_eq!(
                form.entry(0).expect("one entry").contenttype(),
                Some(expected.as_bytes()),
                "inference for {path}"
            );
        }
    }

    #[test]
    fn a_buffer_part_infers_from_the_shown_filename() {
        // `const char *f = Curl_bufref_ptr((form->flags & HTTPPOST_BUFFER) ?
        // &form->showfilename : &form->value);` (`:248-249`). A buffer has no
        // path of its own, so the shown filename is the only thing with a
        // suffix to look at -- and if none was given, the default applies.
        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"f")),
                    FormOption::BufferPtr(Some(b"<html></html>")),
                    FormOption::Buffer(Some(b"page.html")),
                ]
            ),
            FormCode::Ok
        );
        assert_eq!(
            form.entry(0).expect("one entry").contenttype(),
            Some(&b"text/html"[..])
        );

        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"f")),
                    FormOption::BufferPtr(Some(b"bytes")),
                ]
            ),
            FormCode::Ok
        );
        assert_eq!(
            form.entry(0).expect("one entry").contenttype(),
            Some(FILE_CONTENTTYPE_DEFAULT.as_bytes()),
            "no shown filename leaves nothing to infer from"
        );
    }

    #[test]
    fn a_plain_value_part_gets_no_inferred_type() {
        // The inference at `:245` is guarded by `FILENAME || BUFFER`, so an
        // ordinary `CURLFORM_COPYCONTENTS` part is left with no type at all
        // and emits no `Content-Type` header. Inferring one from the field
        // name would add a header curl 8.x does not send.
        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"file.txt")),
                    FormOption::CopyContents(Some(b"v")),
                ]
            ),
            FormCode::Ok
        );
        assert!(form.entry(0).expect("one entry").contenttype().is_none());

        let toppart = tree(&form, 0);
        let part = toppart
            .subparts()
            .expect("a multipart")
            .part(0)
            .expect("one part");
        assert_eq!(
            headers(part),
            vec!["Content-Disposition: form-data; name=\"file.txt\""]
        );
    }

    // --- structure: one call, one entry, and the more chain ----------------

    #[test]
    fn one_call_appends_one_entry_with_a_more_chain() {
        // `AddHttpPost` passes the previous node as the parent from
        // `FormAddCheck`'s second iteration onward (`:276`) and a parented node
        // is spliced into `parent->more` (`:86-92`), so N accumulators become
        // ONE top-level entry with N-1 children. That is what makes
        // `-F 'name=@a,@b,@c'` one form field rather than three.
        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"files")),
                    FormOption::File(Some(b"a.txt")),
                    FormOption::File(Some(b"b.txt")),
                    FormOption::File(Some(b"c.txt")),
                ]
            ),
            FormCode::Ok
        );
        assert_eq!(form.len(), 1, "one call, one top-level entry");
        let entry = form.entry(0).expect("one entry");
        assert_eq!(entry.more().len(), 2);
        assert_eq!(entry.contents(), Some(b"a.txt".as_slice()));
        assert_eq!(entry.more()[0].contents(), Some(b"b.txt".as_slice()));
        assert_eq!(entry.more()[1].contents(), Some(b"c.txt".as_slice()));

        // `for(file = post; file; file = file->more)` (`:759`) starts at the
        // entry itself, which is why one code path serves both shapes.
        let paths: Vec<Option<&[u8]>> =
            entry.files().map(FormEntry::contents).collect();
        assert_eq!(
            paths,
            vec![
                Some(b"a.txt".as_slice()),
                Some(b"b.txt".as_slice()),
                Some(b"c.txt".as_slice()),
            ]
        );

        // Only the top entry carries the name; the children have none.
        assert_eq!(entry.name_bytes(), Some(b"files".as_slice()));
        assert!(entry.more()[0].name().is_none());

        // `*last_post` is that single top-level entry.
        assert_eq!(
            form.last().expect("a tail").name_bytes(),
            Some(b"files".as_slice())
        );
    }

    #[test]
    fn filename_and_buffer_write_the_same_field() {
        // `:554-561` is one arm for two options, both writing `showfilename`.
        for option in [
            FormOption::FileName(Some(b"shown")),
            FormOption::Buffer(Some(b"shown")),
        ] {
            let mut form = FormList::new();
            assert_eq!(
                form_add(
                    &mut form,
                    vec![
                        FormOption::CopyName(Some(b"n")),
                        FormOption::BufferPtr(Some(b"bytes")),
                        option,
                    ]
                ),
                FormCode::Ok
            );
            assert_eq!(
                form.entry(0).expect("one entry").showfilename(),
                Some(&b"shown"[..])
            );
        }

        // And `CURLFORM_BUFFER` does NOT set `CURL_HTTPPOST_BUFFER`, despite
        // its name: only `CURLFORM_BUFFERPTR` does (`:471`).
        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"n")),
                    FormOption::CopyContents(Some(b"v")),
                    FormOption::Buffer(Some(b"shown")),
                ]
            ),
            FormCode::Ok
        );
        let flags = form.entry(0).expect("one entry").flags();
        assert!(!flags.buffer);
        assert!(!flags.ptrbuffer);
    }

    #[test]
    fn contentlen_and_contentslength_share_a_field_and_large_is_always_set() {
        // Both options write `FormInfo::contentslength` (`:409`, `:414`), and
        // `AddHttpPost` moves it into `post->contentlen` (`:74`) while ORing
        // `CURL_HTTPPOST_LARGE` in unconditionally (`:78`) and never touching
        // `post->contentslength` at all. So the bridge's selection at
        // `:779-782` always reads `contentlen`, and the `long` member is
        // vestigial.
        for option in [FormOption::ContentsLength(4), FormOption::ContentLen(4)]
        {
            let mut form = FormList::new();
            assert_eq!(
                form_add(
                    &mut form,
                    vec![
                        FormOption::CopyName(Some(b"n")),
                        FormOption::CopyContents(Some(b"0123456789")),
                        option,
                    ]
                ),
                FormCode::Ok
            );
            let entry = form.entry(0).expect("one entry");
            assert!(entry.flags().large, "AddHttpPost ORs LARGE in always");
            assert_eq!(entry.contentlen(), 4);
            assert_eq!(entry.contentslength(), 0, "never written by the C");
            assert_eq!(
                entry.content_length(),
                4,
                "the flag selects contentlen"
            );
        }

        // And the selection itself: with the flag clear the C would read the
        // other member, which is zero -- "measure it".
        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"n")),
                    FormOption::CopyContents(Some(b"value")),
                ]
            ),
            FormCode::Ok
        );
        let entry = form.entry(0).expect("one entry");
        assert_eq!(entry.content_length(), 0);
        assert_eq!(entry.contents(), Some(b"value".as_slice()));
    }

    #[test]
    fn buffer_ptr_with_and_without_a_length() {
        // `curl_mime_data(part, post->buffer, post->bufferlength ?
        // post->bufferlength : -1)` (`:807-810`): a zero length means
        // "measure it", which for a Rust slice is its own length.
        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"n")),
                    FormOption::BufferPtr(Some(b"0123456789")),
                    FormOption::BufferLength(4),
                    FormOption::Buffer(Some(b"shown.bin")),
                ]
            ),
            FormCode::Ok
        );
        let bytes = serialize(&form, 0).expect("serialises");
        let text = String::from_utf8_lossy(&bytes).into_owned();
        assert!(text.contains("\r\n\r\n0123\r\n--"), "four bytes, not ten");
        assert_eq!(form.entry(0).expect("one entry").bufferlength(), 4);

        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"n")),
                    FormOption::BufferPtr(Some(b"0123456789")),
                    FormOption::Buffer(Some(b"shown.bin")),
                ]
            ),
            FormCode::Ok
        );
        let bytes = serialize(&form, 0).expect("serialises");
        let text = String::from_utf8_lossy(&bytes).into_owned();
        assert!(text.contains("\r\n\r\n0123456789\r\n--"), "measure it");
        assert_eq!(form.entry(0).expect("one entry").bufferlength(), 0);
    }

    #[test]
    fn namelength_selects_a_prefix_and_an_overlong_length_is_clamped() {
        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"abcdef")),
                    FormOption::NameLength(3),
                    FormOption::CopyContents(Some(b"v")),
                ]
            ),
            FormCode::Ok
        );
        let entry = form.entry(0).expect("one entry");
        assert_eq!(entry.namelength(), 3);
        assert_eq!(entry.name_bytes(), Some(b"abc".as_slice()));
        // `FormInfoCopyField(&form->name, form->namelength)` at `:267` copies
        // exactly that many bytes, so the entry owns three.
        assert_eq!(entry.name(), Some(b"abc".as_slice()));
        assert_eq!(entry.free_plan().name, Ownership::Owned);

        let bytes = serialize(&form, 0).expect("serialises");
        assert!(String::from_utf8_lossy(&bytes)
            .contains("Content-Disposition: form-data; name=\"abc\"\r\n"));

        // A length beyond the slice is an out-of-bounds read in C and is
        // clamped here; see `effective_usize_len`.
        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"ab")),
                    FormOption::NameLength(99),
                    FormOption::CopyContents(Some(b"v")),
                ]
            ),
            FormCode::Ok
        );
        assert_eq!(
            form.entry(0).expect("one entry").name_bytes(),
            Some(b"ab".as_slice())
        );

        // With no explicit length, `AddHttpPost` substitutes the measured one
        // (`:63-65`), so the entry reports a real length rather than zero.
        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"abcdef")),
                    FormOption::CopyContents(Some(b"v")),
                ]
            ),
            FormCode::Ok
        );
        assert_eq!(form.entry(0).expect("one entry").namelength(), 6);
    }

    #[test]
    fn a_length_above_long_max_is_memory() {
        // `if((src->bufferlength > LONG_MAX) || (namelength > LONG_MAX))
        // return NULL;` (`:66-68`), which `FormAddCheck` reports as
        // `CURL_FORMADD_MEMORY` (`:278-279`). Reachable because
        // `CURLFORM_NAMELENGTH` and `CURLFORM_BUFFERLENGTH` store
        // `(size_t)(long)`, so a negative argument lands above `LONG_MAX`
        // exactly -- see `FormOption`'s decoding contract.
        let above = usize::MAX;

        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"n")),
                    FormOption::NameLength(above),
                    FormOption::CopyContents(Some(b"v")),
                ]
            ),
            FormCode::Memory
        );

        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"n")),
                    FormOption::BufferPtr(Some(b"bytes")),
                    FormOption::BufferLength(above),
                ]
            ),
            FormCode::Memory
        );

        assert!(form.is_empty());
    }

    #[test]
    fn a_negative_content_length_is_memory_when_the_value_is_copied() {
        // `FormInfoCopyField(&form->value, (size_t)form->contentslength)`
        // (`:273`): the cast turns a negative length into a value near
        // `SIZE_MAX`, which no allocator satisfies, so the C reports
        // `CURL_FORMADD_MEMORY`.
        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"n")),
                    FormOption::CopyContents(Some(b"value")),
                    FormOption::ContentLen(-1),
                ]
            ),
            FormCode::Memory
        );

        // On a part whose value is NOT copied the guard is not reached, and
        // the negative length surfaces later, in the bridge, as
        // `CURLE_OUT_OF_MEMORY` -- the code `curl_mime_data`'s failing
        // `curlx_memdup0` produces there.
        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"n")),
                    FormOption::PtrContents(Some(b"value")),
                    FormOption::ContentLen(-1),
                ]
            ),
            FormCode::Ok
        );
        let mut rng = TestRng::from_seed(0);
        let mut toppart = MimePart::new();
        assert_eq!(
            get_form_data(
                &mut toppart,
                &form,
                StreamPolicy::Unavailable,
                &mut rng
            ),
            Err(CURLcode::OutOfMemory)
        );
    }

    // --- the bridge: names, filenames and nesting --------------------------

    #[test]
    fn showfilename_is_gated_on_four_conditions() {
        // `if(!result && post->showfilename) if(post->more || (post->flags &
        // (HTTPPOST_FILENAME | HTTPPOST_BUFFER | HTTPPOST_CALLBACK)))`
        // (`:830-833`). A plain value part with a `CURLFORM_FILENAME` gets NO
        // `filename=` parameter, because none of the four conditions holds --
        // and emitting one would add bytes curl 8.x does not send.
        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"n")),
                    FormOption::CopyContents(Some(b"v")),
                    FormOption::FileName(Some(b"ignored.txt")),
                ]
            ),
            FormCode::Ok
        );
        assert_eq!(
            form.entry(0).expect("one entry").showfilename(),
            Some(&b"ignored.txt"[..]),
            "recorded on the entry either way"
        );
        let bytes = serialize(&form, 0).expect("serialises");
        let text = String::from_utf8_lossy(&bytes).into_owned();
        assert!(
            !text.contains("filename="),
            "no flag holds, so the shown filename is not emitted"
        );

        // A buffer part DOES carry it, through the `HTTPPOST_BUFFER` term.
        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"n")),
                    FormOption::BufferPtr(Some(b"bytes")),
                    FormOption::Buffer(Some(b"shown.txt")),
                ]
            ),
            FormCode::Ok
        );
        let bytes = serialize(&form, 0).expect("serialises");
        assert!(String::from_utf8_lossy(&bytes).contains(
            "Content-Disposition: form-data; name=\"n\"; \
             filename=\"shown.txt\"\r\n"
        ));

        // And a callback part does too, through `HTTPPOST_CALLBACK` -- even
        // though `curl_formget` installs no reader for it.
        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"n")),
                    FormOption::Stream(Some(Box::new(FixedReader::new(3)))),
                    FormOption::FileName(Some(b"stream.bin")),
                ]
            ),
            FormCode::Ok
        );
        let bytes = serialize(&form, 0).expect("serialises");
        assert!(
            String::from_utf8_lossy(&bytes).contains("filename=\"stream.bin\"")
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn filecontent_clears_the_remote_filename() {
        // `if(!result && (post->flags & HTTPPOST_READFILE)) result =
        // curl_mime_filename(part, NULL);` (`:804-805`).
        let path = scratch_file("filecontent", b"body bytes\n");
        let path_text = crate::util::path_bytes(path.as_path());

        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"field")),
                    FormOption::FileContent(Some(path_text)),
                ]
            ),
            FormCode::Ok
        );
        assert!(form.entry(0).expect("one entry").flags().readfile);

        let toppart = tree(&form, 0);
        let part = toppart
            .subparts()
            .expect("a multipart")
            .part(0)
            .expect("one part");
        assert_eq!(
            part.filename(),
            None,
            "the side effect of set_file must be undone"
        );
        let generated = headers(part);
        assert_eq!(
            generated[0], "Content-Disposition: form-data; name=\"field\"",
            "a name=, and no filename="
        );

        // The file's bytes still reach the wire; only the label is gone.
        let bytes = serialize(&form, 0).expect("serialises");
        let text = String::from_utf8_lossy(&bytes).into_owned();
        assert!(text.contains("\r\n\r\nbody bytes\n\r\n--"));
        assert!(!text.contains("filename="));

        std::fs::remove_file(&path).expect("scratch file removed");
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn a_file_part_keeps_the_base_name_it_derived() {
        // The contrast with the test above: `CURLFORM_FILE` leaves the base
        // name in place, so the part advertises it.
        let path = scratch_file("keepname", b"x\n");
        let path_text = crate::util::path_bytes(path.as_path());
        let base = path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("a base name");

        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"field")),
                    FormOption::File(Some(path_text)),
                ]
            ),
            FormCode::Ok
        );
        let toppart = tree(&form, 0);
        let part = toppart
            .subparts()
            .expect("a multipart")
            .part(0)
            .expect("one part");
        assert_eq!(part.filename(), Some(base.as_bytes()));

        std::fs::remove_file(&path).expect("scratch file removed");
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn a_multi_file_field_nests_a_multipart_mixed() {
        // `:741-756` plus `:759-834`. Two files under one name become an
        // intermediate part that carries the FIELD NAME and a nested
        // multipart, and each file becomes a child of that. This is the shape
        // `tests/data/test1133` asserts for
        // `-F 'file3=@a;type=m/f,@b'`, including that the children carry
        // `Content-Disposition: attachment` rather than `form-data` --
        // `form-data` propagates only under a `multipart/form-data` parent
        // (`lib/mime.c:1798-1801`).
        let first = scratch_file("nest_a.txt", b"alpha\n");
        let second = scratch_file("nest_b.dat", b"beta\n");
        let first_text = crate::util::path_bytes(first.as_path());
        let second_text = crate::util::path_bytes(second.as_path());

        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"files")),
                    FormOption::File(Some(first_text)),
                    FormOption::ContentType(Some(b"m/f")),
                    FormOption::File(Some(second_text)),
                ]
            ),
            FormCode::Ok
        );

        let toppart = tree(&form, 0);
        let outer = toppart.subparts().expect("the form multipart");
        assert_eq!(outer.len(), 1, "one form field, one outer part");
        let intermediate = outer.part(0).expect("the intermediate part");

        // The name is on the intermediate part, not on the children.
        assert_eq!(intermediate.name(), Some(&b"files"[..]));
        let generated = headers(intermediate);
        assert_eq!(
            generated[0],
            "Content-Disposition: form-data; name=\"files\""
        );

        // Its own type is `multipart/mixed` with its OWN boundary, which is
        // not the outer one.
        let nested = intermediate.subparts().expect("a nested multipart");
        assert_ne!(nested.boundary(), outer.boundary());
        let nested_text = String::from_utf8_lossy(nested.boundary());
        assert_eq!(
            generated[1],
            format!("Content-Type: multipart/mixed; boundary={nested_text}")
        );

        // Two children, each with its own type: the first explicit, the second
        // inherited from `prevtype` because `.dat` is not in curl's table.
        assert_eq!(nested.len(), 2);
        for (index, expected) in [(0_usize, "m/f"), (1, "m/f")] {
            let child = nested.part(index).expect("a child");
            let generated = headers(child);
            assert!(
                generated[0].starts_with("Content-Disposition: attachment;"),
                "children of a multipart/mixed get `attachment`, not \
                 `form-data`: {generated:?}"
            );
            // `; name="` rather than `name=`, because `filename="` ends in
            // exactly those five characters and would match either way.
            assert!(
                !generated[0].contains("; name=\""),
                "the field name belongs to the intermediate part only: \
                 {generated:?}"
            );
            assert!(
                generated[0].contains("; filename=\""),
                "each child advertises its own file: {generated:?}"
            );
            assert_eq!(generated[1], format!("Content-Type: {expected}"));
        }

        // And end to end: both bodies, in order, inside the nested boundary.
        let bytes = serialize(&form, 0).expect("serialises");
        let text = String::from_utf8_lossy(&bytes).into_owned();
        let alpha = text.find("alpha\n").expect("the first body");
        let beta = text.find("beta\n").expect("the second body");
        assert!(alpha < beta, "part order is observable");

        std::fs::remove_file(&first).expect("scratch file removed");
        std::fs::remove_file(&second).expect("scratch file removed");
    }

    #[test]
    fn the_generator_is_used_in_the_c_order() {
        // The outer multipart is created first (`:732`) and one nested
        // multipart follows per field with a `more` chain, in field order
        // (`:750`). With a deterministic generator that order fixes which
        // boundary each multipart gets, and a boundary is wire bytes -- so the
        // order is part of the contract, not an implementation detail.
        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"plain")),
                    FormOption::CopyContents(Some(b"v")),
                ]
            ),
            FormCode::Ok
        );

        let toppart = tree(&form, 0);
        let outer = toppart.subparts().expect("the form multipart");
        assert_eq!(
            String::from_utf8_lossy(outer.boundary()),
            boundary(SEED_ZERO_TAIL),
            "the outer multipart draws first"
        );
    }

    // --- callback parts ----------------------------------------------------

    #[test]
    fn a_stream_part_carries_its_reader_when_one_was_supplied() {
        // `curl_mime_data_cb(part, clen, fread_func, NULL, NULL, post->userp)`
        // (`:816-817`) with a real `fread_func`, which is what `lib/http.c`
        // passes.
        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"n")),
                    FormOption::Stream(Some(Box::new(FixedReader::new(5)))),
                    FormOption::ContentsLength(5),
                ]
            ),
            FormCode::Ok
        );
        let entry = form.entry(0).expect("one entry");
        assert!(entry.flags().callback);
        assert!(entry.reader().is_some());

        let mut toppart = build(&form, 0, StreamPolicy::Available)
            .expect("the bridge succeeds");
        let mut out = Vec::new();
        let mut buffer = [0_u8; 512];
        loop {
            match toppart.read(&mut buffer) {
                ReadStatus::Bytes(count) => {
                    out.extend_from_slice(&buffer[..count]);
                }
                ReadStatus::Eof => break,
                other => panic!("unexpected status {other:?}"),
            }
        }
        assert!(String::from_utf8_lossy(&out).contains("\r\n\r\nzzzzz\r\n--"));
    }

    #[test]
    fn a_stream_part_is_bodiless_when_no_read_function_was_supplied() {
        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"n")),
                    FormOption::Stream(Some(Box::new(FixedReader::new(5)))),
                    FormOption::ContentsLength(5),
                ]
            ),
            FormCode::Ok
        );
        let bytes = serialize(&form, 0).expect("serialises");
        let b = boundary(SEED_ZERO_TAIL);
        assert_eq!(
            String::from_utf8_lossy(&bytes),
            [
                format!("Content-Type: multipart/form-data; boundary={b}\r\n"),
                "\r\n".to_owned(),
                format!("--{b}\r\n"),
                "Content-Disposition: form-data; name=\"n\"\r\n".to_owned(),
                "\r\n".to_owned(),
                format!("\r\n--{b}--\r\n"),
            ]
            .concat()
        );
    }

    #[test]
    fn a_stream_with_no_length_leaves_the_body_size_unknown() {
        // `if(!clen) clen = -1;` (`:814-815`). An unknown length stays
        // unknown, propagates through the enclosing multipart and is what
        // makes the transfer layer choose chunked framing over a
        // `Content-Length`. Nothing is inferred.
        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"n")),
                    FormOption::Stream(Some(Box::new(FixedReader::new(5)))),
                ]
            ),
            FormCode::Ok
        );
        assert_eq!(form.entry(0).expect("one entry").content_length(), 0);

        let toppart = build(&form, 0, StreamPolicy::Available)
            .expect("the bridge succeeds");
        assert_eq!(
            toppart.content_size(),
            None,
            "unknown propagates up through multipart_size"
        );

        // With a length it is known, and the enclosing size is computable.
        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"n")),
                    FormOption::Stream(Some(Box::new(FixedReader::new(5)))),
                    FormOption::ContentLen(5),
                ]
            ),
            FormCode::Ok
        );
        let toppart = build(&form, 0, StreamPolicy::Available)
            .expect("the bridge succeeds");
        assert!(toppart.content_size().is_some());
    }

    // --- form_get: error mapping -------------------------------------------

    #[test]
    fn form_get_without_a_callback_is_bad_function_argument() {
        // "Validate callback is provided" (`:633-635`): `return
        // (int)CURLE_BAD_FUNCTION_ARGUMENT;`, before anything else happens.
        let form = two_field_form();
        let mut rng = TestRng::from_seed(0);
        assert_eq!(
            form_get(&form, &mut rng, None),
            Err(CURLcode::BadFunctionArgument)
        );
        assert_eq!(CURLcode::BadFunctionArgument as i32, 43);

        // The check comes first for the system-generator entry point too, so a
        // null callback is reported whatever the platform's entropy source
        // does.
        assert_eq!(
            form_get_with_system_rng(&form, None),
            Err(CURLcode::BadFunctionArgument)
        );

        // An empty form does not change the answer.
        let empty = FormList::new();
        let mut rng = TestRng::from_seed(0);
        assert_eq!(
            form_get(&empty, &mut rng, None),
            Err(CURLcode::BadFunctionArgument)
        );
    }

    #[test]
    fn a_short_count_from_the_callback_is_a_read_error() {
        // `append(arg, buffer, nread) != nread` (`:650`) -- the callback's
        // contract is to consume the whole chunk.
        let form = two_field_form();
        let mut rng = TestRng::from_seed(0);
        let mut seen = 0_usize;
        let result = {
            let mut append = |chunk: &[u8]| {
                seen += chunk.len();
                // One byte short, whatever the chunk size.
                chunk.len().saturating_sub(1)
            };
            form_get(&form, &mut rng, Some(&mut append))
        };
        assert_eq!(result, Err(CURLcode::ReadError));
        assert!(seen > 0, "the callback did run before it short-changed us");

        // Returning zero is short too.
        let mut rng = TestRng::from_seed(0);
        let result = {
            let mut append = |_chunk: &[u8]| 0_usize;
            form_get(&form, &mut rng, Some(&mut append))
        };
        assert_eq!(result, Err(CURLcode::ReadError));
    }

    #[test]
    fn the_failure_classification_distinguishes_only_the_abort() {
        // `result = CURLE_READ_ERROR; if(nread == CURL_READFUNC_ABORT) result
        // = CURLE_ABORTED_BY_CALLBACK;` (`:651-653`).
        assert_eq!(
            formget_failure(ReadStatus::Abort),
            CURLcode::AbortedByCallback
        );
        assert_eq!(CURLcode::AbortedByCallback as i32, 42);

        for status in [
            // A real byte count the callback failed to consume in full.
            ReadStatus::Bytes(7),
            ReadStatus::ReadError,
            ReadStatus::Pause,
            ReadStatus::StopFilling,
            // Named for exhaustiveness; the loop breaks on it first.
            ReadStatus::Eof,
        ] {
            assert_eq!(
                formget_failure(status),
                CURLcode::ReadError,
                "{status:?} is a plain read error"
            );
        }
        assert_eq!(CURLcode::ReadError as i32, 26);
    }

    #[test]
    fn a_reader_that_aborts_reaches_the_abort_status() {
        // The other half of the classification above: a source that signals
        // `CURL_READFUNC_ABORT` propagates out of `MimePart::read` as
        // `ReadStatus::Abort`, which `formget_failure` then maps to
        // `CURLE_ABORTED_BY_CALLBACK`.
        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"n")),
                    FormOption::Stream(Some(Box::new(AbortingReader))),
                    FormOption::ContentLen(4),
                ]
            ),
            FormCode::Ok
        );
        let mut toppart = build(&form, 0, StreamPolicy::Available)
            .expect("the bridge succeeds");
        let mut buffer = [0_u8; 512];
        let mut status = toppart.read(&mut buffer);
        // The headers come out first; the abort arrives when the body is
        // reached.
        while let ReadStatus::Bytes(_) = status {
            status = toppart.read(&mut buffer);
        }
        assert_eq!(status, ReadStatus::Abort);
        assert_eq!(
            formget_failure(status),
            CURLcode::AbortedByCallback,
            "which is the code form_get would report"
        );
    }

    // --- form_get: chunking and escaping -----------------------------------

    #[test]
    fn chunking_is_arbitrary_but_the_concatenation_is_exact() {
        // `curl_formget` may deliver the body in any number of pieces; only the
        // concatenation is fixed. Driving the same tree through buffers of 1,
        // 2, 3, 7 and 8192 bytes must produce identical bytes.
        let form = two_field_form();
        let reference = serialize(&form, 0).expect("serialises");
        assert_eq!(reference.len(), 354);

        for size in [1_usize, 2, 3, 7, 64, FORMGET_BUFFER_SIZE] {
            let actual = serialize_with_buffer(&form, 0, size)
                .expect("serialises at every buffer size");
            assert_eq!(
                actual, reference,
                "a {size}-byte buffer must produce identical bytes"
            );
        }

        // And the chunk count really does vary, so the assertion above is not
        // vacuously comparing one arrangement with itself.
        let mut chunks = 0_usize;
        let mut rng = TestRng::from_seed(0);
        let result = {
            let mut append = |chunk: &[u8]| {
                chunks += 1;
                chunk.len()
            };
            form_get(&form, &mut rng, Some(&mut append))
        };
        assert_eq!(result, Ok(()));
        assert!(chunks >= 1);
    }

    #[test]
    fn form_get_uses_the_form_escape_table() {
        // `escape_string` (`lib/mime.c:212-222`) chooses between two tables,
        // and `curl_formget` cannot reach the other one: it passes a null easy
        // handle (`:638`, `:640`), so `data && data->set.mime_formescape` is
        // false and the FORM table applies -- `"` becomes `%22`, CR becomes
        // `%0D`, LF becomes `%0A`, and a backslash is passed through
        // literally. That state is `MimeOptions::default()`, which is what
        // `form_get` passes.
        //
        // Written with escapes rather than as raw strings, because
        // `source_policy::no_raw_string_literal_defeats_the_stripper` in
        // `curl-rs-lib/src/lib.rs` forbids `r"..."` anywhere under this
        // crate's `src/`: the keyword scans that police the zero-`unsafe`
        // invariant strip ordinary string literals and do not lex raw ones, so
        // a raw string here would quietly cost them coverage.
        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    // `a"b\c`
                    FormOption::CopyName(Some(b"a\"b\\c")),
                    FormOption::CopyContents(Some(b"v")),
                ]
            ),
            FormCode::Ok
        );
        let bytes = serialize(&form, 0).expect("serialises");
        let text = String::from_utf8_lossy(&bytes).into_owned();
        assert!(
            // `Content-Disposition: form-data; name="a%22b\c"`
            text.contains("Content-Disposition: form-data; name=\"a%22b\\c\""),
            "the quote escapes and the backslash does not: {text}"
        );

        // The two line endings, which must not reach a header as raw bytes.
        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"a\r\nb")),
                    FormOption::CopyContents(Some(b"v")),
                ]
            ),
            FormCode::Ok
        );
        let bytes = serialize(&form, 0).expect("serialises");
        let text = String::from_utf8_lossy(&bytes).into_owned();
        assert!(text.contains("name=\"a%0D%0Ab\""), "{text}");
    }

    // --- ownership and all-or-nothing --------------------------------------

    #[test]
    fn the_free_plan_transcribes_the_conditional_frees() {
        // `lib/formdata.c:679-686`. `curl_formfree` frees a name only when
        // `HTTPPOST_PTRNAME` is clear and contents only when none of
        // `HTTPPOST_PTRCONTENTS`, `HTTPPOST_BUFFER` or `HTTPPOST_CALLBACK` is
        // set, because otherwise the memory is the caller's -- who may reuse or
        // free it after `curl_formfree` returns. That is observable, and it is
        // the information `curl-rs-ffi` needs on its side of the boundary.

        // Copied name and copied contents: both this library's.
        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"n")),
                    FormOption::CopyContents(Some(b"v")),
                    FormOption::ContentType(Some(b"a/b")),
                    FormOption::FileName(Some(b"shown")),
                ]
            ),
            FormCode::Ok
        );
        assert_eq!(
            form.entry(0).expect("one entry").free_plan(),
            FreePlan {
                name: Ownership::Owned,
                contents: Ownership::Owned,
                contenttype: Ownership::Owned,
                showfilename: Ownership::Owned,
            }
        );

        // Borrowed name, borrowed contents: the two `PTR*` options.
        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::PtrName(Some(b"n")),
                    FormOption::PtrContents(Some(b"v")),
                ]
            ),
            FormCode::Ok
        );
        let plan = form.entry(0).expect("one entry").free_plan();
        assert_eq!(plan.name, Ownership::Borrowed);
        assert_eq!(plan.contents, Ownership::Borrowed);
        // The two unconditional frees stay unconditional even here, because
        // `CURLFORM_CONTENTTYPE` and `CURLFORM_FILENAME` always copy.
        assert_eq!(plan.contenttype, Ownership::Owned);
        assert_eq!(plan.showfilename, Ownership::Owned);

        // A buffer part and a callback part reach the same contents branch
        // through the other two flags.
        for options in [
            vec![
                FormOption::CopyName(Some(b"n")),
                FormOption::BufferPtr(Some(b"bytes")),
            ],
            vec![
                FormOption::CopyName(Some(b"n")),
                FormOption::Stream(Some(Box::new(FixedReader::new(2)))),
            ],
        ] {
            let mut form = FormList::new();
            assert_eq!(form_add(&mut form, options), FormCode::Ok);
            assert_eq!(
                form.entry(0).expect("one entry").free_plan().contents,
                Ownership::Borrowed
            );
        }

        // And the expression of it in the type system: a copied name is owned
        // outright, so it survives a caller that drops its own buffer.
        let copied = {
            let scratch = b"transient".to_vec();
            let mut form = FormList::new();
            assert_eq!(
                form_add(
                    &mut form,
                    vec![
                        FormOption::CopyName(Some(&scratch)),
                        FormOption::CopyContents(Some(b"v")),
                    ]
                ),
                FormCode::Ok
            );
            form.entry(0).expect("one entry").name().map(<[u8]>::to_vec)
        };
        assert_eq!(copied, Some(b"transient".to_vec()));
    }

    #[test]
    fn form_free_releases_a_whole_form() {
        // `curl_formfree` (`:665-689`) walks `next`, recurses into `more` and
        // performs six conditional frees. Taking the form by value is the whole
        // implementation here; this asserts the entry point exists, consumes
        // its argument and leaves nothing behind that the compiler would
        // complain about.
        // First, a form that fails: `form_free` must accept an empty list, as
        // `curl_formfree(NULL)` returns immediately (`:669-671`).
        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"files")),
                    FormOption::CopyName(Some(b"twice")),
                ]
            ),
            FormCode::OptionTwice
        );
        assert!(form.is_empty());
        form_free(form);

        // A form that DOES commit, with children and a boxed reader in it.
        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"files")),
                    FormOption::File(Some(b"a.txt")),
                    FormOption::File(Some(b"b.txt")),
                ]
            ),
            FormCode::Ok
        );
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"stream")),
                    FormOption::Stream(Some(Box::new(FixedReader::new(1)))),
                ]
            ),
            FormCode::Ok
        );
        assert_eq!(form.len(), 2);
        assert_eq!(form.entry(0).expect("first").more().len(), 1);
        form_free(form);
    }

    #[test]
    fn the_stream_twice_check_is_on_the_reader_not_the_value() {
        // `if(curr->userp) retval = CURL_FORMADD_OPTION_TWICE;` (`:495-496`)
        // tests the CONTEXT, not the value -- even though the same arm then
        // writes the value at `:504`. So a `CURLFORM_STREAM` lands cleanly on a
        // node that already has a value from `CURLFORM_FILE`, replacing it, and
        // the resulting part reports BOTH flags.
        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"files")),
                    FormOption::File(Some(b"a.txt")),
                    FormOption::File(Some(b"b.txt")),
                    FormOption::Stream(Some(Box::new(FixedReader::new(1)))),
                ]
            ),
            FormCode::Ok
        );
        let entry = form.entry(0).expect("one entry");
        let spawned = &entry.more()[0];
        assert!(spawned.flags().filename, "AddFormInfo set it");
        assert!(spawned.flags().callback, "CURLFORM_STREAM set it at :494");
        assert!(spawned.reader().is_some());
        // The value slot was overwritten by the placeholder, so the spawned
        // node no longer names `b.txt`. The bridge does not care: `post->flags`
        // governs the content branch, and the TOP entry's `filename` flag sends
        // both children down the file path.
        assert_eq!(
            spawned.contents(),
            Some(STREAM_VALUE_PLACEHOLDER),
            "`:504` replaces the value with the context pointer"
        );
        form_free(form);
    }

    #[test]
    fn form_add_is_all_or_nothing() {
        // `:569-598`. On failure the accumulator chain's fields are released,
        // its nodes are released, and the partially built chain is released by
        // `free_chain` instead of being spliced on. The caller's list is left
        // COMPLETELY unchanged, and a caller may retry.
        let mut form = two_field_form();
        assert_eq!(form.len(), 2);
        let before = serialize(&form, 0).expect("serialises");

        // A list that fails at its LAST option, after several succeeded.
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"third")),
                    FormOption::CopyContents(Some(b"value")),
                    FormOption::ContentType(Some(b"a/b")),
                    FormOption::CopyName(Some(b"again")),
                ]
            ),
            FormCode::OptionTwice
        );
        assert_eq!(form.len(), 2, "nothing was appended");
        assert_eq!(
            serialize(&form, 0).expect("serialises"),
            before,
            "and nothing was changed"
        );

        // A list that fails in `FormAddCheck` rather than at option time, which
        // is the case where the C has built a partial `curl_httppost` chain and
        // has to unwind it.
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"third")),
                    FormOption::File(Some(b"f.txt")),
                    FormOption::ContentsLength(4),
                ]
            ),
            FormCode::Incomplete
        );
        assert_eq!(form.len(), 2);
        assert_eq!(serialize(&form, 0).expect("serialises"), before);

        // And the retry succeeds, appending exactly one entry at the tail.
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"third")),
                    FormOption::CopyContents(Some(b"value")),
                ]
            ),
            FormCode::Ok
        );
        assert_eq!(form.len(), 3);
        assert_eq!(
            form.last().expect("a tail").name_bytes(),
            Some(b"third".as_slice())
        );
    }

    // --- the stdin pseudo-filename -----------------------------------------

    #[test]
    fn the_dash_pseudo_filename_installs_a_reader_of_unknown_length() {
        // `if(!strcmp(file->contents, "-")) result = curl_mime_data_cb(part,
        // (curl_off_t)-1, (curl_read_callback)fread, curlx_fseek, NULL, (void
        // *)stdin);` (`:785-797`). Standard input is not stat'd, so this needs
        // no file -- and it must NOT be confused with an ordinary path, which
        // would fail with `CURLE_READ_ERROR` for a file named `-`.
        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"n")),
                    FormOption::File(Some(b"-")),
                ]
            ),
            FormCode::Ok
        );
        assert_eq!(
            form.entry(0).expect("one entry").contents(),
            Some(STDIN_PSEUDO_FILENAME)
        );

        let toppart = tree(&form, 0);
        let part = toppart
            .subparts()
            .expect("a multipart")
            .part(0)
            .expect("one part");
        // The length is unknown, which propagates and makes the transfer layer
        // choose chunked framing.
        assert_eq!(toppart.content_size(), None);
        // No base name was derived, because `set_file` was never called.
        assert_eq!(part.filename(), None);
        // The type fell through to the default: `-` has no suffix in curl's
        // table and there is no previous part to inherit from.
        assert_eq!(
            headers(part)[1],
            format!("Content-Type: {FILE_CONTENTTYPE_DEFAULT}")
        );
    }

    #[test]
    fn the_stdin_reader_cannot_seek_and_duplicates_to_itself() {
        // The C installs a real `fseek`, which succeeds only when standard
        // input happens to be a redirected regular file; `std::io::Stdin` does
        // not implement `Seek` at all, so `CantSeek` -- the value
        // `mime_part_rewind` derives from a failed `fseek`
        // (`lib/mime.c:983-985`) -- is the honest and already-reachable answer.
        let mut reader = StdinReader;
        assert_eq!(reader.seek(0, SeekWhence::Set), SeekResult::CantSeek);
        assert_eq!(reader.seek(0, SeekWhence::End), SeekResult::CantSeek);
        // An empty buffer is end of data, matching `fread(buf, 1, 0, stdin)`.
        // `StopFilling` would be worse than merely different: `MimePart::read`
        // retries it indefinitely.
        assert_eq!(reader.read(&mut []), ReadStatus::Eof);
        // Duplication shares the one standard input there is, exactly as the C
        // shares its `FILE *` (`lib/mime.c:1122-1123`).
        let copy = reader.duplicate();
        assert_eq!(
            format!("{copy:?}"),
            "StdinReader",
            "the duplicate is the same kind of reader"
        );
    }

    // --- the module's own invariants ---------------------------------------

    #[test]
    fn the_constants_are_the_c_values() {
        assert_eq!(FORMGET_BUFFER_SIZE, 8192, "lib/formdata.c:644");
        assert_eq!(
            FORMGET_CONTENT_TYPE, "multipart/form-data",
            "lib/formdata.c:640"
        );
        assert_eq!(STDIN_PSEUDO_FILENAME, b"-", "lib/formdata.c:785");
        assert!(
            STREAM_VALUE_PLACEHOLDER.is_empty(),
            "present but meaningless -- lib/formdata.c:501-504"
        );
    }

    #[test]
    fn effective_length_resolves_zero_and_clamps_an_overrun() {
        // "Zero means measure it" -- `FormInfoCopyField`'s `if(!len) len =
        // strlen(value);` (`:127-128`) and `AddHttpPost`'s equivalent
        // (`:64-65`).
        assert_eq!(effective_usize_len(0, 7), 7);
        assert_eq!(effective_usize_len(3, 7), 3);
        assert_eq!(effective_usize_len(7, 7), 7);
        // An overrun is an out-of-bounds read in C and is clamped here.
        assert_eq!(effective_usize_len(9, 7), 7);
        assert_eq!(effective_usize_len(usize::MAX, 7), 7);
        // A zero-length subject with no request is still zero.
        assert_eq!(effective_usize_len(0, 0), 0);
        assert_eq!(effective_usize_len(5, 0), 0);
    }

    #[test]
    fn the_form_code_predicate_agrees_with_the_variants() {
        assert!(FormCode::Ok.is_ok());
        for code in [
            FormCode::Memory,
            FormCode::OptionTwice,
            FormCode::Null,
            FormCode::UnknownOption,
            FormCode::Incomplete,
            FormCode::IllegalArray,
            FormCode::Disabled,
        ] {
            assert!(!code.is_ok(), "{code:?} is not success");
            assert_ne!(code, FormCode::Ok);
        }
    }

    #[test]
    fn a_stream_policy_is_two_states_and_nothing_else() {
        // The surviving half of `Curl_getformdata`'s `curl_read_callback
        // fread_func` argument (`lib/formdata.h:52`).
        assert_ne!(StreamPolicy::Available, StreamPolicy::Unavailable);
        let form = two_field_form();
        // Neither policy changes a form with no callback part.
        let with = build(&form, 0, StreamPolicy::Available).expect("builds");
        let without =
            build(&form, 0, StreamPolicy::Unavailable).expect("builds");
        assert_eq!(with.content_size(), without.content_size());
    }

    /// A form field's value, buffer and filename cannot reach a formatted form.
    ///
    /// A multipart body has no header name to classify against, so every
    /// caller-supplied byte is redacted unconditionally and this asserts that
    /// for each of the three routes a value can arrive by.
    #[test]
    fn form_contents_cannot_reach_any_formatted_representation() {
        const PASSWORD: &str = "hunter2-not-in-a-log";
        const BUFFER: &str = "private-file-bytes";
        const FILENAME: &str = "/home/alice/secrets.txt";

        let mut form = FormList::new();
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"password")),
                    FormOption::CopyContents(Some(PASSWORD.as_bytes())),
                ]
            ),
            FormCode::Ok
        );
        assert_eq!(
            form_add(
                &mut form,
                vec![
                    FormOption::CopyName(Some(b"upload")),
                    FormOption::BufferPtr(Some(BUFFER.as_bytes())),
                    FormOption::BufferLength(BUFFER.len()),
                    FormOption::Buffer(Some(FILENAME.as_bytes())),
                ]
            ),
            FormCode::Ok
        );

        let text = format!("{form:?}");
        for secret in [PASSWORD, BUFFER, FILENAME] {
            assert!(!text.contains(secret), "{secret} leaked: {text}");
        }
        // Lengths survive, so the assembly is still debuggable.
        assert!(
            text.contains(&format!("<redacted, {} bytes>", PASSWORD.len())),
            "{text}"
        );

        // The option enum, which is the argument every diagnostic reports.
        let option = FormOption::CopyContents(Some(PASSWORD.as_bytes()));
        let rendered = format!("{option:?}");
        assert!(!rendered.contains(PASSWORD), "{rendered}");
        assert!(
            rendered.starts_with("CopyContents(<redacted,"),
            "{rendered}"
        );

        // An absent option stays distinct from an empty one.
        assert_eq!(
            format!("{:?}", FormOption::CopyContents(None)),
            "CopyContents(None)"
        );
        assert_eq!(
            format!("{:?}", FormOption::CopyContents(Some(b""))),
            "CopyContents(<redacted, 0 bytes>)"
        );
    }
}
