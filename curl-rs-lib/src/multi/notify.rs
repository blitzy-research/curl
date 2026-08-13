//**************************************************************************
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
//**************************************************************************/
// THE LICENCE BANNER ABOVE -- 23 lines, measured and not rounded.
//
// `lib/multi_ntfy.c:1-23` is this module's primary C source and its banner is
// exactly 23 lines: the rule, five lines of ASCII art with the `Project`
// label on the second, the copyright line, the three-line COPYING notice
// ending `https://curl.se/docs/copyright.html.`, the three-line
// use/copy/modify grant, the two-line "AS IS" disclaimer, the licence
// identifier and the closing rule, each separated by a bare comment line.
// Longer banners exist elsewhere in the C tree -- `lib/vtls/rustls.c` carries
// extra copyright lines -- and none of them is the exemplar for this file.
//
// Two renderings of those same 23 lines exist in this crate, and the
// difference is one asterisk on the first and last line. This file uses the
// one its own directory uses: `src/multi/mod.rs:1-23` and
// `src/multi/state.rs:1-23` are byte-identical to the block above, so the
// three files in `src/multi/` agree. `src/error.rs` and `src/util/*` use the
// other rendering. Both satisfy `reuse`, which reads line 21 and nothing
// else about the shape, and a reviewer comparing two files side by side in
// one directory sees consistency rather than a transcription argument.

//! The completion-message queue and the notification subsystem.
//!
//! # What lives here and what lives in `curl-rs-ffi`
//!
//! `curl_multi_info_read` returns `CURLMsg *`, and `struct CURLMsg`
//! (`include/curl/multi.h:97-105`) is **layout-visible**: it holds a
//! `CURL *easy_handle` and a union whose `CURLcode result` member every multi
//! example reads directly. A raw pointer and a union are exactly what this
//! crate does not hold, so the boundary falls here:
//!
//! * **This module** owns the *behaviour*: the queue and its ordering, the
//!   notification store, the enabled set, the failure latch, and the pure
//!   mapping behind `curl_multi_get_offt`. Its message type is
//!   [`CompletionMessage`], which names the transfer by its `mid` rather than
//!   by a pointer.
//! * **`curl-rs-ffi/src/ffi/handle.rs`** owns the `#[repr(C)]` `CURLMsg` and
//!   its `CURLMsg_data` union, and it already carries the mandatory layout
//!   assertion -- size 24, alignment 8, and field offsets 0, 8 and 16 on a
//!   64-bit target (`curl-rs-ffi/src/ffi/handle.rs:94-170`). That assertion is
//!   written, it passes, and it is not repeated here: a second `#[repr(C)]`
//!   declaration of the same name would make cbindgen emit a second,
//!   conflicting C declaration and fail all 129 `docs/examples` programs.
//!   `curl-rs-ffi/src/ffi/types.rs` likewise owns the C-named `CURLMSG` and
//!   `CURLMinfo_offt` enumerations and the `curl_notify_callback` typedef.
//!
//! # `u32` rather than a C width, deliberately
//!
//! `curl_multi_notify_enable` takes an `unsigned int`, and this module's
//! constants and parameters are `u32`. That is not an approximation: the
//! width in `include/curl/multi.h` is fixed by curl's ABI rather than by the
//! compiler, so `u32` records the contract while `c_uint` would record a
//! platform. It is also enforced --
//! `c_scalar_types_appear_only_inside_the_ffi_island` in `src/lib.rs`
//! (`mod source_policy`) permits the C spellings only under
//! `curl-rs-lib/src/ffi/`, and `curl-rs-ffi` is where the conversion belongs.
//! The C entry in `mntfy_entry` is a `uint32_t` in any case
//! (`lib/multi_ntfy.c:33-36`), so the store below is a transcription.
//!
//! # The intrusive list, and why teardown order does not matter
//!
//! `util::llist` records the mapping -- `VecDeque<T>` is what replaced
//! `Curl_llist`, with no `LList` type to reach for -- so the queue below is a
//! `VecDeque<CompletionMessage>`, whose `push_back`/`pop_front` pair is the
//! exact counterpart of the C's append-at-tail (`lib/multi.c:226`) and
//! take-from-head (`:2957`).
//!
//! One divergence follows and is **unobservable**, which is the conclusion
//! rather than the question. `Curl_llist_destroy` removes from the tail, so C
//! destructors run in reverse insertion order, whereas dropping a `VecDeque`
//! runs them front to back. It cannot matter here for two measured reasons:
//! this list is initialised with **no destructor at all**
//! (`Curl_llist_init(&multi->msglist, NULL)`, `lib/multi.c:252`), and
//! [`CompletionMessage`] is three plain `Copy` fields with no `Drop`. Nothing
//! observes the order. `util::llist::dispose_tail_first` exists for a
//! consumer that ever does need the C order; this module does not, and does
//! not call it.

use std::collections::VecDeque;
use std::fmt;

use crate::error::{CURLMcode, CURLcode};
use crate::util::uint_bset::Uint32Bset;

// The message vocabulary

/// What a completion message means: `CURLMSG`.
///
/// Transcribed from `include/curl/multi.h:90-95`:
///
/// ```c
/// typedef enum {
///   CURLMSG_NONE, /* first, not used */
///   CURLMSG_DONE, /* This easy handle has completed. 'result' contains
///                    the CURLcode of the transfer */
///   CURLMSG_LAST  /* last, not used */
/// } CURLMSG;
/// ```
///
/// `#[repr(i32)]` because the C enumeration is a struct field of `CURLMsg`
/// and a C `enum` there is `int`-sized on all four targets of the mandated
/// matrix. The C-shaped, C-named counterpart that cbindgen reads is
/// `curl-rs-ffi/src/ffi/types.rs`.
#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CurlMsgType {
    /// `CURLMSG_NONE` = 0 -- first, not used.
    None = 0,
    /// `CURLMSG_DONE` = 1 -- this easy handle has completed. `result`
    /// contains the `CURLcode` of the transfer.
    ///
    /// The only value curl ever posts: `handle_completed` writes
    /// `msg->extmsg.msg = CURLMSG_DONE` unconditionally
    /// (`lib/multi.c:2410`).
    Done = 1,
    /// `CURLMSG_LAST` = 2 -- last, not used.
    Last = 2,
}

impl CurlMsgType {
    /// Every member, in declaration order, which is also ascending order.
    ///
    /// Exhaustive by construction rather than by discipline: adding a member
    /// without extending this slice leaves [`Self::from_i32`]'s `match`
    /// non-exhaustive and fails the build.
    pub const VARIANTS: &'static [Self] = &[Self::None, Self::Done, Self::Last];

    /// The pinned integer, as a C consumer sees it.
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
    }

    /// The C spelling, for diagnostics and for the ABI crate's bridge.
    #[must_use]
    pub const fn c_name(self) -> &'static str {
        match self {
            Self::None => "CURLMSG_NONE",
            Self::Done => "CURLMSG_DONE",
            Self::Last => "CURLMSG_LAST",
        }
    }

    /// Interprets a raw integer, yielding [`None`](Option::None) when it names
    /// no member.
    ///
    /// The inbound half of the ABI boundary's validation. `CURLMSG_NONE` and
    /// `CURLMSG_LAST` are recognised even though curl never posts them,
    /// because they are part of the enumeration a consumer may switch on.
    #[must_use]
    pub const fn from_i32(raw: i32) -> Option<Self> {
        match raw {
            0 => Some(Self::None),
            1 => Some(Self::Done),
            2 => Some(Self::Last),
            _ => Option::None,
        }
    }
}

/// One completed transfer's result, awaiting collection.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[allow(dead_code)] // consumer: `super`'s `handle_completed` counterpart
pub struct CompletionMessage {
    /// What the message means. `lib/multi.c:2410`.
    pub which: CurlMsgType,
    /// The transfer it concerns, by `mid`. `lib/multi.c:2411` stores the
    /// pointer; `curl-rs-ffi` resolves this `mid` back to one.
    pub mid: u32,
    /// The transfer's result. `lib/multi.c:2412`.
    pub result: CURLcode,
}

impl CompletionMessage {
    /// A `CURLMSG_DONE` message for `mid` carrying `result`.
    ///
    /// The three assignments of `lib/multi.c:2410-2412` as one constructor,
    /// so the message type cannot be omitted at a call site.
    #[must_use]
    #[allow(dead_code)] // consumer: `super`'s `handle_completed` counterpart
    pub const fn done(mid: u32, result: CURLcode) -> Self {
        Self {
            which: CurlMsgType::Done,
            mid,
            result,
        }
    }
}

// The message queue

/// What [`MessageQueue::read`] hands back: the message and the count left.
///
/// The C returns the message as `CURLMsg *` and the count through an
/// out-parameter (`lib/multi.c:2943`, `:2964`). Pairing them in one value is
/// what makes the second impossible to forget, and the count is the part that
/// applications loop on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)] // consumer: `curl-rs-ffi`'s `curl_multi_info_read`
pub struct MessageRead {
    /// The message removed from the head of the queue.
    pub message: CompletionMessage,
    /// How many messages remain **after** that removal -- the C's
    /// `*msgs_in_queue` (`lib/multi.c:2964`), never the count before.
    pub msgs_in_queue: i32,
}

/// The queue of results from completed transfers: strict FIFO.
///
/// The ordering is not a choice. `multi_addmsg` appends at the **tail**
/// (`Curl_llist_append`, `lib/multi.c:226`) and `curl_multi_info_read` takes
/// the **head** (`Curl_llist_head`, `lib/multi.c:2957`), so messages are
/// delivered in completion order and [`VecDeque::push_back`] paired with
/// [`VecDeque::pop_front`] is the exact counterpart.
#[derive(Clone, Debug, Default)]
#[allow(dead_code)] // consumer: `super`'s multi handle
pub(crate) struct MessageQueue {
    /// Head at the front, tail at the back.
    messages: VecDeque<CompletionMessage>,
}

impl MessageQueue {
    /// An empty queue.
    ///
    /// `Curl_llist_init(&multi->msglist, NULL)` (`lib/multi.c:252`). The
    /// `NULL` is the destructor argument, and its absence is what makes the
    /// teardown-order divergence recorded in this module's documentation
    /// unobservable.
    #[must_use]
    #[allow(dead_code)] // consumer: `super`'s multi-handle constructor
    pub(crate) const fn new() -> Self {
        Self {
            messages: VecDeque::new(),
        }
    }

    /// How many messages are waiting.
    ///
    /// `Curl_llist_count(&multi->msglist)`. Constant time, which
    /// [`Self::read`]'s contract requires.
    #[must_use]
    #[allow(dead_code)] // consumer: `super`'s multi handle
    pub(crate) fn len(&self) -> usize {
        self.messages.len()
    }

    /// Whether no message is waiting.
    ///
    /// The C spells this `!Curl_llist_count(...)` at both of its decision
    /// points, `lib/multi.c:224` and `:2952`.
    #[must_use]
    #[allow(dead_code)] // consumer: `super`'s multi handle
    pub(crate) fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    /// Appends a message, reporting whether the empty-to-non-empty edge fired.
    ///
    /// ```c
    /// static void multi_addmsg(struct Curl_multi *multi,
    ///                          struct Curl_message *msg)
    /// {
    ///   if(!Curl_llist_count(&multi->msglist))
    ///     CURLM_NTFY(multi->admin, CURLMNOTIFY_INFO_READ);
    ///   Curl_llist_append(&multi->msglist, msg, &msg->list);
    /// }
    /// ```
    ///
    /// # Why the caller posts the notification rather than this method
    ///
    /// ```ignore
    /// if queue.push(message) {
    ///     notify.add(ADMIN_MID, CURLMNOTIFY_INFO_READ, tracer);
    /// }
    /// ```
    #[allow(dead_code)] // consumer: `super`'s `handle_completed` counterpart
    pub(crate) fn push(&mut self, message: CompletionMessage) -> bool {
        // Tested BEFORE the push, exactly as `lib/multi.c:224` tests before
        // `lib/multi.c:226` appends. Reordering these two lines would silently
        // disable the notification.
        let edge = self.messages.is_empty();
        self.messages.push_back(message);
        edge
    }

    /// Removes and returns the head message, with the count that remains.
    ///
    /// # Three things the C measures that are easy to get wrong
    ///
    /// * **`*msgs_in_queue = 0` is written first, before any validation**
    ///   (`lib/multi.c:2948`, commented "default to none"). A caller with a
    ///   bad handle still gets a zero written. Here that falls out of the
    ///   signature: `None` carries no count, and the ABI shim writes zero on
    ///   every path that does not produce a [`MessageRead`]. `curl-rs-ffi`
    ///   must write it **before** validating the handle, not after.
    /// * **The count is the number remaining AFTER the removal**
    ///   (`lib/multi.c:2964`), not before. Reading one message from a queue of
    ///   three must report `2`. Applications loop on the value.
    /// * **There is no distinct error return.** The C function returns
    ///   `CURLMsg *`, so `NULL` covers a bad handle, callback re-entrancy and
    ///   an empty queue alike (`lib/multi.c:2950-2952` and `:2968`). Two of
    ///   those three guards belong to the caller and are stated below.
    ///
    /// # The two guards this method does not perform
    ///
    /// * `GOOD_MULTI_HANDLE` is a magic-number check on a raw pointer
    ///   (`0x000bab1e`) and belongs to `curl-rs-ffi`, which is the only crate
    ///   holding the pointer.
    /// * `in_callback` is `struct Curl_multi`'s "true while executing a
    ///   callback" flag (`lib/multihandle.h:180`), set around the *application
    ///   socket and timer callbacks* and so owned by the multi handle. It is
    ///   deliberately **not** [`MultiNotify::in_callback`], which reproduces
    ///   the separate `in_ntfy_callback` flag of `lib/multihandle.h:181`. The
    ///   caller must check its own flag before calling this.
    #[allow(dead_code)] // consumer: `curl-rs-ffi`'s `curl_multi_info_read`
    pub(crate) fn read(&mut self) -> Option<MessageRead> {
        // `pop_front` is the `Curl_llist_head` / `Curl_node_elem` /
        // `Curl_node_remove` triple of `lib/multi.c:2957-2962` in one step,
        // and it is also the emptiness guard of `:2952`: an empty queue
        // yields `None`, which the shim renders as the same `NULL` a bad
        // handle produces.
        let message = self.messages.pop_front()?;

        // Read AFTER the removal. `curlx_uztosi` is the C's checked narrowing
        // of a `size_t` to the `int` the out-parameter has
        // (`lib/multi.c:2964`); `i32::try_from` is the same narrowing, and the
        // saturation can only be reached with more than 2^31 - 1 messages
        // outstanding, which needs that many concurrently completed transfers.
        let remaining = self.messages.len();
        let msgs_in_queue = i32::try_from(remaining).unwrap_or(i32::MAX);

        Some(MessageRead {
            message,
            msgs_in_queue,
        })
    }

    /// Removes the first message posted by `mid`, reporting whether one went.
    ///
    /// Reproduces the purge inside `curl_multi_remove_handle`
    /// (`lib/multi.c:855-865`), whose comment is "make sure there is no
    /// pending message in the queue sent from this easy handle":
    ///
    /// ```c
    /// for(e = Curl_llist_head(&multi->msglist); e; e = Curl_node_next(e)) {
    ///   struct Curl_message *msg = Curl_node_elem(e);
    ///   if(msg->extmsg.easy_handle == data) {
    ///     Curl_node_remove(e);
    ///     /* there can only be one from this specific handle */
    ///     break;
    ///   }
    /// }
    /// ```
    #[allow(dead_code)] // consumer: `super`'s `curl_multi_remove_handle`
    pub(crate) fn remove_first_for(&mut self, mid: u32) -> bool {
        let found = self.messages.iter().position(|msg| msg.mid == mid);
        match found {
            Some(at) => {
                // `VecDeque::remove` preserves the order of everything else,
                // which `Curl_node_remove` also does: unlinking one node
                // leaves the rest of the chain in place.
                self.messages.remove(at);
                true
            }
            None => false,
        }
    }
}

// The notification vocabulary

/// `CURLMNOTIFY_INFO_READ` = 0: a result became available to read.
pub const CURLMNOTIFY_INFO_READ: u32 = 0;

/// `CURLMNOTIFY_EASY_DONE` = 1: one transfer reached its terminal state.
pub const CURLMNOTIFY_EASY_DONE: u32 = 1;

/// How many notification types exist: `CURLMNOTIFY_EASY_DONE + 1` = 2.
pub const CURLMNOTIFY_COUNT: u32 = CURLMNOTIFY_EASY_DONE + 1;

/// The `mid` the admin handle holds: 0.
///
/// The multi handle *assigns* it; this module only *interprets* it, and the
/// interpretation is why the constant is declared here. Two sites depend on
/// the value:
///
/// * `multi_addmsg` attributes `CURLMNOTIFY_INFO_READ` to the admin handle
///   rather than to the transfer that completed (`lib/multi.c:225`).
/// * Dispatch resolves `e->mid ? Curl_multi_get_easy(multi, e->mid) :
///   multi->admin` (`lib/multi_ntfy.c:109`), so a recorded `mid` of 0 comes
///   back out as the admin handle.
pub const ADMIN_MID: u32 = 0;

/// `CURL_MNTFY_CHUNK_SIZE` = 128: entries per chunk in the C's store.
pub const CURL_MNTFY_CHUNK_SIZE: usize = 128;

/// `CURLMinfo_offt`: which numeric value `curl_multi_get_offt` should return.
#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CurlMInfoOfft {
    /// `CURLMINFO_NONE` = 0 -- first, never use this.
    ///
    /// Not a request for anything, and it takes the `default` arm of the C's
    /// `switch` (`lib/multi.c:3781-3783`) exactly like an unrecognised
    /// integer: `-1` is written and `CURLM_UNKNOWN_OPTION` returned. See
    /// [`get_offt`].
    None = 0,
    /// `CURLMINFO_XFERS_CURRENT` = 1 -- the number of easy handles currently
    /// managed by the multi handle, e.g. have been added but not yet removed.
    XfersCurrent = 1,
    /// `CURLMINFO_XFERS_RUNNING` = 2 -- the number of easy handles running,
    /// e.g. not done and not queueing.
    XfersRunning = 2,
    /// `CURLMINFO_XFERS_PENDING` = 3 -- the number of easy handles waiting to
    /// start, e.g. for a connection to become available due to limits on
    /// parallelism, max connections or other factors.
    XfersPending = 3,
    /// `CURLMINFO_XFERS_DONE` = 4 -- the number of easy handles finished,
    /// waiting for their results to be read via `curl_multi_info_read()`.
    XfersDone = 4,
    /// `CURLMINFO_XFERS_ADDED` = 5 -- the total number of easy handles added
    /// to the multi handle, ever.
    XfersAdded = 5,
    /// `CURLMINFO_LASTENTRY` = 6 -- the last unused.
    ///
    /// A bound for range checks rather than a value, and it too takes the
    /// `default` arm.
    LastEntry = 6,
}

impl CurlMInfoOfft {
    /// Every member, in declaration order, which is also ascending order.
    pub const VARIANTS: &'static [Self] = &[
        Self::None,
        Self::XfersCurrent,
        Self::XfersRunning,
        Self::XfersPending,
        Self::XfersDone,
        Self::XfersAdded,
        Self::LastEntry,
    ];

    /// The pinned integer, as a C consumer sees it.
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
    }

    /// The C spelling.
    ///
    /// Written out so that a test can assert the *names* as well as the
    /// numbers: the `_OFFT_` misspelling would have produced identical
    /// integers, so only a name check catches it.
    #[must_use]
    pub const fn c_name(self) -> &'static str {
        match self {
            Self::None => "CURLMINFO_NONE",
            Self::XfersCurrent => "CURLMINFO_XFERS_CURRENT",
            Self::XfersRunning => "CURLMINFO_XFERS_RUNNING",
            Self::XfersPending => "CURLMINFO_XFERS_PENDING",
            Self::XfersDone => "CURLMINFO_XFERS_DONE",
            Self::XfersAdded => "CURLMINFO_XFERS_ADDED",
            Self::LastEntry => "CURLMINFO_LASTENTRY",
        }
    }

    /// Interprets a raw integer, yielding [`None`](Option::None) when it names
    /// no member.
    ///
    /// [`get_offt`] takes a raw `i32` rather than this type precisely because
    /// a C caller can pass an integer outside the enumeration, so this is the
    /// classifier rather than a precondition.
    #[must_use]
    pub const fn from_i32(raw: i32) -> Option<Self> {
        match raw {
            0 => Some(Self::None),
            1 => Some(Self::XfersCurrent),
            2 => Some(Self::XfersRunning),
            3 => Some(Self::XfersPending),
            4 => Some(Self::XfersDone),
            5 => Some(Self::XfersAdded),
            6 => Some(Self::LastEntry),
            _ => Option::None,
        }
    }
}

// Tracing: two frozen lines

/// The `printf` format `lib/multi_ntfy.c:171` emits when queueing an entry.
#[allow(dead_code)] // consumers: the drift test below, and `super`'s tracer
pub(crate) const TRACE_FORMAT_ADD: &str = "[NTFY] add %u for xfer %u";

/// The `printf` format `lib/multi_ntfy.c:113-114` emits when dispatching.
///
/// Frozen for the same reason. Its arguments are `(e->type, e->mid)` and the
/// emitting handle is `multi->admin`, **not** the transfer named by `e->mid`
/// -- the C passes `multi->admin` as the trace target even while dispatching
/// an entry that belongs to another transfer.
#[allow(dead_code)] // consumers: the drift test below, and `super`'s tracer
pub(crate) const TRACE_FORMAT_DISPATCH: &str = "[NTFY] dispatch %u to xfer %u";

/// One of the two trace lines this subsystem emits, as data.
///
/// The lines are frozen text, but this crate holds no tracer: the tracing
/// destination belongs to whoever owns the multi handle. Representing the
/// event as a value and rendering it through [`fmt::Display`] puts the frozen
/// text in the module that owns it, under test, while leaving the decision of
/// *whether* to emit -- and to which sink -- with the caller. The renderer
/// substitutes the C's `%u` conversions positionally, so the rendered bytes
/// are identical to the C's for every input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NotifyEvent {
    /// `lib/multi_ntfy.c:171`, emitted against the transfer named by `mid`.
    ///
    /// Two properties of *when* the C emits this are reproduced by
    /// [`MultiNotify::add`] and are easy to lose: it comes **before** the
    /// append, and it is emitted **even when the append then fails**.
    Add {
        /// The `type` argument -- a `CURLMNOTIFY_*` value.
        notification: u32,
        /// The `data->mid` argument.
        mid: u32,
    },
    /// `lib/multi_ntfy.c:113-114`, emitted against the admin handle.
    Dispatch {
        /// The `e->type` argument.
        notification: u32,
        /// The `e->mid` argument.
        mid: u32,
    },
}

impl NotifyEvent {
    /// The C format string this event renders from.
    ///
    /// Exposed so a test can assert that the rendering really is a
    /// substitution of *this* format and not of a paraphrase of it.
    #[must_use]
    #[allow(dead_code)] // consumer: the drift test at the foot of this file
    pub(crate) const fn c_format(self) -> &'static str {
        match self {
            Self::Add { .. } => TRACE_FORMAT_ADD,
            Self::Dispatch { .. } => TRACE_FORMAT_DISPATCH,
        }
    }
}

impl fmt::Display for NotifyEvent {
    /// Renders the frozen text.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Add { notification, mid } => {
                write!(f, "[NTFY] add {notification} for xfer {mid}")
            }
            Self::Dispatch { notification, mid } => {
                write!(f, "[NTFY] dispatch {notification} to xfer {mid}")
            }
        }
    }
}

/// Where the two frozen trace lines go.
///
/// The C reaches a tracer through the `struct Curl_easy *` it is handed --
/// `CURL_TRC_M(data, ...)` at `lib/multi_ntfy.c:171` and
/// `CURL_TRC_M(multi->admin, ...)` at `:113`. This crate's tracer needs a
/// configuration and a sink that the multi handle owns, so the dependency is
/// inverted: this module produces [`NotifyEvent`]s and the caller routes them.
pub(crate) trait NotifyTracer {
    /// Emits one trace line, or discards it.
    ///
    /// The C guards each call site with a verbosity test inside the
    /// `CURL_TRC_M` macro, so an implementation that renders unconditionally
    /// is free to test verbosity here and return without formatting.
    fn trace(&mut self, event: NotifyEvent);
}

impl NotifyTracer for () {
    /// Discards the event.
    ///
    /// The counterpart of a C build with tracing compiled out, and the
    /// implementation a caller uses when it has no tracer to hand.
    fn trace(&mut self, _event: NotifyEvent) {}
}

/// How a dispatch cycle reaches the application.
///
/// The two things `mntfy_chunk_dispatch_all` does with a queued entry
/// (`lib/multi_ntfy.c:100-122`) are resolving its `mid` to a live transfer and
/// invoking the application's `curl_notify_callback`. Both need the multi
/// handle's transfer table and the raw `CURLM *` and `CURL *` pointers the
/// callback expects, so both belong outside this module -- and both are
/// reached through this trait, which keeps [`MultiNotify::dispatch_all`]'s
/// loop, and therefore the four behaviours it must preserve, in the module
/// that owns them.
pub(crate) trait NotifySink: NotifyTracer {
    /// Whether `mid` resolves to a transfer that may be notified.
    ///
    /// The predicate half of
    /// `data = e->mid ? Curl_multi_get_easy(multi, e->mid) : multi->admin;`
    /// followed by `if(data && ...)` (`lib/multi_ntfy.c:109-111`). Two
    /// consequences of that one line must be honoured by any implementation:
    ///
    /// * **`mid` 0 must resolve to the admin handle**, and must therefore
    ///   answer `true` whenever the multi handle has one. The C's ternary
    ///   treats `0` as "no specific transfer" and substitutes `multi->admin`,
    ///   which *is* mid 0, so the two readings coincide.
    /// * **A non-zero `mid` that no longer names a live transfer answers
    ///   `false`**, and the entry is then skipped without being delivered --
    ///   `Curl_multi_get_easy` returns `NULL` for a stale or invalid slot
    ///   (`lib/multi.c:3953-3963`). The entry is still consumed: the C
    ///   advances its read cursor whether or not the callback ran.
    fn resolves(&self, mid: u32) -> bool;

    /// Invokes the application callback for one entry.
    fn deliver(
        &mut self,
        notify: &mut MultiNotify,
        notification: u32,
        mid: u32,
    );
}

// The notification store

/// One queued notification: which type, and about which transfer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NtfyEntry {
    /// The `CURLMNOTIFY_*` value.
    notification: u32,
    /// The transfer this concerns, or 0 for the admin handle.
    mid: u32,
}

/// A bounded run of entries with independent read and write cursors.
///
/// ```c
/// struct mntfy_chunk {
///   struct mntfy_chunk *next;
///   size_t r_offset;
///   size_t w_offset;
///   struct mntfy_entry entries[CURL_MNTFY_CHUNK_SIZE];
/// };
/// ```
#[derive(Clone, Debug)]
struct NtfyChunk {
    /// Entries in write order. Never longer than [`CURL_MNTFY_CHUNK_SIZE`],
    /// which is the C's `w_offset >= CURL_MNTFY_CHUNK_SIZE` bound
    /// (`lib/multi_ntfy.c:68-69`) expressed as a capacity.
    entries: Vec<NtfyEntry>,
    /// How many entries have been dispatched: the C's `r_offset`.
    read: usize,
}

impl NtfyChunk {
    /// An empty chunk with room reserved for its full run.
    fn new() -> Result<Self, CURLMcode> {
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(CURL_MNTFY_CHUNK_SIZE)
            .map_err(|_| CURLMcode::OutOfMemory)?;
        Ok(Self { entries, read: 0 })
    }

    /// Whether another entry fits.
    ///
    /// The C's `chunk->w_offset >= CURL_MNTFY_CHUNK_SIZE` test, inverted
    /// (`lib/multi_ntfy.c:68`).
    fn has_room(&self) -> bool {
        self.entries.len() < CURL_MNTFY_CHUNK_SIZE
    }

    /// Appends an entry, reporting whether it fitted.
    ///
    /// `mntfy_chunk_append` (`lib/multi_ntfy.c:62-74`), which returns `FALSE`
    /// on a full chunk and otherwise writes at `w_offset++`. The push cannot
    /// reallocate, because [`Self::new`] reserved the full run and this
    /// declines to write past it.
    fn append(&mut self, entry: NtfyEntry) -> bool {
        if !self.has_room() {
            return false;
        }
        self.entries.push(entry);
        true
    }

    /// The next entry to dispatch, without consuming it.
    ///
    /// The C's `e = &chunk->entries[chunk->r_offset]` (`lib/multi_ntfy.c:108`)
    /// under the loop condition `chunk->r_offset < chunk->w_offset` (`:107`).
    /// Reading without advancing is the point: the cursor moves only after the
    /// callback has returned.
    fn peek(&self) -> Option<NtfyEntry> {
        self.entries.get(self.read).copied()
    }

    /// Advances the read cursor past the entry [`Self::peek`] returned.
    ///
    /// The C's `chunk->r_offset++`, annotated "once dispatched, safe to
    /// increment" (`lib/multi_ntfy.c:117-118`).
    fn advance(&mut self) {
        self.read += 1;
    }

    /// Discards every entry and rewinds both cursors.
    fn reset(&mut self) {
        self.entries.clear();
        self.read = 0;
    }
}

/// The notification subsystem of one multi handle.
///
/// Supersedes `struct curl_multi_ntfy` (`lib/multi_ntfy.h:31-39`):
///
/// ```c
/// struct curl_multi_ntfy {
///   curl_notify_callback ntfy_cb;
///   void *ntfy_cb_data;
///   struct uint32_bset enabled;
///   struct mntfy_chunk *head;
///   struct mntfy_chunk *tail;
///   CURLMcode failure;
///   BIT(has_entries);
/// };
/// ```
#[derive(Debug)]
#[allow(dead_code)] // consumer: `super`'s multi handle
pub(crate) struct MultiNotify {
    /// Whether the application installed a `curl_notify_callback`.
    ///
    /// The C's `multi->ntfy.ntfy_cb != NULL`. The pointer itself, and the
    /// `ntfy_cb_data` beside it, belong to `curl-rs-ffi`; this is the only
    /// property of them that this module's decisions turn on.
    callback_installed: bool,
    /// Which notification types the application asked for: the C's `enabled`.
    enabled: Uint32Bset,
    /// The chunk ring: the C's `head` and `tail` in one owned collection.
    ///
    /// Front is `head`, back is `tail`. Never empty once anything has been
    /// added, because [`Self::dispatch_all`] keeps the last chunk rather than
    /// freeing it, exactly as `lib/multi_ntfy.c:190-191` does.
    chunks: VecDeque<NtfyChunk>,
    /// A latched failure, reported once and then cleared: the C's `failure`.
    ///
    /// [`CURLMcode::Ok`] means "none". Set only by an allocation failure in
    /// [`Self::add`], which is the C's only writer too
    /// (`lib/multi_ntfy.c:175`).
    failure: CURLMcode,
    /// The cheap "is there anything to dispatch" flag: the C's `has_entries`.
    ///
    /// Read through [`Self::has_entries`], the counterpart of
    /// `CURL_MNTFY_HAS_ENTRIES(m)` (`lib/multi_ntfy.h:56`), which
    /// `multi_perform` (`lib/multi.c:2785`) and `multi_socket`
    /// (`lib/multi.c:3172`) test before calling into dispatch at all.
    has_entries: bool,
    /// True for the duration of a dispatch cycle: the C's
    /// `multi->in_ntfy_callback` (`lib/multihandle.h:181`).
    in_callback: bool,
    /// Test-only fault injection for the chunk allocation.
    #[cfg(test)]
    fail_chunk_allocation: bool,
}

impl MultiNotify {
    /// A subsystem with no callback, nothing enabled and nothing queued.
    #[must_use]
    #[allow(dead_code)] // consumer: `super`'s multi-handle constructor
    pub(crate) fn new() -> Self {
        Self {
            callback_installed: false,
            enabled: Uint32Bset::new(),
            chunks: VecDeque::new(),
            failure: CURLMcode::Ok,
            has_entries: false,
            in_callback: false,
            #[cfg(test)]
            fail_chunk_allocation: false,
        }
    }

    /// Makes the next chunk allocation fail. Tests only.
    ///
    /// See the `fail_chunk_allocation` field for why this exists. The flag
    /// stays set until cleared, so a test can drive several failing adds.
    #[cfg(test)]
    fn set_fail_chunk_allocation(&mut self, fail: bool) {
        self.fail_chunk_allocation = fail;
    }

    /// A chunk, or the C's `NULL` from `mnfty_chunk_create`.
    ///
    /// One indirection over [`NtfyChunk::new`] so that the test-only injection
    /// has somewhere to live without appearing in [`Self::add`]'s logic.
    fn new_chunk(&self) -> Result<NtfyChunk, CURLMcode> {
        #[cfg(test)]
        if self.fail_chunk_allocation {
            return Err(CURLMcode::OutOfMemory);
        }
        NtfyChunk::new()
    }

    /// Gives the enabled set room for every notification type.
    ///
    /// `Curl_mntfy_resize` (`lib/multi_ntfy.c:130-135`):
    ///
    /// ```c
    /// if(Curl_uint32_bset_resize(&multi->ntfy.enabled,
    ///                            CURLMNOTIFY_EASY_DONE + 1))
    ///   return CURLM_OUT_OF_MEMORY;
    /// return CURLM_OK;
    /// ```
    ///
    /// # Errors
    ///
    /// [`CURLMcode::OutOfMemory`] when the set cannot be grown. The multi
    /// handle's constructor fails on it, as `lib/multi.c:258-263` does.
    #[allow(dead_code)] // consumer: `super`'s multi-handle constructor
    pub(crate) fn resize(&mut self) -> CURLMcode {
        match self.enabled.resize(CURLMNOTIFY_COUNT) {
            Ok(()) => CURLMcode::Ok,
            // The bitset reports only `CURLcode::OutOfMemory` here, and the C
            // likewise collapses a non-zero result to one code
            // (`lib/multi_ntfy.c:132-134`). The wildcard keeps that collapse
            // total, so a further failure mode added to the bitset cannot
            // silently become a success.
            Err(_) => CURLMcode::OutOfMemory,
        }
    }

    /// Records whether the application has installed a notify callback.
    ///
    /// What `curl_multi_setopt` reduces to for this module:
    /// `CURLMOPT_NOTIFYFUNCTION` sets or clears the C's `ntfy_cb`, and
    /// `CURLMOPT_NOTIFYDATA` sets `ntfy_cb_data`, which this module never
    /// reads. Their option integers are pinned in
    /// `curl-rs-ffi/src/ffi/opts.rs` and are deliberately not named here.
    #[allow(dead_code)] // consumer: `super`'s `curl_multi_setopt`
    pub(crate) fn set_callback_installed(&mut self, installed: bool) {
        self.callback_installed = installed;
    }

    /// Whether a notify callback is installed.
    #[must_use]
    #[allow(dead_code)] // consumer: `super`'s `curl_multi_setopt`
    pub(crate) fn callback_installed(&self) -> bool {
        self.callback_installed
    }

    /// Whether anything is waiting to be dispatched.
    #[must_use]
    #[allow(dead_code)] // consumer: `super`'s perform and socket paths
    pub(crate) fn has_entries(&self) -> bool {
        self.has_entries
    }

    /// Whether a dispatch cycle is in progress.
    ///
    /// The C's `multi->in_ntfy_callback` (`lib/multihandle.h:181`). The multi
    /// handle returns `CURLM_RECURSIVE_API_CALL` from `curl_multi_perform`
    /// and the three socket entry points while this holds
    /// (`lib/multi.c:2758`, `:3286`, `:3297`, `:3307`).
    #[must_use]
    #[allow(dead_code)] // consumer: `super`'s perform and socket paths
    pub(crate) fn in_callback(&self) -> bool {
        self.in_callback
    }

    /// The latched failure, or [`CURLMcode::Ok`] when there is none.
    ///
    /// Observable through behaviour rather than through the API -- a latched
    /// failure suppresses queueing (`lib/multi_ntfy.c:167`) and stops
    /// dispatch (`:107`, `:184`) -- so this accessor exists for the multi
    /// handle's diagnostics and for the tests below.
    #[must_use]
    #[allow(dead_code)] // consumer: `super`'s diagnostics
    pub(crate) fn failure(&self) -> CURLMcode {
        self.failure
    }

    /// Whether `notification` is currently enabled.
    #[must_use]
    #[allow(dead_code)] // consumer: `super`'s diagnostics
    pub(crate) fn is_enabled(&self, notification: u32) -> bool {
        self.enabled.contains(notification)
    }

    /// Enables a notification type.
    ///
    /// The engine half of `curl_multi_notify_enable`
    /// (`lib/multi.c:3982-3989`), which validates the handle and delegates to
    /// `Curl_mntfy_enable` (`lib/multi_ntfy.c:148-154`):
    ///
    /// ```c
    /// if(type > CURLMNOTIFY_EASY_DONE)
    ///   return CURLM_UNKNOWN_OPTION;
    /// Curl_uint32_bset_add(&multi->ntfy.enabled, type);
    /// return CURLM_OK;
    /// ```
    ///
    /// Four details, each measured:
    ///
    /// * The out-of-range code is **[`CURLMcode::UnknownOption`]**, not
    ///   `CURLM_BAD_FUNCTION_ARGUMENT`. The type is an option-like selector,
    ///   and the C treats an unknown one the way `curl_multi_setopt` treats an
    ///   unknown option.
    /// * `GOOD_MULTI_HANDLE` comes **first** and yields
    ///   [`CURLMcode::BadHandle`]. That check is a magic-number test on a raw
    ///   pointer and belongs to `curl-rs-ffi`; the *ordering* is the contract
    ///   this method's caller owes, so a null handle with an out-of-range type
    ///   reports `CURLM_BAD_HANDLE` and not `CURLM_UNKNOWN_OPTION`.
    /// * **Neither entry point checks `in_callback`.** No such guard is added
    ///   here, because adding one C does not have would reject a call C
    ///   accepts.
    /// * `Curl_uint32_bset_add` returns a `bool` meaning "was in range", not
    ///   "was newly inserted". The C discards it, and so does this: enabling
    ///   an already-enabled type is **idempotent** and reports
    ///   [`CURLMcode::Ok`]. Translating that boolean into an "already enabled"
    ///   error would invert the branch, since `HashSet::insert`'s boolean has
    ///   the opposite sense.
    #[allow(dead_code)] // consumer: `curl-rs-ffi`'s `curl_multi_notify_enable`
    pub(crate) fn enable(&mut self, notification: u32) -> CURLMcode {
        if notification > CURLMNOTIFY_EASY_DONE {
            return CURLMcode::UnknownOption;
        }
        let in_range = self.enabled.add(notification);
        debug_assert!(
            in_range,
            "resize() sizes the set for CURLMNOTIFY_COUNT, so a type that \
             passed the range test above is always within capacity"
        );
        CURLMcode::Ok
    }

    /// Disables a notification type.
    #[allow(dead_code)] // consumer: `curl-rs-ffi`'s `curl_multi_notify_disable`
    pub(crate) fn disable(&mut self, notification: u32) -> CURLMcode {
        if notification > CURLMNOTIFY_EASY_DONE {
            return CURLMcode::UnknownOption;
        }
        self.enabled.remove(notification);
        CURLMcode::Ok
    }

    /// Queues a notification about `mid`, if anything wants it.
    ///
    /// ```c
    /// void Curl_mntfy_add(struct Curl_easy *data, unsigned int type)
    /// {
    ///   struct Curl_multi *multi = data ? data->multi : NULL;
    ///   if(multi && multi->ntfy.ntfy_cb && !multi->ntfy.failure &&
    ///      Curl_uint32_bset_contains(&multi->ntfy.enabled, type)) {
    ///     struct mntfy_chunk *tail = mntfy_non_full_tail(&multi->ntfy);
    ///     CURL_TRC_M(data, "[NTFY] add %u for xfer %u", type, data->mid);
    ///     if(tail)
    ///       mntfy_chunk_append(tail, data, type);
    ///     else
    ///       multi->ntfy.failure = CURLM_OUT_OF_MEMORY;
    ///     multi->ntfy.has_entries = TRUE;
    ///   }
    /// }
    /// ```
    #[allow(dead_code)] // consumer: `super`'s completion and state paths
    pub(crate) fn add(
        &mut self,
        mid: u32,
        notification: u32,
        tracer: &mut (impl NotifyTracer + ?Sized),
    ) {
        if !self.callback_installed
            || !self.failure.is_ok()
            || !self.enabled.contains(notification)
        {
            return;
        }

        // `mntfy_non_full_tail` (`lib/multi_ntfy.c:76-98`): reuse the tail when
        // it has room, otherwise start a new one. The C's three arms -- no
        // tail, tail with room, tail full -- collapse to two here, because an
        // empty ring and a full tail both mean "push a chunk".
        let tail_ready = match self.chunks.back() {
            Some(tail) if tail.has_room() => Ok(()),
            _ => self.new_chunk().map(|chunk| self.chunks.push_back(chunk)),
        };

        // Emitted BEFORE the append and regardless of whether it succeeds,
        // exactly as `lib/multi_ntfy.c:171` sits before `:172-175`.
        tracer.trace(NotifyEvent::Add { notification, mid });

        match tail_ready {
            Ok(()) => {
                let entry = NtfyEntry { notification, mid };
                let appended = self
                    .chunks
                    .back_mut()
                    .is_some_and(|tail| tail.append(entry));
                debug_assert!(
                    appended,
                    "the tail was just proved to have room, so the append \
                     that mirrors lib/multi_ntfy.c:173 cannot decline"
                );
            }
            // `multi->ntfy.failure = CURLM_OUT_OF_MEMORY;`
            // (`lib/multi_ntfy.c:175`).
            Err(code) => self.failure = code,
        }

        // Outside the success arm, as at `lib/multi_ntfy.c:176`.
        self.has_entries = true;
    }

    /// Dispatches every queued notification, then reports any latched failure.
    ///
    /// ```c
    /// CURLMcode Curl_mntfy_dispatch_all(struct Curl_multi *multi)
    /// {
    ///   DEBUGASSERT(!multi->in_ntfy_callback);
    ///   multi->in_ntfy_callback = TRUE;
    ///   while(multi->ntfy.head && !multi->ntfy.failure) {
    ///     struct mntfy_chunk *chunk = multi->ntfy.head;
    ///     mntfy_chunk_dispatch_all(multi, chunk);   /* may add entries! */
    ///     if(chunk == multi->ntfy.tail) /* last one, keep */
    ///       break;
    ///     multi->ntfy.head = chunk->next;
    ///     mnfty_chunk_destroy(chunk);
    ///   }
    ///   multi->in_ntfy_callback = FALSE;
    ///   if(multi->ntfy.failure) {
    ///     CURLMcode mresult = multi->ntfy.failure;
    ///     multi->ntfy.failure = CURLM_OK; /* reset, once delivered */
    ///     return mresult;
    ///   }
    ///   else
    ///     multi->ntfy.has_entries = FALSE;
    ///   return CURLM_OK;
    /// }
    /// ```
    ///
    /// # The five behaviours this reproduces
    ///
    /// 1. **The read cursor advances only after the callback returns**, with
    ///    the C's comment "once dispatched, safe to increment"
    ///    (`lib/multi_ntfy.c:117-118`). Because the callback may queue more
    ///    notifications, advancing early risks delivering an entry twice or
    ///    skipping one.
    /// 2. **A latched failure stops the loop**, at both levels: the inner
    ///    condition is `r_offset < w_offset && !failure` (`:107`) and the
    ///    outer is `head && !failure` (`:184`). The entries left in the chunk
    ///    being dispatched are then **discarded**, because the reset at `:121`
    ///    runs whether or not the loop completed.
    /// 3. **The last chunk is kept, not freed** -- `if(chunk ==
    ///    multi->ntfy.tail) break;` (`:190-191`), so the tail is reset and
    ///    reused. Earlier chunks are dropped.
    /// 4. **A failure is reported exactly once**, then cleared: `mresult =
    ///    failure; failure = CURLM_OK;` (`:200-202`). `has_entries` is
    ///    deliberately **not** cleared on that path -- only the `else` arm
    ///    clears it (`:205`) -- so the next cycle retries.
    /// 5. **`in_callback` is set for the duration** and cleared afterwards
    ///    (`:183`, `:197`), including on the failure path, which is why the
    ///    clear happens before the failure is examined.
    ///
    /// The C's `DEBUGASSERT(!multi->in_ntfy_callback)` (`:182`) is kept as a
    /// `debug_assert!`, and it is unreachable for a stronger reason here than
    /// in C: this method takes `&mut self`, so a re-entrant call would need a
    /// second exclusive borrow and would not compile. The assertion documents
    /// the invariant; the borrow checker enforces it.
    ///
    /// # Errors
    ///
    /// The latched failure, which in practice is
    /// [`CURLMcode::OutOfMemory`] from [`Self::add`]. Returning
    /// [`CURLMcode::Ok`] means every entry reachable in this cycle was
    /// dispatched or deliberately skipped.
    #[allow(dead_code)] // consumer: `super`'s perform and socket paths
    pub(crate) fn dispatch_all(
        &mut self,
        sink: &mut (impl NotifySink + ?Sized),
    ) -> CURLMcode {
        debug_assert!(
            !self.in_callback,
            "dispatch is not re-entrant; the exclusive borrow of self makes \
             this unrepresentable, and lib/multi_ntfy.c:182 asserts it too"
        );
        self.in_callback = true;

        // `while(multi->ntfy.head && !multi->ntfy.failure)`
        // (`lib/multi_ntfy.c:184`).
        while !self.chunks.is_empty() && self.failure.is_ok() {
            // The head chunk, dispatched in place: entries queued during the
            // callback extend it, and the cursor discipline picks them up.
            self.dispatch_head(sink);

            // `if(chunk == multi->ntfy.tail) break;` -- the last chunk is
            // kept so the next cycle has somewhere to write
            // (`lib/multi_ntfy.c:190-191`).
            if self.chunks.len() == 1 {
                break;
            }
            // Earlier chunks are destroyed: `mnfty_chunk_destroy(chunk)`
            // (`:195`). The C reaches the successor through `chunk->next`,
            // which its own reset has already zeroed -- the latent defect this
            // module's documentation records. An owned collection has no such
            // pointer, so popping the front is both correct and unambiguous.
            self.chunks.pop_front();
        }

        // Cleared before the failure is examined, as at `lib/multi_ntfy.c:197`,
        // so the flag is false on every return path.
        self.in_callback = false;

        if self.failure.is_ok() {
            // Only this arm clears the flag (`lib/multi_ntfy.c:205`).
            self.has_entries = false;
            CURLMcode::Ok
        } else {
            // Reported once, then reset (`lib/multi_ntfy.c:200-202`).
            // `has_entries` is left set on purpose: the next cycle retries.
            let reported = self.failure;
            self.failure = CURLMcode::Ok;
            reported
        }
    }

    /// Dispatches the head chunk, then resets it.
    fn dispatch_head(&mut self, sink: &mut (impl NotifySink + ?Sized)) {
        // `if(multi->ntfy.ntfy_cb)` (`lib/multi_ntfy.c:106`): with no callback
        // installed the loop is skipped entirely -- but the reset below still
        // runs, so the chunk is emptied either way.
        if self.callback_installed {
            // `while((chunk->r_offset < chunk->w_offset) &&
            //        !multi->ntfy.failure)` (`:107`).
            while self.failure.is_ok() {
                let Some(entry) = self.chunks.front().and_then(NtfyChunk::peek)
                else {
                    break;
                };

                // `data = e->mid ? Curl_multi_get_easy(multi, e->mid)
                //                : multi->admin;` then
                // `if(data && Curl_uint32_bset_contains(&enabled, e->type))`
                // (`:109-111`). Membership is re-tested here, per the C's
                // comment "only when notification has not been disabled in the
                // meantime", so a type disabled since queueing is skipped.
                if sink.resolves(entry.mid)
                    && self.enabled.contains(entry.notification)
                {
                    sink.trace(NotifyEvent::Dispatch {
                        notification: entry.notification,
                        mid: entry.mid,
                    });
                    // "this may cause new notifications to be added!" (`:112`)
                    sink.deliver(self, entry.notification, entry.mid);
                }

                // "once dispatched, safe to increment" (`:117-118`). Reached
                // whether or not the callback ran, which is what makes a
                // skipped entry consumed rather than retried forever.
                if let Some(head) = self.chunks.front_mut() {
                    head.advance();
                }
            }
        }

        // `mnfty_chunk_reset(chunk)` (`:121`), outside the loop and therefore
        // unconditional. On the failure path this DISCARDS the entries that
        // were not reached, which is the observable half of the C's `memset`.
        if let Some(head) = self.chunks.front_mut() {
            head.reset();
        }
    }
}

impl Default for MultiNotify {
    /// [`MultiNotify::new`].
    ///
    /// Written out rather than derived because [`CURLMcode`] has no `Default`
    /// -- deliberately, since none of its fifteen codes is a more natural zero
    /// than the others from the type's own point of view. Here the zero is
    /// [`CURLMcode::Ok`], which is what the C's `memset` produces.
    fn default() -> Self {
        Self::new()
    }
}

// `curl_multi_get_offt`

/// The counters `curl_multi_get_offt` reports, as already computed.
///
/// The ownership split, stated once here so that neither this module nor its
/// parent duplicates the other:
///
/// * **This module owns** [`CurlMInfoOfft`] and [`get_offt`], which is a pure
///   mapping from these numbers to a result. It reaches into no collection.
/// * **The multi handle owns** the numbers: the transfer table's count, the
///   `process`, `pending` and `msgsent` cardinalities, `xfers_total_ever`, and
///   the two admin-handle predicates. It fills this struct and calls
///   [`get_offt`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)] // consumer: `super`'s `curl_multi_get_offt`
pub(crate) struct MultiCounters {
    /// `Curl_uint32_tbl_count(&multi->xfers)` (`lib/multi.c:3761`): every
    /// transfer in the table, the admin handle included.
    pub(crate) xfers: u32,
    /// `multi->admin != NULL` (`lib/multi.c:3762`).
    ///
    /// Its own field rather than an assumption, because the C tests it: the
    /// admin handle is absent for a brief window during cleanup
    /// (`lib/multi.c:2888-2892` closes it before the table is destroyed).
    pub(crate) admin_present: bool,
    /// `Curl_uint32_bset_count(&multi->process)` (`lib/multi.c:3767`).
    pub(crate) process: u32,
    /// `Curl_uint32_bset_contains(&multi->process, multi->admin->mid)`
    /// (`lib/multi.c:3768`).
    pub(crate) process_has_admin: bool,
    /// `Curl_uint32_bset_count(&multi->pending)` (`lib/multi.c:3773`).
    pub(crate) pending: u32,
    /// `Curl_uint32_bset_count(&multi->msgsent)` (`lib/multi.c:3776`).
    pub(crate) msgsent: u32,
    /// `multi->xfers_total_ever` (`lib/multi.c:3779`), a `curl_off_t`
    /// described as "total of added transfers, ever"
    /// (`lib/multihandle.h:89`) and never decremented.
    ///
    /// `i64` because `curl_off_t` is 64-bit on all four targets of the
    /// mandated matrix, and because it is the only counter the C does not
    /// widen from a `uint32_t`.
    pub(crate) xfers_total_ever: i64,
}

/// Maps a `CURLMinfo_offt` selector onto a number: `curl_multi_get_offt`.
///
/// ```c
/// CURL_EXTERN CURLMcode curl_multi_get_offt(CURLM *multi_handle,
///                                           CURLMinfo_offt info,
///                                           curl_off_t *pvalue);
/// ```
///
/// # Every branch, as measured
///
/// | Selector | Value | Adjustment |
/// |---|---|---|
/// | `CURLMINFO_XFERS_CURRENT` | table count | **minus one** when the admin handle is present |
/// | `CURLMINFO_XFERS_RUNNING` | `process` count | **minus one** when `process` holds the admin `mid` |
/// | `CURLMINFO_XFERS_PENDING` | `pending` count | none |
/// | `CURLMINFO_XFERS_DONE` | `msgsent` count | none |
/// | `CURLMINFO_XFERS_ADDED` | `xfers_total_ever` | none |
/// | anything else | `-1` | returns `CURLM_UNKNOWN_OPTION` |
///
/// # The two guards this function does not perform
///
/// Both precede the `switch` in C and both concern a raw pointer, so both
/// belong to `curl-rs-ffi`, which must apply them **in this order** and
/// **without writing through the pointer**:
///
/// 1. `!GOOD_MULTI_HANDLE(multi)` yields [`CURLMcode::BadHandle`]
///    (`lib/multi.c:3754-3755`).
/// 2. `!pvalue` yields [`CURLMcode::BadFunctionArgument`]
///    (`lib/multi.c:3756-3757`) -- note, **not** `CURLM_UNKNOWN_OPTION`. A
///    `&mut i64` cannot be null, so this check has no expression here.
///
/// # `XFERS_DONE` counts `msgsent`, which is not the queue's length
///
/// Two measured facts keep the two numbers apart, and conflating them would
/// make this counter wrong in both directions:
///
/// * **Reading a message does not decrement it.** `curl_multi_info_read`
///   touches only `msglist` (`lib/multi.c:2943-2969`); a transfer leaves
///   `msgsent` when it is removed from the multi handle
///   (`lib/multi.c:874`) or when the whole set is cleared (`:456`).
/// * **A sub-transfer joins `msgsent` without ever posting a message.**
///   `handle_completed` routes a transfer with a `master_mid` to its master's
///   callback instead of the queue -- "A sub transfer, not for msgsent to
///   application" (`lib/multi.c:2389-2405`) -- and then adds it to `msgsent`
///   anyway (`:2423`).
///
/// So `XFERS_DONE` is at least the queue's length and may exceed it. The
/// invariant that does hold is `struct Curl_multi`'s, stated verbatim at
/// `lib/multihandle.h:91`: "Each transfer's mid may be present in at most one
/// of these" four bitsets. That invariant is the multi handle's to uphold;
/// this function only reports the cardinality it is given.
#[allow(dead_code)] // consumer: `curl-rs-ffi`'s `curl_multi_get_offt`
pub(crate) fn get_offt(
    info: i32,
    counters: &MultiCounters,
    pvalue: &mut i64,
) -> CURLMcode {
    match CurlMInfoOfft::from_i32(info) {
        Some(CurlMInfoOfft::XfersCurrent) => {
            // `n = count(xfers); if(n && multi->admin) --n;`
            // (`lib/multi.c:3761-3764`).
            let visible = if counters.admin_present {
                counters.xfers.saturating_sub(1)
            } else {
                counters.xfers
            };
            *pvalue = i64::from(visible);
            CURLMcode::Ok
        }
        Some(CurlMInfoOfft::XfersRunning) => {
            // `n = count(process); if(n && contains(process, admin->mid)) --n;`
            // (`lib/multi.c:3767-3770`).
            let running = if counters.process_has_admin {
                counters.process.saturating_sub(1)
            } else {
                counters.process
            };
            *pvalue = i64::from(running);
            CURLMcode::Ok
        }
        // No adjustment: the admin handle is never in `pending`
        // (`lib/multi.c:3772-3774`).
        Some(CurlMInfoOfft::XfersPending) => {
            *pvalue = i64::from(counters.pending);
            CURLMcode::Ok
        }
        // No adjustment: the admin handle never completes with a message
        // (`lib/multi.c:3775-3777`).
        Some(CurlMInfoOfft::XfersDone) => {
            *pvalue = i64::from(counters.msgsent);
            CURLMcode::Ok
        }
        // Already a `curl_off_t`, so no widening (`lib/multi.c:3778-3780`).
        Some(CurlMInfoOfft::XfersAdded) => {
            *pvalue = counters.xfers_total_ever;
            CURLMcode::Ok
        }
        // `CURLMINFO_NONE`, `CURLMINFO_LASTENTRY` and every integer outside
        // the enumeration share the C's `default` arm: write, then report
        // (`lib/multi.c:3781-3783`).
        Some(CurlMInfoOfft::None | CurlMInfoOfft::LastEntry) | Option::None => {
            *pvalue = -1;
            CURLMcode::UnknownOption
        }
    }
}

// TESTS
#[cfg(test)]
mod tests {
    use super::*;

    // The pinned ABI integers

    /// `include/curl/multi.h:90-95`. A consumer holds the number, so this is
    /// the assertion that makes reordering the enumeration a test failure
    /// rather than a silent ABI break.
    #[test]
    fn curlmsg_discriminants_are_pinned() {
        assert_eq!(CurlMsgType::None as i32, 0);
        assert_eq!(CurlMsgType::Done as i32, 1);
        assert_eq!(CurlMsgType::Last as i32, 2);

        // The accessor and the cast must agree, since the ABI crate uses the
        // accessor and a C consumer effectively uses the cast.
        for member in CurlMsgType::VARIANTS {
            assert_eq!(member.as_i32(), *member as i32);
        }
        assert_eq!(CurlMsgType::VARIANTS.len(), 3);
    }

    /// The C enumeration is a struct field of `CURLMsg`, where a C `enum` is
    /// `int`-sized. That is what puts `easy_handle` at offset 8 rather than 4,
    /// so the width is part of the layout contract.
    #[test]
    fn curlmsg_is_int_sized_and_int_aligned() {
        assert_eq!(
            core::mem::size_of::<CurlMsgType>(),
            core::mem::size_of::<i32>(),
            "the CURLMSG field of struct CURLMsg is int-sized"
        );
        assert_eq!(
            core::mem::align_of::<CurlMsgType>(),
            core::mem::align_of::<i32>()
        );
    }

    /// The spellings, not just the numbers.
    #[test]
    fn curlmsg_spellings_are_the_header_spellings() {
        assert_eq!(CurlMsgType::None.c_name(), "CURLMSG_NONE");
        assert_eq!(CurlMsgType::Done.c_name(), "CURLMSG_DONE");
        assert_eq!(CurlMsgType::Last.c_name(), "CURLMSG_LAST");
    }

    /// The inbound half of the ABI boundary: every member round-trips and
    /// nothing outside the enumeration is accepted.
    #[test]
    fn curlmsg_from_i32_round_trips_and_rejects_the_rest() {
        for member in CurlMsgType::VARIANTS {
            assert_eq!(CurlMsgType::from_i32(member.as_i32()), Some(*member));
        }
        for raw in [-1, 3, 4, i32::MIN, i32::MAX] {
            assert_eq!(CurlMsgType::from_i32(raw), None);
        }
    }

    /// `include/curl/multi.h:456-474`. All seven, including the two the C
    /// leaves implicit.
    #[test]
    fn curlminfo_offt_discriminants_are_pinned() {
        assert_eq!(CurlMInfoOfft::None as i32, 0);
        assert_eq!(CurlMInfoOfft::XfersCurrent as i32, 1);
        assert_eq!(CurlMInfoOfft::XfersRunning as i32, 2);
        assert_eq!(CurlMInfoOfft::XfersPending as i32, 3);
        assert_eq!(CurlMInfoOfft::XfersDone as i32, 4);
        assert_eq!(CurlMInfoOfft::XfersAdded as i32, 5);
        assert_eq!(CurlMInfoOfft::LastEntry as i32, 6);

        assert_eq!(CurlMInfoOfft::VARIANTS.len(), 7);
        // Contiguous and ascending, which is what makes `LastEntry` usable as
        // a bound the way the header intends.
        for (position, member) in CurlMInfoOfft::VARIANTS.iter().enumerate() {
            assert_eq!(member.as_i32(), i32::try_from(position).unwrap());
        }
    }

    /// The spellings have **no** `_OFFT_` infix.
    ///
    /// This is the test the numbers cannot provide: `CURLMINFO_OFFT_NONE`
    /// would have had the identical value `0`, so only a name check catches
    /// the wrong spelling. The header is the authority and it writes
    /// `CURLMINFO_NONE` and `CURLMINFO_LASTENTRY`.
    #[test]
    fn curlminfo_offt_spellings_carry_no_offt_infix() {
        assert_eq!(CurlMInfoOfft::None.c_name(), "CURLMINFO_NONE");
        assert_eq!(
            CurlMInfoOfft::XfersCurrent.c_name(),
            "CURLMINFO_XFERS_CURRENT"
        );
        assert_eq!(
            CurlMInfoOfft::XfersRunning.c_name(),
            "CURLMINFO_XFERS_RUNNING"
        );
        assert_eq!(
            CurlMInfoOfft::XfersPending.c_name(),
            "CURLMINFO_XFERS_PENDING"
        );
        assert_eq!(CurlMInfoOfft::XfersDone.c_name(), "CURLMINFO_XFERS_DONE");
        assert_eq!(CurlMInfoOfft::XfersAdded.c_name(), "CURLMINFO_XFERS_ADDED");
        assert_eq!(CurlMInfoOfft::LastEntry.c_name(), "CURLMINFO_LASTENTRY");

        for member in CurlMInfoOfft::VARIANTS {
            let name = member.c_name();
            assert!(
                name.starts_with("CURLMINFO_"),
                "{name} is not a CURLMINFO_ token"
            );
            assert!(
                !name.contains("_OFFT_"),
                "{name} carries an _OFFT_ infix that the header does not"
            );
        }
    }

    /// A raw integer outside the enumeration is classified as unknown, which
    /// is what routes it to [`get_offt`]'s default arm.
    #[test]
    fn curlminfo_offt_from_i32_round_trips_and_rejects_the_rest() {
        for member in CurlMInfoOfft::VARIANTS {
            assert_eq!(CurlMInfoOfft::from_i32(member.as_i32()), Some(*member));
        }
        for raw in [-1, 7, 8, 4242, i32::MIN, i32::MAX] {
            assert_eq!(CurlMInfoOfft::from_i32(raw), None);
        }
    }

    /// `include/curl/multi.h:530-531`, `lib/multi_ntfy.c:38` and
    /// `lib/multihandle.h:99-100`.
    #[test]
    fn notification_constants_are_pinned() {
        assert_eq!(CURLMNOTIFY_INFO_READ, 0);
        assert_eq!(CURLMNOTIFY_EASY_DONE, 1);
        // The `+ 1` arithmetic of `lib/multi_ntfy.c:132`, not a literal 2.
        assert_eq!(CURLMNOTIFY_COUNT, CURLMNOTIFY_EASY_DONE + 1);
        assert_eq!(CURLMNOTIFY_COUNT, 2);
        assert_eq!(CURL_MNTFY_CHUNK_SIZE, 128);
        assert_eq!(ADMIN_MID, 0);
        // `EASY_DONE` is the highest valid type, which is what both range
        // tests are written against.
        assert_eq!(
            CURLMNOTIFY_EASY_DONE,
            CURLMNOTIFY_COUNT - 1,
            "the enable/disable bound must be the last valid type"
        );
    }

    /// The `#[repr(C)]` `CURLMsg` and its layout assertion are delegated, and
    /// this proves the delegation was honoured rather than merely intended.
    ///
    /// The agent brief for this file requires a layout assertion -- size 24,
    /// alignment 8, field offsets 0, 8 and 16 on a 64-bit target -- *wherever*
    /// the `#[repr(C)]` struct ends up, and forbids leaving it unassigned.
    /// It ends up in `curl-rs-ffi/src/ffi/handle.rs`, because that struct
    /// holds a raw `CURL *` and a union, and because a second declaration of
    /// the name would make cbindgen emit two conflicting C declarations and
    /// fail all 129 `docs/examples` programs. `core::mem::offset_of!` is
    /// unavailable to this crate in any case: it stabilised in Rust 1.77 and
    /// the MSRV is 1.75, which is why that file computes the offsets itself.
    #[test]
    #[cfg_attr(miri, ignore = "this reads the source tree, not the program")]
    fn the_curlmsg_layout_assertion_lives_in_the_abi_crate() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("this crate's directory has a parent, the workspace root")
            .join("curl-rs-ffi")
            .join("src")
            .join("ffi")
            .join("handle.rs");
        let text = std::fs::read_to_string(&path).unwrap_or_else(|error| {
            panic!(
                "{} must exist and carry the CURLMsg layout assertion: {error}",
                path.display()
            )
        });

        // The five facts the C struct fixes on a 64-bit target. Matched on the
        // asserted values rather than on whole lines, so reformatting the file
        // cannot break this while a changed number still does.
        for fragment in [
            "shape!(CURLMsg, 24, 8)",
            "offset!(CURLMsg, msg), 0",
            "offset!(CURLMsg, easy_handle), 8",
            "offset!(CURLMsg, data), 16",
        ] {
            assert!(
                text.contains(fragment),
                "{} no longer asserts `{fragment}`; the CURLMsg layout \
                 assertion this module delegates to it has been lost",
                path.display()
            );
        }
    }

    // The frozen trace lines

    /// The two format strings are byte-identical to the C's.
    #[test]
    fn trace_formats_are_byte_identical_to_the_c() {
        assert_eq!(TRACE_FORMAT_ADD, "[NTFY] add %u for xfer %u");
        assert_eq!(TRACE_FORMAT_DISPATCH, "[NTFY] dispatch %u to xfer %u");
    }

    /// The rendering is a positional substitution of the frozen format, and
    /// not a paraphrase of it.
    #[test]
    fn trace_rendering_substitutes_the_frozen_format_positionally() {
        for event in [
            NotifyEvent::Add {
                notification: CURLMNOTIFY_INFO_READ,
                mid: 0,
            },
            NotifyEvent::Add {
                notification: CURLMNOTIFY_EASY_DONE,
                mid: 7,
            },
            NotifyEvent::Dispatch {
                notification: 0,
                mid: ADMIN_MID,
            },
            NotifyEvent::Dispatch {
                notification: 1,
                mid: 4_294_967_295,
            },
        ] {
            let (first, second) = match event {
                NotifyEvent::Add { notification, mid }
                | NotifyEvent::Dispatch { notification, mid } => {
                    (notification, mid)
                }
            };
            let expected = event
                .c_format()
                .replacen("%u", &first.to_string(), 1)
                .replacen("%u", &second.to_string(), 1);
            assert_eq!(event.to_string(), expected);
            assert!(!event.to_string().contains('%'));
        }
    }

    /// Both lines carry the `[NTFY]` tag and no newline: the emitter appends
    /// one, exactly as the crate's tracer macros assert for their own formats.
    #[test]
    fn trace_formats_are_single_tagged_lines() {
        for format in [TRACE_FORMAT_ADD, TRACE_FORMAT_DISPATCH] {
            assert!(format.starts_with("[NTFY] "));
            assert!(!format.contains('\n'));
            assert_eq!(format.matches("%u").count(), 2);
        }
    }

    // The message queue

    /// A `CURLMSG_DONE` message for `mid`, with a distinguishable result.
    fn message(mid: u32) -> CompletionMessage {
        CompletionMessage::done(mid, CURLcode::Ok)
    }

    /// `lib/multi.c:2410-2412` as one value.
    #[test]
    fn a_completion_message_is_always_done() {
        let msg = CompletionMessage::done(9, CURLcode::CouldntConnect);
        assert_eq!(msg.which, CurlMsgType::Done);
        assert_eq!(msg.mid, 9);
        assert_eq!(msg.result, CURLcode::CouldntConnect);
    }

    /// `Curl_llist_init(&multi->msglist, NULL)` (`lib/multi.c:252`).
    #[test]
    fn a_new_queue_is_empty() {
        let queue = MessageQueue::new();
        assert!(queue.is_empty());
        assert_eq!(queue.len(), 0);
        assert_eq!(MessageQueue::default().len(), 0);
    }

    /// Append at the tail (`lib/multi.c:226`), take from the head (`:2957`),
    /// so completion order is delivery order.
    #[test]
    fn the_queue_is_strict_fifo() {
        let mut queue = MessageQueue::new();
        for mid in [11, 22, 33] {
            queue.push(message(mid));
        }

        let mut seen = Vec::new();
        while let Some(read) = queue.read() {
            seen.push(read.message.mid);
        }
        assert_eq!(seen, vec![11, 22, 33]);
    }

    /// The off-by-one guard: `*msgs_in_queue` is the count that REMAINS after
    /// the removal (`lib/multi.c:2964`), and a read of an empty queue yields
    /// nothing at all -- which the shim renders as the same `NULL` a bad
    /// handle produces, with zero written (`:2948`, `:2968`).
    #[test]
    fn msgs_in_queue_is_the_remaining_count() {
        let mut queue = MessageQueue::new();
        for mid in [1, 2, 3] {
            queue.push(message(mid));
        }

        for expected in [2, 1, 0] {
            let read = queue.read().expect("a message is queued");
            assert_eq!(
                read.msgs_in_queue, expected,
                "applications loop on this number"
            );
        }
        assert!(queue.read().is_none());
        assert!(queue.is_empty());
    }

    /// A message is consumed exactly once. There is no peek in the public API,
    /// and this is what would fail if one were added and used here.
    #[test]
    fn a_message_is_consumed_exactly_once() {
        let mut queue = MessageQueue::new();
        queue.push(message(5));
        assert_eq!(queue.read().expect("queued").message.mid, 5);
        assert!(queue.read().is_none());
    }

    /// `lib/multi.c:224` tests emptiness BEFORE `:226` appends, so only the
    /// first append onto an empty queue reports the edge -- and the edge
    /// re-arms once the queue drains, because the C derives it from the live
    /// count rather than from a latch.
    #[test]
    fn the_notification_edge_fires_only_on_empty_to_non_empty() {
        let mut queue = MessageQueue::new();

        assert!(queue.push(message(1)), "empty -> non-empty");
        assert!(!queue.push(message(2)), "already non-empty");
        assert!(!queue.push(message(3)), "still non-empty");

        while queue.read().is_some() {}
        assert!(queue.is_empty());

        assert!(queue.push(message(4)), "the edge re-arms once drained");
        assert!(!queue.push(message(5)));
    }

    /// `lib/multi.c:855-865`: the purge inside `curl_multi_remove_handle`
    /// takes at most one message and stops, because "there can only be one
    /// from this specific handle".
    #[test]
    fn removing_a_handles_message_takes_at_most_one() {
        let mut queue = MessageQueue::new();
        for mid in [1, 2, 3] {
            queue.push(message(mid));
        }

        assert!(queue.remove_first_for(2));
        assert_eq!(queue.len(), 2);
        assert!(!queue.remove_first_for(2), "it is gone");
        assert!(!queue.remove_first_for(99), "never queued");

        // Order among the survivors is untouched, as `Curl_node_remove`
        // leaves the rest of the chain in place.
        let mut seen = Vec::new();
        while let Some(read) = queue.read() {
            seen.push(read.message.mid);
        }
        assert_eq!(seen, vec![1, 3]);
    }

    /// The `break` is transcribed rather than generalised: even if the
    /// one-message-per-mid invariant were violated, this removes one.
    #[test]
    fn removing_a_handles_message_does_not_purge_duplicates() {
        let mut queue = MessageQueue::new();
        queue.push(message(7));
        queue.push(message(7));

        assert!(queue.remove_first_for(7));
        assert_eq!(queue.len(), 1, "the C breaks after the first match");
    }

    /// Emptying the queue through the purge re-arms the edge just as reading
    /// it does, because both are the same live count.
    #[test]
    fn the_purge_re_arms_the_notification_edge() {
        let mut queue = MessageQueue::new();
        assert!(queue.push(message(1)));
        assert!(queue.remove_first_for(1));
        assert!(queue.is_empty());
        assert!(queue.push(message(2)), "the edge re-arms after a purge too");
    }

    // The notification subsystem

    /// A [`NotifySink`] that records everything and can queue during dispatch.
    #[derive(Debug, Default)]
    struct Recorder {
        /// Non-zero `mid`s that resolve to a live transfer. `ADMIN_MID`
        /// always resolves, mirroring the C's ternary.
        live: Vec<u32>,
        /// Whether the multi handle still has an admin handle at all.
        admin_present: bool,
        /// Every trace line, in order.
        traced: Vec<NotifyEvent>,
        /// Every delivery, as `(notification, mid)`, in order.
        delivered: Vec<(u32, u32)>,
        /// Queued from inside the next delivery, once, to exercise the
        /// re-entrancy the C annotates "this may cause new notifications to
        /// be added!".
        queue_during_delivery: Option<(u32, u32)>,
    }

    impl Recorder {
        /// A recorder with an admin handle and the given live transfers.
        fn with_live(live: &[u32]) -> Self {
            Self {
                live: live.to_vec(),
                admin_present: true,
                ..Self::default()
            }
        }

        /// Only the `Add` lines, in order.
        fn added(&self) -> Vec<(u32, u32)> {
            self.traced
                .iter()
                .filter_map(|event| match *event {
                    NotifyEvent::Add { notification, mid } => {
                        Some((notification, mid))
                    }
                    NotifyEvent::Dispatch { .. } => None,
                })
                .collect()
        }

        /// Only the `Dispatch` lines, in order.
        fn dispatched(&self) -> Vec<(u32, u32)> {
            self.traced
                .iter()
                .filter_map(|event| match *event {
                    NotifyEvent::Dispatch { notification, mid } => {
                        Some((notification, mid))
                    }
                    NotifyEvent::Add { .. } => None,
                })
                .collect()
        }
    }

    impl NotifyTracer for Recorder {
        fn trace(&mut self, event: NotifyEvent) {
            self.traced.push(event);
        }
    }

    impl NotifySink for Recorder {
        fn resolves(&self, mid: u32) -> bool {
            // `e->mid ? Curl_multi_get_easy(multi, e->mid) : multi->admin`
            // (`lib/multi_ntfy.c:109`): mid 0 is the admin handle.
            if mid == ADMIN_MID {
                self.admin_present
            } else {
                self.live.contains(&mid)
            }
        }

        fn deliver(
            &mut self,
            notify: &mut MultiNotify,
            notification: u32,
            mid: u32,
        ) {
            self.delivered.push((notification, mid));
            if let Some((next_mid, next_type)) =
                self.queue_during_delivery.take()
            {
                notify.add(next_mid, next_type, self);
            }
        }
    }

    /// A subsystem with a callback installed, sized, and both types enabled.
    fn armed() -> MultiNotify {
        let mut notify = MultiNotify::new();
        assert_eq!(notify.resize(), CURLMcode::Ok);
        notify.set_callback_installed(true);
        assert_eq!(notify.enable(CURLMNOTIFY_INFO_READ), CURLMcode::Ok);
        assert_eq!(notify.enable(CURLMNOTIFY_EASY_DONE), CURLMcode::Ok);
        notify
    }

    /// `Curl_mntfy_init` zeroes the struct, and a zeroed bitset holds nothing:
    /// **no notification type is enabled by default**
    /// (`lib/multi_ntfy.c:124-128`).
    #[test]
    fn nothing_is_enabled_before_the_application_asks() {
        let notify = MultiNotify::new();
        assert!(!notify.is_enabled(CURLMNOTIFY_INFO_READ));
        assert!(!notify.is_enabled(CURLMNOTIFY_EASY_DONE));
        assert!(!notify.callback_installed());
        assert!(!notify.has_entries());
        assert!(!notify.in_callback());
        assert_eq!(notify.failure(), CURLMcode::Ok);
        assert_eq!(MultiNotify::default().failure(), CURLMcode::Ok);
    }

    /// `Curl_mntfy_resize` sizes the set for `CURLMNOTIFY_EASY_DONE + 1`
    /// (`lib/multi_ntfy.c:130-135`), and is idempotent.
    #[test]
    fn resize_makes_room_for_every_notification_type() {
        let mut notify = MultiNotify::new();
        assert_eq!(notify.resize(), CURLMcode::Ok);
        assert_eq!(notify.resize(), CURLMcode::Ok, "idempotent");

        for notification in 0..CURLMNOTIFY_COUNT {
            assert_eq!(notify.enable(notification), CURLMcode::Ok);
            assert!(notify.is_enabled(notification));
        }
    }

    /// `type > CURLMNOTIFY_EASY_DONE` yields `CURLM_UNKNOWN_OPTION` -- **not**
    /// `CURLM_BAD_FUNCTION_ARGUMENT` -- from both entry points
    /// (`lib/multi_ntfy.c:150-151` and `:158-159`).
    #[test]
    fn an_out_of_range_notification_type_is_an_unknown_option() {
        let mut notify = armed();
        for notification in [2, 3, 100, u32::MAX] {
            assert_eq!(
                notify.enable(notification),
                CURLMcode::UnknownOption,
                "curl_multi_notify_enable({notification})"
            );
            assert_eq!(
                notify.disable(notification),
                CURLMcode::UnknownOption,
                "curl_multi_notify_disable({notification})"
            );
        }
    }

    /// `Curl_uint32_bset_add` reports "was in range", not "was newly
    /// inserted", and the C discards it: enabling twice is a success both
    /// times. Returning `HashSet::insert`'s boolean would have inverted this.
    #[test]
    fn enabling_is_idempotent_and_disabling_is_forgiving() {
        let mut notify = MultiNotify::new();
        assert_eq!(notify.resize(), CURLMcode::Ok);

        assert_eq!(notify.enable(CURLMNOTIFY_EASY_DONE), CURLMcode::Ok);
        assert_eq!(notify.enable(CURLMNOTIFY_EASY_DONE), CURLMcode::Ok);
        assert!(notify.is_enabled(CURLMNOTIFY_EASY_DONE));

        // Never enabled, and disabling it is still a success: the C's
        // `Curl_uint32_bset_remove` returns nothing.
        assert_eq!(notify.disable(CURLMNOTIFY_INFO_READ), CURLMcode::Ok);
        assert_eq!(notify.disable(CURLMNOTIFY_EASY_DONE), CURLMcode::Ok);
        assert_eq!(notify.disable(CURLMNOTIFY_EASY_DONE), CURLMcode::Ok);
        assert!(!notify.is_enabled(CURLMNOTIFY_EASY_DONE));
    }

    /// All four conditions of `Curl_mntfy_add` (`lib/multi_ntfy.c:167-168`),
    /// each failed in turn. Every failure is a complete no-op: no entry, no
    /// trace line, `has_entries` untouched.
    #[test]
    fn queueing_requires_all_four_conditions() {
        // (1) No callback installed.
        let mut notify = MultiNotify::new();
        assert_eq!(notify.resize(), CURLMcode::Ok);
        assert_eq!(notify.enable(CURLMNOTIFY_EASY_DONE), CURLMcode::Ok);
        let mut sink = Recorder::with_live(&[3]);
        notify.add(3, CURLMNOTIFY_EASY_DONE, &mut sink);
        assert!(!notify.has_entries(), "no callback, no entry");
        assert!(sink.traced.is_empty(), "no callback, no trace line");

        // (2) The type is not enabled.
        let mut notify = MultiNotify::new();
        assert_eq!(notify.resize(), CURLMcode::Ok);
        notify.set_callback_installed(true);
        notify.add(3, CURLMNOTIFY_EASY_DONE, &mut sink);
        assert!(!notify.has_entries(), "type disabled, no entry");
        assert!(sink.traced.is_empty());

        // (3) A failure is already latched.
        let mut notify = armed();
        notify.set_fail_chunk_allocation(true);
        notify.add(3, CURLMNOTIFY_EASY_DONE, &mut sink);
        assert_eq!(notify.failure(), CURLMcode::OutOfMemory);
        let after_latch = sink.traced.len();
        notify.set_fail_chunk_allocation(false);
        notify.add(4, CURLMNOTIFY_EASY_DONE, &mut sink);
        assert_eq!(
            sink.traced.len(),
            after_latch,
            "a latched failure suppresses further queueing entirely"
        );

        // (4) Everything in place: the entry is queued and traced.
        let mut notify = armed();
        let mut sink = Recorder::with_live(&[3]);
        notify.add(3, CURLMNOTIFY_EASY_DONE, &mut sink);
        assert!(notify.has_entries());
        assert_eq!(sink.added(), vec![(CURLMNOTIFY_EASY_DONE, 3)]);
    }

    /// `lib/multi_ntfy.c:170-176`: on an allocation failure the C still emits
    /// the trace line and still sets `has_entries`, and it latches
    /// `CURLM_OUT_OF_MEMORY`.
    #[test]
    fn a_failed_append_still_traces_and_still_marks_work_pending() {
        let mut notify = armed();
        let mut sink = Recorder::with_live(&[8]);
        notify.set_fail_chunk_allocation(true);

        notify.add(8, CURLMNOTIFY_EASY_DONE, &mut sink);

        assert_eq!(
            sink.added(),
            vec![(CURLMNOTIFY_EASY_DONE, 8)],
            "the trace line precedes the append and survives its failure"
        );
        assert_eq!(notify.failure(), CURLMcode::OutOfMemory);
        assert!(
            notify.has_entries(),
            "set outside the `if(tail)`, so the failure reaches dispatch"
        );
    }

    /// `lib/multi_ntfy.c:199-206`: the failure is returned once and then
    /// cleared, and `has_entries` is deliberately LEFT SET so the next cycle
    /// retries. Only the success arm clears it.
    #[test]
    fn a_failure_is_reported_once_and_leaves_work_pending() {
        let mut notify = armed();
        let mut sink = Recorder::with_live(&[8]);
        notify.set_fail_chunk_allocation(true);
        notify.add(8, CURLMNOTIFY_EASY_DONE, &mut sink);
        notify.set_fail_chunk_allocation(false);

        assert_eq!(notify.dispatch_all(&mut sink), CURLMcode::OutOfMemory);
        assert_eq!(notify.failure(), CURLMcode::Ok, "reset once delivered");
        assert!(
            notify.has_entries(),
            "not cleared on the failure path, so the next cycle retries"
        );
        assert!(!notify.in_callback(), "cleared before the failure is read");

        // The retry finds nothing to do, succeeds, and only now clears it.
        assert_eq!(notify.dispatch_all(&mut sink), CURLMcode::Ok);
        assert!(!notify.has_entries());
    }

    /// The `INFO_READ` notification is attributed to the admin handle -- mid
    /// 0 -- and not to the transfer that completed (`lib/multi.c:225`), and
    /// dispatch resolves that mid back to the admin handle
    /// (`lib/multi_ntfy.c:109`).
    #[test]
    fn info_read_is_attributed_to_the_admin_handle() {
        let mut queue = MessageQueue::new();
        let mut notify = armed();
        // The completing transfer is mid 42, and it deliberately does NOT
        // resolve: only the admin handle does. If the notification were
        // attributed to the transfer, nothing would be delivered at all.
        let mut sink = Recorder::with_live(&[]);

        if queue.push(message(42)) {
            notify.add(ADMIN_MID, CURLMNOTIFY_INFO_READ, &mut sink);
        }

        assert_eq!(sink.added(), vec![(CURLMNOTIFY_INFO_READ, ADMIN_MID)]);
        assert_eq!(notify.dispatch_all(&mut sink), CURLMcode::Ok);
        assert_eq!(
            sink.delivered,
            vec![(CURLMNOTIFY_INFO_READ, ADMIN_MID)],
            "the application receives the admin handle, mid 0"
        );
        assert_eq!(sink.dispatched(), vec![(CURLMNOTIFY_INFO_READ, ADMIN_MID)]);
    }

    /// The whole of `multi_addmsg` (`lib/multi.c:216-227`): exactly one
    /// notification for the first message, none for the second and third, and
    /// a fresh one once the queue has drained.
    #[test]
    fn only_the_first_queued_message_notifies() {
        let mut queue = MessageQueue::new();
        let mut notify = armed();
        let mut sink = Recorder::with_live(&[]);

        for mid in [1, 2, 3] {
            if queue.push(message(mid)) {
                notify.add(ADMIN_MID, CURLMNOTIFY_INFO_READ, &mut sink);
            }
        }
        assert_eq!(
            sink.added().len(),
            1,
            "the second and third appends must be silent"
        );

        while queue.read().is_some() {}
        if queue.push(message(4)) {
            notify.add(ADMIN_MID, CURLMNOTIFY_INFO_READ, &mut sink);
        }
        assert_eq!(sink.added().len(), 2, "the edge re-armed once drained");
    }

    /// `lib/multi_ntfy.c:109-111`: an entry whose non-zero mid no longer
    /// resolves is skipped -- and still consumed, because `r_offset++` is
    /// outside the `if`.
    #[test]
    fn an_unresolvable_mid_is_skipped_and_still_consumed() {
        let mut notify = armed();
        let mut sink = Recorder::with_live(&[5]);
        notify.add(5, CURLMNOTIFY_EASY_DONE, &mut sink);
        notify.add(6, CURLMNOTIFY_EASY_DONE, &mut sink);

        assert_eq!(notify.dispatch_all(&mut sink), CURLMcode::Ok);
        assert_eq!(
            sink.delivered,
            vec![(CURLMNOTIFY_EASY_DONE, 5)],
            "mid 6 does not resolve"
        );

        // Consumed, not retried: a second cycle delivers nothing.
        let before = sink.delivered.len();
        assert_eq!(notify.dispatch_all(&mut sink), CURLMcode::Ok);
        assert_eq!(sink.delivered.len(), before);
    }

    /// Membership is re-tested at dispatch time, per the C's comment "only
    /// when notification has not been disabled in the meantime"
    /// (`lib/multi_ntfy.c:110-111`). An entry queued while enabled is skipped
    /// if the type was disabled since -- and is still consumed.
    #[test]
    fn a_type_disabled_after_queueing_is_not_dispatched() {
        let mut notify = armed();
        let mut sink = Recorder::with_live(&[5, 6]);
        notify.add(5, CURLMNOTIFY_EASY_DONE, &mut sink);
        notify.add(6, CURLMNOTIFY_INFO_READ, &mut sink);

        assert_eq!(notify.disable(CURLMNOTIFY_EASY_DONE), CURLMcode::Ok);
        assert_eq!(notify.dispatch_all(&mut sink), CURLMcode::Ok);

        assert_eq!(
            sink.delivered,
            vec![(CURLMNOTIFY_INFO_READ, 6)],
            "the EASY_DONE entry was queued but is no longer wanted"
        );
        assert!(!notify.has_entries());
    }

    /// Clearing the callback stops dispatch without discarding what is
    /// queued: the C skips the loop (`lib/multi_ntfy.c:106`) but still resets
    /// the chunk (`:121`).
    #[test]
    fn clearing_the_callback_stops_delivery() {
        let mut notify = armed();
        let mut sink = Recorder::with_live(&[5]);
        notify.add(5, CURLMNOTIFY_EASY_DONE, &mut sink);

        notify.set_callback_installed(false);
        assert_eq!(notify.dispatch_all(&mut sink), CURLMcode::Ok);
        assert!(sink.delivered.is_empty());
        assert!(
            !notify.has_entries(),
            "the success arm still clears the flag"
        );
    }

    /// `in_ntfy_callback` is set for the duration of a cycle and cleared
    /// afterwards (`lib/multi_ntfy.c:183`, `:197`). The multi handle returns
    /// `CURLM_RECURSIVE_API_CALL` while it holds.
    #[test]
    fn the_dispatch_flag_is_set_only_during_a_cycle() {
        /// Asserts the flag from inside the callback, which is the only place
        /// it is ever true.
        #[derive(Debug, Default)]
        struct FlagWatcher {
            seen_inside: bool,
        }
        impl NotifyTracer for FlagWatcher {
            fn trace(&mut self, _event: NotifyEvent) {}
        }
        impl NotifySink for FlagWatcher {
            fn resolves(&self, _mid: u32) -> bool {
                true
            }
            fn deliver(
                &mut self,
                notify: &mut MultiNotify,
                _notification: u32,
                _mid: u32,
            ) {
                assert!(notify.in_callback(), "true for the whole cycle");
                self.seen_inside = true;
            }
        }

        let mut notify = armed();
        let mut sink = FlagWatcher::default();
        assert!(!notify.in_callback());
        notify.add(1, CURLMNOTIFY_EASY_DONE, &mut sink);
        assert!(!notify.in_callback(), "queueing is not a cycle");

        assert_eq!(notify.dispatch_all(&mut sink), CURLMcode::Ok);
        assert!(sink.seen_inside, "the callback really ran");
        assert!(!notify.in_callback());
    }

    /// "This may cause new notifications to be added!"
    /// (`lib/multi_ntfy.c:112`, `:186`). The new entry is delivered in the
    /// same cycle, and nothing is delivered twice.
    #[test]
    fn a_callback_may_queue_during_dispatch() {
        let mut notify = armed();
        let mut sink = Recorder::with_live(&[1, 2]);
        sink.queue_during_delivery = Some((2, CURLMNOTIFY_INFO_READ));

        notify.add(1, CURLMNOTIFY_EASY_DONE, &mut sink);
        assert_eq!(notify.dispatch_all(&mut sink), CURLMcode::Ok);

        assert_eq!(
            sink.delivered,
            vec![(CURLMNOTIFY_EASY_DONE, 1), (CURLMNOTIFY_INFO_READ, 2)],
            "the entry queued during dispatch is delivered in this cycle"
        );
        assert!(!notify.has_entries());

        // Nothing is delivered twice, which the cursor discipline guarantees:
        // `r_offset` advances only after the callback returns.
        let before = sink.delivered.len();
        assert_eq!(notify.dispatch_all(&mut sink), CURLMcode::Ok);
        assert_eq!(sink.delivered.len(), before);
    }

    /// More than one chunk: the tail is kept and reused while earlier chunks
    /// are dropped (`lib/multi_ntfy.c:190-195`). Every entry is delivered
    /// exactly once and in order.
    #[test]
    fn a_multi_chunk_run_delivers_every_entry_exactly_once() {
        let count = u32::try_from(CURL_MNTFY_CHUNK_SIZE).unwrap() * 2 + 5;
        let live: Vec<u32> = (1..=count).collect();

        let mut notify = armed();
        let mut sink = Recorder::with_live(&live);
        for mid in &live {
            notify.add(*mid, CURLMNOTIFY_EASY_DONE, &mut sink);
        }

        assert_eq!(notify.dispatch_all(&mut sink), CURLMcode::Ok);

        let expected: Vec<(u32, u32)> = live
            .iter()
            .map(|mid| (CURLMNOTIFY_EASY_DONE, *mid))
            .collect();
        assert_eq!(sink.delivered, expected);
        assert!(!notify.has_entries());

        // Reusable afterwards: the kept tail takes the next entry.
        notify.add(1, CURLMNOTIFY_EASY_DONE, &mut sink);
        assert!(notify.has_entries());
        assert_eq!(notify.dispatch_all(&mut sink), CURLMcode::Ok);
        assert_eq!(sink.delivered.len(), expected.len() + 1);
    }

    /// A run that exactly fills one chunk, which is the boundary the C's
    /// `w_offset >= CURL_MNTFY_CHUNK_SIZE` test guards
    /// (`lib/multi_ntfy.c:68`).
    #[test]
    fn a_run_of_exactly_one_chunk_is_delivered_whole() {
        let count = u32::try_from(CURL_MNTFY_CHUNK_SIZE).unwrap();
        let live: Vec<u32> = (1..=count).collect();

        let mut notify = armed();
        let mut sink = Recorder::with_live(&live);
        for mid in &live {
            notify.add(*mid, CURLMNOTIFY_EASY_DONE, &mut sink);
        }

        assert_eq!(notify.dispatch_all(&mut sink), CURLMcode::Ok);
        assert_eq!(sink.delivered.len(), CURL_MNTFY_CHUNK_SIZE);
    }

    /// Dispatching an empty subsystem is a success and clears the flag.
    #[test]
    fn dispatching_nothing_succeeds() {
        let mut notify = armed();
        let mut sink = Recorder::with_live(&[]);
        assert_eq!(notify.dispatch_all(&mut sink), CURLMcode::Ok);
        assert!(!notify.has_entries());
        assert!(sink.delivered.is_empty());
    }

    // `curl_multi_get_offt`

    /// Counters resembling a live multi handle: four transfers plus the admin
    /// handle, which occupies a table slot and a `process` membership of its
    /// own (`lib/multi.c:278-279`).
    fn counters() -> MultiCounters {
        MultiCounters {
            xfers: 5,
            admin_present: true,
            process: 3,
            process_has_admin: true,
            pending: 2,
            msgsent: 1,
            xfers_total_ever: 17,
        }
    }

    /// The two admin adjustments of `lib/multi.c:3760-3771`.
    #[test]
    fn the_admin_handle_is_not_reported_to_the_application() {
        let counters = counters();
        let mut value = 0_i64;

        assert_eq!(
            get_offt(
                CurlMInfoOfft::XfersCurrent.as_i32(),
                &counters,
                &mut value
            ),
            CURLMcode::Ok
        );
        assert_eq!(value, 4, "5 in the table, minus the admin handle");

        assert_eq!(
            get_offt(
                CurlMInfoOfft::XfersRunning.as_i32(),
                &counters,
                &mut value
            ),
            CURLMcode::Ok
        );
        assert_eq!(value, 2, "3 in `process`, minus the admin handle");
    }

    /// The same two selectors when there is no admin handle to discount --
    /// which is why the C tests rather than assumes (`lib/multi.c:3762`,
    /// `:3768`).
    #[test]
    fn without_an_admin_handle_nothing_is_subtracted() {
        let counters = MultiCounters {
            admin_present: false,
            process_has_admin: false,
            ..counters()
        };
        let mut value = 0_i64;

        assert_eq!(
            get_offt(
                CurlMInfoOfft::XfersCurrent.as_i32(),
                &counters,
                &mut value
            ),
            CURLMcode::Ok
        );
        assert_eq!(value, 5);

        assert_eq!(
            get_offt(
                CurlMInfoOfft::XfersRunning.as_i32(),
                &counters,
                &mut value
            ),
            CURLMcode::Ok
        );
        assert_eq!(value, 3);
    }

    /// `if(n && ...)` in the C guards both subtractions against a zero count
    /// (`lib/multi.c:3762`, `:3768`); `saturating_sub` is the same guard.
    #[test]
    fn a_zero_count_never_underflows() {
        let counters = MultiCounters {
            xfers: 0,
            admin_present: true,
            process: 0,
            process_has_admin: true,
            ..MultiCounters::default()
        };
        let mut value = -7_i64;

        for info in [CurlMInfoOfft::XfersCurrent, CurlMInfoOfft::XfersRunning] {
            assert_eq!(
                get_offt(info.as_i32(), &counters, &mut value),
                CURLMcode::Ok
            );
            assert_eq!(value, 0, "{}", info.c_name());
        }
    }

    /// The three selectors the C reports unadjusted
    /// (`lib/multi.c:3772-3780`).
    #[test]
    fn the_unadjusted_selectors_report_their_counters_verbatim() {
        let counters = counters();
        let mut value = 0_i64;

        for (info, expected) in [
            (CurlMInfoOfft::XfersPending, 2),
            (CurlMInfoOfft::XfersDone, 1),
            (CurlMInfoOfft::XfersAdded, 17),
        ] {
            assert_eq!(
                get_offt(info.as_i32(), &counters, &mut value),
                CURLMcode::Ok,
                "{}",
                info.c_name()
            );
            assert_eq!(value, expected, "{}", info.c_name());
        }
    }

    /// `xfers_total_ever` is already a `curl_off_t`, so it is reported without
    /// widening and a large value survives intact.
    #[test]
    fn the_ever_added_counter_is_a_full_width_offset() {
        let counters = MultiCounters {
            xfers_total_ever: i64::from(u32::MAX) + 1,
            ..counters()
        };
        let mut value = 0_i64;
        assert_eq!(
            get_offt(CurlMInfoOfft::XfersAdded.as_i32(), &counters, &mut value),
            CURLMcode::Ok
        );
        assert_eq!(value, 4_294_967_296);
    }

    /// The default arm writes `-1` **and** returns `CURLM_UNKNOWN_OPTION`
    /// (`lib/multi.c:3781-3783`). Both halves, for `CURLMINFO_NONE`, for
    /// `CURLMINFO_LASTENTRY`, and for every integer outside the enumeration.
    #[test]
    fn an_unknown_selector_writes_minus_one_and_reports_unknown_option() {
        let counters = counters();

        let named = [CurlMInfoOfft::None, CurlMInfoOfft::LastEntry];
        for info in named {
            let mut value = 12_345_i64;
            assert_eq!(
                get_offt(info.as_i32(), &counters, &mut value),
                CURLMcode::UnknownOption,
                "{}",
                info.c_name()
            );
            assert_eq!(value, -1, "{} must also write -1", info.c_name());
        }

        for raw in [-1, 7, 8, 999, i32::MIN, i32::MAX] {
            let mut value = 12_345_i64;
            assert_eq!(
                get_offt(raw, &counters, &mut value),
                CURLMcode::UnknownOption,
                "raw selector {raw}"
            );
            assert_eq!(value, -1, "raw selector {raw} must also write -1");
        }
    }

    /// The five real selectors are exactly the five the C `switch` names, so
    /// `NONE` and `LASTENTRY` are the only members that fall through.
    #[test]
    fn exactly_five_selectors_are_answerable() {
        let counters = counters();
        let answered = CurlMInfoOfft::VARIANTS
            .iter()
            .filter(|info| {
                let mut value = 0_i64;
                get_offt(info.as_i32(), &counters, &mut value).is_ok()
            })
            .count();
        assert_eq!(answered, 5, "lib/multi.c:3759-3784 names five cases");
    }

    /// Reading a message does not change `XFERS_DONE`: the counter tracks
    /// `msgsent` membership, and a transfer leaves `msgsent` only on removal
    /// from the multi handle (`lib/multi.c:874`), never on a read
    /// (`lib/multi.c:2943-2969` touches only `msglist`).
    #[test]
    fn reading_a_message_does_not_decrement_xfers_done() {
        let mut queue = MessageQueue::new();
        let mut counters = MultiCounters {
            msgsent: 0,
            ..counters()
        };

        // Two transfers complete: each posts a message and joins `msgsent`,
        // which is what `handle_completed` does (`lib/multi.c:2414`, `:2423`).
        for mid in [10, 11] {
            queue.push(message(mid));
            counters.msgsent += 1;
        }

        let mut value = 0_i64;
        assert_eq!(
            get_offt(CurlMInfoOfft::XfersDone.as_i32(), &counters, &mut value),
            CURLMcode::Ok
        );
        assert_eq!(value, 2);
        assert_eq!(queue.len(), 2, "posted messages and msgsent agree here");

        // Drain the queue. `msgsent` is untouched, so the counter is too.
        while queue.read().is_some() {}
        assert!(queue.is_empty());
        assert_eq!(
            get_offt(CurlMInfoOfft::XfersDone.as_i32(), &counters, &mut value),
            CURLMcode::Ok
        );
        assert_eq!(
            value, 2,
            "reading results does not move a transfer out of msgsent"
        );
    }

    /// A sub-transfer joins `msgsent` without posting a message
    /// (`lib/multi.c:2389-2405`, "A sub transfer, not for msgsent to
    /// application", then `:2423`), so `XFERS_DONE` may exceed the queue's
    /// length. Stated as a test so the two numbers are never conflated.
    #[test]
    fn xfers_done_may_exceed_the_number_of_queued_messages() {
        let mut queue = MessageQueue::new();
        queue.push(message(10));
        // mid 11 is a sub-transfer: `msgsent` gains it, the queue does not.
        let counters = MultiCounters {
            msgsent: 2,
            ..counters()
        };

        let mut value = 0_i64;
        assert_eq!(
            get_offt(CurlMInfoOfft::XfersDone.as_i32(), &counters, &mut value),
            CURLMcode::Ok
        );
        assert_eq!(value, 2);
        assert_eq!(queue.len(), 1);
        assert!(
            value >= i64::try_from(queue.len()).unwrap(),
            "msgsent is a superset of the transfers with a queued message"
        );
    }

    // Source-policy guards for this file

    /// This file contains no `unsafe`, no C scalar width and no reference to
    /// the misspelt `CURLMINFO_OFFT_` tokens, in code.
    #[test]
    #[cfg_attr(miri, ignore = "this reads the source tree, not the program")]
    fn this_file_honours_its_own_grep_gates() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("multi")
            .join("notify.rs");
        let text = std::fs::read_to_string(&path).expect("this file");

        // Spliced from fragments so that none of the forbidden tokens appears
        // contiguously in this file's own code. Writing them as plain literals
        // would make the scan below report itself, which is exactly the kind
        // of self-reference an anchored grep gate has to avoid.
        let forbidden = [
            concat!("un", "safe"),
            concat!("c_", "int"),
            concat!("c_", "uint"),
            concat!("c_", "long"),
            concat!("CURLMINFO", "_OFFT_"),
        ];

        let mut offenders = Vec::new();
        for (number, line) in text.lines().enumerate() {
            // Everything before the first `//`, which is how the crate's own
            // gates exclude a line that merely discusses a token. A `//`,
            // `///` or `//!` line yields the empty string.
            let code = line.split("//").next().unwrap_or("");
            for token in forbidden {
                if code.contains(token) {
                    offenders.push(format!("{}: {token}", number + 1));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "notify.rs must not use these in code: {offenders:?}"
        );

        // Non-vacuous: a scan that matched nothing *anywhere* would be a
        // broken scan rather than a clean file, so each token the prose names
        // must still be found somewhere -- in a comment, which is precisely
        // what the anchoring above excludes. The C-scalar family is named as
        // the alternation the documented gate expression uses, not as three
        // separate spellings, so that is the form asserted.
        for discussed in [
            concat!("un", "safe"),
            "c_(int|uint|long)",
            concat!("c_", "uint"),
            concat!("CURLMINFO", "_OFFT_"),
        ] {
            assert!(
                text.contains(discussed),
                "`{discussed}` is no longer discussed anywhere in this file, \
                 so the scan above proves nothing"
            );
        }

        // `reuse` parses every line bearing the licence-identifier tag in its
        // colon form as a licence expression, so a second, prose mention would
        // be a parse error rather than prose.
        let tag = concat!("SPDX-License-", "Identifier:");
        assert_eq!(
            text.matches(tag).count(),
            1,
            "the licence tag must appear exactly once, on line 21"
        );
    }
}
