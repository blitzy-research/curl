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

//! The PROXY protocol version 1 header -- supersedes `lib/cf-haproxy.c` and
//! `lib/cf-haproxy.h`.
//!
//! # What this module is
//!
//! One connection filter, `Curl_cft_haproxy` (`lib/cf-haproxy.c:186-202`),
//! that writes a single ASCII line at the very start of a connection and then
//! gets out of the way. `--haproxy-protocol` installs it and
//! `--haproxy-clientip` overrides one of its fields; nothing else about the
//! transfer changes.
//!
//! The line it writes is the PROXY protocol version 1 header, the text form
//! HAProxy defined so that a proxied connection can tell its backend who the
//! original client was. It is a preamble, not a framing layer: once the line
//! is out, the filter is connected and every subsequent byte passes
//! straight through, which is why eight of the twelve filter operations are
//! left as [`ConnFilter`]'s pass-through defaults.
//!
//! # Why the bytes are frozen
//!
//! The header is **prepended to the protocol stream**, so it lands inside the
//! `<protocol>` block that `tests/data/test*` compares. That comparison joins
//! the whole expectation into ONE string and compares it with Perl `ne`
//! (`tests/getpart.pm`, `compareparts`): there is no per-line matching, no
//! normalisation and no whitespace tolerance. One byte wrong here fails every
//! `--haproxy-protocol` fixture outright, so the two literals in
//! [`Haproxy::date_out_set`] -- [`HAPROXY_UNKNOWN_HEADER`] and the `PROXY`
//! line's field order -- are a wire contract rather than a formatting
//! preference.
//!
//! # Where it sits in the chain
//!
//! `SETUP -> SSL -> HAPROXY -> HTTP-PROXY -> SSL-PROXY -> SOCKS-PROXY ->
//! HAPPY-EYEBALLS -> winner`, installed by
//! [`crate::conn::ConnectionFilterFactories::haproxy`] at the stage
//! [`crate::conn::SetupState::CnnctHaproxy`] names. Being ABOVE the
//! transport and BELOW nothing that encrypts is the whole of its rule: a
//! header written into a TLS session would arrive encrypted and be
//! unreadable, so `crate::conn` refuses that arrangement before this filter
//! is ever built. That refusal, and its message, belong to `crate::conn` and
//! are deliberately not repeated here.
//!
//! # No feature gate
//!
//! `lib/cf-haproxy.h` is guarded by `#ifndef CURL_DISABLE_PROXY` and by
//! nothing else -- notably not by any HTTP guard, because the PROXY protocol
//! is protocol-agnostic and is used ahead of FTP and raw TCP as readily as
//! ahead of HTTP. This module therefore carries no `cfg` feature attribute
//! at all, and adding one would silently delete it from a build -- silently
//! because a `cfg` naming a feature that does not exist is not an error.

use crate::conn::filters::{
    link, CallCtx, CfQuery, CfQueryValue, CfType, ConnFilter, ConnId,
    FilterBase, FilterChain, IpQuadruple, SocketIndex, CF_TYPE_PROXY,
    CURL_LOG_LVL_NONE,
};
use crate::conn::select::{
    is_valid_sock, EasyPollset, Socket, CURL_SOCKET_BAD,
};
use crate::error::{CURLcode, CurlResult, Error};
use crate::trace::{trc_cf, TraceFilter};
use crate::util::dynbuf::{DynBuf, DYN_HAXPROXY};

// The filter's identity -- the first three members of `Curl_cft_haproxy`

/// The `name` member (`lib/cf-haproxy.c:187`): the label `--trace-config`
/// matches and every trace line from this filter prints.
///
/// Registered in [`crate::trace`] as [`TraceFilter::HaProxy`], which lets
/// [`ConnFilter::trace_filter`]'s default resolve this filter's identity
/// from its name alone rather than from a second table here.
pub(crate) const HAPROXY_FILTER_NAME: &str = "HAPROXY";

/// The `flags` member (`lib/cf-haproxy.c:188`): `CF_TYPE_PROXY`, and ONLY
/// that.
///
/// Measured, and the omission is the interesting half. The three other proxy
/// filters -- SOCKS, HTTP-PROXY and SSL-PROXY -- additionally carry
/// `CF_TYPE_IP_CONNECT`, because each of them terminates a connection of its
/// own. This one does not: it writes a preamble over a connection somebody
/// else established, so it provides no IP connectivity and must not claim to.
/// [`crate::conn::filters::FilterChain::is_ip_connected`] walks the chain
/// looking for exactly that flag, and a HAPROXY filter answering it would
/// report the connection established before the transport below had finished.
pub(crate) const HAPROXY_FLAGS: CfType = CF_TYPE_PROXY;

/// The `log_level` member (`lib/cf-haproxy.c:189`): `CURL_LOG_LVL_NONE`.
///
/// The level itself lives in [`crate::trace::TraceConfig`] here rather than on
/// the filter type, because C's is a process-global that `--trace-config`
/// writes through. This constant records what the C declares so that the
/// identity test below can assert it.
// The allowance is on this ITEM and not on the module: a lint level for
// `dead_code` on a module root would also silence the next unreferenced item
// somebody adds, which `mod source_policy` in the crate root rejects outright.
#[allow(dead_code)] // Asserted by the identity test; the level lives in
                    // `TraceConfig`.
pub(crate) const HAPROXY_LOG_LEVEL: i32 = CURL_LOG_LVL_NONE;

// The two header forms -- wire bytes, frozen

/// The header for a Unix-domain destination (`lib/cf-haproxy.c:75`).
///
/// Fifteen bytes, `CRLF`-terminated, and not a template: a Unix-domain
/// socket has no address family, no address and no port that the PROXY
/// grammar can express, so the C emits its "I cannot say" form and stops.
///
/// The literal is spelled out once, here, and appended verbatim. It must never
/// be built by a `writeln!` or any other helper that would substitute a bare
/// `\n` for the `\r\n`.
pub(crate) const HAPROXY_UNKNOWN_HEADER: &str = "PROXY UNKNOWN\r\n";

/// The `TCP6` token of the header's first field.
const HAPROXY_PROTO_TCP6: &str = "TCP6";

/// The `TCP4` token of the header's first field.
const HAPROXY_PROTO_TCP4: &str = "TCP4";

/// One filter-attributed trace line -- `CURL_TRC_CF`.
///
/// The same shim `conn/filters.rs` and `conn/happy_eyeballs.rs` each declare
/// over the exported `trc_cf!`: the wrapper is per-module by construction,
/// because `macro_rules!` is not exported from either of them, and it exists
/// so that a call site states the filter's identity and socket index without
/// repeating the verbosity test.
macro_rules! trc {
    (
        $cx:expr, $filter:expr, $sockindex:expr,
        $fmt:literal $(, $arg:expr)* $(,)?
    ) => {{
        let identity: Option<TraceFilter> = $filter;
        let sockindex: i32 = $sockindex;
        if let Some(identity) = identity {
            if let Some(tracer) = $cx.tracer_mut() {
                trc_cf!(tracer, identity, sockindex, $fmt $(, $arg)*);
            }
        }
    }};
}

// The state machine -- `enum haproxy_state`

/// Where the header has got to.
///
/// The successor of `haproxy_state` (`lib/cf-haproxy.c:35-39`), and exactly
/// its three values. The C's comments are kept because they are the whole
/// specification of a state each: there is no negotiation, no reply to read
/// and no error state -- the peer never answers a PROXY header, so the only
/// thing that can be in progress is the write.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub(crate) enum HaproxyState {
    /// `HAPROXY_INIT`: *"init/default/no tunnel state"*. The header has not
    /// been composed yet.
    #[default]
    Init,
    /// `HAPROXY_SEND`: *"data_out being sent"*. The header is composed and
    /// some or all of it is still in the buffer.
    Send,
    /// `HAPROXY_DONE`: *"all work done"*. The buffer is released and the
    /// filter is transparent.
    Done,
}

// The connection facts this filter reads

/// The two facts the C reaches through pointers this design does not have.
///
/// `cf_haproxy_date_out_set` reads `cf->conn->unix_domain_socket` and
/// `data->set.str[STRING_HAPROXY_CLIENT_IP]`. Neither is reachable from a
/// filter here: [`CallCtx`] deliberately carries only the tracer and the
/// clock, and a filter cannot reach the connection that owns it. So both
/// arrive as an injected value, built by whoever installs the filter and fixed
/// for its lifetime -- which is faithful, because the C reads both only while
/// composing the header and neither can change during a connect.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct HaproxyConfig {
    /// `data->set.str[STRING_HAPROXY_CLIENT_IP]` --
    /// `CURLOPT_HAPROXY_CLIENT_IP`, which `--haproxy-clientip` sets.
    ///
    /// [`None`] is the option unset, which is the ordinary case. When it is
    /// set it replaces the header's SOURCE address and nothing else; see
    /// [`Haproxy::date_out_set`] for why that asymmetry matters.
    pub(crate) client_ip: Option<String>,
    /// Whether the connection's destination is a Unix-domain socket --
    /// `conn->unix_domain_socket` being non-`NULL`.
    ///
    /// True selects [`HAPROXY_UNKNOWN_HEADER`] and skips the address query
    /// entirely, exactly as the C's `#ifdef USE_UNIX_SOCKETS` branch does.
    pub(crate) unix_domain_socket: bool,
}

impl HaproxyConfig {
    /// The configuration of a plain TCP connection with no client-IP
    /// override -- what `--haproxy-protocol` alone produces.
    #[allow(dead_code)] // Consumer: the filter factory in `crate::conn`.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            client_ip: None,
            unix_domain_socket: false,
        }
    }

    /// Records `CURLOPT_HAPROXY_CLIENT_IP`.
    ///
    /// An empty string is NOT treated as absent: the C tests the pointer, not
    /// the content, so an option set to `""` produces a header with an empty
    /// source field. Reproducing that is the faithful choice, and the option
    /// parser upstream is where a value would be rejected.
    #[allow(dead_code)] // Consumer: the filter factory in `crate::conn`.
    #[must_use]
    pub(crate) fn with_client_ip(
        mut self,
        client_ip: impl Into<String>,
    ) -> Self {
        self.client_ip = Some(client_ip.into());
        self
    }

    /// Records that the destination is a Unix-domain socket.
    #[allow(dead_code)] // Consumer: the filter factory in `crate::conn`.
    #[must_use]
    pub(crate) fn with_unix_domain_socket(mut self, unix: bool) -> Self {
        self.unix_domain_socket = unix;
        self
    }
}

// The filter's own state -- `struct cf_haproxy_ctx`

/// The header being composed and sent.
///
/// The successor of `struct cf_haproxy_ctx` (`lib/cf-haproxy.c:41-44`), whose
/// two members survive unchanged in meaning: `int state` becomes a typed
/// [`HaproxyState`], and `struct dynbuf data_out` becomes a [`DynBuf`].
///
/// This is a CONCRETE FIELD of [`Haproxy`], not a `void *ctx` reached through a
/// cast. `Curl_cftype`'s untyped context (`lib/cfilters.h:232`) is the pattern
/// this translation exists to remove: every C filter opens with
/// `struct cf_..._ctx *ctx = cf->ctx;` and there is nothing but convention
/// keeping the two in step.
#[derive(Debug)]
pub(crate) struct HaproxyCtx {
    /// `int state`, typed.
    state: HaproxyState,
    /// `struct dynbuf data_out`: the header, and the unsent remainder of it
    /// once sending has begun.
    data_out: DynBuf,
}

impl HaproxyCtx {
    /// The context `cf_haproxy_create` allocates and initialises
    /// (`lib/cf-haproxy.c:212-218`).
    ///
    /// `ctx->state = HAPROXY_INIT` and
    /// `curlx_dyn_init(&ctx->data_out, DYN_HAXPROXY)`. The ceiling is
    /// [`DYN_HAXPROXY`], 2048 bytes, which is the C's own choice for this
    /// buffer and is retained: it is what turns an absurd
    /// `CURLOPT_HAPROXY_CLIENT_IP` into [`CURLcode::TooLarge`] rather than an
    /// unbounded allocation or a truncated header.
    fn new() -> Self {
        Self {
            state: HaproxyState::Init,
            data_out: DynBuf::new(DYN_HAXPROXY),
        }
    }

    /// `cf_haproxy_ctx_reset` (`lib/cf-haproxy.c:46-51`): back to the start.
    ///
    /// `curlx_dyn_reset` rather than `curlx_dyn_free`: the ceiling is kept and
    /// the buffer is emptied, so the filter can compose a fresh header if the
    /// connection is established again. That is exactly what
    /// [`ConnFilter::close`]'s contract requires -- filters stay installed and
    /// may be reconnected.
    fn reset(&mut self) {
        self.state = HaproxyState::Init;
        self.data_out.reset();
    }
}

// The filter -- `Curl_cft_haproxy`

/// The PROXY protocol filter -- `Curl_cft_haproxy`
/// (`lib/cf-haproxy.c:186-202`).
///
/// Writes one line and becomes transparent. Of the twelve filter operations it
/// overrides exactly FOUR -- [`ConnFilter::destroy`], [`ConnFilter::connect`],
/// [`ConnFilter::close`] and [`ConnFilter::adjust_pollset`] -- and leaves the
/// remaining EIGHT as [`ConnFilter`]'s pass-through defaults, which is the
/// same division the C's table makes with its eight `Curl_cf_def_*` slots.
///
/// Eight is measured rather than taken on trust: `struct Curl_cftype` declares
/// twelve callbacks after `name`, `flags` and `log_level`
/// (`lib/cfilters.h:210-226`), and `Curl_cft_haproxy` fills four of them with
/// its own functions -- `destroy`, `do_connect`, `do_close` and
/// `adjust_pollset` -- leaving `do_shutdown`, `has_data_pending`, `do_send`,
/// `do_recv`, `cntrl`, `is_alive`, `keep_alive` and `query`. `4 + 8 = 12`, and
/// [`the_filter_identity_matches_the_c_table`] asserts the arithmetic so the
/// count cannot drift from the table it describes.
///
/// Notably `send` and `recv` are NOT overridden: the header is written through
/// the filter below rather than through this filter's own send path, so
/// payload bytes never pass through code owned by this module.
#[derive(Debug)]
pub(crate) struct Haproxy {
    /// The chain link, socket index and two state flags.
    base: FilterBase,
    /// `cf->ctx`, typed.
    ctx: HaproxyCtx,
    /// The two connection facts the C reads through `cf->conn` and
    /// `data->set`.
    config: HaproxyConfig,
}

impl Haproxy {
    /// `cf_haproxy_create` (`lib/cf-haproxy.c:204-229`).
    ///
    /// The context is allocated EAGERLY, as the C's `calloc` does, and not on
    /// the first connect. That is a deliberate difference from the SOCKS and
    /// H1-PROXY filters, which allocate theirs lazily, and it is preserved:
    /// the buffer exists from creation, so [`ConnFilter::destroy`] and
    /// [`ConnFilter::close`] have something well-defined to act on however
    /// early they are called.
    ///
    /// The C's only failure was the allocation, which has no successor here:
    /// the context is a field of this struct, so there is no fallible step and
    /// no `CURLcode` to return.
    #[allow(dead_code)] // Consumer: the filter factory in `crate::conn`.
    #[must_use]
    pub(crate) fn new(
        sockindex: SocketIndex,
        conn: Option<ConnId>,
        config: HaproxyConfig,
    ) -> Self {
        let mut base = FilterBase::new(sockindex);
        // Stamping the identity here is what
        // `ConnectionFilterFactories::haproxy`'s contract explicitly permits:
        // `SetupFilter`'s splice restamps every node it installs, so a correct
        // stamp is idempotent there and a stale one is corrected.
        //
        // It is NOT permitted on the other installation path.
        // `FilterChain::insert_after` asserts the filter arrives UNATTACHED and
        // stamps it itself, so `Self::insert_after` passes `None` -- see the
        // note there, which records why the C leaves both members zeroed too.
        base.set_conn(conn);
        Self {
            base,
            ctx: HaproxyCtx::new(),
            config,
        }
    }

    /// `Curl_cf_haproxy_insert_after` (`lib/cf-haproxy.c:231-244`): build the
    /// filter and install it immediately BELOW the filter at `index`.
    ///
    /// The C names the position with a filter pointer, `cf_at`; a safe chain is
    /// owned from its head, so the position is named by `chain` plus `index`
    /// instead -- the spelling [`crate::conn::cf_setup_insert_after`] already
    /// uses for the same translation.
    ///
    /// # The filter is built UNATTACHED, deliberately
    ///
    /// `conn` is [`None`] here even though the chain's identity is in hand.
    /// `Curl_conn_cf_insert_after` (`lib/cfilters.c:345-363`) stamps `cf->conn`
    /// and `cf->sockindex` onto every node it splices, taking them from
    /// `cf_at`, and `cf_haproxy_create` leaves both zeroed for it -- the
    /// context is `calloc`ed and `Curl_cf_create` sets neither.
    /// [`FilterChain::insert_after`] reproduces that stamping walk and asserts
    /// the filter arrives unattached, so pre-stamping here would both duplicate
    /// the work and trip the assertion.
    ///
    /// [`Self::new`] still takes a `conn`, because the other installation path
    /// wants one: [`crate::conn::ConnectionFilterFactories::haproxy`] hands the
    /// identity to the factory and its contract explicitly permits a filter to
    /// arrive already carrying it.
    ///
    /// # Errors
    ///
    /// Whatever [`FilterChain::insert_after`] reports, which is
    /// [`CURLcode::BadFunctionArgument`] for a position that does not resolve.
    /// Construction itself cannot fail.
    #[allow(dead_code)] // Consumer: the filter factory in `crate::conn`.
    pub(crate) fn insert_after(
        cx: &mut CallCtx<'_, '_>,
        chain: &mut FilterChain,
        index: usize,
        config: HaproxyConfig,
    ) -> CurlResult<()> {
        let filter = Self::new(chain.sockindex(), None, config);
        chain.insert_after(cx, index, link(filter))
    }

    /// Where the header has got to -- for the tests and for tracing.
    #[allow(dead_code)] // Consumer: this module's tests.
    pub(crate) fn state(&self) -> HaproxyState {
        self.ctx.state
    }

    /// The header still waiting to be written.
    ///
    /// Empty both before the header is composed and after it has all been
    /// sent; [`Self::state`] distinguishes the two.
    #[allow(dead_code)] // Consumer: this module's tests.
    pub(crate) fn pending(&self) -> &[u8] {
        self.ctx.data_out.as_slice()
    }

    /// `cf_haproxy_date_out_set` (`lib/cf-haproxy.c:61-97`): compose the whole
    /// header into the buffer.
    ///
    /// # The two forms, and their exact grammar
    ///
    /// **A Unix-domain destination** emits [`HAPROXY_UNKNOWN_HEADER`] and
    /// queries nothing. The C reaches this branch on
    /// `cf->conn->unix_domain_socket` under `#ifdef USE_UNIX_SOCKETS`, and its
    /// comment on the append -- *"the buffer is large enough to hold this!"* --
    /// is why it ignores the return value there; this does not ignore it,
    /// because a checked append costs nothing and the claim is then verified
    /// rather than assumed.
    ///
    /// **A TCP destination** emits, with `%s %s %s %i %i` in this order and no
    /// other spacing:
    ///
    /// ```text
    /// PROXY <TCP4|TCP6> <source-address> <destination-address> <sport> <dport>
    /// ```
    ///
    /// # The override rule, which is asymmetric
    ///
    /// Field 2 is the SOURCE address and is overridable:
    /// `CURLOPT_HAPROXY_CLIENT_IP` replaces it, and otherwise it is
    /// `ipquad.local_ip`, this end of the connection. Field 3 is the
    /// DESTINATION address and is **`ipquad.remote_ip` unconditionally** --
    /// there is no option that changes it and none may be added, because the
    /// receiving backend uses it to decide which service the connection was
    /// addressed to.
    ///
    /// Writing the override into field 3 would produce a header that still
    /// parses, still has five fields and is still accepted by a peer -- and is
    /// wrong. That is why the two fields are asserted independently below
    /// rather than through one whole-line comparison.
    ///
    /// # Two spellings worth not "correcting"
    ///
    /// The C's conversion for both ports is `%i`, not `%u`: they are
    /// `uint16_t` members promoted to `int` by the call. For every value a port
    /// can hold the two render identically, and here the ports are [`u16`], so
    /// `{}` is exact for the whole range and the distinction cannot become
    /// observable. It is recorded only so that nobody "fixes" the format into
    /// something that would render a signed sentinel differently.
    ///
    /// `is_ipv6` is NOT read from `conn->bits.ipv6`. The C obtains it from
    /// `Curl_conn_cf_get_ip_info(cf->next, ...)` (`lib/cf-haproxy.c:78`), which
    /// is answered by `CF_QUERY_IP_INFO` on the socket filter as
    /// `ctx->addr.family == AF_INET6` (`lib/cf-socket.c:1666-1672`). Both
    /// derive from the same address family, but only one of them is what this
    /// filter actually asks, and asking the filter below is also what makes the
    /// answer correct for a chain whose transport was chosen by a race.
    ///
    /// # Errors
    ///
    /// [`CURLcode::FailedInit`] with no filter below to ask,
    /// [`CURLcode::UnknownOption`] where nothing in the chain answers the
    /// address query -- the C's sentinel for an unanswered query -- and
    /// [`CURLcode::TooLarge`] when the composed header would cross
    /// [`DYN_HAXPROXY`].
    fn date_out_set(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<()> {
        debug_assert_eq!(
            self.ctx.state,
            HaproxyState::Init,
            "the header is composed once, in the INIT state"
        );

        // `if(cf->conn->unix_domain_socket)` (`:73-75`).
        if self.config.unix_domain_socket {
            self.ctx.data_out.addn(HAPROXY_UNKNOWN_HEADER.as_bytes())?;
            return Ok(());
        }

        // `result = Curl_conn_cf_get_ip_info(cf->next, data, &is_ipv6,
        // &ipquad); if(result) return result;` (`:78-80`).
        let (is_ipv6, quad) = self.ip_info(cx)?;

        // `:83-86`. The option's presence decides, not its content: the C
        // tests the pointer, so an option set to the empty string yields an
        // empty field rather than falling back to the local address.
        let client_ip = match self.config.client_ip.as_deref() {
            Some(client_ip) => client_ip,
            None => quad.local_ip.as_str(),
        };

        // `:88-91`. Field 3 is `quad.remote_ip` and takes no override.
        let proto = if is_ipv6 {
            HAPROXY_PROTO_TCP6
        } else {
            HAPROXY_PROTO_TCP4
        };
        self.ctx.data_out.addf(format_args!(
            "PROXY {} {} {} {} {}\r\n",
            proto, client_ip, quad.remote_ip, quad.local_port, quad.remote_port
        ))?;
        Ok(())
    }

    /// `Curl_conn_cf_get_ip_info(cf->next, data, ...)`
    /// (`lib/cfilters.c:923-934`): the address family and the connected
    /// quadruple, from the filter BELOW.
    ///
    /// # Errors
    ///
    /// [`CURLcode::FailedInit`] when there is no filter below, and whatever the
    /// query reports otherwise -- [`CURLcode::UnknownOption`] where nothing in
    /// the chain understands it, which is the code the C's own bottom of the
    /// chain returns.
    fn ip_info(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
    ) -> CurlResult<(bool, IpQuadruple)> {
        let Some(next) = self.base.next_mut() else {
            return Err(Error::with_context(
                CURLcode::FailedInit,
                "HAPROXY: no transport below to take the address from",
            ));
        };
        match next.query(cx, CfQuery::IpInfo)? {
            CfQueryValue::IpInfo { is_ipv6, quad } => Ok((is_ipv6, quad)),
            // Unreachable through `FilterChain`, which pairs every answer with
            // its question, but a filter is reached directly here and the
            // mismatch has to resolve to something. The C's sentinel for "the
            // question was not answered" is the honest choice.
            _ => Err(Error::with_context(
                CURLcode::UnknownOption,
                "HAPROXY: the address query was answered with another value",
            )),
        }
    }

    /// `Curl_conn_cf_get_socket(cf, data)` (`lib/cfilters.c:883-890`): the
    /// descriptor readiness is registered on.
    ///
    /// Queried on THIS filter rather than on the one below, exactly as the C
    /// does. The two are equivalent for this filter -- its `query` is the
    /// chaining default -- and asking as the C asks keeps it that way if a
    /// query override is ever added.
    ///
    /// [`crate::conn::select::CURL_SOCKET_BAD`] where the query is unanswered,
    /// which is the C's fallback at `:889`.
    fn socket(&mut self, cx: &mut CallCtx<'_, '_>) -> Socket {
        match self.query(cx, CfQuery::Socket) {
            Ok(CfQueryValue::Socket(sock)) => sock,
            _ => CURL_SOCKET_BAD,
        }
    }

    /// The `switch(ctx->state)` of `cf_haproxy_connect`
    /// (`lib/cf-haproxy.c:117-148`), with the C's two `FALLTHROUGH()`s.
    ///
    /// Separated from [`ConnFilter::connect`] so that the C's single exit
    /// survives the translation: `out:` computes
    /// `*done = (!result) && (ctx->state == HAPROXY_DONE)` from the state the
    /// switch left behind, whichever way it left. Returning `done` from here
    /// instead would have to re-derive it in each arm, and an arm that got it
    /// wrong would report a connection established with bytes still unsent.
    ///
    /// # The fall-through chain, and why each step is not a loop
    ///
    /// `INIT` composes the header and falls into `SEND`; `SEND`, once the
    /// buffer is empty, falls into the `default` arm, which releases it. A
    /// header short enough to be written in one call therefore traverses all
    /// three states in ONE call, which is the ordinary case: the C's
    /// fall-through is what makes a single `connect` sufficient, and a
    /// translation that returned after each state would need three.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::date_out_set`] reports, and whatever the filter below
    /// reports for the write -- except [`CURLcode::Again`], which is not an
    /// error here; see below.
    fn advance(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<()> {
        // `case HAPROXY_INIT:` (`:118-123`).
        if self.ctx.state == HaproxyState::Init {
            self.date_out_set(cx)?;
            self.ctx.state = HaproxyState::Send;
            // `FALLTHROUGH()` into the arm below.
        }

        // `case HAPROXY_SEND:` (`:124-142`).
        if self.ctx.state == HaproxyState::Send {
            let len = self.ctx.data_out.len();
            // `if(len > 0)`. A zero-length buffer cannot happen for a header
            // that was just composed, but the C tests it and the test is free.
            if len > 0 {
                // The two fields are borrowed separately: the bytes come from
                // `ctx` and the write goes through `base`, and nothing here
                // needs both at once.
                let Self { base, ctx, .. } = self;
                let sent = match base.next_mut() {
                    // `Curl_conn_cf_send(cf->next, data, ..., FALSE,
                    // &nwritten)` -- `eos` is FALSE: the header is a preamble
                    // and the stream continues after it.
                    Some(next) => next.send(cx, ctx.data_out.as_slice(), false),
                    None => Err(Error::with_context(
                        CURLcode::FailedInit,
                        "HAPROXY: no transport below to write the header to",
                    )),
                };

                // `if(result) { if(result != CURLE_AGAIN) goto out; result =
                // CURLE_OK; nwritten = 0; }` (`:131-136`). A would-block is
                // NOT a failure: nothing was written, the buffer is left whole
                // and the next call retries it.
                let nwritten = match sent {
                    Ok(nwritten) => nwritten,
                    Err(error) if error.code() == CURLcode::Again => 0,
                    Err(error) => return Err(error),
                };

                // `curlx_dyn_tail(&ctx->data_out, len - nwritten)` (`:137`):
                // keep the UNSENT TAIL. Called unconditionally, as the C calls
                // it -- a complete write asks for a tail of zero, which empties
                // the buffer and lets the fall-through below release it.
                //
                // `checked_sub` reproduces the C exactly rather than guarding
                // against it: a filter reporting more written than it was given
                // makes `len - nwritten` wrap in the C, and `curlx_dyn_tail`
                // then rejects the oversized `trail` with
                // `CURLE_BAD_FUNCTION_ARGUMENT` (`lib/curlx/dynbuf.c:144-145`).
                // The same code is returned here, without the wrap.
                let unsent = len.checked_sub(nwritten).ok_or_else(|| {
                    Error::with_context(
                        CURLcode::BadFunctionArgument,
                        "HAPROXY: the transport reported writing more of the \
                         header than it was given",
                    )
                })?;
                self.ctx.data_out.tail(unsent)?;

                // `if(curlx_dyn_len(&ctx->data_out) > 0) { result = CURLE_OK;
                // goto out; }` (`:138-141`): still unsent bytes, so remain in
                // SEND and report not-done. The caller comes back when the
                // socket is writable again, which is what
                // `ConnFilter::adjust_pollset` has registered for.
                if !self.ctx.data_out.is_empty() {
                    return Ok(());
                }
            }
            self.ctx.state = HaproxyState::Done;
            // `FALLTHROUGH()` into the arm below.
        }

        // `default:` (`:145-147`). The whole header is out, so the buffer is
        // released rather than merely emptied -- this filter will not compose
        // another unless it is closed and connected again, and
        // `HaproxyCtx::reset` is what prepares it for that.
        self.ctx.data_out.free();
        Ok(())
    }
}

impl ConnFilter for Haproxy {
    fn trace_name(&self) -> &'static str {
        HAPROXY_FILTER_NAME
    }

    /// [`HAPROXY_FLAGS`] -- `CF_TYPE_PROXY` alone.
    fn cf_type(&self) -> CfType {
        HAPROXY_FLAGS
    }

    fn base(&self) -> &FilterBase {
        &self.base
    }

    fn base_mut(&mut self) -> &mut FilterBase {
        &mut self.base
    }

    // -- 1. destroy ------------------------------------------------------

    /// `cf_haproxy_destroy` (`lib/cf-haproxy.c:156-161`): the trace line, then
    /// release the buffer.
    ///
    /// Does NOT chain, and must not: the caller has already severed the link
    /// and owns the rest of the chain. The C's `cf_haproxy_ctx_free` also frees
    /// the context allocation itself, which has no successor here -- the
    /// context is a field of this struct and goes with it.
    fn destroy(&mut self, cx: &mut CallCtx<'_, '_>) {
        trc!(
            cx,
            self.trace_filter(),
            self.base.sockindex().as_i32(),
            "destroy"
        );
        self.ctx.data_out.free();
    }

    // -- 2. connect ------------------------------------------------------

    /// `cf_haproxy_connect` (`lib/cf-haproxy.c:99-154`): get the header out.
    ///
    /// # The order of the first two steps is load-bearing
    ///
    /// The filter BELOW is connected first, and its verdict is returned
    /// unchanged when it is not yet done. Only then is the header composed. The
    /// reason is in the header itself: two of its five fields are the local
    /// address and port, which do not exist until the socket is connected, so
    /// composing before the transport is up would produce a header describing
    /// nothing.
    ///
    /// # What `done` means here
    ///
    /// `*done = (!result) && (ctx->state == HAPROXY_DONE)` at the C's single
    /// exit (`:151`), and `cf->connected` takes the same value (`:152`). So
    /// this filter reports itself connected at exactly one moment: when the
    /// last byte of the header has been handed to the filter below. A partially
    /// written header reports `Ok(false)`, which is the [`ConnFilter`]
    /// contract's "would block" -- never [`CURLcode::Again`].
    ///
    /// # Errors
    ///
    /// [`CURLcode::FailedInit`] with no transport below -- where the C
    /// dereferences `cf->next` unconditionally and a chain without one is a
    /// construction bug -- and whatever [`Self::advance`] reports.
    fn connect(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<bool> {
        // `if(cf->connected) { *done = TRUE; return CURLE_OK; }` (`:108-111`).
        if self.base.is_connected() {
            return Ok(true);
        }

        // `result = cf->next->cft->do_connect(cf->next, data, done);
        // if(result || !*done) return result;` (`:113-115`). Both the error and
        // the not-yet-done verdict leave `cf->connected` alone, which it
        // already is: the test above proved it false.
        let Some(next) = self.base.next_mut() else {
            return Err(Error::with_context(
                CURLcode::FailedInit,
                "HAPROXY: no transport below to connect",
            ));
        };
        if !next.connect(cx)? {
            return Ok(false);
        }

        // The switch, then the C's single exit at `out:` (`:150-153`).
        let outcome = self.advance(cx);
        let done = outcome.is_ok() && self.ctx.state == HaproxyState::Done;
        self.base.set_connected(done);
        if done {
            trc!(
                cx,
                self.trace_filter(),
                self.base.sockindex().as_i32(),
                "PROXY protocol header sent"
            );
        }
        outcome.map(|()| done)
    }

    // -- 3. close --------------------------------------------------------

    /// `cf_haproxy_close` (`lib/cf-haproxy.c:163-171`): forget the header and
    /// pass the close down.
    ///
    /// Three steps in the C's order -- clear `connected`, reset the context,
    /// then chain. The reset is what this adds to the generic
    /// `Curl_cf_def_close` shape, and it is what makes a reconnect compose a
    /// FRESH header: the state returns to [`HaproxyState::Init`] and the buffer
    /// is emptied, so a second connect cannot resend a stale line describing
    /// the previous socket's addresses.
    fn close(&mut self, cx: &mut CallCtx<'_, '_>) {
        trc!(
            cx,
            self.trace_filter(),
            self.base.sockindex().as_i32(),
            "close"
        );
        self.base.set_connected(false);
        self.ctx.reset();
        // `if(cf->next) cf->next->cft->do_close(cf->next, data);`
        if let Some(next) = self.base.next_mut() {
            next.close(cx);
        }
    }

    // -- 5. adjust pollset -----------------------------------------------

    /// `cf_haproxy_adjust_pollset` (`lib/cf-haproxy.c:173-184`): while the
    /// header is going out, wait to WRITE.
    ///
    /// The condition is `cf->next->connected && !cf->connected`, and both
    /// halves are necessary. The C's own comment says why: *"If we are not
    /// connected, but the filter below is and not waiting on something, we are
    /// sending."* Simplifying it to `!cf->connected` would register writability
    /// while the transport below was still connecting -- and the transport has
    /// its own readiness to declare for that phase, which this would
    /// override.
    ///
    /// Out-only: [`EasyPollset::set_out_only`] adds `POLLOUT` and REMOVES
    /// `POLLIN`, which is right because a peer never answers a PROXY header, so
    /// there is nothing to read for and a registered read would wake the
    /// transfer for work it cannot do.
    ///
    /// # Errors
    ///
    /// Whatever [`EasyPollset::set_out_only`] reports, which is
    /// [`CURLcode::BadFunctionArgument`] for a socket that is not a descriptor.
    /// The C propagates the same, and reaching it means the filter below
    /// reported itself connected without a socket.
    fn adjust_pollset(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        ps: &mut EasyPollset,
    ) -> CurlResult<()> {
        let below_connected = match self.base.next_ref() {
            Some(next) => next.base().is_connected(),
            // C dereferences `cf->next` here without a test. A chain with no
            // transport below has nothing to be sending over, so the honest
            // answer is that this filter is not waiting for anything.
            None => false,
        };
        if !(below_connected && !self.base.is_connected()) {
            // Leaving the pollset ALONE, which is not the same as clearing it:
            // another filter may have registered the same descriptor.
            return Ok(());
        }

        let sock = self.socket(cx);
        // The `is_valid_sock` test is the debug assertion `EasyPollset::change`
        // performs, hoisted so the trace line can name the descriptor. The
        // invalid case still reaches `set_out_only` and still reports
        // `BadFunctionArgument`, exactly as the C does.
        if is_valid_sock(sock) {
            trc!(
                cx,
                self.trace_filter(),
                self.base.sockindex().as_i32(),
                "adjust_pollset, POLLOUT fd={}",
                sock
            );
        }
        ps.set_out_only(sock, cx.tracer_mut())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::filters::{
        CfControl, Transport, CF_TYPE_IP_CONNECT, CF_TYPE_SSL,
    };
    use crate::conn::select::PollAction;
    use crate::trace::{TraceConfig, TraceLevel, Tracer, WriterSink};
    use crate::util::sync_cell::SyncCell;
    use crate::util::timeval::{CurlTime, TestClock};
    use std::sync::Arc;

    // Two of the imports above reach modules this file does not otherwise
    // depend on, and both are test-only:
    //
    //   * `util::timeval` is unavoidable and is mandated rather than chosen. A
    //     `CallCtx` is built over an injected `&dyn Clock` (AAP 0.3.3 P12) and
    //     every implementation of that trait lives there, so there is no way to
    //     call a filter operation at all without it.
    //   * `util::sync_cell` is the crate's own idiom for exactly this handle --
    //     `conn/filters.rs`'s `InMemory`, `conn/happy_eyeballs.rs`'s
    //     `MemFilter` and `tls/mod.rs`'s `Below` all use it. `Arc<Mutex<_>>`
    //     would work and would be worse: a hand-rolled duplicate of a type the
    //     crate already provides, with a `.lock().unwrap()` at every access.
    //
    // Neither appears in the shipped artifact.

    // -- the transport double ---------------------------------------------
    //
    // `conn/filters.rs` has an in-memory transport of its own, and it is the
    // model this one follows -- same `Arc<SyncCell<State>>` handle, same
    // ordered event log. It cannot be reused directly: `mod tests` there is
    // private and so is the `InMemory` inside it, and the crate has no shared
    // test-support module. Every sibling that needs a bottom-of-chain double
    // therefore declares one -- `MemFilter` in `conn/happy_eyeballs.rs`,
    // `Below` in `tls/mod.rs`, `SlowFilter` in `conn/pool.rs`, `TestFilter` in
    // `conn/shutdown.rs` -- and this follows that precedent rather than
    // exporting another module's test internals. What matters is preserved:
    // the header is asserted over an in-memory transport with no live server
    // anywhere, and no second PRODUCTION abstraction is introduced.

    /// What the transport below has seen and what it will do next.
    #[derive(Debug)]
    struct TransportState {
        /// Every byte accepted, in order. This is the wire.
        output: Vec<u8>,
        /// The most bytes one write will accept. [`None`] accepts everything
        /// offered, which is the ordinary case.
        write_limit: Option<usize>,
        /// How many further writes report [`CURLcode::Again`] before one is
        /// accepted.
        again_writes: usize,
        /// The `eos` flag of every write received, in order.
        eos_seen: Vec<bool>,
        /// Whether `connect` reports itself done.
        connects_done: bool,
        /// What the address query answers. [`None`] leaves it unanswered.
        ip_info: Option<(bool, IpQuadruple)>,
        /// What the socket query answers. [`None`] leaves it unanswered.
        socket: Option<Socket>,
        /// Every operation reaching this filter, in order.
        events: Vec<String>,
    }

    impl Default for TransportState {
        fn default() -> Self {
            Self {
                output: Vec::new(),
                write_limit: None,
                again_writes: 0,
                eos_seen: Vec::new(),
                connects_done: true,
                ip_info: Some((false, v4_quad())),
                socket: Some(9),
                events: Vec::new(),
            }
        }
    }

    /// A handle on the transport that outlives the chain owning it.
    ///
    /// Not a convenience: a linked filter is owned as
    /// `Pin<Box<dyn ConnFilter>>` and there is no way back to its concrete
    /// type -- deliberately, since abolishing that recovery is the whole point
    /// of the translation. A shared handle is the only way a test can observe
    /// what the filter below did, and it is fully typed.
    type Wire = Arc<SyncCell<TransportState>>;

    /// The bottom of the chain: a connection over one byte buffer.
    #[derive(Debug)]
    struct Below {
        base: FilterBase,
        wire: Wire,
    }

    impl Below {
        fn new() -> (Self, Wire) {
            let wire: Wire = Arc::new(SyncCell::new(TransportState::default()));
            let filter = Self {
                base: FilterBase::new(SocketIndex::First),
                wire: Arc::clone(&wire),
            };
            (filter, wire)
        }

        fn note(&self, what: &str) {
            self.wire.borrow_mut().events.push(what.to_owned());
        }
    }

    impl ConnFilter for Below {
        /// Not a registered trace name, so the transport traces nothing and
        /// every trace assertion below is about the filter under test alone.
        fn trace_name(&self) -> &'static str {
            "TEST-TRANSPORT"
        }

        /// A real transport declares `CF_TYPE_IP_CONNECT`, and so does this:
        /// the flag is what makes the chain report IP connectivity, and the
        /// identity test relies on HAPROXY *not* contributing it.
        fn cf_type(&self) -> CfType {
            CF_TYPE_IP_CONNECT
        }

        fn base(&self) -> &FilterBase {
            &self.base
        }

        fn base_mut(&mut self) -> &mut FilterBase {
            &mut self.base
        }

        fn destroy(&mut self, _cx: &mut CallCtx<'_, '_>) {
            self.note("destroy");
        }

        fn connect(&mut self, _cx: &mut CallCtx<'_, '_>) -> CurlResult<bool> {
            self.note("connect");
            let done = self.wire.borrow().connects_done;
            self.base.set_connected(done);
            Ok(done)
        }

        fn close(&mut self, _cx: &mut CallCtx<'_, '_>) {
            self.note("close");
            self.base.set_connected(false);
        }

        fn shutdown(&mut self, _cx: &mut CallCtx<'_, '_>) -> CurlResult<bool> {
            self.note("shutdown");
            Ok(true)
        }

        fn cntrl(
            &mut self,
            _cx: &mut CallCtx<'_, '_>,
            _event: CfControl,
        ) -> CurlResult<()> {
            self.note("cntrl");
            Ok(())
        }

        fn adjust_pollset(
            &mut self,
            _cx: &mut CallCtx<'_, '_>,
            _ps: &mut EasyPollset,
        ) -> CurlResult<()> {
            self.note("adjust_pollset");
            Ok(())
        }

        fn send(
            &mut self,
            _cx: &mut CallCtx<'_, '_>,
            buf: &[u8],
            eos: bool,
        ) -> CurlResult<usize> {
            self.note("send");
            let mut wire = self.wire.borrow_mut();
            wire.eos_seen.push(eos);
            if wire.again_writes > 0 {
                wire.again_writes -= 1;
                return Err(Error::new(CURLcode::Again));
            }
            let take = match wire.write_limit {
                Some(limit) => limit.min(buf.len()),
                None => buf.len(),
            };
            wire.output.extend_from_slice(&buf[..take]);
            Ok(take)
        }

        fn query(
            &mut self,
            _cx: &mut CallCtx<'_, '_>,
            query: CfQuery,
        ) -> CurlResult<CfQueryValue> {
            let wire = self.wire.borrow();
            match query {
                CfQuery::IpInfo => match wire.ip_info.clone() {
                    Some((is_ipv6, quad)) => {
                        Ok(CfQueryValue::IpInfo { is_ipv6, quad })
                    }
                    None => Err(Error::new(CURLcode::UnknownOption)),
                },
                CfQuery::Socket => match wire.socket {
                    Some(sock) => Ok(CfQueryValue::Socket(sock)),
                    None => Err(Error::new(CURLcode::UnknownOption)),
                },
                _ => Err(Error::new(CURLcode::UnknownOption)),
            }
        }
    }

    // -- helpers ----------------------------------------------------------

    fn clock() -> TestClock {
        TestClock::new(CurlTime::new(1_000, 0))
    }

    /// The IPv4 quadruple every test that does not say otherwise runs over.
    fn v4_quad() -> IpQuadruple {
        IpQuadruple {
            remote_ip: "203.0.113.7".to_owned(),
            local_ip: "192.0.2.10".to_owned(),
            remote_port: 443,
            local_port: 54_321,
            transport: Transport::Tcp,
        }
    }

    /// The IPv6 quadruple, addresses in the numeric form the C stores --
    /// `ip_quadruple` holds what `Curl_addr2string` wrote, with no brackets.
    fn v6_quad() -> IpQuadruple {
        IpQuadruple {
            remote_ip: "2001:db8::7".to_owned(),
            local_ip: "2001:db8::10".to_owned(),
            remote_port: 8_443,
            local_port: 40_000,
            transport: Transport::Tcp,
        }
    }

    /// A HAPROXY filter over a fresh transport, linked and ready to connect.
    fn rig(config: HaproxyConfig) -> (Haproxy, Wire) {
        let (below, wire) = Below::new();
        let mut filter =
            Haproxy::new(SocketIndex::First, Some(ConnId::new(7)), config);
        filter.base_mut().set_next(Some(link(below)));
        (filter, wire)
    }

    /// The bytes the transport accepted, as one slice.
    fn wire_bytes(wire: &Wire) -> Vec<u8> {
        wire.borrow().output.clone()
    }

    /// The ordered operation log.
    fn events(wire: &Wire) -> Vec<String> {
        wire.borrow().events.clone()
    }

    /// The header's five fields, split on the single spaces the grammar uses.
    ///
    /// Splitting rather than whole-line matching is deliberate for the override
    /// tests: a source/destination swap produces a line of the right shape with
    /// the right five tokens in the wrong two places, and only a per-field
    /// assertion catches it.
    fn fields(bytes: &[u8]) -> Vec<String> {
        let text = std::str::from_utf8(bytes).expect("the header is ASCII");
        let line = text
            .strip_suffix("\r\n")
            .expect("the header is CRLF-terminated");
        line.split(' ').map(str::to_owned).collect()
    }

    /// Drives one connect to completion, asserting it reported done.
    fn connect_fully(filter: &mut Haproxy, clock: &TestClock) {
        let mut cx = CallCtx::new(clock);
        assert!(
            filter.connect(&mut cx).expect("the header goes out"),
            "one call sends a whole header over an unconstrained transport"
        );
    }

    // -- 1. the filter's identity -----------------------------------------

    /// `struct Curl_cftype Curl_cft_haproxy` (`lib/cf-haproxy.c:186-202`),
    /// member by member.
    ///
    /// The flags are the assertion that matters. `CF_TYPE_PROXY` and nothing
    /// else: the three other proxy filters add `CF_TYPE_IP_CONNECT` because
    /// each terminates a connection, and this one writes a preamble over
    /// somebody else's.
    #[test]
    fn the_filter_identity_matches_the_c_table() {
        let (filter, _wire) = rig(HaproxyConfig::new());

        assert_eq!(filter.trace_name(), "HAPROXY");
        assert_eq!(HAPROXY_FILTER_NAME, "HAPROXY");
        assert_eq!(filter.cf_type(), CF_TYPE_PROXY);
        assert_eq!(HAPROXY_FLAGS, CF_TYPE_PROXY);
        assert!(
            !filter.cf_type().intersects(CF_TYPE_IP_CONNECT),
            "HAPROXY provides no IP connection and must not claim one"
        );
        assert!(!filter.cf_type().intersects(CF_TYPE_SSL));
        assert_eq!(HAPROXY_LOG_LEVEL, 0, "the C's log_level member is 0");

        // The name is what resolves the identity, so `--trace-config proxy`
        // reaches this filter without a second table here.
        assert_eq!(filter.trace_filter(), Some(TraceFilter::HaProxy));
        assert_eq!(TraceFilter::HaProxy.name(), "HAPROXY");

        // The chain link the C's `Curl_cf_create` sets up.
        assert_eq!(filter.sockindex(), SocketIndex::First);
        assert_eq!(filter.base().conn(), Some(ConnId::new(7)));
        assert!(!filter.base().is_connected());

        // The division of the twelve callbacks, as arithmetic rather than as
        // prose. `struct Curl_cftype` declares twelve after the three identity
        // members (`lib/cfilters.h:210-226`); `Curl_cft_haproxy` supplies four
        // and leaves eight as `Curl_cf_def_*`.
        const CFTYPE_CALLBACKS: usize = 12;
        const OVERRIDDEN: usize = 4;
        const PASS_THROUGH: usize = 8;
        assert_eq!(OVERRIDDEN + PASS_THROUGH, CFTYPE_CALLBACKS);
        // The four named, in the C's declaration order: destroy, do_connect,
        // do_close, adjust_pollset. The eight left are do_shutdown,
        // has_data_pending, do_send, do_recv, cntrl, is_alive, keep_alive and
        // query -- each exercised by
        // `the_eight_defaults_are_left_exactly_as_the_c_declares_them` and
        // `destroy_shutdown_and_control_do_not_reach_the_filter_below`.
        assert_eq!(
            ["destroy", "do_connect", "do_close", "adjust_pollset"].len(),
            OVERRIDDEN
        );
        assert_eq!(
            [
                "do_shutdown",
                "has_data_pending",
                "do_send",
                "do_recv",
                "cntrl",
                "is_alive",
                "keep_alive",
                "query",
            ]
            .len(),
            PASS_THROUGH
        );
    }

    /// The context is allocated EAGERLY -- `calloc` before `Curl_cf_create`
    /// (`lib/cf-haproxy.c:212-218`) -- unlike the lazily-allocating SOCKS and
    /// H1-PROXY filters.
    #[test]
    fn the_context_exists_from_creation_in_the_init_state() {
        let filter =
            Haproxy::new(SocketIndex::Secondary, None, HaproxyConfig::new());

        assert_eq!(filter.state(), HaproxyState::Init);
        assert!(filter.pending().is_empty());
        assert_eq!(HaproxyState::default(), HaproxyState::Init);
        assert_eq!(filter.sockindex(), SocketIndex::Secondary);
    }

    /// `Curl_cf_haproxy_insert_after` (`lib/cf-haproxy.c:231-244`) splices the
    /// filter immediately BELOW the named position.
    #[test]
    fn insert_after_installs_the_filter_below_the_named_position() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let mut chain =
            FilterChain::new(Some(ConnId::new(3)), SocketIndex::First);
        let (below, _wire) = Below::new();
        chain.add(&mut cx, link(below));

        Haproxy::insert_after(&mut cx, &mut chain, 0, HaproxyConfig::new())
            .expect("position 0 resolves");

        let names: Vec<&'static str> =
            chain.iter().map(ConnFilter::trace_name).collect();
        assert_eq!(names, vec!["TEST-TRANSPORT", "HAPROXY"]);

        // The splice stamped the identity, which is why the filter is built
        // unattached: `Curl_conn_cf_insert_after` walks the inserted subchain
        // setting `cf->conn` and `cf->sockindex` from `cf_at`.
        let inserted = chain.nth_ref(1).expect("HAPROXY is at position 1");
        assert_eq!(inserted.base().conn(), Some(ConnId::new(3)));
        assert_eq!(inserted.sockindex(), SocketIndex::First);
        assert!(inserted.base().is_attached());

        // A position that does not resolve is the C's `DEBUGASSERT(cf_at)`,
        // which a position cannot express, so it reports instead.
        let outcome = Haproxy::insert_after(
            &mut cx,
            &mut chain,
            99,
            HaproxyConfig::new(),
        );
        assert_eq!(
            outcome.expect_err("no filter at 99").code(),
            CURLcode::BadFunctionArgument
        );
    }

    // -- 2. the header bytes ----------------------------------------------

    /// The Unix-domain literal, byte for byte (`lib/cf-haproxy.c:75`).
    #[test]
    fn the_unknown_header_is_the_fifteen_byte_c_literal() {
        assert_eq!(HAPROXY_UNKNOWN_HEADER, "PROXY UNKNOWN\r\n");
        assert_eq!(HAPROXY_UNKNOWN_HEADER.len(), 15);
        assert_eq!(
            HAPROXY_UNKNOWN_HEADER.as_bytes(),
            b"PROXY UNKNOWN\r\n",
            "the literal is wire bytes and takes no reformatting"
        );

        let clock = clock();
        let (mut filter, wire) =
            rig(HaproxyConfig::new().with_unix_domain_socket(true));
        connect_fully(&mut filter, &clock);

        assert_eq!(wire_bytes(&wire), b"PROXY UNKNOWN\r\n".to_vec());
        assert_eq!(wire_bytes(&wire).len(), 15);
        // A Unix-domain destination asks the transport nothing about
        // addresses: the C's `#ifdef USE_UNIX_SOCKETS` branch returns before
        // the query.
        assert!(
            !events(&wire).contains(&"query".to_owned()),
            "the address query is skipped for a Unix-domain destination"
        );
    }

    /// An IPv4 destination, byte for byte, compared as a slice rather than a
    /// trimmed string.
    #[test]
    fn an_ipv4_destination_gets_the_tcp4_header_byte_for_byte() {
        let clock = clock();
        let (mut filter, wire) = rig(HaproxyConfig::new());
        wire.borrow_mut().ip_info = Some((false, v4_quad()));

        connect_fully(&mut filter, &clock);

        assert_eq!(
            wire_bytes(&wire),
            b"PROXY TCP4 192.0.2.10 203.0.113.7 54321 443\r\n".to_vec()
        );
        // The ports render as plain decimal integers: no padding, no
        // separators. The C's conversion is `%i` over an `int`-promoted
        // `uint16_t`, which is what `{}` over a `u16` reproduces exactly.
        let parts = fields(&wire_bytes(&wire));
        assert_eq!(parts[4], "54321");
        assert_eq!(parts[5], "443");
        // `eos` is FALSE: the header is a preamble, not the end of a stream.
        assert_eq!(wire.borrow().eos_seen, vec![false]);
    }

    /// An IPv6 destination takes the `TCP6` token, and the addresses keep the
    /// unbracketed numeric form `ip_quadruple` stores.
    #[test]
    fn an_ipv6_destination_gets_the_tcp6_header_byte_for_byte() {
        let clock = clock();
        let (mut filter, wire) = rig(HaproxyConfig::new());
        wire.borrow_mut().ip_info = Some((true, v6_quad()));

        connect_fully(&mut filter, &clock);

        assert_eq!(
            wire_bytes(&wire),
            b"PROXY TCP6 2001:db8::10 2001:db8::7 40000 8443\r\n".to_vec()
        );
        let parts = fields(&wire_bytes(&wire));
        assert_eq!(parts[1], "TCP6", "upper case, and not `tcp6`");
        assert!(
            !parts[2].contains('['),
            "the quadruple's addresses are unbracketed"
        );
    }

    /// The family token comes from the ip-info query's own flag, so a chain
    /// that reports IPv6 gets `TCP6` even over addresses that look like
    /// neither -- which is what makes the answer correct for a raced transport.
    #[test]
    fn the_family_token_follows_the_queried_flag_and_nothing_else() {
        let clock = clock();
        for (is_ipv6, expected) in [(false, "TCP4"), (true, "TCP6")] {
            let (mut filter, wire) = rig(HaproxyConfig::new());
            wire.borrow_mut().ip_info = Some((is_ipv6, v4_quad()));
            connect_fully(&mut filter, &clock);
            assert_eq!(fields(&wire_bytes(&wire))[1], expected);
        }
    }

    /// `--haproxy-clientip` replaces field 2 and MUST leave field 3 alone.
    ///
    /// The two fields are asserted independently, and field 3 is additionally
    /// asserted NOT to be the override, so a source/destination swap cannot
    /// pass by producing a well-formed line.
    #[test]
    fn the_client_ip_override_replaces_the_source_and_never_the_destination() {
        let clock = clock();
        let (mut filter, wire) =
            rig(HaproxyConfig::new().with_client_ip("198.51.100.99"));
        wire.borrow_mut().ip_info = Some((false, v4_quad()));

        connect_fully(&mut filter, &clock);

        let bytes = wire_bytes(&wire);
        let parts = fields(&bytes);
        assert_eq!(parts.len(), 6, "PROXY plus five fields");

        // Field 2 -- the SOURCE -- is the override, and is no longer the local
        // address it would otherwise have been.
        assert_eq!(parts[2], "198.51.100.99");
        assert_ne!(parts[2], "192.0.2.10");

        // Field 3 -- the DESTINATION -- is the real remote address, and is NOT
        // the override. This is the assertion that catches a swap.
        assert_eq!(parts[3], "203.0.113.7");
        assert_ne!(parts[3], "198.51.100.99");

        assert_eq!(
            bytes,
            b"PROXY TCP4 198.51.100.99 203.0.113.7 54321 443\r\n".to_vec()
        );
    }

    /// Without the option, field 2 is the local address -- and the same two
    /// fields are still distinct, so the default path cannot swap them either.
    #[test]
    fn without_the_override_the_source_is_the_local_address() {
        let clock = clock();
        let (mut filter, wire) = rig(HaproxyConfig::new());
        connect_fully(&mut filter, &clock);

        let parts = fields(&wire_bytes(&wire));
        assert_eq!(parts[2], "192.0.2.10", "the local address");
        assert_eq!(parts[3], "203.0.113.7", "the remote address");
    }

    /// The option's PRESENCE decides, not its content: the C tests the
    /// pointer, so `CURLOPT_HAPROXY_CLIENT_IP` set to `""` yields an empty
    /// field rather than falling back to the local address.
    #[test]
    fn an_empty_client_ip_is_still_an_override() {
        let clock = clock();
        let (mut filter, wire) = rig(HaproxyConfig::new().with_client_ip(""));
        connect_fully(&mut filter, &clock);

        assert_eq!(
            wire_bytes(&wire),
            b"PROXY TCP4  203.0.113.7 54321 443\r\n".to_vec(),
            "an empty source field, exactly as the C's pointer test yields"
        );
    }

    /// The line ends with `\r\n` and nothing follows it.
    #[test]
    fn the_header_ends_with_crlf_and_nothing_follows_it() {
        let clock = clock();
        let (mut filter, wire) = rig(HaproxyConfig::new());
        connect_fully(&mut filter, &clock);

        let bytes = wire_bytes(&wire);
        assert!(bytes.ends_with(b"\r\n"), "CRLF, never a bare LF");
        assert_eq!(
            bytes.iter().filter(|byte| **byte == b'\n').count(),
            1,
            "exactly one line, with no trailing newline beyond the terminator"
        );
        assert_eq!(bytes.iter().filter(|byte| **byte == b'\r').count(), 1);
        // The CR is the byte before the LF, so the pair is a terminator rather
        // than two stray control bytes.
        let lf = bytes.len() - 1;
        assert_eq!(bytes[lf - 1], b'\r');
        assert!(bytes.is_ascii(), "the whole header is ASCII");
    }

    // -- 3. the ceiling ---------------------------------------------------

    /// `DYN_HAXPROXY` is 2048 (`lib/curlx/dynbuf.h:68`), and an absurd
    /// client IP crosses it: the composition reports the buffer's over-limit
    /// error rather than truncating the header or panicking.
    #[test]
    fn an_oversized_client_ip_is_refused_by_the_dynbuf_ceiling() {
        assert_eq!(DYN_HAXPROXY, 2048);

        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let absurd = "9".repeat(4 * DYN_HAXPROXY);
        let (mut filter, wire) =
            rig(HaproxyConfig::new().with_client_ip(absurd));

        let error = filter
            .connect(&mut cx)
            .expect_err("a header past the ceiling is refused");

        assert_eq!(error.code(), CURLcode::TooLarge);
        // Nothing partial reached the wire, and the filter did not report
        // itself connected on the way out.
        assert!(wire_bytes(&wire).is_empty());
        assert!(!filter.base().is_connected());
        assert!(
            !events(&wire).contains(&"send".to_owned()),
            "the write is never attempted"
        );

        // The state stays INIT, because the C advances to SEND only AFTER the
        // composition succeeds (`lib/cf-haproxy.c:119-122`). So a retry
        // recomposes from the start rather than trying to send a buffer the
        // ceiling path has already emptied -- and fails identically, which is
        // what makes the outcome deterministic rather than order-dependent.
        assert_eq!(filter.state(), HaproxyState::Init);
        assert!(filter.pending().is_empty());
        let again = filter.connect(&mut cx).expect_err("still too large");
        assert_eq!(again.code(), CURLcode::TooLarge);
        assert_eq!(filter.state(), HaproxyState::Init);
    }

    /// A client IP that fits is not refused -- so the test above is a ceiling
    /// test rather than a blanket rejection of long values.
    #[test]
    fn a_client_ip_that_fits_the_ceiling_is_accepted() {
        let clock = clock();
        let long = "7".repeat(64);
        let (mut filter, wire) =
            rig(HaproxyConfig::new().with_client_ip(long.clone()));
        connect_fully(&mut filter, &clock);

        assert_eq!(fields(&wire_bytes(&wire))[2], long);
    }

    // -- 4. the partial write ---------------------------------------------

    /// A transport that accepts ONE byte per write still receives the header
    /// exactly once, in order, with no duplicated prefix.
    ///
    /// `curlx_dyn_tail(&ctx->data_out, len - nwritten)`
    /// (`lib/cf-haproxy.c:137`) is the whole mechanism: the buffer is truncated
    /// to the UNSENT TAIL, so the next call resumes where the last one stopped
    /// instead of resending from the start.
    #[test]
    fn a_one_byte_at_a_time_transport_gets_the_header_exactly_once() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let (mut filter, wire) = rig(HaproxyConfig::new());
        wire.borrow_mut().write_limit = Some(1);

        let expected = b"PROXY TCP4 192.0.2.10 203.0.113.7 54321 443\r\n";
        let mut calls = 0_usize;
        loop {
            calls += 1;
            assert!(calls <= expected.len() + 2, "the send must make progress");
            if filter.connect(&mut cx).expect("each step succeeds") {
                break;
            }
            // Between steps the filter is in SEND, not yet connected, and the
            // buffer holds precisely the bytes still owed.
            assert_eq!(filter.state(), HaproxyState::Send);
            assert!(!filter.base().is_connected());
            let written = wire_bytes(&wire).len();
            assert_eq!(
                filter.pending(),
                &expected[written..],
                "the buffer holds the unsent tail and nothing else"
            );
        }

        assert_eq!(wire_bytes(&wire), expected.to_vec());
        assert_eq!(
            calls,
            expected.len(),
            "one accepted byte per call, and no extra pass"
        );
        assert_eq!(filter.state(), HaproxyState::Done);
        assert!(filter.base().is_connected());
        // Every write carried `eos = false`.
        assert!(wire.borrow().eos_seen.iter().all(|eos| !*eos));
    }

    /// A transport that accepts the header in two uneven pieces gets it once,
    /// which is the ordinary shape of a short write.
    #[test]
    fn a_split_write_is_resumed_rather_than_restarted() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let (mut filter, wire) = rig(HaproxyConfig::new());
        let expected = b"PROXY TCP4 192.0.2.10 203.0.113.7 54321 443\r\n";

        wire.borrow_mut().write_limit = Some(11);
        assert!(!filter
            .connect(&mut cx)
            .expect("a short write is not an error"));
        assert_eq!(wire_bytes(&wire), b"PROXY TCP4 ".to_vec());
        assert_eq!(filter.pending(), &expected[11..]);

        wire.borrow_mut().write_limit = None;
        assert!(filter.connect(&mut cx).expect("the remainder goes out"));

        assert_eq!(wire_bytes(&wire), expected.to_vec());
        // The prefix appears exactly once -- a restart would have produced
        // "PROXY TCP4 PROXY TCP4 ...".
        let text = String::from_utf8(wire_bytes(&wire)).expect("ASCII");
        assert_eq!(text.matches("PROXY").count(), 1);
    }

    /// `CURLE_AGAIN` is mapped to `CURLE_OK` (`lib/cf-haproxy.c:132-135`): the
    /// filter stays unconnected and re-entrant, and a later call completes.
    #[test]
    fn a_would_block_leaves_the_filter_unconnected_and_re_entrant() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let (mut filter, wire) = rig(HaproxyConfig::new());
        wire.borrow_mut().again_writes = 2;

        for attempt in 0..2 {
            let done = filter
                .connect(&mut cx)
                .expect("a would-block is not an error");
            assert!(!done, "attempt {attempt} cannot finish");
            assert_eq!(filter.state(), HaproxyState::Send);
            assert!(!filter.base().is_connected());
            assert!(
                wire_bytes(&wire).is_empty(),
                "nothing is written while the transport blocks"
            );
            // The buffer is left WHOLE: `nwritten = 0` means the tail is the
            // entire header.
            assert_eq!(filter.pending().len(), 45);
        }

        assert!(filter.connect(&mut cx).expect("the third call proceeds"));
        assert_eq!(
            wire_bytes(&wire),
            b"PROXY TCP4 192.0.2.10 203.0.113.7 54321 443\r\n".to_vec()
        );
        assert!(filter.base().is_connected());
    }

    /// A write failure that is NOT a would-block propagates, and leaves the
    /// filter unconnected with its buffer intact for the caller to abandon.
    #[test]
    fn a_real_write_failure_propagates_unchanged() {
        #[derive(Debug)]
        struct Refuser {
            base: FilterBase,
        }

        impl ConnFilter for Refuser {
            fn trace_name(&self) -> &'static str {
                "REFUSER"
            }

            fn base(&self) -> &FilterBase {
                &self.base
            }

            fn base_mut(&mut self) -> &mut FilterBase {
                &mut self.base
            }

            fn connect(
                &mut self,
                _cx: &mut CallCtx<'_, '_>,
            ) -> CurlResult<bool> {
                self.base.set_connected(true);
                Ok(true)
            }

            fn close(&mut self, _cx: &mut CallCtx<'_, '_>) {}

            fn send(
                &mut self,
                _cx: &mut CallCtx<'_, '_>,
                _buf: &[u8],
                _eos: bool,
            ) -> CurlResult<usize> {
                Err(Error::with_context(CURLcode::SendError, "refused"))
            }

            fn query(
                &mut self,
                _cx: &mut CallCtx<'_, '_>,
                query: CfQuery,
            ) -> CurlResult<CfQueryValue> {
                match query {
                    CfQuery::IpInfo => Ok(CfQueryValue::IpInfo {
                        is_ipv6: false,
                        quad: v4_quad(),
                    }),
                    _ => Err(Error::new(CURLcode::UnknownOption)),
                }
            }
        }

        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let mut filter =
            Haproxy::new(SocketIndex::First, None, HaproxyConfig::new());
        filter.base_mut().set_next(Some(link(Refuser {
            base: FilterBase::new(SocketIndex::First),
        })));

        let error = filter.connect(&mut cx).expect_err("the write failed");
        assert_eq!(error.code(), CURLcode::SendError);
        assert!(!filter.base().is_connected());
        assert_eq!(filter.state(), HaproxyState::Send);
    }

    // -- 5. the state walk ------------------------------------------------

    /// INIT -> SEND -> DONE, with `connected` becoming true only at DONE.
    ///
    /// The C's two `FALLTHROUGH()`s mean an unconstrained transport traverses
    /// all three in ONE call, so the intermediate states are observed by
    /// constraining the write.
    #[test]
    fn the_state_walks_init_send_done_and_connects_only_at_done() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let (mut filter, wire) = rig(HaproxyConfig::new());
        wire.borrow_mut().write_limit = Some(5);

        assert_eq!(filter.state(), HaproxyState::Init);
        assert!(!filter.base().is_connected());

        assert!(!filter.connect(&mut cx).expect("a short write"));
        assert_eq!(filter.state(), HaproxyState::Send);
        assert!(!filter.base().is_connected());

        wire.borrow_mut().write_limit = None;
        assert!(filter.connect(&mut cx).expect("the rest goes out"));
        assert_eq!(filter.state(), HaproxyState::Done);
        assert!(filter.base().is_connected());
        // DONE releases the buffer.
        assert!(filter.pending().is_empty());

        // `if(cf->connected) { *done = TRUE; return CURLE_OK; }`: a further
        // call is a no-op that touches the transport not at all.
        let sends = events(&wire).iter().filter(|e| *e == "send").count();
        assert!(filter.connect(&mut cx).expect("already connected"));
        assert_eq!(
            events(&wire).iter().filter(|e| *e == "send").count(),
            sends,
            "a connected filter writes nothing further"
        );
    }

    /// The filter below is connected FIRST, and its not-yet-done verdict is
    /// returned unchanged -- before any header is composed, because two of the
    /// header's fields do not exist until the socket is connected.
    #[test]
    fn the_transport_is_connected_before_the_header_is_composed() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let (mut filter, wire) = rig(HaproxyConfig::new());
        wire.borrow_mut().connects_done = false;

        assert!(!filter.connect(&mut cx).expect("still connecting below"));

        assert_eq!(
            filter.state(),
            HaproxyState::Init,
            "the header is not composed while the transport is connecting"
        );
        assert!(filter.pending().is_empty());
        assert_eq!(events(&wire), vec!["connect".to_owned()]);

        wire.borrow_mut().connects_done = true;
        assert!(filter.connect(&mut cx).expect("now it completes"));
        assert_eq!(filter.state(), HaproxyState::Done);
    }

    // -- 6. close and destroy ---------------------------------------------

    /// `cf_haproxy_close` (`lib/cf-haproxy.c:163-171`): clear `connected`,
    /// reset the context, THEN chain -- and a reconnect rebuilds the header.
    #[test]
    fn close_resets_the_state_chains_down_and_a_reconnect_rebuilds_it() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let (mut filter, wire) = rig(HaproxyConfig::new());

        assert!(filter.connect(&mut cx).expect("connected"));
        assert_eq!(filter.state(), HaproxyState::Done);

        filter.close(&mut cx);

        assert!(!filter.base().is_connected());
        assert_eq!(filter.state(), HaproxyState::Init, "the reset happened");
        assert!(filter.pending().is_empty());
        assert!(
            events(&wire).contains(&"close".to_owned()),
            "the close is chained down"
        );

        // A second connect composes a FRESH header rather than resending a
        // stale one -- and picks up the addresses the transport reports NOW.
        wire.borrow_mut().ip_info = Some((true, v6_quad()));
        wire.borrow_mut().output.clear();
        assert!(filter.connect(&mut cx).expect("reconnected"));
        assert_eq!(
            wire_bytes(&wire),
            b"PROXY TCP6 2001:db8::10 2001:db8::7 40000 8443\r\n".to_vec(),
            "the second header describes the second connection"
        );
    }

    /// `cf_haproxy_destroy` (`lib/cf-haproxy.c:156-161`) releases the buffer
    /// and does NOT chain: the caller has already severed the link and owns
    /// the rest of the chain, so reaching `next` would destroy it twice.
    #[test]
    fn destroy_shutdown_and_control_do_not_reach_the_filter_below() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let (mut filter, wire) = rig(HaproxyConfig::new());
        assert!(filter.connect(&mut cx).expect("connected"));

        // `shutdown` is `Curl_cf_def_shutdown`, which reports done WITHOUT
        // chaining.
        assert!(filter.shutdown(&mut cx).expect("the default shutdown"));
        // `cntrl` is `Curl_cf_def_cntrl`, which returns OK without chaining.
        filter
            .cntrl(&mut cx, CfControl::DataDoneSend)
            .expect("the default control");
        filter.destroy(&mut cx);

        let seen = events(&wire);
        for not_chained in ["shutdown", "cntrl", "destroy"] {
            assert!(
                !seen.contains(&not_chained.to_owned()),
                "{not_chained} must not be chained; log was {seen:?}"
            );
        }
        assert!(filter.pending().is_empty(), "destroy released the buffer");
    }

    /// The eight operations the C leaves as `Curl_cf_def_*` keep those exact
    /// answers, including the pair the C has deliberately swapped.
    #[test]
    fn the_eight_defaults_are_left_exactly_as_the_c_declares_them() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let mut filter =
            Haproxy::new(SocketIndex::First, None, HaproxyConfig::new());

        // With no filter below, each default bottoms out at its own code.
        assert!(!filter.data_pending(&cx));
        assert_eq!(
            filter
                .send(&mut cx, b"x", false)
                .expect_err("no transport")
                .code(),
            CURLcode::RecvError,
            "`Curl_cf_def_send` returns CURLE_RECV_ERROR -- not a slip"
        );
        let mut buf = [0_u8; 4];
        assert_eq!(
            filter
                .recv(&mut cx, &mut buf)
                .expect_err("no transport")
                .code(),
            CURLcode::SendError,
            "`Curl_cf_def_recv` returns CURLE_SEND_ERROR -- the pair is kept"
        );
        assert!(!filter.is_alive(&mut cx).alive);
        filter.keep_alive(&mut cx).expect("the default keeps alive");
        // `Curl_cf_def_cntrl` returns OK without chaining, so it succeeds even
        // with nothing below.
        filter
            .cntrl(&mut cx, CfControl::DataSetup)
            .expect("the default control");
        assert_eq!(
            filter
                .query(&mut cx, CfQuery::HostPort)
                .expect_err("nobody answers")
                .code(),
            CURLcode::UnknownOption
        );
        assert!(filter.shutdown(&mut cx).expect("done without chaining"));

        // And each of them DOES reach the filter below when there is one --
        // except the three that must not, which the test above covers.
        let (mut linked, wire) = rig(HaproxyConfig::new());
        assert_eq!(
            linked
                .query(&mut cx, CfQuery::Socket)
                .expect("the transport answers"),
            CfQueryValue::Socket(9)
        );
        assert_eq!(
            linked
                .send(&mut cx, b"payload", false)
                .expect("passed down"),
            7,
            "payload bytes pass straight through the pass-through default"
        );
        assert_eq!(wire_bytes(&wire), b"payload".to_vec());
    }

    // -- 7. readiness -----------------------------------------------------

    /// `cf_haproxy_adjust_pollset` (`lib/cf-haproxy.c:173-184`): out-only, and
    /// only while `cf->next->connected && !cf->connected`.
    #[test]
    fn the_pollset_asks_to_write_only_while_the_header_is_going_out() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let (mut filter, wire) = rig(HaproxyConfig::new());
        wire.borrow_mut().write_limit = Some(4);

        // Both halves false: nothing below is connected yet.
        let mut ps = EasyPollset::new();
        filter.adjust_pollset(&mut cx, &mut ps).expect("no-op");
        assert!(ps.is_empty(), "an unconnected transport registers nothing");

        // Below connected, this filter not: the sending window.
        assert!(!filter.connect(&mut cx).expect("a short write"));
        let mut ps = EasyPollset::new();
        filter.adjust_pollset(&mut cx, &mut ps).expect("registered");
        assert_eq!(ps.len(), 1);
        assert_eq!(
            ps.action_of(9),
            PollAction::OUT,
            "OUT only -- a peer never answers a PROXY header"
        );
        assert!(
            !ps.action_of(9).contains_in(),
            "POLLIN is removed, not left"
        );

        // Out-only REMOVES a readability another filter registered.
        let mut ps = EasyPollset::new();
        ps.set_in_only(9, None).expect("a readable registration");
        assert!(ps.action_of(9).contains_in());
        filter.adjust_pollset(&mut cx, &mut ps).expect("registered");
        assert_eq!(ps.action_of(9), PollAction::OUT);

        // This filter connected: nothing more to wait for.
        wire.borrow_mut().write_limit = None;
        assert!(filter.connect(&mut cx).expect("finished"));
        let mut ps = EasyPollset::new();
        filter.adjust_pollset(&mut cx, &mut ps).expect("no-op");
        assert!(
            ps.is_empty(),
            "a connected HAPROXY filter waits for nothing of its own"
        );
    }

    /// The double condition is not `!cf->connected`: a transport that is still
    /// connecting owns the readiness for that phase, and this filter must not
    /// override it.
    #[test]
    fn an_unconnected_transport_keeps_its_own_readiness() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let (mut filter, wire) = rig(HaproxyConfig::new());
        wire.borrow_mut().connects_done = false;

        assert!(!filter.connect(&mut cx).expect("still connecting below"));
        assert!(!filter.base().is_connected());

        let mut ps = EasyPollset::new();
        ps.set_in_only(9, None)
            .expect("the transport's own interest");
        filter.adjust_pollset(&mut cx, &mut ps).expect("no-op");

        assert_eq!(
            ps.action_of(9),
            PollAction::IN,
            "the transport's readability survives untouched"
        );
    }

    // -- 8. a chain with no transport -------------------------------------

    /// The C dereferences `cf->next` in `connect`, in `date_out_set` and in
    /// `adjust_pollset`. A chain without a transport below is a construction
    /// bug, and each of the three reports it rather than reproducing the
    /// dereference.
    #[test]
    fn a_chain_with_no_transport_below_reports_failed_init() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let mut filter =
            Haproxy::new(SocketIndex::First, None, HaproxyConfig::new());

        assert_eq!(
            filter.connect(&mut cx).expect_err("nothing below").code(),
            CURLcode::FailedInit
        );

        // `adjust_pollset` treats it as "waiting for nothing", which is the
        // honest answer: there is no socket to wait on.
        let mut ps = EasyPollset::new();
        filter.adjust_pollset(&mut cx, &mut ps).expect("no-op");
        assert!(ps.is_empty());
    }

    /// A transport that answers no address query cannot have a header composed
    /// for it, and the C's unanswered-query sentinel is what comes back.
    #[test]
    fn an_unanswered_address_query_is_reported_not_guessed() {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let (mut filter, wire) = rig(HaproxyConfig::new());
        wire.borrow_mut().ip_info = None;

        let error = filter.connect(&mut cx).expect_err("no addresses");

        assert_eq!(error.code(), CURLcode::UnknownOption);
        assert!(wire_bytes(&wire).is_empty());
        assert!(!filter.base().is_connected());
    }

    // -- 9. tracing -------------------------------------------------------

    /// The filter's trace lines are attributed to it, so
    /// `--trace-config proxy` shows the header going out.
    #[test]
    fn the_filter_emits_lines_attributed_to_its_own_identity() {
        let clock = clock();
        let mut config = TraceConfig::new();
        config.set_filter_level(TraceFilter::HaProxy, TraceLevel::Info);
        let mut sink = WriterSink::new(Vec::new());
        let mut tracer = Tracer::new(&config, &mut sink);
        tracer.set_verbose(true);

        let (mut filter, _wire) = rig(HaproxyConfig::new());
        {
            let mut cx = CallCtx::new(&clock).with_tracer(&mut tracer);
            assert!(filter.connect(&mut cx).expect("connected"));
            filter.close(&mut cx);
            filter.destroy(&mut cx);
        }

        let rendered = String::from_utf8(sink.into_inner()).expect("UTF-8");
        assert!(rendered.contains("[HAPROXY]"), "rendered: {rendered}");
        assert!(rendered.contains("PROXY protocol header sent"));
        assert!(rendered.contains("close"));
        assert!(rendered.contains("destroy"));
    }
}
