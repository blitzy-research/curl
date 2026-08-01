<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# String parsing with `strparse`

The functions take input via a pointer to a pointer, which allows the
functions to advance the pointer on success which then by extension allows
"chaining" of functions like this example that gets a word, a space and then a
second word:

~~~c
if(curlx_str_word(&line, &word1, MAX) ||
   curlx_str_singlespace(&line) ||
   curlx_str_word(&line, &word2, MAX))
  fprintf(stderr, "ERROR\n");
~~~

The input pointer **must** point to a null-terminated buffer area or these
functions risk continuing "off the edge".

## Strings

The functions that return string information does so by populating a
`struct Curl_str`:

~~~c
struct Curl_str {
  char *str;
  size_t len;
};
~~~

Access the struct fields with `curlx_str()` for the pointer and `curlx_strlen()`
for the length rather than using the struct fields directly.

## `curlx_str_init`

~~~c
void curlx_str_init(struct Curl_str *out)
~~~

This initiates a string struct. The parser functions that store info in
strings always init the string themselves, so this stand-alone use is often
not necessary.

## `curlx_str_assign`

~~~c
void curlx_str_assign(struct Curl_str *out, const char *str, size_t len)
~~~

Set a pointer and associated length in the string struct.

## `curlx_str_word`

~~~c
int curlx_str_word(char **linep, struct Curl_str *out, const size_t max);
~~~

Get a sequence of bytes until the first space or the end of the string. Return
non-zero on error. There is no way to include a space in the word, no sort of
escaping. The word must be at least one byte, otherwise it is considered an
error.

`max` is the longest accepted word, or it returns error.

On a successful return, `linep` is updated to point to the byte immediately
following the parsed word.

## `curlx_str_until`

~~~c
int curlx_str_until(char **linep, struct Curl_str *out, const size_t max,
                   char delim);
~~~

Like `curlx_str_word` but instead of parsing to space, it parses to a given
custom delimiter non-zero byte `delim`.

`max` is the longest accepted word, or it returns error.

The parsed word must be at least one byte, otherwise it is considered an
error.

## `curlx_str_untilnl`

~~~c
int curlx_str_untilnl(char **linep, struct Curl_str *out, const size_t max);
~~~

Like `curlx_str_untilnl` but instead parses until it finds a "newline byte".
That means either a CR (ASCII 13) or an LF (ASCII 10) octet.

`max` is the longest accepted word, or it returns error.

The parsed word must be at least one byte, otherwise it is considered an
error.

## `curlx_str_cspn`

~~~c
int curlx_str_cspn(const char **linep, struct Curl_str *out, const char *cspn);
~~~

Get a sequence of characters until one of the bytes in the `cspn` string
matches. Similar to the `strcspn` function.

## `curlx_str_quotedword`

~~~c
int curlx_str_quotedword(char **linep, struct Curl_str *out, const size_t max);
~~~

Get a "quoted" word. This means everything that is provided within a leading
and an ending double quote character. No escaping possible.

`max` is the longest accepted word, or it returns error.

The parsed word must be at least one byte, otherwise it is considered an
error.

## `curlx_str_single`

~~~c
int curlx_str_single(char **linep, char byte);
~~~

Advance over a single character provided in `byte`. Return non-zero on error.

## `curlx_str_singlespace`

~~~c
int curlx_str_singlespace(char **linep);
~~~

Advance over a single ASCII space. Return non-zero on error.

## `curlx_str_passblanks`

~~~c
void curlx_str_passblanks(char **linep);
~~~

Advance over all spaces and tabs.

## `curlx_str_trimblanks`

~~~c
void curlx_str_trimblanks(struct Curl_str *out);
~~~

Trim off blanks (spaces and tabs) from the start and the end of the given
string.

## `curlx_str_number`

~~~c
int curlx_str_number(char **linep, curl_size_t *nump, size_t max);
~~~

Get an unsigned decimal number not larger than `max`. Leading zeroes are just
swallowed. Return non-zero on error. Returns error if there was not a single
digit.

## `curlx_str_numblanks`

~~~c
int curlx_str_numblanks(char **linep, curl_size_t *nump);
~~~

Get an unsigned 63-bit decimal number. Leading blanks and zeroes are skipped.
Returns non-zero on error. Returns error if there was not a single digit.

## `curlx_str_hex`

~~~c
int curlx_str_hex(char **linep, curl_size_t *nump, size_t max);
~~~

Get an unsigned hexadecimal number not larger than `max`. Leading zeroes are
just swallowed. Return non-zero on error. Returns error if there was not a
single digit. Does *not* handled `0x` prefix.

## `curlx_str_octal`

~~~c
int curlx_str_octal(char **linep, curl_size_t *nump, size_t max);
~~~

Get an unsigned octal number not larger than `max`. Leading zeroes are just
swallowed. Return non-zero on error. Returns error if there was not a single
digit.

## `curlx_str_newline`

~~~c
int curlx_str_newline(char **linep);
~~~

Check for a single CR or LF. Return non-zero on error */

## `curlx_str_casecompare`

~~~c
int curlx_str_casecompare(struct Curl_str *str, const char *check);
~~~

Returns true if the provided string in the `str` argument matches the `check`
string case insensitively.

## `curlx_str_cmp`

~~~c
int curlx_str_cmp(struct Curl_str *str, const char *check);
~~~

Returns true if the provided string in the `str` argument matches the `check`
string case sensitively. This is *not* the same return code as `strcmp`.

## `curlx_str_nudge`

~~~c
int curlx_str_nudge(struct Curl_str *str, size_t num);
~~~

Removes `num` bytes from the beginning (left) of the string kept in `str`. If
`num` is larger than the string, it instead returns an error.

## Reference oracle and specified `Rust` successor

The functions above are implemented in `lib/curlx/strparse.c`, and their
prototypes and error codes are declared in `lib/curlx/strparse.h`. Those two
files are the reference oracle for this parsing layer: they define the accepted
syntax and the error boundaries that the migration to a `Rust` `workspace`
preserves. No successor to `lib/curlx/strparse.c` exists yet, so the C sources
remain the working implementation and the parsing module named below is
specified target state. Of the consumers listed later on this page, one --
`curl-rs/src/cli/paramhlp.rs` -- has been delivered; the rest are specified
target state as well, and each is marked where it appears.

### The contract the C sources define

Four properties of these functions are behavior rather than convenience, and a
successor that departs from any of them changes what curl accepts.

- **Accepted syntax is behavior.** What counts as a word, which byte terminates
  a word, which characters a quoted word may escape, what a number may look
  like, which radix prefixes the hexadecimal and octal parsers accept, and
  where blanks are permitted are all reachable from outside the library:
  through command-line arguments, through configuration files and through
  header values. A parser that accepts more than these functions accept, or
  less, changes behavior.
- **Error boundaries are behavior too.** Overflow rejection in the numeric
  parsers, the maximum lengths that callers pass as `max`, and the distinction
  between a value that is not present and a value that is present but
  malformed all propagate outwards as specific error codes and specific
  messages.
- **The advance-on-success discipline.** The functions that walk the input take
  a pointer to the current position and advance it only when they succeed.
  That is what lets a caller chain attempts and fall through on the first
  failure, and it is the reason the introduction can show the chaining idiom.
- **Input is null-terminated.** The C interface depends on it, as the warning
  under the introduction states.

### The specified successor module

The migration specifies `curl-rs-lib/src/util/strparse.rs`, derived from
`lib/curlx/strparse.c`, as the successor to this layer. It is one of the six
`lib/curlx/` sources specified to receive a dedicated module rather than being
absorbed into a shared utility module; see [`CURLX`](CURLX.md) for what the
`curlx_` prefix means and what it implies about these sources.

The transformation is preservation of accepted syntax and error boundaries, and
that is the whole of its purpose. It is not a rewrite in a more fashionable
style. In particular, the target does not delegate this parsing wholesale to a
general-purpose parsing `crate`, because the accepted spellings here are curl's
own and a general parser accepts a different set.

### How the mechanism maps

- `struct Curl_str`, a pointer beside a length, becomes a borrowed byte or
  string slice. The length is carried by the slice type instead of by a
  separate field, so the pointer and the length cannot drift apart.
- The null-termination requirement disappears as an interface obligation. A
  slice carries its own extent, so the successor parses over a bounded region
  instead of over a pointer that the caller promised is terminated somewhere.
  That removes a class of defect rather than tidying one: continuing off the
  edge stops being expressible.
- The advance-on-success discipline is preserved. The specified design advances
  the position only when a parse succeeds, so the chaining idiom shown in the
  introduction has a direct counterpart. The difference is that a failed
  attempt cannot leave a partially advanced cursor visible to the attempt that
  follows it.
- Each of the nineteen documented functions has a counterpart in the specified
  module. The accepted syntax of every counterpart is fixed by the C prototype
  above it on this page, which is why those prototypes are reproduced here
  unchanged.
- Numeric parsing keeps the overflow and radix behavior of the C functions,
  including the specific result each one returns for a value that is out of
  range. Where the standard library's integer parsing accepts or rejects a
  different set of spellings, the module matches the C functions instead of the
  standard library.
- Case-insensitive comparison keeps curl's own definition of case folding,
  which is ASCII-scoped. That deserves stating outright, because a locale-aware
  or Unicode-aware comparison is a behavior change and not a refinement.

### Consumers in the specified target

These consumers are why this fidelity matters. Each of them turns text that
arrives from outside into a decision.

- Command-line argument parsing, at `curl-rs/src/cli/args.rs` and
  `curl-rs/src/cli/paramhlp.rs`, reads numbers, sizes, lists and protocol names
  out of arguments. Both files are on disk, and both compile: `args.rs` supplies
  the `ParameterError` vocabulary that `paramhlp.rs` imports as
  `super::args::ParameterError`. What `args.rs` does not yet carry is the
  clap-derived parser that would turn an argument vector into a configuration,
  and `main.rs` does not call into it, so the binary exits reporting that no
  command-line option can be honoured.
- The configuration-file reader at `curl-rs/src/config/parseconfig.rs` reads
  the same option spellings out of a file instead of out of an argument vector,
  quoted values included.
- Header and response parsing at `curl-rs-lib/src/protocols/http1.rs` splits
  status lines and header lines, where a disagreement about what terminates a
  token is observable on the wire.
- Date parsing at `curl-rs-lib/src/util/parsedate.rs` accepts the date formats
  curl accepts. `curl_getdate` is a public export, so that grammar is part of
  the ABI and not an internal detail.

### Safety and verification

The safety invariant at the root of `curl-rs-lib` is `#![deny(unsafe_code)]`
plus exactly one `#[allow(unsafe_code)]`, on `mod ffi` -- the one narrowly
allowed island at `curl-rs-lib/src/ffi/`, where every `unsafe` block carries a
mandatory `// SAFETY:` comment. It is `deny` and not `forbid` because `forbid`
cannot be locally overridden (`error[E0453]: allow(unsafe_code) incompatible
with previous forbid`) and Agent Action Plan goal G1 permits only three
crates, so the island cannot move into a fourth; `deny` is no weaker, since a
stray `unsafe` block outside the island is a hard error rather than a warning.
In `curl-rs` there is no island at all: measured, that crate contains zero
`unsafe` blocks and zero `#[allow(unsafe_code)]` attributes, so both of its
roots carry `#![forbid(unsafe_code)]` literally -- `curl-rs/src/main.rs` and
the diagnostic binary `curl-rs/src/bin/curlinfo.rs`. Parsing has no business in
an unsafe island in any case. Slice indexing is bounds-checked, so a parser
expressed over slices needs nothing from it.

Fidelity is asserted against the fixture corpus under `tests/data`, where a
fixture can pin the exact bytes the client sends. A parser that accepts a
different set of spellings than the C functions accept therefore surfaces as a
fixture mismatch rather than as a silent difference in behavior.
