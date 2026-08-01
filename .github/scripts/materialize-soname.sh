#!/bin/sh
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# SPDX-License-Identifier: curl
#
# Materialize the versioned shared-library artifact and its development
# symlink chain, and report the names it derives.
#
# WHY THIS EXISTS AT ALL. `curl-rs-ffi/build.rs` stamps the runtime identity
# correctly -- `-Wl,--soname=libcurl.so.4` on Linux and
# `-install_name @rpath/libcurl.4.dylib` on Apple -- but Cargo emits ONE file
# and names it `libcurl.so`. So the artifact declares that it is
# `libcurl.so.4` while no file of that name exists. The dynamic loader
# resolves a `DT_NEEDED` entry by FILE NAME, so an existing consumer already
# recording a dependency on `libcurl.so.4` cannot load this build at all: it
# is not a drop-in replacement for the library AAP 0.1.1 requires it to
# replace, no matter how correct its exports are. Review finding M-14.
#
# WHY IT IS A SCRIPT AND NOT PART OF THE BUILD SCRIPT. A Cargo build script
# runs BEFORE the artifact is linked -- it cannot rename or symlink a file
# that does not exist yet -- and Cargo offers no post-link hook and no control
# over its output file name. Materializing is therefore necessarily a
# post-link packaging step. Making it a script rather than inline YAML gives
# `rust-build.yml` (which packages) and `rust-abi.yml` (which asserts) ONE
# authority, so the names they use cannot drift apart.
#
# THE NAMES ARE DERIVED, NEVER TYPED. `lib/Makefile.soname` is the only place
# the version triple appears, and every name below is computed from it, so a
# change there propagates instead of creating a silent mismatch.
#
# Usage:
#   materialize-soname.sh names       <target-triple>
#   materialize-soname.sh materialize <target-triple> <artifact-directory>
#
# `names` prints shell-eval-able assignments and touches nothing.

set -eu

self_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH='' cd -- "${self_dir}/../.." && pwd)"
authority="${repo_root}/lib/Makefile.soname"

usage() {
  echo "usage: $0 names <target-triple>" >&2
  echo "       $0 materialize <target-triple> <artifact-directory>" >&2
  exit 2
}

# Read one `NAME=<digits>` assignment out of the authority.
#
# Anchored on the whole line so a mention inside the file's explanatory
# comment block -- which does discuss `-version-info 3:12:1` -- cannot be
# mistaken for the assignment.
read_version_field() {
  field="$1"
  value="$(sed -n "s/^${field}=\\([0-9][0-9]*\\)\$/\\1/p" "${authority}")"
  if [ -z "${value}" ]; then
    echo "FAIL: ${authority} defines no numeric ${field}." >&2
    echo "Every shared-library name is derived from it, so there is no" >&2
    echo "safe default to fall back to." >&2
    exit 1
  fi
  # More than one match means the authority is ambiguous; refuse rather than
  # silently take the first.
  if [ "$(printf '%s\n' "${value}" | wc -l)" -ne 1 ]; then
    echo "FAIL: ${authority} defines ${field} more than once." >&2
    exit 1
  fi
  echo "${value}"
}

if [ ! -f "${authority}" ]; then
  echo "FAIL: ${authority} is missing." >&2
  exit 1
fi

# libtool's `-version-info current:revision:age`, from lib/Makefile.soname:32.
current="$(read_version_field VERSIONCHANGE)"
revision="$(read_version_field VERSIONADD)"
age="$(read_version_field VERSIONDEL)"

if [ "${current}" -lt "${age}" ]; then
  echo "FAIL: VERSIONCHANGE (${current}) is less than VERSIONDEL (${age})," >&2
  echo "so the soname major would be negative. libtool's rule is" >&2
  echo "major = current - age." >&2
  exit 1
fi

# libtool's two rules, applied verbatim:
#   soname       = lib<name>.so.(current - age)
#   real object  = lib<name>.so.(current - age).(age).(revision)
# With 12:0:8 that is libcurl.so.4 and libcurl.so.4.8.0, which is what
# lib/CMakeLists.txt:285-286 computes for the C build.
major="$((current - age))"
full="${major}.${age}.${revision}"

[ $# -ge 2 ] || usage
mode="$1"
triple="$2"

case "${triple}" in
  *-apple-*)
    # Mach-O puts the version before the extension, not after it.
    dev_name='libcurl.dylib'
    soname="libcurl.${major}.dylib"
    real_name="libcurl.${full}.dylib"
    ;;
  *-linux-*)
    dev_name='libcurl.so'
    soname="libcurl.so.${major}"
    real_name="libcurl.so.${full}"
    ;;
  *)
    echo "FAIL: no shared-library naming rule for target ${triple}." >&2
    echo "AAP 0.8.3 mandates exactly four targets, two -unknown-linux-gnu" >&2
    echo "and two -apple-darwin." >&2
    exit 1
    ;;
esac

case "${mode}" in
  names)
    echo "SONAME_MAJOR=${major}"
    echo "SONAME_FULL=${full}"
    echo "LIBCURL_DEV=${dev_name}"
    echo "LIBCURL_SONAME=${soname}"
    echo "LIBCURL_REAL=${real_name}"
    ;;

  materialize)
    [ $# -eq 3 ] || usage
    dir="$3"

    if [ ! -d "${dir}" ]; then
      echo "FAIL: artifact directory ${dir} does not exist." >&2
      exit 1
    fi

    cd "${dir}"

    # Cargo's own output. It is a regular file on a fresh build and a symlink
    # only if a previous run of this script already ran and nothing relinked
    # since, so both shapes are handled rather than assumed.
    if [ -L "${dev_name}" ]; then
      if [ ! -e "${real_name}" ]; then
        echo "FAIL: ${dev_name} is already a symlink but ${real_name} is" >&2
        echo "missing, so the chain is broken. Rebuild the crate." >&2
        exit 1
      fi
    elif [ -f "${dev_name}" ]; then
      # COPY rather than move. Cargo hardlinks this path from target/*/deps
      # and rebuilds re-create it; taking a copy leaves Cargo's own
      # bookkeeping untouched, which a rename would not.
      cp -p "${dev_name}" "${real_name}.tmp$$"
      mv -f "${real_name}.tmp$$" "${real_name}"
      rm -f "${dev_name}"
    else
      echo "FAIL: ${dir}/${dev_name} does not exist, so there is no shared" >&2
      echo "library to version. Build curl-rs-ffi (crate-type cdylib) first." >&2
      exit 1
    fi

    # The chain, innermost first: the loader follows DT_NEEDED to the soname,
    # and the linker follows -lcurl to the development name.
    #
    #   libcurl.so  ->  libcurl.so.4  ->  libcurl.so.4.8.0
    #
    # Relative link targets, so the whole directory stays relocatable.
    ln -sf "${real_name}" "${soname}"
    ln -sf "${soname}" "${dev_name}"

    echo "materialized in ${dir}:"
    echo "  ${real_name}  (real object)"
    echo "  ${soname} -> $(readlink "${soname}")"
    echo "  ${dev_name} -> $(readlink "${dev_name}")"
    ;;

  *)
    usage
    ;;
esac
