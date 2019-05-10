#!/bin/bash
# so-check v0.0.1
# Checks for search order privilege escalation vectors
# in system shared objects and executables in $PATH
#
# Related reading:
# https://www.win.tue.nl/~aeb/linux/hh/hh-8.html
# https://www.contextis.com/en/blog/linux-privilege-escalation-via-dynamically-linked-shared-object-library
# https://www.contextis.com/media/images/content/Linux_Privilege_Escalation_via_Dynamically_Linked_Shared_Object_Library02.png
# https://www.exploit-db.com/papers/37606
#
# ~ bcoles 2019
IFS=$'\n\t'
VERBOSE="false"

__script_params=("$@")

readonly _version="0.0.1"

function info() { echo -e "\\033[1;34m[*]\\033[0m  $*"; }
function warn() { echo -e "\\033[1;33m[WARNING]\\033[0m  $*"; }
function error() { echo -e "\\033[1;31m[ERROR]\\033[0m  $*"; exit 1 ; }
function issue() { echo -e "\\033[1;33m[!]\\033[0m  $*"; }
function verbose() { [ "${VERBOSE}" = "true" ] && echo "$*"; }

function __main__() {
  echo -e "--[ \\033[1;32mso-check v${_version}\\033[0m ]--"
  echo

  if [ "$(id -u)" -eq 0 ]; then
    echo
    echo "Running this tool as root does not make sense."
    echo
    id
    exit 1
  fi

  setup
  echo

  info "Environment info:"
  echo

  echo "PATH=${PATH}"
  echo "LD_LIBRARY_PATH=${LD_LIBRARY_PATH}"
  echo "LD_RUN_PATH=${LD_RUN_PATH}"

  junk=$(tr -dc 'a-zA-Z0-9' </dev/urandom | fold -w 32 | head -n 1)
  search_paths=$(LD_PRELOAD="${junk}" LD_DEBUG=libs env 2>/dev/stdout | grep "search path=" | cut -d= -f2- | sed -e 's/\t/\n/g' | head -n 1)
  echo "Library search paths: ${search_paths}"
  echo

  info "Checking library paths..."
  echo

  if [ ! -z "${LD_LIBRARY_PATH}" ] && [ -d "${LD_LIBRARY_PATH}" ] && [ -w "${LD_LIBRARY_PATH}" ]; then
    issue "LD_LIBRARY_PATH $LD_LIBRARY_PATH is writable!"
  fi

  if [ ! -z "${LD_RUN_PATH}" ] && [ -d "${LD_RUN_PATH}" ] && [ -w "${LD_RUN_PATH}" ]; then
    issue "LD_RUN_PATH $LD_RUN_PATH is writable!"
  fi

  while read -r line; do
    p="${line}"

    if [ -d "${p}" ] && [ -w "${p}" ]; then
      issue "${p} directory in library search path is writable!"
    fi
  done <<< "${search_paths//:/$'\n'}"

  info "Checking executable paths..."
  echo

  while read -r line; do
    p="${line}"

    if [ -z "${p}" ]; then
      issue "\$PATH contains empty path"
      continue
    fi

    if [ "${p}" = "." ]; then
      issue "\$PATH contains working directory '.'"
      continue
    fi

    if [ -w "${p}" ]; then
      issue "${p} directory in \$PATH is writable!"
      continue
    fi

    info "Searching executables in ${p} ..."
    echo

    search_path "${p}"
    echo
  done <<< "${PATH//:/$'\n'}"

  info "Complete"
}


function command_exists () {
  command -v "${1}" >/dev/null 2>&1
}

function setup() {
  info "Checking dependencies..."

  # Required
  IFS=' ' read -r -a array <<< "grep sed cut head dirname realpath"
  for bin in "${array[@]}"
  do
    if ! command_exists "${bin}"; then
      error "${bin} is not in \$PATH!"
    fi
  done

  # Optional
  #IFS=' ' read -r -a array <<< "objdump ldd readelf"
  IFS=' ' read -r -a array <<< "objdump ldd"
  for bin in "${array[@]}"
  do
    if ! command_exists "${bin}"; then
      warn "${bin} is not in \$PATH! Some checks will be skipped ..."
    fi
  done
}

function objdump_rpath() {
  path="${1}"

  rpath=$(objdump -x "${path}" 2>/dev/null | grep RPATH | sed 's/RPATH\s*//g' | sed -e 's/^[[:space:]]*//')
  if [ ! -z "${rpath}" ]; then
    verbose "${path} - RPATH: ${rpath}"

    while read -r line; do
      if [[ "${line}" =~ "\$ORIGIN" ]]; then
        p="${line//\$ORIGIN/$(dirname "${path}")\/}"
      else
        p="${line}"
      fi

      if [ -z "${p}" ]; then
        issue "${path} RPATH contains empty path"
        continue
      fi

      if [ "${p}" = "." ]; then
        issue "${path} RPATH contains working directory '.'"
        continue
      fi

      if [ -w "${p}" ]; then
        issue "${path} RPATH ${p} is writable!"
      fi
    done <<< "${rpath//:/$'\n'}"
  fi
}

function objdump_runpath() {
  path="${1}"

  runpath=$(objdump -x "${path}" 2>/dev/null | grep RUNPATH | sed 's/RUNPATH\s*//g' | sed -e 's/^[[:space:]]*//')
  if [ ! -z "${runpath}" ]; then
    verbose "${path} - RUNPATH: ${runpath}"

    while read -r line; do
      if [[ "${line}" =~ "\$ORIGIN" ]]; then
        p="${line//\$ORIGIN/$(dirname "${path}")\/}"
      else
        p="${line}"
      fi

      if [ -z "${p}" ]; then
        issue "${path} RUNPATH contains empty path"
        continue
      fi

      if [ "${p}" = "." ]; then
        issue "${path} RUNPATH contains working directory '.'"
        continue
      fi

      if [ -w "${p}" ]; then
        issue "${path} RUNPATH ${p} is writable!"
      fi
    done <<< "${runpath//:/$'\n'}"
  fi
}

function ldd_notfound() {
  path="${1}"

  notfound=$(ldd "${path}" 2>/dev/null | grep "not found")
  if [ ! -z "${notfound}" ]; then
    issue "${path} missing: ${notfound}"
  fi
}

function ldd_libasan() {
  path="${1}"

  libasan=$(ldd "${path}" 2>/dev/null | grep "libasan.so")
  if [ ! -z "${libasan}" ]; then
    verbose "${path} uses libasan.so"
    if [ -u "${f}" ]; then
      issue "${path} is setuid and uses libasan.so !"
    fi
  fi
}

function readelf_interp() {
  path="${1}"

  interp=$(readelf -l "${path}" 2>/dev/null | grep "interpreter:" | cut -d':' -f2- | sed -e 's/\]$//g' | sed -e 's/^[[:space:]]*//')
  if [ ! -z "${interp}" ] && [ -w "${interp}" ]; then
    issue "${path} interpreter ${interp} is writable!"
  fi
}

function search_path() {
  path="${1}"

  array=()
  while IFS=  read -r -d $'\0'; do
    array+=("$REPLY")
  done < <(find "${path}" -maxdepth 1 -executable -print0 2>/dev/null)

  for ((i=0; i<${#array[@]}; i++)); do
    f="$(realpath "${array[$i]}")"

    verbose "${f}"

    if [ -w "${f}" ]; then
      issue "${f} in \$PATH is writable!"
    fi

    if command_exists objdump; then
      objdump_rpath "${f}"
      objdump_runpath "${f}"
    fi

    if command_exists ldd; then
      ldd_notfound "${f}"
      ldd_libasan "${f}"
    fi

    #if command_exists readelf; then
    #  readelf_interp "${f}"
    #fi
  done <<< "${search_paths//:/$'\n'}"
}

if [[ "${BASH_SOURCE[0]}" = "$0" ]]; then
  __main__ "${__script_params[@]}"
  exit 0
fi
