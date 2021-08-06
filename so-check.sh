#!/bin/bash
# so-check v0.0.2
#
# Checks for search order privilege escalation vectors in system
# environment, system shared objects and executable files in $PATH.
#
# Related reading:
# - https://www.win.tue.nl/~aeb/linux/hh/hh-8.html
# - https://www.contextis.com/en/blog/linux-privilege-escalation-via-dynamically-linked-shared-object-library
# - https://www.contextis.com/media/images/content/Linux_Privilege_Escalation_via_Dynamically_Linked_Shared_Object_Library02.png
# - https://www.exploit-db.com/papers/37606
# - https://blog.pentesteracademy.com/abusing-missing-library-for-privilege-escalation-3-minute-read-296dcf81bec2
# ---
# https://github.com/bcoles/so-check
# v0.0.1 - 2019-04-25
# v0.0.2 - 2021-08-06
# ~ bcoles

IFS=$'\n\t'
VERBOSE="false"

__script_params=("$@")

readonly _version="0.0.2"

function info() { echo -e "\\033[1;34m[*]\\033[0m  $*"; }
function warn() { echo -e "\\033[1;33m[WARNING]\\033[0m  $*"; }
function error() { echo -e "\\033[1;31m[ERROR]\\033[0m  $*"; exit 1 ; }
function issue() { echo -e "\\033[1;33m[!]\\033[0m  $*"; }
function verbose() { [ "${VERBOSE}" = "true" ] && echo "$*"; }

function __main__() {
  echo -e "--[ \\033[1;32mso-check v${_version}\\033[0m ]--"
  echo

  if [ "$(id -u)" -eq 0 ]; then
    warn "Running this tool as root does not make much sense (unless you are in a root user namespace) as root user has write permissions for all files."
    echo
  fi

  setup
  echo

  info "System info:"
  echo
  echo "User: $(id)"
  echo "Kernel: $(uname -a)"
  echo "Working directory: $(pwd)"
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

  ld_preload_config="/etc/ld.so.preload"

  info "Checking ${ld_preload_config}..."
  echo

  if [ -w "${ld_preload_config}" ]; then
    issue "${ld_preload_config} is writable!"
  fi

  if [ -r "${ld_preload_config}" ]; then
    while read -r line; do
      p="${line}"

      if [ -w "${p}" ]; then
        issue "${p} in ${ld_preload_config} is writable!"
      fi
    done <<< "$(cat "${ld_preload_config}")"
  fi

  # TODO: extract and iterate through all "include" directories
  # rather than using hard coded /etc/ld.so.conf.d/ directory
  ld_so_config="/etc/ld.so.conf"

  info "Checking ${ld_so_config}..."
  echo

  if [ -w "${ld_so_config}" ]; then
    issue "${ld_so_config} is writable!"
  fi

  if [ -r "${ld_so_config}" ]; then
    while read -r line; do
      p="${line}"

      if [[ ! "${p}" =~ ^/ ]]; then
        continue
      fi

      if [ -d "${p}" ] && [ -w "${p}" ]; then
        issue "${p} in ${ld_so_config} is writable!"
      fi
    done <<< "$(cat "${ld_so_config}")"
  fi

  ld_so_config_dir="/etc/ld.so.conf.d/"

  info "Checking ${ld_so_config_dir}*.conf..."
  echo

  if [ -w "${ld_so_config_dir}" ]; then
    issue "${ld_so_config_dir} is writable!"
  fi

  array=()
  while IFS=  read -r -d $'\0'; do
    array+=("$REPLY")
  done < <(find "${ld_so_config_dir}" -maxdepth 1 -name "*.conf" -print0 2>/dev/null)

  for ((i=0; i<${#array[@]}; i++)); do
    f="$(realpath "${array[$i]}")"

    verbose "${f}"

    if [ -w "${f}" ]; then
      issue "${f} is writable!"
    fi

    while read -r line; do
      p="${line}"

      if [[ "${p}" =~ ^# ]]; then
        continue
      fi

      if [ -d "${p}" ] && [ -w "${p}" ]; then
        issue "${p} directory in ${f} is writable!"
      fi
    done <<< "$(cat "${f}")"
  done

  info "Checking library paths..."
  echo

  if [ -n "${LD_LIBRARY_PATH}" ] && [ -d "${LD_LIBRARY_PATH}" ] && [ -w "${LD_LIBRARY_PATH}" ]; then
    issue "\$LD_LIBRARY_PATH $LD_LIBRARY_PATH is writable!"
  fi

  if [ -n "${LD_RUN_PATH}" ] && [ -d "${LD_RUN_PATH}" ] && [ -w "${LD_RUN_PATH}" ]; then
    issue "\$LD_RUN_PATH $LD_RUN_PATH is writable!"
  fi

  while read -r line; do
    p="${line}"

    if [ -z "${p}" ]; then
      issue "Library search path contains empty path (working directory)"
      continue
    fi

    if [ -d "${p}" ] && [ -w "${p}" ]; then
      issue "${p} directory in library search path is writable!"
    fi

    analyze_libraries_in_directory "${p}"
  done <<< "${search_paths//:/$'\n'}"

  info "Checking executable paths..."
  echo

  while read -r line; do
    p="${line}"

    if [ -z "${p}" ]; then
      issue "\$PATH contains empty path (working directory)"
      continue
    fi

    if [ "${p}" = "." ]; then
      issue "\$PATH contains '.' (working directory)"
      continue
    fi

    if [ -w "${p}" ]; then
      issue "${p} directory in \$PATH is writable!"
      continue
    fi

    info "Searching executables in ${p} ..."
    echo

    analyze_executables_in_directory "${p}"
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
  IFS=' ' read -r -a array <<< "objdump ldd readelf"
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
  if [ -n "${rpath}" ]; then
    verbose "${path} - RPATH: ${rpath}"

    while read -r line; do
      if [[ "${line}" =~ "\$ORIGIN" ]]; then
        p="${line//\$ORIGIN/$(dirname "${path}")\/}"
      else
        p="${line}"
      fi

      if [ -z "${p}" ]; then
        issue "${path} RPATH contains empty path (working directory)"
        continue
      fi

      if [ "${p}" = "." ]; then
        issue "${path} RPATH contains '.' (working directory)"
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
  if [ -n "${runpath}" ]; then
    verbose "${path} - RUNPATH: ${runpath}"

    while read -r line; do
      if [[ "${line}" =~ "\$ORIGIN" ]]; then
        p="${line//\$ORIGIN/$(dirname "${path}")\/}"
      else
        p="${line}"
      fi

      if [ -z "${p}" ]; then
        issue "${path} RUNPATH contains empty path (working directory)"
        continue
      fi

      if [ "${p}" = "." ]; then
        issue "${path} RUNPATH contains '.' (working directory)"
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
  if [ -n "${notfound}" ]; then
    issue "${path} missing: ${notfound}"
  fi
}

function ldd_libasan() {
  path="${1}"

  libasan=$(ldd "${path}" 2>/dev/null | grep "libasan.so")
  if [ -n "${libasan}" ]; then
    if [ -u "${path}" ]; then
      issue "${path} is setuid and uses libasan.so !"
    else
      verbose "${path} uses libasan.so"
    fi
  fi
}

function readelf_interp() {
  path="${1}"

  interp=$(readelf -l "${path}" 2>/dev/null | grep "interpreter:" | cut -d':' -f2- | sed -e 's/\]$//g' | sed -e 's/^[[:space:]]*//')
  if [ -n "${interp}" ] && [ -w "${interp}" ]; then
    if [ -u "${path}" ]; then
      issue "${path} is setuid and interpreter ${interp} is writable!"
    else
      issue "${path} interpreter ${interp} is writable!"
    fi
  fi
}

function analyze_libraries_in_directory() {
  path="${1}"

  array=()
  while IFS=  read -r -d $'\0'; do
    array+=("$REPLY")
  done < <(find "${path}" -maxdepth 1 -print0 2>/dev/null)

  for ((i=0; i<${#array[@]}; i++)); do
    f="$(realpath "${array[$i]}")"

    verbose "${f}"

    if [ -w "${f}" ]; then
      issue "${f} in library search path is writable!"
    fi
  done
}

function analyze_executables_in_directory() {
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

    if command_exists readelf; then
      readelf_interp "${f}"
    fi
  done
}

if [[ "${BASH_SOURCE[0]}" = "$0" ]]; then
  __main__ "${__script_params[@]}"
  exit 0
fi
