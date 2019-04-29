#!/bin/bash
# so-check v0.0.1
# Checks system shared objects and executables in $PATH
# for privilege escalation vectors
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

echo -e "--[ \\033[1;32mso-check v0.0.1\\033[0m ]--"
echo

if [ "$(id -u)" -eq 0 ]; then
  echo
  echo "Running this tool as root does not make sense."
  echo
  id
  exit 1
fi

info() { echo -e "\\033[1;36m[*]\\033[0m  $*"; }
warn() { echo -e "\\033[1;33m[WARNING]\\033[0m  $*"; }
error() { echo -e "\\033[1;31m[ERROR]\\033[0m  $*"; exit 1 ; }
issue() { echo -e "\\033[1;33m[!]\\033[0m  $*"; }
verbose() { [ "${VERBOSE}" = "true" ] && echo "$*"; }

command_exists () {
  command -v "${1}" >/dev/null 2>&1
}

if ! command_exists objdump; then
  warn "objdump is not in \$PATH! Some checks will be skipped ..."
fi

if ! command_exists ldd; then
  warn "ldd is not in \$PATH! Some checks will be skipped ..."
fi

#if ! command_exists readelf; then
#  warn "readelf is not in \$PATH! Some checks will be skipped ..."
#fi

if ! command_exists grep; then
  error "grep is not in \$PATH!"
fi

if ! command_exists sed; then
  error "sed is not in \$PATH!"
fi

if ! command_exists cut; then
  error "cut is not in \$PATH!"
fi

if ! command_exists head; then
  error "head is not in \$PATH!"
fi

if ! command_exists dirname; then
  error "dirname is not in \$PATH!"
fi

if ! command_exists realpath; then
  error "realpath is not in \$PATH!"
fi

objdump_rpath() {
  path="${1}"

  rpath=$(objdump -x "${path}" 2>/dev/null | grep RPATH | sed 's/RPATH\s*//g' | sed -e 's/^[[:space:]]*//')
  if [ ! -z "${rpath}" ]; then
    verbose "${path} - RPATH: ${rpath}"

    while read -r line; do
      if [[ "${line}" =~ "\$ORIGIN" ]]; then
        p="$(dirname "${path}")/$(echo "${line}" | sed -e 's/\$ORIGIN//g')"
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

objdump_runpath() {
  path="${1}"

  runpath=$(objdump -x "${path}" 2>/dev/null | grep RUNPATH | sed 's/RUNPATH\s*//g' | sed -e 's/^[[:space:]]*//')
  if [ ! -z "${runpath}" ]; then
    verbose "${path} - RUNPATH: ${runpath}"

    while read -r line; do
      if [[ "${line}" =~ "\$ORIGIN" ]]; then
        p="$(dirname "${path}")/$(echo "${line}" | sed -e 's/\$ORIGIN//g')"
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

ldd_notfound() {
  path="${1}"

  notfound=$(ldd "${path}" 2>/dev/null | grep "not found")
  if [ ! -z "${notfound}" ]; then
    issue "${path} missing: ${notfound}"
  fi
}

ldd_libasan() {
  path="${1}"

  libasan=$(ldd "${path}" 2>/dev/null | grep "libasan.so")
  if [ ! -z "${libasan}" ]; then
    verbose "${path} uses libasan.so"
    if [ -u "${f}" ]; then
      issue "${path} is setuid and uses libasan.so !"
    fi
  fi
}

readelf_interp() {
  path="${1}"

  interp=$(readelf -l "${path}" 2>/dev/null | grep "interpreter:" | cut -d':' -f2- | sed -e 's/\]$//g' | sed -e 's/^[[:space:]]*//')
  if [ ! -z "${interp}" ] && [ -w "${interp}" ]; then
    issue "${path} interpreter ${interp} is writable!"
  fi
}

search_path() {
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
      objdump_rpath $f
      objdump_runpath $f
    fi

    if command_exists ldd; then
      ldd_notfound $f
      ldd_libasan $f
    fi

    #if command_exists readelf; then
    #  readelf_interp $f
    #fi
  done <<< "${search_paths//:/$'\n'}"
}

info "Environment info:"
echo

echo "PATH=${PATH}"
echo "LD_LIBRARY_PATH=${LD_LIBRARY_PATH}"
echo "LD_RUN_PATH=${LD_RUN_PATH}"

junk=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
search_paths=$(LD_PRELOAD="${junk}" LD_DEBUG=libs env 2>/dev/stdout | grep "search path=" | cut -d= -f2- | sed -e 's/\t/\n/g' | head -n 1)
echo "Library search paths: ${search_paths}"
echo

info "Checking library paths..."
echo

if [ ! -z $LD_LIBRARY_PATH ] && [ -d $LD_LIBRARY_PATH ] && [ -w $LD_LIBRARY_PATH ]; then
  issue "LD_LIBRARY_PATH $LD_LIBRARY_PATH is writable!"
fi

if [ ! -z $LD_RUN_PATH ] && [ -d $LD_RUN_PATH ] && [ -w $LD_RUN_PATH ]; then
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

  search_path $p
  echo
done <<< "${PATH//:/$'\n'}"
