#!/usr/bin/env bash
set -Eeuo pipefail

ACTION="${1:-}"
STACK_DIR="${2:-}"
STATE_ROOT="${3:-$HOME/.misconfig-hybrid-sandbox/tfstate}"
STACK_NAME="${4:-}"
STATE_NAMESPACE="${5:-default}"

die() {
  echo "ERROR: $*" >&2
  exit 1
}

[[ -n "${ACTION}" ]] || die "Usage: $0 <restore|save|clear> <stack_dir> [state_root] [stack_name] [state_namespace]"
[[ -n "${STACK_DIR}" ]] || die "Stack directory is required"

STACK_DIR="$(cd "${STACK_DIR}" && pwd)"
STACK_NAME="${STACK_NAME:-$(basename "${STACK_DIR}")}"
SAFE_NAMESPACE="$(echo "${STATE_NAMESPACE}" | tr '/[:space:]' '__')"
PERSIST_DIR="${STATE_ROOT}/${SAFE_NAMESPACE}/${STACK_NAME}"

mkdir -p "${PERSIST_DIR}"

copy_if_exists() {
  local source="$1"
  local target="$2"
  if [[ -f "${source}" ]]; then
    mkdir -p "$(dirname "${target}")"
    cp "${source}" "${target}"
  fi
}

case "${ACTION}" in
  restore)
    copy_if_exists "${PERSIST_DIR}/terraform.tfstate" "${STACK_DIR}/terraform.tfstate"
    copy_if_exists "${PERSIST_DIR}/terraform.tfstate.backup" "${STACK_DIR}/terraform.tfstate.backup"
    ;;
  save)
    copy_if_exists "${STACK_DIR}/terraform.tfstate" "${PERSIST_DIR}/terraform.tfstate"
    copy_if_exists "${STACK_DIR}/terraform.tfstate.backup" "${PERSIST_DIR}/terraform.tfstate.backup"
    ;;
  clear)
    rm -f "${PERSIST_DIR}/terraform.tfstate" "${PERSIST_DIR}/terraform.tfstate.backup"
    ;;
  *)
    die "Unknown action: ${ACTION}"
    ;;
esac
