#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_PREFIX="${PROJECT_PREFIX:-threat-demo}"
OPENSTACK_INCLUDE_OBJECT_STORAGE="${OPENSTACK_INCLUDE_OBJECT_STORAGE:-false}"
PUBLIC_CONTAINER="${PUBLIC_CONTAINER:-${PROJECT_PREFIX}-m1-public-container}"
WIDE_OPEN_SG="${WIDE_OPEN_SG:-${PROJECT_PREFIX}-m2-wide-open-sg}"
DEMO_PROJECT="${DEMO_PROJECT:-${PROJECT_PREFIX}-m3-overpriv-project}"
DEMO_USER="${DEMO_USER:-${PROJECT_PREFIX}-m3-overpriv-user}"
DEMO_ROLE="${DEMO_ROLE:-admin}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TF_DIR="${TF_DIR:-${SCRIPT_DIR}/../iac/openstack}"

log() {
  printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

die() {
  log "ERROR: $*"
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing command: $1"
}

is_enabled() {
  case "${1,,}" in
    true|1|yes|y|on) return 0 ;;
    *) return 1 ;;
  esac
}

ensure_auth() {
  openstack token issue -f value -c id >/dev/null 2>&1 || \
    die "OpenStack auth chưa sẵn sàng. Hãy chạy: source <openrc>"
}

run_terraform() {
  terraform -chdir="${TF_DIR}" "$@"
}

main() {
  require_cmd openstack
  require_cmd terraform
  ensure_auth

  if is_enabled "${OPENSTACK_INCLUDE_OBJECT_STORAGE}"; then
    log "M1 object storage is not modeled in iac/openstack; nothing to destroy for that scenario."
  fi

  run_terraform init -input=false
  run_terraform destroy -auto-approve \
    -var="project_prefix=${PROJECT_PREFIX}" \
    -var="demo_password=${DEMO_PASSWORD}" \
    -var="demo_role=${DEMO_ROLE}" \
    -var="include_object_storage=${OPENSTACK_INCLUDE_OBJECT_STORAGE}"

  log "OpenStack demo resources cleanup completed."
}

main "$@"
