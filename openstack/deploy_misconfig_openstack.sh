#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_PREFIX="${PROJECT_PREFIX:-threat-demo}"
OPENSTACK_INCLUDE_OBJECT_STORAGE="${OPENSTACK_INCLUDE_OBJECT_STORAGE:-false}"
PUBLIC_CONTAINER="${PUBLIC_CONTAINER:-${PROJECT_PREFIX}-m1-public-container}"
WIDE_OPEN_SG="${WIDE_OPEN_SG:-${PROJECT_PREFIX}-m2-wide-open-sg}"
DEMO_PROJECT="${DEMO_PROJECT:-${PROJECT_PREFIX}-m3-overpriv-project}"
DEMO_USER="${DEMO_USER:-${PROJECT_PREFIX}-m3-overpriv-user}"
DEMO_PASSWORD="${DEMO_PASSWORD:-ChangeMe123!}"
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

print_next_checks() {
  cat <<EOF

Cloud B misconfiguration deployment completed.

Run verification:
  openstack security group rule list ${WIDE_OPEN_SG}
  openstack role assignment list --project ${DEMO_PROJECT} --user ${DEMO_USER} --names

Resource names:
  WIDE_OPEN_SG=${WIDE_OPEN_SG}
  DEMO_PROJECT=${DEMO_PROJECT}
  DEMO_USER=${DEMO_USER}
EOF

  if is_enabled "$OPENSTACK_INCLUDE_OBJECT_STORAGE"; then
    cat <<EOF
  M1 object storage remains optional and is not provisioned by iac/openstack.
  PUBLIC_CONTAINER=${PUBLIC_CONTAINER} (not created by this Terraform stack)
EOF
  fi
}

main() {
  require_cmd openstack
  require_cmd terraform
  ensure_auth

  if is_enabled "$OPENSTACK_INCLUDE_OBJECT_STORAGE"; then
    log "M1 object storage is not modeled in iac/openstack and will be skipped."
  else
    log "Skipping M1 public object storage because OPENSTACK_INCLUDE_OBJECT_STORAGE=${OPENSTACK_INCLUDE_OBJECT_STORAGE}"
  fi
  run_terraform init -input=false
  run_terraform apply -auto-approve \
    -var="project_prefix=${PROJECT_PREFIX}" \
    -var="demo_password=${DEMO_PASSWORD}" \
    -var="demo_role=${DEMO_ROLE}" \
    -var="include_object_storage=${OPENSTACK_INCLUDE_OBJECT_STORAGE}"

  print_next_checks
}

main "$@"
