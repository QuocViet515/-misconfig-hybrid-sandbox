#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_PREFIX="${PROJECT_PREFIX:-threat-demo}"
OPENSTACK_INCLUDE_OBJECT_STORAGE="${OPENSTACK_INCLUDE_OBJECT_STORAGE:-true}"
PUBLIC_CONTAINER="${PUBLIC_CONTAINER:-${PROJECT_PREFIX}-m1-public-container}"
WIDE_OPEN_SG="${WIDE_OPEN_SG:-${PROJECT_PREFIX}-m2-wide-open-sg}"
DEMO_PROJECT="${DEMO_PROJECT:-${PROJECT_PREFIX}-m3-overpriv-project}"
DEMO_USER="${DEMO_USER:-${PROJECT_PREFIX}-m3-overpriv-user}"
OUT_DIR="${OUT_DIR:-reports/raw/openstack/live}"

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

main() {
  require_cmd openstack
  ensure_auth

  mkdir -p "$OUT_DIR"

  if is_enabled "$OPENSTACK_INCLUDE_OBJECT_STORAGE"; then
    openstack container show "$PUBLIC_CONTAINER" -f json > "${OUT_DIR}/container_public.json"
  else
    log "Skipping object storage export because OPENSTACK_INCLUDE_OBJECT_STORAGE=${OPENSTACK_INCLUDE_OBJECT_STORAGE}"
  fi
  openstack security group rule list "$WIDE_OPEN_SG" -f json > "${OUT_DIR}/security_group_rules.json"
  openstack role assignment list --project "$DEMO_PROJECT" --user "$DEMO_USER" --names -f json > "${OUT_DIR}/role_assignments.json"

  cat <<EOF

OpenStack evidence exported to:
  ${OUT_DIR}/security_group_rules.json
  ${OUT_DIR}/role_assignments.json
EOF

  if is_enabled "$OPENSTACK_INCLUDE_OBJECT_STORAGE"; then
    cat <<EOF
  ${OUT_DIR}/container_public.json
EOF
  fi

  cat <<EOF

Next:
  python -m src.openstack.findings \
    --sg-rules-file ${OUT_DIR}/security_group_rules.json \
    --role-assignments-file ${OUT_DIR}/role_assignments.json \
    --output ./scan_results/openstack_findings.json
EOF

  if is_enabled "$OPENSTACK_INCLUDE_OBJECT_STORAGE"; then
    cat <<EOF
  Optional M1 argument:
    --container-file ${OUT_DIR}/container_public.json
EOF
  fi
}

main "$@"
