#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_PREFIX="${PROJECT_PREFIX:-threat-demo}"
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

ensure_auth() {
  openstack token issue -f value -c id >/dev/null 2>&1 || \
    die "OpenStack auth chưa sẵn sàng. Hãy chạy: source <openrc>"
}

main() {
  require_cmd openstack
  ensure_auth

  mkdir -p "$OUT_DIR"

  openstack container show "$PUBLIC_CONTAINER" -f json > "${OUT_DIR}/container_public.json"
  openstack security group rule list "$WIDE_OPEN_SG" -f json > "${OUT_DIR}/security_group_rules.json"
  openstack role assignment list --project "$DEMO_PROJECT" --user "$DEMO_USER" --names -f json > "${OUT_DIR}/role_assignments.json"

  cat <<EOF

OpenStack evidence exported to:
  ${OUT_DIR}/container_public.json
  ${OUT_DIR}/security_group_rules.json
  ${OUT_DIR}/role_assignments.json

Next:
  python -m src.openstack.findings \
    --container-file ${OUT_DIR}/container_public.json \
    --sg-rules-file ${OUT_DIR}/security_group_rules.json \
    --role-assignments-file ${OUT_DIR}/role_assignments.json \
    --output ./scan_results/openstack_findings.json
EOF
}

main "$@"
