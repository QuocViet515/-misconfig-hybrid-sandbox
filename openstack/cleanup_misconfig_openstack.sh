#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_PREFIX="${PROJECT_PREFIX:-threat-demo}"
PUBLIC_CONTAINER="${PUBLIC_CONTAINER:-${PROJECT_PREFIX}-m1-public-container}"
WIDE_OPEN_SG="${WIDE_OPEN_SG:-${PROJECT_PREFIX}-m2-wide-open-sg}"
DEMO_PROJECT="${DEMO_PROJECT:-${PROJECT_PREFIX}-m3-overpriv-project}"
DEMO_USER="${DEMO_USER:-${PROJECT_PREFIX}-m3-overpriv-user}"
DEMO_ROLE="${DEMO_ROLE:-admin}"

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

resource_exists() {
  local kind="$1"
  local name="$2"

  case "$kind" in
    container) openstack container show "$name" >/dev/null 2>&1 ;;
    security_group) openstack security group show "$name" >/dev/null 2>&1 ;;
    project) openstack project show "$name" >/dev/null 2>&1 ;;
    user) openstack user show "$name" >/dev/null 2>&1 ;;
    role) openstack role show "$name" >/dev/null 2>&1 ;;
    *) die "Unknown resource kind: $kind" ;;
  esac
}

cleanup_public_container() {
  if ! resource_exists container "$PUBLIC_CONTAINER"; then
    log "Container not found, skip: ${PUBLIC_CONTAINER}"
    return 0
  fi

  openstack container set --read-acl "" --write-acl "" "$PUBLIC_CONTAINER" >/dev/null || true

  mapfile -t objects < <(openstack object list "$PUBLIC_CONTAINER" -f value -c Name 2>/dev/null || true)
  for object_name in "${objects[@]}"; do
    [[ -z "$object_name" ]] && continue
    openstack object delete "$PUBLIC_CONTAINER" "$object_name" >/dev/null || true
    log "Deleted object: ${PUBLIC_CONTAINER}/${object_name}"
  done

  openstack container delete "$PUBLIC_CONTAINER" >/dev/null
  log "Deleted container: ${PUBLIC_CONTAINER}"
}

cleanup_wide_open_sg() {
  if ! resource_exists security_group "$WIDE_OPEN_SG"; then
    log "Security group not found, skip: ${WIDE_OPEN_SG}"
    return 0
  fi

  openstack security group delete "$WIDE_OPEN_SG" >/dev/null
  log "Deleted security group: ${WIDE_OPEN_SG}"
}

cleanup_overprivileged_identity() {
  if resource_exists role "$DEMO_ROLE" && resource_exists project "$DEMO_PROJECT" && resource_exists user "$DEMO_USER"; then
    openstack role remove --project "$DEMO_PROJECT" --user "$DEMO_USER" "$DEMO_ROLE" >/dev/null || true
    log "Removed role assignment: ${DEMO_USER} -(${DEMO_ROLE})-> ${DEMO_PROJECT}"
  fi

  if resource_exists user "$DEMO_USER"; then
    openstack user delete "$DEMO_USER" >/dev/null
    log "Deleted user: ${DEMO_USER}"
  else
    log "User not found, skip: ${DEMO_USER}"
  fi

  if resource_exists project "$DEMO_PROJECT"; then
    openstack project delete "$DEMO_PROJECT" >/dev/null
    log "Deleted project: ${DEMO_PROJECT}"
  else
    log "Project not found, skip: ${DEMO_PROJECT}"
  fi
}

main() {
  require_cmd openstack
  ensure_auth

  cleanup_public_container
  cleanup_wide_open_sg
  cleanup_overprivileged_identity

  log "OpenStack demo resources cleanup completed."
}

main "$@"
