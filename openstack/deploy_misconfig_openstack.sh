#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_PREFIX="${PROJECT_PREFIX:-threat-demo}"
PUBLIC_CONTAINER="${PUBLIC_CONTAINER:-${PROJECT_PREFIX}-m1-public-container}"
WIDE_OPEN_SG="${WIDE_OPEN_SG:-${PROJECT_PREFIX}-m2-wide-open-sg}"
DEMO_PROJECT="${DEMO_PROJECT:-${PROJECT_PREFIX}-m3-overpriv-project}"
DEMO_USER="${DEMO_USER:-${PROJECT_PREFIX}-m3-overpriv-user}"
DEMO_PASSWORD="${DEMO_PASSWORD:-ChangeMe123!}"
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

create_sg_rule_if_missing() {
  local rule_label="$1"
  shift

  local output
  if output="$(openstack security group rule create "$@" "$WIDE_OPEN_SG" 2>&1)"; then
    log "Created SG rule: ${rule_label}"
    return 0
  fi

  if grep -Eiq 'already exists|conflict|duplicate' <<<"$output"; then
    log "SG rule already exists: ${rule_label}"
    return 0
  fi

  die "Cannot create SG rule (${rule_label}): ${output}"
}

ensure_public_storage_misconfig() {
  if resource_exists container "$PUBLIC_CONTAINER"; then
    log "Container already exists: ${PUBLIC_CONTAINER}"
  else
    openstack container create "$PUBLIC_CONTAINER" >/dev/null
    log "Created container: ${PUBLIC_CONTAINER}"
  fi

  # MISCONFIGURATION M1: public read ACL cho Swift container
  openstack container set --read-acl ".r:*,.rlistings" "$PUBLIC_CONTAINER" >/dev/null
  log "Set public ACL on container: ${PUBLIC_CONTAINER}"

  local tmp_dir
  local object_file
  tmp_dir="$(mktemp -d)"
  object_file="${tmp_dir}/customer_records.csv"
  cat <<'CSV' >"${object_file}"
customer_id,name,email,ssn
1,Nguyen Van A,nva@example.com,123-45-6789
2,Tran Thi B,ttb@example.com,987-65-4321
CSV

  # Upload data demo để scanner có artifact kiểm tra.
  openstack object create "$PUBLIC_CONTAINER" "$object_file" >/dev/null
  rm -rf "$tmp_dir"
  log "Uploaded sample object to container: ${PUBLIC_CONTAINER}"
}

ensure_wide_open_sg_misconfig() {
  if resource_exists security_group "$WIDE_OPEN_SG"; then
    log "Security group already exists: ${WIDE_OPEN_SG}"
  else
    openstack security group create "$WIDE_OPEN_SG" \
      --description "INSECURE demo SG: ingress from 0.0.0.0/0" >/dev/null
    log "Created security group: ${WIDE_OPEN_SG}"
  fi

  # MISCONFIGURATION M2: ingress mở toàn Internet.
  create_sg_rule_if_missing "SSH 22/tcp from anywhere" \
    --ingress --ethertype IPv4 --protocol tcp --dst-port 22 --remote-ip 0.0.0.0/0

  create_sg_rule_if_missing "RDP 3389/tcp from anywhere" \
    --ingress --ethertype IPv4 --protocol tcp --dst-port 3389 --remote-ip 0.0.0.0/0

  create_sg_rule_if_missing "All traffic from anywhere" \
    --ingress --ethertype IPv4 --protocol any --remote-ip 0.0.0.0/0
}

ensure_overprivileged_identity_misconfig() {
  resource_exists role "$DEMO_ROLE" || die "Role not found: ${DEMO_ROLE}"

  if resource_exists project "$DEMO_PROJECT"; then
    log "Project already exists: ${DEMO_PROJECT}"
  else
    openstack project create "$DEMO_PROJECT" >/dev/null
    log "Created project: ${DEMO_PROJECT}"
  fi

  if resource_exists user "$DEMO_USER"; then
    log "User already exists: ${DEMO_USER}"
  else
    openstack user create --project "$DEMO_PROJECT" --password "$DEMO_PASSWORD" "$DEMO_USER" >/dev/null
    log "Created user: ${DEMO_USER}"
  fi

  # MISCONFIGURATION M3: gán role admin cho user demo.
  local output
  if output="$(openstack role add --project "$DEMO_PROJECT" --user "$DEMO_USER" "$DEMO_ROLE" 2>&1)"; then
    log "Assigned role ${DEMO_ROLE} to ${DEMO_USER} in ${DEMO_PROJECT}"
    return 0
  fi
  if grep -Eiq 'already has role|conflict|exists' <<<"$output"; then
    log "Role assignment already exists: ${DEMO_USER} -> ${DEMO_ROLE} on ${DEMO_PROJECT}"
    return 0
  fi
  die "Cannot assign role: ${output}"
}

print_next_checks() {
  cat <<EOF

Cloud B misconfiguration deployment completed.

Run verification:
  openstack container show ${PUBLIC_CONTAINER} -f yaml
  openstack security group rule list ${WIDE_OPEN_SG}
  openstack role assignment list --project ${DEMO_PROJECT} --user ${DEMO_USER} --names

Resource names:
  PUBLIC_CONTAINER=${PUBLIC_CONTAINER}
  WIDE_OPEN_SG=${WIDE_OPEN_SG}
  DEMO_PROJECT=${DEMO_PROJECT}
  DEMO_USER=${DEMO_USER}
EOF
}

main() {
  require_cmd openstack
  require_cmd grep
  ensure_auth

  ensure_public_storage_misconfig
  ensure_wide_open_sg_misconfig
  ensure_overprivileged_identity_misconfig

  print_next_checks
}

main "$@"
