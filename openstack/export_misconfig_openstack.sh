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

export_object_storage() {
  local output_file="${OUT_DIR}/container_public.json"
  if ! openstack container show "$PUBLIC_CONTAINER" -f json > "$output_file"; then
    log "Object storage export skipped because container ${PUBLIC_CONTAINER} could not be queried"
    rm -f "$output_file"
  fi
}

export_security_group_rules() {
  local catalog_file
  local merge_script
  local rules_dir
  local output_file="${OUT_DIR}/security_group_rules.json"

  catalog_file="$(mktemp)"
  merge_script="$(mktemp)"
  rules_dir="$(mktemp -d)"

  openstack security group list -f json > "$catalog_file"
  python3 > "$merge_script" - "$catalog_file" "$WIDE_OPEN_SG" <<'PY'
import json
import sys

catalog_path, wanted_name = sys.argv[1:]
groups = json.load(open(catalog_path, "r", encoding="utf-8"))
for group in groups:
    if not isinstance(group, dict):
        continue
    if str(group.get("Name", "")) != wanted_name:
        continue
    print(f"{group.get('ID','')}\t{group.get('Name','')}")
PY

  mapfile -t matching_groups < "$merge_script"
  if ((${#matching_groups[@]} == 0)); then
    log "No security groups found with name ${WIDE_OPEN_SG}; writing empty evidence set"
    printf '[]\n' > "$output_file"
    rm -f "$catalog_file" "$merge_script"
    rm -rf "$rules_dir"
    return 0
  fi

  for group_entry in "${matching_groups[@]}"; do
    local sg_id="${group_entry%%$'\t'*}"
    local sg_name="${group_entry#*$'\t'}"
    [[ -n "$sg_id" ]] || continue
    openstack security group rule list "$sg_id" -f json > "${rules_dir}/${sg_id}.json"
    printf '%s\t%s\n' "$sg_id" "$sg_name" >> "${rules_dir}/groups.tsv"
  done

  python3 - "$rules_dir" "$output_file" <<'PY'
import json
import os
import sys
from pathlib import Path

rules_dir = Path(sys.argv[1])
output_path = Path(sys.argv[2])
group_map = {}
for line in (rules_dir / "groups.tsv").read_text(encoding="utf-8").splitlines():
    if not line.strip():
        continue
    sg_id, sg_name = line.split("\t", 1)
    group_map[sg_id] = sg_name

merged = []
seen_rule_ids = set()
for sg_id, sg_name in group_map.items():
    payload = json.load(open(rules_dir / f"{sg_id}.json", "r", encoding="utf-8"))
    for rule in payload:
        if not isinstance(rule, dict):
            continue
        enriched = dict(rule)
        enriched["Security Group ID"] = sg_id
        enriched["Security Group"] = sg_name
        rule_id = str(enriched.get("ID", ""))
        if rule_id and rule_id in seen_rule_ids:
            continue
        if rule_id:
            seen_rule_ids.add(rule_id)
        merged.append(enriched)

output_path.write_text(json.dumps(merged, indent=2) + "\n", encoding="utf-8")
PY

  log "Exported $((${#matching_groups[@]})) matching security group(s) for ${WIDE_OPEN_SG}"
  rm -f "$catalog_file" "$merge_script"
  rm -rf "$rules_dir"
}

export_role_assignments() {
  local output_file="${OUT_DIR}/role_assignments.json"
  if ! openstack role assignment list --project "$DEMO_PROJECT" --user "$DEMO_USER" --names -f json > "$output_file"; then
    log "Role assignment export skipped because ${DEMO_PROJECT}/${DEMO_USER} could not be queried"
    printf '[]\n' > "$output_file"
  fi
}

main() {
  require_cmd openstack
  require_cmd python3
  ensure_auth

  mkdir -p "$OUT_DIR"

  if is_enabled "$OPENSTACK_INCLUDE_OBJECT_STORAGE"; then
    export_object_storage
  else
    log "Skipping object storage export because OPENSTACK_INCLUDE_OBJECT_STORAGE=${OPENSTACK_INCLUDE_OBJECT_STORAGE}"
  fi
  export_security_group_rules
  export_role_assignments

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
