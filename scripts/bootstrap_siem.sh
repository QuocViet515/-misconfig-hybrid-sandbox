#!/usr/bin/env bash
# Trigger-only comment to exercise the delivery workflow after state reseeding.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-${REPO_ROOT}/docker-compose.siem.yml}"
KIBANA_URL="${KIBANA_URL:-http://localhost:5601}"
ELASTICSEARCH_URL="${ELASTICSEARCH_URL:-http://localhost:9200}"

DASHBOARD_ONE_TITLE="Hybrid Misconfiguration Detection Overview"
DASHBOARD_TWO_TITLE="Triage and Remediation Readiness"
DASHBOARD_THREE_TITLE="Compliance Evidence and Investigation Queue"
DASHBOARD_FOUR_TITLE="Runtime Remediation Outcomes"

require_command() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Missing required command: $cmd" >&2
    exit 1
  fi
}

wait_for_url() {
  local name="$1"
  local url="$2"
  local attempts="${3:-120}"
  local delay="${4:-2}"
  local try=1

  until curl -fsS "$url" >/dev/null 2>&1; do
    if (( try >= attempts )); then
      echo "$name did not become ready at $url" >&2
      exit 1
    fi
    sleep "$delay"
    try=$((try + 1))
  done
}

ensure_data_view() {
  local title="$1"
  local name="$2"
  local existing

  existing="$(curl -fsS -H 'kbn-xsrf: true' "${KIBANA_URL}/api/saved_objects/_find?type=index-pattern&per_page=100")"
  if printf '%s' "${existing}" | grep -F "\"title\":\"${title}\"" >/dev/null 2>&1; then
    return 0
  fi

  curl -fsS \
    -X POST \
    -H 'kbn-xsrf: true' \
    -H 'Content-Type: application/json' \
    "${KIBANA_URL}/api/data_views/data_view" \
    -d "{\"data_view\":{\"title\":\"${title}\",\"timeFieldName\":\"@timestamp\",\"name\":\"${name}\"}}" \
    >/dev/null
}

provision_dashboards() {
  KIBANA_URL="${KIBANA_URL}" python3 "${REPO_ROOT}/scripts/provision_dashboard_1.py"
  KIBANA_URL="${KIBANA_URL}" python3 "${REPO_ROOT}/scripts/provision_dashboard_2.py"
  KIBANA_URL="${KIBANA_URL}" python3 "${REPO_ROOT}/scripts/provision_dashboard_3.py"
  KIBANA_URL="${KIBANA_URL}" python3 "${REPO_ROOT}/scripts/provision_dashboard_4.py"
}

find_dashboard_id() {
  local dashboard_title="$1"
  local payload
  payload="$(curl -fsS -H 'kbn-xsrf: true' "${KIBANA_URL}/api/saved_objects/_find?type=dashboard&search_fields=title&search=${dashboard_title// /%20}&per_page=100")"
  printf '%s' "${payload}" | python3 -c '
import json, sys
target = sys.argv[1]
data = json.load(sys.stdin)
for item in data.get("saved_objects", []):
    if item.get("attributes", {}).get("title") == target:
        print(item.get("id", ""))
        raise SystemExit(0)
raise SystemExit(1)
' "${dashboard_title}"
}

verify_dashboard() {
  local dashboard_title="$1"
  local dashboard_id
  dashboard_id="$(find_dashboard_id "${dashboard_title}")"
  curl -fsS -H 'kbn-xsrf: true' "${KIBANA_URL}/api/saved_objects/dashboard/${dashboard_id}" >/dev/null
  printf '%s' "${dashboard_id}"
}

container_running() {
  local name="$1"
  docker ps --format '{{.Names}}' | grep -Fx "$name" >/dev/null 2>&1
}

container_exists() {
  local name="$1"
  docker ps -a --format '{{.Names}}' | grep -Fx "$name" >/dev/null 2>&1
}

main() {
  require_command docker
  require_command curl
  require_command grep
  require_command python3

  if [[ ! -f "${COMPOSE_FILE}" ]]; then
    echo "Compose file not found: ${COMPOSE_FILE}" >&2
    exit 1
  fi

  if container_running "misconfig-elasticsearch" && container_running "misconfig-kibana"; then
    echo "Reusing existing misconfig Elasticsearch/Kibana containers."
  elif container_exists "misconfig-elasticsearch" && container_exists "misconfig-kibana"; then
    echo "Starting existing misconfig Elasticsearch/Kibana containers."
    docker start misconfig-elasticsearch misconfig-kibana >/dev/null
  else
    docker compose -f "${COMPOSE_FILE}" up -d
  fi

  wait_for_url "Elasticsearch" "${ELASTICSEARCH_URL}"
  wait_for_url "Kibana" "${KIBANA_URL}/api/status"

  ensure_data_view "misconfig-findings-*" "misconfig-findings-live"
  ensure_data_view "misconfig-triage-*" "misconfig-triage"
  ensure_data_view "misconfig-remediation-*" "misconfig-remediation"
  ensure_data_view "misconfig-metrics-*" "misconfig-metrics"
  provision_dashboards

  DASHBOARD_ONE_ID="$(verify_dashboard "${DASHBOARD_ONE_TITLE}")"
  DASHBOARD_TWO_ID="$(verify_dashboard "${DASHBOARD_TWO_TITLE}")"
  DASHBOARD_THREE_ID="$(verify_dashboard "${DASHBOARD_THREE_TITLE}")"
  DASHBOARD_FOUR_ID="$(verify_dashboard "${DASHBOARD_FOUR_TITLE}")"

  cat <<EOF
SIEM bootstrap completed.
Elasticsearch: ${ELASTICSEARCH_URL}
Kibana: ${KIBANA_URL}
Dashboards:
- ${KIBANA_URL}/app/dashboards#/view/${DASHBOARD_ONE_ID}
- ${KIBANA_URL}/app/dashboards#/view/${DASHBOARD_TWO_ID}
- ${KIBANA_URL}/app/dashboards#/view/${DASHBOARD_THREE_ID}
- ${KIBANA_URL}/app/dashboards#/view/${DASHBOARD_FOUR_ID}
EOF
}

main "$@"
