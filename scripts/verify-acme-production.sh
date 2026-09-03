#!/usr/bin/env bash
# Verify a c8s ACME TLS-LB without changing the user's TEErminator config.
#
# Required environment:
#   TEERMINATOR_ACME_URL          ACME front-door URL (usually an LB IP)
#   TEERMINATOR_ACME_SERVER_NAME  hostname in the ACME certificate
#   TEERMINATOR_ACME_IMAGE_MANIFEST full TDX MRTD, RTMR1, and RTMR2 manifest
#   TEERMINATOR_ACME_ALLOWLIST    reviewed canonical allowlist JSON
#   TEERMINATOR_ACME_WORKLOAD     workload name stamped into the mesh leaf
#   TEERMINATOR_PROMPT_BODY       JSON body accepted by the production API
#
# Optional environment:
#   TEERMINATOR_TOKEN_FILE        bearer token file
#   TEERMINATOR_PROMPT_PATH       local path (default /v1/chat/completions)
#   TEERMINATOR_PROMPT_TIMEOUT    curl timeout in seconds (default 20)
#   TEERMINATOR_BASE_PORT         first local test port (default 18080)
#   TEERMINATOR_BIN               existing teerminator binary; otherwise go build
#
# The script creates one isolated XDG_CONFIG_HOME per case and removes all of
# them on exit. It never writes the user's normal TEErminator configuration.
# A blocked case proves the local proxy returned no successful application
# response. The proxy's request-boundary test separately proves that a failed
# attestation does not read or forward the prompt body.

set -Eeuo pipefail

die() {
  echo "verify-acme-production: $*" >&2
  exit 2
}

usage() {
  cat >&2 <<'EOF'
Usage: verify-acme-production.sh

Set the required TEERMINATOR_ACME_* and TEERMINATOR_PROMPT_BODY environment
variables first. This command performs five isolated checks against the
current ACME front door: one expected-success case and four fail-closed cases
(wrong allowlist bytes, certificate name, full TDX image, and workload).
EOF
}

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
  usage
  exit 0
fi
[[ $# -eq 0 ]] || die "unknown argument $1 (use --help)"

required_vars=(
  TEERMINATOR_ACME_URL
  TEERMINATOR_ACME_SERVER_NAME
  TEERMINATOR_ACME_IMAGE_MANIFEST
  TEERMINATOR_ACME_ALLOWLIST
  TEERMINATOR_ACME_WORKLOAD
  TEERMINATOR_PROMPT_BODY
)
for var in "${required_vars[@]}"; do
  [[ -n ${!var:-} ]] || die "$var is required"
done

[[ -f "$TEERMINATOR_ACME_ALLOWLIST" ]] || die "allowlist is not a file: $TEERMINATOR_ACME_ALLOWLIST"
[[ -f "$TEERMINATOR_ACME_IMAGE_MANIFEST" ]] || die "image manifest is not a file: $TEERMINATOR_ACME_IMAGE_MANIFEST"
if [[ -n ${TEERMINATOR_TOKEN_FILE:-} ]]; then
  [[ -f "$TEERMINATOR_TOKEN_FILE" ]] || die "token file is not a file: $TEERMINATOR_TOKEN_FILE"
fi

prompt_path=${TEERMINATOR_PROMPT_PATH:-/v1/chat/completions}
[[ $prompt_path == /* ]] || die "TEERMINATOR_PROMPT_PATH must start with /"
prompt_timeout=${TEERMINATOR_PROMPT_TIMEOUT:-20}
base_port=${TEERMINATOR_BASE_PORT:-18080}
[[ $prompt_timeout =~ ^[1-9][0-9]*$ ]] || die "TEERMINATOR_PROMPT_TIMEOUT must be a positive integer"
[[ $base_port =~ ^[1-9][0-9]*$ ]] || die "TEERMINATOR_BASE_PORT must be a positive integer"

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v mktemp >/dev/null 2>&1 || die "mktemp is required"

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_dir=$(cd -- "$script_dir/.." && pwd)
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/teerminator-acme-verify.XXXXXX")
cleanup() {
  if [[ -n ${active_pid:-} ]]; then
    kill "$active_pid" 2>/dev/null || true
    wait "$active_pid" 2>/dev/null || true
  fi
  rm -rf -- "$tmp_dir"
}
trap cleanup EXIT

if [[ -n ${TEERMINATOR_BIN:-} ]]; then
  bin=$TEERMINATOR_BIN
  [[ -x $bin ]] || die "TEERMINATOR_BIN is not executable: $bin"
else
  command -v go >/dev/null 2>&1 || die "go is required when TEERMINATOR_BIN is unset"
  bin="$tmp_dir/teerminator"
  (cd -- "$repo_dir" && go build -o "$bin" .)
fi

run_cli() {
  local config_home=$1
  shift
  XDG_CONFIG_HOME="$config_home" "$bin" "$@"
}

wait_for_listener() {
  local log=$1
  local pid=$2
  for _ in {1..50}; do
    if grep -Fq "Listening on" "$log"; then
      return 0
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
      echo "--- TEErminator start log ---" >&2
      sed -n '1,120p' "$log" >&2 || true
      return 1
    fi
    sleep 0.2
  done
  echo "--- TEErminator start log ---" >&2
  sed -n '1,120p' "$log" >&2 || true
  return 1
}

run_case() {
  local name=$1
  local expected=$2
  local server_name=$3
  local image_manifest=$4
  local workload=$5
  local allowlist=$6

  local case_dir="$tmp_dir/$name"
  local config_home="$case_dir/config"
  local local_addr="127.0.0.1:$((base_port + case_number))"
  local status_file="$case_dir/status.txt"
  local start_log="$case_dir/start.log"
  local response_file="$case_dir/response.txt"
  local remote_args=(
    remote add "$local_addr" "$TEERMINATOR_ACME_URL"
    --mode attest-lb
    --server-name "$server_name"
    --image-manifest "$image_manifest"
  )
  if [[ -n $workload ]]; then
    remote_args+=(--workload "$workload")
  fi
  if [[ -n $allowlist ]]; then
    remote_args+=(--allowlist "$allowlist")
  fi
  mkdir -p -- "$case_dir"

  run_cli "$config_home" "${remote_args[@]}"
  if [[ -n ${TEERMINATOR_TOKEN_FILE:-} ]]; then
    run_cli "$config_home" remote auth "$local_addr" "$TEERMINATOR_TOKEN_FILE"
  fi

  run_cli "$config_home" status --timeout 30 | tee "$status_file"
  if [[ $expected == pass ]]; then
    grep -F "$local_addr" "$status_file" | grep -Fq "Verified" || die "$name: expected Verified status"
  else
    grep -F "$local_addr" "$status_file" | grep -Fq "Failed" || die "$name: expected Failed status"
  fi

  active_pid=""
  XDG_CONFIG_HOME="$config_home" "$bin" start >"$start_log" 2>&1 &
  active_pid=$!
  wait_for_listener "$start_log" "$active_pid" || die "$name: proxy did not start"

  local http_code
  http_code=$(curl --silent --show-error --max-time "$prompt_timeout" \
    --header 'Content-Type: application/json' \
    --data-binary "$TEERMINATOR_PROMPT_BODY" \
    --output "$response_file" --write-out '%{http_code}' \
    "http://$local_addr$prompt_path" || true)

  kill "$active_pid" 2>/dev/null || true
  wait "$active_pid" 2>/dev/null || true
  active_pid=""

  if [[ $expected == pass ]]; then
    [[ $http_code =~ ^2[0-9][0-9]$ ]] || die "$name: expected a 2xx prompt response, got HTTP $http_code"
    echo "PASS $name: Verified attestation and prompt forwarding returned HTTP $http_code"
  else
    [[ ! $http_code =~ ^2[0-9][0-9]$ ]] || die "$name: prompt unexpectedly returned HTTP $http_code"
    echo "PASS $name: status Failed and prompt was blocked (HTTP $http_code)"
  fi
}

wrong_server_name=${TEERMINATOR_WRONG_SERVER_NAME:-wrong.invalid}
wrong_workload=${TEERMINATOR_WRONG_WORKLOAD:-wrong-workload}

case_number=0
run_case correct pass "$TEERMINATOR_ACME_SERVER_NAME" "$TEERMINATOR_ACME_IMAGE_MANIFEST" \
  "$TEERMINATOR_ACME_WORKLOAD" "$TEERMINATOR_ACME_ALLOWLIST"

case_number=1
wrong_allowlist="$tmp_dir/wrong-allowlist.json"
cp -- "$TEERMINATOR_ACME_ALLOWLIST" "$wrong_allowlist"
printf '\n' >>"$wrong_allowlist"
run_case wrong-policy block "$TEERMINATOR_ACME_SERVER_NAME" "$TEERMINATOR_ACME_IMAGE_MANIFEST" \
  "$TEERMINATOR_ACME_WORKLOAD" "$wrong_allowlist"

case_number=2
run_case wrong-certificate block "$wrong_server_name" "$TEERMINATOR_ACME_IMAGE_MANIFEST" \
  "$TEERMINATOR_ACME_WORKLOAD" ""

case_number=3
wrong_image_manifest="$tmp_dir/wrong-image-manifest.json"
python3 - "$TEERMINATOR_ACME_IMAGE_MANIFEST" "$wrong_image_manifest" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
target = value.get("tdx", value)
target["rtmr2"] = ("0" if target["rtmr2"][0] != "0" else "1") + target["rtmr2"][1:]
with open(sys.argv[2], "w", encoding="utf-8") as output:
    json.dump(value, output, separators=(",", ":"))
PY
run_case wrong-image block "$TEERMINATOR_ACME_SERVER_NAME" "$wrong_image_manifest" \
  "$TEERMINATOR_ACME_WORKLOAD" ""

case_number=4
run_case wrong-workload block "$TEERMINATOR_ACME_SERVER_NAME" "$TEERMINATOR_ACME_IMAGE_MANIFEST" \
  "$wrong_workload" ""

echo "All ACME front-door verification checks passed."
