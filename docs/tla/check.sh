#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TLA_URL="${TLA2TOOLS_URL:-https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar}"
TLA_SHA256="${TLA2TOOLS_SHA256:-936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88}"
DEFAULT_DOWNLOAD_PATH="/tmp/tla2tools.jar"

AUTO_DOWNLOAD=0
SPECS=()

usage() {
  cat <<'EOF'
Usage: ./docs/tla/check.sh [--download] [SpecName ...]

Runs TLC model checking on the TLA+ specifications in docs/tla/.

Options:
  --download   Automatically download tla2tools.jar to /tmp/tla2tools.jar if not found locally.
  -h, --help   Show this help message.

Environment:
  TLA2TOOLS_JAR   Explicit path to tla2tools.jar.
  TLA2TOOLS_URL   Override download URL for --download.

Examples:
  ./docs/tla/check.sh --download
  TLA2TOOLS_JAR=/opt/tla/tla2tools.jar ./docs/tla/check.sh
  ./docs/tla/check.sh SessionLockAndIdle
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --download)
      AUTO_DOWNLOAD=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      SPECS+=("$1")
      shift
      ;;
  esac
done

if [[ ${#SPECS[@]} -eq 0 ]]; then
  SPECS=(
    "SessionLockAndIdle"
    "VideoDpbAndPause"
    "ConfigAndPresets"
  )
fi

if ! command -v java >/dev/null 2>&1; then
  echo "ERROR: 'java' not found in PATH. Install OpenJDK 17+ to run TLC." >&2
  exit 1
fi

find_jar() {
  local candidates=(
    "${TLA2TOOLS_JAR:-}"
    "$DEFAULT_DOWNLOAD_PATH"
    "$HOME/.local/share/tla/tla2tools.jar"
    "/opt/tla/tla2tools.jar"
    "/usr/share/java/tla2tools.jar"
  )
  for c in "${candidates[@]}"; do
    if [[ -n "$c" && -f "$c" ]]; then
      echo "$c"
      return 0
    fi
  done
  return 1
}

JAR=""
if ! JAR="$(find_jar)"; then
  if [[ "$AUTO_DOWNLOAD" -eq 1 ]]; then
    echo "==> Downloading tla2tools.jar to $DEFAULT_DOWNLOAD_PATH ..."
    if command -v curl >/dev/null 2>&1; then
      curl -fSL "$TLA_URL" -o "${DEFAULT_DOWNLOAD_PATH}.part"
    elif command -v wget >/dev/null 2>&1; then
      wget -qO "${DEFAULT_DOWNLOAD_PATH}.part" "$TLA_URL"
    else
      echo "ERROR: neither curl nor wget is available to download tla2tools.jar." >&2
      exit 1
    fi
    if [[ -n "$TLA_SHA256" && -z "${TLA2TOOLS_URL:-}" ]]; then
      if command -v sha256sum >/dev/null 2>&1; then
        echo "${TLA_SHA256}  ${DEFAULT_DOWNLOAD_PATH}.part" | sha256sum -c -
      elif command -v shasum >/dev/null 2>&1; then
        echo "${TLA_SHA256}  ${DEFAULT_DOWNLOAD_PATH}.part" | shasum -a 256 -c -
      fi
    fi
    mv "${DEFAULT_DOWNLOAD_PATH}.part" "$DEFAULT_DOWNLOAD_PATH"
    JAR="$DEFAULT_DOWNLOAD_PATH"
  else
    cat >&2 <<EOF
ERROR: tla2tools.jar not found.
Either re-run with --download:
  $0 --download
Or download manually and set TLA2TOOLS_JAR:
  curl -fSL "$TLA_URL" -o "$DEFAULT_DOWNLOAD_PATH"
  TLA2TOOLS_JAR="$DEFAULT_DOWNLOAD_PATH" $0
EOF
    exit 1
  fi
fi

META_BASE="$(mktemp -d "${TMPDIR:-/tmp}/idis-tlc-meta.XXXXXX")"
trap 'rm -rf "$META_BASE"' EXIT

echo "Using Java: $(java -version 2>&1 | head -n 1)"
echo "Using TLC : $JAR"
echo ""

FAILED=0
for spec in "${SPECS[@]}"; do
  tla_file="$SCRIPT_DIR/${spec}.tla"
  cfg_file="$SCRIPT_DIR/${spec}.cfg"
  if [[ ! -f "$tla_file" || ! -f "$cfg_file" ]]; then
    echo "ERROR: missing ${spec}.tla or ${spec}.cfg in $SCRIPT_DIR" >&2
    exit 1
  fi
  echo "============================================================"
  echo "TLC Checking: ${spec}"
  echo "============================================================"
  meta_dir="$META_BASE/$spec"
  mkdir -p "$meta_dir"
  if (cd "$SCRIPT_DIR" && java -XX:+UseParallelGC -cp "$JAR" tlc2.TLC \
      -workers auto \
      -cleanup \
      -metadir "$meta_dir" \
      -config "${spec}.cfg" \
      "${spec}.tla"); then
    echo "[PASS] ${spec}"
    echo ""
  else
    echo "[FAIL] ${spec}" >&2
    FAILED=1
  fi
done

if [[ "$FAILED" -ne 0 ]]; then
  echo "One or more TLA+ specifications FAILED TLC model checking." >&2
  exit 1
fi

echo "All ${#SPECS[@]} TLA+ specifications PASSED TLC model checking."
