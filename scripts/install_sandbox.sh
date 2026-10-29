#!/usr/bin/env bash
#
# Install and verify a sandbox for Daedalus.
#
# Why a script: "how do I install the sandbox" has four answers depending on the host, and the
# one that matters is only knowable by *probing*. This picks the best available mechanism, tells
# you what each level actually enforces, and finishes by asking Daedalus itself what it selected.
#
# It never installs anything without being asked: the default is to probe and report, because a
# 1-2 GB virtual machine is not something a diagnostic command should decide on its own.
#
#   ./scripts/install_sandbox.sh                 # probe only (safe, no changes)
#   ./scripts/install_sandbox.sh --colima        # install Colima + the docker CLI, then start it
#   ./scripts/install_sandbox.sh --podman        # install podman and its machine
#   ./scripts/install_sandbox.sh --verify        # probe only, then run the real isolation tests
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_PYTHON="${REPO_ROOT}/.venv/bin/python"
WORKSPACE="${DAEDALUS_WORKSPACE:-$HOME/.daedalus}"

MODE="probe"
VERIFY=0
for arg in "$@"; do
  case "$arg" in
    --colima) MODE="colima" ;;
    --podman) MODE="podman" ;;
    --verify) VERIFY=1 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

bold() { printf '\033[1m%s\033[0m\n' "$1"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$1"; }
no()   { printf '  \033[31m✗\033[0m %s\n' "$1"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$1"; }

# ---------------------------------------------------------------------------
# Probe
# ---------------------------------------------------------------------------

probe_seatbelt() {
  bold "1. macOS Seatbelt (sandbox-exec) — zero install"
  if [[ "$(uname -s)" != "Darwin" ]]; then
    warn "not macOS; Seatbelt does not exist here"
    return 1
  fi
  if [[ ! -x /usr/bin/sandbox-exec ]]; then
    no "/usr/bin/sandbox-exec is missing"
    return 1
  fi
  # The only honest test is applying a profile: the binary can be present and still refused.
  local output
  if output="$(/usr/bin/sandbox-exec -p '(version 1)(allow default)' /bin/echo seatbelt-ok 2>&1)" \
     && [[ "$output" == *seatbelt-ok* ]]; then
    ok "an actual profile was applied"
    echo "      enforces: writes limited to the worktree, network denied"
    echo "      does NOT enforce: read restriction (measured; a read allowlist aborts dyld,"
    echo "      and a deny rule does not override a blanket allow)"
    return 0
  fi
  no "sandbox-exec is present but a profile cannot be applied:"
  echo "      ${output}"
  echo "      macOS refuses nested sandbox application, so this usually means the current"
  echo "      process is already sandboxed (a CI runner, a sandboxed IDE, an agent harness)."
  echo "      Run this script from a normal login shell to get the real answer."
  return 1
}

probe_container() {
  bold "2. Container runtime (docker / podman)"
  local found=0
  for bin in docker podman; do
    if ! command -v "$bin" >/dev/null 2>&1; then
      warn "$bin CLI not installed"
      continue
    fi
    found=1
    # A CLI with no daemon is not a runtime. This is the distinction that matters.
    if version="$("$bin" info --format '{{.ServerVersion}}' 2>/dev/null)" && [[ -n "$version" ]]; then
      ok "$bin daemon reachable (server $version)"
      return 0
    fi
    no "$bin CLI present but no reachable daemon"
    echo "      the CLI alone is not a sandbox; Daedalus requires a working daemon"
  done
  if [[ $found -eq 0 ]]; then
    warn "no container CLI at all"
  fi
  return 1
}

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------

require_brew() {
  if ! command -v brew >/dev/null 2>&1; then
    echo "Homebrew is required for this path. Install it, or use Docker Desktop / Podman Desktop." >&2
    exit 1
  fi
  if ! brew --version >/dev/null 2>&1; then
    echo "brew is installed but not runnable by $(id -un)." >&2
    exit 1
  fi
}

install_colima() {
  require_brew
  bold "Installing Colima and the docker CLI"
  NONINTERACTIVE=1 HOMEBREW_NO_AUTO_UPDATE=1 brew install colima docker

  bold "Starting the virtual machine"
  echo "  Apple-native virtualisation (vz) is used where available: it is substantially"
  echo "  faster than qemu on Apple silicon."
  if ! colima status >/dev/null 2>&1; then
    # 4 CPU / 6 GB is sized for running a test suite inside the container. Raise it if the
    # target project's tests are heavier; the boundary's own limits still apply on top.
    colima start --vm-type vz --cpu 4 --memory 6 --disk 40
  else
    ok "colima is already running"
  fi

  bold "Verifying the daemon is actually reachable"
  if version="$(docker info --format '{{.ServerVersion}}' 2>/dev/null)" && [[ -n "$version" ]]; then
    ok "docker daemon reachable (server $version)"
  else
    no "docker info failed. Try: colima status; colima restart; docker context ls"
    exit 1
  fi

  bold "Pre-pulling the sandbox base image"
  # Pulling now means the first step does not pay for it, and a pull failure is visible here
  # rather than as a mysterious step failure later.
  docker pull python:3.12-slim
}

install_podman() {
  require_brew
  bold "Installing Podman and its machine"
  NONINTERACTIVE=1 HOMEBREW_NO_AUTO_UPDATE=1 brew install podman
  if ! podman machine inspect >/dev/null 2>&1; then
    # Rootless by default, which is why podman needs no privileged helper.
    podman machine init --cpus 4 --memory 6144 --disk-size 40
  fi
  podman machine start || true
  if version="$(podman info --format '{{.Version.Version}}' 2>/dev/null)" && [[ -n "$version" ]]; then
    ok "podman machine reachable ($version)"
  else
    no "podman info failed. Try: podman machine list; podman machine start"
    exit 1
  fi
  podman pull python:3.12-slim
}

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

ask_daedalus() {
  bold "What Daedalus selects"
  local runner=()
  if [[ -x "$VENV_PYTHON" ]]; then
    runner=("$VENV_PYTHON" -m daedalus.cli)
  elif command -v daedalus >/dev/null 2>&1; then
    runner=(daedalus)
  else
    warn "neither .venv/bin/python nor a daedalus on PATH; skipping"
    return 0
  fi
  PYTHONPATH="${REPO_ROOT}/src" "${runner[@]}" preflight --workspace "$WORKSPACE" || true
}

run_isolation_tests() {
  bold "Real isolation tests (the ones normally skipped)"
  if [[ ! -x "$VENV_PYTHON" ]]; then
    warn "no .venv; run: python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'"
    return 0
  fi
  if ! "$VENV_PYTHON" -c "import pytest_timeout" >/dev/null 2>&1; then
    warn "pytest-timeout is not installed; run: .venv/bin/pip install pytest-timeout"
  fi
  cd "$REPO_ROOT"
  # -rs shows the skip reasons, so a skip is never mistaken for a pass.
  "$VENV_PYTHON" -m pytest tests/test_sandbox_drivers.py -v -rs || true
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

echo
bold "Daedalus sandbox setup"
echo "  repository: $REPO_ROOT"
echo "  workspace : $WORKSPACE"
echo

seatbelt_ok=0
container_ok=0
probe_seatbelt || seatbelt_ok=$?
probe_container || container_ok=$?

case "$MODE" in
  colima)  install_colima; container_ok=0 ;;
  podman)  install_podman;  container_ok=0 ;;
esac

echo
bold "Summary"
if [[ $container_ok -eq 0 ]]; then
  ok "container isolation is available — the strongest level"
elif [[ $seatbelt_ok -eq 0 ]]; then
  ok "Seatbelt is available: kernel-enforced filesystem and network isolation, no install needed"
  echo "      Run Daedalus from a normal login shell so it does not inherit a sandboxed context."
elif [[ "$MODE" == "probe" ]]; then
  warn "only host-process is available: code isolation, rlimits and a scrubbed environment,"
  echo "      enforced at gate time rather than by the kernel"
  echo
  echo "      To install a container runtime:"
  echo "        $0 --colima      # Apple-native VM, ~1-2 GB"
  echo "        $0 --podman      # rootless alternative"
  echo "      Or install Docker Desktop from docker.com."
fi

echo
ask_daedalus

if [[ $VERIFY -eq 1 ]]; then
  echo
  run_isolation_tests
fi

echo
bold "Note on what each level does not do"
echo "  host-process : commands run as $(id -un); filesystem and network are enforced at gate"
echo "                 time only, not by the kernel"
echo "  seatbelt     : writes limited to the worktree and network denied, both kernel-enforced;"
echo "                 reads are NOT restricted, and network_policy=allowlist is refused"
echo "  container    : --network none by default; an allowlist needs extra network configuration"
echo
echo "  None of these protects the control plane itself. The FSM, gate, event log, idempotency,"
echo "  worktree boundary and redaction hold at every level."
