#!/usr/bin/env bash
# The caller may be a credentialed runner.  This wrapper deliberately creates a
# new process environment instead of trying to redact an ever-growing denylist.
set -euo pipefail

required_tools=(gh jq python3 rg sqlite3)

check_required_tools() {
  local tool
  local -a missing_tools=()
  for tool in "${required_tools[@]}"; do
    command -v "$tool" >/dev/null 2>&1 || missing_tools+=("$tool")
  done
  if ((${#missing_tools[@]})); then
    printf 'ACAI hermetic CI preflight: missing required tool(s): %s\n' "${missing_tools[*]}" >&2
    exit 2
  fi
}

# Check the runner image before deriving the child PATH, then retain only the
# setup-python directory plus standard system locations.  This prevents a
# credentialed runner's HOME-local or agent-injected PATH shims from affecting
# tests while still using the Python selected by actions/setup-python.
check_required_tools
python_dir="$(command -v python3)"
python_dir="${python_dir%/*}"
safe_path="$python_dir:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
PATH="$safe_path"
check_required_tools

workspace=${GITHUB_WORKSPACE:?GITHUB_WORKSPACE is required}
runner_temp=${RUNNER_TEMP:-"$workspace/.acai/ci-tmp"}
ci_home="$workspace/.acai/ci-home"
tmpdir="$runner_temp/acai-hermetic-tmp"
command_to_run=${ACAI_HERMETIC_COMMAND:?ACAI_HERMETIC_COMMAND is required}

umask 022
mkdir -p "$ci_home/home" "$ci_home/codex" "$ci_home/xdg-config" "$ci_home/xdg-cache" "$ci_home/pip-cache" "$tmpdir"

# GH_TOKEN and GITHUB_TOKEN are set to empty only in this test/doctor child
# process.  Governance and approval workflows retain their GitHub API access.
exec env -i \
  PATH="$safe_path" \
  LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-}" \
  GITHUB_WORKSPACE="$workspace" \
  RUNNER_TEMP="$runner_temp" \
  TMPDIR="$tmpdir" \
  LANG="${LANG:-C.UTF-8}" \
  LC_ALL="${LC_ALL:-C.UTF-8}" \
  PYTHONNOUSERSITE=1 \
  PYTHONDONTWRITEBYTECODE=1 \
  PYTHONUTF8=1 \
  HOME="$ci_home/home" \
  CODEX_HOME="$ci_home/codex" \
  XDG_CONFIG_HOME="$ci_home/xdg-config" \
  XDG_CACHE_HOME="$ci_home/xdg-cache" \
  PIP_CACHE_DIR="$ci_home/pip-cache" \
  GH_TOKEN= \
  GITHUB_TOKEN= \
  bash -ceu "$command_to_run"
