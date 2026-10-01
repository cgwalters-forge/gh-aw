#!/usr/bin/env bash
#
# host_user_sandbox.sh - Run the agent as a separate unprivileged user on the
# runner VM (sandbox.agent.runtime: host-user).
#
# Hosted runners give the runner user passwordless sudo for the whole job, so
# the agent can't simply run as runner. Instead it runs as SANDBOX_USER, in a
# logind session of its own started by run0 (systemd 256 or later), with:
#   - no sudo, no polkit, no cron/at and no lingering user manager;
#   - subordinate ids and the kvm group, so rootless podman (including
#     multi-uid builds) and /dev/kvm work;
#   - the runner's home hidden, except for the workspace (read-write) and
#     read-only snapshots of the gh-aw files the engine needs;
#   - a private /tmp, with /tmp/gh-aw shared but not writable;
#   - only the environment variables the compiler listed, and never the
#     job's secrets: inference goes through a runner-side proxy.
#
# Subcommands, all run as root through `sudo -n`:
#   enter RUNNER_USER WORKSPACE RUNNER_TEMP
#       Create the sandbox user, close the runner's home and grant the user
#       the workspace. Must run once, before `run`.
#   run [--setenv=NAME=VALUE]... [--writable=FILE]... [--bind-ro=PATH]... -- SCRIPT
#       Run SCRIPT with bash as the sandbox user. --writable grants write
#       access to a file the runner pre-created (the engine's logs);
#       --bind-ro shows a root-owned snapshot of PATH (a file or a
#       directory) at PATH.
#   seal
#       Stop every process of the sandbox user, remove what it left in
#       shared directories, hand the workspace back to the runner and delete
#       the user. No `run` is accepted afterwards.
#
# Exit codes: run exits with SCRIPT's status; anything else exits 1 on error.

# The upper-case variables some functions use come from CONFIG_FILE.
# shellcheck disable=SC2153
set -euo pipefail

readonly SANDBOX_USER="runner-sandbox"
readonly STATE_DIR="/run/gh-aw-host-user"
readonly CONFIG_FILE="${STATE_DIR}/config"
readonly SEALED_FILE="${STATE_DIR}/sealed"
# The sandbox's processes, its run0 sessions and its systemd user manager
# alike, see the root filesystem read-only (ProtectSystem=strict) and get
# private /tmp, /var/tmp, /dev/shm and /run/lock: the only places they can
# write are the workspace, their home and runtime directory, and the files
# the run step grants. These are the shared directories the seal still
# sweeps, in case the confinement missed something.
readonly SHARED_WRITABLE_DIRS=(/tmp /var/tmp /dev/shm /run/lock /var/crash)
readonly USER_MANAGER_DROPIN_DIR=/etc/systemd/system
readonly SUDOERS_FILE="/etc/sudoers.d/zz-gh-aw-host-user"
readonly POLKIT_RULE="/etc/polkit-1/rules.d/00-gh-aw-host-user.rules"
readonly SUBID_COUNT=65536
readonly SANDBOX_UMASK="0002"
# Variables that must never reach the sandbox, whatever the compiler listed:
# the runner's credentials and anything that changes how programs start.
readonly DENIED_ENV_RE='^(ACTIONS_.*|GITHUB_TOKEN|GH_TOKEN|GITHUB_PERSONAL_ACCESS_TOKEN|GH_AW_GITHUB_TOKEN|COPILOT_GITHUB_TOKEN|.*SECRET.*|LD_.*|BASH_ENV|ENV|HOME|USER|LOGNAME|SHELL|SUDO_.*)$'
# What in a .git/config means a credential was left for git to use.
readonly GIT_CREDENTIAL_RE='extraheader|://[^/@[:space:]]+:[^/@[:space:]]+@|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_'

die() {
  echo "::error::host-user sandbox: $*" >&2
  exit 1
}

log() {
  echo "[host-user ${SECONDS}s] $*"
}

require_root() {
  [ "$(id -u)" = 0 ] || die "must run as root (through sudo)"
}

# Loads RUNNER_USER, RUNNER_HOME, WORKSPACE, SANDBOX_UID and SANDBOX_GID
# written by enter.
load_config() {
  [ -r "${CONFIG_FILE}" ] || die "the sandbox was not entered (no ${CONFIG_FILE})"
  # shellcheck source=/dev/null
  . "${CONFIG_FILE}"
}

# Prints the first id after every range already in FILE (/etc/subuid or
# /etc/subgid), so the sandbox's range never overlaps the runner's.
next_free_subid() {
  local file="$1" start=100000
  if [ -f "${file}" ]; then
    start=$(awk -F: -v min="${start}" '
      { end = $2 + $3; if (end > min) min = end }
      END { print min }' "${file}")
  fi
  echo "${start}"
}

cmd_enter() {
  [ $# -eq 3 ] || die "usage: enter RUNNER_USER WORKSPACE RUNNER_TEMP"
  local runner="$1" workspace="$2" runner_temp="$3"
  require_root
  command -v run0 >/dev/null || die "run0 not found: host-user needs systemd 256 or later (e.g. runs-on: ubuntu-26.04)"
  command -v setfacl >/dev/null || die "setfacl not found: install the acl package on the runner"
  [ -e "${CONFIG_FILE}" ] && die "the sandbox was already entered in this job"
  [ -d "${workspace}" ] || die "workspace ${workspace} is not a directory"
  if [ "${runner}" = root ] || [ "${runner}" = "${SANDBOX_USER}" ]; then
    die "invalid runner user ${runner}"
  fi

  local runner_uid runner_home
  runner_uid=$(id -u "${runner}") || die "unknown runner user ${runner}"
  runner_home=$(realpath -e "$(getent passwd "${runner}" | cut -d: -f6)")
  # The runner's home is what gets closed and hidden; anything of the job's
  # outside it would stay visible to the sandbox user.
  local dir
  for dir in "${workspace}" "${runner_temp}"; do
    case "$(realpath -e "${dir}")/" in
      "${runner_home}"/*) ;;
      *) die "${dir} is not under the runner's home ${runner_home}: the host-user sandbox can't hide it" ;;
    esac
  done

  log "creating ${SANDBOX_USER}"
  if ! getent passwd "${SANDBOX_USER}" >/dev/null; then
    useradd --create-home --user-group --shell /bin/bash "${SANDBOX_USER}"
  fi
  local sandbox_uid sandbox_gid sandbox_home
  sandbox_uid=$(id -u "${SANDBOX_USER}")
  sandbox_gid=$(id -g "${SANDBOX_USER}")
  sandbox_home=$(getent passwd "${SANDBOX_USER}" | cut -d: -f6)
  # By uid too: another name for root or the runner is still them.
  if [ "${sandbox_uid}" = 0 ] || [ "${sandbox_uid}" = "${runner_uid}" ]; then
    die "${SANDBOX_USER} has uid ${sandbox_uid}, root's or the runner's"
  fi

  # Subordinate ids for rootless podman, after every existing range.
  if ! grep -q "^${SANDBOX_USER}:" /etc/subuid 2>/dev/null; then
    local first_uid
    first_uid=$(next_free_subid /etc/subuid)
    usermod --add-subuids "${first_uid}-$((first_uid + SUBID_COUNT - 1))" "${SANDBOX_USER}"
  fi
  if ! grep -q "^${SANDBOX_USER}:" /etc/subgid 2>/dev/null; then
    local first_gid
    first_gid=$(next_free_subid /etc/subgid)
    usermod --add-subgids "${first_gid}-$((first_gid + SUBID_COUNT - 1))" "${SANDBOX_USER}"
  fi
  # /dev/kvm is root:kvm 0660 on Ubuntu runners.
  if getent group kvm >/dev/null; then
    usermod -aG kvm "${SANDBOX_USER}"
  fi

  # No root for the sandbox user: no sudo (the last matching rule wins, and
  # this file is read last), no polkit action, and nothing that starts its
  # processes outside a run (cron, at, a lingering user manager), where the
  # seal step could miss them.
  printf '%s ALL=(ALL:ALL) !ALL\n' "${SANDBOX_USER}" >"${SUDOERS_FILE}.tmp"
  chmod 440 "${SUDOERS_FILE}.tmp"
  visudo -cq -f "${SUDOERS_FILE}.tmp" || die "generated sudoers rule is invalid"
  mv "${SUDOERS_FILE}.tmp" "${SUDOERS_FILE}"
  if [ -d /etc/polkit-1 ]; then
    install -d -m 755 "$(dirname "${POLKIT_RULE}")"
    cat >"${POLKIT_RULE}" <<EOF
polkit.addRule(function(action, subject) {
  if (subject.user == "${SANDBOX_USER}") return polkit.Result.NO;
});
EOF
  fi
  local deny
  for deny in /etc/cron.deny /etc/at.deny; do
    grep -qx "${SANDBOX_USER}" "${deny}" 2>/dev/null || echo "${SANDBOX_USER}" >>"${deny}"
  done
  loginctl disable-linger "${SANDBOX_USER}" 2>/dev/null || true

  # Close what runner images leave open to every local user. The runner's
  # home holds the runner's credentials and the job's temp files; inside
  # a run it is also replaced by an empty directory (see cmd_run), but
  # the sandbox user's own systemd manager runs outside that namespace.
  chmod 700 "${runner_home}"
  echo 1 >/proc/sys/kernel/yama/ptrace_scope
  # Some images set XDG_RUNTIME_DIR to runner's in /etc/environment, which
  # PAM hands to every session and which breaks rootless podman.
  # https://github.com/actions/runner-images/issues/14649
  if grep -q '^XDG_RUNTIME_DIR=' /etc/environment 2>/dev/null; then
    sed -i '/^XDG_RUNTIME_DIR=/d' /etc/environment
  fi

  # The agent works in the runner's checkout, so the safe outputs MCP server
  # (which mounts the same directory) sees its changes. Grant the sandbox
  # user the tree with ACLs rather than chown, so runner-side containers
  # keep their access; the seal step hands it back to the runner.
  log "granting ${SANDBOX_USER} the workspace"
  setfacl -R -P -m "u:${SANDBOX_USER}:rwX,d:u:${SANDBOX_USER}:rwX,d:u:${runner}:rwX" "${workspace}"

  install -d -m 755 "${STATE_DIR}"
  # The user manager logind starts for the sandbox's sessions runs outside
  # run0's namespace, and the agent can start services through it: confine
  # it the same way.
  local dropin="${USER_MANAGER_DROPIN_DIR}/user@${sandbox_uid}.service.d"
  install -d -m 755 "${dropin}"
  {
    echo "[Service]"
    confinement_properties "${runner_home}" "${sandbox_home}" "${sandbox_uid}" | sed 's/^--property=//'
  } >"${dropin}/gh-aw-host-user.conf"
  systemctl daemon-reload
  # The agent controls .git while it runs, and the runner runs git in it
  # afterwards (credentials, patches): keep what could make that git run
  # the agent's code (config, hooks) to restore at the seal.
  if [ -d "${workspace}/.git" ] && [ ! -L "${workspace}/.git" ]; then
    # Refuse rather than hand over a credential that the "Clean credentials"
    # step (continue-on-error) failed to remove.
    if grep -Eq "${GIT_CREDENTIAL_RE}" "${workspace}/.git/config"; then
      die "${workspace}/.git/config still holds a git credential; refusing to hand the workspace to the sandbox"
    fi
    install -d -m 700 "${STATE_DIR}/git"
    cp -a "${workspace}/.git/config" "${STATE_DIR}/git/config"
    if [ -d "${workspace}/.git/hooks" ]; then
      cp -a "${workspace}/.git/hooks" "${STATE_DIR}/git/hooks"
    fi
  fi

  # git refuses a repository another user owns.
  install -m 644 -o "${SANDBOX_USER}" -g "${SANDBOX_USER}" /dev/null "${sandbox_home}/.gitconfig"
  git config --file "${sandbox_home}/.gitconfig" --add safe.directory "${workspace}"

  cat >"${CONFIG_FILE}" <<EOF
RUNNER_USER=$(printf '%q' "${runner}")
RUNNER_HOME=$(printf '%q' "${runner_home}")
WORKSPACE=$(printf '%q' "${workspace}")
SANDBOX_UID=${sandbox_uid}
SANDBOX_GID=${sandbox_gid}
SANDBOX_HOME=$(printf '%q' "${sandbox_home}")
EOF
  echo "Entered the host-user sandbox: the agent runs as $(id "${SANDBOX_USER}")"
}

cmd_run() {
  require_root
  load_config
  [ -e "${SEALED_FILE}" ] && die "the sandbox is sealed: nothing can run in it after the seal step"

  local -a setenv=() props=()
  local arg name ro=0
  while [ $# -gt 0 ]; do
    arg="$1"
    shift
    case "${arg}" in
      --setenv=*)
        name="${arg#--setenv=}"
        name="${name%%=*}"
        [[ "${name}" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || die "invalid variable name ${name@Q}"
        [[ "${name}" =~ ${DENIED_ENV_RE} ]] && die "${name} cannot be passed into the sandbox"
        setenv+=("${arg}")
        ;;
      --writable=*)
        local file="${arg#--writable=}"
        if [ -L "${file}" ] || [ ! -f "${file}" ]; then
          die "--writable ${file@Q} is not a regular file"
        fi
        setfacl -m "u:${SANDBOX_USER}:rw" "${file}"
        ;;
      --bind-ro=*)
        local src="${arg#--bind-ro=}" copy
        if [ -L "${src}" ] || { [ ! -d "${src}" ] && [ ! -f "${src}" ]; }; then
          die "--bind-ro ${src@Q} is not a directory or regular file"
        fi
        # A root-owned snapshot: the sandbox can read it whatever the
        # original's modes, and the runner can't change it afterwards. Only
        # what the compiler names is shown, so widening the modes is fine.
        copy="${STATE_DIR}/ro/${ro}"
        ro=$((ro + 1))
        rm -rf "${copy}"
        install -d -m 755 "$(dirname "${copy}")"
        cp -a --no-preserve=ownership,links "${src}" "${copy}"
        chown -R root:root "${copy}"
        chmod -R a+rX,go-w "${copy}"
        props+=("--property=BindReadOnlyPaths=${copy}:${src}")
        ;;
      --)
        break
        ;;
      *)
        die "unknown run argument ${arg@Q}"
        ;;
    esac
  done
  [ $# -eq 1 ] || die "usage: run [--setenv=NAME=VALUE]... [--writable=FILE]... [--bind-ro=DIR]... -- SCRIPT"
  local script="${STATE_DIR}/agent-command.sh"
  local -a confine
  mapfile -t confine < <(confinement_properties "${RUNNER_HOME}" "${SANDBOX_HOME}" "${SANDBOX_UID}")
  install -m 644 -o root -g root "$1" "${script}"

  # run0 starts the command as a transient service through its own PAM
  # stack, so pam_systemd gives it a logind session (XDG_RUNTIME_DIR and a
  # user manager, which rootless podman needs) and HOME/USER/SHELL of the
  # sandbox user. It also sets SUDO_USER and friends, which tools take to
  # mean they run under sudo; --setenv can't unset them, hence env -u.
  # Inside, the runner's home is an empty read-only directory but for the
  # workspace and the snapshots, the rest of the filesystem is read-only
  # (confinement_properties), and /tmp is private but for /tmp/gh-aw,
  # which stays read-only to the sandbox user by its modes.
  exec run0 --pipe --no-ask-password --shell-prompt-prefix= \
    --user="${SANDBOX_USER}" --chdir="${WORKSPACE}" \
    --property=CollectMode=inactive-or-failed \
    --property=UMask="${SANDBOX_UMASK}" \
    "${confine[@]}" \
    --property=ReadWritePaths="${WORKSPACE}" \
    --property=BindPaths="${WORKSPACE}" \
    --property=BindPaths=/tmp/gh-aw \
    "${props[@]}" \
    "${setenv[@]}" \
    -- env -u SUDO_USER -u SUDO_UID -u SUDO_GID -u SUDO_HOME -u SUDO_COMMAND \
    -- bash --noprofile --norc "${script}"
}

# Prints "START COUNT" for the sandbox user's subordinate range in FILE, or
# "0 0" when it has none.
subid_range() {
  local start count
  IFS=: read -r _ start count < <(grep "^${SANDBOX_USER}:" "$1" 2>/dev/null || echo "x:0:0")
  echo "${start} ${count}"
}

# Prints the pids of processes whose real uid is the sandbox user or one of
# its subordinate ids (rootless containers).
sandbox_pids() {
  local sub_start sub_count
  read -r sub_start sub_count < <(subid_range /etc/subuid)
  awk -v uid="${SANDBOX_UID}" -v s="${sub_start}" -v c="${sub_count}" '
    FNR == 1 { pid = FILENAME; sub(/^\/proc\//, "", pid); sub(/\/status$/, "", pid) }
    $1 == "Uid:" && ($2 == uid || ($2 >= s && $2 < s + c)) { print pid }
  ' /proc/[0-9]*/status 2>/dev/null || true
}

# Prints, one --property=... per line, the confinement shared by the sandbox's
# run0 sessions and its user manager: RUNNER_HOME hidden, the root
# filesystem read-only but for SANDBOX_HOME and the runtime directory of
# SANDBOX_UID, and private temporary directories.
confinement_properties() {
  local runner_home="$1" sandbox_home="$2" sandbox_uid="$3"
  printf '%s\n' \
    "--property=PrivateTmp=yes" \
    "--property=ProtectSystem=strict" \
    "--property=ReadWritePaths=-${sandbox_home} -/run/user/${sandbox_uid}" \
    "--property=TemporaryFileSystem=/dev/shm:mode=1777 /run/lock:mode=1777 ${runner_home}:ro" \
    "--property=InaccessiblePaths=-/var/crash" \
    "--property=PrivateIPC=yes"
}

# Removes what the sandbox left in the shared writable directories, in case
# the confinement missed something: anything owned by its uid, gid or
# subordinate ids goes.
remove_sandbox_leftovers() {
  local uid_start uid_count gid_start gid_count
  read -r uid_start uid_count < <(subid_range /etc/subuid)
  read -r gid_start gid_count < <(subid_range /etc/subgid)
  local -a owned=(-uid "${SANDBOX_UID}" -o -gid "${SANDBOX_GID}")
  if [ "${uid_count}" -gt 0 ]; then
    owned+=(-o "(" -uid "+$((uid_start - 1))" -uid "-$((uid_start + uid_count))" ")")
  fi
  if [ "${gid_count}" -gt 0 ]; then
    owned+=(-o "(" -gid "+$((gid_start - 1))" -gid "-$((gid_start + gid_count))" ")")
  fi
  local dir left
  local -a dirs=()
  for dir in "${SHARED_WRITABLE_DIRS[@]}"; do
    if [ -d "${dir}" ]; then dirs+=("${dir}"); fi
  done
  for dir in "${dirs[@]}"; do
    find "${dir}" -mindepth 1 -maxdepth 1 "(" "${owned[@]}" ")" -print -exec rm -rf {} + || true
  done
  for dir in "${dirs[@]}"; do
    left=$(find "${dir}" -mindepth 1 -maxdepth 1 "(" "${owned[@]}" ")" -print -quit 2>/dev/null || true)
    [ -z "${left}" ] || die "could not remove ${left}, which the sandbox left"
  done
}

cmd_seal() {
  require_root
  if [ ! -r "${CONFIG_FILE}" ]; then
    echo "The host-user sandbox was never entered; nothing to seal"
    return 0
  fi
  load_config
  touch "${SEALED_FILE}"

  # The session scopes, the user manager (with podman's pause process and
  # anything started through systemd --user) and every service run0
  # started all live under the user's slice.
  loginctl terminate-user "${SANDBOX_USER}" 2>/dev/null || true
  systemctl kill --signal=KILL "user-${SANDBOX_UID}.slice" 2>/dev/null || true
  systemctl stop "user-${SANDBOX_UID}.slice" 2>/dev/null || true
  local attempt pids
  for attempt in 1 2 3 4 5 6 7 8 9 10; do
    pids=$(sandbox_pids)
    [ -z "${pids}" ] && break
    echo "Killing leftover sandbox processes (attempt ${attempt}): ${pids//$'\n'/ }"
    # shellcheck disable=SC2086 # pids is a list of numbers
    kill -KILL ${pids} 2>/dev/null || true
    sleep 1
  done
  pids=$(sandbox_pids)
  [ -z "${pids}" ] || die "sandbox processes survived the seal: ${pids//$'\n'/ }"

  # Hand the workspace back to the runner, as if it had made the changes.
  # Neither command follows symlinks the agent left.
  if [ -L "${WORKSPACE}" ] || [ ! -d "${WORKSPACE}" ]; then
    die "the workspace ${WORKSPACE} is no longer a directory"
  fi
  setfacl -R -P -b "${WORKSPACE}"
  chown -R -h "${RUNNER_USER}:" "${WORKSPACE}"
  if [ -d "${STATE_DIR}/git" ]; then
    local git_dir="${WORKSPACE}/.git"
    if [ -L "${git_dir}" ] || [ ! -d "${git_dir}" ]; then
      die "the agent replaced ${git_dir}"
    fi
    # commondir and gitdir would point git at config and hooks elsewhere.
    rm -rf "${git_dir}/commondir" "${git_dir}/gitdir" "${git_dir}/config.worktree" "${git_dir}/hooks"
    install -m 644 -o "${RUNNER_USER}" "${STATE_DIR}/git/config" "${git_dir}/config"
    if [ -d "${STATE_DIR}/git/hooks" ]; then
      cp -a "${STATE_DIR}/git/hooks" "${git_dir}/hooks"
    fi
    local common
    common=$(runuser -u "${RUNNER_USER}" -- git -C "${WORKSPACE}" rev-parse --path-format=absolute --git-common-dir) ||
      die "git can't read the restored repository in ${WORKSPACE}"
    [ "$(realpath -e "${common}")" = "$(realpath -e "${git_dir}")" ] ||
      die "git resolves ${WORKSPACE}'s repository to ${common}, not ${git_dir}"
  else
    # There was no repository to restore, so none the agent made may stay.
    rm -rf "${WORKSPACE}/.git"
  fi
  # The agent also controlled the index, the worktree and .git/modules, so it
  # could have made a submodule, or changed a real one, whose own config runs
  # a command (core.fsmonitor) when the runner's git recurses into it, and
  # .gitmodules settings override the ones below. Without a nested repository
  # git has nothing to recurse into, so remove every one: gh-aw's later steps
  # don't need submodule state.
  rm -rf "${WORKSPACE}/.git/modules"
  find -P "${WORKSPACE}" -mindepth 2 -name .git -prune -exec rm -rf {} +
  # Defense in depth for the rest of the job.
  git config --system diff.ignoreSubmodules all
  git config --system submodule.recurse false
  git config --system status.submoduleSummary false
  git config --system core.fsmonitor false

  log "removing what the sandbox left in shared directories"
  remove_sandbox_leftovers
  # Nothing of the sandbox survives into a later job on the same machine.
  rm -rf "${USER_MANAGER_DROPIN_DIR}/user@${SANDBOX_UID}.service.d"
  systemctl daemon-reload
  userdel --remove --force "${SANDBOX_USER}" 2>/dev/null || true
  getent passwd "${SANDBOX_USER}" >/dev/null && die "could not delete ${SANDBOX_USER}"
  rm -rf "${STATE_DIR}"
  echo "Sealed the host-user sandbox"
}

main() {
  [ $# -ge 1 ] || die "usage: $0 enter|run|seal ..."
  local sub="$1"
  shift
  case "${sub}" in
    enter) cmd_enter "$@" ;;
    run) cmd_run "$@" ;;
    seal) cmd_seal "$@" ;;
    *) die "unknown subcommand ${sub@Q}" ;;
  esac
}

main "$@"
