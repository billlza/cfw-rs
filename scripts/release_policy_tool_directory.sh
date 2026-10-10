#!/bin/bash -p
# Fail-closed helpers for the owner-only Cargo policy-tool bootstrap tree.

cfw_require_private_policy_directory() {
  if [[ $# -ne 1 || "$1" != /* || "$1" == "/" || "$1" == */ ]]; then
    echo "error: policy-tool directory must be one canonical absolute path" >&2
    return 1
  fi

  local directory="$1"
  local parent effective_uid parent_mode canonical_parent
  local directory_mode canonical_directory
  parent="$(/usr/bin/dirname "$directory")" || return 1
  effective_uid="$(/usr/bin/id -u)" || {
    echo "error: cannot resolve policy-tool owner" >&2
    return 1
  }

  if [[ ! -d "$parent" || -L "$parent" ]]; then
    echo "error: policy-tool parent is not a real directory: $parent" >&2
    return 1
  fi
  canonical_parent="$(cd "$parent" && /bin/pwd -P)" || {
    echo "error: cannot resolve policy-tool parent: $parent" >&2
    return 1
  }
  parent_mode="$(/usr/bin/stat -f '%Lp' "$parent")" || return 1
  if [[ "$canonical_parent" != "$parent" || \
    "$(/usr/bin/stat -f '%u' "$parent")" != "$effective_uid" || \
    ! "$parent_mode" =~ ^[0-7]{3,4}$ || \
    $((8#$parent_mode & 8#022)) -ne 0 ]]; then
    echo "error: policy-tool parent is unavailable or unsafe: $parent" >&2
    return 1
  fi

  if [[ -e "$directory" || -L "$directory" ]]; then
    if [[ ! -d "$directory" || -L "$directory" ]]; then
      echo "error: policy-tool path is not a real directory: $directory" >&2
      return 1
    fi
  else
    /bin/mkdir -m 0700 "$directory" || {
      echo "error: cannot create policy-tool directory: $directory" >&2
      return 1
    }
  fi

  canonical_directory="$(cd "$directory" && /bin/pwd -P)" || return 1
  directory_mode="$(/usr/bin/stat -f '%Lp' "$directory")" || return 1
  if [[ "$canonical_directory" != "$directory" || \
    "$(/usr/bin/stat -f '%u' "$directory")" != "$effective_uid" || \
    "$directory_mode" != "700" ]]; then
    echo "error: policy-tool directory is unavailable or unsafe: $directory" >&2
    return 1
  fi
}

cfw_run_warning_free_policy_install() {
  if [[ $# -lt 3 || -z "$1" || "$2" != /* || "$3" != /* || \
    ! -x "$3" || -L "$3" ]]; then
    echo "error: policy-tool installation requires a label, private log, and real executable" >&2
    return 1
  fi

  local label="$1"
  local log_path="$2"
  shift 2
  local log_parent effective_uid command_status log_size log_mode
  local warning_status=1
  log_parent="$(/usr/bin/dirname "$log_path")" || return 1
  cfw_require_private_policy_directory "$log_parent" || return 1
  if [[ -e "$log_path" || -L "$log_path" ]]; then
    echo "error: policy-tool installation log already exists: $log_path" >&2
    return 1
  fi

  # The file-size limit is inherited by Cargo and its children. macOS reports
  # this limit in 512-byte blocks, so 131072 fixes the ceiling at 64 MiB.
  if (umask 077; ulimit -f 131072; "$@" >"$log_path" 2>&1); then
    command_status=0
  else
    command_status=$?
  fi

  effective_uid="$(/usr/bin/id -u)" || command_status=1
  if [[ ! -f "$log_path" || -L "$log_path" ]]; then
    echo "error: $label did not produce a real bounded log" >&2
    return 1
  fi
  log_size="$(/usr/bin/stat -f '%z' "$log_path")" || command_status=1
  log_mode="$(/usr/bin/stat -f '%Lp' "$log_path")" || command_status=1
  if [[ "$(/usr/bin/stat -f '%u' "$log_path")" != "$effective_uid" || \
    "$(/usr/bin/stat -f '%l' "$log_path")" != "1" || \
    "$log_mode" != "600" || ! "$log_size" =~ ^[0-9]+$ || \
    "$log_size" -gt 67108864 ]]; then
    /bin/rm -f "$log_path"
    echo "error: $label log is unavailable, unsafe, or unbounded" >&2
    return 1
  fi

  if /usr/bin/grep -Eq '^[[:space:]]*warning([[:space:]]|:)' "$log_path"; then
    warning_status=0
  elif [[ $? -gt 1 ]]; then
    command_status=1
  fi
  /bin/cat "$log_path" || command_status=1
  /bin/rm -f "$log_path" || command_status=1
  if [[ $command_status -ne 0 ]]; then
    echo "error: $label failed" >&2
    return 1
  fi
  if [[ $warning_status -eq 0 ]]; then
    echo "error: $label emitted a warning" >&2
    return 1
  fi
}
