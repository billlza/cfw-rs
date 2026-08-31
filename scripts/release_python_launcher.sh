#!/bin/bash -p
# Shared isolated Python entrypoint for reviewed repository scripts.

cfw_run_release_python_script() {
  if [[ $# -lt 2 ]]; then
    echo "error: cfw_run_release_python_script requires repository, script, and optional arguments" >&2
    return 1
  fi
  local cfw_python_repository="$1"
  local cfw_python_script="$2"
  shift 2
  local cfw_python_executable="${CFW_RELEASE_PYTHON_EXECUTABLE:-}"
  if [[ "$cfw_python_repository" != /* || \
    ! -d "$cfw_python_repository" || -L "$cfw_python_repository" || \
    "$cfw_python_script" != "$cfw_python_repository/scripts/"* || \
    ! -f "$cfw_python_script" || -L "$cfw_python_script" || \
    ! -x "$cfw_python_executable" ]]; then
    echo "error: isolated release Python entrypoint is unavailable or unsafe" >&2
    return 1
  fi
  PYTHONDONTWRITEBYTECODE=1 "$cfw_python_executable" -I -S -B -W error -c '
import os
import runpy
import stat
import sys

repository = os.path.realpath(sys.argv[1])
requested_script = sys.argv[2]
arguments = sys.argv[3:]
scripts_directory = os.path.join(repository, "scripts")
script = os.path.realpath(requested_script)
try:
    relative = os.path.relpath(script, scripts_directory)
except ValueError as error:
    raise RuntimeError("isolated release Python entrypoint path is invalid") from error
if relative == os.pardir or relative.startswith(os.pardir + os.sep):
    raise RuntimeError("isolated release Python entrypoint escaped the reviewed scripts directory")
current = scripts_directory
for component in relative.split(os.sep)[:-1]:
    current = os.path.join(current, component)
    metadata = os.lstat(current)
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise RuntimeError("isolated release Python entrypoint has an unsafe parent")
metadata = os.lstat(requested_script)
if (
    script != requested_script
    or not stat.S_ISREG(metadata.st_mode)
    or metadata.st_nlink != 1
    or metadata.st_uid != os.geteuid()
    or stat.S_IMODE(metadata.st_mode) & 0o022
    or stat.S_ISLNK(metadata.st_mode)
):
    raise RuntimeError("isolated release Python entrypoint is not a safe source file")
if not relative.endswith(".py"):
    raise RuntimeError("isolated release Python entrypoint is not a Python module")
module_components = relative[:-3].split(os.sep)
if any(not component.isidentifier() for component in module_components):
    raise RuntimeError("isolated release Python entrypoint module name is invalid")
module_name = ".".join(["scripts", *module_components])
# Keep every nested import under the same source-owned package. Running a file
# by path drops its package context and makes shared parent-relative imports
# fail before the production runtime can perform its admission checks.
sys.path[:0] = [repository, scripts_directory]
sys.argv = [script, *arguments]
runpy.run_module(module_name, run_name="__main__", alter_sys=True)
' "$cfw_python_repository" "$cfw_python_script" "$@"
}
