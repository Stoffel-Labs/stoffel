#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

hooks_dir="$(git rev-parse --path-format=absolute --git-common-dir)/hooks"
mkdir -p "$hooks_dir"
install -m 0755 .githooks/pre-commit "$hooks_dir/pre-commit"
# A copied hook is an explicit snapshot. Checking out another branch must not
# silently replace executable code used by a later commit.
if git config --local --get-all core.hooksPath >/dev/null; then
    git config --local --unset-all core.hooksPath
fi

echo "Installed a snapshot of .githooks/pre-commit into $hooks_dir"
