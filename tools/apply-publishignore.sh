#!/usr/bin/env bash
# Removes the files / directories listed in .publishignore from the working tree, to preview what the public mirror
# would contain (see ci/github/publish.sh). DESTRUCTIVE: run it on a throwaway clone, or use --dry-run first.
#
# Usage: tools/apply-publishignore.sh [--dry-run|-n] [IGNORE_FILE]
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
REPO_ROOT=$(cd -- "${SCRIPT_DIR}/.." &>/dev/null && pwd)

dry_run=0
ignore_file="${REPO_ROOT}/.publishignore"
for arg in "$@"; do
    case "${arg}" in
        --dry-run | -n) dry_run=1 ;;
        -h | --help)
            sed -n '2,5p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) ignore_file="${arg}" ;;
    esac
done

if [[ ! -f "${ignore_file}" ]]; then
    echo "ignore file not found: ${ignore_file}" >&2
    exit 1
fi

cd "${REPO_ROOT}"

removed=0
missing=0
while IFS= read -r line || [[ -n "${line}" ]]; do
    entry="${line%$'\r'}"
    # Trim surrounding whitespace, skip empty lines and comments
    entry="${entry#"${entry%%[![:space:]]*}"}"
    entry="${entry%"${entry##*[![:space:]]}"}"
    [[ -z "${entry}" || "${entry}" == \#* ]] && continue

    # Directories may be written as `dir/`
    while [[ "${entry}" == */ ]]; do entry="${entry%/}"; done

    # Never touch anything outside the repository
    if [[ -z "${entry}" || "${entry}" == /* || "${entry}" == ".." || "${entry}" == ../* || "${entry}" == */../* || "${entry}" == */.. ]]; then
        echo "skipping unsafe entry: ${line}" >&2
        continue
    fi

    if [[ ! -e "${entry}" && ! -L "${entry}" ]]; then
        echo "not found:  ${entry}"
        missing=$((missing + 1))
        continue
    fi

    if [[ "${dry_run}" -eq 1 ]]; then
        echo "would remove: ${entry}"
    else
        rm -rf -- "${entry}"
        echo "removed:    ${entry}"
    fi
    removed=$((removed + 1))
done <"${ignore_file}"

verb=$([[ "${dry_run}" -eq 1 ]] && echo "would remove" || echo "removed")
echo "${verb} ${removed} entries, ${missing} not found"
