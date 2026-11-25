#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")"
if [ "$#" -gt 1 ]; then
    printf '%s\n' 'Usage: /bin/bash run_all_checks.sh [--fast|--full-rebuild]' >&2
    exit 2
fi
case "${1:---fast}" in
    --fast|--full-rebuild)
        export PYTHONDONTWRITEBYTECODE=1
        exec "${PYTHON:-python3}" scripts/verify_cleanroom.py "${1:---fast}"
        ;;
    *)
        printf '%s\n' 'Usage: /bin/bash run_all_checks.sh [--fast|--full-rebuild]' >&2
        exit 2
        ;;
esac
