#!/usr/bin/env bash
set -euo pipefail

main() {
  local project image
  project="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
  image="${ANSIBLE_EE_IMAGE:-ansible-ee:metadata}"

  if [[ ! -d "$project/tests" ]]; then
    printf 'ERROR: tests directory not found: %s/tests\n' "$project" >&2
    return 1
  fi

  docker run --rm --pull=never --network none \
    -v "$project:/work:ro" \
    -w /work \
    -e HOME=/tmp \
    -e ANSIBLE_LOCAL_TEMP=/tmp/ansible-local \
    -e ANSIBLE_CONFIG=/work/ansible.cfg \
    -e PYTHONDONTWRITEBYTECODE=1 \
    --entrypoint python3 \
    "$image" -m unittest discover -s tests -v "$@"
}

main "$@"
