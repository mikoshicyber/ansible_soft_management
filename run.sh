#!/usr/bin/env bash
set -euo pipefail

save_image() (
  local image="$1" archive="$2" legacy="${3:-}" temporary
  umask 077
  temporary="$(mktemp -- "${archive}.tmp.XXXXXXXX")" || return 1
  trap 'rm -f -- "$temporary"' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  if [[ -n $legacy ]]; then
    gzip -c -- "$legacy" > "$temporary" || return 1
  else
    docker image save "$image" | gzip -c > "$temporary" || return 1
  fi
  [[ -s $temporary ]] || { printf '%s\n' 'ERROR: Docker image archive is empty.' >&2; return 1; }
  mv -T -- "$temporary" "$archive" || return 1
)

prepare_image() {
  local image="$1" cache_dir="$2" base_image="$3" dockerfile="$4"
  local key archive legacy cache_image run_image cache_lock
  key="$(printf '%s' "$image" | sha256sum)" || return 1
  key="${key%% *}"
  legacy="$cache_dir/$key.tar"
  archive="$legacy.gz"
  cache_image="$image"
  if [[ $image == *@sha256:* ]]; then
    cache_image="ansible-ee-cache:sha256-$key"
  fi
  if ! docker info >/dev/null; then
    printf '%s\n' 'ERROR: Docker daemon is unavailable.' >&2
    return 1
  fi
  (umask 077; mkdir -p -- "$cache_dir") || return 1
  exec {cache_lock}>"$legacy.lock" || return 1
  flock "$cache_lock" || return 1
  if [[ -L $archive || ( -e $archive && ( ! -f $archive || ! -s $archive ) ) ]]; then
    printf 'ERROR: Invalid Docker image archive: %s\n' "$archive" >&2
    return 1
  fi
  if [[ ! -f $archive && ( -e $legacy || -L $legacy ) ]]; then
    if [[ -L $legacy || ! -f $legacy || ! -s $legacy ]]; then
      printf 'ERROR: Invalid legacy Docker image archive: %s\n' "$legacy" >&2
      return 1
    fi
    printf 'Compressing existing Docker image archive: %s\n' "$legacy" >&2
    save_image "$cache_image" "$archive" "$legacy" >&2 || return 1
  fi
  if docker image inspect "$image" >/dev/null 2>&1; then
    run_image="$image"
  elif [[ $cache_image != "$image" ]] && docker image inspect "$cache_image" >/dev/null 2>&1; then
    run_image="$cache_image"
  elif [[ -f $archive ]]; then
    printf 'Loading Docker image from %s\n' "$archive" >&2
    docker image load -i "$archive" >&2 || return 1
    run_image="$cache_image"
  elif [[ $image == *@sha256:* ]]; then
    printf 'Pulling prebuilt Docker image: %s\n' "$image" >&2
    docker image pull "$image" >&2 || return 1
    run_image="$image"
  else
    if [[ ! -f $dockerfile || ! -r $dockerfile ]]; then
      printf 'ERROR: Dockerfile is missing or unreadable: %s\n' "$dockerfile" >&2
      return 1
    fi
    if ! docker image inspect "$base_image" >/dev/null 2>&1; then
      printf 'Pulling base Docker image: %s\n' "$base_image" >&2
      docker image pull "$base_image" >&2 || return 1
    fi
    printf 'Building Docker image: %s (base: %s)\n' "$image" "$base_image" >&2
    docker build --pull=false --build-arg "BASE_IMAGE=$base_image" --tag "$image" - < "$dockerfile" >&2 || return 1
    run_image="$image"
  fi
  if ! docker image inspect "$run_image" >/dev/null 2>&1; then
    printf 'ERROR: Expected Docker image is missing: %s\n' "$run_image" >&2
    return 1
  fi
  if [[ ! -f $archive ]]; then
    if [[ $cache_image != "$run_image" ]]; then
      docker image tag "$run_image" "$cache_image" >&2 || return 1
    fi
    printf 'Saving Docker image to %s\n' "$archive" >&2
    save_image "$cache_image" "$archive" >&2 || return 1
  fi
  printf '%s\n' "$run_image"
}

main() {
  local project source_dir image base_image inventory cache_dir run_image
  project="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
  source_dir="${SOURCE_DIR:-/mnt/hdd1/shares/autodownloads}"
  image="${ANSIBLE_EE_IMAGE:-ansible-ee:metadata}"
  base_image="${ANSIBLE_EE_BASE_IMAGE:-quay.io/ansible/awx-ee:latest}"
  inventory="${ANSIBLE_INVENTORY_FILE:-inventory.yaml}"
  cache_dir="${ANSIBLE_EE_CACHE_DIR:-$project/.docker-images}"
  if [[ ${1:-} == -h || ${1:-} == --help ]]; then
    printf '%s\n' 'Usage: ./run.sh [playbook.yml] [ansible-playbook arguments]' 'ANSIBLE_EE_IMAGE (default: ansible-ee:metadata): final image tag or prebuilt digest.' 'ANSIBLE_EE_BASE_IMAGE (default: quay.io/ansible/awx-ee:latest): base image for Dockerfile.' 'Reuse local image or restore its archive; otherwise pull missing base, build and save the final image.' 'An explicit digest selects a prebuilt image, which is pulled instead of built if missing.' 'Set SOURCE_DIR and ANSIBLE_INVENTORY_FILE as needed.' 'Compressed Docker image archives (.tar.gz): ANSIBLE_EE_CACHE_DIR (default: .docker-images in the project directory).' 'Use only trusted Docker images and cache archives.' 'For playbook.yml, --limit selects Windows hosts; localhost runs automatically.'
    return 0
  fi
  if [[ $image != *@sha256:* && ${image##*/} != *:* ]]; then
    printf '%s\n' 'ERROR: Set ANSIBLE_EE_IMAGE to an explicit tag or digest.' >&2
    return 2
  fi
  if [[ $image == "$base_image" ]]; then
    printf '%s\n' 'ERROR: ANSIBLE_EE_IMAGE must differ from ANSIBLE_EE_BASE_IMAGE.' >&2
    return 2
  fi
  if [[ ! -d $source_dir || ! -f $project/$inventory ]]; then
    printf '%s\n' 'ERROR: Source directory or inventory is missing.' >&2
    return 2
  fi
  source_dir="$(cd -- "$source_dir" && pwd -P)"
  if [[ $cache_dir != /* ]]; then cache_dir="$project/$cache_dir"; fi
  command -v docker >/dev/null && command -v flock >/dev/null && command -v sha256sum >/dev/null && command -v gzip >/dev/null || { printf '%s\n' 'ERROR: docker, flock, sha256sum and gzip are required.' >&2; return 2; }
  local -a terminal=() args=("$@")
  if [[ -t 0 && -t 1 ]]; then terminal=(-it); fi
  if (( ${#args[@]} == 0 )) || [[ ${args[0]:-} == -* ]]; then args=(playbook.yml "${args[@]}"); fi
  exec 9>"$project/.software-manager.lock"
  flock -n 9 || { printf '%s\n' 'ERROR: Another local run is active.' >&2; return 1; }
  if ! run_image="$(prepare_image "$image" "$cache_dir" "$base_image" "$project/Dockerfile")"; then
    printf '%s\n' 'ERROR: Docker image preparation failed.' >&2
    return 1
  fi
  local -a command=(ansible-playbook)
  if [[ ${args[0]##*/} == playbook.yml ]]; then
    command=(python3 /work/scripts/run_playbook.py)
  fi
  docker run --pull=never --rm "${terminal[@]}" \
    -v "$project:/work" -v "$source_dir:/source:ro" -w /work \
    -e HOME=/tmp -e ANSIBLE_LOCAL_TEMP=/tmp/ansible-local -e ANSIBLE_CONFIG=/work/ansible.cfg \
    -e TELEGRAM_BOT_TOKEN -e TELEGRAM_TOKEN -e TELEGRAM_CHAT_ID -e TELEGRAM_HTTPS_PROXY \
    "$run_image" "${command[@]}" -i "$inventory" "${args[@]}"
}

main "$@"
