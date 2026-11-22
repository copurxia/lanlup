#!/usr/bin/env bash
# Build the nightly plugin catalog from published wasm assets.
#
# Used by the push-triggered catalog workflows (_release-aggregate.yml) for
# both GitHub and Gitea/Forgejo. This script does NOT compile plugins: it reads
# <plugin>-wasip1.wasm from --wasm-dir when present, extracts lanlu_plugin_info
# via scripts/plugin-info.js, and can reuse unchanged entries from a previous
# catalog so that a mode=none refresh performs zero downloads.
#
# Writes:
#   <out-dir>/plugins.json
#   <out-dir>/lanlu-plugins-wasip1-<sha7>.tar.gz   (only when all wasm are local)
#
# Usage:
#   build-plugin-catalog.sh --wasm-dir DIR --plugins-toml FILE --out-dir DIR \
#     --commit SHA --ref REF [--channel nightly] [--repo-root DIR] \
#     [--previous-catalog FILE] [--refresh-plugins CSV|all]
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
wasm_dir=""
plugins_toml=""
out_dir=""
commit=""
ref=""
channel="nightly"
previous_catalog=""
refresh_plugins=""

while [ $# -gt 0 ]; do
  case "$1" in
    --wasm-dir) wasm_dir="$2"; shift 2 ;;
    --plugins-toml) plugins_toml="$2"; shift 2 ;;
    --out-dir) out_dir="$2"; shift 2 ;;
    --commit) commit="$2"; shift 2 ;;
    --ref) ref="$2"; shift 2 ;;
    --channel) channel="$2"; shift 2 ;;
    --repo-root) repo_root="$2"; shift 2 ;;
    --previous-catalog) previous_catalog="$2"; shift 2 ;;
    --refresh-plugins) refresh_plugins="$2"; shift 2 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [ -z "${wasm_dir}" ] || [ -z "${plugins_toml}" ] || [ -z "${out_dir}" ] || [ -z "${commit}" ] || [ -z "${ref}" ]; then
  echo "usage: $0 --wasm-dir DIR --plugins-toml FILE --out-dir DIR --commit SHA --ref REF" >&2
  exit 2
fi

command -v node >/dev/null 2>&1 || { echo "node is required (scripts/plugin-info.js)" >&2; exit 2; }
command -v jq >/dev/null 2>&1 || { echo "jq is required" >&2; exit 2; }

version="${commit:0:7}"
timestamp="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
mkdir -p "${out_dir}"
entries="$(mktemp)"
trap 'rm -f "${entries}"' EXIT

mapfile -t plugins < <(sed -nE 's/^name = "([^"]+)"$/\1/p' "${plugins_toml}")
expected="${#plugins[@]}"
[ "${expected}" -gt 0 ] || { echo "no plugins found in ${plugins_toml}" >&2; exit 1; }

refresh_all=0
if [ "${refresh_plugins}" = "all" ]; then
  refresh_all=1
fi
in_refresh() {
  [ "${refresh_all}" -eq 1 ] && return 0
  case ",${refresh_plugins}," in
    *",$1,"*) return 0 ;;
  esac
  return 1
}

echo "building catalog for ${expected} plugin(s); refresh=$([ "${refresh_all}" -eq 1 ] && echo all || echo "${refresh_plugins:-none}")"

count=0
total=0
reused=0
for plugin in "${plugins[@]}"; do
  wasm="${wasm_dir}/${plugin}-wasip1.wasm"
  if [ -f "${wasm}" ]; then
    info_err="$(mktemp)"
    if ! info_json="$(node "${repo_root}/scripts/plugin-info.js" "${wasm}" 2>"${info_err}")"; then
      echo "invalid plugin info for ${plugin}:" >&2
      cat "${info_err}" >&2
      rm -f "${info_err}"
      exit 1
    fi
    rm -f "${info_err}"

    # Fail-closed required fields (same rules as the pre-push aggregate).
    if ! printf '%s' "${info_json}" | jq -e '
        def nonempty: type == "string" and length > 0;
        type == "object" and
        (.name | nonempty) and
        (.version | nonempty) and
        (((.type? // "") | nonempty) or ((.plugin_type? // "") | nonempty)) and
        ((has("namespace") | not) or (.namespace | type == "string")) and
        ((has("permissions") | not) or (.permissions | type == "array")) and
        ((has("pre") | not) or (.pre | type == "array")) and
        ((has("after") | not) or (.after | type == "array"))
      ' >/dev/null 2>&1; then
      echo "invalid plugin info for ${plugin}: ${info_json}" >&2
      exit 1
    fi

    size="$(stat --printf='%s' "${wasm}")"
    sha="$(sha256sum "${wasm}" | cut -d' ' -f1)"
    artifact="${plugin//-/_}.wasm"

    jq -cn \
      --arg plugin "${plugin}" \
      --arg asset "${plugin}-wasip1.wasm" \
      --arg artifact "${artifact}" \
      --argjson size "${size}" \
      --arg sha "${sha}" \
      --argjson info "${info_json}" \
      '{
        plugin: $plugin,
        asset: $asset,
        artifact: $artifact,
        size_bytes: $size,
        sha256: $sha,
        namespace: ($info.namespace // ""),
        name: ($info.name // ""),
        version: ($info.version // ""),
        type: ($info.type // $info.plugin_type // ""),
        description: ($info.description // ""),
        icon: ($info.icon // ""),
        author: ($info.author // ""),
        tags: ($info.tags // ""),
        pre: ($info.pre // [])
      }' >> "${entries}"
    echo "refreshed ${plugin} (${size} bytes)"
  elif in_refresh "${plugin}"; then
    echo "refresh requested but no downloaded asset for ${plugin}: ${wasm}" >&2
    exit 1
  else
    prev_entry=""
    if [ -n "${previous_catalog}" ] && [ -f "${previous_catalog}" ]; then
      prev_entry="$(jq -c --arg p "${plugin}" '.plugins[]? | select(.plugin == $p)' "${previous_catalog}" | head -n 1)"
      if ! printf '%s' "${prev_entry}" | jq -e --arg p "${plugin}" '
          .plugin == $p and
          .asset == ($p + "-wasip1.wasm") and
          ((.type // "") | length > 0) and
          ((.sha256 // "") | test("^[0-9a-f]{64}$")) and
          ((.size_bytes // 0) > 0)
        ' >/dev/null 2>&1; then
        prev_entry=""
      fi
    fi
    if [ -z "${prev_entry}" ]; then
      echo "no downloaded asset and no reusable previous entry for ${plugin}" >&2
      exit 1
    fi
    size="$(printf '%s' "${prev_entry}" | jq -r '.size_bytes')"
    jq -cn --argjson e "${prev_entry}" '{
      plugin: $e.plugin,
      asset: $e.asset,
      artifact: $e.artifact,
      size_bytes: $e.size_bytes,
      sha256: $e.sha256,
      namespace: ($e.namespace // ""),
      name: ($e.name // ""),
      version: ($e.version // ""),
      type: ($e.type // ""),
      description: ($e.description // ""),
      icon: ($e.icon // ""),
      author: ($e.author // ""),
      tags: ($e.tags // ""),
      pre: ($e.pre // [])
    }' >> "${entries}"
    reused=$((reused + 1))
    echo "reused ${plugin} (${size} bytes, no download)"
  fi

  count=$((count + 1))
  total=$((total + size))
done

if [ "${count}" -ne "${expected}" ]; then
  echo "catalog entry count ${count} != expected ${expected}" >&2
  exit 1
fi

jq -s \
  --argjson count "${count}" \
  --argjson total "${total}" \
  --arg version "${version}" \
  --arg created "${timestamp}" \
  --arg commit "${commit}" \
  --arg ref "${ref}" \
  --arg channel "${channel}" \
  '{
    schema: 1,
    channel: $channel,
    name: "lanlu-wasip1-plugins",
    version: $version,
    created: $created,
    plugin_count: $count,
    total_size_bytes: $total,
    commit: $commit,
    ref: $ref,
    plugins: .
  }' "${entries}" > "${out_dir}/plugins.json"

# Validate the generated catalog: count, canonical asset names, unique assets,
# non-empty types, and size_bytes matching any locally downloaded wasm file.
jq -e --argjson expected "${expected}" '
  (.plugins | length) == $expected and
  ([.plugins[].asset] | all(test("^[a-z0-9_-]+-wasip1\\.wasm$"))) and
  ([.plugins[].asset] | unique | length) == $expected and
  ([.plugins[].plugin] | all(test("^[a-z0-9_-]+-rs$"))) and
  ([.plugins[].type] | all(length > 0))
' "${out_dir}/plugins.json" >/dev/null

jq -r '.plugins[] | [.plugin, (.size_bytes | tostring)] | @tsv' "${out_dir}/plugins.json" |
while IFS=$'\t' read -r plugin size; do
  wasm="${wasm_dir}/${plugin}-wasip1.wasm"
  if [ -f "${wasm}" ]; then
    actual="$(stat --printf='%s' "${wasm}")"
    if [ "${actual}" != "${size}" ]; then
      echo "size mismatch for ${plugin}: catalog=${size} actual=${actual}" >&2
      exit 1
    fi
  fi
done

present="$(find "${wasm_dir}" -maxdepth 1 -name '*-wasip1.wasm' | wc -l)"
if [ "${present}" -eq "${expected}" ]; then
  staging="${out_dir}/lanlu-plugins-wasip1"
  rm -rf "${staging}"
  mkdir -p "${staging}"
  cp "${wasm_dir}"/*-wasip1.wasm "${staging}/"
  cp "${out_dir}/plugins.json" "${staging}/metadata.json"
  tar -czf "${out_dir}/lanlu-plugins-wasip1-${version}.tar.gz" -C "${out_dir}" "lanlu-plugins-wasip1"
  echo "package: ${out_dir}/lanlu-plugins-wasip1-${version}.tar.gz"
else
  echo "package: skipped (${present}/${expected} wasm downloaded; previous bundle kept)"
fi

echo "catalog: ${out_dir}/plugins.json (${count} plugins, ${total} bytes, reused=${reused})"
