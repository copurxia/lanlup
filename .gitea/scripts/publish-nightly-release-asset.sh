#!/usr/bin/env bash
# 把构建产物上传到 Forgejo 的 nightly release（不存在则创建，同名资产先删后传）。
# 用法: publish-nightly-release-asset.sh <file> [asset-name]
set -euo pipefail

file="${1:?usage: $0 <file> [asset-name]}"
asset_name="${2:-$(basename "${file}")}"
tag="${RELEASE_TAG:-nightly}"

server="${GITHUB_SERVER_URL:?GITHUB_SERVER_URL is required}"
repo="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
token="${RELEASE_TOKEN:-${GITHUB_TOKEN:-}}"
if [ -z "${token}" ]; then
  echo "❌ RELEASE_TOKEN/GITHUB_TOKEN 未设置" >&2
  exit 1
fi

api="${server}/api/v1/repos/${repo}"
auth="Authorization: token ${token}"

release_id="$(curl -sS -H "${auth}" "${api}/releases/tags/${tag}" | jq -r '.id // empty' 2>/dev/null || true)"
if [ -z "${release_id}" ]; then
  payload="$(jq -nc --arg tag "${tag}" --arg sha "${GITHUB_SHA:-}" \
    '{tag_name:$tag,name:$tag,target_commitish:$sha,draft:false,prerelease:false,body:"Nightly builds"}')"
  body_file="$(mktemp)"
  code="$(curl -sS -o "${body_file}" -w '%{http_code}' -X POST \
    -H "${auth}" -H 'Content-Type: application/json' -d "${payload}" \
    "${api}/releases")"
  if [ "${code}" = "201" ]; then
    release_id="$(jq -r '.id' "${body_file}")"
  else
    # 并行 job 可能刚创建了同名 release，回查一次
    release_id="$(curl -sS -H "${auth}" "${api}/releases/tags/${tag}" | jq -r '.id // empty' 2>/dev/null || true)"
    if [ -z "${release_id}" ]; then
      echo "❌ 创建 ${tag} release 失败 (HTTP ${code}): $(cat "${body_file}")" >&2
      exit 1
    fi
  fi
  rm -f "${body_file}"
fi

# 对齐 action-gh-release 的 overwrite_files：同名资产先删除
while read -r asset_id; do
  [ -n "${asset_id}" ] || continue
  curl -sS -X DELETE -H "${auth}" "${api}/releases/${release_id}/assets/${asset_id}" >/dev/null
done < <(curl -sS -H "${auth}" "${api}/releases/${release_id}/assets" \
  | jq -r --arg n "${asset_name}" '.[]? | select(.name==$n) | .id')

curl -sS -f -X POST -H "${auth}" \
  -F "attachment=@${file}" \
  "${api}/releases/${release_id}/assets?name=${asset_name}" >/dev/null

echo "✅ ${asset_name} -> ${tag} release (id=${release_id})"
