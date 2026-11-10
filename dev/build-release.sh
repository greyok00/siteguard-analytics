#!/usr/bin/env bash
# Builds dist/grey-siteguard-<version>.zip.
#
# The archive is the working plugin with comments stripped from every PHP file
# and, when esbuild is on PATH (or ESBUILD points at it), JS and CSS minified.
# The working tree is never modified: everything happens in a temp copy.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
plugin="$root/plugin/grey-siteguard"
version=$(sed -n 's/^ \* Version: *//p' "$plugin/grey-siteguard.php" | head -1)

if [[ -z "$version" ]]; then
  echo "could not read the version from the plugin header" >&2
  exit 1
fi

out="$root/dist/grey-siteguard-$version.zip"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cp -a "$plugin" "$work/grey-siteguard"

mapfile -t php_files < <(find "$work/grey-siteguard" -name '*.php' -print)
php "$root/dev/tools/strip-comments.php" "${php_files[@]}"

# The directory will not accept minified scripts unless the readable originals
# travel with them. SITEGUARD_WPORG=1 adds a source/ folder for that upload;
# GitHub releases stay minified-only.
if [[ "${SITEGUARD_WPORG:-0}" == "1" ]]; then
  mkdir -p "$work/grey-siteguard/source"
  cp "$plugin/assets/admin.js" "$plugin/assets/tracker.js" "$work/grey-siteguard/source/"
fi

# Working notes are not part of the product.
rm -f "$work/grey-siteguard/docs/UNFINISHED.md"

esbuild_bin="${ESBUILD:-esbuild}"
if command -v "$esbuild_bin" >/dev/null 2>&1; then
  while IFS= read -r -d '' asset; do
    case "$asset" in
      *.js|*.css)
        "$esbuild_bin" "$asset" --minify --log-level=warning \
          --outfile="$asset.min" >/dev/null
        mv "$asset.min" "$asset"
        ;;
    esac
  done < <(find "$work/grey-siteguard/assets" -type f \( -name '*.js' -o -name '*.css' \) -print0)
  echo "minified JS/CSS with $esbuild_bin"
else
  echo "esbuild not found: JS/CSS were copied unminified" >&2
fi

rm -f "$out"
(cd "$work" && zip -qr "$out" grey-siteguard -x '*.DS_Store')

sum=$(sha256sum "$out" | awk '{print $1}')
name=$(basename "$out")
tmp=$(mktemp)
grep -v "  $name\$" "$root/dist/SHA256SUMS" > "$tmp" 2>/dev/null || true
printf '%s  %s\n' "$sum" "$name" >> "$tmp"
mv "$tmp" "$root/dist/SHA256SUMS"

echo "built $out ($(du -h "$out" | cut -f1)), sha256 $sum"
