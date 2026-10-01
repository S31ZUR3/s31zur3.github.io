#!/usr/bin/env bash
# Rebuild generated data and publish the site.
#
# Usage:
#   ./publish.sh                 # auto commit message
#   ./publish.sh "blog: my post" # custom commit message
set -euo pipefail
cd "$(dirname "$0")"

msg="${1:-}"

echo "==> Building data.js (writeups)"
python3 generate_data.py >/dev/null

echo "==> Building blog-data.js (blog)"
python3 generate_blog.py

if [[ -z "$(git status --porcelain)" ]]; then
  echo "==> Nothing to publish — working tree is clean."
  exit 0
fi

if [[ -z "$msg" ]]; then
  msg="site: publish $(date '+%Y-%m-%d %H:%M')"
fi

echo "==> Changes:"
git status --short

git add -A
git commit -m "$msg"
git push

echo "==> Published: $msg"
