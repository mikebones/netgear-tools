#!/usr/bin/env bash
# Build the provider into the local filesystem mirror and clear the stale lock.
#
# Terraform records a checksum of the provider binary in .terraform.lock.hcl.
# A locally-built provider gets a new checksum on every build, so the next
# command fails with "does not match any of the checksums recorded in the
# dependency lock file" - which reads like corruption and is really just a
# rebuild. Dropping only this provider's lock entry re-locks it on the next
# init while leaving every upstream provider pinned where it was.
set -euo pipefail

MIRROR="${MIRROR:-$HOME/.terraform.d/plugins/local/mikebones/netgear/0.1.0/windows_amd64}"
BIN="$MIRROR/terraform-provider-netgear.exe"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

mkdir -p "$MIRROR"
( cd "$REPO" && go build -o "$BIN" . )
echo "  built $BIN"

for dir in "$@"; do
  lock="$dir/.terraform.lock.hcl"
  [ -f "$lock" ] || { echo "  no lock in $dir - skipping"; continue; }
  python - "$lock" <<'PY'
import io, re, sys
p = sys.argv[1]
s = io.open(p, encoding="utf-8").read()
out = re.sub(r'provider "local/mikebones/netgear" \{.*?\n\}\n+', "", s, flags=re.S)
io.open(p, "w", encoding="utf-8", newline="\n").write(out)
print("  cleared netgear lock entry" if out != s else "  no netgear lock entry")
PY
  ( cd "$dir" && terraform init -input=false >/dev/null && echo "  re-initialised $dir" )
done
