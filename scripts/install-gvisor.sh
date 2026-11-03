#!/usr/bin/env bash
# Install gVisor (runsc) from its signed apt repository and register it with Docker.
# Debian/Ubuntu; needs sudo.
#
# The repository signing key is checked against a pinned fingerprint before apt trusts it,
# so a swapped key on the download server stops the install instead of slipping through.
# Fingerprint source: website/archive.key in github.com/google/gvisor (The gVisor Authors).
set -euo pipefail
GVISOR_KEY_FPR="6F1DF85E3A71C24918E727D56FC6D554E32BD943"

if docker info --format '{{json .Runtimes}}' 2>/dev/null | grep -q '"runsc"'; then
  echo "runsc already registered"; exit 0
fi
sudo apt-get update -qq
sudo apt-get install -y -qq apt-transport-https ca-certificates curl gnupg >/dev/null

key="$(mktemp)"
trap 'rm -f "$key"' EXIT
curl -fsSL https://gvisor.dev/archive.key -o "$key"
got="$(gpg --show-keys --with-colons "$key" 2>/dev/null | awk -F: '$1=="fpr"{print $10; exit}')"
if [ "$got" != "$GVISOR_KEY_FPR" ]; then
  echo "gVisor signing key fingerprint mismatch: expected $GVISOR_KEY_FPR, got ${got:-none}" >&2
  exit 1
fi
sudo gpg --batch --yes --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg "$key"

echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" \
  | sudo tee /etc/apt/sources.list.d/gvisor.list >/dev/null
sudo apt-get update -qq
sudo apt-get install -y -qq runsc >/dev/null
sudo runsc install
sudo systemctl restart docker
docker info --format '{{json .Runtimes}}' | grep -q '"runsc"'
echo "registered: $(runsc --version | head -1) (key $GVISOR_KEY_FPR verified)"
