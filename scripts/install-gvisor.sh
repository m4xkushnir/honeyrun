#!/usr/bin/env bash
# Install gVisor (runsc) from its signed apt repository and register it with Docker.
# Debian/Ubuntu; needs sudo.
set -euo pipefail
if docker info --format '{{json .Runtimes}}' 2>/dev/null | grep -q '"runsc"'; then
  echo "runsc already registered"; exit 0
fi
sudo apt-get update -qq
sudo apt-get install -y -qq apt-transport-https ca-certificates curl gnupg >/dev/null
curl -fsSL https://gvisor.dev/archive.key | sudo gpg --batch --yes --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" \
  | sudo tee /etc/apt/sources.list.d/gvisor.list >/dev/null
sudo apt-get update -qq
sudo apt-get install -y -qq runsc >/dev/null
sudo runsc install
sudo systemctl restart docker
docker info --format '{{json .Runtimes}}' | grep -q '"runsc"'
echo "registered: $(runsc --version | head -1)"
