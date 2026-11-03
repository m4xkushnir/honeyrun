#!/usr/bin/env bash
# Install gVisor (runsc) and register it with Docker. Linux only; needs sudo.
set -euo pipefail
if docker info --format '{{json .Runtimes}}' 2>/dev/null | grep -q '"runsc"'; then
  echo "runsc already registered"; exit 0
fi
url="https://storage.googleapis.com/gvisor/releases/release/latest/$(uname -m)"
dir="$(mktemp -d)"; cd "$dir"
curl -fsSLO "$url/runsc" -fsSLO "$url/runsc.sha512" \
     -fsSLO "$url/containerd-shim-runsc-v1" -fsSLO "$url/containerd-shim-runsc-v1.sha512"
sha512sum -c runsc.sha512 -c containerd-shim-runsc-v1.sha512
chmod a+rx runsc containerd-shim-runsc-v1
sudo mv runsc containerd-shim-runsc-v1 /usr/local/bin/
sudo /usr/local/bin/runsc install
sudo systemctl restart docker
docker info --format '{{json .Runtimes}}' | grep -q '"runsc"'
echo "runsc $(runsc --version | head -1) registered"
