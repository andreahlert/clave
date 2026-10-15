#!/usr/bin/env bash
# Build kmstool_enclave_cli + libnsm.so from the official AWS SDK and place
# them next to the Dockerfile. Run once on the Nitro parent instance.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"
git clone --depth 1 https://github.com/aws/aws-nitro-enclaves-sdk-c "$tmp"
cd "$tmp"
# The repo ships a container build that outputs the CLI and libnsm.
docker build --target kmstool-enclave-cli -t kmstool-enclave-cli -f containers/Dockerfile.al2 .
cid="$(docker create kmstool-enclave-cli)"
docker cp "$cid":/kmstool_enclave_cli "$here/kmstool_enclave_cli"
docker cp "$cid":/usr/lib/libnsm.so "$here/libnsm.so"
docker rm "$cid"
echo "placed kmstool_enclave_cli and libnsm.so in $here"
