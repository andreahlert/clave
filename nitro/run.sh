#!/usr/bin/env bash
# Launch the enclave and the KMS vsock-proxy on the parent instance.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
REGION="${1:-us-east-1}"

# Allow KMS traffic from the enclave out to the region endpoint.
vsock-proxy 8000 "kms.${REGION}.amazonaws.com" 443 &
echo "vsock-proxy -> kms.${REGION}.amazonaws.com:443 on vsock port 8000"

nitro-cli run-enclave \
    --eif-path "$here/clave.eif" \
    --cpu-count 2 --memory 512 \
    --enclave-cid 16
nitro-cli describe-enclaves
echo "enclave running on CID 16"
