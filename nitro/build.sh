#!/usr/bin/env bash
# Build the enclave image (.eif) from the Docker image and print the PCRs.
# PCR0 is the measurement you pin in the KMS key policy.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"

# Make the clave core available to the Docker build context.
rm -rf "$here/enclave/clave"
cp -r "$here/../src/clave" "$here/enclave/clave"

cd "$here/enclave"
[ -f kmstool_enclave_cli ] || ./fetch_kmstool.sh

docker build -t clave-enclave .
nitro-cli build-enclave --docker-uri clave-enclave:latest \
    --output-file "$here/clave.eif"
echo "built $here/clave.eif"
echo "Pin the PCR0 printed above in kms-policy.json."
