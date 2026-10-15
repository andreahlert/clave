# clave enclave image. Built into an Enclave Image File (.eif) by nitro-cli.
#
# kmstool_enclave_cli is AWS's tool that attaches this enclave's attestation
# document to a kms:Decrypt call. Build it once from the official SDK and drop
# the binary next to this Dockerfile (see fetch_kmstool.sh), then build here.
FROM amazonlinux:2

RUN amazon-linux-extras install -y python3.8 && \
    yum install -y python3 && yum clean all

WORKDIR /app

# Proprietary core + enclave server.
COPY clave/ /app/clave/
COPY server.py /app/server.py

# AWS KMS attestation client (produced by fetch_kmstool.sh).
COPY kmstool_enclave_cli /app/kmstool_enclave_cli
COPY libnsm.so /usr/lib64/libnsm.so
RUN chmod +x /app/kmstool_enclave_cli

CMD ["python3", "/app/server.py"]
