"""Vendor-side key provisioning (runs on your trusted machine, needs boto3).

Generates a random 32-byte proprietary key, encrypts it under your KMS key,
and writes the ciphertext as base64. The plaintext key is never stored. Ship
the ciphertext with your app: it is useless to anyone, because only the
attested enclave can ask KMS to decrypt it.

    pip install boto3
    python provision_key.py --key-id alias/clave --region us-east-1 \
        --out key.enc.b64
"""

import argparse
import base64
import os

import boto3


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--key-id", required=True, help="KMS key id or alias")
    ap.add_argument("--region", required=True)
    ap.add_argument("--out", default="key.enc.b64")
    args = ap.parse_args()

    plaintext = os.urandom(32)  # the proprietary key; never leaves memory here
    kms = boto3.client("kms", region_name=args.region)
    ct = kms.encrypt(KeyId=args.key_id, Plaintext=plaintext)["CiphertextBlob"]

    with open(args.out, "w") as f:
        f.write(base64.b64encode(ct).decode())
    print(f"wrote encrypted key to {args.out} ({len(ct)} bytes ciphertext)")
    print("plaintext key discarded; only the attested enclave can recover it")


if __name__ == "__main__":
    main()
