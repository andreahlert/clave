"""clave Nitro host client.

Runs on the parent EC2 instance (untrusted side). It holds NO plaintext key.
It reads the instance role credentials and the KMS-encrypted key blob, hands
them to the enclave over vsock so the enclave can ask KMS to decrypt, then
drives evaluate() calls. The parent never sees the plaintext key, because KMS
only releases it to the attested enclave.

Usage:
    python client.py --cid <enclave_cid> --region us-east-1 \
        --ciphertext-file key.enc.b64 [--x 42]

Find the enclave CID with:  nitro-cli describe-enclaves
"""

import argparse
import base64
import json
import socket

VSOCK_PORT = 5005


def _rpc(cid, request):
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    s.connect((cid, VSOCK_PORT))
    s.sendall((json.dumps(request) + "\n").encode())
    buf = b""
    while b"\n" not in buf:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
    s.close()
    return json.loads(buf.split(b"\n")[0])


def _instance_creds():
    """Fetch the parent instance role credentials via IMDSv2."""
    import urllib.request

    def imds(path, headers=None, method="GET"):
        req = urllib.request.Request(
            "http://169.254.169.254" + path, headers=headers or {}, method=method
        )
        return urllib.request.urlopen(req, timeout=2).read().decode()

    token = imds(
        "/latest/api/token",
        {"X-aws-ec2-metadata-token-ttl-seconds": "60"},
        method="PUT",
    )
    h = {"X-aws-ec2-metadata-token": token}
    role = imds("/latest/meta-data/iam/security-credentials/", h)
    doc = json.loads(imds("/latest/meta-data/iam/security-credentials/" + role, h))
    return {
        "access_key_id": doc["AccessKeyId"],
        "secret_access_key": doc["SecretAccessKey"],
        "token": doc["Token"],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cid", type=int, required=True, help="enclave CID")
    ap.add_argument("--region", required=True)
    ap.add_argument("--ciphertext-file", required=True,
                    help="file with the base64 KMS-encrypted 32-byte key")
    ap.add_argument("--x", type=int, default=42)
    args = ap.parse_args()

    ciphertext_b64 = open(args.ciphertext_file).read().strip()

    prov = _rpc(args.cid, {
        "op": "provision",
        "region": args.region,
        "ciphertext_b64": ciphertext_b64,
        "creds": _instance_creds(),
    })
    print("provision:", prov)

    out = _rpc(args.cid, {"op": "evaluate", "x": args.x})
    if "y_b64" in out:
        print(f"evaluate({args.x}) =", base64.b64decode(out["y_b64"]).hex())
    else:
        print("evaluate error:", out)


if __name__ == "__main__":
    main()
