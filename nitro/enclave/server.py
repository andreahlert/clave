"""clave Nitro enclave server.

Runs INSIDE an AWS Nitro Enclave. The enclave is an isolated VM with no disk,
no interactive access, and no network: its only channel to the parent EC2
instance is a vsock socket. The proprietary key never exists on the parent;
it arrives only here, released by AWS KMS, and only because this enclave can
present a valid attestation document whose measurements (PCRs) match the KMS
key policy. The parent, the OS, and anyone with the instance cannot read it.

Protocol (newline-delimited JSON over vsock):
    {"op": "provision", "region": "...", "ciphertext_b64": "...",
     "creds": {"access_key_id": "...", "secret_access_key": "...",
               "token": "..."}}
        -> {"ok": true} once the sealed key is decrypted and cached.
    {"op": "evaluate", "x": <int>}
        -> {"y_b64": "..."}  the proprietary core output.
    {"op": "status"}
        -> {"provisioned": <bool>, "queries_used": <int>}

The key release step uses kmstool_enclave_cli, the AWS tool that attaches this
enclave's attestation document to a kms:Decrypt call and proxies it to KMS
through a vsock-proxy running on the parent.
"""

import base64
import json
import socket
import subprocess
import sys

# clave core is copied into the image at /app/clave.
sys.path.insert(0, "/app")
from clave.enclave import Enclave  # noqa: E402

VSOCK_PORT = 5005
KMSTOOL = "/app/kmstool_enclave_cli"
# Port the parent's vsock-proxy listens on, forwarding to KMS over TLS.
KMS_PROXY_PORT = 8000


class State:
    def __init__(self):
        self.enclave = None  # clave.Enclave once provisioned


def _decrypt_key_via_kms(region, ciphertext_b64, creds):
    """Return the plaintext 32-byte key, decrypted by KMS for this enclave.

    kmstool_enclave_cli builds the attestation document internally and sends
    it to KMS. KMS returns plaintext only if the key policy's
    kms:RecipientAttestation:PCRx condition matches this enclave's PCRs.
    """
    cmd = [
        KMSTOOL, "decrypt",
        "--region", region,
        "--proxy-port", str(KMS_PROXY_PORT),
        "--aws-access-key-id", creds["access_key_id"],
        "--aws-secret-access-key", creds["secret_access_key"],
        "--aws-session-token", creds["token"],
        "--ciphertext", ciphertext_b64,
    ]
    out = subprocess.check_output(cmd, text=True).strip()
    # Output looks like: "PLAINTEXT: <base64>"
    _, _, b64 = out.partition("PLAINTEXT: ")
    return base64.b64decode(b64.strip())


def handle(request, state, max_queries=5000):
    """Pure dispatch: map a request dict to a response dict.

    Kept free of socket/subprocess so it can be unit-tested off-Nitro. The
    KMS decrypt is injected via state for the same reason.
    """
    op = request.get("op")

    if op == "provision":
        key = state.decrypt(
            request["region"], request["ciphertext_b64"], request["creds"]
        )
        state.enclave = Enclave(sealed_key=key, max_queries=max_queries)
        return {"ok": True}

    if op == "status":
        enc = state.enclave
        return {
            "provisioned": enc is not None,
            "queries_used": (enc.queries_used if enc else 0),
        }

    if op == "evaluate":
        if state.enclave is None:
            return {"error": "not provisioned"}
        try:
            y = state.enclave.evaluate(int(request["x"]))
            return {"y_b64": base64.b64encode(y).decode()}
        except Exception as exc:  # RateLimitExceeded etc.
            return {"error": type(exc).__name__, "detail": str(exc)}

    return {"error": "unknown op", "op": op}


class EnclaveState(State):
    """Production state: real KMS decrypt, real enclave counter."""

    def decrypt(self, region, ciphertext_b64, creds):
        return _decrypt_key_via_kms(region, ciphertext_b64, creds)


def serve():
    state = EnclaveState()
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    s.bind((socket.VMADDR_CID_ANY, VSOCK_PORT))
    s.listen()
    print(f"clave enclave listening on vsock port {VSOCK_PORT}", flush=True)
    while True:
        conn, _ = s.accept()
        with conn:
            buf = b""
            while b"\n" not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
            if not buf:
                continue
            for line in buf.split(b"\n"):
                if not line.strip():
                    continue
                try:
                    req = json.loads(line)
                    resp = handle(req, state)
                except Exception as exc:
                    resp = {"error": "bad_request", "detail": str(exc)}
                conn.sendall((json.dumps(resp) + "\n").encode())


if __name__ == "__main__":
    serve()
