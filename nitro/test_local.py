"""Off-Nitro smoke test for the enclave protocol dispatch.

Exercises handle() with a fake KMS decrypt so the request/response logic and
the proprietary core wiring can be verified on any machine. The vsock and real
KMS paths can only run on a Nitro instance and are not covered here.

Run:  PYTHONPATH=src python nitro/test_local.py
"""

import base64
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
sys.path.insert(0, os.path.join(HERE, "enclave"))

import server  # noqa: E402
from clave import reference_core  # noqa: E402

KEY = b"\x11" * 32


class FakeState(server.State):
    """Local stand-in: 'KMS' returns a fixed key without any AWS call."""
    def decrypt(self, region, ciphertext_b64, creds):
        return KEY


def check(cond, msg):
    print(("ok   " if cond else "FAIL ") + msg)
    if not cond:
        raise SystemExit(1)


def main():
    state = FakeState()

    r = server.handle({"op": "status"}, state)
    check(r == {"provisioned": False, "queries_used": 0}, "status before provision")

    r = server.handle({
        "op": "provision", "region": "us-east-1",
        "ciphertext_b64": "ignored", "creds": {},
    }, state, max_queries=3)
    check(r == {"ok": True}, "provision succeeds")

    r = server.handle({"op": "evaluate", "x": 42}, state)
    got = base64.b64decode(r["y_b64"])
    check(got == reference_core(KEY, 42), "evaluate matches reference core")

    server.handle({"op": "evaluate", "x": 1}, state)
    server.handle({"op": "evaluate", "x": 2}, state)
    r = server.handle({"op": "evaluate", "x": 3}, state)
    check(r.get("error") == "RateLimitExceeded", "budget enforced after 3 calls")

    r = server.handle({"op": "nonsense"}, state)
    check(r.get("error") == "unknown op", "unknown op rejected")

    print("\nall local enclave-protocol checks passed")


if __name__ == "__main__":
    main()
