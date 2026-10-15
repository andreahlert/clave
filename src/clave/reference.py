"""clave.reference - vendor-only reference implementation.

Computes the expected output for a given input. It needs the key, so it lives
only on the vendor's trusted side and is never shipped to clients. The test
suite uses it to confirm the enclave produces correct results.
"""

import hashlib
import hmac


def reference_core(sealed_key: bytes, x: int) -> bytes:
    """Compute the expected output for input ``x`` (vendor side only)."""
    msg = int(x).to_bytes(16, "big", signed=False)
    return hmac.new(sealed_key, msg, hashlib.sha256).digest()[:8]
