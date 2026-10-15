"""
clave.enclave - simulated Trusted Execution Environment (TEE).

In a real deployment the sealed key lives in hardware-protected memory
(Intel TDX / SGX, ARM TrustZone, AMD SEV-SNP, AWS Nitro Enclaves, Apple
Secure Enclave) and is NEVER readable by the host process, the OS, a
debugger, or a memory dump. This module emulates that boundary in pure
Python so the architectural pattern can be exercised and tested on any
machine. The security argument is identical to hardware; only the
enforcement mechanism differs (a software convention here, silicon there).

What hardware gives you that this simulation only documents:
  * confidentiality of the sealed key under full host compromise
  * integrity of the enclave code (measurement signed by a fused key)
  * side-channel resistance (partial; TEEs have a real attack history)
"""

import hashlib
import hmac


class AttestationError(Exception):
    """Raised when an enclave cannot prove it runs the expected code."""


class RateLimitExceeded(Exception):
    """Raised when the per-session query budget is exhausted."""


# Measurement of the enclave code. In real TEEs the hardware computes this
# over the loaded enclave image. The vendor backend knows the expected value
# and refuses to release the key wrapping material to any other measurement.
ENCLAVE_MEASUREMENT = "clave-core-v1"


class Enclave:
    """A protected compute unit holding a sealed secret.

    The host may call :meth:`evaluate` but has no API to read the key.
    Protection rests on three layers, each mapping to a real TEE feature:

      1. encapsulation  -> hardware memory isolation of the sealed key
      2. rate limiting  -> anti-harvesting / attested key-release policy
      3. attestation    -> remote verification of the enclave measurement
    """

    def __init__(self, sealed_key: bytes, max_queries: int) -> None:
        if len(sealed_key) < 16:
            raise ValueError("sealed_key must be at least 16 bytes")
        # Name-mangled + never returned by any method. Stands in for memory
        # that hardware keeps off-limits to the host.
        self.__sealed_key = sealed_key
        self._max_queries = int(max_queries)
        self._queries = 0

    # --- attestation -----------------------------------------------------
    def attest(self) -> str:
        """Return the code measurement the backend will verify.

        Real TEE: hardware signs (measurement, nonce) with a sealed
        attestation key; the backend checks the signature before releasing
        any secret. Here we expose the measurement string the backend
        compares against its expected value.
        """
        return ENCLAVE_MEASUREMENT

    # --- protected compute ----------------------------------------------
    def evaluate(self, x: int) -> bytes:
        """Run the proprietary core on ``x`` and return its output.

        Enforces the query budget. The only thing an attacker observes is
        the (input, output) pair, never the key or the code path.
        """
        if self._queries >= self._max_queries:
            raise RateLimitExceeded(
                f"query budget of {self._max_queries} exhausted"
            )
        self._queries += 1
        return self._core(x)

    @property
    def queries_used(self) -> int:
        return self._queries

    # --- the secret ------------------------------------------------------
    def _core(self, x: int) -> bytes:
        """The proprietary function.

        Implemented as a keyed pseudo-random function (HMAC-SHA256). Under
        the standard PRF assumption its output is indistinguishable from
        random to anyone without the key, so it CANNOT be generalized from
        input/output samples. An attacker can only memorize pairs it has
        actually observed, which the rate limit caps.

        Replace this body with your real proprietary logic; keep it keyed by
        the sealed secret so that the behavior is unlearnable without the key.
        """
        msg = int(x).to_bytes(16, "big", signed=False)
        return hmac.new(self.__sealed_key, msg, hashlib.sha256).digest()[:8]
