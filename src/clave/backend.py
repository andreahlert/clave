"""clave.backend - vendor-side authorization gate.

The key is never shipped with the software. The backend authorizes use only
for an enclave that proves, by attestation, that it runs the expected code.
The secret stays bound to a verified enclave rather than to the surrounding
host, which is what lets execution remain on the client safely.
"""

from .enclave import ENCLAVE_MEASUREMENT, AttestationError


class Backend:
    """Vendor backend that authorizes enclaves by measurement."""

    def __init__(self, expected_measurement: str = ENCLAVE_MEASUREMENT) -> None:
        self._expected = expected_measurement

    def authorize(self, enclave) -> bool:
        """Return True iff the enclave attests to the expected measurement."""
        try:
            return enclave.attest() == self._expected
        except Exception:
            return False

    def require(self, enclave) -> None:
        """Raise unless the enclave attests correctly."""
        if not self.authorize(enclave):
            raise AttestationError(
                "enclave failed attestation; refusing to authorize"
            )
