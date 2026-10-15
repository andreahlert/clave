"""clave.host - client-side wrapper.

Holds no secret. It can only ask the attested enclave to compute, and it
refuses to run against an enclave the backend will not vouch for.
"""

from .backend import Backend


class Host:
    """Client host that drives an attested enclave."""

    def __init__(self, enclave, backend: Backend) -> None:
        backend.require(enclave)  # raises AttestationError on mismatch
        self._enclave = enclave

    def run(self, x: int) -> bytes:
        return self._enclave.evaluate(x)
