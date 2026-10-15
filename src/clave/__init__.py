"""clave - protect proprietary functions that must run on the client.

Pattern: Attested Split Oracle.

Keep the key-bearing core inside a TEE boundary, and gate it with attestation
plus a query budget. The core is a keyed function whose output is
indistinguishable from random without the key, so its behavior cannot be
generalized from observed input/output pairs. The query budget caps how many
pairs can be collected at all. Together this keeps the client-side behavior
protected even though it executes on hardware the vendor does not control.

Public API:
    Enclave, Backend, Host, reference_core
    ENCLAVE_MEASUREMENT, AttestationError, RateLimitExceeded
"""

from .enclave import (
    Enclave,
    ENCLAVE_MEASUREMENT,
    AttestationError,
    RateLimitExceeded,
)
from .backend import Backend
from .host import Host
from .reference import reference_core

__all__ = [
    "Enclave",
    "Backend",
    "Host",
    "reference_core",
    "ENCLAVE_MEASUREMENT",
    "AttestationError",
    "RateLimitExceeded",
]

__version__ = "0.1.0"
