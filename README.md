# clave

Protect proprietary functions that must run on the client, instead of on a
server. `clave` is a small, dependency-free reference implementation of a
pattern called the **Attested Split Oracle**, plus a test suite that
demonstrates why it works and why plain client-side obfuscation does not.

## The problem

Code that runs entirely on hardware the vendor does not control can be studied
freely. For a deterministic function with a samplable input space, an
independent reimplementation that reproduces the input/output behavior is
enough to copy the functionality. The cost of executing the program (a slow
VM, heavy math, bit circuits) is irrelevant, because execution cost is
orthogonal to how hard the behavior is to learn from samples. See Barak et
al., [On the (Im)possibility of Obfuscating Programs](https://www.iacr.org/archive/crypto2001/21390001.pdf).

## The pattern

Three layers, each mapping to a real [Trusted Execution Environment](https://en.wikipedia.org/wiki/Trusted_execution_environment) (TEE) feature:

| Layer | What it does | Real TEE mechanism |
|-------|--------------|--------------------|
| **Encapsulation** | The key-bearing core runs behind a boundary; the key is never readable by the host | Hardware memory isolation |
| **Attestation** | The core proves it runs the expected code before any secret is released | Signed measurement verified by the vendor backend |
| **Query budget** | The number of input/output pairs that can be collected is capped | Attested key-release policy / anti-harvesting |

The core is written as a **keyed function** whose output is indistinguishable
from random without the key. That is the crux: its behavior cannot be
generalized from observed pairs, so the only option is to memorize pairs that
were actually queried, which the budget limits.

## Quickstart

```python
from clave import Enclave, Backend, Host

enclave = Enclave(sealed_key=my_32_byte_key, max_queries=5000)
host = Host(enclave, Backend())   # raises if attestation fails
result = host.run(42)             # computes without exposing the key
```

## Run the demo

```bash
python examples/demo.py
```

Example output:

```
input space ......... 16,777,216 possible inputs
held-out test set ... 10,000 unseen inputs
query budget ........ 5,000 calls per session

A) local key in client ...... clone matches 100.0% of held-out
B) clave (enclave + budget) . clone matches 0.060% of held-out (after 5,000 queries)
   legit user with budget ... computes      100.0% of held-out

verdict: local-only leaks everything; clave keeps behavior PROTECTED
```

## Run the tests

```bash
pip install -e ".[dev]"
pytest -v
```

## Simulation vs. hardware

This repository emulates the enclave boundary in pure Python so the pattern
can be exercised and tested on any machine. The security argument is identical
to hardware; only the enforcement differs. To deploy for real, replace the
`Enclave._core` body with your proprietary logic and run it inside an actual
TEE:

- **Server / B2B:** [AWS Nitro Enclaves](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html), [Azure Confidential Computing](https://learn.microsoft.com/en-us/azure/confidential-computing/overview), [Google Confidential Space](https://cloud.google.com/confidential-computing/confidential-space/docs/confidential-space-overview)
- **Desktop:** [Open Enclave SDK](https://github.com/openenclave/openenclave), [Apache Teaclave](https://github.com/apache/incubator-teaclave-sgx-sdk)
- **Mobile:** [Apple Secure Enclave](https://developer.apple.com/documentation/cryptokit/secureenclave), [Android StrongBox / Keystore](https://developer.android.com/privacy-and-security/keystore)

## Honest limits

- The boundary protects the **core**, not the input/output at its edges. Put
  inside only the step that, when missing, turns the output into noise.
- Real TEEs have a side-channel history (for example [Foreshadow](https://foreshadowattack.eu/), [Plundervolt](https://plundervolt.com/)). Good against a competitor or a pirate, not a guarantee against a state-level effort.
- Attestation needs a vendor backend. This moves a small verification step off
  the client, not the algorithm itself.
- Pair this with legal protection (copyright, patent, contract) and
  watermarking for cases the technical layer does not cover.

## License

MIT. See [LICENSE](LICENSE).
