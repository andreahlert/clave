"""Side-by-side demonstration.

Scenario A: the key ships inside the client artifact (local-only, the usual
obfuscation setting). A reimplementation reproduces every output.

Scenario B: the key stays in the enclave, gated by attestation and a query
budget (the clave pattern). A reimplementation built from a capped sample is
correct on almost none of the held-out inputs.

Run: python examples/demo.py
"""

import random
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from clave import Enclave, Backend, Host, reference_core, RateLimitExceeded

KEY = os.urandom(32)
INPUT_SPACE = 1 << 24
QUERY_BUDGET = 5_000
HELD_OUT = 10_000


def held_out_inputs(seed):
    rng = random.Random(seed)
    return [rng.randrange(INPUT_SPACE) for _ in range(HELD_OUT)]


def scenario_a_local_key():
    # Key baked into the shipped client: fully readable on the machine.
    embedded_key = KEY
    clone = lambda x: reference_core(embedded_key, x)
    tests = held_out_inputs(seed=100)
    hits = sum(1 for x in tests if clone(x) == reference_core(KEY, x))
    return hits / len(tests)


def scenario_b_clave():
    enc = Enclave(sealed_key=KEY, max_queries=QUERY_BUDGET)
    # Sampling clone: query within the budget, memorize, guess for the rest.
    table = {}
    rng = random.Random(200)
    while True:
        x = rng.randrange(INPUT_SPACE)
        try:
            table[x] = enc.evaluate(x)
        except RateLimitExceeded:
            break
    clone = lambda x: table.get(x, b"\x00" * 8)
    tests = held_out_inputs(seed=300)
    hits = sum(1 for x in tests if clone(x) == reference_core(KEY, x))
    return hits / len(tests), enc.queries_used


def legit_use():
    enc = Enclave(sealed_key=KEY, max_queries=HELD_OUT)
    host = Host(enc, Backend())
    tests = held_out_inputs(seed=300)
    hits = sum(1 for x in tests if host.run(x) == reference_core(KEY, x))
    return hits / len(tests)


if __name__ == "__main__":
    a = scenario_a_local_key()
    b_acc, b_queries = scenario_b_clave()
    legit = legit_use()

    print(f"input space ......... {INPUT_SPACE:,} possible inputs")
    print(f"held-out test set ... {HELD_OUT:,} unseen inputs")
    print(f"query budget ........ {QUERY_BUDGET:,} calls per session")
    print()
    print(f"A) local key in client ...... clone matches {a:.1%} of held-out")
    print(f"B) clave (enclave + budget) . clone matches {b_acc:.3%} of held-out "
          f"(after {b_queries:,} queries)")
    print(f"   legit user with budget ... computes      {legit:.1%} of held-out")
    print()
    verdict = "PROTECTED" if (b_acc < 0.01 and a > 0.99) else "CHECK"
    print(f"verdict: local-only leaks everything; clave keeps behavior {verdict}")
