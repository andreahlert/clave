"""Test suite for clave. Proves the three protection layers hold and that the
Attested Split Oracle pattern keeps client-side behavior from being cloned
through sampling, while an unprotected local key does not.
"""

import os
import random

import pytest

from clave import (
    Enclave,
    Backend,
    Host,
    reference_core,
    AttestationError,
    RateLimitExceeded,
)

KEY = b"\x9f" * 32
INPUT_SPACE = 1 << 24  # ~16.7M possible inputs
QUERY_BUDGET = 5_000   # how many calls the enclave allows per session
HELD_OUT = 10_000      # unseen inputs used to judge a clone, like a test set


def fresh_enclave(budget=QUERY_BUDGET):
    return Enclave(sealed_key=KEY, max_queries=budget)


# --- layer 1: correctness + key confidentiality ------------------------

def test_enclave_output_matches_reference():
    enc = fresh_enclave()
    for x in [0, 1, 42, 999999, INPUT_SPACE - 1]:
        assert enc.evaluate(x) == reference_core(KEY, x)


def test_key_not_exposed_through_public_api():
    enc = fresh_enclave()
    # No public name on the enclave yields the raw key.
    for name in dir(enc):
        if name.startswith("_"):
            continue
        value = getattr(enc, name)
        assert value != KEY
        if callable(value):
            try:
                assert value() != KEY
            except TypeError:
                pass  # method needs arguments; attest() is the only no-arg one
    # The only place the key lives is the name-mangled slot, by design.
    assert enc._Enclave__sealed_key == KEY


# --- layer 2: rate limit ------------------------------------------------

def test_rate_limit_enforced():
    enc = fresh_enclave(budget=3)
    for x in range(3):
        enc.evaluate(x)
    with pytest.raises(RateLimitExceeded):
        enc.evaluate(99)
    assert enc.queries_used == 3


# --- layer 3: attestation ----------------------------------------------

def test_host_runs_on_attested_enclave():
    enc = fresh_enclave()
    host = Host(enc, Backend())
    assert host.run(7) == reference_core(KEY, 7)


def test_host_refuses_wrong_measurement():
    enc = fresh_enclave()
    backend = Backend(expected_measurement="some-other-build")
    with pytest.raises(AttestationError):
        Host(enc, backend)


# --- the headline: sampling cannot clone the protected core ------------

def _build_lookup_clone(oracle, budget):
    """Collect up to `budget` pairs and memorize them. Best a sampler can do
    against a keyed PRF: it cannot generalize to inputs it never queried."""
    table = {}
    rng = random.Random(1)
    for _ in range(budget * 2):
        x = rng.randrange(INPUT_SPACE)
        try:
            table[x] = oracle(x)
        except RateLimitExceeded:
            break
    return lambda x: table.get(x, b"\x00" * 8)


def test_sampled_clone_fails_on_held_out_set():
    enc = fresh_enclave(budget=QUERY_BUDGET)
    clone = _build_lookup_clone(enc.evaluate, QUERY_BUDGET)

    rng = random.Random(2)
    held_out = [rng.randrange(INPUT_SPACE) for _ in range(HELD_OUT)]
    correct = sum(1 for x in held_out if clone(x) == reference_core(KEY, x))
    accuracy = correct / HELD_OUT

    # A clone built from a capped sample is right on essentially none of the
    # unseen inputs. This is the lab's 100k held-out cases, failing.
    assert accuracy < 0.001, f"clone accuracy too high: {accuracy:.4%}"


def test_legit_host_is_correct_on_held_out_set():
    # The real user, with a normal budget, computes unseen inputs correctly.
    enc = fresh_enclave(budget=HELD_OUT)
    host = Host(enc, Backend())
    rng = random.Random(3)
    held_out = [rng.randrange(INPUT_SPACE) for _ in range(HELD_OUT)]
    assert all(host.run(x) == reference_core(KEY, x) for x in held_out)


def test_unprotected_local_key_is_fully_clonable():
    """Contrast case. If the key ships inside the client binary (no enclave),
    a reimplementation reproduces every output. This is why local-only
    obfuscation does not protect behavior: the secret is on the machine."""
    embedded_key = KEY  # stands in for a key baked into a shipped artifact
    local_clone = lambda x: reference_core(embedded_key, x)

    rng = random.Random(4)
    held_out = [rng.randrange(INPUT_SPACE) for _ in range(HELD_OUT)]
    correct = sum(1 for x in held_out if local_clone(x) == reference_core(KEY, x))
    assert correct == HELD_OUT  # 100%: nothing was protected
