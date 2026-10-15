# clave on AWS Nitro Enclaves

Real hardware boundary for the `clave` pattern. The proprietary key lives only
inside the enclave, released by AWS KMS, and only to an enclave whose
attestation measurements (PCRs) match the KMS key policy. The parent EC2
instance, its OS, and anyone with access to the box cannot read the key.

> **Status:** this was written to AWS's documented Nitro + KMS flow and the
> protocol dispatch is tested off-hardware (`python nitro/test_local.py`). The
> vsock and KMS paths require a Nitro-enabled EC2 instance and were **not**
> executed here. Run the steps below on such an instance to validate.

## How the pieces map

| File | Runs where | Role |
|------|-----------|------|
| `enclave/server.py` | inside the enclave | holds the key, serves `evaluate()` over vsock |
| `enclave/Dockerfile` | build time | packages core + server + KMS client into the image |
| `host/client.py` | parent instance | drives the enclave, holds no key |
| `provision_key.py` | your trusted machine | encrypts the key under KMS |
| `kms-policy.json` | AWS KMS | allows decrypt only for the attested enclave |

## One-time setup

1. **Launch a Nitro-enabled instance** (for example `m5.xlarge`) with enclaves
   enabled, attach an IAM role (`clave-parent-role`), and install the tooling:

   ```bash
   sudo amazon-linux-extras install aws-nitro-enclaves-cli -y
   sudo yum install aws-nitro-enclaves-cli-devel -y
   sudo usermod -aG ne $USER && sudo usermod -aG docker $USER
   sudo systemctl enable --now nitro-enclaves-allocator.service
   ```

2. **Create a KMS key** and encrypt your proprietary key, on your trusted
   machine:

   ```bash
   python provision_key.py --key-id alias/clave --region us-east-1 --out key.enc.b64
   ```

3. **Build the enclave** and read the printed PCR0:

   ```bash
   ./build.sh
   ```

4. **Pin PCR0** into `kms-policy.json` (replace `REPLACE_WITH_PCR0_FROM_BUILD`
   and `ACCOUNT_ID`), then apply it:

   ```bash
   aws kms put-key-policy --key-id alias/clave --policy-name default \
       --policy file://kms-policy.json
   ```

## Run

```bash
./run.sh us-east-1                      # starts enclave (CID 16) + KMS vsock-proxy
python host/client.py --cid 16 --region us-east-1 \
    --ciphertext-file key.enc.b64 --x 42
```

Expected: the client prints `evaluate(42) = <hex>`, computed inside the enclave
with a key that never touched the parent.

## Why this protects what the pure-Python version cannot

- The key is decrypted **inside** the enclave by KMS, gated on the enclave's
  PCRs. Change one byte of the enclave image and PCR0 changes, so KMS refuses.
- The parent only ever forwards an encrypted blob and proxies TLS to KMS. It
  never holds plaintext.
- Callers still see inputs and outputs at the vsock edge. Put inside the
  enclave only the keyed step whose output is noise without the key, and keep
  the query budget (`max_queries`) tight.
