# ML-DSA-65 Edge Case Investigation

## Overview

This document records a series of functional and edge-case experiments performed against the local liboqs build using ML-DSA-65.

The purpose of the investigation is to observe how the ML-DSA-65 implementation behaves under:

- Normal signing and verification
- Modified messages
- Modified signatures
- Incorrect public keys
- Empty messages
- Repeated signing of the same message
- Minimal non-empty messages
- Large messages

These experiments are functional investigations and do not constitute a cryptographic security proof.

---

## ML-DSA-65

ML-DSA (Module-Lattice-Based Digital Signature Algorithm) is a post-quantum digital signature algorithm standardized by NIST.

A digital signature provides:

- Authentication of the signer
- Integrity of the signed message
- Verification using a public key

The basic operation is:

```text
Message + Secret Key
        |
        v
      Sign
        |
        v
    Signature
```

The verifier then uses:

```text
Message + Signature + Public Key
              |
              v
           Verify
              |
              v
       VALID / INVALID
```

---

# SD-01: Valid Signature

## Purpose

Establish a baseline for normal ML-DSA-65 operation.

## Procedure

1. Generate an ML-DSA-65 key pair.
2. Generate a test message.
3. Sign the message using the secret key.
4. Verify the signature using the public key.
5. Check the verification result.

## Result

| Operation              | Result  |
| ---------------------- | ------- |
| Keypair generation     | Success |
| Signing                | Success |
| Verification           | Success |
| Signature verification | VALID   |

## Observation

A normally generated ML-DSA-65 signature successfully verifies against the original message and corresponding public key.

## Validation

Key generation and signing returned `OQS_SUCCESS` (`0`).

Signature verification also returned `OQS_SUCCESS` (`0`).

---

# SD-02: Modified Message

## Purpose

Determine whether verification detects modification of the signed message.

## Procedure

1. Generate an ML-DSA-65 key pair.
2. Sign the original message.
3. Modify the message after signing.
4. Attempt verification using the modified message and original signature.

## Result

| Operation                     | Result  |
| ----------------------------- | ------- |
| Keypair generation            | Success |
| Signing                       | Success |
| Message modification          | Yes     |
| Verification                  | Failure |
| Modified message verification | INVALID |

## Key Observation

The message was modified after the signature was generated.

Verification returned `-1`, indicating that the modified message did not verify against the original signature and public key.

## Validation

* Keypair generation returned `OQS_SUCCESS` (`0`).
* Signing returned `OQS_SUCCESS` (`0`).
* The message was modified after signing.
* Verification returned `-1`.
* The modified message was reported as `INVALID`.

---

# SD-03: Modified Signature

## Purpose

Determine whether verification detects modification of an otherwise valid signature.

## Procedure

1. Generate an ML-DSA-65 key pair.
2. Sign a message.
3. Modify one bit of the generated signature.
4. Verify the modified signature against the original message and public key.

## Result

| Operation                       | Result           |
| -------------------------------- | ---------------- |
| Keypair generation              | Success          |
| Signing                         | Success          |
| Signature modification          | One bit modified |
| Verification                    | Failure          |
| Modified signature verification | INVALID          |

## Key Observation

A single bit of the signature was modified before verification.

Verification returned `-1`, and the modified signature was reported as `INVALID`.

## Validation

* Keypair generation returned `OQS_SUCCESS` (`0`).
* Signing returned `OQS_SUCCESS` (`0`).
* One bit of the signature was modified.
* Verification returned `-1`.
* The modified signature was reported as `INVALID`.

---

# SD-04: Wrong Public Key

## Purpose

Determine whether a valid signature can be verified using an unrelated public key.

## Procedure

1. Generate key pair A.
2. Generate an independent key pair B.
3. Sign the message using the secret key from key pair A.
4. Attempt verification using the public key from key pair B.

## Result

| Operation                       | Result  |
| -------------------------------- | ------- |
| Keypair A generation            | Success |
| Keypair B generation            | Success |
| Signing with secret key A       | Success |
| Verification using public key B | Failure |
| Verification result             | INVALID |

## Key Observation

The signature was generated using secret key A but verification was performed using the unrelated public key B.

Verification returned `-1`.

This demonstrates that the signature is associated with the corresponding key pair rather than being valid under an arbitrary ML-DSA-65 public key.

## Validation

* Key pair A generation returned `OQS_SUCCESS` (`0`).
* Key pair B generation returned `OQS_SUCCESS` (`0`).
* Signing with secret key A returned `OQS_SUCCESS` (`0`).
* Verification using public key B returned `-1`.
* The verification result was `INVALID`.

---

# SD-05: Empty Message

## Purpose

Test ML-DSA-65 signing and verification with a zero-length message.

## Procedure

1. Generate an ML-DSA-65 key pair.
2. Use a message with length `0`.
3. Sign the empty message.
4. Verify the resulting signature against the same empty message.

## Result

| Operation                  | Result  |
| --------------------------- | ------- |
| Keypair generation         | Success |
| Signing                    | Success |
| Message length             | 0 bytes |
| Verification               | Success |
| Empty message verification | VALID   |

## Key Observation

An empty message was successfully signed and verified.

## Validation

* Keypair generation returned `OQS_SUCCESS` (`0`).
* Signing returned `OQS_SUCCESS` (`0`).
* The message length was `0` bytes.
* Verification returned `OQS_SUCCESS` (`0`).
* The empty message verification result was `VALID`.

---

# SD-06: Repeated Signing

## Purpose

Determine whether repeatedly signing the same message with the same secret key produces identical signatures.

## Procedure

1. Generate one ML-DSA-65 key pair.
2. Use the same message for both signing operations.
3. Sign the message twice using the same secret key.
4. Compare the two signatures.
5. Verify both signatures independently.

## Result

| Test                      | Result    |
| -------------------------- | --------- |
| Keypair generation        | Success   |
| Signing 1                 | Success   |
| Signing 2                 | Success   |
| Signature comparison      | DIFFERENT |
| Signature 1 verification  | VALID     |
| Signature 2 verification  | VALID     |

## Key Observation

The same message was signed twice using the same secret key.

The two generated signatures were different, but both signatures successfully verified using the corresponding public key.

This behavior is consistent with randomized signing, where fresh randomness can cause separate signing operations to produce different valid signatures.

## Validation

* Keypair generation returned `OQS_SUCCESS` (`0`).
* Both signing operations returned `OQS_SUCCESS` (`0`).
* The two signatures were different.
* Signature 1 verification was `VALID`.
* Signature 2 verification was `VALID`.

---

# SD-07: One-Byte Message

## Purpose

Test signing and verification using the smallest non-empty message.

## Procedure

1. Generate an ML-DSA-65 key pair.
2. Create a one-byte message containing `0x00`.
3. Sign the message.
4. Verify the signature against the same one-byte message.

## Result

| Operation                      | Result  |
| -------------------------------- | ------- |
| Keypair generation             | Success |
| Signing                        | Success |
| Message length                 | 1 byte  |
| Verification                   | Success |
| One-byte message verification  | VALID   |

## Key Observation

A one-byte message was successfully signed and verified.

This provides a boundary test immediately above the zero-length message tested in SD-05.

## Validation

* Keypair generation returned `OQS_SUCCESS` (`0`).
* Signing returned `OQS_SUCCESS` (`0`).
* The message length was `1` byte.
* Verification returned `OQS_SUCCESS` (`0`).
* The one-byte message verification result was `VALID`.

---

# SD-08: Large Message

## Purpose

Test ML-DSA-65 signing and verification with a substantially larger message.

## Procedure

1. Generate an ML-DSA-65 key pair.
2. Create a `1 MiB` message.
3. Fill the message with deterministic test data.
4. Sign the complete message.
5. Verify the resulting signature against the same message.

## Result

| Operation                   | Result           |
| ----------------------------- | ---------------- |
| Keypair generation          | Success          |
| Signing                     | Success          |
| Message length              | 1,048,576 bytes  |
| Verification                | Success          |
| Large message verification  | VALID            |

## Key Observation

A 1 MiB message was successfully signed and verified using ML-DSA-65.

## Validation

* Keypair generation returned `OQS_SUCCESS` (`0`).
* Signing returned `OQS_SUCCESS` (`0`).
* The message length was `1,048,576` bytes.
* Verification returned `OQS_SUCCESS` (`0`).
* The large message verification result was `VALID`.

---

# Consolidated Results

| Test  | Scenario           | Result                 |
| ----- | ------------------- | ----------------------- |
| SD-01 | Valid signature     | VALID                   |
| SD-02 | Modified message    | INVALID                 |
| SD-03 | Modified signature  | INVALID                 |
| SD-04 | Wrong public key    | INVALID                 |
| SD-05 | Empty message       | VALID                   |
| SD-06 | Repeated signing    | DIFFERENT, both VALID   |
| SD-07 | One-byte message    | VALID                   |
| SD-08 | 1 MiB message        | VALID                   |

---

# Overall Observations

The experiments demonstrated the following observed behavior for the tested ML-DSA-65 implementation:

1. Normal signatures successfully verify.
2. Modifying the signed message causes verification to fail.
3. Modifying the signature causes verification to fail.
4. A signature generated using one secret key does not verify using an unrelated public key.
5. An empty message can be successfully signed and verified.
6. Repeated signing of the same message using the same secret key produced different signatures in the tested executions, while both signatures remained valid.
7. A one-byte message can be successfully signed and verified.
8. A 1 MiB message can be successfully signed and verified.

These results provide functional evidence of expected behavior across normal, negative, boundary, repeated-operation, and larger-input cases.

---

# Limitations

These experiments are functional edge-case investigations.

They do not constitute:

* A formal security proof
* A cryptanalysis of ML-DSA
* A proof of resistance against all attacks
* A complete test of every possible input size
* A complete test of every internal implementation path
* A replacement for the official liboqs test suite

The results describe the behavior observed from the local liboqs build used for these experiments.

---

# Environment

Algorithm:

```text
ML-DSA-65
```

Library:

```text
liboqs
```

The experiments were executed against the local liboqs build.

Each experiment used the public liboqs signature API through:

```c
#include <oqs/oqs.h>
```

The primary operations used were:

```c
OQS_SIG_new()
OQS_SIG_keypair()
OQS_SIG_sign()
OQS_SIG_verify()
OQS_SIG_free()
OQS_init()
OQS_destroy()
```

Return code:

```text
OQS_SUCCESS = 0
```

Verification failures in the negative tests returned:

```text
-1
```
