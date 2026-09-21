
# EC-03 : Modified Ciphertext

## Objective

Investigate the behavior of ML-KEM-768 decapsulation when the ciphertext is modified before decapsulation.

This experiment simulates ciphertext tampering by flipping one bit in a copied ciphertext.

## Experimental Setup

1. Generate an ML-KEM-768 key pair.
2. Encapsulate using the generated public key.
3. Copy the original ciphertext.
4. Modify the first byte of the copied ciphertext by flipping one bit.
5. Decapsulate the modified ciphertext using the original secret key.
6. Compare the recovered shared secret with the original encapsulated shared secret.

## Implementation

The ciphertext was modified using:

```c
tampered_ciphertext[0]^=0x01;
```

This flips one bit in the first byte while preserving the original ciphertext for reference.

## Results

| Operation | Result |
|---|---|
| Keypair generation | Success (`0`) |
| Encapsulation | Success (`0`) |
| Ciphertext modification | Completed |
| Decapsulation of modified ciphertext | Success (`0`) |
| Shared-secret comparison | DIFFERENT |

## Observed Output

```text
EC-03 keypair return : 0
EC-03 encapsulation return : 0
EC-03 ciphertext tampered : YES
EC-03 decapsulation return : 0
EC-03 shared-secret comparison : DIFFERENT
```

## Observation

Decapsulation returned `OQS_SUCCESS` even though the ciphertext had been modified.

However, the recovered shared secret differed from the original encapsulated shared secret.

This behavior is consistent with the implicit-rejection design used by ML-KEM, where an invalid ciphertext does not necessarily produce an explicit decapsulation error.

## Interpretation

The experiment demonstrates that modifying a ciphertext can result in a different recovered shared secret while decapsulation still returns success.

The result is specific to the tested ciphertext modification and does not, by itself, establish the complete security or robustness of the liboqs implementation.

Further testing with different malformed ciphertexts and additional validation would be required for broader conclusions.

## Validation

- ML-KEM-768 keypair generation completed successfully.
- Original encapsulation completed successfully.
- One bit of the ciphertext was modified.
- Decapsulation returned `OQS_SUCCESS`.
- The original and recovered shared secrets were different.
