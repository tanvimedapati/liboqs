# EC-04 : All-Zero Ciphertext

## Objective

Investigate the behavior of ML-KEM-768 decapsulation when provided with a ciphertext consisting entirely of zero bytes.

This experiment examines whether decapsulation returns an explicit error when processing an all-zero ciphertext.

## Experimental Setup

1. Initialize the ML-KEM-768 implementation.
2. Generate a valid key pair.
3. Allocate a ciphertext buffer.
4. Initialize every ciphertext byte to zero.
5. Attempt decapsulation using the all-zero ciphertext and generated secret key.
6. Record the decapsulation return value.

## Implementation

The ciphertext was allocated using `calloc`:

```c
zero_ciphertext=calloc(kem->length_ciphertext,1);
```

`calloc` initializes the allocated memory to zero, so every byte in the ciphertext is set to `0x00`.

## Results

| Operation | Result |
|---|---|
| Keypair generation | Success (`0`) |
| Ciphertext construction | All bytes set to zero |
| Decapsulation | Success (`0`) |
| Decapsulation result | `OQS_SUCCESS` |

## Observed Output

```text
EC-04 keypair return : 0
EC-04 ciphertext type : ALL ZERO BYTES
EC-04 decapsulation return : 0
EC-04 decapsulation result : SUCCESS
```

## Observation

Decapsulation returned `OQS_SUCCESS` (`0`) when supplied with the all-zero ciphertext.

However, the experiment did not perform encapsulation or compare the resulting shared secret against a legitimate encapsulated shared secret.

Therefore, the return code alone does not establish that the ciphertext was cryptographically valid or that a legitimate shared secret was recovered.

## Interpretation

The experiment demonstrates that the tested all-zero ciphertext did not cause an explicit decapsulation error in this execution.

This behavior is consistent with ML-KEM's implicit-rejection design, where malformed or invalid ciphertexts do not necessarily result in an explicit API failure.

The result is limited to the tested input and execution environment. It does not establish the complete validity, security, or robustness of the implementation.

## Limitations

- No valid encapsulation reference was generated.
- The recovered shared secret was not compared with an encapsulated shared secret.
- Only one all-zero ciphertext input was tested.
- The experiment does not constitute a complete security audit.

## Validation

- ML-KEM-768 initialization completed successfully.
- Keypair generation returned `OQS_SUCCESS` (`0`).
- An all-zero ciphertext was constructed.
- Decapsulation returned `OQS_SUCCESS` (`0`).
- No conclusion was made about legitimate shared-secret recovery.
