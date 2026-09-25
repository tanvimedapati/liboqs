### EC-05 : Multiple Ciphertext Modifications

| Test | Result |
|---|---|
| Keypair generation | Success |
| Encapsulation | Success |
| First byte modification | Success |
| Middle byte modification | Success |
| Last byte modification | Success |
| Multiple byte modification | Success |
| Decapsulation | Success for all cases |
| Shared-secret comparisons | DIFFERENT for all cases |

### Key Observation

Multiple ciphertext modifications were tested by independently modifying the first byte, middle byte, last byte, and multiple bytes of the original ciphertext.

In all four cases, decapsulation returned `OQS_SUCCESS` (`0`), but the recovered shared secret differed from the original encapsulated shared secret.

The experiment therefore observed different shared-secret outputs for each of the tested ciphertext modifications.

This behavior is consistent with the implicit-rejection design used by ML-KEM, where a modified or invalid ciphertext does not necessarily produce an explicit decapsulation error.

### Validation

- Keypair generation returned `OQS_SUCCESS` (`0`).
- Encapsulation returned `OQS_SUCCESS` (`0`).
- The first byte was modified and decapsulation returned `OQS_SUCCESS` (`0`).
- A middle byte was modified and decapsulation returned `OQS_SUCCESS` (`0`).
- The last byte was modified and decapsulation returned `OQS_SUCCESS` (`0`).
- Multiple bytes were modified and decapsulation returned `OQS_SUCCESS` (`0`).
- All four recovered shared secrets were DIFFERENT from the original encapsulated shared secret.

The experiment was executed against the local liboqs build using ML-KEM-768.
