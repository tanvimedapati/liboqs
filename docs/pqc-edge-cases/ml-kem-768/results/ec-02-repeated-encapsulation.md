# EC-02 : Repeated Encapsulation Using the Same Public Key

## Objective

Verify ML-KEM-768 behavior when encapsulation is performed
multiple times using the same public key.

## Experiment File

experiments/pqc-edge-cases/ml-kem-768/test_repeated_encapsulation.c

## Procedure

1. Initialize the liboqs library.
2. Create an ML-KEM-768 KEM object.
3. Generate one public key and secret key pair.
4. Perform encapsulation twice using the same public key.
5. Decapsulate both ciphertexts using the same secret key.
6. Compare the ciphertexts and encapsulated shared secrets.
7. Compare each encapsulated secret with its corresponding
   decapsulated secret.

## Observed Output

EC-02 keypair return : 0
EC-02 encapsulation 1 return : 0
EC-02 encapsulation 2 return : 0
EC-02 decapsulation 1 return : 0
EC-02 decapsulation 2 return : 0
EC-02 ciphertexts : DIFFERENT
EC-02 encapsulated secrets : DIFFERENT
EC-02 secret 1 comparison : MATCH
EC-02 secret 2 comparison : MATCH

## Results

| Operation | Result |
|---|---|
| Keypair generation | Success |
| First encapsulation | Success |
| Second encapsulation | Success |
| First decapsulation | Success |
| Second decapsulation | Success |
| Ciphertext comparison | DIFFERENT |
| Encapsulated secret comparison | DIFFERENT |
| First shared-secret comparison | MATCH |
| Second shared-secret comparison | MATCH |

## Conclusion

Repeated encapsulation using the same public key completed
successfully.

The two encapsulations produced different ciphertexts and
different shared secrets. Each ciphertext was successfully
decapsulated, and both corresponding shared-secret comparisons
returned MATCH.

This behavior is consistent with randomized encapsulation.

## Integration Relevance

This experiment establishes that repeated encapsulation with
the same public key produces independently generated
ciphertexts and shared secrets while maintaining correct
decapsulation behavior.
