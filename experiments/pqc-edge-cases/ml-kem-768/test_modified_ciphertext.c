/*EC-03 : modifying ciphertext*/
/*author : tanvi medapati*/

#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    OQS_KEM *kem=OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if(kem==NULL) {
        printf("EC-03 : Failed to initialize ML-KEM-768\n");
        return 1;
    }
    uint8_t *public_key=malloc(kem->length_public_key);
    uint8_t *secret_key=malloc(kem->length_secret_key);
    uint8_t *ciphertext=malloc(kem->length_ciphertext);
    uint8_t *tampered_ciphertext=malloc(kem->length_ciphertext);
    uint8_t *shared_secret_enc=malloc(kem->length_shared_secret);
    uint8_t *shared_secret_dec=malloc(kem->length_shared_secret);
    if(public_key==NULL || secret_key==NULL || ciphertext==NULL || tampered_ciphertext==NULL || shared_secret_enc==NULL ||shared_secret_dec==NULL) {
        printf("EC-03 : Memory allocation failed\n");
        free(public_key);
        free(secret_key);
        free(ciphertext);
        free(tampered_ciphertext);
        free(shared_secret_enc);
        free(shared_secret_dec);
        OQS_KEM_free(kem);
        return 1;
    }
    int keypair_return=OQS_KEM_keypair(
        kem,
        public_key,
        secret_key
    );
    printf(
        "EC-03 keypair return : %d\n",
        keypair_return
    );
    if(keypair_return!=OQS_SUCCESS) {
        printf("EC-03 : Keypair generation failed\n");
        goto cleanup_failure;
    }
    int encaps_return=OQS_KEM_encaps(
        kem,
        ciphertext,
        shared_secret_enc,
        public_key
    );
    printf(
        "EC-03 encapsulation return : %d\n",
        encaps_return
    );
    if(encaps_return!=OQS_SUCCESS) {
        printf("EC-03 : Encapsulation failed\n");
        goto cleanup_failure;
    }
    memcpy(
        tampered_ciphertext,
        ciphertext,
        kem->length_ciphertext
    );
    tampered_ciphertext[0]^=0x01;
    printf("EC-03 ciphertext tampered : YES\n");
    int decaps_return=OQS_KEM_decaps(
        kem,
        shared_secret_dec,
        tampered_ciphertext,
        secret_key
    );
    printf(
        "EC-03 decapsulation return : %d\n",
        decaps_return
    );
    if(decaps_return==OQS_SUCCESS) {
        int secret_comparison=memcmp(
            shared_secret_enc,
            shared_secret_dec,
            kem->length_shared_secret
        );
        if(secret_comparison==0) {
            printf(
                "EC-03 shared-secret comparison : MATCH\n"
            );
        } else {
            printf(
                "EC-03 shared-secret comparison : DIFFERENT\n"
            );
        }
    } else {
        printf(
            "EC-03 shared-secret comparison : NOT PERFORMED\n"
        );
    }
    free(public_key);
    free(secret_key);
    free(ciphertext);
    free(tampered_ciphertext);
    free(shared_secret_enc);
    free(shared_secret_dec);

    OQS_KEM_free(kem);

    return 0;

cleanup_failure:

    free(public_key);
    free(secret_key);
    free(ciphertext);
    free(tampered_ciphertext);
    free(shared_secret_enc);
    free(shared_secret_dec);

    OQS_KEM_free(kem);

    return 1;
}
