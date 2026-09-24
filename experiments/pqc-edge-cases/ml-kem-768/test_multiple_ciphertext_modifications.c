/*EC-05 : modify ciphertext multiple times*/
/*author : tanvi medapati*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>

int main(void) {
    OQS_KEM *kem=OQS_KEM_new(OQS_KEM_alg_ml_kem_768);

    if (kem==NULL) {
        printf("EC-05 : Failed to initialize ML-KEM-768\n");
        return 1;
    }

    uint8_t *public_key=malloc(kem->length_public_key);
    uint8_t *secret_key=malloc(kem->length_secret_key);

    uint8_t *ciphertext=malloc(kem->length_ciphertext);
    uint8_t *modified_ciphertext=malloc(kem->length_ciphertext);

    uint8_t *shared_secret_enc=malloc(kem->length_shared_secret);
    uint8_t *shared_secret_dec=malloc(kem->length_shared_secret);

    if (public_key==NULL || secret_key==NULL ||
        ciphertext==NULL || modified_ciphertext==NULL ||
        shared_secret_enc==NULL || shared_secret_dec==NULL) {
        printf("EC-05 : Memory allocation failed\n");

        free(public_key);
        free(secret_key);
        free(ciphertext);
        free(modified_ciphertext);
        free(shared_secret_enc);
        free(shared_secret_dec);
        OQS_KEM_free(kem);

        return 1;
    }

    OQS_STATUS rc;

    rc=OQS_KEM_keypair(kem,public_key,secret_key);
    printf("EC-05 keypair return : %d\n",rc);

    if (rc!=OQS_SUCCESS) {
        goto cleanup;
    }

    rc=OQS_KEM_encaps(kem,ciphertext,shared_secret_enc,public_key);
    printf("EC-05 encapsulation return : %d\n",rc);

    if (rc!=OQS_SUCCESS) {
        goto cleanup;
    }

    /*test 1 : Modify the first byte.*/
    memcpy(modified_ciphertext,ciphertext,kem->length_ciphertext);
    modified_ciphertext[0]^=0x01;

    rc=OQS_KEM_decaps(
        kem,
        shared_secret_dec,
        modified_ciphertext,
        secret_key
    );

    printf("EC-05 modification 1 : FIRST BYTE\n");
    printf("EC-05 decapsulation 1 return : %d\n",rc);

    if (rc==OQS_SUCCESS) {
        printf(
            "EC-05 secret comparison 1 : %s\n",
            memcmp(
                shared_secret_enc,
                shared_secret_dec,
                kem->length_shared_secret
            )==0 ? "MATCH" : "DIFFERENT"
        );
    }

    /*Test 2 : Modify a byte in the middle.*/
    memcpy(modified_ciphertext,ciphertext,kem->length_ciphertext);
    modified_ciphertext[kem->length_ciphertext/2]^=0x01;

    rc=OQS_KEM_decaps(
        kem,
        shared_secret_dec,
        modified_ciphertext,
        secret_key
    );

    printf("EC-05 modification 2 : MIDDLE BYTE\n");
    printf("EC-05 decapsulation 2 return : %d\n",rc);

    if (rc==OQS_SUCCESS) {
        printf(
            "EC-05 secret comparison 2 : %s\n",
            memcmp(
                shared_secret_enc,
                shared_secret_dec,
                kem->length_shared_secret
            )==0 ? "MATCH" : "DIFFERENT"
        );
    }

    /*Test 3 : Modify the last byte.*/
    memcpy(modified_ciphertext,ciphertext,kem->length_ciphertext);
    modified_ciphertext[kem->length_ciphertext-1]^=0x01;

    rc=OQS_KEM_decaps(
        kem,
        shared_secret_dec,
        modified_ciphertext,
        secret_key
    );

    printf("EC-05 modification 3 : LAST BYTE\n");
    printf("EC-05 decapsulation 3 return : %d\n",rc);

    if (rc==OQS_SUCCESS) {
        printf(
            "EC-05 secret comparison 3 : %s\n",
            memcmp(
                shared_secret_enc,
                shared_secret_dec,
                kem->length_shared_secret
            )==0 ? "MATCH" : "DIFFERENT"
        );
    }

    /*Test 4 : Modify multiple bytes.*/
    memcpy(modified_ciphertext,ciphertext,kem->length_ciphertext);
    modified_ciphertext[0]^=0x01;
    modified_ciphertext[kem->length_ciphertext/2]^=0x01;
    modified_ciphertext[kem->length_ciphertext-1]^=0x01;

    rc=OQS_KEM_decaps(
        kem,
        shared_secret_dec,
        modified_ciphertext,
        secret_key
    );

    printf("EC-05 modification 4 : MULTIPLE BYTES\n");
    printf("EC-05 decapsulation 4 return : %d\n",rc);

    if (rc==OQS_SUCCESS) {
        printf(
            "EC-05 secret comparison 4 : %s\n",
            memcmp(
                shared_secret_enc,
                shared_secret_dec,
                kem->length_shared_secret
            )==0 ? "MATCH" : "DIFFERENT"
        );
    }

cleanup:
    free(public_key);
    free(secret_key);
    free(ciphertext);
    free(modified_ciphertext);
    free(shared_secret_enc);
    free(shared_secret_dec);

    OQS_KEM_free(kem);

    return rc==OQS_SUCCESS ? 0 : 1;
}
