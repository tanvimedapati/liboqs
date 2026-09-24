/*SD-01 : valid signature and normal working*/
/*author : tanvi medapati*/
#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    OQS_init();

    OQS_SIG *sig=OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);

    if(sig==NULL) {
        printf("SD-01 ML-DSA-65 initialization : FAILED\n");
        OQS_destroy();
        return EXIT_FAILURE;
    }

    uint8_t *public_key=OQS_MEM_malloc(sig->length_public_key);
    uint8_t *secret_key=OQS_MEM_malloc(sig->length_secret_key);
    uint8_t *signature=OQS_MEM_malloc(sig->length_signature);

    const uint8_t message[]="ML-DSA valid signature test";
    size_t message_len=strlen((const char *)message);
    size_t signature_len=0;

    if(public_key==NULL||secret_key==NULL||signature==NULL) {
        printf("SD-01 memory allocation : FAILED\n");

        OQS_MEM_insecure_free(public_key);
        OQS_MEM_secure_free(secret_key,sig->length_secret_key);
        OQS_MEM_insecure_free(signature);
        OQS_SIG_free(sig);
        OQS_destroy();

        return EXIT_FAILURE;
    }

    OQS_STATUS rc=OQS_SIG_keypair(sig,public_key,secret_key);
    printf("SD-01 keypair return : %d\n",rc);

    if(rc!=OQS_SUCCESS) {
        goto cleanup;
    }

    rc=OQS_SIG_sign(sig,signature,&signature_len,
                    message,message_len,secret_key);

    printf("SD-01 signing return : %d\n",rc);

    if(rc!=OQS_SUCCESS) {
        goto cleanup;
    }

    rc=OQS_SIG_verify(sig,message,message_len,
                      signature,signature_len,public_key);

    printf("SD-01 verification return : %d\n",rc);

    if(rc==OQS_SUCCESS) {
        printf("SD-01 signature verification : VALID\n");
    } else {
        printf("SD-01 signature verification : INVALID\n");
    }

cleanup:
    OQS_MEM_insecure_free(public_key);
    OQS_MEM_secure_free(secret_key,sig->length_secret_key);
    OQS_MEM_insecure_free(signature);
    OQS_SIG_free(sig);
    OQS_destroy();

    return rc==OQS_SUCCESS?EXIT_SUCCESS:EXIT_FAILURE;
}
