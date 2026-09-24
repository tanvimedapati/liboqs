/*SD-02 : old sign, new message*/
/*author : tanvi medapati*/
#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    OQS_init();

    OQS_SIG *sig=OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);

    if(sig==NULL) {
        printf("SD-02 ML-DSA-65 initialization : FAILED\n");
        OQS_destroy();
        return EXIT_FAILURE;
    }

    uint8_t *public_key=OQS_MEM_malloc(sig->length_public_key);
    uint8_t *secret_key=OQS_MEM_malloc(sig->length_secret_key);
    uint8_t *signature=OQS_MEM_malloc(sig->length_signature);

    const uint8_t original_message[]="ML-DSA valid signature test";
    uint8_t modified_message[]="ML-DSA modified signature test";

    size_t original_message_len=strlen((const char *)original_message);
    size_t modified_message_len=strlen((const char *)modified_message);
    size_t signature_len=0;

    if(public_key==NULL||secret_key==NULL||signature==NULL) {
        printf("SD-02 memory allocation : FAILED\n");

        OQS_MEM_insecure_free(public_key);
        OQS_MEM_secure_free(secret_key,sig->length_secret_key);
        OQS_MEM_insecure_free(signature);
        OQS_SIG_free(sig);
        OQS_destroy();

        return EXIT_FAILURE;
    }

    OQS_STATUS rc=OQS_SIG_keypair(sig,public_key,secret_key);
    printf("SD-02 keypair return : %d\n",rc);

    if(rc!=OQS_SUCCESS) {
        goto cleanup;
    }

    rc=OQS_SIG_sign(
        sig,
        signature,
        &signature_len,
        original_message,
        original_message_len,
        secret_key
    );

    printf("SD-02 signing return : %d\n",rc);

    if(rc!=OQS_SUCCESS) {
        goto cleanup;
    }

    printf("SD-02 message modified : YES\n");

    rc=OQS_SIG_verify(
        sig,
        modified_message,
        modified_message_len,
        signature,
        signature_len,
        public_key
    );

    printf("SD-02 verification return : %d\n",rc);

    if(rc==OQS_SUCCESS) {
        printf("SD-02 modified message verification : VALID\n");
    } else {
        printf("SD-02 modified message verification : INVALID\n");
    }

cleanup:
    OQS_MEM_insecure_free(public_key);
    OQS_MEM_secure_free(secret_key,sig->length_secret_key);
    OQS_MEM_insecure_free(signature);
    OQS_SIG_free(sig);
    OQS_destroy();

    return EXIT_SUCCESS;
}
