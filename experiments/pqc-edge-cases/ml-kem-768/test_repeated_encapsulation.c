/*EC-02 Repeated encapsulation using the same public key*/
/*author : tanvi medapati*/
#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void){
    OQS_KEM *kem=NULL;
    uint8_t *public_key=NULL;
    uint8_t *secret_key=NULL;
    uint8_t *ciphertext1=NULL;
    uint8_t *ciphertext2=NULL;
    uint8_t *shared_secret_e1=NULL;
    uint8_t *shared_secret_e2=NULL;
    uint8_t *shared_secret_d1=NULL;
    uint8_t *shared_secret_d2=NULL;
    int exit_code=EXIT_FAILURE;

    OQS_init();

    kem=OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if(kem==NULL){
        fprintf(stderr,"ERROR: ML-KEM-768 is unavailable.\n");
        goto cleanup;
    }

    public_key=OQS_MEM_malloc(kem->length_public_key);
    secret_key=OQS_MEM_malloc(kem->length_secret_key);
    ciphertext1=OQS_MEM_malloc(kem->length_ciphertext);
    ciphertext2=OQS_MEM_malloc(kem->length_ciphertext);
    shared_secret_e1=OQS_MEM_malloc(kem->length_shared_secret);
    shared_secret_e2=OQS_MEM_malloc(kem->length_shared_secret);
    shared_secret_d1=OQS_MEM_malloc(kem->length_shared_secret);
    shared_secret_d2=OQS_MEM_malloc(kem->length_shared_secret);

    if(public_key==NULL || secret_key==NULL || ciphertext1==NULL || ciphertext2==NULL || shared_secret_e1==NULL || shared_secret_e2==NULL || shared_secret_d1==NULL || shared_secret_d2==NULL){
        fprintf(stderr,"ERROR: Memory allocation failed.\n");
        goto cleanup;
    }

    OQS_STATUS rc=OQS_KEM_keypair(kem,public_key,secret_key);
    printf("EC-02 keypair return : %d\n",rc);

    if(rc!=OQS_SUCCESS){
        goto cleanup;
    }

    rc=OQS_KEM_encaps(kem,ciphertext1,shared_secret_e1,public_key);
    printf("EC-02 encapsulation 1 return : %d\n",rc);

    if(rc!=OQS_SUCCESS){
        goto cleanup;
    }

    rc=OQS_KEM_encaps(kem,ciphertext2,shared_secret_e2,public_key);
    printf("EC-02 encapsulation 2 return : %d\n",rc);

    if(rc!=OQS_SUCCESS){
        goto cleanup;
    }

    rc=OQS_KEM_decaps(kem,shared_secret_d1,ciphertext1,secret_key);
    printf("EC-02 decapsulation 1 return : %d\n",rc);

    if(rc!=OQS_SUCCESS){
        goto cleanup;
    }

    rc=OQS_KEM_decaps(kem,shared_secret_d2,ciphertext2,secret_key);
    printf("EC-02 decapsulation 2 return : %d\n",rc);

    if(rc!=OQS_SUCCESS){
        goto cleanup;
    }

    printf("EC-02 ciphertexts : %s\n",
           memcmp(ciphertext1,ciphertext2,kem->length_ciphertext)==0
           ? "IDENTICAL"
           : "DIFFERENT");

    printf("EC-02 encapsulated secrets : %s\n",
           memcmp(shared_secret_e1,shared_secret_e2,kem->length_shared_secret)==0
           ? "IDENTICAL"
           : "DIFFERENT");

    printf("EC-02 secret 1 comparison : %s\n",
           memcmp(shared_secret_e1,shared_secret_d1,kem->length_shared_secret)==0
           ? "MATCH"
           : "MISMATCH");

    printf("EC-02 secret 2 comparison : %s\n",
           memcmp(shared_secret_e2,shared_secret_d2,kem->length_shared_secret)==0
           ? "MATCH"
           : "MISMATCH");

    if(memcmp(shared_secret_e1,shared_secret_d1,kem->length_shared_secret)==0 &&
       memcmp(shared_secret_e2,shared_secret_d2,kem->length_shared_secret)==0){
        exit_code=EXIT_SUCCESS;
    }

cleanup:
    if(kem!=NULL){
        OQS_MEM_secure_free(secret_key,kem->length_secret_key);
        OQS_MEM_secure_free(shared_secret_e1,kem->length_shared_secret);
        OQS_MEM_secure_free(shared_secret_e2,kem->length_shared_secret);
        OQS_MEM_secure_free(shared_secret_d1,kem->length_shared_secret);
        OQS_MEM_secure_free(shared_secret_d2,kem->length_shared_secret);
        OQS_MEM_insecure_free(public_key);
        OQS_MEM_insecure_free(ciphertext1);
        OQS_MEM_insecure_free(ciphertext2);
        OQS_KEM_free(kem);
    }

    OQS_destroy();

    return exit_code;
}
