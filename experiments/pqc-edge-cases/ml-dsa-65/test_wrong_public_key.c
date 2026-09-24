/*SD-04 : wrong public key*/
/*author : tanvi medapati*/
#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
	OQS_init();

	OQS_SIG *sig=OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);

	if(sig==NULL) {
		printf("SD-04 ML-DSA-65 initialization : FAILED\n");
		OQS_destroy();
		return EXIT_FAILURE;
	}

	uint8_t *public_key_a=OQS_MEM_malloc(sig->length_public_key);
	uint8_t *secret_key_a=OQS_MEM_malloc(sig->length_secret_key);

	uint8_t *public_key_b=OQS_MEM_malloc(sig->length_public_key);
	uint8_t *secret_key_b=OQS_MEM_malloc(sig->length_secret_key);

	uint8_t *signature=OQS_MEM_malloc(sig->length_signature);

	const uint8_t message[]="ML-DSA wrong public key test";
	size_t message_len=strlen((const char *)message);
	size_t signature_len=0;

	if(public_key_a==NULL||secret_key_a==NULL||
	   public_key_b==NULL||secret_key_b==NULL||
	   signature==NULL) {
		printf("SD-04 memory allocation : FAILED\n");
		goto cleanup;
	}

	OQS_STATUS rc=OQS_SIG_keypair(
		sig,
		public_key_a,
		secret_key_a
	);

	printf("SD-04 keypair A return : %d\n",rc);

	if(rc!=OQS_SUCCESS) {
		goto cleanup;
	}

	rc=OQS_SIG_keypair(
		sig,
		public_key_b,
		secret_key_b
	);

	printf("SD-04 keypair B return : %d\n",rc);

	if(rc!=OQS_SUCCESS) {
		goto cleanup;
	}

	rc=OQS_SIG_sign(
		sig,
		signature,
		&signature_len,
		message,
		message_len,
		secret_key_a
	);

	printf("SD-04 signing with key A return : %d\n",rc);

	if(rc!=OQS_SUCCESS) {
		goto cleanup;
	}

	printf("SD-04 verification public key : KEY B\n");

	rc=OQS_SIG_verify(
		sig,
		message,
		message_len,
		signature,
		signature_len,
		public_key_b
	);

	printf("SD-04 verification return : %d\n",rc);

	if(rc==OQS_SUCCESS) {
		printf("SD-04 wrong public key verification : VALID\n");
	} else {
		printf("SD-04 wrong public key verification : INVALID\n");
	}

cleanup:
	OQS_MEM_insecure_free(public_key_a);
	OQS_MEM_secure_free(secret_key_a,sig->length_secret_key);
	OQS_MEM_insecure_free(public_key_b);
	OQS_MEM_secure_free(secret_key_b,sig->length_secret_key);
	OQS_MEM_insecure_free(signature);

	OQS_SIG_free(sig);
	OQS_destroy();

	return EXIT_SUCCESS;
}

