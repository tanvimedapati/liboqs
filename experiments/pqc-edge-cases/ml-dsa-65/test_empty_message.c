/*SD-05 : handle 0 byte message*/
/*author : tanvi-medapati*/
#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
	OQS_init();

	OQS_SIG *sig=OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);

	if(sig==NULL) {
		printf("SD-05 ML-DSA-65 initialization : FAILED\n");
		OQS_destroy();
		return EXIT_FAILURE;
	}

	uint8_t *public_key=OQS_MEM_malloc(sig->length_public_key);
	uint8_t *secret_key=OQS_MEM_malloc(sig->length_secret_key);
	uint8_t *signature=OQS_MEM_malloc(sig->length_signature);

	const uint8_t *message=(const uint8_t *)"";
	size_t message_len=0;
	size_t signature_len=0;

	if(public_key==NULL||secret_key==NULL||signature==NULL) {
		printf("SD-05 memory allocation : FAILED\n");
		goto cleanup;
	}

	OQS_STATUS rc=OQS_SIG_keypair(
		sig,
		public_key,
		secret_key
	);

	printf("SD-05 keypair return : %d\n",rc);

	if(rc!=OQS_SUCCESS) {
		goto cleanup;
	}

	rc=OQS_SIG_sign(
		sig,
		signature,
		&signature_len,
		message,
		message_len,
		secret_key
	);

	printf("SD-05 signing return : %d\n",rc);
	printf("SD-05 message length : %zu bytes\n",message_len);

	if(rc!=OQS_SUCCESS) {
		goto cleanup;
	}

	rc=OQS_SIG_verify(
		sig,
		message,
		message_len,
		signature,
		signature_len,
		public_key
	);

	printf("SD-05 verification return : %d\n",rc);

	if(rc==OQS_SUCCESS) {
		printf("SD-05 empty message verification : VALID\n");
	} else {
		printf("SD-05 empty message verification : INVALID\n");
	}

cleanup:
	OQS_MEM_insecure_free(public_key);
	OQS_MEM_secure_free(secret_key,sig->length_secret_key);
	OQS_MEM_insecure_free(signature);

	OQS_SIG_free(sig);
	OQS_destroy();

	return EXIT_SUCCESS;
}
