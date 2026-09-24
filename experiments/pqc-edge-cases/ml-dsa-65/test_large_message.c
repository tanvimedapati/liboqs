#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MESSAGE_LEN (1024*1024)

int main(void) {
	OQS_init();

	OQS_SIG *sig=OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);

	if(sig==NULL) {
		printf("SD-08 ML-DSA-65 initialization : FAILED\n");
		OQS_destroy();
		return EXIT_FAILURE;
	}

	uint8_t *public_key=OQS_MEM_malloc(sig->length_public_key);
	uint8_t *secret_key=OQS_MEM_malloc(sig->length_secret_key);
	uint8_t *signature=OQS_MEM_malloc(sig->length_signature);
	uint8_t *message=OQS_MEM_malloc(MESSAGE_LEN);

	size_t signature_len=0;

	if(public_key==NULL||secret_key==NULL||
	   signature==NULL||message==NULL) {
		printf("SD-08 memory allocation : FAILED\n");
		goto cleanup;
	}

	/* Fill the message with deterministic test data. */
	for(size_t i=0;i<MESSAGE_LEN;i++) {
		message[i]=(uint8_t)(i%256);
	}

	OQS_STATUS rc=OQS_SIG_keypair(
		sig,
		public_key,
		secret_key
	);

	printf("SD-08 keypair return : %d\n",rc);

	if(rc!=OQS_SUCCESS) {
		goto cleanup;
	}

	rc=OQS_SIG_sign(
		sig,
		signature,
		&signature_len,
		message,
		MESSAGE_LEN,
		secret_key
	);

	printf("SD-08 signing return : %d\n",rc);
	printf("SD-08 message length : %d bytes\n",MESSAGE_LEN);

	if(rc!=OQS_SUCCESS) {
		goto cleanup;
	}

	rc=OQS_SIG_verify(
		sig,
		message,
		MESSAGE_LEN,
		signature,
		signature_len,
		public_key
	);

	printf("SD-08 verification return : %d\n",rc);

	if(rc==OQS_SUCCESS) {
		printf("SD-08 large message verification : VALID\n");
	} else {
		printf("SD-08 large message verification : INVALID\n");
	}

cleanup:
	OQS_MEM_insecure_free(public_key);
	OQS_MEM_secure_free(secret_key,sig->length_secret_key);
	OQS_MEM_insecure_free(signature);
	OQS_MEM_insecure_free(message);

	OQS_SIG_free(sig);
	OQS_destroy();

	return EXIT_SUCCESS;
}
