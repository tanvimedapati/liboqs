/*SD-06 : smallest non empty message*/
/*author : tanvi medapati*/
#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
	OQS_init();

	OQS_SIG *sig=OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);

	if(sig==NULL) {
		printf("SD-07 ML-DSA-65 initialization : FAILED\n");
		OQS_destroy();
		return EXIT_FAILURE;
	}

	uint8_t *public_key=OQS_MEM_malloc(sig->length_public_key);
	uint8_t *secret_key=OQS_MEM_malloc(sig->length_secret_key);
	uint8_t *signature=OQS_MEM_malloc(sig->length_signature);

	const uint8_t message[]={0x00};
	size_t message_len=sizeof(message);
	size_t signature_len=0;

	if(public_key==NULL||secret_key==NULL||signature==NULL) {
		printf("SD-07 memory allocation : FAILED\n");
		goto cleanup;
	}

	OQS_STATUS rc=OQS_SIG_keypair(
		sig,
		public_key,
		secret_key
	);

	printf("SD-07 keypair return : %d\n",rc);

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

	printf("SD-07 signing return : %d\n",rc);
	printf("SD-07 message length : %zu byte\n",message_len);

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

	printf("SD-07 verification return : %d\n",rc);

	if(rc==OQS_SUCCESS) {
		printf("SD-07 one-byte message verification : VALID\n");
	} else {
		printf("SD-07 one-byte message verification : INVALID\n");
	}

cleanup:
	OQS_MEM_insecure_free(public_key);
	OQS_MEM_secure_free(secret_key,sig->length_secret_key);
	OQS_MEM_insecure_free(signature);

	OQS_SIG_free(sig);
	OQS_destroy();

	return EXIT_SUCCESS;
}
