/*SD-03 : modified signature*/
/*author : tanvi medapati*/
#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
	OQS_init();

	OQS_SIG *sig=OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);

	if(sig==NULL) {
		printf("SD-03 ML-DSA-65 initialization : FAILED\n");
		OQS_destroy();
		return EXIT_FAILURE;
	}

	uint8_t *public_key=OQS_MEM_malloc(sig->length_public_key);
	uint8_t *secret_key=OQS_MEM_malloc(sig->length_secret_key);
	uint8_t *signature=OQS_MEM_malloc(sig->length_signature);

	const uint8_t message[]="ML-DSA signature modification test";
	size_t message_len=strlen((const char *)message);
	size_t signature_len=0;

	if(public_key==NULL||secret_key==NULL||signature==NULL) {
		printf("SD-03 memory allocation : FAILED\n");
		return EXIT_FAILURE;
	}

	OQS_STATUS rc=OQS_SIG_keypair(sig,public_key,secret_key);
	printf("SD-03 keypair return : %d\n",rc);

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

	printf("SD-03 signing return : %d\n",rc);

	if(rc!=OQS_SUCCESS) {
		goto cleanup;
	}

	/* Modify one bit of the valid signature */
	signature[0]^=0x01;

	printf("SD-03 signature modified : YES\n");

	rc=OQS_SIG_verify(
		sig,
		message,
		message_len,
		signature,
		signature_len,
		public_key
	);

	printf("SD-03 verification return : %d\n",rc);

	if(rc==OQS_SUCCESS) {
		printf("SD-03 modified signature verification : VALID\n");
	} else {
		printf("SD-03 modified signature verification : INVALID\n");
	}

cleanup:
	OQS_MEM_insecure_free(public_key);
	OQS_MEM_secure_free(secret_key,sig->length_secret_key);
	OQS_MEM_insecure_free(signature);
	OQS_SIG_free(sig);
	OQS_destroy();

	return EXIT_SUCCESS;
}
