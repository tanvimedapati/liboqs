/*SD-05 : repeated signing*/
/*author : tanvi medapati*/
#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
	OQS_init();

	OQS_SIG *sig=OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);

	if(sig==NULL) {
		printf("SD-06 ML-DSA-65 initialization : FAILED\n");
		OQS_destroy();
		return EXIT_FAILURE;
	}

	uint8_t *public_key=OQS_MEM_malloc(sig->length_public_key);
	uint8_t *secret_key=OQS_MEM_malloc(sig->length_secret_key);

	uint8_t *signature_1=OQS_MEM_malloc(sig->length_signature);
	uint8_t *signature_2=OQS_MEM_malloc(sig->length_signature);

	const uint8_t message[]="ML-DSA repeated signing test";
	size_t message_len=strlen((const char *)message);

	size_t signature_len_1=0;
	size_t signature_len_2=0;

	if(public_key==NULL||secret_key==NULL||
	   signature_1==NULL||signature_2==NULL) {
		printf("SD-06 memory allocation : FAILED\n");
		goto cleanup;
	}

	OQS_STATUS rc=OQS_SIG_keypair(
		sig,
		public_key,
		secret_key
	);

	printf("SD-06 keypair return : %d\n",rc);

	if(rc!=OQS_SUCCESS) {
		goto cleanup;
	}

	rc=OQS_SIG_sign(
		sig,
		signature_1,
		&signature_len_1,
		message,
		message_len,
		secret_key
	);

	printf("SD-06 signing 1 return : %d\n",rc);

	if(rc!=OQS_SUCCESS) {
		goto cleanup;
	}

	rc=OQS_SIG_sign(
		sig,
		signature_2,
		&signature_len_2,
		message,
		message_len,
		secret_key
	);

	printf("SD-06 signing 2 return : %d\n",rc);

	if(rc!=OQS_SUCCESS) {
		goto cleanup;
	}

	printf("SD-06 signatures : %s\n",
	       (signature_len_1==signature_len_2 &&
	        memcmp(signature_1,signature_2,signature_len_1)==0)
	       ? "IDENTICAL"
	       : "DIFFERENT");

	rc=OQS_SIG_verify(
		sig,
		message,
		message_len,
		signature_1,
		signature_len_1,
		public_key
	);

	printf("SD-06 signature 1 verification : %s\n",
	       rc==OQS_SUCCESS ? "VALID" : "INVALID");

	rc=OQS_SIG_verify(
		sig,
		message,
		message_len,
		signature_2,
		signature_len_2,
		public_key
	);

	printf("SD-06 signature 2 verification : %s\n",
	       rc==OQS_SUCCESS ? "VALID" : "INVALID");

cleanup:
	OQS_MEM_insecure_free(public_key);
	OQS_MEM_secure_free(secret_key,sig->length_secret_key);
	OQS_MEM_insecure_free(signature_1);
	OQS_MEM_insecure_free(signature_2);

	OQS_SIG_free(sig);
	OQS_destroy();

	return EXIT_SUCCESS;
}
