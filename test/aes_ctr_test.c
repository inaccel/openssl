#include <inaccel/coral.h>
#include <inaccel/openssl/aes.h>
#include <openssl/aes.h>
#include <openssl/modes.h>
#include <openssl/rand.h>
#include <string.h>
#include <sys/time.h>

void AES_ctr128_encrypt(const unsigned char *in, unsigned char *out, size_t length, const AES_KEY *key, unsigned char ivec[AES_BLOCK_SIZE], unsigned char ecount_buf[AES_BLOCK_SIZE], unsigned int *num) {
	CRYPTO_ctr128_encrypt(in, out, length, key, ivec, ecount_buf, num, (block128_f) AES_encrypt);
}

int crypt(const unsigned char *in, unsigned char *out, size_t length, const unsigned char *userKey, const int bits, unsigned char ivec[AES_BLOCK_SIZE], unsigned char ecount_buf[AES_BLOCK_SIZE], unsigned int *num) {
	AES_KEY key;
	if (AES_set_encrypt_key(userKey, bits, &key)) {
		return -1;
	}

	struct timeval a, b, res;
	gettimeofday(&b, NULL);

	AES_ctr128_encrypt(in, out, length, &key, ivec, ecount_buf, num);

	gettimeofday(&a, NULL);
	timersub(&a, &b, &res);
	printf("AES_ctr128_crypt: %ld.%06ld sec\n", res.tv_sec, res.tv_usec);

	printf("ivec      =");
	for (unsigned int n = 0; n < AES_BLOCK_SIZE; n++) {
		printf("%02X", ivec[n]);
	}
	printf("\n");
	printf("ecount_buf=");
	for (unsigned int n = 0; n < AES_BLOCK_SIZE; n++) {
		printf("%02X", ecount_buf[n]);
	}
	printf("\n");
	printf("num       =%d\n", *num);

	return 0;
}

int inaccel_crypt(const unsigned char *in, unsigned char *out, size_t length, const unsigned char *userKey, const int bits, unsigned char ivec[AES_BLOCK_SIZE], unsigned char ecount_buf[AES_BLOCK_SIZE], unsigned int *num) {
	inaccel_AES_KEY key;
	if (inaccel_AES_set_encrypt_key(userKey, bits, &key)) {
		return -1;
	}

	struct timeval a, b, res;
	gettimeofday(&b, NULL);

	if (inaccel_AES_ctr128_encrypt(in, out, length, &key, ivec, ecount_buf, num)) {
		perror("inaccel");

		return -1;
	}

	gettimeofday(&a, NULL);
	timersub(&a, &b, &res);
	printf("inaccel_AES_ctr128_crypt: %ld.%06ld sec\n", res.tv_sec, res.tv_usec);

	printf("ivec      =");
	for (unsigned int n = 0; n < AES_BLOCK_SIZE; n++) {
		printf("%02X", ivec[n]);
	}
	printf("\n");
	printf("ecount_buf=");
	for (unsigned int n = 0; n < AES_BLOCK_SIZE; n++) {
		printf("%02X", ecount_buf[n]);
	}
	printf("\n");
	printf("num       =%d\n", *num);

	return 0;
}

int main() {
	size_t length = 100000000;

	unsigned char userKey[32 + 1] = "InAccel OpenSSL test/aes-256-ctr";
	int bits = 256;

	unsigned char ivec[AES_BLOCK_SIZE];
	RAND_bytes(ivec, AES_BLOCK_SIZE / 2);

	unsigned char *plain_golden = (unsigned char *) inaccel_alloc(length);
	if (!plain_golden) {
		return EXIT_FAILURE;
	}
	RAND_bytes(plain_golden, length);

	unsigned char *cipher = (unsigned char *) inaccel_alloc(length);
	if (!cipher) {
		return EXIT_FAILURE;
	}

	unsigned char *plain = (unsigned char *) inaccel_alloc(length);
	if (!plain) {
		return EXIT_FAILURE;
	}

	unsigned char ivec_encrypt[AES_BLOCK_SIZE];
	memcpy(ivec_encrypt, ivec, sizeof(ivec));
	unsigned char ecount_buf_encrypt[AES_BLOCK_SIZE];
	unsigned int num_encrypt = 0;
#ifdef GOLDEN
	if (crypt(plain_golden, cipher, length, userKey, bits, ivec_encrypt, ecount_buf_encrypt, &num_encrypt))
#else
	if (inaccel_crypt(plain_golden, cipher, length, userKey, bits, ivec_encrypt, ecount_buf_encrypt, &num_encrypt))
#endif
		return EXIT_FAILURE;

	unsigned char ivec_decrypt[AES_BLOCK_SIZE];
	memcpy(ivec_decrypt, ivec, sizeof(ivec));
	unsigned char ecount_buf_decrypt[AES_BLOCK_SIZE];
	unsigned int num_decrypt = 0;
#ifdef GOLDEN
	if (crypt(cipher, plain, length, userKey, bits, ivec_decrypt, ecount_buf_decrypt, &num_decrypt))
#else
	if (inaccel_crypt(cipher, plain, length, userKey, bits, ivec_decrypt, ecount_buf_decrypt, &num_decrypt))
#endif
		return EXIT_FAILURE;

	if (memcmp(plain, plain_golden, length)) {
		fprintf(stderr, "bad decrypt\n");

		return EXIT_FAILURE;
	}

	inaccel_free(plain_golden);
	inaccel_free(cipher);
	inaccel_free(plain);

	return EXIT_SUCCESS;
}
