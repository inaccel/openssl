#include <inaccel/coral.h>
#include <inaccel/openssl/aes.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <string.h>
#include <sys/time.h>

int encrypt(const unsigned char *in, unsigned char *out, size_t length, const unsigned char *userKey, const int bits, unsigned char *ivec) {
	AES_KEY key;
	if (AES_set_encrypt_key(userKey, bits, &key)) {
		return -1;
	}

	unsigned char tmp[AES_BLOCK_SIZE];
	memcpy(tmp, ivec, sizeof(tmp));

	struct timeval a, b, res;
	gettimeofday(&b, NULL);

	AES_cbc_encrypt(in, out, length, &key, tmp, AES_ENCRYPT);

	gettimeofday(&a, NULL);
	timersub(&a, &b, &res);
	printf("AES_cbc_encrypt: %ld.%06ld sec\n", res.tv_sec, res.tv_usec);

	return 0;
}

int decrypt(const unsigned char *in, unsigned char *out, size_t length, const unsigned char *userKey, const int bits, unsigned char *ivec) {
	AES_KEY key;
	if (AES_set_decrypt_key(userKey, bits, &key)) {
		return -1;
	}

	unsigned char tmp[AES_BLOCK_SIZE];
	memcpy(tmp, ivec, sizeof(tmp));

	struct timeval a, b, res;
	gettimeofday(&b, NULL);

	AES_cbc_encrypt(in, out, length, &key, tmp, AES_DECRYPT);

	gettimeofday(&a, NULL);
	timersub(&a, &b, &res);
	printf("AES_cbc_decrypt: %ld.%06ld sec\n", res.tv_sec, res.tv_usec);

	return 0;
}

int inaccel_decrypt(const unsigned char *in, unsigned char *out, size_t length, const unsigned char *userKey, const int bits, unsigned char *ivec) {
	inaccel_AES_KEY key;
	if (inaccel_AES_set_decrypt_key(userKey, bits, &key)) {
		return -1;
	}

	unsigned char tmp[AES_BLOCK_SIZE];
	memcpy(tmp, ivec, sizeof(tmp));

	struct timeval a, b, res;
	gettimeofday(&b, NULL);

	if (inaccel_AES_cbc_encrypt(in, out, length, &key, tmp, AES_DECRYPT)) {
		perror("inaccel");

		return -1;
	}

	gettimeofday(&a, NULL);
	timersub(&a, &b, &res);
	printf("inaccel_AES_cbc_decrypt: %ld.%06ld sec\n", res.tv_sec, res.tv_usec);

	return 0;
}

int main() {
	size_t length = 100000000;

	unsigned char userKey[32 + 1] = "InAccel OpenSSL test/aes-256-cbc";
	int bits = 256;

	unsigned char ivec[AES_BLOCK_SIZE];
	RAND_bytes(ivec, AES_BLOCK_SIZE);

	unsigned char *plain_golden = (unsigned char *) malloc(length);
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

	if (encrypt(plain_golden, cipher, length, userKey, bits, ivec)) {
		return EXIT_FAILURE;
	}

#ifndef GOLDEN
	if (inaccel_decrypt(cipher, plain, length, userKey, bits, ivec))
#endif
		if (decrypt(cipher, plain, length, userKey, bits, ivec))
			return EXIT_FAILURE;

	if (memcmp(plain, plain_golden, length)) {
		fprintf(stderr, "bad decrypt\n");

		return EXIT_FAILURE;
	}

	free(plain_golden);
	inaccel_free(cipher);
	inaccel_free(plain);

	return EXIT_SUCCESS;
}
