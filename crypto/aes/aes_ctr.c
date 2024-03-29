#include <byteswap.h>
#include <errno.h>
#include <inaccel/openssl/aes.h>
#include <inaccel/rpc.h>
#include <stdlib.h>

int inaccel_AES_ctr128_encrypt(const unsigned char *in, unsigned char *out, size_t length, const inaccel_AES_KEY *key, unsigned char ivec[inaccel_AES_BLOCK_SIZE], unsigned char ecount_buf[inaccel_AES_BLOCK_SIZE], unsigned int *num) {
	while (*num && length) {
		*out = ecount_buf[*num] ^ *in;

		in++;
		out++;

		*num = (*num + 1) % inaccel_AES_BLOCK_SIZE;
		length--;
	}

	if (!length) {
		return 0;
	}

	inaccel_request request = inaccel_request_create("openssl.crypto.aes.ctr128-crypt");
	if (!request) {
		return -1;
	}

	if (inaccel_request_arg_scalar(request, sizeof(inaccel_AES_KEY), key, 3)) {
		int errsv = errno;

		inaccel_request_release(request);

		errno = errsv;
		return -1;
	}

	inaccel_response *response = NULL;

	unsigned int chunks = 0;

	size_t chunk_offset = 0;
	while (chunk_offset < length) {
		size_t chunk_length = inaccel_AES_CHUNK_SIZE < length - chunk_offset ? inaccel_AES_CHUNK_SIZE : ((length - chunk_offset - 1) | (inaccel_AES_BLOCK_SIZE - 1)) + 1;

		if (inaccel_request_arg_array(request, chunk_length, in + chunk_offset, 0)) {
			int errsv = errno;

			inaccel_request_release(request);

			for (unsigned int chunk = 0; chunk < chunks; chunk++) {
				inaccel_response_wait(response[chunk]);

				inaccel_response_release(response[chunk]);
			}

			free(response);

			errno = errsv;
			return -1;
		}

		if (inaccel_request_arg_array(request, chunk_length, out + chunk_offset, 1)) {
			int errsv = errno;

			inaccel_request_release(request);

			for (unsigned int chunk = 0; chunk < chunks; chunk++) {
				inaccel_response_wait(response[chunk]);

				inaccel_response_release(response[chunk]);
			}

			free(response);

			errno = errsv;
			return -1;
		}

		if (inaccel_request_arg_scalar(request, sizeof(chunk_length), &chunk_length, 2)) {
			int errsv = errno;

			inaccel_request_release(request);

			for (unsigned int chunk = 0; chunk < chunks; chunk++) {
				inaccel_response_wait(response[chunk]);

				inaccel_response_release(response[chunk]);
			}

			free(response);

			errno = errsv;
			return -1;
		}

		if (inaccel_request_arg_scalar(request, inaccel_AES_BLOCK_SIZE, ivec, 4)) {
			int errsv = errno;

			inaccel_request_release(request);

			for (unsigned int chunk = 0; chunk < chunks; chunk++) {
				inaccel_response_wait(response[chunk]);

				inaccel_response_release(response[chunk]);
			}

			free(response);

			errno = errsv;
			return -1;
		}

		inaccel_response *_response = (inaccel_response *) realloc(response, (chunks + 1) * sizeof(inaccel_response *));
		if (!_response) {
			int errsv = errno;

			inaccel_request_release(request);

			for (unsigned int chunk = 0; chunk < chunks; chunk++) {
				inaccel_response_wait(response[chunk]);

				inaccel_response_release(response[chunk]);
			}

			free(response);

			errno = errsv;
			return -1;
		}
		response = _response;

		response[chunks] = inaccel_response_create();
		if (!response[chunks]) {
			int errsv = errno;

			inaccel_request_release(request);

			for (unsigned int chunk = 0; chunk < chunks; chunk++) {
				inaccel_response_wait(response[chunk]);

				inaccel_response_release(response[chunk]);
			}

			free(response);

			errno = errsv;
			return -1;
		}

		if (inaccel_submit(request, response[chunks])) {
			int errsv = errno;

			inaccel_request_release(request);

			for (unsigned int chunk = 0; chunk < chunks; chunk++) {
				inaccel_response_wait(response[chunk]);

				inaccel_response_release(response[chunk]);
			}

			free(response);

			errno = errsv;
			return -1;
		}

		chunk_offset += chunk_length;

		chunks++;

		unsigned long *counter = (unsigned long *) &ivec[inaccel_AES_BLOCK_SIZE / 2];
		*counter += bswap_64(chunk_length / inaccel_AES_BLOCK_SIZE);
	}

	inaccel_request_release(request);

	for (unsigned int chunk = 0; chunk < chunks; chunk++) {
		if (inaccel_response_wait(response[chunk])) {
			int errsv = errno;

			for (; chunk < chunks; chunk++) {
				inaccel_response_wait(response[chunk]);

				inaccel_response_release(response[chunk]);
			}

			free(response);

			errno = errsv;
			return -1;
		}

		inaccel_response_release(response[chunk]);
	}

	free(response);

	*num = (int) (length % inaccel_AES_BLOCK_SIZE);

	for (unsigned int n = 0; n < inaccel_AES_BLOCK_SIZE; n++) {
		ecount_buf[n] = in[chunk_offset - inaccel_AES_BLOCK_SIZE + n] ^ out[chunk_offset - inaccel_AES_BLOCK_SIZE + n];
	}

	return 0;
}
