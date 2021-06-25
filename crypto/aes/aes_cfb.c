#include <errno.h>
#include <inaccel/openssl/aes.h>
#include <inaccel/rpc.h>

int inaccel_AES_cfb128_encrypt(const unsigned char *in, unsigned char *out, size_t length, const inaccel_AES_KEY *key, unsigned char *ivec, int *num, const int enc) {
	if (enc) {
		errno = EINVAL;
		return -1;
	} else {
		inaccel_request request = inaccel_request_create("openssl.crypto.aes.cfb128-decrypt");
		if (!request) {
			return -1;
		}

		if (inaccel_request_arg_array(request, length, in, 0)) {
			int errsv = errno;

			inaccel_request_release(request);

			errno = errsv;
			return -1;
		}

		if (inaccel_request_arg_array(request, length, out, 1)) {
			int errsv = errno;

			inaccel_request_release(request);

			errno = errsv;
			return -1;
		}

		if (inaccel_request_arg_scalar(request, sizeof(length), &length, 2)) {
			int errsv = errno;

			inaccel_request_release(request);

			errno = errsv;
			return -1;
		}

		if (inaccel_request_arg_scalar(request, sizeof(inaccel_AES_KEY), key, 3)) {
			int errsv = errno;

			inaccel_request_release(request);

			errno = errsv;
			return -1;
		}

		if (inaccel_request_arg_scalar(request, inaccel_AES_BLOCK_SIZE, ivec, 4)) {
			int errsv = errno;

			inaccel_request_release(request);

			errno = errsv;
			return -1;
		}

		inaccel_response response = inaccel_response_create();
		if (!response) {
			int errsv = errno;

			inaccel_request_release(request);

			errno = errsv;
			return -1;
		}

		if (inaccel_submit(request, response)) {
			int errsv = errno;

			inaccel_request_release(request);
			inaccel_response_release(response);

			errno = errsv;
			return -1;
		}

		inaccel_request_release(request);

		if (inaccel_response_wait(response)) {
			int errsv = errno;

			inaccel_response_release(response);

			errno = errsv;
			return -1;
		}

		inaccel_response_release(response);

		return 0;
	}
}
