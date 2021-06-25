/**
 * Copyright © 2018-2021 InAccel
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef INACCEL_OPENSSL_AES_H
#define INACCEL_OPENSSL_AES_H

#ifdef  __cplusplus
extern "C" {
#endif

#include <stddef.h>

#define inaccel_AES_BLOCK_SIZE 16

#define inaccel_AES_DECRYPT 0

#define inaccel_AES_ENCRYPT 1

#define inaccel_AES_MAXNR 14

typedef struct {
	unsigned int rd_key[4 * (inaccel_AES_MAXNR + 1)];
	int rounds;
} inaccel_AES_KEY;

int inaccel_AES_cbc_encrypt(const unsigned char *in, unsigned char *out, size_t length, const inaccel_AES_KEY *key, unsigned char *ivec, const int enc);

int inaccel_AES_cfb128_encrypt(const unsigned char *in, unsigned char *out, size_t length, const inaccel_AES_KEY *key, unsigned char *ivec, int *num, const int enc);

int inaccel_AES_ctr128_encrypt(const unsigned char *in, unsigned char *out, size_t length, const inaccel_AES_KEY *key, unsigned char ivec[inaccel_AES_BLOCK_SIZE], unsigned char ecount_buf[inaccel_AES_BLOCK_SIZE], unsigned int *num);

int inaccel_AES_set_decrypt_key(const unsigned char *userKey, const int bits, inaccel_AES_KEY *key);

int inaccel_AES_set_encrypt_key(const unsigned char *userKey, const int bits, inaccel_AES_KEY *key);

#ifdef  __cplusplus
}
#endif

#endif
