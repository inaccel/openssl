#include <inaccel/openssl/aes.h>
#include <string.h>

static void XtimeWord(unsigned int *w) {
	unsigned int a, b;

	a = *w;
	b = a & 0x80808080u;
	a ^= b;
	b -= b >> 7;
	b &= 0x1B1B1B1Bu;
	b ^= a << 1;
	*w = b;
}

static void SubWord(unsigned int *w) {
	unsigned int x, y, a1, a2, a3, a4, a5, a6;

	x = *w;
	y = ((x & 0xFEFEFEFEu) >> 1) | ((x & 0x01010101u) << 7);
	x &= 0xDDDDDDDDu;
	x ^= y & 0x57575757u;
	y = ((y & 0xFEFEFEFEu) >> 1) | ((y & 0x01010101u) << 7);
	x ^= y & 0x1C1C1C1Cu;
	y = ((y & 0xFEFEFEFEu) >> 1) | ((y & 0x01010101u) << 7);
	x ^= y & 0x4A4A4A4Au;
	y = ((y & 0xFEFEFEFEu) >> 1) | ((y & 0x01010101u) << 7);
	x ^= y & 0x42424242u;
	y = ((y & 0xFEFEFEFEu) >> 1) | ((y & 0x01010101u) << 7);
	x ^= y & 0x64646464u;
	y = ((y & 0xFEFEFEFEu) >> 1) | ((y & 0x01010101u) << 7);
	x ^= y & 0xE0E0E0E0u;
	a1 = x;
	a1 ^= (x & 0xF0F0F0F0u) >> 4;
	a2 = ((x & 0xCCCCCCCCu) >> 2) | ((x & 0x33333333u) << 2);
	a3 = x & a1;
	a3 ^= (a3 & 0xAAAAAAAAu) >> 1;
	a3 ^= (((x << 1) & a1) ^ ((a1 << 1) & x)) & 0xAAAAAAAAu;
	a4 = a2 & a1;
	a4 ^= (a4 & 0xAAAAAAAAu) >> 1;
	a4 ^= (((a2 << 1) & a1) ^ ((a1 << 1) & a2)) & 0xAAAAAAAAu;
	a5 = (a3 & 0xCCCCCCCCu) >> 2;
	a3 ^= ((a4 << 2) ^ a4) & 0xCCCCCCCCu;
	a4 = a5 & 0x22222222u;
	a4 |= a4 >> 1;
	a4 ^= (a5 << 1) & 0x22222222u;
	a3 ^= a4;
	a5 = a3 & 0xA0A0A0A0u;
	a5 |= a5 >> 1;
	a5 ^= (a3 << 1) & 0xA0A0A0A0u;
	a4 = a5 & 0xC0C0C0C0u;
	a6 = a4 >> 2;
	a4 ^= (a5 << 2) & 0xC0C0C0C0u;
	a5 = a6 & 0x20202020u;
	a5 |= a5 >> 1;
	a5 ^= (a6 << 1) & 0x20202020u;
	a4 |= a5;
	a3 ^= a4 >> 4;
	a3 &= 0x0F0F0F0Fu;
	a2 = a3;
	a2 ^= (a3 & 0x0C0C0C0Cu) >> 2;
	a4 = a3 & a2;
	a4 ^= (a4 & 0x0A0A0A0A0Au) >> 1;
	a4 ^= (((a3 << 1) & a2) ^ ((a2 << 1) & a3)) & 0x0A0A0A0Au;
	a5 = a4 & 0x08080808u;
	a5 |= a5 >> 1;
	a5 ^= (a4 << 1) & 0x08080808u;
	a4 ^= a5 >> 2;
	a4 &= 0x03030303u;
	a4 ^= (a4 & 0x02020202u) >> 1;
	a4 |= a4 << 2;
	a3 = a2 & a4;
	a3 ^= (a3 & 0x0A0A0A0Au) >> 1;
	a3 ^= (((a2 << 1) & a4) ^ ((a4 << 1) & a2)) & 0x0A0A0A0Au;
	a3 |= a3 << 4;
	a2 = ((a1 & 0xCCCCCCCCu) >> 2) | ((a1 & 0x33333333u) << 2);
	x = a1 & a3;
	x ^= (x & 0xAAAAAAAAu) >> 1;
	x ^= (((a1 << 1) & a3) ^ ((a3 << 1) & a1)) & 0xAAAAAAAAu;
	a4 = a2 & a3;
	a4 ^= (a4 & 0xAAAAAAAAu) >> 1;
	a4 ^= (((a2 << 1) & a3) ^ ((a3 << 1) & a2)) & 0xAAAAAAAAu;
	a5 = (x & 0xCCCCCCCCu) >> 2;
	x ^= ((a4 << 2) ^ a4) & 0xCCCCCCCCu;
	a4 = a5 & 0x22222222u;
	a4 |= a4 >> 1;
	a4 ^= (a5 << 1) & 0x22222222u;
	x ^= a4;
	y = ((x & 0xFEFEFEFEu) >> 1) | ((x & 0x01010101u) << 7);
	x &= 0x39393939u;
	x ^= y & 0x3F3F3F3Fu;
	y = ((y & 0xFCFCFCFCu) >> 2) | ((y & 0x03030303u) << 6);
	x ^= y & 0x97979797u;
	y = ((y & 0xFEFEFEFEu) >> 1) | ((y & 0x01010101u) << 7);
	x ^= y & 0x9B9B9B9Bu;
	y = ((y & 0xFEFEFEFEu) >> 1) | ((y & 0x01010101u) << 7);
	x ^= y & 0x3C3C3C3Cu;
	y = ((y & 0xFEFEFEFEu) >> 1) | ((y & 0x01010101u) << 7);
	x ^= y & 0xDDDDDDDDu;
	y = ((y & 0xFEFEFEFEu) >> 1) | ((y & 0x01010101u) << 7);
	x ^= y & 0x72727272u;
	x ^= 0x63636363u;
	*w = x;
}

static void RotWord(unsigned int *x) {
	unsigned char *w0;
	unsigned char tmp;

	w0 = (unsigned char *)x;
	tmp = w0[0];
	w0[0] = w0[1];
	w0[1] = w0[2];
	w0[2] = w0[3];
	w0[3] = tmp;
}

typedef union {
	unsigned char b[8];
	unsigned int w[2];
	unsigned long long d;
} uni;

static void KeyExpansion(const unsigned char *key, unsigned long long *w, int nr, int nk) {
	unsigned int rcon;
	uni prev;
	unsigned int temp;
	int i, n;

	memcpy(w, key, nk*4);
	memcpy(&rcon, "\1\0\0\0", 4);
	n = nk/2;
	prev.d = w[n-1];
	for (i = n; i < (nr+1)*2; i++) {
		temp = prev.w[1];
		if (i % n == 0) {
			RotWord(&temp);
			SubWord(&temp);
			temp ^= rcon;
			XtimeWord(&rcon);
		} else if (nk > 6 && i % n == 2) {
			SubWord(&temp);
		}
		prev.d = w[i-n];
		prev.w[0] ^= temp;
		prev.w[1] ^= prev.w[0];
		w[i] = prev.d;
	}
}

int inaccel_AES_set_encrypt_key(const unsigned char *userKey, const int bits, inaccel_AES_KEY *key) {
	unsigned long long *rk;

	if (!userKey || !key)
		return -1;
	if (bits != 128 && bits != 192 && bits != 256)
		return -2;

	rk = (unsigned long long*)key->rd_key;

	if (bits == 128)
		key->rounds = 10;
	else if (bits == 192)
		key->rounds = 12;
	else
		key->rounds = 14;

	KeyExpansion(userKey, rk, key->rounds, bits/32);
	return 0;
}

int inaccel_AES_set_decrypt_key(const unsigned char *userKey, const int bits, inaccel_AES_KEY *key) {
	return inaccel_AES_set_encrypt_key(userKey, bits, key);
}
