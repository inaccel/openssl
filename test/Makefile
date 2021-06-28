CFLAGS = -O3 -Wall
LDLIBS = -lcoral-api -lcrypto -linaccel-crypto

test: aes_cbc aes_cfb aes_ctr

aes_cbc: aes_cbc_test
	./aes_cbc_test

aes_cfb: aes_cfb_test
	./aes_cfb_test

aes_ctr: aes_ctr_test
	./aes_ctr_test
