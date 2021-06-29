CFLAGS = -Iinclude -O3 -Wall -fPIC
LDFLAGS = -shared
LDLIBS = -lcoral-api

libinaccel-crypto.so: crypto/aes/aes_cbc.c crypto/aes/aes_cfb.c crypto/aes/aes_core.c crypto/aes/aes_ctr.c

lib%.so:
	$(LINK.c) $^ $(LOADLIBES) $(LDLIBS) $(OUTPUT_OPTION)

clean:
	$(RM) libinaccel-crypto.so
