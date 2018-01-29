
qstrip=$(strip $(subst ",,$(1)))
#"))

CFLAGS = -g -Os -Wall -pipe
LDFLAGS =
LDFLAGS_BIN =
LDLIBS = -lc -lcrypto -lssl
LDLIBS_BIN =

BINDEPS = sipop.o

ifneq ($(CONFIG_SPAK_SHARED_LIBRARY),)
CFLAGS += -fPIC
LDFLAGS_BIN += -Wl,-rpath . -L.
LDLIBS_BIN += -lspak
LIBNAME = libspak.so
else
BINDEPS += spak.o
endif

ifneq ($(CONFIG_SPAK_KEY_FILE),)
CFLAGS += -DCONFIG_SPAK_KEY_FILE=\"$(call qstrip,$(CONFIG_SPAK_KEY_FILE))\"
endif

ifneq ($(CONFIG_SPAK_CRT_FILE),)
CFLAGS += -DCONFIG_SPAK_CRT_FILE=\"$(call qstrip,$(CONFIG_SPAK_CRT_FILE))\"
endif

ifneq ($(CONFIG_SPAK_STATIC_CERT),)
CFLAGS += -DCONFIG_SPAK_STATIC_CERT=1
endif

TARGETS = $(LIBNAME) spaktest sip sipenc sipdec

%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

all: $(TARGETS)

clean:
	rm -f *.o $(TARGETS) spakcert.h

ifneq ($(CONFIG_SPAK_STATIC_CERT),)
spak.o: spakcert.h

spakcert.h:
ifeq ($(CONFIG_SPAK_KEY_FILE)$(CONFIG_SPAK_CRT_FILE),)
	$(error CONFIG_SPAK_KEY_FILE and CONFIG_SPAK_CRT_FILE are not set)
endif
	@echo [GEN] spakcert.h
	@echo -e "// Autogenerate static key/crt data source." > $@
	@echo -e "static char spak_key_data[] = " >> $@
ifneq ($(CONFIG_SPAK_KEY_FILE),)
	@sed 's/\(.*\)/"\1\\n"/g' $(CONFIG_SPAK_KEY_FILE) >> $@
else
	@echo -e "\"\"" >> $@
endif
	@echo -e ";\n" >> $@
	@echo -e "static char spak_crt_data[] = " >> $@
ifneq ($(CONFIG_SPAK_CRT_FILE),)
	@sed 's/\(.*\)/"\1\\n"/g' $(CONFIG_SPAK_CRT_FILE) >> $@
else
	@echo -e "\"\"" >> $@
endif
	@echo -e ";\n" >> $@
endif

libspak.so: spak.o
	$(LD) $(LDFLAGS) -shared -o $@ $^ ${LDLIBS}

spaktest: $(BINDEPS) spaktest.o
	$(CC) $(LDFLAGS_BIN) $(LDFLAGS) -o $@ $^ ${LDLIBS} ${LDLIBS_BIN}

sip: $(BINDEPS) sip.o
	$(CC) $(LDFLAGS_BIN) $(LDFLAGS) -o $@ $^ ${LDLIBS} ${LDLIBS_BIN}

sipenc: $(BINDEPS) sipenc.o
	$(CC) $(LDFLAGS_BIN) $(LDFLAGS) -o $@ $^ ${LDLIBS} ${LDLIBS_BIN}

sipdec: $(BINDEPS) sipdec.o
	$(CC) $(LDFLAGS_BIN) $(LDFLAGS) -o $@ $^ ${LDLIBS} ${LDLIBS_BIN}
