
CFLAGS = -g -Os -Wall -pipe
LDFLAGS =
LDFLAGS_BIN =
LDLIBS = -lc -lcrypto -lssl
LDLIBS_BIN =

ifneq ($(CONFIG_SHARED_LIBRARY),)
CFLAGS += -fPIC
LDFLAGS_BIN += -Wl,-rpath . -L.
LDLIBS_BIN += -lsexpak
LIBNAME = libsexpak.so
else
BINDEPS = sexpak.o
endif

TARGETS = $(LIBNAME) sextest sip

%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

all: $(TARGETS)

clean:
	rm -f *.o $(TARGETS)

libsexpak.so: sexpak.o
	$(LD) $(LDFLAGS) -shared -o $@ $^ ${LDLIBS}

sextest: $(BINDEPS) sextest.o
	$(CC) $(LDFLAGS_BIN) $(LDFLAGS) -o $@ $^ ${LDLIBS} ${LDLIBS_BIN}

sip: $(BINDEPS) sip.o
	$(CC) $(LDFLAGS_BIN) $(LDFLAGS) -o $@ $^ ${LDLIBS} ${LDLIBS_BIN}
