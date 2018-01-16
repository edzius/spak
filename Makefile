
CFLAGS += -g -Os -Wall -pipe
CFLAGS += -fPIC
LDFLAGS = -lcrypto -lssl

OBJECTS = sexpak.o
TARGET = libsexpak.so

%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(LD) $(LDFLAGS) -shared -o ${TARGET} $^ ${LDLIBS}

clean:
	rm -f *.o *.so
