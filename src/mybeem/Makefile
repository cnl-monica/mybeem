OBJECTS = beem.o capture.o sampling.o aggregation.o cache.o list.o queue.o config.o export.o sync.o ipfix.o packetIdent.o debug.o MurmurHash64.o
TARGET=beem

CC=gcc
CFLAGS+= -w -g -O2 -D_THREAD_SAFE -I/usr/include/libxml2
LDFLAGS+= -lpcap -lssl -lxml2 -lrt -lm -lsctp -lcrypto -lpthread -lndpi
lib_LTLIBRARIES = libcityhash.la
all: $(TARGET)


$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $+ $(LDFLAGS)
	
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)

install:
	mkdir -p $(prefix)/usr/sbin
	cp beem $(prefix)/usr/sbin/mybeem
	mkdir -p $(prefix)/etc/mybeem/
	cp config.xml $(prefix)/etc/mybeem/

