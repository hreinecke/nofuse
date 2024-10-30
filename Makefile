
CFLAGS = -Wall -g -DDEBUG_COMMANDS -I/usr/include/fuse3
OBJS := daemon.o nvmeof.o endpoint.o tcp.o null.o uring.o base64.o tls.o fuse.o
LIBS := -luring -lpthread -luuid -lcrypto -lssl -lz -lkeyutils -lfuse3

all: nofuse

nofuse: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

tls_key: tls_key.o
	$(CC) $(CFLAGS) -o $@ $^ -lz -lkeyutils

%.o: %.c common.h utils.h ops.h
	$(CC) $(CFLAGS) -c -o $@ $<

tcp.o: tcp.c common.h utils.h tcp.h tls.h
	$(CC) $(CFLAGS) -c -o $@ $<

tls_key.o: tls_key.c
	$(CC) $(CLAGS) -c -o $@ $^

clean:
	rm -f *.o nofuse
