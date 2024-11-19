
CFLAGS = -Wall -g -I/usr/include/fuse3
OBJS := daemon.o nvmeof.o endpoint.o tcp.o null.o uring.o base64.o tls.o \
	fuse.o configdb.o
LIBS := -luring -lpthread -luuid -lcrypto -lssl -lz -lkeyutils -lfuse3 -lsqlite3

all: nofuse xdp_drop_port.o

nofuse: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

xdp_drop_port.o: xdp_drop_port.c
	clang $(CFLAGS) -target bpf -c $< -o $@

%.o: %.c common.h utils.h ops.h firmware.h
	$(CC) $(CFLAGS) -c -o $@ $<

tcp.o: tcp.c common.h utils.h tcp.h tls.h
	$(CC) $(CFLAGS) -c -o $@ $<

firmware.h:
	git show --no-abbrev-commit | head -1 | cksum | cut -f 1 -d ' ' | base32 | sed -n 's/\(.\{8\}\).*/static char firmware_rev[] = "\1";/p' > $@

clean:
	rm -f firmware.h *.o nofuse
