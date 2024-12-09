
CFLAGS = -Wall -g -I/usr/include/fuse3
OBJS := daemon.o nvmeof.o port.o queue.o tcp.o null.o uring.o \
	base64.o tls.o fuse.o configdb.o etcd_client.o
LIBS := -luring -lpthread -luuid -lcrypto -lssl -lz -lkeyutils \
	-ljson-c -lcurl -lfuse3 -lsqlite3

all: nofuse xdp_drop_port.o base64_test

nofuse: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

xdp_drop_port.o: xdp_drop_port.c
	clang $(CFLAGS) -target bpf -c $< -o $@

base64_test: base64_test.o base64.o
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c common.h utils.h ops.h firmware.h
	$(CC) $(CFLAGS) -c -o $@ $<

tcp.o: tcp.c common.h utils.h tcp.h tls.h
	$(CC) $(CFLAGS) -c -o $@ $<

firmware.h: gen_firmware_rev.sh
	bash ./$< $@

clean:
	rm -f firmware.h *.o nofuse
