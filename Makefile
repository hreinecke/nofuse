BACKEND = ETCD
CFLAGS = -Wall -g -I/usr/include/fuse3
OBJS := daemon.o nvmeof.o port.o queue.o tcp.o null.o uring.o \
	base64.o tls.o

SQL_OBJS := configdb.o fuse.o
ETCD_OBJS := etcd_client.o fuse_etcd.o etcd_backend.o

LIBS := -luring -lpthread -luuid -lcrypto -lssl -lz -lkeyutils -lfuse3

SQL_LIBS := -lsqlite3
ETCD_LIBS := -ljson-c -lcurl

ifeq ($(BACKEND),ETCD)
CFLAGS += -DNOFUSE_ETCD
LIBS += $(ETCD_LIBS)
OBJS += $(ETCD_OBJS)
else
LIBS += $(SQL_LIBS)
OBJS += $(SQL_OBJS)
endif

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
