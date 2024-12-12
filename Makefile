BACKEND = ETCD
CFLAGS = -Wall -g -I/usr/include/fuse3
DAEMON_OBJS := daemon.o
OBJS := nvmeof.o port.o queue.o namespace.o tcp.o null.o uring.o \
	base64.o tls.o

SQL_OBJS := configdb.o
ETCD_OBJS := etcd_client.o etcd_backend.o

LIBS := -luring -lpthread -luuid -lcrypto -lssl -lz -lkeyutils -lfuse3

SQL_LIBS := -lsqlite3
ETCD_LIBS := -ljson-c -lcurl

ifeq ($(BACKEND),ETCD)
CFLAGS += -DNOFUSE_ETCD
DAEMON_OBJS += fuse_etcd.o
LIBS += $(ETCD_LIBS)
OBJS += $(ETCD_OBJS)
else
DAEMON_OBJS += fuse.o
LIBS += $(SQL_LIBS)
OBJS += $(SQL_OBJS)
endif

all: nofuse xdp_drop_port.o base64_test

nofuse: $(DAEMON_OBJS) $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

portd: portd.o $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

nvmetd: nvmetd.o inotify.o
	$(CC) $(CFLAGS) -o $@ $^

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
