
CFLAGS = -Wall -g -I. -I/usr/include/fuse3
DAEMON_OBJS := daemon.o
NVME_OBJS := nvmeof.o port.o queue.o namespace.o tcp.o null.o uring.o tls.o

ETCD_OBJS := etcd/backend.o etcd/watcher.o configfs.o
NEON_OBJS := etcd/client.o etcd/neon.o etcd/base64.o

NVME_LIBS := -luring -lpthread -lcrypto -lssl -lz -lkeyutils
ETCD_LIBS := -luuid -ljson-c
NEON_LIBS := -lneon
LIBS := $(ETCD_LIBS)

DAEMON_OBJS += fuse_etcd.o
DAEMON_OBJS += $(ETCD_OBJS)
DAEMON_LIBS := $(ETCD_LIBS)
DAEMON_LIBS += -luuid

PORTD_OBJS := portd.o
PORTD_OBJS += $(ETCD_OBJS)
PORTD_OBJS += $(NVME_OBJS)
PORTD_LIBS := $(ETCD_LIBS)
PORTD_LIBS += $(NVME_LIBS)

DISCD_OBJS := discd.o
DISCD_OBJS += $(ETCD_OBJS)
DISCD_LIBS += $(ETCD_LIBS)

OBJS := $(ETCD_OBJS)

PRGS := nofuse portd discd nvmetd watcher

all: $(PRGS)

nofuse: $(DAEMON_OBJS) $(NEON_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ -lfuse3 $(NEON_LIBS) $(DAEMON_LIBS)

portd: $(PORTD_OBJS) $(NEON_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(PORTD_LIBS) $(NEON_LIBS)

discd: $(DISCD_OBJS) $(NEON_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(DISCD_LIBS) $(NEON_LIBS)

nvmetd: nvmetd.o inotify.o $(NEON_OBJS) $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(NEON_LIBS) $(LIBS)

watcher: watcher.o etcd/watcher.o configfs.o $(NEON_OBJS) $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(NEON_LIBS) $(LIBS)

xdp_drop_port.o: xdp_drop_port.c
	clang $(CFLAGS) -target bpf -c $< -o $@

%.o: %.c common.h etcd/client.h etcd/backend.h utils.h
	$(CC) $(CFLAGS) -c -o $@ $<

tcp.o: tcp.c common.h tcp.h ops.h etcd/backend.h tls.h

etcd/client.o: etcd/client.c etcd/base64.h common.h etcd/client.h

etcd/neon.o: etcd/neon.c etcd/client.h

configfs.o: configfs.c common.h configfs.h utils.h etcd/client.h etcd/backend.h

etcd/backend.o: etcd/backend.c common.h etcd/backend.h etcd/client.h firmware.h

firmware.h: gen_firmware_rev.sh
	bash ./$< $@

clean:
	rm -f firmware.h *.o $(OBJS) $(PRGS)
