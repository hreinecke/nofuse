
CFLAGS = -Wall -g -I/usr/include/fuse3
DAEMON_OBJS := daemon.o
NVME_OBJS := nvmeof.o port.o queue.o namespace.o tcp.o null.o uring.o tls.o

ETCD_OBJS := etcd_backend.o etcd_watcher.o configfs.o
CURL_OBJS := etcd_client_curl.o etcd_curl.o base64.o
SOCKET_OBJS := etcd_client_socket.o etcd_socket.o base64.o http_parser.o

NVME_LIBS := -luring -lpthread -lcrypto -lssl -lz -lkeyutils
ETCD_LIBS := -luuid -ljson-c
CURL_LIBS := -lcurl

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

all: nofuse portd discd nvmetd xdp_drop_port.o watcher

nofuse: $(DAEMON_OBJS) $(CURL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ -lfuse3 $(CURL_LIBS) $(DAEMON_LIBS)

portd: $(PORTD_OBJS) $(CURL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(PORTD_LIBS) $(CURL_LIBS)

discd: $(DISCD_OBJS) $(CURL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(DISCD_LIBS) $(CURL_LIBS)

nvmetd: nvmetd.o inotify.o $(CURL_OBJS) $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(CURL_LIBS) $(LIBS)

watcher: watcher.o etcd_watcher.o configfs.o $(CURL_OBJS) $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(CURL_LIBS) $(LIBS)

xdp_drop_port.o: xdp_drop_port.c
	clang $(CFLAGS) -target bpf -c $< -o $@

%.o: %.c common.h etcd_client.h utils.h ops.h firmware.h
	$(CC) $(CFLAGS) -c -o $@ $<

tcp.o: tcp.c common.h utils.h tcp.h tls.h
	$(CC) $(CFLAGS) -c -o $@ $<

etcd_client_curl.o: etcd_client.c
	$(CC) $(CFLAGS) -D_USE_CURL -c -o $@ $<

etcd_client_socket.o: etcd_client.c
	$(CC) $(CFLAGS) -c -o $@ $<

etcd_curl.o: etcd_curl.c
	$(CC) $(CFLAGS) -D_USE_CURL -c -o $@ $<

firmware.h: gen_firmware_rev.sh
	bash ./$< $@

clean:
	rm -f firmware.h *.o nofuse
