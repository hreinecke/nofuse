
CFLAGS = -Wall -g -I/usr/include/fuse3
DAEMON_OBJS := daemon.o
OBJS := nvmeof.o port.o queue.o namespace.o tcp.o null.o uring.o \
	base64.o tls.o

ETCD_OBJS := etcd_backend.o etcd_watcher.o
CURL_OBJS := etcd_client_curl.o etcd_curl.o
SOCKET_OBJS := etcd_client_socket.o etcd_socket.o http_parser.o

LIBS := -luring -lpthread -luuid -lcrypto -lssl -lz -lkeyutils -lfuse3
ETCD_LIBS := -ljson-c
CURL_LIBS := -lcurl

DAEMON_OBJS += fuse_etcd.o
LIBS += $(ETCD_LIBS)
OBJS += $(ETCD_OBJS)

all: nofuse portd nvmetd xdp_drop_port.o base64_test watcher

nofuse: $(DAEMON_OBJS) $(SOCKET_OBJS) $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

portd: portd.o $(SOCKET_OBJS) $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

nvmetd: nvmetd.o inotify.o $(SOCKET_OBJS) $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

watcher: watcher.o etcd_watcher.o $(SOCKET_OBJS) $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

xdp_drop_port.o: xdp_drop_port.c
	clang $(CFLAGS) -target bpf -c $< -o $@

base64_test: base64_test.o base64.o
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c common.h utils.h ops.h firmware.h
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
