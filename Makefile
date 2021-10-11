
CFLAGS = -Wall -g
OBJS := daemon.o nvmeof.o pseudo_target.o tcp.o

all: nofuse

nofuse: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ -lpthread

%.o: %.c common.h utils.h
	$(CC) $(CFLAGS) -c -o $@ $<

tcp.o: tcp.c common.h utils.h tcp.h
	$(CC) $(CFLAGS) -c -o $@ $<
