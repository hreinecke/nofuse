
CFLAGS = -Wall -g -DDEBUG_COMMANDS
OBJS := daemon.o nvmeof.o pseudo_target.o tcp.o null.o

all: nofuse

nofuse: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ -luring -lpthread -luuid

%.o: %.c common.h utils.h ops.h
	$(CC) $(CFLAGS) -c -o $@ $<

tcp.o: tcp.c common.h utils.h tcp.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o nofuse
