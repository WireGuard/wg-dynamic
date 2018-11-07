CC ?= gcc
CFLAGS_DEBUG = -g -Wall -Wextra -std=gnu11 -fsanitize=address -fsanitize=leak\
	-fsanitize=undefined
LDFLAGS_DEBUG = -fsanitize=address -fsanitize=leak -fsanitize=undefined
CFLAGS_OPT = -std=gnu11 -O2 -pipe -DNDEBUG
LDFLAGS_OPT =
CFLAGS ?= ${CFLAGS_DEBUG}
LDFLAGS ?= ${LDFLAGS_DEBUG}
.PHONY: clean style
PROGS = wg-dynamic-client wg-dynamic-server
CLIENT_OBJS = wg-dynamic-client.o
SERVER_OBJS = wg-dynamic-server.o
all: ${PROGS}

client: ${CLIENT_OBJS}
	${CC} ${LDFLAGS} ${CLIENT_OBJS} -o $@
server: ${SERVER_OBJS}
	${CC} ${LDFLAGS} ${SERVER_OBJS} -o $@
wg-dynamic-client.o: wg-dynamic-client.c
wg-dynamic-server.o: wg-dynamic-server.c

clean:
	rm -f ${PROGS} *.o *~
style:
	find . -type f \( -name "*.c" -or -name "*.h" \) -and \
	-not \( -name "*.capnp.c" -or -name "*.capnp.h" \) | \
	xargs clang-format -i --style=file
