CC ?= gcc
LIBRARY_INCLUDES = 
LIBRARY_LDFLAGS = -D_REENTRANT -lpthread -lcapnp_c
CFLAGS_DEBUG = -g -Wall -Wextra -std=gnu11 -fsanitize=address -fsanitize=leak\
	-fsanitize=undefined
LDFLAGS_DEBUG = -fsanitize=address -fsanitize=leak -fsanitize=undefined
CFLAGS_OPT = -std=gnu11 -O2 -pipe -DNDEBUG
LDFLAGS_OPT =
CFLAGS ?= ${CFLAGS_DEBUG} ${LIBRARY_INCLUDES}
LDFLAGS ?= ${LDFLAGS_DEBUG} ${LIBRARY_LDFLAGS}
.PHONY: clean style
PROGS = wg-dynamic-client wg-dynamic-server
CLIENT_OBJS = wg_dynamic_client.o client.o protocol.capnp.o
SERVER_OBJS = wg_dynamic_server.o server.o protocol.capnp.o
all: ${PROGS}

wg-dynamic-client: ${CLIENT_OBJS}
	${CC} ${LDFLAGS} ${CLIENT_OBJS} -o $@
wg-dynamic-server: ${SERVER_OBJS}
	${CC} ${LDFLAGS} ${SERVER_OBJS} -o $@

wg_dynamic_client.o: wg_dynamic_client.c client.h
client.o: client.c client.h wireguard.h
wg_dynamic_server.o: wg_dynamic_server.c server.h
server.o: server.c server.h wireguard.h
wireguard.o: wireguard.c wireguard.h
protocol.capnp.o: protocol.capnp.c

# capnproto
protocol.capnp.h: protocol.capnp.c
	;
protocol.capnp.c: protocol.capnp
	capnpc protocol.capnp -oc
%.capnp: ;

clean:
	rm -f ${PROGS} *.o *~
style:
	find . -type f \( -name "*.c" -or -name "*.h" \) -and \
	-not \( -name "*.capnp.c" -or -name "*.capnp.h" \) | \
	xargs clang-format -i --style=file
