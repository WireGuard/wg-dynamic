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
CLIENT_OBJS = wg_dynamic_client.o client.o
SERVER_OBJS = wg_dynamic_server.o
all: ${PROGS}

wg-dynamic-client: ${CLIENT_OBJS}
	${CC} ${LDFLAGS} ${CLIENT_OBJS} -o $@
wg-dynamic-server: ${SERVER_OBJS}
	${CC} ${LDFLAGS} ${SERVER_OBJS} -o $@
wg_dynamic_client.o: wg_dynamic_client.c client.h
client.o: client.c client.h
wg_dynamic_server.o: wg_dynamic_server.c

clean:
	rm -f ${PROGS} *.o *~
style:
	clang-format -i --style=file *.c *.h
