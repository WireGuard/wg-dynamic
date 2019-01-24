# SPDX-License-Identifier: MIT
#
# Copyright (C) 2019 WireGuard LLC. All Rights Reserved.

PKG_CONFIG ?= pkg-config
PREFIX ?= /usr
DESTDIR ?=
SYSCONFDIR ?= /etc
BINDIR ?= $(PREFIX)/bin
LIBDIR ?= $(PREFIX)/lib
MANDIR ?= $(PREFIX)/share/man
BASHCOMPDIR ?= $(PREFIX)/share/bash-completion/completions
RUNSTATEDIR ?= /var/run
WITH_BASHCOMPLETION ?=

ifeq ($(WITH_BASHCOMPLETION),)
ifneq ($(strip $(wildcard $(BASHCOMPDIR))),)
WITH_BASHCOMPLETION := yes
endif
endif

PLATFORM ?= $(shell uname -s | tr '[:upper:]' '[:lower:]')

CFLAGS ?= -O3
CFLAGS += -std=gnu99 -D_GNU_SOURCE
CFLAGS += -Wall -Wextra
CFLAGS += -MMD -MP
CFLAGS += -DRUNSTATEDIR="\"$(RUNSTATEDIR)\""

ifeq ($(PLATFORM),linux)
LIBMNL_CFLAGS := $(shell $(PKG_CONFIG) --cflags libmnl 2>/dev/null)
LIBMNL_LDLIBS := $(shell $(PKG_CONFIG) --libs libmnl 2>/dev/null || echo -lmnl)
CFLAGS += $(LIBMNL_CFLAGS)
LDLIBS += $(LIBMNL_LDLIBS)
endif

ifneq ($(V),1)
BUILT_IN_LINK.o := $(LINK.o)
LINK.o = @echo "  LD      $@";
LINK.o += $(BUILT_IN_LINK.o)
BUILT_IN_COMPILE.c := $(COMPILE.c)
COMPILE.c = @echo "  CC      $@";
COMPILE.c += $(BUILT_IN_COMPILE.c)
endif

all: wg-dynamic-server wg-dynamic-client

wg-dynamic-client: wg-dynamic-client.o netlink.o
wg-dynamic-server: wg-dynamic-server.o netlink.o

ifneq ($(V),1)
clean:
	@for i in wg-dynamic *.o *.d; do echo "  RM      $$i"; $(RM) "$$i"; done
else
clean:
	$(RM) wg-dynamic *.o *.d
endif

install: wg
	@install -v -d "$(DESTDIR)$(BINDIR)" && install -v -m 0755 wg-dynamic-server "$(DESTDIR)$(BINDIR)/wg-dynamic-server"
	@install -v -d "$(DESTDIR)$(BINDIR)" && install -v -m 0755 wg-dynamic-server "$(DESTDIR)$(BINDIR)/wg-dynamic-client"
	@install -v -d "$(DESTDIR)$(MANDIR)/man8" && install -v -m 0644 man/wg-dynamic-server.8 "$(DESTDIR)$(MANDIR)/man8/wg-dynamic-server.8"
	@install -v -d "$(DESTDIR)$(MANDIR)/man8" && install -v -m 0644 man/wg-dynamic-client.8 "$(DESTDIR)$(MANDIR)/man8/wg-dynamic-client.8"
	@[ "$(WITH_BASHCOMPLETION)" = "yes" ] || exit 0; \
	install -v -d "$(DESTDIR)$(BASHCOMPDIR)" && install -v -m 0644 completion/wg-dynamic-server.bash-completion "$(DESTDIR)$(BASHCOMPDIR)/wg-dynamic-server"; \
	install -v -d "$(DESTDIR)$(BASHCOMPDIR)" && install -v -m 0644 completion/wg-dynamic-client.bash-completion "$(DESTDIR)$(BASHCOMPDIR)/wg-dynamic-client"

help:
	@cat INSTALL

.PHONY: clean install help

-include *.d
