# mping — portable build for macOS (BSD userland) and Linux (GNU or musl)

PREFIX   ?= /usr/local
BINDIR   ?= $(PREFIX)/bin
MANDIR   ?= $(PREFIX)/share/man

# Compiler: `cc` is the POSIX default; resolves to clang on macOS and gcc/clang on Linux
CC       ?= cc
# -fno-common: avoids macOS ld warning about __DATA,__common alignment (0x8000 vs segment max 0x4000)
# when merging tentative definitions; also matches modern GCC defaults on Linux.
CFLAGS   ?= -Wall -Wextra -O2 -fno-common
CPPFLAGS ?=
LDFLAGS  ?= -lm

# Object name (override if you need e.g. mping-linux)
PROG     ?= mping

# Single compile flag line (avoids double spaces when CPPFLAGS is empty)
BUILD_CFLAGS := $(strip $(CPPFLAGS) $(CFLAGS))

.PHONY: all clean install uninstall help

all: $(PROG)

$(PROG): mping.c mping.h
	$(CC) $(BUILD_CFLAGS) -o $(PROG) mping.c $(LDFLAGS)

install: $(PROG)
	install -d "$(DESTDIR)$(BINDIR)"
	install -m 755 $(PROG) "$(DESTDIR)$(BINDIR)/$(PROG)"
	install -d "$(DESTDIR)$(MANDIR)/man8"
	install -m 644 mping.8 "$(DESTDIR)$(MANDIR)/man8/$(PROG).8"

uninstall:
	rm -f "$(DESTDIR)$(BINDIR)/$(PROG)" "$(DESTDIR)$(MANDIR)/man8/$(PROG).8"

clean:
	rm -f $(PROG) mping.c~ mping.h~ mping.8~ a.out core *.o

help:
	@echo "Targets:  all (default)  clean  install  uninstall  help"
	@echo "Variables: PREFIX=$(PREFIX)  BINDIR=$(BINDIR)  MANDIR=$(MANDIR)"
	@echo "           CC=$(CC)  CFLAGS=$(CFLAGS)  DESTDIR=$(DESTDIR)"
	@echo "Example:   sudo make install"
	@echo "          make install PREFIX=\$$HOME/.local DESTDIR="
