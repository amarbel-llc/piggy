PREFIX ?= /usr
DESTDIR ?=
BINDIR ?= $(PREFIX)/bin
LIBDIR ?= $(PREFIX)/lib
MANDIR ?= $(PREFIX)/share/man

PLATFORMFILE := src/platform/$(shell uname | cut -d _ -f 1 | tr '[:upper:]' '[:lower:]').sh

BASHCOMPDIR ?= $(PREFIX)/share/bash-completion/completions
ZSHCOMPDIR ?= $(PREFIX)/share/zsh/site-functions
FISHCOMPDIR ?= $(PREFIX)/share/fish/vendor_completions.d

ifneq ($(WITH_ALLCOMP),)
WITH_BASHCOMP := $(WITH_ALLCOMP)
WITH_ZSHCOMP := $(WITH_ALLCOMP)
WITH_FISHCOMP := $(WITH_ALLCOMP)
endif
ifeq ($(WITH_BASHCOMP),)
ifneq ($(strip $(wildcard $(BASHCOMPDIR))),)
WITH_BASHCOMP := yes
endif
endif
ifeq ($(WITH_ZSHCOMP),)
ifneq ($(strip $(wildcard $(ZSHCOMPDIR))),)
WITH_ZSHCOMP := yes
endif
endif
ifeq ($(WITH_FISHCOMP),)
ifneq ($(strip $(wildcard $(FISHCOMPDIR))),)
WITH_FISHCOMP := yes
endif
endif

all:
	@echo "Piggy is a shell script, so there is nothing to do. Try \"make install\" instead."

install-common:


ifneq ($(strip $(wildcard $(PLATFORMFILE))),)
install: install-common
	@install -v -d "$(DESTDIR)$(LIBDIR)/piggy" && install -m 0644 -v "$(PLATFORMFILE)" "$(DESTDIR)$(LIBDIR)/piggy/platform.sh"
	@install -v -d "$(DESTDIR)$(BINDIR)/"
	@trap 'rm -f src/.piggy' EXIT; sed 's:.*PLATFORM_FUNCTION_FILE.*:source "$(LIBDIR)/piggy/platform.sh":' src/piggy.sh > src/.piggy && \
	install -v -d "$(DESTDIR)$(BINDIR)/" && install -m 0755 -v src/.piggy "$(DESTDIR)$(BINDIR)/piggy"
	@install -v -d "$(DESTDIR)$(MANDIR)/man1/" && install -m 0644 -v man/piggy.1 "$(DESTDIR)$(MANDIR)/man1/piggy.1"
else
install: install-common
	@trap 'rm -f src/.piggy' EXIT; sed '/PLATFORM_FUNCTION_FILE/d' src/piggy.sh > src/.piggy && \
	install -v -d "$(DESTDIR)$(BINDIR)/" && install -m 0755 -v src/.piggy "$(DESTDIR)$(BINDIR)/piggy"
	@install -v -d "$(DESTDIR)$(MANDIR)/man1/" && install -m 0644 -v man/piggy.1 "$(DESTDIR)$(MANDIR)/man1/piggy.1"
endif

uninstall:
	@rm -vrf \
		"$(DESTDIR)$(BINDIR)/piggy" \
		"$(DESTDIR)$(LIBDIR)/piggy" \
		"$(DESTDIR)$(MANDIR)/man1/piggy.1"

TESTS = $(sort $(wildcard tests/t[0-9][0-9][0-9][0-9]-*.sh))

test: $(TESTS)

$(TESTS):
	@$@ $(PIGGY_TEST_OPTS)

clean:
	$(RM) -rf tests/test-results/ tests/trash\ directory.*/

.PHONY: install uninstall install-common test clean $(TESTS)
