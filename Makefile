PACKAGE_NAME = signoff

VERSION := $(shell git describe --dirty 2>/dev/null)

MANPAGES = \
	man/signoff.1


all: $(MANPAGES)

doc: $(MANPAGES)
man/%: man/%.txt Makefile
	$(V_GEN) a2x \
		-d manpage \
		-f manpage \
		-a manversion="$(PACKAGE_NAME) $(VERSION)" \
		-a manmanual="$(PACKAGE_NAME) manual" $<

.PHONY: all
