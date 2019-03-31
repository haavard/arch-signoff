PACKAGE_NAME = signoff

VERSION := $(shell cd .. && python3 setup.py -V)

all: $(PACKAGE_NAME).1

$(PACKAGE_NAME).1: $(PACKAGE_NAME).1.txt Makefile
	$(V_GEN) a2x \
		-d manpage \
		-f manpage \
		-a manversion="$(PACKAGE_NAME) $(VERSION)" \
		-a manmanual="$(PACKAGE_NAME) manual" $<

.PHONY: clean
clean:
	$(RM) $(PACKAGE_NAME).1
