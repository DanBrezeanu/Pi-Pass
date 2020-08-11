CC=gcc
OBJS=$(wildcard crypto/obj/*.o) $(wildcard session/obj/*.o) $(wildcard database/obj/*.o) $(wildcard storage/obj/*.o) $(wildcard usb/obj/*.o)
LDFLAGS=../lib
LDLIBS=-lssl -lcrypto -lfastpbkdf2
MKDIR=mkdir -p
EXEC=pipass

.PHONY: all

all:
	@$(MKDIR) crypto/obj session/obj database/obj storage/obj usb/obj
	+$(MAKE) -C crypto
	+$(MAKE) -C database
	+$(MAKE) -C storage
	+$(MAKE) -C usb
	+$(MAKE) -C session
	$(CC) $(OBJS) $(LDFLAGS) -o $(EXEC) $(LDLIBS)
	


