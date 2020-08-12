CC=gcc
LDFLAGS=-Llib/
LDLIBS=-lssl -lcrypto -lfastpbkdf2
MKDIR=mkdir -p
EXEC=pipass
OBJS=$(shell find ./ -name '*.o')

.PHONY: all

all:
	@$(MKDIR) crypto/obj session/obj database/obj storage/obj usb/obj
	@$(MAKE) -s -C crypto
	@$(MAKE) -s -C database
	@$(MAKE) -s -C storage
	@$(MAKE) -s -C usb
	@$(MAKE) -s -C session
	$(eval OBJS=$(shell find ./ -name '*.o'))
	@$(CC) $(OBJS) $(LDFLAGS) -o $(EXEC) $(LDLIBS)
	@echo "LD $(EXEC)"

clean:
	@+$(MAKE) clean -s -C crypto
	@+$(MAKE) clean -s -C database
	@+$(MAKE) clean -s -C storage
	@+$(MAKE) clean -s -C usb
	@+$(MAKE) clean -s -C session
	


