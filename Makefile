CC=$(CROSS_COMPILE)gcc
LDFLAGS=-Llib/ -L/usr/lib/python3.7/
LDLIBS=-lssl -lcrypto -lfastpbkdf2 -lpigpio -lpthread -lrt -lr502 -lpython3.7m -lserialport
MKDIR=mkdir -p
EXEC=pipass

.PHONY: all

all:
	@$(MKDIR) crypto/obj session/obj database/obj storage/obj usb/obj fingerprint/obj display/obj gpio/obj python_api/obj connection/obj
	$(eval OBJS=$(shell find ./ -name 'obj' -type d | xargs -I {} echo {}/\*.o))
	@$(MAKE) -s -C crypto
	@$(MAKE) -s -C database
	@$(MAKE) -s -C storage
	@$(MAKE) -s -C usb
	@$(MAKE) -s -C session
	@$(MAKE) -s -C fingerprint
	@$(MAKE) -s -C display
	@$(MAKE) -s -C gpio
	@$(MAKE) -s -C python_api
	@$(MAKE) -s -C connection
	@echo "   LD $(realpath $(EXEC))"
	@$(CC) $(OBJS) $(LDFLAGS) -o $(EXEC) $(LDLIBS)

clean:
	@+$(MAKE) clean -s -C crypto
	@+$(MAKE) clean -s -C database
	@+$(MAKE) clean -s -C storage
	@+$(MAKE) clean -s -C usb
	@+$(MAKE) clean -s -C session
	@+$(MAKE) clean -s -C fingerprint
	@+$(MAKE) clean -s -C display
	@+$(MAKE) clean -s -C gpio
	@+$(MAKE) clean -s -C python_api
	@+$(MAKE) clean -s -C connection
	


