CC=gcc

.PHONY: usb

usb: usb/usb.c usb/usb_utils.c
	gcc usb/usb.c usb/usb_utils.c \
	-Wall -std=gnu99 -Iusb/include -Iinclude/ -Icrypto/include -Llib/ \
	-o usb-ex \
	-lssl -lcrypto -lfastpbkdf2