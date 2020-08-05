CC=gcc

.PHONY: usb

usb: usb/usb.c usb/usb_utils.c
	gcc usb/usb.c usb/usb_utils.c -Wall -std=gnu99 -Iusb/include -o usb-ex