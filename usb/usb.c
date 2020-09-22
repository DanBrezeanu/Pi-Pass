#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#include <stdio.h>
#include <ctype.h>
#include <string.h>

#include <errors.h>
#include <usb_utils.h>

USB_ERR send_packet(int fd, usb_packet packet) {
    if (fd == -1) {
        return ERR_SEND_DEVICE_NOT_OPEN;
    }

    if (packet == NULL) {
        return ERR_SEND_PACKET_NULL;
    }

    int32_t _bytes_sent = write(fd, packet, PACKET_SIZE);

    if (_bytes_sent == -1) {
        return ERR_SEND_WRITE_DEVICE;
    }

    if (_bytes_sent != PACKET_SIZE) {
        return ERR_SEND_PKG_NOT_FULLY_SENT;
    }

    return USB_OK;
}

usb_packet create_usb_packet(KEY key) {
    usb_packet pack = calloc(PACKET_SIZE, sizeof(BYTE));

    if (pack == NULL)
        return NULL;

    pack[0] = modifier(key);
    pack[2] = key(key);

    return pack;
}


USB_ERR send_string(int fd, BYTE *str) {
    for (int32_t i = 0; i < strlen(str); ++i) {
        KEY _key = key_from_byte(str[i]);
        if (_key == ERR_KEY_NOT_DEFINED)
            return ERR_KEY_NOT_DEFINED;

        usb_packet packet = create_usb_packet(_key);
        if (packet == NULL)
            return ERR_ALLOC_MEM;

        USB_ERR res = send_packet(fd, packet);
        if (res != USB_OK)
            return res;

        packet = create_usb_packet(KEY_NONE);
        if (packet == NULL)
            return ERR_ALLOC_MEM;

        res = send_packet(fd, packet);
        free(packet);

        if (res != USB_OK)
            return res;
    }

    return USB_OK;
}


// int main(int argc, char *argv[])
// {
//     int fd = open("/dev/hidg0", O_RDWR);

//     if (fd == -1) {
//         printf("Could not ope\n");
//         return 1;
//     }

//     USB_ERR res = send_string(fd, "Test string");

//     return res;
// }