#ifndef __DEFINES_H__
#define __DEFINES_H__

#include <stdint.h>

#define PACKET_SIZE 8

#define MASTER_PASS_SIZE    4
#define SALT_SIZE           64
#define SHA256_DGST_SIZE    32
#define SHA256_HEX_SIZE     64
#define PBKDF2_ITERATIONS   256
#define AES256_KEY_SIZE     32
#define IV_SIZE             16
#define MAC_SIZE            16

typedef uint8_t * usb_packet;
typedef uint8_t   BYTE;
typedef uint32_t  USB_ERR;
typedef uint32_t  CRYPTO_ERR;
typedef uint32_t  STORAGE_ERR;
typedef uint16_t  KEY;



#endif