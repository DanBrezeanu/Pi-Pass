#ifndef __DEFINES_H__
#define __DEFINES_H__

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef PIPASS_VERSION
    #define PIPASS_VERSION 0x0001
#endif

#ifndef DEFAULT_GUARD_VALUE
    #define DEFAULT_GUARD_VALUE 0x05F403F2
#endif 

#define PACKET_SIZE 8

#define CPU_ID_SIZE         16

#define MASTER_PASS_SIZE_WITH_PEPPER  (PEPPER_SIZE + MASTER_PASS_SIZE)
#define MASTER_PASS_SIZE    4
#define PEPPER_SIZE         CPU_ID_SIZE
#define SALT_SIZE           64
#define SHA256_DGST_SIZE    32
#define SHA256_HEX_SIZE     64
#define PBKDF2_ITERATIONS   256
#define AES256_KEY_SIZE     32
#define IV_SIZE             16
#define MAC_SIZE            16

#define CREDENTIALS_FIELD_LIMIT ((1 << 16) - 1)
#define CREDENTIAL_HEADER_SIZE  (4 + 2*5)
#define DB_HEADER_SIZE          (2 + 4 + SHA256_DGST_SIZE + SALT_SIZE)


#define S_TTY    "/dev/ttyGS0"
#define SERIAL_PKT_SIZE 20

typedef uint8_t * usb_packet;
typedef uint8_t   BYTE;
typedef uint32_t  PIPASS_ERR;
typedef uint16_t  KEY;

#endif