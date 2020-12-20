/** @file defines.h */
#ifndef __DEFINES_H__
#define __DEFINES_H__

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifndef PIPASS_VERSION
    #define PIPASS_VERSION 0x0001   /**< Current PiPass version */
#endif

#define PACKET_SIZE 8              /**< USB packet size */

#define CPU_ID_SIZE         16     /**< Size of the CPU ID buffer */

#define MASTER_PIN_SIZE_WITH_PEPPER  (PEPPER_SIZE + MASTER_PIN_SIZE)    /**< Size of the buffer containing the pin and the pepper */
#define MASTER_PIN_SIZE    4               /**< Size of the master PIN */
#define PEPPER_SIZE         CPU_ID_SIZE    /**< Hardware pepper size */
#define SALT_SIZE           64             /**< Salt size used in SHA256 hashing and PBKDF2 operations */
#define SHA256_DGST_SIZE    32             /**< Size of a SHA256 digest */
#define SHA256_HEX_SIZE     64             /**< Size of a SHA256 digest converted in hex representation */
#define PBKDF2_ITERATIONS   256            /**< Number of PBKDF2 iterations used when derivating keys */
#define AES256_KEY_SIZE     32             /**< Size of a AES256-GCM key */
#define IV_SIZE             16             /**< Size of a AES256-GCM initialization vector */
#define MAC_SIZE            16             /**< Size of a AES256-GCM message authentication code */

#define CREDENTIALS_FIELD_LIMIT ((1 << 16) - 1)   /**< Maximum length for a credential field */
#define DB_HEADER_SIZE          (2 + 4 + SHA256_DGST_SIZE + SALT_SIZE + AES256_KEY_SIZE + MAC_SIZE + IV_SIZE)  /**< Size of the database header */


#define S_TTY    "/dev/ttyGS0"   /**< Serial port used for communicating via USART */
#define SERIAL_PKT_SIZE 256      /**< Size of a serial packet */

#define FP_PORT  "/dev/ttyS0"   /**< Serial port used for communicating with the fingerprint sensor */

#define MEDIA_DIR "./media"            /**< The directory containing various media files */
#define IMG_DIR   MEDIA_DIR"/img"      /**< The directory containing images */
#define FONTS_DIR MEDIA_DIR"/fonts"    /**< The directory containing fonts */

#define REFRESH_RATE 100000

typedef uint8_t * usb_packet;
typedef uint8_t   BYTE;
typedef uint32_t  PIPASS_ERR;
typedef uint16_t  KEY;

#define MIN(x,y) (((x) < (y)) ? (x) : (y))
#define MAX(x,y) (((x) > (y)) ? (x) : (y))

#endif