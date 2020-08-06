#ifndef __ERRORS_H__
#define __ERRORS_H__

/* USB Error Codes */
#define USB_OK                       0x0000
#define ERR_SEND_DEVICE_NOT_OPEN     0x0002
#define ERR_SEND_PACKET_NULL         0x0003
#define ERR_SEND_WRITE_DEVICE        0x0004
#define ERR_SEND_PKG_NOT_FULLY_SENT  0x0005
#define ERR_ALLOC_MEM                0x0006
#define ERR_KEY_NOT_DEFINED          0xF001

/* Crypto Error Codes */
#define CRYPTO_OK                    0x0000
#define SSL_OK                       0x1001
#define ERR_SHA_INIT_CTX_FAIL        0x1002
#define ERR_SHA_UPDATE_FAIL          0x1003
#define ERR_SHA_FINAL_FAIL           0x1004
#define ERR_SHA_HASH_INV_PARAMS      0x1005
#define ERR_READ_HASH_FAIL           0x1006
#define ERR_HASH_DIFFER              0x1007
#define ERR_HWRNG_OPEN_FAIL          0x1008
#define ERR_HWRNG_READ_FAIL          0x1009
#define ERR_AES_PBKDF_INV_PARAMS     0x100A
#endif