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
#define SSL_OK                       0x0001
#define ERR_SHA_INIT_CTX_FAIL        0x1002
#define ERR_SHA_UPDATE_FAIL          0x1003
#define ERR_SHA_FINAL_FAIL           0x1004
#define ERR_SHA_HASH_INV_PARAMS      0x1005
#define ERR_READ_HASH_FAIL           0x1006
#define ERR_HASH_DIFFER              0x1007
#define ERR_RAND_NOT_SUPPORTED       0x1008
#define ERR_RAND_FAIL                0x1009
#define ERR_AES_PBKDF_INV_PARAMS     0x100A
#define ERR_AES_ENC_INV_PARAMS       0x100B
#define ERR_AES_ENC_EVP_INIT         0x100C
#define ERR_AES_ENC_SET_IVLEN        0x100D
#define ERR_AES_ENC_EVP_INIT_KEY     0x100E
#define ERR_AES_ENC_EVP_AAD          0x100F
#define ERR_AES_ENC_EVP_ENCRYPT      0x1010
#define ERR_AES_ENC_EVP_FINAL        0x1011
#define ERR_AES_ENC_EVP_MAC          0x1012
#define ERR_AES_DEC_INV_PARAMS       0x1013
#define ERR_AES_DEC_EVP_INIT         0x1014
#define ERR_AES_DEC_SET_IVLEN        0x1015
#define ERR_AES_DEC_EVP_INIT_KEY     0x1016
#define ERR_AES_DEC_EVP_AAD          0x1017
#define ERR_AES_DEC_EVP_DECRYPT      0x1018
#define ERR_AES_DEC_EVP_FINAL        0x1019
#define ERR_AES_DEC_EVP_MAC          0x101A

/* Storage Error Codes */
#define STORAGE_OK                   0x0000
#define ERR_USER_NOT_FOUND           0x2001
#define ERR_NO_USER_PROVIDED         0x2002
#define ERR_MEM_LEAK                 0x2003
#define ERR_STORAGE_MEM_ALLOC        0x2004
#define ERR_OPEN_PASSW_FILE          0x2005
#define ERR_OPEN_SALT_FILE           0x2006
#define ERR_READ_SALT_FILE           0x2007

#endif