#ifndef __ERRORS_H__
#define __ERRORS_H__

/* USB Error Codes */
#define USB_OK                         0x0000
#define ERR_SEND_DEVICE_NOT_OPEN       0x0002
#define ERR_SEND_PACKET_NULL           0x0003
#define ERR_SEND_WRITE_DEVICE          0x0004
#define ERR_SEND_PKG_NOT_FULLY_SENT    0x0005
#define ERR_ALLOC_MEM                  0x0006
#define ERR_KEY_NOT_DEFINED            0xF001

/* Crypto Error Codes */
#define CRYPTO_OK                      0x0000
#define SSL_OK                         0x0001
#define ERR_SHA_INIT_CTX_FAIL          0x1002
#define ERR_SHA_UPDATE_FAIL            0x1003
#define ERR_SHA_FINAL_FAIL             0x1004
#define ERR_SHA_HASH_INV_PARAMS        0x1005
#define ERR_READ_HASH_FAIL             0x1006
#define ERR_HASH_DIFFER                0x1007
#define ERR_RAND_NOT_SUPPORTED         0x1008
#define ERR_RAND_FAIL                  0x1009
#define ERR_AES_PBKDF_INV_PARAMS       0x100A
#define ERR_AES_ENC_INV_PARAMS         0x100B
#define ERR_AES_ENC_EVP_INIT           0x100C
#define ERR_AES_ENC_SET_IVLEN          0x100D
#define ERR_AES_ENC_EVP_INIT_KEY       0x100E
#define ERR_AES_ENC_EVP_AAD            0x100F
#define ERR_AES_ENC_EVP_ENCRYPT        0x1010
#define ERR_AES_ENC_EVP_FINAL          0x1011
#define ERR_AES_ENC_EVP_MAC            0x1012
#define ERR_AES_DEC_INV_PARAMS         0x1013
#define ERR_AES_DEC_EVP_INIT           0x1014
#define ERR_AES_DEC_SET_IVLEN          0x1015
#define ERR_AES_DEC_EVP_INIT_KEY       0x1016
#define ERR_AES_DEC_EVP_AAD            0x1017
#define ERR_AES_DEC_EVP_DECRYPT        0x1018
#define ERR_AES_DEC_EVP_FINAL          0x1019
#define ERR_AES_DEC_EVP_MAC            0x101A
#define ERR_RAW2HEX_INV_PARAMS         0x101B
#define ERR_CRYPTO_MEM_ALLOC           0x101C
#define ERR_CRYPTO_KEK_INV_PARAMS      0x101D
#define ERR_CRYPTO_KEK_MEM_LEAK        0x101E
#define ERR_CRYPTO_DEK_BLOB_INV_PARAMS 0x101F
#define ERR_CRYPTO_DEK_BLOB_MEM_LEAK   0x1020
#define ERR_CRYPTO_GEN_HASH_INV_PARAMS 0x1021
#define ERR_CRYPTO_HASH_MEM_LEAK       0x1022
#define ERR_BUF_SANITY_CHECK_FAIL      0x1023
#define ERR_ENC_DB_FIELD_INV_PARAMS    0x1024
#define ERR_ENC_DB_INV_FIELD           0x1025
#define ERR_ENC_CRED_INV_PARAMS        0x1026
#define ERR_ENC_CRED_MEM_LEAK          0x1027
#define ERR_ENC_CRED_MISSING_DEK       0x1028
#define ERR_ENC_CRED_MISSING_KEK       0x1029
#define ERR_ENC_CRED_MEM_ALLOC         0x102A
#define ERR_ENC_CRED_DEK_DECRYPT_FAIL  0x102B
#define ERR_DEC_DB_FIELD_INV_PARAMS    0x102C
#define ERR_DEC_DB_FIELD_MEM_LEAK      0x102D
#define ERR_DEC_DB_INV_FIELD           0x102E
#define ERR_DEC_DB_FIELD_MISSING_FIELD 0x102F
#define ERR_DEC_CRED_INV_PARAMS        0x1030
#define ERR_DEC_CRED_MISSING_KEK       0x1031
#define ERR_DEC_CRED_MISSING_DEK       0x1032
#define ERR_CRYPTO_MEM_LEAK            0x1033
#define ERR_DEC_CRED_MEM_LEAK          0x1034
#define ERR_DEC_CRED_MEM_ALLOC         0x1035


/* Storage Error Codes */
#define STORAGE_OK                     0x0000
#define ERR_USER_NOT_FOUND             0x2001
#define ERR_NO_USER_PROVIDED           0x2002
#define ERR_MEM_LEAK                   0x2003
#define ERR_STORAGE_MEM_ALLOC          0x2004
#define ERR_OPEN_PASSW_FILE            0x2005
#define ERR_OPEN_SALT_FILE             0x2006
#define ERR_READ_SALT_FILE             0x2007
#define ERR_REGISTER_USER_INV_PARAMS   0x2008
#define ERR_USER_HASH_RAW2HEX          0x2009
#define ERR_CREATE_USER_DIR_INV_PARAMS 0x200A
#define ERR_USER_DIR_ALREADY_EXISTS    0x200B
#define ERR_MKDIR_FAIL                 0x200C
#define ERR_CRYPTO_DEK_BLOB_ENCRYPT    0x200D
#define ERR_VERIFY_DIR_INV_PARAMS      0x200E
#define ERR_STORE_DEK_BLOB_INV_PARAMS  0x200F
#define ERR_NO_FILE_PROVIDED           0x2010
#define ERR_STORE_OPEN_FILE            0x2011
#define ERR_STORE_WRITE_FILE           0x2012
#define ERR_STORE_FILE_INV_PARAMS      0x2013
#define ERR_STORE_HASH_INV_PARAMS      0x2014
#define ERR_DUMP_DB_INV_PARAMS         0x2015


/* Database Error Codes */
#define DB_OK                          0x0000
#define ERR_POPULATE_FIELD_INV_PARAMS  0x4001
#define ERR_FIELD_LIMIT_EXCEEDED       0x4002
#define ERR_INVALID_FIELD              0x4003
#define ERR_DB_MEM_LEAK                0x4004
#define ERR_DB_MEM_ALLOC               0x4005
#define ERR_RECALC_HEADER_INV_PARAMS   0x4006
#define ERR_DB_UPDATE_DEK_INV_PARAMS   0x4007
#define ERR_DB_MISSING_KEK             0x4008
#define ERR_DB_UPDATE_KEK_INV_PARAMS   0x4009
#define ERR_DB_UPDATE_LOGIN_INV_PARAMS 0x400A
#define ERR_ENC_DB_MEM_LEAK            0x400B
#define ERR_RAW_DB_INV_PARAMS          0x400C
#define ERR_RAW_DB_MEM_ALLOC           0x400D
#define ERR_RAW_DB_MEM_LEAK            0x400E

#endif