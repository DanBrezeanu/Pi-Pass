/** @file errors.h */
#ifndef __ERRORS_H__
#define __ERRORS_H__

#define PIPASS_OK                      0x0000  /**< Success. */

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
#define SSL_OK                         0x0001  /**< Success value for OpenSSL functions */
#define ERR_SHA_INIT_CTX_FAIL          0x1002
#define ERR_SHA_UPDATE_FAIL            0x1003
#define ERR_SHA_FINAL_FAIL             0x1004
#define ERR_SHA_HASH_INV_PARAMS        0x1005
#define ERR_READ_HASH_FAIL             0x1006
#define ERR_HASH_DIFFER                0x1007
#define ERR_RAND_NOT_SUPPORTED         0x1008  /**< OpenSSL random is not supported. */
#define ERR_RAND_FAIL                  0x1009  /**< Random bytes generation has failed. */ 
#define ERR_AES_PBKDF_INV_PARAMS       0x100A  /**< Invalid parameters specified for #create_PBKDF2_key() function. */
#define ERR_AES_ENC_INV_PARAMS         0x100B  /**< Invalid paramters specified for #encrypt_aes256() function. */
#define ERR_AES_ENC_EVP_INIT           0x100C  /**< Encryption context creation failed */
#define ERR_AES_ENC_SET_IVLEN          0x100D  /**< Setting IV's length failed for the encryption context. */
#define ERR_AES_ENC_EVP_INIT_KEY       0x100E  /**< Setting the key for the encryption context failed. */
#define ERR_AES_ENC_EVP_AAD            0x100F  /**< Setting the AAD for the encryption context failed. */
#define ERR_AES_ENC_EVP_ENCRYPT        0x1010  /**< Setting the plaintext for the encryption context failed. */
#define ERR_AES_ENC_EVP_FINAL          0x1011  /**< Data encryption failed. */ 
#define ERR_AES_ENC_EVP_MAC            0x1012  /**< Extracting the MAC from the ciphertext failed */
#define ERR_AES_DEC_INV_PARAMS         0x1013
#define ERR_AES_DEC_EVP_INIT           0x1014
#define ERR_AES_DEC_SET_IVLEN          0x1015
#define ERR_AES_DEC_EVP_INIT_KEY       0x1016
#define ERR_AES_DEC_EVP_AAD            0x1017
#define ERR_AES_DEC_EVP_DECRYPT        0x1018
#define ERR_AES_DEC_EVP_FINAL          0x1019
#define ERR_AES_DEC_EVP_MAC            0x101A
#define ERR_RAW2HEX_INV_PARAMS         0x101B  /**< Invalid parameters for the #raw_to_hex() function. */
#define ERR_CRYPTO_MEM_ALLOC           0x101C  /**< `malloc()`, `calloc()` or `realloc()` failed to allocate memory. */
#define ERR_CRYPTO_KEK_INV_PARAMS      0x101D
#define ERR_CRYPTO_KEK_MEM_LEAK        0x101E
#define ERR_CRYPTO_DEK_BLOB_INV_PARAMS 0x101F
#define ERR_CRYPTO_DEK_BLOB_MEM_LEAK   0x1020
#define ERR_CRYPTO_GEN_HASH_INV_PARAMS 0x1021
#define ERR_CRYPTO_HASH_MEM_LEAK       0x1022
#define ERR_BUF_SANITY_CHECK_FAIL      0x1023  /**< Buffer is NULL or is not 0-terminated */
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
#define ERR_CRYPTO_MEM_LEAK            0x1033  /**< A non-NULL pointer has been passed when trying to alloc memory, thus resulting in a memory leak.*/
#define ERR_DEC_CRED_MEM_LEAK          0x1034
#define ERR_DEC_CRED_MEM_ALLOC         0x1035
#define ERR_ALLOC_DATAHASH_INV_PARAMS  0x1036
#define ERR_ALLOC_DATAHASH_MEM_ALLOC   0x1037
#define ERR_ALLOC_DATABLOB_INV_PARAMS  0x1038
#define ERR_ALLOC_DATABLOB_MEM_ALLOC   0x1039
#define ERR_MCPY_CRED_BLOB_INV_PARAMS  0x103A
#define ERR_OTK_NOT_INITIALIZED        0x103B
#define ERR_ENC_DEK_OTK_INV_PARAMS     0x103C
#define ERR_DEK_BLOB_ALREADY_INIT      0x103D
#define ERR_DEC_DEK_OTK_MEM_LEAK       0x103E
#define ERR_DEK_BLOB_NOT_INIT          0x103F
#define ERR_DEC_DEK_OTK_MEM_ALLOC      0x1040
#define ERR_ENC_DB_DEK_MEM_ALLOC       0x1041
#define ERR_RETRIEVE_CPU_ID            0x1042  /**< Could not retrieve the CPU hardware ID */
#define ERR_CONCAT_PEPPER_INV_PARAMS   0x1043  /**< Invalid parameters for the #concat_pin_pepper() function. */
#define ERR_VERIFY_PWD_INV_PARAMS      0x1044
#define ERR_DB_HEADER_NOT_LOADED       0x1045
#define ERR_DATABLOB_MEMCPY_INV_PARAMS 0x1046
#define ERR_DATAHASH_MEMCPY_INV_PARAMS 0x1047
#define ERR_CRYPTO_GEN_KEY_INV_PARAMS  0x1048  /**< Invalid parameters for #generate_aes256_key() function. */
#define ERR_OTK_ALREADY_INIT           0x1049
#define ERR_ALREADY_LOGGED_IN          0x104A
#define ERR_DB_HEADER_ALREADY_LOADED   0x104B
#define ERR_DECRYPT_CIPHER_INV_PARAMS  0x104C
#define ERR_ENCRYPT_DATA_INV_PARAMS    0x104D
#define ERR_CRYPTO_ENCRYPT_DATA        0x104E
#define ERR_KEY_MERGE_INV_PARAMS       0x104F

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
#define ERR_REG_NEW_CRED_INV_PARAMS    0x2016
#define ERR_GET_CRED_INV_PARAMS        0x2017
#define ERR_GET_CRED_NOT_FOUND         0x2018
#define ERR_GET_CRED_MEM_ALLOC         0x2019
#define ERR_GET_CRED_MEM_LEAK          0x201A
#define ERR_ALLOC_RD_CRED_INV_PARAMS   0x201B     
#define ERR_ALLOC_RD_CRED_MEM_LEAK     0x201C   
#define ERR_STORG_READ_CRED_INV_PARAMS 0x201D
#define ERR_GET_CRED_DIFF_INDICES      0x201E
#define ERR_AUTH_INV_PARAMS            0x201F
#define ERR_AUTH_MEM_ALLOC             0x2020
#define ERR_ADD_TO_USR_CONF_INV_PARAMS 0x2021
#define ERR_OPEN_USERS_CONF            0x2022
#define ERR_WRITE_USERS_CONF           0x2023
#define ERR_READ_USERS_CONF            0x2024
#define ERR_INIT_DB_HEADER_INV_PARAMS  0x2025
#define ERR_GET_USER_MEM_LEAK          0x2026


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
#define ERR_DB_APPEND_CRED_INV_PARAMS  0x400F
#define ERR_LOAD_DB_INV_PARAMS         0x4010
#define ERR_LOAD_DB_MEM_LEAK           0x4011
#define ERR_LOAD_DB_OPEN_FILE          0x4012
#define ERR_LOAD_DB_READ_FIELD         0x4013
#define ERR_LOAD_DB_MEM_ALLOC          0x4014
#define ERR_LOAD_DB_READ_CRED          0x4015
#define ERR_DB_APPEND_CRED_INV_CRED    0x4016
#define ERR_ZERO_CRED_INV_PARAMS       0x4017
#define ERR_ZERO_CREDH_INV_PARAMS      0x4018
#define ERR_DB_EXIST_CRED_INV_PARAMS   0x4019
#define ERR_CRED_EQUAL_INV_PARAMS      0x4020
#define ERR_CRED_ALREADY_EXISTS        0x4021
#define ERR_CREDENTIALS_DIFFER         0x4022
#define ERR_FIELDS_DIFFER              0x4023
#define ERR_POPULATE_CRED_INV_PARAMS   0x4024
#define ERR_POPULATE_CRED_MEM_LEAK     0x4025
#define ERR_APPND_CRED_ARR_INV_PARAMS  0x4026
#define ERR_APPND_CREDH_ARR_INV_PARAMS 0x4027
#define ERR_DB_NOT_INITIALIZED         0x4028
#define ERR_DB_ALREADY_INIT            0x4029
#define ERR_NOT_LOGGED_IN              0x402A
#define ERR_DB_MISSING_PASSW_HASH      0x402B
#define ERR_GET_MASTER_PWD_INV_PARAMS  0x402C
#define ERR_DB_MISSING_DEK             0x402D
#define ERR_MCPY_CRED_INV_PARAMS       0x402E
#define ERR_LOAD_DB_HEADER_INV_PARAMS  0x402F
#define ERR_DB_FREE_HEADER_INV_PARAMS  0x4030
#define ERR_LOAD_DB_READ               0x4031
#define ERR_GUARD_VALUE_DOES_NOT_MATCH 0x4032
#define ERR_DB_READ_FIELD_INV_PARAMS   0x4033
#define ERR_DB_READ_FIELD_TOO_MUCH     0x4034
#define ERR_DB_READ_FIELD_MEM_LEAK     0x4035
#define ERR_REENCRYPT_DEK_INV_PARAMS   0x4036
#define ERR_DB_NEW_INV_PARAMS          0x4037
#define ERR_FIELD_NOT_ENCRYPTED        0x4038
#define ERR_FIELD_NOT_FOUND            0x4039
#define ERR_FIELD_IS_ENCRYPTED         0x403A
#define ERR_FIELD_ALREADY_EXISTS       0x403B
#define ERR_ALLOC_CRED_ARR_INV_PARAMS  0x403C
#define ERR_RAW_CR_INV_PARAMS          0x403D
#define ERR_CREATE_CRED_INV_PARAMS     0x403E
#define ERR_DB_GET_DEK_INV_PARAMS      0x403F
#define ERR_DB_COPY_CRED_INV_PARAMS    0x4040
#define ERR_DECRYPT_CRED_INV_PARAMS    0x4041



/* Display Error Codes */
#define DISPLAY_OK                     0x0000
#define ERR_DISPLAY_MEM_LEAK           0x5001
#define ERR_DISPLAY_IMPORT_INV_PARAMS  0x5002
#define ERR_DISPLAY_IMPORT             0x5003
#define ERR_DISPLAY_GET_FUNC           0x5004
#define ERR_DISPLAY_NOT_A_FUNC         0x5005
#define ERR_DISPLAY_GETF_INV_PARAMS    0x5006
#define ERR_DISPLAY_CALLF_INV_PARAMS   0x5007
#define ERR_DISPLAY_GETATTR_INV_PARAMS 0x5008
#define ERR_DISPLAY_GET_ATTR           0x5009
#define ERR_DISPLAY_CALL_FUNCTION      0x500A
#define ERR_DISPLAY_TEXT_INV_PARAMS    0x500B
#define ERR_DISPLAY_ALREADY_INIT       0x500C
#define ERR_DISPLAY_NOT_INIT           0x500D
#define ERR_SCREEN_ST_ALREADY_INIT     0x500E
#define ERR_DISPLAY_MEM_ALLOC          0x500F
#define ERR_DISPLAY_NO_SUCH_SCREEN     0x5010
#define ERR_DRAW_NOT_INIT              0x5011
#define ERR_DRAW_IMG_INV_PARAMS        0x5012
#define ERR_DISPLAY_CANVAS_INV_PARAMS  0x5013
#define ERR_DISPLAY_NO_SUCH_FONT       0x5014
#define ERR_DISPLAY_NO_SUCH_ATTRIBUTE  0x5015
#define ERR_COMPUTE_ALIGN_INV_PARAMS   0x5016
#define ERR_PYTHON_INDEX_ERROR         0x5017
#define ERR_PYTHON_GET_ITEM_INV_PARAMS 0x5018
#define ERR_PYTHON_NOT_A_TUPLE         0x5019
#define ERR_DISPLAY_NO_SUCH_ALIGN      0x501A
#define ERR_DISPLAY_RECT_INV_PARAMS    0x501B
#define ERR_DRAW_CONTROLS_INV_PARAMS   0x501C
#define ERR_DISPLAY_GET_FONT_FAIL      0x501D
#define ERR_DRAW_MENU_TILE_INV_PARAMS  0x501E
#define ERR_DISPLAY_NO_SCREEN_TO_SHOW  0x501F
#define ERR_GET_TEXT_SIZE_INV_PARAMS   0x5020
#define ERR_SCREEN_STACK_INIT_FAIL     0x5021
#define ERR_DISPLAY_INIT_FAIL          0x5022
#define ERR_DISPLAY_BUSY               0x5023

/* Connection Error Codes */
#define ERR_SERIAL_MEM_LEAK            0x6001
#define ERR_SERIAL_MEM_ALLOC           0x6002
#define ERR_SERIAL_OPEN_CONN           0x6003
#define ERR_SERIAL_WR_INV_PARAMS       0x6004
#define ERR_SERIAL_RD_INV_PARAMS       0x6004
#define ERR_SERIAL_WR_FAIL             0x6005
#define ERR_SERIAL_RD_FAIL             0x6006
#define ERR_SERIAL_RD_FAIL_BYTES       0x6007
#define ERR_CONN_MEM_LEAK              0x6008
#define ERR_CONN_MEM_ALLOC             0x6009
#define ERR_EXEC_CMD_INV_PARAMS        0x600A
#define ERR_RECV_CMD_INV_PARAMS        0x600B
#define ERR_CONN_ALREADY_OPEN          0x600C
#define ERR_CONN_NOT_INIT              0x600D
#define ERR_SEND_CMD_INV_PARAMS        0x600E
#define ERR_PARSE_CMD_2_BUF_INV_PARAMS 0x600F
#define ERR_CALC_CRC_INV_PARAMS        0x6010
#define ERR_PARSE_BUF_2_CMD_INV_PARAMS 0x6011
#define ERR_PIN_NOT_ENTERED            0x6012
#define ERR_CONN_INVALID_COMM          0x6013
#define ERR_CRC_DIFFERENT              0x6014
#define ERR_READ_TIMED_OUT             0x6015
#define ERR_CONN_INIT_FAIL             0x6016
#define ERR_CONN_TO_SEND_BUSY          0x6017
#define ERR_UNKNOWN_COMMAND            0x6018

/* Fingerprint Error Codes */
#define ERR_VERIFY_PIN_INV_PARAMS      0x7001
#define ERR_FP_ALREADY_INIT            0x7002
#define ERR_DRIVER_INIT_FAIL           0x7003
#define ERR_FINGERPRINT_MEM_ALLOC      0x7004
#define ERR_FP_WRONG_PASSWORD          0x7005
#define ERR_VFY_PASSWORD_FAIL          0x7006
#define ERR_FP_NOT_INIT                0x7007
#define ERR_FP_NOT_UNLOCKED            0x7008
#define ERR_FP_ALREADY_UNLOCKED        0x7009
#define ERR_FP_ENROLL_FAIL             0x700A
#define ERR_FP_VERIFY_FAIL             0x700B
#define ERR_FP_NO_FINGER_FOUND         0x700C
#define ERR_FP_MEM_LEAK                0x700D
#define ERR_FP_GET_DATA_FAIL           0x700E
#define ERR_FP_ASYNC_STOPPED           0x700F

/* GPIO Error Codes */
#define ERR_GPIO_INIT_FAIL             0x8001

#endif