#ifndef __STORAGE_H__
#define __STORAGE_H__

#include <defines.h>
#include <errors.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <strings.h>
#include <storage_utils.h>
#include <crypto_utils.h>
#include <database.h>

PIPASS_ERR create_user_directory(uint8_t *user_hash);
PIPASS_ERR verify_user_directory(uint8_t *user_hash);
PIPASS_ERR store_file(uint8_t *user_hash, uint8_t *content, int32_t content_len, uint8_t *file_name);
PIPASS_ERR store_user_DEK_blob(uint8_t *user_hash, uint8_t *DEK_blob, uint8_t *iv, uint8_t *mac);
PIPASS_ERR dump_database(struct Database *db, uint8_t *user_hash);
PIPASS_ERR load_database(struct Database **db, uint8_t *user_hash);

#endif