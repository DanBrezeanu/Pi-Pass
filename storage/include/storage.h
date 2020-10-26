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
PIPASS_ERR dump_database(uint8_t *user_hash, uint8_t *master_pin);
PIPASS_ERR read_database(uint8_t *user_hash, struct DataBlob *raw_db, uint32_t *raw_db_len);
PIPASS_ERR read_database_header(uint8_t *user_hash, uint8_t **raw_db_header);
#endif