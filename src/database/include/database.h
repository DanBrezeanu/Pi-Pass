#ifndef __DATABASE_H__
#define __DATABASE_H__

#include <errors.h>
#include <defines.h>
#include <crypto_utils.h>
#include <storage_utils.h>
#include <datahash.h>
#include <datablob.h>

struct DatabaseHeader {
    uint16_t version;
    uint32_t db_len;
    struct DataHash master_pin_hash;
    struct DataBlob encrypted_fp_key;
}__attribute__((packed, aligned(1)));

struct Database {
    struct DatabaseHeader *header;

    uint32_t cred_count;
    /* Encrypted values start */
    struct Credential *cred;
    struct DataBlob dek;
    /* Encrypted values end */

} __attribute__((packed, aligned(1)));

PIPASS_ERR db_create_new(uint8_t *master_pin, uint8_t *fp_key, uint8_t *master_password,
  uint32_t master_password_len);
PIPASS_ERR db_update_DEK(uint8_t *dek, uint8_t *master_pin);
PIPASS_ERR db_update_login(uint8_t *login_hash, uint8_t *login_salt);
PIPASS_ERR db_update_KEK(uint8_t *kek_hash, uint8_t *kek_salt);
PIPASS_ERR db_raw(uint8_t **raw_db, int32_t *raw_db_size);
PIPASS_ERR db_header_raw(uint8_t **raw_db_header);
PIPASS_ERR db_append_credential(struct Credential *cr);
PIPASS_ERR db_get_master_pin_hash(struct DataHash *master_pin_hash);
PIPASS_ERR db_get_length(uint32_t *db_len);
PIPASS_ERR db_get_credentials(struct Credential **cr, uint32_t *cred_count);
PIPASS_ERR db_get_DEK(struct DataBlob *dek);
PIPASS_ERR db_get_encrypted_fp_key(struct DataBlob *fp_key);
PIPASS_ERR load_database(uint8_t *raw_db, uint32_t db_len, uint8_t *kek);
PIPASS_ERR load_database_header(uint8_t *raw_db_header);
void print_bytes(char *p, int size, char *name);
void db_free();
void db_free_header();
#endif
