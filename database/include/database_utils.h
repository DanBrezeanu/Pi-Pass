#ifndef __DATABASE_UTILS_H__
#define __DATABASE_UTILS_H__

#include <defines.h>
#include <errors.h>
#include <storage_utils.h>
#include <credentials.h>

PIPASS_ERR read_db_field_32b_from_raw(uint8_t *raw_db, uint32_t *read_cursor, uint32_t db_len, uint32_t *db_field);
PIPASS_ERR read_db_field_16b_from_raw(uint8_t *raw_db, uint32_t *read_cursor, uint32_t db_len, uint16_t *db_field);
PIPASS_ERR read_bytes_from_raw(uint8_t *raw_db, uint32_t *read_cursor, uint32_t db_len, uint8_t **bytes, uint32_t bytes_len);
PIPASS_ERR read_datablob_from_raw(uint8_t *raw_db, uint32_t *read_cursor, uint32_t db_len, struct DataBlob *blob, uint32_t cipher_len);
PIPASS_ERR read_credentials_from_raw(uint8_t *raw_db, uint32_t *read_cursor, uint32_t db_len, 
  struct Credential *cred, struct CredentialHeader *cred_headers, uint32_t cred_len);

#endif