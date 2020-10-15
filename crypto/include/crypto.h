#include <crypto_utils.h>
#include <database.h>
#include <defines.h>
#include <errors.h>

PIPASS_ERR generate_KEK(uint8_t *passw, int32_t passw_len, uint8_t **salt, uint8_t **KEK);

PIPASS_ERR generate_DEK_blob(uint8_t *DEK, uint8_t *KEK, uint8_t* aad, int32_t aad_len,
    uint8_t **iv, uint8_t **mac, uint8_t **DEK_blob);

PIPASS_ERR generate_user_hash(uint8_t *user_data, int32_t user_data_len, uint8_t **user_hash);

PIPASS_ERR generate_login_hash(uint8_t *passw, uint8_t **login_hash, uint8_t **login_salt);

PIPASS_ERR encrypt_db_field(struct Database *db, uint8_t *kek, uint8_t *data, enum DatabaseEncryptedField field);

PIPASS_ERR decrypt_db_field(struct Database *db, uint8_t *kek, uint8_t **data, enum DatabaseEncryptedField field);

PIPASS_ERR encrypt_credential_field(struct Database *db, uint8_t *data, int32_t data_len, uint8_t *master_pass,
  uint8_t **cipher, uint8_t **iv, uint8_t **mac, int16_t *cipher_len);

PIPASS_ERR decrypt_credential_field(struct Database *db, uint8_t **data, int32_t *data_len, uint8_t *master_pass,
  uint8_t *cipher, uint8_t *iv, uint8_t *mac, int16_t cipher_len);

PIPASS_ERR sanity_check_buffer(uint8_t *buf, uint8_t buf_len);
