#include <crypto_utils.h>
#include <database.h>
#include <flags.h>
#include <defines.h>
#include <errors.h>


extern uint8_t *OTK;
extern struct DataBlob *DEK_BLOB;

PIPASS_ERR generate_KEK(uint8_t *passw, uint8_t *salt, uint8_t **KEK);

PIPASS_ERR generate_user_hash(uint8_t *user_data, int32_t user_data_len, uint8_t **user_hash);

PIPASS_ERR generate_new_master_passw_hash(uint8_t *passw, struct DataHash *passw_hash);

PIPASS_ERR encrypt_DEK_with_KEK(uint8_t *dek, uint8_t *kek, struct DataBlob *dek_blob);

PIPASS_ERR decrypt_DEK_with_KEK(uint8_t *kek, uint8_t **dek);

PIPASS_ERR encrypt_DEK_with_OTK(uint8_t *dek);

PIPASS_ERR decrypt_DEK_with_OTK(uint8_t **dek);

PIPASS_ERR encrypt_field_with_DEK(uint8_t *field, int32_t field_len, struct DataBlob *field_blob, int16_t *cipher_len);

PIPASS_ERR decrypt_field_with_DEK(struct DataBlob *cipher, int16_t cipher_len, uint8_t **data, int32_t *data_len);

PIPASS_ERR verify_master_password_with_db(uint8_t *passw);

PIPASS_ERR verify_master_password_with_hash(uint8_t *passw, struct DataHash passw_hash);

PIPASS_ERR generate_OTK();

PIPASS_ERR invalidate_OTK();

PIPASS_ERR invalidate_DEK_BLOB();

PIPASS_ERR generate_new_master_passw_hash(uint8_t *passw, struct DataHash *passw_hash);

PIPASS_ERR encrypt_DEK_with_KEK(uint8_t *dek, uint8_t *kek, struct DataBlob *dek_blob);