#include <crypto_utils.h>

CRYPTO_ERR generate_KEK(uint8_t *passw, int32_t passw_len, uint8_t **salt, uint8_t **KEK);

CRYPTO_ERR generate_DEK_blob(uint8_t *DEK, uint8_t *KEK, uint8_t* aad, int32_t aad_len,
    uint8_t **iv, uint8_t **mac, uint8_t **DEK_blob);

CRYPTO_ERR generate_user_hash(uint8_t *user_data, int32_t user_data_len, uint8_t **user_hash);