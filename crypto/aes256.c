

CRYPTO_ERR create_PBKDF2_key(uint8_t *input, int32_t input_len, uint8_t *salt, int32_t salt_len, uint8_t *pbkdf2_key) {
    if (input == NULL || salt == NULL || !input_len || !salt_len)
        return ERR_AES_PBKDF_INV_PARAMS;

    fastpbkdf2_hmac_sha256(input, input_len, salt, salt_len, PBKDF2_ITERATIONS, pbkdf2_key, AES256_KEY_SIZE);

    return CRYPTO_OK
}