#include <aes256.h>

PIPASS_ERR generate_aes256_key(uint8_t *key) {
    int32_t err = RAND_bytes(key, AES256_KEY_SIZE);
    if (err == -1) {
        return ERR_RAND_NOT_SUPPORTED;
    }

    if (err == 0) {
        zero_buffer(key, AES256_KEY_SIZE);
        return ERR_RAND_FAIL;
    }

    return CRYPTO_OK;
}

PIPASS_ERR create_PBKDF2_key(uint8_t *input, int32_t input_len, uint8_t *salt, int32_t salt_len, uint8_t *pbkdf2_key) {
    if (input == NULL || salt == NULL || pbkdf2_key == NULL || !input_len || !salt_len)
        return ERR_AES_PBKDF_INV_PARAMS;

    fastpbkdf2_hmac_sha256(input, input_len, salt, salt_len, PBKDF2_ITERATIONS, pbkdf2_key, AES256_KEY_SIZE);

    return CRYPTO_OK;
}

PIPASS_ERR encrypt_aes256(uint8_t *plaintext, int32_t plaintext_len, uint8_t *aad, int32_t aad_len, uint8_t *key,
    uint8_t *iv, uint8_t *mac, uint8_t *ciphertext, int32_t *ciphertext_len) {

    EVP_CIPHER_CTX *ctx = NULL;
    PIPASS_ERR err = CRYPTO_OK;
    int32_t res;
    int32_t length;

    if (plaintext == NULL || ciphertext == NULL || !plaintext_len)
        return ERR_AES_ENC_INV_PARAMS;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return ERR_AES_ENC_EVP_INIT;

    res = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    if (res != SSL_OK) {
        err = ERR_AES_ENC_EVP_INIT;
        goto error;
    }

    res = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, NULL);
    if (res != SSL_OK) {
        err = ERR_AES_ENC_SET_IVLEN;
        goto error;
    }

    res = EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    if (res != SSL_OK) {
        err = ERR_AES_ENC_EVP_INIT_KEY;
        goto error;
    }

    if (aad != NULL && aad_len > 0) {
        res = EVP_EncryptUpdate(ctx, NULL, &length, aad, aad_len);
        if (res != SSL_OK) {
            err = ERR_AES_ENC_EVP_AAD;
            goto error;
        }

        *ciphertext_len = length;
    }

    res = EVP_EncryptUpdate(ctx, ciphertext, &length, plaintext, plaintext_len);
    if (res != SSL_OK) {
        err = ERR_AES_ENC_EVP_ENCRYPT;
        goto error;
    }
    *ciphertext_len = length;

    res = EVP_EncryptFinal_ex(ctx, ciphertext + length, &length);
    if (res != SSL_OK) {
        err = ERR_AES_ENC_EVP_FINAL;
        goto error;
    }
    *ciphertext_len += length;

    res = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, MAC_SIZE, mac);
    if (res != SSL_OK) {
        err = ERR_AES_ENC_EVP_MAC;
        goto error;
    }

    EVP_CIPHER_CTX_free(ctx);
    return CRYPTO_OK;

error:
    EVP_CIPHER_CTX_free(ctx);
    *ciphertext_len = 0;
    zero_buffer(ciphertext, plaintext_len);

    return err;
}

PIPASS_ERR decrypt_aes256(uint8_t *ciphertext, int32_t ciphertext_len, uint8_t *aad, int32_t aad_len, uint8_t *mac,
    uint8_t *key, uint8_t *iv, uint8_t *plaintext, int32_t *plaintext_len) {
    
    EVP_CIPHER_CTX *ctx = NULL;
    PIPASS_ERR err = CRYPTO_OK;
    int32_t res;
    int32_t length;

    if (plaintext == NULL || ciphertext == NULL || !ciphertext_len)
        return ERR_AES_DEC_INV_PARAMS;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return ERR_AES_DEC_EVP_INIT;

    res = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    if (res != SSL_OK) {
        err = ERR_AES_DEC_EVP_INIT;
        goto error;
    }

    res = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, NULL);
    if (res != SSL_OK) {
        err = ERR_AES_DEC_SET_IVLEN;
        goto error;
    }

    res = EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
    if (res != SSL_OK) {
        err = ERR_AES_DEC_EVP_INIT_KEY;
        goto error;
    }

    if (aad != NULL && aad_len > 0) {
        res = EVP_DecryptUpdate(ctx, NULL, &length, aad, aad_len);
        if (res != SSL_OK) {
            err = ERR_AES_DEC_EVP_AAD;
            goto error;
        }

        *plaintext_len = length;
    }

    res = EVP_DecryptUpdate(ctx, plaintext, &length, ciphertext, ciphertext_len);
    if (res != SSL_OK) {
        err = ERR_AES_DEC_EVP_DECRYPT;
        goto error;
    }
    *plaintext_len = length;

    res = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, MAC_SIZE, mac);
    if (res != SSL_OK) {
        err = ERR_AES_DEC_EVP_MAC;
        goto error;
    }

    res = EVP_DecryptFinal_ex(ctx, plaintext + length, &length);
    if (res != SSL_OK) {
        err = ERR_AES_DEC_EVP_FINAL;
        goto error;
    }
    *plaintext_len += length;

    EVP_CIPHER_CTX_free(ctx);
    return CRYPTO_OK;

error:
    EVP_CIPHER_CTX_free(ctx);
    *plaintext_len = 0;
    zero_buffer(plaintext, ciphertext_len);

    return err;
}