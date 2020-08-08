#include <sha256.h>

CRYPTO_ERR hash_sha256(uint8_t *input, size_t input_len, uint8_t *salt, uint32_t salt_len, uint8_t *digest) {
    int32_t res;
    SHA256_CTX ctx;

    if (input == NULL || salt == NULL || !input_len || !salt_len)
        return ERR_SHA_HASH_INV_PARAMS;

    res = SHA256_Init(&ctx);
    if (res != SSL_OK)
        return ERR_SHA_INIT_CTX_FAIL;

    res = SHA256_Update(&ctx, salt, salt_len);
    if (res != SSL_OK)
        return ERR_SHA_UPDATE_FAIL;

    res = SHA256_Update(&ctx, input, input_len);
    if (res != SSL_OK)
        return ERR_SHA_UPDATE_FAIL;

    res = SHA256_Final(digest, &ctx);
    if (res != SSL_OK)
        return ERR_SHA_FINAL_FAIL;

    return CRYPTO_OK;
}

CRYPTO_ERR verify_sha256(uint8_t *input, size_t input_len, uint8_t *salt, uint32_t salt_len, int32_t fd_dgst) {
    uint8_t *dgst = malloc(SHA256_DGST_SIZE);
    uint8_t *stored_dgst = malloc(SHA256_DGST_SIZE);
    
    CRYPTO_ERR err = hash_sha256(input, input_len, salt, salt_len, dgst);
    if (err != CRYPTO_OK)
        goto error;

    int32_t res = read(fd_dgst, stored_dgst, SHA256_DGST_SIZE);
    if (res != SHA256_DGST_SIZE) {
        err = ERR_READ_HASH_FAIL;
        goto error;
    }

    if (memcmp(dgst, stored_dgst, SHA256_DGST_SIZE) != 0) {
        err = ERR_HASH_DIFFER;
        goto error;
    }

    err = CRYPTO_OK;

error:
    zero_buffer(dgst, SHA256_DGST_SIZE);
    zero_buffer(stored_dgst, SHA256_DGST_SIZE);
    free(dgst);
    free(stored_dgst);

    return err;
}