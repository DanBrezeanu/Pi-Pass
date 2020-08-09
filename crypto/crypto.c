#include <crypto.h>
#include <aes256.h>

CRYPTO_ERR generate_KEK(uint8_t *passw, int32_t passw_len, uint8_t **salt, uint8_t **KEK) {
    CRYPTO_ERR err = CRYPTO_OK; 
    
    if (passw == NULL || passw_len == 0)
        return ERR_CRYPTO_KEK_INV_PARAMS;

    if (*salt != NULL || *KEK != NULL)
        return ERR_CRYPTO_KEK_MEM_LEAK;

    *salt = malloc(SALT_SIZE);
    if (*salt == NULL)
        return ERR_CRYPTO_MEM_ALLOC;

    *KEK = malloc(AES256_KEY_SIZE);
    if (*KEK == NULL) {
        err = ERR_CRYPTO_MEM_ALLOC;
        goto error;
    }

    err = create_PBKDF2_key(passw, passw_len, *salt, SALT_SIZE, *KEK);
    if (err != CRYPTO_OK)
        goto error;

    return CRYPTO_OK;

error:
    if (*salt != NULL) {
        zero_buffer(*salt, SALT_SIZE);
        free(*salt);
        *salt = NULL;
    }

    if (*KEK != NULL) {
        zero_buffer(*KEK, AES256_KEY_SIZE);
        free(*KEK);
        *KEK = NULL;
    }

    return err;
}


CRYPTO_ERR generate_DEK_blob(uint8_t *DEK, uint8_t *KEK, uint8_t* aad, int32_t aad_len,
    uint8_t **iv, uint8_t **mac, uint8_t **DEK_blob) {

    CRYPTO_ERR err = CRYPTO_OK;

    if (DEK == NULL || KEK == NULL)
        return ERR_CRYPTO_DEK_BLOB_INV_PARAMS;

    if (*DEK_blob != NULL || *iv != NULL || *mac != NULL)
        return ERR_CRYPTO_DEK_BLOB_MEM_LEAK;

    *iv = malloc(IV_SIZE);
    if (*iv == NULL)
        return ERR_CRYPTO_MEM_ALLOC;

    err = create_salt(IV_SIZE, *iv);
    if (err != CRYPTO_OK)
        goto error;

    *DEK_blob = malloc(AES256_KEY_SIZE);
    if (*DEK_blob == NULL) {
        err = ERR_CRYPTO_MEM_ALLOC;
        goto error;
    }

    *mac = malloc(MAC_SIZE);
    if (*mac == NULL) {
        err = ERR_CRYPTO_MEM_ALLOC;
        goto error;
    }

    int32_t DEK_blob_len = 0;
    err = encrypt_aes256(DEK, AES256_KEY_SIZE, aad, aad_len, KEK, *iv, *mac, *DEK_blob, &DEK_blob_len);
    if (err != CRYPTO_OK || DEK_blob_len != AES256_KEY_SIZE) {
        err = ERR_CRYPTO_DEK_BLOB_ENCRYPT;
        goto error;
    }

    return CRYPTO_OK;

error:
    if (*iv != NULL) {
        zero_buffer(*iv, IV_SIZE);
        free(*iv);
        *iv = NULL;
    }

    if (*DEK_blob != NULL) {
        zero_buffer(*DEK_blob, AES256_KEY_SIZE);
        free(*DEK_blob);
        *DEK_blob = NULL;
    }

    if (*mac != NULL) {
        zero_buffer(*mac, MAC_SIZE);
        free(*mac);
        *mac = NULL;
    }

    return err;
}


CRYPTO_ERR generate_user_hash(uint8_t *user_data, int32_t user_data_len, uint8_t **user_hash) {
    uint8_t *user_hash_raw = NULL;
    
    if (user_data == NULL || user_data_len == 0) 
        return ERR_CRYPTO_GEN_HASH_INV_PARAMS;

    if (*user_hash != NULL)
        return ERR_MEM_LEAK;

    user_hash_raw = malloc(SHA256_DGST_SIZE);
    if (user_hash_raw == NULL)
        return ERR_STORAGE_MEM_ALLOC;

    CRYPTO_ERR err = hash_sha256(user_data, user_data_len, NULL, 0, user_hash_raw);
    if (err != CRYPTO_OK) {
        goto error;
    }

    int32_t user_hash_size = 0;
    err = raw_to_hex(user_hash_raw, SHA256_DGST_SIZE, user_hash, &user_hash_size);
    if (err != CRYPTO_OK || user_hash_size != SHA256_HEX_SIZE) {
        err = ERR_USER_HASH_RAW2HEX;
        goto error;
    }

    if (user_hash_raw != NULL) {
        zero_buffer(user_hash_raw, SHA256_DGST_SIZE);
        free(user_hash_raw);
    }

    return STORAGE_OK;

error:
    if (*user_hash != NULL) {
        zero_buffer(*user_hash, SHA256_DGST_SIZE);
        free(*user_hash);
        *user_hash = NULL;
    }

    if (user_hash_raw != NULL) {
        zero_buffer(user_hash_raw, SHA256_HEX_SIZE);
        free(user_hash_raw);
        user_hash_raw = NULL;
    }

    return err;
}

CRYPTO_ERR generate_login_hash(uint8_t *passw, uint8_t **login_hash, uint8_t **login_salt) {
    if (passw == NULL)
        return ERR_CRYPTO_GEN_HASH_INV_PARAMS;
    
    if (*login_hash != NULL || *login_salt != NULL)
        return ERR_CRYPTO_HASH_MEM_LEAK;

    *login_salt = malloc(SALT_SIZE);
    if (*login_salt == NULL)
        return ERR_CRYPTO_MEM_ALLOC;

    CRYPTO_ERR err = create_salt(SALT_SIZE, *login_salt);
    if (err != CRYPTO_OK)
        goto error;

    *login_hash = malloc(SHA256_DGST_SIZE);
    if (*login_hash == NULL)
        return ERR_CRYPTO_MEM_ALLOC;
    
    err = hash_sha256(passw, MASTER_PASS_SIZE, *login_salt, SALT_SIZE, *login_hash);
    if (err != CRYPTO_OK)
        goto error;

    return CRYPTO_OK;

error:
    erase_buffer(login_salt, SALT_SIZE);
    erase_buffer(login_hash, SHA256_DGST_SIZE);

    return err;
}