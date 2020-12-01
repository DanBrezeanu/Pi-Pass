#include <crypto.h>
#include <aes256.h>
#include <database.h>
#include <credentials.h>
#include <sha256.h>
#include <datablob.h>
#include <fingerprint.h>

uint8_t *OTK = NULL;
struct DataBlob *DEK_BLOB = NULL;

PIPASS_ERR generate_KEK(uint8_t *pin, uint8_t *salt, uint8_t *fp_key, uint8_t **KEK) {
    PIPASS_ERR err = PIPASS_OK; 
    uint8_t *pin_pepper = NULL;
    uint8_t *KEK_pin = NULL, *KEK_fp = NULL;
    
    if (pin == NULL || salt == NULL || fp_key == NULL)
        return ERR_CRYPTO_KEK_INV_PARAMS;

    if (*KEK != NULL)
        return ERR_CRYPTO_MEM_LEAK;

    KEK_pin = malloc(AES256_KEY_SIZE);
    if (KEK_pin == NULL) {
        err = ERR_CRYPTO_MEM_ALLOC;
        goto error;
    }

    err = concat_pin_pepper(pin, &pin_pepper);
    if (err != PIPASS_OK)
        goto error;

    err = create_PBKDF2_key(pin_pepper, MASTER_PIN_SIZE_WITH_PEPPER, salt, SALT_SIZE, KEK_pin);
    if (err != PIPASS_OK)
        goto error;

    erase_buffer(&pin_pepper, MASTER_PIN_SIZE_WITH_PEPPER);

    err = merge_keys(KEK_pin, fp_key, KEK);
    if (err != PIPASS_OK)
        goto error;

    err = PIPASS_OK;
    goto cleanup;


error:
    erase_buffer(KEK, AES256_KEY_SIZE);
cleanup:
    erase_buffer(&pin_pepper, MASTER_PIN_SIZE_WITH_PEPPER);
    erase_buffer(&KEK_pin, AES256_KEY_SIZE);
    erase_buffer(&KEK_fp, AES256_KEY_SIZE);

    return err;
} 

PIPASS_ERR generate_user_hash(uint8_t *user_data, int32_t user_data_len, uint8_t **user_hash) {
    uint8_t *user_hash_raw = NULL;
    
    if (user_data == NULL || user_data_len == 0) 
        return ERR_CRYPTO_GEN_HASH_INV_PARAMS;

    if (*user_hash != NULL)
        return ERR_MEM_LEAK;

    user_hash_raw = malloc(SHA256_DGST_SIZE + 1);
    if (user_hash_raw == NULL)
        return ERR_STORAGE_MEM_ALLOC;

    PIPASS_ERR err = hash_sha256(user_data, user_data_len, NULL, 0, user_hash_raw);
    if (err != CRYPTO_OK) {
        goto error;
    }

    int32_t user_hash_size = 0;
    err = raw_to_hex(user_hash_raw, SHA256_DGST_SIZE, user_hash, &user_hash_size);
    if (err != CRYPTO_OK || user_hash_size != SHA256_HEX_SIZE) {
        err = ERR_USER_HASH_RAW2HEX;
        goto error;
    }

    erase_buffer(&user_hash_raw, SHA256_DGST_SIZE);

    return STORAGE_OK;

error:
    erase_buffer(user_hash, SHA256_DGST_SIZE);
    erase_buffer(&user_hash_raw, SHA256_HEX_SIZE);

    return err;
}

PIPASS_ERR generate_new_master_pin_hash(uint8_t *pin, struct DataHash *pin_hash) {
    if (pin == NULL || pin_hash == NULL)
        return ERR_CRYPTO_GEN_HASH_INV_PARAMS;
    
    if (pin_hash->hash != NULL || pin_hash->salt != NULL)
        return ERR_CRYPTO_HASH_MEM_LEAK;

    uint8_t *pin_and_pepper = NULL;
    PIPASS_ERR err;

    err = alloc_datahash(pin_hash);
    if (err != PIPASS_OK)
        goto error;

    err = create_salt(SALT_SIZE, pin_hash->salt);
    if (err != PIPASS_OK)
        goto error;
    
    err = concat_pin_pepper(pin, &pin_and_pepper);
    if (err != PIPASS_OK)
        goto error;
    
    err = hash_sha256(pin_and_pepper, MASTER_PIN_SIZE_WITH_PEPPER, pin_hash->salt, SALT_SIZE, pin_hash->hash);
    if (err != PIPASS_OK)
        goto error;

    erase_buffer(&pin_and_pepper, MASTER_PIN_SIZE_WITH_PEPPER);

    return PIPASS_OK;

error:
    erase_buffer(&pin_and_pepper, MASTER_PIN_SIZE_WITH_PEPPER);
    erase_buffer(&(pin_hash->salt), SALT_SIZE);
    erase_buffer(&(pin_hash->hash), SHA256_DGST_SIZE);

    return err;
}

PIPASS_ERR decrypt_cipher_with_key(struct DataBlob *cipher, uint32_t cipher_len, uint8_t *key, uint8_t **data) {
    if (cipher == NULL || !cipher_len || key == NULL || datablob_has_null_fields(*cipher))
        return ERR_DECRYPT_CIPHER_INV_PARAMS;

    if (*data != NULL)
        return ERR_CRYPTO_MEM_LEAK;

    PIPASS_ERR err;

    *data = malloc(cipher_len);
    if (*data == NULL)
        return ERR_CRYPTO_MEM_ALLOC;

    int32_t data_len = 0;
    err = decrypt_aes256(cipher->ciphertext, cipher_len, NULL, 0, cipher->mac, key, cipher->iv, *data, &data_len);
    if (err != PIPASS_OK)
        goto error;

    return PIPASS_OK;

error:
    erase_buffer(data, cipher_len);

    return err;
}

PIPASS_ERR encrypt_data_with_key(uint8_t *data, uint32_t data_len, uint8_t *key, struct DataBlob *cipher) {
    if (data == NULL || !data_len || key == NULL || cipher == NULL)
        return ERR_ENCRYPT_DATA_INV_PARAMS;

    if (cipher->ciphertext != NULL || cipher->iv != NULL || cipher->mac != NULL)
        return ERR_CRYPTO_MEM_LEAK;

    PIPASS_ERR err;

    err = alloc_datablob(cipher, data_len);
    if (err != PIPASS_OK)
        return err;

    err = create_salt(IV_SIZE, cipher->iv);
    if (err != PIPASS_OK)
        goto error;

    int32_t cipher_len = 0;
    err = encrypt_aes256(data, data_len, NULL, 0, key, cipher->iv, cipher->mac, cipher->ciphertext, &cipher_len);
    if (err != CRYPTO_OK || cipher_len != data_len) {
        err = ERR_CRYPTO_ENCRYPT_DATA;
        goto error;
    }

    return PIPASS_OK;

error:
    free_datablob(cipher, data_len);

    return err;
}

PIPASS_ERR encrypt_DEK_with_KEK(uint8_t *dek, uint8_t *kek, struct DataBlob *dek_blob) {


    if (dek == NULL || kek == NULL || dek_blob == NULL)
        return ERR_CRYPTO_DEK_BLOB_INV_PARAMS;

    if (dek_blob->ciphertext != NULL || dek_blob->iv != NULL || dek_blob->mac != NULL)
        return ERR_CRYPTO_DEK_BLOB_MEM_LEAK;

    PIPASS_ERR err = PIPASS_OK;

    err = alloc_datablob(dek_blob, AES256_KEY_SIZE);
    if (err != PIPASS_OK)
        return err;

    err = create_salt(IV_SIZE, dek_blob->iv);
    if (err != PIPASS_OK)
        goto error;

    int32_t dek_blob_len = 0;
    err = encrypt_aes256(dek, AES256_KEY_SIZE, NULL, 0, kek, dek_blob->iv, dek_blob->mac, dek_blob->ciphertext, &dek_blob_len);
    if (err != PIPASS_OK || dek_blob_len != AES256_KEY_SIZE) {
        err = ERR_CRYPTO_DEK_BLOB_ENCRYPT;
        goto error;
    }

    return PIPASS_OK;

error:
    free_datablob(dek_blob, AES256_KEY_SIZE);

    return err;
}

PIPASS_ERR decrypt_DEK_with_KEK(uint8_t *kek, uint8_t **dek) {
    if (kek == NULL)
        return ERR_DEC_DB_FIELD_INV_PARAMS;

    if (*dek != NULL)
        return ERR_DEC_DB_FIELD_MEM_LEAK;

    PIPASS_ERR err = CRYPTO_OK;
    struct DataBlob dek_blob = {0};

    err = db_get_DEK(&dek_blob);
    if (err != PIPASS_OK)
        return err;

    if (datablob_has_null_fields(dek_blob))
        return ERR_DEC_DB_FIELD_MISSING_FIELD;

    *dek = malloc(AES256_KEY_SIZE);
    if (*dek == NULL) {
        err = ERR_CRYPTO_MEM_ALLOC;
        goto error;
    }

    int32_t data_len = 0;
    err = decrypt_aes256(dek_blob.ciphertext, AES256_KEY_SIZE, NULL, 0, dek_blob.mac, kek, dek_blob.iv, *dek, &data_len);
    if (err != PIPASS_OK)
        goto error;

    return PIPASS_OK;

error:
    erase_buffer(dek, AES256_KEY_SIZE);

    return err;
}

PIPASS_ERR encrypt_DEK_with_OTK(uint8_t *dek) {
    if (OTK == NULL)
        return ERR_OTK_NOT_INITIALIZED;

    if (dek == NULL)
        return ERR_ENC_DEK_OTK_INV_PARAMS;
    
    if (DEK_BLOB != NULL)
        return ERR_DEK_BLOB_ALREADY_INIT;

    PIPASS_ERR err = PIPASS_OK;

    DEK_BLOB = calloc(1, sizeof(struct DataBlob));
    err = alloc_datablob(DEK_BLOB, AES256_KEY_SIZE);
    if (err != PIPASS_OK)
        goto error;

    err = create_salt(IV_SIZE, DEK_BLOB->iv);
    if (err != PIPASS_OK)
        goto error;

    int32_t cipher_len = 0;

    err = encrypt_aes256(dek, AES256_KEY_SIZE, NULL, 0, OTK, DEK_BLOB->iv, DEK_BLOB->mac,
        DEK_BLOB->ciphertext, &cipher_len);
    if (err != PIPASS_OK)
        goto error;

    return PIPASS_OK;

error:
    if (DEK_BLOB != NULL) {
        free_datablob(DEK_BLOB, AES256_KEY_SIZE);
        free(DEK_BLOB);
        DEK_BLOB = NULL;
    }

    return err;
}

PIPASS_ERR decrypt_DEK_with_OTK(uint8_t **dek) {
    if (OTK == NULL)
        return ERR_OTK_NOT_INITIALIZED;
    
    if (DEK_BLOB == NULL)
        return ERR_DEK_BLOB_NOT_INIT;

    if (*dek != NULL)
        return ERR_DEC_DEK_OTK_MEM_LEAK;

    *dek = malloc(AES256_KEY_SIZE);
    if (*dek == NULL)
        return ERR_DEC_DEK_OTK_MEM_ALLOC;

    PIPASS_ERR err = PIPASS_OK;
    int32_t data_len = 0;

    err = decrypt_aes256(DEK_BLOB->ciphertext, AES256_KEY_SIZE, NULL, 0, DEK_BLOB->mac, OTK,
        DEK_BLOB->iv, *dek, &data_len);
    if (err != PIPASS_OK)
        goto error;

    return PIPASS_OK;

error:
    if (*dek != NULL) {
        free(*dek);
        *dek = NULL;
    }

    return err;
}

PIPASS_ERR encrypt_field_with_DEK(uint8_t *field, int32_t field_len, 
  struct DataBlob *field_blob, int16_t *cipher_len) {

    if (!FL_LOGGED_IN)
        return ERR_NOT_LOGGED_IN;

    if (field == NULL || !field_len || cipher_len == NULL || field_blob == NULL)
        return ERR_ENC_CRED_INV_PARAMS;

    if (field_blob->ciphertext != NULL || field_blob->iv != NULL || field_blob->mac != NULL)
        return ERR_CRYPTO_MEM_LEAK;

    if (OTK == NULL)
        return ERR_OTK_NOT_INITIALIZED;
    
    if (DEK_BLOB == NULL)
        return ERR_DEK_BLOB_NOT_INIT;

    PIPASS_ERR err = CRYPTO_OK;

    err = alloc_datablob(field_blob, field_len);
    if (err != PIPASS_OK)
        goto error;

    err = create_salt(IV_SIZE, field_blob->iv);
    if (err != CRYPTO_OK)
        goto error;

    uint8_t *dek = NULL;
    err = decrypt_DEK_with_OTK(&dek);
    if (err != PIPASS_OK)
        goto error;

    err = encrypt_aes256(field, field_len, NULL, 0, dek, field_blob->iv, field_blob->mac, field_blob->ciphertext, (int32_t *)cipher_len);
    if (err != CRYPTO_OK)
        goto error;

    erase_buffer(&dek, AES256_KEY_SIZE);

    return CRYPTO_OK;

error:
    erase_buffer(&dek, AES256_KEY_SIZE);
    free_datablob(field_blob, AES256_KEY_SIZE);

    return err;
}

PIPASS_ERR decrypt_field_with_DEK(struct DataBlob *cipher, int16_t cipher_len, uint8_t **data, int32_t *data_len) {

    if (cipher == NULL || datablob_has_null_fields(*cipher) || !cipher_len)
        return ERR_DEC_CRED_INV_PARAMS;

    if (*data != NULL)
        return ERR_DEC_CRED_MEM_LEAK;

    PIPASS_ERR err = CRYPTO_OK;
    uint8_t *dek = NULL;

    *data = malloc(cipher_len);
    if (*data == NULL) {
        err = ERR_DEC_CRED_MEM_ALLOC;
        goto error;
    }

    err = decrypt_DEK_with_OTK(&dek);
    if (err != PIPASS_OK)
        goto error;

    err = decrypt_aes256(cipher->ciphertext, cipher_len, NULL, 0, cipher->mac, dek, cipher->iv, *data, data_len);
    if (err != CRYPTO_OK)
        goto error;

    erase_buffer(&dek, AES256_KEY_SIZE);

    return CRYPTO_OK;

error:
    erase_buffer(&dek, AES256_KEY_SIZE);
    erase_buffer(data, cipher_len);

    return err;
}

/* TODO */
PIPASS_ERR reencrypt_DEK(struct DataBlob *dek_blob, uint8_t *new_master_pin, uint8_t *new_master_pin_salt, 
  uint8_t *old_master_pin, uint8_t *old_master_pin_salt) {

//       if (dek_blob == NULL || new_master_pin == NULL || new_master_pin_salt == NULL 
//        || old_master_pin == NULL || old_master_pin_salt == NULL)
//         return ERR_REENCRYPT_DEK_INV_PARAMS;
    
//     uint8_t *old_kek = NULL;
//     uint8_t *new_kek = NULL;
//     uint8_t *dek = NULL;
//     struct DataBlob new_dek_blob = {0};

//     PIPASS_ERR err;

//     err = generate_KEK(old_master_pin, old_master_pin_salt, &old_kek);
//     if (err != PIPASS_OK)
//         goto error;    

//     err = generate_KEK(new_master_pin, new_master_pin_salt, &new_kek);
//     if (err != PIPASS_OK)
//         goto error;    

//     err = decrypt_DEK_with_KEK(old_kek, &dek);
//     if (err != PIPASS_OK)
//         goto error;    

//     err = encrypt_DEK_with_KEK(dek, new_kek, &new_dek_blob);
//     if (err != PIPASS_OK)
//         goto error;    

//     err = datablob_memcpy(dek_blob, &new_dek_blob, AES256_KEY_SIZE);
//     if (err != PIPASS_OK)
//         goto error;    

//     err = PIPASS_OK;

// error:
//     erase_buffer(&new_kek, AES256_KEY_SIZE);
//     erase_buffer(&old_kek, AES256_KEY_SIZE);
//     erase_buffer(&dek, AES256_KEY_SIZE);
//     free_datablob(&new_dek_blob, AES256_KEY_SIZE);

    return PIPASS_OK;
}

PIPASS_ERR verify_master_pin_with_db(uint8_t *pin) {
    if (!FL_DB_HEADER_LOADED && !FL_DB_INITIALIZED)
        return ERR_DB_HEADER_NOT_LOADED;
    
    if (pin == NULL)
        return ERR_VERIFY_PWD_INV_PARAMS;

    PIPASS_ERR err;
    uint8_t *pin_pepper = NULL;
    struct DataHash master_pin_hash;

    err = alloc_datahash(&master_pin_hash);
    if (err != PIPASS_OK)
        return err;

    err = db_get_master_pin_hash(&master_pin_hash);
    if (err != PIPASS_OK)
        goto error;

    err = concat_pin_pepper(pin, &pin_pepper);
    if (err != PIPASS_OK)
        goto error;

    err = verify_sha256(pin_pepper, MASTER_PIN_SIZE_WITH_PEPPER, master_pin_hash.salt,
         SALT_SIZE, master_pin_hash.hash);
    if (err != PIPASS_OK)
        goto error;  

    err = PIPASS_OK;

error:
    free_datahash(&master_pin_hash);
    erase_buffer(&pin_pepper, MASTER_PIN_SIZE_WITH_PEPPER);
    
    return err;
}

PIPASS_ERR verify_master_pin_with_hash(uint8_t *pin, struct DataHash pin_hash) {    
    if (pin == NULL || datahash_has_null_fields(pin_hash))
        return ERR_VERIFY_PWD_INV_PARAMS;

    PIPASS_ERR err;
    uint8_t *pin_pepper = NULL;

    err = concat_pin_pepper(pin, &pin_pepper);
    if (err != PIPASS_OK)
        goto error;

    err = verify_sha256(pin_pepper, MASTER_PIN_SIZE_WITH_PEPPER, pin_hash.salt,
         SALT_SIZE, pin_hash.hash);
    if (err != PIPASS_OK)
        goto error;  

    err = PIPASS_OK;

error:
    erase_buffer(&pin_pepper, MASTER_PIN_SIZE_WITH_PEPPER);
    
    return err;
}

PIPASS_ERR merge_keys(uint8_t *key_1, uint8_t *key_2, uint8_t **key) {
    if (key_1 == NULL || key_2 == NULL)
        return ERR_KEY_MERGE_INV_PARAMS;

    if (*key != NULL)
        return ERR_CRYPTO_MEM_LEAK;

    PIPASS_ERR err;
    uint8_t *key_tmp = NULL;

    *key = malloc(AES256_KEY_SIZE);
    if (*key == NULL)
        return ERR_CRYPTO_MEM_ALLOC;

    key_tmp = malloc(AES256_KEY_SIZE * 2);
    if (key_tmp == NULL) {
        err = ERR_CRYPTO_MEM_ALLOC;
        goto error;
    }

    memcpy(key_tmp, key_1, AES256_KEY_SIZE);
    memcpy(key_tmp + AES256_KEY_SIZE, key_2, AES256_KEY_SIZE);

    err = create_PBKDF2_key(key_tmp, 2 * AES256_KEY_SIZE, NULL, 0, *key);
    if (err != PIPASS_OK)
        goto error;

    err = PIPASS_OK;
    goto cleanup;

error:
    erase_buffer(key, AES256_KEY_SIZE);

cleanup:
    erase_buffer(&key_tmp, AES256_KEY_SIZE);

    return err;
}

PIPASS_ERR generate_OTK() {
    if (!FL_LOGGED_IN)
        return ERR_NOT_LOGGED_IN;

    if (!FL_DB_INITIALIZED)
        return ERR_DB_NOT_INITIALIZED;

    if (OTK != NULL)
        return ERR_OTK_ALREADY_INIT;

    if (DEK_BLOB != NULL)
        return ERR_DEK_BLOB_ALREADY_INIT;

    PIPASS_ERR err;

    OTK = malloc(AES256_KEY_SIZE);
    if (OTK == NULL)
        return ERR_CRYPTO_MEM_ALLOC;

    err = generate_aes256_key(OTK);
    if (err != PIPASS_OK)
        goto error;

    return PIPASS_OK;

error:
    erase_buffer(&OTK, AES256_KEY_SIZE);

    return err;
}

PIPASS_ERR invalidate_OTK() {
    if (!FL_LOGGED_IN)
        return ERR_NOT_LOGGED_IN;

    if (!FL_DB_INITIALIZED)
        return ERR_DB_NOT_INITIALIZED;

    if (OTK == NULL)
        return ERR_OTK_NOT_INITIALIZED;

    PIPASS_ERR err;

    if (DEK_BLOB != NULL) {
        err = invalidate_DEK_BLOB();
        if (err != PIPASS_OK)
            return err;
    }

    erase_buffer(&OTK, AES256_KEY_SIZE);

    FL_LOGGED_IN = 0;

    return PIPASS_OK;
}

PIPASS_ERR invalidate_DEK_BLOB() {
     if (!FL_LOGGED_IN)
        return ERR_NOT_LOGGED_IN;

    if (!FL_DB_INITIALIZED)
        return ERR_DB_NOT_INITIALIZED;

    if (DEK_BLOB == NULL)
        return ERR_DEK_BLOB_NOT_INIT;

    PIPASS_ERR err;

    free_datablob(DEK_BLOB, AES256_KEY_SIZE);
    free(DEK_BLOB);
    DEK_BLOB = NULL;

    return PIPASS_OK;
}