#include <crypto.h>
#include <aes256.h>
#include <database.h>
#include <credentials.h>
#include <sha256.h>

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
    erase_buffer(salt, SALT_SIZE);
    erase_buffer(KEK, AES256_KEY_SIZE);

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
    erase_buffer(iv, IV_SIZE);
    erase_buffer(DEK_blob, AES256_KEY_SIZE);
    erase_buffer(mac, MAC_SIZE);

    return err;
}

CRYPTO_ERR generate_user_hash(uint8_t *user_data, int32_t user_data_len, uint8_t **user_hash) {
    uint8_t *user_hash_raw = NULL;
    
    if (user_data == NULL || user_data_len == 0) 
        return ERR_CRYPTO_GEN_HASH_INV_PARAMS;

    if (*user_hash != NULL)
        return ERR_MEM_LEAK;

    user_hash_raw = malloc(SHA256_DGST_SIZE + 1);
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

    erase_buffer(&user_hash_raw, SHA256_DGST_SIZE);

    return STORAGE_OK;

error:
    erase_buffer(user_hash, SHA256_DGST_SIZE);
    erase_buffer(&user_hash_raw, SHA256_HEX_SIZE);

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

CRYPTO_ERR encrypt_db_field(struct Database *db, uint8_t *kek, uint8_t *data, enum DatabaseEncryptedField field) {
    if (db == NULL || kek == NULL || data == NULL)
        return ERR_ENC_DB_FIELD_INV_PARAMS;

    CRYPTO_ERR err = CRYPTO_OK;
    uint8_t **cipher = NULL, **mac = NULL, **iv = NULL;
    uint32_t data_len = 0;

    switch (field) {
    case DEK_BLOB:
        cipher = &(db->dek_blob);
        mac    = &(db->dek_blob_enc_mac);
        iv     = &(db->dek_blob_enc_iv);
        data_len = AES256_KEY_SIZE;
        break;
    case IV_DEK_BLOB:
        cipher = &(db->iv_dek_blob);
        mac    = &(db->iv_dek_blob_enc_mac);
        iv     = &(db->iv_dek_blob_enc_iv);
        data_len = IV_SIZE;
        break;
    case MAC_DEK_BLOB:
        cipher = &(db->mac_dek_blob);
        mac    = &(db->mac_dek_blob_enc_mac);
        iv     = &(db->mac_dek_blob_enc_iv);
        data_len = MAC_SIZE;
        break;
    default:
        return ERR_ENC_DB_INV_FIELD;
    }

    if (*cipher != NULL || *mac != NULL || *iv != NULL)
        return ERR_ENC_DB_MEM_LEAK;

    *cipher = malloc(data_len);
    if (*cipher == NULL) {
        err = ERR_CRYPTO_MEM_ALLOC;
        goto error;
    }

    *iv = malloc(IV_SIZE);
    if (*iv == NULL) {
        err = ERR_CRYPTO_MEM_ALLOC;
        goto error;
    }

    *mac = malloc(MAC_SIZE);
    if (*mac == NULL) {
        err = ERR_CRYPTO_MEM_ALLOC;
        goto error;
    }

    int32_t cipher_len = 0;
    err = encrypt_aes256(data, data_len, NULL, 0, kek, *iv, *mac, *cipher, &cipher_len);
    if (err != CRYPTO_OK)
        goto error;

    return CRYPTO_OK;

error:
    erase_buffer(cipher, data_len);
    erase_buffer(iv, IV_SIZE);
    erase_buffer(mac, MAC_SIZE);

    return err;
}

CRYPTO_ERR decrypt_db_field(struct Database *db, uint8_t *kek, uint8_t **data, enum DatabaseEncryptedField field) {
    if (db == NULL || kek == NULL)
        return ERR_DEC_DB_FIELD_INV_PARAMS;

    if (*data != NULL)
        return ERR_DEC_DB_FIELD_MEM_LEAK;

    CRYPTO_ERR err = CRYPTO_OK;
    uint8_t *cipher = NULL, *mac = NULL, *iv = NULL;
    uint32_t cipher_len = 0;

    switch (field) {
    case DEK_BLOB:
        cipher = db->dek_blob;
        mac    = db->dek_blob_enc_mac;
        iv     = db->dek_blob_enc_iv;
        cipher_len = AES256_KEY_SIZE;
        break;
    case IV_DEK_BLOB:
        cipher = db->iv_dek_blob;
        mac    = db->iv_dek_blob_enc_mac;
        iv     = db->iv_dek_blob_enc_iv;
        cipher_len = IV_SIZE;
        break;
    case MAC_DEK_BLOB:
        cipher = db->mac_dek_blob;
        mac    = db->mac_dek_blob_enc_mac;
        iv     = db->mac_dek_blob_enc_iv;
        cipher_len = MAC_SIZE;
        break;
    default:
        return ERR_DEC_DB_INV_FIELD;
    }

    if (cipher == NULL || mac == NULL || iv == NULL)
        return ERR_DEC_DB_FIELD_MISSING_FIELD;

    *data = malloc(cipher_len);
    if (*data == NULL) {
        err = ERR_CRYPTO_MEM_ALLOC;
        goto error;
    }

    int32_t data_len = 0;
    err = decrypt_aes256(cipher, cipher_len, NULL, 0, mac, kek, iv, *data, &data_len);
    if (err != CRYPTO_OK)
        goto error;

    return CRYPTO_OK;

error:
    erase_buffer(data, data_len);

    return err;
}

CRYPTO_ERR encrypt_credential_field(struct Database *db, uint8_t *data, int32_t data_len, uint8_t *master_pass,
  uint8_t **cipher, uint8_t **iv, uint8_t **mac, int16_t *cipher_len) {
    
    if (db == NULL || data == NULL || !data_len || master_pass == NULL || cipher_len == NULL)
        return ERR_ENC_CRED_INV_PARAMS;

    if (*cipher != NULL || *iv != NULL || *mac != NULL)
        return ERR_CRYPTO_MEM_LEAK;

    if (db->dek_blob == NULL || db->iv_dek_blob == NULL || db->mac_dek_blob == NULL ||
      db->dek_blob_enc_mac == NULL || db->iv_dek_blob_enc_mac == NULL || db->mac_dek_blob_enc_mac == NULL ||
      db->dek_blob_enc_iv == NULL || db->iv_dek_blob_enc_iv == NULL || db->mac_dek_blob_enc_iv == NULL)
        return ERR_ENC_CRED_MISSING_DEK;

    if (db->kek_hash == NULL || db->kek_salt == NULL)
        return ERR_ENC_CRED_MISSING_KEK;

    CRYPTO_ERR err = CRYPTO_OK;
    uint8_t *dek_blob = NULL, *iv_dek_blob = NULL, *mac_dek_blob = NULL;
    uint8_t *dek = NULL;
    
    uint8_t *kek = malloc(AES256_KEY_SIZE);
    if (kek == NULL)
        return ERR_ENC_CRED_MEM_ALLOC; 

    err = create_PBKDF2_key(master_pass, MASTER_PASS_SIZE, db->kek_salt, SALT_SIZE, kek);
    if (err != CRYPTO_OK)
        goto error;

    err = verify_sha256(kek, AES256_KEY_SIZE, db->kek_salt, SALT_SIZE, db->kek_hash);
    if (err != CRYPTO_OK)
        goto error;

    err = decrypt_db_field(db, kek, &dek_blob, DEK_BLOB);
    if (err != CRYPTO_OK)
        goto error;

    err = decrypt_db_field(db, kek, &iv_dek_blob, IV_DEK_BLOB);
    if (err != CRYPTO_OK)
        goto error;

    err = decrypt_db_field(db, kek, &mac_dek_blob, MAC_DEK_BLOB);
    if (err != CRYPTO_OK)
        goto error;

    dek = malloc(AES256_KEY_SIZE);
    if (dek == NULL) {
        err = ERR_ENC_CRED_MEM_ALLOC;
        goto error;
    }

    int32_t dek_size = 0;
    err = decrypt_aes256(dek_blob, AES256_KEY_SIZE, master_pass, MASTER_PASS_SIZE, mac_dek_blob,
        kek, iv_dek_blob, dek, &dek_size);
    if (err != CRYPTO_OK || dek_size != AES256_KEY_SIZE) {
        err = ERR_ENC_CRED_DEK_DECRYPT_FAIL;
        goto error;
    }

    erase_buffer(&kek, AES256_KEY_SIZE);
    erase_buffer(&dek_blob, AES256_KEY_SIZE);
    erase_buffer(&iv_dek_blob, IV_SIZE);
    erase_buffer(&mac_dek_blob, MAC_SIZE);

    *cipher = malloc(data_len);
    if (*cipher == NULL) {
        err = ERR_ENC_CRED_MEM_ALLOC;
        goto error;
    }

    *iv = malloc(IV_SIZE);
    if (*iv == NULL) {
        err = ERR_ENC_CRED_MEM_ALLOC;
        goto error;
    }

    *mac = malloc(MAC_SIZE);
    if (*mac == NULL) {
        err = ERR_ENC_CRED_MEM_ALLOC;
        goto error;
    }

    err = encrypt_aes256(data, data_len, NULL, 0, dek, *iv, *mac, *cipher, (int32_t *)cipher_len);
    if (err != CRYPTO_OK)
        goto error;

    erase_buffer(&dek, AES256_KEY_SIZE);

    return CRYPTO_OK;

error:
    erase_buffer(&dek, AES256_KEY_SIZE);
    erase_buffer(&kek, AES256_KEY_SIZE);
    erase_buffer(&dek_blob, AES256_KEY_SIZE);
    erase_buffer(&iv_dek_blob, IV_SIZE);
    erase_buffer(&mac_dek_blob, MAC_SIZE);
    erase_buffer(cipher, data_len);
    erase_buffer(iv, IV_SIZE);
    erase_buffer(mac, MAC_SIZE);

    return err;
}

CRYPTO_ERR decrypt_credential_field(struct Database *db, uint8_t **data, int32_t *data_len, uint8_t *master_pass,
  uint8_t *cipher, uint8_t *iv, uint8_t *mac, int16_t cipher_len) {
    
    if (db == NULL || cipher == NULL || iv == NULL || mac == NULL || !cipher_len || master_pass == NULL)
        return ERR_DEC_CRED_INV_PARAMS;

    if (*data == NULL || !data_len)
        return ERR_DEC_CRED_MEM_LEAK;

    if (db->dek_blob == NULL || db->iv_dek_blob == NULL || db->mac_dek_blob == NULL ||
      db->dek_blob_enc_mac == NULL || db->iv_dek_blob_enc_mac == NULL || db->mac_dek_blob_enc_mac == NULL ||
      db->dek_blob_enc_iv == NULL || db->iv_dek_blob_enc_iv == NULL || db->mac_dek_blob_enc_iv == NULL)
        return ERR_DEC_CRED_MISSING_DEK;

    if (db->kek_hash == NULL || db->kek_salt == NULL)
        return ERR_DEC_CRED_MISSING_KEK;

    CRYPTO_ERR err = CRYPTO_OK;
    uint8_t *dek_blob = NULL, *iv_dek_blob = NULL, *mac_dek_blob = NULL;
    uint8_t *dek = NULL;
    
    uint8_t *kek = malloc(AES256_KEY_SIZE);
    if (kek == NULL)
        return ERR_DEC_CRED_MEM_ALLOC; 

    err = create_PBKDF2_key(master_pass, MASTER_PASS_SIZE, db->kek_salt, SALT_SIZE, kek);
    if (err != CRYPTO_OK)
        goto error;

    err = verify_sha256(kek, AES256_KEY_SIZE, db->kek_salt, SALT_SIZE, db->kek_hash);
    if (err != CRYPTO_OK)
        goto error;

    err = decrypt_db_field(db, kek, &dek_blob, DEK_BLOB);
    if (err != CRYPTO_OK)
        goto error;

    err = decrypt_db_field(db, kek, &iv_dek_blob, IV_DEK_BLOB);
    if (err != CRYPTO_OK)
        goto error;

    err = decrypt_db_field(db, kek, &mac_dek_blob, MAC_DEK_BLOB);
    if (err != CRYPTO_OK)
        goto error;

    dek = malloc(AES256_KEY_SIZE);
    if (dek == NULL) {
        err = ERR_DEC_CRED_MEM_ALLOC;
        goto error;
    }

    int32_t dek_size = 0;
    err = decrypt_aes256(dek_blob, AES256_KEY_SIZE, master_pass, MASTER_PASS_SIZE, mac_dek_blob,
        kek, iv_dek_blob, dek, &dek_size);
    if (err != CRYPTO_OK || dek_size != AES256_KEY_SIZE) {
        err = ERR_ENC_CRED_DEK_DECRYPT_FAIL;
        goto error;
    }

    erase_buffer(&kek, AES256_KEY_SIZE);
    erase_buffer(&dek_blob, AES256_KEY_SIZE);
    erase_buffer(&iv_dek_blob, IV_SIZE);
    erase_buffer(&mac_dek_blob, MAC_SIZE);

    *data = malloc(cipher_len);
    if (*data == NULL) {
        err = ERR_DEC_CRED_MEM_ALLOC;
        goto error;
    }

    err = decrypt_aes256(cipher, cipher_len, NULL, 0, mac, dek, iv, *data, data_len);
    if (err != CRYPTO_OK)
        goto error;

    erase_buffer(&dek, AES256_KEY_SIZE);

    return CRYPTO_OK;

error:
    erase_buffer(&dek, AES256_KEY_SIZE);
    erase_buffer(&kek, AES256_KEY_SIZE);
    erase_buffer(&dek_blob, AES256_KEY_SIZE);
    erase_buffer(&iv_dek_blob, IV_SIZE);
    erase_buffer(&mac_dek_blob, MAC_SIZE);
    erase_buffer(data, cipher_len);

    return err;
}