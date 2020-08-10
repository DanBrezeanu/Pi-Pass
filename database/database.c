DB_ERROR create_new_db(struct Database *db) {
    if (db != NULL)
        return ERR_DB_MEM_LEAK;

    db = calloc(1, sizeof(struct Database));
    if (db == NULL)
        return ERR_DB_MEM_ALLOC;

    db->version = PIPASS_VERSION;
    db->len = 2 + 4 + 4;

    return DB_OK;
}

DB_ERROR update_db_DEK(struct Database *db, uint8_t *dek_blob, uint8_t *iv_dek_blob, uint8_t *mac_dek_blob, uint8_t *master_pass) {
    if (db == NULL || dek_blob == NULL || iv_dek_blob == NULL || mac_dek_blob == NULL || master_pass == NULL)   
        return ERR_DB_UPDATE_DEK_INV_PARAMS;

    if (db->dek_blob != NULL || db->iv_dek_blob != NULL || db->mac_dek_blob != NULL ||
        db->dek_blob_enc_mac != NULL || db->iv_dek_blob_enc_mac != NULL || db->mac_dek_blob_enc_mac != NULL ||
        db->dek_blob_enc_iv != NULL || db->iv_dek_blob_enc_iv != NULL || db->mac_dek_blob_enc_iv != NULL)
        return ERR_DB_MEM_LEAK;

    if (db->kek_salt == NULL || db->kek_hash == NULL)
        return ERR_DB_MISSING_KEK;

    uint8_t *kek = malloc(AES256_KEY_SIZE);
    if (kek == NULL)
        return ERR_DB_MEM_ALLOC;

    CRYPTO_ERR err = create_PBKDF2_key(master_pass, MASTE_PASS_SIZE, db->kek_salt, SALT_SIZE, kek);
    if (err != CRYPTO_OK)
        goto error;

    err = verify_sha256(kek, AES256_KEY_SIZE, db->kek_salt, SALT_SIZE, db->kek_hash);
    if (err != CRYPTO_OK)
        goto error;

    err = encrypt_db_field(db, kek, dek_blob, DEK_BLOB);
    if (err != CRYPTO_OK)
        goto error;

    err = encrypt_db_field(db, kek, iv_dek_blob, IV_DEK_BLOB);
    if (err != CRYPTO_OK)
        goto error;

    err = encrypt_db_field(db, kek, mac_dek_blob, MAC_DEK_BLOB);
    if (err != CRYPTO_OK)
        goto error;

    erase_buffer(&kek, AES256_KEY_SIZE);

    return DB_OK;

error:
    erase_buffer(&kek, AES256_KEY_SIZE);
    erase_buffer(&(db->dek_blob), AES256_KEY_SIZE);
    erase_buffer(&(db->dek_blob_enc_iv), IV_SIZE);
    erase_buffer(&(db->dek_blob_enc_mac), MAC_SIZE);
    erase_buffer(&(db->iv_dek_blob), IV_SIZE);
    erase_buffer(&(db->iv_dek_blob_enc_iv), IV_SIZE);
    erase_buffer(&(db->iv_dek_blob_enc_mac), MAC_SIZE);
    erase_buffer(&(db->mac_dek_blob), MAC_SIZE);
    erase_buffer(&(db->mac_dek_blob_enc_iv), IV_SIZE);
    erase_buffer(&(db->mac_dek_blob_enc_mac), MAC_SIZE);

    return err;
}

DB_ERROR update_db_login(struct Database *db, uint8_t *login_hash, uint8_t *login_salt) {
    if (db == NULL || login_hash == NULL || login_salt == NULL)
        return ERR_DB_UPDATE_LOGIN_INV_PARAMS;
    
    if (db->login_salt != NULL || db->login_hash != NULL)   
        return ERR_DB_MEM_LEAK;

    DB_ERROR err = DB_OK;

    db->login_hash = malloc(SHA256_DGST_SIZE);
    if (db->login_hash == NULL)
        return ERR_DB_MEM_LEAK;

    db->login_salt = malloc(SALT_SIZE);
    if (db->login_salt == NULL) {
        err = ERR_DB_MEM_ALLOC;
        goto error;
    }

    memcpy(db->login_hash, login_hash, SHA256_DGST_SIZE);
    memcpy(db->login_salt, login_salt, SALT_SIZE);

    return DB_OK;

error:
    zero_buffer(&(db->login_hash), SHA256_DGST_SIZE);
    zero_buffer(&(db->login_salt), SALT_SIZE);

    return err;
}


DB_ERROR update_db_KEK(struct Database *db, uint8_t *kek_hash, uint8_t *kek_salt) {
    if (db == NULL || kek_hash == NULL || kek_salt == NULL)
        return ERR_DB_UPDATE_KEK_INV_PARAMS;
    
    if (db->kek_salt != NULL || db->kek_hash != NULL)   
        return ERR_DB_MEM_LEAK;

    DB_ERROR err = DB_OK;

    db->kek_hash = malloc(SHA256_DGST_SIZE);
    if (db->kek_hash == NULL)
        return ERR_DB_MEM_LEAK;

    db->kek_salt = malloc(SALT_SIZE);
    if (db->kek_salt == NULL) {
        err = ERR_DB_MEM_ALLOC;
        goto error;
    }

    memcpy(db->kek_hash, kek_hash, SHA256_DGST_SIZE);
    memcpy(db->kek_salt, kek_salt, SALT_SIZE);

    return DB_OK;

error:
    zero_buffer(&(db->kek_hash), SHA256_DGST_SIZE);
    zero_buffer(&(db->kek_salt), SALT_SIZE);

    return err;
}