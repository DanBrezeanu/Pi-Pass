#include <database.h>
#include <credentials.h>
#include <crypto.h>
#include <aes256.h>
#include <sha256.h>
#include <datablob.h>
#include <datahash.h>
#include <storage_utils.h>
#include <database_utils.h>

static struct Database *db;
static struct DatabaseHeader *db_header;

PIPASS_ERR db_create_new(uint8_t *master_pass) {
    if (db != NULL || FL_DB_INITIALIZED)
        return ERR_DB_ALREADY_INIT;

    db = calloc(1, sizeof(struct Database));
    if (db == NULL)
        return ERR_DB_MEM_ALLOC;

    db_header = calloc(1, sizeof(struct DatabaseHeader));
    if (db_header == NULL)
        return ERR_DB_MEM_ALLOC;

    db->header = db_header;

    memset(&(db->dek), 0, sizeof(struct DataBlob));
    memset(&(db->header->master_pass_hash), 0, sizeof(struct DataHash));

    PIPASS_ERR err;
    uint8_t *dek = NULL;  
    uint8_t *kek = NULL;

    err = generate_new_master_passw_hash(master_pass, &db->header->master_pass_hash);
    if (err != PIPASS_OK)
        goto error;

    err = generate_KEK(master_pass, db->header->master_pass_hash.salt, &kek);
    if (err != PIPASS_OK)
        goto error;
    
    dek = malloc(AES256_KEY_SIZE);
    if (dek == NULL) {
        err = ERR_DB_MEM_ALLOC;
        goto error;
    }

    err = generate_aes256_key(dek);
    if (err != PIPASS_OK)
        goto error;

    err = encrypt_DEK_with_KEK(dek, kek, &db->dek);
    if (err != PIPASS_OK)
        goto error;

    db->__guard_value = DEFAULT_GUARD_VALUE;
    db->header->version = PIPASS_VERSION;

    db->header->db_len = sizeof(db->__guard_value) + sizeof(db->cred_len) +
        AES256_KEY_SIZE + MAC_SIZE + IV_SIZE; 

    erase_buffer(&dek, AES256_KEY_SIZE);
    erase_buffer(&kek, AES256_KEY_SIZE);

    return PIPASS_OK;

error:
    erase_buffer(&dek, AES256_KEY_SIZE);
    erase_buffer(&kek, AES256_KEY_SIZE);
    db_free();

    return err;
}

PIPASS_ERR db_update_master_pass_hash(struct DataHash *new_master_pass_hash, 
  uint8_t *new_master_pass, uint8_t *old_master_pass) {
     if (db == NULL || !FL_DB_INITIALIZED)
        return ERR_DB_NOT_INITIALIZED;

    if (!FL_LOGGED_IN)
        return ERR_NOT_LOGGED_IN;

    if (datahash_has_null_fields(db->header->master_pass_hash))
        return ERR_DB_MISSING_PASSW_HASH;

    if (new_master_pass_hash == NULL || datahash_has_null_fields(*new_master_pass_hash) ||
      new_master_pass == NULL || old_master_pass == NULL)
        return ERR_DB_UPDATE_LOGIN_INV_PARAMS;

    PIPASS_ERR err = PIPASS_OK;

    err = verify_master_password_with_hash(new_master_pass, *new_master_pass_hash);
    if (err != PIPASS_OK)
        return err;

    err = verify_master_password_with_db(old_master_pass);
    if (err != PIPASS_OK)
        return err;

    if (db->dek.ciphertext != NULL) {
        err = reencrypt_DEK(&(db->dek), new_master_pass, new_master_pass_hash->salt, old_master_pass,
          db->header->master_pass_hash.salt);
    }  

    err = datahash_memcpy(&(db->header->master_pass_hash), new_master_pass_hash);
    if (err != PIPASS_OK)
        goto error;

    return DB_OK;

error:
    
    // TODO: complete error frees
    return err;
}

PIPASS_ERR db_update_DEK(uint8_t *dek, uint8_t *master_pass) {
    if (db == NULL || !FL_DB_INITIALIZED)
        return ERR_DB_NOT_INITIALIZED;

    if (!FL_LOGGED_IN || OTK == NULL)
        return ERR_NOT_LOGGED_IN;

    if (dek == NULL || master_pass == NULL)   
        return ERR_DB_UPDATE_DEK_INV_PARAMS;
    
    if (datablob_has_null_fields(db->dek))
        return ERR_DB_MISSING_DEK;
    
    PIPASS_ERR err;
    uint8_t *kek = NULL;
    struct DataBlob dek_blob;

    err = verify_master_password_with_db(master_pass);
    if (err != PIPASS_OK)
        return err;
    
    err = generate_KEK(master_pass, db->header->master_pass_hash.salt, &kek);
    if (err != PIPASS_OK)
        return err;

    err = encrypt_DEK_with_KEK(dek, kek, &dek_blob);
    if (err != PIPASS_OK)
        goto error;

    err = datablob_memcpy(&(db->dek), &dek_blob, AES256_KEY_SIZE);
    if (err != PIPASS_OK)
        goto error;

    err = invalidate_OTK();
    if (err != PIPASS_OK)
        goto error;

    err = PIPASS_OK;

error:
    erase_buffer(&kek, AES256_KEY_SIZE);
    free_datablob(&dek_blob, AES256_KEY_SIZE);

    return err;
}

PIPASS_ERR db_append_credential(struct Credential *cr, struct CredentialHeader *crh) {
    if (!FL_LOGGED_IN)
        return ERR_NOT_LOGGED_IN;

    if (!FL_DB_INITIALIZED || db == NULL)
        return ERR_DB_NOT_INITIALIZED;

    if (cr == NULL || crh == NULL)
        return ERR_DB_APPEND_CRED_INV_PARAMS;

    if (datablob_has_null_fields(cr->username) || datablob_has_null_fields(cr->password) || 
      !crh->passw_len || !crh->username_len)
        return ERR_DB_APPEND_CRED_INV_CRED; 

    PIPASS_ERR err = PIPASS_OK;

    struct Credential *_tmp_cr = NULL;
    _tmp_cr = realloc(db->cred, (db->cred_len + 1) * sizeof(struct Credential));
    if (_tmp_cr == NULL)
        return ERR_DB_MEM_ALLOC;
    
    db->cred = _tmp_cr;

    struct CredentialHeader *_tmp_crh = NULL;
    _tmp_crh = realloc(db->cred_headers, (db->cred_len + 1) * sizeof(struct CredentialHeader));
    if (_tmp_crh == NULL)
        return ERR_DB_MEM_ALLOC;

    db->cred_headers = _tmp_crh;

    struct Credential *new_cr = &(db->cred[db->cred_len]);
    struct CredentialHeader *new_crh = &(db->cred_headers[db->cred_len]);
    db->cred_len++;

    zero_credential(new_cr);
    zero_credential_header(new_crh);

    if (crh->name_len > 0) {
        err = populate_plaintext_field(new_cr, new_crh, cr->name, crh->name_len, NAME);
        if (err != DB_OK)
            goto error;
    }

    if (crh->url_len > 0) {
        err = populate_plaintext_field(new_cr, new_crh, cr->url, crh->url_len, URL);
        if (err != DB_OK)
            goto error;
    }
    
    if (crh->additional_len > 0) {
        err = populate_plaintext_field(new_cr, new_crh, cr->additional, crh->additional_len, ADDITIONAL);
        if (err != DB_OK)
            goto error;
    }

    err = alloc_datablob(&(new_cr->username), crh->username_len);
    if (err != PIPASS_OK)
        goto error;
    
    err = alloc_datablob(&(new_cr->password), crh->username_len);
    if (err != PIPASS_OK)
        goto error;

    err = memcpy_credential_blobs(new_cr, cr, crh);
    if (err != PIPASS_OK)
        goto error;

    new_crh->username_len = crh->username_len; 
    new_crh->passw_len = crh->passw_len;

    recalculate_header_len(new_crh);

    return PIPASS_OK;

error:
    free_datablob(&(new_cr->username), crh->username_len);
    free_datablob(&(new_cr->password), crh->passw_len);

    db->cred_len--;

    return err;
}

PIPASS_ERR db_raw(uint8_t **raw_db, int32_t *raw_db_size) {
    if (!FL_LOGGED_IN)
        return ERR_NOT_LOGGED_IN;

    if (!FL_DB_INITIALIZED || db == NULL)
        return ERR_DB_NOT_INITIALIZED;

    if (*raw_db != NULL)
        return ERR_RAW_DB_MEM_LEAK;

    int32_t raw_cursor = 0;
    *raw_db = malloc(db->header->db_len);
    if (*raw_db == NULL)
        return ERR_RAW_DB_MEM_ALLOC;

    uint8_t *guard_value_bin = var_to_bin(&db->__guard_value, sizeof(db->__guard_value));
    if (guard_value_bin == NULL)
        return ERR_RAW_DB_MEM_ALLOC;
    append_to_str(*raw_db, &raw_cursor, guard_value_bin, sizeof(db->__guard_value));
    erase_buffer(&guard_value_bin, sizeof(db->__guard_value));


    uint8_t *cred_len_bin = var_to_bin(&db->cred_len, sizeof(db->cred_len));
    if (cred_len_bin == NULL)
        return ERR_RAW_DB_MEM_ALLOC;
    append_to_str(*raw_db, &raw_cursor, cred_len_bin, sizeof(db->cred_len));
    erase_buffer(&cred_len_bin, sizeof(db->cred_len));

    for (int i = 0; i < db->cred_len; ++i) {
        struct CredentialHeader *crh = &(db->cred_headers[i]);
        struct Credential *cr = &(db->cred[i]);

        uint8_t *crh_bin = var_to_bin(crh, CREDENTIAL_HEADER_SIZE);
        if (crh_bin == NULL)
            return ERR_RAW_DB_MEM_ALLOC;

        append_to_str(*raw_db, &raw_cursor, crh_bin, CREDENTIAL_HEADER_SIZE);
        erase_buffer(&crh_bin, CREDENTIAL_HEADER_SIZE);

        
        append_to_str(*raw_db, &raw_cursor, cr->name, crh->name_len);
        append_to_str(*raw_db, &raw_cursor, cr->username.ciphertext, crh->username_len);
        append_to_str(*raw_db, &raw_cursor, cr->username.mac, MAC_SIZE);
        append_to_str(*raw_db, &raw_cursor, cr->username.iv, IV_SIZE);
        append_to_str(*raw_db, &raw_cursor, cr->password.ciphertext, crh->passw_len);
        append_to_str(*raw_db, &raw_cursor, cr->password.mac, MAC_SIZE);
        append_to_str(*raw_db, &raw_cursor, cr->password.iv, IV_SIZE);
        append_to_str(*raw_db, &raw_cursor, cr->url, crh->url_len);
        append_to_str(*raw_db, &raw_cursor, cr->additional, crh->additional_len);   
    }

    append_to_str(*raw_db, &raw_cursor, db->dek.ciphertext, AES256_KEY_SIZE);
    append_to_str(*raw_db, &raw_cursor, db->dek.mac, MAC_SIZE);
    append_to_str(*raw_db, &raw_cursor, db->dek.iv, IV_SIZE);

    *raw_db_size = db->header->db_len;
    //TODO: write error for this
    return PIPASS_OK;
}

PIPASS_ERR db_header_raw(uint8_t **raw_db_header) {
    if (!FL_DB_HEADER_LOADED || db_header == NULL)
        return ERR_DB_HEADER_NOT_LOADED;

    if (*raw_db_header != NULL)
        return ERR_RAW_DB_MEM_LEAK;

    PIPASS_ERR err;

    int32_t raw_cursor = 0;
    *raw_db_header = malloc(DB_HEADER_SIZE);
    if (*raw_db_header == NULL)
        return ERR_RAW_DB_MEM_ALLOC;

    uint8_t *version_bin = var_to_bin(&db_header->version, sizeof(db_header->version));
    if (version_bin == NULL) {
        err = ERR_RAW_DB_MEM_ALLOC;
        goto error;
    }

    append_to_str(*raw_db_header, &raw_cursor, version_bin, sizeof(db_header->version));
    erase_buffer(&version_bin, sizeof(db_header->version));


    uint8_t *db_len_bin = var_to_bin(&db_header->db_len, sizeof(db_header->db_len));
    if (db_len_bin == NULL) {
        err = ERR_RAW_DB_MEM_ALLOC;
        goto error;
    }
    append_to_str(*raw_db_header, &raw_cursor, db_len_bin, sizeof(db_header->db_len));
    erase_buffer(&db_len_bin, sizeof(db_header->db_len));

    append_to_str(*raw_db_header, &raw_cursor, db_header->master_pass_hash.hash, SHA256_DGST_SIZE);
    append_to_str(*raw_db_header, &raw_cursor, db_header->master_pass_hash.salt, SALT_SIZE);

    return PIPASS_OK;

error:
    erase_buffer(raw_db_header, DB_HEADER_SIZE);
    erase_buffer(&version_bin, sizeof(db_header->version));
    erase_buffer(&db_len_bin, sizeof(db_header->db_len));

    return err;
}

PIPASS_ERR db_get_master_pass_hash(struct DataHash *master_pass_hash) {
    if (master_pass_hash == NULL || datahash_has_null_fields(*master_pass_hash))
        return ERR_GET_MASTER_PWD_INV_PARAMS;

    struct DatabaseHeader *header = NULL;
    PIPASS_ERR err;

    if (!FL_DB_INITIALIZED) {
        if (FL_DB_HEADER_LOADED)
           header = db_header;
        else
            return ERR_DB_HEADER_NOT_LOADED;
    } else {
        header = db->header;
    }

    if (datahash_has_null_fields(header->master_pass_hash))
        return ERR_DB_MISSING_PASSW_HASH;
         
    err = datahash_memcpy(master_pass_hash, &(header->master_pass_hash));
    if (err != PIPASS_OK)
        return err;

    return PIPASS_OK;
}

PIPASS_ERR db_get_DEK(struct DataBlob *dek) {
    if (db == NULL || !FL_DB_INITIALIZED)
        return ERR_DB_NOT_INITIALIZED;

    PIPASS_ERR err;

    err = datablob_memcpy(dek, &(db->dek), AES256_KEY_SIZE);
    if (err != PIPASS_OK)
        return err;

    return PIPASS_OK;
}

PIPASS_ERR db_get_length(uint32_t *db_len) {
    if (db_header == NULL || !FL_DB_HEADER_LOADED)
        return ERR_DB_HEADER_NOT_LOADED;

    *db_len = db_header->db_len;

    return PIPASS_OK;
}

void db_free() {
    if (db == NULL || !FL_DB_INITIALIZED)
        return;

    free_datablob(&db->dek, AES256_KEY_SIZE);
    free_datahash(&db->header->master_pass_hash);

    for (int i = 0; i < db->cred_len; ++i)
        free_credential(&(db->cred[i]), &(db->cred_headers[i]));

    free(db->cred);
    free(db->cred_headers);

    db->cred_len = db->header->db_len = db->header->version = 0;

    db_free_header();

    free(db);
    db = NULL;
}

void db_free_header() {
    if (db_header == NULL)
        return;

    free_datahash(&db_header->master_pass_hash);

    free(db_header);
    db_header = NULL;
}

PIPASS_ERR load_database(struct DataBlob *raw_db, uint32_t db_len, uint8_t *kek) {
    if (!FL_LOGGED_IN)
        return ERR_NOT_LOGGED_IN;
    
    if (FL_DB_INITIALIZED || db != NULL)
        return ERR_DB_ALREADY_INIT;

    if (!FL_DB_HEADER_LOADED || db_header == NULL)
        return ERR_DB_HEADER_NOT_LOADED;

    if (raw_db == NULL)
        return ERR_LOAD_DB_INV_PARAMS;

    PIPASS_ERR err;
    uint8_t *raw_db_data = NULL;
    uint32_t read_cursor = 0;

    err = decrypt_cipher_with_key(raw_db, db_len, kek, &raw_db_data);
    if (err != PIPASS_OK)
        return err;

    db = calloc(1, sizeof(struct Database));
    if (db == NULL) {
        err = ERR_DB_MEM_ALLOC;
        goto error;
    } 

    err = read_db_field_32b_from_raw(raw_db_data, &read_cursor, db_len, &(db->__guard_value));
    if (err != PIPASS_OK)
        goto error;

    if (db->__guard_value != DEFAULT_GUARD_VALUE) {
        err = ERR_GUARD_VALUE_DOES_NOT_MATCH;
        goto error;
    }

    err = read_db_field_32b_from_raw(raw_db_data, &read_cursor, db_len, &(db->cred_len));
    if (err != PIPASS_OK)
        goto error;

    if (db->cred_len == 0)
        goto skip_loading_credentials;

    db->cred = calloc(db->cred_len, sizeof(struct Credential));
    db->cred_headers = calloc(db->cred_len, sizeof(struct CredentialHeader));
    if (db->cred == NULL || db->cred_headers == NULL)
        return ERR_DB_MEM_ALLOC;
    
    err = read_credentials_from_raw(raw_db_data, &read_cursor, db_len, db->cred, db->cred_headers, db->cred_len);
    if (err != PIPASS_OK)
        goto error;

skip_loading_credentials:
    err = read_datablob_from_raw(raw_db_data, &read_cursor, db_len, &(db->dek), AES256_KEY_SIZE);
    if (err != PIPASS_OK)
        goto error;

    db->header = db_header;

    return PIPASS_OK;

error:
    erase_buffer(&raw_db_data, db_len);
    db_free();
}

PIPASS_ERR load_database_header(uint8_t *raw_db_header) {
    if (FL_LOGGED_IN)
        return ERR_ALREADY_LOGGED_IN;

    if (FL_DB_INITIALIZED || db != NULL)
        return ERR_DB_ALREADY_INIT;

    if (FL_DB_HEADER_LOADED || db_header != NULL)
        return ERR_DB_HEADER_ALREADY_LOADED;

    if (raw_db_header == NULL)
        return ERR_LOAD_DB_HEADER_INV_PARAMS;

    PIPASS_ERR err;
    uint16_t *db_version = NULL;
    uint32_t *db_len = NULL;

    db_header = calloc(1, sizeof(struct DatabaseHeader));

    db_version = (uint16_t *)bin_to_var(raw_db_header, sizeof(uint16_t));
    if (db_version  == NULL) {
        err = ERR_DB_MEM_ALLOC;
        goto error;
    }

    db_header->db_len = *db_version;
    raw_db_header += sizeof(uint16_t);
    
    db_len = (uint32_t *)bin_to_var(raw_db_header, sizeof(uint32_t));
    if (db_len == NULL) {
        err = ERR_DB_MEM_ALLOC;
        goto error;
    }

    db_header->db_len = *db_len;
    raw_db_header += sizeof(uint32_t);

    err = alloc_datahash(&db_header->master_pass_hash);
    if (err != PIPASS_OK)
        goto error;

    memcpy(db_header->master_pass_hash.hash, raw_db_header, SHA256_DGST_SIZE);
    memcpy(db_header->master_pass_hash.salt, raw_db_header + SHA256_DGST_SIZE, SALT_SIZE);

    err = PIPASS_OK;
    goto cleanup;

error:
    free_datahash(&db_header->master_pass_hash);
    free(db_header);
cleanup:
    if (db_version != NULL)
        free(db_version);
    
    if (db_len != NULL)
        free(db_len);

    return err;
}
