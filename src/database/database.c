#include <database.h>
#include <credentials.h>
#include <crypto.h>
#include <aes256.h>
#include <sha256.h>
#include <datablob.h>
#include <datahash.h>
#include <storage_utils.h>
#include <database_utils.h>
#include <fingerprint.h>

static struct Database *db;
static struct DatabaseHeader *db_header;

PIPASS_ERR db_create_new(uint8_t *master_pin, uint8_t *fp_key, uint8_t *master_password,
  uint32_t master_password_len) {
    if (db != NULL || FL_DB_INITIALIZED)
        return ERR_DB_ALREADY_INIT;

    if (master_pin == NULL || fp_key == NULL || master_password == NULL || !master_password_len)
        return ERR_DB_NEW_INV_PARAMS;

    db = calloc(1, sizeof(struct Database));
    if (db == NULL)
        return ERR_DB_MEM_ALLOC;

    db_header = calloc(1, sizeof(struct DatabaseHeader));
    if (db_header == NULL)
        return ERR_DB_MEM_ALLOC;

    db->header = db_header;

    memset(&(db->dek), 0, sizeof(struct DataBlob));
    memset(&(db->header->master_pin_hash), 0, sizeof(struct DataHash));
    memset(&(db->header->encrypted_fp_key), 0, sizeof(struct DataBlob));

    PIPASS_ERR err;
    uint8_t *dek = NULL;  
    uint8_t *kek = NULL;
    uint8_t *passw_key = NULL;

    err = generate_new_master_pin_hash(master_pin, &db->header->master_pin_hash);
    if (err != PIPASS_OK)
        goto error;

    err = generate_KEK(master_pin, db->header->master_pin_hash.salt, fp_key, &kek);
    if (err != PIPASS_OK)
        goto error;

    passw_key = malloc(AES256_KEY_SIZE);
    if (passw_key == NULL) {
        err = ERR_DB_MEM_ALLOC;
        goto error;
    }

    err = create_PBKDF2_key(master_password, master_password_len, NULL, 0, passw_key);
    if (err != PIPASS_OK)
        goto error;

    err = encrypt_data_with_key(fp_key, AES256_KEY_SIZE, passw_key, &db->header->encrypted_fp_key);
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

    db->header->version = PIPASS_VERSION;
    db->header->db_len = sizeof(db->cred_count) + AES256_KEY_SIZE + MAC_SIZE + IV_SIZE; 

    erase_buffer(&dek, AES256_KEY_SIZE);
    erase_buffer(&kek, AES256_KEY_SIZE);

    err = PIPASS_OK;
    goto cleanup;

error:
    db_free();
cleanup:
    erase_buffer(&dek, AES256_KEY_SIZE);
    erase_buffer(&kek, AES256_KEY_SIZE);
    erase_buffer(&passw_key, AES256_KEY_SIZE);

    return err;
}

/* TODO */
PIPASS_ERR db_update_master_pin_hash(struct DataHash *new_master_pin_hash, 
  uint8_t *new_master_pin, uint8_t *old_master_pin) {
//      if (db == NULL || !FL_DB_INITIALIZED)
//         return ERR_DB_NOT_INITIALIZED;

//     if (!FL_LOGGED_IN)
//         return ERR_NOT_LOGGED_IN;

//     if (datahash_has_null_fields(db->header->master_pin_hash))
//         return ERR_DB_MISSING_PASSW_HASH;

//     if (new_master_pin_hash == NULL || datahash_has_null_fields(*new_master_pin_hash) ||
//       new_master_pin == NULL || old_master_pin == NULL)
//         return ERR_DB_UPDATE_LOGIN_INV_PARAMS;

//     PIPASS_ERR err = PIPASS_OK;

//     err = verify_master_pin_with_hash(new_master_pin, *new_master_pin_hash);
//     if (err != PIPASS_OK)
//         return err;

//     err = verify_master_pin_with_db(old_master_pin);
//     if (err != PIPASS_OK)
//         return err;

//     if (db->dek.ciphertext != NULL) {
//         err = reencrypt_DEK(&(db->dek), new_master_pin, new_master_pin_hash->salt, old_master_pin,
//           db->header->master_pin_hash.salt);
//     }  

//     err = datahash_memcpy(&(db->header->master_pin_hash), new_master_pin_hash);
//     if (err != PIPASS_OK)
//         goto error;

//     return DB_OK;

// error:
    
//     // TODO: complete error frees
//     return err;
}

/* TODO */
PIPASS_ERR db_update_DEK(uint8_t *dek, uint8_t *master_pin) {
//     if (db == NULL || !FL_DB_INITIALIZED)
//         return ERR_DB_NOT_INITIALIZED;

//     if (!FL_LOGGED_IN || OTK == NULL)
//         return ERR_NOT_LOGGED_IN;

//     if (dek == NULL || master_pin == NULL)   
//         return ERR_DB_UPDATE_DEK_INV_PARAMS;
    
//     if (datablob_has_null_fields(db->dek))
//         return ERR_DB_MISSING_DEK;
    
//     PIPASS_ERR err;
//     uint8_t *kek = NULL;
//     struct DataBlob dek_blob;

//     err = verify_master_pin_with_db(master_pin);
//     if (err != PIPASS_OK)
//         return err;
    
//     err = generate_KEK(master_pin, db->header->master_pin_hash.salt, &kek);
//     if (err != PIPASS_OK)
//         return err;

//     err = encrypt_DEK_with_KEK(dek, kek, &dek_blob);
//     if (err != PIPASS_OK)
//         goto error;

//     err = datablob_memcpy(&(db->dek), &dek_blob, AES256_KEY_SIZE);
//     if (err != PIPASS_OK)
//         goto error;

//     err = invalidate_OTK();
//     if (err != PIPASS_OK)
//         goto error;

//     err = PIPASS_OK;

// error:
//     erase_buffer(&kek, AES256_KEY_SIZE);
//     free_datablob(&dek_blob, AES256_KEY_SIZE);

//     return err;
}

PIPASS_ERR db_append_credential(struct Credential *cr) {
    if (!FL_LOGGED_IN)
        return ERR_NOT_LOGGED_IN;

    if (!FL_DB_INITIALIZED || db == NULL)
        return ERR_DB_NOT_INITIALIZED;

    if (cr == NULL)
        return ERR_DB_APPEND_CRED_INV_PARAMS;

    PIPASS_ERR err = PIPASS_OK;

    err = append_to_credential_array(&db->cred, &db->cred_count, cr);
    if (err != PIPASS_OK)
        return err;

    db->header->db_len += cr->cred_size;

    return PIPASS_OK;

error:
    return err;
}

PIPASS_ERR db_raw(uint8_t **raw_db, int32_t *raw_db_size) {
    if (!FL_LOGGED_IN)
        return ERR_NOT_LOGGED_IN;

    if (!FL_DB_INITIALIZED || db == NULL)
        return ERR_DB_NOT_INITIALIZED;

    if (*raw_db != NULL)
        return ERR_RAW_DB_MEM_LEAK;

    PIPASS_ERR err;

    int32_t raw_cursor = 0;
    *raw_db = malloc(db->header->db_len);
    if (*raw_db == NULL)
        return ERR_RAW_DB_MEM_ALLOC;

    uint8_t *cred_count_bin = var_to_bin(&db->cred_count, sizeof(db->cred_count));
    if (cred_count_bin == NULL)
        return ERR_RAW_DB_MEM_ALLOC;

    append_to_str(*raw_db, &raw_cursor, cred_count_bin, sizeof(db->cred_count));
    erase_buffer(&cred_count_bin, sizeof(db->cred_count));

    for (int i = 0; i < db->cred_count; ++i) {
        struct Credential *cr = &(db->cred[i]);
        uint8_t *raw_cr = NULL;
        uint32_t raw_cr_len = 0;

        err = credential_raw(cr, &raw_cr, &raw_cr_len);
        if (err != PIPASS_OK)
            goto error;

        append_to_str(*raw_db, &raw_cursor, raw_cr, raw_cr_len);
        erase_buffer(&raw_cr, raw_cr_len);
    }

    append_to_str(*raw_db, &raw_cursor, db->dek.ciphertext, AES256_KEY_SIZE);
    append_to_str(*raw_db, &raw_cursor, db->dek.mac, MAC_SIZE);
    append_to_str(*raw_db, &raw_cursor, db->dek.iv, IV_SIZE);

    *raw_db_size = raw_cursor;
    return PIPASS_OK;

    //TODO: write error for this
error:
    return err;
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

    append_to_str(*raw_db_header, &raw_cursor, db_header->master_pin_hash.hash, SHA256_DGST_SIZE);
    append_to_str(*raw_db_header, &raw_cursor, db_header->master_pin_hash.salt, SALT_SIZE);

    append_to_str(*raw_db_header, &raw_cursor, db_header->encrypted_fp_key.ciphertext, AES256_KEY_SIZE);
    append_to_str(*raw_db_header, &raw_cursor, db_header->encrypted_fp_key.mac, MAC_SIZE);
    append_to_str(*raw_db_header, &raw_cursor, db_header->encrypted_fp_key.iv, IV_SIZE);

    return PIPASS_OK;

error:
    erase_buffer(raw_db_header, DB_HEADER_SIZE);
    erase_buffer(&version_bin, sizeof(db_header->version));
    erase_buffer(&db_len_bin, sizeof(db_header->db_len));

    return err;
}

PIPASS_ERR db_get_master_pin_hash(struct DataHash *master_pin_hash) {
    if (master_pin_hash == NULL || datahash_has_null_fields(*master_pin_hash))
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

    if (datahash_has_null_fields(header->master_pin_hash))
        return ERR_DB_MISSING_PASSW_HASH;
         
    err = datahash_memcpy(master_pin_hash, &(header->master_pin_hash));
    if (err != PIPASS_OK)
        return err;

    return PIPASS_OK;
}

PIPASS_ERR db_get_DEK(struct DataBlob *dek) {
    if (db == NULL || !FL_DB_INITIALIZED)
        return ERR_DB_NOT_INITIALIZED;

    if (dek == NULL)
        return ERR_DB_GET_DEK_INV_PARAMS;

    PIPASS_ERR err;

    err = alloc_datablob(dek, AES256_KEY_SIZE);
    if (err != PIPASS_OK)
        return err;

    err = datablob_memcpy(dek, &(db->dek), AES256_KEY_SIZE);
    if (err != PIPASS_OK)
        goto error;

    return PIPASS_OK;

error:
    free_datablob(dek, AES256_KEY_SIZE);

    return err;
}

PIPASS_ERR db_get_length(uint32_t *db_len) {
    if (db_header == NULL || !FL_DB_HEADER_LOADED)
        return ERR_DB_HEADER_NOT_LOADED;

    *db_len = db_header->db_len;

    return PIPASS_OK;
}

PIPASS_ERR db_get_credentials(struct Credential **cr, uint32_t *cred_count) {
    if (db == NULL || !FL_DB_INITIALIZED)
        return ERR_DB_NOT_INITIALIZED;
        
    *cr = db->cred;
    *cred_count = db->cred_count;

    return PIPASS_OK;
}

PIPASS_ERR db_get_encrypted_fp_key(struct DataBlob *fp_key) {
    if (db_header == NULL || !FL_DB_HEADER_LOADED)
        return ERR_DB_HEADER_NOT_LOADED;
    
    PIPASS_ERR err;

    err = alloc_datablob(fp_key, AES256_KEY_SIZE);
    if (err != PIPASS_OK)
        return err;

    err = datablob_memcpy(fp_key, &db_header->encrypted_fp_key, AES256_KEY_SIZE);
    if (err != PIPASS_OK)
        goto error;

    return PIPASS_OK;

error:
    free_datablob(fp_key, AES256_KEY_SIZE);

    return err;
}

void db_free() {
    if (db == NULL || !FL_DB_INITIALIZED)
        return;

    free_datablob(&db->dek, AES256_KEY_SIZE);
    free_datahash(&db->header->master_pin_hash);

    for (int i = 0; i < db->cred_count; ++i)
        free_credential(&(db->cred[i]));

    free(db->cred);

    db->cred_count = db->header->db_len = db->header->version = 0;

    db_free_header();

    free(db);
    db = NULL;

    FL_DB_INITIALIZED = FL_LOGGED_IN = 0;

    printf("%p\n", db);
}

void db_free_header() {
    if (db_header == NULL)
        return;

    free_datahash(&db_header->master_pin_hash);
    free_datablob(&db_header->encrypted_fp_key, AES256_KEY_SIZE);

    free(db_header);
    db_header = NULL;

    FL_DB_HEADER_LOADED = 0;
}

PIPASS_ERR load_database(uint8_t *raw_db, uint32_t db_len, uint8_t *kek) {
    if (!FL_LOGGED_IN)
        return ERR_NOT_LOGGED_IN;
    
    if (FL_DB_INITIALIZED || db != NULL)
        return ERR_DB_ALREADY_INIT;

    if (!FL_DB_HEADER_LOADED || db_header == NULL)
        return ERR_DB_HEADER_NOT_LOADED;

    if (raw_db == NULL)
        return ERR_LOAD_DB_INV_PARAMS;

    PIPASS_ERR err;
    uint32_t read_cursor = 0;

    db = calloc(1, sizeof(struct Database));
    if (db == NULL) {
        err = ERR_DB_MEM_ALLOC;
        goto error;
    } 

    err = read_db_field_32b_from_raw(raw_db, &read_cursor, db_len, &(db->cred_count));
    if (err != PIPASS_OK)
        goto error;

    if (db->cred_count == 0)
        goto skip_loading_credentials;

    db->cred = calloc(db->cred_count, sizeof(struct Credential));
    if (db->cred == NULL)
        return ERR_DB_MEM_ALLOC;
    
    err = read_credentials_from_raw(raw_db, &read_cursor, db_len, db->cred, db->cred_count);
    if (err != PIPASS_OK)
        goto error;

skip_loading_credentials:
    err = read_datablob_from_raw(raw_db, &read_cursor, db_len, &(db->dek), AES256_KEY_SIZE);
    if (err != PIPASS_OK)
        goto error;

    db->header = db_header;

    return PIPASS_OK;

error:
    erase_buffer(&raw_db, db_len);
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

    db_header->version = *db_version;
    raw_db_header += sizeof(uint16_t);
    
    db_len = (uint32_t *)bin_to_var(raw_db_header, sizeof(uint32_t));
    if (db_len == NULL) {
        err = ERR_DB_MEM_ALLOC;
        goto error;
    }

    db_header->db_len = *db_len;
    raw_db_header += sizeof(uint32_t);

    err = alloc_datahash(&db_header->master_pin_hash);
    if (err != PIPASS_OK)
        goto error;

    err = alloc_datablob(&db_header->encrypted_fp_key, AES256_KEY_SIZE);
    if (err != PIPASS_OK)
        goto error;

    memcpy(db_header->master_pin_hash.hash, raw_db_header, SHA256_DGST_SIZE);
    raw_db_header += SHA256_DGST_SIZE;

    memcpy(db_header->master_pin_hash.salt, raw_db_header, SALT_SIZE);
    raw_db_header += SALT_SIZE;

    memcpy(db_header->encrypted_fp_key.ciphertext, raw_db_header, AES256_KEY_SIZE);
    raw_db_header += AES256_KEY_SIZE;

    memcpy(db_header->encrypted_fp_key.mac, raw_db_header, MAC_SIZE);
    raw_db_header += MAC_SIZE;

    memcpy(db_header->encrypted_fp_key.iv, raw_db_header, IV_SIZE);
    raw_db_header += IV_SIZE;

    err = PIPASS_OK;
    goto cleanup;

error:
    free_datahash(&db_header->master_pin_hash);
    free_datablob(&db_header->encrypted_fp_key, AES256_KEY_SIZE);
    free(db_header);
cleanup:
    if (db_version != NULL)
        free(db_version);
    
    if (db_len != NULL)
        free(db_len);

    return err;
}

void print_bytes(char *p, int size, char *name) {
    printf("%s\n", name);
    for (int i = 0; i < size; ++i) {
        if (i % 16 == 0 && i) {
            printf("\n");
        }
        printf("0x%.2X ", p[i]);
    }
    printf("\n");
}
