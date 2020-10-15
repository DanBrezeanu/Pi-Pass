#include <storage.h>
#include <database.h>
#include <sha256.h>
#include <credentials.h>

PIPASS_ERR read_credentials(int32_t db_fd, struct Credential *cr, struct CredentialHeader *crh) {
    if (cr == NULL || crh == NULL)
        return ERR_STORG_READ_CRED_INV_PARAMS;

    PIPASS_ERR err = STORAGE_OK;

    if (crh->name_len > 0) {
        err = alloc_and_read_field(db_fd, &(cr->name), crh->name_len);
        if (err != STORAGE_OK)
            goto error;
    }

    if (crh->username_len <= 0) {
        err = ERR_LOAD_DB_READ_CRED;
        goto error;
    }

    err = alloc_and_read_field(db_fd, &(cr->username), crh->username_len);
    if (err != STORAGE_OK)
        goto error;


    err = alloc_and_read_field(db_fd, &(cr->username_mac), MAC_SIZE);
    if (err != STORAGE_OK)
        goto error;


    err = alloc_and_read_field(db_fd, &(cr->username_iv), IV_SIZE);
    if (err != STORAGE_OK)
        goto error;


    if (crh->passw_len <= 0) {
        err = ERR_LOAD_DB_READ_CRED;
        goto error;
    }

    err = alloc_and_read_field(db_fd, &(cr->passw), crh->passw_len);
    if (err != STORAGE_OK)
        goto error;

    err = alloc_and_read_field(db_fd, &(cr->passw_mac), MAC_SIZE);
    if (err != STORAGE_OK)
        goto error;


    err = alloc_and_read_field(db_fd, &(cr->passw_iv), IV_SIZE);
    if (err != STORAGE_OK)
        goto error;

    
    if (crh->url_len > 0) {
        err = alloc_and_read_field(db_fd, &(cr->url), crh->url_len);
        if (err != STORAGE_OK)
            goto error;
    }
    
    if (crh->additional_len > 0) {
            err = alloc_and_read_field(db_fd, &(cr->additional), crh->additional_len);
        if (err != STORAGE_OK)
            goto error;
    }

    return STORAGE_OK;

error:
    erase_buffer(&(cr->name), crh->name_len);
    erase_buffer(&(cr->username), crh->username_len);
    erase_buffer(&(cr->username_mac), MAC_SIZE);
    erase_buffer(&(cr->username_iv), IV_SIZE);
    erase_buffer(&(cr->passw), crh->passw_len);
    erase_buffer(&(cr->passw_mac), MAC_SIZE);
    erase_buffer(&(cr->passw_iv), IV_SIZE);
    erase_buffer(&(cr->url), crh->url_len);
    erase_buffer(&(cr->additional), crh->additional_len);

    return err;
}

PIPASS_ERR read_db_buffers(int32_t db_fd, struct Database *db) {
    PIPASS_ERR err = STORAGE_OK;

    err = alloc_and_read_field(db_fd, &(db->dek_blob), AES256_KEY_SIZE);
    if (err != STORAGE_OK)
        goto error;

    err = alloc_and_read_field(db_fd, &(db->dek_blob_enc_mac), MAC_SIZE);
    if (err != STORAGE_OK)
        goto error;

    err = alloc_and_read_field(db_fd, &(db->dek_blob_enc_iv), IV_SIZE);
    if (err != STORAGE_OK)
        goto error;

    err = alloc_and_read_field(db_fd, &(db->iv_dek_blob), IV_SIZE);
    if (err != STORAGE_OK)
        goto error;

    err = alloc_and_read_field(db_fd, &(db->iv_dek_blob_enc_mac), MAC_SIZE);
    if (err != STORAGE_OK)
        goto error;
        
    err = alloc_and_read_field(db_fd, &(db->iv_dek_blob_enc_iv), IV_SIZE);
    if (err != STORAGE_OK)
        goto error;
        
    err = alloc_and_read_field(db_fd, &(db->mac_dek_blob), MAC_SIZE);
    if (err != STORAGE_OK)
        goto error;
        
    err = alloc_and_read_field(db_fd, &(db->mac_dek_blob_enc_mac), MAC_SIZE);
    if (err != STORAGE_OK)
        goto error;
        
    err = alloc_and_read_field(db_fd, &(db->mac_dek_blob_enc_iv), IV_SIZE);
    if (err != STORAGE_OK)
        goto error;
        
    err = alloc_and_read_field(db_fd, &(db->kek_hash), SHA256_DGST_SIZE);
    if (err != STORAGE_OK)
        goto error;
        
    err = alloc_and_read_field(db_fd, &(db->kek_salt), SALT_SIZE);
    if (err != STORAGE_OK)
        goto error;
        
    err = alloc_and_read_field(db_fd, &(db->login_hash), SHA256_DGST_SIZE);
    if (err != STORAGE_OK)
        goto error;
        
    err = alloc_and_read_field(db_fd, &(db->login_salt), SALT_SIZE);
    if (err != STORAGE_OK)
        goto error;

    return STORAGE_OK;

error:
    erase_buffer(&(db->dek_blob), AES256_KEY_SIZE);
    erase_buffer(&(db->dek_blob_enc_mac), MAC_SIZE);
    erase_buffer(&(db->dek_blob_enc_iv), IV_SIZE);
    erase_buffer(&(db->iv_dek_blob), IV_SIZE);
    erase_buffer(&(db->iv_dek_blob_enc_mac), MAC_SIZE);
    erase_buffer(&(db->iv_dek_blob_enc_iv), IV_SIZE);
    erase_buffer(&(db->mac_dek_blob), MAC_SIZE);
    erase_buffer(&(db->mac_dek_blob_enc_mac), MAC_SIZE);
    erase_buffer(&(db->mac_dek_blob_enc_iv), IV_SIZE);
    erase_buffer(&(db->kek_hash), SHA256_DGST_SIZE);
    erase_buffer(&(db->kek_salt), SALT_SIZE);
    erase_buffer(&(db->login_hash), SHA256_DGST_SIZE);
    erase_buffer(&(db->login_salt), SALT_SIZE);

    return err;
}

PIPASS_ERR create_user_directory(uint8_t *user_hash) {
    if (user_hash == NULL)
        return ERR_CREATE_USER_DIR_INV_PARAMS;
    
    uint8_t *user_dir = NULL;
    int32_t user_dir_len = 0;
    struct stat st = {0};

    PIPASS_ERR err = user_directory(user_hash, &user_dir, &user_dir_len);
    if (err != STORAGE_OK)
        goto error;

    if (stat(user_dir, &st) != -1) {
        err = ERR_USER_DIR_ALREADY_EXISTS;
        goto error;
    }

    int32_t res = mkdir(user_dir, 0700);
    if (res == -1) {
        err = ERR_MKDIR_FAIL;
        goto error;
    }

    err = STORAGE_OK;

error:
    erase_buffer(&user_dir, user_dir_len);

    return err;
}

PIPASS_ERR verify_user_directory(uint8_t *user_hash) {
    if (user_hash == NULL)
        return ERR_VERIFY_DIR_INV_PARAMS;

    struct stat sb = {0};
    int32_t user_dir_len = 0;
    uint8_t *user_dir = NULL;

    PIPASS_ERR err = user_directory(user_hash, &user_dir, &user_dir_len);
    if (err != STORAGE_OK)
        goto error;

    err = ((stat(user_dir, &sb) == 0 && S_ISDIR(sb.st_mode))
           ? (STORAGE_OK)
           : (ERR_USER_NOT_FOUND));

error:
    erase_buffer(&user_dir, user_dir_len);

    return err;
}

PIPASS_ERR dump_database(struct Database *db, uint8_t *user_hash) {
    if (db == NULL || user_hash == NULL)
        return ERR_DUMP_DB_INV_PARAMS;

    PIPASS_ERR err = verify_user_directory(user_hash);
    if (err != STORAGE_OK)
        return err;

    uint8_t *file_path = NULL;
    int32_t file_path_len = 0;
    int32_t file_fd = -1;
    uint8_t *raw_db = NULL;
    uint32_t raw_db_size = 0;

    err = user_file_path(user_hash, PIPASS_DB, &file_path, &file_path_len);
    if (err != STORAGE_OK)
        goto error;

    file_fd = open(file_path, O_WRONLY | O_CREAT, 0400);
    if (file_fd == -1) {
        err = ERR_STORE_OPEN_FILE;
        goto error;
    }

    erase_buffer(&file_path, file_path_len);

    err = raw_database(db, &raw_db, &raw_db_size);
    if (err != DB_OK)
        goto error;

    int32_t res = write(file_fd, raw_db, raw_db_size);
    if (res != raw_db_size) {
        err = ERR_STORE_WRITE_FILE;
        goto error;
    }

    err = STORAGE_OK;

error:
    if (file_fd != -1) {
        close(file_fd);
        file_fd = -1;
    }

    erase_buffer(&file_path, file_path_len);
    erase_buffer(&raw_db, raw_db_size);

    return err;
}

PIPASS_ERR load_database(struct Database **db, uint8_t *user_hash) {
    if (user_hash == NULL)
        return ERR_LOAD_DB_INV_PARAMS;

    if (*db != NULL)
        return ERR_LOAD_DB_MEM_LEAK;

    PIPASS_ERR err = verify_user_directory(user_hash);
    if (err != STORAGE_OK)
        return err;

    uint8_t *db_file_path = NULL;
    int32_t db_file_path_len = 0;
    int32_t db_fd = -1;

    err = user_file_path(user_hash, PIPASS_DB, &db_file_path, &db_file_path_len);
    if (err != STORAGE_OK)
        goto error;


    *db = calloc(1, sizeof(struct Database));

    db_fd = open(db_file_path, O_RDONLY);
    if (db_fd == -1) {
        err = ERR_LOAD_DB_OPEN_FILE;
        goto error;
    }

    erase_buffer(&db_file_path, db_file_path_len);

    int32_t res = read(db_fd, &((*db)->version), sizeof((*db)->version));
    if (res == -1 || res != sizeof((*db)->version)) {
        err = ERR_LOAD_DB_READ_FIELD;
        goto error;
    }

    res = read(db_fd, &((*db)->cred_len), sizeof((*db)->cred_len));
    if (res == -1 || res != sizeof((*db)->cred_len)) {
        err = ERR_LOAD_DB_READ_FIELD;
        goto error;
    }

    if ((*db)->cred_len == 0)
        goto skip_reading_creds;

    (*db)->cred = calloc((*db)->cred_len, sizeof(struct Credential) );
    if ((*db)->cred == NULL) {
        err = ERR_LOAD_DB_MEM_ALLOC;
        goto error;
    }

    (*db)->cred_headers = calloc((*db)->cred_len, sizeof(struct CredentialHeader));
    if ((*db)->cred_headers == NULL) {
        err = ERR_LOAD_DB_MEM_ALLOC;
        goto error;
    }

    for (int i = 0; i < (*db)->cred_len; ++i) {
        res = read(db_fd, &((*db)->cred_headers[i]), sizeof(struct CredentialHeader));
        if (res == -1 || res != sizeof(struct CredentialHeader)) {
            err = ERR_LOAD_DB_READ_CRED;
            goto error;
        }

        err = read_credentials(db_fd, &((*db)->cred[i]), &((*db)->cred_headers[i]));
        if (err != STORAGE_OK)
            goto error;
    }

skip_reading_creds:
    res = read(db_fd, &((*db)->db_len), sizeof((*db)->db_len));
    if (res == -1 || res != sizeof((*db)->db_len)) {
        err = ERR_LOAD_DB_READ_FIELD;
        goto error;
    }

    err = read_db_buffers(db_fd, *db);
    if (err != STORAGE_OK)
        goto error;

    if (db_fd != -1) {
        close(db_fd);
        db_fd = -1;
    }

    return STORAGE_OK;

error:
    if (*db != NULL) {
        memset(*db, 0, sizeof(struct Database));
        free(*db);
        *db = NULL;
    }

    if (db_fd != -1) {
        close(db_fd);
        db_fd = -1;
    }

    erase_buffer(&db_file_path, db_file_path_len);

    return err;
}

