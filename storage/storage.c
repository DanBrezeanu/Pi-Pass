#include <storage.h>
#include <database.h>
#include <sha256.h>
#include <credentials.h>

STORAGE_ERR create_user_directory(uint8_t *user_hash) {
    if (user_hash == NULL)
        return ERR_CREATE_USER_DIR_INV_PARAMS;
    
    uint8_t *user_dir = NULL;
    int32_t user_dir_len = 0;
    struct stat st = {0};

    STORAGE_ERR err = user_directory(user_hash, &user_dir, &user_dir_len);
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

STORAGE_ERR verify_user_directory(uint8_t *user_hash) {
    if (user_hash == NULL)
        return ERR_VERIFY_DIR_INV_PARAMS;

    struct stat sb = {0};
    int32_t user_dir_len = 0;
    uint8_t *user_dir = NULL;

    STORAGE_ERR err = user_directory(user_hash, &user_dir, &user_dir_len);
    if (err != STORAGE_OK)
        goto error;

    err = ((stat(user_dir, &sb) == 0 && S_ISDIR(sb.st_mode))
           ? (STORAGE_OK)
           : (ERR_USER_NOT_FOUND));

error:
    erase_buffer(&user_dir, user_dir_len);

    return err;
}

STORAGE_ERR dump_database(struct Database *db, uint8_t *user_hash) {
    if (db == NULL || user_hash == NULL)
        return ERR_DUMP_DB_INV_PARAMS;

    STORAGE_ERR err = verify_user_directory(user_hash);
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

STORAGE_ERR load_database(struct Database **db, uint8_t *user_hash) {
    if (user_hash == NULL)
        return ERR_LOAD_DB_INV_PARAMS;

    if (*db != NULL)
        return ERR_LOAD_DB_MEM_LEAK;

    STORAGE_ERR err = verify_user_directory(user_hash);
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

        if ((*db)->cred_headers[i].name_len > 0) {
            res = read(db_fd, (*db)->cred[i].name, (*db)->cred_headers[i].name_len);
            if (res == -1 || res != (*db)->cred_headers[i].name_len) {
                err = ERR_LOAD_DB_READ_CRED;
                goto error;
            }
        }

        if ((*db)->cred_headers[i].username_len <= 0) {
            err = ERR_LOAD_DB_READ_CRED;
            goto error;
        }

        res = read(db_fd, (*db)->cred[i].username, (*db)->cred_headers[i].username_len);
        if (res == -1 || res != (*db)->cred_headers[i].username_len) {
            err = ERR_LOAD_DB_READ_CRED;
            goto error;
        }

        res = read(db_fd, (*db)->cred[i].username_mac, MAC_SIZE);
        if (res == -1 || res != MAC_SIZE) {
            err = ERR_LOAD_DB_READ_CRED;
            goto error;
        }

        res = read(db_fd, (*db)->cred[i].username_iv, IV_SIZE);
        if (res == -1 || res != IV_SIZE) {
            err = ERR_LOAD_DB_READ_CRED;
            goto error;
        }

        if ((*db)->cred_headers[i].passw_len <= 0) {
            err = ERR_LOAD_DB_READ_CRED;
            goto error;
        }
    
        res = read(db_fd, (*db)->cred[i].passw, (*db)->cred_headers[i].passw_len);
        if (res == -1 || res != (*db)->cred_headers[i].passw_len) {
            err = ERR_LOAD_DB_READ_CRED;
            goto error;
        }

        res = read(db_fd, (*db)->cred[i].passw_mac, MAC_SIZE);
        if (res == -1 || res != MAC_SIZE) {
            err = ERR_LOAD_DB_READ_CRED;
            goto error;
        }

        res = read(db_fd, (*db)->cred[i].passw_iv, IV_SIZE);
        if (res == -1 || res != IV_SIZE) {
            err = ERR_LOAD_DB_READ_CRED;
            goto error;
        }
        
        if ((*db)->cred_headers[i].url_len > 0) {
            res = read(db_fd, (*db)->cred[i].url, (*db)->cred_headers[i].url_len);
            if (res == -1 || res != (*db)->cred_headers[i].url_len) {
                err = ERR_LOAD_DB_READ_CRED;
                goto error;
            }
        }
        
        if ((*db)->cred_headers[i].url_len > 0) {
            res = read(db_fd, (*db)->cred[i].url, (*db)->cred_headers[i].url_len);
            if (res == -1 || res != (*db)->cred_headers[i].url_len) {
                err = ERR_LOAD_DB_READ_CRED;
                goto error;
            }
        }
    }

skip_reading_creds:
    res = read(db_fd, &((*db)->db_len), sizeof((*db)->db_len));
    if (res == -1 || res != sizeof((*db)->db_len)) {
        err = ERR_LOAD_DB_READ_FIELD;
        goto error;
    }

    (*db)->dek_blob = malloc(AES256_KEY_SIZE);
    if ((*db)->dek_blob == NULL) {
        err = ERR_LOAD_DB_MEM_ALLOC;
        goto error;
    }

    res = read(db_fd, (*db)->dek_blob, AES256_KEY_SIZE);
    if (res == -1 || res != AES256_KEY_SIZE) {
        err = ERR_LOAD_DB_READ_CRED;
        goto error;
    }


    (*db)->dek_blob_enc_mac = malloc(MAC_SIZE);
    if ((*db)->dek_blob_enc_mac == NULL) {
        err = ERR_LOAD_DB_MEM_ALLOC;
        goto error;
    }

    res = read(db_fd, (*db)->dek_blob_enc_mac, MAC_SIZE);
    if (res == -1 || res != MAC_SIZE) {
        err = ERR_LOAD_DB_READ_CRED;
        goto error;
    }


    (*db)->dek_blob_enc_iv = malloc(IV_SIZE);
    if ((*db)->dek_blob_enc_iv == NULL) {
        err = ERR_LOAD_DB_MEM_ALLOC;
        goto error;
    }

    res = read(db_fd, (*db)->dek_blob_enc_iv, IV_SIZE);
    if (res == -1 || res != IV_SIZE) {
        err = ERR_LOAD_DB_READ_CRED;
        goto error;
    }


    (*db)->iv_dek_blob = malloc(IV_SIZE);
    if ((*db)->iv_dek_blob == NULL) {
        err = ERR_LOAD_DB_MEM_ALLOC;
        goto error;
    }

    res = read(db_fd, (*db)->iv_dek_blob, IV_SIZE);
    if (res == -1 || res != IV_SIZE) {
        err = ERR_LOAD_DB_READ_CRED;
        goto error;
    }


    (*db)->iv_dek_blob_enc_mac = malloc(MAC_SIZE);
    if ((*db)->iv_dek_blob_enc_mac == NULL) {
        err = ERR_LOAD_DB_MEM_ALLOC;
        goto error;
    }

    res = read(db_fd, (*db)->iv_dek_blob_enc_mac, MAC_SIZE);
    if (res == -1 || res != MAC_SIZE) {
        err = ERR_LOAD_DB_READ_CRED;
        goto error;
    }

    (*db)->iv_dek_blob_enc_iv = malloc(IV_SIZE);
    if ((*db)->iv_dek_blob_enc_iv == NULL) {
        err = ERR_LOAD_DB_MEM_ALLOC;
        goto error;
    }

    res = read(db_fd, (*db)->iv_dek_blob_enc_iv, IV_SIZE);
    if (res == -1 || res != IV_SIZE) {
        err = ERR_LOAD_DB_READ_CRED;
        goto error;
    }

    (*db)->mac_dek_blob = malloc(MAC_SIZE);
    if ((*db)->mac_dek_blob == NULL) {
        err = ERR_LOAD_DB_MEM_ALLOC;
        goto error;
    }

    res = read(db_fd, (*db)->mac_dek_blob, MAC_SIZE);
    if (res == -1 || res != MAC_SIZE) {
        err = ERR_LOAD_DB_READ_CRED;
        goto error;
    }


    (*db)->mac_dek_blob_enc_mac = malloc(MAC_SIZE);
    if ((*db)->mac_dek_blob_enc_mac == NULL) {
        err = ERR_LOAD_DB_MEM_ALLOC;
        goto error;
    }

    res = read(db_fd, (*db)->mac_dek_blob_enc_mac, MAC_SIZE);
    if (res == -1 || res != MAC_SIZE) {
        err = ERR_LOAD_DB_READ_CRED;
        goto error;
    }

    (*db)->mac_dek_blob_enc_iv = malloc(IV_SIZE);
    if ((*db)->mac_dek_blob_enc_iv == NULL) {
        err = ERR_LOAD_DB_MEM_ALLOC;
        goto error;
    }

    res = read(db_fd, (*db)->mac_dek_blob_enc_iv, IV_SIZE);
    if (res == -1 || res != IV_SIZE) {
        err = ERR_LOAD_DB_READ_CRED;
        goto error;
    }

    (*db)->kek_hash = malloc(SHA256_DGST_SIZE);
    if ((*db)->kek_hash == NULL) {
        err = ERR_LOAD_DB_MEM_ALLOC;
        goto error;
    }

    res = read(db_fd, (*db)->kek_hash, SHA256_DGST_SIZE);
    if (res == -1 || res != SHA256_DGST_SIZE) {
        err = ERR_LOAD_DB_READ_CRED;
        goto error;
    }

    (*db)->kek_salt = malloc(SALT_SIZE);
    if ((*db)->kek_salt == NULL) {
        err = ERR_LOAD_DB_MEM_ALLOC;
        goto error;
    }

    res = read(db_fd, (*db)->kek_salt, SALT_SIZE);
    if (res == -1 || res != SALT_SIZE) {
        err = ERR_LOAD_DB_READ_CRED;
        goto error;
    }

    (*db)->login_hash = malloc(SHA256_DGST_SIZE);
    if ((*db)->login_hash == NULL) {
        err = ERR_LOAD_DB_MEM_ALLOC;
        goto error;
    }

    res = read(db_fd, (*db)->login_hash, SHA256_DGST_SIZE);
    if (res == -1 || res != SHA256_DGST_SIZE) {
        err = ERR_LOAD_DB_READ_CRED;
        goto error;
    }

    (*db)->login_salt = malloc(SALT_SIZE);
    if ((*db)->login_salt == NULL) {
        err = ERR_LOAD_DB_MEM_ALLOC;
        goto error;
    }

    res = read(db_fd, (*db)->login_salt, SALT_SIZE);
    if (res == -1 || res != SALT_SIZE) {
        err = ERR_LOAD_DB_READ_CRED;
        goto error;
    }

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
    /* TODO: ERASE ALLOC'D CRED BUFFERS */

    return err;
}

/* TO BE DELETED */

STORAGE_ERR store_file(uint8_t *user_hash, uint8_t *content, int32_t content_len, uint8_t *file_name) {
    if (user_hash == NULL || content == NULL || file_name == NULL)
        return ERR_STORE_FILE_INV_PARAMS;

    STORAGE_ERR err = verify_user_directory(user_hash);
    if (err != STORAGE_OK)
        return err;

    uint8_t *file_path = NULL;
    int32_t file_path_len = 0;
    int32_t file_fd = -1;

    err = user_file_path(user_hash, file_name, &file_path, &file_path_len);
    if (err != STORAGE_OK)
        goto error;

    file_fd = open(file_path, O_WRONLY | O_CREAT, 0400);
    if (file_fd == -1) {
        err = ERR_STORE_OPEN_FILE;
        goto error;
    }

    erase_buffer(&file_path, file_path_len);

    int32_t res = write(file_fd, content, content_len);
    if (res != content_len) {
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

    return err;
}


STORAGE_ERR store_user_DEK_blob(uint8_t *user_hash, uint8_t *DEK_blob, uint8_t *iv, uint8_t *mac) {
    if (DEK_blob == NULL || user_hash == NULL || iv == NULL || mac == NULL)
        return ERR_STORE_DEK_BLOB_INV_PARAMS;

    STORAGE_ERR err = store_file(user_hash, DEK_blob, AES256_KEY_SIZE, DEK_BLOB_FILE);
    if (err != STORAGE_OK)
        return err;
   
    err = store_file(user_hash, iv, IV_SIZE, IV_DEK_BLOB_FILE);
    if (err != STORAGE_OK)
        return err;
   
    err = store_file(user_hash, mac, MAC_SIZE, MAC_DEK_BLOB_FILE);
    if (err != STORAGE_OK)
        return err;
   
    return STORAGE_OK;
}

STORAGE_ERR store_user_login_hash(uint8_t *user_hash, uint8_t *login_hash, uint8_t *login_salt) {
    if (user_hash == NULL || login_hash == NULL || login_salt == NULL)
        return ERR_STORE_HASH_INV_PARAMS;

    STORAGE_ERR err = store_file(user_hash, login_hash, SHA256_DGST_SIZE, LOGIN_HASH_FILE);
    if (err != STORAGE_OK)
        return err;
   
    err = store_file(user_hash, login_salt, SALT_SIZE, LOGIN_SALT_FILE);
    if (err != STORAGE_OK)
        return err;
   
    return STORAGE_OK;
}

STORAGE_ERR store_user_KEK(uint8_t *user_hash, uint8_t *KEK, uint8_t *KEK_salt) {
    if (user_hash == NULL || KEK == NULL || KEK_salt == NULL)
        return ERR_STORE_HASH_INV_PARAMS;

    uint8_t *KEK_hash = NULL;

    KEK_hash = malloc(SHA256_DGST_SIZE);
    if (KEK_hash == NULL)
        return ERR_STORAGE_MEM_ALLOC;

    CRYPTO_ERR err = hash_sha256(KEK, AES256_KEY_SIZE, NULL, 0, KEK_hash);
    if (err != CRYPTO_OK)
        goto error;

    err = store_file(user_hash, KEK_hash, SHA256_DGST_SIZE, KEK_HASH_FILE);
    if (err != STORAGE_OK)
        goto error;
   
    err = store_file(user_hash, KEK_salt, SALT_SIZE, KEK_SALT_FILE);
    if (err != STORAGE_OK)
        goto error;

    err = STORAGE_OK;

error:
    erase_buffer(&KEK_hash, SHA256_DGST_SIZE);

    return err;
}

