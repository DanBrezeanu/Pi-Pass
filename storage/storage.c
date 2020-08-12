#include <storage.h>
#include <database.h>
#include <sha256.h>

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

