#include <storage.h>
#include <database.h>
#include <sha256.h>
#include <credentials.h>

PIPASS_ERR create_user_directory(uint8_t *user_hash) {
    if (FL_LOGGED_IN)
        return ERR_ALREADY_LOGGED_IN;

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

PIPASS_ERR dump_database(uint8_t *user_hash) {
    if (!FL_LOGGED_IN)
        return ERR_NOT_LOGGED_IN;

    if (!FL_DB_INITIALIZED)
        return ERR_DB_NOT_INITIALIZED;

    if (user_hash == NULL)
        return ERR_DUMP_DB_INV_PARAMS;

    PIPASS_ERR err = verify_user_directory(user_hash);
    if (err != PIPASS_OK)
        return err;


    uint8_t *file_path = NULL;
    int32_t file_path_len = 0;
    int32_t db_fd = -1;
    uint8_t *raw_db = NULL;
    uint8_t *raw_db_header = NULL;
    uint32_t raw_db_size = 0;

    err = user_file_path(user_hash, PIPASS_DB, &file_path, &file_path_len);
    if (err != STORAGE_OK)
        goto error;

    db_fd = open(file_path, O_WRONLY | O_CREAT, 0400);
    if (db_fd == -1) {
        err = ERR_STORE_OPEN_FILE;
        goto error;
    }

    erase_buffer(&file_path, file_path_len);

    err = db_header_raw(&raw_db_header);
    if (err != PIPASS_OK)
        goto error;

    err = db_raw(&raw_db, &raw_db_size);
    if (err != PIPASS_OK)
        goto error;

    int32_t res = write(db_fd, raw_db_header, DB_HEADER_SIZE);
    if (res != DB_HEADER_SIZE) {
        err = ERR_STORE_WRITE_FILE;
        goto error;
    }

    res = write(db_fd, raw_db, raw_db_size);
    if (res != raw_db_size) {
        err = ERR_STORE_WRITE_FILE;
        goto error;
    }

    // TODO: write in a separate file and replace it after write is completed
    err = PIPASS_OK;

error:
    if (db_fd != -1) {
        close(db_fd);
        db_fd = -1;
    }

    erase_buffer(&file_path, file_path_len);
    erase_buffer(&raw_db, raw_db_size);

    return err;
}

PIPASS_ERR read_database(uint8_t *user_hash, uint8_t **raw_db, uint32_t *raw_db_len) {

    if (!FL_LOGGED_IN)
        return ERR_NOT_LOGGED_IN;

    if (FL_DB_INITIALIZED)
        return ERR_DB_ALREADY_INIT;

    if (!FL_DB_HEADER_LOADED)
        return ERR_DB_HEADER_NOT_LOADED;

    if (user_hash == NULL || raw_db == NULL)
        return ERR_LOAD_DB_INV_PARAMS;

    if (*raw_db != NULL)
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

    db_fd = open(db_file_path, O_RDONLY);
    if (db_fd == -1) {
        err = ERR_LOAD_DB_OPEN_FILE;
        goto error;
    }

    erase_buffer(&db_file_path, db_file_path_len);

    int32_t ret = lseek(db_fd, DB_HEADER_SIZE, SEEK_SET);
    if (ret == -1)
        return ERR_LOAD_DB_OPEN_FILE;

    uint32_t db_len = 0;
    err = db_get_length(&db_len);
    if (err != PIPASS_OK)
        goto error;

    *raw_db = calloc(db_len, sizeof(uint8_t));
    if (*raw_db == NULL) {
        err = ERR_STORAGE_MEM_ALLOC;
        goto error;
    }

    int32_t res = read(db_fd, *raw_db, db_len);
    if (res == -1 || res != db_len) {
        err = ERR_LOAD_DB_READ;
        goto error;
    }

    *raw_db_len = db_len; 

    return PIPASS_OK;

error:
    if (db_fd != -1)
        close(db_fd);
    
    erase_buffer(&db_file_path, db_file_path_len);
    erase_buffer(raw_db, db_len);

    return err;
}

PIPASS_ERR read_database_header(uint8_t *user_hash, uint8_t **raw_db_header) {
    if (FL_LOGGED_IN)
        return ERR_ALREADY_LOGGED_IN;

    if (FL_DB_INITIALIZED)
        return ERR_DB_ALREADY_INIT;

    if (*raw_db_header != NULL)
        return ERR_DB_MEM_LEAK;

    PIPASS_ERR err;

    err = verify_user_directory(user_hash);
    if (err != PIPASS_OK)
        return err;

    uint8_t *db_file_path = NULL;
    uint32_t db_file_path_len = 0;
    int32_t db_fd = -1;
    
    err = user_file_path(user_hash, PIPASS_DB, &db_file_path, &db_file_path_len);
    if (err != PIPASS_OK)
        goto error;

    db_fd = open(db_file_path, O_RDONLY);
    if (db_fd == -1) {
        err = ERR_LOAD_DB_OPEN_FILE;
        goto error;
    }

    erase_buffer(&db_file_path, db_file_path_len);

    *raw_db_header = malloc(DB_HEADER_SIZE);
    if (*raw_db_header == NULL)
        return ERR_DB_MEM_ALLOC;

    int32_t res = read(db_fd, *raw_db_header, DB_HEADER_SIZE);
    if (res == -1 || res != DB_HEADER_SIZE) {
        err = ERR_LOAD_DB_READ_FIELD;
        goto error;
    }

    return PIPASS_OK;

error:
    erase_buffer(&db_file_path, db_file_path_len);
    erase_buffer(raw_db_header, DB_HEADER_SIZE);
    if (db_fd != -1)
        close(db_fd);

    return err;
}