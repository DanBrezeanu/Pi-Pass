
#include <sys/stat.h>
#include <storage_utils.h>


STORAGE_ERR verify_user(uint8_t *user) {
    struct stat sb;

    return ((stat(PIPASS_DIR "users/") == 0 && S_ISDIR(sb.st_mode))
           ? (STORAGE_OK)
           : (ERR_USER_NOT_FOUND));
}

STORAGE_ERR verify_master_password(uint8_t *user, uint8_t *key) {
    STORAGE_ERR err;

    err = verify_user(user);
    if (err != STORAGE_OK) {
        goto error;
    }

    uint8_t *user_passw = NULL;
    uint32_t user_passw_len = 0;

    err = user_master_passw_file(user, &user_passw, &user_passw_len);
    if (err != STORAGE_OK) {
        if (user_passw != NULL)
            free(user_passw);

        goto error;
    }

    int32_t passw_fd = open(user_passw, O_RDONLY);
    if (passw_fd == -1) {
        if (user_passw != NULL)
            free(user_passw);
     
        err = ERR_OPEN_PASSW_FILE;
        goto error;
    }

    free(user_passw);

    uint8_t *user_salt = NULL;
    uint32_t user_salt_len = 0;

    err = user_master_salt_file(user, &user_salt, &user_salt_len);
    if (err != STORAGE_OK) {
        if (user_salt != NULL)
            free(user_salt);

        goto error;
    }

    int32_t salt_fd = open(user_salt, O_RDONLY);
    if (salt_fd == -1) {
        if (user_salt != NULL)
            free(user_salt);
     
        err = ERR_OPEN_SALT_FILE;
        goto error;
    }
    
    free(user_salt);
    
    uint8_t *salt = malloc(SALT_SIZE);
    if (salt == NULL) {
        err = ERR_STORAGE_MEM_ALLOC;
        goto error;
    }

    int32_t res = read(salt_fd, salt, SALT_SIZE);
    if (res != SALT_SIZE) {
        zero_buffer(salt, SALT_SIZE);
        free(salt);
        err = ERR_READ_SALT_FILE;
        goto error;
    }

    close(salt_fd);

    err = verify_sha256(key, MASTER_PASS_SIZE, salt, SALT_SIZE, passw_fd);
    if (err != CRYPTO_OK) {
        close(passw_fd);
        zero_buffer(salt, SALT_SIZE);
        free(salt);

        goto error;
    }

error:
    zero_buffer(key);
    return err;
}