#include <storage_utils.h>
#include <authentication.h>

STORAGE_ERR verify_master_password(uint8_t *user, uint8_t *key) {
    STORAGE_ERR err;

    uint8_t *user_passw_file = NULL;
    uint8_t *user_salt_file = NULL;

    uint32_t user_passw_file_len = 0;
    uint32_t user_salt_file_len = 0;

    int32_t passw_fd = -1;
    int32_t salt_fd = -1;

    uint8_t *salt = malloc(SALT_SIZE);

    err = verify_user_directory(user);
    if (err != STORAGE_OK) {
        goto error;
    }

    err = user_file_path(user, MASTER_PASSW, &user_passw_file, &user_passw_file_len);
    if (err != STORAGE_OK) {
        goto error;
    }

    passw_fd = open(user_passw_file, O_RDONLY);
    if (passw_fd == -1) {
        err = ERR_OPEN_PASSW_FILE;
        goto error;
    }

    erase_buffer(&user_passw_file, user_passw_file_len);

    err = user_login_salt_file(user, &user_salt_file, &user_salt_file_len);
    if (err != STORAGE_OK) {
        goto error;
    }

    salt_fd = open(user_salt_file, O_RDONLY);
    if (salt_fd == -1) {     
        err = ERR_OPEN_SALT_FILE;
        goto error;
    }
    
    erase_buffer(&user_salt_file, user_salt_file_len);
    
    if (salt == NULL) {
        err = ERR_STORAGE_MEM_ALLOC;
        goto error;
    }

    int32_t res = read(salt_fd, salt, SALT_SIZE);
    if (res != SALT_SIZE) {
        err = ERR_READ_SALT_FILE;
        goto error;
    }

    close(salt_fd);
    salt_fd = -1;

    err = verify_sha256(key, MASTER_PASS_SIZE, salt, SALT_SIZE, passw_fd);
    if (err != CRYPTO_OK) {
        goto error;
    }

    err = STORAGE_OK;

error:
    erase_buffer(&key, MASTER_PASS_SIZE);
    erase_buffer(&user_passw_file, user_passw_file_len);
    erase_buffer(&user_salt_file, user_salt_file_len);
    erase_buffer(&salt, SALT_SIZE);

    if (salt_fd != -1)
        close(salt_fd);
    
    if (passw_fd != -1)
        close(passw_fd);

    return err;
} 

// #include <stdio.h>

// int main() {
//     uint8_t *user = malloc(SHA256_HEX_SIZE);
//     uint8_t *key = malloc(MASTER_PASS_SIZE);

//     memcpy(user, "55402817f85b8423f989bc5ed92476a4b4967c302201e9540e9bb55579f00e4b", SHA256_HEX_SIZE);
//     memcpy(key, "1234", MASTER_PASS_SIZE);

//     STORAGE_ERR err = verify_master_password(user, key);

//     printf("0x%.4X\n", err);

//     return 0;
// }