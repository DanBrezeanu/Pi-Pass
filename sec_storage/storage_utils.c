#include <storage_utils.h>

STORAGE_ERR user_directory(uint8_t *user, uint8_t **user_dir, uint32_t *user_dir_len) {
    if (user == NULL)
        return ERR_NO_USER_PROVIDED;

    if (*user_dir != NULL)
        return ERR_MEM_LEAK;

    const uint32_t PIPASS_USERS_LEN = strlen(PIPASS_USERS);

    *user_dir = malloc(PIPASS_USERS_LEN + SHA256_DGST_SIZE + 1);
    if (*user_dir == NULL)
        return ERR_STORAGE_MEM_ALLOC;

    memmove(*user_dir, PIPASS_USERS, PIPASS_USERS_LEN);
    memmove(*user_dir + PIPASS_USERS_LEN, user, SHA256_DGST_SIZE);

    *user_dir_len = PIPASS_USERS_LEN + SHA256_DGST_SIZE;
    (*user_dir)[*user_dir_len] = 0;

    return STORAGE_OK;
}

STORAGE_ERR user_master_passw_file(uint8_t *user, uint8_t **user_passw, uint32_t *user_passw_len) {
    STORAGE_ERR err;

    err = user_directory(user, user_passw, user_passw_len);
    if (err != STORAGE_OK)
        return err;

    const int MASTER_PASSW_LEN = strlen(MASTER_PASSW);

    memmove(*user_passw + *user_passw_len, MASTER_PASSW, MASTER_PASSW_LEN);

    *user_passw_len += MASTER_PASSW_LEN;
    (*user_passw)[*user_passw_len] = 0;

    return STORAGE_OK;
}

STORAGE_ERR user_master_salt_file(uint8_t *user, uint8_t **user_salt, uint32_t *user_salt_len) {
    STORAGE_ERR err;

    err = user_directory(user, user_salt, user_salt_len);
    if (err != STORAGE_OK)
        return err;

    const int MASTER_SALT_LEN = strlen(MASTER_SALT);

    memmove(*user_salt + *user_salt_len, MASTER_SALT, MASTER_SALT_LEN);

    *user_salt_len += MASTER_SALT_LEN;
    (*user_salt)[*user_salt_len] = 0;

    return STORAGE_OK;
}