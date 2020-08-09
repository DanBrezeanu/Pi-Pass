#include <storage_utils.h>

STORAGE_ERR user_directory(uint8_t *user, uint8_t **user_dir, uint32_t *user_dir_len) {
    if (user == NULL)
        return ERR_NO_USER_PROVIDED;

    if (*user_dir != NULL)
        return ERR_MEM_LEAK;

    const uint32_t PIPASS_USERS_LEN = strlen(PIPASS_USERS);

    *user_dir = malloc(PIPASS_USERS_LEN + SHA256_HEX_SIZE + 2);
    if (*user_dir == NULL)
        return ERR_STORAGE_MEM_ALLOC;

    memmove(*user_dir, PIPASS_USERS, PIPASS_USERS_LEN);
    memmove(*user_dir + PIPASS_USERS_LEN, user, SHA256_HEX_SIZE);

    *user_dir_len = PIPASS_USERS_LEN + SHA256_HEX_SIZE + 1;
    (*user_dir)[*user_dir_len - 1] = '/';
    (*user_dir)[*user_dir_len] = 0;

    return STORAGE_OK;
}

STORAGE_ERR user_file_path(uint8_t *user, uint8_t *file, uint8_t **user_file_path, uint32_t *user_file_path_len) {
    if (user == NULL)
        return ERR_NO_USER_PROVIDED;

    if (file == NULL)
        return ERR_NO_FILE_PROVIDED;

    if (*user_file_path != NULL)
        return ERR_MEM_LEAK;
    
    STORAGE_ERR err;
    err = user_directory(user, user_file_path, user_file_path_len);
    if (err != STORAGE_OK)
        return err;

    const int32_t FILE_LEN = strlen(file);

    uint8_t *_tmp = realloc(*user_file_path, *user_file_path_len + FILE_LEN + 1);
    if (_tmp == NULL)
        return ERR_STORAGE_MEM_ALLOC;

    *user_file_path = _tmp;

    memmove(*user_file_path + *user_file_path_len, file, FILE_LEN);

    *user_file_path_len += FILE_LEN;
    (*user_file_path)[*user_file_path_len] = 0;

    return STORAGE_OK;
}