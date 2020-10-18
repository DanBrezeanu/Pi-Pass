#include <storage_utils.h>
#include <crypto.h>

PIPASS_ERR user_directory(uint8_t *user, uint8_t **user_dir, uint32_t *user_dir_len) {
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

PIPASS_ERR user_file_path(uint8_t *user, uint8_t *file, uint8_t **user_file_path, uint32_t *user_file_path_len) {
    if (user == NULL)
        return ERR_NO_USER_PROVIDED;

    if (file == NULL)
        return ERR_NO_FILE_PROVIDED;

    if (*user_file_path != NULL)
        return ERR_MEM_LEAK;
    
    PIPASS_ERR err;
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

uint8_t *var_to_bin(void *value, size_t size) {
    uint8_t *bin = malloc(size);
    if (bin == NULL)
        return NULL;

    for (int i = 0; i < size; ++i) {
        bin[i] = *((uint8_t *)value + i);
    }

    return bin;
}

void append_to_str(uint8_t *str, int32_t *cursor, uint8_t *substr, int32_t substr_len) {
    if (substr != NULL) {
        memcpy(str + *cursor, substr, substr_len);
        *cursor += substr_len;
    } 
}

PIPASS_ERR alloc_and_read_field(int32_t fd, uint8_t **field, int16_t field_len) {
    if (fd == -1 || fcntl(fd, F_GETFL) == -1 || !field_len)
        return ERR_ALLOC_RD_CRED_INV_PARAMS;

    if (*field != NULL)
        return ERR_ALLOC_RD_CRED_MEM_LEAK;

    PIPASS_ERR err = STORAGE_OK;

    *field = malloc(field_len);
    if (*field == NULL) {
        err = ERR_LOAD_DB_MEM_ALLOC;
        goto error;
    }

    int32_t res = read(fd, *field, field_len);
    if (res == -1 || res != field_len) {
        err = ERR_LOAD_DB_READ_CRED;
        goto error;
    }

    return STORAGE_OK;

error:
    erase_buffer(field, field_len);

    return err;
} 

PIPASS_ERR alloc_and_read_datablob(int32_t fd, struct DataBlob *blob, int16_t ciphertext_len) {
    if (fd == -1 || fcntl(fd, F_GETFL) == -1 || !ciphertext_len || blob == NULL)
        return ERR_ALLOC_RD_CRED_INV_PARAMS;

    PIPASS_ERR err = STORAGE_OK;

    err = alloc_datablob(blob, ciphertext_len);
    if (err != PIPASS_OK)
        return err;

    int32_t res = read(fd, blob->ciphertext, ciphertext_len);
    if (res == -1 || res != ciphertext_len) {
        err = ERR_LOAD_DB_READ_CRED;
        goto error;
    }

    res = read(fd, blob->iv, IV_SIZE);
    if (res == -1 || res != IV_SIZE) {
        err = ERR_LOAD_DB_READ_CRED;
        goto error;
    }

    res = read(fd, blob->mac, MAC_SIZE);
    if (res == -1 || res != MAC_SIZE) {
        err = ERR_LOAD_DB_READ_CRED;
        goto error;
    }

    return STORAGE_OK;

error:
    erase_buffer(&blob->ciphertext, ciphertext_len);
    erase_buffer(&blob->iv, IV_SIZE);
    erase_buffer(&blob->mac, MAC_SIZE);

    return err;
}

PIPASS_ERR alloc_and_read_datahash(int32_t fd, struct DataHash *hash) {
    if (fd == -1 || fcntl(fd, F_GETFL) == -1 || hash == NULL)
        return ERR_ALLOC_RD_CRED_INV_PARAMS;

    PIPASS_ERR err = STORAGE_OK;

    err = alloc_datahash(hash);
    if (err != STORAGE_OK)
        goto error;

    int32_t res = read(fd, hash->hash, SHA256_DGST_SIZE);
    if (res == -1 || res != SHA256_DGST_SIZE) {
        err = ERR_LOAD_DB_READ_CRED;
        goto error;
    }

    int32_t res = read(fd, hash->salt, SALT_SIZE);
    if (res == -1 || res != SALT_SIZE) {
        err = ERR_LOAD_DB_READ_CRED;
        goto error;
    }

    return STORAGE_OK;

error:
    return err;
} 