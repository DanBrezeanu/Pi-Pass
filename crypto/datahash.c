#include <datahash.h>

PIPASS_ERR alloc_datahash(struct DataHash *hash) {
    if (hash == NULL)
        return ERR_ALLOC_DATAHASH_INV_PARAMS;
    
    hash->hash = malloc(SHA256_DGST_SIZE);
    hash->salt = malloc(SALT_SIZE);

    if (hash->hash == NULL || hash->salt == NULL) {
        free(hash->hash);
        free(hash->salt);

        return ERR_ALLOC_DATAHASH_MEM_ALLOC;
    }

    return PIPASS_OK;
}

PIPASS_ERR datahash_memcpy(struct DataHash *dest, struct DataHash *src) {
    if (dest == NULL || src == NULL || datahash_has_null_fields(*dest) || datahash_has_null_fields(*src))
        return ERR_DATAHASH_MEMCPY_INV_PARAMS;
    
    memcpy(dest->hash, src->hash, SHA256_DGST_SIZE);
    memcpy(dest->salt, src->salt, SALT_SIZE);

    return PIPASS_OK;
}

uint8_t datahash_has_null_fields(struct DataHash hash) {
    return (hash.hash == NULL || hash.salt == NULL);
}

void free_datahash(struct DataHash *hash) {
    if (hash == NULL)
        return;

    erase_buffer(&(hash->hash), SHA256_DGST_SIZE);
    erase_buffer(&(hash->salt), SALT_SIZE);
}