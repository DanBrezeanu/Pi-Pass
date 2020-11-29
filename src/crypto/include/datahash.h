#ifndef __DATA_HASH_H__
#define __DATA_HASH_H__

#include <errors.h>
#include <defines.h>

struct DataHash {
    uint8_t *hash;
    uint8_t *salt;
} __attribute__((packed, aligned(1)));

PIPASS_ERR alloc_datahash(struct DataHash *hash);
PIPASS_ERR datahash_memcpy(struct DataHash *dest, struct DataHash *src);
uint8_t datahash_has_null_fields(struct DataHash hash);
void free_datahash(struct DataHash *hash);

#endif