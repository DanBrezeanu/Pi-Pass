#ifndef __DATABLOB_H__
#define __DATABLOB_H__

#include <errors.h>
#include <defines.h>

struct DataBlob {
    uint8_t *ciphertext;
    uint8_t *mac;
    uint8_t *iv;
} __attribute__((packed, aligned(1)));

PIPASS_ERR alloc_datablob(struct DataBlob *blob, int16_t ciphertext_len);
uint8_t datablob_has_null_fields(struct DataBlob blob);
PIPASS_ERR datablob_memcpy(struct DataBlob *dest, struct DataBlob *src, int16_t ciphertext_len);
void free_datablob(struct DataBlob *blob, uint32_t ciphertext_len);

#endif