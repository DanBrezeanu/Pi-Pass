#ifndef __CRYPTO_UTILS_H__
#define __CRYPTO_UTILS_H__

#include <string.h>
#include <stdint.h>
#include <defines.h>
#include <errors.h>
#include <stdlib.h>

void zero_buffer(uint8_t *buf, int32_t size);
void erase_buffer(uint8_t **buf, int32_t size);
CRYPTO_ERR raw_to_hex(uint8_t *raw, uint32_t raw_len, uint8_t **hex, uint32_t *hex_len);
CRYPTO_ERR sanity_check_buffer(uint8_t *buf, uint8_t buf_len);

#endif
