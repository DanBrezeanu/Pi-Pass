#ifndef __CRYPTO_UTILS_H__
#define __CRYPTO_UTILS_H__

#include <string.h>
#include <stdint.h>
#include <defines.h>
#include <errors.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

void zero_buffer(uint8_t *buf, int32_t size);
void erase_buffer(uint8_t **buf, int32_t size);
PIPASS_ERR raw_to_hex(uint8_t *raw, uint32_t raw_len, uint8_t **hex, uint32_t *hex_len);
PIPASS_ERR sanity_check_buffer(uint8_t *buf, uint8_t buf_len);
PIPASS_ERR cpu_id(uint8_t **hw_id);
PIPASS_ERR concat_passw_pepper(uint8_t *passw, uint8_t **passw_pepper);

#endif
