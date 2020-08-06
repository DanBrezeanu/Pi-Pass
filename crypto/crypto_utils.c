#include <crypto_utils.h>

void zero_buffer(uint8_t *buf, int32_t size) {
    memset(buf, 0, size);
}