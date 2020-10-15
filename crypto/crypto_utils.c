#include <crypto_utils.h>

void zero_buffer(uint8_t *buf, int32_t size) {
    memset(buf, 0, size);
}

void erase_buffer(uint8_t **buf, int32_t size) {
    if (*buf != NULL) {
        zero_buffer(*buf, size);
        free(*buf);
        *buf = NULL;
    }
}

PIPASS_ERR raw_to_hex(uint8_t *raw, uint32_t raw_len, uint8_t **hex, uint32_t *hex_len) {
    uint8_t hx[]= "0123456789abcdef";

    if (raw == NULL || raw_len == 0)
        return ERR_RAW2HEX_INV_PARAMS;

    if (*hex != NULL)
        return ERR_MEM_LEAK;

    *hex = malloc(raw_len * 2 + 1);
    if (*hex == NULL)
        return ERR_CRYPTO_MEM_ALLOC;

    (*hex)[raw_len * 2] = 0;
    *hex_len = raw_len * 2;

    for (int32_t i = 0; i < raw_len; i++) {
        (*hex)[i * 2 + 0] = hx[(raw[i] >> 4) & 0x0F];
        (*hex)[i * 2 + 1] = hx[(raw[i]     ) & 0x0F];
    }
    
    return CRYPTO_OK;
}

PIPASS_ERR sanity_check_buffer(uint8_t *buf, uint8_t buf_len) {
    return ((buf == NULL || buf_len == 0 || buf[buf_len] != 0)
            ? (ERR_BUF_SANITY_CHECK_FAIL)
            : (CRYPTO_OK));
}
