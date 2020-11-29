#include <salt.h>
#include <crypto_utils.h>

PIPASS_ERR create_salt(int32_t size, uint8_t *salt) {
    int32_t err = RAND_bytes(salt, size);
    if (err == -1) {
        return ERR_RAND_NOT_SUPPORTED;
    }

    if (err == 0) {
        zero_buffer(salt, size);
        return ERR_RAND_FAIL;
    }

    return CRYPTO_OK;
} 