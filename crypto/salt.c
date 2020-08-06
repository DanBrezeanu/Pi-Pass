#include <salt.h>

CRYPTO_ERR create_salt(int32_t size, uint8_t *salt) {
    int32_t hwrng_fd = open("/dev/hwrng", O_RWONLY);
    if (hwrng_fd == -1) {
        return ERR_HWRNG_OPEN_FAIL;
    }

    int32_t size_read = 0;
    int32_t res = 0;

    do {
        res = read(hwrng_fd, salt, size - size_read);
        if (res == -1) {    
            zero_buffer(salt);
            return ERR_HWRNG_READ_FAIL;
        }

        size_read += res;
    } while (size_read < size);

    return CRYPTO_OK;
} 