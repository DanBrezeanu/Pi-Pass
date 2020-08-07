#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <errors.h>
#include <stdint.h>
#include <defines.h>
#include <openssl/rand.h>

CRYPTO_ERR create_salt(int32_t size, uint8_t *salt);