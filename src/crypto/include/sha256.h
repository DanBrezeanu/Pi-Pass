#ifndef __SHA256_H__
#define __SHA256_H__

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/sha.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#include <errors.h>
#include <string.h>
#include <defines.h>
#include <stdint.h>
#include <crypto_utils.h>

PIPASS_ERR hash_sha256(uint8_t *input, size_t input_len, uint8_t *salt, uint32_t salt_len, uint8_t *digest);
PIPASS_ERR verify_sha256(uint8_t *input, size_t input_len, uint8_t *salt, uint32_t salt_len, uint8_t *digest);
PIPASS_ERR verify_sha256_fd(uint8_t *input, size_t input_len, uint8_t *salt, uint32_t salt_len, int32_t fd_dgst);

#endif
