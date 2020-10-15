#ifndef __AES256_H__
#define __AES256_H__


#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#include <defines.h>
#include <errors.h>
#include <salt.h>
#include <fastpbkdf2.h>
#include <stdint.h>
#include <crypto_utils.h>

PIPASS_ERR generate_aes256_key(uint8_t *key);

PIPASS_ERR create_PBKDF2_key(uint8_t *input, int32_t input_len, uint8_t *salt, int32_t salt_len, uint8_t *pbkdf2_key);

PIPASS_ERR encrypt_aes256(uint8_t *plaintext, int32_t plaintext_len, uint8_t *aad, int32_t aad_len, uint8_t *key,
    uint8_t *iv, uint8_t *mac, uint8_t *ciphertext, int32_t *ciphertext_len);

PIPASS_ERR decrypt_aes256(uint8_t *ciphertext, int32_t ciphertext_len, uint8_t *aad, int32_t aad_len, uint8_t *mac,
    uint8_t *key, uint8_t *iv, uint8_t *plaintext, int32_t *plaintext_len);

#endif
