/** @file aes256.h */
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


/**
 * Generates a random 256-bit key.
 * 
 * @param[in,out] key   The generated 256-bit key
 * 
 * @note Memory must be already allocated for `key`.
 * 
 * @return  #PIPASS_OK if the key has been successfully generated, else:
 *            - #ERR_CRYPTO_GEN_KEY_INV_PARAMS
 *            - #ERR_RAND_NOT_SUPPORTED
 *            - #ERR_RAND_FAIL
 */
PIPASS_ERR generate_aes256_key(uint8_t *key);

/**
 * Generates a 256-bit key from the provided input and salt.
 * 
 * @param[in] input        The password to be derived into a key
 * @param[in] input_len    The length of the input
 * @param[in] salt         **Optional**. Salt value used in the key derivation function
 * @param[in] salt_len     The length of the salt. If `salt` was `NULL`, this parameter will be ignored
 * @param[out] pbkdf2_key  The key derived from the input and salt.
 * 
 * @note Memory must be already allocated for `pbkdf2_key`. 
 * 
 * @return  #PIPASS_OK if the key has been successfully generated, else:
 *            - #ERR_AES_PBKDF_INV_PARAMS
 * 
 */
PIPASS_ERR create_PBKDF2_key(uint8_t *input, int32_t input_len, uint8_t *salt, int32_t salt_len, uint8_t *pbkdf2_key);


/**
 * Encrypts data with the AES256-GCM algorithm.
 * 
 * @param[in] plaintext       The data to be encrypted
 * @param[in] plaintext_len   The length of the data
 * @param[in] aad             **Optional**. Additional authenticated data
 * @param[in] aad_len         The length of `aad`. If `aad` is `NULL`, this parameter will be ignored
 * @param[in] key             The 256-bit key used to encrypt the data
 * @param[in] iv              Initialization vector, a nonce for the encryption. Must be `IV_SIZE` long.
 * @param[out] mac            Message authentication code resulted from the encryption
 * @param[out] ciphertext     The encrypted data
 * @param[out] ciphertext_len The length of the encrypted data. For AES256-GCM the length of the ciphertext
 *                            is equal to the length of the plaintext
 * 
 * @note This is a low-level function. If possible use #encrypt_data_with_key() function for data
 *       encryption.
 * 
 * @return  #PIPASS_OK if the data has been successfully encrypted, else:
 *            - #ERR_AES_ENC_INV_PARAMS
 *            - #ERR_AES_ENC_EVP_INIT
 *            - #ERR_AES_ENC_SET_IVLEN
 *            - #ERR_AES_ENC_EVP_INIT_KEY
 *            - #ERR_AES_ENC_EVP_AAD
 *            - #ERR_AES_ENC_EVP_ENCRYPT
 *            - #ERR_AES_ENC_EVP_FINAL
 *            - #ERR_AES_ENC_EVP_MAC
 */
PIPASS_ERR encrypt_aes256(uint8_t *plaintext, int32_t plaintext_len, uint8_t *aad, int32_t aad_len, uint8_t *key,
    uint8_t *iv, uint8_t *mac, uint8_t *ciphertext, int32_t *ciphertext_len);


/** Decrypts data with the AES256-GCM algorithm.
 * @param[in] ciphertext        The data to be decrypted
 * @param[in] ciphertext_len    The length of the data
 * @param[in] aad               **Optional**. Additional authenticated data used when encrypted.
 * @param[in] aad_len           The length of `aad`. If `aad` is `NULL`, this parameter will be ignored
 * @param[in] key               The 256-bit key used to decrypt the data
 * @param[in] iv                Initialization vector used when the data was encrypted. Must be `IV_SIZE` long
 * @param[in] mac               Message authentication code resulted from the encryption
 * @param[out] plaintext        The decrytped data
 * @param[out] plaintext_len    The length of the decrypted data. For AES256-GCM the length of the ciphertext
 *                              is equal to the length of the plaintext
 * 
 * @note This is a low-level function. If possible use #decrypt_cipher_with_key() function for data
 *       decryption. 
 *
 */
PIPASS_ERR decrypt_aes256(uint8_t *ciphertext, int32_t ciphertext_len, uint8_t *aad, int32_t aad_len, uint8_t *mac,
    uint8_t *key, uint8_t *iv, uint8_t *plaintext, int32_t *plaintext_len);

#endif
