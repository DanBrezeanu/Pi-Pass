/** @file crypto.h */
#include <crypto_utils.h>
#include <database.h>
#include <flags.h>
#include <defines.h>
#include <errors.h>

extern uint8_t *OTK;                /**< One-time key, used for encrypting the Data Encryption Key at runtime. It changes every session. */
extern struct DataBlob *DEK_BLOB;   /**< The Data Encryption Key encrypted with the #OTK */

/**
 * Generates the Key Encryption Key from the given master pin, master salt and fingerprint data.
 * This function does not check the correctness of the resulting key. In other words, if this
 * function succeeds it does not necessary mean that the key will actually decrypt the database.
 * 
 * @param[in]  pin       The user specific master pin
 * @param[in]  salt      The salt used for generating the Key Encryption Key. Usually it is the
 *                       same with the salt used for hashing the pin.
 * @param[in]  fp_key    The fingerprint key resulted from the key derivation of the fingrprint data.
 * @param[out] KEK       The resulting Key Encryption Key. `*KEK` must be `NULL`, memory will be 
 *                       alloc'd inside the function
 * 
 * @return #PIPASS_OK if the key has been successfully generated, else:
 *            - #ERR_CRYPTO_KEK_INV_PARAMS
 *            - #ERR_CONCAT_PEPPER_INV_PARAMS
 *            - #ERR_RETRIEVE_CPU_ID
 * 
 * 
 */
PIPASS_ERR generate_KEK(uint8_t *pin, uint8_t *salt, uint8_t *fp_key, uint8_t **KEK);

/**
 * 
 * 
 * @param[in]
 * @param[out]
 * 
 * @return
 * 
 */
PIPASS_ERR generate_user_hash(uint8_t *user_data, int32_t user_data_len, uint8_t **user_hash);

/**
 * 
 * 
 * @param[in]
 * @param[out]
 * 
 * @return
 * 
 */
PIPASS_ERR generate_new_master_pin_hash(uint8_t *pin, struct DataHash *pin_hash);

/**
 * 
 * 
 * @param[in]
 * @param[out]
 * 
 * @return
 * 
 */
PIPASS_ERR encrypt_DEK_with_KEK(uint8_t *dek, uint8_t *kek, struct DataBlob *dek_blob);

/**
 * 
 * 
 * @param[in]
 * @param[out]
 * 
 * @return
 * 
 */
PIPASS_ERR decrypt_DEK_with_KEK(uint8_t *kek, uint8_t **dek);

/**
 * 
 * 
 * @param[in]
 * @param[out]
 * 
 * @return
 * 
 */
PIPASS_ERR decrypt_cipher_with_key(struct DataBlob *cipher, uint32_t cipher_len, uint8_t *key, uint8_t **data);

/**
 * 
 * 
 * @param[in]
 * @param[out]
 * 
 * @return
 * 
 */
PIPASS_ERR encrypt_data_with_key(uint8_t *data, uint32_t data_len, uint8_t *key, struct DataBlob *cipher);

/**
 * 
 * 
 * @param[in]
 * @param[out]
 * 
 * @return
 * 
 */
PIPASS_ERR encrypt_DEK_with_OTK(uint8_t *dek);

/**
 * 
 * 
 * @param[in]
 * @param[out]
 * 
 * @return
 * 
 */
PIPASS_ERR decrypt_DEK_with_OTK(uint8_t **dek);

/**
 * 
 * 
 * @param[in]
 * @param[out]
 * 
 * @return
 * 
 */
PIPASS_ERR encrypt_field_with_DEK(uint8_t *field, int32_t field_len, struct DataBlob *field_blob, int16_t *cipher_len);

/**
 * 
 * 
 * @param[in]
 * @param[out]
 * 
 * @return
 * 
 */
PIPASS_ERR decrypt_field_with_DEK(struct DataBlob *cipher, int16_t cipher_len, uint8_t **data, int32_t *data_len);

/**
 * 
 * 
 * @param[in]
 * @param[out]
 * 
 * @return
 * 
 */
PIPASS_ERR merge_keys(uint8_t *key_1, uint8_t *key_2, uint8_t **key);

/**
 * 
 * 
 * @param[in]
 * @param[out]
 * 
 * @return
 * 
 */
PIPASS_ERR reencrypt_DEK(struct DataBlob *dek_blob, uint8_t *new_master_pin, uint8_t *new_master_pin_salt, 
  uint8_t *old_master_pin, uint8_t *old_master_pin_salt);

/**
 * 
 * 
 * @param[in]
 * @param[out]
 * 
 * @return
 * 
 */
PIPASS_ERR verify_master_pin_with_db(uint8_t *pin);

/**
 * 
 * 
 * @param[in]
 * @param[out]
 * 
 * @return
 * 
 */
PIPASS_ERR verify_master_pin_with_hash(uint8_t *pin, struct DataHash pin_hash);

/**
 * 
 * 
 * @param[in]
 * @param[out]
 * 
 * @return
 * 
 */
PIPASS_ERR generate_OTK();

/**
 * 
 * 
 * @param[in]
 * @param[out]
 * 
 * @return
 * 
 */
PIPASS_ERR invalidate_OTK();

/**
 * 
 * 
 * @param[in]
 * @param[out]
 * 
 * @return
 * 
 */
PIPASS_ERR invalidate_DEK_BLOB();

/**
 * 
 * 
 * @param[in]
 * @param[out]
 * 
 * @return
 * 
 */
PIPASS_ERR generate_new_master_pin_hash(uint8_t *pin, struct DataHash *pin_hash);

/**
 * 
 * 
 * @param[in]
 * @param[out]
 * 
 * @return
 * 
 */
PIPASS_ERR encrypt_DEK_with_KEK(uint8_t *dek, uint8_t *kek, struct DataBlob *dek_blob);