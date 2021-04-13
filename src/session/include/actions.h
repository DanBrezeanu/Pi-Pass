/** @file actions.h */
#ifndef __ACTIONS_H__
#define __ACTIONS_H__

#include <errors.h>
#include <defines.h>
#include <storage_utils.h>
#include <crypto_utils.h>
#include <database.h>
#include <credentials.h>

/**
 * Adds a new credential to the database of the user
 * 
 * @param[in] user_hash           Hashed name of the currently logged in user
 * @param[in] type                Type of the new credential
 * @param[in] fields_count        Number of fields in the new credential
 * @param[in] fields_names_len    Array containing the lengths of the field names 
 * @param[in] fields_names        Array containing the fields' names
 * @param[in] fields_data_len     Array containing the lengths of the field data
 * @param[in] fields_encrypted    Boolean array specifying whether the fields are encrypted
 * @param[in] fields_data         Array containing the unecrypted fields' data
 *  
 */
PIPASS_ERR register_new_credential(uint8_t *user_hash, enum CredentialType type, uint16_t fields_count, uint16_t *fields_names_len, 
  uint8_t **fields_names, uint16_t *fields_data_len, uint8_t *fields_encrypted, uint8_t **fields_data);

/**
 * Retrieves one or more credentials from the database by finding a matching name-value field with
 * the one given
 * 
 * @param[in]  user_hash         Hashed name of the currently logged in user
 * @param[in]  field_name        Field name to query after
 * @param[in]  field_name_len    Field's name length
 * @param[in]  field_value       Field value to query after
 * @param[in]  field_value_len   Field's value length
 * @param[out] cr                A copy of the found credential(s)
 * @param[out] cr_len            The number of credentials found
 * 
 */
PIPASS_ERR get_credentials(uint8_t *user_hash, uint8_t *field_name, uint16_t field_name_len, uint8_t *field_value,
  uint16_t field_value_len, struct Credential **cr, uint16_t *cr_len);


PIPASS_ERR get_credential_names(uint8_t ***cr_names, uint16_t *cr_names_count);
PIPASS_ERR get_credential_details(uint8_t *name, struct Credential **cr);
PIPASS_ERR get_encrypted_field_value(uint8_t *cred_name, uint8_t *field_name, uint8_t **value);


#endif