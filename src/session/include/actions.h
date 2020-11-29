#ifndef __ACTIONS_H__
#define __ACTIONS_H__

#include <errors.h>
#include <defines.h>
#include <storage_utils.h>
#include <crypto_utils.h>
#include <database.h>
#include <credentials.h>

PIPASS_ERR register_new_credential(uint8_t *user_hash, enum CredentialType type, uint16_t fields_count, uint16_t *fields_names_len, 
  uint8_t **fields_names, uint16_t *fields_data_len, uint8_t *fields_encrypted, uint8_t **fields_data);

PIPASS_ERR get_credentials(uint8_t *user_hash, uint8_t *field_name, uint16_t field_name_len, uint8_t *field_value,
  uint16_t field_value_len, struct Credential **cr, uint16_t *cr_len);


#endif