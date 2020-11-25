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

// PIPASS_ERR get_credentials_by_name(struct Database *db, uint8_t *user_hash, uint8_t *pin, uint8_t *name, int16_t name_len, 
//  struct PlainTextCredential **ptcr, struct CredentialHeader **ptcrh, int32_t *cred_count);


#endif