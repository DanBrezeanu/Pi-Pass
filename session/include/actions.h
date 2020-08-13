#ifndef __ACTIONS_H__
#define __ACTIONS_H__

#include <errors.h>
#include <defines.h>
#include <storage_utils.h>
#include <crypto_utils.h>
#include <database.h>
#include <credentials.h>

STORAGE_ERR register_new_credential(struct Database *db, uint8_t *user_hash, uint8_t *master_pass, uint8_t *name, int32_t name_len,
 uint8_t *username, int32_t username_len, uint8_t *passw, int32_t passw_len, uint8_t *url, int32_t url_len,
 uint8_t *additional, int32_t additional_len);

STORAGE_ERR get_credential_by_name(struct Database *db, uint8_t *user_hash, uint8_t *master_pass, uint8_t *name, int16_t name_len, 
 struct PlainTextCredential **ptcr, struct CredentialHeader **ptcrh);


#endif