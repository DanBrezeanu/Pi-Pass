#ifndef __CREDENTIALS_H__
#define __CREDENTIALS_H__

#include <errors.h>
#include <defines.h>
#include <string.h>
#include <crypto_utils.h>
#include <database.h>
#include <crypto.h>
#include <credentials_utils.h>
#include <datablob.h>

enum CredentialType {
  PASSWORD_TYPE, CREDIT_CARD_TYPE, OTHER_TYPE 
};

union CredentialFieldData {
    uint8_t *data_plain;
    struct DataBlob data_encryped;
} __attribute__((packed, aligned(1)));

struct Credential {
    uint32_t cred_size;
    enum CredentialType type;
    uint16_t fields_count;
    
    uint16_t *fields_names_len;
    uint8_t **fields_names;
    uint16_t *fields_data_len;
    uint8_t *fields_encrypted;

    union CredentialFieldData *fields_data;
    
} __attribute__((packed, aligned(1)));


PIPASS_ERR alloc_credential(struct Credential **cr);

PIPASS_ERR alloc_credential_arrays(struct Credential *cr);

PIPASS_ERR populate_plaintext_field(struct Credential *cr, uint8_t *field_name, uint8_t *data,
  int32_t data_len);

PIPASS_ERR populate_encrypted_field(struct Credential *cr, uint8_t *field_name, uint8_t *data,
  int32_t data_len);

PIPASS_ERR add_field_credential(struct Credential *cr, uint8_t *field_name, uint16_t field_name_len,
  uint8_t *field_data, uint16_t field_data_len, uint8_t field_is_encrypted);

PIPASS_ERR recalculate_cred_len(struct Credential *cr);

PIPASS_ERR zero_credential(struct Credential *cr);

void free_credential(struct Credential *cr);

PIPASS_ERR append_to_credential_array(struct Credential **cr, int32_t *cr_len, struct Credential *to_add);

PIPASS_ERR create_credential(enum CredentialType type, uint16_t fields_count, uint16_t *fields_names_len, 
  uint8_t **fields_names, uint16_t *fields_data_len, uint8_t *fields_encrypted, uint8_t **fields_data,
  struct Credential **cr);

PIPASS_ERR credential_raw(struct Credential *cr, uint8_t **raw_cr, uint32_t *raw_cr_len);
#endif
