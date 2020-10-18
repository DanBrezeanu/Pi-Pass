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

struct Credential {
    uint8_t *name;
    struct DataBlob username;
    struct DataBlob password;
    uint8_t *url;
    uint8_t *additional;
} __attribute__((packed, aligned(1)));

struct CredentialHeader {
    uint32_t cred_len;
    uint16_t name_len;
    uint16_t username_len;
    uint16_t passw_len;
    uint16_t url_len;
    uint16_t additional_len;
} __attribute__((packed, aligned(1)));

enum CredentialField {
    NAME       = 0,
    URL        = 1,
    ADDITIONAL = 2
};

enum CredentialEncryptedField {
    USERNAME = 0,
    PASSW    = 1
};

struct PlainTextCredential {
    uint8_t *name;
    uint8_t *username;
    uint8_t *passw;
    uint8_t *url;
    uint8_t *additional;
} __attribute__((packed, aligned(1)));

PIPASS_ERR new_credential(struct Credential **cr, struct CredentialHeader **crh);

PIPASS_ERR populate_plaintext_field(struct Credential *cr, struct CredentialHeader *crh, uint8_t *data,
  int32_t data_len, enum CredentialField field_type);

PIPASS_ERR populate_encrypted_field(struct Credential *cr, struct CredentialHeader *crh, uint8_t *data,
  int32_t data_len, enum CredentialEncryptedField field_type);

PIPASS_ERR populate_credential(struct Credential **cr, struct CredentialHeader **crh,
  uint8_t *name, int32_t name_len, uint8_t *username, int32_t username_len, uint8_t *passw, 
  int32_t passw_len, uint8_t *url, int32_t url_len, uint8_t *additional, int32_t additional_len);

PIPASS_ERR recalculate_header_len(struct CredentialHeader *crh);

PIPASS_ERR zero_credential(struct Credential *cr);

PIPASS_ERR zero_credential_header(struct CredentialHeader *crh);

void free_credential(struct Credential *cr, struct CredentialHeader *crh);

void free_plaintext_credential(struct PlainTextCredential *cr, struct CredentialHeader *crh);

PIPASS_ERR append_to_credential_array(struct Credential **cr, int32_t *cr_len, struct Credential *to_add, struct CredentialHeader *to_add_header);

PIPASS_ERR append_to_credential_header_array(struct CredentialHeader **crh, int32_t *crh_len, struct CredentialHeader *to_add);


#endif
