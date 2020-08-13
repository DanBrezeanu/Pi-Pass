#ifndef __CREDENTIALS_H__
#define __CREDENTIALS_H__

#include <errors.h>
#include <defines.h>
#include <string.h>
#include <crypto_utils.h>
#include <database.h>

struct Credential {
    uint8_t *name;
    uint8_t *username;
    uint8_t *username_mac;
    uint8_t *username_iv;
    uint8_t *passw;
    uint8_t *passw_mac;
    uint8_t *passw_iv;
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

DB_ERROR new_credential(struct Credential **cr, struct CredentialHeader **crh);

DB_ERROR populate_plaintext_field(struct Credential *cr, struct CredentialHeader *crh, uint8_t *data,
  int32_t data_len, enum CredentialField field);

DB_ERROR populate_encrypted_field(struct Database *db, struct Credential *cr, struct CredentialHeader *crh, uint8_t *data,
  int32_t data_len, enum CredentialEncryptedField field, uint8_t *master_pass);

DB_ERROR recalculate_header_len(struct CredentialHeader *crh);

DB_ERROR zero_credential(struct Credential *cr);
DB_ERROR zero_credential_header(struct CredentialHeader *crh);

#endif
