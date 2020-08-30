#include <credentials.h>
#include <crypto.h>

DB_ERROR new_credential(struct Credential **cr, struct CredentialHeader **crh) {
    if (*cr != NULL || *crh != NULL)
        return ERR_MEM_LEAK;

    *cr = calloc(1, sizeof(struct Credential));
    *crh = calloc(1, sizeof(struct CredentialHeader));

    return DB_OK;
}

DB_ERROR populate_plaintext_field(struct Credential *cr, struct CredentialHeader *crh, uint8_t *data,
  int32_t data_len, enum CredentialField field) {
    if (cr == NULL || crh == NULL || data == NULL || !data_len) 
        return ERR_POPULATE_FIELD_INV_PARAMS;

    if (data_len > CREDENTIALS_FIELD_LIMIT)
        return ERR_FIELD_LIMIT_EXCEEDED;

    DB_ERROR err = sanity_check_buffer(data, data_len);
    if (err != CRYPTO_OK)
        return err;

    uint8_t **field_buffer = NULL;
    uint16_t *field_len = 0;

    switch (field) {
    case NAME:
        field_buffer = &(cr->name);
        field_len = &(crh->name_len);
        break;
    case URL:
        field_buffer = &(cr->url);
        field_len = &(crh->url_len);
        break;
    case ADDITIONAL:
        field_buffer = &(cr->additional);
        field_len = &(crh->additional_len);
        break;
    default:
        return ERR_INVALID_FIELD;
    }

    if (*field_buffer != NULL)
        return ERR_DB_MEM_LEAK;

    *field_buffer = malloc(data_len + 1);
    if (*field_buffer == NULL)
        return ERR_DB_MEM_ALLOC;

    memcpy(*field_buffer, data, data_len + 1);
    *field_len = data_len;

    err = recalculate_header_len(crh);
    if (err != DB_OK) {
        erase_buffer(field_buffer, data_len);
        return err;
    }

    return DB_OK;
}

DB_ERROR populate_encrypted_field(struct Database *db, struct Credential *cr, struct CredentialHeader *crh, uint8_t *data,
  int32_t data_len, enum CredentialEncryptedField field, uint8_t *master_pass) {

    if (db == NULL || cr == NULL || crh == NULL || !data_len || master_pass == NULL)
        return ERR_POPULATE_FIELD_INV_PARAMS;

    if (data_len > CREDENTIALS_FIELD_LIMIT)
        return ERR_FIELD_LIMIT_EXCEEDED;

    DB_ERROR err = sanity_check_buffer(data, data_len);
    if (err != CRYPTO_OK)
        return err;

    uint8_t **field_cipher = NULL;
    uint8_t **field_iv = NULL;
    uint8_t **field_mac = NULL;
    uint16_t *field_len = 0;

    switch (field) {
    case USERNAME:
        field_cipher = &(cr->username);
        field_iv = &(cr->username_iv);
        field_mac = &(cr->username_mac);
        field_len = &(crh->username_len);
        break;
    case PASSW:
        field_cipher = &(cr->passw);
        field_iv = &(cr->passw_iv);
        field_mac = &(cr->passw_mac);
        field_len = &(crh->passw_len);
        break;
    default:
        return ERR_INVALID_FIELD;
    }

    if (*field_cipher != NULL || *field_iv != NULL || *field_mac != NULL)
        return ERR_DB_MEM_LEAK;

    err = encrypt_credential_field(db, data, data_len, master_pass, field_cipher, field_iv, field_mac, field_len);
    if (err != CRYPTO_OK)
        goto error;

    recalculate_header_len(crh);

    return DB_OK;

error:
    erase_buffer(field_cipher, *field_len);
    erase_buffer(field_iv, IV_SIZE);
    erase_buffer(field_mac, MAC_SIZE);

    return err;

}

DB_ERROR recalculate_header_len(struct CredentialHeader *crh) {
    if (crh == NULL)
        return ERR_RECALC_HEADER_INV_PARAMS;

    crh->cred_len = crh->name_len + crh->username_len + crh->passw_len +
        crh->url_len + crh->additional_len;

    if (crh->username_len > 0)
        crh->cred_len += IV_SIZE + MAC_SIZE;

    if (crh->passw_len > 0)
        crh->cred_len += IV_SIZE + MAC_SIZE;

    return DB_OK;
}

DB_ERROR zero_credential(struct Credential *cr) {
    if (cr == NULL)
        return ERR_ZERO_CRED_INV_PARAMS;

    cr->name = cr->username = cr->username_mac = cr->username_iv = cr->passw = 
    cr->passw_mac = cr->passw_iv = cr->url = cr->additional = NULL;

    return DB_OK;
}

DB_ERROR zero_credential_header(struct CredentialHeader *crh) {
    if (crh == NULL)
        return ERR_ZERO_CREDH_INV_PARAMS;

    crh->cred_len = crh->name_len = crh->username_len = crh->passw_len =
    crh->url_len = crh->additional_len = 0;

    return DB_OK;
}

void free_credential(struct Credential *cr, struct CredentialHeader *crh) {
    if (cr != NULL) {
        if (cr->name != NULL) erase_buffer(&(cr->name), crh->name_len);
        if (cr->username != NULL) erase_buffer(&(cr->username), crh->username_len);
        if (cr->username_mac != NULL) erase_buffer(&(cr->username_mac), MAC_SIZE);
        if (cr->username_iv != NULL) erase_buffer(&(cr->username_iv), IV_SIZE);
        if (cr->passw != NULL) erase_buffer(&(cr->passw), crh->passw_len);
        if (cr->passw_mac != NULL) erase_buffer(&(cr->passw_mac), MAC_SIZE);
        if (cr->passw_iv != NULL) erase_buffer(&(cr->passw_iv), IV_SIZE);
        if (cr->url != NULL) erase_buffer(&(cr->url), crh->url_len);
        if (cr->additional != NULL) erase_buffer(&(cr->additional), crh->additional_len);
    }

    if (crh != NULL) {
        zero_credential_header(crh);
    }
}