#include <credentials.h>
#include <crypto.h>
#include <storage.h>
#include <authentication.h>

PIPASS_ERR new_credential(struct Credential **cr, struct CredentialHeader **crh) {
    if (*cr != NULL || *crh != NULL)
        return ERR_MEM_LEAK;

    PIPASS_ERR err;

    *cr = calloc(1, sizeof(struct Credential));
    if (*cr == NULL)
        return ERR_DB_MEM_ALLOC;

    *crh = calloc(1, sizeof(struct CredentialHeader));
    if (*crh == NULL) {
        err = ERR_DB_MEM_ALLOC;
        goto error;
    }

    return PIPASS_OK;

error:
    if (*cr != NULL)
        free(*cr);

    return err;
}

PIPASS_ERR populate_plaintext_field(struct Credential *cr, struct CredentialHeader *crh, uint8_t *data,
  int32_t data_len, enum CredentialField field_type) {
    if (cr == NULL || crh == NULL || data == NULL || !data_len) 
        return ERR_POPULATE_FIELD_INV_PARAMS;

    if (data_len > CREDENTIALS_FIELD_LIMIT)
        return ERR_FIELD_LIMIT_EXCEEDED;

    PIPASS_ERR err = sanity_check_buffer(data, data_len);
    if (err != PIPASS_OK)
        return err;

    uint8_t **field_buffer = NULL;
    uint16_t *field_len = 0;

    switch (field_type) {
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

    memcpy(*field_buffer, data, data_len);
    (*field_buffer)[data_len] = 0;

    *field_len = data_len;

    err = recalculate_header_len(crh);
    if (err != PIPASS_OK) {
        erase_buffer(field_buffer, data_len);
        return err;
    }

    return PIPASS_OK;
}

PIPASS_ERR populate_encrypted_field(struct Credential *cr, struct CredentialHeader *crh, uint8_t *data,
  int32_t data_len, enum CredentialEncryptedField field_type) {
    
    if (!FL_LOGGED_IN)
        return ERR_NOT_LOGGED_IN;

    if (!FL_DB_INITIALIZED)
        return ERR_DB_NOT_INITIALIZED;

    if (OTK == NULL)
        return ERR_OTK_NOT_INITIALIZED;
    
    if (DEK_BLOB == NULL)
        return ERR_DEK_BLOB_NOT_INIT;

    if (cr == NULL || crh == NULL || !data_len)
        return ERR_POPULATE_FIELD_INV_PARAMS;

    if (data_len > CREDENTIALS_FIELD_LIMIT)
        return ERR_FIELD_LIMIT_EXCEEDED;

    PIPASS_ERR err = sanity_check_buffer(data, data_len);
    if (err != CRYPTO_OK)
        return err;

    struct DataBlob *field = NULL;
    uint16_t *field_len = 0;

    switch (field_type) {
    case USERNAME:
        field = &(cr->username);
        field_len = &(crh->username_len);
        break;
    case PASSW:
        field = &(cr->password);
        field_len = &(crh->passw_len);
        break;
    default:
        return ERR_INVALID_FIELD;
    }

    if (field->ciphertext != NULL || field->iv != NULL || field->mac != NULL)
        return ERR_DB_MEM_LEAK;

    err = encrypt_field_with_DEK(data, data_len, field, field_len);
    if (err != CRYPTO_OK)
        goto error;

    recalculate_header_len(crh);

    return PIPASS_OK;

error:
    free_datablob(field, *field_len);

    return err;
}

PIPASS_ERR populate_credential(struct Credential **cr, struct CredentialHeader **crh,
  uint8_t *name, int32_t name_len, uint8_t *username, int32_t username_len, uint8_t *passw, 
  int32_t passw_len, uint8_t *url, int32_t url_len, uint8_t *additional, int32_t additional_len) {
    
    if (!FL_LOGGED_IN)
        return ERR_NOT_LOGGED_IN;

    if (!FL_DB_INITIALIZED)
        return ERR_DB_NOT_INITIALIZED;

    if (OTK == NULL)
        return ERR_OTK_NOT_INITIALIZED;

    if (DEK_BLOB == NULL)
        return ERR_DEK_BLOB_NOT_INIT;

    if (username == NULL || passw == NULL ||  !username_len || !passw_len)
    return ERR_POPULATE_CRED_INV_PARAMS;

    if (*cr != NULL || *crh != NULL)
        return ERR_POPULATE_CRED_MEM_LEAK;

    PIPASS_ERR err = PIPASS_OK;

    err = new_credential(cr, crh);
    if (err != PIPASS_OK)
        goto error;

    if (name != NULL) {
        err = populate_plaintext_field(*cr, *crh, name, name_len, NAME);
        if (err != PIPASS_OK)
            goto error;
    }

    err = populate_encrypted_field(*cr, *crh, username, username_len, USERNAME);
    if (err != PIPASS_OK)
        goto error;

    err = populate_encrypted_field(*cr, *crh, passw, passw_len, PASSW);
    if (err != PIPASS_OK)
        goto error;

    if (url != NULL) {
        err = populate_plaintext_field(*cr, *crh, url, url_len, URL);
        if (err != PIPASS_OK)
            goto error;
    }

    if (additional != NULL) {
        err = populate_plaintext_field(*cr, *crh, additional, additional_len, ADDITIONAL);
        if (err != PIPASS_OK)
            goto error;
    }

    return PIPASS_OK;

error:
    free_credential(*cr, *crh);
    if (cr != NULL) {
        memset(cr, 0, sizeof(struct Credential));
        free(cr);
        cr = NULL;
    }

    if (crh != NULL) {
        memset(crh, 0, sizeof(struct CredentialHeader));
        free(crh);
        crh = NULL;
    }

    return err;
 }

PIPASS_ERR recalculate_header_len(struct CredentialHeader *crh) {
    if (crh == NULL)
        return ERR_RECALC_HEADER_INV_PARAMS;

    crh->cred_len = crh->name_len + crh->username_len + crh->passw_len +
        crh->url_len + crh->additional_len;

    if (crh->username_len > 0)
        crh->cred_len += IV_SIZE + MAC_SIZE;

    if (crh->passw_len > 0)
        crh->cred_len += IV_SIZE + MAC_SIZE;

    return PIPASS_OK;
}

PIPASS_ERR zero_credential(struct Credential *cr) {
    if (cr == NULL)
        return ERR_ZERO_CRED_INV_PARAMS;

    cr->name = cr->username.ciphertext = cr->username.mac = cr->username.iv =
    cr->password.ciphertext = cr->password.mac = cr->password.iv = cr->url = cr->additional = NULL;

    return PIPASS_OK;
}

PIPASS_ERR zero_credential_header(struct CredentialHeader *crh) {
    if (crh == NULL)
        return ERR_ZERO_CREDH_INV_PARAMS;

    crh->cred_len = crh->name_len = crh->username_len = crh->passw_len =
    crh->url_len = crh->additional_len = 0;

    return DB_OK;
}

void free_credential(struct Credential *cr, struct CredentialHeader *crh) {
    if (cr != NULL) {
        erase_buffer(&(cr->name), crh->name_len);
        erase_buffer(&(cr->url), crh->url_len);
        erase_buffer(&(cr->additional), crh->additional_len);
        
        free_datablob(&(cr->username), crh->username_len);
        free_datablob(&(cr->password), crh->passw_len);
    }

    if (crh != NULL) {
        zero_credential_header(crh);
    }
}

void free_plaintext_credential(struct PlainTextCredential *cr, struct CredentialHeader *crh) {
    if (cr != NULL) {
        erase_buffer(&(cr->name), crh->name_len);
        erase_buffer(&(cr->username), crh->username_len);
        erase_buffer(&(cr->passw), crh->passw_len);
        erase_buffer(&(cr->url), crh->url_len);
        erase_buffer(&(cr->additional), crh->additional_len);
    }

    if (crh != NULL) {
        zero_credential_header(crh);
    }
}

PIPASS_ERR append_to_credential_array(struct Credential **cr, int32_t *cr_len, struct Credential *to_add, struct CredentialHeader *to_add_header) {
    if (to_add == NULL)
        return ERR_APPND_CRED_ARR_INV_PARAMS;

    PIPASS_ERR err;

    if (*cr == NULL) {
        if (*cr_len == 0) {
            *cr = calloc(1, sizeof(struct Credential));

            if (*cr == NULL)
                return ERR_DB_MEM_ALLOC;
        } else {
            return ERR_APPND_CRED_ARR_INV_PARAMS;
        }
    } else {
        struct Credential *_tmp_cr = realloc(*cr, (*cr_len + 1) * sizeof(struct Credential));
        if (_tmp_cr == NULL)
            return ERR_DB_MEM_ALLOC;

        *cr = _tmp_cr;
    }

    err = memcpy_credentials(&((*cr)[*cr_len]), to_add, to_add_header);
    if (err != PIPASS_OK)
        return err;

    return PIPASS_OK;
}

PIPASS_ERR append_to_credential_header_array(struct CredentialHeader **crh, int32_t *crh_len, struct CredentialHeader *to_add) {
    if (to_add == NULL)
        return ERR_APPND_CREDH_ARR_INV_PARAMS;

    if (*crh == NULL) {
        if (*crh_len == 0) {
            *crh = calloc(1, sizeof(struct CredentialHeader));

            if (*crh == NULL)
                return ERR_DB_MEM_ALLOC;
        } else {
            return ERR_APPND_CREDH_ARR_INV_PARAMS;
        }
    } else {
        struct CredentialHeader *_tmp_crh = realloc(*crh, (*crh_len + 1) * sizeof(struct CredentialHeader));
        if (_tmp_crh == NULL)
            return ERR_DB_MEM_ALLOC;

        *crh = _tmp_crh;
    }

    memcpy(&((*crh)[*crh_len]), to_add, sizeof(to_add));
    (*crh_len)++;

    return PIPASS_OK;
}