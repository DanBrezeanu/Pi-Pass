#include <credentials.h>
#include <crypto.h>
#include <storage.h>
#include <authentication.h>

PIPASS_ERR new_credential(struct Credential **cr, struct CredentialHeader **crh) {
    if (*cr != NULL || *crh != NULL)
        return ERR_MEM_LEAK;

    *cr = calloc(1, sizeof(struct Credential));
    *crh = calloc(1, sizeof(struct CredentialHeader));

    return DB_OK;
}

PIPASS_ERR populate_plaintext_field(struct Credential *cr, struct CredentialHeader *crh, uint8_t *data,
  int32_t data_len, enum CredentialField field) {
    if (cr == NULL || crh == NULL || data == NULL || !data_len) 
        return ERR_POPULATE_FIELD_INV_PARAMS;

    if (data_len > CREDENTIALS_FIELD_LIMIT)
        return ERR_FIELD_LIMIT_EXCEEDED;

    PIPASS_ERR err = sanity_check_buffer(data, data_len);
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

    memcpy(*field_buffer, data, data_len);
    (*field_buffer)[data_len] = 0;

    *field_len = data_len;

    err = recalculate_header_len(crh);
    if (err != DB_OK) {
        erase_buffer(field_buffer, data_len);
        return err;
    }

    return DB_OK;
}

PIPASS_ERR populate_encrypted_field(struct Database *db, struct Credential *cr, struct CredentialHeader *crh, uint8_t *data,
  int32_t data_len, enum CredentialEncryptedField field, uint8_t *master_pass) {

    if (db == NULL || cr == NULL || crh == NULL || !data_len || master_pass == NULL)
        return ERR_POPULATE_FIELD_INV_PARAMS;

    if (data_len > CREDENTIALS_FIELD_LIMIT)
        return ERR_FIELD_LIMIT_EXCEEDED;

    PIPASS_ERR err = sanity_check_buffer(data, data_len);
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

PIPASS_ERR populate_credential(struct Database *db, struct Credential **cr, struct CredentialHeader **crh, uint8_t *user_hash,
 uint8_t *master_pass, uint8_t *name, int32_t name_len, uint8_t *username, int32_t username_len, uint8_t *passw,
 int32_t passw_len, uint8_t *url, int32_t url_len, uint8_t *additional, int32_t additional_len) {

    if (db == NULL || master_pass == NULL || username == NULL || passw == NULL ||
      user_hash == NULL || !username_len || !passw_len)
    return ERR_POPULATE_CRED_INV_PARAMS;

    if (*cr != NULL || *crh != NULL)
        return ERR_POPULATE_CRED_MEM_LEAK;

    PIPASS_ERR err = STORAGE_OK;

    err = verify_user_directory(user_hash);
    if (err != STORAGE_OK)
        return err;

    err = verify_master_password(user_hash, master_pass);
    if (err != STORAGE_OK)
        return err;

    err = new_credential(cr, crh);
    if (err != DB_OK)
        goto error;

    if (name != NULL) {
        err = populate_plaintext_field(*cr, *crh, name, name_len, NAME);
        if (err != STORAGE_OK)
            goto error;
    }

    err = populate_encrypted_field(db, *cr, *crh, username, username_len, USERNAME, master_pass);
    if (err != STORAGE_OK)
        goto error;

    err = populate_encrypted_field(db, *cr, *crh, passw, passw_len, PASSW, master_pass);
    if (err != STORAGE_OK)
        goto error;

    if (url != NULL) {
        err = populate_plaintext_field(*cr, *crh, url, url_len, URL);
        if (err != STORAGE_OK)
            goto error;
    }

    if (additional != NULL) {
        err = populate_plaintext_field(*cr, *crh, additional, additional_len, ADDITIONAL);
        if (err != STORAGE_OK)
            goto error;
    }

    return err;

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

    return DB_OK;
}

PIPASS_ERR zero_credential(struct Credential *cr) {
    if (cr == NULL)
        return ERR_ZERO_CRED_INV_PARAMS;

    cr->name = cr->username = cr->username_mac = cr->username_iv = cr->passw = 
    cr->passw_mac = cr->passw_iv = cr->url = cr->additional = NULL;

    return DB_OK;
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

void free_plaintext_credential(struct PlainTextCredential *cr, struct CredentialHeader *crh) {
    if (cr != NULL) {
        if (cr->name != NULL) erase_buffer(&(cr->name), crh->name_len);
        if (cr->username != NULL) erase_buffer(&(cr->username), crh->username_len);
        if (cr->passw != NULL) erase_buffer(&(cr->passw), crh->passw_len);
        if (cr->url != NULL) erase_buffer(&(cr->url), crh->url_len);
        if (cr->additional != NULL) erase_buffer(&(cr->additional), crh->additional_len);
    }

    if (crh != NULL) {
        zero_credential_header(crh);
    }
}

PIPASS_ERR credentials_equal(struct Credential *cr1, struct CredentialHeader *crh1,
  struct Credential *cr2, struct CredentialHeader *crh2) {

    if (cr1 == NULL || crh1 == NULL || cr2 == NULL || crh2 == NULL)
        return ERR_CRED_EQUAL_INV_PARAMS;

    if (crh1->name_len != crh2->name_len || crh1->username_len != crh2->username_len ||
    crh1->passw_len != crh2->passw_len || crh1->url_len != crh2->url_len ||
    crh1->additional_len != crh2->additional_len)
        return ERR_CREDENTIALS_DIFFER;

    if (fields_equal(cr1->name, cr2->name, crh1->name_len) == DB_OK &&
      fields_equal(cr1->username, cr2->username, crh1->username_len) == DB_OK &&
      fields_equal(cr1->passw, cr2->passw, crh1->passw_len) == DB_OK &&
      fields_equal(cr1->url, cr2->url, crh1->url_len) == DB_OK &&
      fields_equal(cr1->additional, cr2->additional, crh1->additional_len) == DB_OK)
        return DB_OK;
    
    return ERR_CREDENTIALS_DIFFER;
}

PIPASS_ERR fields_equal(uint8_t *field1, uint8_t *field2, int32_t field_len) {
    if (field1 == NULL && field2 == NULL && field_len == 0)
        return DB_OK;
    
    if ((field1 == NULL && field2 != NULL) || (field1 != NULL && field2 == NULL))
        return ERR_FIELDS_DIFFER;

    return (strncmp(field1, field2, field_len) == 0)
           ? (DB_OK)
           : (ERR_FIELDS_DIFFER); 
}

PIPASS_ERR append_to_credential_array(struct Credential **cr, int32_t *cr_len, struct Credential *to_add) {
    if (to_add == NULL)
        return ERR_APPND_CRED_ARR_INV_PARAMS;

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

        // TODO: memcopy buffers
        *cr = _tmp_cr;
    }

    (*cr)[*cr_len] = *to_add;
    (*cr_len)++;

    return DB_OK;
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

    (*crh)[*crh_len] = *to_add;
    (*crh_len)++;

    return DB_OK;
}