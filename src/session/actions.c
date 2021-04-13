/// @file actions.c
#include <actions.h>
#include <database.h>
#include <database.h>
#include <credentials.h>
#include <crypto.h>
#include <storage.h>
#include <authentication.h>



PIPASS_ERR register_new_credential(uint8_t *user_hash, enum CredentialType type, uint16_t fields_count, uint16_t *fields_names_len, 
  uint8_t **fields_names, uint16_t *fields_data_len, uint8_t *fields_encrypted, uint8_t **fields_data) {

    if (!FL_LOGGED_IN)
        return ERR_NOT_LOGGED_IN;

    if (!FL_DB_INITIALIZED)
        return ERR_DB_NOT_INITIALIZED;

    if (fields_names_len == NULL || fields_names == NULL || fields_data_len == NULL || 
      fields_encrypted == NULL || fields_data == NULL)
        return ERR_CREATE_CRED_INV_PARAMS;

    struct Credential *cr = NULL; 
    PIPASS_ERR err = PIPASS_OK;

    err = create_credential(type, fields_count, fields_names_len, fields_names, fields_data_len, 
      fields_encrypted, fields_data, &cr);
    if (err != PIPASS_OK) {
        goto error;
    }

    err = db_append_credential(cr);
    if (err != PIPASS_OK)
        goto error;

    err = dump_database(user_hash);
    if (err != PIPASS_OK)
        goto error;

    err = PIPASS_OK;

error:
    free_credential(cr);
    if (cr != NULL) {
        free(cr);
        cr = NULL;
    }

    return err;
}

PIPASS_ERR get_credentials(uint8_t *user_hash, uint8_t *field_name, uint16_t field_name_len, uint8_t *field_value,
  uint16_t field_value_len, struct Credential **cr, uint16_t *cr_len) {
    if (!FL_LOGGED_IN)
        return ERR_NOT_LOGGED_IN;

    if (!FL_DB_INITIALIZED)
        return ERR_DB_NOT_INITIALIZED;

    if (field_name == NULL || !field_name_len || field_value == NULL || !field_value_len)
        return ERR_GET_CRED_INV_PARAMS;

    if (*cr != NULL)
        return ERR_DB_MEM_LEAK;

    PIPASS_ERR err;
    struct Credential *credentials = NULL; 
    uint32_t cred_count = 0;

    *cr_len = 0;

    err = db_get_credentials(&credentials, &cred_count);
    if (err != PIPASS_OK)
        goto error;

    for (int32_t i = 0; i < cred_count; ++i) {
        uint8_t found = 0;

        for (int32_t j = 0; j < credentials[i].fields_count; ++j) {
            if (credentials[i].fields_names_len[j] == field_name_len && !credentials[i].fields_encrypted[j] && 
              credentials[i].fields_data_len[j] == field_value_len && 
              memcmp(credentials[i].fields_data[j].data_plain, field_value, field_value_len) == 0 &&
              memcmp(credentials[i].fields_names[j], field_name, field_name_len) == 0) {
                  found = 1;
                  break;
            }
        }

        if (found) {
            *cr = realloc(*cr, (*cr_len + 1) * sizeof(struct Credential));
            zero_credential(&((*cr)[*cr_len]));

            err = decrypt_credential(&(credentials[i]), &((*cr)[*cr_len]));
            if (err != PIPASS_OK)
                goto error;

            (*cr_len)++;
        }
    }

    return PIPASS_OK;

error:

    return err;
}

PIPASS_ERR get_credential_names(uint8_t ***cr_names, uint16_t *cr_names_count) {
    if (!FL_LOGGED_IN)
        return ERR_NOT_LOGGED_IN;

    if (!FL_DB_INITIALIZED)
        return ERR_DB_NOT_INITIALIZED;

    if (*cr_names != NULL)
        return ERR_DB_MEM_LEAK;

    PIPASS_ERR err;
    uint32_t cred_count = 0;

    *cr_names_count = 0;
    struct Credential *credentials = NULL; 

    err = db_get_credentials(&credentials, &cred_count);
    if (err != PIPASS_OK)
        goto error;

    for (int32_t i = 0; i < cred_count; ++i) {
        for (int32_t j = 0; j < credentials[i].fields_count; ++j) {
            if (credentials[i].fields_names_len[j] == strlen("name") && !credentials[i].fields_encrypted[j] && 
              memcmp(credentials[i].fields_names[j], "name", strlen("name")) == 0) {

                *cr_names = realloc(*cr_names, (*cr_names_count + 1) * sizeof(uint8_t *));
                (*cr_names)[*cr_names_count] = calloc(credentials[i].fields_data_len[j], sizeof(uint8_t));
                memcpy((*cr_names)[*cr_names_count], credentials[i].fields_data[j].data_plain, credentials[i].fields_data_len[j]);
                (*cr_names_count)++;

                break;
            }
        }
    }
    
    return PIPASS_OK;

error:

    return err;
}

PIPASS_ERR get_credential_details(uint8_t *name, struct Credential **cr) {
    if (!FL_LOGGED_IN)
        return ERR_NOT_LOGGED_IN;

    if (!FL_DB_INITIALIZED)
        return ERR_DB_NOT_INITIALIZED;

    if (*cr != NULL)
        return ERR_DB_MEM_LEAK;

    if (name == NULL)
        return ERR_DB_MEM_LEAK;

    PIPASS_ERR err;
    uint32_t cred_count = 0;

    struct Credential *credentials = NULL; 

    err = db_get_credentials(&credentials, &cred_count);
    if (err != PIPASS_OK)
        goto error;

    for (int32_t i = 0; i < cred_count; ++i) {
        for (int32_t j = 0; j < credentials[i].fields_count; ++j) {
            if (credentials[i].fields_names_len[j] == strlen("name") &&
                !credentials[i].fields_encrypted[j] && 
                memcmp(credentials[i].fields_names[j], "name", strlen("name")) == 0 &&
                memcmp(credentials[i].fields_data[j].data_plain, name, credentials[i].fields_data_len[j]) == 0
            ) {
                err = alloc_credential(cr);
                if (err != PIPASS_OK)
                    goto error;
                
                err = copy_credential(credentials[i], *cr);
                if (err != PIPASS_OK)
                    goto error;

                return PIPASS_OK;
            }
        }
    }

    return ERR_NO_CRED_FOUND;

error:

    return err;    
}


PIPASS_ERR get_encrypted_field_value(uint8_t *cred_name, uint8_t *field_name, uint8_t **value) {
    if (!FL_LOGGED_IN)
        return ERR_NOT_LOGGED_IN;

    if (!FL_DB_INITIALIZED)
        return ERR_DB_NOT_INITIALIZED;

    if (*value != NULL)
        return ERR_DB_MEM_LEAK;

    if (cred_name == NULL || field_name == NULL)
        return ERR_DB_MEM_LEAK;
    
    PIPASS_ERR err;
    struct Credential *cr = NULL;
    struct Credential *plain_cr = NULL;

    err = get_credential_details(cred_name, &cr);
    if (err != PIPASS_OK)
        return err;

    err = alloc_credential(&plain_cr);
    if (err != PIPASS_OK)
        return err;

    err = decrypt_credential(cr, plain_cr);
    if (err != PIPASS_OK)
        return err;

    for (uint8_t i = 0; i < plain_cr->fields_count; ++i) {
        if (memcmp(plain_cr->fields_names[i], field_name, plain_cr->fields_names_len[i]) == 0) {
            *value = malloc(plain_cr->fields_data_len[i]);
            memcpy(*value, plain_cr->fields_data[i].data_plain, plain_cr->fields_data_len[i]);
            
            return PIPASS_OK;
        }
    }

    return ERR_FIELD_NOT_FOUND;
}