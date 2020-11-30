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