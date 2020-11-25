#include <credentials.h>
#include <crypto.h>
#include <storage.h>
#include <authentication.h>

PIPASS_ERR alloc_credential(struct Credential **cr) {
    if (*cr != NULL)
        return ERR_MEM_LEAK;

    PIPASS_ERR err;

    *cr = calloc(1, sizeof(struct Credential));
    if (*cr == NULL)
        return ERR_DB_MEM_ALLOC;

    return PIPASS_OK;

error:
    if (*cr != NULL)
        free(*cr);

    return err;
}

PIPASS_ERR alloc_credential_arrays(struct Credential *cr) {
    if (cr == NULL)
        return ERR_ALLOC_CRED_ARR_INV_PARAMS;
    
    if (cr->fields_count == 0)
        return PIPASS_OK;

    cr->fields_names_len = calloc(cr->fields_count, sizeof(uint16_t));
    cr->fields_names     = calloc(cr->fields_count, sizeof(uint8_t *));
    cr->fields_data_len  = calloc(cr->fields_count, sizeof(uint16_t));
    cr->fields_encrypted = calloc(cr->fields_count, sizeof(uint8_t));
    cr->fields_data      = calloc(cr->fields_count, sizeof(union CredentialFieldData));

    return PIPASS_OK;
}

PIPASS_ERR populate_plaintext_field(struct Credential *cr, uint8_t *field_name, uint8_t *data,
  int32_t data_len) {
    if (!FL_LOGGED_IN)
        return ERR_NOT_LOGGED_IN;

    if (!FL_DB_INITIALIZED)
        return ERR_DB_NOT_INITIALIZED;

    if (cr == NULL || field_name == NULL || data == NULL || !data_len) 
        return ERR_POPULATE_FIELD_INV_PARAMS;

    if (data_len > CREDENTIALS_FIELD_LIMIT)
        return ERR_FIELD_LIMIT_EXCEEDED;

    PIPASS_ERR err = sanity_check_buffer(data, data_len);
    if (err != PIPASS_OK)
        return err;

    uint8_t **field = NULL;
    uint16_t *field_len = 0;

   for (int32_t i = 0; i < cr->fields_count; ++i) {
        if (strncmp(field_name, cr->fields_names[i], cr->fields_names_len[i]) == 0) {
            if (cr->fields_encrypted[i]) {
                err = ERR_FIELD_IS_ENCRYPTED;
                goto error;
            }

            field = &(cr->fields_data[i].data_plain);
            field_len = &(cr->fields_data_len[i]);
            break;
        }
    }

    if (*field != NULL)
        return ERR_DB_MEM_LEAK;

    *field = malloc(data_len + 1);
    if (*field == NULL)
        return ERR_DB_MEM_ALLOC;

    memcpy(*field, data, data_len);
    (*field)[data_len] = 0;

    *field_len = data_len;

    err = recalculate_cred_len(cr);
    if (err != PIPASS_OK) {
       goto error;
    }
    return PIPASS_OK;

error:
    erase_buffer(field, data_len);
    return err;

}

PIPASS_ERR populate_encrypted_field(struct Credential *cr, uint8_t *field_name, uint8_t *data,
  int32_t data_len) {
    
    if (!FL_LOGGED_IN)
        return ERR_NOT_LOGGED_IN;

    if (!FL_DB_INITIALIZED)
        return ERR_DB_NOT_INITIALIZED;

    if (OTK == NULL)
        return ERR_OTK_NOT_INITIALIZED;
    
    if (DEK_BLOB == NULL)
        return ERR_DEK_BLOB_NOT_INIT;

    if (cr == NULL || field_name == NULL || !data_len)
        return ERR_POPULATE_FIELD_INV_PARAMS;

    if (data_len > CREDENTIALS_FIELD_LIMIT)
        return ERR_FIELD_LIMIT_EXCEEDED;

    PIPASS_ERR err = sanity_check_buffer(data, data_len);
    if (err != PIPASS_OK)
        return err;

    struct DataBlob *field = NULL;
    uint16_t *field_len = 0;

    for (int32_t i = 0; i < cr->fields_count; ++i) {
        if (strncmp(field_name, cr->fields_names[i], cr->fields_names_len[i]) == 0) {
            if (!cr->fields_encrypted[i]) {
                err = ERR_FIELD_NOT_ENCRYPTED;
                goto error;
            }

            field = &(cr->fields_data[i].data_encryped);
            field_len = &(cr->fields_data_len[i]);
            break;
        }
    }

    if (field == NULL) {
        err = ERR_FIELD_NOT_FOUND;
        goto error;
    }

    if (field->ciphertext != NULL || field->iv != NULL || field->mac != NULL)
        return ERR_DB_MEM_LEAK;

    err = encrypt_field_with_DEK(data, data_len, field, field_len);
    if (err != PIPASS_OK)
        goto error;

    err = recalculate_cred_len(cr);
    if (err != PIPASS_OK)
        goto error;

    return PIPASS_OK;

error:
    free_datablob(field, *field_len);

    return err;
}

PIPASS_ERR add_field_credential(struct Credential *cr, uint8_t *field_name, uint16_t field_name_len,
  uint8_t *field_data, uint16_t field_data_len, uint8_t field_is_encrypted) {
    
    if (!FL_LOGGED_IN)
        return ERR_NOT_LOGGED_IN;

    if (!FL_DB_INITIALIZED)
        return ERR_DB_NOT_INITIALIZED;

    if (OTK == NULL)
        return ERR_OTK_NOT_INITIALIZED;

    if (DEK_BLOB == NULL)
        return ERR_DEK_BLOB_NOT_INIT;

    if (cr == NULL || field_name == NULL || !field_name_len || field_data == NULL ||
      !field_data_len)
    return ERR_POPULATE_CRED_INV_PARAMS;

    PIPASS_ERR err = PIPASS_OK;

    for (int32_t i = 0; i < cr->fields_count; ++i) {
        if (strncmp(field_name, cr->fields_names[i], cr->fields_names_len[i]) == 0) {
            err = ERR_FIELD_ALREADY_EXISTS;
            goto error;
        }
    }

    cr->fields_names_len = realloc(cr->fields_names_len, (cr->fields_count + 1) * sizeof(uint16_t));
    cr->fields_names = realloc(cr->fields_names, (cr->fields_count + 1) * sizeof(uint8_t *));
    cr->fields_data_len = realloc(cr->fields_data_len, (cr->fields_count + 1) * sizeof(uint16_t));
    cr->fields_encrypted = realloc(cr->fields_encrypted, (cr->fields_count + 1) * sizeof(uint8_t));
    cr->fields_data = realloc(cr->fields_data, (cr->fields_count + 1) * sizeof(union CredentialFieldData));

    memset(&cr->fields_data[cr->fields_count], 0, sizeof(union CredentialFieldData));
    cr->fields_names[cr->fields_count] = NULL;

    cr->fields_names_len[cr->fields_count] = field_name_len;
    
    cr->fields_names[cr->fields_count] = malloc(field_name_len);
    memcpy(cr->fields_names[cr->fields_count], field_name, field_name_len);

    cr->fields_encrypted[cr->fields_count] = field_is_encrypted;

    cr->fields_count++;

    if (field_is_encrypted) {
        err = populate_encrypted_field(cr, field_name, field_data, field_data_len);
    } else {
        err = populate_plaintext_field(cr, field_name, field_data, field_data_len);
    }

    if (err != PIPASS_OK) {
        cr->fields_count--;
        goto error;
    }

    return PIPASS_OK;

error:
    erase_buffer(&cr->fields_names[cr->fields_count], field_name_len);

    return err;
 }

PIPASS_ERR recalculate_cred_len(struct Credential *cr) {
    if (cr == NULL)
        return ERR_RECALC_HEADER_INV_PARAMS;

    cr->cred_size = sizeof(cr->type) + sizeof(cr->fields_count);

    for (int32_t i = 0; i < cr->fields_count; ++i) {
        cr->cred_size += sizeof(cr->fields_names_len[i]) + cr->fields_names_len[i];
        cr->cred_size += sizeof(cr->fields_data_len[i]) + cr->fields_data_len[i] +
                         sizeof(cr->fields_encrypted[i]) + 
                         ((cr->fields_encrypted[i]) ? (IV_SIZE + MAC_SIZE) : 0);
    }

    return PIPASS_OK;
}

PIPASS_ERR zero_credential(struct Credential *cr) {
    if (cr == NULL)
        return ERR_ZERO_CRED_INV_PARAMS;

    cr->cred_size = cr->type = cr->fields_count = 0;

    cr->fields_names_len = NULL;
    cr->fields_names = NULL;
    cr->fields_data_len = NULL;
    cr->fields_encrypted = NULL;
    cr->fields_data = NULL;

    return PIPASS_OK;
}

void free_credential(struct Credential *cr) {
    if (cr == NULL)
        return;

    if (cr->fields_data != NULL) {
        for (int32_t i = 0; i < cr->fields_count; ++i) {
            if (!cr->fields_encrypted[i]) {
                if (cr->fields_data[i].data_plain != NULL)
                    erase_buffer(&cr->fields_data[i].data_plain, cr->fields_data_len[i]);
            } else {
                free_datablob(&cr->fields_data[i].data_encryped, cr->fields_data_len[i]);
            }
        }
    }

    if (cr->fields_names != NULL) {
        for (int32_t i = 0; i < cr->fields_count; ++i)
            erase_buffer(&cr->fields_names[i], cr->fields_names_len[i]);
    
        free(cr->fields_names);
        cr->fields_names = NULL;
    }

    erase_buffer(&cr->fields_encrypted, cr->fields_count);

    if (cr->fields_names_len != NULL) {
        free(cr->fields_names_len);
        cr->fields_names_len = NULL;
    }

    if (cr->fields_data_len != NULL) {
        free(cr->fields_data_len);
        cr->fields_data_len = NULL;
    }
}

PIPASS_ERR append_to_credential_array(struct Credential **cr, int32_t *cr_len, struct Credential *to_add) {
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
        zero_credential(&((*cr)[*cr_len]));
    }

    struct Credential *cred = &((*cr)[*cr_len]);

    err = copy_credential(*to_add, cred);
    if (err != PIPASS_OK)
        return err;

    (*cr_len)++;

    return PIPASS_OK;
}

PIPASS_ERR create_credential(enum CredentialType type, uint16_t fields_count, uint16_t *fields_names_len, 
  uint8_t **fields_names, uint16_t *fields_data_len, uint8_t *fields_encrypted, uint8_t **fields_data,
  struct Credential **cr) {
    if (fields_names_len == NULL || fields_names == NULL || fields_data_len == NULL || 
      fields_encrypted == NULL || fields_data == NULL)
        return ERR_CREATE_CRED_INV_PARAMS;

    if (*cr != NULL)
        return ERR_DB_MEM_LEAK;

    PIPASS_ERR err;

    err = alloc_credential(cr);
    if (err != PIPASS_OK)
        return err;

    (*cr)->type = type;

    for (int32_t i = 0; i < fields_count; ++i) {
        err = add_field_credential(*cr, fields_names[i], fields_names_len[i], fields_data[i], 
      fields_data_len[i], fields_encrypted[i]);
        if (err != PIPASS_OK)
            goto error;
    }

    return PIPASS_OK;

error:
    free_credential(*cr);
    *cr = NULL;

    return err;
}

PIPASS_ERR credential_raw(struct Credential *cr, uint8_t **raw_cr, uint32_t *raw_cr_len) {
    if (cr == NULL)
        return ERR_RAW_CR_INV_PARAMS;

    if (*raw_cr != NULL)
        return ERR_DB_MEM_LEAK;

    PIPASS_ERR err;
    int32_t cursor = 0;
    uint8_t *cred_size_bin = NULL;
    uint8_t *type_bin = NULL;
    uint8_t *fields_count_bin = NULL;
    uint8_t *field_name_len_bin = NULL;
    uint8_t *field_data_len_bin = NULL;

    *raw_cr = malloc(cr->cred_size);
    if (*raw_cr == NULL)
        return ERR_DB_MEM_ALLOC;

    cred_size_bin = var_to_bin(&cr->cred_size, sizeof(cr->cred_size));
    if (cred_size_bin == NULL) {
        err = ERR_DB_MEM_ALLOC;
        goto error;
    }
    append_to_str(*raw_cr, &cursor, cred_size_bin, sizeof(cr->cred_size));

    uint8_t type_int = (uint8_t) cr->type; 
    type_bin = var_to_bin(&type_int, sizeof(type_int));
    if (type_bin == NULL) {
        err = ERR_DB_MEM_ALLOC;
        goto error;
    }
    append_to_str(*raw_cr, &cursor, type_bin, sizeof(type_int));

    fields_count_bin = var_to_bin(&cr->fields_count, sizeof(cr->fields_count));
    if (fields_count_bin == NULL) {
        err = ERR_DB_MEM_ALLOC;
        goto error;
    }
    append_to_str(*raw_cr, &cursor, fields_count_bin, sizeof(cr->fields_count));

    for (int32_t i = 0; i < cr->fields_count; ++i) {
        field_name_len_bin = var_to_bin(&cr->fields_names_len[i], sizeof(cr->fields_names_len[i]));
        if (field_name_len_bin == NULL) {
            err = ERR_DB_MEM_ALLOC;
            goto error;
        }
        append_to_str(*raw_cr, &cursor, field_name_len_bin, sizeof(cr->fields_names_len[i]));

        erase_buffer(&field_name_len_bin, sizeof(cr->fields_names_len[i]));
    }

    for (int32_t i = 0; i < cr->fields_count; ++i) {
        append_to_str(*raw_cr, &cursor, cr->fields_names[i], cr->fields_names_len[i]);
    }

    for (int32_t i = 0; i < cr->fields_count; ++i) {
        field_data_len_bin = var_to_bin(&cr->fields_data_len[i], sizeof(cr->fields_data_len[i]));
        if (field_data_len_bin == NULL) {
            err = ERR_DB_MEM_ALLOC;
            goto error;
        }
        append_to_str(*raw_cr, &cursor, field_data_len_bin, sizeof(cr->fields_names_len[i]));

        erase_buffer(&field_data_len_bin, sizeof(cr->fields_data_len[i]));
    }

    append_to_str(*raw_cr, &cursor, cr->fields_encrypted, cr->fields_count);
    
    for (int32_t i = 0; i < cr->fields_count; ++i) {
        if (cr->fields_data_len[i] == 0)
            continue;

        if (cr->fields_encrypted[i]) {
            append_to_str(*raw_cr, &cursor, cr->fields_data[i].data_encryped.ciphertext, cr->fields_data_len[i]);
            append_to_str(*raw_cr, &cursor, cr->fields_data[i].data_encryped.mac, MAC_SIZE);
            append_to_str(*raw_cr, &cursor, cr->fields_data[i].data_encryped.iv, IV_SIZE);
        } else {
            append_to_str(*raw_cr, &cursor, cr->fields_data[i].data_plain, cr->fields_data_len[i]);
        }
    }

    *raw_cr_len = cursor;

    err = PIPASS_OK;
    goto cleanup;

error:
    erase_buffer(raw_cr, cursor);
cleanup:
    erase_buffer(&cred_size_bin, sizeof(cr->cred_size));
    erase_buffer(&type_bin, sizeof(uint8_t));
    erase_buffer(&fields_count_bin, sizeof(cr->fields_count));
    erase_buffer(&field_name_len_bin, sizeof(uint16_t));
    erase_buffer(&field_data_len_bin, sizeof(uint16_t));

    return err;
}