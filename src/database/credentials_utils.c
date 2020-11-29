#include <credentials.h>
#include <credentials_utils.h>
#include <datablob.h>

PIPASS_ERR copy_credential(struct Credential src, struct Credential *copy) {
    if (copy == NULL)
        return ERR_DB_COPY_CRED_INV_PARAMS;

    PIPASS_ERR err;

    copy->fields_count = src.fields_count;
    err = alloc_credential_arrays(copy);
    if (err != PIPASS_OK)
        goto error;

    for (int32_t i = 0; i < copy->fields_count; ++i) {
        copy->fields_names[i] = calloc(src.fields_names_len[i], sizeof(uint8_t));
        
        if (!src.fields_encrypted[i]) {
            copy->fields_data[i].data_plain = calloc(src.fields_data_len[i], sizeof(uint8_t));
            if (copy->fields_data[i].data_plain == NULL) {
                err = ERR_DB_MEM_ALLOC;
                goto error;
            }
        
        } else {
            err = alloc_datablob(&copy->fields_data[i].data_encryped, src.fields_data_len[i]);
            if (err != PIPASS_OK)
                goto error;
        }
    }

    err = memcpy_credentials(copy, &src);
    if (err != PIPASS_OK)
        goto error;

    return PIPASS_OK;

error:
    free_credential(copy);

    return err;
}

PIPASS_ERR memcpy_credentials(struct Credential *dest, struct Credential *src) {
    if (dest == NULL || src == NULL)
        return ERR_MCPY_CRED_INV_PARAMS;

    PIPASS_ERR err;

    dest->cred_size = src->cred_size;
    dest->type = src->type;
    dest->fields_count = src->fields_count;

    if (src->fields_count == 0)
        return PIPASS_OK;

    if (dest->fields_names_len == NULL)
        return ERR_MCPY_CRED_INV_PARAMS;

    memcpy(dest->fields_names_len, src->fields_names_len, src->fields_count * sizeof(uint16_t));

    if (dest->fields_names == NULL)
        return ERR_MCPY_CRED_INV_PARAMS;

    for (uint32_t i = 0; i < src->fields_count; ++i) {
        if (dest->fields_names[i] == NULL)
            return ERR_MCPY_CRED_INV_PARAMS;

        memcpy(dest->fields_names[i], src->fields_names[i], src->fields_names_len[i]);
    }

    if (dest->fields_data_len == NULL)
        return ERR_MCPY_CRED_INV_PARAMS;

    memcpy(dest->fields_data_len, src->fields_data_len, src->fields_count * sizeof(uint16_t));

    if (dest->fields_encrypted == NULL)
        return ERR_MCPY_CRED_INV_PARAMS;

    memcpy(dest->fields_encrypted, src->fields_encrypted, src->fields_count * sizeof(uint8_t));

    if (dest->fields_data == NULL)
        return ERR_MCPY_CRED_BLOB_INV_PARAMS;

    for (uint32_t i = 0; i < src->fields_count; ++i) {
        if (src->fields_encrypted[i]) {
            err = datablob_memcpy(
                &dest->fields_data[i].data_encryped,
                &src->fields_data[i].data_encryped,
                src->fields_data_len[i]
            );
            if (err != PIPASS_OK)
                return err;
        } else {
            memcpy(
                dest->fields_data[i].data_plain, 
                src->fields_data[i].data_plain,
                src->fields_data_len[i]
            );
        }
    }

    return PIPASS_OK;
} 

