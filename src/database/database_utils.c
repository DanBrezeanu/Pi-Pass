#include <datablob.h>
#include <crypto_utils.h>
#include <database_utils.h>
#include <credentials.h>

PIPASS_ERR read_db_field_32b_from_raw(uint8_t *raw_db, uint32_t *read_cursor, uint32_t db_len, uint32_t *db_field) {
    if (raw_db == NULL || read_cursor == NULL || db_field == NULL)
        return ERR_DB_READ_FIELD_INV_PARAMS;

    if (*read_cursor > db_len)
        return ERR_DB_READ_FIELD_TOO_MUCH;

    uint32_t *tmp_uint32t = (uint32_t *)bin_to_var(raw_db + *read_cursor, sizeof(uint32_t));
    if (tmp_uint32t == NULL)
        return ERR_DB_MEM_ALLOC;

    *read_cursor += sizeof(uint32_t);

    *db_field = *tmp_uint32t;

    free(tmp_uint32t);

    return PIPASS_OK;
}

PIPASS_ERR read_db_field_16b_from_raw(uint8_t *raw_db, uint32_t *read_cursor, uint32_t db_len, uint16_t *db_field) {
    if (raw_db == NULL || read_cursor == NULL || db_field == NULL)
        return ERR_DB_READ_FIELD_INV_PARAMS;

    if (*read_cursor > db_len)
        return ERR_DB_READ_FIELD_TOO_MUCH;

    uint16_t *tmp_uint16t = (uint16_t *)bin_to_var(raw_db + *read_cursor, sizeof(uint16_t));
    if (tmp_uint16t == NULL)
        return ERR_DB_MEM_ALLOC;

    *read_cursor += sizeof(uint16_t);

    *db_field = *tmp_uint16t;

    free(tmp_uint16t);

    return PIPASS_OK;
}

PIPASS_ERR read_bytes_from_raw(uint8_t *raw_db, uint32_t *read_cursor, uint32_t db_len, uint8_t **bytes, uint32_t bytes_len) {
     if (raw_db == NULL || read_cursor == NULL || !bytes_len)
        return ERR_DB_READ_FIELD_INV_PARAMS;

    if (*bytes != NULL)
        return ERR_DB_READ_FIELD_MEM_LEAK;
    
    if (*read_cursor + bytes_len > db_len)
        return ERR_DB_READ_FIELD_TOO_MUCH;

    *bytes = malloc(bytes_len);
    if (*bytes == NULL)
        return ERR_DB_MEM_ALLOC;

    memcpy(*bytes, raw_db + *read_cursor, bytes_len);
    *read_cursor += bytes_len;

    return PIPASS_OK;
}

PIPASS_ERR read_datablob_from_raw(uint8_t *raw_db, uint32_t *read_cursor, uint32_t db_len, struct DataBlob *blob, uint32_t cipher_len) {
    if (raw_db == NULL || read_cursor == NULL || blob == NULL)
        return ERR_DB_READ_FIELD_INV_PARAMS;

    if (blob->ciphertext != NULL || blob->iv != NULL || blob->mac != NULL)
        return ERR_DB_READ_FIELD_MEM_LEAK;

    PIPASS_ERR err;

    err = read_bytes_from_raw(raw_db, read_cursor, db_len, &(blob->ciphertext), cipher_len);
    if (err != PIPASS_OK)
        goto error;
   
    err = read_bytes_from_raw(raw_db, read_cursor, db_len, &(blob->mac), MAC_SIZE);
    if (err != PIPASS_OK)
        goto error;
        
    err = read_bytes_from_raw(raw_db, read_cursor, db_len, &(blob->iv), IV_SIZE);
    if (err != PIPASS_OK)
        goto error;
    

    return PIPASS_OK;

error:
    free_datablob(blob, cipher_len);

    return err;
}

PIPASS_ERR read_credentials_from_raw(uint8_t *raw_db, uint32_t *read_cursor, uint32_t db_len, 
  struct Credential *cred, uint32_t cred_count) {

    if (raw_db == NULL || cred == NULL)
        return ERR_DB_READ_FIELD_INV_PARAMS;

    PIPASS_ERR err;

    for (int32_t i = 0; i < cred_count; ++i) {
        struct Credential *cr = &(cred[i]);

        err = read_db_field_32b_from_raw(raw_db, read_cursor, db_len, &(cr->cred_size));
        if (err != PIPASS_OK)
            return err;

        cr->type = raw_db[(*read_cursor)++];

        err = read_db_field_16b_from_raw(raw_db, read_cursor, db_len, &(cr->fields_count));
        if (err != PIPASS_OK)
            return err;

        cr->fields_names_len = calloc(cr->fields_count, sizeof(uint16_t));
        if (cr->fields_names_len == NULL) {
            err = ERR_DB_MEM_ALLOC;
            goto error;
        }

        for (int32_t i = 0; i < cr->fields_count; ++i) {
            err = read_db_field_16b_from_raw(raw_db, read_cursor, db_len, &(cr->fields_names_len[i]));
            if (err != PIPASS_OK)
                return err;
        }

        cr->fields_names = calloc(cr->fields_count, sizeof(uint8_t *));
        if (cr->fields_names == NULL) {
            err = ERR_DB_MEM_ALLOC;
            goto error;
        }

        for (int32_t i = 0; i < cr->fields_count; ++i) {
            err = read_bytes_from_raw(raw_db, read_cursor, db_len, &(cr->fields_names[i]), cr->fields_names_len[i]);
            if (err != PIPASS_OK)
                return err;
        }

        cr->fields_data_len = calloc(cr->fields_count, sizeof(uint16_t));
        if (cr->fields_data_len == NULL) {
            err = ERR_DB_MEM_ALLOC;
            goto error;
        }

        for (int32_t i = 0; i < cr->fields_count; ++i) {
            err = read_db_field_16b_from_raw(raw_db, read_cursor, db_len, &(cr->fields_data_len[i]));
            if (err != PIPASS_OK)
                return err;
        }

        cr->fields_encrypted = calloc(cr->fields_count, sizeof(uint8_t));
        if (cr->fields_encrypted == NULL) {
            err = ERR_DB_MEM_ALLOC;
            goto error;
        }

        for (int32_t i = 0; i < cr->fields_count; ++i) {
            cr->fields_encrypted[i] = raw_db[(*read_cursor)++];
        }

        cr->fields_data = calloc(cr->fields_count, sizeof(union CredentialFieldData));
        if (cr->fields_data == NULL) {
            err = ERR_DB_MEM_ALLOC;
            goto error;
        }

        for (int32_t i = 0; i < cr->fields_count; ++i) {
            if (cr->fields_encrypted[i]) {
                err = read_datablob_from_raw(raw_db, read_cursor, db_len, &(cr->fields_data[i].data_encryped), cr->fields_data_len[i]);
            } else {
                err = read_bytes_from_raw(raw_db, read_cursor, db_len, &(cr->fields_data[i].data_plain), cr->fields_data_len[i]);
            }

            if (err != PIPASS_OK)
                goto error;
        }
    }

    return PIPASS_OK;

error:
    for (int i = 0; i < cred_count; ++i)
        free_credential(&(cred[i]));    

    return err;
}