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
   
    err = read_bytes_from_raw(raw_db, read_cursor, db_len, &(blob->iv), IV_SIZE);
    if (err != PIPASS_OK)
        goto error;
    
    err = read_bytes_from_raw(raw_db, read_cursor, db_len, &(blob->mac), MAC_SIZE);
    if (err != PIPASS_OK)
        goto error;

    return PIPASS_OK;

error:
    free_datablob(blob, cipher_len);

    return err;
}

PIPASS_ERR read_credentials_from_raw(uint8_t *raw_db, uint32_t *read_cursor, uint32_t db_len, 
  struct Credential *cred, struct CredentialHeader *cred_headers, uint32_t cred_len) {

    if (raw_db || cred == NULL || cred_headers == NULL)
        return ERR_DB_READ_FIELD_INV_PARAMS;

    PIPASS_ERR err;

    for (int32_t i = 0; i < cred_len; ++i) {
        struct CredentialHeader *crh = &(cred_headers[i]);

        err = read_db_field_32b_from_raw(raw_db, read_cursor, db_len, &(crh->cred_len));
        if (err != PIPASS_OK)
            return err;

        err = read_db_field_16b_from_raw(raw_db, read_cursor, db_len, &(crh->name_len));
        if (err != PIPASS_OK)
            return err;

        err = read_db_field_16b_from_raw(raw_db, read_cursor, db_len, &(crh->username_len));
        if (err != PIPASS_OK)
            return err;

        err = read_db_field_16b_from_raw(raw_db, read_cursor, db_len, &(crh->passw_len));
        if (err != PIPASS_OK)
            return err;

        err = read_db_field_16b_from_raw(raw_db, read_cursor, db_len, &(crh->url_len));
        if (err != PIPASS_OK)
            return err;

        err = read_db_field_16b_from_raw(raw_db, read_cursor, db_len, &(crh->additional_len));
        if (err != PIPASS_OK)
            return err;
    }

    if (*read_cursor > db_len)
        return ERR_DB_READ_FIELD_TOO_MUCH;

    for (int32_t i = 0; i < cred_len; ++i) {
        struct Credential *cr = &(cred[i]);
        
        if (cred_headers[i].name_len) {
            err = read_bytes_from_raw(raw_db, read_cursor, db_len, &(cr->name), cred_headers[i].name_len);
            if (err != PIPASS_OK)
                goto error;
        }

        err = read_datablob_from_raw(raw_db, read_cursor, db_len, &(cr->username), cred_headers[i].username_len);
        if (err != PIPASS_OK)
            goto error;

        err = read_datablob_from_raw(raw_db, read_cursor, db_len, &(cr->password), cred_headers[i].passw_len);
        if (err != PIPASS_OK)
            goto error;

        if (cred_headers[i].name_len) {
            err = read_bytes_from_raw(raw_db, read_cursor, db_len, &(cr->url), cred_headers[i].url_len);
            if (err != PIPASS_OK)
                goto error;
        }

        if (cred_headers[i].name_len) {
            err = read_bytes_from_raw(raw_db, read_cursor, db_len, &(cr->additional), cred_headers[i].additional_len);
            if (err != PIPASS_OK)
                goto error;
        }
    }

    return PIPASS_OK;

error:
    for (int i = 0; i < cred_len; ++i)
        free_credential(&(cred[i]), &(cred_headers[i]));    

    return err;
}