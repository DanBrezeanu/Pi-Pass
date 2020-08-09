#include <credentials.h>

DB_ERROR populate_field(struct Credential *cr, uint8_t *data, int32_t data_len, enum CredentialField field) {
    if (cr == NULL || data == NULL || data_len == 0) 
        return ERR_POPULATE_FIELD_INV_PARAMS;

    if (data_len > CREDENTIALS_FIELD_LIMIT)
        return ERR_FIELD_LIMIT_EXCEEDED;

    DB_ERROR err = sanity_check_buffer(data, data_len);
    if (err != CRYPTO_OK)
        return err;

    uint8_t *field_buffer = NULL;

    switch (field) {
    case NAME:
        field_buffer = cr->name;
        break;
    case USERNAME:
        field_buffer = cr->username;
        break;
    case PASSW:
        field_buffer = cr->passw;
        break;
    case URL:
        field_buffer = cr->url;
        break;
    case ADDITIONAL:
        field_buffer = cr->addtional;
        break;
    default:
        return ERR_INVALID_FIELD;
    }

    if (field_buffer != NULL)
        return ERR_DB_MEM_LEAK;

    field_buffer = malloc(data_len + 1);
    if (field_buffer == NULL)
        return ERR_DB_MEM_ALLOC;

    memcpy(field_buffer, data, data_len + 1);

    return DB_OK;
}