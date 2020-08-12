#include <actions.h>
#include <database.h>
#include <database.h>
#include <credentials.h>

STORAGE_ERR register_new_credential(struct Database *db, uint8_t *user_hash, uint8_t *master_pass, uint8_t *name, int32_t name_len,
 uint8_t *username, int32_t username_len, uint8_t *passw, int32_t passw_len, uint8_t *url, int32_t url_len,
 uint8_t *additional, int32_t additional_len) {

    if (db == NULL || master_pass == NULL || username == NULL || passw == NULL ||
      user_hash == NULL || !username_len || !passw_len)
        return ERR_REG_NEW_CRED_INV_PARAMS;

    /* TODO: check hash and pass */

    struct Credential *cr = NULL; 
    struct CredentialHeader *crh = NULL; 

    DB_ERROR err = new_credential(&cr, &crh);
    if (err != DB_OK)
        goto error;
    
    if (name != NULL) {
        err = populate_plaintext_field(cr, crh, name, name_len, NAME);
        if (err != STORAGE_OK)
            goto error;
    }

    err = populate_encrypted_field(db, cr, crh, username, username_len, USERNAME, master_pass);
    if (err != STORAGE_OK)
        goto error;
    
    err = populate_encrypted_field(db, cr, crh, passw, passw_len, PASSW, master_pass);
    if (err != STORAGE_OK)
        goto error;

    if (url != NULL) {
        err = populate_plaintext_field(cr, crh, url, url_len, URL);
        if (err != STORAGE_OK)
            goto error;
    }

    if (additional != NULL) {
        err = populate_plaintext_field(cr, crh, additional, additional_len, ADDITIONAL);
        if (err != STORAGE_OK)
            goto error;
    }

    err = append_db_credential(db, cr, crh);
    if (err != DB_OK)
        goto error;

    err = dump_database(db, user_hash);
    if (err != DB_OK)
        goto error;

error:
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