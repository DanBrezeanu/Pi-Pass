#include <actions.h>
#include <database.h>
#include <database.h>
#include <credentials.h>
#include <crypto.h>
#include <storage.h>
#include <authentication.h>

STORAGE_ERR register_new_credential(struct Database *db, uint8_t *user_hash, uint8_t *master_pass, uint8_t *name, int32_t name_len,
 uint8_t *username, int32_t username_len, uint8_t *passw, int32_t passw_len, uint8_t *url, int32_t url_len,
 uint8_t *additional, int32_t additional_len) {

    if (db == NULL || master_pass == NULL || username == NULL || passw == NULL ||
      user_hash == NULL || !username_len || !passw_len)
        return ERR_REG_NEW_CRED_INV_PARAMS;

    struct Credential *cr = NULL; 
    struct CredentialHeader *crh = NULL; 
    STORAGE_ERR err = STORAGE_OK;

    err = verify_user_directory(user_hash);
    if (err != STORAGE_OK)
        return err;

    err = verify_master_password(user_hash, master_pass);
    if (err != STORAGE_OK)
        return err;

    err = new_credential(&cr, &crh);
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

STORAGE_ERR get_credential_by_name(struct Database *db, uint8_t *user_hash, uint8_t *master_pass, uint8_t *name, int16_t name_len, 
  struct PlainTextCredential **ptcr, struct CredentialHeader **ptcrh) {
    if (db == NULL || user_hash == NULL || master_pass == NULL || name == NULL || !name_len)
        return ERR_GET_CRED_INV_PARAMS;

    if (*ptcr != NULL || *ptcrh != NULL)
        return ERR_GET_CRED_MEM_LEAK;

    struct Credential *cr = NULL; 
    struct CredentialHeader *crh = NULL;
    STORAGE_ERR err = CRYPTO_OK;

    err = verify_user_directory(user_hash);
    if (err != STORAGE_OK)
        return err;

    err = verify_master_password(user_hash, master_pass);
    if (err != STORAGE_OK)
        return err;

    for (int i = 0; i < db->cred_len; ++i) {
        if (db->cred_headers[i].name_len == name_len && 
          memcmp(db->cred[i].name, name, db->cred_headers[i].name_len) == 0) {
        
            cr = &(db->cred[i]);
            crh = &(db->cred_headers[i]);
            break;
        }
    }

    if (cr == NULL || crh == NULL) {
        err = ERR_GET_CRED_NOT_FOUND;
        goto error;
    }

    *ptcr = calloc(1, sizeof(struct PlainTextCredential));
    *ptcrh = calloc(1, sizeof(struct CredentialHeader));

    err = decrypt_credential_field(db, &((*ptcr)->username), &((*ptcrh)->username_len), 
      master_pass, cr->username, cr->username_iv, cr->username_mac, crh->username_len);
    if (err != CRYPTO_OK)
        goto error;

    err = decrypt_credential_field(db, &((*ptcr)->passw), &((*ptcrh)->passw_len), 
      master_pass, cr->passw, cr->passw_iv, cr->passw_mac, crh->passw_len);
    if (err != CRYPTO_OK)
        goto error;

    if (crh->name_len > 0 && cr->name != NULL) {
        (*ptcr)->name = malloc(crh->name_len);
        if ((*ptcr)->name == NULL) {
            err = ERR_GET_CRED_MEM_ALLOC;
            goto error;
        }

        memcpy((*ptcr)->name, cr->name, crh->name_len);
        (*ptcrh)->name_len = crh->name_len;
        (*ptcrh)->cred_len += crh->name_len;
    }

    if (crh->url_len > 0 && cr->url != NULL) {
        (*ptcr)->url = malloc(crh->url_len);
        if ((*ptcr)->url == NULL) {
            err = ERR_GET_CRED_MEM_ALLOC;
            goto error;
        }

        memcpy((*ptcr)->url, cr->url, crh->url_len);
        (*ptcrh)->url_len = crh->url_len;
        (*ptcrh)->cred_len += crh->url_len;
    }

    if (crh->additional_len > 0 && cr->additional != NULL) {
        (*ptcr)->additional = malloc(crh->additional_len);
        if ((*ptcr)->additional == NULL) {
            err = ERR_GET_CRED_MEM_ALLOC;
            goto error;
        }

        memcpy((*ptcr)->additional, cr->additional, crh->additional_len);
        (*ptcrh)->additional_len = crh->additional_len;
        (*ptcrh)->cred_len += crh->additional_len;
    }

    return STORAGE_OK;
    

error:
    if (*ptcr != NULL ) {
        erase_buffer(&((*ptcr)->name), crh->name_len);
        erase_buffer(&((*ptcr)->passw), crh->passw_len);
        erase_buffer(&((*ptcr)->username), crh->username_len);
        erase_buffer(&((*ptcr)->url), crh->url_len);
        erase_buffer(&((*ptcr)->additional), crh->additional_len);
        free(*ptcr);
    }

    if (*ptcrh != NULL) {
        free(*ptcrh);
    }

    return err;

}