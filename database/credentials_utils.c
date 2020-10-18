#include <credentials.h>
#include <credentials_utils.h>
#include <datablob.h>

PIPASS_ERR memcpy_credential_blobs(struct Credential *dest, struct Credential *src, struct CredentialHeader *crh) {
    if (dest == NULL || src == NULL || datablob_has_null_fields(dest->username) ||
      datablob_has_null_fields(dest->password) || datablob_has_null_fields(src->username) ||
      datablob_has_null_fields(src->password))
        return ERR_MCPY_CRED_BLOB_INV_PARAMS;

    PIPASS_ERR err;

    err = datablob_memcpy(&dest->username, &src->username, crh->username_len);
    if (err != PIPASS_OK)
      return err;

    err = datablob_memcpy(&dest->password, &src->password, crh->passw_len);
    if (err != PIPASS_OK)
        return err;

    return PIPASS_OK;
}

PIPASS_ERR memcpy_credentials(struct Credential *dest, struct Credential *src, struct CredentialHeader *crh) {
    if (dest == NULL || src == NULL || datablob_has_null_fields(dest->username) ||
      datablob_has_null_fields(dest->password) || datablob_has_null_fields(src->username) ||
      datablob_has_null_fields(src->password))
        return ERR_MCPY_CRED_INV_PARAMS;

    PIPASS_ERR err;

    if (src->name != NULL) {
        if (dest->name == NULL)
            return ERR_MCPY_CRED_INV_PARAMS;
        memcpy(dest->name, src->name, crh->name_len);
    }

    if (src->url != NULL) {
        if (dest->name == NULL)
            return ERR_MCPY_CRED_INV_PARAMS;
        memcpy(dest->name, src->name, crh->name_len);
    }

    if (src->additional != NULL) {
        if (dest->name == NULL)
            return ERR_MCPY_CRED_INV_PARAMS;
        memcpy(dest->name, src->name, crh->name_len);
    }

    err = memcpy_credential_blobs(dest, src, crh);
    if (err != PIPASS_OK)
        return err;


    return PIPASS_OK;
} 

