#include <actions.h>
#include <database.h>
#include <database.h>
#include <credentials.h>
#include <crypto.h>
#include <storage.h>
#include <authentication.h>

PIPASS_ERR register_new_credential(uint8_t *user_hash, enum CredentialType type, uint16_t fields_count, uint16_t *fields_names_len, 
  uint8_t **fields_names, uint16_t *fields_data_len, uint8_t *fields_encrypted, uint8_t **fields_data) {

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

// PIPASS_ERR get_credentials_by_name(struct Database *db, uint8_t *user_hash, uint8_t *master_pass, uint8_t *name, int16_t name_len, 
//   struct PlainTextCredential **ptcr, struct CredentialHeader **ptcrh, int32_t *cred_count) {
//     if (db == NULL || user_hash == NULL || master_pass == NULL || name == NULL || !name_len)
//         return ERR_GET_CRED_INV_PARAMS;

//     if (*ptcr != NULL || *ptcrh != NULL)
//         return ERR_GET_CRED_MEM_LEAK;

//     struct Credential *cr = NULL; 
//     struct CredentialHeader *crh = NULL;
//     PIPASS_ERR err = CRYPTO_OK;

//     err = verify_user_directory(user_hash);
//     if (err != STORAGE_OK)
//         return err;

//     err = verify_master_password(user_hash, master_pass);
//     if (err != STORAGE_OK)
//         return err;

//     *cred_count = 0;

//     for (int i = 0; i < db->cred_len; ++i) {
//         if (db->cred_headers[i].name_len == name_len && 
//           memcmp(db->cred[i].name, name, db->cred_headers[i].name_len) == 0) {
            
//             err = append_to_credential_array(&cr, cred_count, &(db->cred[i]));
//             if (err != DB_OK)
//                 goto error;

//             (*cred_count)--;

//             err = append_to_credential_header_array(&crh, cred_count, &(db->cred_headers[i]));
//             if (err != DB_OK)
//                 goto error;    
//         }
//     }

//     if (cr == NULL && crh == NULL && *cred_count == 0) {
//         err = ERR_GET_CRED_NOT_FOUND;
//         goto error;
//     } else if (cr == NULL || crh == NULL || *cred_count == 0) {
//         err = ERR_GET_CRED_DIFF_INDICES;
//         goto error;
//     }

//     *ptcr = calloc(*cred_count, sizeof(struct PlainTextCredential));
//     if (*ptcr == NULL) {
//         err = ERR_STORAGE_MEM_ALLOC;
//         goto error;
//     }
        
//     *ptcrh = calloc(*cred_count, sizeof(struct CredentialHeader));
//     if (*ptcr == NULL) {
//         err = ERR_STORAGE_MEM_ALLOC;
//         goto error;
//     }

//     for (int i = 0; i < *cred_count; ++i) {
//         err = decrypt_credential_field(db, &((*ptcr)[i].username), &((*ptcrh)[i].username_len), 
//         master_pass, cr[i].username, cr[i].username_iv, cr[i].username_mac, crh[i].username_len);
//         if (err != CRYPTO_OK)
//             goto error;

//         err = decrypt_credential_field(db, &((*ptcr)[i].passw), &((*ptcrh)[i].passw_len), 
//         master_pass, cr[i].passw, cr[i].passw_iv, cr[i].passw_mac, crh[i].passw_len);
//         if (err != CRYPTO_OK)
//             goto error;

//         (*ptcr)[i].username[crh[i].username_len] = 0;
//         (*ptcr)[i].passw[crh[i].passw_len] = 0;

//         if (crh[i].name_len > 0 && cr[i].name != NULL) {
//             (*ptcr)[i].name = malloc(crh[i].name_len + 1);
//             if ((*ptcr)->name == NULL) {
//                 err = ERR_GET_CRED_MEM_ALLOC;
//                 goto error;
//             }

//             memcpy((*ptcr)[i].name, cr[i].name, crh[i].name_len + 1);
//             (*ptcrh)[i].name_len = crh[i].name_len;
//             (*ptcrh)[i].cred_len += crh[i].name_len;
//         }

//         if (crh[i].url_len > 0 && cr[i].url != NULL) {
//             (*ptcr)[i].url = malloc(crh[i].url_len + 1);
//             if ((*ptcr)[i].url == NULL) {
//                 err = ERR_GET_CRED_MEM_ALLOC;
//                 goto error;
//             }

//             memcpy((*ptcr)[i].url, cr[i].url, crh[i].url_len + 1);
//             (*ptcrh)[i].url_len = crh[i].url_len;
//             (*ptcrh)[i].cred_len += crh[i].url_len;
//         }

//         if (crh[i].additional_len > 0 && cr[i].additional != NULL) {
//             (*ptcr)[i].additional = malloc(crh[i].additional_len + 1);
//             if ((*ptcr)[i].additional == NULL) {
//                 err = ERR_GET_CRED_MEM_ALLOC;
//                 goto error;
//             }

//             memcpy((*ptcr)[i].additional, cr[i].additional, crh[i].additional_len + 1);
//             (*ptcrh)[i].additional_len = crh[i].additional_len;
//             (*ptcrh)[i].cred_len += crh[i].additional_len;
//         }
//     }

//     err = STORAGE_OK;
//     goto free_cr_and_crh;

// error:
//     if (*ptcr != NULL) {
//         for (int i = 0; i < *cred_count; ++i) {
//             free_plaintext_credential(&((*ptcr)[i]), &((*ptcrh)[i]));
//         }

//         free(*ptcr);
//         *ptcr = NULL;
//     }

//     if (*ptcrh != NULL) {
//         free(*ptcrh);
//     }

// free_cr_and_crh: // TODO: zero buffers
//     if (cr != NULL) {
//         for (int i = 0; i < *cred_count; ++i)
//             zero_credential(&(cr[i]));
//         free(cr);
//     }

//     if (crh != NULL) {
//         for (int i = 0; i < *cred_count; ++i)
//             zero_credential_header(&(crh[i]));

//         free(crh);
//     }

//     return err;

// }