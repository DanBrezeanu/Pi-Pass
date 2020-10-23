#include <registration.h>
#include <sha256.h>
#include <aes256.h>
#include <crypto.h>
#include <storage.h>
#include <database.h>
#include <credentials.h>
#include <authentication.h>

PIPASS_ERR register_new_user(uint8_t *user_data, int32_t user_data_len, uint8_t *master_pass) {
    if (FL_LOGGED_IN)
        return ERR_ALREADY_LOGGED_IN;
    
    if (FL_DB_INITIALIZED)
        return ERR_DB_ALREADY_INIT;

    if (FL_DB_HEADER_LOADED)
        return ERR_DB_HEADER_ALREADY_LOADED;

    if (user_data == NULL || master_pass == NULL || user_data_len == 0) 
        return ERR_REGISTER_USER_INV_PARAMS;

    uint8_t *user_hash = NULL;
    PIPASS_ERR err = PIPASS_OK;
   
    err = generate_user_hash(user_data, user_data_len, &user_hash);
    if (err != PIPASS_OK)
        goto error;    

    err = db_create_new(master_pass);
    if (err != PIPASS_OK)
        goto error;

    err = create_user_directory(user_hash);
    if (err != PIPASS_OK)
        goto error;

    FL_LOGGED_IN = FL_DB_HEADER_LOADED = FL_DB_INITIALIZED = 1;

    err = dump_database(user_hash, master_pass);
    if (err != DB_OK)
        goto error;

    FL_LOGGED_IN = FL_DB_HEADER_LOADED = FL_DB_INITIALIZED = 0;

    err = PIPASS_OK;

error:
    erase_buffer(&user_hash, SHA256_HEX_SIZE);
    db_free();

    return err;
}

#include <stdio.h>
#include <actions.h>

int main(int argc, char **argv) {
    PIPASS_ERR err = -1;

    if (argc == 1) {
        char pass[] = "1234";
        err = register_new_user("test", strlen("test"), pass);
    } else if (argc == 2) {
        uint8_t *user_hash = NULL;
        err = generate_user_hash("test", 4, &user_hash);
        if (err != STORAGE_OK)
            goto error;

        char pass[] = "1234";

        // err = verify_master_password_with_hashvei(pass, user_hash);

        free(user_hash);
    }
    // } else if (argc == 3){
    //     struct Database *db = NULL;

    //     uint8_t *user_hash = NULL;
    //     err = generate_user_hash("test", 4, &user_hash);
    //     if (err != STORAGE_OK)
    //         goto error;

    //     err = load_database(&db, user_hash);
    //     if (err != STORAGE_OK)
    //         goto error;

    //     uint8_t *pass = calloc(5, 1); 
    //     uint8_t *name = calloc(7, 1); 
    //     uint8_t *username = calloc(10, 1); 
    //     uint8_t *passw = calloc(7, 1); 
    //     uint8_t *url = calloc(19, 1); 

    //     strcpy(pass, "1234");
    //     strcpy(name, "Amazon");
    //     strcpy(username, "GUsername");
    //     strcpy(passw, "GPassw");
    //     strcpy(url, "https://amazon.com");

    //     err = register_new_credential(db, user_hash, pass, name, 6, username, 9, passw, 6, url, 18, NULL, 0);
    //     if (err != STORAGE_OK)
    //         goto error;

    //     free(pass); free(name); free(username); free(passw); free(url);
    //     free(user_hash);
    //     free_database(db);

    // } else if (argc == 4) {
    //     struct Database *db = NULL;

    //     uint8_t *user_hash = NULL;
    //     err = generate_user_hash("test", 4, &user_hash);
    //     if (err != STORAGE_OK)
    //         goto error;

    //     err = load_database(&db, user_hash);
    //     if (err != STORAGE_OK)
    //         goto error;

    //     struct PlainTextCredential *cr = NULL;
    //     struct CredentialHeader *crh = NULL;
    //     int32_t cred_count = 0;

    //     uint8_t *pass = malloc(5);
    //     strcpy(pass, "1234");
    //     uint8_t *name = malloc(7); 
    //     strcpy(name, "Amazon");

    //     //TODO: fix corrupted byte
    //     err = get_credentials_by_name(db, user_hash, pass, name, 6, &cr, &crh, &cred_count);
    //     if (err != STORAGE_OK)
    //         goto error;

    //     for (int i = 0; i < cred_count; ++i) {
    //         printf("%s\n%s\n%s\n%s\n%s\n", cr[i].name, cr[i].username, cr[i].passw, cr[i].url, cr[i].additional);
    //         printf("%d %d %d %d %d\n", crh[i].name_len, crh[i].username_len, crh[i].passw_len, crh[i].url_len, crh[i].additional_len);
    //     }
    //     free(pass);
    //     free(name);
    //     for (int i = 0; i < cred_count; ++i)
    //         free_plaintext_credential(&(cr[i]), &(crh[i]));
    //     free(cr);
    //     free(crh);
    //     free(user_hash);
    //     free_database(db);
    // }
error:
    printf("0x%.4X\n", err);
    return 0;
}