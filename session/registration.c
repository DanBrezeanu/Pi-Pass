#include <registration.h>
#include <sha256.h>
#include <aes256.h>
#include <crypto.h>
#include <storage.h>
#include <database.h>
#include <credentials.h>
#include <authentication.h>

PIPASS_ERR register_new_user(uint8_t *user_data, int32_t user_data_len, uint8_t *master_pass) {
    if (user_data == NULL || master_pass == NULL || user_data_len == 0) 
        return ERR_REGISTER_USER_INV_PARAMS;

    uint8_t *user_dek      = malloc(AES256_KEY_SIZE);
    uint8_t *user_hash     = NULL;
    uint8_t *user_dek_blob = NULL;
    uint8_t *user_kek      = NULL;
    uint8_t *user_kek_hash = NULL;
    uint8_t *kek_salt      = NULL;
    uint8_t *dek_blob_iv   = NULL;
    uint8_t *dek_blob_mac  = NULL;
    uint8_t *login_hash    = NULL;
    uint8_t *login_salt    = NULL;
    struct Database *db    = NULL;

    PIPASS_ERR err = generate_user_hash(user_data, user_data_len, &user_hash);
    if (err != STORAGE_OK)
        goto error;
    
    err = generate_KEK(master_pass, MASTER_PASS_SIZE, &kek_salt, &user_kek);
    if (err != CRYPTO_OK)
        goto error;

    if (user_dek == NULL) {
        err = ERR_STORAGE_MEM_ALLOC;
        goto error;
    }

    err = generate_aes256_key(user_dek);
    if (err != CRYPTO_OK)
        goto error;

    err = generate_DEK_blob(user_dek, user_kek, master_pass, MASTER_PASS_SIZE,
       &dek_blob_iv, &dek_blob_mac, &user_dek_blob);
    if (err != CRYPTO_OK)
        goto error;

    erase_buffer(&user_dek, AES256_KEY_SIZE);

    user_kek_hash = malloc(SHA256_DGST_SIZE);
    if (user_kek_hash == NULL) {
        err = ERR_STORAGE_MEM_ALLOC;
        goto error;
    }

    err = hash_sha256(user_kek, AES256_KEY_SIZE, kek_salt, SALT_SIZE, user_kek_hash);
    if (err != CRYPTO_OK)
        goto error;

    erase_buffer(&user_kek, AES256_KEY_SIZE);

    err = create_user_directory(user_hash);
    if (err != STORAGE_OK)
        goto error;

    err = create_new_db(&db);
    if (err != DB_OK)
        goto error;

    err = update_db_KEK(db, user_kek_hash, kek_salt);
    if (err != DB_OK)
        goto error;

    erase_buffer(&kek_salt, SALT_SIZE);
    erase_buffer(&user_kek_hash, SHA256_DGST_SIZE);

    err = update_db_DEK(db, user_dek_blob, dek_blob_iv, dek_blob_mac, master_pass);
    if (err != DB_OK)
        goto error;

    erase_buffer(&user_dek_blob, AES256_KEY_SIZE);
    erase_buffer(&dek_blob_iv, IV_SIZE);
    erase_buffer(&dek_blob_mac, MAC_SIZE);

    err = generate_login_hash(master_pass, &login_hash, &login_salt);
    if (err != CRYPTO_OK)
        goto error;

    zero_buffer(master_pass, MASTER_PASS_SIZE); 

    err = update_db_login(db, login_hash, login_salt);
    if (err != DB_OK)
        goto error;

    err = dump_database(db, user_hash);
    if (err != DB_OK)
        goto error;

    free_database(db);
    db = NULL;

    err = STORAGE_OK;

error:
    erase_buffer(&user_dek, AES256_KEY_SIZE);
    erase_buffer(&user_kek, AES256_KEY_SIZE);
    erase_buffer(&user_kek_hash, SHA256_DGST_SIZE);
    erase_buffer(&kek_salt, SALT_SIZE);
    erase_buffer(&user_hash, SHA256_HEX_SIZE);
    erase_buffer(&user_dek_blob, AES256_KEY_SIZE);
    erase_buffer(&dek_blob_iv, IV_SIZE);
    erase_buffer(&dek_blob_mac, MAC_SIZE);
    erase_buffer(&login_hash, SHA256_DGST_SIZE);
    erase_buffer(&login_salt, SALT_SIZE);
    if (db != NULL)
        free(db);

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

        err = verify_master_password(user_hash, pass);

        free(user_hash);

    } else if (argc == 3){
        struct Database *db = NULL;

        uint8_t *user_hash = NULL;
        err = generate_user_hash("test", 4, &user_hash);
        if (err != STORAGE_OK)
            goto error;

        err = load_database(&db, user_hash);
        if (err != STORAGE_OK)
            goto error;

        uint8_t *pass = calloc(5, 1); 
        uint8_t *name = calloc(7, 1); 
        uint8_t *username = calloc(10, 1); 
        uint8_t *passw = calloc(7, 1); 
        uint8_t *url = calloc(19, 1); 

        strcpy(pass, "1234");
        strcpy(name, "Amazon");
        strcpy(username, "GUsername");
        strcpy(passw, "GPassw");
        strcpy(url, "https://amazon.com");

        err = register_new_credential(db, user_hash, pass, name, 6, username, 9, passw, 6, url, 18, NULL, 0);
        if (err != STORAGE_OK)
            goto error;

        free(pass); free(name); free(username); free(passw); free(url);
        free(user_hash);
        free_database(db);

    } else if (argc == 4) {
        struct Database *db = NULL;

        uint8_t *user_hash = NULL;
        err = generate_user_hash("test", 4, &user_hash);
        if (err != STORAGE_OK)
            goto error;

        err = load_database(&db, user_hash);
        if (err != STORAGE_OK)
            goto error;

        struct PlainTextCredential *cr = NULL;
        struct CredentialHeader *crh = NULL;
        int32_t cred_count = 0;

        uint8_t *pass = malloc(5);
        strcpy(pass, "1234");
        uint8_t *name = malloc(7); 
        strcpy(name, "Amazon");

        //TODO: fix corrupted byte
        err = get_credentials_by_name(db, user_hash, pass, name, 6, &cr, &crh, &cred_count);
        if (err != STORAGE_OK)
            goto error;

        for (int i = 0; i < cred_count; ++i) {
            printf("%s\n%s\n%s\n%s\n%s\n", cr[i].name, cr[i].username, cr[i].passw, cr[i].url, cr[i].additional);
            printf("%d %d %d %d %d\n", crh[i].name_len, crh[i].username_len, crh[i].passw_len, crh[i].url_len, crh[i].additional_len);
        }
        free(pass);
        free(name);
        for (int i = 0; i < cred_count; ++i)
            free_plaintext_credential(&(cr[i]), &(crh[i]));
        free(cr);
        free(crh);
        free(user_hash);
        free_database(db);
    }
error:
    printf("0x%.4X\n", err);
    return 0;
}