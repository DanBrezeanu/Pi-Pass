#include <registration.h>
#include <sha256.h>
#include <aes256.h>
#include <crypto.h>
#include <storage.h>
#include <database.h>
#include <credentials.h>
#include <authentication.h>

STORAGE_ERR register_new_user(uint8_t *user_data, int32_t user_data_len, uint8_t *master_pass) {
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

    STORAGE_ERR err = generate_user_hash(user_data, user_data_len, &user_hash);
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

    // zero_buffer(master_pass, MASTER_PASS_SIZE);

    err = update_db_login(db, login_hash, login_salt);
    if (err != DB_OK)
        goto error;

    err = dump_database(db, user_hash);
    if (err != DB_OK)
        goto error;

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
    STORAGE_ERR err = -1;

    if (argc == 1) {
        err = register_new_user("test", strlen("test"), "1234");
    } else if (argc == 2) {
        uint8_t *user_hash = NULL;
        err = generate_user_hash("test", 4, &user_hash);
        if (err != STORAGE_OK)
            goto error;

        err = verify_master_password(user_hash, "1234");
    } else {
        struct Database *db = NULL;

        uint8_t *user_hash = NULL;
        err = generate_user_hash("test", 4, &user_hash);
        if (err != STORAGE_OK)
            goto error;

        err = load_database(&db, user_hash);
        if (err != STORAGE_OK)
            goto error;

        err = register_new_credential(db, user_hash, "1234", "Google", 7, "testus", 7, "parola", 7, "https://google.com", strlen("https://google.com") + 1, NULL, 0);
        if (err != STORAGE_OK)
            goto error;

    }
error:
    printf("0x%.4X\n", err);
    return 0;
}