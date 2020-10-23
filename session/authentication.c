#include <storage_utils.h>
#include <authentication.h>
#include <storage.h>
#include <sha256.h>
#include <crypto.h>
#include <aes256.h>
#include <flags.h>

PIPASS_ERR authenticate(uint8_t *user_hash, uint8_t *master_pass) {
    if (FL_LOGGED_IN)
        return ERR_ALREADY_LOGGED_IN;
    
    if (user_hash == NULL || master_pass == NULL)
        return ERR_AUTH_INV_PARAMS;

    PIPASS_ERR err = PIPASS_OK;

    //TODO: check db file exists
    err = verify_user_directory(user_hash);
    if (err != PIPASS_OK)
        return err;

    uint8_t *raw_db_header = NULL;
    struct DataBlob raw_db = {0};
    uint32_t raw_db_len = 0;
    struct DataHash *master_pass_hash = NULL;
    uint8_t *kek = NULL;

    err = read_database_header(user_hash, &raw_db_header);
    if (err != PIPASS_OK)
        goto error;

    err = load_database_header(raw_db_header);
    if (err != PIPASS_OK)
        goto error;

    FL_DB_HEADER_LOADED = 1;
    
    err = verify_master_password_with_db(user_hash);
    if (err != PIPASS_OK)
        return err;

    FL_LOGGED_IN = 1;

    /*  TODO: change raw_db_len acquirement from this function's output to db_get_length() */
    err = read_database(user_hash, &raw_db, &raw_db_len);
    if (err != PIPASS_OK)
        goto error;

    master_pass_hash = calloc(1, sizeof(master_pass_hash));
    if (master_pass_hash == NULL) {
        err = ERR_DB_MEM_ALLOC;
        goto error;
    }
    
    err = alloc_datahash(master_pass_hash);
    if (err != PIPASS_OK)
        goto error;

    err = db_get_master_pass_hash(master_pass_hash);
    if (err != PIPASS_OK)
        goto error;

    err = generate_KEK(master_pass, master_pass_hash->salt, &kek);
    if (err != PIPASS_OK)
        goto error;

    err = load_database(&raw_db, raw_db_len, kek);
    if (err != PIPASS_OK)
        goto error;

    FL_DB_INITIALIZED = 1;

    err = PIPASS_OK;
    goto cleanup;

error:
    FL_DB_HEADER_LOADED = 0;
    FL_DB_INITIALIZED = 0;
    FL_LOGGED_IN = 0;
    db_free_header();

cleanup:
    erase_buffer(&kek, AES256_KEY_SIZE);
    erase_buffer(&raw_db_header, DB_HEADER_SIZE);
    free_datablob(&raw_db, raw_db_len);
    free_datahash(master_pass_hash);
    if (master_pass_hash != NULL)
        free(master_pass_hash);

    return err;
}

PIPASS_ERR verify_user_exists(uint8_t *user, int user_len) {
    uint8_t *user_hash = NULL;
    PIPASS_ERR err = STORAGE_OK;
    
    err = sanity_check_buffer(user, user_len);
    if (err != CRYPTO_OK)
        return err;

    err = generate_user_hash(user, user_len, &user_hash);
    if (err != STORAGE_OK)
        goto error;

    err = verify_user_directory(user_hash);

error:
    erase_buffer(&user_hash, SHA256_HEX_SIZE);

    return err;
}