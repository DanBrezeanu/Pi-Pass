#include <storage_utils.h>
#include <authentication.h>
#include <storage.h>
#include <sha256.h>
#include <crypto.h>
#include <aes256.h>
#include <flags.h>
#include <fingerprint.h>

PIPASS_ERR authenticate(uint8_t *user, uint32_t user_len, uint8_t *master_pin,
  uint8_t *fp_data, uint8_t *master_password, uint32_t master_password_len) {
    if (FL_LOGGED_IN)
        return ERR_ALREADY_LOGGED_IN;
    
    if (user == NULL || master_pin == NULL || !user_len ||
      (fp_data == NULL && (master_password == NULL || !master_password_len)))
        return ERR_AUTH_INV_PARAMS;

    PIPASS_ERR err = PIPASS_OK;

    uint8_t *user_hash = NULL;
    err = generate_user_hash(user, user_len, &user_hash);
    if (err != PIPASS_OK)
        goto error;

    //TODO: check db file exists
    err = verify_user_directory(user_hash);
    if (err != PIPASS_OK)
        return err;

    uint8_t *raw_db_header = NULL;
    uint8_t *raw_db = NULL;
    uint32_t raw_db_len = 0;
    struct DataHash *master_pin_hash = NULL;
    uint8_t *kek = NULL;
    uint8_t *fp_key = NULL;
    uint8_t *master_passw_key = NULL;
    struct DataBlob encrypted_fp_key = {0};
    struct DataBlob dek_blob = {0};
    uint8_t *dek = NULL;

    err = read_database_header(user_hash, &raw_db_header);
    if (err != PIPASS_OK)
        goto error;

    err = load_database_header(raw_db_header);
    if (err != PIPASS_OK)
        goto error;

    FL_DB_HEADER_LOADED = 1;
    
    err = verify_master_pin_with_db(master_pin);
    if (err != PIPASS_OK)
        return err;

    FL_LOGGED_IN = 1;

    /*  TODO: change raw_db_len acquirement from this function's output to db_get_length() */
    err = read_database(user_hash, &raw_db, &raw_db_len);
    if (err != PIPASS_OK)
        goto error;

    master_pin_hash = calloc(1, sizeof(master_pin_hash));
    if (master_pin_hash == NULL) {
        err = ERR_DB_MEM_ALLOC;
        goto error;
    }
    
    err = alloc_datahash(master_pin_hash);
    if (err != PIPASS_OK)
        goto error;

    err = db_get_master_pin_hash(master_pin_hash);
    if (err != PIPASS_OK)
        goto error;

    
    if (fp_data != NULL) {
        fp_key = malloc(AES256_KEY_SIZE);
        if (fp_key == NULL) {
            err = ERR_STORAGE_MEM_ALLOC;
            goto error;
        }

        err = create_PBKDF2_key(fp_data, FINGERPRINT_SIZE, NULL, 0, fp_key);
        if (err != PIPASS_OK)
            goto error;
    } else {
        err = db_get_encrypted_fp_key(&encrypted_fp_key);
        if (err != PIPASS_OK)
            goto error;

        master_passw_key = malloc(AES256_KEY_SIZE);
        if (master_passw_key == NULL) {
            err = ERR_STORAGE_MEM_ALLOC;
            goto error;
        }

        err = create_PBKDF2_key(master_password, master_password_len, NULL, 0, master_passw_key);
        if (err != PIPASS_OK)
            goto error;

        err = decrypt_cipher_with_key(&encrypted_fp_key, AES256_KEY_SIZE, master_passw_key, &fp_key);
        if (err != PIPASS_OK)
            goto error;

        erase_buffer(&master_passw_key, AES256_KEY_SIZE);
    }

    err = generate_KEK(master_pin, master_pin_hash->salt, fp_key, &kek);
    if (err != PIPASS_OK)
        goto error;

    err = load_database(raw_db, raw_db_len, kek);
    if (err != PIPASS_OK)
        goto error;

    FL_DB_INITIALIZED = 1;

    err = generate_OTK();
    if (err != PIPASS_OK)
        goto error;

    err = decrypt_DEK_with_KEK(kek, &dek);
    if (err != PIPASS_OK)
        goto error;
    
    err = encrypt_DEK_with_OTK(dek);
    if (err != PIPASS_OK)
        goto error;

    erase_buffer(&dek, AES256_KEY_SIZE);


    err = PIPASS_OK;
    goto cleanup;

error:
    FL_DB_HEADER_LOADED = 0;
    FL_DB_INITIALIZED = 0;
    FL_LOGGED_IN = 0;
    db_free_header();

cleanup:
    erase_buffer(&user_hash, SHA256_HEX_SIZE);
    erase_buffer(&fp_key, AES256_KEY_SIZE);
    erase_buffer(&master_passw_key, AES256_KEY_SIZE);
    erase_buffer(&kek, AES256_KEY_SIZE);
    erase_buffer(&raw_db_header, DB_HEADER_SIZE);
    erase_buffer(&raw_db, raw_db_len);
    erase_buffer(&dek, AES256_KEY_SIZE);
    free_datahash(master_pin_hash);
    if (master_pin_hash != NULL)
        free(master_pin_hash);

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