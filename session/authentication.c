#include <storage_utils.h>
#include <authentication.h>
#include <storage.h>
#include <sha256.h>
#include <crypto.h>

STORAGE_ERR verify_master_password(uint8_t *user, uint8_t *key) {
    STORAGE_ERR err;

    struct Database *db = NULL;

    err = verify_user_directory(user);
    if (err != STORAGE_OK) {
        goto error;
    }

    err = load_database(&db, user);
    if (err != STORAGE_OK) {
        goto error;
    }

    err = verify_sha256(key, MASTER_PASS_SIZE, db->login_salt, SALT_SIZE, db->login_hash);
    if (err != CRYPTO_OK) {
        goto error;
    }

    err = STORAGE_OK;

error:
    free_database(db);
    return err;
}

STORAGE_ERR verify_user_exists(uint8_t *user, int user_len) {
    uint8_t *user_hash = NULL;
    STORAGE_ERR err = STORAGE_OK;
    
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