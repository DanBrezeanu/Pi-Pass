#include <storage_utils.h>
#include <authentication.h>
#include <storage.h>
#include <sha256.h>
#include <crypto.h>
#include <aes256.h>

PIPASS_ERR authenticate(uint8_t *user_hash, uint8_t *master_pass) {
    if (user_hash == NULL || master_pass == NULL)
        return ERR_AUTH_INV_PARAMS;

    PIPASS_ERR err = PIPASS_OK;

    //TODO: check db file exists
    err = verify_user_directory(user_hash);
    if (err != PIPASS_OK)
        return err;

    err = verify_master_password(user_hash, master_pass);
    if (err != PIPASS_OK)
        return err;
    
    OTK = malloc(AES256_KEY_SIZE);
    if (OTK == NULL)
        return ERR_AUTH_MEM_ALLOC;
        
    OTK = generate_aes256_key()



}

PIPASS_ERR verify_master_password(uint8_t *user_hash, uint8_t *master_pass) {
    PIPASS_ERR err;

    struct Database *db = NULL;

    err = verify_user_directory(user_hash);
    if (err != STORAGE_OK) {
        goto error;
    }

    err = load_database(&db, user_hash);
    if (err != STORAGE_OK) {
        goto error;
    }

    err = verify_sha256(master_pass, MASTER_PASS_SIZE, db->login.salt, SALT_SIZE, db->login.hash);
    if (err != CRYPTO_OK) {
        goto error;
    }

    err = STORAGE_OK;

error:
    free_database(db);
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