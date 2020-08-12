#include <storage_utils.h>
#include <authentication.h>
#include <storage.h>
#include <sha256.h>

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
    // zero_buffer(key, MASTER_PASS_SIZE);
    return err;
} 

// #include <stdio.h>

// int main() {
//     uint8_t *user = malloc(SHA256_HEX_SIZE);
//     uint8_t *key = malloc(MASTER_PASS_SIZE);

//     memcpy(user, "55402817f85b8423f989bc5ed92476a4b4967c302201e9540e9bb55579f00e4b", SHA256_HEX_SIZE);
//     memcpy(key, "1234", MASTER_PASS_SIZE);

//     STORAGE_ERR err = verify_master_password(user, key);

//     printf("0x%.4X\n", err);

//     return 0;
// }