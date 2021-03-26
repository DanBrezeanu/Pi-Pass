#include <registration.h>
#include <sha256.h>
#include <aes256.h>
#include <crypto.h>
#include <storage.h>
#include <database.h>
#include <credentials.h>
#include <authentication.h>
#include <fingerprint.h>

PIPASS_ERR register_new_user(uint8_t *user_data, int32_t user_data_len, uint8_t *master_pin,
  uint8_t *fp_key, uint8_t *master_password, uint32_t master_password_len) {
    if (FL_LOGGED_IN)
        return ERR_ALREADY_LOGGED_IN;
    
    if (FL_DB_INITIALIZED)
        return ERR_DB_ALREADY_INIT;

    if (FL_DB_HEADER_LOADED)
        return ERR_DB_HEADER_ALREADY_LOADED;

    if (user_data == NULL || master_pin == NULL || user_data_len == 0 || fp_key == NULL ||
      master_password == NULL || !master_password_len) 
        return ERR_REGISTER_USER_INV_PARAMS;

    uint8_t *user_hash = NULL;
    PIPASS_ERR err = PIPASS_OK;
   
    err = generate_user_hash(user_data, user_data_len, &user_hash);
    if (err != PIPASS_OK)
        goto error;    

    err = db_create_new(master_pin, fp_key, master_password, master_password_len);
    if (err != PIPASS_OK)
        goto error;

    err = create_user_directory(user_hash);
    if (err != PIPASS_OK)
        goto error;

    FL_LOGGED_IN = FL_DB_HEADER_LOADED = FL_DB_INITIALIZED = 1;

    err = dump_database(user_hash);
    if (err != DB_OK)
        goto error;

    err = add_to_users_conf_file(user_data, user_data_len);
    if (err != PIPASS_OK)
        goto error;

    err = PIPASS_OK;

error:
    /* TODO: remove created files */
    erase_buffer(&user_hash, SHA256_HEX_SIZE);
    db_free();

    FL_LOGGED_IN = FL_DB_HEADER_LOADED = FL_DB_INITIALIZED = 0;

    return err;
}