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
  uint8_t *fp_data, uint8_t *master_password, uint32_t master_password_len) {
    if (FL_LOGGED_IN)
        return ERR_ALREADY_LOGGED_IN;
    
    if (FL_DB_INITIALIZED)
        return ERR_DB_ALREADY_INIT;

    if (FL_DB_HEADER_LOADED)
        return ERR_DB_HEADER_ALREADY_LOADED;

    if (user_data == NULL || master_pin == NULL || user_data_len == 0 || fp_data == NULL ||
      master_password == NULL || !master_password_len) 
        return ERR_REGISTER_USER_INV_PARAMS;

    uint8_t *user_hash = NULL;
    PIPASS_ERR err = PIPASS_OK;
   
    err = generate_user_hash(user_data, user_data_len, &user_hash);
    if (err != PIPASS_OK)
        goto error;    

    err = db_create_new(master_pin, fp_data, master_password, master_password_len);
    if (err != PIPASS_OK)
        goto error;

    err = create_user_directory(user_hash);
    if (err != PIPASS_OK)
        goto error;

    FL_LOGGED_IN = FL_DB_HEADER_LOADED = FL_DB_INITIALIZED = 1;

    err = dump_database(user_hash);
    if (err != DB_OK)
        goto error;

    FL_LOGGED_IN = FL_DB_HEADER_LOADED = FL_DB_INITIALIZED = 0;

    err = PIPASS_OK;

error:
    erase_buffer(&user_hash, SHA256_HEX_SIZE);
    erase_buffer(&fp_data, FINGERPRINT_SIZE);
    db_free();

    return err;
}

#include <stdio.h>
#include <actions.h>

//  err = fp_enroll_fingerprint(&fp_index);
//     if (err != PIPASS_OK)
//         goto error;



int main(int argc, char **argv) {
    PIPASS_ERR err = -1;
    uint8_t *fp_data = NULL;
    init_fingerprint();
    init_gpio();

    fp_verify_pin("0000");

    char pin[] = "1234";
    

    printf("%d\n", DB_HEADER_SIZE);
    if (argc == 1) {
        int index = 0;
        // err = fp_enroll_fingerprint(&index);

        err = fp_get_fingerprint(&fp_data);
        printf("%.4X\n", err);

        err = register_new_user("test", strlen("test"), pin, fp_data, "parola", 6);
        printf("%.4X\n", err);

    } else if (argc == 2) {
        uint8_t *user_hash = NULL;
        // err = fp_get_fingerprint(&fp_data);
        // printf("%.4X\n", err);

        err = authenticate("test", strlen("test"), pin, NULL, "parola", 6);
        printf("auth = %.4X\n", err);

        free(user_hash);
    } else if (argc == 3) {
        // err = fp_get_fingerprint(&fp_data);
        // printf("%.4X\n", err);

        uint8_t *user_hash = NULL;
        err = generate_user_hash("test", 4, &user_hash);        

        err = authenticate("test", strlen("test"), pin, NULL, "parola", 6);
        printf("auth = %.4X\n", err);

        uint16_t names_len[] = {5, 4};
        uint8_t *names[] = {"UserX", "PLSS"};

        uint16_t data_len[] = {6, 3};
        uint8_t *data[] = {"MyUser", "UFF"};

        uint8_t is_encrypted[] = {0, 1};

        err = register_new_credential(user_hash, PASSWORD_TYPE, 2, names_len, names, data_len, is_encrypted, data);
        printf("reg = %.4X", err);

    } else if (argc == 4) {

        uint8_t *user_hash = NULL;
        err = generate_user_hash("test", 4, &user_hash);
        if (err != STORAGE_OK)
            goto error;

        err = authenticate("test", strlen("test"), pin, NULL, "parola", 6);
        if (err != STORAGE_OK)
            goto error;

        struct Credential *cr = NULL;
        uint32_t cr_len = 0;

        err = get_credentials(user_hash, "UserX", 5, "MyUser", 6, &cr, &cr_len);
        if (err != PIPASS_OK)
            goto error;

        for (int32_t i = 0; i < cr_len; ++i) {
            for (int32_t j = 0; j < cr[i].fields_count; ++j) {
                printf("%s\n", cr[i].fields_names[j]);
                printf("%s\n", cr[i].fields_data[j].data_plain);
            }
        }


    }
error:
    printf("0x%.4X\n", err);
    return 0;
}