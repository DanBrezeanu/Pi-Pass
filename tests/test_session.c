#include <check.h>
#include <authentication.h>
#include <fingerprint.h>
#include <database.h>
#include <actions.h>
#include <crypto.h>
#include <aes256.h>
#include <registration.h>

#include <errors.h>
#include <defines.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fts.h>


/********* FIXTURES ************/

uint8_t user[]    = "test_user";
uint8_t pin[]     = "1234";
uint8_t passw[]   = "password";
uint8_t fp_data[FINGERPRINT_SIZE] = {0};


void remove_test_directory() {
    FTS *ftsp = NULL;
    FTSENT *curr;
    char *files[] = { (char *) "/pipass/users/1160130875fda0812c99c5e3f1a03516471a6370c4f97129b221938eb4763e63", NULL };
    ftsp = fts_open(files, FTS_NOCHDIR | FTS_PHYSICAL | FTS_XDEV, NULL);
    while ((curr = fts_read(ftsp)))
        switch(curr->fts_info) {
        case FTS_DP:
        case FTS_F:
        case FTS_SL:
        case FTS_SLNONE:
        case FTS_DEFAULT:
             remove(curr->fts_accpath);
        }

    fts_close(ftsp);        
}

void setup(void) {
    remove_test_directory();

    /* Generate random fingerprint data */    
    RAND_bytes(fp_data, FINGERPRINT_SIZE);
}

void teardown(void) {
    remove_test_directory();
}

/******************************/

START_TEST(test_registration) {
    PIPASS_ERR err;

    /* Register user */
    err = register_new_user(user, strlen(user), pin, fp_data, passw, strlen(passw));
    ck_assert_uint_eq(err, PIPASS_OK);

    /* Generate user hash */
    uint8_t *user_hash = NULL;
    err = generate_user_hash(user, strlen(user), &user_hash);
    ck_assert_uint_eq(err, PIPASS_OK);

    /* Get database file path */
    uint8_t *file_path = NULL;
    uint32_t file_path_len = 0;
    err = user_file_path(user_hash, PIPASS_DB, &file_path, &file_path_len);
    ck_assert_uint_eq(err, PIPASS_OK);

    /* Check database file exist */
    struct stat buffer;
    uint32_t db_exists = (stat(file_path, &buffer) == 0);
    ck_assert_uint_eq(db_exists, 1);
}
END_TEST

START_TEST(test_authentication_with_password) {
    PIPASS_ERR err;
    
    /* Authenticate with password */
    err = authenticate(user, strlen(user), pin, NULL, passw, strlen(passw));
    ck_assert_uint_eq(err, PIPASS_OK);
}
END_TEST

START_TEST(test_authentication_with_fingerprint) {
    PIPASS_ERR err;

    /* Authenticate with fingerprint */
    err = authenticate(user, strlen(user), pin, fp_data, NULL, 0);
    ck_assert_uint_eq(err, PIPASS_OK);
}
END_TEST

START_TEST(test_add_credential) {
    PIPASS_ERR err;

    uint8_t *field_names[]     = {"TestField_1", "TestField_2"};
    uint16_t field_names_len[] = {strlen(field_names[0]), strlen(field_names[1])};

    uint8_t *field_data[]     = {"TestData_1", "TestData_2"};
    uint16_t field_data_len[] = {strlen(field_data[0]), strlen(field_data[1])};

    uint8_t field_encrypted[]    = {0, 1};

    /* Authenticate first */
    err = authenticate(user, strlen(user), pin, NULL, passw, strlen(passw));
    ck_assert_uint_eq(err, PIPASS_OK);

    /* Generate user hash */
    uint8_t *user_hash = NULL;
    err = generate_user_hash(user, strlen(user), &user_hash);
    ck_assert_uint_eq(err, PIPASS_OK);

    /* Add new credential to database */
    err = register_new_credential(user_hash, PASSWORD_TYPE, 2, field_names_len, field_names, field_data_len, field_encrypted, field_data);
    ck_assert_uint_eq(err, PIPASS_OK);

    /* Try getting the credential from the database */
    struct Credential *cr = NULL;
    uint16_t cr_len = 0;

    err = get_credentials(user_hash, "TestField_1", strlen("TestField_1"), "TestData_1", strlen("TestData_1"), &cr, &cr_len);
    ck_assert_uint_eq(err, PIPASS_OK);
    ck_assert_ptr_ne(cr, NULL);
    ck_assert_uint_ne(cr_len, 0);

    for (int32_t i = 0; i < cr->fields_count; ++i) {
        ck_assert_uint_eq(cr->fields_data_len[i], field_data_len[i]);
        ck_assert_mem_eq(cr->fields_data[i].data_plain, field_data[i], field_data_len[i]);

        ck_assert_uint_eq(cr->fields_names_len[i], field_names_len[i]);
        ck_assert_mem_eq(cr->fields_names[i], field_names[i], field_names_len[i]);
    }
}
END_TEST


Suite *session_suite(void) {
    Suite *s;
    TCase *tc_core;

    s = suite_create("session");

    tc_core = tcase_create("core");

    tcase_add_unchecked_fixture(tc_core, setup, teardown);
    tcase_add_test(tc_core, test_registration);
    tcase_add_test(tc_core, test_authentication_with_password);
    tcase_add_test(tc_core, test_authentication_with_fingerprint);
    tcase_add_test(tc_core, test_add_credential);
    suite_add_tcase(s, tc_core);

    return s;
}


