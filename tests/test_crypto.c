#include <check.h>
#include <crypto.h>
#include <aes256.h>

#include <errors.h>
#include <defines.h>

START_TEST(test_generate_aes_key) {
    uint8_t *key = malloc(AES256_KEY_SIZE);
    PIPASS_ERR err = generate_aes256_key(key);

    ck_assert_uint_eq(err, PIPASS_OK);
    ck_assert_ptr_ne(key, NULL);
}
END_TEST


Suite *crypto_suite(void) {
    Suite *s;
    TCase *tc_core;

    s = suite_create("crypto");

    tc_core = tcase_create("core");

    tcase_add_test(tc_core, test_generate_aes_key);
    suite_add_tcase(s, tc_core);

    return s;
}


