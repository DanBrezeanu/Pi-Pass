#include <check.h>
#include "test.h"

int main() {
    SRunner *sr;

    Suite * (*test_suites[])() = {
        crypto_suite,
        session_suite
    };
    size_t suites_count = sizeof(test_suites) / sizeof(test_suites[0]);

    sr = srunner_create(test_suites[0]());
    srunner_set_fork_status(sr, CK_NOFORK);

    for (size_t i = 1; i < suites_count; ++i)
        srunner_add_suite(sr, test_suites[i]());

    srunner_run_all(sr, CK_VERBOSE);
    srunner_free(sr);

    return 0;
}
