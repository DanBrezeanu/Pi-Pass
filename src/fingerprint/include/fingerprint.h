#ifndef __FINGERPRINT_H__
#define __FINGERPRINT_H__

#include <defines.h>
#include <errors.h>
#include <r502.h>


#ifndef DEFAULT_FP_ADDRESS
    #define DEFAULT_FP_ADDRESS 0xFFFFFFFF
#endif

#define MINIMUM_MATCH_SCORE 80

struct async_fp_data {
    uint16_t index;
    uint16_t match_score;
    uint8_t *fp_key;
    uint8_t  stop;
    PIPASS_ERR err;
};

PIPASS_ERR init_fingerprint();
PIPASS_ERR fp_verify_pin(uint8_t *pin);
PIPASS_ERR fp_enroll_fingerprint(uint16_t *fp_index);
PIPASS_ERR fp_verify_fingerprint(uint16_t *index, uint16_t *match_score);
PIPASS_ERR fp_get_fingerprint(uint8_t **fp_key);
void *fp_async_get_fingerprint(void *arg);

#endif