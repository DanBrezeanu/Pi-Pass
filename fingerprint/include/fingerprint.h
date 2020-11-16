#ifndef __FINGERPRINT_H__
#define __FINGERPRINT_H__

#include <defines.h>
#include <errors.h>
#include <r502.h>
#include <pigpio.h>


#ifndef DEFAULT_FP_ADDRESS
    #define DEFAULT_FP_ADDRESS 0xFFFFFFFF
#endif

#define IRQ_PIN 23
#define MINIMUM_MATCH_SCORE 80
#define FINGERPRINT_SIZE 1536

PIPASS_ERR init_fingerprint();
PIPASS_ERR fp_verify_pin(uint8_t *pin);
PIPASS_ERR fp_enroll_fingerprint(uint16_t *fp_index);
PIPASS_ERR fp_verify_fingerprint(uint16_t *index, uint16_t *match_score);
PIPASS_ERR fp_get_fingerprint(uint8_t **fp_data);

#endif