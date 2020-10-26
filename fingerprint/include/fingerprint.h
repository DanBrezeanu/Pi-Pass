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

PIPASS_ERR fp_enroll_fingerprint(uint16_t *fp_index);


#endif