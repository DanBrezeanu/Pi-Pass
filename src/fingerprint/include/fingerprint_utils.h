#ifndef __FINGERPRINT_UTILS_H__
#define __FINGERPRINT_UTILS_H__

#include <defines.h>
#include <errors.h>

uint32_t bin_to_number(uint8_t *bin, size_t size);
void wait_for_sensor_touch();
uint8_t wait_for_sensor_touch_with_timeout(uint32_t timeout_us);

#endif