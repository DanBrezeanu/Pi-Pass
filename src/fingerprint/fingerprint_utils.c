#include <fingerprint_utils.h>
#include <fingerprint.h>
#include <gpio_control.h>

uint32_t bin_to_number(uint8_t *bin, size_t size) {
    uint32_t number = 0;

    for (int i = 0; i < size; ++i) {
        number = number * 10 + bin[i] - '0';
    }

    return number;
}

void wait_for_sensor_touch() {
    wait_for_input(FP_IRQ_PIN, 0);
}

uint8_t wait_for_sensor_touch_with_timeout(uint32_t timeout_us) {
   return wait_for_input_with_timeout(FP_IRQ_PIN, 0, timeout_us);
}