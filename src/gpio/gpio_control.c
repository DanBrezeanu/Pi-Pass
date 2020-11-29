#include <gpio_control.h>
#include <stdlib.h>

PIPASS_ERR init_gpio() {
    int32_t ret;
    PIPASS_ERR err; 

    ret = gpioInitialise();
    if (ret < 0)
        return ERR_GPIO_INIT_FAIL;
    
    ret = gpioSetMode(FP_IRQ_PIN, PI_INPUT);
    if (ret != 0)
        goto error;
    
    ret = gpioSetMode(B1_GPIO, PI_INPUT);
    if (ret != 0)
        goto error;
    ret = gpioSetPullUpDown(B1_GPIO, PI_PUD_UP);
    if (ret != 0)
        goto error;

    ret = gpioSetMode(B2_GPIO, PI_INPUT);
    if (ret != 0)
        goto error;
    ret = gpioSetPullUpDown(B2_GPIO, PI_PUD_UP);
    if (ret != 0)
        goto error;
    
    ret = gpioSetMode(B3_GPIO, PI_INPUT);
    if (ret != 0)
        goto error;
    ret = gpioSetPullUpDown(B3_GPIO, PI_PUD_UP);
    if (ret != 0)
        goto error;
    
    ret = gpioSetMode(B4_GPIO, PI_INPUT);
    if (ret != 0)
        goto error;
    ret = gpioSetPullUpDown(B4_GPIO, PI_PUD_UP);
    if (ret != 0)
        goto error;

    return PIPASS_OK;

error:
    gpioTerminate();
    return ERR_GPIO_INIT_FAIL;
}

enum Button get_pressed_button() {
    int8_t status;
    
    status = gpioRead(B1_GPIO);
    if (status == 0)
        return B1;

    status = gpioRead(B2_GPIO);
    if (status == 0)
        return B2;

    status = gpioRead(B3_GPIO);
    if (status == 0)
        return B3;

    status = gpioRead(B4_GPIO);
    if (status == 0)
        return B4;

    return None;
}

void wait_for_input(uint8_t gpio, int8_t level) {
    int8_t status = 0;

    do {
        status = gpioRead(gpio);
        usleep(1000);
    } while (status != level);
}