#ifndef __GPIO_CONTROL_H__
#define __GPIO_CONTROL_H__

#include <defines.h>
#include <errors.h>
#include <pigpio.h>

enum Button {None = 0, B1 = 1, B2 = 2, B3 = 3, B4 = 4};

#define B1_GPIO   5
#define B2_GPIO   6
#define B3_GPIO   13
#define B4_GPIO   19

#define FP_IRQ_PIN  23


PIPASS_ERR init_gpio();
enum Button get_pressed_button();


#endif