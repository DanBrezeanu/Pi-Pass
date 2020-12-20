#ifndef __SCREENS_H__
#define __SCREENS_H__

#include <errors.h>
#include <defines.h>
#include <string.h>
#include <gpio_control.h>

#define MAIN_SCREEN         0xA0
#define FINGERPRINT_SCREEN  0xA1
#define SHUTDOWN_SCREEN     0xA3
#define PIN_SCREEN          0xA4
#define ERROR_SCREEN        0xA5

PIPASS_ERR show_screen(enum Button pressed);
PIPASS_ERR pin_screen(enum Button pressed);
PIPASS_ERR main_screen(enum Button pressed);
PIPASS_ERR shutdown_screen(enum Button pressed);
PIPASS_ERR fingerprint_screen(enum Button pressed);
PIPASS_ERR wrong_pin_screen(enum Button pressed);


#endif