#ifndef __SCREENS_H__
#define __SCREENS_H__

#include <errors.h>
#include <defines.h>
#include <string.h>

enum Button {None = 0, B1 = 1, B2 = 2, B3 = 3, B4 = 4};

#define MAIN_SCREEN     0xA0
#define SHUTDOWN_SCREEN 0xA3
#define PIN_SCREEN      0xA4

PIPASS_ERR show_screen(enum Button pressed);
PIPASS_ERR pin_screen(enum Button pressed);
PIPASS_ERR main_screen(enum Button pressed);
PIPASS_ERR shutdown_screen(enum Button pressed);


#endif