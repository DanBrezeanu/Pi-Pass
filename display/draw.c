#include <draw.h>
#include <draw_basic.h>
#include <screens.h>

static PIPASS_ERR _draw_main_screen(int32_t option);

PIPASS_ERR draw_screen(uint8_t screen, int32_t option) {
    switch (screen) {
    case MAIN_SCREEN:
        return _draw_main_screen(option);
    default:
        return ERR_DISPLAY_NO_SUCH_SCREEN;
    }

}

static PIPASS_ERR _draw_main_screen(int32_t option) {
    enum Options {CREDENTIALS, SETTINGS, LOCK, SHUTDOWN};

    switch (option) {
    case CREDENTIALS:
        
    }
}



