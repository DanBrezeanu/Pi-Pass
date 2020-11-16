#include <draw.h>
#include <screens.h>
#include <display.h>

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

    PyObject *background = NULL, *canvas = NULL;
    PIPASS_ERR err;

    switch (option) {
    case CREDENTIALS:
        err = draw_image(15, 0, CREDENTIALS_IMAGE, &background);
        if (err != PIPASS_OK)
            goto error;

        err = create_canvas(background, &canvas);
        if (err != PIPASS_OK)
            goto error;

        err = draw_text(5, 50, "Credentials", canvas);
        if (err != PIPASS_OK)
            goto error;
    case SETTINGS:
        break;
    case LOCK:
        break;
    case SHUTDOWN:
        break;
    }

    display(canvas);

error:
    return err;
}



