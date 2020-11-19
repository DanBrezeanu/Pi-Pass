#include <draw.h>
#include <screens.h>
#include <display.h>
#include <draw_basic.h>

static PIPASS_ERR _draw_main_screen(int32_t option);
static PIPASS_ERR _draw_shutdown_screen(int32_t option);
static PIPASS_ERR _draw_menu_tile(uint8_t *image, int32_t image_x, int32_t image_y, uint8_t *text, 
  int32_t text_x, int32_t text_y, PyObject **canvas);

PIPASS_ERR draw_screen(uint8_t screen, int32_t option) {

    switch (screen) {
    case MAIN_SCREEN:
        return _draw_main_screen(option);
    case SHUTDOWN_SCREEN:
        return _draw_shutdown_screen(option);
    default:
        return ERR_DISPLAY_NO_SUCH_SCREEN;
    }
}

static PIPASS_ERR _draw_controls(uint8_t *o1, uint8_t *o2, uint8_t *o3, uint8_t *o4, PyObject *canvas) {
    if (o1 == NULL || o2 == NULL || o3 == NULL || o4 == NULL || canvas == NULL)
        return ERR_DRAW_CONTROLS_INV_PARAMS;
    
    PIPASS_ERR err;
    
    err = draw_rectangle(0, 56, 28,  63, "white", "white", canvas);
    if (err != PIPASS_OK)
        goto error;

    err = draw_rectangle(33, 56, 61,  63, "white", "white", canvas);
    if (err != PIPASS_OK)
        goto error;

    err = draw_rectangle(65, 56, 94,  63, "white", "white", canvas);
    if (err != PIPASS_OK)
        goto error;

    err = draw_rectangle(99, 56, 127, 63, "white", "white", canvas);
    if (err != PIPASS_OK)
        goto error;

    err = draw_text(0, 54, o1, "black", FREEPIXEL_FONT, canvas, ALIGN_TEXT,
      ALIGN_CENTER, 28, 63);
    if (err != PIPASS_OK)
        goto error;

    err = draw_text(33, 54, o2, "black", FREEPIXEL_FONT, canvas, ALIGN_TEXT,
      ALIGN_CENTER, 61, 63);
    if (err != PIPASS_OK)
        goto error;

    err = draw_text(65, 54, o3, "black", FREEPIXEL_FONT, canvas, ALIGN_TEXT,
      ALIGN_CENTER, 94, 63);
    if (err != PIPASS_OK)
        goto error;

    err = draw_text(99, 54, o4, "black", FREEPIXEL_FONT, canvas, ALIGN_TEXT,
      ALIGN_CENTER, 127, 63);
    if (err != PIPASS_OK)
        goto error;

    return PIPASS_OK;

error:
    return err;
}

static PIPASS_ERR _draw_main_screen(int32_t option) {
    enum Options {CREDENTIALS, SETTINGS, LOCK, SHUTDOWN};

    PyObject *canvas = NULL;
    PIPASS_ERR err;

    switch (option) {
    case CREDENTIALS:
        err = _draw_menu_tile(CREDENTIALS_IMAGE, 40, 0, "Credentials", 0, 42, &canvas);
        if (err != PIPASS_OK)
            goto error;
        break;
    case SETTINGS:
        err = _draw_menu_tile(SETTINGS_IMAGE, 40, 0, "Settings", 0, 42, &canvas);
        if (err != PIPASS_OK)
            goto error;
        break;
    case LOCK:
        err = _draw_menu_tile(LOCK_IMAGE, 45, 2, "Lock", 0, 42, &canvas);
        if (err != PIPASS_OK)
            goto error;
        break;
    case SHUTDOWN:
        err = _draw_menu_tile(SHUTDOWN_IMAGE, 40, 0, "Shutdown", 0, 42, &canvas);
        if (err != PIPASS_OK)
            goto error;
        break;
    }

    err = _draw_controls("Prev", "Enter", "Back", "Next", canvas);
    if (err != PIPASS_OK)
        goto error;

    display(canvas);

error:

    return err;
}

static PIPASS_ERR _draw_shutdown_screen(int32_t option) {
    enum Options {YES, NO};

    PyObject *canvas = NULL;
    PIPASS_ERR err;

    err = create_canvas(NULL, &canvas);
    if (err != PIPASS_OK)
        goto error;

    err = draw_text(0, 2, "Power off the device?", "white",
     FREEPIXEL_FONT, canvas, ALIGN_TEXT, ALIGN_CENTER, DISPLAY_WIDTH, 20);
    if (err != PIPASS_OK)
        goto error;

    switch (option) {
    case YES:
        err = draw_rectangle(30, 30, 50, 40, "white", "white", canvas);
        if (err != PIPASS_OK)
            goto error;
        
        err = draw_text(31, 30, "Yes", "black", FREEPIXEL_FONT, canvas, ALIGN_TEXT,
          ALIGN_CENTER, 50, 40);
        if (err != PIPASS_OK)
            goto error;

        err = draw_text(78, 30, "No", "white", FREEPIXEL_FONT, canvas, ALIGN_TEXT,
          ALIGN_CENTER, 97, 40);
        if (err != PIPASS_OK)
            goto error;

        break;

    case NO:
        err = draw_rectangle(77, 30, 97, 40, "white", "white", canvas);
        if (err != PIPASS_OK)
            goto error;
        
        err = draw_text(31, 30, "Yes", "white", FREEPIXEL_FONT, canvas, ALIGN_TEXT,
          ALIGN_CENTER, 50, 40);
        if (err != PIPASS_OK)
            goto error;

        err = draw_text(78, 30, "No", "black", FREEPIXEL_FONT, canvas, ALIGN_TEXT,
          ALIGN_CENTER, 97, 40);
        if (err != PIPASS_OK)
            goto error;

        break;
    }

    err = _draw_controls("Prev", "Enter", "Back", "Next", canvas);
    if (err != PIPASS_OK)
        goto error;

    display(canvas);

error:

    return err;
}

static PIPASS_ERR _draw_menu_tile(uint8_t *image, int32_t image_x, int32_t image_y, uint8_t *text, 
  int32_t text_x, int32_t text_y, PyObject **canvas) {
    if (image == NULL || text == NULL)
        return ERR_DRAW_MENU_TILE_INV_PARAMS;

    PyObject *background = NULL;
    PIPASS_ERR err;

    err = draw_image(image_x, image_y, image, &background);
    if (err != PIPASS_OK)
        goto error;

    err = create_canvas(background, canvas);
    if (err != PIPASS_OK)
        goto error;

    err = draw_text(text_x, text_y, text, "white", DEFAULT_FONT, *canvas, ALIGN_TEXT,
        ALIGN_CENTER, DISPLAY_WIDTH, text_y);
    if (err != PIPASS_OK)
        goto error;

    err = PIPASS_OK;

error:
    return err;
}


