#include <draw.h>
#include <screens.h>
#include <display.h>
#include <draw_basic.h>

static PIPASS_ERR _draw_main_screen(int32_t option);
static PIPASS_ERR _draw_shutdown_screen(int32_t option);
static PIPASS_ERR _draw_menu_tile(uint8_t *image, int32_t image_x, int32_t image_y, uint8_t *text, 
  int32_t text_x, int32_t text_y, PyObject **canvas);
static PIPASS_ERR _draw_pin_screen(int32_t option, va_list args);
static PIPASS_ERR _draw_error_screen(va_list args);
static PIPASS_ERR _draw_fingerprint_screen(int32_t option, va_list args);
static PIPASS_ERR _draw_waiting_for_password_screen(int32_t option);

PIPASS_ERR draw_screen(uint8_t screen, int32_t option, int32_t nargs, ...) {
    PIPASS_ERR err;
    va_list args;
    va_start(args, nargs);

    switch (screen) {
    case PIN_SCREEN:
        err = _draw_pin_screen(option, args);
        break;
    case FINGERPRINT_SCREEN:
        err = _draw_fingerprint_screen(option, args);
        break;
    case MAIN_SCREEN:
        err = _draw_main_screen(option);
        break;
    case SHUTDOWN_SCREEN:
        err = _draw_shutdown_screen(option);
        break;
    case WAITING_FOR_PASSWORD_SCREEN:
        err = _draw_waiting_for_password_screen(option);
        break;
    case ERROR_SCREEN:
        err = _draw_error_screen(args);
        break;

    default:
        err = ERR_DISPLAY_NO_SUCH_SCREEN;
    }

    va_end(args);

    return err;
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

    err = draw_text(0, 54, o1, "black", NO_HIGHLIGHT, FREEPIXEL_FONT, canvas, ALIGN_TEXT,
      ALIGN_CENTER, 28, 63);
    if (err != PIPASS_OK)
        goto error;

    err = draw_text(33, 54, o2, "black", NO_HIGHLIGHT, FREEPIXEL_FONT, canvas, ALIGN_TEXT,
      ALIGN_CENTER, 61, 63);
    if (err != PIPASS_OK)
        goto error;

    err = draw_text(65, 54, o3, "black", NO_HIGHLIGHT, FREEPIXEL_FONT, canvas, ALIGN_TEXT,
      ALIGN_CENTER, 94, 63);
    if (err != PIPASS_OK)
        goto error;

    err = draw_text(99, 54, o4, "black", NO_HIGHLIGHT, FREEPIXEL_FONT, canvas, ALIGN_TEXT,
      ALIGN_CENTER, 127, 63);
    if (err != PIPASS_OK)
        goto error;

    return PIPASS_OK;

error:
    return err;
}


static PIPASS_ERR _draw_pin_screen(int32_t option, va_list args) {
    enum Options {FIRST_DIGIT = 0, SECOND_DIGIT, THIRD_DIGIT, FOURTH_DIGIT, DONE};

    PyObject *canvas = NULL, *_ = NULL;
    PIPASS_ERR err;

    err = create_canvas(NULL, &canvas);
    if (err != PIPASS_OK)
        goto error;

    uint8_t digit_buffer[2] = {0};
    uint8_t *digits = va_arg(args, uint8_t *);

    if (option != DONE) {
        err = draw_rectangle(option * (DISPLAY_WIDTH / 4) + 4, 1, (option * (DISPLAY_WIDTH / 4) + 23),
        26, "white", "white", canvas);
    }
    for (int32_t i = 0; i < 4; ++i) {
        sprintf(digit_buffer, "%d", (int32_t)digits[i]);
        err = draw_text(
            (i * (DISPLAY_WIDTH / 4)),
            0,
            digit_buffer,
            (option == i) ? "black" : "white",
            NO_HIGHLIGHT,
            PIXELMIX_FONT,
            canvas,
            ALIGN_TEXT,
            ALIGN_CENTER,
            ((i + 1) * (DISPLAY_WIDTH / 4)),
            0
        );
    }

    err = draw_text(0, 30, "Done", ((option == DONE) ? "black" : "white"),
      ((option == DONE) ? WITH_HIGHLIGHT : NO_HIGHLIGHT), DEFAULT_FONT, canvas,
       ALIGN_TEXT,ALIGN_CENTER, DISPLAY_WIDTH, 30);
    if (err != PIPASS_OK)
        goto error;

    if (option != DONE)
        err = _draw_controls(CARET_LEFT, CARET_UP, CARET_DOWN, CARET_RIGHT, canvas);
    else
        err = _draw_controls(CARET_LEFT, "Enter", "Back", CARET_RIGHT, canvas);

    if (err != PIPASS_OK)
        goto error;

    display(canvas);

    get_and_call_function(canvas, "__exit__", &_, 0);

error:
    // Py_XDECREF(canvas);
    // PyObject_Free(canvas);

    return err;
}

static PIPASS_ERR _draw_fingerprint_screen(int32_t option, va_list args) {
    enum Options {LOGIN_WITH_PASSW, NONE};

    PyObject *background = NULL;
    PyObject *canvas = NULL;
    PIPASS_ERR err;


    err = draw_image(50, 1, FINGERPRINT_IMAGE, &background);
    if (err != PIPASS_OK)
        goto error;

    err = create_canvas(background, &canvas);
    if (err != PIPASS_OK)
        goto error;

    err = draw_text(0, 20, "Authenticate with\n password instead", ((option == LOGIN_WITH_PASSW) ? "black" : "white"),
      ((option == LOGIN_WITH_PASSW) ? WITH_HIGHLIGHT : NO_HIGHLIGHT), SMALLPIXEL_FONT, canvas,
       ALIGN_TEXT, ALIGN_CENTER, DISPLAY_WIDTH, DISPLAY_HEIGHT);

    err = _draw_controls(CARET_LEFT, "Enter", "", CARET_RIGHT, canvas);

    display(canvas);

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

    err = _draw_controls(CARET_LEFT, "Enter", "Back", CARET_RIGHT, canvas);
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

    err = draw_text(0, 2, "Power off the device?", "white", NO_HIGHLIGHT,
     FREEPIXEL_FONT, canvas, ALIGN_TEXT, ALIGN_CENTER, DISPLAY_WIDTH, 20);
    if (err != PIPASS_OK)
        goto error;

    switch (option) {
    case YES:        
        err = draw_text(31, 30, "Yes", "black", WITH_HIGHLIGHT,
          FREEPIXEL_FONT, canvas, ALIGN_TEXT, ALIGN_CENTER, 50, 40);
        if (err != PIPASS_OK)
            goto error;

        err = draw_text(78, 30, "No", "white", NO_HIGHLIGHT,
          FREEPIXEL_FONT, canvas, ALIGN_TEXT, ALIGN_CENTER, 97, 40);
        if (err != PIPASS_OK)
            goto error;

        break;

    case NO:
        err = draw_rectangle(77, 30, 97, 40, "white", "white", canvas);
        if (err != PIPASS_OK)
            goto error;
        
        err = draw_text(31, 30, "Yes", "white", NO_HIGHLIGHT,
          FREEPIXEL_FONT, canvas, ALIGN_TEXT, ALIGN_CENTER, 50, 40);
        if (err != PIPASS_OK)
            goto error;

        err = draw_text(78, 30, "No", "black", WITH_HIGHLIGHT,
          FREEPIXEL_FONT, canvas, ALIGN_TEXT, ALIGN_CENTER, 97, 40);
        if (err != PIPASS_OK)
            goto error;

        break;
    }

    err = _draw_controls(CARET_LEFT, "Enter", "Back", CARET_RIGHT, canvas);
    if (err != PIPASS_OK)
        goto error;

    display(canvas);

error:

    return err;
}

static PIPASS_ERR _draw_waiting_for_password_screen(int32_t option) {
    enum Options {CANCEL, NONE};

    PyObject *canvas = NULL;
    PIPASS_ERR err;

    err = create_canvas(NULL, &canvas);
    if (err != PIPASS_OK)
        goto error;

    err = draw_text(0, 2, "Type the password in\n   the application", "white", NO_HIGHLIGHT,
     FREEPIXEL_FONT, canvas, ALIGN_TEXT, ALIGN_CENTER, DISPLAY_WIDTH, 20);
    if (err != PIPASS_OK)
        goto error;

    switch (option) {
    case CANCEL:        
        err = draw_text(30, 40, "CANCEL", "black", WITH_HIGHLIGHT,
          FREEPIXEL_FONT, canvas, ALIGN_TEXT, ALIGN_CENTER, 90, 40);
        if (err != PIPASS_OK)
            goto error;

        break;

case NONE:
        err = draw_text(0, 40, "CANCEL", "white", NO_HIGHLIGHT,
          FREEPIXEL_FONT, canvas, ALIGN_TEXT, ALIGN_CENTER, DISPLAY_WIDTH, 40);
        if (err != PIPASS_OK)
            goto error;

        break;
    }

    err = _draw_controls(CARET_LEFT, "Enter", "Back", CARET_RIGHT, canvas);
    if (err != PIPASS_OK)
        goto error;

    display(canvas);

error:

    return err;
}

static PIPASS_ERR _draw_error_screen(va_list args) {
    PyObject *canvas = NULL;
    PIPASS_ERR err;

    err = create_canvas(NULL, &canvas);
    if (err != PIPASS_OK)
        goto error;

    uint8_t *text = va_arg(args, uint8_t *);

    err = draw_text(0, 0, text, "white", NO_HIGHLIGHT, FREEPIXEL_FONT, canvas, ALIGN_TEXT,
            ALIGN_CENTER, DISPLAY_WIDTH, DISPLAY_HEIGHT);
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

    err = draw_text(text_x, text_y, text, "white", NO_HIGHLIGHT,
      DEFAULT_FONT, *canvas, ALIGN_TEXT, ALIGN_CENTER, DISPLAY_WIDTH, text_y);
    if (err != PIPASS_OK)
        goto error;

    err = PIPASS_OK;


error:
    return err;
}

