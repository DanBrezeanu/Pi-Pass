#include <screens.h>
#include <screens_stack.h>
#include <draw.h>
#include <display.h>

PIPASS_ERR show_screen(enum Button pressed) {
    PIPASS_ERR err;

    if (stack_empty()) {
        clear_screen();
        err = ERR_DISPLAY_NO_SCREEN_TO_SHOW;
        goto error;
    }

    display_func screen = stack_top();
    if (screen == NULL) {
        clear_screen();
        err = ERR_DISPLAY_NO_SCREEN_TO_SHOW;
        goto error;
    }

    err = screen(pressed);
    if (err != PIPASS_OK) {
        goto error;
    }

error:
    return err;
}

PIPASS_ERR pin_screen(enum Button pressed) {
    const uint32_t num_options = 5;
    enum Options {FIRST_DIGIT = 0, SECOND_DIGIT, THIRD_DIGIT, FOURTH_DIGIT, DONE};
    static enum Options options = FIRST_DIGIT;

    static uint8_t digits[4] = {0};

    switch (pressed) {
    case B1:
        options = (options + num_options - 1) % num_options;
        break;
    case B2:
        if (options == DONE) {
            stack_push(main_screen);
            goto cleanup;
        } else {
            digits[options] = (digits[options] + 10 - 1) % 10;
        }
        break;
    case B3:
        if (options == DONE) {
            stack_pop();
            goto cleanup;
        } else {
            digits[options] = (digits[options] + 1) % 10;
        }
        break;
    case B4:
        options = (options + 1) % num_options;
        break;
    case None:
        break;
    }    

    return draw_screen(PIN_SCREEN, (int32_t)options, 1, digits);

cleanup:
    memset(digits, 0, 4 * sizeof(uint8_t));
    options = 0;

    return PIPASS_OK;
}


PIPASS_ERR main_screen(enum Button pressed) {
    const uint32_t num_options = 4;
    enum Options {CREDENTIALS, SETTINGS, LOCK, SHUTDOWN};
    static enum Options options = CREDENTIALS; 

    switch (pressed) {
    case B1:
        options = (options + num_options - 1) % num_options;
        break;
    case B2:
        switch (options) {
        case CREDENTIALS:
            break;
        case SETTINGS:
            break;
        case LOCK:
            break;
        case SHUTDOWN:
            stack_push(shutdown_screen);
            return PIPASS_OK;
        default:
            break;
        }
        break;
    case B3:
        /* do nothing, can't go back from main screen */
        break;
    case B4:
        options = (options + 1) % num_options;
        break;
    case None:
        break;
    }

    return draw_screen(MAIN_SCREEN, (int32_t)options, 0);
}

PIPASS_ERR shutdown_screen(enum Button pressed) {
    const uint32_t num_options = 2;
    enum Options {YES, NO};
    static enum Options options = NO; 

    switch (pressed) {
    case B1:
        options = (options + num_options - 1) % num_options;
        break;
    case B2:
        /* select */
        break;
    case B3:
        stack_pop();
        return PIPASS_OK;
        break;
    case B4:
        options = (options + 1) % num_options;
        break;
    case None:
        break;
    }

    return draw_screen(SHUTDOWN_SCREEN, (int32_t)options, 0);
}

int main() {
    PIPASS_ERR err;

    Py_Initialize();
    
    err = init_display();
    if (err != PIPASS_OK) {
        printf("%X\n", err);
        return err;
    }
    
    stack_push(pin_screen);

    show_screen(0);
    sleep(1);

    for (int i = 0; i < 11; ++i) {
        show_screen(3);
        sleep(1);
    }

    show_screen(4);
    sleep(1);

    for (int i = 0; i < 2; ++i) {
        show_screen(3);
        sleep(1);
    }

    show_screen(4);
    sleep(1);

    for (int i = 0; i < 3; ++i) {
        show_screen(3);
        sleep(1);
    }

    show_screen(4);
    sleep(1);

    for (int i = 0; i < 4; ++i) {
        show_screen(3);
        sleep(1);
    }

    show_screen(4);
    sleep(1);

    show_screen(4);
    sleep(1);




    // show_screen(2);
    // sleep(3);
    // show_screen(2);
    // sleep(3);
    // show_screen(2);
    // sleep(3);
    // show_screen(2);
    // sleep(3);
    // show_screen(1);
    // sleep(3);
    // show_screen(4);
    // sleep(1);
    // show_screen(4);
    // sleep(1);
    // show_screen(4);
    // sleep(1);
    // show_screen(2);
    // show_screen(0);
    // sleep(1);
    // show_screen(4);
    // sleep(1);
    // show_screen(4);
    // sleep(1);
    // show_screen(3);
    // show_screen(0);
    // sleep(1);
    // show_screen(1);
    // sleep(1);

    // main_screen(3);
    // sleep(1);
    // main_screen(4);
    // sleep(1);
    // main_screen(4);
    // sleep(1);


    Py_Finalize();

    return 0;
}