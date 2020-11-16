#include <screens.h>

PIPASS_ERR main_screen(enum Button pressed) {
    const uint32_t num_options = 4;
    enum Options {CREDENTIALS, SETTINGS, LOCK, SHUTDOWN};
    static enum Options options = CREDENTIALS; 

    switch (pressed) {
    case B1:
        options = (options + num_options - 1) % num_options;
        break;
    case B2:
        /* select */
        break;
    case B3:
        /* do nothing, can't go back from main screen */
        break;
    case B4:
        options = (options + 1) % num_options;
        break;
    }

    draw_screen(MAIN_SCREEN, (int32_t)options);
}

#include <display.h>

int main() {
    Py_Initialize();
    init_display();
    main_screen(2);

    sleep(5);
    Py_Finalize();

    return 0;
}