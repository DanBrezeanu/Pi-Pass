#include <screens.h>
#include <screens_stack.h>
#include <draw.h>
#include <display.h>
#include <connection.h>
#include <commands.h>
#include <crypto.h>
#include <unistd.h>
#include <pthread.h>
#include <fingerprint.h>

PIPASS_ERR show_screen(enum Button pressed) {
    PIPASS_ERR err;
    int32_t ret;

    ret = pthread_mutex_trylock(&display_lock);
    if (ret != 0) {
        return ERR_DISPLAY_BUSY;
    }

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
    pthread_mutex_unlock(&display_lock);

    return err;
}

PIPASS_ERR pin_screen(enum Button pressed) {
    const uint32_t num_options = 5;
    enum Options {FIRST_DIGIT = 0, SECOND_DIGIT, THIRD_DIGIT, FOURTH_DIGIT, DONE};
    static enum Options options = FIRST_DIGIT;

    static uint8_t digits[4] = {0};

    switch (pressed) {
    case B1:
        if (options != DONE)
            options = (options + num_options - 1) % num_options;
        else
            options =  (options + 1) % num_options;
        break;
    case B2:
        if (options == DONE) {
            PIPASS_ERR err;

            for (int32_t i = 0; i < MASTER_PIN_SIZE; ++i)
                digits[i] += '0';

            err = verify_master_pin_with_db(digits);
            if (err != PIPASS_OK)
                stack_push(wrong_pin_screen);
            else
                stack_push(fingerprint_screen);

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
        if (options != DONE)
            options = (options + 1) % num_options;
        else
            options = (options + num_options - 1) % num_options;
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

PIPASS_ERR fingerprint_screen(enum Button pressed) {
    const uint32_t num_options = 2;
    enum Options {LOGIN_WITH_PASSW, NONE};
    static enum Options options = NONE;
    static pthread_t *fp_thread = NULL;
    static struct async_fp_data *data = NULL;
    int32_t ret = 0;

    if (fp_thread == NULL) {
        fp_thread = calloc(1, sizeof(pthread_t));
        data = calloc(1, sizeof(struct async_fp_data));        
        pthread_create(fp_thread, NULL, fp_async_get_fingerprint, data);    
    }

    if (fp_thread != NULL) {
        struct timespec ts;

        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += 50000000; // 0.05 sec

        ret = pthread_timedjoin_np(*fp_thread, NULL, &ts);
        if (ret == 0) {
            if (data->err == 0) {
                stack_push(main_screen);
            }
           
            free(data);
            free(fp_thread);
            data = NULL;
            fp_thread = NULL;
        }
    }

    switch (pressed) {
    case B1:
        options = (options + num_options - 1) % num_options;
        break;
    case B2:
        /* Send command to PC */
        if (options == LOGIN_WITH_PASSW) {
            if (fp_thread != NULL) {
                data->stop = 1;
                usleep(200000); // wait for thread to end properly
                free(data);
                free(fp_thread);

                data = NULL;
                fp_thread = NULL;
            }
            
            stack_push(main_screen);
        }

        break;
    case B3:
        break;
    case B4:
        options = (options +  1) % num_options;
    case None:
        break;
    }

    return draw_screen(FINGERPRINT_SCREEN, (int32_t)options, 0);
}

PIPASS_ERR wrong_pin_screen(enum Button pressed) {
    PIPASS_ERR err = draw_screen(ERROR_SCREEN, 0, 1, "Wrong pin. \n Please try again.");
    stack_pop();

    return err;
}