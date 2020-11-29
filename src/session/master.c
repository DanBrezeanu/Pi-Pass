#include <connection.h>
#include <commands.h>
// #include <actions.h>
// #include <credentials.h>
// #include <database.h>
// #include <authentication.h>
#include <pthread.h>
#include <gpio_control.h>
#include <display.h>
#include <screens_stack.h>


void *connection_loop(void *arg) {
    PIPASS_ERR err;
    Command *cmd = NULL;

    err = open_connection();
    if (err != PIPASS_OK) {
        printf("%X\n", err);
        return NULL;
    }

    while (1) {
        err = PIPASS_OK;

        if (command_to_send != NO_COMMAND) {
            err = create_command(command_to_send, &cmd);
            if (err != PIPASS_OK)
                goto error;

            err = send_command(cmd);
            if (err != PIPASS_OK)
                goto error;
            
            do {
                err = change_command_to_send(NO_COMMAND, 1);                
            } while (err != PIPASS_OK);
        } else {
            err = recv_command(&cmd);
            if (err != PIPASS_OK)
                goto error;

            printf("%s\n", cmd->options);
            err = execute_command(cmd);
            printf("Execution err = %.4X\n", err);
        }

error:
        cmd = NULL;
        // printf("%X\n", err);
        usleep(100000);
    }
}

void *device_loop(void *arg) {
    enum Button pressed = None;
    display_func screen = NULL;
    PIPASS_ERR err;

    pthread_mutex_lock(&display_lock);
    err = show_screen(None);
    printf("%X\n", err);
    while (1) {
        
        pressed = get_pressed_button();
        
        if (pressed != None || (pressed == None && stack_top() != screen)) {
            err = show_screen(pressed);
            
            usleep(10000);
        } else {
            usleep(1000);
        }

        screen = stack_top();
    }

    pthread_mutex_unlock(&display_lock);

}

void init_device() {
    pthread_t conn_thread, device_thread;
    PIPASS_ERR err;

    Py_Initialize();

    init_gpio();

    err = init_display();
    if (err != PIPASS_OK)
        return;

    stack_push(fingerprint_screen);

    pthread_create(&device_thread, NULL, device_loop, NULL);
    sleep(1);
    pthread_create(&conn_thread, NULL, connection_loop, NULL);
    pthread_join(device_thread, NULL);

    Py_Finalize();
}

// int main() {
//     init_device();
// }