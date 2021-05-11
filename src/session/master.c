#include <connection.h>
#include <commands.h>
#include <actions.h>
#include <credentials.h>
#include <database.h>
#include <authentication.h>
#include <pthread.h>
#include <gpio_control.h>
#include <display.h>
#include <screens_stack.h>
#include <storage.h>
#include <registration.h>
#include <fingerprint.h>
#include <command_execution.h>
#include <json.h>


void *connection_loop(void *arg) {
    PIPASS_ERR err;
    Cmd *cmd = NULL;

    err = open_connection();
    if (err != PIPASS_OK) {
        printf("%X\n", err);
        return NULL;
    }

    while (1) {
        err = PIPASS_OK;

        if (command_to_send != NO_COMMAND) {
            printf("[INFO]  New command: %.2X\n", command_to_send);
            printf("[INFO]       Creating command %.2X\n", command_to_send);
            err = create_command(command_to_send, &cmd);
            if (err != PIPASS_OK) {
                printf("[ERROR]       Command creation failed %.2X. Err: %.4X\n", command_to_send, err);            
                goto error;
            }
            printf("[INFO]       Command created %.2X\n", command_to_send);

            printf("[INFO]       Sending command %.2X\n", command_to_send);
            err = send_command(cmd);
            if (err != PIPASS_OK) {
                printf("[ERROR]       Sending command failed %.2X. Err: %.4X\n", command_to_send, err);
                goto error;
            }
            printf("[INFO]       Command sent %.2X\n", command_to_send);
            
            do {
                err = change_command_to_send(NO_COMMAND, 1);                
            } while (err != PIPASS_OK);
        } else {
            json_object *type;

            err = recv_command(&cmd);
            if (err != PIPASS_OK)
                goto error;

            json_object_object_get_ex(cmd->body, "type", &type);
            printf("[INFO]  Command received: %.2X\n", json_object_get_int(type));

            printf("[INFO]       Executing command: %.2X\n", json_object_get_int(type));
            err = execute_command(cmd);
            if (err != PIPASS_OK)
                printf("[ERROR]       Command execution failed: %.2X. Err: %.4X\n", json_object_get_int(type), err);
            else
                printf("[INFO]        Command executed: %.2X\n", json_object_get_int(type));
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
    uint32_t elapsed = 0;

    while (1) {        
        pressed = get_pressed_button();
        
        if (pressed != None || (pressed == None && stack_top() != screen) || elapsed > REFRESH_RATE * 10) {
            err = show_screen(pressed);
            elapsed = 0;
            usleep(50000);
        } else {
            usleep(1000);
            elapsed += 1000;
        }

        screen = stack_top();
    }

    pthread_mutex_unlock(&display_lock);

}

void init_device() {
    pthread_t conn_thread, device_thread;
    PIPASS_ERR err;

    uint8_t *user = NULL;
    err = get_user(&user);
    if (err != PIPASS_OK) {
        printf("get_user %X\n", err);
        return;
    }

    uint8_t *user_hash = NULL;
    err = generate_user_hash(user, strlen(user), &user_hash);
    if (err != PIPASS_OK) {
        printf("generate_user_hash %X\n", err);
        return;
    }

    err = init_db_header(user_hash);
    if (err != PIPASS_OK) {
        printf("init_db_header %X\n", err);
        return;
    }

    Py_Initialize();
    init_gpio();
    init_fingerprint();
    fp_verify_pin("0000");

    err = init_display();
    if (err != PIPASS_OK)
        return;

    stack_push(pin_screen);

    pthread_create(&device_thread, NULL, device_loop, NULL);
    sleep(1);

    pthread_create(&conn_thread, NULL, connection_loop, NULL);
    pthread_join(device_thread, NULL);

    Py_Finalize();
}

int main() {
    init_gpio();
    init_fingerprint();
    fp_verify_pin("0000");
    PIPASS_ERR err;
    uint8_t *fp_key = NULL;
    uint16_t index;
    // err =  fp_enroll_fingerprint(&index);
    // err =  fp_get_fingerprint(&fp_key);
    // if (err != PIPASS_OK) {
    //     printf("fp_get %X\n", err);
    //     return 0;
    // }

    // register_new_user("test", strlen("test"), "1234", fp_key, "parola", strlen("parola"));
    // if (err != PIPASS_OK) {
    //     printf("%X\n", err);
    //     return 0;
    // }


    // err = authenticate("test", strlen("test"), "1234", NULL, "parola", 6);
    // printf("%.4X", err);
    
    // uint8_t *user_hash = NULL;

    // err = generate_user_hash("test", strlen("test"), &user_hash);
    // printf("%.4X\n", err);

    // err = remove_credential(user_hash, "Insta", strlen("Insta"));
    // printf("%.4X", err);

    // uint16_t fields_names_len[] = {strlen("name"), strlen("url"), strlen("user"), strlen("password")};
    // uint8_t *fields_names[] = {"name", "url", "user", "password"};
    // uint16_t fields_data_len[] = {strlen("facebook"), strlen("https://facebook.com"), strlen("MyFacebookName"), strlen("MyFacebookPassword")};
    // uint8_t fields_encrypted[] = {0, 0, 1, 1};
    // uint8_t *fields_data[] = {"facebook", "https://facebook.com", "MyFacebookName", "MyFacebookPassword"};

    // err = register_new_credential(user_hash, PASSWORD_TYPE, 4, fields_names_len, fields_names, fields_data_len, fields_encrypted, fields_data);
    // printf("%.4X\n", err);

    init_device();
}