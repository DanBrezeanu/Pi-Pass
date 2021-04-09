#include <commands.h>
#include <connection.h>
#include <command_execution.h>
#include <commands_utils.h>
#include <crypto.h>
#include <flags.h>
#include <aes256.h>
#include <authentication.h>

static uint8_t *auth_token = NULL;

static PIPASS_ERR _execute_app_hello(Cmd *cmd);
static PIPASS_ERR _execute_ask_for_pin(Cmd *cmd);
static PIPASS_ERR _execute_ask_for_password(Cmd *cmd);


PIPASS_ERR _execute_command(Cmd *cmd) {
    if (cmd == NULL)
        return ERR_SEND_CMD_INV_PARAMS;

    PIPASS_ERR err = PIPASS_OK;
    json_object *type = NULL;

    if (!json_object_object_get_ex(cmd->body, "type", &type) 
        || json_object_get_type(type) != json_type_int)
        return ERR_JSON_INVALID_KEY;

    switch (json_object_get_int(type)) {
    case APP_HELLO:
        return _execute_app_hello(cmd);
        break;
    case ASK_FOR_PIN:
        return _execute_ask_for_pin(cmd);
        break;
    case ASK_FOR_PASSWORD:
        return _execute_ask_for_password(cmd);
        break;
    default:
        err = ERR_UNKNOWN_COMMAND;
        break;
    }

    return err;
}


static PIPASS_ERR _execute_app_hello(Cmd *cmd) {
    PIPASS_ERR err;
    Cmd *cmd_hello = NULL;

    json_object *sender = NULL;
    json_object *is_reply = NULL;

    printf("Sending HELLO reply\n");

    if (!json_object_object_get_ex(cmd->body, "sender", &sender) 
        || json_object_get_type(sender) != json_type_int)
        return ERR_JSON_INVALID_KEY;

    if (!json_object_object_get_ex(cmd->body, "is_reply", &is_reply) 
        || json_object_get_type(is_reply) != json_type_boolean)
        return ERR_JSON_INVALID_KEY;

    if (json_object_get_int(sender) == SENDER_APP && !json_object_get_boolean(is_reply)) {
        
        /* Create reply */
        err = create_command(APP_HELLO, &cmd_hello);
        if (err != PIPASS_OK)
            goto error;

        /* Set options to either 0 or 1 depending if the device was unlocked */
        err = json_object_object_add(cmd_hello->body, "options", json_object_new_string(((FL_DB_INITIALIZED && FL_LOGGED_IN) ? "1" : "0")));
        if (err != PIPASS_OK)
            return ERR_CMD_JSON_ADD;

        printf("Before send_command\n");

        err = send_command(cmd_hello);
        if (err != PIPASS_OK)
            goto error;

        return PIPASS_OK;
    } else {
        err = ERR_CONN_INVALID_COMM;
        goto error;
    }

    err = PIPASS_OK;

error:
    free_command(&cmd_hello);
    return err;
}

static PIPASS_ERR _execute_ask_for_pin(Cmd *cmd) {
    PIPASS_ERR err;
    Cmd *cmd_send_pin = NULL;

    uint8_t *recvd_pin = NULL;

    json_object *sender   = NULL;
    json_object *is_reply = NULL;
    json_object *json_pin      = NULL;

    if (!json_object_object_get_ex(cmd->body, "sender", &sender) 
        || json_object_get_type(sender) != json_type_int)
        return ERR_JSON_INVALID_KEY;

    if (!json_object_object_get_ex(cmd->body, "is_reply", &is_reply) 
        || json_object_get_type(is_reply) != json_type_boolean)
        return ERR_JSON_INVALID_KEY;

    if (json_object_get_int(sender) == SENDER_APP && !json_object_get_boolean(is_reply)) {

        /* Create reply */
        err = create_command(ASK_FOR_PIN, &cmd_send_pin);
        if (err != PIPASS_OK)
            goto error;
        
        if (!FL_DB_INITIALIZED || !FL_LOGGED_IN) {
            goto reply_with_error;
        }
        
        /* Check pin was received */
        if (!json_object_object_get_ex(cmd->body, "options", &json_pin) ||
            json_object_get_type(json_pin) != json_type_string) {

           goto reply_with_error;
        } 

        /* Check pin size */
        if (json_object_get_string_len(json_pin) != MASTER_PIN_SIZE) {
            goto reply_with_error;
        }

        /* Check pin is correct */
        err = verify_master_pin_with_db(json_object_get_string(json_pin));
        if (err != PIPASS_OK) {
            goto reply_with_error;
        }
        printf("err verify_with_db: %.4X\n", err);

        /* Set new auth_token */
        if (auth_token != NULL) {
            erase_buffer(&auth_token, AUTH_TOKEN_SIZE);
        }
        
        err = get_rand_auth_token(&auth_token);
        if (err != PIPASS_OK)
            goto error;

        err = json_object_object_add(cmd_send_pin->body, "auth_token", json_object_new_string(auth_token));
        if (err != PIPASS_OK)
            return ERR_CMD_JSON_ADD;

        goto send;

    } else {
        err = ERR_PIN_NOT_ENTERED;
        goto error;
    }

reply_with_error:
    err = json_object_object_add(cmd_send_pin->body, "reply_code", json_object_new_int(1));
    if (err != PIPASS_OK) {
        err = ERR_CMD_JSON_ADD;
        goto error;
    }

send:
    err = send_command(cmd_send_pin);
    if (err != PIPASS_OK)
        goto error;

error:
    free_command(&cmd_send_pin);

    return err;
}

static PIPASS_ERR _execute_ask_for_password(Cmd *cmd) {
    PIPASS_ERR err;
    Cmd *cmd_ask_passw = NULL;

    json_object *sender = NULL;
    json_object *is_reply = NULL;
    json_object *options = NULL;

    printf("Sending ASK FOR PASSW reply\n");

    if (!json_object_object_get_ex(cmd->body, "sender", &sender) 
        || json_object_get_type(sender) != json_type_int)
        return ERR_JSON_INVALID_KEY;

    if (!json_object_object_get_ex(cmd->body, "is_reply", &is_reply) 
        || json_object_get_type(is_reply) != json_type_boolean)
        return ERR_JSON_INVALID_KEY;

    if (json_object_get_int(sender) == SENDER_APP && json_object_get_boolean(is_reply)) {
        FL_RECEIVED_PASSWORD = 1;
        
        json_object_object_get_ex(cmd->body, "options", &options);
        printf("Password received: %s\n", json_object_get_string(options));

        uint8_t *user = NULL;
        err = get_user(&user);
        err = authenticate(user, strlen(user), entered_pin, NULL, json_object_get_string(options), json_object_get_string_len(options));
        printf("user: %s   pin: %s passw: %s err: %X", user, entered_pin, json_object_get_string(options), err);
        
        /* Create reply */
        err = create_command(ASK_FOR_PASSWORD, &cmd_ask_passw);
        if (err != PIPASS_OK)
            goto error;

        /* Set options to either 0 or 1 depending if the device was unlocked */
        err = json_object_object_add(cmd_ask_passw->body, "options", json_object_new_string(((FL_DB_INITIALIZED && FL_LOGGED_IN) ? "1" : "0")));
        if (err != PIPASS_OK)
            return ERR_CMD_JSON_ADD;

        printf("Before send_command\n");

        err = send_command(cmd_ask_passw);
        if (err != PIPASS_OK)
            goto error;

        return PIPASS_OK;
    } else {
        err = ERR_CONN_INVALID_COMM;
        goto error;
    }

    err = PIPASS_OK;

error:
    free_command(&cmd_ask_passw);
    return err;
}






