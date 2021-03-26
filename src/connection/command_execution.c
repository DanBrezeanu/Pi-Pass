#include <commands.h>
#include <connection.h>
#include <command_execution.h>
#include <commands_utils.h>
#include <crypto.h>
#include <flags.h>
#include <aes256.h>

static uint8_t *auth_token = NULL;

static PIPASS_ERR _execute_app_hello(Cmd *cmd);
static PIPASS_ERR _execute_ask_for_pin(Cmd *cmd);


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
    default:
        err = ERR_UNKNOWN_COMMAND;
        break;
    }

    return err;
}


static PIPASS_ERR _execute_app_hello(Cmd *cmd) {
    PIPASS_ERR err;
    Cmd *cmd_hello = NULL;

    uint8_t *auth_token = NULL;

    json_object *sender = NULL;
    json_object *is_reply = NULL;

    if (!json_object_object_get_ex(cmd->body, "sender", &sender) 
        || json_object_get_type(sender) != json_type_int)
        return ERR_JSON_INVALID_KEY;

    if (!json_object_object_get_ex(cmd->body, "is_reply", &is_reply) 
        || json_object_get_type(is_reply) != json_type_boolean)
        return ERR_JSON_INVALID_KEY;

    if (json_object_get_int(sender) == SENDER_APP && !json_object_get_boolean(is_reply)) {
        
        err = create_command(APP_HELLO, &cmd_hello);
        if (err != PIPASS_OK)
            goto error;

        err = json_object_object_add(cmd_hello->body, "is_reply", json_object_new_boolean(1));
        if (err != PIPASS_OK)
            return ERR_CMD_JSON_ADD;

        err = get_rand_auth_token(&auth_token);
        if (err != PIPASS_OK)
            goto error;

        err = json_object_object_add(cmd_hello->body, "auth_token", json_object_new_string(auth_token));
        if (err != PIPASS_OK)
            return ERR_CMD_JSON_ADD;

        err = calculate_crc(cmd_hello, &(cmd_hello->crc));
        if (err != PIPASS_OK)
            goto error; 

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
    if (!FL_LOGGED_IN || !FL_DB_HEADER_LOADED)
        return ERR_NOT_LOGGED_IN;

    PIPASS_ERR err;
    Cmd *cmd_send_pin = NULL;

    if (cmd->type == ASK_FOR_PIN && !cmd->is_reply && !check_auth_token(cmd, auth_token)) {
        printf("Pin recvd: %s\n", cmd->options);

        err = verify_master_pin_with_db(cmd->options);
        printf("err verify_with_db: %.4X\n", err);

        /* Create reply */
        err = create_command(ASK_FOR_PIN, &cmd_send_pin);
        if (err != PIPASS_OK)
            goto error;

        cmd_send_pin->is_reply = 1;
        cmd_send_pin->reply_code = err;

        err = calculate_crc(cmd_send_pin, &(cmd_send_pin->crc));
        if (err != PIPASS_OK)
            goto error; 

        err = send_command(cmd_send_pin);
        if (err != PIPASS_OK)
            goto error;

        FL_APP_ACTIVE = 1;

        return PIPASS_OK;
    } else {
        err = ERR_PIN_NOT_ENTERED;
    }

error:
    free_command(&cmd_send_pin);

    return err;
}






