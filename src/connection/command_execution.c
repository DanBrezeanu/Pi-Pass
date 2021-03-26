#include <commands.h>
#include <connection.h>
#include <command_execution.h>
#include <commands_utils.h>
#include <crypto.h>
#include <flags.h>

static PIPASS_ERR _execute_app_hello(Cmd *cmd);
static PIPASS_ERR _execute_ask_for_pin(Cmd *cmd);

PIPASS_ERR _execute_command(Cmd *cmd) {
    if (cmd == NULL)
        return ERR_SEND_CMD_INV_PARAMS;

    PIPASS_ERR err = PIPASS_OK;

    switch (cmd->type) {
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

    if (cmd->sender == SENDER_APP && !cmd->is_reply) {
        
        err = create_command(APP_HELLO, &cmd_hello);
        if (err != PIPASS_OK)
            goto error;

        cmd_hello->is_reply = 1;

        err = calculate_crc(cmd_hello, &(cmd_hello->crc));
        if (err != PIPASS_OK)
            goto error; 

        err = send_command(cmd_hello);
        if (err != PIPASS_OK)
            goto error;

        FL_APP_ACTIVE = 1;

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

    if (cmd->type == ASK_FOR_PIN && cmd->is_reply) {
        printf("Pin recvd: %s\n", cmd->options);

        err = verify_master_pin_with_db(cmd->options);
        printf("err verify_with_db: %.4X\n", err);
    } else {
        err = ERR_PIN_NOT_ENTERED;
    }

    return err;
}






