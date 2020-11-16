#include <connection.h>
#include <commands_utils.h>
#include <commands.h>

static Connection *conn;
uint8_t FL_PIN_ENTERED = 0;

PIPASS_ERR open_connection() {
    PIPASS_ERR err;
    
    if (conn != NULL)
        return ERR_CONN_ALREADY_OPEN;

    conn = calloc(1, sizeof(Connection));
    if (conn == NULL)
        return ERR_CONN_MEM_ALLOC;

    err = open_serial_connection(&(conn->s_conn));
    if (err != PIPASS_OK)
        goto error;

error:
    if (conn != NULL)
        free(conn);

    return err;
}

PIPASS_ERR recv_command(Command **cmd) {
    if (conn == NULL)
        return ERR_CONN_NOT_INIT;

    if (*cmd != NULL)
        return ERR_CONN_MEM_LEAK;
    
    PIPASS_ERR err;
    uint8_t buf[SERIAL_PKT_SIZE] = {0};
    int32_t bytes_read = 0;
    int8_t timed_out = 0;

    pthread_mutex_lock(&(conn->s_conn->serial_lock));
    err = read_bytes(conn->s_conn, buf, SERIAL_PKT_SIZE, &bytes_read, &timed_out);
    if (err != PIPASS_OK)
        goto error;

    err = parse_buffer_to_cmd(buf, SERIAL_PKT_SIZE, cmd);
    if (err != PIPASS_OK)
        goto error;

    uint16_t crc = 0;
    err = calculate_crc(*cmd, &crc);
    if (err != PIPASS_OK)
        goto error;

    if (crc != (*cmd)->crc) {
        err = ERR_CRC_DIFFERENT;
        goto error;
    }

    if (!cmd_requires_additional(*cmd)) {
        pthread_mutex_unlock(&(conn->s_conn->serial_lock));
    }
error:
    pthread_mutex_unlock(&(conn->s_conn->serial_lock));
    return err;
}

PIPASS_ERR send_command(Command *cmd) {
    if (conn == NULL)
        return ERR_CONN_NOT_INIT;

    if (cmd == NULL)
        return ERR_SEND_CMD_INV_PARAMS;

    PIPASS_ERR err;
    uint8_t buf[SERIAL_PKT_SIZE] = {0};

    err = parse_cmd_to_buffer(cmd, buf);
    if (err != PIPASS_OK)
        goto error;

    pthread_mutex_lock(&(conn->s_conn->serial_lock));
    err = write_bytes(conn->s_conn, buf, SERIAL_PKT_SIZE);
    if (err != PIPASS_OK)
        goto error;
    pthread_mutex_unlock(&(conn->s_conn->serial_lock));

    return PIPASS_OK;

error:
    pthread_mutex_unlock(&(conn->s_conn->serial_lock));
    return err;
}

PIPASS_ERR execute_command(Command *cmd) {
    if (conn == NULL)
        return ERR_CONN_NOT_INIT;

    if (cmd == NULL)
        return ERR_SEND_CMD_INV_PARAMS;

    PIPASS_ERR err;

    if (cmd->type == APP_HELLO) {
        if (cmd->sender == SENDER_APP && !cmd->is_reply) {
            Command *cmd_ask_for_pin = NULL;
            err = create_command(ASK_FOR_PIN, &cmd_ask_for_pin);
            if (err != PIPASS_OK)
                goto error;

            err = calculate_crc(cmd_ask_for_pin, &(cmd_ask_for_pin->crc));
            if (err != PIPASS_OK)
                goto error; 

            err = send_command(cmd_ask_for_pin);

        } else {
            err = ERR_CONN_INVALID_COMM;
        }

    }


    if (!FL_PIN_ENTERED) {
        if (cmd->type == ASK_FOR_PIN && cmd->is_reply) {
            err = verify_master_pin_with_db(cmd->options);
            if (err != PIPASS_OK)
                goto error;

            FL_PIN_ENTERED = 1;
        } else {
            err = ERR_PIN_NOT_ENTERED;
            goto error;
        }
    }



error:
    return err;

}