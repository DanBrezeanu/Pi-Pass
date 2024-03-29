#include <connection.h>
#include <commands_utils.h>
#include <commands.h>
#include <authentication.h>
#include <command_execution.h>


static Connection *conn;
uint8_t FL_PIN_ENTERED = 0;
uint8_t FL_APP_ACTIVE = 0;

uint8_t command_to_send = NO_COMMAND;

PIPASS_ERR open_connection() {
    PIPASS_ERR err;
    int32_t ret;
    
    if (conn != NULL)
        return ERR_CONN_ALREADY_OPEN;

    conn = calloc(1, sizeof(Connection));
    if (conn == NULL)
        return ERR_CONN_MEM_ALLOC;

    err = open_serial_connection(&(conn->s_conn));
    if (err != PIPASS_OK)
        goto error;

    ret = pthread_mutex_init(&conn->to_send_lock, NULL);
    if (ret != 0) {
        err = ERR_CONN_INIT_FAIL;
        goto error;
    }

    return PIPASS_OK;

error:
    if (conn != NULL)
        free(conn);

    return err;
}

PIPASS_ERR recv_command(Cmd **cmd) {
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
    
    if (timed_out == 1) {
        err = ERR_READ_TIMED_OUT;
        goto error;
    }

    printf("got data\n");

    err = parse_buffer_to_cmd(buf, bytes_read, cmd);
    if (err != PIPASS_OK)
        goto error;


    uint16_t crc = 0;
    err = calculate_crc(*cmd, &crc);
    if (err != PIPASS_OK)
        goto error;

    // if (crc != (*cmd)->crc) {
    //     err = ERR_CRC_DIFFERENT;
    //     goto error;
    // }

    if (!cmd_requires_additional(*cmd)) {
        pthread_mutex_unlock(&(conn->s_conn->serial_lock));
    }
error:
    pthread_mutex_unlock(&(conn->s_conn->serial_lock));
    return err;
}

PIPASS_ERR execute_command(Cmd *cmd) {
    if (conn == NULL)
        return ERR_CONN_NOT_INIT;

    return _execute_command(cmd);
}

PIPASS_ERR send_command(Cmd *cmd) {
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


PIPASS_ERR change_command_to_send(uint8_t command_type, uint8_t force_change) {
    int32_t ret;
    PIPASS_ERR err;

    ret = pthread_mutex_trylock(&conn->to_send_lock);
    if (ret != 0) {
        return ERR_CONN_TO_SEND_BUSY;
    }

    if (command_to_send != NO_COMMAND && !force_change) {
        err = ERR_CONN_TO_SEND_BUSY;
        goto error;
    }

    command_to_send = command_type;

    err = PIPASS_OK;

error:
    pthread_mutex_unlock(&conn->to_send_lock);
    
    return err;
}