#include <connection.h>

PIPASS_ERR open_connection(Connection **conn) {
    PIPASS_ERR err;
    
    if (*conn != NULL)
        return ERR_CONN_MEM_LEAK;

    *conn = calloc(1, sizeof(Connection));
    if (*conn == NULL)
        return ERR_CONN_MEM_LEAK;

    err = open_serial_connection(&((*conn)->s_conn));
    if (err != PIPASS_OK)
        goto error;

error:
    if (*conn != NULL)
        free(*conn);

    return err;
}

PIPASS_ERR recv_command(Connection *conn, Command **cmd) {
    if (conn == NULL)
        return ERR_RECV_CMD_INV_PARAMS;

    if (*cmd != NULL)
        return ERR_CONN_MEM_LEAK;
    
    PIPASS_ERR err;
    uint8_t buf[SERIAL_PKT_SIZE] = {0};
    int32_t bytes_read = 0;
    int8_t timed_out = 0;

    pthread_mutex_lock(&(conn->s_conn->serial_lock));
    err = read_bytes(conn->s_conn, buf, SERIAL_PKT_SIZE, &bytes_read, &timed_out);

    if (err != PIPASS_OK)
        return err;

    parse_buffer_to_cmd(buf, SERIAL_PKT_SIZE, cmd);

    if (!cmd_requires_additional(*cmd)) {
        pthread_mutex_unlock(&(conn->s_conn->serial_lock));
    }
    

}

PIPASS_ERR execute_command(Connection *conn, uint8_t cmd_code) {
    if (conn == NULL)
        return ERR_EXEC_CMD_INV_PARAMS;

    PIPASS_ERR err;
    Command cmd = {0};

    err = create_command(cmd_code, &cmd);
}