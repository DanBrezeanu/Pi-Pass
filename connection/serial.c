#include <serial.h>

PIPASS_ERR open_serial_connection(SerialConnection **conn) {
    struct termios tty;
    int32_t ret;
    PIPASS_ERR err;

    if (*conn != NULL)
        return ERR_SERIAL_MEM_LEAK;

    *conn = calloc(1, sizeof(SerialConnection));
    if (*conn == NULL)
        return ERR_SERIAL_MEM_ALLOC;

    (*conn)->fd = open(S_TTY, O_RDWR | O_NOCTTY | O_SYNC);
    if ((*conn)->fd < 0) {
        err = ERR_SERIAL_OPEN_CONN;
        goto error;
    }

    ret = tcgetattr((*conn)->fd, &tty);
    if (ret < 0) {
        err = ERR_SERIAL_OPEN_CONN;
        goto error;
    }

    cfsetospeed(&tty, (speed_t)B9600);
    cfsetispeed(&tty, (speed_t)B9600);

    tty.c_cflag |= (CLOCAL | CREAD);
    tty.c_cflag &= ~CSIZE;
    tty.c_cflag |= CS8;
    tty.c_cflag &= ~PARENB;
    tty.c_cflag &= ~CSTOPB;
    tty.c_cflag &= ~CRTSCTS;

    tty.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON);
    tty.c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
    tty.c_oflag &= ~OPOST;

    tty.c_cc[VMIN]  = 0;
    tty.c_cc[VTIME] = 2;

    ret = tcsetattr((*conn)->fd, TCSANOW, &tty);
    if (ret != 0) {
        err = ERR_SERIAL_OPEN_CONN;
        goto error;
    }

    ret = pthread_mutex_init(&((*conn)->serial_lock), NULL);
    if (ret != 0) {
        err = ERR_SERIAL_OPEN_CONN;
        goto error;
    }

    return PIPASS_OK;

error:
    if (*conn != NULL)
        free(*conn);

    return err;
}

PIPASS_ERR write_bytes(SerialConnection *conn, uint8_t *buffer, int32_t num) {
    /* Note: conn->serial_lock must be acquired before calling this function */

    int32_t ret;
    PIPASS_ERR err;
    
    if (conn == NULL || buffer == NULL)
        return ERR_SERIAL_WR_INV_PARAMS;

    ret = write(conn->fd, buffer, num);
    if (ret != num) {
        err = ERR_SERIAL_WR_FAIL;
        goto error;
    }
    tcdrain(conn->fd);

    return PIPASS_OK;
    
error:
    return err;
}

PIPASS_ERR read_bytes(SerialConnection *conn, uint8_t *buffer, int32_t num, int32_t *bytes_read, int8_t *timed_out) {
    /* Note: conn->serial_lock must be acquired before calling this function */

    int32_t ret;
    PIPASS_ERR err;
    
    if (conn == NULL || buffer == NULL)
        return ERR_SERIAL_RD_INV_PARAMS;

    ret = read(conn->fd, buffer, num);
    if (ret < 0) {
        err = ERR_SERIAL_RD_FAIL;
    } else if (ret == 0) {
        *bytes_read = 0;
        *timed_out = 1;

        return PIPASS_OK;
    } else if (ret != num) {
        err = ERR_SERIAL_RD_FAIL_BYTES;
        goto error;
    }

    *bytes_read = ret;
    *timed_out = 0;
    
    return PIPASS_OK;

error:
    return err;
}

PIPASS_ERR close_serial_connection(SerialConnection **conn) {
    if (*conn == NULL)
        return PIPASS_OK;

    close((*conn)->fd);
    pthread_mutex_destroy(&((*conn)->serial_lock));
    free(*conn);
    *conn = NULL;

    return PIPASS_OK;
}