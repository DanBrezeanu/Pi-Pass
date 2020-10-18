#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <errors.h>
#include <defines.h>
#include <pthread.h>

typedef struct SerialConnection {
    int32_t fd;
    pthread_mutex_t serial_lock;
    
} SerialConnection;

PIPASS_ERR open_serial_connection(SerialConnection **conn);
PIPASS_ERR write_bytes(SerialConnection *conn, uint8_t *buffer, int32_t num);
PIPASS_ERR read_bytes(SerialConnection *conn, uint8_t *buffer, int32_t num, int32_t *bytes_read, int8_t *timed_out);

