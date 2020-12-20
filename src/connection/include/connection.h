#ifndef __CONNECTION_H__
#define __CONNECTION_H__

#include <serial.h>
#include <commands.h>
#include <errors.h>
#include <defines.h>
#include <pthread.h>

extern uint8_t FL_PIN_ENTERED;

typedef struct Connection {
    SerialConnection *s_conn;
    Cmd comm;

    pthread_mutex_t to_send_lock;
} Connection;


PIPASS_ERR open_connection();
PIPASS_ERR recv_command(Cmd **cmd);
PIPASS_ERR send_command(Cmd *cmd);
PIPASS_ERR execute_command(Cmd *cmd);
PIPASS_ERR change_command_to_send(uint8_t command_type, uint8_t force_change);
#endif