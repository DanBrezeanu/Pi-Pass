#ifndef __CONNECTION_H__
#define __CONNECTION_H__

#include <serial.h>
#include <commands.h>
#include <errors.h>
#include <defines.h>

extern uint8_t FL_PIN_ENTERED;

typedef struct Connection {
    SerialConnection *s_conn;
    Command comm;
} Connection;

#endif