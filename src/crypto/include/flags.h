#ifndef __FLAGS_H__
#define __FLAGS_H__

#include <stdint.h>
#include <stdlib.h>

extern volatile uint8_t FL_LOGGED_IN;
extern volatile uint8_t FL_DB_INITIALIZED;
extern volatile uint8_t FL_DB_HEADER_LOADED;
extern volatile uint8_t FL_RECEIVED_PASSWORD;

extern uint8_t *entered_pin;


#endif