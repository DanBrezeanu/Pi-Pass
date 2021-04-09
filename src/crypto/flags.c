#include <flags.h>

volatile uint8_t FL_LOGGED_IN = 0;
volatile uint8_t FL_DB_INITIALIZED = 0;
volatile uint8_t FL_DB_HEADER_LOADED = 0;

volatile uint8_t FL_RECEIVED_PASSWORD = 0;
uint8_t *entered_pin = NULL;