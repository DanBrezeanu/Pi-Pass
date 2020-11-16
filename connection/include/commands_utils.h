#ifndef __COMMANDS_UTILS_H__
#define __COMMANDS_UTILS_H__

#include <defines.h>
#include <errors.h>
#include <commands.h>
#include <limits.h>

PIPASS_ERR calculate_crc(Command *cmd, uint16_t *crc);

#endif