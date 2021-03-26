#ifndef __COMMANDS_UTILS_H__
#define __COMMANDS_UTILS_H__

#include <defines.h>
#include <errors.h>
#include <commands.h>
#include <limits.h>

PIPASS_ERR calculate_crc(Cmd *cmd, uint16_t *crc);
PIPASS_ERR check_auth_token(Cmd *cmd, uint8_t *token);
PIPASS_ERR check_size_and_increment(int32_t buf_size, size_t increment, int32_t *counter);
#endif