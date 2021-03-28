#ifndef __COMMANDS_UTILS_H__
#define __COMMANDS_UTILS_H__

#include <defines.h>
#include <errors.h>
#include <commands.h>
#include <limits.h>

PIPASS_ERR calculate_crc(uint8_t *buf, uint16_t *crc);
PIPASS_ERR check_auth_token(Cmd *cmd, uint8_t *token);
PIPASS_ERR get_rand_auth_token(uint8_t **auth_token);
#endif