#include <commands_utils.h>
#include <commands.h>


PIPASS_ERR calculate_crc(Cmd *cmd, uint16_t *crc) {
    if (cmd == NULL || crc == NULL)
        return ERR_CALC_CRC_INV_PARAMS;

    *crc = 0;

    *crc += cmd->type;
    *crc += cmd->sender;
    *crc = ((uint32_t) *crc + cmd->length) % UINT16_MAX;
    *crc += cmd->is_reply;
    *crc += cmd->reply_code;


    for (uint16_t i = 0; i < cmd->length; ++i) {
        *crc = ((uint32_t) *crc + cmd->options[i]) % UINT16_MAX;
    }

    return PIPASS_OK;
}