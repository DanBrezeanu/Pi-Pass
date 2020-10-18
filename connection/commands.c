#include <commands.h>

PIPASS_ERR create_command(uint8_t cmd_code, Command *cmd) {
    PIPASS_ERR err;

    cmd->type = cmd_code;

}

PIPASS_ERR execute_command(Command *cmd) {

}

PIPASS_ERR parse_buffer_to_cmd(uint8_t *buf, int32_t buf_size, Command **cmd) {
    


}

uint8_t cmd_requires_additional(Command *cmd) {
    if (cmd == NULL)
        return 0;

    switch(cmd->type) {
    case STORE_CREDENTIALS:
        return 1;
    case EDIT_CREDENTIALS:
        return 1;
    }

    return 0;
}