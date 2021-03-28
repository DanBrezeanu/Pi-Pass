#include <commands.h>
#include <storage_utils.h>
#include <commands_utils.h>
#include <crypto_utils.h>
#include <json.h>

PIPASS_ERR create_command(uint8_t cmd_code, Cmd **cmd) {
    PIPASS_ERR err;

    if (*cmd != NULL)
        return ERR_CONN_MEM_LEAK;

    (*cmd) = calloc(1, sizeof(Cmd));
    if (*cmd == NULL)
        return ERR_CONN_MEM_ALLOC;

    (*cmd)->body = json_object_new_object();
    
    json_object *type = json_object_new_int(cmd_code);
    json_object *sender = json_object_new_int(SENDER_PIPASS);
    json_object *reply_code = json_object_new_int(0);

    err = json_object_object_add((*cmd)->body, "type", type);
    if (err != PIPASS_OK)
        return ERR_CMD_JSON_ADD;

    err = json_object_object_add((*cmd)->body, "sender", sender);
    if (err != PIPASS_OK)
        return ERR_CMD_JSON_ADD;

    err = json_object_object_add((*cmd)->body, "reply_code", reply_code);
    if (err != PIPASS_OK)
        return ERR_CMD_JSON_ADD;

    return PIPASS_OK;
}

PIPASS_ERR parse_buffer_to_cmd(uint8_t *buf, int32_t buf_size, Cmd **cmd) {
    if (buf == NULL || !buf_size)
        return ERR_PARSE_BUF_2_CMD_INV_PARAMS;

    if (*cmd != NULL)
        return ERR_CONN_MEM_LEAK;

    PIPASS_ERR err;
    int32_t idx = 0;

    memcpy(&(*cmd)->crc, buf + buf_size - sizeof((*cmd)->crc), sizeof((*cmd)->crc));
    buf[buf_size - sizeof((*cmd)->crc)] = 0;

    (*cmd)->body = json_tokener_parse(buf);
    if ((*cmd)->body == NULL)
        return ERR_CMD_JSON_PARSE;
    
    return err;
}

PIPASS_ERR parse_cmd_to_buffer(Cmd *cmd, uint8_t *buf) {
    if (cmd == NULL || buf == NULL)
        return ERR_PARSE_CMD_2_BUF_INV_PARAMS;

    PIPASS_ERR err;
    uint8_t *tmp = json_object_to_json_string(cmd->body);
    if (tmp == NULL)
        return ERR_CMD_JSON_TO_STRING;

    if (strlen(tmp) > PACKET_SIZE - 2) {
        // TODO;
    }

    memcpy(buf, tmp, strlen(tmp));

    err = calculate_crc(tmp, &(cmd->crc));
    if (err != PIPASS_OK)
        goto error;

    memcpy(buf + strlen(tmp), &(cmd->crc), sizeof(cmd->crc));

    err = PIPASS_OK;
error:
    return err;
}

uint8_t cmd_requires_additional(Cmd *cmd) {
    if (cmd == NULL)
        return 0;

    // switch(cmd->type) {
    // case STORE_CREDENTIALS:
    //     return 1;
    // case EDIT_CREDENTIALS:
    //     return 1;
    // }

    // return 0;
}


void free_command(Cmd **cmd) {
    if (*cmd == NULL)
        return;

    json_object_put((*cmd)->body);

    free(*cmd);
    *cmd = NULL;
}