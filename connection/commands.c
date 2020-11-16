#include <commands.h>
#include <storage_utils.h>
#include <commands_utils.h>
#include <crypto_utils.h>

PIPASS_ERR create_command(uint8_t cmd_code, Command **cmd) {
    PIPASS_ERR err;

    if (*cmd != NULL)
        return ERR_CONN_MEM_LEAK;

    (*cmd) = calloc(1, sizeof(Command));
    if (*cmd == NULL)
        return ERR_CONN_MEM_ALLOC;

    (*cmd)->type = cmd_code;
    (*cmd)->sender = SENDER_PIPASS;

    return PIPASS_OK;
}

PIPASS_ERR parse_buffer_to_cmd(uint8_t *buf, int32_t buf_size, Command **cmd) {
    if (buf == NULL || !buf_size)
        return ERR_PARSE_BUF_2_CMD_INV_PARAMS;

    if (*cmd != NULL)
        return ERR_CONN_MEM_LEAK;

    PIPASS_ERR err;
    int32_t idx = 2;

    *cmd = calloc(1, sizeof(Command));

    (*cmd)->type = buf[0];
    (*cmd)->sender = buf[1];

    uint16_t *tmp = bin_to_var(buf + idx, sizeof((*cmd)->length));
    if (tmp == NULL) {
        err = ERR_CONN_MEM_ALLOC;
        goto error;
    }
    (*cmd)->length = *tmp;
    free(tmp);
    idx += sizeof((*cmd)->length);

    (*cmd)->options = malloc((*cmd)->length);
    if ((*cmd)->options == NULL) {
        err = ERR_CONN_MEM_ALLOC;
        goto error;
    }

    memcpy((*cmd)->options, buf + idx, (*cmd)->length);
    idx += (*cmd)->length;

    tmp = bin_to_var(buf + idx, sizeof((*cmd)->crc));
    if (tmp == NULL) {
        err = ERR_CONN_MEM_ALLOC;
        goto error;
    }
    (*cmd)->crc = *tmp;
    free(tmp);
    idx += sizeof((*cmd)->crc);

    (*cmd)->is_reply = buf[idx++];
    (*cmd)->reply_code = buf[idx++];

    return PIPASS_OK;

error:
    erase_buffer(&(*cmd)->options, (*cmd)->length);
    return err;
}

PIPASS_ERR parse_cmd_to_buffer(Command *cmd, uint8_t *buf) {
    if (cmd == NULL || buf == NULL)
        return ERR_PARSE_CMD_2_BUF_INV_PARAMS;

    uint16_t idx = 2;
    PIPASS_ERR err;

    buf[0] = cmd->type;
    buf[1] = cmd->sender;

    uint8_t *length_bin = var_to_bin(cmd->length, sizeof(cmd->length));
    if (length_bin == NULL) {
        err = ERR_CONN_MEM_ALLOC;
        goto error;
    }

    append_to_str(buf, &idx, length_bin, sizeof(cmd->length));

    if (cmd->options != NULL)
        append_to_str(buf, &idx, cmd->options, cmd->length);

    err = calculate_crc(cmd, &(cmd->crc));
    if (err != PIPASS_OK)
        goto error;

    uint8_t *crc_bin = var_to_bin(cmd->crc, sizeof(cmd->crc));
    if (crc_bin == NULL) {
        err = ERR_CONN_MEM_ALLOC;
        goto error;
    }

    append_to_str(buf, &idx, crc_bin, sizeof(cmd->crc));

    buf[idx++] = cmd->is_reply;
    buf[idx++] = cmd->reply_code;

    err = PIPASS_OK;
    goto cleanup;

error:
    zero_buffer(buf, idx);
cleanup:
    erase_buffer(&length_bin, sizeof(cmd->length));
    erase_buffer(&crc_bin, sizeof(cmd->crc));

    return err;
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
