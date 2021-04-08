#include <commands_utils.h>
#include <commands.h>
#include <crypto.h>


PIPASS_ERR calculate_crc(uint8_t *buf, uint16_t *crc) {
    if (buf == NULL || crc == NULL)
        return ERR_CALC_CRC_INV_PARAMS;

    while (*buf) {
        *crc = ((uint32_t) *crc + *buf) % UINT16_MAX;
        ++buf;
    }

    return PIPASS_OK;
}

PIPASS_ERR check_auth_token(Cmd *cmd, uint8_t *token) {
    if (cmd == NULL || token == NULL)
        return ERR_INVALID_AUTH_TOKEN;

    json_object *auth_token;
    
    if (!json_object_object_get_ex(cmd->body, "auth_token", &auth_token) 
        || json_object_get_type(auth_token) != json_type_string)
        return ERR_INVALID_AUTH_TOKEN;

    if (memcmp(json_object_get_string(auth_token), token, SHA256_HEX_SIZE) != 0)
        return ERR_INVALID_AUTH_TOKEN;
    else
        return PIPASS_OK;

    return PIPASS_OK;
}

PIPASS_ERR get_rand_auth_token(uint8_t **auth_token) {
    if (*auth_token != NULL)
        return ERR_CONN_MEM_LEAK;
    
    uint16_t count = 0;
    uint8_t *tmp = NULL;

    *auth_token = malloc(AUTH_TOKEN_SIZE);
    if (*auth_token == NULL)
        return ERR_CONN_MEM_ALLOC;

    tmp = malloc(AUTH_TOKEN_SIZE);
    if (tmp == NULL)
        return ERR_CONN_MEM_ALLOC;

    while (count < AUTH_TOKEN_SIZE) {
        RAND_bytes(tmp, AUTH_TOKEN_SIZE);

        for (uint8_t i = 0; i < AUTH_TOKEN_SIZE; ++i)
            if (isprint(tmp[i])) {
                (*auth_token)[count++] = tmp[i];

                if (count == AUTH_TOKEN_SIZE)
                    break;
            }
    }

    erase_buffer(&tmp, AUTH_TOKEN_SIZE);

    return PIPASS_OK;
}