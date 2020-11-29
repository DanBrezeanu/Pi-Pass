#include <crypto_utils.h>

void zero_buffer(uint8_t *buf, int32_t size) {
    memset(buf, 0, size);
}

void erase_buffer(uint8_t **buf, int32_t size) {
    if (*buf != NULL) {
        zero_buffer(*buf, size);
        free(*buf);
        *buf = NULL;
    }
}

PIPASS_ERR raw_to_hex(uint8_t *raw, uint32_t raw_len, uint8_t **hex, uint32_t *hex_len) {
    uint8_t hx[]= "0123456789abcdef";

    if (raw == NULL || raw_len == 0)
        return ERR_RAW2HEX_INV_PARAMS;

    if (*hex != NULL)
        return ERR_MEM_LEAK;

    *hex = malloc(raw_len * 2 + 1);
    if (*hex == NULL)
        return ERR_CRYPTO_MEM_ALLOC;

    (*hex)[raw_len * 2] = 0;
    *hex_len = raw_len * 2;

    for (int32_t i = 0; i < raw_len; i++) {
        (*hex)[i * 2 + 0] = hx[(raw[i] >> 4) & 0x0F];
        (*hex)[i * 2 + 1] = hx[(raw[i]     ) & 0x0F];
    }
    
    return CRYPTO_OK;
}

PIPASS_ERR sanity_check_buffer(uint8_t *buf, uint8_t buf_len) {
    return ((buf == NULL || buf_len == 0 || buf[buf_len] != 0)
            ? (ERR_BUF_SANITY_CHECK_FAIL)
            : (CRYPTO_OK));
}

PIPASS_ERR cpu_id(uint8_t **hw_id) {
    const uint32_t MAX_SIZE = 32000;

    if (*hw_id != NULL)
        return ERR_CRYPTO_MEM_LEAK;

    PIPASS_ERR err = PIPASS_OK;
    uint8_t *buf = NULL;

    int32_t fd = open("/proc/cpuinfo", O_RDONLY);
    if (fd == -1)
        return ERR_RETRIEVE_CPU_ID;

    buf = malloc(MAX_SIZE + 1);
    int32_t size = read(fd, buf, MAX_SIZE);
    if (size == -1) {
        err = ERR_RETRIEVE_CPU_ID;
        goto error;
    }
    buf[size] = 0;

    uint8_t *serial_line = strstr(buf, "Serial");
    if (serial_line == NULL) {
        err = ERR_RETRIEVE_CPU_ID;
        goto error;
    }

    serial_line += strlen("Serial");

    while (strchr("0123456789abcdef", *serial_line) == NULL && serial_line < buf + size)
        serial_line++;

    if (serial_line == buf + size) {
        err = ERR_RETRIEVE_CPU_ID;
        goto error;
    }
       
    *hw_id = malloc(CPU_ID_SIZE);
    if (*hw_id == NULL) {
        err = ERR_CRYPTO_MEM_ALLOC;
        goto error;
    }

    memcpy(*hw_id, serial_line, CPU_ID_SIZE);

    for (int32_t i = 0; i < CPU_ID_SIZE; ++i)
        if (strchr("0123456789abcdef", (*hw_id)[i]) == NULL) {
            err = ERR_RETRIEVE_CPU_ID;
            goto error;
        }

    free(buf);
    close(fd);

    return PIPASS_OK;

error:
    if (buf != NULL)
        free(buf);

    if (*hw_id != NULL)
        free(*hw_id);

    if (fd != -1)
        close(fd);

    return err;
}

PIPASS_ERR concat_pin_pepper(uint8_t *pin, uint8_t **pin_pepper) {
    if (pin == NULL)
        return ERR_CONCAT_PEPPER_INV_PARAMS;

    if (*pin_pepper != NULL)
        return ERR_CRYPTO_MEM_LEAK;

    PIPASS_ERR err;
    uint8_t *pepper = NULL;

    err = cpu_id(&pepper);
    if (err != PIPASS_OK)
        return err;

    *pin_pepper = malloc(MASTER_PIN_SIZE_WITH_PEPPER);
    if (*pin_pepper == NULL) {
        err = ERR_CRYPTO_MEM_ALLOC;
        goto error;
    }

    memcpy(*pin_pepper, pin, MASTER_PIN_SIZE);
    memcpy(*pin_pepper + MASTER_PIN_SIZE, pepper, PEPPER_SIZE);

    erase_buffer(&pepper, PEPPER_SIZE);

    return PIPASS_OK;

error:
    erase_buffer(&pepper, PEPPER_SIZE);
    erase_buffer(pin_pepper, PEPPER_SIZE);
    
    return err;
}


