#include <fingerprint.h>
#include <fingerprint_utils.h>
#include <gpio_control.h>

#include <errors.h>
#include <unistd.h>
#include <stdio.h>

static Driver *driver;
static uint8_t FL_FP_UNLOCKED;

PIPASS_ERR init_fingerprint() {
    if (driver != NULL)
        return ERR_FP_ALREADY_INIT;

    PIPASS_ERR err;
    int32_t ret;

    err = init_driver(FP_PORT, DEFAULT_FP_ADDRESS, &driver);
    if (err != PIPASS_OK)
        return ERR_DRIVER_INIT_FAIL;

    return PIPASS_OK;
}

PIPASS_ERR fp_verify_pin(uint8_t *pin) {
    if (driver == NULL)
        return ERR_FP_NOT_INIT;

    if (FL_FP_UNLOCKED)
        return ERR_FP_ALREADY_UNLOCKED;

    if (pin == NULL)
        return ERR_VERIFY_PIN_INV_PARAMS;
    

    Reply reply;
    PIPASS_ERR err;

    uint32_t pin_bytes = bin_to_number(pin, sizeof(uint32_t));

    err = call_cmd(driver, VfyPwd, &reply, 1, pin_bytes);
    switch (err) {
    case PIPASS_OK:
        break;
    case WRONG_PASSW:
        return ERR_FP_WRONG_PASSWORD;
    default:
        return ERR_VFY_PASSWORD_FAIL;
    }

    FL_FP_UNLOCKED = 1;

    return PIPASS_OK;
}

PIPASS_ERR fp_enroll_fingerprint(uint16_t *fp_index) {
    if (driver == NULL)
        return ERR_FP_NOT_INIT;

    if (!FL_FP_UNLOCKED)
        return ERR_FP_NOT_UNLOCKED;

    Reply reply;
    PIPASS_ERR err;

    err = call_cmd(driver, TemplateNum, &reply, 0);
    if (err != PIPASS_OK) {
        err = ERR_FP_ENROLL_FAIL;
        goto error;
    }

    uint16_t index = reply.body.template_num.index;

    for (uint8_t i = 1; i <= 2; ++i) {
        do {
            do {
                wait_for_sensor_touch();
                err = call_cmd(driver, GenImg, &reply, 0);
            } while(err != PIPASS_OK);

            err = call_cmd(driver, Img2Tz, &reply, 1, i);
        } while (err != PIPASS_OK);
    }

    err = call_cmd(driver, RegModel, &reply, 0);
    if (err != PIPASS_OK) {
        err = ERR_FP_ENROLL_FAIL;
        goto error;
    }

    err = call_cmd(driver, Store, &reply, 2, 1, index);
    if (err != PIPASS_OK) {
        err = ERR_FP_ENROLL_FAIL;
        goto error;
    }

    *fp_index = index;

    return PIPASS_OK;

error:
    return err;
}

PIPASS_ERR fp_verify_fingerprint(uint16_t *index, uint16_t *match_score) {
    if (driver == NULL)
        return ERR_FP_NOT_INIT;

    if (!FL_FP_UNLOCKED)
        return ERR_FP_NOT_UNLOCKED;

    Reply reply;
    PIPASS_ERR err;

    do {
        wait_for_sensor_touch();
        err = call_cmd(driver, GenImg, &reply, 0);
    } while (err != PIPASS_OK);

    
    err = call_cmd(driver, Img2Tz, &reply, 1, 1);
    if (err != PIPASS_OK) {
        err = ERR_FP_VERIFY_FAIL;
        goto error;
    }

    err = call_cmd(driver, Search, &reply, 3, 1, 0, 0xFF);
    switch (err) {
    case PIPASS_OK:
        break;
    case FINGER_NOT_FOUND:
        return ERR_FP_NO_FINGER_FOUND;
    default:
        return ERR_FP_VERIFY_FAIL;
    }

    if (reply.body.search.match_score < MINIMUM_MATCH_SCORE)
        return ERR_FP_NO_FINGER_FOUND;

    *index = reply.body.search.index;
    *match_score = reply.body.search.match_score;

    return PIPASS_OK;

error:
    return err;
}

PIPASS_ERR fp_get_fingerprint(uint8_t **fp_data) {
    if (driver == NULL)
        return ERR_FP_NOT_INIT;

    if (!FL_FP_UNLOCKED)
        return ERR_FP_NOT_UNLOCKED;

    if (*fp_data != NULL)
        return ERR_FP_MEM_LEAK;

    Reply reply;
    PIPASS_ERR err;

    uint16_t index = 0, match_score = 0;
    err = fp_verify_fingerprint(&index, &match_score);
    if (err != PIPASS_OK)
        return err;

    err = call_cmd(driver, LoadChar, &reply, 2, 1, index);
    if (err != SUCCESS)
        return ERR_FP_GET_DATA_FAIL;

    err = call_cmd(driver, UpChar, &reply, 1, 1);
    if (err != SUCCESS)
        return ERR_FP_GET_DATA_FAIL;

    *fp_data = malloc(FINGERPRINT_SIZE);
    if (*fp_data == NULL)
        return ERR_FINGERPRINT_MEM_ALLOC;

    memcpy(*fp_data, reply.body.up_char.fingerprint, FINGERPRINT_SIZE);

    return PIPASS_OK;
}

void *fp_async_get_fingerprint(void *arg) {
    struct async_fp_data *data = (struct async_fp_data *) arg;

    if (driver == NULL) {
        data->err = ERR_FP_NOT_INIT;
        return NULL;
    }

    if (!FL_FP_UNLOCKED) {
        data->err = ERR_FP_NOT_UNLOCKED;
        return NULL;
    }
    
    Reply reply;
    PIPASS_ERR err = ERR_FP_VERIFY_FAIL;

    uint16_t index = 0, match_score = 0;
    do {
        uint8_t timed_out = wait_for_sensor_touch_with_timeout(100000);
        if (!timed_out)
            err = call_cmd(driver, GenImg, &reply, 0);
        else {
            if (data->stop) {
                data->err = ERR_FP_ASYNC_STOPPED;
                return NULL;
            }
        }
    } while (err != PIPASS_OK);

    
    err = call_cmd(driver, Img2Tz, &reply, 1, 1);
    if (err != PIPASS_OK) {
        data->err = ERR_FP_VERIFY_FAIL;
        return NULL;
    }

    err = call_cmd(driver, Search, &reply, 3, 1, 0, 0xFF);
    switch (err) {
    case PIPASS_OK:
        break;
    case FINGER_NOT_FOUND:
        data->err = ERR_FP_NO_FINGER_FOUND;
        return NULL;
    default:
        data->err = ERR_FP_VERIFY_FAIL;
        return NULL;
    }

    if (reply.body.search.match_score < MINIMUM_MATCH_SCORE) {
        data->err = ERR_FP_NO_FINGER_FOUND;
        return NULL;
    }

    data->index = reply.body.search.index;
    data->match_score = reply.body.search.match_score;

    err = call_cmd(driver, LoadChar, &reply, 2, 1, data->index);
    if (err != SUCCESS) {
        data->err = ERR_FP_GET_DATA_FAIL;
        return NULL;
    }

    err = call_cmd(driver, UpChar, &reply, 1, 1);
    if (err != SUCCESS) {
        data->err = ERR_FP_GET_DATA_FAIL;
        return NULL;
    }

    data->fp_data = malloc(FINGERPRINT_SIZE);
    if (data->fp_data == NULL) {
        data->err = ERR_FINGERPRINT_MEM_ALLOC;
        return NULL;
    }

    memcpy(data->fp_data, reply.body.up_char.fingerprint, FINGERPRINT_SIZE);

    data->err = PIPASS_OK;
    return NULL;
}