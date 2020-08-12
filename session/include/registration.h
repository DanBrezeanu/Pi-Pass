#ifndef __REGISTRATION_H__
#define __REGISTRATION_H__

#include <sys/types.h>
#include <sys/stat.h>
#include <errors.h>
#include <defines.h>

STORAGE_ERR register_new_user(uint8_t *user_data, int32_t user_data_len, uint8_t *master_pass);

#endif
