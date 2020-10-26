#ifndef __AUTHENTICATION_H__
#define __AUTHENTICATION_H__

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <errors.h>
#include <stdint.h>
#include <defines.h>
#include <strings.h>
#include <crypto_utils.h>
#include <storage_utils.h>

PIPASS_ERR authenticate(uint8_t *user_hash, uint8_t *master_pin);
PIPASS_ERR verify_user_exists(uint8_t *user, int user_len);

#endif
