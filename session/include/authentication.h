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

PIPASS_ERR verify_master_password(uint8_t *user, uint8_t *key);

#endif
