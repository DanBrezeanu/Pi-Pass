#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <errors.h>
#include <stdint.h>
#include <defines.h>

STORAGE_ERR verify_user(uint8_t *user);
STORAGE_ERR verify_master_password(uint8_t *user, uint8_t *key);