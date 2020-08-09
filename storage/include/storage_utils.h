#include <string.h>
#include <strings.h>
#include <errors.h>
#include <stdlib.h>
#include <stdint.h>
#include <defines.h>

STORAGE_ERR user_directory(uint8_t *user, uint8_t **user_dir, uint32_t *user_dir_len);
STORAGE_ERR user_master_passw_file(uint8_t *user, uint8_t **user_passw, uint32_t *user_passw_len);
STORAGE_ERR user_master_salt_file(uint8_t *user, uint8_t **user_salt, uint32_t *user_salt_len);