#ifndef __STORAGE_UTILS_H__
#define __STORAGE_UTILS_H__

#include <string.h>
#include <strings.h>
#include <errors.h>
#include <stdlib.h>
#include <stdint.h>
#include <defines.h>
#include <unistd.h>
#include <fcntl.h>
#include <datablob.h>
#include <datahash.h>


PIPASS_ERR user_directory(uint8_t *user, uint8_t **user_dir, uint32_t *user_dir_len);
PIPASS_ERR user_file_path(uint8_t *user, uint8_t *file, uint8_t **user_file_path, uint32_t *user_file_path_len);
uint8_t *var_to_bin(void *value, size_t size);
void *bin_to_var(uint8_t *bin, size_t size);
void append_to_str(uint8_t *str, int32_t *cursor, uint8_t *substr, int32_t substr_len);
PIPASS_ERR alloc_and_read_field(int32_t fd, uint8_t **field, int16_t field_len);
PIPASS_ERR alloc_and_read_datablob(int32_t fd, struct DataBlob *blob, int16_t ciphertext_len);
PIPASS_ERR alloc_and_read_datahash(int32_t fd, struct DataHash *hash);


#endif
