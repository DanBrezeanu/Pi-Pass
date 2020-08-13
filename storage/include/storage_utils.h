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


STORAGE_ERR user_directory(uint8_t *user, uint8_t **user_dir, uint32_t *user_dir_len);
STORAGE_ERR user_file_path(uint8_t *user, uint8_t *file, uint8_t **user_file_path, uint32_t *user_file_path_len);
uint8_t *var_to_bin(void *value, size_t size);
void append_to_str(uint8_t *str, int32_t *cursor, uint8_t *substr, int32_t substr_len);
STORAGE_ERR alloc_and_read_field(int32_t fd, uint8_t **field, int16_t field_len);

#endif
