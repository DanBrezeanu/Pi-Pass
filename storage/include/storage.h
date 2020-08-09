#include <defines.h>
#include <errors.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <strings.h>

STORAGE_ERR create_user_directory(uint8_t *user_hash);
STORAGE_ERR verify_user_directory(uint8_t *user_hash);
STORAGE_ERR store_file(uint8_t *user_hash, uint8_t *content, int32_t content_len, uint8_t *file_name);
STORAGE_ERR store_user_DEK_blob(uint8_t *user_hash, uint8_t *DEK_blob, uint8_t *iv, uint8_t *mac);

