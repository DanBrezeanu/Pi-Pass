#ifndef __ACTIONS_H__
#define __ACTIONS_H__

#include <errors.h>
#include <defines.h>

STORAGE_ERR register_new_credential(uint8_t *user_hash, uint8_t *master_pass, uint8_t *name, uint8_t *username, 
  uint8_t *passw, uint8_t *url, uint8_t *additional);

#endif