#include <actions.h>


STORAGE_ERR register_new_credential(uint8_t *user_hash, uint8_t *master_pass, uint8_t *name, uint8_t *username, 
  uint8_t *passw, uint8_t *url, uint8_t *additional) {

    if (user_hash == NULL || master_pass == NULL || name == NULL || passw == NULL || url == NULL || additional == NULL)
        return ERR_REG_NEW_CRED_INV_PARAMS;

    
}