/** @file registration.h */
#ifndef __REGISTRATION_H__
#define __REGISTRATION_H__

#include <sys/types.h>
#include <sys/stat.h>
#include <errors.h>
#include <defines.h>

/**
 * Registers a new user to the device
 * 
 * @param[in] user_data             Username of the new user
 * @param[in] user_data_len         Length of the username
 * @param[in] master_pin            The new master pin
 * @param[in] fp_data               Fingerprint data
 * @param[in] master_password       The new master password
 * @param[in] master_password_len   Length of the master password
 * 
 */
PIPASS_ERR register_new_user(uint8_t *user_data, int32_t user_data_len, uint8_t *master_pin,
  uint8_t *fp_data, uint8_t *master_password, uint32_t master_password_len);

#endif
