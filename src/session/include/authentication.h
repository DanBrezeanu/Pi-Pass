/** @file authentication.h */
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

/**
 * Authenticates and logs in the specified user.
 * Authentication can be accomplished by providing the master pin
 * and the necessary fingerprint or the master password.
 * 
 * This action also decrypts the database if the verification succeeds.
 * 
 * @param[in] user                  Username to log in with   
 * @param[in] user_len              Length of the username string 
 * @param[in] master_pin            The four digit master pin
 * @param[in] fp_data               Fingerprint data. Can be NULL if authentication
 *                                  is performed with master password
 * @param[in] master_password       The master password. Can be NULL if authentication
 *                                  is performed with fingerprint
 * @param[in] master_password_len   The length of the master password. Parameter is
 *                                  ignored if master_password is NULL
 *
 */
PIPASS_ERR authenticate(uint8_t *user, uint32_t user_len, uint8_t *master_pin,
  uint8_t *fp_data, uint8_t *master_password, uint32_t master_password_len);

/**
 * Verifies if the user provided exists. Verification is done by
 * checking if the appropiate directory exists.
 * 
 * @param[in] user      Username to verify
 * @param[in] user_len  Length of the username
 * 
 */
PIPASS_ERR verify_user_exists(uint8_t *user, uint32_t user_len);

#endif
