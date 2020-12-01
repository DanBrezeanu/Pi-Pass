/** @file crypto_utils.h */
#ifndef __CRYPTO_UTILS_H__
#define __CRYPTO_UTILS_H__

#include <string.h>
#include <stdint.h>
#include <defines.h>
#include <errors.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

/**
 * Zeros a buffer `buf` of length `size` bytes.
 * 
 * @param[in,out]  buf    Buffer to zero
 * @param[in]      size   Size in bytes of the buffer
 * 
 * @note This function cannot fail. Buffer is not checked against
 *       the given size.
 */
void zero_buffer(uint8_t *buf, int32_t size);

/**
 * Zeros and frees a dynamically allocated buffer.
 * 
 * @param[in,out] buf   Pointer to a dynamically allocated buffer
 * @param[in]     size  Size of the buffer
 * 
 * @note This function is safe for `NULL` buffers.
 * 
 * @note This function cannot fail. Buffer is not checked against
 *       the given size.
 * 
 * @note The buffer is set to `NULL` after being free'd.
 */
void erase_buffer(uint8_t **buf, int32_t size);

/**
 * Converts a raw buffer to its equivalent hex representation of each byte.
 * 
 * @param[in]  raw       The buffer to convert
 * @param[in]  raw_len   The length of the buffer
 * @param[out] hex       Pointer to the output hex buffer. `*hex` must be `NULL`,
 *                       memory will be alloc'd inside the function
 * @param[out] hex_len   The length of the output hex buffer. The expected length
 *                       will be `2 * raw_len`
 * 
 * @note The output buffer will be 0-terminated for easy human-readable printing.
 * 
 * @return #PIPASS_OK if the buffer has been successfully converted, else:
 *            - #ERR_RAW2HEX_INV_PARAMS
 *            - #ERR_CRYPTO_MEM_LEAK
 *            - #ERR_CRYPTO_MEM_ALLOC
 */
PIPASS_ERR raw_to_hex(uint8_t *raw, uint32_t raw_len, uint8_t **hex, uint32_t *hex_len);

/**
 * Checks if a buffer is 0-terminated and non-NULL.
 * 
 * @param[in] buf      The buffer to check
 * @param[in] buf_len  The length of the buffer
 * 
 * @return #PIPASS_OK if the buffer satisfies the conditions mentioned above, else:
 *              - #ERR_BUF_SANITY_CHECK_FAIL
 */
PIPASS_ERR sanity_check_buffer(uint8_t *buf, uint8_t buf_len);

/**
 * Extracts the CPU hardware ID.
 * 
 * @param[out] hw_id   The buffer containing the CPU ID. The length of the buffer will be #CPU_ID_SIZE.
 *                     `*hw_id` must be `NULL`, memory will be alloc'd inside the function. 
 * 
 * @note This function is **NOT PORTABLE**. This was explicitly written for the
 *       Raspberry Pi Zero, Raspberry Pi OS 10 Buster.
 * 
 * @return #PIPASS_OK if the hardware ID has been successfully extracted, else:
 *              - #ERR_CRYPTO_MEM_LEAK
 *              - #ERR_RETRIEVE_CPU_ID
 *              - #ERR_CRYPTO_MEM_ALLOC
 *              
 */
PIPASS_ERR cpu_id(uint8_t **hw_id);

/**
 *  Concatenates the given pin with the hardware specific pepper.
 *  For now the chosen pepper is the CPU ID.
 *  
 *  @param[in]   pin           A #MASTER_PIN_SIZE long buffer containtaing the master pin.
 *  @param[out]  pin_pepper    The buffer containing the given pin concatenated with the
 *                             hardware pepper. `*pin_pepper` must be `NULL`, memory will be
 *                             alloc'd inside the function.
 *                             The length of the output buffer will be #MASTER_PIN_SIZE_WITH_PEPPER.
 * 
 *  @return #PIPASS_OK if the buffers have been successfully concatenated, else:
 *              - #ERR_CONCAT_PEPPER_INV_PARAMS
 *              - #ERR_RETRIEVE_CPU_ID
 *              - #ERR_CRYPTO_MEM_LEAK
 *              - #ERR_CRYPTO_MEM_ALLOC
 * 
 */
PIPASS_ERR concat_pin_pepper(uint8_t *pin, uint8_t **pin_pepper);

#endif
