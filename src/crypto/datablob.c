#include <datablob.h>
#include <crypto_utils.h>

PIPASS_ERR alloc_datablob(struct DataBlob *blob, int16_t ciphertext_len) {
    if (blob == NULL || !ciphertext_len)
        return ERR_ALLOC_DATABLOB_INV_PARAMS;
    
    blob->ciphertext = malloc(ciphertext_len);
    blob->iv = malloc(IV_SIZE);
    blob->mac = malloc(MAC_SIZE);

    if (blob->ciphertext == NULL || blob->mac == NULL || blob->iv == NULL) {
        free(blob->ciphertext);
        free(blob->iv);
        free(blob->mac);

        return ERR_ALLOC_DATABLOB_MEM_ALLOC;
    }

    return PIPASS_OK;
}

PIPASS_ERR datablob_memcpy(struct DataBlob *dest, struct DataBlob *src, int16_t ciphertext_len) {
    if (dest == NULL || src == NULL || datablob_has_null_fields(*dest), datablob_has_null_fields(*src))
        return ERR_DATABLOB_MEMCPY_INV_PARAMS;

    memcpy(dest->ciphertext, src->ciphertext, ciphertext_len);
    memcpy(dest->iv, src->iv, IV_SIZE);
    memcpy(dest->mac, src->mac, MAC_SIZE);

    return PIPASS_OK;
}

uint8_t datablob_has_null_fields(struct DataBlob blob) {
    return (blob.ciphertext == NULL || blob.iv == NULL || blob.mac == NULL);
}

void free_datablob(struct DataBlob *blob, uint32_t ciphertext_len) {
    if (blob == NULL)
        return;

    erase_buffer(&(blob->ciphertext), ciphertext_len);
    erase_buffer(&(blob->iv), IV_SIZE);
    erase_buffer(&(blob->mac), MAC_SIZE);
}