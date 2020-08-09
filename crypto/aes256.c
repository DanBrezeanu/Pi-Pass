#include <aes256.h>

CRYPTO_ERR generate_aes256_key(uint8_t *key) {
    int32_t err = RAND_bytes(key, AES256_KEY_SIZE);
    if (err == -1) {
        return ERR_RAND_NOT_SUPPORTED;
    }

    if (err == 0) {
        zero_buffer(key, AES256_KEY_SIZE);
        return ERR_RAND_FAIL;
    }

    return CRYPTO_OK;
}

CRYPTO_ERR create_PBKDF2_key(uint8_t *input, int32_t input_len, uint8_t *salt, int32_t salt_len, uint8_t *pbkdf2_key) {
    if (input == NULL || salt == NULL || pbkdf2_key == NULL || !input_len || !salt_len)
        return ERR_AES_PBKDF_INV_PARAMS;

    fastpbkdf2_hmac_sha256(input, input_len, salt, salt_len, PBKDF2_ITERATIONS, pbkdf2_key, AES256_KEY_SIZE);

    return CRYPTO_OK;
}

CRYPTO_ERR encrypt_aes256(uint8_t *plaintext, int32_t plaintext_len, uint8_t *aad, int32_t aad_len, uint8_t *key,
    uint8_t *iv, uint8_t *mac, uint8_t *ciphertext, int32_t *ciphertext_len) {

    EVP_CIPHER_CTX *ctx = NULL;
    CRYPTO_ERR err = CRYPTO_OK;
    int32_t res;
    int32_t length;

    if (plaintext == NULL || ciphertext == NULL || !plaintext_len)
        return ERR_AES_ENC_INV_PARAMS;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return ERR_AES_ENC_EVP_INIT;

    res = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    if (res != SSL_OK) {
        err = ERR_AES_ENC_EVP_INIT;
        goto error;
    }

    res = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, NULL);
    if (res != SSL_OK) {
        err = ERR_AES_ENC_SET_IVLEN;
        goto error;
    }

    res = EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    if (res != SSL_OK) {
        err = ERR_AES_ENC_EVP_INIT_KEY;
        goto error;
    }

    if (aad != NULL && aad_len > 0) {
        res = EVP_EncryptUpdate(ctx, NULL, &length, aad, aad_len);
        if (res != SSL_OK) {
            err = ERR_AES_ENC_EVP_AAD;
            goto error;
        }

        *ciphertext_len = length;
    }

    res = EVP_EncryptUpdate(ctx, ciphertext, &length, plaintext, plaintext_len);
    if (res != SSL_OK) {
        err = ERR_AES_ENC_EVP_ENCRYPT;
        goto error;
    }
    *ciphertext_len = length;

    res = EVP_EncryptFinal_ex(ctx, ciphertext + length, &length);
    if (res != SSL_OK) {
        err = ERR_AES_ENC_EVP_FINAL;
        goto error;
    }
    *ciphertext_len += length;

    res = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, MAC_SIZE, mac);
    if (res != SSL_OK) {
        err = ERR_AES_ENC_EVP_MAC;
        goto error;
    }

    EVP_CIPHER_CTX_free(ctx);
    return CRYPTO_OK;

error:
    EVP_CIPHER_CTX_free(ctx);
    *ciphertext_len = 0;
    zero_buffer(ciphertext, plaintext_len);
    return err;
}

CRYPTO_ERR decrypt_aes256(uint8_t *ciphertext, int32_t ciphertext_len, uint8_t *aad, int32_t aad_len, uint8_t *mac,
    uint8_t *key, uint8_t *iv, uint8_t *plaintext, int32_t *plaintext_len) {
    
    EVP_CIPHER_CTX *ctx = NULL;
    CRYPTO_ERR err = CRYPTO_OK;
    int32_t res;
    int32_t length;

    if (plaintext == NULL || ciphertext == NULL || !ciphertext_len)
        return ERR_AES_DEC_INV_PARAMS;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return ERR_AES_DEC_EVP_INIT;

    res = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    if (res != SSL_OK) {
        err = ERR_AES_DEC_EVP_INIT;
        goto error;
    }

    res = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, NULL);
    if (res != SSL_OK) {
        err = ERR_AES_DEC_SET_IVLEN;
        goto error;
    }

    res = EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
    if (res != SSL_OK) {
        err = ERR_AES_DEC_EVP_INIT_KEY;
        goto error;
    }

    if (aad != NULL && aad_len > 0) {
        res = EVP_DecryptUpdate(ctx, NULL, &length, aad, aad_len);
        if (res != SSL_OK) {
            err = ERR_AES_DEC_EVP_AAD;
            goto error;
        }

        *plaintext_len = length;
    }

    res = EVP_DecryptUpdate(ctx, plaintext, &length, ciphertext, ciphertext_len);
    if (res != SSL_OK) {
        err = ERR_AES_DEC_EVP_DECRYPT;
        goto error;
    }
    *plaintext_len = length;

    res = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, MAC_SIZE, mac);
    if (res != SSL_OK) {
        err = ERR_AES_DEC_EVP_MAC;
        goto error;
    }

    res = EVP_DecryptFinal_ex(ctx, plaintext + length, &length);
    if (res != SSL_OK) {
        err = ERR_AES_DEC_EVP_FINAL;
        goto error;
    }
    *plaintext_len += length;

    EVP_CIPHER_CTX_free(ctx);
    return CRYPTO_OK;

error:
    EVP_CIPHER_CTX_free(ctx);
    *plaintext_len = 0;
    zero_buffer(plaintext, ciphertext_len);
    return err;
}


// int main() {
//     uint8_t *pin = malloc(MASTER_PASS_SIZE);
//     memcpy(pin, "1234", 4);

//     uint8_t *salt = malloc(SALT_SIZE);
//     CRYPTO_ERR err = create_salt(SALT_SIZE, salt);
//     if (err != CRYPTO_OK)
//         return err; 

//     int fds = open("test_enc/key_salt", O_WRONLY | O_CREAT, 0644);
//     write(fds, salt, SALT_SIZE);
//     close(fds);  

//     uint8_t *file_key = malloc(AES256_KEY_SIZE);

//     err = create_PBKDF2_key(pin, MASTER_PASS_SIZE, salt, SALT_SIZE, file_key);
//     if (err != CRYPTO_OK)
//         return err;

//     uint8_t *iv = malloc(IV_SIZE); 
    
//     err = create_salt(IV_SIZE, iv);
//     if (err != CRYPTO_OK)
//         return err;

//     int fdiv = open("test_enc/iv", O_WRONLY | O_CREAT, 0644);
//     write(fdiv, iv, IV_SIZE);
//     close(fdiv); 

//     uint8_t *mac = malloc(MAC_SIZE);
//     uint8_t *cipher = malloc(500);
//     int cipher_len = 0;

//     err = encrypt_aes256("Anamere", 7, "ADDIT", 5, file_key, iv, mac, cipher, &cipher_len);
//     if (err != CRYPTO_OK)
//         return err;

//     int fd = open("result.bin", O_WRONLY | O_CREAT, 0777);
//     write(fd, cipher, cipher_len);

//     int fdmac = open("test_enc/mac", O_WRONLY | O_CREAT, 0644);
//     write(fdmac, mac, MAC_SIZE);
//     close(fdmac); 

    
//     uint8_t *message = malloc(5);
//     int message_len = 0;

//     uint8_t *file_key_dec = malloc(AES256_KEY_SIZE);
//     create_PBKDF2_key(pin, MASTER_PASS_SIZE, salt, SALT_SIZE, file_key_dec);

//     err = decrypt_aes256(cipher, cipher_len, "ADDIT", 5, mac, file_key_dec, iv, message, &message_len);
//     if (err != CRYPTO_OK)
//         return err;

//     message[message_len] = 0;
//     printf("%s\n", message);
    

//     return 0;
// }