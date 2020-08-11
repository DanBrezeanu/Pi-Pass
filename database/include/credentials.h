#define CREDENTIAL_INIT { NULL, NULL, NULL, NULL, NULL }
#define CREDENTIAL_HEADER_INIT { 0, 0, 0, 0, 0, 0 }

struct Credential {
    uint8_t *name;
    uint8_t *username;
    uint8_t *username_mac;
    uint8_t *username_iv;
    uint8_t *passw;
    uint8_t *passw_mac;
    uint8_t *passw_iv;
    uint8_t *url;
    uint8_t *additional;
} __attribute__((packed, aligned(1)));

struct CredentialHeader {
    uint32_t cred_len;
    uint16_t name_len;
    uint16_t username_len;
    uint16_t passw_len;
    uint16_t url_len;
    uint16_t additional_len;
} __attribute__((packed, aligned(1)));

enum CredentialField {
    NAME       = 0,
    URL        = 1,
    ADDITIONAL = 2
};

enum CredentialEncryptedField {
    USERNAME = 0,
    PASSW    = 1
};