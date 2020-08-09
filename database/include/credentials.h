#define CREDENTIAL_INIT { NULL, NULL, NULL, NULL, NULL }

struct Credential {
    uint8_t *name;
    uint8_t *username;
    uint8_t *passw;
    uint8_t *url;
    uint8_t *additional;
};

enum CredentialField {
    NAME = 0,
    USERNAME = 1,
    PASSW = 2,
    URL = 3,
    ADDITIONAL = 4
};