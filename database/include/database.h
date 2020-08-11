struct Database {
    uint16_t version;
    uint32_t cred_len;
    struct CredentialHeader *cred_headers; 
    struct Credential *cred;
    uint32_t db_len;
    uint8_t *dek_blob;
    uint8_t *dek_blob_enc_mac;
    uint8_t *dek_blob_enc_iv;
    uint8_t *iv_dek_blob;
    uint8_t *iv_dek_blob_enc_mac;
    uint8_t *iv_dek_blob_enc_iv;
    uint8_t *mac_dek_blob;
    uint8_t *mac_dek_blob_enc_mac;
    uint8_t *mac_dek_blob_enc_iv;
    uint8_t *kek_hash;
    uint8_t *kek_salt;
    uint8_t *login_hash;
    uint8_t *login_salt;

} __attribute__((packed, aligned(1)));

enum DatabaseEncryptedField {
    DEK_BLOB = 0,
    IV_DEK_BLOB = 1,
    MAC_DEK_BLOB = 2,
};

DB_ERROR create_new_db(struct Database *db);
DB_ERROR update_db_DEK(struct Database *db, uint8_t *dek_blob, uint8_t *iv_dek_blob, uint8_t *mac_dek_blob, uint8_t *master_pass);
DB_ERROR update_db_login(struct Database *db, uint8_t *login_hash, uint8_t *login_salt);
DB_ERROR update_db_KEK(struct Database *db, uint8_t *kek_hash, uint8_t *kek_salt);