#ifndef __CREDENTIALS_UTILS_H__
#define __CREDENTIALS_UTILS_H__

PIPASS_ERR memcpy_credential_blobs(struct Credential *dst, struct Credential *src, struct CredentialHeader *crh);
PIPASS_ERR memcpy_credentials(struct Credential *dest, struct Credential *src, struct CredentialHeader *crh);

#endif