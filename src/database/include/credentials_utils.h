#ifndef __CREDENTIALS_UTILS_H__
#define __CREDENTIALS_UTILS_H__

PIPASS_ERR memcpy_credentials(struct Credential *dest, struct Credential *src);
PIPASS_ERR copy_credential(struct Credential src, struct Credential *copy);

#endif