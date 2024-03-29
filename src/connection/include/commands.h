#ifndef __COMMANDS_H__
#define __COMMANDS_H__

#include <defines.h>
#include <errors.h>
#include <json.h>

#define SENDER_PIPASS 0x01
#define SENDER_APP    0x02
#define SENDER_PLUGIN 0x03 

#define APP_HELLO   0xB0


#define NO_COMMAND          0x00

/* 
|-- 1 byte --|-- 1 byte -- |-- 2 bytes --|-- 2 bytes --|
|   command  |   sender    |   length    |     CRC     |
*/
#define LIST_CREDENTIALS    0xC0

/* 
|-- 1 byte --|-- 1 byte -- |-- 2 bytes --|-- 4 bytes --|-- 2 bytes --|
|   command  |   sender    |   length    |   cred_id   |     CRC     |
*/
#define DELIVER_CREDENTIALS_HID 0xC1

/* 
|-- 1 byte --|-- 1 byte -- |-- 2 bytes --|-- 4 bytes --|-- 2 bytes --|
|   command  |   sender    |   length    |   cred_id   |     CRC     |
*/
#define DELIVER_CRED_PASSWD_HID 0xC2

/* 
|-- 1 byte --|-- 1 byte -- |-- 2 bytes --|-- 4 bytes --|-- 2 bytes --|
|   command  |   sender    |   length    |   cred_id   |     CRC     |
*/
#define DELIVER_CRED_USER_HID   0xC3

/* 
|-- 1 byte --|-- 1 byte -- |-- 2 bytes --|-- 4 bytes --|-- 2 bytes --|
|   command  |   sender    |   length    |   cred_id   |     CRC     |
*/
#define DELIVER_CREDENTIALS_ACM 0xC2

/* 
|-- 1 byte --|-- 1 byte -- |-- 2 bytes --|-- 4 bytes --|-- 2 bytes --|
|   command  |   sender    |   length    |   cred_id   |     CRC     |
*/
#define DELETE_CREDENTIALS  0xC3

/* 
|-- 1 byte --|-- 1 byte -- |-- 2 bytes --|-- 2 bytes --|
|   command  |   sender    |   length    |     CRC     |
*/
#define STORE_CREDENTIALS   0xC4
#define EDIT_CREDENTIALS    0xC5

#define ENROLL_FINGERPRINT 0xC5
#define DELETE_FINGERPRINT 0xC6
#define LIST_FINGERPRINT   0xC7

#define LOCK_DEVICE        0xC8
#define WIPE_DEVICE        0xC9

#define CHANGE_PIN         0xCA
#define CHANGE_DIP_SWITCH  0XCB 

#define ASK_FOR_PASSWORD   0xCC
#define ASK_FOR_PIN        0xCD
#define CREDENTIAL_DETAILS 0xCE
#define ENCRYPTED_FIELD_VALUE 0xCF
#define ADD_CREDENTIAL      0xD0

#define DEVICE_AUTHENTICATED 0xE0

extern uint8_t command_to_send; 


struct cmd_header {
    uint16_t length;          // 2 bytes in case SERIAL_PKG_SIZE is bigger than 256
    uint16_t crc;
};

typedef struct Cmd {
    struct cmd_header header;
    json_object *body;
} Cmd;

#define AUTH_TOKEN_SIZE     16
#define SERIAL_HEADER_SIZE  4

PIPASS_ERR create_command(uint8_t cmd_code, Cmd **cmd);
PIPASS_ERR parse_buffer_to_cmd(uint8_t *buf, int32_t buf_size, Cmd **cmd);
PIPASS_ERR parse_cmd_to_buffer(Cmd *cmd, uint8_t *buf);
uint8_t cmd_requires_additional(Cmd *cmd);
void free_command(Cmd **cmd);

#endif
