#ifndef __COMMANDS_H__
#define __COMMANDS_H__

#include <defines.h>
#include <errors.h>

#define SENDER_PIPASS 0x01
#define SENDER_APP    0x02
#define SENDER_PLUGIN 0x03 

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




typedef struct Command {
    uint8_t type;
    uint8_t reply_code;

    uint8_t *send_buff;
    uint8_t *recv_buff;

} Command;

#endif
