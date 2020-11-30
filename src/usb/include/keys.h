/** @file keys.h */
#ifndef __KEYS_H__
#define __KEYS_H__

#include <defines.h>

#define key(x)      ((x) & 0xff)          ///< Extract the key code from Key
#define modifier(x) (((x) >> 8) & 0xff)   ///< Extract the modificer from Key

#define  KEY_NONE  0x0000       ///< No key

#define  KEY_a  0x0004          ///< "a" key
#define  KEY_b  0x0005          ///< "b" key
#define  KEY_c  0x0006
#define  KEY_d  0x0007
#define  KEY_e  0x0008
#define  KEY_f  0x0009
#define  KEY_g  0x000A
#define  KEY_h  0x000B
#define  KEY_i  0x000C
#define  KEY_j  0x000D
#define  KEY_k  0x000E
#define  KEY_l  0x000F
#define  KEY_m  0x0010
#define  KEY_n  0x0011
#define  KEY_o  0x0012
#define  KEY_p  0x0013
#define  KEY_q  0x0014
#define  KEY_r  0x0015
#define  KEY_s  0x0016
#define  KEY_t  0x0017
#define  KEY_u  0x0018
#define  KEY_v  0x0019
#define  KEY_w  0x001A
#define  KEY_x  0x001B
#define  KEY_y  0x001C
#define  KEY_z  0x001D

#define  KEY_A  0x0204
#define  KEY_B  0x0205
#define  KEY_C  0x0206
#define  KEY_D  0x0207
#define  KEY_E  0x0208
#define  KEY_F  0x0209
#define  KEY_G  0x020A
#define  KEY_H  0x020B
#define  KEY_I  0x020C
#define  KEY_J  0x020D
#define  KEY_K  0x020E
#define  KEY_L  0x020F
#define  KEY_M  0x0210
#define  KEY_N  0x0211
#define  KEY_O  0x0212
#define  KEY_P  0x0213
#define  KEY_Q  0x0214
#define  KEY_R  0x0215
#define  KEY_S  0x0216
#define  KEY_T  0x0217
#define  KEY_U  0x0218
#define  KEY_V  0x0219
#define  KEY_W  0x021A
#define  KEY_X  0x021B
#define  KEY_Y  0x021C
#define  KEY_Z  0x021D
#define  KEY_1  0x001E
#define  KEY_2  0x001F
#define  KEY_3  0x0020
#define  KEY_4  0x0021
#define  KEY_5  0x0022
#define  KEY_6  0x0023
#define  KEY_7  0x0024
#define  KEY_8  0x0025
#define  KEY_9  0x0026
#define  KEY_0  0x0027

#define  KEY_EXCLAMATION    0x021E
#define  KEY_AT             0x021F
#define  KEY_HASH           0x0220
#define  KEY_DOLLAR         0x0221
#define  KEY_PERCENT        0x0222
#define  KEY_CARAT          0x0223
#define  KEY_AMPERSAND      0x0224
#define  KEY_ASTERISK       0x0225
#define  KEY_PARANTH_OPEN   0x0226
#define  KEY_PARANTH_CLOSE  0x0227
#define  KEY_RETURN         0x0028
#define  KEY_ESCAPE         0x0029
#define  KEY_BACKSPACE      0x002A
#define  KEY_TAB            0x002B
#define  KEY_SPACE          0x002C
#define  KEY_MINUS          0x002D
#define  KEY_EQUAL          0x002E
#define  KEY_UNDERSCORE     0x022D
#define  KEY_PLUS           0x022E
#define  KEY_BRACKET_OPEN   0x002F
#define  KEY_BRACKET_CLOSE  0x0030
#define  KEY_BRACES_OPEN    0x022F
#define  KEY_BRACES_CLOSE   0x0230
#define  KEY_BACKSLASH      0x0031
#define  KEY_PIPE           0x0231
#define  KEY_EUROPE_1       0x0032
#define  KEY_SEMICOLON      0x0033
#define  KEY_COLON          0x0233
#define  KEY_APOSTROPHE     0x0034
#define  KEY_QUOTE          0x0234
#define  KEY_GRAVE          0x0035
#define  KEY_TILDE          0x0235
#define  KEY_COMMA          0x0036
#define  KEY_LESS_THAN      0x0236
#define  KEY_PERIOD         0x0037
#define  KEY_GREATER_THAN   0x0237
#define  KEY_SLASH          0x0038
#define  KEY_QUESTION_MARK  0x0238
#define  KEY_CAPS_LOCK      0x0039

#define  KEY_F1   0x003A
#define  KEY_F2   0x003B
#define  KEY_F3   0x003C
#define  KEY_F4   0x003D
#define  KEY_F5   0x003E
#define  KEY_F6   0x003F
#define  KEY_F7   0x0040
#define  KEY_F8   0x0041
#define  KEY_F9   0x0042
#define  KEY_F10  0x0043
#define  KEY_F11  0x0044
#define  KEY_F12  0x0045

#define  KEY_PRINT_SCREEN   0x0046
#define  KEY_SCROLL_LOCK    0x0047
#define  KEY_PAUSE          0x0048
//  KEY_INSERT             0x49
//  KEY_HOME               0x4A
//  KEY_PAGE_UP            0x4B
//  KEY_DELETE             0x4C
//  KEY_END                0x4D
//  KEY_PAGE_DOWN          0x4E
//  KEY_ARROW_RIGHT        0x4F
//  KEY_ARROW_LEFT         0x50
//  KEY_ARROW_DOWN         0x51
//  KEY_ARROW_UP           0x52
//  KEY_NUM_LOCK           0x53
//  KEY_KEYPAD_DIVIDE      0x54
//  KEY_KEYPAD_MULTIPLY    0x55
//  KEY_KEYPAD_SUBTRACT    0x56
//  KEY_KEYPAD_ADD         0x57
//  KEY_KEYPAD_ENTER       0x58
//  KEY_KEYPAD_1           0x59
//  KEY_KEYPAD_2           0x5A
//  KEY_KEYPAD_3           0x5B
//  KEY_KEYPAD_4           0x5C
//  KEY_KEYPAD_5           0x5D
//  KEY_KEYPAD_6           0x5E
//  KEY_KEYPAD_7           0x5F
//  KEY_KEYPAD_8           0x60
//  KEY_KEYPAD_9           0x61
//  KEY_KEYPAD_0           0x62
//  KEY_KEYPAD_DECIMAL     0x63
//  KEY_EUROPE_2_REAL      0x64
//  KEY_APPLICATION        0x65
//  KEY_POWER              0x66
//  KEY_KEYPAD_EQUAL       0x67
//  KEY_F13                0x68
//  KEY_F14                0x69
//  KEY_F15                0x6A
//  KEY_WIN_L              0xE3




//  KEY_CTRL               0x01
//  KEY_SHIFT              0x02
//  KEY_EUROPE_2           0x03
//  KEY_ALT                0x04
//  KEY_GUI                0x08
//  KEY_LEFT_CTRL          0x01
//  KEY_LEFT_SHIFT         0x02
//  KEY_LEFT_ALT           0x04
//  KEY_LEFT_GUI           0x08
//  KEY_RIGHT_CTRL         0x10
//  KEY_RIGHT_SHIFT        0x20
//  KEY_RIGHT_ALT          0x40
//  KEY_RIGHT_GUI          0x80


#endif