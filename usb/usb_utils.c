#include <usb_utils.h>
#include <errors.h>

KEY key_from_byte(BYTE ch) {
    switch (ch) {
    case 'a': return KEY_a;
    case 'b': return KEY_b;
    case 'c': return KEY_c;
    case 'd': return KEY_d;
    case 'e': return KEY_e;
    case 'f': return KEY_f;
    case 'g': return KEY_g;
    case 'h': return KEY_h;
    case 'i': return KEY_i;
    case 'j': return KEY_j;
    case 'k': return KEY_k;
    case 'l': return KEY_l;
    case 'm': return KEY_m;
    case 'n': return KEY_n;
    case 'o': return KEY_o;
    case 'p': return KEY_p;
    case 'q': return KEY_q;
    case 'r': return KEY_r;
    case 's': return KEY_s;
    case 't': return KEY_t;
    case 'u': return KEY_u;
    case 'v': return KEY_v;
    case 'w': return KEY_w;
    case 'x': return KEY_x;
    case 'y': return KEY_y;
    case 'z': return KEY_z;
    case 'A': return KEY_A;
    case 'B': return KEY_B;
    case 'C': return KEY_C;
    case 'D': return KEY_D;
    case 'E': return KEY_E;
    case 'F': return KEY_F;
    case 'G': return KEY_G;
    case 'H': return KEY_H;
    case 'I': return KEY_I;
    case 'J': return KEY_J;
    case 'K': return KEY_K;
    case 'L': return KEY_L;
    case 'M': return KEY_M;
    case 'N': return KEY_N;
    case 'O': return KEY_O;
    case 'P': return KEY_P;
    case 'Q': return KEY_Q;
    case 'R': return KEY_R;
    case 'S': return KEY_S;
    case 'T': return KEY_T;
    case 'U': return KEY_U;
    case 'V': return KEY_V;
    case 'W': return KEY_W;
    case 'X': return KEY_X;
    case 'Y': return KEY_Y;
    case 'Z': return KEY_Z;
    case '1': return KEY_1;
    case '2': return KEY_2;
    case '3': return KEY_3;
    case '4': return KEY_4;
    case '5': return KEY_5;
    case '6': return KEY_6;
    case '7': return KEY_7;
    case '8': return KEY_8;
    case '9': return KEY_9;
    case '0': return KEY_0;
    case '!': return KEY_EXCLAMATION;
    case '@': return KEY_AT;
    case '#': return KEY_HASH;
    case '$': return KEY_DOLLAR;
    case '%': return KEY_PERCENT;
    case '^': return KEY_CARAT;
    case '&': return KEY_AMPERSAND;
    case '*': return KEY_ASTERISK;
    case '(': return KEY_PARANTH_OPEN;
    case ')': return KEY_PARANTH_CLOSE;
    case '_': return KEY_UNDERSCORE;
    case '+': return KEY_PLUS;
    case ' ': return KEY_SPACE;
    case '-': return KEY_MINUS;
    case '=': return KEY_EQUAL;
    case '[': return KEY_BRACKET_OPEN;
    case ']': return KEY_BRACKET_CLOSE;
    case '{': return KEY_BRACES_OPEN;
    case '}': return KEY_BRACES_CLOSE;
    case '\\': return KEY_BACKSLASH;
    case '|': return KEY_PIPE;
    case ';': return KEY_SEMICOLON;
    case ':': return KEY_COLON;
    case '\'': return KEY_APOSTROPHE;
    case '\"': return KEY_QUOTE;
    case '`': return KEY_GRAVE;
    case '~': return KEY_TILDE;
    case ',': return KEY_COMMA;
    case '<': return KEY_LESS_THAN;
    case '.': return KEY_PERIOD;
    case '>': return KEY_GREATER_THAN;
    case '/': return KEY_SLASH;
    case '?': return KEY_QUESTION_MARK;
    case '\n': return KEY_RETURN;
    default: return ERR_KEY_NOT_DEFINED;
    }
}