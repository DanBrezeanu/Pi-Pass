#ifndef __SCREENS_STACK_H__
#define __SCREENS_STACK_H__

#include <errors.h>
#include <defines.h>
#include <screens.h>

typedef PIPASS_ERR (*display_func) (enum Button);

typedef struct ScreensStack {
    uint16_t capacity;
    uint16_t size;
    display_func *array;

} ScreensStack;


#endif