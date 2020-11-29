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
    pthread_mutex_t lock;
} ScreensStack;

PIPASS_ERR stack_init();
void stack_push(display_func e);
display_func stack_top();
display_func stack_pop();
uint8_t stack_empty();
void stack_destroy();

#endif