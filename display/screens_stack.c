#include <screens_stack.h>
#include <screens.h>

static ScreensStack *st;

PIPASS_ERR stack_init() {
    if (st != NULL)
        return ERR_SCREEN_ST_ALREADY_INIT;

    PIPASS_ERR err;

    st = calloc(1, sizeof(ScreensStack));
    if (st == NULL)
        return ERR_DISPLAY_MEM_ALLOC;

    st->capacity = 32;
    st->size = 0;

    st->array = calloc(st->capacity, sizeof(display_func));
    if (st->array == NULL) {
        err = ERR_DISPLAY_MEM_ALLOC;
        goto error;
    }

    return PIPASS_OK;

error:
    free(st);

    return err;
}

void stack_push(display_func e) {

    if (st->size == st->capacity) {
        st->capacity <<= 1;
        st->array = realloc(st->array, st->capacity * sizeof(display_func));
    }
    
    st->array[st->size++] = e;
}

display_func stack_top() {
    if (st->size == 0) {
        return NULL;
    }

    return st->array[st->size - 1];
}

display_func stack_pop() {
    if (st->size == 0) {
        return NULL;
    }

    display_func ret = stack_top();
    --st->size;

    return ret;
}

uint8_t stack_empty() {
    return (st->size == 0);
}

void stack_destroy() {
    if (st == NULL)
        return;

    free(st->array);
    free(st);
}