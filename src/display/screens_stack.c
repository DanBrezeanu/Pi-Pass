#include <screens_stack.h>
#include <screens.h>
#include <pthread.h>

static ScreensStack *st;

PIPASS_ERR stack_init() {
    if (st != NULL)
        return ERR_SCREEN_ST_ALREADY_INIT;

    PIPASS_ERR err;
    int32_t ret;

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

    ret = pthread_mutex_init(&st->lock, NULL);
    if (ret != 0) {
        err = ERR_SCREEN_STACK_INIT_FAIL;
        goto error;
    }

    return PIPASS_OK;

error:
    free(st);

    return err;
}

void stack_push(display_func e) {
    pthread_mutex_lock(&st->lock);

    if (st->size == st->capacity) {
        st->capacity <<= 1;
        st->array = realloc(st->array, st->capacity * sizeof(display_func));
    }
    
    st->array[st->size++] = e;

    pthread_mutex_unlock(&st->lock);
}

display_func stack_top() {
    if (st->size == 0) {
        return NULL;
    }

    return st->array[st->size - 1];
}

display_func stack_pop() {
    pthread_mutex_lock(&st->lock);
    if (st->size == 0) {
        pthread_mutex_unlock(&st->lock);
        return NULL;
    }

    display_func ret = stack_top();
    --st->size;

    pthread_mutex_unlock(&st->lock);
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