#include <draw_basic.h>
#include <display.h>

static PyObject *render_module;
static PyObject *pillow_module;

PIPASS_ERR init_draw() {
    PIPASS_ERR err;

    if (render_module == NULL) {
        err = import_module("luma.core.render", &render_module);
        if (err != PIPASS_OK)
            return err;
    }

    if (pillow_module == NULL) {
        err = import_module("PIL", &pillow_module);
        if (err != PIPASS_OK)
            return err;
    }

    return PIPASS_OK;
}

PIPASS_ERR _display(PyObject *device, PyObject *canvas) {
    if (device == NULL)
        return ERR_DISPLAY_NOT_INIT;

    if (canvas == NULL)
        return ERR_DISPLAY_CANVAS_INV_PARAMS;

    PIPASS_ERR err;
    PyObject *canv_image = NULL, *_ = NULL;

    err = get_attr(canvas, "image", &canv_image);
    if (err != PIPASS_OK)
        goto error;

    err = get_and_call_function(device, "display", &_, 1, canv_image);
    if (err != PIPASS_OK)
        goto error;

    err = PIPASS_OK;

error:
    Py_XDECREF(canv_image);
    Py_XDECREF(_);

    return err;
}

PIPASS_ERR _draw_image(PyObject *device, int32_t x, int32_t y, uint8_t* image_res, PyObject **background) {
    if (device == NULL)
        return ERR_DISPLAY_NOT_INIT;

    if (pillow_module == NULL)
        return ERR_DRAW_NOT_INIT;

    if (image_res == NULL)
        return ERR_DRAW_IMG_INV_PARAMS;

    PIPASS_ERR err;

    if (*background == NULL) {
        err = new_image(device, DISPLAY_WIDTH, DISPLAY_HEIGHT, background);
        if (err != PIPASS_OK)
            return err;
    }

    PyObject *pillow_image = NULL, *image = NULL, *xy = NULL, *_ = NULL;

    err = get_attr(pillow_module, "Image", &pillow_image);
    if (err != PIPASS_OK)
        goto error;



    err = get_and_call_function(pillow_image, "open", &image, 1, TO_PY_STRING(image_res));
    if (err != PIPASS_OK)
        goto error;  
    
    xy = pack_arguments(2, TO_PY_LONG(x), TO_PY_LONG(y));

    err = get_and_call_function(*background, "paste", &_, 2, image, xy);
    if (err != PIPASS_OK)
        goto error;

    err = PIPASS_OK;

error:
    Py_XDECREF(pillow_image);
    Py_XDECREF(image);
    Py_XDECREF(xy);
    Py_XDECREF(_);

    return err;
}

PIPASS_ERR _draw_text(PyObject *device, int32_t x, int32_t y, uint8_t *text, PyObject *canvas) {
    if (device == NULL)
        return ERR_DISPLAY_NOT_INIT;

    if (text == NULL || canvas == NULL)
        return ERR_DISPLAY_TEXT_INV_PARAMS;

    PyObject *draw = NULL, *_ = NULL, *xy = NULL;

    PIPASS_ERR err = PIPASS_OK;

    err = get_attr(canvas, "draw", &draw);
    if (err != PIPASS_OK)
        goto error; 

    xy = pack_arguments(2, TO_PY_LONG(x), TO_PY_LONG(y));

    err = get_and_call_function(draw, "text", &_, 3, xy, TO_PY_STRING(text), TO_PY_STRING("white"));
    if (err != PIPASS_OK)
        goto error;

    err = PIPASS_OK;

error:
    Py_XDECREF(draw);
    Py_XDECREF(xy);
    Py_XDECREF(_);

    return err;
}

PIPASS_ERR _create_canvas(PyObject *device, PyObject *background, PyObject **canvas) {
    if (device == NULL)
        return ERR_DISPLAY_NOT_INIT;

    if (render_module == NULL)
        return ERR_DRAW_NOT_INIT;

    PIPASS_ERR err;
    PyObject *canv = NULL, *_ = NULL;

    if (background != NULL)
        err = get_and_call_function(render_module, "canvas", &canv, 2, device, background);
    else
        err = get_and_call_function(render_module, "canvas", &canv, 1, device);

    if (err != PIPASS_OK)
        goto error;
    
    err = get_and_call_function(canv, "__enter__", &_, 0);
    if (err != PIPASS_OK)
        goto error;

    *canvas = canv;

    err = PIPASS_OK;
    goto cleanup;

error:
    Py_XDECREF(canv);
cleanup:
    Py_XDECREF(_);

    return err;
}

PIPASS_ERR new_image(PyObject *device, uint32_t width, uint32_t height, PyObject **image) {
    if (device == NULL)
        return ERR_DISPLAY_NOT_INIT;

     if (pillow_module == NULL)
        return ERR_DRAW_NOT_INIT;

    PIPASS_ERR err;
    PyObject *device_mode = NULL, *pillow_image = NULL;
    PyObject *image_result = NULL, *image_size = NULL;

    err = get_attr(pillow_module, "Image", &pillow_image);
    if (err != PIPASS_OK)
        goto error;

    err = get_attr(device, "mode", &device_mode);
    if (err != PIPASS_OK)
        goto error;

    image_size = pack_arguments(2, TO_PY_LONG(width), TO_PY_LONG(height));

    err = get_and_call_function(pillow_image, "new", &image_result, 2, device_mode, image_size);
    if (err != PIPASS_OK)
        goto error;

    *image = image_result;
    
    err = PIPASS_OK;
    goto cleanup;

error:
    Py_XDECREF(image_result);
cleanup:
    Py_XDECREF(device_mode);
    Py_XDECREF(pillow_module);
    Py_XDECREF(pillow_image);
    Py_XDECREF(image_size);

    return err;
}
