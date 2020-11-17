#include <draw_basic.h>
#include <display.h>
#include <python_api.h>
#include <draw.h>

static PyObject *render_module;
static PyObject *pillow_module;
static PyObject *free_pixel_font;

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

    if (free_pixel_font == NULL) {
        PyObject *image_font = NULL;

        err = get_attr(pillow_module, "ImageFont", &image_font);
        if (err != PIPASS_OK)
            goto error_font;

        err = get_and_call_function(image_font, "truetype", &free_pixel_font, 2,
         TO_PY_STRING(FREEPIXEL_FONT_PATH), TO_PY_LONG(12));
        if (err != PIPASS_OK)
            goto error_font;

        goto cleanup;
error_font:
        Py_XDECREF(image_font);
        return ERR_DISPLAY_GET_FONT_FAIL;
    }

cleanup:
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

PIPASS_ERR _draw_text(PyObject *device, int32_t x, int32_t y, uint8_t *text, uint8_t *fill, uint8_t font_attr,
  PyObject *canvas, uint32_t attrs, va_list args) {
    if (device == NULL)
        return ERR_DISPLAY_NOT_INIT;

    if (text == NULL || fill == NULL || canvas == NULL)
        return ERR_DISPLAY_TEXT_INV_PARAMS;

    PyObject *draw = NULL, *_ = NULL, *xy = NULL;
    PyObject *font = NULL;

    uint32_t alignment, max_width, max_height;

    PIPASS_ERR err = PIPASS_OK;

    switch (font_attr) {
    case DEFAULT_FONT:
        font = Py_None;
        break;
    case FREEPIXEL_FONT:
        font = free_pixel_font;
        break;
    default:
        err = ERR_DISPLAY_NO_SUCH_FONT;
        goto error;
    }

    switch (attrs) {
    case NO_ATTRIBUTES:
        xy = pack_arguments(2, TO_PY_LONG(x), TO_PY_LONG(y));
        break;
    case ALIGN_TEXT:
        alignment = va_arg(args, uint32_t);
        max_width = va_arg(args, uint32_t);
        max_height = va_arg(args, uint32_t);
        
        err = compute_alignment(text, font, canvas, alignment, x, y, max_width, max_height, &xy);
        if (err != PIPASS_OK)
            goto error;
        break;
    default:
        err = ERR_DISPLAY_NO_SUCH_ATTRIBUTE;
        goto error;
    }

    err = get_attr(canvas, "draw", &draw);
    if (err != PIPASS_OK)
        goto error; 

    if (font != Py_None)
        Py_INCREF(font);
        
    err = get_and_call_function(draw, "text", &_, 4, xy, TO_PY_STRING(text), TO_PY_STRING(fill), font);
    if (err != PIPASS_OK)
        goto error;

    err = PIPASS_OK;

error:
    Py_XDECREF(draw);
    Py_XDECREF(xy);
    Py_XDECREF(_);

    return err;
}

PIPASS_ERR _draw_rectangle(PyObject *device, int32_t x1, int32_t y1, int32_t x2, int32_t y2, uint8_t *fill, 
  uint8_t *outline, PyObject *canvas) {

    if (device == NULL)
        return ERR_DISPLAY_NOT_INIT;

    if (fill == NULL || outline == NULL || canvas == NULL)
        return ERR_DISPLAY_RECT_INV_PARAMS;

    PIPASS_ERR err;
    PyObject *draw = NULL, *xy = NULL, *_ = NULL;

    xy = pack_arguments(4, TO_PY_LONG(x1), TO_PY_LONG(y1), TO_PY_LONG(x2), TO_PY_LONG(y2));

    err = get_attr(canvas, "draw", &draw);
    if (err != PIPASS_OK)
        goto error;

    err = get_and_call_function(draw, "rectangle", &_, 3, xy, TO_PY_STRING(fill), TO_PY_STRING(outline));
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
    Py_XDECREF(pillow_image);
    Py_XDECREF(image_size);

    return err;
}

PIPASS_ERR compute_alignment(uint8_t *text, PyObject *font, PyObject *canvas, uint32_t alignment,
  uint32_t x1, uint32_t y1, uint32_t x2, uint32_t y2, PyObject **xy) {
    
    if (text == NULL || font == NULL) {
        return ERR_COMPUTE_ALIGN_INV_PARAMS;
    }

    PIPASS_ERR err;

    if (alignment == ALIGN_LEFT) { 
        *xy = pack_arguments(2, TO_PY_LONG(x1), TO_PY_LONG(y1));
        return PIPASS_OK;
    }

    PyObject *width_height = NULL, *draw = NULL, *_width = NULL, *_height = NULL;
    uint32_t width, height;

    err = get_attr(canvas, "draw", &draw);
    if (err != PIPASS_OK)
        goto error;

    Py_INCREF(font);
    err = get_and_call_function(draw, "textsize", &width_height, 2, TO_PY_STRING(text), font);
    if (err != PIPASS_OK)
        goto error;

    err = get_item_at(width_height, 0, &_width);
    if (err != PIPASS_OK)
        goto error;

    err = get_item_at(width_height, 1, &_height);
    if (err != PIPASS_OK)
        goto error;

    width  = FROM_PY_LONG(_width);
    height = FROM_PY_LONG(_height);
    
    if (alignment == ALIGN_RIGHT) {
        *xy = pack_arguments(2, TO_PY_LONG(x2 - width), TO_PY_LONG(y1));
    } else if (alignment == ALIGN_CENTER) {
        int32_t x = (x1 + MAX(0, (int32_t)(x2 - x1 - width) / 2));
        int32_t y = (y1 + MAX(0, (int32_t)(y2 - y1 - height) / 2));

        *xy = pack_arguments(2, TO_PY_LONG(x), TO_PY_LONG(y));
    } else {
        err = ERR_DISPLAY_NO_SUCH_ALIGN;
        goto error;
    }

    
    err = PIPASS_OK;

error:
    Py_XDECREF(width_height);
    Py_XDECREF(draw);
    Py_XDECREF(_width);
    Py_XDECREF(_height);

    return err;
}