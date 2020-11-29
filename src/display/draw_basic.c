#include <draw_basic.h>
#include <display.h>
#include <python_api.h>
#include <draw.h>

static PyObject *render_module;
static PyObject *pillow_module;
static PyObject *free_pixel_font;
static PyObject *pixelmix_font;
static PyObject *fontawesome_font;

PIPASS_ERR load_fonts();

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

    err = load_fonts();
    if (err != PIPASS_OK)
        goto error;
    
    return PIPASS_OK;

error:
    return err;
}

PIPASS_ERR load_fonts() {
    PIPASS_ERR err;
    const uint32_t FONTS_COUNT = 3;

    uint8_t *font_paths[] = {
        FREEPIXEL_FONT_PATH,
        PIXELMIX_FONT_PATH,
        FONTAWESOME_FONT_PATH
    };
    uint32_t font_sizes[] = {12, 25, 12};
    PyObject **font_pyobjects[] = {
        &free_pixel_font,
        &pixelmix_font,
        &fontawesome_font
    };
    PyObject *image_font = NULL;

    for (int32_t i = 0; i < FONTS_COUNT; ++i) {
        if (*font_pyobjects[i] == NULL) {
            err = get_attr(pillow_module, "ImageFont", &image_font);
            if (err != PIPASS_OK)
                goto error;

            err = get_and_call_function(image_font, "truetype", font_pyobjects[i], 2,
            TO_PY_STRING(font_paths[i]), TO_PY_LONG(font_sizes[i]));
            if (err != PIPASS_OK)
                goto error;

            Py_XDECREF(image_font);
            image_font = NULL;
        }
    }

    err = PIPASS_OK;

error:
    return err;
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

PIPASS_ERR _draw_text(PyObject *device, int32_t x, int32_t y, uint8_t *text, uint8_t *fill,
 uint8_t highlight, uint8_t font_attr, PyObject *canvas, uint32_t attrs, va_list args) {
    if (device == NULL)
        return ERR_DISPLAY_NOT_INIT;

    if (text == NULL || fill == NULL || canvas == NULL)
        return ERR_DISPLAY_TEXT_INV_PARAMS;

    PyObject *draw = NULL, *_ = NULL, *xy = NULL;
    PyObject *font = NULL;

    uint32_t alignment, max_width, max_height;

    PIPASS_ERR err = PIPASS_OK;

    /* Determine font */
    if (IS_UTF(text))
        font_attr = FONTAWESOME_FONT;

    switch (font_attr) {
    case DEFAULT_FONT:
        font = Py_None;
        break;
    case FREEPIXEL_FONT:
        font = free_pixel_font;
        break;
    case PIXELMIX_FONT:
        font = pixelmix_font;
        break;
    case FONTAWESOME_FONT:
        font = fontawesome_font;
        break;
    default:
        err = ERR_DISPLAY_NO_SUCH_FONT;
        goto error;
    }

    int32_t aligned_x = 0, aligned_y = 0;
    int32_t text_width = 0, text_height = 0;

    /* Determine x,y if text is aligned */
    switch (attrs) {
    case NO_ATTRIBUTES:
        aligned_x = x;
        aligned_y = y;
        break;
    case ALIGN_TEXT:
        alignment = va_arg(args, uint32_t);
        max_width = va_arg(args, uint32_t);
        max_height = va_arg(args, uint32_t);
        
        err = compute_alignment(text, font, canvas, alignment, x, y, max_width,
          max_height, &aligned_x, &aligned_y);
        if (err != PIPASS_OK)
            goto error;
        break;
    default:
        err = ERR_DISPLAY_NO_SUCH_ATTRIBUTE;
        goto error;
    }

    /* Draw highlight */
    if (highlight == WITH_HIGHLIGHT) {
        err = get_text_size(text, font, canvas, &text_width, &text_height);
        if (err != PIPASS_OK)
            goto error;

        err = _draw_rectangle(
            device,
            MAX(0, aligned_x - 2),
            MAX(0, aligned_y),
            MIN(DISPLAY_WIDTH - 1, aligned_x + text_width + 1),
            MIN(DISPLAY_HEIGHT - 1, aligned_y + text_height + 1),
            "white",
            "white",
            canvas
        );
        if (err != PIPASS_OK)
            goto error; 
    }

    xy = pack_arguments(2, TO_PY_LONG(aligned_x), TO_PY_LONG(aligned_y));

    err = get_attr(canvas, "draw", &draw);
    if (err != PIPASS_OK)
        goto error; 

    Py_INCREF(font);
        
    err = get_and_call_function(draw, "text", &_, 4, xy, TO_PY_STRING(text),
      TO_PY_STRING(fill), font);
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
  int32_t x1, int32_t y1, int32_t x2, int32_t y2, int32_t *aligned_x, int32_t *aligned_y) {
    
    if (text == NULL || font == NULL) {
        return ERR_COMPUTE_ALIGN_INV_PARAMS;
    }

    PIPASS_ERR err;

    if (alignment == ALIGN_LEFT) { 
        *aligned_x = x1;
        *aligned_y = y1;
        return PIPASS_OK;
    }
    
    uint32_t width, height;

    err = get_text_size(text, font, canvas, &width, &height);
    if (err != PIPASS_OK)
        goto error;
    
    if (alignment == ALIGN_RIGHT) {
        *aligned_x = x2 - width;
        *aligned_y = y1;
    } else if (alignment == ALIGN_CENTER) {
        *aligned_x = (x1 + MAX(0, (int32_t)(x2 - x1 - width) / 2));
        *aligned_y = (y1 + MAX(0, (int32_t)(y2 - y1 - height) / 2));
    } else {
        err = ERR_DISPLAY_NO_SUCH_ALIGN;
        goto error;
    }

    err = PIPASS_OK;

error:
    return err;
}

PIPASS_ERR get_text_size(uint8_t *text, PyObject *font, PyObject *canvas, uint32_t *width, uint32_t *height) {
    if (text == NULL || font == NULL || canvas == NULL)
        return ERR_GET_TEXT_SIZE_INV_PARAMS;

    PIPASS_ERR err;
    PyObject *draw = NULL, *width_height = NULL, *_width = NULL, *_height = NULL;

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

    *width  = FROM_PY_LONG(_width);
    *height = FROM_PY_LONG(_height);

    err = PIPASS_OK;

error:
    Py_XDECREF(draw);
    Py_XDECREF(_width);
    Py_XDECREF(_height);

    return err;
}

PIPASS_ERR _clear_screen(PyObject *device) {
    if (device == NULL)
        return ERR_DISPLAY_NOT_INIT;

    PyObject *_ = NULL;
    PIPASS_ERR err;

    err = get_and_call_function(device, "clear", &_, 0);

    Py_XDECREF(_);

    return err;
}