#include <display.h>
#include <draw_basic.h>

static PyObject *device;

PIPASS_ERR init_display() {
    PyObject *device_module = NULL, *serial_module = NULL;
    PyObject *serial = NULL;

    if (device != NULL)
        return ERR_DISPLAY_ALREADY_INIT;

    PIPASS_ERR err = PIPASS_OK;

    err = import_module("luma.oled.device", &device_module);
    if (err != PIPASS_OK)
        return err;

    err = import_module("luma.core.interface.serial", &serial_module);
    if (err != PIPASS_OK)
        goto error;

    err = get_and_call_function(serial_module, "spi", &serial, 2, TO_PY_LONG(0), TO_PY_LONG(0));
    if (err != PIPASS_OK)
        goto error;

    err = get_and_call_function(device_module, "ssd1309", &device, 1, serial);
    if (err != PIPASS_OK)
        goto error;

    err = init_draw();
    if (err != PIPASS_OK)
        goto error;

    err = PIPASS_OK;

error:
    Py_XDECREF(device_module);
    Py_XDECREF(serial_module);
    /* TODO: find if `serial` is still needed */

    return err;
}


PIPASS_ERR destroy_device() {
    Py_XDECREF(device);
}

/* Wrapper function */
PIPASS_ERR display(PyObject *canvas) {
    return _display(device, canvas);
}

/* Wrapper function */
PIPASS_ERR draw_text(int32_t x, int32_t y, uint8_t *text, uint8_t *fill, uint8_t font_attr,
  PyObject *canvas, uint32_t attrs, ...) {
      va_list args;
      va_start(args, attrs);
      PIPASS_ERR err = _draw_text(device, x, y, text, fill, font_attr, canvas, attrs, args);
      va_end(args);

      return err;
}

/* Wrapper function */
PIPASS_ERR draw_rectangle(int32_t x1, int32_t y1, int32_t x2, int32_t y2, uint8_t *fill, 
  uint8_t *outline, PyObject *canvas) {
    return _draw_rectangle(device, x1, y1, x2, y2, fill, outline, canvas);     
}

/* Wrapper function */
PIPASS_ERR draw_image(int32_t x, int32_t y, uint8_t* image_res, PyObject **background) {
    return _draw_image(device, x, y, image_res, background);
}

/* Wrapper function */
PIPASS_ERR create_canvas(PyObject *background, PyObject **canvas) {
    return _create_canvas(device, background, canvas);
}






