#include <display.h>

PIPASS_ERR init_device(PyObject **device) {
    PyObject *device_module = NULL, *serial_module = NULL;
    PyObject *serial = NULL;

    PIPASS_ERR err = DISPLAY_OK;

    err = import_module("luma.oled.device", &device_module);
    if (err != DISPLAY_OK)
        return err;

    err = import_module("luma.core.interface.serial", &serial_module);
    if (err != DISPLAY_OK)
        goto error;

    err = get_and_call_function(serial_module, "spi", &serial, 2, TO_PY_LONG(0), TO_PY_LONG(0));
    if (err != DISPLAY_OK)
        goto error;

    err = get_and_call_function(device_module, "ssd1309", device, 1, serial);
    if (err != DISPLAY_OK)
        goto error;

    err = DISPLAY_OK;

error:
    Py_XDECREF(device_module);
    Py_XDECREF(serial_module);

    return err;
}

PIPASS_ERR display_text(PyObject *device, int32_t x, int32_t y, uint8_t *text) {
    if (device == NULL || text == NULL)
        return ERR_DISPLAY_TEXT_INV_PARAMS;

    PyObject *render_module = NULL, *canv = NULL, *draw = NULL, *_ = NULL;
    PyObject *canv_device = NULL, *canv_image = NULL;

    PIPASS_ERR err = DISPLAY_OK;

    err = import_module("luma.core.render", &render_module);
    if (err != DISPLAY_OK)
        goto error;
        
    err = get_and_call_function(render_module, "canvas", &canv, 1, device);
    if (err != DISPLAY_OK)
        goto error;
    
    err = get_and_call_function(canv, "__enter__", &draw, 0);
    if (err != DISPLAY_OK)
        goto error;

    PyObject *xy = pack_arguments(2, TO_PY_LONG(x), TO_PY_LONG(y));

    err = get_and_call_function(draw, "text", &_, 3, xy, TO_PY_STRING(text), TO_PY_STRING("white"));
    if (err != DISPLAY_OK)
        goto error;

    err = get_attr(canv, "device", &canv_device);
    if (err != DISPLAY_OK)
        goto error;

    err = get_attr(canv, "image", &canv_image);
    if (err != DISPLAY_OK)
        goto error;

    err = get_and_call_function(canv_device, "display", &_, 1, canv_image);
    if (err != DISPLAY_OK)
        goto error;

    err = DISPLAY_OK;

error:
    Py_XDECREF(render_module);
    Py_XDECREF(canv);
    Py_XDECREF(draw);
    Py_XDECREF(xy);
    Py_XDECREF(_);
    Py_XDECREF(canv_device);
    Py_XDECREF(canv_image);

    return err;
}