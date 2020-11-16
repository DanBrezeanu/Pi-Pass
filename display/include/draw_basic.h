#ifndef __DRAW_BASIC_H__
#define __DRAW_BASIC_H__

#include <python_utils.h>
#include <python_api.h>

PIPASS_ERR init_draw();
PIPASS_ERR _display(PyObject *device, PyObject *canvas);
PIPASS_ERR _draw_image(PyObject *device, int32_t x, int32_t y, uint8_t* image_res, PyObject **background);
PIPASS_ERR _draw_text(PyObject *device, int32_t x, int32_t y, uint8_t *text, PyObject *canvas);
PIPASS_ERR _create_canvas(PyObject *device, PyObject *background, PyObject **canvas);
PIPASS_ERR new_image(PyObject *device, uint32_t width, uint32_t height, PyObject **image);

#endif