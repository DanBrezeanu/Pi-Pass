#ifndef __DISPLAY_H__
#define __DISPLAY_H__

#include <python_utils.h>
#include <python_api.h>

#define DISPLAY_WIDTH  128
#define DISPLAY_HEIGHT 64

PIPASS_ERR init_display();
PIPASS_ERR destroy_device();
PIPASS_ERR display(PyObject *canvas);
PIPASS_ERR draw_text(int32_t x, int32_t y, uint8_t *text, PyObject *canvas);
PIPASS_ERR draw_image(int32_t x, int32_t y, uint8_t* image_res, PyObject **background);
PIPASS_ERR create_canvas(PyObject *background, PyObject **canvas);


#endif