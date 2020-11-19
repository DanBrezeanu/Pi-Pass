#ifndef __DISPLAY_H__
#define __DISPLAY_H__

#include <python_utils.h>
#include <python_api.h>
#include <stdarg.h>

#define DISPLAY_WIDTH  128
#define DISPLAY_HEIGHT 64

PIPASS_ERR init_display();
PIPASS_ERR destroy_device();
PIPASS_ERR display(PyObject *canvas);
PIPASS_ERR draw_text(int32_t x, int32_t y, uint8_t *text, uint8_t *fill, uint8_t font_attr,
  PyObject *canvas, uint32_t attrs, ...);
PIPASS_ERR draw_rectangle(int32_t x1, int32_t y1, int32_t x2, int32_t y2, uint8_t *fill, 
  uint8_t *outline, PyObject *canvas);
PIPASS_ERR draw_image(int32_t x, int32_t y, uint8_t* image_res, PyObject **background);
PIPASS_ERR create_canvas(PyObject *background, PyObject **canvas);
PIPASS_ERR clear_screen();


#endif