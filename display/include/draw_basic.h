#ifndef __DRAW_BASIC_H__
#define __DRAW_BASIC_H__

#include <python_utils.h>
#include <python_api.h>
#include <stdarg.h>
#include <display.h>

#define NO_ATTRIBUTES 0x00
#define ALIGN_TEXT    0x03

#define ALIGN_CENTER  0xC0
#define ALIGN_LEFT    0xC1
#define ALIGN_RIGHT   0xC3

#define DEFAULT_FONT   0xF0
#define FREEPIXEL_FONT 0xF1


PIPASS_ERR init_draw();
PIPASS_ERR _display(PyObject *device, PyObject *canvas);
PIPASS_ERR _draw_image(PyObject *device, int32_t x, int32_t y, uint8_t* image_res, PyObject **background);
PIPASS_ERR _draw_text(PyObject *device, int32_t x, int32_t y, uint8_t *text, uint8_t *fill, uint8_t font_attr,
  PyObject *canvas, uint32_t attrs, va_list args);
PIPASS_ERR _draw_rectangle(PyObject *device, int32_t x1, int32_t y1, int32_t x2, int32_t y2, uint8_t *fill, 
  uint8_t *outline, PyObject *canvas);
PIPASS_ERR _create_canvas(PyObject *device, PyObject *background, PyObject **canvas);
PIPASS_ERR new_image(PyObject *device, uint32_t width, uint32_t height, PyObject **image);
PIPASS_ERR compute_alignment(uint8_t *text, PyObject *font, PyObject *canvas, uint32_t alignment,
  uint32_t x1, uint32_t y1, uint32_t x2, uint32_t y2, PyObject **xy);
PIPASS_ERR _clear_screen(PyObject *device);

#endif