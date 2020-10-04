#ifndef __DISPLAY_H__
#define __DISPLAY_H__

#include <python_utils.h>
#include <python_api.h>

DISPLAY_ERROR init_device(PyObject **device);
DISPLAY_ERROR display_text(PyObject *device, int32_t x, int32_t y, uint8_t *text);

#endif