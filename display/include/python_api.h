#ifndef __PYTHON_API_H__
#define __PYTHON_API_H__

#include <python_utils.h>

DISPLAY_ERROR import_module(uint8_t *module_name, PyObject **module);
DISPLAY_ERROR get_function(PyObject *base, uint8_t *func_name, PyObject **func);
DISPLAY_ERROR get_attr(PyObject *base, uint8_t *attr_name, PyObject **attr);
DISPLAY_ERROR call_function(PyObject *func, PyObject *args, PyObject **ret);
DISPLAY_ERROR get_and_call_function(PyObject *base, uint8_t *func_name, PyObject **ret, int num, ...);

#endif