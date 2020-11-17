#ifndef __PYTHON_API_H__
#define __PYTHON_API_H__

#include <python_utils.h>

PIPASS_ERR import_module(uint8_t *module_name, PyObject **module);
PIPASS_ERR get_function(PyObject *base, uint8_t *func_name, PyObject **func);
PIPASS_ERR get_attr(PyObject *base, uint8_t *attr_name, PyObject **attr);
PIPASS_ERR call_function(PyObject *func, PyObject *args, PyObject **ret);
PIPASS_ERR get_and_call_function(PyObject *base, uint8_t *func_name, PyObject **ret, int num, ...);
PIPASS_ERR get_item_at(PyObject *tuple, int32_t index, PyObject **ret);

#endif