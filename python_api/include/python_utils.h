#ifndef __PYTHON_UTILS_H__
#define __PYTHON_UTILS_H__

#include <Python.h>
#include <unistd.h>
#include <errors.h>
#include <defines.h>
#include <stdarg.h>

#define TO_PY_STRING(x) (PyUnicode_DecodeFSDefault((x)))
#define TO_PY_LONG(x) (PyLong_FromLong((x)))

PyObject *pack_arguments(int num, ...);
PyObject *pack_arguments_list(int num, va_list args);

#endif