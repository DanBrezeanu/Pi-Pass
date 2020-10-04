#include <python_utils.h>

PyObject *pack_arguments(int num, ...) {
    va_list args;

    va_start(args, num);
    PyObject *py_args = pack_arguments_list(num, args);
    va_end(args);
    return py_args;
}

PyObject *pack_arguments_list(int num, va_list args) {

    PyObject *py_args = PyTuple_New(num);

    for (int i = 0; i < num; ++i) {
        PyTuple_SetItem(py_args, i, va_arg(args, PyObject *));
    }

    return py_args;
}