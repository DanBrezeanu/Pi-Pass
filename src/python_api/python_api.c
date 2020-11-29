#include <python_utils.h>
#include <python_api.h>

PIPASS_ERR import_module(uint8_t *module_name, PyObject **module) {
    if (module_name == NULL)
        return ERR_DISPLAY_IMPORT_INV_PARAMS;

    if (*module != NULL)
        return ERR_DISPLAY_MEM_LEAK;
    
    PIPASS_ERR err = DISPLAY_OK;

    PyObject *py_module_name = PyUnicode_DecodeFSDefault(module_name);
    if (py_module_name == NULL) {
        err = ERR_DISPLAY_IMPORT;
        goto error;
    }
    
    *module = PyImport_Import(py_module_name);
    if (*module == NULL) {
        err = ERR_DISPLAY_IMPORT;
        goto error;
    }

    err = DISPLAY_OK;

error:
    Py_XDECREF(py_module_name);

    return err;
}


PIPASS_ERR get_function(PyObject *base, uint8_t *func_name, PyObject **func) {
    if (base == NULL || func_name == NULL)
        return ERR_DISPLAY_GETF_INV_PARAMS;

    if (*func != NULL)
        return ERR_DISPLAY_MEM_LEAK;

    *func = PyObject_GetAttrString(base, func_name);
    if (*func == NULL)
        return ERR_DISPLAY_GET_FUNC;

    PIPASS_ERR err = DISPLAY_OK;

    if (!PyCallable_Check(*func)) {
        err = ERR_DISPLAY_NOT_A_FUNC;
        goto error;
    }

    return DISPLAY_OK;

error:
    Py_XDECREF(*func);

    return err;
}

PIPASS_ERR get_and_call_function(PyObject *base, uint8_t *func_name, PyObject **ret, int num, ...) {
    PyObject *func = NULL;
    PyObject *py_args = NULL;
    PIPASS_ERR err = DISPLAY_OK;

    err = get_function(base, func_name, &func);
    if (err != DISPLAY_OK)
        return err;

    va_list args;
    va_start(args, num);
    py_args = pack_arguments_list(num, args);
    va_end(args);

    err = call_function(func, py_args, ret);
    if (err != DISPLAY_OK)
        goto error;
    
    err = DISPLAY_OK;

error:
    Py_XDECREF(func);
    Py_XDECREF(py_args);

    return err;
}

PIPASS_ERR get_attr(PyObject *base, uint8_t *attr_name, PyObject **attr) {
    if (base == NULL || attr_name == NULL)
        return ERR_DISPLAY_GETATTR_INV_PARAMS;

    if (*attr != NULL)
        return ERR_DISPLAY_MEM_LEAK;

    *attr = PyObject_GetAttrString(base, attr_name);
    if (*attr == NULL)
        return ERR_DISPLAY_GET_ATTR;

    return DISPLAY_OK;
}

PIPASS_ERR call_function(PyObject *func, PyObject *args, PyObject **ret) {
    if (func == NULL)
        return ERR_DISPLAY_CALLF_INV_PARAMS;

    if (!PyCallable_Check(func))
        return ERR_DISPLAY_NOT_A_FUNC;

    *ret = PyObject_CallObject(func, args);

    if (*ret == NULL)
        return ERR_DISPLAY_CALL_FUNCTION;

    return DISPLAY_OK;
}

PIPASS_ERR get_item_at(PyObject *tuple, int32_t index, PyObject **ret) {
    if (tuple == NULL)
        return ERR_PYTHON_GET_ITEM_INV_PARAMS;

    if (!PyTuple_Check(tuple))
        return ERR_PYTHON_NOT_A_TUPLE;

    *ret = PyTuple_GetItem(tuple, (Py_ssize_t) index);

    if (*ret == NULL)
        return ERR_PYTHON_INDEX_ERROR;

    return PIPASS_OK;
}
