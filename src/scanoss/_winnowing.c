/*
 SPDX-License-Identifier: MIT

   Copyright (c) 2021, SCANOSS

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
   THE SOFTWARE.

   Winnowing Algorithm implementation for SCANOSS.

   This module implements an adaptation of the original winnowing algorithm by
 S. Schleimer, D. S. Wilkerson and A. Aiken as described in their seminal
 article which can be found here:
   https://theory.stanford.edu/~aiken/publications/papers/sigmod03.pdf
*/

#define PY_SSIZE_T_CLEAN
#include <Python.h>

/* Winnowing configuration. DO NOT CHANGE. */
#define GRAM 30
#define WINDOW 64

char norm_table[256];
/* normalize is also part of the winnowing configuration */
char normalize(char byte)
{
    if (byte < '0' || byte > 'z')
        return 0;
    if (byte <= '9')
        return byte;
    if (byte >= 'a')
        return byte;
    if ((byte >= 'A') && (byte <= 'Z'))
        return byte + 'a' - 'A'; /* just a lowercase */
    return 0;
}

uint32_t
array_min(uint32_t* array, int sz)
{
    int i;
    uint32_t res = UINT_MAX;
    for (i = 0; i < sz; i++) {
        if (array[i] < res) {
            res = array[i];
        }
    }
    return res;
}
uint32_t
call_crc32(char* data, int size, PyObject* crc32c)
{
    PyObject* bytes = PyBytes_FromStringAndSize(data, size);
    PyObject* arglist = Py_BuildValue("(O)", bytes);
    PyObject* result = PyObject_CallObject(crc32c, arglist);
    Py_DECREF(arglist);
    uint32_t ret = PyLong_AsUnsignedLong(result);
    Py_DECREF(result);
    return ret;
}

/* a fast version which uses a pre-built tuple, with a memory view */
uint32_t
call_crc32_f(PyObject* arglist, PyObject* crc32c)
{
    PyObject* result = PyObject_CallObject(crc32c, arglist);
    uint32_t ret = PyLong_AsUnsignedLong(result);
    Py_DECREF(result);
    return ret;
}

static PyObject*
winnowing_compute_wfd(PyObject* self, PyObject* args)
{
    Py_buffer in;
    const char* content;
    PyObject* crc32c;
    char gram[GRAM + 1];
    PyObject* gram_bytes = PyMemoryView_FromMemory(gram, GRAM, PyBUF_READ);
    PyObject* arglist = Py_BuildValue("(O)", gram_bytes);
    int gram_idx = 0;
    uint32_t window[WINDOW];
    int window_idx = 0;
    int content_idx;
    int line = 1, last_line = 0;
    uint32_t last_hash = UINT_MAX;
    PyObject* result = PyList_New(0);
    PyObject* out_buf;

    if (!PyArg_ParseTuple(args, "y*O", &in, &crc32c))
        return NULL;

    if (!PyCallable_Check(crc32c)) {
        PyErr_SetString(PyExc_TypeError, "parameter crc32c must be callable");
        return NULL;
    }
    content = in.buf;
    for (content_idx = 0; content_idx < in.len; content_idx++) {
        unsigned char byte = content[content_idx];
        if (byte == '\n') {
            line++;
            continue;
        }
        byte = norm_table[(int)byte];
        if (byte == 0) {
            continue;
        }
        gram[gram_idx] = byte;
        /* we have full window */
        if (gram_idx == GRAM - 1) {
            gram[GRAM] = 0;
            window[window_idx] = call_crc32_f(arglist, crc32c);
            if (window_idx == WINDOW - 1) {
                uint32_t min_hash = array_min(window, WINDOW);
                if (min_hash != last_hash) {
                    //Hashing the hash will result in a better balanced resulting data set
                    //as it will counter the winnowing effect which selects the "minimum"
                    //hash in each window
                    uint32_t crc = call_crc32((char*)&min_hash, 4, crc32c);
                    char crc_s[9];
                    /* python format will not correctly manage the leading 0, so we preformat
                       with snprintf
                    */
                    snprintf(crc_s, 9, "%08x", crc);
                    if (last_line != line) {
                        if (line == 1)
                            out_buf = PyBytes_FromFormat("%d=%s", line, crc_s);
                        else
                            out_buf = PyBytes_FromFormat("\n%d=%s", line, crc_s);
                    } else
                        out_buf = PyBytes_FromFormat(",%s", crc_s);
                    PyList_Append(result, out_buf);
                    last_line = line;
                    last_hash = min_hash;
                }
                memmove(window, window + 1, 4 * (WINDOW - 1));
            } else
                window_idx++;
            memmove(gram, gram + 1, GRAM - 1);

        } else
            gram_idx++;
    }
    return result;
}

static PyMethodDef winnowingMethods[] = {
    { "compute_wfd",
        winnowing_compute_wfd,
        METH_VARARGS,
        "Compute winnowing finger print for scanoss." },
    { NULL, NULL, 0, NULL } /* Sentinel */
};

static struct PyModuleDef winnowingmodule = {
    PyModuleDef_HEAD_INIT,
    "_winnowing", /* name of module */
    NULL, /* module documentation, may be NULL */
    -1, /* size of per-interpreter state of the module,
                   or -1 if the module keeps state in global variables. */
    winnowingMethods
};

PyObject*
PyInit__winnowing(void)
{
    int i;
    for (i = 0; i < 256; i++) {
        norm_table[i] = normalize(i);
    }
    return PyModule_Create(&winnowingmodule);
}
