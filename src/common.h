/* Copyright (c) 2015 Adam Jakubek
 * Released under the MIT license (see attached LICENSE file).
 */

#ifndef COMMON_H
#define COMMON_H

#define PY_SSIZE_T_CLEAN

#include <Python.h>

#if PY_VERSION_HEX < 0x02050000
typedef int Py_ssize_t;
#endif

#endif /* COMMON_H */
