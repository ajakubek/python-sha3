/* Copyright (c) 2012 Adam Jakubek
 * Released under the MIT license (see attached LICENSE file).
 */

#include <Python.h>            

#include "sha3_types.h"        

static PyMethodDef sha3_methods[] =
{ 
    { NULL }    /* sentinel */
};

#ifndef PyMODINIT_FUNC  /* declarations for DLL import/export */
#define PyMODINIT_FUNC void
#endif

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef sha3_moduledef = {
    PyModuleDef_HEAD_INIT,
    "sha3",                     /* m_name */                    
    "SHA-3 hashing functions.", /* m_doc */
    -1,                         /* m_size */                    
    sha3_methods,               /* m_methods */
    NULL,                       /* m_reload */                  
    NULL,                       /* m_traverse */                
    NULL,                       /* m_clear */                   
    NULL,                       /* m_free */                    
};
#endif

PyMODINIT_FUNC
#if PY_MAJOR_VERSION >=3       
PyInit_sha3(void)              
#else
initsha3(void) 
#endif
{
    PyObject* m;               

    if (!sha3_init_types())    
        return;

#if PY_MAJOR_VERSION >= 3
    m = PyModule_Create(&sha3_moduledef);
#else
    m = Py_InitModule3("sha3", sha3_methods,
                       "SHA-3 hashing functions.");    
#endif

    sha3_register_types(m);

#if PY_MAJOR_VERSION >= 3
    return m;
#endif
}
