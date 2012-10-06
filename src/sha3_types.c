/* Copyright (c) 2012 Adam Jakubek
 * Released under the MIT license (see attached LICENSE file).
 */

#include <Python.h>
#ifdef ENABLE_THREADS
#include "pythread.h"
#endif
#include <structmember.h>
#include "keccak/KeccakNISTInterface.h"

#define MAX_HASH_SIZE           (512)
#define MIN_CONCURRENT_SIZE     (4096)

#ifndef Py_TYPE
#define Py_TYPE(o) ((o)->ob_type)
#endif

#if PY_VERSION_HEX < 0x02050000
typedef int Py_ssize_t;
#endif


static PyTypeObject SHA224Type;
static PyTypeObject SHA256Type;
static PyTypeObject SHA384Type;
static PyTypeObject SHA512Type;

typedef struct
{
    PyObject_HEAD
    hashState hash_state;
    Py_ssize_t digest_size;
    Py_ssize_t block_size;
#ifdef ENABLE_THREADS
    PyThread_type_lock lock;
#endif
} SHAObject;


static void sha_dealloc(SHAObject* self)
{
#ifdef ENABLE_THREADS
    if (self->lock != NULL)
        PyThread_free_lock(self->lock);
#endif
    Py_TYPE(self)->tp_free(self);
}

static PyObject* sha224_new(PyTypeObject* type,
                            PyObject* args,
                            PyObject* kwds)
{
    SHAObject* self;

    self = (SHAObject*)type->tp_alloc(type, 0);
    if (self == NULL)
        return NULL;

    self->digest_size = 224;
    self->block_size = 1152;
#ifdef ENABLE_THREADS
    self->lock = NULL;
#endif

    if (Init(&self->hash_state, 224) != SUCCESS)
        return NULL;

    return (PyObject*)self;
}

static PyObject* sha256_new(PyTypeObject* type,
                            PyObject* args,
                            PyObject* kwds)
{
    SHAObject* self;

    self = (SHAObject*)type->tp_alloc(type, 0);
    if (self == NULL)
        return NULL;

    self->digest_size = 256;
    self->block_size = 1088;
#ifdef ENABLE_THREADS
    self->lock = NULL;
#endif

    if (Init(&self->hash_state, 256) != SUCCESS)
        return NULL;

    return (PyObject*)self;
}

static PyObject* sha384_new(PyTypeObject* type,
                            PyObject* args,
                            PyObject* kwds)
{
    SHAObject* self;

    self = (SHAObject*)type->tp_alloc(type, 0);
    if (self == NULL)
        return NULL;

    self->digest_size = 384;
    self->block_size = 832;
#ifdef ENABLE_THREADS
    self->lock = NULL;
#endif

    if (Init(&self->hash_state, 384) != SUCCESS)
        return NULL;

    return (PyObject*)self;
}

static PyObject* sha512_new(PyTypeObject* type,
                            PyObject* args,
                            PyObject* kwds)
{
    SHAObject* self;

    self = (SHAObject*)type->tp_alloc(type, 0);
    if (self == NULL)
        return NULL;

    self->digest_size = 512;
    self->block_size = 576;
#ifdef ENABLE_THREADS
    self->lock = NULL;
#endif

    if (Init(&self->hash_state, 512) != SUCCESS)
        return NULL;

    return (PyObject*)self;
}

static int sha_init(SHAObject* self, PyObject* args, PyObject* kwds)
{
    if (Init(&self->hash_state, (int)self->digest_size) != SUCCESS)
    {
        PyErr_SetString(PyExc_RuntimeError, "failed to initialize hash state");
        return -1;
    }

    return 0;
}

static PyObject* sha_update(SHAObject* self, PyObject* other)
{
    unsigned char* buffer;
    Py_ssize_t size;
    HashReturn result;

    if (!PyArg_ParseTuple(other, "s#:update", &buffer, &size))
        return NULL;

#if ENABLE_THREADS
    if (self->lock == NULL && size >= MIN_CONCURRENT_SIZE)
        self->lock = PyThread_allocate_lock();

    if (self->lock != NULL && size >= MIN_CONCURRENT_SIZE)
    {
        Py_BEGIN_ALLOW_THREADS
        PyThread_acquire_lock(self->lock, 1);

        result = Update(&self->hash_state, buffer, (DataLength)size * 8);

        PyThread_release_lock(self->lock);
        Py_END_ALLOW_THREADS
    }
    else
        result = Update(&self->hash_state, buffer, (DataLength)size * 8);
#else
    result = Update(&self->hash_state, buffer, (DataLength)size * 8);
#endif

    if (result != SUCCESS)
    {
        PyErr_SetString(PyExc_RuntimeError, "failed to update hash state");
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyObject* sha_digest(SHAObject* self)
{
    char digest[MAX_HASH_SIZE / 8];
    hashState tmp;
    HashReturn result;

    assert(self->digest_size <= MAX_HASH_SIZE);

#if ENABLE_THREADS
    /* Use lock if it's already created, but don't create a new one.
     * This is usually the last method called.
     */
    if (self->lock != NULL)
    {
        Py_BEGIN_ALLOW_THREADS
        PyThread_acquire_lock(self->lock, 1);

        memcpy(&tmp, &self->hash_state, sizeof(hashState));
        result = Final(&tmp, (BitSequence*)digest);

        PyThread_release_lock(self->lock);
        Py_END_ALLOW_THREADS
    }
    else
    {
        memcpy(&tmp, &self->hash_state, sizeof(hashState));
        result = Final(&tmp, (BitSequence*)digest);
    }
#else
    memcpy(&tmp, &self->hash_state, sizeof(hashState));
    result = Final(&tmp, (BitSequence*)digest);
#endif

    if (result!= SUCCESS)
    {
        PyErr_SetString(PyExc_RuntimeError,
            "failed to finalize hash calculation");
        return NULL;
    }

#if PY_MAJOR_VERSION >=3
    return PyBytes_FromStringAndSize(digest, (int)self->digest_size / 8);
#else
    return PyString_FromStringAndSize(digest, (int)self->digest_size / 8);
#endif
}

static PyObject* sha_hexdigest(SHAObject* self)
{
    static const char* DIGITS = "0123456789abcdef";

    unsigned char digest[MAX_HASH_SIZE / 8];
    char hex_digest[MAX_HASH_SIZE / 8 * 2];
    char *p;
    int digest_size, i;
    hashState tmp;
    HashReturn result;

    assert(self->digest_size <= MAX_HASH_SIZE);

#if ENABLE_THREADS
    /* Use lock if it's already created, but don't create a new one.
     * This is usually the last method called.
     */
    if (self->lock != NULL)
    {
        Py_BEGIN_ALLOW_THREADS
        PyThread_acquire_lock(self->lock, 1);

        memcpy(&tmp, &self->hash_state, sizeof(hashState));
        result = Final(&tmp, (BitSequence*)digest);

        PyThread_release_lock(self->lock);
        Py_END_ALLOW_THREADS
    }
    else
    {
        memcpy(&tmp, &self->hash_state, sizeof(hashState));
        result = Final(&tmp, (BitSequence*)digest);
    }
#else
    memcpy(&tmp, &self->hash_state, sizeof(hashState));
    result = Final(&tmp, (BitSequence*)digest);
#endif

    if (result != SUCCESS)
    {
        PyErr_SetString(PyExc_RuntimeError,
            "failed to finalize hash calculation");
        return NULL;
    }
 
    digest_size = (int)self->digest_size / 8;

    p = hex_digest;
    for (i = 0; i < digest_size; ++i)
    {
        *p++ = DIGITS[(digest[i] / 16) & 0xf];
        *p++ = DIGITS[(digest[i] % 16) & 0xf];
    }

#if PY_MAJOR_VERSION >=3
    return PyUnicode_FromStringAndSize(hex_digest, digest_size * 2);
#else
    return PyString_FromStringAndSize(hex_digest, digest_size * 2);
#endif
}

static PyObject* sha_copy(PyObject* self)
{
    SHAObject* sha_self = (SHAObject*)self;
    SHAObject* new_sha;

    if (Py_TYPE(self) == &SHA224Type)
        new_sha = (SHAObject*)PyObject_New(SHAObject, &SHA224Type);
    else if (Py_TYPE(self) == &SHA256Type)
        new_sha = (SHAObject*)PyObject_New(SHAObject, &SHA256Type);
    else if (Py_TYPE(self) == &SHA384Type)
        new_sha = (SHAObject*)PyObject_New(SHAObject, &SHA384Type);
    else if (Py_TYPE(self) == &SHA512Type)
        new_sha = (SHAObject*)PyObject_New(SHAObject, &SHA512Type);

    if (new_sha == NULL)
        return NULL;

    memcpy(&new_sha->hash_state, &sha_self->hash_state, sizeof(hashState));
    new_sha->digest_size = sha_self->digest_size;
    new_sha->block_size = sha_self->digest_size;

    return (PyObject*)new_sha;
}

static PyObject* sha_repr(PyObject* self)
{
    PyObject* str;

#if PY_MAJOR_VERSION >=3
    str = PyUnicode_FromFormat("<%s HASH object @ %p>",
        self->ob_type->tp_name, self);
#else
    str = PyString_FromFormat("<%s HASH object @ %p>",
        self->ob_type->tp_name, self);
#endif
    if (str == NULL)
    {
        PyErr_SetString(PyExc_RuntimeError, "failed to format string");
        return NULL;
    }

    return str;
}

static PyMethodDef SHAMethods[] =
{
    { "update", (PyCFunction)sha_update, METH_VARARGS,
      "Update the hash object with the string in argument." },
    { "digest", (PyCFunction)sha_digest, METH_NOARGS,
      "Return the digest of the strings passed to the update() method." },
    { "hexdigest", (PyCFunction)sha_hexdigest, METH_NOARGS,
      "Return the hexadecimal digest of the strings passed to the update() method." },
    { "copy", (PyCFunction)sha_copy, METH_NOARGS,
      "Return a copy of the hash object." },
    { NULL },   /* sentinel */
};

static PyMemberDef SHAMembers[] =
{
    { "digest_size", T_INT, offsetof(SHAObject, digest_size), READONLY,
      "The size of the resulting hash in bytes." },
    { "block_size", T_INT, offsetof(SHAObject, block_size), READONLY,
      "The internal block size of the hash algorithm in bytes." },
    { NULL },   /* sentinel */
};

#ifndef PyVarObject_HEAD_INIT
    #define PyVarObject_HEAD_INIT(type, size) \
        PyObject_HEAD_INIT(type) size,
#endif

#define DefineSHAType(bits)                                     \
    static PyTypeObject SHA##bits##Type =                       \
    {                                                           \
        PyVarObject_HEAD_INIT(NULL, 0)                          \
        "sha3.sha"#bits,                /* tp_name */           \
        sizeof(SHAObject),              /* tp_basicsize */      \
        0,                              /* tp_itemsize */       \
        (destructor)sha_dealloc,        /* tp_dealloc */        \
        0,                              /* tp_print */          \
        0,                              /* tp_getattr */        \
        0,                              /* tp_setattr */        \
        0,                              /* tp_compare */        \
        sha_repr,                       /* tp_repr */           \
        0,                              /* tp_as_number */      \
        0,                              /* tp_as_sequence */    \
        0,                              /* tp_as_mapping */     \
        0,                              /* tp_hash */           \
        0,                              /* tp_call */           \
        sha_repr,                       /* tp_str */            \
        0,                              /* tp_getattro */       \
        0,                              /* tp_setattro */       \
        0,                              /* tp_as_buffer */      \
        Py_TPFLAGS_DEFAULT,             /* tp_flags */          \
        "SHA-3 "#bits" bit version",    /* tp_doc */            \
        0,                              /* tp_traverse */       \
        0,                              /* tp_clear */          \
        0,                              /* tp_richcompare */    \
        0,                              /* tp_weaklistoffset */ \
        0,                              /* tp_iter */           \
        0,                              /* tp_iternext */       \
        SHAMethods,                     /* tp_methods */        \
        SHAMembers,                     /* tp_members */        \
        0,                              /* tp_getset */         \
        0,                              /* tp_base */           \
        0,                              /* tp_dict */           \
        0,                              /* tp_descr_get */      \
        0,                              /* tp_descr_set */      \
        0,                              /* tp_dictoffset */     \
        (initproc)sha_init,             /* tp_init */           \
        0,                              /* tp_alloc */          \
        sha##bits##_new,                /* tp_new */            \
    };

DefineSHAType(224)
DefineSHAType(256)
DefineSHAType(384)
DefineSHAType(512)

#undef DefineSHAtype


int sha3_init_types(void)
{
    return
        ((PyType_Ready(&SHA224Type) == 0) &&
         (PyType_Ready(&SHA256Type) == 0) &&
         (PyType_Ready(&SHA384Type) == 0) &&
         (PyType_Ready(&SHA512Type) == 0))
        ? 1 : 0;
}

void sha3_register_types(PyObject* module)
{
    Py_INCREF(&SHA224Type);
    Py_INCREF(&SHA256Type);
    Py_INCREF(&SHA384Type);
    Py_INCREF(&SHA512Type);

    PyModule_AddObject(module, "sha224", (PyObject*)&SHA224Type);
    PyModule_AddObject(module, "sha256", (PyObject*)&SHA256Type);
    PyModule_AddObject(module, "sha384", (PyObject*)&SHA384Type);
    PyModule_AddObject(module, "sha512", (PyObject*)&SHA512Type);
}
