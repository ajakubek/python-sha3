.. python-sha3 documentation master file, created by
   sphinx-quickstart on Sat Oct  6 23:11:33 2012.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

:mod:`python-sha3` --- SHA-3 extension module for Python
========================================================

.. module:: sha3

.. moduleauthor:: Adam Jakubek <ajakubek@gmail.com>

This extension for CPython provides SHA-3 cryptographic function (also known
as Keccak). For more information on the Keccak function, please visit
http://keccak.noekeon.org/

The interface of this module follows conventions from Python's builtin
:mod:`hashlib` module.

It can be used with the following versions of Python:
 - Python 2 - version 2.4 and later are supported
 - Python 3 - tested with versions up to 3.2

Internally :mod:`python-sha3` uses optimized version of the Keccak algorithm,
written and released into the public domain by its designers. 
Both 32-bit and 64-bit architectures are supported (tested on x86 and x86_64
architectures).


Building
========

To build the module, type the following command:

  *python setup.py build*

You may specify additional command line arguments to the build command.
The following options are currently supported:

.. option:: --enable-threads

    Causes :mod:`python-sha3` to release GIL when performing hash computations.
    This option can improve performance of multithreaded code which performs a lot
    of hashing. Note that :mod:`python-sha3` will still acquire a per-object lock,
    so the module is fully thread-safe.

To install the module, issue the following command:

  *python setup.py install*


Classes
=======

Four classes with different digest sizes are currently available:
 - :class:`sha3.sha224` - SHA-3 224 bit digest
 - :class:`sha3.sha256` - SHA-3 256 bit digest
 - :class:`sha3.sha384` - SHA-3 384 bit digest
 - :class:`sha3.sha512` - SHA-3 512 bit digest

The interface of these classes follows conventions from Python's builtin
hashlib module.

:mod:`sha3` hashes
------------------

.. class:: sha224()

  Return a new SHA-3 with 224 bit digest size.

  Sponge function parameters:
    - rate: 1152 bits
    - capacity: 448 bits

.. class:: sha256()

  Return a new SHA-3 with 256 bit digest size.

  Sponge function parameters:
    - rate: 1088 bits
    - capacity: 512 bits

.. class:: sha384()

  Return a new SHA-3 with 384 bit digest size.

  Sponge function parameters:
    - rate: 832 bits
    - capacity: 768 bits

.. class:: sha512()

  Return a new SHA-3 with 512 bit digest size.

  Sponge function parameters:
    - rate: 576 bits
    - capacity: 1024 bits

All of above classes provide the same interface.

Hash object methods:
^^^^^^^^^^^^^^^^^^^^

.. method:: sha.update(self, x)

    Update the hash object with message *x*, which can be a string or a buffer
    (`unicode` or `bytes` in Python 3.x).

    Calling :meth:`update()` multiple times is equivalent to a single call with
    a concatenated value of all arguments: ::

        >>> h1 = sha3.sha512()
        >>> h1.update(a)
        >>> h1.update(b)

        >>> h2 = sha3.sha512()
        >>> h2.update(a+b)

        >>> h1.digest() == h2.digest()
        True

.. method:: sha.digest(self)

    Return a string (`bytes` in Python 3.x) with binary digest value.

    Note that this method does not alter state of *self* (:meth:`update()` can
    be called afterwards to extend the hash input message).

.. method:: sha.hexdigest(self)

    Return a string (`unicode` in Python 3.x) with hexadecimal digest value.

    Note that this method does not alter state of *self* (:meth:`update()` can
    be called afterwards to extend the hash input message).

.. method:: sha.copy(self)

    Return a copy of *self*. This method can be called to calculate hashes of
    messages which share the same prefix.

Hash object attributes:
^^^^^^^^^^^^^^^^^^^^^^^

.. attribute:: sha.digest_size

    Read-only size of message digest in bytes.

.. attribute:: sha.block_size

    Read-only size of internal block size in bytes.
    This is equivalent to ``sha.rate / 8``.

.. attribute:: sha.rate

    Read-only rate of sponge function in bits.

.. attribute:: sha.capacity

    Read-only capacity of sponge function in bits.


Copyright
=========

The :mod:`python-sha3` module is distributed under the MIT license:

  | Copyright (c) 2012 Adam Jakubek
  |
  | Permission is hereby granted, free of charge, to any person obtaining
  | a copy of this software and associated documentation files (the
  | "Software"), to deal in the Software without restriction, including
  | without limitation the rights to use, copy, modify, merge, publish,
  | distribute, sublicense, and/or sell copies of the Software, and to
  | permit persons to whom the Software is furnished to do so, subject to
  | the following conditions:
  |
  | The above copyright notice and this permission notice shall be
  | included in all copies or substantial portions of the Software.
  |
  | THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  | EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  | MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
  | NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
  | LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
  | OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
  | WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

------------------------------------------------------------------------------

This project uses code from the Keccak library released into the public
domain with the following license notice:

  | The Keccak sponge function, designed by Guido Bertoni, Joan Daemen,
  | Michaël Peeters and Gilles Van Assche. For more information, feedback or
  | questions, please refer to our website: http://keccak.noekeon.org/
  |
  | Implementation by the designers,
  | hereby denoted as "the implementer".
  |
  | To the extent possible under law, the implementer has waived all copyright
  | and related or neighboring rights to the source code in this file.
  | http://creativecommons.org/publicdomain/zero/1.0/

------------------------------------------------------------------------------

This project uses additional code distributed with the following license notice:

  | Copyright (c) 1998-2008, Brian Gladman, Worcester, UK. All rights reserved.
  |
  | LICENSE TERMS
  |
  | The redistribution and use of this software (with or without changes)
  | is allowed without the payment of fees or royalties provided that:
  |
  |  1. source code distributions include the above copyright notice, this
  |     list of conditions and the following disclaimer;
  |
  |  2. binary distributions include the above copyright notice, this list
  |     of conditions and the following disclaimer in their documentation;
  |
  |  3. the name of the copyright holder is not used to endorse products
  |     built using this software without specific written permission.
  |
  | DISCLAIMER
  |
  | This software is provided 'as is' with no explicit or implied warranties
  | in respect of its properties, including, but not limited to, correctness
  | and/or fitness for purpose.


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

