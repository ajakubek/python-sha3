#!/usr/bin/python
# -*- coding: utf-8 -*-

VERSION='0.1'

import platform
from distutils.core import setup, Extension
import sys

defines = []

filtered_argv = []
for arg in sys.argv:
    if arg == '--enable-threads':
        defines.append(('ENABLE_THREADS', '1'))
    else:
        filtered_argv.append(arg)
sys.argv = filtered_argv


sources = [ 'src/sha3_module.c',
            'src/sha3_types.c',
            'src/keccak/KeccakNISTInterface.c',
            'src/keccak/KeccakSponge.c',
            ]
if '64bit' not in platform.architecture()[0]:
    sources += [ 'src/keccak/KeccakF-1600-opt32.c' ]
else:
    sources += [ 'src/keccak/KeccakF-1600-opt64.c' ]

setup(name='',
      description='SHA-3 extension',
      long_description=open('README').read(),
      author='Adam Jakubek',
      author_email='ajakubek@gmail.com',
      version=VERSION,
      url='https://github.com/ajakubek/python-sha3',
      download_url='http://pypi.python.org/pypi/sha3/%s' % VERSION,
      license='MIT',
      keywords='SHA-3, Keccak, hash',
      ext_modules=[Extension('sha3', sources, define_macros=defines)],
      classifiers=[
          'Development Status :: 3 - Alpha',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: MIT License',
          'Operating System :: MacOS :: MacOS X',
          'Operating System :: Microsoft :: Windows',
          'Operating System :: POSIX',
          'Programming Language :: C',
          'Programming Language :: Python :: 2',
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: Implementation :: CPython',
          'Topic :: Software Development :: Libraries :: Python Modules',
          ],
      )
