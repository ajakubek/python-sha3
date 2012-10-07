.PHONY: build clean docs install test

all: clean build test

build:
	python setup.py build

install:
	python setup.py install

clean:
	cd docs && $(MAKE) $(MFLAGS) clean
	python setup.py clean --all

docs:
	cd docs && $(MAKE) $(MFLAGS) clean
	cd docs && $(MAKE) $(MFLAGS) html
	cd docs/_build/html && zip -r docs.zip *

test:
	python setup.py install --install-lib ./tests
	python tests/test.py
