# This is the master makefile, run make to build all projects
SHELL = /bin/bash
CFLAGS = -I ./ -O0 -g -Wall
VERSION = 0.0.1
export

ifeq ($(shell uname -s),Darwin)
	EXT = dylib
else
	EXT = so
endif

# Targets
.PHONY: all tests install clean randomstr webng servrian maze

all: randomstr webng maze servrian

randomstr:
	$(MAKE) -C src/randomstr

webng:
	$(MAKE) -C src/webng

key: randomstr
	./src/randomstr/randomstr > .KEY

servrian: randomstr webng
	$(MAKE) -C src/servrian

maze: randomstr webng
	$(MAKE) -C src/maze

install:
	cp src/randomstr/randomstr /usr/local/bin
	cp src/webng/libwebng.$(EXT) /usr/local/lib
	cp src/webng/webng.h /usr/local/include
	cp src/servrian/servrian /usr/local/bin
	cp src/maze/maze /usr/local/bin

tests: webng
	$(MAKE) -C tests/Makefile

clean:
	find src/* -type f ! -name "*.c" ! -name "*.h" ! -name "Makefile" \
		-exec rm {} \;
	find tests/* -type f ! -name "*.c" ! -name "Makefile" -exec rm {} \;

