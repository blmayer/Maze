# Make file for the Maze project build. Here we have only four targets for
# now: maze and maze.exe, that builds the executable for the correct
# operating system, clean that clears the object files for a new build, and
# distclean, that clears also the binaries. Currently we are compiling some 
# object files (.o) from header files (.h), which are then linked to create
# the final binary.
SHELL := /bin/bash
OBJS := obj/browser.o obj/getfn.o

# do some system checks
ifeq ($(OS),Windows_NT)
	TARGET = maze.exe
	ARCH = Windows_NT
else 
	ARCH = $(shell uname -s)
	TARGET = maze
	ifeq ($(ARCH),Darwin)
		CFLAGS = -Wall -I ./include -I /usr/local/opt/openssl/include
		LFLAGS = -L /usr/local/lib
		LIBDIR = /usr/local/lib
		INCDIR = /usr/local/include
		LFLAGS = -L /usr/local/lib -lweb -lm -lcrypto
	else
		CFLAGS = -Wall -I ./include
		LFLAGS = -lm -lcrypto -lweb
		LIBDIR = /usr/lib
		INCDIR = /usr/include
	endif
endif

# set directories for search dependencies
vpath %.h 	include
vpath %.c 	src
vpath %.so 	lib

# targets
.PHONY: $(TARGET) clean distclean

# link
$(TARGET): $(OBJS)
	@if test ! -d bin/$(ARCH); then mkdir bin/$(ARCH); fi
	@echo "Now objects will be linked."
	$(CC) $^ $(CFLAGS) -o bin/$(ARCH)/$@ $(LFLAGS)
	@echo "Done."

# compile
obj/%.o: %.c
	@if test ! -d obj; then mkdir obj; fi
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@
	
# remove compilation products
clean:
	@echo "Cleaning up..."
	$(RM) obj/*.o

# remove compilation and linking products
distclean:
	@echo "Cleaning up..."
	$(RM) obj/*.o
	$(RM) -rf bin/*

