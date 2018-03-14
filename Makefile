# Make file for the Servrian project build. Here we have only four targets for
# now: servrian and servrian.exe, that builds the executable for the correct
# operating system, clean that clears the object files for a new build, and
# distclean, that clears also the binaries. Currently we are compiling some 
# object files (.o) from header files (.h), which are then linked to create
# the final binary.

OBJS := $(patsubst src/%.c, obj/%.o, $(wildcard src/*.c))
CFLAGS := -lm -lcrypto -I ./include
ifeq ($(OS),Windows_NT)
	TARGET = servrian.exe
	ARCH = Windows_NT
else
	TARGET = servrian
	ARCH = $(shell uname -s)
endif

# link
$(TARGET): $(OBJS)
	@if test ! -d bin/$(ARCH); then mkdir bin/$(ARCH); fi
	@echo "Now objects will be linked."
	$(CC) $^ $(CFLAGS) -o bin/$(ARCH)/$@
	@echo "Done."

# compile
obj/%.o: src/%.c
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

