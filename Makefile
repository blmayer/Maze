# Make file for the Maze project build. Here we have only four targets for
# now: maze and maze.exe, that builds the executable for the correct
# operating system, clean that clears the object files for a new build, and
# distclean, that clears also the binaries. Currently we are compiling some 
# object files (.o) from header files (.h), which are then linked to create
# the final binary.

ifeq ($(OS),Windows_NT)
	TARGET = maze.exe
	ARCH = Windows_NT
else 
	ARCH = $(shell uname -s)
	ifeq ($(ARCH),Darwin)
		CFLAGS = -I ./include -I /usr/local/opt/openssl/include
		TARGET = maze
	else
		CFLAGS = -I ./include -I ../Randomator/include
		LFLAGS = -L ../Randomator/lib -lm -lcrypto -lweb
		TARGET = maze
	endif
endif

# link
$(TARGET): obj/browser.o obj/getfn.o obj/auxfns.o ../Randomator/lib/libweb.so
	@if test ! -d bin/$(ARCH); then mkdir bin/$(ARCH); fi
	@echo "Now objects will be linked."
	$(CC) $^ $(CFLAGS) -o bin/$(ARCH)/$@ $(LFLAGS)
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

