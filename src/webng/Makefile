# Makefile for the libwebng.so library, run make here to build.
ifeq ($(shell uname -s),Darwin)
	CFLAGS += -fPIC
	LDFLAGS += -dynamiclib
	EXT = dylib
else
	CFLAGS += -fPIC
	LDFLAGS += -shared
	EXT = so
endif

libwebng.$(EXT): $(patsubst %.c, %.o, $(wildcard *.c))
	$(CC) $^ -o $@ $(LDFLAGS)

%.o: %.c %.h
	$(CC) $(CFLAGS) -c $< -o $@

