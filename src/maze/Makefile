# Makefile for the browser library, run make here to build.
CFLAGS += -I ../webng -D VERSION=\"$(VERSION)\" \
	  -D KEY='"$(shell cat ../../.KEY)"'
LDFLAGS = -lwebng -L ../webng

maze: $(patsubst %.c, %.o, $(wildcard *.c))
	$(CC) $^ -o $@ $(LDFLAGS)

%.o: %.c %.h
	$(CC) $(CFLAGS) -c $< -o $@

