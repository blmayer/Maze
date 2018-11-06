# Makefile for the servrian binary, run make here to build.
CFLAGS += -I ../webng -D VERSION=\"$(VERSION)\"
LDFLAGS += -lm -lwebng -L ../webng

servrian: $(patsubst %.c, %.o, $(wildcard *.c))
	$(CC) $^ -o $@ $(LDFLAGS)

%.o: %.c %.h
	$(CC) $(CFLAGS) -c $< -o $@

