# Makefile for the servrian binary, run make here to build.
CFLAGS += -I ../webng -D VERSION=\"$(VERSION)\" \
	  -D KEY='"$(shell cat ../../.KEY)"'
LDFLAGS += -lm -lcrypto -lwebng -L ../webng

servrian: $(patsubst %.c, %.o, $(wildcard *.c))
	$(CC) $^ -o $@ $(LDFLAGS)

%.o: %.c %.h
	$(CC) $(CFLAGS) -c $< -o $@

