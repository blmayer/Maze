bin_PROGRAMS = server
server_SOURCES = main.c receive.c receive.h get.c get.h head.c head.h \
		 login.c login.h post.c post.h aux.c aux.h

server_LDADD = ../webng/libwebng.la
server_CFLAGS = -I ../webng
server_LDFLAGS = -lm -lcrypto

