CC = gcc
GLIBUBUNTUFIX = -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include \
    -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE
GLIBS = ${GLIBUBUNTUFIX} `pkg-config --cflags --libs glib-2.0`
CFLAGS = -std=gnu11 -O2 -g -Wall -Wextra -Wformat=2 $(shell pkg-config glib-2.0 openssl --cflags)

all: chatd chat

chat: chat.o getpasswd.o
	$(CC) $(GLIBS) $(CFLAGS) -o $@ $^ -lreadline $(shell pkg-config glib-2.0 openssl --libs)

chatd: chatd.o
	$(CC) $(GLIBS) $(CFLAGS) -o $@ $^ $(shell pkg-config glib-2.0 openssl --libs) -lm

debugging.o: libs/debugging.c
	${CC} ${CFLAGS} ${GLIBS} libs/debugging.c -c

printing.o: libs/printing.c
	${CC} ${CFLAGS} ${GLIBS} libs/printing.c -c

server.o: libs/server.c
	${CC} ${CFLAGS} ${GLIBS} libs/server.c -c

clean:
	rm -f *.o *~

distclean: clean
	rm -f chatd chat
