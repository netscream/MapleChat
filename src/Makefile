CC = gcc
GLIBUBUNTUFIX = -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include \
    -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -DPURIFY 
GLIBS = -DPURIFY ${GLIBUBUNTUFIX} `pkg-config --cflags --libs glib-2.0`
CFLAGS = -std=gnu11 -O2 -g -Wall -Wextra -Wformat=2 $(shell pkg-config glib-2.0 openssl --cflags)

all: chatd chat

chat: chat.o client.o debugging.o printing.o authentication.o user.o getpasswd.o
	$(CC) $(GLIBS) $(CFLAGS) -o $@ $^ -lreadline $(shell pkg-config glib-2.0 openssl --libs)

chatd: chatd.o game.o server.o debugging.o printing.o authentication.o iterators.o processing.o user.o
	$(CC) $(GLIBS) $(CFLAGS) -o $@ $^ $(shell pkg-config glib-2.0 openssl --libs) -lm

chatd.o:
	${CC} ${CFLAGS} ${GLIBS} chatd.c -c

chat.o:
	${CC} ${CFLAGS} ${GLIBS} chat.c -c

debugging.o: libs/debugging.c
	${CC} ${CFLAGS} ${GLIBS} libs/debugging.c -c

printing.o: libs/printing.c
	${CC} ${CFLAGS} ${GLIBS} libs/printing.c -c

game.o: libs/game.c
	${CC} ${CFLAGS} ${GLIBS} libs/game.c -c

user.o: libs/user.c
	${CC} ${CFLAGS} ${GLIBS} libs/user.c -c

processing.o: libs/processing.c
	${CC} ${CFLAGS} ${GLIBS} libs/processing.c -c

authentication.o: libs/authentication.c
	${CC} ${CFLAGS} ${GLIBS} libs/authentication.c -c

iterators.o: libs/iterators.c
	${CC} ${CFLAGS} ${GLIBS} libs/iterators.c -c

server.o: libs/server.c
	${CC} ${CFLAGS} ${GLIBS} libs/server.c -c

client.o: libs/client.c
	${CC} ${CFLAGS} ${GLIBS} libs/client.c -c

getpasswd.o: libs/getpasswd.c
	${CC} ${CFLAGS} ${GLIBS} libs/getpasswd.c -c

clean:
	rm -f *.o *~

distclean: clean
	rm -f chatd chat

run_server:
	./chatd $$(/labs/tsam16/my_port || echo 2000)

run_client:
	./chat 127.0.0.1 $$(/labs/tsam16/my_port || echo 2000)


