CFLAGS=-g -Wall
#CFLAGS=-g -Wall -Wl,-R/usr/pkg/lib -I/usr/pkg/include -L/usr/pkg/lib -lsodium
PREFIX?=/usr/local

all: vpnd vpnd-keygen

vpnd: diag.c nonce.c os_bsd.c proto.c setup.c util.c vpnd.c
	${CC} ${CFLAGS} -o $@ $^ -lsodium

vpnd-keygen: vpnd-keygen.c
	${CC} ${CFLAGS} -o $@ $< -lsodium


install: vpnd
	cp vpnd ${DESTDIR}/${PREFIX}/sbin/
	cp vpnd-keygen ${DESTDIR}/${PREFIX}/bin/
	cp vpnd.8 ${DESTDIR}/${PREFIX}/man/man8/vpnd.8
	cp vpnd-keygen.8 ${DESTDIR}/${PREFIX}/man/man8/vpnd-keygen.8

clean:
	rm -f vpnd vpnd-keygen
