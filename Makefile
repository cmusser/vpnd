CFLAGS=-g -Wall -I/usr/local/include -L/usr/local/lib -lsodium
#CFLAGS=-g -Wall -Wl,-R/usr/pkg/lib -I/usr/pkg/include -L/usr/pkg/lib -lsodium
PREFIX?=/usr/local

all: vpnd vpnd-keygen

vpnd: vpnd.c log.c net.c os.c proto.c
	${CC} ${CFLAGS} -o $@ $>

vpnd-keygen: vpnd-keygen.c
	${CC} ${CFLAGS} -o $@ $<


install: vpnd
	cp vpnd ${DESTDIR}/${PREFIX}/sbin/
	cp vpnd-keygen ${DESTDIR}/${PREFIX}/bin/
	cp vpnd.rc ${DESTDIR}/${PREFIX}/etc/rc.d/vpnd
	cp vpnd.8 ${DESTDIR}/${PREFIX}/man/man8/vpnd.8
	cp vpnd-keygen.8 ${DESTDIR}/${PREFIX}/man/man8/vpnd-keygen.8

clean:
	rm -f vpnd vpnd-keygen
