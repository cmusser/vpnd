CFLAGS=-g -Wall -I/usr/local/include -L/usr/local/lib -lsodium
#CFLAGS=-g -Wall -Wl,-R/usr/pkg/lib -I/usr/pkg/include -L/usr/pkg/lib -lsodium
PREFIX?=/usr/local

all: vpnd keypair

vpnd: vpnd.c log.c net.c os.c proto.c
	${CC} ${CFLAGS} -o $@ $>

keypair: keypair.c
	${CC} ${CFLAGS} -o $@ $<


install: vpnd
	cp vpnd ${DESTDIR}/${PREFIX}/sbin/
	cp vpnd.rc ${DESTDIR}/${PREFIX}/etc/rc.d/vpnd
	cp vpnd.8 ${DESTDIR}/${PREFIX}/man/man8/vpnd.8

clean:
	rm -f vpnd keypair
