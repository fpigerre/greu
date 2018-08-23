PROG=greu
SRCS=greu.c log.c
MAN=
LDADD=-levent
DPADD=${LIBEVENT}
CFLAGS+= -Wall -Werror -g
DEBUG=-g

.include <bsd.prog.mk>
