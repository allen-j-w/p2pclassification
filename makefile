CC=gcc

CFLAGS=

COMMANDS=network

parser_OBJS=hashtab.o

all: ${COMMANDS}

hashtab: ${parser_OBJS} hashtab.o
	${CC} ${CFLAGS} -o ${@} ${parser_OBJS} ${@}.o


network: ${parser_OBJS} network.o
	${CC} ${CFLAGS} -lpcap -o ${@} ${parser_OBJS} ${@}.o



%.o: %.c
	${CC} ${CFLAGS} -c ${<}
clean:
	-rm   ${COMMANDS} *.o


