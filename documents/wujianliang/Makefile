CC=gcc

CFLAGS=

COMMANDS=parser parsernoopt

parser_OBJS=model.o classif.o hashtab.o

all: ${COMMANDS}

test: ${parser_OBJS} test.o
	${CC} ${CFLAGS} -o ${@} ${parser_OBJS} ${@}.o

parser: ${parser_OBJS} parser.o
	${CC} ${CFLAGS} -lpcap -o ${@} ${parser_OBJS} ${@}.o

parsernoopt: ${parser_OBJS} parsernoopt.o
	${CC} ${CFLAGS} -lpcap -o ${@} ${parser_OBJS} ${@}.o


classif.o : classif.c model.c
	${CC} ${CFLAGS} -c ${<}

%.o: %.c
	${CC} ${CFLAGS} -c ${<}
clean:
	-rm  *~ ${COMMANDS} test *.o

cleanModel: clean
	-rm model.c model.h
