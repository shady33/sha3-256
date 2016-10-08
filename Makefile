rm=/bin/rm -f
CC=cc
DEFS=
INCLUDES=-I.
LIBS=

DEFINES= $(INCLUDES) $(DEFS)
CFLAGS= -std=c99 $(DEFINES) -O2 -fomit-frame-pointer -funroll-loops -g -Wall -Wextra -pedantic -Wshadow -Wpointer-arith -Wcast-qual -Wmissing-prototypes -Wformat=2 -Wcast-align -Wbad-function-cast -Wundef -Wunreachable-code -Wlogical-op -Wfloat-equal -Wold-style-definition

all: sha3_driver

sha3_driver: sha3_driver.c sha3.o
	$(CC) $(CFLAGS) -o sha3_driver sha3_driver.c sha3.o $(LIBS)

sha3.o: sha3.c
	$(CC) $(CFLAGS) -c sha3.c $(LIBS)

clean:
	$(rm) sha3.o sha3_driver *.o core *~
