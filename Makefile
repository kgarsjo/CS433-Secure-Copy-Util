CC=gcc
CCFLAGS=-g -Wall

all: uoenc uodec

uoenc:
	$(CC) $(CCFLAGS) -c uoenc.c
	$(CC) uoenc.o -o uoenc

uodec:
	$(CC) $(CCFLAGS) -c uodec.c
	$(CC) uodec.o -o uodec

clean:
	rm -f *.o uodec uoenc
