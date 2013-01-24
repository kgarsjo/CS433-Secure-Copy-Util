CC=gcc
CCFLAGS=-g -Wall

all: uoenc uodec

uoenc: uoenc.c
	$(CC) $(CCFLAGS) -c uoenc.c `libgcrypt-config --cflags`
	$(CC) uoenc.o -o uoenc `libgcrypt-config --libs`

uodec: uodec.c
	$(CC) $(CCFLAGS) -c uodec.c
	$(CC) uodec.o -o uodec

clean:
	rm -f *.o uodec uoenc
