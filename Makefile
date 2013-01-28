CC=gcc
CCFLAGS=-g -Wall

all: uoenc uodec test

uoenc: uoenc.c
	$(CC) $(CCFLAGS) -c uoenc.c `libgcrypt-config --cflags`
	$(CC) uoenc.o -o $@ `libgcrypt-config --libs`

uodec: uodec.c
	$(CC) $(CCFLAGS) -c uodec.c `libgcrypt-config --cflags`
	$(CC) uodec.o -o $@ `libgcrypt-config --libs`

test:
	echo "this is a test, this is only a test" | cat > text.test 

clean:
	rm -f *.o uodec uoenc
	rm -f *.test *.uo
