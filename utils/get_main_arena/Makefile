CC=gcc
CFLAGS=-m32

main_arena_offset: pmparser.o main_arena_offset.o
	$(CC) $(CFLAGS) main_arena_offset.o pmparser.o -o main_arena_offset

main_arena_offset.o: main_arena_offset.c
	$(CC) $(CFLAGS) -c main_arena_offset.c -o main_arena_offset.o

pmparser.o: pmparser/pmparser.c
	$(CC) $(CFLAGS) -c pmparser/pmparser.c -o pmparser.o

clean:
	rm main_arena_offset *.o