CC = gcc
CFLAGS = -O2 -Wall

pwgen: src/pwgen.c
	$(CC) $(CFLAGS) -o pwgen src/pwgen.c

clean:
	rm -f pwgen pwgen.exe
