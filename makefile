CC = gcc
CFLAGS = -O2 -Wall

pwgen: Src/pwgen.c
	$(CC) $(CFLAGS) -o pwgen Src/pwgen.c

clean:
	rm -f pwgen pwgen.exe
