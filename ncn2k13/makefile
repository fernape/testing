CC=gcc -g
LIBS=-lcrypto -lcrypt
LIBS-OSX=-lcrypto
default: client server

client: bsd-base64.o client.c
	$(CC) client.c bsd-base64.o -o client $(LIBS)

server: bsd-base64.o server.c
	$(CC) server.c bsd-base64.o -o server $(LIBS)

osx:	bsd-base64.o client.c server.c getline.o
	$(CC) client.c ./bsd-base64.o getline.o -o client $(LIBS-OSX)
	$(CC) server.c ./bsd-base64.o getline.o -o server $(LIBS-OSX)

bsd-base64.o:	bsd-base64.c
	$(CC) bsd-base64.c -c -o bsd-base64.o

getline.o: getline.c
	$(CC) getline.c -c -o getline.o

clean:
	rm -f *.o server client *~

