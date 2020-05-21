CC=g++
CFLAGS=-std=c++0x -pthread -lssl -lcrypto

compile: tls_server.o
	$(CC) -o tls_server tls_server.o $(CFLAGS)
