all:
	g++ segwit_addr.c main.cpp -lcrypto -lssl -ljson-c -lsecp256k1 -lcurl -o main