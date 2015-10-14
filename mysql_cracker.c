#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>

#define MIN_CHAR 32
#define MAX_CHAR 126
#define DEFAULT_MAX_LENGTH 16

char getHexVal(const char hex) {
	if (hex >= 'A' && hex <= 'F') {
		return hex + 10 - 'A';
	}
	if (hex >= 'a' && hex <= 'F') {
		return hex + 10 - 'a';
	}
	if (hex >= '0' && hex <= '9') {
		return hex - '0';
	}
	return 0;
}

void convertHash(const char *hexhash, unsigned char *binhash) {
	int i;
	for(i=0; i<SHA_DIGEST_LENGTH; i++) {
		char first = *(hexhash+(2*i));
		char second = *(hexhash+(2*i)+1);
		*(binhash+i) = (getHexVal(first)*16)+getHexVal(second);
	}
}

void hash(const char *plain, int size, char *hash) {
	unsigned char s[SHA_DIGEST_LENGTH], t[SHA_DIGEST_LENGTH];
	SHA1(plain, size, s);
	SHA1(s, SHA_DIGEST_LENGTH, hash);
}

int tryLength(int len, unsigned const char *target, char *plaintext) {
	int base = 1;
	int i;
	for (i=0; i<len; i++) {
		base *= MAX_CHAR-MIN_CHAR+1;
		*(plaintext+i) = MIN_CHAR;
	}

	char *max = plaintext+len;

	unsigned char h[SHA_DIGEST_LENGTH*2];
	
	for(i=0; i<base; i++) {
		char *j;
		for(j=plaintext; j<max && *(j++) == MAX_CHAR+1;) {
			*(j-1) = MIN_CHAR;
			(*j)++;
		}
		hash(plaintext, len, h);
		if (strcmp(h, target) == 0) {
			return 1;
		}
		(*plaintext)++;
	}
	return 0;
}
		
		

int main(int argc, char* argv[]) {
	
	if (argc < 2 || argc > 3) {
		printf("Usage: %s HASH [maxlen]\n", argv[0]);
		return 0;
	}

	int maxlen = DEFAULT_MAX_LENGTH+1;
	if (argc == 3) {
		maxlen = atoi(argv[2])+1;
	}
	
	unsigned char target[SHA_DIGEST_LENGTH];
	convertHash(argv[1], target);

	time_t start, end;
	start = time(NULL);

	int i;
	for(i=1; i<maxlen; i++) {
		printf("Trying length %d\n", i);
		fflush(stdout);
		char *plain = malloc(i);
		if (tryLength(i, target, plain) == 1) {
			end = time(NULL);
			printf("Success: %s (after %ld seconds)\n", plain, end-start);
			return 0;
		}
	}
}
