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
	if (hex >= 'a' && hex <= 'f') {
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
	int i;
	for (i=0; i<len; i++) {
		*(plaintext+i) = MIN_CHAR;
	}

	char *max = plaintext+len;
	unsigned char h[SHA_DIGEST_LENGTH];

	while(1) {
		char *j;
		for(j=plaintext; *(j++) == MAX_CHAR+1;) {
			if (j == max) {
				return 0;
			}
			*(j-1) = MIN_CHAR;
			(*j)++;
		}
		hash(plaintext, len, h);
		if (strncmp(target, h, SHA_DIGEST_LENGTH) == 0) {
			return 1;
		}
		(*plaintext)++;
	}
}
		
		
int main(int argc, char* argv[]) {
	
	if (argc < 2 || argc > 3) {
		printf("Usage: %s HASH [maxlen]\n", argv[0]);
		return 0;
	}

	if (strlen(argv[1]) != SHA_DIGEST_LENGTH*2) {
		printf("Error: Malformed hash!\n");
		printf("Usage: %s HASH [maxlen]\n", argv[0]);
		return 1;
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
		free(plain);
	}
}
