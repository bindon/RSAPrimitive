#ifndef _CRYPTO_MAIN_H
#include "gmp.h"
#include <time.h>

typedef struct rsa_key_size {
	unsigned long keySize;
	int trustValue;
} rsa_key_size;

rsa_key_size KEY_SIZE_ARRAY[] = {
	{ 1024, 40 },
	{ 2048, 56 },
	{ 3072, 64 },
	{ 4096, 64 }
};

clock_t elapsed;
float sec;

#define IN
#define OUT
#define START_WATCH { elapsed = -clock(); }
#define STOP_WATCH { elapsed += clock(); sec = (float)elapsed/CLOCKS_PER_SEC; }
#define PRINT_TIME(qstr) { printf("[%s: %.5f s]\n", qstr, sec); }
#define CRYPTO_SUCCESS 0
#define CRYPTO_FAILED  1

void selfTest(int arrayIndex);
int generatePrimeNumber(IN gmp_randstate_t state, IN mpz_t e, IN int trustValue, OUT mpz_t primeNumber);
int decryptForCRT(IN mpz_t cipherText, IN mpz_t primeP, IN mpz_t primeQ, IN mpz_t n, IN mpz_t dp, IN mpz_t dq, IN mpz_t inverseQ, IN int keySize, OUT mpz_t plainText);
#endif