/**
 * Title  : Cryptographic Primitive Development 001
 * Author : Choi Won Bin, Korea Univ.
 * Date   : 2016-09-20, 2016-09-27, 2016-10-04
 * Description
 * 0. KEY_SIZE_INDEX 값만 수정하면 bit에 따른 신뢰 값을 이용해 알아서 수행
 *    index = {0: 1024, 1: 2048, 2: 3072, 3: 4096}
 * 1. Prime Test는 KEY_SIZE_INDEX 값에 따라 수행한다. 우리가 정한 신뢰 구간 안에 들어감
 * 2. Prime Number의 input 값은 홀수 값만 넣으면 됨, 즉 첫 번째 바이트를 1로 Set
 */

#include <stdio.h>
#include "crypto_main.h"

int main(int argc, char *argv[], char *env[])
{
	int idx, len = 4;
	
	for (idx = 0; idx < len; idx++) {
		selfTest(idx);
	}
}

void selfTest(int arrayIndex)
{
	int resultValue = CRYPTO_FAILED;
	int idx = 0, len = 10;

	// definition 16+1
	mpz_t primeP, primeQ, pMinusOne, qMinusOne;
	mpz_t n, phiN, e, d;
	mpz_t tempValue;
	mpz_t inverseQ, dp, dq; // 중국인의 나머지 정리를 위해 선행 계산되는 값들
	mpz_t plainText, plainTextForNormal, plainTextForCRT, cipherText;
	gmp_randstate_t state;

	// initialize 16
	printf("[initialize...]\n");
	mpz_init2(primeP, KEY_SIZE_ARRAY[arrayIndex].keySize >> 1);
	mpz_init2(primeQ, KEY_SIZE_ARRAY[arrayIndex].keySize >> 1);
	mpz_init2(pMinusOne, KEY_SIZE_ARRAY[arrayIndex].keySize >> 1);
	mpz_init2(qMinusOne, KEY_SIZE_ARRAY[arrayIndex].keySize >> 1);
	mpz_init2(n, KEY_SIZE_ARRAY[arrayIndex].keySize);
	mpz_init2(phiN, KEY_SIZE_ARRAY[arrayIndex].keySize);
	mpz_init2(e, KEY_SIZE_ARRAY[arrayIndex].keySize);
	mpz_init2(d, KEY_SIZE_ARRAY[arrayIndex].keySize);
	mpz_init2(tempValue, KEY_SIZE_ARRAY[arrayIndex].keySize);
	mpz_init2(inverseQ, KEY_SIZE_ARRAY[arrayIndex].keySize);
	mpz_init2(dp, KEY_SIZE_ARRAY[arrayIndex].keySize);
	mpz_init2(dq, KEY_SIZE_ARRAY[arrayIndex].keySize);
	mpz_init2(plainText, KEY_SIZE_ARRAY[arrayIndex].keySize);
	mpz_init2(plainTextForNormal, KEY_SIZE_ARRAY[arrayIndex].keySize);
	mpz_init2(plainTextForCRT, KEY_SIZE_ARRAY[arrayIndex].keySize);
	mpz_init2(cipherText, KEY_SIZE_ARRAY[arrayIndex].keySize);
	gmp_randinit_default(state);

	// start generate rsa key
	printf("[start generate rsa %d key]\n", KEY_SIZE_ARRAY[arrayIndex].keySize);

	// RSA 키 생성속도 시작
	for (idx = 0; idx < len; idx++) {
		START_WATCH;
		printf("%02d번째 키 생성...", idx+1);

		// 1. set e value
		mpz_set_ui(e, 0x10001);

		// 2. set random prime number
		// printf("[generate prime number... trust value is %d]\n", KEY_SIZE_ARRAY[arrayIndex].trustValue);
		// printf("[generate prime number... P]\n");
		if (resultValue = generatePrimeNumber(state, e, KEY_SIZE_ARRAY[arrayIndex].trustValue, primeP)) {
			fprintf(stderr, "소수 P 생성 도중 오류가 발생하였습니다. 오류코드 : 0x[%08x]\n", resultValue);
			goto end;
		}
		// printf("[generate prime number... Q]\n");
		if (resultValue = generatePrimeNumber(state, e, KEY_SIZE_ARRAY[arrayIndex].trustValue, primeQ)) {
			fprintf(stderr, "소수 Q 생성 도중 오류가 발생하였습니다. 오류코드 : 0x[%08x]\n", resultValue);
			goto end;
		}

		// 3. caculate n
		mpz_mul(n, primeP, primeQ);

		// 4. caculate phi-n
		mpz_sub_ui(pMinusOne, primeP, 1); // p-1
		mpz_sub_ui(qMinusOne, primeQ, 1); // q-1
		mpz_mul(phiN, pMinusOne, qMinusOne); // phi(n) = (p-1) * (q-1)

		// 5. caculate d
		mpz_invert(d, e, phiN);

		// 6. verify, e*d mod phi(n)
		mpz_mul(tempValue, e, d); // e와 d를 곱함
		mpz_mod(tempValue, tempValue, phiN); // mod phi(n)

		// 7. caculate inverseQ, dp, dq
		mpz_invert(inverseQ, primeQ, primeP);
		mpz_mod(dp, d, pMinusOne);
		mpz_mod(dq, d, qMinusOne);
		STOP_WATCH;
		PRINT_TIME("키 생성 소요시간");
	}
	/* print values
	gmp_printf("p = %Zx\n", primeP);
	gmp_printf("q = %Zx\n", primeQ);
	gmp_printf("n = %Zx\n", n);
	gmp_printf("phi(n) = %Zx\n", phiN);
	gmp_printf("e = %Zx\n", e);
	gmp_printf("d = %Zx\n", d);
	gmp_printf("verify = %Zx\n", tempValue); // e*d mod phi(n) == 1
	gmp_printf("inverseQ = %Zx\n", inverseQ);
	gmp_printf("dp = %Zx\n", dp);
	gmp_printf("dq = %Zx\n", dq);
	*/


	// end generate rsa key
	printf("[end generate rsa key]\n\n\n");

	// start compare crypto
	printf("[start compare crypto]\n");

	// *. generate plaintext
	mpz_urandomb(plainText, state, KEY_SIZE_ARRAY[arrayIndex].keySize);
	// gmp_printf("plainText = %Zx\n", plainText);

	// 8. normal encryption
	// 암호화 : mpz_powm(c, m, e, n);
	printf("\n[암호화 %d번 수행]\n", len);
	for (idx = 0; idx < len; idx++) {
		START_WATCH;
		mpz_powm(cipherText, plainText, e, n);
		STOP_WATCH;
		// gmp_printf("cipherText = %Zx\n", cipherText);
		PRINT_TIME("암호화 소요 시간");
	}

	// 9. normal decryption
	// 복호화 : mpz_powm(m, c, d, n);
	printf("\n[일반 복호화 %d번 수행]\n", len);
	for (idx = 0; idx < len; idx++) {
		START_WATCH;
		mpz_powm(plainTextForNormal, cipherText, d, n);
		STOP_WATCH;
		// gmp_printf("plainTextForNormal = %Zx\n", plainTextForNormal);
		PRINT_TIME("일반 복호화 소요 시간");
	}

	// 10. CRT decryption
	printf("\n[CRT 복호화 %d번 수행]\n", len);
	for (idx = 0; idx < len; idx++) {
		START_WATCH;
		if (resultValue = decryptForCRT(cipherText, primeP, primeQ, n, dp, dq, inverseQ, KEY_SIZE_ARRAY[arrayIndex].keySize, plainTextForCRT)) {
			fprintf(stderr, "CRT 복호화 도중 오류가 발생하였습니다. 오류코드 : 0x[%08x]\n", resultValue);
			goto end;
		}
		STOP_WATCH;
		// gmp_printf("plainTextForNormal = %Zx\n", plainTextForCRT);
		PRINT_TIME("CRT 복호화 소요 시간");
	}

	// verify decryption
	printf("\n[verify decryption]\n");
	printf("Normal Decryption : %s\n", (mpz_cmp(plainText, plainTextForNormal) ? "INVALID" : "VALID"));
	printf("CRT    Decryption : %s\n", (mpz_cmp(plainText, plainTextForCRT) ? "INVALID" : "VALID"));

	// end compare crypto
	printf("\n[end compare crypto]\n");

end:
	// finalize 16+1
	gmp_randclear(state);
	mpz_clear(primeP);
	mpz_clear(primeQ);
	mpz_clear(pMinusOne);
	mpz_clear(qMinusOne);
	mpz_clear(n);
	mpz_clear(phiN);
	mpz_clear(e);
	mpz_clear(d);
	mpz_clear(tempValue);
	mpz_clear(inverseQ);
	mpz_clear(dp);
	mpz_clear(dq);
	mpz_clear(plainText);
	mpz_clear(plainTextForNormal);
	mpz_clear(plainTextForCRT);
	mpz_clear(cipherText);

	return 0;
}

/**
 * Prime Number를 생성하는 프로그램
 *
 * @param  : mpz_t가 배열(포인터)이기 때문에 call by reference 형태로 매개변수가 넘어감
 *   - IN param
 *     1. state : 기존에 초기화 했던 random state 계속 사용(현재 default로 초기화 하고있기 때문에 P와 Q가 같은 수가 나오지 않으려면 계속 사용해야 함)
 *     2. e     : 기 정의된 e값 사용
 *   - OUT param
 *     1. primeNumber : 결과 소수 반환
 *
 * @description
 *   1. 기본 시드를 사용하여 random number를 생성함
 *   2. 첫 번째 비트를 1로 set하여 홀수로 변환
 *   3. prime number를 56번의 신뢰구간 사이가 될 때까지 반복
 *     3-1. 랜덤하게 생성된 홀수에 2를 더함
 *     3-2. gcd(e, primeNumber-1)=1인지 확인(서로소)
 *
 * @note
 *   mpz_probab_prime_p() 함수의 경우 완벽한 prime number를 판단할 때는 2, 일정 신뢰구간 내에는 1, 아니면 0이 반환
 *
 */
int generatePrimeNumber(IN gmp_randstate_t state, IN mpz_t e, IN int trustValue, OUT mpz_t primeNumber)
{
	int resultValue = CRYPTO_FAILED;

	// definition
	mpz_t tempValue;
	int primeNumberSize = (primeNumber->_mp_alloc * sizeof(unsigned long)) << 3;
	// primeNumber의 크기는 할당된 배열 크기

	// initialize
	mpz_init2(tempValue, primeNumberSize);
	
	// generation random
	mpz_urandomb(primeNumber, state, primeNumberSize);

	// make odd & set MSB
	mpz_setbit(primeNumber, 0); // 최하위 비트를 1로 set 해줌 -> 기존 primeNumber->_mp_d[0] |= 1;
	mpz_setbit(primeNumber, primeNumberSize-1); // 최상위비트를 1로 set 해줌

	// 해당 함수의 결과가 0이 아니면 반복시킴
	while (1)
	{
		if (mpz_probab_prime_p(primeNumber, trustValue)) { // primeNumber 판단
			mpz_sub_ui(tempValue, primeNumber, 1); // p-1을 구해서 tempValue에 넣음
			mpz_gcd(tempValue, e, tempValue); // tempValue == p-1
			if (!mpz_cmp_si(tempValue, 1)) // gcd가 1인지 확인
			{
				break; // gcd가 1이 아니면 while문을 빠져나감
			}
		}
		mpz_add_ui(primeNumber, primeNumber, 2); // 소수 아니면 2를 더함
	}

	resultValue = CRYPTO_SUCCESS;
//end:
	// finalize
	mpz_clear(tempValue);
	
	return resultValue;
}

/**
 * param
 *   - IN param
 *     1. cipherText : 복호화 할 암호문
 *     2. primeP     : 이미 만들어진 소수 p
 *     3. primeQ     : 이미 만들어진 소수 q
 *     4. n          : 이미 만들어진 n
 *     5. d          : 이미 만들어진 d
 *     6. pMinusOne  : 이미 만들어진 p-1
 *     7. qMinusOne  : 이미 만들어진 q-1
 *
 *   - OUT param
 *     1. plainText : 결과 평문
 *
 * description
 *   1. 계산의 효율을 위해 
 *   2. 첫 번째 비트를 1로 set하여 홀수로 변환
 *   3. prime number를 56번의 신뢰구간 사이가 될 때까지 반복
 *     3-1. 랜덤하게 생성된 홀수에 2를 더함
 *     3-2. gcd(e, primeNumber-1)=1인지 확인(서로소)
 *
 * note
 * mpz_probab_prime_p() 함수의 경우 완벽한 prime number를 판단할 때는 2, 일정 신뢰구간 내에는 1, 아니면 0이 반환
 */
int decryptForCRT(IN mpz_t cipherText, IN mpz_t primeP, IN mpz_t primeQ, IN mpz_t n, IN mpz_t dp, IN mpz_t dq, IN mpz_t inverseQ, IN int keySize, OUT mpz_t plainText)
{
	int resultValue = CRYPTO_FAILED;

	// definition 2
	mpz_t x, y;

	// initialize 2
	mpz_init2(x, keySize);
	mpz_init2(y, keySize);

	// x = (c mod p)^dp mod p
	// y = (c mod q)^dq mod q
	// m = y + (x-y)*invQ*q mod n
	// calculate X
	mpz_mod(x, cipherText, primeP);
	mpz_powm(x, x, dp, primeP);
	// calculate Y
	mpz_mod(y, cipherText, primeQ);
	mpz_powm(y, y, dq, primeQ);
	// calculate plainText
	mpz_sub(plainText, x, y); // x-y
	mpz_mul(plainText, plainText, inverseQ); // (x-y)*invQ
	mpz_mod(plainText, plainText, n); // (a*b) mod c = (a mod c) * (b mod c) : mod하고 곱하면 시간이 더 빨라짐
	mpz_mul(plainText, plainText, primeQ); // (x-y)*invQ*q
	mpz_add(plainText, plainText, y); // y+(x-y)*invQ*q
	mpz_mod(plainText, plainText, n);
	// gmp_printf("x = %Zx\n", x);
	// gmp_printf("y = %Zx\n", y);

	resultValue = CRYPTO_SUCCESS;

//end:
	// finalize 2
	mpz_clear(x);
	mpz_clear(y);

	return resultValue;
}