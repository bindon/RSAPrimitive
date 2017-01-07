/**
 * Title  : Cryptographic Primitive Development 001
 * Author : Choi Won Bin, Korea Univ.
 * Date   : 2016-09-20, 2016-09-27, 2016-10-04
 * Description
 * 0. KEY_SIZE_INDEX ���� �����ϸ� bit�� ���� �ŷ� ���� �̿��� �˾Ƽ� ����
 *    index = {0: 1024, 1: 2048, 2: 3072, 3: 4096}
 * 1. Prime Test�� KEY_SIZE_INDEX ���� ���� �����Ѵ�. �츮�� ���� �ŷ� ���� �ȿ� ��
 * 2. Prime Number�� input ���� Ȧ�� ���� ������ ��, �� ù ��° ����Ʈ�� 1�� Set
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
	mpz_t inverseQ, dp, dq; // �߱����� ������ ������ ���� ���� ���Ǵ� ����
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

	// RSA Ű �����ӵ� ����
	for (idx = 0; idx < len; idx++) {
		START_WATCH;
		printf("%02d��° Ű ����...", idx+1);

		// 1. set e value
		mpz_set_ui(e, 0x10001);

		// 2. set random prime number
		// printf("[generate prime number... trust value is %d]\n", KEY_SIZE_ARRAY[arrayIndex].trustValue);
		// printf("[generate prime number... P]\n");
		if (resultValue = generatePrimeNumber(state, e, KEY_SIZE_ARRAY[arrayIndex].trustValue, primeP)) {
			fprintf(stderr, "�Ҽ� P ���� ���� ������ �߻��Ͽ����ϴ�. �����ڵ� : 0x[%08x]\n", resultValue);
			goto end;
		}
		// printf("[generate prime number... Q]\n");
		if (resultValue = generatePrimeNumber(state, e, KEY_SIZE_ARRAY[arrayIndex].trustValue, primeQ)) {
			fprintf(stderr, "�Ҽ� Q ���� ���� ������ �߻��Ͽ����ϴ�. �����ڵ� : 0x[%08x]\n", resultValue);
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
		mpz_mul(tempValue, e, d); // e�� d�� ����
		mpz_mod(tempValue, tempValue, phiN); // mod phi(n)

		// 7. caculate inverseQ, dp, dq
		mpz_invert(inverseQ, primeQ, primeP);
		mpz_mod(dp, d, pMinusOne);
		mpz_mod(dq, d, qMinusOne);
		STOP_WATCH;
		PRINT_TIME("Ű ���� �ҿ�ð�");
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
	// ��ȣȭ : mpz_powm(c, m, e, n);
	printf("\n[��ȣȭ %d�� ����]\n", len);
	for (idx = 0; idx < len; idx++) {
		START_WATCH;
		mpz_powm(cipherText, plainText, e, n);
		STOP_WATCH;
		// gmp_printf("cipherText = %Zx\n", cipherText);
		PRINT_TIME("��ȣȭ �ҿ� �ð�");
	}

	// 9. normal decryption
	// ��ȣȭ : mpz_powm(m, c, d, n);
	printf("\n[�Ϲ� ��ȣȭ %d�� ����]\n", len);
	for (idx = 0; idx < len; idx++) {
		START_WATCH;
		mpz_powm(plainTextForNormal, cipherText, d, n);
		STOP_WATCH;
		// gmp_printf("plainTextForNormal = %Zx\n", plainTextForNormal);
		PRINT_TIME("�Ϲ� ��ȣȭ �ҿ� �ð�");
	}

	// 10. CRT decryption
	printf("\n[CRT ��ȣȭ %d�� ����]\n", len);
	for (idx = 0; idx < len; idx++) {
		START_WATCH;
		if (resultValue = decryptForCRT(cipherText, primeP, primeQ, n, dp, dq, inverseQ, KEY_SIZE_ARRAY[arrayIndex].keySize, plainTextForCRT)) {
			fprintf(stderr, "CRT ��ȣȭ ���� ������ �߻��Ͽ����ϴ�. �����ڵ� : 0x[%08x]\n", resultValue);
			goto end;
		}
		STOP_WATCH;
		// gmp_printf("plainTextForNormal = %Zx\n", plainTextForCRT);
		PRINT_TIME("CRT ��ȣȭ �ҿ� �ð�");
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
 * Prime Number�� �����ϴ� ���α׷�
 *
 * @param  : mpz_t�� �迭(������)�̱� ������ call by reference ���·� �Ű������� �Ѿ
 *   - IN param
 *     1. state : ������ �ʱ�ȭ �ߴ� random state ��� ���(���� default�� �ʱ�ȭ �ϰ��ֱ� ������ P�� Q�� ���� ���� ������ �������� ��� ����ؾ� ��)
 *     2. e     : �� ���ǵ� e�� ���
 *   - OUT param
 *     1. primeNumber : ��� �Ҽ� ��ȯ
 *
 * @description
 *   1. �⺻ �õ带 ����Ͽ� random number�� ������
 *   2. ù ��° ��Ʈ�� 1�� set�Ͽ� Ȧ���� ��ȯ
 *   3. prime number�� 56���� �ŷڱ��� ���̰� �� ������ �ݺ�
 *     3-1. �����ϰ� ������ Ȧ���� 2�� ����
 *     3-2. gcd(e, primeNumber-1)=1���� Ȯ��(���μ�)
 *
 * @note
 *   mpz_probab_prime_p() �Լ��� ��� �Ϻ��� prime number�� �Ǵ��� ���� 2, ���� �ŷڱ��� ������ 1, �ƴϸ� 0�� ��ȯ
 *
 */
int generatePrimeNumber(IN gmp_randstate_t state, IN mpz_t e, IN int trustValue, OUT mpz_t primeNumber)
{
	int resultValue = CRYPTO_FAILED;

	// definition
	mpz_t tempValue;
	int primeNumberSize = (primeNumber->_mp_alloc * sizeof(unsigned long)) << 3;
	// primeNumber�� ũ��� �Ҵ�� �迭 ũ��

	// initialize
	mpz_init2(tempValue, primeNumberSize);
	
	// generation random
	mpz_urandomb(primeNumber, state, primeNumberSize);

	// make odd & set MSB
	mpz_setbit(primeNumber, 0); // ������ ��Ʈ�� 1�� set ���� -> ���� primeNumber->_mp_d[0] |= 1;
	mpz_setbit(primeNumber, primeNumberSize-1); // �ֻ�����Ʈ�� 1�� set ����

	// �ش� �Լ��� ����� 0�� �ƴϸ� �ݺ���Ŵ
	while (1)
	{
		if (mpz_probab_prime_p(primeNumber, trustValue)) { // primeNumber �Ǵ�
			mpz_sub_ui(tempValue, primeNumber, 1); // p-1�� ���ؼ� tempValue�� ����
			mpz_gcd(tempValue, e, tempValue); // tempValue == p-1
			if (!mpz_cmp_si(tempValue, 1)) // gcd�� 1���� Ȯ��
			{
				break; // gcd�� 1�� �ƴϸ� while���� ��������
			}
		}
		mpz_add_ui(primeNumber, primeNumber, 2); // �Ҽ� �ƴϸ� 2�� ����
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
 *     1. cipherText : ��ȣȭ �� ��ȣ��
 *     2. primeP     : �̹� ������� �Ҽ� p
 *     3. primeQ     : �̹� ������� �Ҽ� q
 *     4. n          : �̹� ������� n
 *     5. d          : �̹� ������� d
 *     6. pMinusOne  : �̹� ������� p-1
 *     7. qMinusOne  : �̹� ������� q-1
 *
 *   - OUT param
 *     1. plainText : ��� ��
 *
 * description
 *   1. ����� ȿ���� ���� 
 *   2. ù ��° ��Ʈ�� 1�� set�Ͽ� Ȧ���� ��ȯ
 *   3. prime number�� 56���� �ŷڱ��� ���̰� �� ������ �ݺ�
 *     3-1. �����ϰ� ������ Ȧ���� 2�� ����
 *     3-2. gcd(e, primeNumber-1)=1���� Ȯ��(���μ�)
 *
 * note
 * mpz_probab_prime_p() �Լ��� ��� �Ϻ��� prime number�� �Ǵ��� ���� 2, ���� �ŷڱ��� ������ 1, �ƴϸ� 0�� ��ȯ
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
	mpz_mod(plainText, plainText, n); // (a*b) mod c = (a mod c) * (b mod c) : mod�ϰ� ���ϸ� �ð��� �� ������
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