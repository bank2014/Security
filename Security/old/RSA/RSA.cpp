#pragma warning(disable: 4996) // fopen deprecation 오류 무시

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/applink.c> //applink가 없다는 오류가 발생하여 추가. 
#include <openssl/evp.h>
#include <openssl/pem.h>

#define MODULUS 512

int main(void) {
	EVP_PKEY_CTX* ctx;
	EVP_PKEY* pkey = NULL, * privkey = NULL, * pubkey = NULL;
	size_t outlen = 0, outlen2 = 0;
	FILE* privfp = NULL, * pubfp = NULL;
	const char* privfn = "privateKey.pem";
	const char* pubfn = "publicKey.pem";
	unsigned char* plainText = (unsigned char*)"Hello RSA"; // 암호화할 평문
	unsigned char* cipherText, * originText;
	cipherText = (unsigned char*)calloc(1, MODULUS + EVP_MAX_BLOCK_LENGTH); 
	originText = (unsigned char*)calloc(1, MODULUS + EVP_MAX_BLOCK_LENGTH); 

	// https://www.openssl.org/docs/man1.1.0/man3/OpenSSL_add_all_algorithms.html
	// OpenSSL 3.0 이상의 버전에서 모두 deprecated 됐으므로 사용할 필요가 없다
	//OpenSSL_add_all_algorithms();			- 모든 알고리즘 사용
	//CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON); - 메모리 누수 검사 On
	
	//키 생성
	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); //ctx 생성
	EVP_PKEY_keygen_init(ctx); //ctx 초기화
	EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, MODULUS); //키 길이 설정
	EVP_PKEY_keygen(ctx, &pkey); //키 생성
	EVP_PKEY_CTX_free(ctx); //ctx 반환

	//개인키 저장
	fopen_s(&privfp, privfn, "wb");
	PEM_write_PKCS8PrivateKey(privfp, pkey, NULL, NULL, 0, 0, NULL); // privateKey.pem 에 생성한 개인키를 저장한다
	fclose(privfp);

	//공개키 저장
	fopen_s(&pubfp, pubfn, "wb");
	PEM_write_PUBKEY(pubfp, pkey); // publicKey.pem에 생성한 공개키를 저장
	fclose(pubfp);

	//개인키 로드
	fopen_s(&privfp, privfn, "rb");
	PEM_read_PrivateKey(privfp, &privkey, 0, NULL); //privateKey.pem에서 개인키를 로드하여 privkey에 저장
	fclose(privfp);

	//공개키 로드
	fopen_s(&pubfp, pubfn, "rb");
	PEM_read_PUBKEY(pubfp, &pubkey, 0, NULL); //publicKey.pem에서 개인키를 로드하여 pubkey에 저장
	fclose(pubfp);

	//암호화 - 공개키로 암호화
	ctx = EVP_PKEY_CTX_new(pubkey, NULL); //ctx 생성 및 공개키 설정
	EVP_PKEY_encrypt_init(ctx); //ctx 초기화
	EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING); //패딩 설정
	EVP_PKEY_encrypt(ctx, NULL, &outlen, plainText, MODULUS / 8); //buffer 길이 결정
	EVP_PKEY_encrypt(ctx, cipherText, &outlen, plainText, MODULUS / 8); //RSA 암호화
	EVP_PKEY_CTX_free(ctx); //ctx 반환

	//복호화 - 개인키로 복호화
	ctx = EVP_PKEY_CTX_new(privkey, NULL); //ctx 생성 및 개인키 설정
	EVP_PKEY_decrypt_init(ctx); //ctx 초기화
	EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING); //패딩 설정
	EVP_PKEY_decrypt(ctx, NULL, &outlen2, cipherText, outlen); //buffer 길이 결정
	EVP_PKEY_decrypt(ctx, originText, &outlen2, cipherText, outlen); //RSA 복호화
	EVP_PKEY_CTX_free(ctx); //ctx 반환

	//문자열로 출력
	printf("plain text: %s\n", plainText);	// 평문
	printf("cipher text: %s\n", cipherText);// public key로 암호화된 평문
	printf("origin text: %s\n", originText);// private key로 복호화된 암호문

	getchar();
}