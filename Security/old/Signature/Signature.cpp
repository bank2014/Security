#pragma warning(disable: 4996)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/applink.c> // applink 가 없다는 오류가 발생하여 추가

#define MODULUS 512

int main(void) {
	EVP_PKEY_CTX* ctx;
	EVP_PKEY* pkey = NULL, * privkey = NULL, * pubkey = NULL;
	size_t outlen = 0, result = 0;
	FILE* privfp = NULL, * pubfp = NULL;	// 개인키 파일 포인터, 공개키 파일 포인터
	const char* privfn = "privateKey.pem";
	const char* pubfn = "publicKey.pem";
	unsigned char* plainText = (unsigned char*)"2019076021김선우";	// 평문
	unsigned char* signature;	// 서명
	signature = (unsigned char*)calloc(1, MODULUS + EVP_MAX_BLOCK_LENGTH); // 출력이 Modulus 보다 클 수도 있다. 
	
	// https://www.openssl.org/docs/man1.1.0/man3/OpenSSL_add_all_algorithms.html
	// OpenSSL 3.0 이상의 버전에서 모두 deprecated 됐으므로 사용할 필요가 없다
	//OpenSSL_add_all_algorithms();
	//CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
	
	//키 생성
	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); //ctx 생성 - public key 알고리즘 컨텍스트를 ctx에 할당
	EVP_PKEY_keygen_init(ctx); //ctx 초기화
	EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, MODULUS); //rsa의 키 길이를 512비트로 설정
	EVP_PKEY_keygen(ctx, &pkey); //키 생성
	EVP_PKEY_CTX_free(ctx); //ctx 할당 해제

	//개인키 저장
	fopen_s(&privfp, privfn, "wb"); // 개인키 파일 열기
	PEM_write_PKCS8PrivateKey(privfp, pkey, NULL, NULL, 0, 0, NULL); // PKCS #8 표준 구문에 따라 개인키 정보를 저장
	fclose(privfp);
	//공개키 저장
	fopen_s(&pubfp, pubfn, "wb"); // 공개키 파일 열기
	PEM_write_PUBKEY(pubfp, pkey); // 공개키 저장
	fclose(pubfp);
	//개인키 로드
	fopen_s(&privfp, privfn, "rb"); // 개인키 파일 read byte 모드로 파일 열기
	PEM_read_PrivateKey(privfp, &privkey, 0, NULL); // 캐인키를 읽어서 privkey에 저장
	fclose(privfp);
	//공개키 로드
	fopen_s(&pubfp, pubfn, "rb"); // 공개키 파일 read byte 모드로 열기
	PEM_read_PUBKEY(pubfp, &pubkey, 0, NULL); // 공개키를 읽어서 pubkey에 저장
	fclose(pubfp);

	//서명용 암호화 - 개인키로 암호화 및 해시 알고리즘 지정
	ctx = EVP_PKEY_CTX_new(privkey, NULL); //ctx 생성 및 키 설정 - 개인키 컨텍스트를 ctx에 할당
	EVP_PKEY_sign_init(ctx); //ctx를 서명으로 사용하게 끔 초기화
	EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING); //PKCS #1 모드로 패딩 설정. PKCS #1는 공개키 암호화 첫번째 표준 
	EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()); //sha256을 해시 알고리즘으로 설정
	EVP_PKEY_sign(ctx, NULL, &outlen, plainText, EVP_MD_size(EVP_sha256()));//buffer 길이 결정
	EVP_PKEY_sign(ctx, signature, &outlen, plainText, EVP_MD_size(EVP_sha256())); //RSA 암호화
	EVP_PKEY_CTX_free(ctx);

	//검증용 복호화 - 공개키로 복호화 및 해시 알고리즘 지정
	ctx = EVP_PKEY_CTX_new(pubkey, NULL); //ctx 생성 및 키 설정 - 공개키 컨텍스트를 ctx에 할당
	EVP_PKEY_verify_init(ctx); //ctx를 검증자로 초기화
	EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING); //PKCS #1 표준 모드로 rsa 패딩 설정
	EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()); //sha256 해시 알고리즘으로 설정
	result = EVP_PKEY_verify(ctx, signature, outlen, plainText, EVP_MD_size(EVP_sha256()));// 복호화하여 검증한다. 일치하면 1, 아니면 0 return
	EVP_PKEY_CTX_free(ctx);

	//문자열로 출력 - 가끔 cipher text가 출력되지 않으니 주의
	printf("plain text: %s\n", plainText); // 평문
	printf("signature: %s\n", signature);  // 서명
	printf("result: %d\n", result);		   // 일치하면 1 아니면 0 - 서명이 유효하면 일치하는 것

	//실패 검증용 복호화 - 의도적으로 평문 끝에 !을 붙인 string으로 검사
	plainText = (unsigned char*)"2019076021김선우!"; // 원래 평문과 다른 평문
	ctx = EVP_PKEY_CTX_new(pubkey, NULL); // ctx 생성 및 키 설정
	EVP_PKEY_verify_init(ctx); ///ctx를 검증자로 초기화
	EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING); // PKCS #1 표준 모드로 rsa 패딩 설정
	EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()); // sha256 해시 알고리즘으로 설정
	result = EVP_PKEY_verify(ctx, signature, outlen, plainText, EVP_MD_size(EVP_sha256())); // 복호화하여 검증한다. 일치하면 1, 아니면 0 return
	
	EVP_PKEY_CTX_free(ctx);
	
	printf("plain text: %s\n", plainText);	// 원래 평문과 다른 평문
	printf("result: %d\n", result);			// 평문과 다르므로 0을 return하게 된다
}