#pragma warning(disable: 4996)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/applink.c>

#define MODULUS 512

int main(void) {
	EVP_PKEY_CTX* ctx;
	EVP_PKEY* pkey = NULL, * privkey = NULL, * pubkey = NULL;
	size_t outlen = 0, result = 0;
	FILE* privfp = NULL, * pubfp = NULL;
	const char* privfn = "privateKey.pem";
	const char* pubfn = "publicKey.pem";
	unsigned char* plainText = (unsigned char*)"2019076021김선우";	// 평문
	unsigned char* signature;	// 서명
	signature = (unsigned char*)calloc(1, MODULUS + EVP_MAX_BLOCK_LENGTH); // 출력이 Modulus 보다 클 수도 있다. 
	
	// OpenSSL 3.0 이상 버전에서 모두 deprecated 
	//OpenSSL_add_all_algorithms();
	//CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
	
	//키 생성
	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); //ctx 생성
	EVP_PKEY_keygen_init(ctx); //ctx 초기화
	EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, MODULUS); //키 길이 설정
	EVP_PKEY_keygen(ctx, &pkey); //키 생성
	EVP_PKEY_CTX_free(ctx); //ctx 반환

	//개인키 저장
	fopen_s(&privfp, privfn, "wb");
	PEM_write_PKCS8PrivateKey(privfp, pkey, NULL, NULL, 0, 0, NULL);
	fclose(privfp);
	//공개키 저장
	fopen_s(&pubfp, pubfn, "wb");
	PEM_write_PUBKEY(pubfp, pkey);
	fclose(pubfp);
	//개인키 로드
	fopen_s(&privfp, privfn, "rb");
	PEM_read_PrivateKey(privfp, &privkey, 0, NULL);
	fclose(privfp);
	//공개키 로드
	fopen_s(&pubfp, pubfn, "rb");
	PEM_read_PUBKEY(pubfp, &pubkey, 0, NULL);
	fclose(pubfp);

	//서명용 암호화 - 개인키로 암호화 및 해시 알고리즘 지정
	ctx = EVP_PKEY_CTX_new(privkey, NULL); //ctx 생성 및 키 설정
	EVP_PKEY_sign_init(ctx); //ctx 초기화
	EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING); //패딩 설정
	EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()); //해시 알고리즘 설정
	EVP_PKEY_sign(ctx, NULL, &outlen, plainText, EVP_MD_size(EVP_sha256()));//buffer 길이 결정
	EVP_PKEY_sign(ctx, signature, &outlen, plainText, EVP_MD_size(EVP_sha256())); //RSA 암호화
	EVP_PKEY_CTX_free(ctx);
	//검증용 복호화 - 공개키로 복호화 및 해시 알고리즘 지정
	ctx = EVP_PKEY_CTX_new(pubkey, NULL); //ctx 생성 및 키 설정
	EVP_PKEY_verify_init(ctx); //ctx 초기화
	EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING); //패딩 설정

	EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()); //해시 알고리즘 설정
	result = EVP_PKEY_verify(ctx, signature, outlen, plainText, EVP_MD_size(EVP_sha256()));//RSA 복호화

	EVP_PKEY_CTX_free(ctx);

	//문자열로 출력 - 가끔 cipher text가 출력되지 않으니 주의
	printf("plain text: %s\n", plainText);
	printf("signature: %s\n", signature);
	printf("result: %d\n", result);

	//실패 검증용 복호화 - 의도적으로 평문 끝에 !을 붙인 string으로 검사
	plainText = (unsigned char*)"2019076021김선우!";
	ctx = EVP_PKEY_CTX_new(pubkey, NULL); // ctx 생성 및 키 설정
	EVP_PKEY_verify_init(ctx); // ctx 초기화
	EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING); // 패딩 설정
	EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()); // 해시 알고리즘 설정
	result = EVP_PKEY_verify(ctx, signature, outlen, plainText, EVP_MD_size(EVP_sha256())); // RSA 복호화
	
	EVP_PKEY_CTX_free(ctx);
	
	printf("plain text: %s\n", plainText);
	printf("result: %d\n", result);
}