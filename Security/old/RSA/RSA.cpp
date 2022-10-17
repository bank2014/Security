#pragma warning(disable: 4996) // fopen deprecation ���� ����

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/applink.c> //applink�� ���ٴ� ������ �߻��Ͽ� �߰�. 
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
	unsigned char* plainText = (unsigned char*)"Hello RSA"; // ��ȣȭ�� ��
	unsigned char* cipherText, * originText;
	cipherText = (unsigned char*)calloc(1, MODULUS + EVP_MAX_BLOCK_LENGTH); 
	originText = (unsigned char*)calloc(1, MODULUS + EVP_MAX_BLOCK_LENGTH); 

	// https://www.openssl.org/docs/man1.1.0/man3/OpenSSL_add_all_algorithms.html
	// OpenSSL 3.0 �̻��� �������� ��� deprecated �����Ƿ� ����� �ʿ䰡 ����
	//OpenSSL_add_all_algorithms();			- ��� �˰��� ���
	//CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON); - �޸� ���� �˻� On
	
	//Ű ����
	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); //ctx ����
	EVP_PKEY_keygen_init(ctx); //ctx �ʱ�ȭ
	EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, MODULUS); //Ű ���� ����
	EVP_PKEY_keygen(ctx, &pkey); //Ű ����
	EVP_PKEY_CTX_free(ctx); //ctx ��ȯ

	//����Ű ����
	fopen_s(&privfp, privfn, "wb");
	PEM_write_PKCS8PrivateKey(privfp, pkey, NULL, NULL, 0, 0, NULL); // privateKey.pem �� ������ ����Ű�� �����Ѵ�
	fclose(privfp);

	//����Ű ����
	fopen_s(&pubfp, pubfn, "wb");
	PEM_write_PUBKEY(pubfp, pkey); // publicKey.pem�� ������ ����Ű�� ����
	fclose(pubfp);

	//����Ű �ε�
	fopen_s(&privfp, privfn, "rb");
	PEM_read_PrivateKey(privfp, &privkey, 0, NULL); //privateKey.pem���� ����Ű�� �ε��Ͽ� privkey�� ����
	fclose(privfp);

	//����Ű �ε�
	fopen_s(&pubfp, pubfn, "rb");
	PEM_read_PUBKEY(pubfp, &pubkey, 0, NULL); //publicKey.pem���� ����Ű�� �ε��Ͽ� pubkey�� ����
	fclose(pubfp);

	//��ȣȭ - ����Ű�� ��ȣȭ
	ctx = EVP_PKEY_CTX_new(pubkey, NULL); //ctx ���� �� ����Ű ����
	EVP_PKEY_encrypt_init(ctx); //ctx �ʱ�ȭ
	EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING); //�е� ����
	EVP_PKEY_encrypt(ctx, NULL, &outlen, plainText, MODULUS / 8); //buffer ���� ����
	EVP_PKEY_encrypt(ctx, cipherText, &outlen, plainText, MODULUS / 8); //RSA ��ȣȭ
	EVP_PKEY_CTX_free(ctx); //ctx ��ȯ

	//��ȣȭ - ����Ű�� ��ȣȭ
	ctx = EVP_PKEY_CTX_new(privkey, NULL); //ctx ���� �� ����Ű ����
	EVP_PKEY_decrypt_init(ctx); //ctx �ʱ�ȭ
	EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING); //�е� ����
	EVP_PKEY_decrypt(ctx, NULL, &outlen2, cipherText, outlen); //buffer ���� ����
	EVP_PKEY_decrypt(ctx, originText, &outlen2, cipherText, outlen); //RSA ��ȣȭ
	EVP_PKEY_CTX_free(ctx); //ctx ��ȯ

	//���ڿ��� ���
	printf("plain text: %s\n", plainText);	// ��
	printf("cipher text: %s\n", cipherText);// public key�� ��ȣȭ�� ��
	printf("origin text: %s\n", originText);// private key�� ��ȣȭ�� ��ȣ��

	getchar();
}