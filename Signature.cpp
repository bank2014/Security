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
	unsigned char* plainText = (unsigned char*)"2019076021�輱��";	// ��
	unsigned char* signature;	// ����
	signature = (unsigned char*)calloc(1, MODULUS + EVP_MAX_BLOCK_LENGTH); // ����� Modulus ���� Ŭ ���� �ִ�. 
	
	// OpenSSL 3.0 �̻� �������� ��� deprecated 
	//OpenSSL_add_all_algorithms();
	//CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
	
	//Ű ����
	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); //ctx ����
	EVP_PKEY_keygen_init(ctx); //ctx �ʱ�ȭ
	EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, MODULUS); //Ű ���� ����
	EVP_PKEY_keygen(ctx, &pkey); //Ű ����
	EVP_PKEY_CTX_free(ctx); //ctx ��ȯ

	//����Ű ����
	fopen_s(&privfp, privfn, "wb");
	PEM_write_PKCS8PrivateKey(privfp, pkey, NULL, NULL, 0, 0, NULL);
	fclose(privfp);
	//����Ű ����
	fopen_s(&pubfp, pubfn, "wb");
	PEM_write_PUBKEY(pubfp, pkey);
	fclose(pubfp);
	//����Ű �ε�
	fopen_s(&privfp, privfn, "rb");
	PEM_read_PrivateKey(privfp, &privkey, 0, NULL);
	fclose(privfp);
	//����Ű �ε�
	fopen_s(&pubfp, pubfn, "rb");
	PEM_read_PUBKEY(pubfp, &pubkey, 0, NULL);
	fclose(pubfp);

	//����� ��ȣȭ - ����Ű�� ��ȣȭ �� �ؽ� �˰��� ����
	ctx = EVP_PKEY_CTX_new(privkey, NULL); //ctx ���� �� Ű ����
	EVP_PKEY_sign_init(ctx); //ctx �ʱ�ȭ
	EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING); //�е� ����
	EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()); //�ؽ� �˰��� ����
	EVP_PKEY_sign(ctx, NULL, &outlen, plainText, EVP_MD_size(EVP_sha256()));//buffer ���� ����
	EVP_PKEY_sign(ctx, signature, &outlen, plainText, EVP_MD_size(EVP_sha256())); //RSA ��ȣȭ
	EVP_PKEY_CTX_free(ctx);
	//������ ��ȣȭ - ����Ű�� ��ȣȭ �� �ؽ� �˰��� ����
	ctx = EVP_PKEY_CTX_new(pubkey, NULL); //ctx ���� �� Ű ����
	EVP_PKEY_verify_init(ctx); //ctx �ʱ�ȭ
	EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING); //�е� ����

	EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()); //�ؽ� �˰��� ����
	result = EVP_PKEY_verify(ctx, signature, outlen, plainText, EVP_MD_size(EVP_sha256()));//RSA ��ȣȭ

	EVP_PKEY_CTX_free(ctx);

	//���ڿ��� ��� - ���� cipher text�� ��µ��� ������ ����
	printf("plain text: %s\n", plainText);
	printf("signature: %s\n", signature);
	printf("result: %d\n", result);

	//���� ������ ��ȣȭ - �ǵ������� �� ���� !�� ���� string���� �˻�
	plainText = (unsigned char*)"2019076021�輱��!";
	ctx = EVP_PKEY_CTX_new(pubkey, NULL); // ctx ���� �� Ű ����
	EVP_PKEY_verify_init(ctx); // ctx �ʱ�ȭ
	EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING); // �е� ����
	EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()); // �ؽ� �˰��� ����
	result = EVP_PKEY_verify(ctx, signature, outlen, plainText, EVP_MD_size(EVP_sha256())); // RSA ��ȣȭ
	
	EVP_PKEY_CTX_free(ctx);
	
	printf("plain text: %s\n", plainText);
	printf("result: %d\n", result);
}