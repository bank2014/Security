#pragma warning(disable: 4996)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/applink.c> // applink �� ���ٴ� ������ �߻��Ͽ� �߰�

#define MODULUS 512

int main(void) {
	EVP_PKEY_CTX* ctx;
	EVP_PKEY* pkey = NULL, * privkey = NULL, * pubkey = NULL;
	size_t outlen = 0, result = 0;
	FILE* privfp = NULL, * pubfp = NULL;	// ����Ű ���� ������, ����Ű ���� ������
	const char* privfn = "privateKey.pem";
	const char* pubfn = "publicKey.pem";
	unsigned char* plainText = (unsigned char*)"2019076021�輱��";	// ��
	unsigned char* signature;	// ����
	signature = (unsigned char*)calloc(1, MODULUS + EVP_MAX_BLOCK_LENGTH); // ����� Modulus ���� Ŭ ���� �ִ�. 
	
	// https://www.openssl.org/docs/man1.1.0/man3/OpenSSL_add_all_algorithms.html
	// OpenSSL 3.0 �̻��� �������� ��� deprecated �����Ƿ� ����� �ʿ䰡 ����
	//OpenSSL_add_all_algorithms();
	//CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
	
	//Ű ����
	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); //ctx ���� - public key �˰��� ���ؽ�Ʈ�� ctx�� �Ҵ�
	EVP_PKEY_keygen_init(ctx); //ctx �ʱ�ȭ
	EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, MODULUS); //rsa�� Ű ���̸� 512��Ʈ�� ����
	EVP_PKEY_keygen(ctx, &pkey); //Ű ����
	EVP_PKEY_CTX_free(ctx); //ctx �Ҵ� ����

	//����Ű ����
	fopen_s(&privfp, privfn, "wb"); // ����Ű ���� ����
	PEM_write_PKCS8PrivateKey(privfp, pkey, NULL, NULL, 0, 0, NULL); // PKCS #8 ǥ�� ������ ���� ����Ű ������ ����
	fclose(privfp);
	//����Ű ����
	fopen_s(&pubfp, pubfn, "wb"); // ����Ű ���� ����
	PEM_write_PUBKEY(pubfp, pkey); // ����Ű ����
	fclose(pubfp);
	//����Ű �ε�
	fopen_s(&privfp, privfn, "rb"); // ����Ű ���� read byte ���� ���� ����
	PEM_read_PrivateKey(privfp, &privkey, 0, NULL); // ĳ��Ű�� �о privkey�� ����
	fclose(privfp);
	//����Ű �ε�
	fopen_s(&pubfp, pubfn, "rb"); // ����Ű ���� read byte ���� ����
	PEM_read_PUBKEY(pubfp, &pubkey, 0, NULL); // ����Ű�� �о pubkey�� ����
	fclose(pubfp);

	//����� ��ȣȭ - ����Ű�� ��ȣȭ �� �ؽ� �˰��� ����
	ctx = EVP_PKEY_CTX_new(privkey, NULL); //ctx ���� �� Ű ���� - ����Ű ���ؽ�Ʈ�� ctx�� �Ҵ�
	EVP_PKEY_sign_init(ctx); //ctx�� �������� ����ϰ� �� �ʱ�ȭ
	EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING); //PKCS #1 ���� �е� ����. PKCS #1�� ����Ű ��ȣȭ ù��° ǥ�� 
	EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()); //sha256�� �ؽ� �˰������� ����
	EVP_PKEY_sign(ctx, NULL, &outlen, plainText, EVP_MD_size(EVP_sha256()));//buffer ���� ����
	EVP_PKEY_sign(ctx, signature, &outlen, plainText, EVP_MD_size(EVP_sha256())); //RSA ��ȣȭ
	EVP_PKEY_CTX_free(ctx);

	//������ ��ȣȭ - ����Ű�� ��ȣȭ �� �ؽ� �˰��� ����
	ctx = EVP_PKEY_CTX_new(pubkey, NULL); //ctx ���� �� Ű ���� - ����Ű ���ؽ�Ʈ�� ctx�� �Ҵ�
	EVP_PKEY_verify_init(ctx); //ctx�� �����ڷ� �ʱ�ȭ
	EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING); //PKCS #1 ǥ�� ���� rsa �е� ����
	EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()); //sha256 �ؽ� �˰������� ����
	result = EVP_PKEY_verify(ctx, signature, outlen, plainText, EVP_MD_size(EVP_sha256()));// ��ȣȭ�Ͽ� �����Ѵ�. ��ġ�ϸ� 1, �ƴϸ� 0 return
	EVP_PKEY_CTX_free(ctx);

	//���ڿ��� ��� - ���� cipher text�� ��µ��� ������ ����
	printf("plain text: %s\n", plainText); // ��
	printf("signature: %s\n", signature);  // ����
	printf("result: %d\n", result);		   // ��ġ�ϸ� 1 �ƴϸ� 0 - ������ ��ȿ�ϸ� ��ġ�ϴ� ��

	//���� ������ ��ȣȭ - �ǵ������� �� ���� !�� ���� string���� �˻�
	plainText = (unsigned char*)"2019076021�輱��!"; // ���� �򹮰� �ٸ� ��
	ctx = EVP_PKEY_CTX_new(pubkey, NULL); // ctx ���� �� Ű ����
	EVP_PKEY_verify_init(ctx); ///ctx�� �����ڷ� �ʱ�ȭ
	EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING); // PKCS #1 ǥ�� ���� rsa �е� ����
	EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()); // sha256 �ؽ� �˰������� ����
	result = EVP_PKEY_verify(ctx, signature, outlen, plainText, EVP_MD_size(EVP_sha256())); // ��ȣȭ�Ͽ� �����Ѵ�. ��ġ�ϸ� 1, �ƴϸ� 0 return
	
	EVP_PKEY_CTX_free(ctx);
	
	printf("plain text: %s\n", plainText);	// ���� �򹮰� �ٸ� ��
	printf("result: %d\n", result);			// �򹮰� �ٸ��Ƿ� 0�� return�ϰ� �ȴ�
}