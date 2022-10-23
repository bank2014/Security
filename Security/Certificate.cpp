#pragma warning(disable: 4996)

#include <stdio.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/applink.c> //������ ȯ�濡�� �� ���� ������ ��Ÿ�� ���� �߻�

#define MODULUS 512		// RSA rootŰ ���� = 512��Ʈ

int main(void)
{
	// ���� ������ 
	EVP_PKEY_CTX* ctx;	// Ű ���� ������ �ʿ��� Ű�� ���ؽ�Ʈ
	EVP_PKEY* Root_pkey = NULL, * Root_privkey = NULL, * Root_pubkey = NULL; //rootŰ, ����Ű, ����Ű
	X509* root_x509;	// X509 ǥ���� ������ ��ü
	X509_NAME* name;	// �߱��� �ʵ� ��ü
	int serial = 0;		// �ø���ѹ�: �������� ������ȣ
	FILE* fp = NULL;	// ���� ���� �۾��� ���������� ���� ���� ������
	char Root_PrivKeyFileName[] = "Root_Private_Key.pem";	// ����Ű ���ϸ�
	char Root_PubKeyFileName[] = "Root_Public_Key.pem";		// ����Ű ���ϸ�
	char Root_certFileName[] = "Root_Cert.der";				// ������ ���ϸ�

	//OpenSSL_add_all_algorithms();			-- deprecated & �ʿ� ����
	//CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON); -- deprecated & �ʿ� ����

	// RSA rootŰ ����
	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);	// RSAŰ�� ctx(���ؽ�Ʈ) ����
	EVP_PKEY_keygen_init(ctx);						// EVP_PKEY_keygen�� RSA rootŰ�� �������� ���� ũ�⼳���� ���� ���ֱ� ���� ����
	EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, MODULUS); // RSA rootŰ�� ���̸� 512��Ʈ�� ����. (���� �������� ������ 2048��Ʈ)
	EVP_PKEY_keygen(ctx, &Root_pkey);				// 512��Ʈ�� RSA rootŰ�� �����Ͽ� Root_pkey�� ����
	EVP_PKEY_CTX_free(ctx);						

	// RSA ����Ű�� ����Ű�� ���Ͽ� ����
	fopen_s(&fp, Root_PrivKeyFileName, "wb");							// ����Ű ���� ����
	PEM_write_PKCS8PrivateKey(fp, Root_pkey, NULL, NULL, 0, 0, NULL);	// PKCS#8 PrivateKeyInfo ������ ����Ű�� ���Ͽ� ����(enc=NULL�̹Ƿ�)
	fclose(fp);
	fopen_s(&fp, Root_PubKeyFileName, "wb");							// ����Ű ���� ����
	PEM_write_PUBKEY(fp, Root_pkey);									// rootŰ(����Ű)�� ���Ͽ� ����
	fclose(fp);

	// RSA ����Ű & ����Ű�� ���Ͽ��� �о�� ������ ����
	fopen_s(&fp, Root_PrivKeyFileName, "rb");			// ����Ű ������ read-byte ���� ����
	PEM_read_PrivateKey(fp, &Root_privkey, 0, NULL);	// ����Ű�� Root_privkey�� �����Ѵ�
	fclose(fp);
	fopen_s(&fp, Root_PubKeyFileName, "rb");			// ����Ű ������ read-byte ���� ����
	PEM_read_PUBKEY(fp, &Root_pubkey, 0, NULL);			// ����Ű�� Root_pubkey�� �����Ѵ�
	fclose(fp);

	// ������ ���� �� ����
	root_x509 = X509_new();										// X.509 ǥ�� �������� ����
	X509_set_version(root_x509, X509_VERSION_3);				// ������ ������ ����. ���� ��ũ�ΰ� �־ �װɷ� �����ߴ�. X509_VERSION_3 = 2 �̴�
	ASN1_INTEGER_set(X509_get_serialNumber(root_x509), serial); // ASN1_INTEGER������ �ø���ѹ��� �������� �о�� long Ÿ������ serial�� ����
	X509_gmtime_adj(X509_get_notBefore(root_x509), 0);			// �������� notBefore �ʵ带 ����ð����� ����. = ��ȿ�Ⱓ ����
	X509_gmtime_adj(X509_get_notAfter(root_x509), (long)365 * 24 * 60 * 60); // notAfter�ʵ带 ����ð����κ��� 1�� �ڷ� ���� = ��ȿ�Ⱓ ����
	X509_set_pubkey(root_x509, Root_pubkey);					// Root_pubkey(����Ű)�� �������� ����Ű �ʵ忡 �ִ´�
	name = X509_get_subject_name(root_x509);					// ��ü(������) �ʵ带 ����Ű�� name �����͸� �ʱ�ȭ. 

	//X509_gmtime_adj(X509_get_notAfter(root_x509), (long)365 * 24 * 60 * 60);	-- �ݺ��ǹǷ� �ʿ������ �ּ�ó��
	//X509_set_pubkey(root_x509, Root_pubkey);	-- �ݺ��ǹǷ� �ʿ������ �ּ�ó��
	//name = X509_get_subject_name(root_x509);	-- �ݺ��ǹǷ� �ʿ������ �ּ�ó��

	// ��ü(Subject) �ʵ��� DName ���� (Relative Distinguished Names(RDNs) ����)
	// Ű-value�� ���� : RDNs�� ���� ���� �̸������� �������� �ʰ� Certificate Attributes filter���� Ư�� Ŭ���̾�Ʈ �׷� ��ü�� ������ ������ �� �ִ�
	// ���� ó�� X509_NAME_add_entry_by_txt�� �ִ� ������ �Ʒ��� ����
	X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)"KR", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, (unsigned char*)"Chungbuk", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC, (unsigned char*)"Cheongju", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)"Chungbuk National University", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, (unsigned char*)"Computer Engineering", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"2019076021 SunWoo Kim", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "emailAddress", MBSTRING_ASC, (unsigned char*)"bank2014@naver.com", -1, -1, 0);
	X509_set_issuer_name(root_x509, name);				// ������ = �߱��� �����ϰ� �����Ͽ� �ʵ忡 �ִ´�
	X509_sign(root_x509, Root_privkey, EVP_sha256());	// ����Ű�� �ؽø� ����� ����(Signature)�� �����ϰ� �������� �ִ´�
	fopen_s(&fp, Root_certFileName, "wb");	// ������ ���� ����
	PEM_write_X509(fp, root_x509);			// ���� x509(������)�� ���Ͽ� ����
	fclose(fp);
	X509_free(root_x509);
	EVP_PKEY_free(Root_pkey);
	EVP_PKEY_free(Root_privkey);
	EVP_PKEY_free(Root_pubkey);

	// �������� ���� ����
	root_x509 = X509_new();									// x509 �ʱ�ȭ
	fopen_s(&fp, Root_certFileName, "rb");					// ������ ������ read-byte���� ����
	PEM_read_X509_AUX(fp, &root_x509, NULL, NULL);			// ������ �о�� root_x509�� ����. pem_password�� ���� ��ȣȭ���� �ʾ����Ƿ� pem_password = null
	fclose(fp);
	Root_pubkey = EVP_PKEY_new();							// ����Ű �ʱ�ȭ
	Root_pubkey = X509_get_pubkey(root_x509);				// ���������� ����Ű�� ���´�
	printf("%d\n", X509_verify(root_x509, Root_pubkey));	// �������� ������ ����Ű�� �����Ѵ�. ��ȿ�ϸ� 1, �ƴϸ� 0�� ���
	X509_free(root_x509);
	EVP_PKEY_free(Root_pubkey);
}