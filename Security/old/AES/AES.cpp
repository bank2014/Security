#include <sys/timeb.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#define MAXBUFF 1024	// �õ������ ũ��

void getTimeSubstr(char buff[]);
void AES_encryption(const char* pfn, const char* cfn, unsigned char mykey[], unsigned char iv[]);
void AES_decryption(const char* cfn, const char* dfn, unsigned char mykey[], unsigned char iv[]);

int main(void)
{
	char seedbuff[MAXBUFF];
	unsigned char mykey[EVP_MAX_KEY_LENGTH] = "\0";
	unsigned char iv[EVP_MAX_IV_LENGTH] = "\0";

	getTimeSubstr(seedbuff);	// ���� �ð��� �������� �õ尪�� �ʱ�ȭ
	RAND_seed(seedbuff, 8);		// ���� �õ� �ʱ�ȭ - ���� �ڷᱸ���� �õ尪�� �����ϴµ� ���
	RAND_bytes(mykey, EVP_MAX_KEY_LENGTH);	// ������ EVP_MAX_KEY_LENGTH ũ���� Ű�� �ʱ�ȭ
	RAND_bytes(iv, EVP_MAX_IV_LENGTH);		// ������ EVP_MAX_IV_LENGTH ũ���� Inital vector�� �ʱ�ȭ

	printf("Start\n");
	AES_encryption("pt.txt", "cl.txt", mykey, iv);	// ��ȣȭ
	AES_decryption("cl.txt", "rec.txt", mykey, iv);	// ��ȣȭ
	printf("Finish\n");
	getchar();

	return 0;
}

// ���� �ð��� �������� �õ尪�� �����Ѵ�
void getTimeSubstr(char buff[])
{
	struct _timeb objTimeb;
	struct tm t;
	_ftime_s(&objTimeb);
	localtime_s(&t, &objTimeb.time);
	memcpy(buff, &(t.tm_sec), 4);
	memcpy(buff + 4, &(objTimeb.millitm), 4);
}

// pt.txt �� plain text�� ��ȣȭ�Ͽ� cl.txt�� write�Ѵ�
void AES_encryption(const char* pfn, const char* cfn, unsigned char mykey[], unsigned char iv[])
{
	FILE* ptf, * ctf;
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	int in_len, out_len = 0, ret;
	unsigned char ptext[MAXBUFF + 8];
	unsigned char ctext[MAXBUFF + 8];

	fopen_s(&ptf, pfn, "rb");	// pt.txt
	fopen_s(&ctf, cfn, "wb");	// cl.txt

	EVP_CIPHER_CTX_init(ctx);
	EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, mykey, iv, AES_ENCRYPT); // ��ȣȭ ����

	while ((in_len = fread(ptext, 1, MAXBUFF, ptf)) > 0)
	{
		ret = EVP_CipherUpdate(ctx, ctext, &out_len, ptext, in_len);
		fwrite(ctext, 1, out_len, ctf);
	}
	fclose(ptf);
	ret = EVP_CipherFinal_ex(ctx, ctext, &out_len);
	fwrite(ctext, 1, out_len, ctf);
	fclose(ctf);
	EVP_CIPHER_CTX_cleanup(ctx);
}

// cl.txt�� ��ȣ���� ��ȣȭ�Ͽ� rec.txt�� �����Ѵ�
void AES_decryption(const char* cfn, const char* dfn, unsigned char mykey[], unsigned char iv[])
{
	FILE* ctf, * dtf;
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	int in_len, out_len = 0, ret;
	unsigned char ctext[MAXBUFF + 8];
	unsigned char dtext[MAXBUFF + 16];

	fopen_s(&ctf, cfn, "rb");
	fopen_s(&dtf, dfn, "wb");

	//EVP_CIPHER_CTX_init(ctx);
	EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, mykey, iv, AES_DECRYPT); // ��ȣȭ ����

	while ((in_len = fread(ctext, 1, MAXBUFF, ctf)) > 0)
	{
		ret = EVP_CipherUpdate(ctx, dtext, &out_len, ctext, in_len);
		fwrite(dtext, 1, out_len, dtf);
	}
	fclose(ctf);
	ret = EVP_CipherFinal_ex(ctx, dtext, &out_len);
	fwrite(dtext, 1, out_len, dtf);
	fclose(dtf);
	EVP_CIPHER_CTX_cleanup(ctx);
}
