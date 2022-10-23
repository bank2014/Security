#pragma warning(disable: 4996)

#include <stdio.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/applink.c> //윈도우 환경에서 이 것이 없으면 런타임 오류 발생

#define MODULUS 512		// RSA root키 길이 = 512비트

int main(void)
{
	// 사용될 데이터 
	EVP_PKEY_CTX* ctx;	// 키 생성 과정에 필요한 키의 컨텍스트
	EVP_PKEY* Root_pkey = NULL, * Root_privkey = NULL, * Root_pubkey = NULL; //root키, 개인키, 공개키
	X509* root_x509;	// X509 표준의 인증서 객체
	X509_NAME* name;	// 발급자 필드 객체
	int serial = 0;		// 시리얼넘버: 인증서의 고유번호
	FILE* fp = NULL;	// 파일 관련 작업에 범용적으로 쓰는 파일 포인터
	char Root_PrivKeyFileName[] = "Root_Private_Key.pem";	// 개인키 파일명
	char Root_PubKeyFileName[] = "Root_Public_Key.pem";		// 공개키 파일명
	char Root_certFileName[] = "Root_Cert.der";				// 인증서 파일명

	//OpenSSL_add_all_algorithms();			-- deprecated & 필요 없음
	//CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON); -- deprecated & 필요 없음

	// RSA root키 생성
	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);	// RSA키의 ctx(컨텍스트) 생성
	EVP_PKEY_keygen_init(ctx);						// EVP_PKEY_keygen로 RSA root키를 생성하지 전에 크기설정을 따로 해주기 위해 선언
	EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, MODULUS); // RSA root키의 길이를 512비트로 설정. (따로 설정하지 않으면 2048비트)
	EVP_PKEY_keygen(ctx, &Root_pkey);				// 512비트의 RSA root키를 생성하여 Root_pkey에 저장
	EVP_PKEY_CTX_free(ctx);						

	// RSA 공개키와 개인키를 파일에 저장
	fopen_s(&fp, Root_PrivKeyFileName, "wb");							// 개인키 파일 생성
	PEM_write_PKCS8PrivateKey(fp, Root_pkey, NULL, NULL, 0, 0, NULL);	// PKCS#8 PrivateKeyInfo 구조로 개인키를 파일에 저장(enc=NULL이므로)
	fclose(fp);
	fopen_s(&fp, Root_PubKeyFileName, "wb");							// 공개키 파일 생성
	PEM_write_PUBKEY(fp, Root_pkey);									// root키(공개키)를 파일에 저장
	fclose(fp);

	// RSA 공개키 & 개인키를 파일에서 읽어와 변수에 저장
	fopen_s(&fp, Root_PrivKeyFileName, "rb");			// 개인키 파일을 read-byte 모드로 연다
	PEM_read_PrivateKey(fp, &Root_privkey, 0, NULL);	// 개인키를 Root_privkey에 저장한다
	fclose(fp);
	fopen_s(&fp, Root_PubKeyFileName, "rb");			// 공개키 파일을 read-byte 모드로 연다
	PEM_read_PUBKEY(fp, &Root_pubkey, 0, NULL);			// 공개키를 Root_pubkey에 저장한다
	fclose(fp);

	// 인증서 생성 및 설정
	root_x509 = X509_new();										// X.509 표준 인증서를 생성
	X509_set_version(root_x509, X509_VERSION_3);				// 인증서 버전을 설정. 전용 매크로가 있어서 그걸로 수정했다. X509_VERSION_3 = 2 이다
	ASN1_INTEGER_set(X509_get_serialNumber(root_x509), serial); // ASN1_INTEGER형태의 시리얼넘버를 인증서로 읽어와 long 타입으로 serial에 저장
	X509_gmtime_adj(X509_get_notBefore(root_x509), 0);			// 인증서의 notBefore 필드를 현재시간으로 설정. = 유효기간 시작
	X509_gmtime_adj(X509_get_notAfter(root_x509), (long)365 * 24 * 60 * 60); // notAfter필드를 현재시간으로부터 1년 뒤로 설정 = 유효기간 만료
	X509_set_pubkey(root_x509, Root_pubkey);					// Root_pubkey(공개키)를 인증서의 공개키 필드에 넣는다
	name = X509_get_subject_name(root_x509);					// 주체(발행자) 필드를 가르키는 name 포인터를 초기화. 

	//X509_gmtime_adj(X509_get_notAfter(root_x509), (long)365 * 24 * 60 * 60);	-- 반복되므로 필요없으니 주석처리
	//X509_set_pubkey(root_x509, Root_pubkey);	-- 반복되므로 필요없으니 주석처리
	//name = X509_get_subject_name(root_x509);	-- 반복되므로 필요없으니 주석처리

	// 주체(Subject) 필드의 DName 설정 (Relative Distinguished Names(RDNs) 설정)
	// 키-value인 이유 : RDNs을 통해 개인 이름만으로 구분하지 않고 Certificate Attributes filter으로 특정 클라이언트 그룹 전체의 접근을 승인할 수 있다
	// 스택 처럼 X509_NAME_add_entry_by_txt로 넣는 순으로 아래로 간다
	X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)"KR", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, (unsigned char*)"Chungbuk", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC, (unsigned char*)"Cheongju", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)"Chungbuk National University", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, (unsigned char*)"Computer Engineering", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"2019076021 SunWoo Kim", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "emailAddress", MBSTRING_ASC, (unsigned char*)"bank2014@naver.com", -1, -1, 0);
	X509_set_issuer_name(root_x509, name);				// 발행자 = 발급자 동일하게 설정하여 필드에 넣는다
	X509_sign(root_x509, Root_privkey, EVP_sha256());	// 개인키와 해시를 사용해 서명(Signature)을 설정하고 인증서에 넣는다
	fopen_s(&fp, Root_certFileName, "wb");	// 인증서 파일 생성
	PEM_write_X509(fp, root_x509);			// 위의 x509(인증서)을 파일에 저장
	fclose(fp);
	X509_free(root_x509);
	EVP_PKEY_free(Root_pkey);
	EVP_PKEY_free(Root_privkey);
	EVP_PKEY_free(Root_pubkey);

	// 인증서의 서명 검증
	root_x509 = X509_new();									// x509 초기화
	fopen_s(&fp, Root_certFileName, "rb");					// 인증서 파일을 read-byte모드로 연다
	PEM_read_X509_AUX(fp, &root_x509, NULL, NULL);			// 파일을 읽어와 root_x509에 저장. pem_password로 따로 암호화하지 않았으므로 pem_password = null
	fclose(fp);
	Root_pubkey = EVP_PKEY_new();							// 공개키 초기화
	Root_pubkey = X509_get_pubkey(root_x509);				// 인증서에서 공개키를 얻어온다
	printf("%d\n", X509_verify(root_x509, Root_pubkey));	// 인증서의 서명을 공개키로 검증한다. 유효하면 1, 아니면 0을 출력
	X509_free(root_x509);
	EVP_PKEY_free(Root_pubkey);
}