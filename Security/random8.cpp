#include <stdlib.h>
#include <openssl/rand.h>

int main()
{
	int len = 8;
	unsigned char* out = NULL;
	out = (unsigned char*)malloc(sizeof(unsigned char) * len);

	RAND_bytes(out, len);

	printf("Rand() is ...\n");
	for (int i = 0; i < len; i++)
	{
		printf("%d\n", out[i]);

	}
}