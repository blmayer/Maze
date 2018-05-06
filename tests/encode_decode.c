/* Test file for encode and decode functions */
#include <stdio.h>
#include <string.h>
#include <webng.h>

int main(void)
{
	unsigned char *cypher = "igi7R%^ERgoyt89t@#";
	unsigned char *test_str = "hello world";
	unsigned char *enc_str = encode(test_str, cypher);
	printf("Encoded string:\n%s\n", enc_str);

	unsigned char *orig_str = decode(enc_str, cypher);
	printf("Decoded string:\n%s\n", orig_str);

	if(strcmp(test_str, orig_str) == 0)
	{
		puts("Encode and decode successful!");
		return 0;
	}
	else
	{
		puts("Encode and decode failed!");
		return 1;
	}
}

