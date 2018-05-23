/* Test file for our cryptographic function */
#include <stdio.h>
#include <string.h>
#include <webng.h>

int main(void)
{
	char message[] = "this will be a good encoded string.";
	int mess_len = strlen(message);
	char encoded[mess_len + 1];
	int letters[128] = {0};
	int sum = 0;
	int letter = 0;
	printf("string has length: %d\n", mess_len);

	while(letter < mess_len)
	{
		letters[message[letter]]++;
		sum += letter + message[letter];
		letter++; 
	}
	while(letter > 0)
	{
		letter--;
		encoded[letter] = (message[letter] + sum*letters[message[letter]]) % 95 + 33;
	}
	encoded[mess_len] = 0;
	printf("\n'%s'\n", encoded);

	bzero(letters, 512);
	letter = 0;
	while(letter < mess_len)
	{
		letters[encoded[letter]]++;
		sum += letter + encoded[letter];
		letter++; 
	}
	while(letter > 0)
	{
		letter--;
		message[letter] = (sum*letters[encoded[letter]] - encoded[letter]) % 95 + 33;
	}

	message[mess_len] = 0;
	printf("'%s'\n", message);
	return 0;
}

