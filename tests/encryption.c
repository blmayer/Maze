/* Test file for our cryptographic function */
#include <stdio.h>
#include <string.h>
#include <webng.h>

int main(void)
{
	char message[] = "this will be a really fucking good good encoded string.";
	int mess_len = strlen(message);
	char encoded[mess_len + 1];
	int letters[128] = {0};
	int sum = 0;
	int letter = 0;

	while(letter < mess_len)
	{
		letters[message[letter]]++;
		sum += letter + message[letter];
		letter++; 
	}
	letter = 0;

	while(letter < mess_len)
	{
		encoded[letter] = (message[letter] + sum*letters[message[letter]]) % 95 + 33;
		letter++;
	}


	encoded[mess_len] = 0;
	printf("encoded message is:\n'%s'\nsum: %d\n", encoded, sum);

	strcpy(message, "this will be a reallf fucking good good encoded string.");
	letter = 0;
	bzero(letters, 512);
	sum = 0;

	while(letter < mess_len)
	{
		letters[message[letter]]++;
		sum += letter + message[letter];
		letter++; 
	}
	letter = 0;

	while(letter < mess_len)
	{
		encoded[letter] = (message[letter] + sum*letters[message[letter]]) % 95 + 33;
		letter++;
	}

	encoded[mess_len] = 0;
	printf("encoded message is:\n'%s'\n", encoded);
	return 0;
}

