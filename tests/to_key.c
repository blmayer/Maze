/* Test file for to_key function */
#include <stdio.h>
#include <string.h>
#include <webng.h>

int main(void)
{
	char list[] = "2345 474 23 7569";

	short *keys = to_key(list);

	if(
		keys[0] == 2345 && 
		keys[1] == 474 &&
		keys[2] == 23 &&
		keys[3] == 7569
	)
	{
		return 0;
	}

	return 1;
}

