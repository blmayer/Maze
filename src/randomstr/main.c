/*
 * ****************************************************************************
 *
 * PROJECT:     randomstr: Pseudo random string generator and builder for 
 *			Servrian and Maze.
 *
 * AUTHOR:      Brian Mayer blmayer@icloud.com
 *
 * Copyright (C) 2018    Brian Mayer
 *
 * ****************************************************************************
 */

#include <stdio.h>

int main(void)
{
	/* These are the possible characters in our key */
	char charset[77] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJK0123456789"
			   ",./<>?`~[]{}|;:!@#$%^&*()-=_+";
	
	/* Get random numbers from computer */
	FILE *source = fopen("/dev/urandom", "r");
	
	/* The key */
	char key[513];
	
	/* Loop generating numbers and select from charset */
	int i = 0;
	unsigned int val;
	while(i < 512)
	{
		fread(&val, 1, 1, source); 	/* Only one byte is enough */
		key[i] = charset[val % 76];
		i++;
	}
	
	/* Close our source */
	fclose(source);
	
	/* Add terminating zero */
	key[512] = 0;
	
	/* Print key to screen */
	puts(key);

	return 0;
}

