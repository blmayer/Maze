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
	/* Get random numbers from computer */
	FILE *source = fopen("/dev/urandom", "r");
	
	/* Loop generating numbers less than 1928 */
	short i = 0;
	short val = 0;

	while(i < 256)
	{
		fread(&val, 2, 1, source);
		if(val > 1927 || val < 36)
		{
			val = 0;
			continue;
		}
		printf("%d ", val);
		val = 0;
		i++;
	}
	
	/* Close our source */
	fclose(source);
	
	return 0;
}

