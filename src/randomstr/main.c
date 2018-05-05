/*
 * ****************************************************************************
 *
 * PROJECT:     Randomator: Pseudo random string generator and builder for 
 *				Servrian and Maze.
 *
 * AUTHOR:      Brian Mayer blmayer@icloud.com
 *
 * Copyright (C) 2018    Brian Lee Mayer
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * ****************************************************************************
 */

#include <stdio.h>

int main(void){

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
	while(i < 512){
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

