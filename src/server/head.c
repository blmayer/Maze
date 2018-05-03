/*
 * ****************************************************************************
 *
 * FUNCTION:	serve_head: This is the function that elaborates the header of
 *			  	a response, it takes two arguments: the client's connection
 *			  	and the file requested in the HEAD message.
 *
 * AUTHOR:	  	Brian Mayer	blmayer@icloud.com
 *
 * Copyright (C) 2018	Brian Lee Mayer
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

#include "headfn.h"

int serve_head(unsigned int conn, struct response res) {
	
	/* Create the status variable */
	int *status = 200;
	
	/* Get the page file's size */
	int *page_size = 0;
	*page_size = file_size(res.path);
	
	if(page_size > 0) {
		/* Something went wrong, problablay file was not found */
		*status = 404;
		*page_size = file_size("webpages/404.html");
	} else {
		*status = 200;
	}
	
	/* Create the head */
	unsigned char *head = create_res_header(res);
	
	/* Send the head */
	write(conn, head, strlen(head));
	
	printf("\tHead for %s served.\n", res.path);
	
	return 0;
}

