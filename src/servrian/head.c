/*
 * ****************************************************************************
 *
 * FUNCTION:	serve_head: This is the function that elaborates the header of
 *		a response, it takes two arguments: the client's connection
 *		and the file requested in the HEAD message.
 *
 * AUTHOR:	  	Brian Mayer	blmayer@icloud.com
 *
 * Copyright (C) 2018	Brian Lee Mayer
 *
 * ****************************************************************************
 */

#include "head.h"

int serve_head(unsigned int conn, struct response res) {
	
	/* Create the status variable */
	int *status;
	
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

