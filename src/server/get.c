/*
 * ****************************************************************************
 *
 * AUTHOR:	Brian Mayer blmayer@icloud.com
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

#include "get.h"
#include "login.h"

int serve_get(unsigned int conn, struct response res){

	/* If the user sends the token respond with the correct page */
	if(res.auth != NULL){
		/* Check authorization cases */
		res.status = authorization(res.auth);
	}

	/* ---- Update path with the web pages directory ------------------- */

 	/* If / was passed, redirect to index page */
 	if(strncmp(res.path, "/", 1) == 0){
		strtok(res.path, "/");
		unsigned char *temp = strtok(NULL, "/");
		if(temp == NULL){
			res.path = "index.html";
		} else {
			res.path = temp;
		}
 	}

	/* Choose page based on the status */
	switch(res.status){
	case 200:
		break;
	case 401:
		res.path = "401.html";
		break;
	case 403:
		res.path = "403.html";
		break;
	case 500:
		res.path = "500.html";
		break;
	case 501:
		res.path = "501.html";
	}

prepend:
	/* Prepend webpages path to the path */
	puts("Prepending PATH.");
	unsigned char prep[strlen(res.path) + strlen(PATH) + 1];
	sprintf(prep, "%s%s", PATH, res.path);
	res.path = prep;

	/* Read file and create response ----------------------------------- */

	/* Open the file for reading */
	FILE *page_file = fopen(res.path, "rb");

	if(page_file == NULL){
		/* Something went wrong, probably file was not found */
		puts("Page not found, redirecting...");
		res.status = 404;
		
		/* Changing to 404 page */
		res.path = "404.html";
		goto prepend;
	} else {
		/* File found */
		res.status = 200;
	}
	
	fseek(page_file, 0, SEEK_END);		/* Seek to the end */
	int page_size = ftell(page_file);	/* This position's the size */
	rewind(page_file);			/* Go back to the start */

	/* Read it all in one operation and close */
	unsigned char buff[page_size + 1];
	fread(buff, page_size, sizeof(unsigned char), page_file);
	fclose(page_file);			/* Close the file */
	buff[page_size] = 0;			/* Add the terminating zero */
	res.body = strdup(buff);

	/* ---- Header creation part --------------------------------------- */

	/* Verify the connection and request version */
	if(res.conn != NULL){
		res.conn = "Keep-Alive";
	}

	res.ctype = mime_type(res.path);	/* Update the content type */
	res.clen = page_size;			/* And the content length */
	res.date = date_line();			/* Put the date line */

	/* Create the head */
	unsigned char *response = create_res_header(res);

	write(conn, response, strlen(response));	/* Send response */
	write(conn, res.body, res.clen);		/* Now the body */
	
	printf("\tFile %s served.\n", res.path);
	
	return 0;
}

