/*
 * ****************************************************************************
 *
 * AUTHOR:	Brian Mayer blmayer@icloud.com
 *
 * Copyright (C) 2018	Brian Lee Mayer
 *
 * ****************************************************************************
 */

#include "get.h"
#include "login.h"

int serve_get(unsigned int conn, struct response res)
{
	/* If the user sends the token respond with the correct page */
	if(res.auth != NULL)
	{
		/* Check authorization cases */
		res.status = authorization(res.auth);
	}

	/* ---- Update path with the web pages directory ------------------- */

 	/* If / was passed, redirect to index page */
 	if(strncmp(res.path, "/", 1) == 0 && strlen(res.path) > 1)
	{
		res.path = strtok(res.path, "/");
	}
	else
	{
		res.path = "index.html";
 	}

	/* Choose page based on the status */
	switch(res.status)
	{
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
		break;
	default:
		res.status = 200;
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
	if(res.conn == NULL && res.vers > 1)
	{
		res.conn = "Keep-Alive";
	}

	res.ctype = mime_type(res.path);	/* Update the content type */
	res.clen = page_size;			/* And the content length */
	res.date = date_line();			/* Put the date line */

	/* Create the head */
	unsigned char *response = create_res_header(res);
	write(conn, response, strlen(response));	/* Send response */
	if(res.key != NULL)
	{
		/* Send an encrypted body */
		write(conn, encode(res.body, res.key), res.clen);
	}
	else
	{
		write(conn, res.body, res.clen);
	}

	printf("\tFile %s served.\n", res.path);
	
	return 0;
}

