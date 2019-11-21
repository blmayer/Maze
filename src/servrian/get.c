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

short serve_get(short conn, struct response res)
{
	/* ---- Status checking -------------------------------------------- */

	/* If the user sends the token respond with the correct page */
	// if(res.auth != NULL) {
	// 	/* Check authorization cases */
	// 	res.status = authorization(res.auth);
	// }

	/* Choose page based on the status */
	switch (res.status) {
	case 400:
		res.path = "400.html";
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
		break;
	default:
		res.status = 200;
	}

	/* ---- Update path with the web pages directory ------------------- */

	/* If / was passed, redirect to index page */
	if (strlen(res.path) == 1) {
		res.path = "index.html";
	} else if (strncmp(res.path, "/", 1) == 0) {
		res.path++;
	}

prepend:
	/* Prepend webpages path to the path */
	puts("\tAdjusting path.");
	char prep[strlen(res.path) + strlen(PATH) + 1];
	sprintf(prep, "%s%s", PATH, res.path);
	res.path = prep;

	/* Read file and create response ----------------------------------- */

	/* Open the file for reading */
	FILE *page_file = fopen(res.path, "rb");

	if (page_file == NULL) {
		/* Something went wrong, probably file was not found */
		puts("\tPage not found, redirecting...");
		res.status = 404;
		res.path = "404.html";
		goto prepend;
	}

	fseek(page_file, 0, SEEK_END); /* Seek to the end */
	res.clen = ftell(page_file);   /* This position's the size */
	rewind(page_file);	     /* Go back to the start */

	/* Read it all in one operation and close */
	char buff[res.clen + 1];
	fread(buff, res.clen, sizeof(char), page_file);
	fclose(page_file);  /* Close the file */
	buff[res.clen] = 0; /* Add the terminating zero */
	res.body = buff;

	/* ---- Header creation part --------------------------------------- */

	/* Verify the connection and request version */
	if (res.conn == NULL && res.vers > 1) {
		res.conn = "Keep-Alive";
	} else if (res.conn != NULL && strcmp(res.conn, "Close")) {
		res.conn = "Keep-Alive";
	} else {
		res.conn = "Close";
	}

	res.stext = status_text(res.status); /* Write the status text */
	res.ctype = mime_type(res.path);     /* Update the content type */
	res.date = date_line();		     /* Put the date line */

	/* Create the head */
	char response[res_header_len(res)];
	create_res_header(res, response);

	write(conn, response, strlen(response)); /* Send response */
	write(conn, "\r\n", 2);			 /* Send blank line */
	write(conn, res.body, res.clen);

	printf("\tFile %s served.\n", res.path);

	return 0;
}
