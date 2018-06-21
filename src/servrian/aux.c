/*
 * ****************************************************************************
 *
 * AUTHOR:	Brian Mayer blmayer@icloud.com
 *
 * Copyright (C) 2018	Brian Lee Mayer
 *
 * ****************************************************************************
 */

#include "aux.h"

/* File operations definitions */

int file_size(char *path) 
{	
	/* Get the length of the file requested */
	FILE *page_file = fopen(path, "r");
	
	if(page_file == NULL) {
		perror("\t\tSomething went wrong.");
		return -1;
	}
	
	fseek(page_file, 0, SEEK_END);		/* Seek to the last byte */
	int page_size = ftell(page_file);   	/* The position is the size */
	fclose(page_file);
	
	return page_size;
}

short write_log(char *buff)
{
	FILE *log_file = fopen("logs/log.txt", "a");
	
	if(log_file == NULL) {
		perror("\t\tError opening file");
		exit(1);
	}
	
	fprintf(log_file, "Received:\n%s\n", buff);
	fclose(log_file);
	
	return 0;
}

/* Header processing tools */

char *date_line()
{
    /* Get the current time in the correct format */
    struct tm *cur_time;                /* Obtain current time */
    time_t now = time(NULL);
    cur_time = gmtime(&now);
    static char res_time[30]; 		/* Convert to local time format */

    /* Date: Fri, 19 Feb 1992 08:53:17 GMT */
    strftime(res_time, 30, "%a, %d %b %Y %X %Z", cur_time);

    return res_time;
}

char *status_text(short status)
{
	/* Make the status line */
	static char *status_line;
	switch(status) {
	case 200:
		status_line = "OK";
		break;
	case 400:
		status_line = "Bad Request";
		break;
	case 404:
		status_line = "Not Found";
		break;
	case 500:
		status_line = "Internal Server Error";
		break;
	case 501:
		status_line = "Not Implemented";
		break;
	default:
		status_line = "Unknown";
	}

	return status_line;
}

char *mime_type(char *path) 
{	
	/* Match the extension against some cases */
	static char *mime;
	switch(strcmp(strrchr(path, '.'), ".bsog")) {
	case 6:
		mime = "text/html";
		break;
	case 1:
		mime = "text/css";
		break;
	case 2:
		mime = "application/javascript";
		break;
	case 14:
		mime = "image/png";
		break;
	case 17:
		mime = "image/svg+xml";
		break;
	case 7:
		mime = "image/x-icon";
		break;
	case 21:
		mime = "application/x-font-woff";
		break;
	default:
		mime = "application/octet-stream";
		break;
	}
	
	return mime;
}

