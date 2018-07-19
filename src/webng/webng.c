/*
 * ****************************************************************************
 *
 * PROJECT:	libwebng: A library to make encrypted requests over the web.
 *
 * AUTHOR:	Brian Mayer blmayer@icloud.com
 *
 * Copyright (C) 2018	Brian Mayer
 *
 * ****************************************************************************
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "webng.h"

void read_chunks(int conn, char *body)
{
	/* Here we read and update the body */
	puts("\tReceiving chunked data...");
	int chunk_size = 8;		/* The size to be read */
	int body_size = 1; 		/* This space is for the end 0 */
	char *chunk = malloc(chunk_size);
	int pos;

get_chunk:

	/* ---- Determine chunk size --------------------------------------- */

	pos = 0;
	while(read(conn, chunk + pos, 1) == 1) {
		
		/* The only thing that can break our loop is a line break */
		if(strcmp(chunk + pos, "\n") == 0) { 
			break;
		}
		
		/* Increase pos by 1 to follow the buffer size */
		pos++;
		
		if(pos == chunk_size) {
			chunk_size += 8;
			chunk = realloc(chunk, chunk_size);
		}
	}
	sscanf(chunk, "%x", &pos);	/* Hex of the chunk size */
	bzero(chunk, chunk_size);

	/* ---- Read chunk ------------------------------------------------- */
	
	if(pos > 0) {
		/* Allocate the size needed and read the chunk to body */
		body_size += pos;
		body = realloc(body, body_size);
		
		/* Now read the whole chunk, be sure */
		while(pos > 0){
			pos -= read(conn, body + body_size - pos - 1, pos);
		}
		
		read(conn, chunk, 2); 		/* This will discard a \r\n */
		goto get_chunk;
	}

	free(chunk);
}

void get_header(int conn, char **buffer)
{
	int pos = 0;
	int buff_size = 128;

	/* This is a loop that will read the data coming from our connection */
	while((pos += read(conn, *buffer + pos, 128)) > 0) {	
		*buffer = realloc(*buffer, pos + 128);
		/* The only thing that can break our loop is a blank line */
		if(strncmp(*buffer + pos - 4, "\r\n\r\n", 4) == 0) {
			/* Put zero at end and adjust buffer size */
			*buffer = realloc(*buffer, pos + 1);
			(*buffer)[pos] = '\0';
			break;
		}
	}
}

short parse_URL(char *url, struct url *addr)
{
	/* At first proto looks at the start of the URL */
	addr -> proto = url;
	
	/* Try to match cases http://domain... and //domain... in URL */
	addr -> domain = strstr(url, "://");
	if(addr -> domain != NULL) {
		strcpy(addr -> domain, "\0");
		addr -> domain = addr -> domain + 3;
	} else {
		/* URL starts with domain: www.domain... */
		addr -> domain = url;
		addr -> proto = NULL;
	}

	/* Try to find the port */
	addr -> port = strstr(addr -> domain, ":");
	if(addr -> port == NULL) {
		addr -> port = strstr(addr -> domain, "/");
	} else {
		/* Writing \0 to delimit URL parts */
		strcpy(addr -> port, "\0");
		addr -> port++;
	}
	
	/* Search for a / */
	if(addr -> port != NULL) {
		addr -> path = strstr(addr -> port, "/");
		if(addr -> path != NULL) {
			strcpy(addr -> path, "\0");
			addr -> path++;
			
			/* The last is ? */
			addr -> pars = strstr(addr -> path, "?");
		} else {
			addr -> pars = strstr(addr -> port, "?");
		}
	}

	/* Delimit path */
	if(addr -> pars != NULL) {
		strcpy(addr -> pars, "\0");
		addr -> pars++;
	}

	return 0;
}

short parse_request(char *message, struct request *req)
{
	/* Get first line parameters */
	req -> type = strtok(message, " ");	/* First token is the method */
	if(req -> type == NULL) {
		puts("\tCould not parse the method.");
		return -1;
	}
	
	req -> url = strtok(NULL, " ");		/* Then the url or path */
	strtok(NULL, "/"); 			/* Advance to the version no */

	/* Due to atof we need to test for a NULL pointer */
	char *ver = strtok(NULL, "\r\n");
	if(ver != NULL) {
		req -> vers = atof(ver); 	/* Lastly the HTTP version */
	} else {
		puts("\tCould not parse header's version.");
		return -1;
	}

	/* Put pointer in next line */
	char *temp = strtok(NULL, "\r\n");
	
	while(temp != NULL) {
		/* Keep advancing in string getting some parameters */
		if(strncmp(temp, "Host: ", 6) == 0) {
			req -> host = temp + 6;
			temp = strtok(NULL, "\r\n");
			continue;
		}
		if(strncmp(temp, "User-Agent: ", 12) == 0) {
			req -> user = temp + 12;
			temp = strtok(NULL, "\r\n");
			continue;
		}
		if(strncmp(temp, "Authorization: ", 15) == 0) {
			req -> auth = temp + 15;
			temp = strtok(NULL, "\r\n");
			continue;
		}
		if(strncmp(temp, "Content-Length: ", 16) == 0) {
			req -> clen = atoi(temp + 16);
			temp = strtok(NULL, "\r\n");
			continue;
		}
		if(strncmp(temp, "Content-Type: ", 14) == 0) {
			req -> ctype = temp + 14;
			temp = strtok(NULL, "\r\n");
			continue;
		}
		if(strncmp(temp, "Content-Encoding: ", 18) == 0) {
			req -> cenc = temp + 18;
			temp = strtok(NULL, "\r\n");
			continue;
		}
		if(strncmp(temp, "Connection: ", 12) == 0) {
			req -> conn = temp + 12;
			temp = strtok(NULL, "\r\n");
			continue;
		}
		if(strncmp(temp, "Key: ", 5) == 0) {
			req -> key = temp + 5;
			temp = strtok(NULL, "\r\n");
			continue;
		}
		temp = strtok(NULL, "\r\n");
	}

	return 0;
}

short parse_response(char *message, struct response *res)
{
	/* ---- Get first line parameters ---------------------------------- */

	/* Due to atof we need to test for a NULL pointer */
	char *ver = strtok(message, " ");
	if(ver != NULL) {
		/* The HTTP version */
		res -> vers = atof(ver + 5);
	} else {
		puts("\tCould not parse header's version.");
		return -1;
	}

	/* Advance to the status */
	char *stat = strtok(NULL, " ");
	if(stat != NULL) {
		/* Lastly the HTTP status */
		res -> status = atoi(stat);
	} else {
		puts("\tCould not parse header's status.");
		return -1;
	}

	/* Put pointer in next line */
	char *temp = strtok(NULL, "\r\n");
	
	while(temp != NULL) {
		/* Keep advancing in string getting some parameters */
		if(strncmp(temp, "Server: ", 8) == 0) { 
			res -> serv = temp + 8;
			temp = strtok(NULL, "\r\n");
			continue;
		}
		if(strncmp(temp, "Date: ", 6) == 0) {
			res -> date = temp + 6;
			temp = strtok(NULL, "\r\n");
			continue;
		}
		if(strncmp(temp, "Authorization: ", 15) == 0) {
			res -> auth = temp + 15;
			temp = strtok(NULL, "\r\n");
			continue;
		}
		if(strncmp(temp, "Content-Length: ", 16) == 0) {
			res -> clen = atoi(temp + 16);
			temp = strtok(NULL, "\r\n");
			continue;
		}
		if(strncmp(temp, "Content-Type: ", 14) == 0) {
			res -> ctype = temp + 14;
			temp = strtok(NULL, "\r\n");
			continue;
		}
		if(strncmp(temp, "Content-Encoding: ", 18) == 0) {
			res -> cenc = temp + 18;
			temp = strtok(NULL, "\r\n");
			continue;
		}
		if(strncmp(temp, "Connection: ", 12) == 0) {
			res -> conn = temp + 12;
			temp = strtok(NULL, "\r\n");
			continue;
		}
		if(strncmp(temp, "Transfer-Encoding: ", 19) == 0) {
			res -> ttype = temp + 19;
			temp = strtok(NULL, "\r\n");
			continue;
		}
		if(strncmp(temp, "Key: ", 5) == 0) {
			res -> key = temp + 5;
			temp = strtok(NULL, "\r\n");
			continue;
		}
		temp = strtok(NULL, "\r\n");
	}

	return 0;
}
short req_header_len(struct request req)
{
	/* URL request line, includes version, spaces and \r\n */
	short header_size = strlen(req.type) + strlen(req.url) + 12;

	header_size += 8 + strlen(req.host);	/* Host: \r\n */
	header_size += 14 + strlen(req.user);	/* User-Agent: \r\n */
	header_size += 14 + strlen(req.conn);	/* Connection: \r\n */
	header_size += 10 + strlen(req.cenc);	/* Accept: \r\n */
	
	/* And optional lines */
	if(req.auth != NULL) {
		header_size += 17 + strlen(req.auth);
	}
	if(req.key != NULL) {
		header_size += 7 + strlen(req.key);
	}
	
	/* File length line, if we want */
	if(req.clen > 0) {
		/* Count the number of digits */
		int number = req.clen;
		short digits = 0;
		while(number != 0) {
			number /= 10;
			digits++;
		}
		header_size += digits + 18;		/* Number of digits */
		header_size += 14 + strlen(req.ctype);	/* Content Encoding */
	}
	return header_size + 1;				/* Terminating zero */
}

short create_req_header(struct request req, char *dest)
{	
	/* Copy all parameters to it */
	sprintf(dest, 
		"%s %s HTTP/%.1f\r\n"
		"Host: %s\r\n"
		"User-Agent: %s\r\n"
		"Connection: %s\r\n"
		"Accept: %s\r\n", 
		req.type, req.url, req.vers, req.host, 
		req.user, req.conn, req.cenc);

	/* Optional lines */
	if(req.auth != NULL) {
		sprintf(dest + strlen(dest), "Authorization: %s\r\n", req.auth);
	}
	if(req.clen > 0) {
		sprintf(dest + strlen(dest),
				"Content-Type: %s\r\n"
				"Content-Length: %s\r\n",
				req.ctype, req.clen);
	}
	if(req.key != NULL) {
		sprintf(dest + strlen(dest), "Key: %s\r\n", req.key);
		encode(dest, req.key);
		strcat(dest, "\r\n");
	}

	return 0;
}

short res_header_len(struct response res)
{
	/* URL request line, includes version, spaces and \r\n */
	short header_size = 14; 	/* Size of HTTP/1.1 + xxx + \r\n */

	header_size += 1 + strlen(res.stext);	/* Status text part */
	header_size += 10 + strlen(res.serv);	/* Server information line */
	header_size += 8 + strlen(res.date);	/* Now the server time line */
	header_size += 14 + strlen(res.conn);	/* Connection: \r\n */

	/* File length line, if we want */
	if(res.clen > 0) {
		/* Count the number of digits */
		int number = res.clen;
		short digits = 0;
		while(number != 0){
			number /= 10;
			digits++;
		}
		header_size += digits + 18;		/* Number of digits */
		header_size += 16 + strlen(res.ctype);	/* Content Encoding */
	}
	
	/* Key line */
	if(res.key != NULL) {
		header_size += 7 + strlen(res.key);
	}

	return header_size + 1;				/* Terminating zero */
}

short create_res_header(struct response res, char *dest)
{
	/* Copy all parameters to it */
	sprintf(dest, 
		"HTTP/%.1f %hd %s\r\n"
		"Server: %s\r\nDate: %s\r\nConnection: %s\r\n",
		res.vers, res.status, res.stext, 
		res.serv, res.date, res.conn
	);


	/* Optional lines */
	if(res.clen > 0) {
		sprintf(dest + strlen(dest), 
			"Content-Type: %s\r\nContent-Length: %d\r\n",
			res.ctype, res.clen);
	}

	/* Encrypt using passed key */
	if(res.key != NULL) {
		sprintf(dest, "%s\r\n", encode(dest, res.key));
	}
	
	return 0;
}

short *split_keys(char *key_list)
{
	static short keys[512];
	short i = 0;
	char *key = strtok(key_list, " ");

	while(key != NULL && i < 512) {
		keys[i] = atoi(key);
		printf("%d\n", keys[i]);
		key = strtok(NULL, " ");
		i++;
	}

	return keys;
}

short encode(char *message, char *key)
{
	/* Get length of received message and key */
	int n = strlen(message);
	int i = 0;
	char cipher[n + 1];	/* Add the terminating zero place */
	
	/* Loop changing characters */
	while(i < n) {
		cipher[i] = (message[i] ^ key[i % 512]) + 33;
		i++;
	}

	cipher[n] = 0;	  		/* Add terminating zero */

	return i;
}

short decode(char *cipher, char *key)
{
	/* Get length of received message and key */
	int n = strlen(cipher);
	int i = 0;
	char message[n + 1];	/* Add the terminating zero place */

	/* Loop changing characters */
	while(i < n) {
		message[i] = (cipher[i] - 33) ^ key[i % 512];
		i++;
	}

	message[n] = 0;	  		/* Add terminating zero */

	return i;
}

