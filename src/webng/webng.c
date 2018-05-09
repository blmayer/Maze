/*
 * ****************************************************************************
 *
 * PROJECT:	libwebng: A library to make encripted requests over the web.
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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <webng.h>

unsigned char *read_chunks(int conn){

	/* Here we read and update the body */
	puts("\tReceiving chunked data...");
	int chunk_size = 8;			/* The size to be read */
	int body_size = 1; 			/* This space is for the end 0 */
	unsigned char *chunk = malloc(chunk_size);
	unsigned char *body = malloc(body_size);
	int pos;

get_chunk:

	/* ---- Determine chunk size --------------------------------------- */

	pos = 0;
	while(read(conn, chunk + pos, 1) == 1){
		
		/* The only thing that can break our loop is a line break */
		if(strcmp(chunk + pos, "\n") == 0){ 
			break;
		}
		
		/* Increase pos by 1 to follow the buffer size */
		pos++;
		
		if(pos == chunk_size){
			chunk_size += 8;
			chunk = realloc(chunk, chunk_size);
		}
	}
	sscanf(chunk, "%x", &pos); 
	bzero(chunk, chunk_size);

	/* ---- Read chunk ------------------------------------------------- */
	
	if(pos > 0){
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

	/* ---- Sanitize and return ---------------------------------------- */

	free(chunk);
	body[body_size + 1] = 0;
	char *dest = strdup(body);
	free(body);

	return strdup(dest);
}

unsigned char *get_header(int conn)
{
	int pos = 0;
	int buff_size = 1024;
	unsigned char *buffer = calloc(buff_size, 1);

	/* This is a loop that will read the data coming from our connection */
	while(read(conn, buffer + pos, 1) == 1)
	{	
		/* Increase pos by 1 to follow the buffer size */
		pos++;
		/* The only thing that can break our loop is a blank line */
		if(strcmp(buffer + pos - 4, "\r\n\r\n") == 0)
		{
			break;
		}
		
		if(pos == buff_size)
		{
			buff_size += 512;
			buffer = realloc(buffer, buff_size);
		}
	}

	/* Duplicate so we can free the memory */
	unsigned char *dest = strdup(buffer);
	free(buffer);

	/* Duplicate to not get lost in function */
	return strdup(dest);
}

unsigned char *get_token(unsigned char *source, char par[]){
	
	/* Search for the parameter passed */
	unsigned char *tag = strcasestr(source, par);
	
	/* Check if parameter exists in header */
	if(tag == NULL){
		return NULL;
	}

	/* Offset and take the rest */
	unsigned char *token = strtok(tag + strlen(par), "\r\n");
	
	/* Duplicate the token found to not get lost with function */
	return strdup(token);
}

int parse_URL(char *url, struct url *addr){

	/* Try to match cases http://domain... and //domain... in URL */
	addr -> proto = strstr(url, "://");
	if(addr -> proto == NULL){
		/* URL is like www.domain... */
		addr -> domain = strtok(url, "/:");
	} else {
		/* Get the protocol */
		addr -> proto = strtok(url, ":");
		
		/* Advance to next / to get the domain */
		addr -> domain = strtok(NULL, "/:");
	}

	/* Get the port if there's one */
	addr -> port = strtok(NULL, ":/");

	/* Now get the path */
	addr -> path = strtok(NULL, ":/");

	/* Prepend / to the path in any case */
	int len;

	if(addr -> path == NULL){
		len = 0;
	} else {
		len = strlen(addr -> path);
	}

	unsigned char new[len + 2];
	strcpy(new, "/");

	if(len == 0){
		new[1] = '\0';
	} else {
		strcat(new, addr -> path);
	}

	/* Get parameters and path from new string */
	addr -> pars = strstr(new, "?");
	addr -> path = strdup(new);

	/* Rip off the parameters part */
	strtok(addr -> path, "?");

	return 0;
}

int parse_request(unsigned char *message, struct request *req){

	/* Get first line parameters */
	req -> type = strtok(message, " ");	/* First token is the method */
	if(req -> type == NULL)
	{
		puts("\tCould not parse the method.");
		return -1;
	}
	
	req -> url = strtok(NULL, " ");		/* Then the url or path */
	strtok(NULL, "/"); 			/* Advance to the version no */

	/* Due to atof we need to test for a NULL pointer */
	char *ver = strtok(NULL, "\r\n");
	if(ver != NULL){
		req -> vers = atof(ver); 	/* Lastly the HTTP version */
	} else {
		puts("\tCould not parse header's version.");
		return -1;
	}

	/* Put pointer in next line */
	char *temp = strtok(NULL, "\r\n");
	
	while(temp != NULL)
	{
		/* Keep advancing in string getting some parameters */
		if(strncmp(temp, "Host: ", 6) == 0)
		{
			req -> host = temp + 6;
			temp = strtok(NULL, "\r\n");
			continue;
		}
		if(strncmp(temp, "User-Agent: ", 12) == 0)
		{
			req -> user = temp + 12;
			temp = strtok(NULL, "\r\n");
			continue;
		}
		if(strncmp(temp, "Authorization: ", 15) == 0)
		{
			req -> auth = temp + 15;
			temp = strtok(NULL, "\r\n");
			continue;
		}
		if(strncmp(temp, "Content-Length: ", 16) == 0)
		{
			req -> clen = atoi(temp + 16);
			temp = strtok(NULL, "\r\n");
			continue;
		}
		if(strncmp(temp, "Content-Type: ", 14) == 0)
		{
			req -> ctype = temp + 14;
			temp = strtok(NULL, "\r\n");
			continue;
		}
		if(strncmp(temp, "Content-Encoding: ", 18) == 0)
		{
			req -> cenc = temp + 18;
			temp = strtok(NULL, "\r\n");
			continue;
		}
		if(strncmp(temp, "Connection: ", 12) == 0)
		{
			req -> conn = temp + 12;
			temp = strtok(NULL, "\r\n");
			continue;
		}
		if(strncmp(temp, "Key: ", 5) == 0)
		{
			req -> key = temp + 5;
			temp = strtok(NULL, "\r\n");
			continue;
		}
		temp = strtok(NULL, "\r\n");
	}

	return 0;
}

int parse_response(unsigned char *message, struct response *res)
{
	/* ---- Get first line parameters ---------------------------------- */

	/* Due to atof we need to test for a NULL pointer */
	char *ver = strtok(message, " ");
	if(ver != NULL)
	{
		/* The HTTP version */
		res -> vers = atof(ver + 5);
	} 
	else
	{
		puts("\tCould not parse header's version.");
		return -1;
	}

	/* Advance to the status */
	char *stat = strtok(NULL, " ");
	if(stat != NULL)
	{
		/* Lastly the HTTP status */
		res -> status = atoi(stat);
	} 
	else 
	{
		puts("\tCould not parse header's status.");
		return -1;
	}

	/* Put pointer in next line */
	char *temp = strtok(NULL, "\r\n");
	
	while(temp != NULL)
	{
		/* Keep advancing in string getting some parameters */
		if(strncmp(temp, "Server: ", 8) == 0)
		{
			res -> serv = temp + 8;
			temp = strtok(NULL, "\r\n");
			continue;
		}
		if(strncmp(temp, "Date: ", 6) == 0)
		{
			res -> date = temp + 6;
			temp = strtok(NULL, "\r\n");
			continue;
		}
		if(strncmp(temp, "Authorization: ", 15) == 0)
		{
			res -> auth = temp + 15;
			temp = strtok(NULL, "\r\n");
			continue;
		}
		if(strncmp(temp, "Content-Length: ", 16) == 0)
		{
			res -> clen = atoi(temp + 16);
			temp = strtok(NULL, "\r\n");
			continue;
		}
		if(strncmp(temp, "Content-Type: ", 14) == 0)
		{
			res -> ctype = temp + 14;
			temp = strtok(NULL, "\r\n");
			continue;
		}
		if(strncmp(temp, "Content-Encoding: ", 18) == 0)
		{
			res -> cenc = temp + 18;
			temp = strtok(NULL, "\r\n");
			continue;
		}
		if(strncmp(temp, "Connection: ", 12) == 0)
		{
			res -> conn = temp + 12;
			temp = strtok(NULL, "\r\n");
			continue;
		}
		if(strncmp(temp, "Transfer-Encoding: ", 19) == 0)
		{
			res -> ttype = temp + 19;
			temp = strtok(NULL, "\r\n");
			continue;
		}
		if(strncmp(temp, "Key: ", 5) == 0)
		{
			res -> key = temp + 5;
			temp = strtok(NULL, "\r\n");
			continue;
		}
		temp = strtok(NULL, "\r\n");
	}

	return 0;
}

unsigned char *create_req_header(struct request req){
	
	/* ---- Calculate size of the final string ------------------------ */

	/* URL request line, includes version, spaces and \r\n */
	int header_size = strlen(req.type) + strlen(req.url) + 12;

	/* Host, user agent and conn lines */
	header_size += strlen(req.host) + strlen(req.user) + strlen(req.conn) + 6;
	
	/* Accept line */
	header_size += strlen(req.cenc) + 2;
	
	/* And optional lines */
	if(req.auth != NULL)
	{
		header_size += strlen(req.auth) + 17;
	}
	if(req.key != NULL)
	{
		header_size += strlen(req.key) + 7;
	}
	
	/* File length line, if we want */
	if(req.clen > 0)
	{
		/* Count the number of digits */
		int number = req.clen;
		int digits = 0;
		while(number != 0)
		{
			number /= 10;
			digits++;
		}
		header_size += digits + 18;		/* Number of digits */
		header_size += 14 + strlen(req.ctype);	/* Content Encoding */
	}

	/* ---- Glue them together ----------------------------------------- */

	/* The header string, +1 for the end zero and +2 for blank line */
	unsigned char header[header_size + 48];
	
	/* Copy all parameters to it */
	sprintf(header, 
		"%s %s HTTP/%.1f\r\n"
		"Host: %s\r\n"
		"User-Agent: %s\r\n"
		"Connection: %s\r\n"
		"Accept: %s\r\n", 
		req.type, req.url, req.vers, req.host, 
		req.user, req.conn, req.cenc);

	/* Optional lines */
	if(req.auth != NULL){
		sprintf(header + strlen(header), "Authorization: %s\r\n", req.auth);
	}
	if(req.clen > 0){
		sprintf(header + strlen(header),
				"Content-Type: %s\r\n"
				"Content-Length: %s\r\n",
				req.ctype, req.clen);
	}
	if(req.key != NULL){
		sprintf(header + strlen(header), "Key: %s\r\n", req.key);
		strcpy(header, encode(header, req.key));
		strcat(header, "\r\n");
	}
	
	/* Add blank line */
	strcat(header, "\r\n");
	
	/* Add end zero */
	header[header_size + 47] = 0;

	return strdup(header);
}

unsigned char *create_res_header(struct response res)
{
	/* URL request line, includes version, spaces and \r\n */
	int header_size = 16; 	/* Size of HTTP/1.1 + 5 + \r\n + end zero */

	/* Make the status line */
	char *status_line;
	switch(res.status)
	{
	case 200:
		status_line = "OK";
		header_size += 4;
		break;
	case 400:
		status_line = "Bad Request";
		header_size += 13;
		break;
	case 404:
		status_line = "Not Found";
		header_size += 11;
		break;
	case 500:
		status_line = "Internal Server Error";
		header_size += 23;
		break;
	case 501:
		status_line = "Not Implemented";
		header_size += 17;
		break;
	}

	/* Server information line */
	header_size += 10 + strlen(res.serv);

	/* Now the server time line */
	header_size += 8 + strlen(res.date);

	/* File length line, if we want */
	if(res.clen > 0)
	{
		/* Count the number of digits */
		int number = res.clen;
		int digits = 0;
		while(number != 0){
			number /= 10;
			digits++;
		}
		header_size += digits + 18;		/* Number of digits */
		header_size += 16 + strlen(res.ctype);	/* Content Encoding */
	}
	
	/* Connection line */
	if(res.conn != NULL)
	{
		header_size += strlen(res.conn) + 14;
	}

	/* Another blank line */
	if(res.key != NULL)
	{
		header_size += 2;
	}
	
	/* The header string */
	unsigned char header[header_size + 1];

	/* Copy all parameters to it */
	sprintf(header, 
		"HTTP/%.1f %d %s\r\n"
		"Server: %s\r\n"
		"Date: %s\r\n", 
		res.vers, res.status, status_line, res.serv, res.date);

	/* Optional lines */
	if(res.clen > 0)
	{
		sprintf(header + strlen(header), 
			"Content-Type: %s\r\nContent-Length: %d\r\n",
			res.ctype, res.clen);
	}

	/* Connection line */
	if(res.conn != NULL)
	{
		sprintf(header + strlen(header), "Connection: %s\r\n", res.conn);
	}
	/* Encrypt using passed key */
	if(res.key != NULL)
	{
		sprintf(header, "%s\r\n", encode(header, res.key));
	}
	
	/* Add blank line */
	strcat(header, "\r\n");

	/* Add end zero */
	header[header_size] = 0;

	return strdup(header);
}

unsigned char *encode(unsigned char *message, unsigned char *key){

	/* Get length of received message and key */
	int n = strlen(message);
	int i = 0;
	int key_len = strlen(key);
	unsigned char cipher[n + 1];	/* Add the terminating zero place */
	
	/* Loop changing characters */
	while(i < n){
		cipher[i] = (message[i] ^ key[i % key_len]) + 33;
		i++;
	}

	cipher[n] = 0;	  		/* Add terminating zero */
	return strdup(cipher);
}

unsigned char *decode(unsigned char *cipher, unsigned char *key){

	/* Get length of received message and key */
	int n = strlen(cipher);
	int i = 0;
	int key_len = strlen(key);
	unsigned char message[n + 1];	/* Add the terminating zero place */

	/* Loop changing characters */
	while(i < n){
		message[i] = (cipher[i] - 33) ^ key[i % key_len];
		i++;
	}

	message[n] = 0;	  		/* Add terminating zero */

	return strdup(message);
}

