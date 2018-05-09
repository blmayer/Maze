/*
 * ****************************************************************************
 *
 * PROJECT:	Maze: A simple HTTP 1.1 web browser.
 *
 * AUTHOR: 	Brian Mayer blmayer@icloud.com
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <webng.h>
#include "get.h"

int main(int argc, char *argv[]){

	/* Get URL and port from command line */
	if(argc != 2)
	{
		puts("Please input exactly one parameter");
	}

	/* ---- Parse the url entered to get host, path and parameters ----- */

	struct url url = {0};
	parse_URL(argv[1], &url);

	/* Lookup host name */
	struct addrinfo hints = {0};
	struct addrinfo *host;

	hints.ai_family = AF_INET;		/* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_STREAM; 	/* TCP socket */
	hints.ai_flags = 0;			/* For wildcard IP address */
	hints.ai_protocol = 0; 			/* Any protocol */

	int lookup = getaddrinfo(url.domain, url.port, &hints, &host);
	if(lookup != 0)
	{
		/* Get the host info */
		puts("Unable to resolve host.");
		return -1;
	}

	/* Open a socket */
	int server = socket(AF_INET, SOCK_STREAM, 0);
	if(server < 0)
	{
		perror("Socket creation failed");
		return 0;
	}

	/* Loop on the returned result checking for an address */
	while(connect(server, host -> ai_addr, host -> ai_addrlen) == -1)
	{
		host = host -> ai_next; 
	}
	
	if(host == NULL)
	{
		puts("Could not connect.");
		return -1;
	}
	puts("Connection successful!");
	
	/* Set the socket timeout */
	struct timeval timeout = {10, 0};   /* Timeout structure: 10 seconds */
	setsockopt(server, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, 18);

	/* Create a request structure */
	struct request req = {0};
	req.type = "GET";
	req.url = url.path;
	req.vers = 1.1;
	req.conn = "Keep-Alive";
	req.key = KEY;

	if(host -> ai_canonname == NULL)
	{
		req.host = url.domain;
	} 
	else
	{
		req.host = host -> ai_canonname;
	}
	
	/* Send a not yet encrypted GET request */
	send_get(server, req);
	
	/* ---- Read response's body --------------------------------------- */

	/* Populate the response struct */
	unsigned char *response = get_header(server);
	printf("received\n'%s'\n", response);
	struct response res = {0};
	if(parse_response(response, &res) < 0)
	{
		/* Could be an encrypted response */
		puts("Trying to decode response...");
		printf("decoded:\n'%s'\n", decode(response, KEY));
		if(parse_response(decode(response, KEY), &res) < 0)
		{
			puts("Bad response.");
			return 0;
		}
	}

	/* Print values for checking */
	puts("\tParsed:");
	printf("\tVersion: %.1f\n", res.vers);
	printf("\tStatus: %d\n", res.status);
	printf("\tServer: %s\n", res.serv);
	printf("\tConnection: %s\n", res.conn);
	printf("\tContent Type: %s\n", res.ctype);
	printf("\tContent Length: %d\n", res.clen);
	printf("\tDate: %s\n", res.date);
	printf("\tAuthorization: %s\n", res.auth);
	printf("\tKey: %s\n", res.key);
	
	/* ---- Receiving the body ----------------------------------------- */

	res.body = malloc(1);

	/* The transfer may be normal */
	if(res.clen > 0)
	{
		/* Reallocate space for the body */
		res.body = realloc(res.body, res.clen + 1);
		
		/* Read the content from the socket */
		read(server, res.body, res.clen);
		res.body[res.clen] = 0;
	}

	/* Or may be chunked */
	if(res.ttype != NULL && strcmp(res.ttype, "chunked") == 0)
	{
		/* Here we read and update the body */
		unsigned char *temp = read_chunks(server);
		res.body = strdup(temp);
	}

	/* Body read, close the connection */
	if(req.key != NULL)
	{
		res.body = decode(res.body, req.key);
	}

	printf("Body:\n%s\n", res.body);
	close(server);
	free(res.body);

	return 0;
}

