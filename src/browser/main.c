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
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <webng.h>
#include "get.h"

/* Global variables with default values */
char *KEY = "<KEY>";

int main(int argc, char *argv[]){

	/* Get URL and port from command line */
	if(argc == 2){
		puts("Using port 80.");
		argv[2] = "80";
	} else if(argc > 3){
		puts("Please specify host. Port is optional.");
	}

	/* ---- Parse the url entered to get host, path and parameters --------- */

	struct url url = {0};

	parse_URL(argv[1], &url);

	/* Lookup host name */
	struct addrinfo hints = {0};
	struct addrinfo *host;

	hints.ai_family = AF_INET;			/* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_STREAM; 	/* TCP socket */
	hints.ai_flags = 0;					/* For wildcard IP address */
	hints.ai_protocol = 0; 				/* Any protocol */

	int lookup = getaddrinfo(url.domain, argv[2], &hints, &host);
	if(lookup != 0){
		/* Get the host info */
		puts("Unable to resolve host.");
		return -1;
	}

	/* Open a socket */
	int server = socket(AF_INET, SOCK_STREAM, 0);
	if(server < 0){
		perror("Socket creation failed");
		return 0;
	}

	/* Loop on the returned result checking for an address */
	while(connect(server, host -> ai_addr, host -> ai_addrlen) == -1){
		host = host -> ai_next; 
	}
	
	if(host == NULL){
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

	if(host -> ai_canonname == NULL){
		req.host = url.domain;
	} else {
		req.host = host -> ai_canonname;
	}
	
	/* Send a not yet encrypted GET request */
	send_get(server, req);
	
	/* Populate the response struct */
	unsigned char *response = get_header(server);
	struct response res = {0};
	parse_response(response, &res);

	/* ---- Read response's body ------------------------------------------- */

	/* The transfer may be normal */
	if(res.clen > 0){
		puts("Direct.");
		
		/* Allocate space for the body */
		unsigned char body[res.clen + 1];
		
		/* Read the content from the socket */
		read(server, body, res.clen);
		body[res.clen] = 0;
		printf("Body:\n%s\n", body);
	}

	/* Or may be chunked */
	if(res.ttype != NULL && strcmp(res.ttype, "chunked") == 0){
		/* Here we read and update the body */
		unsigned char *body = read_chunks(server);
		
		printf("Body:\n%s\n", body);
	}

	/* Body read, close the connection */
	close(server);

	return 0;
}

