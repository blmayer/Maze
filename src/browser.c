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
#include <web.h>
#include "getfn.h"

/* Global variables with default values */
char *KEY = "blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#blmayer#";

int main(int argc, char *argv[]){

	/* Get URL and port from command line */
	if(argc == 2){
		puts("Using port 80.");
		argv[2] = "80";
	} else if(argc > 3){
		puts("Please specify host. Port is optional.");
	}

	/* ---- Parse the url entered to get host, path and parameters --------- */

	char *proto, *domain, *path, *pars;
	
	/* First five bytes gives you the protocol */
	switch(strncmp(argv[1], "http:", 5)){
	case 0:
		proto = "http";
		break;

	case 57:
		proto = "https";
		break;
	
	default:
		proto = NULL;
	}

	/* TODO Pass only one time over the url string */
	/* Now we find the domain */
	if(proto == NULL){
		/* URL is like www.domain... or /file..., get everything */
		strncpy(domain, argv[1], strcspn(argv[1], "/"));
	} else {
		/* Try to match cases http://domain... and //domain... in URL */
		domain = strtok(argv[1] + strlen(proto) + 3, "/");
	}
	
	/* Check if domain is not null */
	if(domain == NULL){
		puts("Could not find a domain to lookup, please enter a domain.");
		return -1;
	}
	
	/* Now get the path */
	path = strtok(NULL, "");
	if(path == NULL){
		path = "/";
		pars = NULL;
	} else {
		pars = strchr(path, '?'); 		/* It is easier to find pars first */
		path = strchr(path, '/'); 		/* Get the path after the / */
		if(path == NULL){
			path = "/";
		}
	}

	printf("proto is: %s\n", proto);
	printf("domain is: %s\n", domain);
	printf("path is: %s\n", path);
	printf("pars is: %s\n", pars);

	/* Lookup host name */
	struct addrinfo hints = {0};
	struct addrinfo *host;

	hints.ai_family = AF_INET;			/* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_STREAM; 	/* TCP socket */
	hints.ai_flags = 0;					/* For wildcard IP address */
	hints.ai_protocol = 0; 				/* Any protocol */

	int lookup = getaddrinfo(domain, argv[2], &hints, &host);
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
	req.url = path;
	req.vers = 1.1;
	req.conn = "Keep-Alive";

	if(host -> ai_canonname == NULL){
		req.host = domain;
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

	/* Allocate space for the body */
	unsigned char *body = NULL;

	/* The transfer may be normal */
	if(res.clen > 0){
		/* Allocate the correct size */
		body = realloc(body, res.clen + 1);
		
		/* Read the content from the socket */
		read(server, body, res.clen);
	}

	/* Or may be chunked */
	if(strcmp(res.ttype, "chunked") == 0){
		/* Here we read and update the body */
		unsigned char *chunk;
		int chunk_size; 				/* The size to be read */
		int body_size = 0; 				/* This space is for the end 0 */
	
get_chunk:
		puts("\tReceiving chunked data...");
		chunk = read_chunk(server);
		sscanf(chunk, "%x", &chunk_size); 
		
		if(chunk_size > 0){
			/* Allocate the size needed and read */
			body = realloc(body, body_size + chunk_size);
			
			/* Now read the whole chunk, be sure */
			int got = 0;
			while(got < chunk_size){
				got += read(server, body + body_size + got, chunk_size - got);
			}
			
			body_size += chunk_size;
			read(server, chunk, 2); 	/* This will discard a \r\n */
			goto get_chunk;
		}
	}

	printf("Body:\n%s\n", body);
	free(body);

	/* Body read, close the connection */
	close(server);

	return 0;
}

