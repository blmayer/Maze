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
	printf("arg: %s\n", argv[1]);
	
	/* Try to match cases http://domain... and //domain... in URL */
	proto = strstr(argv[1], "//");
	if(proto == NULL){
		/* URL is like www.domain... or /file..., get everything */
		domain = strtok(argv[1], "/");
		path = strtok(NULL, "");
	} else {
		/* Advance to next / to get the domain */
		domain = strtok(proto + 2, "/");
		path = strtok(NULL, ""); 				/* Get the path after the / */
	}

	/* Check if domain is not null */
	if(domain == NULL){
		puts("Could not find a domain to lookup, please enter a domain.");
		return -1;
	}

	printf("proto is: %s\n", proto);
	printf("domain is: %s\n", domain);
	printf("path is: %s\n", path);

	/* To get parameters look for a ? */
	if(path == NULL){
		path = "/";
	}

	/* Lookup host name */
	struct addrinfo hints = {0};
	struct addrinfo *server;

	hints.ai_family = AF_INET;			/* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_STREAM; 	/* Datagram socket */
	hints.ai_flags = 0;					/* For wildcard IP address */
	hints.ai_protocol = 0; 				/* Any protocol */

	int lookup = getaddrinfo(domain, argv[2], &hints, &server);
	if(lookup != 0){
		/* Get the host info */
		puts("Unable to resolve host.");
		return -1;
	}

	/* Open a socket */
	int tcp_server = socket(AF_INET, SOCK_STREAM, 0);
	if(tcp_server < 0){
		perror("Socket creation failed");
		return 0;
	}

	/* Loop on the returned result checking for an address */
	while(connect(tcp_server, server -> ai_addr, server -> ai_addrlen) == -1){
		server = server -> ai_next; 
	}
	
	if(server == NULL){
		puts("Could not connect.");
		return -1;
	}

	puts("Connection successful!");
	
	/* Create a request structure */
	struct request req = {0};
	req.type = "GET";
	req.url = path;
	req.vers = 1.1;
	req.conn = "Keep-Alive";

	if(server -> ai_canonname == NULL){
		req.host = domain;
	} else {
		req.host = server -> ai_canonname;
	}
	
	/* Send a not yet encrypted GET request */
	send_get(tcp_server, req);
	
	unsigned char *response = get_header(tcp_server);

	puts(response);

	/* Populate the response struct */
	struct response res = {0};
	parse_response(response, &res);

	/* Read response's body */
	if(res.clen == 0){
		puts("No body to read, quiting...");
		close(tcp_server);
		return 0;
	}

	/* Allocate space for the body */
	char body[res.clen + 1];

	/* Read the content from the socket */
	read(tcp_server, body, res.clen);

	body[res.clen] = 0;

	printf("Body:\n%s\n", body);

	return 0;
}

