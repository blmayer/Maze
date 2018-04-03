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
	char *port;
	if(argc == 2){
		puts("Using port 80.");
		port = "80";
	} else if(argc == 3){
		port = argv[2];
	} else {
		puts("Please specify host and/or port.");
		return -1;
	}

	/* Address must not end with a / */
	int addr_len = strlen(argv[1]) - 1;
	if(strcmp(argv[1] + addr_len, "/") == 0){
		/* Remove / */
		argv[1][addr_len] = 0;
	}

	puts(argv[1]);
	/* Lookup host name */
	struct addrinfo hints = {0};
	struct addrinfo *server;

	hints.ai_family = AF_INET;			/* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_STREAM; 	/* Datagram socket */
	hints.ai_flags = 0;					/* For wildcard IP address */
	hints.ai_protocol = 0; 				/* Any protocol */

	int lookup = getaddrinfo(argv[1], port, &hints, &server);
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
	req.url = argv[1];
	req.vers = 1.1;
	req.conn = "Keep-Alive";

	if(server -> ai_canonname == NULL){
		req.host = argv[1];
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

	close(tcp_server);
	
	return 0;
}

