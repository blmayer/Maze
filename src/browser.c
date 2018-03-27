/*
 * ****************************************************************************
 *
 * PROJECT:	 Maze: A simple HTTP 1.1 web browser.
 *
 * AUTHOR:	  Brian Mayer blmayer@icloud.com
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
#include "headers.h"
#include "getfn.h"
#include "transform.h"

int main(int argc, char *argv[]){

	/* Get URL and port from command line */
	if(argc < 3){
		puts("Please enter a valid URL and port.");
		return -1;
	}

	/* Lookup host name */
	struct addrinfo hints = {0};
	struct addrinfo *server;

	hints.ai_family = AF_INET;			/* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_STREAM; 	/* Datagram socket */
	hints.ai_flags = 0;					/* For wildcard IP address */
	hints.ai_protocol = 0; 				/* Any protocol */

	int lookup = getaddrinfo(argv[1], argv[2], &hints, &server);
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

	while(connect(tcp_server, server -> ai_addr, server -> ai_addrlen) == -1){
		server = server -> ai_next; 
	}
	
	if(server == NULL){
		puts("Could not connext.");
		return -1;
	}

	puts("Connection successful!");
	
	/* Create a request structure */
	struct request req = {0};
	req.type = "GET";
	req.url = argv[1];
	req.vers = "1.1";
	req.host = server -> ai_canonname;
	req.conn = "Keep-Alive";
	
	/* Send an encrypted GET request */
	send_get(tcp_server, req, 0);
	
	/* Initialize variables for reading the request */
	puts("\tReady to receive.");
	int pos = 0, buff_size = 1024;
	unsigned char *buffer = calloc(buff_size, 1);

	/* This is a loop that will read the data coming from our connection */
	while(read(tcp_server, buffer + pos, 1) == 1){
		
		/* Increase pos by 1 to follow the buffer size */
		pos++;
		
		/* The only thing that can break our loop is a blank line */
		if(strcmp(buffer + pos - 4, "\r\n\r\n") == 0){ 
			break;
		}
		
		if(pos == buff_size){
			puts("\t\tBuffer grew.");
			buff_size += 512;
			buffer = realloc(buffer, buff_size);
		}
	}
	
	puts(buffer);
	free(buffer);

	close(tcp_server);
	
	return 0;
}
